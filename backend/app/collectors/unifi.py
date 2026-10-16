"""UniFi Network controller collector (Cloud Key Gen1/Gen2(+), UDM/UDR/UCG, self-hosted).

Every adopted switch / AP / gateway becomes a child device in NetworkVision with
its own ports, traffic, CPU/mem, temperature and uplink (used for topology).

Auth: a *local* read-only admin (username/password) is the most compatible.
UniFi Network 9+ also supports an API key (Settings > Control Plane > Integrations).
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from ..services.clients import BAND, from_unifi, wifi_standard
from .base import (
    ChildSnapshot,
    CollectorError,
    FieldSpec,
    Gateway,
    Interface,
    LogLine,
    Neighbor,
    Section,
    Snapshot,
    norm_mac,
)
from .http_base import TLS_FIELDS, HttpCollector, NotFound, first_number

ROLE_BY_TYPE = {"usw": "switch", "uap": "ap", "ugw": "router", "udm": "router", "uxg": "router",
                "ucg": "router", "uck": "controller", "ubb": "bridge", "uph": "phone"}
GATEWAY_TYPES = {"ugw", "udm", "uxg", "ucg"}
KNOWN_CLIENT_DAYS = 30  # offline clients seen within this window stay in the inventory
STATE = {0: "disconnected", 1: "connected", 2: "pending", 4: "upgrading", 5: "provisioning",
         6: "heartbeat missed", 7: "adopting", 9: "adoption failed", 10: "isolated", 11: "rf scanning"}


class UnifiCollector(HttpCollector):
    kind = "unifi"
    label = "UniFi Network controller"
    vendor = "Ubiquiti"
    description = (
        "Discovers all adopted UniFi switches, APs and gateways: ports, PoE, SFP, uplinks, "
        "clients, WAN health, alarms and events."
    )
    default_role = "controller"
    discovers_children = True
    fields = [
        *TLS_FIELDS,
        FieldSpec(key="site", label="Site", type="text", default="default",
                  help="Site *id* (the short one in the URL), usually 'default'."),
        FieldSpec(key="controller_type", label="Controller type", type="select",
                  options=["auto", "unifi-os", "legacy"], default="auto",
                  help="Cloud Key Gen2 / UDM run UniFi OS. 'legacy' = old software controller on :8443."),
        FieldSpec(key="api_key", label="API key (Network 9+)", type="password", secret=True,
                  placeholder="env:UNIFI_API_KEY"),
        FieldSpec(key="username", label="Username", type="text", placeholder="local read-only admin"),
        FieldSpec(key="password", label="Password", type="password", secret=True, placeholder="env:UNIFI_PASSWORD"),
    ]

    def __init__(self, host: str, config: dict[str, Any], secrets: dict[str, Any]) -> None:
        super().__init__(host, config, secrets)
        self._prefix: str | None = None
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._csrf: str | None = None
        self._logged_in = False

    # -- auth --------------------------------------------------------------
    async def _login(self) -> None:
        user, pw, key = self.opt("username"), self.opt("password"), self.opt("api_key")
        ctype = self.opt("controller_type") or "auto"
        if key and not (user and pw):
            self._prefix = "" if ctype == "legacy" else "/proxy/network"
            self._logged_in = True
            return
        if not (user and pw):
            raise CollectorError("UniFi needs either an API key or a username/password")
        c = self.client()
        attempts = [("/api/auth/login", "/proxy/network"), ("/api/login", "")]
        if ctype == "unifi-os":
            attempts = attempts[:1]
        elif ctype == "legacy":
            attempts = attempts[1:]
        last = ""
        for path, prefix in attempts:
            try:
                r = await c.post(path, json={"username": user, "password": pw, "remember": True})
            except httpx.HTTPError as e:
                raise CollectorError(f"Cannot reach UniFi controller: {e}") from e
            if r.status_code == 200:
                self._prefix = prefix
                self._csrf = r.headers.get("x-csrf-token") or r.headers.get("x-updated-csrf-token")
                self._logged_in = True
                return
            last = f"{path} -> HTTP {r.status_code}"
            if r.status_code in (401, 403) and "auth" in path:
                raise CollectorError("UniFi login rejected - use a LOCAL account (not a UI.com SSO account)")
        raise CollectorError(f"UniFi login failed ({last})")

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {}
        if self.opt("api_key") and not self.opt("password"):
            h["X-API-KEY"] = self.opt("api_key")
        if self._csrf:
            h["X-CSRF-Token"] = self._csrf
        return h

    async def api(self, path: str, optional: bool = True) -> list[dict[str, Any]]:
        if not self._logged_in:
            await self._login()
        site = self.opt("site") or "default"
        url = f"{self._prefix}/api/s/{site}/{path}"
        try:
            body = await self.request_json("GET", url, headers=self._headers())
        except NotFound as e:
            if optional:
                return []
            raise CollectorError(f"UniFi endpoint not found: {url} (check the site id)") from e
        except CollectorError as e:
            if "Authentication failed" in str(e) and self.opt("password"):
                self._logged_in = False  # session expired -> exactly one re-login
                await self._login()
                body = await self.request_json("GET", url, headers=self._headers())
            elif optional:
                return []
            else:
                raise
        if isinstance(body, dict):
            meta = body.get("meta", {})
            if meta.get("rc") == "error":
                if optional:
                    return []
                raise CollectorError(f"UniFi API error: {meta.get('msg')}")
            return body.get("data", []) or []
        return []

    # -- collection --------------------------------------------------------
    async def collect(self) -> Snapshot:
        devices = await self.api("stat/device", optional=False)
        health = await self.api("stat/health")
        sysinfo = await self.api("stat/sysinfo")
        clients = await self.api("stat/sta")
        alarms = await self.api("list/alarm?archived=false")
        events = await self.api("stat/event?_limit=100&within=2")
        networks = await self.api("rest/networkconf")

        snap = Snapshot()
        si = sysinfo[0] if sysinfo else {}
        snap.facts = {"vendor": "Ubiquiti", "model": "UniFi Network",
                      "version": si.get("version", ""), "hostname": si.get("hostname", ""),
                      "site": self.opt("site") or "default"}
        snap.metrics["clients"] = len(clients)
        snap.metrics["devices"] = len(devices)
        snap.metrics["devices_offline"] = sum(1 for d in devices if d.get("state") != 1)

        # UniFi can only measure the internet through its *own* gateway. With a third-party
        # router (pfSense, OPNsense...) the "www" subsystem is just "unknown" - not "down".
        has_unifi_gateway = any(d.get("type") in GATEWAY_TYPES for d in devices)
        for sub in health:
            name = sub.get("subsystem")
            status = str(sub.get("status") or "").lower()
            if name == "www" and has_unifi_gateway and status not in ("", "unknown"):
                down, up = sub.get("xput_down"), sub.get("xput_up")
                detail = []
                if down is not None and up is not None:
                    detail.append(f"speedtest down {down} / up {up} Mbps")
                if sub.get("drops"):
                    detail.append(f"{sub['drops']} connectivity drops")
                snap.gateways.append(Gateway(
                    name="Internet", address=str(sub.get("gw_name", "")),
                    up=status != "error",
                    latency_ms=first_number(sub.get("latency")),
                    loss_pct=None,  # "drops" is a count of failed checks, not a percentage
                    detail="; ".join(detail),
                ))
            elif name == "wan" and sub.get("wan_ip"):
                snap.facts["wan_ip"] = sub.get("wan_ip")
                snap.facts["isp"] = (sub.get("isp_name") or sub.get("gw_system-stats", {}).get("isp", ""))

        snap.children = [self._child(d) for d in devices]

        for a in alarms[:100]:
            snap.logs.append(LogLine(ts=(a.get("time") or 0) / 1000, message=str(a.get("msg", a.get("key", ""))),
                                     app="alarm", severity=3, facility="unifi"))
        for e in events:
            key = str(e.get("key", ""))
            sev = 4 if any(w in key for w in ("Disconnected", "Lost", "Down", "Isolated", "Restart")) else 6
            snap.logs.append(LogLine(ts=(e.get("time") or 0) / 1000, message=str(e.get("msg", key)),
                                     app=key.split("_")[0].lower() or "event", severity=sev, facility="unifi"))

        if networks:
            snap.sections.append(Section(
                id="networks", title="Networks / VLANs",
                columns=["Name", "Purpose", "VLAN", "Subnet", "DHCP", "Enabled"],
                rows=[[n.get("name"), n.get("purpose"), n.get("vlan", "") if n.get("vlan_enabled") else "",
                       n.get("ip_subnet", ""), bool(n.get("dhcpd_enabled")), n.get("enabled", True)] for n in networks],
            ))
        # Slow-changing lists are refreshed every few minutes, not every poll.
        known = await self._cached("rest/user")
        wlans = await self._cached("rest/wlanconf")
        neighbors = await self._cached("stat/rogueap?within=24")
        net_names = {n.get("_id", ""): n.get("name", "") for n in networks}

        online = {norm_mac(c.get("mac")) for c in clients}
        snap.clients = [from_unifi(c, True, net_names) for c in clients]
        horizon = time.time() - KNOWN_CLIENT_DAYS * 86400
        snap.clients += [from_unifi(u, False, net_names) for u in known
                         if norm_mac(u.get("mac")) not in online and (u.get("last_seen") or 0) >= horizon]
        snap.wifi = build_wifi(devices, wlans, neighbors, clients, net_names)
        return snap

    async def _cached(self, path: str, ttl: float = 300) -> list[dict[str, Any]]:
        hit = self._cache.get(path)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        data = await self.api(path)
        self._cache[path] = (time.time(), data)
        return data

    def _child(self, d: dict[str, Any]) -> ChildSnapshot:
        mac = norm_mac(d.get("mac", ""))
        state = d.get("state", 0)
        stats = d.get("system-stats", {}) or {}
        c = ChildSnapshot(
            external_id=mac, name=d.get("name") or d.get("model", mac), host=d.get("ip", ""),
            role=ROLE_BY_TYPE.get(d.get("type", ""), "other"), reachable=state == 1,
            error=None if state == 1 else f"UniFi state: {STATE.get(state, state)}",
        )
        c.facts = {
            "vendor": "Ubiquiti", "model": d.get("model_name") or d.get("model", ""), "mac": mac,
            "version": d.get("version", ""), "serial": d.get("serial", ""),
            "upgradable": bool(d.get("upgradable")), "upgrade_to": d.get("upgrade_to_firmware", ""),
            "adopted": d.get("adopted", True), "state": STATE.get(state, str(state)),
        }
        c.metrics = {
            "cpu": first_number(stats.get("cpu")), "mem": first_number(stats.get("mem")),
            "uptime_s": d.get("uptime"), "clients": d.get("num_sta"),
            "satisfaction": d.get("satisfaction"),
            "temp": first_number(d.get("general_temperature")) or _max_temp(d.get("temperatures")),
        }
        c.metrics = {k: v for k, v in c.metrics.items() if v is not None}
        for p in d.get("port_table", []) or []:
            idx = p.get("port_idx")
            c.interfaces.append(Interface(
                name=f"Port {idx}" if idx is not None else str(p.get("name", "?")),
                alias=p.get("name", "") if p.get("name") and not str(p.get("name")).startswith("Port ") else "",
                index=idx, oper_up=bool(p.get("up")), admin_up=p.get("enable", True),
                speed_mbps=float(p["speed"]) if p.get("up") and p.get("speed") else None,
                media=str(p.get("media", "")).lower() or ("sfp" if p.get("sfp_found") else "copper"),
                in_octets=p.get("rx_bytes"), out_octets=p.get("tx_bytes"),
                in_errors=p.get("rx_errors"), out_errors=p.get("tx_errors"),
                in_discards=p.get("rx_dropped"), out_discards=p.get("tx_dropped"),
                poe_w=first_number(p.get("poe_power")) if p.get("poe_enable") else None,
                is_uplink=bool(p.get("is_uplink")),
                extra={"sfp": {k: p.get(k) for k in ("sfp_vendor", "sfp_part", "sfp_temperature", "sfp_rxpower",
                                                       "sfp_txpower") if p.get(k) is not None} or None,
                       "full_duplex": p.get("full_duplex"), "stp_state": p.get("stp_state")},
            ))
        for r in d.get("radio_table_stats", []) or []:
            c.sections.append(Section(id=f"radio-{r.get('name')}", title=f"Radio {r.get('radio', '')}", kind="kv", rows=[
                ["Channel", r.get("channel")], ["Clients", r.get("num_sta")], ["Utilization %", r.get("cu_total")],
                ["TX power", r.get("tx_power")], ["Satisfaction", r.get("satisfaction")],
            ]))
        up = d.get("uplink") or {}
        if up.get("uplink_mac"):
            c.neighbors.append(Neighbor(
                local_port=f"Port {up['port_idx']}" if up.get("port_idx") else str(up.get("name", "uplink")),
                remote_mac=norm_mac(up.get("uplink_mac")),
                remote_name=str(up.get("uplink_device_name", "")),
                remote_port=f"Port {up['uplink_remote_port']}" if up.get("uplink_remote_port") else "",
                protocol="uplink",
            ))
        for n in d.get("lldp_table", []) or []:
            c.neighbors.append(Neighbor(
                local_port=f"Port {n.get('local_port_idx')}" if n.get("local_port_idx") else str(n.get("local_port_name", "")),
                remote_mac=norm_mac(n.get("chassis_id", "")), remote_port=str(n.get("port_id", "")),
                remote_name=str(n.get("chassis_name", n.get("sys_name", ""))), protocol="lldp",
            ))
        return c

    async def close(self) -> None:
        self._logged_in = False
        await super().close()


def _max_temp(temps: Any) -> float | None:
    vals = [first_number(t.get("value")) for t in temps or [] if isinstance(t, dict)]
    vals = [v for v in vals if v is not None]
    return max(vals) if vals else None


def _n(v: Any) -> float | None:
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


def build_wifi(devices: list[dict[str, Any]], wlans: list[dict[str, Any]], neighbors: list[dict[str, Any]],
               clients: list[dict[str, Any]], net_names: dict[str, str]) -> dict[str, Any]:
    """Normalize everything the WiFi dashboard needs from one UniFi site."""
    aps = []
    for d in devices:
        if d.get("type") != "uap":
            continue
        cfg = {r.get("name"): r for r in d.get("radio_table", []) or []}
        radios = []
        for rs in d.get("radio_table_stats", []) or []:
            rc = cfg.get(rs.get("name"), {})
            band = BAND.get(str(rs.get("radio") or rc.get("radio") or "").lower(), str(rs.get("radio")))
            util, srx, stx = _n(rs.get("cu_total")), _n(rs.get("cu_self_rx")) or 0, _n(rs.get("cu_self_tx")) or 0
            proto = "be" if rc.get("is_11be") else "ax" if rc.get("is_11ax") else "ac" if rc.get("is_11ac") else "n"
            radios.append({
                "name": rs.get("name"), "band": band, "channel": rs.get("channel"),
                "width": _n(rs.get("bw")) or _n(rc.get("ht")), "extchannel": rs.get("extchannel"),
                "tx_power": _n(rs.get("tx_power")), "tx_power_mode": rc.get("tx_power_mode"),
                "min_tx_power": _n(rc.get("min_txpower")), "max_tx_power": _n(rc.get("max_txpower")),
                "utilization": util, "self_rx": srx, "self_tx": stx,
                # Airtime used by *other* networks/noise = total busy minus our own rx/tx.
                "interference": max(0.0, util - srx - stx) if util is not None else None,
                "clients": rs.get("num_sta"), "satisfaction": _n(rs.get("satisfaction")),
                "retries_pct": _n(rs.get("tx_retries_pct")), "dfs": bool(rc.get("has_dfs")),
                "standard": wifi_standard(proto, band), "nss": rc.get("nss"), "antenna_gain": _n(rc.get("antenna_gain")),
            })
        vaps = [{
            "ssid": v.get("essid"), "bssid": norm_mac(v.get("bssid")), "band": BAND.get(str(v.get("radio") or "").lower()),
            "channel": v.get("channel"), "clients": v.get("num_sta"), "satisfaction": _n(v.get("satisfaction")),
            "avg_signal": _n(v.get("avg_client_signal")), "tx_bytes": _n(v.get("tx_bytes")), "rx_bytes": _n(v.get("rx_bytes")),
            "tx_retries": _n(v.get("tx_retries")), "tx_dropped": _n(v.get("tx_dropped")), "is_guest": bool(v.get("is_guest")),
            "wlan_id": v.get("wlanconf_id"), "up": v.get("up", True),
        } for v in d.get("vap_table", []) or []]
        up = d.get("uplink") or {}
        aps.append({
            "mac": norm_mac(d.get("mac")), "name": d.get("name") or d.get("model"), "model": d.get("model"),
            "ip": d.get("ip"), "online": d.get("state") == 1, "uptime_s": _n(d.get("uptime")),
            "version": d.get("version"), "satisfaction": _n(d.get("satisfaction")), "clients": d.get("num_sta"),
            "tx_bytes": _n(d.get("tx_bytes")), "rx_bytes": _n(d.get("rx_bytes")),
            "uplink": {"name": up.get("uplink_device_name") or "", "port": up.get("uplink_remote_port"),
                       "speed": up.get("speed"), "type": up.get("type")},
            "radios": radios, "vaps": vaps,
        })

    per_wlan: dict[str, dict[str, Any]] = {}
    for ap in aps:
        for v in ap["vaps"]:
            w = per_wlan.setdefault(v.get("wlan_id") or v.get("ssid") or "", {"clients": 0, "bands": {}, "sat": []})
            w["clients"] += v.get("clients") or 0
            if v.get("band"):
                w["bands"][v["band"]] = w["bands"].get(v["band"], 0) + (v.get("clients") or 0)
            if v.get("satisfaction") is not None and v.get("clients"):
                w["sat"].append((v["satisfaction"], v["clients"]))
    ssids = []
    for w in wlans:
        agg = per_wlan.get(w.get("_id", ""), {"clients": 0, "bands": {}, "sat": []})
        weight = sum(n for _, n in agg["sat"])
        ssids.append({
            "id": w.get("_id"), "name": w.get("name"), "enabled": w.get("enabled", True), "security": w.get("security"),
            "wpa_mode": w.get("wpa_mode"), "hidden": bool(w.get("hide_ssid")), "guest": bool(w.get("is_guest")),
            "bands": w.get("wlan_bands") or ([w["wlan_band"]] if w.get("wlan_band") else []),
            "network": net_names.get(w.get("networkconf_id", ""), ""), "fast_roaming": bool(w.get("fast_roaming_enabled")),
            "pmf": w.get("pmf_mode"), "mlo": bool(w.get("mlo_enabled")), "l2_isolation": bool(w.get("l2_isolation")),
            "clients": agg["clients"], "clients_by_band": agg["bands"],
            "satisfaction": sum(s * n for s, n in agg["sat"]) / weight if weight else None,
        })

    seen = []
    for n in sorted(neighbors, key=lambda x: -(_n(x.get("signal")) or -200))[:500]:
        seen.append({
            "bssid": norm_mac(n.get("bssid")), "ssid": n.get("essid") or "",
            "band": BAND.get(str(n.get("band") or n.get("radio") or "").lower()),
            "channel": n.get("channel"), "width": _n(n.get("bw")), "signal": _n(n.get("signal")),
            "security": n.get("security"), "seen_by": n.get("ap_name") or "", "last_seen": _n(n.get("last_seen")),
            "is_rogue": bool(n.get("is_rogue")), "vendor": n.get("oui") or "",
        })
    wireless = [c for c in clients if not c.get("is_wired")]
    return {"aps": aps, "ssids": ssids, "neighbors": seen, "wireless_clients": len(wireless), "updated": time.time()}
