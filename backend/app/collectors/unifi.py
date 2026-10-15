"""UniFi Network controller collector (Cloud Key Gen1/Gen2(+), UDM/UDR/UCG, self-hosted).

Every adopted switch / AP / gateway becomes a child device in NetworkVision with
its own ports, traffic, CPU/mem, temperature and uplink (used for topology).

Auth: a *local* read-only admin (username/password) is the most compatible.
UniFi Network 9+ also supports an API key (Settings > Control Plane > Integrations).
"""

from __future__ import annotations

from typing import Any

import httpx

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

        for sub in health:
            name = sub.get("subsystem")
            if name == "www":
                snap.gateways.append(Gateway(
                    name="Internet", address=str(sub.get("gw_name", "")),
                    up=sub.get("status") == "ok" if sub.get("status") else None,
                    latency_ms=first_number(sub.get("latency")),
                    loss_pct=first_number(sub.get("drops")),
                    detail=f"down {sub.get('xput_down', '?')} / up {sub.get('xput_up', '?')} Mbps (speedtest)",
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
        if clients:
            top = sorted(clients, key=lambda c: (c.get("tx_bytes", 0) or 0) + (c.get("rx_bytes", 0) or 0), reverse=True)
            snap.sections.append(Section(
                id="clients", title=f"Clients ({len(clients)})",
                columns=["Name", "IP", "MAC", "Network", "Connection", "Signal", "Rx", "Tx"],
                rows=[[c.get("name") or c.get("hostname") or "", c.get("ip", ""), c.get("mac", ""),
                       c.get("network", ""), ("wired" if c.get("is_wired") else c.get("essid", "wifi")),
                       c.get("signal", ""), c.get("rx_bytes", 0), c.get("tx_bytes", 0)] for c in top[:300]],
            ))
        return snap

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
