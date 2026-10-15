"""OPNsense collector (built-in REST API).

Create an API key under System > Access > Users > (user) > API keys. A user in
a group with read-only "Diagnostics", "Status" and "Dashboard" privileges is enough.
"""

from __future__ import annotations

import re
from typing import Any

from ..syslog_parser import parse_syslog
from .base import CollectorError, FieldSpec, Gateway, Interface, LogLine, Section, Snapshot, norm_mac
from .http_base import TLS_FIELDS, HttpCollector, NotFound, first_number, pick

_SEV = {"emergency": 0, "alert": 1, "critical": 2, "error": 3, "warning": 4, "notice": 5,
        "informational": 6, "info": 6, "debug": 7}


class OpnSenseCollector(HttpCollector):
    kind = "opnsense"
    label = "OPNsense (API)"
    vendor = "Deciso"
    description = (
        "CPU, memory, temperature, interfaces, gateways, DHCP leases, services, firmware "
        "and system/firewall logs through OPNsense's native API."
    )
    default_role = "firewall"
    fields = [
        *TLS_FIELDS,
        FieldSpec(key="api_key", label="API key", type="password", secret=True, required=True,
                  placeholder="env:OPNSENSE_API_KEY"),
        FieldSpec(key="api_secret", label="API secret", type="password", secret=True, required=True,
                  placeholder="env:OPNSENSE_API_SECRET"),
        FieldSpec(key="log_lines", label="Log lines per poll", type="number", default=50),
    ]

    async def api(self, path: str, method: str = "GET", optional: bool = True, **kwargs: Any) -> Any:
        key, secret = self.opt("api_key"), self.opt("api_secret")
        if not key or not secret:
            raise CollectorError("OPNsense API key and secret are required")
        call = self.try_json if optional else self.request_json
        return await call(method, f"/api/{path}", auth=(key, secret), **kwargs)

    async def collect(self) -> Snapshot:
        snap = Snapshot()
        try:
            info = await self.api("diagnostics/system/systemInformation", optional=False) or {}
        except NotFound:
            info = await self.api("core/firmware/info") or {}
        resources = await self.api("diagnostics/system/systemResources") or {}
        systime = await self.api("diagnostics/system/systemTime") or {}
        activity = await self.api("diagnostics/activity/getActivity") or {}
        temps = await self.api("diagnostics/system/systemTemperature") or []

        versions = info.get("versions") if isinstance(info, dict) else None
        snap.facts = {
            "vendor": "Deciso",
            "model": "OPNsense",
            "hostname": pick(info, "name", default=""),
            "version": (versions[0] if isinstance(versions, list) and versions else pick(info, "product_version", default="")),
            "versions": versions or [],
        }

        mem = resources.get("memory", {}) if isinstance(resources, dict) else {}
        total, used = first_number(mem.get("total")), first_number(mem.get("used"))
        if total and used is not None:
            snap.metrics["mem"] = used / total * 100
            snap.metrics["mem_total_b"] = total
        cpu = _cpu_from_activity(activity)
        if cpu is not None:
            snap.metrics["cpu"] = cpu
        load = str(pick(systime, "loadavg", default=""))
        if load:
            snap.metrics["load1"] = first_number(load.split(",")[0])
        uptime = _uptime_seconds(str(pick(systime, "uptime", default="")))
        if uptime:
            snap.metrics["uptime_s"] = uptime
        tvals = [first_number(t.get("temperature")) for t in temps if isinstance(t, dict)]
        tvals = [t for t in tvals if t is not None and 0 < t < 150]
        if tvals:
            snap.metrics["temp"] = max(tvals)

        await self._interfaces(snap)
        await self._gateways(snap)
        await self._sections(snap)
        await self._logs(snap)
        return snap

    async def _interfaces(self, snap: Snapshot) -> None:
        overview = await self.api("interfaces/overview/interfacesInfo")
        rows = overview.get("rows", []) if isinstance(overview, dict) else []
        stats = await self.api("diagnostics/traffic/interface") or {}
        traffic = stats.get("interfaces", {}) if isinstance(stats, dict) else {}
        by_device = {v.get("device"): v for v in traffic.values() if isinstance(v, dict)}
        if rows:
            for r in rows:
                dev = r.get("device", "")
                t = by_device.get(dev, {})
                st = r.get("statistics", {}) or {}
                snap.interfaces.append(Interface(
                    name=str(pick(r, "description", "identifier", "device", default=dev)),
                    alias=dev,
                    oper_up=str(pick(r, "status", default="")).lower() in ("up", "active", "associated"),
                    admin_up=bool(r.get("enabled", True)),
                    mac=norm_mac(pick(r, "macaddr", default="")),
                    media=str(pick(r, "media", default="")),
                    speed_mbps=_media_speed(str(pick(r, "media", default=""))),
                    in_octets=_i(pick(t, "bytes received") or pick(st, "bytes received", "received-bytes")),
                    out_octets=_i(pick(t, "bytes transmitted") or pick(st, "bytes transmitted", "sent-bytes")),
                    in_errors=_i(pick(t, "input errors") or pick(st, "input errors", "received-errors")),
                    out_errors=_i(pick(t, "output errors") or pick(st, "output errors", "send-errors")),
                    vlan=str(pick(r, "vlan_tag", default="")),
                    extra={"ip": ", ".join(a.get("ipaddr", "") for a in r.get("ipv4", []) if isinstance(a, dict))
                           or pick(r, "addr4", default="")},
                ))
        else:
            for key, t in traffic.items():
                if not isinstance(t, dict):
                    continue
                snap.interfaces.append(Interface(
                    name=str(pick(t, "name", default=key)), alias=str(t.get("device", "")),
                    in_octets=_i(t.get("bytes received")), out_octets=_i(t.get("bytes transmitted")),
                    in_errors=_i(t.get("input errors")), out_errors=_i(t.get("output errors")),
                ))

    async def _gateways(self, snap: Snapshot) -> None:
        data = await self.api("routes/gateway/status") or {}
        for gw in data.get("items", []) if isinstance(data, dict) else []:
            status = str(pick(gw, "status", default="")).lower()
            snap.gateways.append(Gateway(
                name=str(pick(gw, "name", default="gateway")),
                address=str(pick(gw, "monitor", "address", default="")),
                up=status in ("none", "online", "up") if status else None,
                latency_ms=first_number(pick(gw, "delay")),
                loss_pct=first_number(pick(gw, "loss")),
                detail=str(pick(gw, "status_translated", default="")),
            ))

    async def _sections(self, snap: Snapshot) -> None:
        leases = await self.api("dhcpv4/leases/searchLease") or {}
        rows = leases.get("rows", []) if isinstance(leases, dict) else []
        if not rows:
            kea = await self.api("kea/leases4/search") or {}
            rows = kea.get("rows", []) if isinstance(kea, dict) else []
        if rows:
            snap.metrics["clients"] = sum(1 for r in rows if str(r.get("state", "active")) == "active")
            snap.sections.append(Section(
                id="dhcp", title="DHCP leases", columns=["IP", "MAC", "Hostname", "Interface", "State"],
                rows=[[pick(r, "address"), pick(r, "mac", "hwaddr"), pick(r, "hostname", default=""),
                       pick(r, "if_descr", "if", default=""), pick(r, "state", default="")] for r in rows[:500]],
            ))
        services = await self.api("core/service/search") or {}
        srows = services.get("rows", []) if isinstance(services, dict) else []
        if srows:
            snap.sections.append(Section(
                id="services", title="Services", columns=["Service", "Description", "Running"],
                rows=[[s.get("name"), s.get("description", ""), bool(int(s.get("running", 0) or 0))] for s in srows],
            ))
        fw = await self.api("core/firmware/status") or {}
        if isinstance(fw, dict) and fw:
            snap.facts["updates_available"] = bool(fw.get("updates") not in (None, "0", 0, "")) or \
                str(fw.get("status", "")) in ("update", "upgrade")
            snap.sections.append(Section(id="firmware", title="Firmware", kind="kv", rows=[
                ["Product", pick(fw, "product_name", default="OPNsense")],
                ["Version", pick(fw, "product_version", default=snap.facts.get("version", ""))],
                ["Status", pick(fw, "status_msg", "status", default="")],
                ["Last check", pick(fw, "last_check", default="")],
            ]))

    async def _logs(self, snap: Snapshot) -> None:
        limit = int(self.opt("log_lines") or 50)
        for module, scope in (("core", "system"), ("core", "configd")):
            data = await self.api(f"diagnostics/log/{module}/{scope}", method="POST",
                                  data={"current": 1, "rowCount": limit, "searchPhrase": ""})
            for row in data.get("rows", []) if isinstance(data, dict) else []:
                text = str(row.get("line", ""))
                p = parse_syslog(f"{row.get('timestamp', '')} {text}" if row.get("timestamp") else text)
                snap.logs.append(LogLine(
                    ts=p.ts, message=text or p.message, app=str(row.get("process_name", p.app)),
                    severity=_SEV.get(str(row.get("severity", "")).lower(), p.severity), facility=scope,
                ))


def _i(v: Any) -> int | None:
    f = first_number(v)
    return int(f) if f is not None else None


def _media_speed(media: str) -> float | None:
    m = re.search(r"(\d+)(G|base)", media, re.I)
    if not m:
        return None
    n = float(m.group(1))
    return n * 1000 if m.group(2).upper() == "G" else n


def _cpu_from_activity(activity: Any) -> float | None:
    headers = activity.get("headers", []) if isinstance(activity, dict) else []
    for h in headers:
        m = re.search(r"([\d.]+)%\s+idle", str(h))
        if m and str(h).strip().upper().startswith("CPU"):
            return max(0.0, 100 - float(m.group(1)))
    return None


def _uptime_seconds(s: str) -> float | None:
    # "3 days, 04:05:06" or "04:05:06"
    days = re.search(r"(\d+)\s+day", s)
    hms = re.search(r"(\d+):(\d+)(?::(\d+))?", s)
    if not days and not hms:
        return None
    total = int(days.group(1)) * 86400 if days else 0
    if hms:
        total += int(hms.group(1)) * 3600 + int(hms.group(2)) * 60 + int(hms.group(3) or 0)
    return float(total)
