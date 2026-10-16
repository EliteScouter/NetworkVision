"""pfSense collector.

pfSense has no built-in REST API, so this uses the community *pfSense REST API*
package (https://pfrest.org, v2). Install it on the firewall, create an API key
(System > REST API > Keys) and give it read-only privileges.

No package? Use the SNMP collector against pfSense's built-in bsnmpd and point
pfSense's remote syslog at NetworkVision instead - you still get most data.
"""

from __future__ import annotations

import re
from typing import Any

from ..services.clients import from_lease
from ..syslog_parser import parse_syslog
from .base import CollectorError, FieldSpec, Gateway, Interface, LogLine, Section, Snapshot, norm_mac
from .http_base import TLS_FIELDS, HttpCollector, NotFound, first_number, pick


class PfSenseCollector(HttpCollector):
    kind = "pfsense"
    label = "pfSense (REST API)"
    vendor = "Netgate"
    description = (
        "System health, interfaces, gateways (latency/loss), DHCP leases, services and "
        "logs via the pfSense REST API package (pfrest.org v2)."
    )
    default_role = "firewall"
    fields = [
        *TLS_FIELDS,
        FieldSpec(key="api_key", label="API key", type="password", secret=True, placeholder="env:PFSENSE_API_KEY",
                  help="pfSense REST API v2 key. Use env:VAR to keep it in your Portainer env."),
        FieldSpec(key="username", label="Username (basic auth, optional)", type="text"),
        FieldSpec(key="password", label="Password (basic auth, optional)", type="password", secret=True),
        FieldSpec(key="log_lines", label="Log lines per poll", type="number", default=50),
    ]

    def _auth_kwargs(self) -> dict[str, Any]:
        key = self.opt("api_key")
        if key:
            return {"headers": {"X-API-Key": key}}
        user, pw = self.opt("username"), self.opt("password")
        if user and pw:
            return {"auth": (user, pw)}
        raise CollectorError("Configure an API key (or username/password) for pfSense")

    async def api(self, path: str, optional: bool = False, **params: Any) -> Any:
        kwargs = self._auth_kwargs()
        call = self.try_json if optional else self.request_json
        body = await call("GET", f"/api/v2/{path}", params=params or None, **kwargs)
        if isinstance(body, dict) and "data" in body:
            return body["data"]
        return body

    async def collect(self) -> Snapshot:
        snap = Snapshot()
        try:
            system = await self.api("status/system") or {}
        except NotFound as e:
            raise CollectorError("pfSense REST API v2 not found - is the package installed?") from e

        snap.metrics.update({
            "cpu": first_number(pick(system, "cpu_usage")),
            "mem": first_number(pick(system, "mem_usage")),
            "disk": first_number(pick(system, "disk_usage")),
            "swap": first_number(pick(system, "swap_usage")),
            "temp": first_number(pick(system, "temp_c")),
        })
        load = pick(system, "cpu_load_avg")
        if isinstance(load, list) and load:
            snap.metrics["load1"] = first_number(load[0])
        version = await self.api("system/version", optional=True) or {}
        snap.facts = {
            "vendor": "Netgate",
            "model": pick(system, "system_platform", default="pfSense"),
            "serial": pick(system, "system_serial", "netgate_id", "system_netgate_id", default=""),
            "cpu_model": pick(system, "cpu_model", default=""),
            "cpu_count": pick(system, "cpu_count"),
            "version": pick(version, "version", default=""),
            "bios": " ".join(str(x) for x in (pick(system, "bios_vendor"), pick(system, "bios_version")) if x),
        }
        snap.metrics = {k: v for k, v in snap.metrics.items() if v is not None}

        for item in await self.api("status/interfaces", optional=True) or []:
            name = pick(item, "descr", "name", default="?")
            snap.interfaces.append(Interface(
                name=str(name).upper() if name.islower() else str(name),
                alias=str(pick(item, "hwif", "if", default="")),
                oper_up=str(pick(item, "status", default="")).lower() in ("up", "associated", "online"),
                mac=norm_mac(pick(item, "macaddr", default="")),
                speed_mbps=_media_speed(str(pick(item, "media", default=""))),
                media=str(pick(item, "media", default="")),
                in_octets=_int(pick(item, "inbytes")),
                out_octets=_int(pick(item, "outbytes")),
                in_errors=_int(pick(item, "inerrs")),
                out_errors=_int(pick(item, "outerrs")),
                extra={"ip": pick(item, "ipaddr", default=""), "gateway": pick(item, "gateway", default="")},
            ))

        for gw in await self.api("status/gateways", optional=True) or []:
            status = str(pick(gw, "status", default="")).lower()
            snap.gateways.append(Gateway(
                name=str(pick(gw, "name", default="gateway")),
                address=str(pick(gw, "monitorip", "srcip", default="")),
                up=status in ("online", "none", "up") if status else None,
                latency_ms=first_number(pick(gw, "delay")),
                loss_pct=first_number(pick(gw, "loss")),
                detail=str(pick(gw, "substatus", default="")),
            ))

        leases = await self.api("status/dhcp_server/leases", optional=True) or []
        if leases:
            snap.metrics["clients"] = sum(1 for le in leases if str(pick(le, "active_status", default="")) == "active") or len(leases)
            snap.clients = [from_lease(str(pick(le, "mac", default="")), str(pick(le, "ip", default="")),
                                       str(pick(le, "hostname", default="")),
                                       str(pick(le, "online_status", "active_status", default="")),
                                       str(pick(le, "if", "interface", default="")), pick(le, "ends", "end"))
                            for le in leases if pick(le, "mac")]
            snap.sections.append(Section(
                id="dhcp", title="DHCP leases", columns=["IP", "MAC", "Hostname", "Interface", "State"],
                rows=[[pick(le, "ip"), pick(le, "mac"), pick(le, "hostname", default=""),
                       pick(le, "if", "interface", default=""), pick(le, "online_status", "active_status", default="")]
                      for le in leases[:500]],
            ))
        services = await self.api("status/services", optional=True) or []
        if services:
            snap.sections.append(Section(
                id="services", title="Services", columns=["Service", "Description", "Running"],
                rows=[[pick(s, "name"), pick(s, "description", default=""), bool(pick(s, "status", default=False))]
                      for s in services],
            ))
        rules = await self.api("firewall/rules", optional=True) or []
        if rules:
            snap.sections.append(Section(
                id="rules", title="Firewall rules",
                columns=["#", "Iface", "Action", "Proto", "Source", "Destination", "Description", "Disabled", "Tracker"],
                # The tracker is what filterlog lines carry; the Firewall page resolves it to the description
                # (pfBlockerNG's "pfB_* auto rule" entries are ordinary rules here, so they resolve too).
                rows=[[i, pick(r, "interface", default=""), pick(r, "type", default=""), pick(r, "protocol", default="any"),
                       _addr(r.get("source")), _addr(r.get("destination")), pick(r, "descr", default=""),
                       bool(pick(r, "disabled", default=False)), str(pick(r, "tracker", default="") or "")]
                      for i, r in enumerate(rules)],
            ))

        limit = int(self.opt("log_lines") or 50)
        for kind in ("system", "firewall"):
            for entry in (await self.api(f"status/logs/{kind}", optional=True, limit=limit) or [])[-limit:]:
                line = entry.get("text", "") if isinstance(entry, dict) else str(entry)
                if line:
                    snap.logs.append(_parse_line(line, kind))
        return snap


def _int(v: Any) -> int | None:
    f = first_number(v) if not isinstance(v, int) else v
    return int(f) if f is not None else None


def _media_speed(media: str) -> float | None:
    m = re.search(r"(\d+)(G|base)", media, re.I)
    if not m:
        return None
    n = float(m.group(1))
    return n * 1000 if m.group(2).upper() == "G" else n


def _addr(v: Any) -> str:
    if isinstance(v, dict):
        return ",".join(f"{k}:{x}" for k, x in v.items()) or "any"
    return str(v or "any")


def _parse_line(line: str, kind: str) -> LogLine:
    p = parse_syslog(line)
    sev = p.severity
    if kind == "firewall":
        # filterlog CSV: ...,match,block|pass,in|out,...
        sev = 5 if ",block," in p.message else 7
    return LogLine(ts=p.ts, message=p.message, app=p.app or kind, severity=sev, facility=kind)
