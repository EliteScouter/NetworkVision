"""Generic SNMP v2c/v3 collector.

Works with anything that speaks standard MIBs - HP/Aruba ProCurve, managed
TP-Link (JetStream/Omada), UniFi switches, Cisco, MikroTik, Linux net-snmp,
pfSense/OPNsense bsnmpd, Synology... Vendor-specific CPU/memory OIDs are tried
as fallbacks when HOST-RESOURCES-MIB is not implemented.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)
from pysnmp.proto.rfc1902 import OctetString

from .base import (
    Collector,
    CollectorError,
    FieldSpec,
    Interface,
    Neighbor,
    Section,
    Snapshot,
    norm_mac,
)

# --- OIDs -------------------------------------------------------------------
SYS = {
    "descr": "1.3.6.1.2.1.1.1.0",
    "object_id": "1.3.6.1.2.1.1.2.0",
    "uptime": "1.3.6.1.2.1.1.3.0",
    "contact": "1.3.6.1.2.1.1.4.0",
    "name": "1.3.6.1.2.1.1.5.0",
    "location": "1.3.6.1.2.1.1.6.0",
}
IF = {
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "type": "1.3.6.1.2.1.2.2.1.3",
    "speed": "1.3.6.1.2.1.2.2.1.5",
    "mac": "1.3.6.1.2.1.2.2.1.6",
    "admin": "1.3.6.1.2.1.2.2.1.7",
    "oper": "1.3.6.1.2.1.2.2.1.8",
    "in_oct32": "1.3.6.1.2.1.2.2.1.10",
    "in_disc": "1.3.6.1.2.1.2.2.1.13",
    "in_err": "1.3.6.1.2.1.2.2.1.14",
    "out_oct32": "1.3.6.1.2.1.2.2.1.16",
    "out_disc": "1.3.6.1.2.1.2.2.1.19",
    "out_err": "1.3.6.1.2.1.2.2.1.20",
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "in_oct": "1.3.6.1.2.1.31.1.1.1.6",
    "out_oct": "1.3.6.1.2.1.31.1.1.1.10",
    "high_speed": "1.3.6.1.2.1.31.1.1.1.15",
    "alias": "1.3.6.1.2.1.31.1.1.1.18",
}
HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"  # .2 type .3 descr .4 units .5 size .6 used
HR_RAM_TYPE = "1.3.6.1.2.1.25.2.1.2"
UCD_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"
UCD_MEM_TOTAL = "1.3.6.1.4.1.2021.4.5.0"
UCD_MEM_AVAIL = "1.3.6.1.4.1.2021.4.6.0"
UCD_MEM_BUF = "1.3.6.1.4.1.2021.4.14.0"
UCD_MEM_CACHED = "1.3.6.1.4.1.2021.4.15.0"
UCD_LOAD1 = "1.3.6.1.4.1.2021.10.1.3.1"
HP_CPU = "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0"
HP_MEM = "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1"  # .5 total .7 alloc
TPLINK_CPU = "1.3.6.1.4.1.11863.6.4.1.1.1.1.3"
TPLINK_MEM = "1.3.6.1.4.1.11863.6.4.1.2.1.1.2"
CISCO_CPU_1M = "1.3.6.1.4.1.9.9.109.1.1.1.1.7"
ENT_SENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"
ENT_SENSOR_VALUE = "1.3.6.1.2.1.99.1.1.1.4"
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"  # .5 chassis .7 portid .8 portdesc .9 sysname
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"  # .3 portid .4 portdesc
LLDP_REM_MAN = "1.0.8802.1.1.2.1.4.2.1.3"  # index carries the mgmt address
VLAN_NAMES = "1.3.6.1.2.1.17.7.1.4.3.1.1"

AUTH_PROTOS = {
    "none": usmNoAuthProtocol,
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
}
PRIV_PROTOS = {
    "none": usmNoPrivProtocol,
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES256": usmAesCfb256Protocol,
}
IFTYPE_MEDIA = {6: "copper", 117: "copper", 62: "copper", 71: "wifi", 53: "virtual", 135: "virtual",
                136: "virtual", 161: "lag", 131: "tunnel", 24: "loopback"}


def _value(v: Any) -> Any:
    """Convert a pysnmp value to a plain python value."""
    if isinstance(v, OctetString):
        raw = bytes(v.asOctets())
        if raw and all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
            return raw.decode("ascii", "ignore").strip()
        return raw
    cls = v.__class__.__name__
    if cls in {"NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"}:
        return None
    if cls == "ObjectIdentifier":
        return str(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return v.prettyPrint()


def _text(v: Any) -> str:
    if isinstance(v, bytes):
        if len(v) == 6:
            return norm_mac(v.hex())
        return v.decode("utf-8", "ignore").strip("\x00 ").strip()
    return "" if v is None else str(v)


class SnmpCollector(Collector):
    kind = "snmp"
    label = "SNMP (generic)"
    vendor = "Any"
    description = (
        "Standard SNMP v2c/v3 polling: interfaces, traffic, errors, CPU, memory, "
        "temperature, VLANs and LLDP neighbors. Ideal for HP ProCurve, managed "
        "TP-Link, UniFi switches, Cisco, MikroTik and Linux hosts."
    )
    default_role = "switch"
    fields = [
        FieldSpec(key="snmp_version", label="SNMP version", type="select", options=["2c", "3"], default="2c"),
        FieldSpec(key="port", label="Port", type="number", default=161),
        FieldSpec(key="community", label="Community (v2c)", type="password", secret=True,
                  placeholder="env:SWITCH_SNMP_COMMUNITY", help="Use env:VAR to read from the container env."),
        FieldSpec(key="v3_user", label="v3 username", type="text"),
        FieldSpec(key="v3_auth_proto", label="v3 auth", type="select", options=list(AUTH_PROTOS), default="SHA"),
        FieldSpec(key="v3_auth_key", label="v3 auth key", type="password", secret=True),
        FieldSpec(key="v3_priv_proto", label="v3 privacy", type="select", options=list(PRIV_PROTOS), default="AES"),
        FieldSpec(key="v3_priv_key", label="v3 privacy key", type="password", secret=True),
        FieldSpec(key="timeout", label="Timeout (s)", type="number", default=3),
        FieldSpec(key="ignore_interfaces", label="Ignore interfaces (regex)", type="text",
                  default=r"^(lo\d*|Null\d*|pflog\d*|pfsync\d*|enc\d*|ipfw\d*|usbus\d*|InLoopBack.*)$"),
        FieldSpec(key="lldp", label="Discover LLDP neighbors", type="bool", default=True),
    ]

    def __init__(self, host: str, config: dict[str, Any], secrets: dict[str, Any]) -> None:
        super().__init__(host, config, secrets)
        self._engine = SnmpEngine()
        self._sem = asyncio.Semaphore(4)
        self._target: UdpTransportTarget | None = None

    # -- low level ---------------------------------------------------------
    def _auth(self):
        if str(self.opt("snmp_version")) == "3":
            user = self.opt("v3_user")
            if not user:
                raise CollectorError("SNMPv3 username is required")
            auth_key, priv_key = self.opt("v3_auth_key"), self.opt("v3_priv_key")
            return UsmUserData(
                user,
                authKey=auth_key or None,
                privKey=priv_key or None,
                authProtocol=AUTH_PROTOS.get(self.opt("v3_auth_proto"), usmHMACSHAAuthProtocol)
                if auth_key else usmNoAuthProtocol,
                privProtocol=PRIV_PROTOS.get(self.opt("v3_priv_proto"), usmAesCfb128Protocol)
                if priv_key else usmNoPrivProtocol,
            )
        community = self.opt("community") or "public"
        return CommunityData(community, mpModel=1)

    async def _tgt(self) -> UdpTransportTarget:
        if self._target is None:
            self._target = await UdpTransportTarget.create(
                (self.host, int(self.opt("port"))), timeout=float(self.opt("timeout")), retries=1
            )
        return self._target

    async def get(self, *oids: str) -> dict[str, Any]:
        async with self._sem:
            err, status, _idx, binds = await get_cmd(
                self._engine, self._auth(), await self._tgt(), ContextData(),
                *[ObjectType(ObjectIdentity(o)) for o in oids],
            )
        if err:
            raise CollectorError(f"SNMP: {err}")
        if status:
            return {}
        return {str(name): _value(val) for name, val in binds}

    async def walk(self, oid: str, limit: int = 5000) -> dict[str, Any]:
        """Return {index_suffix: value} for a subtree."""
        out: dict[str, Any] = {}
        prefix = oid + "."
        async with self._sem:
            async for err, status, _idx, binds in bulk_walk_cmd(
                self._engine, self._auth(), await self._tgt(), ContextData(), 0, 40,
                ObjectType(ObjectIdentity(oid)), lexicographicMode=False,
            ):
                if err:
                    raise CollectorError(f"SNMP: {err}")
                if status:
                    break
                for name, val in binds:
                    n = str(name)
                    if not n.startswith(prefix):
                        return out
                    out[n[len(prefix):]] = _value(val)
                    if len(out) >= limit:
                        return out
        return out

    async def safe_walk(self, oid: str) -> dict[str, Any]:
        try:
            return await self.walk(oid)
        except Exception:  # noqa: BLE001 - optional MIBs are allowed to fail
            return {}

    # -- collection --------------------------------------------------------
    async def collect(self) -> Snapshot:
        sysinfo = await self.get(*SYS.values())
        if not sysinfo:
            raise CollectorError("No SNMP response (check community/credentials and ACLs)")
        by_oid = {v: k for k, v in SYS.items()}
        sys = {by_oid.get(k, k): v for k, v in sysinfo.items()}

        snap = Snapshot()
        descr = _text(sys.get("descr"))
        snap.facts = {
            "hostname": _text(sys.get("name")),
            "description": descr,
            "location": _text(sys.get("location")),
            "contact": _text(sys.get("contact")),
            "sys_object_id": _text(sys.get("object_id")),
            "vendor": guess_vendor(descr, _text(sys.get("object_id"))),
        }
        if isinstance(sys.get("uptime"), int):
            snap.metrics["uptime_s"] = sys["uptime"] / 100

        snap.interfaces = await self._interfaces()
        await self._cpu_mem(snap)
        await self._temperature(snap)
        if self.opt("lldp") not in (False, "false", 0):
            snap.neighbors = await self._lldp()
        vlans = await self.safe_walk(VLAN_NAMES)
        if vlans:
            snap.sections.append(Section(
                id="vlans", title="VLANs", columns=["VLAN ID", "Name"],
                rows=sorted(([int(k), _text(v)] for k, v in vlans.items() if k.isdigit()), key=lambda r: r[0]),
            ))
        if snap.neighbors:
            snap.sections.append(Section(
                id="lldp", title="LLDP neighbors", columns=["Local port", "Neighbor", "Remote port", "Address"],
                rows=[[n.local_port, n.remote_name, n.remote_port, n.remote_ip or n.remote_mac] for n in snap.neighbors],
            ))
        return snap

    async def _interfaces(self) -> list[Interface]:
        cols = dict(zip(IF.keys(), await asyncio.gather(*(self.safe_walk(o) for o in IF.values())), strict=True))
        ignore = self.opt("ignore_interfaces") or ""
        ignore_re = re.compile(ignore) if ignore else None
        result: list[Interface] = []
        for idx in sorted(cols["descr"].keys() | cols["name"].keys(), key=lambda x: int(x) if x.isdigit() else 0):
            name = _text(cols["name"].get(idx)) or _text(cols["descr"].get(idx)) or f"if{idx}"
            iftype = cols["type"].get(idx)
            if iftype == 24 or (ignore_re and ignore_re.match(name)):
                continue
            high = cols["high_speed"].get(idx)
            speed = float(high) if isinstance(high, int) and high > 0 else (
                cols["speed"].get(idx, 0) / 1e6 if isinstance(cols["speed"].get(idx), int) else None)
            mac = cols["mac"].get(idx)
            result.append(Interface(
                name=name,
                alias=_text(cols["alias"].get(idx)),
                index=int(idx) if idx.isdigit() else None,
                oper_up=cols["oper"].get(idx) == 1 if idx in cols["oper"] else None,
                admin_up=cols["admin"].get(idx) == 1 if idx in cols["admin"] else None,
                speed_mbps=speed or None,
                mac=norm_mac(mac.hex()) if isinstance(mac, bytes) and len(mac) == 6 else "",
                media=IFTYPE_MEDIA.get(iftype, "other") if isinstance(iftype, int) else "",
                in_octets=cols["in_oct"].get(idx, cols["in_oct32"].get(idx)),
                out_octets=cols["out_oct"].get(idx, cols["out_oct32"].get(idx)),
                in_errors=cols["in_err"].get(idx),
                out_errors=cols["out_err"].get(idx),
                in_discards=cols["in_disc"].get(idx),
                out_discards=cols["out_disc"].get(idx),
                extra={"counter_bits": 64 if idx in cols["in_oct"] else 32},
            ))
        return result

    async def _cpu_mem(self, snap: Snapshot) -> None:
        cpus = [v for v in (await self.safe_walk(HR_CPU)).values() if isinstance(v, int)]
        if cpus:
            snap.metrics["cpu"] = sum(cpus) / len(cpus)
        else:
            for oid in (HP_CPU,):
                try:
                    v = (await self.get(oid)).get(oid)
                except Exception:  # noqa: BLE001
                    v = None
                if isinstance(v, int):
                    snap.metrics["cpu"] = float(v)
                    break
            if "cpu" not in snap.metrics:
                for tbl in (TPLINK_CPU, CISCO_CPU_1M):
                    vals = [v for v in (await self.safe_walk(tbl)).values() if isinstance(v, int)]
                    if vals:
                        snap.metrics["cpu"] = sum(vals) / len(vals)
                        break
            if "cpu" not in snap.metrics:
                try:
                    idle = (await self.get(UCD_CPU_IDLE)).get(UCD_CPU_IDLE)
                    if isinstance(idle, int):
                        snap.metrics["cpu"] = float(100 - idle)
                except Exception:  # noqa: BLE001
                    pass

        storage = await self.safe_walk(HR_STORAGE)
        for key, typ in storage.items():
            if key.startswith("2.") and typ == HR_RAM_TYPE:
                i = key[2:]
                size, used = storage.get(f"5.{i}"), storage.get(f"6.{i}")
                if isinstance(size, int) and size > 0 and isinstance(used, int):
                    # net-snmp "Physical memory" includes buffers/cache; prefer UCD below when present
                    snap.metrics["mem"] = used / size * 100
                    snap.metrics["mem_total_b"] = size * (storage.get(f"4.{i}") or 1)
                    break
        try:
            ucd = await self.get(UCD_MEM_TOTAL, UCD_MEM_AVAIL, UCD_MEM_BUF, UCD_MEM_CACHED, UCD_LOAD1)
        except Exception:  # noqa: BLE001
            ucd = {}
        total, avail = ucd.get(UCD_MEM_TOTAL), ucd.get(UCD_MEM_AVAIL)
        if isinstance(total, int) and total > 0 and isinstance(avail, int):
            reclaim = sum(v for v in (ucd.get(UCD_MEM_BUF), ucd.get(UCD_MEM_CACHED)) if isinstance(v, int))
            snap.metrics["mem"] = max(0.0, (total - avail - reclaim) / total * 100)
            snap.metrics["mem_total_b"] = total * 1024
        load = ucd.get(UCD_LOAD1)
        if load is not None:
            try:
                snap.metrics["load1"] = float(load)
            except (TypeError, ValueError):
                pass
        if "mem" not in snap.metrics:
            hp = await self.safe_walk(HP_MEM)
            total = sum(v for k, v in hp.items() if k.startswith("5.") and isinstance(v, int))
            alloc = sum(v for k, v in hp.items() if k.startswith("7.") and isinstance(v, int))
            if total:
                snap.metrics["mem"] = alloc / total * 100
            else:
                vals = [v for v in (await self.safe_walk(TPLINK_MEM)).values() if isinstance(v, int)]
                if vals:
                    snap.metrics["mem"] = sum(vals) / len(vals)

    async def _temperature(self, snap: Snapshot) -> None:
        types = await self.safe_walk(ENT_SENSOR_TYPE)
        celsius = [k for k, t in types.items() if t == 8]
        if not celsius:
            return
        values = await self.safe_walk(ENT_SENSOR_VALUE)
        temps = [values[k] for k in celsius if isinstance(values.get(k), int) and 0 < values[k] < 150]
        if temps:
            snap.metrics["temp"] = float(max(temps))

    async def _lldp(self) -> list[Neighbor]:
        rem = await self.safe_walk(LLDP_REM)
        if not rem:
            return []
        loc = await self.safe_walk(LLDP_LOC_PORT)
        man = await self.safe_walk(LLDP_REM_MAN)
        ips: dict[str, str] = {}
        for idx in man:
            parts = idx.split(".")
            # timeMark.localPort.remIndex.addrSubtype(1=ipv4).len.a.b.c.d
            if len(parts) >= 9 and parts[3] == "1" and parts[4] == "4":
                ips[".".join(parts[:3])] = ".".join(parts[5:9])
        neighbors: dict[str, Neighbor] = {}
        for key, val in rem.items():
            col, _, idx = key.partition(".")
            parts = idx.split(".")
            if len(parts) < 3:
                continue
            local = parts[1]
            n = neighbors.setdefault(idx, Neighbor(
                local_port=_text(loc.get(f"4.{local}")) or _text(loc.get(f"3.{local}")) or local,
                remote_ip=ips.get(idx, ""),
            ))
            if col == "5":
                n.remote_mac = _text(val) if isinstance(val, bytes) and len(val) == 6 else ""
                if not n.remote_mac and not n.remote_name:
                    n.remote_name = _text(val)
            elif col == "7":
                n.remote_port = n.remote_port or _text(val)
            elif col == "8" and _text(val):
                n.remote_port = _text(val)
            elif col == "9" and _text(val):
                n.remote_name = _text(val)
        return list(neighbors.values())

    async def close(self) -> None:
        try:
            self._engine.close_dispatcher()
        except Exception:  # noqa: BLE001
            pass


def guess_vendor(descr: str, oid: str) -> str:
    d = descr.lower()
    for needle, vendor in (
        ("procurve", "HP ProCurve"), ("aruba", "HPE Aruba"), ("hewlett", "HP"), ("tp-link", "TP-Link"),
        ("jetstream", "TP-Link"), ("ubiquiti", "Ubiquiti"), ("unifi", "Ubiquiti"), ("edgeswitch", "Ubiquiti"),
        ("usw", "Ubiquiti"), ("cisco", "Cisco"), ("mikrotik", "MikroTik"), ("routeros", "MikroTik"),
        ("pfsense", "pfSense"), ("opnsense", "OPNsense"), ("freebsd", "FreeBSD"), ("synology", "Synology"),
        ("linux", "Linux"), ("windows", "Microsoft"), ("netgear", "Netgear"), ("juniper", "Juniper"),
    ):
        if needle in d:
            return vendor
    enterprise = {"11": "HP", "11863": "TP-Link", "41112": "Ubiquiti", "4413": "Ubiquiti", "9": "Cisco",
                  "14988": "MikroTik", "12325": "FreeBSD", "8072": "net-snmp", "6574": "Synology"}
    m = re.match(r"^1\.3\.6\.1\.4\.1\.(\d+)", oid)
    return enterprise.get(m.group(1), "") if m else ""
