"""DHCP insights.

Leases (pfSense / OPNsense) and controller client lists (UniFi), as normalized
into each snapshot's client inventory by services/clients.py, are correlated into one normalized client table, then checked for:

* IP conflicts        - one IP actively held by more than one MAC
* address hopping     - one MAC that used many IPs in 24 h
* duplicate hostnames - one hostname on more than one MAC
* multiple DHCP servers handing out leases in the same /24 (from server log lines)
* rogue DHCP indicators and NAK storms in logs
* brand-new devices    - a MAC never seen before (after a short learning period)
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, update

from ..collectors.base import Snapshot, norm_mac
from ..config import get_settings
from ..db import sessionmaker, with_retry
from ..models import DhcpClient
from ..security_parsers import parse_dhcp, valid_ip
from .alerts import Condition
from .alerts import engine as alerts

log = logging.getLogger("networkvision.dhcp")

STATEFUL_PREFIXES = ("dhcp:ipconflict:", "dhcp:macips:", "dhcp:duphost:", "dhcp:multi:")
INACTIVE_STATES = {"expired", "free", "released", "abandoned", "backup", "reset", "declined"}
GENERIC_HOSTNAMES = {"", "*", "-", "localhost", "unknown", "android", "iphone", "ipad", "espressif", "esp", "none",
                     "(null)", "null", "client", "device", "host"}
PERSIST_EVERY = 300  # seconds between last_seen writes for an unchanged pair
PERSIST_BATCH = 200  # rows per transaction - keeps Galera write sets small
SERVER_WINDOW = 3600
NAK_WINDOW, NAK_THRESHOLD = 600, 10


@dataclass
class Obs:
    mac: str
    ip: str
    hostname: str
    source: str  # lease | controller
    device_id: int
    active: bool = True


def extract(device_id: int, snap: Snapshot) -> list[Obs]:
    """(MAC, IP, hostname) observations from a device's client inventory (see services/clients.py).

    Lease records come from pfSense/OPNsense, controller records from UniFi; both are
    already normalized by the collectors, so no table parsing happens here.
    """
    out: list[Obs] = []
    for c in snap.clients:
        mac, ip = norm_mac(c.get("mac") or ""), str(c.get("ip") or "").strip()
        if not mac or len(mac) != 17 or not valid_ip(ip):
            continue
        sources = c.get("sources") or []
        if "dhcp" in sources:
            source = "lease"
            active = str((c.get("lease") or {}).get("state") or "").lower() not in INACTIVE_STATES
        else:
            source = "controller"
            active = bool(c.get("online"))
        host = str(c.get("hostname") or c.get("name") or "").strip()
        out.append(Obs(mac, ip, host[:128], source, device_id, active))
    return out


def _subnet(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _host_key(h: str) -> str:
    return re.split(r"[.\s]", h.strip().lower(), maxsplit=1)[0] if h else ""


class DhcpInsights:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, Any]] = {}  # (mac, ip) -> row cache
        self.known_macs: set[str] = set()
        self.current: dict[int, list[Obs]] = {}  # device_id -> latest active observations
        self.issues: list[dict[str, Any]] = []
        self.started = time.time()
        self.first_data: float | None = None
        self.servers: dict[str, dict[str, float]] = defaultdict(dict)  # subnet -> server -> last seen
        self.naks: deque[float] = deque(maxlen=1000)

    async def load(self) -> None:
        async with sessionmaker()() as db:
            for r in (await db.execute(select(DhcpClient))).scalars().all():
                self.rows[(r.mac, r.ip)] = {"id": r.id, "mac": r.mac, "ip": r.ip, "hostname": r.hostname, "source": r.source,
                                            "source_device_id": r.source_device_id, "first_seen": r.first_seen,
                                            "last_seen": r.last_seen, "persisted": r.last_seen, "known": r.known,
                                            "label": r.label}
                self.known_macs.add(r.mac)
        if self.rows:
            self.first_data = min(r["first_seen"] for r in self.rows.values())

    def learning(self) -> bool:
        s = get_settings()
        hours = 0.05 if s.demo_mode else s.dhcp_learning_hours
        return self.first_data is None or time.time() - self.first_data < hours * 3600

    # ------------------------------------------------------------- observe
    async def observe(self, device_id: int, snap: Snapshot) -> None:
        if not get_settings().dhcp_enabled:
            return
        obs = extract(device_id, snap)
        if not obs and device_id not in self.current:
            return
        now = time.time()
        if self.first_data is None and obs:
            self.first_data = now
        learning = self.learning()
        new_rows: list[dict[str, Any]] = []
        touched: list[dict[str, Any]] = []
        new_devices: list[Obs] = []
        for o in obs:
            row = self.rows.get((o.mac, o.ip))
            if row is None:
                row = {"id": None, "mac": o.mac, "ip": o.ip, "hostname": o.hostname, "source": o.source,
                       "source_device_id": device_id, "first_seen": now, "last_seen": now, "persisted": 0.0,
                       "known": o.mac in self.known_macs and any(r["known"] for (m, _), r in self.rows.items() if m == o.mac),
                       "label": ""}
                self.rows[(o.mac, o.ip)] = row
                new_rows.append(row)
                if o.mac not in self.known_macs:
                    self.known_macs.add(o.mac)
                    if not learning and o.active:
                        new_devices.append(o)
            else:
                row["last_seen"] = now
                if o.hostname and o.hostname != row["hostname"]:
                    row["hostname"] = o.hostname
                    row["persisted"] = 0.0
                if now - row["persisted"] > PERSIST_EVERY:
                    touched.append(row)
        self.current[device_id] = [o for o in obs if o.active]
        await self._persist(new_rows, touched, now)
        for o in new_devices[:20]:
            await alerts.raise_event(
                None, f"dhcp:new:{o.mac}", f"New device on the network: {o.hostname or o.mac}",
                f"{o.mac} got {o.ip} (seen via {'DHCP lease' if o.source == 'lease' else 'controller'})",
                severity="info", ttl=86400, rule="dhcp_new_device")
        await self.analyze()

    async def _persist(self, new_rows: list[dict], touched: list[dict], now: float) -> None:
        """Write new pairs and refreshed last_seen values in small, retried transactions (Galera-safe)."""
        for i in range(0, len(new_rows), PERSIST_BATCH):
            chunk = new_rows[i:i + PERSIST_BATCH]

            async def _insert(db, chunk=chunk) -> list[int]:
                objs = [DhcpClient(mac=r["mac"], ip=r["ip"], hostname=r["hostname"], source=r["source"],
                                   source_device_id=r["source_device_id"], first_seen=r["first_seen"],
                                   last_seen=r["last_seen"], known=r["known"]) for r in chunk]
                db.add_all(objs)
                await db.commit()
                return [o.id for o in objs]

            for r, rid in zip(chunk, await with_retry(_insert), strict=True):
                r["id"], r["persisted"] = rid, now
        rows = [r for r in touched if r["id"] is not None]
        for i in range(0, len(rows), PERSIST_BATCH):
            chunk = rows[i:i + PERSIST_BATCH]

            async def _touch(db, chunk=chunk) -> None:
                for r in chunk:
                    await db.execute(update(DhcpClient).where(DhcpClient.id == r["id"]).values(
                        last_seen=r["last_seen"], hostname=r["hostname"]))
                await db.commit()

            await with_retry(_touch)
            for r in chunk:
                r["persisted"] = now

    # -------------------------------------------------------------- analyze
    async def analyze(self) -> None:
        s = get_settings()
        now = time.time()
        active = [o for lst in self.current.values() for o in lst]
        issues: list[dict[str, Any]] = []
        conds: list[Condition] = []

        def member(o: Obs) -> dict[str, Any]:
            return {"mac": o.mac, "ip": o.ip, "hostname": o.hostname, "source": o.source, "device_id": o.device_id}

        by_ip: dict[str, dict[str, Obs]] = defaultdict(dict)
        by_host: dict[str, dict[str, Obs]] = defaultdict(dict)
        for o in active:
            by_ip[o.ip][o.mac] = o
            hk = _host_key(o.hostname)
            if hk not in GENERIC_HOSTNAMES and len(hk) > 1:
                by_host[hk][o.mac] = o

        for ip, macs in by_ip.items():
            if len(macs) > 1:
                key = f"dhcp:ipconflict:{ip}"
                detail = " vs ".join(f"{m} ({o.hostname or '?'})" for m, o in macs.items())
                conds.append(Condition(key, "dhcp_ip_conflict", "warning", f"IP conflict on {ip}", detail, False))
                issues.append({"key": key, "type": "ip_conflict", "severity": "warning", "title": f"IP conflict on {ip}",
                               "detail": f"{len(macs)} different devices claim this address", "subject": ip,
                               "members": [member(o) for o in macs.values()]})

        for host, macs in by_host.items():
            if len(macs) > 1:
                key = f"dhcp:duphost:{host}"
                name = next(iter(macs.values())).hostname
                conds.append(Condition(key, "dhcp_duplicate_hostname", "info", f"Duplicate hostname “{name}”",
                                       ", ".join(f"{m} @ {o.ip}" for m, o in macs.items()), False))
                issues.append({"key": key, "type": "duplicate_hostname", "severity": "info",
                               "title": f"Duplicate hostname “{name}”", "detail": f"{len(macs)} MACs use this name",
                               "subject": name, "members": [member(o) for o in macs.values()]})

        day = now - 86400
        ips_by_mac: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in self.rows.values():
            if r["last_seen"] >= day:
                ips_by_mac[r["mac"]].append(r)
        for mac, rows in ips_by_mac.items():
            ips = {r["ip"] for r in rows}
            if len(ips) >= s.dhcp_mac_max_ips:
                host = next((r["hostname"] for r in rows if r["hostname"]), "")
                key = f"dhcp:macips:{mac}"
                conds.append(Condition(key, "dhcp_address_hopping", "info", f"{host or mac} used {len(ips)} IPs today",
                                       ", ".join(sorted(ips)), False))
                issues.append({"key": key, "type": "address_hopping", "severity": "info",
                               "title": f"{host or mac} used {len(ips)} IPs in 24h",
                               "detail": "Short leases, roaming between VLANs, or a static/DHCP mismatch",
                               "subject": mac,
                               "members": [{"mac": mac, "ip": r["ip"], "hostname": r["hostname"], "source": r["source"],
                                            "device_id": r["source_device_id"]} for r in rows]})

        for subnet, servers in list(self.servers.items()):
            for srv, seen in list(servers.items()):
                if now - seen > SERVER_WINDOW:
                    servers.pop(srv)
            if len(servers) > 1:
                key = f"dhcp:multi:{subnet}"
                names = ", ".join(sorted(servers))
                conds.append(Condition(key, "dhcp_multiple_servers", "warning", f"Multiple DHCP servers on {subnet}",
                                       f"Leases handed out by: {names}", False))
                issues.append({"key": key, "type": "multiple_servers", "severity": "warning",
                               "title": f"Multiple DHCP servers on {subnet}", "detail": f"Leases handed out by: {names}",
                               "subject": subnet, "members": [{"server": n, "last_seen": t} for n, t in servers.items()]})

        rank = {"warning": 0, "info": 1}
        self.issues = sorted(issues, key=lambda i: rank.get(i["severity"], 2))
        await alerts.sync_group(STATEFUL_PREFIXES, conds)

    # ----------------------------------------------------------------- logs
    async def ingest_logs(self, batch: list[dict[str, Any]]) -> None:
        if not get_settings().dhcp_enabled:
            return
        now = time.time()
        for e in batch:
            msg = e.get("message", "")
            if "DHCP" not in msg and "dhcp" not in msg.lower() and "lease" not in msg:
                continue
            ev = parse_dhcp(msg)
            if ev is None:
                continue
            server = str(e.get("host") or e.get("device_id") or "?")
            if ev.kind == "ack" and ev.ip:
                self.servers[_subnet(ev.ip)][server] = now
            elif ev.kind == "rogue":
                await alerts.raise_event(
                    e.get("device_id"), f"dhcp:rogue:{ev.server or server}", "Rogue DHCP server detected",
                    f"{ev.server or 'unknown server'} reported by {server}: {msg[:200]}",
                    severity="warning", ttl=3600, rule="dhcp_rogue_server")
            elif ev.kind == "nak":
                self.naks.append(now)
                recent = sum(1 for t in self.naks if now - t < NAK_WINDOW)
                if recent >= NAK_THRESHOLD:
                    await alerts.raise_event(
                        None, "dhcp:nak:storm", "DHCPNAK storm",
                        f"{recent} DHCPNAKs in {NAK_WINDOW // 60} min — possible rogue DHCP server or overlapping scopes",
                        severity="warning", ttl=1800, rule="dhcp_nak_storm")

    # ------------------------------------------------------------------ api
    def clients(self) -> list[dict[str, Any]]:
        active_pairs = {(o.mac, o.ip) for lst in self.current.values() for o in lst}
        conflict_ips = {i["subject"] for i in self.issues if i["type"] == "ip_conflict"}
        sources: dict[tuple[str, str], set[str]] = defaultdict(set)
        for lst in self.current.values():
            for o in lst:
                sources[(o.mac, o.ip)].add(o.source)
        out = []
        for (mac, ip), r in self.rows.items():
            out.append({k: r[k] for k in ("id", "mac", "ip", "hostname", "source", "source_device_id", "first_seen",
                                          "last_seen", "known", "label")}
                       | {"active": (mac, ip) in active_pairs, "conflict": ip in conflict_ips,
                          "seen_by": sorted(sources.get((mac, ip), set()) or {r["source"]})})
        return sorted(out, key=lambda r: (not r["active"], _ip_sort(r["ip"])))

    async def set_known(self, mac: str, known: bool, label: str | None) -> int:
        mac = norm_mac(mac)
        n = 0
        for (m, _), r in self.rows.items():
            if m == mac:
                r["known"] = known
                if label is not None:
                    r["label"] = label[:128]
                n += 1
        if n:
            values: dict[str, Any] = {"known": known}
            if label is not None:
                values["label"] = label[:128]

            async def _mark(db) -> None:
                await db.execute(update(DhcpClient).where(DhcpClient.mac == mac).values(**values))
                await db.commit()

            await with_retry(_mark)
        return n

    def prune(self, before: float) -> None:
        for key in [k for k, r in self.rows.items() if r["last_seen"] < before]:
            self.rows.pop(key, None)


def _ip_sort(ip: str) -> tuple:
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


dhcp = DhcpInsights()
