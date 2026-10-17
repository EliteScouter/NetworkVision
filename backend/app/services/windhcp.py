"""Windows DHCP audit: checks that need the whole picture, not one lease table.

Fed by the Windows DHCP collector (``Snapshot.dhcp_server``) and the DHCP insights'
active observations from every other source (UniFi clients, pfSense/OPNsense leases):

* failover health      - a relationship not in Normal state (CommunicationInterrupted, PartnerDown...)
* configuration drift  - failover replicates leases, not configuration: scope options, ranges,
                         exclusions, reservations and server options compared between partners
* scope exhaustion     - scopes above the warning / critical utilization thresholds
* BAD_ADDRESS          - addresses Windows' conflict detection found already in use
* static IP in a pool  - a device online with an IP inside a dynamic range but holding no lease
* overlapping servers  - another DHCP server handing out leases in a Windows scope's subnet
* reservation mismatch - a reserved device that is using a different address
* unauthorized server  - DHCP server not authorized in Active Directory
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any

from ..config import get_settings
from .alerts import Condition
from .alerts import engine as alerts
from .state import store

log = logging.getLogger("networkvision.windhcp")

PREFIX = "dhcp:win:"
STALE_AFTER = 1800  # ignore a server whose last good read is older than this
BAD_STATES = {"partnerdown": "critical", "communicationinterrupted": "warning"}


def _int(ip: str) -> int | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return int(a) if a.version == 4 else None


def _ranges(scope: dict[str, Any]) -> tuple[tuple[int, int] | None, list[tuple[int, int]], ipaddress.IPv4Network | None]:
    lo, hi = _int(scope["start"]), _int(scope["end"])
    excl = []
    for x in scope.get("exclusions", []):
        a, _, b = x.partition("-")
        ea, eb = _int(a), _int(b or a)
        if ea is not None and eb is not None:
            excl.append((ea, eb))
    try:
        net = ipaddress.IPv4Network(f"{scope['id']}/{scope['mask']}", strict=False)
    except ValueError:
        net = None
    return ((lo, hi) if lo is not None and hi is not None else None), excl, net


def _in_pool(ip: int, pool: tuple[int, int] | None, excl: list[tuple[int, int]]) -> bool:
    return pool is not None and pool[0] <= ip <= pool[1] and not any(a <= ip <= b for a, b in excl)


def _opt_text(o: dict[str, Any] | None) -> str:
    return ", ".join(o["value"]) if o else "(not set)"


def diff_scope(a: dict[str, Any], b: dict[str, Any], an: str, bn: str) -> list[str]:
    """Human-readable differences between the same scope on two failover partners."""
    out: list[str] = []
    for key, label in (("start", "Range start"), ("end", "Range end"), ("mask", "Subnet mask"), ("lease_s", "Lease duration"),
                       ("state", "State")):
        if a.get(key) != b.get(key):
            out.append(f"{label}: {an} {a.get(key)} · {bn} {b.get(key)}")
    ea, eb = set(a.get("exclusions", [])), set(b.get("exclusions", []))
    for x in sorted(ea - eb):
        out.append(f"Exclusion {x} only on {an}")
    for x in sorted(eb - ea):
        out.append(f"Exclusion {x} only on {bn}")
    ra = {r["ip"]: r["mac"] for r in a.get("reservations", [])}
    rb = {r["ip"]: r["mac"] for r in b.get("reservations", [])}
    for ip in sorted(set(ra) | set(rb), key=lambda x: _int(x) or 0):
        if ip not in rb:
            out.append(f"Reservation {ip} ({ra[ip]}) only on {an}")
        elif ip not in ra:
            out.append(f"Reservation {ip} ({rb[ip]}) only on {bn}")
        elif ra[ip] != rb[ip]:
            out.append(f"Reservation {ip}: {an} {ra[ip]} · {bn} {rb[ip]}")
    out += diff_options(a.get("options", []), b.get("options", []), an, bn)
    return out


def diff_options(a: list[dict[str, Any]], b: list[dict[str, Any]], an: str, bn: str) -> list[str]:
    oa, ob = {o["id"]: o for o in a}, {o["id"]: o for o in b}
    out = []
    for oid in sorted(set(oa) | set(ob)):
        x, y = oa.get(oid), ob.get(oid)
        if x is None or y is None or x["value"] != y["value"]:
            name = (x or y)["name"] or f"Option {oid}"
            out.append(f"Option {oid} {name}: {an} {_opt_text(x)} · {bn} {_opt_text(y)}")
    return out


class WinDhcpAudit:
    def __init__(self) -> None:
        self.servers: dict[int, dict[str, Any]] = {}  # device_id -> {"name", "at", "data"}
        self.issues: list[dict[str, Any]] = []

    async def update(self, device_id: int, name: str, data: dict[str, Any]) -> None:
        self.servers[device_id] = {"name": name, "at": time.time(), "data": data}
        await self.analyze()

    def live(self) -> dict[int, dict[str, Any]]:
        now = time.time()
        return {i: s for i, s in self.servers.items()
                if now - s["at"] < STALE_AFTER and (d := store.get(i)) is not None and d.enabled}

    # ------------------------------------------------------------------ analyze
    async def analyze(self, observations: list[Any] | None = None) -> None:
        from .dhcp import dhcp  # local import: dhcp insights own the cross-source observations

        servers = self.live()
        s = get_settings()
        issues: list[dict[str, Any]] = []
        conds: list[Condition] = []

        def issue(key: str, typ: str, sev: str, title: str, detail: str, subject: str, lines: list[str],
                  device_id: int | None = None) -> None:
            conds.append(Condition(PREFIX + key, f"dhcp_{typ}", sev, title,
                                   detail + ("" if not lines else " — " + "; ".join(lines[:6])), False, device_id))
            issues.append({"key": PREFIX + key, "type": typ, "severity": sev, "title": title, "detail": detail,
                           "subject": subject, "members": [{"text": t} for t in lines[:50]]})

        # --- AD authorization
        for did, srv in servers.items():
            if srv["data"].get("authorized") is False:
                issue(f"auth:{did}", "unauthorized", "warning", f"{srv['name']} is not authorized in Active Directory",
                      "Unauthorized Windows DHCP servers stop handing out leases in a domain.", srv["name"], [], did)

        # --- failover health and drift, paired by relationship name (identical on both partners)
        rels: dict[str, list[tuple[int, dict[str, Any], dict[str, Any]]]] = {}
        for did, srv in servers.items():
            for f in srv["data"].get("failover", []):
                rels.setdefault(f["name"], []).append((did, srv, f))
        for rel, members in rels.items():
            bad = [(srv["name"], f["state"]) for _, srv, f in members if f["state"].lower() != "normal"]
            if bad:
                sev = "critical" if any(BAD_STATES.get(st.lower()) == "critical" for _, st in bad) else "warning"
                issue(f"failover:{rel}", "failover", sev, f"DHCP failover “{rel}” is not healthy",
                      "Partners can't sync leases; clients may get conflicting answers or none when one server is down.",
                      rel, [f"{n}: {st}" for n, st in bad])
            if len(members) < 2:
                continue
            (_, sa, fa), (_, sb, fb) = members[0], members[1]
            an, bn = sa["name"], sb["name"]
            scopes_a = {x["id"]: x for x in sa["data"]["scopes"]}
            scopes_b = {x["id"]: x for x in sb["data"]["scopes"]}
            for sc in sorted(set(fa["scopes"]) | set(fb["scopes"])):
                x, y = scopes_a.get(sc), scopes_b.get(sc)
                if x is None or y is None:
                    lines = [f"Scope {sc} exists only on {an if y is None else bn}"]
                else:
                    lines = diff_scope(x, y, an, bn)
                if lines:
                    issue(f"drift:{rel}:{sc}", "config_drift", "warning", f"Scope {sc} differs between {an} and {bn}",
                          "Failover replicates leases, not settings. Run “Replicate Scope” (or "
                          "Invoke-DhcpServerv4FailoverReplication) from the server with the correct config.", sc, lines)
            srv_lines = diff_options(sa["data"].get("server_options", []), sb["data"].get("server_options", []), an, bn)
            if srv_lines:
                issue(f"drift:{rel}:server", "config_drift", "info", f"Server options differ between {an} and {bn}",
                      "Server-level options are never replicated; clients get different settings depending on which "
                      "partner answers.", rel, srv_lines)

        # --- one view of every scope (failover partners report the same scope)
        scopes: dict[str, dict[str, Any]] = {}
        for srv in servers.values():
            for sc in srv["data"]["scopes"]:
                cur = scopes.get(sc["id"])
                if cur is None or sc["pct"] > cur["pct"]:
                    scopes[sc["id"]] = sc

        for sc in scopes.values():
            if sc["state"].lower() != "active" or not (sc["in_use"] + sc["free"]):
                continue
            if sc["pct"] >= s.dhcp_scope_warn_pct:
                sev = "critical" if sc["pct"] >= s.dhcp_scope_crit_pct else "warning"
                issue(f"util:{sc['id']}", "scope_full", sev, f"Scope {sc['id']} is {sc['pct']:.0f}% used",
                      f"{sc['free']} free of {sc['in_use'] + sc['free']} addresses"
                      f"{' in ' + sc['name'] if sc['name'] else ''}. New devices will fail to get an address when it fills up.",
                      sc["id"], [])

        bad: dict[str, set[str]] = {}
        for srv in servers.values():
            for b in srv["data"].get("bad", []):
                bad.setdefault(b["scope"], set()).add(b["ip"])
        for sc, ips in bad.items():
            issue(f"bad:{sc}", "bad_address", "warning", f"{len(ips)} address{'es' if len(ips) > 1 else ''} in {sc} marked BAD_ADDRESS",
                  "Windows pinged these before leasing and something answered: usually a device with a static IP "
                  "inside the pool. Find it, move it outside the range (or reserve it), then delete the BAD_ADDRESS lease.",
                  sc, sorted(ips, key=lambda x: _int(x) or 0))

        # --- cross-source checks against what's actually online
        win_ids = set(servers)
        win_pairs = {(m, ip) for srv in servers.values() for m, ip in srv["data"].get("pairs", [])}
        reserved_ip = {r["ip"]: r["mac"] for sc in scopes.values() for r in sc.get("reservations", [])}
        reserved_mac = {mac: ip for ip, mac in reserved_ip.items()}
        geo = {sid: _ranges(sc) for sid, sc in scopes.items()}
        obs = observations if observations is not None else [o for lst in dhcp.current.values() for o in lst]

        squat: dict[str, Any] = {}
        overlap: dict[str, set[str]] = {}
        ips_by_mac: dict[str, set[str]] = {}
        for o in obs:
            ips_by_mac.setdefault(o.mac, set()).add(o.ip)
            if o.device_id in win_ids:
                continue
            n = _int(o.ip)
            if n is None:
                continue
            for sid, (pool, excl, net) in geo.items():
                if o.source == "lease" and net is not None and ipaddress.IPv4Address(n) in net:
                    dev = store.get(o.device_id)
                    overlap.setdefault(sid, set()).add(dev.name if dev else str(o.device_id))
                elif o.source == "controller" and _in_pool(n, pool, excl) and (o.mac, o.ip) not in win_pairs \
                        and reserved_ip.get(o.ip) != o.mac:
                    squat[o.ip] = (o, sid)

        for sid, names in overlap.items():
            issue(f"overlap:{sid}", "server_overlap", "warning", f"Another DHCP server is handing out addresses in {sid}",
                  f"{', '.join(sorted(names))} also leases addresses in this Windows scope's subnet — two servers "
                  "on one subnet hand out conflicting addresses.", sid, sorted(names))
        for ip, (o, sid) in sorted(squat.items(), key=lambda kv: _int(kv[0]) or 0)[:50]:
            issue(f"static:{ip}", "static_in_pool", "warning", f"{o.hostname or o.mac} uses {ip} without a lease",
                  f"{ip} is inside the dynamic range of scope {sid} but Windows has no lease or reservation for it — "
                  "likely a static IP. Windows may hand this address to another device.", ip, [f"{o.mac} {o.hostname}".strip()])
        for mac, ip in reserved_mac.items():
            seen = ips_by_mac.get(mac)
            if seen and ip not in seen:
                issue(f"resv:{mac}", "reservation_mismatch", "info", f"Reserved device {mac} is using {', '.join(sorted(seen))}",
                      f"It has a reservation for {ip}. It may have a static IP or be getting its address from another server.",
                      mac, [f"Reserved {ip}", *[f"Seen with {x}" for x in sorted(seen)]])

        rank = {"critical": 0, "warning": 1, "info": 2}
        self.issues = sorted(issues, key=lambda i: rank.get(i["severity"], 3))
        await alerts.sync_group((PREFIX,), conds)

    # ---------------------------------------------------------------------- api
    def summary(self) -> list[dict[str, Any]]:
        live = self.live()
        names = {f["name"]: [i for i, s in live.items() if any(x["name"] == f["name"] for x in s["data"]["failover"])]
                 for s in live.values() for f in s["data"]["failover"]}
        out = []
        for did, srv in sorted(self.servers.items(), key=lambda kv: kv[1]["name"].lower()):
            if store.get(did) is None:  # integration removed
                continue
            d = srv["data"]
            out.append({
                "device_id": did, "name": srv["name"], "fqdn": d.get("fqdn"), "updated_at": srv["at"], "stale": did not in live,
                "authorized": d.get("authorized"), "conflict_attempts": d.get("conflict_attempts"),
                "lease_count": d.get("lease_count"), "truncated": d.get("truncated"), "bad": len(d.get("bad", [])),
                "failover": [{**f, "partner_monitored": len(names.get(f["name"], [])) > 1} for f in d.get("failover", [])],
                "scopes": [{k: sc[k] for k in ("id", "name", "mask", "start", "end", "state", "in_use", "free", "pct", "reserved",
                                               "failover")} for sc in d.get("scopes", [])],
            })
        return out


windhcp = WinDhcpAudit()
