"""Firewall log explorer API: search, timeline and top-N aggregations over firewall_events.

Every endpoint takes the same filter set. List filters accept several values and a
leading ``!`` excludes instead of includes (``action=!pass``, ``iface=!INTERNET``).
IP filters accept an address or a CIDR (``src=10.10.20.0/24``, ``dst=2001:db8::/32``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, and_, case, cast, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import get_session
from ..filterlog import cidr_key_range
from ..models import FirewallEvent as FE
from ..models import FirewallMinute as FM
from ..security import require_user
from ..services.firewall import firewall

router = APIRouter(prefix="/api/firewall", tags=["firewall"], dependencies=[Depends(require_user)])

RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
BLOCKED = ("block", "reject")


@dataclass
class Filters:
    since: float
    until: float
    conds: list[Any]
    simple: bool  # only time / action / interface / device: answerable from firewall_minutes
    devices: list[int] | None = None
    actions: tuple[list[str], list[str]] = ([], [])
    ifaces: list[str] | None = None


def _split(values: list[str] | None) -> tuple[list[str], list[str]]:
    inc: list[str] = []
    exc: list[str] = []
    for raw in values or []:
        for v in str(raw).split(","):
            v = v.strip()
            if not v or v == "!":
                continue
            (exc if v.startswith("!") else inc).append(v.lstrip("!"))
    return inc, exc


def _in_out(col: Any, values: list[str] | None, conv=lambda x: x) -> list[Any]:
    inc, exc = _split(values)
    out = []
    try:
        if inc:
            out.append(col.in_([conv(v) for v in inc]))
        if exc:
            out.append(or_(col.is_(None), col.not_in([conv(v) for v in exc])))
    except ValueError as e:
        raise HTTPException(400, f"bad filter value: {e}") from e
    return out


def _ip_cond(key_col: Any, value: str) -> Any:
    rng = cidr_key_range(value)
    if rng is None:
        raise HTTPException(400, f"not an IP address or CIDR: {value}")
    lo, hi = rng
    return key_col == lo if lo == hi else key_col.between(lo, hi)


def _ip_filters(cols: list[Any], values: list[str] | None) -> list[Any]:
    inc, exc = _split(values)
    out = []
    if inc:
        out.append(or_(*[_ip_cond(c, v) for v in inc for c in cols]))
    for v in exc:
        out.append(and_(*[not_(_ip_cond(c, v)) for c in cols]))
    return out


def build_filters(
    since: float | None = None, until: float | None = None, range_: str = Query("1h", alias="range"),
    device_id: list[int] | None = Query(default=None), action: list[str] | None = Query(default=None),
    direction: str | None = None, iface: list[str] | None = Query(default=None), rule: list[str] | None = Query(default=None),
    proto: list[str] | None = Query(default=None), src: list[str] | None = Query(default=None),
    dst: list[str] | None = Query(default=None), ip: list[str] | None = Query(default=None),
    port: list[str] | None = Query(default=None), sport: list[str] | None = Query(default=None),
    ipver: int | None = None, hide_noise: bool = False, q: str | None = None,
) -> Filters:
    now = time.time()
    until_ = until or now
    since_ = since if since is not None else until_ - RANGES.get(range_, 3600)
    if since_ >= until_:
        raise HTTPException(400, "since must be before until")
    conds: list[Any] = [FE.ts >= since_, FE.ts <= until_]
    if device_id:
        conds.append(FE.device_id.in_(device_id))
    conds += _in_out(FE.action, action, str.lower)
    if direction:
        conds.append(FE.direction == direction.lower())
    simple = not any((direction, rule, proto, src, dst, ip, port, sport, ipver, hide_noise, q))
    # An interface filter matches the friendly name or the raw NIC.
    inc, exc = _split(iface)
    if inc:
        conds.append(or_(FE.iface_name.in_(inc), FE.iface.in_(inc)))
    if exc:
        conds.append(and_(FE.iface_name.not_in(exc), FE.iface.not_in(exc)))
    if exc:
        simple = False
    conds += _in_out(FE.rule_id, rule)
    conds += _in_out(FE.proto, proto, str.lower)
    conds += _ip_filters([FE.src_key], src)
    conds += _ip_filters([FE.dst_key], dst)
    conds += _ip_filters([FE.src_key, FE.dst_key], ip)
    conds += _in_out(FE.dst_port, port, int)
    conds += _in_out(FE.src_port, sport, int)
    if ipver in (4, 6):
        conds.append(FE.ipver == ipver)
    if hide_noise:
        conds.append(FE.noise.is_(False))
    for term in (q or "").split():
        neg = term.startswith("-") and len(term) > 1
        like = f"%{term.lstrip('-')}%"
        hit = or_(FE.rule.like(like), FE.rule_id.like(like), FE.src_ip.like(like), FE.dst_ip.like(like),
                  FE.iface_name.like(like), FE.iface.like(like), FE.proto.like(like), FE.info.like(like))
        conds.append(not_(hit) if neg else hit)
    acts = _split(action)
    return Filters(since_, until_, conds, simple, device_id, ([a.lower() for a in acts[0]], [a.lower() for a in acts[1]]), inc)


def _event(r: FE) -> dict[str, Any]:
    return {
        "id": r.id, "ts": r.ts, "device_id": r.device_id, "action": r.action, "direction": r.direction,
        "iface": r.iface, "iface_name": r.iface_name, "rule_id": r.rule_id, "rule": r.rule, "ipver": r.ipver,
        "proto": r.proto, "src_ip": r.src_ip, "src_port": r.src_port, "dst_ip": r.dst_ip, "dst_port": r.dst_port,
        "tcp_flags": r.tcp_flags, "length": r.length, "info": r.info, "noise": r.noise,
    }


def _cursor(c: str | None) -> tuple[float, int] | None:
    if not c:
        return None
    try:
        ts, _, id_ = c.partition(":")
        return float(ts), int(id_)
    except ValueError as e:
        raise HTTPException(400, "bad cursor") from e


# --------------------------------------------------------------------- search
@router.get("/events")
async def events(
    f: Filters = Depends(build_filters), limit: int = Query(200, ge=1, le=1000), cursor: str | None = None,
    count: bool = True, db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Newest first, keyset paginated: pass ``next_cursor`` back as ``cursor`` for older rows."""
    conds = list(f.conds)
    if (cur := _cursor(cursor)) is not None:
        conds.append(or_(FE.ts < cur[0], and_(FE.ts == cur[0], FE.id < cur[1])))
    rows = (await db.execute(select(FE).where(and_(*conds)).order_by(FE.ts.desc(), FE.id.desc()).limit(limit + 1))).scalars().all()
    more = len(rows) > limit
    rows = rows[:limit]
    out: dict[str, Any] = {
        "items": [_event(r) for r in rows],
        "next_cursor": f"{rows[-1].ts!r}:{rows[-1].id}" if more and rows else None,
        "since": f.since, "until": f.until,
    }
    if count and cursor is None:
        cap = 100_000  # an exact count over millions of rows is not worth the wait
        sub = select(FE.id).where(and_(*f.conds)).limit(cap + 1).subquery()
        total = (await db.execute(select(func.count()).select_from(sub))).scalar() or 0
        out.update(total=min(total, cap), total_capped=total > cap)
    return out


@router.get("/events/{event_id}")
async def event(event_id: int, db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    r = await db.get(FE, event_id)
    if r is None:
        raise HTTPException(404, "event not found")
    return _event(r)


# ------------------------------------------------------------------- timeline
def _bucket(db: AsyncSession, col: Any, step: int) -> Any:
    return cast(col / step, Integer) if db.bind.dialect.name == "sqlite" else func.floor(col / step)


def _group(action: str) -> str:
    return "block" if action in BLOCKED else ("pass" if action == "pass" else "other")


@router.get("/timeline")
async def timeline(f: Filters = Depends(build_filters), points: int = Query(120, ge=10, le=600),
                   db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Event counts per bucket split into pass / block / other.

    Unfiltered views (time, action, interface, device only) come from the per-minute counters, which
    include events that were counted but not stored; anything finer is counted from stored rows.
    """
    span = f.until - f.since
    step = max(60 if f.simple else 1, int(span // points) or 1)
    if f.simple:
        step = max(60, (step // 60) * 60)
    first = int(f.since // step)
    buckets: dict[int, dict[str, int]] = {}

    def add(b: int, action: str, n: int, skipped: int = 0) -> None:
        slot = buckets.setdefault(b, {"pass": 0, "block": 0, "other": 0, "skipped": 0})
        slot[_group(action)] += n
        slot["skipped"] += skipped

    if f.simple:
        mconds: list[Any] = [FM.ts >= int(f.since // 60) * 60, FM.ts <= f.until]
        if f.devices:
            mconds.append(FM.device_id.in_(f.devices))
        if f.actions[0]:
            mconds.append(FM.action.in_(f.actions[0]))
        if f.actions[1]:
            mconds.append(FM.action.not_in(f.actions[1]))
        if f.ifaces:
            mconds.append(FM.iface_name.in_(f.ifaces))
        stmt = (select(_bucket(db, FM.ts, step).label("b"), FM.action, func.sum(FM.events), func.sum(FM.skipped))
                .where(and_(*mconds)).group_by("b", FM.action))
        for b, action, n, sk in (await db.execute(stmt)).all():
            add(int(b), action, int(n or 0), int(sk or 0))
        for minute, dev, action, iface_name, n, sk in firewall.pending_counts():
            if f.since - 60 < minute <= f.until and _counter_match(f, dev, action, iface_name):
                add(int(minute // step), action, n, sk)
    else:
        stmt = (select(_bucket(db, FE.ts, step).label("b"), FE.action, func.count())
                .where(and_(*f.conds)).group_by("b", FE.action))
        for b, action, n in (await db.execute(stmt)).all():
            add(int(b), action, int(n))
    empty = {"pass": 0, "block": 0, "other": 0, "skipped": 0}
    n_buckets = int(span // step) + 1
    series = [{"ts": (first + i) * step, **buckets.get(first + i, empty)} for i in range(n_buckets)]
    return {"since": f.since, "until": f.until, "step": step, "source": "counters" if f.simple else "events",
            "series": series}


def _counter_match(f: Filters, dev: int | None, action: str, iface_name: str) -> bool:
    return ((not f.devices or dev in f.devices) and (not f.actions[0] or action in f.actions[0])
            and action not in f.actions[1] and (not f.ifaces or iface_name in f.ifaces))


# ---------------------------------------------------------------------- stats
async def _top(db: AsyncSession, conds: list[Any], cols: list[Any], limit: int) -> list[Any]:
    blocked = func.sum(case((FE.action.in_(BLOCKED), 1), else_=0))
    stmt = (select(*cols, func.count().label("n"), blocked.label("blocked"), func.max(FE.ts).label("last"))
            .where(and_(*conds)).group_by(*cols).order_by(func.count().desc()).limit(limit))
    return list((await db.execute(stmt)).all())


@router.get("/stats")
async def stats(f: Filters = Depends(build_filters), limit: int = Query(10, ge=1, le=100),
                db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    c = f.conds
    actions = (await db.execute(select(FE.action, func.count()).where(and_(*c)).group_by(FE.action))).all()
    sources = await _top(db, c, [FE.src_ip], limit)
    blocked_sources = await _top(db, [*c, FE.action.in_(BLOCKED)], [FE.src_ip], limit)
    dests = await _top(db, c, [FE.dst_ip], limit)
    ports = await _top(db, [*c, FE.dst_port.is_not(None)], [FE.dst_port, FE.proto], limit)
    rules = await _top(db, c, [FE.rule_id, FE.rule], limit)
    ifaces = await _top(db, c, [FE.iface_name], 50)
    protos = await _top(db, c, [FE.proto], 12)
    return {
        "since": f.since, "until": f.until,
        "actions": {a: n for a, n in actions},
        "top_sources": [{"ip": r[0], "count": r.n, "blocked": int(r.blocked or 0), "last": r.last} for r in sources],
        "top_blocked_sources": [{"ip": r[0], "count": r.n, "blocked": int(r.blocked or 0), "last": r.last} for r in blocked_sources],
        "top_destinations": [{"ip": r[0], "count": r.n, "blocked": int(r.blocked or 0), "last": r.last} for r in dests],
        "top_ports": [{"port": r[0], "proto": r[1], "count": r.n, "blocked": int(r.blocked or 0)} for r in ports],
        "top_rules": [{"rule_id": r[0], "rule": r[1], "count": r.n, "blocked": int(r.blocked or 0)} for r in rules],
        "interfaces": [{"iface": r[0], "count": r.n, "blocked": int(r.blocked or 0)} for r in ifaces],
        "protocols": [{"proto": r[0], "count": r.n, "blocked": int(r.blocked or 0)} for r in protos],
    }


@router.get("/facets")
async def facets(db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Values for the filter bar: interfaces and rules seen in the last 24 h, plus ingest health."""
    since = time.time() - 86400
    ifaces = (await db.execute(select(FE.iface_name, func.count()).where(FE.ts >= since)
                               .group_by(FE.iface_name).order_by(func.count().desc()).limit(50))).all()
    rules = (await db.execute(select(FE.rule_id, FE.rule, func.count()).where(FE.ts >= since)
                              .group_by(FE.rule_id, FE.rule).order_by(func.count().desc()).limit(100))).all()
    s = get_settings()
    return {
        "interfaces": [{"iface": i, "count": n} for i, n in ifaces if i],
        "rules": [{"rule_id": r, "rule": d, "count": n} for r, d, n in rules],
        "ingest": {**firewall.stats, "buffered": len(firewall.buffer)},
        "settings": {"store_pass": s.firewall_store_pass, "store_noise": s.firewall_store_noise,
                     "keep_raw_logs": s.firewall_keep_raw_logs, "retention_days": s.retention_days_firewall,
                     "enabled": s.firewall_enabled},
    }
