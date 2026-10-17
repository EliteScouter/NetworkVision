"""Security and DHCP insights endpoints."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Integer, case, cast, distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import Alert, LogEntry, SecurityEvent
from ..security import require_user
from ..security_parsers import is_internal, service_name, valid_ip
from ..services.alerts import alert_dict, engine
from ..services.dhcp import dhcp
from ..services.geoip import country, geoip
from ..services.security import security
from ..services.state import store
from ..services.windhcp import windhcp

router = APIRouter(prefix="/api", tags=["insights"], dependencies=[Depends(require_user)])

RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
ATTACK = ("block", "auth_fail", "ids")
CATS = ("block", "pass", "auth_fail", "auth_ok", "ids")


def _bucket(db: AsyncSession, step: int):
    if db.bind.dialect.name == "sqlite":
        return cast(SecurityEvent.ts / step, Integer)
    return func.floor(SecurityEvent.ts / step)


def _sum_cat(cat: str | tuple[str, ...]):
    cond = SecurityEvent.category.in_(cat) if isinstance(cat, tuple) else SecurityEvent.category == cat
    return func.sum(case((cond, SecurityEvent.count), else_=0))


async def _timeline(db: AsyncSession, since: float, span: int, *conds) -> list[dict[str, Any]]:
    step = max(60, span // 72)
    b = _bucket(db, step).label("b")
    rows = (await db.execute(select(b, SecurityEvent.category, func.sum(SecurityEvent.count))
                             .where(SecurityEvent.ts >= since, *conds).group_by("b", SecurityEvent.category))).all()
    slots: dict[int, dict[str, int]] = {}
    for bk, cat, n in rows:
        slots.setdefault(int(bk), dict.fromkeys(CATS, 0))[cat] = int(n or 0)
    first = int(since // step)
    return [{"ts": (first + i) * step, **slots.get(first + i, dict.fromkeys(CATS, 0))} for i in range(span // step + 1)]


def _detection_src(key: str) -> str | None:
    """Recover the source IP from a sec:* alert key (IPv6 addresses contain colons)."""
    for prefix in ("sec:brute:", "sec:scan:"):
        if key.startswith(prefix):
            return key[len(prefix):]
    if key.startswith("sec:breach:"):
        return key[len("sec:breach:"):].rsplit(":", 1)[0]
    return None


def _device_name(device_id: int | None) -> str | None:
    d = store.get(device_id) if device_id else None
    return d.name if d else None


# ------------------------------------------------------------------ security
@router.get("/security/summary")
async def security_summary(range_: str = Query("24h", alias="range"), db: AsyncSession = Depends(get_session)) -> dict:
    await security.flush()  # include the not-yet-persisted current minute
    span = RANGES.get(range_, 86400)
    since = time.time() - span
    w = SecurityEvent.ts >= since

    totals = {c: 0 for c in CATS}
    for cat, n in (await db.execute(select(SecurityEvent.category, func.sum(SecurityEvent.count)).where(w)
                                    .group_by(SecurityEvent.category))).all():
        totals[cat] = int(n or 0)
    attackers = (await db.execute(select(func.count(distinct(SecurityEvent.src_ip)))
                                  .where(w, SecurityEvent.category.in_(ATTACK)))).scalar() or 0

    attack_sum = _sum_cat(ATTACK).label("attacks")
    src_rows = (await db.execute(
        select(SecurityEvent.src_ip, attack_sum, _sum_cat("block"), _sum_cat("auth_fail"), _sum_cat("ids"),
               _sum_cat("auth_ok"), _sum_cat("pass"), func.max(SecurityEvent.ts),
               func.count(distinct(SecurityEvent.dst_port)))
        .where(w).group_by(SecurityEvent.src_ip).having(attack_sum > 0).order_by(attack_sum.desc()).limit(500))).all()
    sources = [{"ip": r[0], "attacks": int(r[1] or 0), "block": int(r[2] or 0), "auth_fail": int(r[3] or 0),
                "ids": int(r[4] or 0), "auth_ok": int(r[5] or 0), "pass": int(r[6] or 0), "last_seen": r[7],
                "ports": int(r[8] or 0), "country": country(r[0]), "internal": is_internal(r[0])} for r in src_rows]

    countries: dict[str, int] = {}
    for s in sources:
        if s["country"]:
            countries[s["country"]] = countries.get(s["country"], 0) + s["attacks"]

    port_rows = (await db.execute(
        select(SecurityEvent.dst_port, SecurityEvent.proto, func.sum(SecurityEvent.count),
               func.count(distinct(SecurityEvent.src_ip)))
        .where(w, SecurityEvent.category == "block", SecurityEvent.dst_port.is_not(None))
        .group_by(SecurityEvent.dst_port, SecurityEvent.proto).order_by(func.sum(SecurityEvent.count).desc()).limit(15))).all()
    svc_rows = (await db.execute(
        select(SecurityEvent.service, SecurityEvent.category, func.sum(SecurityEvent.count), func.count(distinct(SecurityEvent.src_ip)))
        .where(w, SecurityEvent.category.in_(("auth_fail", "auth_ok", "ids")))
        .group_by(SecurityEvent.service, SecurityEvent.category).order_by(func.sum(SecurityEvent.count).desc()).limit(30))).all()
    recent = (await db.execute(
        select(SecurityEvent).where(w, SecurityEvent.category.in_(("auth_fail", "auth_ok", "ids")))
        .order_by(SecurityEvent.ts.desc(), SecurityEvent.id.desc()).limit(60))).scalars().all()

    detections = sorted((a for a in engine.open.values() if a.rule.startswith("sec_")), key=lambda a: -a.last_seen_at)
    return {
        "range": range_, "totals": totals, "attackers": attackers, "geoip": geoip.source, "geoip_error": geoip.error,
        "timeline": await _timeline(db, since, span),
        "top_sources": sources[:25],
        "countries": sorted(({"country": c, "attacks": n} for c, n in countries.items()), key=lambda x: -x["attacks"])[:20],
        "top_ports": [{"port": p, "proto": pr, "service": service_name(p, pr), "count": int(n or 0), "sources": int(s or 0)}
                      for p, pr, n, s in port_rows],
        "services": [{"service": sv, "category": c, "count": int(n or 0), "sources": int(s or 0)} for sv, c, n, s in svc_rows],
        "recent": [{"ts": r.ts, "category": r.category, "src": r.src_ip, "dst": r.dst_ip, "dport": r.dst_port, "proto": r.proto,
                    "service": r.service, "user": r.username, "detail": r.detail, "severity": r.severity, "count": r.count,
                    "device_id": r.device_id, "country": country(r.src_ip), "internal": is_internal(r.src_ip)} for r in recent],
        "detections": [alert_dict(a) | {"src": _detection_src(a.key)} for a in detections],
        "engine": security.tracked(),
    }


@router.get("/security/ip/{ip}")
async def security_ip(ip: str, range_: str = Query("7d", alias="range"), db: AsyncSession = Depends(get_session)) -> dict:
    if not valid_ip(ip):
        raise HTTPException(422, "Not a valid IP address")
    await security.flush()
    span = RANGES.get(range_, 604800)
    since = time.time() - span
    w = (SecurityEvent.ts >= since, SecurityEvent.src_ip == ip)

    totals = {c: 0 for c in CATS}
    for cat, n in (await db.execute(select(SecurityEvent.category, func.sum(SecurityEvent.count)).where(*w)
                                    .group_by(SecurityEvent.category))).all():
        totals[cat] = int(n or 0)
    first, last = (await db.execute(select(func.min(SecurityEvent.ts), func.max(SecurityEvent.ts)).where(*w))).one()
    ports = (await db.execute(
        select(SecurityEvent.dst_port, SecurityEvent.proto, SecurityEvent.category, func.sum(SecurityEvent.count))
        .where(*w, SecurityEvent.dst_port.is_not(None))
        .group_by(SecurityEvent.dst_port, SecurityEvent.proto, SecurityEvent.category)
        .order_by(func.sum(SecurityEvent.count).desc()).limit(50))).all()
    targets = (await db.execute(
        select(SecurityEvent.dst_ip, func.sum(SecurityEvent.count)).where(*w, SecurityEvent.dst_ip != "")
        .group_by(SecurityEvent.dst_ip).order_by(func.sum(SecurityEvent.count).desc()).limit(20))).all()
    creds = (await db.execute(
        select(SecurityEvent.service, SecurityEvent.username, SecurityEvent.category, func.sum(SecurityEvent.count))
        .where(*w, SecurityEvent.category.in_(("auth_fail", "auth_ok", "ids")))
        .group_by(SecurityEvent.service, SecurityEvent.username, SecurityEvent.category)
        .order_by(func.sum(SecurityEvent.count).desc()).limit(50))).all()
    alerts = (await db.execute(
        select(Alert).where(or_(Alert.key.like(f"%:{ip}"), Alert.key.like(f"%:{ip}:%")))
        .order_by(Alert.started_at.desc()).limit(30))).scalars().all()
    logs = (await db.execute(
        select(LogEntry).where(LogEntry.ts >= since, LogEntry.message.like(f"%{ip}%"))
        .order_by(LogEntry.id.desc()).limit(60))).scalars().all()
    return {
        "ip": ip, "country": country(ip), "internal": is_internal(ip), "totals": totals,
        "first_seen": first, "last_seen": last,
        "timeline": await _timeline(db, since, span, SecurityEvent.src_ip == ip),
        "ports": [{"port": p, "proto": pr, "service": service_name(p, pr), "category": c, "count": int(n or 0)}
                  for p, pr, c, n in ports],
        "targets": [{"ip": t, "count": int(n or 0)} for t, n in targets],
        "credentials": [{"service": s, "user": u, "category": c, "count": int(n or 0)} for s, u, c, n in creds],
        "alerts": [alert_dict(a) for a in alerts],
        "logs": [{"id": r.id, "ts": r.ts, "device": _device_name(r.device_id), "host": r.host, "severity": r.severity,
                  "app": r.app, "message": r.message} for r in logs],
    }


# ---------------------------------------------------------------------- dhcp
class KnownIn(BaseModel):
    mac: str = Field(min_length=11, max_length=17)
    known: bool = True
    label: str | None = Field(default=None, max_length=128)


@router.get("/security/events")
async def security_events(
    category: list[str] = Query(default=list(CATS)), range_: str = Query("24h", alias="range"),
    service: str | None = None, src: str | None = None, port: int | None = None,
    before: float | None = None, limit: int = Query(200, ge=1, le=1000), db: AsyncSession = Depends(get_session),
) -> dict:
    """The individual (per-minute aggregated) events behind every number on the Security page."""
    bad = [c for c in category if c not in CATS]
    if bad:
        raise HTTPException(422, f"Unknown category: {', '.join(bad)}")
    await security.flush()
    since = time.time() - RANGES.get(range_, 86400)
    conds = [SecurityEvent.ts >= since, SecurityEvent.category.in_(category)]
    if service:
        conds.append(SecurityEvent.service == service)
    if src:
        conds.append(SecurityEvent.src_ip == src)
    if port is not None:
        conds.append(SecurityEvent.dst_port == port)
    if before is not None:
        conds.append(SecurityEvent.ts < before)
    rows = (await db.execute(select(SecurityEvent).where(*conds)
                             .order_by(SecurityEvent.ts.desc(), SecurityEvent.id.desc()).limit(limit))).scalars().all()
    return {"items": [{"id": r.id, "ts": r.ts, "category": r.category, "src": r.src_ip, "dst": r.dst_ip, "dport": r.dst_port,
                       "proto": r.proto, "service": r.service, "user": r.username, "detail": r.detail, "severity": r.severity,
                       "count": r.count, "device_id": r.device_id, "device": _device_name(r.device_id),
                       "country": country(r.src_ip), "internal": is_internal(r.src_ip)} for r in rows],
            "more": len(rows) == limit}


@router.get("/dhcp")
async def dhcp_overview() -> dict:
    clients = dhcp.clients()
    now = time.time()
    return {
        "clients": clients,
        "issues": windhcp.issues + dhcp.issues,
        "learning": dhcp.learning(),
        "windows": windhcp.summary(),
        "stats": {
            "total": len(clients), "active": sum(1 for c in clients if c["active"]),
            "macs": len({c["mac"] for c in clients}), "new_24h": len({c["mac"] for c in clients if now - c["first_seen"] < 86400}),
            "unknown": len({c["mac"] for c in clients if not c["known"]}), "issues": len(dhcp.issues) + len(windhcp.issues),
        },
        "sources": {str(k): _device_name(k) for k in dhcp.current},
    }


@router.post("/dhcp/known")
async def dhcp_known(body: KnownIn) -> dict:
    n = await dhcp.set_known(body.mac, body.known, body.label)
    if not n:
        raise HTTPException(404, "MAC not seen")
    return {"updated": n}
