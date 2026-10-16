"""Overview, topology, logs and alerts endpoints."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Integer, and_, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import Alert, Device, Link, LogEntry
from ..security import require_user
from ..services import topology
from ..services.alerts import alert_dict, engine
from ..services.logs import pipeline
from ..services.state import store

router = APIRouter(prefix="/api", tags=["data"], dependencies=[Depends(require_user)])


# ------------------------------------------------------------------- overview
@router.get("/overview")
async def overview() -> dict[str, Any]:
    devs = [d for d in store.devices.values() if d.enabled]
    status = {k: sum(1 for d in devs if d.status == k) for k in ("up", "degraded", "down", "unknown")}
    alerts = list(engine.open.values())
    sev = {k: sum(1 for a in alerts if a.severity == k) for k in ("critical", "warning", "info")}

    # Only internet-facing firewalls count toward WAN totals (a lab firewall behind the main one would double count).
    edge_ids = topology.internet_edge_ids(devs)
    edge = [d for d in devs if d.id in edge_ids]
    wan_rx = wan_tx = 0.0
    gws = []
    wan_history: list = []
    wan_primary: dict[str, Any] | None = None
    busiest = -1.0
    for d in edge:
        for i in d.wan_interfaces():
            wan_rx += i.rx_bps or 0
            wan_tx += i.tx_bps or 0
            # Chart the WAN that carries the most traffic (the real internet edge, not a lab firewall).
            volume = sum((p[1] or 0) + (p[2] or 0) for p in i.history)
            if len(i.history) >= 2 and volume > busiest:
                busiest, wan_history = volume, [list(p) for p in i.history]
                wan_primary = {"device_id": d.id, "device": d.name, "ifname": i.name}
    # Gateways are listed for every firewall/router (internet edge first), not just the edges.
    for d in sorted((d for d in devs if d.role in ("firewall", "router") and d.parent_id is None),
                    key=lambda d: d.id not in edge_ids):
        gws += [{"device": d.name, "device_id": d.id, "name": g.name, "up": g.up, "latency_ms": g.latency_ms, "loss_pct": g.loss_pct,
                 "address": g.address, "edge": d.id in edge_ids} for g in d.gateways]
    controllers = [d for d in devs if d.role == "controller"]
    clients = sum(int(d.metrics.get("clients") or 0) for d in controllers) or \
        max((int(d.metrics.get("clients") or 0) for d in edge), default=0)
    ports = [i for d in devs for i in d.interfaces.values()]
    talkers = sorted(
        ({"device_id": d.id, "device": d.name, "ifname": i.name, "alias": i.alias, "rx_bps": i.rx_bps or 0,
          "tx_bps": i.tx_bps or 0, "util_pct": i.util_pct, "speed_mbps": i.speed_mbps}
         for d in devs for i in d.interfaces.values() if i.oper_up and i.media not in ("virtual", "tunnel")),
        key=lambda x: x["rx_bps"] + x["tx_bps"], reverse=True)[:10]
    return {
        "ts": time.time(),
        "devices": {"total": len(devs), **status},
        "alerts": {"total": len(alerts), **sev},
        "wan": {"rx_bps": wan_rx, "tx_bps": wan_tx, "gateways": gws, "history": wan_history, "primary": wan_primary},
        "clients": clients,
        "throughput_bps": sum(d.rx_bps + d.tx_bps for d in devs),
        "ports": {"up": sum(1 for i in ports if i.oper_up), "total": len(ports),
                  "errors": sum(1 for i in ports if i.errors_per_min > 0)},
        "logs_per_min": pipeline.per_minute(),
        "top_talkers": talkers,
        "recent_alerts": [alert_dict(a) for a in sorted(alerts, key=lambda a: -a.started_at)[:12]],
    }


# ------------------------------------------------------------------- topology
class LinkIn(BaseModel):
    a_device_id: int
    a_port: str = ""
    b_device_id: int
    b_port: str = ""
    label: str = Field(default="", max_length=128)


@router.get("/topology")
async def get_topology(db: AsyncSession = Depends(get_session)) -> dict:
    links = (await db.execute(select(Link))).scalars().all()
    pos = {d.id: (d.pos_x, d.pos_y) for d in (await db.execute(select(Device))).scalars().all()}
    return topology.build(list(links), pos)


@router.post("/links", status_code=201)
async def create_link(body: LinkIn, db: AsyncSession = Depends(get_session)) -> dict:
    if body.a_device_id == body.b_device_id:
        raise HTTPException(422, "A link needs two different devices")
    for did in (body.a_device_id, body.b_device_id):
        if await db.get(Device, did) is None:
            raise HTTPException(404, f"Device {did} not found")
    link = Link(**body.model_dump())
    db.add(link)
    await db.commit()
    return {"id": link.id}


@router.delete("/links/{link_id}", status_code=204)
async def delete_link(link_id: int, db: AsyncSession = Depends(get_session)) -> None:
    link = await db.get(Link, link_id)
    if link is None:
        raise HTTPException(404, "Link not found")
    await db.delete(link)
    await db.commit()


@router.delete("/positions", status_code=204)
async def reset_positions(db: AsyncSession = Depends(get_session)) -> None:
    await db.execute(Device.__table__.update().values(pos_x=None, pos_y=None))
    await db.commit()


# ----------------------------------------------------------------------- logs
def _log_filters(q: str | None, device_id: list[int] | None, severity: int | None, source: str | None,
                 app: str | None, since: float | None, until: float | None) -> list:
    conds = []
    if q:
        for term in q.split()[:5]:
            neg = term.startswith("-") and len(term) > 1
            like = f"%{term[1:] if neg else term}%"
            expr = or_(LogEntry.message.like(like), LogEntry.app.like(like), LogEntry.host.like(like))
            conds.append(~expr if neg else expr)
    if device_id:
        conds.append(LogEntry.device_id.in_(device_id))
    if severity is not None:
        conds.append(LogEntry.severity <= severity)
    if source:
        conds.append(LogEntry.source == source)
    if app:
        conds.append(LogEntry.app == app)
    if since:
        conds.append(LogEntry.ts >= since)
    if until:
        conds.append(LogEntry.ts <= until)
    return conds


@router.get("/logs")
async def get_logs(
    q: str | None = None, device_id: list[int] | None = Query(default=None), severity: int | None = Query(None, ge=0, le=7),
    source: str | None = None, app: str | None = None, since: float | None = None, until: float | None = None,
    before_id: int | None = None, limit: int = Query(200, ge=1, le=1000), db: AsyncSession = Depends(get_session),
) -> dict:
    conds = _log_filters(q, device_id, severity, source, app, since, until)
    if before_id:
        conds.append(LogEntry.id < before_id)
    stmt = select(LogEntry).where(and_(*conds)).order_by(LogEntry.id.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    names = {d.id: d.name for d in store.devices.values()}
    return {"items": [{"id": r.id, "ts": r.ts, "device_id": r.device_id, "device": names.get(r.device_id),
                       "host": r.host, "severity": r.severity, "facility": r.facility, "app": r.app,
                       "message": r.message, "source": r.source} for r in rows]}


@router.get("/logs/histogram")
async def logs_histogram(
    q: str | None = None, device_id: list[int] | None = Query(default=None), severity: int | None = None,
    source: str | None = None, range_: str = Query("1h", alias="range"), db: AsyncSession = Depends(get_session),
) -> dict:
    span = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}.get(range_, 3600)
    step = max(10, span // 60)
    since = time.time() - span
    conds = _log_filters(q, device_id, severity, source, None, since, None)
    if db.bind.dialect.name == "sqlite":
        bucket = cast(LogEntry.ts / step, Integer)
    else:
        bucket = func.floor(LogEntry.ts / step)
    stmt = (select(bucket.label("b"), LogEntry.severity, func.count()).where(and_(*conds))
            .group_by("b", LogEntry.severity))
    rows = (await db.execute(stmt)).all()
    buckets: dict[int, dict[str, int]] = {}
    for b, sev, n in rows:
        group = "error" if sev <= 3 else ("warning" if sev == 4 else "info")
        slot = buckets.setdefault(int(b), {"error": 0, "warning": 0, "info": 0})
        slot[group] += n
    first = int(since // step)
    series = [{"ts": (first + i) * step, **buckets.get(first + i, {"error": 0, "warning": 0, "info": 0})}
              for i in range(int(span // step) + 1)]
    return {"step": step, "series": series}


@router.get("/logs/apps")
async def log_apps(db: AsyncSession = Depends(get_session)) -> dict:
    since = time.time() - 86400
    rows = (await db.execute(select(LogEntry.app, func.count()).where(LogEntry.ts >= since, LogEntry.app != "")
                             .group_by(LogEntry.app).order_by(func.count().desc()).limit(40))).all()
    return {"apps": [{"app": a, "count": n} for a, n in rows]}


# --------------------------------------------------------------------- alerts
@router.get("/alerts")
async def get_alerts(state: str = "active", device_id: int | None = None, limit: int = Query(200, le=1000),
                     db: AsyncSession = Depends(get_session)) -> dict:
    if state == "active":
        items = [a for a in engine.open.values() if device_id is None or a.device_id == device_id]
        items.sort(key=lambda a: ({"critical": 0, "warning": 1, "info": 2}.get(a.severity, 3), -a.started_at))
        return {"items": [alert_dict(a) for a in items]}
    stmt = select(Alert)
    if state == "resolved":
        stmt = stmt.where(Alert.resolved_at.is_not(None))
    if device_id is not None:
        stmt = stmt.where(Alert.device_id == device_id)
    rows = (await db.execute(stmt.order_by(Alert.started_at.desc()).limit(limit))).scalars().all()
    return {"items": [alert_dict(a) for a in rows]}


@router.post("/alerts/{alert_id}/ack")
async def ack_alert(alert_id: int, user: str = Depends(require_user)) -> dict:
    a = await engine.acknowledge(alert_id, user)
    if a is None:
        raise HTTPException(404, "Alert not found")
    return alert_dict(a)


@router.post("/alerts/{alert_id}/unack")
async def unack_alert(alert_id: int, user: str = Depends(require_user)) -> dict:
    a = await engine.acknowledge(alert_id, user, ack=False)
    if a is None:
        raise HTTPException(404, "Alert not found")
    return alert_dict(a)


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int) -> dict:
    a = await engine.resolve(alert_id)
    if a is None:
        raise HTTPException(404, "Alert not found")
    return alert_dict(a)
