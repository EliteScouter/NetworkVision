"""Service (uptime) monitors: CRUD, run-now, dry-run tests, uptime stats and incidents."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, model_validator

from ..db import with_retry
from ..models import Service
from ..security import require_user
from ..services import uptime
from ..services.uptime import monitor

router = APIRouter(prefix="/api/services", tags=["services"], dependencies=[Depends(require_user)])


class ServiceIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: Literal["http", "tcp", "dns", "tls"]
    target: str = Field(min_length=1, max_length=2048)
    port: int | None = Field(default=None, ge=1, le=65535)
    enabled: bool = True
    interval_s: int = Field(default=60, ge=10, le=86400)
    timeout_s: float = Field(default=10, ge=1, le=60)
    config: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=20)
    notes: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def _check(self) -> ServiceIn:
        self.target, self.port, self.config = uptime.normalize(self.kind, self.target, self.port, self.config)
        if self.timeout_s >= self.interval_s:
            raise ValueError("timeout_s must be shorter than interval_s")
        self.name = self.name.strip()
        self.tags = [t.strip()[:32] for t in self.tags if t.strip()]
        return self


def _as_dict(body: ServiceIn, sid: int = 0) -> dict[str, Any]:
    d = body.model_dump()
    d["id"], d["config"] = sid, {**uptime.DEFAULTS, **d["config"]}
    return d


async def _item(sid: int, stats: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    stats = stats if stats is not None else await monitor.stats()
    return {**monitor.services[sid], **monitor.snapshot(sid), **stats.get(sid, {"uptime": {}, "bars": []})}


@router.get("")
async def list_services() -> dict[str, Any]:
    stats = await monitor.stats()
    items = [await _item(sid, stats) for sid in sorted(monitor.services, key=lambda i: monitor.services[i]["name"].lower())]
    counts = {k: 0 for k in ("up", "degraded", "down", "pending", "paused")}
    for it in items:
        counts[it["state"]["status"]] = counts.get(it["state"]["status"], 0) + 1
    certs = [(it["state"]["cert"]["days_left"], it) for it in items if it["state"]["cert"] and it["enabled"]]
    soonest = min(certs, key=lambda c: c[0]) if certs else None
    return {
        "services": items,
        "summary": {
            "total": len(items), **counts,
            "certs_expiring": sum(1 for d, it in certs if d < it["config"]["cert_warn_days"]),
            "soonest_cert": {"id": soonest[1]["id"], "name": soonest[1]["name"], "days_left": soonest[0]} if soonest else None,
        },
    }


@router.get("/incidents")
async def incidents(service_id: int | None = None, limit: int = Query(100, ge=1, le=1000)) -> dict[str, Any]:
    return {"items": await monitor.incidents(service_id, limit)}


@router.post("/test")
async def test_service(body: ServiceIn) -> dict[str, Any]:
    """Run a check once without saving anything - for the add/edit form."""
    return await monitor.test(_as_dict(body))


@router.get("/{sid}")
async def get_service(sid: int) -> dict[str, Any]:
    if sid not in monitor.services:
        raise HTTPException(404, "Service not found")
    return {**await _item(sid), "incidents": await monitor.incidents(sid, 50)}


@router.post("", status_code=201)
async def create_service(body: ServiceIn) -> dict[str, Any]:
    async def _w(db) -> Service:
        s = Service(name=body.name, kind=body.kind, target=body.target, port=body.port, enabled=body.enabled,
                    interval_s=body.interval_s, timeout_s=body.timeout_s, config=body.config, tags=body.tags, notes=body.notes)
        db.add(s)
        await db.commit()
        return s

    s = await with_retry(_w)
    monitor.upsert(uptime.service_dict(s))
    return await _item(s.id)


@router.put("/{sid}")
async def update_service(sid: int, body: ServiceIn) -> dict[str, Any]:
    async def _w(db) -> Service | None:
        s = await db.get(Service, sid)
        if s is None:
            return None
        s.name, s.kind, s.target, s.port, s.enabled = body.name, body.kind, body.target, body.port, body.enabled
        s.interval_s, s.timeout_s, s.config, s.tags, s.notes = body.interval_s, body.timeout_s, body.config, body.tags, body.notes
        await db.commit()
        return s

    s = await with_retry(_w)
    if s is None:
        raise HTTPException(404, "Service not found")
    monitor.upsert(uptime.service_dict(s))
    if not s.enabled:
        await monitor.pause_alerts(sid)
    return await _item(sid)


@router.delete("/{sid}", status_code=204)
async def delete_service(sid: int) -> Response:
    if sid not in monitor.services:
        raise HTTPException(404, "Service not found")
    await monitor.remove(sid)
    await uptime.purge_service(sid)

    async def _w(db) -> None:
        s = await db.get(Service, sid)
        if s is not None:
            await db.delete(s)
            await db.commit()

    await with_retry(_w)
    return Response(status_code=204)


@router.post("/{sid}/check")
async def check_now(sid: int) -> dict[str, Any]:
    if sid not in monitor.services:
        raise HTTPException(404, "Service not found")
    st = monitor.state.get(sid)
    if st is not None and st.running:
        raise HTTPException(409, "A check for this service is already running")
    if st is not None:
        st.running = True
    try:
        await monitor.check(sid)
    finally:
        if sid in monitor.state:
            monitor.state[sid].running = False
    await monitor.flush()
    return await _item(sid)
