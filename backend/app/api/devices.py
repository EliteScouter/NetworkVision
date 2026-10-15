from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..collectors import registry
from ..db import get_session
from ..models import Device, DeviceMetric, InterfaceMetric
from ..security import (
    SECRET_MASK,
    decrypt_secrets,
    encrypt_secrets,
    mask_secrets,
    require_user,
    resolve_secret,
)
from ..services.poller import poller, run_collect
from ..services.state import store

router = APIRouter(prefix="/api", tags=["devices"], dependencies=[Depends(require_user)])

ROLES = ["firewall", "router", "switch", "ap", "controller", "server", "nas", "hypervisor", "iot", "other"]
EXTRA_CONFIG = {"ping", "syslog_aliases", "name_locked"}


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: str
    role: str = "other"
    host: str = Field(default="", max_length=255)
    enabled: bool = True
    poll_interval: int | None = Field(default=None, ge=5, le=3600)
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    location: str = ""
    notes: str = ""

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        if v not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return v

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if any(c in v for c in "/\\ @?#"):
            raise ValueError("host must be a hostname or IP address (no scheme, path or credentials)")
        return v


class DevicePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    role: str | None = None
    enabled: bool | None = None
    tags: list[str] | None = None
    location: str | None = None
    notes: str | None = None


class PositionIn(BaseModel):
    x: float | None
    y: float | None


def _split(kind: str, config: dict[str, Any], secrets: dict[str, Any]) -> tuple[dict, dict]:
    cls = registry.COLLECTORS.get(kind)
    if cls is None:
        raise HTTPException(400, f"Unknown integration kind '{kind}'")
    secret_keys = {f.key for f in cls.fields if f.secret}
    plain_keys = {f.key for f in cls.fields if not f.secret} | EXTRA_CONFIG
    clean_cfg = {k: v for k, v in config.items() if k in plain_keys}
    clean_sec = {k: v for k, v in {**config, **secrets}.items() if k in secret_keys}
    return clean_cfg, clean_sec


def _row(d: Device) -> dict[str, Any]:
    live = store.get(d.id)
    base = live.summary() if live else {"id": d.id, "name": d.name, "status": "unknown"}
    return {
        **base, "kind": d.kind, "role": d.role, "host": d.host, "enabled": d.enabled,
        "poll_interval": d.poll_interval, "config": d.config or {}, "secrets": mask_secrets(decrypt_secrets(d.secrets_enc)),
        "parent_id": d.parent_id, "external_id": d.external_id, "tags": d.tags or [], "location": d.location,
        "notes": d.notes, "last_seen": d.last_seen, "created_at": d.created_at,
    }


@router.get("/integrations")
async def integrations() -> dict:
    return {"integrations": registry.available(), "roles": ROLES}


@router.get("/devices")
async def list_devices(db: AsyncSession = Depends(get_session)) -> dict:
    rows = (await db.execute(select(Device).order_by(Device.parent_id.is_not(None), Device.name))).scalars().all()
    return {"devices": [_row(d) for d in rows]}


@router.get("/devices/{device_id}")
async def get_device(device_id: int, db: AsyncSession = Depends(get_session)) -> dict:
    d = await db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "Device not found")
    live = store.get(device_id)
    out = _row(d)
    if live:
        out.update(live.detail())
        out["config"], out["secrets"] = d.config or {}, mask_secrets(decrypt_secrets(d.secrets_enc))
    out["children"] = [c.summary() for c in store.devices.values() if c.parent_id == device_id]
    return out


@router.post("/devices", status_code=201)
async def create_device(body: DeviceIn, db: AsyncSession = Depends(get_session)) -> dict:
    cfg, sec = _split(body.kind, body.config, body.secrets)
    if body.kind != "demo" and not body.host:
        raise HTTPException(422, "host is required")
    d = Device(name=body.name, kind=body.kind, role=body.role, host=body.host, enabled=body.enabled,
               poll_interval=body.poll_interval, config=cfg, secrets_enc=encrypt_secrets(sec), tags=body.tags,
               location=body.location, notes=body.notes, facts={})
    db.add(d)
    await db.commit()
    await poller.reload(d.id)
    return _row(d)


@router.put("/devices/{device_id}")
async def update_device(device_id: int, body: DeviceIn, db: AsyncSession = Depends(get_session)) -> dict:
    d = await db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "Device not found")
    if d.parent_id is not None:
        raise HTTPException(400, "Discovered devices are managed by their controller; use PATCH")
    cfg, sec = _split(body.kind, body.config, body.secrets)
    old = decrypt_secrets(d.secrets_enc)
    # Masked values mean "unchanged"; empty string means "remove".
    merged = {k: (old.get(k) if v == SECRET_MASK else v) for k, v in sec.items()}
    for k, v in old.items():
        merged.setdefault(k, v)
    d.name, d.kind, d.role, d.host, d.enabled = body.name, body.kind, body.role, body.host, body.enabled
    d.poll_interval, d.config, d.secrets_enc = body.poll_interval, cfg, encrypt_secrets(merged)
    d.tags, d.location, d.notes = body.tags, body.location, body.notes
    await db.commit()
    await poller.reload(d.id)
    return _row(d)


@router.patch("/devices/{device_id}")
async def patch_device(device_id: int, body: DevicePatch, db: AsyncSession = Depends(get_session)) -> dict:
    d = await db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "Device not found")
    data = body.model_dump(exclude_none=True)
    if "role" in data and data["role"] not in ROLES:
        raise HTTPException(422, "invalid role")
    if "name" in data and data["name"] != d.name:
        d.config = {**(d.config or {}), "name_locked": True}
    for k, v in data.items():
        setattr(d, k, v)
    await db.commit()
    poller.devices[d.id] = d
    store.ensure(d)
    if d.parent_id is None:
        await poller.reload(d.id)
    return _row(d)


@router.delete("/devices/{device_id}", status_code=204)
async def delete_device(device_id: int, db: AsyncSession = Depends(get_session)) -> None:
    d = await db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "Device not found")
    await poller.remove(device_id)
    await db.delete(d)
    await db.commit()


@router.put("/devices/{device_id}/position")
async def set_position(device_id: int, body: PositionIn, db: AsyncSession = Depends(get_session)) -> dict:
    d = await db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "Device not found")
    d.pos_x, d.pos_y = body.x, body.y
    await db.commit()
    return {"ok": True}


@router.post("/devices/{device_id}/poll")
async def poll_now(device_id: int) -> dict:
    dev = poller.devices.get(device_id)
    target = dev.parent_id if dev and dev.parent_id else device_id
    if not poller.poll_now(target):
        raise HTTPException(404, "Device is not being polled (disabled or unknown)")
    return {"ok": True}


@router.post("/devices/test")
async def test_device(body: DeviceIn, device_id: int | None = Query(default=None),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """Run one collection with the submitted settings without saving anything."""
    cfg, sec = _split(body.kind, body.config, body.secrets)
    if device_id:
        existing = await db.get(Device, device_id)
        old = decrypt_secrets(existing.secrets_enc) if existing else {}
        sec = {k: (old.get(k) if v == SECRET_MASK else v) for k, v in sec.items()}
        for k, v in old.items():
            sec.setdefault(k, v)
    collector = registry.build(body.kind, body.host, {k: resolve_secret(v) for k, v in cfg.items()},
                               {k: resolve_secret(v) for k, v in sec.items()})
    tmp = Device(id=0, name=body.name, kind=body.kind, host=body.host, config=cfg)
    started = time.perf_counter()
    try:
        snap = await run_collect(collector, tmp, timeout=30)
    finally:
        await collector.close()
    return {
        "ok": snap.reachable and not snap.error, "reachable": snap.reachable, "error": snap.error,
        "elapsed_ms": round((time.perf_counter() - started) * 1000), "facts": snap.facts,
        "metrics": snap.metrics, "interfaces": len(snap.interfaces), "neighbors": len(snap.neighbors),
        "gateways": len(snap.gateways), "children": len(snap.children), "logs": len(snap.logs),
        "sections": [s.title for s in snap.sections],
    }


# ---------------------------------------------------------------- time series
RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}


def _downsample(rows: list[tuple], start: float, span: float, fields: int, points: int = 240) -> list[list]:
    if not rows:
        return []
    step = max(span / points, 1)
    buckets: dict[int, list[list[float]]] = {}
    for r in rows:
        b = int((r[0] - start) // step)
        acc = buckets.setdefault(b, [[] for _ in range(fields)])
        for i in range(fields):
            if r[i + 1] is not None:
                acc[i].append(r[i + 1])
    out = []
    for b in sorted(buckets):
        vals = buckets[b]
        out.append([round(start + b * step + step / 2)] + [(sum(v) / len(v)) if v else None for v in vals])
    return out


@router.get("/devices/{device_id}/metrics")
async def device_metrics(device_id: int, range_: str = Query("1h", alias="range"), db: AsyncSession = Depends(get_session)) -> dict:
    span = RANGES.get(range_, 3600)
    start = time.time() - span
    cols = ["cpu", "mem", "temp", "latency_ms", "loss_pct", "rx_bps", "tx_bps", "clients", "status"]
    q = select(DeviceMetric.ts, *[getattr(DeviceMetric, c) for c in cols]).where(
        DeviceMetric.device_id == device_id, DeviceMetric.ts >= start).order_by(DeviceMetric.ts)
    rows = (await db.execute(q)).all()
    return {"columns": ["ts", *cols], "points": _downsample(rows, start, span, len(cols)), "range": range_}


@router.get("/devices/{device_id}/interfaces/metrics")
async def interface_metrics(device_id: int, ifname: str, range_: str = Query("1h", alias="range"),
                            db: AsyncSession = Depends(get_session)) -> dict:
    span = RANGES.get(range_, 3600)
    start = time.time() - span
    q = select(InterfaceMetric.ts, InterfaceMetric.rx_bps, InterfaceMetric.tx_bps, InterfaceMetric.errors_per_min,
               InterfaceMetric.util_pct).where(InterfaceMetric.device_id == device_id, InterfaceMetric.ifname == ifname,
                                               InterfaceMetric.ts >= start).order_by(InterfaceMetric.ts)
    rows = (await db.execute(q)).all()
    return {"columns": ["ts", "rx_bps", "tx_bps", "errors_per_min", "util_pct"],
            "points": _downsample(rows, start, span, 4), "range": range_}
