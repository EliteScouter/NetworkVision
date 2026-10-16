from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..security import require_user
from ..services.speedtest import speedtest

router = APIRouter(prefix="/api/speedtest", tags=["speedtest"], dependencies=[Depends(require_user)])


class SettingsIn(BaseModel):
    enabled: bool | None = None
    interval_min: int | None = Field(default=None, ge=10, le=1440)
    duration_s: int | None = Field(default=None, ge=3, le=30)
    streams: int | None = Field(default=None, ge=1, le=16)
    expected_down_mbps: float | None = Field(default=None, ge=0)
    expected_up_mbps: float | None = Field(default=None, ge=0)
    alert_pct: int | None = Field(default=None, ge=10, le=100)


@router.get("")
async def status() -> dict[str, Any]:
    recent = await speedtest.recent(30)
    ok = [r for r in recent if not r["error"]]
    return {
        "settings": speedtest.settings, "engine": speedtest.engine.name, "running": speedtest.running,
        "progress": speedtest.progress, "next_run": speedtest.next_run(),
        "last": ok[0] if ok else None, "recent": recent,
    }


@router.post("/run", status_code=202)
async def run_now() -> dict[str, Any]:
    if speedtest.running:
        raise HTTPException(409, "A speed test is already running")
    asyncio.get_running_loop().create_task(speedtest.run("manual"))
    return {"started": True}


@router.put("/settings")
async def update(body: SettingsIn) -> dict[str, Any]:
    patch = body.model_dump(exclude_unset=True)
    return {"settings": await speedtest.update_settings(patch)}
