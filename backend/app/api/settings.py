"""Operational settings, per-device alert tuning and maintenance windows."""

from __future__ import annotations

import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from ..models import MaintenanceWindow
from ..security import require_user
from ..services import notifier
from ..services.runtime import DEVICE_THRESHOLDS, RULES, parse_hhmm, runtime, tuning_dict, valid_tz, window_dict
from ..services.state import store

router = APIRouter(prefix="/api", tags=["settings"], dependencies=[Depends(require_user)])


# -------------------------------------------------------------------- settings
class SettingsIn(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)  # null value = reset to env/default
    disabled_rules: list[str] | None = None


@router.get("/settings")
async def get_settings_() -> dict[str, Any]:
    return {**runtime.public(), "channels": notifier.configured()}


@router.put("/settings")
async def put_settings(body: SettingsIn) -> dict[str, Any]:
    try:
        await runtime.update(body.values, body.disabled_rules)
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, _msg(e)) from e
    return {**runtime.public(), "channels": notifier.configured()}


@router.post("/settings/test-notification")
async def test_notification(user: str = Depends(require_user)) -> dict[str, Any]:
    if not notifier.enabled():
        raise HTTPException(400, "No notification channel is configured")
    return {"results": await notifier.send_test(user)}


def _msg(e: Exception) -> str:
    if isinstance(e, ValidationError):
        return "; ".join(f"{err.get('msg')}" for err in e.errors())
    return str(e)


# ---------------------------------------------------------------- alert tuning
class TuningIn(BaseModel):
    muted: bool = False
    disabled_rules: list[str] = Field(default_factory=list, max_length=64)
    muted_interfaces: list[str] = Field(default_factory=list, max_length=512)
    thresholds: dict[str, float | None] = Field(default_factory=dict)

    @field_validator("disabled_rules")
    @classmethod
    def _rules(cls, v: list[str]) -> list[str]:
        if bad := [r for r in v if r not in RULES]:
            raise ValueError(f"unknown rule(s): {', '.join(bad)}")
        return v

    @field_validator("thresholds")
    @classmethod
    def _th(cls, v: dict[str, float | None]) -> dict[str, float | None]:
        if bad := [k for k in v if k not in DEVICE_THRESHOLDS]:
            raise ValueError(f"unknown threshold(s): {', '.join(bad)}")
        if any(x is not None and (x != x or x < 0) for x in v.values()):
            raise ValueError("thresholds must be positive numbers")
        return v


@router.get("/alert-tuning")
async def list_tuning() -> dict[str, Any]:
    return {"items": [tuning_dict(t, d) for d, t in runtime.tuning.items()], "rules": RULES,
            "thresholds": {short: runtime.get(name) for short, name in DEVICE_THRESHOLDS.items()}}


@router.get("/alert-tuning/{device_id}")
async def get_tuning(device_id: int) -> dict[str, Any]:
    _device(device_id)
    return tuning_dict(runtime.tuning.get(device_id), device_id)


@router.put("/alert-tuning/{device_id}")
async def put_tuning(device_id: int, body: TuningIn) -> dict[str, Any]:
    _device(device_id)
    t = await runtime.set_tuning(device_id, body.model_dump())
    return tuning_dict(t, device_id)


def _device(device_id: int) -> None:
    if store.get(device_id) is None:
        raise HTTPException(404, "Device not found")


# ---------------------------------------------------------- maintenance windows
class WindowIn(BaseModel):
    name: str = Field(default="", max_length=128)
    device_id: int | None = None
    kind: Literal["once", "daily", "weekly"] = "once"
    starts_at: float | None = None
    ends_at: float | None = None
    start_time: str = "00:00"
    duration_min: int = Field(default=60, ge=1, le=7 * 24 * 60)
    weekdays: list[int] = Field(default_factory=list)
    tz: str = Field(default="UTC", max_length=64)

    @model_validator(mode="after")
    def _check(self) -> WindowIn:
        if self.kind == "once":
            if self.starts_at is None or self.ends_at is None or self.ends_at <= self.starts_at:
                raise ValueError("a one-off window needs a start before its end")
            if self.ends_at < time.time():
                raise ValueError("that window is already over")
        else:
            parse_hhmm(self.start_time)
            if self.kind == "weekly" and (not self.weekdays or any(d not in range(7) for d in self.weekdays)):
                raise ValueError("pick at least one weekday")
        if not valid_tz(self.tz):
            raise ValueError(f"unknown time zone {self.tz}")
        return self


@router.get("/maintenance")
async def list_windows() -> dict[str, Any]:
    now = time.time()
    return {"items": sorted((window_dict(w, now) for w in runtime.windows), key=lambda w: (not w["active"], w["id"]))}


@router.get("/maintenance/active")
async def active_windows() -> dict[str, Any]:
    now = time.time()
    return {"items": [window_dict(w, now) for w in runtime.active_windows(now)]}


@router.post("/maintenance", status_code=201)
async def create_window(body: WindowIn, user: str = Depends(require_user)) -> dict[str, Any]:
    if body.device_id is not None:
        _device(body.device_id)
    data = body.model_dump()
    if body.kind == "once":
        data.update(start_time="00:00", duration_min=max(1, int((body.ends_at - body.starts_at) // 60)), weekdays=[])
    else:
        data.update(starts_at=None, ends_at=None, weekdays=sorted(set(body.weekdays)) if body.kind == "weekly" else [])
    w = await runtime.add_window(MaintenanceWindow(**data, enabled=True, created_by=user[:64], created_at=time.time()))
    return window_dict(w)


@router.delete("/maintenance/{window_id}", status_code=204)
async def delete_window(window_id: int) -> None:
    if not await runtime.delete_window(window_id):
        raise HTTPException(404, "Maintenance window not found")
