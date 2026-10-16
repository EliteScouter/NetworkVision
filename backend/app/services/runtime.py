"""Operational settings that can be changed from the UI without a redeploy.

Precedence (lowest -> highest): built-in default < NV_* environment variable < value
saved in the UI. "Reset" in the UI deletes the saved value, so the env var (or the
built-in default) applies again. Saved values live in the ``settings`` table: plain
JSON under ``runtime`` and, for webhook URLs/tokens, an encrypted blob under
``runtime_secrets``. Secrets are never returned to the browser, only masked.

Also holds per-device alert tuning (``alert_tuning`` table) and maintenance windows
(``maintenance_windows`` table), cached in memory because evaluate() runs every poll.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Annotated, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import TypeAdapter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..db import with_retry
from ..models import AlertTuning, MaintenanceWindow, Setting
from ..security import SECRET_MASK, decrypt_blob, encrypt_blob

log = logging.getLogger("networkvision.runtime")

THRESHOLDS = ["alert_cpu_pct", "alert_mem_pct", "alert_temp_c", "alert_latency_ms", "alert_loss_pct",
              "alert_if_util_pct", "alert_if_errors_per_min", "alert_consecutive"]
RETENTION = ["retention_days_metrics", "retention_days_rollup", "retention_days_logs", "retention_days_alerts"]
NOTIFY = ["notify_min_severity"]
SECRETS = ["notify_webhook_url", "notify_discord_webhook_url", "notify_slack_webhook_url", "notify_ntfy_url", "notify_ntfy_token"]
EDITABLE = THRESHOLDS + RETENTION + NOTIFY + SECRETS
SEVERITIES = ("info", "warning", "critical")

# Short names used for per-device threshold overrides -> global setting.
DEVICE_THRESHOLDS = {
    "cpu": "alert_cpu_pct", "mem": "alert_mem_pct", "temp": "alert_temp_c", "latency_ms": "alert_latency_ms",
    "loss_pct": "alert_loss_pct", "if_util": "alert_if_util_pct", "if_errors": "alert_if_errors_per_min",
}

RULES: dict[str, str] = {
    "device_down": "Device down", "poll_error": "Integration error", "high_cpu": "High CPU", "high_mem": "High memory",
    "high_temp": "High temperature", "high_latency": "High latency", "packet_loss": "Packet loss",
    "gateway_down": "Gateway down", "gateway_loss": "Gateway packet loss", "gateway_latency": "Gateway latency",
    "port_flapping": "Port flapping", "port_down": "Link down", "port_errors": "Interface errors",
    "port_saturated": "Interface saturated", "firmware_update": "Firmware update available",
    "log_event": "Critical log event", "speedtest_failed": "Speed test failed", "speedtest_slow": "Internet slower than expected",
}

_RUNTIME_KEY, _SECRETS_KEY = "runtime", "runtime_secrets"


def _adapter(name: str) -> TypeAdapter:
    f = Settings.model_fields[name]
    return TypeAdapter(Annotated[f.annotation, *f.metadata]) if f.metadata else TypeAdapter(f.annotation)


def validate(name: str, value: Any) -> Any:
    """Coerce/validate one UI value with the same rules as the env var. Raises ValueError."""
    if name not in EDITABLE:
        raise ValueError(f"{name} is not editable")
    if name == "notify_min_severity":
        if value not in SEVERITIES:
            raise ValueError("min severity must be info, warning or critical")
        return value
    if name in SECRETS:
        v = str(value or "").strip()
        if v and name != "notify_ntfy_token" and not v.startswith(("http://", "https://")):
            raise ValueError("must be an http(s) URL")
        if len(v) > 2048:
            raise ValueError("too long")
        return v
    v = _adapter(name).validate_python(value)
    if isinstance(v, float) and (v != v or v < 0):
        raise ValueError("must be a positive number")
    return v


def parse_hhmm(value: str) -> tuple[int, int]:
    h, _, m = (value or "").partition(":")
    hh, mm = int(h), int(m)
    if not (0 <= hh < 24 and 0 <= mm < 60):
        raise ValueError("time must be HH:MM")
    return hh, mm


def _zone(tz: str) -> tzinfo:
    try:
        return ZoneInfo(tz or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return UTC  # unknown zone or no tz database in the image


def valid_tz(tz: str) -> bool:
    try:
        ZoneInfo(tz)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        return tz == "UTC"


def window_span(w: MaintenanceWindow, now: float) -> tuple[float, float] | None:
    """The occurrence of ``w`` that covers ``now`` (start, end), or None."""
    if not w.enabled:
        return None
    if w.kind == "once":
        if w.starts_at is not None and w.ends_at is not None and w.starts_at <= now < w.ends_at:
            return w.starts_at, w.ends_at
        return None
    hh, mm = parse_hhmm(w.start_time)
    dur = max(1, int(w.duration_min or 0)) * 60
    zone = _zone(w.tz)
    local_now = datetime.fromtimestamp(now, zone)
    # An occurrence that started up to `duration` ago may still be running.
    for back in range(0, dur // 86400 + 2):
        day = (local_now - timedelta(days=back)).date()
        if w.kind == "weekly" and day.weekday() not in (w.weekdays or []):
            continue
        start = datetime(day.year, day.month, day.day, hh, mm, tzinfo=zone).timestamp()
        if start <= now < start + dur:
            return start, start + dur
    return None


def next_start(w: MaintenanceWindow, now: float) -> float | None:
    if not w.enabled:
        return None
    if w.kind == "once":
        return w.starts_at if w.starts_at and w.starts_at > now else None
    hh, mm = parse_hhmm(w.start_time)
    zone = _zone(w.tz)
    local_now = datetime.fromtimestamp(now, zone)
    for ahead in range(0, 8):
        day = (local_now + timedelta(days=ahead)).date()
        if w.kind == "weekly" and day.weekday() not in (w.weekdays or []):
            continue
        start = datetime(day.year, day.month, day.day, hh, mm, tzinfo=zone).timestamp()
        if start > now:
            return start
    return None


def tuning_dict(t: AlertTuning | None, device_id: int) -> dict[str, Any]:
    return {
        "device_id": device_id, "muted": bool(t and t.muted), "disabled_rules": list(t.disabled_rules or []) if t else [],
        "muted_interfaces": list(t.muted_interfaces or []) if t else [], "thresholds": dict(t.thresholds or {}) if t else {},
    }


def window_dict(w: MaintenanceWindow, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    span = window_span(w, now)
    return {
        "id": w.id, "name": w.name, "device_id": w.device_id, "kind": w.kind, "starts_at": w.starts_at, "ends_at": w.ends_at,
        "start_time": w.start_time, "duration_min": w.duration_min, "weekdays": list(w.weekdays or []), "tz": w.tz,
        "enabled": w.enabled, "created_by": w.created_by, "created_at": w.created_at,
        "active": span is not None, "active_until": span[1] if span else None, "next_start": None if span else next_start(w, now),
    }


class RuntimeSettings:
    def __init__(self) -> None:
        self.overrides: dict[str, Any] = {}
        self.secrets: dict[str, str] = {}
        self.disabled_rules: set[str] = set()
        self.tuning: dict[int, AlertTuning] = {}
        self.windows: list[MaintenanceWindow] = []
        self.secrets_corrupt = False
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------- loading
    async def load(self) -> None:
        async def _q(db: AsyncSession):
            rows = {r.key: r.value for r in (await db.execute(
                select(Setting).where(Setting.key.in_([_RUNTIME_KEY, _SECRETS_KEY])))).scalars()}
            tuning = (await db.execute(select(AlertTuning))).scalars().all()
            windows = (await db.execute(select(MaintenanceWindow))).scalars().all()
            return rows, tuning, windows

        rows, tuning, windows = await with_retry(_q)
        try:
            plain = json.loads(rows.get(_RUNTIME_KEY) or "{}")
        except ValueError:
            log.error("Saved settings are not valid JSON - ignoring them")
            plain = {}
        self.overrides = {}
        for k, v in (plain.get("values") or {}).items():
            try:
                self.overrides[k] = validate(k, v)
            except ValueError as e:
                log.warning("Ignoring saved setting %s: %s", k, e)
        self.disabled_rules = set(plain.get("disabled_rules") or [])
        sec = decrypt_blob(rows.get(_SECRETS_KEY))
        self.secrets_corrupt = sec is None
        if sec is None:
            log.error("Saved notification secrets cannot be decrypted (did NV_SECRET_KEY change?) - re-enter them in Settings")
        self.secrets = {k: v for k, v in (sec or {}).items() if k in SECRETS}
        self.tuning = {t.device_id: t for t in tuning}
        self.windows = list(windows)

    # ------------------------------------------------------------- reading
    def get(self, name: str) -> Any:
        if name in self.secrets:
            return self.secrets[name]
        if name in self.overrides:
            return self.overrides[name]
        return getattr(get_settings(), name)

    def source(self, name: str) -> str:
        if name in self.secrets or name in self.overrides:
            return "ui"
        return "env" if name in get_settings().model_fields_set else "default"

    def env_value(self, name: str) -> Any:
        return getattr(get_settings(), name)

    def threshold(self, name: str, device_id: int | None = None) -> float:
        if device_id is not None and (t := self.tuning.get(device_id)) is not None:
            short = next((k for k, v in DEVICE_THRESHOLDS.items() if v == name), None)
            if short and (t.thresholds or {}).get(short) is not None:
                return float(t.thresholds[short])
        return float(self.get(name))

    def rule_enabled(self, rule: str, device_id: int | None = None) -> bool:
        if rule in self.disabled_rules:
            return False
        t = self.tuning.get(device_id) if device_id is not None else None
        return not (t and rule in (t.disabled_rules or []))

    def device_muted(self, device_id: int | None) -> bool:
        t = self.tuning.get(device_id) if device_id is not None else None
        return bool(t and t.muted)

    def interface_muted(self, device_id: int, ifname: str) -> bool:
        t = self.tuning.get(device_id)
        return bool(t and ifname in (t.muted_interfaces or []))

    def in_maintenance(self, device_id: int | None, parent_id: int | None = None, now: float | None = None) -> MaintenanceWindow | None:
        now = time.time() if now is None else now
        for w in self.windows:
            if w.device_id is not None and w.device_id not in (device_id, parent_id):
                continue
            if window_span(w, now):
                return w
        return None

    def active_windows(self, now: float | None = None) -> list[MaintenanceWindow]:
        now = time.time() if now is None else now
        return [w for w in self.windows if window_span(w, now)]

    def public(self) -> dict[str, Any]:
        """What the UI sees: effective values with sources; secrets masked."""
        fields: dict[str, Any] = {}
        for name in EDITABLE:
            secret = name in SECRETS
            val, env = self.get(name), self.env_value(name)
            fields[name] = {
                "value": (SECRET_MASK if val else "") if secret else val,
                "default": (SECRET_MASK if env else "") if secret else env,
                "source": self.source(name), "secret": secret,
            }
        return {"fields": fields, "disabled_rules": sorted(self.disabled_rules), "rules": RULES,
                "secrets_corrupt": self.secrets_corrupt}

    # ------------------------------------------------------------- writing
    async def update(self, values: dict[str, Any], disabled_rules: list[str] | None = None) -> None:
        """values: name -> new value; None resets to env/default; SECRET_MASK keeps a secret unchanged."""
        overrides, secrets = dict(self.overrides), dict(self.secrets)
        for name, raw in values.items():
            if name not in EDITABLE:
                raise ValueError(f"{name} is not editable")
            if raw is None:
                overrides.pop(name, None)
                secrets.pop(name, None)
            elif name in SECRETS:
                if raw == SECRET_MASK:
                    continue
                secrets[name] = validate(name, raw)
            else:
                overrides[name] = validate(name, raw)
        rules = set(self.disabled_rules) if disabled_rules is None else {r for r in disabled_rules if r in RULES}
        await self._save(overrides, secrets, rules)
        self.overrides, self.secrets, self.disabled_rules = overrides, secrets, rules
        self.secrets_corrupt = False

    async def _save(self, overrides: dict[str, Any], secrets: dict[str, str], rules: set[str]) -> None:
        plain = json.dumps({"values": overrides, "disabled_rules": sorted(rules)})
        blob = encrypt_blob(secrets)

        async def _w(db: AsyncSession) -> None:
            for key, value in ((_RUNTIME_KEY, plain), (_SECRETS_KEY, blob)):
                row = await db.get(Setting, key)
                if row is None:
                    db.add(Setting(key=key, value=value))
                else:
                    row.value = value
            await db.commit()

        async with self._lock:
            await with_retry(_w)

    async def set_tuning(self, device_id: int, data: dict[str, Any]) -> AlertTuning:
        async def _w(db: AsyncSession) -> AlertTuning:
            t = await db.get(AlertTuning, device_id)
            if t is None:
                t = AlertTuning(device_id=device_id)
                db.add(t)
            t.muted = bool(data.get("muted"))
            t.disabled_rules = sorted({r for r in data.get("disabled_rules") or [] if r in RULES})
            t.muted_interfaces = sorted({str(i)[:64] for i in data.get("muted_interfaces") or [] if i})
            t.thresholds = {k: float(v) for k, v in (data.get("thresholds") or {}).items()
                            if k in DEVICE_THRESHOLDS and v is not None and v != ""}
            await db.commit()
            return t

        t = await with_retry(_w)
        if t.muted or t.disabled_rules or t.muted_interfaces or t.thresholds:
            self.tuning[device_id] = t
        else:
            self.tuning.pop(device_id, None)
        return t

    async def add_window(self, w: MaintenanceWindow) -> MaintenanceWindow:
        async def _w(db: AsyncSession) -> MaintenanceWindow:
            fresh = MaintenanceWindow(**{c.name: getattr(w, c.name) for c in MaintenanceWindow.__table__.columns if c.name != "id"})
            db.add(fresh)
            await db.commit()
            return fresh

        saved = await with_retry(_w)
        self.windows.append(saved)
        return saved

    async def delete_window(self, window_id: int) -> bool:
        async def _w(db: AsyncSession) -> bool:
            w = await db.get(MaintenanceWindow, window_id)
            if w is None:
                return False
            await db.delete(w)
            await db.commit()
            return True

        ok = await with_retry(_w)
        self.windows = [w for w in self.windows if w.id != window_id]
        return ok

    def drop_device(self, device_id: int) -> None:
        self.tuning.pop(device_id, None)
        self.windows = [w for w in self.windows if w.device_id != device_id]


runtime = RuntimeSettings()
