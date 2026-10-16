"""Time-series history: hourly rollups + one query API for every chart.

Raw samples (one per minute) are kept for NV_RETENTION_DAYS_METRICS; hourly
rollups (avg + max) for NV_RETENTION_DAYS_ROLLUP. Queries spanning more than
two days read the rollups (plus raw samples newer than the last rolled-up hour),
so a 30-day or 1-year chart is a few hundred rows, not millions.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import sessionmaker, with_retry
from ..models import (
    DEVICE_VALUES,
    GATEWAY_VALUES,
    INTERFACE_VALUES,
    RADIO_VALUES,
    SERVICE_VALUES,
    DeviceMetric,
    DeviceMetricHourly,
    GatewayMetric,
    GatewayMetricHourly,
    InterfaceMetric,
    InterfaceMetricHourly,
    RadioMetric,
    RadioMetricHourly,
    ServiceCheck,
    ServiceCheckHourly,
    Setting,
    SpeedtestResult,
)

log = logging.getLogger("networkvision.history")
HOUR = 3600
RAW_MAX_SPAN = 2 * 86400  # beyond this, read hourly rollups
RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000,
          "90d": 7776000, "1y": 31536000}


@dataclass(frozen=True)
class Series:
    raw: type
    hourly: type | None
    keys: tuple[str, ...]
    values: tuple[str, ...]


SERIES: dict[str, Series] = {
    "device": Series(DeviceMetric, DeviceMetricHourly, ("device_id",), tuple(DEVICE_VALUES)),
    "interface": Series(InterfaceMetric, InterfaceMetricHourly, ("device_id", "ifname"), tuple(INTERFACE_VALUES)),
    "gateway": Series(GatewayMetric, GatewayMetricHourly, ("device_id", "name"), tuple(GATEWAY_VALUES)),
    "radio": Series(RadioMetric, RadioMetricHourly, ("device_id", "radio"), tuple(RADIO_VALUES)),
    "service": Series(ServiceCheck, ServiceCheckHourly, ("service_id",), tuple(SERVICE_VALUES)),
    "speedtest": Series(SpeedtestResult, None, (), ("download_bps", "upload_bps", "latency_ms", "jitter_ms")),
}


# --------------------------------------------------------------------------- #
# Rollups
# --------------------------------------------------------------------------- #
async def _get_watermark(db: AsyncSession, kind: str) -> float | None:
    row = await db.get(Setting, f"rollup:{kind}")
    return float(row.value) if row and row.value else None


async def rollup_kind(kind: str, max_hours: int = 48) -> int:
    """Roll up completed hours for one series. Returns the number of hours processed."""
    s = SERIES[kind]
    if s.hourly is None:
        return 0
    current_hour = math.floor(time.time() / HOUR) * HOUR
    async with sessionmaker()() as db:
        wm = await _get_watermark(db, kind)
        if wm is None:
            first = (await db.execute(select(func.min(s.raw.ts)))).scalar()
            if first is None:
                return 0
            wm = math.floor(first / HOUR) * HOUR - HOUR
    done = 0
    hour = wm + HOUR
    while hour < current_hour and done < max_hours:
        await with_retry(lambda db, h=hour: _rollup_hour(db, s, kind, h))
        hour += HOUR
        done += 1
    return done


async def _rollup_hour(db: AsyncSession, s: Series, kind: str, hour: float) -> None:
    raw = s.raw
    cols = [getattr(raw, k) for k in s.keys]
    aggs = []
    for v in s.values:
        aggs += [func.avg(getattr(raw, v)), func.max(getattr(raw, v))]
    rows = (await db.execute(
        select(*cols, func.count(), *aggs).where(raw.ts >= hour, raw.ts < hour + HOUR).group_by(*cols)
    )).all()
    # Idempotent: replace whatever a previous (interrupted) run wrote for this hour.
    await db.execute(delete(s.hourly).where(s.hourly.ts == hour))
    if rows:
        payload = []
        for r in rows:
            rec: dict[str, Any] = {k: r[i] for i, k in enumerate(s.keys)}
            rec["ts"], rec["samples"] = hour, r[len(s.keys)]
            for j, v in enumerate(s.values):
                rec[f"{v}_avg"] = r[len(s.keys) + 1 + 2 * j]
                rec[f"{v}_max"] = r[len(s.keys) + 2 + 2 * j]
            payload.append(rec)
        await db.execute(insert(s.hourly), payload)
    key = f"rollup:{kind}"
    row = await db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=str(hour)))
    else:
        row.value = str(hour)
    await db.commit()


async def rollup_all() -> None:
    for kind, s in SERIES.items():
        if s.hourly is None:
            continue
        try:
            n = await rollup_kind(kind)
            if n:
                log.debug("Rolled up %d hour(s) of %s metrics", n, kind)
        except Exception:  # noqa: BLE001
            log.exception("Rollup of %s metrics failed", kind)


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #
def resolve_range(range_: str | None, since: float | None, until: float | None) -> tuple[float, float]:
    now = time.time()
    if since is not None:
        until = until if until is not None else now
        if until <= since:
            raise ValueError("'until' must be after 'since'")
        return since, until
    span = RANGES.get(range_ or "1h", 3600)
    return now - span, now


def _downsample(rows: list[list[Any]], start: float, span: float, width: int, points: int, use_max: bool = False,
                sample_interval: float = 60) -> list[list[Any]]:
    if not rows:
        return []
    step = max(span / points, 1)
    buckets: dict[int, list[list[float]]] = {}
    for r in rows:
        b = int((r[0] - start) // step)
        acc = buckets.setdefault(b, [[] for _ in range(width)])
        for i in range(width):
            if r[i + 1] is not None:
                acc[i].append(r[i + 1])
    out: list[list[Any]] = []
    prev: int | None = None
    for b in sorted(buckets):
        # Missing time must look missing: break the line when buckets are skipped
        # (collector offline, NetworkVision stopped...) instead of drawing across the gap.
        if prev is not None and b - prev > max(2, math.ceil(3 * sample_interval / step)):
            out.append([round(start + (prev + 1) * step + step / 2)] + [None] * width)
        vals = buckets[b]
        agg = (lambda v: max(v)) if use_max else (lambda v: sum(v) / len(v))
        out.append([round(start + b * step + step / 2)] + [agg(v) if v else None for v in vals])
        prev = b
    return out


def _stats(rows: list[list[Any]], columns: list[str], span_s: float) -> dict[str, dict[str, float | None]]:
    out: dict[str, dict[str, float | None]] = {}
    for i, c in enumerate(columns):
        vals = sorted(r[i + 1] for r in rows if r[i + 1] is not None)
        if not vals:
            out[c] = {"min": None, "avg": None, "max": None, "p95": None, "last": None}
            continue
        last = next((r[i + 1] for r in reversed(rows) if r[i + 1] is not None), None)
        st: dict[str, float | None] = {
            "min": vals[0], "avg": sum(vals) / len(vals), "max": vals[-1],
            "p95": vals[min(len(vals) - 1, int(math.ceil(0.95 * len(vals))) - 1)], "last": last,
        }
        if c.endswith("_bps"):  # average rate * time = data moved in the window
            st["total_bytes"] = st["avg"] * span_s / 8 if st["avg"] is not None else None
        out[c] = st
    return out


async def query(kind: str, filters: dict[str, Any], since: float, until: float, points: int = 300) -> dict[str, Any]:
    s = SERIES.get(kind)
    if s is None:
        raise KeyError(kind)
    missing = [k for k in s.keys if filters.get(k) in (None, "")]
    if missing:
        raise ValueError(f"missing filter(s): {', '.join(missing)}")
    span = until - since
    values = list(s.values)
    resolution = "raw"
    async with sessionmaker()() as db:
        rows: list[list[Any]] = []
        peaks: list[list[Any]] = []
        if s.hourly is not None and span > RAW_MAX_SPAN:
            resolution = "hourly"
            h = s.hourly
            cond = and_(*(getattr(h, k) == filters[k] for k in s.keys), h.ts >= since - HOUR, h.ts < until)
            hrows = (await db.execute(
                select(h.ts, *[getattr(h, f"{v}_avg") for v in values], *[getattr(h, f"{v}_max") for v in values])
                .where(cond).order_by(h.ts))).all()
            rows = [[r[0] + HOUR / 2, *r[1:1 + len(values)]] for r in hrows]
            peaks = [[r[0] + HOUR / 2, *r[1 + len(values):]] for r in hrows]
            wm = await _get_watermark(db, kind)
            raw_from = max(since, (wm + HOUR) if wm is not None else since)
        else:
            raw_from = since
        raw = s.raw
        conds = [getattr(raw, k) == filters[k] for k in s.keys] + [raw.ts >= raw_from, raw.ts <= until]
        if kind == "speedtest":
            conds.append(raw.error == "")
        rrows = (await db.execute(select(raw.ts, *[getattr(raw, v) for v in values]).where(and_(*conds)).order_by(raw.ts))).all()
        recent = [list(r) for r in rrows]
        rows += recent
        if resolution == "hourly":
            peaks += recent
    interval = HOUR if resolution == "hourly" else get_settings().metrics_persist_interval
    return {
        "kind": kind, "since": since, "until": until, "resolution": resolution, "columns": ["ts", *values],
        "points": _downsample(rows, since, span, len(values), points, sample_interval=interval)
        if kind != "speedtest" else [list(r) for r in rows],
        "peaks": _downsample(peaks, since, span, len(values), points, use_max=True, sample_interval=interval) if peaks else [],
        "stats": _stats(rows, values, span),
        "samples": len(rows),
    }

