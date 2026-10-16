"""Internet speed tests (Cloudflare's public speed-test endpoints, no binary needed).

Measures from the NetworkVision host through your firewall: idle latency + jitter,
download and upload over parallel streams, and latency *under load* (bufferbloat).
Runs on a schedule (default hourly), on demand, streams live progress over the
WebSocket and stores every result for history and alerting.

Note: each run moves real data (roughly link speed x duration in each direction).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import statistics
import time
from collections.abc import Callable
from typing import Any

import httpx
from sqlalchemy import select

from ..config import get_settings
from ..db import sessionmaker, with_retry
from ..models import Setting, SpeedtestResult
from .bus import bus

log = logging.getLogger("networkvision.speedtest")
BASE = "https://speed.cloudflare.com"
DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "interval_min": 60,
    "duration_s": 6,
    "streams": 6,
    "expected_down_mbps": None,
    "expected_up_mbps": None,
    "alert_pct": 70,
}
LIMITS = {"interval_min": (10, 1440), "duration_s": (3, 30), "streams": (1, 16), "alert_pct": (10, 100)}
UPLOAD_CHUNK = 2_000_000


_L4_RTT = re.compile(r"[?&]rtt=(\d+)")
_DUR = re.compile(r"cfSpeed\w+;dur=([\d.]+)")


def rtt_from_server_timing(header: str, elapsed_ms: float) -> float:
    """Network round-trip time for one probe.

    Cloudflare reports the TCP RTT it measured (cfL4 ``rtt``, microseconds) - the true
    network latency. Without it, subtract the server's own processing time from the
    client-side elapsed time, which otherwise dominates (tens of ms of worker time).
    """
    m = _L4_RTT.search(header)
    if m:
        return int(m.group(1)) / 1000
    server_ms = sum(float(x) for x in _DUR.findall(header))
    return max(0.1, elapsed_ms - server_ms)


def result_dict(r: SpeedtestResult) -> dict[str, Any]:
    return {k: getattr(r, k) for k in ("id", "ts", "engine", "trigger", "server", "isp", "public_ip", "download_bps",
                                       "upload_bps", "latency_ms", "jitter_ms", "loaded_latency_ms", "bytes_used",
                                       "duration_s", "error")}


class CloudflareEngine:
    name = "cloudflare"

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.transport = transport

    def client(self, streams: int) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=BASE, transport=self.transport, timeout=httpx.Timeout(30, connect=10),
            limits=httpx.Limits(max_connections=streams + 4, max_keepalive_connections=streams + 4),
            headers={"User-Agent": "NetworkVision-speedtest", "Referer": BASE + "/"},
        )

    async def run(self, cfg: dict[str, Any], progress: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        streams, duration = int(cfg["streams"]), float(cfg["duration_s"])
        out: dict[str, Any] = {"bytes_used": 0}
        async with self.client(streams) as c:
            try:
                meta = (await c.get("/meta")).json()
                colo = meta.get("colo")
                # Older responses had colo as a string; current ones are {"iata": "PDX", "city": "Portland", ...}.
                if isinstance(colo, dict):
                    out["server"] = " ".join(str(x) for x in (colo.get("iata"), colo.get("city")) if x)
                else:
                    out["server"] = " ".join(str(x) for x in (colo, meta.get("city")) if x)
                out["isp"] = meta.get("asOrganization") or ""
                out["public_ip"] = meta.get("clientIp") or ""
            except (httpx.HTTPError, ValueError):
                pass
            progress({"phase": "latency", "progress": 0.02})
            idle = await self._pings(c, 12)
            if idle:
                out["latency_ms"] = statistics.median(idle)
                out["jitter_ms"] = statistics.mean(abs(a - b) for a, b in zip(idle, idle[1:], strict=False)) if len(idle) > 1 else 0.0
            loaded: list[float] = []
            out["download_bps"] = await self._transfer(c, "down", streams, duration, progress, out, loaded)
            out["upload_bps"] = await self._transfer(c, "up", streams, duration, progress, out, None)
            if loaded:
                out["loaded_latency_ms"] = statistics.median(loaded)
        return out

    async def _pings(self, c: httpx.AsyncClient, n: int) -> list[float]:
        samples = []
        for i in range(n):
            t = time.perf_counter()
            try:
                r = await c.get("/__down", params={"bytes": 0})
            except httpx.HTTPError:
                continue
            if i:  # first request pays for TLS/connection setup
                samples.append(rtt_from_server_timing(r.headers.get("server-timing", ""), (time.perf_counter() - t) * 1000))
        return samples

    async def _transfer(self, c: httpx.AsyncClient, direction: str, streams: int, duration: float,
                        progress: Callable[[dict[str, Any]], None], out: dict[str, Any], loaded: list[float] | None) -> float:
        counted = 0
        start = time.perf_counter()
        warmup = min(1.0, duration / 4)
        deadline = start + warmup + duration
        measured_from: tuple[float, int] | None = None
        payload = os.urandom(UPLOAD_CHUNK) if direction == "up" else b""

        def add(n: int) -> None:
            # The warm-up boundary is stamped here, as bytes arrive - not by the monitor loop,
            # which may run late on a busy host and would then see an already-final counter.
            nonlocal counted, measured_from
            if measured_from is None and time.perf_counter() - start >= warmup:
                measured_from = (time.perf_counter(), counted)
            counted += n

        async def worker() -> None:
            while time.perf_counter() < deadline:
                if direction == "down":
                    async with c.stream("GET", "/__down", params={"bytes": 50_000_000}) as r:
                        async for chunk in r.aiter_bytes(65536):
                            add(len(chunk))
                            if time.perf_counter() >= deadline:
                                break
                else:
                    await c.post("/__up", content=payload)
                    add(len(payload))

        async def pinger() -> None:
            while time.perf_counter() < deadline:
                await asyncio.sleep(0.5)
                loaded.extend(await self._pings(c, 2))  # type: ignore[union-attr]

        tasks = [asyncio.create_task(worker()) for _ in range(streams)]
        if loaded is not None:
            tasks.append(asyncio.create_task(pinger()))
        last_t, last_b = start, 0
        try:
            while time.perf_counter() < deadline and not all(t.done() for t in tasks[:streams]):
                await asyncio.sleep(0.4)
                now = time.perf_counter()
                inst = (counted - last_b) * 8 / max(now - last_t, 1e-6)
                last_t, last_b = now, counted
                frac = min(1.0, (now - start) / (warmup + duration))
                progress({"phase": "download" if direction == "down" else "upload", "mbps": inst / 1e6,
                          "progress": (0.05 + 0.45 * frac) if direction == "down" else (0.5 + 0.5 * frac)})
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        end = time.perf_counter()
        out["bytes_used"] += counted
        failures = [t.exception() for t in tasks[:streams] if not t.cancelled() and t.exception()]
        if counted == 0 and failures:
            raise RuntimeError(f"{direction}load failed: {failures[0]}")
        t0, b0 = measured_from or (start, 0)
        return (counted - b0) * 8 / max(end - t0, 1e-6)


class DemoEngine:
    """Simulated results for NV_DEMO_MODE (never touches the internet)."""

    name = "demo"

    async def run(self, cfg: dict[str, Any], progress: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        down, up = random.uniform(820, 945) * 1e6, random.uniform(33, 39) * 1e6
        for i in range(20):
            await asyncio.sleep(0.15)
            phase = "download" if i < 10 else "upload"
            base = down if phase == "download" else up
            progress({"phase": phase, "mbps": base / 1e6 * random.uniform(0.85, 1.05), "progress": (i + 1) / 20})
        return {"server": "SEA Seattle", "isp": "Demo Fiber", "public_ip": "203.0.113.42", "download_bps": down,
                "upload_bps": up, "latency_ms": random.uniform(9, 14), "jitter_ms": random.uniform(0.4, 2.0),
                "loaded_latency_ms": random.uniform(14, 40), "bytes_used": int((down + up) / 8 * cfg["duration_s"])}


class SpeedtestService:
    def __init__(self) -> None:
        self.settings: dict[str, Any] = dict(DEFAULTS)
        self.running = False
        self.progress: dict[str, Any] = {}
        self.last_ts: float | None = None
        self._lock = asyncio.Lock()
        self.engine: CloudflareEngine | DemoEngine = CloudflareEngine()

    async def load(self) -> None:
        if get_settings().demo_mode:
            self.engine = DemoEngine()
        async with sessionmaker()() as db:
            row = await db.get(Setting, "speedtest")
            last = (await db.execute(select(SpeedtestResult.ts).order_by(SpeedtestResult.ts.desc()).limit(1))).scalar()
        if row and row.value:
            try:
                self.settings = {**DEFAULTS, **json.loads(row.value)}
            except ValueError:
                pass
        self.last_ts = last

    async def update_settings(self, patch: dict[str, Any]) -> dict[str, Any]:
        new = {**self.settings}
        for k, v in patch.items():
            if k not in DEFAULTS:
                continue
            if k in LIMITS and v is not None:
                lo, hi = LIMITS[k]
                v = max(lo, min(hi, int(v)))
            new[k] = v
        blob = json.dumps(new)

        async def _save(db) -> None:
            row = await db.get(Setting, "speedtest")
            if row is None:
                db.add(Setting(key="speedtest", value=blob))
            else:
                row.value = blob
            await db.commit()

        await with_retry(_save)
        self.settings = new
        return new

    def next_run(self) -> float | None:
        if not self.settings.get("enabled"):
            return None
        return (self.last_ts or 0) + self.settings["interval_min"] * 60

    async def run(self, trigger: str = "manual") -> dict[str, Any]:
        if self._lock.locked():
            raise RuntimeError("A speed test is already running")
        async with self._lock:
            self.running = True
            started = time.time()
            self._emit({"state": "running", "phase": "starting", "progress": 0.0})
            rec = SpeedtestResult(ts=started, engine=self.engine.name, trigger=trigger)
            try:
                res = await self.engine.run(self.settings, lambda p: self._emit({"state": "running", **p}))
                for k, v in res.items():
                    setattr(rec, k, v)
            except Exception as e:  # noqa: BLE001 - any failure becomes a stored, visible result
                log.warning("Speed test failed: %s", e)
                rec.error = f"{type(e).__name__}: {e}"[:500]
            rec.duration_s = time.time() - started
            self.last_ts = started

            async def _save(db) -> SpeedtestResult:
                db.add(rec)
                await db.commit()
                return rec

            await with_retry(_save)
            result = result_dict(rec)
            self.running = False
            self.progress = {}
            self._emit({"state": "done", "result": result})
            await self._check_alerts(result)
            return result

    def _emit(self, payload: dict[str, Any]) -> None:
        self.progress = payload if payload.get("state") == "running" else {}
        bus.publish({"type": "speedtest", **payload})

    async def _check_alerts(self, r: dict[str, Any]) -> None:
        from .alerts import engine  # local import: avoid cycle

        ttl = self.settings["interval_min"] * 60 + 600
        if r.get("error"):
            await engine.raise_event(None, "speedtest:failed", "Speed test failed", r["error"], severity="warning",
                                     ttl=ttl, rule="speedtest_failed")
            return
        pct = self.settings["alert_pct"] / 100
        slow = []
        for key, label in (("down", "download"), ("up", "upload")):
            expected = self.settings.get(f"expected_{key}_mbps")
            got = (r.get(f"{label}_bps") or 0) / 1e6
            if expected and got < expected * pct:
                slow.append(f"{label} {got:.0f} Mbps (expected {expected:.0f})")
        if slow:
            await engine.raise_event(None, "speedtest:slow", "Internet slower than expected", "; ".join(slow),
                                     severity="warning", ttl=ttl, rule="speedtest_slow")

    async def scheduler(self) -> None:
        await asyncio.sleep(120)  # let the app settle after start-up
        while True:
            due = self.next_run()
            if due is not None and time.time() >= due and not self.running:
                try:
                    await self.run("schedule")
                except Exception:  # noqa: BLE001
                    log.exception("Scheduled speed test crashed")
            await asyncio.sleep(30)

    async def recent(self, limit: int = 30) -> list[dict[str, Any]]:
        async with sessionmaker()() as db:
            rows = (await db.execute(select(SpeedtestResult).order_by(SpeedtestResult.ts.desc()).limit(limit))).scalars().all()
        return [result_dict(r) for r in rows]


speedtest = SpeedtestService()
