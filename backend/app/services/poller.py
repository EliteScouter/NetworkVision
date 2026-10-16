"""Polling orchestration: one asyncio task per integration, plus housekeeping loops."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..collectors import registry
from ..collectors.base import ChildSnapshot, Collector, CollectorError, Snapshot
from ..collectors.ping import icmp_probe
from ..config import get_settings
from ..db import delete_in_chunks, sessionmaker, with_retry
from ..models import (
    Alert,
    Device,
    DeviceMetric,
    DeviceMetricHourly,
    GatewayMetric,
    GatewayMetricHourly,
    InterfaceMetric,
    InterfaceMetricHourly,
    LogEntry,
    RadioMetric,
    RadioMetricHourly,
)
from ..security import SecretError, decrypt_secrets, resolve_secret
from . import history
from .alerts import engine
from .bus import bus
from .clients import tracker as client_tracker
from .keepass import keepass
from .logs import pipeline
from .state import DeviceState, store

log = logging.getLogger("networkvision.poller")


def make_collector(dev: Device) -> Collector:
    secrets = {k: resolve_secret(v) for k, v in decrypt_secrets(dev.secrets_enc).items()}
    config = {k: resolve_secret(v) for k, v in (dev.config or {}).items()}
    return registry.build(dev.kind, dev.host, config, secrets)


async def run_collect(collector: Collector, dev: Device, timeout: float = 45) -> Snapshot:
    """Collect + (optionally) ping concurrently; never raises."""
    want_ping = collector.ping_host and (dev.config or {}).get("ping", True) and dev.host
    ping_task = asyncio.create_task(icmp_probe(dev.host)) if want_ping else None
    try:
        snap = await asyncio.wait_for(collector.collect(), timeout)
    except CollectorError as e:
        snap = Snapshot(reachable=False, error=str(e))
    except TimeoutError:
        snap = Snapshot(reachable=False, error=f"Collection timed out after {timeout:.0f}s")
    except Exception as e:  # noqa: BLE001 - a broken integration must not kill the loop
        log.exception("Collector %s (%s) crashed", dev.name, dev.kind)
        snap = Snapshot(reachable=False, error=f"{type(e).__name__}: {e}")
    if ping_task:
        latency, loss = await ping_task
        if latency is not None:
            snap.metrics.setdefault("latency_ms", round(latency, 2))
        snap.metrics.setdefault("loss_pct", round(loss, 1))
        if not snap.reachable and latency is not None:
            # Host answers ping but the API failed -> degraded, not down.
            snap.reachable = True
    return snap


class Poller:
    def __init__(self) -> None:
        self.tasks: dict[int, asyncio.Task] = {}
        self.collectors: dict[int, Collector] = {}
        self.devices: dict[int, Device] = {}
        self.children: dict[tuple[int, str], int] = {}
        self.log_watermark: dict[int, float] = {}
        self._wake: dict[int, asyncio.Event] = {}
        self._facts_hash: dict[int, str] = {}
        self._kp_versions: dict[int, int] = {}
        self._housekeeping: list[asyncio.Task] = []
        self._dirty = asyncio.Event()

    # ---------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        async with sessionmaker()() as db:
            devices = (await db.execute(select(Device))).scalars().all()
        for d in devices:
            self.devices[d.id] = d
            if d.parent_id is not None:
                self.children[(d.parent_id, d.external_id or "")] = d.id
            store.ensure(d)
        await engine.load()
        self._refresh_host_map()
        for d in devices:
            if d.parent_id is None:
                self._spawn(d)
        self._housekeeping = [asyncio.create_task(c()) for c in (
            self._persist_loop, self._retention_loop, self._broadcast_loop, self._expiry_loop, self._rollup_loop)]
        log.info("Poller started with %d integrations", sum(1 for d in devices if d.parent_id is None))

    async def stop(self) -> None:
        for t in [*self.tasks.values(), *self._housekeeping]:
            t.cancel()
        for t in [*self.tasks.values(), *self._housekeeping]:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        for c in self.collectors.values():
            with contextlib.suppress(Exception):
                await c.close()

    def _spawn(self, dev: Device) -> None:
        if not dev.enabled:
            st = store.ensure(dev)
            st.status = "disabled"
            return
        self._wake[dev.id] = asyncio.Event()
        self.tasks[dev.id] = asyncio.create_task(self._loop(dev.id), name=f"poll-{dev.id}")

    async def reload(self, device_id: int) -> None:
        """Called after create/update: rebuild the collector and restart its loop."""
        await self.remove(device_id, keep_state=True)
        async with sessionmaker()() as db:
            dev = await db.get(Device, device_id)
        if dev is None:
            return
        self.devices[dev.id] = dev
        store.ensure(dev)
        self._refresh_host_map()
        if dev.parent_id is None:
            self._spawn(dev)
        self._dirty.set()

    async def remove(self, device_id: int, keep_state: bool = False) -> None:
        task = self.tasks.pop(device_id, None)
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        c = self.collectors.pop(device_id, None)
        if c:
            with contextlib.suppress(Exception):
                await c.close()
        if not keep_state:
            self.devices.pop(device_id, None)
            for key, cid in list(self.children.items()):
                if key[0] == device_id:
                    self.children.pop(key)
                    self.devices.pop(cid, None)
            store.remove(device_id)
            await engine.drop_device(device_id)
            self._refresh_host_map()
            self._dirty.set()

    def poll_now(self, device_id: int) -> bool:
        ev = self._wake.get(device_id)
        if ev:
            ev.set()
        return ev is not None

    # ---------------------------------------------------------------- polling
    async def _loop(self, device_id: int) -> None:
        s = get_settings()
        await asyncio.sleep((device_id % 10) * 0.3)  # stagger start-up
        while True:
            dev = self.devices.get(device_id)
            if dev is None:
                return
            started = time.monotonic()
            try:
                await self.poll_device(dev)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Unexpected error polling %s", dev.name)
            interval = dev.poll_interval or s.poll_interval
            wait = max(1.0, interval - (time.monotonic() - started))
            ev = self._wake[device_id]
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(ev.wait(), wait)
            ev.clear()

    async def poll_device(self, dev: Device) -> DeviceState:
        kp_version = await asyncio.to_thread(keepass.check) if keepass.configured else 0
        collector = self.collectors.get(dev.id)
        if collector is not None and self._kp_versions.get(dev.id) != kp_version:
            # The .kdbx changed on disk: rebuild so rotated credentials take effect.
            with contextlib.suppress(Exception):
                await collector.close()
            self.collectors.pop(dev.id, None)
            collector = None
        if collector is None:
            try:
                collector = self.collectors[dev.id] = make_collector(dev)
                self._kp_versions[dev.id] = kp_version
            except SecretError as e:
                st = store.ensure(dev)
                st.mark_down(f"Credential reference failed: {e}")
                await engine.process(st)
                self._dirty.set()
                return st
        t0 = time.perf_counter()
        snap = await run_collect(collector, dev)
        st = store.ensure(dev)
        st.poll_ms = round((time.perf_counter() - t0) * 1000, 1)
        if snap.reachable:
            st.apply(snap)
            client_tracker.record(snap.clients)
        else:
            st.mark_down(snap.error or "unreachable")
            st.metrics.update({k: v for k, v in snap.metrics.items() if k in ("latency_ms", "loss_pct")})
            # Controller down -> its children are unknown, not down.
            for (pid, _), cid in self.children.items():
                if pid == dev.id and (c := store.get(cid)):
                    c.status = "unknown"
        await self._ingest_logs(dev.id, snap)
        if snap.children:
            await self._apply_children(dev, snap.children)
        await engine.process(st)
        self._dirty.set()
        return st

    async def _apply_children(self, parent: Device, children: list[ChildSnapshot]) -> None:
        new_rows: list[Device] = []
        async with sessionmaker()() as db:
            for ch in children:
                key = (parent.id, ch.external_id)
                cid = self.children.get(key)
                if cid is None:
                    row = (await db.execute(select(Device).where(
                        Device.parent_id == parent.id, Device.external_id == ch.external_id))).scalar_one_or_none()
                    if row is None:
                        row = Device(name=ch.name[:128], kind=parent.kind, role=ch.role, host=ch.host,
                                     parent_id=parent.id, external_id=ch.external_id, config={}, tags=[],
                                     facts=ch.facts)
                        db.add(row)
                        await db.flush()
                        new_rows.append(row)
                    self.children[key] = row.id
                    self.devices[row.id] = row
                    cid = row.id
                dev = self.devices[cid]
                changed = False
                if ch.host and dev.host != ch.host:
                    dev.host, changed = ch.host, True
                # A user-renamed child keeps its name (name_locked is set by the API on rename).
                if ch.name and not (dev.config or {}).get("name_locked") and dev.name != ch.name[:128]:
                    dev.name, changed = ch.name[:128], True
                if changed:
                    await db.merge(dev)
            await db.commit()
        if new_rows:
            log.info("Discovered %d new device(s) via %s", len(new_rows), parent.name)
            self._refresh_host_map()
        for ch in children:
            dev = self.devices[self.children[(parent.id, ch.external_id)]]
            if not dev.enabled:
                store.ensure(dev)
                continue
            st = store.ensure(dev)
            if ch.reachable:
                st.apply(ch)
            else:
                st.mark_down(ch.error or "offline")
            await self._ingest_logs(dev.id, ch)
            await engine.process(st)

    async def _ingest_logs(self, device_id: int, snap: Snapshot) -> None:
        if not snap.logs:
            return
        if device_id not in self.log_watermark:
            async with sessionmaker()() as db:
                wm = (await db.execute(select(func.max(LogEntry.ts)).where(
                    LogEntry.device_id == device_id, LogEntry.source == "api"))).scalar()
            self.log_watermark[device_id] = float(wm or 0)
        wm = self.log_watermark[device_id]
        dev = self.devices.get(device_id)
        newest = wm
        for line in sorted(snap.logs, key=lambda x: x.ts):
            if line.ts < wm or pipeline.is_duplicate(device_id, line.ts, line.message):
                continue
            newest = max(newest, line.ts)
            pipeline.submit({"ts": line.ts, "device_id": device_id, "host": dev.name if dev else "",
                             "severity": line.severity, "facility": line.facility, "app": line.app,
                             "message": line.message[:8000], "source": "api"})
        self.log_watermark[device_id] = newest

    def _refresh_host_map(self) -> None:
        mapping: dict[str, int] = {}
        for d in self.devices.values():
            for key in (d.host, d.name, (d.facts or {}).get("hostname"), (d.facts or {}).get("ip")):
                if key:
                    mapping[str(key)] = d.id
            for alias in (d.config or {}).get("syslog_aliases", []) or []:
                mapping[str(alias)] = d.id
        pipeline.set_hosts(mapping)

    # ------------------------------------------------------------ housekeeping
    async def _broadcast_loop(self) -> None:
        while True:
            await self._dirty.wait()
            self._dirty.clear()
            if bus.subscribers:
                bus.publish({"type": "state", "ts": time.time(), "devices": [d.summary() for d in store.devices.values()]})
            await asyncio.sleep(2)

    async def _expiry_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            with contextlib.suppress(Exception):
                await engine.expire_events()

    async def _persist_loop(self) -> None:
        s = get_settings()
        while True:
            await asyncio.sleep(s.metrics_persist_interval)
            try:
                await self.persist_once()
            except Exception:  # noqa: BLE001
                log.exception("Metric persistence failed")

    async def persist_once(self) -> None:
        now = time.time()
        dev_rows: list[dict[str, Any]] = []
        if_rows: list[dict[str, Any]] = []
        gw_rows: list[dict[str, Any]] = []
        radio_rows: list[dict[str, Any]] = []
        for st in store.devices.values():
            if not st.enabled or st.status in ("unknown", "disabled") or st.id not in self.devices:
                continue
            m = st.metrics
            dev_rows.append({"ts": now, "device_id": st.id, "status": 0 if st.status == "down" else 1,
                             "cpu": m.get("cpu"), "mem": m.get("mem"), "temp": m.get("temp"),
                             "latency_ms": m.get("latency_ms"), "loss_pct": m.get("loss_pct"),
                             "rx_bps": st.rx_bps, "tx_bps": st.tx_bps,
                             "clients": int(m["clients"]) if m.get("clients") is not None else None})
            for i in st.interfaces.values():
                if i.oper_up and (i.rx_bps is not None or i.errors_per_min):
                    if_rows.append({"ts": now, "device_id": st.id, "ifname": i.name[:64], "rx_bps": i.rx_bps or 0,
                                    "tx_bps": i.tx_bps or 0, "errors_per_min": i.errors_per_min, "util_pct": i.util_pct})
            for g in st.gateways:
                gw_rows.append({"ts": now, "device_id": st.id, "name": g.name[:64],
                                "up": None if g.up is None else int(g.up), "latency_ms": g.latency_ms, "loss_pct": g.loss_pct})
            for ap in (st.wifi or {}).get("aps", []):
                ap_id = self.children.get((st.id, ap.get("mac", "")))
                if ap_id is None or not ap.get("online"):
                    continue
                for r in ap.get("radios", []):
                    radio_rows.append({"ts": now, "device_id": ap_id, "radio": str(r.get("band"))[:16],
                                       "channel": r.get("channel"), "utilization": r.get("utilization"),
                                       "interference": r.get("interference"), "clients": r.get("clients"),
                                       "satisfaction": r.get("satisfaction"), "retries_pct": r.get("retries_pct")})
        updates: list[tuple[int, dict[str, Any], str | None]] = []
        for st in store.devices.values():
            if self.devices.get(st.id) is None:
                continue
            values: dict[str, Any] = {"last_seen": st.last_ok}
            h = hashlib.md5(json.dumps(st.facts, sort_keys=True, default=str).encode()).hexdigest()
            if h != self._facts_hash.get(st.id):
                values["facts"] = st.facts
            updates.append((st.id, values, h))

        async def _write(db: AsyncSession) -> None:
            if dev_rows:
                await db.execute(DeviceMetric.__table__.insert(), dev_rows)
            if if_rows:
                await db.execute(InterfaceMetric.__table__.insert(), if_rows)
            if gw_rows:
                await db.execute(GatewayMetric.__table__.insert(), gw_rows)
            if radio_rows:
                await db.execute(RadioMetric.__table__.insert(), radio_rows)
            for dev_id, values, _ in updates:
                await db.execute(Device.__table__.update().where(Device.id == dev_id).values(**values))
            await db.commit()

        await with_retry(_write)
        for dev_id, _, h in updates:  # only remember facts once they are really committed
            self._facts_hash[dev_id] = h

    async def _rollup_loop(self) -> None:
        await asyncio.sleep(90)
        while True:
            await history.rollup_all()
            await asyncio.sleep(600)

    async def _retention_loop(self) -> None:
        s = get_settings()
        await asyncio.sleep(60)
        while True:
            try:
                now = time.time()
                metrics_cutoff = now - s.retention_days_metrics * 86400
                rollup_cutoff = now - s.retention_days_rollup * 86400
                removed = {
                    "device metrics": await delete_in_chunks(DeviceMetric, DeviceMetric.ts < metrics_cutoff),
                    "interface metrics": await delete_in_chunks(InterfaceMetric, InterfaceMetric.ts < metrics_cutoff),
                    "gateway metrics": await delete_in_chunks(GatewayMetric, GatewayMetric.ts < metrics_cutoff),
                    "radio metrics": await delete_in_chunks(RadioMetric, RadioMetric.ts < metrics_cutoff),
                    **{f"hourly {m.__tablename__}": await delete_in_chunks(m, m.ts < rollup_cutoff) for m in (
                        DeviceMetricHourly, InterfaceMetricHourly, GatewayMetricHourly, RadioMetricHourly)},
                    "logs": await delete_in_chunks(LogEntry, LogEntry.ts < now - s.retention_days_logs * 86400),
                    "alerts": await delete_in_chunks(Alert, Alert.resolved_at.is_not(None)
                                                     & (Alert.resolved_at < now - s.retention_days_alerts * 86400)),
                }
                if any(removed.values()):
                    log.info("Retention cleanup removed %s", ", ".join(f"{n} {k}" for k, n in removed.items() if n))
            except Exception:  # noqa: BLE001
                log.exception("Retention cleanup failed")
            await asyncio.sleep(3600)


poller = Poller()
