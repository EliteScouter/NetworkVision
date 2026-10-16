"""Firewall log explorer: filterlog lines -> structured ``firewall_events`` rows.

Every batch from the log pipeline (syslog and API-polled) is offered to
:meth:`FirewallService.ingest`. filterlog records are parsed, enriched with the
firewall's friendly interface name (igb0.20 -> HOME) and the rule description
(tracker 1770009104 -> "pfB_Top_v4 auto rule"), then buffered and written in
small batches (Galera friendly). Every event is counted per minute, including
the ones the operator chose not to store (pass traffic, multicast noise), so the
timeline stays truthful.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any

from sqlalchemy import insert

from ..config import get_settings
from ..db import delete_in_chunks, with_retry
from ..filterlog import FilterLogEvent, ip_key, is_noise, looks_like_filterlog, parse, rule_label
from ..models import FirewallEvent, FirewallMinute
from .state import store

log = logging.getLogger("networkvision.firewall")
MAX_BUFFER = 200_000
CHUNK = 1000


def _maps() -> tuple[dict[tuple[int | None, str], str], dict[int | None, dict[str, str]]]:
    """Interface (real NIC -> friendly name) and rule (tracker/label -> description) maps.

    Built from the live device state: collectors put each interface's NIC in ``alias`` and the
    firewall rules in a ``rules`` section with a Tracker (pfSense) or Label (OPNsense) column.
    The ``None`` key holds a merged map, used for syslog lines we could not attribute to a device.
    """
    ifmap: dict[tuple[int | None, str], str] = {}
    rules: dict[int | None, dict[str, str]] = {None: {}}
    for d in list(store.devices.values()):
        for i in d.interfaces.values():
            if i.alias and i.alias != i.name:
                ifmap[(d.id, i.alias)] = i.name
                ifmap.setdefault((None, i.alias), i.name)
        for sec in d.sections:
            if sec.id != "rules":
                continue
            cols = [str(c).lower() for c in sec.columns]
            id_col = next((cols.index(c) for c in ("tracker", "label") if c in cols), None)
            desc_col = cols.index("description") if "description" in cols else None
            if id_col is None or desc_col is None:
                continue
            m = rules.setdefault(d.id, {})
            for row in sec.rows:
                if len(row) > max(id_col, desc_col) and row[id_col] not in (None, "") and row[desc_col]:
                    key, desc = str(row[id_col]), str(row[desc_col])
                    m[key] = desc
                    rules[None].setdefault(key, desc)
    return ifmap, rules


class FirewallService:
    def __init__(self) -> None:
        self.buffer: list[dict[str, Any]] = []
        self.counts: dict[tuple[int, int | None, str, str], list[int]] = {}
        self.stats = {"parsed": 0, "stored": 0, "skipped": 0, "dropped": 0, "unparsed": 0}
        self._ifmap: dict[tuple[int | None, str], str] = {}
        self._rules: dict[int | None, dict[str, str]] = {None: {}}
        self._maps_ts = 0.0

    # ------------------------------------------------------------ enrichment
    def _refresh(self) -> None:
        now = time.monotonic()
        if now - self._maps_ts > 30:
            self._ifmap, self._rules = _maps()
            self._maps_ts = now

    def iface_name(self, device_id: int | None, iface: str) -> str:
        return self._ifmap.get((device_id, iface)) or self._ifmap.get((None, iface)) or iface

    def rule_name(self, device_id: int | None, rule_id: str) -> str:
        return rule_label(rule_id, self._rules.get(device_id)) or rule_label(rule_id, self._rules.get(None))

    def to_row(self, ev: FilterLogEvent, ts: float, device_id: int | None) -> dict[str, Any]:
        return {
            "ts": ts, "device_id": device_id, "action": ev.action[:8], "direction": ev.direction[:4],
            "iface": ev.iface[:32], "iface_name": self.iface_name(device_id, ev.iface)[:48],
            "rule_id": ev.rule_id[:40], "rule": self.rule_name(device_id, ev.rule_id)[:128],
            "ipver": ev.ipver, "proto": ev.proto[:12],
            "src_ip": ev.src, "src_key": ip_key(ev.src), "src_port": ev.sport,
            "dst_ip": ev.dst, "dst_key": ip_key(ev.dst), "dst_port": ev.dport,
            "tcp_flags": ev.tcp_flags[:12], "length": ev.length, "info": ev.info[:64],
            "noise": is_noise(ev.src, ev.dst),
        }

    # ---------------------------------------------------------------- ingest
    def ingest(self, batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Pick filterlog lines out of a log batch. Returns the lines to keep in the generic log table."""
        s = get_settings()
        if not s.firewall_enabled:
            return batch
        self._refresh()
        keep: list[dict[str, Any]] = []
        for e in batch:
            msg = e.get("message", "")
            if not looks_like_filterlog(e.get("app", ""), msg):
                keep.append(e)
                continue
            try:
                ev = parse(msg)
            except Exception:  # noqa: BLE001 - one weird line must not stop the rest
                ev = None
            if ev is None:
                self.stats["unparsed"] += 1
                keep.append(e)
                continue
            if s.firewall_keep_raw_logs:
                keep.append(e)
            self.stats["parsed"] += 1
            dev = e.get("device_id")
            ts = float(e.get("ts") or time.time())
            row = self.to_row(ev, ts, dev)
            store_it = (s.firewall_store_pass or row["action"] != "pass") and (s.firewall_store_noise or not row["noise"])
            slot = self.counts.setdefault((int(ts // 60) * 60, dev, row["action"], row["iface_name"]), [0, 0])
            slot[0] += 1
            if not store_it:
                slot[1] += 1
                self.stats["skipped"] += 1
            elif len(self.buffer) < MAX_BUFFER:
                self.buffer.append(row)
            else:
                self.stats["dropped"] += 1
        return keep

    def pending_counts(self) -> list[tuple[int, int | None, str, str, int, int]]:
        """Counts not yet flushed to firewall_minutes (the timeline adds them for the live edge)."""
        return [(*k, v[0], v[1]) for k, v in self.counts.items()]

    # ----------------------------------------------------------------- flush
    async def flush(self, final: bool = False) -> None:
        for _ in range(50):  # bounded: a flood must not starve the counters / event loop
            if not self.buffer:
                break
            chunk, self.buffer = self.buffer[:CHUNK], self.buffer[CHUNK:]

            async def _write(db, rows=chunk):
                await db.execute(insert(FirewallEvent), rows)
                await db.commit()

            try:
                await with_retry(_write)
                self.stats["stored"] += len(chunk)
            except Exception:  # noqa: BLE001 - keep going, drop this chunk
                self.stats["dropped"] += len(chunk)
                log.exception("Failed to store %d firewall events", len(chunk))
        current = int(time.time() // 60) * 60
        done = [k for k in self.counts if final or k[0] < current]
        if not done:
            return
        rows = [{"ts": k[0], "device_id": k[1], "action": k[2], "iface_name": k[3][:48],
                 "events": self.counts[k][0], "skipped": self.counts[k][1]} for k in done]
        for k in done:
            self.counts.pop(k, None)

        async def _counts(db):
            await db.execute(insert(FirewallMinute), rows)
            await db.commit()

        try:
            await with_retry(_counts)
        except Exception:  # noqa: BLE001
            log.exception("Failed to store firewall counters")

    async def run(self) -> None:
        last_retention = time.monotonic() - 3300  # first cleanup ~5 min after start
        while True:
            await asyncio.sleep(2)
            with contextlib.suppress(Exception):
                await self.flush()
            if time.monotonic() - last_retention > 3600:
                last_retention = time.monotonic()
                await self.retention()

    async def retention(self) -> None:
        cutoff = time.time() - get_settings().retention_days_firewall * 86400
        try:
            n = await delete_in_chunks(FirewallEvent, FirewallEvent.ts < cutoff)
            m = await delete_in_chunks(FirewallMinute, FirewallMinute.ts < cutoff)
            if n or m:
                log.info("Firewall retention removed %d events, %d counter rows", n, m)
        except Exception:  # noqa: BLE001
            log.exception("Firewall retention failed")


firewall = FirewallService()
