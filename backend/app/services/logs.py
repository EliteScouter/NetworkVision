"""Log pipeline: every log line (syslog or API-polled) flows through here.

Lines are attributed to a device (by source IP / hostname), de-duplicated,
batch-inserted into the database and streamed live to connected dashboards.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import OrderedDict, deque
from typing import Any

from sqlalchemy import insert

from ..db import with_retry
from ..models import LogEntry
from .bus import bus

log = logging.getLogger("networkvision.logs")
SEV_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


class LogPipeline:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=50_000)
        self.host_map: dict[str, int] = {}
        self._seen: dict[int, OrderedDict[str, None]] = {}
        self.dropped = 0
        self.received = 0
        self.rate: deque[tuple[float, int]] = deque(maxlen=120)

    def set_hosts(self, mapping: dict[str, int]) -> None:
        self.host_map = {k.lower(): v for k, v in mapping.items() if k}

    def device_for(self, *candidates: str) -> int | None:
        for c in candidates:
            if c and (d := self.host_map.get(c.lower())) is not None:
                return d
        return None

    def is_duplicate(self, device_id: int, ts: float, message: str) -> bool:
        """API-polled logs overlap between polls; remember recent line hashes per device."""
        h = hashlib.blake2s(f"{ts:.0f}|{message}".encode(), digest_size=12).hexdigest()
        seen = self._seen.setdefault(device_id, OrderedDict())
        if h in seen:
            return True
        seen[h] = None
        while len(seen) > 5000:
            seen.popitem(last=False)
        return False

    def submit(self, entry: dict[str, Any]) -> None:
        self.received += 1
        try:
            self.queue.put_nowait(entry)
        except asyncio.QueueFull:
            self.dropped += 1

    async def run(self) -> None:
        from .alerts import engine  # local import: avoid cycle

        self.queue = asyncio.Queue(maxsize=50_000)  # bind to the running loop (not the import-time one)
        while True:
            first = await self.queue.get()
            batch = [first]
            deadline = time.monotonic() + 0.75
            while len(batch) < 1000:  # modest batches keep Galera write sets small
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self.queue.get(), timeout))
                except TimeoutError:
                    break
            self.rate.append((time.time(), len(batch)))
            async def _write(db, rows=batch):
                await db.execute(insert(LogEntry), rows)
                await db.commit()

            try:
                await with_retry(_write)
            except Exception:  # noqa: BLE001 - never let the pipeline die
                log.exception("Failed to persist %d log lines", len(batch))
            bus.publish({"type": "logs", "items": batch[-300:]})
            for e in batch:
                if e["severity"] <= 2 and e.get("source") != "system":
                    digest = hashlib.blake2s(e["message"][:80].encode(), digest_size=6).hexdigest()
                    await engine.raise_event(
                        e.get("device_id"), f"log:{e.get('device_id') or e.get('host')}:{digest}",
                        f"{SEV_NAMES[e['severity']].upper()} log from {e.get('host') or 'unknown'}",
                        f"{e.get('app') or ''}: {e['message'][:500]}".strip(": "),
                        severity="critical",
                    )

    def per_minute(self) -> float:
        cutoff = time.time() - 60
        return float(sum(n for t, n in self.rate if t >= cutoff))


pipeline = LogPipeline()
