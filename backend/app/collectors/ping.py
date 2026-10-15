"""Host reachability monitor (ICMP with automatic TCP fallback) + the probe helper
used by the poller to measure latency/loss for every device."""

from __future__ import annotations

import asyncio
import time

from icmplib import async_ping
from icmplib.exceptions import ICMPLibError

from ..config import get_settings
from .base import Collector, CollectorError, FieldSpec, Snapshot


async def icmp_probe(host: str, count: int = 3) -> tuple[float | None, float]:
    """Return (avg_latency_ms | None, loss_pct)."""
    try:
        r = await async_ping(host, count=count, interval=0.2, timeout=1.5,
                             privileged=get_settings().ping_privileged)
        return (r.avg_rtt if r.is_alive else None), r.packet_loss * 100
    except (ICMPLibError, OSError):
        return None, 100.0


async def tcp_probe(host: str, port: int, timeout: float = 2.0) -> float | None:
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return (time.perf_counter() - start) * 1000
    except (TimeoutError, OSError):
        return None


class PingCollector(Collector):
    kind = "ping"
    label = "Ping / TCP monitor"
    vendor = "Any"
    description = "Up/down, latency and packet loss for anything with an IP: servers, APs, printers, unmanaged switches."
    default_role = "server"
    ping_host = False  # we *are* the ping
    fields = [
        FieldSpec(key="count", label="Pings per poll", type="number", default=4),
        FieldSpec(key="tcp_port", label="TCP port (optional)", type="number",
                  help="Also check a TCP port (e.g. 443). Used as fallback when ICMP is blocked."),
    ]

    async def collect(self) -> Snapshot:
        latency, loss = await icmp_probe(self.host, int(self.opt("count") or 4))
        snap = Snapshot(metrics={"latency_ms": latency, "loss_pct": loss})
        port = self.opt("tcp_port")
        if port:
            tcp = await tcp_probe(self.host, int(port))
            snap.metrics["tcp_ms"] = tcp
            if latency is None and tcp is not None:
                snap.metrics["latency_ms"], snap.metrics["loss_pct"] = tcp, 0.0
            if tcp is None:
                snap.error = f"TCP port {port} closed"
        snap.metrics = {k: v for k, v in snap.metrics.items() if v is not None}
        if snap.metrics.get("latency_ms") is None:
            raise CollectorError(f"{self.host} is not responding")
        return snap
