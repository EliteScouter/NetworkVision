"""Security engine.

Every log line from the pipeline is offered to :meth:`SecurityEngine.ingest_batch`.
Firewall, authentication and IDS lines are turned into structured events which:

* feed in-memory sliding windows per source IP, used by the detectors
  (brute force, port scan, login-after-failures, IDS, WAN block spikes);
* are aggregated per minute into ``security_events`` (bounded storage, not one row
  per packet);
* are streamed to dashboards as a live feed.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import insert

from ..config import get_settings
from ..db import with_retry
from ..models import SecurityEvent
from ..security_parsers import AuthEvent, FwEvent, IdsEvent, is_internal, parse_auth, parse_filterlog, parse_ids, service_name
from .alerts import engine as alerts
from .bus import bus
from .geoip import country
from .state import store

log = logging.getLogger("networkvision.security")
MAX_TRACKED_SOURCES = 50_000
REALERT_SECONDS = 30  # throttle repeated raise_event calls for the same source
FLUSH_BATCH = 500  # rows per INSERT transaction (Galera write-set size)


@dataclass
class SourceWindow:
    fails: deque = field(default_factory=lambda: deque(maxlen=5000))  # (ts, service, user)
    touches: deque = field(default_factory=lambda: deque(maxlen=5000))  # (ts, dst, dport, passed)
    last: float = 0.0


def _wan_ifaces() -> dict[tuple[int, str], bool]:
    """(device_id, raw interface) -> is WAN, from firewalls' interface name/alias pairs."""
    out: dict[tuple[int, str], bool] = {}
    for d in store.devices.values():
        if d.role not in ("firewall", "router"):
            continue
        for i in d.interfaces.values():
            is_wan = "wan" in i.name.lower() or "wan" in i.alias.lower()
            for raw in (i.alias, i.name):
                if raw:
                    out[(d.id, raw)] = is_wan
    return out


class SecurityEngine:
    def __init__(self) -> None:
        self.sources: dict[str, SourceWindow] = {}
        self._agg: dict[tuple, list[Any]] = {}
        self._last_alert: dict[str, float] = {}
        self._wan_blocks = 0
        self._baseline: float | None = None
        self._minutes = 0
        self._ignore: list = []
        self._ignore_raw: str | None = None
        self._wan_cache: dict[tuple[int, str], bool] = {}
        self._wan_cache_ts = 0.0
        self.stats = {"firewall": 0, "auth_fail": 0, "auth_ok": 0, "ids": 0}

    # ------------------------------------------------------------ helpers
    def _ignored(self, ip: str) -> bool:
        raw = get_settings().sec_ignore_ips
        if raw != self._ignore_raw:
            self._ignore_raw = raw
            self._ignore = []
            for part in raw.split(","):
                with contextlib.suppress(ValueError):
                    if part.strip():
                        self._ignore.append(ipaddress.ip_network(part.strip(), strict=False))
        if not self._ignore:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(addr in n for n in self._ignore if n.version == addr.version)

    def _is_wan(self, device_id: int | None, iface: str, src: str, direction: str) -> bool:
        now = time.time()
        if now - self._wan_cache_ts > 30:
            self._wan_cache, self._wan_cache_ts = _wan_ifaces(), now
        if device_id is not None and (device_id, iface) in self._wan_cache:
            return self._wan_cache[(device_id, iface)]
        return direction == "in" and not is_internal(src)

    def _window(self, ip: str) -> SourceWindow:
        w = self.sources.get(ip)
        if w is None:
            if len(self.sources) >= MAX_TRACKED_SOURCES:
                self._prune(force=True)
            w = self.sources[ip] = SourceWindow()
        return w

    def _bucket(self, cat: str, ts: float, src: str, dst: str = "", dport: int | None = None, proto: str = "",
                iface: str = "", service: str = "", user: str = "", device_id: int | None = None, severity: int = 0,
                detail: str = "") -> None:
        key = (int(ts // 60) * 60, cat, src, dst, dport, proto, iface, service, user[:64], device_id, severity)
        slot = self._agg.get(key)
        if slot is None:
            self._agg[key] = [1, detail[:255]]
        else:
            slot[0] += 1

    def _throttled(self, key: str) -> bool:
        now = time.time()
        if now - self._last_alert.get(key, 0) < REALERT_SECONDS:
            return True
        self._last_alert[key] = now
        return False

    # ------------------------------------------------------------- ingest
    async def ingest_batch(self, batch: list[dict[str, Any]]) -> None:
        if not get_settings().sec_enabled:
            return
        feed: list[dict[str, Any]] = []
        for e in batch:
            try:
                await self._ingest(e, feed)
            except Exception:  # noqa: BLE001 - one weird line must not stop the rest
                log.debug("security ingest failed", exc_info=True)
        if feed:
            bus.publish({"type": "security", "items": feed[-200:]})

    async def _ingest(self, e: dict[str, Any], feed: list[dict[str, Any]]) -> None:
        msg, app, ts = e.get("message", ""), e.get("app", ""), float(e.get("ts") or time.time())
        dev = e.get("device_id")
        if "filterlog" in app or (msg[:1].isdigit() and ",match," in msg[:80]):
            fw = parse_filterlog(msg)
            if fw:
                await self._on_firewall(fw, ts, dev, feed)
            return
        ids = parse_ids(msg)
        if ids:
            await self._on_ids(ids, ts, dev, feed)
            return
        auth = parse_auth(app, msg)
        if auth:
            await self._on_auth(auth, ts, dev, feed)

    async def _on_firewall(self, fw: FwEvent, ts: float, dev: int | None, feed: list) -> None:
        if self._ignored(fw.src):
            return
        self.stats["firewall"] += 1
        blocked = fw.action == "block"
        cat = "block" if blocked else "pass"
        wan = self._is_wan(dev, fw.iface, fw.src, fw.direction)
        self._bucket(cat, ts, fw.src, fw.dst, fw.dport, fw.proto, fw.iface, service_name(fw.dport, fw.proto), device_id=dev)
        if blocked and wan:
            self._wan_blocks += 1
        # Outbound pass traffic from LAN clients is normal; only track inbound / blocked touches.
        if not blocked and is_internal(fw.src) and not is_internal(fw.dst):
            return
        w = self._window(fw.src)
        w.last = ts
        w.touches.append((ts, fw.dst, fw.dport, not blocked))
        if blocked and len(feed) < 400 and (wan or not is_internal(fw.src)):
            feed.append(self._feed_item("block", ts, fw.src, fw.dst, fw.dport, fw.proto, service_name(fw.dport, fw.proto), dev))
        await self._check_scan(fw.src, w, dev)

    async def _on_auth(self, a: AuthEvent, ts: float, dev: int | None, feed: list) -> None:
        if self._ignored(a.src):
            return
        s = get_settings()
        cat = "auth_ok" if a.ok else "auth_fail"
        self.stats[cat] += 1
        self._bucket(cat, ts, a.src, service=a.service, user=a.user, device_id=dev, detail=a.detail)
        feed.append(self._feed_item(cat, ts, a.src, "", None, "", a.service, dev, user=a.user, detail=a.detail))
        w = self._window(a.src)
        w.last = ts
        window = s.sec_bruteforce_window_min * 60
        cutoff = time.time() - window
        while w.fails and w.fails[0][0] < cutoff:
            w.fails.popleft()
        if not a.ok:
            w.fails.append((ts, a.service, a.user))
            n = len(w.fails)
            if n >= s.sec_bruteforce_failures and not self._throttled(f"brute:{a.src}"):
                services = sorted({f[1] for f in w.fails})
                users = sorted({f[2] for f in w.fails if f[2]})[:8]
                geo = country(a.src)
                await alerts.raise_event(
                    dev, f"sec:brute:{a.src}",
                    f"Brute force on {', '.join(services)} from {a.src}" + (f" ({geo})" if geo else ""),
                    f"{n} failed logins in {s.sec_bruteforce_window_min} min" + (f" · users: {', '.join(users)}" if users else ""),
                    severity="critical" if n >= s.sec_bruteforce_failures * 5 else "warning",
                    ttl=window * 3, rule="sec_bruteforce")
        else:
            prior = [f for f in w.fails if f[1] == a.service] or list(w.fails)
            if len(prior) >= max(3, s.sec_bruteforce_failures // 2):
                await alerts.raise_event(
                    dev, f"sec:breach:{a.src}:{a.service}",
                    f"Login succeeded after {len(prior)} failures: {a.user or 'unknown user'} from {a.src}",
                    f"{a.service} login accepted from a source that was just brute forcing it. Verify this session "
                    f"and rotate the credentials if it was not you.",
                    severity="critical", ttl=86400, rule="sec_login_after_failures")

    async def _on_ids(self, i: IdsEvent, ts: float, dev: int | None, feed: list) -> None:
        if self._ignored(i.src):
            return
        self.stats["ids"] += 1
        self._bucket("ids", ts, i.src, i.dst, i.dport, i.proto, "", i.signature[:64], device_id=dev,
                     severity=i.priority, detail=f"[{i.sid}] {i.signature}")
        feed.append(self._feed_item("ids", ts, i.src, i.dst, i.dport, i.proto, i.signature, dev, severity=i.priority))
        # One alert per signature (sources rotate constantly for internet scanners); the count grows instead.
        if i.priority <= 2 and not self._throttled(f"ids:{i.sid}"):
            await alerts.raise_event(
                dev, f"sec:ids:{i.sid}", f"IDS: {i.signature[:120]}",
                f"latest: {i.src} → {i.dst}{f':{i.dport}' if i.dport else ''} ({i.proto})"
                + (f" · {i.classification}" if i.classification else ""),
                severity="critical" if i.priority == 1 else "warning", ttl=3600, rule="sec_ids")

    async def _check_scan(self, src: str, w: SourceWindow, dev: int | None) -> None:
        s = get_settings()
        cutoff = time.time() - s.sec_scan_window_min * 60
        while w.touches and w.touches[0][0] < cutoff:
            w.touches.popleft()
        if len(w.touches) < min(s.sec_scan_ports, s.sec_scan_hosts):
            return
        ports = {t[2] for t in w.touches if t[2] is not None}
        hosts = {t[1] for t in w.touches}
        if len(ports) < s.sec_scan_ports and len(hosts) < s.sec_scan_hosts:
            return
        got_through = any(t[3] for t in w.touches)
        if not (s.sec_scan_alert_blocked or got_through or is_internal(src)):
            return
        if self._throttled(f"scan:{src}"):
            return
        kind = "port scan" if len(ports) >= s.sec_scan_ports else "host sweep"
        geo = country(src)
        await alerts.raise_event(
            dev, f"sec:scan:{src}", f"{kind.capitalize()} from {src}" + (f" ({geo})" if geo else "")
            + (" — internal host!" if is_internal(src) else ""),
            f"{len(ports)} ports / {len(hosts)} hosts in {s.sec_scan_window_min} min"
            + (" · some traffic was allowed through" if got_through else " · all blocked"),
            severity="critical" if is_internal(src) and got_through else "warning", ttl=900, rule="sec_portscan")

    def _feed_item(self, cat: str, ts: float, src: str, dst: str, dport: int | None, proto: str, service: str,
                   dev: int | None, user: str = "", detail: str = "", severity: int = 0) -> dict[str, Any]:
        return {"ts": ts, "category": cat, "src": src, "dst": dst, "dport": dport, "proto": proto, "service": service,
                "user": user, "detail": detail, "severity": severity, "device_id": dev, "country": country(src),
                "internal": is_internal(src)}

    # ---------------------------------------------------------- housekeeping
    async def run(self) -> None:
        """Flush aggregates every 15 s and evaluate WAN spikes every minute."""
        tick = 0
        while True:
            await asyncio.sleep(15)
            tick += 1
            with contextlib.suppress(Exception):
                await self.flush()
            if tick % 4 == 0:
                with contextlib.suppress(Exception):
                    await self._wan_spike_tick()
                self._prune()

    async def flush(self) -> None:
        if not self._agg:
            return
        agg, self._agg = self._agg, {}
        rows = [{"ts": k[0], "category": k[1], "src_ip": k[2][:64], "dst_ip": (k[3] or "")[:64], "dst_port": k[4],
                 "proto": k[5][:12], "iface": k[6][:32], "service": k[7][:64], "username": k[8], "device_id": k[9],
                 "severity": k[10], "count": v[0], "detail": v[1]} for k, v in agg.items()]
        # One small, retried transaction per chunk: a long backlog never becomes one huge Galera write set.
        for i in range(0, len(rows), FLUSH_BATCH):
            async def _write(db, chunk=rows[i : i + FLUSH_BATCH]) -> None:
                await db.execute(insert(SecurityEvent), chunk)
                await db.commit()

            await with_retry(_write)

    async def _wan_spike_tick(self) -> None:
        s = get_settings()
        count, self._wan_blocks = self._wan_blocks, 0
        self._minutes += 1
        if self._baseline is None:
            self._baseline = float(count)
            return
        limit = max(s.sec_wan_spike_min, self._baseline * s.sec_wan_spike_factor)
        if self._minutes > 5 and count > limit:
            await alerts.raise_event(
                None, "sec:wanspike", "Spike in blocked WAN traffic",
                f"{count} blocked connections in the last minute (baseline ≈ {self._baseline:.0f}/min)",
                severity="warning", ttl=600, rule="sec_wan_spike")
        else:  # only learn from normal minutes so an attack doesn't become the new normal
            self._baseline = self._baseline * 0.9 + count * 0.1

    def _prune(self, force: bool = False) -> None:
        horizon = max(get_settings().sec_bruteforce_window_min, get_settings().sec_scan_window_min) * 60
        cutoff = time.time() - horizon
        stale = [ip for ip, w in self.sources.items() if w.last < cutoff]
        for ip in stale:
            self.sources.pop(ip, None)
        if force and len(self.sources) >= MAX_TRACKED_SOURCES:
            for ip in sorted(self.sources, key=lambda k: self.sources[k].last)[: MAX_TRACKED_SOURCES // 10]:
                self.sources.pop(ip, None)
        old = time.time() - 3600
        self._last_alert = {k: v for k, v in self._last_alert.items() if v > old}

    def tracked(self) -> dict[str, Any]:
        return {"sources": len(self.sources), "pending": len(self._agg), **self.stats}


security = SecurityEngine()
