"""Alert engine.

After every poll the device's live state is evaluated against built-in rules.
Threshold rules must hold for NV_ALERT_CONSECUTIVE polls before opening (no
flapping alerts), and every alert auto-resolves once its condition clears.

Thresholds come from services.runtime (UI settings over env), optionally overridden
per device. Disabled rules, muted devices and muted interfaces produce no
conditions at all; during a maintenance window conditions still open alerts, but
flagged ``suppressed``: recorded, never notified, not counted in device health.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from ..db import sessionmaker, with_retry
from ..models import Alert
from . import notifier
from .bus import bus
from .runtime import runtime
from .state import DeviceState, store

log = logging.getLogger("networkvision.alerts")


@dataclass
class Condition:
    key: str
    rule: str
    severity: str
    title: str
    detail: str = ""
    debounce: bool = True  # require N consecutive hits
    device_id: int | None = None  # only used by sync_group()
    subject: str = ""  # interface name, for per-interface muting
    suppressed: bool = False  # inside a maintenance window


# Alerts whose keys start with these are owned by the log/security/DHCP engines, never by
# the per-device evaluate() pass - process() must not resolve them.
EXTERNAL_PREFIXES = ("log:", "sec:", "dhcp:")
# ... and of those, these are stateless events that expire on their own.
EVENT_PREFIXES = ("log:", "sec:", "dhcp:new:", "dhcp:rogue:", "dhcp:nak:")
EVENT_TTL_ON_LOAD = 1800


def alert_dict(a: Alert) -> dict[str, Any]:
    d = store.get(a.device_id) if a.device_id else None
    return {
        "id": a.id, "key": a.key, "device_id": a.device_id, "device_name": d.name if d else None,
        "rule": a.rule, "severity": a.severity, "title": a.title, "detail": a.detail,
        "started_at": a.started_at, "last_seen_at": a.last_seen_at, "resolved_at": a.resolved_at,
        "acknowledged_at": a.acknowledged_at, "acknowledged_by": a.acknowledged_by, "count": a.count,
        "suppressed": bool(a.suppressed),
    }


def evaluate(dev: DeviceState, now: float | None = None) -> list[Condition]:
    if not dev.enabled or runtime.device_muted(dev.id):
        return []
    out = [c for c in _conditions(dev) if runtime.rule_enabled(c.rule, dev.id)
           and not (c.subject and runtime.interface_muted(dev.id, c.subject))]
    if out and runtime.in_maintenance(dev.id, dev.parent_id, now):
        for c in out:
            c.suppressed = True
    return out


def _conditions(dev: DeviceState) -> list[Condition]:
    def th(name: str) -> float:
        return runtime.threshold(name, dev.id)

    out: list[Condition] = []
    p = f"{dev.id}"
    if dev.status == "down":
        via = "reported offline by its controller" if dev.parent_id else "unreachable"
        out.append(Condition(f"down:{p}", "device_down", "critical", f"{dev.name} is {via}", dev.error or ""))
        return out  # everything else is noise while down
    if dev.status == "degraded" and dev.error:
        out.append(Condition(f"poll:{p}", "poll_error", "warning", f"{dev.name}: integration error", dev.error))

    m = dev.metrics
    if (cpu := m.get("cpu")) is not None and cpu >= th("alert_cpu_pct"):
        out.append(Condition(f"cpu:{p}", "high_cpu", "warning", f"High CPU on {dev.name}", f"CPU at {cpu:.0f}%"))
    if (mem := m.get("mem")) is not None and mem >= th("alert_mem_pct"):
        out.append(Condition(f"mem:{p}", "high_mem", "warning", f"High memory on {dev.name}", f"Memory at {mem:.0f}%"))
    if (temp := m.get("temp")) is not None and temp >= th("alert_temp_c"):
        out.append(Condition(f"temp:{p}", "high_temp", "critical" if temp >= th("alert_temp_c") + 10 else "warning",
                             f"{dev.name} running hot", f"Temperature {temp:.0f} °C"))
    if (lat := m.get("latency_ms")) is not None and lat >= th("alert_latency_ms"):
        out.append(Condition(f"lat:{p}", "high_latency", "warning", f"High latency to {dev.name}", f"{lat:.0f} ms"))
    if (loss := m.get("loss_pct")) is not None and loss >= th("alert_loss_pct") and dev.status != "down":
        out.append(Condition(f"loss:{p}", "packet_loss", "warning", f"Packet loss to {dev.name}", f"{loss:.0f}% loss"))

    for gw in dev.gateways:
        gk = f"{p}:{gw.name}"
        if gw.up is False:
            out.append(Condition(f"gwdown:{gk}", "gateway_down", "critical", f"Gateway {gw.name} down on {dev.name}",
                                 gw.detail or gw.address))
        else:
            if gw.loss_pct is not None and gw.loss_pct >= th("alert_loss_pct"):
                out.append(Condition(f"gwloss:{gk}", "gateway_loss", "warning", f"Gateway {gw.name} packet loss",
                                     f"{gw.loss_pct:.0f}% loss on {dev.name}"))
            if gw.latency_ms is not None and gw.latency_ms >= th("alert_latency_ms"):
                out.append(Condition(f"gwlat:{gk}", "gateway_latency", "warning", f"Gateway {gw.name} high latency",
                                     f"{gw.latency_ms:.0f} ms on {dev.name}"))

    for i in dev.interfaces.values():
        ik = f"{p}:{i.name}"
        label = f"{i.name}" + (f" ({i.alias})" if i.alias else "")
        if i.flaps() >= 4:
            out.append(Condition(f"flap:{ik}", "port_flapping", "warning", f"Port flapping: {label} on {dev.name}",
                                 f"{i.flaps()} link changes in 10 min", debounce=False, subject=i.name))
        elif i.ever_up and i.oper_up is False and i.admin_up is not False:
            out.append(Condition(f"ifdown:{ik}", "port_down", "warning", f"Link down: {label} on {dev.name}",
                                 "Interface was up and went down", subject=i.name))
        if i.errors_per_min >= th("alert_if_errors_per_min"):
            out.append(Condition(f"iferr:{ik}", "port_errors", "warning", f"Errors on {label} ({dev.name})",
                                 f"{i.errors_per_min:.0f} errors/min - check cabling/SFP", subject=i.name))
        if i.util_pct is not None and i.util_pct >= th("alert_if_util_pct"):
            out.append(Condition(f"ifutil:{ik}", "port_saturated", "warning", f"{label} saturated on {dev.name}",
                                 f"{i.util_pct:.0f}% of {i.speed_mbps:.0f} Mbps", subject=i.name))

    if dev.facts.get("upgradable") or dev.facts.get("updates_available"):
        to = dev.facts.get("upgrade_to") or ""
        out.append(Condition(f"fw:{p}", "firmware_update", "info", f"Firmware update available for {dev.name}",
                             f"Upgrade to {to}" if to else "", debounce=False))
    return out


class AlertEngine:
    def __init__(self) -> None:
        self.open: dict[str, Alert] = {}
        self._hits: dict[str, int] = {}
        self._event_expiry: dict[str, float] = {}
        self._evals: dict[int, int] = {}

    async def load(self) -> None:
        async with sessionmaker()() as db:
            rows = (await db.execute(select(Alert).where(Alert.resolved_at.is_(None)))).scalars().all()
        self.open = {a.key: a for a in rows}
        # Events restored after a restart still need to expire eventually.
        for a in rows:
            if a.key.startswith(EVENT_PREFIXES):
                self._event_expiry[a.key] = a.last_seen_at + EVENT_TTL_ON_LOAD
        self._recount()

    def _recount(self) -> None:
        for d in store.devices.values():
            d.alert_counts, d.health = {}, "ok"
        rank = {"ok": 0, "info": 1, "warning": 2, "critical": 3}
        for a in self.open.values():
            if a.suppressed:
                continue
            d = store.get(a.device_id) if a.device_id else None
            if d:
                d.alert_counts[a.severity] = d.alert_counts.get(a.severity, 0) + 1
                if rank[a.severity] > rank[d.health]:
                    d.health = a.severity

    async def process(self, dev: DeviceState) -> None:
        conds = {c.key: c for c in evaluate(dev)}
        need = int(runtime.get("alert_consecutive"))
        # Rates need two samples: don't resolve alerts restored from the DB until the device is warmed up.
        self._evals[dev.id] = self._evals.get(dev.id, 0) + 1
        warm = self._evals[dev.id] > 2
        prefix_keys = {k for k, a in self.open.items()
                       if a.device_id == dev.id and not k.startswith(EXTERNAL_PREFIXES) and k not in self._event_expiry} if warm else set()
        now = time.time()
        opened: list[Alert] = []
        resolved: list[Alert] = []

        for key in list(self._hits):
            if key.split(":")[1] == str(dev.id) and key not in conds:
                self._hits.pop(key, None)

        async with sessionmaker()() as db:
            for key, c in conds.items():
                self._hits[key] = self._hits.get(key, 0) + 1
                existing = self.open.get(key)
                if existing:
                    existing.last_seen_at, existing.detail = now, c.detail
                    if existing.severity != c.severity:
                        existing.severity = c.severity
                    if existing.suppressed and not c.suppressed:
                        # Maintenance is over and the problem is still there: now it is real.
                        existing.suppressed = False
                        opened.append(existing)
                    await db.merge(existing)
                elif not c.debounce or self._hits[key] >= need:
                    a = Alert(key=key, device_id=dev.id, rule=c.rule, severity=c.severity, title=c.title,
                              detail=c.detail, started_at=now, last_seen_at=now, suppressed=c.suppressed)
                    db.add(a)
                    opened.append(a)
            for key in prefix_keys - set(conds):
                a = self.open.pop(key)
                a.resolved_at = now
                await db.merge(a)
                resolved.append(a)
            await db.commit()
        for a in opened:
            self.open[a.key] = a
        if opened or resolved:
            self._recount()
            self._announce(opened, resolved)

    async def raise_event(self, device_id: int | None, key: str, title: str, detail: str,
                          severity: str = "critical", ttl: float = 1800, rule: str = "log_event") -> None:
        """Stateless alerts (e.g. from a critical syslog line) that auto-expire after `ttl` seconds."""
        if not runtime.rule_enabled(rule, device_id) or runtime.device_muted(device_id):
            return
        now = time.time()
        dev = store.get(device_id) if device_id else None
        suppressed = runtime.in_maintenance(device_id, dev.parent_id if dev else None, now) is not None
        self._event_expiry[key] = now + ttl
        async with sessionmaker()() as db:
            if key in self.open:
                a = self.open[key]
                a.count += 1
                a.last_seen_at, a.detail = now, detail
                escalated = RANK[severity] > RANK.get(a.severity, 0)
                if escalated:
                    a.severity, a.title = severity, title
                await db.merge(a)
                await db.commit()
                if escalated:
                    self._recount()
                    bus.publish({"type": "alert", "event": "updated", "alert": alert_dict(a)})
                return
            a = Alert(key=key, device_id=device_id, rule=rule, severity=severity, title=title, detail=detail,
                      started_at=now, last_seen_at=now, suppressed=suppressed)
            db.add(a)
            await db.commit()
        self.open[key] = a
        self._recount()
        self._announce([a], [])

    async def sync_group(self, prefixes: tuple[str, ...], conds: list[Condition]) -> None:
        """Make the open alerts under `prefixes` match `conds` exactly (open new, resolve gone).

        Used by engines that evaluate a whole population at once (e.g. DHCP conflicts).
        """
        now = time.time()
        want = {c.key: c for c in conds}
        opened: list[Alert] = []
        resolved: list[Alert] = []
        changed = False
        async with sessionmaker()() as db:
            for key, c in want.items():
                a = self.open.get(key)
                if a is None:
                    a = Alert(key=key, device_id=c.device_id, rule=c.rule, severity=c.severity, title=c.title,
                              detail=c.detail, started_at=now, last_seen_at=now)
                    db.add(a)
                    opened.append(a)
                elif a.detail != c.detail or a.severity != c.severity or now - a.last_seen_at > 300:
                    a.detail, a.severity, a.title, a.last_seen_at = c.detail, c.severity, c.title, now
                    await db.merge(a)
                    changed = True
            for key, a in list(self.open.items()):
                if key.startswith(prefixes) and key not in want and key not in self._event_expiry:
                    self.open.pop(key)
                    a.resolved_at = now
                    await db.merge(a)
                    resolved.append(a)
            if opened or resolved or changed:
                await db.commit()
        for a in opened:
            self.open[a.key] = a
        if opened or resolved:
            self._recount()
            self._announce(opened, resolved)

    async def sync_external(self, prefix: str, conds: list[Condition], refresh_s: float = 300) -> None:
        """Open/update/resolve the alerts a non-device monitor owns (keys starting with ``prefix``).

        The caller does its own debouncing; every condition passed in is treated as confirmed.
        ``last_seen_at`` is only re-written every ``refresh_s`` so a long outage isn't a write per check.
        """
        now = time.time()
        want = {c.key: c for c in conds if c.key.startswith(prefix)}
        changed: list[Alert] = []
        new: list[Condition] = []
        for key, c in want.items():
            a = self.open.get(key)
            if a is None:
                new.append(c)
            elif a.detail != c.detail or a.severity != c.severity or now - a.last_seen_at >= refresh_s:
                a.last_seen_at, a.detail, a.severity = now, c.detail, c.severity
                changed.append(a)
        gone = [a for k, a in self.open.items() if k.startswith(prefix) and k not in want]
        if not (new or changed or gone):
            return
        for a in gone:
            a.resolved_at = now

        async def _write(db) -> list[Alert]:
            for a in changed + gone:
                await db.merge(a)
            rows = [Alert(key=c.key, device_id=None, rule=c.rule, severity=c.severity, title=c.title, detail=c.detail,
                          started_at=now, last_seen_at=now) for c in new]
            db.add_all(rows)
            await db.commit()
            return rows

        opened = await with_retry(_write)
        for a in gone:
            self.open.pop(a.key, None)
        for a in opened:
            self.open[a.key] = a
        if opened or gone:
            self._recount()
            self._announce(opened, gone)

    async def expire_events(self) -> None:
        now = time.time()
        expired = [k for k, t in self._event_expiry.items() if t < now]
        if not expired:
            return
        done = []
        async with sessionmaker()() as db:
            for k in expired:
                self._event_expiry.pop(k, None)
                a = self.open.pop(k, None)
                if a:
                    a.resolved_at = now
                    await db.merge(a)
                    done.append(a)
            await db.commit()
        if done:
            self._recount()
            self._announce([], done)

    async def acknowledge(self, alert_id: int, user: str, ack: bool = True) -> Alert | None:
        """Ack through the engine so the in-memory copy (merged every poll) stays in sync."""
        now = time.time()
        async with sessionmaker()() as db:
            a = next((x for x in self.open.values() if x.id == alert_id), None) or await db.get(Alert, alert_id)
            if a is None:
                return None
            a.acknowledged_at, a.acknowledged_by = (now, user) if ack else (None, "")
            await db.merge(a)
            await db.commit()
        bus.publish({"type": "alert", "event": "updated", "alert": alert_dict(a)})
        return a

    async def resolve(self, alert_id: int) -> Alert | None:
        """Manual resolve. If the condition persists it will simply re-open later."""
        now = time.time()
        async with sessionmaker()() as db:
            a = next((x for x in self.open.values() if x.id == alert_id), None) or await db.get(Alert, alert_id)
            if a is None or a.resolved_at:
                return a
            a.resolved_at = now
            await db.merge(a)
            await db.commit()
        self.open.pop(a.key, None)
        self._hits.pop(a.key, None)
        self._event_expiry.pop(a.key, None)
        self._recount()
        self._announce([], [a])
        return a

    async def drop_device(self, device_id: int) -> None:
        for k in [k for k, a in self.open.items() if a.device_id == device_id]:
            self.open.pop(k, None)
        self._recount()

    @staticmethod
    def _quiet(a: Alert) -> bool:
        """Recorded but not pushed: maintenance, or tuning changed since the alert opened."""
        return bool(a.suppressed) or runtime.device_muted(a.device_id) or not runtime.rule_enabled(a.rule, a.device_id)

    def _announce(self, opened: list[Alert], resolved: list[Alert]) -> None:
        for a in opened:
            d = alert_dict(a)
            log.info("ALERT %s%s: %s", a.severity.upper(), " (suppressed: maintenance)" if a.suppressed else "", a.title)
            bus.publish({"type": "alert", "event": "opened", "alert": d})
            if not self._quiet(a):
                notifier.fire(d)
        for a in resolved:
            d = alert_dict(a)
            log.info("RESOLVED: %s", a.title)
            bus.publish({"type": "alert", "event": "resolved", "alert": d})
            if not self._quiet(a):
                notifier.fire(d, resolved=True)


RANK = {"info": 0, "warning": 1, "critical": 2}

engine = AlertEngine()
