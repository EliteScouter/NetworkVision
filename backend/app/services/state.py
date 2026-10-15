"""In-memory live state: the latest normalized view of every device.

Raw counters from collectors are turned into rates here (with 32/64-bit wrap
handling), and short rolling histories are kept for instant sparklines without
hitting the database.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any

from ..collectors.base import Gateway, Interface, Neighbor, Section, Snapshot

HISTORY_POINTS = 120  # ~30 min at a 15 s poll interval


@dataclass
class IfState:
    name: str
    alias: str = ""
    index: int | None = None
    oper_up: bool | None = None
    admin_up: bool | None = None
    speed_mbps: float | None = None
    media: str = ""
    mac: str = ""
    vlan: str = ""
    is_uplink: bool = False
    poe_w: float | None = None
    rx_bps: float | None = None
    tx_bps: float | None = None
    util_pct: float | None = None
    errors_per_min: float = 0.0
    rx_pps: float | None = None
    tx_pps: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    ever_up: bool = False
    changes: deque = field(default_factory=lambda: deque(maxlen=50))  # timestamps of up/down transitions
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_POINTS))  # (ts, rx, tx)

    def flaps(self, window: float = 600) -> int:
        cutoff = time.time() - window
        return sum(1 for t in self.changes if t >= cutoff)

    def public(self, with_history: bool = False) -> dict[str, Any]:
        d = {k: v for k, v in asdict(self).items() if k not in ("changes", "history")}
        d["flaps_10m"] = self.flaps()
        if with_history:
            d["history"] = [list(p) for p in self.history]
        return d


@dataclass
class DeviceState:
    id: int
    name: str
    kind: str
    role: str
    host: str
    parent_id: int | None = None
    enabled: bool = True
    status: str = "unknown"  # up | down | degraded | unknown | disabled
    error: str | None = None
    health: str = "ok"  # ok | info | warning | critical  (from active alerts)
    last_poll: float | None = None
    last_ok: float | None = None
    poll_ms: float | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    interfaces: dict[str, IfState] = field(default_factory=dict)
    neighbors: list[Neighbor] = field(default_factory=list)
    gateways: list[Gateway] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    location: str = ""
    rx_bps: float = 0.0
    tx_bps: float = 0.0
    alert_counts: dict[str, int] = field(default_factory=dict)
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_POINTS))
    _counters: dict[str, tuple[float, Interface]] = field(default_factory=dict)

    # -- serialization --------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        ifs = self.interfaces.values()
        return {
            "id": self.id, "name": self.name, "kind": self.kind, "role": self.role, "host": self.host,
            "parent_id": self.parent_id, "enabled": self.enabled, "status": self.status, "health": self.health,
            "error": self.error, "last_poll": self.last_poll, "last_ok": self.last_ok, "poll_ms": self.poll_ms,
            "metrics": self.metrics, "rx_bps": self.rx_bps, "tx_bps": self.tx_bps,
            "vendor": self.facts.get("vendor", ""), "model": self.facts.get("model", ""),
            "version": self.facts.get("version", ""), "tags": self.tags, "location": self.location,
            "ports_up": sum(1 for i in ifs if i.oper_up), "ports_total": len(self.interfaces),
            "alert_counts": self.alert_counts,
            "spark": [[round(t), r, x] for t, r, x, *_ in list(self.history)[-40:]],
        }

    def detail(self) -> dict[str, Any]:
        d = self.summary()
        d.update({
            "facts": self.facts,
            "interfaces": [i.public(with_history=True) for i in self.interfaces.values()],
            "neighbors": [asdict(n) for n in self.neighbors],
            "gateways": [asdict(g) for g in self.gateways],
            "sections": [asdict(s) for s in self.sections],
            "history": [list(p) for p in self.history],
        })
        return d

    # -- update from a snapshot ----------------------------------------------
    def apply(self, snap: Snapshot, now: float | None = None) -> None:
        now = now or time.time()
        self.last_poll = now
        self.error = snap.error
        if snap.reachable:
            self.last_ok = now
        self.status = "up" if snap.reachable and not snap.error else ("degraded" if snap.reachable else "down")
        if snap.facts:
            self.facts = {**self.facts, **{k: v for k, v in snap.facts.items() if v not in (None, "")}}
        self.metrics = {k: v for k, v in snap.metrics.items() if v is not None}
        self.neighbors, self.gateways, self.sections = snap.neighbors, snap.gateways, snap.sections

        seen: set[str] = set()
        total_rx = total_tx = 0.0
        for iface in snap.interfaces:
            seen.add(iface.name)
            st = self.interfaces.get(iface.name) or IfState(name=iface.name)
            self.interfaces[iface.name] = st
            self._update_iface(st, iface, now)
            if st.media not in ("virtual", "tunnel", "lag", "loopback"):
                total_rx += st.rx_bps or 0.0
                total_tx += st.tx_bps or 0.0
        for gone in set(self.interfaces) - seen:
            if snap.reachable:
                self.interfaces.pop(gone, None)
                self._counters.pop(gone, None)
        self.rx_bps, self.tx_bps = total_rx, total_tx
        if snap.reachable:
            self.metrics["rx_bps"], self.metrics["tx_bps"] = total_rx, total_tx
        self.history.append((now, total_rx, total_tx, self.metrics.get("cpu"), self.metrics.get("mem"),
                             self.metrics.get("latency_ms")))

    def mark_down(self, error: str, now: float | None = None) -> None:
        now = now or time.time()
        self.last_poll, self.status, self.error = now, "down", error
        for st in self.interfaces.values():
            st.rx_bps = st.tx_bps = st.util_pct = None
        self.rx_bps = self.tx_bps = 0.0
        self.history.append((now, 0.0, 0.0, None, None, None))

    def _update_iface(self, st: IfState, i: Interface, now: float) -> None:
        if st.oper_up is not None and i.oper_up is not None and st.oper_up != i.oper_up:
            st.changes.append(now)
        st.alias, st.index, st.admin_up = i.alias, i.index, i.admin_up
        st.oper_up, st.speed_mbps, st.media, st.mac = i.oper_up, i.speed_mbps, i.media, i.mac
        st.vlan, st.is_uplink, st.poe_w, st.extra = i.vlan, i.is_uplink, i.poe_w, i.extra
        st.ever_up = st.ever_up or bool(i.oper_up)

        prev = self._counters.get(i.name)
        self._counters[i.name] = (now, i)
        if i.rx_bps is not None or i.tx_bps is not None:
            st.rx_bps, st.tx_bps = i.rx_bps, i.tx_bps
        elif prev:
            t0, p = prev
            dt = now - t0
            if dt > 0.5:
                bits = 64 if i.extra.get("counter_bits", 64) == 64 else 32
                st.rx_bps = _rate(p.in_octets, i.in_octets, dt, bits, 8)
                st.tx_bps = _rate(p.out_octets, i.out_octets, dt, bits, 8)
                errs_prev = (p.in_errors or 0) + (p.out_errors or 0)
                errs_now = (i.in_errors or 0) + (i.out_errors or 0)
                st.errors_per_min = max(0.0, (errs_now - errs_prev) / dt * 60) if errs_now >= errs_prev else 0.0
                if "rx_pkts" in i.extra:
                    st.rx_pps = _rate(p.extra.get("rx_pkts"), i.extra.get("rx_pkts"), dt, 32, 1)
                    st.tx_pps = _rate(p.extra.get("tx_pkts"), i.extra.get("tx_pkts"), dt, 32, 1)
        if i.oper_up is False:
            st.rx_bps = st.tx_bps = 0.0
        speed_bps = (st.speed_mbps or 0) * 1e6
        if speed_bps and st.rx_bps is not None and st.tx_bps is not None:
            st.util_pct = min(100.0, max(st.rx_bps, st.tx_bps) / speed_bps * 100)
        else:
            st.util_pct = None
        st.history.append((round(now), st.rx_bps, st.tx_bps))


def _rate(old: int | None, new: int | None, dt: float, bits: int, mult: int) -> float | None:
    if old is None or new is None:
        return None
    delta = new - old
    if delta < 0:
        if bits == 32 and old > 2**31:
            delta += 2**32
        else:
            return None  # counter reset (reboot) - skip one sample
    return delta * mult / dt


class StateStore:
    def __init__(self) -> None:
        self.devices: dict[int, DeviceState] = {}

    def get(self, device_id: int) -> DeviceState | None:
        return self.devices.get(device_id)

    def ensure(self, device) -> DeviceState:
        st = self.devices.get(device.id)
        if st is None:
            st = DeviceState(id=device.id, name=device.name, kind=device.kind, role=device.role, host=device.host,
                             parent_id=device.parent_id)
            st.facts = dict(device.facts or {})
            self.devices[device.id] = st
        st.name, st.kind, st.role, st.host = device.name, device.kind, device.role, device.host
        st.parent_id, st.enabled = device.parent_id, device.enabled
        st.tags, st.location = list(device.tags or []), device.location or ""
        if not device.enabled:
            st.status = "disabled"
        return st

    def remove(self, device_id: int) -> None:
        self.devices.pop(device_id, None)
        for d in list(self.devices.values()):
            if d.parent_id == device_id:
                self.devices.pop(d.id, None)


store = StateStore()
