"""Topology graph builder.

Links come from (strongest first):
  1. manual links (Settings > Topology),
  2. LLDP neighbors and controller-reported uplinks,
  3. port descriptions that name another device (e.g. port alias "Proxmox-01"),
  4. firewall/router WAN interfaces -> a virtual "Internet" node.
"""

from __future__ import annotations

import re
from typing import Any

from ..collectors.base import norm_mac
from ..models import Link
from .state import DeviceState, IfState, store

INTERNET_ID = "internet"
_norm = re.compile(r"[^a-z0-9]")


def _key(s: str) -> str:
    return _norm.sub("", (s or "").lower())


def _find_port(dev: DeviceState, port: str) -> IfState | None:
    if not port:
        return None
    if port in dev.interfaces:
        return dev.interfaces[port]
    k = _key(port)
    for i in dev.interfaces.values():
        if k in (_key(i.name), _key(i.alias), _key(f"port{i.index}") if i.index is not None else None):
            return i
    if port.isdigit():
        for i in dev.interfaces.values():
            if i.index == int(port) or _key(i.name) in (port, f"port{port}"):
                return i
    return None


def build(manual_links: list[Link], positions: dict[int, tuple[float | None, float | None]]) -> dict[str, Any]:
    devices = [d for d in store.devices.values() if d.enabled]
    by_mac: dict[str, int] = {}
    by_name: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for d in devices:
        if d.facts.get("mac"):
            by_mac[norm_mac(d.facts["mac"])] = d.id
        for i in d.interfaces.values():
            if i.mac:
                by_mac.setdefault(norm_mac(i.mac), d.id)
        for n in (d.name, d.facts.get("hostname", "")):
            if n:
                by_name[_key(n)] = d.id
        if d.host:
            by_ip[d.host] = d.id

    edges: dict[tuple, dict[str, Any]] = {}

    def add(a: int | str, a_port: str, b: int | str, b_port: str, kind: str, label: str = "", link_id: int | None = None) -> None:
        if a == b:
            return
        key = tuple(sorted([str(a), str(b)]))
        existing = edges.get(key)
        rank = {"manual": 4, "lldp": 3, "uplink": 3, "description": 2, "wan": 1}
        if existing and rank.get(existing["kind"], 0) > rank.get(kind, 0):
            # keep stronger source but fill in missing ports
            if str(a) == existing["source"]:
                existing["source_port"] = existing["source_port"] or a_port
                existing["target_port"] = existing["target_port"] or b_port
            else:
                existing["target_port"] = existing["target_port"] or a_port
                existing["source_port"] = existing["source_port"] or b_port
            return
        edges[key] = {"id": "-".join(key), "source": str(a), "target": str(b), "source_port": a_port,
                      "target_port": b_port, "kind": kind, "label": label, "link_id": link_id}

    def resolve(n) -> int | None:
        return (by_mac.get(norm_mac(n.remote_mac)) if n.remote_mac else None) \
            or (by_name.get(_key(n.remote_name)) if n.remote_name else None) \
            or (by_ip.get(n.remote_ip) if n.remote_ip else None)

    for d in devices:
        for n in d.neighbors:
            other = resolve(n)
            if other is not None:
                add(d.id, n.local_port, other, n.remote_port, n.protocol if n.protocol in ("lldp", "uplink") else "lldp")
        for i in d.interfaces.values():
            if i.alias and len(_key(i.alias)) >= 3:
                ak = _key(i.alias)
                target = by_name.get(ak) or next((v for k, v in by_name.items() if len(k) >= 4 and ak.startswith(k)), None)
                if target is not None and target != d.id:
                    add(d.id, i.name, target, "", "description")

    for link in manual_links:
        add(link.a_device_id, link.a_port, link.b_device_id, link.b_port, "manual", link.label, link.id)

    has_internet = False
    for d in devices:
        if d.role in ("firewall", "router") and d.parent_id is None and d.gateways:
            wan = next((i for i in d.interfaces.values() if "wan" in i.name.lower() or "wan" in i.alias.lower()), None)
            if wan is None:
                wan = next((i for i in d.interfaces.values() if i.is_uplink), None)
            # Lab firewalls behind another firewall are not internet edges.
            behind = any(e for e in edges.values() if str(d.id) in (e["source"], e["target"]) and e["kind"] != "wan"
                         and _is_edge_fw(e, d.id))
            if not behind:
                has_internet = True
                add(d.id, wan.name if wan else "", INTERNET_ID, "", "wan")

    # Attach live traffic to every edge from the best side we can measure.
    by_id = {str(d.id): d for d in devices}
    for e in edges.values():
        a, b = by_id.get(e["source"]), by_id.get(e["target"])
        port = (_find_port(a, e["source_port"]) if a else None) or (_find_port(b, e["target_port"]) if b else None)
        up = None
        if port:
            e.update(speed_mbps=port.speed_mbps, rx_bps=port.rx_bps, tx_bps=port.tx_bps, util_pct=port.util_pct,
                     errors_per_min=port.errors_per_min)
            up = port.oper_up
        statuses = [x.status for x in (a, b) if x]
        e["status"] = "down" if up is False or "down" in statuses else "up"

    nodes = []
    for d in devices:
        px, py = positions.get(d.id, (None, None))
        nodes.append({**{k: v for k, v in d.summary().items() if k != "spark"}, "id": str(d.id), "device_id": d.id,
                      "x": px, "y": py, "clients": d.metrics.get("clients")})
    if has_internet:
        gws = [g for d in devices if d.role in ("firewall", "router") for g in d.gateways]
        lat = [g.latency_ms for g in gws if g.latency_ms is not None]
        nodes.append({"id": INTERNET_ID, "device_id": None, "name": "Internet", "role": "internet", "status":
                      "up" if any(g.up is not False for g in gws) else "down", "health": "ok",
                      "metrics": {"latency_ms": min(lat) if lat else None}, "x": None, "y": None})
    return {"nodes": nodes, "edges": list(edges.values())}


def _is_edge_fw(edge: dict[str, Any], dev_id: int) -> bool:
    """True if this firewall's WAN port is cabled to another known device (i.e. it is an inner/lab firewall)."""
    port = edge["source_port"] if edge["source"] == str(dev_id) else edge["target_port"]
    return "wan" in (port or "").lower()
