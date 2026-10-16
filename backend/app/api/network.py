"""Clients inventory and WiFi dashboard endpoints."""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..collectors.base import norm_mac
from ..security import require_user
from ..services.clients import tracker
from ..services.state import store

router = APIRouter(prefix="/api", tags=["network"], dependencies=[Depends(require_user)])

# Signal buckets (dBm) used by most WiFi tools.
SIGNAL_BUCKETS = [("excellent", -60), ("good", -67), ("fair", -75), ("poor", -200)]


def _signal_bucket(sig: float | None) -> str | None:
    if sig is None:
        return None
    return next(name for name, floor in SIGNAL_BUCKETS if sig >= floor)


@router.get("/clients")
async def list_clients() -> dict[str, Any]:
    clients = tracker.merged()
    online = [c for c in clients if c["online"]]
    wireless = [c for c in online if not c.get("wired")]
    return {
        "clients": clients,
        "counts": {
            "total": len(clients), "online": len(online), "offline": len(clients) - len(online),
            "wired": sum(1 for c in online if c.get("wired")), "wireless": len(wireless),
            "by_band": dict(Counter(c.get("band") or "?" for c in wireless)),
            "by_network": dict(Counter(c.get("network") or "unknown" for c in online)),
            "by_category": dict(Counter(c.get("category") for c in online)),
        },
    }


@router.get("/clients/{mac}")
async def get_client(mac: str) -> dict[str, Any]:
    c = tracker.get(mac)
    if c is None:
        raise HTTPException(404, "Client not found")
    return c


@router.get("/wifi")
async def wifi() -> dict[str, Any]:
    ap_ids = {norm_mac(d.facts.get("mac", "")): d.id for d in store.devices.values() if d.facts.get("mac")}
    aps, ssids, neighbors = [], [], []
    controllers = []
    for dev in store.devices.values():
        w = dev.wifi or {}
        if not w or not dev.enabled:
            continue
        controllers.append({"id": dev.id, "name": dev.name, "updated": w.get("updated")})
        for ap in w.get("aps", []):
            aps.append({**ap, "device_id": ap_ids.get(ap["mac"]), "controller": dev.name})
        ssids += [{**s, "controller": dev.name} for s in w.get("ssids", [])]
        neighbors += w.get("neighbors", [])

    own_bssids = {v.get("bssid") for ap in aps for v in ap.get("vaps", [])}
    neighbors = [n for n in neighbors if n.get("bssid") not in own_bssids]
    wireless = [c for c in tracker.merged() if c["online"] and not c.get("wired")]
    radios = [r for ap in aps if ap.get("online") for r in ap.get("radios", [])]
    sats = [c["satisfaction"] for c in wireless if c.get("satisfaction") is not None]
    sigs = [c["signal"] for c in wireless if c.get("signal") is not None]

    channel_load: dict[str, dict[str, int]] = {}
    for n in neighbors:
        if n.get("band") and n.get("channel") is not None:
            band = channel_load.setdefault(n["band"], {})
            band[str(n["channel"])] = band.get(str(n["channel"]), 0) + 1

    return {
        "controllers": controllers,
        "aps": aps,
        "ssids": ssids,
        "neighbors": neighbors,
        "summary": {
            "aps_total": len(aps), "aps_online": sum(1 for a in aps if a.get("online")),
            "clients": len(wireless), "ssids": len([s for s in ssids if s.get("enabled")]),
            "satisfaction": sum(sats) / len(sats) if sats else None,
            "avg_signal": sum(sigs) / len(sigs) if sigs else None,
            "busiest_radio": max(radios, key=lambda r: r.get("utilization") or 0, default=None),
            "neighbors": len(neighbors),
            "by_band": dict(Counter(c.get("band") or "?" for c in wireless)),
            "by_standard": dict(Counter(c.get("standard") or "unknown" for c in wireless)),
            "by_signal": {name: sum(1 for s in sigs if _signal_bucket(s) == name) for name, _ in SIGNAL_BUCKETS},
            "channel_load": channel_load,
        },
        "clients": [{k: c.get(k) for k in ("mac", "display_name", "category", "ssid", "band", "channel", "signal", "snr",
                                           "standard", "satisfaction", "retries_pct", "tx_rate_mbps", "rx_rate_mbps",
                                           "uplink_mac", "uplink_name", "down_bps", "up_bps")} for c in wireless],
    }
