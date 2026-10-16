"""Client inventory: everything that has talked to the network, merged by MAC.

Sources: UniFi (online + known-offline clients with full radio/port detail) and
pfSense/OPNsense DHCP leases. Each integration emits normalized client dicts on
its snapshot; this module merges them, classifies device types, resolves the AP
or switch a client hangs off, and keeps a short live throughput history.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from ..collectors.base import norm_mac
from .state import store

HISTORY_POINTS = 120
BAND = {"ng": "2.4", "na": "5", "6e": "6", "2g": "2.4", "5g": "5", "6g": "6"}

# (category, keywords) - first match wins; checked against name, hostname and vendor.
CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("network", ("unifi", "ubiquiti", "usw-", "uap", "u6-", "u7-", "netgate", "pfsense", "opnsense", "mikrotik", "switch", "router", "accesspoint")),
    ("server", ("proxmox", "pve", "truenas", "unraid", "synology", "diskstation", "nas", "server", "docker", "esxi", "portainer", "kube", "k8s")),
    ("camera", ("camera", "cam-", "ipcam", "doorbell", "ring-", "wyze", "reolink", "hikvision", "dahua", "arlo", "eufy", "g4-", "g5-")),
    ("console", ("xbox", "playstation", "ps4", "ps5", "nintendo", "steamdeck", "steam-deck")),
    ("tv", ("tv", "roku", "chromecast", "appletv", "apple-tv", "shield", "firetv", "fire-tv", "bravia", "webos", "vizio", "tcl", "googletv")),
    ("speaker", ("echo", "alexa", "sonos", "homepod", "google-home", "nest-mini", "nest-audio", "nest-hub")),
    ("printer", ("printer", "brother", "epson", "canon", "laserjet", "officejet", "deskjet")),
    ("iot", ("espressif", "esp-", "esp32", "esp8266", "tuya", "shelly", "sonoff", "tasmota", "smartplug", "plug", "ecobee",
             "hue", "philips lighting", "lifx", "kasa", "wemo", "roomba", "irobot", "myq", "nest", "wled", "zigbee", "tado", "meross")),
    ("tablet", ("ipad", "galaxy-tab", "kindle", "fire-hd", "tablet")),
    ("phone", ("iphone", "pixel", "galaxy", "android", "oneplus", "sm-", "xiaomi", "redmi", "motorola", "moto-", "huawei", "oppo")),
    ("watch", ("watch", "fitbit", "garmin")),
    ("computer", ("macbook", "imac", "mac-mini", "macmini", "laptop", "desktop", "-pc", "pc-", "windows", "thinkpad", "surface",
                  "mbp", "workstation", "dell", "lenovo", "asus", "msi", "framework", "linux", "ubuntu")),
]


def classify(*texts: str | None) -> str:
    hay = " ".join(t.lower() for t in texts if t)
    for cat, words in CATEGORIES:
        if any(w in hay for w in words):
            return cat
    return "unknown"


def wifi_standard(proto: str | None, band: str | None) -> str | None:
    p = (proto or "").lower()
    if p == "be":
        return "Wi-Fi 7"
    if p == "ax":
        return "Wi-Fi 6E" if band == "6" else "Wi-Fi 6"
    if p == "ac":
        return "Wi-Fi 5"
    if p in ("na", "ng", "n"):
        return "Wi-Fi 4"
    if p in ("a", "b", "g"):
        return "802.11" + p
    return None


def _num(v: Any) -> float | None:
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


def from_unifi(s: dict[str, Any], online: bool, network_names: dict[str, str]) -> dict[str, Any]:
    """Normalize a UniFi stat/sta (online) or rest/user (known) record."""
    wired = bool(s.get("is_wired"))
    radio = s.get("radio") or s.get("last_radio")
    band = BAND.get(str(radio or "").lower())
    signal, noise = _num(s.get("signal")), _num(s.get("noise"))
    # UniFi counters are from the AP/switch port's point of view: tx = sent *to* the client (its download).
    tx_r = s.get("wired-tx_bytes-r" if wired else "tx_bytes-r")
    rx_r = s.get("wired-rx_bytes-r" if wired else "rx_bytes-r")
    tx_b = s.get("wired-tx_bytes" if wired else "tx_bytes")
    rx_b = s.get("wired-rx_bytes" if wired else "rx_bytes")
    network = s.get("network") or s.get("last_connection_network_name") or network_names.get(s.get("network_id", ""), "")
    rec = {
        "mac": norm_mac(s.get("mac")),
        "name": s.get("name") or "",
        "hostname": s.get("hostname") or "",
        "ip": s.get("ip") or s.get("last_ip") or "",
        "ipv6": s.get("ipv6_addresses") or ([s["last_ipv6"]] if isinstance(s.get("last_ipv6"), str) and s.get("last_ipv6") else []),
        "vendor": s.get("oui") or "",
        "network": network or "",
        "vlan": s.get("vlan"),
        "is_guest": bool(s.get("is_guest")),
        "fixed_ip": bool(s.get("use_fixedip")),
        "noted": bool(s.get("noted")),
        "online": online,
        "wired": wired,
        "uplink_mac": norm_mac(s.get("sw_mac") if wired else s.get("ap_mac")) or norm_mac(s.get("last_uplink_mac")),
        "uplink_name": s.get("last_uplink_name") or "",
        "sw_port": s.get("sw_port") or (s.get("last_uplink_remote_port") if wired else None),
        "wired_rate_mbps": _num(s.get("wired_rate_mbps")),
        "ssid": s.get("essid") or "",
        "bssid": norm_mac(s.get("bssid")),
        "band": band,
        "radio_proto": s.get("radio_proto"),
        "standard": wifi_standard(s.get("radio_proto"), band) if not wired else None,
        "channel": s.get("channel"),
        "channel_width": s.get("channel_width") or s.get("channelWidth"),
        "signal": signal,
        "rssi": _num(s.get("rssi")),
        "noise": noise,
        "snr": (signal - noise) if signal is not None and noise is not None else None,
        "tx_rate_mbps": (_num(s.get("tx_rate")) or 0) / 1000 or None,
        "rx_rate_mbps": (_num(s.get("rx_rate")) or 0) / 1000 or None,
        "nss": s.get("nss"),
        "retries_pct": _num(s.get("wifi_tx_retries_percentage")),
        "satisfaction": _num(s.get("satisfaction")),
        "satisfaction_reason": s.get("satisfaction_reason"),
        "anomalies": s.get("anomalies"),
        "powersave": s.get("powersave_enabled"),
        "fast_roaming": s.get("is_11r"),
        "mlo": s.get("is_mlo"),
        "down_bps": (_num(tx_r) or 0) * 8 if online else 0.0,
        "up_bps": (_num(rx_r) or 0) * 8 if online else 0.0,
        "down_bytes": _num(tx_b),
        "up_bytes": _num(rx_b),
        "uptime_s": _num(s.get("uptime")),
        "assoc_time": _num(s.get("assoc_time")),
        "first_seen": _num(s.get("first_seen")),
        "last_seen": _num(s.get("last_seen")) or (time.time() if online else None),
        "idle_s": _num(s.get("idletime")),
        "dhcp_end": _num(s.get("dhcpend_time")),
        "sources": ["unifi"],
    }
    return rec


def from_lease(mac: str, ip: str, hostname: str, state: str, interface: str = "", expires: Any = None) -> dict[str, Any]:
    st = (state or "").lower()
    return {
        "mac": norm_mac(mac), "ip": ip or "", "hostname": hostname or "", "network": interface or "",
        "online": st in ("active", "online", "bound"), "sources": ["dhcp"],
        "lease": {"state": state, "interface": interface, "expires": expires},
    }


class ClientTracker:
    def __init__(self) -> None:
        self.history: dict[str, deque] = {}

    def record(self, clients: list[dict[str, Any]]) -> None:
        now = round(time.time())
        for c in clients:
            if c.get("online") and c.get("mac") and "unifi" in c.get("sources", []):
                h = self.history.setdefault(c["mac"], deque(maxlen=HISTORY_POINTS))
                h.append((now, c.get("down_bps") or 0.0, c.get("up_bps") or 0.0))

    def merged(self) -> list[dict[str, Any]]:
        grouped: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for dev in store.devices.values():
            if dev.enabled:
                for c in dev.clients or []:
                    if c.get("mac"):
                        grouped.setdefault(c["mac"], []).append((dev.name, c))
        dev_by_mac = {norm_mac(d.facts.get("mac", "")): d for d in store.devices.values() if d.facts.get("mac")}
        out = []
        for mac, recs in grouped.items():
            # UniFi has the rich, authoritative record; DHCP leases only fill gaps.
            recs.sort(key=lambda r: "unifi" not in r[1].get("sources", []))
            c: dict[str, Any] = {"mac": mac, "sources": [], "via": []}
            for via, r in recs:
                for k, v in r.items():
                    if k != "sources" and v not in (None, "", [], {}) and c.get(k) in (None, "", [], {}):
                        c[k] = v
                c["sources"] += [s for s in r.get("sources", []) if s not in c["sources"]]
                if via not in c["via"]:
                    c["via"].append(via)
            unifi = next((r for _, r in recs if "unifi" in r.get("sources", [])), None)
            c["online"] = bool(unifi["online"]) if unifi else any(r.get("online") for _, r in recs)
            uplink = dev_by_mac.get(c.get("uplink_mac") or "")
            if uplink is not None:
                c["uplink_device_id"], c["uplink_name"] = uplink.id, uplink.name
            c["display_name"] = c.get("name") or c.get("hostname") or (
                f"{c['vendor']} {mac[-5:]}" if c.get("vendor") else mac)
            c["category"] = classify(c.get("name"), c.get("hostname"), c.get("vendor"))
            out.append(c)
        out.sort(key=lambda c: (not c["online"], -((c.get("down_bps") or 0) + (c.get("up_bps") or 0)), c["display_name"].lower()))
        return out

    def get(self, mac: str) -> dict[str, Any] | None:
        mac = norm_mac(mac)
        for c in self.merged():
            if c["mac"] == mac:
                return {**c, "history": [list(p) for p in self.history.get(mac, [])]}
        return None


tracker = ClientTracker()
