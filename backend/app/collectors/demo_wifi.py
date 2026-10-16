"""Simulated UniFi clients, APs and RF neighbours for demo mode.

Produces *raw UniFi-shaped* records and runs them through the real normalizers
(from_unifi / build_wifi), so the demo exercises the same code paths as real gear.
"""

from __future__ import annotations

import math
import random
import time
from typing import Any

from ..services.clients import from_unifi
from .unifi import build_wifi

T0 = time.time()
APS = [("U6-Pro Living Room", "U6PRO"), ("U6-LR Office", "U6LR"), ("U6-Mesh Garage", "U6MESH")]
SSIDS = [("Home", "wlan-home", "LAN"), ("IoT", "wlan-iot", "IoT"), ("Guests", "wlan-guest", "Guests")]
DEVICES = [
    # name, vendor, wired, ssid, band, proto, base_signal, mbps
    ("iPhone-15-Pro", "Apple, Inc.", False, "Home", "na", "ax", -52, 8), ("Pixel-8", "Google, Inc.", False, "Home", "na", "ax", -61, 4),
    ("MacBook-Pro", "Apple, Inc.", False, "Home", "6e", "ax", -48, 45), ("Galaxy-Tab-S9", "Samsung", False, "Home", "na", "ax", -66, 6),
    ("Living-Room-TV", "LG Electronics", False, "Home", "na", "ac", -58, 22), ("Apple-TV", "Apple, Inc.", True, "", None, None, None, 18),
    ("PS5", "Sony Interactive", True, "", None, None, None, 30), ("Xbox-Series-X", "Microsoft", False, "Home", "na", "ax", -63, 12),
    ("ThinkPad-X1", "Lenovo", False, "Home", "na", "ax", -57, 9), ("Sonos-Kitchen", "Sonos, Inc.", False, "Home", "ng", "n", -69, 1),
    ("Echo-Dot-Bedroom", "Amazon Technologies", False, "IoT", "ng", "n", -71, 0.2),
    ("Nest-Thermostat", "Google, Inc.", False, "IoT", "ng", "n", -64, 0.05),
    ("esp-plug-01", "Espressif Inc.", False, "IoT", "ng", "n", -73, 0.01), ("esp-plug-02", "Espressif Inc.", False, "IoT", "ng", "n", -78, 0.01),
    ("shelly-garage-door", "Shelly", False, "IoT", "ng", "n", -81, 0.01), ("Hue-Bridge", "Philips Lighting", True, "", None, None, None, 0.05),
    ("Reolink-Doorbell", "Reolink", False, "IoT", "ng", "n", -67, 2.5), ("Ring-Floodlight", "Ring LLC", False, "IoT", "ng", "n", -75, 1.8),
    ("Brother-Printer", "Brother Industries", False, "Home", "ng", "n", -62, 0.01), ("Kids-iPad", "Apple, Inc.", False, "Home", "na", "ax", -70, 5),
    ("Guest-Pixel-7", "Google, Inc.", False, "Guests", "na", "ax", -68, 3), ("Work-Laptop", "Dell Inc.", False, "Home", "na", "ax", -55, 14),
    ("Proxmox-01", "Dell Inc.", True, "", None, None, None, 60), ("TrueNAS", "Supermicro", True, "", None, None, None, 120),
    ("Roomba-j7", "iRobot", False, "IoT", "ng", "n", -74, 0.1), ("Steam-Deck", "Valve", False, "Home", "na", "ac", -59, 25),
]


def _mac(i: int) -> str:
    return f"0a:{0x10:02x}:{i:02x}:{(i * 7) & 0xFF:02x}:{(i * 13) & 0xFF:02x}:{(i * 31) & 0xFF:02x}"


def _wave(period: float, phase: float = 0) -> float:
    return 0.5 + 0.5 * math.sin((time.time() - T0) / period * 2 * math.pi + phase)


def demo_unifi_data(ap_macs: dict[str, str], uplink_mac: str, offline_aps: set[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    now = time.time()
    online_aps = [a for a, _ in APS if a not in offline_aps]
    stas: list[dict[str, Any]] = []
    for i, (name, vendor, wired, ssid, radio, proto, sig, mbps) in enumerate(DEVICES):
        if name.startswith("Guest") and _wave(1800, i) < 0.3:
            continue  # guests come and go
        ap = online_aps[i % len(online_aps)] if online_aps else None
        rate = mbps * 1e6 / 8 * (0.2 + 1.6 * _wave(300 + i * 17, i)) * random.uniform(0.7, 1.3)
        rec: dict[str, Any] = {
            "mac": _mac(i), "hostname": name.lower(), "name": name if i % 3 else "", "oui": vendor,
            "ip": f"10.0.{30 if ssid == 'IoT' else 70 if ssid == 'Guests' else 10}.{20 + i}",
            "network": {"IoT": "IoT", "Guests": "Guests"}.get(ssid, "LAN"), "is_wired": wired,
            "is_guest": ssid == "Guests", "uptime": 3600 * (2 + i * 3) + (now - T0),
            "first_seen": now - 86400 * (5 + i * 9), "last_seen": now,
            "tx_bytes": int(rate * 3600 * (5 + i)), "rx_bytes": int(rate * 900 * (5 + i)),
        }
        if wired:
            rec.update({"sw_mac": uplink_mac, "sw_port": 10 + i % 12, "wired_rate_mbps": 1000 if i % 4 else 10000,
                        "wired-tx_bytes-r": rate, "wired-rx_bytes-r": rate * 0.2,
                        "wired-tx_bytes": rec["tx_bytes"], "wired-rx_bytes": rec["rx_bytes"]})
        elif ap:
            s = sig + random.uniform(-4, 4)
            chan = {"ng": 6, "na": 44, "6e": 37}[radio]
            width = {"ng": 20, "na": 80, "6e": 160}[radio]
            rec.update({
                "ap_mac": ap_macs.get(ap, ""), "essid": ssid, "bssid": ap_macs.get(ap, ""), "radio": radio,
                "radio_proto": proto, "channel": chan, "channel_width": width, "signal": round(s), "rssi": round(s + 95),
                "noise": -95, "tx_rate": int((866 if radio != "ng" else 144) * 1000 * random.uniform(0.5, 1)),
                "rx_rate": int((866 if radio != "ng" else 144) * 1000 * random.uniform(0.4, 0.9)), "nss": 2,
                "wifi_tx_retries_percentage": round(max(0.0, (-s - 55) * 0.6 + random.uniform(0, 4)), 1),
                "satisfaction": max(35, min(100, int(130 + s + random.uniform(-6, 6)))),
                "tx_bytes-r": rate, "rx_bytes-r": rate * 0.25, "powersave_enabled": radio == "ng",
                "is_11r": radio != "ng", "uptime": 600 + i * 400, "wlanconf_id": f"wlan-{ssid.lower()}",
            })
        stas.append(rec)

    known_offline = [{"mac": _mac(100 + i), "hostname": h, "oui": v, "is_wired": False, "last_seen": now - 3600 * (i + 3),
                      "first_seen": now - 86400 * 40, "last_ip": f"10.0.10.{150 + i}", "last_uplink_name": "U6-LR Office",
                      "last_radio": "na"} for i, (h, v) in enumerate([("old-iphone-11", "Apple, Inc."), ("kindle-paperwhite", "Amazon Technologies"),
                                                                       ("visitor-laptop", "HP Inc.")])]
    clients = [from_unifi(s, True, {}) for s in stas] + [from_unifi(u, False, {}) for u in known_offline]

    devices = []
    for idx, (ap, model) in enumerate(APS):
        mac = ap_macs.get(ap, "")
        mine = [s for s in stas if s.get("ap_mac") == mac]
        radios, vaps = [], []
        for name, radio, chan, bw in (("wifi0", "ng", 6 if idx != 1 else 11, 20), ("wifi1", "na", (36, 149, 100)[idx], 80),
                                      ("wifi2", "6e", 37, 160)):
            if radio == "6e" and idx == 2:
                continue  # the mesh AP has no 6 GHz radio
            on_radio = [s for s in mine if s.get("radio") == radio]
            busy = (55 if radio == "ng" else 18) * (0.6 + 0.6 * _wave(900, idx)) + len(on_radio) * 2
            self_rx, self_tx = busy * 0.2, busy * 0.25
            radios.append({"name": name, "radio": radio, "channel": chan, "bw": bw, "tx_power": 20 if radio == "ng" else 23,
                           "cu_total": round(min(98, busy)), "cu_self_rx": round(self_rx), "cu_self_tx": round(self_tx),
                           "num_sta": len(on_radio), "satisfaction": 96 - int(busy / 4),
                           "tx_retries_pct": round(4 + busy / 8, 1)})
            for ssid, wid, _ in SSIDS:
                on = [s for s in on_radio if s.get("essid") == ssid]
                vaps.append({"essid": ssid, "bssid": mac, "radio": radio, "channel": chan, "num_sta": len(on),
                             "satisfaction": (sum(s["satisfaction"] for s in on) / len(on)) if on else None,
                             "avg_client_signal": (sum(s["signal"] for s in on) / len(on)) if on else None,
                             "tx_bytes": sum(s["tx_bytes"] for s in on), "rx_bytes": sum(s["rx_bytes"] for s in on),
                             "wlanconf_id": wid, "is_guest": ssid == "Guests", "up": True})
        devices.append({"type": "uap", "mac": mac, "name": ap, "model": model, "ip": f"10.0.0.{21 + idx}",
                        "state": 0 if ap in offline_aps else 1, "uptime": 86400 * 11 + (time.time() - T0),
                        "version": "6.7.31", "satisfaction": 93, "num_sta": len(mine),
                        "radio_table": [{"name": r["name"], "radio": r["radio"], "is_11ax": True, "has_dfs": r["radio"] == "na",
                                         "tx_power_mode": "auto", "min_txpower": 6, "max_txpower": 26, "nss": 2} for r in radios],
                        "radio_table_stats": radios if ap not in offline_aps else [], "vap_table": vaps,
                        "uplink": {"uplink_device_name": "Access-SW1" if idx < 2 else "Garage-SW", "uplink_remote_port": 5 + idx,
                                   "speed": 1000, "type": "wire"}})
    wlans = [{"_id": wid, "name": n, "enabled": True, "security": "wpapsk", "wpa_mode": "wpa2" if n == "IoT" else "wpa3",
              "hide_ssid": False, "is_guest": n == "Guests", "wlan_bands": ["2g", "5g"] if n == "IoT" else ["2g", "5g", "6g"],
              "networkconf_id": net, "fast_roaming_enabled": n != "IoT", "pmf_mode": "required" if n != "IoT" else "optional"}
             for n, wid, net in SSIDS]
    rnd = random.Random(42)
    neighbors = []
    for i in range(60):
        band = "ng" if i < 42 else "na"
        neighbors.append({"bssid": "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*tuple(rnd.randrange(256) for _ in range(6))),
                          "essid": rnd.choice(["NETGEAR42", "xfinitywifi", "ATT-5G", "Starbucks", "", "DIRECT-printer",
                                               "TP-Link_8F2C", "MySpectrumWiFi", "Ziply-Home"]),
                          "band": band, "channel": rnd.choice([1, 6, 11, 6, 1, 11, 3, 9]) if band == "ng" else rnd.choice([36, 44, 149, 157, 100]),
                          "bw": 20 if band == "ng" else 80, "signal": rnd.randint(-92, -58), "security": rnd.choice(["wpa2", "wpa3", "open"]),
                          "ap_name": rnd.choice([a for a, _ in APS]), "last_seen": now - rnd.randint(0, 3600), "oui": ""})
    wifi = build_wifi(devices, wlans, neighbors, stas, {"LAN": "LAN", "IoT": "IoT", "Guests": "Guests"})
    return clients, wifi
