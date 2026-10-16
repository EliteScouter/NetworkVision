"""Demo pfSense filterlog: a believable mix of what a homelab edge firewall logs.

LAN clients browsing (pass), pfBlockerNG dropping internet noise on WAN, a scanner
sweeping ports every so often, a NAT'd public service, WireGuard, IoT isolation
and the inevitable IPv6 mDNS chatter hitting "Block all IPv6". Internet addresses
come from the documentation ranges (RFC 5737 / 3849), never real hosts.
"""

from __future__ import annotations

import random
import time

from .base import LogLine, Section

WAN_IP = "203.0.113.10"
DMZ_WEB = "10.0.20.10"
RULES = [
    # tracker, interface, action, description
    ("1770009104", "WAN", "block", "pfB_Top_v4 auto rule"),
    ("1770010011", "WAN", "block", "pfB_Deny_Inbound_v4 auto rule"),
    ("1655058450", "WAN", "pass", "NAT Nextcloud HTTPS"),
    ("1655058460", "WAN", "pass", "WireGuard road warriors"),
    ("1655058378", "LAN", "pass", "Default allow LAN to any rule"),
    ("1655058401", "IOT", "pass", "IoT internet only (DNS/HTTPS/NTP)"),
    ("1655058412", "IOT", "block", "Isolate IoT from LAN"),
    ("1655058470", "WG0", "pass", "Road warriors to LAN"),
    ("1655058480", "DMZ", "pass", "DMZ outbound updates"),
]
IFACES = {"WAN": "igb0", "LAN": "ix0", "DMZ": "igb1", "IOT": "igb1.30", "WG0": "wg0"}
SCAN_PORTS = [21, 22, 23, 25, 80, 81, 110, 135, 139, 443, 445, 1433, 1723, 2375, 3306, 3389, 5060, 5432, 5900, 6379,
              8000, 8080, 8443, 8888, 9200, 11211, 27017]
OUTBOUND = [("1.1.1.1", 53, "udp"), ("9.9.9.9", 853, "tcp"), ("198.51.100.20", 443, "tcp"), ("198.51.100.44", 443, "tcp"),
            ("192.0.2.80", 443, "tcp"), ("192.0.2.81", 80, "tcp"), ("198.51.100.123", 123, "udp"), ("192.0.2.200", 443, "udp")]
LAN_HOSTS = [f"10.0.10.{n}" for n in (21, 22, 35, 42, 57, 64, 88, 101, 140)]
IOT_HOSTS = [f"10.0.30.{n}" for n in (11, 12, 15, 23, 31)]
V6_LL = ["fe80::f57d:6a9e:54ad:69e", "fe80::1c2b:3aff:fe11:9c2", "fe80::8a3:2dff:fe4c:7a10", "fe80::ae1f:6bff:fe20:1d"]

_state: dict = {"last": 0.0, "scans": [], "scan_port": 0}  # scans: [(source, start, end)]


def rules_section() -> Section:
    return Section("rules", "Firewall rules", ["#", "Iface", "Action", "Proto", "Source", "Destination", "Description", "Disabled", "Tracker"],
                   [[i, iface, action, "any", "any", "any", descr, False, tracker] for i, (tracker, iface, action, descr) in enumerate(RULES)])


def _attacker() -> str:
    net = random.choice(["198.51.100", "203.0.113", "192.0.2"])
    return f"{net}.{random.randint(1, 254)}"


def _tracker(descr_prefix: str) -> str:
    return next(t for t, _, _, d in RULES if d.startswith(descr_prefix))


def _v4(tracker: str, iface: str, action: str, direction: str, proto: str, src: str, dst: str, sport: int | None,
        dport: int | None, flags: str = "S", icmp: str = "request") -> str:
    nic = IFACES[iface]
    ttl = random.choice((52, 57, 63, 64, 116, 128, 239))
    head = f"{random.randint(4, 120)},,,{tracker},{nic},match,{action},{direction},4,0x0,,{ttl},{random.randint(1, 65535)},0,"
    if proto == "tcp":
        length = random.choice((40, 44, 52, 60, 64))
        return (head + f"DF,6,tcp,{length},{src},{dst},{sport},{dport},0,{flags},{random.randint(10**8, 4 * 10**9)},,"
                f"{random.choice((1024, 29200, 64240, 65535))},,mss;sackOK;TS;nop;wscale")
    if proto == "udp":
        data = random.randint(20, 512)
        return head + f"none,17,udp,{data + 28},{src},{dst},{sport},{dport},{data}"
    return head + f"none,1,icmp,84,{src},{dst},{icmp},{random.randint(1, 60000)},{random.randint(1, 900)}"


def _v6(tracker: str, iface: str, action: str, proto: str, src: str, dst: str, sport: int | None = None, dport: int | None = None) -> str:
    nic = IFACES[iface]
    head = f"{random.randint(4, 30)},,,{tracker},{nic},match,{action},in,6,0x00,0x00000,255,"
    if proto == "udp":
        data = random.randint(40, 400)
        return head + f"udp,17,{data + 8},{src},{dst},{sport},{dport},{data}"
    return head + f"ipv6-icmp,58,32,{src},{dst},"


def _one(ts: float) -> str:
    r = random.random()
    scanner = next((src for src, t0, t1 in _state["scans"] if t0 <= ts < t1), None)
    if scanner and r < 0.35:  # a sequential port scan from one source
        _state["scan_port"] = (_state["scan_port"] + random.randint(1, 40)) % 65000 + 1
        return _v4(_tracker("pfB_Deny_Inbound"), "WAN", "block", "in", "tcp", scanner, WAN_IP,
                   random.randint(30000, 65000), _state["scan_port"])
    if r < 0.30:  # pfBlockerNG dropping known-bad sources
        proto = random.choices(("tcp", "udp"), (3, 2))[0]
        dst = WAN_IP if proto == "tcp" or random.random() < 0.4 else "10.0.10.35"
        port = random.choice(SCAN_PORTS) if proto == "tcp" else random.choice((50965, 50965, 5060, 1900, 123, 161))
        return _v4(_tracker(random.choice(("pfB_Top", "pfB_Deny"))), "WAN", "block", "in", proto, _attacker(), dst,
                   random.randint(1024, 65000), port)
    if r < 0.36:  # default deny catches the rest
        return _v4("1000000103", "WAN", "block", "in", "tcp", _attacker(), WAN_IP, random.randint(1024, 65000), random.choice(SCAN_PORTS))
    if r < 0.40:
        return _v4("1000000103", "WAN", "block", "in", "icmp", _attacker(), WAN_IP, None, None)
    if r < 0.47:  # public service behind NAT
        return _v4(_tracker("NAT Nextcloud"), "WAN", "pass", "in", "tcp", _attacker(), DMZ_WEB, random.randint(1024, 65000), 443)
    if r < 0.49:
        return _v4(_tracker("WireGuard"), "WAN", "pass", "in", "udp", "192.0.2.77", WAN_IP, random.randint(1024, 65000), 51820)
    if r < 0.66:  # LAN clients going out
        dst, port, proto = random.choice(OUTBOUND)
        return _v4(_tracker("Default allow LAN"), "LAN", "pass", "in", proto, random.choice(LAN_HOSTS), dst,
                   random.randint(32768, 65000), port)
    if r < 0.72:
        dst, port, proto = random.choice(OUTBOUND[:3] + OUTBOUND[6:7])
        return _v4(_tracker("IoT internet only"), "IOT", "pass", "in", proto, random.choice(IOT_HOSTS), dst,
                   random.randint(32768, 65000), port)
    if r < 0.76:  # IoT trying to reach LAN
        return _v4(_tracker("Isolate IoT"), "IOT", "block", "in", random.choice(("tcp", "udp")), random.choice(IOT_HOSTS),
                   random.choice(LAN_HOSTS), random.randint(32768, 65000), random.choice((445, 548, 8009, 1900, 22)))
    if r < 0.78:
        return _v4(_tracker("Road warriors"), "WG0", "pass", "in", "tcp", "10.66.0.2", random.choice(LAN_HOSTS),
                   random.randint(32768, 65000), random.choice((22, 443, 8006, 9443)))
    if r < 0.80:
        return _v4(_tracker("DMZ outbound"), "DMZ", "pass", "in", "tcp", DMZ_WEB, random.choice(OUTBOUND)[0],
                   random.randint(32768, 65000), 443)
    if r < 0.95:  # mDNS over IPv6 link-local hitting "Block all IPv6"
        return _v6("1000000003", random.choice(("LAN", "IOT", "DMZ")), "block", "udp", random.choice(V6_LL), "ff02::fb", 5353, 5353)
    return _v6("1000000003", random.choice(("LAN", "IOT")), "block", "ipv6-icmp", random.choice(V6_LL), "ff02::2")


def pfsense_filterlog() -> list[LogLine]:
    now = time.time()
    last = _state["last"]
    if not last:  # first poll: backfill the last hour so the Firewall page has history to show
        last = now - 3600
        _state["scans"] = [(_attacker(), now - t, now - t + random.uniform(60, 150)) for t in (3000, 1500)]
    _state["last"] = now
    scans = _state["scans"] = [x for x in _state["scans"] if x[2] > now - 3600]
    if (not scans or now > scans[-1][2] + 600) and random.random() < 0.15:
        scans.append((_attacker(), now, now + random.uniform(60, 180)))
    span = now - last
    n = int(span * random.uniform(2.0, 4.0))
    out = []
    for _ in range(min(n, 12000)):
        ts = last + random.random() * span
        line = _one(ts)
        action = line.split(",")[6]
        out.append(LogLine(ts=ts, message=line, severity=5 if action == "block" else 6, app="filterlog", facility="firewall"))
    return out
