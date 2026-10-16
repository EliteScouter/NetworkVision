"""Simulated attacks and DHCP data for demo mode.

All "attacker" addresses come from the RFC 5737 documentation ranges
(198.51.100.0/24, 203.0.113.0/24) so the demo never points at a real host.
"""

from __future__ import annotations

import random
import time
from typing import Any

from ..services.clients import from_lease
from .base import LogLine, Section

T0 = time.time()
WAN_IP = "192.0.2.10"
TARGET_PORTS = [22, 22, 22, 23, 23, 3389, 3389, 445, 80, 443, 8080, 5900, 1433, 3306, 6379, 25, 2375, 8443, 9200, 5060]
SSH_USERS = ["root", "admin", "ubuntu", "test", "oracle", "pi", "user", "git", "postgres", "support"]


def _cycle(period: float, duty: float, offset: float = 0.0) -> bool:
    return ((time.time() - T0 + offset) % period) < period * duty


def _phase(period: float, offset: float = 0.0) -> int:
    return int((time.time() - T0 + offset) // period)


def attacker() -> str:
    return f"{random.choice(['198.51.100', '203.0.113'])}.{random.randint(2, 250)}"


def _mac(seed: str) -> str:
    rnd = random.Random(seed)
    return "02:" + ":".join(f"{rnd.randint(0, 255):02x}" for _ in range(5))


def filterlog(action: str, iface: str, src: str, dst: str, dport: int, proto: str = "tcp", direction: str = "in") -> str:
    pid = 6 if proto == "tcp" else 17
    tail = "0,S,1234567,,64240,,mss" if proto == "tcp" else "40"
    return (f"{random.randint(5, 90)},,,{1000000100 + random.randint(0, 9)},{iface},match,{action},{direction},4,0x0,,"
            f"{random.randint(40, 250)},{random.randint(1, 65000)},0,DF,{pid},{proto},60,{src},{dst},"
            f"{random.randint(1024, 65535)},{dport},{tail}")


def _clf(ip: str, method: str, path: str, status: int) -> str:
    stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} 52 "-" "python-requests/2.31.0"'


_state: dict[str, Any] = {"breach_phase": -1}


def pfsense_logs() -> list[LogLine]:
    now = time.time()
    out: list[LogLine] = []

    def fw(msg: str, sev: int = 5) -> None:
        out.append(LogLine(now - random.random() * 4, msg, sev, "filterlog", "firewall"))

    # 1. constant internet background noise against the WAN
    for _ in range(random.randint(4, 12)):
        port = random.choice(TARGET_PORTS)
        fw(filterlog("block", "igb0", attacker(), WAN_IP, port, "udp" if port in (5060, 53) else "tcp"))
    # 2. a persistent scanner sweeping ports (fully blocked -> shown, not alerted by default)
    if _cycle(900, 0.3):
        base = (_phase(30) * 25) % 1000 + 1
        for p in range(base, base + random.randint(15, 30)):
            fw(filterlog("block", "igb0", "203.0.113.66", WAN_IP, p))
    # 3. legit traffic to port-forwarded services
    for _ in range(random.randint(2, 5)):
        fw(filterlog("pass", "igb0", attacker(), "10.0.0.50", random.choice([443, 443, 443, 1194])), 6)
    # 4. a compromised IoT camera sweeping the LAN from the IoT VLAN
    if _cycle(1200, 0.15, 300):
        for _ in range(random.randint(6, 14)):
            host = f"10.0.10.{random.randint(2, 60)}"
            port = random.choice([22, 23, 80, 443, 445, 554, 8080, 8443, 3389, 5900, 1883, 8000, 9000, 81])
            fw(filterlog("block" if random.random() < 0.7 else "pass", "igb1.30", "10.0.30.66", host, port))
    # 5. firewall GUI and OpenVPN login failures
    if random.random() < 0.12:
        out.append(LogLine(now, "/index.php: webConfigurator authentication error for user 'admin' from: 198.51.100.200",
                           4, "php-fpm", "auth"))
    if random.random() < 0.15:
        out.append(LogLine(now, f"{attacker()}:{random.randint(1024, 65535)} TLS Error: TLS handshake failed", 4, "openvpn"))
    if random.random() < 0.08:
        out.append(LogLine(now, f"{attacker()}:{random.randint(1024, 65535)} AUTH_FAILED: user 'vpnuser' could not authenticate",
                           4, "openvpn"))
    # 6. the real DHCP server for the LAN
    if random.random() < 0.4:
        n = random.randint(20, 90)
        out.append(LogLine(now, f"DHCPACK on 10.0.10.{n} to {_mac(f'lan{n}')} via ix0", 6, "dhcpd"))
    return out


def opnsense_logs() -> list[LogLine]:
    now = time.time()
    out: list[LogLine] = []
    if random.random() < 0.08:
        port = random.choice([1433, 3389, 22, 5900])
        sig = {1433: "ET SCAN Suspicious inbound to MSSQL port 1433", 3389: "ET SCAN Suspicious inbound to RDP port 3389",
               22: "ET SCAN Potential SSH Scan", 5900: "ET SCAN Potential VNC Scan 5900-5920"}[port]
        out.append(LogLine(now, f"[1:{2010935 + port}:3] {sig} [Classification: Attempted Information Leak] [Priority: 2] "
                                f"{{TCP}} {attacker()}:{random.randint(1024, 65535)} -> 10.0.50.1:{port}", 4, "suricata"))
    if _cycle(2700, 0.04, 1200) and random.random() < 0.5:
        out.append(LogLine(now, "[1:2027759:2] ET MALWARE Possible Cobalt Strike Beacon Observed "
                                "[Classification: A Network Trojan was detected] [Priority: 1] "
                                "{TCP} 10.0.50.23:49812 -> 203.0.113.9:443", 1, "suricata"))
    return out


def portainer_logs() -> list[LogLine]:
    """A host behind a port forward: SSH brute force, web login stuffing, and a rogue DHCP container."""
    now = time.time()
    out: list[LogLine] = []
    if _cycle(1500, 0.4, 200):
        for _ in range(random.randint(1, 3)):
            u = random.choice(SSH_USERS)
            inv = "" if u in ("root", "admin") else "invalid user "
            out.append(LogLine(now, f"Failed password for {inv}{u} from 203.0.113.77 port {random.randint(30000, 65000)} ssh2",
                               5, "sshd", "auth"))
        phase = _phase(1500, 200)
        # once per attack wave, after the attacker has had a while, they "get in"
        if _cycle(1500, 0.4, 200) and not _cycle(1500, 0.25, 200) and _state["breach_phase"] != phase and random.random() < 0.2:
            _state["breach_phase"] = phase
            out.append(LogLine(now, "Accepted password for admin from 203.0.113.77 port 40022 ssh2", 6, "sshd", "auth"))
    if _cycle(1100, 0.2, 500):
        for _ in range(random.randint(2, 5)):
            out.append(LogLine(now, _clf("198.51.100.23", "POST", "/api/auth/login", 401), 6, "nginx"))
    if random.random() < 0.3:
        out.append(LogLine(now, _clf(f"10.0.10.{random.randint(20, 60)}", "GET", "/", 200), 6, "nginx"))
    if _cycle(2400, 0.15, 900) and random.random() < 0.5:
        n = random.randint(150, 200)
        out.append(LogLine(now, f"DHCPACK(eth0) 10.0.10.{n} {_mac(f'rogue{n}')} rogue-container", 6, "dnsmasq-dhcp"))
    return out


def unifi_logs() -> list[LogLine]:
    if random.random() < 0.02:
        return [LogLine(time.time(), "Rogue DHCP server detected on Garage-SW Port 6 (server 10.0.30.254)", 4, "evt", "unifi")]
    return []


# ----------------------------------------------------------------------- DHCP
def dhcp_roster() -> list[tuple[str, str, str]]:
    """(ip, mac, hostname) for the currently active leases: the demo UniFi clients plus a few oddities."""
    from .demo_wifi import dhcp_hosts  # local import: demo_wifi imports the UniFi collector

    rows = dhcp_hosts()
    printer = next(ip for ip, _, host in rows if host == "brother-printer")
    if _cycle(1800, 0.6, 100):  # a cheap IoT plug squatting on the printer's static-ish lease
        rows.append((printer, _mac("esp-squatter"), "ESP_3A1F2C"))
    rows.append(("10.0.10.90", _mac("tab-clone"), "galaxy-tab-s9"))  # a second tablet with the same name
    hop = _phase(180) % 7  # a tablet that keeps getting new addresses
    rows.append((f"10.0.10.{120 + hop}", _mac("kids-tablet"), "Kids-Tablet"))
    visitor = _phase(600)  # a new visitor device every ten minutes
    rows.append((f"10.0.70.{100 + visitor % 150}", _mac(f"guest{visitor}"), f"Guest-Phone-{visitor % 97}"))
    return rows


def pfsense_leases() -> list[dict]:
    """Normalized lease records (the gateway's contribution to the client inventory)."""
    leases = [from_lease(mac, ip, host, "active", "LAN" if ip.startswith("10.0.10.") else "GUESTS")
              for ip, mac, host in dhcp_roster()]
    leases.append(from_lease(_mac("old-laptop"), "10.0.10.99", "Old-Laptop", "expired", "LAN"))
    return leases


def pfsense_dhcp_section() -> Section:
    rows = [[c["ip"], c["mac"], c["hostname"], c["lease"]["interface"], c["lease"]["state"]] for c in pfsense_leases()]
    return Section("dhcp", "DHCP leases", ["IP", "MAC", "Hostname", "Interface", "State"], rows)
