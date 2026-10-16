"""Parsers that turn raw log lines into structured security events.

Covered formats:
  * pfSense / OPNsense ``filterlog`` CSV (IPv4 + IPv6, tcp/udp/icmp)
  * OpenSSH (failed / accepted logins)
  * pfSense webConfigurator and OPNsense Web GUI logins
  * OpenVPN authentication failures / successful peers
  * HTTP access logs in combined / common format (nginx, Traefik, Caddy, Apache)
    and HAProxy's HTTP log format: 401/403 count as failed logins
  * Suricata / Snort alerts (fast.log / syslog style)
  * DHCP server lease lines (ISC dhcpd, dnsmasq, Kea) and rogue-DHCP indicators

Every parser is a pure function so it can be unit tested without the app.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache

IP = r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}"
MAC = r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    123: "ntp", 135: "msrpc", 137: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 1194: "openvpn",
    1433: "mssql", 1723: "pptp", 1883: "mqtt", 2222: "ssh-alt", 2375: "docker", 3306: "mysql", 3389: "rdp",
    5060: "sip", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8291: "winbox",
    8443: "https-alt", 8888: "http-alt", 9000: "portainer", 9443: "portainer", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 32400: "plex", 51820: "wireguard",
}

# Networks that are "inside": RFC 1918, CGNAT, loopback, link-local, ULA.
# (ipaddress.is_private is too broad - it also includes the documentation ranges.)
_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)]


@lru_cache(maxsize=65536)
def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _INTERNAL if n.version == addr.version)


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def service_name(port: int | None, proto: str = "tcp") -> str:
    if port is None:
        return proto or ""
    return SERVICES.get(port, f"{proto}/{port}" if proto else str(port))


# --------------------------------------------------------------------------- #
# Firewall (filterlog)
# --------------------------------------------------------------------------- #
@dataclass
class FwEvent:
    action: str  # block | pass | match ...
    iface: str
    direction: str
    proto: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    rule: str = ""


def _int(v: str) -> int | None:
    return int(v) if v.isdigit() else None


def parse_filterlog(message: str) -> FwEvent | None:
    msg = message.strip()
    if not msg[:1].isdigit():  # "filterlog[123]: 5,,,..." when the tag was not split off
        _, _, msg = msg.partition(": ")
    f = msg.split(",")
    if len(f) < 10 or f[6] not in ("block", "pass", "match", "scrub", "rdr", "nat", "binat"):
        return None
    action, iface, direction, ver = f[6], f[4], f[7], f[8]
    try:
        if ver == "4" and len(f) >= 20:
            proto, src, dst, rest = f[16].lower(), f[18], f[19], f[20:]
        elif ver == "6" and len(f) >= 17:
            proto, src, dst, rest = f[12].lower(), f[15], f[16], f[17:]
        else:
            return None
    except IndexError:
        return None
    if not (valid_ip(src) and valid_ip(dst)):
        return None
    sport = dport = None
    if proto in ("tcp", "udp") and len(rest) >= 2:
        sport, dport = _int(rest[0]), _int(rest[1])
    return FwEvent(action=action, iface=iface, direction=direction, proto=proto, src=src, dst=dst,
                   sport=sport, dport=dport, rule=f[3] or f[0])


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
@dataclass
class AuthEvent:
    ok: bool
    service: str
    src: str
    user: str = ""
    detail: str = ""


_SSH_FAIL = [
    re.compile(rf"Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S*) from (?P<ip>{IP}) port"),
    re.compile(rf"Connection closed by (?:authenticating|invalid) user (?P<user>\S*) (?P<ip>{IP}) port \d+ \[preauth\]"),
    re.compile(rf"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) from (?P<ip>{IP})"),
]
_SSH_OK = re.compile(rf"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>{IP})")
_GUI_FAIL = [
    re.compile(rf"authentication error for (?:user )?'(?P<user>[^']*)' from:? (?P<ip>{IP})", re.I),  # pfSense
    re.compile(rf"authentication for (?:user )?'(?P<user>[^']*)' from:? (?P<ip>{IP}) failed", re.I),  # OPNsense
]
_GUI_OK = re.compile(rf"(?:Successful login|logged in) for user '(?P<user>[^']*)' from:? (?P<ip>{IP})", re.I)
_OVPN_IP = re.compile(rf"(?:\[AF_INET6?\])?(?P<ip>{IP}):\d+")
_OVPN_USER = re.compile(r"user(?:name)? '(?P<user>[^']+)'")
_OVPN_FAIL = re.compile(r"AUTH_FAILED|TLS Auth Error|TLS handshake failed|could not authenticate|"
                        r"auth-user-pass-verify\) .*fail|Auth Username/Password verification failed", re.I)
_OVPN_OK = re.compile(r"Peer Connection Initiated with", re.I)
_HTTP_CLF = re.compile(
    rf'^(?:\S+\s+)?(?P<ip>{IP}) \S+ (?P<user>\S+) \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{{3}}) ')
_HAPROXY = re.compile(
    rf"^(?P<ip>{IP}):\d+ \[[^\]]+\] (?P<frontend>\S+) (?P<backend>\S+) [\d/+-]+ (?P<status>\d{{3}}) .*\"(?P<method>[A-Z]+) (?P<path>\S+)")
_LOGIN_PATH = re.compile(r"login|signin|sign_in|auth|session|token|wp-login|xmlrpc", re.I)


def _gui_service(app: str, msg: str) -> str:
    if "opnsense" in msg.lower() or "Web GUI" in msg:
        return "opnsense-gui"
    return "firewall-gui"


def parse_auth(app: str, message: str) -> AuthEvent | None:
    ev = _parse_auth(app, message)
    return ev if ev and valid_ip(ev.src) else None


def _parse_auth(app: str, message: str) -> AuthEvent | None:
    a = (app or "").lower()
    m = message

    if "sshd" in a or " sshd" in m[:40] or "Failed password" in m or "Accepted " in m[:20]:
        for rx in _SSH_FAIL:
            r = rx.search(m)
            if r:
                return AuthEvent(False, "ssh", r["ip"], r["user"])
        r = _SSH_OK.search(m)
        if r:
            return AuthEvent(True, "ssh", r["ip"], r["user"])

    for rx in _GUI_FAIL:
        r = rx.search(m)
        if r:
            return AuthEvent(False, _gui_service(a, m), r["ip"], r["user"])
    r = _GUI_OK.search(m)
    if r:
        return AuthEvent(True, _gui_service(a, m), r["ip"], r["user"])

    if "openvpn" in a or "openvpn" in m[:30].lower():
        ip = _OVPN_IP.search(m)
        if ip:
            user = _OVPN_USER.search(m)
            if _OVPN_FAIL.search(m):
                return AuthEvent(False, "openvpn", ip["ip"], user["user"] if user else "")
            if _OVPN_OK.search(m):
                return AuthEvent(True, "openvpn", ip["ip"], user["user"] if user else "")

    r = _HTTP_CLF.search(m) or _HAPROXY.search(m)
    if r:
        status = int(r["status"])
        if status in (401, 403):
            return AuthEvent(False, "http", r["ip"], "", f'{r["method"]} {r["path"][:120]} -> {status}')
        if status < 400 and r["method"] == "POST" and _LOGIN_PATH.search(r["path"]):
            return AuthEvent(True, "http", r["ip"], "", f'{r["method"]} {r["path"][:120]} -> {status}')
    return None


# --------------------------------------------------------------------------- #
# IDS (Suricata / Snort)
# --------------------------------------------------------------------------- #
@dataclass
class IdsEvent:
    signature: str
    sid: str
    priority: int
    proto: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    classification: str = ""


_IDS = re.compile(
    r"\[(?P<gid>\d+):(?P<sid>\d+):\d+\]\s+(?P<sig>.*?)\s+(?:\[\*\*\]\s+)?"
    r"(?:\[Classification:\s*(?P<cls>[^\]]*)\]\s+)?\[Priority:\s*(?P<prio>\d+)\]\s+"
    r"\{(?P<proto>[A-Za-z0-9-]+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)")


def _split_hostport(s: str) -> tuple[str, int | None]:
    if valid_ip(s):
        return s, None
    host, _, port = s.rpartition(":")
    if valid_ip(host) and port.isdigit():
        return host, int(port)
    return s, None


def parse_ids(message: str) -> IdsEvent | None:
    r = _IDS.search(message)
    if not r:
        return None
    src, sport = _split_hostport(r["src"])
    dst, dport = _split_hostport(r["dst"])
    if not valid_ip(src):
        return None
    return IdsEvent(signature=r["sig"].strip()[:200], sid=r["sid"], priority=int(r["prio"]), proto=r["proto"].lower(),
                    src=src, dst=dst, sport=sport, dport=dport, classification=(r["cls"] or "").strip())


# --------------------------------------------------------------------------- #
# DHCP server lines
# --------------------------------------------------------------------------- #
@dataclass
class DhcpLogEvent:
    kind: str  # ack | nak | rogue
    ip: str = ""
    mac: str = ""
    server: str = ""


_DHCP_ACK = [
    re.compile(rf"DHCPACK on (?P<ip>{IP}) to (?P<mac>{MAC})"),  # ISC dhcpd
    re.compile(rf"DHCPACK\(\S+\) (?P<ip>{IP}) (?P<mac>{MAC})"),  # dnsmasq
    re.compile(rf"lease (?P<ip>{IP}) has been allocated", re.I),  # Kea
]
_DHCP_NAK = re.compile(r"DHCPNAK", re.I)
_DHCP_ROGUE = re.compile(r"rogue dhcp|another dhcp server|unauthori[sz]ed dhcp|dhcp (?:server )?spoof", re.I)
_SERVER_IP = re.compile(rf"(?:server|from|by|\()\s*(?P<ip>{IP})")


def parse_dhcp(message: str) -> DhcpLogEvent | None:
    if _DHCP_ROGUE.search(message):
        s = _SERVER_IP.search(message)
        return DhcpLogEvent("rogue", server=s["ip"] if s else "")
    for rx in _DHCP_ACK:
        r = rx.search(message)
        if r:
            return DhcpLogEvent("ack", ip=r["ip"], mac=(r.groupdict().get("mac") or "").lower().replace("-", ":"))
    if _DHCP_NAK.search(message):
        return DhcpLogEvent("nak")
    return None
