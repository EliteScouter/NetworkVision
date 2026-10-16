import os

import pytest

os.environ.setdefault("NV_SECRET_KEY", "test-secret-key-for-unit-tests-only-0123456789")

from app.collectors.base import Snapshot  # noqa: E402
from app.security_parsers import (  # noqa: E402
    is_internal,
    parse_auth,
    parse_dhcp,
    parse_filterlog,
    parse_ids,
    service_name,
)

# --------------------------------------------------------------------- filterlog
V4 = "5,,,1000000103,igb0,match,block,in,4,0x0,,242,54321,0,none,6,tcp,40,198.51.100.7,192.0.2.10,51234,23,0,S,123,,1024,,"
V6 = "60,,,1000003520,igb0,match,pass,in,6,0x00,0x00000,64,tcp,6,40,2001:db8::1,2001:db8::2,51234,22,0,S,1,,64800,,"
ICMP = "7,,,1000000105,igb0,match,block,in,4,0x0,,64,0,0,none,1,icmp,84,203.0.113.5,192.0.2.10,request,1234,1"


def test_filterlog_ipv4_tcp():
    fw = parse_filterlog(V4)
    assert fw and fw.action == "block" and fw.iface == "igb0" and fw.direction == "in"
    assert (fw.proto, fw.src, fw.dst, fw.sport, fw.dport) == ("tcp", "198.51.100.7", "192.0.2.10", 51234, 23)


def test_filterlog_ipv6_and_tag_prefix():
    fw = parse_filterlog(f"filterlog[4242]: {V6}")
    assert fw and fw.action == "pass" and fw.src == "2001:db8::1" and fw.dport == 22


def test_filterlog_icmp_has_no_ports_and_garbage_is_none():
    fw = parse_filterlog(ICMP)
    assert fw and fw.proto == "icmp" and fw.dport is None
    assert parse_filterlog("this is not a firewall line") is None
    assert parse_filterlog("1,2,3") is None


# -------------------------------------------------------------------------- auth
@pytest.mark.parametrize("app,msg,ok,service,ip,user", [
    ("sshd", "Failed password for invalid user oracle from 203.0.113.77 port 40112 ssh2", False, "ssh", "203.0.113.77", "oracle"),
    ("sshd", "Failed password for root from 203.0.113.77 port 40112 ssh2", False, "ssh", "203.0.113.77", "root"),
    ("sshd", "Connection closed by invalid user git 198.51.100.4 port 5022 [preauth]", False, "ssh", "198.51.100.4", "git"),
    ("sshd", "Accepted publickey for admin from 10.0.10.21 port 51000 ssh2", True, "ssh", "10.0.10.21", "admin"),
    ("php-fpm", "/index.php: webConfigurator authentication error for user 'admin' from: 198.51.100.200",
     False, "firewall-gui", "198.51.100.200", "admin"),
    ("php-fpm", "/index.php: Successful login for user 'admin' from: 10.0.10.21", True, "firewall-gui", "10.0.10.21", "admin"),
    ("audit", "/index.php: Web GUI authentication for 'root' from 198.51.100.9 failed", False, "opnsense-gui", "198.51.100.9", "root"),
    ("openvpn", "203.0.113.4:51234 AUTH_FAILED: user 'vpnuser' could not authenticate", False, "openvpn", "203.0.113.4", "vpnuser"),
    ("nginx", '198.51.100.23 - - [14/Oct/2026:22:30:01 +0000] "POST /api/auth/login HTTP/1.1" 401 52 "-" "curl/8"',
     False, "http", "198.51.100.23", ""),
    ("nginx", '10.0.10.5 - - [14/Oct/2026:22:30:01 +0000] "POST /login HTTP/1.1" 302 0 "-" "Firefox"', True, "http", "10.0.10.5", ""),
])
def test_auth_parsers(app, msg, ok, service, ip, user):
    ev = parse_auth(app, msg)
    assert ev is not None, msg
    assert (ev.ok, ev.service, ev.src, ev.user) == (ok, service, ip, user)


def test_auth_ignores_normal_lines():
    assert parse_auth("nginx", '10.0.10.5 - - [14/Oct/2026:22:30:01 +0000] "GET / HTTP/1.1" 200 10 "-" "x"') is None
    assert parse_auth("sshd", "Server listening on 0.0.0.0 port 22.") is None
    assert parse_auth("kernel", "igb0: link state changed to UP") is None


# --------------------------------------------------------------------------- IDS
def test_suricata_line():
    ev = parse_ids("[1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433 [Classification: Potentially Bad Traffic] "
                   "[Priority: 2] {TCP} 203.0.113.9:4455 -> 10.0.50.1:1433")
    assert ev and ev.sid == "2010935" and ev.priority == 2 and ev.src == "203.0.113.9" and ev.dport == 1433
    assert ev.signature.startswith("ET SCAN")


def test_snort_line():
    ev = parse_ids("[**] [1:1000001:1] Possible SQL injection [**] [Classification: Web Application Attack] [Priority: 1] "
                   "{TCP} 198.51.100.3:3333 -> 10.0.0.50:80")
    assert ev and ev.priority == 1 and ev.dst == "10.0.0.50" and ev.dport == 80


# -------------------------------------------------------------------------- DHCP
def test_dhcp_lines():
    ack = parse_dhcp("DHCPACK on 10.0.10.5 to aa:bb:cc:dd:ee:ff via ix0")
    assert ack and ack.kind == "ack" and ack.ip == "10.0.10.5" and ack.mac == "aa:bb:cc:dd:ee:ff"
    dnsmasq = parse_dhcp("DHCPACK(eth0) 10.0.10.150 02:42:ac:11:00:02 rogue-container")
    assert dnsmasq and dnsmasq.kind == "ack" and dnsmasq.ip == "10.0.10.150"
    rogue = parse_dhcp("Rogue DHCP server detected on Garage-SW Port 6 (server 10.0.30.254)")
    assert rogue and rogue.kind == "rogue" and rogue.server == "10.0.30.254"
    assert parse_dhcp("DHCPNAK on 10.0.10.9 to aa:bb:cc:dd:ee:01 via ix0").kind == "nak"


def test_helpers():
    assert is_internal("10.1.2.3") and is_internal("100.64.1.1") and is_internal("fd00::1")
    assert not is_internal("198.51.100.1") and not is_internal("8.8.8.8")
    assert service_name(22) == "ssh" and service_name(31337, "udp") == "udp/31337"


# --------------------------------------------------------------------- detectors
class Recorder:
    def __init__(self):
        self.events, self.synced = [], []

    async def raise_event(self, device_id, key, title, detail, severity="critical", ttl=1800, rule="log_event"):
        self.events.append({"key": key, "title": title, "severity": severity, "rule": rule})

    async def sync_group(self, prefixes, conds):
        self.synced = conds

    def rules(self):
        return [e["rule"] for e in self.events]


@pytest.fixture
def sec(monkeypatch):
    from app.config import get_settings
    from app.services import security as mod

    rec = Recorder()
    monkeypatch.setattr(mod, "alerts", rec)
    monkeypatch.setattr(get_settings(), "sec_bruteforce_failures", 5)
    engine = mod.SecurityEngine()
    return engine, rec


def _line(app, msg, dev=None):
    import time
    return {"ts": time.time(), "app": app, "message": msg, "device_id": dev, "host": "x", "severity": 6}


async def test_bruteforce_then_breach(sec):
    eng, rec = sec
    batch = [_line("sshd", f"Failed password for root from 203.0.113.77 port {4000 + i} ssh2") for i in range(6)]
    await eng.ingest_batch(batch)
    assert "sec_bruteforce" in rec.rules()
    await eng.ingest_batch([_line("sshd", "Accepted password for root from 203.0.113.77 port 4999 ssh2")])
    breach = [e for e in rec.events if e["rule"] == "sec_login_after_failures"]
    assert breach and breach[0]["severity"] == "critical"
    assert eng._agg  # aggregated for storage


async def test_no_bruteforce_below_threshold(sec):
    eng, rec = sec
    await eng.ingest_batch([_line("sshd", "Failed password for root from 203.0.113.8 port 1 ssh2") for _ in range(3)])
    assert rec.rules() == []


async def test_internal_port_scan_alerts_but_blocked_internet_scan_does_not(sec):
    eng, rec = sec
    internal = [_line("filterlog", V4.replace("198.51.100.7", "10.0.30.66").replace("192.0.2.10", "10.0.10.5")
                      .replace(",51234,23,", f",51234,{p},")) for p in range(1, 40)]
    await eng.ingest_batch(internal)
    assert "sec_portscan" in rec.rules()
    rec.events.clear()
    external = [_line("filterlog", V4.replace(",51234,23,", f",51234,{p},")) for p in range(1, 40)]
    await eng.ingest_batch(external)
    assert "sec_portscan" not in rec.rules()


async def test_ids_priority_maps_to_severity(sec):
    eng, rec = sec
    await eng.ingest_batch([_line("suricata", "[1:1:1] Bad thing [Classification: x] [Priority: 1] {TCP} 10.0.50.23:1 -> 203.0.113.9:443")])
    assert rec.events and rec.events[0]["severity"] == "critical" and rec.events[0]["rule"] == "sec_ids"


async def test_ignore_list(sec, monkeypatch):
    from app.config import get_settings

    eng, rec = sec
    monkeypatch.setattr(get_settings(), "sec_ignore_ips", "203.0.113.0/24")
    await eng.ingest_batch([_line("sshd", f"Failed password for root from 203.0.113.77 port {i} ssh2") for i in range(10)])
    assert rec.rules() == []


async def test_dhcp_analysis(monkeypatch):
    from app.services import dhcp as mod

    rec = Recorder()
    monkeypatch.setattr(mod, "alerts", rec)

    async def no_persist(*_a, **_k):
        return None

    insights = mod.DhcpInsights()
    monkeypatch.setattr(insights, "_persist", no_persist)
    from app.services.clients import from_lease

    snap = Snapshot(clients=[from_lease(mac, ip, host, state, "LAN") for ip, mac, host, state in [
        ("10.0.10.47", "aa:aa:aa:aa:aa:01", "Office-Printer", "active"),
        ("10.0.10.47", "aa:aa:aa:aa:aa:02", "ESP_3A1F2C", "active"),
        ("10.0.10.41", "aa:aa:aa:aa:aa:03", "Galaxy-S23", "active"),
        ("10.0.10.42", "aa:aa:aa:aa:aa:04", "galaxy-s23", "active"),
        ("10.0.10.50", "aa:aa:aa:aa:aa:05", "android", "active"),
        ("10.0.10.51", "aa:aa:aa:aa:aa:06", "android", "active"),
        ("10.0.10.47", "aa:aa:aa:aa:aa:07", "Old", "expired"),
    ]])
    await insights.observe(1, snap)
    types = {i["type"]: i for i in insights.issues}
    assert "ip_conflict" in types and len(types["ip_conflict"]["members"]) == 2  # the expired lease does not count
    assert "duplicate_hostname" in types and types["duplicate_hostname"]["subject"].lower() == "galaxy-s23"
    assert sum(1 for i in insights.issues if i["type"] == "duplicate_hostname") == 1  # "android" is generic
    assert {c.rule for c in rec.synced} >= {"dhcp_ip_conflict", "dhcp_duplicate_hostname"}

    await insights.ingest_logs([{"message": "DHCPACK on 10.0.10.5 to aa:bb:cc:dd:ee:ff via ix0", "host": "pf-edge"},
                                {"message": "DHCPACK(eth0) 10.0.10.150 02:42:ac:11:00:02 x", "host": "docker01"}])
    await insights.analyze()
    assert any(i["type"] == "multiple_servers" for i in insights.issues)


async def test_dhcp_new_device_after_learning(monkeypatch):
    import time

    from app.services import dhcp as mod

    rec = Recorder()
    monkeypatch.setattr(mod, "alerts", rec)

    async def no_persist(*_a, **_k):
        return None

    insights = mod.DhcpInsights()
    monkeypatch.setattr(insights, "_persist", no_persist)
    insights.first_data = time.time() - 10 * 3600  # learning period over
    from app.services.clients import from_unifi

    snap = Snapshot(clients=[from_unifi({"mac": "aa:00:00:00:00:09", "ip": "10.0.70.20", "name": "Guest-Phone"}, True, {})])
    await insights.observe(2, snap)
    assert [e["rule"] for e in rec.events] == ["dhcp_new_device"]
    rec.events.clear()
    await insights.observe(2, snap)
    assert rec.events == []  # only once


def test_dhcp_extract_uses_client_inventory():
    from app.services.clients import from_lease, from_unifi
    from app.services.dhcp import extract

    snap = Snapshot(clients=[
        from_lease("AA-BB-CC-00-00-01", "10.0.10.5", "nas", "active"),
        from_lease("aa:bb:cc:00:00:02", "10.0.10.6", "old", "expired"),
        from_unifi({"mac": "aa:bb:cc:00:00:03", "last_ip": "10.0.10.7", "hostname": "phone"}, False, {}),
        from_lease("aa:bb:cc:00:00:04", "", "no-ip", "active"),
    ])
    obs = {o.mac: o for o in extract(7, snap)}
    assert set(obs) == {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"}
    assert obs["aa:bb:cc:00:00:01"].source == "lease" and obs["aa:bb:cc:00:00:01"].active
    assert not obs["aa:bb:cc:00:00:02"].active  # expired lease
    assert obs["aa:bb:cc:00:00:03"].source == "controller" and not obs["aa:bb:cc:00:00:03"].active  # offline
