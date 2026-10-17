"""Windows DHCP: PowerShell JSON normalization and the cross-server audit."""

import json

import pytest

from app.collectors.windows_dhcp import SCRIPT, WindowsDhcpCollector, build_snapshot, normalize
from app.services.dhcp import Obs
from app.services.state import DeviceState, store
from app.services.windhcp import WinDhcpAudit, diff_scope


def _scope(**kw):
    base = {"id": "10.0.20.0", "name": "Users", "mask": "255.255.255.0", "start": "10.0.20.100", "end": "10.0.20.200",
            "state": "Active", "lease_s": 691200, "in_use": 50, "free": 51, "pct": 49.5, "reserved": 1,
            "options": [{"id": 3, "name": "Router", "value": ["10.0.20.1"]}, {"id": 6, "name": "DNS Servers", "value": ["10.0.0.10", "10.0.0.11"]}],
            "exclusions": ["10.0.20.150-10.0.20.159"],
            "reservations": [{"ip": "10.0.20.120", "mac": "aa-bb-cc-00-00-01", "name": "printer", "type": "Both"},
                             {"ip": "10.0.20.31", "mac": "00-00-00-00-00-01", "name": "static hold", "type": "Both"},
                             {"ip": "10.0.20.140", "mac": "00-15-5d-02-09-06", "name": "old-vm", "type": "Both"}]}
    base.update(kw)
    return base


def _raw(server, state="Normal", scopes=None, leases=None, server_options=None):
    return {
        "server": server, "fqdn": f"{server}.corp.local", "authorized": True, "conflict_attempts": 1,
        # PowerShell emits a single object (not a list) when there is only one: normalize() must cope.
        "server_options": server_options if server_options is not None else {"id": 15, "name": "DNS Domain Name", "value": "corp.local"},
        "failover": {"name": "DC01-DC02", "partner": "dc02.corp.local", "mode": "LoadBalance", "state": state,
                     "role": "Active", "lb": 50, "reserve": 5, "scopes": "10.0.20.0"},
        "scopes": scopes if scopes is not None else [_scope()],
        "leases": leases if leases is not None else [
            {"ip": "10.0.20.101", "mac": "11-22-33-44-55-66", "host": "laptop.corp.local", "state": "Active", "scope": "10.0.20.0", "expires": 1},
            {"ip": "10.0.20.120", "mac": "aa-bb-cc-00-00-01", "host": "printer", "state": "ActiveReservation", "scope": "10.0.20.0", "expires": None},
            {"ip": "10.0.20.130", "mac": "0a-00-14-82", "host": "BAD_ADDRESS", "state": "Declined", "scope": "10.0.20.0", "expires": 2},
        ],
        "truncated": False,
    }


def test_script_is_read_only_and_capped():
    lowered = SCRIPT.lower()
    for verb in ("set-dhcp", "add-dhcp", "remove-dhcp", "invoke-dhcp", "restart-", "stop-"):
        assert verb not in lowered
    assert "__MAX__" in SCRIPT


def test_normalize_and_snapshot():
    data = normalize(json.loads(json.dumps(_raw("DC01"))))
    assert data["failover"][0]["scopes"] == ["10.0.20.0"]
    assert data["server_options"] == [{"id": 15, "name": "DNS Domain Name", "value": ["corp.local"]}]
    snap = build_snapshot(data)
    assert snap.metrics["clients"] == 2
    macs = {c["mac"]: c for c in snap.clients}
    assert set(macs) == {"11:22:33:44:55:66", "aa:bb:cc:00:00:01"}  # BAD_ADDRESS isn't a client
    assert macs["aa:bb:cc:00:00:01"]["online"] is False  # a reservation isn't proof the device is online
    assert macs["aa:bb:cc:00:00:01"]["lease"]["state"] == "reserved"
    ds = snap.dhcp_server
    assert ds["bad"] == [{"ip": "10.0.20.130", "scope": "10.0.20.0"}]
    assert ds["scopes"][0]["failover"] == "DC01-DC02"
    assert ["11:22:33:44:55:66", "10.0.20.101"] in ds["pairs"]
    assert {s.id for s in snap.sections} == {"scopes", "failover", "reservations", "dhcp"}


def test_basic_auth_requires_https():
    c = WindowsDhcpCollector("dc01", {"scheme": "http", "auth": "basic", "username": "u"}, {"password": "p"})
    with pytest.raises(Exception, match="HTTPS"):
        c._run()


def test_diff_scope_reports_each_difference():
    a = normalize({"scopes": [_scope()]})["scopes"][0]
    b = normalize({"scopes": [_scope(end="10.0.20.210", exclusions=[], options=[
        {"id": 3, "name": "Router", "value": "10.0.20.1"}, {"id": 6, "name": "DNS Servers", "value": ["10.0.0.10"]}],
        reservations=[{"ip": "10.0.20.120", "mac": "aa-bb-cc-00-00-02", "name": "printer"}])]})["scopes"][0]
    lines = diff_scope(a, b, "DC01", "DC02")
    assert any(x.startswith("Range end") for x in lines)
    assert any("Exclusion 10.0.20.150-10.0.20.159 only on DC01" in x for x in lines)
    assert any(x.startswith("Reservation 10.0.20.120") for x in lines)
    assert any(x.startswith("Option 6 DNS Servers") for x in lines)
    assert not any(x.startswith("Option 3") for x in lines)
    assert diff_scope(a, a, "DC01", "DC02") == []


async def test_audit_finds_windows_dhcp_problems(monkeypatch):
    synced = {}

    async def fake_sync(prefixes, conds):
        synced["conds"] = conds

    monkeypatch.setattr("app.services.windhcp.alerts.sync_group", fake_sync)
    store.devices.clear()
    store.devices.update({
        1: DeviceState(id=1, name="DC01", kind="windows_dhcp", role="server", host="dc01"),
        2: DeviceState(id=2, name="DC02", kind="windows_dhcp", role="server", host="dc02"),
        3: DeviceState(id=3, name="EliteUNIFI", kind="unifi", role="controller", host="ck"),
        4: DeviceState(id=4, name="PFSense", kind="pfsense", role="firewall", host="fw"),
    })
    try:
        audit = WinDhcpAudit()
        dc01 = build_snapshot(normalize(_raw("DC01", scopes=[_scope(pct=96.0, in_use=97, free=4)]))).dhcp_server
        dc02 = build_snapshot(normalize(_raw("DC02", state="CommunicationInterrupted", server_options=[],
                                             scopes=[_scope(exclusions=[])], leases=[]))).dhcp_server
        audit.servers = {1: {"name": "DC01", "at": 9e12, "data": dc01}, 2: {"name": "DC02", "at": 9e12, "data": dc02}}
        obs = [
            Obs("11:22:33:44:55:66", "10.0.20.101", "laptop", "controller", 3),  # has a Windows lease: fine
            Obs("de:ad:be:ef:00:01", "10.0.20.105", "nas", "controller", 3),       # static inside the pool
            Obs("de:ad:be:ef:00:02", "10.0.20.155", "cam", "controller", 3),       # static, but in an exclusion: fine
            Obs("aa:bb:cc:00:00:01", "10.0.20.99", "printer", "controller", 3),    # reserved .120, using .99
            Obs("de:ad:be:ef:00:03", "10.0.20.50", "phone", "lease", 4),           # pfSense leasing in the same subnet
            Obs("bc:24:11:00:00:31", "10.0.20.31", "static-box", "controller", 3), # held by a placeholder: fine
            Obs("bc:24:11:75:81:26", "10.0.20.140", "new-vm", "controller", 3),    # reserved for the old VM's MAC
        ]
        await audit.analyze(obs)
        by_type = {}
        for i in audit.issues:
            by_type.setdefault(i["type"], []).append(i)
        assert by_type["failover"][0]["severity"] == "warning"
        assert {i["subject"] for i in by_type["config_drift"]} == {"10.0.20.0", "DC01-DC02"}
        assert by_type["scope_full"][0]["severity"] == "critical"
        assert by_type["bad_address"][0]["members"] == [{"text": "10.0.20.130"}]
        assert [i["subject"] for i in by_type["static_in_pool"]] == ["10.0.20.0"]
        assert by_type["static_in_pool"][0]["members"] == [{"text": "10.0.20.105  nas  de:ad:be:ef:00:01"}]
        assert by_type["reservation_mismatch"][0]["subject"] == "aa:bb:cc:00:00:01"
        assert by_type["server_overlap"][0]["members"] == [{"text": "PFSense"}]
        assert by_type["reserved_other"][0]["members"] == [
            {"text": "10.0.20.140  reserved for 00:15:5d:02:09:06 (old-vm) · used by bc:24:11:75:81:26 (new-vm)"}]
        assert "unauthorized" not in by_type
        assert all(c.key.startswith("dhcp:win:") for c in synced["conds"])
        assert audit.issues[0]["severity"] == "critical"
        summary = audit.summary()
        assert [s["name"] for s in summary] == ["DC01", "DC02"]
        assert summary[0]["failover"][0]["partner_monitored"] is True

        # Healthy, identical partners and nothing odd online -> no issues.
        same = build_snapshot(normalize(_raw("DC01", leases=[]))).dhcp_server
        audit.servers = {1: {"name": "DC01", "at": 9e12, "data": same}, 2: {"name": "DC02", "at": 9e12, "data": same}}
        await audit.analyze([])
        assert audit.issues == []
    finally:
        store.devices.clear()


async def test_dns_probe_finds_stale_and_ptr(monkeypatch):
    from types import SimpleNamespace as NS

    import dns.asyncresolver
    import dns.resolver

    from app.collectors import dns_probe

    zone = {
        ("corp.local", "SOA"): [NS()],
        ("_ldap._tcp.dc._msdcs.corp.local", "SRV"): [NS(target="dc01.corp.local."), NS(target="dc02.corp.local.")],
        ("dc01.corp.local", "A"): [NS(address="10.0.0.10")],
        ("laptop.corp.local", "A"): [NS(address="10.0.20.101")],        # matches its lease
        ("oldpc.corp.local", "A"): [NS(address="10.0.20.177")],         # stale: leased .102 now
        ("101.20.0.10.in-addr.arpa.", "PTR"): [NS(target="laptop.corp.local.")],
        ("102.20.0.10.in-addr.arpa.", "PTR"): [NS(target="somebody-else.corp.local.")],
    }

    async def fake_resolve(self, name, rtype, **kw):
        if name == "cloudflare.com":
            raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])
        if (name, rtype) not in zone:
            raise dns.resolver.NXDOMAIN()
        return zone[(name, rtype)]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)
    leases = [{"ip": "10.0.20.101", "host": "LAPTOP"}, {"ip": "10.0.20.102", "host": "oldpc.corp.local"},
              {"ip": "10.0.20.104", "host": "visitor.othercorp.com"},  # foreign suffix: not checked here
              {"ip": "10.0.20.103", "host": "phone"}, {"ip": "10.0.20.130", "host": "BAD_ADDRESS"}]
    p = await dns_probe.probe("10.0.0.10", "corp.local", "dc01.corp.local", "cloudflare.com", leases)
    assert p["ok"] and p["dc_srv"] == ["dc01.corp.local", "dc02.corp.local"] and p["self_a"] == ["10.0.0.10"]
    assert p["external_ok"] is False
    assert p["checked"] == 3 and p["missing"] == 1
    assert p["stale"] == [{"host": "oldpc.corp.local", "lease_ips": ["10.0.20.102"], "dns_ips": ["10.0.20.177"]}]
    assert p["ptr_mismatch"] == [{"ip": "10.0.20.102", "host": "oldpc.corp.local", "ptr": ["somebody-else.corp.local"]}]

    async def dead(self, name, rtype, **kw):
        raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", dead)
    p = await dns_probe.probe("10.0.0.10", "corp.local", "dc01.corp.local", "", leases)
    assert p["ok"] is False and "no answer" in p["error"]


def test_normalize_dns_section():
    raw = _raw("DC01")
    raw["dns"] = {"available": True, "zones": {"name": "corp.local", "type": "Primary", "ad": True, "reverse": False,
                                               "dynamic": "NonsecureAndSecure", "paused": False},
                  "forwarders": "1.1.1.1", "scavenging": False, "events_error": "Access is denied"}
    d = normalize(raw)["dns"]
    assert d["zones"][0]["dynamic"] == "NonsecureAndSecure" and d["forwarders"] == ["1.1.1.1"]
    assert d["events"] is None and d["events_error"] == "Access is denied"
    assert normalize(_raw("DC01"))["dns"]["zones"] is None  # no DNS data at all: unknown, not "zero zones"
    raw["warnings"] = "Get-DhcpServerv4Failover: Access is denied."  # a single PowerShell string, not a list
    assert normalize(raw)["warnings"] == ["Get-DhcpServerv4Failover: Access is denied."]


async def test_audit_dns_issues(monkeypatch):
    monkeypatch.setattr("app.services.windhcp.alerts.sync_group", lambda *a: _noop())
    store.devices.clear()
    store.devices.update({1: DeviceState(id=1, name="DC01", kind="windows_dhcp", role="server", host="dc01"),
                          2: DeviceState(id=2, name="DC02", kind="windows_dhcp", role="server", host="dc02")})
    try:
        def data(probe, **dns):
            d = build_snapshot(normalize(_raw("DCx", leases=[]))).dhcp_server
            d["dns"] = {"available": True, "zones": None, "forwarders": None, "scavenging": None, "events": None, **dns,
                        "probe": probe}
            return d

        ok = {"ok": True, "domain": "corp.local", "dc_srv": ["dc01.corp.local", "dc02.corp.local"], "external_ok": True,
              "stale": [{"host": "oldpc.corp.local", "lease_ips": ["10.0.20.102"], "dns_ips": ["10.0.20.177"]}],
              "ptr_mismatch": [], "checked": 5}
        behind = {**ok, "dc_srv": ["dc01.corp.local"], "external_ok": False, "external_error": "no answer"}
        audit = WinDhcpAudit()
        audit.servers = {
            1: {"name": "DC01", "at": 9e12, "data": data(ok, scavenging=False, zones=[
                {"name": "corp.local", "type": "Primary", "ad": True, "reverse": False, "dynamic": "NonsecureAndSecure", "paused": False}],
                events=[{"id": 4013, "level": 3, "ts": 1, "msg": "The DNS server is waiting for AD DS"}])},
            2: {"name": "DC02", "at": 9e12, "data": data(behind)},
        }
        await audit.analyze([])
        types = {i["type"]: i for i in audit.issues}
        assert types["dns_mismatch"]["members"] == [{"text": "DC02 is missing dc02.corp.local"}]
        assert types["dns_external"]["title"].startswith("DC02")
        assert "Scavenging is off on DC01" in types["dns_stale"]["detail"]
        assert types["dns_insecure_updates"]["subject"] == "corp.local"
        assert types["dns_events"]["severity"] == "info"
        assert "dns_down" not in types
        assert audit.summary()[0]["dns"]["stale"] == 1

        audit.servers[2]["data"]["dns"]["probe"] = {"ok": False, "error": "no answer for corp.local"}
        await audit.analyze([])
        assert any(i["type"] == "dns_down" and i["severity"] == "critical" for i in audit.issues)
        audit.servers[2]["data"]["dns"]["available"] = False  # DHCP-only box: no DNS role, no alert
        await audit.analyze([])
        assert not any(i["type"] == "dns_down" for i in audit.issues)
    finally:
        store.devices.clear()


async def _noop():
    return None
