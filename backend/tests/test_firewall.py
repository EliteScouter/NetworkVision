"""Firewall log explorer: filterlog parsing, enrichment, storage and the search / aggregation API."""

import time

import httpx
import pytest
from fastapi import FastAPI

from app.collectors.base import Interface, Section, Snapshot
from app.filterlog import cidr_key_range, ip_key, is_noise, looks_like_filterlog, parse, rule_label

# --------------------------------------------------------------------- parser
PF_TCP4 = ("5,,,1770009104,igb0,match,block,in,4,0x0,,239,54321,0,none,6,tcp,40,120.226.93.27,50.53.9.115,"
           "3644,3896,0,S,1234567890,,1024,,")
PF_UDP4 = "4,,,1770010011,igb0,match,block,in,4,0x0,,52,21883,0,none,17,udp,56,202.58.200.196,10.10.20.35,15887,50965,28"
PF_ICMP4 = "61,,,1000000103,igb0,match,block,in,4,0x0,,114,40192,0,none,1,icmp,60,192.0.2.9,203.0.113.10,request,1,4532"
PF_PASS4 = ("12,,,1655058378,igb0.10,match,pass,in,4,0x0,,128,61243,0,DF,6,tcp,52,10.10.10.57,173.194.12.228,53266,443,0,S,"
            "3302945471,,64240,,mss;nop;wscale;nop;nop;sackOK")
PF_UDP6 = ("9,,,1000000003,igb1.30,match,block,in,6,0x00,0x00000,255,udp,17,48,fe80::f57d:6a9e:54ad:69e,ff02::fb,"
           "5353,5353,48")
PF_ICMP6 = "9,,,1000000003,igb1.30,match,block,in,6,0x00,0x00000,255,ipv6-icmp,58,32,fe80::1c2b:3aff:fe11:9c2,ff02::2,"
PF_TCP6 = ("77,,,1655058999,igb0,match,pass,in,6,0x00,0x00000,58,tcp,6,40,2001:db8:0:1::25,2001:db8:abcd::10,"
           "51515,443,0,S,1,,64800,,")
OPN_TCP4 = ("49,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,block,in,4,0x0,,242,54321,0,none,6,tcp,40,"
            "192.0.2.5,198.51.100.3,58321,8080,0,S,1873421,,1024,,")
OPN_UDP4 = "96,,,fae559338f65e11c53669fc3642c93c2,vtnet1,match,pass,out,4,0x0,,64,0,0,DF,17,udp,76,10.0.0.1,192.0.2.1,123,123,56"
OPN_ICMP6 = "88,,,c0f7e4b1d6a35cc2c4f91b77b5f50f1b,vtnet1,match,pass,out,6,0x00,0x00000,255,ipv6-icmp,58,24,fe80::1,ff02::1:ff00:1,"


def test_pfsense_ipv4_tcp():
    e = parse(PF_TCP4)
    assert e and (e.action, e.direction, e.iface, e.rule_id, e.ipver) == ("block", "in", "igb0", "1770009104", 4)
    assert (e.proto, e.src, e.dst, e.sport, e.dport, e.tcp_flags, e.length) == ("tcp", "120.226.93.27", "50.53.9.115", 3644, 3896, "S", 40)


def test_pfsense_ipv4_udp_and_icmp():
    u = parse(PF_UDP4)
    assert u and (u.proto, u.sport, u.dport, u.tcp_flags) == ("udp", 15887, 50965, "")
    i = parse(PF_ICMP4)
    assert i and i.proto == "icmp" and i.sport is None and i.dport is None and i.info.startswith("request")
    p = parse(PF_PASS4)
    assert p and p.action == "pass" and p.iface == "igb0.10" and p.dport == 443


def test_pfsense_ipv6():
    u = parse(PF_UDP6)
    assert u and (u.ipver, u.proto, u.src, u.dst, u.sport, u.dport, u.length) == (
        6, "udp", "fe80::f57d:6a9e:54ad:69e", "ff02::fb", 5353, 5353, 48)
    i = parse(PF_ICMP6)
    assert i and i.proto == "ipv6-icmp" and i.dport is None
    t = parse(PF_TCP6)
    assert t and (t.proto, t.src, t.dport, t.tcp_flags) == ("tcp", "2001:db8:0:1::25", 443, "S")


def test_opnsense_lines():
    t = parse(OPN_TCP4)
    assert t and t.rule_id == "02f4bab031b57d1e30553ce08e0ec131" and t.iface == "vtnet0" and t.dport == 8080
    u = parse(OPN_UDP4)
    assert u and u.direction == "out" and u.action == "pass" and u.dport == 123
    i = parse(OPN_ICMP6)
    assert i and i.ipver == 6 and i.proto == "ipv6-icmp"


def test_tag_prefix_and_garbage():
    assert parse(f"filterlog[4471]: {PF_TCP4}").dport == 3896
    assert parse("dhcpd: DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff") is None
    assert parse("1,2,3") is None
    assert parse("5,,,1,igb0,match,block,in,4,0x0,,64,1,0,none,6,tcp,40,not-an-ip,10.0.0.1,1,2,0,S") is None
    assert looks_like_filterlog("filterlog", "anything")
    assert looks_like_filterlog("", PF_UDP4)
    assert not looks_like_filterlog("sshd", "Accepted publickey for root from 10.0.0.42 port 52113 ssh2")


def test_ip_keys_and_noise():
    lo, hi = cidr_key_range("10.10.20.0/24")
    assert lo <= ip_key("10.10.20.35") <= hi
    assert not lo <= ip_key("10.10.21.1") <= hi
    lo6, hi6 = cidr_key_range("2001:db8::/32")
    assert lo6 <= ip_key("2001:db8:abcd::10") <= hi6
    assert not lo6 <= ip_key("10.10.20.35") <= hi6  # IPv4 never falls inside an IPv6 range
    assert ip_key("2001:DB8::1") == ip_key("2001:db8:0::1")
    assert cidr_key_range("nope") is None
    assert is_noise("fe80::1", "ff02::fb") and is_noise("10.0.0.5", "224.0.0.251") and is_noise("10.0.0.5", "255.255.255.255")
    assert not is_noise("10.10.10.57", "173.194.12.228")


def test_rule_labels():
    assert rule_label("1000000003") == "Block all IPv6"
    assert rule_label("1000000103") == "Default deny rule IPv4"
    assert rule_label("1000000777") == "System rule"
    assert rule_label("1770009104", {"1770009104": "pfB_Top_v4 auto rule"}) == "pfB_Top_v4 auto rule"
    assert rule_label("1655058378") == ""


# ----------------------------------------------------------- service + API
@pytest.fixture
async def fw(tmp_path, monkeypatch):
    monkeypatch.setenv("NV_SECRET_KEY", "test-secret-key-for-unit-tests-only-0123456789")
    monkeypatch.setenv("NV_DATA_DIR", str(tmp_path))
    from app import db as dbmod
    from app.config import get_settings
    from app.models import Device
    from app.services.firewall import FirewallService
    from app.services.state import store

    get_settings.cache_clear()
    await dbmod.dispose()
    await dbmod.init_db()
    dev = Device(id=7, name="pf-edge", kind="pfsense", role="firewall", host="192.0.2.1", config={}, tags=[], facts={})
    st = store.ensure(dev)
    snap = Snapshot(interfaces=[Interface("INTERNET", alias="igb0"), Interface("HOME", alias="igb0.10"),
                                Interface("INFRASTRUCTURE", alias="igb1.30")])
    snap.sections = [Section("rules", "Firewall rules", ["#", "Description", "Tracker"], [
        [0, "pfB_Top_v4 auto rule", "1770009104"], [1, "pfB_Deny_Inbound_v4 auto rule", "1770010011"],
        [2, "USER_RULE", "1655058378"]])]
    st.apply(snap)
    service = FirewallService()
    yield dbmod, service
    store.remove(7)
    await dbmod.dispose()
    get_settings.cache_clear()


def _entry(msg: str, ts: float, dev: int | None = 7) -> dict:
    return {"ts": ts, "device_id": dev, "host": "pf-edge", "severity": 5, "facility": "", "app": "filterlog",
            "message": msg, "source": "syslog"}


async def test_ingest_enriches_and_counts(fw, monkeypatch):
    _, service = fw
    now = time.time()
    other = {"ts": now, "device_id": 7, "host": "pf-edge", "severity": 6, "facility": "", "app": "dhcpd",
             "message": "DHCPACK on 10.0.0.5", "source": "syslog"}
    keep = service.ingest([_entry(PF_TCP4, now), _entry(PF_UDP6, now), _entry(PF_PASS4, now), other])
    assert len(keep) == 4  # raw lines are kept in the generic log by default
    rows = {r["proto"]: r for r in service.buffer if r["action"] == "block"}
    assert rows["tcp"]["iface_name"] == "INTERNET" and rows["tcp"]["rule"] == "pfB_Top_v4 auto rule"
    assert rows["udp"]["iface_name"] == "INFRASTRUCTURE" and rows["udp"]["rule"] == "Block all IPv6" and rows["udp"]["noise"]
    pass_row = next(r for r in service.buffer if r["action"] == "pass")
    assert pass_row["iface_name"] == "HOME" and pass_row["rule"] == "USER_RULE"
    # Unattributed syslog still resolves through the merged maps.
    service.buffer.clear()
    service.ingest([_entry(PF_UDP4, now, dev=None)])
    assert service.buffer[0]["iface_name"] == "INTERNET" and service.buffer[0]["rule"] == "pfB_Deny_Inbound_v4 auto rule"

    # Skip pass + noise storage, but keep counting; drop raw filterlog from the generic log.
    from app.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "firewall_store_pass", False)
    monkeypatch.setattr(s, "firewall_store_noise", False)
    monkeypatch.setattr(s, "firewall_keep_raw_logs", False)
    service.buffer.clear()
    service.counts.clear()
    keep = service.ingest([_entry(PF_TCP4, now), _entry(PF_UDP6, now), _entry(PF_PASS4, now), other])
    assert keep == [other]
    assert [r["proto"] for r in service.buffer] == ["tcp"]
    assert sum(v[0] for v in service.counts.values()) == 3 and sum(v[1] for v in service.counts.values()) == 2


async def _seed(service, now: float) -> None:
    lines = [
        (PF_TCP4, now - 30), (PF_UDP4, now - 20), (PF_ICMP4, now - 10), (PF_PASS4, now - 5),
        (PF_UDP6, now - 4), (PF_ICMP6, now - 3), (PF_TCP6, now - 2),
        (PF_TCP4.replace("120.226.93.27", "120.226.93.99"), now - 1),
        (PF_TCP4, now - 7200),  # outside the default 1 h window
    ]
    service.ingest([_entry(m, ts) for m, ts in lines])
    await service.flush(final=True)


@pytest.fixture
async def client(fw):
    from app.api import firewall as fw_api
    from app.security import require_user

    _, service = fw
    original = fw_api.firewall
    fw_api.firewall = service
    app = FastAPI()
    app.include_router(fw_api.router)
    app.dependency_overrides[require_user] = lambda: "tester"
    await _seed(service, time.time())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c
    fw_api.firewall = original


async def test_search_filters(client):
    r = (await client.get("/api/firewall/events")).json()
    assert r["total"] == 8 and len(r["items"]) == 8
    assert r["items"][0]["src_ip"] == "120.226.93.99"  # newest first

    async def total(**q):
        return (await client.get("/api/firewall/events", params=q)).json()["total"]

    assert await total(action="block") == 6
    assert await total(action="!block") == 2
    assert await total(iface="INTERNET") == 5
    assert await total(iface="igb0") == 5  # the raw NIC matches too
    assert await total(iface="!INTERNET") == 3
    assert await total(src="120.226.93.0/24") == 2
    assert await total(src="120.226.93.27") == 1
    assert await total(dst="10.10.20.35") == 1
    assert await total(ip="2001:db8::/32") == 1
    assert await total(port="5353") == 1
    assert await total(port="!5353", proto="udp") == 1
    assert await total(proto="icmp") == 1
    assert await total(ipver=6) == 3
    assert await total(hide_noise=True) == 6
    assert await total(rule="1770009104") == 2
    assert await total(q="pfB_Top") == 2
    assert await total(q="-pfB") == 5
    assert await total(range="24h") == 9
    assert (await client.get("/api/firewall/events", params={"src": "bogus"})).status_code == 400


async def test_pagination_cursor(client):
    seen = []
    cursor = None
    for _ in range(5):
        r = (await client.get("/api/firewall/events", params={"limit": 3, **({"cursor": cursor} if cursor else {})})).json()
        seen += [i["id"] for i in r["items"]]
        cursor = r["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 8 and len(set(seen)) == 8
    one = (await client.get(f"/api/firewall/events/{seen[0]}")).json()
    assert one["id"] == seen[0]


async def test_stats_and_timeline(client):
    s = (await client.get("/api/firewall/stats", params={"action": "block"})).json()
    assert s["actions"] == {"block": 6}
    assert any(x["ip"] == "120.226.93.27" and x["count"] == 1 and x["blocked"] == 1 for x in s["top_sources"])
    all_ = (await client.get("/api/firewall/stats")).json()
    assert sum(x["count"] for x in all_["top_blocked_sources"]) == 6
    assert {r["rule"] for r in s["top_rules"]} >= {"pfB_Top_v4 auto rule", "Block all IPv6"}
    assert any(p["port"] == 3896 and p["proto"] == "tcp" and p["count"] == 2 for p in s["top_ports"])
    assert {i["iface"] for i in s["interfaces"]} == {"INTERNET", "INFRASTRUCTURE"}

    t = (await client.get("/api/firewall/timeline")).json()
    assert t["source"] == "counters"
    assert sum(b["block"] for b in t["series"]) == 6 and sum(b["pass"] for b in t["series"]) == 2
    t2 = (await client.get("/api/firewall/timeline", params={"proto": "udp"})).json()
    assert t2["source"] == "events" and sum(b["block"] for b in t2["series"]) == 2

    f = (await client.get("/api/firewall/facets")).json()
    assert {i["iface"] for i in f["interfaces"]} == {"INTERNET", "HOME", "INFRASTRUCTURE"}
    assert f["ingest"]["parsed"] == 9
