"""History rollups, client inventory, WiFi normalization and the speed test engine."""

import math
import time

import httpx
import pytest
from sqlalchemy import insert, select

from app.collectors.base import norm_mac
from app.collectors.unifi import build_wifi
from app.services.clients import classify, from_lease, from_unifi, wifi_standard
from app.services.speedtest import CloudflareEngine, rtt_from_server_timing


@pytest.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setenv("NV_SECRET_KEY", "test-secret-key-for-unit-tests-only-0123456789")
    monkeypatch.setenv("NV_DATA_DIR", str(tmp_path))
    from app import db as dbmod
    from app.config import get_settings

    get_settings.cache_clear()
    await dbmod.dispose()
    await dbmod.init_db()
    async with dbmod.sessionmaker()() as s:
        from app.models import Device

        s.add(Device(id=1, name="fw", kind="pfsense", role="firewall", host="192.0.2.1", config={}, tags=[], facts={}))
        await s.commit()
    yield dbmod
    await dbmod.dispose()
    get_settings.cache_clear()


# ------------------------------------------------------------------ history
async def test_rollup_and_long_range_query(db):
    from app.models import InterfaceMetric, InterfaceMetricHourly
    from app.services import history

    hour = math.floor(time.time() / 3600) * 3600 - 5 * 3600  # five complete hours ago
    rows = [{"ts": hour + m * 60, "device_id": 1, "ifname": "WAN", "rx_bps": 100.0 + (m % 60), "tx_bps": 10.0,
             "errors_per_min": 0, "util_pct": 1.0} for m in range(4 * 60)]
    async with db.sessionmaker()() as s:
        await s.execute(insert(InterfaceMetric), rows)
        await s.commit()

    assert await history.rollup_kind("interface") >= 4
    assert await history.rollup_kind("interface") == 0  # idempotent: nothing new to roll up
    async with db.sessionmaker()() as s:
        hourly = (await s.execute(select(InterfaceMetricHourly).order_by(InterfaceMetricHourly.ts))).scalars().all()
    first = next(h for h in hourly if h.ts == hour)
    assert first.samples == 60 and first.rx_bps_max == 159.0 and first.rx_bps_avg == pytest.approx(129.5)

    start, end = history.resolve_range("7d", None, None)
    res = await history.query("interface", {"device_id": 1, "ifname": "WAN"}, start, end, 200)
    assert res["resolution"] == "hourly" and res["points"]
    assert res["stats"]["rx_bps"]["max"] == pytest.approx(129.5)  # averages of hours (peaks come separately)
    assert max(p[1] for p in res["peaks"] if p[1] is not None) == 159.0

    raw = await history.query("interface", {"device_id": 1, "ifname": "WAN"}, hour, hour + 3600, 100)
    assert raw["resolution"] == "raw" and raw["stats"]["rx_bps"]["max"] == 159.0


async def test_history_requires_filters(db):
    from app.services import history

    with pytest.raises(ValueError, match="device_id"):
        await history.query("device", {}, 0, 10)
    with pytest.raises(ValueError):
        history.resolve_range(None, 100, 50)


# ------------------------------------------------------------------ clients
def test_classify_devices():
    assert classify("Living-Room-TV", None, "LG Electronics") == "tv"
    assert classify(None, "esp-plug-01", "Espressif Inc.") == "iot"
    assert classify("iPhone-15", None, "Apple, Inc.") == "phone"
    assert classify(None, "proxmox-01", "Dell") == "server"
    assert classify(None, None, None) == "unknown"
    assert wifi_standard("ax", "6") == "Wi-Fi 6E" and wifi_standard("be", "5") == "Wi-Fi 7"


def test_unifi_client_normalization_directions():
    c = from_unifi({"mac": "AA:BB:CC:00:00:01", "is_wired": False, "radio": "na", "radio_proto": "ax", "signal": -60,
                    "noise": -95, "tx_bytes-r": 1000, "rx_bytes-r": 100, "tx_rate": 866000, "essid": "Home"}, True, {})
    assert c["mac"] == "aa:bb:cc:00:00:01" and c["band"] == "5" and c["standard"] == "Wi-Fi 6"
    assert c["down_bps"] == 8000 and c["up_bps"] == 800  # AP transmit = client download
    assert c["snr"] == 35 and c["tx_rate_mbps"] == 866


def test_merge_prefers_unifi_and_ignores_stale_lease():
    from app.services.clients import ClientTracker
    from app.services.state import DeviceState, store

    store.devices.clear()
    unifi = DeviceState(id=1, name="ck", kind="unifi", role="controller", host="x")
    fw = DeviceState(id=2, name="fw", kind="pfsense", role="firewall", host="y")
    unifi.clients = [from_unifi({"mac": "aa:bb:cc:00:00:02", "hostname": "laptop", "last_seen": 1}, False, {})]
    fw.clients = [from_lease("aa:bb:cc:00:00:02", "192.0.2.50", "laptop-dhcp", "active", "LAN")]
    store.devices.update({1: unifi, 2: fw})
    merged = ClientTracker().merged()
    store.devices.clear()
    assert len(merged) == 1
    c = merged[0]
    assert c["online"] is False  # UniFi says offline; an unexpired lease doesn't make it online
    assert c["ip"] == "192.0.2.50" and c["hostname"] == "laptop" and set(c["sources"]) == {"unifi", "dhcp"}


# --------------------------------------------------------------------- wifi
def test_build_wifi_interference_and_ssids():
    devices = [{"type": "uap", "mac": "aa:aa:aa:aa:aa:01", "name": "AP", "state": 1,
                "radio_table": [{"name": "wifi0", "radio": "ng", "is_11ax": True}],
                "radio_table_stats": [{"name": "wifi0", "radio": "ng", "channel": 6, "bw": 20, "cu_total": 68,
                                       "cu_self_rx": 10, "cu_self_tx": 8, "num_sta": 29}],
                "vap_table": [{"essid": "Home", "radio": "ng", "num_sta": 29, "satisfaction": 80, "wlanconf_id": "w1"}]}]
    wlans = [{"_id": "w1", "name": "Home", "security": "wpapsk", "networkconf_id": "n1", "wlan_bands": ["2g", "5g"]}]
    neighbors = [{"bssid": "11:22:33:44:55:66", "essid": "NETGEAR", "band": "ng", "channel": 6, "signal": -70}]
    w = build_wifi(devices, wlans, neighbors, [], {"n1": "LAN"})
    r = w["aps"][0]["radios"][0]
    assert r["band"] == "2.4" and r["interference"] == 50 and r["standard"] == "Wi-Fi 6"
    assert w["ssids"][0]["clients"] == 29 and w["ssids"][0]["network"] == "LAN"
    assert w["neighbors"][0]["band"] == "2.4"


# ---------------------------------------------------------------- speedtest
def test_rtt_parsing():
    hdr = 'cfSpeedEdge;dur=6, cfSpeedWorker;dur=68, cfL4;desc="?proto=TCP&rtt=2596&min_rtt=2415"'
    assert rtt_from_server_timing(hdr, 106.8) == pytest.approx(2.596)
    assert rtt_from_server_timing("cfSpeedEdge;dur=6, cfSpeedWorker;dur=40", 50.0) == pytest.approx(4.0)
    assert rtt_from_server_timing("", 12.0) == 12.0


async def test_cloudflare_engine_against_fake_server():
    chunk = b"x" * 65536

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/meta":
            return httpx.Response(200, json={"colo": {"iata": "PDX", "city": "Portland"}, "asOrganization": "Test ISP", "clientIp": "192.0.2.9"})
        if req.url.path == "/__down":
            n = int(req.url.params.get("bytes", "0"))
            return httpx.Response(200, content=chunk * max(0, min(n, 2_000_000) // len(chunk)),
                                  headers={"server-timing": 'cfL4;desc="?rtt=3000"'})
        if req.url.path == "/__up":
            return httpx.Response(200, headers={"server-timing": 'cfL4;desc="?rtt=3000"'})
        return httpx.Response(404)

    progress: list[dict] = []
    res = await CloudflareEngine(httpx.MockTransport(handler)).run({"streams": 2, "duration_s": 1}, progress.append)
    assert res["server"] == "PDX Portland" and res["isp"] == "Test ISP"
    assert res["latency_ms"] == pytest.approx(3.0) and res["jitter_ms"] == pytest.approx(0.0)
    assert res["download_bps"] > 0 and res["upload_bps"] > 0 and res["bytes_used"] > 0
    assert {"latency", "download", "upload"} <= {p["phase"] for p in progress}


async def test_speedtest_slow_alert(db, monkeypatch):
    from app.services.alerts import engine
    from app.services.speedtest import SpeedtestService

    class Slow:
        name = "fake"

        async def run(self, cfg, progress):
            return {"download_bps": 100e6, "upload_bps": 900e6, "latency_ms": 5.0}

    svc = SpeedtestService()
    svc.engine = Slow()
    await svc.update_settings({"expected_down_mbps": 1000, "expected_up_mbps": 1000, "alert_pct": 70})
    result = await svc.run("manual")
    assert result["download_bps"] == 100e6 and not result["error"]
    alert = engine.open.get("speedtest:slow")
    assert alert is not None and "download 100 Mbps" in alert.detail and "upload" not in alert.detail
    engine.open.clear()
    assert norm_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_downsample_breaks_lines_across_gaps():
    from app.services.history import _downsample

    rows = [[t, 1.0] for t in range(0, 600, 60)] + [[t, 2.0] for t in range(20000, 20600, 60)]
    out = _downsample(rows, 0, 21000, 1, 300)
    assert any(p[1] is None for p in out)  # a gap marker between the two runs
    assert out[0][1] == 1.0 and out[-1][1] == 2.0


async def test_migrate_db_tool_copies_and_refuses_overwrite(db, tmp_path):
    from app.tools.migrate_db import main as migrate

    src = tmp_path / "networkvision.db"  # the fixture's database (has one device)
    dst = tmp_path / "copy.db"
    assert migrate(["--source", f"sqlite:///{src}", "--target", f"sqlite:///{dst}"]) == 0
    assert migrate(["--source", f"sqlite:///{src}", "--target", f"sqlite:///{dst}"]) == 2  # target not empty


def test_topology_matches_real_homelab_layout():
    """VLAN interface names aren't cables; MAC learning links pfSense; only public-gateway firewalls face the internet."""
    from app.collectors.base import Gateway, Interface, Snapshot
    from app.services import topology
    from app.services.clients import from_unifi
    from app.services.state import DeviceState, store

    store.devices.clear()
    pf = DeviceState(id=1, name="PFSense", kind="pfsense", role="firewall", host="10.10.20.1")
    pf.apply(Snapshot(interfaces=[Interface("INTERNET", alias="ix1.2", mac="aa:aa:aa:00:00:02", extra={"gateway": "50.53.0.1"}),
                                  Interface("INFRASTRUCTURE", alias="ix0.20", mac="aa:aa:aa:00:00:01")],
                      gateways=[Gateway("INTERNET_DHCP", "50.53.0.1", True)]))
    opn = DeviceState(id=2, name="OPN-Sense", kind="opnsense", role="firewall", host="10.0.200.254")
    opn.apply(Snapshot(interfaces=[Interface("WAN", alias="vtnet0")], gateways=[Gateway("WAN_DHCP", "~", True)]))
    pc = DeviceState(id=3, name="HP-ProCurve-NET", kind="snmp", role="switch", host="10.10.20.4")
    pc.apply(Snapshot(interfaces=[Interface("VLAN200", alias="OPNSENSE", media="virtual"), Interface("B2", media="copper")]))
    xg = DeviceState(id=4, name="US XG 16", kind="unifi", role="switch", host="10.10.20.3", parent_id=9)
    xg.facts["mac"] = "78:8a:20:f9:1e:93"
    ctl = DeviceState(id=9, name="EliteUNIFI", kind="unifi", role="controller", host="10.10.20.2")
    ctl.clients = [from_unifi({"mac": "aa:aa:aa:00:00:01", "is_wired": True, "sw_mac": "78:8a:20:f9:1e:93", "sw_port": 9}, True, {})]
    store.devices.update({1: pf, 2: opn, 3: pc, 4: xg, 9: ctl})
    try:
        t = topology.build([], {})
        pairs = {(e["source"], e["target"], e["kind"]): e for e in t["edges"]}
        names = {n["id"]: n["name"] for n in t["nodes"]}
        flat = {tuple(sorted((names[e["source"]], names[e["target"]]))): e for e in t["edges"]}
        assert ("HP-ProCurve-NET", "OPN-Sense") not in flat  # VLAN200 "OPNSENSE" is not a cable
        learned = flat[("PFSense", "US XG 16")]
        assert learned["kind"] == "learned" and "Port 9" in (learned["source_port"], learned["target_port"])
        assert ("Internet", "PFSense") in flat and ("Internet", "OPN-Sense") not in flat
        assert topology.internet_edge_ids(list(store.devices.values())) == {1}
        assert pairs  # built something
    finally:
        store.devices.clear()
