import os
import time

import pytest

os.environ.setdefault("NV_SECRET_KEY", "test-secret-key-for-unit-tests-only-0123456789")

from app.collectors.base import Interface, Snapshot  # noqa: E402
from app.security import decrypt_secrets, encrypt_secrets, mask_secrets, resolve_secret  # noqa: E402
from app.services.alerts import evaluate  # noqa: E402
from app.services.state import DeviceState, _rate  # noqa: E402
from app.syslog_parser import parse_syslog  # noqa: E402


# ------------------------------------------------------------------ syslog
def test_rfc3164_with_host_and_pid():
    p = parse_syslog("<34>Oct 11 22:14:15 pf-edge sshd[123]: Failed password for root", "10.0.0.1")
    assert p.severity == 2 and p.facility == "auth"
    assert p.host == "pf-edge" and p.app == "sshd"
    assert p.message == "Failed password for root"


def test_rfc5424():
    p = parse_syslog("<165>1 2026-10-14T22:30:02.003Z sw1 ports - ID47 - port 17 CRC errors", "10.0.0.11")
    assert p.severity == 5 and p.host == "sw1" and p.app == "ports"
    assert p.message == "port 17 CRC errors"


def test_no_pri_no_timestamp_tag_only():
    p = parse_syslog("filterlog: 5,,,1000,igb0,match,block,in", "10.0.0.1")
    assert p.app == "filterlog" and p.host == "10.0.0.1"
    assert p.severity == 4  # guessed from "block"


def test_wild_timestamp_is_replaced():
    now = time.time()
    p = parse_syslog("<14>1 1999-01-01T00:00:00Z h a - - - hello", "1.2.3.4", received=now)
    assert p.ts == now


# ------------------------------------------------------------------- rates
def test_rate_basic_and_wrap():
    assert _rate(1000, 2000, 1.0, 64, 8) == 8000
    assert _rate(2**32 - 100, 100, 1.0, 32, 1) == 200  # 32-bit wrap
    assert _rate(5000, 100, 1.0, 64, 8) is None  # 64-bit reset -> skip


def test_device_state_computes_bps_and_util():
    st = DeviceState(id=1, name="sw", kind="snmp", role="switch", host="x")
    t0 = 1000.0
    st.apply(Snapshot(interfaces=[Interface("p1", oper_up=True, speed_mbps=1000, in_octets=0, out_octets=0)]), now=t0)
    st.apply(Snapshot(interfaces=[Interface("p1", oper_up=True, speed_mbps=1000, in_octets=125_000_000,
                                            out_octets=0)]), now=t0 + 10)
    i = st.interfaces["p1"]
    assert i.rx_bps == pytest.approx(100e6)
    assert i.util_pct == pytest.approx(10.0)


def test_flaps_counted():
    st = DeviceState(id=1, name="sw", kind="snmp", role="switch", host="x")
    for n in range(6):
        st.apply(Snapshot(interfaces=[Interface("p3", oper_up=bool(n % 2))]))
    assert st.interfaces["p3"].flaps() == 5


# ---------------------------------------------------------------- security
def test_secret_roundtrip_and_mask():
    blob = encrypt_secrets({"api_key": "abc", "community": "env:SNMP", "empty": ""})
    assert "abc" not in blob
    data = decrypt_secrets(blob)
    assert data == {"api_key": "abc", "community": "env:SNMP"}
    masked = mask_secrets(data)
    assert masked["api_key"] != "abc" and masked["community"] == "env:SNMP"


def test_env_reference_blocks_own_secrets(monkeypatch):
    monkeypatch.setenv("MY_KEY", "v1")
    assert resolve_secret("env:MY_KEY") == "v1"
    assert resolve_secret("env:NV_SECRET_KEY") == ""
    assert resolve_secret("plain") == "plain"


def test_decrypt_garbage_fails_closed():
    assert decrypt_secrets("not-a-token") == {}


# ------------------------------------------------------------------ alerts
def test_alert_rules():
    st = DeviceState(id=7, name="fw", kind="x", role="firewall", host="x")
    st.apply(Snapshot(metrics={"cpu": 99, "mem": 10}))
    keys = {c.rule for c in evaluate(st)}
    assert "high_cpu" in keys and "high_mem" not in keys
    st.mark_down("boom")
    conds = evaluate(st)
    assert [c.rule for c in conds] == ["device_down"]


# --------------------------------------------------------------- WAN detection
def _fw(*ifaces: Interface) -> DeviceState:
    st = DeviceState(id=9, name="fw", kind="pfsense", role="firewall", host="x")
    st.apply(Snapshot(interfaces=list(ifaces)))
    return st


def test_wan_detected_by_renamed_interface():
    st = _fw(Interface("INTERNET"), Interface("INFRASTRUCTURE"), Interface("DMZ"), Interface("PUBLIC"))
    assert [i.name for i in st.wan_interfaces()] == ["INTERNET"]


def test_wan_prefers_interfaces_with_a_gateway():
    st = _fw(Interface("ISP_BACKUP"), Interface("PRIMARY", extra={"gateway": "203.0.113.1"}), Interface("LAN"))
    assert [i.name for i in st.wan_interfaces()] == ["PRIMARY"]


def test_wan_explicit_override_wins():
    st = _fw(Interface("WAN"), Interface("OPT7"))
    st.wan_override = ["opt7"]
    assert [i.name for i in st.wan_interfaces()] == ["OPT7"]


def test_wan_name_matching_avoids_lookalikes():
    st = _fw(Interface("filter_vlan"), Interface("DISPLAY"), Interface("HOME"))
    assert st.wan_interfaces() == []


def test_no_single_precision_columns_on_mysql():
    """MySQL FLOAT is single precision and rounds epoch timestamps to ~128 s (v0.3.0 bug)."""
    from sqlalchemy.dialects import mysql
    from sqlalchemy.schema import CreateTable

    from app import models  # noqa: F401
    from app.db import Base

    for table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=mysql.dialect()))
        assert " FLOAT" not in ddl.upper(), f"{table.name} has a single-precision FLOAT column"


def test_syslog_timezone_skew_is_learned_and_corrected(monkeypatch):
    """pfSense's default RFC 3164 stamps local time with no zone (e.g. UTC-7 vs a UTC container)."""
    import app.services.syslog as sl
    from app.syslog_parser import ClockSkew

    monkeypatch.setattr(sl, "skew", ClockSkew())
    got: list[dict] = []
    monkeypatch.setattr(sl.pipeline, "submit", got.append)
    monkeypatch.setattr(sl.pipeline, "device_for", lambda *a: 1)
    behind = 7 * 3600
    for _ in range(3):
        stamp = time.strftime("%b %d %H:%M:%S", time.localtime(time.time() - behind))
        sl._ingest(f"<134>{stamp} pfsense filterlog[123]: 5,,,1000,ix1.2,match,block,in,4".encode(), "10.10.20.1")
    assert sl.skew.offset(1) == behind
    assert all(abs(e["ts"] - time.time()) < 5 for e in got)  # corrected to "now", not 7 h ago
    # One odd late packet can't flip the learned offset.
    sl.skew.observe(1, time.time() - 600, time.time())
    assert sl.skew.offset(1) == behind
    # RFC 5424 timestamps carry their zone and are never shifted.
    iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    sl._ingest(f"<134>1 {iso} pfsense filterlog 123 - - 5,,,1000".encode(), "10.10.20.1")
    assert abs(got[-1]["ts"] - time.time()) < 5
