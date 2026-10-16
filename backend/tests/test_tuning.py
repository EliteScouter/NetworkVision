"""UI settings, per-device threshold overrides, muting and maintenance windows."""

import time
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select

from app.collectors.base import Interface, Snapshot
from app.models import Alert, MaintenanceWindow, Setting
from app.services.runtime import window_span
from app.services.state import DeviceState


@pytest.fixture
async def rt(tmp_path, monkeypatch):
    monkeypatch.setenv("NV_SECRET_KEY", "test-secret-key-for-unit-tests-only-0123456789")
    monkeypatch.setenv("NV_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NV_ALERT_CPU_PCT", "85")
    from app import db as dbmod
    from app.config import get_settings
    from app.services.runtime import runtime

    get_settings.cache_clear()
    await dbmod.dispose()
    await dbmod.init_db()
    async with dbmod.sessionmaker()() as s:
        from app.models import Device

        s.add_all([Device(id=1, name="fw", kind="pfsense", role="firewall", host="192.0.2.1", config={}, tags=[], facts={}),
                   Device(id=2, name="ap", kind="unifi", role="ap", host="", parent_id=1, config={}, tags=[], facts={})])
        await s.commit()
    runtime.__init__()
    await runtime.load()
    yield runtime
    runtime.__init__()
    await dbmod.dispose()
    get_settings.cache_clear()


def _dev(cpu: float = 0, dev_id: int = 1, parent_id: int | None = None, **ifs: bool) -> DeviceState:
    st = DeviceState(id=dev_id, name=f"dev{dev_id}", kind="x", role="switch", host="x", parent_id=parent_id)
    st.apply(Snapshot(metrics={"cpu": cpu}, interfaces=[Interface(name=n, oper_up=True) for n in ifs]))
    st.apply(Snapshot(metrics={"cpu": cpu}, interfaces=[Interface(name=n, oper_up=up) for n, up in ifs.items()]))
    return st


def _rules(st: DeviceState, now: float | None = None) -> set[str]:
    from app.services.alerts import evaluate

    return {c.rule for c in evaluate(st, now)}


# ------------------------------------------------------------- precedence
async def test_precedence_default_env_ui(rt):
    assert rt.get("alert_mem_pct") == 92 and rt.source("alert_mem_pct") == "default"
    assert rt.get("alert_cpu_pct") == 85 and rt.source("alert_cpu_pct") == "env"
    await rt.update({"alert_cpu_pct": 50})
    assert rt.get("alert_cpu_pct") == 50 and rt.source("alert_cpu_pct") == "ui"
    await rt.load()  # survives a restart
    assert rt.get("alert_cpu_pct") == 50
    await rt.update({"alert_cpu_pct": None})  # reset -> env again
    assert rt.get("alert_cpu_pct") == 85


async def test_validation_uses_env_constraints(rt):
    with pytest.raises(ValueError):
        await rt.update({"retention_days_rollup": 3})  # ge=7
    with pytest.raises(ValueError):
        await rt.update({"notify_min_severity": "loud"})
    with pytest.raises(ValueError):
        await rt.update({"notify_slack_webhook_url": "file:///etc/passwd"})
    with pytest.raises(ValueError):
        await rt.update({"secret_key": "nope"})


async def test_secrets_encrypted_and_masked(rt):
    from app import db as dbmod
    from app.security import SECRET_MASK

    url = "https://discord.example/api/webhooks/123/very-secret"
    await rt.update({"notify_discord_webhook_url": url})
    async with dbmod.sessionmaker()() as s:
        rows = (await s.execute(select(Setting))).scalars().all()
    assert rows and all("very-secret" not in r.value for r in rows)
    pub = rt.public()["fields"]["notify_discord_webhook_url"]
    assert pub["value"] == SECRET_MASK and pub["source"] == "ui" and "very-secret" not in str(rt.public())
    await rt.update({"notify_discord_webhook_url": SECRET_MASK, "alert_cpu_pct": 70})  # mask = keep
    await rt.load()
    assert rt.get("notify_discord_webhook_url") == url


# ------------------------------------------------------------- thresholds
async def test_global_and_per_device_threshold_overrides(rt):
    assert "high_cpu" not in _rules(_dev(cpu=60))
    await rt.update({"alert_cpu_pct": 50})
    assert "high_cpu" in _rules(_dev(cpu=60))
    await rt.set_tuning(1, {"thresholds": {"cpu": 95}})
    assert "high_cpu" not in _rules(_dev(cpu=60))
    assert "high_cpu" in _rules(_dev(cpu=60, dev_id=3))  # other devices keep the global value
    await rt.load()
    assert rt.threshold("alert_cpu_pct", 1) == 95


# ------------------------------------------------------------- muting
async def test_rule_device_and_interface_muting(rt):
    st = _dev(cpu=99, eth0=False, eth1=False)
    assert {"high_cpu", "port_down"} <= _rules(st)
    await rt.set_tuning(1, {"muted_interfaces": ["eth0"]})
    from app.services.alerts import evaluate

    downs = [c.subject for c in evaluate(st) if c.rule == "port_down"]
    assert downs == ["eth1"]
    await rt.set_tuning(1, {"disabled_rules": ["port_down"]})
    assert "port_down" not in _rules(st) and "high_cpu" in _rules(st)
    await rt.update({}, disabled_rules=["high_cpu"])
    assert "high_cpu" not in _rules(st) and "port_down" in _rules(_dev(cpu=99, dev_id=3, eth0=False))
    await rt.set_tuning(1, {"muted": True})
    assert _rules(st) == set()
    await rt.set_tuning(1, {})  # clearing removes the tuning entirely
    assert 1 not in rt.tuning


# ------------------------------------------------------------- maintenance
async def test_maintenance_suppresses_but_records(rt, monkeypatch):
    from app.services import alerts as alerts_mod

    fired: list[dict] = []
    monkeypatch.setattr(alerts_mod.notifier, "fire", lambda a, resolved=False: fired.append(a))
    await rt.update({"alert_consecutive": 1})
    now = time.time()
    w = await rt.add_window(MaintenanceWindow(name="upgrade", device_id=1, kind="once", starts_at=now - 60, ends_at=now + 600))

    eng = alerts_mod.AlertEngine()
    st = _dev(cpu=99)
    await eng.process(st)
    a = eng.open[f"cpu:{st.id}"]
    assert a.suppressed and fired == []
    assert st.health == "ok"  # suppressed alerts don't colour the device
    child = _dev(cpu=99, dev_id=2, parent_id=1)
    assert all(c.suppressed for c in alerts_mod.evaluate(child))  # window covers children

    from app import db as dbmod

    async with dbmod.sessionmaker()() as s:
        row = (await s.execute(select(Alert).where(Alert.key == a.key))).scalar_one()
    assert row.suppressed

    await rt.delete_window(w.id)
    await eng.process(st)  # still broken after maintenance -> becomes a real alert
    assert not eng.open[a.key].suppressed and [x["key"] for x in fired] == [a.key]


async def test_global_window_and_events(rt, monkeypatch):
    from app.services import alerts as alerts_mod

    fired: list[dict] = []
    monkeypatch.setattr(alerts_mod.notifier, "fire", lambda a, resolved=False: fired.append(a))
    now = time.time()
    await rt.add_window(MaintenanceWindow(kind="once", starts_at=now - 1, ends_at=now + 60))
    eng = alerts_mod.AlertEngine()
    await eng.raise_event(None, "speedtest:slow", "slow", "x", severity="warning", rule="speedtest_slow")
    assert eng.open["speedtest:slow"].suppressed and fired == []
    await rt.update({}, disabled_rules=["log_event"])
    await eng.raise_event(1, "log:1:abc", "crit", "x")
    assert "log:1:abc" not in eng.open


def test_recurring_window_spans_midnight_and_weekdays():
    tz = "Europe/Berlin"
    z = ZoneInfo(tz)
    w = MaintenanceWindow(kind="weekly", start_time="23:30", duration_min=60, weekdays=[0], tz=tz, enabled=True)  # Mondays
    mon_2340 = datetime(2026, 10, 12, 23, 40, tzinfo=z).timestamp()  # 2026-10-12 is a Monday
    tue_0020 = datetime(2026, 10, 13, 0, 20, tzinfo=z).timestamp()
    tue_0040 = datetime(2026, 10, 13, 0, 40, tzinfo=z).timestamp()
    tue_2340 = datetime(2026, 10, 13, 23, 40, tzinfo=z).timestamp()
    assert window_span(w, mon_2340) and window_span(w, tue_0020)
    assert window_span(w, tue_0040) is None and window_span(w, tue_2340) is None
    d = MaintenanceWindow(kind="daily", start_time="02:00", duration_min=30, weekdays=[], tz=tz, enabled=True)
    assert window_span(d, datetime(2026, 10, 14, 2, 10, tzinfo=z).timestamp())
    assert window_span(d, datetime(2026, 10, 14, 2, 31, tzinfo=z).timestamp()) is None
