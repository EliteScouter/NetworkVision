"""Service (uptime) monitoring: validation, the four check types, TLS parsing, state machine and uptime math."""

import asyncio
import datetime as dt
import ipaddress
import math
import ssl
import time

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import insert, select

from app.services import uptime
from app.services.uptime import CertInfo, CheckResult, normalize, parse_status_ranges, san_matches


def svc(kind="http", target="https://app.example.com/health", port=None, **cfg):
    t, p, c = normalize(kind, target, port, cfg)
    return {"id": 1, "name": "app", "kind": kind, "target": t, "port": p, "enabled": True, "interval_s": 60,
            "timeout_s": 5.0, "config": {**uptime.DEFAULTS, **c}, "tags": [], "notes": ""}


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("target", [
    "file:///etc/passwd", "ftp://example.com/", "javascript:alert(1)", "gopher://x", "example.com",
    "https://user:pw@example.com/", "https:///nohost", "https://exa mple.com/", "https://example.com:99999/",
])
def test_http_target_rejected(target):
    with pytest.raises(ValueError):
        normalize("http", target, None, {})


@pytest.mark.parametrize("kind,target,port", [
    ("tcp", "http://example.com", 443), ("tcp", "example.com/path", 22), ("tcp", "a@b", 22),
    ("tcp", "example.com", None), ("tcp", "example.com", 70000), ("dns", "192.0.2.1", None),
    ("tls", "-bad-.example.com", 443), ("smtp", "example.com", 25),
])
def test_other_targets_rejected(kind, target, port):
    with pytest.raises(ValueError):
        normalize(kind, target, port, {})


def test_normalize_cleans_config():
    t, p, c = normalize("http", "https://Example.com:8443/x", None, {"expected_status": "200-299, 301", "junk": 1})
    assert p == 8443 and c["expected_status"] == "200-299,301" and "junk" not in c
    assert normalize("tls", "mail.example.com", None, {})[1] == 443  # TLS defaults to 443
    _, _, d = normalize("dns", "home.example.com", 53, {"expected": "203.0.113.5, 2001:db8::1"})
    assert d["expected"] == ["2001:db8::1", "203.0.113.5"]
    assert normalize("tcp", "[2001:db8::1]", 22, {})[0] == "2001:db8::1"
    for bad in ({"expected_status": "abc"}, {"method": "POST"}, {"method": "HEAD", "keyword": "x"},
                {"cert_warn_days": 7, "cert_crit_days": 7}, {"fail_threshold": 0}, {"slow_ms": "fast"}):
        with pytest.raises(ValueError):
            normalize("http", "https://example.com", None, bad)
    with pytest.raises(ValueError):
        normalize("dns", "example.com", None, {"expected": ["not-an-ip"]})


def test_status_ranges():
    assert parse_status_ranges("200-299,301,4xx") == [(200, 299), (301, 301), (400, 499)]
    for bad in ("", "99", "300-200", "6xx", "2xx-3xx"):
        with pytest.raises(ValueError):
            parse_status_ranges(bad)


def test_san_matching():
    sans = ["example.com", "*.apps.example.com", "192.0.2.10"]
    assert san_matches("EXAMPLE.com.", sans)
    assert san_matches("cloud.apps.example.com", sans)
    assert not san_matches("apps.example.com", sans)  # wildcard needs a label
    assert not san_matches("a.b.apps.example.com", sans)  # ...and only one
    assert not san_matches("evil-example.com", sans)
    assert san_matches("192.0.2.10", sans) and not san_matches("192.0.2.11", sans)
    assert not san_matches("x.com", ["*.com"])  # no wildcard on a bare TLD


# ------------------------------------------------------------------ HTTP
def _transport(handler):
    return httpx.MockTransport(handler)


async def test_http_ok_with_keyword_and_redirect():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/old":
            return httpx.Response(301, headers={"Location": "https://app.example.com/health"})
        assert req.headers["user-agent"].startswith("NetworkVision-uptime/")
        return httpx.Response(200, text="<html>Status: ALL GOOD</html>")

    r = await uptime.check_http(svc(target="https://app.example.com/old", keyword="all good"), _transport(handler))
    assert r.ok and r.response_ms is not None and r.detail["status_code"] == 200 and r.detail["redirects"] == 1

    no_follow = svc(target="https://app.example.com/old", follow_redirects=False)
    r = await uptime.check_http(no_follow, _transport(handler))
    assert r.ok and r.detail["status_code"] == 301  # 3xx is inside the default 200-399

    strict = svc(target="https://app.example.com/old", follow_redirects=False, expected_status="200")
    r = await uptime.check_http(strict, _transport(handler))
    assert not r.ok and r.error.startswith("HTTP 301")


async def test_http_failures():
    r = await uptime.check_http(svc(), _transport(lambda req: httpx.Response(503, text="maintenance")))
    assert not r.ok and r.error == "HTTP 503 (expected 200-399)"

    r = await uptime.check_http(svc(keyword="Welcome"), _transport(lambda req: httpx.Response(200, text="Error page")))
    assert not r.ok and "keyword 'Welcome' not found" in r.error

    def boom(req):
        raise httpx.ConnectTimeout("timed out", request=req)

    r = await uptime.check_http(svc(), _transport(boom))
    assert not r.ok and r.error == "timed out after 5s"

    def refused(req):
        raise httpx.ConnectError("[Errno 111] Connection refused", request=req)

    r = await uptime.check_http(svc(), _transport(refused))
    assert not r.ok and "refused" in r.error


async def test_http_head_and_custom_status():
    seen = {}

    def handler(req):
        seen["method"] = req.method
        return httpx.Response(401)

    r = await uptime.check_http(svc(method="HEAD", expected_status="2xx,401"), _transport(handler))
    assert r.ok and seen["method"] == "HEAD"


# ------------------------------------------------------------------ TCP / DNS
async def test_tcp_check():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        r = await uptime.check_tcp(svc("tcp", "127.0.0.1", port))
        assert r.ok and r.response_ms is not None
    finally:
        server.close()
        await server.wait_closed()
    r = await uptime.check_tcp(svc("tcp", "127.0.0.1", port))
    assert not r.ok and r.error


async def test_dns_check(monkeypatch):
    answers = {"home.example.com": ["203.0.113.5"]}

    async def fake_resolve(host, family):
        if host not in answers:
            import socket

            raise socket.gaierror(-2, "Name or service not known")
        return answers[host]

    monkeypatch.setattr(uptime, "resolve", fake_resolve)
    r = await uptime.check_dns(svc("dns", "home.example.com", expected=["203.0.113.5"]))
    assert r.ok and r.detail["addresses"] == ["203.0.113.5"]
    answers["home.example.com"] = ["203.0.113.5", "198.51.100.66"]  # hijacked / drifted record
    r = await uptime.check_dns(svc("dns", "home.example.com", expected=["203.0.113.5"]))
    assert not r.ok and "198.51.100.66" in r.error
    r = await uptime.check_dns(svc("dns", "gone.example.com"))
    assert not r.ok and r.error.startswith("DNS lookup failed")


# ------------------------------------------------------------------ TLS
def _make_cert(tmp_path, names, days=30):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0]),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NV Test CA")])
    now = dt.datetime.now(dt.UTC)
    alt = [x509.IPAddress(ipaddress.ip_address(n)) if n[0].isdigit() else x509.DNSName(n) for n in names]
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_pem, key_pem = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return cert, cert_pem, key_pem


def test_parse_cert(tmp_path):
    cert, _, _ = _make_cert(tmp_path, ["vault.example.com", "*.apps.example.com"], days=10)
    der = cert.public_bytes(serialization.Encoding.DER)
    info = uptime.parse_cert(der, "vault.example.com")
    assert info.valid and info.san_match and 9.5 < info.days_left <= 10 and info.issuer == "NV Test CA"
    assert info.sans == ["vault.example.com", "*.apps.example.com"]
    wrong = uptime.parse_cert(der, "mail.example.com")
    assert not wrong.valid and "does not cover" in wrong.error
    expired = uptime.parse_cert(der, "vault.example.com", now=time.time() + 11 * 86400)
    assert not expired.valid and expired.error == "certificate has expired" and expired.days_left < 0


async def test_tls_probe_real_handshake(tmp_path):
    _, cert_pem, key_pem = _make_cert(tmp_path, ["localhost", "127.0.0.1"], days=40)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert_pem, key_pem)

    async def handle(reader, writer):
        with __import__("contextlib").suppress(Exception):
            await reader.read(1)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=sctx)
    port = server.sockets[0].getsockname()[1]
    try:
        # Self-signed: reachable, details readable, but not trusted.
        info = await uptime.tls_probe("127.0.0.1", port, "localhost", 5)
        assert not info.valid and info.san_match and 39 < info.days_left <= 40 and info.error
        # Trusting our CA makes it valid.
        trusted = ssl.create_default_context(cafile=str(cert_pem))
        ok = await uptime.tls_probe("127.0.0.1", port, "localhost", 5, ca_context=trusted)
        assert ok.valid and ok.error == ""
        # The check type: reachable -> up, carrying the cert for alerting.
        r = await uptime.check_tls(svc("tls", "127.0.0.1", port, sni="localhost"))
        assert r.ok and r.cert is not None and not r.cert.valid
    finally:
        server.close()
        await server.wait_closed()
    r = await uptime.check_tls(svc("tls", "127.0.0.1", port))
    assert not r.ok


# ------------------------------------------------------------------ monitor
@pytest.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setenv("NV_SECRET_KEY", "test-secret-key-for-unit-tests-only-0123456789")
    monkeypatch.setenv("NV_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("NV_DEMO_MODE", raising=False)
    from app import db as dbmod
    from app.config import get_settings

    get_settings.cache_clear()
    await dbmod.dispose()
    await dbmod.init_db()
    yield dbmod
    await dbmod.dispose()
    get_settings.cache_clear()


@pytest.fixture
async def mon(db, monkeypatch):
    from app.models import Service
    from app.services.alerts import AlertEngine

    async with db.sessionmaker()() as s:
        s.add(Service(id=1, name="Nextcloud", kind="http", target="https://cloud.example.com/", config={"fail_threshold": 3,
                      "slow_ms": 500}, tags=[]))
        await s.commit()
    engine = AlertEngine()
    monkeypatch.setattr(uptime, "alert_engine", engine)
    m = uptime.UptimeMonitor()
    await m.load()
    results: list[CheckResult] = []

    async def fake_execute(svc_):
        return results.pop(0)

    monkeypatch.setattr(m, "execute", fake_execute)
    m.results, m.engine = results, engine  # type: ignore[attr-defined]
    m.services[1]["config"]["check_cert"] = False
    return m


async def test_down_after_consecutive_failures_then_recover(mon, db):
    from app.models import ServiceCheck, ServiceIncident

    fail = CheckResult(False, error="HTTP 502 (expected 200-399)")
    mon.results.extend([CheckResult(True, 120), fail, fail])
    for _ in range(3):
        await mon.check(1)
    st = mon.state[1]
    assert st.status == "degraded" and st.incident_id is None and not mon.engine.open  # not confirmed yet

    mon.results.append(fail)
    snap = await mon.check(1)
    assert snap["state"]["status"] == "down" and st.incident_id is not None
    alert = mon.engine.open["svc:1:down"]
    assert alert.rule == "service_down" and alert.severity == "critical" and alert.device_id is None
    first_fail = st.first_fail_ts

    mon.results.append(CheckResult(True, 90))
    await mon.check(1)
    assert st.status == "up" and "svc:1:down" not in mon.engine.open
    async with db.sessionmaker()() as s:
        inc = (await s.execute(select(ServiceIncident))).scalar_one()
    assert inc.started_at == first_fail and inc.ended_at is not None and inc.checks_failed == 3

    assert await mon.flush() == 5
    async with db.sessionmaker()() as s:
        rows = (await s.execute(select(ServiceCheck.status).order_by(ServiceCheck.ts))).scalars().all()
    assert rows == [1, 0, 0, 0, 1]
    stats = await mon.stats()
    assert stats[1]["uptime"]["24h"] == pytest.approx(40.0) and stats[1]["bars"][-1] == pytest.approx(40.0)
    assert len(stats[1]["bars"]) == uptime.BAR_DAYS and stats[1]["bars"][0] is None
    incidents = await mon.incidents(1)
    assert incidents[0]["service"] == "Nextcloud" and not incidents[0]["ongoing"]


async def test_restart_restores_open_incident(mon, db):
    fail = CheckResult(False, error="timed out after 10s")
    mon.results.extend([fail] * 3)
    for _ in range(3):
        await mon.check(1)
    fresh = uptime.UptimeMonitor()
    await fresh.load()
    assert fresh.state[1].status == "down" and fresh.state[1].incident_id == mon.state[1].incident_id


async def test_slow_and_certificate_alerts(mon):
    st = mon.state[1]
    for _ in range(3):
        mon.results.append(CheckResult(True, 900))
        await mon.check(1)
    assert mon.engine.open["svc:1:slow"].severity == "warning" and st.status == "degraded"
    mon.results.append(CheckResult(True, 100))
    await mon.check(1)
    assert "svc:1:slow" not in mon.engine.open and st.status == "up"

    def cert(days, valid=True, error=""):
        return CertInfo(time.time() + days * 86400, days, "Let's Encrypt", "cloud.example.com", ["cloud.example.com"],
                        True, valid, error)

    async def with_cert(c):
        st.cert, st.cert_ts = c, time.time()
        mon.results.append(CheckResult(True, 100))
        await mon.check(1)

    await with_cert(cert(30))
    assert "svc:1:cert" not in mon.engine.open and st.status == "up"
    await with_cert(cert(15))
    a = mon.engine.open["svc:1:cert"]
    assert a.rule == "cert_expiring" and a.severity == "warning" and "15 days" in a.title and st.status == "degraded"
    await with_cert(cert(5))
    assert mon.engine.open["svc:1:cert"].severity == "critical"  # same alert, escalated
    assert mon.engine.open["svc:1:cert"].id == a.id
    await with_cert(cert(60, valid=False, error="certificate does not cover cloud.example.com"))
    assert mon.engine.open["svc:1:cert"].severity == "critical"
    assert "does not cover" in mon.engine.open["svc:1:cert"].detail
    await with_cert(cert(80))
    assert not mon.engine.open


async def test_disable_and_remove_clear_alerts(mon):
    mon.results.extend([CheckResult(False, error="refused")] * 3)
    for _ in range(3):
        await mon.check(1)
    assert "svc:1:down" in mon.engine.open
    mon.services[1]["enabled"] = False
    await mon.pause_alerts(1)
    assert not mon.engine.open and mon.state[1].status == "paused" and mon.state[1].incident_id is None
    await mon.remove(1)
    assert 1 not in mon.services and 1 not in mon.state


async def test_service_history_rollup_and_uptime_from_rollups(db):
    from app.models import Service, ServiceCheck
    from app.services import history

    async with db.sessionmaker()() as s:
        s.add(Service(id=7, name="Plex", kind="tcp", target="plex.example.com", port=32400, config={}, tags=[]))
        await s.commit()
    hour = math.floor(time.time() / 3600) * 3600 - 5 * 3600
    rows = [{"ts": hour + m * 60, "service_id": 7, "status": 0 if m % 10 == 0 else 1, "response_ms": 20.0 + m % 5,
             "cert_days": None, "error": ""} for m in range(3 * 60)]
    async with db.sessionmaker()() as s:
        await s.execute(insert(ServiceCheck), rows)
        await s.commit()
    assert await history.rollup_kind("service") >= 3
    res = await history.query("service", {"service_id": 7}, *history.resolve_range("7d", None, None))
    assert res["resolution"] == "hourly" and res["stats"]["status"]["avg"] == pytest.approx(0.9)
    m = uptime.UptimeMonitor()
    await m.load()
    stats = await m.stats()
    assert stats[7]["uptime"]["7d"] == pytest.approx(90.0) and stats[7]["uptime"]["90d"] == pytest.approx(90.0)
    with pytest.raises(ValueError, match="service_id"):
        await history.query("service", {}, 0, 10)

    await uptime.purge_service(7)
    async with db.sessionmaker()() as s:
        assert not (await s.execute(select(ServiceCheck))).scalars().all()
