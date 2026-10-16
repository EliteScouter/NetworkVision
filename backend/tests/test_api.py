"""End-to-end smoke test: boots the app in demo mode against a temp SQLite DB."""

import os
import time

import pytest


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    data = tmp_path_factory.mktemp("data")
    os.environ.update({
        "NV_SECRET_KEY": "test-secret-key-for-unit-tests-only-0123456789",
        "NV_DATA_DIR": str(data), "NV_DEMO_MODE": "true", "NV_ADMIN_PASSWORD": "pw-for-tests",
        "NV_SYSLOG_ENABLED": "false", "NV_POLL_INTERVAL": "5", "NV_STATIC_DIR": str(data / "nostatic"),
    })
    from app.config import get_settings

    get_settings.cache_clear()
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


def test_requires_auth(client):
    assert client.get("/api/devices").status_code == 401
    assert client.get("/api/health").json()["status"] == "ok"


def test_bad_login(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401


def test_demo_end_to_end(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "pw-for-tests"})
    assert r.status_code == 200
    deadline = time.time() + 15
    while time.time() < deadline:
        devs = client.get("/api/devices").json()["devices"]
        if len(devs) >= 14 and all(d["status"] != "unknown" for d in devs if d["enabled"]):
            break
        time.sleep(0.5)
    assert len(devs) >= 14, "demo seed + UniFi child discovery"
    topo = client.get("/api/topology").json()
    assert any(e["kind"] == "wan" for e in topo["edges"])
    assert any(e["kind"] == "lldp" for e in topo["edges"])
    ov = client.get("/api/overview").json()
    assert ov["devices"]["total"] >= 14
    assert client.get("/api/logs", params={"limit": 5}).status_code == 200
    assert client.get("/api/logs/histogram", params={"range": "1h"}).status_code == 200


def test_device_crud_never_leaks_secrets(client):
    body = {"name": "test-snmp", "kind": "snmp", "role": "switch", "host": "192.0.2.10",
            "config": {"snmp_version": "2c"}, "secrets": {"community": "s3cr3t-community"}}
    r = client.post("/api/devices", json=body)
    assert r.status_code == 201, r.text
    dev_id = r.json()["id"]
    detail = client.get(f"/api/devices/{dev_id}").text
    assert "s3cr3t-community" not in detail
    # masked value on update keeps the original secret
    body["secrets"] = {"community": "••••••••"}
    assert client.put(f"/api/devices/{dev_id}", json=body).status_code == 200
    assert client.delete(f"/api/devices/{dev_id}").status_code == 204


def test_host_validation(client):
    r = client.post("/api/devices", json={"name": "x", "kind": "ping", "host": "http://evil/x"})
    assert r.status_code == 422


def test_new_feature_endpoints(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "pw-for-tests"}).status_code == 200
    clients = client.get("/api/clients").json()
    assert clients["counts"]["online"] > 0 and clients["clients"][0]["category"]
    mac = clients["clients"][0]["mac"]
    assert client.get(f"/api/clients/{mac}").json()["mac"] == mac
    wifi = client.get("/api/wifi").json()
    assert wifi["aps"] and wifi["ssids"] and wifi["summary"]["clients"] > 0
    dev = next(d for d in client.get("/api/devices").json()["devices"] if d["kind"] == "demo")
    h = client.get("/api/history/device", params={"device_id": dev["id"], "range": "30d"})
    assert h.status_code == 200 and h.json()["resolution"] == "hourly"
    assert client.get("/api/history/nope").status_code == 404
    assert client.get("/api/history/device", params={"range": "1h"}).status_code == 422
    st = client.get("/api/speedtest").json()
    assert st["engine"] == "demo" and st["settings"]["interval_min"] == 60
    r = client.put("/api/speedtest/settings", json={"interval_min": 240, "expected_down_mbps": 2000})
    assert r.json()["settings"]["interval_min"] == 240


def test_services_endpoints(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "pw-for-tests"}).status_code == 200
    listing = client.get("/api/services").json()
    assert listing["summary"]["total"] >= 6 and {s["kind"] for s in listing["services"]} == {"http", "tcp", "dns", "tls"}
    assert len(listing["services"][0]["bars"]) == 90 and set(listing["services"][0]["uptime"]) == {"24h", "7d", "30d", "90d"}

    for bad in ({"name": "x", "kind": "http", "target": "file:///etc/passwd"},
                {"name": "x", "kind": "tcp", "target": "example.com"},  # no port
                {"name": "x", "kind": "http", "target": "https://example.com", "interval_s": 5},
                {"name": "x", "kind": "http", "target": "https://example.com", "interval_s": 10, "timeout_s": 10}):
        assert client.post("/api/services", json=bad).status_code == 422, bad

    body = {"name": "Jellyfin", "kind": "http", "target": "https://media.example.org/health",
            "config": {"keyword": "Healthy", "slow_ms": 800}}
    r = client.post("/api/services/test", json=body)
    assert r.status_code == 200 and "ok" in r.json()
    r = client.post("/api/services", json=body)
    assert r.status_code == 201, r.text
    created = r.json()
    sid = created["id"]
    assert created["config"]["keyword"] == "Healthy" and created["config"]["fail_threshold"] == 3
    checked = client.post(f"/api/services/{sid}/check").json()
    assert checked["state"]["last_ts"] is not None and checked["state"]["status"] != "pending"
    detail = client.get(f"/api/services/{sid}").json()
    assert detail["name"] == "Jellyfin" and isinstance(detail["incidents"], list)
    h = client.get("/api/history/service", params={"service_id": sid, "range": "24h"})
    assert h.status_code == 200 and h.json()["samples"] >= 1

    body.update(enabled=False, name="Jellyfin (paused)")
    upd = client.put(f"/api/services/{sid}", json=body).json()
    assert upd["name"] == "Jellyfin (paused)" and upd["state"]["status"] == "paused"
    assert client.get("/api/services/incidents", params={"service_id": sid}).json()["items"] == []
    assert client.delete(f"/api/services/{sid}").status_code == 204
    assert client.get(f"/api/services/{sid}").status_code == 404
    assert client.put("/api/services/99999", json=body).status_code == 404
