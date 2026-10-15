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
