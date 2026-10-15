"""MFA login flow (via the API) and the KeePass secret provider."""

import os
import time

import pyotp
import pytest


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    data = tmp_path_factory.mktemp("mfa")
    os.environ.update({
        "NV_SECRET_KEY": "test-secret-key-for-unit-tests-only-0123456789",
        "NV_DATA_DIR": str(data), "NV_DEMO_MODE": "false", "NV_ADMIN_PASSWORD": "pw-for-tests",
        "NV_SYSLOG_ENABLED": "false", "NV_STATIC_DIR": str(data / "nostatic"),
    })
    from app.config import get_settings

    get_settings.cache_clear()
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


def _login(c, password="pw-for-tests"):
    return c.post("/api/auth/login", json={"username": "admin", "password": password})


def test_full_mfa_lifecycle(client):
    from fastapi.testclient import TestClient

    from app.main import app

    assert _login(client).json() == {"user": "admin"}
    other = TestClient(app)  # a second browser that should get logged out when MFA is enabled
    assert _login(other).status_code == 200
    assert other.get("/api/devices").status_code == 200

    setup = client.post("/api/auth/mfa/setup").json()
    assert setup["qr_svg"].startswith("data:image/svg+xml")
    totp = pyotp.TOTP(setup["secret"])

    bad = client.post("/api/auth/mfa/enable", json={"password": "pw-for-tests", "code": "000000"})
    assert bad.status_code == 400
    wrong_pw = client.post("/api/auth/mfa/enable", json={"password": "nope", "code": totp.now()})
    assert wrong_pw.status_code == 403

    r = client.post("/api/auth/mfa/enable", json={"password": "pw-for-tests", "code": totp.now()})
    assert r.status_code == 200, r.text
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10
    assert client.get("/api/devices").status_code == 200  # this browser stays signed in
    assert other.get("/api/devices").status_code == 401  # every other session is revoked

    # Password alone no longer creates a session.
    client.post("/api/auth/logout")
    step1 = _login(client).json()
    assert step1["mfa_required"] is True and "user" not in step1
    assert client.get("/api/devices").status_code == 401
    # The half-login token is not a session token.
    assert client.get("/api/devices", headers={"Authorization": f"Bearer {step1['mfa_token']}"}).status_code == 401

    # The code used for enrollment can't be replayed.
    replay = client.post("/api/auth/mfa", json={"mfa_token": step1["mfa_token"], "code": totp.now()})
    assert replay.status_code == 401

    # A recovery code works exactly once.
    ok = client.post("/api/auth/mfa", json={"mfa_token": step1["mfa_token"], "code": codes[0]})
    assert ok.status_code == 200 and client.get("/api/devices").status_code == 200
    again = client.post("/api/auth/mfa", json={"mfa_token": _login(client).json()["mfa_token"], "code": codes[0]})
    assert again.status_code == 401
    assert client.get("/api/auth/mfa/status").json()["recovery_codes_remaining"] == 9

    # Disable needs password + a fresh code (next 30s step, within the drift window).
    next_code = totp.at(time.time() + 30)
    off = client.post("/api/auth/mfa/disable", json={"password": "pw-for-tests", "code": next_code})
    assert off.status_code == 200, off.text
    assert _login(client).json() == {"user": "admin"}


# ------------------------------------------------------------------ KeePass
@pytest.fixture
def kdbx(tmp_path, monkeypatch):
    from pykeepass import create_database

    path = tmp_path / "nv.kdbx"
    db = create_database(str(path), password="master-pw")
    net = db.add_group(db.root_group, "Network")
    e = db.add_entry(net, "pfSense", "apiuser", "pf-password")
    e.set_custom_property("api_key", "pf-api-key")
    db.add_entry(net, "UniFi", "nv-readonly", "unifi-password")
    db.add_entry(db.add_group(db.root_group, "Lab"), "UniFi", "lab", "lab-password")
    db.save()
    monkeypatch.setenv("NV_KEEPASS_FILE", str(path))
    monkeypatch.setenv("NV_KEEPASS_PASSWORD", "master-pw")
    from app.config import get_settings

    get_settings.cache_clear()
    from app.services.keepass import KeePassProvider

    yield KeePassProvider(), path
    get_settings.cache_clear()


def test_keepass_resolves_fields(kdbx):
    kp, _ = kdbx
    assert kp.resolve("Network/pfSense") == "pf-password"
    assert kp.resolve("Network/pfSense#username") == "apiuser"
    assert kp.resolve("Network/pfSense#api_key") == "pf-api-key"
    assert kp.resolve("pfSense") == "pf-password"  # unique title


def test_keepass_errors_are_precise(kdbx):
    from app.security import SecretError

    kp, _ = kdbx
    with pytest.raises(SecretError, match="ambiguous"):
        kp.resolve("UniFi")
    with pytest.raises(SecretError, match="not found"):
        kp.resolve("Network/Nope")
    with pytest.raises(SecretError, match="no field"):
        kp.resolve("Network/UniFi#api_key")


def test_keepass_listing_has_no_secrets(kdbx):
    kp, _ = kdbx
    listing = kp.entries()
    assert {e["ref"] for e in listing} == {"Network/pfSense", "Network/UniFi", "Lab/UniFi"}
    flat = repr(listing)
    assert "pf-password" not in flat and "pf-api-key" not in flat
    assert next(e for e in listing if e["ref"] == "Network/pfSense")["custom_fields"] == ["api_key"]


def test_keepass_wrong_password(kdbx, monkeypatch):
    from app.config import get_settings
    from app.security import SecretError
    from app.services.keepass import KeePassProvider

    monkeypatch.setenv("NV_KEEPASS_PASSWORD", "wrong")
    get_settings.cache_clear()
    with pytest.raises(SecretError, match="unlocked"):
        KeePassProvider().resolve("Network/pfSense")


def test_keepass_reloads_on_change(kdbx):
    from pykeepass import PyKeePass

    kp, path = kdbx
    v1 = kp.check()
    db = PyKeePass(str(path), password="master-pw")
    db.find_entries(title="pfSense", first=True).password = "rotated"
    time.sleep(0.05)
    db.save()
    os.utime(path, (time.time() + 5, time.time() + 5))  # make the mtime change unmistakable
    assert kp.check() > v1
    assert kp.resolve("Network/pfSense") == "rotated"


def test_kp_reference_masking():
    from app.security import mask_secrets

    assert mask_secrets({"api_key": "kp:Network/pfSense", "pw": "plain"}) == {"api_key": "kp:Network/pfSense", "pw": "••••••••"}
