"""Native-install support: config file, per-OS defaults, persisted secret key, first-run admin setup."""

import os
import stat
import sys
from pathlib import Path

import pytest

from app import config


# --------------------------------------------------------------------------- config file
def test_config_file_is_read_and_env_overrides(tmp_path, monkeypatch):
    cfg = tmp_path / "networkvision.env"
    cfg.write_text("NV_POLL_INTERVAL=42\nNV_SYSLOG_PORT=514\n", encoding="utf-8")
    monkeypatch.setenv("NV_CONFIG", str(cfg))
    monkeypatch.delenv("NV_POLL_INTERVAL", raising=False)
    monkeypatch.setenv("NV_SYSLOG_PORT", "1514")
    assert str(cfg) in config.env_files()
    s = config.Settings(_env_file=config.env_files())
    assert s.poll_interval == 42
    assert s.syslog_port == 1514  # a real environment variable beats the file


def test_missing_config_file_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("NV_CONFIG", str(tmp_path / "nope.env"))
    assert config.env_files() == (".env", "../.env")


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_default_paths_per_os(tmp_path, monkeypatch, platform):
    monkeypatch.delenv("NV_CONFIG", raising=False)
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setenv("ProgramData", str(tmp_path))
    if platform == "win32":
        assert config.default_config_file() == tmp_path / "NetworkVision" / "networkvision.env"
        assert config.default_data_dir() == "./data"  # not installed yet
        (tmp_path / "NetworkVision" / "data").mkdir(parents=True)
        assert config.default_data_dir() == str(tmp_path / "NetworkVision" / "data")
    else:
        assert config.default_config_file() == Path("/etc/networkvision/networkvision.env")
        os_dir = Path("/var/lib/networkvision")
        assert config.default_data_dir() == (str(os_dir) if os_dir.is_dir() else "./data")


# --------------------------------------------------------------------------- secret key
def test_secret_key_generated_persisted_and_reused(tmp_path):
    data = tmp_path / "data"
    key = config._load_or_create_secret(str(data))
    path = data / ".secret_key"
    assert len(key) >= 48 and path.read_text(encoding="utf-8") == key
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert config._load_or_create_secret(str(data)) == key  # same key on the next start


def test_empty_secret_file_is_replaced(tmp_path):
    (tmp_path / ".secret_key").write_text("", encoding="utf-8")
    key = config._load_or_create_secret(str(tmp_path))
    assert key and (tmp_path / ".secret_key").read_text(encoding="utf-8") == key


def test_get_settings_uses_persisted_key(tmp_path, monkeypatch):
    monkeypatch.setenv("NV_SECRET_KEY", "")
    monkeypatch.setenv("NV_DATA_DIR", str(tmp_path))
    config.get_settings.cache_clear()
    try:
        first = config.get_settings().secret_key
        config.get_settings.cache_clear()
        assert first and config.get_settings().secret_key == first
        assert (tmp_path / ".secret_key").read_text(encoding="utf-8") == first
    finally:
        config.get_settings.cache_clear()


# --------------------------------------------------------------------------- first-run setup
ENV_KEYS = ("NV_ADMIN_PASSWORD", "NV_ADMIN_PASSWORD_HASH", "NV_AUTH_DISABLED", "NV_TRUSTED_PROXY_HEADER", "NV_ADMIN_TOTP_SECRET")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    data = tmp_path_factory.mktemp("setup")
    saved = {k: os.environ.pop(k) for k in ENV_KEYS if k in os.environ}
    os.environ.update({
        "NV_SECRET_KEY": "test-secret-key-for-unit-tests-only-0123456789",
        "NV_DATA_DIR": str(data), "NV_DEMO_MODE": "false",
        "NV_SYSLOG_ENABLED": "false", "NV_STATIC_DIR": str(data / "nostatic"),
    })
    from app.config import get_settings
    from app.security import login_limiter

    get_settings.cache_clear()
    login_limiter.reset("testclient")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c
    os.environ.update(saved)
    get_settings.cache_clear()


def _login(c, username="owner", password="correct-horse-battery"):
    return c.post("/api/auth/login", json={"username": username, "password": password})


def test_first_run_setup_flow(client):
    me = client.get("/api/auth/me").json()
    assert me["setup_required"] is True and me["configured"] is False and me["user"] is None
    assert _login(client).status_code == 503
    assert client.get("/api/devices").status_code == 401

    assert client.post("/api/auth/setup", json={"username": "owner", "password": "short"}).status_code == 422
    assert client.post("/api/auth/setup", json={"username": "bad name", "password": "correct-horse-battery"}).status_code == 422

    r = client.post("/api/auth/setup", json={"username": "owner", "password": "correct-horse-battery"})
    assert r.status_code == 200, r.text
    assert r.json() == {"user": "owner"}
    assert client.get("/api/devices").status_code == 200  # signed in straight away

    me = client.get("/api/auth/me").json()
    assert me["setup_required"] is False and me["configured"] is True and me["user"] == "owner"

    # Locked: nobody can claim the instance a second time, signed in or not.
    again = client.post("/api/auth/setup", json={"username": "evil", "password": "another-password"})
    assert again.status_code == 409
    client.post("/api/auth/logout")
    assert client.post("/api/auth/setup", json={"username": "evil", "password": "another-password"}).status_code == 409

    assert _login(client, password="wrong-password").status_code == 401
    assert _login(client, username="admin").status_code == 401
    assert _login(client).json() == {"user": "owner"}
    # MFA enrollment works for the UI-created admin.
    assert client.post("/api/auth/mfa/setup").status_code == 200


def test_stored_hash_is_bcrypt(client):
    import json

    from app.db import sessionmaker
    from app.models import Setting

    async def read():
        async with sessionmaker()() as db:
            return await db.get(Setting, "admin")

    row = client.portal.call(read)
    data = json.loads(row.value)
    assert data["username"] == "owner" and data["hash"].startswith("$2") and "correct-horse" not in row.value


def test_account_survives_restart_and_cross_process_race(client):
    from app.security import set_stored_admin, setup_required
    from app.services.account import account

    # Another process created the admin; this one hasn't loaded it yet: the DB row still locks setup.
    set_stored_admin(None)
    assert setup_required() is True
    r = client.post("/api/auth/setup", json={"username": "late", "password": "another-password"})
    assert r.status_code == 409
    assert setup_required() is False  # reloaded from the database

    set_stored_admin(None)
    client.portal.call(account.load)
    assert _login(client).status_code == 200


def test_env_admin_takes_precedence(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("NV_ADMIN_PASSWORD", "env-password-123")
    get_settings.cache_clear()
    try:
        assert _login(client).status_code == 401  # the UI-created password is ignored ...
        assert _login(client, username="admin", password="env-password-123").status_code == 200  # ... env wins
        assert client.get("/api/auth/me").json()["setup_required"] is False
    finally:
        monkeypatch.delenv("NV_ADMIN_PASSWORD")
        get_settings.cache_clear()
    assert _login(client).status_code == 200


def test_setup_closed_when_env_admin_configured(tmp_path, monkeypatch):
    from app.config import get_settings
    from app.security import set_stored_admin, setup_required

    set_stored_admin(None)
    try:
        for key, value in (("NV_ADMIN_PASSWORD", "x" * 10), ("NV_ADMIN_PASSWORD_HASH", "$2b$12$abc"), ("NV_AUTH_DISABLED", "true"),
                           ("NV_TRUSTED_PROXY_HEADER", "Remote-User")):
            monkeypatch.setenv(key, value)
            get_settings.cache_clear()
            assert setup_required() is False, key
            monkeypatch.delenv(key)
        get_settings.cache_clear()
        assert setup_required() is True
    finally:
        get_settings.cache_clear()
