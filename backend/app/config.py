r"""Runtime configuration.

Every setting is read from environment variables, then from a config file, then
from a local ``.env`` file (development). Nothing secret is ever hard-coded or
committed; see ``.env.example`` at the repository root for the full list.

The config file is ``NV_CONFIG`` if set, else the per-OS default written by the
native packages (``/etc/networkvision/networkvision.env`` on Linux,
``%ProgramData%\NetworkVision\networkvision.env`` on Windows). Docker users keep
using plain environment variables.
"""

from __future__ import annotations

import logging
import os
import secrets
import sys
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger("networkvision.config")


def _windows_programdata() -> Path:
    return Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "NetworkVision"


def default_config_file() -> Path:
    """Where the native packages put the config file (it may not exist)."""
    if os.environ.get("NV_CONFIG"):
        return Path(os.environ["NV_CONFIG"])
    if sys.platform == "win32":
        return _windows_programdata() / "networkvision.env"
    return Path("/etc/networkvision/networkvision.env")


def default_data_dir() -> str:
    """The OS data dir when a package created it, else ./data (source checkouts, tests)."""
    os_dir = _windows_programdata() / "data" if sys.platform == "win32" else Path("/var/lib/networkvision")
    return str(os_dir) if os_dir.is_dir() else "./data"


def env_files() -> tuple[str, ...]:
    """Env files in increasing precedence; real environment variables beat all of them."""
    files = [".env", "../.env"]
    cfg = default_config_file()
    if cfg.is_file() and os.access(cfg, os.R_OK):
        files.append(str(cfg))
    elif os.environ.get("NV_CONFIG"):
        log.warning("NV_CONFIG=%s is not a readable file - ignoring it", cfg)
    return tuple(files)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NV_",
        env_file=(".env", "../.env"),  # get_settings() adds the config file, see env_files()
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Core -----------------------------------------------------------------
    app_name: str = "NetworkVision"
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8080
    data_dir: str = Field(default_factory=default_data_dir)
    static_dir: str = "./static"
    demo_mode: bool = False

    # Used to sign sessions AND (via HKDF) to encrypt device credentials at rest.
    # Changing it invalidates sessions and stored device secrets.
    secret_key: str = ""

    # --- Auth -----------------------------------------------------------------
    auth_disabled: bool = False  # only behind a trusted SSO proxy!
    admin_username: str = "admin"
    admin_password: str = ""  # plain text (simple) ...
    admin_password_hash: str = ""  # ... or a bcrypt hash (preferred)
    # Optional: pin the TOTP secret (base32) via env instead of enrolling in the UI.
    admin_totp_secret: str = ""
    # Break-glass: clears UI-enrolled MFA on startup (lost phone + lost recovery codes). Unset afterwards!
    mfa_reset: bool = False
    session_hours: int = 12
    cookie_secure: bool = False  # set true when served over HTTPS
    trusted_proxy_header: str = ""  # e.g. "Remote-User" when using Authelia/Authentik

    # --- KeePass (optional secret source: kp:Group/Entry references) ---------
    keepass_file: str = ""  # e.g. /secrets/networkvision.kdbx (mount it read-only)
    keepass_password: str = ""
    keepass_keyfile: str = ""

    # --- Database -------------------------------------------------------------
    # Either a full SQLAlchemy URL, or the discrete DB_* parts below.
    database_url: str = ""
    db_driver: str = "sqlite"  # sqlite | mariadb | mysql
    db_host: str = "localhost"
    db_port: int = 3306
    db_name: str = "networkvision"
    db_user: str = "networkvision"
    db_password: str = ""

    # --- Collection -----------------------------------------------------------
    poll_interval: int = Field(default=15, ge=5)
    metrics_persist_interval: int = Field(default=60, ge=15)
    retention_days_metrics: int = Field(default=7, ge=1)  # raw per-minute samples
    retention_days_rollup: int = Field(default=365, ge=7)  # hourly rollups (long-range charts)
    retention_days_logs: int = Field(default=14, ge=1)
    retention_days_alerts: int = Field(default=90, ge=1)
    ping_privileged: bool = False

    # --- Syslog receiver ------------------------------------------------------
    syslog_enabled: bool = True
    syslog_port: int = 5514
    syslog_tcp_enabled: bool = True

    # --- Firewall log explorer (pfSense / OPNsense filterlog) ----------------
    firewall_enabled: bool = True
    retention_days_firewall: int = Field(default=7, ge=1)
    firewall_store_pass: bool = True  # false: count pass events but only store block/reject rows
    firewall_store_noise: bool = True  # false: count multicast/broadcast/IPv6 link-local chatter, don't store it
    firewall_keep_raw_logs: bool = True  # false: filterlog lines go only to the Firewall page, not to Logs

    # --- Alert thresholds -----------------------------------------------------
    alert_cpu_pct: float = 90
    alert_mem_pct: float = 92
    alert_temp_c: float = 80
    alert_latency_ms: float = 150
    alert_loss_pct: float = 10
    alert_if_util_pct: float = 90
    alert_if_errors_per_min: float = 50
    alert_consecutive: int = Field(default=3, ge=1)

    # --- Security detections ----------------------------------------------------
    sec_enabled: bool = True
    sec_bruteforce_failures: int = Field(default=10, ge=1)  # auth failures from one source ...
    sec_bruteforce_window_min: int = Field(default=10, ge=1)  # ... within this many minutes
    sec_scan_ports: int = Field(default=15, ge=2)  # distinct destination ports from one source ...
    sec_scan_hosts: int = Field(default=10, ge=2)  # ... or distinct destination hosts ...
    sec_scan_window_min: int = Field(default=5, ge=1)  # ... within this many minutes
    # Internet background scanning that is fully blocked is noise; only alert on scans that
    # got something through, or that come from inside the network, unless this is true.
    sec_scan_alert_blocked: bool = False
    sec_wan_spike_factor: float = Field(default=4.0, ge=1.5)  # blocked/min vs. rolling baseline
    sec_wan_spike_min: int = Field(default=300, ge=1)  # ... and at least this many per minute
    sec_ignore_ips: str = ""  # comma separated IPs/CIDRs never treated as attackers
    retention_days_security: int = Field(default=30, ge=1)

    # --- GeoIP (optional, MaxMind GeoLite2 Country) --------------------------------
    geoip_db: str = ""  # path to a .mmdb; defaults to <data_dir>/GeoLite2-Country.mmdb
    geoip_license_key: str = ""  # if set and the db is missing/stale, download it automatically

    # --- DHCP insights ------------------------------------------------------------
    dhcp_enabled: bool = True
    dhcp_mac_max_ips: int = Field(default=4, ge=2)  # distinct IPs for one MAC in 24h before flagging
    dhcp_learning_hours: float = Field(default=1.0, ge=0)  # no "new device" alerts while learning
    dhcp_scope_warn_pct: float = Field(default=80, ge=1, le=100)  # Windows DHCP scope utilization: warning
    dhcp_scope_crit_pct: float = Field(default=95, ge=1, le=100)  # ... and critical

    # --- Notifications --------------------------------------------------------
    notify_min_severity: str = "warning"  # info | warning | critical
    notify_webhook_url: str = ""
    notify_discord_webhook_url: str = ""
    notify_ntfy_url: str = ""  # e.g. https://ntfy.sh/my-topic
    notify_ntfy_token: str = ""
    notify_slack_webhook_url: str = ""

    @field_validator("db_driver")
    @classmethod
    def _driver(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"sqlite", "mariadb", "mysql"}:
            raise ValueError("NV_DB_DRIVER must be sqlite, mariadb or mysql")
        return v

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        if self.db_driver in {"mariadb", "mysql"}:
            return (
                f"mysql+aiomysql://{quote_plus(self.db_user)}:{quote_plus(self.db_password)}"
                f"@{self.db_host}:{self.db_port}/{self.db_name}?charset=utf8mb4"
            )
        return f"sqlite+aiosqlite:///{self.data_dir}/networkvision.db"


@lru_cache
def config_file_values() -> dict[str, str]:
    """Raw KEY=value pairs of the config file, for env:NAME device-secret references.

    Native installs keep device secrets in the config file instead of the process
    environment, so env:PFSENSE_API_KEY must find them there too.
    """
    from dotenv import dotenv_values

    cfg = default_config_file()
    if not (cfg.is_file() and os.access(cfg, os.R_OK)):
        return {}
    return {k: v for k, v in dotenv_values(cfg).items() if v is not None}


@lru_cache
def get_settings() -> Settings:
    s = Settings(_env_file=env_files())
    if not s.secret_key:
        s.secret_key = _load_or_create_secret(s.data_dir)
    return s


def _load_or_create_secret(data_dir: str) -> str:
    """Fallback when NV_SECRET_KEY is unset: persist a random key in the data dir.

    The file is created owner-only (0600) and reused on every later start. The key
    never leaves the data directory, so it is never committed, but it must be backed
    up together with the database: it encrypts stored device credentials.
    """
    path = Path(data_dir) / ".secret_key"
    try:
        if path.exists():
            key = path.read_text(encoding="utf-8").strip()
            if key:
                return key
            log.warning("%s is empty - generating a new key", path)
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_urlsafe(48)
        # Create with 0600 from the start (no window where the key is world-readable).
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key)
        try:
            os.chmod(path, 0o600)  # also tighten a pre-existing empty file
        except OSError:
            pass
        log.warning(
            "NV_SECRET_KEY is not set - generated one at %s. Back it up, or set "
            "NV_SECRET_KEY explicitly: it encrypts stored device credentials.",
            path,
        )
        return key
    except OSError:
        log.error("NV_SECRET_KEY unset and data dir not writable - using an ephemeral key")
        return secrets.token_urlsafe(48)
