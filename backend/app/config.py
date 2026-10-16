"""Runtime configuration.

Every setting is read from environment variables (or a local ``.env`` file in
development). Nothing secret is ever hard-coded or committed; see
``.env.example`` at the repository root for the full, documented list.
"""

from __future__ import annotations

import logging
import os
import secrets
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger("networkvision.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NV_",
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Core -----------------------------------------------------------------
    app_name: str = "NetworkVision"
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8080
    data_dir: str = "./data"
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

    # --- Alert thresholds -----------------------------------------------------
    alert_cpu_pct: float = 90
    alert_mem_pct: float = 92
    alert_temp_c: float = 80
    alert_latency_ms: float = 150
    alert_loss_pct: float = 10
    alert_if_util_pct: float = 90
    alert_if_errors_per_min: float = 50
    alert_consecutive: int = Field(default=3, ge=1)

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
def get_settings() -> Settings:
    s = Settings()
    if not s.secret_key:
        s.secret_key = _load_or_create_secret(s.data_dir)
    return s


def _load_or_create_secret(data_dir: str) -> str:
    """Fallback when NV_SECRET_KEY is unset: persist a random key in the data volume.

    The key never leaves the container's data directory, so it is never committed,
    but operators should still prefer an explicit NV_SECRET_KEY they can back up.
    """
    path = Path(data_dir) / ".secret_key"
    try:
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_urlsafe(48)
        path.write_text(key, encoding="utf-8")
        try:
            os.chmod(path, 0o600)
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
