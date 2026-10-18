"""Authentication, session tokens and at-rest encryption of device credentials.

Device secrets (API keys, SNMP communities, passwords) are never returned to the
browser. They are stored Fernet-encrypted with a key derived from NV_SECRET_KEY,
or - even better - kept out of the database entirely by entering a reference
like ``env:PFSENSE_API_KEY``, which is resolved from the container environment
at poll time.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import time
from collections import defaultdict, deque
from typing import Any

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, Request, WebSocket, status

from .config import get_settings

COOKIE_NAME = "nv_session"
ENV_REF_PREFIX = "env:"
KEEPASS_REF_PREFIX = "kp:"
SECRET_MASK = "••••••••"


# --------------------------------------------------------------------------- #
# Credential encryption
# --------------------------------------------------------------------------- #
def _derive(purpose: bytes) -> bytes:
    key = get_settings().secret_key.encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"networkvision", info=purpose).derive(key)


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_derive(b"device-secrets-v1")))


def encrypt_secrets(data: dict[str, Any]) -> str | None:
    clean = {k: v for k, v in data.items() if v not in (None, "")}
    if not clean:
        return None
    return _fernet().encrypt(json.dumps(clean).encode()).decode()


def decrypt_secrets(blob: str | None) -> dict[str, Any]:
    if not blob:
        return {}
    try:
        return json.loads(_fernet().decrypt(blob.encode()))
    except (InvalidToken, ValueError):
        # Most likely NV_SECRET_KEY changed. Fail closed, never crash the poller.
        return {}


def encrypt_blob(data: dict[str, Any]) -> str:
    """Encrypt arbitrary JSON state (unlike encrypt_secrets, empty values are kept)."""
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def decrypt_blob(blob: str | None) -> dict[str, Any] | None:
    """None means "present but undecryptable" (NV_SECRET_KEY changed); {} means empty."""
    if not blob:
        return {}
    try:
        return json.loads(_fernet().decrypt(blob.encode()))
    except (InvalidToken, ValueError):
        return None


def is_reference(value: Any) -> bool:
    return isinstance(value, str) and value.startswith((ENV_REF_PREFIX, KEEPASS_REF_PREFIX))


def resolve_secret(value: Any) -> Any:
    """Resolve ``env:NAME`` and ``kp:Group/Entry[#field]`` references.

    env: misses resolve to "" (an unset variable); kp: misses raise SecretError so the
    operator gets a precise message instead of a vague authentication failure.
    """
    if isinstance(value, str) and value.startswith(KEEPASS_REF_PREFIX):
        from .services.keepass import keepass  # local import: avoid cycle

        return keepass.resolve(value[len(KEEPASS_REF_PREFIX) :])
    if isinstance(value, str) and value.startswith(ENV_REF_PREFIX):
        name = value[len(ENV_REF_PREFIX) :].strip()
        # Never let a device config exfiltrate NetworkVision's own secrets (NV_SECRET_KEY, DB password...).
        if not name or name.upper().startswith("NV_"):
            return ""
        if name in os.environ:
            return os.environ[name]
        from .config import config_file_values

        return config_file_values().get(name, "")
    return value


def mask_secrets(data: dict[str, Any]) -> dict[str, Any]:
    """What the UI sees: env:/kp: references are shown (they are not secret), values are masked."""
    out: dict[str, Any] = {}
    for k, v in data.items():
        if is_reference(v):
            out[k] = v
        elif v not in (None, ""):
            out[k] = SECRET_MASK
    return out


# --------------------------------------------------------------------------- #
# Passwords & sessions
# --------------------------------------------------------------------------- #
# Admin account created in the first-run setup page (settings table, key "admin").
# Env credentials (NV_ADMIN_PASSWORD / NV_ADMIN_PASSWORD_HASH) always take precedence.
_stored_admin: dict[str, str] | None = None


def set_stored_admin(account: dict[str, str] | None) -> None:
    global _stored_admin
    _stored_admin = account


def env_admin_configured() -> bool:
    s = get_settings()
    return bool(s.admin_password or s.admin_password_hash)


def admin_password_configured() -> bool:
    return env_admin_configured() or bool(_stored_admin)


def admin_username() -> str:
    if not env_admin_configured() and _stored_admin:
        return _stored_admin["username"]
    return get_settings().admin_username


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _check_hash(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def verify_admin(username: str, password: str) -> bool:
    s = get_settings()
    user_ok = hmac.compare_digest(username.encode(), admin_username().encode())
    if s.admin_password_hash:
        pw_ok = _check_hash(password, s.admin_password_hash)
    elif s.admin_password:
        pw_ok = hmac.compare_digest(password.encode(), s.admin_password.encode())
    elif _stored_admin:
        pw_ok = _check_hash(password, _stored_admin["hash"])
    else:
        pw_ok = False  # no password configured -> nobody gets in
    return user_ok and pw_ok


def auth_configured() -> bool:
    s = get_settings()
    return s.auth_disabled or bool(s.trusted_proxy_header) or admin_password_configured()


def setup_required() -> bool:
    """True until an admin exists (env or first-run page): the UI then shows the setup page."""
    return not auth_configured()


class SecretError(Exception):
    """A secret reference (kp:...) could not be resolved."""


# Bumped whenever MFA is enabled/disabled: every token issued before that stops working.
_session_epoch = 0


def set_session_epoch(epoch: int) -> None:
    global _session_epoch
    _session_epoch = int(epoch)


def issue_token(username: str, purpose: str = "session", ttl: int | None = None) -> str:
    """purpose="session" is a login cookie; purpose="mfa" only proves the password step passed."""
    s = get_settings()
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + (ttl or s.session_hours * 3600),
               "pur": purpose, "ep": _session_epoch}
    return jwt.encode(payload, _derive(b"session-v1"), algorithm="HS256")


def decode_token(token: str, purpose: str = "session") -> str | None:
    try:
        payload = jwt.decode(token, _derive(b"session-v1"), algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    # An "mfa" half-login token must never work as a session (and vice versa).
    if payload.get("pur", "session") != purpose or payload.get("ep", 0) != _session_epoch:
        return None
    return str(payload.get("sub") or "") or None


def _user_from(headers, cookies) -> str | None:
    s = get_settings()
    if s.auth_disabled:
        return "anonymous"
    if s.trusted_proxy_header:
        proxied = headers.get(s.trusted_proxy_header)
        if proxied:
            return proxied
    token = cookies.get(COOKIE_NAME)
    if not token:
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:]
    return decode_token(token) if token else None


def require_user(request: Request) -> str:
    user = _user_from(request.headers, request.cookies)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user


def websocket_user(ws: WebSocket) -> str | None:
    return _user_from(ws.headers, ws.cookies)


# --------------------------------------------------------------------------- #
# Tiny in-memory login rate limiter (per client IP)
# --------------------------------------------------------------------------- #
class LoginLimiter:
    def __init__(self, attempts: int = 8, window: int = 300) -> None:
        self.attempts, self.window = attempts, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        q, now = self._hits[key], time.time()
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.attempts:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts, try later")

    def fail(self, key: str) -> None:
        self._hits[key].append(time.time())

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)


login_limiter = LoginLimiter()
