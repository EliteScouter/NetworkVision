"""TOTP multi-factor authentication for the admin login.

State lives encrypted in the ``settings`` table (key ``mfa``). Alternatively the
operator can pin the secret with NV_ADMIN_TOTP_SECRET; then MFA is always on
and cannot be changed from the UI.

Protections: +-1 step clock drift window, replay protection (a code can't be
used twice), hashed single-use recovery codes, and a session epoch that logs
out every other session when MFA is enabled or disabled.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from typing import Any

import pyotp
import segno

from ..config import get_settings
from ..db import sessionmaker
from ..models import Setting
from ..security import decrypt_blob, encrypt_blob, set_session_epoch

log = logging.getLogger("networkvision.mfa")
ISSUER = "NetworkVision"
RECOVERY_CODES = 10


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").strip().lower().encode()).hexdigest()


def _new_recovery_codes() -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/l/i confusion
    return ["-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(2)) for _ in range(RECOVERY_CODES)]


class MfaService:
    def __init__(self) -> None:
        self.state: dict[str, Any] = {}
        self.corrupt = False
        self._lock = asyncio.Lock()

    # ---------------------------------------------------------------- storage
    async def load(self) -> None:
        async with sessionmaker()() as db:
            row = await db.get(Setting, "mfa")
        state = decrypt_blob(row.value if row else None)
        if state is None:
            # NV_SECRET_KEY changed: fail CLOSED - logins are refused until an operator
            # resets MFA (see README) or pins NV_ADMIN_TOTP_SECRET.
            log.error("MFA state cannot be decrypted (did NV_SECRET_KEY change?). Logins are blocked; see README > MFA reset.")
            self.corrupt, state = True, {}
        self.state = state
        if get_settings().mfa_reset:
            log.warning("NV_MFA_RESET is set: MFA has been cleared. Remove NV_MFA_RESET and re-enroll!")
            self.state = {"epoch": int(state.get("epoch", 0))}
            self.corrupt = False
            self._bump_epoch()
            await self._save()
        set_session_epoch(self.state.get("epoch", 0))

    async def _save(self) -> None:
        blob = encrypt_blob(self.state)
        async with sessionmaker()() as db:
            row = await db.get(Setting, "mfa")
            if row is None:
                db.add(Setting(key="mfa", value=blob))
            else:
                row.value = blob
            await db.commit()

    def _bump_epoch(self) -> None:
        self.state["epoch"] = int(self.state.get("epoch", 0)) + 1
        set_session_epoch(self.state["epoch"])

    # ----------------------------------------------------------------- status
    @property
    def env_secret(self) -> str:
        return get_settings().admin_totp_secret.replace(" ", "").upper()

    @property
    def enabled(self) -> bool:
        return bool(self.env_secret) or bool(self.state.get("enabled")) or self.corrupt

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "source": "env" if self.env_secret else ("database" if self.state.get("enabled") else None),
            "managed_by_env": bool(self.env_secret),
            "recovery_codes_remaining": len(self.state.get("recovery", [])) if not self.env_secret else None,
            "enabled_at": self.state.get("enabled_at"),
            "error": "MFA state unreadable - NV_SECRET_KEY changed?" if self.corrupt else None,
        }

    # ---------------------------------------------------------- verification
    def _check_totp(self, secret: str, code: str, last_step_key: str) -> bool:
        code = code.strip().replace(" ", "")
        if not (code.isdigit() and len(code) == 6):
            return False
        totp = pyotp.TOTP(secret)
        now = time.time()
        for drift in (0, -1, 1):
            step = int(now // 30) + drift
            if hmac.compare_digest(totp.at(step * 30), code):
                if step <= int(self.state.get(last_step_key, -1)):
                    return False  # replay of an already-used code
                self.state[last_step_key] = step
                return True
        return False

    async def verify(self, code: str) -> bool:
        """Verify a login code: TOTP, or a single-use recovery code."""
        if self.corrupt and not self.env_secret:
            return False
        async with self._lock:
            secret = self.env_secret or self.state.get("secret", "")
            if secret and self._check_totp(secret, code, "last_step"):
                await self._save()
                return True
            if not self.env_secret:
                h = _hash_code(code)
                codes: list[str] = self.state.get("recovery", [])
                match = next((c for c in codes if hmac.compare_digest(c, h)), None)
                if match:
                    codes.remove(match)
                    await self._save()
                    log.warning("Recovery code used for login; %d remaining", len(codes))
                    return True
        return False

    # ------------------------------------------------------------- enrolment
    async def begin_setup(self, username: str) -> dict[str, Any]:
        if self.env_secret:
            raise ValueError("MFA is managed by NV_ADMIN_TOTP_SECRET")
        async with self._lock:
            secret = pyotp.random_base32(32)
            self.state["pending_secret"] = secret
            self.state["pending_at"] = time.time()
            await self._save()
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)
        qr = segno.make(uri, error="m")
        return {"secret": secret, "otpauth_uri": uri,
                "qr_svg": qr.svg_data_uri(scale=6, border=2, dark="#e6f1ff", light="#070b16")}

    async def enable(self, code: str) -> list[str]:
        async with self._lock:
            secret = self.state.get("pending_secret")
            if not secret or time.time() - self.state.get("pending_at", 0) > 900:
                raise ValueError("Setup expired - start again")
            if not self._check_totp(secret, code, "pending_last_step"):
                raise ValueError("That code didn't match. Check your phone's clock and try the next code.")
            codes = _new_recovery_codes()
            self.state.update(enabled=True, secret=secret, recovery=[_hash_code(c) for c in codes],
                              enabled_at=time.time(), last_step=self.state.get("pending_last_step", -1))
            for k in ("pending_secret", "pending_at", "pending_last_step"):
                self.state.pop(k, None)
            self.corrupt = False
            self._bump_epoch()
            await self._save()
        log.info("MFA enabled for the admin account")
        return codes

    async def disable(self) -> None:
        if self.env_secret:
            raise ValueError("MFA is managed by NV_ADMIN_TOTP_SECRET - unset it to disable")
        async with self._lock:
            epoch = int(self.state.get("epoch", 0))
            self.state = {"epoch": epoch}
            self.corrupt = False
            self._bump_epoch()
            await self._save()
        log.warning("MFA disabled for the admin account")

    async def regenerate_recovery(self) -> list[str]:
        if self.env_secret or not self.state.get("enabled"):
            raise ValueError("MFA is not enabled in the UI")
        async with self._lock:
            codes = _new_recovery_codes()
            self.state["recovery"] = [_hash_code(c) for c in codes]
            await self._save()
        return codes


mfa = MfaService()
