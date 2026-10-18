"""The admin account created on the first-run setup page.

Native installs start without NV_ADMIN_PASSWORD, so the first browser to open the
dashboard is asked to create the admin account. The bcrypt hash is stored in the
``settings`` table (key ``admin``); once it exists, setup is locked for good.
Env credentials still work and take precedence (and are the way back in if the
stored password is forgotten).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

from sqlalchemy.exc import IntegrityError

from ..db import sessionmaker
from ..models import Setting
from ..security import env_admin_configured, hash_password, set_stored_admin, setup_required

log = logging.getLogger("networkvision.account")
KEY = "admin"


class SetupLocked(Exception):
    """An admin already exists (env or database)."""


class AdminAccount:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def load(self) -> None:
        async with sessionmaker()() as db:
            row = await db.get(Setting, KEY)
        account = None
        if row and row.value:
            try:
                data = json.loads(row.value)
                account = {"username": str(data["username"]), "hash": str(data["hash"])}
            except (ValueError, KeyError, TypeError):
                log.error("Stored admin account is unreadable - set NV_ADMIN_PASSWORD to sign in")
        set_stored_admin(account)
        if account and env_admin_configured():
            log.info("NV_ADMIN_PASSWORD(_HASH) is set - it takes precedence over the admin account created in the UI")

    async def create(self, username: str, password: str) -> None:
        async with self._lock:
            if not setup_required():
                raise SetupLocked
            hashed = await asyncio.to_thread(hash_password, password)
            value = json.dumps({"username": username, "hash": hashed, "created_at": time.time()})
            try:
                async with sessionmaker()() as db:
                    # Insert, never update: the primary key makes a second setup fail even across processes.
                    db.add(Setting(key=KEY, value=value))
                    await db.commit()
            except IntegrityError as e:
                await self.load()
                raise SetupLocked from e
            set_stored_admin({"username": username, "hash": hashed})
            log.warning("First-run setup: admin account %r created from the web UI", username)


account = AdminAccount()
