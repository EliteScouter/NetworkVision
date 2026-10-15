"""KeePass (.kdbx) secret provider.

Mount a KeePass database read-only into the container and reference entries from
any credential field:

    kp:Network/pfSense            -> password of entry "pfSense" in group "Network"
    kp:Network/UniFi#username     -> the username field
    kp:Network/pfSense#api_key    -> a custom string field
    kp:pfSense                    -> title only (must be unique in the database)

Recommended: a *dedicated* small .kdbx that only holds NetworkVision's device
credentials (not your personal vault), since the container needs its master key.
The file is re-read automatically when it changes on disk.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

from ..config import get_settings
from ..security import SecretError

log = logging.getLogger("networkvision.keepass")
STANDARD_FIELDS = {"password", "username", "url", "notes", "title"}


class KeePassProvider:
    def __init__(self) -> None:
        self._db = None
        self._mtime: float | None = None
        self._lock = threading.Lock()
        self.error: str | None = None
        self.loaded_at: float | None = None
        self.version = 0  # bumped on every successful (re)load so collectors can refresh

    @property
    def configured(self) -> bool:
        return bool(get_settings().keepass_file)

    def _load(self):
        s = get_settings()
        if not s.keepass_file:
            raise SecretError("KeePass is not configured (set NV_KEEPASS_FILE)")
        try:
            mtime = os.stat(s.keepass_file).st_mtime
        except OSError as e:
            self.error = f"Cannot read {s.keepass_file}: {e.strerror}"
            raise SecretError(self.error) from e
        if self._db is not None and mtime == self._mtime:
            return self._db
        from pykeepass import PyKeePass
        from pykeepass.exceptions import CredentialsError, HeaderChecksumError, PayloadChecksumError

        try:
            db = PyKeePass(s.keepass_file, password=s.keepass_password or None, keyfile=s.keepass_keyfile or None)
        except (CredentialsError, HeaderChecksumError, PayloadChecksumError) as e:
            self.error = "KeePass database could not be unlocked (wrong NV_KEEPASS_PASSWORD / keyfile?)"
            raise SecretError(self.error) from e
        except Exception as e:  # noqa: BLE001 - corrupt/unsupported file
            self.error = f"KeePass database could not be opened: {type(e).__name__}"
            raise SecretError(self.error) from e
        self._db, self._mtime, self.error, self.loaded_at = db, mtime, None, time.time()
        self.version += 1
        log.info("KeePass database loaded (%d entries)", len(db.entries))
        return db

    def check(self) -> int:
        """Reload if the file changed; returns the current version (cheap: one stat call)."""
        if not self.configured:
            return self.version
        with self._lock:
            try:
                self._load()
            except SecretError:
                pass
        return self.version

    def _find(self, db, ref: str):
        path = [p for p in ref.split("/") if p]
        if not path:
            raise SecretError("Empty KeePass reference")
        entry = db.find_entries(path=path) if len(path) > 1 else None
        if entry is None:
            matches = [e for e in db.find_entries(title=path[-1]) or [] if not self._in_recycle_bin(db, e)]
            if len(path) > 1:
                matches = [e for e in matches if (e.path or [])[:-1] == path[:-1]]
            if len(matches) > 1:
                raise SecretError(f"KeePass reference '{ref}' is ambiguous - use the full Group/Entry path")
            entry = matches[0] if matches else None
        if entry is None:
            raise SecretError(f"KeePass entry '{ref}' not found")
        return entry

    @staticmethod
    def _in_recycle_bin(db, entry) -> bool:
        rb = db.recyclebin_group
        return bool(rb is not None and entry.group is not None and rb.uuid in {g.uuid for g in _ancestors(entry.group)})

    def resolve(self, ref: str) -> str:
        ref, _, field = ref.partition("#")
        field = field.strip() or "password"
        with self._lock:
            db = self._load()
            entry = self._find(db, ref.strip())
            if field.lower() in STANDARD_FIELDS:
                value = getattr(entry, field.lower())
            else:
                value = (entry.custom_properties or {}).get(field)
                if value is None:
                    raise SecretError(f"KeePass entry '{ref}' has no field '{field}'")
        if not value:
            raise SecretError(f"KeePass entry '{ref}' has an empty {field}")
        return str(value)

    def entries(self) -> list[dict[str, Any]]:
        """Entry paths and field *names* for the UI picker. Never returns secret values."""
        with self._lock:
            db = self._load()
            out = []
            for e in db.entries:
                if self._in_recycle_bin(db, e):
                    continue
                out.append({
                    "ref": "/".join(e.path or [e.title or ""]),
                    "title": e.title or "",
                    "group": "/".join((e.path or [])[:-1]),
                    "has_username": bool(e.username),
                    "has_password": bool(e.password),
                    "custom_fields": sorted((e.custom_properties or {}).keys()),
                })
        return sorted(out, key=lambda x: x["ref"].lower())

    def status(self) -> dict[str, Any]:
        s = get_settings()
        if not self.configured:
            return {"configured": False}
        self.check()
        return {"configured": True, "ok": self.error is None and self._db is not None, "error": self.error,
                "file": os.path.basename(s.keepass_file), "entries": len(self._db.entries) if self._db else 0,
                "loaded_at": self.loaded_at, "keyfile": bool(s.keepass_keyfile)}


def _ancestors(group):
    while group is not None:
        yield group
        group = group.parentgroup


keepass = KeePassProvider()
