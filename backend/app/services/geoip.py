"""Optional GeoIP (MaxMind GeoLite2 Country).

* Drop a ``GeoLite2-Country.mmdb`` into the data volume (or point NV_GEOIP_DB at one), or
* set NV_GEOIP_LICENSE_KEY (free MaxMind account) and it is downloaded and refreshed weekly.

Without either, everything still works - countries are simply not shown.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import logging
import os
import tarfile
import time
from functools import lru_cache
from pathlib import Path

import httpx

from ..config import get_settings
from ..security_parsers import is_internal, valid_ip

log = logging.getLogger("networkvision.geoip")
REFRESH_SECONDS = 7 * 86400
DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"

# Demo mode uses documentation address ranges for attackers; give them stable fake countries
# so the dashboard can show its country view without a MaxMind database.
_DEMO_COUNTRIES = ["CN", "RU", "US", "NL", "BR", "IN", "VN", "DE", "KR", "IR", "RO", "UA"]
_DEMO_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


class GeoIP:
    def __init__(self) -> None:
        self._reader = None
        self.source = "none"
        #: Why the automatic download isn't working (shown in the UI); None when fine or not configured.
        self.error: str | None = None
        self._kick: asyncio.Event | None = None  # created inside maintain(): bound to the running loop

    def kick(self) -> None:
        """The license key changed (Settings page): try a download now."""
        self.error = None
        if self._kick is not None:
            self._kick.set()

    @property
    def path(self) -> Path:
        s = get_settings()
        return Path(s.geoip_db) if s.geoip_db else Path(s.data_dir) / "GeoLite2-Country.mmdb"

    @property
    def enabled(self) -> bool:
        return self._reader is not None or self.source == "demo"

    def open(self) -> None:
        try:
            import maxminddb
        except ImportError:  # pragma: no cover - dependency is in requirements
            return
        if self.path.exists():
            try:
                old, self._reader = self._reader, maxminddb.open_database(str(self.path))
                if old is not None:
                    old.close()
                self.source = "maxmind"
                country.cache_clear()
                log.info("GeoIP database loaded (%s)", self.path.name)
            except (OSError, ValueError) as e:
                log.warning("Cannot open GeoIP database %s: %s", self.path, e)
        elif get_settings().demo_mode:
            self.source = "demo"

    def lookup(self, ip: str) -> str | None:
        if not ip or not valid_ip(ip) or is_internal(ip):
            return None
        if self._reader is not None:
            try:
                rec = self._reader.get(ip)
            except ValueError:
                return None
            if isinstance(rec, dict):
                c = rec.get("country") or rec.get("registered_country") or {}
                return c.get("iso_code")
            return None
        if self.source == "demo" and ip.startswith(_DEMO_NETS):
            h = int(hashlib.md5(ip.encode()).hexdigest()[:4], 16)
            return _DEMO_COUNTRIES[h % len(_DEMO_COUNTRIES)]
        return None

    async def maintain(self) -> None:
        """Download/refresh the database when a license key is configured."""
        self.open()
        self._kick = kick = asyncio.Event()
        while True:
            key = get_settings().geoip_license_key
            age = time.time() - self.path.stat().st_mtime if self.path.exists() else None
            ok = True
            forced = kick.is_set()
            kick.clear()
            if key and (forced or age is None or age > REFRESH_SECONDS):
                try:
                    ok = await self._download(key)
                except Exception as e:  # noqa: BLE001 - keep the loop alive
                    log.warning("GeoIP download failed: %s", type(e).__name__)
                    self.error, ok = f"GeoIP download failed ({type(e).__name__}).", False
            # Daily refresh check; hourly retries while broken; a key change in Settings wakes it at once.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(kick.wait(), timeout=86400 if ok and key else 3600)

    async def _download(self, key: str) -> bool:
        params = {"edition_id": "GeoLite2-Country", "license_key": key, "suffix": "tar.gz"}
        try:
            async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
                r = await c.get(DOWNLOAD_URL, params=params)
        except httpx.HTTPError as e:
            log.warning("GeoIP download failed: %s", type(e).__name__)  # never log the URL (contains the key)
            self.error = f"Cannot reach MaxMind ({type(e).__name__}); retrying hourly."
            return False
        if r.status_code != 200:
            log.warning("GeoIP download failed: HTTP %s (check NV_GEOIP_LICENSE_KEY)", r.status_code)
            self.error = (f"MaxMind rejected NV_GEOIP_LICENSE_KEY (HTTP {r.status_code}). Use a license key from "
                          "Account › Manage License Keys: 40 characters, ending in _mmk."
                          if r.status_code in (401, 403) else f"GeoIP download failed (HTTP {r.status_code}); retrying hourly.")
            return False
        with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.isfile() and m.name.endswith(".mmdb")), None)
            if member is None:
                log.warning("GeoIP archive did not contain a .mmdb file")
                self.error = "The MaxMind download did not contain a .mmdb file."
                return False
            data = tar.extractfile(member).read()  # type: ignore[union-attr]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, self.path)
        log.info("GeoIP database updated")
        self.error = None
        self.open()
        return True


geoip = GeoIP()


@lru_cache(maxsize=50_000)
def country(ip: str) -> str | None:
    return geoip.lookup(ip)
