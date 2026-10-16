"""Shared helpers for HTTPS/REST based collectors."""

from __future__ import annotations

import re
from typing import Any

import httpx

from .base import Collector, CollectorError, FieldSpec

TLS_FIELDS = [
    FieldSpec(key="scheme", label="Scheme", type="select", options=["https", "http"], default="https"),
    FieldSpec(key="port", label="Port", type="number", default=443),
    FieldSpec(key="verify_tls", label="Verify TLS certificate", type="bool", default=False,
              help="Most homelab gear uses self-signed certs. Enable if you have a real cert."),
    FieldSpec(key="timeout", label="Timeout (s)", type="number", default=10),
]


class HttpCollector(Collector):
    def __init__(self, host: str, config: dict[str, Any], secrets: dict[str, Any]) -> None:
        super().__init__(host, config, secrets)
        self._client: httpx.AsyncClient | None = None

    @property
    def base_url(self) -> str:
        scheme = self.opt("scheme") or "https"
        port = int(self.opt("port") or (443 if scheme == "https" else 80))
        default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        return f"{scheme}://{host}" + ("" if default else f":{port}")

    def client(self, **kwargs: Any) -> httpx.AsyncClient:
        if self._client is None:
            verify = self.opt("verify_tls") in (True, "true", "1", 1)
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                verify=verify,
                timeout=float(self.opt("timeout") or 10),
                headers={"User-Agent": "NetworkVision", "Accept": "application/json"},
                follow_redirects=False,
                **kwargs,
            )
        return self._client

    async def request_json(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            r = await self.client().request(method, path, **kwargs)
        except httpx.ConnectError as e:
            raise CollectorError(f"Cannot connect to {self.base_url}: {e}") from e
        except httpx.TimeoutException as e:
            raise CollectorError(f"Timeout talking to {self.base_url}") from e
        if r.is_redirect:
            where = r.headers.get("location", "?")
            raise CollectorError(
                f"{self.base_url}{path} redirected (HTTP {r.status_code}) to {where} - "
                "the scheme or port is probably wrong (e.g. http vs https, or the web GUI runs on another port)")
        if r.status_code in (401, 403):
            raise CollectorError(f"Authentication failed ({r.status_code}) for {path}")
        if r.status_code == 404:
            raise NotFound(path)
        if r.status_code >= 400:
            raise CollectorError(f"HTTP {r.status_code} for {path}: {r.text[:200]}")
        try:
            return r.json()
        except ValueError as e:
            raise CollectorError(f"Non-JSON response for {path}: {describe_body(r)}") from e

    async def try_json(self, method: str, path: str, **kwargs: Any) -> Any:
        """Like request_json but returns None for optional endpoints that fail."""
        try:
            return await self.request_json(method, path, **kwargs)
        except (CollectorError, NotFound):
            return None

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class NotFound(CollectorError):
    pass


_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def describe_body(r: httpx.Response) -> str:
    """Explain an unexpected non-JSON reply (usually an HTML page from the wrong service/port)."""
    ctype = r.headers.get("content-type", "unknown").split(";")[0]
    text = r.text or ""
    hint = ""
    if "html" in ctype or text.lstrip().lower().startswith(("<!doctype", "<html")):
        m = _TITLE.search(text)
        title = " ".join(m.group(1).split())[:80] if m else ""
        hint = f' - got an HTML page{f" titled {title!r}" if title else ""}'
        if any(w in text.lower() for w in ("login", "password", "sign in")):
            hint += "; it looks like a web login page, so the API isn't answering on this scheme/port"
        else:
            hint += "; another web server may be answering on this port"
    elif not text.strip():
        hint = " - the body was empty"
    return f"HTTP {r.status_code}, content-type {ctype}{hint}"


_NUM = re.compile(r"-?\d+(?:\.\d+)?")


def first_number(v: Any) -> float | None:
    """'1.234ms' -> 1.234, '0.0 %' -> 0.0, 12 -> 12.0"""
    if isinstance(v, (int, float)):
        return float(v)
    if not isinstance(v, str):
        return None
    m = _NUM.search(v.replace(",", "."))
    return float(m.group()) if m else None


def pick(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return default
