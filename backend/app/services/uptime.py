"""Service (uptime) monitoring for the things you host: HTTP(S), TCP, DNS and TLS certificate checks.

Checks run from the NetworkVision host, each service on its own interval. A service is
only declared down after ``fail_threshold`` consecutive failures (one dropped packet is
not an outage); that opens an incident and a critical alert, both closed by the next
success. Every result lands in the "service" history series (raw samples + hourly
rollups), so 90-day uptime reads a few thousand rollup rows rather than 130k samples.

Checking from inside your own network cannot see what outside visitors see (NAT
reflection, split DNS, an ISP outage) - the README explains pairing this with an
external probe.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import math
import random
import re
import socket
import ssl
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from sqlalchemy import insert, select, update

from .. import __version__
from ..config import get_settings
from ..db import delete_in_chunks, sessionmaker, with_retry
from ..models import Service, ServiceCheck, ServiceCheckHourly, ServiceIncident, Setting
from .alerts import Condition
from .alerts import engine as alert_engine
from .bus import bus

log = logging.getLogger("networkvision.uptime")

KINDS = ("http", "tcp", "dns", "tls")
HOUR = 3600
DAY = 86400
WINDOWS = {"24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY, "90d": 90 * DAY}
BAR_DAYS = 90
CERT_TTL = 3600  # an HTTPS service's certificate is re-read hourly, not every check
MAX_BODY = 1_000_000  # keyword search reads at most this much of a response
SPARK_LEN = 60
FLUSH_EVERY = 10
FLUSH_BATCH = 500
CONCURRENCY = 16

DEFAULTS: dict[str, Any] = {
    "fail_threshold": 3,  # consecutive failures before "down"
    "slow_ms": None,  # warn when the response takes at least this long
    "expected_status": "200-399",  # http
    "keyword": "",  # http: must appear in the body (case-insensitive)
    "method": "GET",  # http: GET | HEAD
    "follow_redirects": True,  # http
    "verify_tls": True,  # http: reject invalid certificates
    "check_cert": True,  # http(s): also track the certificate's expiry
    "record_type": "A",  # dns: A | AAAA | ANY
    "expected": [],  # dns: every resolved address must be one of these
    "sni": "",  # tls: server name to present/verify (default: the target)
    "cert_warn_days": 21,
    "cert_crit_days": 7,
}

_HOST_RE = re.compile(r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$")
_STATUS_RE = re.compile(r"^([1-5])xx$|^(\d{3})(?:-(\d{3}))?$")


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def valid_host(v: str) -> bool:
    return bool(v) and (is_ip(v) or bool(_HOST_RE.match(v)))


def parse_status_ranges(spec: str) -> list[tuple[int, int]]:
    """``"200-299,301,4xx"`` -> [(200, 299), (301, 301), (400, 499)]."""
    out: list[tuple[int, int]] = []
    for part in (p.strip().lower() for p in spec.split(",")):
        if not part:
            continue
        m = _STATUS_RE.match(part)
        if not m:
            raise ValueError(f"invalid status code range '{part}' (use e.g. 200-399, 204, 2xx)")
        if m.group(1):
            lo = int(m.group(1)) * 100
            out.append((lo, lo + 99))
            continue
        lo, hi = int(m.group(2)), int(m.group(3) or m.group(2))
        if not (100 <= lo <= hi <= 599):
            raise ValueError(f"invalid status code range '{part}'")
        out.append((lo, hi))
    if not out:
        raise ValueError("expected_status must list at least one code or range")
    return out


def _bounded_int(v: Any, lo: int, hi: int, name: str) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{name} must be a whole number") from e
    if not lo <= n <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return n


def normalize(kind: str, target: str, port: int | None, config: dict[str, Any] | None) -> tuple[str, int | None, dict[str, Any]]:
    """Validate a service definition. Returns the cleaned (target, port, config); raises ValueError."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    target = (target or "").strip()
    if not target or any(ord(c) < 33 for c in target):
        raise ValueError("target must not be empty or contain spaces")
    raw = dict(config or {})
    cfg: dict[str, Any] = {"fail_threshold": _bounded_int(raw.get("fail_threshold", 3), 1, 20, "fail_threshold")}
    slow = raw.get("slow_ms")
    cfg["slow_ms"] = None if slow in (None, "", 0) else _bounded_int(slow, 1, 120_000, "slow_ms")

    if kind == "http":
        parts = urlsplit(target)
        if parts.scheme.lower() not in ("http", "https"):
            raise ValueError("URL must start with http:// or https://")
        if parts.username or parts.password:
            raise ValueError("URL must not contain credentials")
        try:
            url_port = parts.port
        except ValueError as e:
            raise ValueError("URL has an invalid port") from e
        if not valid_host((parts.hostname or "").strip("[]")):
            raise ValueError("URL must contain a valid hostname or IP address")
        if len(target) > 2048:
            raise ValueError("URL is too long")
        port = url_port
        parse_status_ranges(str(raw.get("expected_status") or "200-399"))
        cfg["expected_status"] = str(raw.get("expected_status") or "200-399").replace(" ", "")
        cfg["keyword"] = str(raw.get("keyword") or "")[:256]
        method = str(raw.get("method") or "GET").upper()
        if method not in ("GET", "HEAD"):
            raise ValueError("method must be GET or HEAD")
        if method == "HEAD" and cfg["keyword"]:
            raise ValueError("a keyword check needs the GET method")
        cfg["method"] = method
        for k in ("follow_redirects", "verify_tls", "check_cert"):
            cfg[k] = bool(raw.get(k, DEFAULTS[k]))
    else:
        host = target.strip("[]")
        if "://" in target or not valid_host(host):
            raise ValueError("target must be a hostname or IP address (no scheme, path or credentials)")
        target = host
        if kind == "dns":
            if is_ip(target):
                raise ValueError("a DNS check needs a hostname, not an IP address")
            port = None
            rtype = str(raw.get("record_type") or "A").upper()
            if rtype not in ("A", "AAAA", "ANY"):
                raise ValueError("record_type must be A, AAAA or ANY")
            cfg["record_type"] = rtype
            expected = raw.get("expected") or []
            if isinstance(expected, str):
                expected = [x for x in re.split(r"[\s,]+", expected) if x]
            if len(expected) > 16:
                raise ValueError("at most 16 expected addresses")
            try:
                cfg["expected"] = sorted({str(ipaddress.ip_address(str(x).strip())) for x in expected})
            except ValueError as e:
                raise ValueError("expected addresses must be IP addresses") from e
        else:
            port = _bounded_int(port if port is not None else (443 if kind == "tls" else None), 1, 65535, "port")
    if kind in ("tls", "http"):
        sni = str(raw.get("sni") or "").strip()
        if sni and (is_ip(sni) or not valid_host(sni)):
            raise ValueError("sni must be a hostname")
        if kind == "tls":
            cfg["sni"] = sni
        warn = _bounded_int(raw.get("cert_warn_days", 21), 1, 365, "cert_warn_days")
        crit = _bounded_int(raw.get("cert_crit_days", 7), 0, 365, "cert_crit_days")
        if crit >= warn:
            raise ValueError("cert_crit_days must be lower than cert_warn_days")
        cfg["cert_warn_days"], cfg["cert_crit_days"] = warn, crit
    return target, port, cfg


def service_dict(s: Service) -> dict[str, Any]:
    return {
        "id": s.id, "name": s.name, "kind": s.kind, "target": s.target, "port": s.port, "enabled": s.enabled,
        "interval_s": s.interval_s, "timeout_s": s.timeout_s, "config": {**DEFAULTS, **(s.config or {})},
        "tags": s.tags or [], "notes": s.notes or "", "created_at": s.created_at, "updated_at": s.updated_at,
    }


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
@dataclass
class CertInfo:
    not_after: float
    days_left: float
    issuer: str
    subject: str
    sans: list[str]
    san_match: bool
    valid: bool
    error: str = ""


@dataclass
class CheckResult:
    ok: bool
    response_ms: float | None = None
    error: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    cert: CertInfo | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "response_ms": self.response_ms, "error": self.error, "detail": self.detail,
                "cert": asdict(self.cert) if self.cert else None}


def san_matches(name: str, sans: list[str]) -> bool:
    """RFC 6125 matching: exact, or a single left-most ``*`` label (``*.example.com``)."""
    name = name.lower().rstrip(".")
    if is_ip(name):
        target = ipaddress.ip_address(name)
        return any(is_ip(s) and ipaddress.ip_address(s) == target for s in sans)
    for s in (x.lower().rstrip(".") for x in sans):
        if s == name:
            return True
        if s.startswith("*.") and "." in name:
            head, rest = name.split(".", 1)
            if head and rest == s[2:] and "." in rest:
                return True
    return False


def _name_attr(name: x509.Name, *oids: x509.ObjectIdentifier) -> str:
    for oid in oids:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return name.rfc4514_string()


def parse_cert(der: bytes, server_name: str, now: float | None = None) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    now = time.time() if now is None else now
    not_after = cert.not_valid_after_utc.timestamp()
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = [*ext.get_values_for_type(x509.DNSName), *(str(i) for i in ext.get_values_for_type(x509.IPAddress))]
    except x509.ExtensionNotFound:
        sans = [str(a.value) for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    match = san_matches(server_name, sans)
    days = (not_after - now) / DAY
    error = "certificate has expired" if days <= 0 else ("" if match else f"certificate does not cover {server_name}")
    return CertInfo(not_after=not_after, days_left=round(days, 2),
                    issuer=_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME),
                    subject=_name_attr(cert.subject, NameOID.COMMON_NAME), sans=sans[:50], san_match=match,
                    valid=not error, error=error)


async def _handshake(host: str, port: int, server_name: str, ctx: ssl.SSLContext, timeout: float) -> bytes:
    _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_name), timeout)
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 2)
    if not der:
        raise ssl.SSLError("server sent no certificate")
    return der


async def tls_probe(host: str, port: int, server_name: str, timeout: float,
                    ca_context: ssl.SSLContext | None = None) -> CertInfo:
    """Handshake with full verification; on a verification failure, re-read the cert unverified to report on it."""
    verify_error = ""
    try:
        der = await _handshake(host, port, server_name, ca_context or ssl.create_default_context(), timeout)
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message or str(e)
        loose = ssl.create_default_context()
        loose.check_hostname, loose.verify_mode = False, ssl.CERT_NONE
        der = await _handshake(host, port, server_name, loose, timeout)
    info = parse_cert(der, server_name)
    if verify_error:
        info.valid, info.error = False, info.error or verify_error
    return info


def _err(e: BaseException, timeout: float) -> str:
    if isinstance(e, (asyncio.TimeoutError, TimeoutError, httpx.TimeoutException)):
        return f"timed out after {timeout:g}s"
    if isinstance(e, ssl.SSLCertVerificationError):
        return f"TLS: {e.verify_message or e}"
    if isinstance(e, socket.gaierror):
        return f"DNS lookup failed: {e.strerror or e}"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused"
    msg = str(e) or type(e).__name__
    return msg if isinstance(e, httpx.HTTPError) else f"{type(e).__name__}: {msg}"


async def check_http(svc: dict[str, Any], transport: httpx.AsyncBaseTransport | None = None) -> CheckResult:
    cfg, timeout = svc["config"], float(svc["timeout_s"])
    ranges = parse_status_ranges(cfg["expected_status"])
    keyword = cfg.get("keyword") or ""
    try:
        async with httpx.AsyncClient(transport=transport, follow_redirects=cfg["follow_redirects"], verify=cfg["verify_tls"],
                                     timeout=httpx.Timeout(timeout), headers={"User-Agent": f"NetworkVision-uptime/{__version__}"}) as c:
            t0 = time.perf_counter()
            async with c.stream(cfg["method"], svc["target"]) as r:
                elapsed = (time.perf_counter() - t0) * 1000  # time to response headers
                body = b""
                if keyword:
                    async for chunk in r.aiter_bytes():
                        body += chunk
                        if len(body) >= MAX_BODY:
                            break
    except (httpx.HTTPError, OSError, ssl.SSLError) as e:
        return CheckResult(False, error=_err(e, timeout)[:255])
    detail: dict[str, Any] = {"status_code": r.status_code, "url": str(r.url)}
    if r.history:
        detail["redirects"] = len(r.history)
    if not any(lo <= r.status_code <= hi for lo, hi in ranges):
        return CheckResult(False, elapsed, f"HTTP {r.status_code} (expected {cfg['expected_status']})", detail)
    if keyword and keyword.lower() not in body.decode(r.encoding or "utf-8", errors="replace").lower():
        return CheckResult(False, elapsed, f"keyword '{keyword}' not found"[:255], detail)
    return CheckResult(True, elapsed, detail=detail)


async def check_tcp(svc: dict[str, Any]) -> CheckResult:
    timeout = float(svc["timeout_s"])
    t0 = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(svc["target"], svc["port"]), timeout)
    except (TimeoutError, OSError) as e:
        return CheckResult(False, error=_err(e, timeout)[:255])
    elapsed = (time.perf_counter() - t0) * 1000
    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 2)
    return CheckResult(True, elapsed, detail={"port": svc["port"]})


async def resolve(host: str, family: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


async def check_dns(svc: dict[str, Any]) -> CheckResult:
    cfg, timeout = svc["config"], float(svc["timeout_s"])
    family = {"A": socket.AF_INET, "AAAA": socket.AF_INET6}.get(cfg["record_type"], socket.AF_UNSPEC)
    t0 = time.perf_counter()
    try:
        addrs = await asyncio.wait_for(resolve(svc["target"], family), timeout)
    except (TimeoutError, OSError) as e:
        return CheckResult(False, error=_err(e, timeout)[:255])
    elapsed = (time.perf_counter() - t0) * 1000
    detail = {"addresses": addrs}
    if not addrs:
        return CheckResult(False, elapsed, "no addresses returned", detail)
    expected = set(cfg.get("expected") or [])
    if expected:
        unexpected = [a for a in addrs if str(ipaddress.ip_address(a)) not in expected]
        if unexpected:
            return CheckResult(False, elapsed, f"unexpected address {', '.join(unexpected)}"[:255], detail)
    return CheckResult(True, elapsed, detail=detail)


async def check_tls(svc: dict[str, Any]) -> CheckResult:
    timeout = float(svc["timeout_s"])
    name = svc["config"].get("sni") or svc["target"]
    t0 = time.perf_counter()
    try:
        cert = await tls_probe(svc["target"], svc["port"], name, timeout)
    except (TimeoutError, OSError, ssl.SSLError, ValueError) as e:
        return CheckResult(False, error=_err(e, timeout)[:255])
    # Reachable = up; a bad certificate is its own (critical) alert and makes the card degraded.
    return CheckResult(True, (time.perf_counter() - t0) * 1000, detail={"port": svc["port"]}, cert=cert)


def demo_result(svc: dict[str, Any]) -> CheckResult:
    """Simulated results for NV_DEMO_MODE (never touches the network)."""
    rnd = random.Random(f"{svc['id']}:{int(time.time() // 60)}")
    base = 40 + (svc["id"] * 37) % 180
    ok = rnd.random() > (0.08 if svc["id"] % 4 == 0 else 0.005)
    cert = None
    if svc["kind"] == "tls" or (svc["kind"] == "http" and svc["target"].startswith("https")):
        days = 5 + (svc["id"] * 23) % 80
        host = urlsplit(svc["target"]).hostname if svc["kind"] == "http" else svc["target"]
        cert = CertInfo(time.time() + days * DAY, float(days), "Let's Encrypt", host or "demo", [host or "demo"], True, True)
    if not ok:
        return CheckResult(False, error="connection refused")
    return CheckResult(True, base * rnd.uniform(0.7, 1.6), detail={"status_code": 200} if svc["kind"] == "http" else {}, cert=cert)


# --------------------------------------------------------------------------- #
# Monitor
# --------------------------------------------------------------------------- #
@dataclass
class SvcState:
    status: str = "pending"  # pending | up | degraded | down | paused
    fails: int = 0
    slow_hits: int = 0
    first_fail_ts: float | None = None
    last_ts: float | None = None
    last_ok_ts: float | None = None
    last: dict[str, Any] = field(default_factory=dict)
    cert: CertInfo | None = None
    cert_ts: float = 0
    cert_error: str = ""
    incident_id: int | None = None
    incident_started: float | None = None
    next_due: float = 0
    running: bool = False
    spark: deque = field(default_factory=lambda: deque(maxlen=SPARK_LEN))


class UptimeMonitor:
    def __init__(self) -> None:
        self.services: dict[int, dict[str, Any]] = {}
        self.state: dict[int, SvcState] = {}
        self.transport: httpx.AsyncBaseTransport | None = None
        self.demo = False
        self._buffer: list[dict[str, Any]] = []
        self._sem: asyncio.Semaphore | None = None
        self._tasks: set[asyncio.Task] = set()
        self._stats_cache: tuple[float, dict[int, dict[str, Any]]] | None = None

    # ------------------------------------------------------------- lifecycle
    async def load(self) -> None:
        self.demo = get_settings().demo_mode
        self._sem = asyncio.Semaphore(CONCURRENCY)
        now = time.time()
        async with sessionmaker()() as db:
            rows = (await db.execute(select(Service))).scalars().all()
            open_inc = (await db.execute(select(ServiceIncident).where(ServiceIncident.ended_at.is_(None)))).scalars().all()
            recent = (await db.execute(select(ServiceCheck.service_id, ServiceCheck.ts, ServiceCheck.response_ms, ServiceCheck.status)
                                       .where(ServiceCheck.ts >= now - 2 * HOUR).order_by(ServiceCheck.ts))).all()
        self.services = {s.id: service_dict(s) for s in rows}
        self.state = {}
        for sid, svc in self.services.items():
            st = self._st(sid)
            st.next_due = now + random.uniform(2, min(15, svc["interval_s"]))
        for inc in open_inc:
            if inc.service_id in self.state:
                st = self.state[inc.service_id]
                st.status, st.incident_id, st.incident_started = "down", inc.id, inc.started_at
                st.fails, st.first_fail_ts = self.services[inc.service_id]["config"]["fail_threshold"], inc.started_at
        for sid, ts, ms, status in recent:
            if sid in self.state:
                self.state[sid].spark.append([ts, ms if status else None])
        log.info("Service monitor ready (%d services)", len(self.services))

    def _st(self, sid: int) -> SvcState:
        st = self.state.get(sid)
        if st is None:
            st = self.state[sid] = SvcState()
        svc = self.services.get(sid)
        if svc and not svc["enabled"]:
            st.status = "paused"
        elif st.status == "paused":
            st.status = "pending"
        return st

    async def run(self) -> None:
        last_flush = time.monotonic()
        while True:
            try:
                now = time.time()
                for sid, svc in list(self.services.items()):
                    st = self._st(sid)
                    if svc["enabled"] and not st.running and now >= st.next_due:
                        st.running = True
                        st.next_due = now + svc["interval_s"]
                        task = asyncio.create_task(self._guarded(sid), name=f"svc-check-{sid}")
                        self._tasks.add(task)
                        task.add_done_callback(self._tasks.discard)
                if time.monotonic() - last_flush >= FLUSH_EVERY:
                    await self.flush()
                    last_flush = time.monotonic()
            except Exception:  # noqa: BLE001 - the scheduler must never die
                log.exception("Service scheduler tick failed")
            await asyncio.sleep(1)

    async def stop(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        with contextlib.suppress(Exception):
            await self.flush()

    async def _guarded(self, sid: int) -> None:
        try:
            assert self._sem is not None
            async with self._sem:
                await self.check(sid)
        except Exception:  # noqa: BLE001
            log.exception("Service check %s crashed", sid)
        finally:
            if sid in self.state:
                self.state[sid].running = False

    # ------------------------------------------------------------- checks
    async def execute(self, svc: dict[str, Any]) -> CheckResult:
        """Run one check for a service definition (does not record anything)."""
        if self.demo:
            await asyncio.sleep(0)
            return demo_result(svc)
        kind = svc["kind"]
        if kind == "http":
            res = await check_http(svc, self.transport)
        elif kind == "tcp":
            res = await check_tcp(svc)
        elif kind == "dns":
            res = await check_dns(svc)
        else:
            res = await check_tls(svc)
        return res

    async def _http_cert(self, svc: dict[str, Any], st: SvcState | None) -> tuple[CertInfo | None, str]:
        parts = urlsplit(svc["target"])
        if parts.scheme != "https" or not svc["config"].get("check_cert", True):
            return None, ""
        if st and st.cert_ts and time.time() - st.cert_ts < CERT_TTL:
            return st.cert, st.cert_error
        host = (parts.hostname or "").strip("[]")
        try:
            return await tls_probe(host, parts.port or 443, host, float(svc["timeout_s"])), ""
        except (TimeoutError, OSError, ssl.SSLError, ValueError) as e:
            return (st.cert if st else None), _err(e, float(svc["timeout_s"]))[:255]

    async def test(self, svc: dict[str, Any]) -> dict[str, Any]:
        res = await self.execute(svc)
        if svc["kind"] == "http" and not self.demo and res.cert is None:
            res.cert, _ = await self._http_cert(svc, None)
        return res.as_dict()

    async def check(self, sid: int) -> dict[str, Any] | None:
        svc = self.services.get(sid)
        if svc is None:
            return None
        res = await self.execute(svc)
        st = self._st(sid)
        if svc["kind"] == "http" and res.cert is None and not self.demo:
            cert, err = await self._http_cert(svc, st)
            if cert is not None or err:
                st.cert, st.cert_error, st.cert_ts = cert, err, time.time()
        elif res.cert is not None or svc["kind"] == "tls":
            st.cert, st.cert_error, st.cert_ts = res.cert, "", time.time()
        if sid not in self.services:  # deleted while the check ran
            return None
        await self._record(svc, st, res)
        return self.snapshot(sid)

    async def _record(self, svc: dict[str, Any], st: SvcState, res: CheckResult) -> None:
        sid, cfg, now = svc["id"], svc["config"], time.time()
        need = int(cfg["fail_threshold"])
        st.last_ts, st.last = now, res.as_dict()
        st.last.pop("cert", None)
        st.spark.append([now, res.response_ms if res.ok else None])
        self._buffer.append({"ts": now, "service_id": sid, "status": 1 if res.ok else 0, "response_ms": res.response_ms,
                             "cert_days": st.cert.days_left if st.cert else None, "error": res.error[:255]})
        if res.ok:
            st.last_ok_ts = now
            if st.incident_id is not None:
                await self._close_incident(st, now)
            st.fails, st.first_fail_ts = 0, None
            slow = cfg.get("slow_ms")
            st.slow_hits = st.slow_hits + 1 if slow and res.response_ms is not None and res.response_ms >= slow else 0
        else:
            st.fails += 1
            st.slow_hits = 0
            if st.first_fail_ts is None:
                st.first_fail_ts = now
            if st.fails >= need and st.incident_id is None:
                await self._open_incident(sid, st, res.error)
        prev, down = st.status, st.incident_id is not None
        cert_bad = bool(st.cert and (not st.cert.valid or st.cert.days_left < cfg["cert_warn_days"]))
        if down:
            st.status = "down"
        elif not res.ok or st.slow_hits >= need or cert_bad:
            st.status = "degraded"  # failing but not yet confirmed, slow, or a certificate problem
        else:
            st.status = "up"
        if st.status != prev:
            self._stats_cache = None
        await alert_engine.sync_external(f"svc:{sid}:", self.conditions(svc, st, res))
        bus.publish({"type": "service", "service_id": sid, "state": self.snapshot(sid)["state"]})

    def conditions(self, svc: dict[str, Any], st: SvcState, res: CheckResult) -> list[Condition]:
        sid, name, cfg = svc["id"], svc["name"], svc["config"]
        p = f"svc:{sid}:"
        out: list[Condition] = []
        if st.incident_id is not None:
            since = time.strftime("%H:%M", time.localtime(st.incident_started or time.time()))
            out.append(Condition(p + "down", "service_down", "critical", f"{name} is down",
                                 f"{res.error or 'check failing'} · {st.fails} failed checks since {since}", debounce=False))
            return out  # slow/cert noise is irrelevant while it's unreachable
        if st.slow_hits >= int(cfg["fail_threshold"]) and res.response_ms is not None:
            out.append(Condition(p + "slow", "service_slow", "warning", f"{name} is responding slowly",
                                 f"{res.response_ms:.0f} ms (threshold {cfg['slow_ms']} ms)", debounce=False))
        c = st.cert
        if c is not None:
            when = time.strftime("%Y-%m-%d", time.gmtime(c.not_after))
            if not c.valid:
                out.append(Condition(p + "cert", "cert_invalid", "critical", f"Invalid TLS certificate on {name}",
                                     f"{c.error} (issuer {c.issuer}, expires {when})", debounce=False))
            elif c.days_left < cfg["cert_warn_days"]:
                sev = "critical" if c.days_left < cfg["cert_crit_days"] else "warning"
                days = max(0, math.floor(c.days_left))
                out.append(Condition(p + "cert", "cert_expiring", sev, f"TLS certificate for {name} expires in {days} days",
                                     f"Expires {when} · issuer {c.issuer}", debounce=False))
        return out

    async def _open_incident(self, sid: int, st: SvcState, error: str) -> None:
        started = st.first_fail_ts or time.time()

        async def _w(db) -> int:
            inc = ServiceIncident(service_id=sid, started_at=started, error=error[:255], checks_failed=st.fails)
            db.add(inc)
            await db.commit()
            return inc.id

        st.incident_id, st.incident_started = await with_retry(_w), started
        log.warning("Service %s is DOWN: %s", self.services.get(sid, {}).get("name", sid), error)

    async def _close_incident(self, st: SvcState, now: float) -> None:
        inc_id, fails = st.incident_id, st.fails

        async def _w(db) -> None:
            await db.execute(update(ServiceIncident).where(ServiceIncident.id == inc_id).values(ended_at=now, checks_failed=fails))
            await db.commit()

        await with_retry(_w)
        st.incident_id, st.incident_started = None, None
        self._stats_cache = None

    async def flush(self) -> int:
        """Write buffered results in small transactions (Galera-friendly write sets)."""
        n = 0
        while self._buffer:
            batch, self._buffer = self._buffer[:FLUSH_BATCH], self._buffer[FLUSH_BATCH:]
            alive = [r for r in batch if r["service_id"] in self.services]
            if not alive:
                continue

            async def _w(db, rows=alive) -> None:
                await db.execute(insert(ServiceCheck), rows)
                await db.commit()

            try:
                await with_retry(_w)
                n += len(alive)
                cached = self._stats_cache[1] if self._stats_cache else {}
                if any(cached.get(r["service_id"], {}).get("uptime", {}).get("24h") is None for r in alive):
                    self._stats_cache = None  # a brand-new service: show its first numbers now, not in a minute
            except Exception:  # noqa: BLE001
                self._buffer = alive + self._buffer if len(self._buffer) < 20_000 else self._buffer
                raise
        return n

    # ------------------------------------------------------------- CRUD hooks
    def upsert(self, svc: dict[str, Any]) -> None:
        prev = self.services.get(svc["id"])
        self.services[svc["id"]] = svc
        st = self._st(svc["id"])
        if prev is None or any(prev[k] != svc[k] for k in ("kind", "target", "port", "config", "enabled")):
            st.next_due, st.cert_ts = time.time(), 0  # re-check now with the new definition
        self._stats_cache = None

    async def remove(self, sid: int) -> None:
        self.services.pop(sid, None)
        self.state.pop(sid, None)
        self._buffer = [r for r in self._buffer if r["service_id"] != sid]
        await alert_engine.sync_external(f"svc:{sid}:", [])
        self._stats_cache = None

    async def pause_alerts(self, sid: int) -> None:
        """A disabled service keeps its history but must not keep alerts (or an incident) open."""
        st = self.state.get(sid)
        if st and st.incident_id is not None:
            await self._close_incident(st, time.time())
        if st:
            st.fails, st.slow_hits, st.first_fail_ts, st.status = 0, 0, None, "paused"
        await alert_engine.sync_external(f"svc:{sid}:", [])

    # ------------------------------------------------------------- read side
    def snapshot(self, sid: int) -> dict[str, Any]:
        st = self._st(sid)
        return {
            "id": sid,
            "state": {
                "status": st.status, "last_ts": st.last_ts, "last_ok_ts": st.last_ok_ts, "fails": st.fails,
                "response_ms": st.last.get("response_ms") if st.last.get("ok") else None, "error": st.last.get("error", ""),
                "detail": st.last.get("detail", {}), "incident_started": st.incident_started, "running": st.running,
                "next_due": st.next_due if self.services.get(sid, {}).get("enabled") else None,
                "cert": asdict(st.cert) if st.cert else None, "cert_error": st.cert_error,
                "spark": [p[1] for p in st.spark],
            },
        }

    async def stats(self, now: float | None = None) -> dict[int, dict[str, Any]]:
        """Uptime % per window and BAR_DAYS daily bars (oldest first) for every service. Cached for a minute."""
        now = time.time() if now is None else now
        if self._stats_cache and now - self._stats_cache[0] < 60:
            return self._stats_cache[1]
        since = now - BAR_DAYS * DAY
        samples: dict[int, list[tuple[float, float, float]]] = {}  # sid -> (ts, n, up)
        async with sessionmaker()() as db:
            wm_row = await db.get(Setting, "rollup:service")
            wm = float(wm_row.value) if wm_row and wm_row.value else None
            if wm is not None:
                h = ServiceCheckHourly
                for sid, ts, n, avg in (await db.execute(select(h.service_id, h.ts, h.samples, h.status_avg)
                                                         .where(h.ts >= since, h.ts <= wm))).all():
                    if n and avg is not None:
                        samples.setdefault(sid, []).append((ts + HOUR / 2, float(n), float(avg) * n))
            raw_from = max(since, wm + HOUR) if wm is not None else since
            r = ServiceCheck
            for sid, ts, status in (await db.execute(select(r.service_id, r.ts, r.status).where(r.ts >= raw_from))).all():
                samples.setdefault(sid, []).append((ts, 1.0, float(status)))
        out: dict[int, dict[str, Any]] = {}
        for sid in self.services:
            rows = samples.get(sid, [])
            uptime: dict[str, float | None] = {}
            for label, span in WINDOWS.items():
                n = sum(x[1] for x in rows if x[0] >= now - span)
                uptime[label] = round(100 * sum(x[2] for x in rows if x[0] >= now - span) / n, 3) if n else None
            n_b, up_b = [0.0] * BAR_DAYS, [0.0] * BAR_DAYS
            for ts, n, up in rows:
                i = BAR_DAYS - 1 - int((now - ts) // DAY)
                if 0 <= i < BAR_DAYS:
                    n_b[i] += n
                    up_b[i] += up
            out[sid] = {"uptime": uptime, "bars": [round(100 * u / n, 2) if n else None for n, u in zip(n_b, up_b, strict=True)]}
        self._stats_cache = (now, out)
        return out

    async def incidents(self, service_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        q = select(ServiceIncident).order_by(ServiceIncident.started_at.desc()).limit(limit)
        if service_id is not None:
            q = q.where(ServiceIncident.service_id == service_id)
        async with sessionmaker()() as db:
            rows = (await db.execute(q)).scalars().all()
        now = time.time()
        return [{"id": i.id, "service_id": i.service_id, "service": self.services.get(i.service_id, {}).get("name"),
                 "started_at": i.started_at, "ended_at": i.ended_at, "duration_s": (i.ended_at or now) - i.started_at,
                 "error": i.error, "checks_failed": i.checks_failed, "ongoing": i.ended_at is None} for i in rows]


async def purge_service(sid: int) -> None:
    """Delete a service's samples in small batches before the row itself (no giant cascade write set)."""
    await delete_in_chunks(ServiceCheck, ServiceCheck.service_id == sid)
    await delete_in_chunks(ServiceCheckHourly, ServiceCheckHourly.service_id == sid)
    await delete_in_chunks(ServiceIncident, ServiceIncident.service_id == sid)


monitor = UptimeMonitor()
