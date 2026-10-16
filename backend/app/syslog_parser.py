"""Tolerant syslog parser: RFC 5424, RFC 3164 (BSD) and the many vendor dialects
in between (pfSense, OPNsense, ProCurve, UniFi, TP-Link all differ slightly)."""

from __future__ import annotations

import re
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime

FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "security", "console", "solaris-cron", "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7",
]
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(
    r"^1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|(?:\[.*?\])+)\s?(?P<msg>.*)$",
    re.S,
)
_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$", re.S)
_BSD_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$", re.S)
_TAG = r"(?P<app>[A-Za-z0-9_.\-/()]{1,64})(?:\[\d+\])?:\s?(?P<msg>.*)$"
_HOST_APP = re.compile(r"^(?P<host>[\w.\-:]+)\s+" + _TAG, re.S)
_APP_ONLY = re.compile(r"^" + _TAG, re.S)
_HOSTLIKE = re.compile(r"^[\w.\-:]+$")


@dataclass
class ParsedSyslog:
    ts: float
    host: str
    severity: int
    facility: str
    app: str
    message: str
    #: True when the device sent a timestamp without a timezone (RFC 3164 / ISO without offset).
    naive: bool = False


def _parse_iso(s: str) -> float | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _parse_bsd(s: str) -> float | None:
    try:
        now = datetime.now()
        dt = datetime.strptime(f"{now.year} {' '.join(s.split())}", "%Y %b %d %H:%M:%S")
        if dt > now.replace(microsecond=0) and (dt - now).days > 1:  # December logs read in January
            dt = dt.replace(year=now.year - 1)
        return dt.timestamp()
    except ValueError:
        return None


def guess_severity(msg: str) -> int:
    m = msg.lower()
    if any(w in m for w in ("panic", "emerg", "kernel trap")):
        return 0
    if any(w in m for w in ("critical", " crit", "fatal")):
        return 2
    if any(w in m for w in ("error", "failed", "failure", "denied", "unreachable")):
        return 3
    if any(w in m for w in ("warn", "block", "down", "timeout", "flap", "loop", "dropped")):
        return 4
    return 6


def parse_syslog(raw: str, fallback_host: str = "", received: float | None = None) -> ParsedSyslog:
    received = received or time.time()
    line = raw.strip().strip("\x00").rstrip("\n")
    severity: int | None = None
    facility = ""
    m = _PRI.match(line)
    if m:
        pri = int(m.group(1))
        severity, fac = pri & 7, pri >> 3
        facility = FACILITIES[fac] if fac < len(FACILITIES) else str(fac)
        line = line[m.end():]

    ts: float | None = None
    naive = False
    host, app, msg = fallback_host, "", line

    m5 = _RFC5424.match(line)
    if m5:
        ts = _parse_iso(m5["ts"]) if m5["ts"] != "-" else None
        host = m5["host"] if m5["host"] != "-" else fallback_host
        app = m5["app"] if m5["app"] != "-" else ""
        msg = m5["msg"].lstrip("﻿")
    else:
        rest = line
        mi = _ISO.match(line)
        mb = None if mi else _BSD_TS.match(line)
        if mi:
            ts, rest = _parse_iso(mi["ts"]), mi["rest"]
            naive = not re.search(r"(Z|[+-]\d{2}:?\d{2})$", mi["ts"])
        elif mb:
            ts, rest = _parse_bsd(mb["ts"]), mb["rest"]
            naive = True
        msg = rest
        had_ts = bool(mi or mb)
        mh = _HOST_APP.match(rest) if had_ts else None
        ma = None if mh else _APP_ONLY.match(rest)
        if mh:
            host, app, msg = mh["host"], mh["app"], mh["msg"]
        elif ma:
            app, msg = ma["app"], ma["msg"]
        elif had_ts:
            parts = rest.split(None, 1)
            if len(parts) == 2 and _HOSTLIKE.match(parts[0]):
                host, msg = parts[0], parts[1]

    if severity is None:
        severity = guess_severity(msg)
    if ts is None or abs(ts - received) > 86400 * 2:
        ts, naive = received, False  # device clocks lie; never trust a wildly wrong timestamp
    return ParsedSyslog(ts=ts, host=host or fallback_host, severity=severity, facility=facility,
                        app=app[:64], message=msg.strip()[:8000], naive=naive)


class ClockSkew:
    """Learns each sender's timezone offset from timezone-less timestamps.

    Classic syslog (pfSense's default) stamps local time with no zone, so a firewall in
    UTC-7 would land 7 hours in the past in a UTC container. Live syslog arrives within
    milliseconds, so (arrival - stamped) is the sender's offset; rounded to 15-minute steps
    (covers every real timezone) and voted over recent lines so one late packet can't flip it.
    """

    STEP = 900
    MAX = 14 * 3600 + 900

    def __init__(self) -> None:
        self._votes: dict[object, deque[int]] = {}
        self._offset: dict[object, int] = {}

    def observe(self, key: object, stamped: float, received: float) -> None:
        delta = received - stamped
        if abs(delta) > self.MAX:
            return
        votes = self._votes.setdefault(key, deque(maxlen=25))
        votes.append(int(round(delta / self.STEP)) * self.STEP)
        self._offset[key] = Counter(votes).most_common(1)[0][0]

    def offset(self, key: object) -> int:
        return self._offset.get(key, 0)

    def snapshot(self) -> dict[str, int]:
        return {str(k): v for k, v in self._offset.items() if v}


skew = ClockSkew()
