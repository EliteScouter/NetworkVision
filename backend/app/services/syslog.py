"""Syslog receiver (UDP + TCP). Point every device's remote syslog at NetworkVision.

Inside the container it binds an unprivileged port (default 5514); publish it as
514/udp (and 514/tcp) on the host in your compose file.
"""

from __future__ import annotations

import asyncio
import logging
import time

from ..config import get_settings
from ..syslog_parser import parse_syslog
from .logs import pipeline

log = logging.getLogger("networkvision.syslog")


def _ingest(raw: bytes, addr: str) -> None:
    text = raw.decode("utf-8", "replace")
    for line in text.splitlines() or [text]:
        if not line.strip():
            continue
        p = parse_syslog(line, fallback_host=addr, received=time.time())
        pipeline.submit({
            "ts": p.ts, "device_id": pipeline.device_for(addr, p.host), "host": p.host or addr,
            "severity": p.severity, "facility": p.facility, "app": p.app, "message": p.message, "source": "syslog",
        })


class _UdpProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        _ingest(data, addr[0])


async def _tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    addr = writer.get_extra_info("peername")[0]
    try:
        while not reader.at_eof():
            head = await reader.read(1)
            if not head:
                break
            if head.isdigit():  # RFC 6587 octet counting: "123 <msg>"
                num = head + await reader.readuntil(b" ")
                data = await reader.readexactly(int(num.strip()))
            else:  # non-transparent framing (newline terminated)
                data = head + await reader.readuntil(b"\n")
            _ingest(data, addr)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()


async def start() -> list:
    s = get_settings()
    handles = []
    if not s.syslog_enabled:
        return handles
    loop = asyncio.get_running_loop()
    try:
        transport, _ = await loop.create_datagram_endpoint(_UdpProtocol, local_addr=("0.0.0.0", s.syslog_port))
        handles.append(transport)
        log.info("Syslog listening on udp/%d", s.syslog_port)
    except OSError as e:
        log.error("Cannot bind syslog udp/%d: %s", s.syslog_port, e)
    if s.syslog_tcp_enabled:
        try:
            server = await asyncio.start_server(_tcp_client, "0.0.0.0", s.syslog_port, limit=65536)
            handles.append(server)
            log.info("Syslog listening on tcp/%d", s.syslog_port)
        except OSError as e:
            log.error("Cannot bind syslog tcp/%d: %s", s.syslog_port, e)
    return handles
