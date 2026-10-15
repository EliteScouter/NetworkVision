from __future__ import annotations

import asyncio
import contextlib
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..security import websocket_user
from ..services.bus import bus
from ..services.state import store

router = APIRouter()


@router.websocket("/api/ws")
async def live(ws: WebSocket) -> None:
    if not websocket_user(ws):
        await ws.close(code=4401)
        return
    # Same-origin check: browsers always send Origin on WebSocket handshakes.
    origin, host = ws.headers.get("origin"), ws.headers.get("host")
    if origin and host and origin.split("://", 1)[-1] != host:
        await ws.close(code=4403)
        return
    await ws.accept()
    q = bus.subscribe()
    try:
        await ws.send_json({"type": "state", "ts": time.time(), "devices": [d.summary() for d in store.devices.values()]})

        async def pump() -> None:
            while True:
                await ws.send_json(await q.get())

        async def drain() -> None:  # detect client disconnects / answer pings
            while True:
                msg = await ws.receive_text()
                if msg == "ping":
                    await ws.send_json({"type": "pong", "ts": time.time()})

        tasks = [asyncio.create_task(pump()), asyncio.create_task(drain())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        for t in done:  # a closed tab ends one task with WebSocketDisconnect: that's normal
            if not t.cancelled() and (exc := t.exception()) and not isinstance(exc, (WebSocketDisconnect, RuntimeError)):
                raise exc
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        bus.unsubscribe(q)
