"""Tiny in-process pub/sub used to stream live updates to WebSocket clients."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subs: set[asyncio.Queue[dict[str, Any]]] = set()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._subs.discard(q)

    def publish(self, msg: dict[str, Any]) -> None:
        for q in list(self._subs):
            if q.full():  # slow client: drop its oldest message rather than block everyone
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(msg)

    @property
    def subscribers(self) -> int:
        return len(self._subs)


bus = EventBus()
