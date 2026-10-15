"""Outbound notifications: generic webhook, Discord, Slack, ntfy. All optional, all via env."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ..config import get_settings

log = logging.getLogger("networkvision.notify")
RANK = {"info": 0, "warning": 1, "critical": 2}
COLORS = {"info": 0x38BDF8, "warning": 0xF59E0B, "critical": 0xF43F5E, "resolved": 0x22C55E}


def enabled() -> bool:
    s = get_settings()
    return any((s.notify_webhook_url, s.notify_discord_webhook_url, s.notify_ntfy_url, s.notify_slack_webhook_url))


async def notify(alert: dict[str, Any], resolved: bool = False) -> None:
    s = get_settings()
    if RANK.get(alert.get("severity", "info"), 0) < RANK.get(s.notify_min_severity, 1):
        return
    verb = "RESOLVED" if resolved else alert.get("severity", "").upper()
    title = f"[{verb}] {alert.get('title', '')}"
    body = alert.get("detail") or ""
    jobs = []
    async with httpx.AsyncClient(timeout=10) as c:
        if s.notify_webhook_url:
            jobs.append(c.post(s.notify_webhook_url, json={"event": "resolved" if resolved else "opened", "alert": alert}))
        if s.notify_discord_webhook_url:
            jobs.append(c.post(s.notify_discord_webhook_url, json={"username": "NetworkVision", "embeds": [{
                "title": title[:256], "description": body[:2000],
                "color": COLORS["resolved" if resolved else alert.get("severity", "info")],
            }]}))
        if s.notify_slack_webhook_url:
            jobs.append(c.post(s.notify_slack_webhook_url, json={"text": f"*{title}*\n{body}"}))
        if s.notify_ntfy_url:
            headers = {"Title": title[:200], "Priority": "5" if alert.get("severity") == "critical" and not resolved else "3",
                       "Tags": "white_check_mark" if resolved else ("rotating_light" if alert.get("severity") == "critical" else "warning")}
            if s.notify_ntfy_token:
                headers["Authorization"] = f"Bearer {s.notify_ntfy_token}"
            jobs.append(c.post(s.notify_ntfy_url, content=(body or title).encode(), headers=headers))
        for r in await asyncio.gather(*jobs, return_exceptions=True):
            if isinstance(r, Exception):
                log.warning("Notification failed: %s", r)
            elif r.status_code >= 400:
                log.warning("Notification endpoint returned HTTP %s", r.status_code)


def fire(alert: dict[str, Any], resolved: bool = False) -> None:
    if enabled():
        asyncio.get_running_loop().create_task(notify(alert, resolved))
