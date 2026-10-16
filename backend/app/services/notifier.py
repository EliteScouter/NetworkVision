"""Outbound notifications: generic webhook, Discord, Slack, ntfy.

All optional. Endpoints come from services.runtime: set in the UI (Settings >
Notifications) or via NV_NOTIFY_* env vars.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from .runtime import runtime

log = logging.getLogger("networkvision.notify")
RANK = {"info": 0, "warning": 1, "critical": 2}
COLORS = {"info": 0x38BDF8, "warning": 0xF59E0B, "critical": 0xF43F5E, "resolved": 0x22C55E}
CHANNELS = {"webhook": "notify_webhook_url", "discord": "notify_discord_webhook_url",
            "slack": "notify_slack_webhook_url", "ntfy": "notify_ntfy_url"}


def configured() -> list[str]:
    return [name for name, key in CHANNELS.items() if runtime.get(key)]


def enabled() -> bool:
    return bool(configured())


def _requests(c: httpx.AsyncClient, alert: dict[str, Any], resolved: bool) -> dict[str, Any]:
    verb = "RESOLVED" if resolved else alert.get("severity", "").upper()
    title = f"[{verb}] {alert.get('title', '')}"
    body = alert.get("detail") or ""
    jobs: dict[str, Any] = {}
    if url := runtime.get("notify_webhook_url"):
        jobs["webhook"] = c.post(url, json={"event": "resolved" if resolved else "opened", "alert": alert})
    if url := runtime.get("notify_discord_webhook_url"):
        jobs["discord"] = c.post(url, json={"username": "NetworkVision", "embeds": [{
            "title": title[:256], "description": body[:2000],
            "color": COLORS["resolved" if resolved else alert.get("severity", "info")],
        }]})
    if url := runtime.get("notify_slack_webhook_url"):
        jobs["slack"] = c.post(url, json={"text": f"*{title}*\n{body}"})
    if url := runtime.get("notify_ntfy_url"):
        headers = {"Title": title[:200], "Priority": "5" if alert.get("severity") == "critical" and not resolved else "3",
                   "Tags": "white_check_mark" if resolved else ("rotating_light" if alert.get("severity") == "critical" else "warning")}
        if token := runtime.get("notify_ntfy_token"):
            headers["Authorization"] = f"Bearer {token}"
        jobs["ntfy"] = c.post(url, content=(body or title).encode(), headers=headers)
    return jobs


async def _send(alert: dict[str, Any], resolved: bool) -> dict[str, dict[str, Any]]:
    async with httpx.AsyncClient(timeout=10) as c:
        jobs = _requests(c, alert, resolved)
        results = await asyncio.gather(*jobs.values(), return_exceptions=True)
    out: dict[str, dict[str, Any]] = {}
    for name, r in zip(jobs, results, strict=True):
        if isinstance(r, Exception):
            log.warning("Notification via %s failed: %s", name, r)
            out[name] = {"ok": False, "error": str(r)[:200] or type(r).__name__}
        elif r.status_code >= 400:
            log.warning("Notification endpoint %s returned HTTP %s", name, r.status_code)
            out[name] = {"ok": False, "error": f"HTTP {r.status_code}"}
        else:
            out[name] = {"ok": True, "status": r.status_code}
    return out


async def notify(alert: dict[str, Any], resolved: bool = False) -> None:
    if RANK.get(alert.get("severity", "info"), 0) < RANK.get(runtime.get("notify_min_severity"), 1):
        return
    await _send(alert, resolved)


async def send_test(user: str) -> dict[str, dict[str, Any]]:
    """Send a test message to every configured channel, ignoring the minimum severity."""
    alert = {"id": 0, "key": "test", "rule": "test", "severity": "info", "device_id": None, "device_name": None,
             "title": "NetworkVision test notification", "detail": f"Sent from Settings by {user}. If you can read this, it works."}
    return await _send(alert, resolved=False)


def fire(alert: dict[str, Any], resolved: bool = False) -> None:
    if enabled():
        asyncio.get_running_loop().create_task(notify(alert, resolved))
