"""NetworkVision - application entrypoint."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from . import __version__
from .api import auth, data, devices, ws
from .api import history as history_api
from .api import network as network_api
from .api import services as services_api
from .api import speedtest as speedtest_api
from .collectors import registry
from .config import get_settings
from .db import dispose, init_db
from .security import auth_configured, require_user
from .services import notifier, syslog
from .services.bus import bus
from .services.keepass import keepass
from .services.logs import pipeline
from .services.mfa import mfa
from .services.poller import poller
from .services.speedtest import speedtest
from .services.uptime import monitor as uptime_monitor


def _setup_logging() -> None:
    s = get_settings()
    logging.basicConfig(level=s.log_level.upper(), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("pysnmp").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(_: FastAPI):
    _setup_logging()
    log = logging.getLogger("networkvision")
    s = get_settings()
    log.info("NetworkVision %s starting (demo=%s)", __version__, s.demo_mode)
    if not auth_configured():
        log.warning("No admin password set (NV_ADMIN_PASSWORD / NV_ADMIN_PASSWORD_HASH) - logins are impossible")
    await init_db()
    await mfa.load()
    if keepass.configured:
        st = await asyncio.to_thread(keepass.status)
        if st.get("ok"):
            log.info("KeePass secret provider ready (%s, %d entries)", st["file"], st["entries"])
        else:
            log.error("KeePass secret provider: %s", st.get("error"))
    if s.demo_mode:
        from .demo_seed import seed_demo

        await seed_demo()
    log_task = asyncio.create_task(pipeline.run(), name="log-pipeline")
    handles = await syslog.start()
    await poller.start()
    await speedtest.load()
    speed_task = asyncio.create_task(speedtest.scheduler(), name="speedtest-scheduler")
    await uptime_monitor.load()
    uptime_task = asyncio.create_task(uptime_monitor.run(), name="uptime-scheduler")
    try:
        yield
    finally:
        await poller.stop()
        for h in handles:
            h.close()
        for task in (log_task, speed_task, uptime_task):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await uptime_monitor.stop()
        await dispose()


app = FastAPI(title="NetworkVision", version=__version__, lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if not request.url.path.startswith("/api/docs"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws: wss:; font-src 'self' data:; frame-ancestors 'none'",
        )
    return response


app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(data.router)
app.include_router(history_api.router)
app.include_router(network_api.router)
app.include_router(speedtest_api.router)
app.include_router(services_api.router)
app.include_router(ws.router)


@app.get("/api/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/meta")
async def meta(_: str = Depends(require_user)) -> dict:
    s = get_settings()
    return {
        "version": __version__, "demo_mode": s.demo_mode, "poll_interval": s.poll_interval,
        "syslog": {"enabled": s.syslog_enabled, "port": s.syslog_port, "tcp": s.syslog_tcp_enabled},
        "database": "sqlite" if s.sqlalchemy_url.startswith("sqlite") else "mariadb",
        "notifications": notifier.enabled(), "ws_clients": bus.subscribers,
        "logs": {"received": pipeline.received, "dropped": pipeline.dropped},
        "collectors": [c["kind"] for c in registry.available()],
        "retention": {"metrics_days": s.retention_days_metrics, "logs_days": s.retention_days_logs},
        "thresholds": {"cpu": s.alert_cpu_pct, "mem": s.alert_mem_pct, "temp": s.alert_temp_c,
                       "latency_ms": s.alert_latency_ms, "loss_pct": s.alert_loss_pct,
                       "if_util": s.alert_if_util_pct, "if_errors": s.alert_if_errors_per_min},
    }


# --------------------------------------------------------------- SPA frontend
_static = Path(get_settings().static_dir).resolve()
if (_static / "index.html").exists():
    if (_static / "assets").exists():
        app.mount("/assets", StaticFiles(directory=_static / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        candidate = (_static / path).resolve()
        if path and candidate.is_file() and _static in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(_static / "index.html", headers={"Cache-Control": "no-cache"})
