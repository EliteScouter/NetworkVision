"""Async SQLAlchemy engine/session. Works with SQLite (default) and MariaDB/MySQL."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings

log = logging.getLogger("networkvision.db")


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        s = get_settings()
        url = s.sqlalchemy_url
        kwargs: dict = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            Path(s.data_dir).mkdir(parents=True, exist_ok=True)
            kwargs = {"connect_args": {"timeout": 30}}
        else:
            kwargs.update(pool_size=10, max_overflow=10, pool_recycle=1800)
        _engine = create_async_engine(url, **kwargs)
        if url.startswith("sqlite"):

            @event.listens_for(_engine.sync_engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _):  # pragma: no cover - trivial
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()

        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as session:
        yield session


async def init_db() -> None:
    from . import models  # noqa: F401  (register tables)

    async with engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    safe = engine().url.render_as_string(hide_password=True)
    log.info("Database ready (%s)", safe)


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
