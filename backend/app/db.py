"""Async SQLAlchemy engine/session. Works with SQLite (default) and MariaDB/MySQL."""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

from sqlalchemy import ColumnElement, delete, event, select, text
from sqlalchemy.exc import DBAPIError
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
            # READ COMMITTED avoids gap locks, which cause needless certification
            # conflicts on Galera clusters; harmless on a single MariaDB server.
            kwargs.update(pool_size=10, max_overflow=10, pool_recycle=1800, isolation_level="READ COMMITTED")
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
        if conn.dialect.name in ("mysql", "mariadb"):
            await conn.run_sync(_upgrade_single_precision)
    safe = engine().url.render_as_string(hide_password=True)
    log.info("Database ready (%s)", safe)


def _upgrade_single_precision(conn) -> None:
    """Releases before 0.3.1 created MySQL ``FLOAT`` (single precision) columns, which
    round epoch timestamps to ~128 s. Convert any such column to ``DOUBLE`` in place."""
    rows = conn.execute(text(
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_schema = DATABASE() AND data_type = 'float'")).all()
    for table_name, column_name in rows:
        table = Base.metadata.tables.get(table_name)
        if table is None or column_name not in table.c:
            continue  # not ours
        null = "NULL" if table.c[column_name].nullable else "NOT NULL"
        log.warning("Upgrading %s.%s from FLOAT to DOUBLE (timestamp precision fix)", table_name, column_name)
        conn.execute(text(f"ALTER TABLE `{table_name}` MODIFY `{column_name}` DOUBLE {null}"))


# MariaDB/Galera errors that are safe to retry: deadlock / certification failure,
# lock wait timeout, node not ready (WSREP), and dropped connections (node failover).
RETRYABLE_MYSQL_CODES = {1213, 1205, 1047, 1180, 2006, 2013}


def _is_retryable(exc: BaseException) -> bool:
    orig = getattr(exc, "orig", None)
    args = getattr(orig, "args", ()) or ()
    return bool(args) and isinstance(args[0], int) and args[0] in RETRYABLE_MYSQL_CODES


async def with_retry[T](fn: Callable[[AsyncSession], Awaitable[T]], attempts: int = 4) -> T:
    """Run ``fn(session)`` in a fresh session/transaction, retrying transient cluster errors.

    ``fn`` must be idempotent per attempt (it gets a new session each time) and commit itself.
    """
    for attempt in range(1, attempts + 1):
        try:
            async with sessionmaker()() as db:
                return await fn(db)
        except DBAPIError as e:
            if attempt == attempts or not _is_retryable(e):
                raise
            delay = 0.1 * 2**attempt + random.random() * 0.1
            log.warning("Transient database error (%s), retry %d/%d in %.2fs", e.orig, attempt, attempts - 1, delay)
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable")


async def delete_in_chunks(model: type, where: ColumnElement[bool], batch: int = 5000) -> int:
    """Delete matching rows in small transactions.

    One huge DELETE is a single giant Galera write set: it stalls the whole cluster
    (flow control) or exceeds wsrep_max_ws_size. Small batches replicate smoothly.
    """
    total = 0
    pk = model.__table__.primary_key.columns.values()[0]
    while True:
        async def _one(db: AsyncSession) -> int:
            ids = (await db.execute(select(pk).where(where).limit(batch))).scalars().all()
            if ids:
                await db.execute(delete(model).where(pk.in_(ids)))
                await db.commit()
            return len(ids)

        n = await with_retry(_one)
        total += n
        if n < batch:
            return total
        await asyncio.sleep(0.05)  # let replication breathe between batches


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
