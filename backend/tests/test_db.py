"""Galera-safety helpers: chunked deletes and retry of transient cluster errors."""

import os

import pytest
from sqlalchemy import func, insert, select
from sqlalchemy.exc import OperationalError


@pytest.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setenv("NV_SECRET_KEY", "test-secret-key-for-unit-tests-only-0123456789")
    monkeypatch.setenv("NV_DATA_DIR", str(tmp_path))
    from app import db as dbmod
    from app.config import get_settings

    get_settings.cache_clear()
    await dbmod.dispose()
    await dbmod.init_db()
    yield dbmod
    await dbmod.dispose()
    get_settings.cache_clear()
    os.environ.pop("NV_DATA_DIR", None)


class _MySQLError(Exception):
    pass


def _galera_error(code: int) -> OperationalError:
    return OperationalError("INSERT ...", {}, _MySQLError(code, "simulated"))


async def test_delete_in_chunks_removes_only_matching(db):
    from app.models import LogEntry

    async with db.sessionmaker()() as s:
        await s.execute(insert(LogEntry), [{"ts": float(i), "message": f"m{i}"} for i in range(2500)])
        await s.commit()
    removed = await db.delete_in_chunks(LogEntry, LogEntry.ts < 2000, batch=300)
    assert removed == 2000
    async with db.sessionmaker()() as s:
        assert (await s.execute(select(func.count(LogEntry.id)))).scalar() == 500


async def test_with_retry_recovers_from_deadlock(db, monkeypatch):
    monkeypatch.setattr("app.db.asyncio.sleep", _no_sleep)
    calls = []

    async def flaky(_session):
        calls.append(1)
        if len(calls) < 3:
            raise _galera_error(1213)  # Galera certification failure / deadlock
        return "ok"

    assert await db.with_retry(flaky) == "ok"
    assert len(calls) == 3


async def test_with_retry_does_not_retry_real_errors(db, monkeypatch):
    monkeypatch.setattr("app.db.asyncio.sleep", _no_sleep)
    calls = []

    async def broken(_session):
        calls.append(1)
        raise _galera_error(1064)  # SQL syntax error: retrying cannot help

    with pytest.raises(OperationalError):
        await db.with_retry(broken)
    assert len(calls) == 1


async def _no_sleep(_s):
    return None
