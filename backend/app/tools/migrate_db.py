"""Copy a NetworkVision database to another one (e.g. SQLite -> MariaDB/Galera).

Run inside the container (it has the data volume and the drivers):

    python -m app.tools.migrate_db \\
        --source sqlite:////data/networkvision.db \\
        --target "mysql+pymysql://networkvision:${NV_DB_PASSWORD}@10.0.0.20:3306/networkvision?charset=utf8mb4"

Without --target, the NV_DB_* environment variables are used. The target schema is
created automatically; the copy refuses to run if the target already contains
devices (use --force to append anyway). Rows keep their IDs, are copied in
dependency order, in small transactions (Galera friendly), and counts are
verified at the end. Encrypted credentials move as-is, so keep NV_SECRET_KEY.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from urllib.parse import quote_plus

from sqlalchemy import create_engine, func, insert, select, text

from .. import models  # noqa: F401  (registers every table)
from ..db import Base

BATCH = 1000


def default_target() -> str:
    pw = os.environ.get("NV_DB_PASSWORD", "")
    return (f"mysql+pymysql://{quote_plus(os.environ.get('NV_DB_USER', 'networkvision'))}:{quote_plus(pw)}"
            f"@{os.environ.get('NV_DB_HOST', 'localhost')}:{os.environ.get('NV_DB_PORT', '3306')}"
            f"/{os.environ.get('NV_DB_NAME', 'networkvision')}?charset=utf8mb4")


def sync_url(url: str) -> str:
    """Accept the app's async URLs too."""
    return url.replace("sqlite+aiosqlite", "sqlite").replace("mysql+aiomysql", "mysql+pymysql")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default="sqlite:////data/networkvision.db")
    ap.add_argument("--target", default=None)
    ap.add_argument("--force", action="store_true", help="copy even if the target already has devices")
    args = ap.parse_args(argv)

    src = create_engine(sync_url(args.source))
    dst = create_engine(sync_url(args.target or default_target()), pool_pre_ping=True)
    print(f"source: {src.url.render_as_string(hide_password=True)}")
    print(f"target: {dst.url.render_as_string(hide_password=True)}")

    Base.metadata.create_all(dst)
    tables = Base.metadata.sorted_tables  # parents before children
    with dst.connect() as c:
        existing = c.execute(select(func.count()).select_from(Base.metadata.tables["devices"])).scalar()
    if existing and not args.force:
        print(f"ABORT: target already has {existing} device(s). Use --force to append.", file=sys.stderr)
        return 2

    mysql = dst.dialect.name in ("mysql", "mariadb")
    started = time.time()
    report = []
    for table in tables:
        pk = list(table.primary_key.columns)
        order = pk[0] if pk else None
        copied = 0
        with src.connect() as s:
            total = s.execute(select(func.count()).select_from(table)).scalar() or 0
            offset = 0
            while offset < total:
                q = select(table)
                if order is not None:
                    q = q.order_by(order)
                rows = [dict(r._mapping) for r in s.execute(q.limit(BATCH).offset(offset))]
                if not rows:
                    break
                with dst.begin() as d:
                    if mysql:
                        # devices.parent_id references devices itself; checks are per-session only.
                        d.execute(text("SET SESSION foreign_key_checks = 0"))
                    d.execute(insert(table), rows)
                copied += len(rows)
                offset += len(rows)
        with dst.connect() as d:
            now_in_target = d.execute(select(func.count()).select_from(table)).scalar()
        report.append((table.name, total, now_in_target))
        print(f"  {table.name:<26} {total:>9,} rows -> target has {now_in_target:,}")

    bad = [r for r in report if r[2] < r[1]]
    print(f"done in {time.time() - started:.1f}s")
    if bad:
        print("WARNING: these tables have fewer rows in the target:", ", ".join(r[0] for r in bad), file=sys.stderr)
        return 1
    print("All tables verified. Now set NV_DB_DRIVER=mariadb (+ NV_DB_HOST etc.) and restart NetworkVision.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
