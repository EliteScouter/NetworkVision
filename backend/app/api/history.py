"""One endpoint behind every chart's history explorer."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..security import require_user
from ..services import history

router = APIRouter(prefix="/api", tags=["history"], dependencies=[Depends(require_user)])


@router.get("/history/{kind}")
async def get_history(
    kind: str,
    device_id: int | None = None,
    ifname: str | None = None,
    name: str | None = None,
    radio: str | None = None,
    range_: str = Query("24h", alias="range"),
    since: float | None = None,
    until: float | None = None,
    points: int = Query(300, ge=20, le=1500),
) -> dict:
    """``range`` = 15m|1h|6h|24h|7d|30d|90d|1y, or pass ``since``/``until`` (epoch seconds) for a custom window."""
    if kind not in history.SERIES:
        raise HTTPException(404, f"Unknown series '{kind}'. Valid: {', '.join(history.SERIES)}")
    try:
        start, end = history.resolve_range(range_, since, until)
        filters = {"device_id": device_id, "ifname": ifname, "name": name, "radio": radio}
        return await history.query(kind, filters, start, end, points)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
