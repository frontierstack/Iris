"""Timeline endpoints: correlated clusters, and the indicators placed alongside them."""
from __future__ import annotations

from fastapi import APIRouter, Query

from ..store import STORE

router = APIRouter(prefix="/timeline", tags=["timeline"])


@router.get("")
def timeline(scope: str = Query("all", pattern="^(all|case)$")) -> dict:
    """scope=case re-runs correlation over only the curated case-set events.

    The correlation pass is O(the whole pool) — 30 s at 1.2 M events — and used to run on THIS thread
    whenever the store version had moved. It is now built in the background (store.analysis_ready);
    while that is in flight the request returns at once with empty clusters and `status.state ==
    'building'`, which the Timeline screen renders as progress rather than a spinner.

    Indicators are NOT folded into this response: extracting them is its own O(pool) pass and would
    put the clusters behind it. They come from GET /api/timeline/iocs, which the screen fetches
    alongside this one so each has its own loading state.
    """
    a = STORE.analysis_ready(scope)
    status = STORE.analysis_status(scope)
    if a is None:
        return {"stats": {"window": "0s", "clusters": 0, "entities": 0, "egress": "0 B"},
                "clusters": [], "status": status}
    return {"stats": a["stats"], "clusters": [c.model_dump() for c in a["clusters"]], "status": status}


@router.get("/iocs")
def timeline_iocs(scope: str = Query("all", pattern="^(all|case)$"),
                  limit: int = Query(200, ge=1, le=1000)) -> dict:
    """Indicators as timeline markers — each at the moment it was FIRST seen, with the event it came from.

    "When did we first see this indicator" was previously answerable only by opening the IOC panel and
    reading a column; the incident chronology showed clusters and nothing else. Markers are ordered
    earliest first so the screen can interleave them with the clusters.
    """
    from .iocs import ioc_markers
    markers = ioc_markers(scope, limit)
    return {"total": len(markers), "iocs": [m.model_dump() for m in markers]}
