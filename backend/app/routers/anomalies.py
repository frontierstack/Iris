"""GET /api/anomalies — every rule (built-in or custom) with ≥1 hit in the active case."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from ..anomalies import ready as anomalies_ready, status as anomalies_status

router = APIRouter(prefix="/anomalies", tags=["anomalies"])


@router.get("")
def list_anomalies(sev: Optional[str] = None, limit: int = 100) -> dict:
    """The aggregation is built ONCE per (store version, rules revision) in the background — see
    app/anomalies.py. `sev` and `limit` slice that cached, already-sorted list; nothing here walks the
    event pool. While a build is in flight the response is empty with `status.state == 'building'` and
    a `pct`, which the Anomalies screen renders as progress: an empty list with no status reads as
    "no rule has fired", and that is a false statement about the evidence."""
    sev_filter = {s.strip().lower() for s in (sev or "").split(",") if s.strip()}
    rows = anomalies_ready()
    status = anomalies_status()
    if rows is None:
        return {"total": 0, "anomalies": [], "status": status}
    out = [a for a in rows if a.sev in sev_filter] if sev_filter else rows
    return {"total": len(out), "anomalies": out[: max(0, limit)], "status": status}
