"""Charts on the active case: list, draw one, remove one.

The ASSISTANT draws these through `ai/tools.create_chart`, and both paths go through `app/charts.py`
for the same reason every other pair does in this codebase: two implementations of "what does this
query look like over time" would eventually disagree, and a chart that disagrees with the search
behind it is worse than no chart.

Charts live on the case (case.json) because they are a CONCLUSION about the evidence rather than part
of it — the same place, and the same lifecycle, as the graph links and the notes.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import charts as chart_build
from ..models import CaseChart
from ..store import STORE

router = APIRouter(prefix="/case/charts", tags=["charts"])


class ChartCreate(BaseModel):
    title: str
    kind: str = "line"
    mode: str = "time"
    queries: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    groupBy: str = ""
    bucket: str = "auto"
    points: int = 60
    note: str = ""
    sources: str = ""
    sev: str = ""
    rangeFrom: Optional[str] = None
    rangeTo: Optional[str] = None
    scope: str = "all"


@router.get("", response_model=list[CaseChart])
def list_charts() -> list[CaseChart]:
    with STORE.lock:
        rows = [dict(c) for c in STORE.charts]
    out: list[CaseChart] = []
    for row in rows:
        try:
            out.append(CaseChart.model_validate(row))
        except Exception:  # noqa: BLE001 — a chart is derived; dropping one costs a redraw
            continue
    return out


@router.post("", response_model=CaseChart)
def create_chart(body: ChartCreate) -> CaseChart:
    if STORE.pending:
        raise HTTPException(409, "there is no case to put a chart on — create one first")
    try:
        chart = chart_build.build(STORE, title=body.title, kind=body.kind, mode=body.mode,
                                  queries=list(body.queries), labels=list(body.labels),
                                  group_by=body.groupBy, bucket=body.bucket, points=body.points,
                                  sources=body.sources, sev=body.sev, frm=body.rangeFrom,
                                  to=body.rangeTo, scope=body.scope, note=body.note,
                                  created_by=STORE.analyst or "analyst")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    with STORE.lock:
        STORE.charts.append(chart.model_dump())
    STORE.save_meta()
    return chart


@router.delete("/{chart_id}", response_model=list[CaseChart])
def delete_chart(chart_id: str) -> list[CaseChart]:
    with STORE.lock:
        before = len(STORE.charts)
        STORE.charts = [c for c in STORE.charts if str(c.get("id") or "") != chart_id]
        gone = before - len(STORE.charts)
    if not gone:
        raise HTTPException(404, "no such chart on this case")
    STORE.save_meta()
    return list_charts()
