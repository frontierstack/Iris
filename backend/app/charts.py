"""Charts the assistant can draw: a series computed from the EVIDENCE, never handed to Iris as numbers.

The analyst asked for the assistant to be able to build graphs, line graphs included. The mechanism
matters more than the picture, and there are two ways to build one:

  * the model works out the numbers and Iris draws them, or
  * the model names the QUESTION and Iris works out the numbers.

Only the second one is safe here. A chart is a claim about the evidence — an analyst reads a spike at
02:00 and believes 41 failures happened at 02:00 — and a model that types its own series can be
wrong in a way nothing on the screen can show. This project already refuses the same shape in three
other places: a tool that "expects the model to count rows" (see the aggregation tools), a citation
that cannot be resolved against the pool, and an arithmetic shortcut that replaces an OBSERVATION of
the pool with a BELIEF about it. So `build()` takes queries and computes every point through
`search_engine.search`, the SAME path the result list and the Search screen's histogram use — the
chart, the list and the count can never disagree about what matched, because there is one search.

What a chart therefore carries with it is its own provenance: the queries, the filters, the bucket
size, the totals, and whether the read was exact. Re-running it must reproduce it.

Two honesty rules, both inherited rather than invented:
  * AN EVENT WITH NO PARSED TIMESTAMP IS NEVER PLACED IN A BUCKET. Two-phase ingest means a raw
    source has no timestamps at all, so folding those in would draw a spike where the log is silent.
    They are counted in `withoutTimestamp` and the panel says so.
  * A BOUNDED READ NEVER CLAIMS TO BE THE WHOLE PICTURE. `search(positions=True)` stops at
    `_POSITIONS_CAP`; when it does, `exact` is False and `counted` says what was actually read.

The bucket ladder is `routers.events._BUCKET_LADDER`, imported rather than re-declared: an axis tick
has to be a round unit of time on every chart in the app, and two ladders would eventually differ.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import numpy as np

from . import search as search_engine
from .models import CaseChart, ChartSeries

UTC = timezone.utc

MAX_SERIES = 6          # a line chart with more lines than this is a table
MAX_POINTS = 240        # ...and more points than this is a texture, not a shape
MAX_BARS = 40


def _iso(ep: float) -> str:
    return datetime.fromtimestamp(ep, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _positions(store: Any, query: str, sources: str, sev: str, frm: Optional[str],
               to: Optional[str], scope: str) -> dict[str, Any]:
    """Every matching position for one query, through the ONE search path.

    `routers.events._search_filters` is what resolves sources/sev/from/to/scope into the same shapes
    the list endpoint uses; going around it would give the chart its own idea of what "this source"
    means.
    """
    from .routers.events import _search_filters      # local: routers import the store, not the reverse
    events, ts, version, lo, hi, src_set, sev_set = _search_filters(sources, sev, frm, to, scope)
    res = search_engine.search(events, ts, version, query, lo, hi, src_set, sev_set, 0, 1,
                               desc=False, whole_pool=scope != "case", positions=True)
    return {"res": res, "ts": ts}


def _series_times(store: Any, queries: list[str], sources: str, sev: str, frm: Optional[str],
                  to: Optional[str], scope: str) -> tuple[list[np.ndarray], list[dict[str, Any]]]:
    out: list[np.ndarray] = []
    meta: list[dict[str, Any]] = []
    for q in queries:
        got = _positions(store, q, sources, sev, frm, to, scope)
        res, ts = got["res"], got["ts"]
        pos = res.get("positions")
        if pos is None or pos.shape[0] == 0 or ts.shape[0] == 0:
            out.append(np.zeros(0, dtype=np.float64))
            meta.append({"total": int(res["total"]), "counted": 0, "withoutTimestamp": 0,
                         "exact": bool(res.get("positionsExact", True))})
            continue
        t = ts[pos]
        dated = np.isfinite(t)
        out.append(t[dated])
        meta.append({"total": int(res["total"]), "counted": int(pos.shape[0]),
                     "withoutTimestamp": int(pos.shape[0] - int(dated.sum())),
                     "exact": bool(res.get("positionsExact", True))})
    return out, meta


def build(store: Any, *, title: str, kind: str = "line", mode: str = "time",
          queries: Optional[list[str]] = None, labels: Optional[list[str]] = None,
          group_by: str = "", bucket: str = "auto", points: int = 60,
          sources: str = "", sev: str = "", frm: Optional[str] = None, to: Optional[str] = None,
          scope: str = "all", note: str = "", created_by: str = "", run_id: str = "") -> CaseChart:
    """Compute a chart from the pool. Raises ValueError with an analyst-readable reason."""
    kind = (kind or "line").strip().lower()
    mode = (mode or "time").strip().lower()
    if kind not in ("line", "area", "bar"):
        raise ValueError(f"kind must be line, area or bar (not {kind!r})")
    if mode not in ("time", "category"):
        raise ValueError(f"mode must be time or category (not {mode!r})")
    title = (title or "").strip()
    if not title:
        raise ValueError("a chart needs a title — say what it shows, e.g. "
                         "'Failed SSH logins per hour, 10.0.0.5 vs everyone else'")
    qs = [str(q) for q in (queries or [])]
    if mode == "time" and not qs:
        raise ValueError("queries is required for a time chart: one query per line on the chart")
    if len(qs) > MAX_SERIES:
        raise ValueError(f"at most {MAX_SERIES} series — a chart with more lines than that is a table; "
                         f"use aggregate_events for a breakdown")
    names = [str(x) for x in (labels or [])]

    if mode == "category":
        return _category(store, title=title, kind=kind, query=qs[0] if qs else "", group_by=group_by,
                         top=points, sources=sources, sev=sev, frm=frm, to=to, scope=scope,
                         note=note, created_by=created_by, run_id=run_id)

    want = max(8, min(MAX_POINTS, int(points or 60)))
    times, meta = _series_times(store, qs, sources, sev, frm, to, scope)
    live = [t for t in times if t.shape[0]]
    if not live:
        raise ValueError("none of those queries matched an event with a parsed timestamp, so there is "
                         "nothing to plot. Check the queries with count_events first, and remember "
                         "that a source still in phase 1 (raw) has no timestamps to bucket.")
    lo = float(min(float(t.min()) for t in live))
    hi = float(max(float(t.max()) for t in live))
    size = _bucket_for(hi - lo, want, bucket)
    origin = float(int(lo // size) * size)
    n = int((hi - origin) // size) + 1
    n = max(1, min(MAX_POINTS, n))
    grid = [_iso(origin + i * size) for i in range(n)]
    series: list[ChartSeries] = []
    for i, t in enumerate(times):
        if t.shape[0]:
            bins = np.minimum(((t - origin) // size).astype(np.int64), n - 1)
            bins = bins[bins >= 0]
            counts = np.bincount(bins, minlength=n)[:n].astype(np.int64)
        else:
            counts = np.zeros(n, dtype=np.int64)
        series.append(ChartSeries(label=(names[i] if i < len(names) and names[i] else qs[i] or "all"),
                                  query=qs[i], points=[int(v) for v in counts.tolist()],
                                  total=int(meta[i]["total"])))
    return CaseChart(
        id=f"ch{uuid.uuid4().hex[:10]}", title=title, kind=kind, mode="time",
        x=grid, xLabel=_bucket_label(size), yLabel="events", series=series,
        bucketSec=float(size), scope=scope, sources=sources, sev=sev,
        rangeFrom=frm or "", rangeTo=to or "",
        total=sum(int(m["total"]) for m in meta),
        counted=sum(int(m["counted"]) for m in meta),
        withoutTimestamp=sum(int(m["withoutTimestamp"]) for m in meta),
        exact=all(bool(m["exact"]) for m in meta),
        note=note, createdAt=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        createdBy=created_by, runId=run_id)


def _category(store: Any, *, title: str, kind: str, query: str, group_by: str, top: int,
              sources: str, sev: str, frm: Optional[str], to: Optional[str], scope: str,
              note: str, created_by: str, run_id: str) -> CaseChart:
    """One bar per value of a field — `aggregate_events` as a picture, through the same aggregation."""
    from .ai.tools import _aggregate, _matching     # the ONE implementation of the fold
    field = (group_by or "").strip()
    if not field:
        raise ValueError("groupBy is required for a category chart — name the field to count by, "
                         "e.g. 'source', 'user' or 'status'")
    res = _matching({"query": query, "sources": sources, "sev": sev, "from": frm, "to": to,
                     "scope": scope})
    groups, distinct, missing = _aggregate(res["rows"], field)
    n = max(1, min(MAX_BARS, int(top or 20)))
    groups = groups[:n]
    if not groups:
        raise ValueError(f"nothing matched, or no event carries {field!r} — check it with "
                         f"distinct_values before charting it")
    return CaseChart(
        id=f"ch{uuid.uuid4().hex[:10]}", title=title, kind="bar" if kind == "line" else kind,
        mode="category", x=[str(g.get("value") or "(none)") for g in groups],
        xLabel=field, yLabel="events",
        series=[ChartSeries(label=field, query=query,
                            points=[float(g.get("count") or 0) for g in groups],
                            total=int(res["total"]))],
        groupBy=field, scope=scope, sources=sources, sev=sev,
        rangeFrom=frm or "", rangeTo=to or "",
        total=int(res["total"]), counted=len(res["rows"]), withoutField=int(missing),
        distinctGroups=int(distinct), truncated=distinct > n, exact=True,
        note=note, createdAt=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        createdBy=created_by, runId=run_id)


def _bucket_for(span: float, want: int, asked: str) -> float:
    """The bucket size, from the app's ONE ladder (`routers.events._BUCKET_LADDER`)."""
    from .routers.events import _bucket_size
    fixed = {"second": 1.0, "minute": 60.0, "hour": 3600.0, "day": 86400.0, "week": 604800.0}
    a = (asked or "auto").strip().lower()
    if a in fixed:
        # ...but never so fine that the chart becomes a texture: a minute bucket over a year is
        # 525,600 points, and the caller asking for it has not looked at the range.
        if span / fixed[a] <= MAX_POINTS:
            return fixed[a]
    return _bucket_size(max(span, 1.0), want)


def _bucket_label(size: float) -> str:
    if size < 60:
        return f"per {int(size)}s"
    if size < 3600:
        return f"per {int(size / 60)}m"
    if size < 86400:
        return f"per {int(size / 3600)}h"
    if size < 604800:
        return f"per {int(size / 86400)}d"
    return f"per {int(size / 604800)}w"
