"""Event search / detail endpoints."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from fastapi import APIRouter, HTTPException, Query

from .. import config
from ..models import Event, EventDetail
from ..normalize import parse_ts
from .. import search as search_engine
from ..store import STORE, _iso_to_epoch as _epoch

router = APIRouter(prefix="/events", tags=["events"])

# /events/fields walks at most this many matching events — enough for a faithful facet picture, bounded so a
# 1M-event case never turns the sidebar refresh into a multi-second scan.
_FIELDS_SCAN_CAP = 20_000
# Fixed event columns that are offered as facets alongside the parser-specific Event.fields keys.
_FIXED_COLUMNS = ("host", "user", "source", "file", "sev")


def _search_filters(sources: str, sev: str, from_: Optional[str], to: Optional[str], scope: str) -> tuple:
    """Resolve the shared list/fields filters into (events, ts, version, lo, hi, src_set, sev_set).

    Both endpoints must see the SAME result set for the same query string, so this is the single place
    that turns scope/from/to/sources/sev into search_engine.search() arguments.
    """
    with STORE.lock:
        if scope == "case":
            # search the curated subset only; it is small, so the vector index is not worth building
            events = STORE.case_set_events()
            ts = np.asarray([_epoch(e.ts) for e in events], dtype=np.float64) if events else np.zeros(0, dtype=np.float64)
        else:
            events = STORE.events
            ts = STORE.ts
        n = len(events)
        lo, hi = 0, n
        if from_:
            dt = parse_ts(from_)
            if dt:
                lo = int(np.searchsorted(ts, dt.timestamp(), side="left"))
        if to:
            dt = parse_ts(to)
            if dt:
                hi = int(np.searchsorted(ts, dt.timestamp(), side="right"))
        src_set = {s.strip() for s in sources.split(",") if s.strip()}
        sev_set = {s.strip().lower() for s in sev.split(",") if s.strip()}
        # a distinct cache key for the subset: its index must never be confused with the full corpus one
        version = STORE.version if scope != "case" else -(STORE.version * 1000 + len(STORE.case_set)) - 1
    return events, ts, version, lo, hi, src_set, sev_set


@router.get("")
def list_events(q: str = "", sources: str = "", sev: str = "", from_: Optional[str] = Query(None, alias="from"),
                to: Optional[str] = None, limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0),
                scope: str = Query("all", pattern="^(all|case)$"),
                sort: str = Query("ts_desc", pattern="^(ts_desc|ts_asc)$")) -> dict:
    events, ts, version, lo, hi, src_set, sev_set = _search_filters(sources, sev, from_, to, scope)
    # Search runs OUTSIDE the store lock: the event list is only ever replaced (never mutated in place) and the
    # index is keyed by version, so concurrent searches don't serialize behind ingest / each other.
    res = search_engine.search(events, ts, version, q, lo, hi, src_set, sev_set, offset, limit, desc=sort == "ts_desc")
    rows: list[Event] = res["rows"]
    total: int = res["total"]
    # NOTE: no per-row baseline here — that is an O(N) analyzer call per row (it made a 200-row page take ~10 s on
    # a 90k-event case). Baselines are computed on the detail endpoint only.
    # stamp_membership returns the API rows already — a pooled Event is a slotted object and is not
    # JSON-serializable, so the conversion to dicts is the boundary and happens exactly once, here.
    out = STORE.stamp_membership(rows)
    # `index` says whether the vectorised index is ready, and how far along it is if not — a query that
    # falls back to the scan because the index is still warming looks like a slow query otherwise.
    return {"total": total, "totalExact": bool(res.get("totalExact", True)),
            "rows": out, "engine": res["engine"], "tookMs": res["tookMs"],
            "candidates": res["candidates"], "index": res["index"]}


@router.get("/fields")
def list_fields(q: str = "", sources: str = "", sev: str = "", from_: Optional[str] = Query(None, alias="from"),
                to: Optional[str] = None, scope: str = Query("all", pattern="^(all|case)$"),
                limit: int = Query(40, ge=1, le=500),
                # A PLAIN default, not Query(...): a handler declared `= Query(8)` has a Query OBJECT
                # as its Python default, so every direct call that omits it (tests, ai/tools.py) gets
                # that object and dies on the first use — the trap CLAUDE.md records for `from_`. The
                # bound is enforced below instead, where a direct caller is covered too.
                values: int = 8) -> dict:
    """Field facets for the CURRENT result set — the same q/sources/sev/from/to/scope as GET /events.

    For every field name (Event.fields keys plus the fixed columns host/user/source/file/sev): how many
    matching events carry it, a few sample values and the most common values. Sorted by count desc.
    Only the first _FIELDS_SCAN_CAP matching events (newest first) are walked; `sampled` says so.

    `values` is how many values per field come back (8 by default). The rail asks for more when the
    analyst opens a field that has more — on a workspace with hundreds of sources, a `source` facet
    capped at 8 offers eight of them to click and hides the rest behind a count, which reads as "these
    are the sources" rather than "these are the commonest eight".
    """
    values = max(1, min(500, int(values or 8)))
    events, ts, version, lo, hi, src_set, sev_set = _search_filters(sources, sev, from_, to, scope)
    res = search_engine.search(events, ts, version, q, lo, hi, src_set, sev_set, 0, _FIELDS_SCAN_CAP, desc=True)
    rows: list[Event] = res["rows"]
    total_events: int = res["total"]

    counts: dict[str, int] = {}
    value_counts: dict[str, dict[str, int]] = {}
    samples: dict[str, list[str]] = {}

    def bump(name: str, value: str) -> None:
        counts[name] = counts.get(name, 0) + 1
        if not value:
            return
        vc = value_counts.get(name)
        if vc is None:
            vc = value_counts[name] = {}
        vc[value] = vc.get(value, 0) + 1
        s = samples.get(name)
        if s is None:
            samples[name] = [value]
        elif len(s) < 5 and value not in s:
            s.append(value)

    for e in rows:
        if e.host:
            bump("host", e.host)
        if e.user:
            bump("user", e.user)
        bump("source", e.source)
        bump("file", e.file)
        bump("sev", e.sev)
        for k, v in e.fields.items():
            if k in _FIXED_COLUMNS:
                # a parser field named like a fixed column folds into that column rather than shadowing it
                continue
            bump(k, v if isinstance(v, str) else str(v))

    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    fields = []
    for name, cnt in ordered[:limit]:
        vc = value_counts.get(name, {})
        top = sorted(vc.items(), key=lambda kv: (-kv[1], kv[0]))[:values]
        fields.append({
            "name": name,
            "count": cnt,
            "sample": [v[:200] for v in samples.get(name, [])],
            "topValues": [{"value": v[:200], "count": c} for v, c in top],
            "distinct": len(vc),
        })
    return {
        "fields": fields,
        "total": len(ordered),
        "events": total_events,
        "scanned": len(rows),
        "sampled": total_events > len(rows),
        "engine": res["engine"],
        "tookMs": res["tookMs"],
    }


# Reading to the end just to report "line 42 of N" is not worth minutes on a multi-gigabyte log, so
# above this the count is dropped (the field is nullable and the UI already renders it that way).
_COUNT_LINES_MAX = 64 << 20


@dataclass
class _Excerpt:
    """One matched line plus the lines either side, collected while streaming past it."""

    line: int
    text: str
    before: list[tuple[int, str]]
    want: int
    after: list[tuple[int, str]] = field(default_factory=list)

    def __init__(self, line: int, text: str, before: "deque[tuple[int, str]]", want: int) -> None:
        self.line, self.text, self.want = line, text, want
        self.before = list(before)
        self.after = []

    @property
    def done(self) -> bool:
        return len(self.after) >= self.want

    def feed(self, n: int, text: str) -> None:
        if n > self.line and not self.done:
            self.after.append((n, text))

    def context(self) -> list[dict]:
        rows = [*self.before, (self.line, self.text), *self.after]
        return [{"n": n, "text": t[:1000], "current": n == self.line} for n, t in rows]


@router.get("/{eid}/location")
def event_location(eid: str, context: int = Query(3, ge=0, le=20)) -> dict:
    """Where in its original log file this event came from.

    Resolved on demand by matching the event's raw text against the file rather than stamping a line
    number at parse time — that keeps it exact for cases ingested before this existed, and honest about
    formats where "a line" is meaningless (JSON arrays, EVTX, memory dumps), which report line: null.
    """
    e = STORE.event(eid)
    if e is None:
        raise HTTPException(404, "event not found")
    path = STORE.source_paths.get(e.sourceId)
    if path is None or not path.is_file():
        return {"file": e.file, "line": None, "totalLines": None, "exact": False,
                "reason": "the original upload is no longer on disk", "context": []}
    raw = (e.raw or "").strip()
    if not raw:
        return {"file": e.file, "line": None, "totalLines": None, "exact": False,
                "reason": "this event has no raw line to locate", "context": []}

    # STREAMED, one line at a time. This used to be `fh.read().splitlines()`: on a 1.1 GB log that is
    # the whole file as one string PLUS ten million string objects, seconds of work and gigabytes of
    # allocation, on the request that renders a single event — which is most of why the event detail
    # page was slow. Nothing here needs the whole file: it needs one line and a few either side.
    needle = raw[:400]
    before: deque[tuple[int, str]] = deque(maxlen=context)
    exact_hit: Optional[_Excerpt] = None
    loose_hit: Optional[_Excerpt] = None
    total = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for n, text in enumerate(fh, 1):
                total = n
                line = text.rstrip("\r\n")
                for hit in (exact_hit, loose_hit):      # still filling the lines AFTER a match
                    if hit is not None:
                        hit.feed(n, line)
                if exact_hit is None:
                    if line.strip() == raw:
                        exact_hit = _Excerpt(n, line, before, context)
                    elif loose_hit is None and needle and needle in line:
                        # the parser may have rewritten the line slightly; keep the first containment
                        # match as a fallback, but keep looking for an exact one (the old two-pass
                        # behaviour, in a single pass over the file)
                        loose_hit = _Excerpt(n, line, before, context)
                before.append((n, line))
                if exact_hit is not None and exact_hit.done and total >= exact_hit.line + context:
                    if path.stat().st_size > _COUNT_LINES_MAX:
                        total = 0        # counting to the end of a huge file is not worth the wait
                        break
    except OSError as exc:
        return {"file": e.file, "line": None, "totalLines": None, "exact": False,
                "reason": f"could not read the file ({config.safe_os_error(exc)})", "context": []}

    hit = exact_hit or loose_hit
    if hit is None:
        return {"file": e.file, "line": None, "totalLines": total or None, "exact": False,
                "reason": "this format does not map one event to one line (JSON array, EVTX, binary dump)",
                "context": []}
    return {
        "file": e.file,
        "line": hit.line,
        "totalLines": total or None,
        "exact": exact_hit is not None,
        "reason": None if exact_hit is not None else "matched on a prefix — the parser rewrote the line slightly",
        "context": hit.context(),
    }


@router.get("/{eid}", response_model=EventDetail)
def get_event(eid: str) -> EventDetail:
    e = STORE.event(eid)
    if e is None:
        raise HTTPException(404, "event not found")
    # NON-BLOCKING. This used to call `STORE.analysis()`, which BUILDS the whole-pool correlation
    # analysis if it is not current — minutes on a large workspace, on the request thread, for a page
    # that is otherwise a dictionary lookup. Opening any event could pay for it, which is what "event
    # detail loads very slow" was. Same rule as every other derived reader in the app: ask for it if
    # it is there, never build it here, and SAY when it is missing rather than returning an empty list
    # that reads as "nothing correlates with this event".
    analysis = STORE.analysis_ready()
    az = analysis.get("analyzer") if analysis else None
    corr = []
    baseline = e.baseline
    status = None
    if az is not None:
        i = STORE.event_index[eid]
        corr = az.correlations_for(i)
        baseline = baseline or az.baseline_for(i)
    else:
        from .. import correlate

        status = correlate.ANALYSIS_CACHE.status("all", STORE._derived_key("all"))
    entry = STORE.case_set.get(eid)
    return EventDetail(**{**e.model_dump(), "baseline": baseline, "correlations": corr,
                          "analysis": status,
                          "inCase": entry is not None, "labels": list(entry.labels) if entry else []})
