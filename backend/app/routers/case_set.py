"""The case set: events the analyst curated as part of the investigation (see docs/API_CONTRACT.md).

Replaces the old /api/pins. Membership drives report evidence AND the `scope=case` analysis on
/api/timeline, /api/graph, /api/report and /api/events.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..models import CaseSetEntry, CaseSetResponse
from ..store import STORE

router = APIRouter(prefix="/case-set", tags=["case-set"])


class CaseSetBody(BaseModel):
    labels: Optional[list[str]] = None
    note: Optional[str] = None


@router.get("", response_model=CaseSetResponse)
def list_case_set() -> CaseSetResponse:
    with STORE.lock:
        entries = list(STORE.case_set.values())
    events = [e for e in (STORE.event(x.eventId) for x in entries) if e is not None]
    return CaseSetResponse(entries=entries, events=STORE.stamp_membership(events), labels=STORE.case_labels())


@router.post("/{eid}", response_model=CaseSetEntry)
def add(eid: str, body: Optional[CaseSetBody] = None) -> CaseSetEntry:
    b = body or CaseSetBody()
    entry = STORE.add_to_case(eid, b.labels, b.note)
    if entry is None:
        raise HTTPException(404, "event not found in the active case")
    return entry


@router.patch("/{eid}", response_model=CaseSetEntry)
def update(eid: str, body: CaseSetBody) -> CaseSetEntry:
    if eid not in STORE.case_set:
        raise HTTPException(404, "event is not in the case set")
    entry = STORE.add_to_case(eid, body.labels, body.note)  # add_to_case is an upsert
    if entry is None:
        raise HTTPException(404, "event not found in the active case")
    return entry


class SourceAddBody(BaseModel):
    labels: Optional[list[str]] = None
    limit: int = 5000  # a guard: whole-file adds can be enormous, and the case set is meant to be curated


@router.post("/source/{sid}")
def add_source(sid: str, body: Optional[SourceAddBody] = None) -> dict:
    """Add every event of one log file to the case set (the + on a Sources row)."""
    b = body or SourceAddBody()
    with STORE.lock:
        src = STORE.sources.get(sid)
        if src is None:
            raise HTTPException(404, "source not found")
        ids = [e.id for e in STORE.events if e.sourceId == sid]
    labels = b.labels if b.labels is not None else [src.file]
    truncated = len(ids) > b.limit
    # ONE case.json write for the whole file: save_meta() re-serializes the entire case set + sources,
    # so persisting per event made this quadratic (a few thousand events effectively hung).
    added = len(STORE.add_many_to_case(ids[: b.limit], labels, None))
    return {"ok": True, "added": added, "total": len(ids), "truncated": truncated, "file": src.file}


@router.delete("/source/{sid}")
def remove_source(sid: str) -> dict:
    """Take a whole log file back out of the case set."""
    with STORE.lock:
        ids = [eid for eid in STORE.case_set if (e := STORE.event(eid)) is not None and e.sourceId == sid]
    removed = STORE.remove_many_from_case(ids)  # one case.json write, same reason as add_source
    return {"ok": True, "removed": removed}


@router.delete("/{eid}")
def remove(eid: str) -> dict:
    if not STORE.remove_from_case(eid):
        raise HTTPException(404, "event is not in the case set")
    return {"ok": True}
