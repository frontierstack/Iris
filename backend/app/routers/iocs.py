"""Indicators of compromise for the active case.

Two sources, merged into one list:
  * extracted — derived from detection-bearing events every time (report._iocs)
  * manual    — entered by the analyst and persisted in case.json

Either way an indicator carries the events and log files it was seen in, so the UI can link straight
to the line it came from. A manual indicator is looked up across the corpus on read, which is the
whole point of adding one: type an IP you got from threat intel and immediately see where it appears.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..models import IOC, IOCHit, IocMarker, IOCResponse
from ..report import MAX_IOC_HITS, _iocs, sample_hit
from ..store import STORE

router = APIRouter(prefix="/iocs", tags=["iocs"])
UTC = timezone.utc


class IOCBody(BaseModel):
    kind: str = "other"
    value: str
    note: str = ""
    # events this indicator came from. They become part of its timeline (see _apply_citations); ids that
    # are not real events are dropped rather than stored, so an indicator can never cite a phantom log.
    citedEventIds: Optional[list[str]] = None


def _ioc_id(kind: str, value: str) -> str:
    return f"{kind.strip().lower()}:{value.strip()}"


def _locate(value: str, events: list) -> IOC:
    """Find every place a literal indicator appears: raw, message, entities and field values."""
    needle = value.lower()
    hit = IOC(id="", kind="", value=value, manual=True)
    for e in events:
        found = (needle in e.raw.lower() or needle in e.msg.lower()
                 or any(needle == x.lower() for x in e.entities)
                 or any(needle in v.lower() for v in e.fields.values()))
        if not found:
            continue
        hit.count += 1
        if e.file and e.file not in hit.files:
            hit.files.append(e.file)
        if not hit.firstSeen or e.ts < hit.firstSeen:
            hit.firstSeen = e.ts
        if not hit.lastSeen or e.ts > hit.lastSeen:
            hit.lastSeen = e.ts
        sample_hit(hit, e)      # every file in `files` keeps a hit to click — see report.sample_hit
    return hit


def _apply_citations(ioc: IOC, cited: list[str]) -> None:
    """Fold the events the author CITED into the indicator's own timeline.

    `_locate` only finds an indicator where its literal text appears. An indicator recorded from a
    finding ("this key fingerprint is the attacker's", cited from the event that showed it) must still
    be placeable in time, so the cited events contribute their timestamps and hits as well. Without
    this an AI- or analyst-recorded indicator has firstSeen: null and cannot go on the timeline at all.
    """
    have = {h.eventId for h in ioc.hits}
    for eid in cited:
        e = STORE.event(eid)
        if e is None:
            continue  # a stale citation (its source was deleted) is dropped, never invented
        if not ioc.firstSeen or e.ts < ioc.firstSeen:
            ioc.firstSeen = e.ts
        if not ioc.lastSeen or e.ts > ioc.lastSeen:
            ioc.lastSeen = e.ts
        if e.file and e.file not in ioc.files:
            ioc.files.append(e.file)
        if eid not in have:
            sample_hit(ioc, e)
            have.add(eid)
    ioc.hits.sort(key=lambda h: h.ts)


def _all_iocs(scope: str) -> list[IOC]:
    events = STORE.case_set_events() if scope == "case" else STORE.events
    out: list[IOC] = []
    seen: set[str] = set()
    for i in _iocs(events):
        i.id = _ioc_id(i.kind, i.value)
        i.addedBy = "extracted"
        seen.add(i.id)
        out.append(i)
    with STORE.lock:
        manual = list(STORE.manual_iocs)
    for m in manual:
        kind, value = str(m.get("kind") or "other"), str(m.get("value") or "")
        if not value:
            continue
        mid = _ioc_id(kind, value)
        # who recorded it: 'ai' for the investigator, 'analyst' for anything entered by hand (including
        # every indicator that predates the field). This is the audit trail, not decoration.
        by = "ai" if str(m.get("addedBy") or "") == "ai" else "analyst"
        cited = [str(x) for x in (m.get("citedEventIds") or []) if str(x)]
        if mid in seen:
            # the extractor already found it — keep the richer extracted entry, just flag it as also manual
            for existing in out:
                if existing.id == mid:
                    existing.manual = True
                    existing.addedBy = by
                    existing.addedAt = str(m.get("addedAt") or "")
                    existing.citedEventIds = cited
                    existing.note = str(m.get("note") or "") or existing.note
                    _apply_citations(existing, cited)
            continue
        located = _locate(value, events)
        located.id, located.kind, located.manual = mid, kind, True
        located.note = str(m.get("note") or "")
        located.addedBy = by  # type: ignore[assignment]
        located.addedAt = str(m.get("addedAt") or "")
        located.citedEventIds = cited
        _apply_citations(located, cited)
        out.append(located)
    return sorted(out, key=lambda i: (-i.count, i.kind, i.value))


def ioc_markers(scope: str, limit: int = 200) -> list[IocMarker]:
    """Indicators projected onto the incident chronology, earliest first.

    An indicator with no timestamp anywhere (never seen, no citation) cannot be placed and is left off
    the timeline rather than parked at epoch zero — the IOC panel still lists it.
    """
    out: list[IocMarker] = []
    for i in _all_iocs(scope):
        if not i.firstSeen:
            continue
        hit = i.hits[0] if i.hits else None
        out.append(IocMarker(id=i.id, kind=i.kind, value=i.value, ts=i.firstSeen, lastSeen=i.lastSeen,
                             count=i.count, manual=i.manual, addedBy=i.addedBy, note=i.note,
                             eventId=hit.eventId if hit else "", file=hit.file if hit else "",
                             sourceId=hit.sourceId if hit else ""))
    out.sort(key=lambda m: (m.ts, m.kind, m.value))
    return out[:limit]


@router.get("", response_model=IOCResponse)
def list_iocs(scope: str = Query("all", pattern="^(all|case)$"), kind: str = "") -> IOCResponse:
    out = _all_iocs(scope)
    if kind:
        wanted = {k.strip().lower() for k in kind.split(",") if k.strip()}
        out = [i for i in out if i.kind.lower() in wanted]
    return IOCResponse(total=len(out), iocs=out)


@router.post("", response_model=IOC)
def add_ioc(body: IOCBody) -> IOC:
    value = body.value.strip()
    if not value:
        raise HTTPException(400, "value is required")
    kind = (body.kind or "other").strip().lower() or "other"
    iid = _ioc_id(kind, value)
    with STORE.lock:
        if any(_ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) == iid for m in STORE.manual_iocs):
            raise HTTPException(409, "that indicator is already tracked on this case")
        STORE.manual_iocs.append({"kind": kind, "value": value, "note": body.note.strip(),
                                  "addedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                  "addedBy": "analyst",
                                  "citedEventIds": [e for e in (body.citedEventIds or []) if STORE.event(e)]})
    STORE.save_meta()
    return next((i for i in _all_iocs("all") if i.id == iid), IOC(id=iid, kind=kind, value=value, manual=True))


@router.patch("/{ioc_id:path}", response_model=IOC)
def update_ioc(ioc_id: str, body: IOCBody) -> IOC:
    with STORE.lock:
        for m in STORE.manual_iocs:
            if _ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) == ioc_id:
                if body.value.strip():
                    m["value"] = body.value.strip()
                if body.kind.strip():
                    m["kind"] = body.kind.strip().lower()
                m["note"] = body.note.strip()
                new_id = _ioc_id(m["kind"], m["value"])
                break
        else:
            raise HTTPException(404, "indicator not found (only manually added ones can be edited)")
    STORE.save_meta()
    return next((i for i in _all_iocs("all") if i.id == new_id), IOC(id=new_id, kind=body.kind, value=body.value, manual=True))


@router.delete("/{ioc_id:path}")
def delete_ioc(ioc_id: str) -> dict:
    with STORE.lock:
        before = len(STORE.manual_iocs)
        STORE.manual_iocs = [m for m in STORE.manual_iocs
                             if _ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) != ioc_id]
        removed = before - len(STORE.manual_iocs)
    if not removed:
        raise HTTPException(404, "indicator not found (extracted indicators cannot be deleted — they come from events)")
    STORE.save_meta()
    return {"ok": True}
