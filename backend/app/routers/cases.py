"""Multi-case endpoints (see docs/API_CONTRACT.md → "Cases (multi-case)")."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import cases
from ..models import Case, CaseDetail, CaseNote, CaseSummary, NoteRef, Source
from ..store import STORE

router = APIRouter(prefix="/cases", tags=["cases"])


class CaseCreate(BaseModel):
    name: str
    analyst: Optional[str] = None


class CasePatch(BaseModel):
    name: Optional[str] = None
    analyst: Optional[str] = None


@router.get("", response_model=list[CaseSummary])
def list_cases() -> list[CaseSummary]:
    return cases.list_cases()


class TrashEntry(BaseModel):
    entry: str        # folder name in the trash, "<CASE-000N>-<timestamp>"
    caseId: str       # the id it had when deleted
    name: str
    deletedAt: str
    events: int
    sources: int
    sizeBytes: int
    # What the case HELD, not just what it ingested: a curation-only case has no uploads and no events
    # of its own, and a trash row of three zeros says nothing about what would come back on a restore.
    caseSet: int = 0
    noteCount: int = 0
    iocCount: int = 0
    graphLinkCount: int = 0


# NOTE: declared before /{case_id} — FastAPI matches in order, so a dynamic route registered first
# would swallow "/trash" and 404 it as a missing case.
@router.get("/trash", response_model=list[TrashEntry])
def list_trash() -> list[TrashEntry]:
    """Deleted cases that can still be restored, newest first."""
    return [TrashEntry(**t) for t in cases.list_trash()]


@router.post("/trash/{entry}/restore", response_model=CaseSummary)
def restore_trash(entry: str) -> CaseSummary:
    """Put a deleted case back. It returns under a fresh id if its original id was reused."""
    try:
        cid = cases.restore_trash(entry)
    except KeyError:
        raise HTTPException(404, "no such entry in the trash")
    return cases.summary(cid)


@router.get("/{case_id}", response_model=CaseDetail)
def case_detail(case_id: str) -> CaseDetail:
    try:
        return cases.detail(case_id)
    except KeyError:
        raise HTTPException(404, "case not found")


@router.post("", response_model=CaseSummary)
def create_case(body: CaseCreate) -> CaseSummary:
    return cases.create_case(body.name, body.analyst)


@router.post("/{case_id}/activate", response_model=Case)
def activate_case(case_id: str) -> Case:
    try:
        cases.activate(case_id)
    except KeyError:
        raise HTTPException(404, "case not found")
    return STORE.case()


@router.patch("/{case_id}", response_model=CaseSummary)
def patch_case(case_id: str, body: CasePatch) -> CaseSummary:
    try:
        return cases.patch_case(case_id, body.name, body.analyst)
    except KeyError:
        raise HTTPException(404, "case not found")


@router.post("/{case_id}/sources/{sid}/detach", response_model=list[Source])
def detach_source(case_id: str, sid: str) -> list[Source]:
    """Take a source back OUT of the case, leaving it in the case-less pool.

    A case is a curation layer: the analyst chooses what is in scope, and that choice has to be
    reversible without destroying evidence. The events stay in the pool with the same ids (nothing is
    re-parsed and nothing leaves search) — only the case stops claiming them. Deleting the file outright
    is still DELETE /api/sources/{id}.
    """
    if case_id != STORE.case_id or STORE.pending:
        raise HTTPException(409, "only the active case can be edited — activate it first")
    if sid not in STORE.sources:
        raise HTTPException(404, "source not found")
    detached = STORE.detach_case_source(sid)
    if not detached:
        raise HTTPException(409, "the file backing this source could not be read, so it cannot be moved "
                                 "out of the case — delete it from Sources instead")
    # a detach stages bytes back into library/ and flips an origin: both change what /api/library says,
    # and its memo tolerates version drift while enrichment is running, so announce it explicitly
    from .library import invalidate_library_cache
    invalidate_library_cache()
    return detached


class NoteBody(BaseModel):
    text: str = ""
    refs: Optional[list[NoteRef]] = None


@router.get("/{case_id}/notes", response_model=list[CaseNote])
def list_notes(case_id: str) -> list[CaseNote]:
    try:
        return cases.list_notes(case_id)
    except KeyError:
        raise HTTPException(404, "case not found")


@router.post("/{case_id}/notes", response_model=CaseNote)
def add_note(case_id: str, body: NoteBody) -> CaseNote:
    if not body.text.strip() and not body.refs:
        raise HTTPException(400, "a note needs text or at least one reference")
    try:
        return cases.add_note(case_id, body.text, body.refs)
    except KeyError:
        raise HTTPException(404, "case not found")


@router.patch("/{case_id}/notes/{note_id}", response_model=CaseNote)
def update_note(case_id: str, note_id: str, body: NoteBody) -> CaseNote:
    try:
        return cases.update_note(case_id, note_id, body.text, body.refs)
    except KeyError:
        raise HTTPException(404, "note not found")


@router.delete("/{case_id}/notes/{note_id}")
def delete_note(case_id: str, note_id: str) -> dict:
    try:
        cases.delete_note(case_id, note_id)
    except KeyError:
        raise HTTPException(404, "note not found")
    return {"ok": True}


@router.delete("/{case_id}")
def delete_case(case_id: str) -> dict:
    try:
        cases.delete_case(case_id)
    except KeyError:
        raise HTTPException(404, "case not found")
    return {"ok": True}
