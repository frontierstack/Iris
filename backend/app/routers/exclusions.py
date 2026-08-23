"""Exclusions: the suppressions that stop a rule claiming evidence the analyst has already judged.

Every write here re-runs the catalogue over the pool (`STORE.reapply_all_rules`), because an exclusion
changes what is TAGGED and the detections already on the events would otherwise disagree with the
suppression list that produced them. That is O(pool) and it is not optional — a rules screen showing a
suppression that has not been applied is worse than no suppression at all.

See app/exclusions.py for why nothing is ever excluded by default and why every row carries a count.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..exclusions import EXCLUSIONS, ExclusionError, suggestions
from ..models import Exclusion, ExclusionInput, ExclusionsResponse
from ..store import STORE

router = APIRouter(prefix="/exclusions", tags=["exclusions"])


def _reapply() -> None:
    STORE.reapply_all_rules()


@router.get("", response_model=ExclusionsResponse)
def list_exclusions() -> ExclusionsResponse:
    """Every exclusion, what each one suppressed on the last pass, and the ready-made ones on offer."""
    rows = EXCLUSIONS.all()
    return ExclusionsResponse(exclusions=rows, suggestions=suggestions(),
                              suppressed=EXCLUSIONS.total_suppressed())


@router.post("", response_model=Exclusion)
def create_exclusion(body: ExclusionInput) -> Exclusion:
    try:
        ex = EXCLUSIONS.create(body)
    except ExclusionError as exc:
        raise HTTPException(400, str(exc))
    _reapply()
    return EXCLUSIONS.get(ex.id) or ex


@router.put("/{exclusion_id}", response_model=Exclusion)
def update_exclusion(exclusion_id: str, body: ExclusionInput) -> Exclusion:
    try:
        ex = EXCLUSIONS.update(exclusion_id, body)
    except KeyError:
        raise HTTPException(404, "exclusion not found")
    except ExclusionError as exc:
        raise HTTPException(400, str(exc))
    _reapply()
    return EXCLUSIONS.get(ex.id) or ex


@router.post("/{exclusion_id}/toggle", response_model=Exclusion)
def toggle_exclusion(exclusion_id: str) -> Exclusion:
    try:
        ex = EXCLUSIONS.toggle(exclusion_id)
    except KeyError:
        raise HTTPException(404, "exclusion not found")
    _reapply()
    return EXCLUSIONS.get(ex.id) or ex


@router.delete("/{exclusion_id}")
def delete_exclusion(exclusion_id: str) -> dict:
    if not EXCLUSIONS.delete(exclusion_id):
        raise HTTPException(404, "exclusion not found")
    _reapply()
    return {"ok": True}


@router.post("/clear")
def clear_exclusions() -> dict:
    """Remove every exclusion. Nothing is hidden afterwards — this only ever reveals detections."""
    n = EXCLUSIONS.clear()
    _reapply()
    return {"ok": True, "removed": n}
