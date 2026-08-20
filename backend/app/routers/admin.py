"""Admin endpoints: destructive maintenance operations."""
from __future__ import annotations

from fastapi import APIRouter, Body

from ..store import STORE

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/clear-all")
def clear_all(body: dict = Body(default={})) -> dict:
    """Wipe the whole workspace: every case (uploads, case.json, notes, attachments, case set, manual
    IOCs, graph links), the deleted-case trash, every file staged in the library, the entire parsed
    event pool and the search index over it, the upload/parse job registry, and the AI assistant's
    conversation history (transcripts quote the evidence verbatim, so they are evidence too). Nothing
    survives on disk and nothing stale survives in memory — a restart comes up empty.

    Deliberately KEPT: detection rules (rules.json — custom rules and built-in overrides are
    configuration, cleared from Anomalies → Rules) and settings.json. With {"resetSettings": true}
    settings.json is removed as well and defaults reloaded (incl. the AI key).
    """
    reset_settings = bool(body.get("resetSettings", False)) if isinstance(body, dict) else False
    removed = STORE.clear_all(reset_settings=reset_settings)
    return {"ok": True, "removed": removed}
