"""The registry of AI investigation runs — what is in flight, what it changed, and how to stop it.

This used to be an in-memory dict, on the argument that "a run is a live conversation, not case data".
That was wrong in practice: refreshing the panel, switching tabs or restarting the server lost the
objective the analyst typed, the transcript, the report and the list of what the agent changed. The
record now lives in `ai/history.py` (`$IRIS_DATA_DIR/ai/history.json`) and this module is the thin
facade the investigator and the router call — the names and signatures are unchanged.

What stays in memory: only the stop flag, which is meaningless after a restart (a killed run is
reconciled to `interrupted` at startup, so there is nothing left to stop).
"""
from __future__ import annotations

from typing import Any, Optional

from ..models import AiAction, AiRun, AiTranscriptEntry
from .history import HISTORY, new_id  # noqa: F401 — new_id is re-exported, callers import it from here

KEEP = 20  # default page size for the listing endpoint


def start(run_id: str, prompt: str, model: str, *, focus: str = "",
          case_id: str = "", case_name: str = "", parent_id: str = "",
          thread_id: str = "") -> dict[str, Any]:
    return HISTORY.start(run_id, prompt, model, focus=focus, case_id=case_id, case_name=case_name,
                         parent_id=parent_id, thread_id=thread_id)


def thread(run_id: str) -> list[dict[str, Any]]:
    """Every turn of one conversation, oldest first — see HistoryStore.thread."""
    return HISTORY.thread(run_id)


def finish(run_id: str, state: str, reason: str, steps: int, tool_calls: int, answer: str,
           actions: list[dict[str, Any]], unverified: list[str], error: str = "") -> None:
    HISTORY.finish(run_id, state, reason, steps, tool_calls, answer, actions, unverified, error)


def request_stop(run_id: str) -> bool:
    """Ask a run to stop at its next checkpoint. Returns False if there is no such live run."""
    return HISTORY.request_stop(run_id)


def stop_requested(run_id: str) -> bool:
    return HISTORY.stop_requested(run_id)


def get(run_id: str) -> Optional[dict[str, Any]]:
    return HISTORY.get(run_id)


def listing(limit: int = KEEP, case_id: Optional[str] = None) -> list[dict[str, Any]]:
    return HISTORY.listing(limit, case_id)


def delete(run_id: str) -> bool:
    return HISTORY.delete(run_id)


def clear_all() -> int:
    return HISTORY.clear_all()


def as_model(rec: dict[str, Any], *, since: int = 0, transcript: bool = True) -> AiRun:
    """`since` serves the rejoin path: only transcript entries the client has not seen are returned."""
    rows = rec.get("transcript") or []
    if not transcript:
        rows = []
    elif since:
        rows = [e for e in rows if int(e.get("seq") or 0) > since]
    return AiRun(id=rec["id"], prompt=rec.get("prompt", ""), focus=rec.get("focus", ""),
                 parentId=rec.get("parentId", ""), threadId=rec.get("threadId", "") or rec["id"],
                 model=rec.get("model", ""), caseId=rec.get("caseId", ""), caseName=rec.get("caseName", ""),
                 startedAt=rec.get("startedAt", ""), endedAt=rec.get("endedAt", ""),
                 updatedAt=rec.get("updatedAt", ""), state=rec.get("state", "running"),
                 reason=rec.get("reason", ""), steps=rec.get("steps", 0),
                 toolCalls=rec.get("toolCalls", 0), answer=rec.get("answer", ""),
                 error=rec.get("error", ""), interrupted=bool(rec.get("interrupted")),
                 actions=[AiAction(**a) for a in rec.get("actions") or []],
                 unverifiedCitations=list(rec.get("unverifiedCitations") or []),
                 transcript=[AiTranscriptEntry(**e) for e in rows],
                 transcriptSeq=int(rec.get("seq") or 0),
                 transcriptTruncated=bool(rec.get("transcriptTruncated")))


def undo_run(run_id: str) -> dict[str, Any]:
    """Reverse every write of one run, newest first. Idempotent — already-undone actions are skipped."""
    from .tools import undo_action
    rec = HISTORY.get(run_id)
    if rec is None:
        raise KeyError(run_id)
    actions = list(rec.get("actions") or [])
    undone = 0
    for a in reversed(actions):
        if a.get("undone"):
            continue
        try:
            if undo_action(a):
                a["undone"] = True
                undone += 1
        except Exception:  # noqa: BLE001 — one failed reversal must not block the rest
            continue
    HISTORY.set_actions(run_id, actions)
    return {"ok": True, "undone": undone, "actions": actions}
