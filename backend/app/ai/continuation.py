"""Continuing a conversation: what a follow-up turn already knows.

The analyst's report: *"when asked for it to continue, it didn't even have context into all the work it
had already done and redid the entire analysis."* Every `POST /api/ai/investigate` was a cold start —
same system prompt, same orientation block, no memory of the turn before it — so "now build me the
timeline" re-ran the whole investigation and spent its budget rediscovering facts the analyst had
already been told.

A follow-up is a NEW RUN on purpose (see ai/history.py): the run is the unit of budget, of stopping and
of undo, and folding turn two into turn one's record would make "revert what it just did" ambiguous.
What the follow-up inherits instead is a BRIEF, built here from the persisted transcripts of the
earlier turns in the same thread.

WHAT THE BRIEF CARRIES, and why each part is load-bearing:
  • the analyst's earlier objectives verbatim — "continue" means nothing without them;
  • the report each turn produced — that is the established narrative, and re-deriving it is exactly
    the waste being removed;
  • the tools already called and what they returned, so the model does not repeat them (a repeat costs
    the analyst wall clock and tells nobody anything new);
  • every VERIFIED event id seen — citations are load-bearing. A follow-up that cannot see the ids the
    previous turn cited would either re-search for them or, worse, write a claim with no citation;
  • what is ALREADY WRITTEN to the case, with what each write was, so a second turn asked to "document
    this" adds what is missing instead of duplicating notes and indicators.

DETERMINISTIC AND BOUNDED, like ai/compaction.py and for the same reasons: asking the model to
summarise itself is another provider round-trip that can fail, costs budget, and can drop or invent a
cited id. Everything here is already structured. The most recent turns are kept in full and older ones
are clipped harder — recency is what a follow-up is usually about.
"""
from __future__ import annotations

from typing import Any, Optional

from . import eventids

MAX_BRIEF_CHARS = 9000        # the whole prior-conversation block handed to a follow-up
MAX_TURNS = 8                 # earlier turns folded in; older ones are dropped with a line saying so
MAX_ANSWER_RECENT = 2600      # the previous turn's report, kept near-verbatim
MAX_ANSWER_OLDER = 900
MAX_CALLS_PER_TURN = 14
MAX_IDS = 120

_ID_RE = eventids.BARE     # hex, not decimal — see ai/eventids.py

HEADER = (
    "EARLIER IN THIS CONVERSATION — you have already done the work below for this analyst. It is "
    "established: do NOT repeat these tool calls and do NOT re-derive these conclusions. Treat the "
    "event ids as verified and cite them verbatim. Build on this; the analyst's new request is at the "
    "top of this message.")


def _clip(text: Any, limit: int) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= limit else s[:limit] + " …"


def _ids_from(rec: dict[str, Any], out: list[str]) -> None:
    """Ids the turn actually SAW: its report, its prose and the summaries of its tool results."""
    chunks = [str(rec.get("answer") or "")]
    for e in rec.get("transcript") or []:
        kind = e.get("kind")
        if kind in ("text", "warning"):
            chunks.append(str(e.get("text") or ""))
        elif kind == "tool":
            chunks.append(str(e.get("summary") or ""))
            args = e.get("args")
            if isinstance(args, dict):
                chunks.append(" ".join(str(v) for v in args.values()))
    for chunk in chunks:
        for m in _ID_RE.finditer(chunk):
            v = m.group(1)
            if v not in out and len(out) < MAX_IDS:
                out.append(v)


def _calls_of(rec: dict[str, Any]) -> list[str]:
    """One line per tool call: what was asked, and what came back."""
    lines: list[str] = []
    for e in rec.get("transcript") or []:
        if e.get("kind") != "tool":
            continue
        args = e.get("args") if isinstance(e.get("args"), dict) else {}
        shown = ", ".join(f"{k}={_clip(v, 60)}" for k, v in list(args.items())[:3])
        summary = _clip(e.get("summary") or ("failed" if e.get("ok") is False else ""), 140)
        line = f"{e.get('name') or 'tool'}({shown})" + (f" -> {summary}" if summary else "")
        if line not in lines:
            lines.append(line)
    return lines


def _writes_of(rec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for a in rec.get("actions") or []:
        if a.get("undone"):
            continue      # the analyst took it back off the case; it is NOT there any more
        out.append(f"{a.get('tool')}: {_clip(a.get('summary'), 160)}")
    return out


def build(records: list[dict[str, Any]], *, max_chars: int = MAX_BRIEF_CHARS) -> str:
    """The prior-conversation block for a follow-up turn, or '' when there is nothing to carry."""
    turns = [r for r in records if (r.get("prompt") or r.get("answer") or r.get("transcript"))]
    if not turns:
        return ""
    dropped = max(0, len(turns) - MAX_TURNS)
    turns = turns[-MAX_TURNS:]

    ids: list[str] = []
    writes: list[str] = []
    parts: list[str] = [HEADER]
    if dropped:
        parts.append(f"\n({dropped} earlier turn(s) of this conversation are not shown.)")

    for i, rec in enumerate(turns):
        recent = i >= len(turns) - 2
        n = dropped + i + 1
        head = f"\n--- TURN {n} — the analyst asked: {_clip(rec.get('prompt'), 600)}"
        state = str(rec.get("state") or "")
        if state and state != "done":
            head += f"  [this turn ended: {state}{' / ' + str(rec.get('reason')) if rec.get('reason') else ''}]"
        parts.append(head)
        calls = _calls_of(rec)
        if calls:
            parts.append("Tools already run (their answers are below — do not run them again):\n" +
                         "\n".join(f"  {c}" for c in calls[:MAX_CALLS_PER_TURN]))
        answer = str(rec.get("answer") or "").strip()
        if answer:
            parts.append("You reported:\n" + _clip(answer, MAX_ANSWER_RECENT if recent else MAX_ANSWER_OLDER))
        _ids_from(rec, ids)
        writes.extend(_writes_of(rec))

    if ids:
        parts.append("\nVERIFIED EVENT IDS already seen in this conversation (real, cite verbatim):\n" +
                     ", ".join(ids))
    if writes:
        parts.append("\nALREADY WRITTEN TO THE CASE by earlier turns — do NOT write these again; add "
                     "what is missing, or correct them with the update_/delete_ tools:\n" +
                     "\n".join(f"- {w}" for w in writes[-40:]))
    else:
        parts.append("\nNOTHING has been written to the case by this conversation yet.")

    brief = "\n".join(parts)
    if len(brief) > max_chars:
        # keep the head (the earlier objectives) and the tail (the latest report, the ids, the writes):
        # the middle is the oldest prose, which is the least useful thing to a follow-up.
        brief = brief[: max_chars // 3] + "\n… [earlier turns abbreviated] …\n" + brief[-(2 * max_chars // 3):]
    return brief


def for_run(run_id: str, *, exclude: str = "") -> tuple[str, str, str, Optional[dict[str, Any]]]:
    """(brief, threadId, parentId, parent record) for a follow-up continuing `run_id`.

    Returns an empty brief when the id is unknown — a follow-up whose parent has been pruned or deleted
    must still RUN, as a fresh conversation, rather than failing on a missing transcript.
    """
    from .runs import thread as _thread

    rows = [r for r in _thread(run_id) if r.get("id") != exclude]
    if not rows:
        return "", "", "", None
    parent = rows[-1]
    thread_id = str(parent.get("threadId") or parent.get("id") or run_id)
    return build(rows), thread_id, str(parent.get("id") or run_id), parent
