"""Automatic context compaction — how a long investigation finishes instead of stopping.

The context ceiling used to be a TERMINAL bound: when the estimated transcript passed
`IRIS_AI_MAX_CONTEXT_TOKENS` the run did one wrap-up turn and ended, mid-investigation, with the
analyst reading "budget reached". Tool results are what grow (a 50-row search per step), and they are
also the most compressible thing in the transcript, so the ceiling is the wrong place to give up.

WHAT COMPACTION DOES
  • keeps the system message and the ORIGINAL analyst objective verbatim — the task must never be the
    thing that gets summarised away;
  • keeps a contiguous TAIL of recent turns verbatim, so the model's immediate working state survives;
  • replaces everything in between with ONE running brief: the tools already called and what they
    returned, every event id that has been seen (citations are load-bearing — a claim whose citation was
    compacted away would become uncited and the citation validator would then flag the model's own
    correct finding), the indicators/entities established, what has already been written to the case,
    and the model's own prose findings so far.

The brief is built DETERMINISTICALLY, not by asking the model to summarise itself. A summarisation call
is another provider round-trip that can fail, costs budget of its own, and can drop or invent a cited
id — the one thing this transcript cannot afford. Everything the brief needs is already structured.

WHY THE TAIL MUST START ON A NON-TOOL MESSAGE
The chat-completions schema requires every `role:"tool"` message to answer an assistant message that
carries the matching `tool_calls`. Cutting the transcript in the middle of a tool round leaves orphan
tool results and the provider rejects the whole request, so the cut point is moved forward to the first
message that is not a tool result — a contiguous suffix then always has both halves of every pair.

BOUNDED, in both directions:
  • at most `max_compactions` per run (IRIS_AI_MAX_COMPACTIONS, default 6, hard cap 20);
  • a FLOOR: if a compaction cannot get the estimate below `floor_ratio` of the ceiling — the brief plus
    the kept tail are simply too big — it refuses and the run stops on the context budget as before.
    Without that floor a run whose tail alone exceeds the ceiling would compact, fail to shrink, and
    compact again forever.
Wall clock and the 200-writes limit stay hard stops: this raises the CONTEXT ceiling, not the others.
"""
from __future__ import annotations

import re
from typing import Any, Optional

import orjson

from . import eventids

MAX_BRIEF_CHARS = 6000
MAX_IDS = 120
MAX_LINES = 40
TAIL_MESSAGES = 6          # recent messages kept verbatim (before the non-tool adjustment)
MIN_COMPACTIBLE = 4        # fewer middle messages than this and there is nothing worth summarising

# Event ids are HEX (`e79f`, `l6e2c94f91078ed`) — see ai/eventids.py. This used to be a decimal
# pattern, so every id past `e9` containing a letter was dropped from the brief: the run then
# carried on with its citations missing, and the citation validator flagged its own correct finding.
_ID_RE = eventids.BARE

BRIEF_HEADER = (
    "RUNNING BRIEF — the earlier part of this investigation was summarised to stay inside the context "
    "window. Everything below is established fact from tool results you already saw; treat the event "
    "ids as verified and cite them verbatim. Continue the objective from here.")


def _text_of(msg: dict[str, Any]) -> str:
    c = msg.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):  # some gateways return content parts
        return " ".join(str(p.get("text") or "") for p in c if isinstance(p, dict))
    return ""


def _ids_in(text: str, out: list[str]) -> None:
    for m in _ID_RE.finditer(text or ""):
        if m.group(1) not in out and len(out) < MAX_IDS:
            out.append(m.group(1))


def safe_cut(messages: list[dict[str, Any]], keep_tail: int) -> int:
    """Index of the first message of the kept tail: never a `role:'tool'` message (see module docstring)."""
    start = max(2, len(messages) - keep_tail)   # 0 = system, 1 = the objective; never cut those away
    while start < len(messages) and messages[start].get("role") == "tool":
        start += 1
    return start


def build_brief(middle: list[dict[str, Any]], actions: list[dict[str, Any]], objective: str) -> str:
    """One user-role message standing in for `middle`. Deterministic and bounded."""
    calls: list[str] = []
    findings: list[str] = []
    ids: list[str] = []
    seen_calls: set[str] = set()
    pending: dict[str, str] = {}
    for msg in middle:
        role = msg.get("role")
        if role == "assistant":
            text = _text_of(msg).strip()
            if text:
                _ids_in(text, ids)
                findings.append(text)
            for c in msg.get("tool_calls") or []:
                fn = c.get("function") or {}
                name = str(fn.get("name") or "")
                raw = str(fn.get("arguments") or "")
                pending[str(c.get("id") or "")] = name
                line = f"{name}({raw[:180]})"
                if line not in seen_calls:
                    seen_calls.add(line)
                    calls.append(line)
        elif role == "tool":
            body = _text_of(msg)
            _ids_in(body, ids)
            name = str(msg.get("name") or pending.get(str(msg.get("tool_call_id") or "")) or "tool")
            calls.append(f"  ↳ {name} returned: {_result_gist(body)}")
        elif role == "user":
            text = _text_of(msg).strip()
            if text and text != objective:
                _ids_in(text, ids)

    parts = [BRIEF_HEADER, f"\nOBJECTIVE (unchanged): {objective[:600]}"]
    if calls:
        parts.append("\nWORK ALREADY DONE (do not repeat these calls — their answers are below):\n" +
                     "\n".join(calls[-MAX_LINES:]))
    if findings:
        joined = "\n".join(findings[-MAX_LINES:])
        parts.append("\nWHAT YOU HAVE ESTABLISHED SO FAR:\n" + joined[-3000:])
    if ids:
        parts.append("\nVERIFIED EVENT IDS seen in those results (cite these verbatim; they are real):\n" +
                     ", ".join(ids))
    if actions:
        parts.append("\nALREADY WRITTEN TO THE CASE (do not write these again):\n" +
                     "\n".join(f"- {a.get('tool')}: {a.get('summary')}" for a in actions[-MAX_LINES:]))
    parts.append("\nCONTINUE the objective from here: what is still unanswered, answer it, then report.")
    brief = "\n".join(parts)
    if len(brief) > MAX_BRIEF_CHARS:
        # keep the head (objective, work done) and the tail (ids, writes, instruction) — the middle is prose
        brief = brief[: MAX_BRIEF_CHARS // 2] + "\n… [brief truncated] …\n" + brief[-MAX_BRIEF_CHARS // 2:]
    return brief


def _result_gist(body: str) -> str:
    """A tool result reduced to the numbers that matter. Falls back to a clipped string."""
    try:
        data = orjson.loads(body)
    except (orjson.JSONDecodeError, TypeError, ValueError):
        return (body or "")[:200]
    if isinstance(data, dict):
        if "error" in data:
            return f"error: {str(data['error'])[:160]}"
        keep = {k: data[k] for k in ("total", "returned", "distinctGroups", "engine", "hits", "ok", "caseId",
                                     "added", "removed", "ruleId", "linkId", "noteId") if k in data}
        if "groups" in data and isinstance(data["groups"], list):
            keep["groups"] = [{"value": g.get("value"), "count": g.get("count")} for g in data["groups"][:12]]
        if "rows" in data and isinstance(data["rows"], list):
            keep["ids"] = [r.get("id") for r in data["rows"][:20] if isinstance(r, dict)]
        if keep:
            return orjson.dumps(keep).decode()[:400]
    return body[:200]


def compact(messages: list[dict[str, Any]], actions: list[dict[str, Any]], *,
            keep_tail: int = TAIL_MESSAGES, force: bool = False) -> Optional[tuple[list[dict[str, Any]], int]]:
    """(new transcript, number of messages folded away) — or None when there is nothing worth folding.

    `force` folds even a short middle. Used when the PROVIDER has refused the transcript for its size
    (client.ContextTooLong): at that point "not worth summarising" is not a judgement Iris gets to
    make, because the alternative is the run ending.
    """
    if len(messages) < 4:
        return None
    start = safe_cut(messages, keep_tail)
    middle = messages[2:start]
    if len(middle) < (1 if force else MIN_COMPACTIBLE):
        return None
    objective = _text_of(messages[1])
    brief = build_brief(middle, actions, objective)
    out = [messages[0], messages[1], {"role": "user", "content": brief}] + messages[start:]
    return out, len(middle)
