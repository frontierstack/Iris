"""The tool-using investigative agent: one free-form analyst objective, many bounded steps, streamed.

This replaces the fixed pipeline of canned parallel agents for the "do an investigation" case. The
analyst types what they want ("trace everything to do with 45.83.140.22 and build me a case"); the
model then drives the app itself — think, call a tool, read the result, call another — until it has an
answer, and every step is streamed to the panel so the analyst watches the investigation rather than a
spinner.

BOUNDS (all four, because each fails differently):
  • steps      — IRIS_AI_MAX_STEPS, default 40, hard cap 120. A loop that keeps re-searching forever.
                 It used to default to 14, which stopped real investigations rather than loops.
  • wall clock — IRIS_AI_MAX_SECONDS, default 600, hard cap 900. A single slow provider call chain.
  • context    — IRIS_AI_MAX_CONTEXT_TOKENS, default 60 000 (estimated at 4 chars/token). NO LONGER a
                 terminal bound: hitting it COMPACTS the transcript (ai/compaction.py) and the run
                 carries on, bounded by IRIS_AI_MAX_COMPACTIONS (default 6) and by a floor below which
                 compaction refuses instead of looping.
  • writes     — 200 per run, enforced in tools.RunContext.
  • ONE CALL   — IRIS_AI_TOOL_SECONDS, default 90, hard cap 600. The other four are per RUN, and a
                 single unbounded tool call could spend all of them with nothing able to interrupt it.
                 See STOPPING below and `_watch`.
When steps, wall clock or an uncompactable context trips, the run does ONE final turn with the tools
switched off (`tool_choice:'none'`) so the analyst gets the report the work already earned. That final
turn is also where a model that still wants to act writes the call out as prose — see
client.parse_text_tool_calls; raw tool-call markup is stripped and reported, never printed at the
analyst.

STOPPING: `runs.request_stop(run_id)` sets a flag that is checked before every step, inside the token
loop and after every tool call. Those three checkpoints all fire BETWEEN operations, so on their own
they cannot interrupt a tool that is already executing — measured live, a run parked inside
`entity_profile` at step 1 on an 11.4 M-event pool accepted a Stop in 100 ms and was still `running,
steps: 0` twenty seconds later. Two things close that hole, neither of which kills a thread (a
half-built derived structure or a partially swapped source is worse than a slow stop):
  • the flag is handed to the tool layer as `RunContext.stopper`, so a handler that waits on anything
    (`tools._await_derived`) checks it every 250 ms and refuses with a ToolError;
  • `_watch` runs every handler off the loop and watches it: a READ tool that has not cooperated is
    abandoned (left to finish, result discarded) once the analyst stops or once its deadline plus a
    grace period passes. A WRITE gets 3x the budget and is never abandoned for a stop alone — see
    `_watch` for why, and for why it is still finite.
So a stop lands in ~0.25 s for a cooperating handler and within `IRIS_AI_TOOL_SECONDS` + 5 s for one
that never looks up. Closing the SSE stream also ends the run — the generator stops being pulled.

That per-CALL deadline is what makes the four per-RUN bounds above mean anything: all four are checked
BETWEEN operations, so one tool call that never returns defeats every one of them at once. Measured:
a run parked in `entity_profile` sat at `steps: 0` for ~30 minutes, long past its own `maxSeconds: 600`,
with a stop requested 28 minutes earlier, and the wrap-up turn that owes the analyst a report never ran.

CONVERSATIONS: a follow-up question is a NEW run that carries `continue_from` — same thread, fresh
budgets, its own undo list — and starts from a deterministic brief of what the earlier turns
established (ai/continuation.py). Before that, every prompt was a cold start, so "now build me the
timeline" re-ran the whole investigation it had just reported on and spent its budget rediscovering
facts the analyst had already been told.

TWO NUDGES the loop injects, both as ordinary user turns, both bounded, neither able to force the
model's hand — the model can decline either and carry on:
  • CHECK_IN, every CHECK_IN_EVERY tool calls (max MAX_CHECK_INS): "can you answer now?". The
    budgets are a runaway-loop ceiling, but a model reads them as a plan and keeps drilling long
    after the question was answered.
  • DOCUMENT_CHECK, once, when a run that did real work is about to finish having written NOTHING to
    the case. A finding that lives only in the chat is lost when the panel closes.

The generator NEVER raises: every failure becomes a terminal {"type":"error"} event, like graph_review.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any, AsyncIterator, Callable, Optional

import orjson

from ..config import get_settings
from . import compaction, continuation, runs
from .client import AIError, LLMClient, absorb_text_calls, has_tool_call_syntax, parse_text_tool_calls
from .history import HISTORY
from .prompts import (CHECK_IN, DOCUMENT_CHECK, INVESTIGATOR_SYSTEM, WRAP_UP,
                      investigator_user_prompt)
from .tools import (REGISTRY, RunContext, ToolError, tool_budget_seconds, tool_schemas,
                    unverified_citations)

DISABLED_MESSAGE = ("AI assistant is disabled — choose a provider and add an API key in Settings → AI "
                    "assistant. The investigator needs a model that supports tool calling.")

MAX_STEPS_CAP = 120
MAX_SECONDS_CAP = 900
MAX_COMPACTIONS_CAP = 20
TOOL_RESULT_CHARS = 6000     # one tool result handed back to the model
MAX_WRITES = 200
# How often the loop looks up from a running tool call to check the stop flag and the deadline. The
# handler runs on a worker thread; this is the event loop watching it, not polling inside it.
TOOL_POLL = 0.25
# Grace on top of the tool's own budget before the loop stops waiting for a handler that is not
# cooperating. A handler that checks `ctx.check()` refuses first, with a far better message; this is
# the backstop for one that never looks up (a cold-index search over 11 M events, say).
TOOL_GRACE = 5.0
# A write gets this multiple of the budget before the loop gives up on it — see `_watch`. It is a much
# longer rope on purpose, and it is still finite: the run must be able to end.
WRITE_DEADLINE_FACTOR = 3.0
# Below this fraction of the ceiling a compaction counts as having worked. If the brief plus the kept
# tail cannot get under it, compacting again would not help either — see ai/compaction.py.
COMPACT_FLOOR = 0.8
# How many tool calls a run may make before the loop asks it, once per interval, whether it can
# already answer. The analyst's report: a question about one IP "went through a lot of tool calls, it
# did find good info, but it likely went deeper than it should have". Left alone the model treats
# the step budget as a plan; this is what turns "am I done?" into a question it actually answers.
# It is a nudge injected as a user turn, never a forced stop — a genuine reconstruction may need more.
CHECK_IN_EVERY = 8
MAX_CHECK_INS = 3
# Below this many tool calls a run was a question, not an investigation, and asking it to write the
# case up would be noise. At or above it, finishing with an empty case is the failure the analyst
# reported: "didn't interact with the case at all when it should, that include everything in the
# case from the timeline to iocs".
DOCUMENT_MIN_CALLS = 3


def _env_int(name: str, default: int, cap: int) -> int:
    try:
        v = int(os.environ.get(name, "") or default)
    except ValueError:
        v = default
    return max(1, min(cap, v))


def limits(max_steps: Optional[int] = None, max_seconds: Optional[int] = None) -> dict[str, int]:
    """The four bounds in force for a run.

    `maxSteps` defaults to 40, not the old 14. The step count was standing in for the context ceiling —
    a long investigation ran out of steps while it was still working, and the analyst got "budget
    reached (max_steps)" instead of an answer. Context is now handled by compaction (ai/compaction.py),
    so steps only have to stop a genuine LOOP, and 40 is where a loop is obvious while real work is not
    yet finished. The wall clock is the bound that actually protects the analyst's time, and it is
    unchanged in kind (raised to 600 s by default) — it, and the 200-write limit, remain hard stops.
    """
    steps = _env_int("IRIS_AI_MAX_STEPS", 40, MAX_STEPS_CAP)
    secs = _env_int("IRIS_AI_MAX_SECONDS", 600, MAX_SECONDS_CAP)
    ctx = _env_int("IRIS_AI_MAX_CONTEXT_TOKENS", 60_000, 500_000)
    compactions = _env_int("IRIS_AI_MAX_COMPACTIONS", 6, MAX_COMPACTIONS_CAP)
    if max_steps:
        steps = max(1, min(MAX_STEPS_CAP, int(max_steps)))
    if max_seconds:
        secs = max(5, min(MAX_SECONDS_CAP, int(max_seconds)))
    return {"maxSteps": steps, "maxSeconds": secs, "maxContextTokens": ctx, "maxWrites": MAX_WRITES,
            "maxCompactions": compactions,
            # a FIFTH bound, per CALL rather than per run: without it one tool could eat the whole
            # wall clock with nothing able to interrupt it. See `_watch`.
            "maxToolSeconds": tool_budget_seconds()}


def _est_tokens(messages: list[dict[str, Any]]) -> int:
    """Cheap, deliberately pessimistic estimate — 4 characters per token over the serialized transcript."""
    try:
        return len(orjson.dumps(messages)) // 4
    except TypeError:
        return sum(len(str(m)) for m in messages) // 4


def _clip(text: str, limit: int = TOOL_RESULT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated, {len(text) - limit} more characters — narrow the query]"


def build_context(store: Any) -> str:
    """A short orientation block. Deliberately small: the agent's job is to go and look, and a huge
    prompt preamble both costs budget and invites the model to answer from the preamble instead."""
    lines: list[str] = []
    try:
        c = store.case()
        if c.pending:
            lines.append("No case exists yet (the workspace is case-less; analysis still works).")
        else:
            lines.append(f"Active case {c.id} '{c.name}' — {len(c.caseSet)} events curated into the case set, "
                         f"{len(c.notes)} note(s).")
            if getattr(store, "summary", ""):
                lines.append(f"Case summary: {store.summary[:500]}")
        lines.append(f"Pool: {c.poolEventCount:,} events across {len(c.sources) + len(c.librarySources)} source(s)."
                     + (" A background load is still in progress — results may be incomplete." if c.poolLoading else ""))
        raw_n = 0
        for s in (list(c.sources) + list(c.librarySources))[:20]:
            rng = f" {s.range[0][:19]}→{s.range[1][:19]}" if s.range else ""
            # WHETHER A SOURCE IS INTERPRETED IS PART OF ITS IDENTITY here. A raw source has no parsed
            # fields and no extracted entities, so `field:value` and `entity:"…"` cannot match it — the
            # agent was answering scope questions over the interpreted subset and calling it the pool.
            state = str(getattr(s, "enrich", "") or "")
            tag = "" if state == "enriched" else f", RAW — not interpreted ({state or 'raw'})"
            if state and state != "enriched":
                raw_n += 1
            lines.append(f"- source {s.id} {s.file} ({s.parser}, {s.events:,} events{rng}{tag})")
        if raw_n:
            lines.append(
                f"SCOPE WARNING: {raw_n} of these sources are RAW. Their lines ARE searchable and ARE in "
                "the pool, but only by FREE TEXT — they carry no parsed fields and no extracted entities, "
                "so entity:\"…\" and field:value silently skip them. For any question about totals, "
                "coverage or 'which logs mention X', search the bare value as free text (or read "
                "entity_profile's `coverage` block, which counts both) and say which sources are raw.")
    except Exception as exc:  # noqa: BLE001 — orientation must never sink the run
        lines.append(f"(workspace summary unavailable: {exc})")
    # The most common parsed field names, so a trivial question does not have to spend a discovery step
    # guessing at `src_ip` vs `client_ip`. Best effort: a facet scan must never sink the run.
    try:
        from ..routers.events import list_fields
        from .tools import call_route
        facets = call_route(list_fields, q="", scope="all", limit=18)
        names = [f["name"] for f in facets.get("fields", [])]
        if names:
            lines.append("Most common parsed fields (use them as field:value terms): " + ", ".join(names))
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(lines)


def _cache_key(name: str, args: dict[str, Any]) -> str:
    try:
        return name + "|" + orjson.dumps(args, option=orjson.OPT_SORT_KEYS).decode()
    except TypeError:
        return name + "|" + repr(sorted(args.items()))


async def _run_tool(name: str, args: dict[str, Any], ctx: RunContext) -> tuple[bool, Any]:
    t = REGISTRY.get(name)
    if t is None:
        known = ", ".join(sorted(REGISTRY))
        return False, f"no such tool: {name}. The tools you have are: {known}"
    try:
        t.validate_args(args)
    except ToolError as exc:
        return False, str(exc)
    # A read the run has already done is served from the run's own cache. Re-running it costs wall
    # clock and, worse, fills the context with a byte-identical second copy of an answer the model
    # already has — which is exactly the pressure compaction then has to relieve.
    key = "" if t.writes else _cache_key(name, args)
    if key and key in ctx.cache:
        ctx.cache_hits += 1
        cached = ctx.cache[key]
        if isinstance(cached, dict):
            return True, {**cached, "cached": True,
                          "note": "identical call already made in this run — the previous result is repeated "
                                  "verbatim, nothing was re-run. Do not issue it a third time."}
        return True, cached
    budget = float(tool_budget_seconds())
    ctx.begin_call(name, budget)
    try:
        # Tool handlers are synchronous and can be O(the pool) — a search over a million events on the
        # event loop would stall every other request in the process.
        result = await _watch(t, args, ctx, budget)
        if key:
            ctx.cache[key] = result
        return True, result
    except ToolError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


# Abandoned handler threads whose result nobody will read. Kept referenced so the event loop does not
# log "Task was destroyed but it is pending", and drained so a late exception is not reported as
# "never retrieved". The THREAD is never killed: a half-built derived structure or a partially swapped
# source is worse than a slow stop.
_ORPHANS: set[Any] = set()


def _abandon(task: Any) -> None:
    _ORPHANS.add(task)
    task.add_done_callback(lambda f: (_ORPHANS.discard(f), None if f.cancelled() else f.exception()))


async def _watch(t: Any, args: dict[str, Any], ctx: RunContext, budget: float) -> Any:
    """Run one handler off the event loop, watching the stop flag and the deadline while it runs.

    All three of the run's stop checkpoints fire BETWEEN operations, so a tool already executing could
    not be interrupted at all — measured live, a Stop accepted in 100 ms had no effect on a run parked
    inside `entity_profile` at step 1. A handler that calls `ctx.check()` now refuses within 250 ms.
    This is the backstop for one that does not: after `budget + TOOL_GRACE` (or immediately once the
    analyst has pressed Stop) the loop stops WAITING for it and reports a ToolError the model can act
    on. The work carries on to completion on its thread and its result is discarded.

    A WRITE gets a much longer rope and is never abandoned merely because the analyst stopped. Its
    `action` lands in `ctx.actions` — the list `runs.finish` persists and `POST /api/ai/runs/{id}/undo`
    reverses — so walking away from one mid-flight could leave a change on the case that the run's own
    record does not know about, i.e. an un-undoable write. Writes are bounded work; the only O(pool)
    ones (add_graph_link, the rule tools' detection re-run) are seconds, not minutes. But `never` is
    not a bound: a run that cannot terminate is the harm this whole mechanism exists to prevent, so at
    WRITE_DEADLINE_FACTOR x the budget it is abandoned too, and the refusal SAYS the change may still
    land and may be missing from the run's undo record. That is a bad outcome stated plainly, which
    beats a run that hangs for thirty minutes past every one of its four other budgets.
    """
    task = asyncio.ensure_future(asyncio.to_thread(t.fn, args, ctx))
    started = time.monotonic()
    hard = started + budget + TOOL_GRACE
    hard_write = started + budget * WRITE_DEADLINE_FACTOR + TOOL_GRACE
    while True:
        done, _pending = await asyncio.wait({task}, timeout=TOOL_POLL)
        if done:
            return task.result()
        if t.writes:
            if time.monotonic() < hard_write:
                continue
            _abandon(task)
            raise ToolError(
                f"{t.name} did not finish within {int(budget * WRITE_DEADLINE_FACTOR)}s and the run "
                "stopped waiting for it. It is a WRITE, so it may still complete on its own — check "
                "the case before repeating it, and tell the analyst it may be missing from this run's "
                "list of changes. Do not simply call it again.")
        stopped = ctx.stopping()
        if stopped or time.monotonic() >= hard:
            _abandon(task)
            if stopped:
                raise ToolError(f"stopped by the analyst while {t.name} was still running. It was left to "
                                "finish on its own thread and its result was discarded — nothing was "
                                "written and nothing is half done.")
            raise ToolError(
                f"{t.name} did not finish within {int(budget)}s on this workspace and was abandoned. "
                "This is a size problem, not an error, and it is NOT an empty result — do not report it "
                "as an absence of evidence. Make a narrower call: add a `sources`, `from`/`to` or "
                "`query` filter, use count_events / aggregate_events instead of reading rows, or use "
                "entity_profile for a single entity.")


def _n(v: Any) -> str:
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return str(v)


def _len(d: dict[str, Any], key: str) -> int:
    v = d.get(key)
    return len(v) if isinstance(v, (list, dict)) else 0


# The transcript line for each READ tool, keyed by tool name.
#
# This used to sniff the payload for well-known keys, in a fixed order — and `get_event` returns a
# payload with a `detections` key, so every single-event fetch summarised itself as "0 rule(s) fired":
# a status line about the wrong question entirely, on the tool the analyst watched the agent call
# twenty times in a row. Key-sniffing cannot be fixed by reordering, because two tools legitimately
# return the same key meaning different things. The tool knows what it was asked; it names its own line.
def _names(items: Any, key: str, cap: int = 3) -> str:
    """`nginx-access.log, auth.log +2 more` — WHERE the hits are, which a bare count never says.

    The analyst's complaint was that "1,284 matching events" does not tell them anything they can act
    on; the files those events live in is the first thing they would ask next. Every caller guards with
    `.get`, so a payload that does not carry the key degrades to the plain count, never to an error.
    """
    if not isinstance(items, list):
        return ""
    seen: list[str] = []
    for it in items:
        v = str((it or {}).get(key, "")).strip() if isinstance(it, dict) else str(it or "").strip()
        if v and v not in seen:
            seen.append(v)
    if not seen:
        return ""
    head = ", ".join(seen[:cap])
    return head + (f" +{len(seen) - cap} more" if len(seen) > cap else "")


def _where(d: dict[str, Any]) -> str:
    """The source names behind an entity_profile / aggregate answer, from its own top-N breakdown."""
    top = ((d.get("breakdown") or {}).get("source") or {}).get("top")
    return _names(top, "value")


_SUMMARY: dict[str, Callable[[dict[str, Any]], str]] = {
    "search_events": lambda d: (f"{d.get('returned', _len(d, 'rows'))} of {_n(d.get('total', 0))} matching events"
                                + (f" — {_names(d.get('rows'), 'source')}"
                                   if _names(d.get("rows"), "source") else "")),
    "get_events": lambda d: (f"read {d.get('returned', 0)} of {d.get('requested', 0)} event(s)"
                             + (f" — {_len(d, 'missing')} id(s) do not exist" if d.get("missing") else "")),
    "get_event": lambda d: (f"event {d.get('id', '?')} — {d.get('source', '?')} {d.get('ts') or 'no timestamp'}"
                            + (f", {_len(d, 'detections')} detection(s)" if d.get("detections") else "")),
    "count_events": lambda d: f"{_n(d.get('total', 0))} event(s) match",
    "aggregate_events": lambda d: (f"{d.get('distinctGroups', 0)} {d.get('groupBy', '')} group(s) "
                                   f"over {_n(d.get('total', 0))} event(s)"
                                   + (f" — top: {_names(d.get('groups'), 'value')}"
                                      if _names(d.get("groups"), "value") else "")),
    "distinct_values": lambda d: (f"{d.get('distinct', 0)} distinct {d.get('field', '')} value(s) "
                                  f"over {_n(d.get('total', 0))} event(s)"),
    "events_over_time": lambda d: (f"{_n(d.get('total', 0))} event(s) across "
                                   f"{d.get('distinctBuckets', 0)} {d.get('bucket', '')} bucket(s)"),
    "sample_events": lambda d: f"{d.get('sampled', 0)} sample row(s) from {_n(d.get('total', 0))} match(es)",
    "list_sources": lambda d: (f"{_len(d, 'caseSources')} case + {_len(d, 'librarySources')} library "
                               f"source(s), {_n(d.get('poolEventCount', 0))} events"),
    "list_event_fields": lambda d: f"{_len(d, 'fields')} field(s) over {_n(d.get('events', 0))} event(s)",
    "get_timeline": lambda d: f"{_len(d, 'clusters')} of {d.get('totalClusters', 0)} correlated cluster(s)",
    "list_detections": lambda d: f"{_len(d, 'detections')} of {d.get('total', 0)} rule(s) fired",
    "list_anomalies": lambda d: f"{d.get('shown', _len(d, 'anomalies'))} anomal(ies), {_n(d.get('totalHits', 0))} hits",
    "list_detection_rules": lambda d: f"{_len(d, 'rules')} of {d.get('total', 0)} rule(s) in the catalogue",
    "build_graph": lambda d: (f"{(d.get('totals') or {}).get('entitiesShown', 0)} entit(ies), "
                              f"{(d.get('totals') or {}).get('relationsShown', 0)} relation(s)"),
    "graph_sources": lambda d: f"{_len(d, 'sources')} of {d.get('total', 0)} source(s) contribute entities",
    "graph_find": lambda d: f"{_len(d, 'nodes')} matching node(s) of {d.get('totalNodes', 0)}",
    "graph_node": lambda d: (f"{(d.get('node') or {}).get('id', 'node')} — {_len(d, 'neighbours')} "
                             f"relation(s), {_len(d, 'timeline')} event(s)"),
    "graph_path": lambda d: (f"path found: {' → '.join(d.get('path') or [])}" if d.get("found")
                             else "no path between those entities"),
    "entity_profile": lambda d: (f"{d.get('value', '?')}: {_n(d.get('total', 0))} event(s) in "
                                 f"{(d.get('breakdown') or {}).get('source', {}).get('distinct', 0)} source(s)"
                                 + (f" — {_where(d)}" if _where(d) else "")
                                 + f", {(d.get('graph') or {}).get('totalRelations', 0)} relation(s)"),
    "list_iocs": lambda d: f"{_len(d, 'iocs')} indicator(s)",
    "list_notes": lambda d: f"{_len(d, 'notes')} case note(s)",
    "list_graph_links": lambda d: f"{_len(d, 'links')} manual graph link(s)",
    "list_cases": lambda d: f"{d.get('total', _len(d, 'cases'))} case(s), active {d.get('activeCaseId') or 'none'}",
    "get_case_set": lambda d: f"{d.get('shown', _len(d, 'entries'))} of {d.get('total', 0)} curated event(s)",
    "get_case_state": lambda d: (f"case {d.get('caseId')} '{d.get('name')}'" if d.get("hasCase")
                                 else "no case — the workspace is case-less"),
}


def _summarize(name: str, ok: bool, data: Any) -> str:
    """One line for the transcript UI — the analyst should be able to follow without opening payloads."""
    if not ok:
        return f"refused: {str(data)[:200]}"
    if not isinstance(data, dict):
        return "ok"
    # a write reports what it changed; that summary is written by the tool itself
    action = data.get("action")
    if isinstance(action, dict):
        return str(action.get("summary", "changed the case"))
    fn = _SUMMARY.get(name)
    line = ""
    if fn is not None:
        try:
            line = fn(data)
        except Exception:  # noqa: BLE001 — a transcript line must never sink a run
            line = ""
    if not line:
        line = "ok"
    return line + (" (repeat of an earlier call)" if data.get("cached") else "")


def _case_tag(store: Any) -> tuple[str, str]:
    """The case this run is ASSOCIATED with — empty in the case-less workspace. See ai/history.py."""
    try:
        if getattr(store, "pending", False):
            return "", ""
        return str(getattr(store, "case_id", "") or ""), str(getattr(store, "name", "") or "")
    except Exception:  # noqa: BLE001 — a transcript tag must never sink a run
        return "", ""


def _case_open(store: Any) -> bool:
    """Is there a case to write into? `pending` means an id held in reserve and nothing on disk."""
    try:
        return not bool(getattr(store, "pending", False))
    except Exception:  # noqa: BLE001 — never sink a run over an orientation question
        return False


async def investigate(store: Any, objective: str, run_id: str,
                      max_steps: Optional[int] = None, max_seconds: Optional[int] = None,
                      client: Optional[LLMClient] = None, focus: str = "",
                      continue_from: str = "") -> AsyncIterator[dict[str, Any]]:
    """Async generator of SSE-ready dicts — see docs/API_CONTRACT.md → "AI investigator".

    `continue_from` is the previous run of the SAME conversation. The turn is still its own run —
    its own budget, its own stop, its own undo list — but it starts from a brief of what the earlier
    turns established (ai/continuation.py) instead of from nothing. Without it, "now build me the
    timeline" re-ran the entire investigation it had just reported on.

    Every event that the panel renders is ALSO appended to the persisted transcript
    (`ai/history.py`), so a client that refreshes, opens a second tab or reconnects after a dropped
    stream can rejoin by polling `GET /api/ai/runs/{id}?since=<seq>` instead of losing the run.
    """
    lim = limits(max_steps, max_seconds)
    settings = get_settings()
    client = client or LLMClient.from_settings(settings.ai)
    # `stopper` is what makes a stop observable INSIDE a tool: a handler that waits on a derived build
    # calls ctx.check() and refuses within 250 ms, instead of the run sitting at `steps: 0` for minutes
    # after the analyst pressed Stop and got an instant HTTP 200.
    ctx = RunContext(run_id=run_id, model=client.model, max_writes=lim["maxWrites"],
                     stopper=lambda: runs.stop_requested(run_id))
    case_id, case_name = _case_tag(store)
    # A follow-up inherits the conversation, not the run: same thread, fresh budgets. Resolved BEFORE
    # `runs.start`, because the record it writes is what carries `threadId` for every later turn.
    prior_brief, thread_id, parent_id = "", "", ""
    if continue_from:
        prior_brief, thread_id, parent_id, _parent = await asyncio.to_thread(
            continuation.for_run, continue_from, exclude=run_id)
    runs.start(run_id, objective, client.model, focus=focus, case_id=case_id, case_name=case_name,
               parent_id=parent_id, thread_id=thread_id)
    yield {"type": "run", "runId": run_id, "model": client.model,
           "threadId": thread_id or run_id, "parentId": parent_id, **lim}

    objective = (objective or "").strip()
    if not objective:
        msg = "Type what you want investigated — the agent needs an objective."
        runs.finish(run_id, "error", "error", 0, 0, "", [], [], msg)
        yield {"type": "error", "message": msg}
        return

    if not client.configured:
        runs.finish(run_id, "error", "error", 0, 0, "", [], [], DISABLED_MESSAGE)
        yield {"type": "error", "message": DISABLED_MESSAGE}
        return

    tools = tool_schemas()
    # the focus note is context for the MODEL only — the transcript stores the analyst's words verbatim
    asked = objective + (f"\n\n(The analyst opened this from: {focus})" if focus else "")
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": INVESTIGATOR_SYSTEM},
        {"role": "user", "content": investigator_user_prompt(asked, build_context(store), prior_brief)},
    ]
    started = time.monotonic()
    step = 0
    tool_calls = 0
    compactions = 0
    check_ins = 0            # scope nudges sent (see CHECK_IN_EVERY)
    next_check_in = CHECK_IN_EVERY
    documented = False       # the "you wrote nothing to the case" prompt has been sent once
    text_mode = False        # the provider is not doing native tool calling; we parsed the text form
    answer = ""
    reason = "complete"
    state = "done"
    error = ""

    def elapsed() -> float:
        return time.monotonic() - started

    try:
        # The old line read "up to 40 steps, 600s, 46 tools", which the analyst reasonably took as a
        # plan the agent intended to work through. Those numbers are a runaway-loop ceiling, and the
        # line now says which is which.
        opening = (f"investigating with {client.model} — it stops as soon as it can answer "
                   f"(ceiling: {lim['maxSteps']} steps / {lim['maxSeconds']}s, {len(tools)} tools "
                   f"available)")
        if continue_from:
            opening = (f"continuing the conversation with {client.model} — it already has what the "
                       f"earlier turns established")
        HISTORY.append(run_id, {"kind": "status", "text": opening})
        yield {"type": "status", "text": opening}
        while True:
            if runs.stop_requested(run_id):
                reason, state = "stopped", "stopped"
                break
            if step >= lim["maxSteps"]:
                reason = "max_steps"
                break
            if elapsed() >= lim["maxSeconds"]:
                reason = "timeout"
                break
            if _est_tokens(messages) >= lim["maxContextTokens"]:
                # The context ceiling is not a reason to abandon an investigation: fold the earlier turns
                # into a running brief and carry on. Bounded by maxCompactions and by the floor below —
                # if compacting cannot buy room, the run stops on the budget exactly as it used to.
                folded = None
                if compactions < lim["maxCompactions"]:
                    # Try progressively shorter tails: on a run whose individual tool results are large,
                    # six recent messages can be over the ceiling on their own, and giving up there would
                    # stop an investigation that a two-message tail could have carried on.
                    for tail in (compaction.TAIL_MESSAGES, 4, 2):
                        attempt = compaction.compact(messages, ctx.actions, keep_tail=tail)
                        if attempt is None:
                            continue
                        folded = attempt
                        if _est_tokens(attempt[0]) < lim["maxContextTokens"] * COMPACT_FLOOR:
                            break
                if folded is None:
                    reason = "budget"
                    break
                candidate, dropped = folded
                if _est_tokens(candidate) >= lim["maxContextTokens"] * COMPACT_FLOOR:
                    note = ("context is full and summarising the earlier steps did not free enough room — "
                            "stopping and reporting what is established")
                    HISTORY.append(run_id, {"kind": "warning", "text": note})
                    yield {"type": "warning", "message": note, "ids": []}
                    reason = "budget"
                    break
                messages = candidate
                compactions += 1
                note = (f"compacted {dropped} earlier steps into a running brief "
                        f"(compaction {compactions} of {lim['maxCompactions']}) — the objective, the "
                        f"verified event ids and everything already written to the case were kept")
                HISTORY.append(run_id, {"kind": "status", "text": note})
                yield {"type": "status", "text": note, "compactions": compactions, "droppedMessages": dropped}

            # SCOPE CHECK-IN. Injected as a user turn between steps, at most MAX_CHECK_INS times: it
            # costs nothing when the model was about to finish anyway, and it is the only thing that
            # interrupts a drill-down that has stopped changing the answer. Never a forced stop — the
            # model may decline it and keep going, which a genuine reconstruction sometimes should.
            if tool_calls >= next_check_in and check_ins < MAX_CHECK_INS:
                check_ins += 1
                next_check_in = tool_calls + CHECK_IN_EVERY
                messages.append({"role": "user", "content": CHECK_IN.format(calls=tool_calls)})
                note = (f"{tool_calls} tool calls so far — asked the assistant whether it can answer "
                        f"now rather than keep investigating")
                HISTORY.append(run_id, {"kind": "status", "text": note})
                yield {"type": "status", "text": note, "checkIn": check_ins}
            step += 1
            HISTORY.append(run_id, {"kind": "step", "step": step})
            yield {"type": "step", "step": step, "elapsedSec": round(elapsed(), 1)}
            buf: list[str] = []
            final_msg: dict[str, Any] = {}
            async for item in client.stream_chat(messages, tools=tools, max_tokens=1400, temperature=0.1):
                # Checked INSIDE the token loop, not only between steps: a plain question streams prose
                # and never calls a tool, so a stop that was only checked at the two old checkpoints
                # could not interrupt it at all — which is what "there is no way to stop it" meant.
                if runs.stop_requested(run_id):
                    break
                if item["type"] == "text":
                    buf.append(item["text"])
                    HISTORY.append_text(run_id, item["text"])
                    yield {"type": "delta", "text": item["text"], "step": step}
                elif item["type"] == "message":
                    final_msg = item["message"]
            if runs.stop_requested(run_id):
                answer = final_msg.get("content") or "".join(buf)
                reason, state = "stopped", "stopped"
                break
            if not final_msg:
                final_msg = {"role": "assistant", "content": "".join(buf)}
            # The one place text-mode tool calls are turned into real ones, whatever client produced the
            # message. `textToolCalls*` are markers absorb_text_calls leaves behind, not part of the wire schema —
            # they must not be echoed back to the provider on the next turn.
            final_msg = absorb_text_calls(final_msg)
            parsed_text_call = bool(final_msg.pop("textToolCalls", False))
            unparsed_text_call = bool(final_msg.pop("textToolCallsUnparsed", False))
            if parsed_text_call and not text_mode:
                text_mode = True
                note = ("this provider is not returning native tool calls — the model wrote the call out as "
                        "text and Iris parsed it. Results may be less reliable; a model with proper "
                        "tool-calling support is strongly preferred.")
                HISTORY.append(run_id, {"kind": "warning", "text": note})
                yield {"type": "warning", "message": note, "ids": []}
            if unparsed_text_call:
                note = ("the model emitted tool-call markup that could not be parsed into a real call; it was "
                        "removed from the transcript. Ask it to use the tools directly.")
                HISTORY.append(run_id, {"kind": "warning", "text": note})
                yield {"type": "warning", "message": note, "ids": []}
            messages.append(final_msg)

            calls = final_msg.get("tool_calls") or []
            if not calls:
                answer = final_msg.get("content") or "".join(buf)
                # THE CASE IS THE POINT. A run that investigated and wrote nothing down leaves the
                # analyst to re-key every finding by hand — reported as "didn't interact with the case
                # at all when it should, that include everything in the case from the timeline to
                # iocs". So once, before letting it finish, ask. It is a prompt and not a forced write:
                # the model may answer "nothing here warrants recording", which for a plain question is
                # the right answer, and inventing a finding to have something to file would be worse
                # than filing nothing. Only when there IS a case (writes refuse while pending) and the
                # run did real work (DOCUMENT_MIN_CALLS).
                if (not documented and ctx.writes == 0 and tool_calls >= DOCUMENT_MIN_CALLS
                        and _case_open(store) and not runs.stop_requested(run_id)
                        and elapsed() < lim["maxSeconds"] and step < lim["maxSteps"]
                        # ...and only if there is room to pay for the turn. A run at its context
                        # ceiling that is handed one more user message compacts or stops on the
                        # budget, and the report it had ALREADY WRITTEN is replaced by whatever
                        # the wrap-up manages. Losing the answer to ask for a write-up is a much
                        # worse trade than finishing with an unwritten case.
                        and _est_tokens(messages) < lim["maxContextTokens"]):
                    documented = True
                    messages.append({"role": "user", "content": DOCUMENT_CHECK})
                    note = "nothing recorded in the case yet — asking the assistant to write up what it found"
                    HISTORY.append(run_id, {"kind": "status", "text": note})
                    yield {"type": "status", "text": note, "documentCheck": True}
                    continue
                reason = "complete"
                break

            for call in calls:
                if runs.stop_requested(run_id):
                    break
                fn = call.get("function") or {}
                name = str(fn.get("name") or "")
                raw_args = fn.get("arguments") or "{}"
                try:
                    args = orjson.loads(raw_args) if raw_args.strip() else {}
                    if not isinstance(args, dict):
                        raise ValueError("arguments were not a JSON object")
                except (orjson.JSONDecodeError, ValueError) as exc:
                    args, parse_err = {}, f"could not parse the arguments you sent ({exc}). Send valid JSON."
                else:
                    parse_err = ""
                tool_calls += 1
                call_id = str(call.get("id") or f"{run_id}-c{tool_calls}")
                writes = bool(getattr(REGISTRY.get(name), "writes", False))
                HISTORY.append(run_id, {"kind": "tool", "id": call_id, "name": name, "args": args,
                                        "writes": writes})
                # `call_id`, NOT `call.get("id")`: a provider that omits the id (or repeats one) made
                # every live tool_call carry `id: null`, so the panel matched the RESULT against the
                # first null-id card and the rest span forever. The persisted transcript already used
                # the stamped id; the stream now uses the same one, so live and reloaded agree.
                yield {"type": "tool_call", "id": call_id, "name": name, "arguments": args, "step": step}
                t0 = time.perf_counter()
                if parse_err:
                    ok, result = False, parse_err
                else:
                    ok, result = await _run_tool(name, args, ctx)
                took = int((time.perf_counter() - t0) * 1000)
                payload = result if ok else {"error": result}
                body = _clip(orjson.dumps(payload).decode())
                messages.append({"role": "tool", "tool_call_id": call.get("id"), "name": name, "content": body})
                summary = _summarize(name, ok, result)
                HISTORY.tool_result(run_id, call_id, ok, summary, took)
                yield {"type": "tool_result", "id": call_id, "name": name, "ok": ok, "tookMs": took,
                       "summary": summary,
                       "data": payload if len(body) <= 4000 else {"truncated": True}}
                action = result.get("action") if (ok and isinstance(result, dict)) else None
                if action:
                    HISTORY.note_action(run_id, action)
                    yield {"type": "write", "action": action}

        # ---- wrap-up: a budget stop still owes the analyst the report the work earned.
        # This is also where raw tool-call syntax used to reach the analyst: the final turn is asked for
        # with tool_choice:'none', so a model that still wants to act writes the call out as prose. It is
        # stripped here and reported as what it was — an attempted call after the budget ran out.
        if reason in ("max_steps", "timeout", "budget") and not runs.stop_requested(run_id):
            note = f"budget reached ({reason}) — writing the final report"
            HISTORY.append(run_id, {"kind": "status", "text": note})
            yield {"type": "status", "text": note}
            messages.append({"role": "user", "content": WRAP_UP})
            buf = []
            wrap_msg: dict[str, Any] = {}
            async for item in client.stream_chat(messages, tools=None, max_tokens=1400, temperature=0.1,
                                                 tool_choice="none"):
                if runs.stop_requested(run_id):
                    break
                if item["type"] == "text":
                    buf.append(item["text"])
                    HISTORY.append_text(run_id, item["text"])
                    yield {"type": "delta", "text": item["text"], "step": step}
                elif item["type"] == "message":
                    wrap_msg = item["message"]
            # The assembled message is the fallback, exactly as in the main loop. Collecting ONLY the
            # `text` deltas meant that a provider which streams no prose deltas — perfectly legal, the
            # client always yields the assembled `message` — produced an EMPTY report after a run had
            # spent its entire budget. That is the "it ran for ages and gave me no answer" case, and the
            # report the model actually wrote was sitting in the message the whole time.
            wrapped = "".join(buf) or str(wrap_msg.get("content") or "")
            if wrapped and not buf:
                HISTORY.append_text(run_id, wrapped)       # deltas never carried it into the transcript
                yield {"type": "delta", "text": wrapped, "step": step}
            # never let an empty wrap-up erase what the run had already established
            if wrapped:
                answer = wrapped

        if has_tool_call_syntax(answer):
            answer, attempted = parse_text_tool_calls(answer)
            names = ", ".join(sorted({str((c.get("function") or {}).get("name") or "?") for c in attempted})) or "a tool"
            note = (f"the model tried to call {names} after its budget ran out; the call was NOT executed and "
                    "its markup was removed from the report")
            HISTORY.append(run_id, {"kind": "warning", "text": note})
            yield {"type": "warning", "message": note, "ids": []}

        unverified = await asyncio.to_thread(unverified_citations, answer)
        if unverified:
            warn = ("these event ids in the answer do not exist in this workspace and must not be "
                    "trusted: " + ", ".join(unverified))
            HISTORY.append(run_id, {"kind": "warning", "text": warn})
            yield {"type": "warning", "message": warn, "ids": unverified}
        if answer:
            yield {"type": "answer", "text": answer}
        runs.finish(run_id, state, reason, step, tool_calls, answer, ctx.actions, unverified)
        yield {"type": "done", "runId": run_id, "threadId": thread_id or run_id,
               "parentId": parent_id, "reason": reason, "state": state, "steps": step,
               "toolCalls": tool_calls, "writes": ctx.writes, "actions": ctx.actions,
               "unverifiedCitations": unverified, "answer": answer, "elapsedSec": round(elapsed(), 1),
               "compactions": compactions, "cachedToolCalls": ctx.cache_hits, "textToolCalls": text_mode}
    except AIError as exc:
        error = str(exc)
        runs.finish(run_id, "error", "error", step, tool_calls, answer, ctx.actions, [], error)
        yield {"type": "error", "message": error, "actions": ctx.actions}
    except asyncio.CancelledError:
        runs.finish(run_id, "stopped", "disconnected", step, tool_calls, answer, ctx.actions, [])
        raise
    except Exception as exc:  # noqa: BLE001 — never raise out of the stream
        error = f"investigation failed: {type(exc).__name__}: {exc}"
        runs.finish(run_id, "error", "error", step, tool_calls, answer, ctx.actions, [], error)
        yield {"type": "error", "message": error, "actions": ctx.actions}
