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

THREE NUDGES the loop injects, all as ordinary user turns, all bounded, none able to force the
model's hand — the model can decline any of them and carry on:
  • CHECK_IN, only after CHECK_IN_STREAK consecutive tool calls that returned NOTHING NEW (a repeat,
    a refusal, an empty result). It used to fire on the call count alone, every 8 calls, and was
    reported as pushing the model to "stop investigating too early when it probably should
    continue... a lot of log files that might need to be sifted through". Call count cannot tell a
    run working through thirty sources from one asking the same question in a loop; a barren streak
    can. It asks for a different ANGLE first and the report second.
  • BUDGET_NOTICE, once, at BUDGET_NOTICE_AT of the step or wall-clock budget. About the REPORT, not
    about stopping: the failure it prevents is a run spending its last steps on one more search.
  • DOCUMENT_CHECK, once, when a run that did real work is about to finish having written NOTHING to
    the case. A finding that lives only in the chat is lost when the panel closes.

The generator NEVER raises: every failure becomes a terminal {"type":"error"} event, like graph_review.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any, AsyncIterator, Callable, Optional

import orjson

from ..config import get_settings
from . import compaction, continuation, runs
from .argrepair import repair_arguments
from .client import (AIError, BadToolArguments, ContextTooLong, LLMClient, ProviderUnavailable,
                     absorb_text_calls, has_tool_call_syntax, parse_text_tool_calls)
from .history import HISTORY
from .system_prompts import PROMPTS
from .prompts import (ARG_TOO_BIG, BUDGET_NOTICE, CHECK_IN, COMPACTED_CONTINUE, CONTINUE_WORK,
                      DOCUMENT_CHECK, NO_CASE_LINE, run_budget, RECORD_NUDGE, REPORT_NOW,
                      SUMMARY_CHECK, WRAP_UP, investigator_user_prompt)
from .tools import (REGISTRY, RunContext, ToolError, tool_budget_seconds, tool_schemas,
                    unverified_citations)

DISABLED_MESSAGE = ("AI assistant is disabled — choose a provider and add an API key in Settings → AI "
                    "assistant. The investigator needs a model that supports tool calling.")

MAX_STEPS_CAP = 120
MAX_SECONDS_CAP = 900
MAX_COMPACTIONS_CAP = 20
TOOL_RESULT_CHARS = 6000     # one tool result handed back to the model
MAX_WRITES = 200
# "no limit" as a number, so the loop's comparisons need no special case. Large enough that no run
# reaches it, small enough to stay an ordinary int in JSON and in the UI.
NO_LIMIT = 1_000_000_000
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
# ---- the check-in, and why it is no longer a metronome.
# It used to fire every 8 tool calls, up to 3 times, on the CALL COUNT alone: "you have made N tool
# calls — can you answer now?". The analyst's report on that: "often this influences the model to stop
# investigating too early when it probably should continue. This gets in the way for a lot of log files
# that might need to be sifted through." Both halves were wrong. A run working through thirty sources
# is not a runaway loop, and 8 calls out of a 40-step budget is barely a start — so the nudge arrived
# while the work was still productive and biased it toward stopping. It also asked a question the model
# cannot answer usefully at that point, which costs a turn every time.
#
# What actually distinguishes a runaway loop from an investigation is not how MANY calls have been made
# but whether they are still returning anything. So the check-in fires on EVIDENCE of spinning: a run
# of consecutive calls that each came back cached (a repeat of one already made), refused, or empty.
# Productive work resets the streak and is never interrupted.
CHECK_IN_MIN_CALLS = 12       # never before this - the opening of a real investigation looks like this too
CHECK_IN_STREAK = 5           # consecutive calls that returned nothing new
CHECK_IN_COOLDOWN = 8         # calls between nudges, so declining one is not re-asked immediately
MAX_CHECK_INS = 2
# The other moment a nudge is worth its turn, and it is about the REPORT, not about stopping early: the
# run is close enough to a hard budget stop that it needs to leave room to write one. Sent at most once.
BUDGET_NOTICE_AT = 0.75       # fraction of the step OR wall-clock budget spent
# Below this many tool calls a run was a question, not an investigation, and asking it to write the
# case up would be noise. At or above it, finishing with an empty case is the failure the analyst
# reported: "didn't interact with the case at all when it should, that include everything in the
# case from the timeline to iocs".
DOCUMENT_MIN_CALLS = 3
# How many turns a run may lose to the PROVIDER refusing the model's own tool-call arguments before
# the run fails. The client already re-sends such a turn once (client.stream_chat); this is the next
# layer — the model is TOLD its call did not run and asked for a smaller one, which is the only thing
# that actually changes the outcome, since the failure is a call too long to finish in one reply.
# Bounded because a model that cannot write a parsable call will not learn to on the tenth attempt —
# but exhausting it is NOT the end of the run: the tool channel is unusable, so the loop stops calling
# tools and takes the wrap-up turn. Ending a 37-call investigation with `state: error` and no report,
# which is what a bare re-raise did, throws away every finding for a sampling accident. The count is
# CONSECUTIVE: any turn the provider parses resets it, so three unrelated accidents spread across a
# long run are not treated as one escalating failure.
MAX_ARG_FAILURES = 3
# How many times the loop may ask for a call the model DESCRIBED and then did not make. An empty turn
# is how the loop recognises "finished", so a turn that trails off into the call it was about to make
# ("Let me write one and update the case:") used to be published as the final report with the work
# undone. Bounded, because a model that narrates twice will narrate a third time; the run then takes
# the wrap-up turn instead of shipping the fragment.
MAX_CONTINUE_NUDGES = 2
# ---- the provider's OWN context window, which Iris cannot see and which is often SMALLER than
# IRIS_AI_MAX_CONTEXT_TOKENS. Reported live as `openai HTTP 400 at .../chat/completions` and a dead
# run: the analyst's llama.cpp gateway (context shift on — which only helps GENERATED tokens) refused
# a prompt larger than n_ctx, Iris's estimate was still under its 60k ceiling, so nothing compacted
# and the run ended with every finding unrecorded. Now the 400 is the compaction trigger: fold, lower
# this run's ceiling to below what just failed, retry the turn. Bounded per turn and per run.
CONTEXT_RETRIES = 4           # attempts to fit ONE turn
CONTEXT_RECOVERIES = 12       # forced folds per run
CONTEXT_SHRINK = 0.75         # the new ceiling, as a fraction of the estimate the provider refused
MIN_CEILING = 3_000           # below this there is no room for a tool result at all
ELIDE_RESULT_CHARS = 600      # a tool result in the kept tail is cut to this when folding was not enough
TOOL_RESULT_CHARS_SMALL = 2500   # new tool results are clipped harder once the window is known to be small
# ---- transient provider failures (5xx, 429, a dropped connection, a timeout): retried with a backoff
# before the run is failed. Nothing of the turn has reached the transcript when they happen.
PROVIDER_RETRIES = 3
PROVIDER_BACKOFF = (2.0, 5.0, 10.0)
# ---- record AS YOU GO. The analyst's report: findings need to be documented "as it is finding, then
# build a full summary at the end". The compaction and provider-failure paths above are why it is not
# tidiness: the transcript is finite and a run can end mid-way, so a finding that lives only in the
# chat is one crash from gone. After RECORD_EVERY productive reads with no write, the loop asks ONCE
# for what is solid so far (never to finish), at most MAX_RECORD_NUDGES times per run.
RECORD_MIN_CALLS = 4
RECORD_EVERY = 6
MAX_RECORD_NUDGES = 3
# What counts as "the summary is written", so the end-of-run SUMMARY_CHECK is skipped: a note of
# kind='summary', or update_case setting the case summary. A FINDING note does not count — those are
# written as findings are found, and the summary is the one that ties them together.
SUMMARY_TOOLS = ("add_note", "update_case")


def _env_int(name: str, default: int, cap: int) -> int:
    try:
        v = int(os.environ.get(name, "") or default)
    except ValueError:
        v = default
    return max(1, min(cap, v))


def limits(max_steps: Optional[int] = None, max_seconds: Optional[int] = None) -> dict[str, int]:
    """The bounds in force for a run.

    `maxSteps` defaults to 40, not the old 14. The step count was standing in for the context ceiling —
    a long investigation ran out of steps while it was still working, and the analyst got "budget
    reached (max_steps)" instead of an answer. Context is now handled by compaction (ai/compaction.py),
    so steps only have to stop a genuine LOOP, and 40 is where a loop is obvious while real work is not
    yet finished. The wall clock is the bound that actually protects the analyst's time.

    All three of those are now SETTINGS (`settings.ai`), not env-only constants: changing them used to
    take a restart and a shell, so a case that genuinely needed forty more steps just hit the wall.
    `settings.ai.enforceLimits = False` removes them entirely — `enforced: False` in the result, and
    the ceilings come back as a sentinel no counter reaches. Two things are deliberately NOT covered by
    that switch, because neither is policy: `maxToolSeconds` (one call may never eat the whole run) and
    the context ceiling / compaction (the provider's window is a fact). Env vars still SEED the
    defaults for a headless install; a value saved in the UI wins.
    """
    ai = None
    try:
        ai = get_settings().ai
    except Exception:  # noqa: BLE001 — a settings read must never stop a run from starting
        ai = None
    steps = _env_int("IRIS_AI_MAX_STEPS", 40, MAX_STEPS_CAP)
    secs = _env_int("IRIS_AI_MAX_SECONDS", 600, MAX_SECONDS_CAP)
    writes = MAX_WRITES
    enforced = True
    if ai is not None:
        enforced = bool(getattr(ai, "enforceLimits", True))
        steps = max(1, int(getattr(ai, "maxSteps", steps) or steps))
        secs = max(5, int(getattr(ai, "maxSeconds", secs) or secs))
        writes = max(1, int(getattr(ai, "maxWrites", writes) or writes))
    ctx = _env_int("IRIS_AI_MAX_CONTEXT_TOKENS", 60_000, 500_000)
    compactions = _env_int("IRIS_AI_MAX_COMPACTIONS", 6, MAX_COMPACTIONS_CAP)
    if max_steps:
        steps = max(1, int(max_steps))
    if max_seconds:
        secs = max(5, int(max_seconds))
    if not enforced:
        # A sentinel rather than a branch at every checkpoint: `step >= NO_LIMIT` is simply never true,
        # so no comparison in the loop has to learn about this and none can be forgotten.
        steps = secs = writes = NO_LIMIT
    return {"maxSteps": steps, "maxSeconds": secs, "maxContextTokens": ctx, "maxWrites": writes,
            "maxCompactions": compactions, "enforced": int(enforced),
            # a FIFTH bound, per CALL rather than per run: without it one tool could eat the whole
            # wall clock with nothing able to interrupt it. See `_watch`.
            "maxToolSeconds": tool_budget_seconds()}


# NO OUTPUT CAP. Iris sends no `max_tokens` on any request — the analyst's instruction, and the right
# one: a cap Iris picks is a cap Iris cannot pick correctly. The hard-coded 1400 here is what cut
# `build_case_graph` off at char 3313 and `add_note` at char 2308 mid-argument, and the provider then
# refused the whole call as invalid JSON ("could not parse the arguments you sent"). The backend model
# knows its own context window and enforces its own ceiling; a second, blind, smaller limit in front of
# it can only truncate replies that were going to finish. See `client._chat_body`. What stays is
# `ai/argrepair.py`, which salvages a reply the PROVIDER truncated, and the CONTEXT bound
# (IRIS_AI_MAX_CONTEXT_TOKENS) — that one is not a limit on the model, it is when Iris folds its own
# transcript into a brief so a long run keeps working.


def _bad_args_message(exc: Exception, finish: str) -> str:
    """The refusal a model gets when even the repair pass could not salvage its arguments.

    It names TRUNCATION when that is what happened, because "send valid JSON" is unactionable advice
    for a reply that was cut off — the model would send the same oversized call again.
    """
    low = str(exc).lower()
    cut = finish == "length" or "unexpected end" in low or "eof" in low or "unterminated" in low
    if cut:
        return ("your arguments were CUT OFF before they finished (" + str(exc) + "). The reply hit "
                "its token limit — this call was too big to write in one turn. Send the SAME call "
                "with fewer items (split a large `links` / `eventIds` / note into several calls) and "
                "keep prose short.")
    return f"could not parse the arguments you sent ({exc}). Send valid JSON."


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


def _fit_context(messages: list[dict[str, Any]], actions: list[dict[str, Any]],
                 ceiling: int) -> tuple[list[dict[str, Any]], int, int, bool]:
    """Make the transcript fit under `ceiling` after the PROVIDER refused it: (messages, folded, elided, fits).

    Folds first (progressively shorter tails, forced), then — if the kept tail is itself too big, which
    on a run with large tool results it can be — elides the biggest tool results in what is left down
    to a stub that tells the model to re-run the call narrower if it still needs it. The system message
    and the objective are never touched; if those two alone do not fit, nothing here can help and the
    caller says so.
    """
    target = ceiling * COMPACT_FLOOR
    before = _est_tokens(messages)
    folded = 0
    for tail in (compaction.TAIL_MESSAGES, 4, 2):
        if _est_tokens(messages) < target:
            break
        attempt = compaction.compact(messages, actions, keep_tail=tail, force=True)
        if attempt is None:
            continue
        messages, d = attempt
        folded += d
    elided = 0
    if _est_tokens(messages) >= target:
        for m in messages[2:]:
            if m.get("role") != "tool":
                continue
            body = str(m.get("content") or "")
            if len(body) <= ELIDE_RESULT_CHARS:
                continue
            m["content"] = (body[:ELIDE_RESULT_CHARS] + "\n… [result elided to fit the model's context "
                            "window — call again with a narrower query if you still need it]")
            elided += 1
            if _est_tokens(messages) < target:
                break
    after = _est_tokens(messages)
    # A fold that did not make the transcript SMALLER (a brief can outweigh a handful of tiny results)
    # is reported as no progress, so the caller stops retrying instead of re-sending the same size.
    if after >= before:
        folded, elided = 0, 0
    return messages, folded, elided, after < ceiling


def _tell_compacted(messages: list[dict[str, Any]]) -> bool:
    """Tell the MODEL, in the transcript, that the middle of the conversation was folded.

    Only the panel was told. The model was handed a re-shaped conversation and had to work out from the
    brief alone what had happened to it — and on the run this was written for, the very next turn was
    "No summary note exists yet. Let me write one and update the case:" with no call attached, which the
    loop read as completion.

    Idempotent: a single turn can fold several times (`_fit_context` tries progressively shorter tails),
    and repeating the note once per fold would itself be transcript to carry.
    """
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        if str(m.get("content") or "").startswith(COMPACTED_CONTINUE[:40]):
            return False
        break
    messages.append({"role": "user", "content": COMPACTED_CONTINUE})
    return True


# An action the model announced in the first person. Deliberately a small, closed list of openings: the
# cost of a MISS is the original bug (a dangling sentence published as the report), and the cost of a
# false positive is one wasted turn, but a detector that fires on ordinary report prose would waste one
# on every run.
_PROMISE_RE = re.compile(
    r"\b(let me\b|let's\b|i'?ll\b|i will\b|i'?m going to\b|i am going to\b|"
    r"going to (?:add|write|record|create|update|call|check|search|query|build|annotate)\b|"
    r"now i(?:'?ll| will)?\b|next,? i\b)",
    re.I)


def _promises_action(text: str) -> bool:
    """Did this turn narrate the call it was about to make, instead of making it?

    Both conditions have to hold, because the phrase alone appears in perfectly good reports ("I will
    note that the account was disabled"):
      • an action phrase in the LAST 400 characters — where a trailing announcement lives;
      • and either the text ends on a colon (a real report does not trail off into one) or it is under
        300 characters (too short to be the report a run owes the analyst).
    """
    body = (text or "").strip()
    if not body:
        return False
    tail = body[-400:]
    if not _PROMISE_RE.search(tail):
        return False
    return body.endswith(":") or len(body) < 300


def _has_summary(actions: list[dict[str, Any]]) -> bool:
    for a in actions:
        if a.get("undone") or str(a.get("tool") or "") not in SUMMARY_TOOLS:
            continue
        s = str(a.get("summary") or "").lower()
        if a.get("tool") == "update_case" and "summary" in s:
            return True
        if a.get("tool") == "add_note" and ("summary note" in s or not s.startswith("wrote a finding note")):
            # a pre-`kind` action ("wrote a case note") is taken as a summary — never nag a run twice
            return True
    return False


def build_context(store: Any) -> str:
    """A short orientation block. Deliberately small: the agent's job is to go and look, and a huge
    prompt preamble both costs budget and invites the model to answer from the preamble instead."""
    lines: list[str] = []
    try:
        c = store.case()
        if c.pending:
            lines.append("No case exists yet (the workspace is case-less; analysis still works). If this "
                         "objective is an investigation, create_case FIRST and record findings into it.")
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
    "list_exclusions": lambda d: (f"{d.get('total', 0)} exclusion(s), suppressing "
                                  f"{_n(d.get('suppressedTotal', 0))} detection(s)"),
    "list_graph_findings": lambda d: (f"{_len(d, 'findings')} of {d.get('total', 0)} entity-graph finding(s) "
                                      f"over the {d.get('scope', 'all')} scope"),
    "preview_detection_rule": lambda d: (f"would flag {_n(d.get('hits', 0))} event(s)"
                                         + (f" ({d.get('sharePercent')}% of the pool)" if d.get('sharePercent') is not None else "")
                                         + " — nothing saved"),
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


def _returned_something(ok: bool, result: Any) -> bool:
    """Did this call move the investigation, or is the run spinning?

    The check-in used to fire on the CALL COUNT, which cannot tell a run working through thirty log
    files from one asking the same question in a loop — so it interrupted the first. This is the
    distinction that matters, and it is deliberately narrow: only a REPEAT (served from the run's own
    dedupe cache), a REFUSAL, or an explicitly empty result counts as nothing new.

    A zero-hit search is real evidence once — ruling something out is work — which is why one of these
    changes nothing on its own; it takes CHECK_IN_STREAK of them in a row to earn a nudge.
    """
    if not ok:
        return False
    if not isinstance(result, dict):
        return True
    if result.get("cached"):
        return False       # the model asked something it had already asked
    for key in ("hits", "count", "total", "matched", "events"):
        v = result.get(key)
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            return v > 0
    for key in ("results", "rows", "values", "samples", "nodes", "entities", "findings",
                "detections", "anomalies", "sources", "fields", "entries", "paths", "clusters"):
        v = result.get(key)
        if isinstance(v, list):
            return len(v) > 0
    return True


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


def _case_line(store: Any) -> str:
    """The extra sentence a write-up nudge carries when there is no case: create one, then record.

    The nudges used to be SKIPPED in a case-less workspace ("every case-scoped write refuses while
    pending, so asking would only waste a turn"). The analyst's rule is the opposite: *"no case — the
    workspace is case-less — it should then create the case."* The model can create one itself
    (`create_case` is a tool), so a missing case is an instruction, not an exemption.
    """
    return "" if _case_open(store) else NO_CASE_LINE


async def investigate(store: Any, objective: str, run_id: str,
                      max_steps: Optional[int] = None, max_seconds: Optional[int] = None,
                      client: Optional[LLMClient] = None, focus: str = "",
                      continue_from: str = "", system_prompt_id: Optional[str] = None) -> AsyncIterator[dict[str, Any]]:
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
    # The system prompt: the built-in one, plus the analyst's saved instructions (ai/system_prompts.py) —
    # `system_prompt_id` None = the settings default, '' = built-in, an id = that prompt. A missing id
    # is REPORTED and the built-in prompt runs; it is never swapped for some other saved prompt.
    system_text, sp = PROMPTS.resolve(system_prompt_id)
    if sp["missing"]:
        msg = (f"saved system prompt {sp['missing']!r} no longer exists — running on the built-in prompt. "
               f"Pick another under Settings → System prompts.")
        HISTORY.append(run_id, {"kind": "warning", "text": msg})
        yield {"type": "warning", "message": msg, "ids": []}
    if sp["id"] or sp["builtinEdited"]:
        parts = []
        if sp["builtinEdited"]:
            parts.append("built-in prompt: edited (Settings → System prompts)")
        if sp["id"]:
            parts.append(f"additional instructions: {sp['name']}")
        note = " · ".join(parts)
        HISTORY.append(run_id, {"kind": "status", "text": note})
        yield {"type": "status", "text": note,
               "systemPrompt": {"id": sp["id"], "name": sp["name"], "builtinEdited": sp["builtinEdited"]}}
    # the focus note is context for the MODEL only — the transcript stores the analyst's words verbatim
    asked = objective + (f"\n\n(The analyst opened this from: {focus})" if focus else "")
    messages: list[dict[str, Any]] = [
        # The budget block goes on the SYSTEM message, after whatever prompt is in force (shipped,
        # analyst-edited, or with saved instructions appended): a run has to know what it is actually
        # working under, and with the limits off that block is the only thing that says so.
        {"role": "system", "content": system_text + run_budget(lim)},
        {"role": "user", "content": investigator_user_prompt(asked, build_context(store), prior_brief)},
    ]
    started = time.monotonic()
    step = 0
    tool_calls = 0
    compactions = 0
    check_ins = 0            # scope nudges sent (see CHECK_IN_MIN_CALLS)
    arg_failures = 0         # CONSECUTIVE turns the provider refused for unparsable tool arguments
    provider_args_exhausted = False   # the tool channel is unusable — go to the wrap-up, not to an error
    continue_nudges = 0      # times the model was asked for a call it described but never made
    barren = 0               # consecutive tool calls that returned nothing new (cached / refused / empty)
    next_check_in = CHECK_IN_MIN_CALLS
    budget_noticed = False   # the "leave room for the report" nudge has been sent once
    documented = False       # the "you wrote nothing to the case" prompt has been sent once
    summarised = False       # the "write the summary note" prompt has been sent once
    record_nudges = 0        # "record as you go" nudges sent
    productive_since_write = 0   # reads that returned evidence since the last write (or the start)
    ceiling = lim["maxContextTokens"]   # lowered when the provider refuses the transcript (ContextTooLong)
    result_chars = TOOL_RESULT_CHARS
    context_recoveries = 0
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
                   + (f"(ceiling: {lim['maxSteps']} steps / {lim['maxSeconds']}s, {len(tools)} tools "
                      f"available)" if lim.get("enforced", 1) else
                      f"(no step or time limit — Stop is the only thing that ends it early; "
                      f"{len(tools)} tools available)"))
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
            if _est_tokens(messages) >= ceiling:
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
                        if _est_tokens(attempt[0]) < ceiling * COMPACT_FLOOR:
                            break
                if folded is None:
                    reason = "budget"
                    break
                candidate, dropped = folded
                if _est_tokens(candidate) >= ceiling * COMPACT_FLOOR:
                    note = ("context is full and summarising the earlier steps did not free enough room — "
                            "stopping and reporting what is established")
                    HISTORY.append(run_id, {"kind": "warning", "text": note})
                    yield {"type": "warning", "message": note, "ids": []}
                    reason = "budget"
                    break
                messages = candidate
                compactions += 1
                _tell_compacted(messages)
                # A fold can swallow the very message carrying DOCUMENT_CHECK / SUMMARY_CHECK — that is
                # how a run ended having been asked for its summary note and never seeing the request.
                # Re-armed only while the work is still outstanding, so neither can be asked twice.
                if documented and ctx.writes == 0:
                    documented = False
                if summarised and not _has_summary(ctx.actions):
                    summarised = False
                note = (f"compacted {dropped} earlier steps into a running brief "
                        f"(compaction {compactions} of {lim['maxCompactions']}) — the objective, the "
                        f"verified event ids and everything already written to the case were kept")
                HISTORY.append(run_id, {"kind": "status", "text": note})
                yield {"type": "status", "text": note, "compactions": compactions, "droppedMessages": dropped}

            # SCOPE CHECK-IN. Injected as a user turn between steps, and ONLY when the last
            # CHECK_IN_STREAK calls each returned nothing new — a repeat, a refusal or an empty
            # result. That is the signature of a drill-down that has stopped changing the answer;
            # a run still finding things is never interrupted, however many calls it has made.
            # Never a forced stop: the model may decline and carry on, and the copy says so.
            if (barren >= CHECK_IN_STREAK and tool_calls >= next_check_in
                    and check_ins < MAX_CHECK_INS):
                check_ins += 1
                next_check_in = tool_calls + CHECK_IN_COOLDOWN
                barren = 0
                messages.append({"role": "user", "content": CHECK_IN.format(streak=CHECK_IN_STREAK)})
                note = (f"the last {CHECK_IN_STREAK} tool calls returned nothing new — asked the "
                        f"assistant for a different angle, or the report")
                HISTORY.append(run_id, {"kind": "status", "text": note})
                yield {"type": "status", "text": note, "checkIn": check_ins}
            # BUDGET NOTICE. Not "can you stop yet?" but "leave room to write it up": past this point
            # a hard stop is close, and the failure mode is a run that spends its last steps on one
            # more search and hands the analyst nothing. Once per run.
            # ...and never when there is no budget to be three-quarters of: the notice names a
            # number of steps remaining, which would be nonsense, and its whole purpose is to leave
            # room before a stop that is not coming.
            elif (lim.get("enforced", 1) and not budget_noticed
                  and (step >= lim["maxSteps"] * BUDGET_NOTICE_AT
                       or elapsed() >= lim["maxSeconds"] * BUDGET_NOTICE_AT)):
                budget_noticed = True
                left = max(0, lim["maxSteps"] - step)
                messages.append({"role": "user", "content": BUDGET_NOTICE.format(
                    steps=left, seconds=max(0, int(lim["maxSeconds"] - elapsed())))})
                note = (f"{left} steps left — reminded the assistant to leave room to write the "
                        f"report and record what it found")
                HISTORY.append(run_id, {"kind": "status", "text": note, })
                yield {"type": "status", "text": note, "budgetNotice": True}
            # RECORD AS YOU GO. Evidence has been coming back and none of it has been written down.
            # Asked between steps, never as a request to finish: the copy says to record what is solid
            # and carry on. Only with a case to write into, and at most MAX_RECORD_NUDGES times.
            elif (record_nudges < MAX_RECORD_NUDGES and productive_since_write >= RECORD_EVERY
                  and tool_calls >= RECORD_MIN_CALLS):
                record_nudges += 1
                calls_since = productive_since_write
                productive_since_write = 0
                messages.append({"role": "user", "content": RECORD_NUDGE.format(calls=calls_since,
                                                                                 case=_case_line(store))})
                note = (f"{calls_since} tool calls returned evidence and none of it is recorded in the "
                        f"case yet — asked the assistant to write down what is solid before continuing")
                HISTORY.append(run_id, {"kind": "status", "text": note})
                yield {"type": "status", "text": note, "recordNudge": record_nudges}
            step += 1
            HISTORY.append(run_id, {"kind": "step", "step": step})
            yield {"type": "step", "step": step, "elapsedSec": round(elapsed(), 1)}
            buf: list[str] = []
            final_msg: dict[str, Any] = {}
            finish = ""
            retry_turn = False       # BadToolArguments: the model is told and the step is re-taken
            ctx_tries = 0            # ContextTooLong recoveries on THIS turn
            prov_tries = 0           # transient provider failures on THIS turn
            while True:
                buf, final_msg, finish = [], {}, ""
                try:
                    async for item in client.stream_chat(messages, tools=tools, temperature=0.1):
                        # Checked INSIDE the token loop, not only between steps: a plain question
                        # streams prose and never calls a tool, so a stop that was only checked at the
                        # two old checkpoints could not interrupt it at all — which is what "there is
                        # no way to stop it" meant.
                        if runs.stop_requested(run_id):
                            break
                        if item["type"] == "text":
                            buf.append(item["text"])
                            HISTORY.append_text(run_id, item["text"])
                            yield {"type": "delta", "text": item["text"], "step": step}
                        elif item["type"] == "message":
                            final_msg = item["message"]
                            finish = str(item.get("finish") or "")
                    break
                except BadToolArguments as exc:
                    # The provider rejected what the MODEL wrote, so this turn does not exist: no prose
                    # was streamed, no call was made, and the transcript is unchanged. Ending a 27-call
                    # investigation here — which is what used to happen — throws away every finding
                    # for a sampling accident. Tell the model instead, and let it send a smaller call.
                    arg_failures += 1
                    if arg_failures > MAX_ARG_FAILURES:
                        # The tool channel is unusable, but the investigation is not: 37 calls and 16
                        # writes were on the case when this used to `raise`. Stop calling tools and take
                        # the wrap-up turn, which is exactly what a budget stop does.
                        provider_args_exhausted = True
                        note = (f"the provider could not parse the tool-call arguments the model wrote "
                                f"{MAX_ARG_FAILURES} turns running; no further tool calls will be made. "
                                f"Writing the report from what the run already established. Provider "
                                f"said: {str(exc)[:200]}")
                        HISTORY.append(run_id, {"kind": "warning", "text": note})
                        yield {"type": "warning", "message": note, "ids": []}
                        break
                    note = (f"the provider could not parse the tool-call arguments the model wrote "
                            f"(attempt {arg_failures} of {MAX_ARG_FAILURES}); nothing ran. Asked it to "
                            f"send a smaller call. Provider said: {str(exc)[:200]}")
                    HISTORY.append(run_id, {"kind": "warning", "text": note})
                    yield {"type": "warning", "message": note, "ids": []}
                    messages.append({"role": "user", "content": ARG_TOO_BIG})
                    retry_turn = True
                    break
                except ContextTooLong as exc:
                    # THE PROVIDER'S WINDOW IS THE REAL CEILING. Iris's estimate said there was room;
                    # the model's server said there was not, and it is right. Fold the transcript,
                    # drop this run's ceiling to below what was just refused so the between-step
                    # compaction fires earlier from now on, and re-send the SAME turn — nothing of it
                    # reached the transcript. This used to be the end of the run, reported as
                    # "openai HTTP 400 ... the assistant stops working after that".
                    ctx_tries += 1
                    context_recoveries += 1
                    est = _est_tokens(messages)
                    ceiling = max(MIN_CEILING, min(ceiling, int(est * CONTEXT_SHRINK)))
                    result_chars = min(result_chars, TOOL_RESULT_CHARS_SMALL)
                    messages, folded, elided, fits = _fit_context(messages, ctx.actions, ceiling)
                    if folded:
                        compactions += 1
                    if ctx_tries > CONTEXT_RETRIES or context_recoveries > CONTEXT_RECOVERIES or (
                            not folded and not elided):
                        raise AIError(
                            f"{exc}. Folding the transcript could not make it fit"
                            f"{'' if folded or elided else ' (nothing left to fold: the system prompt, the tool definitions and the objective alone are over the limit)'}"
                            f" — give the model a larger context window (n_ctx / max context) or continue "
                            f"in a new conversation. Everything written to the case so far is kept.") from exc
                    _tell_compacted(messages)
                    if documented and ctx.writes == 0:
                        documented = False
                    if summarised and not _has_summary(ctx.actions):
                        summarised = False
                    note = (f"the provider refused the request because the conversation no longer fits the "
                            f"model's context window (estimated ~{est:,} tokens). Folded {folded} earlier "
                            f"message(s) into a running brief"
                            + (f" and elided {elided} large tool result(s)" if elided else "")
                            + f"; this run now compacts at ~{ceiling:,} tokens. Retrying the same turn — "
                            f"the objective, the verified event ids and everything already written to the "
                            f"case were kept"
                            + (", and the assistant continues from where it was" if fits
                               else ". It may still not fit"))
                    # A RECOVERED fold is the mechanism working, not a failure — and it was the last
                    # line on screen when a run ended for an unrelated reason, which is what made the
                    # fold look like the cause. A fold that may still not fit stays a warning: that one
                    # genuinely may end the run.
                    kind = "warning" if not fits else "status"
                    HISTORY.append(run_id, {"kind": kind, "text": note})
                    yield {"type": kind, "message": note, "text": note, "ids": [],
                           "contextCeiling": ceiling, "compactions": compactions}
                    continue
                except ProviderUnavailable as exc:
                    prov_tries += 1
                    if prov_tries > PROVIDER_RETRIES:
                        raise AIError(f"{exc} — gave up after {PROVIDER_RETRIES} retries. Everything "
                                      f"written to the case so far is kept; send a follow-up in this "
                                      f"conversation to continue from here once the provider is back.") from exc
                    delay = PROVIDER_BACKOFF[min(prov_tries - 1, len(PROVIDER_BACKOFF) - 1)]
                    note = (f"the AI provider failed ({str(exc)[:200]}); retrying in {delay:.0f}s "
                            f"(attempt {prov_tries} of {PROVIDER_RETRIES}) — the run continues from where "
                            f"it was, nothing is lost")
                    HISTORY.append(run_id, {"kind": "warning", "text": note})
                    yield {"type": "warning", "message": note, "ids": [], "retry": prov_tries}
                    waited = 0.0
                    while waited < delay and not runs.stop_requested(run_id):
                        await asyncio.sleep(0.25)
                        waited += 0.25
                    if runs.stop_requested(run_id):
                        break
                    continue
            if provider_args_exhausted:
                reason = "tool_arguments"
                break
            if retry_turn:
                continue
            # CONSECUTIVE, not cumulative: the provider parsed this turn, so whatever went wrong before
            # was a sampling accident and not an escalating failure.
            arg_failures = 0
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
            # NARRATION THAT NEVER STREAMED. The transcript's prose comes only from `text` deltas, and a
            # provider is perfectly entitled to return the turn's content in the assembled message and
            # stream no deltas at all — the wrap-up turn below already guards exactly that case, with
            # the note explaining why. The main loop did not, so on such a provider every line the model
            # wrote ALONGSIDE its tool calls was dropped on the floor and the run read as a column of
            # silent calls. Back-filled only when the deltas carried nothing, so a streaming provider is
            # untouched, and before the tool entries of this turn are appended, so it keeps its place in
            # front of the calls it is about.
            if calls and not buf:
                said = str(final_msg.get("content") or "").strip()
                if said:
                    HISTORY.append_text(run_id, said)
                    yield {"type": "delta", "text": said, "step": step}
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
                        and not runs.stop_requested(run_id)
                        and elapsed() < lim["maxSeconds"] and step < lim["maxSteps"]
                        # ...and only if there is room to pay for the turn. A run at its context
                        # ceiling that is handed one more user message compacts or stops on the
                        # budget, and the report it had ALREADY WRITTEN is replaced by whatever
                        # the wrap-up manages. Losing the answer to ask for a write-up is a much
                        # worse trade than finishing with an unwritten case.
                        and _est_tokens(messages) < ceiling):
                    documented = True
                    messages.append({"role": "user", "content": DOCUMENT_CHECK.format(case=_case_line(store))})
                    note = ("nothing recorded in the case yet — asking the assistant to write up what it found"
                            + ("" if _case_open(store) else " (and to create the case first)"))
                    HISTORY.append(run_id, {"kind": "status", "text": note})
                    yield {"type": "status", "text": note, "documentCheck": True}
                    continue
                # THE FULL SUMMARY AT THE END. A run that recorded as it went has events, a timeline
                # and indicators on the case — and no narrative tying them together. Once, ask for the
                # summary note (and the case summary) before the report. Skipped when a note already
                # exists, because that is what "an equivalent summary" looks like on the case.
                if (not summarised and ctx.writes > 0 and tool_calls >= DOCUMENT_MIN_CALLS
                        and not _has_summary(ctx.actions)
                        and not runs.stop_requested(run_id)
                        and elapsed() < lim["maxSeconds"] and step < lim["maxSteps"]
                        and _est_tokens(messages) < ceiling):
                    summarised = True
                    messages.append({"role": "user", "content": SUMMARY_CHECK})
                    note = "findings were recorded as the run went — asking the assistant for the case summary"
                    HISTORY.append(run_id, {"kind": "status", "text": note})
                    yield {"type": "status", "text": note, "summaryCheck": True}
                    continue
                # AN EMPTY TURN IS HOW THE LOOP KNOWS THE MODEL IS FINISHED — and a model handed a
                # freshly folded transcript answered "No summary note exists yet. Let me write one and
                # update the case:" with no call attached. That half-sentence became the final report
                # and the summary note was never written. Ask for the call; past the bound, take the
                # wrap-up turn so the analyst gets a real report rather than the fragment.
                if _promises_action(answer) and not runs.stop_requested(run_id):
                    if continue_nudges < MAX_CONTINUE_NUDGES:
                        continue_nudges += 1
                        messages.append({"role": "user", "content": CONTINUE_WORK})
                        note = ("the assistant described a tool call and did not make it — asked it to "
                                f"make the call or say the work is finished (nudge {continue_nudges} of "
                                f"{MAX_CONTINUE_NUDGES})")
                        HISTORY.append(run_id, {"kind": "status", "text": note})
                        yield {"type": "status", "text": note, "continueNudge": continue_nudges}
                        continue
                    reason = "unfinished"
                    break
                reason = "complete"
                break

            for call in calls:
                if runs.stop_requested(run_id):
                    break
                fn = call.get("function") or {}
                name = str(fn.get("name") or "")
                raw_args = fn.get("arguments") or "{}"
                # A local model writing a long call is the common failure here, and it fails in one
                # of two ways: the reply is cut off mid-string at the token limit, or a quote/newline
                # inside a long string was never escaped. Both used to refuse the whole call, which
                # cost the run a turn and the analyst the write. Try strict JSON, then the mechanical
                # repair in ai/argrepair.py — and if the repair DROPPED anything, say so loudly:
                # a write that quietly lands nine of ten links is the silent-omission bug.
                writes = bool(getattr(REGISTRY.get(name), "writes", False))
                repairs: list[str] = []
                parse_err = ""
                blocked_write = False
                try:
                    args = orjson.loads(raw_args) if raw_args.strip() else {}
                    if not isinstance(args, dict):
                        raise ValueError("arguments were not a JSON object")
                except (orjson.JSONDecodeError, ValueError) as exc:
                    fixed, repairs = repair_arguments(raw_args)
                    if fixed is None:
                        args, repairs = {}, []
                        parse_err = _bad_args_message(exc, finish)
                    else:
                        args = fixed
                # A SALVAGED WRITE IS NOT A WRITE. `argrepair` closes a cut-off blob by dropping the
                # incomplete trailing element, which is a reasonable trade for a read — the model can
                # see what came back and ask again. For a write it is the silent-omission bug: an
                # add_note whose `text` survived and whose trailing `citedEventIds` did not would land
                # on the analyst's case as a finding with no evidence behind it. On the run this was
                # written for, the salvage happened to come out `{}` and the schema check refused it —
                # that was luck. Refuse it here instead, before the handler exists to be called.
                if writes and any("CUT OFF" in r for r in repairs):
                    blocked_write = True
                    args, repairs = {}, []
                    parse_err = ("your arguments were CUT OFF before they finished, and this tool WRITES "
                                 "to the case — the call was refused whole rather than run with the "
                                 "missing part guessed at. NOTHING was changed. Send it again smaller: "
                                 "split a long `links` / `eventIds` / note into several calls and keep "
                                 "prose short.")
                tool_calls += 1
                call_id = str(call.get("id") or f"{run_id}-c{tool_calls}")
                # Stamped INTO the assistant message too (it is the same dict — `final_msg` is already
                # on the transcript), so the tool result below answers an id the provider can match. A
                # tool message whose `tool_call_id` names no call in the preceding assistant turn is
                # rejected outright by an OpenAI-shaped API.
                call["id"] = call_id
                HISTORY.append(run_id, {"kind": "tool", "id": call_id, "name": name, "args": args,
                                        "writes": writes})
                # `call_id`, NOT `call.get("id")`: a provider that omits the id (or repeats one) made
                # every live tool_call carry `id: null`, so the panel matched the RESULT against the
                # first null-id card and the rest span forever. The persisted transcript already used
                # the stamped id; the stream now uses the same one, so live and reloaded agree.
                yield {"type": "tool_call", "id": call_id, "name": name, "arguments": args, "step": step}
                if blocked_write:
                    note = (f"the model's arguments for {name} were CUT OFF mid-value (the reply hit its "
                            f"token limit). {name} writes to the case, so the call was refused whole "
                            f"rather than repaired — the write was blocked and nothing was changed. The "
                            f"assistant was asked to send a smaller call.")
                    HISTORY.append(run_id, {"kind": "warning", "text": note})
                    yield {"type": "warning", "message": note, "ids": []}
                elif repairs:
                    note = (f"the model's arguments for {name} were not valid JSON and were repaired "
                            f"before the call: {'; '.join(repairs)}. Check what this "
                            f"{'wrote to the case' if writes else 'returned'}.")
                    HISTORY.append(run_id, {"kind": "warning", "text": note})
                    yield {"type": "warning", "message": note, "ids": []}
                t0 = time.perf_counter()
                if parse_err:
                    ok, result = False, parse_err
                else:
                    ok, result = await _run_tool(name, args, ctx)
                took = int((time.perf_counter() - t0) * 1000)
                payload = result if ok else {"error": result}
                if repairs and isinstance(payload, dict):
                    # the model has to know what it actually sent, or it cannot re-send what was lost
                    payload = {**payload, "argumentsRepaired": repairs}
                body = _clip(orjson.dumps(payload).decode(), result_chars)
                # `call_id`, not `call.get("id")`: the live stream and the persisted transcript both
                # use the stamped id, and a provider that omits or repeats ids otherwise desynchronises
                # the message sent BACK to it from the two the analyst is looking at.
                messages.append({"role": "tool", "tool_call_id": call_id, "name": name, "content": body})
                productive = _returned_something(ok, result)
                barren = 0 if productive else barren + 1
                if writes and ok:
                    productive_since_write = 0
                elif productive and not writes:
                    productive_since_write += 1
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
        # `tool_arguments` and `unfinished` are not budget stops: the run is being taken off the tool
        # channel because that channel is unusable, or because the model kept describing calls without
        # making them. Both still owe the analyst the report the work earned — which is the whole reason
        # this turn exists — so they route here too, with a prompt that does not claim a spent budget.
        if reason in ("max_steps", "timeout", "budget", "tool_arguments", "unfinished") and not runs.stop_requested(run_id):
            budget_stop = reason in ("max_steps", "timeout", "budget")
            note = (f"budget reached ({reason}) — writing the final report" if budget_stop else
                    ("the provider could not parse the assistant's tool calls — writing the final report "
                     "from what it established" if reason == "tool_arguments" else
                     "the assistant kept describing calls without making them — asking it for the final "
                     "report"))
            HISTORY.append(run_id, {"kind": "status", "text": note})
            yield {"type": "status", "text": note}
            messages.append({"role": "user", "content": WRAP_UP if budget_stop else REPORT_NOW})
            buf = []
            wrap_msg: dict[str, Any] = {}
            async for item in client.stream_chat(messages, tools=None, temperature=0.1,
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
            # The wrap-up turn is reached for reasons other than a spent budget now (`tool_arguments`,
            # `unfinished`), and telling the analyst a budget ran out when it did not is a false claim
            # about their run.
            note = (f"the model tried to call {names} "
                    + ("after its budget ran out" if reason in ("max_steps", "timeout", "budget")
                       else "in its final report")
                    + "; the call was NOT executed and its markup was removed from the report")
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
               "compactions": compactions, "cachedToolCalls": ctx.cache_hits, "textToolCalls": text_mode,
               "contextCeiling": ceiling, "recordNudges": record_nudges}
    except AIError as exc:
        error = _kept_note(str(exc), tool_calls, ctx.writes)
        runs.finish(run_id, "error", "error", step, tool_calls, answer, ctx.actions, [], error)
        yield {"type": "error", "message": error, "actions": ctx.actions}
    except asyncio.CancelledError:
        runs.finish(run_id, "stopped", "disconnected", step, tool_calls, answer, ctx.actions, [])
        raise
    except Exception as exc:  # noqa: BLE001 — never raise out of the stream
        error = _kept_note(f"investigation failed: {type(exc).__name__}: {exc}", tool_calls, ctx.writes)
        runs.finish(run_id, "error", "error", step, tool_calls, answer, ctx.actions, [], error)
        yield {"type": "error", "message": error, "actions": ctx.actions}


def _kept_note(error: str, tool_calls: int, writes: int) -> str:
    """A failed run is not a lost one: say what survives and how to go on.

    The follow-up is seeded with this run's transcript (ai/continuation.py carries an unfinished turn's
    calls AND its working notes), so "continue" resumes rather than restarting — which is what the
    analyst saw happen before.
    """
    if tool_calls == 0 and writes == 0:
        return error
    if "kept" in error and "follow-up" in error:
        return error
    return (f"{error} — the {tool_calls} tool call(s) already made and the {writes} change(s) written to "
            f"the case are kept; send a follow-up message in this conversation and the assistant "
            f"continues from where it stopped instead of starting over.")
