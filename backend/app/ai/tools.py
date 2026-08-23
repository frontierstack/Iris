"""The tools the investigative agent can call — the app's OWN operations, not a second implementation.

Every handler delegates to the existing router/service layer (search via routers.events → search.py,
the graph via store.graph_v2, the case set via Store.add_many_to_case, indicators via routers.iocs,
notes via cases.add_note). Nothing here re-derives evidence; if it did, the agent and the analyst
would be looking at two different cases.

Three rules the whole design rests on:

1. **Reads are free, writes are narrow.** Only additive curation is exposed — put an event in the case
   set, record an indicator, write a note, draw a graph link, name the case. There is deliberately NO
   tool that deletes a case, deletes a source, clears data, edits detection rules or resets anything:
   an agent that can destroy evidence is not an evidence tool.
2. **Every write is attributed.** `addedBy='ai'` / `author='AI assistant …'` / `ai=True` plus the run id
   go onto the artefact itself, so an analyst reading case.json six months later can tell which
   indicators a model proposed. Provenance is not a UI nicety, it is the audit trail.
3. **Every write is grounded.** A write tool that accepts `citedEventIds` REJECTS the call when any of
   those ids is not a real event in the workspace. A fabricated event id in an incident report is a
   serious harm, so the check is a hard refusal (the model is told which ids were bad and can retry),
   never a silent drop.

Handlers are synchronous and are executed off the event loop (asyncio.to_thread) by investigator.py —
a search over a million events would otherwise stall every other request on the process.
"""
from __future__ import annotations

import inspect
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from . import eventids

UTC = timezone.utc

MAX_ROWS = 50            # rows any single read tool may return
MAX_TEXT = 400           # per-field text clamp inside a tool result
MAX_GRAPH_LINKS = 40    # links one build_case_graph call may draw
MAX_CITED = 50           # cited event ids accepted on one write
MAX_GROUPS = 200         # buckets any single aggregation may return

# ---------------------------------------------------------------- time bounds on ONE tool call
#
# A tool call used to be unbounded. On the analyst's 11.4 M-event pool a single `entity_profile` at
# step 1 went through the BLOCKING `Store.graph_v2()` and never came back: the run showed
# `state: running, steps: 0` for minutes, the stop was accepted in 100 ms and had no effect, and the
# graph build's contention on `STORE.lock` stalled enrichment and `/api/library` at the same time.
# Nothing could interrupt it because all three stop checkpoints fire BETWEEN operations.
#
# The answer is NOT to kill the thread — a half-built derived structure or a partially swapped source
# is worse than a slow stop. It is (a) a deadline every handler can see, (b) a stop flag every handler
# can see, and (c) refusing with a ToolError that names the narrower call, which the model can act on.
TOOL_SECONDS_DEFAULT = 90     # wall clock one tool call may take before it must refuse
TOOL_SECONDS_CAP = 600
DERIVED_WAIT_DEFAULT = 60     # of that, how long a tool may WAIT for a derived structure to build
DERIVED_POLL = 0.25           # how often a wait re-checks the value AND the stop flag


def _env_seconds(name: str, default: int, cap: int) -> int:
    try:
        v = int(os.environ.get(name, "") or default)
    except ValueError:
        return default
    return max(1, min(cap, v))


def tool_budget_seconds() -> int:
    """Wall clock a single tool call gets. `IRIS_AI_TOOL_SECONDS`, capped."""
    return _env_seconds("IRIS_AI_TOOL_SECONDS", TOOL_SECONDS_DEFAULT, TOOL_SECONDS_CAP)


def derived_wait_seconds() -> int:
    """How long a graph/analysis/anomaly tool may wait for a background build before refusing.

    Deliberately shorter than the tool budget, so the COOPERATIVE refusal (which names what is still
    building, how far along it is and what to call instead) wins the race against the investigator's
    hard deadline, which can only say "this took too long"."""
    return _env_seconds("IRIS_AI_DERIVED_WAIT", DERIVED_WAIT_DEFAULT, TOOL_SECONDS_CAP)


# The grammar the agent is expected to write. Repeated in the tool descriptions AND in the system
# prompt: a model that guesses the syntax burns steps discovering it, and a malformed query that the
# lenient parser turns into zero matches reads exactly like real absence of evidence.
DSL_HELP = (
    "Query syntax: `field:value` terms and bare free text, combined with AND / OR / NOT (a leading `-` "
    "also negates), grouped with ( ), phrases in \"double quotes\". Escape a literal colon with a "
    "backslash: `10.0.0.9\\:3001`. Fields: source, file, host, user, sev, msg, raw, id, entity, plus any "
    "parsed field name (call list_event_fields to discover them). "
    "`entity:\"<value>\"` is the one field that matches EXACTLY — it is the right way to pull every event "
    "involving an IP, user, host, process, file or hash, because free text also matches 10.0.0.100 when "
    "you meant 10.0.0.1 and every line that merely mentions the string. Example: "
    "`user:svc_deploy AND src_ip:10.0.0.100 AND NOT host:bastion-1`.")


class ToolError(Exception):
    """A tool refused the call. The message goes back to the model as the tool result."""


@dataclass
class RunContext:
    """State shared by every tool call of one investigation."""
    run_id: str
    model: str = ""
    writes: int = 0
    max_writes: int = 200
    actions: list[dict[str, Any]] = field(default_factory=list)
    # Results of READ tools already answered in this run, keyed by tool + canonical arguments. An agent
    # that re-issues a query it has already run pays for it twice: once in wall clock, once in context —
    # and repeated identical tool results are the emptiest thing compaction has to summarise. Any write
    # invalidates the whole cache, because a write can change what a read returns.
    cache: dict[str, Any] = field(default_factory=dict)
    cache_hits: int = 0
    # The two things a long-running handler needs in order to be interruptible at all. Both are
    # optional: a tool called directly (tests, MCP) gets the default budget and no stop flag, which
    # is exactly the old behaviour plus a ceiling.
    stopper: Optional[Callable[[], bool]] = None   # investigator wires this to runs.stop_requested
    deadline: float = 0.0                          # time.monotonic() the CURRENT call must give up at
    tool_name: str = ""                            # the call in flight, for the refusal message

    # ---------------------------------------------------------------- interruption
    def begin_call(self, name: str, budget: Optional[float] = None) -> None:
        """Start the clock for one tool call. Called by the investigator before it dispatches."""
        self.tool_name = name
        self.deadline = time.monotonic() + float(budget if budget is not None else tool_budget_seconds())

    def stopping(self) -> bool:
        """True once the analyst has pressed Stop. Safe to call from a handler thread."""
        try:
            return bool(self.stopper and self.stopper())
        except Exception:  # noqa: BLE001 — a broken stopper must never break a tool
            return False

    def remaining(self) -> float:
        """Seconds left in this call's budget. Unset deadline = the default budget, not infinity."""
        if not self.deadline:
            return float(tool_budget_seconds())
        return max(0.0, self.deadline - time.monotonic())

    def check(self, what: str = "") -> None:
        """Cooperative checkpoint: raise a ToolError if the analyst stopped or the budget is spent.

        A handler that loops or waits calls this. It is the ONLY way a stop can land inside a tool —
        killing the thread is not an option (see the module note on `TOOL_SECONDS_DEFAULT`)."""
        label = what or self.tool_name or "this call"
        if self.stopping():
            raise ToolError(f"stopped by the analyst while {label} was running — nothing was left half done.")
        if self.deadline and time.monotonic() >= self.deadline:
            raise ToolError(f"{label} ran out of its time budget ({tool_budget_seconds()}s) and was "
                            "abandoned cleanly. Try a narrower call.")

    def record(self, tool: str, summary: str, undo: dict[str, Any]) -> dict[str, Any]:
        self.cache.clear()
        self.writes += 1
        action = {"id": f"{self.run_id}-{self.writes}", "runId": self.run_id, "tool": tool,
                  "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "summary": summary,
                  "undo": undo, "undone": False}
        self.actions.append(action)
        return action


@dataclass
class Tool:
    name: str
    description: str
    properties: dict[str, Any]
    required: list[str]
    writes: bool
    fn: Callable[[dict[str, Any], RunContext], dict[str, Any]]

    def schema(self) -> dict[str, Any]:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description,
            "parameters": {"type": "object", "properties": self.properties,
                           "required": self.required, "additionalProperties": False}}}

    def validate_args(self, args: dict[str, Any]) -> None:
        """Refuse arguments this tool does not declare, and say what it DOES take.

        A model that invents parameters (`create_case(severity=…, status=…)` — neither exists on the Case
        model) is guessing rather than reading the schema, and silently dropping the extras would let it
        believe it had set something it had not. Missing required parameters are named here too, rather
        than surfacing later as a confusing TypeError from a handler.
        """
        unknown = [k for k in args if k not in self.properties]
        # absent or explicitly null only: `query:""` is a legitimate "match everything", and a handler
        # gives a better message than a schema check for the values it considers empty.
        missing = [k for k in self.required if k not in args or args[k] is None]
        if not unknown and not missing:
            return
        parts = []
        if unknown:
            parts.append(f"{self.name} has no parameter(s) {', '.join(sorted(unknown))}")
        if missing:
            parts.append(f"{self.name} requires {', '.join(missing)}")
        raise ToolError(
            "; ".join(parts) + ". Its schema is: " +
            ", ".join(f"{k}{' (required)' if k in self.required else ''}" for k in self.properties) +
            ". Call it again with only these parameters.")


REGISTRY: dict[str, Tool] = {}


def tool(name: str, description: str, properties: dict[str, Any], required: Optional[list[str]] = None,
         writes: bool = False) -> Callable[[Callable], Callable]:
    def deco(fn: Callable[[dict[str, Any], RunContext], dict[str, Any]]) -> Callable:
        REGISTRY[name] = Tool(name, description, properties, required or [], writes, fn)
        return fn
    return deco


def tool_schemas() -> list[dict[str, Any]]:
    return [t.schema() for t in REGISTRY.values()]


# --------------------------------------------------- calling a route handler directly
# A FastAPI handler declared `scope: str = Query("all", pattern=...)` does NOT have "all" as its Python
# default — it has a `fastapi.params.Query` OBJECT. FastAPI substitutes the real value only when it
# invokes the handler through the request pipeline. Calling one straight from a tool and omitting a
# parameter therefore hands the body a `Query` instance where it expects a string, and the first
# `.strip()` downstream raises `'Query' object has no attribute 'strip'`.
#
# That is exactly what `list_event_fields` did to the analyst: it omitted `from_`, so the field-facet
# tool failed on EVERY call and the agent could not tell whether an IP was a structured field or only a
# free-text match. It is a whole class of latent bug — events.py, graph.py, timeline.py, iocs.py and
# sources.py all carry `Query(...)` defaults — so the fix is structural rather than one extra argument:
# every direct handler call in this module goes through `call_route`, which fills in the REAL default
# for any parameter the caller did not supply. `tests/test_ai_tool_calls.py` asserts no sentinel can
# reach a handler again.
def _real_default(param: inspect.Parameter) -> Any:
    """The value FastAPI would have used for a parameter nobody passed."""
    d = param.default
    if d is inspect.Parameter.empty:
        return None
    inner = getattr(d, "default", inspect.Parameter.empty)
    if inner is inspect.Parameter.empty:
        return d                       # a plain Python default — use it as-is
    # a Query/Path/Body/Header FieldInfo: its `.default` is the real one (Ellipsis / PydanticUndefined
    # both mean "required", and a required parameter the caller omitted can only sensibly be None)
    if inner is Ellipsis or type(inner).__name__ == "PydanticUndefinedType":
        return None
    return inner


def is_fastapi_sentinel(value: Any) -> bool:
    """True for a `Query(...)`/`Depends(...)` object that leaked into a handler as a value."""
    mod = type(value).__module__ or ""
    return mod.startswith("fastapi.params") or mod.startswith("pydantic.fields")


def call_route(fn: Callable[..., Any], /, **kwargs: Any) -> Any:
    """Call a FastAPI route handler as a plain function, with its declared defaults resolved."""
    call: dict[str, Any] = {}
    for name, p in inspect.signature(fn).parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        call[name] = kwargs[name] if name in kwargs else _real_default(p)
    unknown = set(kwargs) - set(call)
    if unknown:
        raise TypeError(f"{fn.__name__}() has no parameter(s) {sorted(unknown)}")
    return fn(**call)


# ------------------------------------------------------------------ helpers
def _s(v: Any, limit: int = MAX_TEXT) -> str:
    return str(v or "")[:limit]


# A model that DOUBLE-ESCAPES its tool arguments sends the two characters backslash-n where it means a
# line break, so a note arrives as one wall of text with visible \n in it. Measured on the analyst's
# own case: all four AI-written notes were stored that way, headings and markdown tables included, and
# the panel rendered them as a single unreadable paragraph.
_ESCAPED = re.compile(r"\\(?:r\\n|n|r)")


def _prose(v: Any, limit: int = MAX_TEXT) -> str:
    """A free-text field the analyst will READ, with double-escaped line breaks repaired.

    Only when the text has no real line break of its own and carries at least two escape sequences.
    That narrowness is the point: a backslash-n inside a quoted evidence line (a Windows path, a regex,
    a raw log excerpt) is DATA, and rewriting it would corrupt what the note claims the log said. A
    model that double-escapes does it to the whole argument, so the all-or-nothing test is exactly the
    signal — and when it is ambiguous, nothing is touched.

    Never used for `query`: the search DSL has its own backslash escape (`\\:` for a literal colon).
    """
    text = str(v or "")
    if "\n" not in text and "\r" not in text and len(_ESCAPED.findall(text)) >= 2:
        text = _ESCAPED.sub("\n", text).replace("\\t", "\t")
    return text[:limit]


def _int(args: dict[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    try:
        n = int(args.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _scope(args: dict[str, Any]) -> str:
    return "case" if str(args.get("scope") or "all").lower() == "case" else "all"


def _ids(args: dict[str, Any], key: str, cap: int = MAX_CITED) -> list[str]:
    raw = args.get(key)
    if isinstance(raw, str):
        raw = [x.strip() for x in raw.split(",")]
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for x in raw:
        s = str(x).strip()
        if s and s not in out:
            out.append(s)
    return out[:cap]


# ------------------------------------------------- reading events: ONE row shape, shared by three tools
# The agent went back for events one at a time because the tool that FOUND them did not return what it
# needed: search_events gave identity and a 300-char message, but never the raw log line, the parsed
# fields or the entities. `get_event` was the only way to get those, and it takes one id — so reading
# twenty hits cost twenty steps of a forty-step budget and the run ended with no answer. The fix is in
# the result shape (`include`) and in a batch read (`get_events`), not in a faster per-event fetch.
DETAIL_PARTS = ("raw", "fields", "entities")
MAX_FETCH = 25           # events one get_events call may return
DETAIL_BUDGET = 4500     # total chars of optional raw/field text one multi-event result may carry


def _include(args: dict[str, Any]) -> set[str]:
    """Parse `include` — which heavy parts of an event row the caller actually wants."""
    want = {p.strip().lower() for p in _s(args.get("include"), 200).replace(" ", ",").split(",") if p.strip()}
    bad = sorted(want - set(DETAIL_PARTS))
    if bad:
        raise ToolError(f"include does not accept {', '.join(bad)}. It takes any of: "
                        f"{', '.join(DETAIL_PARTS)} (comma-separated).")
    return want


ROW_BUDGET = 5600        # bytes one multi-event tool result may occupy (under TOOL_RESULT_CHARS)


def _detail_caps(n: int) -> tuple[int, int]:
    """(raw chars, parsed fields) per event so that n events still fit inside ONE tool result.

    investigator._clip truncates a tool result at TOOL_RESULT_CHARS and the truncation takes the END of
    the payload — so an unclamped twenty-event read does not come back slightly short, it comes back
    missing its last events entirely, which is the silent-omission failure this codebase keeps fighting.
    Clamping every row a little is the honest trade, and the clamp is reported per row.
    """
    per = DETAIL_BUDGET // max(1, n)
    return max(120, min(1200, per)), (4 if per < 300 else (10 if per < 700 else 30))


def _size(obj: Any) -> int:
    import orjson
    try:
        return len(orjson.dumps(obj))
    except TypeError:
        return len(str(obj))


def _shed(out: dict[str, Any], budget: int, steps: list[tuple[str, Callable[[], None]]],
          why: str) -> dict[str, Any]:
    """Shrink a result until it fits ONE tool result, in a DEFINED order, and say what went.

    A fixed per-row clamp is not a budget: the same twenty-five events can be 4 kB or 13 kB depending
    on how long the log lines are, and `_clip` cuts from the END — so the overflow is paid entirely by
    the last rows, which vanish without a word. Shedding in a stated order keeps the shape of the
    answer (every row the caller asked for, every count) and gives up the detail, which is the right
    way round. Never drop a ROW here: the caller named those ids.
    """
    shed: list[str] = []
    for label, apply in steps:
        if _size(out) <= budget:
            break
        apply()
        shed.append(label)
    if shed:
        out["trimmed"] = ", ".join(shed) + " — " + why
    return out


def _fit_rows(out: dict[str, Any], budget: int = ROW_BUDGET) -> dict[str, Any]:
    """Fit a multi-event read into one tool result WITHOUT losing any of its rows."""
    rows = out.get("rows") or []

    def clamp_raw(n: int) -> Callable[[], None]:
        def go() -> None:
            for r in rows:
                if "raw" in r:
                    r["raw"] = str(r["raw"])[:n]
        return go

    def drop(key: str) -> Callable[[], None]:
        def go() -> None:
            for r in rows:
                r.pop(key, None)
                r.pop(key + "Truncated", None)
        return go

    def thin_fields(n: int) -> Callable[[], None]:
        def go() -> None:
            for r in rows:
                if isinstance(r.get("fields"), dict):
                    r["fields"] = dict(list(r["fields"].items())[:n])
        return go

    def thin_detections(n: int) -> Callable[[], None]:
        """Keep the first n rule ids per row and say how many were dropped.

        Last on the ladder on purpose — a detection id is the most citable thing on a row. It exists at
        all because the catalogue GREW: an event that fires six rules carries six ids, and at 25 rows
        that is the difference between fitting in one tool result and having the last rows silently cut
        off the end. Never drop the key entirely: "no detections" and "detections not shown" are
        different claims about the evidence.
        """
        def go() -> None:
            for r in rows:
                d = r.get("detections")
                if isinstance(d, list) and len(d) > n:
                    r["detections"] = d[:n]
                    r["detectionsTruncated"] = len(d) - n
        return go

    def keep_identity() -> Callable[[], None]:
        """The floor of the ladder: id, timestamp, severity, source and detections, nothing else.

        A ladder that can RUN OUT is not a budget — and this one could, because the identity of 25 rows
        (id, ts, sev, source, file, host, user, a 300-character msg, and the JSON key names for all of
        them) is ~6 kB before a single log line is included. When it ran out, `_clip` took the overflow
        off the END and the last rows vanished without a word, which is the failure this whole function
        exists to prevent. So the last step gives up everything that is not needed to CITE the row and
        go and read it. It is a real loss, and it is stated in `trimmed` — but a row the model can
        still open beats a row it never saw.
        """
        keep = ("id", "ts", "sev", "source", "detections", "detectionsTruncated", "inCase")
        def go() -> None:
            for r in rows:
                for k in [k for k in r if k not in keep]:
                    r.pop(k, None)
        return go

    def clamp_msg(n: int) -> Callable[[], None]:
        def go() -> None:
            for r in rows:
                if len(str(r.get("msg", ""))) > n:
                    r["msg"] = str(r["msg"])[:n]
        return go

    # The last three steps exist because the BASE row grew: `msg` is capped at 300 characters and the
    # detection list is as long as the number of rules that fired, so 25 rows of ordinary events can
    # exceed the budget with raw, fields and entities ALREADY dropped — and then the ladder ran out and
    # `_clip` cut the last rows off the end without a word, which is the exact failure this exists to
    # prevent. `msg` is a normalized summary and goes before `raw`; a detection id is the most citable
    # thing on a row, so it is trimmed last and never removed (an empty list would say "nothing fired").
    return _shed(out, budget, [
        ("shorter raw lines", clamp_raw(240)),
        ("fewer parsed fields", thin_fields(4)),
        ("entities dropped", drop("entities")),
        ("shorter raw lines again", clamp_raw(120)),
        ("parsed fields dropped", drop("fields")),
        ("shorter messages", clamp_msg(160)),
        ("raw lines dropped", drop("raw")),
        ("fewer detection ids per row", thin_detections(2)),
        ("shorter messages again", clamp_msg(80)),
        ("everything but the identity of each row", keep_identity()),
    ], "to keep every row you asked for inside one tool result. Ask for fewer ids, or a smaller limit, "
       "if you need the full text of each line.")


def _row(r: dict[str, Any], want: set[str] = frozenset(), raw_cap: int = 400,
         field_cap: int = 30) -> dict[str, Any]:
    """One event as the agent reads it: the identity every read tool returns, plus what `include` asked
    for. ONE implementation for search_events / get_events / sample_events, so the three can never drift
    into describing the same event differently. `r` is an API row (Store.stamp_membership / model_dump).
    """
    out: dict[str, Any] = {
        "id": r["id"], "ts": r["ts"], "sev": r["sev"], "source": r["source"], "file": r["file"],
        "host": r.get("host") or "", "user": r.get("user") or "", "msg": _s(r.get("msg"), 300),
        "detections": [d["id"] if isinstance(d, dict) else d.id for d in (r.get("detections") or [])],
        "inCase": bool(r.get("inCase"))}
    if "raw" in want:
        full = str(r.get("raw") or "")
        out["raw"] = full[:raw_cap]
        if len(full) > raw_cap:
            out["rawTruncated"] = len(full) - raw_cap
    if "fields" in want:
        f = r.get("fields") or {}
        out["fields"] = {k: _s(v, 120) for k, v in list(f.items())[:field_cap]}
        if len(f) > field_cap:
            out["fieldsTruncated"] = len(f) - field_cap
    if "entities" in want:
        out["entities"] = list(r.get("entities") or [])[:20]
    return out


def _store():
    from ..store import STORE
    return STORE


def _require_case(what: str) -> None:
    """Refuse a case-scoped write when no case exists.

    Creating one is an EXPLICIT tool call (create_case). A write that quietly conjured a case would
    make `Case.pending` a lie and leave a case on disk the analyst never asked for.
    """
    store = _store()
    if store.pending:
        raise ToolError(f"there is no active case, so {what} cannot be stored. "
                        "Call create_case(name=…) first if the investigation warrants one.")


def verify_event_ids(ids: list[str]) -> list[str]:
    """Return the ids that are NOT real events in the workspace pool."""
    store = _store()
    return [i for i in ids if store.event(i) is None]


def _cited(args: dict[str, Any], text: str, what: str, how: str) -> list[str]:
    """The event ids backing a write — from `citedEventIds`, or from the ids written in the text itself.

    The rule that every finding must be traceable is not negotiable, but WHERE the analyst-visible
    citation lives is. A model that writes "every one of the 64 events, e.g. `l6e2c94f91078ed`" into the
    note and forgets the parameter has cited its evidence; refusing that call outright cost the analyst
    a whole round trip and, measured on their own run, several more as the model retried. So the ids in
    the prose are adopted — VERIFIED against the pool exactly like the parameter, so a fabricated id is
    still refused and still named. An empty result is still a refusal: a finding with no evidence must
    not go in the case file.
    """
    ids = _ids(args, "citedEventIds")
    if ids:
        _check_citations(ids, what)
        return ids
    store = _store()
    found = [v for v in eventids.find(text or "") if store.event(v) is not None][:MAX_CITED]
    if found:
        return found
    raise ToolError(
        f"citedEventIds is required: {what} with no evidence cannot go in the case file. Pass the event "
        f"ids you actually saw (from search_events / sample_events / entity_profile / get_events) in "
        f"citedEventIds — {how}. Ids written in the text are used when the parameter is missing, but only "
        f"if they are real ids from this workspace.")


def _check_citations(ids: list[str], what: str) -> None:
    unknown = verify_event_ids(ids)
    if unknown:
        raise ToolError(
            f"refusing to save {what}: these cited event ids do not exist in this workspace: "
            f"{', '.join(unknown[:10])}. Cite only ids returned by search_events / get_event / "
            f"get_timeline, verbatim, and try again.")


def _budget(ctx: RunContext) -> None:
    if ctx.writes >= ctx.max_writes:
        raise ToolError(f"this run has already made {ctx.writes} changes, which is the per-run limit. "
                        "Summarise what you found instead of writing more.")


# ------------------------------------------------- waiting for a derived structure, with a deadline
# The entity graph, the correlation analysis and the anomaly roll-up are O(the whole pool) to build:
# CLAUDE.md's own table puts a graph build at 55 s parallel / 187 s serial at 1.2 M events, and the
# analyst's pool is 11.4 M. Calling the BLOCKING accessor from a tool handler therefore parks the run
# — and, because the build contends `STORE.lock`, stalls ingest and `/api/library` with it.
#
# CLAUDE.md is right that an agent cannot poll a `building` status and that an empty list would make it
# report "no detections fired". The answer is not the blocking accessor, and it is not an empty result
# either: it is a BOUNDED wait on the non-blocking accessor (which starts the background build), with a
# refusal that says exactly what is still building, how far along it is, and what to call instead. A
# ToolError is data the model can act on; a run that never returns is not.
def _await_derived(ctx: RunContext, what: str, ready: Callable[[], Any],
                   status: Callable[[], dict[str, Any]], alternative: str) -> Any:
    """Poll a `derived.AsyncCache` accessor until it has a value, the analyst stops, or time runs out."""
    v = ready()
    if v is not None:
        return v
    st = status() or {}
    note = st.get("note")
    if note:
        # Paused, not building: `Store.derived_builds_paused()` refuses to start a build while the pool
        # is loading or the enrichment queue is working. Waiting would be waiting for nothing.
        raise ToolError(f"the {what} is not built and cannot be built right now — Iris is {note}. "
                        f"{alternative}")
    budget = min(float(derived_wait_seconds()), ctx.remaining())
    until = time.monotonic() + budget
    while time.monotonic() < until:
        ctx.check(f"waiting for the {what}")
        time.sleep(DERIVED_POLL)
        v = ready()
        if v is not None:
            return v
    st = status() or {}
    pct = st.get("pct")
    where = f" (it is {pct:.0f}% built)" if isinstance(pct, (int, float)) and st.get("state") == "building" else ""
    raise ToolError(
        f"the {what} is still building after {int(budget)}s{where} and this workspace is large enough "
        f"that it may take minutes. This is NOT an empty result — do not report it as an absence of "
        f"evidence. {alternative}")


GRAPH_ALTERNATIVE = ("Answer from the search index instead: entity_profile(value=…) gives the exact "
                     "counts, the time window, the breakdown by source/host/user/severity and citable "
                     "log lines for one entity without the graph, and search_events / aggregate_events "
                     "answer the rest. Retry the graph later in the run if relations are essential.")


def _graph(ctx: RunContext, scope: str):
    """The entity graph for `scope`, waiting a BOUNDED time for a background build. Never blocks forever.

    Used by every tool whose answer genuinely requires the graph (the relations are the answer).
    `entity_profile` deliberately does NOT use this — it omits the relations and says so, because the
    rest of its answer needs no graph at all and it is the first tool the prompt sends the model to.
    """
    store = _store()
    return _await_derived(ctx, "entity graph",
                          lambda: store.graph_v2_ready(scope),
                          lambda: store.graph_status(scope),
                          GRAPH_ALTERNATIVE)


def _analysis(ctx: RunContext, scope: str) -> dict[str, Any]:
    store = _store()
    return _await_derived(ctx, "correlation analysis",
                          lambda: store.analysis_ready(scope),
                          lambda: store.analysis_status(scope),
                          "Build the timeline yourself instead: search_events / events_over_time over "
                          "the entity or query you care about, then add_events_to_case + "
                          "annotate_case_events. That needs no correlation pass.")


def _anomalies(ctx: RunContext) -> list[Any]:
    from .. import anomalies
    return _await_derived(ctx, "detection roll-up",
                          anomalies.ready, anomalies.status,
                          "search_events with `sev:critical OR sev:high` reaches detection-bearing "
                          "events directly, and list_detection_rules says which rules exist at all.")


# ------------------------------------------------------- the query language, used correctly
# app/query.py is deliberately FORGIVING: an unbalanced quote or a dangling AND does not raise, it just
# parses to something that matches nothing. For a human at the search box that is the right trade — for
# an agent it is a trap, because "0 matches" from a broken query is indistinguishable from "this is not
# in the logs", and that is precisely how an analyst gets told something is absent when it is present.
# So the tool layer screens the query first and refuses with a corrected example.
def validate_query(q: str) -> str:
    s = (q or "").strip()
    if not s:
        return ""
    quotes = depth = 0
    esc = False
    for ch in s:
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
        elif ch == '"':
            quotes += 1
        elif quotes % 2 == 0 and ch == "(":
            depth += 1
        elif quotes % 2 == 0 and ch == ")":
            depth -= 1
            if depth < 0:
                raise ToolError(f"unbalanced ')' in the query {s!r}. {DSL_HELP}")
    if quotes % 2:
        raise ToolError(f'unbalanced double quote in the query {s!r} — every phrase needs a closing ". {DSL_HELP}')
    if depth:
        raise ToolError(f"unclosed '(' in the query {s!r}. {DSL_HELP}")
    words = s.split()
    if words and words[-1].upper() in ("AND", "OR", "NOT"):
        raise ToolError(f"the query {s!r} ends with {words[-1].upper()} and has no right-hand term. {DSL_HELP}")
    for w in words:
        if w.upper() in ("AND", "OR"):
            continue
        # `user:` with nothing after it matches every event that has the field at all, which is almost
        # never what was meant — and silently so.
        if w.endswith(":") and not w.endswith("\\:") and len(w) > 1:
            raise ToolError(f"the term {w!r} has a field but no value. Write `{w}<value>`, or escape the "
                            f"colon as `{w[:-1]}\\:` to search for the literal text. {DSL_HELP}")
    return s


def _filters(args: dict[str, Any]) -> tuple:
    """(events, ts, version, lo, hi, src_set, sev_set) for the same filter set GET /api/events takes.

    Goes through the events router's own resolver so an aggregation and a search of the same query can
    never disagree about what "the result set" is.
    """
    from ..routers.events import _search_filters
    return call_route(_search_filters, sources=_s(args.get("sources"), 500), sev=_s(args.get("sev"), 100),
                      from_=_s(args.get("from"), 64) or None, to=_s(args.get("to"), 64) or None,
                      scope=_scope(args))


def _uninterpreted_sources() -> list[dict[str, Any]]:
    """Sources still in phase 1 — raw lines, no parsed fields and no extracted entities.

    Load-bearing for COVERAGE. `entity:"x"` and `field:value` can only match what phase 2 extracted, so
    on a raw-first workspace they answer over a SUBSET of the pool. The analyst reported it exactly:
    *"the assistant is not including all log sources in its investigation, only enriched data is being
    searched against."* Free text still reaches every raw line, so the evidence is all there — what was
    missing is any signal that the two query forms cover different amounts of it.
    """
    store = _store()
    out: list[dict[str, Any]] = []
    try:
        for src in store.sources.values():
            if str(getattr(src, "enrich", "") or "") in ("raw", "queued", "enriching", "skipped", "error"):
                out.append({"sourceId": src.id, "file": src.file, "events": int(src.events or 0),
                            "state": str(getattr(src, "enrich", "") or "raw")})
    except Exception:  # noqa: BLE001 — coverage reporting must never sink a tool call
        return []
    return sorted(out, key=lambda r: -r["events"])


def _matching(args: dict[str, Any], *, cap: int = 0) -> dict[str, Any]:
    """Every event matching the query — the backend does the work, the model never counts rows itself.

    `search_engine.search` is the same code path the search screen uses (vector/CUDA index when the pool
    is big enough, exact predicate confirmation), so an aggregate is exact, not sampled.
    """
    from .. import search as search_engine
    q = validate_query(_s(args.get("query"), 2000))
    events, ts, version, lo, hi, src_set, sev_set = _filters(args)
    limit = cap if cap else max(1, len(events))
    res = search_engine.search(events, ts, version, q, lo, hi, src_set, sev_set, 0, limit, desc=False)
    return res


_GROUP_FIXED = {"source": lambda e: [e.source], "sourceId": lambda e: [e.sourceId], "file": lambda e: [e.file],
                "host": lambda e: [e.host], "user": lambda e: [e.user], "sev": lambda e: [e.sev],
                "detection": lambda e: [d.id for d in e.detections],
                "entity": lambda e: list(e.entities)}


def _group_values(e: Any, field: str) -> list[str]:
    fn = _GROUP_FIXED.get(field)
    if fn is not None:
        return [v for v in fn(e) if v]
    v = e.fields.get(field)
    return [str(v)] if v not in (None, "") else []


def _aggregate(rows: list[Any], field: str) -> tuple[list[dict[str, Any]], int, int]:
    """(groups sorted by count desc, distinct group count, events with no value for the field)."""
    counts: dict[str, dict[str, Any]] = {}
    missing = 0
    for e in rows:
        vals = _group_values(e, field)
        if not vals:
            missing += 1
            continue
        for v in vals:
            g = counts.get(v)
            if g is None:
                counts[v] = {"value": _s(v, 200), "count": 1, "first": e.ts, "last": e.ts}
            else:
                g["count"] += 1
                if e.ts < g["first"]:
                    g["first"] = e.ts
                if e.ts > g["last"]:
                    g["last"] = e.ts
    ordered = sorted(counts.values(), key=lambda g: (-g["count"], g["value"]))
    return ordered, len(ordered), missing


def _cost(res: dict[str, Any]) -> dict[str, Any]:
    return {"engine": res.get("engine"), "tookMs": res.get("tookMs")}


# ================================================================== READ tools
@tool("search_events",
      "Retrieve individual matching events so you can READ them. Pass include='raw,fields' to get the "
      "original log lines and parsed fields in the SAME call — do not search and then fetch the hits one "
      "by one. Do NOT use it to count or to work out which logs something appears in: it returns at most "
      "50 rows and counting them yourself will be wrong; use aggregate_events / count_events for that. "
      + DSL_HELP,
      {"query": {"type": "string", "description": "DSL query; empty string matches everything"},
       "include": {"type": "string",
                   "description": "comma-separated extras to return per row: raw (the original log line), "
                                  "fields (parsed fields), entities. Omit for identity + message only."},
       "limit": {"type": "integer", "description": "rows to return, 1-50 (default 20)"},
       "offset": {"type": "integer", "description": "skip this many matches before returning rows"},
       "sources": {"type": "string", "description": "comma-separated source ids to restrict to"},
       "sev": {"type": "string", "description": "comma-separated severities: critical,high,medium,low,info"},
       "from": {"type": "string", "description": "ISO-8601 UTC lower bound on the timestamp"},
       "to": {"type": "string", "description": "ISO-8601 UTC upper bound on the timestamp"},
       "scope": {"type": "string", "enum": ["all", "case"], "description": "'all' = everything ingested (default), 'case' = the curated case set only"},
       "sort": {"type": "string", "enum": ["ts_asc", "ts_desc"], "description": "chronological or newest-first (default ts_asc)"}},
      ["query"])
def _search_events(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.events import list_events
    validate_query(_s(args.get("query"), 2000))
    limit = _int(args, "limit", 20, 1, MAX_ROWS)
    want = _include(args)
    res = call_route(list_events, q=_s(args.get("query"), 2000), sources=_s(args.get("sources"), 500),
                     sev=_s(args.get("sev"), 100), from_=_s(args.get("from"), 64) or None,
                     to=_s(args.get("to"), 64) or None, limit=limit, offset=_int(args, "offset", 0, 0, 100000),
                     scope=_scope(args), sort="ts_desc" if str(args.get("sort")) == "ts_desc" else "ts_asc")
    rows = res["rows"]
    raw_cap, field_cap = _detail_caps(len(rows))
    out = {"total": res["total"], "returned": len(rows), "engine": res.get("engine"),
           "tookMs": res.get("tookMs"),
           "rows": [_row(r, want, raw_cap, field_cap) for r in rows]}
    if res["total"] > len(rows):
        out["note"] = (f"{res['total']:,} events match but only {len(rows)} are shown. Do not infer counts or "
                       "coverage from these rows — call aggregate_events to get exact per-source counts.")
    if not want:
        out["hint"] = ("these rows carry identity and the normalized message only. If you need the original "
                       "log lines or the parsed fields, re-run this search with include='raw,fields' rather "
                       "than fetching the hits one at a time.")
    return _fit_rows(out)


@tool("count_events",
      "EXACT number of events matching a query — no rows, no sampling, no arithmetic on your part. "
      "Use it for 'does this appear at all' and 'how much of it is there'. " + DSL_HELP,
      {"query": {"type": "string", "description": "DSL query; '' matches everything"},
       "sources": {"type": "string", "description": "comma-separated source ids to restrict to"},
       "sev": {"type": "string", "description": "comma-separated severities"},
       "from": {"type": "string"}, "to": {"type": "string"},
       "scope": {"type": "string", "enum": ["all", "case"]}},
      ["query"])
def _count_events(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    res = _matching(args, cap=1)
    return {"query": _s(args.get("query"), 2000), "scope": _scope(args), "total": res["total"], **_cost(res)}


@tool("aggregate_events",
      "Count matching events GROUPED BY a field — the fastest and only exact way to answer 'which logs / "
      "hosts / users does X appear in', 'where is it most frequent', 'what is the breakdown by severity'. "
      "One call replaces paging through rows, and the counts are computed over EVERY match, not a sample. "
      "groupBy accepts source, sourceId, file, host, user, sev, detection, entity, or any parsed field "
      "name from list_event_fields. Groups with zero matches are simply not returned. " + DSL_HELP,
      {"query": {"type": "string", "description": "DSL query; '' matches everything"},
       "groupBy": {"type": "string", "description": "field to group by, e.g. 'source'"},
       "top": {"type": "integer", "description": "groups to return, 1-200 (default 25); they come back count-descending"},
       "sources": {"type": "string"}, "sev": {"type": "string"},
       "from": {"type": "string"}, "to": {"type": "string"},
       "scope": {"type": "string", "enum": ["all", "case"]}},
      ["query", "groupBy"])
def _aggregate_events(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    field = _s(args.get("groupBy"), 80).strip()
    if not field:
        raise ToolError("groupBy is required — name the field to count by, e.g. 'source'.")
    res = _matching(args)
    groups, distinct, missing = _aggregate(res["rows"], field)
    top = _int(args, "top", 25, 1, MAX_GROUPS)
    return {"query": _s(args.get("query"), 2000), "scope": _scope(args), "groupBy": field,
            "total": res["total"], "distinctGroups": distinct, "withoutField": missing,
            "groups": groups[:top], "truncated": distinct > top, **_cost(res)}


@tool("distinct_values",
      "The distinct values a field takes within a result set, with how many events carry each. Use it to "
      "answer 'which users', 'which destination ports', 'what statuses' without reading rows. " + DSL_HELP,
      {"query": {"type": "string"}, "field": {"type": "string", "description": "field name"},
       "limit": {"type": "integer", "description": "values to return, 1-200 (default 50)"},
       "sources": {"type": "string"}, "sev": {"type": "string"},
       "from": {"type": "string"}, "to": {"type": "string"},
       "scope": {"type": "string", "enum": ["all", "case"]}},
      ["query", "field"])
def _distinct_values(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    field = _s(args.get("field"), 80).strip()
    if not field:
        raise ToolError("field is required")
    res = _matching(args)
    groups, distinct, missing = _aggregate(res["rows"], field)
    limit = _int(args, "limit", 50, 1, MAX_GROUPS)
    return {"field": field, "total": res["total"], "distinct": distinct, "withoutField": missing,
            "values": [{"value": g["value"], "count": g["count"]} for g in groups[:limit]],
            "truncated": distinct > limit, **_cost(res)}


_BUCKETS = {"minute": 60, "hour": 3600, "day": 86400}


def _histogram(rows: list[Any], want: str, limit: int) -> dict[str, Any]:
    """Timestamp histogram over already-matched events.

    ONE implementation, shared by events_over_time and entity_profile — the two must never be able to
    describe the same activity differently. Events with no parsed timestamp are counted separately
    rather than folded into a bucket they cannot honestly claim (see "Raw is never a lie").
    """
    from math import isfinite
    from ..store import _iso_to_epoch
    epochs = [ep for ep in (_iso_to_epoch(e.ts) for e in rows) if isfinite(ep)]
    undated = len(rows) - len(epochs)
    if not epochs:
        return {"bucket": "", "buckets": [], "distinctBuckets": 0, "truncated": False,
                "first": None, "last": None, "peak": None, "withoutTimestamp": undated}
    lo, hi = min(epochs), max(epochs)
    if want not in _BUCKETS:
        span = max(1.0, hi - lo)
        want = "minute" if span <= 3 * 3600 else ("hour" if span <= 5 * 86400 else "day")
    size = _BUCKETS[want]
    counts: dict[int, int] = {}
    for ep in epochs:
        b = int(ep // size) * size
        counts[b] = counts.get(b, 0) + 1
    keys = sorted(counts)
    peak = max(counts.items(), key=lambda kv: kv[1])

    def iso(ep: float) -> str:
        return datetime.fromtimestamp(ep, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {"bucket": want, "buckets": [{"start": iso(k), "count": counts[k]} for k in keys[:limit]],
            "distinctBuckets": len(keys), "truncated": len(keys) > limit,
            "first": iso(lo), "last": iso(hi),
            "peak": {"start": iso(peak[0]), "count": peak[1]}, "withoutTimestamp": undated}


@tool("events_over_time",
      "A timestamp histogram of the matching events — when the activity started, when it stopped, when it "
      "peaked — without pulling a single row. bucket is minute, hour, day or auto.",
      {"query": {"type": "string"}, "bucket": {"type": "string", "enum": ["auto", "minute", "hour", "day"]},
       "limit": {"type": "integer", "description": "buckets to return, 1-200 (default 60)"},
       "sources": {"type": "string"}, "sev": {"type": "string"},
       "from": {"type": "string"}, "to": {"type": "string"},
       "scope": {"type": "string", "enum": ["all", "case"]}},
      ["query"])
def _events_over_time(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    res = _matching(args)
    rows = res["rows"]
    if not rows:
        return {"total": 0, "buckets": [], "first": None, "last": None, **_cost(res)}
    want = _s(args.get("bucket"), 20).strip().lower() or "auto"
    return {"total": res["total"],
            **_histogram(rows, want, _int(args, "limit", 60, 1, MAX_GROUPS)), **_cost(res)}


@tool("sample_events",
      "A small, evenly spread sample of the matching events, for READING actual log lines when you need "
      "to see what they look like. It is a sample, never a census: never count from it or conclude "
      "coverage from it — use count_events / aggregate_events for that.",
      {"query": {"type": "string"}, "n": {"type": "integer", "description": "sample size, 1-20 (default 5)"},
       "include": {"type": "string",
                   "description": "comma-separated extras per row: raw (default), fields, entities"},
       "sources": {"type": "string"}, "sev": {"type": "string"},
       "from": {"type": "string"}, "to": {"type": "string"},
       "scope": {"type": "string", "enum": ["all", "case"]}},
      ["query"])
def _sample_events(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    n = _int(args, "n", 5, 1, 20)
    want = _include(args) or {"raw"}
    res = _matching(args)
    rows = res["rows"]
    total = len(rows)
    if total <= n:
        picked = rows
    else:
        step = total / float(n)
        picked = [rows[min(total - 1, int(i * step))] for i in range(n)]
    raw_cap, field_cap = _detail_caps(len(picked))
    return _fit_rows({"total": res["total"], "sampled": len(picked),
                      "note": "a spread sample for reading — not a count",
                      "rows": [_row(r, want, raw_cap, field_cap) for r in _store().stamp_membership(picked)],
                      **_cost(res)})


@tool("get_events",
      "Read MANY events in ONE call — pass every id you want. This is the tool for 'now show me those "
      "lines': fetching ids one at a time with get_event spends a whole step per event and exhausts the "
      "step budget before there is an answer. Returns each event's identity, message, detections and "
      "whatever `include` asks for (the raw log line by default). Ids that do not exist come back named "
      "in `missing` rather than silently dropped. Use get_event (singular) only for the DEEP DIVE on one "
      f"event — correlations, baseline and surrounding file lines. Maximum {MAX_FETCH} ids per call.",
      {"eventIds": {"type": "array", "items": {"type": "string"},
                    "description": f"event ids exactly as returned by search_events, up to {MAX_FETCH}"},
       "include": {"type": "string",
                   "description": "comma-separated extras per event: raw (default), fields, entities"}},
      ["eventIds"])
def _get_events(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    ids = _ids(args, "eventIds", cap=MAX_FETCH * 8)
    if not ids:
        raise ToolError("eventIds is required — pass the ids you want to read, e.g. "
                        "[\"e12\", \"e13\"]. To find ids first, call search_events.")
    if len(ids) > MAX_FETCH:
        raise ToolError(
            f"{len(ids)} ids is more than get_events returns in one call (maximum {MAX_FETCH}). Ask for "
            f"the {MAX_FETCH} that matter most, or — if what you actually need is a count or a breakdown "
            "rather than the lines themselves — use count_events / aggregate_events, which are exact over "
            "every match.")
    want = _include(args) or {"raw"}
    found: list[Any] = []
    missing: list[str] = []
    for eid in ids:
        e = store.event(eid)
        if e is None:
            missing.append(eid)
        else:
            found.append(e)
    raw_cap, field_cap = _detail_caps(max(1, len(found)))
    # stamp_membership is the same pool→API conversion list_events uses for a page of results: the batch
    # read is the SEARCH path's shape, not a second implementation of the detail endpoint (which computes
    # correlations and a baseline per event — an O(pool) analyzer call each, and never what a batch wants).
    out: dict[str, Any] = {"requested": len(ids), "returned": len(found),
                           "rows": [_row(r, want, raw_cap, field_cap)
                                    for r in store.stamp_membership(found)]}
    if missing:
        out["missing"] = missing
        out["note"] = ("no event exists in this workspace with these ids: " + ", ".join(missing[:10]) +
                       ". Do not cite them — go back to search_events for the real ids.")
    return _fit_rows(out)


@tool("get_event",
      "DEEP DIVE on ONE event: every parsed field, the raw log line, its detections, the events Iris "
      "correlated with it and the baseline. With contextLines > 0 it also returns the surrounding lines "
      "of the original log file. Call it when you need the correlations or the file context for a single "
      "decisive event. To read SEVERAL events, call get_events once with all their ids instead — one "
      "get_event per id burns the step budget and is never the right way to read a result set.",
      {"eventId": {"type": "string", "description": "event id exactly as returned by search_events"},
       "includeRaw": {"type": "boolean", "description": "include the raw log line (default true)"},
       "contextLines": {"type": "integer", "description": "lines of the source file either side, 0-10 (default 0)"}},
      ["eventId"])
def _get_event(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.events import get_event
    from fastapi import HTTPException
    eid = _s(args.get("eventId"), 200)
    try:
        d = call_route(get_event, eid=eid)
    except HTTPException:
        raise ToolError(f"no event with id {eid!r} exists in this workspace")
    out = d.model_dump()
    out["fields"] = {k: _s(v, 200) for k, v in list(out.get("fields", {}).items())[:60]}
    out["msg"] = _s(out.get("msg"), 600)
    out["raw"] = _s(out.get("raw"), 1200) if args.get("includeRaw", True) else ""
    out["correlations"] = [{"id": c["id"], "ts": c["ts"], "sev": c["sev"], "msg": _s(c["msg"], 200),
                            "reason": _s(c["reason"], 200)} for c in out.get("correlations", [])[:10]]
    out["entities"] = out.get("entities", [])[:40]
    n = _int(args, "contextLines", 0, 0, 10)
    if n:
        from ..routers.events import event_location
        loc = call_route(event_location, eid=eid, context=n)
        out["fileContext"] = {"file": loc["file"], "line": loc["line"], "exact": loc["exact"],
                              "lines": [{"n": c["n"], "text": _s(c["text"], 300), "current": c["current"]}
                                        for c in loc["context"]]}
    return out


@tool("list_sources",
      "List every ingested log source (case sources and case-less library sources) with its parser, "
      "event count and time range. Use it to know what evidence exists before searching.",
      {})
def _list_sources(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    c = store.case()
    def row(s: Any, origin: str) -> dict[str, Any]:
        return {"id": s.id, "file": s.file, "parser": s.parser, "events": s.events, "state": s.state,
                "range": list(s.range) if s.range else None, "origin": origin}
    return {"caseSources": [row(s, "case") for s in c.sources],
            "librarySources": [row(s, "library") for s in c.librarySources],
            "poolEventCount": c.poolEventCount, "poolLoading": c.poolLoading}


@tool("get_timeline",
      "The correlated incident clusters over the pool (or the case set): what Iris already grouped "
      "together, when, why, and the event ids in each cluster. The best starting point for 'build me a timeline'.",
      {"scope": {"type": "string", "enum": ["all", "case"]},
       "limit": {"type": "integer", "description": "clusters to return, 1-40 (default 20)"}})
def _get_timeline(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    scope = _scope(args)
    # A BOUNDED wait on the non-blocking accessor, not the blocking one: at 11.4 M events the
    # correlation pass is minutes of work and a blocking call parks the whole run inside step 1.
    a = _analysis(ctx, scope)
    limit = _int(args, "limit", 20, 1, 40)
    clusters = [{"id": c.id, "title": c.title, "start": c.start, "end": c.end, "span": c.span, "tag": c.tag,
                 "sev": c.sev, "count": c.count, "sources": c.sources, "why": _s(c.why, 300),
                 "eventIds": c.eventIds[:20]} for c in a["clusters"][:limit]]
    return {"stats": a["stats"], "clusters": clusters, "totalClusters": len(a["clusters"])}


@tool("list_detections",
      "Every detection rule that fired, with hit counts, first/last seen and sample event ids. "
      "Answers 'what did the detections catch' without searching.",
      {"sev": {"type": "string", "description": "comma-separated severities to keep"},
       "limit": {"type": "integer", "description": "rules to return, 1-50 (default 20)"}})
def _list_detections(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    # A screen can render "building, 42 %" and poll; an agent cannot, and handing it an empty list
    # while the aggregation is still building would have it report "no detections fired" — a false
    # statement about the evidence. That reasoning still holds, and it is why this waits rather than
    # returning `[]`. What changed is that the wait is BOUNDED: on an 11.4 M-event pool the blocking
    # accessor parked the whole run with no way to stop it. `_anomalies` waits, checks the stop flag
    # every 250 ms, and refuses with a message that says the roll-up is BUILDING, not empty.
    sev = {s.strip().lower() for s in (_s(args.get("sev"), 100) or "").split(",") if s.strip()}
    rows = [a for a in _anomalies(ctx) if not sev or a.sev in sev]
    limit = _int(args, "limit", 20, 1, MAX_ROWS)
    return {"total": len(rows),
            "detections": [{"ruleId": a.ruleId, "name": a.name, "sev": a.sev, "hits": a.hits,
                            "firstSeen": a.firstSeen, "lastSeen": a.lastSeen, "sources": a.sources,
                            "sampleEventIds": [e.id for e in a.sample]} for a in rows[:limit]]}


@tool("list_event_fields",
      "Field facets for a query: which parsed fields the matching events carry and their most common "
      "values. Use it to discover what field:value terms are worth searching before guessing.",
      {"query": {"type": "string", "description": "the same DSL query as search_events ('' = everything)"},
       "scope": {"type": "string", "enum": ["all", "case"]},
       "limit": {"type": "integer", "description": "fields to return, 1-40 (default 20)"}})
def _list_fields(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.events import list_fields
    validate_query(_s(args.get("query"), 2000))
    # every omitted parameter (from_/to/sources/sev) gets its REAL default here — see call_route
    res = call_route(list_fields, q=_s(args.get("query"), 2000), scope=_scope(args),
                     limit=_int(args, "limit", 20, 1, 40))
    return {"events": res["events"], "sampled": res["sampled"],
            "fields": [{"name": f["name"], "count": f["count"],
                        "topValues": f["topValues"][:6]} for f in res["fields"]]}


@tool("build_graph",
      "BUILD the entity graph for a chosen set of logs (or the case set) and return it: the entities, the "
      "typed relations between them, and what each is made of. This is the tool for 'map what is going "
      "on in these logs' — graph_find/graph_node answer questions about ONE entity, this one gives the "
      "picture. Restricting it to the sources you care about is the difference between a map and a "
      "hairball.",
      {"sources": {"type": "string",
                   "description": "comma-separated source ids (list_sources) — the logs to graph. Omit for the whole pool."},
       "scope": {"type": "string", "enum": ["all", "case"],
                 "description": "'case' graphs ONLY the events curated into the case timeline"},
       "types": {"type": "string", "description": "comma-separated entity types to keep"},
       "relations": {"type": "string",
                     "description": "comma-separated relations to keep (auth_from, connected_to, ran, spawned, "
                                    "wrote, read, deleted, resolved, requested, used_key, on_host, session, "
                                    "co_occurred). co_occurred is 'appeared in the same event' — noise on a busy "
                                    "log, and excluded unless you ask for it."},
       "minLinkEvents": {"type": "integer", "description": "drop relations supported by fewer than N events (default 1)"},
       "limit": {"type": "integer", "description": "max entities to return, 1-50 (default 30)"}})
def _build_graph(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..graph import RELATIONS
    store = _store()
    scope = _scope(args)
    gb = _graph(ctx, scope)             # bounded wait: never parks the run on a multi-minute build
    sids = [x.strip() for x in _s(args.get("sources"), 500).split(",") if x.strip()]
    files: Optional[set[str]] = None
    unknown: list[str] = []
    if sids:
        with store.lock:
            files = {store.sources[x].file for x in sids if x in store.sources}
            unknown = [x for x in sids if x not in store.sources]
        if not files:
            raise ToolError(f"none of those source ids exist: {', '.join(sids[:8])}. Call list_sources first.")
    tset = {t.strip() for t in _s(args.get("types"), 200).split(",") if t.strip()} or None
    rset = {r.strip() for r in _s(args.get("relations"), 300).split(",") if r.strip()} or None
    if rset:
        bad = sorted(rset - set(RELATIONS))
        if bad:
            raise ToolError(f"unknown relation(s): {', '.join(bad)}. Valid: {', '.join(RELATIONS)}")
    else:
        rset = {r for r in RELATIONS if r != "co_occurred"}
    limit = _int(args, "limit", 30, 1, MAX_ROWS)
    nodes, edges, stats = gb.select(types=tset, relations=rset,
                                    min_count=_int(args, "minLinkEvents", 1, 1, 10_000),
                                    limit=limit, in_case=set(store.case_set.keys()), files=files)
    # The summary blocks come FIRST and the long lists last, because investigator._clip truncates a tool
    # result from the END: with `totals`/`byType`/`byRelation` after the relations list, the default call
    # (22 kB against a 6 kB clip) lost precisely the counts that say what the graph contains. Relations
    # are capped to what survives that clip rather than to a number that merely looks generous.
    rel_cap = min(len(edges), MAX_ROWS)
    return {
        "scope": scope,
        "sources": sids,
        "unknownSources": unknown,
        "totals": {"entitiesShown": len(nodes), "entitiesTotal": stats.get("totalNodes", 0),
                   "relationsShown": rel_cap, "relationsTotal": stats.get("totalEdges", 0),
                   "truncated": bool(stats.get("truncated")) or rel_cap < len(edges)},
        "byType": stats.get("byType", {}),
        "byRelation": stats.get("byRelation", {}),
        "note": ("co_occurred (entities merely appearing in the same event) is excluded unless you ask for it"
                 if "co_occurred" not in rset else ""),
        "entities": [{"id": n.id, "type": n.type, "value": n.value, "events": n.count, "detections": n.detections,
                      "sev": n.sev, "first": n.first, "last": n.last, "inCase": n.inCase,
                      "facts": [{"k": k, "v": _s(v, 120)} for k, v in n.facts[:4]]} for n in nodes],
        "relations": [{"source": e.source, "relation": e.relation, "target": e.target, "events": e.count,
                       "first": e.first, "last": e.last, "outcome": e.outcome, "why": _s(e.why, 120),
                       "eventIds": e.eventIds[:3], "ai": bool(e.ai)} for e in edges[:rel_cap]],
    }


@tool("graph_sources",
      "Which log files the entity graph can be built from, with how many entities and relations each one "
      "actually contributes. Call it before build_graph: a package or proxy log has plenty of entities and "
      "no relations at all, and picking one of those is why a graph comes back with nothing to connect.",
      {"scope": {"type": "string", "enum": ["all", "case"]}})
def _graph_sources(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    gb = _graph(ctx, _scope(args))
    ent: dict[str, int] = {}
    for agg in gb.nodes.values():
        for f in agg.files:
            ent[f] = ent.get(f, 0) + 1
    rel: dict[str, int] = {}
    for ed in gb.edges.values():
        for f in ed.files:
            rel[f] = rel.get(f, 0) + 1
    with store.lock:
        rows = [{"sourceId": s.id, "file": s.file, "events": s.events,
                 "entities": ent.get(s.file, 0), "relations": rel.get(s.file, 0)}
                for s in store.sources.values()]
    rows.sort(key=lambda r: (-r["relations"], -r["entities"]))
    return {"total": len(rows), "sources": rows[:MAX_ROWS],
            "note": "a source with entities but no relations records things, not interactions between them"}


@tool("graph_find",
      "Find entity-graph nodes by substring. Node ids are '<type>:<value>' (e.g. 'ip:45.83.140.22', "
      "'user:svc_deploy'). Use it to get the exact node id before calling graph_node, graph_path or add_graph_link.",
      {"query": {"type": "string", "description": "substring of the node value or label"},
       "types": {"type": "string", "description": "comma-separated entity types to keep (ip,user,host,process,pid,file,hash,domain,url,port,email,key,session,pod,service,registry)"},
       "scope": {"type": "string", "enum": ["all", "case"]},
       "limit": {"type": "integer", "description": "nodes to return, 1-50 (default 20)"}},
      ["query"])
def _graph_find(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    gb = _graph(ctx, _scope(args))
    needle = _s(args.get("query"), 200).lower()
    tset = {t.strip() for t in _s(args.get("types"), 200).split(",") if t.strip()} or None
    limit = _int(args, "limit", 20, 1, MAX_ROWS)
    out: list[dict[str, Any]] = []
    for nid in gb.ranked_ids():
        agg = gb.nodes.get(nid)
        if agg is None:
            continue
        if tset and agg.type not in tset:
            continue
        if needle and needle not in agg.value.lower() and needle not in agg.label.lower():
            continue
        out.append({"id": nid, "type": agg.type, "label": agg.label, "count": agg.count,
                    "sev": agg.sev, "detections": agg.detections, "first": agg.first, "last": agg.last})
        if len(out) >= limit:
            break
    return {"nodes": out, "totalNodes": len(gb.nodes)}


@tool("graph_node",
      "Everything the entity graph knows about one node: its facts, its typed relations to other nodes "
      "(with counts, outcomes and a plain-English reason) and a sample of the events it appears in.",
      {"nodeId": {"type": "string", "description": "'<type>:<value>', e.g. 'ip:45.83.140.22'"},
       "scope": {"type": "string", "enum": ["all", "case"]}},
      ["nodeId"])
def _graph_node(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    gb = _graph(ctx, _scope(args))
    nid = _s(args.get("nodeId"), 300)
    # node_detail returns the node's own fields FLAT, plus `neighbours` (GraphEdge) and `timeline`
    d = gb.node_detail(nid, set(store.case_set.keys()))
    if d is None:
        raise ToolError(f"no graph node with id {nid!r}. Call graph_find first to get exact node ids.")
    return {"node": {k: v for k, v in d.items() if k not in ("neighbours", "timeline")},
            "neighbours": [{"source": e.source, "relation": e.relation, "target": e.target, "count": e.count,
                            "sev": e.sev, "outcome": e.outcome, "first": e.first, "last": e.last,
                            "why": _s(e.why, 200), "eventIds": e.eventIds[:5]} for e in d["neighbours"][:30]],
            "timeline": d["timeline"][-20:]}


PROFILE_BUCKETS = 16     # activity buckets an entity profile starts with
PROFILE_RAW = 300        # chars of raw log line per sample row in a profile
PROFILE_BUDGET = 5600    # bytes: must stay under investigator.TOOL_RESULT_CHARS or the tail is cut


def _fit_profile(out: dict[str, Any]) -> dict[str, Any]:
    """Shed detail until the profile fits ONE tool result — in a defined order, and say what went.

    A constant tuned to one corpus is not a budget: measured on the sample pool the profile ran from
    1.1 kB to 8.1 kB depending on how busy the entity is, and investigator._clip cuts from the END, so
    the busiest entities — the ones actually worth profiling — would silently lose their sample events
    and their graph relations. Shedding in a stated order keeps the ANSWER (counts, breakdown, window)
    and gives up the illustration, which is the right way round.
    """
    graph = out.get("graph") or {}

    def _trim_relations(cap: int) -> None:
        # ONLY when the block actually carries relations. Writing `relations: []` onto a graph block
        # that says the graph is not built would turn a declared omission into "this entity has no
        # relations" — the exact confusion the omission notice exists to prevent.
        if isinstance(graph.get("relations"), list):
            graph["relations"] = graph["relations"][:cap]

    return _shed(out, PROFILE_BUDGET, [
        ("shorter sample lines",
         lambda: [r.__setitem__("raw", str(r.get("raw", ""))[:120]) for r in out.get("sampleEvents") or []]),
        ("fewer graph relations", lambda: _trim_relations(8)),
        ("fewer activity buckets",
         lambda: (out.get("activity") or {}).__setitem__(
             "buckets", ((out.get("activity") or {}).get("buckets") or [])[:8])),
        # The coverage BLOCK can lose its per-source detail; its `note` and its two totals never go —
        # they are the statement that this answer covers the whole pool (or does not).
        ("fewer mention sources",
         lambda: (out.get("coverage") or {}).__setitem__(
             "mentionsBySource", ((out.get("coverage") or {}).get("mentionsBySource") or [])[:5])),
        ("shallower breakdown",
         lambda: [f.__setitem__("top", (f.get("top") or [])[:4]) for f in (out.get("breakdown") or {}).values()]),
        ("fewer sample events",
         lambda: out.__setitem__("sampleEvents", (out.get("sampleEvents") or [])[:2])),
        ("fewer graph relations again", lambda: _trim_relations(4)),
    ], "to keep this profile inside one tool result. The counts, the time window and the breakdown are "
       "complete and exact; only the illustrative detail was reduced. Use search_events with the "
       "`query` above for more.")


@tool("entity_profile",
      "EVERYTHING Iris knows about ONE entity — an IP, user, host, process, file, hash or domain — in a "
      "SINGLE call. This is the tool for 'tell me everything this IP is involved with', 'what has this "
      "user been doing', 'is this host implicated'. It returns the exact event count, the first and last "
      "time it was seen, the breakdown by source / host / user / severity / detection, an activity "
      "histogram, and a few representative log lines with ids ready to cite. It also returns the "
      "entity's typed graph relations WHEN the entity graph is already built; on a large workspace it "
      "will say `graph.available: false` and omit them rather than make you wait minutes for a build — "
      "that is a stated omission, never a claim that the entity has no relations. "
      "Answer from THIS, then drill into anything that looks wrong — do not rebuild it "
      "out of six separate calls. The `query` it returns (entity:\"<value>\") is the exact-match query "
      "for this entity's events; pass it to search_events / aggregate_events to go deeper. "
      "It also returns a `coverage` block: entity:\"…\" only matches sources that have been INTERPRETED, "
      "so on a workspace with raw sources it reports the free-text mention count over the whole pool as "
      "well, with the sources those mentions are in. Read it before making any claim about totals.",
      {"value": {"type": "string",
                 "description": "the entity value, e.g. '45.83.140.22' or 'svc_deploy'. A graph node id "
                                "('ip:45.83.140.22') is accepted too."},
       "scope": {"type": "string", "enum": ["all", "case"]},
       "from": {"type": "string", "description": "ISO-8601 UTC lower bound"},
       "to": {"type": "string", "description": "ISO-8601 UTC upper bound"},
       "sources": {"type": "string", "description": "comma-separated source ids to restrict to"},
       "sampleEvents": {"type": "integer", "description": "representative lines to return, 0-10 (default 5)"}},
      ["value"])
def _entity_profile(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    """The whole answer to "what is this entity involved with", composed from the existing services.

    Nothing here derives evidence of its own: the count and every breakdown come from the same
    `search.search` + `_aggregate` path aggregate_events uses, the relations come from the built entity
    graph, and the sample rows go through the same `_row` shape as search_events. It exists because the
    model was spending six or seven steps stapling those calls together — and, on a real run, ran out of
    budget before it had stapled them. One call, one search pass, one graph lookup.
    """
    from ..graph import GraphBuilder, NODE_TYPES
    store = _store()
    raw_value = _s(args.get("value"), 300).strip()
    if not raw_value:
        raise ToolError("value is required — the entity to profile, e.g. '45.83.140.22' or 'svc_deploy'.")
    # a graph node id ('ip:45.83.140.22') is a perfectly reasonable thing for the model to pass here,
    # since graph_find hands them out. Accept it rather than searching for the literal string.
    node_id, value = "", raw_value
    head, _, tail = raw_value.partition(":")
    if tail and head in NODE_TYPES:
        node_id, value = raw_value, tail

    scope = _scope(args)
    query = GraphBuilder.node_query(value)      # entity:"…" — the ONE query form that matches exactly
    res = _matching({**args, "query": query, "scope": scope})
    rows = res["rows"]

    facets: dict[str, Any] = {}
    for field in ("source", "host", "user", "sev", "detection"):
        groups, distinct, _missing = _aggregate(rows, field)
        if groups:
            facets[field] = {"distinct": distinct,
                             "top": [{"value": g["value"], "count": g["count"]} for g in groups[:8]]}

    # The graph half: typed relations to other entities, which no amount of searching produces.
    #
    # This is the ONE tool that must never wait for the graph. The prompt sends the model here FIRST for
    # any entity question, so a blocking `store.graph_v2()` made the common path run a full extraction:
    # measured on the analyst's 11.4 M-event pool the run sat at `steps: 0` for minutes, the Stop it
    # accepted in 100 ms had no effect, and the build's `STORE.lock` contention stalled enrichment and
    # `/api/library` at the same time. Everything above — the exact count, the window, the breakdown, the
    # histogram, the citable samples — comes from the search index and needs no graph at all.
    #
    # So: the NON-blocking accessor, which returns the graph when it is current and otherwise starts the
    # background build and answers None. When it answers None the relations block is OMITTED — and the
    # omission is DECLARED, loudly, with the build's own state. An undeclared omission is exactly the
    # silent-absence bug this project keeps fighting: "no relations" and "relations not computed yet"
    # are different facts about the evidence and must never be rendered the same way.
    graph: dict[str, Any] = {}
    try:
        gb = store.graph_v2_ready(scope)
        if gb is None:
            st = store.graph_status(scope) or {}
            graph = {"available": False, "state": st.get("state", "building"), "pct": st.get("pct", 0.0),
                     "omitted": "relations",
                     "why": (st.get("note") or
                             "the entity graph for this workspace is not built yet; a background build "
                             "has been started rather than making you wait for it"),
                     "note": ("RELATIONS ARE NOT INCLUDED IN THIS PROFILE and this does NOT mean the "
                              "entity has none — nothing has been computed about them yet. Everything "
                              "else here (the count, the window, the breakdown, the samples) is complete "
                              "and exact: it comes from the search index, not the graph. Answer from it. "
                              "If typed relations are essential, call graph_node/build_graph later in the "
                              "run, which waits for the build and reports its progress.")}
        else:
            nid = node_id if node_id in gb.nodes else next(
                (f"{t}:{value}" for t in NODE_TYPES if f"{t}:{value}" in gb.nodes), "")
            if nid:
                d = gb.node_detail(nid, set(store.case_set.keys()))
                if d is not None:
                    graph = {"available": True,
                             "nodeId": nid, "type": d.get("type"), "label": d.get("label"),
                             "sev": d.get("sev"), "inCase": bool(d.get("inCase")),
                             "facts": [{"k": k, "v": _s(v, 120)} for k, v in (d.get("facts") or [])[:6]],
                             "relations": [{"source": e.source, "relation": e.relation, "target": e.target,
                                            "events": e.count, "outcome": e.outcome, "first": e.first,
                                            "last": e.last, "why": _s(e.why, 140)}
                                           for e in (d.get("neighbours") or [])[:15]],
                             "totalRelations": len(d.get("neighbours") or [])}
    except Exception as exc:  # noqa: BLE001 — the counts are the answer; the graph is the bonus
        graph = {"available": False, "omitted": "relations",
                 "unavailable": f"{type(exc).__name__}: {exc}",
                 "note": "relations could not be read; the counts and samples above are unaffected"}

    # COVERAGE. `entity:"…"` matches EXTRACTED entities, and only an interpreted (phase 2) source has
    # any — so on a raw-first workspace this profile silently covered a subset of the pool. The bare
    # value as free text reaches every raw line, so both numbers are computed and BOTH are reported.
    # They answer different questions and neither is a correction of the other: the exact count is what
    # Iris knows this entity IS, the mention count is every line the string appears in (which also
    # matches 10.0.0.100 when you meant 10.0.0.1, and any line that merely quotes it).
    coverage: dict[str, Any] = {}
    try:
        raw_sources = _uninterpreted_sources()
        mention = _matching({**args, "query": f'"{value}"', "scope": scope})
        m_groups, _d, _m = _aggregate(mention["rows"], "source")
        coverage = {
            "exactEntityMatches": res["total"],
            "textMentions": mention["total"],
            "mentionsBySource": [{"value": g["value"], "count": g["count"]} for g in m_groups[:12]],
            "mentionQuery": f'"{value}"',
        }
        if raw_sources:
            coverage["uninterpretedSources"] = [
                {"file": r["file"], "events": r["events"], "state": r["state"]} for r in raw_sources[:12]]
            coverage["note"] = (
                f"{len(raw_sources)} source(s) in this workspace are NOT interpreted yet (phase 1: raw "
                f"lines only). They have no extracted entities and no parsed fields, so entity:\"…\" and "
                f"field:value CANNOT match them — free text can, and does: `textMentions` is the count "
                f"over the WHOLE pool. Use the mention query for coverage claims, read the lines with "
                f"search_events(query='\"{value}\"', include='raw') and cite those ids. Never report the "
                f"exact-entity count as the total for the workspace while sources are uninterpreted.")
        elif mention["total"] > res["total"]:
            coverage["note"] = (
                "every source is interpreted, so the exact count is complete for this entity; the extra "
                "mentions are lines that merely contain the string (a longer IP, a substring, a quoted "
                "reference). Prefer the exact count and cite mentions only when you have read them.")
    except Exception as exc:  # noqa: BLE001 — the profile is still the answer
        coverage = {"available": False, "why": f"{type(exc).__name__}: {exc}"}

    n = _int(args, "sampleEvents", 5, 0, 10)
    picked: list[Any] = []
    if n and rows:
        step = len(rows) / float(n)
        picked = [rows[min(len(rows) - 1, int(i * step))] for i in range(min(n, len(rows)))]

    out: dict[str, Any] = {
        "value": value, "scope": scope, "query": query, "total": res["total"],
        "queryNote": "entity:\"…\" matches this entity EXACTLY, unlike free text.",
        "coverage": coverage,
        "activity": _histogram(rows, "auto", PROFILE_BUCKETS),
        "breakdown": facets,
        "graph": graph or {"available": True, "relations": [], "totalRelations": 0,
                           "note": "the entity graph IS built and this value is not a node in it — the "
                                   "counts above still stand, they come from the search index"},
        "sampleEvents": [_row(r, {"raw"}, PROFILE_RAW, 0) for r in store.stamp_membership(picked)],
        **_cost(res)}
    if not res["total"]:
        mentions = int((coverage or {}).get("textMentions") or 0)
        if mentions:
            # The case the analyst hit: nothing extracted, thousands of lines. Absence of an EXTRACTED
            # entity is not absence of evidence, and reporting it as such would be the silent-omission bug.
            out["note"] = (
                f"no event carries {value!r} as an EXTRACTED entity — but {mentions:,} log line(s) contain "
                f"the string. Those sources are raw (not interpreted), which is why the extraction is "
                f"empty. This is NOT absence of evidence: answer from the mentions, read them with "
                f"search_events(query='\"{value}\"', include='raw') and cite those ids.")
        else:
            out["note"] = (f"no event in this workspace carries {value!r} as an extracted entity, and no log "
                           "line contains the string either — it is genuinely not in the ingested logs, "
                           "which is itself a finding.")
    return _fit_profile(out)


@tool("graph_path",
      "Shortest chain of typed relations between two entities — 'how does this IP reach that file?'. "
      "Use it to prove or disprove a pivot before claiming one.",
      {"from": {"type": "string", "description": "start node id"},
       "to": {"type": "string", "description": "end node id"},
       "maxHops": {"type": "integer", "description": "1-8 (default 4)"},
       "scope": {"type": "string", "enum": ["all", "case"]}},
      ["from", "to"])
def _graph_path(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    gb = _graph(ctx, _scope(args))
    a, b = _s(args.get("from"), 300), _s(args.get("to"), 300)
    nodes, edges = gb.shortest_path(a, b, _int(args, "maxHops", 4, 1, 8))
    return {"found": bool(nodes), "path": [n.id for n in nodes],
            "edges": [{"source": e.source, "relation": e.relation, "target": e.target, "count": e.count,
                       "why": _s(e.why, 200)} for e in edges]}


@tool("list_iocs",
      "Indicators of compromise already known: extracted from detection-bearing events plus any recorded "
      "by hand or by a previous run, each with first/last seen and the events it was seen in.",
      {"scope": {"type": "string", "enum": ["all", "case"]},
       "limit": {"type": "integer", "description": "1-50 (default 30)"}})
def _list_iocs(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.iocs import _all_iocs
    out = _all_iocs(_scope(args))[: _int(args, "limit", 30, 1, MAX_ROWS)]
    return {"total": len(out),
            "iocs": [{"id": i.id, "kind": i.kind, "value": i.value, "count": i.count, "manual": i.manual,
                      "addedBy": i.addedBy, "firstSeen": i.firstSeen, "lastSeen": i.lastSeen,
                      "files": i.files[:5], "eventIds": [h.eventId for h in i.hits]} for i in out]}


@tool("list_notes",
      "The analyst's case notes, oldest first, with their authors — including notes written by earlier AI runs.",
      {"limit": {"type": "integer", "description": "1-50 (default 20)"}})
def _list_notes(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    with store.lock:
        notes = list(store.notes)
    notes = notes[-_int(args, "limit", 20, 1, MAX_ROWS):]
    return {"total": len(notes),
            "notes": [{"id": n.id, "author": n.author, "createdAt": n.createdAt, "text": _s(n.text, 1000),
                       "refs": [{"kind": r.kind, "value": r.value} for r in n.refs]} for n in notes]}


@tool("get_case_state",
      "The current workspace: whether a case exists at all, its id/name/summary, how many events are in "
      "the pool, how many are curated into the case set, and the labels in use. Call this first.",
      {})
def _get_case_state(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    c = store.case()
    return {"hasCase": not c.pending, "caseId": c.id, "name": c.name, "summary": getattr(store, "summary", ""),
            "analyst": c.analyst, "poolEventCount": c.poolEventCount, "caseEventCount": c.eventCount,
            "caseSetSize": len(c.caseSet), "labels": store.case_labels(), "notes": len(c.notes),
            "sources": len(c.sources), "librarySources": len(c.librarySources),
            "poolLoading": c.poolLoading}


# ================================================================= WRITE tools
def _ai_author(ctx: RunContext) -> str:
    return f"AI assistant ({ctx.model})" if ctx.model else "AI assistant"


@tool("create_case",
      "Create a NEW case and make it active. Only call this when the analyst asked for a case to be built "
      "and none exists (get_case_state.hasCase is false) — it is never a side effect of anything else.",
      {"name": {"type": "string", "description": "short descriptive case name"},
       "summary": {"type": "string", "description": "one-paragraph summary of what is being investigated"}},
      ["name"], writes=True)
def _create_case(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from .. import cases
    _budget(ctx)
    store = _store()
    name = _s(args.get("name"), 200).strip()
    if not name:
        raise ToolError("a case needs a name")
    if not store.pending:
        raise ToolError(f"case {store.case_id} ('{store.name}') is already active — use update_case to rename it, "
                        "or add evidence to it with add_events_to_case.")
    summary = cases.create_case(name, None)
    if args.get("summary"):
        store.summary = _prose(args.get("summary"), 4000)
        store.save_meta()
    action = ctx.record("create_case", f"created case {summary.id} '{name}'",
                        {"kind": "case", "caseId": summary.id})
    return {"ok": True, "caseId": summary.id, "name": summary.name, "action": action}


@tool("update_case",
      "Set the active case's name and/or summary. The summary is the case's own description, shown with "
      "the case and included in the report.",
      {"name": {"type": "string"}, "summary": {"type": "string"}},
      [], writes=True)
def _update_case(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    _budget(ctx)
    _require_case("the case name/summary")
    store = _store()
    before = {"name": store.name, "summary": getattr(store, "summary", "")}
    changed = []
    if args.get("name"):
        store.name = _s(args.get("name"), 200).strip()
        changed.append("name")
    if args.get("summary") is not None:
        store.summary = _prose(args.get("summary"), 4000)
        changed.append("summary")
    if not changed:
        raise ToolError("nothing to change — pass name and/or summary")
    store.save_meta()
    action = ctx.record("update_case", f"set case {'/'.join(changed)}",
                        {"kind": "case_meta", "before": before})
    return {"ok": True, "name": store.name, "summary": getattr(store, "summary", ""), "action": action}


@tool("add_events_to_case",
      "Add events to the CASE SET — the curated evidence that defines the case. Every id must be a real "
      "event id you have seen in a tool result; unknown ids abort the whole call. Label them so the "
      "analyst can see why each one is there.",
      {"eventIds": {"type": "array", "items": {"type": "string"}, "description": "event ids, max 50 per call"},
       "labels": {"type": "array", "items": {"type": "string"}, "description": "short labels, e.g. ['initial access']"},
       "note": {"type": "string", "description": "why these events are evidence"}},
      ["eventIds"], writes=True)
def _add_events_to_case(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    _budget(ctx)
    _require_case("case-set membership")
    ids = _ids(args, "eventIds")
    if not ids:
        raise ToolError("eventIds is empty")
    _check_citations(ids, "these events into the case set")
    store = _store()
    labels = [_s(l, 60) for l in (args.get("labels") or []) if str(l).strip()][:8] or ["ai"]
    if "ai" not in labels:
        labels = labels + ["ai"]     # provenance: the label survives in case.json
    note = _prose(args.get("note"), 600)
    entries = store.add_many_to_case(ids, labels, note or None)
    added = [e.eventId for e in entries]
    action = ctx.record("add_events_to_case", f"added {len(added)} event(s) to the case set",
                        {"kind": "case_set", "eventIds": added})
    return {"ok": True, "added": len(added), "eventIds": added, "labels": labels, "action": action}


@tool("remove_events_from_case",
      "Take events back out of the case set (an undo for an add you now believe is noise).",
      {"eventIds": {"type": "array", "items": {"type": "string"}}},
      ["eventIds"], writes=True)
def _remove_events_from_case(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    _budget(ctx)
    _require_case("case-set membership")
    ids = _ids(args, "eventIds")
    if not ids:
        raise ToolError("eventIds is empty")
    store = _store()
    present = [i for i in ids if i in store.case_set]
    removed = store.remove_many_from_case(present)
    action = ctx.record("remove_events_from_case", f"removed {removed} event(s) from the case set",
                        {"kind": "case_set_removed", "eventIds": present})
    return {"ok": True, "removed": removed, "action": action}


@tool("add_ioc",
      "Record an indicator of compromise on the case. Cite the event ids it came from: they become the "
      "indicator's timeline, which is how the analyst answers 'when did we first see this'. Unknown "
      "event ids abort the call.",
      {"kind": {"type": "string", "description": "ipv4, domain, url, file-path, file-hash, email, user-agent, aws-access-key, dst-endpoint, other"},
       "value": {"type": "string", "description": "the indicator itself, verbatim"},
       "note": {"type": "string", "description": "why it is an indicator — one sentence"},
       "citedEventIds": {"type": "array", "items": {"type": "string"}, "description": "the events this indicator was observed in"}},
      ["kind", "value", "citedEventIds"], writes=True)
def _add_ioc(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.iocs import _all_iocs, _ioc_id
    _budget(ctx)
    _require_case("an indicator")
    value = _s(args.get("value"), 500).strip()
    if not value:
        raise ToolError("value is required")
    kind = (_s(args.get("kind"), 60).strip().lower() or "other")
    # The note is where a model that forgets the parameter usually writes the ids ("seen in `l6e2…`").
    cited = _cited(args, _s(args.get("note"), 600), f"the indicator {value!r}",
                   "an indicator is only actionable if the analyst can open the log line it came from")
    iid = _ioc_id(kind, value)
    store = _store()
    with store.lock:
        if any(_ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) == iid for m in store.manual_iocs):
            raise ToolError(f"{value} is already tracked on this case")
        store.manual_iocs.append({"kind": kind, "value": value, "note": _prose(args.get("note"), 600),
                                  "addedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                  "addedBy": "ai", "runId": ctx.run_id,
                                  "citedEventIds": cited})
    store.save_meta()
    ioc = next((i for i in _all_iocs("all") if i.id == iid), None)
    action = ctx.record("add_ioc", f"recorded indicator {kind}:{value}", {"kind": "ioc", "iocId": iid})
    return {"ok": True, "ioc": {"id": iid, "kind": kind, "value": value,
                                "count": ioc.count if ioc else 0,
                                "firstSeen": ioc.firstSeen if ioc else None,
                                "lastSeen": ioc.lastSeen if ioc else None},
            "citedEventIds": cited, "action": action}


@tool("add_note",
      "Write a note into the case file: your reasoning, a finding, or the timeline you reconstructed. "
      "Cite the event ids behind it — they are attached to the note as clickable references and are "
      "verified before the note is saved. It is stored under your name, not the analyst's.",
      {"text": {"type": "string", "description": "the note, Markdown allowed"},
       "citedEventIds": {"type": "array", "items": {"type": "string"}, "description": "events this note is based on"},
       "searchRefs": {"type": "array", "items": {"type": "string"}, "description": "optional saved queries to attach"}},
      ["text", "citedEventIds"], writes=True)
def _add_note(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from .. import cases
    from ..models import NoteRef
    _budget(ctx)
    _require_case("a note")
    text = _prose(args.get("text"), 12000).strip()
    if not text:
        raise ToolError("text is required")
    cited = _cited(args, text, "a note",
                   "one id per claim is enough, and they become the note's clickable references")
    refs = [NoteRef(kind="event", value=i, label=i) for i in cited]
    for q in (args.get("searchRefs") or [])[:5]:
        if str(q).strip():
            refs.append(NoteRef(kind="search", value=_s(q, 300), label=_s(q, 60)))
    store = _store()
    note = cases.add_note(store.case_id, text, refs, author=_ai_author(ctx))
    action = ctx.record("add_note", f"wrote a case note ({len(cited)} citation(s))",
                        {"kind": "note", "noteId": note.id, "caseId": store.case_id})
    return {"ok": True, "noteId": note.id, "author": note.author, "citedEventIds": cited, "action": action}


# The node id the agent writes: "<type>:<value>". An authored node is not evidence — it is a
# CONCLUSION about evidence — so it is stored on the case, drawn distinctly, and carries the ids it was
# drawn from. It exists because a raw-first workspace extracts NOTHING: `add_graph_link` could refuse
# every endpoint it was ever given ("not a node in the graph"), so the investigation graph the analyst
# asked for could not be drawn at all.
def _node_spec(raw: str, what: str) -> tuple[str, str, str]:
    """('ip:10.0.0.5', 'ip', '10.0.0.5') — or a ToolError naming the shape and the types."""
    from ..graph import NODE_TYPES

    text = _s(raw, 300).strip()
    kind, _, value = text.partition(":")
    kind, value = kind.strip().lower(), value.strip()
    if not value:
        raise ToolError(
            f"{what} must be a node id of the form <type>:<value>, e.g. ip:45.83.140.22 or "
            f"user:svc_deploy. Types: {', '.join(sorted(NODE_TYPES))}. (Got {text!r}.)")
    if kind not in NODE_TYPES:
        raise ToolError(f"{kind!r} is not an entity type. Use one of: {', '.join(sorted(NODE_TYPES))}.")
    return f"{kind}:{value}", kind, value


def _ensure_node(store: Any, gb: Any, nid: str, kind: str, value: str, ctx: RunContext,
                 why: str, cited: list[str]) -> bool:
    """Put an AUTHORED node on the case graph if nothing already provides it. True when it was created."""
    if gb is not None and nid in gb.nodes:
        return False                      # extraction found it; the real node wins, with its real counts
    if any(str(n.get("id")) == nid for n in store.graph_nodes):
        return False
    store.graph_nodes.append({"id": nid, "type": kind, "value": value, "label": value,
                              "why": _prose(why, 300), "ai": True, "runId": ctx.run_id,
                              "citedEventIds": list(cited)[:MAX_CITED],
                              "createdAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")})
    return True


def _write_link(args: dict[str, Any], ctx: RunContext, gb: Any) -> dict[str, Any]:
    """One link, plus any node it needs. Shared by add_graph_link and build_case_graph."""
    from ..graph import RELATIONS

    store = _store()
    s_id, s_kind, s_val = _node_spec(args.get("source"), "source")
    t_id, t_kind, t_val = _node_spec(args.get("target"), "target")
    rel = _s(args.get("relation"), 60).strip() or "co_occurred"
    if s_id == t_id:
        raise ToolError("a link needs two different nodes")
    if rel not in RELATIONS:
        raise ToolError(f"relation must be one of: {', '.join(RELATIONS)}")
    why = _prose(args.get("why"), 600)
    cited = _ids(args, "citedEventIds")
    if cited:
        _check_citations(cited, "this graph link")
    elif not why.strip():
        raise ToolError("say why this link exists (`why`), and cite the events it came from "
                        "(`citedEventIds`) — a connection nobody can check is not a finding")
    if gb is not None and ((s_id, t_id, rel) in gb.edges or (t_id, s_id, rel) in gb.edges):
        raise ToolError(f"the extractor already drew {s_id} -{rel}-> {t_id} — draw one it MISSED")
    lid = f"{s_id}|{rel}|{t_id}"
    try:
        conf = max(0.0, min(1.0, float(args.get("confidence", 0.6))))
    except (TypeError, ValueError):
        conf = 0.6
    created: list[str] = []
    with store.lock:
        if any(l.get("id") == lid for l in store.graph_links):
            raise ToolError(f"that link already exists: {lid}")
        for nid, kind, val in ((s_id, s_kind, s_val), (t_id, t_kind, t_val)):
            if _ensure_node(store, gb, nid, kind, val, ctx, why, cited):
                created.append(nid)
        store.graph_links.append({"id": lid, "source": s_id, "target": t_id, "relation": rel,
                                  "why": why, "confidence": conf, "ai": True,
                                  "runId": ctx.run_id, "citedEventIds": cited,
                                  "createdAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")})
    store.save_meta()
    return {"linkId": lid, "source": s_id, "target": t_id, "relation": rel, "confidence": conf,
            "createdNodes": created, "citedEventIds": cited}


@tool("add_graph_link",
      "Draw ONE connection on the case's entity graph that the extractor could not see — a pivot implied "
      "by timing, an alias, a chain across log sources. Node ids are `<type>:<value>` (ip:45.83.140.22, "
      "user:svc_deploy, host:web-1, domain:…, file:…, hash:…, process:…); an end that is not already in "
      "the extracted graph is CREATED on the case, which is how a graph gets drawn on a workspace whose "
      "sources are still raw. Building several links at once? Use build_case_graph instead. "
      "The link is saved as AI-authored, shown dashed to the analyst, and is reversible.",
      {"source": {"type": "string", "description": "node id"},
       "target": {"type": "string", "description": "node id"},
       "relation": {"type": "string", "description": "auth_from, connected_to, ran, spawned, wrote, read, deleted, resolved, requested, used_key, on_host, session, co_occurred"},
       "why": {"type": "string", "description": "the evidence for this link, citing timestamps/event ids"},
       "confidence": {"type": "number", "description": "0-1"},
       "citedEventIds": {"type": "array", "items": {"type": "string"}, "description": "events supporting the link"}},
      ["source", "target", "relation", "why"], writes=True)
def _add_graph_link(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    _budget(ctx)
    _require_case("a graph link")
    out = _write_link(args, ctx, _graph_or_none(ctx))
    action = ctx.record("add_graph_link",
                        f"linked {out['source']} -{out['relation']}-> {out['target']}",
                        {"kind": "graph_link", "linkId": out["linkId"],
                         "createdNodes": out["createdNodes"]})
    return {"ok": True, **out, "action": action}


def _graph_or_none(ctx: RunContext) -> Any:
    """The extracted graph if it is ALREADY built, else None — never a build.

    A write must not park the run behind a 55-190 s extraction, and on a raw workspace there is nothing
    to extract anyway. Without it the check "did the extractor already draw this?" is skipped, which
    can only mean an authored duplicate of a relation the graph already had — visible, dashed and
    removable, and a far better outcome than an investigation that cannot draw its own conclusions.
    """
    try:
        return _store().graph_v2_ready("all")
    except Exception:  # noqa: BLE001
        return None


def _as_link(item: Any) -> Optional[dict[str, Any]]:
    """One link, from an object OR from a pipe-separated line.

    The object form is the schema. The STRING form exists because a nested array-of-objects is the
    hardest thing for a small local model to emit, and getting it wrong is not a graceful failure: the
    analyst's gateway answered HTTP 500 "Failed to parse tool call arguments as JSON … column 315" and
    took the whole turn with it. Accepting

        ip:10.0.0.101 | connected_to | ip:66.218.84.137 | 40 proxy records | l6e2c94f9,l6e2c94fa

    costs nothing, is impossible to get syntactically wrong, and produces exactly the same link. Both
    forms go through the same validation, citation check and refusal path — this only widens what the
    model may TYPE, never what it may assert.
    """
    if isinstance(item, dict):
        return item
    if not isinstance(item, str) or not item.strip():
        return None
    parts = [p.strip() for p in item.split("|")]
    if len(parts) < 3:
        parts = [p.strip() for p in item.split("->")]      # a second shape people write by hand
        if len(parts) < 3:
            return None
    out: dict[str, Any] = {"source": parts[0], "relation": parts[1], "target": parts[2]}
    if len(parts) > 3:
        out["why"] = parts[3]
    if len(parts) > 4:
        out["citedEventIds"] = [x.strip() for x in parts[4].replace(";", ",").split(",") if x.strip()]
    return out


@tool("build_case_graph",
      "BUILD THE INVESTIGATION GRAPH — the picture of how the things you found connect, drawn in ONE "
      "call. Pass every link you want: each is {source, target, relation, why, citedEventIds, "
      "confidence} with node ids `<type>:<value>` (ip:45.83.140.22, user:svc_deploy, host:web-1, "
      "domain:cdn.example.com, file:/tmp/x, hash:…, process:…, port:443). Ends that extraction never "
      "found are CREATED on the case — so this works on a workspace whose sources are still raw, where "
      "there is no extracted graph at all. This is the tool for 'connect what you found', 'build me a "
      "graph of this'. Everything it draws is attributed to you, dashed on screen, and reversible; "
      "build_graph (read) is the extractor's own graph, which this one adds to rather than replaces.",
      {"links": {"type": "array",
                 "description": "the links to draw. Each item may instead be a single string, "
                                "'<type>:<value> | relation | <type>:<value> | why | eventIds' — use "
                                "that if nested objects are awkward for you; it is validated identically",
                 "items": {"type": "object", "properties": {
                     "source": {"type": "string", "description": "node id, <type>:<value>"},
                     "target": {"type": "string", "description": "node id, <type>:<value>"},
                     "relation": {"type": "string", "description": "auth_from, connected_to, ran, spawned, wrote, read, deleted, resolved, requested, used_key, on_host, session, co_occurred"},
                     "why": {"type": "string", "description": "the evidence for this link"},
                     "confidence": {"type": "number"},
                     "citedEventIds": {"type": "array", "items": {"type": "string"}}}}}},
      ["links"], writes=True)
def _build_case_graph(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    """Many links, ONE call, one save — and one action, so the whole picture reverts together.

    Per-item, not all-or-nothing: a run that drew nine good links and one with a bad citation should
    keep the nine and be told exactly what was wrong with the tenth. Each refusal names its link, so the
    model can fix that one instead of re-sending the set (which would then collide with itself).
    """
    _budget(ctx)
    _require_case("a graph")
    raw = args.get("links")
    if isinstance(raw, str):
        raw = [line for line in raw.splitlines() if line.strip()]
    if not isinstance(raw, list) or not raw:
        raise ToolError("links must be a non-empty array of {source, target, relation, why, "
                        "citedEventIds} objects — or, if that is awkward, one string per link: "
                        "'ip:10.0.0.5 | connected_to | ip:45.83.140.22 | why | e12,e13'")
    if len(raw) > MAX_GRAPH_LINKS:
        raise ToolError(f"at most {MAX_GRAPH_LINKS} links in one call; you sent {len(raw)}")
    gb = _graph_or_none(ctx)
    drawn: list[dict[str, Any]] = []
    created: list[str] = []
    refused: list[dict[str, str]] = []
    for i, item in enumerate(raw):
        parsed = _as_link(item)
        if parsed is None:
            refused.append({"link": f"#{i + 1}",
                            "why": "each link must be an object, or a line "
                                   "'<type>:<value> | relation | <type>:<value> | why | ids'"})
            continue
        try:
            out = _write_link(parsed, ctx, gb)
        except ToolError as exc:
            refused.append({"link": f"{parsed.get('source')} -> {parsed.get('target')}", "why": str(exc)})
            continue
        drawn.append(out)
        created.extend(out["createdNodes"])
    if not drawn:
        raise ToolError("no link could be drawn: " + "; ".join(f"{r['link']}: {r['why']}" for r in refused[:6]))
    action = ctx.record("build_case_graph",
                        f"drew {len(drawn)} link(s) and {len(created)} new node(s) on the case graph",
                        {"kind": "graph_batch", "linkIds": [d["linkId"] for d in drawn],
                         "createdNodes": created})
    res: dict[str, Any] = {"ok": True, "drawn": len(drawn), "links": drawn,
                           "createdNodes": created, "action": action,
                           "note": "the analyst sees these dashed on the Graph screen with scope=case; "
                                   "they are attributed to you and revert together"}
    if refused:
        res["refused"] = refused
        res["refusedNote"] = ("these links were NOT drawn — fix and re-send only these, the rest are "
                              "already saved")
    return res


# ============================================================ DETECTION RULES
# The agent may now tune the detection catalogue, because "this rule is too noisy / we are missing this
# pattern" is a normal outcome of an investigation. It does so through the SAME validated path the rules
# screen uses — routers.rules → RULES_STORE — so every existing guarantee still holds: detect.parse_param
# validation, the save-time ReDoS screen, the RULES_STORE.rev bump the anomaly cache keys on, and
# STORE.reapply_rule so the detections on the pool match the catalogue. There is deliberately NO tool for
# `POST /api/rules/clear` or restore-defaults: wiping the built-in catalogue is not an investigative act.
def _rule_input(args: dict[str, Any], base: Optional[Any] = None) -> Any:
    """Build the SAME RuleInput the rules screen posts. `base` supplies the values the caller omitted."""
    from ..models import RuleFlags, RuleInput, RuleThreshold
    b = base
    conds = args.get("conditions")
    if conds is None and b is not None:
        conds = [c.model_dump() for c in (b.conditions or [])] or None
    th = args.get("threshold")
    if th is None and b is not None and b.threshold is not None:
        th = b.threshold.model_dump()
    sev = _s(args.get("sev"), 20).strip().lower() or (b.sev if b else "medium")
    if sev not in ("critical", "high", "medium", "low", "info"):
        raise ToolError("sev must be one of critical, high, medium, low, info")
    flags = args.get("flags")
    if flags is None:
        flags = (b.flags.model_dump() if (b is not None and b.flags) else {"ignoreCase": True, "multiline": False})
    try:
        return RuleInput(
            name=_s(args.get("name"), 120).strip() or (b.name if b else ""),
            description=_s(args.get("description"), 1000) if args.get("description") is not None
            else (b.description if b else ""),
            sev=sev,  # type: ignore[arg-type]
            enabled=bool(args.get("enabled", b.enabled if b else True)),
            kind="conditions" if conds else "regex",
            pattern=(_s(args.get("pattern"), 2000) if args.get("pattern") is not None
                     else (b.pattern if b else "")),
            field=_s(args.get("field"), 60).strip() or (b.field if b else "any") or "any",
            flags=RuleFlags(**flags) if isinstance(flags, dict) else None,
            sourceFilter=_s(args.get("sourceFilter"), 200) if args.get("sourceFilter") is not None
            else ((b.sourceFilter if b else "") or ""),
            conditions=conds,
            combinator=_s(args.get("combinator"), 8).strip().lower() or (b.combinator if b else "and"),  # type: ignore[arg-type]
            threshold=RuleThreshold(**th) if isinstance(th, dict) else None,
            tags=[_s(t, 40) for t in (args.get("tags") or (list(b.tags) if b else []))][:8],
            # provenance, exactly like IOC.addedBy='ai' and note author "AI assistant (<model>)"
            createdBy="ai")
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 — a pydantic complaint must reach the model as a tool error
        raise ToolError(f"that rule definition is not valid: {exc}")


def _rule_snapshot(r: Any) -> dict[str, Any]:
    """The fields needed to re-create/restore this rule through the validated path."""
    return {"name": r.name, "description": r.description, "sev": r.sev, "enabled": r.enabled,
            "pattern": r.pattern or "", "field": r.field or "any",
            "flags": r.flags.model_dump() if r.flags else None,
            "sourceFilter": r.sourceFilter or "",
            "conditions": [c.model_dump() for c in (r.conditions or [])] or None,
            "combinator": r.combinator,
            "threshold": r.threshold.model_dump() if r.threshold else None,
            "tags": list(r.tags),
            "params": {p.key: p.value for p in (r.params or []) if p.value != p.default}}


def _rule_row(r: Any) -> dict[str, Any]:
    return {"id": r.id, "name": r.name, "sev": r.sev, "enabled": r.enabled, "builtin": r.builtin,
            "kind": r.kind, "hits": r.hits, "trigger": _s(r.logic, 400), "mechanism": r.mechanism,
            "description": _s(r.description, 400), "error": r.error, "createdBy": r.createdBy,
            "params": [{"key": p.key, "label": p.label, "kind": p.kind, "value": p.value,
                        "default": p.default} for p in (r.params or [])]}


def _reapply(rule_id: str) -> dict[str, Any]:
    """Re-run one rule over the pool and SAY WHAT IT COST.

    Re-running detections is O(pool) — about ten seconds at 1.2 M events, and a built-in change re-runs
    the whole built-in pass because the windowed rules depend on each other. It happens on a worker
    thread (investigator runs every handler through asyncio.to_thread) so the API stays responsive, but
    the run pays for it in wall clock, so the cost goes back to the model and into the transcript.
    """
    from ..store import STORE
    t0 = datetime.now(UTC)
    hits = STORE.reapply_rule(rule_id)
    ms = int((datetime.now(UTC) - t0).total_seconds() * 1000)
    with STORE.lock:
        pool = len(STORE.events)
    return {"hits": hits, "reapplyMs": ms, "poolEvents": pool}


def _get_rule(rule_id: str) -> Any:
    from ..rules import RULES_STORE
    r = RULES_STORE.get(rule_id)
    if r is None:
        raise ToolError(f"no rule with id {rule_id!r}. Call list_detection_rules to get exact ids.")
    return r


@tool("list_detection_rules",
      "The detection catalogue: built-in Sigma-like rules and any custom rules, with what each one "
      "actually triggers on, its editable parameters and how many events it has hit. Read this before "
      "proposing a change — a rule that already exists should be tuned, not duplicated.",
      {"query": {"type": "string", "description": "substring of the id, name or description"},
       "builtin": {"type": "string", "enum": ["all", "builtin", "custom"], "description": "default all"},
       "limit": {"type": "integer", "description": "1-60 (default 30)"}})
def _list_detection_rules(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.rules import list_rules
    rules = call_route(list_rules, includeRemoved=False)
    which = _s(args.get("builtin"), 20).strip().lower() or "all"
    needle = _s(args.get("query"), 200).lower()
    out = []
    for r in rules:
        if which == "builtin" and not r.builtin:
            continue
        if which == "custom" and r.builtin:
            continue
        if needle and needle not in r.id.lower() and needle not in r.name.lower() \
                and needle not in (r.description or "").lower():
            continue
        out.append(_rule_row(r))
    limit = _int(args, "limit", 30, 1, 60)
    return {"total": len(out), "rules": out[:limit]}


@tool("create_detection_rule",
      "Create a CUSTOM detection rule so future ingests flag this pattern automatically. Either a regex "
      "(`pattern`, with `field` = any|msg|raw|host|user|source|file) or a list of typed `conditions` "
      "[{field, op, value}] with an optional `threshold` {count, window, groupBy} for burst detection. "
      "The regex is screened for catastrophic backtracking and rejected if it is unsafe. Saving re-runs "
      "the rule over the whole pool, which costs roughly a second per 100k events — the result reports it.",
      {"name": {"type": "string"}, "description": {"type": "string", "description": "what a hit MEANS (prose; it matches nothing)"},
       "sev": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
       "pattern": {"type": "string", "description": "regular expression (regex rules)"},
       "field": {"type": "string", "description": "any|msg|raw|host|user|source|file (default any)"},
       "sourceFilter": {"type": "string", "description": "only events whose source/file contains this"},
       "conditions": {"type": "array", "description": "typed conditions [{field, op, value}]",
                      "items": {"type": "object", "properties": {"field": {"type": "string"},
                                                                 "op": {"type": "string"},
                                                                 "value": {"type": "string"}}}},
       "combinator": {"type": "string", "enum": ["and", "or"]},
       "threshold": {"type": "object", "description": "{count, window (seconds), groupBy}",
                     "properties": {"count": {"type": "integer"}, "window": {"type": "integer"},
                                    "groupBy": {"type": "string"}}},
       "tags": {"type": "array", "items": {"type": "string"}},
       "enabled": {"type": "boolean"}},
      ["name"], writes=True)
def _create_detection_rule(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from fastapi import HTTPException
    from ..routers.rules import create_rule
    _budget(ctx)
    if not _s(args.get("name"), 120).strip():
        raise ToolError("a rule needs a name")
    if not _s(args.get("pattern"), 2000).strip() and not (args.get("conditions") or []):
        raise ToolError("a custom rule needs either a `pattern` (regex) or at least one entry in `conditions`")
    body = _rule_input(args)
    try:
        r = call_route(create_rule, body=body)
    except HTTPException as exc:
        raise ToolError(f"the rule was rejected: {exc.detail}")
    cost = _reapply(r.id)
    action = ctx.record("create_detection_rule",
                        f"created detection rule {r.id} '{r.name}' ({cost['hits']} hit(s), {cost['reapplyMs']} ms)",
                        {"kind": "rule_created", "ruleId": r.id})
    return {"ok": True, "rule": _rule_row(r), **cost, "action": action}


# ============================================================ EXCLUSIONS
# "This rule keeps reporting the same benign thing" is a normal outcome of an investigation, and the fix
# is a suppression rather than a disabled rule — switching a rule off loses everything it would have
# caught, while an exclusion loses only the thing that was judged. The agent gets the same three verbs
# the screen has, through the same validated router, and every write is undoable with the run.
@tool("list_exclusions",
      "The exclusions in force: what each one suppresses, which rules it is scoped to, and how many "
      "detections it actually removed on the last pass. Call this before concluding that a rule did not "
      "fire — a suppression is the other reason a detection is missing, and the ready-made suggestions "
      "Iris offers (public resolvers, machine accounts, health checks) are listed too.",
      {})
def _list_exclusions(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.exclusions import list_exclusions
    res = call_route(list_exclusions)
    rows = [{"id": x.id, "name": x.name, "enabled": x.enabled,
             "conditions": [f"{c.field} {c.op} {c.value}".strip() for c in x.conditions],
             "combinator": x.combinator,
             "scope": x.ruleIds or "every rule", "suppressed": x.suppressed,
             "appliesToGraph": x.appliesToGraph, "why": x.note}
            for x in res.exclusions]
    return {"total": len(rows), "suppressedTotal": res.suppressed, "exclusions": rows,
            "suggested": [{"name": s.name, "why": s.why,
                           "conditions": [f"{c.field} {c.op} {c.value}".strip() for c in s.conditions]}
                          for s in res.suggestions]}


@tool("add_exclusion",
      "Suppress a rule on evidence that has already been judged benign — a public resolver, a monitoring "
      "probe, a machine account. It stops the DETECTION, never the event: the line stays in the pool, in "
      "search and on the timeline. Scope it with `ruleIds` unless the thing really is uninteresting to "
      "every rule; 'this address is never interesting' and 'not interesting for THIS rule' are different "
      "claims and the second is usually what is meant. Say WHY in `note` — an unexplained suppression is "
      "indistinguishable from missing evidence to whoever reads the case next.",
      {"name": {"type": "string"},
       "conditions": {"type": "array", "description": "typed conditions [{field, op, value}] — same "
                                                      "vocabulary as create_detection_rule",
                      "items": {"type": "object", "properties": {"field": {"type": "string"},
                                                                 "op": {"type": "string"},
                                                                 "value": {"type": "string"}}}},
       "combinator": {"type": "string", "enum": ["and", "or"]},
       "ruleIds": {"type": "array", "items": {"type": "string"},
                   "description": "rule ids this applies to; omit for every rule"},
       "note": {"type": "string", "description": "why this is benign"}},
      ["name", "conditions"], writes=True)
def _add_exclusion(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from fastapi import HTTPException
    from ..models import ExclusionInput, RuleCondition
    from ..routers.exclusions import create_exclusion
    _budget(ctx)
    rows = args.get("conditions") or []
    if not isinstance(rows, list) or not rows:
        raise ToolError("an exclusion needs at least one condition — one that matches everything would "
                        "switch the whole catalogue off")
    try:
        conds = [RuleCondition(field=_s(c.get("field"), 120), op=_s(c.get("op"), 30) or "contains",
                               value=_s(c.get("value"), 2000)) for c in rows if isinstance(c, dict)]
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"those conditions are not valid: {exc}")
    body = ExclusionInput(name=_s(args.get("name"), 120), conditions=conds,
                          combinator="or" if _s(args.get("combinator"), 8).lower() == "or" else "and",
                          ruleIds=[_s(r, 60) for r in (args.get("ruleIds") or []) if _s(r, 60)],
                          note=_s(args.get("note"), 2000), enabled=True)
    try:
        ex = call_route(create_exclusion, body=body)
    except HTTPException as exc:
        raise ToolError(f"the exclusion was rejected: {exc.detail}")
    action = ctx.record("add_exclusion",
                        f"added exclusion {ex.id} '{ex.name}' ({'every rule' if not ex.ruleIds else str(len(ex.ruleIds)) + ' rule(s)'})",
                        {"kind": "exclusion_added", "exclusionId": ex.id})
    return {"ok": True, "id": ex.id, "name": ex.name, "trigger": ex.logic,
            "appliesToGraph": ex.appliesToGraph,
            "note": ("detections have been re-evaluated across the whole pool; anything this suppresses "
                     "no longer appears in the anomaly list, and the events themselves are untouched"),
            "action": action}


@tool("delete_exclusion",
      "Remove an exclusion. This only ever REVEALS detections — whatever it was suppressing comes back "
      "on the next pass. Use it when a suppression turns out to have been hiding something that matters.",
      {"exclusionId": {"type": "string"}, "why": {"type": "string"}},
      ["exclusionId"], writes=True)
def _delete_exclusion(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..exclusions import EXCLUSIONS
    from ..routers.exclusions import delete_exclusion
    _budget(ctx)
    eid = _s(args.get("exclusionId"), 60).strip()
    cur = EXCLUSIONS.get(eid)
    if cur is None:
        raise ToolError(f"no exclusion with id {eid!r}. Call list_exclusions for the exact ids.")
    before = cur.model_dump()
    call_route(delete_exclusion, exclusion_id=eid)
    action = ctx.record("delete_exclusion", f"removed exclusion {eid} '{cur.name}'",
                        {"kind": "exclusion_deleted", "exclusionId": eid, "before": before})
    return {"ok": True, "removed": eid, "action": action}


@tool("preview_detection_rule",
      "DRY-RUN a rule definition against the whole pool WITHOUT saving it: how many events it would "
      "flag, up to 20 of them, and the trigger sentence describing what the engine would actually "
      "evaluate. Same arguments as create_detection_rule. Call this BEFORE creating a rule — saving one "
      "re-runs the catalogue over the pool and stamps detections on the analyst's evidence, so a rule "
      "that turns out to match a million lines (or none) is expensive to install and expensive to undo. "
      "A pattern that is unsafe or too slow comes back as `error` rather than being run.",
      {"name": {"type": "string", "description": "only used to label the preview"},
       "pattern": {"type": "string", "description": "regular expression (regex rules)"},
       "field": {"type": "string", "description": "any|msg|raw|host|user|source|file (default any)"},
       "sourceFilter": {"type": "string", "description": "only events whose source/file contains this"},
       "conditions": {"type": "array", "description": "typed conditions [{field, op, value}]",
                      "items": {"type": "object", "properties": {"field": {"type": "string"},
                                                                 "op": {"type": "string"},
                                                                 "value": {"type": "string"}}}},
       "combinator": {"type": "string", "enum": ["and", "or"]},
       "threshold": {"type": "object", "description": "{count, window (seconds), groupBy}",
                     "properties": {"count": {"type": "integer"}, "window": {"type": "integer"},
                                    "groupBy": {"type": "string"}}},
       "sev": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]}},
      [])
def _preview_detection_rule(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from fastapi import HTTPException
    from ..routers.rules import preview_rule_endpoint
    if not _s(args.get("pattern"), 2000).strip() and not (args.get("conditions") or []):
        raise ToolError("a preview needs either a `pattern` (regex) or at least one entry in `conditions`")
    body = _rule_input({**args, "name": _s(args.get("name"), 120).strip() or "preview"})
    try:
        res = call_route(preview_rule_endpoint, body=body)
    except HTTPException as exc:
        raise ToolError(f"that rule definition is not valid: {exc.detail}")
    # `sample` is a list of EventOut; _row takes the API row shape, which is what model_dump gives it.
    rows = [_row(e.model_dump(), {"raw"}, 200, 0) for e in res.sample[:10]]
    out: dict[str, Any] = {"hits": res.hits, "tookMs": res.tookMs, "trigger": res.trigger,
                           "mechanism": res.mechanism, "sample": rows, "saved": False}
    if res.error:
        out["error"] = res.error
    # A rule that matches nothing and a rule that matches everything are both wrong, and neither is
    # obvious from a number alone once the pool is large. Say which one this is.
    total = len(_store().events)
    if total:
        out["poolEvents"] = total
        out["sharePercent"] = round(res.hits * 100.0 / total, 3)
        if res.hits == 0:
            out["note"] = ("this rule matches NOTHING in the pool as it stands. That may be correct for a "
                           "rule meant to catch something that has not happened yet — say so if it is.")
        elif res.hits * 20 >= total:
            out["note"] = ("this matches more than 5% of every event in the workspace. A rule that fires "
                           "on that share of the evidence is a label, not a detection.")
    return out


@tool("list_graph_findings",
      "Detections that read the ENTITY GRAPH instead of one line at a time: one address authenticating "
      "as many accounts, one account used from many addresses, a hash present on many hosts, a name "
      "resolving to many addresses, a relationship that is almost all failures, an entity that spans "
      "many log files. Each finding names the ENTITY and cites real event ids. These findings never "
      "appear in list_detections — that tool reads Event.detections, and a fan-out is a property of a "
      "node, not of any one of its events.",
      {"scope": {"type": "string", "enum": ["all", "case"], "description": "whole pool (default) or the case set"},
       "sev": {"type": "string", "description": "comma-separated severities to keep"},
       "limit": {"type": "integer", "description": "findings to return, 1-100 (default 30)"}})
def _list_graph_findings(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from .. import graph_findings
    scope = "case" if _s(args.get("scope"), 8).strip().lower() == "case" else "all"
    limit = max(1, min(100, int(args.get("limit") or 30)))
    want = {x.strip().lower() for x in _s(args.get("sev"), 80).split(",") if x.strip()}
    # The graph is the expensive part and it may still be building. _await_derived is the same bounded
    # wait every other graph tool takes: it ends, and it refuses with what is still building rather than
    # answering [] — an empty list here would be read as "the graph is clean", which nothing checked.
    store = _store()
    _await_derived(ctx, "graph", lambda: store.graph_v2_ready(scope),
                   lambda: store.graph_status(scope), "list_graph_findings")
    rows = graph_findings.get(scope)
    if want:
        rows = [f for f in rows if f.sev in want]
    return {"total": len(rows), "scope": scope,
            "findings": [f.as_dict() for f in rows[:limit]]}


@tool("update_detection_rule",
      "Change a CUSTOM rule you or the analyst created: its name, description, severity, pattern, "
      "conditions or threshold. Fields you leave out keep their current value. Built-in rules are not "
      "edited this way — use set_builtin_rule_params for those.",
      {"ruleId": {"type": "string"}, "name": {"type": "string"}, "description": {"type": "string"},
       "sev": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
       "pattern": {"type": "string"}, "field": {"type": "string"}, "sourceFilter": {"type": "string"},
       "conditions": {"type": "array", "items": {"type": "object"}},
       "combinator": {"type": "string", "enum": ["and", "or"]},
       "threshold": {"type": "object"}, "tags": {"type": "array", "items": {"type": "string"}},
       "enabled": {"type": "boolean"}},
      ["ruleId"], writes=True)
def _update_detection_rule(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from fastapi import HTTPException
    from ..routers.rules import update_rule
    _budget(ctx)
    rid = _s(args.get("ruleId"), 60).strip()
    cur = _get_rule(rid)
    if cur.builtin:
        raise ToolError(f"{rid} is a built-in rule: its matching shape is code. Change what it compares "
                        "against with set_builtin_rule_params, or switch it off with set_detection_rule_enabled.")
    before = _rule_snapshot(cur)
    body = _rule_input(args, cur)
    try:
        r = call_route(update_rule, rule_id=rid, body=body)
    except HTTPException as exc:
        raise ToolError(f"the change was rejected: {exc.detail}")
    cost = _reapply(rid)
    action = ctx.record("update_detection_rule",
                        f"updated rule {rid} '{r.name}' ({cost['hits']} hit(s), {cost['reapplyMs']} ms)",
                        {"kind": "rule_updated", "ruleId": rid, "before": before})
    return {"ok": True, "rule": _rule_row(r), **cost, "action": action}


@tool("set_detection_rule_enabled",
      "Switch a rule on or off. Works for custom rules and for built-ins (a built-in that is switched off "
      "stays in the catalogue and can be switched back on). Use this for a rule that is too noisy — never "
      "delete a built-in.",
      {"ruleId": {"type": "string"}, "enabled": {"type": "boolean"}},
      ["ruleId", "enabled"], writes=True)
def _set_rule_enabled(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.rules import toggle_rule
    _budget(ctx)
    rid = _s(args.get("ruleId"), 60).strip()
    cur = _get_rule(rid)
    want = bool(args.get("enabled"))
    if cur.enabled == want:
        return {"ok": True, "unchanged": True, "rule": _rule_row(cur)}
    r = call_route(toggle_rule, rule_id=rid)
    cost = _reapply(rid)
    action = ctx.record("set_detection_rule_enabled",
                        f"{'enabled' if want else 'disabled'} rule {rid} '{r.name}'",
                        {"kind": "rule_enabled", "ruleId": rid, "before": cur.enabled})
    return {"ok": True, "rule": _rule_row(r), **cost, "action": action}


@tool("set_builtin_rule_params",
      "Retune a BUILT-IN rule by changing the constants its condition compares against — the threshold, "
      "the window in seconds, the event ids, the status codes, the regex. Call list_detection_rules first "
      "to see the exact parameter keys and their current values. Every value is validated: a bad one is "
      "refused here, and a rule never silently stops matching. Pass an empty params object to put the "
      "rule back to its shipped values.",
      {"ruleId": {"type": "string", "description": "e.g. SIGMA-AUTH-0111"},
       "params": {"type": "object", "description": "{param key: value} — keys come from list_detection_rules"},
       "sev": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
       "description": {"type": "string", "description": "analyst-facing prose only; it changes nothing about what fires"}},
      ["ruleId", "params"], writes=True)
def _set_builtin_rule_params(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from fastapi import HTTPException
    from ..models import RuleInput
    from ..routers.rules import update_rule
    _budget(ctx)
    rid = _s(args.get("ruleId"), 60).strip()
    cur = _get_rule(rid)
    if not cur.builtin:
        raise ToolError(f"{rid} is a custom rule — edit it with update_detection_rule.")
    params = args.get("params")
    if not isinstance(params, dict):
        raise ToolError("params must be an object of {parameter key: value}")
    known = {p.key for p in (cur.params or [])}
    unknown = [k for k in params if k not in known]
    if unknown:
        raise ToolError(f"{rid} has no parameter(s) {', '.join(sorted(unknown))}. Its parameters are: "
                        f"{', '.join(sorted(known)) or '(none)'}.")
    before = _rule_snapshot(cur)
    sev = _s(args.get("sev"), 20).strip().lower() or cur.sev
    body = RuleInput(name=cur.name, description=(_s(args.get("description"), 1000)
                                                 if args.get("description") is not None else cur.description),
                     sev=sev,  # type: ignore[arg-type]
                     enabled=cur.enabled, kind="builtin", tags=list(cur.tags), createdBy="ai",
                     params={k: str(v) for k, v in params.items()})
    try:
        r = call_route(update_rule, rule_id=rid, body=body)
    except HTTPException as exc:
        # detect.parse_param said no — the model gets the reason, and the rule keeps running as it was
        raise ToolError(f"that parameter value was rejected and NOTHING changed: {exc.detail}")
    cost = _reapply(rid)
    changed = ", ".join(f"{k}={v}" for k, v in params.items()) or "shipped defaults"
    action = ctx.record("set_builtin_rule_params", f"retuned {rid} ({changed}) — {cost['hits']} hit(s)",
                        {"kind": "rule_builtin_params", "ruleId": rid, "before": before})
    return {"ok": True, "rule": _rule_row(r), **cost, "action": action}


@tool("delete_detection_rule",
      "Delete a CUSTOM rule for good. Built-in rules can never be deleted here — switch one off with "
      "set_detection_rule_enabled instead.",
      {"ruleId": {"type": "string"}}, ["ruleId"], writes=True)
def _delete_detection_rule(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.rules import delete_rule
    _budget(ctx)
    rid = _s(args.get("ruleId"), 60).strip()
    cur = _get_rule(rid)
    if cur.builtin:
        raise ToolError(f"{rid} is a built-in rule and must not be deleted. Use "
                        "set_detection_rule_enabled(enabled=false) if it is too noisy.")
    before = _rule_snapshot(cur)
    call_route(delete_rule, rule_id=rid)
    cost = _reapply(rid)
    action = ctx.record("delete_detection_rule", f"deleted custom rule {rid} '{cur.name}'",
                        {"kind": "rule_deleted", "before": before})
    return {"ok": True, "ruleId": rid, **cost, "action": action}


# ================================================================= curation: read
# The tools below close the loop the analyst asked for: everything that can be CREATED here can also be
# listed, edited and taken back off the case. A model that can only add is a model whose mistakes the
# analyst has to clean up by hand.


@tool("list_anomalies",
      "The detection ROLL-UP: every rule that fired, with its hit count, first/last seen and the sources "
      "it fired in — the Anomalies screen, as data. Use this instead of paging list_detections when the "
      "question is 'what fired at all' or 'which rule is noisy'.",
      {"sev": {"type": "string", "description": "comma-separated severities to keep (critical,high,medium,low,info)"},
       "limit": {"type": "integer", "description": "1-50 (default 25)"}})
def _list_anomalies(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    # A BOUNDED wait, not the blocking accessor and not an empty list: see the note in list_detections.
    rows = _anomalies(ctx)
    wanted = {x.strip().lower() for x in _s(args.get("sev"), 100).split(",") if x.strip()}
    if wanted:
        rows = [a for a in rows if a.sev in wanted]
    limit = _int(args, "limit", 25, 1, MAX_ROWS)
    out = rows[:limit]
    return {"total": len(rows), "shown": len(out),
            "totalHits": sum(a.hits for a in rows),
            "anomalies": [{"ruleId": a.ruleId, "name": a.name, "sev": a.sev, "kind": a.kind, "hits": a.hits,
                           "firstSeen": a.firstSeen, "lastSeen": a.lastSeen, "sources": a.sources[:8],
                           "sampleEventIds": [e.id for e in a.sample[:5]]} for a in out]}


@tool("list_cases",
      "Every case on this server, newest first, with which one is ACTIVE. Case-scoped writes always go "
      "to the active case — call activate_case first if the analyst meant a different one.",
      {})
def _list_cases(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from .. import cases
    rows = cases.list_cases()
    store = _store()
    return {"total": len(rows), "activeCaseId": "" if store.pending else store.case_id,
            "cases": [{"id": c.id, "name": c.name, "analyst": c.analyst, "createdAt": c.createdAt,
                       "updatedAt": c.updatedAt, "sources": c.sources, "events": c.events,
                       "caseSet": c.caseSet, "active": c.active} for c in rows[:MAX_ROWS]]}


@tool("get_case_set",
      "The curated case set — the events the analyst (or an earlier run) put in the case, with their "
      "labels and per-event notes, oldest first. This IS the case timeline: annotate_case_event edits "
      "an entry, remove_events_from_case takes one out.",
      {"limit": {"type": "integer", "description": "1-50 (default 30)"},
       "label": {"type": "string", "description": "only entries carrying this label"}})
def _get_case_set(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    if store.pending:
        # A read must never look like a failure: with no case there simply is no curated set yet.
        return {"total": 0, "shown": 0, "labels": [], "entries": [], "hasCase": False,
                "note": "there is no active case, so nothing is curated yet"}
    with store.lock:
        entries = list(store.case_set.values())
    want = _s(args.get("label"), 80).strip().lower()
    if want:
        entries = [e for e in entries if any(l.lower() == want for l in e.labels)]
    entries.sort(key=lambda e: (e.addedAt, e.eventId))
    rows = []
    for e in entries[: _int(args, "limit", 30, 1, MAX_ROWS)]:
        ev = store.event(e.eventId)
        rows.append({"eventId": e.eventId, "labels": e.labels, "note": _s(e.note, 400), "addedAt": e.addedAt,
                     "ts": ev.ts if ev else None, "sev": ev.sev if ev else None,
                     "source": ev.source if ev else "", "msg": _s(ev.msg, 200) if ev else ""})
    return {"total": len(entries), "shown": len(rows), "labels": store.case_labels(), "entries": rows}


@tool("list_graph_links",
      "Links drawn on top of the extracted entity graph — by the analyst, by graph review, or by an "
      "earlier run. These are the only edges that can be edited or deleted; extracted edges come from "
      "the events themselves and are not editable.",
      {})
def _list_graph_links(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    store = _store()
    with store.lock:
        links = [dict(l) for l in store.graph_links]
    return {"total": len(links),
            "links": [{"id": str(l.get("id") or ""), "source": str(l.get("source") or ""),
                       "target": str(l.get("target") or ""), "relation": str(l.get("relation") or ""),
                       "why": _s(l.get("why"), 300), "confidence": l.get("confidence"),
                       "ai": bool(l.get("ai")), "runId": str(l.get("runId") or ""),
                       "citedEventIds": list(l.get("citedEventIds") or [])[:10]}
                      for l in links[:MAX_ROWS]]}


# ================================================================= curation: edit and remove


@tool("activate_case",
      "Switch which case is ACTIVE. Every case-scoped write (case set, notes, indicators, graph links) "
      "goes to the active case, so switch before curating a different investigation. The event pool is "
      "not affected — searching and the graph span everything either way.",
      {"caseId": {"type": "string", "description": "id from list_cases, e.g. CASE-0003"}},
      ["caseId"], writes=True)
def _activate_case(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from .. import cases
    _budget(ctx)
    store = _store()
    cid = _s(args.get("caseId"), 40).strip()
    known = [c.id for c in cases.list_cases()]
    if cid not in known:
        raise ToolError(f"no such case: {cid}. Existing cases: {', '.join(known) or 'none'}")
    previous = "" if store.pending else store.case_id
    if cid == previous:
        return {"ok": True, "caseId": cid, "name": store.name, "unchanged": True}
    cases.activate(cid)
    store = _store()
    action = ctx.record("activate_case", f"made {cid} the active case",
                        {"kind": "case_active", "before": previous})
    return {"ok": True, "caseId": store.case_id, "name": store.name,
            "caseSetSize": len(store.case_set), "notes": len(store.notes), "action": action}


@tool("update_ioc",
      "Edit an indicator already on the case: correct its value, re-classify its kind, or rewrite the "
      "note explaining why it matters. Only MANUALLY recorded indicators can be edited — extracted ones "
      "are derived from events and change when the evidence does.",
      {"iocId": {"type": "string", "description": "id from list_iocs, e.g. 'ipv4:10.0.0.100'"},
       "value": {"type": "string", "description": "new value (omit to keep)"},
       "kind": {"type": "string", "description": "new kind (omit to keep)"},
       "note": {"type": "string", "description": "new explanation (omit to keep)"}},
      ["iocId"], writes=True)
def _update_ioc(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.iocs import _all_iocs, _ioc_id
    _budget(ctx)
    _require_case("an indicator")
    store = _store()
    iid = _s(args.get("iocId"), 300).strip()
    with store.lock:
        target = next((m for m in store.manual_iocs
                       if _ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) == iid), None)
        if target is None:
            extracted = any(i.id == iid for i in _all_iocs("all"))
            raise ToolError(
                f"{iid} is an EXTRACTED indicator — it comes from the events and cannot be edited; "
                f"correct the rule or add a manual indicator instead" if extracted else
                f"no manual indicator with id {iid}. Call list_iocs and use the `id` field.")
        before = {"kind": target.get("kind"), "value": target.get("value"), "note": target.get("note", "")}
        if args.get("value") is not None:
            new_value = _s(args.get("value"), 500).strip()
            if not new_value:
                raise ToolError("value cannot be blanked — delete_ioc removes an indicator")
            target["value"] = new_value
        if args.get("kind") is not None:
            new_kind = _s(args.get("kind"), 60).strip().lower()
            if new_kind:
                target["kind"] = new_kind
        if args.get("note") is not None:
            target["note"] = _prose(args.get("note"), 600)
        new_id = _ioc_id(str(target.get("kind") or "other"), str(target.get("value") or ""))
        target["editedBy"] = "ai"
        target["editedAt"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        target["runId"] = ctx.run_id
    store.save_meta()
    action = ctx.record("update_ioc", f"edited indicator {iid} -> {new_id}",
                        {"kind": "ioc_updated", "iocId": new_id, "before": before})
    return {"ok": True, "iocId": new_id, "previousId": iid,
            "kind": target["kind"], "value": target["value"], "note": target.get("note", ""),
            "action": action}


@tool("delete_ioc",
      "Remove an indicator from the case — a false positive, a duplicate, or one you recorded in error. "
      "Only MANUAL indicators can be removed; an extracted one would come straight back, because it is "
      "derived from the events. The removal is undoable.",
      {"iocId": {"type": "string", "description": "id from list_iocs"},
       "why": {"type": "string", "description": "one sentence — why it should not be tracked"}},
      ["iocId"], writes=True)
def _delete_ioc(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from ..routers.iocs import _all_iocs, _ioc_id
    _budget(ctx)
    _require_case("an indicator")
    store = _store()
    iid = _s(args.get("iocId"), 300).strip()
    with store.lock:
        target = next((m for m in store.manual_iocs
                       if _ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) == iid), None)
        if target is None:
            extracted = any(i.id == iid for i in _all_iocs("all"))
            raise ToolError(
                f"{iid} is an EXTRACTED indicator: it is derived from the events and cannot be deleted. "
                f"Disable or tune the detection rule that produces it instead." if extracted else
                f"no manual indicator with id {iid}. Call list_iocs and use the `id` field.")
        snapshot = dict(target)
        store.manual_iocs = [m for m in store.manual_iocs if m is not target]
    store.save_meta()
    action = ctx.record("delete_ioc", f"removed indicator {iid}"
                        + (f" ({_s(args.get('why'), 120)})" if args.get("why") else ""),
                        {"kind": "ioc_deleted", "before": snapshot})
    return {"ok": True, "iocId": iid, "action": action}


@tool("update_note",
      "Rewrite a case note — correct it, extend it, or attach different events. Cited event ids are "
      "verified exactly as they are on add_note, and the note keeps its author and gains an edited "
      "timestamp so the analyst can see it changed.",
      {"noteId": {"type": "string", "description": "id from list_notes, e.g. n3"},
       "text": {"type": "string", "description": "the new note text (omit to keep the current text)"},
       "citedEventIds": {"type": "array", "items": {"type": "string"},
                         "description": "replacement citations (omit to keep the current ones)"}},
      ["noteId"], writes=True)
def _update_note(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from .. import cases
    from ..models import NoteRef
    _budget(ctx)
    _require_case("a note")
    store = _store()
    nid = _s(args.get("noteId"), 60).strip()
    with store.lock:
        current = next((n for n in store.notes if n.id == nid), None)
    if current is None:
        raise ToolError(f"no note with id {nid}. Call list_notes for the ids.")
    before = {"text": current.text, "refs": [r.model_dump() for r in current.refs]}
    text = None
    if args.get("text") is not None:
        text = _prose(args.get("text"), 12000).strip()
        if not text:
            raise ToolError("text cannot be blanked — delete_note removes a note")
    refs = None
    if args.get("citedEventIds") is not None:
        cited = _ids(args, "citedEventIds")
        if not cited:
            raise ToolError("citedEventIds cannot be emptied: a finding in the case file needs its evidence")
        _check_citations(cited, f"note {nid}")
        refs = [NoteRef(kind="event", value=i, label=i) for i in cited]
    if text is None and refs is None:
        raise ToolError("nothing to change: pass text, citedEventIds, or both")
    try:
        note = cases.update_note(store.case_id, nid, text, refs)
    except KeyError:
        raise ToolError(f"no note with id {nid} on case {store.case_id}")
    action = ctx.record("update_note", f"edited case note {nid}",
                        {"kind": "note_updated", "noteId": nid, "caseId": store.case_id, "before": before})
    return {"ok": True, "noteId": note.id, "author": note.author, "updatedAt": note.updatedAt,
            "text": _s(note.text, 600), "action": action}


@tool("delete_note",
      "Remove a note from the case file — one written in error, superseded, or duplicated. The full note "
      "is kept in this run's action log, so the removal is undoable.",
      {"noteId": {"type": "string", "description": "id from list_notes"},
       "why": {"type": "string", "description": "one sentence — why it should go"}},
      ["noteId"], writes=True)
def _delete_note(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    from .. import cases
    _budget(ctx)
    _require_case("a note")
    store = _store()
    nid = _s(args.get("noteId"), 60).strip()
    with store.lock:
        current = next((n for n in store.notes if n.id == nid), None)
    if current is None:
        raise ToolError(f"no note with id {nid}. Call list_notes for the ids.")
    snapshot = current.model_dump()
    try:
        cases.delete_note(store.case_id, nid)
    except KeyError:
        raise ToolError(f"no note with id {nid} on case {store.case_id}")
    action = ctx.record("delete_note", f"deleted case note {nid}"
                        + (f" ({_s(args.get('why'), 120)})" if args.get("why") else ""),
                        {"kind": "note_deleted", "caseId": store.case_id, "before": snapshot})
    return {"ok": True, "noteId": nid, "deletedText": _s(snapshot.get("text"), 300), "action": action}


def _annotate_one(store: Any, eid: str, labels_arg: Any, note_arg: Any) -> dict[str, Any]:
    """Apply one annotation. ONE implementation, shared by annotate_case_event and
    annotate_case_events — a per-event write and a batch write of the same thing must not diverge.

    Returns {eventId, before, labels, note, unchanged}. Raises ToolError for anything the caller got
    wrong, so the batch can report it per entry instead of failing the whole timeline.
    """
    with store.lock:
        current = store.case_set.get(eid)
    if current is None:
        raise ToolError(f"{eid} is not in the case set. Add it with add_events_to_case first "
                        f"(annotating an event that is not in the case would be a note about nothing).")
    before = {"labels": list(current.labels), "note": current.note}
    labels = before["labels"]
    if labels_arg is not None:
        if not isinstance(labels_arg, list):
            raise ToolError("labels must be a list of strings")
        labels = [_s(l, 60).strip() for l in labels_arg[:12] if _s(l, 60).strip()]
    note = before["note"] if note_arg is None else _prose(note_arg, 800)
    if labels == before["labels"] and note == before["note"]:
        return {"eventId": eid, "before": before, "labels": labels, "note": note, "unchanged": True}
    entry = store.add_to_case(eid, labels, note)     # add_to_case is an upsert — same path the UI uses
    if entry is None:
        raise ToolError(f"{eid} is not an event in this workspace")
    return {"eventId": eid, "before": before, "labels": list(entry.labels), "note": _s(entry.note, 400),
            "unchanged": False}


@tool("annotate_case_event",
      "Label or annotate ONE event already in the case set. To write a whole timeline, call "
      "annotate_case_events once with every entry instead — one call per event spends the step budget "
      "on bookkeeping. Labels replace the entry's existing labels; pass the full list you want it to carry.",
      {"eventId": {"type": "string", "description": "an event already in the case set"},
       "labels": {"type": "array", "items": {"type": "string"},
                  "description": "the complete label list for this entry (replaces what is there)"},
       "note": {"type": "string", "description": "why this event matters at this point in the timeline"}},
      ["eventId"], writes=True)
def _annotate_case_event(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    _budget(ctx)
    _require_case("the case set")
    store = _store()
    eid = _s(args.get("eventId"), 60).strip()
    r = _annotate_one(store, eid, args.get("labels"), args.get("note"))
    if r["unchanged"]:
        return {"ok": True, "eventId": eid, "unchanged": True, "labels": r["labels"], "note": r["note"]}
    action = ctx.record("annotate_case_event", f"annotated {eid} ({', '.join(r['labels']) or 'no labels'})",
                        {"kind": "case_set_annotated", "eventId": eid, "before": r["before"]})
    return {"ok": True, "eventId": eid, "labels": r["labels"], "note": r["note"], "action": action}


@tool("annotate_case_events",
      "Write a WHOLE case timeline in one call: label and annotate many case-set events at once. Each "
      "entry is {eventId, labels, note}, so every step of the sequence gets its own label and its own "
      "sentence of context. Annotating twenty events one at a time spends twenty steps of the budget and "
      "is never the right way to build a timeline. Every event must already be in the case set (add them "
      "with add_events_to_case first). Entries that fail are reported individually — the rest still "
      "apply — and the whole batch is undone as one action.",
      {"entries": {"type": "array",
                   "description": "one object per event: {eventId, labels (full replacement list), note}",
                   "items": {"type": "object",
                             "properties": {"eventId": {"type": "string"},
                                            "labels": {"type": "array", "items": {"type": "string"}},
                                            "note": {"type": "string"}},
                             "required": ["eventId"]}}},
      ["entries"], writes=True)
def _annotate_case_events(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    _budget(ctx)
    _require_case("the case set")
    store = _store()
    entries = args.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ToolError("entries must be a non-empty list of {eventId, labels, note} objects, one per "
                        "event you want to annotate.")
    if len(entries) > MAX_CITED:
        raise ToolError(f"{len(entries)} entries is more than one call applies (maximum {MAX_CITED}). "
                        "Split it into batches.")
    applied: list[dict[str, Any]] = []
    befores: list[dict[str, Any]] = []
    failed: list[dict[str, str]] = []
    unchanged: list[str] = []
    for raw in entries:
        if not isinstance(raw, dict):
            failed.append({"eventId": _s(raw, 60), "error": "each entry must be an object with an eventId"})
            continue
        eid = _s(raw.get("eventId"), 60).strip()
        if not eid:
            failed.append({"eventId": "", "error": "entry has no eventId"})
            continue
        try:
            r = _annotate_one(store, eid, raw.get("labels"), raw.get("note"))
        except ToolError as exc:
            failed.append({"eventId": eid, "error": str(exc)})
            continue
        if r["unchanged"]:
            unchanged.append(eid)
            continue
        befores.append({"eventId": eid, "before": r["before"]})
        applied.append({"eventId": eid, "labels": r["labels"], "note": r["note"]})
    out: dict[str, Any] = {"ok": True, "annotated": len(applied), "unchanged": unchanged,
                           "entries": applied}
    if failed:
        out["failed"] = failed
        out["note"] = (f"{len(failed)} entr(ies) were not applied — see `failed`. The rest were. An event "
                       "must be in the case set before it can be annotated.")
    if befores:
        out["action"] = ctx.record(
            "annotate_case_events", f"annotated {len(applied)} case timeline event(s)",
            {"kind": "case_set_annotated_many", "entries": befores})
    return out


@tool("delete_graph_link",
      "Remove a link from the entity graph — one drawn on a wrong assumption, a duplicate, or a pivot "
      "the evidence did not support. Only added links can be removed; extracted edges come from the "
      "events. Undoable.",
      {"linkId": {"type": "string", "description": "id from list_graph_links ('<source>|<relation>|<target>')"},
       "why": {"type": "string", "description": "one sentence — why the link does not hold"}},
      ["linkId"], writes=True)
def _delete_graph_link(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    _budget(ctx)
    _require_case("a graph link")
    store = _store()
    lid = _s(args.get("linkId"), 400).strip()
    with store.lock:
        target = next((l for l in store.graph_links if str(l.get("id") or "") == lid), None)
        if target is None:
            known = [str(l.get("id") or "") for l in store.graph_links][:10]
            raise ToolError(f"no added link with id {lid}. Added links are: {', '.join(known) or 'none'}. "
                            f"An EXTRACTED edge cannot be deleted — it is what the events say.")
        snapshot = dict(target)
        store.graph_links = [l for l in store.graph_links if l is not target]
    store.save_meta()
    action = ctx.record("delete_graph_link", f"removed graph link {lid}"
                        + (f" ({_s(args.get('why'), 120)})" if args.get("why") else ""),
                        {"kind": "graph_link_deleted", "before": snapshot})
    return {"ok": True, "linkId": lid, "action": action}


# ------------------------------------------------------------------ undo
def _restore_rule(before: dict[str, Any], rule_id: str = "") -> bool:
    """Put a custom rule back the way it was (or re-create it), through the validated path."""
    from fastapi import HTTPException
    from ..routers.rules import create_rule, update_rule
    from ..rules import RULES_STORE
    from ..store import STORE
    args = dict(before)
    args.pop("params", None)
    body = _rule_input(args)
    try:
        if rule_id and RULES_STORE.get(rule_id) is not None:
            call_route(update_rule, rule_id=rule_id, body=body)
            STORE.reapply_rule(rule_id)
        else:
            r = call_route(create_rule, body=body)
            STORE.reapply_rule(r.id)
    except (HTTPException, ToolError):
        return False
    return True


def undo_action(action: dict[str, Any]) -> bool:
    """Reverse one recorded write. Returns True if anything changed.

    Writes are applied immediately rather than queued behind a confirm dialog (see docs/API_CONTRACT.md
    → "AI investigator"), so this is the safety net that makes that choice defensible: every artefact an
    agent created can be taken back off the case in one call.
    """
    from .. import cases
    store = _store()
    undo = action.get("undo") or {}
    kind = str(undo.get("kind") or "")
    if kind == "case_set":
        return store.remove_many_from_case(list(undo.get("eventIds") or [])) > 0
    if kind == "case_set_removed":
        return bool(store.add_many_to_case(list(undo.get("eventIds") or []), ["ai"], None))
    if kind == "ioc":
        iid = str(undo.get("iocId") or "")
        from ..routers.iocs import _ioc_id
        with store.lock:
            before = len(store.manual_iocs)
            store.manual_iocs = [m for m in store.manual_iocs
                                 if _ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) != iid]
            removed = before - len(store.manual_iocs)
        store.save_meta()
        return removed > 0
    if kind == "note":
        try:
            cases.delete_note(str(undo.get("caseId") or store.case_id), str(undo.get("noteId") or ""))
            return True
        except KeyError:
            return False
    if kind in ("graph_link", "graph_batch"):
        ids = {str(undo.get("linkId") or "")} | {str(x) for x in (undo.get("linkIds") or [])}
        ids.discard("")
        # The nodes this write CREATED go back too, or reverting a graph leaves its vertices behind as
        # a scatter of unconnected dots the analyst never drew.
        made = {str(x) for x in (undo.get("createdNodes") or [])}
        with store.lock:
            before = len(store.graph_links)
            store.graph_links = [l for l in store.graph_links if str(l.get("id")) not in ids]
            removed = before - len(store.graph_links)
            if made:
                still_used = {str(l.get("source")) for l in store.graph_links} | \
                             {str(l.get("target")) for l in store.graph_links}
                store.graph_nodes = [n for n in store.graph_nodes
                                     if str(n.get("id")) not in made or str(n.get("id")) in still_used]
        store.save_meta()
        return removed > 0
    if kind == "rule_created":
        from ..routers.rules import delete_rule
        from ..rules import RULES_STORE
        rid = str(undo.get("ruleId") or "")
        if RULES_STORE.get(rid) is None or RULES_STORE.is_builtin(rid):
            return False
        call_route(delete_rule, rule_id=rid)
        store.reapply_rule(rid)
        return True
    if kind in ("rule_updated", "rule_deleted"):
        return _restore_rule(dict(undo.get("before") or {}), str(undo.get("ruleId") or ""))
    if kind == "rule_enabled":
        from ..routers.rules import toggle_rule
        from ..rules import RULES_STORE
        rid = str(undo.get("ruleId") or "")
        cur = RULES_STORE.get(rid)
        if cur is None or cur.enabled == bool(undo.get("before")):
            return False
        call_route(toggle_rule, rule_id=rid)
        store.reapply_rule(rid)
        return True
    if kind == "rule_builtin_params":
        from ..models import RuleInput
        from ..routers.rules import update_rule
        from ..rules import RULES_STORE
        rid = str(undo.get("ruleId") or "")
        before = dict(undo.get("before") or {})
        if not RULES_STORE.is_builtin(rid):
            return False
        call_route(update_rule, rule_id=rid,
                   body=RuleInput(name=str(before.get("name") or ""), description=str(before.get("description") or ""),
                                  sev=before.get("sev") or "medium", enabled=bool(before.get("enabled", True)),
                                  kind="builtin", tags=list(before.get("tags") or []), createdBy="ai",
                                  params={k: str(v) for k, v in (before.get("params") or {}).items()}))
        store.reapply_rule(rid)
        return True
    if kind == "ioc_updated":
        from ..routers.iocs import _ioc_id
        iid, before = str(undo.get("iocId") or ""), dict(undo.get("before") or {})
        with store.lock:
            target = next((m for m in store.manual_iocs
                           if _ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) == iid), None)
            if target is None:
                return False
            target["kind"] = before.get("kind") or target.get("kind")
            target["value"] = before.get("value") or target.get("value")
            target["note"] = before.get("note", "")
        store.save_meta()
        return True
    if kind == "ioc_deleted":
        from ..routers.iocs import _ioc_id
        before = dict(undo.get("before") or {})
        if not before.get("value"):
            return False
        iid = _ioc_id(str(before.get("kind") or "other"), str(before.get("value") or ""))
        with store.lock:
            if any(_ioc_id(str(m.get("kind") or "other"), str(m.get("value") or "")) == iid
                   for m in store.manual_iocs):
                return False
            store.manual_iocs.append(before)
        store.save_meta()
        return True
    if kind == "note_updated":
        from ..models import NoteRef
        before = dict(undo.get("before") or {})
        try:
            cases.update_note(str(undo.get("caseId") or store.case_id), str(undo.get("noteId") or ""),
                              before.get("text"), [NoteRef(**r) for r in (before.get("refs") or [])])
            return True
        except (KeyError, TypeError, ValueError):
            return False
    if kind == "note_deleted":
        from ..models import CaseNote
        before = dict(undo.get("before") or {})
        if not before:
            return False
        try:
            cases.restore_note(str(undo.get("caseId") or store.case_id), CaseNote(**before))
            return True
        except (KeyError, TypeError, ValueError):
            return False
    if kind == "case_set_annotated":
        before = dict(undo.get("before") or {})
        eid = str(undo.get("eventId") or "")
        if eid not in store.case_set:
            return False
        return store.add_to_case(eid, list(before.get("labels") or []), str(before.get("note") or "")) is not None
    if kind == "case_set_annotated_many":
        # One batch write is one undo: every entry goes back to the labels and note it carried before.
        # An entry the analyst has since removed from the case set is skipped, not resurrected.
        changed = False
        for ent in (undo.get("entries") or []):
            eid = str((ent or {}).get("eventId") or "")
            before = dict((ent or {}).get("before") or {})
            if not eid or eid not in store.case_set:
                continue
            if store.add_to_case(eid, list(before.get("labels") or []), str(before.get("note") or "")) is not None:
                changed = True
        return changed
    if kind == "graph_link_deleted":
        before = dict(undo.get("before") or {})
        lid = str(before.get("id") or "")
        if not lid:
            return False
        with store.lock:
            if any(str(l.get("id") or "") == lid for l in store.graph_links):
                return False
            store.graph_links.append(before)
        store.save_meta()
        return True
    if kind == "case_active":
        prev = str(undo.get("before") or "")
        if not prev or prev == store.case_id:
            return False
        try:
            cases.activate(prev)
            return True
        except (KeyError, ValueError):
            return False
    if kind == "case_meta":
        before = undo.get("before") or {}
        store.name = str(before.get("name") or store.name)
        store.summary = str(before.get("summary") or "")
        store.save_meta()
        return True
    # a created CASE is deliberately not undone: deleting a case is not something the agent path may do
    return False


# ------------------------------------------------------------------ citations in prose
# Event ids are "e<decimal>" (case sources) or "l<8 hex><hex>" (library sources) — see Store._append_events.
_ID_RE = re.compile(r"\b(e\d{1,9}|l[0-9a-f]{9,20})\b")


def unverified_citations(text: str) -> list[str]:
    """Ids the model wrote in its answer that are not real events. Reported, not silently dropped."""
    seen: list[str] = []
    for m in _ID_RE.finditer(text or ""):
        if m.group(1) not in seen:
            seen.append(m.group(1))
    return verify_event_ids(seen)[:20]
