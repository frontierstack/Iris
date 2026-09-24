"""Loop guarding for the investigator: what ends a run whose model has stopped moving — and, before
that, what gets it moving again.

The run budget (steps, wall clock, writes) is a SETTING, and the analyst can switch it off for a case
that has to be worked to the end. With it off, the only things that ended a run were the analyst
pressing Stop and the model's own judgement — and a model that has lost the plot has no judgement
left to apply. Measured on the shipped test double: an identical refused call, forty-five times, and
nothing in the loop said no. Even with the budget ON, a 40-step run could spend every step on the
same question, and one assistant turn could carry any number of calls.

So the guard is NOT a budget and is NOT subject to the limits switch. It is a detector for the
specific shapes a loop takes, each with its own bound, and it fires on EVIDENCE — what the calls
were and what they returned — never on the count of calls alone (the check-in that fired on the count
was reported as pushing the model to stop investigating too early, and that report still stands):

  1. THE SAME CALL AGAIN. One exact call (tool + canonical arguments) may be made MAX_IDENTICAL times:
     the first runs, the second is served from the run's dedupe cache with a note, the third is REFUSED
     with the reason. A successful WRITE clears the read counts, exactly as it clears the cache, because
     re-reading after a change is the one legitimate reason to ask the same question twice; the
     absolute per-run cap (MAX_IDENTICAL_EVER) is never cleared.
  2. THE SAME WRITE AGAIN. A write identical to one that already SUCCEEDED in this run is refused and
     nothing changes: a second copy of a note or an indicator on the analyst's case is never what was
     meant. A write that FAILED may be retried (a derived build may have finished since).
  3. PAGING AS ENUMERATION. Consecutive calls to one tool whose arguments differ only in a paging key
     (offset / limit / page / cursor) are pages of one question. Past MAX_PAGING the next page is
     refused and the aggregate tools are named: fifty rows at a time over a million events is a loop
     with a slow clock, and a wrong coverage claim at the end of it — the exact thing the counting
     tools exist to prevent.
  4. MANY CALLS IN ONE TURN. An assistant message may carry any number of tool calls; past
     MAX_CALLS_PER_TURN the rest are refused and the model is asked to send them next turn. Every
     refused call still gets a tool result, because an OpenAI-shaped provider rejects a transcript in
     which a tool_call has no answer.
  5. STREAKS. Refusals 1-3 are visible to the model and it can change course. When it does not, two
     streaks end the run with reason `loop` — which takes the wrap-up turn, so the analyst gets the
     report the work earned and can press Continue: `repeat_limit()` consecutive repeats (a tight loop,
     caught early), or MAX_BARREN_STREAK consecutive calls that each returned nothing new (repeats,
     refusals or empty results — the wide net, by which point the check-in has asked twice for a
     different angle). A single productive call resets both, so a run that is still finding things is
     never interrupted however long it is.

WHAT A REFUSAL HAS TO DO, which is the second half of this module and the reason it is more than a
counter. Reported by the analyst: *"There is an issue where it will announce this over and over, 'I'm
hitting a loop, let me try a different approach' without saying what it is going to do different.
Might be more of an issue for not as smart models, but I still want to handle this better and have
the model be able to recover and progress."* Two defects behind that, and neither is the detection:

  * **A refusal was a PROHIBITION, not a ROUTE.** "Change the arguments, take a different angle, or
    write your report" says what the guard will not accept and nothing about what to do instead. A
    strong model derives the next move; a weaker one paraphrases the refusal back as prose — "let me
    try a different approach" — and sends something equally repetitive, because nothing told it which
    approach. The guard holds everything needed to name one: which tool was repeated, which arguments
    that tool has already been given, which tools have not been called at all. `advice()` spends a
    few hundred characters naming CONCRETE calls — untried tools with what each one answers, plus
    ways to vary the call that was refused (drop the time window, drop a term, aggregate instead of
    page). A refusal that names the next call is the whole fix for most of this.
  * **Nothing acted on the ANNOUNCEMENT.** A turn was judged only by its tool calls, so a turn that
    said "I'm hitting a loop, let me try a different approach" and then sent a call that was refused
    again was treated exactly like the first one, and the same refusal came back. `begin_turn(prose)`
    reads the announcement: a turn that declares a change of plan, or repeats prose it has already
    written, while nothing productive has happened, counts as a `plan_repeat`. Two of those — or
    RECOVER_AT consecutive repeats — and the run is handed a RECOVERY PLAN (`recovery()`) as a user
    turn instead of a third identical refusal: what did not run, what it has already tried, the calls
    it has NOT made, and one instruction — make one of them in this turn, or report. The streaks are
    then cleared so the plan gets a real chance.

Recovery is bounded (MAX_RECOVERIES) and each one shortens the fuse (`repeat_limit`), because a model
that ignores two concrete plans is not going to use a third, and the analyst is owed the report the
work earned rather than another six turns of announcements.

The guard is a pure state machine: `admit` before a call, `observe` after it, `tripped` between. It
holds no reference to the store, the client or the run — the set of tools that exist is passed IN, so
a name it suggests is always one the model actually has — and `tests/test_ai_loop_guard.py` plus
`tests/test_ai_loop_recovery.py` drive it directly as well as through the investigator.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import orjson

MAX_IDENTICAL = 2          # times one exact call may be made; the next is refused
MAX_IDENTICAL_EVER = 8     # ...and an absolute per-run cap on one exact call that no write resets
MAX_REPEAT_STREAK = 6      # consecutive repeats (cached, or refused as a repeat / a page) end the run
MAX_BARREN_STREAK = 24     # consecutive calls with nothing new end the run
MAX_PAGING = 8             # consecutive pages of one question before the next page is refused
MAX_CALLS_PER_TURN = 24    # tool calls one assistant message may carry; the rest are refused
# ---- recovery, before the run is ended. RECOVER_AT is deliberately BELOW MAX_REPEAT_STREAK: the
# first loop is answered with a plan, not with an ending, because "the model should be able to recover
# and progress" and by the time six calls have repeated the analyst has watched six announcements.
RECOVER_AT = 3             # consecutive repeats at which a recovery PLAN is injected instead
PLAN_REPEATS_AT = 2        # ...or announcements of a change of plan that changed nothing
MAX_RECOVERIES = 2         # plans per run; past this the streak simply ends the run
# Arguments that turn one question into many pages of it. `limit` is included: asking for the same
# query with a bigger limit is "more of the same", and it is counted as a page rather than refused.
PAGING_KEYS = ("offset", "limit", "page", "cursor")
# What replaces paging: the answer to "how many / which sources / which values" in ONE call.
AGGREGATES = "aggregate_events, count_events, distinct_values, events_over_time or entity_profile"

# ---------------------------------------------------------------- the routes a refusal can name
# ORDERED, and the order is the advice: orientation first (a model that is looping usually does not
# know what is in the workspace), then the counting tools that answer a question paging cannot, then
# the pivots. Each entry is (tool, what it answers) and the text is written to be read by a model
# mid-run: it says what comes BACK, not what the tool is called after. Only names in this table are
# ever suggested, and only when the run actually has that tool — `untried()` takes the available set.
ROUTES: tuple[tuple[str, str], ...] = (
    ("workspace_overview", "every source with its parse state and time range, the pool totals, the "
                           "case and the detections — the whole opening in one call"),
    ("list_event_fields", "the field names this evidence actually carries, so a `field:value` query "
                          "stops guessing at names that are not there"),
    ("aggregate_events", "how many events by source / host / user / any field, for a query — instead "
                         "of reading rows to count them"),
    ("distinct_values", "which values a field actually takes, which is the answer when a query you "
                        "guessed comes back empty"),
    ("events_over_time", "when the activity happened, so a window is widened or narrowed on evidence "
                         "rather than on a hunch"),
    ("batch_query", "up to twelve different queries answered in ONE call, each with its own count"),
    ("source_profile", "what one log file contains: its fields, their commonest values, its severity "
                       "mix, its detections and sample lines"),
    ("profile_entities", "up to ten entities at once, each with its extracted count AND its "
                         "free-text mention count"),
    ("entity_profile", "one entity's whole footprint: count, window, breakdown, citable samples and "
                       "the query for its own events"),
    ("find_related_events", "what else in the pool shares the entities of the events you already "
                            "have — the pivot, from ids you hold"),
    ("trace_thread", "the SAME pivot followed several hops at once: what connects to what, with the "
                     "event ids for each connection and the chains that lead out of your seed"),
    ("list_detections", "what the detection catalogue already flagged, which is evidence you have "
                        "not read yet"),
    ("list_graph_findings", "what the entity graph says — fan-out and failure-heavy relations that no "
                            "single line shows"),
    ("list_sources", "every log file in the workspace, so the next question can name one you have "
                     "not touched"),
    ("sample_events", "a spread of real lines, when you do not yet know what this evidence looks like"),
    ("get_case_state", "what is already recorded on the case, so the work is not done twice"),
    ("delegate_investigation", "two to four worker agents on separate sub-questions, at the same "
                               "time, each reporting its findings back"),
)
_ROUTE_NAMES = frozenset(name for name, _ in ROUTES)

# Tools whose question is a DSL query, and so can be varied along the query, the window and the
# sources. Kept as sets rather than a per-tool table: the advice depends on the arguments that are
# present, not on the tool's identity, and a new query tool should get the same advice for free.
QUERY_TOOLS = frozenset({"search_events", "count_events", "aggregate_events", "distinct_values",
                         "events_over_time", "sample_events", "batch_query", "get_events"})
ENTITY_TOOLS = frozenset({"entity_profile", "profile_entities", "find_related_events",
                          "trace_thread"})
GRAPH_TOOLS = frozenset({"build_graph", "graph_find", "graph_node", "graph_path", "graph_sources"})
RULE_TOOLS = frozenset({"list_detection_rules", "create_detection_rule", "update_detection_rule",
                        "preview_detection_rule", "set_builtin_rule_params"})

# An announcement of a change of plan. This is the sentence the analyst reported, in the shapes a
# model writes it. It is NOT evidence on its own — `begin_turn` only counts it when the turn also
# achieved nothing — because "a different angle" appears in perfectly good prose, and the cost of a
# false positive has to stay at one extra user turn.
_ANNOUNCE_RE = re.compile(
    r"(?:hitting|caught in|stuck in|in|another) a? ?loop"
    r"|loop(?:ing)? (?:again|here|once more)"
    r"|(?:try|take|use|attempt|switch to) (?:a |an |another |some )?"
    r"(?:different|another|new|alternative|alternate|fresh) "
    r"(?:approach|angle|tack|route|strategy|way|method|direction|path|line)"
    r"|(?:different|another|new|fresh) (?:approach|angle|tack|strategy)"
    r"|chang(?:e|ing) (?:my |the |our )?(?:approach|angle|tack|strategy|plan|direction|course)"
    r"|repeating (?:myself|the same)"
    r"|(?:same|identical) (?:call|query|result|answer|thing) again"
    r"|that (?:call|query|one) (?:was|has been|got) refused",
    re.I)
_WORD_RE = re.compile(r"[a-z0-9]+")
_PROSE_MIN = 20            # below this there is no plan in the text to repeat
_PROSE_WORDS = 24          # words of the prose that make its fingerprint
_PROSE_KEEP = 12           # fingerprints remembered per run


def call_key(name: str, args: dict[str, Any]) -> str:
    """The canonical identity of one call: tool name + arguments with the keys sorted."""
    try:
        return name + "|" + orjson.dumps(args, option=orjson.OPT_SORT_KEYS).decode()
    except TypeError:
        return name + "|" + repr(sorted(args.items()))


def _page_key(name: str, args: dict[str, Any]) -> str:
    """The identity of the QUESTION a call asks, with its paging arguments removed."""
    return call_key(name, {k: v for k, v in args.items() if k not in PAGING_KEYS})


def _tool_of(key: str) -> str:
    return key.split("|", 1)[0]


def prose_fingerprint(text: str) -> str:
    """The identity of what a turn SAID, robust to the model rewording the edges of it.

    Words only, lower-cased, the first `_PROSE_WORDS` of them. Two turns with the same fingerprint are
    the same announcement however the punctuation moved; short prose has no fingerprint at all, so a
    bare "Checking." never counts as a repeated plan.
    """
    body = (text or "").strip()
    if len(body) < _PROSE_MIN:
        return ""
    words = _WORD_RE.findall(body.lower())
    return " ".join(words[:_PROSE_WORDS])


def announces_change(text: str) -> bool:
    """Does this turn SAY it is changing approach (rather than showing it with a different call)?"""
    return bool(_ANNOUNCE_RE.search(text or ""))


def returned_something(ok: bool, result: Any) -> bool:
    """Did this call move the investigation, or is the run spinning?

    Deliberately narrow: only a REPEAT (served from the run's own dedupe cache), a REFUSAL, or an
    explicitly empty result counts as nothing new. A zero-hit search is real evidence once — ruling
    something out is work — which is why one of these changes nothing on its own; it takes a streak.
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


# ---------------------------------------------------------------- rendering advice
def _fmt_value(v: Any, cap: int = 40) -> str:
    if isinstance(v, str):
        s = v
    elif isinstance(v, (list, tuple)):
        # kept as a list in the rendering: `sources='auth.log'` reads as the string the model did not
        # send, and a refusal that misquotes the call it is refusing is worse than a longer one
        s = "[" + ", ".join(str(x) for x in v) + "]"
    else:
        s = str(v)
    s = " ".join(s.split())
    return (s[: cap - 1] + "…") if len(s) > cap else s


def _fmt_args(args: dict[str, Any], cap: int = 90) -> str:
    """One line of the arguments a call was given, short enough to sit inside a refusal."""
    if not args:
        return "(no arguments)"
    parts = [f"{k}={_fmt_value(v)!r}" for k, v in sorted(args.items())]
    out = ", ".join(parts)
    return (out[: cap - 1] + "…") if len(out) > cap else out


def pivots(name: str, args: dict[str, Any]) -> list[str]:
    """Ways to vary THIS call that are a different question, not a rewording of the same one.

    Derived from the arguments that are actually present, so nothing suggested is a no-op: there is no
    point telling a model to drop a time window it never set.
    """
    a = dict(args or {})
    q = a.get("query") if isinstance(a.get("query"), str) else None
    out: list[str] = []
    if name in QUERY_TOOLS or name in ENTITY_TOOLS:
        if a.get("from") or a.get("to"):
            out.append("the same question with the TIME WINDOW removed (drop `from`/`to`) — the "
                       "evidence may simply sit outside it")
        if a.get("sources"):
            out.append("the same question across EVERY source (drop `sources`) — you are asking one "
                       "file about something that may be in another")
        if q and len(q.split()) > 1:
            out.append("the same query with its narrowest term DROPPED — one term at a time is how "
                       "you find out which term is the empty one")
        if q and ":" in q:
            out.append("the FREE-TEXT form of that query (drop the `field:` prefix) — a `field:value` "
                       "term cannot match a source that is still RAW, and most of a fresh workspace is")
        if q == "" or q is None:
            out.append("the same tool with an actual query — an empty query is the whole pool, which "
                       "is rarely the question")
    if name in ENTITY_TOOLS:
        out.append("that value as FREE TEXT (`search_events` / `count_events` with the bare value) — "
                   "`entity:` only sees what phase 2 extracted, free text sees every raw line")
    if name in GRAPH_TOOLS:
        out.append("`graph_sources` — which files actually contribute RELATIONS; a source with "
                   "entities and no relations graphs to nothing, which looks identical to an empty graph")
    if name in RULE_TOOLS:
        out.append("`preview_detection_rule` — what a rule WOULD flag, without saving it")
    return out


def untried(tried: Iterable[str], available: Optional[Iterable[str]] = None,
            cap: int = 4) -> list[tuple[str, str]]:
    """The routes this run has not taken yet, in ROUTES order, filtered to tools it actually has."""
    seen = set(tried or ())
    have = set(available) if available is not None else _ROUTE_NAMES
    out = [(n, what) for n, what in ROUTES if n not in seen and n in have]
    return out[:cap]


def _bullets(items: Iterable[str]) -> str:
    return "".join(f"\n  - {s}" for s in items)


@dataclass
class LoopGuard:
    counts: dict[str, int] = field(default_factory=dict)    # exact call → times made; reads reset on a write
    ever: dict[str, int] = field(default_factory=dict)      # exact call → times made, never reset
    written: dict[str, int] = field(default_factory=dict)   # exact write → the ordinal of its success
    tools_tried: dict[str, int] = field(default_factory=dict)      # tool → attempts, for the advice
    tools_productive: dict[str, int] = field(default_factory=dict)  # tool → calls that returned something
    variants: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # tool → argument sets sent
    repeat_streak: int = 0
    barren_streak: int = 0
    page_streak: int = 0
    turn_calls: int = 0
    plan_repeats: int = 0        # announcements of a change of plan that changed nothing (see begin_turn)
    recoveries: int = 0          # recovery plans handed to the model
    refused_repeats: int = 0
    refused_writes: int = 0
    refused_pages: int = 0
    refused_turn_cap: int = 0
    tripped: str = ""            # why the run is being stopped; '' while it is not
    available: frozenset[str] = frozenset()   # the tools this run has; only these are ever suggested
    _write_keys: set[str] = field(default_factory=set)
    _last_key: str = ""
    _last_page_key: str = ""
    _refused_keys: list[str] = field(default_factory=list)   # what the guard has actually turned away
    _prose: list[str] = field(default_factory=list)          # fingerprints of what the turns SAID
    # the call in flight: (key, writes, kind) with kind ∈ run | repeat | refused | skipped
    _pending: tuple[str, bool, str] = ("", False, "")

    # ---------------------------------------------------------------- per turn
    def begin_turn(self, prose: str = "") -> bool:
        """A new assistant message. Returns whether it RE-ANNOUNCED a plan without changing anything.

        Its calls are counted against MAX_CALLS_PER_TURN from zero, and its PROSE is read: the
        reported symptom is a model that says "I'm hitting a loop, let me try a different approach"
        every turn, which is a loop the call-shape rules cannot see when the calls themselves differ.
        Two shapes count, and both require that nothing productive has happened since (any productive
        call clears `plan_repeats` in `observe`):
          * the turn ANNOUNCES a change of approach — and an announcement is not a change; and
          * the turn repeats prose this run has already written, whatever it says.
        """
        self.turn_calls = 0
        fp = prose_fingerprint(prose)
        repeated = bool(fp and fp in self._prose)
        declared = announces_change(prose)
        if fp:
            self._prose.append(fp)
            del self._prose[:-_PROSE_KEEP]
        if (repeated or declared) and (self.repeat_streak or self.barren_streak or self.plan_repeats):
            # ...and only while the run is already showing a loop: the first "let me take another
            # angle" of a healthy investigation is exactly what a good model says when it pivots.
            self.plan_repeats += 1
            return True
        return False

    # ---------------------------------------------------------------- before a call
    def skip(self) -> None:
        """The call will not run for a reason that is not the guard's (its arguments never parsed)."""
        self._pending = ("", False, "skipped")

    def admit(self, name: str, args: dict[str, Any], writes: bool) -> Optional[str]:
        """Decide whether this call may run. None = run it; otherwise the refusal to hand the model.

        Every attempt is COUNTED, refused or not — the model made the call, and a refused call that
        is re-sent identically is the loop this exists to catch. A refusal always names what to do
        INSTEAD (`advice`): the analyst's report was of a model told only that it was looping.
        """
        key = call_key(name, args)
        pkey = _page_key(name, args)
        self.turn_calls += 1
        if writes:
            self._write_keys.add(key)
        n = self.counts.get(key, 0)
        n_ever = self.ever.get(key, 0)
        self.counts[key] = n + 1
        self.ever[key] = n_ever + 1
        self.tools_tried[name] = self.tools_tried.get(name, 0) + 1
        seen_args = self.variants.setdefault(name, [])
        if args not in seen_args and len(seen_args) < 8:
            seen_args.append(dict(args))
        # paging: the same question as the previous call, with only its page changed
        if pkey == self._last_page_key and key != self._last_key and pkey != key:
            self.page_streak += 1
        else:
            self.page_streak = 0
        self._last_key, self._last_page_key = key, pkey
        if self.tripped:
            self._pending = (key, writes, "refused")
            return (f"this run is being stopped — {self.tripped}. No further tool calls run; write "
                    f"your final report from what is already established.")
        if self.turn_calls > MAX_CALLS_PER_TURN:
            self.refused_turn_cap += 1
            self._pending = (key, writes, "refused")
            return (f"too many tool calls in one turn — the first {MAX_CALLS_PER_TURN} ran and this "
                    f"one did not. Send the remaining calls in your next turn, fewer at a time.")
        if writes and key in self.written:
            self.refused_writes += 1
            self._refuse(key)
            self._pending = (key, writes, "repeat")
            return (f"this exact write was already made in this run (change {self.written[key]}) and "
                    f"NOTHING was changed now. Do not repeat it, and do not re-send it with only the "
                    f"wording moved — it is already on the case. Either write the NEXT finding (a "
                    f"different one), or, if the work is done, say so and give your report."
                    + self._no_announcement())
        if n >= MAX_IDENTICAL or n_ever >= MAX_IDENTICAL_EVER:
            self.refused_repeats += 1
            self._refuse(key)
            self._pending = (key, writes, "repeat")
            return (f"REFUSED — you have already made this exact call {n_ever} time(s) in this run "
                    f"({name} with {_fmt_args(args)}) and its answer is in this transcript above. It "
                    f"was NOT run again, so nothing has changed. Do ONE of these instead, in this "
                    f"turn:" + self.advice(name, args) +
                    f"\nRepeating it will end the run." + self._no_announcement())
        if self.page_streak >= MAX_PAGING:
            self.refused_pages += 1
            self._refuse(key)
            self._pending = (key, writes, "repeat")
            return (f"REFUSED — you have paged through this same query {self.page_streak} times; that "
                    f"is enumeration and this page was NOT run. Paging rows cannot answer 'how many', "
                    f"'which sources' or 'which values': use {AGGREGATES} for that in ONE call. Or do "
                    f"one of these:" + self.advice(name, args) + self._no_announcement())
        self._pending = (key, writes, "run")
        return None

    def _refuse(self, key: str) -> None:
        self._refused_keys.append(key)
        del self._refused_keys[:-8]

    def _no_announcement(self) -> str:
        """The sentence that answers the reported symptom, and only once it is warranted.

        Added from the SECOND refusal on: the first one does not need it, and a model that is not
        looping should never be lectured about a sentence it has not written.
        """
        if self.refused_repeats + self.refused_writes + self.refused_pages < 2:
            return ""
        return (" Do NOT reply with 'I am hitting a loop' or 'let me try a different approach' — an "
                "announcement is not a change and it costs the analyst a turn. Make the different "
                "call itself.")

    # ---------------------------------------------------------------- what to do instead
    def advice(self, name: str = "", args: Optional[dict[str, Any]] = None,
               pivot_cap: int = 2, route_cap: int = 2) -> str:
        """CONCRETE next moves: ways to vary the refused call, then tools this run has not called.

        This is the part a refusal was missing. It is assembled from the guard's own record, so every
        name in it is a tool the run actually has and none of the variations is a no-op.
        """
        items = pivots(name, args or {})[:pivot_cap]
        items += [f"`{tool}` — {what}" for tool, what in
                  untried(self.tools_tried, self.available or None, cap=route_cap)]
        if not items:
            items = ["a question about a source, field, entity or window you have NOT touched yet — "
                     "name it and ask it",
                     "your final report, if the objective is genuinely answered, citing the event ids "
                     "you actually saw"]
        return _bullets(items)

    def needs_recovery(self) -> bool:
        """Is this the moment to hand the model a PLAN rather than another refusal?

        Deliberately below the tripping thresholds, and bounded: the analyst asked for a model that
        can "recover and progress", and ending a run at the first loop is not recovery. Past
        MAX_RECOVERIES the streaks are left to end the run — two concrete plans ignored is evidence
        that a third will be too, and the report the work earned is worth more than six more turns.
        """
        if self.tripped or self.recoveries >= MAX_RECOVERIES:
            return False
        return self.repeat_streak >= RECOVER_AT or self.plan_repeats >= PLAN_REPEATS_AT

    def recovery(self) -> str:
        """The body of the recovery plan: what did not run, what has been tried, what has not.

        The instruction wrapper is `prompts.LOOP_RECOVERY` — this is the part only the guard knows.
        """
        self.recoveries += 1
        why = []
        if self.repeat_streak:
            why.append(f"your last {self.repeat_streak} tool call(s) repeated a call already made in "
                       f"this run, so they did not run")
        if self.plan_repeats:
            why.append(f"{self.plan_repeats} of your turns announced a change of approach and then "
                       f"did not make a different call")
        if self.barren_streak and not why:
            why.append(f"your last {self.barren_streak} tool calls returned nothing new")
        lines = ["WHERE THIS RUN IS: " + ("; ".join(why) if why else
                                          "the last several calls have not moved the investigation") + "."]
        spent = [f"{t} x{c}" for t, c in sorted(self.tools_tried.items(), key=lambda kv: -kv[1])[:6]]
        if spent:
            lines.append("ALREADY CALLED: " + ", ".join(spent) + ".")
        got = [t for t, c in sorted(self.tools_productive.items(), key=lambda kv: -kv[1]) if c][:4]
        if got:
            lines.append("These DID return evidence — build on what they gave you rather than on the "
                         "calls that were refused: " + ", ".join(got) + ".")
        if self._refused_keys:
            last = self._refused_keys[-1]
            lines.append("REFUSED, and it will stay refused: " + _tool_of(last) + " with " +
                         _fmt_args(self._args_of(last)) + ".")
        lines.append("NOT YET CALLED IN THIS RUN — each answers something different from what you "
                     "have been asking:" + self.advice(_tool_of(self._refused_keys[-1])
                                                       if self._refused_keys else "",
                                                       self._args_of(self._refused_keys[-1])
                                                       if self._refused_keys else {},
                                                       pivot_cap=3, route_cap=5))
        return "\n".join(lines)

    def _args_of(self, key: str) -> dict[str, Any]:
        try:
            return orjson.loads(key.split("|", 1)[1])
        except (IndexError, orjson.JSONDecodeError, ValueError):
            return {}

    def recovered(self) -> None:
        """The plan has been sent: clear the streaks so it gets a real chance to be followed.

        What is NOT cleared: `ever` (an identical call is still refused — the plan asks for a
        DIFFERENT call, and letting the repeated one through would make the plan a reset button), and
        `written` (a duplicate write stays refused). The fuse shortens instead — see `repeat_limit`.
        """
        self.repeat_streak = 0
        self.barren_streak = 0
        self.plan_repeats = 0

    def repeat_limit(self) -> int:
        """Consecutive repeats that end the run — shorter after each recovery plan was ignored."""
        if self.recoveries <= 0:
            return MAX_REPEAT_STREAK
        return max(2, MAX_REPEAT_STREAK - 2 * self.recoveries)

    def take_pending(self) -> tuple[str, bool, str]:
        """Hand the staged decision to the caller and clear the slot.

        `admit`/`skip` stage the call in flight and `observe` consumes it, which only works while the
        two strictly alternate. They no longer do: a lane of reads is admitted and then dispatched
        together, so the investigator takes each decision here and hands it back to `observe` with the
        result it belongs to. Everything that still calls them in pairs is unaffected.
        """
        pending, self._pending = self._pending, ("", False, "")
        return pending

    # ---------------------------------------------------------------- after a call
    def observe(self, ok: bool, result: Any, pending: Optional[tuple[str, bool, str]] = None) -> bool:
        """Record what the call in flight came back with. Returns whether it was PRODUCTIVE.

        A call the guard refused counts as a repeat; a run's own dedupe cache hit does too; anything
        else is judged on its result. This is also where the streaks trip.
        """
        key, writes, kind = pending if pending is not None else self._pending
        self._pending = ("", False, "")
        cached = bool(ok and isinstance(result, dict) and result.get("cached"))
        productive = False
        if kind == "repeat" or cached:
            self.repeat_streak += 1
            self.barren_streak += 1
        else:
            self.repeat_streak = 0
            productive = returned_something(ok, result)
            self.barren_streak = 0 if productive else self.barren_streak + 1
        if productive:
            tool = _tool_of(key)
            if tool:
                self.tools_productive[tool] = self.tools_productive.get(tool, 0) + 1
            # the model is moving again: an announcement of a change of plan was a real one
            self.plan_repeats = 0
        if kind == "run" and ok and writes and key:
            # a change landed: a later identical write is refused, and every READ may be asked again
            self.written[key] = len(self.written) + 1
            self.counts = {k: v for k, v in self.counts.items() if k in self._write_keys}
        if not self.tripped:
            if self.repeat_streak >= self.repeat_limit():
                self.tripped = (f"the last {self.repeat_streak} tool calls each repeated a call already "
                                f"made in this run" +
                                (f", and {self.recoveries} recovery plan(s) naming other calls did not "
                                 f"change that" if self.recoveries else ""))
            elif self.barren_streak >= MAX_BARREN_STREAK:
                self.tripped = (f"the last {self.barren_streak} tool calls each returned nothing new "
                                f"(repeats, refusals or empty results)")
        return productive

    # ---------------------------------------------------------------- reporting
    def stats(self) -> dict[str, Any]:
        return {"refusedRepeats": self.refused_repeats, "refusedWrites": self.refused_writes,
                "refusedPages": self.refused_pages, "refusedTurnCap": self.refused_turn_cap,
                "recoveries": self.recoveries, "tripped": self.tripped}
