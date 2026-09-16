"""Loop guarding for the investigator: what ends a run whose model has stopped moving.

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
     report the work earned and can press Continue: MAX_REPEAT_STREAK consecutive repeats (a tight loop,
     caught early), or MAX_BARREN_STREAK consecutive calls that each returned nothing new (repeats,
     refusals or empty results — the wide net, by which point the check-in has asked twice for a
     different angle). A single productive call resets both, so a run that is still finding things is
     never interrupted however long it is.

The guard is a pure state machine: `admit` before a call, `observe` after it, `tripped` between. It
holds no reference to the store, the client or the run, so `tests/test_ai_loop_guard.py` drives it
directly as well as through the investigator.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import orjson

MAX_IDENTICAL = 2          # times one exact call may be made; the next is refused
MAX_IDENTICAL_EVER = 8     # ...and an absolute per-run cap on one exact call that no write resets
MAX_REPEAT_STREAK = 6      # consecutive repeats (cached, or refused as a repeat / a page) end the run
MAX_BARREN_STREAK = 24     # consecutive calls with nothing new end the run
MAX_PAGING = 8             # consecutive pages of one question before the next page is refused
MAX_CALLS_PER_TURN = 24    # tool calls one assistant message may carry; the rest are refused
# Arguments that turn one question into many pages of it. `limit` is included: asking for the same
# query with a bigger limit is "more of the same", and it is counted as a page rather than refused.
PAGING_KEYS = ("offset", "limit", "page", "cursor")
# What replaces paging: the answer to "how many / which sources / which values" in ONE call.
AGGREGATES = "aggregate_events, count_events, distinct_values, events_over_time or entity_profile"


def call_key(name: str, args: dict[str, Any]) -> str:
    """The canonical identity of one call: tool name + arguments with the keys sorted."""
    try:
        return name + "|" + orjson.dumps(args, option=orjson.OPT_SORT_KEYS).decode()
    except TypeError:
        return name + "|" + repr(sorted(args.items()))


def _page_key(name: str, args: dict[str, Any]) -> str:
    """The identity of the QUESTION a call asks, with its paging arguments removed."""
    return call_key(name, {k: v for k, v in args.items() if k not in PAGING_KEYS})


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


@dataclass
class LoopGuard:
    counts: dict[str, int] = field(default_factory=dict)    # exact call → times made; reads reset on a write
    ever: dict[str, int] = field(default_factory=dict)      # exact call → times made, never reset
    written: dict[str, int] = field(default_factory=dict)   # exact write → the ordinal of its success
    repeat_streak: int = 0
    barren_streak: int = 0
    page_streak: int = 0
    turn_calls: int = 0
    refused_repeats: int = 0
    refused_writes: int = 0
    refused_pages: int = 0
    refused_turn_cap: int = 0
    tripped: str = ""            # why the run is being stopped; '' while it is not
    _write_keys: set[str] = field(default_factory=set)
    _last_key: str = ""
    _last_page_key: str = ""
    # the call in flight: (key, writes, kind) with kind ∈ run | repeat | refused | skipped
    _pending: tuple[str, bool, str] = ("", False, "")

    # ---------------------------------------------------------------- per turn
    def begin_turn(self) -> None:
        """A new assistant message: its calls are counted against MAX_CALLS_PER_TURN from zero."""
        self.turn_calls = 0

    # ---------------------------------------------------------------- before a call
    def skip(self) -> None:
        """The call will not run for a reason that is not the guard's (its arguments never parsed)."""
        self._pending = ("", False, "skipped")

    def admit(self, name: str, args: dict[str, Any], writes: bool) -> Optional[str]:
        """Decide whether this call may run. None = run it; otherwise the refusal to hand the model.

        Every attempt is COUNTED, refused or not — the model made the call, and a refused call that
        is re-sent identically is the loop this exists to catch.
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
            self._pending = (key, writes, "repeat")
            return (f"this exact write was already made in this run (change {self.written[key]}) and "
                    f"NOTHING was changed now. Do not repeat it. If you meant to change something, send "
                    f"different arguments; if the work is done, say so and report.")
        if n >= MAX_IDENTICAL or n_ever >= MAX_IDENTICAL_EVER:
            self.refused_repeats += 1
            self._pending = (key, writes, "repeat")
            return (f"you have already made this exact call {n_ever} time(s) in this run and its answer "
                    f"has not changed — it was NOT run again. Change the arguments, take a different "
                    f"angle, or write your report. Repeating it will end the run.")
        if self.page_streak >= MAX_PAGING:
            self.refused_pages += 1
            self._pending = (key, writes, "repeat")
            return (f"you have paged through this same query {self.page_streak} times — that is "
                    f"enumeration, and it was NOT run. Paging rows cannot answer 'how many', 'which "
                    f"sources' or 'which values': use {AGGREGATES} for that in ONE call, or narrow the "
                    f"query to the rows you actually need to read.")
        self._pending = (key, writes, "run")
        return None

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
        if kind == "run" and ok and writes and key:
            # a change landed: a later identical write is refused, and every READ may be asked again
            self.written[key] = len(self.written) + 1
            self.counts = {k: v for k, v in self.counts.items() if k in self._write_keys}
        if not self.tripped:
            if self.repeat_streak >= MAX_REPEAT_STREAK:
                self.tripped = (f"the last {self.repeat_streak} tool calls each repeated a call already "
                                f"made in this run")
            elif self.barren_streak >= MAX_BARREN_STREAK:
                self.tripped = (f"the last {self.barren_streak} tool calls each returned nothing new "
                                f"(repeats, refusals or empty results)")
        return productive

    # ---------------------------------------------------------------- reporting
    def stats(self) -> dict[str, Any]:
        return {"refusedRepeats": self.refused_repeats, "refusedWrites": self.refused_writes,
                "refusedPages": self.refused_pages, "refusedTurnCap": self.refused_turn_cap,
                "tripped": self.tripped}
