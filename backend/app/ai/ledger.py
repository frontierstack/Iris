"""THE INVESTIGATION LEDGER — what has been done, and what is still open.

Two analyst reports, months apart, are the same bug seen from two sides:

    "often lower context models will perform already completed tasks [after compaction]"
    "I want the AI assistant to make better connections to things that are connected"

Both are about MEMORY OF THE INVESTIGATION rather than about the model. Everything Iris knew about a
run lived in the transcript — the tool calls, their results, the entities they turned up — and the
transcript is the one thing that gets folded away when the window fills. `ai/compaction.py` does a
careful job of carrying facts forward, but it is reconstructing them from the messages it is about to
delete, under a character cap, oldest-first. So on a small window the record of the first twenty calls
goes over the side, the model asks for them again, gets the same answers, and the run spends its
remaining budget re-deriving what it already knew.

The fix is not a better summary. It is to keep the record OUTSIDE the thing that gets summarised.

    A `Ledger` belongs to the RUN, not to the messages. Compaction cannot reach it, a provider
    refusing the transcript cannot lose it, and an in-run restart rebuilds the messages around it.
    Every fold and every restart re-renders it from the live object, so the model is handed a
    COMPLETE list of what it has already asked and a COMPLETE list of what is still open, at the
    exact moment it would otherwise have forgotten both.

It holds two things, and the second is the new one:

  WORK DONE — one line per DISTINCT call: the tool, the arguments that identify it, and what came
  back, as numbers. Keyed by `loopguard.call_key` so the ledger and the loop guard can never
  disagree about what "the same call" means. A repeat increments a counter instead of adding a line.

  OPEN LEADS — the things the evidence has turned up and nobody has followed yet. This is the half
  that did not exist anywhere. An investigation is a graph walk: a search returns an address, the
  address names an account, the account touches a host. Each of those is a LEAD, and today the only
  place a lead existed was inside a tool result the model had to notice and remember. Leads are
  harvested from the results AUTOMATICALLY (`observe`) and closed automatically when a later call
  actually goes and looks at them, so the model owes no bookkeeping turn for any of it — and the
  ledger can then answer, at any moment, the question the system prompt says decides whether an
  investigation is finished: *is there a lead left that nobody has followed?*

Design rules, each of which is load-bearing:

  • DETERMINISTIC. Nothing here asks a model anything. The same run produces the same ledger, for
    the same reason compaction and continuation are deterministic: a summarisation round-trip can
    fail, costs budget, and can drop or invent a cited id.
  • BOUNDED, and bounded by IMPORTANCE rather than by recency. `build_brief` drops its oldest lines
    first, which is exactly wrong for "do not repeat these calls" — the oldest calls are the ones
    the model has most thoroughly forgotten. A ledger that must shed lines sheds the WEAKEST
    (repeated, barren, low-signal) and says how many it dropped.
  • A LEAD IS NEVER AN INSTRUCTION TO WRITE ANYTHING. It is a question that has not been asked.
    Closing one requires a call that actually looked, not a sentence.
  • It can be rebuilt from a persisted run record (`from_records`), so a follow-up turn inherits the
    parent's ledger and does not re-walk ground the conversation already covered.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import orjson

from .loopguard import call_key

# ---------------------------------------------------------------- bounds
MAX_CALLS = 400            # distinct calls remembered; past this the weakest are shed
MAX_LEADS = 240            # leads remembered, open and closed together
RENDER_CALLS = 60          # call lines in a rendered block, before shedding
RENDER_LEADS = 14          # open leads shown; the rest are counted
ARG_CHARS = 110            # one call's arguments, in the rendered line
GIST_CHARS = 150           # one call's result, in the rendered line
WHY_CHARS = 130

# Arguments that identify WHAT was asked rather than how much of it was wanted. A call that differs
# only by `limit` asked the same question, and printing `limit=50` in a one-line record spends a
# fifth of the line on the least informative thing in it.
_NOISE_ARGS = frozenset({"limit", "offset", "page", "cursor", "include", "scope", "maxRows", "top"})

# How much a lead of each kind is worth before its own evidence is weighed in. An entity is the unit
# an investigation actually pivots on; a source that has never been read is a whole seam of evidence;
# a detection that fired is somebody else's judgement that something matters.
_KIND_WEIGHT = {
    "entity": 1.0, "peer": 1.05, "source": 0.9, "detection": 0.95,
    "host": 0.85, "user": 0.95, "file": 0.6, "question": 0.8,
}

#: A value that is never worth following on its own — it is a container, not a lead.
_NOISE_VALUES = frozenset({"", "-", "n/a", "none", "null", "unknown", "0.0.0.0", "127.0.0.1", "::1",
                           "localhost", "info", "low", "medium", "high", "critical",
                           "success", "failure", "denied", "true", "false"})

_WS = re.compile(r"\s+")


def _clip(v: Any, limit: int) -> str:
    s = "" if v is None else str(v)
    s = _WS.sub(" ", s).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


@dataclass
class Call:
    """One distinct question this run has asked, and the answer it got."""
    name: str
    args: str            # the identifying arguments, already rendered and clipped
    gist: str = ""       # what came back, as numbers
    n: int = 1           # times asked (a repeat bumps this, it never adds a line)
    step: int = 0
    ok: bool = True
    productive: bool = True

    def line(self) -> str:
        head = f"{self.name}({self.args})"
        tail = self.gist or ("refused" if not self.ok else "nothing")
        rep = f"  [asked {self.n}x]" if self.n > 1 else ""
        return f"{head} -> {tail}{rep}"

    def weight(self) -> float:
        """How much this line is worth keeping when the block has to be shortened.

        A REFUSED or BARREN call is worth MORE than it looks: "I already asked that and it returned
        nothing" is precisely the line that stops it being asked a third time. What is worth least
        is a call that has already been repeated, because its answer is evidently memorable.
        """
        w = 1.0
        if not self.ok:
            w += 0.5
        if not self.productive:
            w += 0.4
        w -= 0.15 * (self.n - 1)
        return w


@dataclass
class Lead:
    """Something the evidence turned up that nobody has looked at yet."""
    key: str
    kind: str
    value: str
    why: str = ""
    weight: float = 1.0
    step: int = 0
    state: str = "open"        # open | followed | dismissed
    closed_by: str = ""        # the call that covered it

    def line(self) -> str:
        why = f" — {_clip(self.why, WHY_CHARS)}" if self.why else ""
        return f"{self.kind} {self.value}{why}"


def _norm(value: Any) -> str:
    return _WS.sub(" ", str(value or "")).strip()


def _lead_key(kind: str, value: str) -> str:
    return f"{kind}:{value.lower()}"


def _ident_args(args: dict[str, Any]) -> str:
    """The arguments that say WHAT was asked, rendered for a one-line record."""
    keep = {k: v for k, v in (args or {}).items() if k not in _NOISE_ARGS and v not in (None, "", [], {})}
    if not keep:
        return ""
    parts = []
    for k in sorted(keep):
        v = keep[k]
        if isinstance(v, (list, tuple)):
            v = f"[{len(v)} item(s)]" if len(v) > 3 else ", ".join(_clip(x, 40) for x in v)
        elif isinstance(v, dict):
            v = f"{{{len(v)} key(s)}}"
        parts.append(f"{k}={_clip(v, 60)}")
    return _clip(", ".join(parts), ARG_CHARS)


def result_gist(result: Any) -> str:
    """A tool result reduced to the numbers that matter.

    Deliberately the same JOB as `compaction._result_gist` and deliberately not the same function:
    that one starts from a JSON STRING (it reads a transcript message) and this one from the live
    object, and making either parse the other's input would put a serialise/deserialise round trip
    on the hot path of every tool call for no gain.
    """
    if isinstance(result, str):
        return _clip(result, GIST_CHARS)
    if not isinstance(result, dict):
        return _clip(result, GIST_CHARS)
    if result.get("error"):
        return "refused: " + _clip(result["error"], GIST_CHARS - 9)
    keep: dict[str, Any] = {}
    for k in ("total", "count", "hits", "returned", "distinctGroups", "distinctValues", "relatedEvents",
              "seeds", "nodes", "edges", "sharePercent", "caseId", "noteId", "iocId", "ruleId", "added"):
        v = result.get(k)
        if isinstance(v, (int, float, str)) and not isinstance(v, bool):
            keep[k] = v
    for k, v in result.items():
        if isinstance(v, list) and k not in keep:
            keep[k] = f"{len(v)} item(s)"
    if not keep:
        # A shape with no counts and no lists in it: say WHICH keys came back rather than dumping the
        # body. The body is what the model already has in the transcript; the ledger line exists to
        # be readable after the transcript is gone, and 150 characters of JSON is neither.
        names = ", ".join(sorted(result)[:8])
        return _clip(f"returned {names}" if names else "empty result", GIST_CHARS)
    return _clip(", ".join(f"{k}={v}" for k, v in keep.items()), GIST_CHARS)


# ---------------------------------------------------------------- lead harvesting
#
# Each entry is (result key, lead kind, why-template). The shapes are the ones the read tools
# actually return — `find_related_events` co-occurrence, an `aggregate_events` breakdown, the graph
# findings, the detection roll-up — so a tool that answers one of those questions feeds the ledger
# without knowing the ledger exists.
_VALUE_LISTS: tuple[tuple[str, str, str], ...] = (
    ("coOccurringEntities", "entity", "co-occurs with what you pivoted from"),
    ("connections", "entity", "connected by the thread trace"),
    ("byHost", "host", "carries the activity"),
    ("byUser", "user", "carries the activity"),
    ("byDetection", "detection", "fired on these events"),
    ("relatedEntities", "entity", "shares events with the subject"),
    ("topEntities", "entity", "prominent in this source"),
)
_TOP_PER_LIST = 6


class Ledger:
    """The record of one investigation. Owned by the run; never part of the transcript."""

    def __init__(self) -> None:
        self.calls: dict[str, Call] = {}
        self.leads: dict[str, Lead] = {}
        self.writes: list[str] = []
        self.shed_calls = 0
        self.shed_leads = 0
        self._seen_values: set[str] = set()   # every value any call has ASKED about, lower-cased

    # ------------------------------------------------------------ observing
    def observe(self, name: str, args: dict[str, Any], ok: bool, result: Any, *,
                step: int = 0, productive: bool = True) -> None:
        """Record one finished tool call: the question, the answer, and the leads it turned up."""
        args = args if isinstance(args, dict) else {}
        key = call_key(name, args)
        existing = self.calls.get(key)
        if existing is not None:
            existing.n += 1
        else:
            self.calls[key] = Call(name=name, args=_ident_args(args), gist=result_gist(result),
                                   step=step, ok=bool(ok), productive=bool(productive))
            self._shed_calls()
        # Anything this call NAMED is a thing somebody has now looked at — a lead about it is closed
        # whether it was the call's subject or one of its filters.
        self._close_from_args(name, args)
        if ok:
            self._harvest(name, args, result, step)

    def note_write(self, action: dict[str, Any]) -> None:
        line = f"{action.get('tool')}: {_clip(action.get('summary'), 160)}"
        if line not in self.writes:
            self.writes.append(line)

    def dismiss(self, kind: str, value: str, why: str = "") -> None:
        lead = self.leads.get(_lead_key(kind, _norm(value)))
        if lead is not None and lead.state == "open":
            lead.state = "dismissed"
            lead.closed_by = why

    # ------------------------------------------------------------ leads
    def add_lead(self, kind: str, value: Any, why: str = "", weight: float = 1.0, step: int = 0) -> None:
        v = _norm(value)
        if not v or v.lower() in _NOISE_VALUES or len(v) > 160:
            return
        key = _lead_key(kind, v)
        if key in self.leads:
            # Seen again by another call: it is more central than the first sighting suggested.
            self.leads[key].weight = max(self.leads[key].weight, weight)
            return
        state = "followed" if v.lower() in self._seen_values else "open"
        self.leads[key] = Lead(key=key, kind=kind, value=v, why=why,
                               weight=weight * _KIND_WEIGHT.get(kind, 1.0), step=step, state=state,
                               closed_by="already looked at when it was first seen" if state == "followed" else "")
        self._shed_leads()

    def open_leads(self) -> list[Lead]:
        out = [l for l in self.leads.values() if l.state == "open"]
        out.sort(key=lambda l: (-l.weight, l.step, l.value))
        return out

    def counts(self) -> dict[str, int]:
        states = {"open": 0, "followed": 0, "dismissed": 0}
        for l in self.leads.values():
            states[l.state] = states.get(l.state, 0) + 1
        return {"calls": len(self.calls), "writes": len(self.writes), **states}

    # ------------------------------------------------------------ rendering
    def render(self, *, max_chars: int = 4000, leads: int = RENDER_LEADS,
               calls: int = RENDER_CALLS) -> str:
        """The block handed to the model. Empty when the run has not done anything yet."""
        work = self.render_work(calls)
        opened = self.render_leads(leads)
        # `self.writes` counts too. Without it a ledger holding only writes rendered the empty
        # string, so a fold early in a run that had already put something on the case dropped the
        # one section that stops the model writing it a second time.
        if not work and not opened and not self.writes:
            return ""
        parts = [H_LEDGER]
        if work:
            parts.append(H_DONE + work)
        if self.writes:
            parts.append(H_WROTE + "\n".join("- " + w for w in self.writes[-30:]))
        parts.append(opened or H_NO_LEADS)
        block = "\n".join(parts)
        if len(block) <= max_chars:
            return block
        # The OPEN LEADS are what the run does next, so they survive a squeeze and the call list is
        # what gives way — shortened from the least informative end, never silently.
        room = max(400, max_chars - len(H_LEDGER) - len(opened) - 200)
        work = self.render_work(calls, max_chars=room)
        parts = [H_LEDGER] + ([H_DONE + work] if work else []) + [opened or H_NO_LEADS]
        return "\n".join(parts)[:max_chars]

    def render_work(self, limit: int = RENDER_CALLS, max_chars: int = 0) -> str:
        if not self.calls:
            return ""
        ordered = sorted(self.calls.values(), key=lambda c: (-c.weight(), c.step))
        shown = ordered[:limit]
        dropped = len(ordered) - len(shown)
        lines = [c.line() for c in sorted(shown, key=lambda c: c.step)]
        if max_chars:
            out: list[str] = []
            used = 0
            for line in lines:
                if used + len(line) + 1 > max_chars:
                    dropped += len(lines) - len(out)
                    break
                out.append(line)
                used += len(line) + 1
            lines = out
        if dropped > 0 or self.shed_calls:
            names = sorted({c.name for c in ordered[len(lines):]})
            lines.append(f"({dropped + self.shed_calls} further call(s) not listed"
                         + (": " + ", ".join(names[:10]) if names else "")
                         + " — they were made and answered; ask something NEW.)")
        return "\n".join(lines)

    def render_leads(self, limit: int = RENDER_LEADS) -> str:
        opened = self.open_leads()
        if not opened:
            return ""
        shown = opened[:limit]
        lines = [f"{i + 1}. {l.line()}" for i, l in enumerate(shown)]
        if len(opened) > len(shown):
            lines.append(f"… and {len(opened) - len(shown)} more.")
        done = sum(1 for l in self.leads.values() if l.state != "open")
        tail = f"\n({done} lead(s) already followed or ruled out.)" if done else ""
        return H_OPEN + "\n".join(lines) + tail

    # ------------------------------------------------------------ internals
    def _close_from_args(self, name: str, args: dict[str, Any]) -> None:
        """A call that NAMES a value has looked at it — every lead about it is closed.

        Matched against the whole serialised argument blob rather than against one parameter: the
        value can arrive as `query='entity:"10.0.0.5"'`, as `entities:[...]`, as `sourceId`, or
        inside a batch of twelve queries, and enumerating those per tool is a list that would go
        out of date the first time a tool grew a parameter.
        """
        try:
            blob = orjson.dumps(args).decode().lower()
        except TypeError:
            blob = str(args).lower()
        for lead in self.leads.values():
            if lead.state == "open" and lead.value.lower() in blob:
                lead.state = "followed"
                lead.closed_by = name
        # Remember the values this run has asked about, so a lead HARVESTED later for something
        # already investigated does not come back as open work.
        for token in _values_in(args):
            self._seen_values.add(token)

    def _harvest(self, name: str, args: dict[str, Any], result: Any, step: int) -> None:
        if not isinstance(result, dict):
            return
        # A tool that already ranks its own leads (trace_thread) is believed: it did the scoring
        # against the pool, which nothing here can do from a result body.
        for item in _rows(result, "leads")[:RENDER_LEADS]:
            if isinstance(item, dict):
                self.add_lead(str(item.get("kind") or "entity"), item.get("value"),
                              str(item.get("why") or ""), float(item.get("weight") or 1.0), step)
        for key, kind, why in _VALUE_LISTS:
            rows = result.get(key)
            if not isinstance(rows, list):
                continue
            for row in rows[:_TOP_PER_LIST]:
                value, count = _value_count(row)
                if value:
                    self.add_lead(kind, value, f"{why} ({count} events)" if count else why,
                                  _count_weight(count), step)
        # A breakdown is a list of leads when it is a breakdown BY something pivotable.
        group_by = str(args.get("groupBy") or "")
        kind = {"entity": "entity", "host": "host", "user": "user",
                "detection": "detection", "source": "source", "file": "source"}.get(group_by, "")
        if kind:
            for row in _rows(result, "groups")[:_TOP_PER_LIST]:
                value, count = _value_count(row)
                if value:
                    self.add_lead(kind, value, f"{count} events in the {group_by} breakdown" if count
                                  else f"a value of {group_by}", _count_weight(count), step)
        # A graph finding is about a PAIR, and the PEER is the half nobody has looked at.
        for f in _rows(result, "findings")[:RENDER_LEADS]:
            if not isinstance(f, dict):
                continue
            peer = f.get("peer") or f.get("peerValue") or _node_value(f.get("peerId"))
            subject = f.get("entity") or f.get("value") or _node_value(f.get("nodeId"))
            why = _clip(f.get("title") or f.get("summary") or f.get("ruleName") or "a graph finding", WHY_CHARS)
            if subject:
                self.add_lead("entity", subject, why, 1.4, step)
            if peer:
                self.add_lead("peer", peer, f"the other end of: {why}", 1.5, step)
        # A source nobody has read is a seam of evidence, and a RAW one is invisible to every
        # entity: query the run has made — which is the silent-omission case, not a preference.
        for s in _rows(result, "sources")[:24]:
            if not isinstance(s, dict):
                continue
            state = str(s.get("enrich") or s.get("state") or "").lower()
            if state == "raw":
                self.add_lead("source", s.get("file") or s.get("id"),
                              "still RAW — invisible to entity: and field: queries; read it as free text",
                              1.2, step)

    def _shed_calls(self) -> None:
        if len(self.calls) <= MAX_CALLS:
            return
        ordered = sorted(self.calls.items(), key=lambda kv: (kv[1].weight(), -kv[1].step))
        for key, _c in ordered[: len(self.calls) - MAX_CALLS]:
            self.calls.pop(key, None)
            self.shed_calls += 1

    def _shed_leads(self) -> None:
        if len(self.leads) <= MAX_LEADS:
            return
        # closed leads first, then the weakest open ones
        ordered = sorted(self.leads.items(),
                         key=lambda kv: (kv[1].state == "open", kv[1].weight, -kv[1].step))
        for key, _l in ordered[: len(self.leads) - MAX_LEADS]:
            self.leads.pop(key, None)
            self.shed_leads += 1

    # ------------------------------------------------------------ rebuilding from a record
    @classmethod
    def from_records(cls, records: Iterable[dict[str, Any]]) -> "Ledger":
        """The ledger of a conversation, rebuilt from the persisted run records.

        A follow-up turn inherits it, so "now build me the timeline" does not re-ask the twenty
        questions the previous turn already answered. Only the CALLS and the WRITES can be recovered
        this way — `ai/history.py` stores a tool entry's name, arguments and result SUMMARY, not the
        result body, so the leads a result carried are not in the record. A follow-up therefore
        starts with an accurate "already done" list and an empty lead list, which is the honest
        shape: an unfollowed lead nobody wrote down is not evidence that it is still open.
        """
        led = cls()
        for rec in records:
            for e in rec.get("transcript") or []:
                if e.get("kind") != "tool":
                    continue
                args = e.get("args") if isinstance(e.get("args"), dict) else {}
                name = str(e.get("name") or "tool")
                key = call_key(name, args)
                if key in led.calls:
                    led.calls[key].n += 1
                    continue
                led.calls[key] = Call(name=name, args=_ident_args(args),
                                      gist=_clip(e.get("summary"), GIST_CHARS),
                                      step=int(e.get("step") or 0), ok=e.get("ok") is not False)
                led._shed_calls()
            for a in rec.get("actions") or []:
                if not a.get("undone"):
                    led.note_write(a)
        return led


# ---------------------------------------------------------------- headers
#
# Named constants because `ai/compaction.py` has to find these sections again in an EARLIER brief in
# order to carry them forward, exactly as it already does for its own — see its `_section`.
H_LEDGER = ("INVESTIGATION LEDGER — kept by Iris outside the conversation, so it is COMPLETE and "
            "was not summarised. It is authoritative: if a call is listed here it has been made, "
            "whatever the messages above do or do not still show.")
H_DONE = ("\nALREADY ASKED AND ANSWERED — do NOT make any of these calls again; the answer is on "
          "the line:\n")
H_WROTE = "\nALREADY WRITTEN TO THE CASE — do not write these again:\n"
H_OPEN = ("\nOPEN LEADS — things this investigation turned up and has NOT yet looked at. This is "
          "your work queue: take the next call from here rather than re-asking something above. A "
          "lead is closed by a CALL that looks at it, or by one sentence in your report saying why it "
          "does not matter — never by ignoring it.\n")
H_NO_LEADS = ("\nOPEN LEADS: none. Every lead the evidence produced has been followed. If the "
              "objective is answered, record what is left to record and write the report.")
_HEADERS = (H_DONE, H_WROTE, H_OPEN)


def is_ledger(text: str) -> bool:
    return (text or "").lstrip().startswith(H_LEDGER[:48])


def _rows(result: dict[str, Any], key: str) -> list[Any]:
    """The value at `key` when it is a LIST, else nothing.

    Every one of these keys is a list in one tool and a NUMBER in another — `get_case_state` reports
    `sources` as a count, `workspace_overview` as the list — and a bare `result.get(key) or []`
    happily slices an int and raises `TypeError: 'int' object is not subscriptable` out of the
    ledger, which ends the RUN. The ledger is bookkeeping: it may never be the thing that fails an
    investigation, so every shape it reads is checked rather than assumed.
    """
    v = result.get(key)
    return v if isinstance(v, list) else []


def _value_count(row: Any) -> tuple[str, int]:
    if isinstance(row, dict):
        v = row.get("value") if row.get("value") is not None else row.get("name")
        n = row.get("count") if isinstance(row.get("count"), int) else row.get("hits")
        return _norm(v), int(n) if isinstance(n, int) else 0
    if isinstance(row, str):
        return _norm(row), 0
    return "", 0


def _count_weight(count: int) -> float:
    """How strong a lead is, from how much evidence sits behind it.

    Deliberately FLAT-ISH and deliberately capped. A value on ten thousand events is usually
    infrastructure — the proxy, the resolver, the domain controller — and a picker that ranked
    purely by count would put the least interesting thing in the workspace at the top of the queue
    every time. A lead seen a handful of times, in the company of something already suspicious, is
    the one worth a call.
    """
    if count <= 0:
        return 1.0
    if count > 50_000:
        return 0.55
    if count > 5_000:
        return 0.8
    if count < 5:
        return 1.15
    return 1.0


def _node_value(node_id: Any) -> str:
    """`ip:10.0.0.5` -> `10.0.0.5`. A graph node id is typed, and the TYPE is not the lead.

    Split ONLY on a known node type, never on any colon. A first attempt guessed from the shape of
    the rest ("does it look like an address?") and got `ip:103.156.38.160` wrong, which turned the
    peer of a graph finding into a lead nobody could search for. `graph.NODE_TYPES` is the exact
    answer and it is the same list the ids are built from, so the two cannot drift.
    """
    s = _norm(node_id)
    head, sep, rest = s.partition(":")
    if sep and rest:
        from ..graph import NODE_TYPES
        if head in NODE_TYPES:
            return rest
    return s


def _values_in(args: Any, out: Optional[set[str]] = None) -> set[str]:
    """Every scalar string in an argument tree, lower-cased — what this call looked at."""
    if out is None:
        out = set()
    if isinstance(args, dict):
        for v in args.values():
            _values_in(v, out)
    elif isinstance(args, (list, tuple)):
        for v in args:
            _values_in(v, out)
    elif isinstance(args, str) and 0 < len(args) <= 160:
        out.add(args.lower())
    return out
