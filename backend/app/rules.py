"""Custom detection rules (raw regex OR composed conditions) + built-in rule catalogue exposure.

Custom rules persist in $IRIS_DATA_DIR/rules.json = {"rules": [...], "disabledBuiltins": [...], "seq": n}.

Evaluation is guarded in TWO layers, because either one alone is insufficient:

1. Save time — `catastrophic_reason()` rejects the classic ReDoS shapes (a repeated group whose body is nothing
   but unbounded quantifiers, or whose alternatives match the same text) with a 400 that says WHY. This is a
   heuristic: it is defence in depth, NOT a guarantee, and it deliberately never fires on the shipped built-ins.
2. Evaluation time — a real, interruptible deadline. `re` never releases the GIL while backtracking, so the old
   "run it in a thread and abandon the thread" trick only *reported* a timeout: the runaway thread kept burning a
   core and pinned the whole interpreter. The optional `regex` module (requirements.txt) accepts `timeout=` on
   every match call and aborts the match itself, so `SafePattern.search` hands it the time remaining in the pass
   and a pathological pattern unwinds instead of hanging the app. The worker thread is still there as the outer
   guard for non-regex slowness (huge event sets, condition evaluation).

Without the `regex` module the engine falls back to `re`: layer 1 still applies and the request still returns
after RULE_TIMEOUT_S, but the abandoned thread cannot be killed — see REGEX_ENGINE / SANDBOX_NOTE.
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

import numpy as np

try:  # optional: `regex` is `re`-compatible AND supports a real timeout= on match calls
    import regex as _regex  # type: ignore[import-untyped]
except Exception:  # pragma: no cover - the app must run without it
    _regex = None

REGEX_ENGINE = "regex" if _regex is not None else "re"
SANDBOX_NOTE = ("evaluation deadlines are enforced inside the match" if _regex is not None else
                "the `regex` module is not installed: a runaway match cannot be interrupted, only reported")

from . import config
from .detect import (MAX_CONDITIONS, PARAMS as BUILTIN_PARAMS, all_builtin_rules, condition_pred,
                     condition_values, conditions_trigger, find_bursts, param_spec, parse_condition, parse_param,
                     regex_trigger)

# Registers the ENTITY-GRAPH rules into the shipped catalogue (detect.EXTRA_RULES). Imported for the
# side effect on purpose: the rules store is the one place that has to know about every built-in, and a
# catalogue that depends on some other module having been imported first is a catalogue that is
# sometimes short a dozen rules.
from . import graph_rules  # noqa: F401
from .models import (EMPTY_LIST, Detection, Event, Rule, RuleCondition, RuleFlags, RuleInput,
                     RuleParam, RulePattern, RuleTestInput, RuleThreshold, max_sev)

MAX_PATTERN_LEN = 2000
RULE_TIMEOUT_S = 5.0
FIXED_FIELDS = ("msg", "raw", "host", "user", "source", "file")
MAX_WINDOW_S = 86400 * 7


def _param_value(ov: dict[str, Any], rule_id: str, spec: Any) -> str:
    """The value a built-in's parameter is actually running with: the analyst's override if it is valid,
    otherwise the shipped default. Also understands the legacy bare `pattern` override written before
    conditions were fully parameterised."""
    raw = ov.get("params")
    if isinstance(raw, dict) and raw.get(spec.key) is not None:
        candidate = str(raw[spec.key])
    elif spec.kind == "regex" and spec.key == "pattern" and ov.get("pattern"):
        candidate = str(ov["pattern"])
    else:
        return spec.default
    try:
        value = parse_param(spec, candidate)
    except ValueError:
        return spec.default
    # a catastrophic override stored by an older build must degrade to the shipped behaviour, never
    # silently switch the rule off (and never reach detect.run_rules, which matches on bare `re`)
    if spec.kind == "regex" and catastrophic_reason(value):
        return spec.default
    return value


class RuleError(ValueError):
    """Invalid rule definition (bad regex etc.) -> HTTP 400 in the router."""


class RuleTimeout(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(ts: str) -> float:
    """Event timestamp → epoch seconds for the windowed (threshold) rules. Unparsable → 0.0, which simply
    keeps that event out of every window instead of raising inside the rule engine."""
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return 0.0


# ------------------------------------------------------------------ layer 1: static ReDoS screening
# A tiny structural reader for a pattern. It is NOT a regex parser — it only needs to answer "is this a
# repeated group whose body can match the same text in exponentially many ways", which is the shape behind
# essentially every ReDoS report. Anything it is unsure about it lets through; layer 2 is what actually holds.
_LITERAL_BRANCH = re.compile(r"[A-Za-z0-9_ /:@,;=~%!'\"<>#&-]*\Z")


def _split_alternatives(body: str) -> list[str]:
    """Top-level `|` branches of `body`, respecting escapes, [...] classes and (...) nesting."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    cls = esc = False
    for ch in body:
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\":
            cur.append(ch)
            esc = True
            continue
        if cls:
            cur.append(ch)
            if ch == "]":
                cls = False
            continue
        if ch == "[":
            cls = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return parts


def _atoms(branch: str) -> list[tuple[str, str]]:
    """`branch` split into (atom, quantifier) pairs. Quantifier is '' when the atom is not repeated."""
    out: list[tuple[str, str]] = []
    i, n = 0, len(branch)
    while i < n:
        ch = branch[i]
        if ch == "\\":
            atom, i = branch[i:i + 2], i + 2
        elif ch == "[":
            j = i + 1
            if j < n and branch[j] == "^":
                j += 1
            if j < n and branch[j] == "]":
                j += 1
            while j < n and branch[j] != "]":
                j += 2 if branch[j] == "\\" else 1
            atom, i = branch[i:j + 1], j + 1
        elif ch == "(":
            j, depth, esc, cls = i, 0, False, False
            while j < n:
                c = branch[j]
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif cls:
                    cls = c != "]"
                elif c == "[":
                    cls = True
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            atom, i = branch[i:j + 1], j + 1
        else:
            atom, i = ch, i + 1
        quant = ""
        if i < n and branch[i] in "*+?":
            quant, i = branch[i], i + 1
        elif i < n and branch[i] == "{":
            j = branch.find("}", i)
            if j != -1 and re.fullmatch(r"\{\d*(,\d*)?\}", branch[i:j + 1]):
                quant, i = branch[i:j + 1], j + 1
        if quant and i < n and branch[i] in "?+":  # lazy / possessive suffix
            quant, i = quant + branch[i], i + 1
        out.append((atom, quant))
    return out


def _unbounded(quant: str) -> bool:
    """True for a quantifier with no upper bound: * + {n,} (and their lazy/possessive spellings)."""
    if not quant:
        return False
    if quant[0] in "*+":
        return True
    if quant[0] == "{" and "}" in quant:
        inner = quant[1:quant.index("}")]
        return "," in inner and inner.split(",", 1)[1] == ""
    return False


def _group_body(atom: str) -> Optional[str]:
    """Body of a `(...)` atom, or None when it is not a plain/capturing/non-capturing group (lookarounds,
    inline flags and conditionals never repeat in the dangerous way and are skipped)."""
    if not (atom.startswith("(") and atom.endswith(")")):
        return None
    inner = atom[1:-1]
    if inner.startswith("?"):
        m = re.match(r"\?(P<[^>]*>|<[A-Za-z_][^>]*>|:|>)", inner)
        if not m:
            return None
        inner = inner[m.end():]
    return inner


def _risky_body(body: str) -> Optional[str]:
    """Why repeating `body` is exponential, or None."""
    branches = _split_alternatives(body)
    if len(branches) > 1:
        literal = [b for b in branches if _LITERAL_BRANCH.match(b)]
        for i, a in enumerate(literal):
            for b in literal[i + 1:]:
                if a == b or a.startswith(b) or b.startswith(a):
                    pair = f"'{a}' and '{b}'" if a != b else f"'{a}' twice"
                    return (f"the repeated group ({body}) has alternatives that match the same text ({pair}), "
                            "so a non-matching line can be split between them in exponentially many ways")
    for br in branches:
        atoms = _atoms(br)
        if atoms and all(_unbounded(q) for _a, q in atoms):
            return (f"the repeated group ({body}) is itself made only of unbounded quantifiers "
                    "(nested quantifiers), which backtracks exponentially on a line that does not match")
    return None


def catastrophic_reason(pattern: str) -> Optional[str]:
    """Plain-English reason this pattern is a catastrophic-backtracking risk, or None.

    Deliberately conservative — it must never reject a legitimate rule (test_rule_sandbox.py asserts every
    shipped built-in regex and every pattern used by the test suite passes). Patterns it cannot classify are
    allowed through and caught by the evaluation deadline instead.
    """
    if not isinstance(pattern, str):
        return None
    try:
        return _scan_fragment(pattern, 0)
    except Exception:  # pragma: no cover - a screening heuristic must never break a save
        return None


def _scan_fragment(fragment: str, depth: int) -> Optional[str]:
    if depth > 12:  # pragma: no cover - absurd nesting; let layer 2 handle it
        return None
    for branch in _split_alternatives(fragment):
        for atom, quant in _atoms(branch):
            body = _group_body(atom)
            if body is None:
                continue
            if _unbounded(quant):
                reason = _risky_body(body)
                if reason:
                    return reason
            reason = _scan_fragment(body, depth + 1)
            if reason:
                return reason
    return None


def screen_pattern(pattern: str, what: str = "pattern") -> None:
    """Raise RuleError (→ 400) when `pattern` has an obviously catastrophic shape. Save time only."""
    reason = catastrophic_reason(pattern)
    if reason:
        raise RuleError(f"{what} rejected: {reason}. Rewrite it (for example make the inner repetition "
                        "bounded, or give the alternatives distinct prefixes).")


# ------------------------------------------------------------------ layer 2: compile / match with a deadline
_DEADLINE = threading.local()


class SafePattern:
    """A compiled pattern whose `.search()` honours the deadline of the evaluation pass it runs in.

    Backed by the `regex` module when it is installed, which aborts the match itself at `timeout=`; that is the
    only thing that actually stops catastrophic backtracking, since `re` holds the GIL throughout. Falls back to
    `re` (no interruption possible — see SANDBOX_NOTE) so the app still runs with the base dependency set.
    """

    __slots__ = ("_rx", "pattern", "timed")

    def __init__(self, rx: Any, pattern: str, timed: bool) -> None:
        self._rx = rx
        self.pattern = pattern
        self.timed = timed

    def search(self, text: str) -> Any:
        left = _remaining()
        if left is None or not self.timed:
            return self._rx.search(text)
        if left <= 0:
            raise RuleTimeout(f"evaluation exceeded {RULE_TIMEOUT_S:g}s (catastrophic pattern?)")
        try:
            return self._rx.search(text, timeout=left)
        except TimeoutError as exc:
            raise RuleTimeout(f"evaluation exceeded {RULE_TIMEOUT_S:g}s (catastrophic pattern?)") from exc


def _remaining() -> Optional[float]:
    """Seconds left in the current evaluation pass, or None when we are not inside one."""
    at = getattr(_DEADLINE, "at", None)
    return None if at is None else at - time.monotonic()


def compile_pattern(pattern: str, flags: Optional[RuleFlags], strict: bool = False) -> "SafePattern":
    """Compile an analyst-supplied pattern. `strict` adds the save-time ReDoS screening (layer 1); the
    evaluation path leaves it off so a pattern stored by an older build degrades to "reports an error and
    matches nothing" rather than being re-litigated mid-pass."""
    if not isinstance(pattern, str) or not pattern.strip():
        raise RuleError("pattern must be a non-empty regular expression")
    if len(pattern) > MAX_PATTERN_LEN:
        raise RuleError(f"pattern too long ({len(pattern)} chars, max {MAX_PATTERN_LEN})")
    if strict:
        screen_pattern(pattern)
    fl = flags or RuleFlags()
    engine = _regex if _regex is not None else re
    f = 0
    if fl.ignoreCase:
        f |= engine.IGNORECASE
    if fl.multiline:
        f |= engine.MULTILINE
    try:
        rx = engine.compile(pattern, f)
    except engine.error as exc:
        raise RuleError(f"invalid regex: {exc}") from exc
    except (OverflowError, RecursionError, ValueError) as exc:
        raise RuleError(f"invalid regex: {exc}") from exc
    return SafePattern(rx, pattern, timed=_regex is not None)


def compile_condition_regex(value: str) -> "SafePattern":
    """The case-insensitive matcher a `regex` condition row evaluates with — same semantics as
    detect.condition_pred, but deadline-aware (detect compiles with bare `re`)."""
    return compile_pattern(value, RuleFlags(ignoreCase=True))


def _matcher(rx: "SafePattern", field: str, source_filter: str) -> Callable[[Event], bool]:
    field = (field or "any").strip()
    sf = (source_filter or "").strip().lower()
    search = rx.search

    def source_ok(e: Event) -> bool:
        return not sf or sf in e.source.lower() or sf in e.file.lower()

    if field == "any":
        def pred(e: Event) -> bool:
            if not source_ok(e):
                return False
            if search(e.msg) or search(e.raw):
                return True
            for v in e.fields.values():
                if search(v):
                    return True
            return False
    elif field in FIXED_FIELDS:
        def pred(e: Event) -> bool:
            return source_ok(e) and bool(search(getattr(e, field) or ""))
    else:
        def pred(e: Event) -> bool:
            if not source_ok(e):
                return False
            v = e.fields.get(field)
            return bool(v) and bool(search(v))
    return pred


# ------------------------------------------------------------------ composed conditions
def validate_conditions(conditions: Iterable[Any], strict: bool = False) -> list[RuleCondition]:
    """Normalize + validate the condition rows of a custom rule. Raises RuleError (→ 400 in the router).

    Every value goes through detect.parse_condition, which types it by operator with the same Param
    machinery the built-ins use, so an uncompilable regex or a bad operator can never be stored.
    """
    rows = list(conditions or ())
    if len(rows) > MAX_CONDITIONS:
        raise RuleError(f"too many conditions ({len(rows)}, max {MAX_CONDITIONS})")
    out: list[RuleCondition] = []
    for i, c in enumerate(rows, 1):
        field = c.field if isinstance(c, RuleCondition) else str((c or {}).get("field", ""))
        op = c.op if isinstance(c, RuleCondition) else str((c or {}).get("op", ""))
        value = c.value if isinstance(c, RuleCondition) else str((c or {}).get("value", ""))
        try:
            f, o, v = parse_condition(field, op, value)
        except ValueError as exc:
            raise RuleError(f"condition {i}: {exc}") from exc
        if strict and o == "regex":
            try:
                screen_pattern(v, "condition regex")
            except RuleError as exc:
                raise RuleError(f"condition {i}: {exc}") from exc
        out.append(RuleCondition(field=f, op=o, value=v))
    return out


def validate_threshold(th: Optional[RuleThreshold]) -> Optional[RuleThreshold]:
    """Validate the optional windowed-burst part of a condition rule. Raises RuleError."""
    if th is None:
        return None
    try:
        count = int(th.count)
        window = int(th.window)
    except (TypeError, ValueError):
        raise RuleError("threshold count and window must be whole numbers") from None
    if count < 1:
        raise RuleError("threshold count must be at least 1")
    if window < 1:
        raise RuleError("threshold window must be at least 1 second")
    if window > MAX_WINDOW_S:
        raise RuleError("threshold window cannot exceed 7 days")
    group = (th.groupBy or "").strip()
    if len(group) > 120:
        raise RuleError("group-by field name is too long")
    return RuleThreshold(count=count, window=window, groupBy=group)


def _condition_pred(field: str, op: str, value: str) -> Callable[[Event], bool]:
    """detect.condition_pred, except that a `regex` row matches through SafePattern.

    detect compiles condition regexes with bare `re`, which cannot be interrupted; routing just that operator
    through the sandbox's own compiler keeps the semantics identical (case-insensitive search over every value
    the field yields, absent field = no match) while putting the analyst's regex under the pass deadline.
    """
    if op != "regex":
        return condition_pred(field, op, value)
    rx = compile_condition_regex((value or "").strip())

    def pred(e: Event) -> bool:
        return any(rx.search(x) for x in condition_values(e, field) if x != "")

    return pred


def conditions_matcher(r: Rule) -> Callable[[Event], bool]:
    """Predicate for a condition-built rule: every row AND-ed / OR-ed, plus the source filter.

    Rows are re-validated here, so a rules.json edited by hand (or written by an older version) degrades
    to "matches nothing" via RuleError instead of taking the rule engine down.
    """
    rows = validate_conditions(r.conditions)
    if not rows:
        raise RuleError("a condition rule needs at least one condition")
    preds = [_condition_pred(c.field, c.op, c.value) for c in rows]
    any_of = (r.combinator or "and").lower() == "or"
    sf = (r.sourceFilter or "").strip().lower()

    def pred(e: Event) -> bool:
        if sf and sf not in e.source.lower() and sf not in e.file.lower():
            return False
        return any(p(e) for p in preds) if any_of else all(p(e) for p in preds)

    return pred


def _rule_trigger(r: Rule) -> str:
    """The auto-generated TRIGGER for a custom rule — read-only, and never the analyst's description."""
    if r.conditions:
        th = (r.threshold.count, r.threshold.window, r.threshold.groupBy) if r.threshold else None
        return conditions_trigger([(c.field, c.op, c.value) for c in r.conditions], r.combinator, th,
                                  r.sourceFilter or "")
    if r.pattern:
        return regex_trigger(r.field or "any", r.pattern, r.sourceFilter or "")
    return ""


def _rule_mechanism(r: Rule) -> str:
    """The PRIMARY method a custom rule decides by, in the built-ins' own vocabulary."""
    if r.threshold:
        return "threshold"
    if r.conditions:
        return "regex" if all(c.op == "regex" for c in r.conditions) else "fields"
    return "regex"


def decorate(r: Rule) -> Rule:
    """Attach the DERIVED read-only fields to a custom rule: trigger (`logic`), mechanism and `patterns`.

    `patterns` is a projection of the regex conditions (or the rule's own pattern) — like RULE_PATTERNS for
    the built-ins, it is derived here and never maintained separately.
    """
    if r.conditions:
        patterns = [RulePattern(field=c.field, pattern=c.value) for c in r.conditions if c.op == "regex"]
    else:
        patterns = [RulePattern(field=r.field or "any", pattern=r.pattern)] if r.pattern else []
    return r.model_copy(update={"logic": _rule_trigger(r), "mechanism": _rule_mechanism(r), "patterns": patterns})


def _run_with_timeout(fn: Callable[[], Any], timeout: float = RULE_TIMEOUT_S) -> Any:
    """Run fn in a daemon thread under a `timeout`-second deadline.

    The deadline is published to the worker thread (`_DEADLINE.at`), so every SafePattern.search inside `fn`
    matches with the time that is actually left and aborts the match itself — that is what stops a
    catastrophic pattern, because `re` never yields the GIL and the join() below alone could only *report*
    the timeout while the runaway thread kept the whole process pinned. The join is still the outer guard for
    slowness that is not inside a regex.
    """
    box: dict[str, Any] = {}

    def target() -> None:
        _DEADLINE.at = time.monotonic() + timeout
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc
        finally:
            _DEADLINE.at = None

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise RuleTimeout(f"evaluation exceeded {timeout:g}s (catastrophic pattern?)")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def find_matches(events: list[Event], pattern: str, field: str, flags: Optional[RuleFlags], source_filter: str,
                 timeout: float = RULE_TIMEOUT_S) -> list[int]:
    """Indices of events matched by the pattern (raises RuleError / RuleTimeout)."""
    rx = compile_pattern(pattern, flags)
    pred = _matcher(rx, field, source_filter or "")
    return _run_with_timeout(lambda: [i for i, e in enumerate(events) if pred(e)], timeout)


def test_rule(events: list[Event], body: RuleTestInput) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        idx = find_matches(events, body.pattern, body.field, body.flags, body.sourceFilter or "")
    except RuleError as exc:
        raise
    except RuleTimeout as exc:
        return {"hits": 0, "sample": [], "tookMs": int((time.perf_counter() - t0) * 1000), "error": str(exc)}
    sample = [events[i] for i in idx[:20]]
    return {"hits": len(idx), "sample": sample, "tookMs": int((time.perf_counter() - t0) * 1000)}


def preview_rule(events: list[Event], r: Rule) -> dict[str, Any]:
    """What this rule WOULD flag, without saving it and without tagging a single event.

    `test_rule` above answers the same question for a bare regex, which is what the rule drawer's live
    box needs. This one takes a whole Rule — regex OR typed conditions OR conditions plus a windowed
    threshold — and it exists because the alternative is worse in a specific way: an author (a person or
    the assistant) who cannot try a rule has to SAVE it to find out what it does, and saving re-runs the
    catalogue over the pool and stamps detections on the analyst's evidence. Undoing that is a second
    full pass. A rule is cheap to imagine and expensive to install, so trying one must not cost an
    install.

    It deliberately builds the predicate through `conditions_matcher` / `compiled` — the SAME path
    `apply_rule` uses — so a preview and the rule that follows it can never disagree. Anything unsafe is
    refused here exactly as it would be at save time (ReDoS screen, condition validation, the sandbox
    deadline); a timeout comes back as `error`, not as an exception, because "this pattern is too
    expensive to run" is the answer the author needs.
    """
    t0 = time.perf_counter()
    try:
        if r.conditions:
            pred = conditions_matcher(r)
        else:
            if not (r.pattern or "").strip():
                raise RuleError("a rule needs either a pattern or at least one condition")
            bad = screen_pattern(r.pattern or "")
            if bad:
                raise RuleError(bad)
            pred = _matcher(compile_pattern(r.pattern or "", r.flags), r.field or "any", r.sourceFilter or "")
    except RuleError as exc:
        return {"hits": 0, "sample": [], "tookMs": 0, "error": str(exc)}
    select = (lambda: RulesStore._threshold_hits(r, events, pred)) if (r.conditions and r.threshold) \
        else (lambda: [i for i, e in enumerate(events) if pred(e)])
    try:
        idx = _run_with_timeout(select)
    except RuleTimeout as exc:
        return {"hits": 0, "sample": [], "tookMs": int((time.perf_counter() - t0) * 1000), "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - a preview must never take a request down
        return {"hits": 0, "sample": [], "tookMs": int((time.perf_counter() - t0) * 1000),
                "error": f"{type(exc).__name__}: {exc}"}
    return {"hits": len(idx), "sample": [events[i] for i in idx[:20]],
            "tookMs": int((time.perf_counter() - t0) * 1000)}


# ------------------------------------------------------------------ persistence
class RulesStore:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.custom: dict[str, Rule] = {}
        self.order: list[str] = []
        self.disabled_builtins: set[str] = set()
        # built-in metadata the analyst edited: {rule_id: {name?, description?, sev?, tags?}}. The matching logic
        # itself is Python and never overridden — only how the rule presents and what severity it tags with.
        self.builtin_overrides: dict[str, dict[str, Any]] = {}
        # built-ins removed from the catalogue: they stop firing and vanish from GET /api/rules, but the code is
        # still there, so restore() puts them back (unlike a custom rule, which is really deleted).
        self.removed_builtins: set[str] = set()
        self.seq = 0
        self.errors: dict[str, str] = {}
        self._compiled: dict[str, tuple[str, int, "SafePattern"]] = {}
        self._loaded = False
        # Monotonic revision of the CATALOGUE, bumped by every mutator (they all end in save()) and by
        # load(). Derived structures that depend on rule metadata — the anomaly aggregation, which shows
        # each rule's current name/severity/kind — key on it, so a rename or a toggle misses their cache
        # by construction instead of relying on the caller also having re-run detections.
        self.rev = 0

    # -- io
    def load(self) -> None:
        with self.lock:
            if self._loaded:
                return
            self._loaded = True
            self.rev += 1
            try:
                data = json.loads(config.RULES_PATH.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return
            for raw in data.get("rules", []):
                try:
                    r = Rule.model_validate(raw)
                except Exception:
                    continue
                r.builtin = False
                # a rule written before conditions existed has none, and stays a plain regex rule
                r.kind = "conditions" if r.conditions else "regex"
                r.hits = None
                r.error = None
                if r.conditions:
                    # re-validate on load: a stored value that no longer parses must degrade to a rule that
                    # matches nothing and says why, never to an exception inside the rule engine
                    try:
                        r.conditions = validate_conditions(r.conditions)
                        r.threshold = validate_threshold(r.threshold)
                    except RuleError as exc:
                        r.error = str(exc)
                        self.errors[r.id] = str(exc)
                self.custom[r.id] = r
                self.order.append(r.id)
            self.disabled_builtins = {str(x) for x in data.get("disabledBuiltins", [])}
            self.removed_builtins = {str(x) for x in data.get("removedBuiltins", [])}
            raw_over = data.get("builtinOverrides")
            if isinstance(raw_over, dict):
                for rid, ov in raw_over.items():
                    if isinstance(ov, dict):
                        self.builtin_overrides[str(rid)] = {k: v for k, v in ov.items()
                                                            if k in ("name", "description", "sev", "tags", "pattern", "params")}
            self.seq = int(data.get("seq", len(self.custom)) or 0)

    def save(self) -> None:
        with self.lock:
            # Every mutator ends here, so this is the one place the catalogue revision has to move.
            # It is bumped before the write and never rolled back on an OSError: a failed write means
            # the in-memory catalogue and the file disagree, and serving a cached view of the OLD
            # catalogue on top of that would compound the problem.
            self.rev += 1
            # logic/mechanism/patterns are DERIVED (decorate()), so they are never persisted
            data = {"rules": [self.custom[i].model_dump(exclude={"hits", "error", "overridden", "removed", "logic",
                                                                 "mechanism", "patterns"})
                              for i in self.order if i in self.custom],
                    "disabledBuiltins": sorted(self.disabled_builtins),
                    "removedBuiltins": sorted(self.removed_builtins),
                    "builtinOverrides": dict(sorted(self.builtin_overrides.items())),
                    "seq": self.seq}
        try:
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            tmp = config.RULES_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
            tmp.replace(config.RULES_PATH)
        except OSError:
            pass

    def _next_id(self) -> str:
        while True:
            self.seq += 1
            rid = f"RULE-{self.seq:04d}"
            if rid not in self.custom:
                return rid

    # -- catalogue
    def builtin_rules(self, include_removed: bool = False) -> list[Rule]:
        self.load()
        out = []
        with self.lock:
            overrides = dict(self.builtin_overrides)
            removed = set(self.removed_builtins)
            disabled = set(self.disabled_builtins)
        for br in all_builtin_rules():
            is_removed = br.id in removed
            if is_removed and not include_removed:
                continue
            ov = overrides.get(br.id) or {}
            default_tags = [br.id.split("-")[1].lower()] if "-" in br.id else []
            tags = ov.get("tags")
            out.append(Rule(id=br.id, name=str(ov.get("name") or br.name),
                            description=str(ov.get("description") if ov.get("description") is not None else br.description),
                            sev=ov.get("sev") or br.level,  # type: ignore[arg-type]
                            enabled=br.id not in disabled, builtin=True, kind="builtin",
                            tags=list(tags) if isinstance(tags, list) else default_tags, createdBy="system",
                            createdAt="", updatedAt="", overridden=bool(ov), removed=is_removed,
                            # `logic` is the TRIGGER - the condition the engine actually evaluates - never the
                            # description. They used to be the same string, which made the editable description
                            # box look like it was what did the flagging.
                            logic=br.trigger or br.description, mechanism=br.mechanism,
                            error=self.errors.get(br.id),
                            params=[RuleParam(key=p.key, label=p.label, kind=p.kind, default=p.default,
                                              value=_param_value(ov, br.id, p), field=p.field, help=p.help)
                                    for p in br.params],
                            # regex params doubled as `patterns` for the compact list view
                            patterns=[RulePattern(field=p.field or "raw", pattern=_param_value(ov, br.id, p))
                                      for p in br.params if p.kind == "regex"]))
        return out

    def custom_rules(self) -> list[Rule]:
        self.load()
        with self.lock:
            return [decorate(self.custom[i]) for i in self.order if i in self.custom]

    def all_rules(self, include_removed: bool = False) -> list[Rule]:
        return self.builtin_rules(include_removed) + self.custom_rules()

    def get(self, rid: str) -> Optional[Rule]:
        self.load()
        with self.lock:
            if rid in self.custom:
                return decorate(self.custom[rid])
        for r in self.builtin_rules(include_removed=True):
            if r.id == rid:
                return r
        return None

    def detection_disabled(self) -> set[str]:
        """Built-in ids that must not fire: switched off OR removed from the catalogue."""
        self.load()
        with self.lock:
            return set(self.disabled_builtins) | set(self.removed_builtins)

    def detection_params(self) -> dict[str, dict[str, str]]:
        """{rule_id: {param key: value}} — the analyst's tuning of built-in conditions, handed to run_rules.

        Values that no longer parse are dropped rather than breaking the pass, and the rule is flagged so
        the editor can show why it fell back to the shipped default.
        """
        self.load()
        with self.lock:
            items = list(self.builtin_overrides.items())
        out: dict[str, dict[str, str]] = {}
        for rid, ov in items:
            raw = ov.get("params")
            # legacy shape: a bare "pattern" key from before conditions were fully parameterised
            if not isinstance(raw, dict):
                raw = {"pattern": ov["pattern"]} if ov.get("pattern") else {}
            clean: dict[str, str] = {}
            for key, val in raw.items():
                spec = param_spec(rid, str(key))
                if spec is None:
                    continue
                try:
                    norm = parse_param(spec, str(val))
                except ValueError as exc:
                    self.errors[rid] = f"{spec.label}: {exc}"
                    continue
                if spec.kind == "regex":
                    reason = catastrophic_reason(norm)
                    if reason:
                        # drop it: run_rules then falls back to the shipped regex (degrade, never disable)
                        self.errors[rid] = f"{spec.label}: {reason}"
                        continue
                clean[str(key)] = norm
            if clean:
                out[rid] = clean
        return out

    def detection_overrides(self) -> dict[str, dict[str, Any]]:
        """{rule_id: {"name":…, "sev":…}} so detections carry the analyst's naming/severity, not the shipped one."""
        self.load()
        with self.lock:
            out: dict[str, dict[str, Any]] = {}
            for rid, ov in self.builtin_overrides.items():
                pick = {k: ov[k] for k in ("name", "sev") if ov.get(k)}
                if pick:
                    out[rid] = pick
            return out

    def is_builtin(self, rid: str) -> bool:
        return any(br.id == rid for br in all_builtin_rules())

    def enabled_custom(self) -> list[Rule]:
        return [r for r in self.custom_rules() if r.enabled]

    # -- mutation
    def create(self, body: RuleInput) -> Rule:
        """Create a custom rule: either a raw regex (legacy shape, unchanged) or composed conditions."""
        self.load()
        conds = validate_conditions(body.conditions or (), strict=True)
        threshold = validate_threshold(body.threshold) if conds else None
        if not conds:
            compile_pattern(body.pattern or "", body.flags, strict=True)
        with self.lock:
            rid = self._next_id()
            now = _now()
            r = Rule(id=rid, name=body.name.strip() or rid, description=body.description, sev=body.sev, enabled=body.enabled,
                     builtin=False, kind="conditions" if conds else "regex",
                     pattern="" if conds else (body.pattern or ""), field=body.field or "any", flags=body.flags or RuleFlags(),
                     sourceFilter=body.sourceFilter or "", conditions=conds, combinator=body.combinator, threshold=threshold,
                     tags=list(body.tags), createdBy=body.createdBy, createdAt=now, updatedAt=now)
            self.custom[rid] = r
            self.order.append(rid)
        self.save()
        return decorate(r)

    def update_builtin(self, rid: str, body: RuleInput) -> Rule:
        """Store an override for a built-in: its metadata AND its condition parameters.

        The *shape* of a built-in stays Python (bursts, cross-event joins), but every value that shape
        compares against is a parameter, so `body.params` genuinely changes what fires. Values are
        validated here so a bad one is a 400 at save time rather than a rule that silently stops matching.
        `field`/`flags`/`sourceFilter` are still ignored - they only mean something for custom regex rules.
        """
        self.load()
        if not self.is_builtin(rid):
            raise KeyError(rid)
        shipped = next(b for b in all_builtin_rules() if b.id == rid)
        default_tags = [rid.split("-")[1].lower()] if "-" in rid else []
        ov: dict[str, Any] = {}
        name = (body.name or "").strip()
        if name and name != shipped.name:
            ov["name"] = name
        if (body.description or "") != shipped.description:
            ov["description"] = body.description or ""
        if body.sev and body.sev != shipped.level:
            ov["sev"] = body.sev
        if list(body.tags) != default_tags:
            ov["tags"] = list(body.tags)
        # condition parameters. Only values that differ from the shipped default are stored, so a rule
        # edited back to stock stops counting as overridden.
        specs = {p.key: p for p in BUILTIN_PARAMS.get(rid, ())}
        supplied = dict(body.params or {})
        # a bare `pattern` on the body still works: it targets the rule's regex parameter
        if body.pattern and "pattern" not in supplied and "pattern" in specs:
            supplied["pattern"] = body.pattern
        tuned: dict[str, str] = {}
        for key, val in supplied.items():
            spec = specs.get(key)
            if spec is None:
                raise RuleError(f"{rid} has no parameter '{key}'")
            try:
                norm = parse_param(spec, str(val))
            except ValueError as exc:
                raise RuleError(f"{spec.label}: {exc}") from exc
            if spec.kind == "regex":
                # a built-in's regex parameter runs inside detect.run_rules on bare `re`, so the save-time
                # screen is the only guard it gets — reject the catastrophic shapes here
                screen_pattern(norm, spec.label)
            if norm != spec.default:
                tuned[key] = norm
        if tuned:
            ov["params"] = tuned
        with self.lock:
            self.errors.pop(rid, None)
            if ov:
                self.builtin_overrides[rid] = ov
            else:  # edited back to the shipped values → stop tracking an override
                self.builtin_overrides.pop(rid, None)
            # `enabled` is not part of the override blob — it lives in disabledBuiltins like the toggle uses
            if body.enabled:
                self.disabled_builtins.discard(rid)
            else:
                self.disabled_builtins.add(rid)
            self.removed_builtins.discard(rid)  # editing a removed built-in brings it back
        self.save()
        return next(b for b in self.builtin_rules(include_removed=True) if b.id == rid)

    def restore_builtin(self, rid: str) -> Rule:
        """Drop any override AND un-remove — back to the shipped definition."""
        self.load()
        if not self.is_builtin(rid):
            raise KeyError(rid)
        with self.lock:
            self.builtin_overrides.pop(rid, None)
            self.removed_builtins.discard(rid)
            self.disabled_builtins.discard(rid)
        self.save()
        return next(b for b in self.builtin_rules() if b.id == rid)

    def update(self, rid: str, body: RuleInput) -> Rule:
        self.load()
        conds = validate_conditions(body.conditions or (), strict=True)
        threshold = validate_threshold(body.threshold) if conds else None
        if not conds:
            compile_pattern(body.pattern or "", body.flags, strict=True)
        with self.lock:
            cur = self.custom.get(rid)
            if cur is None:
                raise KeyError(rid)
            r = cur.model_copy(update={
                "name": body.name.strip() or cur.name, "description": body.description, "sev": body.sev, "enabled": body.enabled,
                "kind": "conditions" if conds else "regex",
                "pattern": "" if conds else (body.pattern or ""), "field": body.field or "any", "flags": body.flags or RuleFlags(),
                "sourceFilter": body.sourceFilter or "", "conditions": conds, "combinator": body.combinator,
                "threshold": threshold, "tags": list(body.tags), "createdBy": body.createdBy or cur.createdBy,
                "updatedAt": _now(), "error": None})
            self.custom[rid] = r
            self.errors.pop(rid, None)
            self._compiled.pop(rid, None)
        self.save()
        return decorate(r)

    def remove_builtin(self, rid: str) -> bool:
        """Take a built-in out of the catalogue: it stops firing and disappears from the rule list.
        Reversible via restore_builtin, since the matching code still ships with the app."""
        self.load()
        if not self.is_builtin(rid):
            return False
        with self.lock:
            self.removed_builtins.add(rid)
        self.save()
        return True

    def clear_all(self, scope: str = "all") -> dict[str, int]:
        """Empty the rule list.

        scope='custom' deletes every custom rule and leaves the built-ins alone.
        scope='all' also takes every built-in out of the catalogue.
        Built-ins are only *removed*, never destroyed - their matching code ships with the app, so
        restore_defaults() brings the whole catalogue back. Custom rules are gone for good.
        """
        self.load()
        with self.lock:
            n_custom = len(self.custom)
            self.custom.clear()
            self.order = []
            self.errors.clear()
            self._compiled.clear()
            n_builtin = 0
            if scope == "all":
                ids = {b.id for b in all_builtin_rules()}
                n_builtin = len(ids - self.removed_builtins)
                self.removed_builtins |= ids
        self.save()
        return {"custom": n_custom, "builtin": n_builtin}

    def restore_defaults(self) -> int:
        """Put every removed built-in back and drop all metadata/regex overrides. Custom rules untouched."""
        self.load()
        with self.lock:
            n = len(self.removed_builtins)
            self.removed_builtins.clear()
            self.builtin_overrides.clear()
            self.disabled_builtins.clear()
        self.save()
        return n

    def delete(self, rid: str) -> bool:
        self.load()
        with self.lock:
            if rid not in self.custom:
                return False
            del self.custom[rid]
            self.order = [i for i in self.order if i != rid]
            self.errors.pop(rid, None)
            self._compiled.pop(rid, None)
        self.save()
        return True

    def toggle(self, rid: str) -> Rule:
        self.load()
        with self.lock:
            if rid in self.custom:
                cur = self.custom[rid]
                r = cur.model_copy(update={"enabled": not cur.enabled, "updatedAt": _now()})
                self.custom[rid] = r
            elif self.is_builtin(rid):
                if rid in self.disabled_builtins:
                    self.disabled_builtins.discard(rid)
                else:
                    self.disabled_builtins.add(rid)
                r = next(b for b in self.builtin_rules(include_removed=True) if b.id == rid)
            else:
                raise KeyError(rid)
        self.save()
        return r

    # -- evaluation
    def compiled(self, r: Rule) -> "SafePattern":
        fl = r.flags or RuleFlags()
        key = (r.pattern or "", (2 if fl.ignoreCase else 0) | (8 if fl.multiline else 0))
        with self.lock:
            hit = self._compiled.get(r.id)
            if hit and hit[0] == key[0] and hit[1] == key[1]:
                return hit[2]
            rx = compile_pattern(r.pattern or "", fl)
            self._compiled[r.id] = (key[0], key[1], rx)
            return rx

    def apply_rule(self, r: Rule, events: list[Event], exclude: Optional[Any] = None) -> int:
        """Tag every matching event with this rule (idempotent). Returns hits; records timeout errors on the rule.

        Both custom shapes run through the SAME sandbox: the predicate (regex or composed conditions, plus
        the optional windowed burst) is evaluated inside _run_with_timeout, so a pathological rule is
        abandoned after RULE_TIMEOUT_S rather than hanging the ingest.
        """
        try:
            pred = conditions_matcher(r) if r.conditions else _matcher(self.compiled(r), r.field or "any", r.sourceFilter or "")
        except RuleError as exc:
            self.errors[r.id] = str(exc)
            r.error = str(exc)
            return 0
        select = (lambda: self._threshold_hits(r, events, pred)) if (r.conditions and r.threshold) \
            else (lambda: [i for i, e in enumerate(events) if pred(e)])
        try:
            idx = _run_with_timeout(select)
        except RuleTimeout as exc:
            self.errors[r.id] = str(exc)
            r.error = str(exc)
            return 0
        except Exception as exc:  # pragma: no cover - defensive
            self.errors[r.id] = f"{type(exc).__name__}: {exc}"
            r.error = self.errors[r.id]
            return 0
        self.errors.pop(r.id, None)
        r.error = None
        # Exclusions apply to CUSTOM rules exactly as they do to built-ins (detect._tag). An analyst who
        # excludes a resolver and then writes their own rule would otherwise find the suppression quietly
        # did not cover it — "applies to all rules" has to mean all of them.
        if exclude is None:
            from .exclusions import EXCLUSIONS
            exclude = EXCLUSIONS.matcher()
        ex = exclude
        hits = 0
        for i in idx:
            e = events[i]
            if not ex.empty and ex.excluded(e, r.id):
                continue
            hits += 1
            if not any(d.id == r.id for d in e.detections):
                e.add_detection(Detection(name=r.name, id=r.id, level=r.sev))
                e.raise_sev(r.sev)   # reversible: see Event.recompute_sev
        return hits

    @staticmethod
    def _threshold_hits(r: Rule, events: list[Event], pred: Callable[[Event], bool]) -> list[int]:
        """Indices to tag for a windowed condition rule: the anchor (last) event of each qualifying burst.

        Reuses detect.find_bursts, so a custom threshold rule has exactly the same semantics as a built-in
        one: group by a field, slide a window of `window` seconds, fire at `count` or more.
        """
        th = r.threshold
        assert th is not None
        matched = [i for i, e in enumerate(events) if pred(e)]
        if not matched:
            return []
        ts = np.asarray([_epoch(events[i].ts) for i in range(len(events))], dtype=np.float64)
        group = (th.groupBy or "").strip()

        def key_of(i: int) -> str:
            if not group:
                return "all"
            vals = [v for v in condition_values(events[i], group) if v]
            return vals[0] if vals else ""

        hits = []
        for _key, anchor, count, _first in find_bursts(matched, ts, key_of, float(th.window), int(th.count)):
            hits.append(anchor)
            events[anchor].set_field("burst.count", str(count))
            events[anchor].set_field("burst.window", f"{th.window}s")
        return sorted(set(hits))

    def apply_all(self, events: list[Event], exclude: Optional[Any] = None) -> int:
        """Every enabled custom rule. `exclude` is the pass's ONE compiled exclusion set — shared with
        the built-in pass so the suppression counts land in a single place and each rule does not
        recompile the same conditions."""
        total = 0
        for r in self.enabled_custom():
            total += self.apply_rule(r, events, exclude)
        return total

    @staticmethod
    def strip_rule(rid: str, events: Iterable[Event]) -> None:
        for e in events:
            if e.detections and any(d.id == rid for d in e.detections):
                kept = [d for d in e.detections if d.id != rid]
                e.detections = kept or EMPTY_LIST
                e.recompute_sev()   # the rule took its severity escalation with it

    def with_hits(self, rules: list[Rule], events: list[Event]) -> list[Rule]:
        counts: dict[str, int] = {}
        for e in events:
            for d in e.detections:
                counts[d.id] = counts.get(d.id, 0) + 1
        # A GRAPH rule tags no event, so `counts` has nothing to say about it and 0 would be a lie in the
        # loudest possible place: "this rule has never fired". Its hits come from the graph findings
        # roll-up when one has ALREADY been computed — never by building a graph to answer /api/rules —
        # and stay None ("not evaluated") otherwise. None and 0 are different facts here.
        graph_hits = _graph_hits()
        out = []
        for r in rules:
            if r.mechanism == "graph":
                out.append(r.model_copy(update={"hits": graph_hits.get(r.id), "error": self.errors.get(r.id) or r.error}))
                continue
            out.append(r.model_copy(update={"hits": counts.get(r.id, 0), "error": self.errors.get(r.id) or r.error}))
        return out


def _graph_hits() -> dict[str, Optional[int]]:
    """Findings per graph rule, ONLY from an already-computed roll-up. Never builds anything."""
    try:
        from .graph_findings import peek_counts
        return peek_counts()
    except Exception:  # noqa: BLE001 - the rules screen must render even if the graph layer is unhappy
        return {}


RULES_STORE = RulesStore()
