"""Exclusions — the suppressions that stop a rule claiming evidence the analyst has already judged.

The analyst's ask: *"google dns is likely something not to detect on, so have an exclusion section and
also be able to manage these exclusions"*. A detection engine without one degrades the same way every
time: the known-benign thing fires on every ingest, the analyst learns to skim past that rule, and the
day it means something they skim past that too.

The shape:
  * An exclusion is a NAME plus typed CONDITIONS over the same field vocabulary a custom rule uses
    (`detect.condition_pred`), so there is one condition language in the app, not two.
  * `ruleIds` empty means EVERY rule; a non-empty list scopes it. Those are genuinely different claims
    — "this resolver is never interesting" versus "this resolver is not interesting for THIS rule" —
    and the second is usually what someone means, so the UI has to be able to express it.
  * It suppresses the DETECTION, never the event. The line stays in the pool, in search, in the raw
    viewer and on the timeline. Nothing about the evidence changes; only the claim a rule made about it.

Three rules this module exists to keep, because this is the one feature in Iris that can HIDE things:

1. **Nothing is excluded by default.** Iris SUGGESTS a small library (public resolvers, loopback,
   broadcast) with the reason stated, and adding one is a deliberate act. Shipping suppressions enabled
   would mean an analyst's first search silently omitted evidence they never chose to omit.
2. **A suppression that cannot be seen is a lie.** Every exclusion carries `suppressed` — how many
   detections it actually removed on the last pass — and the API reports the total. An exclusion that
   suppresses nothing is probably wrong; one that suppresses ten thousand things is worth knowing about.
3. **It never guesses.** An exclusion whose conditions read event FIELDS cannot be evaluated against an
   entity-graph node, which has only a type and a value. Rather than half-applying it, `appliesToGraph`
   says so and graph findings are left alone.

Persistence is `$IRIS_DATA_DIR/exclusions.json`, atomic tmp+replace under the store lock, shaped like
`rules.json` / `jobs.json`. It is CONFIGURATION, not evidence, so `clear-all` keeps it — the same call
the Settings copy already makes about rules.json and settings.json.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from . import config
from .detect import CONDITION_OPS, condition_pred, parse_condition
from .models import Exclusion, ExclusionInput, ExclusionSuggestion, RuleCondition

UTC = timezone.utc
FORMAT = 1
MAX_EXCLUSIONS = 500
MAX_CONDITIONS = 20

# Node-evaluable condition fields: an entity-graph node has a TYPE and a VALUE and nothing else, so
# these are the only fields an exclusion can be checked against there. `entity` and `value` both mean
# the node's value; `type` means its node type (ip, user, host, …).
GRAPH_FIELDS = frozenset({"entity", "entities", "value", "node", "nodevalue", "type", "nodetype",
                          "ip", "user", "host", "domain", "hash", "file", "process"})
# Of those, the ones that also NAME a node type, so `ip is 8.8.8.8` matches the ip node and not a user
# who happens to be called that.
GRAPH_TYPE_FIELDS = {"ip": "ip", "user": "user", "host": "host", "domain": "domain", "hash": "hash",
                     "file": "file", "process": "process"}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _path() -> Path:
    """Resolved per call, never at import: the tests point DATA_DIR at a throwaway directory."""
    return Path(config.DATA_DIR) / "exclusions.json"


class ExclusionError(ValueError):
    """A definition that will not validate. Carries the sentence shown to the analyst."""


def trigger_text(conditions: list[RuleCondition], combinator: str, rule_ids: list[str]) -> str:
    """What this exclusion suppresses, in words. Generated and read-only, exactly like a rule's trigger."""
    rows = []
    for c in conditions:
        phrase = CONDITION_OPS.get(c.op, ("", c.op))[1]
        rows.append(f"{c.field} {phrase}" if c.op == "exists" else f'{c.field} {phrase} "{c.value}"')
    if not rows:
        return ""
    joiner = " AND " if (combinator or "and").lower() != "or" else " OR "
    scope = "every rule" if not rule_ids else (
        f"{len(rule_ids)} rule{'s' if len(rule_ids) != 1 else ''} ({', '.join(rule_ids[:4])}"
        f"{', …' if len(rule_ids) > 4 else ''})")
    return f"Suppresses {scope} on events where {joiner.join(rows)}."


def validate(body: ExclusionInput) -> list[RuleCondition]:
    """Validate a definition through the SAME typed machinery a rule condition uses. Raises."""
    if not (body.name or "").strip():
        raise ExclusionError("an exclusion needs a name")
    rows = list(body.conditions or [])
    if not rows:
        raise ExclusionError("an exclusion needs at least one condition — one that matches everything "
                             "would switch the whole catalogue off")
    if len(rows) > MAX_CONDITIONS:
        raise ExclusionError(f"at most {MAX_CONDITIONS} conditions")
    out: list[RuleCondition] = []
    for c in rows:
        try:
            f, o, v = parse_condition(c.field, c.op, c.value)
        except ValueError as exc:
            raise ExclusionError(str(exc)) from exc
        out.append(RuleCondition(field=f, op=o, value=v))
    return out


def _graph_evaluable(conditions: list[RuleCondition]) -> bool:
    """Can EVERY condition be evaluated against a node (a type and a value)?

    All of them, deliberately — an exclusion is a conjunction of claims and applying the half that
    happens to fit a node would suppress findings the analyst never excluded.
    """
    return bool(conditions) and all(c.field.strip().lower() in GRAPH_FIELDS for c in conditions)


def node_pred(conditions: list[RuleCondition], combinator: str) -> Callable[[str, str], bool]:
    """Compile the node-side matcher: (node type, node value) -> excluded?"""
    parts: list[Callable[[str, str], bool]] = []
    for c in conditions:
        field = c.field.strip().lower()
        want_type = GRAPH_TYPE_FIELDS.get(field, "")
        # Reuse the event matcher by handing it a one-field pseudo-event; the operator semantics
        # (contains / regex / in / …) then cannot drift between the two sides.
        value_pred = _value_pred(c)
        if field in ("type", "nodetype"):
            parts.append(lambda t, v, p=value_pred: p(t))
        elif want_type:
            parts.append(lambda t, v, p=value_pred, wt=want_type: t == wt and p(v))
        else:
            parts.append(lambda t, v, p=value_pred: p(v))
    any_of = (combinator or "and").lower() == "or"

    def pred(node_type: str, node_value: str) -> bool:
        if not parts:
            return False
        return any(p(node_type, node_value) for p in parts) if any_of \
            else all(p(node_type, node_value) for p in parts)

    return pred


def _value_pred(c: RuleCondition) -> Callable[[str], bool]:
    """One condition as a plain string test, via detect.condition_pred on a one-field pseudo-event."""
    from .models import Event

    inner = condition_pred("msg", c.op, c.value)

    def pred(value: str) -> bool:
        return inner(Event(id="", ts="", source="", sourceId="", file="", host="", user="",
                           msg=value, sev="info", raw=value, fields={}))

    return pred


class _Compiled:
    """One exclusion, ready to evaluate. Built once per pass, never per event."""
    __slots__ = ("id", "name", "rule_ids", "pred", "node_pred", "graph", "hits")

    def __init__(self, ex: Exclusion) -> None:
        self.id = ex.id
        self.name = ex.name
        self.rule_ids = set(ex.ruleIds or ())
        preds = [condition_pred(c.field, c.op, c.value) for c in ex.conditions]
        any_of = (ex.combinator or "and").lower() == "or"
        self.pred = (lambda e: any(p(e) for p in preds)) if any_of else (lambda e: all(p(e) for p in preds))
        self.graph = _graph_evaluable(list(ex.conditions))
        self.node_pred = node_pred(list(ex.conditions), ex.combinator) if self.graph else None
        self.hits = 0


class Matcher:
    """The compiled, live exclusion set handed to one detection pass.

    Deliberately a plain object rather than a closure: the pass has to be able to report what each
    exclusion suppressed afterwards, and a counter that nobody can read is how a suppression becomes
    invisible.
    """

    __slots__ = ("_all", "_by_rule", "empty")

    def __init__(self, exclusions: list[Exclusion]) -> None:
        self._all: list[_Compiled] = []
        self._by_rule: dict[str, list[_Compiled]] = {}
        for ex in exclusions:
            if not ex.enabled:
                continue
            try:
                c = _Compiled(ex)
            except Exception:  # noqa: BLE001 — a broken exclusion must never take the pass down
                continue
            if c.rule_ids:
                for rid in c.rule_ids:
                    self._by_rule.setdefault(rid, []).append(c)
            else:
                self._all.append(c)
        self.empty = not self._all and not self._by_rule

    def excluded(self, event: Any, rule_id: str) -> str:
        """The id of the exclusion that suppresses this (event, rule), or '' — the hot path.

        `empty` is checked by the callers first, so an installation with no exclusions pays one
        attribute read per detection and nothing else.
        """
        for c in self._all:
            try:
                if c.pred(event):
                    c.hits += 1
                    return c.id
            except Exception:  # noqa: BLE001
                continue
        for c in self._by_rule.get(rule_id, ()):  # type: ignore[arg-type]
            try:
                if c.pred(event):
                    c.hits += 1
                    return c.id
            except Exception:  # noqa: BLE001
                continue
        return ""

    def excluded_node(self, node_type: str, node_value: str, rule_id: str) -> str:
        """Same question for an entity-graph node. Only exclusions that can be evaluated against a node
        take part — see `_graph_evaluable`; the rest are left out rather than half-applied."""
        for c in self._all:
            if c.graph and c.node_pred is not None and c.node_pred(node_type, node_value):
                c.hits += 1
                return c.id
        for c in self._by_rule.get(rule_id, ()):  # type: ignore[arg-type]
            if c.graph and c.node_pred is not None and c.node_pred(node_type, node_value):
                c.hits += 1
                return c.id
        return ""

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in list(self._all) + [x for v in self._by_rule.values() for x in v]:
            out[c.id] = out.get(c.id, 0) + c.hits
        return out


# --------------------------------------------------------------------------- the suggestions
# Offered, never applied. Each says WHY, because "8.8.8.8 is Google" is context an analyst may or may
# not accept — a resolver being benign infrastructure is exactly what makes it useful to an attacker
# for tunnelling, so this is a judgement Iris must not make on anybody's behalf.
def suggestions() -> list[ExclusionSuggestion]:
    C = RuleCondition
    return [
        ExclusionSuggestion(
            name="Public DNS resolvers",
            why="Google, Cloudflare, Quad9 and OpenDNS answer for most of the internet, so they show up "
                "in almost every capture and firewall log. Excluding them quiets that — but a resolver is "
                "also the perfect cover for DNS tunnelling, so scope this to the rules you mean.",
            conditions=[C(field="_ip", op="in",
                          value="8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, "
                                "208.67.222.222, 208.67.220.220, 2001:4860:4860::8888, 2606:4700:4700::1111")],
            combinator="or"),
        ExclusionSuggestion(
            name="Loopback and unspecified addresses",
            why="127.0.0.1, ::1 and 0.0.0.0 are the host talking to itself or a service bound to "
                "everything. They are almost never the subject of a finding.",
            conditions=[C(field="_ip", op="in", value="127.0.0.1, ::1, 0.0.0.0, 255.255.255.255")],
            combinator="or"),
        ExclusionSuggestion(
            name="NTP and time sync",
            why="Time servers are contacted by every host on a schedule, which reads as beaconing to any "
                "rule that counts regularity.",
            conditions=[C(field="dst_port", op="equals", value="123")]),
        ExclusionSuggestion(
            name="Windows machine accounts",
            why="An account ending in $ is a computer, not a person. Machine accounts authenticate "
                "constantly and dominate any per-account fan-out count.",
            conditions=[C(field="user", op="regex", value=r"\\$$")]),
        ExclusionSuggestion(
            name="Kubernetes system identities",
            why="system:serviceaccount and system:node identities are the cluster running itself. They "
                "are the loudest thing in an audit log and almost never the finding.",
            conditions=[C(field="user", op="starts_with", value="system:")]),
        ExclusionSuggestion(
            name="Monitoring and health checks",
            why="Uptime probes hit the same path from the same few addresses forever, which looks like "
                "scanning to a rule that counts requests.",
            conditions=[C(field="user_agent", op="regex",
                          value=r"(?i)(kube-probe|ELB-HealthChecker|Pingdom|UptimeRobot|StatusCake|"
                                r"Datadog|NewRelicPinger|GoogleHC|Prometheus)")]),
    ]


# --------------------------------------------------------------------------- the store
class ExclusionStore:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.items: dict[str, Exclusion] = {}
        self.order: list[str] = []
        self._loaded_from: Optional[Path] = None
        # Monotonic revision, bumped by every mutation. The anomaly roll-up and the graph-findings memo
        # key on it, so a change to a suppression misses their caches BY CONSTRUCTION rather than by a
        # call site remembering to invalidate — the same reasoning as RULES_STORE.rev.
        self.rev = 0
        self._suppressed: dict[str, int] = {}

    # -- io
    def load(self) -> None:
        with self.lock:
            path = _path()
            if self._loaded_from == path:
                return
            self.items, self.order = {}, []
            self._loaded_from = path
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return
            for row in raw.get("exclusions", []) if isinstance(raw, dict) else []:
                try:
                    ex = Exclusion(**row)
                except Exception:  # noqa: BLE001 — one bad row must not empty the list
                    continue
                ex.appliesToGraph = _graph_evaluable(list(ex.conditions))
                ex.logic = trigger_text(list(ex.conditions), ex.combinator, list(ex.ruleIds))
                self.items[ex.id] = ex
                self.order.append(ex.id)
            self.rev += 1

    def _save_locked(self) -> None:
        path = _path()
        body = {"format": FORMAT,
                "exclusions": [self.items[i].model_dump(exclude={"suppressed"}) for i in self.order
                               if i in self.items]}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(body, indent=2), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass
        self.rev += 1

    # -- reads
    def all(self) -> list[Exclusion]:
        self.load()
        with self.lock:
            rows = [self.items[i].model_copy() for i in self.order if i in self.items]
        for r in rows:
            r.suppressed = self._suppressed.get(r.id)
        return rows

    def get(self, eid: str) -> Optional[Exclusion]:
        self.load()
        with self.lock:
            ex = self.items.get(eid)
            return ex.model_copy() if ex else None

    def matcher(self) -> Matcher:
        """The compiled set for ONE detection pass."""
        return Matcher(self.all())

    def record(self, counts: dict[str, int]) -> None:
        """Publish what the last pass suppressed, per exclusion."""
        with self.lock:
            self._suppressed = dict(counts)

    def total_suppressed(self) -> int:
        with self.lock:
            return sum(self._suppressed.values())

    # -- writes
    def create(self, body: ExclusionInput, created_by: str = "user") -> Exclusion:
        rows = validate(body)
        self.load()
        with self.lock:
            if len(self.items) >= MAX_EXCLUSIONS:
                raise ExclusionError(f"at most {MAX_EXCLUSIONS} exclusions")
            eid = f"EX-{uuid.uuid4().hex[:10]}"
            ex = Exclusion(id=eid, name=body.name.strip()[:120], conditions=rows,
                           combinator=body.combinator, ruleIds=[r.strip() for r in body.ruleIds if r.strip()],
                           note=(body.note or "").strip()[:2000], enabled=bool(body.enabled),
                           createdBy=created_by, createdAt=_now(), updatedAt=_now(),  # type: ignore[arg-type]
                           appliesToGraph=_graph_evaluable(rows),
                           logic=trigger_text(rows, body.combinator, list(body.ruleIds)))
            self.items[eid] = ex
            self.order.append(eid)
            self._save_locked()
            return ex.model_copy()

    def update(self, eid: str, body: ExclusionInput) -> Exclusion:
        rows = validate(body)
        self.load()
        with self.lock:
            cur = self.items.get(eid)
            if cur is None:
                raise KeyError(eid)
            ex = cur.model_copy(update={
                "name": body.name.strip()[:120], "conditions": rows, "combinator": body.combinator,
                "ruleIds": [r.strip() for r in body.ruleIds if r.strip()],
                "note": (body.note or "").strip()[:2000], "enabled": bool(body.enabled),
                "updatedAt": _now(), "appliesToGraph": _graph_evaluable(rows),
                "logic": trigger_text(rows, body.combinator, list(body.ruleIds))})
            self.items[eid] = ex
            self._save_locked()
            return ex.model_copy()

    def toggle(self, eid: str) -> Exclusion:
        self.load()
        with self.lock:
            cur = self.items.get(eid)
            if cur is None:
                raise KeyError(eid)
            ex = cur.model_copy(update={"enabled": not cur.enabled, "updatedAt": _now()})
            self.items[eid] = ex
            self._save_locked()
            return ex.model_copy()

    def delete(self, eid: str) -> bool:
        self.load()
        with self.lock:
            if eid not in self.items:
                return False
            del self.items[eid]
            self.order = [i for i in self.order if i != eid]
            self._save_locked()
            return True

    def clear(self) -> int:
        self.load()
        with self.lock:
            n = len(self.items)
            self.items, self.order = {}, []
            self._save_locked()
            return n


EXCLUSIONS = ExclusionStore()
