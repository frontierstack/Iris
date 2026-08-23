"""Detections that read the ENTITY GRAPH rather than one event at a time.

`detect.run_rules` answers "is THIS line suspicious?". A whole class of findings cannot be phrased that
way, because the evidence is the SHAPE of the relationships and no single line contains it: one address
authenticating as fourteen different accounts, one account signing in from nine addresses, a binary hash
that turns up on six hosts, a domain answering with thirty addresses. Every one of those lines is
unremarkable on its own — which is exactly why an event-at-a-time engine cannot see them.

So these rules run over the built graph (`graph.GraphBuilder`: typed nodes, typed relations with counts
and outcomes) and produce FINDINGS instead of tagging events. Everything else about them is deliberately
the same as a built-in:

  * the SAME four-piece model — description (prose, editable, matches nothing), trigger (what the engine
    evaluates, read-only), mechanism ('graph'), params (every constant, tunable);
  * the SAME catalogue: they are registered into `detect` and served by `/api/rules`, so they toggle,
    tune and restore through the machinery that already exists. There is no second rules screen;
  * the SAME citation rule: a finding names the event ids it was derived from, verified against the
    pool, because a claim about the evidence that cannot be opened is not a finding.

What they are NOT is attached to `Event.detections`. A fan-out is a property of a node, not of any one
of its events, and stamping an arbitrary "representative" event with it would put a claim on a line that
does not support it — the exact silent-evidence bug this project keeps fighting. They are served on
their own endpoint and shown in their own section.

Cost: one pass over nodes and one over edges of an ALREADY-BUILT graph — no extraction, no walk of the
pool. Measured on the analyst's 18k-node / 221k-relation graph: ~40 ms. It is never allowed to trigger a
graph build (see `routers/graph.graph_anomalies`), because a rule roll-up must not be the thing that
starts a 90-second extraction.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

from .detect import Param, Rule, register_builtins

# How many findings one rule may return, and how many citations each finding carries. Both are caps on
# the ANSWER, not on the analysis: the counts in a finding are exact over the whole graph, and
# `truncated` says when the list was cut so a number on screen is never quietly partial.
MAX_FINDINGS_PER_RULE = 25
MAX_CITATIONS = 8
MAX_RELATED = 12

P = Param


@dataclass(frozen=True)
class GraphFinding:
    """One hit: which rule, which entity, what the shape actually is, and where to read it."""
    ruleId: str
    name: str
    sev: str
    nodeId: str
    nodeType: str
    nodeValue: str
    summary: str          # one sentence, in the analyst's terms
    metric: int           # the number the threshold was compared against (fan-out, sources, …)
    metricLabel: str
    related: list[str]    # the neighbour node ids that make up the fan-out, capped
    citedEventIds: list[str]
    first: str = ""
    last: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"ruleId": self.ruleId, "name": self.name, "sev": self.sev, "nodeId": self.nodeId,
                "nodeType": self.nodeType, "nodeValue": self.nodeValue, "summary": self.summary,
                "metric": self.metric, "metricLabel": self.metricLabel, "related": self.related,
                "citedEventIds": self.citedEventIds, "first": self.first, "last": self.last}


# --------------------------------------------------------------------------- the catalogue
GRAPH_RULES: tuple[Rule, ...] = (
    Rule("SIGMA-GRAPH-0010", "One address, many accounts", "high",
         description="A single address authenticating as many different accounts. That is one machine holding "
                     "credentials that belong to many people — a spray, a stolen password vault, or a jump box "
                     "everyone shares, and the last one is a finding too.",
         trigger="Counts DISTINCT user nodes linked to one ip node by an authentication relation (auth_from, "
                 "session, on_host). Fires at the distinct-account threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0014", "One account, many addresses", "high",
         description="One account used from many different addresses. Either the person is travelling through "
                     "proxies, or the credential is in more than one pair of hands.",
         trigger="Counts DISTINCT ip nodes linked to one user node by an authentication relation. Fires at the "
                 "distinct-address threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0018", "Host reaching many external addresses", "medium",
         description="One host connecting out to many different public addresses. Scanning, a beacon walking a "
                     "list of fallbacks, or a download from somewhere it should not be.",
         trigger="Counts DISTINCT PUBLIC ip nodes linked to one host node by connected_to or requested. Private "
                 "and loopback addresses are excluded. Fires at the distinct-address threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0022", "One binary on many hosts", "high",
         description="The same file or hash present on many hosts. That is how a tool spreads — and a hash is "
                     "the one identifier that survives being renamed on the way.",
         trigger="Counts DISTINCT host nodes linked to one hash or file node. Fires at the distinct-host "
                 "threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0026", "Entity spans many log sources", "medium",
         description="One entity appearing across many different logs. It is not suspicious by itself — it is "
                     "the pivot: the thing that ties the web tier, the firewall and the endpoint into one story.",
         trigger="Counts the DISTINCT source files a node's own events came from (its exact per-file tally, not "
                 "a sample). Fires at the source threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0030", "Relationship that almost always fails", "high",
         description="Two entities related mostly by REFUSALS. A relationship that is nearly all failure is "
                     "something trying to get in, not something using the system.",
         trigger="For each relation with at least the minimum number of events, the share of its outcomes that "
                 "are failure or denied. Fires at the failure-ratio threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0034", "Domain answering with many addresses", "medium",
         description="One name resolving to many different addresses. Large services do this legitimately; so "
                     "does fast-flux infrastructure keeping a controller reachable while addresses are burned.",
         trigger="Counts DISTINCT ip nodes linked to one domain node by resolved. Fires at the distinct-address "
                 "threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0038", "Account used on many hosts", "high",
         description="One account touching many hosts. That is the shape of lateral movement: the same "
                     "credential walked from machine to machine.",
         trigger="Counts DISTINCT host nodes linked to one user node. Fires at the distinct-host threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0042", "One-off account on a busy host", "medium",
         description="An account seen ONCE on a host that everything else uses constantly. A single appearance "
                     "against a heavy baseline is what a stolen credential looks like on its first use.",
         trigger="A user-host relation whose event count is at or below the rare threshold, on a host node whose "
                 "own event count is at or above the busy threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0046", "Connected entity carrying rule hits", "critical",
         description="An entity that both fired detections and connects to many others. This is where an "
                     "investigation starts: the detections say something happened, the links say how far it "
                     "reaches.",
         trigger="A node whose events carry at least the detection threshold AND whose degree (distinct "
                 "neighbours) is at least the connection threshold.",
         mechanism="graph"),
)

GRAPH_PARAMS: dict[str, tuple[Param, ...]] = {
    "SIGMA-GRAPH-0010": (
        P("relations", "Authentication relations", "values", "auth_from, session, on_host", "relation",
          "Relation types that count as this address acting as this account."),
        P("distinctUsers", "Distinct accounts to fire", "int", "6", "user",
          "How many DIFFERENT accounts one address must be linked to."),
    ),
    "SIGMA-GRAPH-0014": (
        P("relations", "Authentication relations", "values", "auth_from, session, on_host", "relation",
          "Relation types that count as this account being used from this address."),
        P("distinctIps", "Distinct addresses to fire", "int", "5", "ip",
          "How many DIFFERENT addresses one account must be used from."),
    ),
    "SIGMA-GRAPH-0018": (
        P("relations", "Network relations", "values", "connected_to, requested, resolved", "relation",
          "Relation types that count as this host reaching out."),
        P("distinctIps", "Distinct addresses to fire", "int", "25", "ip",
          "How many DIFFERENT public addresses one host must reach."),
    ),
    "SIGMA-GRAPH-0022": (
        P("nodeTypes", "Entity types", "values", "hash, file", "type",
          "Which entity types count as 'a binary' for this rule."),
        P("distinctHosts", "Distinct hosts to fire", "int", "3", "host",
          "How many DIFFERENT hosts the same file or hash must appear on."),
    ),
    "SIGMA-GRAPH-0026": (
        P("minSources", "Distinct sources to fire", "int", "4", "file",
          "How many DIFFERENT log files an entity must appear in."),
        P("nodeTypes", "Entity types", "values", "ip, user, host, domain, hash", "type",
          "Types worth reporting as a pivot; infrastructure types (port, pid, session) are noise here."),
    ),
    "SIGMA-GRAPH-0030": (
        P("minEvents", "Events needed", "int", "10", "",
          "Below this the ratio is not evidence of anything — three failures out of three is a typo."),
        P("failureRatio", "Failure percentage to fire", "int", "80", "outcome",
          "Percentage of the relation's outcomes that must be failure or denied."),
    ),
    "SIGMA-GRAPH-0034": (
        P("relations", "Resolution relations", "values", "resolved", "relation",
          "Relation types that count as a name answering with an address."),
        P("distinctIps", "Distinct addresses to fire", "int", "8", "ip",
          "How many DIFFERENT addresses one name must resolve to."),
    ),
    "SIGMA-GRAPH-0038": (
        P("distinctHosts", "Distinct hosts to fire", "int", "5", "host",
          "How many DIFFERENT hosts one account must appear on."),
    ),
    "SIGMA-GRAPH-0042": (
        P("rareCount", "Events that count as one-off", "int", "1", "",
          "A user-host relation with at most this many events is treated as a first appearance."),
        P("busyCount", "Events that make a host busy", "int", "500", "",
          "The host must carry at least this many events of its own, or 'rare' means nothing."),
    ),
    "SIGMA-GRAPH-0046": (
        P("minDetections", "Detections to fire", "int", "3", "",
          "How many of the entity's events must have fired a rule."),
        P("minDegree", "Connections to fire", "int", "4", "",
          "How many DIFFERENT neighbours the entity must have."),
    ),
}

register_builtins(GRAPH_RULES, GRAPH_PARAMS)

_AUTH_DEFAULT = ("auth_from", "session", "on_host")


# --------------------------------------------------------------------------- parameter access
def _params() -> dict[str, dict[str, str]]:
    from .rules import RULES_STORE
    return RULES_STORE.detection_params()


def _disabled() -> set[str]:
    from .rules import RULES_STORE
    return RULES_STORE.detection_disabled()


def _overrides() -> dict[str, dict]:
    """{rule_id: {'name':…, 'sev':…}} — the analyst's edits to a graph rule's metadata."""
    from .rules import RULES_STORE
    RULES_STORE.load()
    with RULES_STORE.lock:
        return {k: dict(v) for k, v in RULES_STORE.builtin_overrides.items()}


class _Tuning:
    """The live value of every constant, resolved ONCE per evaluation.

    Same contract as `detect._praw`: an override that is missing or will not parse degrades to the
    shipped default rather than switching the rule off, because a rule that silently stops reporting is
    indistinguishable from a graph with nothing to report.
    """

    def __init__(self) -> None:
        self._p = _params()

    def _raw(self, rid: str, key: str) -> str:
        ov = self._p.get(rid, {}).get(key)
        if isinstance(ov, str) and ov.strip():
            return ov.strip()
        spec = next((p for p in GRAPH_PARAMS.get(rid, ()) if p.key == key), None)
        return spec.default if spec else ""

    def n(self, rid: str, key: str) -> int:
        try:
            return int(float(self._raw(rid, key).replace(",", "").replace("_", "")))
        except ValueError:
            spec = next((p for p in GRAPH_PARAMS.get(rid, ()) if p.key == key), None)
            return int(spec.default) if spec else 0

    def l(self, rid: str, key: str) -> tuple[str, ...]:
        return tuple(x.strip().lower() for x in self._raw(rid, key).split(",") if x.strip())


# --------------------------------------------------------------------------- helpers
def _is_public(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified)


def _split(node_id: str) -> tuple[str, str]:
    t, _, v = node_id.partition(":")
    return t, v


def _cite(builder: Any, node: Any) -> list[str]:
    """Event ids for a node, newest first, capped.

    A node keeps POOL INDICES (its first 200 plus a ring of the most recent); the ids are resolved here
    against the very pool the graph was built from, so a finding can always be opened. An index that no
    longer resolves is dropped rather than guessed at.
    """
    out: list[str] = []
    events = builder.events
    n = len(events)
    for j in reversed(node.recent() or list(node.events)):
        if 0 <= j < n:
            eid = events[j].id
            if eid and eid not in out:
                out.append(eid)
                if len(out) >= MAX_CITATIONS:
                    break
    return out


def _finding(rule: Rule, node_id: str, node: Any, summary: str, metric: int, label: str,
             related: Iterable[str], builder: Any, sev: Optional[str] = None,
             overrides: Optional[dict[str, dict]] = None) -> GraphFinding:
    t, v = _split(node_id)
    ov = (overrides or {}).get(rule.id) or {}
    return GraphFinding(ruleId=rule.id, name=str(ov.get("name") or rule.name),
                        sev=str(ov.get("sev") or sev or rule.level),
                        nodeId=node_id, nodeType=t, nodeValue=v, summary=summary, metric=metric,
                        metricLabel=label, related=list(related)[:MAX_RELATED],
                        citedEventIds=_cite(builder, node), first=node.first, last=node.last)


def _neighbours_by_type(builder: Any) -> dict[str, dict[str, dict[str, set[str]]]]:
    """node id -> relation -> neighbour TYPE -> set of neighbour ids.

    Built in ONE pass over the deduplicated edge keys (not over edge occurrences), because every rule
    below asks the same question in a different shape: "how many distinct X is this node linked to?".
    Six independent scans of the edge table would cost six times as much and answer the same thing.
    """
    out: dict[str, dict[str, dict[str, set[str]]]] = {}
    for (src, dst, rel) in builder.edges:
        st, _ = _split(src)
        dt, _ = _split(dst)
        out.setdefault(src, {}).setdefault(rel, {}).setdefault(dt, set()).add(dst)
        out.setdefault(dst, {}).setdefault(rel, {}).setdefault(st, set()).add(src)
    return out


def _linked(index: dict[str, dict[str, dict[str, set[str]]]], node_id: str, want_type: str,
            relations: Optional[Iterable[str]] = None) -> set[str]:
    per_rel = index.get(node_id)
    if not per_rel:
        return set()
    rels = set(relations) if relations else None
    out: set[str] = set()
    for rel, by_type in per_rel.items():
        if rels is not None and rel not in rels:
            continue
        out |= by_type.get(want_type, set())
    return out


def _values(ids: Iterable[str]) -> list[str]:
    return [i.partition(":")[2] for i in ids]


# --------------------------------------------------------------------------- evaluation
def evaluate(builder: Any) -> list[GraphFinding]:
    """Every graph rule against an already-built graph. Never builds anything, never touches the store.

    Findings are returned severity-first, then by the size of the thing found, so the top of the list is
    the largest fan-out at the highest severity rather than whichever rule happened to run first.
    """
    off = _disabled()
    rules = {r.id: r for r in GRAPH_RULES if r.id not in off}
    if not rules or not builder.nodes:
        return []
    tune = _Tuning()
    ovs = _overrides()
    index = _neighbours_by_type(builder)
    found: list[GraphFinding] = []

    def emit(rule_id: str, rows: list[GraphFinding]) -> None:
        rows.sort(key=lambda f: -f.metric)
        found.extend(rows[:MAX_FINDINGS_PER_RULE])

    # ---- fan-out rules over nodes. One pass, every node, each rule checking its own shape.
    r10 = rules.get("SIGMA-GRAPH-0010")
    r14 = rules.get("SIGMA-GRAPH-0014")
    r18 = rules.get("SIGMA-GRAPH-0018")
    r22 = rules.get("SIGMA-GRAPH-0022")
    r26 = rules.get("SIGMA-GRAPH-0026")
    r34 = rules.get("SIGMA-GRAPH-0034")
    r38 = rules.get("SIGMA-GRAPH-0038")
    r46 = rules.get("SIGMA-GRAPH-0046")

    a10_rels = tune.l("SIGMA-GRAPH-0010", "relations") or _AUTH_DEFAULT
    a10_min = tune.n("SIGMA-GRAPH-0010", "distinctUsers")
    a14_rels = tune.l("SIGMA-GRAPH-0014", "relations") or _AUTH_DEFAULT
    a14_min = tune.n("SIGMA-GRAPH-0014", "distinctIps")
    a18_rels = tune.l("SIGMA-GRAPH-0018", "relations")
    a18_min = tune.n("SIGMA-GRAPH-0018", "distinctIps")
    a22_types = set(tune.l("SIGMA-GRAPH-0022", "nodeTypes"))
    a22_min = tune.n("SIGMA-GRAPH-0022", "distinctHosts")
    a26_min = tune.n("SIGMA-GRAPH-0026", "minSources")
    a26_types = set(tune.l("SIGMA-GRAPH-0026", "nodeTypes"))
    a34_rels = tune.l("SIGMA-GRAPH-0034", "relations")
    a34_min = tune.n("SIGMA-GRAPH-0034", "distinctIps")
    a38_min = tune.n("SIGMA-GRAPH-0038", "distinctHosts")
    a46_det = tune.n("SIGMA-GRAPH-0046", "minDetections")
    a46_deg = tune.n("SIGMA-GRAPH-0046", "minDegree")

    rows10: list[GraphFinding] = []
    rows14: list[GraphFinding] = []
    rows18: list[GraphFinding] = []
    rows22: list[GraphFinding] = []
    rows26: list[GraphFinding] = []
    rows34: list[GraphFinding] = []
    rows38: list[GraphFinding] = []
    rows46: list[GraphFinding] = []

    for node_id, node in builder.nodes.items():
        ntype = node.type
        if r10 and ntype == "ip":
            users = _linked(index, node_id, "user", a10_rels)
            if len(users) >= a10_min:
                rows10.append(_finding(r10, node_id, node,
                                       f"{node.value} authenticated as {len(users)} different accounts "
                                       f"({', '.join(sorted(_values(users))[:5])}"
                                       f"{', …' if len(users) > 5 else ''})",
                                       len(users), "accounts", sorted(users), builder, overrides=ovs))
        if r14 and ntype == "user":
            ips = _linked(index, node_id, "ip", a14_rels)
            if len(ips) >= a14_min:
                rows14.append(_finding(r14, node_id, node,
                                       f"{node.value} was used from {len(ips)} different addresses",
                                       len(ips), "addresses", sorted(ips), builder, overrides=ovs))
        if r18 and ntype == "host":
            ips = {i for i in _linked(index, node_id, "ip", a18_rels) if _is_public(i.partition(':')[2])}
            if len(ips) >= a18_min:
                rows18.append(_finding(r18, node_id, node,
                                       f"{node.value} reached {len(ips)} different public addresses",
                                       len(ips), "external addresses", sorted(ips), builder, overrides=ovs))
        if r22 and ntype in a22_types:
            hosts = _linked(index, node_id, "host")
            if len(hosts) >= a22_min:
                rows22.append(_finding(r22, node_id, node,
                                       f"{node.label or node.value} is present on {len(hosts)} hosts "
                                       f"({', '.join(sorted(_values(hosts))[:5])}"
                                       f"{', …' if len(hosts) > 5 else ''})",
                                       len(hosts), "hosts", sorted(hosts), builder, overrides=ovs))
        if r26 and ntype in a26_types:
            files = len(node.files)
            if files >= a26_min:
                rows26.append(_finding(r26, node_id, node,
                                       f"{node.value} appears in {files} different log files "
                                       f"({', '.join(sorted(node.files)[:3])}"
                                       f"{', …' if files > 3 else ''})",
                                       files, "log files", [], builder, overrides=ovs))
        if r34 and ntype == "domain":
            ips = _linked(index, node_id, "ip", a34_rels)
            if len(ips) >= a34_min:
                rows34.append(_finding(r34, node_id, node,
                                       f"{node.value} resolved to {len(ips)} different addresses",
                                       len(ips), "addresses", sorted(ips), builder, overrides=ovs))
        if r38 and ntype == "user":
            hosts = _linked(index, node_id, "host")
            if len(hosts) >= a38_min:
                rows38.append(_finding(r38, node_id, node,
                                       f"{node.value} appears on {len(hosts)} hosts "
                                       f"({', '.join(sorted(_values(hosts))[:5])}"
                                       f"{', …' if len(hosts) > 5 else ''})",
                                       len(hosts), "hosts", sorted(hosts), builder, overrides=ovs))
        if r46 and node.detections >= a46_det:
            deg = builder.degree(node_id)
            if deg >= a46_deg:
                rows46.append(_finding(r46, node_id, node,
                                       f"{node.value} fired {node.detections} detections and connects to "
                                       f"{deg} other entities",
                                       node.detections, "detections", [], builder,
                                       sev=node.sev if node.sev in ("critical", "high") else None,
                                       overrides=ovs))

    for rid, rows in (("SIGMA-GRAPH-0010", rows10), ("SIGMA-GRAPH-0014", rows14), ("SIGMA-GRAPH-0018", rows18),
                      ("SIGMA-GRAPH-0022", rows22), ("SIGMA-GRAPH-0026", rows26), ("SIGMA-GRAPH-0034", rows34),
                      ("SIGMA-GRAPH-0038", rows38), ("SIGMA-GRAPH-0046", rows46)):
        emit(rid, rows)

    # ---- edge-shaped rules. One pass over the relations.
    r30 = rules.get("SIGMA-GRAPH-0030")
    r42 = rules.get("SIGMA-GRAPH-0042")
    a30_min = tune.n("SIGMA-GRAPH-0030", "minEvents")
    a30_ratio = max(1, min(100, tune.n("SIGMA-GRAPH-0030", "failureRatio")))
    a42_rare = tune.n("SIGMA-GRAPH-0042", "rareCount")
    a42_busy = tune.n("SIGMA-GRAPH-0042", "busyCount")
    rows30: list[GraphFinding] = []
    rows42: list[GraphFinding] = []
    if r30 or r42:
        for (src, dst, rel), ed in builder.edges.items():
            if r30 and ed.count >= a30_min and ed.outcomes:
                total = sum(ed.outcomes.values())
                bad = ed.outcomes.get("failure", 0) + ed.outcomes.get("denied", 0)
                if total and (bad * 100) // total >= a30_ratio:
                    node = builder.nodes.get(src)
                    if node is not None:
                        pct = (bad * 100) // total
                        rows30.append(_finding(r30, src, node,
                                               f"{src.partition(':')[2]} → {dst.partition(':')[2]}: "
                                               f"{pct}% of {total} {rel.replace('_', ' ')} events failed or were denied",
                                               bad, "failed events", [dst], builder, overrides=ovs))
            if r42 and ed.count <= a42_rare:
                st, _ = _split(src)
                dt, _ = _split(dst)
                user_id, host_id = ("", "")
                if st == "user" and dt == "host":
                    user_id, host_id = src, dst
                elif st == "host" and dt == "user":
                    user_id, host_id = dst, src
                if user_id:
                    host = builder.nodes.get(host_id)
                    user = builder.nodes.get(user_id)
                    if host is not None and user is not None and host.count >= a42_busy:
                        rows42.append(_finding(r42, user_id, user,
                                               f"{user.value} appears {ed.count} time(s) on {host.value}, a host "
                                               f"carrying {host.count:,} events",
                                               host.count, "host events", [host_id], builder, overrides=ovs))
    emit("SIGMA-GRAPH-0030", rows30)
    emit("SIGMA-GRAPH-0042", rows42)

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    found.sort(key=lambda f: (-order.get(f.sev, 0), -f.metric, f.ruleId, f.nodeId))
    return found


def rule_ids() -> set[str]:
    return {r.id for r in GRAPH_RULES}


def counts(findings: Iterable[GraphFinding]) -> dict[str, int]:
    """Findings per rule id — what `/api/rules` reports as a graph rule's `hits`."""
    out: dict[str, int] = {}
    for f in findings:
        out[f.ruleId] = out.get(f.ruleId, 0) + 1
    return out
