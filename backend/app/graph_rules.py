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

Cost: passes over the nodes and the edges of an ALREADY-BUILT graph — no extraction, no walk of the
pool. It is never allowed to trigger a graph build (see `routers/graph.graph_anomalies`), because a
rule roll-up must not be the thing that starts a 90-second extraction, and `graph_findings` memoises
the result per (graph, rule catalogue, exclusion list) so it is paid once per graph rather than once
per request.

Measured here on a synthetic graph of the size CLAUDE.md records for the analyst's workspace
(18,429 nodes / 221,239 relations), best of five, warm:

    the ten fan-out / edge rules                      897 ms
    plus SIGMA-GRAPH-0050 (bridges) and -0054       1,704 ms

The structural rules cost what they cost: a bridge is a global property, so finding one needs the
undirected adjacency (`_adjacency`, one walk of the edge keys) and a Tarjan low-link pass over it.
Both are O(nodes + relations) — the same order as `_neighbours_by_type`, which the module already
pays for — and `SIGMA-GRAPH-0050.maxNodes` is the bound that keeps it from growing without limit on
a graph nobody sized for. Disabling either rule removes its cost entirely; nothing here is built
speculatively.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
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
    # The OTHER END, when the finding is about one RELATION rather than about a node's fan-out.
    # A fan-out finding ("this account was used on nine hosts") is a property of the node and
    # `related` is the nine; a relation finding ("A to B is 99% failures") is a property of the
    # PAIR, and without naming B the screen can only offer everything A ever did — which is what
    # "the graph and events do not show the specific flagged items" meant. Empty for fan-out rules.
    peerId: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"ruleId": self.ruleId, "name": self.name, "sev": self.sev, "nodeId": self.nodeId,
                "nodeType": self.nodeType, "nodeValue": self.nodeValue, "summary": self.summary,
                "metric": self.metric, "metricLabel": self.metricLabel, "related": self.related,
                "citedEventIds": self.citedEventIds, "first": self.first, "last": self.last,
                "peerId": self.peerId}


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
         trigger="A node of one of the reported types whose events carry at least the detection threshold "
                 "AND whose degree (distinct neighbours) is at least the connection threshold.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0050", "The only link between two groups", "medium",
         description="One relation holds two otherwise separate parts of the picture together. Cut it and "
                     "the graph falls into two pieces. That is where an investigation should look first: "
                     "whatever crossed between those groups crossed HERE, and nowhere else. It is the jump "
                     "host, the shared account, the one file that travelled - and it is a property of the "
                     "PAIR, which is why the finding names both ends and cites the relation's own events.",
         trigger="A bridge in the undirected graph (Tarjan low-link) whose removal separates two groups, "
                 "each holding at least the minimum number of entities. Skipped entirely above the node "
                 "cap, because this runs on the request thread.",
         mechanism="graph"),
    Rule("SIGMA-GRAPH-0054", "Outside address reaching into the estate through one account", "high",
         description="A public address used an account a handful of times, and that account is on several "
                     "machines. Read forwards it is the shape of an intrusion: something outside, a "
                     "credential, then the estate. Read backwards it is the question worth asking about any "
                     "external login - what does that account actually reach?",
         trigger="A PUBLIC ip node linked to a user node by an authentication relation whose event count is "
                 "at or below the rare threshold, where that user is also linked to at least the minimum "
                 "number of host nodes. The peer is the account; the related entities are the hosts.",
         mechanism="graph"),
)

GRAPH_PARAMS: dict[str, tuple[Param, ...]] = {
    "SIGMA-GRAPH-0010": (
        P("relations", "Authentication relations", "values", "auth_from, session, on_host", "relation",
          "Relation types that count as this address acting as this account."),
        P("distinctUsers", "Distinct accounts to fire", "int", "6", "user",
          "How many DIFFERENT accounts one address must be linked to."),
        P("outlierMultiplier", "Outlier multiple", "int", "3", "",
          "The address must ALSO reach this many times the 90th-percentile fan-out of the other "
          "addresses in this graph. A domain controller, a VPN concentrator and a proxy all make this "
          "shape and all of them are the norm in their own workspace. Set to 1 to use the fixed "
          "threshold alone."),
        P("minPopulation", "Comparable entities needed", "int", "40", "",
          "Below this many addresses the distribution describes nothing and only the fixed threshold "
          "applies - a small graph must not invent outliers out of four data points."),
        P("burstHours", "Hours that count as compressed", "int", "1", "",
          "An address whose whole life in the logs fits inside this many hours is reported CRITICAL: "
          "forty accounts over three weeks is a shared bastion, forty accounts in four minutes is a "
          "spray, and they are the same shape. Set to 0 to report every one at the shipped severity."),
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
        P("outlierMultiplier", "Outlier multiple", "int", "3", "",
          "The host must ALSO reach this many times the 90th-percentile external fan-out of the other "
          "hosts here. Any workstation with a browser passes a fixed 25 in a minute; what is worth "
          "reporting is the one reaching further than its neighbours. Set to 1 for the fixed threshold "
          "alone."),
        P("minPopulation", "Comparable entities needed", "int", "40", "",
          "Below this many hosts the distribution describes nothing and only the fixed threshold applies."),
        P("burstHours", "Hours that count as compressed", "int", "1", "",
          "A host whose whole life in the logs fits inside this many hours is reported CRITICAL - that "
          "is a scan or a beacon walking its fallbacks, not a day of browsing. 0 disables the escalation."),
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
        P("outlierMultiplier", "Outlier multiple", "int", "3", "",
          "The name must ALSO resolve to this many times the 90th-percentile address count of the "
          "other names here. Every CDN-hosted name answers with a pool; fast flux is the one that "
          "answers with far more than its neighbours. Set to 1 for the fixed threshold alone."),
        P("minPopulation", "Comparable entities needed", "int", "40", "",
          "Below this many names the distribution describes nothing and only the fixed threshold applies."),
        P("burstHours", "Hours that count as compressed", "int", "1", "",
          "A name whose whole life in the logs fits inside this many hours is reported CRITICAL: a "
          "long-lived CDN name does not appear and vanish inside an hour. 0 disables the escalation."),
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
        P("nodeTypes", "Entity types", "values", "ip, user, host, domain, hash, file, process", "type",
          "Types worth reporting. Without this the rule fired on INFRASTRUCTURE nodes - port:443 has "
          "a detection on nearly every event that mentions it and a degree in the thousands, so it "
          "was reported `critical` as the most connected entity carrying rule hits in the workspace, "
          "which is true and says nothing."),
    ),
    "SIGMA-GRAPH-0050": (
        P("minSide", "Entities each side must hold", "int", "3", "",
          "How many entities the SMALLER of the two groups must contain. Every leaf's single relation "
          "is technically a bridge; this is what separates 'the only way between two parts of the "
          "picture' from 'a node with one link'."),
        P("maxNodes", "Largest graph to analyse", "int", "20000", "",
          "The bridge pass is linear in nodes+relations but it runs on the request thread. Above this "
          "the rule reports nothing rather than making the Anomalies screen wait."),
    ),
    "SIGMA-GRAPH-0054": (
        P("relations", "Authentication relations", "values", "auth_from, session, on_host", "relation",
          "Relation types that count as this address being used as this account."),
        P("rareCount", "Events that count as a first use", "int", "3", "",
          "The address-to-account relation must be at most this many events. A busy relation is the "
          "person who works remotely; a handful is a first use."),
        P("minHosts", "Hosts the account must reach", "int", "2", "host",
          "How far into the estate the account goes. One host is a login; several is a path."),
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
@lru_cache(maxsize=65536)
def _is_public(value: str) -> bool:
    """Cached because rule 0018 asks it once per (host, ip-neighbour) PAIR, not once per address:
    on the analyst-sized graph that is 45,831 calls over ~7,000 distinct addresses, and each one
    parses the string with `ipaddress` and then asks six properties of the result — measured 1.77 s
    of a 6.42 s profile. Same input, same answer; `normalize.is_public_ip` is cached on the detection
    path for exactly this reason. The size is bounded so a long-lived process cannot grow one entry
    per address it has ever seen."""
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


def _cite_edge(edge: Any) -> list[str]:
    """Event ids for one RELATION — these are already ids, kept by the aggregator (capped at 20).

    Newest last in insertion order, so the newest-first convention `_cite` uses is reproduced by
    reversing. No pool lookup is needed and none is done: an edge stores ids, a node stores indices.
    """
    out: list[str] = []
    for eid in reversed(getattr(edge, "events", ()) or ()):
        if eid and eid not in out:
            out.append(eid)
            if len(out) >= MAX_CITATIONS:
                break
    return out


def _finding(rule: Rule, node_id: str, node: Any, summary: str, metric: int, label: str,
             related: Iterable[str], builder: Any, sev: Optional[str] = None,
             overrides: Optional[dict[str, dict]] = None,
             peer: str = "", edge: Any = None) -> GraphFinding:
    """`edge` is the relation the finding is ABOUT, when it is about one.

    Citations then come from that relation's own events instead of the node's most recent ones. The
    difference is not cosmetic: 10.0.0.134 has a failing relation to 103.156.38.160 AND one to
    103.156.9.160, and citing the node gave both findings the SAME eight event ids — neither set
    being events of the relation being claimed. A citation that resolves cleanly to the wrong
    evidence is the worst failure available here, so an edge finding cites its edge.
    """
    t, v = _split(node_id)
    ov = (overrides or {}).get(rule.id) or {}
    # The edge is preferred and the node is the fallback, never the other way round: the aggregator
    # keeps at most 20 ids per relation and an event with no id contributes none, so an edge CAN come
    # back with nothing. "A finding you cannot open is an assertion" outranks the precision here —
    # the node's events are still genuinely this node's, and this is the behaviour that shipped
    # before. Every real relation has ids, so the exact path is the one that runs.
    cited = (_cite_edge(edge) if edge is not None else []) or _cite(builder, node)
    first, last = (edge.first, edge.last) if edge is not None else (node.first, node.last)
    return GraphFinding(ruleId=rule.id, name=str(ov.get("name") or rule.name),
                        sev=str(ov.get("sev") or sev or rule.level),
                        nodeId=node_id, nodeType=t, nodeValue=v, summary=summary, metric=metric,
                        metricLabel=label, related=list(related)[:MAX_RELATED],
                        citedEventIds=cited, first=first, last=last, peerId=peer)


def _neighbours_by_type(builder: Any) -> dict[str, dict[str, dict[str, set[str]]]]:
    """node id -> relation -> neighbour TYPE -> set of neighbour ids.

    Built in ONE pass over the deduplicated edge keys (not over edge occurrences), because every rule
    below asks the same question in a different shape: "how many distinct X is this node linked to?".
    Six independent scans of the edge table would cost six times as much and answer the same thing.

    Folding `_adjacency`'s undirected sets into this same pass was TRIED and measured SLOWER — this
    body is the hot loop of the whole module and the extra branch plus two set writes per relation
    cost 608 ms at 221,239 relations, against 254 ms for the separate tight loop. A shared walk is
    usually the cheaper shape; here it is not, so the two stay apart.
    """
    out: dict[str, dict[str, dict[str, set[str]]]] = {}
    for (src, dst, rel) in builder.edges:
        # `_split` inlined: only the TYPE half is wanted here and this runs twice per relation —
        # 442,478 calls on the analyst's graph, each returning a tuple that is immediately discarded.
        st = src.partition(":")[0]
        dt = dst.partition(":")[0]
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


# --------------------------------------------------------------------------- context, not thresholds
def _outlier_floor(values: list[int], multiplier: int, min_population: int) -> int:
    """A threshold read off THIS graph rather than fixed in Python.

    Every fan-out rule here answers "is this a lot?", and a fixed number cannot: 25 external
    addresses is a quiet afternoon for a workstation with a browser and an extraordinary number for
    a database server. So the rule keeps its shipped floor — which is what protects a small graph,
    where a distribution means nothing — and ALSO requires the node to stand out against the other
    nodes of its own type in the same workspace.

    p90 rather than the median, because the interesting population is not "every address" but
    "addresses that do a lot of this", and a distribution of mostly-ones has a median of one. Returns
    0 (no additional floor) when the multiplier is off or the population is too small to describe.
    """
    if multiplier <= 1 or len(values) < min_population:
        return 0
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * 0.9))] * multiplier


_MONTH_DAYS = (0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334)


def _epoch(iso: str) -> Optional[float]:
    """`2026-05-01T10:00:00Z` -> seconds. Hand-parsed for the same reason `store._iso_to_epoch` is:
    `strptime` is microseconds per call and this is asked for every finding that survives the cut."""
    try:
        y, mo, d = int(iso[0:4]), int(iso[5:7]), int(iso[8:10])
        h, mi, s = int(iso[11:13]), int(iso[14:16]), int(iso[17:19])
    except (ValueError, IndexError):
        return None
    if not (1970 <= y <= 2200 and 1 <= mo <= 12 and 1 <= d <= 31):
        return None
    days = (y - 1970) * 365 + (y - 1969) // 4 - (y - 1901) // 100 + (y - 1601) // 400
    days += _MONTH_DAYS[mo - 1] + (d - 1)
    if mo > 2 and (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)):
        days += 1
    return days * 86400.0 + h * 3600 + mi * 60 + s


def _compressed(first: str, last: str, hours: int) -> bool:
    """Did the whole of this entity's life happen inside `hours`?

    This is the single cheapest thing that separates a SPRAY from a JUMP BOX, and both make the same
    shape. Forty accounts from one address over three weeks is a shared bastion; forty accounts from
    one address in four minutes is an attack. The rule reports both - it has to, the second one is
    real evidence - but it says which it is looking at, and it raises the severity for the one that
    could not be routine.
    """
    if hours <= 0 or not first or not last:
        return False
    a, b = _epoch(first), _epoch(last)
    if a is None or b is None:
        return False
    return 0 <= (b - a) <= hours * 3600.0


def _adjacency(builder: Any) -> dict[str, set[str]]:
    """The graph as an UNDIRECTED simple graph, which is what the structural rules need.

    Built separately from `_neighbours_by_type` and only when a rule that needs it is enabled: it is
    a second pass over the edge keys, and six of the ten rules never look at it.
    """
    out: dict[str, set[str]] = {}
    for (src, dst, _rel) in builder.edges:
        if src == dst:
            continue
        out.setdefault(src, set()).add(dst)
        out.setdefault(dst, set()).add(src)
    return out


def _bridges(adj: dict[str, set[str]], max_nodes: int) -> list[tuple[str, str, int]]:
    """Every relation whose removal splits the graph, with the size of the SMALLER side.

    An iterative Tarjan low-link pass, O(nodes + relations). Iterative and not recursive on purpose:
    a chain of entities is exactly the shape that makes a graph deep, and Python's recursion limit
    would turn the most interesting graph into a RecursionError.

    `max_nodes` is a real bound, not a nicety. `graph_findings.ready()` runs this on the REQUEST
    thread, so a pass that grows without limit would put an unbounded wait in front of the Anomalies
    screen. Over the cap the rule reports nothing rather than reporting slowly - and says so through
    its parameter, which is the analyst's to raise.

    Returns (a, b, smaller_side). The leaf case - every pendant node's single edge is a bridge - is
    left to the caller's `minSide`, because it is the caller that knows what 'a group' means.
    """
    if not adj or len(adj) > max_nodes:
        return []
    disc: dict[str, int] = {}
    low: dict[str, int] = {}
    size: dict[str, int] = {}
    out: list[tuple[str, str, int]] = []
    timer = 0
    for root in adj:
        if root in disc:
            continue
        disc[root] = low[root] = timer
        timer += 1
        size[root] = 1
        seen_in_component = 1
        component_bridges: list[tuple[str, str, str]] = []   # (a, b, subtree root)
        stack = [(root, iter(adj[root]), "")]
        while stack:
            u, it, pu = stack[-1]
            descended = False
            for v in it:
                if v == pu:
                    continue                    # a simple graph, so the parent appears once
                if v in disc:
                    if disc[v] < low[u]:
                        low[u] = disc[v]
                else:
                    disc[v] = low[v] = timer
                    timer += 1
                    size[v] = 1
                    seen_in_component += 1
                    stack.append((v, iter(adj[v]), u))
                    descended = True
                    break
            if descended:
                continue
            stack.pop()
            if pu:
                if low[u] < low[pu]:
                    low[pu] = low[u]
                size[pu] += size[u]
                if low[u] > disc[pu]:
                    component_bridges.append((pu, u, u))
        for a, b, sub in component_bridges:
            side = size[sub]
            out.append((a, b, min(side, seen_in_component - side)))
    return out


def _pair_index(builder: Any, wanted: Optional[set[tuple[str, str]]] = None
                ) -> dict[tuple[str, str], tuple[Any, str]]:
    """{unordered pair -> (strongest edge, its relation)}, in ONE pass over the edge table.

    A finding about a pair has to cite THAT PAIR's events (`_cite_edge`), so it needs the edge
    object; looking it up by scanning the edges per pair would be O(relations) per finding, which on
    a 221k-relation graph is the whole budget several times over. "Strongest" is the event count, so
    the citation comes from the relation that actually carries the evidence rather than from
    whichever key happened to be inserted first.

    `wanted` is the set of pairs the caller will actually ask about. Measured at 221,239 relations:
    building the whole index costs 510 ms of dict writes, and the structural rules ask about a few
    hundred pairs. With `wanted` the pass is a membership test per relation and the writes disappear.
    """
    out: dict[tuple[str, str], tuple[Any, str]] = {}
    for (src, dst, rel), ed in builder.edges.items():
        if src == dst:
            continue
        k = (src, dst) if src <= dst else (dst, src)
        if wanted is not None and k not in wanted:
            continue
        cur = out.get(k)
        if cur is None or ed.count > cur[0].count:
            out[k] = (ed, rel)
    return out


def _pair(index: dict[tuple[str, str], tuple[Any, str]], a: str, b: str) -> tuple[Any, str]:
    return index.get((a, b) if a <= b else (b, a), (None, ""))


# --------------------------------------------------------------------------- evaluation
def evaluate(builder: Any) -> list[GraphFinding]:
    """Every graph rule against an already-built graph. Never builds anything, never touches the store.

    Findings are returned severity-first, then by the size of the thing found, so the top of the list is
    the largest fan-out at the highest severity rather than whichever rule happened to run first.

    A candidate is collected as a CHEAP TUPLE — its metric, its node, and whatever the sentence will
    need — and `_finding` runs only for the rows that survive `MAX_FINDINGS_PER_RULE`. That matters
    because `_finding` formats a summary, sorts the neighbour ids and, above all, calls `_cite`, which
    walks a node's head-plus-ring event indices and resolves each one against the pool. Measured on a
    graph of the size CLAUDE.md records for the analyst's workspace (18,429 nodes / 221,239 relations):
    64,418 findings were built and cited in order to return 250.

    It is EXACT, not an approximation of the old answer. `emit` sorted the finished findings on
    `-f.metric` with a stable sort, so a tie was broken by the order the nodes were appended, which is
    `builder.nodes` iteration order. The tuples are appended in that same order and sorted on the same
    number by the same stable sort, so the survivors and their order cannot move.
    `tests/test_graph_rules_candidates.py` keeps the build-everything-first version as the oracle and
    compares finding for finding on randomised graphs.
    """
    off = _disabled()
    rules = {r.id: r for r in GRAPH_RULES if r.id not in off}
    if not rules or not builder.nodes:
        return []
    tune = _Tuning()
    ovs = _overrides()
    index = _neighbours_by_type(builder)
    found: list[GraphFinding] = []

    def emit(rows: list[tuple], make: Callable[[tuple], GraphFinding]) -> None:
        rows.sort(key=lambda r: -r[0])          # r[0] IS the metric, and the sort is stable
        found.extend(make(r) for r in rows[:MAX_FINDINGS_PER_RULE])

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
    a46_types = set(tune.l("SIGMA-GRAPH-0046", "nodeTypes"))
    # The three rules whose shape is ALSO the shape of ordinary infrastructure. Each keeps its fixed
    # floor and gains a second one read off this graph (see `_outlier_floor`), plus a severity
    # escalation when the whole fan-out is compressed into a short window (see `_compressed`).
    a10_mult, a10_pop = tune.n("SIGMA-GRAPH-0010", "outlierMultiplier"), tune.n("SIGMA-GRAPH-0010", "minPopulation")
    a18_mult, a18_pop = tune.n("SIGMA-GRAPH-0018", "outlierMultiplier"), tune.n("SIGMA-GRAPH-0018", "minPopulation")
    a34_mult, a34_pop = tune.n("SIGMA-GRAPH-0034", "outlierMultiplier"), tune.n("SIGMA-GRAPH-0034", "minPopulation")
    a10_burst = tune.n("SIGMA-GRAPH-0010", "burstHours")
    a18_burst = tune.n("SIGMA-GRAPH-0018", "burstHours")
    a34_burst = tune.n("SIGMA-GRAPH-0034", "burstHours")
    dist10: list[int] = []
    dist18: list[int] = []
    dist34: list[int] = []

    # (metric, node id, node, …whatever that rule's sentence needs). Nothing here formats a string,
    # sorts a neighbour list or touches the pool.
    rows10: list[tuple] = []
    rows14: list[tuple] = []
    rows18: list[tuple] = []
    rows22: list[tuple] = []
    rows26: list[tuple] = []
    rows34: list[tuple] = []
    rows38: list[tuple] = []
    rows46: list[tuple] = []

    for node_id, node in builder.nodes.items():
        ntype = node.type
        if r10 and ntype == "ip":
            users = _linked(index, node_id, "user", a10_rels)
            if users:
                dist10.append(len(users))
            if len(users) >= a10_min:
                rows10.append((len(users), node_id, node, users))
        if r14 and ntype == "user":
            ips = _linked(index, node_id, "ip", a14_rels)
            if len(ips) >= a14_min:
                rows14.append((len(ips), node_id, node, ips))
        if r18 and ntype == "host":
            ips = {i for i in _linked(index, node_id, "ip", a18_rels) if _is_public(i.partition(':')[2])}
            if ips:
                dist18.append(len(ips))
            if len(ips) >= a18_min:
                rows18.append((len(ips), node_id, node, ips))
        if r22 and ntype in a22_types:
            hosts = _linked(index, node_id, "host")
            if len(hosts) >= a22_min:
                rows22.append((len(hosts), node_id, node, hosts))
        if r26 and ntype in a26_types:
            files = len(node.files)
            if files >= a26_min:
                rows26.append((files, node_id, node))
        if r34 and ntype == "domain":
            ips = _linked(index, node_id, "ip", a34_rels)
            if ips:
                dist34.append(len(ips))
            if len(ips) >= a34_min:
                rows34.append((len(ips), node_id, node, ips))
        if r38 and ntype == "user":
            hosts = _linked(index, node_id, "host")
            if len(hosts) >= a38_min:
                rows38.append((len(hosts), node_id, node, hosts))
        if r46 and ntype in a46_types and node.detections >= a46_det:
            deg = builder.degree(node_id)
            if deg >= a46_deg:
                rows46.append((node.detections, node_id, node, deg))

    def make10(r: tuple) -> GraphFinding:
        n, node_id, node, users = r
        fast = _compressed(node.first, node.last, a10_burst)
        return _finding(r10, node_id, node,
                        f"{node.value} authenticated as {n} different accounts "
                        f"({', '.join(sorted(_values(users))[:5])}"
                        f"{', …' if n > 5 else ''})"
                        + (f" — all of it inside {a10_burst}h" if fast else ""),
                        n, "accounts", sorted(users), builder,
                        sev="critical" if fast else None, overrides=ovs)

    def make14(r: tuple) -> GraphFinding:
        n, node_id, node, ips = r
        return _finding(r14, node_id, node,
                        f"{node.value} was used from {n} different addresses",
                        n, "addresses", sorted(ips), builder, overrides=ovs)

    def make18(r: tuple) -> GraphFinding:
        n, node_id, node, ips = r
        fast = _compressed(node.first, node.last, a18_burst)
        return _finding(r18, node_id, node,
                        f"{node.value} reached {n} different public addresses"
                        + (f" — all of it inside {a18_burst}h" if fast else ""),
                        n, "external addresses", sorted(ips), builder,
                        sev="critical" if fast else None, overrides=ovs)

    def make22(r: tuple) -> GraphFinding:
        n, node_id, node, hosts = r
        return _finding(r22, node_id, node,
                        f"{node.label or node.value} is present on {n} hosts "
                        f"({', '.join(sorted(_values(hosts))[:5])}"
                        f"{', …' if n > 5 else ''})",
                        n, "hosts", sorted(hosts), builder, overrides=ovs)

    def make26(r: tuple) -> GraphFinding:
        files, node_id, node = r
        return _finding(r26, node_id, node,
                        f"{node.value} appears in {files} different log files "
                        f"({', '.join(sorted(node.files)[:3])}"
                        f"{', …' if files > 3 else ''})",
                        files, "log files", [], builder, overrides=ovs)

    def make34(r: tuple) -> GraphFinding:
        n, node_id, node, ips = r
        fast = _compressed(node.first, node.last, a34_burst)
        return _finding(r34, node_id, node,
                        f"{node.value} resolved to {n} different addresses"
                        + (f" — all of it inside {a34_burst}h" if fast else ""),
                        n, "addresses", sorted(ips), builder,
                        sev="critical" if fast else None, overrides=ovs)

    def make38(r: tuple) -> GraphFinding:
        n, node_id, node, hosts = r
        return _finding(r38, node_id, node,
                        f"{node.value} appears on {n} hosts "
                        f"({', '.join(sorted(_values(hosts))[:5])}"
                        f"{', …' if n > 5 else ''})",
                        n, "hosts", sorted(hosts), builder, overrides=ovs)

    def make46(r: tuple) -> GraphFinding:
        dets, node_id, node, deg = r
        return _finding(r46, node_id, node,
                        f"{node.value} fired {dets} detections and connects to "
                        f"{deg} other entities",
                        dets, "detections", [], builder,
                        sev=node.sev if node.sev in ("critical", "high") else None,
                        overrides=ovs)

    # The second floor, read off this graph. Applied to the CANDIDATE ROWS rather than inside the
    # node loop because it cannot be known until every node of the type has been counted.
    f10 = _outlier_floor(dist10, a10_mult, a10_pop)
    f18 = _outlier_floor(dist18, a18_mult, a18_pop)
    f34 = _outlier_floor(dist34, a34_mult, a34_pop)
    if f10:
        rows10 = [r for r in rows10 if r[0] >= f10]
    if f18:
        rows18 = [r for r in rows18 if r[0] >= f18]
    if f34:
        rows34 = [r for r in rows34 if r[0] >= f34]

    for rows, make in ((rows10, make10), (rows14, make14), (rows18, make18), (rows22, make22),
                       (rows26, make26), (rows34, make34), (rows38, make38), (rows46, make46)):
        emit(rows, make)

    # ---- edge-shaped rules. One pass over the relations.
    r30 = rules.get("SIGMA-GRAPH-0030")
    r42 = rules.get("SIGMA-GRAPH-0042")
    a30_min = tune.n("SIGMA-GRAPH-0030", "minEvents")
    a30_ratio = max(1, min(100, tune.n("SIGMA-GRAPH-0030", "failureRatio")))
    a42_rare = tune.n("SIGMA-GRAPH-0042", "rareCount")
    a42_busy = tune.n("SIGMA-GRAPH-0042", "busyCount")
    rows30: list[tuple] = []
    rows42: list[tuple] = []
    if r30 or r42:
        for (src, dst, rel), ed in builder.edges.items():
            if r30 and ed.count >= a30_min and ed.outcomes:
                total = sum(ed.outcomes.values())
                bad = ed.outcomes.get("failure", 0) + ed.outcomes.get("denied", 0)
                if total and (bad * 100) // total >= a30_ratio:
                    node = builder.nodes.get(src)
                    if node is not None:
                        # `ed` rides along so the finding can cite the RELATION rather than the node.
                        # Appended LAST: `emit` sorts on r[0] only, so the tuple's shape is free to
                        # grow at the end without moving a single survivor.
                        rows30.append((bad, src, node, dst, rel, (bad * 100) // total, total, ed))
            if r42 and ed.count <= a42_rare:
                st = src.partition(":")[0]
                dt = dst.partition(":")[0]
                user_id, host_id = ("", "")
                if st == "user" and dt == "host":
                    user_id, host_id = src, dst
                elif st == "host" and dt == "user":
                    user_id, host_id = dst, src
                if user_id:
                    host = builder.nodes.get(host_id)
                    user = builder.nodes.get(user_id)
                    if host is not None and user is not None and host.count >= a42_busy:
                        rows42.append((host.count, user_id, user, host_id, host, ed.count, ed))

    def make30(r: tuple) -> GraphFinding:
        bad, src, node, dst, rel, pct, total, ed = r
        return _finding(r30, src, node,
                        f"{src.partition(':')[2]} → {dst.partition(':')[2]}: "
                        f"{pct}% of {total} {rel.replace('_', ' ')} events failed or were denied",
                        bad, "failed events", [dst], builder, overrides=ovs, peer=dst, edge=ed)

    def make42(r: tuple) -> GraphFinding:
        hcount, user_id, user, host_id, host, count, ed = r
        return _finding(r42, user_id, user,
                        f"{user.value} appears {count} time(s) on {host.value}, a host "
                        f"carrying {hcount:,} events",
                        hcount, "host events", [host_id], builder, overrides=ovs,
                        peer=host_id, edge=ed)

    emit(rows30, make30)
    emit(rows42, make42)

    # ---- structural rules: about a PAIR or a PATH rather than about a node's fan-out, so each one
    # names its peer and cites the relation's own events.
    #
    # Both need the EDGE OBJECT behind a pair, and the edge table is the biggest thing here. So the
    # candidates are collected FIRST, their pairs are gathered into one set, and the edge table is
    # walked ONCE keeping only those. Building the whole pair index instead measured 510 ms at
    # 221,239 relations, to answer a few hundred questions.
    r50 = rules.get("SIGMA-GRAPH-0050")
    r54 = rules.get("SIGMA-GRAPH-0054")
    wanted: set[tuple[str, str]] = set()
    cand50: list[tuple] = []
    cand54: list[tuple] = []

    def want(a: str, b: str) -> None:
        wanted.add((a, b) if a <= b else (b, a))

    if r50:
        a50_side = tune.n("SIGMA-GRAPH-0050", "minSide")
        a50_max = tune.n("SIGMA-GRAPH-0050", "maxNodes")
        for a, b, side in _bridges(_adjacency(builder), a50_max):
            if side < a50_side:
                continue
            node, peer = builder.nodes.get(a), builder.nodes.get(b)
            if node is None or peer is None:
                continue
            cand50.append((side, a, node, b, peer))
            want(a, b)
    if r54:
        a54_rels = tune.l("SIGMA-GRAPH-0054", "relations") or _AUTH_DEFAULT
        a54_rare = tune.n("SIGMA-GRAPH-0054", "rareCount")
        a54_hosts = tune.n("SIGMA-GRAPH-0054", "minHosts")
        # Memoised: an account reached from twelve outside addresses asked the SAME question about
        # its hosts twelve times, and `_linked` walks that node's whole relation index each time —
        # measured as 35,000 extra calls and ~0.4 s on an 18k-node graph.
        hosts_of: dict[str, set[str]] = {}
        for node_id, node in builder.nodes.items():
            if node.type != "ip" or not _is_public(node.value):
                continue
            for user_id in _linked(index, node_id, "user", a54_rels):
                hosts = hosts_of.get(user_id)
                if hosts is None:
                    hosts = hosts_of[user_id] = _linked(index, user_id, "host")
                if len(hosts) < a54_hosts:
                    continue
                user = builder.nodes.get(user_id)
                if user is not None:
                    cand54.append((len(hosts), node_id, node, user_id, user, hosts))
                    want(node_id, user_id)

    pairs = _pair_index(builder, wanted) if wanted else {}

    if r50:
        rows50 = [(side, a, node, b, peer) + _pair(pairs, a, b) for side, a, node, b, peer in cand50]

        def make50(r: tuple) -> GraphFinding:
            side, a, node, b, peer, ed, rel = r
            return _finding(r50, a, node,
                            f"{node.value} → {peer.value} is the ONLY link between two groups of "
                            f"entities; the smaller side holds {side}"
                            + (f" ({rel.replace('_', ' ')})" if rel else ""),
                            side, "entities cut off", [b], builder, overrides=ovs, peer=b, edge=ed)

        emit(rows50, make50)

    if r54:
        rows54: list[tuple] = []
        for n, node_id, node, user_id, user, hosts in cand54:
            ed, _rel = _pair(pairs, node_id, user_id)
            if ed is None or ed.count > a54_rare:
                continue
            rows54.append((n, node_id, node, user_id, user, ed.count, hosts, ed))

        def make54(r: tuple) -> GraphFinding:
            n, node_id, node, user_id, user, count, hosts, ed = r
            return _finding(r54, node_id, node,
                            f"{node.value} used {user.value} {count} time(s), and that account "
                            f"reaches {n} hosts ({', '.join(sorted(_values(hosts))[:5])}"
                            f"{', …' if n > 5 else ''})",
                            n, "hosts reached", sorted(hosts), builder, overrides=ovs,
                            peer=user_id, edge=ed)

        emit(rows54, make54)

    # Exclusions apply here too, but ONLY the ones that can be evaluated against a node — a node has a
    # type and a value and no fields, so an exclusion reading `dst_port` cannot be checked against one.
    # `Matcher.excluded_node` skips those rather than half-applying them (exclusions.appliesToGraph says
    # so on the row), because suppressing a finding on a condition nobody checked is the worst outcome
    # available here. The suggested "public DNS resolvers" exclusion is exactly why this exists: 8.8.8.8
    # is the biggest fan-out in most workspaces and it is not a finding.
    try:
        from .exclusions import EXCLUSIONS
        ex = EXCLUSIONS.matcher()
    except Exception:  # noqa: BLE001 - a graph roll-up must not fail over a suppression list
        ex = None
    if ex is not None and not ex.empty:
        found = [f for f in found if not ex.excluded_node(f.nodeType, f.nodeValue, f.ruleId)]

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
