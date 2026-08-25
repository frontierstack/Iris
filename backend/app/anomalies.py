"""Anomaly aggregation — one row per rule that fired, built ONCE per (store version, rules revision).

`GET /api/anomalies` is pure aggregation over `STORE.events`: every event, every detection on it, folded
into a per-rule row (hits, first/last seen, sources, ≤5 sample events). At 1,224,226 events that walk took
~1 s **on every request**, under the store lock, and both the sidebar count and the Anomalies screen ask
for it — so the pool was being walked twice per screen load while holding the lock that ingest needs.

It is now a `derived.AsyncCache` slot, exactly like `graph.GRAPH_CACHE` and `correlate.ANALYSIS_CACHE`:
built once per key in a background thread, single-flight, with a `status()` the endpoint reports so the
screen can say *building, 42 %* rather than render an empty list — an empty anomaly list is read by an
analyst as "nothing fired", which is a lie about the evidence while a build is still running.

THE KEY IS NOT JUST THE STORE VERSION. Anomalies also depend on the RULE CATALOGUE: a row carries the
rule's current name, severity and kind, and which rules exist at all decides which rows there are. Every
mutating rule endpoint does currently route through `Store.reapply_rule` / `reapply_all_rules`, which
bump the store version — but that is a property of five call sites in `routers/rules.py`, not of the
cache, and a future edit that renames a rule without re-running detections would silently serve the old
name forever. So the key carries `RULES_STORE.rev` (bumped in `RulesStore.save()`, which every mutator
calls) as well: a rule change misses the cache by construction, whatever the store does.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from .derived import DEFAULT_SYNC_LIMIT, AsyncCache
from .models import AnomalyCase, SEV_ORDER, Anomaly
from .rules import RULES_STORE
from .store import STORE

SLOT = "all"


def _sync_limit() -> int:
    """Pools at or below this many events aggregate on the request thread (well under a second)."""
    try:
        return int(os.environ.get("IRIS_ANOMALY_SYNC_MAX", DEFAULT_SYNC_LIMIT))
    except ValueError:
        return DEFAULT_SYNC_LIMIT


# One aggregation, keyed on (store version, rules revision). Nothing else may build it.
ANOMALY_CACHE = AsyncCache("anomalies", sync_limit=_sync_limit())


def cache_key() -> str:
    """Store version AND rules revision — see the module docstring for why both are needed."""
    return f"{SLOT}:{STORE.version}:{RULES_STORE.rev}"


def _build() -> list[Anomaly]:
    """The whole aggregation, over every event in the pool. Runs off the request thread above the
    sync limit; the store lock is taken only to grab the list reference, never held across the walk
    (a 1.2 M-event fold under the lock is a second of blocked ingest)."""
    rules = {r.id: r for r in RULES_STORE.all_rules()}
    with STORE.lock:
        events = STORE.events
        # which case each source's hits belong to — a few dozen entries, resolved once, never per event
        case_id = "" if getattr(STORE, "pending", False) else str(getattr(STORE, "case_id", "") or "")
        case_name = str(getattr(STORE, "name", "") or "")
        origin = dict(getattr(STORE, "source_origin", {}) or {})
    lib_key = ("", "Library — not filed in a case")
    case_key = (case_id, case_name)
    agg: dict[str, dict] = {}
    for i, e in enumerate(events):
        if not e.detections:
            continue
        for d in e.detections:
            a = agg.get(d.id)
            if a is None:
                r = rules.get(d.id)
                a = agg[d.id] = {"ruleId": d.id, "name": r.name if r else d.name,
                                 "sev": r.sev if r else d.level, "hits": 0,
                                 "firstSeen": e.ts, "lastSeen": e.ts, "sources": set(), "sample": [],
                                 "kind": r.kind if r else "builtin", "cases": {}}
            a["hits"] += 1
            ck = case_key if (case_id and origin.get(e.sourceId, "case") == "case") else lib_key
            a["cases"][ck] = a["cases"].get(ck, 0) + 1
            if e.ts < a["firstSeen"]:
                a["firstSeen"] = e.ts
            if e.ts > a["lastSeen"]:
                a["lastSeen"] = e.ts
            a["sources"].add(e.source)
            if len(a["sample"]) < 5:
                a["sample"].append(e)
        if (i & 0xFFFF) == 0:
            ANOMALY_CACHE.tick(SLOT, i)
    out = []
    for a in agg.values():
        a["sources"] = sorted(a["sources"])
        a["cases"] = [AnomalyCase(caseId=k[0], caseName=k[1], hits=n)
                      for k, n in sorted(a["cases"].items(), key=lambda kv: (-kv[1], kv[0]))]
        out.append(Anomaly(**a))
    # sorted ONCE, here: every filtered response is a slice of this order, so the endpoint never sorts
    out.sort(key=lambda x: (-SEV_ORDER.get(x.sev, 0), -x.hits, x.ruleId))
    return out


def _size() -> int:
    return len(STORE.events)


def ready() -> Optional[list[Anomaly]]:
    """The aggregation if it is current, else None with a background build started. Never blocks."""
    from .store import STORE
    if STORE.derived_builds_paused():
        # see Store.derived_builds_paused — a fold of the whole pool per file loaded is waste, and on
        # a memory-tight VM it was part of what pushed the process over
        ANOMALY_CACHE.pause(SLOT, cache_key(), _size(), STORE.derived_pause_note())
        return None
    return ANOMALY_CACHE.ready(SLOT, cache_key(), _size(), _build)


def get() -> list[Anomaly]:
    """The aggregation, BUILDING IT IF NEEDED (blocking). For non-request callers and tests."""
    return ANOMALY_CACHE.get(SLOT, cache_key(), _size(), _build)


def status() -> dict[str, Any]:
    return ANOMALY_CACHE.status(SLOT, cache_key())


def peek() -> Optional[list[Anomaly]]:
    """The aggregation ONLY if already built. Never builds, never starts a build."""
    return ANOMALY_CACHE.peek(SLOT, cache_key())


def invalidate() -> None:
    ANOMALY_CACHE.invalidate()
