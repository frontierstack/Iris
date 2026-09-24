"""READS THAT ARE PURE FUNCTIONS OF THE POOL, remembered across runs and across agents.

A run already serves an identical read from its own cache (`RunContext.cache`). What nothing covered is
the read being repeated by a DIFFERENT run: every new chat opens by profiling the same source and
breaking the same field down, and every worker agent of a delegation begins by orienting on a pool
the lead oriented on a minute ago. Measured on a proxy-shaped pool of 150,000 events, the opening
`source_profile` costs ~930 ms and a twelve-query `batch_query` ~1.6 s, every time, for an answer
that cannot have changed.

It cannot have changed because of what the key holds. An entry is valid for exactly one state of
everything these tools read:

    Store.version        every ingest, delete, enrichment swap and detection re-stamp bumps it
    Store.case_set_rev   `scope: "case"` reads the curated set
    RULES_STORE.rev      a rule's name / severity / state appears in detection breakdowns
    EXCLUSIONS.rev       a suppression changes which detections exist

so invalidation is by CONSTRUCTION, the same doctrine as `derived.AsyncCache` and the anomaly cache:
nothing has to remember to clear this, because a changed world is a different key. The counters are
in-memory and restart at zero, and so does this — it is never persisted, so that cannot matter.

Only an ALLOWLIST is cached, and it is short on purpose. A tool is on it only if its whole answer is
derived from the event pool and the detection catalogue. Anything that reads the CASE (notes,
indicators, links), a derived structure that may still be building (the graph, the timeline), or the
clock is left out: a stale "relations: not computed yet" or a stale note list would be a wrong answer
served instantly, which is the worst kind.

Entries are stored SERIALISED and handed back as a fresh object each time. Results are passed around
and annotated by the loop (`cached`, clipping); a shared dict mutated by one run would be read by the
next.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Optional

import orjson

# Pure functions of (pool, catalogue). See the module docstring for what keeps a tool OFF this list.
CACHEABLE = frozenset({
    "count_events", "aggregate_events", "distinct_values", "events_over_time", "batch_query",
    "search_events", "source_profile", "list_event_fields", "trace_thread",
})

MAX_ENTRIES = 256
MAX_ENTRY_BYTES = 256 * 1024        # a result bigger than this is not worth holding
_LOCK = threading.Lock()
_CACHE: "OrderedDict[tuple, bytes]" = OrderedDict()
hits = 0
misses = 0


def _state() -> Optional[tuple]:
    """Everything a cacheable tool reads, as counters. A changed world is a different key."""
    try:
        from ..store import STORE
        from ..rules import RULES_STORE
        from ..exclusions import EXCLUSIONS
        return (int(STORE.version), int(STORE.case_set_rev), int(RULES_STORE.rev), int(EXCLUSIONS.rev))
    except Exception:  # noqa: BLE001 — no key means no cache, never a failed tool call
        return None


def _key(name: str, args: dict[str, Any]) -> Optional[tuple]:
    if name not in CACHEABLE:
        return None
    state = _state()
    if state is None:
        return None
    from .loopguard import call_key
    return (call_key(name, args), *state)


def get(name: str, args: dict[str, Any]) -> Any:
    """The remembered result, as a FRESH object, or None."""
    global hits, misses
    key = _key(name, args)
    if key is None:
        return None
    with _LOCK:
        blob = _CACHE.get(key)
        if blob is None:
            misses += 1
            return None
        _CACHE.move_to_end(key)
        hits += 1
    return orjson.loads(blob)


def put(name: str, args: dict[str, Any], result: Any) -> None:
    key = _key(name, args)
    if key is None or not isinstance(result, dict):
        return
    try:
        blob = orjson.dumps(result)
    except TypeError:
        return                       # not plain data: leave it uncached rather than guess
    if len(blob) > MAX_ENTRY_BYTES:
        return
    with _LOCK:
        _CACHE[key] = blob
        _CACHE.move_to_end(key)
        while len(_CACHE) > MAX_ENTRIES:
            _CACHE.popitem(last=False)


def clear() -> None:
    with _LOCK:
        _CACHE.clear()
