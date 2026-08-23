"""The graph-rule roll-up: evaluate `graph_rules` over the built graph, once per (graph, catalogue).

Why this is its own tiny module rather than a fourth `derived.AsyncCache` slot: the expensive thing is
the GRAPH, and that already has one. Evaluating the rules over an already-built graph is a pass over the
node and edge tables — measured at ~40 ms on an 18k-node graph — so a second background builder would be
machinery around nothing. What it does need is a memo, because `/api/rules` and the Anomalies screen
both ask, and neither should re-run it per request.

Two invariants, both learned elsewhere in this project and both load-bearing here:

  * **It never builds a graph.** `ready()` asks `graph_v2_ready()`, which returns None while a build is
    outstanding, and reports that state instead of a result. A rule roll-up must never be the thing that
    starts a 90-second extraction — that is the mistake `Store.snapshot()` was fixed for.
  * **The key carries the RULE CATALOGUE as well as the graph.** A finding quotes the rule's current
    name and severity, and which rules exist at all decides which findings there are, so a rules edit
    has to miss the memo by construction rather than by somebody remembering to invalidate it. Same
    reasoning as `anomalies.cache_key()`.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Optional

from .graph_rules import GraphFinding, counts, evaluate

_LOCK = threading.Lock()
_KEY: str = ""
_VALUE: list[GraphFinding] = []
_MS: int = 0


def _key(scope: str) -> str:
    from .rules import RULES_STORE
    from .store import STORE
    return f"{scope}:{STORE._derived_key(scope)}:{RULES_STORE.rev}"


def _evaluate(scope: str, builder: Any) -> list[GraphFinding]:
    global _KEY, _VALUE, _MS
    t0 = time.perf_counter()
    rows = evaluate(builder)
    ms = int((time.perf_counter() - t0) * 1000)
    with _LOCK:
        _KEY, _VALUE, _MS = _key(scope), rows, ms
    return rows


def ready(scope: str = "all") -> tuple[Optional[list[GraphFinding]], dict[str, Any]]:
    """(findings, graph status). findings is None when the graph is not built yet — never a blank list.

    An empty list means "the rules ran and nothing matched"; None means "we have not looked". Rendering
    the second as the first is the silent-absence bug: it tells the analyst the graph is clean when
    nothing has read it.
    """
    from .store import STORE

    key = _key(scope)
    with _LOCK:
        if key == _KEY:
            return list(_VALUE), {"state": "ready", "buildMs": _MS}
    builder = STORE.graph_v2_ready(scope)
    if builder is None:
        from .graph import GRAPH_CACHE
        return None, GRAPH_CACHE.status(scope, STORE._derived_key(scope))
    rows = _evaluate(scope, builder)
    with _LOCK:
        return list(rows), {"state": "ready", "buildMs": _MS}


def get(scope: str = "all") -> list[GraphFinding]:
    """Findings, BUILDING THE GRAPH IF NEEDED (blocking). For the AI tools and tests, never for a route."""
    from .store import STORE

    key = _key(scope)
    with _LOCK:
        if key == _KEY:
            return list(_VALUE)
    return _evaluate(scope, STORE.graph_v2(scope))


def peek_counts() -> dict[str, Optional[int]]:
    """Findings per rule id from the memo ONLY. Never builds, never starts a build.

    Returns {} when nothing has been evaluated, so `/api/rules` reports a graph rule's hits as unknown
    rather than as zero.
    """
    with _LOCK:
        if not _KEY:
            return {}
        return dict(counts(_VALUE))


def invalidate() -> None:
    global _KEY, _VALUE
    with _LOCK:
        _KEY, _VALUE = "", []
