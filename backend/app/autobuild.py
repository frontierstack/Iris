"""The entity graph builds ITSELF, instead of waiting for someone to open the Graph screen.

The analyst: *"The entity graph only starts building when you visit the entity graph page, but it
should start that process automatically and refresh automatically when a new source is added."*

That was literally true. `Store.graph_v2_ready()` starts a build when something ASKS for the graph, and
the only things that ask are the Graph screen and a handful of AI tools — deliberately, because the
sidebar used to poll `/api/graph` on every page and that turned a 300 MB library load into a full
six-worker extraction every few seconds (see `Store.derived_builds_paused`; on this VM it ended in
SIGSEGV). So the fix cannot be "ask more often". It is a WATCHER that asks ONCE, at the right moment.

The right moment, and every part of it is load-bearing:
  • the pool is not loading and the enrichment queue is idle — `derived_builds_paused()` already
    encodes exactly that, and it is the storm guard, not a nicety;
  • the store version has actually moved since the last build was kicked off, so a quiet workspace
    costs nothing at all;
  • and it has been QUIET for `IRIS_GRAPH_AUTOBUILD_QUIET` seconds (default 20). A burst of uploads
    bumps the version once per file; without the quiet window this would start a build per file and
    throw all but the last away — the same storm through a different door.

What it does NOT do: block anything, build inline, or force a scope nobody looks at. It calls the
ordinary non-blocking accessor (`graph_v2_ready`), which starts the same background build the Graph
screen would have started, into the same single-flight cache. If the analyst opens the screen first,
the build is already running (or done) and they see a progress panel or a graph instead of a cold
start. `IRIS_GRAPH_AUTOBUILD=0` turns it off.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Optional

TICK = 2.0                       # how often the watcher looks; it does nothing on a quiet workspace
DEFAULT_QUIET = 20.0             # seconds of no version change before a build is worth starting
SCOPE = "all"                    # the scope the Graph screen opens on; `case` builds when it is asked


def _env_float(name: str, default: float) -> float:
    try:
        v = float(os.environ.get(name, "") or default)
    except ValueError:
        return default
    return max(1.0, min(3600.0, v))


def enabled() -> bool:
    return (os.environ.get("IRIS_GRAPH_AUTOBUILD", "1") or "1").strip().lower() not in ("0", "false", "no")


def quiet_seconds() -> float:
    return _env_float("IRIS_GRAPH_AUTOBUILD_QUIET", DEFAULT_QUIET)


class GraphAutoBuilder:
    """One daemon thread. Started in the lifespan, stopped with the app."""

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._store: Any = None
        self.builds = 0                 # how many builds this watcher has kicked off (tests read it)
        self.last_version = -1          # the version it last acted on

    def start(self, store: Any) -> None:
        if not enabled() or (self._thread and self._thread.is_alive()):
            return
        self._store = store
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="iris-graph-autobuild", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout)
        self._thread = None

    # ------------------------------------------------------------------ the loop
    def _run(self) -> None:
        seen_version = -1
        changed_at = 0.0
        while not self._stop.is_set():
            self._stop.wait(TICK)
            if self._stop.is_set():
                return
            try:
                self.tick(time.monotonic(), seen_version, changed_at)
            except Exception:  # noqa: BLE001 — a watcher must never take the process down
                pass
            # `tick` is pure except for the build call, so the loop keeps its own bookkeeping
            store = self._store
            version = int(getattr(store, "version", 0) or 0)
            if version != seen_version:
                seen_version, changed_at = version, time.monotonic()

    def tick(self, now: float, seen_version: int, changed_at: float) -> bool:
        """One decision. Returns True when a build was kicked off. Separated so it is testable."""
        store = self._store
        if store is None:
            return False
        version = int(getattr(store, "version", 0) or 0)
        if version == self.last_version:
            return False                      # already kicked off a build for this version
        if version != seen_version or changed_at <= 0:
            return False                      # it JUST changed; wait for the quiet window
        if now - changed_at < quiet_seconds():
            return False
        if getattr(store, "graph_builds_paused", store.derived_builds_paused)():
            return False                      # a load or an enrichment run is in flight — the storm guard
        if not getattr(store, "events", None):
            self.last_version = version       # nothing to build; do not come back for this version
            return False
        self.last_version = version
        self.builds += 1
        # The ordinary non-blocking accessor: it returns the graph if it is current, and otherwise
        # starts exactly the background build the Graph screen would have started, into the same
        # single-flight cache. Nothing here waits for it.
        store.graph_v2_ready(SCOPE)
        return True


AUTOBUILD = GraphAutoBuilder()
