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

What it DOES do, and what the first version got wrong: it CONFIRMS that the ask took. Asking is not
starting — `AsyncCache.ready` answers None both when it spawned a build and when it refused to (the
single-flight guard, a build that raised) — and marking the version handled on the ask alone left
the graph uncached until the version moved again, which on a settled workspace is never. See `tick`.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Optional

TICK = 2.0                       # how often the watcher looks; it does nothing on a quiet workspace
DEFAULT_QUIET = 20.0             # seconds of no version change before a build is worth starting
SCOPE = "all"                    # the scope the Graph screen opens on; `case` builds when it is asked

# ASKING IS NOT STARTING, and the watcher has to be able to tell the difference — see `tick`.
# It confirms afterwards instead of assuming, and these bound how often it looks and how long it
# keeps trying. RECHECK doubles per unconfirmed ask so a build that fails every time cannot become
# a slow poller, and MAX_ATTEMPTS ends it: the Graph screen still asks for itself when it is opened.
RECHECK = 30.0
MAX_RECHECK = 600.0
MAX_ATTEMPTS = 6


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
        self.builds = 0                 # how many asks this watcher has made (tests read it)
        self.last_version = -1          # the version whose graph is CONFIRMED current, or given up on
        self._asked_version = -1        # the version last asked for, not yet confirmed
        self._recheck_at = 0.0          # when to confirm that ask
        self._attempts = 0              # consecutive unconfirmed asks for `_asked_version`

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

    def _graph_state(self, store: Any) -> str:
        """'ready' | 'building' | 'idle', or '' when the store cannot say.

        This is the only way to learn whether an ask actually took: `graph_v2_ready` answers None
        both when it started a build and when it refused to, and those are opposite outcomes.
        """
        fn = getattr(store, "graph_status", None)
        if not callable(fn):
            return ""
        try:
            st = fn(SCOPE) or {}
        except Exception:  # noqa: BLE001 — a status read must never take the watcher down
            return ""
        return str(st.get("state") or "")

    def tick(self, now: float, seen_version: int, changed_at: float) -> bool:
        """One decision. Returns True when a build was asked for. Separated so it is testable.

        **Asking is not starting, and recording the version as handled at the moment of the ask is
        what left the graph permanently empty.** `graph_v2_ready` returns None for two opposite
        outcomes: a background build was started, or `AsyncCache.ready` REFUSED to start one. The
        refusal that actually happens is the single-flight guard — a build for version N is still
        running when the version moves to N+1, so the ask for N+1 is dropped, the N build finishes
        and caches a value under the wrong key, and nothing is left in flight. A build that RAISED
        is the same shape: `_inflight` clears and the status falls back to 'idle'.

        Either way the old code had already set `last_version`, so the watcher never came back and
        the graph stayed uncached until the version moved again — which on a settled workspace is
        never. `GET /api/graph` then answers `state:'idle'` with no nodes, and an idle+empty payload
        is what the Graph screen renders as "no entities in this pool" (and stops polling for).
        Reproduced against the real `derived.AsyncCache`; see tests/test_graph_autobuild_retry.py.

        The fix must not become a poller — polling `/api/graph` is what turned a library load into a
        six-worker extraction every few seconds and ended in SIGSEGV. So the ask is CONFIRMED rather
        than repeated: one `graph_status()` read (O(1), no build) after a backoff, and
          * 'ready'    -> the graph for this version is current. Stop; a settled workspace costs nothing.
          * 'building' -> a build is genuinely in flight. Wait; asking again cannot start a second one.
          * 'idle'     -> the ask did not take. Ask once more, on a doubling backoff, MAX_ATTEMPTS times.
          * ''         -> the store cannot report state; keep the original one-ask restraint.
        """
        store = self._store
        if store is None:
            return False
        version = int(getattr(store, "version", 0) or 0)
        if version == self.last_version:
            return False                      # settled: this version's graph is current, or given up on
        if version == self._asked_version:
            if now < self._recheck_at:
                return False                  # asked recently — a build needs time to appear
            state = self._graph_state(store)
            if state in ("ready", ""):
                self.last_version = version
                return False
            if state == "building":
                self._recheck_at = now + RECHECK
                return False
            if self._attempts >= MAX_ATTEMPTS:
                # It has refused or failed this many times; something is wrong that another ask will
                # not fix. Stop rather than retry forever — opening the Graph screen still asks.
                self.last_version = version
                return False
            # 'idle' and nothing cached for this version: the ask was dropped. Re-ask below.
        else:
            self._attempts = 0
        if version != seen_version or changed_at <= 0:
            return False                      # it JUST changed; wait for the quiet window
        if now - changed_at < quiet_seconds():
            return False
        if getattr(store, "graph_builds_paused", store.derived_builds_paused)():
            # A load or an enrichment run is in flight — the storm guard, and it wins over everything
            # above. Push the confirmation deadline out too, so a long pause costs one status read per
            # RECHECK rather than one per 2 s tick.
            self._recheck_at = max(self._recheck_at, now + RECHECK)
            return False
        if not getattr(store, "events", None):
            self.last_version = version       # nothing to build; do not come back for this version
            return False
        self._asked_version = version
        self._attempts += 1
        self._recheck_at = now + min(MAX_RECHECK, RECHECK * (2 ** (self._attempts - 1)))
        self.builds += 1
        # The ordinary non-blocking accessor: it returns the graph if it is current, and otherwise
        # starts exactly the background build the Graph screen would have started, into the same
        # single-flight cache. Nothing here waits for it.
        got = store.graph_v2_ready(SCOPE)
        if got is not None:
            self.last_version = version       # a small pool builds inline and hands the graph straight back
        return True


AUTOBUILD = GraphAutoBuilder()
