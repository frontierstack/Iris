"""Version-keyed caches for DERIVED structures that must never be built on a request thread.

Two structures in this app are O(the whole pool) to build and are asked for by a screen that polls:
the typed entity graph (`graph.GraphBuilder`) and the correlation analysis (`correlate.Analyzer`).
At 1.2 M events they took 90 s and 30 s respectively, and both were built INLINE on whichever request
arrived first after a version bump — the Graph and Timeline screens simply never came back.

This is the same contract `search.py` already uses for the vectorised index, generalised:

* the value is built ONCE per store version, in a background thread;
* a request that arrives while a build is in flight returns immediately with `state: 'building'` and a
  `pct`, so the UI can say *building, 42 %* instead of showing a spinner that reads as a hang;
* the build is SINGLE-FLIGHT per slot — a burst of polls cannot start two multi-second builds;
* a small pool (<= `sync_limit` events) is still built inline, because a sub-second build is far better
  UX than a "building" flash plus a poll, and it keeps every existing test synchronous.

A *slot* is the thing being cached ('all' / 'case'); the *key* carries the store version, so a bump
misses the cache by construction and a stale value can never be served. Only the newest key per slot is
retained, so the cache holds at most one graph and one analysis per scope.
"""
from __future__ import annotations

import threading
import time
import traceback
from typing import Any, Callable, Optional

# Pools at or below this many events are built on the request thread: the build is well under a second
# and a synchronous answer is simpler for every caller (and for the test suite). Override for testing.
DEFAULT_SYNC_LIMIT = 20_000


class BuildCancelled(Exception):
    """The builder gave up because its own key is already stale — a `Store.bump()` landed mid-build.

    A build that is cancelled is not a failure: its value could never have been served (the key carries
    the version), so it is stopped to free the CPU rather than run to completion for nothing. It is a
    distinct exception so `get()` can drop the status without printing a traceback that reads like a bug.
    """


def _blank_status() -> dict[str, Any]:
    return {"state": "idle", "events": 0, "target": 0, "startedTs": 0.0, "buildMs": 0.0}


class AsyncCache:
    """One background-built value per slot, keyed on the store version."""

    def __init__(self, name: str, sync_limit: int = DEFAULT_SYNC_LIMIT) -> None:
        self.name = name
        self.sync_limit = sync_limit
        self._lock = threading.Lock()                       # guards the maps below; never held across a build
        self._build_locks: dict[str, threading.Lock] = {}   # one build at a time per slot
        self._entries: dict[str, tuple[str, Any]] = {}      # slot -> (key, value)
        self._status: dict[str, dict[str, Any]] = {}
        # slot -> the key a build is CURRENTLY running (or scheduled) for. This is the single-flight guard
        # AND the source of truth for "a build is in flight": it must survive `invalidate()`, because a
        # store bump lands mid-build routinely and dropping the status there is what made the Graph screen
        # report `idle` with no nodes — which the UI reads as "this pool has no entities", stops polling,
        # and the graph never appears. See tests/test_derived_cache.py::test_bump_during_a_build_*.
        self._inflight: dict[str, str] = {}
        self._paused: dict[str, bool] = {}   # slots reporting `building` while the store is still loading

    # ------------------------------------------------------------------ status
    def _st(self, slot: str) -> dict[str, Any]:
        return self._status.setdefault(slot, _blank_status())

    def _begin(self, slot: str, key: str, size: int) -> None:
        """Mark a build as in flight. Called BEFORE the work starts — and, in `ready`, before the thread is
        even spawned, so the request that scheduled the build already reports `building` rather than racing
        the thread to set it."""
        with self._lock:
            st = self._st(slot)
            if not (self._inflight.get(slot) == key and st["state"] == "building"):
                st.update(state="building", events=0, target=int(size), startedTs=time.time(), buildMs=0.0)
            st.pop("note", None)
            self._paused.pop(slot, None)
            self._inflight[slot] = key

    def _end(self, slot: str, key: str) -> None:
        with self._lock:
            if self._inflight.get(slot) == key:
                self._inflight.pop(slot, None)

    def status(self, slot: str, key: Optional[str] = None) -> dict[str, Any]:
        """State of this slot, in the same shape as `search.index_status()`.

        `state` is 'ready' only when the cached value matches `key` — a value from an older version is
        stale, and reporting it as ready is how an analyst ends up acting on last version's graph. It is
        'building' whenever a build is in flight for this slot, whatever key that build carries: a build
        for a superseded version is still the reason this request has nothing to return, and the screen
        must keep polling through it.
        """
        with self._lock:
            s = dict(self._st(slot))
            ent = self._entries.get(slot)
            ready = ent is not None and (key is None or ent[0] == key)
            building = slot in self._inflight or s["state"] == "building"
            note = s.get("note") if self._paused.get(slot) else None
        target = int(s["target"] or 0)
        done = int(s["events"] or 0)
        elapsed = (time.time() - s["startedTs"]) if s["startedTs"] else 0.0
        state = "ready" if ready else ("building" if building else "idle")
        out = {"state": state,
               "events": done, "target": target,
               "pct": round(min(100.0, done / target * 100.0), 1) if (state == "building" and target) else (100.0 if ready else 0.0),
               "elapsedSec": int(elapsed) if state == "building" else 0,
               "buildMs": round(float(s["buildMs"] or 0.0), 1)}
        if note and state == "building":
            out["note"] = note
        return out

    def tick(self, slot: str, done: int) -> None:
        """Progress callback handed to the builder. Cheap enough to call every few thousand events."""
        with self._lock:
            st = self._st(slot)
            if st["state"] == "building":
                st["events"] = int(done)

    # ------------------------------------------------------------------ access
    def peek(self, slot: str, key: str) -> Optional[Any]:
        """The cached value if it is current. Never builds, never blocks."""
        with self._lock:
            ent = self._entries.get(slot)
        return ent[1] if ent is not None and ent[0] == key else None

    def get(self, slot: str, key: str, size: int, build: Callable[[], Any]) -> Any:
        """The value, BUILDING IT IF NEEDED (blocking). Callers that must not block use `ready`."""
        hit = self.peek(slot, key)
        if hit is not None:
            return hit
        with self._lock:
            bl = self._build_locks.setdefault(slot, threading.Lock())
        with bl:
            hit = self.peek(slot, key)       # another thread may have built it while we waited
            if hit is not None:
                return hit
            self._begin(slot, key, size)
            t0 = time.perf_counter()
            try:
                value = build()
            except BuildCancelled:
                # Not an error: this key is already stale, so nothing was lost. Clear the status and
                # release the single-flight guard — leaving `_inflight` set here is exactly the bug
                # that made the Graph screen poll a build that would never publish anything.
                with self._lock:
                    self._st(slot).update(_blank_status())
                self._end(slot, key)
                raise
            except BaseException as exc:
                # NEVER fail silently. The status drops back to 'idle' and the next request retries, so
                # the app keeps working — but a build that dies every time would otherwise be an endpoint
                # that is permanently, inexplicably empty, with nothing anywhere saying why.
                with self._lock:
                    self._st(slot).update(_blank_status())
                self._end(slot, key)
                print(f"[iris] {self.name} build failed for {slot}: {type(exc).__name__}: {exc}")
                traceback.print_exc()
                raise
            with self._lock:
                # replacing the entry drops the previous version's value — the cache holds one per slot
                self._entries[slot] = (key, value)
                self._st(slot).update(state="ready", events=int(size), target=int(size), startedTs=0.0,
                                      buildMs=(time.perf_counter() - t0) * 1000.0)
            self._end(slot, key)
            return value

    def pause(self, slot: str, key: str, size: int,
              note: str = "waiting for the library load to finish") -> None:
        """Report `building` for a slot WITHOUT starting a build — the store is still ingesting and any
        build now would be discarded on the next bump. The status carries a note so the screen can say
        what it is waiting for rather than showing a progress bar that never moves.

        The note is the CALLER's to supply: there are two reasons to pause (the library load and the
        phase-2 enrichment queue) and they are cleared by different things, so a fixed string would
        tell the analyst to wait for something that already finished."""
        with self._lock:
            st = self._st(slot)
            if st["state"] != "building":
                st.update(state="building", events=0, target=int(size), startedTs=time.time(), buildMs=0.0)
            st["note"] = note
            self._paused[slot] = True

    def ready(self, slot: str, key: str, size: int, build: Callable[[], Any]) -> Optional[Any]:
        """The value if it is current, else None — and a background build is started.

        This is what a request handler calls. It never blocks on a big pool; it answers `None` and the
        handler reports `status()` so the screen can show progress.
        """
        hit = self.peek(slot, key)
        if hit is not None:
            return hit
        if size <= self.sync_limit:
            try:
                return self.get(slot, key, size, build)
            except BuildCancelled:
                # A small pool builds on the REQUEST thread. If a bump beat us to it there is nothing
                # worth raising into the handler — answer "not ready" and let the next poll rebuild.
                return None
        with self._lock:
            if slot in self._inflight:
                return None                  # single-flight: a burst of polls starts exactly one build
        # Publish `building` BEFORE the thread exists. `ready()` is called by the request handler which
        # then reads `status()` in the same request: if the status were left to the new thread there is a
        # window in which the handler answers `{nodes: [], state: 'idle'}`, and an idle+empty payload is
        # what the screen renders as "no entities in this pool" (and stops polling).
        self._begin(slot, key, size)

        def run() -> None:
            try:
                self.get(slot, key, size, build)
            except Exception:
                pass                         # already reported by get(), with a traceback
            finally:
                self._end(slot, key)

        t = threading.Thread(target=run, daemon=True, name=f"iris-{self.name}-{slot}")
        t.start()
        return None

    def invalidate(self, slot: Optional[str] = None) -> None:
        """Drop cached values. Version keying already makes a bump miss; this is for a wipe, where the
        old value must be released immediately rather than at the next build.

        The STATUS of a slot with a build in flight is deliberately kept. `Store.bump()` calls this on
        every ingest / rule re-apply / case switch, and those land in the middle of a multi-minute build
        all the time; clearing the status there made the very next poll report `idle`, which the Graph
        screen shows as an empty graph and — because it only polls while `building` — never corrects.
        """
        with self._lock:
            slots = set(self._entries) | set(self._status) if slot is None else {slot}
            for s in slots:
                self._entries.pop(s, None)
                if s not in self._inflight:
                    self._status.pop(s, None)
