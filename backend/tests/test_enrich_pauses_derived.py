"""Phase-2 enrichment must not restart the derived builds once per file.

The library load already had this problem and `Store.derived_builds_paused()` already fixed it there:
every file the loader finished bumped the store version, every bump invalidated the graph, the analysis
and the anomaly roll-up, and a poll then started a full six-worker graph extraction that the next bump
threw away. On the analyst's WSL2 VM that storm was part of what killed processes with SIGSEGV.

Enrichment has exactly the same shape — one bump per source as its events are replaced — so it pauses
derived builds for exactly as long as a LIVE worker still has work. The live-worker requirement is the
other half: a queue nobody is servicing is abandoned, and if it could pause derived builds the Graph,
Timeline and Anomalies screens would report `building` forever.
"""
from __future__ import annotations

import threading
import time

from app import enrich
from app.store import STORE


class _FakeThread:
    def __init__(self, alive: bool) -> None:
        self._alive = alive

    def is_alive(self) -> bool:
        return self._alive


def _queue(items: list[str], current: str = "", alive: bool = True) -> enrich.EnrichQueue:
    q = enrich.EnrichQueue()
    q._q = list(items)
    q._current = current
    q._thread = _FakeThread(alive)  # type: ignore[assignment]
    return q


def test_an_idle_queue_does_not_pause_anything() -> None:
    assert _queue([]).working() is False


def test_a_live_worker_with_work_is_working() -> None:
    assert _queue(["s1", "s2"]).working() is True
    assert _queue([], current="s1").working() is True


def test_a_queue_with_no_live_worker_is_abandoned_not_busy() -> None:
    """The permanent-'building' trap: nothing will ever service this, so it must not pause a build."""
    assert _queue(["s1", "s2"], alive=False).working() is False
    assert _queue(["s1"], alive=True).working() is True


def test_a_stopped_worker_is_not_alive_either() -> None:
    q = _queue(["s1"])
    q._stop = True
    assert q.working() is False


def test_derived_builds_pause_while_enrichment_is_in_flight(monkeypatch) -> None:
    assert STORE.derived_builds_paused() is False, "nothing is loading or enriching in a fresh store"

    monkeypatch.setattr(enrich.QUEUE, "working", lambda: True)
    assert STORE.derived_builds_paused() is True
    assert STORE.derived_pause_note() == "waiting for source enrichment to finish"

    # the library load still wins the note — it is the one the analyst can act on first
    monkeypatch.setattr(STORE, "pool_loading", True)
    assert STORE.derived_pause_note() == "waiting for the library load to finish"


def test_the_worker_never_yields_to_itself() -> None:
    """`_run` must ask `pool_loading` directly.

    If it consulted `derived_builds_paused()` — which now counts this very queue — the worker would put
    every source back and wait for itself, forever, and nothing would ever be enriched.
    """
    import inspect

    # Comments in `_run` name `derived_builds_paused` to explain precisely this trap, so match the CALL,
    # not the word.
    src = inspect.getsource(enrich.EnrichQueue._run)
    code = " ".join(ln.split("#", 1)[0] for ln in src.splitlines())
    assert "store.pool_loading" in code
    assert "derived_builds_paused" not in code


def test_a_real_run_drains_and_then_releases_the_pause() -> None:
    """End to end on the real queue: paused while it works, released the moment it is done."""
    seen: list[str] = []
    gate = threading.Event()

    class _Fake:
        pool_loading = False

        def derived_builds_paused(self) -> bool:  # pragma: no cover - must never be called by _run
            raise AssertionError("_run must not consult derived_builds_paused")

        def enrich_source(self, sid: str):
            seen.append(sid)
            gate.wait(2.0)
            return enrich.EnrichResult(sid=sid, ok=True)

    q = enrich.EnrichQueue()
    q.start(_Fake())  # type: ignore[arg-type]
    try:
        q.submit("s1")
        for _ in range(500):
            if seen:
                break
            threading.Event().wait(0.01)
        assert seen == ["s1"], "the worker picked the source up"
        assert q.working() is True, "paused while it works"
        gate.set()
        assert q.drain(5.0) is True
        assert q.working() is False, "released the moment the queue is empty"
    finally:
        gate.set()
        q.stop()


# --------------------------------------------------------------- the search index warm
def test_the_index_warm_is_skipped_during_an_ingest_storm(monkeypatch) -> None:
    """A ~75 s pure-Python index rebuild, discarded on the next source's bump, is what starves the GIL.

    Measured on the analyst's 11.4 M-event pool during a 680-source enrichment run: `/api/library` took
    21-69 s and `/api/health` 9.4 s, while `/api/case` — which takes the SAME store lock — answered in
    0.87 s. The process was GIL-starved, not lock-blocked, and the index warm was a large part of it.
    """
    from app import search as _search
    from app.store import STORE

    calls: list[int] = []
    monkeypatch.setattr(_search, "warm_async", lambda getter, **kw: calls.append(1))

    monkeypatch.setattr(STORE, "derived_builds_paused", lambda: True)
    assert STORE.warm_search_async() is False
    assert calls == [], "no warm may start while the pool is still being ingested"

    monkeypatch.setattr(STORE, "derived_builds_paused", lambda: False)
    assert STORE.warm_search_async() is True
    assert len(calls) == 1, "the warm runs normally once the storm is over"


def test_a_drained_queue_warms_the_index_exactly_once() -> None:
    """The one warm that matters is the one AFTER the last source, and the worker is what knows."""
    warmed: list[str] = []
    done: list[str] = []

    class _Fake:
        pool_loading = False

        def enrich_source(self, sid: str):
            done.append(sid)
            return enrich.EnrichResult(sid=sid, ok=True)

        def warm_search_async(self) -> bool:
            warmed.append("x")
            return True

    q = enrich.EnrichQueue()
    q.start(_Fake())  # type: ignore[arg-type]
    try:
        for sid in ("s1", "s2", "s3"):
            q.submit(sid)
        assert q.drain(5.0) is True
        assert done == ["s1", "s2", "s3"]
        # at most one warm per drain — never one per source, which is the storm being fixed
        assert 1 <= len(warmed) <= len(done), warmed
        assert warmed, "the queue draining must trigger the warm the bumps all skipped"
    finally:
        q.stop()


def test_a_failing_warm_never_takes_the_worker_down() -> None:
    """A bad warm must not strand every remaining source as raw — a search would warm it anyway."""
    done: list[str] = []

    class _Boom:
        pool_loading = False

        def enrich_source(self, sid: str):
            done.append(sid)
            return enrich.EnrichResult(sid=sid, ok=True)

        def warm_search_async(self) -> bool:
            raise RuntimeError("index warm exploded")

    q = enrich.EnrichQueue()
    q.start(_Boom())  # type: ignore[arg-type]
    try:
        q.submit("s1")
        assert q.drain(5.0) is True
        q.submit("s2")
        assert q.drain(5.0) is True, "the worker survived and kept servicing the queue"
        assert done == ["s1", "s2"]
    finally:
        q.stop()


def test_a_query_does_not_start_an_index_rebuild_during_an_enrichment_run(monkeypatch):
    """The one warm path that ignored the pause.

    `Store.warm_search_async` has always refused while sources are still being enriched — rebuilding
    the packed index is minutes of pure-Python work that the next finished source invalidates. But a
    SEARCH that finds no index called `search.warm_async` directly, so during an enrichment run every
    query started that build anyway. Observed live on an 11 M-event pool: the index cycled
    ready -> idle -> building -> ready for the whole run and no query ever got to use it.
    """
    from app import search as se

    built: list[int] = []
    monkeypatch.setattr(se, "get_index", lambda *a, **k: built.append(1))

    def _settle(deadline: float = 5.0) -> None:
        """The warm runs on a timer THREAD, so give it a bounded chance to run rather than a fixed
        sleep — a fixed one is a flake as soon as the machine is busy, which under the full suite it
        always is."""
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            with se._lock:
                warming = se._warming
            if not warming:
                return
            time.sleep(0.02)

    se.set_warm_gate(lambda: False)          # i.e. an ingest/enrichment storm is in flight
    try:
        se.warm_async(lambda: ([object()] * (se._MIN_VECTOR + 1), None, 1, ""), delay=0.0)
        _settle()
        assert built == [], "a build started while derived work was paused"

        se.set_warm_gate(lambda: True)       # the queue drained
        se.warm_async(lambda: ([object()] * (se._MIN_VECTOR + 1), None, 1, ""), delay=0.0)
        _settle()
        assert built == [1], "the build that matters — the one after the storm — must still run"
    finally:
        se.set_warm_gate(None)


def test_the_store_installs_the_gate_so_the_pause_is_actually_enforced():
    """The gate is only useful if something wires it to the store's own pause."""
    from app import search as se
    from app.store import STORE

    se.set_warm_gate(None)
    try:
        STORE.install_index_signature_provider()
        assert se._warm_gate is not None
        assert se.may_warm() is (not STORE.derived_builds_paused())
    finally:
        se.set_warm_gate(None)
