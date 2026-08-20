"""Two-phase ingest: land the log RAW and searchable at once, understand it afterwards.

The analyst's question was "wouldn't it be better to just import the logs raw and have them readily
available" — and the measurement behind it (on their own corpus, per file, this machine):

    file                      parser         format parse      normalize
    ...1164eed.jsonl          JSONL           0.21s (15%)    1.18s (85%)
    apt-eipp.log              plain text      0.05s (17%)    0.24s (83%)
    pi-strace-trace.log       delimited       0.03s (11%)    0.27s (89%)

Pulling FIELDS out of a line is 11-17% of ingest. The other 83-89% is normalization: timestamp parsing,
severity inference, entity extraction and building the pydantic `Event`. That cost is paid identically
whether the file yields 26 useful fields or none, and 99% of the events in that pool had none.

So the split is not "parse vs raw", it is WHEN:

* **Phase 1 (`raw_events`)** — split the container into records and build the plainest possible Event:
  the raw text, its file, its id. No timestamp, no severity, no entities, no fields. It is a few string
  operations per line, and the result is in the pool and in the search index immediately.
* **Phase 2 (`enrich_source`)** — the real parser and the full normalization, on a background worker,
  one source at a time, replacing that source's events in place. This is what the timeline, the entity
  graph, the detections and field filters need, and it is exactly the work that can wait.

What must stay true, and why each one is load-bearing:

* **Event ids may not move.** Case sets, notes and indicators cite them. When the parse produces one
  record per raw line (nginx, syslog, CSV, JSONL — the common case) the ids are reused positionally and
  nothing moves at all. When it does not (multi-line stitching, a container that is not line-oriented),
  the ids are reassigned and `remap` reports the old -> new mapping so curation can follow. A citation
  that cannot be remapped is REPORTED, never silently dropped.
* **Raw is never a lie.** An unenriched event carries `ts=""`, `sev="info"` and no fields — not a guessed
  timestamp and not an inferred severity. Everything that reads the pool can already handle an unstamped
  event (it sorts last and matches no time window); what it must NOT do is present "info" as a judgement.
  `Source.enrich` is how a screen knows the difference.
* **Binary and structured containers do not have a raw phase.** An EVTX record, a SQLite row or a PDF
  page has no readable text until its parser has run, so "import it raw" would mean importing nothing.
  Those parse fully on ingest, exactly as before, and are born `enriched`.
"""
from __future__ import annotations

import contextlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Iterable, Optional

from . import jobs
from .models import Event
from .normalize import leading_ts

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .store import Store

log = logging.getLogger("iris.enrich")

# A raw record is one line. Overlong lines are kept whole: truncating evidence at ingest is not this
# layer's decision, and the search index and the viewer both cope.
MAX_RAW_PREVIEW = 200
# How often the raw phase publishes progress is `jobs.PROGRESS_EVERY_RECORDS` — the one knob, owned by
# the tracker both phases publish into. This module used to declare its own copy with a comment claiming
# it "matches" that one, which nothing enforced. `import jobs` is safe here and stays that way: jobs.py
# imports config only, and reaches the store lazily inside functions.


def raw_events(sid: str, filename: str, family: str, data: bytes, prefix: str,
               first_id: int = 1, progress: Optional[Callable[[int, int], None]] = None) -> list[Event]:
    """Phase 1: bytes -> the plainest events that are still true.

    `family` is the sniffer's guess and is recorded so source chips and per-parser filters work before
    enrichment; it does NOT mean the file has been parsed. Nothing here inspects the line's content.
    """
    text = data.decode("utf-8", "replace")
    out: list[Event] = []
    append = out.append
    n = first_id
    done = 0
    # The ONE thing worth reading out of a line up front. Everything else a parse would produce —
    # fields, entities, severity — costs a per-event dict and a fistful of string objects and can be
    # done later, per source, on demand. A timestamp cannot: without it an event has no place in a
    # time window, a timeline or a burst rule, and no later question can put it there. It is READ,
    # never inferred: a line whose time cannot be recognised keeps ts="".
    #
    # The cache matters more than it looks: an export is mostly runs of lines sharing one second, so
    # this turns the parse into a dict hit for nearly every line after the first of each second.
    ts_cache: dict[str, str] = {}
    lead = leading_ts
    every = max(1, int(jobs.PROGRESS_EVERY_RECORDS))   # read once per call, so a test can turn it down
    for line in text.splitlines():
        done += len(line) + 1
        if not line.strip():
            continue
        # No fields/entities/detections and no explicit msg: `Event` derives msg from raw[:200] and
        # points the three containers at the shared frozen empties. On a gigabyte of DNS log that is
        # the difference between ~666 and ~386 bytes an event — see the note in models.py.
        append(Event(
            id=f"{prefix}{n:x}" if prefix else f"e{n:x}",
            ts=lead(line, ts_cache), source=family, sourceId=sid, file=filename, host="", user="",
            msg=line[:MAX_RAW_PREVIEW], sev="info", raw=line,
        ))
        n += 1
        # the raw phase is fast but not instant on a gigabyte, and a progress bar that only ever reads
        # 0% or 100% is the same "is it hung?" question this whole change exists to answer
        if progress is not None and not len(out) % every:
            progress(min(done, len(data)), len(out))
    return out


@dataclass
class EnrichResult:
    """What one enrichment did, in the terms the analyst needs to trust it."""
    sid: str
    ok: bool = False
    raw_events: int = 0
    events: int = 0
    one_to_one: bool = False
    remap: dict[str, str] = field(default_factory=dict)
    lost_citations: list[str] = field(default_factory=list)
    error: str = ""
    took_ms: int = 0


class EnrichQueue:
    """One background worker, one source at a time, oldest first.

    Deliberately serial. Enrichment is the same work the old inline ingest did, and running several at
    once would recreate the problem this whole change exists to fix: the API starving while the machine
    parses. It also yields while the library is still loading (`Store.derived_builds_paused`), for the
    same reason the derived caches do.
    """

    def __init__(self) -> None:
        self._committing = False        # a parsed batch is waiting for its shared merge
        self._q: list[str] = []
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._current: str = ""
        self._stop = False
        self._warned_no_worker = False
        self.last: dict[str, EnrichResult] = {}

    # ---------------------------------------------------------------- queue
    def _alive(self) -> bool:
        """Is there a worker that could ever service this queue? Call under `self._lock`."""
        return self._thread is not None and self._thread.is_alive() and not self._stop

    def submit(self, sid: str) -> None:
        with self._lock:
            if sid in self._q or sid == self._current:
                return
            self._q.append(sid)
            orphaned = not self._alive() and not self._warned_no_worker
            if orphaned:
                self._warned_no_worker = True
        self._wake.set()
        if orphaned:
            # A submit with no worker is a source that will sit in the pool as raw lines forever: no
            # timestamps, no fields, no detections, and nothing left that would ever give it any. It
            # used to be completely silent — the only symptom was `drain()` burning its whole timeout.
            log.warning(
                "enrichment queued for source %s but no enrichment worker is running — it will stay "
                "raw until EnrichQueue.start() is called (the FastAPI lifespan normally does this)", sid)

    def cancel(self, sid: str) -> bool:
        with self._lock:
            if sid in self._q:
                self._q.remove(sid)
                return True
        return False

    def status(self) -> dict:
        with self._lock:
            return {"running": self._current, "queued": list(self._q), "pending": len(self._q) + (1 if self._current else 0)}

    def working(self) -> bool:
        """True while a LIVE worker still has phase-2 work to do.

        The live-worker requirement is the whole point. A queue nobody is servicing is abandoned, not
        busy — `submit()` logs a warning for exactly that case — and anything that waits on this
        (`Store.derived_builds_paused`) would otherwise wait forever, leaving the Graph, Timeline and
        Anomalies screens reporting `building` for the rest of the process's life.
        """
        with self._lock:
            return self._alive() and bool(self._q or self._current or self._committing)

    def drain(self, timeout: float = 60.0) -> bool:
        """Block until the queue is empty. Tests only — nothing in a request path may call this.

        A queue with no live worker is ABANDONED, not busy: nothing will ever pop it, so waiting on it
        can only ever cost the full timeout. That is exactly what happened between tests — the FastAPI
        lifespan starts the worker and stops it again, so any test that ingested outside a
        `with TestClient(app)` block left a queue nobody was servicing, and the autouse teardown paid
        30 s for it. Every one of those. The suite went from ~2 min to 68 min.

        So: drop the abandoned entries (they cannot complete, and carrying them into the next test is
        how one test's enrichment lands in the middle of another) and return at once. Callers that
        need the work to actually HAPPEN start the worker first — `tests/conftest.drain_enrichment`
        does, and that path still blocks until the queue is genuinely empty.
        """
        deadline = time.time() + timeout
        while True:
            with self._lock:
                # `_committing` too: a batch that has parsed its sources but not merged them yet is
                # still work in flight, and a caller that treats it as finished races the commit.
                if not self._q and not self._current and not self._committing:
                    return True
                if not self._alive():
                    self._q.clear()
                    return True
            if time.time() >= deadline:
                return False
            time.sleep(0.01)

    # --------------------------------------------------------------- worker
    def start(self, store: "Store") -> None:
        if self._thread and self._thread.is_alive():
            if not self._stop:
                return
            # A stop() is in flight and the old worker has not noticed yet. Clearing `_stop` and
            # returning here would leave the queue looking live while that thread exits — the drain
            # would then wait for a worker that is already gone. Let it finish, then replace it.
            self._wake.set()
            self._thread.join(timeout=5.0)
        self._stop = False
        self._warned_no_worker = False
        self._committing = False
        self._thread = threading.Thread(target=self._run, args=(store,), name="iris-enrich", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop = True
        self._wake.set()

    def _run(self, store: "Store") -> None:
        while not self._stop:
            with self._lock:
                sid = self._q.pop(0) if self._q else ""
                self._current = sid
            if not sid:
                self._wake.wait(timeout=1.0)
                self._wake.clear()
                continue
            try:
                if store.pool_loading:
                    # The library is still loading; put it back and wait rather than competing with it.
                    # This asks `pool_loading` DIRECTLY and must keep doing so: `derived_builds_paused()`
                    # now also covers this queue, so calling it here would make the worker yield to
                    # itself forever and nothing would ever be enriched.
                    with self._lock:
                        self._q.append(sid)
                        self._current = ""
                    self._wake.wait(timeout=2.0)
                    self._wake.clear()
                    continue
                # One MERGE for a run of sources, not one per source. `_swap_many` is O(the whole
                # pool) whatever changed, so on a large workspace it dominated: ~45 s per source, and
                # a queue of forty small files took half an hour with almost no time spent parsing.
                # The batch is bounded two ways — a count and a wall clock — because the sources only
                # become searchable when it commits, and an analyst watching the queue should see it
                # move rather than jump once at the end.
                # `nullcontext` when the store cannot batch: the queue drives whatever store it was
                # given, and a store without the batch API simply commits per source as it always did.
                # Only batch when there is something to batch WITH. A lone source gains nothing from
                # a deferred merge and pays for it: its events reach the pool one step later, which
                # widens the window in which a search (or a caller reading the case straight after an
                # upload) still sees the raw lines. Batching is for a QUEUE — that is where the
                # O(pool) merge is being amortised.
                with self._lock:
                    more_waiting = bool(self._q)
                batching = getattr(store, "enrich_batch", None) if more_waiting else None
                pending = getattr(store, "enrich_batch_size", None)
                # A batch holds finished parses that are NOT in the pool yet, and the inner loop
                # clears `_current` as soon as the queue runs dry — so without this flag `working()`
                # and `drain()` can both say "done" while the commit is still to come. Anything that
                # acts on that answer (a test that wipes memory, `derived_builds_paused` releasing,
                # the post-run index warm) then races the commit, and the events it was holding are
                # dropped on the floor.
                with self._lock:
                    self._committing = True
                with (batching() if batching else contextlib.nullcontext()):
                    self.last[sid] = store.enrich_source(sid)
                    started = time.time()
                    while (pending is not None and pending() and pending() < BATCH_MAX
                           and (time.time() - started) < BATCH_SECONDS):
                        with self._lock:
                            nxt = self._q.pop(0) if self._q else ""
                            self._current = nxt
                        if not nxt:
                            break
                        if store.pool_loading or self._stop:
                            with self._lock:
                                self._q.insert(0, nxt)
                                self._current = ""
                            break
                        try:
                            self.last[nxt] = store.enrich_source(nxt)
                        except Exception as exc:   # one bad file must not lose the whole batch
                            self.last[nxt] = EnrichResult(sid=nxt, ok=False,
                                                          error=f"{type(exc).__name__}: {exc}")
            except Exception as exc:  # a bad file may never take the worker down
                self.last[sid] = EnrichResult(sid=sid, ok=False, error=f"{type(exc).__name__}: {exc}")
            finally:
                with self._lock:
                    self._current = ""
                    self._committing = False
                    drained = not self._q
            if drained:
                # The storm is over: this is the ONE index warm that matters. Every bump during the run
                # skipped it (Store.warm_search_async), because a ~75 s pure-Python rebuild that is
                # discarded on the next source's bump is what starves the GIL and makes every other
                # request slow. Failing here must never take the worker down — a search will warm it too.
                try:
                    store.warm_search_async()
                except Exception:
                    log.debug("post-enrichment index warm failed", exc_info=True)


# How much phase-2 work shares one pool merge. Bounded by BOTH a count and a wall clock: the merge is
# what the batch exists to amortise, but nothing in the batch is searchable until it commits, so a
# long batch trades one kind of waiting for another.
BATCH_MAX = 25
BATCH_SECONDS = 30.0

QUEUE = EnrichQueue()
