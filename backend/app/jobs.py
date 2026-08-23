"""Server-side upload / parse job registry.

Upload and parse progress used to live only in the browser tab that started it: switching tabs or
refreshing lost every trace of what was uploading, what was parsing and what failed — and a 263 MB CSV
parses in a background thread for minutes after the HTTP request has already returned (see
store.SYNC_LIMIT), so the work genuinely outlives the request that started it.

This module is the single source of truth for that progress. A job is created BEFORE the bytes start
moving (POST /api/jobs), advanced while they move (PATCH /api/jobs/{id} carries bytes-received from the
XHR, which is the only place that number exists), flipped to `parsing` by the ingest endpoint and
resolved to `ready` / `error` when the parser finishes — including the threaded case, which is picked up
by `sync()` reading the source states back out of the store.

Persistence: `$IRIS_DATA_DIR/jobs.json`, written atomically (tmp + replace) under the registry lock, so
concurrent uploads and parse threads cannot interleave a half-written file.

Restart semantics: a process that dies mid-parse leaves jobs claiming to be running forever. `reconcile()`
runs once at startup AFTER the case is restored: jobs whose sources came back complete are resolved
normally, and anything still queued/uploading/parsing becomes `error` with `interrupted = true`.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from . import config, metrics

UTC = timezone.utc

# queued -> uploading -> parsing -> ready | error
ACTIVE_STATES = ("queued", "uploading", "parsing")
TERMINAL_STATES = ("ready", "error")

RETAIN_SEC = 30 * 60      # a FAILED job stays visible this long, so a refresh right after it lands still shows it
# A job that SUCCEEDED clears itself. "Clear finished" was a button the analyst had to press after every
# ingest to tidy up rows that had nothing left to say: the file is parsed, it is in the Sources table
# below with its parser, its state and its event count, and the transfer row is a duplicate of that.
# Long enough to see the row land and settle (a poll is 2 s), short enough that the panel empties itself.
# A FAILURE is the opposite and keeps the full RETAIN_SEC: it is the ONE thing on that panel that is not
# restated anywhere else in a form the analyst can act on, and auto-clearing it would silently discard
# the report of evidence that never made it into the pool.
READY_RETAIN_SEC = 20
MAX_JOBS = 200            # hard cap, oldest first — jobs.json must not grow without bound
# An upload nobody has advanced for this long is dead (tab closed mid-transfer). "Advanced" includes the
# HEARTBEAT: the Ingest screen declares every dropped file up front and then sends three at a time, so a
# file behind eight others is legitimately untouched for as long as the queue ahead of it takes. Measured
# from job CREATION this buried a whole drop of packet captures at exactly 600 s — eight rows reading "the
# upload stopped before the server received the whole file", every one of them with received:0, i.e. an
# upload that had never been given a chance to start. Only the sending tab knows whether a queued transfer
# is still intended, so it says so (POST /api/jobs/heartbeat) and this stays the watchdog for the case it
# was written for: nobody is coming back for this one.
STALE_UPLOAD_SEC = 600

# Detection at library-stage time reads a BOUNDED prefix: fingerprinting a 263 MB file must not cost a
# full pass. registry.fingerprint() only ever looks at the first 256 KB of text anyway.
PROBE_BYTES = 2 * 1024 * 1024


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- parse progress
# `parsing` used to be the whole story: a 263 MB CSV sat in that one state for ten minutes with nothing
# to distinguish it from a hang. This tracker is the fine-grained side of it — bytes of source consumed
# out of the file's size, plus the event count — and it is deliberately IN MEMORY ONLY, keyed by source
# id. It is written thousands of times per file; putting it in jobs.json would rewrite that file on every
# tick for state that is worthless after a restart anyway (reconcile() buries interrupted jobs regardless).
# Readers merge it into the job rows at read time, so any tab sees it, not just the one that uploaded.
# The publish cadence for BOTH ingest phases, in records (~0.5 s of parsing at one worker). It lives
# here because it is a property of this tracker, not of either producer: phase 1 (enrich.raw_events) and
# phase 2 (store._parse_source) both tick into PARSE_PROGRESS and there is no reason for them to disagree.
# enrich.py used to carry a second copy whose comment said "matches jobs.PROGRESS_EVERY_RECORDS" — which
# is a promise a constant cannot keep. Read it at CALL time (`jobs.PROGRESS_EVERY_RECORDS`), never
# `from .jobs import PROGRESS_EVERY_RECORDS` into a module global, or turning it down in a test moves one
# phase and not the other.
PROGRESS_EVERY_RECORDS = 20_000


def progress_step(total: int) -> int:
    """Bytes of source log between two progress publishes, for a file of `total` bytes.

    A RECORD count alone cannot drive a progress bar. At 20,000 records a 5,000-line file never
    reaches the modulo and publishes NOTHING between "start" and "done": the bar reads 0 % for the
    whole parse and then jumps to complete. A 25,000-line file ticks exactly once, at 80 %. On a
    library of 617 mostly-small files that is every file, which is what "it's just showing 0%" was.

    Bytes are also what `pct` is computed from, so stepping in bytes makes the tick cadence and the
    number on screen the same quantity. ~100 publishes per file whatever its size, with a 32 KB floor
    so a tiny file still moves and a big one is not publishing per record (each publish takes the
    tracker lock and credits throughput).
    """
    return max(32 * 1024, int(total) // 100)


@dataclass
class ParseProgress:
    key: str                  # source id
    file: str
    total: int                # bytes of source log
    done: int = 0
    events: int = 0
    workers: int = 1          # >1 when the file is being parsed by the multi-process path
    phase: str = "parsing"    # 'parsing' | 'merging'
    started_ts: float = field(default_factory=time.time)
    updated_ts: float = field(default_factory=time.time)

    def public(self) -> dict[str, Any]:
        done = min(self.done, self.total) if self.total else self.done
        elapsed = max(1e-3, self.updated_ts - self.started_ts)
        rate = done / elapsed
        pct = (done / self.total * 100.0) if self.total else 0.0
        eta = ((self.total - done) / rate) if (self.total and rate > 1.0 and done < self.total) else None
        return {"bytesDone": int(done), "bytesTotal": int(self.total), "pct": round(min(100.0, pct), 1),
                "events": int(self.events), "workers": int(self.workers), "phase": self.phase,
                "bytesPerSec": int(rate), "etaSec": (int(eta) if eta is not None else None),
                "elapsedSec": int(elapsed)}


class ProgressTracker:
    """Live per-source parse progress. Cheap enough to touch from a parse loop; never persisted."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: dict[str, ParseProgress] = {}

    def start(self, key: str, file: str, total: int, workers: int = 1) -> None:
        with self._lock:
            self._rows[key] = ParseProgress(key=key, file=file, total=max(0, int(total)), workers=max(1, workers))

    def advance(self, key: str, *, done: Optional[int] = None, add: int = 0, events: Optional[int] = None,
                phase: str = "") -> None:
        with self._lock:
            row = self._rows.get(key)
            if row is None:
                return
            if done is not None:
                row.done = max(row.done, int(done))
            if add:
                row.done += int(add)
            if events is not None:
                row.events = int(events)
            if phase:
                row.phase = phase
            row.updated_ts = time.time()
            ev, done = row.events, row.done
        # OUTSIDE the tracker lock, and after it: throughput is credited from the same ticks the Sources
        # page reads, so "events/s" moves while a big file is being parsed instead of staying at 0 until
        # it finishes. Deltas are per source, so ticking a thousand times credits the work once.
        metrics.record_progress(key, ev, done)

    def finish(self, key: str) -> None:
        with self._lock:
            self._rows.pop(key, None)

    def get(self, key: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._rows.get(key)
            return row.public() if row is not None else None

    def merge(self, keys: Iterable[str]) -> Optional[dict[str, Any]]:
        """Combined progress across several sources (one upload can expand into many)."""
        with self._lock:
            rows = [self._rows[k] for k in keys if k in self._rows]
            if not rows:
                return None
            total = sum(r.total for r in rows)
            done = sum(min(r.done, r.total) if r.total else r.done for r in rows)
            events = sum(r.events for r in rows)
            started = min(r.started_ts for r in rows)
            updated = max(r.updated_ts for r in rows)
            workers = max(r.workers for r in rows)
            phase = rows[0].phase
        merged = ParseProgress(key="", file="", total=total, done=done, events=events, workers=workers,
                               phase=phase, started_ts=started, updated_ts=updated)
        return merged.public()

    def active(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{"sourceId": r.key, "file": r.file, **r.public()} for r in self._rows.values()]

    def all_rows(self) -> dict[str, dict[str, Any]]:
        """Every in-flight row, keyed by source id, taking the lock ONCE.

        `GET /api/case` attaches this to its sources, and the analyst's library is ~680 of them: calling
        `get()` per source would be 680 lock acquisitions on the most-polled endpoint in the app to read
        a table that never holds more than a handful of rows.
        """
        with self._lock:
            return {k: r.public() for k, r in self._rows.items()}


PARSE_PROGRESS = ProgressTracker()


@dataclass
class Job:
    id: str
    file: str
    size: int                      # bytes the client said it would send (0 when unknown)
    target: str                    # 'case' | 'library'
    caseId: str = ""               # '' for a library staging job — it belongs to no case by design
    received: int = 0
    state: str = "queued"
    parser: str = ""
    confidence: float = 0.0
    events: int = 0
    error: str = ""
    interrupted: bool = False      # the server died while this job was in flight
    # Failed by the WATCHDOG, not by the parser. The distinction is what makes reviving safe: a byte, a
    # heartbeat or the ingest request itself brings a stale job back, while a job `finish()` failed stays
    # failed — that failure is a real report about evidence that did not reach the pool.
    stale: bool = False
    sourceIds: list[str] = field(default_factory=list)
    created_ts: float = field(default_factory=time.time)
    updated_ts: float = field(default_factory=time.time)

    def public(self, progress: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        return {
            "id": self.id, "file": self.file, "size": self.size, "received": self.received,
            "state": self.state, "target": self.target, "caseId": self.caseId, "parser": self.parser,
            "confidence": round(self.confidence, 3), "events": self.events, "error": self.error,
            "interrupted": self.interrupted, "stale": self.stale, "sourceIds": list(self.sourceIds),
            # live parse progress, present only while state == 'parsing' (see ProgressTracker)
            "progress": progress,
            "createdAt": _iso(self.created_ts), "updatedAt": _iso(self.updated_ts),
        }

    def live(self, adopted: Iterable[str] = ()) -> dict[str, Any]:
        """`public()` with the live parse progress attached — what the API serves.

        `adopted` are tracker rows the registry matched to this job because it has not learned its own
        source ids yet (see `JobRegistry._adopt_locked`). They are used for DISPLAY only and are never
        written to `sourceIds`, so nothing about job resolution depends on the match being right.
        """
        keys: Iterable[str] = self.sourceIds or list(adopted)
        prog = PARSE_PROGRESS.merge(keys) if self.state == "parsing" else None
        if prog is None and self.state == "parsing" and self.size:
            # the parse thread has not registered yet (or the file is still being staged)
            prog = {"bytesDone": 0, "bytesTotal": self.size, "pct": 0.0, "events": 0, "workers": 1,
                    "phase": "parsing", "bytesPerSec": 0, "etaSec": None, "elapsedSec": 0}
        return self.public(prog)


def _store_snapshot() -> tuple[str, dict[str, tuple[str, int, str, str, str]]]:
    """(active case id, {sourceId: (state, events, parser, error, enrich)}).

    Taken under the STORE lock and returned as plain data BEFORE the registry lock is acquired: the
    registry must never hold its own lock while reaching into the store, or a parse thread finishing a
    job could deadlock against a reader.
    """
    try:
        from .store import STORE
        with STORE.lock:
            return STORE.case_id, {sid: (s.state, s.events, s.parser, s.error or "", s.enrich)
                                   for sid, s in STORE.sources.items()}
    except Exception:
        return "", {}


class JobRegistry:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._jobs: dict[str, Job] = {}
        self._loaded_from: Optional[Path] = None

    # ------------------------------------------------------------- persistence
    @staticmethod
    def _path() -> Path:
        # resolved per call, not at import: the tests point DATA_DIR at a throwaway directory
        return config.DATA_DIR / "jobs.json"

    def load(self) -> None:
        path = self._path()
        rows: list[dict] = []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            rows = raw.get("jobs") if isinstance(raw, dict) else raw
        except (OSError, ValueError):
            rows = []
        with self.lock:
            self._jobs = {}
            for r in rows or []:
                if not isinstance(r, dict) or not r.get("id"):
                    continue
                try:
                    self._jobs[str(r["id"])] = Job(
                        id=str(r["id"]), file=str(r.get("file") or ""), size=int(r.get("size") or 0),
                        target=str(r.get("target") or "case"), caseId=str(r.get("caseId") or ""),
                        received=int(r.get("received") or 0), state=str(r.get("state") or "queued"),
                        parser=str(r.get("parser") or ""), confidence=float(r.get("confidence") or 0.0),
                        events=int(r.get("events") or 0), error=str(r.get("error") or ""),
                        interrupted=bool(r.get("interrupted")), stale=bool(r.get("stale")),
                        sourceIds=[str(s) for s in (r.get("sourceIds") or [])],
                        created_ts=float(r.get("created_ts") or time.time()),
                        updated_ts=float(r.get("updated_ts") or time.time()),
                    )
                except (TypeError, ValueError):
                    continue
            self._loaded_from = path

    def _save_locked(self) -> None:
        path = self._path()
        rows = []
        for j in self._jobs.values():
            d = j.public()
            d.pop("progress", None)   # live-only, meaningless after a restart
            d["created_ts"] = j.created_ts
            d["updated_ts"] = j.updated_ts
            rows.append(d)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"jobs": rows}, indent=1), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass

    def _ensure_loaded(self) -> None:
        if self._loaded_from is None or self._loaded_from != self._path():
            self.load()

    # ------------------------------------------------------------------ writes
    def create(self, file: str, size: int, target: str = "case", case_id: str = "") -> Job:
        job = Job(id=uuid.uuid4().hex[:12], file=file or "upload", size=max(0, int(size or 0)),
                  target="library" if target == "library" else "case", caseId=case_id or "")
        with self.lock:
            self._ensure_loaded()
            self._jobs[job.id] = job
            self._prune_locked()
            self._save_locked()
        return job

    def _touch(self, job: Job) -> None:
        job.updated_ts = time.time()

    def progress(self, job_id: str, received: int) -> Optional[Job]:
        """Bytes-in-flight, reported by the uploading tab. Purely client-side knowledge — the server only
        sees the body once it is complete — so it is stored, not trusted for correctness."""
        with self.lock:
            self._ensure_loaded()
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if job.state in TERMINAL_STATES and not job.stale:
                return job
            # A stale job is one the watchdog buried; a byte arriving says it was wrong. Reviving here
            # matters because the bury and the transfer race: the tab reaches file #9 seconds after the
            # watchdog gave up on it, and without this the row reads "failed" for the whole upload and
            # only corrects itself when the ingest request finally lands.
            self._revive_locked(job)
            job.received = max(job.received, min(int(received or 0), job.size or int(received or 0)))
            job.state = "uploading"
            self._touch(job)
            self._save_locked()
            return job

    def _revive_locked(self, job: Job) -> None:
        """Undo a watchdog bury. Caller holds the lock; a job that is not stale is left exactly as it is."""
        if not job.stale:
            return
        job.stale = False
        job.error = ""
        job.interrupted = False
        job.state = "uploading" if job.received else "queued"

    def heartbeat(self, job_ids: Iterable[str]) -> tuple[list[str], list[str]]:
        """"These transfers are still mine." Returns (alive, revived) ids.

        The only party that knows whether a QUEUED upload is still coming is the tab holding the file
        handle: the server has seen nothing from it by definition. Unknown ids and jobs that finished
        between two ticks are ignored rather than refused — a tab one version behind, or one whose batch
        resolved while the request was in flight, is not an error.
        """
        alive: list[str] = []
        revived: list[str] = []
        with self.lock:
            self._ensure_loaded()
            for jid in job_ids:
                job = self._jobs.get(str(jid))
                if job is None:
                    continue
                if job.state in TERMINAL_STATES:
                    if not job.stale:
                        continue          # really finished — a heartbeat may not resurrect it
                    self._revive_locked(job)
                    revived.append(job.id)
                self._touch(job)
                alive.append(job.id)
            if alive:
                self._save_locked()
        return alive, revived

    def begin_parse(self, job_id: str, size: Optional[int] = None) -> Optional[Job]:
        with self.lock:
            self._ensure_loaded()
            job = self._jobs.get(job_id)
            if job is None:
                return None
            self._revive_locked(job)   # the body arrived, so any watchdog verdict on it was wrong
            if size is not None:
                job.size = job.size or int(size)
                job.received = int(size)
            elif job.size:
                job.received = job.size
            job.state = "parsing"
            job.error = ""
            self._touch(job)
            self._save_locked()
            return job

    def attach_sources(self, job_id: str, source_ids: Iterable[str]) -> Optional[Job]:
        with self.lock:
            self._ensure_loaded()
            job = self._jobs.get(job_id)
            if job is None:
                return None
            job.sourceIds = [s for s in source_ids]
            self._touch(job)
            self._save_locked()
            return job

    def finish(self, job_id: str, *, parser: str = "", events: int = 0, confidence: float = 0.0,
               source_ids: Optional[Iterable[str]] = None, error: str = "") -> Optional[Job]:
        """Resolve a job — unless phase 2 of the ingest has not run yet.

        `sync()` refuses to resolve a job whose sources are still raw/queued/enriching, but nothing
        went through sync on the common path: ingest returns a source in state READY the moment the RAW
        phase lands (milliseconds), so routers.sources._report called this method and the job reported
        `ready` with the file still un-parsed. A phase-2 parse failure then arrived AFTER the analyst had
        been told the upload was fine — and a failed parse reaching them is the entire reason the job
        registry exists. So the same rule is applied here: stay `parsing`, keep the source ids, and let
        sync() settle it when enrichment ends (successfully or as an ERROR source).
        """
        sids = list(source_ids) if source_ids is not None else None
        pending_enrich = False
        if sids and not error:
            # snapshot the store BEFORE taking the registry lock — never hold this lock into the store
            _, known = _store_snapshot()
            pending_enrich = any(known[s][4] in ("raw", "queued", "enriching") for s in sids if s in known)
        with self.lock:
            self._ensure_loaded()
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if sids is not None:
                job.sourceIds = list(sids)
            # Whatever this resolves to is a REAL verdict about the file, so it outranks any watchdog
            # bury and is never revived by a later heartbeat from a tab that has not caught up yet.
            job.stale = False
            job.parser = parser or job.parser
            job.events = int(events)
            job.confidence = float(confidence or job.confidence)
            if job.size:
                job.received = job.size
            if error:
                job.state = "error"
                job.error = error[:2000]
            elif pending_enrich:
                job.state = "parsing"      # phase 2 is still to come; sync() resolves it
                job.error = ""
            else:
                job.state = "ready"
                job.error = ""
            self._touch(job)
            self._prune_locked()
            self._save_locked()
            return job

    def fail(self, job_id: str, message: str) -> Optional[Job]:
        return self.finish(job_id, error=message or "upload failed")

    def clear_all(self) -> int:
        """Drop EVERY job, running ones included, and remove jobs.json. Returns how many were dropped.

        Only /api/admin/clear-all uses this: the sources those jobs describe no longer exist, so leaving
        the rows behind would keep an "uploading 3 files" banner over an empty workspace, and jobs.json
        would repopulate the list on the next restart.
        """
        with self.lock:
            self._ensure_loaded()
            n = len(self._jobs)
            self._jobs = {}
            try:
                self._path().unlink(missing_ok=True)
            except OSError:
                pass
            self._loaded_from = self._path()
            return n

    def clear_finished(self) -> int:
        with self.lock:
            self._ensure_loaded()
            gone = [jid for jid, j in self._jobs.items() if j.state in TERMINAL_STATES]
            for jid in gone:
                del self._jobs[jid]
            self._save_locked()
            return len(gone)

    # ------------------------------------------------------------ reconciliation
    def _prune_locked(self) -> None:
        now = time.time()
        keep: dict[str, Job] = {}
        for jid, j in self._jobs.items():
            keep_for = READY_RETAIN_SEC if j.state == "ready" else RETAIN_SEC
            if j.state in TERMINAL_STATES and now - j.updated_ts > keep_for:
                continue
            keep[jid] = j
        if len(keep) > MAX_JOBS:
            ordered = sorted(keep.values(), key=lambda j: j.created_ts)
            # never drop something still running just because it is old — cut finished jobs first
            excess = len(keep) - MAX_JOBS
            for j in ordered:
                if excess <= 0:
                    break
                if j.state in TERMINAL_STATES:
                    del keep[j.id]
                    excess -= 1
            if excess > 0:
                for j in sorted(keep.values(), key=lambda j: j.created_ts)[:excess]:
                    del keep[j.id]
        self._jobs = keep

    def sync(self) -> None:
        """Resolve `parsing` jobs against the store, then age out dead uploads and prune.

        This is what makes a THREADED parse (files over store.SYNC_LIMIT) land in the registry: nothing
        calls back when the thread finishes, so the job is resolved the next time anybody reads the list.
        """
        case_id, sources = _store_snapshot()
        now = time.time()
        with self.lock:
            self._ensure_loaded()
            changed = False
            for job in self._jobs.values():
                # A LIBRARY job belongs to no case (`caseId` is ''), so it can never match the active
                # case id — it would have sat in `parsing` forever now that finish() defers to us.
                if job.state == "parsing" and job.sourceIds and job.caseId in (case_id, ""):
                    rows = [sources[s] for s in job.sourceIds if s in sources]
                    if not rows or any(r[0] == "PARSING" for r in rows):
                        continue
                    # Ingest has two phases (app/enrich.py) and the job covers BOTH: the raw phase is
                    # near-instant, so resolving here would report "ready" while the file has no
                    # timestamps, no fields and no detections yet — and a parse that fails in phase 2
                    # would land after the job had already claimed success. 'skipped' is a settled
                    # state (the analyst declined enrichment), so it resolves.
                    if any(r[4] in ("raw", "queued", "enriching") for r in rows):
                        continue
                    errs = [r[3] for r in rows if r[0] == "ERROR" and r[3]]
                    job.events = sum(r[1] for r in rows)
                    job.parser = job.parser or (rows[0][2] if rows else "")
                    job.state = "error" if errs else "ready"
                    job.error = "; ".join(errs)[:2000] if errs else ""
                    self._touch(job)
                    changed = True
                elif job.state in ("queued", "uploading") and now - job.updated_ts > STALE_UPLOAD_SEC:
                    # `updated_ts` is advanced by a byte (PATCH) AND by a heartbeat, so reaching here
                    # means the sending tab has said nothing for ten minutes — it is gone. Name the state
                    # honestly: a job with received:0 never started, and telling the analyst an upload
                    # "stopped before the server received the whole file" about a transfer that never
                    # sent a byte sends them looking for a network fault that does not exist.
                    job.state = "error"
                    job.stale = True
                    job.error = ("the upload stopped before the server received the whole file"
                                 if job.received else
                                 "this transfer never started — the tab that queued it is gone"
                                 " (drop the file again to retry)")
                    self._touch(job)
                    changed = True
            before = len(self._jobs)
            self._prune_locked()
            if changed or len(self._jobs) != before:
                self._save_locked()

    def reconcile(self) -> int:
        """Startup pass: resolve what finished, then bury what the restart killed. Returns jobs buried.

        One thing a restart does NOT kill: a source waiting for phase 2. `Store.requeue_unenriched()`
        re-queues every raw/queued/enriching source at startup, so its job is not dead work — telling
        the analyst to re-upload a file that is about to finish enriching would be wrong in the other
        direction. Those jobs stay `parsing` and sync() settles them when the worker gets to them.
        """
        self.load()
        self.sync()
        _, known = _store_snapshot()
        resuming = {sid for sid, row in known.items() if row[4] in ("raw", "queued", "enriching")}
        with self.lock:
            buried = 0
            for job in self._jobs.values():
                if job.state == "parsing" and any(s in resuming for s in job.sourceIds):
                    continue
                if job.state in ACTIVE_STATES:
                    was = "parsing" if job.state == "parsing" else "uploading"
                    job.state = "error"
                    job.interrupted = True
                    job.error = (f"the server restarted while this file was still {was}"
                                 " — re-upload it, or attach it again from the library")
                    self._touch(job)
                    buried += 1
            if buried:
                self._save_locked()
            return buried

    # ------------------------------------------------------------------- reads
    def _adopt_locked(self, jobs: list[Job]) -> dict[str, list[str]]:
        """Match in-flight tracker rows to jobs that do not know their own source ids yet.

        Phase 1 of an ingest (`enrich.raw_events`) runs INSIDE the upload request and publishes progress
        under a source id the store mints at the top of `add_file` — but the registry only hears that id
        when the request RETURNS and `_report` calls `attach_sources`/`finish`. So for the whole raw
        split every OTHER tab saw the 0 % placeholder: a moment at 9 k rows, minutes on the analyst's
        1.07 GB / 10 M-row CSV, which is exactly the "is it hung?" gap two-phase ingest exists to close.
        (CLAUDE.md: live parse progress is one of two things that may move on the Sources page but must
        never disappear.)

        The alternative was to push the source id into the job as soon as `add_file` mints it. That is
        more precise, but it has to be wired into every ingest caller — `routers/sources.upload_sources`,
        `routers/library.stage_files`, the attach path — and the one that silently forgets is invisible
        until someone uploads a gigabyte. Reading it off the tracker fixes all of them at once and keeps
        the store free of job-registry plumbing.

        The match is by FILE NAME, which is exact on the path that matters: a non-container upload
        reaches `Store.add_file` under the name the job was created with. It is DISPLAY only — nothing
        here writes `sourceIds`, touches jobs.json or feeds `sync()`/`reconcile()`, so a wrong guess can
        never resolve a job or claim a parse failed. A row already owned by any job is never adopted and
        each row goes to at most one job (oldest first), so two concurrent uploads of the same file name
        cannot both display the same bytes.

        Callers must hold `self.lock`.
        """
        waiting = [j for j in jobs if j.state == "parsing" and not j.sourceIds]
        if not waiting:
            return {}
        claimed = {sid for j in self._jobs.values() for sid in j.sourceIds}
        free = [r for r in PARSE_PROGRESS.active() if r["sourceId"] not in claimed]
        if not free:
            return {}
        out: dict[str, list[str]] = {}
        taken: set[str] = set()
        for job in sorted(waiting, key=lambda j: j.created_ts):
            cands = [r for r in free if r["file"] == job.file and r["sourceId"] not in taken]
            if not cands:
                continue
            # same name twice in flight: the declared size settles it when the sizes differ at all
            cands.sort(key=lambda r: 0 if (job.size and r["bytesTotal"] == job.size) else 1)
            taken.add(cands[0]["sourceId"])
            out[job.id] = [cands[0]["sourceId"]]
        return out

    def snapshot(self, limit: int = 100) -> dict[str, Any]:
        self.sync()
        with self.lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_ts, reverse=True)[:max(1, limit)]
            adopted = self._adopt_locked(jobs)
            rows = [j.live(adopted.get(j.id, ())) for j in jobs]
            active = sum(1 for j in self._jobs.values() if j.state in ACTIVE_STATES)
        return {"jobs": rows, "active": active, "total": len(rows)}

    def get(self, job_id: str) -> Optional[Job]:
        with self.lock:
            self._ensure_loaded()
            return self._jobs.get(job_id)


REGISTRY = JobRegistry()


# --------------------------------------------------------------------- probing
def probe_upload(filename: str, data: bytes, total_size: Optional[int] = None) -> dict[str, Any]:
    """What IS this file — without parsing it.

    Library staging deliberately never parses (nothing may touch the store or materialise a case), which
    left staged bytes completely opaque: a name and a size. Fingerprinting is cheap next to parsing and
    only ever reads a bounded prefix, so it runs at stage time and the answer is cached on the library
    entry. Full parsing still happens on attach.
    """
    from .parsers.registry import fingerprint

    size = int(total_size if total_size is not None else len(data))
    head = data if len(data) <= PROBE_BYTES else data[:PROBE_BYTES]
    out: dict[str, Any] = {"parser": "", "confidence": 0.0, "state": "MAP", "sample": "",
                           "lines": 0, "linesEstimated": False}
    try:
        fp = fingerprint(filename, head)
    except Exception:
        return out
    out["parser"] = fp.parser.name
    out["confidence"] = round(float(fp.confidence), 3)
    out["state"] = fp.state
    out["sample"] = (fp.sample or "")[:2000]
    newlines = head.count(b"\n")
    if len(head) < size and head:
        out["lines"] = int(newlines * (size / len(head)))
        out["linesEstimated"] = True
    else:
        out["lines"] = newlines + (1 if head and not head.endswith(b"\n") else 0)
    return out
