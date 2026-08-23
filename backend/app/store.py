"""In-memory WORKSPACE store: parsed sources, normalized events, and the optional active case.

The event pool is NOT owned by a case. It holds two kinds of source:

  * origin='case'    — uploaded into (or attached to) the active case; bytes live in cases/<id>/uploads/
  * origin='library' — staged in $IRIS_DATA_DIR/library/, belonging to NO case; they survive every case
                       delete and every case switch

Search, timeline, detections, the entity graph, IOC extraction and event detail all read the whole pool,
so analysis works with zero cases on disk. A case adds curation on top: the case set, notes, manual IOCs,
accepted graph links, findings and the report.
"""
from __future__ import annotations

import hashlib

import json
import os
import re
import shutil
import sys
import threading
import time
import uuid
from calendar import timegm
from collections import Counter, OrderedDict, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import numpy as np

from . import config, enrich, metrics, pool_store
from .detect import RULES, run_rules
from .exclusions import EXCLUSIONS
from .rules import RULES_STORE
from .models import (Case, CaseEnrichment, CaseNote, CaseSetEntry, CaseSnapshot, EnrichActivity, EnrichCounts, Event,
                     ParseProgressInfo, PoolFileProgress, PoolProgress, PoolSkip, Posture, QueueItem,
                     Source, max_sev)
from .normalize import to_iso   # the per-record normalization itself lives in parsers/parallel.py
from .parsers import archives
from .parsers.base import BaseParser, ParsedEvent
from .parsers.delimited import DelimitedParser
from .parsers.registry import fingerprint, state_for

SYNC_LIMIT = 50 * 1024 * 1024
# How much of a file the SNIFFER is shown when the bytes are being streamed rather than held. Every
# fingerprint rule reads a magic number, an extension or the first few lines; `probe_upload` has always
# passed a 2 MB prefix for the same reason. Reading a 1.9 GB capture to decide it is a pcap is exactly
# the cost the streaming path exists to remove.
SNIFF_HEAD_BYTES = 2 * 1024 * 1024
# Line-oriented text families that can be shown RAW before they are parsed (see app/enrich.py). A parser
# marked `chunkable` already qualifies by definition — it can be split on newlines — and these are the
# line formats that are not chunkable for other reasons. Anything binary or container-shaped is absent on
# purpose: it has no readable raw form, so a raw-first import of it would import nothing.
_RAW_FIRST_FAMILIES = {"text", "syslog", "nginx", "delimited", "csv", "jsonl", "json"}


def settings_auto_enrich() -> bool:
    """Should an ingested source be queued for enrichment automatically?

    Default yes: raw-first is about WHEN the interpretation happens, not about doing without it. Turning
    it off makes enrichment strictly on demand, per source, which is the mode for someone who only wants
    grep over raw lines.
    """
    try:
        return bool(getattr(config.get_settings().ingest, "autoEnrich", True))
    except Exception:
        return True
# During a bulk (library) load, parsed events are merged into the pool in batches of this many, not once
# per file: every merge is a sort + full reindex of the WHOLE pool, so per-file merges were quadratic in
# the number of files and an allocation storm (34 files -> 34 rebuilds of a 1.3 M-entry dict). A batch
# still lands within a file or two, so search fills in as the load runs.
BULK_FLUSH_EVENTS = 250_000
# Total staged bytes the STARTUP path is allowed to parse inline. The case-less pool has no size ceiling —
# a real library held 589 MB across ~40 files — and cases.startup() runs inside the FastAPI lifespan, so
# parsing it there kept /api/health from ever answering. Anything above this loads in a background thread
# and the API comes up immediately; `Case.poolLoading` / `poolPending` say it is still filling.
LIBRARY_SYNC_LIMIT = 8 * 1024 * 1024
# A LAST-RESORT default, used only when the workspace is empty and there is nothing to measure.
#
# The old value, 50, was quoted at the analyst about every file regardless of what was in it, and it
# lied by 2.3x on the one that mattered: "1149 MB needs 57.5 GB". The cost is not a property of Iris,
# it is a property of the LOG. Measured on this machine after the slotted-Event work, on the analyst's
# own DNS_Logs.csv (a 67 MB slice, 582,530 rows, process RSS delta):
#
#     raw (phase 1 — in the pool and searchable at once)   462 B/event    4.0x source bytes
#     enriched (phase 2 — 10 parsed columns per row)     ~1513 B/event   ~9-13x source bytes
#
# and on a 124-byte synthetic DNS line with no parsed fields, 409 B/event / 3.1x. That spread IS the
# point: `Store.pool_bytes_per_source_byte()` measures the live pool rather than guessing, and says
# whether the number it returns was measured. This constant only fills in for an empty workspace, and
# sits at the top of the observed range because over-quoting an empty workspace is a warning while
# under-quoting it is an OOM kill.
POOL_BYTES_PER_SOURCE_BYTE = 16


def _obj_bytes(x: object) -> int:
    """`sys.getsizeof` rounded up to CPython's 16-byte allocation quantum."""
    return (sys.getsizeof(x) + 15) & ~15


def _str_bytes(s: str) -> int:
    """A string's cost, PER EVENT. Empty and single-character strings are CPython singletons (the
    latin-1 cache), so a column full of `-` costs nothing per row — counting it was most of why the
    first version of this estimator overshot the real RSS by half on a 10-column DNS CSV."""
    return _obj_bytes(s) if len(s) > 1 else 0


# The fixed per-event cost of being IN THE POOL, not just of existing: the slotted object with shared
# empty containers, its slot in `Store.events`, its `event_index` entry (dict table ~27 B + the int
# value ~32 B) and its slot in the float64 `Store.ts` array.
_EVENT_BASE_BYTES = _obj_bytes(Event(id="x", raw="y")) + 8 + 27 + 32 + 8
# A models.Detection is a small pydantic model; events carrying one are a minority, so a flat figure is
# enough and avoids walking pydantic internals per event.
_DETECTION_BYTES = 400


def event_bytes(e: Event) -> int:
    """Bytes of RAM one pooled `Event` retains — counted, not assumed.

    Only what the event OWNS is counted, because only that scales with the event count:

      * `source` / `file` / `sourceId` are ONE string per source, shared by every one of its events;
      * `msg` is the same object as `raw` wherever it was derived from it (see models.Event);
      * `fields` KEYS are the parser's header — one set of strings per source, not per row. The caller
        (`Store.pool_bytes_per_source_byte`) adds them once, which is why they are skipped here;
      * empty and one-character values are interpreter singletons (`_str_bytes`).

    Validated against process RSS on the analyst's own DNS_Logs.csv (67 MB, 582,530 rows): 454 B/event
    calculated vs 459 measured raw, and 1,435 vs 1,514 once enriched with 10 parsed columns.
    """
    n = _EVENT_BASE_BYTES + _str_bytes(e.raw) + _str_bytes(e.id)
    m = e._msg
    if m is not None and m is not e.raw:
        n += _str_bytes(m)
    n += _str_bytes(e.ts) + _str_bytes(e.host) + _str_bytes(e.user)
    f = e.fields
    if f:
        n += _obj_bytes(f) + sum(_str_bytes(v) for v in f.values())
    ents = e.entities
    if ents:
        n += _obj_bytes(ents) + sum(_str_bytes(x) for x in ents)
    dets = e.detections
    if dets:
        n += _obj_bytes(dets) + _DETECTION_BYTES * len(dets)
    return n


# How many events a ratio measurement walks. Strided across the whole pool so it is not a picture of
# whichever source happens to be first.
POOL_RATIO_SAMPLE = 20_000
UTC = timezone.utc


def pool_budget_bytes() -> int:
    """How many bytes of staged log the pool may load at startup. **0 = unlimited, and that is the
    default.**

    There used to be a machine-derived cap here (40 % of RAM / the measured cost per source byte), and it
    silently left the two largest files of a 61-file library out of the pool. The analyst's judgement,
    which is the right one: *"there should be no budget limit — data gets uploaded, it becomes
    searchable."* A file that was uploaded as evidence and is not in search is worse than a slow or
    memory-hungry Iris, because nothing about a search tells you it was answered over part of the
    corpus. Everything staged is loaded.

    `IRIS_POOL_MAX_MB` still sets a cap for anyone who deliberately wants one (a shared box, a small VM);
    unset means no limit at all.
    """
    env = os.environ.get("IRIS_POOL_MAX_MB", "").strip()
    if env:
        try:
            return max(0, int(float(env) * 1024 * 1024))
        except ValueError:
            pass
    return 0


# Below this, a file is never refused for memory: the check exists for the handful of files that can
# take the process down, and a library of small logs must not turn into a wall of skip notices.
_MEMORY_CHECK_MIN = 64 << 20


def pool_headroom_bytes() -> int:
    """Bytes of source log this machine can still afford to hold as Events, RIGHT NOW.

    The budget above is a static per-machine guess; this is the live figure, and it is what an explicit
    "load it anyway" is checked against. Honest refusal beats an OOM kill that takes the whole workspace
    (and every other loaded source) with it.

    The cost per source byte is MEASURED on the pool that is already loaded (see
    `Store.pool_bytes_per_source_byte`) and only falls back to the constant on an empty workspace.
    """
    try:
        import psutil
        return max(0, int(psutil.virtual_memory().available * 0.8 / STORE.pool_bytes_per_source_byte()[0]))
    except Exception:
        return 0

def _under_data_dir(path: Path) -> bool:
    """True when `path` resolves inside $IRIS_DATA_DIR. Used to decide whether a path READ OUT OF
    case.json may be opened as-is; a stray or planted absolute path is resolved by basename instead."""
    try:
        return config.DATA_DIR.resolve() in path.resolve().parents
    except (OSError, ValueError):
        return False


def _wipe_tree(path: Path) -> int:
    """Delete a whole directory tree, returning how many FILES it held. Missing tree = 0."""
    n = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                n += 1
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)
    return n


FAMILY_HINTS = {
    "delimited": ("firewall.edge", ("fw", "firewall", "pipe", "flow", "pan", "asa", "fortigate")),
}


def raw_hash(raw: str) -> str:
    """A stable fingerprint of one log line — the anchor a curated entry keeps.

    sha1 truncated to 16 hex: short enough to sit in case.json for thousands of entries, wide enough
    that two DIFFERENT lines colliding is not a practical concern, and it never stores the line twice.
    """
    if not raw:
        return ""
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


class Store:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.case_id = "CASE-0001"
        # A PENDING case has an id reserved but nothing on disk: no folder, no case.json, and it is not
        # listed by /api/cases. It exists so the UI always has something to render after the last case is
        # deleted, without resurrecting a phantom "Untitled case" the analyst never asked for. Any real
        # write (ingest, rename, note) materialises it — see _materialise().
        self.pending = False
        self.name = "Untitled case"
        # one-paragraph description of the investigation. Analyst-editable; also what the AI
        # investigator's update_case tool sets. Persisted in case.json alongside the name.
        self.summary = ""
        self.analyst = config.get_settings().analyst
        self.created_at = datetime.now(UTC)
        self.sources: dict[str, Source] = {}
        self.source_paths: dict[str, Path] = {}
        # sid -> the member's provenance path INSIDE its container ("bundle.zip!var/log/auth.log"),
        # for the sources whose `source_paths` entry is a container rather than their own bytes. That
        # only happens for a library-staged archive, where every member shares the one staged file —
        # and it is exactly what made phase 2 re-read the ARCHIVE and replace a parsed syslog member
        # with lines of decoded zip binary, reporting the source `enriched` afterwards. Absent means
        # the path IS the source; `source_bytes()` is the one place that has to know the difference.
        self.source_member: dict[str, str] = {}
        self.source_parsers: dict[str, BaseParser] = {}
        self.source_order: list[str] = []
        # sid -> 'case' | 'library'. A library source belongs to no case: it is parsed into the pool but
        # is never written into case.json and is never dropped when the active case changes.
        self.source_origin: dict[str, str] = {}
        # sid -> the on-disk name in $IRIS_DATA_DIR/library/ this source came from. Kept after a source is
        # ATTACHED to a case (origin flips to 'case'), because it is the only thing that stops
        # restore_library() re-parsing the same bytes a second time into the same pool.
        self.source_library: dict[str, str] = {}
        # sid -> stable event-id prefix. "" keeps the legacy global counter (e1, e2, …) so case ids that
        # are already persisted in case.json case sets never move. Library sources use "l<sid>", which is
        # derived from the file name, so their event ids survive a restart AND an attach.
        self.source_prefix: dict[str, str] = {}
        self.events: list[Event] = []
        self.event_index: dict[str, int] = {}
        self.ts: np.ndarray = np.zeros(0, dtype=np.float64)
        # curated events that ARE the case (replaces pins). Ordered by insertion; keyed by event id.
        self.case_set: "OrderedDict[str, CaseSetEntry]" = OrderedDict()
        self.notes: list[CaseNote] = []
        # indicators the analyst entered by hand; extracted ones are derived from events each time
        self.manual_iocs: list[dict[str, str]] = []
        self.skews: dict[str, float] = {}
        # sid -> events of that source that carry a `parse_error` field. Kept per source so parse
        # COVERAGE (a headline number on /api/case) is a sum over ~60 sources instead of a scan of
        # millions of events on every poll — that scan, under the store lock, was a big part of why the
        # endpoint took 15 s during ingest.
        self.source_parse_errors: dict[str, int] = {}
        self.unmapped_fields = 0
        self.rules_fired = 0
        # background detection refresh after a delete (see _refresh_detections_async)
        self._detect_busy = False
        self._detect_again = False
        # Serialises detection PASSES against each other without holding the store lock. run_rules
        # mutates `Event.detections` in place, so two concurrent passes would double every hit — but the
        # pass is O(pool) (~10 s at 1.2 M events) and holding `self.lock` for it blocked /api/case, every
        # delete and every write for the duration: that was the 4.9 s stall measured on `/api/case` at
        # the start of an ingest. Readers never needed the lock for this; only other passes do.
        self._detect_lock = threading.Lock()
        # save_meta() serialisation. It builds `meta` under `self.lock` and then writes the file
        # OUTSIDE it (the write must not hold the store lock), so two concurrent saves could land in
        # the opposite order to the one they were built in and the OLDER snapshot would win —
        # silently reverting case.json to a state before the edit that triggered the newer save.
        # That is not theoretical: every `bump()` calls save_meta, and the enrichment worker bumps
        # once per source it finishes, so a background save routinely overlaps a case-set / note /
        # IOC write on a request thread. `_meta_seq` stamps each build, `_meta_written` records the
        # newest stamp that has actually reached disk, and a save carrying an older stamp is dropped.
        # A counter rather than one big lock because callers may already hold `self.lock` here, and
        # taking a second lock underneath it while another thread takes them the other way round is
        # how this would deadlock instead.
        self._meta_seq = 0
        self._meta_written: dict[str, int] = {}
        self._meta_write_lock = threading.Lock()
        self.version = 0
        # The correlation analysis and the typed graph are NOT cached on the store any more: they live in
        # derived.AsyncCache (correlate.ANALYSIS_CACHE / graph.GRAPH_CACHE), keyed on `version` +
        # `case_set_rev`, built in the background. See the "derived structures" section below.
        # Bumped on every case-set mutation, so a scope='case' key changes even when an edit leaves the
        # set the same SIZE (relabelling one entry used to leave a stale case analysis behind).
        self.case_set_rev = 0
        # cached distinct-entity count for /api/case (see _entity_count)
        self._entities_count = 0
        self._entities_version = -1
        self._entities_busy = False
        # measured RAM-per-source-byte for THIS pool (see pool_bytes_per_source_byte), cached per version
        self._pool_ratio: Optional[tuple[float, bool]] = None
        self._pool_ratio_version = -1
        # links accepted from the AI reviewer or drawn by hand - persisted in case.json
        self.graph_links: list[dict[str, Any]] = []
        # Nodes the ANALYST or the AGENT put on the graph, as opposed to the ones extraction found.
        # A raw-first workspace extracts nothing at all, so without these an investigation graph could
        # not be drawn: `add_graph_link` had to refuse every endpoint because no node existed to name.
        # Same shape and same lifecycle as `graph_links` — persisted in case.json, overlaid per request,
        # never part of the built structure.
        self.graph_nodes: list[dict[str, Any]] = []
        self._event_seq = 0
        # True while `activate` has cleared memory and not yet read the new case back off disk. A
        # save_meta() landing in that window writes an EMPTY case over a real one — see save_meta.
        self._switching = False
        # sid -> the number its first event id was assigned from. See `_assign_ids`; persisted so a
        # reload reproduces the ids a case set already cites.
        self.source_id_base: dict[str, int] = {}
        # >0 while a BULK load (restore / library restore) is running: per-source detection re-runs and
        # index warms are suppressed, because both are O(whole pool) and doing them once per file made
        # restoring 40 library files quadratic (100% CPU for minutes with the API still unreachable).
        self._bulk = 0
        # Events parsed during a bulk load that have not been merged into the pool yet, and the sources
        # they came from. See _append_events: 34 files used to mean 34 sorts + reindexes of the whole,
        # growing pool. They are merged in batches of BULK_FLUSH_EVENTS or at the end of the load.
        self._pending: list[Event] = []
        # open batch of finished phase-2 parses waiting for one shared merge (enrich_batch)
        self._enrich_batch: Optional[list[dict]] = None
        self._pending_lock = threading.Lock()
        # background pool load progress — surfaced as Case.poolLoading / poolPending / poolLoaded so the
        # analysis screens can say "still loading" instead of showing zero hits and looking like data loss
        self.pool_loading = False
        self.pool_pending = 0
        self.pool_loaded = 0
        # BYTES, not just a file count: "loading 16 more sources" says nothing when one of them is 263 MB
        # and the rest are 2 MB. Total is fixed when the load is planned; done advances per finished file
        # and, within the file being parsed, from the live per-source progress (jobs.PARSE_PROGRESS).
        self.pool_bytes_total = 0
        self.pool_bytes_done = 0
        self.pool_current_file = ""
        self.pool_started_ts = 0.0
        # staged files deliberately NOT parsed because the pool budget was reached (see pool_budget_bytes),
        # keyed by on-disk library name. The AGGREGATE (pool_skipped) is derived from this, never set on its
        # own: "2 files skipped" without saying which two hid 526 MB of evidence from search.
        self.pool_skips: "OrderedDict[str, PoolSkip]" = OrderedDict()
        # The PLAN of the background pool load, on-disk name -> {file, size, state}, in library order.
        # `poolProgress` carried only an aggregate plus `currentFile`, so a load of 40 files said nothing
        # about which ones were already in the pool; this is the per-file half (PoolProgress.files).
        self.pool_plan: "OrderedDict[str, dict[str, Any]]" = OrderedDict()

    # ------------------------------------------------------- pool skip record
    @property
    def pool_skipped(self) -> int:
        """How many staged files are NOT in the pool. Derived, so the header count and the per-file list
        can never disagree — they did, and the aggregate was the only thing the analyst ever saw."""
        return len(self.pool_skips)

    def note_pool_skip(self, name: str, display: str, size: int, reason: str, detail: str,
                       budget: int = 0, used: int = 0) -> None:
        with self.lock:
            self.pool_skips[name] = PoolSkip(fileName=name, displayName=display or name, size=size,
                                             reason=reason, detail=detail, budgetBytes=budget, usedBytes=used)

    def _plan_state(self, name: str, state: str, size: int = 0, events: int = 0) -> None:
        """Advance one file of the pool-load plan. Callers hold the store lock."""
        row = self.pool_plan.get(name)
        if row is None:
            return
        row["state"] = state
        if size:
            row["size"] = size
        if events:
            row["events"] = events

    def clear_pool_skip(self, name: str) -> None:
        with self.lock:
            self.pool_skips.pop(name, None)

    # ------------------------------------------------- what a byte of log costs
    def pool_bytes_per_source_byte(self) -> tuple[float, bool]:
        """`(bytes of RAM per byte of source log, measured?)` for THIS workspace.

        `POOL_BYTES_PER_SOURCE_BYTE = 50` was a single number quoted at the analyst about every file, and
        it lied by 2.3x on the one that mattered ("1149 MB needs 57.5 GB"). The cost is not a property of
        Iris, it is a property of the LOG: a DNS row with ten parsed columns costs four times a plain
        syslog line of the same length. So measure it, on the events already in the pool, and say when
        the answer is a fallback rather than a measurement.

        Both halves of the pool's real cost are counted: the `Event` objects (`event_bytes`, strided
        sample) and the packed search index, whose size the search module reports exactly. Cached per
        store version — the walk is ~20 k events, not the pool.
        """
        with self.lock:
            version = self.version
            cached = self._pool_ratio
            if cached is not None and self._pool_ratio_version == version:
                return cached
            events = self.events
            sized = [(s.events, s.size) for s in self.sources.values() if s.events and s.size]
        src_bytes = sum(sz for _, sz in sized)
        n = len(events)
        if n < 200 or src_bytes <= 0:
            return float(POOL_BYTES_PER_SOURCE_BYTE), False
        step = max(1, n // POOL_RATIO_SAMPLE)
        sample = events[::step]
        per_event = sum(event_bytes(e) for e in sample) / len(sample)
        # field names are one set of strings per source (the header), so they are added once, not per row
        keys: set[str] = set()
        for e in sample:
            keys.update(e.fields)
        total = per_event * n + sum(_obj_bytes(k) for k in keys)
        try:
            from . import search as _search
            total += float(_search.index_status().get("bytes") or 0.0)
        except Exception:
            pass
        ratio = max(1.0, total / src_bytes)
        with self.lock:
            self._pool_ratio, self._pool_ratio_version = (ratio, True), version
        return ratio, True

    # ------------------------------------------------------------ case paths
    @property
    def case_dir(self) -> Path:
        return config.case_dir(self.case_id)

    @property
    def upload_dir(self) -> Path:
        return config.upload_dir(self.case_id)

    @property
    def case_path(self) -> Path:
        return config.case_path(self.case_id)

    # ------------------------------------------------------------- lifecycle
    # -------------------------------------------------------- pool / origins
    def case_source_ids(self) -> list[str]:
        """Sources that belong to the active case, in ingest order."""
        return [s for s in self.source_order
                if s in self.sources and self.source_origin.get(s, "case") == "case"]

    def library_source_ids(self) -> list[str]:
        """Sources staged in the library — parsed into the pool, belonging to no case."""
        return [s for s in self.source_order
                if s in self.sources and self.source_origin.get(s, "case") == "library"]

    def case_events(self) -> list[Event]:
        """The pool events that came from the active case's own sources, in timestamp order.

        Returns self.events unchanged when nothing is staged in the library — a 1.2M-event case must not
        pay for a full copy on every save_meta().
        """
        with self.lock:
            lib = {s for s in self.sources if self.source_origin.get(s, "case") == "library"}
            if not lib:
                return self.events
            events = self.events
        return [e for e in events if e.sourceId not in lib]

    def case_event_count(self) -> int:
        with self.lock:
            return sum(self.sources[s].events for s in self.case_source_ids())

    def reset(self, delete_files: bool = True) -> None:
        """Clear the in-memory CASE. delete_files=True also removes the active case's uploads (POST
        /api/case/reset); False just drops the memory image (used when switching cases — files stay on
        disk). Library sources are never touched: they belong to no case, so no case operation may
        remove them from the pool."""
        with self.lock:
            self._clear_memory(delete_files, keep_library=True)
            self.name = "Untitled case"
            self.bump()

    def _clear_memory(self, delete_files: bool, keep_library: bool = False) -> None:
        """Drop the in-memory image. `keep_library` retains the case-less pool (sources + their events),
        which is what every CASE operation wants; only a full workspace reload (cases.startup) clears it,
        and it must, because restore_library() APPENDS just like restore() does."""
        with self.lock:
            keep = set(self.library_source_ids()) if keep_library else set()
            if not keep_library:
                # the whole pool is being rebuilt (startup / data-dir switch): skip records name files of
                # the OLD library, and a stale "missing from search" warning is its own kind of lie
                self.pool_skips.clear()
            if delete_files:
                for sid, path in self.source_paths.items():
                    if sid in keep:
                        continue
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
            self.sources = {k: v for k, v in self.sources.items() if k in keep}
            self.source_paths = {k: v for k, v in self.source_paths.items() if k in keep}
            self.source_member = {k: v for k, v in self.source_member.items() if k in keep}
            self.source_parsers = {k: v for k, v in self.source_parsers.items() if k in keep}
            self.source_origin = {k: v for k, v in self.source_origin.items() if k in keep}
            self.source_library = {k: v for k, v in self.source_library.items() if k in keep}
            self.source_prefix = {k: v for k, v in self.source_prefix.items() if k in keep}
            self.source_order = [s for s in self.source_order if s in keep]
            self.events = [e for e in self.events if e.sourceId in keep] if keep else []
            self.event_index = {}
            self.ts = np.zeros(0, dtype=np.float64)
            self._reindex()
            self.case_set = OrderedDict()
            self.notes: list[CaseNote] = []
            self.summary = ""
            self.skews = {k: v for k, v in self.skews.items() if k in keep}
            self.source_parse_errors = {k: v for k, v in self.source_parse_errors.items() if k in keep}
            self.unmapped_fields = 0
            self.rules_fired = 0
            self._entities_count = 0
            self._entities_version = -1
            self.case_set_rev += 1
            self._drop_derived()
            self.graph_links = []
            self.graph_nodes = []
            self._event_seq = 0
            self.source_id_base = {}

    def clear_all(self, reset_settings: bool = False) -> dict[str, int]:
        """Wipe the whole WORKSPACE — disk AND memory — and hand back a reserved (pending) case id.

        This used to clear only the ACTIVE case: it reset the in-memory case, deleted that one case's
        uploads and its case.json, and stopped. Everything else survived and a restart brought it all
        back — other cases with their uploads/notes/attachments, the deleted-case trash, the whole
        case-less library (bytes AND their parsed events, so search still returned hits), and jobs.json.
        Under the case-optional model the pool is the workspace, so a "clear all data" that cannot see
        `library/` (a sibling of `cases/`, invisible to `case_ids()`) clears almost nothing.

        Removed: every case directory (uploads, case.json, notes, attachments, case set, manual IOCs,
        graph links), cases/index.json, the trash, the library + its index, jobs.json, ai/history.json,
        the legacy single-case layout, the whole `cache/` tree (the persisted graph and the parsed-pool
        cache — both are derived FROM the evidence and quote it), every parsed event in the pool and
        the search index built over it.
        Deliberately KEPT: settings.json (unless reset_settings) and rules.json — detection rules are
        configuration, not evidence, and are cleared from Anomalies → Rules.

        The AI conversation history goes too, and that is not an afterthought: a transcript quotes the
        evidence verbatim, so leaving it behind would mean "clear all data" left copies of the log lines
        on disk — and history.json would repopulate the assistant panel on the next restart.
        """
        from . import cases as _cases  # local import: cases imports this module
        from .ai.history import HISTORY as AI_HISTORY
        from .jobs import REGISTRY

        with self.lock:
            n_sources = len(self.sources)
            n_events = len(self.events)
            # the pool is workspace-wide: keep_library=False is the whole point here
            self._clear_memory(delete_files=False, keep_library=False)
            self.manual_iocs = []
            self.pool_loading = False
            self.pool_pending = 0
            self.pool_loaded = 0
            self.pool_bytes_total = 0
            self.pool_bytes_done = 0
            self.pool_current_file = ""
            self.pool_plan.clear()
            self.pool_skips.clear()  # the staged files those skips named are about to be deleted
            self.name = "Untitled case"
            self.created_at = datetime.now(UTC)

        n_cases = len(_cases.case_ids())
        n_trash = len(_cases.list_trash())
        files = _wipe_tree(config.CASES_DIR)
        files += _wipe_tree(config.TRASH_DIR)
        files += _wipe_tree(config.LIBRARY_DIR)
        files += _wipe_tree(config.LEGACY_UPLOAD_DIR)
        # The whole cache tree, not only the graph pickles: derived caches (the graph aggregate, the
        # parsed-pool cache) are built FROM the evidence and quote it — a wipe that left them behind
        # would leave copies of the analyst's logs on disk and repopulate a screen after the restart.
        # The HMAC key goes with them; a new one costs one rebuild and nothing else.
        n_cache = _wipe_tree(config.CACHE_DIR)
        files += n_cache
        from . import sealed
        sealed.reset_key()          # the key file went with the tree; the next write makes a new one
        try:
            config.LEGACY_CASE_PATH.unlink(missing_ok=True)
        except OSError:
            pass
        n_jobs = REGISTRY.clear_all()
        n_ai = AI_HISTORY.clear_all()
        # A fresh id is reserved but nothing is written: /api/cases is [] and the UI shows "no active case".
        _cases._go_pending(_cases.next_id())
        with self.lock:
            if reset_settings:
                config.reset_settings()
                self.analyst = config.get_settings().analyst
        self.bump()  # drops the search index and the cached analysis over the events that just went away
        return {"sources": n_sources, "events": n_events, "files": files,
                "cases": n_cases, "trash": n_trash, "jobs": n_jobs, "aiRuns": n_ai, "cache": n_cache}

    @contextmanager
    def bulk_load(self):
        """Suppress the per-file detection re-run, search warm and case.json write during a bulk load.

        Every one of those is O(the whole pool); paying them once per restored file is what turned a
        589 MB library into minutes of 100% CPU. The caller runs _run_detections() + bump() once at the end.
        """
        with self.lock:
            self._bulk += 1
        try:
            yield
        finally:
            with self.lock:
                self._bulk = max(0, self._bulk - 1)
                last = self._bulk == 0
            if last:
                self._flush_pending()      # whatever the last batch left behind lands now

    def _drop_derived(self) -> None:
        """Release the cached graph / analysis / anomaly aggregation. Version keying already makes them
        unreachable after a bump; this frees the memory at once instead of at the next build, which
        matters when the caller is a wipe or a case switch (the anomaly rows hold sample Events, which
        would otherwise keep a handful of the wiped pool's events alive)."""
        try:
            from .anomalies import ANOMALY_CACHE
            from .correlate import ANALYSIS_CACHE
            from .graph import GRAPH_CACHE
            ANALYSIS_CACHE.invalidate()
            GRAPH_CACHE.invalidate()
            ANOMALY_CACHE.invalidate()
        except Exception:
            pass

    def bump(self) -> None:
        self.version += 1
        self._drop_derived()
        if self._bulk:
            # a bulk load bumps the version (so caches miss) but skips the expensive tail
            return
        try:
            from . import search as _search  # local import to avoid a cycle
            _search.invalidate()
            self.warm_search_async()
        except Exception:
            pass
        self.save_meta()

    def install_index_signature_provider(self) -> None:
        """Let `search` ask this store what pool it is indexing, so EVERY warm path can use the
        on-disk index cache — including the one a query kicks off, which is the path that runs after
        a restart and the reason the cache file never appeared."""
        try:
            from . import search as _search
            _search.set_signature_provider(self._index_signature)
            # And the gate: `warm_search_async` checks the pause, but the warm a QUERY starts went
            # straight to `search.warm_async`, so during an enrichment run every query kicked off a
            # full re-pack that the next finished source threw away.
            _search.set_warm_gate(lambda: not self.derived_builds_paused())
        except Exception:
            pass

    def _index_signature(self) -> str:
        """Content key for the on-disk search index (see app/index_store.py). Computed on the warm
        thread, never on a request: it walks the SOURCE table, not the pool, but it still takes the
        store lock."""
        try:
            from . import index_store
            return index_store.signature(self)
        except Exception:
            return ""

    def warm_search_async(self) -> bool:
        """Start the background index warm — unless an ingest storm is in flight.

        Same reasoning as `derived_builds_paused()`, which this deliberately reuses. Rebuilding the packed
        index is a long PURE-PYTHON loop (~8 s per 1.2 M events, so ~75 s on an 11.4 M-event pool), and
        every source phase-2 enrichment finishes bumps the version and invalidates it — so the warm was
        building for 75 s, being thrown away 30-60 s later, and starting again, for the whole length of a
        multi-file enrichment run. That loop holds the GIL, which is what made `/api/health` measure 9.4 s
        and `/api/library` 21-69 s on the analyst's pool: the process was GIL-starved, not lock-blocked.

        Skipping is SAFE because nothing depends on the index existing: `search()` calls `index_ready()`,
        which never builds and answers from the scan path (`engine: 'cpu'`) when the index is missing or
        stale. So a search during enrichment is slower, never wrong. The warm that matters is the ONE
        after the storm, which `EnrichQueue` triggers when its queue drains and any search triggers anyway.

        Returns True if a warm was scheduled.
        """
        from . import search as _search  # local import to avoid a cycle
        if self.derived_builds_paused():
            return False
        _search.warm_async(lambda: (self.events, self.ts, self.version, self._index_signature()))
        return True

    # ---------------------------------------------------------- persistence
    def snapshot(self) -> CaseSnapshot:
        """Totals for the case detail screen — the CASE's own sources only, never the library pool.
        Persisted so an INACTIVE case can still report them."""
        with self.lock:
            if not self.case_source_ids():
                # no case sources: every number below is 0 and case_events() would still walk the whole
                # pool to prove it. save_meta() calls this on every write.
                # `events` is the CASE's count, so it is 0 here. Reporting len(self.events) made a
                # brand-new case display the whole workspace pool as its own event total — the case
                # looked like it had swallowed every ingested log the moment it was created.
                return CaseSnapshot(events=0, sev={}, range=None, clusters=0,
                                    detections=0, entities=0)
        events = self.case_events()
        a = self.cached_analysis()   # only if already built — snapshot() must never trigger one
        with self.lock:
            sev: dict[str, int] = {}
            for e in events:
                sev[e.sev] = sev.get(e.sev, 0) + 1
            rng = (events[0].ts, events[-1].ts) if events else None
            detections = sum(len(e.detections) for e in events)
            clusters = len(a["clusters"]) if a else 0
            entities = len({x for e in events for x in e.entities})
            # len(events), not len(self.events): every other field here is computed over the case's own
            # events, so the total must be too — the pool belongs to the workspace, not to the case.
            return CaseSnapshot(events=len(events), sev=sev, range=rng, clusters=clusters,
                                detections=detections, entities=entities)

    def _materialise(self) -> None:
        """Promote a pending case to a real one on disk (called on the first genuine write)."""
        if self.pending:
            self.pending = False
            config.upload_dir(self.case_id).mkdir(parents=True, exist_ok=True)

    def save_meta(self) -> None:
        """Persist case metadata + source list so a restart (e.g. container recreate) can restore the case.

        REFUSES while a case switch is in flight. `activate` clears the in-memory case and then reads
        the new one back; anything that calls save_meta() in that window — the enrichment worker
        finishing a source, a detection pass bumping the version, an AI write — would serialise an EMPTY
        case set, empty notes and empty graph links over a case that has them, and nothing would ever
        put them back. The switch does its own save at the end, so nothing is lost by skipping here.
        """
        if self.pending:
            return  # nothing has been put in this case yet — do not create it on disk
        if self._switching:
            return  # a half-loaded store must never be allowed to overwrite the record on disk
        try:
            snap = self.snapshot().model_dump()
            with self.lock:
                # stamped while the state it describes is still locked — see _meta_seq in __init__
                self._meta_seq += 1
                seq = self._meta_seq
                meta = {
                    "case_id": self.case_id, "name": self.name, "summary": self.summary, "analyst": self.analyst,
                    "created_at": self.created_at.isoformat(), "updated_at": datetime.now(UTC).isoformat(),
                    "case_set": [e.model_dump() for e in self.case_set.values()],
                    "notes": [n.model_dump() for n in self.notes], "manual_iocs": list(self.manual_iocs), "graph_links": list(self.graph_links),
                    "graph_nodes": list(self.graph_nodes), "snapshot": snap,
                    "event_count": sum(self.sources[s].events for s in self.case_source_ids()),
                    "sources": [
                        {"id": sid, "file": self.sources[sid].file, "path": str(self.source_paths.get(sid, "")),
                         "events": self.sources[sid].events, "size": self.sources[sid].size,
                         "mapping": (list(self.source_parsers[sid].mapping)
                                     if isinstance(self.source_parsers.get(sid), DelimitedParser)
                                     and self.source_parsers[sid].mapping else None),
                         "delimiter": self.sources[sid].delimiter,
                         # where this source's event ids start — replayed on restore so the ids a case
                         # set cites are the ids the reload produces
                         "idBase": int(self.source_id_base.get(sid, 0)),
                         # the staged library file this source was attached from, and the event-id prefix
                         # it was parsed with — both must survive a restart or the same bytes would come
                         # back a second time (as a library source) with different event ids
                         "library": self.source_library.get(sid, ""),
                         "idPrefix": self.source_prefix.get(sid, "")}
                        # An archive we REFUSED to expand (password protected, bomb cap tripped) is a
                        # notice, not a source: persisting it would re-ingest the container as binary
                        # strings on the next restart. Library sources belong to no case and are
                        # persisted by the library index instead.
                        for sid in self.case_source_ids()
                        if not (self.sources[sid].parser == "archive" and self.sources[sid].state == "ERROR")
                    ],
                }
            # The path comes from the case id CAPTURED with the state above, never from
            # `self.case_path` — that is re-read after the lock is released, so an `activate()` landing
            # in between would write this case's contents into the NEXT case's case.json.
            cid = str(meta["case_id"])
            case_path = config.case_path(cid)
            with self._meta_write_lock:
                # Per CASE, because the guarantee that is wanted is per file: a save for the case just
                # switched away from must still land even though the new case has saved since.
                if seq <= self._meta_written.get(cid, 0):
                    # A save built AFTER this one already reached disk. Writing ours now would revert
                    # case.json to the older snapshot — losing case-set entries, notes, indicators or
                    # graph links added in between until the next write happens to put them back.
                    return
                self._write_meta_file(case_path, meta)
                self._meta_written[cid] = seq
        except OSError:
            pass

    def _write_meta_file(self, case_path: Path, meta: dict[str, Any]) -> None:
        """The disk half of save_meta. Call under `_meta_write_lock`."""
        try:
            if not case_path.parent.is_dir():
                # NEVER mkdir a case into existence here. Every legitimate caller already has a case
                # directory — `_materialise()` and `cases.create_case()` both create it — so a missing
                # one means the case was DELETED (its folder is in .trash/). This runs from background
                # threads too (`bump()` calls it, and phase-2 enrichment calls `bump()`), so a save
                # landing just after `delete_case` moved the folder brought `cases/<id>/case.json` back
                # and the deleted case reappeared in /api/cases. A delete is on purpose; honour it.
                return
            tmp = case_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(meta, indent=1), encoding="utf-8")
            tmp.replace(case_path)
        except OSError:
            pass

    def restore(self, case_id: Optional[str] = None) -> bool:
        """Rebuild the case from cases/<id>/case.json + saved uploads. Returns True if anything was restored."""
        with self.lock:
            if case_id:
                self.case_id = case_id
            case_path = self.case_path
        try:
            meta = json.loads(case_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        with self.lock:
            self.name = meta.get("name", self.name)
            self.summary = str(meta.get("summary") or "")
            self.analyst = meta.get("analyst", self.analyst)
            self.notes = _load_notes(meta.get("notes"))
            raw_links = meta.get("graph_links")
            self.graph_links = [l for l in raw_links if isinstance(l, dict) and l.get("source") and l.get("target")] if isinstance(raw_links, list) else []
            raw_nodes = meta.get("graph_nodes")
            self.graph_nodes = ([n for n in raw_nodes if isinstance(n, dict) and n.get("id")]
                                if isinstance(raw_nodes, list) else [])
            raw_iocs = meta.get("manual_iocs")
            self.manual_iocs = [i for i in raw_iocs if isinstance(i, dict) and i.get("value")] if isinstance(raw_iocs, list) else []
            try:
                self.created_at = datetime.fromisoformat(meta["created_at"])
            except (KeyError, ValueError):
                pass
        restored = False
        # ONE detection pass and ONE index warm for the whole case, not one per file
        with self.bulk_load():
            for src in meta.get("sources", []):
                raw = str(src.get("path") or "")
                path = Path(raw)
                # case.json is data, not code: an absolute path in it is only trusted when it stays
                # inside the data dir. Nothing in the API writes this field today, but one write
                # primitive away it would be "read any file on the host into the searchable pool".
                # Outside the data dir it falls through to the by-basename resolve below, which can
                # only ever land in this case's own uploads/ directory.
                if path.is_absolute() and not _under_data_dir(path):
                    path = Path("")
                if not path.is_file():
                    # Resolve by file name instead. Split on BOTH separators: a case.json written on Windows
                    # holds "D:\...\uploads\x.log", and Path(...).name on Linux would return that whole string,
                    # so the same data dir bind-mounted into the container would restore zero sources.
                    name = raw.replace("\\", "/").rsplit("/", 1)[-1]
                    cand = self.upload_dir / name if name else None
                    if cand is None or not cand.is_file():
                        continue
                    path = cand
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                # Replay the id base this source was parsed with, so `e4` comes back as `e4`. Restore
                # is sequential and holds no other writer, so setting the counter here is enough — the
                # assignment itself takes the store lock a moment later.
                try:
                    id_base = int(src.get("idBase") or 0)
                except (TypeError, ValueError):
                    id_base = 0
                if id_base:
                    with self.lock:
                        self._event_seq = max(self._event_seq, id_base)
                self.add_file(src["file"], data, background_ok=False, sid=src.get("id"), path=path,
                              library_name=str(src.get("library") or ""), id_prefix=str(src.get("idPrefix") or ""))
                del data  # the parsed events are the copy that matters; do not hold the raw bytes as well
                if src.get("mapping"):
                    try:
                        self.remap_source(src["id"], src["mapping"], src.get("delimiter"))
                    except Exception:
                        pass
                restored = True
        with self.lock:
            self.case_set = OrderedDict()
            for raw in meta.get("case_set") or []:
                try:
                    entry = CaseSetEntry.model_validate(raw)
                except Exception:
                    continue
                # KEEP IT even when the event is not (yet) in the pool. This line used to be
                # `if entry.eventId in self.event_index`, and `save_meta()` runs a few lines below — so a
                # reload in which the ids came out different silently deleted the analyst's timeline AND
                # WROTE THAT BACK, permanently. Reported as "when viewing a case, and leaving, the
                # timeline events disappear and do not show up again", and the same for the graph.
                # A curated entry is the ANALYST'S record, not a view of the pool: it survives a source
                # being removed, a re-parse, a restart. The screens already render an entry whose event
                # cannot be resolved as "event not in the pool", which is the honest answer; deleting it
                # is not.
                self.case_set[entry.eventId] = entry
            # migrate the pre-case-set format: a bare list of pinned event ids
            for eid in meta.get("pinned") or []:
                if isinstance(eid, str) and eid in self.event_index and eid not in self.case_set:
                    self.case_set[eid] = CaseSetEntry(eventId=eid, addedAt=to_iso(self.created_at))
        self._reanchor_case_set()
        self.save_meta()
        return restored

    def _reanchor_case_set(self) -> int:
        """Re-point curated entries at the LINE they were anchored to, whenever their id has drifted.

        Event ids are assigned from a counter that depends on what else is in the pool, so the same
        file re-parsed in a different order comes back with different ids. Two things go wrong, and the
        second is worse than the first:
          • the id no longer exists — the timeline entry points at nothing (and used to be silently
            deleted, and the deletion written back: "the timeline events disappear and do not show up
            again");
          • the id exists but now belongs to a DIFFERENT line. Measured in the reproduction: the entry
            cited `e4`, the reload gave `e4` to the CSV header row, and the entry resolved cleanly to
            the wrong evidence. In a forensics tool that is the worse failure by far — nothing looks
            broken.
        So the anchor is authoritative: `file` + a hash of the raw text is what the entry MEANS, and
        the id is a pointer that may go stale or be reused. Every entry whose pointer disagrees with
        its anchor is re-pointed. One pass over the pool, only when something actually disagrees.

        An entry whose line is genuinely gone (its source was deleted) is LEFT ALONE — the analyst
        curated it, and the screens say "event not in the pool" rather than dropping it.
        """
        with self.lock:
            drifted = []
            for entry in self.case_set.values():
                if not entry.rawHash:
                    continue                      # written before anchors existed; nothing to check
                ev = self.event(entry.eventId)
                if ev is None or raw_hash(ev.raw) != entry.rawHash:
                    drifted.append(entry)
            if not drifted:
                return 0
            wanted = {(e.file, e.rawHash) for e in drifted}
            files = {e.file for e in drifted}
            found: dict[tuple[str, str], str] = {}
            for ev in self.events:
                if ev.file not in files:
                    continue
                key = (ev.file, raw_hash(ev.raw))
                if key in wanted and key not in found:
                    found[key] = ev.id
                    if len(found) == len(wanted):
                        break
            if not found:
                return 0
            rebuilt: "OrderedDict[str, CaseSetEntry]" = OrderedDict()
            healed = 0
            for entry in self.case_set.values():
                new_id = found.get((entry.file, entry.rawHash)) if entry in drifted else None
                if new_id and new_id != entry.eventId and new_id not in rebuilt:
                    rebuilt[new_id] = entry.model_copy(update={"eventId": new_id})
                    healed += 1
                elif entry.eventId not in rebuilt:
                    rebuilt[entry.eventId] = entry
            self.case_set = rebuilt
            self.case_set_rev += 1
        if healed:
            print(f"[iris] case timeline: re-anchored {healed} entr{'y' if healed == 1 else 'ies'} "
                  f"whose event ids had moved", flush=True)
        return healed

    def library_sid(file_name: str) -> str:
        """The source id of a staged library file.

        Library files are stored as "<8 hex>_<sanitized name>", so the id is DERIVED from the name rather
        than allocated: the same file gets the same sid (and therefore the same event ids) on every
        restart, which is what makes restore_library() idempotent and an attach non-duplicating.
        """
        head = file_name.partition("_")[0]
        if len(head) == 8 and all(ch in "0123456789abcdef" for ch in head.lower()):
            return head.lower()
        return uuid.uuid5(uuid.NAMESPACE_URL, f"iris-library/{file_name}").hex[:8]

    @classmethod
    def _member_sid(cls, file_name: str, index: int) -> str:
        """Source id of the index-th member of a staged container (index 0 == the file itself)."""
        if index == 0:
            return cls.library_sid(file_name)
        return uuid.uuid5(uuid.NAMESPACE_URL, f"iris-library/{file_name}#{index}").hex[:8]

    def _add_library_members(self, name: str, display: str, data: Optional[bytes],
                             background_ok: bool) -> list[Source]:
        """Parse a staged library file (expanding containers) into the pool as library-origin sources.

        Deterministic: member order and per-member ids come from the file name + index, so a restart
        rebuilds exactly the same sources with exactly the same event ids — which is what lets
        restore_library() skip work instead of duplicating it.

        `data=None` is the streaming path and the one that matters for a big upload: the container is
        expanded FROM DISK (`archives.expand_path`), and a file that is not a container at all is never
        read here — it comes back `passthrough` and `add_file` streams it. The 3.35 GB capture bundle is
        why: `expand(filename, data)` cannot look at the first member without the whole archive in RAM.
        """
        path = config.LIBRARY_DIR / name
        if data is None:
            expanded = archives.expand_path(display or name, path)
        else:
            expanded = self.expand_upload_ex(display or name, data)
        members = expanded.members
        if expanded.errors:
            # a container Iris refuses to open stays a staged blob: parsing it as binary strings would
            # put noise in the pool. It is still attachable, where ingest reports the refusal properly.
            return []
        out: list[Source] = []
        if expanded.passthrough:
            # not a container: this file IS the single source, and its bytes stay on disk
            sid = self._member_sid(name, 0)
            with self.lock:
                exists = sid in self.sources
            if exists:
                return []
            src = self.add_file(display or name, None, background_ok=background_ok, sid=sid, path=path,
                                origin="library", library_name=name, id_prefix=f"l{sid}")
            pool_store.save_manifest(name, [src.id])
            return [src]
        for i, (member_name, blob) in enumerate(members):
            sid = self._member_sid(name, i)
            with self.lock:
                if sid in self.sources:
                    continue
            # A single member carrying the file's own name is the file itself (the byte path's way of
            # saying "not a container"); anything else is a real member and records where it came from
            # so `source_bytes` can read it back out of the container instead of re-reading the archive.
            is_self = len(members) == 1 and member_name == (display or name)
            out.append(self.add_file(member_name, blob, background_ok=background_ok, sid=sid, path=path,
                                     origin="library", library_name=name, id_prefix=f"l{sid}",
                                     member="" if is_self else member_name))
        if out:
            # Which members this file expands into. Written here because this is the only place that
            # knows: an archive's member list needs the archive expanded, which is what a cache HIT
            # exists to avoid doing again.
            pool_store.save_manifest(name, [s.id for s in out])
        return out

    def source_bytes(self, sid: str) -> bytes:
        """The bytes of THIS source — never its container's.

        Everything that re-reads a source (phase 2, a remap, the raw viewer, field suggestions) used to
        do `source_paths[sid].read_bytes()`, which is right for every source except one: a member of a
        library-staged archive, whose recorded path is the archive. `tests/test_archive_members.py`
        pins what that cost — 20 clean syslog lines replaced by 21 lines of decoded zip binary, on a
        source still reporting READY / enriched.

        Reading the member back out of the container is also the BOUNDED thing to do: one member is
        capped at `archives.MAX_MEMBER_BYTES`, while the container it lives in is not capped at all.
        """
        with self.lock:
            path = self.source_paths.get(sid)
            member = self.source_member.get(sid, "")
        if path is None:
            raise FileNotFoundError(f"source {sid} has no file on disk")
        if not member:
            return path.read_bytes()
        return archives.read_member(path, member)

    def source_head(self, sid: str, limit: int) -> bytes:
        """A bounded prefix of `source_bytes`, for callers that only sniff (field suggestions, a binary
        check). A member is still read whole — a container cannot be sliced — but it is one member."""
        with self.lock:
            path = self.source_paths.get(sid)
            member = self.source_member.get(sid, "")
        if path is None:
            raise FileNotFoundError(f"source {sid} has no file on disk")
        if member:
            return archives.read_member(path, member)[:limit]
        with open(path, "rb") as fh:
            return fh.read(limit)

    def _room_for(self, source_bytes: int) -> bool:
        """Is there live memory for a source of this size? Never blocks a small file.

        The estimate is MEASURED on the pool already loaded (`pool_bytes_per_source_byte`), so it
        reflects what this corpus actually costs rather than a global average — the difference
        between "this 1.1 GB export needs 57 GB" and "it needs about 4.6". Files below the floor are
        never refused: the check exists for the handful that can kill the process, and a workspace of
        small logs must not become a wall of skip notices.
        """
        if source_bytes < _MEMORY_CHECK_MIN:
            return True
        head = pool_headroom_bytes()
        if head <= 0:
            return True          # no psutil, no answer — never refuse on a number we do not have
        return source_bytes <= head

    def _install_cached_library_file(self, name: str, display: str, path: Path) -> Optional[list[Source]]:
        """Put a staged file's members straight into the pool from the cache. None = no usable entry.

        This is the whole point of `pool_store`: no read of the file, no parse, no normalization, and
        — because the cached sources come back `enriched`/`skipped` — no phase-2 queue either. The
        registrations below mirror `add_file` exactly; anything it sets and this does not is a source
        that behaves subtly differently from a parsed one, which is the failure mode to watch for.
        """
        try:
            members = pool_store.load(name)
        except Exception as exc:  # noqa: BLE001 — a cache may never break a library load
            print(f"[iris] pool cache: {name} failed to load ({type(exc).__name__}: {exc}); parsing it")
            return None
        if not members:
            return None
        from .parsers.registry import parser_by_name

        out: list[Source] = []
        events: list[Event] = []
        for src, evs, errors in members:
            parser = parser_by_name(src.parser)
            if parser is None:
                # The parser that produced these events is not in this build. Re-parse rather than
                # serve events nothing can now explain, remap or re-enrich.
                print(f"[iris] pool cache: {name} was parsed by {src.parser!r}, which this build does "
                      f"not have; parsing it again")
                return None
            with self.lock:
                if src.id in self.sources:
                    continue
                self.sources[src.id] = src
                self.source_paths[src.id] = path
                self.source_parsers[src.id] = parser
                self.source_origin[src.id] = "library"
                self.source_library[src.id] = name
                self.source_prefix[src.id] = f"l{src.id}"
                self.source_parse_errors[src.id] = errors
                self.source_order.append(src.id)
            out.append(src)
            events.extend(evs)
        if not out:
            return None
        if events:
            self._append_events(events)
        return out

    def restore_library(self, entries: Optional[list[tuple[str, str]]] = None) -> int:
        """Parse staged library files into the pool. Returns the number of sources added.

        APPENDS, exactly like restore(): it is only safe because it skips every library file that is
        already represented in memory — either as a library source or as a case source it was attached
        to (`source_library` keeps the link across the attach). Calling it twice adds nothing.

        `entries` is [(on-disk name, display name)]; it defaults to reading the library index.
        """
        rows = entries if entries is not None else self._library_todo()
        added = 0
        from_cache = 0
        # Entries whose staged file is gone can never be read again — on this workspace one of them is
        # 3.3 GB. Swept here because this is the one place that runs when the library is known and
        # settled, and it costs a directory listing.
        try:
            dropped = pool_store.prune()
            if dropped:
                print(f"[iris] pool cache: removed {dropped} orphaned entr{'y' if dropped == 1 else 'ies'}")
        except Exception:  # noqa: BLE001 — housekeeping may never break a load
            pass
        with self.bulk_load():
            for name, display in rows:
                with self.lock:
                    if name in set(self.source_library.values()):
                        continue  # already in the pool (staged, or attached to the active case)
                    self.pool_current_file = display or name
                    self._plan_state(name, "parsing")
                path = config.LIBRARY_DIR / name
                if not path.is_file():
                    with self.lock:
                        self.pool_pending = max(0, self.pool_pending - 1)
                        self._plan_state(name, "error")
                    continue
                # Can this machine hold it AT ALL, right now? Loading a file the box cannot back does
                # not fail politely: the allocation lands, the VM cannot page it, and the process dies
                # with SIGSEGV — taking every other loaded source with it and coming back to do the
                # same thing again. Seen live on an 11.4 M-event workspace: a crash LOOP in which the
                # app was never usable long enough to delete a case. A refusal that names the file and
                # offers "load it anyway" is the honest form of the same limit.
                size = self._library_size(name)
                if not self._room_for(size):
                    need = int(size * self.pool_bytes_per_source_byte()[0])
                    self.note_pool_skip(
                        name, display, size, "memory",
                        f"needs about {need // (1 << 20)} MB of memory and this machine has "
                        f"{pool_headroom_bytes() * self.pool_bytes_per_source_byte()[0] // (1 << 20)} MB "
                        f"free — its events are NOT searchable. Free memory (or close other work) and "
                        f"load it from Sources.")
                    with self.lock:
                        self.pool_pending = max(0, self.pool_pending - 1)
                        self._plan_state(name, "skipped", size=size)
                    continue
                # The parsed pool from last time, if this exact file was cached by this build. It is
                # checked BEFORE the bytes are read: on a hit the file is never opened at all, which
                # is most of the win on a 1.76 GB library. See app/pool_store.py.
                cached = self._install_cached_library_file(name, display, path)
                if cached is not None:
                    added += len(cached)
                    from_cache += len(cached)
                    with self.lock:
                        self.pool_pending = max(0, self.pool_pending - 1)
                        self.pool_loaded += 1
                        self.pool_bytes_done += self._library_size(name)
                        self.pool_current_file = ""
                        self._plan_state(name, "done", size=self._library_size(name),
                                         events=sum(s.events for s in cached))
                    continue
                try:
                    # The file is NOT read here any more — a restart used to pull every staged log into
                    # memory whole, and this library is 4.9 GB. Prove it is readable and take its size;
                    # `_add_library_members` streams the rest (or reads one archive member at a time).
                    nbytes = path.stat().st_size
                    with open(path, "rb") as probe:
                        probe.read(1)
                except OSError as exc:
                    # not a budget problem and not a parser problem — the bytes themselves are unreachable.
                    # Reported as its own reason, because the fix is on disk, not in the settings.
                    self.note_pool_skip(name, display, 0, "unreadable",
                                        f"could not be read from the library on disk ({config.safe_os_error(exc)}) — its events are NOT searchable")
                    with self.lock:
                        self.pool_pending = max(0, self.pool_pending - 1)
                        self._plan_state(name, "error")
                    continue
                sids = self._add_library_members(name, display, None, background_ok=False)
                added += len(sids)
                with self.lock:
                    self.pool_pending = max(0, self.pool_pending - 1)
                    self.pool_loaded += 1
                    self.pool_bytes_done += nbytes
                    self.pool_current_file = ""
                    self._plan_state(name, "done", size=nbytes, events=sum(s.events for s in sids))
        if from_cache:
            # Restored events carry the detections they were saved with, so the tally has to include
            # them. It is counted here, after the bulk buffer has flushed — inside the loop the events
            # are still in `_pending` and `self.events` would tally to zero. The caller's single
            # `_run_detections()` pass re-stamps everything anyway (that is also what corrects a
            # detection whose RULE changed since the file was cached); this keeps the count honest for
            # a caller that does not run one.
            with self.lock:
                self.rules_fired = sum(len(e.detections) for e in self.events)
        return added

    @staticmethod
    def _library_size(name: str) -> int:
        try:
            return (config.LIBRARY_DIR / name).stat().st_size
        except OSError:
            return 0

    def _library_todo(self) -> list[tuple[str, str]]:
        """Staged files that are not already in the pool, in library-index order."""
        from .routers.library import library_entries  # local import: routers import the store

        with self.lock:
            have = set(self.source_library.values())
        return [(name, display) for name, display in library_entries() if name not in have]

    def load_library(self, background_ok: bool = True) -> bool:
        """Bring the case-less pool up to date. Returns True when the work was handed to a thread.

        Startup calls this. The pool has NO size ceiling — a real library held 589 MB across ~40 files —
        and cases.startup() runs inside the FastAPI lifespan, so parsing inline there meant /api/health
        never answered and the container went `unhealthy`. Anything over LIBRARY_SYNC_LIMIT therefore
        loads in a daemon thread while the API serves requests; `pool_loading` / `pool_pending` report it.
        """
        rows = self._library_todo()
        if not rows:
            return False
        budget = pool_budget_bytes()
        total = 0
        take: list[tuple[str, str]] = []
        # WHICH files were left out, not just how many: these are usually the biggest logs in the library
        # (on the real one, 2 files of 263 MB out of 61), and a file missing from search is indistinguishable
        # from a search that legitimately found nothing.
        skips: "OrderedDict[str, PoolSkip]" = OrderedDict()
        for name, display in rows:
            try:
                size = (config.LIBRARY_DIR / name).stat().st_size
            except OSError:
                size = 0
            if budget and total + size > budget and take:
                skips[name] = PoolSkip(
                    fileName=name, displayName=display or name, size=size, reason="budget",
                    budgetBytes=budget, usedBytes=total,
                    detail=(f"{size / 1e6:.0f} MB would take the workspace pool past its {budget / 1e6:.0f} MB "
                            f"memory budget ({total / 1e6:.0f} MB already loaded). Its events are NOT searchable. "
                            f"Raise IRIS_POOL_MAX_MB (0 = unlimited) or remove other sources, then load it."))
                continue
            take.append((name, display))
            total += size
        rows = take
        with self.lock:
            self.pool_skips = skips
            self.pool_plan = OrderedDict(
                (name, {"file": display or name, "size": self._library_size(name), "state": "pending", "events": 0})
                for name, display in rows)
            self.pool_pending = len(rows)
            self.pool_loaded = 0
            self.pool_loading = True
            self.pool_bytes_total = total
            self.pool_bytes_done = 0
            self.pool_current_file = ""
            self.pool_started_ts = time.time()
        if skips:
            print(f"[iris] {len(skips)} library file(s) left unparsed: the case-less pool is capped at "
                  f"{budget / 1e6:.0f} MB of log (IRIS_POOL_MAX_MB). Not searchable until loaded: "
                  + ", ".join(f"{s.displayName} ({s.size / 1e6:.0f} MB)" for s in skips.values()))

        def run() -> None:
            try:
                self.restore_library(rows)
            except Exception as exc:  # a corrupt staged file must never take the workspace down
                print(f"[iris] library pool load failed: {exc}")
            finally:
                with self._detect_lock:
                    self._run_detections()      # O(pool): never under self.lock, see _detect_lock
                with self.lock:
                    self.pool_loading = False
                    self.pool_pending = 0
                    self.pool_current_file = ""
                    self.pool_bytes_done = self.pool_bytes_total
                self.bump()

        if background_ok and total > LIBRARY_SYNC_LIMIT:
            print(f"[iris] loading {len(rows)} library file(s) ({total / 1e6:.0f} MB) in the background")
            threading.Thread(target=run, daemon=True).start()
            return True
        run()
        return False

    def load_pool_file(self, name: str, display: str = "") -> list[Source]:
        """Parse ONE staged library file into the pool NOW, ignoring the startup budget.

        The deliberate escape hatch behind POST /api/library/unattached/{name}/load: the budget is a
        machine-wide guess, and the analyst may need exactly the file it skipped. Callers must do the
        memory sanity check (`pool_headroom_bytes`) first — this method only refuses to pretend, so if
        the parse fails the source lands in the pool in state ERROR carrying the reason.
        """
        path = config.LIBRARY_DIR / Path(name).name
        with open(path, "rb") as probe:   # OSError is the caller's to report, before anything changes
            probe.read(1)
        with self.bulk_load():
            added = self._add_library_members(path.name, display or path.name, None, background_ok=True)
        self.clear_pool_skip(path.name)
        with self._detect_lock:
            self._run_detections()
        self.bump()
        return added

    def add_library_file(self, name: str, display: str, data: "Optional[bytes]" = None) -> list[Source]:
        """Parse a freshly staged library file into the pool (the bytes are already on disk).

        Never materialises a case and never writes into cases/ — that guarantee is the whole point of
        staging: an upload must not conjure a case the analyst did not create.

        `data` is optional and callers should leave it out: the bytes ARE on disk by the time this runs,
        so handing them in as well is a second full copy of the upload for no benefit. It stays
        accepted for the callers that legitimately hold bytes with no file behind them (tests).
        """
        return self._add_library_members(name, display, data, background_ok=True)

    def attach_library_source(self, name: str) -> list[Source]:
        """Attach a staged library file to the ACTIVE case, MOVING it inside the pool rather than
        re-parsing it.

        The events already exist and keep their ids: the source's origin flips to 'case' and a copy of the
        bytes is written into the case's uploads so the case stays self-contained on disk. Re-parsing here
        is what would double-count the file, so it must never happen. Returns [] when the file is not in
        the pool (an archive, or a file staged by an older build), and the caller falls back to ingest.
        """
        with self.lock:
            mine = [s for s in self.source_order if self.source_library.get(s) == name]
            # already attached to THIS case: attaching again is a no-op, not a second copy
            if mine and all(self.source_origin.get(s) == "case" for s in mine):
                return [self.sources[s] for s in mine]
            sids = [s for s in mine if self.source_origin.get(s) == "library"]
            if not sids:
                return []
        self._materialise()
        out: list[Source] = []
        # every member of a staged container shares one file on disk, so the bytes are copied ONCE
        dest = self.upload_dir / name
        staged = config.LIBRARY_DIR / name
        try:
            self.upload_dir.mkdir(parents=True, exist_ok=True)
            if staged.is_file():
                dest.write_bytes(staged.read_bytes())
            else:
                dest = staged
        except OSError:
            dest = staged
        for sid in sids:
            src = self.sources[sid]
            with self.lock:
                self.source_origin[sid] = "case"
                self.source_paths[sid] = dest
                # source_library[sid] stays: it is what stops restore_library() re-adding these bytes
            out.append(src)
        with self.lock:
            self.bump()
        return out

    def _stage_into_library(self, sid: str) -> str:
        """Copy a case upload into `library/` so it can be detached, and register it.

        The name follows the staging convention `<8 hex>_<sanitized>` because `library_sid()` DERIVES the
        source id from it — a random prefix here would give the file a different identity on every
        restart. The bytes are copied rather than moved: the copy under `cases/<id>/uploads/` is removed
        by detach_case_source once nothing reads it, and a failure part-way must never leave the case
        pointing at a file that is no longer there.
        """
        with self.lock:
            src = self.sources.get(sid)
            path = self.source_paths.get(sid)
        if src is None or path is None or not Path(path).is_file():
            return ""
        original = Path(src.file).name or "upload.log"
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", original) or "upload.log"
        name = f"{uuid.uuid4().hex[:8]}_{safe}"
        config.LIBRARY_DIR.mkdir(parents=True, exist_ok=True)
        target = config.LIBRARY_DIR / name
        try:
            shutil.copy2(path, target)
        except OSError:
            return ""
        # The library index is what gives a staged file its display name and upload time; without an
        # entry the Sources page would show the sanitized on-disk name instead.
        try:
            idx = {}
            if config.LIBRARY_INDEX.is_file():
                loaded = json.loads(config.LIBRARY_INDEX.read_text(encoding="utf-8"))
                idx = loaded if isinstance(loaded, dict) else {}
            idx[name] = {"file": original, "size": target.stat().st_size,
                         "uploadedAt": to_iso(datetime.now(UTC))}
            tmp = config.LIBRARY_INDEX.with_suffix(".tmp")
            tmp.write_text(json.dumps(idx, indent=2), encoding="utf-8")
            tmp.replace(config.LIBRARY_INDEX)
        except (OSError, ValueError):
            pass  # the file is staged either way; only its pretty name is lost
        with self.lock:
            self.source_library[sid] = name
        return name

    def detach_case_source(self, sid: str) -> list[Source]:
        """The inverse of attach_library_source: take a source back OUT of the case and leave it in the
        case-less pool.

        Scoping a case is a choice the analyst makes in both directions, so "add this pool source" needs
        an "and take it back out" that is not a delete: the events stay in the pool (same ids, no
        re-parse, nothing removed from search), only the case's claim on them goes away. The case's copy
        of the bytes is removed once no source reads from it any more; the staged library file — which is
        the copy that survives every case delete — is left alone.

        A source ATTACHED FROM the library detaches straight back: its bytes are still staged and its
        event ids carry the persisted `l<sid>` prefix, so it comes back identically after a restart.

        A file UPLOADED STRAIGHT INTO the case has no case-less copy, and refusing there left the analyst
        with only one way out of a mis-filed upload: delete the evidence. So the bytes are STAGED into
        the library first (`_stage_into_library`) and the same detach then runs. Nothing is re-parsed and
        no event id changes in this process; on the next restart the file is restored as a library source
        and its ids take the `l<sid>` form, exactly as if it had been uploaded to the library — which is
        what it now is. Returns [] only when the bytes are gone.
        """
        with self.lock:
            if sid not in self.sources or self.source_origin.get(sid) != "case":
                return []
            name = self.source_library.get(sid) or ""
        if not name or not (config.LIBRARY_DIR / name).is_file():
            name = self._stage_into_library(sid)
        if not name or not (config.LIBRARY_DIR / name).is_file():
            return []
        # every member of an expanded container shares one staged file — detach them together, or the
        # case would keep half a container and restore_library() would find the other half already in memory
        with self.lock:
            sids = [s for s in self.source_order
                    if self.source_library.get(s) == name and self.source_origin.get(s) == "case"]
        staged = config.LIBRARY_DIR / name
        out: list[Source] = []
        for s in sids:
            with self.lock:
                old = self.source_paths.get(s)
                self.source_origin[s] = "library"
                self.source_paths[s] = staged
                out.append(self.sources[s])
            if old is not None and old != staged:
                with self.lock:
                    still_used = any(p == old for p in self.source_paths.values())
                if not still_used:
                    try:
                        old.unlink(missing_ok=True)
                    except OSError:
                        pass
        with self.lock:
            # curated entries pointing at events that are no longer the case's own sources are still
            # valid — the case set is a selection over the whole pool — so it is deliberately untouched
            self.bump()
        self.save_meta()
        return out

    # -------------------------------------------------------------- ingest
    @staticmethod
    def expand_upload(filename: str, data: bytes) -> list[tuple[str, bytes]]:
        """Members of an uploaded container, or the file itself. See parsers.archives.expand.

        Kept for callers that only want the bytes; anything user-facing should use expand_upload_ex so a
        password-protected / bombed / traversing archive can be reported instead of silently ingesting
        nothing.
        """
        return archives.expand(filename, data).members

    @staticmethod
    def expand_upload_ex(filename: str, data: bytes) -> "archives.Expanded":
        """Expansion WITH the problems: encrypted archives, zip-slip members and tripped bomb caps.

        Member names carry provenance — `incident.zip!var/log/auth.log` — so Source.file / Event.file show
        which archive (and which path inside it) a line came from.
        """
        return archives.expand(filename, data)

    def ingest_upload(self, filename: str, data: bytes) -> list[Source]:
        """Expand a container, ingest what came out, and surface what did NOT as an ERROR source.

        The single entry point for user-facing ingest (POST /api/sources, POST /api/library/attach): an
        archive that is password protected, tripped the zip-bomb caps, tried to escape its root or needs an
        optional package Iris does not have becomes an ERROR source carrying the explanation, so the
        analyst sees why nothing was ingested instead of an empty upload.
        """
        expanded = self.expand_upload_ex(filename, data)
        members = expanded.members
        if expanded.errors:
            # A container we could not open comes back as itself; ingesting that as binary strings on top
            # of the ERROR notice would just be noise.
            members = [(n, b) for n, b in members if not (n == filename and b is data)]
        out = [self.add_file(name, blob) for name, blob in members]
        if expanded.errors:
            out.append(self.add_error_source(filename, data, " ".join(expanded.errors)[:2000]))
        return out

    def ingest_upload_path(self, filename: str, staged: Path) -> list[Source]:
        """`ingest_upload` starting from bytes ALREADY ON DISK, which is where an upload now lands.

        Same contract: expand the container, ingest what came out, and surface what did NOT as an ERROR
        source. What changes is that a file which is not a container is never read — it is already at
        `staged`, so the source simply points there and phase 1 streams it. `expand_path` answers "is
        this an archive?" from a 64 KB head, so deciding that a 1.9 GB capture is not one costs 64 KB.
        """
        expanded = archives.expand_path(filename, staged)
        if expanded.passthrough:
            return [self.add_file(filename, None, path=staged)]
        members = expanded.members
        if expanded.errors:
            # A container we could not open comes back as itself; ingesting that as binary strings on
            # top of the ERROR notice would just be noise.
            members = [(n, b) for n, b in members if n != filename]
        out = [self.add_file(name, blob) for name, blob in members]
        if expanded.errors:
            # the refusal names the file the analyst uploaded, and its bytes stay where they were staged
            out.append(self.add_error_source(filename, None, " ".join(expanded.errors)[:2000], path=staged))
        elif not out:
            # an empty container: keep the upload visible rather than reporting nothing at all
            out = [self.add_file(filename, None, path=staged)]
        else:
            # the members were written to their own files; the staged copy has no reader left
            staged.unlink(missing_ok=True)
        return out

    def add_error_source(self, filename: str, data: Optional[bytes], message: str,
                         path: Optional[Path] = None) -> Source:
        """Register a source that could NOT be ingested, so the failure is visible in the UI.

        Used for archives Iris refuses to expand (password protected, bomb caps tripped, unsupported
        format). The original bytes are still written to the case so the analyst can download them.
        """
        self._materialise()
        sid = uuid.uuid4().hex[:8]
        if path is None:
            path = self.upload_dir / f"{sid}_{re.sub(r'[^A-Za-z0-9._-]', '_', filename)}"
            try:
                self.upload_dir.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data or b"")
            except OSError:
                pass
        if data is None:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
        else:
            size = len(data)
        src = Source(id=sid, file=filename, parser="archive", events=0, range=None, confidence=0.0,
                     state="ERROR", size=size, sample=f"<{size:,} bytes>", error=message)
        with self.lock:
            self.sources[sid] = src
            self.source_paths[sid] = path
            self.source_origin[sid] = "case"
            self.source_order.append(sid)
            self.bump()
        return src

    def add_file(self, filename: str, data: Optional[bytes] = None, background_ok: bool = True,
                 sid: Optional[str] = None, path: Optional[Path] = None, origin: str = "case",
                 library_name: str = "", id_prefix: str = "", member: str = "") -> Source:
        """Register and parse a raw file into the pool. Files above SYNC_LIMIT parse in a background thread.

        origin='library' means the bytes live in $IRIS_DATA_DIR/library/ and belong to no case: the source
        is parsed and searchable, but it is never written into case.json and a pending case stays pending.

        **`data=None` means "the bytes are the file at `path`"** and is how a large upload avoids ever
        existing in memory: the sniff reads a bounded head, the size comes from `stat()`, and phase 1
        streams the file a chunk at a time. Pass `data` only when the caller genuinely holds bytes that
        are NOT simply the contents of `path` — which is one case, an expanded archive member, and that
        one passes `member` too so `source_bytes()` can find it again.
        """
        if origin != "library":
            self._materialise()
        sid = sid or uuid.uuid4().hex[:8]
        if path is None:
            path = self.upload_dir / f"{sid}_{re.sub(r'[^A-Za-z0-9._-]', '_', filename)}"
            try:
                self.upload_dir.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data or b"")
            except OSError:
                pass
        streamed = data is None
        if streamed:
            # Never read the whole file to answer "what is this?" — the sniffer only ever looks at a
            # prefix, and this branch exists precisely because the file can be gigabytes.
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            with open(path, "rb") as fh:
                head = fh.read(SNIFF_HEAD_BYTES)
        else:
            size, head = len(data), data
        fp = fingerprint(filename, head)
        parser = fp.parser
        if isinstance(parser, DelimitedParser):
            parser = DelimitedParser(family=self._family_for_delimited(filename))
        src = Source(id=sid, file=filename, parser=parser.name, events=0, range=None, confidence=fp.confidence,
                     state="PARSING", size=size, sample=fp.sample,
                     origin="library" if origin == "library" else "case")  # type: ignore[arg-type]
        with self.lock:
            self.sources[sid] = src
            self.source_paths[sid] = path
            self.source_parsers[sid] = parser
            self.source_origin[sid] = "library" if origin == "library" else "case"
            if library_name:
                self.source_library[sid] = library_name
            if id_prefix:
                self.source_prefix[sid] = id_prefix
            if member:
                self.source_member[sid] = member
            self.source_order.append(sid)
        if self._raw_first_ok(parser):
            # Phase 1: the lines land in the pool and the index NOW; the parse and the normalization that
            # cost 85% of ingest are queued behind it. See app/enrich.py for the measurements.
            self._raw_source(sid, data, fp.state, fp.confidence, path=path if streamed else None, size=size)
            if origin == "library" and pool_store.was_skipped(sid):
                # The analyst declined phase 2 for this file before the restart. Re-asking would undo
                # the decision, and on a big workspace it is the decision that unblocked their screen.
                with self.lock:
                    self.sources[sid].enrich = "skipped"  # type: ignore[assignment]
            elif settings_auto_enrich():
                self.queue_enrichment(sid)
            return self.sources[sid]
        # `data=None` reaches _parse_source, which loads the bytes itself — on the PARSE thread for a
        # big file, so the request that started the ingest never holds them.
        if background_ok and size > SYNC_LIMIT:
            threading.Thread(target=self._parse_source, args=(sid, data, fp.state, fp.confidence), daemon=True).start()
        else:
            self._parse_source(sid, data, fp.state, fp.confidence)
        return self.sources[sid]

    @staticmethod
    def _raw_first_ok(parser) -> bool:
        """Can this container be shown as raw lines before it is parsed?

        Only line-oriented TEXT can. An EVTX record, a SQLite row, a PDF page or an OCR'd screenshot has
        no readable text until its parser has produced it, so a "raw" import of one would import nothing
        at all — those parse fully on ingest and are born `enriched`.
        """
        if getattr(parser, "binary", False):
            return False
        return bool(getattr(parser, "chunkable", False)) or getattr(parser, "family", "") in _RAW_FIRST_FAMILIES

    def _raw_source(self, sid: str, data: Optional[bytes], state: str, confidence: float,
                    path: Optional[Path] = None, size: int = 0) -> None:
        """Phase 1 of a two-phase ingest: raw lines into the pool, nothing interpreted.

        `path` (with `data=None`) reads the file a chunk at a time instead of holding it — see
        `enrich.raw_events_from_file`. The events are identical either way; what changes is that a
        1.9 GB capture is no longer in this process as bytes AND as a decoded str AND as a list of
        every line, on top of the events themselves.
        """
        from .jobs import PARSE_PROGRESS

        src = self.sources[sid]
        parser = self.source_parsers[sid]
        total = size if data is None else len(data)
        PARSE_PROGRESS.start(sid, src.file, total)
        with self.lock:
            prefix = self.source_prefix.get(sid, "")
            base = self._event_seq
        def tick(done: int, n: int) -> None:
            PARSE_PROGRESS.advance(sid, done=done, events=n, phase="reading")

        first_id = 1 if prefix else base + 1
        if data is None and path is not None:
            events = enrich.raw_events_from_file(sid, src.file, parser.family, path, prefix,
                                                 first_id=first_id, progress=tick, total=total)
        else:
            events = enrich.raw_events(sid, src.file, parser.family, data or b"", prefix,
                                       first_id=first_id, progress=tick)
        PARSE_PROGRESS.advance(sid, done=total, events=len(events), phase="merging")
        if not prefix:
            with self.lock:
                self._event_seq += len(events)
        with self.lock:
            src.events = len(events)
            src.state = state  # type: ignore[assignment]
            src.confidence = confidence
            src.range = None          # nothing has been timestamped yet, and no one may pretend otherwise
            src.enrich = "raw"        # type: ignore[assignment]
            self.source_parse_errors[sid] = 0
        self._append_events(events)
        n = len(events)
        del events
        PARSE_PROGRESS.finish(sid)
        self.bump()
        metrics.finish_progress(sid, n, total)

    def queue_enrichment(self, sid: str) -> bool:
        """Mark a source as waiting for phase 2 and hand it to the worker.

        The STATE and the QUEUE are set together, in that order, because they answer the same question in
        two places: `Source.enrich` is what every screen and `GET /api/case` read, `enrich.QUEUE` is what
        actually does the work. Submitting without marking left a source reading `raw` while it sat in the
        queue, so the workspace banner counted it as "never going to be interpreted" when it was next up.
        Returns False when the source is unknown or is already `enriched` — see routers/sources.py for the
        state rules; this is the one place that writes them.
        """
        with self.lock:
            src = self.sources.get(sid)
            if src is None or src.enrich == "enriched":
                return False
            if src.enrich not in ("queued", "enriching"):
                src.enrich = "queued"  # type: ignore[assignment]
                src.enrichError = None
        pool_store.remember_skip(sid, False)   # asking for it back cancels the persisted decision
        enrich.QUEUE.submit(sid)
        return True

    def skip_enrichment(self, sid: str) -> bool:
        """The analyst declines phase 2 for this source: cancel it from the queue and mark it `skipped`.

        A source ALREADY being enriched is not skippable and this returns False — the parse is running,
        it replaces the source's events when it lands, and recording "skipped" would be a claim about the
        pool that stops being true a few seconds later. `enrich_source` also refuses to start on a
        `skipped` source, so cancelling first and marking second cannot race into a started run.
        """
        enrich.QUEUE.cancel(sid)
        with self.lock:
            src = self.sources.get(sid)
            if src is None or src.enrich in ("enriching", "enriched"):
                return False
            src.enrich = "skipped"  # type: ignore[assignment]
            origin = self.source_origin.get(sid, "case")
        if origin == "library":
            # The DECISION outlives the process. Without this a restart re-parses the file as raw and
            # `autoEnrich` queues it straight back, so "skip the rest" — the way out of a blocked
            # Graph screen — would silently undo itself on the next boot.
            pool_store.remember_skip(sid, True)
        return True

    def requeue_unenriched(self) -> int:
        """Re-submit every source still waiting for phase 2. Called once, at startup.

        A source that was raw or mid-enrichment when the process died would otherwise sit in the pool as
        raw lines forever — searchable, but with no timestamps, fields or detections and nothing left
        that would ever give it any. 'skipped' is the analyst's decision and is never overridden.

        With `ingest.autoEnrich` OFF, a `raw` source is left alone: off means nothing enriches on its own,
        and a restart is not a request. A source that was already `queued`/`enriching` WAS asked for —
        either by the analyst or by the setting before it changed — so that request survives the restart.
        """
        auto = settings_auto_enrich()
        with self.lock:
            states = ("raw", "queued", "enriching") if auto else ("queued", "enriching")
            pending = [sid for sid, src in self.sources.items() if src.enrich in states]
            for sid in pending:
                self.sources[sid].enrich = "queued"  # type: ignore[assignment]
        for sid in pending:
            enrich.QUEUE.submit(sid)
        return len(pending)

    def enrich_source(self, sid: str) -> "enrich.EnrichResult":
        """Phase 2: parse and normalize a source that is currently in the pool as raw lines.

        Runs on the enrichment worker, never on a request thread. The source's raw events are REPLACED by
        the parsed ones; ids are preserved positionally when the parse is one-record-per-line, which is
        the common case (nginx, syslog, CSV, JSONL). When it is not, ids are reassigned and the result
        carries the old -> new map so curation can be moved with them.
        """
        import time
        from .jobs import PARSE_PROGRESS

        t0 = time.perf_counter()
        with self.lock:
            src = self.sources.get(sid)
            path = self.source_paths.get(sid)
            parser = self.source_parsers.get(sid)
        if src is None or path is None or parser is None:
            return enrich.EnrichResult(sid=sid, ok=False, error="unknown source")
        if src.enrich in ("enriched", "skipped"):
            return enrich.EnrichResult(sid=sid, ok=True, error="already " + src.enrich)
        with self.lock:
            src.enrich = "enriching"  # type: ignore[assignment]
        try:
            # THE bug this accessor exists for. `path` is the staged CONTAINER when this source is an
            # archive member, so reading it here replaced a parsed syslog member with lines of decoded
            # zip binary — and left the source reporting READY / enriched over the top of it.
            data = self.source_bytes(sid)
            PARSE_PROGRESS.start(sid, src.file, len(data))
            PARSE_PROGRESS.advance(sid, done=0, phase="enriching")
        except (OSError, KeyError, ValueError) as exc:
            with self.lock:
                src.enrich, src.enrichError = "error", str(exc)  # type: ignore[assignment]
            return enrich.EnrichResult(sid=sid, ok=False, error=str(exc))

        old_ids = [e.id for e in self.events if e.sourceId == sid]
        try:
            batches = self._parse_batches(sid, src, parser, data)
            events, skew, unmapped = self._finish_batches(sid, batches, assign_ids=False)
        except Exception as exc:
            PARSE_PROGRESS.finish(sid)
            msg = f"{type(exc).__name__}: {exc}"
            with self.lock:
                # The parse failing in phase 2 is still THE PARSE FAILING, and every screen reads
                # Source.state to say so. The raw lines stay in the pool and stay searchable — that is
                # the point of the split — but the file must never look successfully parsed.
                src.enrich, src.enrichError = "error", msg  # type: ignore[assignment]
                src.state, src.error = "ERROR", msg  # type: ignore[assignment]
            self.bump()
            return enrich.EnrichResult(sid=sid, ok=False, error=msg)

        one_to_one = len(events) == len(old_ids)
        remap: dict[str, str] = {}
        try:
            if one_to_one:
                # the ids the analyst may already have cited stay exactly where they are
                for ev, old in zip(events, old_ids):
                    ev.id = old
            else:
                with self.lock:
                    prefix = self.source_prefix.get(sid, "")
                    base = self._event_seq
                    self.source_id_base[sid] = base
                    if not prefix:
                        self._event_seq += len(events)
                for i, ev in enumerate(events):
                    ev.id = f"{prefix}{i + 1:x}" if prefix else f"e{base + i + 1:x}"
                # a citation follows its RAW TEXT, which is the one thing both phases agree on
                by_raw: dict[str, str] = {}
                for ev in events:
                    by_raw.setdefault(ev.raw, ev.id)
                for e in self.events:
                    if e.sourceId == sid and e.raw in by_raw:
                        remap[e.id] = by_raw[e.raw]
            events.sort(key=ts_key)
            with self.lock:
                gone = sid not in self.sources
            if gone:
                # The source (or the case holding it) was deleted while phase 2 was running. Swapping
                # its events into the pool now would resurrect evidence the analyst just removed, with
                # ids nothing references — abandon the result instead. The raw lines went with the delete.
                PARSE_PROGRESS.finish(sid)
                return enrich.EnrichResult(sid=sid, ok=False, error="source removed during enrichment")
            deferred = self._defer_swap(sid, events, remap, skew, unmapped, len(old_ids), t0)
            if deferred is not None:
                return deferred          # committed with the rest of the batch, see `enrich_batch`
            lost = self._swap_source_events(sid, events, remap)
        except Exception as exc:
            # Anything raising AFTER `enriching` was set leaves the source stuck in that state for the
            # life of the process: nothing re-queues it, POST /enrich treats it as already pending and
            # POST /enrich/skip refuses it, so the workspace banner counts down work that will never
            # finish. An id-assignment change did exactly that. Fail it properly — `error` is retryable.
            PARSE_PROGRESS.finish(sid)
            msg = f"{type(exc).__name__}: {exc}"
            with self.lock:
                src.enrich, src.enrichError = "error", msg  # type: ignore[assignment]
                src.state, src.error = "ERROR", msg  # type: ignore[assignment]
            self.bump()
            return enrich.EnrichResult(sid=sid, ok=False, error=msg)

        with self.lock:
            stamped = [e.ts for e in events if e.ts]
            src.events = len(events)
            src.range = (stamped[0], stamped[-1]) if stamped else None
            src.enrich = "enriched"  # type: ignore[assignment]
            src.enrichError = None
            src.enrichedAt = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            if skew is not None:
                self.skews[sid] = skew
            self.source_parse_errors[sid] = unmapped
        PARSE_PROGRESS.finish(sid)
        with self._detect_lock:
            self._run_detections()
        self.bump()
        # Cache the finished source so the next restart neither re-parses nor re-enriches it. It runs
        # AFTER the detection pass, because the detections are stamped on the events and are part of
        # what is being saved; and it uses `events`, which this method already holds, so the cache
        # never costs a scan of the pool.
        self._cache_library_source(sid, events)
        # ONLY a case-origin source belongs in case.json — a library source persists nothing here
        # (save_meta lists case sources only), so the write is pure risk on a background worker.
        # save_meta itself refuses to recreate a deleted case directory; this is the cheaper half.
        if self.source_origin.get(sid, "case") == "case":
            self.save_meta()
        return enrich.EnrichResult(sid=sid, ok=True, raw_events=len(old_ids), events=len(events),
                                   one_to_one=one_to_one, remap=remap, lost_citations=lost,
                                   took_ms=int((time.perf_counter() - t0) * 1000))

    def _cache_library_source(self, sid: str, events: list[Event]) -> None:
        """Persist one finished LIBRARY source's parsed events (see app/pool_store.py). Never raises.

        Case-origin sources are deliberately not cached: their bytes live under `cases/<id>/uploads/`,
        they are restored from case.json with ids allocated by that file's order, and a case can be
        deleted, restored from the trash or detached — an extra copy of its events keyed on a library
        path would be a second source of truth for evidence that already has one.
        """
        try:
            with self.lock:
                name = self.source_library.get(sid, "")
                src = self.sources.get(sid)
                origin = self.source_origin.get(sid, "case")
                errors = self.source_parse_errors.get(sid, 0)
            if not name or src is None or origin != "library":
                return
            pool_store.save_member(name, src, events, errors)
        except Exception as exc:  # noqa: BLE001 — a cache write may never fail an ingest
            print(f"[iris] pool cache: could not cache {sid} ({type(exc).__name__}: {exc})")

    # ---------------------------------------------------------------- batched phase 2
    @contextmanager
    def enrich_batch(self):
        """Hold the pool merge until several sources have been interpreted, then do ONE.

        The merge is O(the whole pool) whatever changed — a new list, a sort, an id index and a
        timestamp array over every event in the workspace — so on the analyst's 11.4 M-event pool it
        cost ~45 s PER SOURCE and a queue of forty small text files took half an hour, almost none of
        it parsing. Batching turns forty merges into one.

        What is deliberately NOT deferred: the parse itself, the id assignment and the citation remap
        all still happen per source, so the ids an analyst may have cited are decided exactly as
        before. What IS deferred is when those events enter the pool — which is also why a source
        stays `enriching` until the flush rather than claiming to be `enriched` while its parsed rows
        are not yet searchable.
        """
        with self.lock:
            if self._enrich_batch is not None:      # already inside one: let the outer context own it
                nested = True
            else:
                nested, self._enrich_batch = False, []
        try:
            yield
        finally:
            if not nested:
                self.flush_enrich_batch()

    def enrich_batch_size(self) -> int:
        """How many finished parses are waiting for the shared merge. 0 when no batch is open."""
        with self.lock:
            return len(self._enrich_batch or [])

    def _defer_swap(self, sid: str, events: list[Event], remap: dict[str, str], skew, unmapped: int,
                    raw_events: int, t0: float):
        """Stash a finished parse for the batch commit, or return None when there is no batch open."""
        import time as _time

        with self.lock:
            if self._enrich_batch is None:
                return None
            self._enrich_batch.append({"sid": sid, "events": events, "remap": remap, "skew": skew,
                                       "unmapped": unmapped, "raw": raw_events, "t0": t0})
        from .jobs import PARSE_PROGRESS

        PARSE_PROGRESS.finish(sid)
        return enrich.EnrichResult(sid=sid, ok=True, raw_events=raw_events, events=len(events),
                                   one_to_one=len(events) == raw_events, remap=remap, lost_citations=[],
                                   took_ms=int((_time.perf_counter() - t0) * 1000))

    def flush_enrich_batch(self) -> int:
        """Commit every deferred source in ONE merge, one detection pass and one bump."""
        with self.lock:
            batch, self._enrich_batch = self._enrich_batch, None
        if not batch:
            return 0
        # A source deleted while the batch was open must not be resurrected — the same rule the
        # single-source path applies, re-checked here because the window is longer.
        with self.lock:
            live = [b for b in batch if b["sid"] in self.sources]
        if not live:
            return 0
        lost = self._swap_many({b["sid"]: b["events"] for b in live}, 
                               {k: v for b in live for k, v in b["remap"].items()})
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock:
            for b in live:
                sid, events = b["sid"], b["events"]
                src = self.sources.get(sid)
                if src is None:
                    continue
                stamped = [e.ts for e in events if e.ts]
                src.events = len(events)
                src.range = (stamped[0], stamped[-1]) if stamped else None
                src.enrich = "enriched"  # type: ignore[assignment]
                src.enrichError = None
                src.enrichedAt = now
                if b["skew"] is not None:
                    self.skews[sid] = b["skew"]
                self.source_parse_errors[sid] = b["unmapped"]
        with self._detect_lock:
            self._run_detections()
        self.bump()
        for b in live:                      # the cache wants the events, which the batch still holds
            self._cache_library_source(b["sid"], b["events"])
        if any(self.source_origin.get(b["sid"], "case") == "case" for b in live):
            self.save_meta()
        for b in live:
            result = enrich.QUEUE.last.get(b["sid"])
            if result is not None:
                result.lost_citations = lost.get(b["sid"], [])
        return len(live)

    def _swap_source_events(self, sid: str, events: list[Event], remap: dict[str, str]) -> list[str]:
        """Replace ONE source's events. See `_swap_many` — this is the single-source case."""
        return self._swap_many({sid: events}, remap).get(sid, [])

    def _swap_many(self, by_source: dict[str, list[Event]], remap: dict[str, str]) -> dict[str, list[str]]:
        """Replace SEVERAL sources' events in one merge, moving any curation that cited the old ids.

        The merge is the expensive part and it is O(the whole pool) however few events change: a new
        list, a sort, an id index and a timestamp array over every event in the workspace. Measured on
        the analyst's 11.4 M-event pool it was ~45 s PER SOURCE, so a queue of forty small text files
        took half an hour — almost none of it parsing. Doing it once for a batch is the whole reason
        this takes a mapping instead of a single sid.

        Same optimistic off-lock build as `_append_events` / `_remove_events_of`: everything is built
        on a snapshot and swapped in under a very short critical section, because building it under
        the lock is seconds and the swap is a few assignments.
        """
        sids = set(by_source)
        lost: dict[str, list[str]] = {sid: [] for sid in sids}
        if not sids:
            return lost
        incoming: list[Event] = [e for evs in by_source.values() for e in evs]
        # Say what this is and how big it is BEFORE the first O(pool) stage. Everything below runs for
        # minutes on a large workspace and used to be completely silent: the analyst saw "1 queued to
        # interpret" for a 16.9 MB file and nothing about the 13.8 M-event merge it was queued behind.
        enrich.MERGE.start(len(sids), len(self.events))
        # A source's raw events may still be sitting in the BULK BUFFER when phase 2 lands: the raw
        # phase appends into `_pending` during a library load and the enrichment worker can swap that
        # same source before `_flush_pending` runs. Filtering only `self.events` then left BOTH copies
        # in the pool — the same ids twice, so every count and every detection over that source
        # doubled. The buffer is purged first, and under its own lock, so a flush racing this either
        # sees the events gone or has already merged them (in which case the swap below removes them).
        with self._pending_lock:
            if self._pending:
                self._pending = [e for e in self._pending if e.sourceId not in sids]
        while True:
            base = self.events
            enrich.MERGE.step("filtering", len(base))
            merged = [e for e in base if e.sourceId not in sids]
            merged.extend(incoming)
            enrich.MERGE.step("sorting", len(merged))
            merged.sort(key=ts_key)
            enrich.MERGE.step("indexing", len(merged))
            index = _build_index(merged)
            enrich.MERGE.step("timestamps", len(merged))
            ts = _epochs(merged) if merged else np.zeros(0, dtype=np.float64)
            fired = sum(len(e.detections) for e in merged)
            enrich.MERGE.step("curation", len(merged))
            with self.lock:
                if self.events is not base:
                    continue
                self.events = merged
                self.event_index = index
                self.ts = ts
                self.rules_fired = fired
                if self.case_set:
                    # which source a lost citation belonged to, so each one is reported to the source
                    # whose enrichment dropped it rather than to whichever was first in the batch
                    owner = {e.id: e.sourceId for e in base if e.sourceId in sids}
                    moved = OrderedDict()
                    changed = False
                    for k, v in self.case_set.items():
                        if k in index:
                            moved[k] = v
                        elif k in remap:
                            moved[remap[k]] = v
                            changed = True
                        elif k in owner:
                            # only a citation of a source in THIS batch can go missing here
                            lost[owner[k]].append(k)
                            # KEEP the entry. It used to be dropped here — the analyst's timeline entry
                            # deleted because a re-parse produced a different id for its line — and the
                            # next save_meta() persisted the deletion. It stays, unresolved and
                            # reported, and `_reanchor_case_set` below re-points it at its line when
                            # that line is still in the pool.
                            moved[k] = v
                            changed = True
                        else:
                            moved[k] = v
                    if changed:
                        self.case_set = moved
                        self.case_set_rev += 1
                break
        # ids just moved for a whole batch of sources: re-point any entry whose pointer no longer
        # matches its anchor. Cheap when nothing drifted — it walks the case set, not the pool.
        self._reanchor_case_set()
        enrich.MERGE.finish()
        return lost

    @staticmethod
    def _family_for_delimited(filename: str) -> str:
        fam, hints = FAMILY_HINTS["delimited"]
        lower = filename.lower()
        return fam if any(h in lower for h in hints) else "delimited"

    def remap_source(self, sid: str, fields: list[str], delimiter: Optional[str]) -> Source:
        with self.lock:
            src = self.sources[sid]
        # source_bytes, not source_paths[sid].read_bytes(): for a member of a staged archive the
        # recorded path is the CONTAINER, and re-parsing that as the member is how a mapping accepted
        # on a log inside a zip used to fill the pool with the zip's own bytes.
        data = self.source_bytes(sid)
        parser = DelimitedParser(fields=fields, delimiter=delimiter, family=self._family_for_delimited(src.file))
        with self.lock:
            self.source_parsers[sid] = parser
            src.parser = parser.name
            src.delimiter = delimiter
            src.guessedFields = list(fields)
            src.state = "PARSING"
        self._remove_events_of(sid)
        self._parse_source(sid, data, "READY", 0.95)
        return self.sources[sid]

    def _parse_source(self, sid: str, data: Optional[bytes], state: str, confidence: float) -> None:
        """Parse one source into the pool.

        Deliberately does as little as possible while holding `self.lock`. Tokenizing, normalizing, the
        merge/sort of the pool and the detection pass are all O(file) or O(pool) and used to run inside
        the lock, so `GET /api/case` (which takes the same lock) blocked for 15 s at a time while a big
        file was ingesting. The only critical section left here is the source-metadata update.

        `data=None` means "read them yourself". That matters for WHEN as much as for how much: this
        runs on the parse thread for anything over SYNC_LIMIT, so the request that started the ingest
        has already returned and is not holding a gigabyte while it does.
        """
        from .jobs import PARSE_PROGRESS

        parser = self.source_parsers[sid]
        src = self.sources[sid]
        if data is None:
            try:
                data = self.source_bytes(sid)
            except (OSError, KeyError, ValueError) as exc:
                with self.lock:
                    src.state = "ERROR"
                    src.error = f"could not read the file back: {type(exc).__name__}: {exc}"
                self.bump()
                return
        PARSE_PROGRESS.start(sid, src.file, len(data))
        try:
            batches = self._parse_batches(sid, src, parser, data)
        except Exception as exc:  # parser blew up on this file
            PARSE_PROGRESS.finish(sid)
            with self.lock:
                src.state = "ERROR"
                src.error = f"{type(exc).__name__}: {exc}"
            self.bump()
            return
        PARSE_PROGRESS.advance(sid, done=len(data), phase="merging")
        events, skew, unmapped = self._finish_batches(sid, batches)
        del batches
        with self.lock:
            src.events = len(events)
            src.state = state  # type: ignore[assignment]
            src.confidence = confidence
            if isinstance(parser, DelimitedParser):
                src.guessedFields = list(parser.guessed) if parser.guessed else src.guessedFields
                src.delimiter = parser.delimiter
                if parser.mapping is None:
                    src.state = state_for(confidence, parser)  # type: ignore[assignment]
            stamped = [e.ts for e in events if e.ts]
            src.range = (stamped[0], stamped[-1]) if stamped else None
            if skew is not None:
                self.skews[sid] = skew
            self.unmapped_fields += unmapped
            self.source_parse_errors[sid] = unmapped
        # the merge + sort of the whole pool, and the detection pass over it, stay OUT of the lock
        self._append_events(events)
        n_events = len(events)
        # Kept only when this source is finished at parse time; otherwise the reference dies with the
        # `del` below, because holding a second list of a million events costs what the pool costs.
        events_for_cache = events if self.sources[sid].enrich == "enriched" else []
        del events
        PARSE_PROGRESS.finish(sid)
        if not self._bulk:  # a bulk load runs the rules ONCE at the end, not once per file
            with self._detect_lock:      # NOT self.lock — see _detect_lock's comment
                self._run_detections()
        self.bump()
        metrics.finish_progress(sid, n_events, len(data))
        # A source that is born `enriched` (EVTX, SQLite, PDF, an OCR'd image: no readable raw phase)
        # is finished right here and will never reach `enrich_source`, so this is its only chance to
        # be cached. A raw-first source is NOT cached here — it is not interpreted yet.
        self._cache_library_source(sid, events_for_cache)

    def _parse_batches(self, sid: str, src: Source, parser: BaseParser, data: bytes) -> list:
        """Tokenize + normalize one file into ordered chunks, in parallel when that pays.

        The parallel path (parsers.parallel) hands byte-range chunks to worker PROCESSES — plain threads
        cannot help, the work is pure-Python and CPU bound behind the GIL. It degrades to the single
        worker below whenever the parser is not chunkable, the file is small, or the pool will not start.
        """
        from .jobs import PARSE_PROGRESS, PROGRESS_EVERY_RECORDS, progress_step
        from .parsers import parallel as par

        prep = par.prepare(parser, data)
        if prep is not None:
            plan, head_parsed, head_end = prep
            PARSE_PROGRESS.start(sid, src.file, len(data), workers=plan.workers)
            done = [head_end]

            def tick(nbytes: int) -> None:
                done[0] += nbytes
                PARSE_PROGRESS.advance(sid, done=done[0])

            chunks = par.run_parallel(plan, data, sid, src.file, parser.family, progress=tick)
            if chunks is not None:
                head_batch = par.normalize_batch(head_parsed, sid, src.file, parser.family)
                head_batch.nbytes = head_end
                return [head_batch] + chunks
            # the pool would not start — fall back to one worker on a pristine copy of the parser
            parser = plan.parser
            PARSE_PROGRESS.start(sid, src.file, len(data))
        parsed: list[ParsedEvent] = []
        n = 0
        approx = 0
        # Publish on a BYTE step as well as the record count. The record count alone never fires on a
        # small file - at 20,000 records a 5,000-line log ticked ZERO times, so its bar read 0 % for
        # the whole parse and then jumped to done. Whichever comes first wins; see jobs.progress_step.
        step = progress_step(len(data))
        next_at = step
        for pe in parser.parse_bytes(data):
            parsed.append(pe)
            n += 1
            approx += len(pe.raw) + 1
            if approx >= next_at or n % PROGRESS_EVERY_RECORDS == 0:
                next_at = approx + step
                PARSE_PROGRESS.advance(sid, done=min(approx, len(data)), events=n)
        return [par.normalize_batch(parsed, sid, src.file, parser.family)]

    def _finish_batches(self, sid: str, batches: list, assign_ids: bool = True) -> tuple[list[Event], Optional[float], int]:
        """Stitch the chunks, assign event ids over the WHOLE file, then sort by timestamp.

        Ids follow RECORD order (not sorted order) and the sort is stable, so the single-worker and the
        parallel paths produce byte-identical ids — which they must, because case sets reference them.
        """
        from .parsers.parallel import merge_batches

        events, skew, unmapped = merge_batches(batches)
        if not assign_ids:
            # enrichment assigns them itself: the whole point is to reuse the ids the raw phase handed
            # out, which are already cited by case sets, notes and indicators
            return events, skew, unmapped
        with self.lock:
            prefix = self.source_prefix.get(sid, "")
            base = self._event_seq
            # Remember where this source's ids START. Persisted per source in case.json (`idBase`) and
            # replayed by `restore`, because the legacy global counter is only stable if the SAME
            # sources are parsed in the SAME order into a pool of the same size — and they are not: an
            # upload lands in a pool that already holds other sources, while a restore starts from an
            # empty one. That mismatch is what made a case's own event ids differ from the ids its
            # case set cites.
            self.source_id_base[sid] = base
            if not prefix:
                # legacy global counter: ids are e1, e2, … in ingest order. Case sources KEEP it so event
                # ids already persisted in a case set do not move under an analyst's feet.
                self._event_seq += len(events)
        if prefix:
            for i, ev in enumerate(events):
                ev.id = f"{prefix}{i + 1:x}"
        else:
            for i, ev in enumerate(events):
                ev.id = f"e{base + i + 1:x}"
        events.sort(key=ts_key)
        return events, skew, unmapped

    def _normalize(self, sid: str, filename: str, family: str, parsed: list[ParsedEvent]) -> tuple[list[Event], Optional[float], int]:
        """Single-batch normalization. The per-record work lives in parsers.parallel.normalize_batch so
        that the parallel path cannot drift from this one."""
        from .parsers.parallel import normalize_batch

        return self._finish_batches(sid, [normalize_batch(parsed, sid, filename, family)])

    def _flush_pending(self) -> None:
        """Merge everything a bulk load has buffered into the pool — one sort, one reindex."""
        with self._pending_lock:
            batch, self._pending = self._pending, []
        if batch:
            self._merge_into_pool(batch)

    def _append_events(self, events: list[Event]) -> None:
        """Publish a source's events into the pool.

        In BULK mode the events are only buffered; `_flush_pending` merges them once the buffer passes
        BULK_FLUSH_EVENTS or the load ends. Outside bulk mode (a normal upload) they merge at once.

        Called WITHOUT the store lock: merging + sorting + reindexing 2 M events takes seconds, and doing
        it under the lock is half of why `GET /api/case` stalled during ingest. The new list, index and
        timestamp array are built off a snapshot and swapped in under a very short critical section; if
        another writer got there first the work is redone (rare — writes are the slow path, not the
        common one). Never mutate self.events in place: searches read events/ts without the lock.
        """
        if not events:
            return
        if self._bulk:
            with self._pending_lock:
                self._pending.extend(events)
                due = len(self._pending) >= BULK_FLUSH_EVENTS
            if due:
                self._flush_pending()
            return
        self._merge_into_pool(events)

    def _merge_into_pool(self, events: list[Event]) -> None:
        while True:
            base = self.events
            merged = base + events
            merged.sort(key=ts_key)
            index = {e.id: i for i, e in enumerate(merged)}
            ts = _epochs(merged) if merged else np.zeros(0, dtype=np.float64)
            with self.lock:
                if self.events is base:
                    self.events = merged
                    self.event_index = index
                    self.ts = ts
                    return

    def _reindex(self) -> None:
        if any(self.events[i].ts > self.events[i + 1].ts for i in range(len(self.events) - 1)):
            self.events = sorted(self.events, key=ts_key)
        self.event_index = {e.id: i for i, e in enumerate(self.events)}
        self.ts = _epochs(self.events) if self.events else np.zeros(0, dtype=np.float64)

    def _run_detections(self) -> None:
        """Built-in Sigma-like rules (minus disabled ones) + enabled custom regex rules."""
        RULES_STORE.load()
        # ONE compiled exclusion set for the whole pass, built here rather than per rule: it is the same
        # set for every rule and compiling a regex condition sixty times over would be the same mistake
        # the _prx hoisting fixed. `record` publishes what it actually suppressed, which is what keeps a
        # suppression list from being invisible on the screen that manages it.
        excl = EXCLUSIONS.matcher()
        info = run_rules(self.events, self.ts, disabled=RULES_STORE.detection_disabled(),
                         overrides=RULES_STORE.detection_overrides(),
                         params=RULES_STORE.detection_params(),
                         exclude=excl)
        custom = RULES_STORE.apply_all(self.events, excl)
        EXCLUSIONS.record(excl.counts())
        self.rules_fired = int(info["fired"]) + custom  # type: ignore[arg-type]

    def reapply_all_rules(self) -> int:
        """Re-run the whole catalogue from scratch. Used after a bulk change (clear all / restore defaults)
        where per-rule stripping would leave stale detections behind."""
        with self._detect_lock:
            self._run_detections()
        with self.lock:
            self.bump()
            return self.rules_fired

    def reapply_rule(self, rule_id: str) -> int:
        """Fast path after a rule changed: drop its previous hits, re-run just that rule, bump the version.

        The whole thing is a pass over the pool that mutates `Event.detections`, so it serialises against
        other passes on `_detect_lock` — but not against readers on `self.lock`: saving a rule must not
        freeze /api/case and every other request for the length of a rule pass."""
        r0 = RULES_STORE.get(rule_id)
        if r0 is not None and r0.mechanism == "graph":
            # A GRAPH rule tags no event, so re-running the catalogue over the pool would change nothing
            # at a cost of O(pool). Its findings are keyed on RULES_STORE.rev (bumped by every mutator),
            # so the roll-up misses by construction and the next read re-evaluates. Bump the version so
            # anything watching the store still refreshes.
            self.bump()
            return 0
        with self._detect_lock:
            RULES_STORE.strip_rule(rule_id, self.events)
            hits = 0
            r = RULES_STORE.get(rule_id)
            if r is not None and r.enabled and not r.builtin:
                hits = RULES_STORE.apply_rule(r, self.events)
            elif r is not None and r.builtin:  # built-ins are evaluated together (bursts depend on each other)
                self._run_detections()
                hits = sum(1 for e in self.events for d in e.detections if d.id == rule_id)
            fired = sum(len(e.detections) for e in self.events)
        with self.lock:
            self.rules_fired = fired
            self.bump()
            return hits

    # ---------------------------------------------------------- multi-case
    def activate(self, case_id: str, save_current: bool = True, force: bool = False) -> None:
        """Switch the in-memory store to another on-disk case (previous case stays on disk).

        `force` reloads even when the id is unchanged — needed after a delete, where the store still
        carries the deleted case's name/events in memory and would otherwise write that stale identity
        back over the fresh case.json.

        A PENDING store always reloads, whatever the id. After the last case is deleted the store holds
        the next id in reserve, and creating a case hands back that very same id — so the unchanged-id
        short circuit fired and left `pending` set, meaning the brand-new case still reported itself as
        "no case exists".
        """
        with self.lock:
            if case_id == self.case_id and not force and not self.pending:
                return
            before = self._pool_signature()
            if save_current:
                self.save_meta()  # no-op while pending
            # keep_library: the case-less pool is NOT part of any case, so switching cases must never
            # discard it (and must never re-parse it either — that is where a double count would come from)
            self._switching = True
            self._clear_memory(delete_files=False, keep_library=True)
            self.pending = False
            self.case_id = case_id
            self.name = "Untitled case"
            self.analyst = config.get_settings().analyst
            self.created_at = datetime.now(UTC)
            self.version += 1
            self._drop_derived()
        try:
            self.restore(case_id)
        finally:
            # cleared in a finally: a restore that raises must not leave every future save_meta() a
            # no-op, which would silently stop persisting the case for the life of the process
            with self.lock:
                self._switching = False
        # A file the PREVIOUS case had attached left the pool with that case; it is still staged in the
        # library and belongs to no case, so it comes back as a library source. Files already in memory
        # (or attached to THIS case) are skipped, so nothing is ever parsed twice.
        self.load_library()
        # The library pool survived the switch, so its detections must be re-evaluated together with the
        # new case's events (bursts are windowed across the whole pool) and rules_fired recomputed.
        #
        # ONLY when the pool actually changed. A detection pass is O(the whole pool) — measured at
        # 11.1 M events it is minutes of pure-Python regex work and enough allocation churn to SEGFAULT
        # the process on this VM, which is exactly how `create_case` (an empty case, nothing entering or
        # leaving the pool) took the app down while the AI investigator was mid-run. Switching cases
        # cannot change what a rule matched on an event that did not move: every surviving event still
        # carries its own detections, and the windowed burst rules only see a different density if the
        # SET of events changed. So compare the pool before and after, and do nothing when it is the same.
        if self._pool_signature() != before:
            with self._detect_lock:
                self._run_detections()
        self.bump()

    def _pool_signature(self) -> tuple:
        """What is in the pool, cheaply: one entry per SOURCE, never a walk of the events.

        Used to decide whether a case switch has to re-run detections. Sources are a few dozen entries,
        so this is free; the pass it can skip is minutes.
        """
        return tuple(sorted((sid, s.events, s.range) for sid, s in self.sources.items()))

    def _remove_events_of(self, sid: str) -> None:
        """Drop one source's events from the pool. Must be FAST — this is a click, not a job.

        It used to re-run the WHOLE detection catalogue inline, under the store lock: ~15 s at 1.2 M
        events, during which every other request queued behind it, for a delete the analyst expects to
        be instant. Removing events cannot create a detection on a surviving event, and each event
        already carries the detections it matched, so nothing has to be recomputed for the answer to be
        correct — only `rules_fired` (a count) and windowed BURST rules, whose density can legitimately
        change when neighbouring events disappear. So: the count is recomputed in the same pass (no
        regex, no rule evaluation), and the burst re-evaluation is handed to a background thread that
        bumps the version again when it lands, exactly like the search index and the derived caches.

        The old code also built a set of every SURVIVING event id purely to prune the case set — 1.3 M
        strings to filter a curated list of a few dozen. The removed ids are collected in the one pass
        that has to happen anyway.
        """
        # The filter, the new index and the timestamp array are built OFF the lock on a snapshot and
        # swapped in — the same optimistic pattern as _append_events. Building them under the lock was
        # several seconds on a 1.7 M-event pool during which /api/case and every write queued; the swap
        # itself is a few assignments. If another writer replaced the list meanwhile, do it again.
        while True:
            base = self.events
            removed: set[str] = set()
            kept: list[Event] = []
            fired = 0
            for e in base:
                if e.sourceId == sid:
                    removed.add(e.id)
                else:
                    kept.append(e)
                    fired += len(e.detections)   # exact for everything except bursts, see below
            if not removed:
                return
            # `kept` preserves order, so it is already sorted; only the index and ts need rebuilding
            index = {e.id: i for i, e in enumerate(kept)}
            ts = _epochs(kept) if kept else np.zeros(0, dtype=np.float64)
            with self.lock:
                if self.events is not base:
                    continue                      # lost the race — redo on the new list
                self.events = kept
                self.event_index = index
                self.ts = ts
                if self.case_set:
                    before = len(self.case_set)
                    self.case_set = OrderedDict((k, v) for k, v in self.case_set.items() if k not in removed)
                    if len(self.case_set) != before:
                        self.case_set_rev += 1
                self.rules_fired = fired
                self.bump()
                break
        self._refresh_detections_async()

    def _refresh_detections_async(self) -> None:
        """Re-evaluate the rule catalogue off the request thread, coalescing repeated calls.

        Only windowed rules can change when events are removed (`find_bursts` counts events inside a
        window), so this is a correction, not the answer — the pool is already usable and correct for
        every non-burst rule the moment `_remove_events_of` returns. A second delete while one of these
        is running just sets the flag again rather than starting a second full pass.
        """
        with self.lock:
            if getattr(self, "_detect_busy", False):
                self._detect_again = True
                return
            self._detect_busy = True
            self._detect_again = False

        def run() -> None:
            try:
                while True:
                    with self._detect_lock:
                        self._run_detections()
                    with self.lock:
                        self.bump()
                        if not self._detect_again:
                            self._detect_busy = False
                            return
                        self._detect_again = False
            except Exception:  # noqa: BLE001 — a failed refresh must not take the store down
                with self.lock:
                    self._detect_busy = False

        threading.Thread(target=run, daemon=True).start()

    def delete_source(self, sid: str, delete_file: bool = True) -> bool:
        with self.lock:
            if sid not in self.sources:
                return False
            del self.sources[sid]
            self.source_parsers.pop(sid, None)
            self.source_origin.pop(sid, None)
            self.source_library.pop(sid, None)
            self.source_prefix.pop(sid, None)
            self.source_order = [s for s in self.source_order if s != sid]
            self.skews.pop(sid, None)
            self.source_parse_errors.pop(sid, None)
            self.source_member.pop(sid, None)
            path = self.source_paths.pop(sid, None)
            # members of one expanded container share a file on disk — never unlink it while a sibling
            # source still reads from it
            if path is not None and any(p == path for p in self.source_paths.values()):
                delete_file = False
        if path and delete_file:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        self._remove_events_of(sid)
        return True

    # ------------------------------------------------------------- queries
    def event(self, eid: str) -> Optional[Event]:
        i = self.event_index.get(eid)
        return self.events[i] if i is not None else None

    # ------------------------------------------------------------- case set
    def add_to_case(self, eid: str, labels: Optional[list[str]] = None, note: Optional[str] = None,
                    persist: bool = True) -> Optional[CaseSetEntry]:
        """Mark an event as part of the case. Idempotent — a second call updates labels/note.

        `persist=False` skips the case.json write so a BULK caller can do one write at the end —
        save_meta() re-serializes the whole case set plus every source, so writing per event made
        whole-file adds quadratic. Bulk callers MUST use add_many_to_case (which saves in a finally),
        never persist=False on its own, or memory and disk diverge until the next write.
        """
        with self.lock:
            if eid not in self.event_index:
                return None
            cur = self.case_set.get(eid)
            ev = self.event(eid)
            entry = CaseSetEntry(
                eventId=eid,
                labels=_clean_labels(labels) if labels is not None else (cur.labels if cur else []),
                note=(note if note is not None else (cur.note if cur else "")),
                addedAt=cur.addedAt if cur else to_iso(datetime.now(UTC)),
                # the anchor: what this entry is REALLY pointing at, so it can be found again when the
                # ids move (see CaseSetEntry and `_reanchor_case_set`)
                file=(cur.file if cur and cur.file else (getattr(ev, "file", "") or "")),
                rawHash=(cur.rawHash if cur and cur.rawHash else raw_hash(getattr(ev, "raw", ""))),
            )
            self.case_set[eid] = entry
            self.case_set_rev += 1
            if persist:
                self.save_meta()
            return entry

    def remove_from_case(self, eid: str, persist: bool = True) -> bool:
        with self.lock:
            if eid not in self.case_set:
                return False
            del self.case_set[eid]
            self.case_set_rev += 1
            if persist:
                self.save_meta()
            return True

    def add_many_to_case(self, eids: Iterable[str], labels: Optional[list[str]] = None,
                         note: Optional[str] = None) -> list[CaseSetEntry]:
        """Upsert many events into the case set with ONE case.json write (see add_to_case).

        The write happens in a finally: if something raises partway the entries already applied in
        memory are still persisted, so a restart cannot disagree with the running process.
        """
        out: list[CaseSetEntry] = []
        try:
            with self.lock:
                for eid in eids:
                    entry = self.add_to_case(eid, labels, note, persist=False)
                    if entry is not None:
                        out.append(entry)
        finally:
            self.save_meta()
        return out

    def remove_many_from_case(self, eids: Iterable[str]) -> int:
        """Drop many events from the case set with ONE case.json write."""
        removed = 0
        try:
            with self.lock:
                for eid in eids:
                    if self.remove_from_case(eid, persist=False):
                        removed += 1
        finally:
            self.save_meta()
        return removed

    def case_set_events(self) -> list[Event]:
        """Case-set events in timestamp order (the analyzer needs them sorted)."""
        with self.lock:
            idx = [self.event_index[e] for e in self.case_set if e in self.event_index]
        return sorted((self.events[i] for i in idx), key=ts_key)

    def case_labels(self) -> list[str]:
        seen: dict[str, None] = {}
        with self.lock:
            for entry in self.case_set.values():
                for lab in entry.labels:
                    seen.setdefault(lab, None)
        return sorted(seen)

    def stamp_membership(self, events: list[Event]) -> list[dict]:
        """The API rows for one PAGE of events, with case-set membership stamped on.

        Returns dicts, not `Event`s. Case membership is not pool state — `Event` deliberately has no
        `inCase`/`labels` slot (that was 16 bytes x every log line to store `False` and an empty list),
        so the stamp lands on the boundary representation. Never mutates the pooled objects.
        """
        with self.lock:
            cs = {k: v.labels for k, v in self.case_set.items()}
        out = []
        for e in events:
            row = e.model_dump()
            labels = cs.get(e.id)
            if labels is not None:
                row["inCase"], row["labels"] = True, list(labels)
            out.append(row)
        return out

    # ------------------------------------------------- derived structures (graph / correlation)
    # Both of these are O(the whole pool) to build — 90 s and 30 s at 1.2 M events — and both used to be
    # built INLINE by whichever request arrived first after a version bump. They now live in
    # derived.AsyncCache: keyed on `self.version` (so a bump can only miss, never serve stale), built in
    # a background thread above `sync_limit`, single-flight, with a `status()` the endpoint reports.
    def _derived_key(self, scope: str) -> str:
        if scope == "case":
            return f"case:{self.version}:{len(self.case_set)}:{self.case_set_rev}"
        return f"{scope}:{self.version}"

    def _derived_size(self, scope: str) -> int:
        """How many events the build will walk — decides sync vs background, and drives `pct`."""
        return len(self.case_set) if scope == "case" else len(self.events)

    def _scope_events(self, scope: str) -> tuple[list[Event], np.ndarray]:
        if scope == "case":
            subset = self.case_set_events()
            ts = np.asarray([_iso_to_epoch(e.ts) for e in subset], dtype=np.float64) if subset \
                else np.zeros(0, dtype=np.float64)
            return subset, ts
        with self.lock:
            return self.events, self.ts

    def graph_v2(self, scope: str = "all"):
        """The typed graph (graph.GraphBuilder), BUILDING IT IF NEEDED. Blocking — request handlers that
        must answer promptly use `graph_v2_ready`."""
        from .graph import GRAPH_CACHE

        return GRAPH_CACHE.get(scope, self._derived_key(scope), self._derived_size(scope),
                               lambda: self._build_graph_v2(scope))

    def derived_builds_paused(self) -> bool:
        """True while the library is still loading — derived structures are NOT built then.

        Every file the loader finishes bumps the version, and every bump invalidates the graph, the
        analysis and the anomaly roll-up. The sidebar polls `/api/graph` on every page, so during a
        300 MB load Iris was starting a full graph extraction — six spawn workers, the whole pool
        packed and pickled — every few seconds, throwing each one away on the next bump. That is a
        memory and CPU storm on top of the parse itself. On the analyst's WSL2 machine it went past what
        the VM would give: workers, and twice the main process, died with SIGSEGV in plain string code
        (`graph._bucket`) — the signature of a page fault the hypervisor could not back, not a bug in
        that line. The build that matters is the ONE after the load, so that is the one that runs.
        Callers report `status.state == 'building'` with `note` while paused; the UI already renders that.

        **Phase-2 enrichment is the same storm.** Every source the enrichment worker finishes replaces
        that source's events and bumps the version, which invalidates all three derived caches — so a
        40-file enrichment run would start a full six-worker graph extraction after every file and throw
        each one away on the next bump, exactly as the library load did. The build that matters is the
        one after the queue drains. `EnrichQueue.working()` is false when no worker is live, so an
        abandoned queue cannot pause derived builds permanently.
        """
        return bool(self.pool_loading) or enrich.QUEUE.working()

    def derived_pause_note(self) -> str:
        """Why derived builds are paused, in the analyst's terms. See `derived_builds_paused`."""
        if self.pool_loading:
            return "waiting for the library load to finish"
        return "waiting for source enrichment to finish"

    def graph_v2_ready(self, scope: str = "all"):
        """The typed graph if it is current, else None with a background build started."""
        from .graph import GRAPH_CACHE

        key = self._derived_key(scope)
        if self.derived_builds_paused():
            GRAPH_CACHE.pause(scope, key, self._derived_size(scope), self.derived_pause_note())
            return None
        # Only the BACKGROUND path is cancellable. A bump lands mid-build routinely and the value this
        # build would produce is already unreachable (the key carries the version), so stopping it frees
        # a CPU-saturating extraction — and, with the multi-process path, tears the workers down instead
        # of leaving six of them burning cores on a result nothing can read. `graph_v2()` (the blocking
        # callers: report, AI review, /graph/node) must NOT be cancellable: they legitimately wait, and
        # raising into them would turn an ingest during a report into a 500.
        return GRAPH_CACHE.ready(scope, key, self._derived_size(scope),
                                 lambda: self._build_graph_v2(scope, cancel_key=key))

    def graph_status(self, scope: str = "all") -> dict[str, Any]:
        from .graph import GRAPH_CACHE

        return GRAPH_CACHE.status(scope, self._derived_key(scope))

    def _build_graph_v2(self, scope: str, cancel_key: Optional[str] = None):
        from . import graph_store
        from .graph import GRAPH_CACHE, GraphBuilder

        events, _ = self._scope_events(scope)
        # `_scope_events` took and released the store lock; nothing below holds it. The multi-process
        # extraction dispatches from THIS thread, so holding it here would put the store lock in the
        # hands of a thread that blocks on subprocesses.
        cancelled = (lambda: self._derived_key(scope) != cancel_key) if cancel_key else None
        # A restart re-parses the same library into the same pool; the graph built last time is that
        # pool's graph. graph_store keys on the pool's CONTENT and stores event references as ids, so
        # a hit is exact and a miss is silent. This is what makes the graph usable within seconds of a
        # restart instead of after a 60-190 s extraction.
        sig = graph_store.signature(self, scope)
        pre = graph_store.load(self, scope, sig)
        gb = GraphBuilder(events, progress=lambda i: GRAPH_CACHE.tick(scope, i), cancelled=cancelled,
                          preloaded=pre)
        if pre is None and events:
            graph_store.save(self, scope, gb, sig)
        return gb

    def analysis(self, scope: str = "all") -> dict[str, Any]:
        """Cached correlation output (clusters, entities, edges, correlations), BUILDING IF NEEDED.

        scope='case' re-runs the analyzer over ONLY the case-set events, so clusters/graph/baselines
        describe the curated subset rather than filtering the full-corpus result.
        """
        from .correlate import ANALYSIS_CACHE

        return ANALYSIS_CACHE.get(scope, self._derived_key(scope), self._derived_size(scope),
                                  lambda: self._build_analysis(scope))

    def analysis_ready(self, scope: str = "all") -> Optional[dict[str, Any]]:
        from .correlate import ANALYSIS_CACHE

        if self.derived_builds_paused():
            ANALYSIS_CACHE.pause(scope, self._derived_key(scope), self._derived_size(scope),
                                 self.derived_pause_note())
            return None
        return ANALYSIS_CACHE.ready(scope, self._derived_key(scope), self._derived_size(scope),
                                    lambda: self._build_analysis(scope))

    def analysis_status(self, scope: str = "all") -> dict[str, Any]:
        from .correlate import ANALYSIS_CACHE

        return ANALYSIS_CACHE.status(scope, self._derived_key(scope))

    def _build_analysis(self, scope: str) -> dict[str, Any]:
        from .correlate import ANALYSIS_CACHE, analyze

        events, ts = self._scope_events(scope)
        return analyze(events, ts, progress=lambda i: ANALYSIS_CACHE.tick(scope, i))

    def cached_analysis(self, scope: str = "all") -> Optional[dict[str, Any]]:
        """The analysis ONLY if it is already built. Never builds, never starts a build — for callers
        that merely want to enrich a number they are already returning (see `_entity_count`)."""
        from .correlate import ANALYSIS_CACHE

        return ANALYSIS_CACHE.peek(scope, self._derived_key(scope))

    def _pool_progress(self) -> Optional["PoolProgress"]:
        """Byte-level progress of the background pool load, including the file being parsed right now.

        Callers must hold the store lock (case() does). The per-file share comes from the live parse
        tracker, so a single 263 MB file still shows movement instead of a frozen "16 more sources".
        """
        from .jobs import PARSE_PROGRESS

        if not self.pool_loading:
            return None
        rows = PARSE_PROGRESS.active()
        cur = max(rows, key=lambda r: r["bytesTotal"]) if rows else None
        cur_done = int(cur["bytesDone"]) if cur else 0
        cur_total = int(cur["bytesTotal"]) if cur else 0
        done = self.pool_bytes_done + min(cur_done, cur_total)
        total = max(self.pool_bytes_total, done)
        elapsed = max(1e-3, time.time() - self.pool_started_ts) if self.pool_started_ts else 1e-3
        rate = done / elapsed
        eta = int((total - done) / rate) if (total > done and rate > 1.0) else None
        return PoolProgress(
            bytesDone=int(done), bytesTotal=int(total),
            pct=round(min(100.0, done / total * 100.0), 1) if total else 0.0,
            filesDone=self.pool_loaded, filesTotal=self.pool_loaded + self.pool_pending,
            currentFile=(cur["file"] if cur else self.pool_current_file),
            currentBytesDone=cur_done, currentBytesTotal=cur_total,
            currentPct=round(min(100.0, cur_done / cur_total * 100.0), 1) if cur_total else 0.0,
            workers=int(cur["workers"]) if cur else 1,
            bytesPerSec=int(rate), etaSec=eta, elapsedSec=int(elapsed),
            files=self._pool_files(cur))

    def _pool_files(self, cur: Optional[dict[str, Any]]) -> list["PoolFileProgress"]:
        """The per-file half of poolProgress: every file in the plan with its state, and live bytes for
        the one being parsed right now."""
        out: list[PoolFileProgress] = []
        for row in self.pool_plan.values():
            size = int(row.get("size") or 0)
            state = str(row.get("state") or "pending")
            if state == "done":
                done, pct = size, 100.0
            elif state == "parsing" and cur and cur.get("file") == row.get("file"):
                done = min(int(cur["bytesDone"]), int(cur["bytesTotal"]) or size or 0)
                pct = round(min(100.0, done / size * 100.0), 1) if size else 0.0
            else:
                done, pct = 0, 0.0
            out.append(PoolFileProgress(file=str(row.get("file") or ""), size=size, state=state,  # type: ignore[arg-type]
                                        bytesDone=int(done), pct=pct, events=int(row.get("events") or 0)))
        return out

    # ------------------------------------------------------- headline statistics
    def _entity_count(self) -> int:
        """Distinct entities across the pool — served from a cache, refreshed in the background.

        This is a `set()` union over every entity of every event: on a 2.3 M-event pool it takes many
        seconds, and `GET /api/case` recomputed it on EVERY request while holding the store lock. It is a
        posture number, so a value one version old is perfectly good; what is not acceptable is a UI poll
        that blocks for 15 s behind an ingest. The refresh runs at most one thread at a time and reads
        `self.events` without the lock (the list is only ever replaced, never mutated in place).
        """
        a = self.cached_analysis()   # free if the analysis happens to be built; never builds one
        with self.lock:
            if a is not None:
                self._entities_count = len(a["entities"])
                self._entities_version = self.version
                return self._entities_count
            if self._entities_version == self.version:
                return self._entities_count
            if not self.events:
                self._entities_count = 0
                self._entities_version = self.version
                return 0
            if self._entities_busy:
                return self._entities_count
            self._entities_busy = True
            version = self.version
            events = self.events

        def run() -> None:
            try:
                count = len({x for e in events for x in e.entities})
            except Exception:
                count = self._entities_count
            with self.lock:
                self._entities_count = count
                self._entities_version = version
                self._entities_busy = False

        threading.Thread(target=run, daemon=True).start()
        return self._entities_count

    # ---------------------------------------------------- two-phase ingest status
    def enrichment(self) -> CaseEnrichment:
        """How much of the pool has been through phase 2 (see app/enrich.py).

        Derived from the PER-SOURCE metadata — `Source.enrich`, a few dozen entries — and never from a
        walk of `self.events`. `GET /api/case` must stay O(1) in the event count (it was 15-20 s on a
        2.5 M-event pool when it re-counted coverage and entities per request), and this is exactly the
        kind of "just one more tally" that put it there.

        `pending` and `outstanding` answer different questions and both are needed:
          * `pending` = queued + enriching — is work in flight? It is what a progress banner counts down.
          * `outstanding` = raw + queued + enriching — is my ANSWER incomplete? Those sources are in the
            pool as raw lines, so the timeline, the entity graph and the detections are running over part
            of the corpus, and every screen that shows one has to say so.
        A `skipped` source is deliberately in neither: the analyst declined it, and a warning that can
        never be cleared is noise.
        """
        # queue status is read OUTSIDE the store lock: the enrichment worker takes the queue lock and the
        # store lock (never nested, but never in this order either), and taking them the other way round
        # here is how a lock-order inversion gets introduced by accident.
        q = enrich.QUEUE.status()
        tally: Counter[str] = Counter()
        with self.lock:
            for src in self.sources.values():
                tally[src.enrich] += 1
        # a state EnrichCounts does not declare would be a models.py/store.py disagreement, not evidence:
        # drop it rather than 500 the one endpoint every screen polls
        counts = EnrichCounts(**{k: v for k, v in tally.items() if k in EnrichCounts.model_fields})
        pending = counts.queued + counts.enriching
        running = str(q.get("running") or "")
        # Live detail for the source in phase 2 right now. On a big pool a source takes tens of
        # seconds, so a bare "1 running" changes once a minute and reads as frozen; the tracker
        # already holds the file, the phase and the percentage, and this is the one place the UI can
        # get them without another request per source.
        # The queue names what it POPPED, and it holds that name through the batch commit that
        # follows — during which the source is already `enriched`. Reporting it as running is how the
        # banner came to say "Interpreting capture20110811.binetflow" about a finished file, and to
        # count one of the three queued sources as that file, leaving "2 waiting behind it".
        if running:
            with self.lock:
                live = self.sources.get(running)
            if live is None or live.enrich != "enriching":
                running = ""
        file_name, pct, phase, eta = "", None, "", None
        if running:
            from .jobs import PARSE_PROGRESS

            row = PARSE_PROGRESS.get(running)
            with self.lock:
                src = self.sources.get(running)
            file_name = (src.file if src else "") or (row or {}).get("file", "")
            if row:
                pct = row.get("pct")
                phase = str(row.get("phase") or "")
                eta = row.get("etaSec")
        # `raw` with nothing in flight means automatic interpretation is off and only the analyst can
        # move it; `error` means the parse failed and can be retried. Both need a person, which is a
        # different sentence from "work is in flight".
        needs = counts.error + (counts.raw if pending == 0 else 0)
        activity = self._enrich_activity(q, running, file_name, pct, eta, counts)
        return CaseEnrichment(counts=counts, running=running, pending=pending, activity=activity,
                              outstanding=counts.raw + pending,
                              committing=bool(q.get("committing")),
                              runningFile=file_name, runningPct=pct, runningPhase=phase,
                              runningEtaSec=eta, needsAction=needs)

    @staticmethod
    def _enrich_activity(q: dict, running: str, file_name: str, pct, eta, counts) -> EnrichActivity:
        """Turn the queue's phase into the sentence the analyst reads.

        Every branch names WHAT is happening and, where the number exists, HOW BIG it is. The merge one
        matters most: it is the longest thing here, it belongs to no single source, and saying "1 queued
        to interpret" while it runs is how a working app reads as a hung one.
        """
        merge = enrich.MERGE.snapshot()
        phase = str(q.get("phase") or "idle")
        elapsed = int(q.get("phaseElapsedSec") or 0)
        if merge:
            n, ev = merge["sources"], merge["events"]
            stage = merge.get("stage") or ""
            return EnrichActivity(
                kind="merging", elapsedSec=int(merge.get("elapsedSec") or 0),
                sources=n, events=ev, stage=stage,
                stageIndex=int(merge.get("stageIndex") or 0), stageCount=int(merge.get("stageCount") or 0),
                detail=(f"Merging {n} interpreted source{'' if n == 1 else 's'} into the pool "
                        f"({ev:,} events) — {stage}. This rebuilds the whole pool index and takes "
                        f"minutes at this size; anything queued waits for it."))
        if phase == "noWorker":
            return EnrichActivity(kind="noWorker", elapsedSec=elapsed,
                                  detail="Nothing is servicing the interpretation queue — these sources "
                                         "stay raw until Iris is restarted. Their lines are still in the "
                                         "pool and still searchable.")
        if phase == "waitingForPool":
            return EnrichActivity(kind="waitingForPool", elapsedSec=elapsed,
                                  detail="Waiting for the library to finish loading before interpreting "
                                         "anything — the two would otherwise compete for the machine.")
        if running:
            return EnrichActivity(kind="parsing", elapsedSec=elapsed, file=file_name or running,
                                  pct=pct, etaSec=eta,
                                  detail=f"Interpreting {file_name or running}"
                                         + (f" — {pct:.0f}%" if isinstance(pct, (int, float)) else ""))
        if counts.queued:
            # Queued with no phase to explain it: the worker is between items. Say that rather than
            # implying something is being read.
            return EnrichActivity(kind="idle", elapsedSec=elapsed,
                                  detail=f"{counts.queued} source{'' if counts.queued == 1 else 's'} "
                                         "waiting for the interpretation worker.")
        return EnrichActivity(kind="idle", elapsedSec=elapsed)

    # ---------------------------------------------------------------- case
    def case(self) -> Case:
        """The workspace as the UI sees it.

        `sources` / `eventCount` describe the CASE (empty while no case exists); `librarySources` /
        `poolEventCount` describe the whole analysable pool, which is what Search, Timeline, Anomalies and
        the graph run over. Posture and queue describe the pool too — they are workbench health, not case
        documentation.
        """
        enrichment = self.enrichment()   # takes the store lock itself, so before the `with` below
        # Live parse detail, attached per response. One lock acquisition for the whole tracker (it holds
        # a handful of rows at most) and then a dict lookup per source — never a call per source, on the
        # most-polled endpoint in the app. It is attached to a COPY: `self.sources` holds the real
        # objects, and stamping a percentage onto them would leave a finished file claiming 84 % forever.
        from .jobs import PARSE_PROGRESS

        live = PARSE_PROGRESS.all_rows()

        def _with_progress(src: Source) -> Source:
            row = live.get(src.id) if live else None
            if row is None:
                return src
            # Only while the source is genuinely being read. A tracker row can outlive the work by a
            # moment (finish() is the last statement of the parse), and a READY source showing a live
            # percentage is a claim about work that is over.
            if src.state != "PARSING" and src.enrich != "enriching":
                return src
            return src.model_copy(update={"progress": ParseProgressInfo(**row)})

        with self.lock:
            case_ids_ = self.case_source_ids()
            sources = [_with_progress(self.sources[s]) for s in case_ids_]
            lib_sources = [_with_progress(self.sources[s]) for s in self.library_source_ids()]
            case_events = sum(self.sources[s].events for s in case_ids_)
            pool_sources = [self.sources[s] for s in self.source_order if s in self.sources]
            n = len(self.events)
            # both of these used to be full scans of the pool, under this lock, on every single request
            parse_errors = sum(self.source_parse_errors.get(s, 0) for s in self.sources)
            parsed_ok = max(0, n - parse_errors)
            coverage = (parsed_ok / n * 100.0) if n else 0.0
            skew_count = len(self.skews)
            max_skew = max(self.skews.values()) if self.skews else 0.0
            fired = self.rules_fired
            ent_count = self._entity_count()
            unmapped_files = [s for s in pool_sources if s.state == "MAP"]
            posture = [
                Posture(label="Parse coverage", value=f"{coverage:.1f}%", pct=round(coverage, 1),
                        color="ok" if coverage >= 95 else "warn" if coverage >= 80 else "bad"),
                Posture(label="Unmapped fields", value=str(self.unmapped_fields + len(unmapped_files) * 7),
                        pct=min(100.0, (self.unmapped_fields + len(unmapped_files) * 7) * 1.5),
                        color="ok" if not unmapped_files and self.unmapped_fields == 0 else "warn"),
                Posture(label="Clock skew corrected", value=f"{skew_count} source{'s' if skew_count != 1 else ''}",
                        pct=(skew_count / max(1, len(pool_sources)) * 100.0) if pool_sources else 0.0, color="ok"),
                Posture(label="Detections fired", value=str(fired), pct=min(100.0, fired * 6.0),
                        color="bad" if fired else "ok"),
            ]
            queue = [
                QueueItem(label="Timestamps normalized to UTC",
                          detail=f"{skew_count} skews, max {int(round(max_skew))}s" if skew_count else "no skew detected", done=n > 0),
                QueueItem(label="Entity extraction — IP, user, host, PID", detail=f"{ent_count} entities", done=n > 0),
                QueueItem(label=f"Field mapping for {unmapped_files[0].file}" if unmapped_files else "Field mapping",
                          detail="awaiting review" if unmapped_files else "all sources mapped", done=not unmapped_files),
                QueueItem(label="Sigma ruleset evaluation", detail=f"{len(RULES)} of {len(RULES)} rules" if n else "waiting for data", done=n > 0),
            ]
            return Case(id=self.case_id, name=self.name, summary=self.summary, analyst=self.analyst,
                        createdAt=to_iso(self.created_at),
                        sources=sources, eventCount=case_events, librarySources=lib_sources, poolEventCount=n,
                        poolLoading=self.pool_loading, poolPending=self.pool_pending, poolLoaded=self.pool_loaded,
                        poolProgress=self._pool_progress(),
                        poolSkipped=self.pool_skipped, poolSkippedFiles=list(self.pool_skips.values()),
                        poolBudgetBytes=pool_budget_bytes(), enrichment=enrichment,
                        caseSet=list(self.case_set.values()), notes=self.notes, pending=self.pending,
                        posture=posture, queue=queue)


def _load_notes(raw: Any) -> list[CaseNote]:
    """Parse persisted notes, migrating the earlier single-blob format into one entry."""
    if isinstance(raw, str):
        text = raw.strip()
        return [CaseNote(id="n1", text=text, createdAt=to_iso(datetime.now(UTC)))] if text else []
    out: list[CaseNote] = []
    for item in raw or []:
        try:
            out.append(CaseNote.model_validate(item))
        except Exception:
            continue
    return out


def _clean_labels(labels: Optional[list[str]]) -> list[str]:
    """Trim, drop blanks, de-duplicate case-insensitively, keep order."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in labels or []:
        lab = str(raw).strip()
        if not lab or lab.lower() in seen:
            continue
        seen.add(lab.lower())
        out.append(lab)
    return out


# Sort key for a pool that may hold unstamped events. An empty `ts` is UNKNOWN, not 1970: it sorts after
# every known time (so a timeline never opens with a wall of undated lines) and, as +inf in the epoch
# array, falls outside every from/to window — an event whose time nobody knows is not known to be inside
# one. `ts_key` and `_iso_to_epoch` must agree on that ordering or the array and the list disagree.
def ts_key(e: "Event") -> tuple[int, str]:
    return (1, "") if not e.ts else (0, e.ts)


def _iso_to_epoch(s: str) -> float:
    """Epoch seconds from the one timestamp format Iris stores (`to_iso`).

    Hand-parsed rather than `datetime.strptime`, which costs ~8.6 us a call: this runs once per event on
    every append, and the append re-indexes the WHOLE pool, so on a 1.7 M-event pool strptime alone was
    ~15 s of the ingest. calendar.timegm on sliced ints is ~5x faster; anything that does not match the
    fixed layout falls back to the general parser.
    """
    if not s:
        return float("inf")   # unknown — sorts last, matches no window
    try:
        return float(timegm((int(s[0:4]), int(s[5:7]), int(s[8:10]),
                             int(s[11:13]), int(s[14:16]), int(s[17:19]), 0, 0, 0)))
    except (ValueError, IndexError):
        try:
            return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
        except ValueError:
            return float("inf")


def _build_index(events: list) -> dict:
    """`{e.id: i}` over the whole pool.

    This was briefly chunked with a `time.sleep(0)` between blocks, on the theory that a 13.8 M-iteration
    Python loop starves every other thread and is why `/api/case` could not answer during a merge. That
    theory is WRONG and the note is kept so it is not re-derived: CPython already releases the GIL every
    `sys.getswitchinterval()` (5 ms by default) between bytecodes, so a long pure-Python loop is
    preempted whether or not it yields, and the mutation test could not tell the two versions apart.

    What actually made the merge unanswerable was memory pressure (the machine swapping) plus one core
    saturated — and `merged.sort(key=...)`, which precomputes the keys in Python and then compares them
    in C without releasing the GIL at all. That one is a genuine multi-second stall and no amount of
    yielding elsewhere fixes it. The answer to "what is it waiting on?" is therefore to SAY so
    (`enrich.MergeProgress`), not to pretend the wait can be chunked away.
    """
    return {e.id: i for i, e in enumerate(events)}


def _epochs(events: list[Event]) -> np.ndarray:
    """Timestamp array for a ts-SORTED event list. Consecutive events almost always share a timestamp
    (second granularity), so the previous conversion is reused instead of redone."""
    out = np.empty(len(events), dtype=np.float64)
    prev_s: Optional[str] = None
    prev_v = 0.0
    for i, e in enumerate(events):
        s = e.ts
        if s != prev_s:
            prev_v = _iso_to_epoch(s)
            prev_s = s
        out[i] = prev_v
    return out


STORE = Store()
