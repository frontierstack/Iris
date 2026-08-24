"""Phase 2 parses SMALL sources in parallel: many files, many processes, one merge."""
import pathlib


def edit(path, pairs):
    p = pathlib.Path(path)
    s = p.read_text(encoding="utf-8")
    for old, new in pairs:
        assert old in s, f"NOT FOUND in {path}:\n{old[:250]}"
        s = s.replace(old, new, 1)
    p.write_text(s, encoding="utf-8")
    print("patched", path)


# ---------------------------------------------------------------- the worker task
edit("app/parsers/parallel.py", [
    ('''@dataclass
class Plan:''',
     '''def parse_whole(path, member: str, parser: BaseParser, sid: str, filename: str, family: str) -> list:
    """WORKER ENTRY POINT: parse one WHOLE small file and return its normalized batches.

    The chunked path above splits a big file across processes. This is the other shape of the
    problem: a queue of many small files, each parsed in a second, one after another on the single
    enrichment worker — pure-Python, GIL-bound, so threads could not help and the queue drained one
    core wide. Here each small file IS the unit of work: one process per file, the parent only
    commits. The bytes are read here, in the worker, so the parent never holds them.
    """
    from pathlib import Path as _P
    from . import archives
    p = _P(path)
    data = archives.read_member(p, member) if member else p.read_bytes()
    parsed = list(parser.parse_bytes(data))
    del data
    return [normalize_batch(parsed, sid, filename, family)]


@dataclass
class Plan:'''),
])

# ---------------------------------------------------------------- the store: parse and commit can be split
edit("app/store.py", [
    ('''    def enrich_source(self, sid: str) -> "enrich.EnrichResult":''',
     '''    def enrich_task(self, sid: str) -> Optional[tuple]:
        """What a worker process needs to parse this source on its own: (path, member, parser, file,
        family, size). None when the source is gone or already settled. Marks it `enriching`."""
        with self.lock:
            src = self.sources.get(sid)
            path = self.source_paths.get(sid)
            parser = self.source_parsers.get(sid)
            member = self.source_member.get(sid, "")
            if src is None or path is None or parser is None or src.enrich in ("enriched", "skipped"):
                return None
            src.enrich = "enriching"  # type: ignore[assignment]
            size = src.size
        from .jobs import PARSE_PROGRESS
        PARSE_PROGRESS.start(sid, src.file, size)
        PARSE_PROGRESS.advance(sid, done=0, phase="enriching")
        return (str(path), member, parser, src.file, parser.family, size)

    def enrich_source(self, sid: str, batches: Optional[list] = None) -> "enrich.EnrichResult":'''),
    ('''        with self.lock:
            src.enrich = "enriching"  # type: ignore[assignment]
        try:
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
            PARSE_PROGRESS.advance(sid, done=len(data), phase="finishing", stage_pct=0)''',
     '''        with self.lock:
            src.enrich = "enriching"  # type: ignore[assignment]
        data = b""
        if batches is None:
            try:
                data = self.source_bytes(sid)
                PARSE_PROGRESS.start(sid, src.file, len(data))
                PARSE_PROGRESS.advance(sid, done=0, phase="enriching")
            except (OSError, KeyError, ValueError) as exc:
                with self.lock:
                    src.enrich, src.enrichError = "error", str(exc)  # type: ignore[assignment]
                return enrich.EnrichResult(sid=sid, ok=False, error=str(exc))
        old_ids = [e.id for e in self.events if e.sourceId == sid]
        try:
            # `batches` already parsed (in a worker process, see EnrichQueue) skips straight to the commit
            if batches is None:
                batches = self._parse_batches(sid, src, parser, data)
            PARSE_PROGRESS.advance(sid, done=len(data) if data else src.size, phase="finishing", stage_pct=0)'''),
])

# ---------------------------------------------------------------- the queue: parallel parse of small sources
edit("app/enrich.py", [
    ('''BATCH_MAX = 25
BATCH_SECONDS = 30.0''',
     '''BATCH_MAX = 25
BATCH_SECONDS = 30.0
# Small sources are parsed in PARALLEL processes (one file per worker) and committed here in order.
# Big ones keep the chunked pool. Bound is the memory-aware worker count, never more than this.
PARALLEL_SMALL_MAX = 6'''),
    ('''                with self._lock:
                    more_waiting = bool(self._q)
                batching = getattr(store, "enrich_batch", None) if more_waiting else None''',
     '''                with self._lock:
                    more_waiting = bool(self._q)
                batching = getattr(store, "enrich_batch", None) if more_waiting else None
                # Many SMALL files waiting: parse them side by side in worker processes and commit each
                # as it lands. The parse is pure-Python and GIL-bound, so on one worker a queue of
                # forty one-second files took forty seconds a core; across processes it takes about
                # forty divided by the workers the machine can hold.
                small = self._peel_small(sid, store) if more_waiting else []
                if small:
                    self._parse_small_parallel(small, store, batching)
                    continue'''),
    ('''    # --------------------------------------------------------------- worker
    def start(self, store: "Store") -> None:''',
     '''    def _peel_small(self, first: str, store: "Store") -> list[str]:
        """Take the run of small queued sources (the current one included) for parallel parsing."""
        try:
            from .graph_parts import workers_by_memory
            from .parsers.parallel import min_parallel_bytes
            cap = min(PARALLEL_SMALL_MAX, workers_by_memory(PARALLEL_SMALL_MAX))
        except Exception:
            return []
        if cap < 2:
            return []
        limit = min_parallel_bytes()

        def small(sid: str) -> bool:
            src = getattr(store, "sources", {}).get(sid)
            return src is not None and 0 < src.size < limit and src.enrich in ("queued", "raw", "error")

        if not small(first):
            return []
        out = [first]
        with self._lock:
            while self._q and len(out) < cap and small(self._q[0]):
                out.append(self._q.pop(0))
        return out if len(out) >= 2 else []

    def _parse_small_parallel(self, sids: list[str], store: "Store", batching) -> None:
        """Parse `sids` in worker processes; commit each in the parent, in completion order."""
        import contextlib
        from concurrent.futures import ProcessPoolExecutor, as_completed
        from multiprocessing import get_context
        from .parsers.parallel import background_worker_init, parse_whole
        tasks = {}
        for sid in sids:
            t = store.enrich_task(sid)
            if t is not None:
                tasks[sid] = t
        if not tasks:
            return
        with self._lock:
            self._committing = True
        self._set_phase("parsing")
        try:
            pool = ProcessPoolExecutor(max_workers=min(len(tasks), PARALLEL_SMALL_MAX),
                                       mp_context=get_context("spawn"), initializer=background_worker_init)
        except Exception as exc:
            log.warning("parallel enrichment unavailable (%s); parsing one at a time", exc)
            with (batching() if batching else contextlib.nullcontext()):
                for sid in tasks:
                    self.last[sid] = store.enrich_source(sid)
            return
        try:
            futs = {pool.submit(parse_whole, *t): sid for sid, t in tasks.items()}
            with (batching() if batching else contextlib.nullcontext()):
                for fut in as_completed(futs):
                    sid = futs[fut]
                    with self._lock:
                        self._current = sid
                    try:
                        batches = fut.result()
                    except Exception as exc:          # a worker failed on this file: parse it here
                        log.warning("parallel parse of %s failed (%s); parsing in-process", sid, exc)
                        self.last[sid] = store.enrich_source(sid)
                        continue
                    try:
                        self.last[sid] = store.enrich_source(sid, batches=batches)
                    except Exception as exc:  # one bad file must not lose the batch
                        self.last[sid] = EnrichResult(sid=sid, ok=False, error=f"{type(exc).__name__}: {exc}")
        finally:
            pool.shutdown(wait=True)
            with self._lock:
                self._current = ""
                self._committing = False
            self._set_phase("idle")

    # --------------------------------------------------------------- worker
    def start(self, store: "Store") -> None:'''),
])
