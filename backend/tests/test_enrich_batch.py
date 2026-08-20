"""Phase 2 commits in BATCHES, and a batched run must be indistinguishable from a per-source one.

The merge that puts a source's parsed events into the pool is O(the WHOLE pool) however little
changed — a new list, a sort, an id index and a timestamp array over every event in the workspace.
Measured on the analyst's 11.4 M-event pool that was ~45 s per source, so a queue of forty small text
files took half an hour with almost none of the time spent parsing. Batching turns forty merges into
one.

That is a change to how evidence enters the pool, so the tests here are about SAMENESS, not speed:
same events, same ids, same order, same detections, same per-source metadata, same citation remapping
and the same refusal to resurrect a source that was deleted while its parse was running. The ids are
the part that must not move — case sets, notes and indicators cite them.
"""
from __future__ import annotations

import pytest

from app import config, enrich
from app.store import STORE

LOG_A = b"".join(
    f"2026-08-19T10:{i // 60:02d}:{i % 60:02d}Z hostA sshd[{i}]: Failed password for root from 10.0.0.{i % 250} port 22\n".encode()
    for i in range(120)
)
LOG_B = b"".join(
    f"2026-08-19T11:{i // 60:02d}:{i % 60:02d}Z hostB sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash{i}\n".encode()
    for i in range(90)
)
LOG_C = b"".join(
    f"2026-08-19T12:{i // 60:02d}:{i % 60:02d}Z hostC nginx: GET /admin/{i} 401 from 45.83.140.22\n".encode()
    for i in range(70)
)
LOGS = {"a.log": LOG_A, "b.log": LOG_B, "c.log": LOG_C}


@pytest.fixture(autouse=True)
def _clean():
    # DRAIN before wiping, both ways round. The session keeps an enrichment worker alive, so a wipe
    # while it holds a batch leaves that batch to commit into the next test — which is how a module
    # that looks self-contained makes an unrelated one fail three modules later.
    enrich.QUEUE.drain(10.0)
    STORE.clear_all()
    yield
    enrich.QUEUE.drain(10.0)
    STORE.clear_all()


def _stage_all() -> list[str]:
    """Stage the three logs and get them into the pool as RAW, without enriching them."""
    from app.config import update_settings
    from app.routers.library import _library_index, _write_library_index

    update_settings({"ingest": {"autoEnrich": False}})
    try:
        config.LIBRARY_DIR.mkdir(parents=True, exist_ok=True)
        names = []
        idx = _library_index()
        for i, (name, body) in enumerate(LOGS.items()):
            on_disk = f"abcdef{i:02d}_{name}"
            (config.LIBRARY_DIR / on_disk).write_bytes(body)
            idx[on_disk] = {"name": name, "size": len(body)}
            names.append((on_disk, name))
        _write_library_index(idx)
        STORE.restore_library(names)
    finally:
        update_settings({"ingest": {"autoEnrich": True}})
    return [s.id for s in STORE.sources.values()]


def _snapshot() -> list[tuple]:
    return [(e.id, e.ts, e.sev, e.msg, e.raw, e.sourceId, dict(e.fields),
             tuple(d.id for d in e.detections)) for e in STORE.events]


def _source_meta() -> dict:
    return {s.id: (s.events, s.range, s.enrich, s.state) for s in STORE.sources.values()}


def test_a_batched_run_produces_the_same_pool_as_a_per_source_run():
    sids = _stage_all()
    for sid in sids:                                   # the old behaviour: one merge per source
        STORE.enrich_source(sid)
    one_by_one, meta_one = _snapshot(), _source_meta()
    assert one_by_one and all(m[2] == "enriched" for m in meta_one.values())

    STORE.clear_all()
    sids = _stage_all()
    with STORE.enrich_batch():                          # the new behaviour: one merge for all three
        for sid in sids:
            STORE.enrich_source(sid)
    batched, meta_batched = _snapshot(), _source_meta()

    assert [row[0] for row in batched] == [row[0] for row in one_by_one], "event ids moved"
    assert batched == one_by_one
    assert sorted(meta_batched.values()) == sorted(meta_one.values())


def test_the_merge_happens_once_for_the_whole_batch():
    """The entire point: N sources, one O(pool) merge."""
    sids = _stage_all()
    merges = {"n": 0}
    from app import store as store_mod

    real = store_mod.Store._swap_many

    def counted(self, by_source, remap):
        merges["n"] += 1
        return real(self, by_source, remap)

    store_mod.Store._swap_many = counted                # type: ignore[assignment]
    try:
        with STORE.enrich_batch():
            for sid in sids:
                STORE.enrich_source(sid)
    finally:
        store_mod.Store._swap_many = real               # type: ignore[assignment]
    assert merges["n"] == 1, f"{len(sids)} sources took {merges['n']} merges"
    assert len(STORE.events) == sum(len(v.splitlines()) for v in LOGS.values())


def test_events_are_not_in_the_pool_until_the_batch_commits():
    """A source stays `enriching` until its parsed rows are actually searchable. Claiming `enriched`
    while the events are still held back would be a lie about what a search can find."""
    sids = _stage_all()
    with STORE.enrich_batch():
        STORE.enrich_source(sids[0])
        src = STORE.sources[sids[0]]
        assert src.enrich == "enriching"
        # still the RAW rows: they carry the timestamp phase 1 read, but no parsed fields
        assert all(not e.fields for e in STORE.events if e.sourceId == sids[0])
    assert STORE.sources[sids[0]].enrich == "enriched"
    assert any(e.ts for e in STORE.events if e.sourceId == sids[0])


def test_the_batch_commits_even_when_one_source_fails(monkeypatch):
    sids = _stage_all()
    bad = sids[1]
    from app import store as store_mod

    real = store_mod.Store._parse_batches

    def explode(self, sid, *a, **k):
        if sid == bad:
            raise ValueError("unterminated record")
        return real(self, sid, *a, **k)

    # the CLASS, not the instance: `monkeypatch.setattr(STORE, ...)` undoes itself by SETTING the old
    # bound method back, which leaves an instance attribute shadowing the class for the rest of the
    # session — and the next module's class-level patch of the same method then silently does nothing
    monkeypatch.setattr(store_mod.Store, "_parse_batches", explode)
    with STORE.enrich_batch():
        for sid in sids:
            STORE.enrich_source(sid)

    assert STORE.sources[bad].enrich == "error"
    assert STORE.sources[bad].state == "ERROR"
    for sid in (sids[0], sids[2]):
        assert STORE.sources[sid].enrich == "enriched", "one bad file must not lose the batch"


def test_a_source_deleted_during_the_batch_is_not_resurrected():
    """The window between parsing and committing is longer with a batch, so the check that the source
    still exists has to happen at COMMIT time as well."""
    sids = _stage_all()
    with STORE.enrich_batch():
        for sid in sids:
            STORE.enrich_source(sid)
        gone = sids[0]
        STORE.delete_source(gone)
    assert gone not in STORE.sources
    assert not any(e.sourceId == gone for e in STORE.events), "deleted evidence came back"
    for sid in sids[1:]:
        assert STORE.sources[sid].enrich == "enriched"


def test_a_batch_always_closes_even_if_the_body_raises():
    """`enrich_batch` is a context manager; an exception inside it must still commit what was parsed,
    or those sources sit at `enriching` for the life of the process."""
    sids = _stage_all()
    with pytest.raises(RuntimeError):
        with STORE.enrich_batch():
            STORE.enrich_source(sids[0])
            raise RuntimeError("something went wrong mid-batch")
    assert STORE.sources[sids[0]].enrich == "enriched"
    assert STORE.enrich_batch_size() == 0


def test_the_queue_batches_a_run_of_sources():
    """End to end through the worker, which is what actually drives this in the app.

    The worker is stopped for the staging: the session has one running, and a live worker picks each
    file up AS IT IS STAGED — one source per batch, which measures the test's timing rather than the
    code. The real sequence is the other way round (a library load fills the queue, the lifespan
    starts the worker), and that is what is reproduced here.
    """
    enrich.QUEUE.stop()
    sids = _stage_all()
    merges = {"n": 0}
    from app import store as store_mod

    real = store_mod.Store._swap_many

    def counted(self, by_source, remap):
        merges["n"] += 1
        return real(self, by_source, remap)

    store_mod.Store._swap_many = counted                # type: ignore[assignment]
    try:
        # Queue everything, THEN start the worker — which is the real sequence: a library load (or
        # `requeue_unenriched` on startup) fills the queue and the lifespan starts the worker after.
        # Starting first makes the worker drain each source before the next is submitted, so there is
        # nothing to batch, which is a property of the test rather than of the code.
        for sid in sids:
            STORE.queue_enrichment(sid)
        enrich.QUEUE.start(STORE)
        assert enrich.QUEUE.drain(30.0)
    finally:
        store_mod.Store._swap_many = real               # type: ignore[assignment]
        # Leave the session as it was found: a LIVE worker. Stopping it here and walking away is how
        # a later module's phase-2 test silently never runs (the source just stays queued for ever).
        enrich.QUEUE.start(STORE)

    assert all(s.enrich == "enriched" for s in STORE.sources.values())
    assert merges["n"] < len(sids), f"the worker merged {merges['n']} times for {len(sids)} sources"
