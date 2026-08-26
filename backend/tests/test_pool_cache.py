"""The parsed pool survives a restart (app/pool_store.py).

The analyst's question was "why does it have to reparse every single time". It did, because nothing
about the pool was persisted: every start re-read the staged library, ran phase 1 over all of it, and
then re-queued every source for phase 2 because a re-parsed source comes back `raw`. That is hours of
work with unchanged inputs — and while that queue runs, derived builds are paused, so the graph is
blank for the duration.

What these tests pin is not the speed. It is that a cached source is INDISTINGUISHABLE from a parsed
one — same ids, same messages, same fields, same detections — and that every reason to distrust an
entry (a changed file, a foreign tag, a missing member, an unknown parser) parses instead.
"""
from __future__ import annotations

import pytest

from app import config, pool_store
from app.models import Detection
from app.store import STORE

LOG = (b"2026-08-19T10:00:00Z host1 sshd[11]: Failed password for root from 10.0.0.5 port 22 ssh2\n"
       b"2026-08-19T10:00:01Z host1 sshd[11]: Failed password for root from 10.0.0.5 port 22 ssh2\n"
       b"2026-08-19T10:00:02Z host1 sshd[12]: Accepted password for alice from 10.0.0.9 port 22 ssh2\n")


@pytest.fixture(autouse=True)
def _clean():
    pool_store.clear()
    STORE.clear_all()
    yield
    pool_store.clear()
    STORE.clear_all()


def _stage(name: str = "srv.log", data: bytes = LOG) -> str:
    """Put a file in the library the way staging does."""
    from app.routers.library import _library_index, _write_library_index

    config.LIBRARY_DIR.mkdir(parents=True, exist_ok=True)
    on_disk = f"abcdef01_{name}"
    (config.LIBRARY_DIR / on_disk).write_bytes(data)
    idx = _library_index()
    idx[on_disk] = {"name": name, "size": len(data)}
    _write_library_index(idx)
    return on_disk


def _load_pool(on_disk: str, display: str = "srv.log") -> int:
    return STORE.restore_library([(on_disk, display)])


def _enrich_everything() -> None:
    """Every source through phase 2, whoever runs it.

    The background worker is live in the test session, so a source can be `enriching` by the time this
    is called — enriching it again here would be a second pass over the same file. Wait for the queue
    first, then pick up anything auto-enrichment did not take.
    """
    from tests.conftest import drain_enrichment

    drain_enrichment()
    for sid in list(STORE.sources):
        if STORE.sources[sid].enrich in ("raw", "queued"):
            STORE.enrich_source(sid)
    drain_enrichment()


def _snapshot() -> list[tuple]:
    return [(e.id, e.ts, e.sev, e.msg, e.raw, e.file, dict(e.fields), list(e.entities),
             tuple(d.id for d in e.detections)) for e in STORE.events]


def _forget_memory() -> None:
    """A restart, as far as the pool is concerned: memory gone, disk untouched."""
    STORE._clear_memory(delete_files=False, keep_library=False)


def test_a_restart_restores_the_pool_without_reparsing(monkeypatch):
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    before = _snapshot()
    assert before and all(s.enrich == "enriched" for s in STORE.sources.values())

    _forget_memory()
    # Parsing is the ONLY other way to produce events here, so failing it proves the restore path
    # served them from the cache rather than reading the file again.
    from app import store as store_mod
    monkeypatch.setattr(store_mod.Store, "_add_library_members",
                        lambda *a, **k: pytest.fail("the file was parsed again instead of restored"))
    assert _load_pool(on_disk) == 1
    assert _snapshot() == before


def test_a_restored_source_is_not_queued_for_enrichment_again():
    """Re-enrichment is the expensive half, and it is what keeps the graph paused after a restart."""
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()

    _forget_memory()
    _load_pool(on_disk)
    src = next(iter(STORE.sources.values()))
    assert src.enrich == "enriched"
    assert STORE.enrichment().outstanding == 0


def test_event_ids_are_identical_so_citations_still_resolve():
    """Case sets, notes and indicators cite event ids. A cache that renumbered them would break
    every citation in the workspace, silently."""
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    ids = [e.id for e in STORE.events]

    _forget_memory()
    _load_pool(on_disk)
    assert [e.id for e in STORE.events] == ids
    assert all(i in STORE.event_index for i in ids)


def test_the_message_is_preserved_exactly():
    """`Event.__init__` derives `_msg` from `raw`, so rebuilding through it would rewrite the message
    of every event whose msg equals its raw prefix. The unpacker sets slots directly."""
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    msgs = [e.msg for e in STORE.events]

    _forget_memory()
    _load_pool(on_disk)
    assert [e.msg for e in STORE.events] == msgs


def test_a_changed_file_is_never_served_from_the_cache():
    """A stale entry is not a slow answer — it is evidence no parser in this build produced."""
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    n_before = len(STORE.events)

    _forget_memory()
    (config.LIBRARY_DIR / on_disk).write_bytes(LOG + b"2026-08-19T10:00:03Z host1 sshd[13]: extra\n")
    _load_pool(on_disk)
    assert len(STORE.events) == n_before + 1        # re-parsed, not restored


def test_a_foreign_or_edited_entry_is_a_miss_not_a_load():
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    _forget_memory()

    member = next(p for p in (config.CACHE_DIR / "pool").glob("*.pkl"))
    blob = bytearray(member.read_bytes())
    blob[-1] ^= 0x01                                 # one byte, anywhere in the payload
    member.write_bytes(bytes(blob))

    assert _load_pool(on_disk) == 1                  # parsed instead
    assert len(STORE.events) == 3


def test_a_missing_member_makes_the_whole_file_parse():
    """A partially cached archive must never produce a partial pool."""
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    _forget_memory()

    for p in (config.CACHE_DIR / "pool").glob("*.pkl"):
        p.unlink()                                    # the manifest survives, the members do not
    assert _load_pool(on_disk) == 1
    assert len(STORE.events) == 3


def test_a_parser_this_build_does_not_have_is_re_parsed(monkeypatch):
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    _forget_memory()

    from app import store as store_mod
    monkeypatch.setattr(store_mod, "parser_by_name", lambda name: None, raising=False)
    from app.parsers import registry
    monkeypatch.setattr(registry, "parser_by_name", lambda name: None)
    assert _load_pool(on_disk) == 1
    assert len(STORE.events) == 3
    assert all(s.parser for s in STORE.sources.values())


def test_the_cache_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("IRIS_POOL_CACHE", "0")
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    pool_dir = config.CACHE_DIR / "pool"
    assert not pool_dir.exists() or not list(pool_dir.glob("*.pkl"))


def test_a_skip_decision_survives_a_restart():
    """'Skip the rest and build now' is the way out of a blocked Graph screen. A restart that
    re-queued those sources would undo the decision and start the pause again."""
    # Auto-enrichment off for this one: the background worker would otherwise interpret the file
    # between the load and the skip, and a source that is already `enriched` is correctly unskippable.
    from app.config import update_settings

    update_settings({"ingest": {"autoEnrich": False}})
    try:
        on_disk = _stage()
        _load_pool(on_disk)
        sid = next(iter(STORE.sources))
        assert STORE.skip_enrichment(sid) is True
    finally:
        update_settings({"ingest": {"autoEnrich": True}})

    _forget_memory()
    _load_pool(on_disk)
    assert STORE.sources[sid].enrich == "skipped"
    assert STORE.enrichment().outstanding == 0

    STORE.queue_enrichment(sid)                       # asking for it back cancels the decision
    assert pool_store.was_skipped(sid) is False


def test_removing_a_library_file_drops_its_cache():
    from app.routers.library import forget_staged

    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    assert list((config.CACHE_DIR / "pool").glob("*"))

    forget_staged(on_disk)
    assert not list((config.CACHE_DIR / "pool").glob(f"{pool_store._stem(on_disk)}*"))


def test_the_pipeline_digest_invalidates_the_cache_when_parsing_code_changes(monkeypatch):
    """`POOL_FORMAT` is a manual bump and forgetting it serves events no parser in this build would
    produce. The digest over the parser / normalize / models / detect sources catches it by itself."""
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    _forget_memory()

    monkeypatch.setattr(pool_store, "_PIPELINE", "different-code")
    from app import store as store_mod
    seen: list = []
    original = store_mod.Store._add_library_members
    monkeypatch.setattr(store_mod.Store, "_add_library_members",
                        lambda self, *a, **k: (seen.append(1), original(self, *a, **k))[1])
    _load_pool(on_disk)
    assert seen, "a changed pipeline must re-parse rather than serve cached events"


def test_fields_and_detections_come_back_with_the_events():
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    fired = STORE.rules_fired
    fields = [dict(e.fields) for e in STORE.events]

    _forget_memory()
    _load_pool(on_disk)
    assert [dict(e.fields) for e in STORE.events] == fields
    assert STORE.rules_fired == fired


def test_a_rule_change_is_not_hidden_by_the_cache():
    """A cached event carries the detections it was SAVED with.

    That is fine only because a library load re-runs the whole catalogue once at the end
    (`Store.load_library`), which re-stamps every event from the current rules. If that pass were ever
    dropped, a restart would resurrect detections from a rule the analyst has since turned off — a
    finding attributed to a rule that no longer says it, which is worse than a missing one.
    """
    from app.rules import RULES_STORE

    # A line that fires a plain regex rule (SIGMA-LNX-0041: sudo opening an interactive shell), so the
    # test does not depend on a burst threshold being reachable with three lines.
    log = (b"2026-08-19T10:00:00Z host1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash\n"
           b"2026-08-19T10:00:01Z host1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/su\n"
           b"2026-08-19T10:00:02Z host1 sshd[12]: Accepted password for alice from 10.0.0.9 port 22 ssh2\n")
    on_disk = _stage("sudo.log", log)
    _load_pool(on_disk, "sudo.log")
    _enrich_everything()
    fired = [(e.id, tuple(d.id for d in e.detections)) for e in STORE.events if e.detections]
    assert fired, "the fixture log must fire at least one rule for this test to mean anything"
    rule_id = fired[0][1][0]

    RULES_STORE.toggle(rule_id)                 # off
    try:
        _forget_memory()
        _load_pool(on_disk, "sudo.log")         # served from the cache, detections and all
        with STORE._detect_lock:                # the pass `load_library` runs after a restore
            STORE._run_detections()
        still = {d.id for e in STORE.events for d in e.detections}
        assert rule_id not in still, "a disabled rule survived the restore"
    finally:
        RULES_STORE.toggle(rule_id)             # back on, for whatever runs next


def test_a_source_bigger_than_one_frame_round_trips(monkeypatch):
    """The bug that made the analyst's 10 M-row DNS log re-parse on every single restart.

    A cache entry is written as a header frame plus one frame per `CHUNK` events, so only sources
    LARGER than a chunk have more than one — which is why every small file restored fine and only the
    big ones kept re-parsing. Writing those frames from one Pickler with `clear_memo()` between dumps
    put the writer's and reader's memos out of step, and the read failed on the first frame with
    "NEWOBJ class argument must be a type, not str". The file verified its HMAC and looked perfect;
    it simply could not be read, so it was silently rebuilt every boot.

    A tiny CHUNK forces the multi-frame case on a small fixture.
    """
    monkeypatch.setattr(pool_store, "CHUNK", 2)
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    before = _snapshot()
    assert len(before) > pool_store.CHUNK, "the fixture must span more than one frame"

    entry = next(p for p in (config.CACHE_DIR / "pool").glob("*.pkl"))
    assert entry.stat().st_size > 0

    _forget_memory()
    from app import store as store_mod
    monkeypatch.setattr(store_mod.Store, "_add_library_members",
                        lambda *a, **k: pytest.fail("a multi-frame entry was re-parsed instead of restored"))
    assert _load_pool(on_disk) == 1
    assert _snapshot() == before


def test_events_carrying_objects_survive_the_frames(monkeypatch):
    """Detections are pydantic models, so a frame holds real OBJECTS, not just strings — which is
    what the desynchronised memo tripped over. Pin that they come back intact across a frame break."""
    monkeypatch.setattr(pool_store, "CHUNK", 1)
    log = (b"2026-08-19T10:00:00Z host1 sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash\n"
           b"2026-08-19T10:00:01Z host1 sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/su\n")
    on_disk = _stage("sudo2.log", log)
    _load_pool(on_disk, "sudo2.log")
    _enrich_everything()
    before = [(e.id, tuple((d.id, d.name, d.level) for d in e.detections)) for e in STORE.events]
    assert any(d for _, d in before), "the fixture must fire a rule for this to mean anything"

    _forget_memory()
    _load_pool(on_disk, "sudo2.log")
    after = [(e.id, tuple((d.id, d.name, d.level) for d in e.detections)) for e in STORE.events]
    assert after == before


def test_an_entry_whose_file_is_gone_is_deleted():
    """A cache entry is keyed on a staged file, so an entry whose file has been removed can never be
    read again — it is pure disk, and on the analyst's workspace one entry is 3.3 GB. `forget()`
    covers the deletes Iris performs; this covers a file removed while the app was down, a rename,
    and a half-written entry from a crash."""
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    entries = sorted(p.name for p in (config.CACHE_DIR / "pool").glob("*"))
    assert any(pool_store._stem(on_disk) in n for n in entries)

    (config.LIBRARY_DIR / on_disk).unlink()          # the file goes away behind Iris's back
    removed = pool_store.prune()
    assert removed >= 1
    left = [p.name for p in (config.CACHE_DIR / "pool").glob("*")]
    assert not any(pool_store._stem(on_disk) in n for n in left)


def test_prune_keeps_the_entries_that_are_still_backed_by_a_file():
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    before = sorted(p.name for p in (config.CACHE_DIR / "pool").glob("*"))
    assert pool_store.prune() == 0, "a live entry was deleted"
    assert sorted(p.name for p in (config.CACHE_DIR / "pool").glob("*")) == before
    # and it is still usable
    _forget_memory()
    assert _load_pool(on_disk) == 1


# --------------------------------------------------------------------------- the corrected stamp
# `pipeline_digest()` deliberately excludes detect.py: a rule fix must never cost a re-parse of a
# 1.76 GB library. The price is that a cached source comes back carrying the detections that were
# current when it was WRITTEN, and only the correction pass after a library load fixes them. Measured
# on the analyst's workspace, the cache held 1,293 SIGMA-APP-0070 hits where the current rule produces
# 10 — every one of the 1,283 the false-positive class the `_secret_real` fix removed. So for the
# length of that pass every screen showed detections the catalogue rejects, and because the correction
# was REAL the bump was real: the search index, the graph, the analysis and the anomaly roll-up were
# rebuilt twice on every restart, forever, because nothing wrote the correction back. Now it is
# written back once and it converges.
def _stamp_ids() -> set[str]:
    return {d.id for e in STORE.events for d in e.detections}


def test_the_cache_converges_after_a_correction_changes_the_stamp():
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    sid = next(iter(STORE.sources))

    # Plant the stale stamp in the CACHE, exactly as a since-tightened rule would have left behind.
    evs = [e for e in STORE.events if e.sourceId == sid]
    assert evs
    for e in evs:
        e.detections = [Detection(name="stale rule", id="TEST-STALE", level="high")]
    STORE._cache_library_source(sid, evs, report=False)

    # A restart: the pool comes back from the cache still carrying it.
    _forget_memory()
    _load_pool(on_disk)
    assert "TEST-STALE" in _stamp_ids(), "the cache did not serve the planted stamp"

    v0 = STORE.version
    STORE._refresh_detections_async(resave_cache=True)
    assert STORE.wait_detections(60)
    assert "TEST-STALE" not in _stamp_ids()
    assert STORE.version > v0, "a real correction MUST still invalidate the derived layer"

    # ...and the next restart has nothing to correct, so nothing is invalidated and nothing rewritten.
    _forget_memory()
    _load_pool(on_disk)
    assert "TEST-STALE" not in _stamp_ids(), "the corrected stamp was not written back to the cache"
    v1 = STORE.version
    STORE._refresh_detections_async(resave_cache=True)
    assert STORE.wait_detections(60)
    assert STORE.version == v1, "the second restart rebuilt the derived layer for nothing"


def test_only_the_startup_path_rewrites_the_cache(monkeypatch):
    """A source delete runs the same correction pass. It must never kick off a multi-gigabyte rewrite."""
    on_disk = _stage()
    _load_pool(on_disk)
    _enrich_everything()
    sid = next(iter(STORE.sources))

    calls = {"n": 0}
    real = STORE.__class__._resave_pool_cache
    monkeypatch.setattr(STORE.__class__, "_resave_pool_cache",
                        lambda self: (calls.__setitem__("n", calls["n"] + 1), real(self))[1])

    def dirty() -> None:
        for e in STORE.events:
            if e.sourceId == sid:
                e.detections = [Detection(name="planted", id="TEST-PLANTED", level="info")]
                return

    dirty()
    STORE._refresh_detections_async()                      # the delete path: no flag
    assert STORE.wait_detections(60)
    assert calls["n"] == 0

    dirty()
    STORE._refresh_detections_async(resave_cache=True)     # the startup path
    assert STORE.wait_detections(60)
    assert calls["n"] == 1
