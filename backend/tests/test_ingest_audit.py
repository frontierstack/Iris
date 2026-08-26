"""Regressions from the ingest-path audit (2026-08-25). Each test names the failure it pins.

Uploads land in the LIBRARY by default now, so the library path is the one every one of these takes.
"""
from __future__ import annotations

import gzip
import io
import threading
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import config, enrich as enrich_mod, jobs as jobs_mod
from app import store as store_mod
from app.jobs import REGISTRY
from app.main import app
from app.parsers import archives
from app.store import STORE

from tests.conftest import drain_enrichment

LINES = [f"Jan 01 00:00:{i:02d} host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2"
         for i in range(20)]
LOG = ("\n".join(LINES) + "\n").encode()


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


@pytest.fixture(autouse=True)
def _tidy():
    with STORE.lock:
        before = set(STORE.sources)
    yield
    with STORE.lock:
        mine = [sid for sid in STORE.sources if sid not in before]
    for sid in mine:
        try:
            STORE.delete_source(sid)
        except Exception:
            pass


@pytest.fixture()
def auto_enrich():
    before = config.get_settings().ingest.autoEnrich
    config.update_settings({"ingest": {"autoEnrich": True}})
    yield
    config.update_settings({"ingest": {"autoEnrich": before}})


@pytest.fixture()
def raw_only():
    """The suite turns phase 2 on for everyone (see conftest); a test about the RAW state turns it off."""
    before = config.get_settings().ingest.autoEnrich
    config.update_settings({"ingest": {"autoEnrich": False}})
    yield
    config.update_settings({"ingest": {"autoEnrich": before}})


def _zip(*members: tuple[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, blob in members:
            z.writestr(name, blob)
    return buf.getvalue()


def _stage(client, filename: str, blob: bytes, job_id: str = "") -> list[dict]:
    before = {s["id"] for s in client.get("/api/case").json()["librarySources"]}
    url = "/api/library/upload" + (f"?jobIds={job_id}" if job_id else "")
    r = client.post(url, files=[("files", (filename, blob, "application/octet-stream"))])
    assert r.status_code == 200, r.text
    drain_enrichment()
    return [s for s in client.get("/api/case").json()["librarySources"] if s["id"] not in before]


def _raws(sid: str) -> list[str]:
    return [e.raw for e in STORE.events if e.sourceId == sid]


# ---------------------------------------------------------------- #1 compressed single-file logs
def test_a_gz_log_in_the_library_is_enriched_not_failed(c, auto_enrich) -> None:
    """`_expand_single` names the payload `auth.log` (no `!`), so `read_member` refused it and EVERY
    compressed log failed phase 2 with "'auth.log' does not name a member inside a container"."""
    srcs = _stage(c, "auth.log.gz", gzip.compress(LOG))
    assert len(srcs) == 1, srcs
    src = srcs[0]
    assert src["enrich"] == "enriched", f"phase 2 failed: {src.get('enrichError')} / {src.get('error')}"
    assert src["events"] == len(LINES)
    assert _raws(src["id"]) == LINES
    assert all(e.ts for e in STORE.events if e.sourceId == src["id"]), "not interpreted"


def test_read_member_walks_into_a_zip_inside_a_gz() -> None:
    inner = _zip(("var/log/auth.log", LOG))
    blob = gzip.compress(inner)
    p = config.DATA_DIR / "nested-probe.zip.gz"
    p.write_bytes(blob)
    try:
        assert archives.read_member(p, "nested-probe.zip!var/log/auth.log") == LOG
    finally:
        p.unlink(missing_ok=True)


# ---------------------------------------------------------------- #2 UTF-16 export re-read in phase 2
def test_a_utf16_export_is_transcoded_in_phase_two_as_well(c, auto_enrich) -> None:
    """Phase 1 saw the transcoded bytes; phase 2 re-read the raw UTF-16 as UTF-8 and every line came
    back full of NULs while the source reported `enriched`."""
    srcs = _stage(c, "export.log", ("\n".join(LINES) + "\n").encode("utf-16"))
    src = srcs[0]
    assert src["enrich"] == "enriched", src
    raws = _raws(src["id"])
    assert raws == LINES, raws[:2]
    assert not any("\x00" in r or "�" in r for r in raws)


# ---------------------------------------------------------------- #4 a bad member is not a lost archive
def test_an_archive_with_one_bad_member_still_ingests_the_good_ones(c, auto_enrich) -> None:
    job = REGISTRY.create("mixed.zip", 10, "library", "")
    blob = _zip(("a.log", LOG), ("b.log", LOG), ("../escape.log", LOG))
    srcs = _stage(c, "mixed.zip", blob, job_id=job.id)
    good = [s for s in srcs if s["state"] != "ERROR"]
    bad = [s for s in srcs if s["state"] == "ERROR"]
    assert len(good) == 2, [s["file"] for s in srcs]
    assert bad and "mixed.zip" in bad[0]["file"] and bad[0]["error"], "the refusal must be an ERROR source"
    row = [j for j in c.get("/api/jobs?limit=500").json()["jobs"] if j["id"] == job.id][0]
    assert row["state"] == "error" and "mixed.zip" in row["error"], row


def test_a_password_protected_zip_is_an_error_source_not_a_silent_ready(c) -> None:
    # a zip whose central directory says "encrypted" (flag bit 0) with a stored member
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("secret.log", LOG)
    raw = bytearray(buf.getvalue())
    idx = raw.find(b"PK\x03\x04")
    raw[idx + 6] |= 1                       # general-purpose flag: encrypted
    cd = raw.find(b"PK\x01\x02")
    raw[cd + 8] |= 1
    job = REGISTRY.create("locked.zip", 10, "library", "")
    srcs = _stage(c, "locked.zip", bytes(raw), job_id=job.id)
    assert srcs and any(s["state"] == "ERROR" for s in srcs), srcs
    row = [j for j in c.get("/api/jobs?limit=500").json()["jobs"] if j["id"] == job.id][0]
    assert row["state"] == "error", row


# ---------------------------------------------------------------- #3 concurrent case uploads, unique ids
def test_concurrent_case_uploads_never_share_an_event_id(c) -> None:
    c.post("/api/cases", json={"name": "ids"})
    big = ("\n".join(f"Jan 01 00:00:{i % 60:02d} host app[1]: line {i}" for i in range(3000)) + "\n").encode()
    codes: list[int] = []

    def up(name: str) -> None:
        r = c.post("/api/sources", files=[("files", (name, big, "text/plain"))])
        codes.append(r.status_code)

    threads = [threading.Thread(target=up, args=(f"lane-{i}.log",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert codes == [200] * 4
    mine = [e for e in STORE.events if e.file.startswith("lane-")]
    assert len(mine) == 12000
    assert len({e.id for e in mine}) == 12000, "duplicate event ids across upload lanes"


# ---------------------------------------------------------------- #6 an exception mid-parse
def test_an_exception_after_the_parser_marks_the_source_error_not_parsing(c, monkeypatch) -> None:
    def boom(self, sid, batches, assign_ids=True):
        raise RuntimeError("merge exploded")
    monkeypatch.setattr(store_mod.Store, "_finish_batches", boom)
    # a binary format has no raw phase, so this goes straight through _parse_source
    r = c.post("/api/library/upload", files=[("files", ("x.evtx", b"ElfFile\x00" + b"\x00" * 64, "application/octet-stream"))])
    assert r.status_code == 200, r.text
    src = [s for s in c.get("/api/case").json()["librarySources"] if s["file"] == "x.evtx"][0]
    assert src["state"] == "ERROR" and "merge exploded" in (src["error"] or ""), src


# ---------------------------------------------------------------- #8 a source never stays `enriching`
def test_a_bad_zip_member_read_in_phase_two_fails_the_source_cleanly(c, auto_enrich, monkeypatch) -> None:
    import zipfile as zf_mod
    real = store_mod.Store.source_bytes

    def bad(self, sid):
        raise zf_mod.BadZipFile("File is not a zip file")
    monkeypatch.setattr(store_mod.Store, "source_bytes", bad)
    srcs = _stage(c, "plain.log", LOG)
    src = srcs[0]
    assert src["enrich"] == "error" and src["state"] == "ERROR", src
    assert "not a zip" in (src["enrichError"] or "")
    monkeypatch.setattr(store_mod.Store, "source_bytes", real)


# ---------------------------------------------------------------- #7 a job for a deleted source settles
def test_a_job_whose_source_was_deleted_does_not_say_parsing_forever(c) -> None:
    before = config.get_settings().ingest.autoEnrich
    config.update_settings({"ingest": {"autoEnrich": False}})
    try:
        job = REGISTRY.create("gone.log", 10, "library", "")
        r = c.post(f"/api/library/upload?jobIds={job.id}", files=[("files", ("gone.log", LOG, "text/plain"))])
        assert r.status_code == 200
        sid = r.json()[0]["sourceId"]
        assert c.delete(f"/api/sources/{sid}").status_code == 200
        row = [j for j in c.get("/api/jobs?limit=500").json()["jobs"] if j["id"] == job.id][0]
        assert row["state"] != "parsing", row
    finally:
        config.update_settings({"ingest": {"autoEnrich": before}})


# ---------------------------------------------------------------- #11 the failure names the file
def test_a_job_error_names_the_member_that_failed(c, monkeypatch) -> None:
    from app.parsers import registry as reg

    real = reg.fingerprint

    def picky(filename, head):
        if filename.endswith("bad.log"):
            raise ValueError("cannot sniff this one")
        return real(filename, head)
    monkeypatch.setattr(store_mod, "fingerprint", picky)
    job = REGISTRY.create("two.zip", 10, "library", "")
    srcs = _stage(c, "two.zip", _zip(("ok.log", LOG), ("bad.log", LOG)), job_id=job.id)
    row = [j for j in c.get("/api/jobs?limit=500").json()["jobs"] if j["id"] == job.id][0]
    assert row["state"] == "error" and "bad.log" in row["error"] and "cannot sniff" in row["error"], row
    assert any(s["state"] != "ERROR" for s in srcs), "the good member must still be in the pool"


def test_an_unreadable_container_reports_could_not_be_read(monkeypatch) -> None:
    p = config.DATA_DIR / "unreadable.log.gz"
    monkeypatch.setattr(archives, "_read_all", lambda path: (_ for _ in ()).throw(PermissionError(13, "Permission denied")))
    p.write_bytes(gzip.compress(LOG))
    try:
        out = archives.expand_path("unreadable.log.gz", p)
        assert out.errors and "could not be read" in out.errors[0] and "unreadable.log.gz" in out.errors[0]
    finally:
        p.unlink(missing_ok=True)


# ------------------------------------------------- #12 phase 2 re-pointing cited ids at other lines
def test_phase_two_keeps_every_cited_id_on_its_own_line(c, raw_only) -> None:
    """Phase 2 reuses the phase-1 ids. It must give each one back to the SAME line.

    `enrich_source` collected them as `[e.id for e in self.events if e.sourceId == sid]` — the pool,
    which is sorted by TIMESTAMP — and zipped that against the parser's output, which is in RECORD
    order. For any file whose lines are not chronological (a merged or multi-host syslog, anything
    with clock skew, a stack trace whose continuation lines carry no time at all) the two orders
    differ and every id lands on a different line. Reproduced on the three lines below: e1 e2 e3 came
    back pointing at each other's lines, with nothing anywhere reporting it.

    That is the failure this project already calls its worst: a citation that resolves cleanly to the
    WRONG evidence. Case-set entries survive it (they carry a file+rawHash anchor and are re-anchored),
    but an id quoted in a note, an indicator, an exported report or an AI answer does not.
    """
    log = (b"2026-05-01T10:00:03Z host1 sshd[1]: THIRD line, latest time\n"
           b"2026-05-01T10:00:01Z host1 sshd[2]: FIRST line, earliest time\n"
           b"2026-05-01T10:00:02Z host1 sshd[3]: SECOND line, middle time\n")
    rows = _stage(c, "out-of-order.log", log)
    sid = rows[0]["id"]
    # The whole point is the raw -> enriched transition. If staging already enriched it this test
    # proves nothing, which is exactly how the doubles in test_source_delete stayed green for years.
    assert STORE.sources[sid].enrich == "raw", STORE.sources[sid].enrich
    before = {e.id: e.raw for e in STORE.events if e.sourceId == sid}
    assert len(before) == 3, before

    STORE.enrich_source(sid)
    assert STORE.sources[sid].enrich == "enriched", STORE.sources[sid].enrich

    after = {e.id: e.raw for e in STORE.events if e.sourceId == sid}
    assert set(after) == set(before), "phase 2 changed which ids exist, not just what they point at"
    moved = {i: (before[i], after[i]) for i in before if before[i] != after[i]}
    assert not moved, f"phase 2 moved {len(moved)} cited id(s) onto a different log line: {moved}"
