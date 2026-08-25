"""A log inside a staged archive is its own source, and every reader must get ITS bytes.

The bug, found while making large uploads stop holding the whole file in memory. `Store.source_paths`
means "where this source's bytes are", and it is true for every ingest path except one: a library-staged
container gives EVERY member the path of the container. Phase 1 was fine — it is handed the member's
blob — but everything that re-reads the file later opened the archive:

    phase 2      20 clean syslog lines replaced by 21 lines of decoded zip binary,
                 and the source reported state READY / enrich `enriched` over the top of it
    remap        a field mapping accepted on a member re-parsed the zip
    raw viewer   "show me the raw log" answered with the container, called it binary
    download     handed over the archive under the member's name

The first is evidence corruption: the pool ends up holding the container's own bytes labelled as a
parsed log, with nothing on screen suggesting anything went wrong. `Store.source_bytes()` is the single
accessor that knows the difference, and reading one member back is also the BOUNDED thing to do —
archives.MAX_MEMBER_BYTES, where the container has no cap at all.
"""
from __future__ import annotations

import io
import tarfile
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
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
    """Delete the sources this module stages, so nothing it uploads leaks into another test file.

    The pool is process-wide and these tests deliberately stage archives into the LIBRARY. Left behind,
    they break an assertion in test_archives.py that every `source_paths` entry lives under the case's
    upload directory — which is true of the sources that test creates and is not this module's to
    falsify.
    """
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
    """Phase 2 must actually run — that is the half of the ingest this file is about."""
    before = config.get_settings().ingest.autoEnrich
    config.update_settings({"ingest": {"autoEnrich": True}})
    yield
    config.update_settings({"ingest": {"autoEnrich": before}})


def _zip(*members: tuple[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, blob in members:
            z.writestr(name, blob)
    return buf.getvalue()


def _tar(*members: tuple[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, blob in members:
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))
    return buf.getvalue()


def _stage(client, filename: str, blob: bytes) -> list[dict]:
    """Upload, let phase 2 finish, and return ONLY the sources this upload created.

    Every test here uploads a member called `var/log/auth.log`, so matching by name across the whole
    workspace would happily hand back the previous test's source and pass on the wrong evidence.
    """
    before = {s["id"] for s in client.get("/api/case").json()["librarySources"]}
    r = client.post("/api/library/upload", files=[("files", (filename, blob, "application/octet-stream"))])
    assert r.status_code == 200, r.text
    drain_enrichment()
    return [s for s in client.get("/api/case").json()["librarySources"] if s["id"] not in before]


def _member_source(sources: list[dict], suffix: str) -> dict:
    hit = [s for s in sources if s["file"].endswith(suffix)]
    assert hit, f"no source ending in {suffix!r} — got {[s['file'] for s in sources]}"
    return hit[0]


def test_phase_two_parses_the_member_not_the_archive(c, auto_enrich) -> None:
    """The corruption. Before the fix this source came back with 21 events of decoded zip binary."""
    src = _member_source(_stage(c, "bundle.zip", _zip(("var/log/auth.log", LOG))), "!var/log/auth.log")
    assert src["enrich"] == "enriched", f"phase 2 did not run: {src}"
    assert src["events"] == len(LINES), f"expected the member's {len(LINES)} lines, got {src['events']}"

    raws = [e.raw for e in STORE.events if e.sourceId == src["id"]]
    assert raws == LINES
    assert not any("�" in r for r in raws), "the archive's own bytes reached the pool"
    # phase 2 is what produced these, so they are INTERPRETED: a timestamp is the proof
    assert all(e.ts for e in STORE.events if e.sourceId == src["id"])


def test_a_tar_member_is_read_back_the_same_way(c, auto_enrich) -> None:
    src = _member_source(_stage(c, "evidence.tar", _tar(("logs/auth.log", LOG))), "!logs/auth.log")
    assert src["enrich"] == "enriched" and src["events"] == len(LINES)
    assert [e.raw for e in STORE.events if e.sourceId == src["id"]] == LINES


def test_each_member_of_a_multi_member_archive_gets_its_own_bytes(c, auto_enrich) -> None:
    """The failure mode this really guards: every member sharing one path means every member could
    come back as the same wrong thing."""
    other = ("\n".join(f"Feb 02 01:02:{i:02d} web nginx: GET /{i} 200" for i in range(7)) + "\n").encode()
    sources = _stage(c, "two.zip", _zip(("a/first.log", LOG), ("b/second.log", other)))
    first = _member_source(sources, "!a/first.log")
    second = _member_source(sources, "!b/second.log")
    assert first["events"] == len(LINES)
    assert second["events"] == 7
    assert [e.raw for e in STORE.events if e.sourceId == first["id"]] == LINES
    assert [e.raw for e in STORE.events if e.sourceId == second["id"]] == other.decode().splitlines()


def test_the_raw_viewer_shows_the_member(c, auto_enrich) -> None:
    src = _member_source(_stage(c, "view.zip", _zip(("var/log/auth.log", LOG))), "!var/log/auth.log")
    body = c.get(f"/api/sources/{src['id']}/raw?limit=100").json()
    assert body["binary"] is False, "the container's bytes were served, so the member looked binary"
    assert body["totalLines"] == len(LINES)
    assert [row["text"] for row in body["lines"]] == LINES


def test_the_raw_viewer_still_filters_and_pages_a_member(c, auto_enrich) -> None:
    src = _member_source(_stage(c, "page.zip", _zip(("var/log/auth.log", LOG))), "!var/log/auth.log")
    body = c.get(f"/api/sources/{src['id']}/raw?q=00:00:07&limit=10").json()
    assert body["matches"] == 1 and body["lines"][0]["text"] == LINES[7]
    page = c.get(f"/api/sources/{src['id']}/raw?offset=5&limit=3").json()
    assert [row["text"] for row in page["lines"]] == LINES[5:8]


def test_downloading_a_member_gives_the_member(c, auto_enrich) -> None:
    src = _member_source(_stage(c, "dl.zip", _zip(("var/log/auth.log", LOG))), "!var/log/auth.log")
    r = c.get(f"/api/sources/{src['id']}/download")
    assert r.status_code == 200
    assert r.content == LOG, "the archive was served instead of the file that was asked for"
    assert "auth.log" in r.headers.get("content-disposition", "")


def test_source_bytes_of_a_plain_library_file_is_the_file(c) -> None:
    """The other half of the accessor's contract: a source that IS its file must not go looking for a
    container that does not exist."""
    sources = _stage(c, "plain.log", LOG)
    src = _member_source(sources, "plain.log")
    assert STORE.source_bytes(src["id"]) == LOG
    assert STORE.source_member.get(src["id"], "") == ""


def test_a_member_records_where_it_came_from(c) -> None:
    src = _member_source(_stage(c, "prov.zip", _zip(("var/log/auth.log", LOG))), "!var/log/auth.log")
    assert STORE.source_member[src["id"]] == "prov.zip!var/log/auth.log"
    assert STORE.source_bytes(src["id"]) == LOG
    # and the recorded path really is the container — that is the condition the accessor exists for
    assert STORE.source_paths[src["id"]].name.endswith("prov.zip")


def test_deleting_a_member_forgets_its_provenance(c) -> None:
    src = _member_source(_stage(c, "gone.zip", _zip(("var/log/auth.log", LOG))), "!var/log/auth.log")
    sid = src["id"]
    assert sid in STORE.source_member
    assert c.delete(f"/api/sources/{sid}").status_code in (200, 204)
    assert sid not in STORE.source_member


# --------------------------------------------------------- one bad member is one bad member
# Reported: a bundle whose members included a file named `.xlsx` that was really a plain zip. It failed
# with "this file is a plain ZIP archive, not an Excel workbook. Rename it to .zip" — and the failure
# was not confined to that file, because the members were registered with a list comprehension over
# `add_file`: the first raise abandoned every member after it and failed the upload.
XLSX_ZIP = _zip(("readme.txt", b"not a workbook"), ("inner/app.log", b"boot ok"))


def test_a_zip_named_xlsx_inside_a_bundle_is_expanded(c) -> None:
    """Handle the file as what it IS: a zip full of logs, expanded, with its members in the pool."""
    sources = _stage(c, "bundle.zip", _zip(("var/log/auth.log", LOG), ("docs/report.xlsx", XLSX_ZIP)))
    files = [s["file"] for s in sources]
    assert "bundle.zip!var/log/auth.log" in files
    inner = _member_source(sources, "!inner/app.log")
    assert inner["state"] != "ERROR", inner
    assert not [s for s in sources if s["state"] == "ERROR"], files


def test_one_unreadable_member_never_costs_the_others(c, monkeypatch) -> None:
    """A member the ingest cannot register becomes an ERROR source. The rest of the bundle still lands."""
    from app.store import STORE as S

    real = S.add_file

    def boom(filename, *a, **kw):
        if filename.endswith("bad.log"):
            raise RuntimeError("this file is a plain ZIP archive, not an Excel workbook")
        return real(filename, *a, **kw)

    monkeypatch.setattr(S, "add_file", boom)
    sources = _stage(c, "mixed.zip", _zip(("bad.log", b"x"), ("var/log/auth.log", LOG)))
    good = _member_source(sources, "!var/log/auth.log")
    assert good["events"] == len(LINES), "a later member was dropped by an earlier failure"
    bad = _member_source(sources, "!bad.log")
    assert bad["state"] == "ERROR" and "plain ZIP archive" in (bad["error"] or "")
