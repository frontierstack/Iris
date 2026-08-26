"""A cached archive member must come back knowing it IS a member.

`load_pool_file` mirrors `add_file`'s registrations — the docstring says so, and warns that
"anything it sets and this does not is a source that behaves subtly differently from a parsed one".
`source_member` was exactly that. An archive member's bytes are inside the container, so
`Store.source_bytes` needs the member name to find them; restored from the cache it had none, so
every read of that source fell back to the CONTAINER. The raw viewer then answers for the wrong
file — on a .zip it reports a binary blob, on a .gz it decompresses a different member — and it
only happens after a restart, on evidence that parsed perfectly the first time.
"""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import config, pool_store
from app.main import app
from app.store import STORE

MEMBER = "inner-auth.log"
RECORDED = f"evidence.zip!{MEMBER}"   # archives.py records the container with the member
LINES = [f"2026-08-26T00:00:{i:02d}Z web1 sshd[7]: Accepted password for alice from 10.0.0.{i}"
         for i in range(30)]


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(MEMBER, "\n".join(LINES) + "\n")
    return buf.getvalue()


@pytest.fixture()
def c():
    """clear_all on BOTH sides: this test ends with a hand-driven restart (`_clear_memory` +
    `restore_library`), and leaving the store holding a restored archive member leaks into whatever
    file pytest runs next."""
    STORE.clear_all()
    with TestClient(app) as client:
        yield client
    STORE.clear_all()


def _member_source(files):
    return next(s for s in files if s["file"].endswith(MEMBER))


def test_a_restored_member_still_reads_its_own_bytes(c) -> None:
    assert pool_store.enabled(), "this test is about the cache"
    r = c.post("/api/library/upload", files=[("files", ("evidence.zip", _zip(), "application/zip"))])
    assert r.status_code == 200, r.text

    from tests.conftest import drain_enrichment
    drain_enrichment()

    sid = _member_source(c.get("/api/case").json()["librarySources"])["id"]
    assert STORE.source_member.get(sid) == RECORDED
    fresh = c.get(f"/api/sources/{sid}/raw").json()
    assert any(LINES[0] in str(l) for l in fresh.get("lines", [])), fresh

    # the cache entry is written when the source finishes; force it if the run had nothing to save
    STORE._resave_pool_cache()

    # ...and now the restart
    STORE._clear_memory(delete_files=False, keep_library=False)
    STORE.restore_library()
    assert sid in STORE.sources, "the member did not come back at all"

    assert STORE.source_member.get(sid) == RECORDED, (
        "restored from the cache the source forgot it lives inside evidence.zip; every read of it "
        "now returns the container")
    back = c.get(f"/api/sources/{sid}/raw").json()
    assert any(LINES[0] in str(l) for l in back.get("lines", [])), back


def test_a_cache_entry_never_claims_more_events_than_it_holds(c) -> None:
    """A `skipped` source is FINISHED, so `save_member` accepted it — and `_parse_source` hands it
    an EMPTY list, because only an `enriched` source's events are worth caching. The entry then said
    "this source has N events" and held none, and it is a HIT on the next boot: the Sources table
    reports N, and search, the timeline, the graph and every citation have nothing. A file that
    parsed correctly and was then field-mapped disappears from the workspace at the next restart.

    A skipped source not being cached is the intended design (`pool_store`'s own note: what must
    survive is the DECISION, not megabytes of raw lines). What must not happen is a cache entry
    that disagrees with its own row.
    """
    from app.models import Source

    STORE.clear_all()
    r = c.post("/api/library/upload", files=[("files", ("plain.log", b"\n".join(
        l.encode() for l in LINES) + b"\n", "text/plain"))])
    assert r.status_code == 200, r.text
    sid = next(iter(STORE.sources))
    name = STORE.source_library[sid]

    row = STORE.sources[sid].model_copy(update={"enrich": "skipped", "events": len(LINES)})
    assert isinstance(row, Source)
    wrote = pool_store.save_member(name, row, [], 0)
    assert wrote is False, "wrote a cache entry claiming events it does not hold"

    # ...and the honest case still writes
    assert pool_store.save_member(name, row.model_copy(update={"events": 0}), [], 0) is True
