"""Bulk case-set operations must persist ONCE, not once per event.

`save_meta()` re-serializes the whole case set plus every source, so calling it per event made
`POST /api/case-set/source/{id}` quadratic — adding a large source effectively hung. These tests pin
the call count AND prove the on-disk result is byte-identical (modulo timestamps) to what the old
per-event path wrote.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import store as store_mod
from app.main import app
from app.store import STORE

N = 400
LOG = "".join(
    f"Jan 01 {i // 3600:02d}:{i // 60 % 60:02d}:{i % 60:02d} host-{i % 3} sshd[{1000 + i}]: "
    f"Accepted password for user{i % 7} from 10.0.0.{i % 200} port 22 ssh2\n"
    for i in range(N)
).encode()


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def source(c):
    c.post("/api/case/reset")
    r = c.post("/api/sources", files=[("files", ("bulk.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text
    sid = r.json()[0]["id"]
    assert r.json()[0]["events"] == N
    return sid


class _Counter:
    def __init__(self, monkeypatch):
        self.n = 0
        real = store_mod.Store.save_meta

        def counted(inner_self):
            self.n += 1
            return real(inner_self)

        monkeypatch.setattr(store_mod.Store, "save_meta", counted)


def _case_set_on_disk() -> list[dict]:
    meta = json.loads(STORE.case_path.read_text(encoding="utf-8"))
    # addedAt is wall-clock; the old path stamped each entry as it went, the new one within one loop
    return [{k: v for k, v in e.items() if k != "addedAt"} for e in meta["case_set"]]


def test_add_source_persists_once(c, source, monkeypatch) -> None:
    counter = _Counter(monkeypatch)
    r = c.post(f"/api/case-set/source/{source}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["added"] == N and body["total"] == N and body["truncated"] is False
    # O(1), not O(N): one write for the batch (plus a little slack for any incidental bump)
    assert counter.n <= 2, f"save_meta called {counter.n}x for {N} events"
    assert len(STORE.case_set) == N
    assert len(_case_set_on_disk()) == N


def test_remove_source_persists_once(c, source, monkeypatch) -> None:
    assert c.post(f"/api/case-set/source/{source}").status_code == 200
    counter = _Counter(monkeypatch)
    r = c.delete(f"/api/case-set/source/{source}")
    assert r.status_code == 200, r.text
    assert r.json()["removed"] == N
    assert counter.n <= 2, f"save_meta called {counter.n}x for {N} events"
    assert len(STORE.case_set) == 0
    assert _case_set_on_disk() == []


def test_batched_disk_state_matches_the_per_event_path(c, source) -> None:
    """The whole point: batching must not change WHAT lands in case.json."""
    # same order the endpoint walks (store order), so only the batching differs
    ids = [e.id for e in STORE.events if e.sourceId == source]
    assert len(ids) == N

    # the old behaviour, reproduced exactly: one upsert (and one write) per event
    for eid in ids:
        assert STORE.add_to_case(eid, ["bulk.log"], None) is not None
    per_event = _case_set_on_disk()
    assert len(per_event) == N

    # and now the batched endpoint from a clean case set
    assert c.delete(f"/api/case-set/source/{source}").json()["removed"] == N
    assert c.post(f"/api/case-set/source/{source}").json()["added"] == N
    assert _case_set_on_disk() == per_event


def test_single_item_endpoints_still_write_immediately(c, source, monkeypatch) -> None:
    eid = c.get("/api/events?limit=1").json()["rows"][0]["id"]
    counter = _Counter(monkeypatch)
    assert c.post(f"/api/case-set/{eid}", json={"labels": ["x"], "note": "n"}).status_code == 200
    assert counter.n >= 1
    [entry] = _case_set_on_disk()
    # `file`/`rawHash` are the entry's ANCHOR (see CaseSetEntry): what it points at, so a re-parse that
    # moves the ids can re-find the line instead of the timeline being silently dropped.
    assert {k: entry[k] for k in ("eventId", "labels", "note")} == {"eventId": eid, "labels": ["x"], "note": "n"}
    assert entry["file"] and entry["rawHash"]
    assert c.delete(f"/api/case-set/{eid}").status_code == 200
    assert _case_set_on_disk() == []


def test_bulk_add_persists_what_it_applied_even_if_it_raises(c, source) -> None:
    """A failure partway must not leave memory ahead of disk — a restart re-reads case.json."""
    ids = [e.id for e in STORE.events if e.sourceId == source]

    def boom(seq):
        for i, eid in enumerate(seq):
            if i == 10:
                raise RuntimeError("boom")
            yield eid

    with pytest.raises(RuntimeError):
        STORE.add_many_to_case(boom(ids), ["bulk.log"], None)
    assert len(STORE.case_set) == 10
    assert len(_case_set_on_disk()) == 10
