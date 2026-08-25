"""library/index.json has ONE writer at a time.

Four upload lanes and GET /api/library all rewrote it read-modify-write with no lock and a shared
`.tmp` name: entries were lost to the last stale writer, and on Windows `replace()` raised
PermissionError under a concurrent reader/writer — reported as `POST /api/library/upload` 500 mid-drop.
"""
from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.routers import library as lib

LOG = b"Jan 01 00:00:01 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2\n"


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def test_concurrent_index_updates_lose_nothing(c) -> None:
    n = 40
    errors: list[BaseException] = []

    def writer(i: int) -> None:
        try:
            lib._update_library_index(lambda idx: idx.__setitem__(f"f{i}.log", {"file": f"f{i}.log"}) or True)
            for _ in range(5):
                lib._library_index()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors[:3]
    idx = lib._library_index()
    assert {f"f{i}.log" for i in range(n)} <= set(idx)
    assert not [p for p in config.LIBRARY_DIR.iterdir() if p.suffix == ".tmp"], "a tmp file was left behind"


def test_every_concurrently_staged_file_keeps_its_name(c) -> None:
    names = [f"concurrent-{i}.log" for i in range(8)]
    results: list[int] = []

    def upload(name: str) -> None:
        r = c.post("/api/library/upload", files=[("files", (name, LOG, "text/plain"))])
        results.append(r.status_code)

    threads = [threading.Thread(target=upload, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [200] * len(names)
    idx = lib._library_index()
    assert {m.get("file") for m in idx.values()} >= set(names), "an entry was overwritten by a stale writer"
    listed = {row["displayName"] for row in c.get("/api/library").json()}
    assert set(names) <= listed
