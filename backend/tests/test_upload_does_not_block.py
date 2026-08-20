"""An upload must never freeze the rest of the app.

The upload handlers are `async def`, and they used to call the parse SYNCHRONOUSLY — for anything under
SYNC_LIMIT (50 MB) the whole parse ran on uvicorn's event loop. Every other request in the process,
`/api/health` included, waited for it. Measured on the analyst's machine: `/api/health` took 17.6 s while
one 44 MB file parsed. That was "the whole app locks up when ingesting logs" — not a lock, not the
workers, just blocking work on the loop.

This test slows the parse down deliberately and asserts a concurrent request still answers at once. It
drives the ASGI app directly with an event loop of its own, because TestClient serialises requests and
would hide exactly the bug being pinned.
"""
from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from app.main import app
from app.store import STORE

NGINX = b'10.0.0.5 - - [11/Aug/2026:03:14:47 +0000] "GET /a HTTP/1.1" 200 12 "-" "curl/8"\n' * 50


@pytest.mark.parametrize("path,field", [("/api/library/upload", "files"), ("/api/sources", "files")])
def test_health_answers_while_an_upload_parses(monkeypatch, path, field):
    # Patch the CLASS, not the instance. monkeypatch.setattr on an instance for an attribute the
    # instance inherits records the bound method and "restores" it as an INSTANCE attribute — which then
    # shadows every later class-level patch (test_upload_jobs gates Store._parse_source and never saw
    # its gate). Two tests failed in the full run for exactly that reason and passed alone.
    # Two-phase ingest (app/enrich.py) split what an upload does synchronously: a TEXT log now lands
    # through `_raw_source` (phase 1) and its real parse happens later on the enrichment worker, while a
    # binary/structured container still parses inline through `_parse_source`. Both are blocking work
    # reached from an `async def` handler, so BOTH are slowed here and the counter is the sum. Slowing
    # only `_parse_source` is how this test silently stopped exercising the upload path at all: it kept
    # passing on `worst < 0.5` while never once running the blocking call it exists to place off-loop.
    from app import store as store_mod
    slowed = {"n": 0}

    def slow(name):
        real = getattr(store_mod.Store, name)

        def wrapper(self, *a, **k):
            slowed["n"] += 1
            time.sleep(1.5)      # blocking work — the thing that used to sit on the event loop
            return real(self, *a, **k)

        return wrapper

    # Patch the CLASS, not the instance — see the note above.
    for _name in ("_raw_source", "_parse_source"):
        monkeypatch.setattr(store_mod.Store, _name, slow(_name))

    async def go():
        transport = httpx.ASGITransport(app=app)
        # base_url must be a host Iris answers to: app/security.py refuses a Host header that is a DNS
        # name it does not recognise (DNS-rebinding defence). "t" was one; "localhost" is the real thing
        # a browser or start.sh sends anyway.
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as c:
            # make sure a case exists for the /api/sources branch, else it stages to the library anyway
            await c.post("/api/cases", json={"name": "loop"})
            upload = asyncio.create_task(c.post(path, files={field: ("slow.log", NGINX, "text/plain")}))
            # Probe the loop repeatedly for the whole duration of the parse. A single probe can slip in
            # before the blocking call (the multipart read yields first), so the WORST latency over the
            # window is what proves the loop stayed free.
            # Measure the WHOLE tick — request plus the 50 ms sleep. A blocked loop delays whichever
            # await is pending, and that is as likely to be the sleep as the request; timing only the
            # request let a 1.5 s stall hide inside the sleep and the test passed with the bug present.
            worst = 0.0
            deadline = time.perf_counter() + 2.5
            statuses: list[int] = []
            while time.perf_counter() < deadline:
                t0 = time.perf_counter()
                r = await c.get("/api/health")
                await asyncio.sleep(0.05)
                worst = max(worst, time.perf_counter() - t0 - 0.05)
                statuses.append(r.status_code)
            up = await upload
            return statuses, worst, up.status_code

    statuses, worst, up_status = asyncio.run(go())
    assert all(s == 200 for s in statuses) and up_status == 200
    assert slowed["n"] >= 1, "no slowed ingest phase ran — the test is not exercising the upload path"
    assert worst < 0.5, f"/api/health waited {worst:.2f}s behind an upload — the parse is on the event loop"
