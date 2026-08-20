"""Opening one event must not cost the whole pool, or the whole file.

"Event detail page loads very slow" had two causes, and both are patterns this codebase already
forbids elsewhere:

* `GET /api/events/{id}` called `STORE.analysis()` — the BLOCKING accessor, which BUILDS the
  whole-pool correlation analysis when it is not current. That is minutes on a large workspace, on a
  request thread, for a page that is otherwise a dictionary lookup. Every other derived reader in the
  app uses the non-blocking accessor and reports a status; this one did not.
* `GET /api/events/{id}/location` did `fh.read().splitlines()` on the source file. For a 1.1 GB log
  that is the file as one string plus ten million string objects — gigabytes of allocation to show
  three lines of context.

The second rule is the one worth stating twice: when the analysis is not available the response says
so. An empty `correlations` list with no explanation is a claim — "nothing correlates with this
event" — and that is the silent-omission failure this project keeps closing.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import STORE


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _ingest(c, name: str, body: bytes) -> str:
    r = c.post("/api/library/upload", files=[("files", (name, body, "text/plain"))])
    assert r.status_code == 200, r.text
    from tests.conftest import drain_enrichment

    drain_enrichment()
    ev = c.get("/api/events", params={"limit": 5}).json()
    assert ev["rows"], "the upload produced no events"
    return ev["rows"][0]["id"]


LOG = b"".join(
    f"2026-08-19T10:{i // 60:02d}:{i % 60:02d}Z host1 sshd[{i}]: Failed password for root from 10.0.0.{i % 250} port 22\n".encode()
    for i in range(400)
)


def test_opening_an_event_never_builds_the_analysis(c, monkeypatch):
    """The blocking accessor must not be reachable from this endpoint at all."""
    eid = _ingest(c, "detail.log", LOG)

    def boom(*a, **k):
        raise AssertionError("event detail built the whole-pool analysis on the request thread")

    monkeypatch.setattr(STORE, "analysis", boom)
    r = c.get(f"/api/events/{eid}")
    assert r.status_code == 200
    assert r.json()["id"] == eid


def test_when_correlations_are_unavailable_the_response_says_so(c, monkeypatch):
    eid = _ingest(c, "detail2.log", LOG)
    monkeypatch.setattr(STORE, "analysis_ready", lambda scope="all": None)

    body = c.get(f"/api/events/{eid}").json()
    assert body["correlations"] == []
    assert body["analysis"], "an empty correlation list with no explanation is a claim, not an answer"
    assert "state" in body["analysis"]


def test_correlations_are_returned_when_the_analysis_is_there(c):
    eid = _ingest(c, "detail3.log", LOG)
    STORE.analysis()                       # build it deliberately, off the endpoint
    body = c.get(f"/api/events/{eid}").json()
    assert body.get("analysis") is None, "a real answer must not carry an omission notice"
    assert isinstance(body["correlations"], list)


def test_the_context_excerpt_does_not_read_the_whole_file(c, monkeypatch):
    """`fh.read()` is what made this expensive; the endpoint streams the file instead.

    `_io.TextIOWrapper` is immutable, so the guard goes on `open` itself: the endpoint gets a handle
    that iterates normally and refuses to be slurped.
    """
    eid = _ingest(c, "detail4.log", LOG)

    import builtins

    real_open = builtins.open

    class NoSlurp:
        def __init__(self, fh):
            self._fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return self._fh.__exit__(*a)

        def __iter__(self):
            return iter(self._fh)

        def read(self, *a, **k):
            raise AssertionError("the location endpoint slurped the whole file")

        def __getattr__(self, name):
            return getattr(self._fh, name)

    def guarded(*a, **k):
        fh = real_open(*a, **k)
        return NoSlurp(fh) if (a and str(a[0]).endswith("detail4.log")) else fh

    monkeypatch.setattr(builtins, "open", guarded)
    try:
        r = c.get(f"/api/events/{eid}/location", params={"context": 2})
    finally:
        monkeypatch.setattr(builtins, "open", real_open)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["line"] is not None and body["exact"] is True
    assert body["context"], "the excerpt is the point of this endpoint"
    assert any(row["current"] for row in body["context"])


def test_the_excerpt_still_shows_the_lines_either_side(c):
    eid = _ingest(c, "detail5.log", LOG)
    rows = c.get("/api/events", params={"limit": 200}).json()["rows"]
    target = rows[len(rows) // 2]           # something with neighbours on both sides

    body = c.get(f"/api/events/{target['id']}/location", params={"context": 3}).json()
    assert body["line"] is not None
    ns = [row["n"] for row in body["context"]]
    assert ns == sorted(ns) and len(ns) == len(set(ns))
    current = [row["n"] for row in body["context"] if row["current"]]
    assert current == [body["line"]]
    assert min(ns) <= body["line"] <= max(ns)
    assert len(ns) <= 7                      # 3 before + the line + 3 after


def test_an_event_whose_line_is_not_in_the_file_is_reported_not_guessed(c):
    """A format where one event is not one line must say that, not point at an arbitrary line."""
    eid = _ingest(c, "detail6.log", LOG)
    ev = STORE.event(eid)
    assert ev is not None
    ev.raw = "a line that is definitely not in the file at all"

    body = c.get(f"/api/events/{eid}/location").json()
    assert body["line"] is None
    assert body["context"] == []
    assert body["reason"]
