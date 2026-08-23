"""A file missing from the pool must say so BY NAME, with the reason and the numbers.

The failure this pins came off the analyst's real library: 2 of 61 staged files were skipped at startup
because the pool hit its memory budget — and they were the two largest, 263 MB each, ~526 MB of the
589 MB total. The API reported `poolSkipped: 2` and nothing else, so half a gigabyte of evidence was
absent from search and looked exactly like "no matching events".

Budget skips and parse failures are DIFFERENT problems with different fixes, so they must never be
conflated: raising IRIS_POOL_MAX_MB does nothing for a parser that blew up, and re-mapping fields does
nothing for a file that was never read.

NOTE: there is no budget by DEFAULT any more — `pool_budget_bytes()` returns 0 (unlimited) unless
IRIS_POOL_MAX_MB is set, because uploaded evidence has to be searchable. The tests below still force a
cap explicitly, because the reporting has to stay correct for anyone who sets one.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app import cases
from app import store as store_mod
from app.main import app
from app.store import STORE
from tests.conftest import drain_enrichment

LINE = b"Jan 01 00:00:01 host sshd[1]: Accepted password for alice from 45.66.13.201 port 22 ssh2\n"


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _wipe(c) -> None:
    for cid in list(cases.case_ids()):
        c.delete(f"/api/cases/{cid}")
    for f in c.get("/api/library").json():
        if f["caseId"] == "":
            c.delete(f"/api/library/unattached/{f['fileName']}")


def _cold_process() -> None:
    with STORE.lock:
        STORE._clear_memory(delete_files=False)


def _await_pool(client, timeout: float = 30.0) -> dict:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        case = client.get("/api/case").json()
        if not case["poolLoading"]:
            return case
        time.sleep(0.02)
    raise AssertionError("the pool never finished loading")


def _staged(client) -> dict[str, dict]:
    return {f["displayName"]: f for f in client.get("/api/library").json() if f["caseId"] == ""}


def test_budget_skips_name_the_files_and_the_numbers(c, monkeypatch) -> None:
    """The real shape of the bug: the big files are the skipped ones, and each says so individually."""
    _wipe(c)
    small = LINE * 5
    big = LINE * 200
    for name, blob in [("small-a.log", small), ("huge-b.log", big), ("huge-c.log", big)]:
        assert c.post("/api/library/upload", files=[("files", (name, blob, "text/plain"))]).status_code == 200

    budget = len(small) + 10          # room for the first file only
    monkeypatch.setattr(store_mod, "pool_budget_bytes", lambda: budget)
    _cold_process()
    with TestClient(app) as restarted:
        case = _await_pool(restarted)
        skipped = case["poolSkippedFiles"]
        assert case["poolSkipped"] == len(skipped) == 2, "the header count IS the per-file list"
        assert case["poolBudgetBytes"] == budget, "the analyst has to be able to see the budget"
        assert {s["displayName"] for s in skipped} == {"huge-b.log", "huge-c.log"}
        for s in skipped:
            assert s["reason"] == "budget"
            assert s["size"] == len(big) > 0, "the size is what makes the skip understandable"
            assert s["budgetBytes"] == budget
            assert "IRIS_POOL_MAX_MB" in s["detail"], "the remedy must be in the message"

        lib = _staged(restarted)
        assert len(lib) == 3, "nothing was lost — every staged file is still listed"
        for name in ("huge-b.log", "huge-c.log"):
            assert lib[name]["skipped"] is True
            assert lib[name]["skipReason"] == "budget"
            assert lib[name]["budgetBytes"] == budget
            assert lib[name]["events"] == 0 and lib[name]["sourceId"] == ""
        # the file that DID load is not marked — a warning on everything is a warning on nothing
        assert lib["small-a.log"]["skipped"] is False
        assert lib["small-a.log"]["skipReason"] == ""
        assert lib["small-a.log"]["events"] == 5


def test_a_parse_failure_is_not_a_budget_skip(c, monkeypatch) -> None:
    """A parser that blows up reports ITS error. Budget has nothing to do with it, and vice versa.

    The pool cache is off for this one: it makes the restart restore the events that were parsed
    successfully BEFORE the parser was broken, so the file is never handed to the exploding parser at
    all. That is the cache doing its job (and `pool_store.pipeline_digest()` is what invalidates it
    when parser CODE really changes) — but this test is about how a parse failure is reported.
    """
    monkeypatch.setenv("IRIS_POOL_CACHE", "0")
    _wipe(c)
    c.post("/api/library/upload", files=[("files", ("boom.log", LINE * 3, "text/plain"))])

    from app.parsers.base import BaseParser

    original = BaseParser.parse_bytes

    def explode(self, data):  # noqa: ANN001
        raise ValueError("unterminated record at line 3")
        yield  # pragma: no cover - keeps it a generator

    monkeypatch.setattr(BaseParser, "parse_bytes", explode, raising=False)
    for cls in BaseParser.__subclasses__():
        if "parse_bytes" in cls.__dict__:
            monkeypatch.setattr(cls, "parse_bytes", explode)
    _cold_process()
    with TestClient(app) as restarted:
        case = _await_pool(restarted)
        assert case["poolSkipped"] == 0, "a parse failure is not a budget skip"
        assert case["poolSkippedFiles"] == []

        # Two-phase ingest (app/enrich.py): the pool is loaded once the RAW lines are in, so
        # `_await_pool` returns before the parser has run and therefore before it can fail. The
        # failure this test is about belongs to phase 2, so wait for it. Nothing here is weakened —
        # the assertions below are the same, and `Source.state == ERROR` still has to arrive.
        drain_enrichment()

        row = _staged(restarted)["boom.log"]
        assert row["skipped"] is True and row["skipReason"] == "parse-error"
        assert "unterminated record" in row["skipDetail"], "the parser's own message, not a budget story"
        assert "IRIS_POOL_MAX_MB" not in row["skipDetail"]
        assert row["budgetBytes"] == 0
        # it IS a source in the pool, in ERROR — that is what makes it a different problem
        src = [s for s in restarted.get("/api/case").json()["librarySources"] if s["file"] == "boom.log"]
        assert src and src[0]["state"] == "ERROR"

    monkeypatch.setattr(BaseParser, "parse_bytes", original, raising=False)


def test_load_anyway_loads_a_budget_skipped_file(c, monkeypatch) -> None:
    """The remedy has to work: an explicit load parses the file and clears the skip everywhere."""
    _wipe(c)
    small, big = LINE * 5, LINE * 40
    c.post("/api/library/upload", files=[("files", ("keep.log", small, "text/plain"))])
    c.post("/api/library/upload", files=[("files", ("left-out.log", big, "text/plain"))])

    monkeypatch.setattr(store_mod, "pool_budget_bytes", lambda: len(small) + 10)
    _cold_process()
    with TestClient(app) as restarted:
        _await_pool(restarted)
        row = _staged(restarted)["left-out.log"]
        assert row["skipped"] is True and row["skipReason"] == "budget"

        r = restarted.post(f"/api/library/unattached/{row['fileName']}/load")
        assert r.status_code == 200, r.text
        assert r.json()["skipped"] is False and r.json()["events"] == 40

        case = restarted.get("/api/case").json()
        assert case["poolSkipped"] == 0 and case["poolSkippedFiles"] == []
        assert case["poolEventCount"] == 45, "its events are searchable now"
        assert _staged(restarted)["left-out.log"]["skipped"] is False
        # idempotent: a second load must not duplicate the events
        assert restarted.post(f"/api/library/unattached/{row['fileName']}/load").status_code == 200
        assert restarted.get("/api/case").json()["poolEventCount"] == 45


def test_load_anyway_loads_it_even_when_memory_looks_tight(c, monkeypatch) -> None:
    """"There should be no budget limit — data gets uploaded, it becomes searchable." (the analyst)

    This used to answer 507 and leave the file out of the pool when the live memory estimate said it
    would not fit. That estimate is a per-machine guess over an AVERAGE cost per source byte, it cannot
    know this particular file is mostly blank lines, and the cost of being wrong is asymmetric: a slow
    or memory-hungry Iris is visible, whereas a search silently answered over part of the corpus is not.
    An explicit "load it anyway" is the least ambiguous request there is, so it loads and the estimate
    goes to the log as a warning.
    """
    _wipe(c)
    small = LINE * 5
    c.post("/api/library/upload", files=[("files", ("first.log", small, "text/plain"))])
    c.post("/api/library/upload", files=[("files", ("too-big.log", LINE * 40, "text/plain"))])
    monkeypatch.setattr(store_mod, "pool_budget_bytes", lambda: len(small) + 10)
    _cold_process()
    with TestClient(app) as restarted:
        _await_pool(restarted)
        row = _staged(restarted)["too-big.log"]
        assert row["skipped"] is True

        monkeypatch.setattr("app.routers.library.pool_headroom_bytes", lambda: 1)
        r = restarted.post(f"/api/library/unattached/{row['fileName']}/load")
        assert r.status_code == 200, r.text
        drain_enrichment()
        assert restarted.get("/api/case").json()["poolEventCount"] == 45, "every line is in the pool"
        assert _staged(restarted)["too-big.log"]["skipped"] is False


def test_deleting_a_skipped_file_clears_the_warning(c, monkeypatch) -> None:
    _wipe(c)
    small, big = LINE * 5, LINE * 40
    c.post("/api/library/upload", files=[("files", ("stay.log", small, "text/plain"))])
    c.post("/api/library/upload", files=[("files", ("drop.log", big, "text/plain"))])
    monkeypatch.setattr(store_mod, "pool_budget_bytes", lambda: len(small) + 10)
    _cold_process()
    with TestClient(app) as restarted:
        _await_pool(restarted)
        row = _staged(restarted)["drop.log"]
        assert restarted.delete(f"/api/library/unattached/{row['fileName']}").status_code == 200
        case = restarted.get("/api/case").json()
        assert case["poolSkipped"] == 0 and case["poolSkippedFiles"] == []


def test_case_still_answers_while_a_skipped_file_is_in_the_plan() -> None:
    """GET /api/case must not 500 because a file was skipped.

    `Store._plan_state(name, "skipped")` is a real state of the pool-load plan, but
    `PoolFileProgress.state` was declared `Literal["pending","parsing","done","error"]`, so building
    the response raised a pydantic ValidationError and the most-called endpoint in the app returned
    500 for the whole window a skipped file sat in `pool_plan`. Seen live on a 617-source library
    with `poolSkipped: 1`.

    Driven through `_pool_files` directly rather than through a real capped load: `poolProgress` is
    None once `pool_loading` clears, so the failing window is the load itself and asserting on it via
    the API is a race. The state transition is what regressed, so that is what is pinned.

    The value is kept distinct on purpose. "the parser failed" (error) and "this file was never read"
    (skipped) have different fixes, and collapsing them would file evidence that is absent from
    search behind a message about parsing.
    """
    st = store_mod.STORE
    with st.lock:
        st.pool_plan["huge.log"] = {"file": "huge.log", "size": 1 << 20, "state": "pending", "events": 0}
        st._plan_state("huge.log", "skipped", size=1 << 20)
    try:
        rows = st._pool_files(None)
        by_file = {r.file: r.state for r in rows}
        assert by_file.get("huge.log") == "skipped", by_file
        # It must survive serialisation too - the 500 came from pydantic, not from the dict above.
        assert any(r.model_dump()["state"] == "skipped" for r in rows)
    finally:
        with st.lock:
            st.pool_plan.pop("huge.log", None)


def test_a_memory_skip_is_reported_as_memory_and_not_as_unreadable(c) -> None:
    """The five reasons must reach the client distinctly — each one means a different fix.

    'unreadable' says the bytes could not be read off disk, and an analyst reading it goes and checks
    the file. 'memory' says the machine had no RAM for it, and the fix is to free some. Reporting the
    second as the first is not a wording slip; it is the wrong instruction. (The UI collapsed them
    because its own `PoolSkip.reason` type declared only two values — this pins the API half.)
    """
    STORE.note_pool_skip("x_big.pcap", "big.pcap", 1_933_574_144, "memory",
                         "needs about 11962 MB of memory and this machine has 6856.0 MB free")
    try:
        rows = c.get("/api/case").json()["poolSkippedFiles"]
        mine = [r for r in rows if r["fileName"] == "x_big.pcap"]
        assert mine, "the skip was not reported at all"
        row = mine[0]
        assert row["reason"] == "memory", f"reason was flattened to {row['reason']!r}"
        assert row["displayName"] == "big.pcap" and row["size"] == 1_933_574_144
        assert "memory" in row["detail"]
    finally:
        STORE.clear_pool_skip("x_big.pcap")


def test_every_skip_reason_survives_the_round_trip(c) -> None:
    """No reason may be silently rewritten on its way to the client."""
    reasons = ["budget", "memory", "unreadable", "parse-error", "not-parsed"]
    for i, r in enumerate(reasons):
        STORE.note_pool_skip(f"x_{i}.log", f"{r}.log", 100, r, f"detail for {r}")
    try:
        rows = {x["fileName"]: x for x in c.get("/api/case").json()["poolSkippedFiles"]}
        got = [rows[f"x_{i}.log"]["reason"] for i in range(len(reasons))]
        assert got == reasons
    finally:
        for i in range(len(reasons)):
            STORE.clear_pool_skip(f"x_{i}.log")
