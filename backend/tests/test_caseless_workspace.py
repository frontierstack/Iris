"""Analysis without a case.

"Everything should work without a case — search, entity graph etc. A case is just there to document and
combine info if an investigation is needed."

So the parsed event pool belongs to the WORKSPACE, not to a case: a file staged in the library is parsed,
searched, correlated, detected on and graphed with zero cases on disk. A case adds the curated case set,
notes, manual IOCs, accepted graph links and the report on top.

The two things that can silently break that model are double counting on ATTACH (the events already
exist — attaching must move the source, never re-parse it) and double counting on RESTART
(restore_library APPENDS, exactly like restore). Both are asserted here with exact totals.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import cases, config
from app.main import app
from app.store import STORE

# An SSH brute-force burst (SIGMA-LNX-0045 needs 10 failures in 300 s) followed by a success, so
# detections, clusters, the graph and IOC extraction all have something to say about it.
LOG = b"".join(
    b"Jan 01 00:00:%02d host sshd[1%02d]: Failed password for root from 45.66.13.201 port 22 ssh2\n" % (i, i)
    for i in range(1, 13)
) + b"Jan 01 00:00:30 host sshd[130]: Accepted password for alice from 45.66.13.201 port 22 ssh2\n"
N = len(LOG.splitlines())

OTHER = b"Jan 02 09:00:00 web-01 nginx: 198.51.100.7 - - [02/Jan/2026:09:00:00 +0000] \"GET /x HTTP/1.1\" 200 12\n"


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _wipe(c) -> None:
    """No cases AND no library: every test here starts from a genuinely empty workspace."""
    for cid in list(cases.case_ids()):
        c.delete(f"/api/cases/{cid}")
    for f in c.get("/api/library").json():
        if f["caseId"] == "":
            c.delete(f"/api/library/unattached/{f['fileName']}")
    assert c.get("/api/cases").json() == []
    assert c.get("/api/case").json()["poolEventCount"] == 0


def _stage(c, name: str, data: bytes = LOG) -> dict:
    r = c.post("/api/library/upload", files=[("files", (name, data, "text/plain"))])
    assert r.status_code == 200, r.text
    return r.json()[0]


# ------------------------------------------------------------------ analysis with zero cases
def test_search_works_with_zero_cases(c) -> None:
    _wipe(c)
    _stage(c, "caseless.log")

    assert c.get("/api/cases").json() == [], "staging must not have created a case"
    r = c.get("/api/events", params={"q": "alice"}).json()
    assert r["total"] == 1, r
    assert r["rows"][0]["file"] == "caseless.log"
    # and the whole pool is listable
    assert c.get("/api/events", params={"limit": 100}).json()["total"] == N


def test_timeline_anomalies_graph_and_iocs_all_work_with_zero_cases(c) -> None:
    _wipe(c)
    _stage(c, "detect-me.log")
    assert c.get("/api/cases").json() == []

    tl = c.get("/api/timeline").json()
    assert tl["stats"] and int(tl["stats"]["entities"]) > 0, tl

    anomalies = c.get("/api/anomalies").json()
    assert anomalies["total"] > 0, "detections must run on a case-less pool"

    graph = c.get("/api/graph").json()
    assert graph["nodes"], "the entity graph must build with no case"
    assert graph["stats"]["totalNodes"] > 1 and graph["edges"], graph["stats"]

    iocs = c.get("/api/iocs").json()
    assert iocs["total"] > 0 and any(i["value"] == "45.66.13.201" for i in iocs["iocs"])

    # event detail (correlations + baseline) resolves too
    eid = c.get("/api/events", params={"limit": 1}).json()["rows"][0]["id"]
    assert c.get(f"/api/events/{eid}").status_code == 200
    assert c.get("/api/events/fields").json()["fields"]


def test_uploading_with_no_case_creates_no_case_directory(c) -> None:
    _wipe(c)
    pending_id = c.get("/api/case").json()["id"]
    before = set(cases.case_ids())

    c.post("/api/sources", files=[("files", ("via-sources.log", LOG, "text/plain"))])
    _stage(c, "via-library.log")

    assert c.get("/api/cases").json() == []
    assert set(cases.case_ids()) == before == set()
    assert not config.case_dir(pending_id).exists()
    assert STORE.pending is True
    assert c.get("/api/case").json()["poolEventCount"] == 2 * N


# ------------------------------------------------------------------ attach must not double count
def test_attaching_a_library_source_does_not_double_count(c) -> None:
    _wipe(c)
    staged = _stage(c, "attach-me.log")
    before = c.get("/api/events", params={"limit": 1}).json()["total"]
    assert before == N
    ids_before = {r["id"] for r in c.get("/api/events", params={"limit": 500}).json()["rows"]}

    made = c.post("/api/cases", json={"name": "Curating"}).json()
    assert c.get("/api/events", params={"limit": 1}).json()["total"] == before, "creating a case moved events"

    r = c.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": staged["fileName"]}]})
    assert r.status_code == 200, r.text

    after = c.get("/api/events", params={"limit": 1}).json()["total"]
    assert after == before, f"attach duplicated the file's events ({before} -> {after})"
    ids_after = {r["id"] for r in c.get("/api/events", params={"limit": 500}).json()["rows"]}
    assert ids_after == ids_before, "attach re-parsed the file instead of moving the source"

    case = c.get("/api/case").json()
    assert case["id"] == made["id"] and case["pending"] is False
    assert case["eventCount"] == N, "the file is now IN the case"
    assert case["librarySources"] == [], "and no longer floating in the case-less pool"
    assert case["poolEventCount"] == N

    # attaching the same file twice is idempotent, not additive
    c.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": staged["fileName"]}]})
    assert c.get("/api/events", params={"limit": 1}).json()["total"] == before


def test_restart_restores_the_library_pool_exactly_once(c) -> None:
    _wipe(c)
    _stage(c, "restarted.log")
    total = c.get("/api/events", params={"limit": 1}).json()["total"]
    assert total == N

    for _ in range(2):  # every new TestClient runs the startup lifespan again
        with TestClient(app) as again:
            assert again.get("/api/cases").json() == []
            got = again.get("/api/events", params={"limit": 1}).json()["total"]
            assert got == total, f"a restart duplicated the library pool ({total} -> {got})"
            assert again.get("/api/case").json()["poolEventCount"] == total


def test_restart_after_an_attach_does_not_duplicate_the_file(c) -> None:
    """The staged copy survives an attach, so the restart must load it from the CASE only."""
    _wipe(c)
    staged = _stage(c, "attached-then-restarted.log")
    c.post("/api/cases", json={"name": "Holds it"})
    c.post("/api/library/attach", json={"items": [{"caseId": "", "fileName": staged["fileName"]}]})
    total = c.get("/api/events", params={"limit": 1}).json()["total"]
    assert total == N
    assert (config.LIBRARY_DIR / staged["fileName"]).is_file(), "the staged bytes must survive an attach"

    with TestClient(app) as again:
        got = again.get("/api/events", params={"limit": 1}).json()["total"]
        assert got == total, f"restart re-parsed the staged copy on top of the case copy ({total} -> {got})"
        case = again.get("/api/case").json()
        assert case["eventCount"] == N and case["librarySources"] == []


# ------------------------------------------------------------------ the case is still a case
def test_scope_case_still_returns_only_curated_events(c) -> None:
    _wipe(c)
    _stage(c, "pool.log")
    c.post("/api/cases", json={"name": "Curated"})
    rows = c.get("/api/events", params={"limit": 500}).json()["rows"]
    assert len(rows) == N
    c.post(f"/api/case-set/{rows[0]['id']}")

    assert c.get("/api/events", params={"scope": "case", "limit": 500}).json()["total"] == 1
    assert c.get("/api/events", params={"limit": 500}).json()["total"] == N
    assert len(c.get("/api/iocs", params={"scope": "case"}).json()["iocs"]) <= len(c.get("/api/iocs").json()["iocs"])


def test_switching_cases_preserves_the_caseless_pool(c) -> None:
    _wipe(c)
    _stage(c, "floating.log")
    a = c.post("/api/cases", json={"name": "A"}).json()
    c.post("/api/sources", files=[("files", ("in-case-a.log", OTHER, "text/plain"))])
    assert c.get("/api/case").json()["eventCount"] == 1
    assert c.get("/api/events", params={"limit": 1}).json()["total"] == N + 1  # library pool + 1 case event

    b = c.post("/api/cases", json={"name": "B"}).json()
    case = c.get("/api/case").json()
    assert case["id"] == b["id"]
    assert case["eventCount"] == 0, "case B is empty"
    assert case["poolEventCount"] == N, "the case-less pool must survive the switch, exactly once"
    assert [s["file"] for s in case["librarySources"]] == ["floating.log"]
    assert c.get("/api/events", params={"q": "alice"}).json()["total"] == 1

    c.post(f"/api/cases/{a['id']}/activate")
    back = c.get("/api/case").json()
    assert back["eventCount"] == 1 and back["poolEventCount"] == N + 1


def test_deleting_every_case_leaves_the_pool_analysable(c) -> None:
    _wipe(c)
    _stage(c, "survivor.log")
    c.post("/api/cases", json={"name": "Doomed"})
    c.post("/api/sources", files=[("files", ("doomed.log", OTHER, "text/plain"))])
    assert c.get("/api/events", params={"limit": 1}).json()["total"] == N + 1

    for cid in list(cases.case_ids()):
        c.delete(f"/api/cases/{cid}")

    assert c.get("/api/cases").json() == []
    case = c.get("/api/case").json()
    assert case["pending"] is True
    assert case["poolEventCount"] == N, "the case-less pool went down with the case"
    assert c.get("/api/events", params={"q": "alice"}).json()["total"] == 1
    assert c.get("/api/graph").json()["nodes"]


def test_deleting_a_staged_file_removes_it_from_the_pool(c) -> None:
    _wipe(c)
    staged = _stage(c, "regret.log")
    assert c.get("/api/events", params={"limit": 1}).json()["total"] == N
    assert c.delete(f"/api/library/unattached/{staged['fileName']}").status_code == 200
    assert c.get("/api/events", params={"limit": 1}).json()["total"] == 0
    assert c.get("/api/case").json()["librarySources"] == []


def test_case_documentation_still_requires_a_case(c) -> None:
    """What a case is FOR keeps needing one — worded as normal behaviour, not as a failure."""
    _wipe(c)
    _stage(c, "no-case-here.log")
    pending_id = c.get("/api/case").json()["id"]

    assert c.get(f"/api/cases/{pending_id}").status_code == 404
    assert c.get(f"/api/cases/{pending_id}/notes").status_code == 404
    # the case set is empty and adding to it materialises nothing on disk beforehand
    assert c.get("/api/case-set").json()["entries"] == []
    assert not config.case_dir(pending_id).exists()
