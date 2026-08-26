"""POST /api/admin/clear-all must clear ALL of it — disk and memory.

The analyst's report was "clearing all data in settings does not clear the data at all", and it was
accurate: clear_all only ever knew about the ACTIVE case. Everything else came through untouched —
other cases with their uploads and notes, the deleted-case trash, the whole case-less library (bytes
AND the events parsed from them, so search kept returning hits), and jobs.json. A restart then
restored the lot.

So this seeds a realistic workspace (two cases, an upload each, notes, a manual IOC, a case-set entry,
a trashed case, a staged library file that is parsed into the pool, jobs, a custom rule) and pins both
directions: nothing survives in memory, nothing survives on disk, and a fresh cases.startup() —
standing in for a container restart — still comes up empty.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import cases, config
from app.ai.history import HISTORY as AI_HISTORY, HistoryStore
from app.jobs import REGISTRY
from app.main import app
from app.store import STORE

LOG = b"".join(
    b"Jan 01 00:00:%02d host sshd[1%02d]: Failed password for root from 45.66.13.201 port 22 ssh2\n" % (i, i)
    for i in range(1, 13)
)
OTHER = b"Jan 02 09:00:00 web-01 nginx: 198.51.100.7 - - [02/Jan/2026:09:00:00 +0000] \"GET /x HTTP/1.1\" 200 12\n"


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def _seed(c) -> str:
    """A workspace with something of every kind in it. Returns the active case id."""
    a = c.post("/api/cases", json={"name": "Case A"}).json()["id"]
    assert c.post("/api/sources", files=[("files", ("a.log", LOG, "text/plain"))]).status_code == 200
    c.post(f"/api/cases/{a}/notes", json={"text": "a note"})
    c.post("/api/iocs", json={"type": "ip", "value": "45.66.13.201", "note": "manual"})
    rows = c.get("/api/events?limit=5").json()["rows"]
    assert rows
    c.post(f"/api/case-set/{rows[0]['id']}")
    # a second case, deleted so it lands in .trash/ with its uploads
    b = c.post("/api/cases", json={"name": "Case B"}).json()["id"]
    c.post("/api/sources", files=[("files", ("b.log", OTHER, "text/plain"))])
    c.delete(f"/api/cases/{b}")
    c.post(f"/api/cases/{a}/activate")
    # a case-less staged file — parsed into the pool, invisible to case_ids()
    assert c.post("/api/library/upload", files=[("files", ("lib.log", LOG, "text/plain"))]).status_code == 200
    # two AI conversations. A transcript quotes the evidence verbatim, so it IS evidence and must go too.
    for rid, prompt in (("run-wipe-1", "trace 45.66.13.201"), ("run-wipe-2", "build me a timeline")):
        AI_HISTORY.start(rid, prompt, "test-model", case_id=a, case_name="Case A")
        AI_HISTORY.append(rid, {"kind": "tool", "name": "search_events", "id": "c0", "args": {"query": "sshd"}})
        AI_HISTORY.finish(rid, "done", "complete", 2, 1, "Failed password for root from 45.66.13.201.", [], [])
    return a


def _seeded(c) -> str:
    a = _seed(c)
    assert len(c.get("/api/cases").json()) >= 2
    case = c.get("/api/case").json()
    assert case["eventCount"] > 0 and case["poolEventCount"] > case["eventCount"]
    assert c.get("/api/cases/trash").json(), "the trashed case should be recoverable before the wipe"
    assert any(f["caseId"] == "" for f in c.get("/api/library").json())
    assert c.get("/api/jobs").json()["jobs"]
    assert len(c.get("/api/ai/runs").json()["runs"]) == 2
    return a


def test_clear_all_empties_memory_and_the_api(c) -> None:
    _seeded(c)
    body = c.post("/api/admin/clear-all", json={}).json()
    assert body["ok"] is True
    r = body["removed"]
    assert r["sources"] >= 2 and r["events"] >= 2 and r["files"] >= 3
    assert r["cases"] >= 2 and r["trash"] >= 1 and r["jobs"] >= 1
    assert r["aiRuns"] == 2   # the analyst is told the transcripts went too

    assert c.get("/api/cases").json() == []
    case = c.get("/api/case").json()
    assert case["eventCount"] == 0 and case["poolEventCount"] == 0
    assert case["sources"] == [] and case["librarySources"] == []
    assert case["pending"] is True  # an id is reserved, but nothing exists
    assert c.get("/api/events?limit=50").json()["total"] == 0
    assert c.get("/api/events?q=sshd").json()["total"] == 0  # the search index went with it
    assert c.get("/api/library").json() == []
    assert c.get("/api/cases/trash").json() == []
    assert c.get("/api/jobs").json()["jobs"] == []
    assert c.get("/api/iocs").json()["iocs"] == []
    assert c.get("/api/ai/runs").json()["runs"] == []
    assert c.get("/api/ai/runs/run-wipe-1").status_code == 404
    with STORE.lock:
        assert STORE.events == [] and STORE.sources == {} and STORE.source_order == []
        assert STORE.case_set == {} and STORE.notes == [] and STORE.manual_iocs == []
        assert STORE.graph_links == []


def test_clear_all_leaves_nothing_on_disk(c) -> None:
    _seeded(c)
    c.post("/api/admin/clear-all", json={})
    left = {str(p.relative_to(config.DATA_DIR)).replace("\\", "/")
            for p in config.DATA_DIR.rglob("*") if p.is_file()}
    # only bookkeeping and preserved configuration may remain
    assert not [p for p in left if p.startswith("cases/") and p != "cases/index.json"], left
    assert not [p for p in left if p.startswith("library/")], left
    assert not [p for p in left if p.startswith(".trash/")], left
    assert "jobs.json" not in left, left
    # A transcript can quote a log line verbatim, so ai/history.json is evidence and may not survive.
    # ai/system_prompts.json is the analyst's own standing instructions for the assistant:
    # CONFIGURATION, kept exactly like rules.json and exclusions.json (app/ai/system_prompts.py).
    # An allowlist, not `startswith("ai/")` - the blanket form quietly meant "that feature may not
    # exist", and it is the sort of assertion a new config file trips a release later.
    assert not [p for p in left if p.startswith("ai/") and p != "ai/system_prompts.json"], left
    assert not any("45.66.13.201" in p for p in left), left
    assert not config.LIBRARY_DIR.exists() and not config.TRASH_DIR.exists()
    assert cases.case_ids() == []


def test_clear_all_survives_a_restart(c) -> None:
    _seeded(c)
    c.post("/api/admin/clear-all", json={})
    cases.startup()  # what the FastAPI lifespan does on a container restart
    assert cases.case_ids() == []
    with STORE.lock:
        assert STORE.events == [] and STORE.sources == {}
    assert c.get("/api/cases").json() == []
    assert c.get("/api/case").json()["poolEventCount"] == 0
    assert c.get("/api/events?limit=50").json()["total"] == 0
    REGISTRY.load()
    assert REGISTRY.snapshot()["jobs"] == []
    # the AI history must come up empty in MEMORY and on DISK — a fresh store shares neither with the
    # one that did the wipe, so this is the "restart brings it all back" regression
    AI_HISTORY.load()
    assert AI_HISTORY.listing(50) == []
    fresh = HistoryStore()
    fresh.load()
    assert fresh.listing(50) == []
    assert AI_HISTORY.reconcile() == 0
    assert c.get("/api/ai/runs").json()["runs"] == []


def test_clear_all_keeps_rules_and_settings(c) -> None:
    """The deliberate exceptions — the UI copy states both."""
    c.put("/api/settings", json={"analyst": "Keeper"})
    made = c.post("/api/rules", json={"name": "kept rule", "pattern": "sshd", "severity": "low",
                                      "description": "d", "field": "msg"})
    assert made.status_code in (200, 201), made.text
    _seeded(c)
    c.post("/api/admin/clear-all", json={})
    assert c.get("/api/settings").json()["analyst"] == "Keeper"
    assert any(x["name"] == "kept rule" for x in c.get("/api/rules").json())
    assert config.RULES_PATH.is_file() and config.SETTINGS_PATH.is_file()


def test_clear_all_reset_settings_flag_still_wipes_settings(c) -> None:
    c.put("/api/settings", json={"analyst": "Temp Analyst"})
    _seeded(c)
    c.post("/api/admin/clear-all", json={"resetSettings": True})
    assert c.get("/api/settings").json()["analyst"] == "Analyst"
    assert any(x["name"] for x in c.get("/api/rules").json())  # rules are NOT settings


def test_workspace_is_usable_again_after_clear_all(c) -> None:
    """The wipe must leave a working workspace, not a broken one: staging still works with no case."""
    _seeded(c)
    c.post("/api/admin/clear-all", json={})
    r = c.post("/api/library/upload", files=[("files", ("fresh.log", LOG, "text/plain"))])
    assert r.status_code == 200, r.text
    assert c.get("/api/case").json()["poolEventCount"] == len(LOG.splitlines())
    assert c.get("/api/cases").json() == []  # staging still never invents a case


def test_clear_all_wipes_the_derived_cache_tree(c):
    """A cache built FROM the evidence quotes the evidence. `clear-all` used to remove only the graph
    pickles by name, so anything else under cache/ — the parsed-pool cache, the HMAC key — survived a
    wipe and could repopulate a screen after the next restart."""
    from app import config

    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (config.CACHE_DIR / "graph-all.pkl").write_bytes(b"x")
    (config.CACHE_DIR / "graph.key").write_bytes(b"k" * 32)
    pool = config.CACHE_DIR / "pool"
    pool.mkdir(exist_ok=True)
    (pool / "src-1.pkl").write_bytes(b"events")

    r = c.post("/api/admin/clear-all", json={})
    assert r.status_code == 200
    assert r.json()["removed"]["cache"] >= 3
    assert not any(config.CACHE_DIR.rglob("*"))
