"""`GET /api/anomalies` is a DERIVED cache, not a per-request fold over the event pool.

On the real 1,224,226-event workspace the endpoint walked every event — under the store lock — on every
request (~1 s), and it is asked for twice per screen load (the sidebar count and the Anomalies table).
It is now an `app/anomalies.py` `AsyncCache` slot, built once per key in the background.

Its key is the one thing here that is NOT the same as the graph's: anomalies depend on the RULE
CATALOGUE as well as on the pool. A row carries the rule's current name/severity/kind, and which rules
exist decides which rows exist at all. So these tests pin, separately:

  1. a cache HIT does not iterate `STORE.events` at all;
  2. filters (`sev`, `limit`) served from the cache equal a freshly computed aggregation, exactly;
  3. the cache MISSES on a pool change (ingest) AND on every rule mutation — create, update, toggle,
     delete, restore-defaults, clear, and `STORE.reapply_all_rules()`. A stale detection list is an
     evidence-integrity bug: an analyst reading last version's hits is reading evidence that moved.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app import anomalies as anomaly_mod
from app.anomalies import ANOMALY_CACHE
from app.main import app
from app.rules import RULES_STORE
from app.store import STORE
from tests.conftest import load_sample_case
from tests.conftest import drain_enrichment


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


class _CountingList(list):
    """A list that records every full iteration of itself."""

    def __init__(self, *a):
        super().__init__(*a)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


def _settle(counting, idle: float = 0.4, timeout: float = 15.0) -> None:
    """Wait until no thread is iterating STORE.events any more, then zero the counter.

    Same reason as tests/test_derived_cache.py::_settle — the app walks the pool from unnamed daemon
    threads (index warm, entity-count refresh, library load) and one of those still running from an
    earlier test would otherwise be attributed to our request.
    """
    deadline = time.time() + timeout
    last, stable = counting.iterations, time.time()
    while time.time() < deadline:
        time.sleep(0.05)
        if counting.iterations != last:
            last, stable = counting.iterations, time.time()
        elif time.time() - stable >= idle:
            break
    counting.iterations = 0


def _warm(client) -> None:
    assert client.get("/api/anomalies?limit=200").status_code == 200
    assert anomaly_mod.status()["state"] == "ready"   # small fixture -> built synchronously


# --------------------------------------------------------------- no full scan on a cache hit
def test_anomalies_hit_does_not_iterate_the_event_pool(client, monkeypatch):
    _warm(client)
    counting = _CountingList(STORE.events)
    monkeypatch.setattr(STORE, "events", counting)
    _settle(counting)
    for params in ("limit=200", "limit=1", "sev=critical,high&limit=50", "sev=low", "limit=0"):
        assert client.get(f"/api/anomalies?{params}").status_code == 200
    assert counting.iterations == 0, (
        f"GET /api/anomalies folded the whole event pool {counting.iterations}x on a cache hit — every "
        f"filter must slice the cached aggregation")


def test_anomalies_hit_is_fast(client):
    _warm(client)
    times = []
    for _ in range(3):
        t0 = time.perf_counter()
        client.get("/api/anomalies?limit=200")
        times.append(time.perf_counter() - t0)
    assert min(times) < 1.0, f"/api/anomalies took {min(times)*1000:.0f} ms from cache"


def test_response_carries_the_build_status(client):
    _warm(client)
    st = client.get("/api/anomalies?limit=5").json()["status"]
    assert set(st) == {"state", "events", "target", "pct", "elapsedSec", "buildMs"}
    assert st["state"] == "ready"


# ------------------------------------------------------------------ filters match a fresh build
def _fresh(sev: set[str] | None = None) -> list[dict]:
    """Recompute the aggregation from scratch, ignoring the cache entirely."""
    rows = anomaly_mod._build()
    if sev:
        rows = [r for r in rows if r.sev in sev]
    return [{"ruleId": r.ruleId, "sev": r.sev, "hits": r.hits, "name": r.name, "kind": r.kind,
             "firstSeen": r.firstSeen, "lastSeen": r.lastSeen, "sources": r.sources} for r in rows]


def _served(client, qs: str) -> list[dict]:
    body = client.get(f"/api/anomalies?{qs}").json()
    return [{k: a[k] for k in ("ruleId", "sev", "hits", "name", "kind", "firstSeen", "lastSeen", "sources")}
            for a in body["anomalies"]]


def test_filters_from_cache_match_a_fresh_aggregation(client):
    _warm(client)
    assert _served(client, "limit=1000") == _fresh()
    assert _served(client, "limit=3") == _fresh()[:3]
    for sev in ("critical", "high", "medium", "low", "info", "high,critical"):
        want = _fresh({s for s in sev.split(",")})
        assert _served(client, f"sev={sev}&limit=1000") == want, f"sev={sev} filtered wrongly from the cache"
        assert client.get(f"/api/anomalies?sev={sev}&limit=1000").json()["total"] == len(want)


def test_total_counts_the_filtered_set_not_the_page(client):
    """The sidebar tag reads `total` off a limit=1 request — it must be the whole count, not 1."""
    _warm(client)
    body = client.get("/api/anomalies?limit=1").json()
    assert body["total"] == len(_fresh())
    assert len(body["anomalies"]) <= 1


# ------------------------------------------------------------------------------- invalidation
def _key() -> str:
    return anomaly_mod.cache_key()


def _rule_ids(client, **params) -> dict[str, int]:
    body = client.get("/api/anomalies", params={"limit": 1000, **params}).json()
    return {a["ruleId"]: a["hits"] for a in body["anomalies"]}


def test_ingest_invalidates_the_aggregation(client):
    _warm(client)
    before = _rule_ids(client)
    key = _key()
    body = (b"Aug 17 04:11:02 anom-canary sshd[9931]: Failed password for root from 198.51.100.91 port 51000 ssh2\n" * 12)
    r = client.post("/api/sources", files=[("files", ("anom-canary.log", body, "text/plain"))])
    assert r.status_code in (200, 201), r.text
    assert _key() != key, "an ingest must move the anomaly cache key"
    assert ANOMALY_CACHE.peek("all", _key()) is None, "the pre-ingest aggregation was reachable under the NEW key"
    # Two-phase ingest: the parse happens on the enrichment worker, and while it is in flight
    # `Store.derived_builds_paused()` deliberately holds the derived builds off (one bump per
    # source would otherwise restart the whole extraction per file). Wait for the state the
    # analyst actually ends up looking at. The invalidation itself is asserted above.
    drain_enrichment()
    after = _rule_ids(client)
    assert sum(after.values()) > sum(before.values()), "the newly ingested source's hits are missing — a stale list was served"


def test_source_delete_invalidates_the_aggregation(client):
    case = client.get("/api/case").json()
    sid = next(s for s in case["librarySources"] + case["sources"] if "anom-canary" in s["file"])["id"]
    before = sum(_rule_ids(client).values())
    assert client.delete(f"/api/sources/{sid}").status_code == 200
    assert sum(_rule_ids(client).values()) < before, "a deleted source's hits survived — the cache was not invalidated"


def test_reapply_all_rules_invalidates_the_aggregation(client):
    _warm(client)
    key = _key()
    STORE.reapply_all_rules()
    assert _key() != key, "reapply_all_rules must move the anomaly cache key"
    assert ANOMALY_CACHE.peek("all", _key()) is None


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda c: c.post("/api/rules", json={"name": "cache canary", "pattern": "cachecanary",
                                                      "field": "any", "sev": "high"}), id="create"),
    pytest.param(lambda c: c.post("/api/rules/restore-defaults"), id="restore-defaults"),
    pytest.param(lambda c: c.post("/api/rules/clear?scope=custom"), id="clear-custom"),
])
def test_rule_mutations_move_the_cache_key(client, mutate):
    _warm(client)
    key, rev = _key(), RULES_STORE.rev
    r = mutate(client)
    assert r.status_code in (200, 201), r.text
    assert RULES_STORE.rev != rev, "a rule mutation must move RULES_STORE.rev"
    assert _key() != key, "a rule mutation must move the anomaly cache key"
    assert ANOMALY_CACHE.peek("all", _key()) is None
    assert client.get("/api/anomalies?limit=1000").status_code == 200


def test_a_builtin_rename_is_reflected_immediately(client):
    """The rows carry the rule's CURRENT name and severity. A rename that did not invalidate would leave
    the analyst reading a detection under a name that no longer exists anywhere in the catalogue."""
    _warm(client)
    rows = client.get("/api/anomalies?limit=1000").json()["anomalies"]
    target = next(a for a in rows if a["kind"] == "builtin")
    rid = target["ruleId"]
    rule = next(r for r in client.get("/api/rules").json() if r["id"] == rid)
    body = {"name": "renamed by the cache test", "sev": "critical", "description": rule.get("description") or "",
            "pattern": rule.get("pattern") or "", "field": rule.get("field") or "any"}
    assert client.put(f"/api/rules/{rid}", json=body).status_code == 200
    after = next(a for a in client.get("/api/anomalies?limit=1000").json()["anomalies"] if a["ruleId"] == rid)
    assert after["name"] == "renamed by the cache test", "a stale rule name was served from the cache"
    assert after["sev"] == "critical", "a stale severity was served from the cache"
    client.post(f"/api/rules/{rid}/restore")


def test_toggle_and_delete_invalidate(client):
    _warm(client)
    r = client.post("/api/rules", json={"name": "toggle canary", "pattern": "sshd", "field": "any", "sev": "low"})
    assert r.status_code in (200, 201), r.text
    rid = r.json()["id"]
    assert rid in _rule_ids(client), "a newly created rule's hits are missing from the aggregation"
    assert client.post(f"/api/rules/{rid}/toggle").status_code == 200      # -> disabled
    assert rid not in _rule_ids(client), "a disabled rule still had hits — the cache was not invalidated"
    assert client.post(f"/api/rules/{rid}/toggle").status_code == 200      # -> enabled again
    assert rid in _rule_ids(client)
    assert client.delete(f"/api/rules/{rid}").status_code == 200
    assert rid not in _rule_ids(client), "a deleted rule still had hits — the cache was not invalidated"


def test_rules_rev_moves_on_every_mutator(client):
    """`RULES_STORE.rev` is bumped in save(), which every mutator ends with. If a mutator ever stops
    calling save(), this is the test that says so — the cache key would silently stop moving."""
    _warm(client)
    seen = set()
    for call in (lambda: client.post("/api/rules", json={"name": "rev canary", "pattern": "revcanary",
                                                         "field": "any", "sev": "info"}),
                 lambda: client.post("/api/rules/clear?scope=custom"),
                 lambda: client.post("/api/rules/restore-defaults")):
        rev = RULES_STORE.rev
        assert call().status_code in (200, 201)
        assert RULES_STORE.rev > rev
        seen.add(RULES_STORE.rev)
    assert len(seen) == 3


def test_ai_list_detections_blocks_rather_than_reporting_none(client):
    """The `list_detections` agent tool reads the BLOCKING accessor. An agent cannot poll a `building`
    status the way a screen can, so serving it the empty in-flight payload would have it state that no
    detection fired — a false claim about the evidence, in a report."""
    from app.ai.tools import REGISTRY, RunContext
    load_sample_case(client)
    anomaly_mod.invalidate()
    out = REGISTRY["list_detections"].fn({"limit": 50}, RunContext(run_id="test"))
    assert out["total"] == len(_fresh()) and out["total"] > 0
    assert out["detections"], "the agent was told nothing fired while the aggregation was building"
    assert out["detections"][0]["ruleId"] == _fresh()[0]["ruleId"]
    sev = REGISTRY["list_detections"].fn({"limit": 50, "sev": "high,critical"}, RunContext(run_id="test"))
    assert sev["total"] == len(_fresh({"high", "critical"}))


def test_clear_all_drops_the_cached_aggregation(client):
    load_sample_case(client)
    _warm(client)
    assert ANOMALY_CACHE.peek("all", _key()) is not None
    client.post("/api/admin/clear-all", json={"confirm": "DELETE ALL DATA"})
    assert ANOMALY_CACHE.peek("all", _key()) is None
    assert client.get("/api/anomalies?limit=50").json()["anomalies"] == []
