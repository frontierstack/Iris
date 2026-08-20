"""Every AI tool must actually run.

The analyst asked "what logs does 10.0.0.100 exist in?" and the field-facet tool failed on EVERY call
with `'Query' object has no attribute 'strip'`, so the agent could not tell whether the IP was a
structured field or only a free-text match — and said so in its answer. A tool that reliably fails is
worse than one that does not exist, because the model burns steps on it.

The cause was structural, not a typo: `app/ai/tools.py` calls FastAPI route handlers directly, and a
handler declared `from_: Optional[str] = Query(None, alias="from")` does NOT have `None` as its Python
default — it has a `fastapi.params.Query` OBJECT, which FastAPI only replaces when it invokes the
handler through the request pipeline. Any tool that omitted such a parameter passed a sentinel into
the body. events.py, graph.py, timeline.py, iocs.py and sources.py all carry `Query(...)` defaults, so
this was one call away from happening again somewhere else.

So there are two tests here, and the second is the one that would have caught it:
  1. `call_route` resolves every declared default, and a `Query` sentinel is recognisable; and
  2. EVERY registered tool is invoked with minimal arguments against a real fixture pool and must not
     raise anything but a deliberate `ToolError`, and must not leak a sentinel into its result.
"""
from __future__ import annotations

import json

import pytest
from fastapi import Query
from fastapi.testclient import TestClient

from app.ai.tools import REGISTRY, RunContext, ToolError, call_route, is_fastapi_sentinel
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


# ------------------------------------------------------------------ the mechanism
def test_call_route_resolves_fastapi_defaults(client):
    from app.routers.events import list_fields

    seen: dict = {}

    def spy(q: str = "", sources: str = "", sev: str = "",
            from_=Query(None, alias="from"), to=None,
            scope: str = Query("all", pattern="^(all|case)$"), limit: int = Query(40, ge=1, le=500)):
        seen.update(locals())
        return {"ok": True}

    call_route(spy, q="x")
    assert seen["q"] == "x"
    assert seen["from_"] is None          # the sentinel is gone — this is the analyst's crash
    assert seen["scope"] == "all"         # and the REAL default is used, not the Query object
    assert seen["limit"] == 40
    assert not any(is_fastapi_sentinel(v) for v in seen.values())

    # the real handler, called the way the tool calls it
    res = call_route(list_fields, q="", scope="all", limit=5)
    assert "fields" in res and "events" in res and "sampled" in res

    with pytest.raises(TypeError):
        call_route(spy, notAParameter=1)


def test_is_fastapi_sentinel_recognises_query_objects():
    assert is_fastapi_sentinel(Query(None, alias="from")) is True
    assert is_fastapi_sentinel(Query("all")) is True
    assert is_fastapi_sentinel("all") is False
    assert is_fastapi_sentinel(None) is False


# ------------------------------------------------------------------ every tool
def _minimal_args(name: str) -> dict:
    """The smallest plausible call for each tool — enough to reach the body, not to be clever."""
    eid = STORE.events[0].id
    node = next(iter(STORE.graph_v2("all").nodes), "ip:127.0.0.1")
    per_tool = {
        "search_events": {"query": "", "limit": 3, "include": "raw,fields"},
        "get_event": {"eventId": eid, "contextLines": 2},
        "get_events": {"eventIds": [e.id for e in STORE.events[:5]], "include": "raw,fields,entities"},
        "entity_profile": {"value": (STORE.events[0].entities or ["nothing-at-all"])[0]},
        "annotate_case_events": {"entries": [{"eventId": eid, "labels": ["smoke"], "note": "smoke"}]},
        "list_event_fields": {"query": "", "limit": 5},
        "graph_find": {"query": "", "limit": 3},
        "graph_node": {"nodeId": node},
        "graph_path": {"from": node, "to": node},
        "create_case": {"name": "smoke-test case"},
        "update_case": {"summary": "smoke"},
        "add_events_to_case": {"eventIds": [eid], "labels": ["smoke"]},
        "remove_events_from_case": {"eventIds": [eid]},
        "add_ioc": {"kind": "ipv4", "value": "203.0.113.222", "citedEventIds": [eid]},
        "add_note": {"text": "smoke", "citedEventIds": [eid]},
        "add_graph_link": {"source": node, "target": node, "relation": "co_occurred", "why": "smoke",
                           "citedEventIds": [eid]},
        # aggregation — the tools that answer a question without returning rows
        "count_events": {"query": ""},
        "aggregate_events": {"query": "", "groupBy": "source"},
        "distinct_values": {"query": "", "field": "sev"},
        "events_over_time": {"query": "", "bucket": "hour"},
        "sample_events": {"query": "", "n": 3},
        # the detection catalogue
        "list_detection_rules": {"limit": 5},
        "create_detection_rule": {"name": "smoke rule", "pattern": "zzz-smoke-not-present", "sev": "low"},
        "update_detection_rule": {"ruleId": "RULE-9999", "name": "nope"},
        "set_detection_rule_enabled": {"ruleId": "RULE-9999", "enabled": False},
        "set_builtin_rule_params": {"ruleId": "SIGMA-AUTH-0111", "params": {}},
        "delete_detection_rule": {"ruleId": "RULE-9999"},
    }
    return per_tool.get(name, {})


def test_every_registered_tool_runs_without_crashing(client):
    """The regression net. A refusal (ToolError) is a legitimate answer; an exception is a bug."""
    ctx = RunContext(run_id="smoke", model="test")
    failures: list[str] = []
    for name, t in REGISTRY.items():
        try:
            result = t.fn(_minimal_args(name), ctx)
        except ToolError:
            continue                     # a deliberate, model-readable refusal
        except Exception as exc:         # noqa: BLE001 — this is exactly what we are testing for
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        assert isinstance(result, dict), name
        # nothing that leaked a FastAPI sentinel can be serialised back to the model
        assert not any(is_fastapi_sentinel(v) for v in result.values()), name
        json.dumps(result, default=str)
    assert not failures, "tools raised: " + "; ".join(failures)


def test_list_event_fields_answers_the_analysts_question(client):
    """'what logs does <ip> exist in' — the facet tool has to work with only a query, no time bounds."""
    ctx = RunContext(run_id="facets", model="test")
    out = REGISTRY["list_event_fields"].fn({"query": ""}, ctx)
    assert out["events"] > 0 and out["fields"]
    assert isinstance(out["sampled"], bool)
    names = {f["name"] for f in out["fields"]}
    assert {"source", "file", "sev"} <= names
    assert all(isinstance(f["count"], int) and f["topValues"] is not None for f in out["fields"])

    # and with a real term, scoped, exactly as the agent would call it after a search
    ip = next((e for e in STORE.events if e.host), None)
    scoped = REGISTRY["list_event_fields"].fn({"query": ip.host if ip else "", "limit": 5}, ctx)
    assert isinstance(scoped["events"], int)
