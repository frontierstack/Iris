"""AI graph reviewer (POST /api/graph/ai-review): the model is monkeypatched, no network is used."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import app.ai.graph_review as graph_review
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def _events(client, body=None) -> list[dict]:
    r = client.post("/api/graph/ai-review", json=body or {})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/event-stream")
    return [json.loads(line[len("data: "):]) for line in r.text.split("\n") if line.startswith("data: ")]


def _pick_pairs():
    """From the real sample-case graph: one existing deterministic edge, and one (a, b, relation) that does NOT exist."""
    gb = STORE.graph_v2("all")
    existing = next(iter(gb.edges))                       # (source, target, relation)
    ids = list(gb.nodes)
    novel = None
    for a in ids:
        for b in ids:
            if a != b and (a, b, "connected_to") not in gb.edges and (b, a, "connected_to") not in gb.edges:
                novel = (a, b, "connected_to")
                break
        if novel:
            break
    assert novel is not None
    return existing, novel


def _mock_model(monkeypatch, reply: dict) -> dict:
    calls: dict = {}

    async def fake_json(self, system, user, max_tokens=800, temperature=0.0):
        calls["system"], calls["user"] = system, user
        return reply

    monkeypatch.setattr(graph_review.LLMClient, "complete_json", fake_json)
    monkeypatch.setattr(graph_review.LLMClient, "configured", property(lambda self: True))
    return calls


def test_ai_disabled_single_error(client, monkeypatch):
    monkeypatch.setattr(graph_review.LLMClient, "configured", property(lambda self: False))
    evs = _events(client)
    assert len(evs) == 1
    assert evs[0]["type"] == "error"
    assert evs[0]["message"] == graph_review.DISABLED_MESSAGE


def test_validator_keeps_only_real_links(client, monkeypatch):
    (es, et, er), (ns, nt, nr) = _pick_pairs()
    gb = STORE.graph_v2("all")
    reply = {
        "links": [
            {"source": ns, "target": nt, "relation": nr, "why": "same session id 20 s later", "confidence": 0.8},
            {"source": ns, "target": "host:does-not-exist.example", "relation": "connected_to", "why": "x", "confidence": 0.9},
            {"source": ns, "target": ns, "relation": "connected_to", "why": "self", "confidence": 0.9},
            {"source": es, "target": et, "relation": er, "why": "already known", "confidence": 0.9},
            {"source": ns, "target": nt, "relation": "not_a_relation", "why": "bad vocab", "confidence": 0.9},
        ],
        "aliases": [
            {"a": ns, "b": nt, "reason": "same box"},
            {"a": ns, "b": "ip:0.0.0.0", "reason": "bogus"},
        ],
        "narrative": "Initial access via **" + ns + "**, then pivot.",
    }
    calls = _mock_model(monkeypatch, reply)
    evs = _events(client, {"scope": "all"})
    types = [e["type"] for e in evs]

    # a couple of progress lines before the model answer, and the model was actually asked
    assert types[0] == "thinking" and types.count("thinking") >= 2
    assert any("asking" in e["text"] for e in evs if e["type"] == "thinking")
    assert "NODES" in calls["user"] and "EDGES" in calls["user"] and "SAMPLE EVENTS" in calls["user"]
    assert ns in calls["user"] and f"{es} -{er}-> {et}" in calls["user"]

    links = [e for e in evs if e["type"] == "link"]
    assert len(links) == 1
    edge = links[0]["edge"]
    assert edge["source"] == ns and edge["target"] == nt and edge["relation"] == nr
    assert edge["ai"] is True and edge["count"] == 0 and edge["eventIds"] == []
    assert edge["confidence"] == 0.8 and links[0]["confidence"] == 0.8
    assert edge["id"] == f"{ns}|{nr}|{nt}"
    assert (ns, nt, nr) not in gb.edges

    aliases = [e for e in evs if e["type"] == "alias"]
    assert aliases == [{"type": "alias", "a": ns, "b": nt, "reason": "same box"}]

    narrative = [e for e in evs if e["type"] == "narrative"]
    assert len(narrative) == 1 and narrative[0]["text"].startswith("Initial access via")

    assert evs[-1] == {"type": "done", "links": 1, "aliases": 1}
    # ordering: thinking* → link → alias → narrative → done, and no error
    assert "error" not in types
    assert types.index("link") < types.index("alias") < types.index("narrative") < types.index("done")


def test_confidence_is_clamped(client, monkeypatch):
    _, (ns, nt, nr) = _pick_pairs()
    gb = STORE.graph_v2("all")
    # a second novel pair using a different relation on the same nodes
    other_rel = next(r for r in graph_review.RELATIONS if r != nr and (ns, nt, r) not in gb.edges and (nt, ns, r) not in gb.edges)
    reply = {
        "links": [
            {"source": ns, "target": nt, "relation": nr, "why": "too sure", "confidence": 1.7},
            {"source": ns, "target": nt, "relation": other_rel, "why": "negative", "confidence": -0.3},
        ],
        "aliases": [],
        "narrative": "n/a",
    }
    _mock_model(monkeypatch, reply)
    evs = _events(client)
    confs = {e["edge"]["relation"]: e["edge"]["confidence"] for e in evs if e["type"] == "link"}
    assert confs == {nr: 1.0, other_rel: 0.0}
    assert evs[-1] == {"type": "done", "links": 2, "aliases": 0}


def test_model_failure_becomes_error_event(client, monkeypatch):
    async def boom(self, system, user, max_tokens=800, temperature=0.0):
        raise graph_review.AIError("openai HTTP 500")

    monkeypatch.setattr(graph_review.LLMClient, "complete_json", boom)
    monkeypatch.setattr(graph_review.LLMClient, "configured", property(lambda self: True))
    evs = _events(client)
    assert evs[-1]["type"] == "error" and "500" in evs[-1]["message"]
    assert all(e["type"] in ("thinking", "error") for e in evs)
