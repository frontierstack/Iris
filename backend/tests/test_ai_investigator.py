"""The tool-using AI investigator.

No network and no API key: the model is a scripted transcript (FakeModel) that yields exactly what the
real streaming client yields, so the loop, the tool dispatch, the citation checks, the budgets, the stop
switch and the SSE framing are all exercised against real store mutations.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app.ai import investigator, runs as ai_runs
from app.ai.client import LLMClient
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


# ------------------------------------------------------------------ the fake model
class FakeModel:
    """Replays a scripted list of turns. A turn is {'text':…} and/or {'calls':[(tool, args), …]}."""

    def __init__(self, script=None, default=None, model="fake-model"):
        self.script = list(script or [])
        self.default = default
        self.model = model
        self.configured = True
        self.seen: list[dict] = []

    async def stream_chat(self, messages, tools=None, max_tokens=1400, temperature=0.1, tool_choice="auto"):
        self.seen.append({"messages": [dict(m) for m in messages], "tools": tools, "tool_choice": tool_choice})
        turn = self.script.pop(0) if self.script else (self.default or {"text": "Nothing further."})
        text = turn.get("text", "")
        for i in range(0, len(text), 17):
            yield {"type": "text", "text": text[i:i + 17]}
        msg = {"role": "assistant", "content": text}
        calls = turn.get("calls") or []
        if calls and tool_choice != "none":
            msg["tool_calls"] = [{"id": f"c{n}", "type": "function",
                                  "function": {"name": name, "arguments": json.dumps(args)}}
                                 for n, (name, args) in enumerate(calls)]
        yield {"type": "message", "message": msg, "finish": "tool_calls" if msg.get("tool_calls") else "stop"}


out_fake: list[FakeModel] = []


def run_agent(objective, script=None, default=None, run_id=None, **kw) -> list[dict]:
    """Drive the generator to completion and return every SSE payload it produced."""
    fake = FakeModel(script, default)
    rid = run_id or ai_runs.new_id()

    async def go():
        return [ev async for ev in investigator.investigate(STORE, objective, rid, client=fake, **kw)]

    out = asyncio.run(go())
    out_fake.append(fake)
    return out


def of(events, kind) -> list[dict]:
    return [e for e in events if e["type"] == kind]


def a_real_event_id() -> str:
    return STORE.events[0].id


# ------------------------------------------------------------------ the loop
def test_loop_runs_tools_in_order_then_answers(client):
    """The spine of the loop — plus the documentation check that now sits at the end of it.

    A run that investigated (>= DOCUMENT_MIN_CALLS tool calls) and wrote NOTHING to the case is asked
    once, before it is allowed to finish, whether it should record what it found. That is an extra
    model turn, which is why this test scripts five and not four: the fifth is the model declining,
    which for a plain question is the right answer. See investigator.DOCUMENT_CHECK.
    """
    eid = a_real_event_id()
    evs = run_agent("what happened?", [
        {"text": "Orienting.", "calls": [("get_case_state", {})]},
        {"calls": [("search_events", {"query": "", "limit": 3})]},
        {"calls": [("get_event", {"eventId": eid})]},
        {"text": f"Nothing malicious, based on `{eid}`."},
        {"text": f"Nothing here warrants a case artefact. Based on `{eid}`."},
    ])
    assert evs[0]["type"] == "run" and evs[0]["maxSteps"] >= 1
    assert [c["name"] for c in of(evs, "tool_call")] == ["get_case_state", "search_events", "get_event"]
    assert all(r["ok"] for r in of(evs, "tool_result"))
    assert [s["step"] for s in of(evs, "step")] == [1, 2, 3, 4, 5]
    assert any(s.get("documentCheck") for s in of(evs, "status")), "the case write-up was never offered"
    answer = of(evs, "answer")
    assert len(answer) == 1 and eid in answer[0]["text"]
    done = evs[-1]
    assert done["type"] == "done" and done["reason"] == "complete" and done["steps"] == 5
    assert done["toolCalls"] == 3 and done["writes"] == 0
    # the model's prose is streamed as it is written, not only at the end
    assert "".join(d["text"] for d in of(evs, "delta")).startswith("Orienting.")
    # the tool results really went back into the transcript
    fake = out_fake[-1]
    roles = [m["role"] for m in fake.seen[-1]["messages"]]
    assert roles.count("tool") == 3 and roles[0] == "system"


def test_search_results_are_real_events(client):
    evs = run_agent("find things", [{"calls": [("search_events", {"query": "", "limit": 5})]}, {"text": "ok"}])
    rows = of(evs, "tool_result")[0]["data"]["rows"]
    assert rows and all(STORE.event(r["id"]) is not None for r in rows)


# ------------------------------------------------------------------ writes + provenance
def test_writes_mutate_the_store_and_are_attributed_to_the_ai(client):
    eid = a_real_event_id()
    before_notes = len(STORE.notes)
    evs = run_agent("build the case", [
        {"calls": [("add_events_to_case", {"eventIds": [eid], "labels": ["initial access"], "note": "seed"})]},
        {"calls": [("add_ioc", {"kind": "ipv4", "value": "203.0.113.77", "note": "c2",
                                "citedEventIds": [eid]})]},
        {"calls": [("add_note", {"text": "Timeline reconstructed.", "citedEventIds": [eid]})]},
        {"text": "Done."},
    ])
    writes = of(evs, "write")
    assert [w["action"]["tool"] for w in writes] == ["add_events_to_case", "add_ioc", "add_note"]

    entry = STORE.case_set.get(eid)
    assert entry is not None and "ai" in entry.labels          # provenance survives in case.json

    iocs = client.get("/api/iocs").json()["iocs"]
    ioc = next(i for i in iocs if i["value"] == "203.0.113.77")
    assert ioc["addedBy"] == "ai" and ioc["manual"] is True and ioc["citedEventIds"] == [eid]
    assert ioc["firstSeen"] == STORE.event(eid).ts             # the citation places it in time

    assert len(STORE.notes) == before_notes + 1
    note = STORE.notes[-1]
    assert note.author.startswith("AI assistant") and [r.value for r in note.refs] == [eid]

    run = client.get(f"/api/ai/runs/{evs[0]['runId']}").json()
    assert len(run["actions"]) == 3 and run["state"] == "done"


def test_undo_takes_the_whole_run_back_off_the_case(client):
    eid = STORE.events[1].id
    evs = run_agent("curate", [
        {"calls": [("add_events_to_case", {"eventIds": [eid], "labels": ["x"]}),
                   ("add_ioc", {"kind": "domain", "value": "undo-me.example", "citedEventIds": [eid]})]},
        {"text": "Done."},
    ])
    rid = evs[0]["runId"]
    assert eid in STORE.case_set
    r = client.post(f"/api/ai/runs/{rid}/undo").json()
    assert r["ok"] and r["undone"] == 2
    assert eid not in STORE.case_set
    assert not any(i["value"] == "undo-me.example" for i in client.get("/api/iocs").json()["iocs"])
    # idempotent
    assert client.post(f"/api/ai/runs/{rid}/undo").json()["undone"] == 0
    assert client.post("/api/ai/runs/run-nope/undo").status_code == 404


def test_graph_link_is_saved_as_ai_authored(client):
    gb = STORE.graph_v2("all")
    ids = list(gb.nodes)
    pair = next((a, b) for a in ids[:20] for b in ids[:20]
                if a != b and (a, b, "co_occurred") not in gb.edges and (b, a, "co_occurred") not in gb.edges)
    eid = a_real_event_id()
    evs = run_agent("connect", [
        {"calls": [("add_graph_link", {"source": pair[0], "target": pair[1], "relation": "co_occurred",
                                       "why": "same session", "confidence": 0.7, "citedEventIds": [eid]})]},
        {"text": "Linked."},
    ])
    assert of(evs, "tool_result")[0]["ok"] is True
    link = next(l for l in STORE.graph_links if l["source"] == pair[0] and l["target"] == pair[1])
    assert link["ai"] is True and link["runId"] == evs[0]["runId"] and link["citedEventIds"] == [eid]
    client.post(f"/api/ai/runs/{evs[0]['runId']}/undo")


# ------------------------------------------------------------------ grounding
def test_fabricated_event_id_is_refused_and_nothing_persists(client):
    before = len(STORE.manual_iocs)
    evs = run_agent("record it", [
        {"calls": [("add_ioc", {"kind": "ipv4", "value": "198.51.100.9", "citedEventIds": ["e999999"]})]},
        {"calls": [("add_note", {"text": "invented", "citedEventIds": ["e999999"]})]},
        {"calls": [("add_events_to_case", {"eventIds": ["nope-1"]})]},
        {"text": "I could not verify those."},
    ])
    results = of(evs, "tool_result")
    assert [r["ok"] for r in results] == [False, False, False]
    assert all("do not exist" in json.dumps(r["data"]) for r in results)
    assert not of(evs, "write")
    assert len(STORE.manual_iocs) == before
    assert not any(i["value"] == "198.51.100.9" for i in client.get("/api/iocs").json()["iocs"])


def test_unverified_ids_in_the_answer_are_flagged(client):
    eid = a_real_event_id()
    evs = run_agent("summarize", [{"text": f"Confirmed in `{eid}` and also `e987654`."}])
    warn = of(evs, "warning")
    assert len(warn) == 1 and warn[0]["ids"] == ["e987654"]
    assert evs[-1]["unverifiedCitations"] == ["e987654"]


def test_case_scoped_writes_refuse_without_a_case(client):
    """A write must never conjure a case — create_case is the only thing that may."""
    pending, name = STORE.pending, STORE.name
    STORE.pending = True
    try:
        evs = run_agent("note it", [
            {"calls": [("add_note", {"text": "x", "citedEventIds": [a_real_event_id()]})]}, {"text": "ok"}])
        res = of(evs, "tool_result")[0]
        assert res["ok"] is False and "create_case" in json.dumps(res["data"])
    finally:
        STORE.pending, STORE.name = pending, name


# ------------------------------------------------------------------ bounds and stopping
def test_step_budget_halts_a_runaway_loop(client):
    evs = run_agent("loop forever", default={"text": "Interim findings.", "calls": [("get_case_state", {})]},
                    max_steps=3)
    assert len(of(evs, "step")) == 3
    assert len(of(evs, "tool_call")) == 3
    done = evs[-1]
    assert done["reason"] == "max_steps" and done["state"] == "done"
    # the wrap-up turn still produces a report, and it is asked for WITHOUT tools
    assert of(evs, "answer")
    assert out_fake[-1].seen[-1]["tool_choice"] == "none"


def test_time_budget_halts_a_runaway_loop(client, monkeypatch):
    """The wall-clock bound, without actually waiting for it: the clock jumps after the first step."""
    ticks = iter([0.0, 0.0, 0.0, 0.0] + [10_000.0] * 100)
    monkeypatch.setattr(investigator.time, "monotonic", lambda: next(ticks))
    evs = run_agent("loop forever", default={"text": "Interim findings.", "calls": [("get_case_state", {})]},
                    max_seconds=30, max_steps=40)
    assert len(of(evs, "tool_call")) == 1
    assert evs[-1]["reason"] == "timeout"
    assert of(evs, "answer")                       # the wrap-up still reports what it found


def test_stop_request_ends_the_run(client):
    rid = ai_runs.new_id()
    fake = FakeModel(default={"calls": [("get_case_state", {})]})

    async def go():
        out = []
        async for ev in investigator.investigate(STORE, "keep going", rid, client=fake, max_steps=20):
            out.append(ev)
            if ev["type"] == "tool_result" and len(of(out, "tool_result")) == 2:
                assert ai_runs.request_stop(rid) is True   # the analyst hits Stop mid-flight
        return out

    evs = asyncio.run(go())
    assert len(of(evs, "tool_call")) == 2                  # halted at the next checkpoint, not at max_steps
    assert evs[-1]["reason"] == "stopped" and evs[-1]["state"] == "stopped"
    assert not of(evs, "answer")                           # a stop skips the wrap-up turn
    assert ai_runs.get(rid)["state"] == "stopped"
    assert ai_runs.request_stop(rid) is False              # no longer live


def test_bad_tool_name_and_bad_json_come_back_as_tool_errors(client):
    evs = run_agent("misbehave", [
        {"calls": [("no_such_tool", {})]},
        {"text": "ok"},
    ])
    res = of(evs, "tool_result")[0]
    assert res["ok"] is False and "no such tool" in json.dumps(res["data"])


# ------------------------------------------------------------------ the HTTP surface
def _sse(resp) -> list[dict]:
    return [json.loads(l[len("data: "):]) for l in resp.text.split("\n") if l.startswith("data: ")]


def _fake_provider(monkeypatch, fake: FakeModel) -> FakeModel:
    """Make the endpoint build our scripted model instead of a real one."""
    monkeypatch.setattr(LLMClient, "from_settings", classmethod(lambda cls, s: fake))
    return fake


def test_endpoint_streams_sse_and_reports_the_run_id(client, monkeypatch):
    eid = a_real_event_id()
    _fake_provider(monkeypatch, FakeModel([{"calls": [("list_sources", {})]},
                                           {"text": f"Two sources, see `{eid}`."}]))
    r = client.post("/api/ai/investigate", json={"prompt": "what sources do we have?"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    rid = r.headers["X-Iris-Run-Id"]
    evs = _sse(r)
    assert evs[0]["type"] == "run" and evs[0]["runId"] == rid
    assert [c["name"] for c in of(evs, "tool_call")] == ["list_sources"]
    assert evs[-1]["type"] == "done" and evs[-1]["runId"] == rid
    assert client.get(f"/api/ai/runs/{rid}").json()["state"] == "done"


def test_disabled_provider_is_one_clear_error(client, monkeypatch):
    off = FakeModel()
    off.configured = False
    _fake_provider(monkeypatch, off)
    evs = _sse(client.post("/api/ai/investigate", json={"prompt": "go"}))
    assert [e["type"] for e in evs] == ["run", "error"]
    assert "Settings" in evs[1]["message"]


def test_stop_endpoint_reports_unknown_runs(client):
    assert client.post("/api/ai/investigate/run-unknown/stop").json() == {"ok": False, "runId": "run-unknown"}


def test_tool_surface_is_read_plus_bounded_writes(client):
    body = client.get("/api/ai/tools").json()
    names = {t["name"] for t in body["tools"]}
    assert {"search_events", "get_event", "get_timeline", "graph_path", "list_iocs",
            "aggregate_events", "count_events", "distinct_values", "events_over_time",
            "sample_events"} <= names
    writes = {t["name"] for t in body["tools"] if t["writes"]}
    assert writes == {"create_case", "update_case", "activate_case",
                      "add_events_to_case", "remove_events_from_case", "annotate_case_event",
                      # the BATCH form of the same write: a case timeline is written in one call, not
                      # one call per event (see tests/test_ai_tool_efficiency.py)
                      "annotate_case_events",
                      "add_ioc", "update_ioc", "delete_ioc",
                      "add_note", "update_note", "delete_note",
                      # build_case_graph is the BATCH form: the investigation graph is drawn in one
                      # call, and it may CREATE the nodes extraction never found — which is what makes
                      # a graph drawable at all on a workspace whose sources are still raw.
                      "add_graph_link", "build_case_graph", "delete_graph_link",
                      # the detection catalogue: create/tune/toggle, and delete a CUSTOM rule only
                      "create_detection_rule", "update_detection_rule", "set_detection_rule_enabled",
                      "set_builtin_rule_params", "delete_detection_rule"}
    # nothing that destroys evidence or wipes the built-in catalogue is reachable, by name or by intent
    assert not any(w in n for n in names for w in ("clear", "reset", "wipe", "restore_default"))
    # Curation IS deletable — an agent that can only append leaves its mistakes for the analyst. What
    # must never be deletable is EVIDENCE: the case itself, a source, the pool, a built-in rule.
    assert {n for n in names if "delete" in n} == {"delete_detection_rule", "delete_ioc", "delete_note",
                                                   "delete_graph_link"}
    assert not any(n in names for n in ("delete_case", "delete_source", "delete_event", "delete_events"))
    assert body["limits"]["maxSteps"] <= investigator.MAX_STEPS_CAP
    assert body["limits"]["maxCompactions"] >= 1


def test_empty_prompt_is_refused(client):
    evs = _sse(client.post("/api/ai/investigate", json={"prompt": "   "}))
    assert evs[-1]["type"] == "error" and "objective" in evs[-1]["message"]


def test_get_event_can_return_the_surrounding_log_lines(client):
    """A full event payload is bigger than the UI preview cap, so exercise the handler itself."""
    from app.ai.tools import REGISTRY, RunContext
    eid = a_real_event_id()
    data = REGISTRY["get_event"].fn({"eventId": eid, "contextLines": 2}, RunContext(run_id="t"))
    assert data["id"] == eid and data["raw"]
    ctx = data["fileContext"]
    assert any(l["current"] for l in ctx["lines"])

    # and through the loop, where the oversized payload is summarised rather than streamed whole
    evs = run_agent("look closer", [
        {"calls": [("get_event", {"eventId": eid, "contextLines": 2})]}, {"text": "ok"}])
    assert of(evs, "tool_result")[0]["ok"] is True
