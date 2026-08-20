"""The investigator's second generation: aggregation, compaction, rule editing and honest tool calling.

Four real analyst failures are pinned here, and none of them needs a network or an API key — the model
is the same scripted FakeModel the older investigator tests use.

1. "what logs does 10.0.0.100 exist in?" was answered by paging through rows until the budget ran out,
   ending in "confirmed in one source; the other 29 neither confirmed nor ruled out". It is now ONE
   aggregate_events call with exact per-source counts.
2. "budget reached (max_steps)" mid-investigation. The context ceiling now compacts and CONTINUES.
3. The model could not touch detection rules, so "make this rule less noisy" was not actionable.
4. The model emitted `<tool_call><function=create_case>…` as literal text in its final report, with
   invented parameters. That text form is now parsed into a real call, and can never reach the report.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app.ai import client as ai_client, compaction, investigator, runs as ai_runs
from app.ai.tools import REGISTRY, RunContext, ToolError
from app.main import app
from app.rules import RULES_STORE
from app.store import STORE
from tests.conftest import load_sample_case
from tests.test_ai_investigator import FakeModel, of

# 45.83.140.22 is in the sample pool three times over: the edge access log, the firewall pipe log and
# CloudTrail. Two other sources (the syslog, the k8s audit) do not carry it at all — which is what makes
# it the right probe for "which logs is this in, and which are ruled OUT".
SHARED_IP = "45.83.140.22"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def run_agent(objective, script=None, default=None, run_id=None, **kw):
    fake = FakeModel(script, default)
    rid = run_id or ai_runs.new_id()

    async def go():
        return [ev async for ev in investigator.investigate(STORE, objective, rid, client=fake, **kw)]

    return asyncio.run(go()), fake


def call(name: str, args: dict, ctx=None):
    return REGISTRY[name].fn(args, ctx or RunContext(run_id="t", model="test"))


# ================================================== 1. aggregation over enumeration
def test_one_aggregate_call_answers_which_logs_contain_the_ip(client):
    out = call("aggregate_events", {"query": SHARED_IP, "groupBy": "file"})
    files = {g["value"]: g["count"] for g in out["groups"]}

    # every source that contains it is named, with an EXACT count — not a sample
    assert len(files) >= 3
    assert sum(files.values()) == out["total"] > 0
    assert any("edge-lb-01" in f for f in files) and any("fw-edge-2" in f for f in files)
    assert any("cloudtrail" in f.lower() for f in files)
    # ...and a source that does NOT contain it is absent, which is the answer to "ruled out?"
    assert not any("k8s_audit" in f for f in files)
    assert out["truncated"] is False and out["distinctGroups"] == len(files)

    # the same number the row-based path would have had to count by hand
    assert call("count_events", {"query": SHARED_IP})["total"] == out["total"]
    # and it is genuinely exhaustive: the per-file counts equal a per-file count_events
    for name, n in files.items():
        assert call("count_events", {"query": SHARED_IP, "sources": name})["total"] == n

    # the search tool, asked the same thing, is explicitly NOT to be counted from
    rows = call("search_events", {"query": SHARED_IP, "limit": 5})
    assert rows["returned"] == 5 and rows["total"] == out["total"]
    assert "aggregate_events" in rows["note"]


def test_aggregate_reports_its_cost_and_groups_by_any_field(client):
    out = call("aggregate_events", {"query": "", "groupBy": "sev", "top": 10})
    assert out["engine"] in ("cpu", "vector", "cuda") and isinstance(out["tookMs"], float)
    assert {g["value"] for g in out["groups"]} <= {"critical", "high", "medium", "low", "info"}
    assert sum(g["count"] for g in out["groups"]) == out["total"]
    # a parsed field, not a fixed column
    fields = call("list_event_fields", {"query": "", "limit": 8})["fields"]
    name = next(f["name"] for f in fields if f["name"] not in ("source", "file", "sev", "host", "user"))
    per = call("aggregate_events", {"query": "", "groupBy": name})
    assert per["total"] == out["total"] and per["withoutField"] >= 0


def test_count_distinct_histogram_and_sample(client):
    assert call("count_events", {"query": "definitely-not-in-these-logs-xyz"})["total"] == 0

    d = call("distinct_values", {"query": "", "field": "source"})
    assert d["distinct"] >= 2 and all(v["count"] > 0 for v in d["values"])

    h = call("events_over_time", {"query": "", "bucket": "hour"})
    assert h["buckets"] and h["peak"]["count"] >= 1
    assert sum(b["count"] for b in h["buckets"]) <= h["total"]
    assert h["first"] <= h["last"]

    s = call("sample_events", {"query": "", "n": 4})
    assert len(s["rows"]) == 4 and all(STORE.event(r["id"]) is not None for r in s["rows"])
    assert "not a count" in s["note"]


@pytest.mark.parametrize("bad,needle", [
    ('user:root AND "unterminated', "unbalanced double quote"),
    ("(host:a AND user:b", "unclosed"),
    ("host:a AND", "no right-hand term"),
    ("user:", "no value"),
])
def test_a_malformed_query_is_a_helpful_refusal_never_an_empty_result(client, bad, needle):
    """Zero matches from a broken query is indistinguishable from real absence — so it must not happen."""
    for tool in ("search_events", "count_events"):
        with pytest.raises(ToolError) as exc:
            call(tool, {"query": bad, "groupBy": "source"})
        assert needle in str(exc.value)
        assert "\\:" in str(exc.value)          # the correction shows the escaping rule


def test_escaped_colon_still_searches_the_literal_text(client):
    """The DSL escape CLAUDE.md warns about must survive the new validation layer."""
    assert call("count_events", {"query": r"10.0.0.9\:3001"})["total"] >= 0
    assert call("count_events", {"query": "sev:high"})["total"] == call(
        "aggregate_events", {"query": "sev:high", "groupBy": "source"})["total"]


def test_a_repeated_read_is_served_from_the_run_cache(client):
    evs, fake = run_agent("look twice", [
        {"calls": [("count_events", {"query": SHARED_IP})]},
        {"calls": [("count_events", {"query": SHARED_IP})]},
        {"calls": [("count_events", {"query": SHARED_IP, "scope": "case"})]},
        {"text": "done"},
    ])
    results = of(evs, "tool_result")
    assert results[0]["data"].get("cached") is None
    assert results[1]["data"]["cached"] is True           # identical call — the previous answer, verbatim
    assert results[1]["data"]["total"] == results[0]["data"]["total"]
    assert results[2]["data"].get("cached") is None       # different arguments — really re-run
    assert evs[-1]["cachedToolCalls"] == 1


def test_a_write_invalidates_the_cache(client):
    ctx = RunContext(run_id="cache", model="test")
    ctx.cache["x"] = {"stale": True}
    ctx.record("update_case", "changed something", {"kind": "case_meta", "before": {}})
    assert ctx.cache == {}


def test_unknown_parameters_are_a_clear_schema_error(client):
    """`create_case(severity=…, status=…)` — the parameters the real model invented."""
    evs, _ = run_agent("build a case", [
        {"calls": [("create_case", {"name": "supply-chain compromise", "summary": "x",
                                    "severity": "high", "status": "open"})]},
        {"text": "I used the wrong parameters."},
    ])
    res = of(evs, "tool_result")[0]
    assert res["ok"] is False
    msg = json.dumps(res["data"])
    assert "severity" in msg and "status" in msg and "has no parameter" in msg
    assert "name" in msg and "summary" in msg          # it is told what the tool DOES take
    assert not of(evs, "write")                        # and nothing was created


# ================================================== 2. compaction
def _fat_script(n: int):
    """n turns that each pull a big tool result, then a final report citing a real event id.

    The LAST turn is the model declining the documentation check (see investigator.DOCUMENT_CHECK): a
    run with this many tool calls and no writes is asked once, before it may finish, whether it should
    record what it found. It has to keep citing the same id, because the answer this test cares about
    is the one the run ends with.
    """
    eid = STORE.events[0].id
    turns = [{"text": f"Step {i}: gathering.", "calls": [("search_events", {"query": "", "limit": 20,
                                                                            "offset": i * 20})]}
             for i in range(n)]
    turns.append({"text": f"Final report: the decisive record is `{eid}`."})
    turns.append({"text": f"Nothing here warrants a case artefact. The decisive record is `{eid}`."})
    return turns, eid


def test_a_run_that_would_blow_the_context_compacts_and_finishes(client, monkeypatch):
    # The ceiling has to leave room for the system prompt (~2.7 k tokens) PLUS a brief and a tail, or
    # compaction correctly refuses on its own floor and the run stops on the budget — which would be
    # testing the floor, not compaction. 9 000 is the smallest round number that still forces several
    # compactions with the current prompt.
    monkeypatch.setenv("IRIS_AI_MAX_CONTEXT_TOKENS", "9000")
    monkeypatch.setenv("IRIS_AI_MAX_COMPACTIONS", "6")
    script, eid = _fat_script(9)
    evs, fake = run_agent("investigate everything", script, max_steps=20)

    done = evs[-1]
    assert done["reason"] == "complete" and done["state"] == "done"   # NOT 'budget'
    assert done["compactions"] >= 1
    assert eid in done["answer"] and not done["unverifiedCitations"]  # the citation survived compaction

    notes = [s for s in of(evs, "status") if "compacted" in s["text"]]
    assert notes and "running brief" in notes[0]["text"]
    assert notes[0]["droppedMessages"] >= compaction.MIN_COMPACTIBLE

    # the compaction is in the PERSISTED transcript too — an analyst reading the run back must know
    rec = client.get(f"/api/ai/runs/{evs[0]['runId']}").json()
    assert any("compacted" in e["text"] for e in rec["transcript"])

    # the model really was handed a shorter transcript, and it still starts with system + the objective
    last = fake.seen[-1]["messages"]
    assert last[0]["role"] == "system" and "investigate everything" in last[1]["content"]
    assert any("RUNNING BRIEF" in (m.get("content") or "") for m in last)
    assert len(last) < 2 + 2 * len(script)


def test_compaction_keeps_the_transcript_valid_for_the_provider(client):
    """Every role:'tool' message must still answer an assistant message that called it."""
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "objective"}]
    for i in range(6):
        messages.append({"role": "assistant", "content": f"turn {i}",
                         "tool_calls": [{"id": f"c{i}", "type": "function",
                                         "function": {"name": "search_events", "arguments": "{}"}}]})
        messages.append({"role": "tool", "tool_call_id": f"c{i}", "name": "search_events",
                         "content": json.dumps({"total": 3, "rows": [{"id": "e1"}]})})
    out, dropped = compaction.compact(messages, [])
    assert dropped > 0 and out[0]["role"] == "system" and out[1]["content"] == "objective"
    assert out[2]["role"] == "user" and "RUNNING BRIEF" in out[2]["content"]
    assert out[3]["role"] != "tool"                     # no orphaned tool result at the cut
    open_calls: set[str] = set()
    for m in out[3:]:
        if m["role"] == "assistant":
            open_calls = {c["id"] for c in m.get("tool_calls") or []}
        elif m["role"] == "tool":
            assert m["tool_call_id"] in open_calls, "a tool result lost the call it answers"


def test_the_brief_preserves_citations_and_what_was_already_written(client):
    eid = STORE.events[0].id
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "trace the intrusion"}]
    for i in range(6):
        messages.append({"role": "assistant", "content": "", "tool_calls": [
            {"id": f"c{i}", "type": "function", "function": {"name": "search_events", "arguments": "{}"}}]})
        messages.append({"role": "tool", "tool_call_id": f"c{i}", "name": "search_events",
                         "content": json.dumps({"total": 9, "rows": [{"id": eid}]})})
    actions = [{"tool": "add_ioc", "summary": "recorded indicator ipv4:45.83.140.22"}]
    out, _ = compaction.compact(messages, actions)
    brief = out[2]["content"]
    assert eid in brief                      # the citation is still available to cite
    assert "trace the intrusion" in brief    # the objective is never summarised away
    assert "add_ioc" in brief                # and it knows what it already wrote
    assert len(brief) <= compaction.MAX_BRIEF_CHARS


def test_compaction_is_capped_and_cannot_loop_forever(client, monkeypatch):
    monkeypatch.setenv("IRIS_AI_MAX_CONTEXT_TOKENS", "900")
    monkeypatch.setenv("IRIS_AI_MAX_COMPACTIONS", "2")
    evs, _ = run_agent("never stop", default={"text": "still going, more data please",
                                              "calls": [("search_events", {"query": "", "limit": 20})]},
                       max_steps=40)
    done = evs[-1]
    assert done["reason"] == "budget"                     # the ceiling is still a real stop
    assert done["compactions"] <= 2
    assert done["steps"] < 40                             # it did not burn the whole step budget looping
    assert of(evs, "answer")                              # and the analyst still gets a report


def test_compaction_refuses_when_there_is_nothing_to_fold():
    assert compaction.compact([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}], []) is None
    short = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"},
             {"role": "assistant", "content": "a"}, {"role": "user", "content": "b"}]
    assert compaction.compact(short, []) is None


def test_the_default_step_budget_is_no_longer_the_binding_limit():
    lim = investigator.limits()
    assert lim["maxSteps"] >= 40 and lim["maxSteps"] <= investigator.MAX_STEPS_CAP
    assert lim["maxSeconds"] >= 240 and lim["maxSeconds"] <= investigator.MAX_SECONDS_CAP
    assert 1 <= lim["maxCompactions"] <= investigator.MAX_COMPACTIONS_CAP


def test_stop_still_works_while_compaction_is_in_play(client, monkeypatch):
    monkeypatch.setenv("IRIS_AI_MAX_CONTEXT_TOKENS", "6000")
    rid = ai_runs.new_id()
    fake = FakeModel(default={"calls": [("search_events", {"query": "", "limit": 20})]})

    async def go():
        out = []
        async for ev in investigator.investigate(STORE, "keep going", rid, client=fake, max_steps=40):
            out.append(ev)
            if ev["type"] == "tool_result" and len(of(out, "tool_result")) == 2:
                ai_runs.request_stop(rid)
        return out

    evs = asyncio.run(go())
    assert evs[-1]["state"] == "stopped" and len(of(evs, "tool_call")) == 2


# ================================================== 3. text-mode tool calls
ANALYST_LEAK = (
    "budget reached (max_steps) — writing the final report\n"
    "<tool_call><function=create_case><parameter=name>pi-coding-agent supply-chain compromise</parameter>"
    "<parameter=summary>Malicious postinstall script</parameter><parameter=severity>high</parameter>"
    "<parameter=status>open</parameter></function></tool_call>")


def test_the_text_form_tool_call_is_parsed_not_printed():
    cleaned, calls = ai_client.parse_text_tool_calls(ANALYST_LEAK)
    assert "<tool_call>" not in cleaned and "<function=" not in cleaned
    assert len(calls) == 1 and calls[0]["function"]["name"] == "create_case"
    args = json.loads(calls[0]["function"]["arguments"])
    assert args["name"].startswith("pi-coding-agent") and args["severity"] == "high"
    assert ai_client.has_tool_call_syntax(ANALYST_LEAK) is True
    assert ai_client.has_tool_call_syntax("a normal report about `e12`") is False


def test_streamed_deltas_never_show_raw_tool_call_markup():
    """The parser cleaned the FINAL message, but the analyst watched `<tool_call><function=` type
    itself out delta by delta first. `_hold_split` holds a delta back until it cannot be the start
    of a marker; everything from a real marker on is buffered to the end of the turn."""
    shown, held = [], ""
    # deltas chopped mid-marker on purpose - that is how it actually arrives
    for delta in ["Report: ", "the host is ", "compromis", "ed.\n<tool", "_call><func",
                  "tion=create_case><parameter=name>x</parameter>", "</function></tool_call>"]:
        safe, held = ai_client._hold_split(held + delta)
        if safe:
            shown.append(safe)
    stream = "".join(shown)
    assert "<tool" not in stream and "<func" not in stream
    assert stream == "Report: the host is compromised.\n"
    # what was held is markup only - nothing of it reaches the analyst
    tail, calls = ai_client.parse_text_tool_calls(held)
    assert tail == "" and calls[0]["function"]["name"] == "create_case"


def test_hold_split_does_not_swallow_ordinary_prose():
    # a lone '<' or a fenced code block that is not a tool call must stream through untouched
    text = "a < b and ```python" + chr(10) + "print(1)" + chr(10) + "``` done"
    safe, held = ai_client._hold_split(text)
    assert safe == text and held == ""
    # a trailing ``` COULD still become ```tool_call, so it is held until the next delta settles it
    safe, held = ai_client._hold_split("closing fence ```")
    assert safe == "closing fence " and held == "```"
    safe, held = ai_client._hold_split(held + chr(10) + "rest")
    assert safe == "```" + chr(10) + "rest" and held == ""
    # a trailing partial marker is held, then released once it turns out to be plain text
    safe, held = ai_client._hold_split("see <fun")
    assert safe == "see " and held == "<fun"
    safe2, held2 = ai_client._hold_split(held + "ky output")
    assert safe2 == "<funky output" and held2 == ""


def test_the_json_text_form_is_parsed_too():
    _, calls = ai_client.parse_text_tool_calls(
        '<tool_call>{"name": "count_events", "arguments": {"query": "x"}}</tool_call>')
    assert calls[0]["function"]["name"] == "count_events"
    assert json.loads(calls[0]["function"]["arguments"]) == {"query": "x"}


def test_a_text_mode_model_still_drives_the_app(client):
    """No native tool_calls at all — the loop must still execute the call and warn that it did."""
    pending, name = STORE.pending, STORE.name
    STORE.pending = True
    try:
        evs, _ = run_agent("build me a case", [
            {"text": ANALYST_LEAK},
            {"text": "Case created."},
        ])
    finally:
        STORE.pending, STORE.name = pending, name
    calls = of(evs, "tool_call")
    assert [c["name"] for c in calls] == ["create_case"]
    warn = [w["message"] for w in of(evs, "warning")]
    assert any("not returning native tool calls" in w for w in warn)
    # the invented parameters are refused with a schema error rather than silently dropped
    res = of(evs, "tool_result")[0]
    assert res["ok"] is False and "severity" in json.dumps(res["data"])
    # and nothing resembling tool-call markup reaches the transcript prose
    assert "<tool_call>" not in "".join(d["text"] for d in of(evs, "delta") if d["step"] > 1)


def test_raw_tool_call_syntax_never_reaches_the_final_report(client):
    """The budget wrap-up turn asks with tool_choice:'none', which is what invited the leak."""
    evs, _ = run_agent("investigate", default={"text": "Interim.", "calls": [("get_case_state", {})]},
                       max_steps=2)
    # the wrap-up model reply is the default turn, so script the leak as the LAST thing it says
    evs, _ = run_agent("investigate", script=[
        {"text": "working", "calls": [("get_case_state", {})]},
        {"text": "working", "calls": [("get_case_state", {})]},
    ], default={"text": ANALYST_LEAK}, max_steps=2)
    done = evs[-1]
    assert done["reason"] == "max_steps"
    assert "<tool_call>" not in done["answer"] and "<function=" not in done["answer"]
    assert any("tried to call create_case after its budget ran out" in w["message"]
               for w in of(evs, "warning"))
    rec = client.get(f"/api/ai/runs/{done['runId']}").json()
    assert "<tool_call>" not in rec["answer"]


def test_a_provider_that_rejects_tools_fails_loudly():
    assert ai_client._rejects_tools(400, '{"error":{"message":"Unrecognized request argument: tools"}}')
    assert ai_client._rejects_tools(400, "this model does not support function calling")
    assert not ai_client._rejects_tools(400, "context length exceeded")
    assert not ai_client._rejects_tools(401, "invalid api key")


# ================================================== 4. case create / modify
def test_create_case_and_update_case_work_end_to_end(client):
    """The analyst asked for a case to be created and added to; the model wrote XML instead. Both halves
    of what it was reaching for really work — and the pool survives the switch, so the rest of the module
    still has evidence to search."""
    from app import cases

    origin = STORE.case_id
    made = ""
    try:
        STORE.pending = True
        evs, _ = run_agent("open a case for this", [
            {"calls": [("create_case", {"name": "AI-made case", "summary": "first summary"})]},
            {"calls": [("update_case", {"name": "AI-made case (renamed)", "summary": "second summary"})]},
            {"text": "Case is set up."},
        ])
        assert [r["ok"] for r in of(evs, "tool_result")] == [True, True]
        made = STORE.case_id
        assert STORE.pending is False and made != origin
        assert STORE.name == "AI-made case (renamed)" and STORE.summary == "second summary"
        state = call("get_case_state", {})
        assert state["hasCase"] is True and state["name"] == "AI-made case (renamed)"
        assert [w["action"]["tool"] for w in of(evs, "write")] == ["create_case", "update_case"]

        # a second create_case is refused, with the alternative spelled out
        evs2, _ = run_agent("another", [{"calls": [("create_case", {"name": "second"})]}, {"text": "no"}])
        res = of(evs2, "tool_result")[0]
        assert res["ok"] is False and "update_case" in json.dumps(res["data"])
    finally:
        cases.activate(origin)
        if made and made != origin:
            cases.delete_case(made)
    assert STORE.case_id == origin and len(STORE.events) > 0


def test_events_can_be_added_to_the_case_the_agent_just_made(client):
    eid = STORE.events[2].id
    evs, _ = run_agent("curate", [
        {"calls": [("add_events_to_case", {"eventIds": [eid], "labels": ["initial access"]})]},
        {"text": "added"}])
    assert of(evs, "tool_result")[0]["ok"] is True and eid in STORE.case_set
    client.post(f"/api/ai/runs/{evs[0]['runId']}/undo")
    assert eid not in STORE.case_set


# ================================================== 5. detection rules
def _rule_ids() -> set[str]:
    return {r["id"] for r in RULES_STORE.all_rules()} if False else {r.id for r in RULES_STORE.all_rules()}


def test_the_agent_can_create_a_rule_through_the_validated_path(client):
    rev = RULES_STORE.rev
    evs, _ = run_agent("write a rule for this", [
        {"calls": [("create_detection_rule", {"name": "AI: sudo to root",
                                              "description": "a session escalating to root",
                                              "pattern": "sudo:.*COMMAND=", "field": "raw",
                                              "sev": "medium", "tags": ["ai"]})]},
        {"text": "Rule added."},
    ])
    res = of(evs, "tool_result")[0]
    assert res["ok"] is True
    rid = res["data"]["rule"]["id"]
    assert res["data"]["rule"]["createdBy"] == "ai"          # provenance, like IOC.addedBy
    assert isinstance(res["data"]["reapplyMs"], int) and res["data"]["poolEvents"] > 0  # cost reported
    assert RULES_STORE.rev > rev                             # the anomaly cache keys on this

    listed = {r["id"]: r for r in client.get("/api/rules").json()}
    assert rid in listed and listed[rid]["name"] == "AI: sudo to root"
    assert listed[rid]["hits"] == res["data"]["hits"]

    # and the run's change list can take it straight back off
    assert [w["action"]["tool"] for w in of(evs, "write")] == ["create_detection_rule"]
    assert client.post(f"/api/ai/runs/{evs[0]['runId']}/undo").json()["undone"] == 1
    assert rid not in {r["id"] for r in client.get("/api/rules").json()}


def test_an_unsafe_or_invalid_rule_is_refused_and_nothing_changes(client):
    before = len(client.get("/api/rules").json())
    evs, _ = run_agent("write a bad rule", [
        {"calls": [("create_detection_rule", {"name": "broken", "pattern": "([a-z]+)+$"})]},
        {"calls": [("create_detection_rule", {"name": "unclosed", "pattern": "(unclosed"})]},
        {"calls": [("create_detection_rule", {"name": "empty"})]},
        {"text": "I could not save those."},
    ])
    results = of(evs, "tool_result")
    assert [r["ok"] for r in results] == [False, False, False]
    assert "rejected" in json.dumps(results[0]["data"]) or "backtrack" in json.dumps(results[0]["data"])
    assert not of(evs, "write")
    assert len(client.get("/api/rules").json()) == before


def test_a_bad_builtin_parameter_is_refused_and_the_rule_keeps_working(client):
    builtin = next(r for r in client.get("/api/rules").json()
                   if r["builtin"] and any(p["kind"] in ("int", "seconds") for p in r["params"]))
    rid = builtin["id"]
    key = next(p["key"] for p in builtin["params"] if p["kind"] in ("int", "seconds"))
    hits_before = builtin["hits"]

    evs, _ = run_agent("retune it", [
        {"calls": [("set_builtin_rule_params", {"ruleId": rid, "params": {"notAParam": "5"}})]},
        {"calls": [("set_builtin_rule_params", {"ruleId": rid, "params": {key: "not a number"}})]},
        {"calls": [("create_detection_rule", {"name": "unsafe", "pattern": "(a+)+$"})]},
        {"text": "Left it alone."},
    ])
    results = of(evs, "tool_result")
    assert [r["ok"] for r in results] == [False, False, False]
    assert "no parameter" in json.dumps(results[0]["data"])
    assert "NOTHING changed" in json.dumps(results[1]["data"])
    after = next(r for r in client.get("/api/rules").json() if r["id"] == rid)
    assert after["enabled"] is True and after["hits"] == hits_before   # degraded to shipped behaviour
    assert [p["value"] for p in after["params"]] == [p["value"] for p in builtin["params"]]


def test_a_builtin_can_be_retuned_and_undone(client):
    builtin = next(r for r in client.get("/api/rules").json()
                   if r["builtin"] and any(p["kind"] in ("int", "seconds") for p in r["params"]))
    rid = builtin["id"]
    param = next(p for p in builtin["params"] if p["kind"] in ("int", "seconds"))
    new_value = str(int(param["value"]) + 3)

    evs, _ = run_agent("make it less noisy", [
        {"calls": [("set_builtin_rule_params", {"ruleId": rid, "params": {param["key"]: new_value}})]},
        {"text": "Retuned."},
    ])
    assert of(evs, "tool_result")[0]["ok"] is True
    after = next(r for r in client.get("/api/rules").json() if r["id"] == rid)
    assert next(p["value"] for p in after["params"] if p["key"] == param["key"]) == new_value

    client.post(f"/api/ai/runs/{evs[0]['runId']}/undo")
    restored = next(r for r in client.get("/api/rules").json() if r["id"] == rid)
    assert next(p["value"] for p in restored["params"] if p["key"] == param["key"]) == param["value"]


def test_a_noisy_rule_can_be_switched_off_but_a_builtin_can_never_be_deleted(client):
    builtin = next(r for r in client.get("/api/rules").json() if r["builtin"])
    rid = builtin["id"]
    evs, _ = run_agent("silence it", [
        {"calls": [("delete_detection_rule", {"ruleId": rid})]},
        {"calls": [("set_detection_rule_enabled", {"ruleId": rid, "enabled": False})]},
        {"text": "Disabled it instead."},
    ])
    results = of(evs, "tool_result")
    assert results[0]["ok"] is False and "must not be deleted" in json.dumps(results[0]["data"])
    assert results[1]["ok"] is True
    assert next(r for r in client.get("/api/rules").json() if r["id"] == rid)["enabled"] is False

    client.post(f"/api/ai/runs/{evs[0]['runId']}/undo")
    assert next(r for r in client.get("/api/rules").json() if r["id"] == rid)["enabled"] is True


def test_a_custom_rule_can_be_updated_and_deleted_by_the_agent(client):
    evs, _ = run_agent("rule lifecycle", [
        {"calls": [("create_detection_rule", {"name": "AI: temp", "pattern": "zzz-nothing-matches"})]},
        {"text": "made it"}])
    rid = of(evs, "tool_result")[0]["data"]["rule"]["id"]

    evs2, _ = run_agent("tune it", [
        {"calls": [("update_detection_rule", {"ruleId": rid, "sev": "high", "description": "tuned"})]},
        {"text": "tuned"}])
    assert of(evs2, "tool_result")[0]["ok"] is True
    row = next(r for r in client.get("/api/rules").json() if r["id"] == rid)
    assert row["sev"] == "high" and row["description"] == "tuned" and row["pattern"] == "zzz-nothing-matches"

    evs3, _ = run_agent("drop it", [{"calls": [("delete_detection_rule", {"ruleId": rid})]}, {"text": "gone"}])
    assert of(evs3, "tool_result")[0]["ok"] is True
    assert rid not in {r["id"] for r in client.get("/api/rules").json()}
    # undo re-creates it through the same validated path (a new id: ids are never reused)
    assert client.post(f"/api/ai/runs/{evs3[0]['runId']}/undo").json()["undone"] == 1
    assert any(r["name"] == "AI: temp" for r in client.get("/api/rules").json())
    for r in client.get("/api/rules").json():
        if r["name"] == "AI: temp":
            client.delete(f"/api/rules/{r['id']}")


def test_the_agent_cannot_wipe_the_catalogue(client):
    """No clear/restore-defaults tool, by name or by any handler reachable from the registry."""
    names = set(REGISTRY)
    assert not any(n for n in names if "clear" in n or "restore" in n)
    n_builtin = len([r for r in client.get("/api/rules").json() if r["builtin"]])
    assert n_builtin > 20
