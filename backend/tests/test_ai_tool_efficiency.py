"""Can the agent reach an answer in a few calls — or does the tool surface invite paging?

The analyst pasted this out of a live run:

    eventId: l764130da6      step 19    get_event    0 rule(s) fired - 2 ms
    eventId: l1d7c9ac0e40    step 20

Two separate faults in three lines. The agent was fetching events ONE AT A TIME, spending a whole step
of a forty-step budget on each 2 ms call, and at step 20 it had produced no answer; and every one of
those calls summarised itself as "0 rule(s) fired", which is not what was asked and not what the
analyst was watching for.

The root cause was not that get_event was slow. It was that `search_events` — the tool that FOUND the
events — returned no raw log line, no parsed fields and no entities, so an agent told to "open the
actual events before citing them" had no other move. That is the same lesson CLAUDE.md already records
for counting ("aggregation, not enumeration"), unlearned for reads.

And the analyst's follow-up widened it: "I feel like it's doing a lot without giving answers quickly.
For example: tell me everything this IP is involved with." That question has a short, knowable answer —
Iris already computes every part of it — but no single tool returned it, so the model stitched six or
seven calls together and often ran out of budget mid-staple.

So this file pins the shape of the answer, not the speed of any one call:
  * a result set can be READ in one call (get_events / search_events include=)
  * an entity question is answerable in ONE call (entity_profile)
  * a timeline can be WRITTEN in one call (annotate_case_events)
  * every tool result says something about what was asked
  * a multi-event result fits in one tool result instead of being truncated from the end
  * a run that spends its budget still hands the analyst the report it earned
"""
from __future__ import annotations

import asyncio
import json

import orjson
import pytest
from fastapi.testclient import TestClient

from app.ai import investigator, runs as ai_runs
from app.ai.investigator import TOOL_RESULT_CHARS, _summarize
from app.ai.tools import MAX_FETCH, REGISTRY, RunContext, ToolError
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def ctx() -> RunContext:
    return RunContext(run_id="eff", model="test")


def busiest_entity() -> str:
    gb = STORE.graph_v2("all")
    return max(gb.nodes.values(), key=lambda a: a.count).value


# ============================================================ reading a result set costs ONE call
def test_get_events_reads_a_whole_result_set_in_one_call(client):
    """The direct answer to the pasted transcript: N events, one tool call."""
    ids = [e.id for e in STORE.events[:12]]
    out = REGISTRY["get_events"].fn({"eventIds": ids, "include": "raw,fields"}, ctx())
    assert out["requested"] == 12 and out["returned"] == 12
    assert [r["id"] for r in out["rows"]] == ids          # caller's order is preserved
    assert all("raw" in r for r in out["rows"])
    assert "missing" not in out


def test_get_events_names_ids_that_do_not_exist(client):
    """A silently dropped id is how a fabricated citation survives — they come back named."""
    real = STORE.events[0].id
    out = REGISTRY["get_events"].fn({"eventIds": [real, "e-not-a-real-id"]}, ctx())
    assert out["returned"] == 1
    assert out["missing"] == ["e-not-a-real-id"]
    assert "Do not cite" in out["note"]


def test_get_events_refuses_an_oversized_batch_and_says_what_to_do(client):
    """Truncating silently would be the same silent-omission bug in a new place."""
    ids = [e.id for e in STORE.events[: MAX_FETCH + 5]]
    with pytest.raises(ToolError) as exc:
        REGISTRY["get_events"].fn({"eventIds": ids}, ctx())
    msg = str(exc.value)
    assert str(MAX_FETCH) in msg and "aggregate_events" in msg


def test_search_events_can_return_the_lines_it_found(client):
    """The gap that CAUSED the loop: search returned no raw line, so the model had to go back for it."""
    plain = REGISTRY["search_events"].fn({"query": "", "limit": 5}, ctx())
    assert all("raw" not in r for r in plain["rows"])
    # and it says so, rather than leaving the model to discover the gap by calling get_event
    assert "include='raw,fields'" in plain["hint"]

    full = REGISTRY["search_events"].fn({"query": "", "limit": 5, "include": "raw,fields"}, ctx())
    assert all("raw" in r and "fields" in r for r in full["rows"])
    assert "hint" not in full


def test_include_refuses_an_unknown_part_with_the_real_list(client):
    with pytest.raises(ToolError) as exc:
        REGISTRY["search_events"].fn({"query": "", "include": "raw,everything"}, ctx())
    assert "everything" in str(exc.value) and "entities" in str(exc.value)


def test_a_multi_event_read_fits_inside_one_tool_result(client):
    """investigator._clip cuts from the END: an unclamped batch loses its LAST events entirely."""
    ids = [e.id for e in STORE.events[:MAX_FETCH]]
    out = REGISTRY["get_events"].fn({"eventIds": ids, "include": "raw,fields,entities"}, ctx())
    assert out["returned"] == len(ids)
    body = orjson.dumps(out)
    assert len(body) <= TOOL_RESULT_CHARS, (
        f"a full {len(ids)}-event read is {len(body)} bytes and would be truncated at "
        f"{TOOL_RESULT_CHARS} — the last events would silently vanish")


# ============================================================ one entity question, ONE call
def test_entity_profile_answers_the_whole_question_in_one_call(client):
    """'tell me everything this IP is involved with' — count, window, breakdown, relations, lines."""
    value = busiest_entity()
    out = REGISTRY["entity_profile"].fn({"value": value}, ctx())
    assert out["total"] > 0
    # the exact-match query, not free text — free text would also match 10.0.0.100 for 10.0.0.1
    assert out["query"] == f'entity:"{value}"'
    assert out["activity"]["first"] and out["activity"]["last"]
    assert "source" in out["breakdown"] and out["breakdown"]["source"]["top"]
    assert out["sampleEvents"] and all(r["id"] and "raw" in r for r in out["sampleEvents"])
    # and it agrees exactly with asking the same question the long way round
    counted = REGISTRY["count_events"].fn({"query": out["query"]}, ctx())
    assert counted["total"] == out["total"]
    agg = REGISTRY["aggregate_events"].fn({"query": out["query"], "groupBy": "source"}, ctx())
    assert agg["distinctGroups"] == out["breakdown"]["source"]["distinct"]


def test_entity_profile_accepts_a_graph_node_id(client):
    """graph_find hands out 'ip:1.2.3.4'; passing that back must not search for the literal string."""
    gb = STORE.graph_v2("all")
    nid = max(gb.nodes.items(), key=lambda kv: kv[1].count)[0]
    out = REGISTRY["entity_profile"].fn({"value": nid}, ctx())
    assert out["value"] == nid.split(":", 1)[1]
    assert out["graph"].get("nodeId") == nid
    assert out["graph"]["relations"] is not None


def test_entity_profile_is_honest_about_an_entity_that_is_not_there(client):
    """Absence of evidence is a finding — it must not read as a broken call."""
    out = REGISTRY["entity_profile"].fn({"value": "203.0.113.254"}, ctx())
    assert out["total"] == 0
    assert "no event" in out["note"]


def test_every_entity_profile_fits_in_one_tool_result(client):
    """The busiest entities are the ones worth profiling, and they were the ones being truncated."""
    gb = STORE.graph_v2("all")
    top = sorted(gb.nodes.items(), key=lambda kv: -kv[1].count)[:15]
    over = []
    for nid, _agg in top:
        out = REGISTRY["entity_profile"].fn({"value": nid}, ctx())
        size = len(orjson.dumps(out))
        if size > TOOL_RESULT_CHARS:
            over.append(f"{nid}={size}")
    assert not over, "profiles that would be truncated: " + ", ".join(over)


def test_a_trimmed_profile_says_so_and_keeps_the_counts(client):
    """Shedding illustration is fine; shedding it silently is not, and the ANSWER must survive."""
    gb = STORE.graph_v2("all")
    nid = max(gb.nodes.items(), key=lambda kv: kv[1].count)[0]
    out = REGISTRY["entity_profile"].fn({"value": nid}, ctx())
    if "trimmed" in out:
        assert "complete and exact" in out["trimmed"]
    assert out["total"] > 0 and out["breakdown"]["source"]["top"]


# ============================================================ writing a timeline costs ONE call
def test_annotate_case_events_writes_a_whole_timeline_in_one_call(client):
    c = ctx()
    ids = [e.id for e in STORE.events[:6]]
    REGISTRY["add_events_to_case"].fn({"eventIds": ids, "labels": ["ai"]}, c)
    entries = [{"eventId": i, "labels": [f"step-{n}"], "note": f"stage {n}"} for n, i in enumerate(ids)]
    out = REGISTRY["annotate_case_events"].fn({"entries": entries}, c)
    assert out["annotated"] == len(ids)
    for n, i in enumerate(ids):
        assert STORE.case_set[i].labels == [f"step-{n}"]
        assert STORE.case_set[i].note == f"stage {n}"
    # ONE undoable action for the whole batch, not six
    assert len([a for a in c.actions if a["tool"] == "annotate_case_events"]) == 1


def test_a_batch_annotation_is_undone_as_one_action(client):
    from app.ai.tools import undo_action
    c = ctx()
    ids = [e.id for e in STORE.events[:4]]
    REGISTRY["add_events_to_case"].fn({"eventIds": ids, "labels": ["ai"]}, c)
    REGISTRY["annotate_case_events"].fn(
        {"entries": [{"eventId": i, "labels": ["before"], "note": "b"} for i in ids]}, c)
    action = [a for a in c.actions if a["tool"] == "annotate_case_events"][-1]
    REGISTRY["annotate_case_events"].fn(
        {"entries": [{"eventId": i, "labels": ["after"], "note": "a"} for i in ids]}, c)
    after = [a for a in c.actions if a["tool"] == "annotate_case_events"][-1]
    assert undo_action(after) is True
    for i in ids:
        assert STORE.case_set[i].labels == ["before"]
    assert undo_action(action) is True


def test_a_bad_entry_does_not_lose_the_rest_of_the_timeline(client):
    c = ctx()
    ids = [e.id for e in STORE.events[:3]]
    REGISTRY["add_events_to_case"].fn({"eventIds": ids, "labels": ["ai"]}, c)
    out = REGISTRY["annotate_case_events"].fn({"entries": [
        {"eventId": ids[0], "labels": ["ok"]},
        {"eventId": "e-not-real", "labels": ["nope"]},
        {"eventId": ids[1], "labels": ["ok"]},
    ]}, c)
    assert out["annotated"] == 2
    assert [f["eventId"] for f in out["failed"]] == ["e-not-real"]
    assert STORE.case_set[ids[0]].labels == ["ok"]


def test_the_single_and_batch_annotate_agree(client):
    """Two ways to write the same thing must not drift — they share _annotate_one."""
    c = ctx()
    a, b = STORE.events[0].id, STORE.events[1].id
    REGISTRY["add_events_to_case"].fn({"eventIds": [a, b], "labels": ["ai"]}, c)
    REGISTRY["annotate_case_event"].fn({"eventId": a, "labels": ["x", "y"], "note": "n"}, c)
    REGISTRY["annotate_case_events"].fn({"entries": [{"eventId": b, "labels": ["x", "y"], "note": "n"}]}, c)
    assert STORE.case_set[a].labels == STORE.case_set[b].labels == ["x", "y"]
    assert STORE.case_set[a].note == STORE.case_set[b].note == "n"


# ============================================================ every result says what was asked
def test_no_read_tool_summarises_itself_as_ok(client):
    """'ok' is not a status line. The analyst is watching this trail to follow the investigation."""
    from tests.test_ai_tool_calls import _minimal_args
    c = ctx()
    vague = []
    for name, t in REGISTRY.items():
        if t.writes:
            continue
        try:
            result = t.fn(_minimal_args(name), c)
        except ToolError:
            continue
        line = _summarize(name, True, result)
        if line == "ok" or not line.strip():
            vague.append(name)
    assert not vague, "these tools do not say what they answered: " + ", ".join(vague)


def test_get_event_does_not_report_the_wrong_question(client):
    """The pasted bug: get_event summarised itself as '0 rule(s) fired'."""
    eid = STORE.events[0].id
    out = REGISTRY["get_event"].fn({"eventId": eid}, ctx())
    line = _summarize("get_event", True, out)
    assert eid in line
    assert "rule(s) fired" not in line


def test_sample_events_reports_the_size_of_its_sample(client):
    """It shares the 'rows' key with search_events and was reporting '0 of N' for every call."""
    out = REGISTRY["sample_events"].fn({"query": "", "n": 4}, ctx())
    line = _summarize("sample_events", True, out)
    assert line.startswith("4 sample row")


def test_a_repeat_call_is_labelled_as_one(client):
    out = REGISTRY["count_events"].fn({"query": ""}, ctx())
    assert "repeat" in _summarize("count_events", True, {**out, "cached": True})


# ============================================================ the loop
class Scripted:
    """A provider that replays a plan. Turns are [(tool, args), ...] or a final string."""

    model = "scripted"
    configured = True

    def __init__(self, plan, deltas=True):
        self.plan = list(plan)
        self.deltas = deltas

    async def stream_chat(self, messages, tools=None, max_tokens=1400, temperature=0.1, tool_choice="auto"):
        if tool_choice == "none" or not self.plan:
            text = "FINAL REPORT"
            if self.deltas:
                yield {"type": "text", "text": text}
            yield {"type": "message", "message": {"role": "assistant", "content": text}, "finish": "stop"}
            return
        turn = self.plan.pop(0)
        if isinstance(turn, str):
            yield {"type": "message", "message": {"role": "assistant", "content": turn}, "finish": "stop"}
            return
        yield {"type": "message",
               "message": {"role": "assistant", "content": "",
                           "tool_calls": [{"id": f"c{i}", "type": "function",
                                           "function": {"name": n, "arguments": json.dumps(a)}}
                                          for i, (n, a) in enumerate(turn)]},
               "finish": "tool_calls"}


def drive(objective, plan, deltas=True, **kw):
    async def go():
        return [e async for e in investigator.investigate(
            STORE, objective, ai_runs.new_id(), client=Scripted(plan, deltas), **kw)]
    return asyncio.run(go())


def test_an_entity_question_is_answered_in_two_steps(client):
    """The benchmark objective. Stitched out of the old surface it was 18 tool calls."""
    value = busiest_entity()
    evs = drive(f"tell me everything {value} is involved with",
                [[("entity_profile", {"value": value})], "Report."])
    done = [e for e in evs if e["type"] == "done"][0]
    assert done["steps"] == 2 and done["toolCalls"] == 1
    assert done["reason"] == "complete" and done["answer"]


def test_reading_twenty_events_no_longer_costs_twenty_steps(client):
    ids = [e.id for e in STORE.events[:20]]
    evs = drive("read these", [[("get_events", {"eventIds": ids, "include": "raw"})], "Report."])
    done = [e for e in evs if e["type"] == "done"][0]
    assert done["steps"] == 2
    result = [e for e in evs if e["type"] == "tool_result"][0]
    assert result["ok"] and result["summary"] == "read 20 of 20 event(s)"


def test_a_budget_stop_still_delivers_the_report(client):
    """A run that spends its whole budget owes the analyst the report the work earned.

    The wrap-up turn collected only streamed `text` deltas, so a provider that yields the assembled
    message and no deltas — perfectly legal — produced an EMPTY answer after a full-length run. That
    is precisely "it took a very long time and gave me no answer".
    """
    plan = [[("count_events", {"query": ""})] for _ in range(10)]
    evs = drive("loop", plan, deltas=False, max_steps=3)
    done = [e for e in evs if e["type"] == "done"][0]
    assert done["reason"] == "max_steps"
    assert done["answer"] == "FINAL REPORT", "the budget wrap-up produced no report"
    assert [e for e in evs if e["type"] == "answer"]


def test_a_budget_stop_delivers_the_report_when_the_provider_streams(client):
    plan = [[("count_events", {"query": ""})] for _ in range(10)]
    evs = drive("loop", plan, deltas=True, max_steps=3)
    done = [e for e in evs if e["type"] == "done"][0]
    assert done["reason"] == "max_steps" and done["answer"] == "FINAL REPORT"
