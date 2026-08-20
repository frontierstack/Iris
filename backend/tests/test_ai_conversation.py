"""Conversations: continuing a run, stopping early, and writing findings into the case.

Three analyst reports, one test file, because they are the same complaint from three sides:

  1. *"when asked for it to continue, it didn't even have context into all the work it had already done
     and redid the entire analysis."* — every prompt was a cold start. A follow-up is now a new run in
     the same THREAD, seeded with a deterministic brief of the earlier turns (`ai/continuation.py`).
  2. *"it went through a lot of tool calls … it likely went deeper than it should have. For, up to 40
     steps, 600s, 46 tools the assistant should not feel that is has to go through these limits."* —
     the budgets are a runaway-loop ceiling, not a plan, and the loop now says so mid-run (CHECK_IN).
  3. *"didn't interact with the case at all when it should, that include everything in the case from
     the timeline to iocs."* — a run that investigated and recorded nothing is asked, once, to write it
     up (DOCUMENT_CHECK).

Nudges 2 and 3 are PROMPTS, not enforcement: the model may decline either. That is deliberate — forcing
a write would produce case artefacts for questions that did not warrant one, and inventing a finding to
have something to file is a worse failure than filing nothing.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app.ai import continuation, investigator, runs as ai_runs
from app.ai.history import HISTORY
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


class FakeModel:
    """Replays scripted turns, exactly like tests/test_ai_investigator.py's."""

    def __init__(self, script=None, default=None, model="fake-model"):
        self.script = list(script or [])
        self.default = default
        self.model = model
        self.configured = True
        self.seen: list[dict] = []

    async def stream_chat(self, messages, tools=None, max_tokens=1400, temperature=0.1, tool_choice="auto"):
        self.seen.append({"messages": [dict(m) for m in messages], "tool_choice": tool_choice})
        turn = self.script.pop(0) if self.script else (self.default or {"text": "Done."})
        text = turn.get("text", "")
        if text:
            yield {"type": "text", "text": text}
        msg = {"role": "assistant", "content": text}
        calls = turn.get("calls") or []
        if calls and tool_choice != "none":
            msg["tool_calls"] = [{"id": f"c{n}", "type": "function",
                                  "function": {"name": name, "arguments": json.dumps(args)}}
                                 for n, (name, args) in enumerate(calls)]
        yield {"type": "message", "message": msg, "finish": "stop"}


def drive(objective, script=None, default=None, run_id=None, **kw):
    """Run one turn to completion; returns (events, the fake model, run id)."""
    fake = FakeModel(script, default)
    rid = run_id or ai_runs.new_id()

    async def go():
        return [ev async for ev in investigator.investigate(STORE, objective, rid, client=fake, **kw)]

    return asyncio.run(go()), fake, rid


def of(events, kind):
    return [e for e in events if e["type"] == kind]


def first_user_message(fake: FakeModel) -> str:
    return str(fake.seen[0]["messages"][1]["content"])


def an_event_id() -> str:
    return STORE.events[0].id


# ------------------------------------------------------------------ threads
def test_a_follow_up_joins_the_same_conversation(client):
    _evs, _f, first = drive("who is 10.0.0.1?", [{"text": "It is a workstation."}])
    _evs2, _f2, second = drive("and what did it do?", [{"text": "It logged in."}], continue_from=first)

    a, b = ai_runs.get(first), ai_runs.get(second)
    assert b["parentId"] == first
    assert b["threadId"] == a["threadId"] == first, "a follow-up must join the first turn's thread"
    ids = [r["id"] for r in ai_runs.thread(second)]
    assert ids == [first, second], "the thread is every turn, oldest first"
    # ...and reading the thread from EITHER end gives the same conversation
    assert [r["id"] for r in ai_runs.thread(first)] == ids


def test_a_follow_up_starts_from_what_the_last_turn_established(client):
    eid = an_event_id()
    _evs, _f, first = drive("what happened?", [
        {"calls": [("get_event", {"eventId": eid})]},
        {"text": f"A failed login, see `{eid}`."},
        {"text": "Nothing to record."},
    ])
    _evs2, fake2, _second = drive("now build the timeline", [{"text": "Building."}], continue_from=first)

    prompt = first_user_message(fake2)
    assert "EARLIER IN THIS CONVERSATION" in prompt
    assert "what happened?" in prompt, "the earlier objective is what 'continue' refers to"
    assert "A failed login" in prompt, "the previous report is the established narrative"
    assert "get_event" in prompt, "the work already done must not be repeated"
    assert eid in prompt, "citations are load-bearing and must survive into the next turn"
    assert "now build the timeline" in prompt.split("EARLIER IN THIS CONVERSATION")[0], \
        "the NEW request has to come first, or the model answers the old one"


def test_a_first_turn_carries_no_brief(client):
    _evs, fake, _rid = drive("plain question", [{"text": "Answer."}])
    assert "EARLIER IN THIS CONVERSATION" not in first_user_message(fake)


def test_continuing_a_deleted_run_still_runs(client):
    """A pruned or deleted parent must degrade to a fresh conversation, never to a failure."""
    _evs, _f, first = drive("first", [{"text": "ok"}])
    assert ai_runs.delete(first)
    evs, fake, second = drive("continue please", [{"text": "starting over"}], continue_from=first)
    assert evs[-1]["type"] == "done"
    assert "EARLIER IN THIS CONVERSATION" not in first_user_message(fake)
    assert ai_runs.get(second)["threadId"] == second, "it becomes the root of its own thread"


def test_a_run_written_before_threads_existed_is_its_own_thread(client):
    """Records on disk from before this feature have neither field. They are one-turn conversations."""
    _evs, _f, rid = drive("legacy", [{"text": "ok"}])
    with HISTORY.lock:
        rec = HISTORY._runs[rid]
        rec.pop("threadId", None)
        rec.pop("parentId", None)
    assert [r["id"] for r in ai_runs.thread(rid)] == [rid]


def test_the_thread_endpoint_returns_the_whole_conversation(client):
    _evs, _f, first = drive("turn one", [{"text": "one"}])
    _evs2, _f2, second = drive("turn two", [{"text": "two"}], continue_from=first)

    body = client.get(f"/api/ai/runs/{second}/thread").json()
    assert body["threadId"] == first
    assert [r["id"] for r in body["runs"]] == [first, second]
    assert body["runs"][0]["answer"] == "one", "past turns come back in full, transcripts included"
    assert body["runs"][0]["transcript"], "a past turn without its transcript cannot be rendered"
    assert client.get("/api/ai/runs/run-nope/thread").status_code == 404


def test_the_brief_carries_the_writes_so_a_follow_up_does_not_duplicate_them(client):
    records = [{
        "id": "run-1", "prompt": "investigate", "answer": "Compromise confirmed in `e1`.",
        "state": "done", "transcript": [{"kind": "tool", "name": "add_ioc", "args": {"value": "1.2.3.4"},
                                         "summary": "indicator added"}],
        "actions": [{"id": "a1", "tool": "add_ioc", "summary": "IOC 1.2.3.4"},
                    {"id": "a2", "tool": "add_note", "summary": "narrative note", "undone": True}],
    }]
    brief = continuation.build(records)
    assert "ALREADY WRITTEN TO THE CASE" in brief
    assert "IOC 1.2.3.4" in brief
    assert "narrative note" not in brief, "an UNDONE write is not on the case any more"
    assert "e1" in brief


def test_the_brief_says_when_nothing_was_written(client):
    brief = continuation.build([{"id": "r", "prompt": "q", "answer": "a", "state": "done", "transcript": []}])
    assert "NOTHING has been written to the case" in brief


def test_the_brief_is_bounded(client):
    records = [{"id": f"r{i}", "prompt": f"question {i}", "answer": "x" * 5000, "state": "done",
                "transcript": [{"kind": "tool", "name": "search_events", "args": {"query": "y" * 500},
                                "summary": "z" * 500}] * 40}
               for i in range(30)]
    brief = continuation.build(records)
    assert len(brief) <= continuation.MAX_BRIEF_CHARS + 200
    assert "question 29" in brief, "the most recent turn must survive the clipping"


# ------------------------------------------------------------------ stopping early
def test_a_long_run_is_asked_whether_it_can_answer_yet(client):
    """The check-in. It fires as a user turn between steps and never forces the model's hand."""
    script = [{"calls": [("count_events", {"query": f"q{i}"})]} for i in range(investigator.CHECK_IN_EVERY)]
    script.append({"text": "Enough — answering now."})
    evs, fake, _rid = drive("dig", script)

    notes = [s for s in of(evs, "status") if s.get("checkIn")]
    assert len(notes) == 1, "exactly one check-in after the first interval"
    assert "tool calls so far" in notes[0]["text"]
    sent = [m for m in fake.seen[-1]["messages"] if m["role"] == "user"]
    assert any("CHECK-IN" in str(m["content"]) for m in sent)


def test_a_short_run_is_never_nudged(client):
    evs, _f, _rid = drive("quick question", [
        {"calls": [("count_events", {"query": "x"})]},
        {"text": "Two events."},
        {"text": "Nothing to record."},
    ])
    assert not [s for s in of(evs, "status") if s.get("checkIn")]


def test_the_nudges_are_bounded(client):
    """A model that ignores the check-in must not be nagged on every step for the rest of the run."""
    n = investigator.CHECK_IN_EVERY * (investigator.MAX_CHECK_INS + 3)
    script = [{"calls": [("count_events", {"query": f"q{i}"})]} for i in range(n)]
    script.append({"text": "done"})
    evs, _f, _rid = drive("dig forever", script)
    assert len([s for s in of(evs, "status") if s.get("checkIn")]) == investigator.MAX_CHECK_INS


# ------------------------------------------------------------------ writing it down
def test_an_investigation_that_recorded_nothing_is_asked_to_write_it_up(client):
    eid = an_event_id()
    evs, fake, _rid = drive("investigate this host", [
        {"calls": [("count_events", {"query": "a"})]},
        {"calls": [("count_events", {"query": "b"})]},
        {"calls": [("get_event", {"eventId": eid})]},
        {"text": "Here is what I found."},
        {"calls": [("add_note", {"text": f"Findings, see `{eid}`", "citedEventIds": [eid]})]},
        {"text": "Recorded in the case."},
    ])
    assert any(s.get("documentCheck") for s in of(evs, "status"))
    assert any("BEFORE YOU FINISH" in str(m["content"])
               for m in fake.seen[-1]["messages"] if m["role"] == "user")
    assert [w["action"]["tool"] for w in of(evs, "write")] == ["add_note"]
    assert evs[-1]["writes"] == 1


def test_the_write_up_may_be_declined(client):
    """A plain question does not need case artefacts, and inventing one to have something to file is
    worse than filing nothing. The prompt says so; nothing here forces a write."""
    evs, _f, _rid = drive("how many events mention this?", [
        {"calls": [("count_events", {"query": "a"})]},
        {"calls": [("count_events", {"query": "b"})]},
        {"calls": [("count_events", {"query": "c"})]},
        {"text": "412 events."},
        {"text": "Nothing here warrants recording — it was a count."},
    ])
    assert any(s.get("documentCheck") for s in of(evs, "status"))
    assert evs[-1]["writes"] == 0 and evs[-1]["reason"] == "complete"
    assert "warrants recording" in of(evs, "answer")[0]["text"]


def test_a_run_that_already_wrote_is_not_asked(client):
    eid = an_event_id()
    evs, _f, _rid = drive("investigate and record", [
        {"calls": [("count_events", {"query": "a"})]},
        {"calls": [("count_events", {"query": "b"})]},
        {"calls": [("add_note", {"text": f"note `{eid}`", "citedEventIds": [eid]})]},
        {"text": "Done and recorded."},
    ])
    assert not any(s.get("documentCheck") for s in of(evs, "status"))
    assert evs[-1]["writes"] == 1


def test_the_write_up_is_offered_only_once(client):
    """A model that answers the documentation prompt with more prose must still be able to finish."""
    script = [{"calls": [("count_events", {"query": f"q{i}"})]} for i in range(3)]
    script += [{"text": "answer"}, {"text": "still nothing recorded"}, {"text": "and again"}]
    evs, _f, _rid = drive("investigate", script)
    assert len([s for s in of(evs, "status") if s.get("documentCheck")]) == 1
    assert evs[-1]["type"] == "done" and evs[-1]["reason"] == "complete"


def test_nothing_is_asked_when_there_is_no_case_to_write_into(client, monkeypatch):
    """Every case-scoped write refuses while the store is pending, so asking would only waste a turn."""
    monkeypatch.setattr(STORE, "pending", True, raising=False)
    evs, _f, _rid = drive("investigate", [
        {"calls": [("count_events", {"query": "a"})]},
        {"calls": [("count_events", {"query": "b"})]},
        {"calls": [("count_events", {"query": "c"})]},
        {"text": "Findings."},
    ])
    assert not any(s.get("documentCheck") for s in of(evs, "status"))


def test_the_opening_line_does_not_read_as_a_plan(client):
    """"up to 40 steps, 600s, 46 tools" was taken as what the agent intended to spend."""
    evs, _f, first = drive("quick", [{"text": "answer"}])
    opening = of(evs, "status")[0]["text"]
    assert "stops as soon as it can answer" in opening and "ceiling" in opening
    evs2, _f2, _second = drive("more", [{"text": "answer"}], continue_from=first)
    assert "continuing the conversation" in of(evs2, "status")[0]["text"]
