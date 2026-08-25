"""Conversations: continuing a run, stopping early, and writing findings into the case.

Three analyst reports, one test file, because they are the same complaint from three sides:

  1. *"when asked for it to continue, it didn't even have context into all the work it had already done
     and redid the entire analysis."* — every prompt was a cold start. A follow-up is now a new run in
     the same THREAD, seeded with a deterministic brief of the earlier turns (`ai/continuation.py`).
  2. *"it went through a lot of tool calls … it likely went deeper than it should have. For, up to 40
     steps, 600s, 46 tools the assistant should not feel that is has to go through these limits."* —
     the budgets are a runaway-loop ceiling, not a plan, and the loop now says so mid-run (CHECK_IN).
     Its FOLLOW-UP report matters as much: firing that nudge on the call count alone "influences the
     model to stop investigating too early when it probably should continue … a lot of log files that
     might need to be sifted through". So it fires on a BARREN STREAK — consecutive calls that each
     returned nothing new — and never on productive work, however much of it there is.
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
def _barren(i: int) -> tuple[str, dict]:
    """One call that returns NOTHING NEW: a query no line can match, so `hits` comes back 0."""
    return ("count_events", {"query": f"zzz-no-such-value-{i}"})


def _productive(i: int) -> tuple[str, dict]:
    """One call that genuinely returns something. The args VARY: an identical repeat is served from the
    run's own dedupe cache, and a repeat is exactly what "nothing new" means."""
    return ("count_events", {"query": f"NOT zzz-no-such-value-{i}"})


def test_a_run_that_stops_finding_things_is_asked_for_another_angle(client):
    """The check-in. It fires as a user turn between steps and never forces the model's hand."""
    n = investigator.CHECK_IN_MIN_CALLS + investigator.CHECK_IN_STREAK
    script = [{"calls": [_barren(i)]} for i in range(n)]
    script.append({"text": "Enough — answering now."})
    evs, fake, _rid = drive("dig", script)

    notes = [s for s in of(evs, "status") if s.get("checkIn")]
    assert len(notes) == 1, f"exactly one check-in, got {notes}"
    assert "nothing new" in notes[0]["text"]
    sent = [m for m in fake.seen[-1]["messages"] if m["role"] == "user"]
    assert any("CHECK-IN" in str(m["content"]) for m in sent)
    # and the copy must not read as an instruction to wrap up
    nudge = next(str(m["content"]) for m in sent if "CHECK-IN" in str(m["content"]))
    assert "DIFFERENT angle" in nudge and "continuing is the right answer" in nudge


def test_a_run_that_keeps_finding_things_is_never_interrupted(client):
    """The analyst's report: the count-based nudge stopped runs that should have kept sifting.

    Far more calls than the old `CHECK_IN_EVERY` would have allowed, all of them productive: no nudge.
    """
    n = investigator.CHECK_IN_MIN_CALLS * 3
    script = [{"calls": [_productive(i)]} for i in range(n)]
    script.append({"text": "done"})
    evs, _f, _rid = drive("sift every source", script)
    assert not [s for s in of(evs, "status") if s.get("checkIn")], "productive work was interrupted"


def test_a_barren_streak_early_in_a_run_is_not_enough(client):
    """A slow start is not a runaway loop — the floor is there so the opening is never nudged."""
    script = [{"calls": [_barren(i)]} for i in range(investigator.CHECK_IN_STREAK + 1)]
    script.append({"text": "done"})
    evs, _f, _rid = drive("dig", script)
    assert not [s for s in of(evs, "status") if s.get("checkIn")]


def test_one_productive_call_resets_the_streak(client):
    """Nothing-new has to be CONSECUTIVE: a find in the middle means the line of enquiry is alive."""
    script: list = [{"calls": [_productive(i)]} for i in range(investigator.CHECK_IN_MIN_CALLS)]
    for i in range(investigator.CHECK_IN_STREAK * 4):
        script.append({"calls": [_barren(100 + i) if i % 2 else _productive(200 + i)]})
    script.append({"text": "done"})
    evs, _f, _rid = drive("dig", script)
    assert not [s for s in of(evs, "status") if s.get("checkIn")]


def test_a_short_run_is_never_nudged(client):
    evs, _f, _rid = drive("quick question", [
        {"calls": [("count_events", {"query": "x"})]},
        {"text": "Two events."},
        {"text": "Nothing to record."},
    ])
    assert not [s for s in of(evs, "status") if s.get("checkIn")]


def test_the_nudges_are_bounded(client):
    """A model that ignores the check-in must not be nagged on every step for the rest of the run."""
    n = (investigator.CHECK_IN_MIN_CALLS
         + investigator.CHECK_IN_STREAK * (investigator.MAX_CHECK_INS + 3)
         + investigator.CHECK_IN_COOLDOWN * (investigator.MAX_CHECK_INS + 3))
    script = [{"calls": [_barren(i)]} for i in range(n)]
    script.append({"text": "done"})
    evs, _f, _rid = drive("dig forever", script, max_steps=n + 2)
    assert len([s for s in of(evs, "status") if s.get("checkIn")]) == investigator.MAX_CHECK_INS


def test_the_budget_notice_is_about_the_report_not_about_stopping(client):
    """Sent once, near the ceiling, and it must not tell the model to stop investigating."""
    script = [{"calls": [_productive(i)]} for i in range(8)]
    script.append({"text": "done"})
    evs, fake, _rid = drive("dig", script, max_steps=6)
    notes = [s for s in of(evs, "status") if s.get("budgetNotice")]
    assert len(notes) == 1, f"exactly one budget notice, got {notes}"
    sent = [str(m["content"]) for m in fake.seen[-1]["messages"] if m["role"] == "user"]
    nudge = next(m for m in sent if "BUDGET —" in m)
    assert "Keep investigating if the evidence warrants it" in nudge


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


def test_with_no_case_the_write_up_says_to_create_one(client, monkeypatch):
    """The analyst's rule: "no case — the workspace is case-less — it should then create the case."
    The nudge used to be skipped while pending; now it fires and tells the model to create_case first."""
    monkeypatch.setattr(STORE, "pending", True, raising=False)
    evs, fake, _rid = drive("investigate", [
        {"calls": [("count_events", {"query": "a"})]},
        {"calls": [("count_events", {"query": "b"})]},
        {"calls": [("count_events", {"query": "c"})]},
        {"text": "Findings."},
    ])
    checks = [s for s in of(evs, "status") if s.get("documentCheck")]
    assert len(checks) == 1 and "create the case" in checks[0]["text"]
    nudge = next(str(m["content"]) for m in fake.seen[-1]["messages"]
                 if m["role"] == "user" and "BEFORE YOU FINISH" in str(m["content"]))
    assert "create_case" in nudge and "NO CASE" in nudge


def test_the_opening_line_does_not_read_as_a_plan(client):
    """"up to 40 steps, 600s, 46 tools" was taken as what the agent intended to spend."""
    evs, _f, first = drive("quick", [{"text": "answer"}])
    opening = of(evs, "status")[0]["text"]
    assert "stops as soon as it can answer" in opening and "ceiling" in opening
    evs2, _f2, _second = drive("more", [{"text": "answer"}], continue_from=first)
    assert "continuing the conversation" in of(evs2, "status")[0]["text"]
