"""A run survives its provider, records as it goes, and a failed run is continued — not restarted.

The analyst's report, verbatim: *"openai HTTP 400 at https://…/v1/chat/completions (the response body
is in the server log) — assistant stops working after that — found that this was due to context size
limits, but context shifting is enabled, so there needs to be some smart compacting so the assistant
can continue. This is also why a case needs to be started soon and documentation of the finding
documented sooner as well."* And earlier: *"continuing the assistant it restarted the entire
investigation all over instead of having context and understanding of all the work it already did."*

Four things, each pinned here:
  1. The provider's context window is the REAL ceiling. Its 400 is the compaction trigger: fold, lower
     the run's ceiling, re-send the same turn (client.ContextTooLong → investigator._fit_context).
  2. A transient provider failure (5xx / 429 / dropped connection) is retried with a backoff, not fatal.
  3. Findings are recorded AS THE RUN GOES (RECORD_NUDGE), and the full summary is asked for at the END
     (SUMMARY_CHECK) when the run wrote findings but no narrative.
  4. A run that ended in an error is continued from where it stopped: the brief carries its calls AND
     the prose it wrote, marked "ended early — continue, do not restart".
"""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app.ai import continuation, investigator, runs as ai_runs
from app.ai.client import AIError, ContextTooLong, ProviderUnavailable
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


class FakeModel:
    """Scripted turns. A turn may be an exception, raised BEFORE anything is yielded — the provider's
    way of refusing a request — or a dict {text, calls}."""

    def __init__(self, script=None, default=None, model="fake-model"):
        self.script = list(script or [])
        self.default = default
        self.model = model
        self.configured = True
        self.seen: list[dict] = []

    async def stream_chat(self, messages, tools=None, temperature=0.1, tool_choice="auto"):
        self.seen.append({"messages": [dict(m) for m in messages], "tool_choice": tool_choice})
        turn = self.script.pop(0) if self.script else (self.default or {"text": "Done."})
        if isinstance(turn, BaseException):
            raise turn
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
    fake = FakeModel(script, default)
    rid = run_id or ai_runs.new_id()

    async def go():
        return [ev async for ev in investigator.investigate(STORE, objective, rid, client=fake, **kw)]

    return asyncio.run(go()), fake, rid


def of(events, kind):
    return [e for e in events if e["type"] == kind]


def _read(i):
    return ("count_events", {"query": f"NOT zzz-no-such-value-{i}"})


def _big_read(i):
    """A read whose result is large enough that folding it actually shrinks the transcript."""
    return ("search_events", {"query": f"NOT zzz-no-such-value-{i}", "limit": 30, "include": "raw,fields"})


def an_event_id() -> str:
    return STORE.events[0].id


# ------------------------------------------------------------------ 1. the provider's window
def test_a_context_overflow_compacts_and_retries_the_same_turn(client):
    """Six reads build a transcript; the provider then refuses it. The run folds, retries, finishes."""
    script = [{"calls": [_big_read(i)]} for i in range(6)]
    script.append(ContextTooLong("the conversation no longer fits", status=400))
    script.append({"text": "Answer after the fold."})
    evs, fake, _rid = drive("investigate", script, default={"text": "Nothing to record."})

    warns = [w for w in of(evs, "warning") if w.get("contextCeiling")]
    assert len(warns) == 1, [w["message"] for w in of(evs, "warning")]
    assert "no longer fits" in warns[0]["message"] and "Retrying the same turn" in warns[0]["message"]
    assert evs[-1]["type"] == "done" and evs[-1]["reason"] == "complete"
    assert any("Answer after the fold" in d["text"] for d in of(evs, "delta"))
    # the retried request is SMALLER than the refused one, and the objective is still in it
    refused, retried = None, None
    for prev, cur in zip(fake.seen, fake.seen[1:]):
        if len(json.dumps(cur["messages"])) < len(json.dumps(prev["messages"])):
            refused, retried = prev["messages"], cur["messages"]
            break
    assert refused is not None, "no request was ever smaller than the one before it"
    assert len(json.dumps(retried)) < len(json.dumps(refused))
    assert retried[0]["role"] == "system" and "ANALYST OBJECTIVE" in str(retried[1]["content"])
    assert any("RUNNING BRIEF" in str(m.get("content")) for m in retried if m["role"] == "user")
    # the run's ceiling was lowered so the between-step compaction fires earlier from now on
    assert evs[-1]["contextCeiling"] < investigator.limits()["maxContextTokens"]
    assert evs[-1]["compactions"] >= 1


def test_a_transcript_with_nothing_to_fold_fails_with_the_real_fix_named(client):
    """System prompt + objective alone over the window: no fold can help. Say so; do not loop."""
    evs, fake, _rid = drive("investigate", [ContextTooLong("does not fit", status=400)])
    assert evs[-1]["type"] == "error"
    assert "larger context window" in evs[-1]["message"]
    assert len(fake.seen) == 1, "nothing to fold means one attempt, not four"


def test_the_context_recovery_is_bounded(client):
    script = [{"calls": [_big_read(i)]} for i in range(6)]
    script += [ContextTooLong("no", status=400)] * (investigator.CONTEXT_RETRIES + 1)
    evs, _fake, _rid = drive("investigate", script)
    assert evs[-1]["type"] == "error"
    assert "context window" in evs[-1]["message"]


# ------------------------------------------------------------------ 2. transient failures
def test_a_transient_provider_failure_is_retried_not_fatal(client, monkeypatch):
    monkeypatch.setattr(investigator, "PROVIDER_BACKOFF", (0.01,))
    script = [{"calls": [_read(1)]}, ProviderUnavailable("openai HTTP 503 at x", status=503),
              {"text": "Back, and done."}]
    evs, fake, _rid = drive("investigate", script)
    retries = [w for w in of(evs, "warning") if w.get("retry")]
    assert len(retries) == 1 and "retrying" in retries[0]["message"]
    assert evs[-1]["type"] == "done" and "Back, and done" in evs[-1]["answer"]


def test_provider_retries_are_bounded_and_the_error_says_what_is_kept(client, monkeypatch):
    monkeypatch.setattr(investigator, "PROVIDER_BACKOFF", (0.01,))
    script = [{"calls": [_read(1)]}] + [ProviderUnavailable("openai HTTP 502", status=502)] * (
        investigator.PROVIDER_RETRIES + 1)
    evs, _fake, rid = drive("investigate", script)
    assert evs[-1]["type"] == "error"
    assert "kept" in evs[-1]["message"] and "follow-up" in evs[-1]["message"]
    rec = ai_runs.get(rid)
    assert rec["state"] == "error" and rec["toolCalls"] == 1


def test_a_non_transient_4xx_is_not_retried(client, monkeypatch):
    monkeypatch.setattr(investigator, "PROVIDER_BACKOFF", (0.01,))
    evs, fake, _rid = drive("investigate", [AIError("openai HTTP 401 at x — the API key was rejected")])
    assert evs[-1]["type"] == "error" and len(fake.seen) == 1


# ------------------------------------------------------------------ 3. record as you go, summarise at the end
def test_findings_are_asked_to_be_recorded_before_the_run_finishes(client):
    n = investigator.RECORD_EVERY + 2
    script = [{"calls": [_read(i)]} for i in range(n)]
    script.append({"text": "done"})
    evs, fake, _rid = drive("sift every source", script)
    nudges = [s for s in of(evs, "status") if s.get("recordNudge")]
    assert len(nudges) == 1, nudges
    assert "none of it is recorded" in nudges[0]["text"]
    sent = [str(m["content"]) for m in fake.seen[-1]["messages"] if m["role"] == "user"]
    nudge = next(s for s in sent if "RECORD AS YOU GO" in s)
    assert "NOT a request to finish" in nudge


def test_a_write_resets_the_record_nudge(client):
    eid = an_event_id()
    script = [{"calls": [_read(i)]} for i in range(investigator.RECORD_EVERY - 1)]
    script.append({"calls": [("add_events_to_case", {"eventIds": [eid]})]})
    script += [{"calls": [_read(100 + i)]} for i in range(investigator.RECORD_EVERY - 1)]
    script.append({"text": "done"})
    evs, _fake, _rid = drive("investigate", script)
    assert not [s for s in of(evs, "status") if s.get("recordNudge")]


def test_the_record_nudges_are_bounded(client):
    script = [{"calls": [_read(i)]} for i in range(investigator.RECORD_EVERY * (investigator.MAX_RECORD_NUDGES + 2))]
    script.append({"text": "done"})
    evs, _fake, _rid = drive("investigate", script)
    assert len([s for s in of(evs, "status") if s.get("recordNudge")]) == investigator.MAX_RECORD_NUDGES


def test_a_run_that_recorded_findings_is_asked_for_the_summary(client):
    eid = an_event_id()
    evs, fake, _rid = drive("investigate", [
        {"calls": [_read(1)]}, {"calls": [_read(2)]},
        {"calls": [("add_events_to_case", {"eventIds": [eid]})]},
        {"text": "Recorded the events; done."},
        {"calls": [("add_note", {"text": f"Summary, see `{eid}`", "citedEventIds": [eid]})]},
        {"text": "Summary written."},
    ])
    assert any(s.get("summaryCheck") for s in of(evs, "status"))
    assert not any(s.get("documentCheck") for s in of(evs, "status"))
    assert any("no SUMMARY yet" in str(m["content"]) for m in fake.seen[-1]["messages"] if m["role"] == "user")
    assert [w["action"]["tool"] for w in of(evs, "write")] == ["add_events_to_case", "add_note"]


def test_a_run_that_wrote_the_note_itself_is_not_asked_again(client):
    eid = an_event_id()
    evs, _fake, _rid = drive("investigate", [
        {"calls": [_read(1)]}, {"calls": [_read(2)]},
        {"calls": [("add_events_to_case", {"eventIds": [eid]})]},
        {"calls": [("add_note", {"text": f"Summary `{eid}`", "citedEventIds": [eid]})]},
        {"text": "done"},
    ])
    assert not any(s.get("summaryCheck") for s in of(evs, "status"))


# ------------------------------------------------------------------ 4. continuing a failed run
def test_a_follow_up_continues_a_failed_run_from_where_it_stopped(client, monkeypatch):
    monkeypatch.setattr(investigator, "PROVIDER_BACKOFF", (0.01,))
    eid = an_event_id()
    script = [
        {"text": "Looking at the SSH failures first.", "calls": [_read(1)]},
        {"text": f"Established: the burst comes from one address, e.g. `{eid}`.", "calls": [_read(2)]},
    ] + [ProviderUnavailable("openai HTTP 500", status=500)] * (investigator.PROVIDER_RETRIES + 1)
    evs, _fake, first = drive("trace the ssh brute force", script)
    assert evs[-1]["type"] == "error"

    evs2, fake2, second = drive("continue", [{"text": "Carrying on."}], continue_from=first)
    assert evs2[-1]["type"] == "done"
    brief = str(fake2.seen[0]["messages"][1]["content"])
    assert "ENDED EARLY" in brief and "do not restart" in brief
    assert "count_events" in brief                       # the calls it made are listed
    assert "one address" in brief                        # its working notes travel too
    assert eid in brief                                  # and the ids it saw are verified citations
    assert ai_runs.get(second)["threadId"] == ai_runs.get(first)["threadId"]


def test_the_unfinished_turn_keeps_more_of_its_calls_than_an_old_one():
    calls = [{"kind": "tool", "name": f"tool_{i}", "args": {"q": str(i)}, "summary": "ok", "ok": True}
             for i in range(40)]
    rec = {"id": "r1", "prompt": "dig", "state": "error", "reason": "error", "error": "HTTP 500",
           "transcript": calls + [{"kind": "text", "text": "so far: nothing conclusive"}], "answer": "", "actions": []}
    brief = continuation.build([rec])
    assert brief.count("tool_") == 40
    assert "nothing conclusive" in brief
