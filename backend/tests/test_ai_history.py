"""Persisted AI conversation history.

The analyst's report was that refreshing the page or switching tabs lost the chat. So this pins the
whole contract of `app/ai/history.py`:

  • a finished conversation is readable from a SEPARATE request (the refresh case);
  • a run still in flight is visible to a second reader and its transcript GROWS;
  • the history survives a simulated restart (a fresh HistoryStore reading the same file — a stronger
    proof than a second TestClient, because it shares no memory with the one that wrote it);
  • a run the restart killed reconciles to a terminal, clearly-labelled state;
  • retention prunes oldest-first and one enormous run cannot blow the file up;
  • deleting one conversation leaves the others;
  • `clear all data` removes every transcript from disk AND memory;
  • nothing secret is ever written.

No network and no API key: the model is the same scripted FakeModel the investigator tests use.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app import config
from app.ai import history as ai_history, runs as ai_runs
from app.ai.history import HISTORY, HistoryStore
from app.ai.client import LLMClient
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case
from tests.test_ai_investigator import FakeModel, of


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


@pytest.fixture(autouse=True)
def _clean_history():
    HISTORY.clear_all()
    yield
    HISTORY.clear_all()


def _fresh_reader() -> HistoryStore:
    """What a second process (or the same one after a restart) sees on disk."""
    s = HistoryStore()
    s.load()
    return s


def _drive(objective: str, script=None, default=None, run_id=None, **kw) -> list[dict]:
    fake = FakeModel(script, default)
    rid = run_id or ai_runs.new_id()

    async def go():
        from app.ai import investigator
        return [ev async for ev in investigator.investigate(STORE, objective, rid, client=fake, **kw)]

    return asyncio.run(go())


# --------------------------------------------------------------- the refresh case
def test_a_finished_run_is_readable_from_a_separate_request(client, monkeypatch):
    eid = STORE.events[0].id
    monkeypatch.setattr(LLMClient, "from_settings",
                        classmethod(lambda cls, s: FakeModel([{"text": "Looking.", "calls": [("list_sources", {})]},
                                                              {"text": f"Two sources, see `{eid}`."}])))
    r = client.post("/api/ai/investigate", json={"prompt": "what sources do we have?"})
    rid = r.headers["X-Iris-Run-Id"]

    # a completely separate request — this is exactly what a page refresh does
    run = client.get(f"/api/ai/runs/{rid}").json()
    assert run["state"] == "done" and run["prompt"] == "what sources do we have?"
    assert run["model"] == "fake-model" and run["startedAt"] and run["endedAt"]
    assert eid in run["answer"]
    kinds = [e["kind"] for e in run["transcript"]]
    assert "step" in kinds and "tool" in kinds and "text" in kinds
    tool = next(e for e in run["transcript"] if e["kind"] == "tool")
    assert tool["name"] == "list_sources" and tool["ok"] is True and tool["summary"]
    assert run["transcriptSeq"] == max(e["seq"] for e in run["transcript"])

    # and it is in the history list, newest first, WITHOUT the transcript payload
    rows = client.get("/api/ai/runs").json()["runs"]
    assert rows[0]["id"] == rid and rows[0]["transcript"] == []
    assert rows[0]["transcriptSeq"] > 0


def test_since_returns_only_the_tail(client):
    _drive("tail me", [{"calls": [("get_case_state", {})]}, {"text": "done"}],
           run_id="run-tailtest")
    full = client.get("/api/ai/runs/run-tailtest").json()
    seq = full["transcriptSeq"]
    assert seq >= 3
    tail = client.get(f"/api/ai/runs/run-tailtest?since={seq - 1}").json()
    assert [e["seq"] for e in tail["transcript"]] == [seq]
    assert client.get(f"/api/ai/runs/run-tailtest?since={seq}").json()["transcript"] == []


def test_a_tool_result_reaches_a_client_that_has_already_seen_the_call(client):
    """The card's spinner is what says "still running", so the PATCH has to be sent, not just stored.

    A tool entry is appended when the call starts and updated in place when the result lands, which
    keeps its `seq`. Filtering `?since=` on `seq` alone therefore withheld exactly the update the
    panel was waiting for, and every polling tab kept the call spinning for the rest of the run —
    reported as "the spinner on the tools continues to spin even when that tool is done being used".
    """
    from app.ai.history import HISTORY

    rid = "run-patchtail"
    HISTORY.start(rid, "watch me", "fake-model")
    HISTORY.append(rid, {"kind": "tool", "id": "c1", "name": "list_sources", "args": {}, "writes": False})
    call_seq = client.get(f"/api/ai/runs/{rid}").json()["transcriptSeq"]
    # the client has now seen everything up to and including the call
    assert client.get(f"/api/ai/runs/{rid}?since={call_seq}").json()["transcript"] == []

    HISTORY.tool_result(rid, "c1", True, "3 sources", 12)
    tail = client.get(f"/api/ai/runs/{rid}?since={call_seq}").json()["transcript"]
    assert [e["seq"] for e in tail] == [call_seq], tail
    assert tail[0]["ok"] is True and tail[0]["summary"] == "3 sources" and tail[0]["tookMs"] == 12
    # the entry keeps its PLACE in the conversation - only what is SENT changes
    full = client.get(f"/api/ai/runs/{rid}").json()
    assert [e["seq"] for e in full["transcript"]] == [call_seq]
    assert full["transcriptSeq"] > call_seq
    HISTORY.delete(rid)


# --------------------------------------------------------------- mid-run visibility
def test_an_in_flight_run_is_visible_to_a_second_reader_and_grows(client):
    """A second tab (here: a HistoryStore that shares no memory) must see the run WHILE it is running."""
    seen: list[tuple[str, int]] = []

    async def go():
        from app.ai import investigator
        fake = FakeModel([{"calls": [("get_case_state", {})]},
                          {"calls": [("list_sources", {})]},
                          {"text": "All done."}])
        async for ev in investigator.investigate(STORE, "watch me", "run-inflight", client=fake):
            if ev["type"] == "tool_result":
                rec = _fresh_reader().get("run-inflight")
                seen.append((rec["state"], len(rec["transcript"])))

    asyncio.run(go())
    assert len(seen) == 2
    assert [s for s, _ in seen] == ["running", "running"]      # not "done", and not missing
    assert seen[1][1] > seen[0][1], seen                       # the transcript really grew
    final = _fresh_reader().get("run-inflight")
    assert final["state"] == "done" and len(final["transcript"]) > seen[1][1]


def test_history_survives_a_restart(client):
    _drive("survive", [{"calls": [("get_case_state", {})]}, {"text": "Report body."}],
           run_id="run-restart")
    HISTORY.load()                       # what the lifespan does — memory is rebuilt from the file
    rec = HISTORY.get("run-restart")
    assert rec["state"] == "done" and rec["answer"] == "Report body."
    assert any(e["kind"] == "tool" for e in rec["transcript"])
    assert client.get("/api/ai/runs/run-restart").json()["answer"] == "Report body."


def test_a_run_interrupted_by_a_restart_reconciles_to_a_terminal_state(client):
    HISTORY.start("run-killed", "interrupted objective", "fake-model")
    HISTORY.append("run-killed", {"kind": "step", "step": 1})
    assert _fresh_reader().get("run-killed")["state"] == "running"

    buried = HISTORY.reconcile()          # standing in for the process dying and coming back
    assert buried == 1
    rec = HISTORY.get("run-killed")
    assert rec["state"] == "error" and rec["interrupted"] is True
    assert rec["reason"] == "interrupted" and rec["endedAt"]
    assert "restarted" in rec["error"]
    assert HISTORY.reconcile() == 0       # idempotent — a buried run is not buried twice
    # and it is no longer stoppable, because there is nothing left to stop
    assert HISTORY.request_stop("run-killed") is False


# --------------------------------------------------------------- stopping
def test_a_stopped_run_is_recorded_with_a_stopped_status(client):
    async def go():
        from app.ai import investigator
        fake = FakeModel(default={"calls": [("get_case_state", {})]})
        out = []
        async for ev in investigator.investigate(STORE, "keep going", "run-stopme", client=fake, max_steps=20):
            out.append(ev)
            if ev["type"] == "tool_result" and len(of(out, "tool_result")) == 1:
                assert ai_runs.request_stop("run-stopme") is True
        return out

    evs = asyncio.run(go())
    assert evs[-1]["state"] == "stopped"
    rec = _fresh_reader().get("run-stopme")
    assert rec["state"] == "stopped" and rec["reason"] == "stopped" and rec["endedAt"]
    assert client.get("/api/ai/runs/run-stopme").json()["state"] == "stopped"


def test_a_prose_only_run_can_still_be_stopped(client):
    """The bug the analyst hit: a plain question never calls a tool, so a stop that was only checked
    between steps and between tool calls could not interrupt it at all."""
    class Slow(FakeModel):
        async def stream_chat(self, messages, tools=None, max_tokens=1400, temperature=0.1, tool_choice="auto"):
            ai_runs.request_stop("run-prose")          # the analyst hits Stop while prose is streaming
            for chunk in ("First. ", "Second. ", "Third. "):
                yield {"type": "text", "text": chunk}
            yield {"type": "message", "message": {"role": "assistant", "content": "First. Second. Third."},
                   "finish": "stop"}

    async def go():
        from app.ai import investigator
        return [ev async for ev in investigator.investigate(STORE, "just answer", "run-prose",
                                                            client=Slow(), max_steps=20)]

    evs = asyncio.run(go())
    assert evs[-1]["reason"] == "stopped" and evs[-1]["state"] == "stopped"
    assert len(of(evs, "delta")) == 0                  # halted before the first token was forwarded
    assert _fresh_reader().get("run-prose")["state"] == "stopped"


# --------------------------------------------------------------- retention
def test_retention_prunes_oldest_first(monkeypatch):
    monkeypatch.setattr(ai_history, "MAX_RUNS", 5)
    for i in range(9):
        rid = f"run-{i:02d}"
        HISTORY.start(rid, f"objective {i}", "fake-model")
        HISTORY.finish(rid, "done", "complete", 1, 0, f"answer {i}", [], [])
    ids = [r["id"] for r in HISTORY.listing(50)]
    assert len(ids) == 5
    assert ids == ["run-08", "run-07", "run-06", "run-05", "run-04"]   # newest first, oldest dropped
    assert [r["id"] for r in _fresh_reader().listing(50)] == ids       # the file agrees


def test_a_running_conversation_is_never_pruned(monkeypatch):
    monkeypatch.setattr(ai_history, "MAX_RUNS", 3)
    HISTORY.start("run-live", "still going", "fake-model")
    for i in range(6):
        rid = f"run-f{i}"
        HISTORY.start(rid, "x", "fake-model")
        HISTORY.finish(rid, "done", "complete", 1, 0, "y", [], [])
    assert HISTORY.get("run-live") is not None
    assert HISTORY.get("run-live")["state"] == "running"


def test_one_enormous_run_cannot_blow_the_file_up(monkeypatch):
    monkeypatch.setattr(ai_history, "MAX_FILE_BYTES", 200_000)
    HISTORY.start("run-huge", "x" * 50_000, "fake-model")
    for i in range(ai_history.MAX_ENTRIES + 200):
        HISTORY.append("run-huge", {"kind": "status", "text": "y" * 20_000})
    rec = HISTORY.get("run-huge")
    assert len(rec["transcript"]) <= ai_history.MAX_ENTRIES
    assert rec["transcriptTruncated"] is True
    assert len(rec["prompt"]) <= ai_history.MAX_PROMPT + 1
    assert all(len(e["text"]) <= ai_history.MAX_TEXT + 1 for e in rec["transcript"])
    size = config.DATA_DIR.joinpath("ai", "history.json").stat().st_size
    assert size <= ai_history.MAX_FILE_BYTES, size


# --------------------------------------------------------------- deletes
def test_deleting_one_conversation_leaves_the_others(client):
    for rid in ("run-a", "run-b", "run-c"):
        HISTORY.start(rid, rid, "fake-model")
        HISTORY.finish(rid, "done", "complete", 1, 0, "ok", [], [])
    assert client.delete("/api/ai/runs/run-b").json()["ok"] is True
    ids = {r["id"] for r in client.get("/api/ai/runs").json()["runs"]}
    assert ids == {"run-a", "run-c"}
    assert client.get("/api/ai/runs/run-b").status_code == 404
    assert client.delete("/api/ai/runs/run-b").status_code == 404
    assert {r["id"] for r in _fresh_reader().listing(50)} == {"run-a", "run-c"}

    assert client.delete("/api/ai/runs").json()["removed"] == 2
    assert client.get("/api/ai/runs").json()["runs"] == []
    assert _fresh_reader().listing(50) == []


# --------------------------------------------------------------- scoping + secrets
def test_a_run_records_the_case_it_targeted_but_history_is_global(client):
    """Scoping decision: global storage, case ASSOCIATION. A run may target no case at all."""
    _drive("with a case", [{"text": "ok"}], run_id="run-cased")
    rec = HISTORY.get("run-cased")
    assert rec["caseId"] == STORE.case_id and rec["caseName"] == STORE.name

    pending = STORE.pending
    STORE.pending = True
    try:
        _drive("case-less", [{"text": "ok"}], run_id="run-caseless")
    finally:
        STORE.pending = pending
    assert HISTORY.get("run-caseless")["caseId"] == ""

    # the default listing is workspace-wide; ?caseId= filters without hiding the storage layout
    ids = {r["id"] for r in client.get("/api/ai/runs").json()["runs"]}
    assert {"run-cased", "run-caseless"} <= ids
    only_caseless = {r["id"] for r in client.get("/api/ai/runs?caseId=").json()["runs"]}
    assert only_caseless == {"run-caseless"}


def test_no_secret_is_ever_written_to_the_transcript(client):
    from app.config import get_settings, update_settings
    before = get_settings().ai.apiKey
    update_settings({"ai": {"apiKey": "sk-super-secret-value-0123456789"}})
    try:
        _drive("say something", [{"calls": [("get_case_state", {})]}, {"text": "Fine."}], run_id="run-secret")
        blob = config.DATA_DIR.joinpath("ai", "history.json").read_text(encoding="utf-8")
        assert "sk-super-secret" not in blob
        assert "apiKey" not in blob
        rec = json.loads(blob)["runs"][0]
        assert set(rec) >= {"id", "prompt", "model", "transcript", "actions", "state"}
        assert "apiKey" not in json.dumps(rec)
    finally:
        update_settings({"ai": {"apiKey": before}})


def test_writes_and_undo_state_survive_a_refresh(client):
    eid = STORE.events[2].id
    _drive("curate", [
        {"calls": [("add_events_to_case", {"eventIds": [eid], "labels": ["persisted"]})]},
        {"text": "Added."}], run_id="run-writes")
    run = client.get("/api/ai/runs/run-writes").json()
    assert len(run["actions"]) == 1 and run["actions"][0]["tool"] == "add_events_to_case"
    assert run["actions"][0]["undone"] is False

    assert client.post("/api/ai/runs/run-writes/undo").json()["undone"] == 1
    # the undone flag has to survive the refresh too, or the panel offers to revert it again
    assert client.get("/api/ai/runs/run-writes").json()["actions"][0]["undone"] is True
    assert _fresh_reader().get("run-writes")["actions"][0]["undone"] is True
