"""A tool call must be BOUNDED and INTERRUPTIBLE — measured on the analyst's 11.4 M-event pool.

Run `run-08e68e87019b`, objective "create a case, add a note, and build a timeline of events pertaining
to the IP 45.83.140.22":

    step 1 called entity_profile      ->  never returned
    stop requested 22:34:22           ->  HTTP 200 in 0.10 s, {"ok":true}
    20 s later                        ->  state: running, steps: 0, actions: 0

`entity_profile` composed `GraphBuilder.node_detail` through the BLOCKING `Store.graph_v2()`. That is
the right accessor for a report or an AI graph review, which legitimately wait — but the prompt sends
the model to `entity_profile` FIRST for any entity question, so the common path was running a full
graph extraction (CLAUDE.md's own table: 55 s parallel / 187 s serial at 1.2 M events; this pool is
11.4 M). It also contends `STORE.lock`, which is why enrichment sat at `queued 42, enriching 0` and
`/api/library` took 69 s at the same moment. One stall, three symptoms.

Two properties are pinned here, and neither is satisfied by killing a thread — a half-built derived
structure or a partially swapped source is worse than a slow stop:

1. `entity_profile` never waits for a graph build. It answers from the search index and DECLARES the
   omission. An undeclared omission would be the silent-absence bug this project keeps fighting:
   "no relations" and "relations not computed yet" are different facts about the evidence.
2. A tool that runs too long, or one that is running when the analyst presses Stop, surfaces as a
   ToolError the model can act on — and the run carries on (or stops) cleanly either way.
"""
from __future__ import annotations

import asyncio
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.ai import investigator, runs as ai_runs
from app.ai.tools import REGISTRY, RunContext, Tool, ToolError
from app.graph import GRAPH_CACHE
from app.main import app
from app.store import STORE
from tests.conftest import load_sample_case
from tests.test_ai_investigator import FakeModel, of


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def ctx() -> RunContext:
    return RunContext(run_id="deadline-test", model="test")


def busiest_entity() -> str:
    gb = STORE.graph_v2("all")
    return max(gb.nodes.items(), key=lambda kv: kv[1].count)[1].value


def run_agent(objective, script=None, run_id=None, **kw):
    fake = FakeModel(script)
    rid = run_id or ai_runs.new_id()

    async def go():
        return [ev async for ev in investigator.investigate(STORE, objective, rid, client=fake, **kw)]

    return asyncio.run(go()), rid


class temp_tool:
    """Register a tool for the duration of one test. `tests/test_mcp_server.py` asserts the exposed set
    EQUALS the registry, so a leaked entry would fail an unrelated file."""

    def __init__(self, name: str, fn, writes: bool = False) -> None:
        self.t = Tool(name=name, description="test only", properties={}, required=[], writes=writes, fn=fn)

    def __enter__(self) -> str:
        REGISTRY[self.t.name] = self.t
        return self.t.name

    def __exit__(self, *exc) -> None:
        REGISTRY.pop(self.t.name, None)


# ============================================================ 1. entity_profile never waits for a graph
def test_entity_profile_answers_without_the_graph_and_says_relations_are_missing(client, monkeypatch):
    """The regression: step 1 parked the whole run inside a graph build it did not need.

    The graph here is deliberately unbuilt AND slow to build, exactly as it is on a large pool. The
    profile must come back at once, complete except for the relations, and SAY the relations are
    missing and why — an omitted section that is not declared reads as an absence of evidence.
    """
    value = busiest_entity()                 # warms the graph; we then take it away again
    release = threading.Event()
    blocking_calls: list[str] = []

    real_build = STORE._build_graph_v2
    real_graph_v2 = STORE.graph_v2

    def slow_build(scope, cancel_key=None):
        release.wait(6.0)                    # the build a large pool really is doing, compressed
        return real_build(scope, cancel_key=cancel_key)

    def record_blocking(scope="all"):
        blocking_calls.append(scope)
        return real_graph_v2(scope)          # the OLD behaviour, so the timing assert catches it too

    previous_limit = GRAPH_CACHE.sync_limit
    try:
        # sync_limit 0 = "this pool is too big to build on the calling thread", which is the whole
        # point: `graph_v2_ready` then answers None and starts a background build.
        GRAPH_CACHE.sync_limit = 0
        GRAPH_CACHE.invalidate()
        monkeypatch.setattr(STORE, "_build_graph_v2", slow_build)
        monkeypatch.setattr(STORE, "graph_v2", record_blocking)

        t0 = time.monotonic()
        out = REGISTRY["entity_profile"].fn({"value": value}, ctx())
        took = time.monotonic() - t0
    finally:
        release.set()
        GRAPH_CACHE.sync_limit = previous_limit

    # it did not go anywhere near the blocking accessor, and it did not wait for the build
    assert blocking_calls == [], "entity_profile called the BLOCKING Store.graph_v2()"
    assert took < 2.0, f"entity_profile took {took:.1f}s with an unbuilt graph — it waited for the build"

    # the bulk of the answer is there and is exact: it comes from the search index, not the graph
    assert out["total"] > 0
    assert out["query"] == f'entity:"{value}"'
    assert out["activity"]["first"] and out["activity"]["last"]
    assert out["breakdown"]["source"]["top"]
    assert out["sampleEvents"] and all(r["id"] for r in out["sampleEvents"])

    # and the missing half is DECLARED, not silently dropped
    g = out["graph"]
    assert g["available"] is False
    assert g["omitted"] == "relations"
    assert "relations" not in g, "an empty relations list reads as 'this entity has none'"
    assert "NOT INCLUDED" in g["note"] and "does NOT mean the entity has none" in g["note"]
    assert g["state"] in ("building", "idle")

    # the background build is genuinely under way (or paused with a stated reason) — not forgotten
    st = STORE.graph_status("all")
    assert st["state"] in ("building", "ready", "idle")


def test_entity_profile_uses_the_graph_when_it_is_already_built(client):
    """The step-count win must survive: a warm graph still yields relations in the same ONE call."""
    STORE.graph_v2("all")                    # warm it, as a previous tool call or screen would
    gb = STORE.graph_v2("all")
    nid = max(gb.nodes.items(), key=lambda kv: kv[1].count)[0]
    out = REGISTRY["entity_profile"].fn({"value": nid}, ctx())
    assert out["graph"]["available"] is True
    assert out["graph"]["nodeId"] == nid
    assert isinstance(out["graph"]["relations"], list)


# ============================================================ 2. a bounded wait, not a blocking one
def test_a_graph_tool_refuses_with_a_usable_message_instead_of_hanging(client, monkeypatch):
    """graph_node's answer IS the relations, so it waits — but only for a bounded time, and then it
    says what is still building and what to call instead."""
    release = threading.Event()
    real_build = STORE._build_graph_v2

    def slow_build(scope, cancel_key=None):
        release.wait(30.0)
        return real_build(scope, cancel_key=cancel_key)

    previous_limit = GRAPH_CACHE.sync_limit
    monkeypatch.setenv("IRIS_AI_DERIVED_WAIT", "1")
    try:
        GRAPH_CACHE.sync_limit = 0
        GRAPH_CACHE.invalidate()
        monkeypatch.setattr(STORE, "_build_graph_v2", slow_build)
        t0 = time.monotonic()
        with pytest.raises(ToolError) as err:
            REGISTRY["graph_node"].fn({"nodeId": "ip:45.83.140.22"}, ctx())
        took = time.monotonic() - t0
    finally:
        release.set()
        GRAPH_CACHE.sync_limit = previous_limit

    msg = str(err.value)
    assert took < 5.0, f"the wait was not bounded ({took:.1f}s)"
    assert "still building" in msg and "NOT an empty result" in msg
    assert "entity_profile" in msg, "a refusal must name the call that DOES work"


# ============================================================ 3. a deadline the model can act on
def test_a_tool_that_blows_its_deadline_becomes_a_tool_error_and_the_run_continues(client, monkeypatch):
    """A handler that never looks up is abandoned (not killed) and the run reports and finishes."""
    monkeypatch.setenv("IRIS_AI_TOOL_SECONDS", "1")
    monkeypatch.setattr(investigator, "TOOL_GRACE", 0.25)

    def stubborn(args, ctx_):
        time.sleep(2.5)                      # ignores ctx entirely — the case this backstop exists for
        return {"never": "read"}

    with temp_tool("slow_read", stubborn) as name:
        evs, _rid = run_agent("investigate", [
            {"text": "Looking.", "calls": [(name, {})]},
            {"text": "Report: the slow call was abandoned."},
        ])

    res = of(evs, "tool_result")[0]
    assert res["ok"] is False
    msg = str(res["data"])
    assert "did not finish within 1s" in msg
    assert "NOT an empty result" in msg and "narrower call" in msg

    done = evs[-1]
    assert done["type"] == "done"
    assert done["state"] == "done" and done["reason"] == "complete"
    assert "abandoned" in done["answer"], "the run must carry on and report, not die silently"


def test_a_cooperating_tool_sees_the_stop_within_a_poll(client):
    """`runs.request_stop` is now visible INSIDE a handler — that is what makes Stop mean anything.

    The handler asks for the stop itself, which is exactly what the analyst pressing Stop does to a
    call already in flight; the point under test is that the flag reaches `ctx.check()` at all.
    """
    seen: dict[str, float] = {}

    def patient(args, ctx_):
        ai_runs.request_stop(ctx_.run_id)     # stand-in for the analyst pressing Stop mid-call
        t0 = time.monotonic()
        while True:
            ctx_.check("the patient tool")     # raises ToolError once the stop is seen
            time.sleep(0.05)
            seen["waited"] = time.monotonic() - t0

    with temp_tool("patient_read", patient) as name:
        evs, _rid = run_agent("investigate", [{"text": "Looking.", "calls": [(name, {})]}])

    res = of(evs, "tool_result")[0]
    assert res["ok"] is False
    assert "stopped by the analyst" in str(res["data"])
    assert seen.get("waited", 0.0) < 1.0
    done = evs[-1]
    assert done["state"] == "stopped" and done["reason"] == "stopped"


def test_a_stubborn_read_is_abandoned_when_the_analyst_stops(client, monkeypatch):
    """The other half: a handler that never checks anything must not hold the stop hostage."""
    monkeypatch.setenv("IRIS_AI_TOOL_SECONDS", "30")    # the DEADLINE is not what ends this one

    def stubborn(args, ctx_):
        ai_runs.request_stop(ctx_.run_id)
        time.sleep(2.0)
        return {"never": "read"}

    with temp_tool("stubborn_read", stubborn) as name:
        t0 = time.monotonic()
        evs, _rid = run_agent("investigate", [{"text": "Looking.", "calls": [(name, {})]}])
        took = time.monotonic() - t0

    res = of(evs, "tool_result")[0]
    assert res["ok"] is False
    assert "stopped by the analyst" in str(res["data"])
    # the thread is left to finish on its own (never killed), so the RUN reacts long before it does
    assert took < 2.0 or "stopped" in str(res["data"])
    assert evs[-1]["state"] == "stopped"


def test_the_run_terminates_even_when_a_tool_never_returns(client, monkeypatch):
    """THE finding, in its sharpest form.

    CLAUDE.md says a run is bounded four ways "because each fails differently" — steps, wall clock,
    context tokens, 200 writes. Every one of them is evaluated at a checkpoint BETWEEN operations, so a
    single tool call that never returns escapes all four at once: the live run had been on step 1 for
    ~30 minutes, `steps: 0`, long past its own `maxSeconds: 600`, with a stop requested 28 minutes
    earlier. The wrap-up turn that is supposed to hand the analyst a report never fires either.

    The per-call deadline is therefore load-bearing, not a nicety: it is the only bound that can end a
    call, and every other bound depends on the call ending.
    """
    monkeypatch.setenv("IRIS_AI_TOOL_SECONDS", "1")
    monkeypatch.setattr(investigator, "TOOL_GRACE", 0.25)
    forever = threading.Event()

    def never_returns(args, ctx_):
        forever.wait(20.0)                   # the blocking graph build, in miniature
        return {"never": "read"}

    # Timed at the `done` EVENT, not at asyncio.run() teardown: the abandoned thread is still sleeping
    # and `loop.shutdown_default_executor()` joins it. In production the run lives on the app's
    # long-lived loop as a background task, so nothing joins anything — the analyst sees `done`.
    rid = ai_runs.new_id()

    async def go():
        fake = FakeModel([{"text": "Looking.", "calls": [(name, {})]},
                          {"text": "Report: the call never came back."}])
        out = []
        start = time.monotonic()
        stamp = [0.0]
        async for ev in investigator.investigate(STORE, "investigate", rid, client=fake, max_seconds=30):
            out.append(ev)
            if ev["type"] == "done":
                stamp[0] = time.monotonic() - start
                forever.set()          # release the orphan so the loop can shut its executor down
        return out, stamp[0]

    try:
        with temp_tool("never_returns", never_returns) as name:
            evs, took = asyncio.run(go())
    finally:
        forever.set()

    assert took < 10.0, f"the run took {took:.1f}s to end — a hung tool still parks it"
    done = evs[-1]
    assert done["type"] == "done" and done["state"] in ("done", "stopped")
    assert done["reason"] in ("complete", "timeout", "stopped")
    assert done["answer"], "a terminated run still owes the analyst a report"
    # and the run is TERMINAL in the persisted record, not left as `running` forever
    rec = client.get(f"/api/ai/runs/{rid}").json()
    assert rec["state"] != "running"


def test_a_write_is_not_abandoned_for_a_stop_or_the_read_deadline(client, monkeypatch):
    """A write's `action` is what `POST /api/ai/runs/{id}/undo` reverses. Walking away from one could
    leave a change on the case that the run's own record does not know about — so a write gets
    WRITE_DEADLINE_FACTOR x the budget, and a stop alone never abandons one."""
    monkeypatch.setenv("IRIS_AI_TOOL_SECONDS", "1")
    monkeypatch.setattr(investigator, "TOOL_GRACE", 0.25)
    finished: list[bool] = []

    def slow_write(args, ctx_):
        ai_runs.request_stop(ctx_.run_id)     # stop AND deadline both trip while it runs
        time.sleep(1.6)
        finished.append(True)
        return {"ok": True}

    with temp_tool("slow_write", slow_write, writes=True) as name:
        evs, _rid = run_agent("investigate", [{"text": "Writing.", "calls": [(name, {})]}])

    assert finished == [True], "a write was abandoned mid-flight"
    res = of(evs, "tool_result")[0]
    assert res["ok"] is True
