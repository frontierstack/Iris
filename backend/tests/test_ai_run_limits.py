"""The investigator's run budget is a SETTING, and it can be switched off.

The step and wall-clock ceilings were env-only constants, so changing them took a restart and a
shell. In practice that meant a case which genuinely needed forty more steps just hit
"budget reached (max_steps)" and the analyst had no way to say "this one is worth it". They are
`settings.ai` now, and `enforceLimits: False` removes the step, time and write ceilings entirely.

What that switch deliberately does NOT touch, because none of it is a policy choice: the per-CALL
deadline (one tool may never eat the whole run), the context ceiling and compaction (the provider's
window is a fact, not a preference), and Stop.
"""
from __future__ import annotations

import asyncio

import pytest

from app import config
from app.ai import investigator, runs as ai_runs
from app.ai.investigator import NO_LIMIT, limits
from app.ai.prompts import run_budget
from app.store import STORE


class LoopingModel:
    """Always asks for another tool call, so the run only ends when a budget stops it."""

    def __init__(self) -> None:
        self.model = "fake"
        self.configured = True
        self.turns = 0
        self.system: list[str] = []

    async def stream_chat(self, messages, tools=None, max_tokens=1400, temperature=0.1, tool_choice="auto"):
        self.system.append(messages[0]["content"])
        self.turns += 1
        msg = {"role": "assistant", "content": ""}
        if tool_choice != "none":
            msg["tool_calls"] = [{"id": f"c{self.turns}", "type": "function",
                                  "function": {"name": "no_such_tool", "arguments": "{}"}}]
        else:                                     # the wrap-up turn
            msg["content"] = "done"
            yield {"type": "text", "text": "done"}
        yield {"type": "message", "message": msg,
               "finish": "tool_calls" if msg.get("tool_calls") else "stop"}


def _run(fake, **kw):
    rid = ai_runs.new_id()

    async def go():
        return [ev async for ev in investigator.investigate(STORE, "look at everything", rid, client=fake, **kw)]

    return asyncio.run(go())


@pytest.fixture(autouse=True)
def _restore():
    before = config.get_settings().ai.model_dump()
    yield
    config.update_settings({"ai": {k: before[k] for k in
                                  ("enforceLimits", "maxSteps", "maxSeconds", "maxWrites")}})


def test_the_budget_comes_from_settings() -> None:
    config.update_settings({"ai": {"enforceLimits": True, "maxSteps": 40, "maxSeconds": 600, "maxWrites": 200}})
    lim = limits()
    assert (lim["maxSteps"], lim["maxSeconds"], lim["maxWrites"], lim["enforced"]) == (40, 600, 200, 1)

    # and it is not capped at the old env ceiling of 120 — the whole point is that a deep case can ask
    # for more than the shipped default
    config.update_settings({"ai": {"maxSteps": 400, "maxSeconds": 7200, "maxWrites": 5000}})
    lim = limits()
    assert (lim["maxSteps"], lim["maxSeconds"], lim["maxWrites"]) == (400, 7200, 5000)


def test_switching_the_limits_off_removes_all_three() -> None:
    config.update_settings({"ai": {"enforceLimits": False}})
    lim = limits()
    assert lim["enforced"] == 0
    assert lim["maxSteps"] == lim["maxSeconds"] == lim["maxWrites"] == NO_LIMIT
    # ...but NOT the two bounds that are facts rather than preferences
    assert 0 < lim["maxToolSeconds"] < NO_LIMIT
    assert 0 < lim["maxContextTokens"] < NO_LIMIT
    assert 0 < lim["maxCompactions"] < NO_LIMIT


def test_the_run_actually_stops_at_the_configured_step_count() -> None:
    config.update_settings({"ai": {"enforceLimits": True, "maxSteps": 3, "maxSeconds": 600}})
    fake = LoopingModel()
    evs = _run(fake)
    done = [e for e in evs if e["type"] == "done"]
    assert done and done[0]["reason"] == "max_steps"
    assert done[0]["steps"] == 3, done[0]


def test_with_the_limits_off_the_same_run_goes_past_the_old_ceiling() -> None:
    """The end-to-end proof: the identical looping model, stopped only by the analyst's Stop."""
    config.update_settings({"ai": {"enforceLimits": False}})
    fake = LoopingModel()
    rid = ai_runs.new_id()

    async def go():
        seen = []
        async for ev in investigator.investigate(STORE, "work it to the end", rid, client=fake):
            seen.append(ev)
            if ev.get("type") == "step" and len([e for e in seen if e.get("type") == "step"]) >= 45:
                ai_runs.request_stop(rid)      # well past the shipped 40-step ceiling
        return seen

    evs = asyncio.run(go())
    steps = [e for e in evs if e.get("type") == "step"]
    assert len(steps) >= 45, f"stopped after {len(steps)} steps despite the limits being off"
    done = [e for e in evs if e["type"] == "done"]
    assert done and done[0]["reason"] == "stopped"


def test_the_system_message_states_the_budget_in_force() -> None:
    config.update_settings({"ai": {"enforceLimits": True, "maxSteps": 7, "maxSeconds": 90}})
    fake = LoopingModel()
    _run(fake)
    assert "RUN BUDGET FOR THIS RUN" in fake.system[0]
    assert "7 tool-calling steps" in fake.system[0] and "90 seconds" in fake.system[0]

    config.update_settings({"ai": {"enforceLimits": False}})
    fake2 = LoopingModel()
    rid = ai_runs.new_id()

    async def one_turn():
        out = []
        async for ev in investigator.investigate(STORE, "deep", rid, client=fake2):
            out.append(ev)
            if ev.get("type") == "step":
                ai_runs.request_stop(rid)
        return out

    asyncio.run(one_turn())
    assert "RUN BUDGET — NONE" in fake2.system[0]
    assert "RECORD AS YOU GO" in fake2.system[0]


def test_the_budget_block_is_appended_to_whatever_prompt_is_in_force() -> None:
    """It is appended, not baked in, because the analyst may have EDITED the built-in prompt."""
    bounded = run_budget({"enforced": 1, "maxSteps": 40, "maxSeconds": 600, "maxWrites": 200})
    unbounded = run_budget({"enforced": 0, "maxSteps": NO_LIMIT, "maxSeconds": NO_LIMIT, "maxWrites": NO_LIMIT})
    assert str(NO_LIMIT) not in unbounded, "a sentinel must never be shown to the model as a number"
    assert "40 tool-calling steps" in bounded
