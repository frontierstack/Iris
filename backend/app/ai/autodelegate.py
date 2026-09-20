"""AUTOMATIC DELEGATION — Iris plans the fan-out itself instead of waiting for the model to ask.

The analyst asked for this three times, in nearly the same words: *"make sure two agents are always
working"*, *"I'm not seeing multiple agents working"*, *"I'm still not seeing multiple agents
working"*. Everything needed to run agents had been there the whole time — a delegation of three
finishes 27 tool calls in about four seconds against a fast provider. What was missing is that the
model has to CHOOSE to delegate, and theirs does not. One real run on their own gateway, read back
from the transcript:

    207 s of wall clock, 7 tool calls, ~5.6 s of it spent in tools. 97 % of the run was the model
    generating, about 30 s a turn — and turns 3-6 were four INDEPENDENT drill-downs (`dst_port:500`,
    then three different `dst_ip`s), taken one turn at a time. The parallel nudge fired after the
    fourth and was ignored.

So soft nudges are not a mechanism, and tool speed is not where the time is. The lever is fewer
SEQUENTIAL MODEL TURNS, which is exactly what agents buy — and the only way to get them on a model
that will not ask is for Iris to ask on its behalf.

How, and why this shape:

* ONE small planning request. It carries the objective, a digest of what the lead has found and the
  workspace summary — and NO TOOL SCHEMAS. The lead's own requests carry ~14k tokens of them, which
  on a local model is most of the prefill, so the planner answers in a fraction of a lead turn.
* It goes through `client.complete`, a plain completion. Forcing `tool_choice` to the delegate tool
  would have been simpler and is provider-dependent: a gateway that rejects it fails the TURN, and
  the classifier that spots a tools rejection ends the RUN. A plain completion works everywhere.
  It also keeps scripted test providers honest: a double that only implements `stream_chat` cannot
  plan, is skipped without a word, and its script is not consumed by a request it never expected.
* The plan is dispatched as an ordinary `delegate_investigation` call — a synthesised assistant turn
  the loop treats exactly like one the model wrote. Same lanes, same guard, same transcript, same
  roster, same verification of every event id the agents report. Nothing here runs an agent itself.
* An EMPTY plan is respected. A dependent chain (search, read those ids, pivot on what they said)
  is correct work and must not be forced into a fan-out it cannot form.
* A question answered in a turn or two never reaches the threshold at all.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Callable, Optional

from .argrepair import repair_arguments
from .prompts import PLANNER_SYSTEM, PLANNER_USER

AUTO_DELEGATE_FIRST = 2      # tool turns the lead takes alone before the first split is planned
AUTO_DELEGATE_AGAIN = 4      # ...and between later ones: the agents' answers need acting on first
MAX_AUTO_DELEGATIONS = 3     # planning attempts per run (an empty plan counts — it is an answer)
MAX_AUTO_DELEGATIONS_OFF = 8  # with the run limits switched off a long investigation may fan out more
PLANNER_TIMEOUT = 120.0      # seconds; the planner is one small request, not a turn of the run
DIGEST_CHARS = 9000          # how much of the lead's work the planner is shown
RESULT_CHARS = 1400          # ...of which one tool result may take this much
OBJECTIVE_CHARS = 4000


def _clip(text: Any, limit: int) -> str:
    s = str(text or "")
    return s if len(s) <= limit else s[:limit] + " …"


def digest(messages: list[dict[str, Any]], limit: int = DIGEST_CHARS) -> str:
    """What the lead has done, newest work kept: its prose, its calls, and what came back.

    Built from the live transcript rather than the persisted run record, because the record keeps a
    one-line SUMMARY per call ("12 of 12 queries matched something") and the planner needs the
    FINDINGS — which values, which counts — to write tasks that name them. Walked backwards so that
    when the budget runs out it is the oldest work that is dropped, not the newest.
    """
    parts: list[str] = []
    used = 0
    for m in reversed(messages[2:]):            # [0] system, [1] the objective — both sent separately
        role = m.get("role")
        if role == "tool":
            piece = f"RESULT of {m.get('name') or 'tool'}: {_clip(m.get('content'), RESULT_CHARS)}"
        elif role == "assistant":
            said = _clip(str(m.get("content") or "").strip(), 600)
            calls = "; ".join(
                f"{(c.get('function') or {}).get('name')}({_clip((c.get('function') or {}).get('arguments'), 300)})"
                for c in (m.get("tool_calls") or []))
            piece = "LEAD: " + " ".join(x for x in (said, ("CALLED " + calls) if calls else "") if x)
            if piece == "LEAD: ":
                continue
        else:
            continue                             # nudges are Iris talking, not findings
        if used + len(piece) > limit and parts:
            break
        parts.append(piece)
        used += len(piece)
    return "\n".join(reversed(parts)) or "(nothing yet)"


_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


def parse_plan(text: str, agents: int) -> list[dict[str, str]]:
    """The tasks out of the planner's reply — tolerant of everything a small model wraps JSON in.

    A fence, a sentence before the object, a trailing comma, a reply cut off mid-list: each is
    repaired mechanically (`argrepair`, the same salvage tool arguments get) and none is guessed at.
    A task with no question in it is dropped, exactly as `delegate_investigation` would drop it, and
    the key the question arrives under is as forgiving here as it is there.
    """
    from .tools import _task_objective, _s
    raw = _FENCE.sub("", (text or "").strip()).strip()
    start = min([i for i in (raw.find("{"), raw.find("[")) if i >= 0] or [-1])
    if start < 0:
        return []
    raw = raw[start:]
    data: Any = None
    for end in (len(raw), max(raw.rfind("}"), raw.rfind("]")) + 1):
        try:
            data = json.loads(raw[:end])
            break
        except (ValueError, TypeError):
            continue
    if data is None:
        try:
            data, _notes = repair_arguments(raw)
        except Exception:  # noqa: BLE001 — an unparsable plan is "no plan", never a failed run
            return []
    items = data.get("tasks") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for i, t in enumerate(items, 1):
        objective = _s(_task_objective(t), OBJECTIVE_CHARS).strip()
        if not objective or objective.lower() in seen:
            continue
        seen.add(objective.lower())
        src = t if isinstance(t, dict) else {}
        name = re.sub(r"[^A-Za-z0-9_.-]+", "-", _s(src.get("name"), 40).strip()).strip("-") or f"agent{i}"
        out.append({"name": name, "objective": objective, "focus": _s(src.get("focus"), 1200).strip()})
        if len(out) >= max(2, agents):
            break
    return out


def due(*, enabled: bool, turns_alone: int, attempts: int, delegations: int, enforced: bool) -> bool:
    """Is it time to plan a split? Pure, so the policy can be read and tested in one place."""
    if not enabled:
        return False
    if attempts >= (MAX_AUTO_DELEGATIONS if enforced else MAX_AUTO_DELEGATIONS_OFF):
        return False
    first = attempts == 0 and delegations == 0
    return turns_alone >= (AUTO_DELEGATE_FIRST if first else AUTO_DELEGATE_AGAIN)


async def plan(client: Any, objective: str, messages: list[dict[str, Any]], context: str, agents: int,
               stopped: Callable[[], bool]) -> tuple[Optional[list[dict[str, str]]], str]:
    """Ask for a split. Returns (tasks, '') or (None, why-not) — it never raises.

    `None, ''` means "this client cannot plan" and is deliberately SILENT: that is a scripted test
    provider, not a provider failure, and a status line there would be noise about nothing.
    """
    complete = getattr(client, "complete", None)
    if not callable(complete):
        return None, ""
    user = PLANNER_USER.format(objective=_clip(objective, OBJECTIVE_CHARS), digest=digest(messages),
                               context=_clip(context, 3500), agents=max(2, agents))
    task = asyncio.ensure_future(complete(PLANNER_SYSTEM, user, 0.2))
    t0 = time.monotonic()
    try:
        while not task.done():
            # A STOP LANDS HERE TOO. The planner is a provider request like any other, and a run that
            # cannot be stopped while it waits for one is the bug this project already fixed twice.
            if stopped():
                task.cancel()
                return None, "the run was stopped"
            if time.monotonic() - t0 > PLANNER_TIMEOUT:
                task.cancel()
                return None, f"the planner did not answer within {int(PLANNER_TIMEOUT)} s"
            await asyncio.wait([task], timeout=0.25)
        text = task.result()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 — a failed plan costs the split, never the run
        print(f"[iris] automatic delegation: planner failed: {type(exc).__name__}: {exc}", flush=True)
        return None, f"the planner request failed ({type(exc).__name__})"
    tasks = parse_plan(str(text or ""), agents)
    if len(tasks) < 2:
        return None, ("the planner judged the remaining work to be one dependent chain"
                      if not tasks else "the planner found only one separable question")
    return tasks, ""


def assistant_turn(run_id: str, n: int, tasks: list[dict[str, str]]) -> dict[str, Any]:
    """The synthesised assistant message: narration plus ONE delegate_investigation call."""
    names = ", ".join(t["name"] for t in tasks)
    return {
        "role": "assistant",
        "content": (f"Splitting the remaining work across {len(tasks)} agents so it runs at the same "
                    f"time: {names}."),
        "tool_calls": [{
            "id": f"{run_id}-auto{n}", "type": "function",
            "function": {"name": "delegate_investigation",
                         "arguments": json.dumps({"tasks": tasks}, ensure_ascii=False)},
        }],
    }
