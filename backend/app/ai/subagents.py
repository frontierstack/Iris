"""DELEGATION — one lead analyst, several worker agents, all reading the same evidence pool.

*"Also, parallel agents there needs to be one agent delegating work. Make multiple agents smarter to
work with, make sure two agents are always working."*

What existed before this module was PARALLEL TOOL CALLS: the independent reads of ONE model turn run
at the same time (`investigator._lanes`). That is real concurrency and it stays — it is what makes
four counts cost one wait. But it is not delegation, because there is only ever one mind: the lead
model has to hold every sub-question in its own context, ask them one turn at a time, and read every
byte that comes back. On a workspace with thirty sources that is exactly where a run runs out of
context and starts summarising instead of investigating.

Delegation is a different shape and solves a different problem:

* **The lead stays the analyst.** It decides what the questions are, it holds the case, and it is the
  only thing that WRITES. A worker is a pair of hands with read tools — it cannot create a case, add a
  note, draw a link or touch a rule, by ABSENCE rather than by a check (the registry it is handed
  contains no write tool at all). So a fan-out can never race on case.json, can never double-write an
  indicator, and can never produce an action the lead's undo list does not know about.
* **Context is the scarce resource, and delegation is what actually buys some.** A worker reads
  fifty rows, forty field facets and three histograms and hands back a page of findings with verified
  event ids. The forty thousand characters it read never enter the lead's transcript. That is the
  whole point: the lead's window holds CONCLUSIONS, the workers' windows hold EVIDENCE.
* **Two agents are always working.** `delegate_investigation` REFUSES a single task — one worker is
  not delegation, it is a slower way to make the call yourself, and it hands the lead a second-hand
  answer for no saving at all. The floor is two, and the ceiling is the analyst's "Parallel tool
  calls" setting (at least two, at most four, because every worker is a live provider stream plus a
  tool call in flight).

Three rules that make a worker's answer usable as evidence:

1. **A worker's report is PROSE, not a tool result.** It is a model talking. The lead is told so in
   as many words, and every event id in it is verified against the live pool here (`verify_event_ids`)
   before it is handed over — an id a worker invented is dropped and the drop is REPORTED, never
   silently passed up to be cited in a note. The lead re-reads anything decisive itself.
2. **A worker is bounded like a run**: its own step count, its own wall clock, its own per-call
   deadline, and the analyst's Stop reaches it — `RunContext.stopping()` is the lead's own stopper, so
   pressing Stop ends the workers, not just the lead.
3. **The workers SHARE the lead's read cache.** Two agents asking the same question is one search;
   the second is served from `RunContext.cache` exactly as a repeat by the lead would be. That is also
   why a worker may not write: a write clears that cache, and clearing it under three concurrent
   readers is how you get two agents holding different answers to the same question.

Live visibility is not decoration here — the analyst asked to SEE two agents working. The handler
runs inside a worker thread (tool handlers are sync), so it cannot touch the event loop's queues; it
records progress into a thread-safe registry instead and `investigator` drains it while it waits,
turning it into ordinary `status` events. Start and finish are reported per agent the moment they
happen; the calls in between are rolled into one line every few seconds rather than one line each,
because thirty "agent A called count_events" rows is the transcript noise this project keeps deleting.
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import Any, Callable, Optional

import orjson

MAX_TASKS = 6                 # more than this is a survey, not a delegation
MIN_TASKS = 2                 # "make sure two agents are always working"
WORKER_RESULT_CHARS = 3000    # a worker's own tool results are clipped harder than the lead's
REPORT_CHARS = 4000           # ...and so is what it hands back
TASK_OBJECTIVE_CHARS = 1200
# Seconds of the DELEGATE call's own budget held back so every agent can still write its report and
# the handler can return normally. Overrunning means `investigator._watch` abandons the whole call and
# the lead loses every agent's work, not just the one that ran long.
WRAP_UP_RESERVE = 25.0
AGENT_MARGIN = 30.0
# A worker has no compaction of its own — deliberately: it is a short loop with one question, and a
# running brief is machinery it would spend its few steps on. What it does need is a CEILING, because
# ten steps of three reads at WORKER_RESULT_CHARS each is ~90k characters on top of the schemas, which
# is more than a small local model's whole window. So the OLDEST results are stubbed as it goes. It is
# the honest trade here: a worker has already reasoned about an old result (its conclusions are in its
# own prose), and the alternative is the provider refusing the turn and the agent returning nothing.
WORKER_CONTEXT_CHARS = 56_000
ELIDED_CHARS = 400
KEEP_RECENT = 4               # messages at the end `_fit` will not touch: this turn's work


def _env_int(name: str, default: int, cap: int) -> int:
    try:
        v = int(os.environ.get(name, "") or default)
    except ValueError:
        return default
    return max(1, min(cap, v))


def worker_steps() -> int:
    """Model turns one worker may take. Small on purpose: a worker answers ONE scoped question."""
    return _env_int("IRIS_AI_WORKER_STEPS", 10, 30)


def worker_seconds() -> int:
    return _env_int("IRIS_AI_WORKER_SECONDS", 300, 900)


def worker_parallel_reads() -> int:
    """How many of a worker's own tool calls run together. Its reads are independent by construction."""
    return _env_int("IRIS_AI_WORKER_READS", 3, 4)


# ------------------------------------------------------------------ live progress
# The handler runs on a thread (see the module note), so this is a plain lock and a list, never an
# asyncio queue. `drain` is called from the event loop between polls of the call it is waiting on.
_PROGRESS: dict[str, list[dict[str, Any]]] = {}
_LOCK = threading.Lock()


MAX_PROGRESS_ROWS = 500       # per run, in case nothing ever drains it
MAX_PROGRESS_RUNS = 32        # ...and runs, for a caller that never drains at all


def note(run_id: str, event: dict[str, Any]) -> None:
    """Record one progress event for a lead run. Never raises: progress must not break a worker.

    Bounded in BOTH directions. The investigator drains this while it waits and clears the run's entry
    when it ends, but `delegate_investigation` is an ordinary registry tool and MCP can call it too —
    and an MCP caller has a fresh run id every request and never drains. A per-run cap alone would
    still leak one list per request forever, so the oldest run is evicted as well (a plain dict keeps
    insertion order, which is all this needs).
    """
    if not run_id:
        return
    try:
        with _LOCK:
            rows = _PROGRESS.setdefault(run_id, [])
            if len(rows) < MAX_PROGRESS_ROWS:
                rows.append(event)
            while len(_PROGRESS) > MAX_PROGRESS_RUNS:
                _PROGRESS.pop(next(iter(_PROGRESS)))
    except Exception:  # noqa: BLE001
        pass


def drain(run_id: str) -> list[dict[str, Any]]:
    """Everything recorded since the last drain, and forget it."""
    with _LOCK:
        return _PROGRESS.pop(run_id, [])


def forget(run_id: str) -> None:
    with _LOCK:
        _PROGRESS.pop(run_id, None)


# ------------------------------------------------------------------ the worker itself
def worker_tools() -> dict[str, Any]:
    """The tools a worker may use: every READ in the registry, and nothing else.

    Absence, not a check. A worker holding `add_note` that is merely told not to call it will call it
    eventually; a worker that was never given the schema cannot. `delegate_investigation` is left out
    too — a worker that delegates is a fan-out with no ceiling and no lead.
    """
    from . import tools as T
    return {name: t for name, t in T.REGISTRY.items()
            if not t.writes and name != "delegate_investigation"}


def _schemas(reg: dict[str, Any]) -> list[dict[str, Any]]:
    return [t.schema() for t in reg.values()]


def _clip(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + f"\n…[clipped, {len(text) - limit} more chars]"


def _fit(messages: list[dict[str, Any]]) -> int:
    """Stub the OLDEST tool results until the transcript is under WORKER_CONTEXT_CHARS. Returns how many.

    Three things it must not touch, and the third is the one that is easy to get wrong:
    * the system message and the task (messages[0] and [1]) — if those two alone did not fit, nothing
      here could help anyway;
    * an assistant message, because an OpenAI-shaped provider matches a tool message to the
      `tool_calls` of the assistant turn that asked for it;
    * **the RECENT tail.** The fixed part can be bigger than the ceiling on its own (a long system
      prompt and a big orientation block), and then a loop that just kept going would stub every
      result including the one that had ARRIVED THIS TURN — leaving the worker reasoning about a stub
      of the answer it asked for, which is worse than being refused. It stops at `KEEP_RECENT`
      messages from the end and reports how far it got.
    """
    total = sum(len(str(m.get("content") or "")) for m in messages)
    if total <= WORKER_CONTEXT_CHARS:
        return 0
    elided = 0
    for m in messages[2:max(2, len(messages) - KEEP_RECENT)]:
        if total <= WORKER_CONTEXT_CHARS:
            break
        if m.get("role") != "tool":
            continue
        body = str(m.get("content") or "")
        if len(body) <= ELIDED_CHARS:
            continue
        m["content"] = (body[:ELIDED_CHARS] + "\n…[this result was elided to keep your context inside "
                        "the model's window — call again, narrower, if you still need it]")
        total -= len(body) - len(str(m["content"]))
        elided += 1
    return elided


async def _dispatch(calls: list[dict[str, Any]], reg: dict[str, Any], ctx: Any, agent: str,
                    run_id: str, width: int) -> list[dict[str, Any]]:
    """Run one turn's calls, up to `width` at a time, answering every one of them.

    EVERY tool_call must get a tool message back or an OpenAI-shaped provider rejects the next
    request — a refusal is an answer, a skipped call is a broken transcript. Order is preserved for
    the same reason the lead preserves it: the provider matches messages to its own call ids.
    """
    from .investigator import _run_tool
    prepared: list[dict[str, Any]] = []
    for i, call in enumerate(calls):
        fn = call.get("function") or {}
        name = str(fn.get("name") or "")
        cid = str(call.get("id") or f"{run_id}-{agent}-{i}")
        call["id"] = cid
        raw = fn.get("arguments") or "{}"
        try:
            args = orjson.loads(raw) if str(raw).strip() else {}
            if not isinstance(args, dict):
                raise ValueError("arguments were not a JSON object")
            err = ""
        except Exception as exc:  # noqa: BLE001
            args, err = {}, f"your arguments were not valid JSON ({exc}). Send the call again, smaller."
        if name not in reg and not err:
            err = (f"{name} is not available to you. You are a worker agent with READ tools only: "
                   + ", ".join(sorted(reg)) + ".")
        prepared.append({"id": cid, "name": name, "args": args, "err": err, "ok": False, "result": ""})

    sem = asyncio.Semaphore(max(1, width))

    async def one(entry: dict[str, Any]) -> None:
        if entry["err"]:
            entry["ok"], entry["result"] = False, entry["err"]
            return
        async with sem:
            note(run_id, {"agent": agent, "phase": "call", "tool": entry["name"]})
            entry["ok"], entry["result"] = await _run_tool(entry["name"], entry["args"], ctx)

    await asyncio.gather(*(one(e) for e in prepared))
    return prepared


async def run_worker(task: dict[str, Any], *, client: Any, ctx: Any, context_block: str,
                     run_id: str, max_steps: int, deadline: float) -> dict[str, Any]:
    """One worker agent: a bounded read-only tool loop over ONE scoped question.

    Returns what the lead reads — the worker's report, the event ids in it that actually exist, and
    how much work it cost. It never raises: a worker that dies takes its own task down and no more,
    because the lead is owed an answer for every task it delegated.
    """
    from .prompts import WORKER_SYSTEM, WORKER_TASK
    from . import tools as T

    name = str(task.get("name") or "agent")[:60]
    objective = _clip(str(task.get("objective") or "").strip(), TASK_OBJECTIVE_CHARS)
    focus = _clip(str(task.get("focus") or "").strip(), 400)
    reg = worker_tools()
    schemas = _schemas(reg)
    started = time.perf_counter()
    note(run_id, {"agent": name, "phase": "start", "objective": objective[:160]})

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": WORKER_SYSTEM},
        {"role": "user", "content": WORKER_TASK.format(
            name=name, objective=objective,
            focus=("\nWHAT THE LEAD ALREADY KNOWS (do not re-derive it): " + focus) if focus else "",
            context=context_block)},
    ]
    report = ""
    calls_made = 0
    steps = 0
    stopped = ""
    elided = 0
    for steps in range(1, max_steps + 1):
        if ctx.stopping():
            stopped = "the analyst stopped the run"
            break
        if time.monotonic() >= deadline:
            stopped = "this agent reached its time budget"
            break
        elided += _fit(messages)     # before the request, not after it is refused
        buf: list[str] = []
        msg: dict[str, Any] = {}
        try:
            async for item in client.stream_chat(messages, tools=schemas, temperature=0.1):
                # A STOP HAS TO LAND INSIDE THE STREAM, not only between steps. A gateway reply
                # takes as long as it takes, and reading one to the end after the analyst pressed
                # Stop is most of what "the stop button does not stop things at all" actually was:
                # the lead finalises the run in about a second while each worker quietly finishes
                # the reply it is part-way through and then asks for another. Dropping out here
                # costs a half-read reply, which is what was asked for.
                if ctx.stopping():
                    stopped = "the analyst stopped the run"
                    break
                if item["type"] == "text":
                    buf.append(item["text"])
                elif item["type"] == "message":
                    msg = item["message"]
        except Exception as exc:  # noqa: BLE001 — one worker's provider failure is not the run's
            stopped = f"{type(exc).__name__}: {exc}"
            break
        if stopped:      # broke out of the stream above - do not dispatch a half-read turn
            break
        text = "".join(buf) or str(msg.get("content") or "")
        calls = list(msg.get("tool_calls") or [])
        if text.strip():
            report = text            # the LATEST prose is the report; earlier turns are narration
        if not calls:
            break
        messages.append(msg)
        prepared = await _dispatch(calls, reg, ctx, name, run_id, worker_parallel_reads())
        calls_made += len(prepared)
        for entry in prepared:
            payload = entry["result"] if entry["ok"] else {"error": entry["result"]}
            messages.append({"role": "tool", "tool_call_id": entry["id"], "name": entry["name"],
                             "content": _clip(orjson.dumps(payload).decode(), WORKER_RESULT_CHARS)})
    else:
        stopped = f"this agent used all {max_steps} of its steps"

    # A worker that spent its budget mid-search has findings in its transcript and no report written.
    # One final turn with the tool channel CLOSED is what turns those into an answer — the same trade
    # the lead's own wrap-up makes, and for the same reason: the work is already paid for. It is
    # skipped when there is no room left for it: overrunning here is how the whole delegate call gets
    # abandoned by the investigator's watchdog, losing every OTHER agent's report as well.
    if stopped and not ctx.stopping() and ctx.remaining() > WRAP_UP_RESERVE:
        from .prompts import WORKER_WRAP_UP
        messages.append({"role": "user", "content": WORKER_WRAP_UP.format(why=stopped)})
        try:
            buf = []
            msg = {}
            async for item in client.stream_chat(messages, tools=None, temperature=0.1,
                                                 tool_choice="none"):
                if item["type"] == "text":
                    buf.append(item["text"])
                elif item["type"] == "message":
                    msg = item["message"]
            piece = "".join(buf) or str(msg.get("content") or "")
            if piece.strip():
                report = piece
        except Exception:  # noqa: BLE001 — the partial report is better than none
            pass

    # VERIFIED CITATIONS ONLY. A worker is a model, and an id it invented must not reach the lead to
    # be copied into a note — that is the fabricated-citation harm, one remove further away from the
    # analyst and therefore harder to catch. What it claimed and what exists are BOTH reported.
    from .eventids import find as find_ids
    claimed = find_ids(report, cap=80)
    bad = T.verify_event_ids(claimed)          # NB: it returns the ids that do NOT exist
    real = [i for i in claimed if i not in bad]
    took = int((time.perf_counter() - started) * 1000)
    note(run_id, {"agent": name, "phase": "done", "calls": calls_made, "tookMs": took,
                  "stopped": stopped})
    out: dict[str, Any] = {
        "agent": name, "objective": objective, "report": _clip(report.strip(), REPORT_CHARS),
        "eventIds": real, "toolCalls": calls_made, "steps": steps, "tookMs": took,
    }
    if elided:
        # SAID, never silent: a worker whose own older evidence was stubbed may have reported less
        # than it found, and the lead has to be able to tell that from "there was nothing there".
        out["elidedResults"] = elided
    if stopped:
        out["endedEarly"] = stopped
    if bad:
        out["droppedCitations"] = bad[:20]
        out["note"] = (f"{len(bad)} event id(s) this agent wrote do not exist in the workspace and were "
                       "removed. Do NOT cite them. Treat the findings that rested on them as unverified.")
    if not report.strip():
        out["report"] = ""
        out["note"] = "this agent produced no report" + (f" — {stopped}" if stopped else "") + "."
    return out


def max_agents(parallel: int) -> int:
    """At least two (that is the whole feature), at most four, otherwise the analyst's setting."""
    return max(MIN_TASKS, min(4, int(parallel or MIN_TASKS)))


async def run_tasks(tasks: list[dict[str, Any]], *, client: Any, ctx: Any, context_block: str,
                    run_id: str, width: int) -> list[dict[str, Any]]:
    """Every task, at most `width` agents in flight, results in the order the lead asked for them."""
    sem = asyncio.Semaphore(max(MIN_TASKS, width))
    # THE AGENTS' CLOCK IS THE DELEGATE CALL'S CLOCK. `delegate_investigation` is a tool call like any
    # other and `investigator._watch` abandons it at its own deadline — so a worker budget taken from
    # the environment alone would routinely outlive the call that is waiting for it and every report
    # would be thrown away. `ctx.remaining()` is that call's real budget (the tool's `budget_factor`
    # is already in it); the margin leaves room for the wrap-up turns and for returning the result.
    budget = max(20.0, min(float(worker_seconds()), ctx.remaining() - AGENT_MARGIN))
    deadline = time.monotonic() + budget
    steps = worker_steps()

    async def one(task: dict[str, Any]) -> dict[str, Any]:
        async with sem:
            try:
                return await run_worker(task, client=client, ctx=ctx, context_block=context_block,
                                        run_id=run_id, max_steps=steps, deadline=deadline)
            except Exception as exc:  # noqa: BLE001 — the lead is owed an answer for every task
                return {"agent": str(task.get("name") or "agent")[:60],
                        "objective": str(task.get("objective") or "")[:200],
                        "report": "", "eventIds": [], "toolCalls": 0, "steps": 0, "tookMs": 0,
                        "error": f"{type(exc).__name__}: {exc}"}

    return list(await asyncio.gather(*(one(t) for t in tasks)))


def run_blocking(tasks: list[dict[str, Any]], *, client: Any, ctx: Any, context_block: str,
                 run_id: str, width: int) -> list[dict[str, Any]]:
    """`run_tasks` from a synchronous tool handler.

    Tool handlers run on a worker thread (`asyncio.to_thread`), which has no event loop of its own, so
    a fresh one here is correct and cannot interfere with the request loop. `asyncio.run` also cancels
    and closes what it started, so a worker left mid-stream by a Stop does not outlive the call.
    """
    return asyncio.run(run_tasks(tasks, client=client, ctx=ctx, context_block=context_block,
                                 run_id=run_id, width=width))
