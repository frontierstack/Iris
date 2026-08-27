"""The LIVE bus: what the assistant changed, pushed to every open screen as it happens.

*"When the AI assistant is working and building a case, I want to see the case being updated live
when the agent is working ... see events appear live without having to refresh the page."*

The panel already knew: every `write` the investigator makes streams down the run's own SSE and the
panel invalidated the case queries when one arrived. That covered exactly one situation — the tab
that started the run, with the panel still open. Close the panel (it unmounts), watch from a second
tab, or lose the stream to a reconnect, and the case screen sat on stale data until the run ENDED.

So the signal moves out of the panel. This module is an in-process broadcast: the investigate route
publishes the events that change the workspace (`run`, `write`, `done`, `undo`), and `GET /api/ai/live`
streams them to every subscriber as server-sent events. The SPA opens ONE `EventSource` for the whole
app (in the provider that is mounted for its lifetime) and turns each event into a query
invalidation — the screens then refetch what they show, and a note, an indicator or a timeline entry
appears the moment the agent wrote it. Push, not polling: nothing asks the server "anything new?"
every second for the hours a workspace sits idle.

Deliberately small:
- **Subscribers are asyncio queues on the event loop.** `publish` is called from the loop (the
  drive task), so no locking; a full queue DROPS the event for that subscriber rather than blocking
  the run — a screen that has fallen that far behind will refetch on the next event anyway, and the
  persisted transcript is the record.
- **Events carry ids and the action, never the transcript.** This is a "something changed, look
  again" signal; the case data itself is fetched through the same endpoints the screens already use,
  so the live view and a refreshed view cannot differ.
- **No history.** A subscriber that connects mid-run sees what happens next; what happened before is
  in `GET /api/ai/runs/{id}`. The SPA refetches once on connect to cover the gap.
"""
from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator

QUEUE_MAX = 256           # events a slow subscriber may fall behind before it starts losing them
KEEPALIVE_SEC = 15        # an SSE comment line, so a proxy/browser idle timeout never drops the stream

_SUBS: set[asyncio.Queue] = set()
_DROPPED = 0


def subscribers() -> int:
    return len(_SUBS)


def dropped() -> int:
    return _DROPPED


def publish(event: dict[str, Any]) -> int:
    """Hand one event to every subscriber. Returns how many received it.

    Never blocks and never raises: the run that produced the event must not depend on who is watching.
    """
    global _DROPPED
    delivered = 0
    for q in list(_SUBS):
        try:
            q.put_nowait(event)
            delivered += 1
        except asyncio.QueueFull:
            _DROPPED += 1
    return delivered


async def stream() -> AsyncIterator[str]:
    """The SSE body for one subscriber: `data: {...}` per event, `: keepalive` when idle."""
    q: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)
    _SUBS.add(q)
    try:
        import orjson
        yield "data: " + orjson.dumps({"type": "hello", "subscribers": len(_SUBS)}).decode() + "\n\n"
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=KEEPALIVE_SEC)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            yield "data: " + orjson.dumps(item).decode() + "\n\n"
    finally:
        _SUBS.discard(q)


def event_for(run_id: str, item: dict[str, Any]) -> dict[str, Any] | None:
    """The live-bus event for one investigator stream item, or None for items that change nothing.

    Prose deltas, tool reads and step markers are the panel's business. The bus carries what a SCREEN
    has to react to: the run starting (so a case screen can show "the assistant is working"), each
    write (the action, so the SPA knows which case it created or which artefact it touched), and the
    end (the final refetch, whatever the reason).
    """
    t = item.get("type")
    if t == "write":
        return {"type": "write", "runId": run_id, "action": item.get("action") or {}}
    if t == "run":
        return {"type": "run", "runId": run_id, "caseId": item.get("caseId") or ""}
    if t in ("done", "error"):
        return {"type": "done", "runId": run_id, "state": item.get("state") or t,
                "writes": item.get("writes") or 0}
    return None
