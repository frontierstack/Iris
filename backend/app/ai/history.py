"""Persisted AI conversation history — the transcript store behind the assistant panel.

The panel used to hold the whole conversation in React state. Refreshing the page, switching tabs or
opening a second tab lost everything: the objective the analyst typed, the steps the agent took, the
report it wrote and the list of what it changed in the case. A run also genuinely outlives the request
that started it — the SSE stream can be dropped while the agent keeps working — so the browser was
never the right place for that record.

This module is the single source of truth for it, and it is deliberately shaped like `app/jobs.py`:

  • one file, `$IRIS_DATA_DIR/ai/history.json`, written atomically (tmp + replace) under the registry
    lock, so a run finishing and a second tab reading cannot interleave a half-written file;
  • the path is resolved per call, never at import, because the tests point DATA_DIR at a throwaway dir;
  • `reconcile()` runs once at startup: a run that was mid-flight when the process died becomes
    `error` / `interrupted` instead of claiming to still be running forever;
  • retention is bounded in BOTH directions — a count cap and a byte cap on the whole file, plus a
    per-run entry cap — and pruning is oldest-terminal-first. A running conversation is never pruned.

WHAT IS STORED: the analyst's prompt, the streamed prose, one entry per tool call with its arguments
and result summary, the writes the run made (`actions`), warnings / unverified citations, the model
name, timestamps, status and the run id. **Never the API key or any other secret** — nothing from
`settings.ai` other than the model NAME ever reaches this file.

SCOPING: history is GLOBAL, with a case ASSOCIATION. A run records the case that was active when it
started (`caseId` / `caseName`, both empty in the case-less workspace) but the transcripts live at the
workspace level, not under `cases/<id>/`. Three reasons, in order:
  1. a run may target no case at all — the workspace is case-optional and the agent reads the whole
     pool — so per-case storage has nowhere to put half of them;
  2. filing them under a case would send them to `.trash/` on a case delete and resurrect them on a
     restore, so a transcript the analyst deleted could come back;
  3. the transcript is a record of what the ANALYST asked and what they were told, which outlives the
     case it happened to be pointed at.
A case delete therefore KEEPS its runs, tagged with the (now gone) case name. Undoing such a run is
harmless — `runs.undo_run` skips reversals that fail.

CONVERSATIONS, NOT JUST RUNS: a follow-up question is a NEW run that carries `threadId` (the first
run's id) and `parentId` (the turn it continues). The run stays the unit of budget, of stopping and of
undo — one turn's writes are reversed without touching the rest of the conversation — while the THREAD
is what the analyst sees as one chat and what `ai/continuation.py` turns into the context a follow-up
starts from. Grouping by a stored id rather than by "the runs that look related" is what makes
"continue from where you left off" mean something after a refresh, a restart or a second tab.

WIPED BY "clear all data": `Store.clear_all` calls `clear_all()` here, because a transcript can quote
evidence verbatim and an analyst who asks for everything to be deleted means the transcripts too.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .. import config

UTC = timezone.utc

# ------------------------------------------------------------------ retention
MAX_RUNS = 50                 # conversations kept, oldest terminal ones dropped first
MAX_FILE_BYTES = 8 * 1024 * 1024   # hard ceiling on history.json — transcripts must not grow forever
MAX_ENTRIES = 400             # transcript lines per run; a 14-step run is ~60, a pathological one is not
MAX_TEXT = 8000               # one prose entry
MAX_ANSWER = 20000            # the final report
MAX_PROMPT = 4000
MAX_SUMMARY = 400
MAX_ARGS_CHARS = 800          # the serialized tool arguments we keep for the UI line
MAX_THREAD_RUNS = 24          # turns of ONE conversation returned at once (see `thread()`)

FLUSH_EVERY = 1.0             # seconds — deltas arrive per token; the file is not rewritten per token

TERMINAL = ("done", "stopped", "error")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clip(text: Any, limit: int) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= limit else s[:limit] + "…"


def _clip_args(args: Any) -> dict[str, Any]:
    """Tool arguments, bounded. The panel only ever shows the first few keys of this."""
    if not isinstance(args, dict):
        return {}
    out: dict[str, Any] = {}
    used = 0
    for k, v in args.items():
        if used >= MAX_ARGS_CHARS:
            break
        if isinstance(v, (str, int, float, bool)) or v is None:
            sv: Any = _clip(v, 200) if isinstance(v, str) else v
        elif isinstance(v, list):
            sv = [_clip(x, 80) for x in v[:20]]
        else:
            sv = _clip(json.dumps(v, default=str), 200)
        out[str(k)[:60]] = sv
        used += len(str(sv))
    return out


class HistoryStore:
    """Every AI conversation this workspace has had, newest last in `_runs` insertion order."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._runs: dict[str, dict[str, Any]] = {}
        self._stop: set[str] = set()          # in memory only: a stop request cannot survive a restart
        self._loaded_from: Optional[Path] = None
        self._dirty_since: float = 0.0
        # The background writer behind the THROTTLED save — see `_save_locked`. Lazy, daemon, one per
        # process, and it never holds a reference to anything but this store.
        self._writer: Optional[threading.Thread] = None
        self._wake = threading.Event()
        self._suppress_write = False          # set by clear_all; cleared by the next real save

    # ------------------------------------------------------------- persistence
    @staticmethod
    def _dir() -> Path:
        return config.DATA_DIR / "ai"

    @classmethod
    def _path(cls) -> Path:
        return cls._dir() / "history.json"

    def load(self) -> None:
        path = self._path()
        rows: list[dict] = []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            rows = raw.get("runs") if isinstance(raw, dict) else raw
        except (OSError, ValueError):
            rows = []
        with self.lock:
            self._runs = {}
            for r in rows or []:
                if not isinstance(r, dict) or not r.get("id"):
                    continue
                rec = _blank(str(r["id"]))
                for k in rec:
                    if k in r:
                        rec[k] = r[k]
                rec["stop"] = False
                # a transcript read back from disk is history: nothing may still be streaming into it
                self._runs[rec["id"]] = rec
            self._loaded_from = path
            self._dirty_since = 0.0

    def _ensure_loaded(self) -> None:
        if self._loaded_from is None or self._loaded_from != self._path():
            self.load()

    def _rows_locked(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in r.items() if k != "stop"} for r in self._runs.values()]

    def _dump_locked(self) -> Optional[str]:
        try:
            return json.dumps({"runs": self._rows_locked()}, default=str)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _write_blob(path: Path, blob: str) -> None:
        # A PRIVATE tmp name, not the shared `history.tmp`: the background writer and a forced save can
        # both be in here at once, and on Windows `replace()` raises PermissionError while another
        # thread holds the same file — the library index learned this the expensive way.
        tmp = path.with_suffix(f".{uuid.uuid4().hex[:8]}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(blob, encoding="utf-8")
            tmp.replace(path)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            return

    def _writer_loop(self) -> None:
        """Drains the throttled save off the caller's thread, coalescing whatever landed while it wrote."""
        while True:
            self._wake.wait()
            self._wake.clear()
            with self.lock:
                blob = None if self._suppress_write else self._prune_locked()
                path = self._path()
            if blob is not None:
                self._write_blob(path, blob)

    def _schedule_locked(self) -> None:
        if self._writer is None or not self._writer.is_alive():
            self._writer = threading.Thread(target=self._writer_loop, name="ai-history-writer", daemon=True)
            self._writer.start()
        self._wake.set()

    def _save_locked(self, force: bool = True) -> None:
        # Structural events (a step, a tool call, a result, a write) force a write; streamed PROSE does
        # not — append_text is called once per token, and rewriting the file per token is what jobs.py
        # learned to avoid with PARSE_PROGRESS.
        #
        # THE THROTTLED SAVE DOES NOT RUN HERE. `append_text` is called from the investigator's token
        # loop, which is on the event loop that is also writing the SSE frames — and a save is a prune,
        # a full `json.dumps` of every conversation in the file and an atomic write through the data-dir
        # bind mount. Once a second, for the length of it, no token could leave the server: the panel
        # showed a burst, a pause, a burst. It is handed to a background writer instead, which coalesces
        # (one pending write, however many tokens land while it runs) and which the loop never waits for.
        # A forced save stays synchronous: those are per STEP, not per token, and callers that mutate and
        # then hand control back to the analyst should leave the file already correct.
        self._suppress_write = False
        if not force:
            if (time.time() - self._dirty_since) < FLUSH_EVERY:
                return
            self._dirty_since = time.time()   # stamped BEFORE, so the throttle holds while the write runs
            self._schedule_locked()
            return
        blob = self._prune_locked()
        if blob is None:
            return
        self._write_blob(self._path(), blob)
        self._dirty_since = time.time()

    def _touch_locked(self, rec: dict[str, Any]) -> None:
        rec["updatedAt"] = _now()

    # ------------------------------------------------------------- retention
    def _prune_locked(self) -> Optional[str]:
        """Count first, then bytes. A run that is still `running` is never dropped.

        Returns the serialised file it settled on, because measuring the byte cap IS serialising it:
        dumping again in the caller doubled the most expensive thing a save does.
        """
        def droppable() -> list[dict[str, Any]]:
            return sorted((r for r in self._runs.values() if r["state"] in TERMINAL),
                          key=_order_key)

        while len(self._runs) > MAX_RUNS:
            rows = droppable()
            if not rows:
                break
            self._runs.pop(rows[0]["id"], None)

        # the byte cap is what stops ONE enormous run from blowing the file up: measure, drop, re-measure
        blob = self._dump_locked()
        for _ in range(MAX_RUNS + 2):
            if blob is None or len(blob) <= MAX_FILE_BYTES:
                return blob
            rows = droppable()
            if not rows:
                # a single running conversation is over budget on its own — clamp its transcript rather
                # than lose the run, so the file still cannot grow without bound
                biggest = max(self._runs.values(), key=lambda r: len(r.get("transcript") or []), default=None)
                if biggest is None or not biggest.get("transcript"):
                    return blob
                keep = max(20, len(biggest["transcript"]) // 2)
                biggest["transcript"] = biggest["transcript"][-keep:]
                biggest["transcriptTruncated"] = True
            else:
                self._runs.pop(rows[0]["id"], None)
            blob = self._dump_locked()
        return blob

    # ------------------------------------------------------------------ writes
    def start(self, run_id: str, prompt: str, model: str, *, focus: str = "",
              case_id: str = "", case_name: str = "", parent_id: str = "",
              thread_id: str = "") -> dict[str, Any]:
        rec = _blank(run_id)
        rec.update({"prompt": _clip(prompt, MAX_PROMPT), "model": model or "", "focus": _clip(focus, 400),
                    "caseId": case_id or "", "caseName": case_name or "",
                    "parentId": parent_id or "", "threadId": thread_id or run_id,
                    "startedAt": _now(), "updatedAt": _now(), "state": "running"})
        with self.lock:
            self._ensure_loaded()
            rec["ord"] = max([int(r.get("ord") or 0) for r in self._runs.values()] or [0]) + 1
            self._stop.discard(run_id)
            self._runs[run_id] = rec
            self._save_locked()
        return dict(rec)

    def _append_locked(self, rec: dict[str, Any], entry: dict[str, Any]) -> None:
        tr = rec["transcript"]
        if len(tr) >= MAX_ENTRIES:
            rec["transcriptTruncated"] = True
            return
        # bound every field BEFORE it lands: one tool call with a 200 kB argument blob must not be
        # able to push the whole file past its byte cap on its own
        if entry.get("kind") == "tool":
            entry["name"] = _clip(entry.get("name"), 80)
            entry["args"] = _clip_args(entry.get("args"))
        if "text" in entry:
            entry["text"] = _clip(entry.get("text"), MAX_TEXT)
        rec["seq"] += 1
        entry["seq"] = rec["seq"]
        tr.append(entry)

    def append(self, run_id: str, entry: dict[str, Any], *, flush: bool = True) -> None:
        with self.lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return
            self._append_locked(rec, entry)
            self._touch_locked(rec)
            self._save_locked(force=flush)

    def append_text(self, run_id: str, text: str) -> None:
        """Streamed prose. Coalesced into the previous text line so one entry per paragraph, not per token."""
        with self.lock:
            rec = self._runs.get(run_id)
            if rec is None or not text:
                return
            tr = rec["transcript"]
            if tr and tr[-1].get("kind") == "text" and len(tr[-1].get("text") or "") < MAX_TEXT:
                tr[-1]["text"] = _clip((tr[-1].get("text") or "") + text, MAX_TEXT)
            else:
                self._append_locked(rec, {"kind": "text", "text": _clip(text, MAX_TEXT)})
            self._touch_locked(rec)
            self._save_locked(force=False)   # throttled: this is called once per token

    def tool_result(self, run_id: str, call_id: str, ok: bool, summary: str, took_ms: int) -> None:
        with self.lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return
            for e in reversed(rec["transcript"]):
                if e.get("kind") == "tool" and e.get("id") == call_id:
                    # `updSeq` on the SHARED counter, so a reconnecting client sees the patch: the entry
                    # keeps its `seq` (its place in the conversation), and `?since=` picks it up because
                    # it was touched after that cursor. Without it the call stayed "waiting for the
                    # result…" in every polling tab until the whole run ended.
                    rec["seq"] += 1
                    e.update({"ok": bool(ok), "summary": _clip(summary, MAX_SUMMARY), "tookMs": int(took_ms),
                              "updSeq": rec["seq"]})
                    break
            self._touch_locked(rec)
            self._save_locked()

    def note_action(self, run_id: str, action: dict[str, Any]) -> None:
        """A write landed. Recorded as it happens so a refresh mid-run still shows what changed."""
        with self.lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return
            if not any(a.get("id") == action.get("id") for a in rec["actions"]):
                rec["actions"].append(dict(action))
            self._touch_locked(rec)
            self._save_locked()

    def finish(self, run_id: str, state: str, reason: str, steps: int, tool_calls: int, answer: str,
               actions: list[dict[str, Any]], unverified: list[str], error: str = "") -> None:
        with self.lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return
            rec.update({"state": state, "reason": reason, "steps": int(steps), "toolCalls": int(tool_calls),
                        "answer": _clip(answer, MAX_ANSWER), "actions": [dict(a) for a in actions],
                        "unverifiedCitations": [str(u) for u in unverified][:200],
                        "error": _clip(error, 4000), "endedAt": _now()})
            self._touch_locked(rec)
            self._stop.discard(run_id)
            self._save_locked()

    def set_actions(self, run_id: str, actions: list[dict[str, Any]]) -> None:
        """Used by undo: the actions carry `undone`, and that has to survive a refresh too."""
        with self.lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return
            rec["actions"] = [dict(a) for a in actions]
            self._touch_locked(rec)
            self._save_locked()

    # ------------------------------------------------------------------ stop
    def request_stop(self, run_id: str) -> bool:
        with self.lock:
            rec = self._runs.get(run_id)
            if rec is None or rec["state"] != "running":
                return False
            self._stop.add(run_id)
            return True

    def stop_requested(self, run_id: str) -> bool:
        with self.lock:
            return run_id in self._stop

    # ------------------------------------------------------------------ reads
    def get(self, run_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            self._ensure_loaded()
            rec = self._runs.get(run_id)
            return _copy(rec) if rec else None

    def listing(self, limit: int = MAX_RUNS, case_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Newest first. Case-associated but NOT case-scoped — see the module docstring."""
        with self.lock:
            self._ensure_loaded()
            rows = sorted(self._runs.values(), key=_order_key, reverse=True)
            if case_id is not None:
                rows = [r for r in rows if r.get("caseId") == case_id]
            return [_copy(r) for r in rows[:max(1, limit)]]

    # ------------------------------------------------------------------ deletes
    def thread(self, run_id: str, limit: int = MAX_THREAD_RUNS) -> list[dict[str, Any]]:
        """Every turn of the conversation `run_id` belongs to, oldest first.

        Keyed on `threadId` rather than walked up `parentId`: a walk breaks the moment retention prunes
        a middle turn, and the follow-up would then silently lose the earlier half of the conversation it
        is meant to continue. A record written before threads existed has neither field, so it is its own
        one-turn thread — which is exactly what it was.
        """
        with self.lock:
            self._ensure_loaded()
            rec = self._runs.get(run_id)
            if rec is None:
                return []
            tid = str(rec.get("threadId") or rec.get("id") or run_id)
            rows = [r for r in self._runs.values() if str(r.get("threadId") or r.get("id")) == tid]
            rows.sort(key=_order_key)
            return [_copy(r) for r in rows[-limit:]]

    def delete(self, run_id: str) -> bool:
        with self.lock:
            self._ensure_loaded()
            if run_id not in self._runs:
                return False
            del self._runs[run_id]
            self._stop.discard(run_id)
            self._save_locked()
            return True

    def clear_all(self) -> int:
        """Drop every transcript and remove history.json. Returns how many conversations were removed.

        Called by `Store.clear_all` — a transcript can quote the evidence verbatim, so "clear all data"
        has to take it with everything else, and leaving history.json behind would repopulate the panel
        on the next restart.
        """
        with self.lock:
            self._ensure_loaded()
            n = len(self._runs)
            self._runs = {}
            self._stop.clear()
            # A throttled save may already be in flight on the writer thread; without this it would
            # take the lock the moment this returns and write `{"runs": []}` straight back, leaving a
            # file behind that "clear all data" said it had removed.
            self._suppress_write = True
            self._wake.clear()
            try:
                self._path().unlink(missing_ok=True)
                for tmp in self._dir().glob("history.*.tmp"):
                    tmp.unlink(missing_ok=True)
                self._path().with_suffix(".tmp").unlink(missing_ok=True)
            except OSError:
                pass
            try:
                d = self._dir()
                if d.is_dir() and not any(d.iterdir()):
                    d.rmdir()
            except OSError:
                pass
            self._loaded_from = self._path()
            return n

    # ------------------------------------------------------------ reconciliation
    def reconcile(self) -> int:
        """Startup pass: a run the restart killed must not display as still running. Returns how many."""
        self.load()
        with self.lock:
            buried = 0
            for rec in self._runs.values():
                if rec["state"] == "running":
                    rec.update({"state": "error", "reason": "interrupted", "interrupted": True,
                                "endedAt": _now(),
                                "error": "the server restarted while this investigation was still running "
                                         "— its changes to the case were kept and can still be reverted"})
                    self._touch_locked(rec)
                    buried += 1
            if buried:
                self._save_locked()
            return buried


def _order_key(rec: dict[str, Any]) -> tuple[int, str]:
    """Oldest to newest. `ord` first, `startedAt` only as a fallback for pre-`ord` files."""
    return (int(rec.get("ord") or 0), str(rec.get("startedAt") or ""))


def _blank(run_id: str) -> dict[str, Any]:
    # `ord` is a persisted monotonic sequence number and it is what "newest" and "oldest" MEAN here.
    # Ordering on `startedAt` alone is wrong: it is ISO-8601 to the SECOND, so several runs in the same
    # second tie, and the prune then drops an arbitrary one instead of the oldest.
    return {"id": run_id, "ord": 0, "prompt": "", "focus": "", "model": "", "caseId": "", "caseName": "",
            # A CONVERSATION is a chain of runs: `threadId` is the first run's id and every follow-up
            # carries it, `parentId` is the turn this one continues. A run is always the root of its own
            # thread until something continues it, so a record written before threads existed reads
            # correctly as a one-turn conversation (see `thread()`).
            "parentId": "", "threadId": "",
            "startedAt": "", "endedAt": "", "updatedAt": "", "state": "running", "reason": "",
            "steps": 0, "toolCalls": 0, "answer": "", "error": "", "interrupted": False,
            "actions": [], "unverifiedCitations": [], "transcript": [], "seq": 0,
            "transcriptTruncated": False, "stop": False}


def _copy(rec: dict[str, Any]) -> dict[str, Any]:
    out = dict(rec)
    out["actions"] = [dict(a) for a in rec.get("actions") or []]
    out["transcript"] = [dict(e) for e in rec.get("transcript") or []]
    out["unverifiedCitations"] = list(rec.get("unverifiedCitations") or [])
    return out


HISTORY = HistoryStore()


def new_id() -> str:
    return "run-" + uuid.uuid4().hex[:12]
