"""Saved ADDITIONAL INSTRUCTIONS for the investigator (`$IRIS_DATA_DIR/ai/system_prompts.json`).

The built-in system prompt (`prompts.INVESTIGATOR_SYSTEM`) carries the operating rules the rest of the
loop depends on — answer first, cite real event ids, record as you go, how the search DSL works. A saved
prompt is what the analyst adds ON TOP of that for a kind of investigation: the house report format,
what "critical" means in their environment, which sources to distrust, a language, the questions a
phishing case always has to answer. It is ALWAYS appended to the built-in prompt, never used instead
of it — the analyst's words: *"the ones to add will be in conjunction of the built in prompt. This will
be additional ad hoc prompt for investigations."* (An earlier build had a `replace` mode; it is gone,
and a stored `mode` field is ignored.)

`settings.ai.systemPromptId` names the one used by default; a run can name another
(`AiInvestigateRequest.systemPromptId`), and `""` means the built-in prompt alone. An id that no longer
exists NEVER fails or silently swaps the prompt: `resolve()` says so, and the investigator streams a
warning and runs on the built-in prompt.

Same persistence shape as `ai/history.py` and `jobs.py`: one file, atomic tmp+replace under a lock,
path resolved per call (the tests point DATA_DIR at a throwaway dir). It is CONFIGURATION, not
evidence — `clear-all` keeps it, like rules.json and exclusions.json.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from .. import config
from .prompts import INVESTIGATOR_SYSTEM

MAX_PROMPTS = 50
MAX_NAME = 120
MAX_TEXT = 40_000

EXTEND_HEADER = (
    "\n\nADDITIONAL INSTRUCTIONS FOR THIS INVESTIGATION\n"
    "The analyst has attached the following instructions ({name!r}) to this investigation. Follow them "
    "wherever they do not conflict with the evidence rules above — a cited event id must still be real, "
    "and a claim must still trace to a line in the pool.\n\n"
)


class PromptError(ValueError):
    """A rejected prompt — the router turns it into a 400 naming the fix."""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class SystemPromptStore:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self._rows: list[dict[str, Any]] = []
        self._loaded_from: Optional[Path] = None

    # ------------------------------------------------------------- persistence
    @staticmethod
    def _path() -> Path:
        return config.DATA_DIR / "ai" / "system_prompts.json"

    def _ensure_loaded_locked(self) -> None:
        path = self._path()
        if self._loaded_from == path:
            return
        rows: list[dict[str, Any]] = []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            rows = raw.get("prompts") if isinstance(raw, dict) else raw
        except (OSError, ValueError):
            rows = []
        self._rows = []
        for r in rows or []:
            if not isinstance(r, dict) or not r.get("id"):
                continue
            self._rows.append(_normalise(r))
        self._loaded_from = path

    def _save_locked(self) -> None:
        path = self._path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"system_prompts.{uuid.uuid4().hex[:6]}.tmp")
        tmp.write_text(json.dumps({"prompts": self._rows}, indent=2), encoding="utf-8")
        tmp.replace(path)

    # ------------------------------------------------------------- reads
    def list(self) -> list[dict[str, Any]]:
        with self.lock:
            self._ensure_loaded_locked()
            return [dict(r) for r in self._rows]

    def get(self, prompt_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            self._ensure_loaded_locked()
            for r in self._rows:
                if r["id"] == prompt_id:
                    return dict(r)
        return None

    # ------------------------------------------------------------- writes
    def create(self, name: str, text: str) -> dict[str, Any]:
        row = {"id": "sp-" + uuid.uuid4().hex[:10], "name": _name(name), "text": _text(text),
               "createdAt": _now(), "updatedAt": _now()}
        with self.lock:
            self._ensure_loaded_locked()
            if len(self._rows) >= MAX_PROMPTS:
                raise PromptError(f"at most {MAX_PROMPTS} saved system prompts — delete one first")
            self._rows.append(row)
            self._save_locked()
        return dict(row)

    def update(self, prompt_id: str, *, name: Optional[str] = None,
               text: Optional[str] = None) -> Optional[dict[str, Any]]:
        with self.lock:
            self._ensure_loaded_locked()
            for r in self._rows:
                if r["id"] != prompt_id:
                    continue
                if name is not None:
                    r["name"] = _name(name)
                if text is not None:
                    r["text"] = _text(text)
                r["updatedAt"] = _now()
                self._save_locked()
                return dict(r)
        return None

    def delete(self, prompt_id: str) -> bool:
        with self.lock:
            self._ensure_loaded_locked()
            before = len(self._rows)
            self._rows = [r for r in self._rows if r["id"] != prompt_id]
            if len(self._rows) == before:
                return False
            self._save_locked()
        return True

    # ------------------------------------------------------------- the effective prompt
    def resolve(self, prompt_id: Optional[str]) -> tuple[str, dict[str, Any]]:
        """The system prompt a run should use, plus a description of where it came from.

        `None` = whatever `settings.ai.systemPromptId` says; `""` = the built-in prompt alone; an id =
        that saved prompt. Returns `(text, info)` where `info` is `{id, name, missing}` — `missing`
        is the id that was asked for and does not exist, in which case `text` is the built-in prompt.
        The caller reports that; this never raises and never picks another prompt in its place.
        """
        if prompt_id is None:
            prompt_id = config.get_settings().ai.systemPromptId or ""
        if not prompt_id:
            return INVESTIGATOR_SYSTEM, {"id": "", "name": "", "missing": ""}
        row = self.get(prompt_id)
        if row is None:
            return INVESTIGATOR_SYSTEM, {"id": "", "name": "", "missing": prompt_id}
        return compose(row), {"id": row["id"], "name": row["name"], "missing": ""}


def compose(row: dict[str, Any]) -> str:
    """The effective system prompt for one saved row: the built-in prompt, then the analyst's text.
    Pure — the preview endpoint uses it too."""
    return INVESTIGATOR_SYSTEM + EXTEND_HEADER.format(name=row.get("name", "")) + row["text"]


def _name(v: Any) -> str:
    s = str(v or "").strip()
    if not s:
        raise PromptError("a system prompt needs a name")
    if len(s) > MAX_NAME:
        raise PromptError(f"name is over {MAX_NAME} characters")
    return s


def _text(v: Any) -> str:
    s = str(v or "").replace("\r\n", "\n").strip()
    if not s:
        raise PromptError("a system prompt needs some text")
    if len(s) > MAX_TEXT:
        raise PromptError(f"prompt text is over {MAX_TEXT:,} characters")
    return s



def _normalise(r: dict[str, Any]) -> dict[str, Any]:
    return {"id": str(r["id"]), "name": str(r.get("name") or "untitled")[:MAX_NAME],
            "text": str(r.get("text") or "")[:MAX_TEXT],
            "createdAt": str(r.get("createdAt") or ""), "updatedAt": str(r.get("updatedAt") or "")}


PROMPTS = SystemPromptStore()
