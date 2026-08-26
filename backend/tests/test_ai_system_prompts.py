"""Saved system prompts: the store, the API, and the investigator actually using the selected one."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config
from app.ai import investigator, runs
from app.ai.prompts import INVESTIGATOR_SYSTEM
from app.ai.system_prompts import PROMPTS, compose
from app.main import app
from app.store import STORE


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class CaptureModel:
    """A fake provider that records the system message it was handed and answers at once."""
    def __init__(self) -> None:
        self.model = "fake"
        self.configured = True
        self.system: list[str] = []

    async def stream_chat(self, messages, tools=None, max_tokens=1400, temperature=0.1, tool_choice="auto"):
        self.system.append(messages[0]["content"])
        yield {"type": "text", "text": "done"}
        yield {"type": "message", "message": {"role": "assistant", "content": "done"}, "finish": "stop"}


async def _run(fake, **kw):
    rid = runs.new_id()
    return [ev async for ev in investigator.investigate(STORE, "what happened?", rid, client=fake, **kw)]


@pytest.fixture(autouse=True)
def _clean():
    for row in PROMPTS.list():
        PROMPTS.delete(row["id"])
    config.update_settings({"ai": {"systemPromptId": ""}})
    yield
    for row in PROMPTS.list():
        PROMPTS.delete(row["id"])
    config.update_settings({"ai": {"systemPromptId": ""}})


def test_crud_over_the_api(client):
    r = client.get("/api/ai/system-prompts")
    assert r.status_code == 200
    assert r.json()["prompts"] == [] and r.json()["activeId"] == ""
    assert r.json()["builtin"] == INVESTIGATOR_SYSTEM

    r = client.post("/api/ai/system-prompts", json={"name": "House style", "text": "Write in British English."})
    assert r.status_code == 201, r.text
    row = r.json()
    assert row["mode"] == "extend" and row["id"].startswith("sp-")

    eff = client.get(f"/api/ai/system-prompts/{row['id']}/effective").json()["text"]
    assert eff.startswith(INVESTIGATOR_SYSTEM) and eff.endswith("Write in British English.")
    assert "ANALYST INSTRUCTIONS" in eff and "'House style'" in eff

    r = client.put(f"/api/ai/system-prompts/{row['id']}", json={"mode": "replace", "text": "You are terse."})
    assert r.status_code == 200 and r.json()["mode"] == "replace"
    assert client.get(f"/api/ai/system-prompts/{row['id']}/effective").json()["text"] == "You are terse."

    # a saved prompt survives a reload of the store from disk
    PROMPTS._loaded_from = None
    assert [p["name"] for p in client.get("/api/ai/system-prompts").json()["prompts"]] == ["House style"]

    assert client.delete(f"/api/ai/system-prompts/{row['id']}").status_code == 200
    assert client.delete(f"/api/ai/system-prompts/{row['id']}").status_code == 404
    assert client.get("/api/ai/system-prompts").json()["prompts"] == []


def test_validation(client):
    assert client.post("/api/ai/system-prompts", json={"name": "", "text": "x"}).status_code == 400
    assert client.post("/api/ai/system-prompts", json={"name": "a", "text": "  "}).status_code == 400
    assert client.post("/api/ai/system-prompts", json={"name": "a", "text": "x", "mode": "bogus"}).status_code == 422
    assert client.put("/api/ai/system-prompts/sp-nope", json={"name": "a"}).status_code == 404


def test_deleting_the_default_resets_settings(client):
    row = client.post("/api/ai/system-prompts", json={"name": "d", "text": "t"}).json()
    client.put("/api/settings", json={"ai": {"systemPromptId": row["id"]}})
    assert client.get("/api/ai/system-prompts").json()["activeId"] == row["id"]
    r = client.delete(f"/api/ai/system-prompts/{row['id']}")
    assert r.json()["defaultReset"] is True
    assert client.get("/api/settings").json()["ai"]["systemPromptId"] == ""


@pytest.mark.anyio
async def test_the_investigator_uses_the_selected_prompt():
    ext = PROMPTS.create("Extend me", "Always end with a haiku.", "extend")
    rep = PROMPTS.create("Replace me", "You are a pirate.", "replace")

    fake = CaptureModel()
    await _run(fake)                                   # no default set → built-in alone
    assert fake.system[-1] == INVESTIGATOR_SYSTEM

    config.update_settings({"ai": {"systemPromptId": ext["id"]}})
    evs = await _run(fake)                             # the settings default
    assert fake.system[-1] == compose(ext)
    assert fake.system[-1].startswith(INVESTIGATOR_SYSTEM) and "Always end with a haiku." in fake.system[-1]
    st = [e for e in evs if e.get("type") == "status" and e.get("systemPrompt")]
    assert st and st[0]["systemPrompt"]["name"] == "Extend me"

    await _run(fake, system_prompt_id=rep["id"])       # a per-run override
    assert fake.system[-1] == "You are a pirate."

    await _run(fake, system_prompt_id="")              # '' = built-in even though a default is set
    assert fake.system[-1] == INVESTIGATOR_SYSTEM

    evs = await _run(fake, system_prompt_id="sp-gone")  # a missing id is reported, never swapped
    assert fake.system[-1] == INVESTIGATOR_SYSTEM
    warn = [e for e in evs if e.get("type") == "warning"]
    assert warn and "sp-gone" in warn[0]["message"]
    assert [e for e in evs if e.get("type") == "done"]  # the run still ran
