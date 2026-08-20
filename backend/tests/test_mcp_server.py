"""Iris as an MCP server: handshake, tool exposure, the two switches, and the auth token.

The rules that matter, and what breaks when each is wrong:

* Disabled by default — enabling hands an outside model the whole evidence pool.
* Writes are a SEPARATE switch. Read-only is the useful default; a write tool must not even be listed
  when writes are off, or a client will offer the analyst an action that can only fail.
* The tool surface IS `ai/tools.REGISTRY`. A second declaration here would let an external agent see a
  different case from the internal one.
* A bearer token, when set, is required — and is masked on every read of the settings.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.ai.tools import REGISTRY
from app.config import get_settings, update_settings
from app.main import app
from tests.conftest import load_sample_case


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sample_case(client):
    return load_sample_case(client)


# A token is MANDATORY now: `enabled` with no token is fail-closed (503), because that state served
# every read tool to anything that could reach the port. So the helpers carry one, and the tests that
# are ABOUT authentication set their own. See tests/test_security.py for the fail-closed cases.
TOKEN = "test-mcp-token-value"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def rpc(client, method, params=None, rpc_id=1, headers=None):
    body = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/api/mcp", json=body, headers=AUTH if headers is None else headers)


def enable(**kw):
    kw.setdefault("token", TOKEN)
    update_settings({"mcp": {"enabled": True, **kw}})


def disable():
    update_settings({"mcp": {"enabled": False, "allowWrites": False, "token": ""}})


def test_disabled_by_default_and_404s(client):
    disable()
    assert get_settings().mcp.enabled is False
    r = rpc(client, "tools/list")
    assert r.status_code == 404
    assert "disabled" in r.json()["error"]["message"]


def test_initialize_handshake(client):
    enable()
    try:
        r = rpc(client, "initialize", {"protocolVersion": "2025-03-26",
                                       "clientInfo": {"name": "cursor", "version": "1.0"},
                                       "capabilities": {}})
        assert r.status_code == 200
        res = r.json()["result"]
        # the client's protocol revision is echoed back, not overridden
        assert res["protocolVersion"] == "2025-03-26"
        assert res["serverInfo"]["name"] == "iris"
        assert res["capabilities"]["tools"] == {"listChanged": False}
        assert "aggregate_events" in res["instructions"] or "Iris" in res["instructions"]
        # notifications get 202 and no body — replying to one desynchronises the client
        n = client.post("/api/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                        headers=AUTH)
        assert n.status_code == 202 and not n.content
    finally:
        disable()


def test_read_tools_only_until_writes_are_allowed(client):
    enable()
    try:
        names = [t["name"] for t in rpc(client, "tools/list").json()["result"]["tools"]]
        assert "search_events" in names and "aggregate_events" in names
        assert "add_ioc" not in names and "create_case" not in names
        assert all(REGISTRY[n].writes is False for n in names)
        # every read tool in the registry is offered — the surface is the registry, not a subset
        assert set(names) == {n for n, t in REGISTRY.items() if not t.writes}

        enable(allowWrites=True)
        names2 = [t["name"] for t in rpc(client, "tools/list").json()["result"]["tools"]]
        assert set(names2) == set(REGISTRY)
        write = next(t for t in rpc(client, "tools/list").json()["result"]["tools"] if t["name"] == "add_ioc")
        assert write["annotations"]["readOnlyHint"] is False
        assert write["annotations"]["destructiveHint"] is False
    finally:
        disable()


def test_calling_a_write_tool_with_writes_off_is_a_tool_error_not_a_crash(client):
    enable()
    try:
        r = rpc(client, "tools/call", {"name": "create_case", "arguments": {"name": "x"}})
        assert r.status_code == 200
        res = r.json()["result"]
        assert res["isError"] is True
        assert "write access is disabled" in res["content"][0]["text"]
    finally:
        disable()


def test_a_read_tool_actually_runs_against_the_pool(client, sample_case):
    enable()
    try:
        r = rpc(client, "tools/call", {"name": "count_events", "arguments": {"query": ""}})
        res = r.json()["result"]
        assert res["isError"] is False
        payload = json.loads(res["content"][0]["text"])
        assert payload["total"] > 0
        assert res["structuredContent"] == payload
    finally:
        disable()


def test_unknown_tool_and_unknown_method(client):
    enable()
    try:
        res = rpc(client, "tools/call", {"name": "delete_everything", "arguments": {}}).json()["result"]
        assert res["isError"] is True and "no such tool" in res["content"][0]["text"]
        err = rpc(client, "nonsense/method").json()["error"]
        assert err["code"] == -32601
    finally:
        disable()


def test_bad_arguments_come_back_as_the_tool_schema(client):
    enable()
    try:
        res = rpc(client, "tools/call",
                  {"name": "count_events", "arguments": {"nonsense": 1}}).json()["result"]
        assert res["isError"] is True
        assert "no parameter" in res["content"][0]["text"]
    finally:
        disable()


def test_token_is_required_when_set_and_masked_on_read(client):
    enable(token="s3cret-token-value")
    try:
        assert rpc(client, "tools/list", headers={}).status_code == 401
        assert rpc(client, "tools/list", headers={"Authorization": "Bearer wrong"}).status_code == 401
        ok = rpc(client, "tools/list", headers={"Authorization": "Bearer s3cret-token-value"})
        assert ok.status_code == 200

        shown = client.get("/api/settings").json()["mcp"]["token"]
        assert "s3cret" not in shown and shown.endswith("alue")
        # a masked value echoed back by the UI must not overwrite the real token
        client.put("/api/settings", json={"mcp": {"token": shown}})
        assert get_settings().mcp.token == "s3cret-token-value"
        # an empty token IS a deliberate removal — and it now CLOSES the server rather than opening it
        client.put("/api/settings", json={"mcp": {"token": ""}})
        assert get_settings().mcp.token == ""
        assert rpc(client, "tools/list", headers={}).status_code == 503
    finally:
        disable()


def test_status_gives_the_ui_paste_ready_client_config(client):
    enable(token="")
    try:
        s = client.get("/api/mcp/status").json()
        assert s["enabled"] is True and s["allowWrites"] is False
        # enabled but untokened: the analyst's switch is on, the server is not answering, and the
        # status says which of the two is true rather than making the UI infer it from `enabled`.
        assert s["serving"] is False and "no bearer token" in s["blockedReason"]
        assert s["url"].endswith("/api/mcp")
        assert s["toolCount"] == len(s["readTools"])
        assert s["config"]["cursor"]["mcpServers"]["iris"]["url"] == s["url"]
        assert "claude mcp add --transport http iris" in s["config"]["claudeCode"]
        assert "Authorization" not in json.dumps(s["config"]["cursor"])  # no token set

        gen = client.post("/api/mcp/token").json()["token"]
        assert len(gen) > 20
        s2 = client.get("/api/mcp/status").json()
        assert s2["hasToken"] is True and s2["serving"] is True
        # The snippets carry a PLACEHOLDER, never the credential: /api/mcp/status has no credential of
        # its own, so a live token in its body would be readable by anything that could reach the port.
        # The one clear-text delivery is the POST above, which the Settings panel fills in client-side.
        assert gen not in json.dumps(s2)
        assert s2["config"]["cursor"]["mcpServers"]["iris"]["headers"]["Authorization"].startswith("Bearer ")
        assert "Bearer" in s2["config"]["claudeCode"]
    finally:
        disable()


def test_the_get_stream_is_refused_politely(client):
    enable()
    try:
        r = client.get("/api/mcp")
        assert r.status_code == 405
    finally:
        disable()
