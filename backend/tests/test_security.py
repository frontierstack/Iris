"""Network-facing hardening — see app/security.py for the reasoning behind each control.

Every test here fails against the code as it was before this file existed. That is deliberate: the
findings were verified live against the analyst's own running instance, and a security fix with no
failing test is indistinguishable from a comment.

The four things being pinned, and what each one is worth:

* **CORS is not `*`.** Iris is unauthenticated, so the wildcard is a standing grant to every page the
  analyst has open to read the whole evidence pool. The PREFLIGHT matters as much as the simple
  request — a hostile origin was being told `access-control-allow-methods: DELETE, …` for
  `/api/sources/{id}`, which is the delete that has no trash.
* **A cross-site write is refused.** CORS stops the response being READ; it does not stop the request
  being SENT. `POST /api/admin/clear-all` takes an optional body, so a plain HTML form on any page
  wipes the workspace and the attacker never needs to see the reply.
* **MCP fails closed.** `enabled` with no token served all 26 tools to anything that could reach the
  port. In a forensics tool the reads ARE the sensitive asset, so `allowWrites:false` is not a
  mitigation.
* **Nothing hands out a credential.** `/api/mcp/status` was returning the live bearer token in
  cleartext, three times, next to a masked copy of itself.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config, security
from app.config import get_settings, update_settings
from app.main import app

EVIL = "https://evil.example"


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Every test states its own posture. A leftover IRIS_AUTH_TOKEN would silently pass tests that
    are meant to prove the no-token default is still safe."""
    monkeypatch.delenv("IRIS_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("IRIS_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("IRIS_ALLOWED_HOSTS", raising=False)
    yield


# --------------------------------------------------------------------- S1: CORS
def test_cors_is_never_a_wildcard():
    origins = security.cors_origins()
    assert "*" not in origins
    assert origins, "an empty allowlist would break `npm run dev`"
    assert all(o.startswith("http://") or o.startswith("https://") for o in origins)


def test_cors_wildcard_cannot_be_configured_back_in(monkeypatch):
    """`IRIS_CORS_ORIGINS=*` must not be an escape hatch — it is the vulnerability, spelled out."""
    monkeypatch.setenv("IRIS_CORS_ORIGINS", "*")
    assert "*" not in security.cors_origins()
    monkeypatch.setenv("IRIS_CORS_ORIGINS", "https://iris.internal, http://10.0.0.5:8000/")
    assert security.cors_origins() == ["https://iris.internal", "http://10.0.0.5:8000"]


def test_a_hostile_origin_gets_no_cors_grant_on_a_read(client):
    """The original finding: `curl -H "Origin: https://evil.example" .../api/case` came back with
    `access-control-allow-origin: *`, so the page could read the body."""
    r = client.get("/api/case", headers={"Origin": EVIL})
    assert r.headers.get("access-control-allow-origin") is None


def test_the_preflight_for_a_destructive_method_is_refused(client):
    """Verified live: OPTIONS with `Access-Control-Request-Method: POST` answered 200 with
    `access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT`. A fix that only sets
    allow_origins would still pass a naive same-origin test, so this asserts the hostile case."""
    for path, method in (("/api/admin/clear-all", "POST"),
                         ("/api/cases/CASE-0001", "DELETE"),
                         ("/api/sources/s1", "DELETE")):
        r = client.options(path, headers={"Origin": EVIL, "Access-Control-Request-Method": method})
        assert r.status_code == 403, f"{method} {path} preflight was granted"
        assert r.headers.get("access-control-allow-methods") is None
        assert r.headers.get("access-control-allow-origin") is None


def test_the_preflight_for_the_dev_server_still_works(client):
    """A safe default that breaks `npm run dev` is a default someone turns off."""
    r = client.options("/api/settings", headers={"Origin": "http://localhost:5173",
                                                 "Access-Control-Request-Method": "PUT"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


# --------------------------------------------- S5 (a): cross-site writes, i.e. CSRF
@pytest.mark.parametrize("method,path", [
    ("post", "/api/admin/clear-all"),
    ("delete", "/api/cases/CASE-0001"),
    ("delete", "/api/sources/s1"),
    ("put", "/api/settings"),
    ("post", "/api/mcp/token"),
])
def test_cross_site_writes_are_refused(client, method, path):
    r = client.request(method.upper(), path, headers={"Origin": EVIL}, json={})
    assert r.status_code == 403
    assert "cross-site" in r.json()["detail"]


def test_the_form_post_that_wipes_the_workspace_is_refused(client):
    """`<form action="http://localhost:8000/api/admin/clear-all" method="POST">` is a SIMPLE request:
    no preflight, so CORS never gets a say, and the attacker does not need to read the reply. The only
    thing that stops it is refusing the body shape — no Iris client ever sends form-encoded."""
    r = client.post("/api/admin/clear-all",
                    headers={"Content-Type": "application/x-www-form-urlencoded"}, content=b"")
    assert r.status_code == 415
    r = client.post("/api/admin/clear-all", headers={"Content-Type": "text/plain"}, content=b"{}")
    assert r.status_code == 415


def test_sec_fetch_site_catches_a_write_with_no_origin_header(client):
    r = client.post("/api/admin/clear-all", headers={"Sec-Fetch-Site": "cross-site"}, json={})
    assert r.status_code == 403


def test_same_origin_and_non_browser_writes_still_work(client):
    """The whole point: curl, the MCP stdio bridge, Cursor and the SPA itself must be unaffected."""
    assert client.put("/api/settings", json={"theme": "graphite"}).status_code == 200          # no Origin
    assert client.put("/api/settings", json={"theme": "iris-dark"},
                      headers={"Origin": "http://testserver"}).status_code == 200              # same origin
    assert client.put("/api/settings", json={"theme": "iris-dark"},
                      headers={"Sec-Fetch-Site": "same-origin"}).status_code == 200


def test_reads_are_never_blocked_by_the_cross_site_guard(client):
    """A safe method cannot change evidence, and blocking it would break `<img>`-style embeds and
    anything that probes health. CORS is what stops the BODY being read; this guard is about writes."""
    assert client.get("/api/health", headers={"Origin": EVIL}).status_code == 200


# --------------------------------------------- S5 (b): DNS rebinding
def test_a_dns_name_that_is_not_this_machine_is_refused(client):
    """Rebinding `evil.example` to 127.0.0.1 makes the attacker's page SAME-origin with Iris, so every
    origin check passes by construction. Validating Host is the standard answer (and the one the MCP
    spec asks for). An IP literal cannot be rebound, so it stays allowed."""
    assert client.get("/api/case", headers={"Host": "evil.example"}).status_code == 403
    assert client.get("/api/case", headers={"Host": "192.168.1.5:8000"}).status_code == 200
    assert client.get("/api/case", headers={"Host": "[::1]:8000"}).status_code == 200
    assert client.get("/api/case", headers={"Host": "localhost:8000"}).status_code == 200


def test_a_reverse_proxy_hostname_can_be_allowed(monkeypatch, client):
    monkeypatch.setenv("IRIS_ALLOWED_HOSTS", "iris.company.internal")
    assert client.get("/api/case", headers={"Host": "iris.company.internal"}).status_code == 200
    assert client.get("/api/case", headers={"Host": "evil.example"}).status_code == 403


# --------------------------------------------- S5 (c): the optional local token
def test_no_token_by_default_means_nothing_changes(client):
    assert security.auth_token() == ""
    assert client.get("/api/case").status_code == 200


def test_the_token_gate_accepts_the_three_ways_a_real_client_has(monkeypatch, client):
    monkeypatch.setenv("IRIS_AUTH_TOKEN", "hunter2-token")
    assert client.get("/api/case").status_code == 401
    assert client.get("/api/case", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/case", headers={"Authorization": "Bearer hunter2-token"}).status_code == 200
    assert client.get("/api/case", headers={"X-Iris-Token": "hunter2-token"}).status_code == 200
    assert client.get("/api/case", headers={"Cookie": "iris_token=hunter2-token"}).status_code == 200


def test_the_token_gate_leaves_health_reachable(monkeypatch, client):
    """The container HEALTHCHECK and start.sh/start.ps1 both poll it. Gating it would make setting a
    token look like the app failed to come up."""
    monkeypatch.setenv("IRIS_AUTH_TOKEN", "hunter2-token")
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health").json()["ok"] is True


def test_the_token_gate_does_not_double_gate_the_mcp_endpoint(monkeypatch):
    """/api/mcp carries its own mandatory bearer token, so requiring IRIS_AUTH_TOKEN on top would mean
    two secrets for one door. Its UI helpers are NOT exempt — they hand out client configuration."""
    monkeypatch.setenv("IRIS_AUTH_TOKEN", "t")
    assert security.needs_token("/api/mcp") is False
    assert security.needs_token("/api/mcp/status") is True
    assert security.needs_token("/api/mcp/token") is True
    assert security.needs_token("/api/health") is False
    assert security.needs_token("/api/events") is True
    assert security.needs_token("/index.html") is False


def test_the_url_token_plants_a_locked_down_cookie(monkeypatch, client):
    """The whole of "logging in": open the app once at /?token=… . The cookie must be HttpOnly (a
    script must not be able to read the credential back out) and SameSite=strict (or it would be
    attached to cross-site requests and re-open the CSRF hole the Origin check just closed)."""
    from app.main import FRONTEND_DIST
    if not (FRONTEND_DIST / "index.html").exists():
        pytest.skip("frontend/dist not built — the SPA route is not mounted")
    monkeypatch.setenv("IRIS_AUTH_TOKEN", "hunter2-token")
    assert "set-cookie" not in client.get("/?token=wrong").headers
    r = client.get("/?token=hunter2-token")
    cookie = r.headers.get("set-cookie", "")
    assert "iris_token=hunter2-token" in cookie
    assert "httponly" in cookie.lower() and "samesite=strict" in cookie.lower()


# --------------------------------------------------------------------- S2: MCP
def test_mcp_enabled_without_a_token_serves_nothing(client):
    """VERIFIED live: `POST /api/mcp {"method":"tools/list"}` with no Authorization header returned
    HTTP 200 and all 26 tools. `enabled` + no token is no longer an accepted state."""
    update_settings({"mcp": {"enabled": True, "allowWrites": False, "token": ""}})
    try:
        r = client.post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 503
        assert "no bearer token" in r.json()["error"]["message"]
        assert "tools" not in r.text
        # ...and the same for a tool call, not only the listing
        r = client.post("/api/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                          "params": {"name": "count_events", "arguments": {}}})
        assert r.status_code == 503
    finally:
        update_settings({"mcp": {"enabled": False, "token": ""}})


def test_mcp_status_says_it_is_not_serving_and_why(client):
    update_settings({"mcp": {"enabled": True, "token": ""}})
    try:
        s = client.get("/api/mcp/status").json()
        assert s["enabled"] is True and s["serving"] is False
        assert "no bearer token" in s["blockedReason"]
        s2 = client.post("/api/mcp/token").json()
        assert len(s2["token"]) > 20
        s3 = client.get("/api/mcp/status").json()
        assert s3["serving"] is True and s3["blockedReason"] == ""
    finally:
        update_settings({"mcp": {"enabled": False, "token": ""}})


def test_mcp_status_never_hands_out_the_token(client):
    """It was returning the live token in cleartext in three places (cursor headers, the claudeCode
    command, the stdio bridge env) while masking a fourth copy of it — on an endpoint with no
    credential of its own. CLAUDE.md's rule is "in the clear exactly once", from POST /api/mcp/token."""
    update_settings({"mcp": {"enabled": True, "token": "s3cret-token-value"}})
    try:
        body = client.get("/api/mcp/status").text
        assert "s3cret-token-value" not in body
        s = json.loads(body)
        assert s["hasToken"] is True and "s3cret" not in s["token"]
        # the shape is still there, so the analyst can see an Authorization header is part of it
        assert "Authorization" in json.dumps(s["config"]["cursor"])
    finally:
        update_settings({"mcp": {"enabled": False, "token": ""}})


def test_removing_the_mcp_token_closes_the_server_rather_than_opening_it(client):
    """`PUT /api/settings {"mcp":{"token":""}}` is a deliberate removal (the UI has that button). It
    used to leave `enabled:true` answering everything unauthenticated."""
    update_settings({"mcp": {"enabled": True, "token": "abc123token"}})
    try:
        client.put("/api/settings", json={"mcp": {"token": ""}})
        assert get_settings().mcp.token == ""
        r = client.post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 503
    finally:
        update_settings({"mcp": {"enabled": False, "token": ""}})


# --------------------------------------------------------- path traversal on the case id
@pytest.mark.parametrize("raw", [
    "..%5C..%5C..%5CUsers",          # Windows: uvicorn unquotes before routing, %5C survives
    "C:%5CWindows",                  # drive-absolute join replaces the base entirely
    "%5C%5Cattacker.example%5Cshare",  # UNC — read_text() opens an outbound SMB connection (NTLM leak)
    "%2E%2E",                        # `..` — encoded, because an HTTP client normalises the bare form
    "CASE-1",                        # too short for the id shape
    "case-0001",                     # wrong case
])
def test_a_case_id_that_is_not_a_case_id_never_reaches_the_filesystem(client, raw):
    """`GET /api/cases/{id}` called summary() — which reads case.json and iterates uploads/ — BEFORE
    its `case_id not in case_ids()` guard. The fix is at the sink (config.case_path & friends), so it
    holds for every current and future caller, not just this route."""
    assert client.get(f"/api/cases/{raw}").status_code == 404


def test_the_path_helpers_refuse_a_bad_id_directly():
    for fn in (config.case_dir, config.upload_dir, config.attachment_dir, config.case_path):
        for bad in ("..", "../..", r"..\..", "C:\\Windows", r"\\host\share", "", "CASE-1", "x"):
            with pytest.raises(KeyError):
                fn(bad)
        assert "CASE-0007" in str(fn("CASE-0007"))


def test_the_case_id_shape_has_exactly_one_definition():
    from app import cases as cases_mod
    assert cases_mod._ID_RE is config.CASE_ID_RE


# --------------------------------------------------------- S3: the AI gateway, honestly reported
def test_tls_verification_is_on_for_a_fresh_install():
    from app.models import AISettings
    assert AISettings().verifyTls is True


def test_turning_tls_verification_off_is_reported_as_a_warning(client):
    """It cannot be reported by its absence: `verifyTls:false` is a checkbox nobody looks at again,
    and every objective, tool result and quoted log line goes over that connection."""
    update_settings({"ai": {"provider": "openai", "baseUrl": "https://10.0.0.109:3001/v1",
                            "verifyTls": False}})
    try:
        codes = [w["code"] for w in client.get("/api/settings").json()["security"]["warnings"]]
        assert "ai-tls-unverified" in codes
        update_settings({"ai": {"verifyTls": True}})
        codes = [w["code"] for w in client.get("/api/settings").json()["security"]["warnings"]]
        assert "ai-tls-unverified" not in codes
    finally:
        update_settings({"ai": {"provider": "none", "baseUrl": "", "verifyTls": True}})


def test_the_settings_response_states_the_posture(client):
    sec = client.get("/api/settings").json()["security"]
    assert sec["authRequired"] is False
    assert "*" not in sec["corsOrigins"]
    assert "no-auth" in [w["code"] for w in sec["warnings"]]


def test_the_posture_block_is_read_only(client):
    """It is derived, never persisted — echoing the whole settings object back on PUT must not store
    it or trip validation."""
    r = client.put("/api/settings", json=client.get("/api/settings").json())
    assert r.status_code == 200
    assert "security" not in json.loads(config.SETTINGS_PATH.read_text(encoding="utf-8"))


# --------------------------------------------------------- persistent SSRF via ai.baseUrl
@pytest.mark.parametrize("bad", [
    "http://127.0.0.1:8000/api/admin/clear-all?x=",   # the appended API path parks in the query
    "http://169.254.169.254/latest/meta-data/?x=",
    "https://api.openai.com/v1#frag",
    "file:///etc/passwd",
    "gopher://x/",
    "notaurl",
])
def test_a_base_url_that_would_change_which_request_is_made_is_refused(client, bad):
    """ai/client.py appends `/chat/completions` to this value, so a query string turns a settings write
    into "POST any path you like, including Iris's own wipe-everything endpoint". Rejecting a query or
    fragment removes that primitive. A private-IP blocklist deliberately is NOT used: the analyst's own
    gateway is on 10.0.0.109, and a control that refuses the real setup gets switched off."""
    r = client.put("/api/settings", json={"ai": {"baseUrl": bad}})
    assert r.status_code == 400
    assert get_settings().ai.baseUrl != bad


@pytest.mark.parametrize("good", ["", "https://api.openai.com/v1", "https://10.0.0.109:3001/v1",
                                  "http://localhost:11434/v1"])
def test_the_base_urls_analysts_actually_use_still_save(client, good):
    try:
        assert client.put("/api/settings", json={"ai": {"baseUrl": good}}).status_code == 200
        assert get_settings().ai.baseUrl == good
    finally:
        update_settings({"ai": {"baseUrl": ""}})


# --------------------------------------------------------- the middleware itself
def test_the_policy_is_a_pure_function():
    """check_request() takes headers and returns a verdict, so the whole policy is testable without a
    server — and so the middleware can stay raw ASGI (it must never wrap an SSE body)."""
    assert security.check_request("GET", "/api/case", {"host": "localhost:8000"}) is None
    assert security.check_request("POST", "/api/case", {"host": "localhost:8000",
                                                        "origin": EVIL})[0] == 403
    assert security.check_request("GET", "/api/case", {"host": "evil.example"})[0] == 403


def test_streaming_endpoints_are_not_wrapped():
    """SSE (the AI investigator, the graph review) must not sit behind a body-buffering middleware."""
    from starlette.middleware.base import BaseHTTPMiddleware
    assert not issubclass(security.SecurityMiddleware, BaseHTTPMiddleware)
    assert security.SecurityMiddleware in [m.cls for m in app.user_middleware]
    # outermost, so a refusal happens before CORSMiddleware can decorate the response
    assert app.user_middleware[0].cls is security.SecurityMiddleware


# ---------------------------------------------- the handover items: everything the API can reach
def test_a_ca_bundle_from_settings_cannot_point_outside_the_data_dir(tmp_path):
    """`ai.caBundle` is settable over an unauthenticated PUT and then handed to httpx as `verify`.
    An arbitrary absolute path made it an existence oracle for the whole filesystem — a path that
    exists fails differently from one that does not. Confining it to DATA_DIR keeps the real use
    (drop a corporate CA in the data dir) and removes the probe."""
    from app.ai.client import resolve_verify

    outside = tmp_path / "outside.pem"
    outside.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    assert resolve_verify(True, str(outside)) is True          # ignored, not honoured

    inside = config.DATA_DIR / "ca-test.pem"
    inside.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    try:
        assert resolve_verify(True, str(inside)) == str(inside)
        assert resolve_verify(True, "ca-test.pem") == str(inside)   # relative = relative to DATA_DIR
    finally:
        inside.unlink()


@pytest.mark.parametrize("escape", ["../outside.pem", "..", "/etc/ssl/cert.pem", r"C:\Windows\win.ini"])
def test_a_ca_bundle_that_escapes_is_dropped_not_followed(escape):
    from app.ai.client import _settings_ca_path
    assert _settings_ca_path(escape) == ""


def test_verification_off_still_wins_over_any_bundle():
    from app.ai.client import resolve_verify
    assert resolve_verify(False, "ca-test.pem") is False


def test_an_os_error_reaching_the_client_carries_no_server_path():
    """`str(OSError)` is `[Errno 2] ...: '/data/library/x.log'` — on a native install that is the
    analyst's user name and the data-dir layout, returned to an unauthenticated caller."""
    exc = FileNotFoundError(2, "No such file or directory")
    exc.filename = str(config.DATA_DIR / "library" / "dns.csv")
    msg = config.safe_os_error(exc)
    assert "dns.csv" in msg                       # the useful half is kept
    assert str(config.DATA_DIR) not in msg
    assert "library" not in msg


def test_the_raw_viewer_reports_a_missing_file_without_its_path(client):
    r = client.get("/api/sources/nope/raw")
    assert r.status_code in (404, 500)
    assert str(config.DATA_DIR) not in r.text


def test_a_library_name_naming_an_ntfs_stream_is_refused(client):
    """`report.log:hidden` is an alternate data stream OF another file, and it passes both the
    basename check and the resolved-parent check — the parent is still library/."""
    from app.routers.library import _library_path
    from fastapi import HTTPException

    for bad in ("x.log:hidden", "x.log:$DATA", ":stream"):
        with pytest.raises(HTTPException) as ei:
            _library_path(bad)
        assert ei.value.status_code == 400


_PLANTED_RAN: list = []


def _planted_payload():
    """Stands in for whatever an attacker would put in a pickle dropped into the data dir."""
    _PLANTED_RAN.append(True)
    return {}


class _Planted:
    def __reduce__(self):
        return (_planted_payload, ())


def test_the_graph_cache_refuses_a_file_this_install_did_not_write(tmp_path, monkeypatch):
    """The cache is a pickle in the bind-mounted data dir: a file dropped there is arbitrary code in
    the app process. A bad tag must be a cache MISS (rebuild), never a crash and never a load."""
    import pickle
    from app import graph_store

    monkeypatch.setattr(graph_store, "_KEY", None, raising=False)
    p = graph_store._path("all")
    p.parent.mkdir(parents=True, exist_ok=True)

    p.write_bytes(pickle.dumps({"format": graph_store.GRAPH_FORMAT, "sig": "s",
                                "nodes": [], "edges": [], "boom": _Planted()}))
    _PLANTED_RAN.clear()
    try:
        assert graph_store.load(object(), "all", "s") is None
        assert not _PLANTED_RAN                    # the payload never reached the unpickler
    finally:
        p.unlink(missing_ok=True)
        monkeypatch.setattr(graph_store, "_KEY", None, raising=False)


def test_the_graph_cache_seal_round_trips_and_a_single_edited_byte_fails():
    from app import graph_store
    blob = b"payload bytes"
    sealed = graph_store._seal(blob)
    assert graph_store._unseal(sealed) == blob
    torn = bytearray(sealed)
    torn[-1] ^= 0x01
    assert graph_store._unseal(bytes(torn)) is None
    assert graph_store._unseal(blob) is None       # unsigned = not ours


def test_restore_will_not_open_a_path_outside_the_data_dir(tmp_path):
    """`case.json` is data. Nothing sets an absolute path there today, but reading one as-is is one
    write primitive away from "any file on the host becomes searchable evidence"."""
    from app.store import _under_data_dir

    assert _under_data_dir(config.DATA_DIR / "cases" / "CASE-0001" / "uploads" / "a.log")
    assert not _under_data_dir(tmp_path / "secret.txt")
    assert not _under_data_dir(Path("/etc/passwd"))
