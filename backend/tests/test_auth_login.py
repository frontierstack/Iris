"""Password + PIN login — the analyst-facing answer to the `no-auth` warning.

`IRIS_AUTH_TOKEN` was the only existing control and it is the wrong shape for a person: it is set by
whoever starts the process, it is one shared secret, and there is no way to type it. These tests pin
the gate itself, the things that must stay reachable through it (or the app cannot be signed into),
and the two ways an over-eager gate would lock the analyst out of their own evidence.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import auth, config, security
from app.main import app

PW, PIN = "correct-horse", "482913"


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _no_login(monkeypatch):
    """Every test states its own posture, and none may leave a login behind — a stray auth.json would
    401 every other test module in the suite."""
    monkeypatch.delenv("IRIS_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(auth, "ITERATIONS", 1_000)      # the KDF is deliberately slow; not here
    auth.clear_credentials()
    # The lockout is keyed on the CLIENT ADDRESS and every TestClient shares one, so the throttle
    # test would otherwise lock out the tests that follow it — which is the control working, in the
    # wrong scope.
    auth._failures.clear()
    yield
    auth.clear_credentials()
    auth._failures.clear()
    (config.DATA_DIR / "auth.json").unlink(missing_ok=True)


def test_nothing_changes_until_a_login_is_configured(client):
    assert client.get("/api/case").status_code == 200
    st = client.get("/api/auth/status").json()
    assert st["enabled"] is False and st["configured"] is False and st["authenticated"] is True


def test_setting_both_credentials_gates_the_api(client):
    r = client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    assert r.status_code == 200 and r.json()["enabled"] is True
    # the caller who just set them is signed in — logging the analyst out of the tab they are
    # working in, at the moment they turn security on, is how a security feature gets turned off
    assert client.get("/api/case").status_code == 200

    with TestClient(app) as anon:
        assert anon.get("/api/case").status_code == 401
        assert anon.get("/api/events").status_code == 401


def test_the_login_endpoints_and_health_stay_reachable(client):
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    with TestClient(app) as anon:
        assert anon.get("/api/health").status_code == 200      # the container HEALTHCHECK
        assert anon.get("/api/auth/status").status_code == 200  # or the SPA cannot know to ask
        assert anon.get("/api/auth/status").json()["authenticated"] is False
        assert anon.post("/api/auth/login", json={"password": PW, "pin": PIN}).status_code == 200


def test_both_halves_are_required_and_the_refusal_does_not_say_which_was_wrong(client):
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    with TestClient(app) as anon:
        bad_pin = anon.post("/api/auth/login", json={"password": PW, "pin": "000000"})
        bad_pw = anon.post("/api/auth/login", json={"password": "nope-nope", "pin": PIN})
        assert bad_pin.status_code == 401 and bad_pw.status_code == 401
        assert bad_pin.json()["detail"] == bad_pw.json()["detail"]
        assert anon.get("/api/case").status_code == 401


def test_a_session_cookie_opens_the_gate_and_logout_closes_it(client):
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    with TestClient(app) as user:
        assert user.get("/api/case").status_code == 401
        assert user.post("/api/auth/login", json={"password": PW, "pin": PIN}).status_code == 200
        assert user.get("/api/case").status_code == 200          # the cookie rides along
        assert user.post("/api/auth/logout").status_code == 200
        assert user.get("/api/case").status_code == 401


def test_repeated_failures_are_throttled(client):
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    with TestClient(app) as anon:
        for _ in range(auth.LOCKOUT_AFTER):
            anon.post("/api/auth/login", json={"password": PW, "pin": "111111"})
        r = anon.post("/api/auth/login", json={"password": PW, "pin": PIN})   # the RIGHT credentials
        assert r.status_code == 401 and "try again in" in r.json()["detail"]


def test_a_half_configured_login_never_gates_anything():
    """`enabled` with only one credential would be an un-openable door. Both or nothing."""
    with pytest.raises(auth.AuthError):
        auth.set_credentials(PW, "", enable=True)
    with pytest.raises(auth.AuthError):
        auth.set_enabled(True)
    assert auth.enabled() is False


@pytest.mark.parametrize("pw,pin,why", [
    ("short", "123456", "too short"),
    ("long-enough-pw", "12", "PIN too short"),
    ("long-enough-pw", "abcd", "PIN not digits"),
    ("123456", "123456", "same value twice"),
])
def test_weak_credentials_are_refused(client, pw, pin, why):
    r = client.post("/api/auth/credentials", json={"password": pw, "pin": pin})
    assert r.status_code == 400, why
    assert auth.enabled() is False


def test_changing_the_login_needs_a_session(client):
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    with TestClient(app) as anon:
        # otherwise anything that can reach the port could overwrite the password and lock the
        # analyst out of their own case
        assert anon.post("/api/auth/credentials", json={"password": "attacker-pw", "pin": "999999"}).status_code == 401
        assert anon.post("/api/auth/enabled", json={"enabled": False}).status_code == 401
        assert anon.delete("/api/auth/credentials").status_code == 401
    assert client.delete("/api/auth/credentials").status_code == 200
    assert auth.enabled() is False


def test_the_stored_credentials_are_hashed_and_never_served(client):
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    raw = (config.DATA_DIR / "auth.json").read_text(encoding="utf-8")
    assert PW not in raw and PIN not in raw
    assert "pbkdf2-sha256" in raw
    for path in ("/api/settings", "/api/auth/status"):
        body = client.get(path).text
        assert PW not in body and PIN not in body and "hash" not in body


def test_the_posture_stops_warning_about_no_auth_once_a_login_is_set(client):
    codes = [w["code"] for w in client.get("/api/settings").json()["security"]["warnings"]]
    assert "no-auth" in codes
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    sec = client.get("/api/settings").json()["security"]
    assert "no-auth" not in [w["code"] for w in sec["warnings"]]
    assert sec["authRequired"] is True and sec["loginRequired"] is True and sec["tokenRequired"] is False


def test_the_headless_token_still_works_without_signing_in(monkeypatch, client):
    """Two doors to the same room: a script carrying IRIS_AUTH_TOKEN must not be asked for a person's
    password as well."""
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    monkeypatch.setenv("IRIS_AUTH_TOKEN", "headless-secret")
    with TestClient(app) as script:
        assert script.get("/api/case").status_code == 401
        assert script.get("/api/case", headers={"Authorization": "Bearer headless-secret"}).status_code == 200


def test_the_mcp_endpoint_keeps_its_own_credential(client):
    """/api/mcp carries a mandatory token of its own; requiring the UI login on top would be two
    secrets for one door, and Cursor cannot sign in."""
    client.post("/api/auth/credentials", json={"password": PW, "pin": PIN})
    assert security.check_request("POST", "/api/mcp", {"host": "localhost:8000"}) is None
    assert security.check_request("GET", "/api/case", {"host": "localhost:8000"})[0] == 401
