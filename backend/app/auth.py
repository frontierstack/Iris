"""Password + PIN login for the UI — the answer to "Iris has no authentication".

`IRIS_AUTH_TOKEN` already existed and stays: it is the HEADLESS credential, meant for curl, the MCP
bridge and a reverse proxy, and it is set by whoever starts the process. It is the wrong shape for a
person, which is why the warning kept being read as "there is nothing I can do about this". This
module is the other half: two secrets the analyst sets in Settings and types on a login page.

Decisions worth keeping, each because the alternative is worse:

* **Two factors of the same kind is a deliberate choice, not confusion with real MFA.** The analyst
  asked for a password AND a PIN and both are required. It is not a second *channel* — anyone who can
  read one stored credential can read the other — so this defends against shoulder-surfing and a
  guessed password, not against a compromised host. Say that plainly rather than implying otherwise.
* **Hashed with PBKDF2-HMAC-SHA256, stdlib only.** scrypt/argon2 are better, but argon2 is a new
  dependency in a 5.5 GB image and `hashlib.scrypt` needs an OpenSSL build that is not guaranteed
  where this runs. 600k iterations, a per-credential 16-byte salt, `compare_digest` for the verify.
* **Never in settings.json.** `GET /api/settings` is the most-fetched endpoint in the app and its
  masking rules are already subtle. The hashes live in their own file, 0600 where the OS allows it,
  and NOTHING serves it — the API exposes only `enabled` and "is a credential set".
* **Sessions are in memory.** A restart logs everyone out, which for a local evidence tool is the
  right default: the session cannot outlive the process that holds the pool. The cookie is HttpOnly,
  SameSite=strict and (by construction) unreadable by page script.
* **Failed attempts are throttled per client.** A 4-6 digit PIN is guessable in minutes otherwise.
  The lockout grows with consecutive failures and is stated in the refusal, because a control that
  silently stops answering reads as a broken app.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any, Optional

from . import config

# --- tuning -----------------------------------------------------------------------------------
ITERATIONS = 600_000          # PBKDF2-HMAC-SHA256 rounds; ~0.2 s on this class of machine
SALT_BYTES = 16
SESSION_TTL = 12 * 3600       # a working day; the process holds the evidence, not the browser
COOKIE_NAME = "iris_session"
MIN_PASSWORD = 8
MIN_PIN = 4
MAX_PIN = 12
LOCKOUT_AFTER = 5             # consecutive failures before the first delay
LOCKOUT_STEPS = (30, 60, 300, 900)   # seconds, then the last one repeats

_lock = threading.Lock()
_sessions: dict[str, float] = {}          # token -> expiry (monotonic)
_failures: dict[str, tuple[int, float]] = {}   # client -> (consecutive failures, locked-until)


class AuthError(ValueError):
    """A credential that cannot be accepted, with the reason the analyst needs to fix it."""


# --- storage ----------------------------------------------------------------------------------
def _path():
    return config.DATA_DIR / "auth.json"


_cache: tuple[float, int, dict[str, Any]] = (-1.0, -1, {})


def _read() -> dict[str, Any]:
    """auth.json, memoised on its own (mtime, size).

    `security.check_request` asks `enabled()` on EVERY request, so an unconditional read would put a
    file open + JSON parse in front of every search, every poll and every SSE token. One stat is the
    price instead, and a change made by another process (an analyst deleting the file to get back in)
    is still picked up on its next request rather than needing a restart.
    """
    global _cache
    p = _path()
    try:
        st = p.stat()
        key = (st.st_mtime, st.st_size)
    except OSError:
        _cache = (-1.0, -1, {})
        return {}
    if (_cache[0], _cache[1]) == key:
        return _cache[2]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        data = data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        data = {}
    _cache = (key[0], key[1], data)
    return data


def _write(data: dict[str, Any]) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass          # Windows / bind mounts: best effort. The hash is the control, not the mode.
    os.replace(tmp, p)
    global _cache
    _cache = (-1.0, -1, {})     # the next read re-stats; a same-second write must never be missed


def _hash(value: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, ITERATIONS).hex()


def _record(value: str) -> dict[str, str]:
    salt = secrets.token_bytes(SALT_BYTES)
    return {"salt": salt.hex(), "hash": _hash(value, salt), "algo": "pbkdf2-sha256", "iter": str(ITERATIONS)}


def _verify(value: str, rec: Any) -> bool:
    if not isinstance(rec, dict) or not value:
        return False
    try:
        salt = bytes.fromhex(str(rec.get("salt") or ""))
        iters = int(rec.get("iter") or ITERATIONS)
    except ValueError:
        return False
    if not salt:
        return False
    want = str(rec.get("hash") or "")
    got = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, iters).hex()
    return hmac.compare_digest(got, want)


# --- state ------------------------------------------------------------------------------------
def enabled() -> bool:
    """True when a login is required. Both credentials must exist — a half-configured gate would
    otherwise lock the analyst out of their own evidence with no way back in."""
    d = _read()
    return bool(d.get("enabled")) and bool(d.get("password")) and bool(d.get("pin"))


def configured() -> bool:
    d = _read()
    return bool(d.get("password")) and bool(d.get("pin"))


def status() -> dict[str, Any]:
    d = _read()
    return {"enabled": bool(d.get("enabled")) and bool(d.get("password")) and bool(d.get("pin")),
            "configured": bool(d.get("password")) and bool(d.get("pin")),
            "minPassword": MIN_PASSWORD, "minPin": MIN_PIN, "maxPin": MAX_PIN}


def set_credentials(password: str, pin: str, enable: bool = True) -> dict[str, Any]:
    """Store both credentials and (by default) turn the gate on. Both are required together: setting
    only one would leave `enabled` unreachable, and rotating only the password silently keeps an old
    PIN the analyst believes they replaced."""
    password, pin = (password or "").strip(), (pin or "").strip()
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"the password must be at least {MIN_PASSWORD} characters")
    if not pin.isdigit():
        raise AuthError("the PIN must be digits only")
    if not (MIN_PIN <= len(pin) <= MAX_PIN):
        raise AuthError(f"the PIN must be {MIN_PIN} to {MAX_PIN} digits")
    if pin == password:
        raise AuthError("the PIN and the password must not be the same")
    _write({"enabled": bool(enable), "password": _record(password), "pin": _record(pin),
            "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    return status()


def set_enabled(on: bool) -> dict[str, Any]:
    d = _read()
    if on and not (d.get("password") and d.get("pin")):
        raise AuthError("set a password and a PIN before turning the login on")
    d["enabled"] = bool(on)
    _write(d)
    if not on:
        clear_sessions()      # the gate is down; a stale session is meaningless either way
    return status()


def clear_credentials() -> dict[str, Any]:
    """Remove the login entirely. Deliberately reachable only from an AUTHENTICATED session (see the
    router): 'forgot the password' is answered by deleting auth.json on the host, which requires the
    disk access that this control was never meant to defend against."""
    _write({})
    clear_sessions()
    return status()


# --- login ------------------------------------------------------------------------------------
def _lock_state(client: str) -> float:
    """Seconds still to wait for this client, 0 when it may try."""
    with _lock:
        fails, until = _failures.get(client, (0, 0.0))
    return max(0.0, until - time.monotonic())


def _note_failure(client: str) -> float:
    with _lock:
        fails, _ = _failures.get(client, (0, 0.0))
        fails += 1
        wait = 0.0
        if fails >= LOCKOUT_AFTER:
            step = min(fails - LOCKOUT_AFTER, len(LOCKOUT_STEPS) - 1)
            wait = float(LOCKOUT_STEPS[step])
        _failures[client] = (fails, time.monotonic() + wait)
        return wait


def _note_success(client: str) -> None:
    with _lock:
        _failures.pop(client, None)


def login(password: str, pin: str, client: str = "") -> str:
    """A session token, or raise AuthError. BOTH credentials are checked every time, and the same
    message comes back whichever one was wrong — telling an attacker which half they got right halves
    the work for free."""
    wait = _lock_state(client)
    if wait > 0:
        raise AuthError(f"too many failed attempts — try again in {int(wait) + 1}s")
    d = _read()
    ok_pw = _verify(password or "", d.get("password"))
    ok_pin = _verify(pin or "", d.get("pin"))
    if not (ok_pw and ok_pin):
        wait = _note_failure(client)
        msg = "the password or the PIN is wrong"
        raise AuthError(f"{msg} — too many attempts, locked for {int(wait)}s" if wait else msg)
    _note_success(client)
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = time.monotonic() + SESSION_TTL
        _prune_locked()
    return token


def valid_session(token: str) -> bool:
    if not token:
        return False
    with _lock:
        exp = _sessions.get(token)
        if exp is None:
            return False
        if exp < time.monotonic():
            _sessions.pop(token, None)
            return False
        return True


def end_session(token: str) -> None:
    with _lock:
        _sessions.pop(token, None)


def clear_sessions() -> None:
    with _lock:
        _sessions.clear()


def _prune_locked() -> None:
    now = time.monotonic()
    for t in [t for t, exp in _sessions.items() if exp < now]:
        _sessions.pop(t, None)


def session_from_cookie(cookie_header: str) -> str:
    for part in (cookie_header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE_NAME and v:
            return v.strip()
    return ""
