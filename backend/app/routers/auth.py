"""Login endpoints. See `app/auth.py` for why the credentials are stored the way they are.

Every path here is exempt from the gate itself (`security.OPEN_API_PREFIXES`) — a door behind its own
lock cannot be opened. That is exactly why the WRITE endpoints below check the session explicitly:
being outside the middleware's gate is not the same as being public, and `set` / `disable` / `clear`
change who can read the evidence pool.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from .. import auth

# The app mounts every router under an /api prefix, so this one declares only its own segment.
router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    password: str = ""
    pin: str = ""


class CredentialsBody(BaseModel):
    password: str = ""
    pin: str = ""
    enabled: bool = True


class EnabledBody(BaseModel):
    enabled: bool


def _client(request: Request) -> str:
    """Who is being throttled. The peer address, which for a local tool is the honest answer — there
    is no proxy chain to trust, and trusting X-Forwarded-For would let the attacker reset their own
    lockout by changing a header."""
    return request.client.host if request.client else "?"


def _authenticated(request: Request) -> bool:
    """A live UI session, or the headless shared token. Either is a caller who is already inside."""
    from .. import security

    cookie = request.headers.get("cookie", "")
    if auth.valid_session(auth.session_from_cookie(cookie)):
        return True
    token = security.auth_token()
    return bool(token) and security.token_matches({k.lower(): v for k, v in request.headers.items()}, cookie, token)


def _require_session(request: Request) -> None:
    """Guard for the credential writes.

    Open while NO login is configured — that is the first-run case, and requiring a session to create
    the first one is a deadlock. Once a login exists, changing it needs a session: otherwise anything
    that can reach the port could overwrite the password and lock the analyst out of their own case.
    """
    if auth.configured() and not _authenticated(request):
        raise HTTPException(401, "sign in first: changing the login needs a signed-in session")


def _set_cookie(response: Response, token: str) -> None:
    # HttpOnly: page script must never be able to read it. SameSite=strict: a cross-site request
    # cannot ride the session, which is the same reasoning as the CSRF guard in security.py.
    response.set_cookie(auth.COOKIE_NAME, token, httponly=True, samesite="strict",
                        max_age=auth.SESSION_TTL, path="/")


@router.get("/status")
def status(request: Request) -> dict:
    """What the SPA needs before it can decide to render a login page. Carries no credential."""
    st = auth.status()
    st["authenticated"] = (not st["enabled"]) or _authenticated(request)
    return st


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response) -> dict:
    try:
        token = auth.login(body.password, body.pin, client=_client(request))
    except auth.AuthError as exc:
        # 401, not 400: this is a rejected credential, and the SPA distinguishes them.
        raise HTTPException(401, str(exc))
    _set_cookie(response, token)
    return {"ok": True, **auth.status(), "authenticated": True}


@router.post("/logout")
def logout(request: Request, response: Response) -> dict:
    auth.end_session(auth.session_from_cookie(request.headers.get("cookie", "")))
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"ok": True}


@router.post("/credentials")
def set_credentials(body: CredentialsBody, request: Request, response: Response) -> dict:
    _require_session(request)
    try:
        st = auth.set_credentials(body.password, body.pin, enable=body.enabled)
    except auth.AuthError as exc:
        raise HTTPException(400, str(exc))
    # Sign the caller straight in. They just proved they know both secrets by choosing them, and
    # turning the gate on without a session would log the analyst out of the tab they are working in.
    token = auth.login(body.password, body.pin, client=_client(request))
    _set_cookie(response, token)
    return {"ok": True, **st, "authenticated": True}


@router.post("/enabled")
def set_enabled(body: EnabledBody, request: Request) -> dict:
    _require_session(request)
    try:
        return {"ok": True, **auth.set_enabled(body.enabled)}
    except auth.AuthError as exc:
        raise HTTPException(400, str(exc))


@router.delete("/credentials")
def clear_credentials(request: Request, response: Response) -> dict:
    """Remove the login completely. Needs a session — see `_require_session`. An analyst who has
    forgotten both secrets deletes `auth.json` from the data dir, which needs the disk access this
    control never claimed to defend against."""
    _require_session(request)
    st = auth.clear_credentials()
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"ok": True, **st}
