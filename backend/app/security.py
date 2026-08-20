"""Network-facing hardening for a single-analyst local forensics tool.

Iris has no user model and does not want one: it is one analyst, one machine, one evidence pool. But
"no auth" was being read as "no exposure", and it is not — the process listens on a TCP port that the
analyst's own browser can reach, and a browser will happily make requests to localhost on behalf of
whatever page is open in another tab. Three distinct holes, three distinct answers, none of which is a
login screen:

1. **Reading the evidence cross-origin.** `Access-Control-Allow-Origin: *` on an unauthenticated API
   means any page the analyst visits can `fetch('http://localhost:8000/api/events?q=')` and read the
   body. The wildcard is the whole vulnerability — no credential is needed, because none is required.
   Fixed by `cors_origins()`: the SPA is served from the SAME origin and therefore needs no CORS entry
   at all; only the Vite dev server does. Never `*`.

2. **Firing destructive requests cross-site (CSRF).** Locking CORS down does NOT stop the request being
   *sent* — it only stops the response being *read*. `POST /api/admin/clear-all` takes an optional body,
   so `<form action="http://localhost:8000/api/admin/clear-all" method="POST">` submitted from any page
   wipes the workspace, and the attacker never needs to see the reply. Fixed by `check_request()`:
   an unsafe method (POST/PUT/PATCH/DELETE) carrying a foreign `Origin` is refused. Browsers send
   `Origin` on every such request, including form posts and `mode:'no-cors'` fetches; non-browser
   clients (curl, the MCP stdio bridge, Cursor, Claude Code) send none and are unaffected.

3. **DNS rebinding.** An attacker who controls `evil.example` can point it at 127.0.0.1, at which point
   their page is SAME-origin with Iris and every check above passes by construction. The standard
   defence — and the one the MCP spec asks for explicitly — is to validate the `Host` header. Iris
   refuses a `Host` that is a DNS *name* it does not recognise, while allowing every IP literal: a
   rebinding attack needs a name, and an analyst reaching the box at `192.168.1.5:8000` uses a literal.
   `IRIS_ALLOWED_HOSTS` adds names for anyone running behind a reverse proxy.

4. **Anything that can reach the port.** The three above are about a browser. A shared machine, a LAN,
   or a published Docker port is about anything at all. The baseline answer is to bind to loopback
   (docker-compose publishes `127.0.0.1:8000` and `start.* local` binds 127.0.0.1); the real answer for
   anyone who deliberately exposes it is `IRIS_AUTH_TOKEN`, an opt-in shared secret. It is deliberately
   NOT a login system: one env var, accepted as `Authorization: Bearer`, `X-Iris-Token`, or the cookie
   the app sets when you open `http://host:8000/?token=…` once. The SPA needs no code change because
   same-origin fetches carry the cookie on their own.

Everything here is a pure function plus one raw-ASGI middleware. Raw ASGI, not `BaseHTTPMiddleware`,
because the AI investigator and the graph review stream SSE and a body-wrapping middleware is exactly
the wrong thing to put in front of a long-lived stream.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
from typing import Iterable, Optional

from . import auth
from urllib.parse import urlsplit

# Methods that cannot change state. A cross-site GET is a CORS problem (finding 1), not a CSRF one.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Reachable without the token when one is set.
#   /api/health   — the container HEALTHCHECK and the thing start.sh/start.ps1 poll to decide the app
#                   came up. It returns {"ok", "version"} and no evidence.
#   /api/mcp      — the MCP endpoint carries its OWN mandatory bearer token (routers/mcp.py refuses to
#                   serve without one), so requiring IRIS_AUTH_TOKEN on top means two secrets for one
#                   door. Deliberately NOT a prefix: /api/mcp/status and /api/mcp/token are UI
#                   endpoints that hand out client configuration, and they stay behind the gate.
#   /api/auth/*   — the login endpoints themselves. A gate whose door is behind the gate cannot be
#                   opened: the SPA has to be able to ask whether a login is required, and post one.
OPEN_API_PATHS = frozenset({"/api/health", "/api/mcp"})
OPEN_API_PREFIXES = ("/api/auth/",)

DEV_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")

# Host names that are always this machine. Everything else must be an IP literal or be named in
# IRIS_ALLOWED_HOSTS — see the DNS-rebinding note above.
LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "testserver", "iris"})


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


def _normalise_origin(value: str) -> str:
    """`HTTP://LocalHost:8000/` and `http://localhost:8000` are the same origin."""
    v = value.strip().rstrip("/")
    if not v:
        return ""
    parts = urlsplit(v if "//" in v else f"//{v}")
    scheme = (parts.scheme or "http").lower()
    netloc = (parts.netloc or parts.path).lower()
    return f"{scheme}://{netloc}"


def cors_origins() -> list[str]:
    """Origins allowed to read a cross-origin response.

    Default: the app's own ports on loopback plus the Vite dev server. The SPA is same-origin and needs
    none of these — this list exists for `npm run dev`. `IRIS_CORS_ORIGINS` replaces it entirely
    (comma-separated). A literal `*` is refused: the wildcard on an unauthenticated API is finding 1.
    """
    configured = _env_list("IRIS_CORS_ORIGINS")
    if configured:
        out = [_normalise_origin(o) for o in configured if _normalise_origin(o) and o.strip() != "*"]
        if out:
            return out
    port = os.environ.get("IRIS_PORT", "8000").strip() or "8000"
    origins = [f"http://localhost:{port}", f"http://127.0.0.1:{port}", *DEV_ORIGINS]
    seen: dict[str, None] = {}
    for o in origins:
        seen.setdefault(_normalise_origin(o), None)
    return list(seen)


def auth_token() -> str:
    """The optional shared secret. Unset (the default) = no token gate; loopback binding is the baseline."""
    return os.environ.get("IRIS_AUTH_TOKEN", "").strip()


def allowed_hosts() -> list[str]:
    return [h.lower() for h in _env_list("IRIS_ALLOWED_HOSTS")]


def _host_name(host_header: str) -> str:
    """Strip the port (and IPv6 brackets) from a Host header value."""
    h = (host_header or "").strip().lower()
    if not h:
        return ""
    if h.startswith("["):                       # [::1]:8000
        return h[1:].split("]", 1)[0]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def host_is_allowed(host_header: str) -> bool:
    name = _host_name(host_header)
    if not name:
        return True                             # HTTP/1.0 or a synthetic ASGI scope; nothing to rebind
    if name in LOOPBACK_NAMES or name in allowed_hosts():
        return True
    try:
        ipaddress.ip_address(name)              # an IP literal cannot be the target of DNS rebinding
        return True
    except ValueError:
        return False


def _self_origins(host_header: str) -> set[str]:
    h = (host_header or "").strip().lower()
    return {f"http://{h}", f"https://{h}"} if h else set()


def origin_is_allowed(origin: str, host_header: str) -> bool:
    o = _normalise_origin(origin)
    if not o:
        return True                             # no Origin at all = not a browser; curl and MCP clients
    return o in set(cors_origins()) or o in _self_origins(host_header)


COOKIE_NAME = "iris_token"


def constant_eq(a: str, b: str) -> bool:
    """compare_digest raises TypeError on a non-ASCII str, and header values are decoded latin-1 —
    so a header full of high bytes would otherwise be a 500 rather than a refusal."""
    if not a or not b:
        return False
    try:
        return secrets.compare_digest(a, b)
    except TypeError:
        return False


def _token_presented(headers: dict[str, str], cookie_header: str) -> list[str]:
    out: list[str] = []
    auth = (headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        out.append(auth[7:].strip())
    x = (headers.get("x-iris-token") or "").strip()
    if x:
        out.append(x)
    for part in (cookie_header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE_NAME and v:
            out.append(v.strip())
    return out


def token_matches(headers: dict[str, str], cookie_header: str, token: str) -> bool:
    return any(constant_eq(c, token) for c in _token_presented(headers, cookie_header))


def needs_token(path: str) -> bool:
    if not path.startswith("/api/") and path != "/api":
        return False
    if any(path.startswith(pre) for pre in OPEN_API_PREFIXES):
        return False
    return path.rstrip("/") not in OPEN_API_PATHS


# Body types a browser can post cross-site with NO preflight. No Iris client ever sends them: the SPA
# sends application/json, and uploads send multipart/form-data. Refusing them is what closes the
# `<form action="http://localhost:8000/api/admin/clear-all" method="POST">` hole even if CORS regresses.
UNPREFLIGHTED_BODY_TYPES = ("application/x-www-form-urlencoded", "text/plain")


def _cross_site(headers: dict[str, str], host: str, origin: str) -> Optional[str]:
    """Is this request coming from another site? Returns the reason, or None if it is not."""
    if origin:
        # An Origin that IS allowed settles it. Checking Sec-Fetch-Site as well would refuse the Vite
        # dev server, which the browser labels `same-site` (different port, same registrable domain).
        return None if origin_is_allowed(origin, host) else f"Origin {origin}"
    # No Origin at all is either a non-browser client (curl, the MCP bridge, Cursor) or a browser
    # request shape that omits it. Sec-Fetch-Site is the fallback that still catches the second case.
    site = (headers.get("sec-fetch-site") or "").strip().lower()
    if site in ("cross-site", "same-site"):
        return f"Sec-Fetch-Site: {site}"
    return None


def check_request(method: str, path: str, headers: dict[str, str]) -> Optional[tuple[int, str]]:
    """The whole policy, as one pure function. Returns (status, message) to refuse, or None to allow.

    Order matters: Host first (a rebound name makes every later check pass by construction), then the
    cross-site checks, then the token. Each refusal names what to change — a 403 with no explanation on
    a tool the analyst runs themselves is a bug report, not a security control.
    """
    method = method.upper()
    host = headers.get("host", "")
    origin = headers.get("origin", "")
    if not host_is_allowed(host):
        return (403, f"refusing a request for host {_host_name(host)!r}: Iris answers on localhost and on "
                     f"IP addresses only, because a DNS name that resolves to this machine is how a "
                     f"rebinding attack reaches a local tool. Add it to IRIS_ALLOWED_HOSTS if this is "
                     f"your own reverse proxy.")

    # The PREFLIGHT is the request that decides whether a hostile page may send a DELETE at all, so it
    # is checked here as well as by CORSMiddleware. A fix that only sets allow_origins is one config
    # edit away from handing `access-control-allow-methods: DELETE, …` back to evil.example again.
    if method == "OPTIONS":
        asked = (headers.get("access-control-request-method") or "").strip().upper()
        if asked and asked not in SAFE_METHODS and origin and not origin_is_allowed(origin, host):
            return (403, f"preflight for a cross-site {asked} from {origin} refused: Iris never grants "
                         f"another origin permission to change or delete evidence.")
        return None

    if method not in SAFE_METHODS:
        reason = _cross_site(headers, host, origin)
        if reason:
            return (403, f"cross-site {method} refused ({reason}). Iris is an unauthenticated local "
                         f"tool, so a request from another site is never legitimate. Set "
                         f"IRIS_CORS_ORIGINS if you are serving the UI from a different origin.")
        if path.startswith("/api/"):
            ctype = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if ctype in UNPREFLIGHTED_BODY_TYPES:
                return (415, f"{ctype} is not accepted on {path}. A browser can post that body shape to "
                             f"another site without asking permission first, which is how a page the "
                             f"analyst merely visits could reach a destructive endpoint. Iris clients "
                             f"send application/json (or multipart/form-data to upload).")

    token = auth_token()
    if token and needs_token(path):
        cookie = headers.get("cookie", "")
        if not token_matches(headers, cookie, token):
            return (401, "IRIS_AUTH_TOKEN is set on this instance. Send it as 'Authorization: Bearer "
                         "<token>' or 'X-Iris-Token: <token>', or open the UI once at "
                         "http://<host>:<port>/?token=<token> to set the session cookie.")

    # The UI login (password + PIN, set in Settings). Checked AFTER the shared token so a headless
    # client that already carries IRIS_AUTH_TOKEN is not asked for a person's credentials as well —
    # they are two doors to the same room, for two different kinds of caller.
    if needs_token(path) and auth.enabled():
        cookie = headers.get("cookie", "")
        if not (token and token_matches(headers, cookie, token)):
            if not auth.valid_session(auth.session_from_cookie(cookie)):
                return (401, "sign in to Iris: this instance is protected by a password and a PIN "
                             "(Settings -> Security). POST /api/auth/login to get a session.")
    return None


class SecurityMiddleware:
    """Raw-ASGI: it either refuses with a short JSON body or hands the scope straight through, so it
    never touches a streaming response (SSE) the way a BaseHTTPMiddleware body wrapper would."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers") or []}
        verdict = check_request(scope.get("method", "GET"), scope.get("path", "/"), headers)
        if verdict is None:
            return await self.app(scope, receive, send)
        status, message = verdict
        # {"detail": …} is the shape FastAPI uses for HTTPException, and the shape the frontend's
        # parseError() already reads — a refusal from the middleware must not look different in the UI
        # from a refusal from a route.
        body = json.dumps({"detail": message}).encode()
        response_headers = [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]
        if status == 401:
            response_headers.append((b"www-authenticate", b"Bearer"))
        await send({"type": "http.response.start", "status": status, "headers": response_headers})
        await send({"type": "http.response.body", "body": body})


# ------------------------------------------------------------------ posture, for the UI and the log
def security_posture() -> dict[str, object]:
    """What is actually protecting this instance, as data. The Settings panel renders it and the
    startup banner prints it: a hardening measure nobody can see is one nobody maintains."""
    from .config import get_settings          # lazy: config imports this module for public_settings()

    s = get_settings()
    token = auth_token()
    warnings: list[dict[str, str]] = []

    login_on = auth.enabled()
    if not token and not login_on:
        warnings.append({
            "code": "no-auth",
            "message": "Iris has no authentication. Anything that can reach this port can read every "
                       "ingested log and delete every case. Set a password and PIN in Settings -> "
                       "Security, or set IRIS_AUTH_TOKEN for headless clients.",
        })
    elif login_on and not token:
        # Worth stating rather than staying silent: the UI is gated, but a client that speaks to the
        # API directly (curl, a script, the MCP bridge) still needs IRIS_AUTH_TOKEN to be kept out —
        # and the login cookie is not a credential such a client can obtain.
        warnings.append({
            "code": "auth-ui-only",
            "message": "The UI is protected by a password and PIN. API clients are covered by the same "
                       "session cookie; set IRIS_AUTH_TOKEN as well if scripts or other tools need to "
                       "reach this instance without signing in.",
        })
    if s.mcp.enabled and not s.mcp.token:
        warnings.append({
            "code": "mcp-no-token",
            "message": "The MCP server is enabled with no bearer token, so it refuses every request. "
                       "Generate a token to actually serve outside agents.",
        })
    if s.ai.provider != "none" and s.ai.baseUrl.lower().startswith("https://") and not s.ai.verifyTls:
        warnings.append({
            "code": "ai-tls-unverified",
            "message": f"TLS certificate verification is OFF for {s.ai.baseUrl}. Every objective, every "
                       f"tool result and every quoted log line is sent over a connection that cannot "
                       f"tell that host from anyone on the path who answers for it. Supply the real "
                       f"certificate as ai.caBundle (or /data/ca.pem, or $IRIS_CA_BUNDLE) instead.",
        })
    return {
        "authRequired": bool(token) or auth.enabled(),
        "loginRequired": auth.enabled(),          # the UI password+PIN specifically
        "tokenRequired": bool(token),             # the headless shared secret specifically
        "corsOrigins": cors_origins(),
        "allowedHosts": allowed_hosts(),
        "mcpServing": bool(s.mcp.enabled and s.mcp.token),
        "warnings": warnings,
    }


def startup_banner() -> list[str]:
    posture = security_posture()
    mode = 'token+login' if posture['tokenRequired'] and posture['loginRequired'] else (
        'token' if posture['tokenRequired'] else ('login' if posture['loginRequired'] else 'none'))
    lines = [f"[iris] security: auth={mode} "
             f"cors={','.join(cors_origins())}"]
    for w in posture["warnings"]:            # type: ignore[union-attr]
        lines.append(f"[iris] WARNING ({w['code']}): {w['message']}")
    return lines
