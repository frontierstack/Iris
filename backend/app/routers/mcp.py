"""Iris as an MCP server — the same tools the built-in investigator uses, offered to OUTSIDE agents
(Cursor, Claude Code, Claude Desktop, anything that speaks Model Context Protocol).

Design decisions, each of which has an alternative that looked easier and is worse:

* **The tool surface is `ai/tools.REGISTRY`, not a second implementation.** Everything the internal
  agent can do — search, aggregate, timeline, graph, detections, case curation — is already defined
  there with a JSON Schema, argument validation, citation checks and provenance. Re-declaring tools
  here would give an external model a different view of the same evidence, which is the one thing the
  whole tools module exists to prevent.
* **Transport is Streamable HTTP on the port the app already serves** (`POST /api/mcp`), not a stdio
  sidecar process. A stdio server would need its own interpreter, and it would build its OWN event
  pool — 1.2M events parsed twice, and two answers to the same question. Clients that only speak
  stdio use the tiny bridge in `mcp/iris-mcp-stdio.py`, which forwards to this endpoint.
* **No new dependency.** This is JSON-RPC 2.0 over one POST; the spec explicitly allows a single JSON
  response instead of an SSE stream when the server has nothing to push. Adding the MCP SDK to a
  5.5 GB CUDA image for ~150 lines of dispatch was not a good trade.
* **Off by default, writes off separately** (`settings.mcp`). Enabling it hands a remote model the
  analyst's whole evidence pool; `allowWrites` is a second switch because a read cannot change a case
  and a write can. A bearer token can be required on top.
* **Writes are attributed and undoable, exactly like the internal agent's.** Each call runs in a
  `RunContext` whose model name says which MCP client made it, so an IOC added from Cursor reads as
  `AI assistant (MCP: cursor)` in case.json rather than appearing from nowhere.
"""
from __future__ import annotations

import secrets
from typing import Any, Optional

import orjson
from fastapi import APIRouter, Body, Header, Request, Response

from .. import config
from ..ai.tools import REGISTRY, RunContext, ToolError
from ..config import VERSION, get_settings, update_settings

router = APIRouter(prefix="/mcp", tags=["mcp"])

# Protocol revisions this server knows how to answer. We echo the client's version when we know it and
# otherwise answer with our newest — a client that asked for something unknown still gets a usable
# server rather than a handshake failure.
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL = SUPPORTED_PROTOCOLS[0]

SERVER_INSTRUCTIONS = (
    "Iris is a log parser and correlation workbench. Its event pool spans every ingested source; a CASE "
    "is optional curation on top. Start with get_case_state and list_event_fields, then search_events / "
    "aggregate_events to answer questions with exact counts rather than by sampling rows. "
    "Every write tool requires citedEventIds naming real events — a fabricated id is refused."
)


# --------------------------------------------------------------------- helpers
def _err(rpc_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": rpc_id, "error": error}


def _ok(rpc_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def exposed_tools(allow_writes: bool) -> list[Any]:
    return [t for t in REGISTRY.values() if allow_writes or not t.writes]


def _tool_descriptor(t: Any) -> dict[str, Any]:
    d = {
        "name": t.name,
        "description": t.description,
        "inputSchema": {"type": "object", "properties": t.properties,
                        "required": t.required, "additionalProperties": False},
    }
    if t.writes:
        # readOnlyHint/destructiveHint are the MCP annotations a client uses to decide what to
        # auto-approve. Iris writes are additive curation, never destructive — say both.
        d["annotations"] = {"title": t.name, "readOnlyHint": False, "destructiveHint": False,
                            "idempotentHint": False, "openWorldHint": False}
    else:
        d["annotations"] = {"title": t.name, "readOnlyHint": True, "openWorldHint": False}
    return d


def _client_label(info: Any) -> str:
    if isinstance(info, dict):
        name = str(info.get("name") or "").strip()
        if name:
            return name[:60]
    return "unknown client"


def _authorised(authorization: Optional[str], token: str) -> bool:
    """A token is now MANDATORY (see `_serving_block`), so this is only ever called with one set. It
    still refuses an empty token rather than returning True: 'no token configured' must never be the
    thing that makes an unauthenticated request succeed."""
    if not token:
        return False
    value = (authorization or "").strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    return secrets.compare_digest(value, token)


def _serving_block(s: Any) -> Optional[str]:
    """Why this server is not answering, or None if it is.

    `enabled` with no token used to be an accepted state, and it served every read tool in the registry
    to anything that could reach the port — verified live on the analyst's own instance. Reads are the
    sensitive asset in a forensics tool, so `allowWrites:false` is not the mitigation it looks like.
    The switch now FAILS CLOSED: enabling the server is a decision to expose the pool, and a decision to
    expose the pool has to come with the credential that scopes it.
    """
    if not s.mcp.enabled:
        return "the Iris MCP server is disabled (Settings → MCP server)"
    if not s.mcp.token:
        return ("the Iris MCP server is enabled but has no bearer token, so it refuses every request. "
                "Generate one in Settings → MCP server (or set IRIS_MCP_TOKEN) and put it in your "
                "client's Authorization header. Iris has no other authentication, so an untokened MCP "
                "endpoint hands the whole evidence pool to anything that can reach this port.")
    return None


# --------------------------------------------------------------------- dispatch
def _handle(msg: dict[str, Any], allow_writes: bool, state: dict[str, Any]) -> Optional[dict[str, Any]]:
    """One JSON-RPC message → one response, or None for a notification (which gets no reply)."""
    rpc_id = msg.get("id")
    method = str(msg.get("method") or "")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    is_notification = "id" not in msg

    if method.startswith("notifications/"):
        return None

    if method == "initialize":
        asked = str(params.get("protocolVersion") or "")
        state["client"] = _client_label(params.get("clientInfo"))
        return _ok(rpc_id, {
            "protocolVersion": asked if asked in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "iris", "title": "Iris — log parser & correlation workbench",
                           "version": VERSION},
            "instructions": SERVER_INSTRUCTIONS,
        })

    if method == "ping":
        return _ok(rpc_id, {})

    if method == "tools/list":
        return _ok(rpc_id, {"tools": [_tool_descriptor(t) for t in exposed_tools(allow_writes)]})

    # Iris exposes tools only. Answering these with an empty list instead of "method not found" keeps
    # clients that probe every capability quiet in the log.
    if method in ("resources/list", "resources/templates/list"):
        return _ok(rpc_id, {"resources": [], "resourceTemplates": []})
    if method == "prompts/list":
        return _ok(rpc_id, {"prompts": []})

    if method == "tools/call":
        name = str(params.get("name") or "")
        args = params.get("arguments")
        if not isinstance(args, dict):
            args = {}
        tool = REGISTRY.get(name)
        if tool is None or (tool.writes and not allow_writes):
            known = ", ".join(sorted(t.name for t in exposed_tools(allow_writes)))
            reason = (f"no such tool: {name}" if tool is None else
                      f"{name} writes to the case, and write access is disabled in Iris "
                      f"(Settings → MCP server → allow writes)")
            return _ok(rpc_id, {"isError": True,
                                "content": [{"type": "text", "text": f"{reason}. Available tools: {known}"}]})
        ctx: RunContext = state["ctx"]
        try:
            tool.validate_args(args)
            result = tool.fn(args, ctx)
        except ToolError as exc:
            return _ok(rpc_id, {"isError": True, "content": [{"type": "text", "text": str(exc)}]})
        except Exception as exc:  # noqa: BLE001 — a tool crash must reach the client as a tool error
            return _ok(rpc_id, {"isError": True,
                                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}]})
        text = orjson.dumps(result, option=orjson.OPT_INDENT_2).decode()
        payload: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": False}
        if isinstance(result, dict):
            payload["structuredContent"] = result
        return payload if is_notification else _ok(rpc_id, payload)

    if is_notification:
        return None
    return _err(rpc_id, -32601, f"method not found: {method}")


# --------------------------------------------------------------------- endpoint
@router.post("")
async def mcp_endpoint(request: Request, authorization: Optional[str] = Header(None)) -> Response:
    """Streamable-HTTP MCP endpoint. One POST in, one JSON-RPC response out (no SSE: this server
    never pushes unsolicited messages, and the spec allows a plain JSON reply in that case)."""
    s = get_settings()
    blocked = _serving_block(s)
    if blocked is not None:
        # 404 when switched off (there is nothing here), 503 when enabled-but-untokened (there IS
        # something here and it is misconfigured — a client that gets 404 will stop asking, a client
        # that gets 503 tells the analyst to go and finish the setup).
        status = 404 if not s.mcp.enabled else 503
        return Response(status_code=status, media_type="application/json",
                        content=orjson.dumps(_err(None, -32000, blocked)))
    if not _authorised(authorization, s.mcp.token):
        return Response(status_code=401, media_type="application/json",
                        headers={"WWW-Authenticate": "Bearer"},
                        content=orjson.dumps(_err(None, -32001, "invalid or missing bearer token")))
    raw = await request.body()
    try:
        msg = orjson.loads(raw or b"")
    except orjson.JSONDecodeError:
        return Response(status_code=400, media_type="application/json",
                        content=orjson.dumps(_err(None, -32700, "parse error")))

    # A tool handler can be O(the whole pool); running it on the event loop would stall every other
    # request in the process — the same reason investigator.py uses to_thread.
    import anyio

    state: dict[str, Any] = {"client": "unknown client"}

    def run_batch() -> list[Any]:
        state["ctx"] = RunContext(run_id=f"mcp-{secrets.token_hex(4)}",
                                  model=f"MCP: {state.get('client', 'unknown client')}")
        items = msg if isinstance(msg, list) else [msg]
        out: list[Any] = []
        for item in items:
            if not isinstance(item, dict):
                out.append(_err(None, -32600, "invalid request"))
                continue
            reply = _handle(item, s.mcp.allowWrites, state)
            if reply is not None:
                out.append(reply)
        return out

    replies = await anyio.to_thread.run_sync(run_batch)
    if not replies:                      # notifications only
        return Response(status_code=202)
    body = replies if isinstance(msg, list) else replies[0]
    return Response(content=orjson.dumps(body), media_type="application/json")


@router.get("")
def mcp_get() -> Response:
    """Clients may open a GET stream for server→client messages. Iris has none to send, and the spec
    says a server that does not offer one answers 405."""
    return Response(status_code=405, media_type="application/json",
                    content=orjson.dumps(_err(None, -32000, "this server does not offer an SSE stream")))


# --------------------------------------------------------------------- UI support
# The snippets are documentation, not a credential store. `/api/mcp/status` is a plain GET with no
# secret of its own, so putting the live token into three separate places in its body made a masked
# `••••1234` next to it pure theatre — anything that could read the status could read the token. The
# rule CLAUDE.md states is "returned in the clear exactly once", i.e. from POST /api/mcp/token, and the
# Settings panel already fills THAT value into the snippets it renders itself.
TOKEN_PLACEHOLDER = "<your Iris MCP token>"


def _client_config(url: str, token: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"url": url}
    if token:
        entry["headers"] = {"Authorization": f"Bearer {token}"}
    return {"mcpServers": {"iris": entry}}


@router.get("/status")
def mcp_status(request: Request) -> dict[str, Any]:
    """Everything the Settings panel needs: state, the tool list, and ready-to-paste client config."""
    s = get_settings()
    # The URL a CLIENT must use, not the one the browser happened to load: inside Docker the app sees
    # its own container name, so the host-facing origin is what gets pasted into mcp.json.
    origin = str(request.base_url).rstrip("/")
    url = f"{origin}/api/mcp"
    token = s.mcp.token
    # NEVER the real token: see TOKEN_PLACEHOLDER. The placeholder appears only when a token exists, so
    # the snippet still shows the analyst that an Authorization header is part of the config.
    snippet_token = TOKEN_PLACEHOLDER if token else ""
    blocked = _serving_block(s)
    reads = [t.name for t in REGISTRY.values() if not t.writes]
    writes = [t.name for t in REGISTRY.values() if t.writes]
    return {
        "enabled": s.mcp.enabled,
        "allowWrites": s.mcp.allowWrites,
        "hasToken": bool(token),
        "token": config.mask_key(token),
        # `enabled` is what the analyst set; `serving` is whether a client will actually get an answer.
        # They differ in exactly one state — enabled with no token — and that state used to serve the
        # whole read surface unauthenticated. The UI must render `serving`, not `enabled`.
        "serving": blocked is None,
        "blockedReason": blocked or "",
        "url": url,
        "protocol": DEFAULT_PROTOCOL,
        "transport": "http",
        "toolCount": len(reads) + (len(writes) if s.mcp.allowWrites else 0),
        "readTools": reads,
        "writeTools": writes,
        "config": {
            # Cursor reads ~/.cursor/mcp.json (global) or .cursor/mcp.json (per project); the CLI picks
            # up the same files. Claude Desktop uses the same shape in claude_desktop_config.json.
            "cursor": _client_config(url, snippet_token),
            "claudeCode": "claude mcp add --transport http iris " + url +
                          (f' --header "Authorization: Bearer {snippet_token}"' if snippet_token else ""),
            "stdioBridge": {"mcpServers": {"iris": {
                "command": "python",
                "args": ["mcp/iris-mcp-stdio.py"],
                "env": {"IRIS_URL": origin,
                        **({"IRIS_MCP_TOKEN": snippet_token} if snippet_token else {})}}}},
        },
    }


@router.post("/token")
def mcp_new_token() -> dict[str, Any]:
    """Generate a bearer token (and return it ONCE in the clear — every later read is masked).

    Deliberately NOT gated on the existing MCP token. The Settings panel is the only caller and it
    cannot present that token — it is masked the moment it is stored, which is the point. Requiring it
    would break the one button the analyst has and buy nothing: an attacker who can reach this endpoint
    unauthenticated can already `PUT /api/settings` and set a token of their own choosing. What
    actually protects this route is the cross-site guard in app/security.py (a web page cannot POST
    here) plus IRIS_AUTH_TOKEN when the port is exposed at all.
    """
    token = secrets.token_urlsafe(24)
    update_settings({"mcp": {"token": token}})
    return {"token": token}
