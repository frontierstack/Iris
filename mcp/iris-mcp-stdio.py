#!/usr/bin/env python3
"""stdio → HTTP bridge for the Iris MCP server.

Iris serves MCP over HTTP on the port the app already listens on (POST /api/mcp), because a stdio
server would have to build its OWN copy of the event pool — a second parse of every log, and two
different answers to the same question. Clients that can only launch a command (older Claude Desktop
builds, editors without HTTP transport) run this instead: it is a dumb pipe that forwards each
JSON-RPC line to the running Iris and writes the reply back.

Requirements: Python 3.9+ and a running Iris. No third-party packages — the standard library only,
so it works with whatever interpreter the client happens to invoke.

Configure it like this (Cursor ~/.cursor/mcp.json, or claude_desktop_config.json):

    {"mcpServers": {"iris": {
       "command": "python",
       "args": ["/absolute/path/to/Iris/mcp/iris-mcp-stdio.py"],
       "env": {"IRIS_URL": "http://localhost:8000", "IRIS_MCP_TOKEN": ""}}}}

Environment:
    IRIS_URL        base URL of the running app       (default http://localhost:8000)
    IRIS_MCP_TOKEN  bearer token, if one is set in Settings → MCP server
    IRIS_MCP_TIMEOUT seconds to wait for one tool call (default 180 — a search over a million
                    events is legitimately slow, and a bridge that times out first reports a
                    working tool as broken)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("IRIS_URL", "http://localhost:8000").rstrip("/")
URL = BASE if BASE.endswith("/api/mcp") else BASE + "/api/mcp"
TOKEN = os.environ.get("IRIS_MCP_TOKEN", "").strip()
TIMEOUT = float(os.environ.get("IRIS_MCP_TIMEOUT", "180"))


def log(msg: str) -> None:
    # stdout is the protocol channel — anything human-readable MUST go to stderr or the client sees
    # a corrupt JSON-RPC stream and drops the server with an unhelpful error.
    print(f"[iris-mcp] {msg}", file=sys.stderr, flush=True)


def post(payload: dict) -> dict | None:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(URL, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        if resp.status == 202:
            return None
        raw = resp.read()
        return json.loads(raw) if raw else None


def error_for(msg: dict, code: int, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": code, "message": text}}


def main() -> int:
    log(f"bridging stdio → {URL}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            reply = post(msg)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            hint = ("  Enable it in Iris → Settings → MCP server." if exc.code == 404 else
                    # 503 = enabled but no bearer token configured. Iris fails closed there rather than
                    # serving the whole evidence pool unauthenticated, so the fix is on the SERVER, not
                    # in this bridge's environment — 401 is the one that means "your token is wrong".
                    "  Iris is enabled but has no bearer token, so it refuses every request. "
                    "Generate one in Settings → MCP server and set IRIS_MCP_TOKEN here." if exc.code == 503 else
                    "  Check IRIS_MCP_TOKEN against Settings → MCP server." if exc.code == 401 else "")
            reply = error_for(msg, -32000, f"Iris returned HTTP {exc.code}: {detail}{hint}")
        except urllib.error.URLError as exc:
            reply = error_for(msg, -32000, f"cannot reach Iris at {URL}: {exc.reason}. Is the app running?")
        except Exception as exc:  # noqa: BLE001
            reply = error_for(msg, -32000, f"{type(exc).__name__}: {exc}")
        # A notification gets no reply — writing one would break the client's request/response pairing.
        if reply is None or "id" not in msg:
            continue
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
