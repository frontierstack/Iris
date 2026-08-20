# Using Iris from Cursor, Claude Code and other MCP clients

Iris can act as an **MCP server**: an outside AI tool connects to the running app and gets the same
tools the built-in assistant uses — search the event pool, aggregate exact counts, read the timeline
and the entity graph, list detections, and (optionally) curate the case.

It is the *same* workspace. There is no second copy of the evidence, no re-parsing, and no separate
index: an answer a model gets in Cursor is the answer the Search screen gives.

---

## 1. Turn it on

**Settings → MCP server** (collapsed by default).

| Switch | What it does |
|---|---|
| **Enable MCP server** | Serves MCP at `http://<host>:8000/api/mcp`. Off by default. |
| **Allow write tools** | Lets a connected model create a case, curate the case set, add indicators, notes, graph links and detection rules. Off by default — read-only is the useful default. |
| **Bearer token** | Optional. When set, a client must send `Authorization: Bearer <token>`. Generated tokens are shown **once**. |

No restart is needed for any of these.

**What can never happen from MCP**: deleting a case, deleting a source, clearing data, deleting a
built-in rule, or resetting the workspace. Those tools do not exist in the registry at all. Everything
a model does write is attributed (`AI assistant (MCP: cursor)`, `addedBy:'ai'`) and lands in
`case.json`, where you can see and remove it.

---

## 2. Requirements

* Iris running and reachable **from the client machine**. Same machine → `http://localhost:8000`.
  Another machine → that host's address, and set a token.
* Evidence already ingested. The tools read the workspace pool; an empty pool answers
  "no events", which is a true answer, not an error.
* A case only for the write tools that curate one. Search, graph, timeline and detections work with
  no case at all.
* For the stdio bridge only: Python 3.9+ on the client machine (standard library only).

---

## 3. Cursor

Cursor reads **the same config in the editor and in the terminal CLI**:

* global: `~/.cursor/mcp.json`
* per project: `.cursor/mcp.json` in the repo root

```json
{
  "mcpServers": {
    "iris": {
      "url": "http://localhost:8000/api/mcp"
    }
  }
}
```

With a token:

```json
{
  "mcpServers": {
    "iris": {
      "url": "http://localhost:8000/api/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

Then:

1. Reload the Cursor window (or restart it). Running `cursor` in a terminal picks the same file up
   automatically.
2. Check **Settings → MCP** — `iris` should appear as connected with its tool count. In the CLI,
   `cursor mcp list` shows which servers are active.
3. Use it by name in chat: *"Use iris to find every event involving 10.0.0.100 and tell me which
   sources it appears in."*

**Not showing up?** The JSON must be valid (a trailing comma is the usual culprit), the URL must be
reachable from that machine (`curl -X POST http://localhost:8000/api/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' -H 'content-type: application/json'`),
and the server must be enabled in Settings — a disabled server answers **404** on purpose.

---

## 4. Claude Code

```bash
claude mcp add --transport http iris http://localhost:8000/api/mcp
# with a token:
claude mcp add --transport http iris http://localhost:8000/api/mcp --header "Authorization: Bearer <token>"
```

`claude mcp list` verifies it; `/mcp` inside a session lists the tools. Add `--scope project` to write
the entry into the project's `.mcp.json` instead of your user config.

---

## 5. Claude Desktop, or any client that can only launch a command

Some clients speak stdio only. `mcp/iris-mcp-stdio.py` bridges stdio to the HTTP endpoint — it is a
dumb pipe with no dependencies, and it never parses logs itself, so there is still only one event pool.

```json
{
  "mcpServers": {
    "iris": {
      "command": "python",
      "args": ["/absolute/path/to/Iris/mcp/iris-mcp-stdio.py"],
      "env": {
        "IRIS_URL": "http://localhost:8000",
        "IRIS_MCP_TOKEN": ""
      }
    }
  }
}
```

`IRIS_MCP_TIMEOUT` (default 180 s) bounds one tool call — a search over a million events is
legitimately slow, and a bridge that gives up first would report a working tool as broken.

---

## 6. What the tools are

Read tools (always available when the server is on):

| Tool | Use it for |
|---|---|
| `get_case_state` | what exists: case, pool size, sources, whether the pool is still loading |
| `search_events` | rows matching a DSL query |
| `count_events` | the exact number matching a query — no sampling, no arithmetic |
| `aggregate_events` | counts grouped by source / host / user / any field |
| `distinct_values`, `events_over_time`, `sample_events` | the shape of the data |
| `list_event_fields` | the parsed field vocabulary (call this before guessing field names) |
| `get_event`, `get_timeline` | one event in context; correlated clusters |
| `list_anomalies` | the detection roll-up: which rules fired, how often, first/last seen |
| `list_cases`, `get_case_set` | every case on disk (and which is active); the curated case timeline |
| `list_graph_links` | the links added on top of the extracted graph (the editable ones) |
| `graph_find`, `graph_node`, `graph_path` | the entity graph: locate a node, its facts and neighbours, the path between two |
| `list_sources`, `list_detections`, `list_iocs`, `list_notes`, `list_detection_rules` | what is ingested, what fired, indicators, notes, the rule catalogue |

Write tools (only when **Allow write tools** is on) form a closed loop — everything that can be created
can also be edited and removed:

| Area | Tools |
|---|---|
| Cases | `create_case`, `update_case` (name/summary), `activate_case` (switch which case writes land in) |
| Case timeline | `add_events_to_case`, `annotate_case_event` (labels + per-step note), `remove_events_from_case` |
| Indicators | `add_ioc`, `update_ioc`, `delete_ioc` |
| Notes | `add_note`, `update_note`, `delete_note` |
| Entity graph | `add_graph_link`, `delete_graph_link` |
| Detection rules | `create_detection_rule`, `update_detection_rule`, `set_detection_rule_enabled`, `set_builtin_rule_params`, `delete_detection_rule` (custom only — a built-in can be disabled, never deleted) |

Only MANUAL artefacts can be edited or removed. An extracted indicator or an extracted graph edge is
what the events say: the tool refuses and points at the real fix (tune the rule that produces it).
Every removal keeps a full snapshot, so `POST /api/ai/runs/{id}/undo` puts the whole run back.

Every write tool that records a claim requires `citedEventIds` naming **real** events. A fabricated
event id is refused outright, with the bad ids named — a made-up citation in an incident report is a
serious harm, not a formatting slip.

### Query syntax the model should use

`field:value` terms and bare free text, combined with `AND` / `OR` / `NOT` (a leading `-` also
negates), grouped with `( )`, phrases in `"double quotes"`. Escape a literal colon with a backslash:
`10.0.0.9\:3001`. Fields: `source`, `file`, `host`, `user`, `sev`, `msg`, `raw`, `id`, plus any parsed
field name. The tools teach this themselves — `validate_query` refuses a malformed query rather than
letting it return zero matches, because "no results" and "broken query" must never look the same.

---

## 7. Security notes

* The endpoint is **off by default** and lives on the same port as the app, which has no login. Treat
  enabling it as "this machine's evidence is available to anything that can reach port 8000".
* Set a token whenever Iris is not alone on a trusted network. Iris binds `0.0.0.0` in Docker.
* Keep **Allow write tools** off unless you want a model curating the case. Reads cannot change
  anything; writes are additive and attributed, but they are still changes to evidence.
* Tokens are stored in `settings.json` alongside the AI API key and are masked on every read.
