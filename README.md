<div align="center">

# Iris

**A log parser and correlation workbench for incident response.**

Ingest anything a machine wrote down. Normalize it into one schema, detect, correlate, and report —
on one machine, with nothing leaving it.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)
![React 18 + TypeScript](https://img.shields.io/badge/react-18%20%2B%20TS-61DAFB.svg)
![Docker or native](https://img.shields.io/badge/run-docker%20%7C%20native-2496ED.svg)
![CUDA optional](https://img.shields.io/badge/CUDA-optional-76B900.svg)

</div>

---

## What it is

Drop a folder of evidence onto Iris and it works out what each file is, parses it, and puts every line into
one searchable pool. From there it runs a detection catalogue over that pool, builds an entity graph of what
talked to what, and drafts a findings report you can export.

It is built around one deliberate constraint: **a case is optional.** Search, detections, the entity graph and
event detail all work with zero cases on disk. A case adds only curation — a timeline, notes, indicators,
accepted graph links, and the report. You never have to file evidence before you can look at it.

Everything runs locally. The only outbound connection Iris makes is to the AI endpoint you configure, and that
is off until you configure it.

## Highlights

| | |
|---|---|
| **Ingest** | Syslog, nginx, EVTX, CloudTrail, k8s audit, JSONL, CSV and delimited text, XLSX, DOCX, PDF, `.eml`/`.mbox`/`.msg`, SQLite databases, pcap/pcapng, memory dumps, screenshots (OCR), archives, and unknown text. Format is decided by content, not by extension. |
| **Two-phase ingest** | Raw lines are searchable *before* they are interpreted. Splitting fields out of a line is roughly 15 % of ingest and normalizing it is the other 85 %, so Iris does the second half in the background, per source, on demand. |
| **Search** | `user:svc_deploy AND src_ip:45.83.140.22`, free text, `NOT`/`OR`, quotes, wildcards, `\:` escaping. Columns are configurable over any parsed field, and every value on screen is a one-click include (`+`) or exclude (`−`). |
| **Detections** | 104 Sigma-like built-ins — 94 per-event, plus 10 that read the entity graph — across web, identity, Windows, Linux, AWS, Azure/Entra ID, Microsoft 365, Defender, Kubernetes, mail and packet captures. Every constant is editable, and a custom rule is a regex or a set of typed conditions. |
| **Exclusions** | Suppress the known-benign without hiding evidence: an exclusion drops the *detection*, never the line. Nothing ships enabled — Iris suggests a library and applies none of it. |
| **Entity graph** | Typed nodes and relations, filtered by source, by link strength, and by how connected an entity is. Painted to a canvas, so it stays interactive at thousands of nodes. |
| **AI investigator** | One free-form objective. The assistant drives Iris's own tools and streams what it does. Every finding is cited to a real event id, and every change it makes is listed and reversible. |
| **MCP server** | The same tools exposed to Cursor, Claude Code and Claude Desktop. Off by default, token required. |
| **GPU (optional)** | CUDA is probed in the background and used for the search index, substring scans and the co-occurrence GEMM. Everything falls back to numpy — the app must always run without a GPU. |
| **Export** | Markdown, JSON, STIX 2.1 or PDF. |

## Quick start

**You do not need anything installed first.** Setup does not assume Python, Node, Docker or tesseract are
present — anything missing is fetched through the system package manager (`apt`, `dnf`, `pacman`, `zypper`,
`apk`, `brew`, or `winget` on Windows), showing the exact command and asking once.

| Platform | Command |
|---|---|
| **Windows** | `.\setup.ps1` |
| **Linux / WSL 2 / macOS** | `./setup.sh` |

Then open **http://127.0.0.1:8000** and drop your first files onto the **Sources** screen.

<details>
<summary><strong>Other setup modes</strong></summary>

```bash
./setup.sh gpu | cpu        # force an image instead of auto-detecting
./setup.sh local            # no Docker: install onto this machine
./setup.sh down | logs      # stop and remove / follow logs
./setup.sh --yes            # install anything missing without asking
./setup.sh --no-install     # never install; report what is missing and stop
```

`local` mode installs into a virtualenv at `./.venv` and resolves GPU wheels for *that* host: it reads the CUDA
version off the driver and picks `cupy-cuda11x`/`12x`/`13x` plus the matching `torch` index, uses torch's ROCm
build on AMD, torch/MPS on Apple Silicon, and CPU-only numpy where there is no GPU. Override a wrong guess with
`IRIS_CUPY` / `IRIS_TORCH_INDEX`.

</details>

### Everyday use

```bash
./start.sh                  # start (Docker), wait for /api/health to answer, open the browser
./start.sh local            # no Docker: uvicorn on this machine
./start.sh stop | restart | logs | status
```

`start.*` will not serve a build your tree has already moved past. On every start it compares the built SPA —
or, in Docker mode, the image's build time — against the sources, rebuilds what is stale and names the file
that changed, and recreates the container so a running one cannot stay on its old image. In `local` mode it
also refuses to start when something else is already serving that port: otherwise the health probe succeeds
against the *old* process and your browser opens onto the previous build.

### Uninstall

```bash
./uninstall.sh              # add: docker | local | all
```

**Your evidence is kept** unless you pass `--purge-data`, which prints what will be lost and then requires the
word `DELETE` typed in full.

## Requirements

- **Docker install** — Docker Desktop (Windows/macOS) or Docker Engine with Compose (Linux). Nothing else.
- **Native install** — Python 3.11+ and Node 18+; setup installs both if they are missing.
- **GPU (optional)** — Windows: Docker Desktop on the WSL 2 backend plus a current Windows NVIDIA driver, never
  a Linux driver inside WSL. Linux: the NVIDIA driver plus the
  [Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html).
  macOS: no CUDA in Docker, so the CPU image is used automatically.

<details>
<summary><strong>Windows: WSL 2 tuning (recommended)</strong></summary>

Iris is memory-heavy, and Docker Desktop runs it inside a WSL 2 VM whose default is half your RAM. `.\wsl.ps1`
reports what your `.wslconfig` sets against what Iris wants; `-Apply` writes it, backing the file up first.
`setup.ps1` offers it, and `start.ps1` warns when the file has drifted.

</details>

## Use Iris from Cursor or Claude Code

Iris speaks MCP. **Settings → MCP server** (off by default, token required) exposes the assistant's own tools —
search, exact aggregations, timeline, entity graph, detections, and optional case curation — at `/api/mcp`,
with paste-ready configuration for Cursor, Claude Code and stdio-only clients.

It is the *same* tool registry the built-in investigator uses, so an external agent and Iris can never end up
looking at different cases. See [`docs/MCP.md`](docs/MCP.md).

## Security

There is no user model — one analyst, one machine, one evidence pool — but that is not the same as no exposure:

- Iris binds to **127.0.0.1** by default, and CORS is an allowlist, never `*`.
- A **password and PIN** gate for the UI is configurable in Settings; `IRIS_AUTH_TOKEN` is the headless equivalent.
- The MCP server fails **closed**: enabled with no token serves nothing at all.
- Cross-site writes, `Host`-header rebinding, and path traversal into the data directory are each closed
  explicitly, and `GET /api/settings` reports the live posture — so a dangerous state is visible instead of
  looking exactly like a working app.

Loopback binding is not a defence against a web page on the same machine; that is what the request checks are
for. `HOWTO.md → Security` says which control closes what.

## Development

```bash
cd backend  && pip install -r requirements.txt && uvicorn app.main:app --reload --port 8000
cd frontend && npm install --ignore-scripts && npm run dev    # :5173, proxies /api → :8000
```

`--ignore-scripts` is not optional: `frontend/.npmrc` disables dependency lifecycle hooks — the supply-chain
foothold Iris does not need — and the Dockerfile and setup scripts pass the flag explicitly.

Building by hand? Pass `WEB_REBUILD` and `--force-recreate`, or you can ship an old frontend inside a new image:

```bash
WEB_REBUILD=$(date +%s) docker compose up -d --build --force-recreate
```

## Documentation

| | |
|---|---|
| [`HOWTO.md`](HOWTO.md) | The reference: every script flag, every `IRIS_*` variable with its default, a per-screen guide, and troubleshooting. |
| [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) | The backend ⇄ frontend contract. |
| [`docs/MCP.md`](docs/MCP.md) | Driving Iris from an external agent. |

## License

MIT — see [`LICENSE`](LICENSE).
