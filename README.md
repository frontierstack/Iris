# Iris — log parser & correlation workbench

Drop syslog, nginx, EVTX, CloudTrail, k8s audit, JSON/CSV/XLSX, SQLite databases, mail, PDFs, DOCX, screenshots (OCR),
memory dumps, archives or unknown text into the workspace. Iris fingerprints each file, normalizes every line into one
schema, runs detections, correlates events into incident clusters and an entity graph, and drafts a findings report
(Markdown / JSON / STIX 2.1 / PDF).

* **A case is optional.** Search, detections, the entity graph and event detail all work on the whole ingested pool
  with zero cases on disk. A case adds curation: a timeline, notes, indicators, accepted graph links, the report.
* **Search** — `user:svc_deploy AND src_ip:45.83.140.22`, free text, NOT/OR, quotes, wildcards, `\:` escaping.
  Configurable columns, and every value on screen is a one-click include (`+`) or exclude (`−`) filter.
* **Entity graph** — typed nodes and relations on a canvas, filtered by source, by link strength
  (*min link events*) and by how connected an entity is (*min connections*).
* **Detections** — 33 Sigma-like built-ins, every constant editable, plus custom rules written as a regex or as
  typed conditions.
* **AI investigator** — one free-form objective; the assistant drives Iris's own tools and streams what it does.
  Every change it makes is listed and reversible.
* **MCP** — the same tools exposed to Cursor / Claude Code / Claude Desktop.
* **GPU** — CUDA is probed in the background (cupy → torch → nvidia-smi) and used for the search index, substring
  scans and the co-occurrence GEMM; everything falls back to numpy.

## Quick start (Docker)

| Where | Command |
|---|---|
| Windows (Docker Desktop) | `.\setup.ps1` |
| WSL2 / Linux / macOS | `./setup.sh` |
| Force a mode | `./setup.sh gpu` · `./setup.sh cpu` · `.\setup.ps1 -Mode gpu` |
| No Docker (native install) | `./setup.sh local` · `.\setup.ps1 -Mode local` |
| Stop / logs | `./setup.sh down` · `./setup.sh logs` |
| Uninstall | `./uninstall.sh` · `.\uninstall.ps1` — add `local`/`all`; your evidence is kept unless you pass `--purge-data` |

Then open http://localhost:8000 and drop your first files onto the **Sources** screen.

**Starting from a bare machine is fine.** Setup does not assume Python, Node, Docker or tesseract are
installed — anything missing is fetched through the system package manager (`apt`/`dnf`/`pacman`/`brew`,
or `winget` on Windows), showing the command and asking once. Add `--yes` / `-Yes` to skip the prompts,
or `--no-install` / `-NoInstall` to only be told what is missing.

Already set up? **`.\start.ps1` / `./start.sh`** is the everyday launcher: one
container serves the API and the UI, it waits for `/api/health` to actually answer, prints numbered steps with a
live spinner, and opens the browser. `stop`, `restart`, `logs` and `status` do what they say.

Every script, flag and environment variable is documented in **`HOWTO.md`**.

`local` mode installs onto the machine instead of building an image: base Python deps always, and — when it finds a
GPU — the compute libraries that match *that* host. It reads the CUDA version off the driver and picks the right
wheels (`cupy-cuda11x`/`12x`/`13x` plus the matching `torch` index), uses torch's ROCm build on AMD, torch/MPS on
Apple Silicon, and falls back to CPU-only numpy when there is no GPU. Override a wrong guess with `IRIS_CUPY` /
`IRIS_TORCH_INDEX`.

Manual: `docker compose up -d --build` (CPU) or
`docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d --build` (GPU).
Optional env in `.env` (see `.env.example`) seeds the first start only.

### GPU prerequisites
* **Windows**: Docker Desktop with the WSL 2 backend + a current Windows NVIDIA driver. Do not install a Linux
  driver inside WSL.
* **Linux**: NVIDIA driver + [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
  (`sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker`).
* **macOS**: no CUDA in Docker — the CPU image is used automatically.

### WSL 2 tuning (Windows, recommended)
Iris is memory-heavy and Docker Desktop runs it inside a WSL 2 VM. `.\wsl.ps1` reports what your `.wslconfig` sets
against what Iris wants, `-Apply` writes it (backing the file up first). `setup.ps1` offers it and `start.ps1` warns
when the file has drifted. Details and the reasoning: run `.\wsl.ps1` or see `HOWTO.md`.

## Use Iris from Cursor / Claude Code
Iris speaks MCP. Settings → **MCP server** (off by default) exposes the assistant's own tools — search, exact
aggregations, timeline, entity graph, detections, optional case curation — at `/api/mcp`, with paste-ready config
for Cursor, Claude Code and stdio-only clients. See `docs/MCP.md`.

## Development
```
cd backend  && pip install -r requirements.txt && uvicorn app.main:app --reload --port 8000
cd frontend && npm install --ignore-scripts && npm run dev   # http://localhost:5173, proxies /api → :8000
cd backend  && python -m pytest -q
```
`--ignore-scripts` is not optional: `frontend/.npmrc` disables dependency install hooks, and the Dockerfile and
setup scripts pass the flag explicitly.

Everyday guide: `HOWTO.md`. API contract: `docs/API_CONTRACT.md`. Project conventions: `CLAUDE.md`.
