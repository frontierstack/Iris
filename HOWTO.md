# Iris — HOWTO

## Access
| What | Where |
|---|---|
| App (UI) | http://127.0.0.1:8000 |
| API base | http://127.0.0.1:8000/api |
| Health check | http://127.0.0.1:8000/api/health |
| Interactive API docs (Swagger) | http://127.0.0.1:8000/docs |
| MCP endpoint | http://127.0.0.1:8000/api/mcp (off by default) |

> Use `127.0.0.1`, not `localhost`. The port is published on the IPv4 loopback only, and a connection to
> the IPv6 one (`::1`) is not refused — it hangs until it times out, so anything that says `localhost`
> waits for that attempt to lose first. Measured here on the same request: **2,084 ms via `localhost`
> against 5 ms via `127.0.0.1`**. `start.sh` / `start.ps1` open the literal for you.
| From another machine on your LAN | **not by default** — see [Security](#security) |

**Iris listens on loopback only.** The published port is `127.0.0.1:8000`, so the app is reachable from the
machine it runs on and nowhere else. To reach it from your LAN, set `IRIS_BIND_HOST=0.0.0.0` **and** protect the
instance: turn on **Settings → Security** (a password and a PIN, asked for on a login page) for people, and set
`IRIS_AUTH_TOKEN` for scripts and MCP clients, which cannot sign in. Without either, every endpoint — including
the one that wipes the workspace — is open to whoever can reach the port. See [Security](#security).

Everything runs in ONE container named `iris`: the FastAPI API under `/api` and the built React SPA at `/`. There
is no second service to start. Data lives in `./backend/data` on the host, bind-mounted to `/data` in the container,
so a container run and a local `uvicorn` run share the same evidence.

---

# Scripts

Four scripts, each with one job — plus the escape hatch:

| Script | Job |
|---|---|
| `setup.ps1` / `setup.sh` | **First run.** Environment + Docker checks, GPU passthrough probe, per-host GPU wheel resolution, image build. |
| `start.ps1` / `start.sh` | **Every day.** Bring the app up (or stop / restart / logs / status), wait for `/api/health`, open the browser. |
| `wsl.ps1` | **Windows only.** Report and apply the WSL 2 settings Iris wants. |
| `uninstall.ps1` / `uninstall.sh` | **Removal.** Take out the Docker install, the local install, or both. Your evidence is kept unless you ask for it to go. |
| `docker compose` | The escape hatch if you would rather not use any of them. |

One script per platform, no wrappers: the `start.cmd` / `setup.cmd` double-click launchers are gone. On Windows,
right-click a `.ps1` → **Run with PowerShell** does the same thing, and running it from a terminal is what you want
anyway — these scripts print progress you are meant to read.

> Editing a `.ps1`? They are saved as **UTF-8 with a BOM** on purpose. PowerShell 5.1 decodes a BOM-less file as
> cp1252, and a UTF-8 em dash inside a double-quoted string ends in byte `0x94` — a curly quote that silently
> terminates the string and produces parse errors pages away from the real line.

## `start.*` — the everyday launcher

```powershell
.\start.ps1                      # Docker: bring the whole app up (the GPU image if one was built)
.\start.ps1 -Mode local          # no Docker: rebuild frontend/dist if stale, run uvicorn on this machine
.\start.ps1 -Mode stop           # stop the container
.\start.ps1 -Mode restart        # stop, then start
.\start.ps1 -Mode logs           # follow the container logs (Ctrl+C to exit)
.\start.ps1 -Mode status         # is it up, what is it doing, how big is the pool
.\start.ps1 -Build               # force an image rebuild before starting
.\start.ps1 -NoBrowser           # don't open the app when it is ready
.\start.ps1 -SkipWslCheck        # don't look at .wslconfig at all
.\start.ps1 -Port 8080           # serve on another port
```

```bash
./start.sh                       # start everything
./start.sh local                 # no Docker: uvicorn on this machine
./start.sh stop | restart | logs | status
./start.sh --build   | -b        # force an image rebuild first
./start.sh --no-browser | -n     # don't open the app
./start.sh --port=8080           # serve on another port  (or IRIS_PORT=8080)
./start.sh --help    | -h        # print the usage header
```

| PowerShell | bash | Meaning |
|---|---|---|
| `-Mode docker` (default) | `docker` (default) | Start the container. |
| `-Mode local` | `local` | No Docker: rebuilds `frontend/dist` when the tree is newer than it, then runs uvicorn on the host. |
| `-Mode stop` | `stop` | Stop the container. |
| `-Mode restart` | `restart` | Stop, then start. |
| `-Mode logs` | `logs` | Follow container logs. |
| `-Mode status` | `status` | Up/down, pool size, whether it is still loading. |
| `-Build` | `--build`, `-b` | Rebuild the image first. Otherwise it builds when no `iris:*` image exists, or when a source file is newer than the image. |
| `-NoBrowser` | `--no-browser`, `-n` | Don't open the browser. |
| `-Port <n>` | `--port=<n>`, `$IRIS_PORT` | Port to serve/probe. |
| `-SkipWslCheck` | *(n/a — Windows only)* | Skip the `.wslconfig` drift check. |

**What the output means.** Each long operation prints a numbered step, a live spinner with elapsed time and *what
it is waiting for* (build phase, `parsing library 12/34 files, 61% of bytes`), then a result line with how long it
took. When the output is redirected to a file or a CI log the spinner is replaced by a plain progress line every
10 s — `\r` does not collapse in a log file. The closing summary reports the version, the compute backend, the pool
size, whether the library is still loading, and any files that were **skipped** (those are not in search — Sources
says which and why).

Starting is not instant on a large library: the API answers in seconds, but parsing a few hundred MB of logs back
into the pool takes minutes, and the entity graph is restored from cache or rebuilt after that. The spinner says
which of those is happening.

### It never serves a build the tree has moved past

A fix that is deployed but not *served* looks exactly like a fix that does not work, and this has cost several
rounds of "it still looks the same" on changes that were correct. So the launcher checks, on every start, that what
it is about to serve matches what is in the tree:

| Mode | Checked against | If the tree is newer |
|---|---|---|
| `local` | `frontend/dist/index.html` vs `frontend/src`, `index.html`, `package.json`, `package-lock.json`, `vite.config.ts`, `tsconfig.json` | Runs `npm run build` first, naming the file that changed. |
| `local` | `package-lock.json` vs `node_modules` | Runs `npm ci --ignore-scripts` before the build. |
| `local` | `backend/requirements.txt` vs `.venv` | Warns and names `setup.* local` — it does not install behind your back. |
| `docker` | the image's build time vs the SPA sources, `backend/app`, the requirements files, `Dockerfile`, the compose files | Rebuilds the image, then recreates the container on it. |

Step `[2] Checking the UI bundle` / `Checking the image against the tree` prints either `is current` or the first
file that changed. Nothing is skipped silently: if `npm` is missing, or the image's build time cannot be read, it
says so and names the remedy (`--build` / `-Build`) rather than starting on a stale build without comment.

`local` mode also refuses to start when something is **already serving Iris on that port**. Without that check
uvicorn fails to bind while the health probe succeeds against the *old* process — so the browser opens onto the
previous build and the launcher looks like it worked. Stop the other one, or pass `--port=` / `-Port`.

## `setup.*` — first run

```powershell
.\setup.ps1                # auto-detect: GPU + Docker passthrough, then build & start
.\setup.ps1 -Mode gpu      # force the CUDA image
.\setup.ps1 -Mode cpu      # force the CPU image
.\setup.ps1 -Mode local    # no Docker: install Python/Node deps onto this machine
.\setup.ps1 -Mode down     # stop & remove the container
.\setup.ps1 -Mode logs     # follow logs
.\setup.ps1 -Yes           # install anything missing without asking
.\setup.ps1 -NoInstall     # never install; report what is missing and stop
```

```bash
./setup.sh                 # auto-detect (default)
./setup.sh gpu | cpu       # force an image
./setup.sh local           # no Docker: install onto this machine
./setup.sh down            # stop & remove
./setup.sh logs            # follow logs
./setup.sh --yes | -y      # install anything missing without asking
./setup.sh --no-install    # never install; report what is missing and stop
```

### Setup always builds fresh

`setup.*` is the *first-run and after-an-update* script, so it never reuses a previous build: it exports a fresh
`WEB_REBUILD` (which busts the SPA layer of the image — see below) and brings the container up with
`--force-recreate`, so a container that was already running cannot stay on its old image. `local` mode rebuilds
`frontend/dist` unconditionally.

### Missing dependencies are installed, not reported

**Assume a machine with nothing on it — no Python, no Node, no Docker.** Setup bootstraps whatever Iris
needs rather than exiting with a link. Every install shows the exact command first and asks once; `--yes`
answers yes, `--no-install` restores the old behaviour of naming the package and stopping.

| Missing | Linux / macOS | Windows |
|---|---|---|
| Python 3.11+ | `apt` / `dnf` / `yum` / `pacman` / `zypper` / `apk` / `brew` | `winget install Python.Python.3.12` |
| pip | `ensurepip`, then the distro package | `ensurepip` |
| Node + npm (builds the UI) | same package managers | `winget install OpenJS.NodeJS.LTS` |
| tesseract (screenshot OCR) | same package managers | `winget install UB-Mannheim.TesseractOCR` |
| Docker | Docker's official `get.docker.com` script, shown before it runs; `brew install --cask docker` on macOS | `winget install Docker.DockerDesktop` (+ `wsl --install`) |
| Compose plugin | distro package | bundled with Docker Desktop — update it |
| NVIDIA Container Toolkit | NVIDIA's repo + `nvidia-ctk runtime configure` (native Linux only) | not applicable — a Windows driver / WSL setting, so setup states the checklist |

Notes that matter in practice:

- **`local` mode installs into a virtualenv at `./.venv`**, and `start.* local` uses it automatically. Two
  reasons: Debian 12 and Ubuntu 24.04 mark the system interpreter *externally managed* (PEP 668), so a plain
  `pip install` there fails outright; and uninstalling is then one directory rather than a guess about which
  shared `site-packages` belong to Iris. If the venv cannot be created, setup falls back to the system
  interpreter and passes `--break-system-packages` when PEP 668 demands it.
- **Windows uses `winget`** (shipped as *App Installer* on Windows 10 1809+). If it is absent, setup says how
  to get it — Microsoft Store, or https://aka.ms/getwinget — instead of failing silently. After an install it
  rebuilds `PATH` from the registry, so a freshly installed Python or Node is usable **in the same run**.
- **Docker Desktop usually needs one reboot** after installing before the engine starts, and its first launch
  asks you to accept the licence. Setup says so rather than reporting an unreachable daemon.
- **npm lifecycle scripts never run** (`--ignore-scripts`), here and in the Dockerfile — see `frontend/.npmrc`.
- Nothing is installed without a prompt. In a non-interactive shell (CI, a pipe) with no `--yes`/`-Yes`, every
  install is declined automatically rather than hanging on a question nobody can answer.

`setup.sh` detects native Linux, WSL2, macOS and Git-Bash-on-Windows; on Git Bash it delegates to `setup.ps1` with
the same mode. It starts Docker Desktop if it is not running, checks that Docker can *actually* see the GPU (not
just that one exists), and builds `iris:cuda` (nvidia/cuda base + cupy) or `iris:cpu` (python:3.12-slim).

**`local` mode** installs the same dependency set onto the host instead of building an image, resolving GPU wheels
per machine: it reads the driver's CUDA version out of `nvidia-smi` — matching both spellings, `CUDA Version:`
(older) and `CUDA UMD Version:` (580+ drivers) — and picks `cupy-cuda11x`/`12x`/`13x` plus the matching torch index
(`cu118`…`cu128`), torch's ROCm build on AMD, torch/MPS on Apple Silicon, or numpy alone when there is no GPU.
`IRIS_CUPY` and `IRIS_TORCH_INDEX` override the guess. The dependencies it cannot find, it installs — see above.

On Windows, `setup.ps1` also checks `.wslconfig` and offers to apply the Iris settings before it builds.

## `wsl.ps1` — WSL 2 tuning (Windows)

```powershell
.\wsl.ps1                  # report only: what is set, what Iris wants, and why
.\wsl.ps1 -Apply           # write the settings (backs the file up first)
.\wsl.ps1 -Apply -Restart  # ...and run `wsl --shutdown` so they take effect — STOPS EVERY CONTAINER
.\wsl.ps1 -Quiet           # only speak up when something has drifted
```

Docker Desktop runs Iris inside a WSL 2 VM, and Iris is memory-heavy: a 300 MB library becomes several GB of parsed
events built by six worker processes. On an untuned VM that has produced SIGSEGVs inside plain Python and stdlib
code with 12 GB free — page faults the VM could not back, not bugs in the code. What it sets:

| Setting | Why |
|---|---|
| `kernelCommandLine = transparent_hugepage=never sysctl.vm.compaction_proactiveness=0` | THP + background compaction under allocation pressure is the failure mode. Iris allocates millions of small objects and gains nothing from huge pages. |
| `[experimental] autoMemoryReclaim = disabled` | WSL's reclaim walks the guest page cache constantly for no benefit on a workload holding a multi-GB pool. |
| `memory` / `swap` | Only filled in when **missing** — a deliberate value is never overwritten. |

The changes need `wsl --shutdown` (or a reboot) to take effect, which stops every container you are running,
including ones that have nothing to do with Iris. That is why `-Restart` is opt-in and never automatic.

> The setting an earlier version wrote, `sysctl.vm.compact_memory=0`, is a **no-op** — `compact_memory` is a
> write-only trigger, not a tunable. If your `.wslconfig` still has it, `wsl.ps1` will report the drift.

## `uninstall.*` — removing Iris

```powershell
.\uninstall.ps1                # Docker install: container, images, and an offer to prune the build cache
.\uninstall.ps1 local          # local (no-Docker) install: node_modules, dist, __pycache__, caches, venv
.\uninstall.ps1 all            # both
.\uninstall.ps1 -Pip           # local/all: also `pip uninstall` backend\requirements*.txt
.\uninstall.ps1 -PurgeData     # ALSO delete backend\data — irreversible, and it asks you to type DELETE
.\uninstall.ps1 -Yes           # don't ask (does NOT cover -PurgeData)
.\uninstall.ps1 -DryRun        # print what would go and stop
```

`local` and `all` also take the named form `-Mode local`, matching `start.ps1`.

```bash
./uninstall.sh                 # Docker install
./uninstall.sh local | all     # local install, or both
./uninstall.sh --pip           # also pip uninstall the Python dependencies
./uninstall.sh --purge-data    # ALSO delete backend/data — irreversible, asks you to type DELETE
./uninstall.sh --yes  | -y     # don't ask (does NOT cover --purge-data)
./uninstall.sh --dry-run | -n  # print what would go and stop
./uninstall.sh --help | -h     # print the usage header
```

**Your evidence is kept by default.** `backend/data` holds every case, every uploaded log, `rules.json`,
`settings.json` and `auth.json` — the one thing here that cannot be rebuilt from the repo. It goes only with
`--purge-data` / `-PurgeData`, which prints what is about to be lost (case count, staged file count, size) and
then requires you to type `DELETE`. `--yes` deliberately does **not** answer that prompt: an uninstall flag
should never be the thing that quietly destroys an investigation.

What each mode removes:

| Mode | What goes |
|---|---|
| `docker` | The `iris` container (`docker compose down --remove-orphans`), the `iris:cpu` / `iris:cuda` images, and — **only if you say yes** — the shared BuildKit cache. |
| `local` | `frontend/node_modules`, `frontend/dist`, `frontend/.vite`, every `__pycache__`, the pytest/mypy/ruff caches, and `.venv` if you made one. Python packages stay unless you pass `--pip`. |
| `all` | Both of the above, in that order. |

Three things it will not do, each on purpose:

- **It never deletes the source tree it lives in.** Delete that folder yourself once you are happy — a script
  that removes its own working directory cannot report what it did.
- **The build cache is offered, never assumed.** BuildKit does not tag layers by project, so Iris's cache is
  indistinguishable from every other project's on this machine. `--pip` is gated the same way: `setup.* local`
  installs into whatever interpreter ran it rather than a venv, so those packages are very likely shared.
- **It does not shrink `docker_data.vhdx`.** Removing the images frees space *inside* Docker; Windows does not
  get it back until that file is made sparse — see `wsl.ps1` and the disk notes below.

## Plain `docker compose`

```bash
docker compose up -d --build                                                   # CPU
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d --build   # CUDA
docker compose down                                                            # stop
docker compose logs -f                                                         # logs
docker restart iris                                                            # restart (the pool is re-parsed from /data)
docker compose down -v                                                         # stop AND remove volumes
```

Build args: `BASE_IMAGE`, `WITH_GPU`, `GPU_REQUIREMENTS`, `GPU_TORCH_INDEX` — the GPU overlay fills them from
`IRIS_GPU_BASE_IMAGE`, `IRIS_GPU_REQUIREMENTS` and `IRIS_GPU_TORCH_INDEX`, which the setup scripts export after
reading your driver.

**If you build by hand, set `WEB_REBUILD` yourself:**

```bash
WEB_REBUILD=$(date +%s) docker compose up -d --build --force-recreate
```

`WEB_REBUILD` is a build arg placed immediately before the frontend `COPY` in the Dockerfile, and its compose
default is the constant `now`. A constant means BuildKit may reuse the cached SPA layer — it has reported
`COPY frontend/ ./  CACHED` for a context that had genuinely changed — and the image then ships a frontend from an
earlier build while the build output says it succeeded. `--force-recreate` is the other half: plain `up -d` leaves
a *running* container on its old image, so a freshly built one is tagged and never served. `start.*` and `setup.*`
pass both for you.

---

# Environment variables

Copy `.env.example` → `.env` for the common ones. **They only seed the FIRST start** (before `settings.json`
exists); after that the Settings page is the source of truth. `IRIS_ENV_OVERRIDES=1` forces env to win on every
start. Docker compose does **not** support inline comments in `.env` — keep comments on their own lines.

### Everyday
| Variable | Default | What it does |
|---|---|---|
| `IRIS_DATA_DIR` | `backend/data` (`/data` in Docker) | Where cases, library, settings, rules and caches live. |
| `IRIS_DATA_HOST_DIR` | `./backend/data` | Host path bind-mounted to `/data` by compose. |
| `IRIS_PORT` | `8000` | Port used by `start.sh` (PowerShell: `-Port`). |
| `IRIS_COMPUTE_MODE` | `auto` | `auto` \| `cuda` \| `cpu`. |
| `IRIS_ENV_OVERRIDES` | unset | `1` makes env win over saved settings on every start. |

### AI assistant
| Variable | Default | What it does |
|---|---|---|
| `IRIS_AI_PROVIDER` / `IRIS_AI_MODEL` | — | `openai` \| `none`; model name. |
| `IRIS_AI_BASE_URL` | — | OpenAI-compatible endpoint (e.g. `http://host.docker.internal:11434/v1`). |
| `IRIS_AI_API_KEY` | — | Seeds the key; masked everywhere after that. |
| `IRIS_CA_BUNDLE` | auto (`/data/ca.pem`) | CA bundle for TLS-inspecting proxies. |
| `IRIS_AI_MAX_STEPS` | 40 (cap 120) | Tool-calling steps per investigation. |
| `IRIS_AI_MAX_SECONDS` | 600 (cap 900) | Wall clock per run. |
| `IRIS_AI_MAX_CONTEXT_TOKENS` | 60 000 | Estimated context ceiling; triggers compaction, not a stop. The estimate counts the tool schemas (~11k tokens) and the system prompt as well as the transcript. The model's OWN window is the real ceiling: when the provider refuses a request for its size (HTTP 400 naming the context), Iris folds the transcript, sets this run's ceiling from the limit the provider stated (or below what was refused) and retries the same turn. When folding cannot fit, the run restarts from its own record — the same recovery as typing "continue" — up to 3 times before it stops. |
| `IRIS_AI_MAX_COMPACTIONS` | 6 (cap 20) | How many times a run may compact its transcript while the run limits are ON. With "Limit how far a run can go" OFF there is no cap — a fold that frees no room is still refused. |
| `IRIS_AI_TOOL_SECONDS` | 90 (cap 600) | Wall clock ONE tool call gets. Past it (plus 5 s grace) a read is abandoned and reported to the model as a ToolError naming the narrower call; a write is always awaited. Also how long a stop can take to land inside a tool that never checks it. |
| `IRIS_AI_DERIVED_WAIT` | 60 (cap 600) | How long a graph / timeline / detection-roll-up tool waits for its background build before refusing with its progress. Keep it below `IRIS_AI_TOOL_SECONDS` so that refusal wins. |

### MCP server
| Variable | Default | What it does |
|---|---|---|
| `IRIS_MCP_ENABLED` | off | Expose `/api/mcp` at all. |
| `IRIS_MCP_ALLOW_WRITES` | off | Separate switch: a read cannot change a case, a write can. |
| `IRIS_MCP_TOKEN` | — | **Required.** `Authorization: Bearer <token>`. Enabling the server without one makes it answer `503` to everything — see [Security](#security). |

### Security
| Variable | Default | What it does |
|---|---|---|
| `IRIS_BIND_HOST` | `127.0.0.1` | Host interface the port binds to (compose publish address, and `--host` for `start.* local`). `0.0.0.0` exposes Iris to the network — set `IRIS_AUTH_TOKEN` at the same time. |
| `IRIS_AUTH_TOKEN` | unset (no gate) | A shared secret for the whole API. Send it as `Authorization: Bearer <token>` or `X-Iris-Token: <token>`, or open the UI once at `http://<host>:<port>/?token=<token>` and the browser keeps it in an HttpOnly, SameSite=strict cookie. `/api/health` stays open (healthchecks, `start.*`); `/api/mcp` is exempt because it carries its own mandatory token. |
| `IRIS_CORS_ORIGINS` | `http://localhost:<port>`, `http://127.0.0.1:<port>`, `http://localhost:5173`, `http://127.0.0.1:5173` | Comma-separated origins allowed to read a cross-origin response. `*` is refused — on an API with no authentication the wildcard lets every page you visit read your whole evidence pool. The SPA is same-origin and needs no entry; this list exists for `npm run dev`. |
| `IRIS_ALLOWED_HOSTS` | unset | Extra DNS names Iris answers to. By default it answers to `localhost` and to **IP addresses**, and refuses any other name: a DNS name that resolves to this machine is how a rebinding attack reaches a local tool. Set this to your reverse proxy's hostname. |

**What protects Iris, and what does not.** There is no user model, on purpose — one analyst, one machine, one
evidence pool. What actually stands between the evidence and a hostile web page:

* **CORS is an allowlist, never `*`.** A page on another origin cannot read any response.
* **A cross-site write is refused** (`403`). CORS only stops the response being *read*; it does not stop the
  request being *sent*, and `POST /api/admin/clear-all` accepts an empty body, so a plain HTML `<form>` on any
  page would otherwise wipe the workspace without the attacker ever seeing the reply. Requests carrying a
  foreign `Origin` (or `Sec-Fetch-Site: cross-site`) are rejected before they reach a handler, as are
  form-encoded and `text/plain` bodies on `/api` — the two body shapes a browser can post cross-site with no
  preflight. curl, the MCP stdio bridge, Cursor and Claude Code send no `Origin` and are unaffected.
* **The `Host` header is validated**, which is what stops DNS rebinding.
* **Settings → Security: a password and a PIN.** Both are required, both are asked for on one login page, and
  both are stored as salted PBKDF2-SHA256 hashes in `auth.json` in the data dir — never in `settings.json`, and
  never returned by any endpoint. The session is an HttpOnly, SameSite=strict cookie that lasts 12 hours and
  lives in memory on the server, so restarting Iris signs everyone out. Repeated failures are throttled per
  client (5 tries, then 30 s doubling to 15 min) because a short PIN is otherwise guessable. Forgotten both?
  `docker exec iris rm /data/auth.json` and the login is gone — this control assumes you own the disk.
  It keeps a person at the keyboard, and a page open in your browser, out of the pool; it is **not** encryption
  of the evidence, and a PIN stored next to the password is not a second factor in the phone-app sense.
* **`IRIS_AUTH_TOKEN`** is the same gate for clients that cannot sign in — curl, scripts, the MCP stdio bridge.
  Set it as well as (not instead of) the login when the port is reachable from anywhere else.

Loopback binding is **not** a defence against a malicious web page: a browser running on this machine reaches
`http://localhost:8000` whatever the bind address is. It defends against the network, and nothing else.

Two things to know about what is on disk: `settings.json` in the data dir holds `ai.apiKey` and `mcp.token`
**in the clear** (they are masked in the API and the UI, never in the file) — that is normal for a credential
store, but the data dir is the bind mount you back up and copy around. And AI conversation transcripts in
`ai/history.json` quote log lines verbatim, so they are evidence: `clear all data` deletes them for that reason.

### Automatic sizing
Iris sizes its worker pools itself on every start, from what the **process can actually use** — not
from the host's core count:
- **Cores**: the affinity mask, then a container CPU quota (`--cpus`, `deploy.resources`). Two are
  kept for the API process (measured: with one, `/api/health` stalled 3-7 s whenever a pool started).
  SMT siblings count at 1.5x the physical cores — on the 8-logical/4-physical host this was measured
  on, every pool saturated at six, and hyper-threads are not cores for pure-Python string work.
- **Memory**: the cgroup limit inside a container, otherwise free RAM, minus 2 GB reserved for the
  pool itself; each parse worker is budgeted 512 MB, each graph worker 300 MB, each enrichment lane
  768 MB (a whole small file per worker).
- **Ceiling 32** per pool — past that the parent (unpickling and merging every worker's result) is the
  bottleneck and more workers only cost memory.
So a 50-core / 256 GB box gets 32 parse and graph workers; a laptop with 4 cores gets 2; a container
given `--cpus=4` gets 2 whatever the host has. Settings → Compute shows the machine, the numbers and
the reasoning; `start.*` prints them; the `IRIS_*_WORKERS` variables below pin any one of them.
**On Docker Desktop for Windows the container sees the WSL 2 VM, not the host** — WSL's default is
half the RAM — so `.\wsl.ps1 -Apply` writes `memory` (75 % of the host), `swap` and `processors`
into `.wslconfig` from the machine's real hardware; `setup.ps1` prints both sides in its preflight.

### Performance and limits (rarely needed)
| Variable | Default | What it does |
|---|---|---|
| `IRIS_POOL_MAX_MB` | **unset — unlimited** | Megabytes of **source log** the pool may load at startup. There is no cap by default: a file that was uploaded as evidence and is not in search is worse than a slow Iris, because nothing about a search tells you it was answered over part of the corpus. Set it (a shared box, a small VM) and anything over the cap stays in the library, listed by name, loadable one file at a time. Not a RAM figure — parsed events cost several times the source bytes. |
| `IRIS_AUTO_ENRICH` | `0` (off) | Seeds `settings.ingest.autoEnrich` on first run. `0` = a log lands as raw searchable lines and phase 2 (timestamps, fields, entities, detections) never starts on its own — see *Two-phase ingest* below. Like every `IRIS_*` variable it only seeds settings the first time; after that Settings wins. |
| `IRIS_PARSE_WORKERS` | **derived** (see *Automatic sizing*) | Parallel parse workers for files over `IRIS_PARSE_MIN_MB`. `1` disables parallel parsing. |
| `IRIS_ENRICH_WORKERS` | **derived**, at most half the parse count | Lanes that interpret SMALL sources in parallel during phase 2. `1` = one at a time. |
| `IRIS_PARSE_MIN_MB` | 32 | File size above which parallel parsing kicks in. |
| `IRIS_PARSE_CHUNK_MB` | 4 | Byte-range chunk size per worker, in MB. |
| `IRIS_GRAPH_WORKERS` | **derived** (see *Automatic sizing*) | Entity-extraction workers. `1` disables parallel graph building. |
| `IRIS_GRAPH_PARALLEL_MIN` | 50 000 | Events below which the graph is built in-process. |
| `IRIS_GRAPH_CHUNK` | 25 000 | Events per graph chunk. |
| `IRIS_GRAPH_CACHE` | `1` | `0` disables persisting the built graph to `cache/graph-<scope>.pkl`. |
| `IRIS_GRAPH_AUTOBUILD` | `1` | The entity graph starts building on its own once the workspace settles, instead of waiting for you to open the Graph screen. `0` disables it. |
| `IRIS_GRAPH_AUTOBUILD_QUIET` | `20` | Seconds of no change before that automatic build starts. It never runs while sources are loading or enriching. |
| `IRIS_INDEX_CACHE` | `1` | `0` disables persisting the packed search index to `cache/search-index.iris`. With it on, a restart reads the index back in seconds instead of re-packing every event (165 s on an 11 M-event pool, during which every search is slow). |
| `IRIS_POOL_CACHE` | `1` | `0` disables the parsed-pool cache (`cache/pool/`). With it on, a restart restores parsed, already-interpreted events instead of re-reading and re-enriching every staged file. Costs disk (roughly the size of the parsed events); `Clear all data` deletes it. |
| `IRIS_GRAPH_TIMING` | unset | Log a per-phase breakdown of each graph build. |
| `IRIS_GRAPH_SYNC_MAX` / `IRIS_ANALYSIS_SYNC_MAX` / `IRIS_ANOMALY_SYNC_MAX` | 20 000 | Event count above which these are built in the background instead of on the request. |
| `IRIS_GPU_INDEX_MAX` | auto (≤ 50 % of free VRAM) | Bytes of search index allowed on the GPU. `0` keeps it on numpy. |
| `IRIS_CUPY` / `IRIS_TORCH_INDEX` | auto per driver | Override the GPU wheels `setup.* local` picks. |

---

# Using the app

The left sidebar is a fixed text nav (no icons); groups collapse, and items within a group can be dragged into your own order.

**A case is optional.** Search, detections, the entity graph and event detail read the whole ingested pool and work
with no case at all. A case adds curation: a timeline, notes, indicators, accepted graph links and the report.

### 1. Sources
Drop files on the drop zone or click **Choose files**. Everything lands in the workspace, parsed and searchable at
once; filing a log into a case is a separate step on the row afterwards.

Supported: text logs (nginx/syslog/plaintext), `.evtx` and EVTX XML, JSON/JSONL/CloudTrail/k8s audit, CSV/TSV/
pipe-delimited, SQLite databases, packet captures (`.pcap`/`.pcapng`/`.cap`), `.eml`/`.mbox`/`.msg`, PDF, XLSX/XLS, DOCX, images via OCR, memory/binary dumps
(strings + IOC extraction), and `zip`/`tar`/`gz`/`bz2`/`xz`/`7z` archives (nested to depth 3). Unknown layouts land
in state **MAP** — click the row to edit the field mapping or press **Suggest with AI**.

Timestamps are read in ISO-8601, nginx, syslog, Kibana and common locale shapes, and as a bare **epoch** in seconds,
milliseconds, microseconds or nanoseconds (10 / 13 / 16 / 19 digits, with or without a fraction) — a log whose only
clock is `1724580000123` sorts and windows like any other. The unit comes from the digit count.

* Filter by name/parser and by state; per-source size and a combined total.
* **Live parse progress**, and a warning naming any file that is **not** in the pool — a file absent from search is
  indistinguishable from a search that found nothing.
* Transfers **clear themselves**. Once a file is ingested *and* parsed, its transfer row ages out on its own (about
  20 seconds) — the file is in the Sources table right below it with its parser, state and event count, so the row
  has nothing left to say. A **failed** transfer stays for 30 minutes and has to be dismissed: it is the one thing
  on that panel restated nowhere else, and clearing it automatically would silently drop the report that evidence
  never made it into the pool.
* Click a row to open the **raw log viewer** (numbered pages, server-side line filter). Structured and binary
  sources show their parsed records instead of bytes. **Detach** turns it into a floating window you can drag and
  resize anywhere; the choice is remembered.
* The last column is **Delete** — it removes the events from the workspace *and* the file from disk. There is no
  trash for sources; the confirm says so.

**Two-phase ingest.** A text log is searchable the moment it is uploaded, but nothing about it is *understood* yet.
Phase 1 lands the raw lines; phase 2 — the real parser plus timestamps, severity, fields, entities and detections —
runs afterwards on one background worker, because that second half is 83–89 % of the cost of ingesting a log and it
is paid whether the file yields useful fields or none. Each row carries an **enrich** chip:

| chip | what it means |
|---|---|
| `raw` | in the pool and searchable as text — **no timestamps, no severities, no fields, no entities, no detections**. This source is invisible to the timeline, the entity graph and the anomaly list. |
| `queued` | waiting for the worker. |
| `enriching` | being parsed right now. |
| `enriched` | done. Also the starting state of anything with no raw form (EVTX, SQLite, PDF, XLSX, OCR, mail, packet captures) — those parse fully on upload. |
| `skipped` | you declined phase 2. It stays raw on purpose and raises no warning. |
| `error` | phase 2 failed; the message is on the row. The raw lines are still in the pool — nothing was lost — and **Enrich now** retries it. |

Per row: **Enrich now** (queues it immediately, even with auto-enrich off) and **Skip** (leaves it raw). A source
being enriched right now cannot be skipped — the parse is already running and will replace its events when it
lands. While anything is still `raw`, `queued` or `enriching`, a workspace banner says so and Timeline, Graph and
Anomalies mark themselves incomplete: those screens are answering over part of the corpus, and an empty graph that
really means "not enriched yet" would be a lie about the evidence. **Settings → Compute → Two-phase ingest** turns the automatic
behaviour off if you want raw text and nothing else.

### 2. Search
Press `/` to focus. Examples:
`user:svc_deploy AND src_ip:45.83.140.22` · `sev:critical` · `source:aws.cloudtrail NOT errorCode:AccessDenied` ·
`"bulk export"` · `host:bastion*` · `entity:"10.0.0.1"` (exact) · `path:C\:\Windows` (escaped colon)

* **Columns are configurable** — built-ins plus any parsed field (status codes, `src_ip`, `EventID`), remembered
  per browser. The message column shows the **raw line** by default; normalized `msg` is available as its own column.
* **Every value is a filter**: `+` narrows to it, `−` excludes it. Same on the fields rail.
* Above 2 000 events the search runs through a vectorized index — on the GPU when CUDA is active. The status line
  under the filters shows the hit count, the engine badge and `index warming N %` while it builds.

### 3. Cases
The Cases page is a card grid (a filter/sort toolbar appears above three cases). Name and analyst are edited
inline. Deleting a case moves it to the trash (last 5 kept) — **Recently deleted** restores it.

**Export report** (top right, for the active case) builds and downloads the report as Markdown, PDF, JSON or a
STIX 2.1 bundle — the same file `GET /api/report/export` serves.

Inside a case: the **timeline**, **notes** (markdown, paste screenshots), **indicators** and its **sources**.

Deleting a case also takes the files it had **attached** out of the workspace (they are in the trash with the case,
not in the library any more), so their detections and graph findings go with it. Files you never filed into the
case stay in the library.

**The timeline** is the curated events in time order, grouped under sticky date headings, with the gap since the
previous entry (`+3m 12s`) so the pace of the sequence is visible. Each row leads with **your** sentence — the
first line of the note — and shows the clock, severity and labels; an entry you have not written up yet falls back
to the log's own message, in mono, so it is clear whose words those are.

**Click any row to open it.** The log line is in there, not on the row: the event id to cite, the full UTC
timestamp, the file and host and user, your note and labels with their editor, then the **raw line exactly as the
log recorded it**, the fields parsed out of it, the entities it mentions and the detections it fired — plus a
button through to the full event page. Several entries can be open at once, so two moments can be compared side by
side. Add lines from a file in this case or from Search; the header line says how many events, what window they
span and how many are annotated.

### 4. Anomalies and rules
The anomaly list and the rule catalogue, each with a text filter and chips that carry their own counts. A rule has
four separate pieces: an analyst-editable **description** (prose, matches nothing), a read-only **trigger** (what
the engine actually evaluates), its **mechanism**, and **params** — every constant in the condition, editable and
validated. Custom rules are a raw regex or a list of typed conditions with an optional threshold.

#### Exclusions
Some things are never the finding. A public DNS resolver answers for every host you own, a monitoring
probe hits the same path forever, and a Windows machine account authenticates all day — and a rule that
reports them on every ingest teaches you to skim past that rule, which is the day it stops working.

**Anomalies → Exclusions** manages them. An exclusion is a name plus conditions (the same field / operator
/ value builder custom rules use), scoped either to **every rule** or to the rules you choose. It
suppresses the **detection**, never the event: the line stays in the pool, in search, in the raw viewer
and on the timeline.

* **Nothing is excluded until you add it.** Iris offers a suggested list — public resolvers, loopback,
  NTP, machine accounts, Kubernetes system identities, health checkers — each with the reason stated.
  Adding one is a click; none is applied for you. (A resolver being benign infrastructure is exactly what
  makes it useful for DNS tunnelling, so that judgement is yours.)
* **Every row says how much it hid.** The count is detections suppressed on the last pass; `—` means
  nothing has been re-evaluated since it changed. An exclusion suppressing nothing is usually wrong.
* Exclusions marked *events only* cannot be applied to entity-graph findings, because their conditions
  read event fields and a graph node has only a type and a value. That is stated, never guessed.
* The AI assistant can manage them too (`list_exclusions`, `add_exclusion`, `delete_exclusion`), and every
  change it makes is undoable with that run.

#### Entity-graph rules
Some findings cannot be phrased as "is this line suspicious?" — one address authenticating as fourteen
different accounts is a property of the **shape** of the relationships, and every one of those lines is
unremarkable on its own. Iris ships ten rules that read the entity graph instead, listed on **Anomalies →
Graph findings**:

| Rule | What it looks for |
|---|---|
| `SIGMA-GRAPH-0010` | one address, many accounts (spray, shared credentials, a jump box) |
| `SIGMA-GRAPH-0014` | one account, many addresses |
| `SIGMA-GRAPH-0018` | a host reaching many different public addresses |
| `SIGMA-GRAPH-0022` | the same file or hash present on many hosts |
| `SIGMA-GRAPH-0026` | an entity that appears across many log files — the pivot |
| `SIGMA-GRAPH-0030` | a relationship that is almost entirely failures or denials |
| `SIGMA-GRAPH-0034` | a domain answering with many addresses (fast flux) |
| `SIGMA-GRAPH-0038` | one account touching many hosts (lateral movement) |
| `SIGMA-GRAPH-0042` | a one-off account on a host everything else uses constantly |
| `SIGMA-GRAPH-0046` | a well-connected entity that also fired detections |

They are ordinary built-ins in the rule catalogue: switch one off, retune its thresholds, restore it.
What differs is what they read and what they produce — a finding names the **entity** and links to the
graph focused on it and to its events. They are computed from the entity graph, so the section says
*waiting for the entity graph* until that is built rather than showing an empty list.

### 5. Entity graph
Live force layout on a canvas. Drag nodes (toggle *Pin after drag*), drag empty space to pan, wheel to zoom,
double-click / `⌂` / `0` fits, arrows pan (Shift = faster), `+`/`−` zoom.

* **Nothing is selected at first** — pick the logs to graph. A graph over every source at once is a hairball.
  The selection persists until you clear it.
* **Search** filters the whole graph, not just what is drawn, and keeps each match's direct neighbours.
* **min link events** = relationship *strength*: hides links supported by fewer than N events, then any node left
  with no links.
* **min connections** = how *connected* an entity is: hides nodes with fewer than N links in the graph being
  shown. A different question — an IP seen once, attached to one busy host, survives any link-event threshold but
  not this one. The hint line says how many nodes it hid.
* *seen with* (co-occurrence) is hidden by default: it is true of nearly every pair in a busy log.
* Click a node for its facts and linked entities; **Search** on a node opens exactly that entity's events.

### 6. AI assistant
Open the panel, type an objective in your own words ("trace every event involving this IP and build me a case").
The agent uses Iris's own tools and streams each step. Everything it writes is listed as it happens and
**Revert all** takes the whole run back off the case. Indicators, notes and graph links it creates must cite real
event ids or the call is refused. Conversations persist server-side — closing the tab does not stop the run, and
**Stop** halts it on the server.

**Detach** turns the panel into a floating window you can drag and resize — put it beside the search results and
read the evidence it is citing while it works, instead of opening and closing a slide-over that covers the page.
**Dock** puts it back, and the choice and the window's geometry are both remembered. Detached it is not modal: the
page underneath stays clickable and <kbd>Esc</kbd> no longer closes it (that would throw away a half-written
objective); use the × on the title bar.

**System prompts.** Settings → **System prompts** holds *additional* instructions for investigations — a report
format, what counts as critical in your environment, sources to distrust, the questions a phishing case always has to
answer. A saved prompt is always **added to** the built-in prompt. The built-in prompt itself is editable there too
(*Edit built-in prompt*, with *Restore shipped prompt* to go back) — it carries the rules on searching, citing real
event ids and stopping, so edit it knowingly; the citation check itself lives in code and stays. Pick one as the **default**; the **Prompt** chip under the
assistant's composer opens a menu to run a question with a specific saved prompt, or with the built-in prompt alone — and to edit a
saved prompt or add a new one right there, without leaving the chat. *View effective* shows the exact
text the model receives, and the built-in prompt is readable there too. Saved prompts live in
`ai/system_prompts.json` in the data directory and are kept by *Clear all data*, like rules.

### 7. Settings
**Appearance** (9 themes + the interface and monospace face + density; the default is *Iris dark*, the
observability console palette — teal on graphite, IBM Plex Sans over JetBrains Mono) · **Compute** (GPU list, live utilization / VRAM / temp / power / CPU / RSS /
parse throughput sampled every 2 s with 2–30 min charts, mode auto / CUDA / CPU, *Re-check now*, and
**Two-phase ingest** — the auto-enrich toggle, which schedules *when* the expensive parse runs, not whether
it runs) · **AI assistant**
(enable, model, key, *Test connection*; **run limits** — how many tool-calling steps, seconds and case
writes one investigation may spend, or **off** for a case that has to be worked to the end; Advanced → base
URL, TLS verification, custom CA bundle) · **System prompts**
(save / edit standing instructions for the assistant, pick the default — see §6) · **MCP server**
(below) · **Data** (**Clear all data**, behind a type-the-phrase confirm — it wipes cases, trash, library, the pool,
jobs and AI conversations; rules and settings are kept, and the panel says so).

---

# Let Cursor / Claude Code use Iris (MCP)
Settings → **MCP server** (collapsible, off by default) turns Iris into an MCP server at
`http://127.0.0.1:8000/api/mcp`, offering the same tools the built-in assistant uses. Paste the config it shows
into `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project), or run the `claude mcp add` command it prints.
Writes are a separate switch and an optional bearer token gates the endpoint — the generated token is shown in the
clear exactly once. Full guide, including the stdio bridge for clients without HTTP transport: **`docs/MCP.md`**.

# Run without Docker (dev mode)
```bash
cd backend  && pip install -r requirements.txt && uvicorn app.main:app --reload --port 8000
cd frontend && npm install --ignore-scripts && npm run dev   # UI at http://localhost:5173 (proxies /api → :8000)
# optional GPU: pip install -r backend/requirements-gpu.txt   (needs a CUDA 12.x driver)
```
Frontend build/type-check: `cd frontend && npm run build`

# Handy API calls (curl)
```bash
curl 127.0.0.1:8000/api/health
curl -F "files=@/path/to/access.log" -F "files=@/path/to/x.evtx" 127.0.0.1:8000/api/sources
curl "127.0.0.1:8000/api/events?q=user:svc_deploy&sev=critical,high&limit=50"
curl "127.0.0.1:8000/api/graph?limit=200&minCount=3&minDegree=2"      # link strength + how connected
curl "127.0.0.1:8000/api/graph?limit=200&q=10.0.0.1"                  # searches the WHOLE graph
curl 127.0.0.1:8000/api/anomalies
curl 127.0.0.1:8000/api/timeline
curl 127.0.0.1:8000/api/library                                        # every staged file: parser, state, events
curl 127.0.0.1:8000/api/report
curl -o report.md "127.0.0.1:8000/api/report/export?format=md"        # md | json | stix | pdf
curl 127.0.0.1:8000/api/compute
curl -X POST 127.0.0.1:8000/api/compute/recheck
curl "127.0.0.1:8000/api/compute/metrics?window=150"                  # live GPU/process/throughput samples (2 s)
curl 127.0.0.1:8000/api/parsers                                        # supported file types + availability (OCR etc.)
curl -X POST 127.0.0.1:8000/api/sources/<id>/mapping/suggest          # AI/heuristic field-mapping suggestion
curl -X POST -H 'content-type: application/json' -d '{"resetSettings":false}' 127.0.0.1:8000/api/admin/clear-all
```
```bash
# two-phase ingest: enrich one source now / decline it, and see what is outstanding
curl -X POST 127.0.0.1:8000/api/sources/<sid>/enrich
curl -X POST 127.0.0.1:8000/api/sources/<sid>/enrich/skip
curl -s 127.0.0.1:8000/api/case | python -c "import json,sys; print(json.load(sys.stdin)['enrichment'])"
curl -X PUT -H 'content-type: application/json' -d '{"ingest":{"autoEnrich":false}}' 127.0.0.1:8000/api/settings
```
Full contract: `docs/API_CONTRACT.md`.

# Troubleshooting
- **A timeline entry says "event not in the pool"** — the log line it points at is not loaded right now
  (its source was deleted, or the file has not finished parsing). The entry itself is never discarded: it
  keeps your labels and note, and it re-points itself at the line as soon as that line is back, even if the
  event id changed.
- **The app updated but the screen looks the same** — four caches sit between an edit and what you see, and
  the launcher now closes three of them for you. Check them in this order:
  1. **The build.** `start.*` compares the tree against `frontend/dist` (local) or against the image's build
     time (docker) and rebuilds when yours is newer, naming the file that changed. If step `[2]` said
     `is current` and you still expect a change, your edit is not in one of the paths it watches — force it:
     `./start.sh --build` / `.\start.ps1 -Build`.
  2. **The container.** Both scripts pass `--force-recreate`, so a running container cannot stay on its old
     image. A hand-run `docker compose up -d` does not — see *Plain `docker compose`* above.
  3. **A second Iris.** `local` mode refuses to start when something already serves that port, because
     otherwise you end up reading the old instance. Docker mode cannot detect that — check `docker ps`.
  4. **Your browser**, the one thing no script can reach. Hard-refresh once: **Ctrl+Shift+R**
     (Windows/Linux) or **Cmd+Shift+R** (macOS). Iris serves `index.html` with `Cache-Control: no-store`
     and its hashed assets as immutable, so this should only ever be needed for a copy cached before that
     header existed. To see what the server actually sends:
     `curl -s -D- -o /dev/null http://127.0.0.1:8000/ | grep -i cache` (use `-D-`, not `-I` — the page route
     answers HEAD with 405).
- **The app is slow right after starting** — it is re-parsing the library into the pool, and the entity graph is
  restored or rebuilt after that. `./start.sh status` (or the Sources page) says how many files are left. Derived
  builds are deliberately paused until the load finishes.
- **A file is missing from search** — Sources names it and why. `budget`/`unreadable` mean it was never parsed
  (raise `IRIS_POOL_MAX_MB`, or load that one file anyway from the library list); `parse-error` means it *was*
  parsed and the parser failed; `not-parsed` is an archive only expanded on attach.
- **A file is searchable but has no timestamp, fields or detections** — it is still `raw`: phase 2 has not run.
  The Sources row says so; press **Enrich now**, or turn `Auto-enrich` back on. Nothing is lost either way — the
  raw lines are in the pool and stay there.
- **Nothing is enriching and the queue never moves** — the pool is probably still loading (enrichment yields to it
  by design), or auto-enrich is off and nothing has been asked for. `GET /api/case` → `enrichment` says which:
  `pending` is work in flight, `outstanding` is how much of the corpus is not interpreted yet.
- **A `.db-wal` / `-shm` / `-journal` file is refused** — those are SQLite siblings, not databases. Iris opens a
  database `immutable=1`, which never replays a WAL, so uncheckpointed rows are missing; on a live browser profile
  that is the newest activity. Check the database in first.
- **AI Test connection fails with `CERTIFICATE_VERIFY_FAILED … self-signed certificate`** — a corporate proxy or
  antivirus is re-signing HTTPS. Export its root CA as PEM into the data dir; Iris picks it up automatically:
  `docker cp corp-root.pem iris:/data/ca.pem` (or set `IRIS_CA_BUNDLE`, or type the path in Settings → AI →
  Advanced → *Custom CA bundle*). The Settings field must name a file **inside the data dir** — a bare name or a
  relative path is taken as relative to it, and anything outside is ignored (it is settable over the API, and an
  arbitrary path there is a way to ask the server which files exist). `IRIS_CA_BUNDLE` is not restricted: whoever
  starts the process can already read the disk. Last resort: turn off *Verify TLS certificates* (insecure). On Windows, export
  from `certmgr.msc` → Trusted Root → Export → Base-64 X.509 (.CER) → rename to `.pem`.
- **Something is filling `%TEMP%`** — almost certainly `%TEMP%\wsl-crashes`. When a process inside the
  WSL VM segfaults, WSL writes a CORE DUMP of it there, and a dump of Iris is the size of the pool it
  was holding: four of them in one afternoon came to **146 GB**, one of them 116.5 GB. Worse than the
  disk: that dump contains your log contents in plaintext, in a temp directory. `.wslconfig` now
  carries `maxCrashDumpCount=0` (applied by `wsl.ps1 -Apply`), which stops them being written; delete
  any existing ones from `%TEMP%\wsl-crashes`. Raise the count only while diagnosing a crash, and
  clear the folder afterwards.
- **Docker is eating my C: drive** — two separate things, and the first hides the second.
  `./start.sh --build` (or `.\start.ps1 -Build`) now removes the image each build replaces and trims
  the build cache to 10 GB, so the space is freed *inside* Docker automatically. But Docker's virtual
  disk on Windows (`%LOCALAPPDATA%\Docker\wsl\disk\docker_data.vhdx`) never shrinks: it grew to
  63 GB here while holding 27 GB. Make it sparse once, with Docker Desktop closed, and freed blocks
  come back to Windows from then on:
  `wsl --terminate docker-desktop` then `wsl --manage docker-desktop --set-sparse true` (WSL 2.3+).
  Verify with `fsutil sparse queryflag "%LOCALAPPDATA%\Docker\wsl\disk\docker_data.vhdx"`.
  Iris's own data is NOT in there — it lives in the bind-mounted data dir, where `cache/` holds the
  saved graph, the parsed pool and the search index. Deleting `cache/` is always safe (it costs one
  rebuild), and `Clear all data` removes it along with everything else.
- **Settings → Compute says CPU but I have an NVIDIA GPU** — run
  `docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi`. If that fails: Windows → Docker
  Desktop must use the WSL 2 backend + a current Windows driver (`wsl --update`); Linux → install the NVIDIA
  Container Toolkit, `sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker`. Then
  re-run setup in `gpu` mode — the CPU image never has cupy installed.
- **Port 8000 in use** — `.\start.ps1 -Port 8080` / `./start.sh --port=8080`, or change the left side of
  `ports: "8000:8000"` in `docker-compose.yml`. On Windows, `127.0.0.1:8000` can also be squatted by another WSL
  relay while `127.0.0.1:8000` works — try the explicit IP before assuming Iris is down.
- **Docker not running** — the setup scripts start Docker Desktop for you; otherwise start it and re-run.
- **Container keeps restarting / segfaults during a big load (Windows)** — run `.\wsl.ps1`, apply the settings, and
  `wsl --shutdown` when you can afford to stop your containers.
- **Wipe everything** — Settings → Data → *Clear all data* empties the workspace but leaves Iris installed.
  `docker compose down -v` does **not** wipe it either: the evidence is a bind mount at `./backend/data`, not a
  volume. To remove the install as well, see [`uninstall.*`](#uninstall--removing-iris) — and note that it too
  keeps your data unless you pass `--purge-data` / `-PurgeData`.
- **Sources table looks empty after upload** — files parse in the background; the state pill shows PARSING with
  the phase, percentage, event count and ETA (hover it for bytes and rate), then READY / REVIEW / MAP / ERROR
  (hover ERROR for the reason). Once the file is READY, the *Interpreted* chip carries the same percentage for
  phase 2, which on a large capture is the longer half.
- **A file shows PARSING with "no progress reported yet"** — nothing is working on it *right now*. The
  usual reason is that automatic interpretation is off (Settings → the `autoEnrich` ingest setting): the
  lines are in the pool and searchable, and phase 2 waits for you to ask. Use *Interpret now* on the row,
  or turn automatic interpretation back on. Iris says this instead of showing a 0 % bar, because a bar
  that never moves cannot be told apart from a hang.
- **The Sources strip says *Merging interpreted sources into the pool* or *Re-checking windowed
  detection rules*** — both are normal. The first is one rebuild of the whole pool index after a batch of
  files finishes interpreting (minutes on a workspace of millions of events; the strip shows which step
  and for how long). The second runs in the background after that (and once after every restart) and holds nothing up: search, the
  timeline and the graph already have the new events. Only the *windowed* rules (bursts, sprays) need the
  whole pool re-read; every per-event rule was applied before the events went in.
- **The graph shows *N sources still interpreting — graph covers M*** — the entity graph no longer waits for
  every source to finish interpreting: it builds from the ones that are ready and each remaining source joins
  the moment it lands. Small files are interpreted several at a time in worker processes; large ones are split
  across workers as before.
- **A drop of many files shows some as *waiting its turn*** — that is normal and healthy: Iris sends three files
  at a time and the rest queue. They are not stalled, and the tab tells the server they are still coming, so they
  are not failed either. Leave the tab open: **closing it abandons everything that has not been sent yet**, and
  those rows turn into *this transfer never started* about ten minutes later.
