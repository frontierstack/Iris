#!/usr/bin/env bash
# Iris start script (Linux / WSL / macOS).
#
#   ./start.sh                # Docker: bring the whole app up (CUDA image if one was built)
#   ./start.sh local          # no Docker: build the frontend if needed, run uvicorn on this machine
#   ./start.sh --build        # force a rebuild of the image before starting
#   ./start.sh restart        # stop, then start
#   ./start.sh stop           # stop the container
#   ./start.sh logs           # follow the container logs
#   ./start.sh status         # is it up, what is it doing, and how big is the pool
#   ./start.sh --no-browser   # don't open http://localhost:8000
#
# One container serves EVERYTHING: the FastAPI API under /api and the built React SPA at /. First-time
# setup (GPU wheel resolution, Docker checks) lives in setup.sh — this script starts what is already set
# up, and builds the image itself if it never has been.
#
# Every long operation prints a numbered step, a live spinner with elapsed time and WHAT it is waiting
# for, and a result line. A script that prints nothing for two minutes looks exactly like a hung one.
set -uo pipefail
cd "$(dirname "$0")"

MODE=docker
BUILD=0
OPEN=1
PORT="${IRIS_PORT:-8000}"

for arg in "$@"; do
  case "$arg" in
    docker|local|stop|restart|logs|status) MODE="$arg" ;;
    --build|-b)      BUILD=1 ;;
    --no-browser|-n) OPEN=0 ;;
    --port=*)        PORT="${arg#*=}" ;;
    -h|--help)       sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "[iris] unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

URL="http://localhost:${PORT}"
START_TS=$(date +%s)
STEP=0

if [ -t 1 ]; then C_DIM=$'\033[90m'; C_CY=$'\033[36m'; C_GR=$'\033[32m'; C_YE=$'\033[33m'; C_RE=$'\033[31m'; C_0=$'\033[0m'
else C_DIM=''; C_CY=''; C_GR=''; C_YE=''; C_RE=''; C_0=''; fi

step() { STEP=$((STEP+1)); printf '%s[%d]%s %s%s%s\n' "$C_DIM" "$STEP" "$C_0" "$C_CY" "$*" "$C_0"; }
ok()   { printf '    %sOK%s  %s\n' "$C_GR" "$C_0" "$*"; }
info() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_0"; }
warn() { printf '    %s!   %s%s\n' "$C_YE" "$*" "$C_0"; }
die()  { printf '    %sX   %s%s\n' "$C_RE" "$*" "$C_0" >&2; exit 1; }

# spin <label> <timeout> <until-cmd> [detail-cmd]
# until-cmd returns 0 when the wait is over; detail-cmd prints a one-line status shown beside the spinner.
spin() {
  local label="$1" timeout="$2" until_cmd="$3" detail_cmd="${4:-}"
  local frames='|/-\' i=0 t0 el detail line last_tick=-10
  t0=$(date +%s)
  while :; do
    if eval "$until_cmd" >/dev/null 2>&1; then
      [ -t 1 ] && printf '\r%*s\r' 120 ''
      return 0
    fi
    el=$(( $(date +%s) - t0 ))
    if [ "$el" -ge "$timeout" ]; then
      [ -t 1 ] && printf '\r%*s\r' 120 ''
      return 1
    fi
    detail=''
    [ -n "$detail_cmd" ] && detail=$(eval "$detail_cmd" 2>/dev/null)
    if [ -t 1 ]; then
      line=$(printf '    %s %s  %ss  %s' "${frames:i%4:1}" "$label" "$el" "$detail")
      printf '\r%s%-118.118s%s' "$C_DIM" "$line" "$C_0"
    elif [ $(( el - last_tick )) -ge 10 ]; then
      # Redirected (a log file, CI): \r does not collapse, so an animated spinner writes one enormous
      # line. A plain line every 10s carries the same information and stays readable afterwards.
      last_tick=$el
      printf '    ... %s  %ss  %s\n' "$label" "$el" "$detail"
    fi
    sleep 1
    i=$((i+1))
  done
}

# The interpreter used for the little JSON formatters below. Resolved once, and TESTED: on Windows,
# `python3` exists in PATH as a Microsoft Store stub that prints an advert and exits non-zero, so
# `command -v` finding it proves nothing. Whichever candidate can actually run `-c` wins.
PY_BIN=""
for _cand in python3 python py; do
  if command -v "$_cand" >/dev/null 2>&1 && "$_cand" -c "import sys" >/dev/null 2>&1; then
    PY_BIN=$(command -v "$_cand"); break
  fi
done

api() {   # api <path> -> body on stdout, non-zero when it did not answer
  if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 5 "$URL$1" 2>/dev/null
  elif [ -n "$PY_BIN" ]; then "$PY_BIN" -c "import urllib.request,sys;sys.stdout.write(urllib.request.urlopen('$URL$1',timeout=5).read().decode())" 2>/dev/null
  else return 1; fi
}
# The formatters keep to SIMPLE f-string fields and pull every subscript into a local first: a nested
# same-quote f-string (f"{d["k"]}") is a syntax error before Python 3.12, and the whole program is inside
# bash single quotes so an inner single quote is not available either.
json_fmt() {   # json_fmt <python-program>  — reads stdin, prints nothing if anything goes wrong
  [ -n "$PY_BIN" ] || return 0
  "$PY_BIN" -c "$1" 2>/dev/null
}

healthy() { api /api/health | grep -q '"ok":true'; }
pool_detail() {
  api /api/case | json_fmt '
import sys, json
d = json.load(sys.stdin)
n = d.get("poolEventCount", 0)
if d.get("poolLoading"):
    done = d.get("poolLoaded", 0)
    total = done + d.get("poolPending", 0)
    prog = d.get("poolProgress") or {}
    pct = int(prog.get("pct") or 0)
    # bytes and files are the live signal; the event count only moves when a batch merges into the pool
    # (Store.BULK_FLUSH_EVENTS), so per-tick it looks frozen and worries people
    print(f"parsing library {done}/{total} files, {pct}% of bytes")
else:
    print(f"{n:,} events in the pool")
'
}
pool_loading() { api /api/case | grep -q '"poolLoading":true'; }

summary() {
  local h c ver
  h=$(api /api/health)
  c=$(api /api/case)
  ver=$(echo "$h" | sed -n 's/.*"version":"\([^"]*\)".*/v\1/p')
  echo
  printf "  %sIris is up%s  %s%s%s\n" "$C_GR" "$C_0" "$C_DIM" "$ver" "$C_0"
  printf "  %s\n" "$URL"
  api /api/compute | json_fmt '
import sys, json
d = json.load(sys.stdin)
gpus = d.get("gpus") or []
gpu = "CPU (numpy)"
if d.get("active") == "cuda" and gpus:
    name = gpus[0].get("name", "GPU")
    backend = d.get("backend", "")
    gpu = name + " - " + str(backend)
print("  compute   " + gpu)
'
  echo "$c" | json_fmt '
import sys, json
d = json.load(sys.stdin)
n = d.get("poolEventCount", 0)
srcs = len(d.get("sources") or []) + len(d.get("librarySources") or [])
print(f"  pool      {n:,} events across {srcs} source(s)")
pending = d.get("poolPending", 0)
if d.get("poolLoading"):
    print(f"  loading   still parsing the library ({pending} file(s) to go)")
skipped = d.get("poolSkipped", 0)
if skipped:
    print(f"  skipped   {skipped} file(s) NOT in the pool - Sources says which and why")
'
  printf "  %slogs      ./start.sh logs        stop  ./start.sh stop%s\n" "$C_DIM" "$C_0"
  printf "  %stotal     %ss%s\n" "$C_DIM" "$(( $(date +%s) - START_TS ))" "$C_0"
  echo
}

open_app() {
  [ "$OPEN" = "1" ] || return 0
  if   command -v xdg-open     >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 &
  elif command -v open         >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1 &
  elif command -v wslview      >/dev/null 2>&1; then wslview "$URL" >/dev/null 2>&1 &
  elif command -v explorer.exe >/dev/null 2>&1; then explorer.exe "$URL" >/dev/null 2>&1 &
  fi
  return 0
}

# ── local (no Docker) ────────────────────────────────────────────────────────
if [ "$MODE" = "local" ]; then
  step "Checking Python"
  PY="$PY_BIN"
  [ -n "$PY" ] || die "python not found. Install Python 3.11+ or run ./setup.sh local"
  ok "$("$PY" --version 2>&1)"
  if [ ! -f frontend/dist/index.html ]; then
    step "Building the UI (frontend/dist is missing)"
    if command -v npm >/dev/null 2>&1; then
      ( cd frontend && { [ -d node_modules ] || npm ci --ignore-scripts; } && npm run build ) || die "frontend build failed"
      ok "frontend built"
    else
      warn "npm not found - only the API at $URL/api will respond"
    fi
  fi
  [ -f .env ] || { [ -f .env.example ] && cp .env.example .env; }
  step "Starting Iris (uvicorn) on port $PORT"
  info "Ctrl-C stops it"
  if [ "$OPEN" = "1" ]; then ( spin "waiting for the API" 300 healthy >/dev/null && open_app ) & fi
  cd backend
  # Loopback by DEFAULT: Iris has no authentication, so 0.0.0.0 offered the whole evidence pool and
  # every destructive endpoint to the network. IRIS_BIND_HOST=0.0.0.0 exposes it deliberately — set
  # IRIS_AUTH_TOKEN too (HOWTO -> Security). This does NOT stop a malicious web page: a browser on
  # this machine reaches localhost whatever the bind address is; that is what app/security.py is for.
  exec "$PY" -m uvicorn app.main:app --host "${IRIS_BIND_HOST:-127.0.0.1}" --port "$PORT"
fi

# ── docker plumbing ──────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "docker not found. Run ./setup.sh first, or:  ./start.sh local"
if docker compose version >/dev/null 2>&1; then compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then compose() { docker-compose "$@"; }
else die "Docker Compose not found (install the compose plugin)."; fi

step "Checking the Docker daemon"
if ! docker info >/dev/null 2>&1; then
  info "daemon not reachable - trying to start it"
  command -v systemctl >/dev/null 2>&1 && sudo systemctl start docker >/dev/null 2>&1 || true
  [ "$(uname -s)" = "Darwin" ] && [ -d /Applications/Docker.app ] && open -a Docker >/dev/null 2>&1 || true
  spin "waiting for the Docker daemon" 180 "docker info" || die "Docker daemon not reachable. Start Docker and re-run."
fi
ok "engine $(docker version --format '{{.Server.Version}}' 2>/dev/null)"

FILES=(-f docker-compose.yml)
GPU_IMAGE=0
if docker image inspect iris:cuda >/dev/null 2>&1; then FILES+=(-f docker-compose.gpu.yml); GPU_IMAGE=1; fi

case "$MODE" in
  logs) compose "${FILES[@]}" logs -f; exit $? ;;
  stop) step "Stopping Iris"; compose "${FILES[@]}" stop >/dev/null && ok "stopped"; exit $? ;;
  status)
    step "Container"
    compose "${FILES[@]}" ps
    if healthy; then summary; else warn "not answering at $URL/api/health"; fi
    exit 0 ;;
  restart) step "Stopping Iris"; compose "${FILES[@]}" stop >/dev/null; ok "stopped" ;;
esac

[ -f .env ] || { [ -f .env.example ] && cp .env.example .env; }

if [ "$BUILD" = "0" ] && ! docker image inspect iris:cpu >/dev/null 2>&1 && ! docker image inspect iris:cuda >/dev/null 2>&1; then
  info "no Iris image yet - building it (first run, several minutes)"
  BUILD=1
fi

if [ "$BUILD" = "1" ]; then
  step "Building the image"
  # Remember what this build is about to replace, so the old image can be removed by ID afterwards.
  # Every rebuild leaves a 5.5 GB untagged layer set behind; a day of them is tens of gigabytes.
  IMAGE_TAG=$([ "$GPU_IMAGE" = "1" ] && echo "iris:cuda" || echo "iris:cpu")
  PREV_IMAGE="$(docker image inspect -f '{{.Id}}' "$IMAGE_TAG" 2>/dev/null || true)"
  [ "$GPU_IMAGE" = "1" ] && info "CUDA image (iris:cuda)" || info "CPU image (iris:cpu)"
  info "the frontend build and the Python wheels are the slow parts; output follows"
  t0=$(date +%s)
  # WEB_REBUILD makes the SPA layer rebuild every time (see the Dockerfile): BuildKit has reported
  # `COPY frontend/ ./  CACHED` for a context that HAD changed, and the image then shipped an old
  # frontend while the build said "Built".
  WEB_REBUILD="$(date +%s)" compose "${FILES[@]}" build || die "image build failed (see the output above)"
  ok "image built ($(( $(date +%s) - t0 ))s)"
fi

step "Starting the container"
[ "$GPU_IMAGE" = "1" ] && info "using iris:cuda"
# --force-recreate: `up -d` leaves a RUNNING container on its old image, so a fresh build can be
# built, tagged and never actually served. That is how a fix sat in an image for hours.
compose "${FILES[@]}" up -d --force-recreate || die "compose up failed. See:  ./start.sh logs"

# The image this build replaced, by ID — only after the new one is actually running, and only the one
# this run superseded. Never a blanket `docker image prune`: this machine has other projects on it,
# and their untagged layers are not ours to delete.
if [ "$BUILD" = "1" ] && [ -n "${PREV_IMAGE:-}" ]; then
  NOW_IMAGE="$(docker image inspect -f '{{.Id}}' "$IMAGE_TAG" 2>/dev/null || true)"
  if [ -n "$NOW_IMAGE" ] && [ "$NOW_IMAGE" != "$PREV_IMAGE" ]; then
    docker rmi "$PREV_IMAGE" >/dev/null 2>&1 && info "removed the image this build replaced (~5.5 GB)"
  fi
  # Build cache grows without bound — 38 GB of it in one session. Keep enough to make the next build
  # fast (the CUDA wheels are the slow part) and drop the rest.
  docker builder prune -f --keep-storage 10GB >/dev/null 2>&1     && info "trimmed the build cache to 10 GB"
fi
ok "container running"

step "Waiting for the API"
t0=$(date +%s)
if spin "starting" 300 healthy "echo 'the app restores its case and starts the library load'"; then
  ok "API answering ($(( $(date +%s) - t0 ))s)"
else
  warn "the container started but $URL/api/health did not answer in 5 minutes"
  warn "check the logs:  ./start.sh logs"
  exit 1
fi

# The library load is BACKGROUND work: the app is usable now. Report it rather than block on it.
if pool_loading; then
  step "Library load (background - the app is already usable)"
  t0=$(date +%s)
  if spin "parsing" 20 "! pool_loading" pool_detail; then
    ok "library loaded ($(( $(date +%s) - t0 ))s)"
  else
    info "$(pool_detail)"
    info "still going - the UI shows progress"
  fi
fi

summary
open_app
