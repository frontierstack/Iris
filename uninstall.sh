#!/usr/bin/env bash
# Iris uninstall script (Linux / WSL / macOS).
#
#   ./uninstall.sh              # remove the Docker install (container, images, offer the build cache)
#   ./uninstall.sh local        # remove the local (no-Docker) install: node_modules, dist, caches
#   ./uninstall.sh all          # both of the above
#   ./uninstall.sh --purge-data # ALSO delete backend/data - every case, upload and setting. Irreversible.
#   ./uninstall.sh --pip        # local/all: also `pip uninstall` the Python dependencies
#   ./uninstall.sh --yes        # don't ask (does NOT cover --purge-data, which asks separately)
#   ./uninstall.sh --dry-run    # print what would be removed and stop
#
# YOUR EVIDENCE IS KEPT BY DEFAULT. backend/data holds the cases, the uploaded logs, the rules and the
# settings, and it is the one thing here that cannot be rebuilt from this repo. It is removed ONLY with
# --purge-data, and that asks you to type DELETE first.
#
# This script never deletes the source tree it lives in - remove that directory yourself when done.
set -uo pipefail
cd "$(dirname "$0")"

MODE=docker
PURGE_DATA=0
PIP_UNINSTALL=0
ASSUME_YES=0
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    docker|local|all) MODE="$arg" ;;
    --purge-data)     PURGE_DATA=1 ;;
    --pip)            PIP_UNINSTALL=1 ;;
    --yes|-y)         ASSUME_YES=1 ;;
    --dry-run|-n)     DRY_RUN=1 ;;
    -h|--help)        sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "[iris] unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then C_DIM=$'\033[90m'; C_CY=$'\033[36m'; C_GR=$'\033[32m'; C_YE=$'\033[33m'; C_RE=$'\033[31m'; C_0=$'\033[0m'
else C_DIM=''; C_CY=''; C_GR=''; C_YE=''; C_RE=''; C_0=''; fi

STEP=0
step() { STEP=$((STEP+1)); printf '%s[%d]%s %s%s%s\n' "$C_DIM" "$STEP" "$C_0" "$C_CY" "$*" "$C_0"; }
ok()   { printf '    %sOK%s  %s\n' "$C_GR" "$C_0" "$*"; }
info() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_0"; }
warn() { printf '    %s!   %s%s\n' "$C_YE" "$*" "$C_0"; }
bad()  { printf '    %sX   %s%s\n' "$C_RE" "$*" "$C_0" >&2; }

human() {   # human <path> -> "1.2G", or nothing when the path does not exist
  [ -e "$1" ] || return 0
  du -sh "$1" 2>/dev/null | cut -f1
}

rm_path() {   # rm_path <path> [label]
  local p="$1" label="${2:-$1}" size
  if [ ! -e "$p" ]; then info "$label - not present"; return 0; fi
  size=$(human "$p")
  if [ "$DRY_RUN" = "1" ]; then info "would remove $label (${size:-?})"; return 0; fi
  if rm -rf -- "$p"; then ok "removed $label (${size:-?})"; else bad "could not remove $label"; fi
}

confirm() {   # confirm <question> -> 0 when the answer is yes
  [ "$ASSUME_YES" = "1" ] && return 0
  [ "$DRY_RUN" = "1" ] && return 1
  local reply=""
  printf '    %s%s [y/N] %s' "$C_YE" "$1" "$C_0"
  read -r reply </dev/tty 2>/dev/null || reply=""
  case "$reply" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

DATA_DIR="${IRIS_DATA_HOST_DIR:-./backend/data}"
DRY_NOTE=""
[ "$DRY_RUN" = "1" ] && DRY_NOTE="  (dry run - nothing will be removed)"

echo
printf '  %sIris uninstall%s  mode: %s%s\n' "$C_CY" "$C_0" "$MODE" "$DRY_NOTE"
if [ "$PURGE_DATA" = "1" ]; then
  printf '  %sdata: WILL BE DELETED%s  %s (%s)\n' "$C_RE" "$C_0" "$DATA_DIR" "$(human "$DATA_DIR")"
else
  printf '  %sdata: kept%s  %s (%s)  - pass --purge-data to remove it\n' "$C_GR" "$C_0" "$DATA_DIR" "$(human "$DATA_DIR")"
fi
echo

# --- docker ------------------------------------------------------------------
if [ "$MODE" = "docker" ] || [ "$MODE" = "all" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    step "Docker"
    info "docker not found - nothing to remove"
  elif ! docker info >/dev/null 2>&1; then
    step "Docker"
    warn "the Docker daemon is not reachable - start Docker and re-run to remove the container and images"
  else
    if docker compose version >/dev/null 2>&1; then compose() { docker compose "$@"; }
    elif command -v docker-compose >/dev/null 2>&1; then compose() { docker-compose "$@"; }
    else compose() { return 1; }; fi

    FILES=(-f docker-compose.yml)
    docker image inspect iris:cuda >/dev/null 2>&1 && FILES+=(-f docker-compose.gpu.yml)

    step "Stopping and removing the container"
    if [ "$DRY_RUN" = "1" ]; then
      info "would run: docker compose down --remove-orphans"
    else
      # No -v. The data dir is a HOST bind mount, so `down` cannot touch it either way, but
      # IRIS_DATA_HOST_DIR may legitimately name a volume - and deleting the evidence is what
      # --purge-data is for, with its own confirmation.
      if compose "${FILES[@]}" down --remove-orphans >/dev/null 2>&1; then
        ok "compose stack down"
      elif docker rm -f iris >/dev/null 2>&1; then
        ok "removed the container 'iris'"
      else
        info "no Iris container running"
      fi
    fi

    step "Removing the images"
    for tag in iris:cpu iris:cuda; do
      if docker image inspect "$tag" >/dev/null 2>&1; then
        size=$(docker image inspect -f '{{.Size}}' "$tag" 2>/dev/null)
        size_mb=$(( ${size:-0} / 1024 / 1024 ))
        if [ "$DRY_RUN" = "1" ]; then
          info "would remove image $tag (${size_mb} MB)"
        elif docker rmi -f "$tag" >/dev/null 2>&1; then
          ok "removed $tag (${size_mb} MB)"
        else
          bad "could not remove $tag (is a container still using it?)"
        fi
      else
        info "$tag - not present"
      fi
    done

    step "Build cache"
    # BuildKit does not tag its layers by project, so Iris's own cache cannot be told apart from
    # anything else on this machine. Offered, never assumed - other projects share that cache and
    # their layers are not ours to delete.
    if [ "$DRY_RUN" = "1" ]; then
      info "would offer: docker builder prune -f  (shared with every other project here)"
    elif confirm "Prune the shared Docker build cache? This affects OTHER projects on this machine."; then
      if docker builder prune -f >/dev/null 2>&1; then ok "build cache pruned"; else bad "prune failed"; fi
    else
      info "left alone - run 'docker builder prune' yourself if you want the space back"
    fi
  fi
  echo
fi

# --- local (no Docker) -------------------------------------------------------
if [ "$MODE" = "local" ] || [ "$MODE" = "all" ]; then
  step "Frontend dependencies and build output"
  rm_path frontend/node_modules "frontend/node_modules"
  rm_path frontend/dist         "frontend/dist"
  rm_path frontend/.vite        "frontend/.vite"

  step "Python and test caches"
  if [ "$DRY_RUN" = "1" ]; then
    info "would remove every __pycache__ directory in the tree"
  else
    find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null
    ok "__pycache__ directories removed"
  fi
  rm_path .pytest_cache         ".pytest_cache"
  rm_path backend/.pytest_cache "backend/.pytest_cache"
  rm_path .mypy_cache           ".mypy_cache"
  rm_path .ruff_cache           ".ruff_cache"

  step "Virtualenv"
  rm_path .venv         ".venv"
  rm_path backend/.venv "backend/.venv"

  step "Python dependencies"
  if [ "$PIP_UNINSTALL" != "1" ]; then
    info "left installed - pass --pip to uninstall them too"
  else
    PY=""
    for cand in python3 python py; do
      if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import sys" >/dev/null 2>&1; then
        PY=$(command -v "$cand"); break
      fi
    done
    if [ -z "$PY" ]; then
      warn "python not found - skipping"
    else
      # setup.sh local installs into whatever interpreter ran it, NOT a venv, so these packages are
      # very likely shared with other things on this machine. Named and confirmed, never assumed.
      warn "setup.sh local does not use a venv, so these packages may be shared with OTHER projects"
      info "interpreter: $PY"
      if [ "$DRY_RUN" = "1" ]; then
        info "would run: pip uninstall -y -r backend/requirements.txt (and requirements-gpu.txt)"
      elif confirm "Uninstall everything listed in backend/requirements*.txt from $PY?"; then
        if "$PY" -m pip uninstall -y -r backend/requirements.txt >/dev/null 2>&1; then
          ok "base requirements uninstalled"
        else
          warn "some base packages could not be uninstalled (see: pip uninstall -r backend/requirements.txt)"
        fi
        if [ -f backend/requirements-gpu.txt ]; then
          if "$PY" -m pip uninstall -y -r backend/requirements-gpu.txt >/dev/null 2>&1; then
            ok "GPU requirements uninstalled"
          else
            info "no GPU packages to remove"
          fi
        fi
      else
        info "left installed"
      fi
    fi
  fi
  echo
fi

# --- data (opt-in, and it asks) ----------------------------------------------
step "Evidence and settings ($DATA_DIR)"
if [ "$PURGE_DATA" != "1" ]; then
  info "KEPT - your cases, uploads, rules and settings. Pass --purge-data to delete them."
elif [ ! -e "$DATA_DIR" ]; then
  info "not present"
elif [ "$DRY_RUN" = "1" ]; then
  info "would DELETE $DATA_DIR ($(human "$DATA_DIR")) - every case, upload, rule and setting"
else
  SIZE=$(human "$DATA_DIR")
  NCASES=$(ls -1 "$DATA_DIR/cases" 2>/dev/null | grep -cv '^index.json$')
  NLIB=$(ls -1 "$DATA_DIR/library" 2>/dev/null | grep -cv '^index.json$')
  printf '    %sAbout to permanently delete %s (%s)%s\n' "$C_RE" "$DATA_DIR" "${SIZE:-?}" "$C_0"
  printf '      %s case(s), %s staged file(s), plus rules.json, settings.json, auth.json and the trash.\n' "${NCASES:-0}" "${NLIB:-0}"
  printf '      There is no undo, and nothing in this repo can rebuild any of it.\n'
  printf '    %sType DELETE to confirm: %s' "$C_RE" "$C_0"
  REPLY_TXT=""
  read -r REPLY_TXT </dev/tty 2>/dev/null || REPLY_TXT=""
  if [ "$REPLY_TXT" = "DELETE" ]; then
    if rm -rf -- "$DATA_DIR"; then ok "data directory removed"; else bad "could not remove $DATA_DIR"; fi
  else
    info "not confirmed - data KEPT"
  fi
fi

echo
printf '  %sDone.%s The source tree at %s was not touched - delete it yourself when you are finished.\n' "$C_GR" "$C_0" "$(pwd)"
if [ "$PURGE_DATA" != "1" ]; then
  printf '  %sYour evidence is still in %s%s\n' "$C_DIM" "$DATA_DIR" "$C_0"
fi
echo
