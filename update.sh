#!/usr/bin/env bash
# Iris updater (Linux / WSL / macOS).
#
#   ./update.sh                # check GitHub, show exactly what would change, ask, then update + refresh
#   ./update.sh check          # the diff check only - nothing is changed (exit 0 = up to date, 10 = update available)
#   ./update.sh --yes          # update without asking
#   ./update.sh --diff         # also print the full patch (--diff=backend/app scopes it to a path)
#   ./update.sh rollback       # go back to the version before the last update (and refresh the install)
#   ./update.sh --mode=M       # how to refresh the install afterwards: auto (default) | docker | local | none
#   ./update.sh --stash        # set local edits aside, update, then put them back
#   ./update.sh --no-restart   # update the code only; do not rebuild or restart anything
#   ./update.sh --branch=B --remote=R --port=N
#   ./update.sh --adopt        # connect a copy that was downloaded as a zip (not a git checkout) to GitHub
#
# What it will not do: touch the evidence (backend/data is not in the repository, and the update refuses
# if an incoming change would reach it), discard your edits (a conflicting edit stops the update unless
# --stash), or rewrite history (fast-forward only; a copy with commits of its own is refused, with the fix).
# Exit codes: 0 done / up to date, 10 update available (check), 1 error, 2 bad arguments, 3 refused/declined.
set -uo pipefail

# THE UPDATER UPDATES ITSELF. bash reads a script as it runs, so a `git merge` that rewrites this file
# mid-run makes bash continue from a byte offset into the NEW file - it executes half a line of
# something else. Run from a private copy instead, and point it back at the checkout.
if [ -z "${IRIS_UPDATE_COPY:-}" ]; then
  _root="$(cd "$(dirname "$0")" && pwd)"
  _copy="$(mktemp "${TMPDIR:-/tmp}/iris-update.XXXXXX" 2>/dev/null)" || _copy=""
  if [ -n "$_copy" ] && cp "$0" "$_copy" 2>/dev/null; then
    IRIS_UPDATE_COPY="$_copy" IRIS_UPDATE_ROOT="$_root" exec bash "$_copy" "$@"
  fi
  IRIS_UPDATE_ROOT="$_root"
fi
ROOT="${IRIS_UPDATE_ROOT:-$(cd "$(dirname "$0")" && pwd)}"
# "LF will be replaced by CRLF" on every git call of a Windows checkout is noise, not a finding.
# Set for THIS process only (git >= 2.31 reads config from the environment); nothing is written.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.safecrlf GIT_CONFIG_VALUE_0=false
[ -n "${IRIS_UPDATE_COPY:-}" ] && trap 'rm -f "$IRIS_UPDATE_COPY"' EXIT
cd "$ROOT" || exit 1

DEFAULT_URL="https://github.com/frontierstack/Iris.git"
ACTION=update
YES=0
DIFF=0
DIFF_PATH=""
MODE=auto
STASH=0
RESTART=1
BRANCH=""
REMOTE=origin
PORT="${IRIS_PORT:-8000}"
ADOPT=0

for arg in "$@"; do
  case "$arg" in
    check|update|rollback) ACTION="$arg" ;;
    --yes|-y)         YES=1 ;;
    --diff)           DIFF=1 ;;
    --diff=*)         DIFF=1; DIFF_PATH="${arg#*=}" ;;
    --mode=*)         MODE="${arg#*=}" ;;
    --stash)          STASH=1 ;;
    --no-restart)     RESTART=0 ;;
    --branch=*)       BRANCH="${arg#*=}" ;;
    --remote=*)       REMOTE="${arg#*=}" ;;
    --port=*)         PORT="${arg#*=}" ;;
    --adopt)          ADOPT=1 ;;
    -h|--help)        sed -n '2,21p' "$ROOT/update.sh"; exit 0 ;;
    *) echo "[iris] unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done
case "$MODE" in auto|docker|local|none) ;; *) echo "[iris] --mode must be auto, docker, local or none" >&2; exit 2 ;; esac

BIND_HOST="${IRIS_BIND_HOST:-127.0.0.1}"
case "$BIND_HOST" in 0.0.0.0|::|"*"|"") BIND_HOST="127.0.0.1" ;; esac
URL="http://${BIND_HOST}:${PORT}"
STEP=0
if [ -t 1 ]; then C_DIM=$'\033[90m'; C_CY=$'\033[36m'; C_GR=$'\033[32m'; C_YE=$'\033[33m'; C_RE=$'\033[31m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else C_DIM=''; C_CY=''; C_GR=''; C_YE=''; C_RE=''; C_B=''; C_0=''; fi
step() { STEP=$((STEP+1)); printf '%s[%d]%s %s%s%s\n' "$C_DIM" "$STEP" "$C_0" "$C_CY" "$*" "$C_0"; }
ok()   { printf '    %sOK%s  %s\n' "$C_GR" "$C_0" "$*"; }
info() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_0"; }
line() { printf '    %s\n' "$*"; }
warn() { printf '    %s!   %s%s\n' "$C_YE" "$*" "$C_0"; }
die()  { printf '    %sX   %s%s\n' "$C_RE" "$1" "$C_0" >&2; exit "${2:-1}"; }   # die <message> [exit code]

# spin <label> <pid> - a live spinner while a background job runs (a plain line every 10 s when redirected)
spin() {
  local label="$1" pid="$2" frames='|/-\' i=0 t0 el last=-10
  t0=$(date +%s)
  while kill -0 "$pid" 2>/dev/null; do
    el=$(( $(date +%s) - t0 ))
    if [ -t 1 ]; then printf '\r    %s%s %s  %ss%s' "$C_DIM" "${frames:i%4:1}" "$label" "$el" "$C_0"
    elif [ $((el - last)) -ge 10 ]; then last=$el; printf '    ... %s  %ss\n' "$label" "$el"; fi
    sleep 0.4; i=$((i+1))
  done
  [ -t 1 ] && printf '\r%*s\r' 100 ''
  wait "$pid"
}

confirm() {   # confirm <question> - yes with --yes; a non-interactive run without --yes DECLINES
  [ "$YES" = "1" ] && return 0
  if [ ! -t 0 ]; then warn "not interactive and --yes not given: declining"; return 1; fi
  local a; printf '    %s? %s [y/N] %s' "$C_B" "$1" "$C_0"; read -r a
  case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

healthy() {
  if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 3 "$URL/api/health" 2>/dev/null | grep -q '"ok":true'
  else return 1; fi
}

# ── 1. the checkout ──────────────────────────────────────────────────────────
step "Checking this copy of Iris"
command -v git >/dev/null 2>&1 || die "git is not installed. Install it (apt/dnf/brew install git) and re-run."
IS_REPO=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  TOP="$(git rev-parse --show-toplevel 2>/dev/null)"
  [ "$(cd "$TOP" && pwd -P)" = "$(pwd -P)" ] && IS_REPO=1
fi
if [ "$IS_REPO" = "0" ]; then
  if [ "$ADOPT" = "0" ]; then
    die "this copy is not a git checkout (downloaded as a zip?). Re-run with --adopt to connect it to GitHub:
        the files are compared with the latest version first, and nothing is replaced without asking." 3
  fi
  info "adopting this copy: git init + $DEFAULT_URL"
  git init -q . || die "git init failed"
  git remote add "$REMOTE" "$DEFAULT_URL" 2>/dev/null || true
fi
if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  git remote add "$REMOTE" "$DEFAULT_URL" || die "could not add the remote $REMOTE"
  info "added remote $REMOTE -> $DEFAULT_URL"
fi
HAS_HEAD=1; git rev-parse --verify -q HEAD >/dev/null 2>&1 || HAS_HEAD=0
if [ -z "$BRANCH" ]; then
  # A copy with no commits yet (just adopted) is on whatever `git init` named its branch - "master" on
  # many machines, which GitHub does not have. Only a real checkout's branch is worth following.
  [ "$HAS_HEAD" = "1" ] && BRANCH="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)"
  [ -n "$BRANCH" ] || BRANCH=main
fi
# inside .git: never tracked, never in a diff. ABSOLUTE, because the UI build runs from frontend/.
STATE="$(cd "$(git rev-parse --git-dir)" && pwd)/iris-update"
mkdir -p "$STATE"
ok "$(git remote get-url "$REMOTE")  ·  branch $BRANCH"

# ── rollback ─────────────────────────────────────────────────────────────────
if [ "$ACTION" = "rollback" ]; then
  [ -s "$STATE/previous" ] || die "no earlier version is recorded - nothing to roll back to" 3
  PREV="$(cat "$STATE/previous")"
  git cat-file -e "$PREV^{commit}" 2>/dev/null || die "the recorded version $PREV is not in this repository any more" 3
  [ "$(git rev-parse HEAD)" = "$PREV" ] && { ok "already at $(git log -1 --format='%h %s' "$PREV")"; exit 0; }
  step "Rolling back"
  line "from  $(git log -1 --format='%h  %ad  %s' --date=short HEAD)"
  line "to    $(git log -1 --format='%h  %ad  %s' --date=short "$PREV")"
  CHANGED="$(git diff --name-only "$PREV" HEAD)"
  info "$(printf '%s\n' "$CHANGED" | grep -c .) file(s) go back"
  confirm "Roll Iris back to $(git rev-parse --short "$PREV")" || die "declined - nothing changed" 3
  FROM="$(git rev-parse HEAD)"
  # --keep, not --hard: it refuses rather than overwrite a local edit to a file the rollback touches.
  git reset --quiet --keep "$PREV" || die "rollback refused: a local edit touches a file it would change. Commit or discard it first (git status)." 3
  echo "$FROM" > "$STATE/previous"            # so a second rollback returns to where this one started
  printf '%s %s rollback %s -> %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$BRANCH" "$FROM" "$PREV" >> "$STATE/history"
  ok "now at $(git log -1 --format='%h  %s' HEAD)"
  NAMES="$CHANGED"
else
  # ── 2. fetch ───────────────────────────────────────────────────────────────
  step "Fetching the latest version from GitHub"
  GIT_TERMINAL_PROMPT=0 git fetch --prune --quiet "$REMOTE" "$BRANCH" >"$STATE/fetch.log" 2>&1 &
  if ! spin "git fetch $REMOTE $BRANCH" $!; then
    sed 's/^/        /' "$STATE/fetch.log" >&2
    die "could not fetch $REMOTE/$BRANCH - check the network, or that the branch exists"
  fi
  UP="$REMOTE/$BRANCH"
  ok "fetched $(git log -1 --format='%h  %ad' --date=short "$UP")"

  # ── 3. the diff check ──────────────────────────────────────────────────────
  step "What would change"
  if [ "$HAS_HEAD" = "1" ]; then
    read -r AHEAD BEHIND < <(git rev-list --left-right --count "HEAD...$UP" 2>/dev/null || echo "0 0")
    line "this copy  $(git log -1 --format='%h  %ad  %s' --date=short HEAD)"
  else
    AHEAD=0; BEHIND=$(git rev-list --count "$UP")
    line "this copy  (not yet a git checkout - compared file by file)"
  fi
  line "GitHub     $(git log -1 --format='%h  %ad  %s' --date=short "$UP")"

  if [ "$HAS_HEAD" = "1" ] && [ "$BEHIND" = "0" ]; then
    ok "Iris is up to date"
    [ "$AHEAD" != "0" ] && info "this copy has $AHEAD commit(s) of its own that GitHub does not"
    DIRTY="$(git status --porcelain --untracked-files=no | wc -l | tr -d ' ')"
    [ "$DIRTY" != "0" ] && info "$DIRTY file(s) edited locally (kept as they are)"
    exit 0
  fi

  BASE=HEAD; [ "$HAS_HEAD" = "0" ] && BASE=""
  if [ -n "$BASE" ]; then
    printf '\n    %s%s incoming commit(s)%s\n' "$C_B" "$BEHIND" "$C_0"
    git log --no-merges --format='      %h  %ad  %s' --date=short "HEAD..$UP" | head -n 25
    [ "$BEHIND" -gt 25 ] && info "  ... and $((BEHIND - 25)) more"
    NUMSTAT="$(git diff --numstat HEAD "$UP")"
    NAMESTAT="$(git diff --name-status HEAD "$UP")"
  else
    # An adopted copy has no commits and an EMPTY index, and against an empty index every file reads as
    # new (it reported all 105 backend files). Load GitHub's tree into the INDEX - the files on disk are
    # not touched - so the diff is exactly the files that differ, in the direction GitHub would bring.
    git read-tree "$UP" >/dev/null 2>&1 || die "could not read $UP"
    NUMSTAT="$(git diff --numstat -R 2>/dev/null)"
    NAMESTAT="$(git diff --name-status -R 2>/dev/null)"
  fi
  NAMES="$(printf '%s\n' "$NUMSTAT" | awk -F'\t' 'NF>=3{print $3}')"

  # Changed files by AREA, with line counts: "412 files changed" says nothing an analyst can act on.
  printf '\n    %sfiles by area%s\n' "$C_B" "$C_0"
  printf '%s\n' "$NUMSTAT" | awk -F'\t' '
    NF>=3 {
      p=$3; a=($1=="-")?0:$1; d=($2=="-")?0:$2
      area="Other"
      if (p ~ /^backend\/requirements/ || p ~ /^frontend\/package(-lock)?\.json$/) area="Dependencies"
      else if (p ~ /^(Dockerfile|docker-compose.*\.ya?ml|\.dockerignore)$/) area="Docker image"
      else if (p ~ /^backend\//) area="Backend (API, parsers, detections)"
      else if (p ~ /^frontend\//) area="Frontend (UI)"
      else if (p ~ /\.(sh|ps1)$/) area="Scripts"
      else if (p ~ /\.md$/ || p ~ /^docs\//) area="Docs"
      n[area]++; A[area]+=a; D[area]+=d
      if (n[area] <= 8) f[area]=f[area] "        " p "\n"
    }
    END {
      order="Backend (API, parsers, detections)|Frontend (UI)|Dependencies|Docker image|Scripts|Docs|Other"
      k=split(order, o, "|")
      for (i=1;i<=k;i++) { x=o[i]; if (!(x in n)) continue
        printf "      %-36s %4d file(s)   +%d -%d\n", x, n[x], A[x], D[x]
        printf "%s", f[x]
        if (n[x] > 8) printf "        ... and %d more\n", n[x]-8 }
    }'

  # What the change MEANS for this install - the part a file list cannot tell you.
  has() { printf '%s\n' "$NAMES" | grep -Eq "$1"; }
  IMPACT=()
  has '^backend/requirements\.txt$'                && IMPACT+=("Python dependencies changed - installed during the update")
  has '^backend/requirements-gpu\.txt$'            && IMPACT+=("GPU wheels changed - a Docker rebuild picks them up; a local install should re-run ./setup.sh local")
  has '^frontend/package(-lock)?\.json$'           && IMPACT+=("UI dependencies changed - reinstalled (npm ci) during the update")
  has '^(Dockerfile|docker-compose.*)$'            && IMPACT+=("the image definition changed - the Docker rebuild is a full one")
  has '^backend/app/(parsers/|normalize\.py)'      && IMPACT+=("parsers changed - on the next start the library is RE-PARSED once (can take a while on a big library)")
  has '^backend/app/detect\.py$'                   && IMPACT+=("detections changed - the search index and entity graph rebuild once, in the background")
  has '^update\.(sh|ps1)$'                         && IMPACT+=("the updater itself changed - this run finishes on the copy it started with")
  has '^setup\.(sh|ps1)$'                          && IMPACT+=("setup changed - if something is missing afterwards, re-run setup")
  if [ ${#IMPACT[@]} -gt 0 ]; then
    printf '\n    %swhat it means for this install%s\n' "$C_B" "$C_0"
    for m in "${IMPACT[@]}"; do line "  - $m"; done
  fi

  # THE EVIDENCE. backend/data is not in the repository; an update that would reach it is refused.
  if printf '%s\n' "$NAMES" | grep -Eq '^(backend/data/|\.env$)'; then
    die "an incoming change touches backend/data or .env - refusing. Report this; your evidence and settings were not changed." 3
  fi
  if [ -d backend/data ] && ! git check-ignore -q backend/data/probe 2>/dev/null; then
    warn "backend/data is not git-ignored in this copy - the update will not touch it, but check .gitignore"
  fi
  info "your evidence (backend/data) and .env are outside the repository and are not touched"

  # ── local state ────────────────────────────────────────────────────────────
  step "Checking this copy for local changes"
  CONFLICT=""; DIRTY=""; COLLIDE=""
  if [ "$HAS_HEAD" = "1" ]; then
    DIRTY="$( { git diff --name-only HEAD; git diff --name-only --cached; } 2>/dev/null | sort -u)"
    [ -n "$DIRTY" ] && CONFLICT="$(comm -12 <(printf '%s\n' "$DIRTY" | sort -u) <(printf '%s\n' "$NAMES" | sort -u))"
    # A file GitHub ADDS that already exists here untracked would block the merge.
    ADDED="$(printf '%s\n' "$NAMESTAT" | awk -F'\t' '$1=="A"{print $2}')"
    while IFS= read -r f; do
      [ -n "$f" ] && [ -e "$f" ] && ! git ls-files --error-unmatch -- "$f" >/dev/null 2>&1 && COLLIDE="$COLLIDE$f"$'\n'
    done <<< "$ADDED"
  fi
  NDIRTY=$(printf '%s' "$DIRTY" | grep -c . || true)
  if [ "$HAS_HEAD" = "0" ]; then
    # An adopted copy has no history to tell an edit of yours from an old version of Iris, so there is
    # nothing to set aside: every file listed above is REPLACED. Said before the question, not after.
    warn "this copy has no git history, so every file listed above will be REPLACED with GitHub's version -"
    warn "including any file you edited yourself. Copy those somewhere first if you want to keep them."
  fi
  if [ "$HAS_HEAD" = "1" ]; then
    if [ "$NDIRTY" = "0" ]; then ok "no local edits"; else info "$NDIRTY file(s) edited locally"; fi
  fi
  if [ -n "$CONFLICT" ]; then
    warn "edited here AND changed on GitHub:"
    printf '%s\n' "$CONFLICT" | sed 's/^/          /'
  elif [ "$NDIRTY" != "0" ]; then
    ok "none of them is touched by the update - they are kept as they are"
  fi
  if [ -n "$COLLIDE" ]; then
    warn "GitHub adds file(s) that already exist here, untracked:"
    printf '%s' "$COLLIDE" | sed 's/^/          /'
  fi
  if [ "${AHEAD:-0}" != "0" ]; then
    warn "this copy has $AHEAD commit(s) of its own that GitHub does not have:"
    git log --format='          %h  %s' "$UP..HEAD" | head -n 10
  fi

  if [ "$DIFF" = "1" ]; then
    step "The full patch${DIFF_PATH:+ ($DIFF_PATH)}"
    COLOR=--no-color; [ -t 1 ] && COLOR=--color
    if [ -n "$BASE" ]; then git --no-pager diff $COLOR HEAD "$UP" -- ${DIFF_PATH:+"$DIFF_PATH"}
    else git --no-pager diff $COLOR -R -- ${DIFF_PATH:+"$DIFF_PATH"}; fi
  fi

  if [ "$ACTION" = "check" ]; then
    printf '\n'; ok "update available: $BEHIND commit(s). Run ./update.sh to apply it."
    exit 10
  fi

  # Refusals come AFTER the whole picture has been shown, so the analyst sees why.
  if [ "${AHEAD:-0}" != "0" ]; then
    die "this copy has its own commits, so it cannot simply move to GitHub's version. To keep them: git rebase $UP. To drop them: git reset --keep $UP." 3
  fi
  if [ -n "$COLLIDE" ]; then
    die "move or delete the untracked file(s) above first - the update would have to overwrite them" 3
  fi
  if [ -n "$CONFLICT" ] && [ "$STASH" = "0" ]; then
    die "re-run with --stash to set your edits aside and put them back after the update, or commit/discard them first" 3
  fi

  printf '\n'
  confirm "Update Iris to $(git rev-parse --short "$UP")" || die "declined - nothing changed" 3

  # ── 4. apply ───────────────────────────────────────────────────────────────
  step "Updating the code"
  FROM="$( [ "$HAS_HEAD" = "1" ] && git rev-parse HEAD || echo "")"
  STASHED=0
  if [ "$STASH" = "1" ] && [ "$NDIRTY" != "0" ]; then
    git stash push --quiet -m "iris-update $(date -u +%Y-%m-%dT%H:%M:%SZ)" || die "git stash failed"
    STASHED=1; info "local edits set aside (git stash)"
  fi
  if [ "$HAS_HEAD" = "1" ]; then
    git merge --ff-only --quiet "$UP" || die "the fast-forward failed - nothing was changed"
  else
    # An adopted copy: files that differ from GitHub are REPLACED. Listed above, confirmed just now.
    git reset --quiet "$UP" && git checkout --quiet -- . || die "could not check out $UP"
    # `git init` may have named the branch "master"; the next update follows the branch it is ON.
    git branch -M "$BRANCH" >/dev/null 2>&1 || true
    git branch --set-upstream-to="$UP" >/dev/null 2>&1 || true
  fi
  if [ "$STASHED" = "1" ]; then
    if git stash pop --quiet; then ok "local edits put back"
    else warn "your edits conflict with the update - they are kept in the stash (git stash list); resolve, then git stash drop"; fi
  fi
  [ -n "$FROM" ] && echo "$FROM" > "$STATE/previous"
  printf '%s %s update %s -> %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$BRANCH" "${FROM:-none}" "$(git rev-parse HEAD)" >> "$STATE/history"
  ok "now at $(git log -1 --format='%h  %s' HEAD)"
fi

# ── 5. refresh the install ───────────────────────────────────────────────────
# Which install THIS checkout is. The container is matched by the working directory compose recorded on
# it, so a second checkout on the same machine can never rebuild the analyst's running Iris.
norm() { printf '%s' "$1" | tr '\\' '/' | tr 'A-Z' 'a-z' | sed 's#/*$##'; }
HERE="$(norm "$(pwd -W 2>/dev/null || pwd)")"
CONTAINER_HERE=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  WD="$(docker inspect iris --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' 2>/dev/null || true)"
  [ -n "$WD" ] && [ "$(norm "$WD")" = "$HERE" ] && CONTAINER_HERE=1
fi
INSTALL="$MODE"
if [ "$MODE" = "auto" ]; then
  if [ "$CONTAINER_HERE" = "1" ]; then INSTALL=docker
  elif [ -x .venv/bin/python ] || [ -d frontend/node_modules ] || [ -f frontend/dist/index.html ]; then INSTALL=local
  else INSTALL=none; fi
fi
changed() { printf '%s\n' "$NAMES" | grep -Eq "$1"; }

if [ "$RESTART" = "0" ]; then
  step "Refreshing the install"
  info "--no-restart: the code is updated; rebuild/restart it yourself (./start.sh --build, or ./start.sh local)"
elif [ "$INSTALL" = "docker" ]; then
  step "Rebuilding and restarting the Docker install"
  info "start.sh --build: new image, container recreated, health checked, the old image removed"
  ./start.sh --build --no-browser --port="$PORT" || die "the rebuild failed - the code is updated; fix the error above and run ./start.sh --build (or ./update.sh rollback)"
elif [ "$INSTALL" = "local" ]; then
  step "Refreshing the local install"
  if changed '^backend/requirements\.txt$'; then
    if [ -x .venv/bin/python ]; then
      info "installing the changed Python dependencies into .venv"
      .venv/bin/python -m pip install --quiet -r backend/requirements.txt >"$STATE/pip.log" 2>&1 &
      spin "pip install -r backend/requirements.txt" $! || { tail -n 15 "$STATE/pip.log" | sed 's/^/        /'; die "pip install failed"; }
      ok "Python dependencies installed"
    else
      warn "Python dependencies changed and there is no .venv here - run ./setup.sh local"
    fi
  fi
  changed '^backend/requirements-gpu\.txt$' && warn "GPU wheels changed - run ./setup.sh local to resolve them for this machine"
  if command -v npm >/dev/null 2>&1 && [ -f frontend/package.json ]; then
    (
      cd frontend || exit 1
      if [ ! -d node_modules ] || changed '^frontend/package(-lock)?\.json$'; then
        npm ci --ignore-scripts >"$STATE/npm.log" 2>&1 || exit 1
      fi
      npm run build >>"$STATE/npm.log" 2>&1
    ) &
    spin "building the UI" $! || { tail -n 20 "$STATE/npm.log" | sed 's/^/        /'; die "the UI build failed"; }
    ok "UI rebuilt"
  else
    warn "npm not found - the UI was not rebuilt (./start.sh local will try, or run ./setup.sh local)"
  fi
  if healthy; then
    # A health answer on the port proves SOMETHING is serving Iris there, not that it is this install
    # (a Docker Iris on the same port answers too) - so it is said as a condition, not a claim.
    warn "something is serving Iris on $URL - if that is this local install, it is still running the OLD code: stop it (Ctrl-C in its terminal) and run ./start.sh local"
  else
    info "start it with: ./start.sh local"
  fi
else
  step "Refreshing the install"
  info "no running install from this folder was found - start it with ./start.sh (Docker) or ./start.sh local"
fi

printf '\n'
ok "Iris is at $(git log -1 --format='%h  %ad  %s' --date=short HEAD)"
[ -s "$STATE/previous" ] && info "to go back: ./update.sh rollback"
exit 0
