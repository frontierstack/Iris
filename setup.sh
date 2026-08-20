#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Iris setup — native Linux, WSL2, macOS, or Git-Bash on Windows (delegates to setup.ps1).
# Detects the environment, Docker flavour and NVIDIA GPU passthrough, then builds
# and starts the right image (CUDA or CPU).
#
#   ./setup.sh            # auto-detect (default)
#   ./setup.sh gpu        # force CUDA image
#   ./setup.sh cpu        # force CPU image
#   ./setup.sh local      # no Docker: install Python/Node deps onto this machine (GPU deps if an NVIDIA GPU is present)
#   ./setup.sh down       # stop & remove containers
#   ./setup.sh logs       # follow logs
#
#   --yes | -y            # install missing dependencies without asking
#   --no-install          # never install anything; report what is missing and stop
#
# MISSING DEPENDENCIES ARE INSTALLED, NOT REPORTED. Anything Iris needs and cannot find — Python, pip,
# Node, tesseract (OCR), Docker, the compose plugin — is offered through this machine's own package
# manager, once, with the exact command shown first. Declining always leaves the old behaviour: a clear
# message naming the package and the URL.
# ──────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")"

MODE=auto
ASSUME_YES=0
NO_INSTALL=0
for arg in "$@"; do
  case "$arg" in
    auto|gpu|cpu|local|down|logs) MODE="$arg" ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --no-install) NO_INSTALL=1 ;;
    -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
    *) printf '[iris] unknown argument: %s (try --help)\n' "$arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;32m[iris]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[iris]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[iris]\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. Environment ────────────────────────────────────────────────────────────
OS="$(uname -s 2>/dev/null || echo unknown)"
ENV_KIND="linux"
case "$OS" in
  Darwin*)               ENV_KIND="macos" ;;
  MINGW*|MSYS*|CYGWIN*)  ENV_KIND="windows-gitbash" ;;
  Linux*)  grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null && ENV_KIND="wsl" ;;
esac
log "Environment: $ENV_KIND ($OS)"

if [[ "$ENV_KIND" == "windows-gitbash" ]] && command -v powershell.exe >/dev/null 2>&1; then
  log "Windows host shell detected -> delegating to setup.ps1"
  PS_ARGS=(-Mode "$MODE")
  [[ $ASSUME_YES == 1 ]] && PS_ARGS+=(-Yes)
  [[ $NO_INSTALL == 1 ]] && PS_ARGS+=(-NoInstall)
  exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "./setup.ps1" "${PS_ARGS[@]}"
fi

# ── 1a. Dependency installation ───────────────────────────────────────────────
# One place that knows how to put software on this machine, so every "X not found" below can offer a
# fix instead of only naming one. The package NAME differs per manager, which is why each ensure_*
# helper carries its own table rather than a single generic mapping.
PKG_MGR=""
detect_pkg_mgr() {
  [[ -n "$PKG_MGR" ]] && { echo "$PKG_MGR"; return 0; }
  if   [[ "$ENV_KIND" == "macos" ]] && command -v brew >/dev/null 2>&1; then PKG_MGR=brew
  elif command -v apt-get >/dev/null 2>&1; then PKG_MGR=apt
  elif command -v dnf     >/dev/null 2>&1; then PKG_MGR=dnf
  elif command -v yum     >/dev/null 2>&1; then PKG_MGR=yum
  elif command -v pacman  >/dev/null 2>&1; then PKG_MGR=pacman
  elif command -v zypper  >/dev/null 2>&1; then PKG_MGR=zypper
  elif command -v apk     >/dev/null 2>&1; then PKG_MGR=apk
  elif command -v brew    >/dev/null 2>&1; then PKG_MGR=brew
  else PKG_MGR=none; fi
  echo "$PKG_MGR"
}

SUDO=""
need_sudo() {
  # brew refuses to run as root; everything else needs it unless we already are root.
  [[ "$(detect_pkg_mgr)" == "brew" ]] && { SUDO=""; return 0; }
  if [[ "$(id -u)" == "0" ]]; then SUDO=""; return 0; fi
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; return 0; fi
  return 1
}

APT_UPDATED=0
pkg_install_cmd() {   # pkg_install_cmd <pkg...> -> prints the command that would run
  local mgr; mgr="$(detect_pkg_mgr)"
  case "$mgr" in
    apt)    echo "$SUDO apt-get install -y $*" ;;
    dnf)    echo "$SUDO dnf install -y $*" ;;
    yum)    echo "$SUDO yum install -y $*" ;;
    pacman) echo "$SUDO pacman -S --needed --noconfirm $*" ;;
    zypper) echo "$SUDO zypper install -y $*" ;;
    apk)    echo "$SUDO apk add $*" ;;
    brew)   echo "brew install $*" ;;
    *)      echo "" ;;
  esac
}

ask() {   # ask <question> -> 0 for yes
  [[ $ASSUME_YES == 1 ]] && return 0
  [[ ! -t 0 ]] && return 1        # non-interactive and no --yes: never install silently
  local reply=""
  printf '\033[1;33m[iris]\033[0m %s [Y/n] ' "$1"
  read -r reply </dev/tty 2>/dev/null || reply=""
  [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

pkg_install() {   # pkg_install <what-for> <pkg...>
  local what="$1"; shift
  local mgr cmd
  mgr="$(detect_pkg_mgr)"
  if [[ $NO_INSTALL == 1 ]]; then warn "--no-install: not installing $what"; return 1; fi
  if [[ "$mgr" == "none" ]]; then warn "no supported package manager found - cannot install $what automatically"; return 1; fi
  if ! need_sudo; then warn "root privileges are needed to install $what, and sudo is not available"; return 1; fi
  cmd="$(pkg_install_cmd "$@")"
  log "$what is missing. This will run:"
  printf '        %s\n' "$cmd"
  ask "Install it now?" || { warn "skipped - $what was not installed"; return 1; }
  if [[ "$mgr" == "apt" && $APT_UPDATED == 0 ]]; then
    # A first-boot container/VM has no package lists at all, so install fails with "Unable to locate
    # package" for a package that exists. Refresh once per run, not per package.
    log "Refreshing package lists (apt-get update)..."
    $SUDO apt-get update -qq || warn "apt-get update failed - continuing anyway"
    APT_UPDATED=1
  fi
  # shellcheck disable=SC2086
  eval "$cmd" || { warn "installing $what failed"; return 1; }
  return 0
}

find_python() {
  local c
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
      command -v "$c"; return 0
    fi
  done
  return 1
}

# ── 1c. Preflight ─────────────────────────────────────────────────────────────
# nvidia-smi ships WITH the driver, so "nvidia-smi not found" cannot tell "no NVIDIA card" from
# "NVIDIA card, no driver". Iris reported the second as the first and quietly settled for numpy on a
# machine that has a GPU in it. Ask the PCI bus what the hardware actually is.
nvidia_hardware() {
  if command -v lspci >/dev/null 2>&1; then
    lspci 2>/dev/null | grep -i 'vga\|3d controller' | grep -i nvidia | sed 's/.*: //' | head -1 && return 0
  fi
  # WSL has no PCI bus of its own; the Windows host driver surfaces as /dev/dxg.
  [[ -e /dev/dxg ]] && { echo "GPU via WSL (/dev/dxg)"; return 0; }
  ls /sys/bus/pci/devices/*/vendor 2>/dev/null | while read -r f; do
    [[ "$(cat "$f" 2>/dev/null)" == "0x10de" ]] && { echo "NVIDIA device (PCI 0x10de)"; break; }
  done | head -1
}

# A dependency that is checked silently is indistinguishable from one that is never checked - which
# is how "there is no check for Python" gets reported about code that does check. Say it out loud.
preflight() {
  local for_what="$1" hw smi
  log "Preflight ($for_what):"
  row() { local mark='.'; [[ "$2" == *MISSING* || "$2" == *"NO DRIVER"* ]] && mark='!'; printf '  %s %-14s %s\n' "$mark" "$1" "$2"; }
  if [[ "$for_what" == "local" ]]; then
    row "Python 3.11+" "$(find_python >/dev/null 2>&1 && "$(find_python)" --version 2>&1 || echo MISSING)"
    row "Node + npm"   "$(command -v npm >/dev/null 2>&1 && npm --version 2>&1 || echo MISSING)"
    row "tesseract"    "$(command -v tesseract >/dev/null 2>&1 && echo present || echo 'MISSING (screenshot OCR)')"
  else
    row "docker"       "$(command -v docker >/dev/null 2>&1 && echo present || echo MISSING)"
    row "compose"      "$( { docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1; } && echo present || echo MISSING)"
  fi
  smi=""; command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1 && smi=1
  hw="$(nvidia_hardware 2>/dev/null | head -1)"
  if   [[ -n "$smi" ]]; then row "NVIDIA GPU" "driver OK"
  elif [[ -n "$hw"  ]]; then row "NVIDIA GPU" "$hw - NO DRIVER"
  else                       row "NVIDIA GPU" "none (CPU mode)"; fi
  row "pkg manager"  "$(detect_pkg_mgr)"
}

# The GPU libraries need a working driver, not just a card. Offer the distro's driver package when
# the hardware is there and nvidia-smi is not - otherwise Iris silently runs on CPU.
ensure_nvidia_driver() {
  command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1 && return 0
  local hw; hw="$(nvidia_hardware 2>/dev/null | head -1)"
  [[ -n "$hw" ]] || return 1
  if [[ "$ENV_KIND" == "wsl" ]]; then
    warn "NVIDIA hardware is visible to WSL but nvidia-smi does not answer."
    warn "The driver belongs on WINDOWS, never inside WSL: install the latest Windows NVIDIA driver"
    warn "and run 'wsl --update'. Installing a Linux NVIDIA driver in WSL breaks GPU passthrough."
    return 1
  fi
  warn "NVIDIA hardware detected ($hw) but nvidia-smi is not available - the driver is missing."
  case "$(detect_pkg_mgr)" in
    apt)     pkg_install "the NVIDIA driver" nvidia-driver ;;
    dnf|yum) pkg_install "the NVIDIA driver" akmod-nvidia ;;
    pacman)  pkg_install "the NVIDIA driver" nvidia nvidia-utils ;;
    zypper)  pkg_install "the NVIDIA driver" nvidia-video-G06 ;;
    *)       warn "install the driver from https://www.nvidia.com/download/index.aspx and re-run" ; return 1 ;;
  esac || { warn "continuing without GPU acceleration (numpy)."; return 1; }
  warn "a REBOOT is usually required after a driver install before nvidia-smi works."
  command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1
}

# ── 1b. Native (no Docker) install ────────────────────────────────────────────
# Same dependency set the image gets, installed straight onto the host: base always, GPU extras when a GPU is present.
if [[ "$MODE" == "local" ]]; then
  preflight local

  # --- Python -----------------------------------------------------------------
  PY="$(find_python || true)"
  if [[ -z "$PY" ]]; then
    # Distinguish "no python" from "python too old" - they need different packages and the second
    # case is the confusing one (python3 exists, so a bare "not found" reads as wrong).
    if command -v python3 >/dev/null 2>&1; then
      warn "python3 is $(python3 --version 2>&1 | awk '{print $2}') - Iris needs 3.11 or newer."
    fi
    case "$(detect_pkg_mgr)" in
      apt)    pkg_install "Python 3" python3 python3-pip python3-venv ;;
      dnf|yum) pkg_install "Python 3" python3 python3-pip ;;
      pacman) pkg_install "Python 3" python python-pip ;;
      zypper) pkg_install "Python 3" python3 python3-pip ;;
      apk)    pkg_install "Python 3" python3 py3-pip ;;
      brew)   pkg_install "Python 3" python@3.12 ;;
      *)      false ;;
    esac
    PY="$(find_python || true)"
  fi
  [[ -n "$PY" ]] || die "Python 3.11+ not found and could not be installed. Install it and re-run: https://www.python.org/downloads/"
  log "Python: $("$PY" --version 2>&1)"

  # --- venv -------------------------------------------------------------------
  # Iris installs into a virtualenv at ./.venv, for two reasons that are both real on current distros:
  # Debian 12 / Ubuntu 24.04 mark the system interpreter EXTERNALLY-MANAGED (PEP 668), so `pip install`
  # there fails outright; and uninstalling cleanly means deleting one directory instead of guessing
  # which shared site-packages belong to Iris. start.sh local prefers .venv automatically.
  if [[ ! -x .venv/bin/python ]]; then
    log "Creating the virtualenv (.venv)..."
    if ! "$PY" -m venv .venv 2>/dev/null; then
      # Debian splits venv out of the stdlib package; without it `python3 -m venv` fails with
      # "ensurepip is not available".
      warn "python venv module is unavailable"
      case "$(detect_pkg_mgr)" in
        apt) pkg_install "the Python venv module" "python3-venv" && "$PY" -m venv .venv 2>/dev/null || true ;;
        *)   : ;;
      esac
    fi
  fi
  if [[ -x .venv/bin/python ]]; then
    PY="$(cd .venv/bin && pwd)/python"
    log "Using the virtualenv: .venv"
    "$PY" -m pip install --quiet --upgrade pip setuptools wheel || warn "could not upgrade pip inside the venv - continuing"
  else
    warn "could not create a virtualenv - installing into $PY instead"
    if ! "$PY" -m pip --version >/dev/null 2>&1; then
      log "pip is missing - bootstrapping it (python -m ensurepip)"
      "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || \
        case "$(detect_pkg_mgr)" in
          apt)     pkg_install "pip" python3-pip ;;
          dnf|yum) pkg_install "pip" python3-pip ;;
          pacman)  pkg_install "pip" python-pip ;;
          zypper)  pkg_install "pip" python3-pip ;;
          apk)     pkg_install "pip" py3-pip ;;
          *)       : ;;
        esac
      "$PY" -m pip --version >/dev/null 2>&1 || die "pip is not available for $PY. Install pip and re-run."
    fi
    # PEP 668: on an externally-managed interpreter pip refuses by design. Say so and pass the
    # documented opt-out rather than failing with a wall of text about a virtual environment.
    if "$PY" -m pip install --dry-run --quiet -r backend/requirements.txt 2>&1 | grep -q 'externally-managed-environment'; then
      warn "this interpreter is externally managed (PEP 668) - using --break-system-packages"
      PIP_EXTRA="--break-system-packages"
    fi
  fi
  PIP_EXTRA="${PIP_EXTRA:-}"

  log "Installing backend requirements..."
  # shellcheck disable=SC2086
  "$PY" -m pip install $PIP_EXTRA -r backend/requirements.txt || die "pip install of backend/requirements.txt failed"

  # --- OCR (tesseract) --------------------------------------------------------
  # The image parser shells out to the tesseract BINARY; without it, screenshots and photographed
  # screens fail at parse time rather than at setup time, which is the worst moment to find out.
  ensure_tesseract() {
    if command -v tesseract >/dev/null 2>&1; then
      log "OCR: $(tesseract --version 2>&1 | head -1)"
      return 0
    fi
    case "$(detect_pkg_mgr)" in
      apt)     pkg_install "tesseract (OCR for screenshots)" tesseract-ocr tesseract-ocr-eng ;;
      dnf|yum) pkg_install "tesseract (OCR for screenshots)" tesseract tesseract-langpack-eng ;;
      pacman)  pkg_install "tesseract (OCR for screenshots)" tesseract tesseract-data-eng ;;
      zypper)  pkg_install "tesseract (OCR for screenshots)" tesseract-ocr tesseract-ocr-traineddata-english ;;
      apk)     pkg_install "tesseract (OCR for screenshots)" tesseract-ocr tesseract-ocr-data-eng ;;
      brew)    pkg_install "tesseract (OCR for screenshots)" tesseract ;;
      *)       warn "tesseract not found - image/screenshot OCR will be unavailable" ; return 1 ;;
    esac || warn "tesseract not installed - every other format still parses; only image OCR is affected."
  }
  ensure_tesseract

  # The right GPU packages differ per machine (vendor, CUDA major/minor, OS), so resolve at setup time
  # instead of pinning one set. Override with IRIS_CUPY / IRIS_TORCH_INDEX if the guess is wrong.
  local_has_nvidia() {
    command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1 && return 0
    if [[ -x /usr/lib/wsl/lib/nvidia-smi ]] && /usr/lib/wsl/lib/nvidia-smi -L >/dev/null 2>&1; then
      export PATH="$PATH:/usr/lib/wsl/lib"; return 0; fi
    return 1
  }
  install_gpu_libs() {
    local cuda maj min cupy tag index
    # older drivers print "CUDA Version: 12.4"; newer ones (580+) print "CUDA UMD Version: 13.3"
    cuda="$(nvidia-smi 2>&1 | sed -n 's/.*CUDA[[:space:]]*\(UMD[[:space:]]*\)\?Version:[[:space:]]*\([0-9]\+\.[0-9]\+\).*/\2/p' | head -1)"
    if [[ -z "$cuda" ]]; then
      warn "Could not read the CUDA version from nvidia-smi - skipping GPU libraries (Iris runs on CPU)."; return 1; fi
    maj="${cuda%%.*}"; min="${cuda##*.}"
    log "Driver reports CUDA $cuda"
    case "$maj" in
      13) cupy='cupy-cuda13x[ctk]>=13.0' ;;
      12) cupy='cupy-cuda12x[ctk]>=13.0' ;;
      11) cupy='cupy-cuda11x>=13.0' ;;
      *)  warn "Unrecognised CUDA major '$maj' - trying the CUDA 12 wheel."; cupy='cupy-cuda12x[ctk]>=13.0' ;;
    esac
    if   (( maj >= 13 )); then tag=cu128           # CUDA 13 drivers run cu128 wheels (minor-version compatible)
    elif (( maj == 12 && min >= 8 )); then tag=cu128
    elif (( maj == 12 && min >= 6 )); then tag=cu126
    elif (( maj == 12 && min >= 4 )); then tag=cu124
    elif (( maj == 12 )); then tag=cu121
    else tag=cu118; fi
    [[ -n "${IRIS_CUPY:-}" ]] && cupy="$IRIS_CUPY"
    index="${IRIS_TORCH_INDEX:-https://download.pytorch.org/whl/$tag}"
    log "Installing GPU compute libraries: $cupy + torch ($tag). Multi-GB download..."
    "$PY" -m pip install $PIP_EXTRA "$cupy" 'nvidia-ml-py>=12.560' || warn "cupy failed to install - correlation will run on CPU (numpy)."
    "$PY" -m pip install $PIP_EXTRA torch --index-url "$index" || warn "torch failed to install (index $index). Set IRIS_TORCH_INDEX and re-run to override."
    if probe="$("$PY" -c 'import cupy; cupy.zeros(1).sum(); print(cupy.cuda.runtime.runtimeGetVersion())' 2>&1)"; then
      log "cupy is working (CUDA runtime $probe)"
    else
      warn "cupy is not usable on this host: $probe"; warn "Iris will fall back to torch, then to numpy."
    fi
  }

  if [[ "$ENV_KIND" == "macos" ]]; then
    # No CUDA on macOS. Apple Silicon gets torch's MPS backend; cupy has no macOS wheels at all.
    if [[ "$(uname -m)" == "arm64" ]]; then
      log "macOS on Apple Silicon - installing torch (Metal/MPS backend); cupy is CUDA-only and skipped."
      "$PY" -m pip install $PIP_EXTRA torch || warn "torch failed to install - Iris runs on CPU (numpy)."
    else
      log "macOS on Intel - no GPU acceleration available, CPU only (numpy)."
    fi
  elif local_has_nvidia || ensure_nvidia_driver; then
    log "NVIDIA GPU detected: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | paste -sd ',' -)"
    install_gpu_libs
  elif command -v rocminfo >/dev/null 2>&1 || [[ -e /dev/kfd ]]; then
    # AMD ROCm (Linux only). cupy's ROCm wheels are source-built and fragile, so use torch's ROCm build.
    log "AMD ROCm GPU detected - installing the torch ROCm build (cupy has no reliable ROCm wheel)."
    "$PY" -m pip install $PIP_EXTRA torch --index-url "${IRIS_TORCH_INDEX:-https://download.pytorch.org/whl/rocm6.2}" \
      || warn "torch (ROCm) failed to install - Iris runs on CPU (numpy). Set IRIS_TORCH_INDEX to pick another ROCm build."
  else
    log "No GPU detected - CPU only (numpy). Iris is fully functional without a GPU."
  fi

  # --- Node / npm -------------------------------------------------------------
  # Without this the UI is never built and Iris serves the API alone - a working install with no app
  # in it. That is worth installing Node for, not warning about.
  ensure_node() {
    command -v npm >/dev/null 2>&1 && return 0
    case "$(detect_pkg_mgr)" in
      apt)     pkg_install "Node.js (to build the UI)" nodejs npm ;;
      dnf|yum) pkg_install "Node.js (to build the UI)" nodejs npm ;;
      pacman)  pkg_install "Node.js (to build the UI)" nodejs npm ;;
      zypper)  pkg_install "Node.js (to build the UI)" nodejs npm ;;
      apk)     pkg_install "Node.js (to build the UI)" nodejs npm ;;
      brew)    pkg_install "Node.js (to build the UI)" node ;;
      *)       return 1 ;;
    esac
    command -v npm >/dev/null 2>&1
  }
  if ensure_node; then
    log "Node: $(node --version 2>&1) / npm $(npm --version 2>&1)"
    log "Building the frontend..."
    # --ignore-scripts everywhere: npm lifecycle hooks are the supply-chain foothold, and Iris needs none.
    (cd frontend && npm install --ignore-scripts && npm run build) || warn "the frontend build failed - the API still serves on :8000"
  else
    warn "npm not found and could not be installed - skipping the frontend build."
    warn "The API will serve on :8000 but there will be NO UI. Install Node 18+ and re-run: https://nodejs.org/"
  fi

  [[ -f .env ]] || cp .env.example .env
  if [[ -x .venv/bin/python ]]; then
    log "Done. Start Iris with:  ./start.sh local        (it uses .venv automatically)"
  else
    log "Done. Start Iris with:  ./start.sh local"
  fi
  exit 0
fi

# ── 2. Docker CLI ─────────────────────────────────────────────────────────────
install_docker() {
  # Only Linux/WSL can be scripted sensibly. Docker Desktop on macOS is a signed .app and on Windows an
  # installer with a EULA - offered through the platform's own package manager or not at all.
  case "$ENV_KIND" in
    macos)
      if [[ "$(detect_pkg_mgr)" == "brew" ]]; then
        if [[ $NO_INSTALL == 1 ]]; then return 1; fi
        log "Docker is missing. This will run:"
        printf '        brew install --cask docker\n'
        ask "Install Docker Desktop now?" || return 1
        brew install --cask docker || return 1
        log "Docker Desktop installed - starting it..."
        open -a Docker 2>/dev/null || true
        return 0
      fi
      return 1 ;;
    linux|wsl)
      # get.docker.com is Docker's own convenience script. It is piped to sh, so it is shown, named and
      # confirmed first - never run silently.
      if [[ $NO_INSTALL == 1 ]]; then return 1; fi
      command -v curl >/dev/null 2>&1 || pkg_install "curl" curl || return 1
      need_sudo || { warn "installing Docker needs root, and sudo is not available"; return 1; }
      log "Docker is missing. This will download and run Docker's official install script:"
      printf '        curl -fsSL https://get.docker.com | %s sh\n' "$SUDO"
      ask "Install Docker Engine now?" || return 1
      curl -fsSL https://get.docker.com -o /tmp/iris-get-docker.sh || { warn "could not download the Docker install script"; return 1; }
      $SUDO sh /tmp/iris-get-docker.sh || { rm -f /tmp/iris-get-docker.sh; warn "the Docker install script failed"; return 1; }
      rm -f /tmp/iris-get-docker.sh
      # Without this every docker call needs sudo for the rest of this login session.
      if [[ "$(id -u)" != "0" ]]; then
        $SUDO usermod -aG docker "$USER" 2>/dev/null && \
          warn "added $USER to the 'docker' group - log out and back in (or run 'newgrp docker') to use docker without sudo"
      fi
      command -v systemctl >/dev/null 2>&1 && $SUDO systemctl enable --now docker >/dev/null 2>&1 || true
      return 0 ;;
  esac
  return 1
}

[[ "$MODE" == "down" || "$MODE" == "logs" ]] || preflight docker

if ! command -v docker >/dev/null 2>&1; then
  install_docker || true
fi
if ! command -v docker >/dev/null 2>&1; then
  case "$ENV_KIND" in
    wsl)   die "docker not found in WSL. Either install Docker Desktop for Windows and enable Settings > Resources > WSL integration for this distro, or install Docker Engine inside WSL: https://docs.docker.com/engine/install/ubuntu/" ;;
    macos) die "docker not found. Install Docker Desktop for Mac (or OrbStack): https://docs.docker.com/desktop/setup/install/mac-install/" ;;
    *)     die "docker not found. Install Docker Engine: https://docs.docker.com/engine/install/  then: sudo usermod -aG docker \$USER && newgrp docker" ;;
  esac
fi

DOCKER="docker"
if ! docker info >/dev/null 2>&1; then
  # permission problem on the socket? try sudo (native Linux / Docker Engine in WSL)
  if [[ "$ENV_KIND" != "macos" ]] && command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
    warn "Using 'sudo docker' (to avoid this: sudo usermod -aG docker \$USER && newgrp docker)"
    DOCKER="sudo docker"
  fi
fi

# ── 3. Daemon running? try to start it ────────────────────────────────────────
if ! $DOCKER info >/dev/null 2>&1; then
  case "$ENV_KIND" in
    macos)
      log "Starting Docker Desktop..."; open -a Docker 2>/dev/null || open -a OrbStack 2>/dev/null || true ;;
    wsl)
      DD="/mnt/c/Program Files/Docker/Docker/Docker Desktop.exe"
      if [[ -f "$DD" ]]; then
        log "Starting Docker Desktop on the Windows host..."
        ( nohup "$DD" >/dev/null 2>&1 & ) || true
      elif command -v systemctl >/dev/null 2>&1; then log "Starting Docker Engine (systemd)..."; sudo systemctl start docker || true
      elif command -v service >/dev/null 2>&1;   then log "Starting Docker Engine (service)..."; sudo service docker start || true
      fi ;;
    linux)
      if   command -v systemctl >/dev/null 2>&1; then log "Starting Docker Engine (systemd)..."; sudo systemctl start docker || true
      elif command -v service >/dev/null 2>&1;   then log "Starting Docker Engine (service)..."; sudo service docker start || true
      fi ;;
  esac
  for _ in $(seq 1 60); do $DOCKER info >/dev/null 2>&1 && break; sleep 2; done
  $DOCKER info >/dev/null 2>&1 || die "Docker daemon is not reachable. Start Docker and re-run."
fi
SRV_OS="$($DOCKER version --format '{{.Server.Os}}' 2>/dev/null || echo linux)"
[[ "$SRV_OS" == "windows" ]] && die "Docker is in Windows-containers mode. Switch to Linux containers (Docker Desktop tray icon) and re-run."
log "Docker engine: $($DOCKER version --format '{{.Server.Version}}' 2>/dev/null || echo ok)"

# ── 4. Compose v2 vs legacy ───────────────────────────────────────────────────
ensure_compose() {
  $DOCKER compose version >/dev/null 2>&1 && return 0
  command -v docker-compose >/dev/null 2>&1 && return 0
  case "$(detect_pkg_mgr)" in
    apt)     pkg_install "the Docker Compose plugin" docker-compose-plugin ;;
    dnf|yum) pkg_install "the Docker Compose plugin" docker-compose-plugin ;;
    pacman)  pkg_install "the Docker Compose plugin" docker-compose ;;
    zypper)  pkg_install "the Docker Compose plugin" docker-compose ;;
    apk)     pkg_install "the Docker Compose plugin" docker-cli-compose ;;
    brew)    pkg_install "the Docker Compose plugin" docker-compose ;;
    *)       return 1 ;;
  esac
  $DOCKER compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1
}
ensure_compose || true

if $DOCKER compose version >/dev/null 2>&1; then COMPOSE="$DOCKER compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"; [[ "$DOCKER" == sudo* ]] && COMPOSE="sudo docker-compose"
else die "Docker Compose not found. Install the compose plugin: https://docs.docker.com/compose/install/"; fi

FILES=(-f docker-compose.yml)
case "$MODE" in
  down) exec $COMPOSE "${FILES[@]}" -f docker-compose.gpu.yml down ;;
  logs) exec $COMPOSE "${FILES[@]}" logs -f ;;
  auto|gpu|cpu) ;;
  *) die "usage: $0 [auto|gpu|cpu|local|down|logs] [--yes] [--no-install]" ;;
esac

# ── 5. GPU detection ──────────────────────────────────────────────────────────
has_gpu() {
  command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1 && return 0
  # WSL2 ships nvidia-smi in /usr/lib/wsl/lib (not always on PATH)
  if [[ -x /usr/lib/wsl/lib/nvidia-smi ]] && /usr/lib/wsl/lib/nvidia-smi -L >/dev/null 2>&1; then
    export PATH="$PATH:/usr/lib/wsl/lib"; return 0; fi
  # Windows-host nvidia-smi.exe visible from WSL interop
  if [[ "$ENV_KIND" == "wsl" ]] && command -v nvidia-smi.exe >/dev/null 2>&1 && nvidia-smi.exe -L >/dev/null 2>&1; then
    NVSMI="nvidia-smi.exe"; return 0; fi
  [[ -e /dev/nvidia0 || -e /dev/dxg ]] && return 0
  return 1
}
NVSMI="nvidia-smi"
gpu_names() { $NVSMI --query-gpu=name --format=csv,noheader 2>/dev/null | paste -sd ',' - || echo "NVIDIA GPU"; }
docker_gpu_ok() { $DOCKER run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi -L >/dev/null 2>&1; }

# The container toolkit is what lets the daemon see the GPU at all on native Linux. It is a package,
# so it can be installed here rather than printed as a link and left to the reader.
install_nvidia_toolkit() {
  [[ "$ENV_KIND" == "linux" ]] || return 1
  [[ $NO_INSTALL == 1 ]] && return 1
  need_sudo || return 1
  case "$(detect_pkg_mgr)" in
    apt)
      log "NVIDIA Container Toolkit is missing. This will add NVIDIA's apt repository and install it."
      ask "Install the NVIDIA Container Toolkit now?" || return 1
      curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | $SUDO gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg 2>/dev/null || return 1
      curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        | $SUDO tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null || return 1
      $SUDO apt-get update -qq && $SUDO apt-get install -y nvidia-container-toolkit || return 1
      ;;
    dnf|yum)
      log "NVIDIA Container Toolkit is missing. This will add NVIDIA's yum repository and install it."
      ask "Install the NVIDIA Container Toolkit now?" || return 1
      curl -fsSL https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo \
        | $SUDO tee /etc/yum.repos.d/nvidia-container-toolkit.repo >/dev/null || return 1
      $SUDO "$(detect_pkg_mgr)" install -y nvidia-container-toolkit || return 1
      ;;
    pacman) pkg_install "the NVIDIA Container Toolkit" nvidia-container-toolkit || return 1 ;;
    *) return 1 ;;
  esac
  $SUDO nvidia-ctk runtime configure --runtime=docker >/dev/null 2>&1 || return 1
  command -v systemctl >/dev/null 2>&1 && $SUDO systemctl restart docker >/dev/null 2>&1 || true
  sleep 3
  return 0
}

USE_GPU=0
if [[ "$MODE" == "cpu" ]]; then
  log "CPU mode forced."
elif [[ "$ENV_KIND" == "macos" ]]; then
  log "macOS: Docker has no CUDA support -> CPU image."
elif [[ "$MODE" == "gpu" ]] || has_gpu; then
  log "NVIDIA GPU detected: $(gpu_names)"
  log "Checking Docker GPU passthrough (pulls a tiny CUDA base image once)..."
  if docker_gpu_ok; then
    USE_GPU=1; log "GPU passthrough OK -> CUDA image"
  else
    # One attempt to actually fix it before falling back - on native Linux the missing piece is a package.
    if [[ "$ENV_KIND" == "linux" ]] && install_nvidia_toolkit && docker_gpu_ok; then
      USE_GPU=1; log "NVIDIA Container Toolkit installed - GPU passthrough OK -> CUDA image"
    else
      case "$ENV_KIND" in
        wsl)   warn "Docker cannot see the GPU. Docker Desktop: enable WSL 2 backend + WSL integration, update the *Windows* NVIDIA driver, run 'wsl --update'. Never install a Linux NVIDIA driver inside WSL. Docker Engine inside WSL: install nvidia-container-toolkit." ;;
        linux) warn "Docker cannot see the GPU. Install NVIDIA Container Toolkit: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html  then: sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker" ;;
      esac
      [[ "$MODE" == "gpu" ]] && die "GPU mode forced but passthrough failed."
      warn "Falling back to CPU image (Iris still runs; parsing uses CPU)."
    fi
  fi
else
  log "No NVIDIA GPU detected -> CPU image."
fi
if [[ $USE_GPU == 1 ]]; then
  FILES+=(-f docker-compose.gpu.yml)
  # Match the image's CUDA runtime + wheel set to the host driver. A CUDA 12 runtime works on 12.x AND 13.x
  # drivers (backward compatible), so only a CUDA 11-only host needs the older pair.
  # Two header spellings: "CUDA Version: 12.4" (older) and "CUDA UMD Version: 13.3" (580+ drivers).
  HOST_CUDA="$($NVSMI 2>&1 | sed -n 's/.*CUDA[[:space:]]*\(UMD[[:space:]]*\)\?Version:[[:space:]]*\([0-9]\+\.[0-9]\+\).*/\2/p' | head -1)"
  if [[ -n "$HOST_CUDA" && "${HOST_CUDA%%.*}" -le 11 ]]; then
    log "Host driver supports CUDA $HOST_CUDA -> building on the CUDA 11.8 runtime (cupy-cuda11x)"
    export IRIS_GPU_BASE_IMAGE='nvidia/cuda:11.8.0-runtime-ubuntu22.04'
    export IRIS_GPU_REQUIREMENTS='requirements-gpu-cuda11.txt'
    export IRIS_GPU_TORCH_INDEX='https://download.pytorch.org/whl/cu118'
  elif [[ -n "$HOST_CUDA" ]]; then
    log "Host driver supports CUDA $HOST_CUDA -> CUDA 12.4 runtime image (cupy-cuda12x + torch cu124)"
  fi
fi

# ── 6. Build & run ────────────────────────────────────────────────────────────
[[ -f .env ]] || cp .env.example .env
if [[ $USE_GPU == 1 ]]; then log "Building & starting (CUDA)..."; else log "Building & starting (CPU)..."; fi
$COMPOSE "${FILES[@]}" up -d --build || die "compose up failed"
log "Iris is up -> http://localhost:8000   (Settings > Compute shows the active backend)"
[[ "$ENV_KIND" == "wsl" ]] && log "The same URL works from Windows browsers."
exit 0
