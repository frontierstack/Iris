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
# ──────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")"
MODE="${1:-auto}"
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
  exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "./setup.ps1" -Mode "$MODE"
fi

# ── 1b. Native (no Docker) install ────────────────────────────────────────────
# Same dependency set the image gets, installed straight onto the host: base always, GPU extras when a GPU is present.
if [[ "$MODE" == "local" ]]; then
  PY="$(command -v python3 || command -v python || true)"
  [[ -n "$PY" ]] || die "python3 not found. Install Python 3.11+ and re-run."
  log "Python: $("$PY" --version 2>&1)"

  log "Installing backend requirements..."
  "$PY" -m pip install -r backend/requirements.txt || die "pip install of backend/requirements.txt failed"

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
    "$PY" -m pip install "$cupy" 'nvidia-ml-py>=12.560' || warn "cupy failed to install - correlation will run on CPU (numpy)."
    "$PY" -m pip install torch --index-url "$index" || warn "torch failed to install (index $index). Set IRIS_TORCH_INDEX and re-run to override."
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
      "$PY" -m pip install torch || warn "torch failed to install - Iris runs on CPU (numpy)."
    else
      log "macOS on Intel - no GPU acceleration available, CPU only (numpy)."
    fi
  elif local_has_nvidia; then
    log "NVIDIA GPU detected: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | paste -sd ',' -)"
    install_gpu_libs
  elif command -v rocminfo >/dev/null 2>&1 || [[ -e /dev/kfd ]]; then
    # AMD ROCm (Linux only). cupy's ROCm wheels are source-built and fragile, so use torch's ROCm build.
    log "AMD ROCm GPU detected - installing the torch ROCm build (cupy has no reliable ROCm wheel)."
    "$PY" -m pip install torch --index-url "${IRIS_TORCH_INDEX:-https://download.pytorch.org/whl/rocm6.2}" \
      || warn "torch (ROCm) failed to install - Iris runs on CPU (numpy). Set IRIS_TORCH_INDEX to pick another ROCm build."
  else
    log "No GPU detected - CPU only (numpy). Iris is fully functional without a GPU."
  fi

  if command -v npm >/dev/null 2>&1; then
    log "Building the frontend..."
    (cd frontend && npm install --ignore-scripts && npm run build)
  else
    warn "npm not found - skipping the frontend build (the API still serves on :8000)."
  fi

  [[ -f .env ]] || cp .env.example .env
  log "Done. Start Iris with:  cd backend && python3 -m uvicorn app.main:app --port 8000"
  exit 0
fi

# ── 2. Docker CLI ─────────────────────────────────────────────────────────────
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
if $DOCKER compose version >/dev/null 2>&1; then COMPOSE="$DOCKER compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"; [[ "$DOCKER" == sudo* ]] && COMPOSE="sudo docker-compose"
else die "Docker Compose not found. Install the compose plugin: https://docs.docker.com/compose/install/"; fi

FILES=(-f docker-compose.yml)
case "$MODE" in
  down) exec $COMPOSE "${FILES[@]}" -f docker-compose.gpu.yml down ;;
  logs) exec $COMPOSE "${FILES[@]}" logs -f ;;
  auto|gpu|cpu) ;;
  *) die "usage: $0 [auto|gpu|cpu|local|down|logs]" ;;
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
    case "$ENV_KIND" in
      wsl)   warn "Docker cannot see the GPU. Docker Desktop: enable WSL 2 backend + WSL integration, update the *Windows* NVIDIA driver, run 'wsl --update'. Never install a Linux NVIDIA driver inside WSL. Docker Engine inside WSL: install nvidia-container-toolkit." ;;
      linux) warn "Docker cannot see the GPU. Install NVIDIA Container Toolkit: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html  then: sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker" ;;
    esac
    [[ "$MODE" == "gpu" ]] && die "GPU mode forced but passthrough failed."
    warn "Falling back to CPU image (Iris still runs; parsing uses CPU)."
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
