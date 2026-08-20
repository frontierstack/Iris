<#
 Iris setup for Windows (PowerShell 5.1+ / pwsh).
 Handles Docker Desktop (WSL 2 or Hyper-V backend), starts Docker if it isn't running,
 detects an NVIDIA GPU + container passthrough, and builds the CUDA or CPU image.

   .\setup.ps1              # auto-detect
   .\setup.ps1 -Mode gpu    # force CUDA image
   .\setup.ps1 -Mode cpu    # force CPU image
   .\setup.ps1 -Mode local  # no Docker: install Python/Node deps into this machine (GPU deps if an NVIDIA GPU is present)
   .\setup.ps1 -Mode down   # stop & remove
   .\setup.ps1 -Mode logs   # follow logs

 Prefer running inside WSL? Open your distro in this folder and run ./setup.sh
#>
param([ValidateSet('auto','gpu','cpu','local','down','logs')][string]$Mode = 'auto')
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
function Log($m)  { Write-Host "[iris] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[iris] $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[iris] $m" -ForegroundColor Red; exit 1 }

function Test-Gpu {
  if (-not (Get-Command nvidia-smi -ErrorAction SilentlyContinue)) {
    $cand = Join-Path $env:SystemRoot 'System32\nvidia-smi.exe'
    if (Test-Path $cand) { $env:PATH += ";" + (Split-Path $cand) } else { return $false }
  }
  & nvidia-smi -L *> $null
  return ($LASTEXITCODE -eq 0)
}

# ── GPU wheel resolution ─────────────────────────────────────────────────────
# The right GPU packages differ per machine (CUDA major/minor, vendor, OS), so resolve them at setup
# time instead of pinning one set. Override with IRIS_CUPY / IRIS_TORCH_INDEX if the guess is wrong.
function Get-CudaVersion {
  # The header line is the max CUDA the DRIVER supports (the runtime wheel may be older). Two known spellings:
  #   older drivers: "CUDA Version: 12.4"      newer (580+): "CUDA UMD Version: 13.3"
  $out = (& nvidia-smi 2>&1 | Out-String)
  if ($out -match 'CUDA(?:\s+UMD)?\s+Version:\s*(\d+)\.(\d+)') { return @([int]$Matches[1], [int]$Matches[2]) }
  return $null
}
function Resolve-GpuWheels {
  $cuda = Get-CudaVersion
  if (-not $cuda) { return $null }
  $maj, $min = $cuda[0], $cuda[1]
  Log "Driver reports CUDA $maj.$min"
  # cupy ships one wheel per CUDA major line
  $cupy = switch ($maj) { 13 { 'cupy-cuda13x[ctk]>=13.0' } 12 { 'cupy-cuda12x[ctk]>=13.0' } 11 { 'cupy-cuda11x>=13.0' }
                          default { Warn "Unrecognised CUDA major '$maj' - trying the CUDA 12 wheel."; 'cupy-cuda12x[ctk]>=13.0' } }
  # torch publishes a fixed set of index tags; pick the highest that does not exceed the driver
  $tag = if ($maj -ge 13) { 'cu128' }             # CUDA 13 drivers run cu128 wheels (minor-version compatible)
         elseif ($maj -eq 12 -and $min -ge 8) { 'cu128' }
         elseif ($maj -eq 12 -and $min -ge 6) { 'cu126' }
         elseif ($maj -eq 12 -and $min -ge 4) { 'cu124' }
         elseif ($maj -eq 12) { 'cu121' }
         else { 'cu118' }
  if ($env:IRIS_CUPY) { $cupy = $env:IRIS_CUPY }
  $index = if ($env:IRIS_TORCH_INDEX) { $env:IRIS_TORCH_INDEX } else { "https://download.pytorch.org/whl/$tag" }
  return @{ cupy = $cupy; torchIndex = $index; tag = $tag }
}

# ── Native (no Docker) install ───────────────────────────────────────────────
# Mirrors what the Docker image does, straight onto the host: base deps always, GPU deps that match THIS machine.
if ($Mode -eq 'local') {
  $py = (Get-Command python -ErrorAction SilentlyContinue), (Get-Command python3 -ErrorAction SilentlyContinue) |
        Where-Object { $_ } | Select-Object -First 1
  if (-not $py) { Die "python not found on PATH. Install Python 3.11+ and re-run." }
  Log "Python: $((& $py.Source --version) 2>&1)"

  Log "Installing backend requirements..."
  & $py.Source -m pip install -r backend/requirements.txt
  if ($LASTEXITCODE -ne 0) { Die "pip install of backend/requirements.txt failed" }

  if (Test-Gpu) {
    $names = ((& nvidia-smi --query-gpu=name --format=csv,noheader 2>$null) -join ', ')
    Log "NVIDIA GPU detected: $names"
    $w = Resolve-GpuWheels
    if (-not $w) {
      Warn "Could not read the CUDA version from nvidia-smi - skipping GPU libraries (Iris runs on CPU)."
    } else {
      Log "Installing GPU compute libraries: $($w.cupy) + torch ($($w.tag)). Multi-GB download..."
      & $py.Source -m pip install $w.cupy 'nvidia-ml-py>=12.560'
      if ($LASTEXITCODE -ne 0) { Warn "cupy failed to install - correlation will run on CPU (numpy)." }
      & $py.Source -m pip install torch --index-url $w.torchIndex
      if ($LASTEXITCODE -ne 0) { Warn "torch failed to install (index $($w.torchIndex)). Set IRIS_TORCH_INDEX and re-run to override." }
      $probe = & $py.Source -c "import cupy; cupy.zeros(1).sum(); print(cupy.cuda.runtime.runtimeGetVersion())" 2>&1
      if ($LASTEXITCODE -eq 0) { Log "cupy is working (CUDA runtime $probe)" }
      else { Warn "cupy is not usable on this host: $probe" ; Warn "Iris will fall back to torch, then to numpy." }
    }
  } else {
    Log "No NVIDIA GPU detected - CPU only (numpy). Iris is fully functional without a GPU."
  }

  if (Get-Command npm -ErrorAction SilentlyContinue) {
    Log "Building the frontend..."
    Push-Location frontend; & npm install --ignore-scripts; & npm run build; Pop-Location
  } else { Warn "npm not found - skipping the frontend build (the API still serves on :8000)." }

  if (-not (Test-Path .env)) { Copy-Item .env.example .env }
  Log "Done. Start Iris with:  cd backend; python -m uvicorn app.main:app --port 8000"
  exit 0
}

# ── Docker CLI ───────────────────────────────────────────────────────────────
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Die "docker not found. Install Docker Desktop for Windows (choose the WSL 2 backend for GPU support): https://docs.docker.com/desktop/setup/install/windows-install/"
}
function Test-Daemon { & docker info *> $null; return ($LASTEXITCODE -eq 0) }

if (-not (Test-Daemon)) {
  $dd = @("$env:ProgramFiles\Docker\Docker\Docker Desktop.exe", "$env:LOCALAPPDATA\Docker\Docker Desktop.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($dd) { Log "Docker daemon not running - starting Docker Desktop..."; Start-Process $dd | Out-Null }
  else     { Warn "Docker daemon not running and Docker Desktop.exe not found - waiting in case a WSL/remote engine comes up..." }
  $ok = $false
  for ($i = 0; $i -lt 90 -and -not $ok; $i++) { Start-Sleep -Seconds 2; $ok = Test-Daemon }
  if (-not $ok) { Die "Docker daemon not reachable after 3 minutes. Start Docker and re-run." }
}
$srvOs  = (& docker version --format '{{.Server.Os}}' 2>$null)
$srvVer = (& docker version --format '{{.Server.Version}}' 2>$null)
if ($srvOs -eq 'windows') { Die "Docker is in Windows-containers mode. Tray icon -> 'Switch to Linux containers...' and re-run." }
Log "Docker engine: $srvVer"

# ── Compose v2 vs legacy ─────────────────────────────────────────────────────
& docker compose version *> $null
if ($LASTEXITCODE -eq 0) { $composeExe = 'docker'; $composePre = @('compose') }
elseif (Get-Command docker-compose -ErrorAction SilentlyContinue) { $composeExe = 'docker-compose'; $composePre = @() }
else { Die "Docker Compose not found (update Docker Desktop)." }
function Compose([string[]]$a) { & $composeExe @($composePre + $a) }

$files = @('-f','docker-compose.yml')
if ($Mode -eq 'down') { Compose ($files + @('-f','docker-compose.gpu.yml','down')); exit $LASTEXITCODE }
if ($Mode -eq 'logs') { Compose ($files + @('logs','-f')); exit $LASTEXITCODE }

# ── GPU detection ────────────────────────────────────────────────────────────
function Test-DockerGpu {
  & docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi -L *> $null
  return ($LASTEXITCODE -eq 0)
}
function Get-Backend {
  # Older Docker Desktop put "WSL" in OperatingSystem; current versions report just "Docker Desktop"
  # and only the kernel string carries the marker (e.g. 6.18.x-microsoft-standard-WSL2). Check both,
  # otherwise a perfectly good WSL-2 engine gets warned about for no reason.
  try {
    $os  = (& docker info --format '{{.OperatingSystem}}' 2>$null)
    $krn = (& docker info --format '{{.KernelVersion}}' 2>$null)
    if ("$os" -match 'WSL' -or "$krn" -match 'WSL|microsoft') { return 'wsl2' }
    return "$os"
  } catch { return 'unknown' }
}

$useGpu = $false
if ($Mode -eq 'cpu') { Log "CPU mode forced." }
elseif ($Mode -eq 'gpu' -or (Test-Gpu)) {
  $names = ((& nvidia-smi --query-gpu=name --format=csv,noheader 2>$null) -join ', ')
  if (-not $names) { $names = 'NVIDIA GPU' }
  Log "NVIDIA GPU detected: $names"
  $be = Get-Backend
  if ($be -ne 'wsl2') { Warn "Docker backend is '$be'. GPU passthrough on Windows needs the WSL 2 backend (Docker Desktop > Settings > General > 'Use the WSL 2 based engine')." }
  Log "Checking Docker GPU passthrough (pulls a tiny CUDA base image once)..."
  if (Test-DockerGpu) { $useGpu = $true; Log "GPU passthrough OK -> CUDA image" }
  else {
    Warn "Docker cannot see the GPU. Checklist: WSL 2 backend on; latest Windows NVIDIA driver; run 'wsl --update'; do NOT install a Linux NVIDIA driver inside WSL."
    if ($Mode -eq 'gpu') { Die "GPU mode forced but passthrough failed." }
    Warn "Falling back to CPU image (Iris still runs; parsing uses CPU)."
  }
} else { Log "No NVIDIA GPU detected -> CPU image." }

if ($useGpu) {
  $files += @('-f','docker-compose.gpu.yml')
  # Match the image's CUDA runtime + wheel set to what the host driver supports. A CUDA 12 runtime works on
  # 12.x AND 13.x drivers (backward compatible), so only a CUDA 11-only host needs the older pair.
  $cuda = Get-CudaVersion
  if ($cuda -and $cuda[0] -le 11) {
    Log "Host driver supports CUDA $($cuda[0]).$($cuda[1]) -> building on the CUDA 11.8 runtime (cupy-cuda11x)"
    $env:IRIS_GPU_BASE_IMAGE  = 'nvidia/cuda:11.8.0-runtime-ubuntu22.04'
    $env:IRIS_GPU_REQUIREMENTS = 'requirements-gpu-cuda11.txt'
    $env:IRIS_GPU_TORCH_INDEX  = 'https://download.pytorch.org/whl/cu118'
  } elseif ($cuda) {
    Log "Host driver supports CUDA $($cuda[0]).$($cuda[1]) -> CUDA 12.4 runtime image (cupy-cuda12x + torch cu124)"
  }
}

# ── WSL 2 tuning ─────────────────────────────────────────────────────────────
# Iris is memory-heavy inside the VM, and an untuned VM has segfaulted processes on this class of machine.
# setup REPORTS and offers to fix it; it never restarts WSL behind your back (that stops every container).
# See wsl.ps1 for what each setting does and why.
$wslHelper = Join-Path $PSScriptRoot 'wsl.ps1'
if ((Test-Path $wslHelper) -and (Get-Command wsl -ErrorAction SilentlyContinue)) {
  try {
    . $wslHelper -Quiet
    if (Get-WslDrift) {
      Show-WslStatus
      $ans = Read-Host "    Write these settings to .wslconfig now? [y/N]"
      if ($ans -match '^(y|yes)$') {
        Write-WslConfig
        Warn "they take effect after:  wsl --shutdown   (stops every container; start Docker again after)"
      }
    }
  } catch { }
}

# ── Build & run ──────────────────────────────────────────────────────────────
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
if ($useGpu) { Log "Building & starting (CUDA)..." } else { Log "Building & starting (CPU)..." }
Compose ($files + @('up','-d','--build'))
if ($LASTEXITCODE -ne 0) { Die "compose up failed" }
Log "Iris is up -> http://localhost:8000   (Settings > Compute shows the active backend)"
