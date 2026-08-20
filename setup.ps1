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

   -Yes                     # install missing dependencies without asking
   -NoInstall               # never install anything; report what is missing and stop

 THIS ASSUMES A BARE MACHINE. Nothing is expected to be present - not Python, not Node, not Docker,
 not even a package manager. Anything missing is installed through winget (Windows 10 1809+ ships it
 as "App Installer"); if winget itself is absent, the script says exactly which one-line command
 installs it and which direct download to use instead. Declining any prompt leaves the old behaviour:
 a clear message naming the dependency and its URL.

 Prefer running inside WSL? Open your distro in this folder and run ./setup.sh
#>
param(
  [ValidateSet('auto','gpu','cpu','local','down','logs')][string]$Mode = 'auto',
  [switch]$Yes,
  [switch]$NoInstall
)
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
function Log($m)  { Write-Host "[iris] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[iris] $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[iris] $m" -ForegroundColor Red; exit 1 }

# ── Dependency installation (winget) ─────────────────────────────────────────
# One place that knows how to put software on this machine. Everything below can then offer a fix
# instead of only naming one - which matters most on a fresh Windows box, where NOTHING is installed.

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Update-SessionPath {
  # winget writes the new PATH to the registry, but THIS process keeps the environment block it was
  # started with - so a freshly installed python/node is "not found" until the shell is restarted.
  # Rebuilding $env:PATH from both hives is what makes install-then-use work in one run.
  $machine = [Environment]::GetEnvironmentVariable('Path','Machine')
  $user    = [Environment]::GetEnvironmentVariable('Path','User')
  $env:PATH = (@($machine, $user) | Where-Object { $_ }) -join ';'
}

function Ask($question) {
  if ($Yes) { return $true }
  # Non-interactive (CI, a pipe) and no -Yes: never install silently.
  if ([Console]::IsInputRedirected) { return $false }
  Write-Host "[iris] $question [Y/n] " -ForegroundColor Yellow -NoNewline
  $reply = $Host.UI.ReadLine()
  return ($reply -eq '' -or $reply -match '^(y|yes)$')
}

$script:WingetChecked = $false
function Get-Winget {
  $wg = Get-Command winget -ErrorAction SilentlyContinue
  if ($wg) { return $wg.Source }
  if (-not $script:WingetChecked) {
    $script:WingetChecked = $true
    Warn "winget is not available, so dependencies cannot be installed automatically."
    Warn "winget ships with Windows 10 1809+ as 'App Installer'. To get it:"
    Warn "  * Microsoft Store -> search 'App Installer' -> Install, or"
    Warn "  * https://aka.ms/getwinget  (download and run the .msixbundle)"
    Warn "Then re-run this script. Alternatively install the dependencies named below by hand."
  }
  return $null
}

function Install-Package {
  # Install-Package <friendly name> <winget id> [-Extra @('--override','...')]
  param([string]$What, [string]$Id, [string[]]$Extra = @())
  if ($NoInstall) { Warn "-NoInstall: not installing $What" ; return $false }
  $wg = Get-Winget
  if (-not $wg) { return $false }
  Log "$What is missing. This will run:"
  Write-Host ("        winget install --id $Id -e --accept-package-agreements --accept-source-agreements " + ($Extra -join ' '))
  if (-not (Ask "Install it now?")) { Warn "skipped - $What was not installed" ; return $false }
  $args = @('install','--id',$Id,'-e','--accept-package-agreements','--accept-source-agreements','--disable-interactivity') + $Extra
  & $wg @args
  # winget uses a wide range of exit codes; 0 is installed, -1978335189 is "already installed".
  if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) {
    Warn "installing $What failed (winget exit $LASTEXITCODE)"
    return $false
  }
  Update-SessionPath
  Log "$What installed."
  return $true
}

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

# ── Finding (or installing) the base tools ───────────────────────────────────
function Find-Python {
  # Iris needs 3.11+. `python` on a bare Windows box is usually the Microsoft Store STUB: it exists,
  # prints an advert and exits non-zero, so Get-Command finding it proves nothing. Only an
  # interpreter that can actually run -c and reports a new enough version counts.
  foreach ($name in @('python','python3','py')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    if ($cmd.Source -like '*\WindowsApps\*' -and (Get-Item $cmd.Source).Length -lt 100kb) { continue }  # Store stub
    & $cmd.Source -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' *> $null
    if ($LASTEXITCODE -eq 0) { return $cmd.Source }
  }
  return $null
}

function Ensure-Python {
  $py = Find-Python
  if ($py) { return $py }
  $any = Get-Command python -ErrorAction SilentlyContinue
  if ($any) { Warn "a 'python' was found but it is either the Microsoft Store stub or older than 3.11" }
  if (Install-Package 'Python 3.12' 'Python.Python.3.12') {
    $py = Find-Python
    if (-not $py) {
      # The installer adds python to PATH, but a brand-new machine may still need the refresh below
      # to see it, and py.exe (the launcher) is registered even when python.exe is not on PATH yet.
      Update-SessionPath
      $py = Find-Python
    }
  }
  return $py
}

function Ensure-Node {
  if (Get-Command npm -ErrorAction SilentlyContinue) { return $true }
  if (Install-Package 'Node.js LTS (to build the UI)' 'OpenJS.NodeJS.LTS') {
    Update-SessionPath
    return [bool](Get-Command npm -ErrorAction SilentlyContinue)
  }
  return $false
}

function Ensure-Tesseract {
  # The image parser shells out to the tesseract BINARY. Without it, screenshots and photographed
  # screens fail at PARSE time rather than at setup time, which is the worst moment to find out.
  if (Get-Command tesseract -ErrorAction SilentlyContinue) {
    Log "OCR: $((& tesseract --version 2>&1 | Select-Object -First 1))"
    return $true
  }
  if (Install-Package 'tesseract (OCR for screenshots)' 'UB-Mannheim.TesseractOCR') {
    Update-SessionPath
    # The UB-Mannheim build installs to Program Files and does not always add itself to PATH.
    if (-not (Get-Command tesseract -ErrorAction SilentlyContinue)) {
      $guess = Join-Path $env:ProgramFiles 'Tesseract-OCR'
      if (Test-Path (Join-Path $guess 'tesseract.exe')) {
        $env:PATH += ";$guess"
        [Environment]::SetEnvironmentVariable('Path',
          ([Environment]::GetEnvironmentVariable('Path','User') + ";$guess"), 'User')
        Log "added $guess to PATH"
      }
    }
    return [bool](Get-Command tesseract -ErrorAction SilentlyContinue)
  }
  Warn "tesseract not installed - every other format still parses; only image OCR is affected."
  return $false
}

# ── Native (no Docker) install ───────────────────────────────────────────────
# Mirrors what the Docker image does, straight onto the host: base deps always, GPU deps that match THIS machine.
if ($Mode -eq 'local') {
  $py = Ensure-Python
  if (-not $py) { Die "Python 3.11+ not found and could not be installed. Install it and re-run: https://www.python.org/downloads/" }
  Log "Python: $((& $py --version) 2>&1)"

  # Iris installs into a virtualenv at .\.venv so that uninstalling is one directory rather than a
  # guess about which shared site-packages belong to Iris. start.ps1 -Mode local prefers it automatically.
  $venvPy = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
  if (-not (Test-Path $venvPy)) {
    Log "Creating the virtualenv (.venv)..."
    & $py -m venv .venv
    if ($LASTEXITCODE -ne 0) { Warn "could not create a virtualenv - installing into $py instead" }
  }
  if (Test-Path $venvPy) {
    $py = $venvPy
    Log "Using the virtualenv: .venv"
    & $py -m pip install --quiet --upgrade pip setuptools wheel
  } else {
    & $py -m pip --version *> $null
    if ($LASTEXITCODE -ne 0) {
      Log "pip is missing - bootstrapping it (python -m ensurepip)"
      & $py -m ensurepip --upgrade *> $null
      & $py -m pip --version *> $null
      if ($LASTEXITCODE -ne 0) { Die "pip is not available for $py. Reinstall Python with pip included and re-run." }
    }
  }

  Log "Installing backend requirements..."
  & $py -m pip install -r backend/requirements.txt
  if ($LASTEXITCODE -ne 0) { Die "pip install of backend/requirements.txt failed" }

  Ensure-Tesseract | Out-Null

  if (Test-Gpu) {
    $names = ((& nvidia-smi --query-gpu=name --format=csv,noheader 2>$null) -join ', ')
    Log "NVIDIA GPU detected: $names"
    $w = Resolve-GpuWheels
    if (-not $w) {
      Warn "Could not read the CUDA version from nvidia-smi - skipping GPU libraries (Iris runs on CPU)."
    } else {
      Log "Installing GPU compute libraries: $($w.cupy) + torch ($($w.tag)). Multi-GB download..."
      & $py -m pip install $w.cupy 'nvidia-ml-py>=12.560'
      if ($LASTEXITCODE -ne 0) { Warn "cupy failed to install - correlation will run on CPU (numpy)." }
      & $py -m pip install torch --index-url $w.torchIndex
      if ($LASTEXITCODE -ne 0) { Warn "torch failed to install (index $($w.torchIndex)). Set IRIS_TORCH_INDEX and re-run to override." }
      $probe = & $py -c "import cupy; cupy.zeros(1).sum(); print(cupy.cuda.runtime.runtimeGetVersion())" 2>&1
      if ($LASTEXITCODE -eq 0) { Log "cupy is working (CUDA runtime $probe)" }
      else { Warn "cupy is not usable on this host: $probe" ; Warn "Iris will fall back to torch, then to numpy." }
    }
  } else {
    Log "No NVIDIA GPU detected - CPU only (numpy). Iris is fully functional without a GPU."
  }

  if (Ensure-Node) {
    Log "Node: $((& node --version) 2>&1) / npm $((& npm --version) 2>&1)"
    Log "Building the frontend..."
    # --ignore-scripts everywhere: npm lifecycle hooks are the supply-chain foothold, and Iris needs none.
    Push-Location frontend
    & npm install --ignore-scripts
    if ($LASTEXITCODE -eq 0) { & npm run build }
    if ($LASTEXITCODE -ne 0) { Warn "the frontend build failed - the API still serves on :8000" }
    Pop-Location
  } else {
    Warn "npm not found and could not be installed - skipping the frontend build."
    Warn "The API will serve on :8000 but there will be NO UI. Install Node 18+ and re-run: https://nodejs.org/"
  }

  if (-not (Test-Path .env)) { Copy-Item .env.example .env }
  Log "Done. Start Iris with:  .\start.ps1 -Mode local        (it uses .venv automatically)"
  exit 0
}

# ── Docker CLI ───────────────────────────────────────────────────────────────
function Ensure-Docker {
  if (Get-Command docker -ErrorAction SilentlyContinue) { return $true }
  # Docker Desktop needs virtualisation and, on a fresh machine, the WSL 2 feature. winget pulls the
  # WSL dependency in itself; the reboot warning is the part people miss, so it is stated up front.
  Warn "Docker Desktop is not installed. It requires the WSL 2 feature and hardware virtualisation,"
  Warn "and Windows usually needs ONE REBOOT after installing it before the engine will start."
  if (Install-Package 'Docker Desktop' 'Docker.DockerDesktop') {
    Update-SessionPath
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
      $cli = "$env:ProgramFiles\Docker\Docker\resources\bin"
      if (Test-Path $cli) { $env:PATH += ";$cli" }
    }
    return [bool](Get-Command docker -ErrorAction SilentlyContinue)
  }
  return $false
}

function Ensure-Wsl {
  # Docker Desktop's WSL 2 backend is also what makes GPU passthrough possible, so it is worth
  # enabling here rather than leaving the user to find the checklist later.
  if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) { return $false }
  & wsl --status *> $null
  if ($LASTEXITCODE -eq 0) { return $true }
  if ($NoInstall) { return $false }
  if (-not (Test-Admin)) {
    Warn "WSL 2 does not look installed, and enabling it needs an elevated PowerShell."
    Warn "Open PowerShell as Administrator and run:  wsl --install"
    return $false
  }
  Log "WSL 2 is not installed. This will run:  wsl --install --no-distribution"
  if (-not (Ask "Install WSL 2 now?")) { return $false }
  & wsl --install --no-distribution
  Warn "WSL 2 installed - a REBOOT is required before Docker Desktop can use it."
  return $true
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Ensure-Wsl | Out-Null
  Ensure-Docker | Out-Null
}
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
  if (-not $ok) {
    Warn "If Docker Desktop was only just installed, Windows usually needs one reboot (and the first"
    Warn "launch asks you to accept its licence terms) before the engine comes up."
    Die "Docker daemon not reachable after 3 minutes. Start Docker and re-run."
  }
}
$srvOs  = (& docker version --format '{{.Server.Os}}' 2>$null)
$srvVer = (& docker version --format '{{.Server.Version}}' 2>$null)
if ($srvOs -eq 'windows') { Die "Docker is in Windows-containers mode. Tray icon -> 'Switch to Linux containers...' and re-run." }
Log "Docker engine: $srvVer"

# ── Compose v2 vs legacy ─────────────────────────────────────────────────────
& docker compose version *> $null
if ($LASTEXITCODE -eq 0) { $composeExe = 'docker'; $composePre = @('compose') }
elseif (Get-Command docker-compose -ErrorAction SilentlyContinue) { $composeExe = 'docker-compose'; $composePre = @() }
else {
  # On Windows compose is part of Docker Desktop rather than a separate package, so the fix is an
  # update, not an install.
  Die "Docker Compose not found. Update Docker Desktop (it bundles the compose plugin): https://docs.docker.com/compose/install/"
}
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
    # On Windows the missing piece is a DRIVER or a Windows setting, never a Linux package - there is
    # nothing this script can install to fix it, so it says exactly what to check instead of guessing.
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
      $ans = if ($Yes) { 'y' } else { Read-Host "    Write these settings to .wslconfig now? [y/N]" }
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
