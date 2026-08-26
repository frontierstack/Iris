<#
 Iris start script (Windows, PowerShell 5.1+ / pwsh).

   .\start.ps1                 # Docker: bring the whole app up (GPU image if one was built / GPU present)
   .\start.ps1 -Mode local     # no Docker: build the frontend if needed, run uvicorn on this machine
   .\start.ps1 -Build          # force a rebuild of the image before starting
   .\start.ps1 -Mode restart   # stop, then start
   .\start.ps1 -Mode stop      # stop the container
   .\start.ps1 -Mode logs      # follow the container logs
   .\start.ps1 -Mode status    # is it up, what is it doing, and how big is the pool
   .\start.ps1 -NoBrowser      # don't open http://127.0.0.1:8000
   .\start.ps1 -SkipWslCheck   # don't look at .wslconfig (see wsl.ps1)

 One container serves EVERYTHING: the FastAPI API under /api and the built React SPA at /. There is no
 second service to start. First-time setup (GPU wheel resolution, Docker install checks) lives in
 setup.ps1 — this script starts what is already set up, and builds the image itself if it never has been.

 NOTE for anyone editing this file: it is saved as UTF-8 WITH a BOM on purpose. PowerShell 5.1 decodes a
 BOM-less file as cp1252, and a UTF-8 em dash inside a double-quoted string ends in byte 0x94 — a curly
 quote, which silently terminates the string and produces parse errors pages away from the real line.
#>
param(
  [ValidateSet('docker','local','stop','restart','logs','status')][string]$Mode = 'docker',
  [switch]$Build,
  [switch]$NoBrowser,
  [switch]$SkipWslCheck,
  [int]$Port = 8000
)
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
# NOT `localhost`. It resolves to ::1 first, nothing is published there (compose binds the port on
# IRIS_BIND_HOST, 127.0.0.1 by default), and the connection is not REFUSED — it hangs until it times
# out, so every caller waits for the IPv6 attempt to lose. Measured on this machine, the same request:
# http://localhost:8000/api/health = 2,084 ms, http://127.0.0.1:8000/api/health = 5 ms. Every health
# poll below paid it (which is why "waiting for the API" always reported ~2.1 s however fast the
# container came up), and so did the browser we open. Always address the app by its literal.
$BindHost = if ($env:IRIS_BIND_HOST) { $env:IRIS_BIND_HOST } else { '127.0.0.1' }
if ($BindHost -in @('0.0.0.0', '::', '*')) { $BindHost = '127.0.0.1' }
if ($BindHost.Contains(':') -and -not $BindHost.StartsWith('[')) { $BindHost = "[$BindHost]" }
$Url = "http://${BindHost}:$Port"
$script:StepNo = 0
$script:Started = Get-Date
# Animate only for a human: redirected output gets periodic lines instead (see Spin).
$script:Tty = -not [Console]::IsOutputRedirected
$script:LastTick = -10

# ── output helpers ───────────────────────────────────────────────────────────
# Every long operation gets: a numbered step line, a live spinner while it runs, and a result line with
# how long it took. A script that prints nothing for two minutes is indistinguishable from a hung one.
$Frames = @('|','/','-','\')
function Step([string]$m) {
  $script:StepNo++
  Write-Host ("[{0}] " -f $script:StepNo) -NoNewline -ForegroundColor DarkGray
  Write-Host $m -ForegroundColor Cyan
}
function Ok([string]$m, [double]$secs = -1) {
  $t = ''
  if ($secs -ge 0) { $t = " ({0:n1}s)" -f $secs }
  Write-Host "    OK  " -NoNewline -ForegroundColor Green
  Write-Host "$m$t"
}
function Info([string]$m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn([string]$m) { Write-Host "    !   $m" -ForegroundColor Yellow }
function Die([string]$m)  { Write-Host "    X   $m" -ForegroundColor Red; exit 1 }

function Spin {
  <# Runs a scriptblock that returns $true when done, spinning until it does.
     -Detail is a scriptblock returning a status string (pool progress, build phase) shown beside the
     spinner, so the wait says WHAT it is waiting for rather than just that it is waiting. #>
  param(
    [Parameter(Mandatory)][scriptblock]$Until,
    [string]$Label = 'working',
    [scriptblock]$Detail,
    [int]$TimeoutSec = 600,
    [double]$PollSec = 0.75
  )
  $t0 = Get-Date
  $i = 0
  $done = $false
  $script:LastTick = -10
  while (((Get-Date) - $t0).TotalSeconds -lt $TimeoutSec) {
    if (& $Until) { $done = $true; break }
    $el = ((Get-Date) - $t0).TotalSeconds
    $extra = ''
    if ($Detail) { $extra = & $Detail }
    $line = "    {0} {1}  {2:n0}s  {3}" -f $Frames[$i % 4], $Label, $el, $extra
    if ($line.Length -gt 118) { $line = $line.Substring(0, 118) }
    if ($script:Tty) {
      Write-Host ("`r" + $line.PadRight(120)) -NoNewline -ForegroundColor DarkGray
    } elseif ($el - $script:LastTick -ge 10) {
      # Redirected (a log file, CI): `r does not collapse, so an animated spinner writes one enormous
      # line. Print a plain progress line every 10s instead — the same information, readable afterwards.
      $script:LastTick = [int]$el
      Write-Host ("    ... {0}  {1:n0}s  {2}" -f $Label, $el, $extra) -ForegroundColor DarkGray
    }
    Start-Sleep -Milliseconds ($PollSec * 1000)
    $i++
  }
  if ($script:Tty) { Write-Host ("`r" + (' ' * 120) + "`r") -NoNewline }
  return @{ Done = $done; Seconds = ((Get-Date) - $t0).TotalSeconds }
}

# ── the app ──────────────────────────────────────────────────────────────────
function Get-Health {
  try { return Invoke-RestMethod -Uri "$Url/api/health" -TimeoutSec 3 -ErrorAction Stop } catch { return $null }
}
function Get-CaseState {
  try { return Invoke-RestMethod -Uri "$Url/api/case" -TimeoutSec 5 -ErrorAction Stop } catch { return $null }
}
function Pool-Detail {
  $c = Get-CaseState
  if (-not $c) { return '' }
  if ($c.poolLoading) {
    $done = [int]$c.poolLoaded; $total = $done + [int]$c.poolPending
    $pct = 0; if ($c.poolProgress) { $pct = [int]$c.poolProgress.pct }
    # bytes and files are the live signal; the event count only moves when a batch merges into the pool
    # (see Store.BULK_FLUSH_EVENTS), so showing it per tick looks frozen and worries people
    return ("parsing library {0}/{1} files, {2}% of bytes" -f $done, $total, $pct)
  }
  return ("{0:n0} events in the pool" -f $c.poolEventCount)
}

function Open-App { if (-not $NoBrowser) { Start-Process $Url | Out-Null } }

# ── docker plumbing ──────────────────────────────────────────────────────────
function Get-Compose {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Die "docker not found. Run .\setup.ps1 first, or start without Docker:  .\start.ps1 -Mode local"
  }
  & docker compose version *> $null
  if ($LASTEXITCODE -eq 0) { return @{ exe = 'docker'; pre = @('compose') } }
  if (Get-Command docker-compose -ErrorAction SilentlyContinue) { return @{ exe = 'docker-compose'; pre = @() } }
  Die "Docker Compose not found (update Docker Desktop)."
}
function Compose([string[]]$a) { $c = Get-Compose; & $c.exe @($c.pre + $a) }
function Test-Daemon { & docker info *> $null; return ($LASTEXITCODE -eq 0) }

function Start-DockerDesktop {
  $dd = @("$env:ProgramFiles\Docker\Docker\Docker Desktop.exe", "$env:LOCALAPPDATA\Docker\Docker Desktop.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($dd) { Info "starting Docker Desktop"; Start-Process $dd | Out-Null }
  else     { Warn "Docker Desktop.exe not found - waiting for an engine to appear" }
  $r = Spin -Until { Test-Daemon } -Label 'waiting for the Docker daemon' -TimeoutSec 180 -PollSec 2
  return $r.Done
}

function Get-ComposeFiles {
  $files = @('-f', 'docker-compose.yml')
  & docker image inspect iris:cuda *> $null
  if ($LASTEXITCODE -eq 0) { $files += @('-f', 'docker-compose.gpu.yml') }
  return $files
}

function Show-Summary {
  $h = Get-Health
  $c = Get-CaseState
  Write-Host ""
  Write-Host "  Iris is up" -ForegroundColor Green -NoNewline
  if ($h) { Write-Host "  v$($h.version)" -ForegroundColor DarkGray } else { Write-Host "" }
  Write-Host "  $Url" -ForegroundColor White
  try {
    $comp = Invoke-RestMethod -Uri "$Url/api/compute" -TimeoutSec 5 -ErrorAction Stop
    $gpu = 'CPU (numpy)'
    if ($comp.active -eq 'cuda' -and $comp.gpus.Count -gt 0) { $gpu = "$($comp.gpus[0].name) - $($comp.backend)" }
    Write-Host "  compute   $gpu" -ForegroundColor DarkGray
    # Iris sizes its worker pools from what the CONTAINER/process can see (app/resources.py); on
    # Docker Desktop that is the WSL VM's share, not the host - Check-Wsl says when they differ.
    $r = $comp.resources
    if ($r) {
      $m = $r.machine; $p = $r.profile
      Write-Host ("  workers   parse {0} - graph {1} - enrichment {2}  (sees {3} cores, {4:n1} GB RAM)" -f `
        $p.parseWorkers, $p.graphWorkers, $p.enrichWorkers, $m.cpuUsable, ($m.memTotalMB / 1024)) -ForegroundColor DarkGray
      if ($p.pinned.PSObject.Properties.Count -gt 0) {
        Write-Host ("  pinned    " + (($p.pinned.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ')) -ForegroundColor DarkGray
      }
    }
  } catch { }
  if ($c) {
    $srcs = $c.sources.Count + $c.librarySources.Count
    Write-Host ("  pool      {0:n0} events across {1} source(s)" -f $c.poolEventCount, $srcs) -ForegroundColor DarkGray
    if ($c.poolLoading) {
      Write-Host ("  loading   still parsing the library ({0} file(s) to go) - the UI fills in as it lands" -f $c.poolPending) -ForegroundColor Yellow
    }
    if ($c.poolSkipped -gt 0) {
      Write-Host ("  skipped   {0} file(s) NOT in the pool - Sources says which and why" -f $c.poolSkipped) -ForegroundColor Yellow
    }
  }
  Write-Host "  logs      .\start.ps1 -Mode logs        stop  .\start.ps1 -Mode stop" -ForegroundColor DarkGray
  Write-Host ("  total     {0:n0}s" -f ((Get-Date) - $script:Started).TotalSeconds) -ForegroundColor DarkGray
  Write-Host ""
}

# ── WSL tuning check (Docker on Windows only) ────────────────────────────────
function Check-Wsl {
  if ($SkipWslCheck) { return }
  $helper = Join-Path $PSScriptRoot 'wsl.ps1'
  if (-not (Test-Path $helper)) { return }
  try {
    . $helper -Quiet
    Show-WslStatus -OnlyIfDrift
  } catch { }
}

# ── local (no Docker) ────────────────────────────────────────────────────────
if ($Mode -eq 'local') {
  Step "Checking Python"
  # setup.ps1 -Mode local installs into .\.venv, so prefer it: the backend dependencies are installed
  # THERE, and starting the system interpreter instead fails with ModuleNotFoundError on fastapi.
  $pyExe = $null
  $venvPy = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
  if (Test-Path $venvPy) {
    $pyExe = $venvPy
    Info "using the virtualenv (.venv)"
  } else {
    $cmd = (Get-Command python -ErrorAction SilentlyContinue), (Get-Command python3 -ErrorAction SilentlyContinue) |
           Where-Object { $_ } | Select-Object -First 1
    if ($cmd) { $pyExe = $cmd.Source }
  }
  if (-not $pyExe) { Die "python not found on PATH. Install Python 3.11+ or run .\setup.ps1 -Mode local" }
  Ok ((& $pyExe --version) 2>&1)

  if (-not (Test-Path 'frontend/dist/index.html')) {
    Step "Building the UI (frontend/dist is missing)"
    if (Get-Command npm -ErrorAction SilentlyContinue) {
      Push-Location frontend
      if (-not (Test-Path 'node_modules')) { & npm ci --ignore-scripts }
      & npm run build
      Pop-Location
      Ok "frontend built"
    } else {
      Warn "npm not found - only the API at $Url/api will respond"
    }
  }
  if (-not (Test-Path .env) -and (Test-Path .env.example)) { Copy-Item .env.example .env }

  Step "Starting Iris (uvicorn) on port $Port"
  Info "Ctrl-C stops it"
  if (-not $NoBrowser) {
    Start-Job -ScriptBlock {
      param($u)
      for ($i = 0; $i -lt 180; $i++) {
        try { if ((Invoke-RestMethod -Uri "$u/api/health" -TimeoutSec 2).ok) { Start-Process $u; break } } catch {}
        Start-Sleep -Seconds 1
      }
    } -ArgumentList $Url | Out-Null
  }
  Push-Location backend
  # Loopback by DEFAULT: Iris has no authentication, so 0.0.0.0 offered the whole evidence pool and
  # every destructive endpoint to the network. Set IRIS_BIND_HOST=0.0.0.0 to expose it deliberately,
  # and set IRIS_AUTH_TOKEN at the same time (HOWTO -> Security). This does NOT stop a malicious web
  # page: a browser on this machine reaches localhost whatever the bind address is. That attack is
  # closed by backend/app/security.py.
  $bindHost = if ($env:IRIS_BIND_HOST) { $env:IRIS_BIND_HOST } else { '127.0.0.1' }
  & $pyExe -m uvicorn app.main:app --host $bindHost --port $Port
  Pop-Location
  exit $LASTEXITCODE
}

# ── docker modes ─────────────────────────────────────────────────────────────
Step "Checking the Docker daemon"
if (-not (Test-Daemon)) {
  if (-not (Start-DockerDesktop)) { Die "Docker daemon not reachable after 3 minutes. Start Docker and re-run." }
}
$srvVer = (& docker version --format '{{.Server.Version}}' 2>$null)
Ok "engine $srvVer"

$files = Get-ComposeFiles
$gpuImage = $files -contains 'docker-compose.gpu.yml'

switch ($Mode) {
  'logs'   { Compose ($files + @('logs', '-f')); exit $LASTEXITCODE }
  'stop'   {
    Step "Stopping Iris"
    Compose ($files + @('stop')) | Out-Null
    Ok "stopped"
    exit 0
  }
  'status' {
    Step "Container"
    Compose ($files + @('ps'))
    $h = Get-Health
    if ($h) { Show-Summary } else { Warn "not answering at $Url/api/health" }
    Check-Wsl
    exit 0
  }
  'restart' {
    Step "Stopping Iris"
    Compose ($files + @('stop')) | Out-Null
    Ok "stopped"
  }
}

Check-Wsl

if (-not (Test-Path .env) -and (Test-Path .env.example)) { Copy-Item .env.example .env }

# Build only when asked, or when no image exists yet (a first run straight from a clone).
$needBuild = [bool]$Build
if (-not $needBuild) {
  & docker image inspect iris:cpu *> $null; $cpu = ($LASTEXITCODE -eq 0)
  & docker image inspect iris:cuda *> $null; $cuda = ($LASTEXITCODE -eq 0)
  if (-not ($cpu -or $cuda)) { $needBuild = $true; Info "no Iris image yet - building it (first run, several minutes)" }
}

if ($needBuild) {
  Step "Building the image"
  # What this build is about to replace, so the old image can be removed by ID once the new one is
  # actually running. Every rebuild leaves a 5.5 GB untagged layer set behind.
  $imageTag = if ($gpuImage) { 'iris:cuda' } else { 'iris:cpu' }
  $prevImage = (docker image inspect -f '{{.Id}}' $imageTag 2>$null)
  if ($gpuImage) { Info "CUDA image (iris:cuda)" } else { Info "CPU image (iris:cpu)" }
  Info "the frontend build and the Python wheels are the slow parts; output follows"
  $t0 = Get-Date
  # WEB_REBUILD makes the SPA layer rebuild every time (see the Dockerfile). BuildKit has reported
  # `COPY frontend/ ./  CACHED` for a context that HAD changed, and the image then shipped an old
  # frontend while the build reported success — a UI fix missing from the bundle is indistinguishable
  # from a UI fix that does not work.
  $env:WEB_REBUILD = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
  Compose ($files + @('build'))
  if ($LASTEXITCODE -ne 0) { Die "image build failed (see the output above)" }
  Ok "image built" ((Get-Date) - $t0).TotalSeconds
}

Step "Starting the container"
if ($gpuImage) { Info "using iris:cuda" }
# --force-recreate: `up -d` leaves a RUNNING container on its OLD image, so a freshly built image can
# be tagged and never actually served.
Compose ($files + @('up', '-d', '--force-recreate'))
if ($LASTEXITCODE -ne 0) { Die "compose up failed. See:  .\start.ps1 -Mode logs" }
Ok "container running"

# Only the image THIS run superseded, and only once the new one is serving. Never a blanket
# `docker image prune`: other projects live on this machine and their untagged layers are not ours.
if ($needBuild -and $prevImage) {
  $nowImage = (docker image inspect -f '{{.Id}}' $imageTag 2>$null)
  if ($nowImage -and $nowImage -ne $prevImage) {
    docker rmi $prevImage 2>&1 | Out-Null
    Info "removed the image this build replaced (~5.5 GB)"
  }
  # The build cache grows without bound (38 GB in one session). Keep enough for a fast next build.
  docker builder prune -f --keep-storage 10GB 2>&1 | Out-Null
  Info "trimmed the build cache to 10 GB"
}

Step "Waiting for the API"
$r = Spin -Until { $null -ne (Get-Health) } -Label 'starting' -TimeoutSec 300 `
          -Detail { 'the app restores its case and starts the library load' }
if (-not $r.Done) {
  Warn "the container started but $Url/api/health did not answer in 5 minutes"
  Warn "check the logs:  .\start.ps1 -Mode logs"
  exit 1
}
Ok "API answering" $r.Seconds

# The library load is BACKGROUND work: the app is usable now. Report it rather than blocking on it, but
# give it a few seconds of spinner so a small library finishes before the summary prints.
$c = Get-CaseState
if ($c -and $c.poolLoading) {
  Step "Library load (background - the app is already usable)"
  $r2 = Spin -Until { $s = Get-CaseState; -not $s -or -not $s.poolLoading } -Label 'parsing' `
             -TimeoutSec 20 -Detail { Pool-Detail }
  if ($r2.Done) { Ok "library loaded" $r2.Seconds } else { Info (Pool-Detail); Info "still going - the UI shows progress" }
}

Show-Summary
Open-App
