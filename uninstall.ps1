<#
Iris uninstall script (Windows / PowerShell).

  .\uninstall.ps1              # remove the Docker install (container, images, offer the build cache)
  .\uninstall.ps1 local        # remove the local (no-Docker) install: node_modules, dist, caches
  .\uninstall.ps1 all          # both of the above
  .\uninstall.ps1 -PurgeData   # ALSO delete backend\data - every case, upload and setting. Irreversible.
  .\uninstall.ps1 -Pip         # local/all: also `pip uninstall` the Python dependencies
  .\uninstall.ps1 -Yes         # don't ask (does NOT cover -PurgeData, which asks separately)
  .\uninstall.ps1 -DryRun      # print what would be removed and stop

YOUR EVIDENCE IS KEPT BY DEFAULT. backend\data holds the cases, the uploaded logs, the rules and the
settings, and it is the one thing here that cannot be rebuilt from this repo. It is removed ONLY with
-PurgeData, and that asks you to type DELETE first.

This script never deletes the source tree it lives in - remove that folder yourself when done.

NOTE for editors: this file is UTF-8 WITH a BOM on purpose. PowerShell 5.1 decodes a BOM-less file as
cp1252, and a non-ASCII character inside a double-quoted string can silently terminate it.
#>
[CmdletBinding()]
param(
  [ValidateSet('docker','local','all')]
  [string]$Mode = 'docker',
  [switch]$PurgeData,
  [switch]$Pip,
  [switch]$Yes,
  [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

$script:Step = 0
function Write-Step { param([string]$Text) ; $script:Step++ ; Write-Host ("[{0}] " -f $script:Step) -ForegroundColor DarkGray -NoNewline ; Write-Host $Text -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) ; Write-Host "    OK  " -ForegroundColor Green -NoNewline ; Write-Host $Text }
function Write-Info { param([string]$Text) ; Write-Host ("    " + $Text) -ForegroundColor DarkGray }
function Write-Warn { param([string]$Text) ; Write-Host ("    !   " + $Text) -ForegroundColor Yellow }
function Write-Bad  { param([string]$Text) ; Write-Host ("    X   " + $Text) -ForegroundColor Red }

function Get-SizeText {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return '' }
  try {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) {
      $bytes = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
    } else {
      $bytes = $item.Length
    }
  } catch { return '' }
  if ($null -eq $bytes) { $bytes = 0 }
  if     ($bytes -ge 1GB) { return ('{0:N1} GB' -f ($bytes / 1GB)) }
  elseif ($bytes -ge 1MB) { return ('{0:N0} MB' -f ($bytes / 1MB)) }
  elseif ($bytes -ge 1KB) { return ('{0:N0} KB' -f ($bytes / 1KB)) }
  else                    { return ("$bytes B") }
}

function Remove-Target {
  param([string]$Path, [string]$Label)
  if (-not $Label) { $Label = $Path }
  if (-not (Test-Path -LiteralPath $Path)) { Write-Info "$Label - not present" ; return }
  $size = Get-SizeText $Path
  if ($DryRun) { Write-Info "would remove $Label ($size)" ; return }
  try {
    Remove-Item -LiteralPath $Path -Recurse -Force -Confirm:$false -ErrorAction Stop
    Write-Ok "removed $Label ($size)"
  } catch {
    Write-Bad "could not remove $Label - $($_.Exception.Message)"
  }
}

function Confirm-Action {
  param([string]$Question)
  if ($Yes)    { return $true }
  if ($DryRun) { return $false }
  Write-Host ("    " + $Question + " [y/N] ") -ForegroundColor Yellow -NoNewline
  $reply = $Host.UI.ReadLine()
  return ($reply -match '^(y|yes)$')
}

$DataDir = $env:IRIS_DATA_HOST_DIR
if (-not $DataDir) { $DataDir = '.\backend\data' }

Write-Host ''
$dryNote = ''
if ($DryRun) { $dryNote = '  (dry run - nothing will be removed)' }
Write-Host '  Iris uninstall' -ForegroundColor Cyan -NoNewline
Write-Host ("  mode: " + $Mode + $dryNote)
$dataSize = Get-SizeText $DataDir
if ($PurgeData) {
  Write-Host '  data: WILL BE DELETED' -ForegroundColor Red -NoNewline
  Write-Host ("  $DataDir ($dataSize)")
} else {
  Write-Host '  data: kept' -ForegroundColor Green -NoNewline
  Write-Host ("  $DataDir ($dataSize)  - pass -PurgeData to remove it")
}
Write-Host ''

# --- docker ------------------------------------------------------------------
if ($Mode -eq 'docker' -or $Mode -eq 'all') {
  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) {
    Write-Step 'Docker'
    Write-Info 'docker not found - nothing to remove'
  } else {
    docker info *> $null
    if (-not $?) {
      Write-Step 'Docker'
      Write-Warn 'the Docker daemon is not reachable - start Docker Desktop and re-run to remove the container and images'
    } else {
      $files = @('-f','docker-compose.yml')
      docker image inspect iris:cuda *> $null
      if ($?) { $files += @('-f','docker-compose.gpu.yml') }

      Write-Step 'Stopping and removing the container'
      if ($DryRun) {
        Write-Info 'would run: docker compose down --remove-orphans'
      } else {
        # No -v. The data dir is a HOST bind mount so `down` cannot touch it either way, but
        # IRIS_DATA_HOST_DIR may legitimately name a volume - deleting the evidence is what
        # -PurgeData is for, with its own confirmation.
        & docker compose @files down --remove-orphans *> $null
        if ($?) {
          Write-Ok 'compose stack down'
        } else {
          docker rm -f iris *> $null
          if ($?) { Write-Ok "removed the container 'iris'" } else { Write-Info 'no Iris container running' }
        }
      }

      Write-Step 'Removing the images'
      foreach ($tag in @('iris:cpu','iris:cuda')) {
        docker image inspect $tag *> $null
        if (-not $?) { Write-Info "$tag - not present" ; continue }
        $bytes = docker image inspect -f '{{.Size}}' $tag 2>$null
        $mb = 0
        if ($bytes) { $mb = [int]([int64]$bytes / 1MB) }
        if ($DryRun) {
          Write-Info "would remove image $tag ($mb MB)"
        } else {
          docker rmi -f $tag *> $null
          if ($?) { Write-Ok "removed $tag ($mb MB)" } else { Write-Bad "could not remove $tag (is a container still using it?)" }
        }
      }

      Write-Step 'Build cache'
      # BuildKit does not tag its layers by project, so Iris's own cache cannot be told apart from
      # anything else on this machine. Offered, never assumed.
      if ($DryRun) {
        Write-Info 'would offer: docker builder prune -f  (shared with every other project here)'
      } elseif (Confirm-Action 'Prune the shared Docker build cache? This affects OTHER projects on this machine.') {
        docker builder prune -f *> $null
        if ($?) { Write-Ok 'build cache pruned' } else { Write-Bad 'prune failed' }
      } else {
        Write-Info "left alone - run 'docker builder prune' yourself if you want the space back"
      }

      # Docker Desktop's VHDX only ever grows: pruning inside Docker does not hand the space back to
      # Windows. Say so rather than letting the analyst wonder where 60 GB went.
      Write-Info 'note: freed Docker space stays inside docker_data.vhdx. See HOWTO -> Disk to reclaim it.'
    }
  }
  Write-Host ''
}

# --- local (no Docker) -------------------------------------------------------
if ($Mode -eq 'local' -or $Mode -eq 'all') {
  Write-Step 'Frontend dependencies and build output'
  Remove-Target 'frontend\node_modules' 'frontend\node_modules'
  Remove-Target 'frontend\dist'         'frontend\dist'
  Remove-Target 'frontend\.vite'        'frontend\.vite'

  Write-Step 'Python and test caches'
  if ($DryRun) {
    Write-Info 'would remove every __pycache__ directory in the tree'
  } else {
    $pycache = Get-ChildItem -Path . -Recurse -Force -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue
    foreach ($d in $pycache) {
      try { Remove-Item -LiteralPath $d.FullName -Recurse -Force -Confirm:$false -ErrorAction Stop } catch { }
    }
    Write-Ok '__pycache__ directories removed'
  }
  Remove-Target '.pytest_cache'         '.pytest_cache'
  Remove-Target 'backend\.pytest_cache' 'backend\.pytest_cache'
  Remove-Target '.mypy_cache'           '.mypy_cache'
  Remove-Target '.ruff_cache'           '.ruff_cache'

  Write-Step 'Virtualenv'
  Remove-Target '.venv'         '.venv'
  Remove-Target 'backend\.venv' 'backend\.venv'

  Write-Step 'Python dependencies'
  if (-not $Pip) {
    Write-Info 'left installed - pass -Pip to uninstall them too'
  } else {
    $py = $null
    foreach ($cand in @('python','py','python3')) {
      $cmd = Get-Command $cand -ErrorAction SilentlyContinue
      if ($cmd) {
        # `python3` on Windows is often the Microsoft Store stub: it prints an advert and exits
        # non-zero, so Get-Command finding it proves nothing. Whichever candidate can actually run
        # -c wins.
        & $cmd.Source -c 'import sys' *> $null
        if ($?) { $py = $cmd.Source ; break }
      }
    }
    if (-not $py) {
      Write-Warn 'python not found - skipping'
    } else {
      # setup.ps1 local installs into whatever interpreter ran it, NOT a venv, so these packages are
      # very likely shared with other things on this machine.
      Write-Warn 'setup.ps1 local does not use a venv, so these packages may be shared with OTHER projects'
      Write-Info "interpreter: $py"
      if ($DryRun) {
        Write-Info 'would run: pip uninstall -y -r backend\requirements.txt (and requirements-gpu.txt)'
      } elseif (Confirm-Action "Uninstall everything listed in backend\requirements*.txt from $py") {
        & $py -m pip uninstall -y -r backend\requirements.txt *> $null
        if ($?) { Write-Ok 'base requirements uninstalled' } else { Write-Warn 'some base packages could not be uninstalled' }
        if (Test-Path -LiteralPath 'backend\requirements-gpu.txt') {
          & $py -m pip uninstall -y -r backend\requirements-gpu.txt *> $null
          if ($?) { Write-Ok 'GPU requirements uninstalled' } else { Write-Info 'no GPU packages to remove' }
        }
      } else {
        Write-Info 'left installed'
      }
    }
  }
  Write-Host ''
}

# --- data (opt-in, and it asks) ----------------------------------------------
Write-Step "Evidence and settings ($DataDir)"
if (-not $PurgeData) {
  Write-Info 'KEPT - your cases, uploads, rules and settings. Pass -PurgeData to delete them.'
} elseif (-not (Test-Path -LiteralPath $DataDir)) {
  Write-Info 'not present'
} elseif ($DryRun) {
  Write-Info "would DELETE $DataDir ($(Get-SizeText $DataDir)) - every case, upload, rule and setting"
} else {
  $size = Get-SizeText $DataDir
  $nCases = 0
  $nLib = 0
  if (Test-Path -LiteralPath (Join-Path $DataDir 'cases')) {
    $nCases = @(Get-ChildItem -LiteralPath (Join-Path $DataDir 'cases') -Force -Directory -ErrorAction SilentlyContinue).Count
  }
  if (Test-Path -LiteralPath (Join-Path $DataDir 'library')) {
    $nLib = @(Get-ChildItem -LiteralPath (Join-Path $DataDir 'library') -Force -File -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -ne 'index.json' }).Count
  }
  Write-Host ("    About to permanently delete $DataDir ($size)") -ForegroundColor Red
  Write-Host ("      $nCases case(s), $nLib staged file(s), plus rules.json, settings.json, auth.json and the trash.")
  Write-Host  '      There is no undo, and nothing in this repo can rebuild any of it.'
  Write-Host  '    Type DELETE to confirm: ' -ForegroundColor Red -NoNewline
  $typed = $Host.UI.ReadLine()
  if ($typed -ceq 'DELETE') {
    try {
      Remove-Item -LiteralPath $DataDir -Recurse -Force -Confirm:$false -ErrorAction Stop
      Write-Ok 'data directory removed'
    } catch {
      Write-Bad "could not remove $DataDir - $($_.Exception.Message)"
    }
  } else {
    Write-Info 'not confirmed - data KEPT'
  }
}

Write-Host ''
Write-Host '  Done.' -ForegroundColor Green -NoNewline
Write-Host ("  The source tree at " + $PSScriptRoot + " was not touched - delete it yourself when you are finished.")
if (-not $PurgeData) {
  Write-Host ("  Your evidence is still in " + $DataDir) -ForegroundColor DarkGray
}
Write-Host ''
