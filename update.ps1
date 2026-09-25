<#
 Iris updater (Windows, PowerShell 5.1+ / pwsh).

   .\update.ps1                  # check GitHub, show exactly what would change, ask, then update + refresh
   .\update.ps1 -Action check    # the diff check only - nothing is changed (exit 0 = up to date, 10 = update available)
   .\update.ps1 -Yes             # update without asking
   .\update.ps1 -Diff            # also print the full patch (-DiffPath backend\app scopes it to a path)
   .\update.ps1 -Action rollback # go back to the version before the last update (and refresh the install)
   .\update.ps1 -Mode M          # how to refresh the install afterwards: auto (default) | docker | local | none
   .\update.ps1 -Stash           # set local edits aside, update, then put them back
   .\update.ps1 -NoRestart       # update the code only; do not rebuild or restart anything
   .\update.ps1 -Branch B -Remote R -Port N
   .\update.ps1 -Adopt           # connect a copy that was downloaded as a zip (not a git checkout) to GitHub

 What it will not do: touch the evidence (backend\data is not in the repository, and the update refuses
 if an incoming change would reach it), discard your edits (a conflicting edit stops the update unless
 -Stash), or rewrite history (fast-forward only; a copy with commits of its own is refused, with the fix).
 Exit codes: 0 done / up to date, 10 update available (check), 1 error, 3 refused/declined.

 Saved as UTF-8 WITH a BOM and kept to ASCII on purpose - see the note at the top of start.ps1.
 PowerShell parses the whole script before running it, so an update that rewrites this file mid-run is
 harmless here (update.sh has to run from a private copy for the same reason).
#>
param(
  [ValidateSet('update','check','rollback')][string]$Action = 'update',
  [switch]$Yes,
  [switch]$Diff,
  [string]$DiffPath = '',
  [ValidateSet('auto','docker','local','none')][string]$Mode = 'auto',
  [switch]$Stash,
  [switch]$NoRestart,
  [string]$Branch = '',
  [string]$Remote = 'origin',
  [int]$Port = 8000,
  [switch]$Adopt
)
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
$DefaultUrl = 'https://github.com/frontierstack/Iris.git'
# "LF will be replaced by CRLF" on every git call of a Windows checkout is noise, not a finding.
# Set for THIS process only (git >= 2.31 reads config from the environment); nothing is written.
$env:GIT_CONFIG_COUNT = '1'; $env:GIT_CONFIG_KEY_0 = 'core.safecrlf'; $env:GIT_CONFIG_VALUE_0 = 'false'
$BindHost = if ($env:IRIS_BIND_HOST) { $env:IRIS_BIND_HOST } else { '127.0.0.1' }
if ($BindHost -in @('0.0.0.0', '::', '*')) { $BindHost = '127.0.0.1' }
$Url = "http://${BindHost}:$Port"
$script:StepNo = 0
$script:Tty = -not [Console]::IsOutputRedirected

function Step([string]$m) {
  $script:StepNo++
  Write-Host ("[{0}] " -f $script:StepNo) -NoNewline -ForegroundColor DarkGray
  Write-Host $m -ForegroundColor Cyan
}
function Ok([string]$m)   { Write-Host "    OK  " -NoNewline -ForegroundColor Green; Write-Host $m }
function Info([string]$m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Line([string]$m) { Write-Host "    $m" }
function Warn([string]$m) { Write-Host "    !   $m" -ForegroundColor Yellow }
function Die([string]$m, [int]$code = 1) { Write-Host "    X   $m" -ForegroundColor Red; exit $code }
function Head([string]$m) { Write-Host ""; Write-Host "    $m" -ForegroundColor White }

# git, returning its output as lines; the exit code is captured HERE, into $script:GitExit, never read
# later from the automatic variable (which carries over from whatever native command ran last).
# Named G, NOT Git: PowerShell names are case-insensitive and a function outranks an executable, so a
# function called Git would resolve `& git` inside itself to ITSELF and recurse until the stack ran out.
function G([string[]]$a) {
  $out = & git @a 2>&1
  $script:GitExit = $LASTEXITCODE
  # The leading comma is load-bearing: PowerShell UNROLLS a returned array, so a one-line answer came back
  # as a bare string and (G ...)[0] was its first CHARACTER - every single-line git answer was wrong.
  return ,@($out | ForEach-Object { "$_" })
}

# Run a native command in the background with a spinner, output to a log. Returns $true on success.
function Run-Spin([string]$Label, [string]$Exe, [string[]]$ArgList, [string]$Log) {
  $p = Start-Process -FilePath $Exe -ArgumentList $ArgList -NoNewWindow -PassThru `
        -RedirectStandardOutput "$Log.out" -RedirectStandardError $Log
  $null = $p.Handle     # cache the handle now, or ExitCode reads back empty once the process is gone
  $frames = @('|','/','-','\'); $i = 0; $t0 = Get-Date; $last = -10
  while (-not $p.HasExited) {
    $el = [int]((Get-Date) - $t0).TotalSeconds
    if ($script:Tty) { Write-Host ("`r    {0} {1}  {2}s" -f $frames[$i % 4], $Label, $el) -NoNewline -ForegroundColor DarkGray }
    elseif ($el - $last -ge 10) { $last = $el; Write-Host ("    ... {0}  {1}s" -f $Label, $el) -ForegroundColor DarkGray }
    Start-Sleep -Milliseconds 400; $i++
  }
  $p.WaitForExit()
  if ($script:Tty) { Write-Host ("`r" + (' ' * 100) + "`r") -NoNewline }
  return ($p.ExitCode -eq 0)
}

function Confirm-Step([string]$q) {
  if ($Yes) { return $true }
  if ([Console]::IsInputRedirected) { Warn "not interactive and -Yes not given: declining"; return $false }
  $a = Read-Host "    ? $q [y/N]"
  return ($a -match '^(y|yes)$')
}

function Test-Healthy {
  try { $h = Invoke-RestMethod -Uri "$Url/api/health" -TimeoutSec 3 -ErrorAction Stop; return [bool]$h.ok } catch { return $false }
}

# -- 1. the checkout ----------------------------------------------------------
Step "Checking this copy of Iris"
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Die "git is not installed. Install it (winget install Git.Git) and re-run."
}
$isRepo = $false
$top = G @('rev-parse', '--show-toplevel')
if ($script:GitExit -eq 0 -and $top.Count -gt 0) {
  $here = (Get-Location).Path.TrimEnd('\').ToLower()
  $isRepo = (($top[0] -replace '/', '\').TrimEnd('\').ToLower() -eq $here)
}
if (-not $isRepo) {
  if (-not $Adopt) {
    Die "this copy is not a git checkout (downloaded as a zip?). Re-run with -Adopt to connect it to GitHub: the files are compared with the latest version first, and nothing is replaced without asking." 3
  }
  Info "adopting this copy: git init + $DefaultUrl"
  G @('init', '-q', '.') | Out-Null
  if ($script:GitExit -ne 0) { Die "git init failed" }
  G @('remote', 'add', $Remote, $DefaultUrl) | Out-Null
}
G @('remote', 'get-url', $Remote) | Out-Null
if ($script:GitExit -ne 0) {
  G @('remote', 'add', $Remote, $DefaultUrl) | Out-Null
  if ($script:GitExit -ne 0) { Die "could not add the remote $Remote" }
  Info "added remote $Remote -> $DefaultUrl"
}
G @('rev-parse', '--verify', '-q', 'HEAD') | Out-Null
$hasHead = ($script:GitExit -eq 0)
if (-not $Branch) {
  # A copy with no commits yet (just adopted) is on whatever `git init` named its branch - "master" on
  # many machines, which GitHub does not have. Only a real checkout's branch is worth following.
  $Branch = 'main'
  if ($hasHead) {
    $b = G @('symbolic-ref', '--quiet', '--short', 'HEAD')
    if ($script:GitExit -eq 0 -and $b.Count -gt 0) { $Branch = $b[0] }
  }
}
$gitDir = (G @('rev-parse', '--git-dir'))[0]
# inside .git: never tracked, never in a diff. ABSOLUTE, because the UI build runs from frontend\.
$State = Join-Path (Resolve-Path $gitDir).Path 'iris-update'
New-Item -ItemType Directory -Force $State | Out-Null
$remoteUrl = (G @('remote', 'get-url', $Remote))[0]
Ok "$remoteUrl  -  branch $Branch"

function Log-History([string]$what, [string]$from, [string]$to) {
  Add-Content -Path (Join-Path $State 'history') -Value ("{0} {1} {2} {3} -> {4}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Branch, $what, $from, $to)
}

$Names = @()
if ($Action -eq 'rollback') {
  $prevFile = Join-Path $State 'previous'
  if (-not (Test-Path $prevFile)) { Die "no earlier version is recorded - nothing to roll back to" 3 }
  $prev = (Get-Content $prevFile -TotalCount 1).Trim()
  G @('cat-file', '-e', "$prev^{commit}") | Out-Null
  if ($script:GitExit -ne 0) { Die "the recorded version $prev is not in this repository any more" 3 }
  $cur = (G @('rev-parse', 'HEAD'))[0]
  if ($cur -eq $prev) { Ok "already at $((G @('log', '-1', '--format=%h %s', $prev))[0])"; exit 0 }
  Step "Rolling back"
  Line ("from  " + (G @('log', '-1', '--format=%h  %ad  %s', '--date=short', 'HEAD'))[0])
  Line ("to    " + (G @('log', '-1', '--format=%h  %ad  %s', '--date=short', $prev))[0])
  $Names = @(G @('diff', '--name-only', $prev, 'HEAD') | Where-Object { $_ })
  Info "$($Names.Count) file(s) go back"
  if (-not (Confirm-Step "Roll Iris back to $($prev.Substring(0,7))")) { Die "declined - nothing changed" 3 }
  # --keep, not --hard: it refuses rather than overwrite a local edit to a file the rollback touches.
  G @('reset', '--quiet', '--keep', $prev) | Out-Null
  if ($script:GitExit -ne 0) { Die "rollback refused: a local edit touches a file it would change. Commit or discard it first (git status)." 3 }
  Set-Content -Path $prevFile -Value $cur -Encoding ascii   # a second rollback returns to where this one started
  Log-History 'rollback' $cur $prev
  Ok ("now at " + (G @('log', '-1', '--format=%h  %s', 'HEAD'))[0])
} else {
  # -- 2. fetch ---------------------------------------------------------------
  Step "Fetching the latest version from GitHub"
  $env:GIT_TERMINAL_PROMPT = '0'
  $fetchLog = Join-Path $State 'fetch.log'
  if (-not (Run-Spin "git fetch $Remote $Branch" 'git' @('fetch', '--prune', '--quiet', $Remote, $Branch) $fetchLog)) {
    Get-Content $fetchLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
    Die "could not fetch $Remote/$Branch - check the network, or that the branch exists"
  }
  $Up = "$Remote/$Branch"
  Ok ("fetched " + (G @('log', '-1', '--format=%h  %ad', '--date=short', $Up))[0])

  # -- 3. the diff check ------------------------------------------------------
  Step "What would change"
  $ahead = 0; $behind = 0
  if ($hasHead) {
    $lr = (G @('rev-list', '--left-right', '--count', "HEAD...$Up"))[0] -split '\s+'
    $ahead = [int]$lr[0]; $behind = [int]$lr[1]
    Line ("this copy  " + (G @('log', '-1', '--format=%h  %ad  %s', '--date=short', 'HEAD'))[0])
  } else {
    $behind = [int](G @('rev-list', '--count', $Up))[0]
    Line "this copy  (not yet a git checkout - compared file by file)"
  }
  Line ("GitHub     " + (G @('log', '-1', '--format=%h  %ad  %s', '--date=short', $Up))[0])

  if ($hasHead -and $behind -eq 0) {
    Ok "Iris is up to date"
    if ($ahead -gt 0) { Info "this copy has $ahead commit(s) of its own that GitHub does not" }
    $d = @(G @('status', '--porcelain', '--untracked-files=no') | Where-Object { $_ })
    if ($d.Count -gt 0) { Info "$($d.Count) file(s) edited locally (kept as they are)" }
    exit 0
  }

  if ($hasHead) {
    Head "$behind incoming commit(s)"
    $log = G @('log', '--no-merges', '--format=%h  %ad  %s', '--date=short', "HEAD..$Up")
    $log | Select-Object -First 25 | ForEach-Object { Line "  $_" }
    if ($behind -gt 25) { Info "  ... and $($behind - 25) more" }
    $numstat = G @('diff', '--numstat', 'HEAD', $Up)
    $namestat = G @('diff', '--name-status', 'HEAD', $Up)
  } else {
    # An adopted copy has no commits and an EMPTY index, and against an empty index every file reads as
    # new. Load GitHub's tree into the INDEX - the files on disk are not touched - so the diff is exactly
    # the files that differ, in the direction GitHub would bring.
    G @('read-tree', $Up) | Out-Null
    if ($script:GitExit -ne 0) { Die "could not read $Up" }
    $numstat = G @('diff', '--numstat', '-R')
    $namestat = G @('diff', '--name-status', '-R')
  }

  # Changed files by AREA, with line counts: "412 files changed" says nothing an analyst can act on.
  $areas = [ordered]@{}
  foreach ($a in @('Backend (API, parsers, detections)','Frontend (UI)','Dependencies','Docker image','Scripts','Docs','Other')) {
    $areas[$a] = @{ n = 0; add = 0; del = 0; files = New-Object System.Collections.ArrayList }
  }
  foreach ($l in $numstat) {
    $parts = $l -split "`t"
    if ($parts.Count -lt 3) { continue }
    $p = $parts[2]; $Names += $p
    $add = 0; $del = 0
    if ($parts[0] -ne '-') { $add = [int]$parts[0] }
    if ($parts[1] -ne '-') { $del = [int]$parts[1] }
    $area = 'Other'
    if ($p -match '^backend/requirements' -or $p -match '^frontend/package(-lock)?\.json$') { $area = 'Dependencies' }
    elseif ($p -match '^(Dockerfile|docker-compose.*\.ya?ml|\.dockerignore)$') { $area = 'Docker image' }
    elseif ($p -match '^backend/') { $area = 'Backend (API, parsers, detections)' }
    elseif ($p -match '^frontend/') { $area = 'Frontend (UI)' }
    elseif ($p -match '\.(sh|ps1)$') { $area = 'Scripts' }
    elseif ($p -match '\.md$' -or $p -match '^docs/') { $area = 'Docs' }
    $x = $areas[$area]; $x.n++; $x.add += $add; $x.del += $del
    if ($x.files.Count -lt 8) { [void]$x.files.Add($p) }
  }
  Head "files by area"
  foreach ($k in $areas.Keys) {
    $x = $areas[$k]
    if ($x.n -eq 0) { continue }
    Line ("  {0,-36} {1,4} file(s)   +{2} -{3}" -f $k, $x.n, $x.add, $x.del)
    foreach ($f in $x.files) { Info "      $f" }
    if ($x.n -gt 8) { Info "      ... and $($x.n - 8) more" }
  }

  # What the change MEANS for this install - the part a file list cannot tell you.
  function Has([string]$re) { return [bool]($Names | Where-Object { $_ -match $re } | Select-Object -First 1) }
  $impact = @()
  if (Has '^backend/requirements\.txt$')           { $impact += 'Python dependencies changed - installed during the update' }
  if (Has '^backend/requirements-gpu\.txt$')       { $impact += 'GPU wheels changed - a Docker rebuild picks them up; a local install should re-run .\setup.ps1 -Mode local' }
  if (Has '^frontend/package(-lock)?\.json$')      { $impact += 'UI dependencies changed - reinstalled (npm ci) during the update' }
  if (Has '^(Dockerfile|docker-compose.*)$')       { $impact += 'the image definition changed - the Docker rebuild is a full one' }
  if (Has '^backend/app/(parsers/|normalize\.py)') { $impact += 'parsers changed - on the next start the library is RE-PARSED once (can take a while on a big library)' }
  if (Has '^backend/app/detect\.py$')              { $impact += 'detections changed - the search index and entity graph rebuild once, in the background' }
  if (Has '^update\.(sh|ps1)$')                    { $impact += 'the updater itself changed - the new version is used from the next run' }
  if (Has '^setup\.(sh|ps1)$')                     { $impact += 'setup changed - if something is missing afterwards, re-run setup' }
  if ($impact.Count -gt 0) { Head "what it means for this install"; foreach ($m in $impact) { Line "  - $m" } }

  # THE EVIDENCE. backend\data is not in the repository; an update that would reach it is refused.
  if (Has '^(backend/data/|\.env$)') {
    Die "an incoming change touches backend\data or .env - refusing. Report this; your evidence and settings were not changed." 3
  }
  if (Test-Path 'backend\data') {
    & git check-ignore -q 'backend/data/probe' 2>$null
    if ($LASTEXITCODE -ne 0) { Warn "backend\data is not git-ignored in this copy - the update will not touch it, but check .gitignore" }
  }
  Info "your evidence (backend\data) and .env are outside the repository and are not touched"

  # -- local state ------------------------------------------------------------
  Step "Checking this copy for local changes"
  $dirty = @(); $conflict = @(); $collide = @()
  if ($hasHead) {
    $dirty = @((G @('diff', '--name-only', 'HEAD')) + (G @('diff', '--name-only', '--cached')) | Where-Object { $_ } | Sort-Object -Unique)
    $conflict = @($dirty | Where-Object { $Names -contains $_ })
    # A file GitHub ADDS that already exists here untracked would block the merge.
    foreach ($l in $namestat) {
      $parts = $l -split "`t"
      if ($parts[0] -eq 'A' -and (Test-Path -LiteralPath $parts[1])) {
        & git ls-files --error-unmatch -- $parts[1] *> $null
        if ($LASTEXITCODE -ne 0) { $collide += $parts[1] }
      }
    }
  }
  if (-not $hasHead) {
    # An adopted copy has no history to tell an edit of yours from an old version of Iris, so there is
    # nothing to set aside: every file listed above is REPLACED. Said before the question, not after.
    Warn "this copy has no git history, so every file listed above will be REPLACED with GitHub's version -"
    Warn "including any file you edited yourself. Copy those somewhere first if you want to keep them."
  }
  if ($hasHead) { if ($dirty.Count -eq 0) { Ok "no local edits" } else { Info "$($dirty.Count) file(s) edited locally" } }
  if ($conflict.Count -gt 0) {
    Warn "edited here AND changed on GitHub:"; $conflict | ForEach-Object { Write-Host "          $_" }
  } elseif ($dirty.Count -gt 0) { Ok "none of them is touched by the update - they are kept as they are" }
  if ($collide.Count -gt 0) {
    Warn "GitHub adds file(s) that already exist here, untracked:"; $collide | ForEach-Object { Write-Host "          $_" }
  }
  if ($ahead -gt 0) {
    Warn "this copy has $ahead commit(s) of its own that GitHub does not have:"
    G @('log', '--format=%h  %s', "$Up..HEAD") | Select-Object -First 10 | ForEach-Object { Write-Host "          $_" }
  }

  if ($Diff) {
    Step ("The full patch" + $(if ($DiffPath) { " ($DiffPath)" } else { '' }))
    $dargs = @('--no-pager', 'diff', '--color')
    if ($hasHead) { $dargs += @('HEAD', $Up) } else { $dargs += @('-R') }
    if ($DiffPath) { $dargs += @('--', ($DiffPath -replace '\\', '/')) }
    & git @dargs
  }

  if ($Action -eq 'check') {
    Write-Host ""; Ok "update available: $behind commit(s). Run .\update.ps1 to apply it."
    exit 10
  }

  # Refusals come AFTER the whole picture has been shown, so the analyst sees why.
  if ($ahead -gt 0) {
    Die "this copy has its own commits, so it cannot simply move to GitHub's version. To keep them: git rebase $Up. To drop them: git reset --keep $Up." 3
  }
  if ($collide.Count -gt 0) { Die "move or delete the untracked file(s) above first - the update would have to overwrite them" 3 }
  if ($conflict.Count -gt 0 -and -not $Stash) {
    Die "re-run with -Stash to set your edits aside and put them back after the update, or commit/discard them first" 3
  }

  Write-Host ""
  $target = (G @('rev-parse', '--short', $Up))[0]
  if (-not (Confirm-Step "Update Iris to $target")) { Die "declined - nothing changed" 3 }

  # -- 4. apply ---------------------------------------------------------------
  Step "Updating the code"
  $from = ''
  if ($hasHead) { $from = (G @('rev-parse', 'HEAD'))[0] }
  $stashed = $false
  if ($Stash -and $dirty.Count -gt 0) {
    G @('stash', 'push', '--quiet', '-m', ("iris-update " + (Get-Date).ToUniversalTime().ToString('s'))) | Out-Null
    if ($script:GitExit -ne 0) { Die "git stash failed" }
    $stashed = $true; Info "local edits set aside (git stash)"
  }
  if ($hasHead) {
    G @('merge', '--ff-only', '--quiet', $Up) | Out-Null
    if ($script:GitExit -ne 0) { Die "the fast-forward failed - nothing was changed" }
  } else {
    # An adopted copy: files that differ from GitHub are REPLACED. Listed above, confirmed just now.
    G @('reset', '--quiet', $Up) | Out-Null
    $r1 = $script:GitExit
    G @('checkout', '--quiet', '--', '.') | Out-Null
    if ($r1 -ne 0 -or $script:GitExit -ne 0) { Die "could not check out $Up" }
    # `git init` may have named the branch "master"; the next update follows the branch it is ON.
    G @('branch', '-M', $Branch) | Out-Null
    G @('branch', "--set-upstream-to=$Up") | Out-Null
  }
  if ($stashed) {
    G @('stash', 'pop', '--quiet') | Out-Null
    if ($script:GitExit -eq 0) { Ok "local edits put back" }
    else { Warn "your edits conflict with the update - they are kept in the stash (git stash list); resolve, then git stash drop" }
  }
  $now = (G @('rev-parse', 'HEAD'))[0]
  if ($from) { Set-Content -Path (Join-Path $State 'previous') -Value $from -Encoding ascii }
  Log-History 'update' $(if ($from) { $from } else { 'none' }) $now
  Ok ("now at " + (G @('log', '-1', '--format=%h  %s', 'HEAD'))[0])
}

# -- 5. refresh the install ---------------------------------------------------
# Which install THIS checkout is. The container is matched by the working directory compose recorded on
# it, so a second checkout on the same machine can never rebuild the analyst's running Iris.
function Norm([string]$p) { return ($p -replace '/', '\').TrimEnd('\').ToLower() }
$here = Norm (Get-Location).Path
$containerHere = $false
if (Get-Command docker -ErrorAction SilentlyContinue) {
  # The labels as JSON, NOT an `index .Config.Labels "..."` template: Windows PowerShell passes the
  # embedded double quotes to docker unescaped, the template fails to parse, and the Docker install
  # would silently never be recognised. JSON needs no quotes in the argument at all.
  $labels = & docker inspect iris --format '{{json .Config.Labels}}' 2>$null
  $inspectOk = ($LASTEXITCODE -eq 0)
  if ($inspectOk -and $labels) {
    try {
      $wd = ($labels | ConvertFrom-Json).'com.docker.compose.project.working_dir'
      if ($wd -and ((Norm "$wd") -eq $here)) { $containerHere = $true }
    } catch { }
  }
}
$install = $Mode
if ($Mode -eq 'auto') {
  if ($containerHere) { $install = 'docker' }
  elseif ((Test-Path '.venv\Scripts\python.exe') -or (Test-Path 'frontend\node_modules') -or (Test-Path 'frontend\dist\index.html')) { $install = 'local' }
  else { $install = 'none' }
}
function Changed([string]$re) { return [bool]($Names | Where-Object { $_ -match $re } | Select-Object -First 1) }

if ($NoRestart) {
  Step "Refreshing the install"
  Info "-NoRestart: the code is updated; rebuild/restart it yourself (.\start.ps1 -Build, or .\start.ps1 -Mode local)"
} elseif ($install -eq 'docker') {
  Step "Rebuilding and restarting the Docker install"
  Info "start.ps1 -Build: new image, container recreated, health checked, the old image removed"
  # the same PowerShell this runs in (Windows PowerShell or pwsh), not whichever one PATH finds first
  $shell = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  & $shell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'start.ps1') -Build -NoBrowser -Port $Port
  $startOk = ($LASTEXITCODE -eq 0)
  if (-not $startOk) { Die "the rebuild failed - the code is updated; fix the error above and run .\start.ps1 -Build (or .\update.ps1 -Action rollback)" }
} elseif ($install -eq 'local') {
  Step "Refreshing the local install"
  if (Changed '^backend/requirements\.txt$') {
    if (Test-Path '.venv\Scripts\python.exe') {
      Info "installing the changed Python dependencies into .venv"
      $pipOk = Run-Spin 'pip install -r backend\requirements.txt' (Resolve-Path '.venv\Scripts\python.exe').Path @('-m', 'pip', 'install', '--quiet', '-r', 'backend\requirements.txt') (Join-Path $State 'pip.log')
      if (-not $pipOk) { Get-Content (Join-Path $State 'pip.log') -Tail 15 | ForEach-Object { Write-Host "        $_" }; Die "pip install failed" }
      Ok "Python dependencies installed"
    } else { Warn "Python dependencies changed and there is no .venv here - run .\setup.ps1 -Mode local" }
  }
  if (Changed '^backend/requirements-gpu\.txt$') { Warn "GPU wheels changed - run .\setup.ps1 -Mode local to resolve them for this machine" }
  $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
  if (-not $npm) { $npm = Get-Command npm -ErrorAction SilentlyContinue }
  if ($npm -and (Test-Path 'frontend\package.json')) {
    Push-Location frontend
    $webOk = $true
    if (-not (Test-Path 'node_modules') -or (Changed '^frontend/package(-lock)?\.json$')) {
      $webOk = Run-Spin 'npm ci' $npm.Source @('ci', '--ignore-scripts') (Join-Path $State 'npm-ci.log')
    }
    if ($webOk) { $webOk = Run-Spin 'building the UI' $npm.Source @('run', 'build') (Join-Path $State 'npm-build.log') }
    Pop-Location
    if (-not $webOk) { Die "the UI build failed - see $State\npm-*.log" }
    Ok "UI rebuilt"
  } else { Warn "npm not found - the UI was not rebuilt (.\start.ps1 -Mode local will try, or run .\setup.ps1 -Mode local)" }
  # A health answer proves SOMETHING serves Iris on the port (a Docker Iris answers too), not that it is this install.
  if (Test-Healthy) { Warn "something is serving Iris on $Url - if that is this local install, it is still running the OLD code: stop it (Ctrl-C in its window) and run .\start.ps1 -Mode local" }
  else { Info "start it with: .\start.ps1 -Mode local" }
} else {
  Step "Refreshing the install"
  Info "no running install from this folder was found - start it with .\start.ps1 (Docker) or .\start.ps1 -Mode local"
}

Write-Host ""
Ok ("Iris is at " + (G @('log', '-1', '--format=%h  %ad  %s', '--date=short', 'HEAD'))[0])
if (Test-Path (Join-Path $State 'previous')) { Info "to go back: .\update.ps1 -Action rollback" }
exit 0
