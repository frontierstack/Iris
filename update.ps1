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
   .\update.ps1 -NoInstall       # never install or change anything outside the repo; report what is missing

 Before anything else it checks what IT needs - winget (installed, registered, current), git (installed,
 on PATH, new enough, its PATH entries sane) and, for a local install, Node and the .venv - lists every
 fix with its exact command and asks ONCE (-Yes answers it).

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
  [switch]$Adopt,
  [switch]$NoInstall
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
  $out = & $script:GitExe @a 2>&1
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

# -- 0. what the updater needs ------------------------------------------------
# The updater runs on machines that have moved on since setup: git upgraded, moved or uninstalled, PATH
# hand-edited, winget never registered for this user. Everything it needs is checked HERE, every fix is
# printed with the exact command, and ONE question covers them all (-Yes answers it; -NoInstall only
# reports). Same rules as setup.ps1 - see "Setup bootstraps the machine" in CLAUDE.md, and the two traps
# it records: a function returning a boolean must send native output to Out-Host, and a fresh install
# is invisible to THIS process until its PATH is rebuilt from the registry.
$GitMin    = [version]'2.31'   # GIT_CONFIG_COUNT (the per-process config at the top) needs 2.31
$WingetMin = [version]'1.6'    # older builds lack --disable-interactivity and stall on source agreements
$NodeMin   = 18                # Vite 5
$EnvKeyMachine = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$WindowsApps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Ask-Fix([string]$q) {
  if ($Yes) { return $true }
  if ([Console]::IsInputRedirected) { Warn "not interactive and -Yes not given: nothing is changed"; return $false }
  $a = Read-Host "    ? $q [Y/n]"
  return ($a -eq '' -or $a -match '^(y|yes)$')
}
function Use-Tls12 { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 }
function Norm-Dir([string]$p) { return ([Environment]::ExpandEnvironmentVariables($p.Trim().Trim('"'))).TrimEnd('\').ToLower() }

# PATH as STORED, with %VARS% unexpanded - GetEnvironmentVariable expands them, and writing that back
# would silently turn every %USERPROFILE% entry into a literal path.
function Get-RawPath([string]$scope) {
  if ($scope -eq 'User') { $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment') }
  else { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($EnvKeyMachine) }
  if (-not $k) { return '' }
  try { return [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $k.Close() }
}
function Set-RawPath([string]$scope, [string]$value) {
  if ($scope -eq 'User') { $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true) }
  else { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($EnvKeyMachine, $true) }
  if (-not $k) { throw "cannot open the $scope environment for writing" }
  try { $k.SetValue('Path', $value, [Microsoft.Win32.RegistryValueKind]::ExpandString) } finally { $k.Close() }
  # Tell Explorer the environment changed, so every NEW window sees it without a sign-out.
  try {
    if (-not ('IrisUpdate.Env' -as [type])) {
      Add-Type -Namespace IrisUpdate -Name Env -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, UIntPtr w, string l, uint f, uint t, out UIntPtr r);'
    }
    $r = [UIntPtr]::Zero
    [void][IrisUpdate.Env]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$r)
  } catch { }
}
function Test-OnPath([string]$dir, [string]$raw) {
  $n = Norm-Dir $dir
  foreach ($p in ($raw -split ';')) { if ($p.Trim() -and (Norm-Dir $p) -eq $n) { return $true } }
  return $false
}
function Add-UserPath([string]$dir) {
  $raw = Get-RawPath 'User'
  if (-not (Test-OnPath $dir $raw)) { Set-RawPath 'User' ((($raw.TrimEnd(';')), $dir | Where-Object { $_ }) -join ';') }
  if (-not (Test-OnPath $dir $env:PATH)) { $env:PATH = $env:PATH.TrimEnd(';') + ";$dir" }
  return $true
}
function Remove-PathEntries($a) {
  $drop = @{}; foreach ($e in $a.Entries) { $drop[(Norm-Dir $e)] = $true }
  $keep = @((Get-RawPath $a.Scope) -split ';' | Where-Object { $_.Trim() -and -not $drop.ContainsKey((Norm-Dir $_)) })
  Set-RawPath $a.Scope ($keep -join ';')
  return $true
}
# Rebuild THIS process's PATH: what it has, plus whatever the registry gained since it started (an
# install from another window, or one made a moment ago). Merged, never replaced - replacing drops
# entries the parent shell added on purpose (an activated venv, a tool's own bin folder).
function Merge-SessionPath {
  $have = New-Object System.Collections.ArrayList; $seen = @{}
  foreach ($p in (@($env:PATH -split ';') + @([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') + @([Environment]::GetEnvironmentVariable('Path', 'User') -split ';'))) {
    if (-not $p -or -not $p.Trim()) { continue }
    $n = Norm-Dir $p
    if ($seen.ContainsKey($n)) { continue }
    $seen[$n] = $true; [void]$have.Add($p)
  }
  # winget is an app-execution ALIAS in this folder; a PATH without it hides a winget that is installed.
  if ((Test-Path (Join-Path $WindowsApps 'winget.exe')) -and -not $seen.ContainsKey((Norm-Dir $WindowsApps))) { [void]$have.Add($WindowsApps) }
  $env:PATH = $have -join ';'
}
function Get-ExeVersion([string]$exe, [string[]]$a) {
  try { $out = & $exe @a 2>$null; $code = $LASTEXITCODE } catch { return $null }
  if ($code -ne 0) { return $null }
  if ((@($out) -join ' ') -match '(\d+)\.(\d+)(?:\.(\d+))?') {
    $b = '0'; if ($matches[3]) { $b = $matches[3] }
    return [version]("{0}.{1}.{2}" -f $matches[1], $matches[2], $b)
  }
  return $null
}
function Get-WingetVersion {
  $wg = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $wg) { return $null }
  return (Get-ExeVersion $wg.Source @('--version'))
}

$script:WingetFresh = $false
function Invoke-Winget([string]$verb, [string]$id) {
  $wg = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $wg) { return $false }
  if (-not $script:WingetFresh) {
    # A stale source index answers "No package found" for a package that exists.
    & $wg.Source source update 2>&1 | Out-Null
    $script:WingetFresh = $true
  }
  $a = @($verb, '--id', $id, '-e', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements')
  $v = Get-WingetVersion
  if ($v -and $v -ge [version]'1.4') { $a += '--disable-interactivity' }
  # Out-Host, never a bare call: this function's return value is a boolean (see CLAUDE.md).
  & $wg.Source @a 2>&1 | Out-Host
  $code = $LASTEXITCODE
  Merge-SessionPath
  # 0 done; 0x8A15002B nothing newer to install; 0x8A150061 already installed
  return ($code -eq 0 -or $code -eq -1978335189 -or $code -eq -1978335135)
}
function Install-WingetBundle {
  # The App Installer bundle itself, from Microsoft's short link - the last resort for both a missing
  # and an outdated winget.
  $ProgressPreference = 'SilentlyContinue'   # PS 5.1's progress bar makes a large download crawl
  $f = Join-Path $env:TEMP 'iris-AppInstaller.msixbundle'
  try {
    Use-Tls12
    Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile $f -UseBasicParsing -ErrorAction Stop
    Add-AppxPackage -Path $f -ForceApplicationShutdown -ErrorAction Stop
  } catch { Warn "installing the App Installer bundle failed: $($_.Exception.Message)" }
  Remove-Item $f -Force -ErrorAction SilentlyContinue
  Merge-SessionPath
}
function Install-Winget {
  # 1. App Installer is often PROVISIONED on the machine but not REGISTERED for this user (a new
  #    profile, a Sandbox, a machine that never opened the Store). Registering needs no download.
  try { Add-AppxPackage -RegisterByFamilyName -MainPackage 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe' -ErrorAction Stop } catch { }
  Merge-SessionPath
  if (Get-Command winget -ErrorAction SilentlyContinue) { return $true }
  # 2. Microsoft's own repair path: the WinGet PowerShell module installs winget AND its dependencies
  #    (VCLibs, UI.Xaml), which the bare bundle does not.
  try {
    Use-Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
    Install-Module -Name Microsoft.WinGet.Client -Force -Scope CurrentUser -Repository PSGallery -AllowClobber -ErrorAction Stop | Out-Null
    Import-Module Microsoft.WinGet.Client -ErrorAction Stop
    Repair-WinGetPackageManager -Latest -Force -ErrorAction Stop 2>&1 | Out-Host
  } catch { Warn "the WinGet module route failed: $($_.Exception.Message)" }
  Merge-SessionPath
  if (Get-Command winget -ErrorAction SilentlyContinue) { return $true }
  Install-WingetBundle
  return [bool](Get-Command winget -ErrorAction SilentlyContinue)
}
function Update-Winget {
  $before = Get-WingetVersion
  $null = Invoke-Winget 'upgrade' 'Microsoft.AppInstaller'
  if (-not ((Get-WingetVersion) -gt $before)) { Install-WingetBundle }
  $after = Get-WingetVersion
  return [bool]($after -and $after -ge $WingetMin)
}

# Git's root from any of its exes: <root>\cmd\git.exe, <root>\bin\git.exe, <root>\mingw64\bin\git.exe.
function Get-GitRoot([string]$exe) {
  $d = Split-Path $exe -Parent
  for ($i = 0; $i -lt 3 -and $d; $i++) {
    if (Test-Path -LiteralPath (Join-Path $d 'cmd\git.exe')) { return $d }
    $d = Split-Path $d -Parent
  }
  return $null
}
# Every git on this machine, whether or not PATH can see it: the installer's registry record, what
# PATH resolves, and the usual places (Program Files, per-user, PortableGit, scoop).
function Find-GitInstalls {
  $cands = New-Object System.Collections.ArrayList
  foreach ($k in @('HKLM:\SOFTWARE\GitForWindows', 'HKCU:\SOFTWARE\GitForWindows', 'HKLM:\SOFTWARE\WOW6432Node\GitForWindows')) {
    $ip = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).InstallPath
    if ($ip) { [void]$cands.Add(@((Join-Path $ip 'cmd\git.exe'), $true)) }
  }
  foreach ($c in @(Get-Command git.exe -All -CommandType Application -ErrorAction SilentlyContinue)) { [void]$cands.Add(@($c.Source, $false)) }
  foreach ($r in @("$env:ProgramFiles\Git", "${env:ProgramFiles(x86)}\Git", "$env:LOCALAPPDATA\Programs\Git",
                   "$env:LOCALAPPDATA\Programs\PortableGit", "$env:USERPROFILE\scoop\apps\git\current")) {
    [void]$cands.Add(@((Join-Path $r 'cmd\git.exe'), $false))
  }
  $out = New-Object System.Collections.ArrayList; $seen = @{}
  foreach ($c in $cands) {
    if (-not (Test-Path -LiteralPath $c[0] -PathType Leaf)) { continue }
    $root = Get-GitRoot $c[0]
    $dir = Split-Path $c[0] -Parent
    if ($root) { $dir = Join-Path $root 'cmd' }
    $n = Norm-Dir $dir
    if ($seen.ContainsKey($n)) { if ($c[1]) { $seen[$n].Installed = $true }; continue }
    $exe = Join-Path $dir 'git.exe'
    $o = [pscustomobject]@{ Dir = $dir; Exe = $exe; Root = $root; Installed = [bool]$c[1]; Version = (Get-ExeVersion $exe @('--version')) }
    $seen[$n] = $o; [void]$out.Add($o)
  }
  return ,$out.ToArray()
}
function Install-GitDirect {
  # No winget, or winget could not: Git for Windows' own installer from its latest GitHub release, run
  # silently - for the whole machine when elevated, for this user when not (no UAC prompt either way).
  $ProgressPreference = 'SilentlyContinue'
  try {
    Use-Tls12
    $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/git-for-windows/git/releases/latest' -Headers @{ 'User-Agent' = 'iris-update' } -ErrorAction Stop
    $arch = '32-bit'
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' } elseif ([Environment]::Is64BitOperatingSystem) { $arch = '64-bit' }
    $asset = @($rel.assets | Where-Object { $_.name -match "^Git-[\d.]+-$arch\.exe$" })[0]
    if (-not $asset) { Warn "no $arch installer in $($rel.tag_name)"; return $false }
    $dest = Join-Path $env:TEMP $asset.name
    Info "downloading $($asset.browser_download_url)"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dest -UseBasicParsing -ErrorAction Stop
  } catch { Warn "downloading Git for Windows failed: $($_.Exception.Message)"; return $false }
  $inst = @('/VERYSILENT', '/NORESTART', '/NOCANCEL', '/SP-', '/SUPPRESSMSGBOXES', '/o:PathOption=Cmd')
  if (-not (Test-Admin)) { $inst += '/CURRENTUSER' }
  $p = Start-Process -FilePath $dest -ArgumentList $inst -Wait -PassThru
  Remove-Item $dest -Force -ErrorAction SilentlyContinue
  Merge-SessionPath
  return ($p.ExitCode -eq 0)
}
function Install-Git([bool]$upgrade) {
  $ok = $false
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    $verb = 'install'; if ($upgrade) { $verb = 'upgrade' }
    $ok = Invoke-Winget $verb 'Git.Git'
    if ($ok -and $upgrade) {
      # "nothing newer" is a success code to winget, and a portable git is not a package it manages -
      # only a version that actually moved counts.
      $g = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
      $ok = [bool]($g -and (Get-ExeVersion $g.Source @('--version')) -ge $GitMin)
    }
  }
  if (-not $ok) { $ok = Install-GitDirect }
  # The installer writes PATH to the registry; if this window still cannot see git, point it there.
  if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) {
    # Assigned first, never piped or @()-wrapped: the function returns ,$array, and either of those
    # NESTS it - the pipeline would see one item, the whole list.
    $all = Find-GitInstalls
    $best = @($all | Where-Object { $_.Version } | Sort-Object @{ e = 'Version'; Descending = $true }, @{ e = 'Installed'; Descending = $true })[0]
    if ($best) { $null = Add-UserPath $best.Dir }
  }
  return [bool]($ok -and (Get-Command git -CommandType Application -ErrorAction SilentlyContinue))
}

Step "Checking what the updater needs"
$Fixes = New-Object System.Collections.ArrayList
function Add-Fix([int]$Order, [string]$What, [string]$Cmd, [scriptblock]$Do, $Arg = $null) {
  [void]$Fixes.Add([pscustomobject]@{ Order = $Order; What = $What; Cmd = $Cmd; Do = $Do; Arg = $Arg })
}
$hadGit = [bool](Get-Command git -CommandType Application -ErrorAction SilentlyContinue)
Merge-SessionPath
if (-not $hadGit -and (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) {
  Info "git is on the saved PATH but not on this window's (opened before git was installed, or PATH was changed in this shell) - using it for this run"
}

# winget: the ALIAS folder is a standard user PATH entry; without it an installed winget is "missing".
if ((Test-Path (Join-Path $WindowsApps 'winget.exe')) -and -not (Test-OnPath $WindowsApps ((Get-RawPath 'User') + ';' + (Get-RawPath 'Machine')))) {
  Add-Fix 10 "put $WindowsApps back on your PATH (winget and other app aliases live there)" "user PATH += $WindowsApps" { param($a) Add-UserPath $a } $WindowsApps
}
$wgVer = Get-WingetVersion

# git
$gits = Find-GitInstalls   # NOT @(...): see Install-Git
$working = @($gits | Where-Object { $_.Version } | Sort-Object @{ e = 'Version'; Descending = $true }, @{ e = 'Installed'; Descending = $true })
$winner = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$winVer = $null; if ($winner) { $winVer = Get-ExeVersion $winner.Source @('--version') }
$needGit = ''   # '' | install | upgrade
$best = $null
if (-not $winner -or -not $winVer) {
  if ($winner) { Warn "the git on PATH ($($winner.Source)) does not run" }
  if ($working.Count -gt 0) {
    $best = $working[0]
    Warn "git $($best.Version) is installed at $($best.Dir), but that folder is not on PATH"
    # This run uses it either way; the fix is for every window after this one.
    $env:PATH = "$($best.Dir);$env:PATH"
    Add-Fix 40 "add $($best.Dir) to your PATH" "user PATH += $($best.Dir)" { param($a) Add-UserPath $a } $best.Dir
    $winVer = $best.Version
    if ($winVer -lt $GitMin) { $needGit = 'upgrade' }
  } else {
    $needGit = 'install'
  }
} elseif ($winVer -lt $GitMin) {
  $needGit = 'upgrade'
}
if ($needGit) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Add-Fix 20 "install winget (App Installer) so dependencies can be installed" "Add-AppxPackage -RegisterByFamilyName ...DesktopAppInstaller / Repair-WinGetPackageManager / aka.ms/getwinget" { param($a) Install-Winget }
  }
  if ($needGit -eq 'install') {
    Add-Fix 30 "install Git for Windows" "winget install --id Git.Git -e   (else: the silent installer from github.com/git-for-windows)" { param($a) Install-Git $false }
  } else {
    Add-Fix 30 "upgrade git $winVer -> the latest (the updater needs $GitMin+)" "winget upgrade --id Git.Git -e   (else: the silent installer from github.com/git-for-windows)" { param($a) Install-Git $true }
  }
}
if ($wgVer -and $wgVer -lt $WingetMin) {
  Add-Fix 20 "update winget $wgVer -> the latest" "winget upgrade --id Microsoft.AppInstaller -e   (else: aka.ms/getwinget)" { param($a) Update-Winget }
}

# PATH hygiene, limited to GIT's entries - the rest of PATH is not the updater's business. An entry that
# names a FILE (git-bash.exe, bash.exe) is ignored by Windows, because PATH lists folders; an entry whose
# folder is gone is what an uninstall or a move leaves behind. Neither does anything but mislead.
foreach ($scope in @('User', 'Machine')) {
  $bad = @()
  foreach ($p in ((Get-RawPath $scope) -split ';')) {
    if (-not $p.Trim()) { continue }
    $x = [Environment]::ExpandEnvironmentVariables($p.Trim().Trim('"'))
    if ($x -notmatch 'git') { continue }
    if (Test-Path -LiteralPath $x -PathType Leaf) { $bad += $p; Warn "$scope PATH entry is a FILE, not a folder: $p"; continue }
    # Only when its DRIVE is here: a folder on an unplugged disk or a share is not a stale entry.
    $q = $null; try { $q = Split-Path -Qualifier $x -ErrorAction Stop } catch { }
    if ($q -and (Test-Path "$q\") -and -not (Test-Path -LiteralPath $x)) { $bad += $p; Warn "$scope PATH entry points at a folder that no longer exists: $p" }
  }
  if ($bad.Count -eq 0) { continue }
  if ($scope -eq 'User' -or (Test-Admin)) {
    Add-Fix 50 "remove $($bad.Count) broken git entr$(if ($bad.Count -eq 1) { 'y' } else { 'ies' }) from the $scope PATH" ("$scope PATH -= " + ($bad -join ' ; ')) { param($a) Remove-PathEntries $a } ([pscustomobject]@{ Scope = $scope; Entries = $bad })
  } else {
    Warn "removing them from the MACHINE PATH needs an elevated PowerShell (run this again as Administrator)"
  }
}

Line ("{0,-8} {1}" -f 'winget', $(if ($wgVer) { "$wgVer" } else { 'not available' }))
# The git this run uses: the one PATH resolves, or the installed one it just put first.
$inUse = $null
if ($winner -and (Get-ExeVersion $winner.Source @('--version'))) { $inUse = $winner.Source }
elseif ($best) { $inUse = $best.Exe }
if ($inUse) { Line ("{0,-8} {1}  {2}" -f 'git', $winVer, $inUse) } else { Line ("{0,-8} {1}" -f 'git', 'not installed') }
foreach ($o in $gits) {
  if ($inUse -and (Norm-Dir $o.Dir) -eq (Norm-Dir (Split-Path $inUse -Parent))) { continue }
  $v = 'does not run'; if ($o.Version) { $v = "$($o.Version)" }
  Info ("{0,-8} {1}  {2}  (also on this machine - not the one in use)" -f '', $v, $o.Exe)
}
if ($winner -and $winVer -and $working.Count -gt 0 -and $working[0].Version -gt $winVer) {
  Warn "an older git ($winVer) comes first on PATH; $($working[0].Version) at $($working[0].Dir) is shadowed by it"
}

if ($Fixes.Count -gt 0) {
  $plan = @($Fixes | Sort-Object Order)
  Head "to fix"
  foreach ($f in $plan) { Line "  - $($f.What)"; Info "      $($f.Cmd)" }
  if ($NoInstall) { Warn "-NoInstall: nothing was changed" }
  elseif (Ask-Fix "Fix $(if ($plan.Count -eq 1) { 'this' } else { "these $($plan.Count)" }) now?") {
    foreach ($f in $plan) {
      $r = $null
      try { $r = & $f.Do $f.Arg } catch { Warn $_.Exception.Message }
      if (@($r)[-1] -eq $true) { Ok $f.What } else { Warn "not done: $($f.What)" }
    }
  } else { Warn "skipped - nothing was changed" }
}
Merge-SessionPath
$gitCmd = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $gitCmd) {
  Die "git is not available. Install Git for Windows (winget install --id Git.Git -e, or https://git-scm.com/download/win) and re-run."
}
$GitExe = $gitCmd.Source
$gv = Get-ExeVersion $GitExe @('--version')
if (-not $gv) { Die "git at $GitExe does not run - reinstall it (winget install --id Git.Git -e --force) and re-run." }
if ($gv -lt $GitMin) { Warn "git $gv is older than $GitMin - the update still works; expect a line-ending warning on every call" }
Ok "git $gv  ($GitExe)"

# -- 1. the checkout ----------------------------------------------------------
Step "Checking this copy of Iris"
# "dubious ownership": git refuses a repository owned by another account (a copy made elevated, a
# folder on another drive, an unzipped download) - and every git call then fails, which would read
# below as "not a git checkout". It is a one-line trust entry, so it is named and offered.
$probe = & $GitExe -C $PSScriptRoot rev-parse --show-toplevel 2>&1
if ((@($probe) -join ' ') -match 'dubious ownership') {
  $safe = ($PSScriptRoot -replace '\\', '/')
  Warn "git refuses this folder: it is owned by another Windows account (git calls this 'dubious ownership')"
  Info "      git config --global --add safe.directory $safe"
  if ($NoInstall) { Die "-NoInstall: trust the folder with the command above and re-run" 3 }
  if (-not (Ask-Fix "Trust this folder for git?")) { Die "declined - git cannot read this copy until it is trusted" 3 }
  & $GitExe config --global --add safe.directory $safe 2>&1 | Out-Host
  Ok "folder trusted"
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
  if (-not (Run-Spin "git fetch $Remote $Branch" $GitExe @('fetch', '--prune', '--quiet', $Remote, $Branch) $fetchLog)) {
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
    & $GitExe check-ignore -q 'backend/data/probe' 2>$null
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
        & $GitExe ls-files --error-unmatch -- $parts[1] *> $null
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
    & $GitExe @dargs
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
# Docker Desktop installed but its CLI folder off PATH would read as "no Docker install" and skip the
# rebuild the analyst's container needs - so the CLI is looked for where Docker Desktop puts it.
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  $dockerBin = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
  if (Test-Path (Join-Path $dockerBin 'docker.exe')) {
    $env:PATH = $env:PATH.TrimEnd(';') + ";$dockerBin"
    Warn "Docker Desktop's CLI ($dockerBin) is not on PATH - using it for this run; re-running Docker Desktop's installer restores it"
  }
}
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
  $shell = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  # A .venv is a pointer to the Python it was made from. Upgrading or uninstalling that Python leaves a
  # .venv whose python.exe cannot start - pip would fail with a message about the venv, not about why.
  $venvPy = '.venv\Scripts\python.exe'
  $venvBroken = $false
  if (Test-Path $venvPy) { & $venvPy -c 'import sys' *> $null; $venvBroken = ($LASTEXITCODE -ne 0) }
  $needSetup = ''
  if ($venvBroken) { $needSetup = ".venv cannot start its Python (the Python it was made from was upgraded or removed)" }
  elseif ((Changed '^backend/requirements\.txt$') -and -not (Test-Path $venvPy)) { $needSetup = "Python dependencies changed and there is no .venv here" }
  if ($needSetup) {
    Warn $needSetup
    Info "      .\setup.ps1 -Mode local   (installs Python if needed, rebuilds .venv, the dependencies and the UI)"
    if ($NoInstall) { Die "-NoInstall: run the command above yourself" 3 }
    if (-not (Ask-Fix "Run setup for the local install now?")) { Die "declined - the code is updated; run .\setup.ps1 -Mode local before starting Iris" 3 }
    $sArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'setup.ps1'), '-Mode', 'local')
    if ($Yes) { $sArgs += '-Yes' }
    & $shell @sArgs
    $setupOk = ($LASTEXITCODE -eq 0)
    if (-not $setupOk) { Die "setup failed - the code is updated; fix the error above and run .\setup.ps1 -Mode local" }
    Ok "local install rebuilt by setup"
    if (Test-Healthy) { Warn "something is serving Iris on $Url - if that is this local install, it is still running the OLD code: stop it (Ctrl-C in its window) and run .\start.ps1 -Mode local" }
    else { Info "start it with: .\start.ps1 -Mode local" }
    Write-Host ""
    Ok ("Iris is at " + (G @('log', '-1', '--format=%h  %ad  %s', '--date=short', 'HEAD'))[0])
    exit 0
  }
  # Node builds the UI. Missing, or too old for Vite, and the build fails halfway with a syntax error
  # that says nothing about the version - so it is installed or upgraded here, asked once.
  $nodeMajor = 0
  $nodeCmd = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($nodeCmd) { $nv = Get-ExeVersion $nodeCmd.Source @('--version'); if ($nv) { $nodeMajor = $nv.Major } }
  $hasNpm = [bool]((Get-Command npm.cmd -ErrorAction SilentlyContinue) -or (Get-Command npm -ErrorAction SilentlyContinue))
  if ((-not $hasNpm -or $nodeMajor -lt $NodeMin) -and (Test-Path 'frontend\package.json')) {
    $verb = 'install'; $what = "Node.js LTS is needed to build the UI and is not installed"
    if ($nodeMajor -gt 0) { $verb = 'upgrade'; $what = "Node.js $nodeMajor is too old to build the UI (needs $NodeMin+)" }
    Warn $what
    Info "      winget $verb --id OpenJS.NodeJS.LTS -e"
    if ($NoInstall) { Warn "-NoInstall: not installing Node.js" }
    elseif (Ask-Fix "$(if ($verb -eq 'install') { 'Install' } else { 'Upgrade' }) Node.js LTS now?") {
      $wgOk = [bool](Get-Command winget -ErrorAction SilentlyContinue)
      if (-not $wgOk) { $wgOk = Install-Winget }
      if ($wgOk -and (Invoke-Winget $verb 'OpenJS.NodeJS.LTS')) {
        $nodeDir = Join-Path $env:ProgramFiles 'nodejs'
        if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $nodeDir 'npm.cmd'))) { $env:PATH = "$nodeDir;$env:PATH" }
        Ok "Node.js $((Get-ExeVersion 'node' @('--version')))"
      } else { Warn "Node.js was not installed - install it from https://nodejs.org/ and re-run" }
    }
  }
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
