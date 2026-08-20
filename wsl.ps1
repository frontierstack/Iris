<#
 Iris — WSL 2 tuning for the Docker backend.

   .\wsl.ps1              # report: what is set, what Iris wants, and why
   .\wsl.ps1 -Apply       # write the settings (backs the file up first)
   .\wsl.ps1 -Apply -Restart   # ...and shut WSL down so they take effect (STOPS EVERY CONTAINER)

 WHY THIS EXISTS
 Docker Desktop runs Iris inside a WSL 2 VM, and Iris is a memory-heavy application: a 300 MB library
 becomes ~7 GB of parsed events, built by six worker processes. On this class of machine that combination
 has produced SIGSEGVs in plain Python and stdlib code — `str.strip()`, a dict comprehension,
 `multiprocessing.reduction.dumps` — and `npm run build` dying the same way inside a different container.
 Pure-Python code does not segfault on its own; those are page faults the VM could not back. Iris is built
 to survive them (workers are contained, the crash handler names the line), but the VM should not be doing
 it in the first place.

 WHAT IT SETS, and why each one
 * transparent_hugepage=never — THP asks the kernel to assemble 2 MB pages under memory pressure, and
   khugepaged's compaction is the single most common source of this failure mode. Iris allocates millions
   of small objects; huge pages buy it nothing.
 * sysctl.vm.compaction_proactiveness=0 — stops background compaction entirely. NOTE: the value that was
   here before, `sysctl.vm.compact_memory=0`, does nothing at all — `compact_memory` is a write-only
   TRIGGER, not a setting, so writing 0 to it is a no-op. That is why the guard never worked.
 * wsl2/maxCrashDumpCount=0 — a segfault in the VM writes a CORE DUMP of the crashed Linux process to
   %TEMP%\wsl-crashes. Four of them in one afternoon came to 146 GB (one was 116.5 GB), because the
   process being dumped holds the whole event pool. And such a dump contains the analyst's log
   contents in plaintext, in a temp directory — a disk problem and a handling problem at once.
 * [experimental] autoMemoryReclaim=disabled — WSL's reclaim walks the guest's page cache and hands memory
   back to Windows. On a workload that holds a multi-GB pool it churns constantly for no benefit.
 * memory / swap — kept as they are (24 GB / 8 GB here) unless they are unset, in which case they are
   given values that leave the host room.

 None of this is Iris-specific tuning of your machine for its own benefit: every one of these settings
 makes the VM more predictable under allocation pressure, which is what was breaking.
#>
param(
  [switch]$Apply,
  [switch]$Restart,
  [switch]$Quiet
)
$ErrorActionPreference = 'Continue'

$WslConfig = Join-Path $env:USERPROFILE '.wslconfig'

# key = section/name, value = what Iris wants. `$null` means "leave whatever is there".
$Wanted = [ordered]@{
  'wsl2/kernelCommandLine'          = 'transparent_hugepage=never sysctl.vm.compaction_proactiveness=0'
  'wsl2/maxCrashDumpCount'          = '0'
  'experimental/autoMemoryReclaim'  = 'disabled'
}
# only applied when the key is MISSING — never overwrite a deliberate choice
$Defaults = [ordered]@{
  'wsl2/memory' = '24GB'
  'wsl2/swap'   = '8GB'
}

function Read-WslConfig {
  <# .wslconfig is INI. Returns @{ 'section/key' = value } plus the raw lines, so a rewrite keeps
     comments and ordering for everything it does not touch. #>
  $map = @{}
  $lines = @()
  if (Test-Path $WslConfig) { $lines = @(Get-Content -LiteralPath $WslConfig) }
  $section = ''
  foreach ($line in $lines) {
    $t = $line.Trim()
    if ($t -match '^\[(.+)\]$') { $section = $Matches[1].Trim().ToLower(); continue }
    if ($t -match '^\s*[#;]') { continue }
    if ($t -match '^([^=]+)=(.*)$') { $map["$section/$($Matches[1].Trim())"] = $Matches[2].Trim() }
  }
  return @{ Map = $map; Lines = $lines }
}

function Get-WslDrift {
  $cfg = Read-WslConfig
  $drift = @()
  foreach ($k in $Wanted.Keys) {
    $have = $cfg.Map[$k]
    if ($have -ne $Wanted[$k]) { $drift += [pscustomobject]@{ Key = $k; Have = $have; Want = $Wanted[$k]; Kind = 'set' } }
  }
  foreach ($k in $Defaults.Keys) {
    if (-not $cfg.Map.ContainsKey($k)) { $drift += [pscustomobject]@{ Key = $k; Have = $null; Want = $Defaults[$k]; Kind = 'default' } }
  }
  return $drift
}

function Write-WslConfig {
  <# Rewrites .wslconfig with the wanted keys, preserving every other line. A backup is written next to
     it first — this is the user's file, not ours. #>
  $cfg = Read-WslConfig
  if (Test-Path $WslConfig) {
    $backup = "$WslConfig.iris-backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item -LiteralPath $WslConfig -Destination $backup -Force
    Write-Host "[iris] backed up $WslConfig -> $backup" -ForegroundColor DarkGray
  }

  $all = [ordered]@{}
  foreach ($k in $Wanted.Keys)  { $all[$k] = $Wanted[$k] }
  foreach ($k in $Defaults.Keys) { if (-not $cfg.Map.ContainsKey($k)) { $all[$k] = $Defaults[$k] } }

  # start from the existing lines, replacing in place where the key already exists
  $out = New-Object System.Collections.Generic.List[string]
  $seen = @{}
  $section = ''
  foreach ($line in $cfg.Lines) {
    $t = $line.Trim()
    if ($t -match '^\[(.+)\]$') { $section = $Matches[1].Trim().ToLower(); $out.Add($line); continue }
    if ($t -match '^([^=#;]+)=(.*)$') {
      $key = "$section/$($Matches[1].Trim())"
      if ($all.Contains($key)) {
        $out.Add("$($Matches[1].Trim())=$($all[$key])")
        $seen[$key] = $true
        continue
      }
    }
    $out.Add($line)
  }
  # append whatever was not already present, under its section
  foreach ($key in $all.Keys) {
    if ($seen[$key]) { continue }
    $parts = $key.Split('/')
    $sec = $parts[0]; $name = $parts[1]
    $header = "[$sec]"
    $idx = -1
    for ($i = 0; $i -lt $out.Count; $i++) { if ($out[$i].Trim().ToLower() -eq $header.ToLower()) { $idx = $i; break } }
    if ($idx -lt 0) {
      if ($out.Count -gt 0) { $out.Add('') }
      $out.Add($header)
      $out.Add("$name=$($all[$key])")
    } else {
      # insert directly under the section header so it lands in the right block
      $out.Insert($idx + 1, "$name=$($all[$key])")
    }
    $seen[$key] = $true
  }
  # a note at the top, once
  if (-not ($out -join "`n").Contains('Tuned for Iris')) {
    $out.Insert(0, '# Tuned for Iris (see wsl.ps1): THP and background compaction off — this VM segfaulted')
    $out.Insert(1, '# processes in plain Python/stdlib code under allocation pressure with 12+ GB free.')
  }
  Set-Content -LiteralPath $WslConfig -Value $out -Encoding UTF8
  Write-Host "[iris] wrote $WslConfig" -ForegroundColor Green
}

function Show-WslStatus {
  param([switch]$OnlyIfDrift)
  if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) { return }
  $drift = Get-WslDrift
  if ($OnlyIfDrift -and -not $drift) { return }
  if (-not $drift) {
    if (-not $Quiet) { Write-Host "[iris] WSL 2 tuning: OK" -ForegroundColor Green }
    return
  }
  Write-Host ""
  Write-Host "  WSL 2 is not tuned for a memory-heavy container" -ForegroundColor Yellow
  foreach ($d in $drift) {
    $have = $d.Have; if (-not $have) { $have = '(not set)' }
    Write-Host ("    {0,-34} {1}" -f $d.Key, $have) -ForegroundColor DarkGray
    Write-Host ("    {0,-34} -> {1}" -f '', $d.Want) -ForegroundColor Yellow
  }
  Write-Host "    Iris survives what this causes, but the VM should not be causing it." -ForegroundColor DarkGray
  Write-Host "    Fix it with:  .\wsl.ps1 -Apply -Restart     (stops every container)" -ForegroundColor Cyan
  Write-Host ""
}

# ── running directly (not dot-sourced by start.ps1/setup.ps1) ────────────────
if ($MyInvocation.InvocationName -ne '.') {
  if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Host "[iris] wsl.exe not found — nothing to tune (this only applies to Docker Desktop on WSL 2)." -ForegroundColor Yellow
    return
  }
  Write-Host "[iris] .wslconfig: $WslConfig"
  if ($Apply) {
    Write-WslConfig
    if ($Restart) {
      Write-Host "[iris] shutting WSL down so the new settings load (every container stops)..." -ForegroundColor Yellow
      & wsl --shutdown
      Write-Host "[iris] done. Start Docker Desktop again, then run .\start.ps1" -ForegroundColor Green
    } else {
      Write-Host "[iris] settings written. They take effect after:  wsl --shutdown   (stops every container)" -ForegroundColor Cyan
    }
  } else {
    Show-WslStatus
    if (-not (Get-WslDrift)) { Write-Host "[iris] nothing to change." -ForegroundColor Green }
  }
}
