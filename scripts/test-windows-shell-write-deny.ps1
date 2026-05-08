#requires -Version 5.1

<#
.SYNOPSIS
Phase 30 Wave 1 field-smoke harness for nono shell on Windows.

.DESCRIPTION
Drives `nono.exe shell --profile claude-code --allow-cwd` with a one-shot
PowerShell -Command injection that attempts to write to a path OUTSIDE the
claude-code profile grant set. Asserts the write is blocked at OS level
(mandatory-label NO_WRITE_UP enforcement, NOT just hook-level).

Closes Phase 30 acceptance #3 (D-06: OS-level write-deny REQUIRED).
Optionally closes acceptance #4 (D-06 inverse: reads of granted paths still work)
via the -IncludeReadCheck switch (default true).

Exit codes:
  0  -> PASS overall (write blocked AND read worked, if checked)
  1  -> FAIL: write succeeded inside sandbox (D-06 violated)
  2  -> INDETERMINATE: any unexpected shell exit code (treat as field-test inconclusive)

.PARAMETER NonoBinary
Path to the nono.exe binary to test. Defaults to the workspace release build.

.PARAMETER LogDir
Directory for harness logs. Defaults to ci-logs-local/.

.PARAMETER SkipBuild
Skip the cargo build step. Use when iterating on the harness itself.

.PARAMETER SkipLeakedLabelClear
Skip the leaked-label clear prelude. Use when running on a fresh test box where D-09 leaked labels don't exist.

.PARAMETER IncludeReadCheck
Also exercise acceptance #4 (Get-Content on ~/.claude/claude.json). Default true.

.EXAMPLE
pwsh -File scripts/test-windows-shell-write-deny.ps1
#>

param(
    [string]$NonoBinary = "$PSScriptRoot\..\target\x86_64-pc-windows-msvc\release\nono.exe",
    [string]$LogDir = "ci-logs-local",
    [switch]$SkipBuild,
    [switch]$SkipLeakedLabelClear,
    [bool]$IncludeReadCheck = $true
)

# Want non-zero shell exits to bubble up to $LASTEXITCODE for evaluation,
# NOT terminate the harness. Sibling windows-test-harness.ps1 uses 'Stop'
# because it's a cargo-test orchestrator; this harness diverges deliberately.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$logFile = Join-Path $LogDir "test-windows-shell-write-deny-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $stamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ'
    $line = "[$stamp] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

Write-Log "==> Phase 30 Wave 1 write-deny harness starting"
Write-Log "==> Log: $logFile"
Write-Log "==> Nono binary: $NonoBinary"

# ---- Step 1: Build (skippable) ----------------------------------------------
if (-not $SkipBuild) {
    Write-Log "==> Step 1: cargo build -p nono-cli --release --target x86_64-pc-windows-msvc"
    Push-Location (Join-Path $PSScriptRoot '..')
    try {
        cargo build -p nono-cli --release --target x86_64-pc-windows-msvc 2>&1 | Tee-Object -Variable buildOut | Out-Null
        $buildOut | ForEach-Object { Write-Log $_ "BUILD" }
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Build failed with exit $LASTEXITCODE" "ERROR"
            exit 2
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Log "==> Step 1: SKIPPED (-SkipBuild)"
}

if (-not (Test-Path $NonoBinary)) {
    Write-Log "Nono binary not found at $NonoBinary" "ERROR"
    exit 2
}

# ---- Step 2: Leaked-label clear prelude (D-09 hygiene; skippable) ----------
if (-not $SkipLeakedLabelClear) {
    Write-Log "==> Step 2: clear D-09 leaked Low-IL labels (RESEARCH Question 7)"
    $leaked = @(
        "$env:USERPROFILE\.cache\claude",
        "$env:USERPROFILE\.cargo",
        "$env:USERPROFILE\.claude",
        "$env:USERPROFILE\.config\git\ignore",
        "$env:USERPROFILE\.gitconfig",
        "$env:USERPROFILE\.local\bin",
        "$env:USERPROFILE\.rustup",
        "$env:USERPROFILE\AppData\Roaming\nono\profiles",
        "$env:USERPROFILE\Nono"
    )
    foreach ($p in $leaked) {
        if (Test-Path $p) {
            # /setintegritylevel "(NX)Medium" sets default Medium-IL with NX (no-execute) inheritance.
            # Equivalent to icacls /remove:s for a Medium-default object. Errors are non-fatal --
            # most leaked paths will already be Medium when this script runs again.
            $result = icacls $p /setintegritylevel "(NX)Medium" 2>&1
            Write-Log "icacls ${p}: $result" "DEBUG"
        }
    }
} else {
    Write-Log "==> Step 2: SKIPPED (-SkipLeakedLabelClear)"
}

# ---- Step 3: Acceptance #3 -- write to path OUTSIDE grant set ---------------
Write-Log "==> Step 3: Acceptance #3 -- Set-Content to ~/Desktop/nono-acceptance3.txt should fail (broker shell, mandatory-label NO_WRITE_UP)"

$targetFile = Join-Path $env:USERPROFILE "Desktop\nono-acceptance3.txt"
# Pre-clean any leftover file from a prior run.
if (Test-Path $targetFile) { Remove-Item $targetFile -Force -ErrorAction SilentlyContinue }

# One-shot script injected into the sandboxed PowerShell. Sentinel exit codes:
#   42 = PASS (write blocked -> file does NOT exist)
#    1 = FAIL (write succeeded -> file exists)
#
# Phase 31 Wave-0 fix (RESEARCH Open Q3 / 30-WAVE-2-PROCMON.md):
# The previous invocation passed positional [path] [content] to the
# Out-File cmdlet, which is NOT valid PowerShell — Out-File takes
# -FilePath (and accepts pipeline input), not positional path+content.
# Without -FilePath, PowerShell parses the second positional as the
# encoding parameter; the parse error always throws, catch always runs,
# the file is never created, and exit 42 (PASS) ALWAYS fires — masking
# whether the write was OS-denied or never attempted.
#
# Set-Content -Path -Value with -ErrorAction Stop raises an OS-level
# UnauthorizedAccessException through the catch when MIC NO_WRITE_UP
# enforces (PASS path: file absent, exit 42). If MIC is broken,
# Set-Content succeeds, the file exists, exit 1 (FAIL) fires.
$injected = @"
try {
  Set-Content -Path '$targetFile' -Value 'phase 31 write-deny test' -ErrorAction Stop
} catch {
  Write-Host "[harness] Set-Content threw: `$_"
}
if (Test-Path '$targetFile') { exit 1 } else { exit 42 }
"@

Write-Log "==> Launching: $NonoBinary shell --profile claude-code --allow-cwd --shell powershell.exe -- -NoLogo -NoProfile -Command <injected>"
Write-Log "==> Injected script: $injected" "DEBUG"

# Stream stderr to log so 'child connected to pipe' marker (RESEARCH Question 1)
# and 'label guard: skipping apply + revert' warnings (D-09 expected noise) are captured.
& $NonoBinary shell --profile claude-code --allow-cwd `
    --shell powershell.exe `
    -- -NoLogo -NoProfile -Command $injected 2>&1 | Tee-Object -Variable shellOut | Out-Null
$shellExit = $LASTEXITCODE
$shellOut | ForEach-Object { Write-Log $_ "SHELL" }

Write-Log "==> Sandboxed shell exited: $shellExit"

# Post-clean (defense in depth -- the FAIL branch is what would leave the file behind).
if (Test-Path $targetFile) {
    Write-Log "Cleaning leftover $targetFile (would have caused future false-pass)" "WARN"
    Remove-Item $targetFile -Force -ErrorAction SilentlyContinue
}

$writeDenyResult = switch ($shellExit) {
    42 { "PASS" }
    1  { "FAIL" }
    default { "INDETERMINATE" }
}
Write-Log "==> Acceptance #3 result: $writeDenyResult (shell exit $shellExit)"

# ---- Step 4: Acceptance #4 -- read of granted path still works (optional) ---
$readResult = "SKIPPED"
if ($IncludeReadCheck) {
    Write-Log "==> Step 4: Acceptance #4 -- Get-Content ~/.claude/claude.json should succeed"
    $injectedRead = @"
`$claudeJson = Join-Path `$env:USERPROFILE '.claude\claude.json'
if (Test-Path `$claudeJson) {
  try {
    `$line = Get-Content `$claudeJson -TotalCount 1 -ErrorAction Stop
    if (`$line) { exit 42 } else { exit 1 }
  } catch {
    Write-Host "[harness] Get-Content threw: `$_"
    exit 1
  }
} else {
  Write-Host "[harness] ~/.claude/claude.json does not exist; treat as SKIPPED"
  exit 99
}
"@
    & $NonoBinary shell --profile claude-code --allow-cwd `
        --shell powershell.exe `
        -- -NoLogo -NoProfile -Command $injectedRead 2>&1 | Tee-Object -Variable readOut | Out-Null
    $readExit = $LASTEXITCODE
    $readOut | ForEach-Object { Write-Log $_ "READ" }
    Write-Log "==> Read-check shell exited: $readExit"
    $readResult = switch ($readExit) {
        42 { "PASS" }
        1  { "FAIL" }
        99 { "SKIPPED (file missing)" }
        default { "INDETERMINATE" }
    }
    Write-Log "==> Acceptance #4 result: $readResult (shell exit $readExit)"
}

# ---- Summary -----------------------------------------------------------------
Write-Log "================================================================"
Write-Log "Phase 30 Wave 1 write-deny harness summary:"
Write-Log "  Acceptance #3 (write-deny):  $writeDenyResult"
Write-Log "  Acceptance #4 (read-still-works): $readResult"
Write-Log "  Log file: $logFile"
Write-Log "================================================================"

# Overall exit code:
#   0 if write-deny=PASS AND (read=PASS OR read=SKIPPED)
#   1 if write-deny=FAIL OR read=FAIL
#   2 otherwise (INDETERMINATE)
if ($writeDenyResult -eq "PASS" -and ($readResult -eq "PASS" -or $readResult -like "SKIPPED*")) {
    Write-Log "Overall: PASS"
    exit 0
} elseif ($writeDenyResult -eq "FAIL" -or $readResult -eq "FAIL") {
    Write-Log "Overall: FAIL" "ERROR"
    exit 1
} else {
    Write-Log "Overall: INDETERMINATE" "WARN"
    exit 2
}
