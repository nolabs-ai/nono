# Phase 31 Wave (broker dispatch) — Field Smoke Runbook

**Run by:** Plan 31-05 on the Windows test box (Win 11 26200 or any Windows 10 17763+ with PowerShell 5.1+ + Claude Code installed).
**Outcome drives:** Plan 31-06's cookbook update + PROJECT.md SHELL-01 outcome flip + STATE.md key-decisions block + ROADMAP.md Phase 31 status update.
**Failure trigger (CONTEXT D-13):** If Acceptance #1 or #2 fails, allocate ≤2 days ProcMon; if unresolved by day 5 of phase work, halt phase, write paused finding, replan per D-13 escalation tree.

***

## Pre-test environment hygiene

1. **Close all existing nono sessions on the test box.** `taskkill /f /im nono.exe` if any orphaned supervisors are running. The capability-pipe DACL is per-supervisor; stale supervisors hold pipe handles that can confuse the new broker launch.

2. **Confirm Plan 31-03 binary is on the working tree.** Wave 2 cascade-arm must be present:
   ```
   grep -c "WindowsTokenArm::BrokerLaunch" crates/nono-cli/src/exec_strategy_windows/launch.rs
   ```
   Expected: >= 4 (variant + selector + match arm + at least one test).

3. **Build a fresh release binary and broker:**
   ```
   cargo build -p nono-cli --release --target x86_64-pc-windows-msvc
   cargo build -p nono-shell-broker --release --target x86_64-pc-windows-msvc
   ```
   Expected: both exit 0; binaries at `target\x86_64-pc-windows-msvc\release\nono.exe` and `target\x86_64-pc-windows-msvc\release\nono-shell-broker.exe`. Both must be SIBLINGS in the same dir (`current_exe().parent()` lands here per D-07).

4. **Verify Claude Code is installed:**
   ```
   claude --version
   ```
   Acceptance #2 cannot be exercised without a working `claude` CLI.

5. **(Optional) Clear D-09 leaked Low-IL labels** (carry-forward from Phase 30 D-11 — leaks are EXPECTED, not a failure indicator):
   ```powershell
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
   foreach ($p in $leaked) { icacls $p /setintegritylevel "(NX)Medium" 2>$null }
   ```
   Phase 30 D-09 / Phase 31 D-11 deferred to v2.4 (`nono-labels-guard-leak` quick task).

***

## Acceptance criteria → harness commands

| Acceptance | Decision | Harness | Expected | Gate |
|------------|----------|---------|----------|------|
| Acceptance #1: shell launches without 0xC0000142 | D-01/D-15 | Manual: `.\nono.exe shell --profile claude-code --allow-cwd` | Shell prompt appears; no STATUS_DLL_INIT_FAILED; no silent exit; `whoami /groups | findstr "Mandatory Label"` shows `Low Mandatory Level S-1-16-4096` | Operator visual + Get-Process check |
| Acceptance #2: claude TUI renders | D-05 | `pwsh -File scripts\test-windows-shell-tui.ps1` | All checklist steps PASS | Script exit 0 |
| Acceptance #3: write outside grant set is OS-denied | D-06 | `pwsh -File scripts\test-windows-shell-write-deny.ps1` | Inner shell exit 42 (sentinel — file does NOT exist; Set-Content raised UnauthorizedAccessException) | Script exit 0 with `Acceptance #3 result: PASS` |
| Acceptance #4: read of granted path works | D-06 inverse | Same harness as #3 (default `-IncludeReadCheck`) | Inner shell exit 42 on Get-Content of `~/.claude\claude.json` | Script exit 0 with `Acceptance #4 result: PASS` or `SKIPPED (file missing)` |
| Acceptance #7: harness Set-Content fix verified | New (Plan 31-01) | grep + manual injection check | `grep -c "Set-Content -Path '" scripts\test-windows-shell-write-deny.ps1` returns >= 1 AND no `Out-File '` (unparseable shape) | Static check; runtime: Acceptance #3 distinguishes OS-deny from parse-error |

***

## Smoke-gate evidence table (mirrors Phase 30 shape)

Fill in the rightmost column during Wave field execution.

| Token / Spawn arm | PTY | Detached | Outcome (Phase 31 expected) | Outcome (observed) |
|---|---|---|---|---|
| BrokerLaunch (broker→Low-IL child via current_exe().parent() resolution) | Some (ConPTY) | No | Launches; broker spawns Low-IL child via CreateProcessAsUserW(dwCreationFlags=0); mandatory-label NO_WRITE_UP enforces write-deny outside grant set | _(operator fills)_ |
| Null token | Some (ConPTY) | Yes | Phase 15 detached path; launches; no write enforcement | (unchanged) |
| Null token | None | Yes | Phase 15 detached path | (unchanged) |
| WRITE_RESTRICTED + session-SID | None | No | Existing `nono run` non-PTY supervised; unchanged from HEAD | _(verify no regression)_ |

***

## Expected log markers

These messages indicate **healthy** Phase 31 broker behavior. Their absence is a regression signal.

- **`broker spawned Low-IL child`** (or equivalent — `tracing::info!` from broker's stderr) — broker successfully self-degraded and spawned the child.
- **`child connected to pipe`** (capability-pipe SDDL admitted the broker, NOT the Low-IL grandchild; broker is Medium-IL so the existing Phase 11 SDDL already admits it without changes per RESEARCH §3c).
- **`label guard: skipping apply + revert`** — D-09 / D-11 leaked-label warnings on the 9 known paths. EXPECTED noise; not a failure indicator.

These messages indicate **failure** modes (D-13 escalation triggers):

- **`STATUS_DLL_INIT_FAILED` / `0xC0000142`** — broker dispatch failed; CSRSS attach denied at Low-IL despite broker pattern. **A1 invalidated** — escalate to Plan 31-06 with full ProcMon trace; SHELL-01 → v3.0 deferral.
- **`Broker binary not found: ...`** (`NonoError::BrokerNotFound`) — Plan 31-04 deployment failed; broker artifact missing. Re-run Plan 31-04 OR copy broker.exe manually next to nono.exe.
- **`Failed to connect to Windows supervisor pipe` / `ERROR_FILE_NOT_FOUND`** — capability-pipe rendezvous file accessibility issue (Phase 30 RESEARCH Pitfall 4). Document and proceed; not a Phase 31 failure indicator unless persistent.
- **`Access is denied` from `Get-Content` on a granted path** — Acceptance #4 violated; Low-IL token may be silently mis-applied; check `low_integrity_primary_token_sets_low_il` test result.
- **Silent input drop / broken echo in claude TUI** — RESEARCH Pitfall 2 / A2 sub-shape. Step 5 of TUI checklist FAILS; trigger D-13 timebox.

***

## Decision matrix (drives Plan 31-06)

| Acceptance #1 | #2 | #3 | #4 | #7 | Plan 31-06 path |
|---|---|---|---|---|---|
| PASS | PASS | PASS | PASS | PASS | **Success path:** SHELL-01 → ✔ validated v2.3 Phase 31; cookbook security-envelope paragraph; debug session → resolved/. |
| PASS | PASS | PASS | SKIPPED (file missing) | PASS | Same as success path; document missing `~/.claude\claude.json` in SUMMARY (test box may not have it). |
| PASS | PASS | FAIL | * | PASS | **D-13 escalation:** OS-level write-deny did not fire even with corrected harness. ProcMon trace MIC enforcement on `~/Desktop`; verify Low-IL token is actually applied to the grandchild. ≤2 days timebox. |
| PASS | FAIL | * | * | * | **D-13 escalation:** A2 sub-shape — Low-IL grandchild survives DllMain but TUI is broken. ProcMon trace `\Device\ConDrv` ALPC interactions in the grandchild. ≤2 days timebox. |
| FAIL | * | * | * | * | **D-13 escalation (terminal):** A1 invalidated — broker pattern doesn't bypass CSRSS denial at Low-IL on this Windows version. ProcMon trace ImageLoad chain in conhost.exe + grandchild to identify failed DllMain. If unresolved by day 5: SHELL-01 → ✘ v3.0 deferral per D-16; cookbook reverts to Phase 30 final-state language. |

If ProcMon ALSO fails to surface a workable option (3-5 working days exhausted): SHELL-01 → deferred to v3.0; cookbook revert per CONTEXT D-16.

***

## Operator log

| Date | Acceptance #1 | #2 | #3 | #4 | #7 | Notes |
|------|--------------|----|----|----|----|----|
| _(operator fills via /gsd-execute-phase 31 checkpoint:human-verify)_ | | | | | | |

***

## References

- Plan 31-01 (foundation: D-06 lift + D-07 BrokerNotFound + Wave 0 harness fix): `.planning/phases/31-broker-process-architecture-shell-01/31-01-PLAN.md`
- Plan 31-02 (broker crate + main.rs production hardening): `.planning/phases/31-broker-process-architecture-shell-01/31-02-PLAN.md`
- Plan 31-03 (BrokerLaunch cascade arm + HANDLE_LIST + Job Object): `.planning/phases/31-broker-process-architecture-shell-01/31-03-PLAN.md`
- Plan 31-04 (release pipeline + signing + MSI): `.planning/phases/31-broker-process-architecture-shell-01/31-04-PLAN.md`
- Plan 31-05 (this — field smoke + Job Object test lift): `.planning/phases/31-broker-process-architecture-shell-01/31-05-PLAN.md`
- Plan 31-06 (cookbook + bookkeeping flip): `.planning/phases/31-broker-process-architecture-shell-01/31-06-PLAN.md`
- Phase 30 smoke-gate template: `.planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md`
- Phase 30 ProcMon evidence (failure-mode reference): `.planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md`
- Broker PoC field validation (2026-05-08): `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/SUMMARY.md`
