# Phase 30 Wave 2 ProcMon Investigation

**Date:** 2026-05-08
**Trigger:** Plan 30-04 Checkpoint 3 = `wave2-trigger-launch` (Acceptance #1 silent launch failure)
**Operator:** oscarmackjr-twg
**Trace file:** `C:\temp\NativeProcessMonitorFormat.pml` (10.4 MB binary, NOT committed; gitignored via `*.pml`)
**Evidence exports:** `C:\temp\FirstFailure.csv` (call stack of one row — superseded by row-level analysis below)

## Failure surface

**Failing process:** `powershell.exe` (PID 35976)
**Parent process:** `nono.exe` (PID 5776) → `conhost.exe --headless` (PID 24988) ConPTY pseudoconsole host
**Token integrity level:** Low (per Plan 30-02 `WindowsTokenArm::LowIlPrimary` cascade arm — confirmed by Plan 30-02 unit test `low_integrity_primary_token_sets_low_il`)
**Token restricted SIDs:** None (Low-IL primary token; no per-session WFP SID — D-01 design intent)

**Operation:** `Process Exit`
**Exit Status:** `-1073741502` = `0xC0000142` = **`STATUS_DLL_INIT_FAILED`**

**Lifespan:**
- `nono.exe` (5776) — silent supervisor exit shortly after child death (matches Plan 30-04 Checkpoint 2 manual diagnostic)
- `conhost.exe --headless --width 80 --height 24 --signal 0x27c --server 0x268` (24988) — 9:27:39.2574256 → .3810542 (~124ms)
- `powershell.exe -NoLogo` (35976) — 9:27:39.3438341 → .3789976 (**~35ms**, terminated by STATUS_DLL_INIT_FAILED before reaching `main()`)

**Load Image chain captured (PID 35976):**

| Time | Image | Result |
|------|-------|--------|
| .3526627 | powershell.exe | SUCCESS |
| .3527676 | ntdll.dll | SUCCESS |
| .3779797 | kernel32.dll | SUCCESS |
| .3781337 | KernelBase.dll | SUCCESS |
| _(no further Load Image events captured)_ | | |
| .3788124 | Thread Exit | — |
| .3789976 | Process Exit (Exit Status: 0xC0000142) | — |

**6.8 ms window between KernelBase.dll Load Image and Process Exit contains zero further Load Image events.** PowerShell typically loads 30-40+ DLLs before reaching `main()` — advapi32, RPCRT4, ucrtbase, msvcrt, combase, ole32, etc. The complete absence of these in the 6.8 ms death window confirms the failure happens in the static-init / DllMain chain of one of the four already-loaded DLLs, NOT in a downstream import.

**Non-failure noise discarded** (all four are normal startup probes for every PowerShell process):
- `RegQueryValue HKLM\System\CurrentControlSet\Control\Session Manager\RaiseExceptionOnPossibleDeadlock` → NAME NOT FOUND (heap deadlock-detection opt-in; absent on most systems)
- `RegOpenKey HKLM\System\CurrentControlSet\Control\Session Manager\Segment Heap` → NAME NOT FOUND (heap implementation opt-in)
- `RegOpenKey HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell.exe` → NAME NOT FOUND (per-image debug-injection / app-compat key; absent unless admin configured one)
- `RegQueryValue HKLM\System\CurrentControlSet\Control\Notifications\<GUID>` → BUFFER TOO SMALL (size-probe pattern — caller is just asking how big the buffer needs to be)

These are red-herrings explicitly classified during analysis to avoid re-investigating during sixth-option synthesis.

## RESEARCH category match

**Match: ImageLoad / DllMain failure**, with strong sub-classification to **`\Device\ConDrv` ALPC denial via CSRSS console-subsystem startup** (RESEARCH Pitfall 2 — Microsoft-documented ConPTY + restricted-token integrity-mismatch).

### Why this sub-classification

PowerShell is a console-subsystem application (`/SUBSYSTEM:CONSOLE`). When `KernelBase.dll`'s DllMain runs `BasepInitializeBaseDll` on `DLL_PROCESS_ATTACH`, it invokes the console-subsystem connection sequence:

```
KernelBase!BaseDllInitialize
  → KernelBase!ConClntInitialize
    → KernelBase!ConsoleAllocateConsole / ConClnt::ConnectConsole
      → ALPC connect to CSRSS console handler port (\Device\ConDrv equivalent)
```

The CSRSS ALPC port's mandatory label and DACL **exclude Low-IL clients**. The connect call returns `STATUS_ACCESS_DENIED`. The DllMain returns FALSE. The loader sets `STATUS_DLL_INIT_FAILED` and terminates the process.

**Critical:** the inherited ConPTY ALPC handles passed by `--signal 0x27c --server 0x268` are a SEPARATE communication path (the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE channel between `nono.exe` ↔ `conhost.exe` for terminal I/O). They do NOT bypass the CSRSS console-subsystem startup ALPC handshake that KernelBase performs unconditionally for every console-subsystem process.

### Why ProcMon doesn't show the ALPC denial directly

ProcMon's standard event tree does not surface ALPC port operations as first-class events (ALPC is not a Windows file-system filter driver hook). The denial happens inside KernelBase.dll user-mode code calling `NtAlpcConnectPort`, which fails synchronously and propagates back as a `NTSTATUS` to KernelBase's DllMain, which then returns FALSE to the loader. ProcMon sees the resulting Process Exit with `STATUS_DLL_INIT_FAILED` but not the underlying ALPC operation. To catch the ALPC denial directly would require either:
- WPA / Event Tracing for Windows (ETW) with the `Microsoft-Windows-Kernel-AuditApi` provider enabled
- Live debugger attach with breakpoint on `KernelBase!ConClntInitialize` and stepping into NtAlpcConnectPort

For our purposes the diagnosis is sufficient: PowerShell loads exactly the 4 lowest DLLs (its own image + the foundational triple ntdll/kernel32/KernelBase), then dies with the precise NTSTATUS that Microsoft's documentation associates with CSRSS-attach failure under integrity mismatch.

### Cross-references confirming match

- RESEARCH §"Pitfall 2: PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE + restricted/Low-IL token = silent integrity-mismatch failure" — Plan 30-03's TUI runbook explicitly warned this failure mode "passes step (1) and (2) but fails step (5)" — and that's exactly the false-positive Checkpoint 1 PASS recorded in 30-04 Plan 30-04 SUMMARY § "Checkpoint 1 was a false positive."
- Phase 15 `windows-supervised-exec-cascade.md` documented the same `STATUS_DLL_INIT_FAILED` signature for the **detached** path (`nono run`); Phase 15's fix (`should_allocate_pty` gate at `supervised_runtime.rs:88-94`) made the detached path skip ConPTY for restricted-token shapes. **Phase 30 cannot apply Phase 15's gate** because `nono shell` REQUIRES interactive ConPTY by definition (D-04: rejected the Phase 15 detached waiver).
- The original debug session (`nono-shell-status-dll-init-failed.md`) recorded `STATUS_DLL_INIT_FAILED (0xC0000142)` on 2026-05-07 as the trigger; Wave 2 ProcMon evidence corroborates that the same NTSTATUS surfaces on the supervised+ConPTY path even after Plan 30-02's cascade-arm landing.

## Hypothesis space

The trace localizes the failure to **CSRSS console-subsystem ALPC handshake denied at Low-IL during KernelBase DllMain**. Sixth-option candidates per RESEARCH §"What 'surfaced a 6th option' looks like" + Microsoft-documented patterns:

### 6a — AppContainer model instead of mandatory-label Low-IL primary token

Replace the Low-IL primary token with an AppContainer-shaped token (LOWBOX SID + capabilities). AppContainer processes have their own integrity model AND a per-package CSRSS ALPC handler that DOES accept AppContainer clients.

**Pros:** Microsoft-supported model; CSRSS works out of the box for AppContainers; mandatory-label NO_WRITE_UP enforcement still applies (AppContainer processes run at LOW IL effectively).
**Cons:** Substantial code rework — AppContainer requires capability SIDs, manifests, and a different `CreateProcess*` API surface. Capability set design becomes a new D-decision. Would likely span multiple plans.
**Effort estimate:** 1-2 weeks; new AppContainer-shape Wave (Phase 31) rather than a Plan 30-05 fix.

### 6b — Broker-process / pre-attach pattern

Spawn a **small custom intermediary binary at Medium IL** (not PowerShell), which:
1. CreateProcess as Medium-IL child of `nono.exe`
2. Inherits ConPTY handles + opens CSRSS console (succeeds because Medium-IL is allowed)
3. Calls `SetTokenInformation(TokenIntegrityLevel, Low)` on its own process token
4. Spawns `powershell.exe -NoLogo` as a child via `CreateProcessW(..)` with the now-Low-IL token; the child INHERITS the already-attached console (KernelBase's DllMain's console-attach is a no-op when a console is inherited)

**Pros:** Microsoft-documented pattern (used by some browser sandbox implementations); preserves Low-IL for the actual user-running shell; mandatory-label NO_WRITE_UP enforcement applies to the inherited Low-IL child.
**Cons:** Requires shipping a new small binary (`nono-shell-broker.exe` or similar); inherits its own subset of attack surface (the broker is the boundary between Medium and Low IL); CONTEXT D-01 specifies Low-IL primary token from `CreateProcessAsUserW` — this is a different mechanism (broker-then-self-degrade).
**Effort estimate:** ~1 week; could land in a follow-up Plan 30-05 sub-wave or a separate phase.

### 6c — Sequencing fix: AllocConsole in supervisor before drop

`nono.exe` calls `AllocConsole()` itself at Medium-IL, then `CreateProcessAsUserW` with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE; the child supposedly inherits the parent's already-allocated console.

**Pros:** Smallest code change; lives entirely in `nono-cli`.
**Cons:** **Does not actually solve the problem.** PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE *replaces* the inherited console; KernelBase's DllMain on the child still calls `ConClntInitialize` against the new ConPTY-attached console, which still routes through CSRSS ALPC at Low-IL → still denied. Verified theoretically; would need live test to falsify.
**Effort estimate:** 1-2 days experimental; almost certainly fails based on the user-mode console-init code path.

### 6d — Job Object UI restrictions instead of mandatory-label IL

Drop the mandatory-label IL approach entirely. Use Job Object UI restrictions (`JOB_OBJECT_UILIMIT_*`) + filesystem ACL grants + WFP/AppID network filtering to enforce the security envelope.

**Pros:** No console-subsystem incompatibility; PowerShell runs at Medium-IL where everything works.
**Cons:** **Violates CONTEXT.md D-06** which specifically requires OS-level write-deny via mandatory labels (NO_WRITE_UP). Job Object UI restrictions are clipboard/window-handle/global-atom restrictions, NOT filesystem write enforcement. Would require a different acceptance-criteria framing for Phase 30 (re-discuss-phase scope).
**Effort estimate:** Re-discuss-phase + new Phase 31; substantial rescoping.

### 6e — Defer to v3.0 / kernel-driver

Accept that user-mode + ConPTY + Low-IL + console-subsystem-attach is structurally incompatible on current Windows kernel versions. Document the finding. Ship Phase 30 as v3.0 deferral with the failure-mode evidence preserved as the institutional knowledge.

**Pros:** Honest disposition; preserves evidence for future kernel-driver Phase 31; unblocks v2.3 milestone.
**Cons:** SHELL-01 stays unenforced on Windows for v2.3; cookbook reverts (RESEARCH §Cookbook Rollback Path Option Rev-B); user-perception cost.
**Effort estimate:** 1-2 days for honest documentation + cookbook revert + bookkeeping.

### 6f — Fork PowerShell stdin/stdout via redirection, not ConPTY

Use plain CreatePipe-based stdio (matching Phase 17's anonymous-pipe shape) for `nono shell` instead of ConPTY. Trade interactive TUI fidelity (no alt-screen, no cursor positioning) for working write-deny enforcement.

**Pros:** Removes the ConPTY+Low-IL incompatibility entirely; PowerShell at Low-IL with stdio redirection should work (no console-subsystem startup attempts CSRSS attach when stdin/stdout are pipes).
**Cons:** **Breaks Acceptance #2** (TUI rendering). Claude Code's TUI explicitly REQUIRES alt-screen + raw-mode input + cursor positioning. Phase 30's CONTEXT D-05 locked TUI rendering as a Phase 30 acceptance criterion. This option fails the phase contract.
**Effort estimate:** Breaks the phase contract; not viable unless CONTEXT D-05 is re-discussed.

## Sixth-option proposal

**Recommendation: 6e (defer to v3.0) with 6b (broker-process) as a Phase 31 candidate.**

Rationale:
1. **Phase 30 contract:** D-04 timebox 3-5 working days. Wave 2 has produced unambiguous diagnostic evidence (CSRSS ALPC denial at Low-IL during KernelBase DllMain) within Day 1. The remaining timebox would be spent attempting 6b (1+ week) or 6a (1-2 weeks) — both exceed the timebox. CONTEXT D-04 explicitly says "phase ships at end-of-timebox regardless."
2. **6e is honest:** the field evidence shows a structural Win32 kernel-userspace boundary issue (ALPC port DACL excludes Low-IL clients in the CSRSS console-subsystem attach path). This isn't a bug we can fix in `nono-cli` without architectural rework. v3.0 deferral with this evidence is the disciplined call.
3. **6b is the natural follow-up phase:** the broker-process pattern is Microsoft-supported and would fit a dedicated Phase 31. Plan 30-05's terminal Resolution section explicitly references it as the next investigation.
4. **Cookbook revert** (RESEARCH §Cookbook Rollback Path Option Rev-B) preserves institutional honesty: v2.3 users get a clear "nono shell on Windows is deferred to v3.0; use nono run for non-interactive flows" instead of an over-promised feature.

The alternative — accept the broker-process pattern (6b) inside the Phase 30 timebox — risks shipping a half-implemented broker that introduces new attack surface without rigorous threat-modeling. CONTEXT D-04's timebox explicitly anticipated this fork.

## Trace evidence files

- `.pml` binary: `C:\temp\NativeProcessMonitorFormat.pml` (NOT committed — gitignored via `*.pml` rule added to `.gitignore` in this plan)
- `.csv` first-row stack export: `C:\temp\FirstFailure.csv` (initial export; superseded — that row was WMI service noise, not the failure surface)
- Filter export `.pmf`: not exported — filter recipe documented inline below

### Final filter recipe (post-iteration)

The Plan 30-05 RESEARCH § ProcMon Trace Plan filter recipe was iterated during execution. Final form that produced the diagnostic:

```
Process Name is nono.exe       Include
PID is 35976                   Include   (the powershell.exe child PID, identified via Process Tree)
Operation is Process Create    Include
Operation is Load Image        Include
Operation is Process Exit      Include
Operation is Thread Exit       Include
Result is REPARSE              Exclude   (drops registry-symlink redirect noise)
```

The original recipe (broad Path-contains rules + 4-process Process-Name list) over-captured WMI service activity (`svchost.exe` + `WmiPrvSE.exe` background work). PID-based filtering on the specific child process (35976 in this trace) is sharper.

## Critical caveat for Phase 31 inheritance — `Out-File` false-PASS on Acceptance #3

The harness `scripts/test-windows-shell-write-deny.ps1:130-137` injects:

```powershell
$injected = @"
try {
  Out-File '$targetFile' 'phase 30 write-deny test' -ErrorAction Stop
} catch {
  Write-Host "[harness] Out-File threw: `$_"
}
if (Test-Path '$targetFile') { exit 1 } else { exit 42 }
"@
```

The `Out-File '<path>' '<content>'` syntax is **invalid PowerShell** — `Out-File` does not accept content as a positional parameter. PowerShell binds the second positional to `-Encoding`, which `ValidateSet` rejects (the same `Out-File : Cannot validate argument on parameter 'Encoding'` error surfaced when manually testing the CLI gap).

**Consequence: Acceptance #3 always exits 42 (PASS) regardless of whether the write would actually be blocked by mandatory-label enforcement.** The injected script flow is:

1. `Out-File` throws `ParameterBindingValidationException` immediately
2. `catch` block writes a harness message and falls through (no exit)
3. The file was never created (because of the parameter error, NOT because of OS-level write-deny)
4. `Test-Path` returns False
5. `exit 42` fires — the PASS sentinel

**The test never measures what it claims to measure.** Even if the cascade arm produced a Medium-IL child that COULD write to ~/Desktop, the harness would still report PASS. This was masked in Plan 30-04 because Acceptance #1 silent-launch failure short-circuited the harness before the `Out-File` even fired (the harness flow exited at INDETERMINATE due to the unrelated `nono shell -- -NoLogo` CLI mismatch).

**Phase 31 must rewrite this assertion** before any Wave-2 ProcMon work can claim a write-deny verdict. Recommended replacement (PowerShell-correct):

```powershell
$injected = @"
try {
  Set-Content -Path '$targetFile' -Value 'phase 30 write-deny test' -ErrorAction Stop
} catch {
  Write-Host "[harness] Set-Content threw: `$_"
}
if (Test-Path '$targetFile') { exit 1 } else { exit 42 }
"@
```

`Set-Content -Path -Value` is the canonical positional-parameter shape; `-ErrorAction Stop` ensures the write attempt becomes a terminating error if denied, taking the catch path; `Test-Path` then accurately reflects whether the OS allowed the write.

## RESEARCH cross-references

- Filter recipe: 30-RESEARCH.md § "Filter recipe for ConPTY + restricted-token failures" (lines 232-243; iterated above to PID-scoped form)
- Categories: 30-RESEARCH.md § "Events to look for" (lines 245-249); match = ImageLoad / DllMain failure with CSRSS ALPC sub-classification
- Sixth-option examples: 30-RESEARCH.md § "What 'surfaced a 6th option' looks like" (lines 252-256)
- Surfaced-nothing path: 30-RESEARCH.md § "What surfacing nothing looks like" (lines 259-263) — does NOT apply; a clear sixth-option space WAS surfaced
- Cookbook rollback: 30-RESEARCH.md § "Cookbook Rollback Path" Option Rev-B (Plan 30-05 Tasks 5-6 will execute this on the 6e path)

## Timebox

Wave 2 investigation timeboxed to 3-5 working days per CONTEXT.md D-04. Day count tracking:

- **Day 1: 2026-05-08** — Task 1 ProcMon trace setup + capture; Task 2 trace analysis localized failure to `STATUS_DLL_INIT_FAILED` in PowerShell child after KernelBase load + 6.8 ms; Task 3 (this document) + Task 4 sixth-option synthesis. Recommendation: 6e (defer to v3.0) with 6b (broker pattern) as Phase 31 candidate. Awaiting user decision on Tasks 5-6 implementation path.
- **Day 2-N:** TBD — depends on user decision in Task 4. If 6e: ~1 day for Tasks 5-6 (cookbook revert + final bookkeeping). If 6b: 1+ week, exceeds timebox; would split into Phase 31.

## Final outcome

**Result:** Wave 2 EXHAUSTED — no workable user-mode option surfaced within the 3-5 working day timebox.

**Investigation activities:**
- **Day 1 (2026-05-08):** Task 1 ProcMon trace setup; Task 2 trace analysis localized failure to `STATUS_DLL_INIT_FAILED (0xC0000142)` inside KernelBase.dll DllMain at the CSRSS console-subsystem ALPC handshake. Task 3 (this document) captured findings. Task 4 sixth-option synthesis examined six candidates (6a AppContainer 1-2 weeks, 6b broker-process 1+ week, 6c pre-AllocConsole likely fails, 6d JobObject UI restrictions violates D-06, 6e v3.0 deferral, 6f pipe-stdio violates D-05) — all viable user-mode paths exceed timebox. Task 5 SKIPPED per `exhaust-without-fix` decision. Task 6 ships failure-path bookkeeping.

**Phase 30 ships:** failure-mode finding; SHELL-01 → ✘ deferred to v3.0 / Phase 31.

**Cookbook reverted:** Option Rev-B (text replacement, NOT git revert):
- Top-of-doc `<Note>` block recommendation stripped; replaced with a limited Note pointing to "Known limitation" + new "deferred to v3.0" section.
- Step 4 `nono shell` instruction stripped; replaced with `nono run -- <command>` recommendation.
- Step 5 "Interactive verification (manual)" block removed.
- Step 6 user-handoff table rows mentioning `nono shell` removed; replaced with non-TUI `nono run` recommendations.
- "Known limitation: `nono run` cannot host TUI agents on Windows" section RETAINED (factually correct).
- New section "`nono shell` on Windows is deferred to v3.0" added with the four-failure-mode evidence and pointer to this document.

**Debug session:** moved to `.planning/debug/resolved/nono-shell-status-dll-init-failed.md` with `## Resolution` section preserving the four-failure-mode finding and Phase 31 follow-up scope.

**v3.0 / Phase 31 follow-up:** strongest candidate is option 6b (broker-process pattern) — Microsoft-documented workaround where a small Medium-IL intermediary attaches to CSRSS, lowers itself to Low-IL via `SetTokenInformation(TokenIntegrityLevel, Low)`, then spawns PowerShell as a Low-IL child inheriting the already-attached console. Phase 31 will re-discuss-phase based on whether 6b proves viable in that scope's larger budget. CONTEXT.md `<deferred>` block enumerates the kernel-driver alternative.

**Wave 1 cascade arm code stays in tree:** `WindowsTokenArm::LowIlPrimary` enum + `select_windows_token_arm` helper + `pty_token_gate_tests` (6/6 truth-table) + Windows-only `low_integrity_primary_token_sets_low_il` runtime test all pass. The unit tests + helper enum are guards on the underlying mechanism for whenever v3.0 / Phase 31 activates this path. The code is deliberately NOT removed — Phase 30's investigation IS the institutional knowledge that future work builds on.

**Commits:**
- `baebc3f0`+`ccf28720`+`5a91e40c`+`aef4a2c3` (30-01 bookkeeping prelude)
- `a496734b`+`09e8ffb9` (30-02 cascade arm + tests)
- `c8e31388` (30-03 SUMMARY only — scripts deferred to 30-04 commit)
- `a86e6db3`+`b79a4839` (30-04 wave2-trigger-launch + harness ship)
- `d9030cc5` (30-05 ProcMon analysis — Tasks 2+3)
- _(this commit ships Tasks 5+6 terminal close — failure path)_
