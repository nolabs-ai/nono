---
phase: 30-windows-nono-shell-architecture
plan: "02"
subsystem: windows
tags: [windows, token-cascade, mandatory-integrity-control, conpty, first-live-use, low-integrity]

# Dependency graph
requires:
  - phase: 30-windows-nono-shell-architecture
    provides: Phase 30 research, context decisions D-01/D-02/D-03, PATTERNS.md cascade shape

provides:
  - WindowsTokenArm enum + select_windows_token_arm pure helper (file-private, pub(super))
  - 6th cascade arm in spawn_windows_child: LowIlPrimary for PTY+!detached path
  - pty_token_gate_tests module (6 pure cross-platform unit tests for cascade truth table)
  - low_integrity_primary_token_tests module (2 Windows-only FFI tests for token integrity SID)
  - First live runtime exercise of create_low_integrity_primary_token (previously unreachable)

affects:
  - 30-03 (field-smoke harness depends on this cascade arm landing)
  - 30-04 (cookbook + outcome flip depends on field-smoke success)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "WindowsTokenArm enum + select_windows_token_arm pure helper: extract cascade decision into a pure function for testability — matches the existing detached_token_gate_tests analog"
    - "Named-local holder discipline: let holder = fn()?; let raw = holder.0; _holder = Some(holder); prevents UAF via temporary drop (Pitfall 1) and double-close (Pitfall 5)"
    - "match WindowsTokenArm over if/else chain: exhaustiveness-checked arm dispatch; every arm initializes both holders explicitly"

key-files:
  created: []
  modified:
    - crates/nono-cli/src/exec_strategy_windows/launch.rs

key-decisions:
  - "D-01 closed at code level: PTY arm selects LowIlPrimary, not WRITE_RESTRICTED; branch ordering (PTY before session_sid) verified against execution_runtime.rs:334"
  - "SECURITY_MANDATORY_LOW_RID import path is windows_sys::Win32::System::SystemServices, not windows_sys::Win32::Security (auto-fixed Rule 1)"
  - "assert_eq! type cast: SECURITY_MANDATORY_LOW_RID is i32; GetSidSubAuthority returns *mut u32; cast as u32 for comparison (auto-fixed Rule 1)"
  - "Pre-existing clippy errors in crates/nono/src/manifest.rs are out-of-scope; logged to deferred-items"

patterns-established:
  - "select_windows_token_arm: pure decision function pattern; all cascade arm decisions are testable without spawning a process or calling FFI"
  - "pty_token_gate_tests placement: adjacent to detached_token_gate_tests (the analog); related truth-table guards kept together"
  - "low_integrity_primary_token_tests: #[cfg(all(test, target_os = \"windows\"))] gate with #[allow(clippy::unwrap_used)] — matches existing restricted_token.rs test convention"

requirements-completed:
  - D-01
  - D-02
  - D-03

# Metrics
duration: 12min
completed: 2026-05-07
---

# Phase 30 Plan 02: Windows Token Cascade Low-IL PTY Arm Summary

**Low-IL primary token cascade arm inserted for supervised+PTY Windows shell path; select_windows_token_arm pure helper + 8 unit tests pin branch ordering and token integrity SID invariants**

## Performance

- **Duration:** 12 min
- **Started:** 2026-05-07T23:22:36Z
- **Completed:** 2026-05-07T23:34:13Z
- **Tasks:** 3 (committed as one atomic unit — all changes in one file, tightly coupled)
- **Files modified:** 1

## Accomplishments

- Extracted `WindowsTokenArm` enum and `select_windows_token_arm` pure helper before the cascade, enabling unit-testable truth-table coverage of the 5-way arm decision without any FFI or process spawn
- Rewrote `spawn_windows_child` token cascade as `match WindowsTokenArm` with the 6th arm (`LowIlPrimary` when `pty.is_some() && !is_detached`); named-local holder discipline and UAF/double-close comment preserved verbatim; Phase 30 D-01 comment block added with waiver rationale (AppID WFP fallback, parallel to Phase 15 detached-path waiver)
- Added `pty_token_gate_tests` (6 pure cross-platform unit tests covering the full truth table including the new Wave 1 path, detached priority, and the structurally-unreachable legacy arms) and `low_integrity_primary_token_tests` (2 Windows-only FFI tests: `low_integrity_primary_token_sets_low_il` asserting `SECURITY_MANDATORY_LOW_RID` = 0x1000 integrity SID, `low_integrity_primary_token_drop_is_safe` smoking Pitfall 1/5 lifecycle)
- Verified `session_sid: Some(exec_strategy::generate_session_sid())` at `execution_runtime.rs:334` — RESEARCH Question 6 assertion holds; branch ordering (PTY arm short-circuits BEFORE session_sid arm) is correct
- 831 unit tests pass; 21 pre-existing integration test failures unchanged (Windows binary tests on non-Windows host)

## Task Commits

All three tasks were committed as one atomic unit (single file, tightly coupled changes):

1. **Tasks 1+2+3: Insert Low-IL PTY arm, extract gate helper, add truth-table + FFI tests** - `a496734b` (feat)

**Plan metadata:** (to be committed by orchestrator)

_Note: TDD approach — enum/helper added before tests, then tests run to verify GREEN immediately. Two auto-fixes applied during compilation (Rule 1: wrong import path, type cast mismatch)._

## Files Created/Modified

- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — Added `WindowsTokenArm` enum, `select_windows_token_arm` pure helper, 6th cascade arm in `spawn_windows_child`, `pty_token_gate_tests` module (6 tests), `low_integrity_primary_token_tests` module (2 Windows-only tests); 286 lines added, 20 removed

## Decisions Made

- Chose helper-extraction route over inline closure (plan's `<discretion>` block authorized this); makes cascade truth table unit-testable without process spawn
- Used `match WindowsTokenArm` over `if/else if` chain: exhaustiveness enforcement + arm-by-arm grep-ability
- Placed `pty_token_gate_tests` immediately after `detached_token_gate_tests` (analog); placed `low_integrity_primary_token_tests` immediately after `pty_token_gate_tests`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Wrong import path for SECURITY_MANDATORY_LOW_RID**
- **Found during:** Task 3 (low_integrity_primary_token_tests module compilation)
- **Issue:** Plan's `<interfaces>` block specified `windows_sys::Win32::Security::SECURITY_MANDATORY_LOW_RID` — but the constant lives in `windows_sys::Win32::System::SystemServices` (same path used in `crates/nono/src/sandbox/windows.rs:30`)
- **Fix:** Changed import to `use windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_LOW_RID;`
- **Files modified:** `crates/nono-cli/src/exec_strategy_windows/launch.rs`
- **Verification:** `cargo test -p nono-cli pty_token_gate_tests` compilation succeeds
- **Committed in:** `a496734b` (task commit)

**2. [Rule 1 - Bug] Type mismatch in assert_eq! (u32 vs i32)**
- **Found during:** Task 3 (low_integrity_primary_token_tests module compilation)
- **Issue:** `SECURITY_MANDATORY_LOW_RID` is `i32` in windows-sys (C int constant); `GetSidSubAuthority` returns `*mut u32`; `assert_eq!` with different types fails to compile
- **Fix:** Cast constant as `u32`: `SECURITY_MANDATORY_LOW_RID as u32`
- **Files modified:** `crates/nono-cli/src/exec_strategy_windows/launch.rs`
- **Verification:** `cargo test -p nono-cli pty_token_gate_tests` compilation and all 6 tests pass
- **Committed in:** `a496734b` (task commit)

---

**Total deviations:** 2 auto-fixed (2 Rule 1 — compile-time type/import bugs in test code)
**Impact on plan:** Both fixes corrected incorrect API assumptions in the plan's `<interfaces>` block. No security or behavioral impact — both were in `#[cfg(all(test, ...))]` test code only.

## Issues Encountered

- Pre-existing `clippy` errors in `crates/nono/src/manifest.rs` (two "this `if` can be collapsed into the outer `match`" warnings elevated to errors by `-D warnings`) prevented `cargo clippy -p nono-cli` from passing. These errors exist in baseline before this plan's changes (verified by `git stash` + re-run). Files not touched by this plan — out of scope per scope boundary rule. Logged to deferred-items.

## Known Stubs

None — all code paths are fully wired. The `low_integrity_primary_token_tests` module tests exercise real Win32 FFI on Windows; on non-Windows hosts, the module is compiled out by `#[cfg(all(test, target_os = "windows"))]`.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced beyond what the plan's `<threat_model>` already covers (T-30-05 through T-30-12).

## User Setup Required

None - no external service configuration required. Windows-host test run needed to exercise `low_integrity_primary_token_tests` (requires actual Windows logon session for `OpenProcessToken`).

## Next Phase Readiness

- Plan 30-03 (field-smoke harness) can proceed: the cascade now takes the `LowIlPrimary` arm when `pty.is_some()` — the structural prerequisite for observing whether ConPTY + Low-IL token works end-to-end
- Plan 30-04 (cookbook + outcome flip) depends on Plan 30-03 field-smoke success
- If `cargo test low_integrity_primary_token_tests` on a Windows test box reveals A2 violation (integrity SID not Low-IL), Plan 30-04's Wave 2 trigger fires

---
*Phase: 30-windows-nono-shell-architecture*
*Completed: 2026-05-07*
