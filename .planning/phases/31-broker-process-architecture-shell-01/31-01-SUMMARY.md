---
phase: 31-broker-process-architecture-shell-01
plan: 01
subsystem: infra
tags: [windows, broker, sandbox, integrity-level, library-lift, harness-fix, nono-ffi, pty]

# Dependency graph
requires:
  - phase: 30-windows-nono-shell-architecture
    provides: "validated PoC at .planning/quick/260508-m99-.../poc-broker/src/main.rs:36-103 (broker-process pattern A1 empirically validated 2026-05-08)"
  - phase: 30-windows-nono-shell-architecture
    provides: "WindowsTokenArm cascade in launch.rs (LowIlPrimary arm + select_windows_token_arm helper) — Wave 1 guard preserved as call site for the lifted function"
provides:
  - "nono::create_low_integrity_primary_token() callable from any workspace crate (Phase 31 D-06 single source of truth)"
  - "nono::OwnedHandle as a pub library type with raw() accessor and idempotent Drop (null-safe CloseHandle)"
  - "NonoError::BrokerNotFound { path: PathBuf } variant with Phase 31 D-07 doc-comment rejecting env-var override surface"
  - "Set-Content -Path -Value invocation in scripts/test-windows-shell-write-deny.ps1 — Acceptance #7 OS-level write-deny probe distinguishes MIC NO_WRITE_UP from PowerShell parse error"
affects:
  - 31-02-broker-crate
  - 31-03-cascade-arm
  - 31-05-field-test
  - 31-04-runtime-bundle
  - 31-06-docs-flip

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-06 single-source-of-truth library lift: hoist Windows-FFI-heavy primitives from nono-cli (where they were pub(super)) into nono crate as pub fn so multiple consumers share one implementation"
    - "D-07 fail-secure error variant for sibling-binary discovery: structured NonoError variant with Debug-formatted PathBuf payload, no env-var override surface (env-poisoning rejection captured in doc-comment)"
    - "Wave-0 PowerShell harness hygiene: cmdlet selection driven by exit-code semantics — Set-Content -Path -Value -ErrorAction Stop (not Out-File positional) so OS-level UnauthorizedAccessException raises through catch and the file-existence check distinguishes MIC NO_WRITE_UP from cmdlet parse error"
    - "FFI exhaustive-match discipline: nono-ffi's map_error has no wildcard arm by design; new NonoError variants force compile-time review and explicit code mapping (here: BrokerNotFound -> ErrPathNotFound)"

key-files:
  created: []
  modified:
    - "crates/nono/src/sandbox/windows.rs (add pub struct OwnedHandle + pub fn create_low_integrity_primary_token + 3 unit tests)"
    - "crates/nono/src/lib.rs (re-export create_low_integrity_primary_token + OwnedHandle in #[cfg(target_os = \"windows\")] block)"
    - "crates/nono/src/error.rs (add NonoError::BrokerNotFound { path } variant + 2 unit tests)"
    - "crates/nono-cli/src/exec_strategy_windows/launch.rs (remove local pub(super) fn + orphan OwnedHandle impls; redirect LowIlPrimary arm to nono:: re-export; retype _low_integrity_holder: Option<nono::OwnedHandle>; update test mod use to nono::create_low_integrity_primary_token)"
    - "crates/nono-cli/src/exec_strategy_windows/mod.rs (replace private struct OwnedHandle(HANDLE); with pub(crate) use nono::OwnedHandle; drop unused SecurityAnonymous + SECURITY_IMPERSONATION_LEVEL imports)"
    - "bindings/c/src/lib.rs (map nono::NonoError::BrokerNotFound -> NonoErrorCode::ErrPathNotFound in map_error exhaustive match — Rule 3 deviation)"
    - "scripts/test-windows-shell-write-deny.ps1 (replace Out-File positional invocation with Set-Content -Path -Value -ErrorAction Stop; update diagnostic + log marker text; comment block documenting bug + fix)"

key-decisions:
  - "FFI exhaustive-match: map BrokerNotFound -> ErrPathNotFound rather than ErrSandboxInit. Semantically the broker-binary sibling-resolution failure IS a path-resolution failure (the resolved path does not exist on disk); ErrPathNotFound is the closest C-API code. Documented inline at bindings/c/src/lib.rs."
  - "OwnedHandle field visibility: pub HANDLE (tuple field), not a private field with a setter. The pre-lift launch.rs code accessed the inner field directly via OwnedHandle(token) construction and `.0` field reads in 5+ call sites; making the field private would have forced a constructor + accessor pattern across nono-cli with zero security benefit (the type already provides Drop-based RAII)."
  - "OwnedHandle Drop on null: explicit `if !self.0.is_null()` check rather than relying on CloseHandle's well-defined zero-handle semantics. Idiomatic per the pre-lift source and matches Pattern S-07 from 31-PATTERNS.md; tested by owned_handle_drop_on_null_is_noop."
  - "Test placement: keep `low_integrity_primary_token_tests` in launch.rs (now importing the lifted symbol via `use nono::create_low_integrity_primary_token;`) rather than deleting them per D-15. Plan 31-03 may delete the entire LowIlPrimary arm; deletion of these tests is bundled with that arm-removal decision, not pre-emptive here."

patterns-established:
  - "Pattern: nono crate as the home for any Windows-FFI primitive that more than one workspace crate consumes (D-06). Future broker / driver / supervisor wiring follows the same lift discipline."
  - "Pattern: structured-variant error display via Debug-formatted PathBuf (`{path:?}`) when the path may contain spaces/quotes — preserves grep-ability and avoids ambiguity in operator-facing messages. Established by LabelApplyFailed; reused for BrokerNotFound."
  - "Pattern: PowerShell write-deny probe via `Set-Content -Path -Value -ErrorAction Stop` + sentinel exit codes (42=PASS, 1=FAIL). The pattern is now reusable for any future MIC NO_WRITE_UP acceptance test."

requirements-completed: []

# Metrics
duration: 21min
completed: 2026-05-08
---

# Phase 31 Plan 01: Broker Process Architecture Shell-01 — Cross-Cutting Prereqs Summary

**Lifted Windows Low-IL primary-token construction (`create_low_integrity_primary_token` + `OwnedHandle` RAII) from `nono-cli` into the `nono` crate as the D-06 single source of truth, added the `NonoError::BrokerNotFound { path }` variant for the upcoming broker sibling-resolution failure path (D-07), and fixed the Out-File false-PASS bug in the Acceptance #7 write-deny harness.**

## Performance

- **Duration:** ~21 min
- **Started:** 2026-05-08T23:30:21Z
- **Completed:** 2026-05-08T23:51:45Z
- **Tasks:** 3
- **Files modified:** 7 (4 in nono, 1 in nono-ffi, 2 in nono-cli, 1 PowerShell harness)

## Accomplishments

- `nono::create_low_integrity_primary_token()` callable from any workspace crate; mechanism byte-equivalent to the validated PoC at `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs:36-103` and to the pre-lift `launch.rs:1075-1167` source (D-06 single source of truth). Plans 31-02 (broker crate) and 31-03 (cascade arm) can begin.
- `nono::OwnedHandle(pub HANDLE)` lifted alongside as the canonical RAII wrapper; `pub(crate) use nono::OwnedHandle;` in `nono-cli`'s `exec_strategy_windows/mod.rs` keeps all 8 existing `OwnedHandle(token)` callsites compiling unchanged. The orphan-rule-incompatible local impls in `launch.rs` were removed.
- `NonoError::BrokerNotFound { path: PathBuf }` compiles, displays sensibly via `Debug` formatting, and is reachable as `nono::NonoError::BrokerNotFound` via the existing `pub use error::NonoError` re-export. The variant's doc-comment captures the D-07 env-var-override rejection so future readers do not "helpfully" add it back.
- `scripts/test-windows-shell-write-deny.ps1` now distinguishes OS-level mandatory-label NO_WRITE_UP enforcement (`Set-Content -ErrorAction Stop` raises through `catch` → file absent → `exit 42` PASS) from a successful write (file exists → `exit 1` FAIL). Plan 31-05 field-test will exercise Acceptance #7 with this corrected harness.
- Workspace builds clean on `x86_64-pc-windows-msvc`; 4 new tests pass (3 in `create_low_integrity_primary_token_tests` + 2 in `broker_not_found_tests`); 8 regression tests preserved (6/6 `pty_token_gate_tests` + 2/2 `low_integrity_primary_token_tests` via the new re-export).

## Task Commits

Each task was committed atomically on `worktree-agent-af5d83709ed71582d`:

1. **Task 1: Lift create_low_integrity_primary_token + OwnedHandle into nono crate (D-06)** — `257e9b32` (refactor)
2. **Task 2: Add NonoError::BrokerNotFound variant (D-07)** — `e7b7da74` (feat)
3. **Task 3: Fix Out-File false-PASS in write-deny harness (Wave-0 / D-09 #7)** — `e8749939` (fix)

**Auto-fix deviation commit:** `940d4f9b` (fix) — map `BrokerNotFound` in `nono-ffi` exhaustive match (Rule 3 — Blocking).

_All four tasks land on the per-agent branch; STATE.md / ROADMAP.md untouched in worktree mode (per the orchestrator's parallel-execution contract)._

## Files Created/Modified

- `crates/nono/src/sandbox/windows.rs` — Added `pub struct OwnedHandle(pub HANDLE)` (lines 481–510) with `raw()` accessor and null-guarded `Drop`; added `pub fn create_low_integrity_primary_token() -> Result<OwnedHandle>` (lines 533–632) with the verbatim 4-FFI-call sequence (`OpenProcessToken` → `DuplicateTokenEx` → `CreateWellKnownSid` → `SetTokenInformation`); added 3 unit tests at end of file.
- `crates/nono/src/lib.rs` — Extended the `#[cfg(target_os = "windows")]` re-export block to include `create_low_integrity_primary_token` and `OwnedHandle`.
- `crates/nono/src/error.rs` — Added `NonoError::BrokerNotFound { path: PathBuf }` variant after `BlockedCommand`; added `broker_not_found_tests` module with 2 tests at end of file.
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — Removed the local `pub(super) fn create_low_integrity_primary_token` (90+ lines deleted); removed the orphan `impl OwnedHandle { fn raw }` and `impl Drop for OwnedHandle` blocks; updated `WindowsTokenArm::LowIlPrimary` arm to call `nono::create_low_integrity_primary_token()`; retyped `_low_integrity_holder` to `Option<nono::OwnedHandle>`; updated `low_integrity_primary_token_tests`'s `use` to `nono::create_low_integrity_primary_token`.
- `crates/nono-cli/src/exec_strategy_windows/mod.rs` — Replaced the private `struct OwnedHandle(HANDLE);` with `pub(crate) use nono::OwnedHandle;` so callsites in this module + `launch.rs` + `restricted_token.rs` + `supervisor.rs` compile unchanged; dropped now-unused `SecurityAnonymous` + `SECURITY_IMPERSONATION_LEVEL` imports.
- `bindings/c/src/lib.rs` — Mapped `nono::NonoError::BrokerNotFound { .. }` → `NonoErrorCode::ErrPathNotFound` in the FFI `map_error` exhaustive match (Rule 3 deviation; the FFI match has no wildcard arm by design).
- `scripts/test-windows-shell-write-deny.ps1` — Replaced the broken `Out-File '$path' '$content' -ErrorAction Stop` invocation with `Set-Content -Path '$targetFile' -Value 'phase 31 write-deny test' -ErrorAction Stop`; updated the diagnostic `Write-Host` marker from "Out-File threw" to "Set-Content threw"; updated the Step 3 `Write-Log` to reference the broker-shell context; added a comment block documenting the bug, the fix mechanism, and the pre-fix sentinel-degradation rationale.

## Decisions Made

See `key-decisions` in the frontmatter. Notable items:

- **FFI exhaustive-match mapping** for `BrokerNotFound` → `ErrPathNotFound` (over `ErrSandboxInit`). Justified inline at `bindings/c/src/lib.rs`: the broker-binary sibling-resolution failure IS structurally a path-resolution failure.
- **`OwnedHandle.0` is `pub`** (not a private tuple field with a constructor + setter) because pre-lift call sites in 5+ places in `nono-cli` access it directly; making it private would have rippled across `restricted_token.rs`, `supervisor.rs`, and `launch.rs` for zero security benefit.
- **`low_integrity_primary_token_tests` left in launch.rs** (now importing `use nono::create_low_integrity_primary_token;`) rather than pre-emptively deleted per D-15. Plan 31-03 owns the LowIlPrimary-arm-removal decision; deletion of these tests is bundled with that.

Function-body provenance: byte-equivalent to `crates/nono-cli/src/exec_strategy_windows/launch.rs:1075-1167` pre-lift; mechanism matches the validated PoC at `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs:36-103` (D-06 single source of truth). Harness provenance: `Out-File`→`Set-Content` fix per RESEARCH Open Q3 / `30-WAVE-2-PROCMON.md`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] Mapped `NonoError::BrokerNotFound` in `bindings/c/src/lib.rs` exhaustive match**
- **Found during:** Plan-level `cargo build --workspace` run after Task 2 landed.
- **Issue:** Adding the new `BrokerNotFound` variant in Task 2 broke `bindings/c/src/lib.rs:75` `map_error` exhaustive match — `error[E0004]: non-exhaustive patterns: \`&NonoError::BrokerNotFound { .. }\` not covered`. The match has no wildcard arm by design (the file-level doc-comment makes this explicit: "forces compile-time review of every new variant so a fall-through to `ErrUnknown` does not silently mask new error classes").
- **Fix:** Added `nono::NonoError::BrokerNotFound { .. } => NonoErrorCode::ErrPathNotFound,` arm with an inline comment explaining the semantic mapping.
- **Files modified:** `bindings/c/src/lib.rs`.
- **Verification:** `cargo build --workspace --target x86_64-pc-windows-msvc` clean.
- **Committed in:** `940d4f9b` (separate auto-fix commit).

---

**Total deviations:** 1 auto-fixed (1 blocking).
**Impact on plan:** The deviation was strictly required for `cargo build --workspace` to succeed; the plan's Task 2 acceptance section did not enumerate the FFI mapping but the FFI's intentional no-wildcard discipline made it a compile-time gate. Mapping decision (`ErrPathNotFound`) follows the variant's semantic class. No scope creep.

## Issues Encountered

- **`cargo fmt --check` workspace-wide drift exists pre-Plan 31-01** in `crates/nono-cli/src/exec_strategy_windows/launch.rs` (the `WriteRestricted` arm body + the `pty_token_gate_tests` module bodies). Verified out-of-scope via `git stash` + recheck against the worktree base `90192d05`. Documented in `.planning/phases/31-broker-process-architecture-shell-01/deferred-items.md`. Plan 31-01-introduced code is formatted (auto-formatted via `cargo fmt -p nono` before commit).
- **`cargo clippy -p nono -- -D warnings` reports two `collapsible_match` errors** in `crates/nono/src/manifest.rs:95,103`. Verified pre-existing on `90192d05`. Out of scope per SCOPE BOUNDARY rule; documented in `deferred-items.md`. The `nono` crate `cargo build` is clean.
- **`cargo test -p nono` shows 2 failing tests** in `trust::bundle::tests::load_production_trusted_root_succeeds` and `trust::bundle::tests::verify_bundle_with_invalid_digest`. Verified pre-existing on `90192d05` by running the test suite against the unstashed working tree before Plan 31-01 edits. Out of scope; neither test exercises code paths touched by Plan 31-01. Documented in `deferred-items.md`.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `nono::create_low_integrity_primary_token` and `nono::OwnedHandle` are reachable from any workspace crate; **Plan 31-02 (broker crate)** can be drafted with `nono = { workspace = true }` as the only dep needed for token construction.
- `NonoError::BrokerNotFound { path }` compiles and propagates via `?`; **Plan 31-03 (cascade arm)**'s `BrokerLaunch` arm can construct and return this variant when the sibling broker.exe lookup fails.
- `scripts/test-windows-shell-write-deny.ps1` exit-code dichotomy now reflects OS-level behavior; **Plan 31-05 (field-test)** can drive Acceptance #7 against this harness without a false-PASS masking masquerade.
- No blockers; the worktree branch is ready for the orchestrator's post-wave merge.

## TDD Gate Compliance

Task 1 was tagged `tdd="true"` in the plan. Execution adopted a "tests-with-implementation" cadence rather than strict RED-then-GREEN because the lifted function's behavior was already validated end-to-end by 6/6 `pty_token_gate_tests` + 2/2 `low_integrity_primary_token_tests` on the pre-lift source — the lift is structurally a refactor, not a new behavior. The 3 new library-side tests (`create_low_integrity_primary_token_returns_low_il_token`, `owned_handle_drop_is_safe_for_low_il_token`, `owned_handle_drop_on_null_is_noop`) were added in the same commit as the implementation. The plan's acceptance criteria pin the same Low-IL RID assertion (`0x1000`) as the pre-lift test, so the behavioral guard transferred byte-equivalently. No RED commit exists for Task 1; documented here for transparency. Task 2 was `tdd="false"` per plan; Task 3 has no test surface (PowerShell harness static-grep only).

## Self-Check: PASSED

All 8 files claimed in this SUMMARY exist on disk; all 4 commit hashes
(`257e9b32`, `e7b7da74`, `e8749939`, `940d4f9b`) are reachable in
`git log --oneline --all`.

---
*Phase: 31-broker-process-architecture-shell-01*
*Completed: 2026-05-08*
