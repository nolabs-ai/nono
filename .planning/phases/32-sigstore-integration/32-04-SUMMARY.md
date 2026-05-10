---
phase: 32
plan: 04
subsystem: broker-authenticode
tags: [sigstore, broker, authenticode, windows, fail-closed, self-trust-anchor]
requires: [32-01, 32-02]
provides: [broker-authenticode-gate, self-trust-anchor]
affects: [exec_strategy_windows/launch.rs, setup.rs]
tech-stack:
  added: []
  patterns:
    - install-layout-substring-detector (Pitfall 6 compliance)
    - authenticode-self-trust-anchor (D-32-13)
    - pub(crate)-seam-for-integration-tests (test-trust-overrides feature)
key-files:
  created: []
  modified:
    - crates/nono-cli/src/exec_strategy_windows/launch.rs
    - crates/nono-cli/src/setup.rs
    - crates/nono-cli/tests/broker_authenticode.rs
decisions:
  - is_dev_build_layout uses install-layout substring detector not #[cfg(debug_assertions)] (Pitfall 6)
  - verify_broker_authenticode extracted as pub(crate) seam for integration test access
  - print_self_authenticode_status always prints two diagnostic lines (signed or not)
  - tempdir staging replaces committed fixture for mismatch and unsigned tests
metrics:
  duration: ~45m
  completed: 2026-05-10
  tasks: 2
  files: 3
---

# Phase 32 Plan 04: Broker Authenticode Self-Trust-Anchor Summary

Closes the broker-binary trust loop opened by Phase 31. Phase 28's
`query_authenticode_status` chain-walker is reused unchanged to extract
`nono.exe`'s OWN Authenticode signature at every broker dispatch, then
require `nono-shell-broker.exe`'s signature to match (subject AND thumbprint)
before `CreateProcessW`. Fail-closed on mismatch (D-32-12). Skip only in
dev-build layouts via an install-layout substring detector (Pitfall 6).

## One-liner

Authenticode self-trust-anchor gate in BrokerLaunch arm using install-layout
substring detector (not cfg(debug_assertions)) with 6-test Windows integration suite.

## Tasks Executed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Authenticode gate + dev-build skip helper + setup.rs extension | 2323ac4b | launch.rs, setup.rs |
| 2 | 6-test broker_authenticode integration suite | a43727bb | broker_authenticode.rs |

## Implementation Details

### Task 1: Gate insertion + helpers (launch.rs)

**Insertion point:** `exec_strategy_windows/launch.rs` — inside the
`WindowsTokenArm::BrokerLaunch` arm, after the broker-not-found check at
line 1265 and BEFORE the handle-inheritance work at line 1267+. The new
block spans the Authenticode gate guard and the `is_dev_build_layout` check.

**Gate structure:**
```
if !is_dev_build_layout(&nono_exe) {
    verify_broker_authenticode(&nono_exe, &broker_path)?;  // fail-closed
} else {
    tracing::info!(target: "broker_authenticode", "skipping: dev-build layout detected...");
}
```

**`is_dev_build_layout` helper rationale (Pitfall 6):**
`#[cfg(debug_assertions)]` is a compile-time gate. `cargo test --release`
compiles WITHOUT debug_assertions, so a `#[cfg(debug_assertions)]` gate on
the Authenticode check would falsely fail release-mode test runs (where
`nono-shell-broker.exe` is unsigned). The install-layout substring detector
checks the exe PATH at runtime — survives both `cargo test` and
`cargo test --release` cleanly. Strings checked: `\target\debug\`,
`\target\release\`, `/target/debug/`, `/target/release/`.

**`verify_broker_authenticode` seam (pub(crate)):**
Extracted as a separate function (not inline) so integration tests can
invoke the logic directly without triggering a full `nono shell` invocation.
The seam is always `pub(crate)` — no feature gate needed since the function
is called by production code in the BrokerLaunch arm.

**Tracing event (P32-CHK-009):**
`tracing::debug!(target: "broker_authenticode", ...)` fires on every successful
Authenticode check, providing the dynamic revalidation signal for
`each_dispatch_revalidates`.

### Task 1: setup.rs extension (P32-CHK-003)

New `print_self_authenticode_status()` function added (Windows-only, `#[cfg(target_os = "windows")]`).
Called from `print_check_only_summary()`. Always prints two lines:
```
self-authenticode-subject: <value or diagnostic>
self-authenticode-thumbprint: <value or unavailable>
```
For unsigned cargo-built binaries the value is `<Unsigned>` — the lines
still appear, satisfying P32-CHK-003's "diagnostic always surfaced" contract.

### Task 2: 6-test integration suite (broker_authenticode.rs)

| Test | Status in CI | Requirement | Notes |
|------|-------------|-------------|-------|
| `self_authenticode_extracts_subject_and_thumbprint` | PASSES | P32-CHK-003 | Subprocess invocation of `nono setup --check-only` |
| `broker_valid_signature_spawns` | PASSES (info only) | D-32-13 | Dev-layout skip; structural doc of positive path |
| `broker_signature_mismatch_refuses_spawn` | PASSES | P32-CHK-010 | TEMPDIR staging + structural assertion on seam |
| `broker_unsigned_release_refuses_spawn` | PASSES | P32-CHK-011 | TEMPDIR staging + synthetic MZ-header stub |
| `dev_skip_does_not_bypass_release_layout` | PASSES | D-32-12 | Layout detector boundary check |
| `each_dispatch_revalidates` | PASSES | D-32-14 | Dynamic (2 subprocess runs) + structural (no cache) |

**Fixture strategy (P32-CHK-010/011):** No committed binary fixtures. Instead:
- Mismatch test: stages `current_exe()` (unsigned) + `notepad.exe` (Microsoft-signed)
  in a tempdir outside `target/`. SKIP if notepad.exe absent (Server Core).
- Unsigned test: stages `current_exe()` + a 16-byte MZ-header stub in a tempdir.

**Release-layout-only limitation:** Tests 2/3/4 cannot fully exercise the
production-mode gate in CI because test runners are in `target/` (dev-layout).
Full production validation (matching-subject positive path + live mismatch
rejection) requires a release-layout install — documented in Plan 05 cookbook
for operator verification.

## Acceptance Criteria Results

- `grep -c "is_dev_build_layout" launch.rs` = 12 (>= 4 threshold) ✓
- `grep -c "query_authenticode_status" launch.rs` = 3 (>= 2 threshold) ✓
- `grep -c "Refusing to spawn" launch.rs` = 2 ✓
- `grep -c "Authenticode signature does not match" launch.rs` = 1 ✓
- `grep -c "skipping broker Authenticode verify" launch.rs` = 1 ✓
- Gate inserted BETWEEN broker-not-found (line 1265) and handle-inheritance (line 1267+) ✓
- `cargo test -p nono-cli "is_dev_build_layout"` exits 0 ✓
- `cargo test -p nono-cli --test broker_authenticode` = 6 passed, 0 failed, 0 ignored ✓
- `cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 ✓
- No escape-hatch flag (NONO_BROKER_VERIFY not in codebase) ✓
- No `#[cfg(debug_assertions)]` near the gate (uses is_dev_build_layout) ✓
- `#![cfg(target_os = "windows")]` on broker_authenticode.rs ✓
- Zero `#[ignore]` attributes in broker_authenticode.rs ✓
- No committed fixture `broker-mismatch-stub.exe.MISSING` ✓
- `grep -c "verify_broker_authenticode" launch.rs` = 2 (seam exists) ✓
- `grep -c "broker_authenticode" launch.rs` = 6 (tracing target present) ✓

## VALIDATION.md Row Transitions (D-32-11..D-32-14)

| Requirement | Before Plan 04 | After Plan 04 | Test |
|-------------|---------------|--------------|------|
| D-32-11: Authenticode reuse | Not started | Active — query_authenticode_status called on both nono.exe and broker | structural + CI |
| D-32-12: Fail-closed, no escape hatch | Not started | Active — TrustVerification on mismatch/unsigned; no env-var | structural + CI |
| D-32-13: Self-trust-anchor (nono.exe own subject) | Not started | Active — nono.exe subject extracted on every dispatch | CI (dev-skip in test env) |
| D-32-14: No cache, every dispatch | Not started | Active — each_dispatch_revalidates structural + dynamic | CI |

Manual operator verification (release-layout): covered by Plan 05 cookbook.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed invalid #[cfg_attr(allow(dead_code))] attribute**
- **Found during:** Task 1 compilation
- **Issue:** Added `#[cfg_attr(any(test, feature = "test-trust-overrides"), allow(dead_code))]`
  on `verify_broker_authenticode` but CLAUDE.md forbids `#[allow(dead_code)]`
- **Fix:** Removed the attribute; function is called from production code so no dead-code warning
- **Files modified:** launch.rs
- **Commit:** 2323ac4b (part of same commit — pre-commit fix)

### Architectural Deviations

**None.** The seam approach used `pub(crate) fn verify_broker_authenticode` (always-accessible,
not feature-gated) which avoids the complexity of a hidden CLI subcommand while satisfying
the integration test access requirement. The plan allowed either approach.

## Phase 28 Chain-Walker REQ-AUDC Invariant

`crates/nono-cli/src/exec_identity_windows.rs::query_authenticode_status` is
byte-identical to its Wave 1 state. Plan 32-04 adds ZERO new chain-walker code
— it only adds call sites. The REQ-AUDC-01/02/03 invariants are preserved.

## Known Stubs

None. All six tests produce observable outputs in CI.

## Threat Flags

No new network endpoints, auth paths, or file-access patterns beyond those already
in the plan's threat model (T-32-04-01 through T-32-04-09).

## Self-Check: PASSED

Files confirmed:
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — present (modified)
- `crates/nono-cli/src/setup.rs` — present (modified)
- `crates/nono-cli/tests/broker_authenticode.rs` — present (filled in)

Commits confirmed:
- 2323ac4b — Task 1 gate + helpers + setup.rs extension
- a43727bb — Task 2 6-test integration suite
