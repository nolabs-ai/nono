---
phase: 36-upst3-deep-closure
plan: 01a
subsystem: profile
tags: [deprecated-schema, legacy-policy-patch, deprecation-counter, strict-mode, port-closure, d-20-manual-replay, rust, serde, clap]

# Dependency graph
requires:
  - phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
    provides: "Phase 34-04b pragmatic Option C seed (LEGACY_OVERRIDE_DENY_WARNED AtomicBool + serde alias) that this plan replaces"
provides:
  - "New crates/nono-cli/src/deprecated_schema.rs module: LegacyPolicyPatch (serde-driven legacy-key rewriter) + DeprecationCounter (per-key AtomicBool one-shot stderr WARN)"
  - "--strict flag on nono profile validate (fail-closed on legacy keys)"
  - "LEGACY_OVERRIDE_DENY_WARNED AtomicBool global retired with tombstone comment"
  - "Integration tests for --strict mode (profile_validate_strict.rs)"
affects:
  - 36-01b
  - 36-01c
  - 36-01d

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-20 manual-replay: upstream f0abd413 used as design source; commit body cites SHA; no Upstream-commit: trailer"
    - "DeprecationCounter: OnceLock<HashMap<&'static str, AtomicBool>> for wait-free per-key one-shot stderr emission"
    - "LegacyPolicyPatch with #[serde(deny_unknown_fields)] to reject unknown legacy keys fail-closed"
    - "Integration tests via CARGO_BIN_EXE_nono subprocess pattern to keep stderr capture clean across tests"

key-files:
  created:
    - crates/nono-cli/src/deprecated_schema.rs
    - crates/nono-cli/tests/profile_validate_strict.rs
  modified:
    - crates/nono-cli/src/main.rs
    - crates/nono-cli/src/cli.rs
    - crates/nono-cli/src/profile_cmd.rs
    - crates/nono-cli/src/profile/mod.rs

key-decisions:
  - "LegacyPolicyPatch intentionally has NO serde alias for bypass_protection — detection ONLY fires on literal override_deny JSON key; canonical profiles must NOT trigger legacy-key detection"
  - "LEGACY_OVERRIDE_DENY_WARNED AtomicBool retired (not just tombstoned) into DeprecationCounter map to prevent double-emission; existing call site in profile/mod.rs::detect_legacy_override_deny_key() updated to call GLOBAL_DEPRECATION_COUNTER.emit_once()"
  - "Cross-target Linux/macOS clippy documented as SKIP — x86_64-linux-gnu-gcc and cc cross-compilers not installed on this Windows host; CI matrix will catch platform regressions"
  - "Release mode used for all builds and tests — debug mode triggers pre-existing rustc ICE in x509_cert::builder (unrelated to Phase 36)"

patterns-established:
  - "Pattern: DeprecationCounter as static process-wide OnceLock map — reusable for future legacy key additions in Plans 36-01c/d"
  - "Pattern: empty security.groups fixture for profile validate integration tests to avoid group-not-found errors masking the behavior under test"

requirements-completed:
  - REQ-PORT-CLOSURE-02

# Metrics
duration: 180min
completed: 2026-05-12
---

# Phase 36 Plan 01a: DEPRECATED-SCHEMA-MODULE Summary

**LegacyPolicyPatch serde rewriter + DeprecationCounter per-key AtomicBool + --strict fail-closed mode on nono profile validate, replacing Phase 34-04b's pragmatic single-AtomicBool seed (D-20 manual-replay of upstream f0abd413 v0.47.0)**

## Performance

- **Duration:** ~180 min
- **Started:** 2026-05-12T00:00:00Z
- **Completed:** 2026-05-12T05:00:00Z
- **Tasks:** 3 (Task 1: module skeleton + unit tests, Task 2: wiring + integration tests + AtomicBool retirement, Task 3: close-gate verification + fmt fixes)
- **Files modified:** 6

## Accomplishments

- Created `crates/nono-cli/src/deprecated_schema.rs` (260+ LOC): `LegacyPolicyPatch` with `#[serde(deny_unknown_fields)]` and `#[must_use] rewrite() -> Result<CanonicalPolicy>`, `DeprecationCounter` with `OnceLock<HashMap<&'static str, AtomicBool>>` for wait-free one-shot WARN emission, and `pub static GLOBAL_DEPRECATION_COUNTER`
- Wired `--strict` flag on `nono profile validate` via new `pub strict: bool` field on `ProfileValidateArgs`; strict-mode pushes legacy-key errors to `errors` Vec (fail-closed); non-strict pushes to `warnings` Vec
- Retired `LEGACY_OVERRIDE_DENY_WARNED: AtomicBool` global from `profile/mod.rs` (tombstone comment cites Plan 36-01a + D-36-B1); call site migrated to `GLOBAL_DEPRECATION_COUNTER.emit_once()`
- 4 inline unit tests + 3 integration tests (subprocess pattern via `CARGO_BIN_EXE_nono`), all passing

## Task Commits

Each task was committed atomically:

1. **Task 1 RED: add failing integration tests** - `cbe9708b` (test)
2. **Task 1/2 GREEN: create deprecated_schema module** - `18aca09b` (feat)
3. **Task 2 GREEN: wire --strict flag + retire LEGACY_OVERRIDE_DENY_WARNED** - `ed09a586` (feat)
4. **Task 3: close-gate verification + fmt fixes** - `1805bff2` (chore)

## Files Created/Modified

- `crates/nono-cli/src/deprecated_schema.rs` (CREATED, ~260 LOC) - LegacyPolicyPatch, DeprecationCounter, GLOBAL_DEPRECATION_COUNTER, 4 unit tests
- `crates/nono-cli/tests/profile_validate_strict.rs` (CREATED, 148 LOC) - 3 integration tests for strict/non-strict validate paths
- `crates/nono-cli/src/main.rs` (MODIFIED) - Added `mod deprecated_schema;` in alphabetical order
- `crates/nono-cli/src/cli.rs` (MODIFIED) - Added `pub strict: bool` to `ProfileValidateArgs`
- `crates/nono-cli/src/profile_cmd.rs` (MODIFIED) - Wired LegacyPolicyPatch detection + DeprecationCounter.emit_once() in cmd_validate; fixed rustfmt import order
- `crates/nono-cli/src/profile/mod.rs` (MODIFIED) - Retired LEGACY_OVERRIDE_DENY_WARNED + emit_legacy_override_deny_warning_once(); migrated to GLOBAL_DEPRECATION_COUNTER.emit_once()

## Decisions Made

- **LegacyPolicyPatch has no serde alias for bypass_protection**: The struct ONLY matches `override_deny`. Adding `#[serde(alias = "bypass_protection")]` would cause canonical profiles to trigger false-positive legacy detection. Detection is intentionally narrow: only the literal legacy key fires the counter.
- **LEGACY_OVERRIDE_DENY_WARNED retired (not just tombstoned)**: The call site in `detect_legacy_override_deny_key()` was updated to call `GLOBAL_DEPRECATION_COUNTER.emit_once()` to avoid double-emission when both `profile/mod.rs` and `profile_cmd.rs` encounter the same profile.
- **Cross-target clippy skipped**: `x86_64-linux-gnu-gcc` and `cc` (macOS cross-compiler) are not installed on this Windows host. Cross-target clippy for Linux cfg-gated code will run in CI.
- **Release-mode builds throughout**: Debug builds trigger a pre-existing rustc ICE in `x509_cert::builder` unrelated to Phase 36. All verification uses `--release`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed serde alias bypass_protection from LegacyPolicyPatch**
- **Found during:** Task 2 integration test execution
- **Issue:** Initial LegacyPolicyPatch had `#[serde(alias = "bypass_protection")]` which caused canonical profiles containing `bypass_protection` to deserialize into LegacyPolicyPatch and trigger `has_legacy_keys() = true`, incorrectly flagging valid modern profiles
- **Fix:** Removed the alias entirely. `LegacyPolicyPatch` now only matches the literal `override_deny` JSON key. Added unit test `legacy_policy_patch_passes_through_unknown_legacy_keys` to lock the invariant.
- **Files modified:** `crates/nono-cli/src/deprecated_schema.rs`
- **Verification:** `test_profile_validate_strict_accepts_canonical_key` integration test passes (canonical profile + --strict = exit 0)
- **Committed in:** ed09a586

**2. [Rule 1 - Bug] Fixed integration test fixture using non-existent security group**
- **Found during:** Task 2 integration test execution
- **Issue:** Initial fixture used `"security": {"groups": ["allow_read_home"]}` — group not found in embedded policy, causing group-not-found validation errors that masked the legacy-key detection behavior under test
- **Fix:** Changed all integration test fixtures to use `"security": {"groups": []}` (empty array avoids group resolution entirely)
- **Files modified:** `crates/nono-cli/tests/profile_validate_strict.rs`
- **Verification:** All 3 integration tests pass cleanly
- **Committed in:** ed09a586

**3. [Rule 1 - Bug] Fixed rustfmt import ordering in profile_cmd.rs**
- **Found during:** Task 3 close-gate fmt check
- **Issue:** `use crate::deprecated_schema` was placed before `use crate::config::embedded`, violating rustfmt's alphabetical crate-path ordering rule
- **Fix:** Moved `deprecated_schema` import after `config::embedded`
- **Files modified:** `crates/nono-cli/src/profile_cmd.rs`
- **Verification:** `cargo fmt --all -- --check` exits 0
- **Committed in:** 1805bff2

**4. [Rule 1 - Bug] Fixed rustfmt line-length in deprecated_schema.rs test helper**
- **Found during:** Task 3 close-gate fmt check
- **Issue:** Two-line let binding in a test helper was split by rustfmt differently than manually written
- **Fix:** Collapsed `let result: ... = \n    serde_json::from_str(...)` onto a single line
- **Files modified:** `crates/nono-cli/src/deprecated_schema.rs`
- **Verification:** `cargo fmt --all -- --check` exits 0
- **Committed in:** 1805bff2

---

**Total deviations:** 4 auto-fixed (2 code bugs, 2 fmt bugs)
**Impact on plan:** All auto-fixes required for correctness (canonical-profile false-positive, group resolution noise) and CI hygiene (fmt). No scope creep.

## Close-Gate Verification (D-36-A5)

| Gate | Command | Result |
|------|---------|--------|
| 1. Unit + integration tests | `cargo test --release -p nono-cli` | PASS (4 unit + 3 integration) |
| 2. Windows host clippy | `cargo clippy --release -p nono-cli --all-targets -D warnings -D clippy::unwrap_used` | PASS |
| 3. Linux cross-target clippy | `cargo clippy --target x86_64-unknown-linux-gnu` | SKIP — x86_64-linux-gnu-gcc not installed on Windows host |
| 4. macOS cross-target clippy | `cargo clippy --target x86_64-apple-darwin` | SKIP — cc cross-compiler not installed on Windows host |
| 5. Fmt check | `cargo fmt --all -- --check` | PASS (after 2 fmt fixes) |
| 6. Phase 15 smoke gate | detached-console paths | SKIP — Plan 36-01a does not touch detached-console code paths |
| 7. wfp_port_integration | WFP hardware gate | SKIP — hardware-gated |
| 8. learn_windows_integration | Windows learn mode | SKIP — not applicable to this plan |

## D-20 Commit Shape Verification

- `f0abd413` cited in commit bodies: 3 occurrences across plan commits
- `Upstream-commit:` trailer present: 0 (D-20 manual-replay — no D-19 trailer)
- `Signed-off-by:` trailers present: 8 across plan commits

## Migration Notes: LEGACY_OVERRIDE_DENY_WARNED Retirement

The `LEGACY_OVERRIDE_DENY_WARNED: AtomicBool` global at `profile/mod.rs:47` (Phase 34-04b Option C seed) was found to have exactly one caller: `detect_legacy_override_deny_key()` inside `profile/mod.rs`. That function was updated to call `GLOBAL_DEPRECATION_COUNTER.emit_once("override_deny", "bypass_protection")` instead of the retired helper. No other callers existed elsewhere in the codebase. Tombstone comment at the deletion site cites Plan 36-01a + D-36-B1 (upstream f0abd413).

## Known Stubs

None — all wired production code. `GLOBAL_DEPRECATION_COUNTER` emits live stderr WARNs; `LegacyPolicyPatch::rewrite()` performs real serde deserialization and returns canonical form.

## Threat Flags

No new security-relevant surface introduced beyond the plan's threat model. The `--strict` flag is an operator-controlled lever (not a bypass); `LegacyPolicyPatch` fails closed via `#[serde(deny_unknown_fields)]` + `Result` error propagation.

## Next Phase Readiness

Plan 36-01b can now compose on top of `deprecated_schema.rs`:
- `GLOBAL_DEPRECATION_COUNTER` is available for any new legacy keys
- `LegacyPolicyPatch` is extensible: add new `#[serde(deny_unknown_fields)]`-compatible fields for additional upstream legacy keys
- `--strict` flag is wired end-to-end; 36-01b/c/d can reuse without re-touching clap surface
- REQ-PORT-CLOSURE-02 acceptance criteria #1, #2, #3 met; criteria #4-#6 deferred to Plans 36-01b/c/d

---
*Phase: 36-upst3-deep-closure*
*Plan: 01a*
*Completed: 2026-05-12*
