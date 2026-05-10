---
phase: 32
plan: 01
subsystem: trust
tags: [sigstore, tuf, test-scaffolding, fixture, httpmock]
dependency_graph:
  requires: []
  provides:
    - "crates/nono/tests/fixtures/trust-root-frozen.json (frozen TUF root, D-32-02/06)"
    - "crates/nono/src/trust/mod.rs::load_test_trusted_root (D-32-15 #2)"
    - "crates/nono-cli [dev-dependencies] httpmock = 0.7"
    - "5 #[ignore]'d integration test scaffolds in crates/nono-cli/tests/"
  affects:
    - "Plans 02/03/04 — all consume this Wave 0 scaffolding"
tech_stack:
  added:
    - "httpmock 0.7 (dev-dependency, crates/nono-cli)"
  patterns:
    - "#[cfg(test)] pub(crate) helper for hermetic test fixture loading"
    - "#[ignore = ...] scaffold test with D-32-XX traceability comment"
key_files:
  created:
    - "crates/nono-cli/tests/setup_trust_root.rs"
    - "crates/nono-cli/tests/keyless_offline_invariant.rs"
    - "crates/nono-cli/tests/keyless_sign.rs"
    - "crates/nono-cli/tests/keyless_verify.rs"
    - "crates/nono-cli/tests/broker_authenticode.rs"
    - "crates/nono-cli/tests/fixtures/.gitkeep"
  modified:
    - "crates/nono/src/trust/mod.rs (load_test_trusted_root helper appended)"
    - "crates/nono-cli/Cargo.toml (httpmock dev-dep added)"
decisions:
  - "Task 1 checkpoint satisfied pre-flight by orchestrator: TrustedRoot::production() fails on sigstore-verify 0.6.5 with 'Signature threshold of 3 not met for role root'; fixture captured from sigstore/root-signing@main targets/trusted_root.json (6787 bytes). Committed at d9969978."
  - "load_test_trusted_root visibility is pub(crate) + #[cfg(test)], never pub, per D-32-15 T-32-01-03 mitigation"
  - "No #[allow(dead_code)] added despite dead_code warning: pre-existing clippy failures in nono lib mean make ci already fails; dead_code warning is anticipated by plan (Plan 02 adds the caller)"
  - "broker_authenticode.rs uses #![allow(clippy::unwrap_used)] per plan spec: Windows-only test file where test ergonomics take precedence (all tests are #[ignore]'d scaffolds)"
metrics:
  duration: "~4 minutes (Task 2 only; Task 1 was pre-flight)"
  completed: "2026-05-10"
  tasks_completed: 2
  files_changed: 8
---

# Phase 32 Plan 01: Sigstore Integration Test Scaffolding Summary

Wave 0 foundation for Phase 32: frozen TUF root fixture + `load_test_trusted_root()` library helper + `httpmock` dev-dep + 5 `#[ignore]`'d integration test scaffolds, enabling Plans 02/03/04 to land without touching Wave 0 files.

## Tasks Completed

### Task 1: Capture frozen Sigstore TUF root fixture

**Status:** DONE — satisfied pre-flight by orchestrator.

The `TrustedRoot::production()` call fails on sigstore-verify 0.6.5 with "Signature threshold of 3 not met for role root" (upstream drift issue that Plan 32-02 mitigates). The orchestrator captured the fixture from `sigstore/root-signing@main targets/trusted_root.json` before spawning this executor.

- **Fixture path:** `crates/nono/tests/fixtures/trust-root-frozen.json`
- **Size:** 6787 bytes
- **Shape:** `application/vnd.dev.sigstore.trustedroot+json;version=0.1`, 2 Fulcio CAs, 2 Rekor tlogs, 1 TSA, 2 ctlogs
- **Verification:** `TrustedRoot::from_file(path)` succeeds; `node -e "JSON.parse(...)"` passes
- **Commit:** `d9969978` ("test(32-01): capture frozen Sigstore TUF root fixture")

### Task 2: Add helper + wire dev-dep + create 5 test scaffolds

**Status:** DONE.

**Step 1 — `load_test_trusted_root()` helper added to `crates/nono/src/trust/mod.rs`:**
- Visibility: `pub(crate)` + `#[cfg(test)]` — never exported to library consumers
- Loads from `CARGO_MANIFEST_DIR/tests/fixtures/trust-root-frozen.json` via `load_trusted_root()`
- No `#[allow(dead_code)]` — Plan 02 adds the caller (migrated bundle.rs tests)
- No `.unwrap()` / `.expect()` — delegates to `load_trusted_root` which returns `Result`

**Step 2 — `httpmock = "0.7"` added to `crates/nono-cli/Cargo.toml` `[dev-dependencies]`:**
- Alphabetical insertion between no prior h-prefix entry and `jsonschema`
- Cargo.lock updated with resolved httpmock 0.7.x

**Step 3 — 5 scaffold test files created:**

| File | Plan | D-XX IDs |
|------|------|----------|
| `crates/nono-cli/tests/setup_trust_root.rs` | 02 | D-32-01 |
| `crates/nono-cli/tests/keyless_offline_invariant.rs` | 02 | D-32-03 |
| `crates/nono-cli/tests/keyless_sign.rs` | 03 | D-32-07 |
| `crates/nono-cli/tests/keyless_verify.rs` | 03 | D-32-08, D-32-09 |
| `crates/nono-cli/tests/broker_authenticode.rs` | 04 | D-32-11..14 (Windows-only) |

`crates/nono-cli/tests/fixtures/.gitkeep` also created for Wave 0+ fixture directory.

**Step 4 — Verification:**
- `cargo build -p nono --tests`: exits 0 (1 dead_code warning for load_test_trusted_root, anticipated by plan)
- `cargo build -p nono-cli --tests`: exits 0
- `cargo test -p nono-cli --test setup_trust_root --test keyless_offline_invariant --test keyless_sign --test keyless_verify`: 9 tests reported, all ignored, 0 failures

**Commit:** `ccf2004b`

## Commits

| Hash | Message | Files |
|------|---------|-------|
| `d9969978` | `test(32-01): capture frozen Sigstore TUF root fixture` | `crates/nono/tests/fixtures/trust-root-frozen.json` |
| `ccf2004b` | `feat(32-01): add load_test_trusted_root helper + httpmock dev-dep + 5 test scaffolds` | 8 files |

## Deviations from Plan

### Pre-flight Deviation: Task 1 checkpoint satisfied by orchestrator

**Rule:** Not a deviation rule — orchestrator-declared pre-satisfaction.

- **Found during:** Plan initialization
- **Issue:** `TrustedRoot::production()` fails on sigstore-verify 0.6.5 with "Signature threshold of 3 not met for role root"; cannot be run autonomously
- **Fix:** Orchestrator captured fixture from canonical `sigstore/root-signing@main targets/trusted_root.json` and committed to worktree base (`d9969978`)
- **Result:** Task 1 automated verify command passes; no executor action required

### Known Warning: `load_test_trusted_root` dead_code

The `#[cfg(test)] pub(crate) fn load_test_trusted_root()` generates a `dead_code` warning under `cargo build -p nono --tests` because no callers exist yet. This is:
- **Anticipated by the plan:** "Plan 02 will reference this helper in the migrated bundle.rs tests"
- **Not a blocker:** `cargo build` exits 0; the warning is not an error in non-CI mode
- **Pre-existing context:** `make ci` (`cargo clippy -D warnings`) already fails on 2 pre-existing `collapsible_match` errors in `crates/nono/` unrelated to this plan
- **Resolution:** Plan 02 adds the caller, eliminating the warning

## Known Stubs

None — this plan ships only `#[ignore]`'d scaffolds. No stubs that would prevent the plan's goal (providing Wave 0 scaffolding) are present.

## Threat Surface Scan

No new network endpoints, auth paths, or file access patterns introduced. The `load_test_trusted_root()` helper is `#[cfg(test)] pub(crate)` — invisible to production-compiled artifacts. The `httpmock` dev-dependency never appears in the production binary. See threat model T-32-01-01 through T-32-01-05 in the plan for the full disposition.

## Pointers to Downstream Plans

- **Plan 02 (32-02):** Fills in `setup_trust_root.rs` and `keyless_offline_invariant.rs`; adds `load_test_trusted_root()` caller in migrated bundle.rs tests (closes dead_code warning)
- **Plan 03 (32-03):** Fills in `keyless_sign.rs` and `keyless_verify.rs`; lifts `#[ignore]` from all 7 tests
- **Plan 04 (32-04):** Fills in `broker_authenticode.rs` (Windows-only); lifts `#[ignore]` from 6 Windows tests

## Self-Check: PASSED

Verified:
- `test -f crates/nono/tests/fixtures/trust-root-frozen.json` → FOUND
- `test -f crates/nono/src/trust/mod.rs` → FOUND (contains `pub(crate) fn load_test_trusted_root`)
- `test -f crates/nono-cli/Cargo.toml` → FOUND (contains `httpmock = "0.7"`)
- `test -f crates/nono-cli/tests/setup_trust_root.rs` → FOUND
- `test -f crates/nono-cli/tests/keyless_offline_invariant.rs` → FOUND
- `test -f crates/nono-cli/tests/keyless_sign.rs` → FOUND
- `test -f crates/nono-cli/tests/keyless_verify.rs` → FOUND
- `test -f crates/nono-cli/tests/broker_authenticode.rs` → FOUND
- `test -f crates/nono-cli/tests/fixtures/.gitkeep` → FOUND
- Commit `d9969978` → FOUND in git log
- Commit `ccf2004b` → FOUND in git log
