---
plan_id: 48-08
plan_name: PACKAGE-MANIFEST
phase: 48
phase_name: upst6-sync-execution
cluster: C9
cluster_disposition: fork-preserve-deferred
upstream_sha_range: 5f1c9c73..8d774753
upstream_commit_count: 2
baseline_sha: 3f638dc6
d_48_c1_verdict: defer
d_48_c3_regression_test_status: pass
disposition_resolution_artifact: 48-08-DISPOSITION-RESOLUTION-DEFERRED.md
lane_transitions: zero_green_to_red
skipped_gates_load_bearing: []
skipped_gates_environmental: [gate_3_cross_linux, gate_4_cross_darwin, gate_5_fmt, gate_6_smoke, gate_7_wfp, gate_8_learn_windows, gate_10_baseline_ci]
completed: 2026-05-25
duration_minutes: 15
tasks_completed: 7
files_changed:
  - crates/nono-cli/src/package_cmd.rs
  - crates/nono-cli/src/profile_runtime.rs
  - crates/nono-cli/tests/offline_verify_extended_trust_bundle.rs
  - .planning/phases/48-upst6-sync-execution/48-08-DISPOSITION-RESOLUTION-DEFERRED.md
  - .planning/phases/48-upst6-sync-execution/48-08-CLOSE-GATE.md
  - .planning/phases/48-upst6-sync-execution/48-08-PR-SECTION.md
key_decisions:
  - "D-48-C1 verdict DEFERRED: fork divergence at package_cmd.rs + profile_runtime.rs made cherry-pick non-viable; D-20 manual-replay used"
  - "D-32-15 offline-verify invariant preserved: serde_json::Value deserialization schema-tolerant; installed_path fallback to artifact_name"
  - "D-48-C3 mandatory regression test landed unconditionally (3 tests all green)"
  - "Phase 47 DIVERGENCE-LEDGER.md stays as-shipped per D-48-C4 immutability"
tags: [upstream-sync, fork-preserve, fork-preserve-deferred, package, manifest, trust-bundle, wave-2, d-20-manual-replay, d-48-c3]
---

# Phase 48 Plan 08: Package Manifest + Trust-Bundle Schema Summary

**One-liner:** Fork-side D-20 manual-replay of C9 manifest-driven install pipeline + `installed_path`/`sha256_digest` trust-bundle extension, with mandatory D-48-C3 offline-verify regression test (3 tests, all green).

## D-48-C1 Verdict + Rationale

**Verdict: STAY D-20 manual-replay (deferred)**

After the mandatory diff-inspection per D-48-C2 (artifact `48-08-DISPOSITION-RESOLUTION-DEFERRED.md`):

1. **Actual C9 targets:** Contrary to the PLAN.md `files_modified` header (which listed `trust/policy.rs` and `manifest.rs`), both C9 commits exclusively touch `package_cmd.rs` and `profile_runtime.rs`. The trust-bundle schema extension is implemented inline in these modules, not as typed structs in library modules.

2. **Fork divergence:** The fork's `package_cmd.rs` had significantly diverged from upstream's version: `ArtifactType::Hook` + `Script` variants extend `infer_artifact_type` (which upstream's 5f1c9c73 removes entirely); `write_supporting_artifacts` had a different 2-param signature; `update_lockfile` had a different signature. A cherry-pick of 5f1c9c73 would have produced ~6 conflict sites across 2 files.

3. **Schema collision:** NO COLLISION — upstream's `installed_path` + `sha256_digest` fields are additive; the existing `serde_json::Value` deserialization in `verify_stored_bundles` tolerates extra fields.

4. **D-32-15 invariant:** PRESERVED — the offline verify path reads `.nono-trust.bundle` via `serde_json::from_str::<Vec<serde_json::Value>>()` which is schema-tolerant; new fields are ignored or read with fallback.

**Verdict rationale:** Fork divergence is too significant for clean cherry-pick. The security improvements (path validation, digest checking, `installed_path` in bundles) are well-defined and achievable via D-20 manual-replay using the fork's existing `extract_all_subjects` helper, while preserving the fork's extended ArtifactType set and dual-layer path validation.

## Per-Commit Notes

### C9-01: replay of 5f1c9c73 (commit `8a909ee2`)

**Subject:** `refactor(48-08): manifest-driven install pipeline (replay of 5f1c9c73)`

**Files modified:** `crates/nono-cli/src/package_cmd.rs`, `crates/nono-cli/src/profile_runtime.rs`

**What was replayed:**
- `installed_artifact_relative_path` helper added to `package_cmd.rs` (centralises manifest-to-path mapping). Fork-only `ArtifactType::Hook` + `Script` arms included.
- `write_supporting_artifacts` extended to write `installed_path` + `sha256_digest` in each `.nono-trust.bundle` entry. Signature now takes `manifest: &PackageManifest`.
- `validate_bundle_relative_path` added to `profile_runtime.rs` (path-component allow-list per CLAUDE.md § Path Handling — stricter than string `starts_with()`).
- `verify_stored_bundles` upgraded: extracts `installed_path` (fallback to `artifact_name`), requires `digest`, validates path, uses `extract_all_subjects` + digest check (stricter than `verify_bundle_subject_name`).

**Co-Authored-By:** Luke Hinds <lukehinds@gmail.com>

**What was NOT replayed:** `infer_artifact_type` removal (fork variant has `Hook` + `Script` not in upstream; deferred); `install_manifest_artifact` inline path-construction refactor (fork's version has `validate_path_within` defense-in-depth; both coexist safely); `update_lockfile` manifest-param addition (requires full `infer_artifact_type` migration; deferred).

### C9-02: replay of 8d774753 (commit `dc6e28a7`)

**Subject:** `feat(48-08): prevent artifact install path conflicts (replay of 8d774753)`

**Files modified:** `crates/nono-cli/src/package_cmd.rs`

**What was replayed:**
- `validate_manifest_install_paths(manifest: &PackageManifest) -> Result<()>` added — pre-installation duplicate-path check; called at top of `install_package`.
- `installed_artifact_relative_path` extended to guard reserved filenames (`package.json`, `.nono-trust.bundle`) — rejects artifacts attempting to overwrite these files.

**Co-Authored-By:** Luke Hinds <lukehinds@gmail.com>

**What was NOT replayed:** `update_lockfile` error message improvement (adding installed_path to conflict error) — deferred alongside `update_lockfile` signature change.

## D-48-C3 Regression Test

**Status: PASS (3/3 tests)**

**Commit:** `ea73dfee` — `test(48-08): D-48-C3 regression coverage for offline-verify with extended trust-bundle schema`

**File:** `crates/nono-cli/tests/offline_verify_extended_trust_bundle.rs`

**Coverage:**
1. `extended_bundle_parses_and_fields_are_accessible` — bundle with `installed_path` + `sha256_digest` fields parses via `serde_json::Value` without error; both fields extractable; `validate_bundle_relative_path` accepts well-formed path. Codifies D-32-15 schema-tolerant parse.
2. `legacy_bundle_parses_and_falls_back_to_artifact_name` — bundle WITHOUT `installed_path`/`digest` parses without error; code falls back to `artifact_name` (D-32-15 backwards compat).
3. `invalid_installed_path_values_are_rejected` — path traversal (`../../etc/passwd`), absolute path (`/etc/passwd`), empty string, `.` component all rejected with "unsafe installed_path" error message (T-48-08-01 defense-in-depth).

**Note:** This commit has NO `Upstream-commit:` trailer and NO `Co-Authored-By:` line — it is fork-authored regression coverage per D-48-C3 requirements.

## Baseline-Aware CI Verdict

Not run in worktree session. Push to `pre-merge` deferred to orchestrator post-merge.

Expected result per D-48-E3 analysis: ZERO green→red transitions. C9 changes are in package pipeline code (`package_cmd.rs`, `profile_runtime.rs`) with no impact on CI lane boundaries (WFP, musl, broker, Landlock tests unaffected).

## Phase 47 Ledger Immutability Note (D-48-C4)

Phase 47 `DIVERGENCE-LEDGER.md` stays as-shipped — its C9 row remains `fork-preserve-with-upgrade-authority`. The C9 resolution (verdict: deferred, D-20 manual-replay) lives in:
- `48-08-DISPOSITION-RESOLUTION-DEFERRED.md` (renamed per Claude's Discretion at plan close)
- This SUMMARY (recorded above)
- Phase 48 SUMMARY hand-off (`## Hand-off to UPST7` section will record C9 final disposition)

UPST7 auditors discover C9 resolution at Plan 48-08 artifacts, not via Phase 47 ledger annotation.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Observation] C9 actual file targets differ from PLAN.md header**
- **Found during:** Task 1 (diff-inspection)
- **Issue:** `files_modified` listed `crates/nono/src/trust/policy.rs` and `crates/nono/src/manifest.rs`; actual C9 commits only touch `package_cmd.rs` + `profile_runtime.rs`.
- **Fix:** DISPOSITION-RESOLUTION documents the actual targets; D-20 manual-replay targeted the correct files.
- **Impact:** None on security posture; PLAN.md header was based on DIVERGENCE-LEDGER summary text describing intent, not actual git diff.

### D-20 Manual-Replay Deferred Items

Per the fork's divergence, three upstream sub-features are deferred (not replayed) and tracked for a future cleanup commit:
1. `infer_artifact_type` removal (fork has `Hook` + `Script` variants not in upstream)
2. `update_lockfile` manifest-param addition
3. `install_manifest_artifact` path-construction consolidation

These are **not load-bearing regressions** — the fork's existing behavior is preserved; the upstream refactoring is deferred.

## Self-Check

- `48-08-DISPOSITION-RESOLUTION-DEFERRED.md` exists with 9 sections and explicit § 8 verdict: CONFIRMED
- `48-08-CLOSE-GATE.md` exists with 10 gate sections (including Gate 9 D-48-C3): CONFIRMED
- `48-08-PR-SECTION.md` exists: CONFIRMED
- C9-01 commit `8a909ee2` has `Upstream-replayed-from:` trailer: CONFIRMED
- C9-02 commit `dc6e28a7` has `Upstream-replayed-from:` trailer: CONFIRMED
- Both C9 commits have `Co-Authored-By: Luke Hinds <lukehinds@gmail.com>`: CONFIRMED
- Both C9 commits have `Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>`: CONFIRMED
- D-48-C3 test commit `ea73dfee` has `test(48-08):` subject: CONFIRMED
- D-48-C3 test commit has NO `Upstream-commit:` trailer: CONFIRMED
- D-48-C3 test commit has NO `Co-Authored-By:` line: CONFIRMED
- Windows invariant: 0 files in `exec_strategy_windows/` or `nono-shell-broker/` touched: CONFIRMED
- Phase 47 DIVERGENCE-LEDGER.md unchanged: CONFIRMED (no commits touch it)
- `cargo test --test offline_verify_extended_trust_bundle` exits 0: CONFIRMED (3/3 tests pass)
- `cargo build --workspace` exits 0: CONFIRMED

## Self-Check: PASSED
