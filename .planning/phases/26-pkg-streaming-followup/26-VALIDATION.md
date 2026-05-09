---
phase: 26
slug: pkg-streaming-followup
status: partial
nyquist_compliant: partial
wave_0_complete: true
created: 2026-05-09
---

# Phase 26 — Validation Strategy

> Retroactive Nyquist audit. Phase 26 ships in two plans:
> - **Plan 26-01** (REQ-PKGS-02 + REQ-PKGS-03) — executed 2026-04-29 / closed 2026-05-01. Nyquist audit complete; 1 gap filled this audit.
> - **Plan 26-02** (REQ-PKGS-01 + REQ-PKGS-04) — plan + CONTEXT committed; execution **queued for v2.4 follow-up** (Linux/macOS host required for streaming RSS measurement + run_nono e2e tests post-`NONO_TEST_HOME` seam landing).
>
> Phase 26 is recorded as **PARTIAL** at the milestone level. Nyquist coverage for the executed surface (Plan 26-01) is complete after this audit.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust built-in) |
| **Config file** | `crates/nono-cli/Cargo.toml` (test target gated by `[[bin]]` — nono-cli has NO library target) |
| **Test target flag** | `--bin nono` (required; `--lib` fails with "no library targets found") |
| **Quick run command** | `cargo test -p nono-cli --bin nono -- <test_name>` |
| **Full suite command** | `cargo test --workspace` |
| **Plan 26-01 module** | `crates/nono-cli/src/package_cmd.rs::tests` (line 1153) and `crates/nono-cli/src/package.rs::tests` (line 323) |
| **Estimated runtime** | ~6s targeted; ~3 min workspace-wide |

---

## Sampling Rate

- **After every task commit:** `cargo build --workspace` + targeted test for the touched requirement.
- **After every plan wave:** `cargo test -p nono-cli --bin nono` (full nono-cli surface, ~836 tests + new additions).
- **Before `/gsd-verify-work`:** `make ci` must be green modulo documented carry-overs (2 pre-existing `nono::manifest` `collapsible_match` clippy errors and 2 pre-existing TUF integration failures from `869349df` baseline; carried per Plan 22-03 § Out-of-scope #5).
- **Max feedback latency:** ~10s for targeted; ~3min for full.

---

## Per-Task Verification Map

### Plan 26-01 — PKG fork-architectural decisions (executed 2026-04-29)

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 26-01-01 | 01 | 1 | PKGS-02 | T-26-01-01 (Tampering — `..` traversal) | `validate_relative_path` rejects `..` Path components at input-string layer before any filesystem syscall | unit | `cargo test -p nono-cli --bin nono -- validate_relative_path_rejects_traversal` | ✅ | ✅ green |
| 26-01-01 | 01 | 1 | PKGS-02 | T-26-01-02 (Tampering — absolute path) | `validate_relative_path` rejects Unix `/foo` and (Windows-host) `C:\foo`, `\\server\share` shapes | unit | `cargo test -p nono-cli --bin nono -- validate_relative_path_rejects_absolute_path` | ✅ | ✅ green |
| 26-01-01 | 01 | 1 | PKGS-02 | T-26-01-03 (Tampering — symlink-traversal) | `validate_path_within` (canonicalize-and-component-compare, line 1043) rejects symlink-resolved escapes from `staging_root`; defense-in-depth posture preserved | unit | `cargo test -p nono-cli --bin nono -- validate_path_within_rejects_symlink_escape` | ✅ | ✅ green |
| 26-01-02 | 01 | 1 | PKGS-03 | T-26-01-04 (Tampering — unknown variant) | `ArtifactType::Plugin` round-trips JSON `"plugin"` via `#[serde(rename_all = "snake_case")]` | unit | `cargo test -p nono-cli --bin nono -- artifact_type_plugin_round_trips` | ✅ | ✅ green |
| 26-01-02 | 01 | 1 | PKGS-03 | T-26-01-04 (Tampering — unknown variant) | Unknown `artifact_type` JSON values (`"made_up_variant"`, `"PLUGIN"`, non-string) deserialize as `Err` (fail-closed; no silent coercion to default or to filename-fallback `Script`) | unit | `cargo test -p nono-cli --bin nono -- artifact_type_unknown_fails_closed` | ✅ | ✅ green |
| 26-01-03 | 01 | 1 | PKGS-03 | — | `ArtifactType::Plugin` match arms exhaustive across 1+ enum-discriminant site in `package_cmd.rs`; deferred-divergence comment removed | build-gate | `cargo build --workspace` (non-exhaustive match would surface here) | ✅ | ✅ green |
| 26-01-D19 | 01 | 1 | PKGS-02 + PKGS-03 | — | D-19 byte-identical preservation: `crates/nono/` untouched across the plan | grep-gate | `git diff --stat <baseline>..HEAD -- crates/nono/ \| wc -l` returns `0` | ✅ | ✅ green (verified at SUMMARY time) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

### Plan 26-02 — PKG streaming + auto-pull (NOT EXECUTED)

| Task ID | Plan | Requirement | Status | Notes |
|---------|------|-------------|--------|-------|
| 26-02-* | 02 | PKGS-01 | ⬜ deferred | Streaming refactor port of upstream `9ebad89a`. Execution queued for v2.4 — requires Linux/macOS host (`proc_self_status` RSS measurement). |
| 26-02-* | 02 | PKGS-04 | ⬜ deferred | Registry auto-pull. Execution queued for v2.4 — `run_nono` harness depends on `dirs::home_dir()` Windows seam landed in Phase 27.1 (`NONO_TEST_HOME`); revisit on a Linux/macOS host. |

Plan 26-02 validation contract will be authored when Plan 26-02 is scheduled for execution. Out of scope for this audit.

---

## Wave 0 Requirements

Existing test infrastructure (Rust `cargo test` + the `tempfile` crate already in `crates/nono-cli/Cargo.toml:73`) covers all Plan 26-01 requirements. No Wave 0 framework installation needed.

---

## Manual-Only Verifications

All Plan 26-01 phase behaviors have automated verification after this audit (the prior gap on truth #7 is now closed by `validate_path_within_rejects_symlink_escape`).

One privilege-conditional behavior:

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Symlink creation on Windows without Developer Mode / SeCreateSymbolicLink privilege | PKGS-02 truth #7 | `std::os::windows::fs::symlink_dir` returns `Err` on hosts lacking the privilege; the regression test early-returns in that case (NOT `#[ignore]`). On a privilege-missing host, validation of the canonicalize-and-compare layer falls back to manual review of `validate_path_within` invariants. | Run on a host with the symlink privilege (the current dev box satisfies this — verified 2026-05-09). The test prints `skipping symlink test` to stderr only when privilege is missing. |

---

## Validation Audit 2026-05-09

| Metric | Count |
|--------|-------|
| Requirements in Plan 26-01 scope | 2 (PKGS-02, PKGS-03) |
| Truths declared (must_haves.truths) | 12 |
| Truths with automated tests | 5 (#5, #6, #7, #8, #9) |
| Truths covered by build/grep/CI gates | 7 (#1, #2, #3, #4, #10, #11, #12) |
| Gaps found | 1 (truth #7) |
| Resolved | 1 (truth #7 — `validate_path_within_rejects_symlink_escape` added) |
| Escalated | 0 |
| Plan 26-02 scope | 2 reqs (PKGS-01, PKGS-04) — execution deferred to v2.4; out of scope for this audit |

---

## Validation Sign-Off

- [x] All Plan 26-01 tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (none — no framework install needed)
- [x] No watch-mode flags
- [x] Feedback latency < 10s targeted, < 3min full
- [ ] `nyquist_compliant: true` — set to `partial` because Plan 26-02 is unexecuted; will flip to `true` only after Plan 26-02 executes and a follow-up validation pass closes PKGS-01 + PKGS-04 truths.

**Approval:** approved 2026-05-09 (Plan 26-01 surface only)

---

## Validation Audit 2026-05-09 (re-audit)

Re-confirmed compliance at HEAD via fresh `cargo test -p nono-cli --bin nono -- validate_relative_path_rejects_traversal validate_relative_path_rejects_absolute_path validate_path_within_rejects_symlink_escape artifact_type_plugin_round_trips artifact_type_unknown_fails_closed`: **5 passed; 0 failed; 0 ignored** (~9 s targeted, includes build). All Per-Task Map runtime rows remain green.

Documentation drift corrected on one must-have grep gate (cosmetic only — runtime behavior was always satisfied):

| Row | Drift | Fix |
|-----|-------|-----|
| Plan must-have truth #2 | Documented `grep -c 'fn validate_path_within' crates/nono-cli/src/package_cmd.rs` = "exactly 1" (production fn definition only). At HEAD this returns 2 — production fn at line 1043 + new test fn name `validate_path_within_rejects_symlink_escape` at line 1210, which shares the `fn validate_path_within` substring. Same overlap pattern truth #1 already documents for `fn validate_relative_path` (3 matches: 1 production + 2 test fn names). | Production-fn count of 1 verifiable by line-by-line inspection: `crates/nono-cli/src/package_cmd.rs:1043` is the only `fn validate_path_within(base: &Path, full: &Path) -> Result<()>` definition. The line-1210 match is the regression test added during the original 2026-05-09 audit to close truth #7 — its function-name overlap with truth #2's grep pattern is benign. Defense-in-depth posture (truth #2 substance) is unchanged. |

| Metric | Count |
|--------|-------|
| Gaps found | 0 (runtime); 1 (cosmetic grep-gate drift on truth #2) |
| Resolved | 1 (cosmetic — documented inline above) |
| Escalated | 0 |
| New tests written | 0 |
| Existing tests verified | 5 (all green at HEAD) |
| `nyquist_compliant` status | unchanged: `partial` (Plan 26-02 still queued for v2.4; will flip to `true` only after Plan 26-02 executes and a follow-up validation pass closes PKGS-01 + PKGS-04 truths) |
