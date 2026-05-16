---
phase: 41-ci-cleanup-v24-broker-code-review-closure
plan: 09
type: summary
status: complete
requirements:
  - REQ-CI-01
closes_gaps:
  - Gap-1
  - Gap-2
  - Gap-3
  - Gap-4
  - Gap-5
  - Gap-6
  - WR-06
depends_on:
  - 41-02
subsystem: ci-cleanup
tags:
  - cross-target-clippy
  - dead-code
  - cfg-gate
  - clippy-manual-inspect
  - REQ-CI-01-SC4
dependency_graph:
  requires:
    - "Plan 41-02 (Unix simple cleanup — established the per-item cfg-gate convention)"
    - "Plan 41-08 (closed REQ-CI-02 BrokerPath gap; this plan continues 41 close-out)"
  provides:
    - "REQ-CI-01 SC#1 + SC#3 achievable on next CI push (Linux Test, Linux Clippy, macOS Clippy lanes should flip RED → GREEN)"
    - "WR-06 close-out (validate_env_var_patterns_local drift risk eliminated via delegation)"
    - "Cleaner SetupRunner contract on non-Windows targets (struct has 4 fields instead of 9; 6 WFP-dependent methods do not exist)"
  affects:
    - "Phase 41 close gate (REQ-CI-01 SC#3 — green lanes on PR head SHA)"
    - "Phase 43 baseline inheritance (no change to baseline SHA; this plan does not move the upstream-sync baseline)"
tech-stack:
  added: []
  patterns:
    - "Inverse cfg_attr direction (cfg_attr(not(target_os = \"windows\"), allow(dead_code))) for Windows-read-only fields — established here as a documented inversion of the existing cfg_attr(target_os = \"windows\", allow(dead_code)) precedent at launch_runtime.rs lines 189 + 194"
    - "Module-level inner cfg attribute (#![cfg(target_os = \"windows\")]) for tests/common/ helpers whose sole callers are Windows-only"
    - "Idiomatic inspect_err for side-effect-only error cleanup (vs the clippy::manual_inspect-flagged map_err(|e| {...; e}) shape)"
key-files:
  created: []
  modified:
    - crates/nono-cli/src/profile_runtime.rs
    - crates/nono-cli/src/exec_strategy_windows/mod.rs
    - crates/nono-cli/src/setup.rs
    - crates/nono-cli/src/launch_runtime.rs
    - crates/nono-cli/tests/common/test_env.rs
    - crates/nono/src/keystore.rs
decisions:
  - "Used #![cfg(target_os = \"windows\")] module-inner attribute on tests/common/test_env.rs (Option (a) in the verifier's recommendations) rather than lifting the windows_run_* test cluster into a separate tests/env_vars_windows.rs file (Option (b)). Minimal-touch + the file is already a Windows-only mirror by callsite contract."
  - "Used per-item #[cfg(target_os = \"windows\")] attributes on the SetupRunner WFP surface (Plan 41-02 pattern) rather than extracting to a #[cfg(target_os = \"windows\")] mod wfp_setup; submodule. Extraction was discussed in 41-VERIFICATION.md as a cleaner option but introduces blast radius risk (moving non-WFP-related code unintentionally) — out of scope for a clippy cleanup pass."
  - "For Task 1, deleted the local copy of validate_env_var_patterns_local rather than cfg-gating it to Windows. Deletion closes both Gap 1 (orphan canonical fn) AND WR-06 (drift-risk duplication) per the verifier's planner-recommended fold-together at 41-VERIFICATION.md § Deferred line 207."
  - "For Task 4, used .inspect_err(|_| ...) (anonymous binding) per the verifier's Gap 6 recommendation, rather than .inspect_err(|_e| ...) (named binding, the existing precedent at keystore.rs:1006). Both work; |_| is more idiomatic and matches the verifier recommendation."
metrics:
  duration: "7m 5s (425 seconds, plan-start to last code commit)"
  completed: "2026-05-16T21:38:48Z"
  tasks_completed: 4
  files_changed: 6
  commits_source: 4
  commits_total: 5
---

# Phase 41 Plan 09: Cross-target gap closure (Linux/macOS clippy + dead-code) Summary

**One-liner:** Closes the 6 -Dwarnings findings from CI run 25972316892 by wiring profile_runtime to the canonical env-var pattern validator (folding WR-06), cfg-gating the WFP SetupRunner surface + interactive_shell field + EnvVarGuard mirror to Windows, and swapping the macOS keystore cleanup-on-error idiom from map_err to inspect_err.

## Status

| Aspect | Value |
|--------|-------|
| Tasks completed | 4 / 4 |
| Source commits | 4 |
| Files modified | 6 (1 file > planned: includes exec_strategy_windows/mod.rs from Task 1 Edit 0) |
| Plan-wide automated checks | All 6 PASS (zero matches for 5 dead-code patterns + zero matches for the lint string in the Gap-6 line range) |
| REQ-CI-01 SC#4 audit | 0 raw `#[allow(dead_code)]` introduced across the diff |
| Local cargo check | clean (nono, nono-cli, nono-cli --tests, nono --lib) |
| Local cargo test | profile_runtime tests pass (2/2); keystore tests pass (126/126) |
| Cross-target Linux/macOS clippy | NOT runnable on Windows dev host without cross-toolchain (load-bearing per memory feedback_clippy_cross_target); decisive signal lives in GH Actions on next PR push |

## Tasks Completed

| Task | Name | Commit | Gap(s) closed | Files |
|------|------|--------|---------------|-------|
| 1 | Wire validate_env_var_patterns delegate + Windows re-export | `05065209` | Gap 1 + WR-06 | `crates/nono-cli/src/profile_runtime.rs`, `crates/nono-cli/src/exec_strategy_windows/mod.rs` |
| 2 | Cfg-gate WFP fields and phase_index methods on SetupRunner | `389c0fae` | Gap 3 + Gap 4 | `crates/nono-cli/src/setup.rs` |
| 3 | Cfg-gate interactive_shell field and EnvVarGuard::set_all mirror | `e97b596e` | Gap 2 + Gap 5 | `crates/nono-cli/src/launch_runtime.rs`, `crates/nono-cli/tests/common/test_env.rs` |
| 4 | Swap map_err to inspect_err in keystore Apple cleanup | `0699c6f4` | Gap 6 | `crates/nono/src/keystore.rs` |

## Task 1: Wire validate_env_var_patterns delegate (Gap 1 + WR-06)

**Commit:** `05065209` — `fix(41-09): wire validate_env_var_patterns delegate + Windows re-export (REQ-CI-01, closes WR-06)`

**What changed:**

1. `crates/nono-cli/src/exec_strategy_windows/mod.rs` — extended the public re-export tuple at line 76 from `pub(crate) use env_sanitization::is_dangerous_env_var;` to `pub(crate) use env_sanitization::{is_dangerous_env_var, validate_env_var_patterns};`. This mirrors the non-Windows precedent at `exec_strategy.rs:50` so the new delegate call (introduced in edit 2 below) resolves on both targets via `crate::exec_strategy::validate_env_var_patterns`.

2. `crates/nono-cli/src/profile_runtime.rs` — three edits:
   - Replaced the `validate_env_var_patterns_local(&env_config.allow_vars, "allow_vars")` call inside the `allowed_env_vars` closure with `crate::exec_strategy::validate_env_var_patterns(&env_config.allow_vars, "allow_vars")`.
   - Replaced the `validate_env_var_patterns_local(&env_config.deny_vars, "deny_vars")` call inside the `denied_env_vars` closure with `crate::exec_strategy::validate_env_var_patterns(&env_config.deny_vars, "deny_vars")`.
   - Deleted the entire `fn validate_env_var_patterns_local(...)` declaration including its doc comment (previously at lines 288-306 of the pre-edit file).
   - Rewrote the leading justification comment (previously a D-34-E1 invariant block) to document the WR-06 close-out and explain why the old "boundary-crossing" rationale was incorrect (the canonical fn lives in `exec_strategy/env_sanitization.rs`, which is platform-agnostic, not in `exec_strategy_windows/`).

**Why:** CI run 25972316892 surfaced the canonical `validate_env_var_patterns` (at `exec_strategy/env_sanitization.rs:127`) as never-used on Linux/macOS because the only caller was the byte-identical local copy in profile_runtime.rs. Wiring the delegate clears both the dead-code lint (Gap 1) AND the byte-identical duplication (WR-06 drift risk).

**Evidence:**

- `grep -c 'validate_env_var_patterns_local' crates/nono-cli/src/profile_runtime.rs` returns `0` (local copy gone — fn definition AND both callers removed).
- Callsite count (the actual `if let Some(err) = crate::exec_strategy::validate_env_var_patterns(...)` pattern, not the comment mention) returns `2`.
- `pub(crate) fn validate_env_var_patterns` in `crates/nono-cli/src/exec_strategy/env_sanitization.rs` unchanged (1 declaration).
- Non-Windows re-export at `exec_strategy.rs:50` unchanged.
- Windows-side re-export tuple now carries both `is_dangerous_env_var` and `validate_env_var_patterns` (1 match for the combined-form regex).
- `cargo check -p nono-cli` succeeds.
- `cargo test -p nono-cli --bin nono profile_runtime`: 2 passed, 0 failed (`absent_environment_block_returns_none`, `empty_allow_vars_fails_closed`).

## Task 2: Cfg-gate SetupRunner WFP fields and phase_index methods (Gaps 3 + 4)

**Commit:** `389c0fae` — `fix(41-09): cfg-gate WFP fields and phase_index methods on SetupRunner (REQ-CI-01)`

**What changed (all in `crates/nono-cli/src/setup.rs`):**

1. **Struct field cfg-gates** — added `#[cfg(target_os = "windows")]` to each of the 5 WFP-related field declarations: `register_wfp_service`, `install_wfp_service`, `install_wfp_driver`, `start_wfp_service`, `start_wfp_driver`.
2. **Constructor field-read cfg-gates** — same 5 attributes prepended to the corresponding `field: args.field` initializers inside `SetupRunner::new(args: &SetupArgs)`. The lockstep gating is required because struct-literal field initialization must syntactically match the field set on the chosen target.
3. **Phase-index method cfg-gates** — prepended `#[cfg(target_os = "windows")]` to each of the 6 method declarations: `register_phase_index`, `install_phase_index`, `start_phase_index`, `install_driver_phase_index`, `start_driver_phase_index`, `recheck_wfp_phase_index`. The 7th method in the same cluster (`any_windows_wfp_action_requested`) was already cfg-gated before this plan and remains untouched.
4. **Test fixture field cfg-gates** — same 5 attributes prepended to the corresponding `field: false,` initializers inside the `setup_profiles` test fixture struct literal. Required per Rust RFC 2342 so the fixture matches the struct's field shape on every target.

**Why:** All 5 WFP boolean fields are only read by the Windows-only WFP setup flow (`#[cfg(target_os = "windows")] fn register_windows_wfp_service`, etc.) and the 6 phase_index methods are only called from those Windows-only flow methods. On Linux/macOS, both the fields and the methods compile but are never exercised, producing the "never read" / "never used" errors under `-Dwarnings`.

**Evidence:**

- Struct fields with cfg gate: `5` (verified by `grep -B 1 -E '^\s+(register|install|start)_wfp_(service|driver): bool,'` piped to `grep -c 'cfg(target_os = "windows")'`).
- Constructor reads with cfg gate: `5`.
- Phase_index methods with cfg gate: `6`.
- Test fixture entries with cfg gate: `5`.
- Raw `#[allow(dead_code)]` additions in the diff: `0` (REQ-CI-01 SC#4 honored).
- `any_windows_wfp_action_requested` declaration count: `1` (unchanged — no duplication).
- `cargo check -p nono-cli` succeeds.
- `cargo check -p nono-cli --tests` succeeds — the test fixture compiles on Windows host.

**Note:** The counter expressions in `total_phases` (lines 649-672 pre-edit, slightly shifted post-edit), `protection_phase_index`, `profiles_phase_index`, and `refresh_trust_root_phase_index` were ALREADY inside `#[cfg(target_os = "windows")] if !self.check_only { ... }` blocks before this plan, so their field reads only fire on Windows already. No additional gating needed on those sites.

## Task 3: Cfg-gate interactive_shell + EnvVarGuard mirror (Gaps 2 + 5)

**Commit:** `e97b596e` — `fix(41-09): cfg-gate interactive_shell field and EnvVarGuard::set_all mirror (REQ-CI-01)`

**What changed:**

1. `crates/nono-cli/src/launch_runtime.rs` — prepended `#[cfg_attr(not(target_os = "windows"), allow(dead_code))]` to the `pub(crate) interactive_shell: bool` field declaration on `ExecutionFlags`, with an inline doc comment explaining (a) where the field is read on Windows (`execution_runtime.rs:411`, `exec_strategy_windows/mod.rs:669,743`, `exec_strategy_windows/supervisor.rs:373,434`) and (b) why the direction inverts the precedent at the adjacent `allowed_env_vars` / `denied_env_vars` fields (those gate on `target_os = "windows"` because they are Unix-read; `interactive_shell` is Windows-read).
2. `crates/nono-cli/tests/common/test_env.rs` — added `#![cfg(target_os = "windows")]` as a module-inner attribute (gates the whole compilation unit) immediately after the doc-comment header. Added a new doc-comment paragraph explaining the Phase-41-Plan-09 rationale.

**Why:** `ExecutionFlags.interactive_shell` is set on every platform (in `ExecutionFlags::defaults`) but read only inside `#[cfg(target_os = "windows")]` blocks, so on Linux/macOS the field is dead-code. The `EnvVarGuard::set_all` integration-test mirror's sole caller (`tests/env_vars.rs:1047` inside the `windows_run_redirects_profile_state_vars_into_writable_allowlist` test) is Windows-only, making the entire mirror file orphan on Linux/macOS.

**Evidence:**

- `interactive_shell` cfg-attr gate count: `1` (precise match for the `not(target_os = "windows")` direction).
- `test_env.rs` inner cfg attribute count: `1` (the `#!` form is the module-level form).
- Precedent at `launch_runtime.rs` lines 189 + 194 (formerly 180 + 185, shifted by my doc-comment addition) unchanged — still uses non-inverted `cfg_attr(target_os = "windows", allow(dead_code))`. Plus one pre-existing module-level `#![cfg_attr(...)]` at line 1 was already there.
- Raw `#[allow(dead_code)]` additions: `0` (REQ-CI-01 SC#4 honored — `cfg_attr(not(...), allow(dead_code))` is a conditional gate, explicitly permitted per the existing precedent at the same struct).
- `cargo check -p nono-cli` succeeds.
- `cargo check -p nono-cli --tests` succeeds.

## Task 4: Swap map_err → inspect_err in keystore Apple cleanup (Gap 6)

**Commit:** `0699c6f4` — `fix(41-09): swap map_err to inspect_err in keystore Apple cleanup (REQ-CI-01)`

**What changed (one-line shape swap in `crates/nono/src/keystore.rs`):**

Before (at lines 1074-1078 pre-edit, inside `#[cfg(target_os = "macos")] load_from_apple_password`):

```rust
.map_err(|e| {
    let _ = child.kill();
    let _ = child.wait();
    e
})?;
```

After:

```rust
.inspect_err(|_| {
    // Kill the process if it timed out
    let _ = child.kill();
    let _ = child.wait();
})?;
```

**Why:** The `.map_err(|e| { ...; e })` shape with a side-effect-only closure that returns the input error unchanged is the canonical `clippy::manual_inspect` pattern. The macOS Clippy lane in CI run 25972316892 escalated this lint to error under `-Dwarnings`. The new shape is behavior-identical (cleanup runs on Err, original error propagates via `?`) and matches the verbatim precedent at `keystore.rs:1006` inside `load_from_op`. The choice of `|_|` over `|_e|` (the precedent uses the named binding) follows the verifier's Gap 6 recommendation for the idiomatic anonymous form.

**Evidence:**

- Line-range scoped grep `sed -n '1068,1080p' crates/nono/src/keystore.rs | grep -c 'map_err'` returns `0` (Gap-6 site cleared).
- `grep -B 1 -A 4 'inspect_err(|_|' crates/nono/src/keystore.rs | grep -c 'child.kill'` returns `1` (new site exists with the kill+wait body).
- `grep -c 'inspect_err(|_e|' crates/nono/src/keystore.rs` returns `1` (the `load_from_op` precedent at line 1006 is untouched).
- Alternative content check `grep -A 2 '.map_err(|e| {' crates/nono/src/keystore.rs | grep -c 'child.kill'` returns `0` (no remaining `.map_err(|e| {` is followed by `child.kill` within 2 lines — the only such combination was the Gap-6 site).
- The file retains 13 other `.map_err(|e| { ... })` sites that transform the error type — these were NOT touched and remain correct.
- `cargo check -p nono --lib` succeeds.
- `cargo test -p nono --lib keystore`: 126 passed, 0 failed (no behavior regression).

**Security note (CLAUDE.md § Fail Secure):** The best-effort cleanup-on-error invariant is preserved verbatim. When `wait_with_timeout` returns `Err`, both `child.kill()` and `child.wait()` run (both results intentionally discarded via `let _ =`) before the original error propagates via `?`. The two combinator forms are semantically identical when the closure returns the input error unchanged.

## Plan-Wide Verification

All 6 checks from the plan's `<verification>` block pass:

| Check | Expected | Actual |
|-------|----------|--------|
| `grep -c 'validate_env_var_patterns_local' crates/nono-cli/src/profile_runtime.rs` | `0` | `0` |
| `interactive_shell` field with `cfg_attr(not(...), allow(dead_code))` gate | `1` | `1` |
| WFP struct fields cfg-gated | `5` | `5` |
| phase_index methods cfg-gated | `6` | `6` |
| `tests/common/test_env.rs` inner module gate `#![cfg(target_os = "windows")]` | `1` | `1` |
| `sed -n '1068,1080p' crates/nono/src/keystore.rs | grep -c 'map_err'` | `0` | `0` |
| REQ-CI-01 SC#4 audit: raw `#[allow(dead_code)]` additions across diff | `0` | `0` |

**Local cargo verification:**

- `cargo check -p nono-cli`: clean
- `cargo check -p nono-cli --tests`: clean
- `cargo check -p nono --lib`: clean
- `cargo test -p nono-cli --bin nono profile_runtime`: 2/2 passed
- `cargo test -p nono --lib keystore`: 126/126 passed

## Deviations from Plan

### [Rule 3 — Plan-internal inconsistency] Task 1 verification grep over-counts due to comment self-mention

**Found during:** Task 1 verification.

**Issue:** The plan's automated `<verify>` check for Task 1 asserts `test "$(grep -c 'crate::exec_strategy::validate_env_var_patterns' crates/nono-cli/src/profile_runtime.rs)" = '2'`. However, the plan's prescribed Edit-2a comment block (which I applied verbatim) contains the literal string `crate::exec_strategy::validate_env_var_patterns` once inside a doc comment. With both call-sites correctly delegating AND the prescribed comment intact, the literal grep count is `3` (1 comment + 2 call-sites), not `2`.

**Fix:** No code change. I verified the semantic invariants via more precise greps:
- Call-site-only count (`grep -E '^\s+if let Some\(err\) = crate::exec_strategy::validate_env_var_patterns\('`): `2` ✓
- Comment-mention count: `1` ✓
- Local-copy count (`validate_env_var_patterns_local`): `0` ✓

The plan's `<acceptance_criteria>` includes the same `= 2` literal grep but ALSO includes more precise checks ("local copy is gone", "fn declaration is gone", "canonical fn remains untouched", "re-export at exec_strategy.rs:50 remains untouched") all of which pass. The behavior is correct; the literal grep was overly broad given the plan's own prescribed comment text.

**Files modified:** None additional (this is a verification-grep inconsistency in the plan, not a code drift).

**Commit:** N/A (documented here per deviation policy).

### [No Rule 4 architectural deviations encountered.]

## Known Stubs

None — this plan is a pure dead-code cleanup + idiom swap pass. No stubs introduced.

## Threat Flags

None — all 6 gaps are dead-code lints + one combinator idiom swap. No trust boundaries crossed, added, or modified. The keystore.rs change preserves the cleanup-on-error invariant verbatim (best-effort `child.kill()` + `child.wait()` still runs when `wait_with_timeout` errs). The threat register in the plan (T-41-09-01 through T-41-09-04) all carry `mitigate` dispositions that this plan addresses.

## Deferred Items (carry-forward)

The 7 WARNINGS (WR-01..WR-08 minus WR-06 which Task 1 closed) remain backlog per the user's "Blocker only" scope discipline established in the prior 41-08 pass. See `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-VERIFICATION.md` § Deferred (Backlog) for full table. Not in scope for this plan.

## Lesson Reinforced

**Cross-target clippy is load-bearing.** Locally satisfying `cargo check` on Windows is necessary but NOT sufficient. CI run 25972316892 surfaced 6 errors that were structurally invisible to the Windows-host verification of Phase 41-08 because the prior verifier honestly documented cross-target Linux clippy as SKIPPED. This plan re-validates memory `feedback_clippy_cross_target` (Phase 25 CR-A regression lesson): for any Phase 41-style cleanup touching cfg-gated Unix code, the cross-target Linux clippy gate must be run (or the verifier must surface the SKIP as the load-bearing risk it is). The lesson generalizes beyond Phase 41 to every future plan that touches platform-conditional symbols.

This plan does NOT close that gap in the local tooling. The cross-toolchain (`x86_64-unknown-linux-gnu` target on Windows host) is not present in this dev environment. The decisive signal for REQ-CI-01 SC#1 + SC#3 lives in GitHub Actions on the next PR push, which is captured in the plan's `human_verification_truths` and the SUMMARY's status table above.

## Live CI Verification — Pending

The codebase-level fix is complete. CI is the decisive signal per REQ-CI-01 SC#1 + SC#3:

- On the next push to the Phase 41 PR head, GH Actions Linux Test (job class 76346400920), Linux Clippy (job class 76346400927), and macOS Clippy (job class 76346400923) lanes are expected to transition from RED to GREEN.
- No occurrence of the following strings is expected in the new lane logs: `function 'validate_env_var_patterns' is never used`, `field 'interactive_shell' is never read`, `fields 'register_wfp_service'`, `methods 'register_phase_index'`, `associated function 'set_all' is never used`, `using 'map_err' over 'inspect_err'`.

Status at SUMMARY-write time: **pending next PR push** (codebase-level fix complete; live CI lane status to be observed post-push).

## Self-Check: PASSED

All claims in this SUMMARY have been verified:

**Files created/modified (all confirmed exist with expected changes):**
- `crates/nono-cli/src/profile_runtime.rs` — FOUND, contains 2 delegate calls, 0 `validate_env_var_patterns_local` references
- `crates/nono-cli/src/exec_strategy_windows/mod.rs` — FOUND, contains the combined re-export tuple
- `crates/nono-cli/src/setup.rs` — FOUND, contains 5 + 5 + 6 + 5 = 21 new cfg attributes
- `crates/nono-cli/src/launch_runtime.rs` — FOUND, contains the `cfg_attr(not(...), ...)` gate on `interactive_shell`
- `crates/nono-cli/tests/common/test_env.rs` — FOUND, contains `#![cfg(target_os = "windows")]`
- `crates/nono/src/keystore.rs` — FOUND, Gap-6 line range is clean of `map_err`

**Commits (all confirmed in `git log --oneline`):**
- `05065209` Task 1
- `389c0fae` Task 2
- `e97b596e` Task 3
- `0699c6f4` Task 4
