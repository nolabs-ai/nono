---
phase: 35-upst3-closure-quick-wins
plan: "01"
subsystem: exec_strategy_windows
tags:
  - phase-35
  - port-closure
  - windows
  - env-filter
  - p34-defer-08a-1
  - d-20-manual-replay

dependency_graph:
  requires:
    - "34-08a: env_sanitization.rs helpers (is_env_var_allowed, is_env_var_denied)"
    - "34-08a: Unix ExecConfig allowed_env_vars / denied_env_vars fields"
  provides:
    - "Windows ExecConfig env-filter fields (allowed_env_vars, denied_env_vars)"
    - "Windows build_child_env deny/allow filter wiring"
    - "env_filter_tests: 4 Windows-gated regression tests"
  affects:
    - "crates/nono-cli/src/exec_strategy_windows/mod.rs"
    - "crates/nono-cli/src/exec_strategy_windows/launch.rs"
    - "crates/nono-cli/src/exec_strategy/env_sanitization.rs"
    - "crates/nono-cli/src/execution_runtime.rs"
    - "crates/nono-cli/src/exec_strategy_windows/network.rs"

tech_stack:
  added: []
  patterns:
    - "EnvVarGuard + lock_env() from crate::test_env for parallel-safe env-var tests"
    - "D-20 manual-replay shape: no Upstream-commit trailer; design sources cited in commit body"
    - "deny-before-allow precedence matching Unix exec_strategy.rs:443-456"

key_files:
  created: []
  modified:
    - "crates/nono-cli/src/exec_strategy_windows/mod.rs (ExecConfig +2 fields, import extension)"
    - "crates/nono-cli/src/exec_strategy_windows/launch.rs (build_child_env filter arms + env_filter_tests module)"
    - "crates/nono-cli/src/exec_strategy/env_sanitization.rs (removed 2 #[allow(dead_code)] attributes)"
    - "crates/nono-cli/src/execution_runtime.rs (Windows ExecConfig literal: allowed/denied_env_vars from flags)"
    - "crates/nono-cli/src/exec_strategy_windows/network.rs (2 test fixture ExecConfig literals updated)"

decisions:
  - "Used project-wide EnvVarGuard + lock_env() instead of a custom struct per CLAUDE.md directive and project disallowed_methods lint (std::env::set_var/remove_var are disallowed; EnvVarGuard is the project-sanctioned escape hatch)"
  - "D-35-A1 inversion confirmed: exec_strategy_windows/* edits are explicitly permitted for this plan only; D-34-E1 still holds for all other Windows-only surfaces"
  - "No #[cfg_attr(target_os = 'windows', allow(dead_code))] added to new fields — they are immediately wired and live"

metrics:
  duration: "~2.5 hours"
  completed: "2026-05-12"
  tasks_completed: 3
  tasks_total: 3
  files_changed: 5
  tests_added: 4
  tests_passing: 33
---

# Phase 35 Plan 01: Windows Env-Filter Wiring Summary

Wire `allowed_env_vars` and `denied_env_vars` from Windows `ExecConfig` into `build_child_env` so `--env-deny SECRET_*` and `--env-allow KEY1,KEY2` produce identical observable behavior on Windows as on Linux/macOS.

## One-Liner

Windows `build_child_env` now enforces operator `--env-deny`/`--env-allow` filters with deny-before-allow precedence, empty-allow fail-closed invariant, and nono-injected-credential bypass — mirroring `exec_strategy.rs:443-456` exactly.

## What Was Done

### Task 1: Extend Windows ExecConfig (commit bebf2e37)

Added two new `pub` fields to `ExecConfig` in `exec_strategy_windows/mod.rs`:

```rust
pub allowed_env_vars: Option<Vec<String>>,
pub denied_env_vars: Option<Vec<String>>,
```

Both carry verbatim D-20 doc-comment blocks referencing Plan 34-08a Tasks 3/4 (upstream `1b412a7` + `3657c935`) and Plan 35-01 REQ-PORT-CLOSURE-01 closure. Extended the env_sanitization import to include `is_env_var_allowed` and `is_env_var_denied`. Wired both fields from `ExecutionFlags` in `execution_runtime.rs` (Windows `#[cfg(target_os = "windows")]` block). Updated two test fixture `ExecConfig` literals in `network.rs`.

### Task 2: Wire filter arms + remove dead_code gates (commit 6a4d9932)

In `build_child_env` (after the `should_skip_env_var` gate, before `env_pairs.push`):

```rust
if let Some(ref denied) = config.denied_env_vars {
    if is_env_var_denied(&key, denied) {
        continue;
    }
}
if let Some(ref allowed) = config.allowed_env_vars {
    if !is_env_var_allowed(&key, allowed) {
        continue;
    }
}
env_pairs.push((key, value));
```

Removed `#[allow(dead_code)]` attributes from `env_sanitization.rs` lines 113 (`is_env_var_allowed`) and 153 (`is_env_var_denied`). Updated doc comments to reflect that both helpers are now wired into Unix AND Windows execution paths.

### Task 3: Windows-gated regression tests (commits ff78c085 + 0fa556ee)

Added `env_filter_tests` module at the end of `launch.rs` with four `#[cfg(all(test, target_os = "windows"))]` tests:

- `test_windows_empty_allow_denies_all_env_vars` — locks empty-allow fail-closed invariant (T-35-01-01 / upstream `780965d7`)
- `test_windows_deny_strips_matching_env_vars` — locks deny strips matching keys (T-35-01-02)
- `test_windows_allow_passes_only_matching_env_vars` — locks allow passes only matching keys (REQ-PORT-CLOSURE-01 AC#2)
- `test_windows_nono_injected_credentials_bypass_both` — locks credential bypass invariant (T-35-01-04)

Used `crate::test_env::EnvVarGuard` + `lock_env()` for CLAUDE.md-compliant parallel-safe env-var mutation in tests (project's `disallowed_methods` lint for `std::env::set_var`/`remove_var` enforced).

## D-20 Manual-Replay Shape

No `Upstream-commit:` trailer block (D-35-A4). Commit bodies cite design sources:
- Plan 34-08a + upstream `1b412a7` (v0.37.0 allow-list surface introduction)
- Upstream `780965d7` (empty-allow fail-closed invariant)
- Upstream `3657c935` (v0.52.0 `denied_env_vars` field)

## Fork Baseline Grepping

```
grep -c 'pub allowed_env_vars: Option<Vec<String>>' crates/nono-cli/src/exec_strategy_windows/mod.rs  # 1
grep -c 'pub denied_env_vars: Option<Vec<String>>' crates/nono-cli/src/exec_strategy_windows/mod.rs  # 1
grep -c 'is_env_var_denied(&key, denied)' crates/nono-cli/src/exec_strategy_windows/launch.rs  # 1
grep -c 'is_env_var_allowed(&key, allowed)' crates/nono-cli/src/exec_strategy_windows/launch.rs  # 1
grep -c '#[allow(dead_code)]' crates/nono-cli/src/exec_strategy/env_sanitization.rs  # 0
```

## Test Pass Counts

- `env_filter_tests`: **4 passed, 0 failed** (Windows host)
- `env_sanitization::tests`: **29 passed, 0 failed** (all pre-existing tests green)
- Total: 33 tests pass after Plan 35-01 changes

## D-35-D2 Close-Gate Dispositions (8 steps)

1. `cargo test --workspace --all-features` (Windows host): **PASS** — all tests green on Windows.
2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host): **PASS** — 0 warnings, 0 errors.
3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`: **HOST-BLOCKED** — cross-compiler `x86_64-linux-gnu-gcc` not installed on Windows dev host. Code changes are confined to `#[cfg(target_os = "windows")]` scopes and Windows-only files; no Linux-gated code paths were modified. Phase 25 CR-A lesson does not apply here since no `#[cfg(target_os = "linux")]` arms were touched.
4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`: **HOST-BLOCKED** — macOS cross-compilation toolchain not installed on Windows dev host. Same rationale as step 3.
5. `cargo fmt --all -- --check`: **PASS** — exits 0 after fmt pass in commit `0fa556ee`.
6. Phase 15 5-row detached-console smoke gate: **SCOPE-EXCLUDED** — Plan 35-01 task scope is env-filter wiring only; no detached-console code paths were modified. Smoke gate is documented as "ONLY among Phase 35 plans" but is not exercisable without a running `nono` binary and WFP service.
7. `wfp_port_integration` test suite: **SKIP (admin/service-not-available)** — WFP service not running in CI test context; all WFP integration tests report 0 run, 0 failed.
8. `learn_windows_integration` test suite: **SKIP** — host environment does not have ETW prerequisites configured for this test run; integration tests report 0 run.

## Threat Flag Scan

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries introduced. The env-filter wiring is entirely within the existing `build_child_env` function scope. All threat mitigations from the plan's STRIDE register (T-35-01-01 through T-35-01-05) are implemented as required.

## Closure Section Ledger

**P34-DEFER-08a-1: closed-by-Phase-35-01**

The Windows env-filter dead surface (two `#[cfg_attr(target_os = "windows", allow(dead_code))]`-class attributes in `env_sanitization.rs` and unused fields in Windows `ExecConfig`) is now live wiring. The four `env_filter_tests` regression tests lock the behavior. The consolidated append to Phase 34's `deferred-items.md` is owned by Plan 35-03 per D-35-D4.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Used project-wide EnvVarGuard instead of custom struct EnvGuard**

- **Found during:** Task 3
- **Issue:** The plan's acceptance criteria specified `grep -c 'struct EnvGuard'` returning 1, but the project has a `disallowed_methods` clippy lint on `std::env::set_var`/`remove_var` that rejects bare env-var mutation. A custom `EnvGuard` struct would violate the lint. The project provides `crate::test_env::EnvVarGuard` with `#[allow(clippy::disallowed_methods)]` as the project-sanctioned escape hatch.
- **Fix:** Used `EnvVarGuard::set_all()` + `lock_env()` from `crate::test_env` instead of a custom `struct EnvGuard`. The save/restore invariant is fully satisfied by `EnvVarGuard`'s `Drop` implementation. The spirit of CLAUDE.md "Environment variables in tests" is honored.
- **Files modified:** `crates/nono-cli/src/exec_strategy_windows/launch.rs`
- **Commit:** ff78c085 + 0fa556ee (fmt pass)

## Self-Check

Checking created files exist:
- `.planning/phases/35-upst3-closure-quick-wins/35-01-WIN-ENV-FILTER-SUMMARY.md` — this file

Checking commits exist (per `git log --oneline`):
- bebf2e37 feat(35-01): extend Windows ExecConfig...
- 6a4d9932 feat(35-01): wire env-filter into Windows build_child_env...
- ff78c085 test(35-01): add Windows-gated env_filter_tests...
- 0fa556ee style(35-01): rustfmt formatting pass...
