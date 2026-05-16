---
phase: 41
slug: ci-cleanup-v24-broker-code-review-closure
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-15
---

# Phase 41 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust built-in) + `cargo clippy` (lints) + `pwsh` (Windows MSI validator) |
| **Config file** | `Cargo.toml` (workspace) / `Makefile` (`make test`, `make clippy`, `make ci`) |
| **Quick run command** | `make clippy` (cross-target clippy verification from Windows host) |
| **Full suite command** | `make ci` (clippy + fmt + tests across the workspace) |
| **Estimated runtime** | ~60–180 seconds (clippy) / 5–10 minutes (full CI) |

---

## Sampling Rate

- **After every task commit:** `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`
- **After every plan wave:** `make ci` (clippy + fmt + full test suite)
- **Before `/gsd-verify-work`:** 7 CI lanes green on PR head (Linux Clippy + macOS Clippy + Win Build/Integration/Regression/Security/Packaging) + zero `success → failure` transitions vs baseline `a72736bb`
- **Max feedback latency:** ~3 minutes for clippy, ~10 minutes for full CI

---

## Per-Task Verification Map

> Populated by the planner. Each row = one task. `Wave 0` is the new-test scaffolding for the 3 broker hygiene tests (CR-01/CR-02/CR-03) per D-11 + D-12.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 41-01-XX | 01 | 1 | REQ-CI-01 | — | API migration preserves capability-request semantics | unit + clippy | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | ✅ (`exec_strategy.rs`) | ⬜ pending |
| 41-02-XX | 02 | 1 | REQ-CI-01 | — | No `#[allow(dead_code)]`; orphans deleted or wired per CLAUDE.md | unit + clippy | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` + `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` | ✅ (existing) | ⬜ pending |
| 41-03-XX | 03 | 1 | REQ-CI-02 | — | MSI validator passes mandatory `-BrokerPath` correctly | integration | `pwsh ./scripts/validate-windows-msi-contract.ps1 …` | ✅ (existing) | ⬜ pending |
| 41-04-XX | 04 | 1 | REQ-CI-02 | — | Block-net probe spawns and reaches the connect call | integration | `cargo test --test env_vars windows_run_block_net_blocks_probe_connection -- --nocapture` | ✅ (existing) | ⬜ pending |
| 41-05-XX | 05 | 1 | REQ-CI-02 | — | env_vars parallel test does not race; uses `EnvVarGuard` | unit | `cargo test --test env_vars windows_run_redirects_profile_state_vars_into_writable_allowlist -- --test-threads=1` | ✅ (existing) | ⬜ pending |
| 41-06-XX | 06 | 0 | REQ-BROKER-CR-01 | T-BROKER-FFI | `NonoError::BrokerNotFound` → `ErrSandboxInit` (-6), not `ErrPathNotFound` (-1) | unit (FFI, inline in `bindings/c/src/lib.rs` mod tests) | `cargo test -p <bindings-c-crate-name> broker_not_found_maps_to_err_sandbox_init` (replace crate name with the actual one from `bindings/c/Cargo.toml`) | ❌ W0 (new, inline) | ⬜ pending |
| 41-06-XX | 06 | 0 | REQ-BROKER-CR-02 | T-BROKER-NULL | Broker argv parser rejects `--inherit-handle 0x0` with `SandboxInit` error | unit | `cargo test -p nono-shell-broker parse_args_null_inherit_handle_returns_error` | ❌ W0 (new) | ⬜ pending |
| 41-06-XX | 06 | 0 | REQ-BROKER-CR-03 | T-BROKER-EMPTY | Broker argv parser rejects empty `--inherit-handle` list with `SandboxInit` error | unit | `cargo test -p nono-shell-broker parse_args_empty_inherit_handle_list_returns_error` | ⚠️ flip existing | ⬜ pending |
| 41-07-XX | 07 | 1 | REQ-BROKER-CR-04 | — | Job-object test FAILS loudly when broker artifact missing | unit | `cargo test -p nono-cli --test exec_strategy_windows broker_launch_assigns_child_to_job_object` | ✅ (existing) | ⬜ pending |
| 41-07-XX | 07 | 1 | REQ-CI-03 | — | Baseline SHA + skipped-gates convention + STATE.md cleanup land in single PR | docs grep | `grep -F "$(git rev-parse HEAD)" .planning/templates/upstream-sync-quick.md` | ✅ (existing) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Wave 0 lands the 3 new broker-hygiene tests so subsequent CR fixes have a place to live. Per CONTEXT D-11 + D-12:

- [ ] `bindings/c/src/lib.rs` (inline `#[cfg(test)] mod tests` block) — add FFI test for `BrokerNotFound → ErrSandboxInit` (CR-01); workspace has no `crates/nono-ffi/` — FFI tests live inline alongside the FFI code per PATTERNS verification.
- [ ] `crates/nono-shell-broker/src/main.rs` — add `parse_args_null_inherit_handle_returns_error` unit test (CR-02)
- [ ] `crates/nono-shell-broker/src/main.rs` — flip existing `parse_args_empty_inherit_handle_list_is_ok` → `_returns_error` at ~line 489 (CR-03; RESEARCH.md verified 489-502)
- [x] `cargo test` framework — already installed via Rust toolchain

*Cross-target clippy from the Windows host is mandatory per `feedback_clippy_cross_target` memory; not a Wave 0 install (toolchain already configured).*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| 7 CI lanes green on PR head | REQ-CI-01 + REQ-CI-02 | Lives in GitHub Actions; not reproducible locally | Open draft PR after 41-01 lands; verify all 7 lanes pass on final commit |
| Baseline reset SHA = Phase 41 close SHA | REQ-CI-03 SC#1 | SHA is only known at phase close | `git rev-parse HEAD` after final Plan 41-07 commit; cross-check against `upstream-sync-quick.md` |
| `nono-py` / `nono-ts` downstream FFI unaffected by CR-01 remap | REQ-BROKER-CR-01 (verification) | Cross-repo dependency | Manually grep `../nono-py/` and `../nono-ts/` for integer error-code mapping per CONTEXT D-10 |
| STATE.md `## Deferred Items` cleared of v24 CR-A entries | REQ-CI-03 SC#3 | Doc edit, no automated assertion | `grep -i "v24.*CR-A" .planning/STATE.md` returns empty after Plan 41-07 final commit |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (3 broker tests: CR-01 FFI mapping + CR-02 null handle + CR-03 empty list flip)
- [ ] No watch-mode flags (cargo test runs single-shot)
- [ ] Feedback latency < 180s for clippy quick run
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
