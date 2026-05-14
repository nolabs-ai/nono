# Phase 41 — non-Windows CI cleanup (33 pre-existing latents)

**Status:** TRACKER — not yet planned as a formal phase. See ROADMAP.md for phase formalization once scoped.

**Filed:** 2026-05-14 during `/gsd-quick` session iterating PR #2 on `fix/40-rollback-status-cfg-gate`.

## Context

PR #2 unbreaks Phase 40's structural CI breakage on Linux/macOS, but CI run after PR #2's round-3 fix-chain still shows **33 errors** that were previously masked by the cascade of compile-stops PR #2 clears. These predate Plan 40-03 and represent fork-side tech debt accumulated across upstream-sync phases.

## Error categorization

| Class | Count | Sample sites |
|---|---|---|
| **API migration — `nono::CapabilityRequest::path` deprecated** | 14 | `crates/nono-cli/src/exec_strategy.rs:2662, 2684, 2690, 2696, 2705, 2710, 2717, 2729, 2742, 2757, 2763, 2781, 2794, 2809` |
| **Dead code — non-Windows orphans** | ~14 | `audit_ledger.rs::{AUDIT_LEDGER_FILENAME, AUDIT_LEDGER_LOCK_FILENAME, SESSION_DIGEST_DOMAIN, LEDGER_CHAIN_DOMAIN, LEDGER_HASH_ALGORITHM, SessionDigestPayload, ExecutableIdentityDigestPayload, LedgerRecord, LedgerLinkPayload, LedgerVerificationResult, compute_session_digest, path_bytes, append_session, validate_ledger_session_id, append_locked, verify_session_in_ledger, LedgerLock::acquire, hash_ledger_link}`; `audit_integrity.rs::record_capability_decision`; `exec_identity.rs::NotApplicable`; `exec_strategy.rs:376 audit_recorder field`; `exec_strategy/env_sanitization.rs::validate_env_var_patterns`; `exec_strategy/supervisor_linux.rs::kill_all`; `launch_runtime.rs::interactive_shell`; `protected_paths.rs::{sort_and_dedup_roots, paths_equal}`; `pty_proxy.rs::shutdown_attach_listener`; `rollback_session.rs::rollback_root_with_override`; `session.rs::session_log_path` |
| **Disallowed methods — `std::env::set_var/remove_var`** | 2 | `crates/nono-cli/src/test_env.rs:343, 344` — must migrate to `EnvVarGuard` (lint's recommended replacement) |
| **Unreachable expression** | 1 | `crates/nono-cli/src/exec_strategy.rs:1930` |
| **Sundry / fields-never-read** | 2+ | misc — needs investigation |

## Root cause hypotheses

1. **API migration latent**: The `CapabilityRequest::path` field was deprecated upstream (likely during Phase 34's v0.41–v0.52 sync or earlier), with `HandleTarget::FilePath` becoming the new shape via `kind` + `target` fields. Linux/macOS call sites in `exec_strategy.rs::handle_capability_message` were never migrated. Windows code uses the separate `exec_strategy_windows` module which presumably already migrated.
2. **Dead-code orphans**: Many functions in `audit_ledger.rs` look essential (`compute_session_digest`, `append_session`, `verify_session_in_ledger`). Most likely they're consumed via a Windows-only callsite (e.g. an `audit-verify` command path that's `#[cfg(target_os = "windows")]`) and the non-Windows side imports the module but never wires the calls. Needs investigation per-function: delete vs `#[allow(dead_code)]` with rationale vs actually-wire-up.
3. **test_env hygiene**: `crates/nono-cli/src/test_env.rs:343, 344` use `std::env::set_var/remove_var` directly inside `EnvVarGuard::Drop` impl. The `disallowed_methods` clippy lint (configured in fork) bans these in favor of `EnvVarGuard::remove()`. Self-referential — the `EnvVarGuard::Drop` is the very thing that's supposed to abstract away `std::env::*`. Either the lint config needs a per-file exception OR the `Drop` impl needs restructuring.

## Why Windows CI doesn't catch this

Memory note `feedback-clippy-cross-target` (Phase 25 CR-A regression lesson) — Windows-host `cargo clippy --workspace` cannot see `#[cfg(not(target_os = "windows"))]` blocks. The fork's CI gates 3+4 (cross-target clippy) are documented-skipped because the Windows dev host lacks the C cross-compilers required for `aws-lc-sys`/`ring`. Effective coverage is fork CI on `ubuntu-latest` + `macos-latest`, which only runs on PRs.

## Acceptance criteria

- [ ] All 33 errors on `fix/40-rollback-status-cfg-gate`'s round-3 CI run resolved
- [ ] Linux/macOS Clippy jobs conclude `success` on PR's CI run
- [ ] Windows CI remains clean (no regression)
- [ ] Each fix-class is its own atomic commit (CR-A pattern, mirroring PR #2's discipline)
- [ ] Dead-code dispositions are documented in commit body (delete vs allow-with-rationale vs wire-up)
- [ ] If `CapabilityRequest::path` → `HandleTarget::FilePath` migration is a significant API surface change, surface it in CONTEXT.md and consider splitting into its own sub-plan

## Suggested phase structure

- **Phase 41-01 (CR-A simple)**: dead-code, unreachable, disallowed-methods — ~17 fixes, ~10 commits, ~half-day
- **Phase 41-02 (API migration)**: `CapabilityRequest::path` → `HandleTarget::FilePath` — needs research pass first to understand the new API and validate the migration pattern with a single call site before bulk-applying

## Blocking on / unblocked by

- PR #2 (`fix/40-rollback-status-cfg-gate`) merging — once that lands on `main`, Phase 40 Wave 1 (plans 40-01 + 40-04) can proceed in parallel with Phase 41

## References

- PR #2: https://github.com/oscarmackjr-twg/nono/pull/2
- Phase 40 handoff: `.planning/phases/40-upst4-sync-execution/.continue-here.md`
- Original Phase 40 debug session: gone (deleted before pickup, content preserved in PR #2 body)
- Memory: `feedback-clippy-cross-target` (Phase 25 CR-A regression lesson — cross-target clippy required for cfg-gated Unix code)
