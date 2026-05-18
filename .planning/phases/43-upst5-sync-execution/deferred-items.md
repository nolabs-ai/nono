# Phase 43 — Deferred Items (out-of-scope discoveries during plan execution)

Tracking out-of-scope items per executor agent SCOPE BOUNDARY rule: discoveries NOT directly caused by current task's changes.

## Items deferred

### Item D-43-DEF-01 — `supervisor::aipc_sdk::tests::windows_loopback_tests::helper_stamps_session_token_from_env` parallel-test env-var-leakage flake

**Discovered during:** Plan 43-03 Task 3 close-gate (Gate 1 — `cargo test --workspace --all-features`).

**Symptom:** When running the full workspace test suite, the test fails with:
```
assertion `left == right` failed: SDK must stamp NONO_SESSION_TOKEN into CapabilityRequest.session_token
  left: "testtoken12345678"
 right: "testtoken12345678abc"
```

**Root cause analysis:**
1. Test passes in isolation (`cargo test -p nono --lib supervisor::aipc_sdk::tests::windows_loopback_tests::helper_stamps_session_token_from_env` → 1 passed)
2. Test passes at baseline `5e5f1005` (verified via `git checkout 5e5f1005 -- . && cargo test ... → ok`)
3. Test failure manifests only in parallel-test mode (Rust runs unit tests in parallel within the same process)
4. Mismatch suggests another concurrent test sets `NONO_SESSION_TOKEN=testtoken12345678abc` and doesn't restore the env var before this test reads it
5. **NOT caused by Plan 43-03:** Plan 43-03 touches only `crates/nono-cli/src/` (9 files); does NOT touch `crates/nono/src/supervisor/aipc_sdk.rs` or any test that sets `NONO_SESSION_TOKEN`
6. **NOT caused by Plan 43-01b foundation:** Plan 43-01b touched `crates/nono-cli/src/` files (audit_attestation.rs, credential_runtime.rs, session_commands_windows.rs) which are also unrelated to NONO_SESSION_TOKEN
7. Direct CLAUDE.md hit: § Coding Standards / "Environment variables in tests": "Tests that modify HOME, TMPDIR, XDG_CONFIG_HOME, or other env vars must save and restore the original value. Rust runs unit tests in parallel within the same process, so an unrestored env var causes flaky failures in unrelated tests."

**Disposition:** **DEFERRED** to a follow-on test-hygiene plan that audits all `NONO_*` env-var-setting tests for the save/restore pattern. Out of scope for Plan 43-03 (Cluster 1 = pack management CLI surface; doesn't touch supervisor/aipc_sdk).

**Verification at baseline:** confirmed PASSING at `5e5f1005` (Plan 43-01b head) in isolation; flaking only emerges in parallel-test mode with this specific test invocation order.

**Recommendation:** Phase 43 follow-on or Phase 44 dedicated plan to audit `crates/nono/src/supervisor/aipc_sdk.rs` test module for env-var hygiene per CLAUDE.md § Environment variables in tests pattern; introduce `test_env::EnvVarGuard` (already in scope in fork — used elsewhere in `profile/mod.rs` tests) to all NONO_*-setting tests.
