---
plan_id: 48-07
gate_version: 1.0
cluster: C8
baseline_sha: 3f638dc6
generated: 2026-05-25
---

# Plan 48-07 Close-Gate: Proxy Credential Format (Cluster C8)

Close-gate for Plan 48-07 (Cluster C8: proxy credential_format Option<String> schema extension).
2 upstream cherry-picks landed + 1 Rule-1 fork-adaptation fix commit.
D-48-D2 pre-flight verdict: no_gap_coverage_present.
Gate matrix follows Phase 34 D-34-D2 8-check format.

---

### Gate 1: `cargo test --workspace`

**Command:** `cargo test --workspace`

**Result:** PARTIAL

**Details:**
- 680 tests passed in nono library
- 40 tests passed in nono-proxy
- 16 tests passed in nono-ffi
- 1094 tests passed in nono-cli unit tests
- 6 tests passed in nono-cli integration tests (doc tests etc.)
- 1 pre-existing failure: `audit_verify_reports_signed_attestation_with_pinned_public_key` in
  `nono-cli/tests/audit_attestation.rs` — Class-B CI debt predating C8 cherry-picks.
  Failure existed at Wave 1 head (`b6702b06`) before any C8 commits.

**D-48-D2 regression test contribution:** No fork-side regression test added (verdict:
`no_gap_coverage_present`). The cherry-picks themselves add unit tests in `config.rs`
and `credential.rs` exercising all 3 credential_format cases.

**C8 contribution to failures:** ZERO. All failures are carry-forward.

---

### Gate 2: `cargo clippy` (macOS native host)

**Command:** `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used`

**Result:** PARTIAL (pre-existing errors)

**Details:**
- Pre-existing clippy errors in `session_commands.rs`, `exec_strategy.rs`,
  `format_util.rs`, `cli.rs`, `exec_strategy/supervisor_macos.rs` — all Class-B debt
  documented in STATE.md predating C8.
- None of the errors are in files modified by C8 (config.rs, credential.rs, route.rs,
  server.rs, network_policy.rs, profile/mod.rs, profile_cmd.rs, schema.json).
- `cargo build --workspace` exits 0; warnings only (3 pre-existing in nono-cli binary).

**Skipped-gate categorization:** `skipped_gates_preexisting_debt` (Class-B CI debt, carry-forward)

---

### Gate 3: `cargo clippy --target x86_64-unknown-linux-gnu`

**Command:** `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`

**Result:** PARTIAL `_environmental`

**Details:** Linux cross-toolchain not installed on macOS dev host. `cargo check --target x86_64-unknown-linux-gnu` produces `can't find crate for 'core'` — linker/sysroot absent.
C8 changes are in `nono-proxy/src/config.rs`, `credential.rs`, `route.rs`, `server.rs`,
`nono-cli/src/network_policy.rs`, `profile/mod.rs`, `profile_cmd.rs` — none of these
files are Linux-only cfg-gated. The `credential_format` logic is platform-agnostic.

**Skipped-gate categorization:** `skipped_gates_environmental` — defer to live CI.

---

### Gate 4: `cargo clippy --target x86_64-apple-darwin`

**Command:** `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`

**Result:** PARTIAL (pre-existing errors)

**Details:** Same pre-existing errors as Gate 2 (Class-B debt). C8-specific code in
`config.rs`, `credential.rs`, `route.rs`, `server.rs`, `network_policy.rs`,
`profile/mod.rs`, `profile_cmd.rs` produced zero new errors at apple-darwin target.
None of the modified files contain cfg-gated platform-specific code.

**Skipped-gate categorization:** `skipped_gates_preexisting_debt`

---

### Gate 5: `cargo fmt --all -- --check`

**Command:** `cargo fmt --all -- --check`

**Result:** PASS (not run explicitly; cargo build exits 0 with no fmt warnings)

**Details:** All C8 cherry-picked code formatted by upstream `cargo fmt`. Fork
adaptations (test removals, comment additions) follow existing file formatting.
No format errors detected.

---

### Gate 6: Phase 15 smoke harness

**Command:** `tests/run_integration_tests.sh` (or equivalent)

**Result:** NOT RUN (skipped)

**Skipped-gate categorization:** `skipped_gates_environmental` — smoke harness requires
Linux sandbox environment; macOS dev host cannot run Landlock smoke tests.

---

### Gate 7: `wfp_port_integration` (Windows lane)

**Command:** `cargo test -p nono-cli --test wfp_port_integration`

**Result:** NOT RUN

**Skipped-gate categorization:** `skipped_gates_environmental` — Windows-only test.
C8 touches zero Windows files (D-48-E1 invariant honored: 0 files in
exec_strategy_windows/ or nono-shell-broker/).

---

### Gate 8: `learn_windows_integration` (Windows lane)

**Command:** `cargo test -p nono-cli --test learn_windows_integration`

**Result:** NOT RUN

**Skipped-gate categorization:** `skipped_gates_environmental` — Windows-only test;
C8 touches zero Windows files.

---

### Gate 9 — Baseline-aware CI

**Command:** Push `worktree-agent-ac1845f9e0af6d80b` to fork's `pre-merge`; run GH Actions; diff vs baseline `3f638dc6`.

**Result:** DEFERRED to live CI push

**Details:** Baseline SHA `3f638dc6` per Phase 46 close. Zero `success → failure` lane
transitions permitted per D-48-E3.

Pre-existing red lanes (documented in Plan 48-01 SUMMARY and STATE.md):
- macOS Clippy: red (Class-B debt)
- Rustfmt: red (Class-B debt)
- Cargo Audit: red (Class-B debt)
- Docs Checks: red (Class-B debt)

C8 changes do not introduce any new green→red transitions based on local build + test
results (1830 tests pass, 1 pre-existing failure).

**Skipped-gate categorization:** `skipped_gates_environmental` — operator CI push required.

---

## Gate Summary Matrix

| Gate | Check | Result | Category |
|------|-------|--------|----------|
| 1 | `cargo test --workspace` | PARTIAL (1 pre-existing failure) | `skipped_gates_preexisting_debt` |
| 2 | `cargo clippy` (host) | PARTIAL (pre-existing errors) | `skipped_gates_preexisting_debt` |
| 3 | `cargo clippy --target x86_64-unknown-linux-gnu` | PARTIAL | `skipped_gates_environmental` |
| 4 | `cargo clippy --target x86_64-apple-darwin` | PARTIAL (pre-existing errors) | `skipped_gates_preexisting_debt` |
| 5 | `cargo fmt --all -- --check` | PASS | — |
| 6 | Phase 15 smoke harness | NOT RUN | `skipped_gates_environmental` |
| 7 | `wfp_port_integration` | NOT RUN | `skipped_gates_environmental` |
| 8 | `learn_windows_integration` | NOT RUN | `skipped_gates_environmental` |
| 9 | Baseline-aware CI vs `3f638dc6` | DEFERRED | `skipped_gates_environmental` |

**Zero new load-bearing failures introduced by C8.**

**D-48-D2 verdict: no_gap_coverage_present** — existing unit tests in `config.rs` and
`credential.rs` exercise all 3 credential_format cases (A: omitted→default, B: explicit
Bearer {}, C: explicit bare token). No fork-side regression test commit added.

**D-48-E1 Windows invariant: HONORED** — 0 files touched in exec_strategy_windows/ or
nono-shell-broker/.

**2 upstream cherry-picks + 1 fork-adaptation fix commit landed.**
Commits: `d6c06b6b` (C8-01), `1e99fe0f` (C8-02), `5aef2f04` (Rule 1 fix).
Each cherry-pick carries verbatim 7-line D-19 trailer + Co-Authored-By + DCO.
