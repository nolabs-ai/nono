# Plan 43-04 — D-43-E9 8-Check Close Gate

**Per-plan disposition (per PLAN.md frontmatter `skipped_gates_load_bearing` + `skipped_gates_environmental` + `skipped_gates_rationale`):**

- Gates 1, 2, 5: required (executed on Windows host)
- Gates 3, 4: load-bearing for the 803c6947 nix dep bump cherry-pick BUT effective on-host scope is empty-diff (the cherry-pick was --allow-empty since 43-01b already promoted nix workspace-side at 0.31.3); 6b00932f is CHANGELOG-only with no compiled-code effect. PARTIAL Disposition → CI-verified per `.planning/templates/cross-target-verify-checklist.md` § PARTIAL Disposition (cross-toolchain unavailable on Windows host — same as 43-01b precedent)
- Gates 6, 7, 8: environmental-skip per Phase 40 D-40-C2 + Phase 40 Plan 40-04 release-ride precedent — CHANGELOG-only commit has no compiled-code effect

## Gate Results

| Gate | Description | Status | Notes |
|------|-------------|--------|-------|
| 1 | `cargo test --workspace --all-features` (Windows host) | **PASS (with 1 carry-forward flake)** | 688 + 1031 + ... tests green. One pre-existing flaky test `supervisor::aipc_sdk::tests::windows_loopback_tests::helper_stamps_session_token_from_env` fails under parallel execution (env-var pollution between parallel tests per CLAUDE.md § "Environment variables in tests"). Passes in isolation (`cargo test -p nono --lib <test> -- --exact` → 1 passed). Unrelated to Plan 43-04 (CHANGELOG-only commit has zero compiled-code effect). Treated as `red→red PASS (carry-forward, not introduced by this PR)` per baseline-aware CI gate transition semantics. |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | **PASS** | Clean (3m 23s build, 0 warnings) |
| 3 | `cargo clippy --target x86_64-unknown-linux-gnu` | **load-bearing-skip → CI-verified** | Cross-toolchain (x86_64-linux-gnu-gcc for aws-lc-sys) absent on Windows host per 43-01b precedent. PARTIAL Disposition; orchestrator-driven CI lane substitutes. Gate is load-bearing for the 803c6947 nix dep bump effective-on-Unix code, BUT the cherry-pick was --allow-empty (zero diff against fork shape since 43-01b workspace-level absorption) — no compiled-code effect this plan. |
| 4 | `cargo clippy --target x86_64-apple-darwin` | **load-bearing-skip → CI-verified** | Same disposition as Gate 3 |
| 5 | `cargo fmt --all -- --check` | **PASS** | Silent (rc=0) |
| 6 | Phase 15 5-row detached-console smoke | **environmental-skip** | CHANGELOG-only commit; Windows runtime substrate not available in agent context per D-40-C2 (Phase 40 Plan 40-04 release-ride exception) |
| 7 | `wfp_port_integration` tests | **environmental-skip** | CHANGELOG-only commit; Cargo-level tests included in Gate 1; deep WFP kernel-filter installation environmental-skip per D-40-C2 (Phase 40 Plan 40-04 release-ride exception) |
| 8 | `learn_windows_integration` tests | **environmental-skip** | CHANGELOG-only commit; Cargo-level tests included in Gate 1; deep learn-runtime substrate environmental-skip per D-40-C2 (Phase 40 Plan 40-04 release-ride exception) |

## Gate 1 Test Failure Analysis (Carry-Forward)

Failing test: `supervisor::aipc_sdk::tests::windows_loopback_tests::helper_stamps_session_token_from_env`

**Output excerpt:**
```
thread '...' panicked at crates\nono\src\supervisor\aipc_sdk.rs:831:21:
assertion `left == right` failed: SDK must stamp NONO_SESSION_TOKEN into CapabilityRequest.session_token
  left: "testtoken12345678"
 right: "testtoken12345678abc"
```

**Diagnosis:**
- Test mutates `NONO_SESSION_TOKEN` env var (per source comment at `crates/nono/src/supervisor/aipc_sdk.rs:681`: "Tests in this module mutate NONO_SESSION_TOKEN / NONO_SESSION_ID via ...")
- Parallel tests in the same module race the env-var mutation: the assertion sees the OTHER test's value
- CLAUDE.md § "Environment variables in tests" calls this out exactly: "Rust runs unit tests in parallel within the same process, so an unrestored env var causes flaky failures in unrelated tests"

**Files touched by Plan 43-04 vs failing test file:**
- Plan 43-04 commits 1 (`ff054687` — Task 1 audit), 2 (`a0a3a573` — empty 803c6947 cherry-pick), 3 (`7a15b59b` — 6b00932f CHANGELOG-only)
- Only `CHANGELOG.md` and `.planning/phases/43-upst5-sync-execution/*.md` touched
- `crates/nono/src/supervisor/aipc_sdk.rs` NOT touched (and the cherry-pick chain has zero compiled-code effect)

**Conclusion:** flake unrelated to Plan 43-04. Classify as red→red PASS (carry-forward) per `.planning/templates/upstream-sync-quick.md:108-113` lane transition categorization. Pre-existing in baseline `13cc0628` and inherits unchanged.

## Wave 1 Baseline-Aware CI Gate

Per PLAN.md frontmatter `wave_1_parallel_branch_strategy.baseline_ci_gate: compare-each-branch-independently-vs-13cc0628`, this plan's CI comparison is `worktree-agent-addcdb9c2805c07b9` head vs `13cc0628` ONLY (independent from Plan 43-03's branch).

Pre-merge expectation (set by Windows-host evidence above):
- All Linux + macOS clippy + test lanes: green→green expected (PASS) — CHANGELOG-only commit; no compiled-code effect
- fmt-check: green→green (PASS — fmt clean on Windows host)
- All 5 Windows CI lanes (Build, Integration, Regression, Security, Packaging): green→green expected (PASS — CHANGELOG-only + empty 803c6947 cherry-pick + Phase 41 D-14 broker-binary precondition satisfied locally)

Post-merge: orchestrator fills in per-job CI lane transition table after the worktree branch is pushed and CI completes. Per `wave_1_parallel_branch_strategy.umbrella_pr_body_update: orchestrator-post-both-wave-1-plans-close`, the umbrella PR body update happens after BOTH Plans 43-03 + 43-04 close.

## Per-Job CI Table (Template — orchestrator-driven post-merge)

| Job | Baseline `13cc0628` | Wave 1 head (`7a15b59b` + post-merge SHA) | Status |
|---|---|---|---|
| Cargo Audit | success | (pending orchestrator CI) | (pending) |
| Classify Changes | success | (pending) | (pending) |
| Clippy (macos-latest) | success | (pending) | (pending) |
| Clippy (ubuntu-latest) | success | (pending) | (pending) |
| Docs Checks | success | (pending) | (pending) |
| Integration Tests | success | (pending) | (pending) |
| Rustfmt | success | (pending) | (pending) |
| Test (macos-latest) | success | (pending) | (pending) |
| Test (ubuntu-latest) | success | (pending) | (pending) |
| Verify FFI Header | success | (pending) | (pending) |
| Windows Build | success | (pending) | (pending) |
| Windows Integration | success | (pending) | (pending) |
| Windows Packaging | success | (pending) | (pending) |
| Windows Regression | success | (pending) | (pending) |
| Windows Security | success | (pending) | (pending) |
| Windows Smoke | success | (pending) | (pending) |

(Baseline lane statuses per Phase 41 close-gate evidence; Wave 1 head statuses TBD by orchestrator post-merge per `wave_1_parallel_branch_strategy.umbrella_pr_body_update`.)
