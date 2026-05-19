# Phase 37 deferred items

Out-of-scope discoveries encountered during execution. Tracked per executor
scope-boundary rule for the verifier to pick up or for a future phase to address.

## Plan 37-01

### Pre-existing Windows broker smoke-test flake

- **Test:** `supervisor::aipc_sdk::tests::windows_real_broker_smoke_tests::sdk_request_job_object_round_trips_through_real_broker`
- **Crate:** `nono` (lib)
- **Discovered during:** Plan 37-01 Task 3 full nono lib test run.
- **Observation:** Failed on first run inside the `cargo test -p nono --lib` batch
  (1/692 tests failed). Re-running the same single test name immediately passes
  (`1 passed`). Re-running the full batch also passes (692/692). Strong flake signal —
  likely a timing/ordering interaction with another Windows broker test sharing
  the test process.
- **Why out-of-scope:** Plan 37-01 touches `NonoError::UnsupportedKernelFeature` and
  4 of 5 Linux cgroup-v2 detection sites in `supervisor_linux.rs`. Nothing in this
  plan modifies the Windows broker IPC stack.
- **Memory cross-reference:** project_phase41_open_gaps notes Linux clippy / macOS
  pre-existing CI gaps; this is a separate Windows-host test flake not previously
  tracked.
- **Suggested follow-up:** open a small CI cleanup ticket targeting Phase 41 series
  (CI cleanup phase) to either de-flake (serialize the broker smoke tests) or
  mark them as `#[ignore]`-with-explicit-run-flag.

### Cross-target Linux clippy + tests deferred to live CI

- **Why partial on dev host:** `cargo check --target x86_64-unknown-linux-gnu`
  for `nono-cli` fails on the Windows dev host because `cc-rs` requires the
  `x86_64-linux-gnu-gcc` cross C compiler, which is not installed locally.
  This matches the CLAUDE.md "Cross-target clippy verification" rule:
  "If the cross-toolchain is not installed, the related verification REQ MUST
  be marked PARTIAL and deferred to live CI per
  `.planning/templates/cross-target-verify-checklist.md`."
- **What was verified locally (Windows host):**
  - `cargo check --workspace` — exits 0
  - `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` — exits 0
  - `cargo test -p nono --lib` — 692/692 (with one flake on a Windows broker
    test re-running clean; see above)
  - `cargo test -p nono-ffi --lib` — 42/42, including the new
    `map_error_unsupported_kernel_feature_returns_err_unsupported_platform`
  - `cargo test -p nono-cli --test resl_nix_async_signal_safety` — 5/5
    (CR-01 regression test still green)
  - Lib-side unit tests `cargo test -p nono --lib unsupported_kernel_feature`
    — 3/3
- **What requires Linux live CI (covered by Plan 37-04):**
  - `cargo clippy --workspace --target x86_64-unknown-linux-gnu
    -- -D warnings -D clippy::unwrap_used`
  - `cargo test -p nono-cli --test resl_nix_async_signal_safety
    --target x86_64-unknown-linux-gnu`
  - The 4 new `unsupported_kernel_feature_swap_tests` plus the 3 updated
    pre-existing `detect_from_str_*_rejected` tests in
    `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` (Linux-gated via
    `cfg(all(test, target_os = "linux"))`).

## Plan 37-02

### CI doc-flag-allowlist drift: `--dangerous-force-wfp-ready`

`bash .github/scripts/check-cli-doc-flags.sh` reports:

```
Missing RunArgs flags in docs/cli/usage/flags.mdx:
  --dangerous-force-wfp-ready
```

**Origin:** `--dangerous-force-wfp-ready` was added to `SandboxArgs` by Phase 41
(REQ-CI-02) but never documented in `docs/cli/usage/flags.mdx`. It is gated
behind `NONO_TEST_HARNESS` and is a test-only flag, so the omission may be
intentional.

**Scope:** out-of-scope for Plan 37-02 (the plan adds `--no-auto-pull`, which
IS correctly documented in the same docs file).

**Action:** no fix here; flag for a Phase 41 follow-up plan or a Phase 37
fix-pass if the executor encounters the same CI failure on the green-gate run.

### Pre-existing Phase 41 test failure: `broker_launch_assigns_child_to_job_object`

`cargo test -p nono-cli --bin nono` (Windows host) fails this test with:

```
nono-shell-broker.exe missing at ...\target\x86_64-pc-windows-msvc\release\
  nono-shell-broker.exe and ...\target\release\nono-shell-broker.exe;
  pre-build with `cargo build -p nono-shell-broker --release` (or set the
  broker pre-build via crates/nono-cli/build.rs per Phase 41 D-14).
```

**Origin:** Phase 41 D-14 added a release-mode broker pre-build requirement
that is not satisfied by a `cargo build -p nono-cli` (debug) invocation. The
test asserts Job Object containment is enforced before ResumeThread and was
intentionally written to fail rather than silently skip.

**Scope:** out-of-scope for Plan 37-02 (touches `nono-cli/src/cli.rs` +
`profile/mod.rs` + new `diagnostic_formatter.rs`; does NOT touch
`exec_strategy_windows/launch.rs` or the broker harness).

**Action:** no fix here; this test is independently green on CI when the
release-mode broker pre-build runs. Plan 37-02 verification is satisfied via
the targeted test-name filters that exclude this pre-existing Windows-host
test infrastructure issue.
