# Plan 43-03 — Interim Close Gate (post cherry-pick 3 of 8)

**Run:** 2026-05-18
**HEAD:** `b7c8e07e fix(43-03-cra): register outdated/pin/unpin in Windows ROOT_HELP_TEMPLATE` (CR-A on top of cherry-pick 3)
**Per Task 2 step 8a:** Windows-host gates 1+2 against the post-Wave-0b-head baseline (5e5f1005).

## Cherry-picks in this checkpoint

| Pos | Fork SHA | Upstream SHA | Subject |
|-----|----------|--------------|---------|
| 1   | `32f053f2` | `64d9f283` | feat(package): add package pinning and outdated commands |
| —   | `f7706199` | (CR-A) | fix(43-03-cra): adapt cherry-pick 64d9f283 to fork's PackageStatus/PackageAdvisory struct shape |
| 2   | `1dc7ec9f` | `a5985edd` | feat(cli): implement `nono update` command |
| —   | `acffeb3f` | (CR-A) | fix(43-03-cra): adapt cherry-pick a5985edd to fork's PackageStatusResponse field name |
| 3   | `52a4dd6`  | `be23d6df` | style(cli): improve formatting and simplify error handling |
| —   | `b7c8e07e` | (CR-A) | fix(43-03-cra): register outdated/pin/unpin in Windows ROOT_HELP_TEMPLATE |

## Gate 1 — cargo test (nono-cli --bin nono)

```
running 1010 tests across nono-cli binary
test result: 1008 passed; 2 failed; 0 ignored
  - 1 failure resolved in CR-A b7c8e07e (test_root_help_lists_all_commands → now passing)
  - 1 failure environmental: broker_launch_assigns_child_to_job_object — pre-existing Phase 41 D-14 / CR-04 (broker binary not pre-built); same environmental skip as Plan 43-01b SUMMARY Issue 1
```

**Post-fix re-run:** `cargo test -p nono-cli --bin nono cli::tests::test_root_help_lists_all_commands` → 1 passed / 0 failed

**Verdict:** PASS (environmental broker-binary precondition is the same environmental skip as Plan 43-01b; Phase 41 CR-04 recommendation stands).

## Gate 2 — cargo clippy --workspace --all-targets

```
cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
Finished `dev` profile [unoptimized + debuginfo] target(s) in 3m 26s
CLIPPY_EXIT=0
```

**Verdict:** PASS

## Wave 1 baseline-aware CI gate intermediate position

vs baseline `13cc0628` (Phase 41 close) + 43-01b head `5e5f1005`:
- Cherry-picks at this checkpoint touch only `crates/nono-cli/src/` (5 files: cli.rs, cli_bootstrap.rs, package.rs, package_cmd.rs, registry_client.rs, app_runtime.rs)
- 0 Windows-file touches (D-43-E1 invariant)
- 0 profile/mod.rs touches (Phase 36-01b preservation)
- 0 override_deny touches (Phase 36-01c rename preserved)

**Status: ON-TRACK** — continue to cherry-picks 4-5 before next interim gate.
