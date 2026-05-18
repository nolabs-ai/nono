# Plan 43-03 — Interim Close Gate (post cherry-pick 5 of 8)

**Run:** 2026-05-18
**HEAD:** `4bc5c838 fix(43-03-cra): drop explicit auto-deref in pack_update_hint save_state for rust 1.95 clippy`
**Per Task 2 step 8b:** Windows-host gates 1+2 against the post-Wave-0b-head baseline (5e5f1005).

## Cherry-picks in this checkpoint (cumulative)

| Pos | Fork SHA | Upstream SHA | Subject |
|-----|----------|--------------|---------|
| 1   | `32f053f2` | `64d9f283` | feat(package): add package pinning and outdated commands |
| —   | `f7706199` | (CR-A) | fix(43-03-cra): adapt cherry-pick 64d9f283 to fork's PackageStatus/PackageAdvisory struct shape |
| 2   | `1dc7ec9f` | `a5985edd` | feat(cli): implement `nono update` command |
| —   | `acffeb3f` | (CR-A) | fix(43-03-cra): adapt cherry-pick a5985edd to fork's PackageStatusResponse field name |
| 3   | `52a4dd6`  | `be23d6df` | style(cli): improve formatting and simplify error handling |
| —   | `b7c8e07e` | (CR-A) | fix(43-03-cra): register outdated/pin/unpin in Windows ROOT_HELP_TEMPLATE |
| 4   | `bed1fa5f` | `5098fc10` | feat(packs): add pinning, outdated, and clarify publishing versioning |
| —   | `3a5238b2` | (CR-A) | fix(43-03-cra): add fork-side list_pack_store_profiles adapter for cherry-pick 5098fc10 |
| 5   | `bdc5acf`  | `317c97b7` | style(cli): adjust line breaks and module order |
| —   | `4bc5c838` | (CR-A) | fix(43-03-cra): drop explicit auto-deref in pack_update_hint save_state for rust 1.95 clippy |

## Gate 1 — cargo test (nono-cli --bin nono)

```
running 1011 tests across nono-cli binary
test result: 1010 passed; 1 failed; 0 ignored
  - 1 failure environmental: broker_launch_assigns_child_to_job_object — Phase 41 D-14 / CR-04 (broker binary pre-build precondition); same environmental skip as Plan 43-01b SUMMARY Issue 1
```

**Verdict:** PASS (environmental broker-binary precondition only; pre-existing Phase 41 disposition).

## Gate 2 — cargo clippy --workspace --all-targets

```
cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
Finished `dev` profile [unoptimized + debuginfo] target(s) in 8.41s
CLIPPY_EXIT=0
```

**Verdict:** PASS (post Rule 1+2 CR-A `4bc5c838` clippy auto-deref fix)

## Wave 1 baseline-aware CI gate intermediate position (vs `13cc0628` baseline + 43-01b `5e5f1005`)

| Lane (Windows host) | Baseline | Post-cherry-pick 5 | Verdict |
|---------------------|----------|---------------------|---------|
| cargo test nono-cli | green    | green               | PASS    |
| cargo clippy workspace | green | green               | PASS    |
| cargo fmt --check   | green    | (deferred to Task 3) | TBD    |

## Touch summary so far (vs `5e5f1005`)

```
git diff --stat 5e5f1005..HEAD -- crates/nono-cli/src/
  crates/nono-cli/src/app_runtime.rs     |   9 ++
  crates/nono-cli/src/cli.rs             | 103 +++++++++++++++++++++--
  crates/nono-cli/src/cli_bootstrap.rs   |   3 +
  crates/nono-cli/src/main.rs            |   2 +
  crates/nono-cli/src/pack_update_hint.rs| 270 +++++++++++++++++++++++++++++++ (NEW)
  crates/nono-cli/src/package.rs         |  17 ++++
  crates/nono-cli/src/package_cmd.rs     | 308 +++++++++++++++++++++++++++++++++++
  crates/nono-cli/src/profile/mod.rs     |  73 +++++++++++ (CR-A list_pack_store_profiles adapter)
  crates/nono-cli/src/registry_client.rs | 100 +++++++++++++++++--
  crates/nono-cli/src/sandbox_prepare.rs |   4 +
```

- 0 `*_windows.rs` / `exec_strategy_windows/` / `nono-shell-broker/` touches (D-43-E1 invariant)
- profile/mod.rs touch: 73 lines ADDITIVE-ONLY (new `list_pack_store_profiles` fn; Phase 36-01b protected `From<ProfileDeserialize> for Profile` impl at line 1893 UNTOUCHED — verified via diff inspection)
- 0 `override_deny` references (Phase 36-01c rename preserved)
- 0 `Cargo.toml` / workspace.toml touches (no workspace-deps discipline triggered)

**Status: ON-TRACK** — continue to cherry-picks 6-8 to close gate.
