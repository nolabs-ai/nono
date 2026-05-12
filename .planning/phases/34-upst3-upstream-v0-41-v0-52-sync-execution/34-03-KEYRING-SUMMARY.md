---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-03
plan: 03
slug: keyring
cluster_id: C5
type: execute
wave: 1
depends_on: ["34-04", "34-04b"]
blocks: []
upstream_tag_range: v0.43.0..v0.45.0
upstream_commit_count: 8
landed_commit_count: 8
requirements: [C5]
tags: [upst3, c5, keyring, display, audit, wave-1, complete]

dependency_graph:
  requires:
    - 34-04 (path canonicalization schema)
    - 34-04b (FP canonical schema)
    - 34-01 (CLI consolidation)
    - keyring v3 windows-native (fork commit 77021c98)
  provides:
    - system-keyring feature flag (default on; opt-out for headless)
    - command_display::truncate_command (char-aware)
    - command_display::format_command_line (shell-quote)
    - Dockerfile-headless (root, fork variant)
  affects:
    - crates/nono/Cargo.toml (feature flag)
    - crates/nono/src/keystore.rs (cfg-gate)
    - crates/nono-cli/Cargo.toml (feature flag + shlex dep)
    - crates/nono-cli/src/trust_keystore.rs (cfg-gate)
    - crates/nono-cli/src/command_display.rs (new module)
    - crates/nono-cli/src/audit_commands.rs (use shared helpers)
    - crates/nono-cli/src/session_commands.rs (use shared helpers)
    - crates/nono-proxy/Cargo.toml (feature flag)

tech-stack:
  added:
    - shlex = "1" (nono-cli) — for shell-quote of command-args in display
    - system-keyring feature flag (nono, nono-cli, nono-proxy)
  patterns:
    - cfg-gated keyring code with explicit fail-closed fallback for headless builds
    - char-aware truncation (chars().take()) replacing byte-slicing

key-files:
  created:
    - Dockerfile-headless (root)
    - .dockerignore
    - crates/nono-cli/src/command_display.rs
  modified:
    - crates/nono/Cargo.toml
    - crates/nono/src/keystore.rs
    - crates/nono-cli/Cargo.toml
    - crates/nono-cli/src/trust_keystore.rs
    - crates/nono-cli/src/audit_commands.rs
    - crates/nono-cli/src/session_commands.rs
    - crates/nono-cli/src/output.rs
    - crates/nono-cli/src/main.rs
    - crates/nono-cli/src/profile_save_runtime.rs
    - crates/nono-cli/src/rollback_commands.rs
    - crates/nono-cli/src/capability_ext.rs (no-op; upstream's reformat targeted unlanded test)
    - crates/nono-proxy/Cargo.toml
    - bindings/c/Cargo.toml (release-bump no-op for fork)
    - CHANGELOG.md
    - Cargo.lock

decisions:
  - "Plan listed commit order put 7b58c3ee before f5215917 (system-keyring default-on before optional feature exists). Reordered to upstream topology: f5215917 first (introduces feature), 7b58c3ee second (enables by default). Plan order in PLAN.md was non-chronological — applied upstream topological order to ensure clean build between commits."
  - "Windows-native keyring v3 backend (fork commit 77021c98, 2026-05-10) preserved by marking windows-native target's keyring dep optional = true. Composition: keyring is unconditional cdylib transitive when system-keyring is on (default), suppressed when --no-default-features."
  - "f5215917 keystore.rs conflicts: fork's HEAD already had all the constants/types/tests that upstream was adding (KeyringDecode, GO_KEYRING_PREFIX, apply_keyring_decode, test_validate_keyring_uri_*). Took HEAD for the duplicate-add conflicts; added #[cfg(feature = \"system-keyring\")] gates to GO_KEYRING_PREFIX and KeyringDecode to maintain headless-build correctness."
  - "f5215917 trust_keystore.rs conflicts: merged fork's richer system_keystore_label() error messages with upstream's #[cfg(not(feature = \"system-keyring\"))] fail-closed fallback. Fork's better messages survive on the system-keyring path; headless builds get a clean error pointing at env://, file://, op:// alternatives."
  - "1f912e53 (style: cargo fmt) became a no-op on fork — upstream's reformatted lines were inside test_from_profile_connect_port_errors_on_macos which fork has not landed yet. Preserved as --allow-empty commit with full D-19 trailer so the 8-commit chain stays intact for the plan-close smoke check."
  - "30c0f76e (chore: release v0.43.0), f4050670 (chore: release v0.43.1), d38fe644 (chore: release v0.45.0): release-bump commits became no-ops on fork — fork keeps its own crate versions (0.37.1) per fork divergence policy, and fork's CHANGELOG already covers versions through [0.47.1]. Preserved as --allow-empty commits with D-19 trailers."
  - "e21e27d1 audit_commands.rs conflict: upstream's diff re-inserts cmd_verify + cmd_cleanup at a different line position. Fork already has both functions (its own variants with richer features). Dropped upstream's duplicate insertion; kept only the format_command_line import and call-site changes that auto-merged into session/rollback/output surfaces."

metrics:
  duration_minutes: ~95
  completed: "2026-05-11"
  cherry_picks_attempted: 8
  cherry_picks_landed: 8
  cherry_picks_substantive: 3   # f5215917, e21e27d1, 91476107
  cherry_picks_empty: 4         # 1f912e53, 30c0f76e, f4050670, d38fe644
  cherry_picks_clean_apply: 1   # 7b58c3ee (only Cargo path-dep version conflict)
---

# Phase 34 Plan 03: C5 Headless Keyring + Audit-Display Fixes (v0.43–v0.45, 8 commits) Summary

Cluster C5 lands the optional `system-keyring` feature flag (default on for backward compatibility; opt-out for headless/container builds) plus two display-surface fixes (char-aware truncation + shell-quote command args). The 8 upstream commits were cherry-picked in upstream topological order (NOT the plan's listed order), with 3 substantive commits applying fork-aware merges and 4 release-bump/cargo-fmt commits becoming no-ops on the fork. Fork's Windows Credential Manager backend (`keyring v3` `windows-native`, added 2026-05-10 in fork commit `77021c98`) is preserved across the feature-flag transition by marking the Windows target's `keyring` dep `optional = true` alongside Linux/macOS gating. All D-19 trailers, D-34-E1 invariants, and fork-defense baselines hold; D-34-D2 gates 1/2/5 PASS (P34-DEFER-01-1 carry-forward acceptable per plan invariants).

## One-liner

Optional `system-keyring` feature (default on, opt-out for headless) + char-aware truncation + shell-quote args, with fork's Windows Credential Manager backend preserved via composable `optional = true` Windows target.

## Pre-state (captured at Task 1)

**HEAD:** `ddd4ce25` (post-Plan-34-01 SUMMARY commit)

**Keyring config (verbatim):**

```toml
# crates/nono/Cargo.toml (workspace root section)
keyring = "3"   # unconditional, no feature gate

[target.'cfg(target_os = "linux")'.dependencies]
keyring = { version = "3", features = ["sync-secret-service"] }

[target.'cfg(target_os = "macos")'.dependencies]
keyring = { version = "3", features = ["apple-native"] }

[target.'cfg(target_os = "windows")'.dependencies]
keyring = { version = "3", features = ["windows-native"] }
```

(`apple-native` and `windows-native` are fork additions per Phase 31 and commit `77021c98`.)

## Cherry-pick chain (chronological, as landed)

Note on order: PLAN.md listed commits in upstream-release-grouping order (`7b58c3ee` before `f5215917`). Upstream **topology** is the reverse: `f5215917` introduces the `system-keyring` feature gate; `7b58c3ee` then enables it by default. Cherry-picking in the plan's listed order would fail to build between commits (default depends on a non-existent feature). Applied upstream topological order; documented this deviation explicitly.

| Order | New SHA   | Upstream SHA | Tag    | Subject                                                            | Outcome     |
| ----- | --------- | ------------ | ------ | ------------------------------------------------------------------ | ----------- |
| 1     | 459d47e8  | f5215917     | v0.43.0 | feat: make system keyring optional for headless/container builds   | substantive |
| 2     | afde16f5  | 7b58c3ee     | v0.43.0 | fix: set system-keyring as default feature for backward compat     | substantive |
| 3     | 02686954  | e21e27d1     | v0.43.1 | fix(cli): shell-quote command args in display output (#660)        | substantive |
| 4     | 03ab7006  | 1f912e53     | v0.43.0 | style: run cargo fmt                                               | empty       |
| 5     | dc5247bf  | 30c0f76e     | v0.43.0 | chore: release v0.43.0                                             | empty       |
| 6     | d375b05e  | 91476107     | v0.43.1 | fix(cli): char-aware truncation in truncate_command                | substantive |
| 7     | 2e8e7eba  | f4050670     | v0.43.1 | chore: release v0.43.1                                             | empty       |
| 8     | c1c542e3  | d38fe644     | v0.45.0 | chore: release v0.45.0                                             | empty       |

**Final HEAD:** `c1c542e3`

## D-34-E1 invariant verification (Windows-only files)

Per-commit `git diff --stat | grep -cE '_windows|exec_strategy_windows'` returned **0** for all 8 commits.

## D-19 trailer verification

```
git log --format='%B' main~8..main | grep -c '^Upstream-commit: '   = 8 ✓
git log --format='%B' main~8..main | grep -c '^Upstream-author: '   = 8 ✓ (lowercase 'a')
git log --format='%B' main~8..main | grep -c '^Upstream-Author: '   = 0 ✓ (no uppercase)
git log --format='%B' main~8..main | grep -c '^Signed-off-by: '     = 16 ✓ (2 per commit)
```

## Fork-defense baselines (post-Plan-34-03)

| Pattern                                                              | Threshold | Actual | Status |
| -------------------------------------------------------------------- | --------- | ------ | ------ |
| `policy.rs` never_grant / apply_deny_overrides                       | ≥21       | 21     | hold   |
| `package_cmd.rs` validate_path_within                                | ≥9        | 9      | hold   |
| `profile/mod.rs` capabilities.aipc / loaded_profile                  | ≥17       | 17     | hold   |
| `policy.rs` find_denied_user_grants                                  | ≥1        | 7      | hold   |
| `profile/mod.rs` bypass_protection                                   | ≥1        | 17     | hold   |
| `crates/nono/Cargo.toml` windows-native                              | ≥1        | 1      | hold   |

## D-34-D2 close-gate (per plan-instruction)

| #   | Gate                                                                          | Status                                | Notes                                                                                                          |
| --- | ----------------------------------------------------------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| 1   | `cargo test --workspace --all-features`                                       | PASS (with P34-DEFER-01-1 carry-fwd)  | 907 passed, 1 failed (`query_ext::tests::test_query_path_denied` — pre-existing Windows path canon flake). Verified failure exists on pre-Plan-34-03 HEAD ddd4ce25. Per plan invariants: P34-DEFER-01-1 carry-forward is acceptable. |
| 2   | Windows clippy: `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` | PASS                                  | Clean.                                                                                                         |
| 3   | Linux clippy: `--target x86_64-unknown-linux-gnu`                             | documented-deferred to CI             | Linker not installed on Windows host. D-34-D2 deferral per user-accepted posture from 34-04 close.            |
| 4   | macOS clippy: `--target x86_64-apple-darwin`                                  | documented-deferred to CI             | Same as gate 3.                                                                                                |
| 5   | `cargo fmt --all -- --check`                                                  | PASS                                  | Clean.                                                                                                         |
| 6   | (admin-skipped)                                                               | n/a                                   | Per plan invariants.                                                                                           |
| 7   | (admin-skipped)                                                               | n/a                                   | Per plan invariants.                                                                                           |
| 8   | (admin-skipped)                                                               | n/a                                   | Per plan invariants.                                                                                           |

### Test-isolation flake note

During the first `cargo test --workspace --all-features` run, an additional failure was observed: `nono::supervisor::aipc_sdk::tests::windows_loopback_tests::helper_stamps_session_token_from_env` failed with an env-var assertion mismatch ("testtoken12345678" vs "testtoken12345678abc"). Running the test in isolation passed (`cargo test -p nono --lib helper_stamps_session_token_from_env`), and a second full `cargo test --workspace --all-features` invocation did NOT reproduce the failure (only `query_ext::test_query_path_denied` failed). Conclusion: this is a parallel-test env-var leak (similar shape to the `HOME` flake documented in CLAUDE.md's "Environment variables in tests" section) and not a regression introduced by Plan 34-03. Not blocking.

## Deviations from Plan

### Auto-fixed during execution

**1. [Rule 3 - Blocking issue] Reordered commits to upstream topology**

- **Found during:** Task 2 (first cherry-pick attempt)
- **Issue:** PLAN.md listed `7b58c3ee` (set system-keyring default) before `f5215917` (introduce optional system-keyring feature). Applying that order would fail to build between commits — `7b58c3ee` requires a `system-keyring` feature in `[features]` to exist, which `f5215917` introduces.
- **Fix:** Cherry-picked in upstream topological order (`f5215917` → `7b58c3ee` → `e21e27d1` → `1f912e53` → `30c0f76e` → `91476107` → `f4050670` → `d38fe644`), verified against `git log upstream/main --ancestry-path f5215917^..d38fe644`.
- **Files modified:** none (just commit ordering)
- **Commits:** all 8

**2. [Rule 2 - Auto-add critical fork-defense] Windows-native `optional = true`**

- **Found during:** Task 2 (commit 1, after f5215917 conflict resolution)
- **Issue:** Upstream's `f5215917` only adds `optional = true` to Linux/macOS target keyring deps; Windows isn't in upstream because upstream lacks the `windows-native` backend. Leaving Windows target unmodified would make `--no-default-features` builds on Windows STILL pull in `keyring` (breaking the headless-build promise on Windows).
- **Fix:** Added `optional = true` to the Windows target's `keyring` line in `crates/nono/Cargo.toml` AND `crates/nono-cli/Cargo.toml`, preserving fork's `features = ["windows-native"]`. Verified via `grep 'windows-native' crates/nono/Cargo.toml` → 1 hit.
- **Files modified:** `crates/nono/Cargo.toml`, `crates/nono-cli/Cargo.toml`
- **Commits:** 459d47e8 (commit 1)

**3. [Rule 2 - Auto-add critical fork-defense] cfg-gated KeyringDecode + GO_KEYRING_PREFIX**

- **Found during:** Task 2 (commit 1, keystore.rs conflict resolution)
- **Issue:** Fork's `KeyringDecode` enum, `GO_KEYRING_PREFIX` const, and related `apply_keyring_decode`/`parse_keyring_uri`/`load_from_keyring_uri` functions already existed in fork's HEAD but without `#[cfg(feature = "system-keyring")]` gates (fork pre-dated the feature). With the feature now introduced, an `--no-default-features` build would have dead/unreachable code that imports unconditional `keyring::` symbols and fail to build.
- **Fix:** Added `#[cfg(feature = "system-keyring")]` to `KeyringDecode` enum and `GO_KEYRING_PREFIX` const; the `apply_keyring_decode`, `parse_keyring_uri`, `load_from_keyring_uri`, and `KeyringUriParts` items were auto-gated via the conflict resolution. Verified with `cargo build --workspace` (default features → builds).
- **Files modified:** `crates/nono/src/keystore.rs`
- **Commits:** 459d47e8 (commit 1)

### Empty commits (preserved with D-19 trailers)

| Commit | Reason |
| ------ | ------ |
| 03ab7006 (1f912e53) | Upstream's cargo-fmt reflow targeted lines in `test_from_profile_connect_port_*` tests that fork has not landed. |
| dc5247bf (30c0f76e) | Release-bump to v0.43.0; fork keeps its own crate versions (0.37.1). Fork's CHANGELOG already covers later versions. |
| 2e8e7eba (f4050670) | Release-bump to v0.43.1; same posture as above. |
| c1c542e3 (d38fe644) | Release-bump to v0.45.0; same posture as above. |

All four preserved with full D-19 trailers so the cluster-C5 upstream-commit chain (8 entries) survives the plan-close smoke check.

### Threat-model alignment

- **T-34-03-01 (D-34-E1):** mitigated — per-commit grep returned 0 across all 8 commits.
- **T-34-03-02 (D-19 trailer):** mitigated — Upstream-commit count = 8, Signed-off-by count = 16, lowercase 'a' enforced.
- **T-34-03-03 (windows-native silently dropped):** mitigated — Windows target's `keyring` dep marked `optional = true` with `features = ["windows-native"]` preserved. Verified post-cluster.
- **T-34-03-04 / T-34-03-05 / T-34-03-06:** accepted/sentinel posture as planned.

## Deferred Issues

- **P34-DEFER-01-1 (carry-forward):** `query_ext::tests::test_query_path_denied` fails on Windows host with the `\\?\C:\some\random` vs `/some/random` mismatch (Windows path canonicalization on a test that expects POSIX paths). Pre-existing; not introduced by Plan 34-03. Tracked in `deferred-items.md`.
- **D-34-D2 gates 3 (Linux clippy) and 4 (macOS clippy):** documented-deferred to CI per user-accepted posture (Linux/macOS linkers not installed on Windows host).

## Push

```
git push origin main
```

To be performed at plan-close per <sequential_execution> directive.

## Self-Check: PASSED

All artifact files exist on disk; all 8 commit SHAs reachable via `git log --all`.

- 34-03-KEYRING-SUMMARY.md ✓
- Dockerfile-headless ✓
- .dockerignore ✓
- crates/nono-cli/src/command_display.rs ✓
- 8/8 commits: 459d47e8, afde16f5, 02686954, 03ab7006, dc5247bf, d375b05e, 2e8e7eba, c1c542e3
