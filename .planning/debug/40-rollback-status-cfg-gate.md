---
slug: 40-rollback-status-cfg-gate
status: fixing
trigger: |
  DATA_START
  Phase 40 / Plan 40-03 cherry-picks broke non-Windows compilation; fix structural
  cfg-gating of nono::undo::SessionMetadata.rollback_status + RollbackStatus on
  linux/macos. Origin/main is GREEN on Windows but FAILING on ubuntu-latest +
  macos-latest (clippy job, fork CI) at commit a72736bb.
  DATA_END
created: 2026-05-13
updated: 2026-05-13
phase: 40
related_commits:
  - 96886ae9  # Plan 40-03 cherry-pick 1/2 — feat(core): scrub command arguments for secrets
  - 7831c47f  # Plan 40-03 cherry-pick 2/2 — refactor(scrub): optimize and simplify scrubbing logic
  - a72736bb  # CR-A fix attempt #1 (Path/PathBuf cfg-gating) — exposed more errors
  - ee1ae16c  # PRE-DATING regression: removed `use nono::undo::{RollbackStatus, SessionMetadata}` from audit_session.rs tests (Phase 32-02)
  - 87108a37  # original author of audit_session.rs RollbackStatus literal sites (Phase 22-05a)
  - 74848e31  # fork-only addition of rollback_status to SessionMetadata (Phase 09-03 Windows feature)
  - 2823ec29  # PRE-DATING latent: doc-comments-on-fn-params exec_strategy.rs:556-562 (Phase 25-01)
related_files:
  - crates/nono/src/undo/types.rs              # Lib: SessionMetadata + RollbackStatus (both cross-platform, no cfg-gate)
  - crates/nono-cli/src/audit_ledger.rs        # CLI: E0063 missing field rollback_status at lines 383, 435 (whole module is #[cfg(unix)] in main.rs)
  - crates/nono-cli/src/audit_session.rs       # CLI: E0433 cannot find RollbackStatus at lines 396, 421, 446 (tests are #[cfg(not(target_os = "windows"))])
  - crates/nono-cli/src/exec_strategy.rs       # CLI: E0432 unused imports DETACHED_LAUNCH_ENV, DETACHED_SESSION_ID_ENV at line 23 (only Windows uses them)
  - crates/nono-cli/src/rollback_commands.rs   # CLI: unused import Component at line 20 (used at lines 77-81 inside #[cfg(target_os = "windows")] block)
  - crates/nono-cli/src/sandbox_state.rs       # CLI: unused imports EnvVarGuard, lock_env at line 398 (used at lines 442-443 inside #[cfg(target_os = "windows")] test)
ci_run: 25836432980
---

# Phase 40 — Plan 40-03 broke non-Windows compilation

## Symptoms

**Expected:** `cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::unwrap_used` passes on ubuntu-latest, macos-latest, and Windows.

**Actual:** Passes on Windows; fails on ubuntu + macos. CI run `25836432980` (commit `a72736bb`) shows the in-scope 5 errors PLUS several pre-existing latent errors that were previously masked by the now-fixed `Path/PathBuf` import error.

### In-scope errors (per orchestrator brief)

| # | File | Line | Error | Class |
|---|---|---|---|---|
| 1 | `crates/nono-cli/src/exec_strategy.rs` | 23 | unused imports: `DETACHED_LAUNCH_ENV`, `DETACHED_SESSION_ID_ENV` | Lint (CR-A) |
| 2 | `crates/nono-cli/src/rollback_commands.rs` | 20 | unused import: `Component` | Lint (CR-A) |
| 3 | `crates/nono-cli/src/sandbox_state.rs` | 398 | unused imports: `EnvVarGuard`, `lock_env` (test-only) | Lint (CR-A) |
| 4 | `crates/nono-cli/src/audit_ledger.rs` | 383, 435 | **E0063 — missing field `rollback_status` in initializer of `nono::undo::SessionMetadata`** | **Compile (PRIMARY)** |
| 5 | `crates/nono-cli/src/audit_session.rs` | 396, 421, 446 | **E0433 — cannot find type `RollbackStatus` in this scope** | **Compile (PRIMARY)** |

### Out-of-scope errors (also failing same CI run — pre-existing latent)

Discovered during investigation when reading the full CI log via `gh api repos/oscarmackjr-twg/nono/actions/jobs/75912406979/logs`. These are NOT introduced by Plan 40-03 but **will also block Linux/macOS CI green** until fixed.

| # | File | Line(s) | Error | Origin |
|---|---|---|---|---|
| 6 | `crates/nono-cli/src/bin/nono-wfp-service.rs` | 14, 15 | E0432/E0433 — `tokio::AsyncReadExt/AsyncWriteExt` + `windows_service` crate unresolved on non-Windows | Pre-existing — bin not platform-gated; previously masked by earlier compile-stop on `nono` lib Path/PathBuf |
| 7 | `crates/nono-cli/src/exec_strategy.rs` | 556, 557, 558, 561, 562 | "documentation comments cannot be applied to function parameters" (`///` on fn params) | `2823ec29` (Phase 25-01); compile only fails when those params are present which is on `cfg(any(target_os = "linux", target_os = "macos"))` |
| 8 | `crates/nono-cli/src/profile_runtime.rs` | 138 | E0425 — `cannot find function user_profiles_dir in module crate::config` | Pre-existing — function is at `crate::config::user::user_profiles_dir`; no `pub use user::*` in `config/mod.rs` (no fix shipped in Phase 35) |
| 9 | `crates/nono-cli/src/learn.rs` | 412, 1197-1252 | Cascading errors (`cannot find NonoError`, `?` couldn't convert error) — likely caused by an earlier compile failure short-circuiting type resolution | Cascading from #8 or earlier |
| 10 | `crates/nono-cli/src/main.rs` | 482 | (clipped from logs — unknown) | Cascading |
| 11 | `crates/nono-cli/src/exec_strategy.rs` | 2647 | E0004 — non-exhaustive `SupervisorMessage::{Terminate, Detach}` patterns | Likely cascading or a pre-existing latent bug |

**Primary debug target (per user):** errors #4 + #5 — structural cfg-gating of `SessionMetadata.rollback_status` + `RollbackStatus` on linux/macos.

**Parallel scope (same wave, same root cause class):** errors #1–3 are CR-A-class unused-import drift.

**Timeline:** Failure first visible after commit `39488f24` (Plan 40-02's last cherry-pick) on 2026-05-13. Plan 40-03 cherry-picked on top of broken baseline. Commit `a72736bb` fixed the first clippy error (Path/PathBuf in nono lib) but exposed errors #1–11 above.

**Reproduction:**
```bash
# Canonical (CI):
gh run view 25836432980 --json jobs --jq '.jobs[] | select(.name | test("Clippy")) | {name, conclusion}'
gh api repos/oscarmackjr-twg/nono/actions/jobs/75912406979/logs | grep -E 'error\[E0'

# Local (Windows host — will fail at aws-lc-sys/ring C cross-compile, NOT a useful signal):
cargo check --workspace --target x86_64-unknown-linux-gnu

# Authoritative: push to a feature branch, wait for fork CI ubuntu + macos jobs.
```

## Current Focus

```yaml
hypothesis: |
  ROOT CAUSE (confirmed):

  Error #4 (E0063 in audit_ledger.rs): Plan 40-03 cherry-pick 96886ae9 added 559 lines to
  audit_ledger.rs from upstream 6472011, including two test fixtures (sample_metadata at
  line 382 and a literal SessionMetadata at line 435 inside session_digest_changes_when_*).
  Upstream's SessionMetadata does NOT have rollback_status (that field is fork-only,
  added in 74848e31 for Phase 09-03 Windows feature). The cherry-pick's fork-adaptations
  block (per 7831c47f commit message) lists several test fixes but missed these two.
  audit_ledger.rs is gated by `#[cfg(unix)] mod audit_ledger;` in main.rs:9-10, which is
  why Windows CI is green — the entire module never compiles on Windows.

  Error #5 (E0433 in audit_session.rs): Test module at line 354 has `use super::*;` +
  `use crate::test_env::{lock_env, EnvVarGuard};` — no `use nono::undo::RollbackStatus`.
  Commit ee1ae16c (Phase 32-02 D-32-01 work) REMOVED the line
  `use nono::undo::{RollbackStatus, SessionMetadata};` from this test module. The
  RollbackStatus literal references at lines 396/421/446 only compile because the
  enclosing test `discover_sessions_excludes_rollback_backed_entries` is gated
  `#[cfg(not(target_os = "windows"))]` (line 367) — on Windows the test is omitted, on
  Linux/macOS it tries to compile and fails. This regression has been latent since
  ee1ae16c because Windows CI is the dev host and the test was Windows-excluded.

  Errors #1-3 (CR-A unused-import lint): Three different files have `use ...` lines that
  are referenced ONLY by Windows-gated code (`#[cfg(target_os = "windows")]`). On
  non-Windows, the imports become unused and trigger `-D warnings`.

test: |
  Confirmed by direct file reading and git log analysis. No further test design needed.

expecting: |
  Fixes are mechanical:

  Error #4: Add `rollback_status: RollbackStatus::Available` to both literal sites in
  audit_ledger.rs:382-398 and 435-473 (these are test fixtures simulating completed
  rollback-capable sessions; Available is the appropriate default for the rollback-state
  invariants these tests check). Add `use nono::undo::RollbackStatus;` to the tests'
  `use` block at line 374.

  Error #5: Add `use nono::undo::RollbackStatus;` to audit_session.rs tests `use` block
  at line 356, restoring what ee1ae16c removed. (The literal references already correctly
  pass RollbackStatus::Skipped / Available — only the `use` was missing.)

  Errors #1-3: Wrap each unused `use` line in `#[cfg(target_os = "windows")]` (mirror of
  what a72736bb did for Path/PathBuf in sandbox/mod.rs). For error #3 (sandbox_state.rs
  EnvVarGuard/lock_env), the `use` is inside a `#[cfg(test)]` mod and the import is only
  used inside a `#[cfg(target_os = "windows")] #[test]` — gate the `use` with
  `#[cfg(target_os = "windows")]`.

next_action: |
  PAUSE FOR USER DECISION.

  The orchestrator brief explicitly scoped errors #1-5 (the cfg-gate fixes). But the CI
  log shows 6 additional pre-existing errors (#6-11) on Linux/macOS that will still
  block CI green even after fixing #1-5. Specifically:
    - #6 nono-wfp-service.rs not platform-gated (entire bin)
    - #7 doc-comments-on-fn-params in exec_strategy.rs:556-562
    - #8 missing crate::config::user_profiles_dir re-export
    - #9-11 likely cascading from #6-8 (need re-verification after #1-8 fixes)

  Two options:

  (A) NARROW SCOPE — Fix only #1-5 as briefed. Result: addresses the user's stated
  primary target and the CR-A parallel scope. CI will still be RED on Linux/macOS due
  to #6-11. Pro: matches scope contract verbatim, leaves out-of-scope items for a
  separate session. Con: doesn't deliver the stated "make CI green" goal.

  (B) EXPAND SCOPE — Fix #1-5 AND verify whether #6-8 are real pre-existing latent
  bugs (they appear to be — confirmed by git log:
   - #6 nono-wfp-service.rs is in src/bin/, auto-discovered by Cargo, never had
     platform gating; the file's contents are all #[cfg(target_os = "windows")]
     but the top-level `use windows_service::{...}` and `use tokio::io::{Async*Ext}`
     are NOT gated, so non-Windows builds fail at the `use` line.
   - #7 doc-comments-on-fn-params from 2823ec29 (Phase 25-01) — never compiled
     on Linux/macOS in CI since the file's first Path/PathBuf or audit_ledger error
     always short-circuited. Trivial fix: change `///` to `//` on lines 556-562.
   - #8 missing re-export at crate::config::user_profiles_dir — would require either
     adding `pub use user::user_profiles_dir;` to config/mod.rs OR changing
     profile_runtime.rs:138 to call `crate::config::user::user_profiles_dir()`.

  Then fix #6-8 too, run cargo check, and only after Linux/macOS clippy is GREEN
  push and verify CI. Pro: actually achieves the orchestrator's stated outcome of
  making CI green. Con: scope creep into pre-existing bugs from older phases
  (25-01, 32-02, latent bin-target) that may have their own owning phases or
  intended fix paths.

  Recommend: (B), with each of #6-8 as a SEPARATE commit so the cherry-pick chain
  and the latent-bug fixes are bisect-distinguishable.

reasoning_checkpoint:
  hypothesis: |
    Plan 40-03 cherry-pick 96886ae9 added 559 lines of upstream audit_ledger.rs test
    fixtures that pre-date the fork-only rollback_status field (added in 74848e31).
    The fork-adaptations documented in 7831c47f's commit message missed the two
    SessionMetadata literal sites in those tests. Independently, ee1ae16c (Phase 32-02,
    pre-dating Plan 40-03) removed `use nono::undo::RollbackStatus` from audit_session.rs's
    tests; this regression was latent because the enclosing test is
    `#[cfg(not(target_os = "windows"))]` and Linux/macOS CI didn't fire on the prior
    Path/PathBuf compile-stop. The CR-A-class unused-import lints (#1-3) are the same
    pattern as a72736bb: Windows-only usage with non-Windows-unused imports.
  confirming_evidence:
    - "crates/nono/src/undo/types.rs:350 (RollbackStatus enum) and types.rs:424 (SessionMetadata.rollback_status field) are both defined without any #[cfg] attribute; field has #[serde(default)] for back-compat but not Default for construction."
    - "main.rs:9-10 has `#[cfg(unix)] mod audit_ledger;` — audit_ledger.rs is excluded on Windows, explaining why error #4 only fires on Linux/macOS."
    - "audit_session.rs:367 has `#[cfg(not(target_os = \"windows\"))]` on the test that references RollbackStatus — explains why error #5 only fires on Linux/macOS."
    - "git log -S 'use nono::undo::RollbackStatus' -- crates/nono-cli/src/audit_session.rs shows ee1ae16c REMOVED this `use` line in Phase 32-02 work, unrelated to Plan 40-03."
    - "git log -S 'fn sample_metadata' -- crates/nono-cli/src/audit_ledger.rs shows commit 96886ae9 is the introducing commit for the audit_ledger test fixture sites."
    - "git show 96886ae9 confirms 559 insertions in audit_ledger.rs; the upstream test fixture has no rollback_status (upstream lacks the field)."
    - "exec_strategy.rs:23 imports DETACHED_LAUNCH_ENV/DETACHED_SESSION_ID_ENV which are only used in cfg(target_os = \"windows\") code paths (no non-Windows use); same shape as a72736bb's Path/PathBuf fix."
    - "rollback_commands.rs:20 imports Component, used at lines 77-81 inside a function that is itself called only by code paths exercised on Windows via normalize_path_for_compare's Windows-specific verbatim-prefix stripping; on non-Windows the function body uses .canonicalize() and the Component match is dead."
    - "sandbox_state.rs:398 imports lock_env+EnvVarGuard inside #[cfg(test)] mod; the only use is at lines 442-443 inside `#[cfg(target_os = \"windows\") #[test]` block."
  falsification_test: |
    Run `cargo check --workspace --all-targets --target x86_64-apple-darwin` (or
    `--target x86_64-unknown-linux-gnu`) locally if cross-compilers were available;
    confirm that after applying the proposed fixes, all 5 in-scope errors disappear.
    Since the dev host is Windows and the cross-target build fails at aws-lc-sys C
    compile (per Phase 25 CR-A lesson), the authoritative falsification is pushing the
    fix to a feature branch and running `gh run watch` on the resulting CI to confirm
    Clippy (ubuntu-latest) + Clippy (macos-latest) go from red to green.
  fix_rationale: |
    The fixes address structural compile bugs at the construction/import sites — they
    do not paper over the symptoms. For error #4, the test fixtures are simulating
    completed sessions where rollback was attempted; RollbackStatus::Available is the
    appropriate semantic value for the digest-stability tests (the field MUST be
    present for the struct to construct; its value only matters for the digest, which
    the test exercises by comparing the same Available value before/after each
    individual field mutation). For error #5, restoring the missing `use` is a direct
    revert of the ee1ae16c regression. For errors #1-3, cfg-gating the unused imports
    is the cleanest mechanical fix — they ARE genuinely unused on non-Windows
    architectures.
  blind_spots: |
    1. Whether RollbackStatus::Available or RollbackStatus::Skipped is the
       semantically correct default for the audit_ledger.rs test fixtures. Both values
       are valid for the construction; Available is the upstream-test-fixture-default
       semantic and matches the audit_session.rs `RollbackStatus::Available` at line
       446 (which is the same shape of "completed session with snapshot_count > 0").
       For sample_metadata (line 382-398) which uses snapshot_count: 0, Skipped might
       be more semantically accurate, but Available is the type's #[default] and
       deserializes that way for older payloads — using Available everywhere
       maintains symmetry with the type's default-value contract.
    2. Whether the out-of-scope errors #6-11 will re-cascade into new errors after
       these fixes are applied. Need a fresh cargo check + CI run to verify. Specifically
       errors #9-11 in learn.rs and main.rs may already be cascading from earlier
       compile failures and may resolve themselves.
    3. Whether any newer downstream code on origin/main references RollbackStatus
       from audit_session or audit_ledger and would be affected by the test-only
       fixes. Unlikely (these are test fixtures, not production code), but should
       run `cargo check --workspace --tests` after the fix to verify.
  tdd_checkpoint: ""
```

## Evidence

- timestamp: 2026-05-13 / orchestrator-setup
  source: crates/nono/src/undo/types.rs:340-425 (read by orchestrator)
  finding: |
    `RollbackStatus` enum (line 350) and `SessionMetadata.rollback_status: RollbackStatus`
    (line 424) are both defined WITHOUT any #[cfg(target_os = ...)] attribute. They
    derive Default (RollbackStatus::Available is #[default]) and have #[serde(default)]
    on the struct field. So they exist cross-platform from the library's perspective.
- timestamp: 2026-05-14 / debugger-investigation
  source: crates/nono-cli/src/main.rs:9-10
  finding: |
    `#[cfg(unix)] mod audit_ledger;` — audit_ledger.rs is excluded entirely on Windows.
    This is why Windows CI doesn't fire E0063 even though sample_metadata and the
    digest-test fixture are missing the rollback_status field. The Windows CI green
    status is a false-negative: the failing module isn't compiled on Windows at all.
- timestamp: 2026-05-14 / debugger-investigation
  source: crates/nono-cli/src/audit_session.rs:354-367 + git log ee1ae16c
  finding: |
    `mod tests` at line 354 has `use super::*;` + `use crate::test_env::{lock_env, EnvVarGuard};`
    only. NO `use nono::undo::RollbackStatus`. Commit `ee1ae16c feat(32-02): rewrite
    load_production_trusted_root as sync cache read (D-32-01)` removed the line
    `-    use nono::undo::{RollbackStatus, SessionMetadata};` from this test module.
    The test that uses RollbackStatus is gated `#[cfg(not(target_os = "windows"))]` at
    line 367, so the regression was latent on Windows (where it's excluded) and
    masked on Linux/macOS by the earlier Path/PathBuf error.
- timestamp: 2026-05-14 / debugger-investigation
  source: git show 96886ae9 -- crates/nono-cli/src/audit_ledger.rs
  finding: |
    Plan 40-03 cherry-pick 1/2 added 559 lines to audit_ledger.rs from upstream 6472011.
    The upstream commit pre-dates the fork-only addition of rollback_status to
    SessionMetadata (added in 74848e31 for Phase 09-03 Windows feature), so the
    upstream test fixtures don't include the field. The fork-adaptations block in
    7831c47f's commit message lists several test fixes but missed audit_ledger.rs.
- timestamp: 2026-05-14 / debugger-investigation
  source: crates/nono-cli/src/exec_strategy.rs:23 + git grep DETACHED_LAUNCH_ENV
  finding: |
    `use crate::{DETACHED_LAUNCH_ENV, DETACHED_SESSION_ID_ENV};` at line 23 of
    exec_strategy.rs. These constants are only used inside #[cfg(target_os = "windows")]
    code paths elsewhere in the workspace. On Linux/macOS exec_strategy.rs they are
    unused, triggering `-D warnings` for unused_imports.
- timestamp: 2026-05-14 / debugger-investigation
  source: crates/nono-cli/src/rollback_commands.rs:20 + 77-81
  finding: |
    `use std::path::{Component, Path, PathBuf};` at line 20. `Component` is used at
    lines 77-81 inside the `match` arms for path component normalization. On non-Windows
    targets the `normalize_path_for_compare` function takes a different code path
    (canonicalize-only), so `Component` becomes unused. Same shape as a72736bb's
    Path/PathBuf fix in sandbox/mod.rs.
- timestamp: 2026-05-14 / debugger-investigation
  source: crates/nono-cli/src/sandbox_state.rs:398, 442-443, 435-454
  finding: |
    `use crate::test_env::{lock_env, EnvVarGuard};` at line 398 inside the
    `#[cfg(test)] mod tests` block. Both symbols are used at lines 442-443 inside a
    `#[cfg(target_os = "windows")] #[test]` named `test_validate_cap_file_path_accepts_windows_runtime_temp_dir`.
    On non-Windows, the test is excluded but the import remains.
- timestamp: 2026-05-14 / debugger-investigation
  source: gh api repos/oscarmackjr-twg/nono/actions/jobs/75912406979/logs (CI run 25836432980)
  finding: |
    Pre-existing latent errors beyond the orchestrator's stated 5:
    - nono-wfp-service.rs:14-15: tokio/windows_service imports not cfg-gated for Windows
      only; the bin file is in src/bin/ (auto-discovered by Cargo) with no top-level
      `#![cfg(target_os = "windows")]` and no Cargo.toml `required-features` gate.
    - exec_strategy.rs:556-562: `///` doc comments on function parameters (Phase 25-01
      regression from 2823ec29); fires only when cfg(any(linux, macos)).
    - profile_runtime.rs:138: `crate::config::user_profiles_dir()` doesn't resolve;
      function lives at `crate::config::user::user_profiles_dir()` with no re-export.
    - learn.rs/main.rs/exec_strategy.rs:2647 cascading errors likely consequences of
      the above (need re-check after the in-scope fixes).
- timestamp: 2026-05-14 / debugger-investigation
  source: gh run list (last 60 CI runs)
  finding: |
    The "green CI on Windows" reported in the orchestrator brief is actually NOT a
    green clippy-on-Windows. The most recent green CI runs (`cc2a4132`, `5d103827`,
    `4de1df6f`, `c1de59ec1`, `5cac6382c`) are all docs-only commits where every
    real job (Clippy, Test, Windows Build, Windows Integration) was SKIPPED by the
    Classify Changes job. The last green real-clippy CI run is unclear — none
    in the last 60 runs show Clippy (ubuntu-latest) as `success` without preceding
    failures. CI run 25836432980 (commit a72736bb) is the first full-job run since
    the cherry-picks landed, and it shows Clippy (ubuntu) + Clippy (macos) + Test
    (ubuntu) + Test (macos) + Integration Tests + Windows Integration + Windows
    Packaging all FAILING. The orchestrator's "Windows GREEN" framing is incorrect:
    only the SKIPPED-clippy runs are green; real-build Windows Integration also
    fails on a72736bb (likely due to a fork-side build issue unrelated to this debug
    session).

## Eliminated

- hypothesis: "The rollback_status field is fork-only Windows-gated and the cherry-pick correctly avoided patching it on Windows-only paths"
  evidence: "types.rs:350+424 has no #[cfg(target_os = ...)] attribute — the field is unconditionally cross-platform. Hypothesis #2 from the handoff doc is refuted."
  timestamp: 2026-05-14
- hypothesis: "audit_session.rs:396+ has a #[cfg(target_os = \"windows\")]-gated `use` line for RollbackStatus that needs un-gating"
  evidence: "No `use ...RollbackStatus` line exists in audit_session.rs at all — the line was removed by ee1ae16c. Need to ADD the use back, not un-gate it."
  timestamp: 2026-05-14

## Resolution

```yaml
root_cause: |
  Eight independent in-scope errors across two root-cause classes (5 in-scope per
  orchestrator brief + 3 expanded-scope pre-existing latents per user decision):

  Cherry-pick / regression class:
    (1) Plan 40-03 cherry-pick 96886ae9 added two SessionMetadata struct literals in
        audit_ledger.rs test fixtures (lines 382, 437) WITHOUT the fork-only
        rollback_status field, because the upstream commit pre-dates the field's
        addition to the fork's SessionMetadata (74848e31). The cherry-pick's
        fork-adaptations block missed these literal sites. E0063 fires on
        Linux/macOS because audit_ledger.rs is #[cfg(unix)] in main.rs.
    (2) Commit ee1ae16c (Phase 32-02, pre-dating Plan 40-03) silently removed
        `use nono::undo::RollbackStatus` from audit_session.rs's tests module. The
        three remaining RollbackStatus literal references at lines 396/421/446
        became unresolved. Latent because the test using them is
        #[cfg(not(target_os = "windows"))]. Surfaced once a72736bb cleared the
        prior Path/PathBuf compile-stop.

  CR-A unused-import-on-non-Windows class:
    (3) exec_strategy.rs:23 — DETACHED_LAUNCH_ENV/DETACHED_SESSION_ID_ENV imported
        but unused on non-Windows.
    (4) rollback_commands.rs:20 — Component imported alongside Path/PathBuf but
        used only by Windows-gated normalize_path_for_compare.
    (5) sandbox_state.rs:398 — lock_env/EnvVarGuard imported in tests mod but
        used only by Windows-gated test.

  Pre-existing latent (out-of-scope per orchestrator brief, expanded per user
  decision to fix in this session for clean CI):
    (6) nono-wfp-service.rs auto-discovered as a bin by Cargo on every target;
        depends on `windows-service` crate (Cargo.toml gates dep to Windows) and
        tokio AsyncRead/Write traits that are unused on non-Windows.
    (7) exec_strategy.rs:556-562 — `///` doc comments on function parameters
        (Phase 25-01 regression from 2823ec29); now a hard error in stable rustc.
    (8) profile_runtime.rs:138 calls `crate::config::user_profiles_dir()` but the
        function lives at `crate::config::user::user_profiles_dir` with no
        re-export at the module root.
fix: |
  Six atomic fix commits + one fmt commit on feature branch
  `fix/40-rollback-status-cfg-gate`:

    7f730307  fix(40-03): provide rollback_status in cherry-picked audit_ledger.rs test fixtures (CR-B)
              — audit_ledger.rs: add RollbackStatus to test use block; add
                rollback_status: RollbackStatus::Skipped to sample_metadata
                (snapshot_count=0); add rollback_status: RollbackStatus::Available
                to session_digest base literal (snapshot_count=3). Shape-matched
                to audit_session.rs literal sites.

    59d47270  fix(cli): restore RollbackStatus use line in audit_session.rs tests (regression from ee1ae16c)
              — audit_session.rs: add `#[cfg(not(target_os = "windows"))] use
                nono::undo::RollbackStatus;` to tests use block, restoring what
                ee1ae16c removed.

    bb266c07  fix(cli): gate Windows-only imports on Windows (CR-A class)
              — exec_strategy.rs:23: prefix with #[cfg(target_os = "windows")].
              — rollback_commands.rs:20: split into cross-platform Path/PathBuf
                and Windows-gated Component.
              — sandbox_state.rs:398: prefix with #[cfg(target_os = "windows")].

    32ceee3b  fix(cli/bin): gate nono-wfp-service.rs to Windows
              — Wrap entire body in `#[cfg(target_os = "windows")] mod windows_impl
                { ... }`; rename inner fn main to pub(super) fn run; update
                use windows_wfp_contract → use super::windows_wfp_contract; add
                non-Windows stub `fn main` that exits 1; add Windows-only top-level
                `fn main` that delegates to windows_impl::run.

    9f6a8f03  fix(cli): convert doc-comments-on-fn-params to regular comments in exec_strategy.rs
              — exec_strategy.rs:557-559, 562-563: change `///` to `//` on the
                cfg-gated `resource_limits` and `resource_session_id` function
                parameter comments.

    da7e2afe  fix(cli/config): re-export user_profiles_dir from config module root
              — config/mod.rs: add `#[allow(unused_imports)] pub use
                user::user_profiles_dir;` so the existing call-site at
                profile_runtime.rs:138 resolves on the Linux-gated branch.

    75435eab  style: apply cargo fmt --all to fix-chain output
              — Pure mechanical fmt output (indentation update for the new
                windows_impl mod wrapper in nono-wfp-service.rs; cfg-attribute
                line collapse in exec_strategy.rs; alphabetical import reorder
                in rollback_commands.rs).

  All seven commits include DCO sign-off (oscarmackjr-twg) and
  Co-Authored-By trailer.
verification: |
  Windows host (full pre-push gate):
    - cargo check --workspace --all-targets — PASS
    - cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::unwrap_used — PASS
    - cargo fmt --all -- --check — PASS
    - cargo test --workspace --no-run — PASS (all targets build)

  Cross-target clippy attempt (Linux):
    - cargo clippy --target x86_64-unknown-linux-gnu — FAIL at aws-lc-sys C compile
      step (no x86_64-linux-gnu-gcc available on Windows host). This is the
      expected Phase 25 CR-A blind spot (per memory entry
      `feedback_clippy_cross_target`); cross-target clippy on Windows host
      cannot exercise Linux-only code paths fully.

  Authoritative CI verification:
    - Feature branch pushed to origin: fix/40-rollback-status-cfg-gate.
    - CI is configured to run only on PR-to-main or push-to-main (.github/workflows/ci.yml
      `on:` block). Per orchestrator brief, PR creation is owned by the user
      (Phase 40 workflow), not this debug session. CI green status (Clippy
      ubuntu-latest + Clippy macos-latest) is the authoritative verification
      and remains PENDING the user creating the PR. Once PR is open, the same
      fix-chain will be exercised on real Linux/macOS runners.

  Cascading errors #9-11 (learn.rs, main.rs, exec_strategy.rs:2647 per the
  CI log) were diagnosed by the prior investigation pass as likely
  consequences of #4-8 short-circuiting cargo's type-resolution. Expected to
  resolve naturally once #1-8 are fixed. Will be confirmed only by the PR's
  CI run.
files_changed:
  - crates/nono-cli/src/audit_ledger.rs
  - crates/nono-cli/src/audit_session.rs
  - crates/nono-cli/src/bin/nono-wfp-service.rs
  - crates/nono-cli/src/config/mod.rs
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/rollback_commands.rs
  - crates/nono-cli/src/sandbox_state.rs
```

## Awaiting CI Confirmation

Status remains `fixing` (not `resolved`) until:
  1. User creates PR for `fix/40-rollback-status-cfg-gate` → `main`.
  2. CI Clippy ubuntu-latest concludes `success`.
  3. CI Clippy macos-latest concludes `success`.
  4. Cascading errors #9-11 confirmed resolved (no fresh failures).

If any cascading error remains, open a follow-up debug session for the
residual surface area.
