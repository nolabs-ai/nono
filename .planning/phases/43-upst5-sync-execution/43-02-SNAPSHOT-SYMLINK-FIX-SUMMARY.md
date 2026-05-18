---
phase: 43-upst5-sync-execution
plan: 02
cluster_id: 7
subsystem: undo-snapshot-restore + security-fix-cherry-pick
tags: [upstream-sync, security-fix, will-sync, d19-cherry-pick, symlink-toctou, cluster-7]
status: COMPLETE
dependency_graph:
  requires:
    - "Plan 43-01b workspace foundation (MSRV 1.95 + centralized deps + lints inheritance)"
    - "Phase 41 clean baseline 13cc0628 (all CI lanes green)"
    - "Phase 42 audit Cluster 7 disposition (will-sync, single SHA 66c69f86)"
  provides:
    - "Pre-flight `validate_restore_target` symlink check in `SnapshotManager::restore_to`"
    - "Closed TOCTOU symlink-redirect race window in fork's snapshot/restore path"
    - "Two new `#[cfg(unix)]` regression tests in undo::snapshot::tests"
  affects:
    - "Plan 43-03 PACK-MGMT (Wave 1 parallel) UNBLOCKED"
    - "Plan 43-04 RELEASE-RIDE (Wave 1 parallel) UNBLOCKED"
    - "Plan 43-05 PLATFORM-DETECTION-FOUNDATION (Wave 2a) UNBLOCKED downstream"
    - "Plan 43-06 PLATFORM-DETECTION-WINDOWS (Wave 2b) UNBLOCKED downstream"
tech_stack:
  added:
    - "std::fs::symlink_metadata (cross-platform; cross-toolchain inherent — already in std)"
    - "std::path::Component pattern matching for restore-target traversal"
  patterns:
    - "Pre-flight symlink validation before any filesystem write (defense against TOCTOU symlink redirect)"
    - "Longest-tracked-root prefix match via `Path::starts_with` + `.max_by_key(|p| p.components().count())`"
    - "Component-wise iteration via `relative_parent.components()` with explicit `CurDir | Normal(_) | _` exhaustive match"
    - "NotFound treated as OK (early termination — path doesn't exist yet, restore will create)"
key_files_modified:
  - crates/nono/src/undo/snapshot.rs
key_files_created:
  - .planning/phases/43-upst5-sync-execution/43-02-PRE-CHERRY-PICK-AUDIT.md
  - .planning/phases/43-upst5-sync-execution/43-02-CLOSE-GATE.md
  - .planning/phases/43-upst5-sync-execution/43-02-PR-SECTION.md
  - .planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host (rustup target installed but x86_64-linux-gnu-gcc absent — same precondition as Plan 43-01b); CI lane substitute per .planning/templates/cross-target-verify-checklist.md § PARTIAL Disposition (snapshot.rs is cross-platform Rust, so load-bearing)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host (rustup target installed but cc/clang for macOS absent — same precondition as Plan 43-01b); CI lane substitute per checklist § PARTIAL Disposition (snapshot.rs is cross-platform Rust, so load-bearing)"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent; snapshot.rs unrelated to detached-console PTY path"
  gate_7_wfp_port_integration: "Cargo-level wfp_port_integration tests DID pass in Gate 1 (2 passed, 1 ignored); deep WFP kernel-filter installation environmental-skip per D-40-C2; snapshot.rs unrelated to WFP"
  gate_8_learn_windows_integration: "Cargo-level learn_windows_integration tests DID pass in Gate 1 (60 passed, 14 ignored); deep learn-runtime substrate environmental-skip per D-40-C2; snapshot.rs unrelated to learn"
key_decisions:
  - "DEC-1 (no-interactive-editor protocol observed): used `git -c core.editor=true cherry-pick --no-commit 66c69f86` followed by `git commit -F /tmp/43-02-cherry-pick-msg.txt`. `git cherry-pick --continue` never invoked. `[ ! -f .git/CHERRY_PICK_HEAD ]` confirmed transaction sealed. Per <no_interactive_editor_protocol> mandate."
  - "DEC-2 (path-handling verdict: as-is): pre-cherry-pick audit (Task 1) verified upstream uses `Path::starts_with` component-wise stdlib primitive + `relative_parent.components()` iteration. No `String::starts_with` on paths. Compliant with CLAUDE.md § Common Footguns #1 verbatim. No amendment required."
  - "DEC-3 (clean cherry-pick — no conflicts): `git -c core.editor=true cherry-pick --no-commit 66c69f86` reported `Auto-merging crates/nono/src/undo/snapshot.rs` and exited cleanly. The fork's `restore_failures` aggregation in `restore_to` body (Phase 22 / Phase 41 era) does not overlap with upstream's insertion site; the pre-flight validation loop inserts upstream of the per-file failure handling, preserving fork's aggregation untouched."
  - "DEC-4 (broker pre-build precondition triggered + remediated): Plan 43-01b SUMMARY § Issue 1 documented this Phase 41 D-14 / CR-04 precondition. Same outcome here: first `cargo test --workspace --all-features` failed `broker_launch_assigns_child_to_job_object` because `target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe` was absent. Ran `cargo build -p nono-shell-broker --release` (4m 14s); re-ran tests; all 2197 passed. Documented as environment-setup precondition, not a regression."
  - "DEC-5 (worktree-mode PR-open deferral): worktree executor wrote `43-02-PR-SECTION.md` but did NOT invoke `gh pr edit`. The Phase 43 umbrella PR is not yet opened at the time of this worktree's execution; orchestrator picks up the PR-section + assembles umbrella PR body post-merge. Consistent with Plan 43-01b's deferral pattern."
patterns_established:
  - "Single-file security cherry-pick discipline: when an upstream cluster touches exactly one cross-platform file with no fork-side conflicts, the cherry-pick lands as one atomic D-19 commit with verbatim 6-field trailer; D-43-E1 is trivially honored; no Windows-side accommodation needed."
  - "Path-handling pre-audit before cherry-pick: when CLAUDE.md § Common Footguns #1 applies (security-flavored fix touching path validation), the Task 1 audit must verify upstream's path-comparison style (`Path::starts_with` vs `String::starts_with`) and record the verdict as `as-is | path-handling-amendment-required`. This forecloses silent absorption of a String-compare vulnerability."
  - "Broker pre-build precondition as orchestrator-onboarding item: each new worktree-agent start should consider pre-running `cargo build -p nono-shell-broker --release` to avoid the first-test-run failure mode documented in Plan 43-01b Issue 1 + this plan DEC-4."
requirements_completed:
  - "REQ-UPST5-02 (Cluster 7 portion). 1 of 6 syncable clusters from v0.53.0..v0.54.0 audit now closed (security-flavored Wave 0b sequenced per D-43-A4)."
duration: "≈ 60 minutes (Task 1 audit + Task 2 cherry-pick + Task 3 close-gate + broker pre-build + Task 4 PR-section + Task 5 SUMMARY)"
completed: "2026-05-18"
---

# Phase 43 Plan 02: Snapshot Symlink Fix — Cluster 7 D-19 cherry-pick of upstream 66c69f86

## Outcome

**One-liner:** Single-file cherry-pick of upstream `66c69f86` (`fix(snapshot): validate restore targets against symlinks`) onto fork main as Wave 0b. The cherry-pick adds a pre-flight `validate_restore_target` symlink check inside `SnapshotManager::restore_to`, closing the TOCTOU race window where an attacker creating a symlink between snapshot-taken and restore-invoked could redirect the restore write outside the tracked directory.

The cherry-pick landed verbatim (no path-handling amendment needed); upstream's implementation is CLAUDE.md-compliant (`Path::starts_with` component-wise stdlib primitive + `relative_parent.components()` iteration; no string-path compare). Fork's `restore_to` aggregation behavior preserved untouched.

## Security context

This is a security-flavored fix addressing a TOCTOU (time-of-check-to-time-of-use) race in the snapshot/restore path. Before the fix, an attacker with filesystem write access to a tracked directory could:

1. Wait for a snapshot to be taken.
2. Delete a tracked subdirectory.
3. Create a symlink with the same name pointing to a location OUTSIDE the tracked directory (e.g., `/etc/`, `~/.ssh/`, `C:\Windows\System32\`).
4. Trigger a restore.

Pre-fix: the restore mechanism would `create_dir_all` + write through the symlink, corrupting files in the attacker-chosen location.

Post-fix: `validate_restore_target` runs BEFORE any filesystem write. For each manifest path that needs restoration, it:
- Verifies the longest matching tracked-root prefix (component-wise via `Path::starts_with`).
- Calls `fs::symlink_metadata` on the tracked root → rejects if it is itself a symlink, or is not a directory.
- Walks the relative parent components, calling `fs::symlink_metadata` on each → rejects on any intermediate symlink, or non-directory.
- Treats `NotFound` as OK (early termination — path doesn't exist yet, restore will create).

The TOCTOU window is now structurally closed in the fork too. Per Phase 42 ledger Cluster 7 rationale: "defends restore mechanism against symlink-redirect race conditions; an attacker creating a symlink between snapshot-taken and restore-invoked could redirect the restore write to a location outside the tracked directory, enabling data corruption or trust-boundary escape."

Per CLAUDE.md § Path Handling (CRITICAL):
- **Always use path component comparison, not string operations.** Upstream's implementation uses `Path::starts_with` (component-wise stdlib primitive) and `relative_parent.components()` iteration. No `String::starts_with` on paths. The pre-cherry-pick audit (Task 1) explicitly verified this.
- **Canonicalize paths at the enforcement boundary.** The validator does NOT canonicalize — it inspects each existing component for symlink-ness via `fs::symlink_metadata` (which does NOT follow symlinks). This is the correct primitive — canonicalize would resolve the symlink before the check, defeating the purpose. Component-wise symlink_metadata is the operative defense.
- **Fail secure on any error.** All `fs::symlink_metadata` errors (other than `NotFound`) bubble up as `NonoError::Snapshot`, aborting the restore.

## Performance

- 1 atomic commit + this SUMMARY commit
- Single `cargo build -p nono`: clean (~2m 14s — cold start includes full sigstore + dep rebuild)
- Single `cargo test --workspace --all-features` (post broker pre-build): 2197 passed / 0 failed / 19 ignored
- Single `cargo clippy --workspace --all-targets`: clean (~2m 31s)
- Single `cargo fmt --all -- --check`: clean (no formatting drift)

## Accomplishments

1. **Upstream `66c69f86` cherry-picked verbatim onto fork main with D-19 6-field trailer block.** Commit `07c0fb71` carries `Upstream-commit: 66c69f86`, `Upstream-tag: v0.54.0`, `Upstream-author: Luke Hinds <lukehinds@gmail.com>`, `Upstream-subject: fix(snapshot): validate restore targets against symlinks`, `Upstream-date: 2026-05-12T06:28:34+01:00`, `Upstream-categories: other`, plus `Co-Authored-By` (Luke Hinds) + 2× DCO `Signed-off-by` (Oscar Mack full name + GitHub handle).

2. **Symlink-redirect TOCTOU race closed in fork's snapshot/restore path.** `validate_restore_target` runs pre-flight, before any `create_dir_all`, temp-file creation, rename, or chmod touches the path. Component-wise symlink rejection per CLAUDE.md § Common Footguns #1.

3. **No-interactive-editor protocol observed.** `git -c core.editor=true cherry-pick --no-commit 66c69f86` → `git commit -F /tmp/43-02-cherry-pick-msg.txt` → `[ ! -f .git/CHERRY_PICK_HEAD ]` confirmed sealed. `git cherry-pick --continue` was never invoked, eliminating the Windows-editor stall risk per <no_interactive_editor_protocol> mandate.

4. **D-43-E1 invariant trivially honored.** `git diff --name-only HEAD~1 HEAD` returns exactly one file: `crates/nono/src/undo/snapshot.rs`. Zero `*_windows.rs` edits; zero `crates/nono-shell-broker/` edits.

5. **Fork's `restore_failures` aggregation preserved.** The fork's `restore_to` body retains the per-file failure aggregation (Phase 22 / Phase 41 era — surfaces locked-file failures on Windows without aborting the whole restore). The cherry-pick's pre-flight validation loop inserts upstream of that aggregation; existing per-file failure handling untouched. `git diff HEAD~1 HEAD -- crates/nono/src/undo/snapshot.rs` confirms +175 / -0 (pure additive).

6. **Two new `#[cfg(unix)]` regression tests added.** `restore_rejects_symlinked_parent_directory` + `restore_rejects_symlink_before_create_dir_all`. Skipped on Windows host (correct — Unix-symlink semantics); will execute on Linux + macOS CI lanes.

7. **Path-handling discipline verified pre-cherry-pick.** Task 1's audit (`43-02-PRE-CHERRY-PICK-AUDIT.md`) explicitly verified upstream's path-comparison style; the verdict `as-is` recorded; no amendment applied.

8. **8-check close gate executed.** Gates 1, 2, 5 PASS on Windows host (2197 tests / clippy clean / fmt clean). Gates 3, 4 load-bearing-skip → CI per checklist § PARTIAL Disposition (same cross-toolchain precondition as Plan 43-01b). Gates 6, 7, 8 environmental-skip per D-40-C2 (cargo-level wfp_port + learn_windows tests DID pass inside Gate 1).

9. **PR-section + close-gate evidence produced for orchestrator.** `43-02-PR-SECTION.md` captures the umbrella PR contribution section verbatim; `43-02-CLOSE-GATE.md` captures the 8-gate evidence + threat-model close-out. Worktree-mode `gh pr edit` deferred to orchestrator post-merge.

## Task Commits

| Task | Commit     | Subject                                                                          | Files                                                                  |
|------|------------|----------------------------------------------------------------------------------|------------------------------------------------------------------------|
| 1    | (no commit — text-only audit artifact) | n/a — Task 1 produces `43-02-PRE-CHERRY-PICK-AUDIT.md`              | n/a (artifact picked up by Task 5 SUMMARY commit)                      |
| 2    | `07c0fb71` | fix(snapshot): validate restore targets against symlinks                          | crates/nono/src/undo/snapshot.rs (+175 / -0)                           |
| 3    | (no commit — text-only close-gate evidence) | n/a — Task 3 produces `43-02-CLOSE-GATE.md`                          | n/a (artifact picked up by Task 5 SUMMARY commit)                      |
| 4    | (no commit — text-only PR-section evidence) | n/a — Task 4 produces `43-02-PR-SECTION.md` (worktree-mode deferral) | n/a (artifact picked up by Task 5 SUMMARY commit)                      |
| 5    | (this commit — `docs(43-02): summarize cluster 7 snapshot symlink-validation cherry-pick`) | SUMMARY.md + audit + close-gate + PR-section | 4 planning artifacts                                                   |

## Files Created/Modified

**Created (committed in Task 5):**
- `.planning/phases/43-upst5-sync-execution/43-02-PRE-CHERRY-PICK-AUDIT.md` — Task 1 audit evidence (upstream commit shape + fork-side divergence + path-handling verdict)
- `.planning/phases/43-upst5-sync-execution/43-02-CLOSE-GATE.md` — 8-check close gate evidence (D-43-E9) + Wave 0b baseline-aware CI gate template
- `.planning/phases/43-upst5-sync-execution/43-02-PR-SECTION.md` — Plan 43-02 contribution section for Phase 43 umbrella PR (orchestrator post-merge append)
- `.planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md` — this SUMMARY

**Modified (committed in Task 2 — `07c0fb71`):**
- `crates/nono/src/undo/snapshot.rs` — +175 / -0 (pre-flight `validate_restore_target` check in `restore_to`; new helper `validate_restore_target`; two new `#[cfg(unix)]` regression tests)

## Decisions Made

### DEC-1: No-interactive-editor protocol observed (mandatory per `<no_interactive_editor_protocol>`)

The cherry-pick was executed with `git -c core.editor=true cherry-pick --no-commit 66c69f86`. The `core.editor=true` override (Unix `true` command, returns 0 silently) prevents any editor invocation. The `--no-commit` flag stages without opening an editor. After verifying the staged diff (`git diff --staged --name-only` → `crates/nono/src/undo/snapshot.rs`), the commit was sealed explicitly via `git commit -F /tmp/43-02-cherry-pick-msg.txt`. `git cherry-pick --continue` was never invoked, eliminating the Windows-editor stall risk (T-43-02-07 in the plan threat model). Final assertion `[ ! -f .git/CHERRY_PICK_HEAD ]` confirmed the transaction sealed cleanly.

### DEC-2: Path-handling verdict — `as-is` (no amendment required)

Task 1's pre-cherry-pick audit verified upstream's path-comparison style by reading `git show 66c69f86 -- crates/nono/src/undo/snapshot.rs` end-to-end. Upstream uses:
- `path.starts_with(tracked)` where `path: &Path` and `tracked: &PathBuf` → this is `Path::starts_with` (component-wise stdlib primitive), NOT `String::starts_with`.
- `relative_parent.components()` iteration with explicit `CurDir | Normal(name) | _` exhaustive match — pure component-wise iteration.

Verdict recorded as `as-is`. The cherry-pick landed verbatim with no Path-vs-String amendment. Falsifiable check: `git diff --staged crates/nono/src/undo/snapshot.rs | grep -E '\.starts_with\("/' | wc -l` returns 0 (no string-path comparisons introduced).

### DEC-3: Clean cherry-pick — fork's `restore_failures` aggregation preserved untouched

The fork's `restore_to` body has a fork-only `restore_failures: Vec<(PathBuf, String)>` aggregation (Phase 22 / Phase 41 era; surfaces locked-file failures on Windows without aborting the whole restore). This is the only structural divergence between fork's and upstream's pre-patch shape.

Inspecting upstream's diff context, the insertion site (between `let mut applied_changes = Vec::new();` and `// Restore files from manifest`) is UPSTREAM of the fork's `restore_failures` aggregation. The 3-line context window for `git apply` is satisfied; the fork's extra line stays untouched.

Result: `git -c core.editor=true cherry-pick --no-commit 66c69f86` reported `Auto-merging crates/nono/src/undo/snapshot.rs` and exited cleanly with no conflicts. Verified the +175 / -0 stat matches upstream's diff byte-for-byte.

### DEC-4: Broker pre-build precondition (Plan 43-01b precedent)

First `cargo test --workspace --all-features` run failed `exec_strategy::launch::broker_dispatch_tests::broker_launch_assigns_child_to_job_object` because `target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe` was absent in this fresh worktree. This is the well-documented Phase 41 D-14 / CR-04 environment-setup precondition (also encountered by Plan 43-01b — see its SUMMARY Issue 1).

Remediation:
```bash
cargo build -p nono-shell-broker --release   # 4m 14s
```

Then re-ran the full workspace test gate: `TOTAL: 2197 passed, 0 failed, 19 ignored`. Same numbers as Plan 43-01b's final test gate.

Recommendation (forwarded from Plan 43-01b): orchestrator should pre-run `cargo build -p nono-shell-broker --release` as part of each worktree-agent's environment setup, per Phase 41 CR-04 disposition.

### DEC-5: Worktree-mode PR-open deferral

`43-02-PR-SECTION.md` was written in Task 4 but `gh pr edit <pr-number> --body-file ...` was NOT invoked. The Phase 43 umbrella PR is not yet opened at this worktree's execution time. Orchestrator picks up `43-02-PR-SECTION.md` post-merge, assembles the umbrella PR body (combining 43-01b's section + 43-02's section + downstream waves' sections), and opens the umbrella PR. Consistent with Plan 43-01b's deferral pattern.

## Deviations from Plan

**None.** Plan 43-02 executed exactly as written:
- Task 1: pre-cherry-pick audit landed as `43-02-PRE-CHERRY-PICK-AUDIT.md`; verdict `as-is`.
- Task 2: cherry-pick committed cleanly via no-interactive-editor protocol; D-19 trailer verified; cherry-pick state sealed.
- Task 3: 8-check close gate executed; results recorded in `43-02-CLOSE-GATE.md`; broker pre-build precondition surfaced and remediated per Plan 43-01b precedent (this is a known environment-setup issue, not a deviation).
- Task 4: `43-02-PR-SECTION.md` written; worktree-mode `gh pr edit` deferral documented.
- Task 5: this SUMMARY committed.

The broker pre-build remediation was NOT a Rule 1/2/3 deviation — it's an environment-setup precondition the orchestrator can pre-run. Logged here for awareness and consistency with Plan 43-01b's identical issue.

## Issues Encountered

### Issue 1 — Phase 41 D-14 / CR-04 broker-binary precondition (recurrence from Plan 43-01b)

Identical to Plan 43-01b SUMMARY § Issue 1. First `cargo test --workspace --all-features` failed because the broker release binary was absent in the worktree. Resolved via `cargo build -p nono-shell-broker --release` (4m 14s); re-ran tests; all 2197 passed.

**Recommendation:** orchestrator's worktree-agent environment-setup script should include `cargo build -p nono-shell-broker --release` as a prerequisite to `cargo test --workspace --all-features` (per Phase 41 CR-04 disposition).

## D-43-E9 8-check close gate

See `.planning/phases/43-upst5-sync-execution/43-02-CLOSE-GATE.md` for full evidence. Summary:

| Gate | Description                                           | Disposition                                                                          |
|------|-------------------------------------------------------|--------------------------------------------------------------------------------------|
| 1    | `cargo test --workspace --all-features` (Windows)     | PASS (2197 passed, 0 failed, 19 ignored — post broker pre-build)                     |
| 2    | `cargo clippy --workspace --all-targets` (Windows)    | PASS                                                                                 |
| 3    | `cargo clippy --target x86_64-unknown-linux-gnu`      | load-bearing-skip → CI-verified (cross-toolchain absent — same as 43-01b)            |
| 4    | `cargo clippy --target x86_64-apple-darwin`           | load-bearing-skip → CI-verified (cross-toolchain absent — same as 43-01b)            |
| 5    | `cargo fmt --all -- --check`                          | PASS                                                                                 |
| 6    | Phase 15 5-row detached-console smoke                 | environmental-skip (D-40-C2)                                                         |
| 7    | `wfp_port_integration` tests                          | environmental-skip (cargo-level 2 passed / 1 ignored in Gate 1; deep WFP n/a)        |
| 8    | `learn_windows_integration` tests                     | environmental-skip (cargo-level 60 passed / 14 ignored in Gate 1; deep n/a)          |

## Wave 0b CI Verification — DOWNSTREAM (orchestrator-owned)

Per `.planning/templates/upstream-sync-quick.md:108-113`, the baseline-aware CI gate compares post-merge CI lanes on the head SHA against baseline `13cc0628` (Phase 41 close). In worktree mode, the actual branch-push + CI lane assessment is deferred to the orchestrator.

**Pre-merge expectation (set by Windows-host evidence in Gate sections of `43-02-CLOSE-GATE.md`):**
- Linux + macOS clippy lanes: green→green (PASS) — snapshot.rs is portable Rust; new validator uses `std::fs::symlink_metadata` + `std::path::Component` which are cross-platform stdlib
- Linux + macOS test lanes: green→green (PASS) — new `#[cfg(unix)]` regression tests will execute on Linux + macOS runners
- All 5 Windows CI lanes (Build, Integration, Regression, Security, Packaging): green→green (PASS) — local Windows test gate proves 2197/0 passing; snapshot.rs is platform-neutral pre-flight check
- fmt-check: green→green (PASS)

**Security-flavor posture (per plan ):** "ANY new red lane is a real regression (no carry-forward acceptable for security-flavored work in this plan)." If any lane transitions green→red post-merge, orchestrator escalates as Rule 1.

**Post-merge:** orchestrator fills in the actual lane transition table in `43-02-CLOSE-GATE.md` § "Wave 0b baseline-aware CI gate".

## Threat-model close-out

See `43-02-CLOSE-GATE.md` § Threat-model close-out for the full T-43-02-* register. Summary:

| Threat ID    | Category | Status     |
|--------------|----------|------------|
| T-43-02-01   | Tampering | MITIGATED — the cherry-pick IS the mitigation |
| T-43-02-02   | Tampering | MITIGATED — Task 1 audit verified Path-not-String compare |
| T-43-02-03   | Repudiation | MITIGATED — D-19 6-field trailer + Co-Authored-By + 2 Signed-off-by verified |
| T-43-02-04   | Tampering | MITIGATED — single-file scope (D-43-E1) trivially honored |
| T-43-02-05   | DoS | ACCEPTED — one `symlink_metadata` syscall per restore path is acceptable |
| T-43-02-06   | Information Disclosure | ACCEPTED — `NonoError::Snapshot` only visible to unsandboxed supervisor |
| T-43-02-07   | DoS | MITIGATED — `<no_interactive_editor_protocol>` observed; `[ ! -f .git/CHERRY_PICK_HEAD ]` confirmed sealed |

ASVS L1 disposition satisfied: all high threats mitigated; medium threats mitigated; low threats accepted with explicit documentation.

## Self-Check

| Check                                                                                                                              | Result |
|------------------------------------------------------------------------------------------------------------------------------------|--------|
| `[ -f .planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md ]`                                            | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-02-CLOSE-GATE.md ]`                                                              | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-02-PR-SECTION.md ]`                                                              | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-02-PRE-CHERRY-PICK-AUDIT.md ]`                                                   | FOUND  |
| `git log --oneline -1 07c0fb71` matches `fix(snapshot): validate restore targets against symlinks`                                 | FOUND  |
| `git log -1 --format='%B' 07c0fb71 | grep -c '^Upstream-commit: 66c69f86'` → 1                                                     | PASS   |
| `git log -1 --format='%B' 07c0fb71 | grep -c '^Upstream-tag: v0.54.0'` → 1                                                         | PASS   |
| `git log -1 --format='%B' 07c0fb71 | grep -c '^Upstream-author: '` → 1                                                             | PASS   |
| `git log -1 --format='%B' 07c0fb71 | grep -c '^Upstream-subject: '` → 1                                                            | PASS   |
| `git log -1 --format='%B' 07c0fb71 | grep -c '^Upstream-date: '` → 1                                                               | PASS   |
| `git log -1 --format='%B' 07c0fb71 | grep -c '^Upstream-categories: '` → 1                                                         | PASS   |
| `git log -1 --format='%B' 07c0fb71 | grep -c '^Co-Authored-By: '` → 1 (≥ 1)                                                        | PASS   |
| `git log -1 --format='%B' 07c0fb71 | grep -cE '^Signed-off-by: '` → 2 (≥ 2)                                                        | PASS   |
| `git diff --name-only 07c0fb71~1 07c0fb71` returns exactly `crates/nono/src/undo/snapshot.rs`                                      | PASS   |
| `git diff --name-only 07c0fb71~1 07c0fb71 | grep -cE '_windows\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0           | PASS   |
| `[ ! -f .git/CHERRY_PICK_HEAD ]`                                                                                                   | PASS   |
| `cargo build -p nono` exits 0                                                                                                      | PASS   |
| `cargo test -p nono --lib undo::snapshot` exits 0 (23 passed / 0 failed)                                                           | PASS   |
| `cargo test --workspace --all-features` (post broker pre-build) — 2197 passed / 0 failed / 19 ignored                              | PASS   |
| `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) exits 0                              | PASS   |
| `cargo fmt --all -- --check` exits 0                                                                                               | PASS   |
| `git diff 07c0fb71~1 07c0fb71 -- crates/nono/src/undo/snapshot.rs | grep -E '\.starts_with\("/' | wc -l` → 0                       | PASS   |

Status: **PASSED.**

## User Setup Required

None for this plan instance. Orchestrator (post-merge) responsibilities:
1. Pre-build the broker release binary in fresh worktrees (per Plan 43-01b + 43-02 DEC-4 recommendation).
2. Push the worktree branch to remote.
3. Open or update the Phase 43 umbrella PR with body assembled from `43-01b-PR-SECTION.md` + `43-02-PR-SECTION.md` + any subsequent plan sections.
4. After CI completes on the head SHA, fill in the CI lane transition table in `43-02-CLOSE-GATE.md` § "Wave 0b baseline-aware CI gate".

## Next Phase Readiness

Wave 0b complete. Wave 1 (Plans 43-03 PACK-MGMT + 43-04 RELEASE-RIDE, parallel per D-43-A2) is now **UNBLOCKED**. Wave 2a (Plan 43-05 PLATFORM-DETECTION-FOUNDATION) and Wave 2b (Plan 43-06 PLATFORM-DETECTION-WINDOWS) inherit Wave 0b baseline transitively.

The Phase 43 umbrella PR is NOT yet opened (worktree mode); orchestrator will assemble + open it post-merge per Task 4 + DEC-5 deferral.

The fork's snapshot/restore TOCTOU symlink-redirect window is now closed — security gain banked in v2.5 per Phase 42 Cluster 7 explicit recommendation: "the security flavor argues for sequencing this cluster early in the wave structure to close the symlink-race window in the fork too."
