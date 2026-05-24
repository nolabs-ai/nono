---
plan_id: 48-01
phase: 48
artifact: pre-cherry-pick-audit
cluster: C4
cluster_disposition: will-sync
upstream_sha_range: c2c6f2ca..863bbfd3
upstream_commit_count: 9
baseline_sha: 3f638dc6
verdict: RED
verdict_history:
  - YELLOW (initial Task 1 prediction, 2026-05-24)
  - RED (flipped after empirical cherry-pick attempt on 858ad009 surfaced structural fork-side divergence the prediction missed — see § 9)
cherry_picks_landed:
  - c2c6f2ca → caab9967 (commit 1/9) — 3 trivial import-merge conflicts resolved
  - b8a32006 → a93b2bed (commit 2/9) — clean auto-merge
cherry_picks_remaining: 7 of 9 (858ad009, bbc652a0, 1e9385a7, 98f8cb18, d146001b, a0222be2, 863bbfd3)
generated: 2026-05-24
generated_by: gsd-execute-phase orchestrator (Phase 48 Plan 48-01 Tasks 1+2 partial)
---

# Plan 48-01 Pre-cherry-pick Audit (D-48-B2)

Mandatory pre-flight artifact for Cluster C4 (Linux Landlock v6 signal/socket scoping + af_unix pathname mediation; 9 commits in upstream `v0.55.0`). Mirrors the 8-section shape of `.planning/phases/43-upst5-sync-execution/43-02-PRE-CHERRY-PICK-AUDIT.md` per Convention Pattern D.

## 1. Pre-flight closure (Task 0)

- CWD: `/c/Users/OMack/Nono` (verified per `feedback_windows_worktree_cwd`)
- Plan branch: `phase-48-01-landlock-v6-af-unix` (created off baseline `3f638dc63463d1070334f9a9a3de419168cee27d`)
- Baseline equals HEAD at branch creation: `git rev-parse HEAD` → `3f638dc63463d1070334f9a9a3de419168cee27d`
- `git fetch upstream --tags` succeeded; new branch `upstream/pack-update-hints` observed (informational only)
- All 9 C4 commit shas resolvable locally (`git cat-file -e <sha>^{commit}` exit 0 for each)
- Upstream remote: `https://github.com/always-further/nono.git`
- Origin remote: `https://github.com/oscarmackjr-twg/nono.git`

## 2. Upstream-chronological cherry-pick order (D-48-B1 + Claude's Discretion bullet)

`git log --pretty='%H %ai %s' v0.54.0..v0.57.0 -- crates/nono/src/sandbox/linux.rs crates/nono/src/sandbox/mod.rs crates/nono-cli/src/cli.rs` (filtered to C4 shas, sorted by author date):

| # | author-date (ISO 8601) | sha | subject |
|---|------------------------|-----|---------|
| 1 | 2026-05-13T13:00:14+01:00 | c2c6f2ca | feat(landlock): add landlock v6 signal and abstract unix socket scoping |
| 2 | 2026-05-13T13:26:32+01:00 | b8a32006 | docs(capability): clarify linux signal mode behavior with landlock |
| 3 | 2026-05-13T13:55:51+01:00 | 858ad009 | feat(cli): add recursive unix socket directory grants |
| 4 | 2026-05-13T14:05:36+01:00 | bbc652a0 | feat(unix-socket): record explicit scope for grants |
| 5 | 2026-05-13T14:41:40+01:00 | 1e9385a7 | feat(sandbox): add explicit allowlist for pathname af_unix sockets |
| 6 | 2026-05-13T15:11:14+01:00 | 98f8cb18 | test(supervisor-linux): add unix listener for connect capability test |
| 7 | 2026-05-13T15:31:27+01:00 | d146001b | fix(sandbox): correctly resolve af_unix socket paths for seccomp |
| 8 | 2026-05-13T16:23:12+01:00 | a0222be2 | feat(linux): implement af_unix pathname mediation |
| 9 | 2026-05-13T21:13:14+01:00 | 863bbfd3 | refactor(supervisor): refine ipc denial reporting and audit timestamps |

**Chronological order matches the Phase 47 ledger row order for Cluster C4.** No reordering required. Cherry-picks proceed in this sequence in Task 2.

## 3. Per-commit diff-inspection table

| sha | upstream subject | files touched (fork-shared) | predicted conflict | resolution strategy |
|-----|------------------|-----------------------------|--------------------|--------------------|
| c2c6f2ca | feat(landlock): add landlock v6 signal and abstract unix socket scoping (14 files, +787/−29) | lib.rs, sandbox/mod.rs, sandbox/linux.rs, capability.rs, cli.rs, exec_strategy.rs, output.rs, query_ext.rs, sandbox_prepare.rs, setup.rs, why_runtime.rs, plus 3 docs files | **YES** (lib.rs:89 cfg-gate divergence — fork wraps the `pub use sandbox::{...}` line in `#[cfg(target_os = "linux")]`; upstream edits an unscoped variant) | Keep the fork's `#[cfg(target_os = "linux")]` gate and merge the new items (`LandlockScopePolicy`, `landlock_scope_policy`) into the same gated block. Apply the same gate-preservation strategy to `sandbox/mod.rs` if a parallel divergence surfaces. In-commit edit. |
| b8a32006 | docs(capability): clarify linux signal mode behavior with landlock (2 files, +16/−11) | capability.rs, sandbox/linux.rs (small) | LOW (docs-only on capability.rs; sandbox/linux.rs touch is test conciseness) | Apply as-is; verify after c2c6f2ca lands (capability.rs hunk may shift contextually) |
| 858ad009 | feat(cli): add recursive unix socket directory grants (11 files, +624/−76) | capability_ext.rs, cli.rs, output.rs, profile/mod.rs (+20), capability.rs, sandbox/macos.rs, state.rs (+58/−13), plus 3 docs files | MEDIUM (profile/mod.rs +20 lines is additive; state.rs touch is serialization migration) | Apply as-is; if `profile/mod.rs` exhaustive match arms become non-exhaustive, extend in-commit (same rule as a0222be2 per § 5) |
| bbc652a0 | feat(unix-socket): record explicit scope for grants (7 files, +116/−49) | CHANGELOG.md (+8), capability_ext.rs, cli.rs, sandbox/linux.rs, sandbox/macos.rs, plus 2 docs files | LOW (additive `SocketScope` enum + helper consolidation) | Apply as-is. CHANGELOG.md `[unreleased]` hunk lands cleanly. |
| 1e9385a7 | feat(sandbox): add explicit allowlist for pathname af_unix sockets (4 files, +324/−67) | exec_strategy.rs, supervisor_linux.rs (+304/−), supervised_runtime.rs, sandbox/linux.rs | MEDIUM (supervisor_linux.rs hot-spot; will land after c2c6f2ca's supervisor edits) | Apply as-is; rely on c2c6f2ca's earlier landing to give supervisor_linux.rs its current shape |
| 98f8cb18 | test(supervisor-linux): add unix listener for connect capability test (1 file, +1) | supervisor_linux.rs | NONE (1-line test addition) | Apply as-is |
| d146001b | fix(sandbox): correctly resolve af_unix socket paths for seccomp (2 files, +80/−19) | supervisor_linux.rs (+90/−), sandbox/linux.rs | LOW (sequential fixup on top of 1e9385a7 surface) | Apply as-is |
| a0222be2 | feat(linux): implement af_unix pathname mediation (21 files, +903/−70) | **profile/mod.rs (+71)**, policy.rs (+1), diagnostic.rs (+135), exec_strategy.rs (+204/−), supervisor_linux.rs (+268), execution_runtime.rs, launch_runtime.rs, main.rs, profile_cmd.rs, profile_runtime.rs, rollback_runtime.rs, sandbox_prepare.rs, setup.rs, supervised_runtime.rs, schema_shape.rs, sandbox/linux.rs, sandbox/mod.rs, lib.rs, plus 1 docs file | **HIGH** (profile/mod.rs adds `pub enum LinuxAfUnixMediation`, `pub struct LinuxConfig`, `pub linux: LinuxConfig` field. Fork's `impl From<ProfileDeserialize> for Profile` at line 2068 must extend the exhaustive match arm to cover the new field) | Extend `impl From<ProfileDeserialize> for Profile` in the **same commit body** per D-19 fidelity. Compile-time enforcement via `cargo build -p nono-cli` is the falsifier. Apply pre-flight § 5 strategy verbatim. |
| 863bbfd3 | refactor(supervisor): refine ipc denial reporting and audit timestamps (2 files, +79/−64) | exec_strategy.rs, supervisor_linux.rs | MEDIUM (supervisor_linux.rs refactor on top of 1e9385a7 + d146001b + a0222be2 surface) | Apply as-is; rely on chronological stacking |

**Aggregate fork-shared file touch count vs the 18 files in plan frontmatter:** matches. Additional files brought in by full cherry-pick that are NOT in frontmatter (`state.rs`, `diagnostic.rs`, `execution_runtime.rs`, `profile_cmd.rs`, `profile_runtime.rs`, `rollback_runtime.rs`, `schema_shape.rs`, `CHANGELOG.md`, `docs/cli/**`) are accepted — the frontmatter `files_modified` lists the audit-narrowed surface; cherry-picks bring the full upstream commits.

## 4. Re-export scan on C4 lead commit `c2c6f2ca` (Phase 47 D-47-D2 re-confirmation)

```
$ git show c2c6f2ca -- crates/nono/src/sandbox/linux.rs | grep '^+pub'
+pub struct LandlockScopePolicy {
+pub fn landlock_scope_policy(caps: &CapabilitySet) -> Result<LandlockScopePolicy> {
+pub fn landlock_scope_policy_with_abi(

$ git show c2c6f2ca -- crates/nono/src/sandbox/mod.rs | grep '^+pub use'
+pub use linux::{DetectedAbi, LandlockScopePolicy, detect_abi, landlock_scope_policy};

$ git show c2c6f2ca -- crates/nono/src/lib.rs | grep '^+pub use'
+pub use sandbox::{DetectedAbi, LandlockScopePolicy, detect_abi, is_wsl2, landlock_scope_policy};
```

**Intra-cluster origin confirmed.** `LandlockScopePolicy`, `landlock_scope_policy`, and `landlock_scope_policy_with_abi` are introduced as new `pub` items in `c2c6f2ca` (Cluster C4 lead). The re-export edits in `sandbox/mod.rs` and `lib.rs` add those same items into the public surface in the same commit. `DetectedAbi`, `detect_abi`, `is_wsl2` are pre-existing items being extended; no external dependency on a non-C4 cluster.

**Per `feedback_cluster_isolation_invalid` preventive discipline:** the Phase 47 audit's conclusion of intra-cluster integrity for C4 holds.

**Note for c2c6f2ca cherry-pick (fork-side adaptation):** the fork wraps the `pub use sandbox::{DetectedAbi, detect_abi, is_wsl2}` line in `#[cfg(target_os = "linux")]` at `lib.rs:88-89`. Upstream's hunk targets an unscoped variant. Resolution: preserve the fork's `#[cfg(target_os = "linux")]` gate and merge the new items into the gated block, producing `#[cfg(target_os = "linux")] pub use sandbox::{detect_abi, is_wsl2, DetectedAbi, LandlockScopePolicy, landlock_scope_policy};`. Strategic intent: keep the Windows-build green by preventing Linux-only types from leaking into the cross-platform re-export surface.

## 5. profile/mod.rs hot-spot inspection (Phase 47 Empirical cross-check File #4) — commit `a0222be2`

```
$ git show a0222be2 -- crates/nono-cli/src/profile/mod.rs | grep -E '^[+-](enum|struct|impl From|pub|\s+pub)'
+pub enum LinuxAfUnixMediation {
+    pub fn is_pathname(self) -> bool {
+pub struct LinuxConfig {
+    pub af_unix_mediation: Option<LinuxAfUnixMediation>,
+    pub linux: LinuxConfig,
```

**Upstream change shape:**
- Introduces `pub enum LinuxAfUnixMediation` with `is_pathname(self) -> bool` method
- Introduces `pub struct LinuxConfig { pub af_unix_mediation: Option<LinuxAfUnixMediation>, ... }`
- Adds `pub linux: LinuxConfig` field to a parent struct (likely `ProfileDeserialize` / `Profile`)

**Fork-side anchor:**
- `struct ProfileDeserialize` at line 2021
- `impl From<ProfileDeserialize> for Profile` at line 2068
- The fork's exhaustive `From<ProfileDeserialize>` match arm (per Phase 36-01b D-36-B1) MUST be extended to cover the new `linux: LinuxConfig` field.

**Strategy (in-commit; D-19 fidelity preserved):**
1. Let cherry-pick apply upstream's a0222be2 hunks.
2. If `cargo build -p nono-cli` fails with `non_exhaustive` / missing-field errors at line 2068+, edit `impl From<ProfileDeserialize> for Profile` in the SAME conflict-resolution pass — do NOT split into a separate fork-side commit.
3. The extension must map `raw.linux` → `Profile.linux` (or equivalent target field) using the upstream-canonical `LinuxConfig` shape.
4. Compile-time enforcement: `cargo build -p nono-cli` is the falsifier.
5. PATTERNS.md row #6 invariant: profile round-trip tests at lines 289-311 must still pass post-cherry-pick (covered in Task 3 Gate 1 `cargo test --workspace`).

## 6. Windows-arm intersection check (D-48-B2 rationale; D-48-E1 invariant)

```
$ git grep -nE 'cfg\(target_os\s*=\s*"windows"\)|cfg\(windows\)' \
    crates/nono/src/lib.rs crates/nono/src/sandbox/linux.rs crates/nono-cli/src/exec_strategy.rs
crates/nono-cli/src/exec_strategy.rs:23:#[cfg(target_os = "windows")]
crates/nono/src/lib.rs:82:#[cfg(target_os = "windows")]
crates/nono/src/lib.rs:90:#[cfg(target_os = "windows")]
crates/nono/src/lib.rs:102:#[cfg(target_os = "windows")]
```

**Inspection:** None of the four Windows-cfg blocks contain (or are adjacent to) the lines the C4 cherry-picks edit:
- `exec_strategy.rs:23` — gates a Windows-only `use crate::{DETACHED_LAUNCH_ENV, DETACHED_SESSION_ID_ENV}` import. C4 edits are below in non-cfg regions.
- `lib.rs:82` — gates `pub use sandbox::windows::{...}` re-exports (Windows-only Phase 41 supervisor surface).
- `lib.rs:90` — wraps `pub use sandbox::{detect_abi, is_wsl2, DetectedAbi};` in a `#[cfg(target_os = "linux")]` block (NOT windows — `cfg(target_os = "linux")` matched the regex spuriously above; re-checked manually: this is `#[cfg(target_os = "linux")]` at line 89 — outside the windows-cfg set).
- `lib.rs:102` — gates Windows-specific re-export block.

**D-48-E1 invariant preserved:** Cluster C4 cherry-picks land ZERO hunks inside `#[cfg(target_os = "windows")]` or `#[cfg(windows)]` blocks. Per Phase 47 ledger row "C4 | ... | no" (windows-touch column) — re-confirmed empirically.

## 7. Audit verdict + cherry-pick strategy

**Verdict: YELLOW**

Two commits predicted to require in-commit fork-side extension (NOT escalation to D-48-B3 split):

| sha | extension required | scope |
|-----|--------------------|-------|
| `c2c6f2ca` | Preserve `#[cfg(target_os = "linux")]` gate on `lib.rs` re-export line; merge new items into gated block | 1 hunk, ~1 line |
| `a0222be2` | Extend `impl From<ProfileDeserialize> for Profile` exhaustive match at `profile/mod.rs:2068+` to cover new `pub linux: LinuxConfig` field | 1 hunk, ~5-10 lines depending on field count |

All remaining 7 commits predicted to apply cleanly (LOW/MEDIUM conflict pressure; standard 3-way merge resolution).

**Proceed to Task 2** with the documented per-commit conflict-resolution steps. **Do NOT escalate to D-48-B3 split.** If a NEW conflict surfaces during cherry-pick that is not predicted above, STOP per Task 2 step 6 instruction and flip the verdict here to RED before continuing.

## 8. Acceptance summary (per-commit final disposition)

| sha | predicted | disposition |
|-----|-----------|-------------|
| c2c6f2ca | YELLOW | approved for cherry-pick (with cfg-gate preservation on lib.rs) |
| b8a32006 | LOW | approved for cherry-pick |
| 858ad009 | MEDIUM | approved for cherry-pick |
| bbc652a0 | LOW | approved for cherry-pick |
| 1e9385a7 | MEDIUM | approved for cherry-pick |
| 98f8cb18 | NONE | approved for cherry-pick |
| d146001b | LOW | approved for cherry-pick |
| a0222be2 | HIGH | approved for cherry-pick (with in-commit `From<ProfileDeserialize>` exhaustive-match extension per § 5) |
| 863bbfd3 | MEDIUM | approved for cherry-pick |

**Overall:** 9/9 approved for cherry-pick. No splits. Foundation gate clear to proceed to Task 2.

---

## 9. Verdict flip to RED (post-empirical-attempt amendment, 2026-05-24)

The initial YELLOW verdict was based on diff-stat inspection (§ 3) and re-export analysis (§ 4-5). Empirical cherry-pick attempts revealed the audit systematically underestimated structural fork-side divergence on shared files. The verdict is flipped to **RED** and the plan needs replanning or human-resolved cherry-picks for the remaining 7 commits.

### Empirical findings

**Commit c2c6f2ca (cherry-pick #1) — landed as `caab9967`:**
- Predicted: 1 lib.rs conflict (cfg-gate divergence)
- Actual: 3 conflicts (lib.rs, sandbox/mod.rs, why_runtime.rs) — all trivial import/re-export set merges, all fork-side superset of upstream
- Resolution: trivial; all preserved fork's Windows-cfg re-export blocks + extended linux-cfg gated lines with new upstream items
- Per-commit smoke: `cargo build --workspace` PASS in 40s

**Commit b8a32006 (cherry-pick #2) — landed as `a93b2bed`:**
- Predicted: LOW (docs-only + small test conciseness)
- Actual: clean auto-merge, no conflicts

**Commit 858ad009 (cherry-pick #3) — ATTEMPTED + ABORTED:**
- Predicted: MEDIUM (profile/mod.rs +20 lines minor)
- **Actual: 13 conflict blocks across 11 files** — significantly broader than predicted:
  - `crates/nono-cli/src/capability_ext.rs` — 3 conflicts including a structural divergence at L757 where the fork renamed `profile.filesystem.deny` → `profile.policy.add_deny_access` (likely Phase 36-01b work) and upstream inserts a new 143-line `unix_socket_bind` loop in the deny-loop region. Resolution requires inserting upstream's loop while preserving the fork's rename — NOT a "take theirs" or "take ours" merge.
  - `crates/nono-cli/src/cli.rs` — 5 conflicts (likely mix of import merges + flag/arg structural changes)
  - `crates/nono-cli/src/output.rs` — 1 conflict (fork-empty, take upstream — trivial)
  - `crates/nono-cli/src/profile/mod.rs` — 4 conflicts (1 with 7-line HEAD divergence, 2 with 11-line HEAD divergence — substantial fork-side structural code requiring careful merge)
  - `crates/nono/src/capability.rs` — 5 conflicts (4 trivial, 1 with 7-line HEAD divergence)
  - `crates/nono/src/lib.rs` — 1 import-set merge (trivial)
  - `crates/nono/src/sandbox/macos.rs` — 2 large fork-empty blocks (154 + 252 lines, "take upstream" trivial)
  - `crates/nono/src/state.rs` — 5 fork-empty blocks (all "take upstream" — UnixSocketCapState struct + restoration loop + 3 test additions)
  - `docs/cli/features/profile-authoring.mdx`, `profiles-groups.mdx`, `docs/cli/usage/flags.mdx` — 3 doc files with section-add conflicts (resolved via `git checkout --theirs`)

**Why the audit was wrong:**
- § 3 diff-stat inspection (`git show --stat`) showed file-touch counts but not per-line conflict locations
- § 4 re-export scan covered only `c2c6f2ca` lead commit; subsequent commits' divergence-overlap was not exhaustively pre-inspected
- § 5 profile/mod.rs hot-spot scan only covered `a0222be2`; missed that `858ad009` ALSO touches profile/mod.rs in regions where the fork has 11+ line structural divergence
- The fork's Phase 36-01b refactor of profile structure (`profile.policy.add_deny_access` rename) was known per PATTERNS.md row #6 but was not mapped to specific upstream commits' conflict zones

### Recommended next steps

Two viable paths for the remaining 7 cherry-picks (858ad009 onwards), to be decided by the maintainer:

**Path A: Split escalation per D-48-B3 + Convention Pattern F.** Replan Plan 48-01 into:
- `48-01a-clean-cherry-picks-PLAN.md`: commits 1-2 (already landed) + simple `git checkout --theirs` files-only commits (those where ALL HEAD sides are empty)
- `48-01b-structural-merge-PLAN.md`: commits requiring careful semantic merge (858ad009 + a0222be2 minimum)

**Path B: Fresh subagent context per commit.** Hand each remaining commit to a dedicated `gsd-executor` agent with a fresh 200K context budget. Each agent reads the relevant fork-side files in depth, resolves conflicts with semantic understanding, commits with trailer, runs smoke build. Sequential (Wave 1 file-overlap forces it anyway).

**Path C: Human-in-the-loop per commit.** Maintainer drives `git cherry-pick` interactively, decides resolution per conflict, commits with the trailer template at the top of this audit. Highest fidelity for security-critical merge work but slowest cadence.

### State at handoff (2026-05-24)

- Branch: `phase-48-01-landlock-v6-af-unix` (off baseline `3f638dc6`)
- HEAD: `a93b2bed` (cherry-pick 2/9 landed; build verified)
- Working tree: clean (cherry-pick 3 attempt reverted via `git reset --hard HEAD`)
- No `gh pr` opened (Task 5 not reached)
- No close-gate run (Task 3 not reached)
- No CI push (Task 4 not reached)
- `.git/COMMIT_TRAILER_TMP` exists — safe to delete; was used as scratch for the 2 landed commits
