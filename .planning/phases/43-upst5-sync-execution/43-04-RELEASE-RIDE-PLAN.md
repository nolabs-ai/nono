---
plan_id: 43-04-RELEASE-RIDE
phase: 43-upst5-sync-execution
plan: 04
wave: "1"
type: execute
cluster_id: 3
disposition: will-sync
upstream_range: v0.53.0..v0.54.0
upstream_shas: [6b00932f, 803c6947]
upstream_tag: v0.54.0
baseline_sha: 13cc0628
umbrella_pr_section: "Plan 43-04 — Cluster 3 release v0.54.0 (CHANGELOG-only) + nix dep bump"
opens_umbrella_pr: false
requirements: [REQ-UPST5-02]
depends_on: ["43-02-SNAPSHOT-SYMLINK-FIX"]
autonomous: true
files_modified:
  - CHANGELOG.md
  - crates/nono/Cargo.toml
  - crates/nono-cli/Cargo.toml
  - Cargo.lock
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (load-bearing for nix dep bump only; CHANGELOG-only commit has no compiled-code effect)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (load-bearing for nix dep bump only)"
  gate_6_phase15_smoke: "CHANGELOG-only changes have no compiled-code effect; Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent (release-ride exception per Phase 40 Plan 40-04)"
  gate_7_wfp_port_integration: "CHANGELOG-only changes have no compiled-code effect; release-ride exception per Phase 40 Plan 40-04"
  gate_8_learn_windows_integration: "CHANGELOG-only changes have no compiled-code effect; release-ride exception per Phase 40 Plan 40-04"
wave_1_parallel_branch_strategy:
  protocol: per-plan-feature-branch
  branch_from: post-Wave-0b-head  # i.e., the commit produced by Plan 43-02 close
  baseline_ci_gate: compare-each-branch-independently-vs-13cc0628
  umbrella_pr_body_update: orchestrator-post-both-wave-1-plans-close
  rationale: D-43-E6 + project_cross_fork_pr_pattern — one PR per branch pair (GitHub one-PR-per-branch-pair rule means per-plan upstream PRs require per-plan feature branches)
  branch_name: "43-04-cluster-3"
  coordination_note: "Plans 43-03 and 43-04 BOTH branch from post-Wave-0b-head independently; no shared branch; surface-disjoint per D-43-A2. Orchestrator merges both branches before opening/updating umbrella PR body with both Wave 1 sections."
must_haves:
  truths:
    - "Pre-flight Wave 1 branching: feature branch `43-04-cluster-3` created from post-Wave-0b-head (Plan 43-02 close SHA, substituted at plan-open) per `wave_1_parallel_branch_strategy.protocol: per-plan-feature-branch`; no shared branch with Plan 43-03 — surface-disjoint per D-43-A2 + memory `project_cross_fork_pr_pattern`"
    - "Cherry-pick of 6b00932f (chore: release v0.54.0) lands as a SINGLE commit with Cargo.toml + Cargo.lock + per-crate Cargo.toml version-bump hunks REVERTED per D-43-E10 BEFORE the final `git commit -F` (no --amend per CLAUDE.md commit policy — see B-3 fix: --no-commit + reverts + explicit commit-with-D-19-trailer in a single pass)"
    - "Cherry-pick of 803c6947 (chore(deps): bump nix from 0.31.2 to 0.31.3) lands as a straight cherry-pick — nix is a cross-platform Unix dep used by nono + nono-cli, no Windows-only effect"
    - "Both cherry-picks carry verbatim 6-line D-19 trailer block (D-43-E2)"
    - "Fork's workspace version pin (0.53.0 across all 5 crate-level Cargo.toml files, OR workspace-inherited if Plan 43-01 centralized version) preserved across 6b00932f cherry-pick — verified via dual-shape acceptance (literal pin OR `version.workspace = true`); fork version NUMBER must remain 0.53.0 regardless of shape"
    - "6b00932f commit body documents exactly which hunks were reverted (Cargo.toml/Cargo.lock per-crate version bumps) per D-43-E10 + Phase 40 Plan 40-04 DEC-2; this documentation is in the INITIAL commit message (written via `git commit -F`), NOT added via --amend"
    - "CHANGELOG.md absorbs upstream v0.54.0 release notes; fork's existing version entries preserved; C5 SHAs (`ce06bd59` Cluster 5 + `0748cced`/`5d821c12` Cluster 4) explicitly tagged inline as 'to be handled via Plan 43-05 / Plan 43-06' per Phase 40 Plan 40-04 DEC-3 precedent"
    - "Zero green→red lane transitions vs baseline SHA 13cc0628 (D-43-E3); per-branch-independent comparison per `wave_1_parallel_branch_strategy.baseline_ci_gate`"
    - "Cross-target clippy load-bearing only for nix dep bump (CHANGELOG-only is out-of-scope for cross-target clippy per .planning/templates/cross-target-verify-checklist.md § Scope); Gates 3+4 load-bearing for nix dep bump commit, environmental for CHANGELOG-only commit"
    - "Zero touches to fork-only Windows files — D-43-E1 (Cluster 3 is CHANGELOG + Unix-side dep bump, no Windows-only effect per Phase 42 ledger)"
    - "Plan 43-04 contribution section appended to Phase 43 umbrella PR body (D-43-E6); orchestrator handles per-plan-branch merge + umbrella body update after BOTH Wave 1 plans close per `wave_1_parallel_branch_strategy.umbrella_pr_body_update`"
    - "No --amend used anywhere in this plan: cherry-picks use `--no-commit` + reverts + explicit `git commit -F` workflow; commit body (including D-19 trailer + revert documentation) is written into the message file BEFORE commit, never amended after"
  artifacts:
    - path: CHANGELOG.md
      provides: "Fork CHANGELOG with upstream v0.54.0 release notes absorbed"
      contains: "0.54.0"
    - path: .planning/phases/43-upst5-sync-execution/43-04-RELEASE-RIDE-SUMMARY.md
      provides: "Per-commit cherry-pick log with reverted-hunks evidence + 8-check close gate + PR umbrella contribution"
  key_links:
    - from: CHANGELOG.md fork's existing [0.53.0] heading
      to: upstream v0.54.0 release notes absorbed under it (per Phase 40 Plan 40-04 DEC-3 precedent)
      via: subsection markers labelled "absorbed from upstream v0.54.0 — <date>"
      pattern: "absorbed from upstream"
---

<objective>
Cherry-pick Cluster 3's 2 upstream commits — (a) `6b00932f chore: release v0.54.0` (CHANGELOG-only per the Phase 40 release-ride convention D-43-E10: fork DROPS upstream Cargo.toml + Cargo.lock version-bump hunks, absorbs only CHANGELOG.md entries) + (b) `803c6947 chore(deps): bump nix from 0.31.2 to 0.31.3` (straight cherry-pick — cross-platform Unix syscall dep, no Windows effect) — onto fork main as Wave 1 in parallel with Plan 43-03-PACK-MGMT.

Per D-43-A2 + Phase 42 ledger: Cluster 3 is surface-disjoint from Cluster 1 (CHANGELOG + nix dep bump vs CLI surface). Per `wave_1_parallel_branch_strategy` frontmatter (B-1 fix): each Wave 1 plan operates on its own feature branch (`43-04-cluster-3` for this plan), branching from post-Wave-0b-head; orchestrator merges both feature branches before umbrella PR body update.

Per D-43-E10 + Phase 40 Plan 40-04 precedent (commit `64b231a7` for upstream v0.52.0 release): the fork tracks its own version pin (currently 0.53.0); upstream's chore-release version-bump hunks are reverted. **B-3 fix: revert workflow is `--no-commit` + revert hunks + write commit message file (with D-19 trailer + revert documentation) + explicit `git commit -F` — NEVER --amend, since CLAUDE.md commit policy prefers new commits and has no "mechanical reshaping" exception.**

Output: 1 feature branch (`43-04-cluster-3`) + 2 cherry-pick commits (1 with explicit revert hunks for `6b00932f` via `--no-commit` + revert + `git commit -F`; 1 straight cherry-pick for `803c6947`) + 1 SUMMARY.md + 1 contribution section appended to Phase 43 umbrella PR.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/43-upst5-sync-execution/43-CONTEXT.md (D-43-E10 release-ride convention)
@.planning/phases/43-upst5-sync-execution/43-PATTERNS.md § Plan 43-04 (Phase 40 Plan 40-04 SUMMARY verbatim precedent)
@.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md § Cluster: Release v0.54.0 + nix bump
@.planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md (Wave 0b close; depends_on; provides post-Wave-0b-head SHA)
@.planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md (PRIMARY skeleton — verbatim release-ride precedent for upstream v0.53.0 release commit c4b25b8 → Phase 43 mirrors for v0.54.0 release commit 6b00932f)
@.planning/templates/upstream-sync-quick.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md
@CHANGELOG.md

<interfaces>
<!-- Current shape of fork CHANGELOG.md + per-crate Cargo.toml — verified via Read at plan-open. -->

Fork's current version pin: 0.53.0 (workspace-wide). Verified per `Cargo.toml:1-9` + `crates/nono/Cargo.toml:3` + `crates/nono-cli/Cargo.toml:3` + `crates/nono-proxy/Cargo.toml:3` + `crates/nono-shell-broker/Cargo.toml:3` + `bindings/c/Cargo.toml:3`.

**Note (post-Plan-43-01 shape):** Plan 43-01's edition-2024 cherry-pick may have centralized `version` into `[workspace.package]` (i.e., per-crate Cargo.toml files switch from literal `version = "0.53.0"` to `version.workspace = true`). The dual-shape acceptance from Plan 43-01 Task 2 carries forward: each per-crate Cargo.toml may have EITHER literal pin OR workspace inheritance. Plan 43-04 Task 1 verifies which shape is active.

Fork's `CHANGELOG.md` exists; existing `[0.53.0] - 2026-05-14` (or similar) heading per Phase 40 Plan 40-04 SUMMARY DEC-3 precedent. Upstream v0.54.0 entries will be absorbed UNDER fork's existing version heading per Phase 40 DEC-3 (NOT as a separate fork's-0.54.0 heading — fork is still at 0.53.0).

Fork's `crates/nono/Cargo.toml` + `crates/nono-cli/Cargo.toml` use `nix` directly (NOT via workspace deps), per Phase 40 Plan 40-04 SUMMARY observation. Upstream's 803c6947 bumps `nix` 0.31.2 → 0.31.3; the per-crate Cargo.toml dep declarations must each accept the new version.

If Plan 43-01 (Cluster 2 edition-2024) introduced workspace-level `nix` deps (it might — per Phase 42 ledger Cluster 2 promotes `nix` to workspace deps), then 803c6947 must bump the workspace `nix` dep instead of per-crate. The executor verifies at cherry-pick time which shape the post-Plan-43-01 fork uses.
</interfaces>

<upstream_commits>
| Position | SHA (abbrev) | Subject | Cherry-pick shape |
|---|---|---|---|
| 1 | 6b00932f | chore: release v0.54.0 | CHANGELOG-only per D-43-E10; revert Cargo.toml + Cargo.lock + all 5 per-crate Cargo.toml version hunks via `--no-commit` + `git checkout HEAD --` + `git commit -F` (NO --amend) |
| 2 | 803c6947 | chore(deps): bump nix from 0.31.2 to 0.31.3 | Straight cherry-pick; per-crate (or workspace-level if Plan 43-01 promoted nix) |

Chronological order: 803c6947 lands BEFORE 6b00932f in upstream history (the release commit is the v0.54.0 tag itself; the dep bump landed earlier in the v0.53.0..v0.54.0 range). Verify with `git log -1 --format='%aI' <sha>` for each.

Categories: `other` for both. windows-touch: `no` for both (verified via Phase 42 D-42-C2).
</upstream_commits>

<d19_trailer_block_template>
Verbatim per template; applied to each of 2 cherry-picks:
```
Upstream-commit: <8-char>
Upstream-tag: v0.54.0
Upstream-author: <from `git log -1 --format='%an <%ae>' <sha>`>
Upstream-subject: <from `git log -1 --format='%s' <sha>`>
Upstream-date: <from `git log -1 --format='%aI' <sha>`>
Upstream-categories: other
Co-Authored-By: <same name + email as Upstream-author>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
</d19_trailer_block_template>

<no_amend_release_ride_workflow>
<!-- B-3 fix: CLAUDE.md commit policy says "prefer new commits over amending"; there is NO "mechanical reshaping" exception. The release-ride workflow that previously used --amend (Task 3 step 9) is replaced with a single-pass `--no-commit` + revert + `commit -F` flow that writes the complete commit message (including D-19 trailer + revert documentation) in ONE commit operation. -->

**Release-ride cherry-pick workflow (NO --amend, NO --continue):**

1. `git -c core.editor=true cherry-pick --no-commit <release-sha>`  # stages without committing or opening editor
2. Revert the version-bump hunks: `git checkout HEAD -- Cargo.toml Cargo.lock <per-crate-Cargo.toml-files>`
3. Stage only CHANGELOG.md (and any other allowed files): `git add CHANGELOG.md`
4. Verify staged diff scope: `git diff --staged --name-only` returns ONLY allowed files
5. Build the complete commit message INCLUDING D-19 trailer + `Reverted from upstream's release commit:` documentation, write to `/tmp/43-04-cp-<sha>.txt`
6. Commit explicitly: `git commit -F /tmp/43-04-cp-<sha>.txt`  # single commit, no editor, no amend
7. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]] || { echo "FAIL"; exit 1; }`

This produces a SINGLE commit with the correct message (D-19 trailer + revert documentation) — no --amend needed, no editor opened.
</no_amend_release_ride_workflow>
</context>

<tasks>

<task id="1" type="execute" autonomous="true">
  <name>Task 1: Pre-flight Wave-1 branching + resolve chronological order + verify CHANGELOG + Cargo.toml baseline</name>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md DEV-2 (release-commit Cargo.toml revert convention)
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md DEC-3 (CHANGELOG fork-conflict resolution under existing version heading)
    - .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md § Cluster 3
    - CHANGELOG.md (full file — verify current shape)
    - Cargo.toml + all 5 per-crate Cargo.toml files (verify version pin = 0.53.0)
    - memory: project_cross_fork_pr_pattern (per-plan feature branches)
    - PLAN.md frontmatter `wave_1_parallel_branch_strategy` block
  </read_first>
  <action>
    1. Confirm Plan 43-02 closed: `git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: 66c69f86'` → 1. Capture post-Wave-0b-head SHA: `POST_WAVE_0B_HEAD=$(git rev-parse HEAD)` (must be identical to Plan 43-03's captured SHA — both Wave 1 plans branch from the same point).
    2. **Pre-flight Wave-1 branching (B-1 fix per `wave_1_parallel_branch_strategy.protocol`):** create the per-plan feature branch for Cluster 3:
       `git checkout -b 43-04-cluster-3 $POST_WAVE_0B_HEAD`
       Document the substituted SHA in `.planning/phases/43-upst5-sync-execution/43-04-BRANCH.txt` (one line: `branch=43-04-cluster-3 from=$POST_WAVE_0B_HEAD`).
    3. Resolve chronological order:
       ```
       for sha in 6b00932f 803c6947; do git log -1 --format='%aI %H %s' $sha; done | sort -k1
       ```
       Record order (expected: 803c6947 first, 6b00932f second) into `.planning/phases/43-upst5-sync-execution/43-04-CHERRY-PICK-ORDER.md`.
    4. Verify fork's version pin = 0.53.0 (dual-shape post-Plan-43-01):
       `grep -h '^version' Cargo.toml crates/nono/Cargo.toml crates/nono-cli/Cargo.toml crates/nono-proxy/Cargo.toml crates/nono-shell-broker/Cargo.toml bindings/c/Cargo.toml | sort -u`
       Expected: only `version = "0.53.0"` (workspace root inherits from `[workspace.package]` per Plan 43-01 edition-2024 cherry-pick).
       Also accept dual-shape per Plan 43-01 acceptance: each per-crate file matches EITHER literal `^version = "0\.53\.0"` OR `^version\.workspace = true`. Record per-file shape.
    5. Verify CHANGELOG.md shape: confirm a `[0.53.0]` heading (or whatever fork's current pin maps to) exists. Record line number for the upstream-v0.54.0-absorption-target insertion point.
    6. Verify nix dep shape post-Plan-43-01:
       `grep -nE 'nix.*workspace.*=.*true|^nix = \"' crates/nono/Cargo.toml crates/nono-cli/Cargo.toml Cargo.toml 2>/dev/null`
       Record whether nix is now workspace-level (Plan 43-01 promoted it per Phase 42 ledger Cluster 2) or still per-crate. This determines the shape of the 803c6947 cherry-pick application.
    7. Record per-SHA pre-flight audit into `.planning/phases/43-upst5-sync-execution/43-04-PRE-CHERRY-PICK-AUDIT.md`:
       - 803c6947: shape (workspace vs per-crate nix dep), conflict prediction
       - 6b00932f: hunks to revert per crate (list of files), CHANGELOG conflict prediction, per-crate version-shape (literal vs inherited) so revert command knows which files to checkout
       - C5/C4 SHA presence in upstream v0.54.0 CHANGELOG entry: `git show 6b00932f -- CHANGELOG.md | grep -cE 'ce06bd59|0748cced|5d821c12'` → record count (expected ≥ 1 — these are C4+C5 SHAs that Plans 43-05 + 43-06 will handle; must be inline-tagged per Phase 40 Plan 40-04 DEC-3)
  </action>
  <acceptance_criteria>
    - Per-plan feature branch created: `git rev-parse --abbrev-ref HEAD` → `43-04-cluster-3`
    - Branch baseline recorded: `.planning/phases/43-upst5-sync-execution/43-04-BRANCH.txt` exists with substituted `$POST_WAVE_0B_HEAD` SHA
    - `.planning/phases/43-upst5-sync-execution/43-04-CHERRY-PICK-ORDER.md` exists with 2 sorted rows
    - All 5 per-crate Cargo.toml files (+ root workspace) verified preserving fork pin 0.53.0 in some shape (literal or workspace-inherited)
    - CHANGELOG.md current shape captured (existing `[0.53.0]` heading line number recorded)
    - nix dep shape (workspace vs per-crate) recorded
    - `.planning/phases/43-upst5-sync-execution/43-04-PRE-CHERRY-PICK-AUDIT.md` exists with both per-SHA audit rows + per-crate version-shape inventory
  </acceptance_criteria>
  <done>Wave-1 per-plan feature branch `43-04-cluster-3` created from post-Wave-0b-head per `wave_1_parallel_branch_strategy`; cherry-pick order resolved + per-SHA audit complete + per-crate version-shape inventory captured; cherry-pick chain safe to proceed.</done>
</task>

<task id="2" type="execute" autonomous="true">
  <name>Task 2: Cherry-pick 803c6947 (nix dep bump — straight cherry-pick)</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-04-CHERRY-PICK-ORDER.md
    - .planning/phases/43-upst5-sync-execution/43-04-PRE-CHERRY-PICK-AUDIT.md
    - .planning/phases/43-upst5-sync-execution/43-04-BRANCH.txt (verify current branch is 43-04-cluster-3)
    - .planning/templates/upstream-sync-quick.md (D-19 trailer block)
  </read_first>
  <action>
    **Pre-flight:** verify current branch is `43-04-cluster-3`: `[[ "$(git rev-parse --abbrev-ref HEAD)" == "43-04-cluster-3" ]]`. If not, `git checkout 43-04-cluster-3` first.
    1. Working tree clean check.
    2. `git -c core.editor=true cherry-pick --no-commit 803c6947`
    3. Resolve any conflicts:
       - If nix is per-crate post-Plan-43-01 (per Task 1 audit), apply upstream's bump to each per-crate file
       - If nix was promoted to workspace deps in Plan 43-01, apply the bump to the workspace `[workspace.dependencies]` entry instead
       - Cargo.lock will need regen post-edit (`cargo update -p nix` to bump the lockfile entry)
    4. Verify staged diff scope:
       - `git diff --staged --name-only` — should be `Cargo.toml` (workspace) AND/OR `crates/nono/Cargo.toml` + `crates/nono-cli/Cargo.toml`, AND `Cargo.lock`
       - `git diff --staged --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0
    5. Build D-19 trailer block per template; write commit message to `/tmp/43-04-cp-803c6947.txt`:
       - Verbatim upstream subject + body
       - `Fork-side notes:` paragraph documenting the nix dep shape (workspace vs per-crate) applied
       - 6-line D-19 trailer + 1 Co-Authored-By + 2 Signed-off-by
    6. Commit explicitly: `git commit -F /tmp/43-04-cp-803c6947.txt`
    7. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]] || { echo "FAIL"; exit 1; }`
    8. Verify build: `cargo build --workspace` exits 0 (catches any nix 0.31.3 API break)
  </action>
  <acceptance_criteria>
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-commit: 803c6947'` → 1
    - `git log -1 --format='%B' HEAD | grep -cE '^(Upstream-tag|Upstream-author|Upstream-subject|Upstream-date|Upstream-categories|Co-Authored-By): '` → ≥ 6
    - `git log -1 --format='%B' HEAD | grep -cE '^Signed-off-by: '` → ≥ 2
    - `git diff --name-only HEAD~1 HEAD | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0
    - `grep -h 'nix' Cargo.toml crates/nono/Cargo.toml crates/nono-cli/Cargo.toml 2>/dev/null | grep -c '0\\.31\\.3'` → ≥ 1
    - Cherry-pick state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`
    - `cargo build --workspace` exits 0
  </acceptance_criteria>
  <done>803c6947 cherry-pick committed with D-19 trailer; nix bumped to 0.31.3; workspace builds clean; no --amend used.</done>
</task>

<task id="3" type="execute" autonomous="true">
  <name>Task 3: Cherry-pick 6b00932f (release v0.54.0) — CHANGELOG-only per D-43-E10 via single-commit revert workflow (NO --amend)</name>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md DEV-2 (revert convention; lines 119-127) + DEC-3 (CHANGELOG conflict pattern; line 104)
    - .planning/phases/43-upst5-sync-execution/43-04-PRE-CHERRY-PICK-AUDIT.md (Task 1 audit including C4+C5 SHA presence in upstream's v0.54.0 CHANGELOG entry + per-crate version-shape inventory)
    - `<no_amend_release_ride_workflow>` block above (MANDATORY — B-3 fix; replaces previous --amend-based workflow)
    - CLAUDE.md § Commits (DCO sign-off required; prefer new commits over --amend — no "mechanical reshaping" exception exists)
  </read_first>
  <action>
    Apply the `<no_amend_release_ride_workflow>` single-pass cherry-pick (B-3 fix — previous version used --amend in step 9; replaced with single `git commit -F` that writes the complete message including D-19 trailer + revert documentation in one operation):

    1. Working tree clean check.
    2. `git -c core.editor=true cherry-pick --no-commit 6b00932f`
    3. Apply the Phase 40 release-ride convention per D-43-E10 — REVERT Cargo.toml + Cargo.lock + per-crate Cargo.toml version-bump hunks. Build the file list dynamically using Task 1's per-crate version-shape inventory (only checkout files that actually carry a local `version =` declaration; for files using `version.workspace = true`, the workspace root is the only file to checkout for the version):
       ```
       # Always checkout root + Cargo.lock
       git checkout HEAD -- Cargo.toml Cargo.lock
       # For each per-crate file with literal version pin (per Task 1 audit), checkout:
       for f in <files-with-literal-version-pin-from-Task-1-audit>; do
         git checkout HEAD -- "$f"
       done
       # Files using version.workspace = true automatically inherit from the reverted root Cargo.toml
       ```
    4. Resolve CHANGELOG.md manually per Phase 40 Plan 40-04 DEC-3 pattern:
       - Open CHANGELOG.md and the staged conflict
       - KEEP fork's existing entries (including existing `[0.53.0]` heading and its body)
       - Insert upstream's v0.54.0 release notes under fork's existing `[0.53.0]` heading (per Phase 40 Plan 40-04 DEC-3 — the version pin mismatch is handled by absorbing under fork's existing version heading with subsection markers labelled "absorbed from upstream v0.54.0 - <upstream date>")
       - For C4 SHAs `0748cced` + `5d821c12` and C5 SHA `ce06bd59` if they appear in upstream's v0.54.0 CHANGELOG entry per Task 1 audit: tag inline as "to be handled via Plan 43-05 (platform-detection foundation) / Plan 43-06 (Windows platform detection)" — explicit boundary so reviewers see Phase 43 + Phase 43 plan structure
       - For Cluster 1 commit SHAs (42601ed7, 98c18f1f, 18b03fa6, 317c97b7, 5098fc1c, be23d6df, a5985edd, 64d9f283) if they appear in upstream's v0.54.0 CHANGELOG entry: note "absorbed via Plan 43-03" inline
       - For Cluster 7 commit `66c69f86` if it appears: note "absorbed via Plan 43-02"
       - For Cluster 6 (won't-sync) commits `548bb800`, `021074c9`, `ff2d8b84`: note "won't-sync per Phase 42 ledger Cluster 6 / D-43-D1 — fork's clippy ruleset diverges; selective absorption deferred"
       - For Cluster 2 commit `8b888a1c`: note "absorbed via Plan 43-01"
    5. Stage CHANGELOG.md only:
       `git add CHANGELOG.md`
    6. Verify nothing else is staged:
       `git diff --staged --name-only` should return only `CHANGELOG.md`
    7. Verify no Windows-only file edits:
       `git diff --staged --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0
    8. **Build the complete commit message INCLUDING D-19 trailer + revert documentation, write to `/tmp/43-04-cp-6b00932f.txt` (B-3 fix — message written BEFORE commit, NOT amended after):**
       - Verbatim upstream subject + body (preserved from `git log -1 --format=%B 6b00932f`)
       - `Reverted from upstream's release commit:` section explicitly enumerating each reverted hunk (Cargo.toml workspace version, Cargo.lock version, each per-crate Cargo.toml version that had a literal pin per Task 1 audit). Cite D-43-E10 + Phase 40 Plan 40-04 DEV-2 precedent commit `64b231a7`.
       - `Fork-side notes:` paragraph documenting the per-crate version-shape (literal vs workspace-inherited) preserved
       - 6-line D-19 trailer block (Upstream-commit, Upstream-tag, Upstream-author, Upstream-subject, Upstream-date, Upstream-categories)
       - 1 Co-Authored-By line
       - 2 Signed-off-by lines
    9. Commit EXPLICITLY in one operation (NO --amend, NO `--continue`):
       `git commit -F /tmp/43-04-cp-6b00932f.txt`
       This single commit carries the complete message (D-19 trailer + revert documentation) — no follow-up amend needed.
    10. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]] || { echo "FAIL: cherry-pick state still open"; exit 1; }`
    11. Verify version pins UNCHANGED:
        `grep -h '^version' Cargo.toml crates/nono/Cargo.toml crates/nono-cli/Cargo.toml crates/nono-proxy/Cargo.toml crates/nono-shell-broker/Cargo.toml bindings/c/Cargo.toml | sort -u` returns only `version = "0.53.0"` (or only workspace-inherited shape if Plan 43-01 promoted version to workspace)
  </action>
  <acceptance_criteria>
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-commit: 6b00932f'` → 1
    - `git log -1 --format='%B' HEAD | grep -cE '^(Upstream-tag|Upstream-author|Upstream-subject|Upstream-date|Upstream-categories|Co-Authored-By): '` → ≥ 6
    - `git log -1 --format='%B' HEAD | grep -cE '^Signed-off-by: '` → ≥ 2
    - `git log -1 --format='%B' HEAD | grep -c '^Reverted from upstream'` → 1 (revert-hunks documentation present IN the initial commit message, not amended)
    - `git diff --name-only HEAD~1 HEAD` returns exactly `CHANGELOG.md`
    - `grep -h '^version' Cargo.toml crates/nono/Cargo.toml crates/nono-cli/Cargo.toml crates/nono-proxy/Cargo.toml crates/nono-shell-broker/Cargo.toml bindings/c/Cargo.toml | sort -u` returns only one version line at fork's pin (0.53.0)
    - `grep -c '^## \\[0.53.0\\]' CHANGELOG.md` → ≥ 1 (fork's existing heading preserved)
    - `grep -c 'absorbed from upstream v0.54.0' CHANGELOG.md` → ≥ 1 (per Phase 40 DEC-3 subsection markers)
    - For any C4/C5 SHA found in Task 1 audit: corresponding "to be handled via Plan 43-0X" inline tag present in CHANGELOG.md
    - **Cherry-pick state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`**
    - **No --amend used:** verify reflog shows single commit operation, not commit-then-amend: `git reflog HEAD@{0} HEAD@{2} | grep -c 'amend' → 0` (no amend ops in reflog for this task's commit)
  </acceptance_criteria>
  <done>6b00932f cherry-pick committed as a SINGLE commit via `--no-commit` + revert + explicit `git commit -F` workflow (NO --amend per CLAUDE.md commit policy + B-3 fix); CHANGELOG-only per D-43-E10; version pins preserved; revert hunks documented in the initial commit message; cross-plan C4/C5 SHA boundaries marked inline.</done>
</task>

<task id="4" type="execute" autonomous="true">
  <name>Task 4: Per-plan 8-check close gate (D-43-E9) + Wave 1 baseline-aware CI gate</name>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md (close gate section lines 142-184)
    - .planning/phases/43-upst5-sync-execution/43-03-CLOSE-GATE.md (Wave 1 sibling format if available)
  </read_first>
  <action>
    Execute D-43-E9 8-check close gate. Per-gate disposition (per frontmatter `skipped_gates_rationale`):
    - Gates 1, 2, 5: required (run as standard)
    - Gates 3, 4 cross-target clippy: load-bearing for the nix dep bump (cross-platform Unix dep with cfg-gated callers). Pure CHANGELOG-only 6b00932f cherry-pick adds nothing to compile, but 803c6947 changes nix dep version — the load-bearing scope applies to the nix dep bump commit
    - Gates 6, 7, 8: environmental-skip (Phase 40 Plan 40-04 precedent — release-ride CHANGELOG is documentation-only; nix dep affects Unix-side code only)

    Per `wave_1_parallel_branch_strategy.baseline_ci_gate: compare-each-branch-independently-vs-13cc0628`, this plan's CI comparison is `43-04-cluster-3` head vs `13cc0628` ONLY — do NOT include Plan 43-03's commits in the diff. The orchestrator merges both branches before umbrella PR body update; each plan's individual CI baseline is independent.

    Record into `.planning/phases/43-upst5-sync-execution/43-04-CLOSE-GATE.md`. Per-job CI table mirroring Phase 40 Plan 40-04 SUMMARY lines 162-184 format.

    Baseline-aware CI gate vs `13cc0628`: zero green→red transitions required.
  </action>
  <acceptance_criteria>
    - Gates 1, 2, 5 exit 0 on Windows host
    - Gates 3, 4 either exit 0 OR documented `skipped_gates_load_bearing: [3, 4]` with PARTIAL Disposition prose for nix dep bump (rationale in frontmatter)
    - Gates 6, 7, 8 documented `skipped_gates_environmental: [6, 7, 8]` with "CHANGELOG-only — no compiled-code effect" rationale (in frontmatter)
    - Baseline CI gate: zero green→red transitions vs `13cc0628` (independent `43-04-cluster-3`-head comparison per `wave_1_parallel_branch_strategy.baseline_ci_gate`)
    - `.planning/phases/43-upst5-sync-execution/43-04-CLOSE-GATE.md` exists with all evidence
  </acceptance_criteria>
  <done>Close gate executed on independent `43-04-cluster-3` branch with release-ride-specific skip categorization; baseline CI clean.</done>
</task>

<task id="5" type="execute" autonomous="true">
  <name>Task 5: Append Plan 43-04 contribution section to umbrella PR + Write SUMMARY.md</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md (PRIMARY SUMMARY skeleton)
    - All Tasks 1-4 artifacts
    - PLAN.md frontmatter `wave_1_parallel_branch_strategy.umbrella_pr_body_update` (orchestrator-driven)
  </read_first>
  <action>
    1. Write `.planning/phases/43-upst5-sync-execution/43-04-PR-SECTION.md`:
       ```markdown
       ## Plan 43-04 — Cluster 3 release v0.54.0 (CHANGELOG-only) + nix dep bump

       **Cluster:** 3 (Release v0.54.0 + nix bump)
       **Disposition:** will-sync (D-19 cherry-pick of 2 upstream SHAs with release-ride convention) on feature branch `43-04-cluster-3`
       **Upstream commits:** 803c6947 (nix 0.31.2 → 0.31.3 straight cherry-pick) + 6b00932f (release v0.54.0 — CHANGELOG-only per D-43-E10; Cargo.toml + Cargo.lock + per-crate version-bump hunks reverted per Phase 40 Plan 40-04 precedent commit 64b231a7; via single-pass `--no-commit` + revert + `git commit -F` workflow per CLAUDE.md commit policy — NO --amend)
       **Files touched:** CHANGELOG.md (upstream v0.54.0 entries absorbed under fork's existing version heading) + crates/nono/Cargo.toml + crates/nono-cli/Cargo.toml + Cargo.lock (nix dep bump only; version pins preserved at 0.53.0)
       **Key decision:** D-43-E10 release-ride convention applied to 6b00932f — fork tracks own version separately; only CHANGELOG entries absorbed. C4 (Cluster 4 Windows platform detection) + C5 (Cluster 5 platform-conditional profile fields) commit SHAs found in upstream's v0.54.0 CHANGELOG entry are inline-tagged "to be handled via Plan 43-05 / Plan 43-06" per Phase 40 Plan 40-04 DEC-3 cross-plan boundary marking. Wave 1 per-plan-feature-branch protocol per `wave_1_parallel_branch_strategy` (D-43-E6 + project_cross_fork_pr_pattern).
       **CI baseline diff:** zero `success → failure` transitions vs baseline `13cc0628` (independent `43-04-cluster-3`-head comparison per `wave_1_parallel_branch_strategy.baseline_ci_gate`)
       ```
    2. Per `wave_1_parallel_branch_strategy.umbrella_pr_body_update: orchestrator-post-both-wave-1-plans-close`: orchestrator handles the actual umbrella PR body update after BOTH Wave 1 plans (43-03 + 43-04) close. This task produces the contribution-section text only.
    3. Write `.planning/phases/43-upst5-sync-execution/43-04-RELEASE-RIDE-SUMMARY.md` mirroring Phase 40 Plan 40-04 SUMMARY skeleton verbatim. Frontmatter `skipped_gates_load_bearing: [3, 4]` + `skipped_gates_environmental: [6, 7, 8]` + `skipped_gates_rationale` block + `wave_1_parallel_branch_strategy` block. Document the release-ride convention application in DEC-N sections + explicit DEC entry citing B-3 fix (single-pass `--no-commit` workflow replacing --amend). Include the per-job CI table. Include a "Wave 1 branch coordination" section.
    4. Commit: `git commit -m "docs(43-04): summarize cluster 3 release-ride + nix dep bump" --signoff`
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-04-PR-SECTION.md` exists
    - `.planning/phases/43-upst5-sync-execution/43-04-RELEASE-RIDE-SUMMARY.md` exists
    - SUMMARY frontmatter contains `cluster_id: 3`, `requirements_completed: [REQ-UPST5-02]`, `skipped_gates_*` lists, `skipped_gates_rationale`, `wave_1_parallel_branch_strategy`
    - SUMMARY explicitly cites D-43-E10 + Phase 40 Plan 40-04 precedent commit `64b231a7`
    - SUMMARY explicitly documents the no-amend single-pass release-ride workflow per B-3 fix
    - "Wave 1 branch coordination" section present documenting feature-branch strategy
    - `grep -c 'absorbed from upstream' CHANGELOG.md` → ≥ 1 (verifies DEC-3 absorption pattern)
    - `git log -1 --format='%s' HEAD | grep -E '^docs\\(43-04\\):'` matches
  </acceptance_criteria>
  <done>Plan 43-04 contribution section captured; umbrella PR body update deferred to orchestrator per `wave_1_parallel_branch_strategy`; SUMMARY.md written + committed.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| upstream release-commit Cargo.toml version-bump hunks → fork's workspace version pin | If silently accepted, fork would re-bump to upstream's 0.54.0; fork tracks own version 0.53.0 |
| upstream CHANGELOG.md entry → fork's CHANGELOG.md | Conflict resolution must preserve fork's existing entries AND absorb upstream's new entries; if fork's entries are dropped, traceability lost |
| nix 0.31.2 → 0.31.3 API surface | Minor version bump in Unix syscall crate; any behavior change in `nix::*` callers must be caught by Gates 3+4 cross-target clippy |
| C4/C5 SHAs mentioned in upstream's v0.54.0 CHANGELOG entry → cross-plan coordination | Plans 43-05 + 43-06 handle these clusters; CHANGELOG must inline-tag them so reviewers see plan boundaries |
| `git commit --amend` on a cherry-pick → CLAUDE.md commit policy violation | Previous version of plan used --amend in Task 3 step 9; CLAUDE.md says "prefer new commits over amending" and has no "mechanical reshaping" exception. Replaced with single-pass `--no-commit` + revert + `git commit -F` workflow per B-3 fix |
| Wave 1 parallel branches (`43-03-cluster-1` + `43-04-cluster-3`) → umbrella PR | Per memory `project_cross_fork_pr_pattern`, GitHub's one-PR-per-branch-pair rule requires per-plan feature branches |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-43-04-01 | Tampering | fork's workspace version pin (0.53.0) silently bumped to 0.54.0 by accepting upstream's release-commit Cargo.toml hunks | mitigate | Task 3 step 3 reverts Cargo.toml + Cargo.lock + 5 per-crate Cargo.toml files (dynamic file-list per Task 1 per-crate version-shape inventory) per D-43-E10 + Phase 40 Plan 40-04 DEV-2 precedent. Verified via Task 3 acceptance grep returning only one `version = "0.53.0"` line across all crate Cargo.toml files |
| T-43-04-02 | Tampering | fork's CHANGELOG.md existing entries silently dropped during merge conflict resolution | mitigate | Task 3 step 4 applies the Phase 40 Plan 40-04 DEC-3 pattern explicitly: KEEP fork's existing entries, absorb upstream's entries UNDER fork's existing version heading with "absorbed from upstream v0.54.0" subsection markers. Verified via Task 3 acceptance grep `## [0.53.0]` count ≥ 1 |
| T-43-04-03 | Repudiation | cherry-pick commit missing D-19 trailer block | mitigate | Tasks 2 + 3 acceptance verify trailer presence via grep on each commit; D-19 trailer is part of the INITIAL commit message (single-pass write via `git commit -F`), not added via --amend |
| T-43-04-04 | Tampering | nix 0.31.2 → 0.31.3 minor bump introduces a behavior change that breaks fork's Unix-side syscall callers (crates/nono-cli/exec_strategy/, crates/nono/sandbox/linux.rs) | mitigate | Task 4 Gate 3 cross-target Linux clippy (load-bearing for nix dep bump) + Gate 1 cargo test catches API breaks. If a behavior change surfaces, classify per Phase 40 CR-A class (separate follow-on fix with `fix(43-04-cra):` prefix — NEVER --amend). Per Phase 42 ledger Cluster 3: "cross-platform dependency bump with no Windows-only effect" — Unix-side coverage is the load-bearing test |
| T-43-04-05 | Tampering | C4/C5 SHAs absorbed silently into CHANGELOG without inline cross-plan tagging — reviewers may interpret as already-shipped when they're actually Plans 43-05/06's scope | mitigate | Task 3 step 4 explicitly tags C4 SHAs (`0748cced`, `5d821c12`) and C5 SHA (`ce06bd59`) as "to be handled via Plan 43-05 / Plan 43-06" inline. Verified by manual review of CHANGELOG.md before commit. Phase 40 Plan 40-04 DEC-3 set the precedent for this cross-plan boundary marking |
| T-43-04-06 | Tampering | --amend on cherry-pick commit changes the commit hash AND violates CLAUDE.md commit policy ("prefer new commits over amending") | mitigate | B-3 fix: previous version of plan used --amend in Task 3 step 9. Replaced with single-pass `--no-commit` + revert + `git commit -F` workflow per `<no_amend_release_ride_workflow>` block. The complete commit message (D-19 trailer + revert documentation) is written into the message file BEFORE commit, never amended after. Verified via Task 3 acceptance: `git reflog | grep -c 'amend' → 0` for this task's commit |
| T-43-04-07 | Tampering | Wave 1 branches share commits with each other due to missing branch protocol | mitigate | `wave_1_parallel_branch_strategy.protocol: per-plan-feature-branch` enforced via Task 1 pre-flight (`git checkout -b 43-04-cluster-3 $POST_WAVE_0B_HEAD`); Plan 43-03 branches `43-03-cluster-1` independently from the same SHA. Orchestrator merges both before umbrella PR body update. CI comparison is per-branch-independent per `baseline_ci_gate` |

**ASVS L1 disposition:** `high` threats (T-43-04-01 version-pin tampering; T-43-04-02 CHANGELOG drop; T-43-04-05 cross-plan tagging) — mitigate. `medium` threats (T-43-04-03 trailer; T-43-04-04 nix API break; T-43-04-06 amend prohibition; T-43-04-07 branch coordination) — mitigate. Security gate satisfied.
</threat_model>

<verification>
Per-plan close gate (D-43-E9 = Phase 34 D-34-D2 8-check format) — release-ride exception per <must_includes_per_plan> §9:

| Gate | Description | Required | Disposition |
|------|-------------|----------|-------------|
| 1 | `cargo test --workspace --all-features` (Windows host) | required | execute |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | required | execute |
| 3 | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | load-bearing (nix dep bump touches Unix-side callers) | execute or skipped_gates_load_bearing → CI-verified |
| 4 | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped_gates_load_bearing → CI-verified |
| 5 | `cargo fmt --all -- --check` | required | execute |
| 6 | Phase 15 5-row detached-console smoke | environmental — CHANGELOG-only has no compiled-code effect | skipped_gates_environmental with rationale |
| 7 | `wfp_port_integration` tests | environmental — CHANGELOG-only has no compiled-code effect | skipped_gates_environmental |
| 8 | `learn_windows_integration` tests | environmental — CHANGELOG-only has no compiled-code effect | skipped_gates_environmental |

Wave 1 baseline-aware CI gate: zero `success → failure` lane transitions vs baseline SHA `13cc0628` per D-43-E3; per-branch-independent comparison per `wave_1_parallel_branch_strategy.baseline_ci_gate`.
</verification>

<success_criteria>
- 803c6947 (nix 0.31.2 → 0.31.3) cherry-picked as straight cherry-pick with verbatim D-19 trailer
- 6b00932f (release v0.54.0) cherry-picked CHANGELOG-only per D-43-E10 via single-pass `--no-commit` + revert + `git commit -F` workflow per CLAUDE.md commit policy (NO --amend per B-3 fix); commit message includes D-19 trailer + revert documentation in the INITIAL commit (not amended after)
- Wave 1 per-plan-feature-branch protocol honored per `wave_1_parallel_branch_strategy` (B-1 fix)
- Fork's version pin (0.53.0) preserved across both cherry-picks
- CHANGELOG.md absorbs upstream v0.54.0 entries under fork's existing version heading per Phase 40 Plan 40-04 DEC-3 pattern
- C4/C5/Cluster-1/Cluster-7/Cluster-6 cross-plan SHAs inline-tagged in CHANGELOG per cross-plan boundary marking
- D-43-E1 invariant holds (0 Windows-file touches)
- D-43-E9 8-check close gate with release-ride skip categorization (load-bearing 3+4 for nix dep; environmental 6-8 for CHANGELOG-only)
- Wave 1 baseline-aware CI gate: zero green→red transitions vs `13cc0628` (per-branch-independent comparison)
- Plan 43-04 contribution section appended to Phase 43 umbrella PR (orchestrator-driven after both Wave 1 plans close per `wave_1_parallel_branch_strategy.umbrella_pr_body_update`)
- SUMMARY.md committed
- REQ-UPST5-02 acceptance criteria #1 advanced for Cluster 3
- No --amend used anywhere in this plan's execution
</success_criteria>

<output>
After completion, create `.planning/phases/43-upst5-sync-execution/43-04-RELEASE-RIDE-SUMMARY.md` per Task 5 specification.
</output>
</output>
