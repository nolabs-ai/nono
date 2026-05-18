---
plan_id: 43-03-PACK-MGMT
phase: 43-upst5-sync-execution
plan: 03
wave: "1"
type: execute
cluster_id: 1
disposition: will-sync
upstream_range: v0.53.0..v0.54.0
upstream_shas: [42601ed7, 98c18f1f, 18b03fa6, 317c97b7, 5098fc1c, be23d6df, a5985edd, 64d9f283]
upstream_tag: v0.54.0
baseline_sha: 13cc0628
umbrella_pr_section: "Plan 43-03 — Cluster 1 pack management (nono update + pinning/outdated + hints)"
opens_umbrella_pr: false
requirements: [REQ-UPST5-02]
depends_on: ["43-02-SNAPSHOT-SYMLINK-FIX"]
autonomous: true
files_modified:
  - crates/nono-cli/src/pack_update_hint.rs
  - crates/nono-cli/src/package.rs
  - crates/nono-cli/src/package_cmd.rs
  - crates/nono-cli/src/registry_client.rs
  - crates/nono-cli/src/app_runtime.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/cli_bootstrap.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/sandbox_prepare.rs
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (all 9 modified files are cross-platform Rust, so load-bearing)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (all 9 modified files are cross-platform Rust, so load-bearing)"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_7_wfp_port_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_8_learn_windows_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
wave_1_parallel_branch_strategy:
  protocol: per-plan-feature-branch
  branch_from: post-Wave-0b-head  # i.e., the commit produced by Plan 43-02 close
  baseline_ci_gate: compare-each-branch-independently-vs-13cc0628
  umbrella_pr_body_update: orchestrator-post-both-wave-1-plans-close
  rationale: D-43-E6 + project_cross_fork_pr_pattern — one PR per branch pair (GitHub one-PR-per-branch-pair rule means per-plan upstream PRs require per-plan feature branches)
  branch_name: "43-03-cluster-1"
  coordination_note: "Plans 43-03 and 43-04 BOTH branch from post-Wave-0b-head independently; no shared branch; surface-disjoint per D-43-A2. Orchestrator merges both branches before opening/updating umbrella PR body with both Wave 1 sections."
scope_justification: "5 tasks at upper-edge of context budget; mirrors Phase 40 Plan 40-01's 5-commit chain pattern verbatim; Task 2 internally decomposed via per-commit interim close-gate checkpoints at commits 3 + 5 per CR-A class regression handling pattern. Recommendation explicitly preserved current structure rather than splitting."
must_haves:
  truths:
    - "All 8 upstream Cluster 1 cherry-picks landed on fork main with verbatim 6-line D-19 trailer block per commit (D-43-E2)"
    - "Cherry-picks applied in TRUE upstream chronological order (commit date), not Phase 42 ledger table order — per Phase 40 Plan 40-01 DEV-1 lesson"
    - "Pre-flight Wave 1 branching: feature branch `43-03-cluster-1` created from post-Wave-0b-head (Plan 43-02 close SHA, substituted at plan-open) per `wave_1_parallel_branch_strategy.protocol: per-plan-feature-branch`; no shared branch with Plan 43-04 — surface-disjoint per D-43-A2 + memory `project_cross_fork_pr_pattern`"
    - "New CLI surface (`nono update`, `nono package pinning`, `nono package outdated`, pack-update-hints) composes additively with fork's existing `nono package` command surface — no command-name collision"
    - "Phase 36-01b `From<ProfileDeserialize> for Profile` exhaustive match preserved (no Cluster 1 commit touches profile/mod.rs::From impl — Phase 42 ledger confirms pack-mgmt surface is disjoint from profile-deserialization)"
    - "Phase 36-01c `bypass_protection` rename honored (no Cluster 1 commit references pre-rename `override_deny` in pack-mgmt code paths)"
    - "Zero green→red lane transitions vs baseline SHA 13cc0628 (D-43-E3); interim close-gate checkpoints every 3-4 cherry-picks to surface regressions early per 43-PATTERNS.md Pattern 1 + Phase 40 Plan 40-01 CR-A class handling"
    - "All cross-target clippy lanes (Linux + macOS) exit 0 — or marked load-bearing-skip → CI-verified (D-43-E4); all 9 modified files are cross-platform Rust"
    - "Zero touches to fork-only Windows files — D-43-E1 (8 commits × 0 Windows files = 0)"
    - "Plan 43-03 contribution section appended to Phase 43 umbrella PR body (D-43-E6); orchestrator handles per-plan-branch merge + umbrella body update after BOTH Wave 1 plans close per `wave_1_parallel_branch_strategy.umbrella_pr_body_update`"
    - "Workspace edits touch all 5 Cargo.toml files atomically IF a cluster commit adds dependencies — per memory `project_workspace_crates` (D-43-E5); Cluster 1 likely doesn't but planner verifies at cherry-pick time"
    - "Any CR-A class mechanical fix lands as separate `chore(43-03):` follow-on commit per CLAUDE.md commit policy (NEVER --amend; CLAUDE.md has no 'mechanical reshaping' exception)"
  artifacts:
    - path: crates/nono-cli/src/pack_update_hint.rs
      provides: "Pack update hint surface with refresh-on-first-run + unparsable-version-treated-as-older logic"
    - path: crates/nono-cli/src/package_cmd.rs
      provides: "`nono package pinning` + `nono package outdated` subcommands"
    - path: crates/nono-cli/src/cli.rs
      provides: "`nono update` top-level command surface"
    - path: .planning/phases/43-upst5-sync-execution/43-03-PACK-MGMT-SUMMARY.md
      provides: "Per-commit cherry-pick chain log + 8-check close gate evidence + PR umbrella contribution section"
  key_links:
    - from: cli.rs `nono update` command
      to: registry_client.rs registry refresh path
      via: "package manager update flow"
      pattern: "nono update|update_packages"
    - from: package_cmd.rs `pinning`/`outdated` subcommands
      to: package.rs package metadata + version compare
      via: "version compare logic (unparsable = older)"
      pattern: "pinning|outdated"
---

<objective>
Cherry-pick Cluster 1's 8 upstream commits (new pack-management CLI surface: `nono update`, `nono package pinning`, `nono package outdated`, inline pack-update hints + formatting/error-handling polish) onto fork main as a Wave 1 cherry-pick chain. Per Phase 42 ledger Cluster 1: all 8 touch only cross-platform `crates/nono-cli/src/` files (`pack_update_hint.rs`, `package*.rs`, `registry_client.rs`, `cli.rs`, `app_runtime.rs`, `cli_bootstrap.rs`, `main.rs`, `sandbox_prepare.rs`); no `_windows.rs` or `platform.rs` intersection; new CLI surface composes additively with fork's existing `nono package` command surface.

Wave 1 runs in parallel with Plan 43-04-RELEASE-RIDE per D-43-A2 (surface-disjoint: Cluster 1 = CLI surface, Cluster 3 = CHANGELOG + nix dep). Per `wave_1_parallel_branch_strategy` frontmatter (B-1 fix): each Wave 1 plan operates on its own feature branch (`43-03-cluster-1` for this plan), branching from post-Wave-0b-head; orchestrator merges both feature branches before umbrella PR body update.

Plan 43-03 uses the Phase 40 Plan 40-01 multi-commit cherry-pick chain pattern with interim close-gate checkpoints every 3-4 commits (Phase 40 CR-A class regression handling per 40-01 DEV-3). CR-A fixes land as separate commits (NEVER --amend per CLAUDE.md commit policy).

Output: 1 feature branch (`43-03-cluster-1`) + 8 cherry-pick commits + (optional) 1-2 CR-A follow-on fix commits if interim CI gate catches regressions (separate commits, never --amend) + 1 SUMMARY.md + 1 contribution section appended to Phase 43 umbrella PR.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/43-upst5-sync-execution/43-CONTEXT.md
@.planning/phases/43-upst5-sync-execution/43-PATTERNS.md (§ Plan 43-03 + § Pattern 1 D-19 Trailer + § Pattern 3 Close Gate)
@.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md (§ Cluster: Pack management — 8 commits table)
@.planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md (Wave 0b close gate; depends_on; provides post-Wave-0b-head SHA for branch_from)
@.planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (PRIMARY skeleton — multi-commit cherry-pick chain + CR-A class regression handling)
@.planning/templates/upstream-sync-quick.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md

<interfaces>
<!-- Cherry-pick chain surface — verified via `git show <sha> --stat` for each SHA at plan-open. Composes against fork's existing crates/nono-cli/src/ surface. -->

The 9 modified files all exist in the fork today; the cherry-pick chain extends them. Critical interface points:
- `crates/nono-cli/src/cli.rs` — fork's clap argument definitions root. Adding `nono update` as a new top-level subcommand is additive.
- `crates/nono-cli/src/main.rs` — fork's command-routing dispatch. Adding a `nono update` arm is additive; fork's existing `nono package` arm is preserved.
- `crates/nono-cli/src/package_cmd.rs` — fork's package command runtime. Adding `pinning` + `outdated` subcommand handlers is additive.
- `crates/nono-cli/src/registry_client.rs` — fork's registry interaction surface. Refresh / outdated-detection extensions are additive.
- `crates/nono-cli/src/app_runtime.rs` + `cli_bootstrap.rs` — fork's app initialization. Hint registration is additive.
- `crates/nono-cli/src/sandbox_prepare.rs` — fork's pre-exec sandbox setup. Any pack-related sandbox prep additions must NOT touch the Phase 22-05 / Phase 23 audit-related code paths (verify via diff inspection per-commit).

Phase 36-01b/c surface to preserve (NO Cluster 1 commit should touch this, but verify per-commit):
- `crates/nono-cli/src/profile/mod.rs::From<ProfileDeserialize> for Profile` (Phase 36-01b CommandsConfig extension at lines 1893-1921)
- `bypass_protection` field name (Phase 36-01c rename — no Cluster 1 commit should re-introduce `override_deny`)
</interfaces>

<upstream_commits>
<!-- Per Phase 42 DIVERGENCE-LEDGER.md § Cluster: Pack management. Cherry-pick ordering MUST be by commit date, not by ledger-table order — per Phase 40 Plan 40-01 DEV-1 lesson. -->

| Ledger row | SHA (abbrev) | Subject | files-changed |
|---|---|---|---|
| 1 | 42601ed7 | fix(pack-update-hint): treat unparsable installed as older in update check | 1 |
| 2 | 98c18f1f | feat(pack-hints): document inline pack update hints | 1 |
| 3 | 18b03fa6 | feat(pack_update_hint): refresh hints synchronously on first run | 1 |
| 4 | 317c97b7 | style(cli): adjust line breaks and module order | 2 |
| 5 | 5098fc1c | feat(packs): add pinning, outdated, and clarify publishing versioning | 3 |
| 6 | be23d6df | style(cli): improve formatting and simplify error handling | 2 |
| 7 | a5985edd | feat(cli): implement `nono update` command | 2 |
| 8 | 64d9f283 | feat(package): add package pinning and outdated commands | 6 |

Plan-open Task 1 verifies actual chronological order via:
`for sha in 42601ed7 98c18f1f 18b03fa6 317c97b7 5098fc1c be23d6df a5985edd 64d9f283; do git log -1 --format='%aI %H %s' $sha; done | sort -k1`

The sorted output is the cherry-pick order.

Categories per Phase 42 ledger: mix of `other` + `package`. windows-touch: `no` for all 8 (verified via Phase 42 D-42-C2).
</upstream_commits>

<d19_trailer_block_template>
Per Phase 40 standardization (lowercase 'Upstream-author:'); applied verbatim to each of 8 cherry-picks:
```
Upstream-commit: <8-char abbreviated SHA>
Upstream-tag: v0.54.0
Upstream-author: <from `git log -1 --format='%an <%ae>' <sha>`>
Upstream-subject: <from `git log -1 --format='%s' <sha>`>
Upstream-date: <from `git log -1 --format='%aI' <sha>`>
Upstream-categories: <ledger row categories field>
Co-Authored-By: <same name + email as Upstream-author>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
</d19_trailer_block_template>
</context>

<tasks>

<task id="1" type="execute" autonomous="true">
  <name>Task 1: Pre-flight Wave-1 branching + resolve true upstream chronological order + per-SHA diff audit</name>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (DEV-1: "Cherry-picks applied in TRUE upstream chronological order, not Phase 42 ledger table order"; lines 113-119)
    - .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md (§ Cluster 1 commit table)
    - memory: project_cross_fork_pr_pattern (one PR per branch pair; per-plan feature branches required)
    - PLAN.md frontmatter `wave_1_parallel_branch_strategy` block
  </read_first>
  <action>
    1. Confirm Plan 43-02 closed (Wave 0b): `git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: 66c69f86'` → 1. Capture the post-Wave-0b-head SHA: `POST_WAVE_0B_HEAD=$(git rev-parse HEAD)`.
    2. **Pre-flight Wave-1 branching (B-1 fix per `wave_1_parallel_branch_strategy.protocol`):** create the per-plan feature branch for Cluster 1:
       `git checkout -b 43-03-cluster-1 $POST_WAVE_0B_HEAD`
       Document the substituted SHA in `.planning/phases/43-upst5-sync-execution/43-03-BRANCH.txt` (one line: `branch=43-03-cluster-1 from=$POST_WAVE_0B_HEAD`). Per memory `project_cross_fork_pr_pattern`: GitHub's one-PR-per-branch-pair rule means per-plan upstream PRs require per-plan feature branches; Plan 43-04 simultaneously branches `43-04-cluster-3` from the same `$POST_WAVE_0B_HEAD` (surface-disjoint per D-43-A2).
    3. Resolve chronological order for the 8 Cluster 1 SHAs:
       ```
       for sha in 42601ed7 98c18f1f 18b03fa6 317c97b7 5098fc1c be23d6df a5985edd 64d9f283; do
         git log -1 --format='%aI %H %s' $sha
       done | sort -k1
       ```
       Record the sorted output (the cherry-pick order) into `.planning/phases/43-upst5-sync-execution/43-03-CHERRY-PICK-ORDER.md`.
    4. For each SHA in chronological order, run a quick per-commit audit:
       - `git show <sha> --stat` — file list confirms it's Cluster-1-shape (only `crates/nono-cli/src/{pack_update_hint,package*,registry_client,cli,app_runtime,cli_bootstrap,main,sandbox_prepare}.rs`)
       - `git show <sha> --stat | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 (D-43-E1 pre-check)
       - `git show <sha> -- crates/nono-cli/src/profile/mod.rs 2>/dev/null | wc -l` → 0 (no Phase 36-01b From-impl touch)
       - `git show <sha> | grep -cE 'override_deny|bypass_protection'` — note any matches; if `override_deny` appears, the cherry-pick will need post-cherry-pick rename per Phase 36-01c
       - If any SHA shows Cargo.toml or workspace.toml changes, flag for workspace-edits-touch-all-5-crates discipline per D-43-E5
    5. Record per-SHA audit findings in `.planning/phases/43-upst5-sync-execution/43-03-PER-SHA-AUDIT.md` (one row per SHA: chronological position, shape verification, Windows-touch check, profile/mod.rs touch check, override_deny touch check, workspace.toml touch flag).
  </action>
  <acceptance_criteria>
    - Per-plan feature branch created: `git rev-parse --abbrev-ref HEAD` → `43-03-cluster-1`
    - Branch baseline recorded: `.planning/phases/43-upst5-sync-execution/43-03-BRANCH.txt` exists with substituted `$POST_WAVE_0B_HEAD` SHA
    - `.planning/phases/43-upst5-sync-execution/43-03-CHERRY-PICK-ORDER.md` exists with 8 sorted rows
    - `.planning/phases/43-upst5-sync-execution/43-03-PER-SHA-AUDIT.md` exists with 8 audit rows
    - For every SHA: D-43-E1 pre-check (Windows-touch) = 0
    - For every SHA: profile/mod.rs touch count = 0 (Phase 36-01b preservation)
    - All `override_deny` matches documented (planner-recorded count; cherry-pick may need rename per Phase 36-01c)
  </acceptance_criteria>
  <done>Wave-1 per-plan feature branch `43-03-cluster-1` created from post-Wave-0b-head per `wave_1_parallel_branch_strategy`; cherry-pick chronological order resolved + per-SHA audit complete; cherry-pick chain is safe to proceed on dedicated branch.</done>
</task>

<task id="2" type="execute" autonomous="true">
  <name>Task 2: Execute 8-commit cherry-pick chain with D-19 trailer + interim close-gate checkpoints</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-03-CHERRY-PICK-ORDER.md (Task 1 output)
    - .planning/phases/43-upst5-sync-execution/43-03-PER-SHA-AUDIT.md (Task 1 output)
    - .planning/phases/43-upst5-sync-execution/43-03-BRANCH.txt (Task 1 output — verify current branch matches)
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md § "Task Commits" lines 82-92 (chain pattern) + DEV-2 lines 120-127 (CR-A class) + DEV-3 lines 129-134 (CR-A regression handling)
    - .planning/templates/upstream-sync-quick.md (D-19 trailer template)
    - CLAUDE.md § Commits (DCO sign-off required; prefer NEW commits over --amend — no "mechanical reshaping" exception exists)
  </read_first>
  <action>
    **Pre-flight:** confirm working on the correct branch: `[[ "$(git rev-parse --abbrev-ref HEAD)" == "43-03-cluster-1" ]] || { echo "FAIL: wrong branch"; exit 1; }`. If different, `git checkout 43-03-cluster-1` first.

    For each SHA in chronological order from Task 1:
    1. Working tree clean check: `git status --porcelain` empty (or only contains planning files).
    2. `git -c core.editor=true cherry-pick --no-commit <sha>` (no-commit + editor-suppressed so executor can verify the diff before sealing AND no editor invocation can block on Windows; see Plan 43-02 `<no_interactive_editor_protocol>` precedent).
    3. Resolve any conflicts hunk-by-hunk:
       - Preserve fork-only divergences identified in Task 1's audit (if any)
       - If `override_deny` appears in the upstream hunks per Task 1's audit, apply the Phase 36-01c rename: `bypass_protection` is the canonical fork name. Document the rename in the commit body under `Fork-side notes:`.
       - If any conflict reaches into `profile/mod.rs::From<ProfileDeserialize> for Profile` (should not, per Task 1's audit), STOP and surface — this would require cross-plan coordination with Plan 43-05's diff-inspection.
       - If any conflict reaches into fork-only Windows files (D-43-E1 violation), STOP unless the 4-condition addendum applies.
    4. Verify the staged diff:
       - `git diff --staged --stat` shows only Cluster-1-shape files
       - `git diff --staged --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0
    5. Build D-19 trailer block per template; substitute upstream metadata from `git log -1 --format='%an <%ae> | %s | %aI' <sha>` + category from Task 1 audit. Write to `/tmp/43-03-cp-<sha>.txt`.
    6. Commit explicitly (NEVER `--continue`): `git commit -F /tmp/43-03-cp-<sha>.txt`. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`.
    7. Per-commit smoke: `cargo check -p nono-cli` exits 0. If non-zero, classify per Phase 40 DEV-2 / DEV-3 — **all fixes land as NEW commits, never --amend**:
       - **Rule 1 (CR-A class regression caused by the cherry-pick):** land as separate follow-on commit with `fix(43-03-cra): <description>` prefix, NOT --amend; document in commit body citing Phase 40 Plan 40-01 DEV-3 precedent.
       - **Rule 2 (mechanical fix completing the cherry-pick's pattern — e.g., missing import):** land as separate `chore(43-03): mechanical fix for <sha> cherry-pick` commit (NOT --amend per CLAUDE.md commit policy — CLAUDE.md has NO "mechanical reshaping" exception). Document the fix-target SHA in the commit body. Verify via `git log --format='%s' HEAD~2..HEAD` showing chore commit at HEAD and cherry-pick at HEAD~1. (Previous plan revision incorrectly described an --amend fallback; replaced with separate-commit per B-3 fix + CLAUDE.md commit policy alignment.)

    Interim close-gate checkpoints — after commits 3, 5, and 8:
    8a. After commit 3: run `cargo test --workspace --all-features` + `cargo clippy --workspace --all-targets -- -D warnings` (Windows host gates 1+2). Record into `.planning/phases/43-upst5-sync-execution/43-03-INTERIM-GATE-3.md`. If any regression vs Plan 43-02 close baseline, classify per Phase 40 DEV-3 and apply CR-A follow-on as separate commit before continuing.
    8b. After commit 5: same as 8a, recorded into `43-03-INTERIM-GATE-5.md`.
    8c. After commit 8 (final): full 8-check close gate executes in Task 3.

    9. Verify all 8 commits landed with trailer blocks:
       `git log --format='%B' 43-03-cluster-1 ^$POST_WAVE_0B_HEAD | grep -c '^Upstream-commit: '` → 8
       (Account for any CR-A / chore follow-on commits which do NOT have `Upstream-commit:` trailers — they're separate commits per CLAUDE.md policy.)
  </action>
  <acceptance_criteria>
    - Current branch is `43-03-cluster-1`: `git rev-parse --abbrev-ref HEAD` matches
    - 8 cherry-pick commits land in chronological order on the feature branch
    - `git log --format='%B' 43-03-cluster-1 ^$POST_WAVE_0B_HEAD | grep -c '^Upstream-commit: '` → 8 (each cherry-pick has the trailer; chore + CR-A follow-on commits do NOT)
    - `git log --format='%B' 43-03-cluster-1 ^$POST_WAVE_0B_HEAD | grep -c '^Upstream-author: '` → 8 (lowercase 'a')
    - `git log --format='%B' 43-03-cluster-1 ^$POST_WAVE_0B_HEAD | grep -c '^Upstream-tag: v0.54.0'` → 8
    - `git diff --stat $POST_WAVE_0B_HEAD..HEAD | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 (D-43-E1)
    - `git diff --name-only $POST_WAVE_0B_HEAD..HEAD -- crates/nono-cli/src/profile/mod.rs | wc -l` → 0 (Phase 36-01b preservation)
    - Interim close-gate checkpoints exist for commits 3 and 5 (`43-03-INTERIM-GATE-3.md`, `43-03-INTERIM-GATE-5.md`)
    - `cargo build --workspace` exits 0 at HEAD
    - **All cherry-pick state cleanly sealed after each commit:** `[[ ! -f .git/CHERRY_PICK_HEAD ]]` after each iteration
    - **No --amend used during the chain:** `git log --format='%B' $POST_WAVE_0B_HEAD..HEAD` shows only cherry-pick commits + separately-committed chore/CR-A fixes; any `chore(43-03):` or `fix(43-03-cra):` subjects are NEW commits (not amended into cherry-picks)
    - Any CR-A follow-on fix commits documented with `fix(43-03-cra): ` subject prefix per Phase 40 DEV-3 precedent
    - Any mechanical fix commits documented with `chore(43-03): mechanical fix for <sha> cherry-pick` subject prefix per B-3 fix + CLAUDE.md commit policy
  </acceptance_criteria>
  <done>All 8 cherry-picks landed on feature branch `43-03-cluster-1` in chronological order with verbatim D-19 trailers; CR-A and mechanical-fix follow-ons (if any) handled via SEPARATE commits per Phase 40 precedent + CLAUDE.md commit policy (never --amend); interim close gates clean; cherry-pick state cleanly sealed.</done>
</task>

<task id="3" type="execute" autonomous="true">
  <name>Task 3: Per-plan 8-check close gate (D-43-E9) + Wave 1 baseline-aware CI gate</name>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md (full file)
    - .planning/phases/43-upst5-sync-execution/43-01-CLOSE-GATE.md (Wave 0a format precedent)
    - .planning/phases/43-upst5-sync-execution/43-02-CLOSE-GATE.md (Wave 0b format precedent)
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (lines 148-184 — per-job CI table format)
  </read_first>
  <action>
    Execute the full D-43-E9 8-check close gate identical to Plans 43-01 + 43-02 Task 3. Record into `.planning/phases/43-upst5-sync-execution/43-03-CLOSE-GATE.md`.

    Wave 1 baseline-aware CI gate considerations (B-1 fix — independent per-branch comparison):
    - Baseline SHA: `13cc0628` per D-43-E3
    - Wave 1 runs in parallel with Plan 43-04 BUT on a SEPARATE branch (`43-03-cluster-1` vs `43-04-cluster-3`) per `wave_1_parallel_branch_strategy.protocol`. Per `wave_1_parallel_branch_strategy.baseline_ci_gate: compare-each-branch-independently-vs-13cc0628`, this plan's CI comparison is `43-03-cluster-1` head vs `13cc0628` ONLY — do NOT include Plan 43-04's commits in the diff. The orchestrator merges both branches before umbrella PR body update; each plan's individual CI baseline is independent.
    - Per Phase 40 Plan 40-01 DEV-3: if a green→red transition appears on a Windows-host-only lane and root-causes to a Cluster 1 cherry-pick (e.g., dead-code in `crates/nono-cli/src/cli.rs` after a `--feature` change), classify as CR-A class and land a separate `fix(43-03-cra):` follow-on per Task 2 step 7 (NEVER --amend). The classification table from 40-01 DEV-3 applies: clear causation + mechanical fix + non-architectural decision = CR-A; ambiguous Windows-only failure with potential broker/BrokerPath/libdbus interaction = STOP and surface to user.
  </action>
  <acceptance_criteria>
    - Gates 1, 2, 5 exit 0 on Windows host
    - Gates 3, 4 either exit 0 OR documented `skipped_gates_load_bearing: [3, 4]` per frontmatter rationale
    - Gates 6, 7, 8 either pass OR documented `skipped_gates_environmental: [6, 7, 8]` per frontmatter rationale
    - Baseline-aware CI gate: zero green→red transitions vs `13cc0628`, with per-job table mirroring 40-01 SUMMARY lines 162-184 format; comparison done on `43-03-cluster-1` head independently (NOT cross-plan with 43-04)
    - `.planning/phases/43-upst5-sync-execution/43-03-CLOSE-GATE.md` exists with all gate evidence
  </acceptance_criteria>
  <done>Close gate executed on independent `43-03-cluster-1` branch; baseline CI clean; any CR-A regressions handled per Task 2 step 7 as separate commits.</done>
</task>

<task id="4" type="execute" autonomous="true">
  <name>Task 4: Append Plan 43-03 contribution section to Phase 43 umbrella PR body (D-43-E6)</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt (umbrella PR URL from Plan 43-01)
    - .planning/phases/43-upst5-sync-execution/43-01-PR-SECTION.md + 43-02-PR-SECTION.md (precedent format)
    - PLAN.md frontmatter `wave_1_parallel_branch_strategy.umbrella_pr_body_update` (orchestrator-driven)
  </read_first>
  <action>
    Write `.planning/phases/43-upst5-sync-execution/43-03-PR-SECTION.md`:
    ```markdown
    ## Plan 43-03 — Cluster 1 pack management (nono update + pinning/outdated + hints)

    **Cluster:** 1 (Pack management — new `nono update` + `nono package pinning` + `nono package outdated` CLI surface + inline pack-update hints)
    **Disposition:** will-sync (D-19 cherry-pick chain of 8 upstream SHAs: 42601ed7, 98c18f1f, 18b03fa6, 317c97b7, 5098fc1c, be23d6df, a5985edd, 64d9f283 — applied in upstream chronological order on feature branch `43-03-cluster-1`)
    **Upstream commits:** 8 cherry-picks (+ any CR-A follow-on `fix(43-03-cra):` or `chore(43-03): mechanical fix` commits documented in SUMMARY — all SEPARATE commits per CLAUDE.md commit policy, never --amend)
    **Files touched:** crates/nono-cli/src/{pack_update_hint.rs, package.rs, package_cmd.rs, registry_client.rs, app_runtime.rs, cli.rs, cli_bootstrap.rs, main.rs, sandbox_prepare.rs}
    **Key decision:** Chronological-order discipline per Phase 40 Plan 40-01 DEV-1 lesson. Interim close-gate checkpoints at commits 3 and 5 (CR-A class regression handling per Phase 40 DEV-3). Phase 36-01b `From<ProfileDeserialize>` exhaustive match preserved (0 touches to profile/mod.rs). Phase 36-01c `bypass_protection` rename honored. Wave 1 per-plan-feature-branch protocol per `wave_1_parallel_branch_strategy` (D-43-E6 + project_cross_fork_pr_pattern).
    **CI baseline diff:** zero `success → failure` transitions vs baseline `13cc0628` (independent `43-03-cluster-1`-head comparison per `wave_1_parallel_branch_strategy.baseline_ci_gate`)
    ```
    Per `wave_1_parallel_branch_strategy.umbrella_pr_body_update: orchestrator-post-both-wave-1-plans-close`: orchestrator handles the actual umbrella PR body update after BOTH Wave 1 plans (43-03 + 43-04) close. This task produces the contribution-section text only; the SUMMARY documents the orchestrator deferral.
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-03-PR-SECTION.md` exists with `## Plan 43-03 — ` heading
    - Section enumerates all 8 SHAs explicitly
    - SUMMARY documents orchestrator deferral per `wave_1_parallel_branch_strategy.umbrella_pr_body_update`
  </acceptance_criteria>
  <done>Plan 43-03 contribution section captured; umbrella PR body update deferred to orchestrator per `wave_1_parallel_branch_strategy`.</done>
</task>

<task id="5" type="execute" autonomous="true">
  <name>Task 5: Write Plan 43-03 SUMMARY.md</name>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (PRIMARY skeleton — multi-commit chain SUMMARY shape)
    - All artifacts produced by Tasks 1-4
  </read_first>
  <action>
    Write `.planning/phases/43-upst5-sync-execution/43-03-PACK-MGMT-SUMMARY.md` mirroring 40-01 SUMMARY structure verbatim. The "Task Commits" section enumerates all 8 cherry-picks (chronological order; for each: upstream SHA → fork SHA + subject) plus any CR-A / chore follow-on fix commits (all as separate commits per CLAUDE.md commit policy). Include a "Wave 1 branch coordination" section documenting the `wave_1_parallel_branch_strategy` execution (branch created, baseline SHA, orchestrator-deferred umbrella update).
    Commit: `git commit -m "docs(43-03): summarize cluster 1 pack-mgmt 8-commit cherry-pick chain" --signoff`
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-03-PACK-MGMT-SUMMARY.md` exists
    - Frontmatter contains cluster_id (=1), requirements_completed: [REQ-UPST5-02], skipped_gates_*, skipped_gates_rationale
    - "Task Commits" section enumerates all 8 cherry-picks + any CR-A / chore follow-ons
    - "Wave 1 branch coordination" section present documenting feature-branch strategy
    - `grep -c '^## ' SUMMARY.md` → ≥ 10
    - `git log -1 --format='%s' HEAD | grep -E '^docs\\(43-03\\):'` matches
  </acceptance_criteria>
  <done>SUMMARY.md written; committed on `43-03-cluster-1` branch; Plan 43-03 ready for Wave 2a (Plan 43-05) consumption AFTER orchestrator merges both Wave 1 branches.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| upstream `nono update` registry-refresh path → fork's pack management subsystem | New CLI command interacts with the registry over the network; trust boundary at HTTP response parsing + signed-artifact verification |
| upstream pack-pinning manifest → fork's pack resolution | Cluster 1 introduces `pinning` data; manifest parsing is a deserialization boundary that must fail-secure on malformed input |
| 8 sequential cherry-picks → fork's CLI surface | Each cherry-pick is a separate provenance boundary; trailer block per commit is the structural provenance record |
| Wave 1 parallel branches (`43-03-cluster-1` + `43-04-cluster-3`) → umbrella PR | Per memory `project_cross_fork_pr_pattern`, GitHub's one-PR-per-branch-pair rule requires per-plan feature branches; the umbrella PR body aggregates both Wave 1 sections after orchestrator merge |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-43-03-01 | Tampering | upstream `nono update` registry-refresh HTTP layer | accept | Cluster 1 commits 7+8 introduce the `nono update` + `package outdated` commands; HTTP layer relies on existing fork registry_client (audited at v2.4); no new TLS / cert / auth surface introduced per Phase 42 ledger. The signed-artifact verification (Phase 26-01) still gates installation per REQ-PKGS-04 carry-forward |
| T-43-03-02 | Spoofing | pack pinning manifest deserialization | mitigate | Cluster 1's `pinning` data MUST deserialize with strict serde (deny unknown fields where the schema dictates); if any commit introduces lax deserialization, the cherry-pick MUST be amended. Task 2 cherry-pick verification includes a grep for `serde(deny_unknown_fields)` consistency vs Phase 26 / 36 manifest precedents |
| T-43-03-03 | Repudiation | any of 8 cherry-pick commits missing D-19 trailer | mitigate | Task 2 acceptance verifies trailer count = 8 via grep |
| T-43-03-04 | Tampering | fork-only Windows files touched (D-43-E1 violation) | mitigate | Task 1 per-SHA audit + Task 2 per-commit staged-diff check both verify 0 Windows-file touches. Cluster 1 is structurally cross-platform per Phase 42 ledger |
| T-43-03-05 | Elevation | new `nono update` command surfaces a privilege boundary the fork hadn't previously exposed | mitigate | `nono update` runs in the user's existing CLI context; no new privilege elevation introduced. Sandbox state for the update flow is governed by `sandbox_prepare.rs` extensions which Task 1's per-SHA audit checks for Phase 22-05 / Phase 23 audit-path collisions |
| T-43-03-06 | Tampering | Phase 36-01b `From<ProfileDeserialize>` exhaustive match collision | mitigate | Task 1 per-SHA audit verifies `profile/mod.rs` is NOT in any Cluster 1 commit's `files_changed` list (Phase 42 ledger confirms this) |
| T-43-03-07 | Tampering | Phase 36-01c `override_deny → bypass_protection` rename regression | mitigate | Task 1 per-SHA audit greps for `override_deny`; Task 2 cherry-pick applies rename if upstream still uses pre-rename name |
| T-43-03-08 | DoS | unparsable-version-as-older logic introduced by 42601ed7 silently degrades update detection | accept | Per Phase 42 ledger: this IS the upstream fix's intent ("treat unparsable installed as older in update check"). Conservative behavior — defaults to triggering update path rather than silently swallowing. Acceptable trade-off per upstream's deliberate design |
| T-43-03-09 | Tampering | Wave 1 branches share commits with each other due to missing branch protocol | mitigate | `wave_1_parallel_branch_strategy.protocol: per-plan-feature-branch` enforced via Task 1 pre-flight (`git checkout -b 43-03-cluster-1 $POST_WAVE_0B_HEAD`); Plan 43-04 branches `43-04-cluster-3` independently from the same SHA. Orchestrator merges both before umbrella PR body update. CI comparison is per-branch-independent per `baseline_ci_gate` |

**ASVS L1 disposition:** `high` threats (T-43-03-04 Windows-files invariant; T-43-03-06 From-impl preservation) — mitigate. `medium` threats (T-43-03-02 pack pinning deserialization; T-43-03-03 trailer; T-43-03-05 sandbox surface; T-43-03-07 rename regression; T-43-03-09 branch coordination) — mitigate. `low` threats (T-43-03-01 HTTP layer reuse; T-43-03-08 unparsable-version-as-older) — accept. Security gate satisfied.
</threat_model>

<verification>
Per-plan close gate identical to Plans 43-01 + 43-02 (D-43-E9 = Phase 34 D-34-D2 8-check format). Interim close-gate checkpoints at commits 3 + 5 per Task 2 step 8.

Wave 1 baseline-aware CI gate: zero `success → failure` lane transitions vs baseline SHA `13cc0628` per D-43-E3; per-branch-independent comparison per `wave_1_parallel_branch_strategy.baseline_ci_gate`.

CR-A class regression handling (Phase 40 Plan 40-01 DEV-3): any green→red transition root-caused to a Cluster 1 cherry-pick gets a separate `fix(43-03-cra):` follow-on commit (NEVER --amend per CLAUDE.md commit policy).

Mechanical fix handling (B-3 fix): any mechanical fix (e.g., missing import completing a cherry-pick pattern) lands as separate `chore(43-03): mechanical fix for <sha> cherry-pick` commit (NEVER --amend; CLAUDE.md has no "mechanical reshaping" exception).
</verification>

<success_criteria>
- All 8 upstream Cluster 1 cherry-picks landed on feature branch `43-03-cluster-1` in chronological order with verbatim D-19 trailer blocks
- Wave 1 per-plan-feature-branch protocol honored per `wave_1_parallel_branch_strategy` (B-1 fix)
- Phase 36-01b `From<ProfileDeserialize>` exhaustive match preserved (0 touches to profile/mod.rs)
- Phase 36-01c `bypass_protection` rename honored
- D-43-E1 invariant holds (0 Windows-file touches across 8 commits)
- Interim close-gate checkpoints at commits 3 + 5 clean
- D-43-E9 8-check close gate clean at HEAD
- Wave 1 baseline-aware CI gate: zero green→red transitions vs `13cc0628` (per-branch-independent comparison)
- Any CR-A class regressions handled via separate `fix(43-03-cra):` follow-on commits per Phase 40 DEV-3 precedent (NEVER --amend)
- Any mechanical fixes handled via separate `chore(43-03):` follow-on commits per CLAUDE.md commit policy (NEVER --amend) — B-3 fix
- Plan 43-03 contribution section appended to Phase 43 umbrella PR body (orchestrator-driven after both Wave 1 plans close per `wave_1_parallel_branch_strategy.umbrella_pr_body_update`)
- SUMMARY.md committed
- REQ-UPST5-02 acceptance criteria #1 advanced for Cluster 1
</success_criteria>

<output>
After completion, create `.planning/phases/43-upst5-sync-execution/43-03-PACK-MGMT-SUMMARY.md` per Task 5 specification.
</output>
</output>
