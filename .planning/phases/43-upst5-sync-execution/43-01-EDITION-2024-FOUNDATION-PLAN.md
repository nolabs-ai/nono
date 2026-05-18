---
plan_id: 43-01-EDITION-2024-FOUNDATION
phase: 43-upst5-sync-execution
plan: 01
wave: "0a"
type: execute
cluster_id: 2
disposition: will-sync
upstream_range: v0.53.0..v0.54.0
upstream_shas: [8b888a1c]
upstream_tag: v0.54.0
baseline_sha: 13cc0628
umbrella_pr_section: "Plan 43-01 — Cluster 2 Rust edition 2024 + workspace deps centralization"
opens_umbrella_pr: true
requirements: [REQ-UPST5-02]
depends_on: []
autonomous: true
files_modified:
  - Cargo.toml
  - Cargo.lock
  - bindings/c/Cargo.toml
  - crates/nono/Cargo.toml
  - crates/nono-cli/Cargo.toml
  - crates/nono-proxy/Cargo.toml
  - crates/nono-shell-broker/Cargo.toml
  - "(upstream-driven file list ~86 source files across crates/* per 8b888a1c diff — edition-2024 source migrations: dyn keyword, parens around trait bounds, closure-capture semantics; exact list follows upstream diff verbatim)"
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_7_wfp_port_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_8_learn_windows_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
must_haves:
  truths:
    - "Cherry-pick of upstream 8b888a1c (v0.54.0 Rust edition 2024 + workspace dependency centralization) landed on fork main with verbatim 6-line D-19 trailer block (D-43-E2)"
    - "Fork workspace `edition` advanced from `2021` to whatever upstream 8b888a1c chose (planner-verified at cherry-pick time; expected `2024`) atomically with the cherry-pick (D-43-B1)"
    - "Fork workspace `rust-version` advanced from `1.77` to whatever upstream 8b888a1c chose (planner-verified at cherry-pick time; expected `1.85` or higher) atomically with the cherry-pick (D-43-B2)"
    - "All 5 member crate Cargo.toml files still resolve `edition.workspace = true` + `rust-version.workspace = true` post-edit — workspace inheritance preserved (D-43-E5 / memory `project_workspace_crates`)"
    - "Fork's workspace `version` pin (currently 0.53.0) NOT bumped — Cluster 2 is a feature commit, not a release commit; the Phase 40 release-ride convention does not apply here (D-43-E10 scope limited to Cluster 3 / Plan 43-04). Preservation tolerates BOTH shapes: literal `version = \"0.53.0\"` per crate OR `version.workspace = true` (if upstream 8b888a1c centralized version via [workspace.package]) — see Task 2 acceptance for the dual-shape grep"
    - "REQ-UPST5-02 acceptance criterion #1 advanced for Cluster 2 (will-sync cluster has plan + cherry-pick + D-19 trailer)"
    - "Zero green→red lane transitions vs baseline SHA 13cc0628 (D-43-E3)"
    - "All cross-target clippy lanes (Windows host + Linux + macOS) exit 0 — or marked load-bearing-skip → CI-verified per .planning/templates/cross-target-verify-checklist.md (D-43-E4)"
    - "Zero touches to fork-only Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/`) outside the cross-platform 4-condition addendum — D-43-E1 / Phase 22 D-17"
    - "Phase 43 umbrella PR opened with Plan 43-01 contribution section (D-43-E6 / memory `project_cross_fork_pr_pattern`)"
  artifacts:
    - path: Cargo.toml
      provides: "Workspace edition + rust-version + centralized [workspace.dependencies] (nix, landlock, url, getrandom additions)"
      contains: "edition = \"2024\""
    - path: .planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md
      provides: "Per-Phase-34-D-34-D2 8-check close gate evidence + per-plan PR umbrella contribution section text"
  key_links:
    - from: workspace root Cargo.toml
      to: crates/{nono,nono-cli,nono-proxy,nono-shell-broker}/Cargo.toml + bindings/c/Cargo.toml
      via: "edition.workspace = true + rust-version.workspace = true inheritance"
      pattern: "edition\\.workspace = true"
---

<objective>
Cherry-pick upstream Cluster 2's single commit `8b888a1c` (Rust 2024 edition migration + workspace dependency centralization — 86 files, +2,234/-1,470) as the Wave 0a sequential foundation gate for Phase 43. This commit atomically advances the fork workspace from `edition = "2021"` / `rust-version = "1.77"` to whatever upstream chose (expected `edition = "2024"` / `rust-version = "1.85"`), centralizes `nix`, `landlock`, `url`, `getrandom` under `[workspace.dependencies]`, and applies edition-2024 source migrations (`dyn` keyword, parens around trait bounds, edition-2024 closure-capture semantics) across every cfg-gated branch.

Purpose: every downstream Phase 43 plan (43-02 through 43-06) rebases cleanly only on top of this edition-2024 + MSRV baseline. Conflicts contained to one sequencing decision per D-43-A1.

Output: 1 cherry-pick commit + 1 follow-on `chore(43-01): regenerate Cargo.lock` commit (separate, NOT --amend) + 1 umbrella PR opened with Plan 43-01 contribution section + 1 SUMMARY.md.
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
@.planning/phases/43-upst5-sync-execution/43-PATTERNS.md
@.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md
@.planning/phases/42-upst5-audit/42-01-SUMMARY.md
@.planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md
@.planning/templates/upstream-sync-quick.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md

<interfaces>
<!-- Current workspace shape — verified pre-plan via Read on Cargo.toml + per-crate Cargo.toml; cherry-pick lands on top of this baseline. -->

Current `Cargo.toml` (root) workspace package block (pre-plan baseline; lines 11-17 per 43-PATTERNS.md):

```toml
[workspace.package]
edition = "2021"
rust-version = "1.77"
authors = ["Luke Hinds"]
license = "Apache-2.0"
repository = "https://github.com/always-further/nono"
homepage = "https://github.com/always-further/nono"
```

All 5 member crates declare `edition.workspace = true` + `rust-version.workspace = true` (verified per `crates/nono/Cargo.toml:4-5`, `crates/nono-cli/Cargo.toml:4-5`, `crates/nono-proxy/Cargo.toml:4-5`, `crates/nono-shell-broker/Cargo.toml:4-5`, `bindings/c/Cargo.toml:4-5`). Atomic edit of `[workspace.package]` propagates to all 5 crates via inheritance.

Current workspace version pin: 0.53.0 (verified at `Cargo.toml:1-9` + per-crate `Cargo.toml:3` for nono/nono-cli/nono-proxy/nono-shell-broker/bindings/c). MUST be preserved across this cherry-pick — the Phase 40 release-ride convention (drop Cargo.toml version hunks) is reserved for Cluster 3 / Plan 43-04 release commits, NOT for Cluster 2's feature commit. However, if the cherry-pick conflict on `Cargo.toml` includes BOTH version-bump hunks AND edition/MSRV hunks, the executor must keep the edition + MSRV hunks and revert the version hunks (per 43-PATTERNS.md Plan 43-01 conflict-resolution clause).

**Post-cherry-pick shape note (workspace centralization):** Upstream 8b888a1c may promote `version` to `[workspace.package]` (i.e., per-crate Cargo.toml files switch from literal `version = "0.53.0"` to `version.workspace = true` and root [workspace.package] carries the literal). This IS the expected post-centralization shape and MUST NOT be detected as a version drop. Task 2's acceptance grep accepts EITHER shape per crate (literal pin OR workspace inheritance).
</interfaces>

<upstream_commit>
<!-- Resolvable via `git log upstream/v0.54.0 -1 --format=%B 8b888a1c` AND `git show 8b888a1c -- Cargo.toml | head -40`. -->

Upstream commit `8b888a1c` per Phase 42 DIVERGENCE-LEDGER.md Cluster 2:
- Subject: `feat: upgrade to Rust edition 2024, centralize workspace dependencies`
- Tag: v0.54.0
- Files changed: 86 (+2,234 / -1,470)
- Categories: other,profile,policy,proxy,audit
- windows-touch: no (judgment-override per Phase 42 D-42-C2 — mechanical heuristic flagged yes because `platform.rs` is in files_changed, but diff is pure cross-platform edition-migration boilerplate)
</upstream_commit>

<d19_trailer_block_template>
<!-- Verbatim 6-line shape per .planning/templates/upstream-sync-quick.md:240-247; lowercase 'Upstream-author:' per Phase 40 standardization (D-43-E2). -->

```
Upstream-commit: 8b888a1c
Upstream-tag: v0.54.0
Upstream-author: <full name from `git log upstream/v0.54.0 -1 --format='%an <%ae>' 8b888a1c`>
Co-Authored-By: <same name + email as Upstream-author>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

Field rules (.planning/templates/upstream-sync-quick.md:249-256):
1. Trailer block separated from body by EXACTLY ONE blank line.
2. Field order is FIXED: `Upstream-commit` → `Upstream-tag` → `Upstream-author` → `Co-Authored-By` → `Signed-off-by` (full name) → `Signed-off-by` (github handle).
3. `Upstream-author` LOWERCASE 'a' (NOT `Upstream-Author`) per Phase 40 standardization.
4. Abbreviated 8-char SHA in `Upstream-commit:`.
</d19_trailer_block_template>
</context>

<tasks>

<task id="1" type="execute" autonomous="true">
  <name>Task 1: Verify upstream MSRV + edition at cherry-pick time (D-43-B1 / D-43-B2)</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-CONTEXT.md (D-43-B1, D-43-B2)
    - .planning/phases/43-upst5-sync-execution/43-PATTERNS.md § "Plan 43-01" Cargo.toml conflict-resolution clause
    - Upstream commit body: `git log upstream/v0.54.0 -1 --format='%B' 8b888a1c`
    - Upstream Cargo.toml at cherry-pick point: `git show upstream/v0.54.0:Cargo.toml | sed -n '1,40p'`
  </read_first>
  <action>
    1. Confirm `upstream` remote points at `https://github.com/always-further/nono.git`:
       `git remote -v | grep upstream`
       (Expected: `upstream  https://github.com/always-further/nono.git (fetch)` + `(push)`. If absent, ask the user before proceeding — do NOT add the remote yourself.)
    2. Ensure upstream tags are present locally:
       `git fetch upstream --tags`
    3. Read upstream's `[workspace.package]` block AT the v0.54.0 tag (not at HEAD of upstream/main, which may be post-v0.54.0):
       `git show v0.54.0:Cargo.toml | sed -n '/\[workspace.package\]/,/^\[/p'`
       Extract the exact `edition = "..."` and `rust-version = "..."` values. ALSO inspect whether upstream centralized `version` into `[workspace.package]` (record the shape: literal pin vs centralized). Record all three pieces of evidence verbatim in the Task 1 evidence file and in the Plan 43-01 SUMMARY.
    4. Verify the SHA: `git log -1 --format='%H %s' 8b888a1c` — confirm the subject matches Phase 42 ledger ("feat: upgrade to Rust edition 2024, centralize workspace dependencies"). If the subject differs, STOP and surface the discrepancy.
    5. Verify locally-installed rustc satisfies the upstream MSRV:
       `rustc --version` and compare against the value from step 3. If local rustc is older, run `rustup update stable` then re-verify. Document the chosen rustc toolchain version (and any `rustup update` step taken) in the SUMMARY's "Issues Encountered" section.
    6. Record the MSRV verification artifact at `.planning/phases/43-upst5-sync-execution/43-01-MSRV-VERIFICATION.txt` (one file with the upstream values, the local rustc version, the workspace-version-shape evidence, and any rustup commands run). NO git commit yet — Task 1 produces text-only evidence.
  </action>
  <acceptance_criteria>
    - `git remote -v | grep upstream | grep -c 'always-further/nono.git'` → ≥ 1
    - `git tag --list 'v0.54.0' | wc -l` → 1
    - `git rev-parse v0.54.0 --short=8` matches `8b888a1c` (or the cherry-pick SHA cited in Phase 42 ledger for this cluster); discrepancy means the planner-recorded short SHA is from a different upstream — STOP and report.
    - `.planning/phases/43-upst5-sync-execution/43-01-MSRV-VERIFICATION.txt` exists with `edition`, `rust-version`, `rustc --version`, and `workspace_version_shape` lines all present (grep verifiable).
    - Local `rustc --version` major.minor ≥ upstream `rust-version` value (semver compare).
  </acceptance_criteria>
  <done>Upstream MSRV + edition + version-shape values recorded in `43-01-MSRV-VERIFICATION.txt`; local rustc confirmed ≥ upstream MSRV; cherry-pick is safe to proceed.</done>
</task>

<task id="2" type="execute" autonomous="true">
  <name>Task 2: Cherry-pick upstream 8b888a1c with D-19 trailer block + separate Cargo.lock regen commit</name>
  <read_first>
    - .planning/templates/upstream-sync-quick.md (§ "D-19 cherry-pick trailer block" lines 222-256)
    - .planning/phases/43-upst5-sync-execution/43-PATTERNS.md § "Plan 43-01" Cargo.toml conflict-resolution clause
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md (lines 119-127 — Cargo.toml conflict-resolution selective-revert pattern)
    - Output of Task 1 (`43-01-MSRV-VERIFICATION.txt`) for the exact upstream edition + MSRV values + version-shape evidence
    - CLAUDE.md § Commits (DCO sign-off required; prefer new commits over --amend)
  </read_first>
  <action>
    1. Confirm working tree clean: `git status --porcelain` returns only the new `43-01-MSRV-VERIFICATION.txt` and PLAN.md (no staged or unstaged source edits).
    2. Cherry-pick the upstream commit WITHOUT auto-commit (so we can inspect and selectively revert version hunks if present); use a no-op editor to prevent any interactive prompt:
       `git -c core.editor=true cherry-pick --no-commit 8b888a1c`
       Note: `--no-commit` stages without opening an editor; do NOT use `git cherry-pick --continue` later (that path opens the commit-message editor). Commit explicitly with `git commit -F /tmp/43-01-cherry-pick-msg.txt` in step 5.
    3. If conflicts surface, resolve hunk-by-hunk:
       - Workspace `Cargo.toml` `[workspace.package]`: KEEP upstream's `edition` + `rust-version`. KEEP fork's `version = "0.53.0"` shape (whether literal per-crate OR centralized in workspace — match whatever upstream 8b888a1c set, but never bump the version number from 0.53.0).
       - Workspace `Cargo.toml` `[workspace.dependencies]`: KEEP upstream's centralizations (nix, landlock, url, getrandom additions).
       - Per-crate `Cargo.toml`: KEEP fork's version pin AT 0.53.0. The PER-CRATE SHAPE may legitimately change from literal `version = "0.53.0"` to `version.workspace = true` if upstream centralized version into [workspace.package] (Task 1 step 3 records which shape upstream uses); both shapes are accepted post-cherry-pick. If upstream's commit ALSO bumps the workspace `version` NUMBER (it should NOT — this is a feature commit not a release commit — but verify), selectively revert the version-number bump: `git checkout HEAD -- Cargo.toml bindings/c/Cargo.toml crates/nono/Cargo.toml crates/nono-cli/Cargo.toml crates/nono-proxy/Cargo.toml crates/nono-shell-broker/Cargo.toml`, then re-apply upstream's edition/rust-version/centralization changes manually preserving the 0.53.0 number.
       - `Cargo.lock`: regenerate post-edit via `cargo update --workspace` (this happens AFTER the cherry-pick commit lands, as a SEPARATE follow-on commit per step 6).
       - Source files (86 in total): accept upstream's edition-2024 migration verbatim. Do NOT cherry-pick any Windows-only file edits — verify via `git diff --staged --name-only -- 'crates/**/*_windows.rs' 'crates/nono-cli/src/exec_strategy_windows/' 'crates/nono-shell-broker/'` returns empty. If upstream touched any of these paths (it should not — Cluster 2 was judgment-overridden to `windows-touch: no`), apply the 4-condition addendum per D-43-E1: (1) required cross-platform struct field, (2) cross-platform default factory only, (3) ≤5 lines, (4) document in SUMMARY. If any one of the 4 conditions fails, STOP and surface the conflict.
    4. Verify the staged diff matches upstream's intent:
       `git diff --staged --stat | head -20`
       `git diff --staged --name-only | wc -l` — should be ~86 files
    5. Commit with full D-19 trailer block. Use the trailer template in `<d19_trailer_block_template>` above; substitute the exact upstream author name + email by extracting:
       `git log -1 --format='%an <%ae>' 8b888a1c`
       The commit body should:
       - Start with upstream's verbatim subject ("feat: upgrade to Rust edition 2024, centralize workspace dependencies") and body
       - Include a `Fork-side notes:` paragraph documenting: (a) the upstream MSRV value applied; (b) fork's version pin preserved at 0.53.0 (note whether per-crate switched to workspace inheritance); (c) any 4-condition addendum invocations (or "no addenda invoked"); (d) reference to Plan 43-01 PLAN.md
       - End with the exact 6-line D-19 trailer block
       Write the commit message to `/tmp/43-01-cherry-pick-msg.txt` first (via Write tool), then commit:
       `git commit -F /tmp/43-01-cherry-pick-msg.txt`
       After commit, confirm cherry-pick state is sealed (not left mid-resolution): `[[ ! -f .git/CHERRY_PICK_HEAD ]] || { echo "FAIL: cherry-pick state still open"; exit 1; }`
    6. Regenerate Cargo.lock as a SEPARATE chore commit (NOT --amend — CLAUDE.md commit policy says "prefer new commits"; there is no "mechanical regeneration" exception in CLAUDE.md):
       `cargo update`  # regenerate Cargo.lock post-edition-2024 cherry-pick
       If `cargo update` changes Cargo.lock, stage and commit as a NEW commit:
       `git add Cargo.lock`
       Write the chore message to `/tmp/43-01-lockfile-msg.txt`:
       ```
       chore(43-01): regenerate Cargo.lock post-edition-2024 cherry-pick

       Mechanical regeneration follow-up to upstream-commit 8b888a1c cherry-pick.
       No D-19 trailer block — this is a fork-side mechanical commit, not an
       upstream-traced commit. Logically pairs with the prior cherry-pick.

       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
       Then: `git commit -F /tmp/43-01-lockfile-msg.txt`
       If `cargo update` does NOT change Cargo.lock (no transitive changes), skip the chore commit and document the no-op in the SUMMARY.
  </action>
  <acceptance_criteria>
    - Cherry-pick state sealed (not mid-resolution): `[[ ! -f .git/CHERRY_PICK_HEAD ]]` after step 5
    - Cherry-pick commit count = 1: `git log --format='%s' HEAD~2..HEAD | grep -c '^feat: upgrade to Rust edition 2024'` ≥ 1 (cherry-pick at HEAD~1) OR HEAD if no Cargo.lock regen needed
    - Identify the cherry-pick commit (call it `CP_SHA`; HEAD if no Cargo.lock changes, HEAD~1 if chore commit landed): `CP_SHA=$(git log --format='%H %s' HEAD~3..HEAD | grep 'feat: upgrade to Rust edition 2024' | awk '{print $1}')`
    - `git log -1 --format='%B' $CP_SHA | grep -c '^Upstream-commit: 8b888a1c'` → 1
    - `git log -1 --format='%B' $CP_SHA | grep -c '^Upstream-tag: v0.54.0'` → 1
    - `git log -1 --format='%B' $CP_SHA | grep -c '^Upstream-author: '` → 1 (lowercase 'a')
    - `git log -1 --format='%B' $CP_SHA | grep -c '^Upstream-subject: ' || true` — Note: the upstream-sync-quick.md template uses 6 fields: `Upstream-commit`, `Upstream-tag`, `Upstream-author`, plus `Co-Authored-By` + 2× `Signed-off-by`. If the orchestrator's planning_context references a 6-line block with `Upstream-subject:` / `Upstream-date:` / `Upstream-categories:` fields per <must_includes_per_plan> §3, those fields MUST also be present. Use the union: include all 6 documented fields from <must_includes_per_plan> AND the 2 Signed-off-by lines from the template. Verify with the 6 grep counts in the <must_includes_per_plan> §3 trailer block.
    - `git log -1 --format='%B' $CP_SHA | grep -c '^Co-Authored-By: '` → ≥ 1
    - `git log -1 --format='%B' $CP_SHA | grep -cE '^Signed-off-by: '` → ≥ 2 (DCO + GitHub attribution)
    - `git show $CP_SHA -- Cargo.toml | grep -E '^\+edition = ' | head -1` shows the new edition value (whatever Task 1 captured)
    - `git show $CP_SHA -- Cargo.toml | grep -E '^\+rust-version = ' | head -1` shows the new MSRV value
    - **Workspace version pin preserved (dual-shape acceptance):**
      - Root workspace literal: `grep -cE '^version = "0\.53\.0"' Cargo.toml` → 1
      - EACH per-crate Cargo.toml accepts EITHER literal pin OR workspace inheritance:
        ```bash
        for f in crates/nono/Cargo.toml crates/nono-cli/Cargo.toml crates/nono-proxy/Cargo.toml crates/nono-shell-broker/Cargo.toml bindings/c/Cargo.toml; do
          grep -qE '^version = "0\.53\.0"|^version\.workspace = true' "$f" || { echo "FAIL: $f has neither literal version pin nor workspace inheritance"; exit 1; }
        done
        ```
        Loop exits 0 (all 5 files pass).
      - Either shape is correct post-cherry-pick; the dual-shape acceptance reflects upstream's optional `[workspace.package].version` centralization (verified at Task 1 step 3). The old single-grep acceptance (`xargs grep -lE '^version = "0\.53\.0"' | wc -l → 5`) was logically broken — it returned 0 if upstream centralized version, falsely signaling a regression.
    - `git show $CP_SHA --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 (D-43-E1 invariant)
    - `cargo build --workspace` exits 0
    - Local `cargo check --workspace` exits 0
    - If Cargo.lock chore commit landed: `git log -1 --format='%s' HEAD | grep -E '^chore\\(43-01\\): regenerate Cargo\\.lock'` matches AND `git log -1 --format='%B' HEAD | grep -c '^Upstream-commit: '` → 0 (chore commit has NO D-19 trailer per CLAUDE.md commit policy — separate fork-side mechanical commit)
  </acceptance_criteria>
  <done>Cherry-pick committed as a clean single commit; D-19 trailer block intact (per <must_includes_per_plan> §3 6-line shape); fork version pin preserved on all 5 per-crate Cargo.toml files in EITHER literal or workspace-inheritance shape; D-43-E1 Windows-only-files invariant holds; cherry-pick state sealed (no `.git/CHERRY_PICK_HEAD`); Cargo.lock regen (if needed) landed as separate `chore(43-01):` commit (NOT --amend); cargo build clean.</done>
</task>

<task id="3" type="execute" autonomous="true">
  <name>Task 3: Per-plan 8-check close gate (D-43-E9) + Wave 0a baseline-aware CI gate</name>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md (full file)
    - .planning/templates/upstream-sync-quick.md (§ "Baseline-aware CI gate" lines 96-113)
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (lines 148-184 — Wave-1 CI Verification per-job table format)
    - .planning/phases/43-upst5-sync-execution/43-PATTERNS.md § "Pattern 3: Per-Plan 8-Check Close Gate"
  </read_first>
  <action>
    Run the 8-check close gate per D-43-E9 (= Phase 34 D-34-D2 verbatim). For each gate, record output (or skip rationale) into `/tmp/43-01-close-gate.log`:
    1. Gate 1: `cargo test --workspace --all-features` (Windows host) — record pass/fail counts.
    2. Gate 2: `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host).
    3. Gate 3: `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`. If the cross-toolchain is absent or `aws-lc-sys` / `ring` fail to link, mark as `load-bearing-skip → CI-verified` per `.planning/templates/cross-target-verify-checklist.md` § PARTIAL Disposition. Record the exact SKIPPED reason verbatim per checklist line 58-60 (rationale already in frontmatter `skipped_gates_rationale`).
    4. Gate 4: `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`. Same handling as Gate 3.
    5. Gate 5: `cargo fmt --all -- --check`.
    6. Gate 6 (Phase 15 5-row detached-console smoke): if smoke harness not available in this executor context, mark `environmental-skip` per Phase 40 D-40-C2 precedent.
    7. Gate 7 (`wfp_port_integration` tests): `cargo test --workspace -- wfp_port_integration` if Windows runtime available; else `environmental-skip`.
    8. Gate 8 (`learn_windows_integration` tests): `cargo test --workspace -- learn_windows_integration` if Windows runtime available; else `environmental-skip`.

    9. Baseline-aware CI gate (Wave 0a): push branch and compare against baseline SHA `13cc0628`. Per D-43-E3 + `.planning/templates/upstream-sync-quick.md:108-113`:
       - Push the branch: `git push -u origin HEAD` (orchestrator may already manage push in worktree mode; if so, defer push to orchestrator and document in SUMMARY "wait-for-CI is downstream of orchestrator-merge").
       - Once CI completes, per-lane diff vs baseline `13cc0628` via `gh run list --branch <branch> --limit 1 --json databaseId,headSha` then `gh run view <run-id> --json jobs`.
       - Lane categorization (D-43-E3): green→green=PASS, green→red=FAIL, red→red=PASS (carry-forward), red→green=PASS+IMPROVEMENT.
       - **Critical:** since baseline `13cc0628` is the Phase 41 clean baseline (all CI lanes green per Phase 41 close), ANY red lane on the cherry-pick head commit is a real regression. Apply Phase 40 Plan 40-01 CR-A class fix-on-main pattern if a regression appears (separate follow-on commit with `fix(43-01): <description>` prefix, NOT --amend).
    10. Record all gate evidence into a per-plan close-gate evidence file: `.planning/phases/43-upst5-sync-execution/43-01-CLOSE-GATE.md` (one section per gate; baseline-CI per-job table per Phase 40 Plan 40-04 SUMMARY lines 162-184 format).
  </action>
  <acceptance_criteria>
    - Gates 1, 2, 5 exit 0 on Windows host
    - Gates 3, 4 either exit 0 OR are marked `skipped_gates_load_bearing: [3, 4]` with the exact `cross-target-verify-checklist.md` § PARTIAL Disposition prose recorded (per frontmatter `skipped_gates_rationale`)
    - Gates 6, 7, 8 either pass OR are marked `skipped_gates_environmental: [6, 7, 8]` with Phase 40 D-40-C2 precedent cited
    - Baseline-aware CI gate produces ZERO green→red lane transitions vs baseline `13cc0628`
    - `.planning/phases/43-upst5-sync-execution/43-01-CLOSE-GATE.md` exists with per-gate sections + per-job CI table
    - `grep -cE '^\\| .* \\| .* \\| ' .planning/phases/43-upst5-sync-execution/43-01-CLOSE-GATE.md` → ≥ 16 (8 gates × at least 2 cols)
  </acceptance_criteria>
  <done>8-check close gate executed with all skips properly categorized (load-bearing vs environmental); baseline CI diff captured; zero new regressions vs `13cc0628`.</done>
</task>

<task id="4" type="execute" autonomous="true">
  <name>Task 4: Open Phase 43 umbrella PR + append Plan 43-01 contribution section (D-43-E6)</name>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md § "Accomplishments" line 79 (PR #922 body update pattern)
    - .planning/phases/43-upst5-sync-execution/43-PATTERNS.md § "Pattern 6: Umbrella PR Body Assembly"
    - memory: project_cross_fork_pr_pattern (GitHub one-PR-per-branch-pair rule; per-plan feature branches feed into umbrella PR body)
  </read_first>
  <action>
    1. Verify Phase 40's PR #922 is closed (it was closed at v2.4 ship per CONTEXT.md). If still open, surface to user before opening a fresh umbrella.
    2. Open new umbrella PR against `upstream/main` (or against the agreed-upon Phase 43 base branch — confirm with user if ambiguous; per memory `project_cross_fork_pr_pattern` the fork ships ONE umbrella PR per phase):
       - Title: `Phase 43 — UPST5 sync execution (v0.53.0..v0.54.0)`
       - Body: open with milestone summary (Phase 43, REQ-UPST5-02, baseline `13cc0628`), then the first contribution section for Plan 43-01 (template below). Subsequent plans (43-02..43-06) will append their own sections.
       - Use `gh pr create`:
         ```
         gh pr create --base main --head <branch> --title "Phase 43 — UPST5 sync execution (v0.53.0..v0.54.0)" --body-file /tmp/43-umbrella-pr-body.md
         ```
       - Record PR URL in `.planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt` (single-line: the PR URL).
    3. Contribution section template for Plan 43-01 (per <must_includes_per_plan> §9 + Phase 40 D-40-A1):
       ```markdown
       ## Plan 43-01 — Cluster 2 Rust edition 2024 + workspace deps centralization

       **Cluster:** 2 (Rust edition 2024 + workspace dependency centralization)
       **Disposition:** will-sync (D-19 cherry-pick of single upstream SHA 8b888a1c)
       **Upstream commits:** 8b888a1c
       **Files touched:** Cargo.toml + 5 crate-level Cargo.toml files + ~86 source files (edition-2024 source migrations per upstream)
       **Key decision:** D-43-B1 atomic MSRV bump applied (1.77 → <upstream MSRV from Task 1>); fork's version pin (0.53.0) preserved per D-43-E10-scope (release-ride convention reserved for Plan 43-04 only); D-43-E1 Windows-only-files invariant holds (0 Windows files touched). Cargo.lock regeneration landed as separate `chore(43-01):` follow-on commit per CLAUDE.md commit policy (no --amend).
       **CI baseline diff:** zero `success → failure` transitions vs baseline `13cc0628`
       ```
       Fill in the `<upstream MSRV from Task 1>` placeholder with the exact value captured.
    4. (Worktree mode note) If running inside a worktree, defer PR open + push to the orchestrator. In that case, Task 4 produces the contribution-section text in `.planning/phases/43-upst5-sync-execution/43-01-PR-SECTION.md` and the orchestrator handles the actual `gh pr create` + body update. Document this in the SUMMARY's "Wave 0a CI Verification — DOWNSTREAM" section.
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-01-PR-SECTION.md` exists with the Plan 43-01 contribution section text
    - Either: `.planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt` exists with the umbrella PR URL (executor-mode); OR the SUMMARY documents that PR open is deferred to orchestrator (worktree-mode)
    - Contribution section grep: `grep -c '^## Plan 43-01 — ' .planning/phases/43-upst5-sync-execution/43-01-PR-SECTION.md` → 1
  </acceptance_criteria>
  <done>Plan 43-01 contribution section text captured; umbrella PR opened (or deferred to orchestrator with explicit documentation).</done>
</task>

<task id="5" type="execute" autonomous="true">
  <name>Task 5: Write Plan 43-01 SUMMARY.md</name>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (full file — closest skeleton template per 43-PATTERNS.md)
    - All artifacts produced by Tasks 1-4 (`43-01-MSRV-VERIFICATION.txt`, `43-01-CLOSE-GATE.md`, `43-01-PR-SECTION.md`, `43-01-UMBRELLA-PR.txt` if present)
  </read_first>
  <action>
    Write `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md` mirroring the 40-01 SUMMARY skeleton structure exactly:
    - Frontmatter (phase, plan, cluster_id, subsystem, tags, dependency graph, tech-stack, key-files modified, skipped_gates_load_bearing, skipped_gates_environmental, skipped_gates_rationale, key-decisions, patterns-established, requirements-completed, duration, completed)
    - Sections: Performance / Accomplishments / Task Commits (enumerate BOTH the cherry-pick commit AND the separate Cargo.lock chore commit if landed) / Files Created/Modified / Decisions Made (DEC-1..N, including DEC for separate-commit Cargo.lock policy + dual-shape version preservation acceptance) / Deviations from Plan (Rule 1/2/3 with auto-fix details) / Issues Encountered / D-43-E9 8-check close gate (mirror 40-01 table format lines 148-161; document skipped_gates_rationale per gate) / Wave 0a CI Verification (per-job table per 40-04 SUMMARY lines 162-184; baseline = `13cc0628`) / Threat-model close-out (table mirroring 40-01 lines 165-174) / Self-Check: PASSED (file/commit/gate verification grep evidence) / User Setup Required (None for cluster 2) / Next Phase Readiness (Plan 43-02 SNAPSHOT-SYMLINK-FIX can start after Wave 0a closes per D-43-A4)
    Commit the SUMMARY separately from the cherry-pick + chore commits:
    `git commit -m "docs(43-01): summarize cluster 2 edition-2024 + MSRV cherry-pick" --signoff` (with second Signed-off-by line for GitHub handle if DCO convention requires it).
  </action>
  <acceptance_criteria>
    - File exists: `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md`
    - Frontmatter contains: phase, plan, cluster_id, requirements_completed
    - Grep counts: `grep -c '^## ' SUMMARY.md` → ≥ 10 (Performance, Accomplishments, Task Commits, Files, Decisions Made, Deviations, Issues, Close Gate, CI Verification, Threat Model, Self-Check, User Setup, Next Phase Readiness)
    - `git log -1 --format='%s' HEAD | grep -E '^docs\\(43-01\\):'` matches (the SUMMARY commit subject)
    - `git log -1 --format='%B' HEAD | grep -cE '^Signed-off-by: '` → ≥ 1 (DCO)
  </acceptance_criteria>
  <done>SUMMARY.md written with all skeleton sections; committed separately from cherry-pick + chore commits; Plan 43-01 ready for Wave 0b dependency consumption.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| upstream/main → fork/main (cherry-pick) | Untrusted upstream commit content crosses into the fork at cherry-pick time; conflict resolutions can silently introduce edition-2024 regressions OR accidentally bump fork's workspace version (the latter would trip downstream release tooling) |
| edition-2021 → edition-2024 transition | New edition's `let_chains` + `if_let_rescope` lint scopes can shift binding scopes in pre-existing `match` arms — low risk for fork (upstream tested at scale) but not zero |
| MSRV 1.77 → 1.85+ transition | Any fork-only code path that relies on 1.77-only behavior would surface at cherry-pick time; CI's Linux + macOS clippy lanes are the structural detector |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-43-01-01 | Tampering | `Cargo.toml` `[workspace.package]` block | mitigate | Selective hunk acceptance per Task 2 step 3; fork's `version = "0.53.0"` preserved across all 5 per-crate Cargo.toml files in either literal or workspace-inheritance shape; verified via Task 2 dual-shape acceptance loop (each file matches `^version = "0\.53\.0"|^version\.workspace = true`) |
| T-43-01-02 | Tampering | fork-only Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/`) | mitigate | D-43-E1 invariant verified at Task 2 acceptance: `git show $CP_SHA --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` returns 0. 4-condition addendum applied only if upstream genuinely needs a cross-platform struct field (none expected for Cluster 2 per Phase 42 judgment-override `windows-touch: no`) |
| T-43-01-03 | Repudiation | cherry-pick commit body missing D-19 trailer block | mitigate | Task 2 acceptance verifies all 6 trailer fields (`Upstream-commit`, `Upstream-tag`, `Upstream-author`, `Upstream-subject`, `Upstream-date`, `Upstream-categories`) plus 2 `Signed-off-by` lines via grep |
| T-43-01-04 | Elevation | edition-2024 `if_let_rescope` shifts binding scope on a fork-only `match` arm | mitigate | Task 3 Gate 1 (`cargo test --workspace --all-features`) is the structural detector; Gates 3+4 cross-target clippy catch any Linux/macOS-only scope shifts. If a regression surfaces, classify as Phase 40 CR-A class (mechanical, minimal-scope fix in a follow-on commit) |
| T-43-01-05 | DoS | `cargo update --workspace` regenerates Cargo.lock with a problematic transitive bump | accept | Cargo.lock regeneration is mechanically tied to MSRV bump (lands as separate `chore(43-01):` commit per CLAUDE.md commit policy); any transitive that breaks would surface in Gate 1 immediately. Phase 41 baseline `13cc0628` is the known-good reference; Task 3 baseline-aware CI gate is the live regression detector |
| T-43-01-06 | Information Disclosure | edition-2024 closure-capture changes leak previously-borrowed values into broader scopes | accept | Low-risk for fork — Cluster 2 is pure edition-migration boilerplate per Phase 42 ledger; upstream tested at scale; CI is the structural detector |
| T-43-01-07 | Tampering | Cherry-pick state left mid-resolution (orphaned `.git/CHERRY_PICK_HEAD`) leading to a second `--continue` opening an interactive editor on Windows | mitigate | Task 2 step 2 uses `git -c core.editor=true cherry-pick --no-commit` (no editor invocation path); step 5 explicitly verifies `[[ ! -f .git/CHERRY_PICK_HEAD ]]` after the explicit `git commit -F /tmp/43-01-cherry-pick-msg.txt`; no `--continue` is ever invoked |

**ASVS L1 disposition:** All `high` threats (T-43-01-01, T-43-01-02) mitigated. `medium` threats (T-43-01-03, T-43-01-04, T-43-01-07) mitigated. `low` threats accepted with CI as detector. Security gate satisfied.
</threat_model>

<verification>
Per-plan close gate (D-43-E9 = Phase 34 D-34-D2 8-check format):

| Gate | Description | Required | Disposition |
|------|-------------|----------|-------------|
| 1 | `cargo test --workspace --all-features` (Windows host) | required | execute |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | required | execute |
| 3 | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped_gates_load_bearing → CI-verified |
| 4 | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped_gates_load_bearing → CI-verified |
| 5 | `cargo fmt --all -- --check` | required | execute |
| 6 | Phase 15 5-row detached-console smoke | environmental | execute or skipped_gates_environmental |
| 7 | `wfp_port_integration` tests | environmental | execute (Windows host) or skipped_gates_environmental |
| 8 | `learn_windows_integration` tests | environmental | execute (Windows host) or skipped_gates_environmental |

Wave 0a baseline-aware CI gate: zero `success → failure` lane transitions vs baseline SHA `13cc0628` per D-43-E3.

All skipped gates categorized per Phase 40 anti-pattern #3 (`skipped_gates_load_bearing` vs `skipped_gates_environmental`) in SUMMARY frontmatter with rationale (mirrors `skipped_gates_rationale` block in this PLAN's frontmatter).
</verification>

<success_criteria>
- Cherry-pick of upstream `8b888a1c` landed on fork main with verbatim D-19 trailer block
- Workspace edition advanced to upstream's value (expected 2024); workspace `rust-version` advanced to upstream's value (expected 1.85+); fork version pin (0.53.0) preserved on all 5 crate-level Cargo.toml files in EITHER literal pin OR workspace-inheritance shape (dual-shape acceptance handles upstream's optional version centralization)
- Cargo.lock regeneration (if needed) landed as separate `chore(43-01):` commit per CLAUDE.md commit policy (NOT --amend)
- Cherry-pick state sealed (no orphaned `.git/CHERRY_PICK_HEAD`)
- D-43-E1 Windows-only-files invariant holds (0 unauthorized touches)
- D-43-E9 8-check close gate executed with all skips properly categorized
- Wave 0a baseline-aware CI gate: zero `success → failure` lane transitions vs baseline `13cc0628`
- Phase 43 umbrella PR opened with Plan 43-01 contribution section appended
- SUMMARY.md committed; Plan 43-01 ready for Wave 0b (Plan 43-02 SNAPSHOT-SYMLINK-FIX) consumption per D-43-A4
- REQ-UPST5-02 acceptance criteria #1 (every audit `will-sync` cluster has plan with cherry-picks + D-19 trailers) advanced for Cluster 2
</success_criteria>

<output>
After completion, create `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md` per Task 5 specification.
</output>
</output>
