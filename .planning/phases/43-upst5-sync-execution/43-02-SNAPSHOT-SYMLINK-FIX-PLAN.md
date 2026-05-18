---
plan_id: 43-02-SNAPSHOT-SYMLINK-FIX
phase: 43-upst5-sync-execution
plan: 02
wave: "0b"
type: execute
cluster_id: 7
disposition: will-sync
upstream_range: v0.53.0..v0.54.0
upstream_shas: [66c69f86]
upstream_tag: v0.54.0
baseline_sha: 13cc0628
umbrella_pr_section: "Plan 43-02 — Cluster 7 snapshot restore symlink validation"
opens_umbrella_pr: false
requirements: [REQ-UPST5-02]
depends_on: ["43-01-EDITION-2024-FOUNDATION"]
autonomous: true
files_modified:
  - crates/nono/src/undo/snapshot.rs
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (snapshot.rs is cross-platform Rust, so load-bearing)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (snapshot.rs is cross-platform Rust, so load-bearing)"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_7_wfp_port_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_8_learn_windows_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
must_haves:
  truths:
    - "Cherry-pick of upstream 66c69f86 (fix(snapshot): validate restore targets against symlinks) landed on fork main with verbatim 6-line D-19 trailer block (D-43-E2)"
    - "Symlink-redirect race-condition window between snapshot-taken and restore-invoked is closed in the fork (security-flavored fix; Phase 42 ledger Cluster 7 explicit recommendation honored)"
    - "Touches ONLY `crates/nono/src/undo/snapshot.rs` (single-file cherry-pick — Cluster 7 surface per Phase 42 ledger)"
    - "Path-component comparison preserved (no `String::starts_with` on paths — CLAUDE.md § Common Footguns #1)"
    - "Zero green→red lane transitions vs baseline SHA 13cc0628 (D-43-E3)"
    - "Cross-target clippy lanes (Linux + macOS) exit 0 — or marked load-bearing-skip → CI-verified per cross-target-verify-checklist.md (D-43-E4); snapshot.rs is cross-platform Rust code, so Gates 3+4 are load-bearing"
    - "Zero touches to fork-only Windows files — D-43-E1 trivially honored (single non-Windows file)"
    - "Plan 43-02 contribution section appended to Phase 43 umbrella PR body (D-43-E6)"
    - "Wave 0b lands sequentially after Plan 43-01 close (per D-43-A4 security-urgency-outranks-parallelization but post-edition-2024-baseline to avoid follow-up edit risk)"
    - "Cherry-pick state sealed (no orphaned `.git/CHERRY_PICK_HEAD`); no `git cherry-pick --continue` ever invoked — `--no-commit` path commits explicitly via `git commit -F`"
  artifacts:
    - path: crates/nono/src/undo/snapshot.rs
      provides: "Pre-flight `validate_restore_target` symlink check in `restore_to`"
      contains: "validate_restore_target"
    - path: .planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md
      provides: "Per-Phase-34-D-34-D2 8-check close gate evidence + PR umbrella contribution section + STRIDE T-43-02-* mitigation evidence"
  key_links:
    - from: snapshot.rs `restore_to` function
      to: snapshot.rs `validate_restore_target` helper
      via: "pre-flight call before any filesystem write"
      pattern: "validate_restore_target"
---

<objective>
Cherry-pick upstream Cluster 7's single commit `66c69f86 fix(snapshot): validate restore targets against symlinks` (security fix) onto fork main as Wave 0b. This closes a TOCTOU race: an attacker creating a symlink between snapshot-taken and restore-invoked could redirect the restore write outside the tracked directory, enabling data corruption or trust-boundary escape.

Purpose: close the symlink-redirect race window in the fork too. Per Phase 42 ledger Cluster 7 explicit recommendation: "the security flavor argues for sequencing this cluster early in the wave structure". Per D-43-A4, Wave 0b sequences after Wave 0a (edition-2024 baseline) but before Wave 1 (parallel clusters 1 + 3).

Output: 1 cherry-pick commit + 1 SUMMARY.md + 1 contribution section appended to Phase 43 umbrella PR.
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
@.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md (§ Cluster: Snapshot restore symlink validation)
@.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md (Wave 0a baseline; depends_on)
@.planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (trailer + close-gate skeleton)
@.planning/templates/upstream-sync-quick.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md
@crates/nono/src/undo/snapshot.rs

<interfaces>
<!-- Current shape of crates/nono/src/undo/snapshot.rs — verified via Read on the existing file. Cluster 7's single commit lands on top. -->

The fork's `crates/nono/src/undo/snapshot.rs` is a 1100+ line cross-platform module (per 43-PATTERNS.md). The cherry-pick adds a pre-flight `validate_restore_target` check in the existing `restore_to` (or equivalent restore-entry function); follows the upstream fix verbatim. Per CLAUDE.md § Path Handling (CRITICAL), the validation MUST:
- Use `Path::components()` iteration, NOT `String::starts_with` on paths (CLAUDE.md § Common Footguns #1)
- Canonicalize paths at the enforcement boundary (CLAUDE.md § Path Security)
- Fail secure on any error (CLAUDE.md § Core Principles)

If upstream's commit uses `String::starts_with` on paths (unlikely — upstream wrote this as a security fix), the cherry-pick MUST be amended to use `Path::starts_with` or component iteration. Document any such amendment in the commit body + SUMMARY deviations.
</interfaces>

<upstream_commit>
<!-- Resolvable via `git log v0.54.0 -1 --format=%B 66c69f86` AND `git show 66c69f86 -- crates/nono/src/undo/snapshot.rs`. -->

Upstream commit `66c69f86` per Phase 42 DIVERGENCE-LEDGER.md Cluster 7:
- Subject: `fix(snapshot): validate restore targets against symlinks`
- Tag: v0.54.0
- Files changed: 1 (`crates/nono/src/undo/snapshot.rs`)
- Categories: other
- windows-touch: no (cross-platform; `std::fs::symlink_metadata` is the operative cross-platform check)
- Rationale (Phase 42 ledger): "defends restore mechanism against symlink-redirect race conditions; an attacker creating a symlink between snapshot-taken and restore-invoked could redirect the restore write to a location outside the tracked directory, enabling data corruption or trust-boundary escape"
</upstream_commit>

<d19_trailer_block_template>
```
Upstream-commit: 66c69f86
Upstream-tag: v0.54.0
Upstream-author: <from `git log -1 --format='%an <%ae>' 66c69f86`>
Co-Authored-By: <same name + email as Upstream-author>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
(Per <must_includes_per_plan> §3 also include `Upstream-subject`, `Upstream-date`, `Upstream-categories` if those are the orchestrator-canonical 6-field shape.)
</d19_trailer_block_template>

<no_interactive_editor_protocol>
<!-- Per B-4: Windows `git cherry-pick --continue` may stall on an editor invocation; the `--no-commit` path bypasses that risk. -->

**MANDATORY cherry-pick discipline for ALL cherry-pick tasks in this plan:**

1. **Use `--no-commit` + explicit editor-suppression:**
   ```bash
   git -c core.editor=true cherry-pick --no-commit <sha>
   ```
   The `core.editor=true` (Unix `true` command, returns 0 silently) prevents any editor invocation that might block on Windows.

2. **NEVER use `git cherry-pick --continue`:**
   The `--continue` path opens the commit-message editor and can stall the agent. Instead, after staging conflict resolutions, commit explicitly with `git commit -F /tmp/msg.txt`.

3. **Verify cherry-pick state is sealed after commit:**
   ```bash
   [[ ! -f .git/CHERRY_PICK_HEAD ]] || { echo "FAIL: cherry-pick state still open"; exit 1; }
   ```
   This confirms the cherry-pick transaction completed cleanly. An orphaned `CHERRY_PICK_HEAD` would cause downstream commands to interpret subsequent work as continuing the cherry-pick.

4. **On conflict:** resolve manually, `git add` the resolved files, then `git commit -F /tmp/msg.txt` directly. Do NOT invoke `--continue` or `--abort` from a "resolved" state — commit explicitly.
</no_interactive_editor_protocol>
</context>

<tasks>

<task id="1" type="execute" autonomous="true">
  <name>Task 1: Pre-cherry-pick read — verify upstream commit shape + fork's current snapshot.rs surface</name>
  <read_first>
    - crates/nono/src/undo/snapshot.rs (full file — verify current shape; identify the `restore_to` or equivalent entry point)
    - Upstream commit content: `git show 66c69f86 -- crates/nono/src/undo/snapshot.rs` (read the full diff)
    - Upstream commit body: `git log -1 --format=%B 66c69f86`
    - CLAUDE.md § Path Handling (CRITICAL) + § Common Footguns
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md § "Accomplishments" (single-area cherry-pick discipline)
  </read_first>
  <action>
    1. Confirm Wave 0a (Plan 43-01) closed: `git log -1 --format='%s' HEAD~N..HEAD | grep -c 'Upstream-commit: 8b888a1c'` ≥ 1 (where N covers the 43-01 cherry-pick + optional Cargo.lock chore commit + SUMMARY commits). If Plan 43-01 has not landed yet, STOP — Wave 0b cannot start before Wave 0a per D-43-A4.
    2. Verify the upstream commit SHA + subject: `git log v0.54.0 -1 --format='%H %s' 66c69f86`. Confirm subject matches Phase 42 ledger ("fix(snapshot): validate restore targets against symlinks").
    3. Read the upstream diff: `git show 66c69f86 -- crates/nono/src/undo/snapshot.rs`. Identify:
       - The validation helper function name (likely `validate_restore_target` or similar)
       - The call site (which function in the restore path invokes the validator)
       - Whether upstream uses `Path::components()` or `Path::starts_with` (NOT string `starts_with`)
       - Whether upstream's diff stays within snapshot.rs (it should — Phase 42 ledger says 1 file)
    4. Audit the fork's snapshot.rs for any prior fork-only divergence from upstream that would conflict:
       - `grep -nE 'restore_to|restore_target|symlink_metadata' crates/nono/src/undo/snapshot.rs | head -30`
       - `git log --oneline -- crates/nono/src/undo/snapshot.rs | head -20` (recent fork-side touches)
       - Look for any fork-only Windows handling, fork-only path canonicalization, or fork-only TOCTOU defenses that the cherry-pick must preserve.
    5. Record findings in `.planning/phases/43-upst5-sync-execution/43-02-PRE-CHERRY-PICK-AUDIT.md`:
       - Upstream commit shape (validator function name + call site)
       - Path-handling style upstream uses (component iteration vs string compare)
       - Fork-only divergences in snapshot.rs that the cherry-pick must preserve
       - Verdict: cherry-pick proceeds as-is OR needs path-handling amendment per CLAUDE.md § Common Footguns #1.
  </action>
  <acceptance_criteria>
    - `git log -1 --format='%s' HEAD | grep -E '(43-01|docs\\(43-01\\):|Upstream-commit: 8b888a1c)' || git log -5 --format='%H %s' | grep -c 'Upstream-commit: 8b888a1c'` indicates Plan 43-01 chain present on HEAD
    - `git rev-parse v0.54.0 --short=8` confirms upstream tag reachable
    - `git show 66c69f86 --name-only --format=''` returns exactly 1 file: `crates/nono/src/undo/snapshot.rs`
    - `.planning/phases/43-upst5-sync-execution/43-02-PRE-CHERRY-PICK-AUDIT.md` exists with all 4 audit sections
    - Audit verdict recorded as one of: `[as-is | path-handling-amendment-required]`
  </acceptance_criteria>
  <done>Pre-cherry-pick audit committed to evidence file; path-handling verdict recorded; ready for cherry-pick.</done>
</task>

<task id="2" type="execute" autonomous="true">
  <name>Task 2: Cherry-pick upstream 66c69f86 with D-19 trailer block (no-interactive-editor protocol)</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-02-PRE-CHERRY-PICK-AUDIT.md (Task 1 output)
    - .planning/templates/upstream-sync-quick.md (§ D-19 trailer block)
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (cherry-pick + trailer-append discipline)
    - `<no_interactive_editor_protocol>` block above (MANDATORY discipline — `--no-commit` + editor suppression + explicit commit; never `--continue`)
  </read_first>
  <action>
    1. Working tree clean: `git status --porcelain` returns only the pre-cherry-pick audit file + PLAN.md.
    2. **Pre-flight (no-interactive-editor protocol):** confirm git editor suppression works in the agent context:
       `git -c core.editor=true rev-parse HEAD` exits 0 (smoke confirming `core.editor` override accepted).
    3. Cherry-pick with `--no-commit` + suppressed editor so the executor can verify the diff before sealing the commit AND no editor invocation can block:
       `git -c core.editor=true cherry-pick --no-commit 66c69f86`
       The `--no-commit` flag stages without opening an editor. Do NOT subsequently invoke `git cherry-pick --continue` (which DOES open the editor on Windows) — commit explicitly in step 7 with `git commit -F`.
    4. If conflicts surface (unlikely — Phase 42 ledger confirms snapshot.rs is cross-platform and fork's shape is upstream-byte-identical per Phase 33 enumeration, but verify):
       - Resolve hunk-by-hunk preserving any fork-only divergence identified in Task 1's audit
       - If Task 1's audit recorded `path-handling-amendment-required`, apply the amendment now: rewrite the validator to use `Path::components()` iteration per CLAUDE.md § Common Footguns #1. Document the amendment in the commit body under a `Fork-side notes:` paragraph.
       - After resolving, `git add <resolved-files>` to stage. Do NOT invoke `--continue`.
    5. Verify the staged diff is confined to `crates/nono/src/undo/snapshot.rs`:
       `git diff --staged --name-only` returns exactly that one file (or, with the path-handling amendment, still only that file).
    6. Verify NO Windows-only file edits:
       `git diff --staged --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0
    7. Build the D-19 trailer block. Extract upstream metadata:
       `git log -1 --format='%an <%ae>' 66c69f86` (Upstream-author + Co-Authored-By value)
       `git log -1 --format='%s' 66c69f86` (Upstream-subject value)
       `git log -1 --format='%aI' 66c69f86` (Upstream-date value, ISO 8601)
       Categories from Phase 42 ledger: `other`
       Write the commit message to `/tmp/43-02-cherry-pick-msg.txt`:
       - Verbatim upstream subject + body (preserved from `git log -1 --format=%B 66c69f86`)
       - `Fork-side notes:` paragraph documenting: (a) any path-handling amendment per Task 1's audit, (b) preservation of any fork-only snapshot.rs divergences, (c) reference to Plan 43-02 PLAN.md + CLAUDE.md § Path Handling
       - 6-line D-19 trailer block (Upstream-commit, Upstream-tag, Upstream-author, Upstream-subject, Upstream-date, Upstream-categories) + 1 Co-Authored-By line + 2 Signed-off-by lines
    8. Commit explicitly (NOT `--continue` — explicit `commit -F` avoids the editor entirely):
       `git commit -F /tmp/43-02-cherry-pick-msg.txt`
    9. Verify cherry-pick state sealed:
       `[[ ! -f .git/CHERRY_PICK_HEAD ]] || { echo "FAIL: cherry-pick state still open"; exit 1; }`
  </action>
  <acceptance_criteria>
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-commit: 66c69f86'` → 1
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-tag: v0.54.0'` → 1
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-author: '` → 1 (lowercase 'a')
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-subject: '` → 1
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-date: '` → 1
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-categories: '` → 1
    - `git log -1 --format='%B' HEAD | grep -c '^Co-Authored-By: '` → ≥ 1
    - `git log -1 --format='%B' HEAD | grep -cE '^Signed-off-by: '` → ≥ 2
    - `git diff --name-only HEAD~1 HEAD` returns exactly `crates/nono/src/undo/snapshot.rs`
    - `git diff --name-only HEAD~1 HEAD | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 (D-43-E1)
    - **Cherry-pick state sealed:** `[[ ! -f .git/CHERRY_PICK_HEAD ]]` (transaction closed cleanly; no orphaned mid-resolution state)
    - `cargo build -p nono` exits 0
    - `cargo test -p nono --lib undo::snapshot` exits 0 (existing snapshot tests still green)
    - If the diff contains string-path comparisons, grep `git show HEAD -- crates/nono/src/undo/snapshot.rs | grep -E '\\.starts_with\\("/' | wc -l` → 0 (no `String::starts_with` on paths per CLAUDE.md § Common Footguns)
  </acceptance_criteria>
  <done>Cherry-pick committed via no-interactive-editor protocol (`--no-commit` + explicit `git commit -F`; never `--continue`); cherry-pick state sealed; D-19 trailer intact; D-43-E1 invariant holds; path-handling discipline preserved; nono unit tests green.</done>
</task>

<task id="3" type="execute" autonomous="true">
  <name>Task 3: Per-plan 8-check close gate (D-43-E9) + Wave 0b baseline-aware CI gate</name>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md (full file)
    - .planning/templates/upstream-sync-quick.md (§ Baseline-aware CI gate)
    - .planning/phases/43-upst5-sync-execution/43-01-CLOSE-GATE.md (Wave 0a close-gate format for consistency)
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md (per-job CI table format lines 162-184)
  </read_first>
  <action>
    Execute the D-43-E9 8-check close gate identically to Plan 43-01 Task 3:
    1. Gate 1: `cargo test --workspace --all-features` (Windows host)
    2. Gate 2: `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host)
    3. Gate 3: `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` (snapshot.rs is cross-platform Rust — Gate 3 is load-bearing per frontmatter `skipped_gates_rationale`)
    4. Gate 4: `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` (load-bearing for same reason)
    5. Gate 5: `cargo fmt --all -- --check`
    6. Gate 6: Phase 15 5-row detached-console smoke (environmental-skip if unavailable)
    7. Gate 7: `wfp_port_integration` tests (environmental-skip if no Windows runtime)
    8. Gate 8: `learn_windows_integration` tests (environmental-skip if no Windows runtime)
    9. Baseline-aware CI gate: per-lane diff vs baseline SHA `13cc0628`. Cluster 7 is a security fix; ANY new red lane is a real regression (no carry-forward acceptable for security-flavored work in this plan).
    10. Record into `.planning/phases/43-upst5-sync-execution/43-02-CLOSE-GATE.md` (mirror 43-01 format).
  </action>
  <acceptance_criteria>
    - Gates 1, 2, 5 exit 0 on Windows host
    - Gates 3, 4 either exit 0 OR documented as `skipped_gates_load_bearing: [3, 4]` per checklist § PARTIAL Disposition prose (rationale already in frontmatter)
    - Gates 6, 7, 8 either pass OR documented as `skipped_gates_environmental: [6, 7, 8]` (rationale already in frontmatter)
    - Baseline-aware CI gate: zero green→red transitions vs `13cc0628`
    - `.planning/phases/43-upst5-sync-execution/43-02-CLOSE-GATE.md` exists with per-gate sections + per-job CI table
  </acceptance_criteria>
  <done>Close gate executed; baseline CI diff captured; zero new regressions; security fix landed cleanly.</done>
</task>

<task id="4" type="execute" autonomous="true">
  <name>Task 4: Append Plan 43-02 contribution section to Phase 43 umbrella PR body (D-43-E6)</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt (if Plan 43-01 produced it — contains the umbrella PR URL)
    - .planning/phases/43-upst5-sync-execution/43-01-PR-SECTION.md (template precedent)
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md § Accomplishments (PR #922 body update pattern after the first section)
  </read_first>
  <action>
    1. Read the umbrella PR URL from `43-UMBRELLA-PR.txt` (if executor-mode) or document in SUMMARY that worktree-mode defers to orchestrator.
    2. Write Plan 43-02 contribution section to `.planning/phases/43-upst5-sync-execution/43-02-PR-SECTION.md`:
       ```markdown
       ## Plan 43-02 — Cluster 7 snapshot restore symlink validation

       **Cluster:** 7 (Snapshot restore symlink validation — security fix)
       **Disposition:** will-sync (D-19 cherry-pick of single upstream SHA 66c69f86)
       **Upstream commits:** 66c69f86
       **Files touched:** crates/nono/src/undo/snapshot.rs (1 file, pre-flight `validate_restore_target` symlink check in restore path)
       **Key decision:** Wave 0b sequencing per D-43-A4 — security-urgency outranks parallelization speed; post-edition-2024-baseline ordering avoids follow-up edit risk. Path-handling discipline per CLAUDE.md § Common Footguns #1 (component iteration, not string compare).
       **CI baseline diff:** zero `success → failure` transitions vs baseline `13cc0628`
       ```
    3. Append the section to the umbrella PR body. Use `gh pr view <pr-number> --json body -q .body` to read the current body, append Plan 43-02 section, then `gh pr edit <pr-number> --body-file /tmp/43-umbrella-pr-body-updated.md`.
    4. If worktree-mode: defer the `gh pr edit` to orchestrator and document the deferral in the SUMMARY's "Wave 0b CI Verification — DOWNSTREAM" section.
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-02-PR-SECTION.md` exists with `## Plan 43-02 — ` heading
    - Either: umbrella PR body updated and verified via `gh pr view <pr-number> --json body -q .body | grep -c '^## Plan 43-02 — '` ≥ 1; OR SUMMARY explicitly documents worktree-mode deferral to orchestrator
  </acceptance_criteria>
  <done>Plan 43-02 contribution section captured + appended (or deferred to orchestrator with explicit documentation).</done>
</task>

<task id="5" type="execute" autonomous="true">
  <name>Task 5: Write Plan 43-02 SUMMARY.md</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md (Phase 43 skeleton precedent — match its frontmatter shape exactly)
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (cross-reference for skeleton)
    - All artifacts produced by Tasks 1-4
  </read_first>
  <action>
    Write `.planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md` mirroring the 43-01 SUMMARY frontmatter + section structure. Add a dedicated "Security context" paragraph at the top of "Accomplishments" citing CLAUDE.md § Path Handling (CRITICAL) and Phase 42 ledger Cluster 7's rationale (symlink-redirect race; pre-Phase-43 the fork was vulnerable to the same TOCTOU upstream patched).
    Commit: `git commit -m "docs(43-02): summarize cluster 7 snapshot symlink-validation cherry-pick" --signoff`
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md` exists
    - Frontmatter contains: phase, plan, cluster_id (=7), requirements_completed: [REQ-UPST5-02], skipped_gates_load_bearing, skipped_gates_environmental, skipped_gates_rationale
    - Grep counts: `grep -c '^## ' SUMMARY.md` → ≥ 10
    - `grep -c 'symlink' SUMMARY.md` → ≥ 3 (security context, threat model, accomplishments)
    - `git log -1 --format='%s' HEAD | grep -E '^docs\\(43-02\\):'` matches
  </acceptance_criteria>
  <done>SUMMARY.md written; committed; Plan 43-02 ready for Wave 1 dependency consumption.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| filesystem state at snapshot-taken time → filesystem state at restore-invoked time | TOCTOU window where an attacker can replace a tracked path with a symlink to redirect the restore write outside the tracked directory |
| upstream commit body → fork commit body | Cherry-pick provenance must be reproducible from D-19 trailer |
| fork's existing snapshot.rs → cherry-picked diff | If the fork had any prior fork-only divergence from upstream snapshot.rs (verified absent per Phase 42 Cluster 7 rationale citing "fork's snapshot system is byte-identical to upstream's per Phase 33 fork-only-surface enumeration"), the cherry-pick must preserve it |
| `git cherry-pick --continue` on Windows | Opens commit-message editor; can stall agent in non-interactive contexts. Avoided entirely via `--no-commit` + `core.editor=true` + explicit `git commit -F` per `<no_interactive_editor_protocol>` |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-43-02-01 | Tampering | restore-target path between snapshot-taken and restore-invoked | mitigate | THIS PLAN closes it. The upstream fix introduces a pre-flight `validate_restore_target` (or equivalent) that checks `symlink_metadata` on the target before any write. Task 2 lands the fix verbatim; Task 1's audit confirms path-component iteration discipline per CLAUDE.md § Common Footguns #1 |
| T-43-02-02 | Tampering | path validation uses `String::starts_with` (vulnerable per CLAUDE.md § Common Footguns #1) | mitigate | Task 1 audit checks upstream's path-handling style; if upstream used string compare (unlikely for a security fix), Task 2 amends to use `Path::components()` iteration and documents the amendment in the commit body |
| T-43-02-03 | Repudiation | cherry-pick commit missing D-19 trailer | mitigate | Task 2 acceptance verifies the full 6-line trailer block via grep |
| T-43-02-04 | Tampering | fork-only Windows files touched (D-43-E1 violation) | mitigate | Task 2 acceptance verifies via `git diff --name-only HEAD~1 HEAD | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` returning 0 (single-file scope inherently honors this) |
| T-43-02-05 | DoS | `validate_restore_target` adds a syscall per restore path (perf cost) | accept | The added cost is one `symlink_metadata` syscall per restore path; security gain (kernel-enforced TOCTOU close) vastly outweighs the perf cost. CLAUDE.md § Performance does not list snapshot/restore on the zero-startup-latency hot path |
| T-43-02-06 | Information Disclosure | `validate_restore_target` error path leaks filesystem layout to a less-trusted caller | accept | Error surfaces via `NonoError` to the supervisor (unsandboxed) which already has full filesystem visibility; no information added to the threat model that wasn't already visible to the parent process |
| T-43-02-07 | DoS | cherry-pick stalls on Windows because `git cherry-pick --continue` opens an editor in non-interactive agent context | mitigate | `<no_interactive_editor_protocol>` mandated: `--no-commit` + `core.editor=true` + explicit `git commit -F`; never `--continue`. Task 2 acceptance verifies cherry-pick state sealed via `[[ ! -f .git/CHERRY_PICK_HEAD ]]` |

**ASVS L1 disposition:** `high` threat T-43-02-01 (the TOCTOU race this plan closes) — mitigate. `high` T-43-02-04 (Windows-only-files invariant) — mitigate. `medium` T-43-02-02 (path comparison style) — mitigate via Task 1 audit verdict. `medium` T-43-02-03 (D-19 trailer) — mitigate. `medium` T-43-02-07 (cherry-pick stall) — mitigate via protocol. Security gate satisfied.
</threat_model>

<verification>
Per-plan close gate identical to Plan 43-01 Task 3 (D-43-E9 = Phase 34 D-34-D2 8-check format):

| Gate | Description | Required | Disposition |
|------|-------------|----------|-------------|
| 1 | `cargo test --workspace --all-features` (Windows host) | required | execute |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | required | execute |
| 3 | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | load-bearing (snapshot.rs is cross-platform Rust) | execute or skipped_gates_load_bearing → CI-verified |
| 4 | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped_gates_load_bearing → CI-verified |
| 5 | `cargo fmt --all -- --check` | required | execute |
| 6 | Phase 15 5-row detached-console smoke | environmental | execute or skipped_gates_environmental |
| 7 | `wfp_port_integration` tests | environmental | execute (Windows host) or skipped_gates_environmental |
| 8 | `learn_windows_integration` tests | environmental | execute (Windows host) or skipped_gates_environmental |

Wave 0b baseline-aware CI gate: zero `success → failure` lane transitions vs baseline SHA `13cc0628`.
</verification>

<success_criteria>
- Cherry-pick of upstream `66c69f86` landed with verbatim D-19 trailer block via no-interactive-editor protocol (`--no-commit` + `core.editor=true` + explicit `git commit -F`; never `--continue`)
- Cherry-pick state sealed (no orphaned `.git/CHERRY_PICK_HEAD`)
- Symlink-redirect TOCTOU window closed in the fork's snapshot/restore path
- Path-component comparison discipline preserved (no `String::starts_with` on paths)
- D-43-E1 invariant trivially honored (single non-Windows file)
- 8-check close gate executed; baseline CI diff: zero new regressions
- Plan 43-02 contribution section appended to Phase 43 umbrella PR
- SUMMARY.md committed; Plan 43-02 ready for Wave 1 (Plans 43-03 + 43-04 parallel) consumption per D-43-A2
- REQ-UPST5-02 acceptance criteria #1 advanced for Cluster 7
</success_criteria>

<output>
After completion, create `.planning/phases/43-upst5-sync-execution/43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md` per Task 5 specification.
</output>
</output>
