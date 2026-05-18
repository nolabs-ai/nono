---
plan_id: 43-05-PLATFORM-DETECTION-FOUNDATION
phase: 43-upst5-sync-execution
plan: 05
wave: "2a"
type: execute
cluster_id: 5
# W-8 fix: canonical disposition values per CONTEXT.md / Phase 42 ledger / D-43-E8: will-sync | fork-preserve | won't-sync
# Conservative default = fork-preserve per D-42-C3; Task 1 may upgrade to will-sync via diff-inspection per D-43-C1.
disposition: fork-preserve
disposition_resolution_at_plan_open: true
final_disposition_field_name: resolved_disposition
resolved_disposition: fork-preserve  # Task 1 verdict 2026-05-18 — D-40-B1 clauses (a)+(b) both FAIL; see 43-05-DISPOSITION-RESOLUTION.md
upstream_range: v0.53.0..v0.54.0
upstream_shas: [ce06bd59]
upstream_tag: v0.54.0
baseline_sha: 13cc0628
umbrella_pr_section: "Plan 43-05 — Cluster 5 platform-conditional profile fields foundation"
opens_umbrella_pr: false
requirements: [REQ-UPST5-02]
depends_on: ["43-04-RELEASE-RIDE"]
autonomous: true
files_modified:
  # Note: actual list depends on resolved_disposition. Both shapes here for orchestrator visibility.
  # If resolved_disposition = will-sync (diff-inspection upgrades to D-19 cherry-pick):
  #   - crates/nono-cli/src/platform.rs (NEW, ~659 lines)
  #   - crates/nono-cli/src/profile/mod.rs (WhenPredicate extension; +217 lines)
  #   - crates/nono-cli/src/wiring.rs (+126 lines)
  #   - crates/nono-cli/src/policy.rs (+28 lines)
  #   - crates/nono-cli/src/main.rs (module declaration: pub mod platform;)
  #   - crates/nono-cli/data/nono-profile.schema.json (+99 lines WhenPredicate definition)
  # If resolved_disposition = fork-preserve (D-20 manual replay):
  #   - Subset of above; minimal replay scope per D-43-C1 + Phase 40 Plan 40-05 precedent
  - crates/nono-cli/src/platform.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/wiring.rs
  - crates/nono-cli/src/policy.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/data/nono-profile.schema.json
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (platform.rs contains cfg-gated Linux branches — load-bearing)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (platform.rs contains cfg-gated macOS branches — load-bearing)"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_7_wfp_port_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_8_learn_windows_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
must_haves:
  truths:
    - "Task 1 mandatory diff-inspection per D-43-C1 (Phase 40 D-40-B1 pattern) produces structured verdict, writes canonical value into PLAN.md frontmatter `resolved_disposition:` field via `gsd-sdk query frontmatter.set` or in-place sed (values: will-sync | fork-preserve per D-43-E8 canonical disposition values per W-8 fix; default frontmatter `disposition:` is conservative `fork-preserve` per D-42-C3 and remains unchanged — `resolved_disposition` is the post-Task-1 verdict field)"
    - "Phase 36-01b `From<ProfileDeserialize> for Profile` exhaustive match at profile/mod.rs:1893-1921 preserved — Cluster 5's WhenPredicate field extension lands as one additional exhaustively-enumerated arm; rustc's struct-literal completeness check catches any future regression"
    - "Phase 36-01c `bypass_protection` rename honored — if upstream ce06bd59 references pre-rename `override_deny`, cherry-pick MUST apply the rename; serde alias direction is `#[serde(default, alias = \"override_deny\")]` on `bypass_protection`"
    - "Path-component comparison preserved in any platform-detection code that touches paths (CLAUDE.md § Common Footguns #1)"
    - "If resolved_disposition = will-sync: cherry-pick commit carries verbatim 6-line D-19 trailer block (D-43-E2). If resolved_disposition = fork-preserve: replay commit(s) carry full D-40-B3 5-section body (`Upstream intent:` / `What was replayed:` / `What was NOT replayed and why:` / `Fork-only wiring preserved:` / `Upstream-replayed-from:`) — NO D-19 trailer block"
    - "WhenPredicate JSON-schema-vs-Rust-deserialization parity verified (W-4 fix): if Branch B (manual replay) is chosen AND wiring.rs is SKIPped, JSON schema's `when:` predicate MUST be rejected at deserialization time via `#[serde(deny_unknown_fields)]` or explicit error in `From<ProfileDeserialize>` impl — fail-secure per CLAUDE.md § Core Principles; T-43-05-10 mitigation"
    - "Zero green→red lane transitions vs baseline SHA 13cc0628 (D-43-E3)"
    - "All cross-target clippy lanes (Linux + macOS) exit 0 — or marked load-bearing-skip → CI-verified (D-43-E4); platform.rs WILL contain cfg-gated per-OS code so Gates 3+4 are load-bearing"
    - "Zero touches to fork-only Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/`) — D-43-E1 invariant. Cluster 5 introduces `platform.rs` with cross-platform + cfg-gated branches; the cfg(target_os = \"windows\") branches inside platform.rs are NEW cross-platform module code (NOT fork-only Windows code), so they are PERMITTED per the cross-platform-by-construction nature. Verified via `git diff --stat HEAD~N HEAD | grep -E '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/' | wc -l` returning 0"
    - "Plan 43-05 contribution section appended to Phase 43 umbrella PR body (D-43-E6)"
    - "Wave 2a lands after Wave 1 close (Plans 43-03 + 43-04 both merged) per D-43-A3"
    - "Cherry-pick / replay state cleanly sealed (no orphaned `.git/CHERRY_PICK_HEAD`); no `git cherry-pick --continue` ever invoked per `<no_interactive_editor_protocol>` precedent from Plan 43-02"
  artifacts:
    - path: crates/nono-cli/src/platform.rs
      provides: "Cross-platform runtime platform detection (~659 lines per upstream; new file IF resolved_disposition=will-sync, partial IF resolved_disposition=fork-preserve manual replay)"
      min_lines: 200  # minimum surface for ANY shape of replay; full cherry-pick = ~659
    - path: crates/nono-cli/src/profile/mod.rs
      provides: "WhenPredicate-bearing field on Profile + extension of From<ProfileDeserialize> exhaustive match"
      contains: "WhenPredicate"
    - path: .planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md
      provides: "Disposition-resolution evidence + per-commit log (will-sync OR manual-replay shape) + close-gate evidence + PR umbrella contribution"
  key_links:
    - from: crates/nono-cli/src/main.rs
      to: crates/nono-cli/src/platform.rs (NEW module)
      via: "pub mod platform; declaration"
      pattern: "pub mod platform"
    - from: crates/nono-cli/src/profile/mod.rs::From<ProfileDeserialize>
      to: WhenPredicate field on Profile
      via: "exhaustive struct-literal enumeration extended"
      pattern: "WhenPredicate|when"
---

<objective>
Absorb Cluster 5's single upstream commit `ce06bd59 feat(profile): add platform-conditional profile fields` (introduces `crates/nono-cli/src/platform.rs` ~659 lines + extends `profile/mod.rs::WhenPredicate` deserialization ~217 lines + `wiring.rs` conditional evaluation ~126 lines + `policy.rs` ~28 lines + profile JSON schema ~99 lines) into the fork as Wave 2a.

Default disposition: fork-preserve (D-20 manual replay) per D-42-C3 conservative-default-for-first-windows-touch-cycle. UPGRADE AUTHORITY per D-43-C1: Task 1 opens with a structured diff-inspection task; if zero fork-only-line conflicts AND identical surface semantics, the resolved_disposition upgrades to `will-sync` (D-19 trailer cherry-pick). Otherwise resolved_disposition stays `fork-preserve`. **W-8 fix:** canonical disposition values are `will-sync | fork-preserve | won't-sync` per D-43-E8; the frontmatter `disposition:` defaults to the conservative `fork-preserve`, and Task 1 writes the post-verdict canonical value into the separate `resolved_disposition:` field — no `TBD-at-plan-open` or `will-sync-via-diff-inspection-upgrade` non-canonical values appear in frontmatter.

The verdict task records the disposition in PLAN.md frontmatter + SUMMARY frontmatter. Subsequent task shape depends on the verdict (mid-plan branch).

Per D-43-C2 + Phase 40 Plan 40-05 precedent: Plan 43-05 is the FOUNDATION cluster (`platform.rs` module that Plan 43-06's Cluster 4 Windows registry parsing builds on). Plan 43-06 sequences after Plan 43-05 close (per D-43-A3 Wave 2b).

Output: 1 disposition-resolution docs commit (Task 1, writes `resolved_disposition`) + 1 cherry-pick commit (if upgrade) OR 1+ D-20 replay commits (if preserve) + 1 SUMMARY.md + 1 contribution section appended to Phase 43 umbrella PR.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/43-upst5-sync-execution/43-CONTEXT.md (D-43-C1 + D-43-C2 + D-43-E1..E10)
@.planning/phases/43-upst5-sync-execution/43-PATTERNS.md § Plan 43-05 (PRIMARY reference — Phase 40 Plan 40-05 FP-PROFILE-SAVE skeleton + Q1-Q6 surface-overlap questions + platform.rs analog selection)
@.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md § Cluster: Platform-conditional profile fields
@.planning/phases/43-upst5-sync-execution/43-04-RELEASE-RIDE-SUMMARY.md (Wave 1 close; depends_on)
@.planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md (PRIMARY skeleton — D-20 manual replay with disposition-resolution-at-plan-open + From-impl exhaustive enumeration discipline)
@.planning/phases/36-upst3-deep-closure/36-01b-CANONICAL-PROFILE-SECTIONS-SUMMARY.md (Phase 36-01b CommandsConfig extension precedent — closest analog for WhenPredicate field extension)
@.planning/phases/36-upst3-deep-closure/36-01c-OVERRIDE-DENY-RENAME-SUMMARY.md (Phase 36-01c override_deny → bypass_protection rename — required if upstream ce06bd59 references pre-rename name)
@.planning/templates/upstream-sync-quick.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md
@crates/nono-cli/src/profile/mod.rs
@crates/nono-cli/src/policy.rs
@crates/nono-cli/src/wiring.rs
@crates/nono-cli/src/instruction_deny.rs

<interfaces>
<!-- Critical fork-side interfaces the diff-inspection must verify against. -->

**Phase 36-01b's `From<ProfileDeserialize> for Profile` impl** (current shape at `crates/nono-cli/src/profile/mod.rs:1893-1921`, per 43-PATTERNS.md):

```rust
impl From<ProfileDeserialize> for Profile {
    fn from(raw: ProfileDeserialize) -> Self {
        Self {
            extends: raw.extends,
            meta: raw.meta,
            security: raw.security,
            filesystem: raw.filesystem,
            policy: raw.policy,
            network: raw.network,
            env_credentials: raw.env_credentials,
            environment: raw.environment,
            workdir: raw.workdir,
            hooks: raw.hooks,
            rollback: raw.rollback,
            open_urls: raw.open_urls,
            allow_launch_services: raw.allow_launch_services,
            interactive: raw.interactive,
            skipdirs: raw.skipdirs,
            capabilities: raw.capabilities,
            unsafe_macos_seatbelt_rules: raw.unsafe_macos_seatbelt_rules,
            packs: raw.packs,
            command_args: raw.command_args,
            // Plan 36-01b: canonical section per upstream f0abd413 (v0.47.0).
            commands: raw.commands,
        }
    }
}
```

Cluster 5's WhenPredicate extension (if a new field on Profile is introduced) lands as ONE MORE arm in this impl, exhaustively enumerated. The fork's discipline (Phase 36-01b) is that EVERY Profile field appears here — rustc's struct-literal completeness check is the structural guard against future field additions silently being dropped.

**Phase 36-01c rename:** `bypass_protection` is the canonical name; `override_deny` is the serde alias. If upstream ce06bd59 references `override_deny` as a field name OR pattern-matches on it, the cherry-pick MUST apply the rename. Serde alias direction: `#[serde(default, alias = "override_deny")]` on `bypass_protection`.

**`Group::platform: Option<String>` at `policy.rs:43-46`** — existing fork-side platform-conditional concept (a string-based platform filter on policy groups). Cluster 5's `WhenPredicate` extends to richer predicate shape (per Phase 42 ledger: "conditional `paths` / `names` / `origins` / `groups` / `env_credentials`"). The two CAN coexist; diff-inspection verifies no rename/replace.

**`wiring.rs` existing shape** (Plan 36-02 yaml-merge directive surface header at `wiring.rs:1-24` per 43-PATTERNS.md). Cluster 5 extends WiringDirective with conditional evaluation; the extension is additive but must not collide with the existing `WiringDirective` enum variants.

**NEW file `crates/nono-cli/src/platform.rs`** — does NOT exist in fork (verified via Phase 42 ledger). Closest analog: `crates/nono-cli/src/instruction_deny.rs` (cross-platform module with `#[cfg(target_os = "...")]` per-platform implementations + `#[cfg(not(target_os = "..."))]` no-op fallback). Key pattern elements to preserve in any cherry-pick OR replay:
- Module-level `//!` doc comment explaining purpose
- `use nono::{CapabilitySet, Result, NonoError}` style for fork's library re-exports
- `#[cfg(target_os = "linux"|"macos"|"windows")]` per-platform branches
- Conservative `pub` exports (only what callers need)

**W-4 fix — JSON-schema-vs-Rust-deserialization parity:** If Branch B (fork-preserve manual replay) is chosen AND `wiring.rs` is SKIPped per minimal-replay-scope policy, then the JSON schema's `when:` predicate would be accepted at deserialization but no-op'd at evaluation — a silent behavior divergence between fork and upstream. Fail-secure per CLAUDE.md § Core Principles: in Branch B, EITHER also include `wiring.rs` replay (so `when:` actually evaluates) OR reject `when:` predicates at deserialization time via `#[serde(deny_unknown_fields)]` on the affected struct OR explicit error in `From<ProfileDeserialize>` impl. This is enforced by Task 2 Branch B step 6 + threat model T-43-05-10.
</interfaces>

<upstream_commit>
Upstream commit `ce06bd59` per Phase 42 ledger Cluster 5:
- Subject: `feat(profile): add platform-conditional profile fields`
- Tag: v0.54.0
- Files changed: 6 (per ledger)
- Categories: profile,policy,package
- windows-touch: YES (creates `platform.rs` which is on the pinned list per D-42-C1)
- Touches: NEW `platform.rs` (659 lines) + `profile/mod.rs` (+217) + `wiring.rs` (+126) + `policy.rs` (+28) + schema (+99) + package_cmd.rs + main.rs + docs
</upstream_commit>

<diff_inspection_questions>
Per D-43-C1 + Phase 40 D-40-B1 + 43-PATTERNS.md § Plan 43-05 Q1-Q6 series. Task 1 answers each with numeric or named evidence:

- **Q1:** Does upstream `ce06bd59` touch `crates/nono-cli/src/terminal_approval.rs`? (Phase 18.1 D-04-locked surface — current `build_prompt_text + HandleKind` count = 45 matches per 40-05 SUMMARY.) Expected: 0 (Cluster 5 is profile-deserialization, not approval-prompt).
- **Q2:** Does upstream `ce06bd59` touch `crates/nono-cli/src/profile/mod.rs::From<ProfileDeserialize> for Profile`? Expected: YES (Cluster 5's WhenPredicate field extends this impl). Collision check: Phase 36-01b's `commands: raw.commands` arm at line 1919-1921 must be preserved + the new arm added exhaustively per Phase 36-01b discipline.
- **Q3:** Does upstream `ce06bd59` touch `crates/nono-cli/src/policy.rs`? Expected: YES (+28 lines). Coexistence check vs existing `Group::platform: Option<String>` at `policy.rs:43-46`.
- **Q4:** Does upstream `ce06bd59` touch `crates/nono-cli/src/wiring.rs`? Expected: YES (+126 lines). Coexistence check vs Plan 36-02 yaml-merge directive surface (header at `wiring.rs:1-24`); extension must not collide with existing `WiringDirective` enum variants.
- **Q5:** Does upstream `ce06bd59` reference the pre-rename name `override_deny`? Verify via `git show ce06bd59 | grep -E 'override_deny|bypass_protection'`. If `override_deny` appears, cherry-pick must rename arm-by-arm per Phase 36-01c.
- **Q6:** Does upstream `ce06bd59` collide with Phase 36-01b's `commands: CommandsConfig` enumeration at `profile/mod.rs:1893-1921`? Verify via diff inspection; the new `WhenPredicate`-bearing field must land as one ADDITIONAL exhaustively-enumerated arm, not replace any existing arm.
- **Q7 (Plan 43-05 specific):** Does upstream `ce06bd59` `platform.rs` use `Path::starts_with` or `String::starts_with` for any path comparison? If `String::starts_with`, the cherry-pick MUST be amended per CLAUDE.md § Common Footguns #1.
- **Q8 (Plan 43-05 specific):** Does upstream `ce06bd59` introduce any new public exports that collide with fork's existing `crates/nono-cli/src/exec_strategy_windows/` or `crates/nono-shell-broker/` API surface? Per D-43-E1 + 43-PATTERNS.md § Pattern 4: must verify the cfg-gated platform.rs branches don't conflict with broker dispatch's `WindowsTokenArm::BrokerLaunch` decision tree.

**Upgrade rule (Phase 40 D-40-B1 clause (a) AND (b)):**
- Clause (a): Trial cherry-pick produces ZERO content conflicts AND ZERO modify/delete
- Clause (b): Surface semantics IDENTICAL — no behavioral surprise (e.g., no upstream three-way enum where fork has two-way; no new CLI flag the fork doesn't have)

If both clauses pass → set `resolved_disposition = will-sync`.
If either clause fails → keep `resolved_disposition = fork-preserve`.
</diff_inspection_questions>

<d19_trailer_block_template>
(IF resolved_disposition = will-sync after Task 1 verdict)
```
Upstream-commit: ce06bd59
Upstream-tag: v0.54.0
Upstream-author: <from `git log -1 --format='%an <%ae>' ce06bd59`>
Upstream-subject: feat(profile): add platform-conditional profile fields
Upstream-date: <from `git log -1 --format='%aI' ce06bd59`>
Upstream-categories: profile,policy,package
Co-Authored-By: <same name + email as Upstream-author>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
</d19_trailer_block_template>

<d20_replay_body_template>
(IF resolved_disposition = fork-preserve after Task 1 verdict; per 43-PATTERNS.md Pattern 2 + Phase 40 Plan 40-05 SUMMARY DEV-2)
```
<one-paragraph commit subject + body explaining the replay scope>

Upstream intent: <one-sentence summary of ce06bd59's goal>

What was replayed: <list of fork-side changes that absorb upstream's intent — typically a minimal subset: schema field + struct field + From-impl arm + the bare minimum platform.rs surface that doesn't introduce dead code>

What was NOT replayed and why: <list of upstream hunks deliberately skipped + rationale — e.g., CLI-flag plumbing dead without the CLI flag itself; the three-way prompt UX restructure that's not security; wiring.rs conditional evaluation that needs no caller in fork>

Fork-only wiring preserved: <fork-specific invariants the replay protects — Phase 36-01b From-impl exhaustive match; Phase 36-01c bypass_protection rename; Group::platform Option<String> coexistence; broker dispatch Windows-token-arm decision tree; W-4 fix WhenPredicate deserialization rejection if wiring.rs SKIPped>

Upstream-replayed-from: ce06bd59

Co-Authored-By: Claude <noreply@anthropic.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
ZERO `Upstream-commit:` trailer lines (D-20 branch — falsifiable smoke per 43-PATTERNS.md Pattern 2).
</d20_replay_body_template>

<no_interactive_editor_protocol>
Same as Plan 43-02 (B-4 precedent applies here too — `platform.rs` cherry-pick may conflict, and Windows `git cherry-pick --continue` opens an editor):

1. Use `git -c core.editor=true cherry-pick --no-commit <sha>` (editor suppressed)
2. NEVER use `git cherry-pick --continue` (opens editor on Windows)
3. After staging conflict resolution, `git add <files>` + `git commit -F /tmp/msg.txt` explicitly
4. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`
</no_interactive_editor_protocol>
</context>

<tasks>

<task id="1" type="execute" autonomous="true">
  <name>Task 1: Mandatory diff-inspection (D-43-C1) — answer Q1-Q8 + record disposition verdict in `resolved_disposition`</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-CONTEXT.md (D-43-C1)
    - .planning/phases/43-upst5-sync-execution/43-PATTERNS.md § Plan 43-05 (Q1-Q6 + platform.rs analog)
    - .planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md (PRIMARY skeleton — disposition resolution at plan-open: DEV-1 line 111 + Q-series; key-decisions block)
    - crates/nono-cli/src/profile/mod.rs:1893-1921 (Phase 36-01b From-impl exhaustive enumeration)
    - crates/nono-cli/src/policy.rs:39-46 (Group::platform existing platform-conditional concept)
    - crates/nono-cli/src/wiring.rs:1-24 (Plan 36-02 yaml-merge directive surface header)
    - crates/nono-cli/src/instruction_deny.rs (closest analog for platform.rs)
    - Upstream commit: `git show ce06bd59 -- crates/nono-cli/src/` + `git show ce06bd59 --stat`
  </read_first>
  <action>
    1. Confirm Plan 43-04 closed: `git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: 6b00932f'` → 1.
    2. Confirm `crates/nono-cli/src/platform.rs` does NOT exist in fork: `ls crates/nono-cli/src/platform.rs 2>/dev/null && echo "EXISTS — STOP" || echo "absent as expected"`
    3. Answer Q1-Q8 from `<diff_inspection_questions>` above:
       - **Q1 (terminal_approval.rs):** `git show ce06bd59 --name-only | grep -c 'crates/nono-cli/src/terminal_approval.rs'`
       - **Q2 (profile/mod.rs From-impl):** `git show ce06bd59 -- crates/nono-cli/src/profile/mod.rs | grep -cE 'impl From<ProfileDeserialize>|fn from\\(raw: ProfileDeserialize\\)'`
       - **Q3 (policy.rs):** `git show ce06bd59 --name-only | grep -c 'crates/nono-cli/src/policy.rs'`; if YES, diff the policy.rs hunks vs fork's `Group::platform: Option<String>` at lines 39-46
       - **Q4 (wiring.rs):** `git show ce06bd59 --name-only | grep -c 'crates/nono-cli/src/wiring.rs'`; if YES, verify additive vs existing WiringDirective variants
       - **Q5 (override_deny rename):** `git show ce06bd59 | grep -cE 'override_deny|bypass_protection'`; record both counts
       - **Q6 (CommandsConfig enumeration collision):** read upstream's profile/mod.rs hunk and confirm Phase 36-01b's `commands: raw.commands` arm at lines 1919-1921 is preserved + new WhenPredicate-bearing field arm added as additional enumeration
       - **Q7 (path comparison style):** `git show ce06bd59 -- crates/nono-cli/src/platform.rs | grep -cE '\\.starts_with\\("/|\\.starts_with\\("[A-Z]'` — should be 0 (no string compare); compare to `Path::starts_with` count
       - **Q8 (broker dispatch collision):** `git show ce06bd59 | grep -cE 'WindowsTokenArm|BrokerLaunch'` — should be 0 (Cluster 5 introduces cross-platform module; broker concerns are separate)
    4. Run trial cherry-pick on a scratch branch (do NOT pollute main; editor-suppressed per `<no_interactive_editor_protocol>`):
       ```
       git switch -c 43-05-trial-cherry-pick
       git -c core.editor=true cherry-pick --no-commit ce06bd59
       git status --porcelain | head -50
       git diff --staged --stat | head -30
       ```
       Count: content conflicts (look for `UU` or `AA` in `git status`), modify/delete (look for `DU`/`UD`).
    5. Apply Phase 40 D-40-B1 upgrade rule (writing canonical disposition value per W-8 fix):
       - Clause (a) PASS: trial produced ZERO content conflicts AND ZERO modify/delete
       - Clause (b) PASS: surface semantics IDENTICAL per Q1-Q8 (no behavioral surprise; e.g., no upstream-introduced field with a value the fork hasn't already migrated)
       If both PASS → set `RESOLVED_DISPOSITION="will-sync"`
       If either FAILS → set `RESOLVED_DISPOSITION="fork-preserve"`
       (Canonical values only — no `TBD-at-plan-open`, no `will-sync-via-diff-inspection-upgrade`; per W-8 fix.)
    6. Abort the trial cherry-pick + delete scratch branch:
       ```
       git cherry-pick --abort
       git switch -
       git branch -D 43-05-trial-cherry-pick
       ```
    7. Record verdict + Q1-Q8 evidence in `.planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md`. **Write `resolved_disposition` into PLAN.md frontmatter via canonical value (W-8 fix):**
       Preferred (if SDK supports it):
       `gsd-sdk query frontmatter.set ".planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-PLAN.md" resolved_disposition "$RESOLVED_DISPOSITION"`
       Fallback (if SDK setter unavailable, use sed in-place):
       `sed -i.bak "s/^resolved_disposition: null/resolved_disposition: $RESOLVED_DISPOSITION/" .planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-PLAN.md && rm .planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-PLAN.md.bak`
       Note: the frontmatter `disposition:` field STAYS at `fork-preserve` (conservative default per D-42-C3); `resolved_disposition:` holds the post-verdict canonical value. Downstream tooling reads `resolved_disposition` for the live verdict.
    8. Commit the disposition resolution as a docs commit (Phase 40 Plan 40-05 pattern — disposition resolution committed BEFORE any code change):
       `git add .planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md .planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-PLAN.md`
       `git commit -m "docs(43-05): record D-43-C1 diff-inspection verdict for cluster 5" --signoff`
  </action>
  <acceptance_criteria>
    - `crates/nono-cli/src/platform.rs` confirmed absent pre-plan (per Phase 42 ledger)
    - `.planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md` exists with Q1-Q8 numeric evidence + trial cherry-pick results + verdict
    - PLAN.md frontmatter `resolved_disposition:` field updated to one of CANONICAL values: `will-sync` | `fork-preserve` (W-8 fix — no non-canonical values like `TBD-at-plan-open` or `will-sync-via-diff-inspection-upgrade`)
    - PLAN.md frontmatter `disposition:` remains `fork-preserve` (conservative default unchanged)
    - `git status --porcelain` clean (scratch branch deleted; only the disposition resolution commit on the main worktree branch)
    - Disposition docs commit landed: `git log -1 --format='%s' HEAD | grep -E '^docs\\(43-05\\):'`
    - Q5 evidence recorded: `override_deny` count + `bypass_protection` count
    - Q7 evidence recorded: 0 string-`starts_with` on paths (else cherry-pick / replay applies amendment)
    - Q8 evidence recorded: 0 broker dispatch collision (else STOP and surface to user)
  </acceptance_criteria>
  <done>Disposition resolution committed as docs-only commit before any code change; PLAN.md frontmatter `resolved_disposition:` updated with CANONICAL value per W-8 fix; Tasks 2+ branch on the `resolved_disposition` value.</done>
</task>

<task id="2" type="execute" autonomous="true">
  <name>Task 2: Apply cluster 5 per resolved_disposition verdict — cherry-pick (if will-sync) OR D-20 manual replay (if fork-preserve)</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md (Task 1 verdict)
    - PLAN.md frontmatter `resolved_disposition` (the canonical Task-1 verdict per W-8 fix)
    - If resolved_disposition = will-sync: .planning/templates/upstream-sync-quick.md (D-19 trailer) + .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (cherry-pick discipline)
    - If resolved_disposition = fork-preserve: .planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md (D-20 manual replay — Task 2 commit + 5-section body discipline) + 43-PATTERNS.md Pattern 2 (D-20 falsifiable smokes)
    - .planning/phases/36-upst3-deep-closure/36-01b-CANONICAL-PROFILE-SECTIONS-SUMMARY.md (extension pattern for From-impl exhaustive enumeration — Cluster 5's WhenPredicate field adds ONE more arm)
    - `<no_interactive_editor_protocol>` block above (MANDATORY editor-suppressed cherry-pick discipline)
  </read_first>
  <action>
    Branch on Task 1 verdict (read `resolved_disposition` from PLAN.md frontmatter; canonical values per W-8 fix):

    ### Branch A — IF resolved_disposition = will-sync
    1. Working tree clean.
    2. `git -c core.editor=true cherry-pick --no-commit ce06bd59`
    3. Resolve any incidental conflicts (Task 1 confirmed zero — but verify):
       - Preserve Phase 36-01b From-impl exhaustive enumeration (new WhenPredicate-bearing field arm added; existing `commands: raw.commands` arm preserved)
       - Apply Phase 36-01c `override_deny → bypass_protection` rename if Task 1 Q5 found `override_deny` in upstream hunks
       - Apply path-component amendment if Task 1 Q7 found `String::starts_with` in platform.rs
       - Verify NO touches to fork-only Windows files (D-43-E1) — `git diff --staged --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0
    4. Add `pub mod platform;` to `crates/nono-cli/src/main.rs` if upstream's diff didn't include it (verify; typically upstream's diff DOES include the module declaration).
    5. Build D-19 trailer block per template; write to `/tmp/43-05-cp-ce06bd59.txt`. Body includes:
       - Verbatim upstream subject + body
       - `Fork-side notes:` paragraph documenting: (a) override_deny rename applied or N/A; (b) path-handling amendment applied or N/A; (c) verdict origin (Task 1 D-43-C1 diff-inspection upgrade — `resolved_disposition: will-sync`); (d) Phase 36-01b From-impl exhaustive enumeration extended with WhenPredicate arm
       - 6-line D-19 trailer + 1 Co-Authored-By + 2 Signed-off-by
    6. Commit explicitly (no --continue): `git commit -F /tmp/43-05-cp-ce06bd59.txt`. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`.

    ### Branch B — IF resolved_disposition = fork-preserve
    1. Working tree clean.
    2. Define minimal replay scope per Phase 40 Plan 40-05 DEC-2 ("Minimal replay scope") — only the schema + struct + From-impl-arm + bare-minimum platform.rs surface that doesn't introduce dead code. Specific minimal scope for Cluster 5:
       - `crates/nono-cli/data/nono-profile.schema.json`: add `WhenPredicate` JSON schema definition (+99 lines per ledger)
       - `crates/nono-cli/src/profile/mod.rs`: add `WhenPredicate`-bearing Profile field (with `#[serde(default)]` and any `alias` matching upstream's deserialize shape) + extend `From<ProfileDeserialize> for Profile` impl with the new arm exhaustively (per Phase 36-01b discipline); add `merge_profiles` dedup-append for the new field
       - `crates/nono-cli/src/platform.rs` (NEW, partial): create the module with the minimal surface needed to make WhenPredicate evaluate — typically `pub fn current_platform() -> Platform { ... }` (`#[cfg(target_os = "linux"|"macos"|"windows")]` branches + the data structures it returns). Defer the full 659-line shape (distro detection, version detection, registry parsing) to Plan 43-06 or a future phase
       - `crates/nono-cli/src/wiring.rs`: SKIP — no caller in fork (Plan 36-02's yaml-merge directive surface doesn't need conditional evaluation yet). **CRITICAL W-4 fix:** if wiring.rs is SKIPped, the `when:` predicate in the JSON schema would be accepted at deserialization but no-op'd at evaluation. To prevent this silent behavior divergence, ALSO apply ONE of: (a) `#[serde(deny_unknown_fields)]` on the deserialize-target struct that would carry `when:` (rejects `when:` with parse error), OR (b) explicit error in `From<ProfileDeserialize>` impl when a `when:` predicate is present (fail-secure per CLAUDE.md § Core Principles). Document which mitigation was applied in the commit body.
       - `crates/nono-cli/src/policy.rs`: SKIP — existing `Group::platform: Option<String>` already provides the platform-conditional concept; replay only if upstream's policy.rs hunks are required for WhenPredicate to compile
       - Module declaration: add `pub mod platform;` to `crates/nono-cli/src/main.rs`
    3. Apply the replay edits. Verify NO touches to fork-only Windows files (D-43-E1):
       `git diff --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0
    4. Build D-20 replay commit body per template; write to `/tmp/43-05-replay.txt`. ZERO `Upstream-commit:` trailer; full 5-section body (Upstream intent / What was replayed / What was NOT replayed and why / Fork-only wiring preserved [include W-4 fix mitigation note] / Upstream-replayed-from) per 43-PATTERNS.md Pattern 2.
    5. Commit: `git commit -F /tmp/43-05-replay.txt`
    6. **W-4 fix smoke check (Branch B with wiring.rs SKIPped):** verify the chosen mitigation works:
       - If (a) `deny_unknown_fields` chosen: `cargo test -p nono-cli profile::deserialize_when_predicate_rejected` (test must exist and pass; if test doesn't exist, write one as part of replay)
       - If (b) explicit error chosen: same — verify deserialization with a `when:` predicate returns `NonoError` not silent acceptance
    7. Run falsifiable smoke (per 43-PATTERNS.md Pattern 2):
       ```
       git log --format='%B' HEAD~1..HEAD | grep -c '^Upstream-commit: '          # MUST be 0
       git log --format='%B' HEAD~1..HEAD | grep -c '^Upstream intent:'           # MUST be 1
       git log --format='%B' HEAD~1..HEAD | grep -c '^What was replayed:'         # MUST be 1
       git log --format='%B' HEAD~1..HEAD | grep -c '^What was NOT replayed'      # MUST be 1
       git log --format='%B' HEAD~1..HEAD | grep -c '^Fork-only wiring preserved:' # MUST be 1
       git log --format='%B' HEAD~1..HEAD | grep -c '^Upstream-replayed-from: '   # MUST be 1
       ```
       If any grep returns the wrong count, rephrase the commit body to avoid false positives (see Phase 40 Plan 40-05 DEV-2 false-positive lesson). For message-only fixes on an unpushed commit, per CLAUDE.md commit policy, prefer creating a NEW commit (e.g., `docs(43-05): clarify replay body section markers`) over --amend.
  </action>
  <acceptance_criteria>
    Branch A (will-sync — `resolved_disposition: will-sync`):
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-commit: ce06bd59'` → 1
    - 6-line trailer + 1 Co-Authored-By + ≥ 2 Signed-off-by present
    - Phase 36-01b From-impl exhaustively enumerated: `grep -c 'commands: raw.commands' crates/nono-cli/src/profile/mod.rs` ≥ 1 AND new WhenPredicate-bearing field arm visible in same impl
    - `pub mod platform;` present in main.rs
    - Cherry-pick state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`
    - `cargo build --workspace` exits 0

    Branch B (fork-preserve — `resolved_disposition: fork-preserve`):
    - `git log -1 --format='%B' HEAD | grep -c '^Upstream-commit: '` → 0
    - 5-section D-20 body falsifiable smokes all pass (counts above)
    - `Upstream-replayed-from: ce06bd59` present
    - Phase 36-01b From-impl exhaustively enumerated WITH new arm
    - Phase 36-01c bypass_protection canonical name preserved
    - **W-4 fix mitigation applied if wiring.rs SKIPped:** EITHER (a) `deny_unknown_fields` on relevant struct verified via `grep -c 'deny_unknown_fields' crates/nono-cli/src/profile/mod.rs` ≥ 1 + test confirming `when:` is rejected, OR (b) explicit error in From-impl verified via test + grep
    - `cargo build --workspace` exits 0

    Both branches:
    - `git diff --name-only HEAD~1 HEAD | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 (D-43-E1)
    - `git diff --name-only HEAD~1 HEAD | grep -c 'crates/nono-cli/src/platform.rs'` ≥ 1 (NEW module exists)
    - `grep -c 'pub mod platform' crates/nono-cli/src/main.rs` → 1
  </acceptance_criteria>
  <done>Cluster 5 absorbed per Task 1 `resolved_disposition`; commit shape matches verdict (D-19 trailer OR D-20 5-section body); Phase 36-01b/c invariants preserved; D-43-E1 holds; W-4 fix mitigation applied in Branch B if wiring.rs SKIPped (no silent JSON-schema-vs-Rust-deserialization divergence).</done>
</task>

<task id="3" type="execute" autonomous="true">
  <name>Task 3: Per-plan 8-check close gate (D-43-E9) + Wave 2a baseline-aware CI gate</name>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md
    - .planning/phases/43-upst5-sync-execution/43-03-CLOSE-GATE.md (Wave 1 sibling format)
    - .planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md close gate section + branch-specific smoke check (lines 167-173)
  </read_first>
  <action>
    Execute D-43-E9 8-check close gate identically to Plans 43-01..04. platform.rs WILL contain cfg-gated per-OS code → Gates 3+4 are LOAD-BEARING (cross-target clippy substitute = CI's Linux/macOS lanes per checklist § PARTIAL Disposition; rationale in frontmatter `skipped_gates_rationale`).

    Plus branch-specific smoke per Task 2 (read `resolved_disposition` from PLAN.md frontmatter):
    - Branch A (resolved_disposition = will-sync): verify D-19 trailer count = 1 + per-shape smokes
    - Branch B (resolved_disposition = fork-preserve): verify all 5 D-20 body sections present + ZERO Upstream-commit trailer lines (per 43-PATTERNS.md Pattern 2) + W-4 fix mitigation evidence (deny_unknown_fields grep or explicit-error test result)

    Record into `.planning/phases/43-upst5-sync-execution/43-05-CLOSE-GATE.md` with per-job CI table per 40-04 SUMMARY format. Baseline = `13cc0628`; zero green→red transitions required.

    Additional verification specific to Plan 43-05 (preservation invariants):
    - Phase 18.1 D-04-locked surface unchanged: `grep -c 'build_prompt_text\\|HandleKind' crates/nono-cli/src/terminal_approval.rs` → 45 (per Phase 40 Plan 40-05 baseline)
    - Phase 36-01b commands enumeration preserved: `grep -c 'commands: raw\\.commands' crates/nono-cli/src/profile/mod.rs` → ≥ 1
    - Phase 36-01c bypass_protection canonical name: `grep -c 'bypass_protection' crates/nono-cli/src/profile/mod.rs crates/nono-cli/src/policy.rs 2>/dev/null` → ≥ 1
  </action>
  <acceptance_criteria>
    - Gates 1, 2, 5 exit 0 on Windows host
    - Gates 3, 4 either exit 0 OR documented `skipped_gates_load_bearing: [3, 4]` per frontmatter rationale
    - Gates 6, 7, 8 documented `skipped_gates_environmental: [6, 7, 8]` per frontmatter rationale
    - Baseline CI gate: zero green→red transitions vs `13cc0628`
    - Phase 18.1 surface count preserved (45 — unchanged)
    - Phase 36-01b/c preservation invariants verified via grep
    - Branch-specific smoke (per Task 2 `resolved_disposition`) all pass
    - W-4 fix mitigation evidence captured in close gate (Branch B only)
    - `.planning/phases/43-upst5-sync-execution/43-05-CLOSE-GATE.md` exists
  </acceptance_criteria>
  <done>Close gate executed with both standard 8-check AND branch-specific D-19 / D-20 smokes + cross-phase preservation invariants + W-4 fix mitigation evidence.</done>
</task>

<task id="4" type="execute" autonomous="true">
  <name>Task 4: Append Plan 43-05 contribution section to umbrella PR + Write SUMMARY.md</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt
    - .planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md (PRIMARY SUMMARY skeleton)
    - All Tasks 1-3 artifacts
  </read_first>
  <action>
    1. Write `.planning/phases/43-upst5-sync-execution/43-05-PR-SECTION.md`:
       ```markdown
       ## Plan 43-05 — Cluster 5 platform-conditional profile fields foundation

       **Cluster:** 5 (Platform-conditional profile fields — single upstream commit ce06bd59 introducing crates/nono-cli/src/platform.rs + WhenPredicate deserialization)
       **Disposition:** <CANONICAL FROM TASK 1 VERDICT (resolved_disposition field): will-sync | fork-preserve>
       **Upstream commits:** ce06bd59
       **Files touched:** crates/nono-cli/src/platform.rs (NEW, <full 659 lines | partial replay scope>) + crates/nono-cli/src/profile/mod.rs (WhenPredicate field + From-impl extension per Phase 36-01b discipline) + crates/nono-cli/src/main.rs (pub mod platform;) + crates/nono-cli/data/nono-profile.schema.json (WhenPredicate schema) + <wiring.rs / policy.rs if applicable per verdict>
       **Key decision:** D-43-C1 diff-inspection authority applied — Task 1 trial cherry-pick + Q1-Q8 surface-overlap analysis produced canonical `resolved_disposition` verdict <verdict>. Phase 36-01b From-impl exhaustive enumeration preserved (commands: raw.commands arm + new WhenPredicate-bearing field arm both present). Phase 36-01c bypass_protection canonical name honored. Path-component comparison preserved per CLAUDE.md § Common Footguns #1. <If Branch B with wiring.rs SKIPped: W-4 fix mitigation applied — JSON-schema-vs-Rust-deserialization parity preserved via deny_unknown_fields or explicit error.>
       **CI baseline diff:** zero `success → failure` transitions vs baseline `13cc0628`
       ```
       Fill in verdict + file list based on Task 1 / Task 2 outcome.
    2. Append to umbrella PR body or defer to orchestrator per worktree mode.
    3. Write `.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md` mirroring Phase 40 Plan 40-05 SUMMARY skeleton verbatim. Critical sections:
       - Frontmatter must include `resolved_disposition:` value (matching PLAN.md frontmatter and Task 1 verdict; canonical values only per W-8 fix)
       - "Accomplishments" enumerates: disposition resolution + cherry-pick OR replay scope + Phase 36-01b/c preservation evidence + (if Branch B) what was deferred + (if Branch B + wiring.rs SKIPped) W-4 fix mitigation evidence
       - "Decisions Made" cites D-43-C1 + Phase 40 D-40-B1 verdict precedent + W-4 fix + W-8 fix (canonical disposition values)
       - Per-job CI table per Wave 2a head commit vs baseline `13cc0628`
    4. Commit: `git commit -m "docs(43-05): summarize cluster 5 platform-detection-foundation per D-43-C1 verdict" --signoff`
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-05-PR-SECTION.md` exists with verdict-driven disposition line (canonical value)
    - `.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md` exists
    - SUMMARY frontmatter `resolved_disposition:` matches PLAN.md frontmatter (and Task 1 verdict); CANONICAL value per W-8 fix
    - SUMMARY cites D-43-C1 + Phase 40 D-40-B1 verdict precedent explicitly
    - SUMMARY documents W-4 fix mitigation if Branch B + wiring.rs SKIPped
    - SUMMARY explicitly notes W-8 fix (canonical disposition values used)
    - `git log -1 --format='%s' HEAD | grep -E '^docs\\(43-05\\):'` matches
  </acceptance_criteria>
  <done>Plan 43-05 contribution section captured + SUMMARY.md written + committed; Plan 43-06 sequenced after Plan 43-05 close.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| upstream `ce06bd59` profile/mod.rs From-impl extension → fork's Phase 36-01b exhaustive enumeration | Silent drop of the `commands: raw.commands` arm would re-introduce the bug Phase 36-01b closed (canonical-section drop); rustc's struct-literal completeness is the structural detector |
| upstream `platform.rs` path-detection logic → fork's path-handling discipline | If upstream uses `String::starts_with` on paths, the vulnerability per CLAUDE.md § Common Footguns #1 lands in the fork; Task 1 Q7 catches this |
| upstream `WhenPredicate` deserialization → fork's profile loading | New deserialization surface is a Spoofing boundary; serde discipline (`#[serde(deny_unknown_fields)]` where the schema requires it) must match Phase 26/36 manifest precedents |
| upstream `policy.rs` extension → fork's `Group::platform: Option<String>` existing platform-conditional concept | Two concepts must coexist (string-platform vs WhenPredicate); Task 1 Q3 verifies no rename/replace |
| upstream `platform.rs` `#[cfg(target_os = "windows")]` branch → fork's `crates/nono-shell-broker/` + `exec_strategy_windows/` API surface | If platform.rs's Windows branch exports collide with broker dispatch surface, D-43-E1 invariant is at risk; Task 1 Q8 catches this |
| JSON schema `when:` predicate → Rust deserialization | If Branch B SKIPped wiring.rs, schema accepts `when:` but Rust no-ops it → silent behavior divergence between fork and upstream. W-4 fix: T-43-05-10 mitigation enforces fail-secure rejection |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-43-05-01 | Tampering | Phase 36-01b `From<ProfileDeserialize> for Profile` exhaustive enumeration regression (silent drop of `commands: raw.commands` arm) | mitigate | Task 1 Q6 + Task 2 explicit extension preserving Phase 36-01b discipline. Verified at Task 3 via grep `'commands: raw.commands' crates/nono-cli/src/profile/mod.rs` returning ≥ 1 |
| T-43-05-02 | Tampering | Phase 36-01c `bypass_protection` rename regression | mitigate | Task 1 Q5 counts `override_deny` matches in upstream; Task 2 applies rename arm-by-arm if needed. Verified at Task 3 via grep `'bypass_protection'` returning ≥ 1 |
| T-43-05-03 | Tampering | `platform.rs` uses `String::starts_with` on paths (CLAUDE.md § Common Footguns #1) | mitigate | Task 1 Q7 catches this; Task 2 amends to `Path::components()` iteration if needed |
| T-43-05-04 | Tampering | fork-only Windows files (broker, exec_strategy_windows/, *_windows.rs) touched directly by cherry-pick (D-43-E1 violation) | mitigate | Task 2 acceptance grep `git diff --name-only HEAD~1 HEAD | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` returns 0 |
| T-43-05-05 | Tampering | `platform.rs` Windows branch exports collide with broker dispatch's `WindowsTokenArm::BrokerLaunch` decision tree (D-43-E1 4-condition addendum check) | mitigate | Task 1 Q8 catches this; if collision exists, resolved_disposition forced to fork-preserve with documented redesign |
| T-43-05-06 | Spoofing | upstream `WhenPredicate` deserialization accepts unknown fields, allowing profile tampering | mitigate | Task 2 cherry-pick / replay applies `#[serde(deny_unknown_fields)]` matching Phase 26/36 manifest precedent (verify via diff inspection during Task 2; if upstream uses lax deserialization, amend) |
| T-43-05-07 | Repudiation | Branch A: cherry-pick missing D-19 trailer / Branch B: replay commit missing 5-section body | mitigate | Task 3 branch-specific smoke verifies trailer counts OR 5-section grep counts |
| T-43-05-08 | Elevation | new `platform.rs` introduces public exports the fork hadn't curated (e.g., a `current_platform()` function with elevated privileges) | mitigate | Task 2 preserves conservative `pub` exports per platform.rs analog (`instruction_deny.rs` pattern); diff inspection in Task 1 verifies upstream's public surface matches expectation |
| T-43-05-09 | DoS | platform-detection performs runtime syscall on every profile load | accept | Detection is one-time at process startup (`OnceLock`-cached pattern per Phase 40 Plan 40-04 Landlock ABI cache precedent); no per-request cost |
| T-43-05-10 | Spoofing/Tampering | JSON schema accepts `when:` predicate but Rust deserialization no-ops it → silent behavior divergence between fork and upstream profile evaluation | mitigate | **W-4 fix:** if Branch B (manual replay) is chosen AND wiring.rs is SKIPped, also reject `when:` predicates at deserialization time via `#[serde(deny_unknown_fields)]` on the deserialize-target struct OR explicit error in `From<ProfileDeserialize>` impl. Fail-secure per CLAUDE.md § Core Principles. Task 2 Branch B step 2 enforces; Task 2 step 6 + Task 3 verify with mitigation-specific test + grep |
| T-43-05-11 | Repudiation | non-canonical disposition value (`TBD-at-plan-open`, `will-sync-via-diff-inspection-upgrade`) in frontmatter breaks downstream tooling that expects canonical D-43-E8 values | mitigate | **W-8 fix:** Task 1 writes canonical value (`will-sync` | `fork-preserve`) into `resolved_disposition:` field via `gsd-sdk query frontmatter.set` or in-place sed; frontmatter `disposition:` stays at conservative `fork-preserve` default; downstream tooling reads `resolved_disposition` for live verdict |

**ASVS L1 disposition:** `high` threats (T-43-05-01 From-impl regression, T-43-05-04 Windows-files invariant, T-43-05-05 broker collision, T-43-05-10 schema-vs-deserialization parity) — mitigate. `medium` threats (T-43-05-02 rename regression, T-43-05-03 path comparison, T-43-05-06 deserialization, T-43-05-07 trailer/body, T-43-05-08 public surface, T-43-05-11 disposition canonical value) — mitigate. `low` threat (T-43-05-09 perf) — accept. Security gate satisfied.
</threat_model>

<verification>
Per-plan close gate (D-43-E9 = Phase 34 D-34-D2 8-check format):

| Gate | Description | Required | Disposition |
|------|-------------|----------|-------------|
| 1 | `cargo test --workspace --all-features` (Windows host) | required | execute |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | required | execute |
| 3 | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | load-bearing (platform.rs contains cfg-gated Linux branches) | execute or skipped_gates_load_bearing → CI-verified |
| 4 | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped_gates_load_bearing → CI-verified |
| 5 | `cargo fmt --all -- --check` | required | execute |
| 6 | Phase 15 5-row detached-console smoke | environmental | skipped_gates_environmental |
| 7 | `wfp_port_integration` tests | environmental (Windows-host only) | skipped_gates_environmental |
| 8 | `learn_windows_integration` tests | environmental (Windows-host only) | skipped_gates_environmental |

Branch-specific smoke per Task 1 verdict (per `resolved_disposition` frontmatter):
- Branch A (resolved_disposition = will-sync): `Upstream-commit:` trailer count = 1; Phase 36-01b commands enumeration preserved; Phase 36-01c bypass_protection preserved
- Branch B (resolved_disposition = fork-preserve): 5-section D-20 body grep counts all = 1; `Upstream-commit:` trailer count = 0; `Upstream-replayed-from: ce06bd59` present; W-4 fix mitigation evidence (deny_unknown_fields grep or explicit-error test result) if wiring.rs SKIPped

Wave 2a baseline-aware CI gate: zero `success → failure` lane transitions vs baseline SHA `13cc0628` per D-43-E3.
</verification>

<success_criteria>
- Task 1 diff-inspection verdict recorded in PLAN.md + SUMMARY.md frontmatter `resolved_disposition:` field via canonical value per W-8 fix (`will-sync` | `fork-preserve`; no non-canonical strings) + docs-only commit (Phase 40 Plan 40-05 pattern)
- Task 2 produces 1 cherry-pick (Branch A) OR 1+ D-20 replay commits (Branch B) matching the `resolved_disposition`
- Phase 36-01b From-impl exhaustive enumeration preserved + extended with WhenPredicate-bearing field arm
- Phase 36-01c `bypass_protection` canonical name preserved
- Path-component comparison preserved per CLAUDE.md § Common Footguns #1
- D-43-E1 invariant holds (0 unauthorized Windows-file touches)
- W-4 fix mitigation applied (Branch B + wiring.rs SKIPped): JSON schema's `when:` predicate rejected at deserialization (via `deny_unknown_fields` OR explicit error in From-impl) — no silent fork-vs-upstream behavior divergence
- D-43-E9 8-check close gate + branch-specific smoke clean
- Wave 2a baseline-aware CI gate: zero green→red transitions vs `13cc0628`
- Plan 43-05 contribution section appended to Phase 43 umbrella PR
- SUMMARY.md committed; Plan 43-06 sequenced after Plan 43-05 close per D-43-A3
- REQ-UPST5-02 acceptance criteria #2 + #3 advanced for Cluster 5 (windows-touch:yes cluster handled per audit disposition with explicit Phase 43 plan-phase verdict)
</success_criteria>

<output>
After completion, create `.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md` per Task 4 specification.
</output>
</output>
