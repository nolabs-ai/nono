---
plan_id: 43-06-PLATFORM-DETECTION-WINDOWS
phase: 43-upst5-sync-execution
plan: 06
wave: "2b"
type: execute
cluster_id: 4
# W-8 fix: canonical disposition values per CONTEXT.md / Phase 42 ledger / D-43-E8: will-sync | fork-preserve | won't-sync
# Conservative default = fork-preserve per D-42-C3; Task 1 may upgrade to will-sync via diff-inspection per D-43-C1
# (constrained by Plan 43-05's resolved_disposition).
disposition: fork-preserve
disposition_resolution_at_plan_open: true
final_disposition_field_name: resolved_disposition
resolved_disposition: fork-preserve  # Task 1 verdict 2026-05-18: foundation-constraint-forced + trial-pick 2 content conflicts (W-8 canonical value)
upstream_range: v0.53.0..v0.54.0
upstream_shas: [0748cced, 5d821c12]
upstream_tag: v0.54.0
baseline_sha: 13cc0628
umbrella_pr_section: "Plan 43-06 — Cluster 4 Windows platform detection (registry queries + REG_DWORD fix)"
opens_umbrella_pr: false
requirements: [REQ-UPST5-02]
depends_on: ["43-05-PLATFORM-DETECTION-FOUNDATION"]
autonomous: true
files_modified:
  # Constrained by Plan 43-05 resolved_disposition. Both commits land as a unit (0748cced introduces parsing, 5d821c12 fixes the parsing bug).
  - crates/nono-cli/src/platform.rs  # Existing post-Plan-43-05; Cluster 4's Windows registry queries + REG_DWORD fix extend the Windows branch
  - crates/nono-cli/src/profile/mod.rs  # 0748cced extends WhenPredicate deserialization by 67 lines per ledger
  - crates/nono-cli/src/wiring.rs  # 0748cced touches WiringDirective::Skipped serialization skip (4 lines)
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (platform.rs has cfg-gated cross-platform branches — load-bearing)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (platform.rs has cfg-gated cross-platform branches — load-bearing)"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent (Cluster 4 IS Windows-specific; Gates 7+8 below should run on Windows host if possible)"
  gate_7_wfp_port_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent; SHOULD run on Windows host for Plan 43-06 specifically because Cluster 4 introduces Windows registry parsing — surface to user if Windows host available"
  gate_8_learn_windows_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent; SHOULD run on Windows host for Plan 43-06 specifically — surface to user if Windows host available"
must_haves:
  truths:
    - "Plan 43-06 dependency on Plan 43-05 honored: `crates/nono-cli/src/platform.rs` exists in fork (introduced by Plan 43-05 cherry-pick OR D-20 manual replay) before any Cluster 4 hunk is applied"
    - "Task 1 mandatory diff-inspection per D-43-C1 (Phase 40 D-40-B1 pattern) writes canonical value into PLAN.md frontmatter `resolved_disposition:` field per W-8 fix (canonical values per D-43-E8: will-sync | fork-preserve). Verdict is CONSTRAINED by Plan 43-05's `resolved_disposition` per 43-PATTERNS.md § Plan 43-06: if Plan 43-05 resolved_disposition = will-sync (full platform.rs cherry-picked), Cluster 4 cherry-picks compose cleanly → Plan 43-06 can also resolve to will-sync; if Plan 43-05 resolved_disposition = fork-preserve (partial platform.rs replay), Plan 43-06 MUST also resolve to fork-preserve (replay-when-foundation-is-also-replayed pattern)"
    - "BOTH commits 0748cced + 5d821c12 land as a unit (0748cced introduces Windows registry parsing; 5d821c12 fixes the REG_DWORD parsing bug — cherry-picking one without the other safely is not viable per Phase 42 ledger Cluster 4 rationale); W-7 fix: wrapped-transaction script lands both atomically with rollback on partial failure"
    - "Both upstream SHAs are reachable pre-task (W-7 fix pre-flight): `git cat-file -e 0748cced^{commit} && git cat-file -e 5d821c12^{commit}` exit 0"
    - "Chronological order verified falsifiably (W-5 fix): post-task, HEAD's Upstream-commit trailer is 5d821c12 (REG_DWORD fix, lands SECOND), HEAD~1's Upstream-commit trailer is 0748cced (feature, lands FIRST)"
    - "Windows-touch:yes first-cycle review honored — D-43-E1 4-condition addendum applied for each Windows-specific extension: (1) required cross-platform struct field; (2) cross-platform default factory only; (3) ≤5 lines (or documented exception); (4) documented in SUMMARY + STATE. The cfg(target_os = \"windows\") branches inside platform.rs are NEW cross-platform module code (NOT fork-only Windows code in *_windows.rs / exec_strategy_windows/ / crates/nono-shell-broker/), so they are PERMITTED — but EACH Windows hunk must be cross-referenced against the addendum"
    - "Phase 36-01b `From<ProfileDeserialize> for Profile` exhaustive enumeration preserved across both commits (0748cced extends WhenPredicate; collision check against Phase 36-01b's commands arm + Plan 43-05's WhenPredicate field-arm extension)"
    - "Phase 36-01c `bypass_protection` rename honored — verify both 0748cced + 5d821c12 don't reference pre-rename `override_deny`"
    - "REG_DWORD parsing per 5d821c12: hex-prefixed values (0xN) converted to decimal string; `unwrap_or_default()` replaced with `map_or(\"\", |part| part)` to avoid panic on malformed version strings; unit test included. This is the bug fix on top of 0748cced — landing them together prevents the parsing panic from reaching fork main"
    - "Path-component comparison preserved per CLAUDE.md § Common Footguns #1 (registry parsing involves no filesystem paths but verify any new path-touching code)"
    - "If resolved_disposition = will-sync (Plan 43-05 also will-sync): each of 2 cherry-picks carries verbatim 6-line D-19 trailer block. If resolved_disposition = fork-preserve: each replay commit carries full D-40-B3 5-section body with ZERO `Upstream-commit:` trailer lines"
    - "Zero green→red lane transitions vs baseline SHA 13cc0628 (D-43-E3)"
    - "All cross-target clippy lanes (Linux + macOS) exit 0 — or marked load-bearing-skip → CI-verified (D-43-E4); Cluster 4 extends platform.rs which already has cross-platform branches from Plan 43-05"
    - "Zero touches to fork-only Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/`) — D-43-E1; Windows-specific REG_DWORD parsing lands INSIDE platform.rs's #[cfg(target_os = \"windows\")] branch, NOT in fork's *_windows.rs files"
    - "Plan 43-06 contribution section appended to Phase 43 umbrella PR body (D-43-E6); Plan 43-06 closes Phase 43"
    - "Cherry-pick state cleanly sealed after both commits via wrapped-transaction script (W-7 fix); no orphaned `.git/CHERRY_PICK_HEAD`; no `git cherry-pick --continue` ever invoked per `<no_interactive_editor_protocol>` precedent from Plan 43-02"
  artifacts:
    - path: crates/nono-cli/src/platform.rs
      provides: "Windows registry queries for product name + version + edition + REG_DWORD parsing fix"
      contains: "registry"
    - path: .planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md
      provides: "Disposition-resolution evidence + windows-touch:yes 4-condition addendum table + close-gate + PR umbrella contribution + Phase 43 close"
  key_links:
    - from: crates/nono-cli/src/platform.rs Windows branch (from Plan 43-05)
      to: Windows registry query implementation (Cluster 4)
      via: "#[cfg(target_os = \"windows\")] gated extension"
      pattern: "registry|RegOpenKeyExW|RegQueryValueExW"
    - from: 0748cced Windows registry parsing
      to: 5d821c12 REG_DWORD parsing fix (lands as unit via W-7 wrapped-transaction)
      via: "Sequential cherry-pick AS PAIR (Phase 42 ledger explicit recommendation); atomic with rollback on partial failure"
      pattern: "REG_DWORD|hex-prefixed"
---

<objective>
Absorb Cluster 4's 2 upstream commits as a unit: `0748cced feat(platform): implement robust windows platform detection` (queries Windows registry for product name + version + edition; ~66 net lines on platform.rs + 67 lines on profile/mod.rs WhenPredicate deserialization + 4 lines on wiring.rs WiringDirective::Skipped serialization skip) + `5d821c12 fix(platform): correctly parse windows registry dword values` (REG_DWORD parsing bug fix on top of 0748cced; identifies REG_DWORD values during registry parsing, converts hex-prefixed values (0x123) to decimal string, replaces `unwrap_or_default()` with `map_or("", |part| part)` to avoid panic on malformed version strings, adds unit test; ~26 net lines on platform.rs).

Both commits MUST land as a unit per Phase 42 ledger Cluster 4 rationale: cherry-picking 0748cced without 5d821c12 leaves the REG_DWORD parsing panic on fork main; cherry-picking 5d821c12 without 0748cced has nothing to fix. **W-7 fix:** Task 2 Branch A uses a wrapped-transaction script that lands both cherry-picks atomically with `trap 'git reset --hard $PRE_TASK_HEAD' ERR` rollback on partial failure; pre-flight verifies both SHAs are reachable; post-commit acceptance falsifiably verifies both trailers present.

Default disposition: fork-preserve (D-20 manual replay) per D-42-C3 conservative-default-for-windows-touch-yes-cluster. UPGRADE AUTHORITY per D-43-C1: Task 1 diff-inspection. CONSTRAINED by Plan 43-05's `resolved_disposition` — if Plan 43-05 stayed fork-preserve (partial platform.rs replay), Plan 43-06 MUST also stay fork-preserve (replay-when-foundation-is-also-replayed pattern per 43-PATTERNS.md). **W-8 fix:** canonical disposition values per D-43-E8 only (`will-sync` | `fork-preserve`); frontmatter `disposition:` defaults to conservative `fork-preserve`; Task 1 writes canonical post-verdict value into `resolved_disposition:` field.

Windows-touch:yes first-cycle review honored — each Windows-specific extension is cross-referenced against the D-43-E1 4-condition addendum. The cfg(target_os = "windows") branches inside platform.rs are PERMITTED (cross-platform module code, NOT fork-only Windows code per D-11 / D-43-E1 scope) — but each hunk is reviewed for: (1) required cross-platform struct field, (2) cross-platform default factory only, (3) ≤5 lines (or documented exception with rationale), (4) documented in SUMMARY + STATE.

Per D-43-A3: Plan 43-06 is Wave 2b, sequential after Plan 43-05 (Wave 2a). Plan 43-06 closes Phase 43.

Output: 2 cherry-pick commits via W-7 wrapped-transaction script (Branch A, both resolved_dispositions will-sync) OR 1-2 D-20 replay commits (Branch B, fork-preserve) — both commits land as a unit + 1 SUMMARY.md + 1 contribution section appended to Phase 43 umbrella PR.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/43-upst5-sync-execution/43-CONTEXT.md (D-43-A3 + D-43-C1 + D-43-C2 + D-43-E1)
@.planning/phases/43-upst5-sync-execution/43-PATTERNS.md § Plan 43-06 (Phase 40 Plan 40-06 FP-PROXY-TLS skeleton — terminal-Wave-2 D-20 with sequential dependency on prior fork-preserve)
@.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md § Cluster: Windows platform detection
@.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md (depends_on — Plan 43-05's resolved_disposition CONSTRAINS Plan 43-06's resolved_disposition)
@.planning/phases/40-upst4-sync-execution/40-06-FP-PROXY-TLS-SUMMARY.md (PRIMARY skeleton — terminal-Wave-2 D-20 with sequential dependency + Windows-fallback decision pattern)
@.planning/phases/36-upst3-deep-closure/36-01b-CANONICAL-PROFILE-SECTIONS-SUMMARY.md (From-impl extension pattern)
@.planning/templates/upstream-sync-quick.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md
@crates/nono-cli/src/platform.rs

<interfaces>
<!-- Post-Plan-43-05, the fork has crates/nono-cli/src/platform.rs (either full upstream shape if Plan 43-05 = will-sync, or partial replay if Plan 43-05 = fork-preserve). Cluster 4 extends the Windows branch. -->

The exact `platform.rs` surface depends on Plan 43-05's `resolved_disposition`:
- **Plan 43-05 resolved_disposition = will-sync (full 659 lines):** platform.rs has full upstream shape including Windows branch skeleton; Cluster 4 cherry-picks compose cleanly because 0748cced + 5d821c12 land on the same upstream-shaped platform.rs they were originally written against.
- **Plan 43-05 resolved_disposition = fork-preserve (partial replay):** platform.rs has minimal surface (e.g., `current_platform()` + per-OS branches with bare detection); Cluster 4's Windows registry parsing must replay-on-replay — extending the fork's partial Windows branch with the registry parsing + REG_DWORD fix shape.

**D-43-E1 4-condition addendum scope:** Cluster 4's cherry-pick MUST be reviewed per-hunk:
1. Required cross-platform struct field — the Windows-specific extension MUST be needed by a cross-platform caller (e.g., `Platform::Windows { version: String }` is consumed by cross-platform WhenPredicate evaluation)
2. Cross-platform default factory only — fork's *_windows.rs files MUST NOT receive new factory functions
3. ≤5 lines — small additions; larger Windows-specific blocks documented with explicit rationale
4. Documented in SUMMARY + STATE — Task 4's SUMMARY includes a per-hunk 4-condition addendum table

**Fork-only Windows files that MUST NOT receive Cluster 4 edits (per D-43-E1 + 43-PATTERNS.md verification grep):**
- `crates/nono-cli/src/exec_identity_windows.rs`
- `crates/nono-cli/src/learn_windows.rs`
- `crates/nono-cli/src/open_url_runtime_windows.rs`
- `crates/nono-cli/src/pty_proxy_windows.rs`
- `crates/nono-cli/src/session_commands_windows.rs`
- `crates/nono-cli/src/trust_intercept_windows.rs`
- `crates/nono/src/supervisor/socket_windows.rs`
- `crates/nono-cli/tests/exec_identity_windows.rs`
- All files under `crates/nono-cli/src/exec_strategy_windows/`
- All files under `crates/nono-shell-broker/`
</interfaces>

<upstream_commits>
| Position | SHA (abbrev) | Subject | files-changed |
|---|---|---|---|
| 1 | 0748cced | feat(platform): implement robust windows platform detection | 4 (per ledger: platform.rs +66, profile/mod.rs +67, wiring.rs +4, schema +N) |
| 2 | 5d821c12 | fix(platform): correctly parse windows registry dword values | 1 (per ledger: platform.rs +26) |

Both `windows-touch: yes` per Phase 42 D-42-C1/C2. Both touch platform.rs (introduced by Cluster 5 / Plan 43-05).

Categories: `other,profile` for 0748cced; `other` for 5d821c12.

Chronological order: 0748cced FIRST (introduces the parsing), 5d821c12 SECOND (fixes the parsing bug). Verify via `git log -1 --format='%aI' <sha>` for each.

W-7 fix pre-flight reachability check: `git cat-file -e 0748cced^{commit} && git cat-file -e 5d821c12^{commit}` (both exit 0).
</upstream_commits>

<d19_trailer_block_template>
(IF resolved_disposition = will-sync after Task 1 verdict; applied to each of 2 cherry-picks)
```
Upstream-commit: <8-char>
Upstream-tag: v0.54.0
Upstream-author: <from `git log -1 --format='%an <%ae>' <sha>`>
Upstream-subject: <from `git log -1 --format='%s' <sha>`>
Upstream-date: <from `git log -1 --format='%aI' <sha>`>
Upstream-categories: <other | other,profile>
Co-Authored-By: <same name + email as Upstream-author>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
</d19_trailer_block_template>

<d20_replay_body_template>
(IF resolved_disposition = fork-preserve after Task 1 verdict; per 43-PATTERNS.md Pattern 2 + Phase 40 Plan 40-06 SUMMARY — applied to 1-2 replay commits)
```
<one-paragraph subject/body explaining the replay scope; combine 0748cced + 5d821c12 into a single replay if pragmatic, OR keep separate for traceability>

Upstream intent: <one-sentence summary of 0748cced + 5d821c12 — Windows registry-based platform detection with REG_DWORD parsing fix>

What was replayed: <list of fork-side changes — registry query Windows branch + REG_DWORD parsing logic incl. hex-prefix conversion + map_or pattern replacing unwrap_or_default + unit test>

What was NOT replayed and why: <list — if Plan 43-05 stayed fork-preserve, upstream's profile/mod.rs WhenPredicate extension hunks may already be covered by Plan 43-05's replay; if 0748cced's WhenPredicate hunks compose additively, replay them here; if they collide with Plan 43-05's replay scope, document the deferral>

Fork-only wiring preserved: <fork-specific invariants — D-43-E1 broker dispatch Windows-token-arm decision tree byte-identical; *_windows.rs files unchanged; Phase 36-01b From-impl exhaustive enumeration; Phase 36-01c bypass_protection rename>

Upstream-replayed-from: 0748cced
Upstream-replayed-from: 5d821c12

Co-Authored-By: Claude <noreply@anthropic.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
ZERO `Upstream-commit:` trailer lines.
</d20_replay_body_template>

<no_interactive_editor_protocol>
Same as Plans 43-02 + 43-05 (B-4 precedent applies — Windows `git cherry-pick --continue` opens an editor and can stall):

1. Use `git -c core.editor=true cherry-pick --no-commit <sha>` (editor suppressed)
2. NEVER use `git cherry-pick --continue` (opens editor on Windows)
3. After staging conflict resolution, `git add <files>` + `git commit -F /tmp/msg.txt` explicitly
4. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`
</no_interactive_editor_protocol>

<wrapped_transaction_protocol>
<!-- W-7 fix: Cluster 4's 2 commits MUST land as a unit. Wrapped-transaction script lands both atomically; rollback on partial failure. -->

**MANDATORY for Branch A (Task 2) — both 0748cced + 5d821c12 cherry-picks:**

```bash
# Pre-flight: verify both SHAs reachable (W-7 fix)
git cat-file -e 0748cced^{commit} || { echo "FAIL: 0748cced unreachable"; exit 1; }
git cat-file -e 5d821c12^{commit} || { echo "FAIL: 5d821c12 unreachable"; exit 1; }

# Capture pre-task HEAD for rollback target
PRE_TASK_HEAD=$(git rev-parse HEAD)

# Wrap both cherry-picks in a trap that rolls back on partial failure
trap 'echo "FAIL: partial cherry-pick — rolling back to $PRE_TASK_HEAD"; git reset --hard $PRE_TASK_HEAD; exit 1' ERR
set -e

# Cherry-pick 0748cced (chronologically first)
git -c core.editor=true cherry-pick --no-commit 0748cced
# ... resolve conflicts (per Task 2 step 3 below), build commit msg, write to /tmp/43-06-cp-0748cced.txt
git commit -F /tmp/43-06-cp-0748cced.txt
[[ ! -f .git/CHERRY_PICK_HEAD ]] || { echo "FAIL: 0748cced state still open"; exit 1; }

# Cherry-pick 5d821c12 (chronologically second; fixes 0748cced's REG_DWORD parsing bug)
git -c core.editor=true cherry-pick --no-commit 5d821c12
# ... resolve conflicts, build commit msg, write to /tmp/43-06-cp-5d821c12.txt
git commit -F /tmp/43-06-cp-5d821c12.txt
[[ ! -f .git/CHERRY_PICK_HEAD ]] || { echo "FAIL: 5d821c12 state still open"; exit 1; }

# Both succeeded — disable rollback
trap - ERR
set +e

# Post-commit falsifiable acceptance (W-7 fix + W-5 fix chronological-order check)
[[ "$(git log -1 --format=%B HEAD | grep -E '^Upstream-commit:' | awk '{print $2}')" == "5d821c12" ]] \
  || { echo "FAIL: HEAD's Upstream-commit is not 5d821c12 (W-5 fix chronological-order violation)"; exit 1; }
[[ "$(git log -1 --format=%B HEAD~1 | grep -E '^Upstream-commit:' | awk '{print $2}')" == "0748cced" ]] \
  || { echo "FAIL: HEAD~1's Upstream-commit is not 0748cced (W-5 fix chronological-order violation)"; exit 1; }
[[ "$(git log HEAD~2..HEAD --format=%B | grep -c '^Upstream-commit: \(0748cced\|5d821c12\)')" -eq 2 ]] \
  || { echo "FAIL: both SHA trailers must appear exactly once across HEAD~1..HEAD"; exit 1; }
```

Rollback semantics: if either cherry-pick fails (conflict + resolve attempt errors, OR commit verification fails), `trap ... ERR` triggers `git reset --hard $PRE_TASK_HEAD`, returning the working tree to the pre-task state. This prevents leaving the fork in a state where 0748cced landed but 5d821c12 didn't (REG_DWORD parsing panic on main).
</wrapped_transaction_protocol>
</context>

<tasks>

<task id="1" type="execute" autonomous="true">
  <name>Task 1: Mandatory diff-inspection (D-43-C1) constrained by Plan 43-05 resolved_disposition + record disposition + SHA reachability pre-flight</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-CONTEXT.md (D-43-C1, D-43-A3, D-43-E1)
    - .planning/phases/43-upst5-sync-execution/43-PATTERNS.md § Plan 43-06 (replay-when-foundation-is-also-replayed pattern + Windows-fallback decision pattern)
    - .planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md (CRITICAL — Plan 43-05's `resolved_disposition` CONSTRAINS Plan 43-06's `resolved_disposition` per 43-PATTERNS.md § Plan 43-06)
    - .planning/phases/40-upst4-sync-execution/40-06-FP-PROXY-TLS-SUMMARY.md (PRIMARY skeleton — Wave 2 sequential D-20 + Windows-fallback decision pattern DEC-6 line 156-159)
    - Upstream commits: `git show 0748cced --stat` + `git show 5d821c12 --stat` + `git show 0748cced -- crates/nono-cli/src/platform.rs` + `git show 5d821c12 -- crates/nono-cli/src/platform.rs`
    - Fork's post-Plan-43-05 platform.rs: read full file via Read tool
  </read_first>
  <action>
    1. Confirm Plan 43-05 closed: `git log --format='%B' HEAD~10..HEAD | grep -cE '^Upstream-commit: ce06bd59|^Upstream-replayed-from: ce06bd59'` → ≥ 1.
    2. **W-7 fix SHA reachability pre-flight:** verify both Cluster 4 SHAs are reachable BEFORE any task action that depends on them:
       `git cat-file -e 0748cced^{commit} && git cat-file -e 5d821c12^{commit}`
       If either fails: STOP and surface "upstream fetch incomplete; run `git fetch upstream --tags` and re-attempt".
    3. Read Plan 43-05's `resolved_disposition` from `.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md` frontmatter (or PLAN.md frontmatter). Record it as the "foundation verdict" constraint.
    4. Apply 43-PATTERNS.md § Plan 43-06 replay-when-foundation-is-also-replayed constraint:
       - If foundation `resolved_disposition` = `will-sync`: Cluster 4 can attempt upgrade-to-will-sync; proceed to diff-inspection Q-series below
       - If foundation `resolved_disposition` = `fork-preserve`: Plan 43-06 MUST stay fork-preserve (the partial replay of Plan 43-05's platform.rs cannot cleanly accept Cluster 4's cherry-picks because the SHAs reference upstream's full 659-line shape that the fork doesn't have); set `RESOLVED_DISPOSITION="fork-preserve"` and SKIP the trial cherry-pick step (proceed directly to step 8)
    5. (If foundation `resolved_disposition` allows attempting upgrade) Answer Q-series for both Cluster 4 commits:
       - **Q1 (terminal_approval.rs):** `git show 0748cced 5d821c12 --name-only | grep -c 'crates/nono-cli/src/terminal_approval.rs'` → expected 0
       - **Q2 (profile/mod.rs From-impl):** `git show 0748cced --name-only | grep -c 'crates/nono-cli/src/profile/mod.rs'`; if YES, verify Phase 36-01b commands enumeration + Plan 43-05's WhenPredicate extension both preserved + 0748cced's extension is additive
       - **Q3 (wiring.rs):** `git show 0748cced --name-only | grep -c 'crates/nono-cli/src/wiring.rs'`; if YES (per ledger: 4 lines for WiringDirective::Skipped serialization skip), verify Plan 36-02 yaml-merge surface unchanged
       - **Q4 (path comparison):** `git show 0748cced 5d821c12 | grep -cE '\\.starts_with\\("/' `→ expected 0
       - **Q5 (override_deny):** `git show 0748cced 5d821c12 | grep -cE 'override_deny|bypass_protection'`; record both counts
       - **Q6 (Windows-only files touched):** `git show 0748cced 5d821c12 --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → expected 0. If non-zero, the touches MUST be inside cross-platform files (platform.rs's #[cfg(target_os = "windows")] branch IS cross-platform); verify via file extension (platform.rs is NOT a *_windows.rs file)
       - **Q7 (broker dispatch collision):** `git show 0748cced 5d821c12 | grep -cE 'WindowsTokenArm|BrokerLaunch'` → expected 0
       - **Q8 (D-43-E1 4-condition addendum per Windows-specific hunk):** for each Windows-specific extension in 0748cced/5d821c12, record:
         - (1) consumed by cross-platform caller? (YES — WhenPredicate evaluation is cross-platform)
         - (2) cross-platform default factory only? (verify — Windows-specific behavior via `#[cfg(target_os = "windows")]`)
         - (3) ≤5 lines? (most Cluster 4 hunks exceed 5 lines — document as "exception per D-43-E1 with rationale: Windows-platform-detection requires a meaningful registry-parsing implementation which cannot fit in 5 lines; this is the documented exception pattern" — see 43-CONTEXT.md D-43-C1 verdict-recording mechanism)
         - (4) documented in SUMMARY + STATE? (Task 4 captures)
       - **Q9 (Windows-fallback decision — per Phase 40 Plan 40-06 DEC-6 pattern):** Does Cluster 4 introduce a Windows-specific behavior that the fork's *_windows.rs files have a divergent version of? If YES, document the decision: Option A (uniform behavior — upstream wins) OR Option B (preserve fork's existing path with warning log). Audit evidence: `grep -rE 'registry|RegOpenKey|RegQueryValue' crates/nono-cli/src/exec_strategy_windows/ crates/nono-shell-broker/` — if zero matches, Option A applies by default (no fork-side path to suppress).
    6. Trial cherry-pick BOTH commits in chronological order on a scratch branch (editor-suppressed per `<no_interactive_editor_protocol>`):
       ```
       git switch -c 43-06-trial-cherry-pick
       git -c core.editor=true cherry-pick --no-commit 0748cced
       <inspect; count conflicts>
       git cherry-pick --abort  (if conflicts surface — never --continue) THEN re-attempt OR;
       if 0748cced clean: stage + `git commit -F /tmp/trial-0748cced.txt` (placeholder msg); then try 5d821c12
       ```
       Count: content conflicts, modify/delete, behavioral surprises.
    7. Apply Phase 40 D-40-B1 upgrade rule (CONSTRAINED by foundation verdict; canonical values per W-8 fix):
       - Foundation `resolved_disposition = will-sync` AND clauses (a)+(b) both PASS: `RESOLVED_DISPOSITION="will-sync"`
       - Foundation `resolved_disposition = will-sync` AND either clause FAILS: `RESOLVED_DISPOSITION="fork-preserve"` (downgrade-on-failed-upgrade)
       - Foundation `resolved_disposition = fork-preserve`: `RESOLVED_DISPOSITION="fork-preserve"` (forced by foundation constraint)
       (Canonical values only — no non-canonical strings per W-8 fix.)
    8. Abort trial + delete scratch branch:
       ```
       git cherry-pick --abort 2>/dev/null
       git switch -
       git branch -D 43-06-trial-cherry-pick
       ```
    9. Record verdict + Q1-Q9 evidence + foundation constraint + 4-condition addendum table + Windows-fallback decision + SHA reachability evidence in `.planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md`. **Write `resolved_disposition` into PLAN.md frontmatter (W-8 fix; canonical value):**
       Preferred: `gsd-sdk query frontmatter.set ".planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-PLAN.md" resolved_disposition "$RESOLVED_DISPOSITION"`
       Fallback: `sed -i.bak "s/^resolved_disposition: null/resolved_disposition: $RESOLVED_DISPOSITION/" .planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-PLAN.md && rm .planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-PLAN.md.bak`
    10. Commit the disposition resolution as a docs commit:
       `git add .planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md .planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-PLAN.md`
       `git commit -m "docs(43-06): record D-43-C1 diff-inspection verdict for cluster 4 (constrained by 43-05 verdict)" --signoff`
  </action>
  <acceptance_criteria>
    - Plan 43-05 closed (verified via grep)
    - **W-7 SHA reachability pre-flight passes:** `git cat-file -e 0748cced^{commit}` exits 0 AND `git cat-file -e 5d821c12^{commit}` exits 0
    - Foundation `resolved_disposition` read from `.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md` frontmatter
    - `.planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md` exists with: foundation constraint, Q1-Q9 numeric evidence, 4-condition addendum per-hunk table, Windows-fallback decision (Option A or B with audit evidence), trial cherry-pick result, final verdict, SHA reachability evidence
    - PLAN.md frontmatter `resolved_disposition:` field updated to CANONICAL value: `will-sync` | `fork-preserve` (W-8 fix; no non-canonical strings)
    - PLAN.md frontmatter `disposition:` remains `fork-preserve` (conservative default unchanged)
    - `git status --porcelain` clean (scratch branch deleted)
    - Disposition docs commit landed
    - Q6 evidence recorded: 0 fork-only-Windows-file touches OR explicit per-touch 4-condition addendum entries
    - Q7 evidence recorded: 0 broker dispatch collision
  </acceptance_criteria>
  <done>Disposition resolution committed as docs-only commit before any code change; PLAN.md frontmatter `resolved_disposition:` updated with CANONICAL value (W-8 fix); SHA reachability pre-flight passed (W-7 fix prerequisite); 4-condition addendum table recorded; Tasks 2+ branch on the `resolved_disposition` value.</done>
</task>

<task id="2" type="execute" autonomous="true">
  <name>Task 2: Apply cluster 4 per resolved_disposition — both commits as a unit via W-7 wrapped-transaction</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md (Task 1 verdict + 4-condition addendum table)
    - PLAN.md frontmatter `resolved_disposition` (the canonical Task-1 verdict per W-8 fix)
    - If resolved_disposition = will-sync: .planning/templates/upstream-sync-quick.md (D-19 trailer) + .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (multi-cherry-pick discipline)
    - If resolved_disposition = fork-preserve: .planning/phases/40-upst4-sync-execution/40-06-FP-PROXY-TLS-SUMMARY.md (D-20 manual replay + Windows-fallback decision Pattern + replay-when-surface-structurally-absent)
    - `<wrapped_transaction_protocol>` block above (MANDATORY for Branch A — W-7 fix; atomic-commit-with-rollback)
    - `<no_interactive_editor_protocol>` block above (MANDATORY — B-4 fix; editor-suppressed cherry-pick)
  </read_first>
  <action>
    Branch on Task 1 verdict; in BOTH branches the 2 commits land as a unit (sequentially in chronological order: 0748cced first, 5d821c12 second).

    ### Branch A — IF resolved_disposition = will-sync (requires Plan 43-05 resolved_disposition = will-sync)
    **Apply `<wrapped_transaction_protocol>` script verbatim (W-7 fix).** Key script elements integrated with conflict-resolution + commit-message-build:

    1. Working tree clean check.
    2. Capture pre-task HEAD: `PRE_TASK_HEAD=$(git rev-parse HEAD)`
    3. Install rollback trap: `trap 'echo "FAIL: partial cherry-pick — rolling back to $PRE_TASK_HEAD"; git reset --hard $PRE_TASK_HEAD; exit 1' ERR; set -e`
    4. **First cherry-pick (0748cced):**
       a. `git -c core.editor=true cherry-pick --no-commit 0748cced`
       b. Resolve any conflicts hunk-by-hunk:
          - Verify D-43-E1: `git diff --staged --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0. If non-zero AND the touch is in platform.rs's `#[cfg(target_os = "windows")]` branch (cross-platform module), apply the 4-condition addendum per Task 1's table; otherwise STOP (trap will rollback).
          - Apply Phase 36-01c rename if Task 1 Q5 found `override_deny` matches
          - Apply path-handling amendment if Task 1 Q4 found string compare
       c. Build D-19 trailer block per template; write to `/tmp/43-06-cp-0748cced.txt`. Body includes verbatim upstream subject + body + `Fork-side notes:` paragraph + 6-line D-19 trailer + 1 Co-Authored-By + 2 Signed-off-by.
       d. Commit explicitly: `git commit -F /tmp/43-06-cp-0748cced.txt`
       e. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`
       f. Build/test smoke: `cargo build --workspace` exits 0 (compile-only; test failures related to REG_DWORD bug are EXPECTED and clear after 5d821c12 lands)
    5. **Second cherry-pick (5d821c12):**
       a. `git -c core.editor=true cherry-pick --no-commit 5d821c12`
       b. Resolve any conflicts (similar discipline)
       c. Build D-19 trailer block; write to `/tmp/43-06-cp-5d821c12.txt`
       d. Commit explicitly: `git commit -F /tmp/43-06-cp-5d821c12.txt`
       e. Verify state sealed: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`
    6. Both cherry-picks succeeded — disable rollback: `trap - ERR; set +e`
    7. **W-7 fix + W-5 fix post-commit falsifiable acceptance:**
       ```
       # W-5 fix: chronological order verified falsifiably
       [[ "$(git log -1 --format=%B HEAD | grep -E '^Upstream-commit:' | awk '{print $2}')" == "5d821c12" ]] \
         || { echo "FAIL: HEAD is not 5d821c12"; exit 1; }
       [[ "$(git log -1 --format=%B HEAD~1 | grep -E '^Upstream-commit:' | awk '{print $2}')" == "0748cced" ]] \
         || { echo "FAIL: HEAD~1 is not 0748cced"; exit 1; }
       # W-7 fix: both trailers present exactly once across the 2-commit range
       [[ "$(git log HEAD~2..HEAD --format=%B | grep -c '^Upstream-commit: \(0748cced\|5d821c12\)')" -eq 2 ]] \
         || { echo "FAIL: both SHA trailers must appear exactly once"; exit 1; }
       ```

    ### Branch B — IF resolved_disposition = fork-preserve
    1. Working tree clean.
    2. Define minimal replay scope — both commits' Windows-specific intent combined:
       - **Replay scope:** Windows registry parsing on `platform.rs` (the Windows branch from Plan 43-05's partial replay or full cherry-pick); REG_DWORD parsing logic with hex-prefix conversion + `map_or("", |part| part)` panic-safety; unit test for the parser; 0748cced's WhenPredicate hunks IF additive against Plan 43-05's replay (otherwise document deferral)
       - **NOT replayed:** any wiring.rs WiringDirective::Skipped serialization skip if Plan 43-05's replay didn't include wiring.rs extensions (deferred — no caller in fork until WhenPredicate evaluation is wired)
       - **D-43-E1 invariant:** all replay edits land INSIDE `platform.rs` `#[cfg(target_os = "windows")]` branch (cross-platform module — NOT fork's *_windows.rs files)
    3. Apply the replay edits. Verify:
       - `git diff --name-only | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0
       - REG_DWORD parsing safety: NO `unwrap_or_default()` patterns introduced; use `map_or("", |part| part)` per upstream 5d821c12 fix
       - Unit test added for the REG_DWORD parser
    4. Decide commit shape — combine BOTH commits into ONE replay commit (preferred for traceability — Cluster 4 is a parser + parser-fix unit) OR split into 2 replay commits (one per upstream SHA). Default: ONE combined replay commit with both `Upstream-replayed-from:` lines per Phase 40 Plan 40-06 SUMMARY DEV-1 + 40-05 SUMMARY DEC-4 (eb6cb09 fold-into-single-commit precedent).
    5. Build D-20 replay commit body per template; write to `/tmp/43-06-replay.txt`. ZERO `Upstream-commit:` trailer; full 5-section body; TWO `Upstream-replayed-from:` lines (0748cced + 5d821c12); 4-condition addendum table inline in commit body per D-43-E1 documentation requirement.
    6. Commit: `git commit -F /tmp/43-06-replay.txt`
    7. Run falsifiable smoke per 43-PATTERNS.md Pattern 2:
       ```
       git log --format='%B' HEAD~1..HEAD | grep -c '^Upstream-commit: '             # MUST be 0
       git log --format='%B' HEAD~1..HEAD | grep -c '^Upstream intent:'              # MUST be 1
       git log --format='%B' HEAD~1..HEAD | grep -c '^What was replayed:'            # MUST be 1
       git log --format='%B' HEAD~1..HEAD | grep -c '^What was NOT replayed'         # MUST be 1
       git log --format='%B' HEAD~1..HEAD | grep -c '^Fork-only wiring preserved:'   # MUST be 1
       git log --format='%B' HEAD~1..HEAD | grep -c '^Upstream-replayed-from: '      # MUST be 2 (0748cced + 5d821c12)
       ```
  </action>
  <acceptance_criteria>
    Branch A (resolved_disposition = will-sync, 2 cherry-picks via W-7 wrapped-transaction):
    - `git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: '` → 2 (one per cherry-pick)
    - Each cherry-pick has 6-line trailer + 1 Co-Authored-By + ≥ 2 Signed-off-by
    - **W-5 fix falsifiable chronological-order check passes:**
      - `[[ "$(git log -1 --format=%B HEAD | grep -E '^Upstream-commit:' | awk '{print $2}')" == "5d821c12" ]]`
      - `[[ "$(git log -1 --format=%B HEAD~1 | grep -E '^Upstream-commit:' | awk '{print $2}')" == "0748cced" ]]`
    - **W-7 fix atomic-landing check passes:** `[[ "$(git log HEAD~2..HEAD --format=%B | grep -c '^Upstream-commit: \(0748cced\|5d821c12\)')" -eq 2 ]]`
    - Cherry-pick state cleanly sealed after BOTH commits: `[[ ! -f .git/CHERRY_PICK_HEAD ]]`

    Branch B (resolved_disposition = fork-preserve, 1 combined replay commit):
    - `git log --format='%B' HEAD~1..HEAD | grep -c '^Upstream-commit: '` → 0
    - 5-section D-20 body all grep counts pass
    - `git log --format='%B' HEAD~1..HEAD | grep -c '^Upstream-replayed-from: '` → 2 (both SHAs cited)

    Both branches:
    - `git diff --name-only <range>..HEAD | grep -cE '_windows\\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 (D-43-E1 — Windows-specific code lives INSIDE platform.rs cross-platform module)
    - REG_DWORD parsing safety: `grep -cE 'unwrap_or_default' crates/nono-cli/src/platform.rs` count UNCHANGED from pre-task or DECREASED (no new unwrap_or_default introductions); `grep -cE 'map_or\\("[^"]*", \\|' crates/nono-cli/src/platform.rs` ≥ 1 (5d821c12's panic-safe pattern present)
    - Unit test added for REG_DWORD parser: `grep -cE 'fn test.*reg_?dword|fn test.*parse.*hex|fn test.*registry.*dword' crates/nono-cli/src/platform.rs` ≥ 1
    - `cargo build --workspace` exits 0
    - `cargo test -p nono-cli` exits 0 (no parsing panics)
    - Phase 36-01b/c invariants preserved: From-impl exhaustive enumeration + bypass_protection rename
  </acceptance_criteria>
  <done>Cluster 4's 2 commits absorbed as a unit per Task 1 `resolved_disposition`; Branch A used W-7 wrapped-transaction with atomic-rollback on partial failure + W-5 falsifiable chronological-order check; D-43-E1 invariant holds (Windows-specific code in cross-platform platform.rs only, NOT in fork's *_windows.rs files); REG_DWORD parsing panic-safe; unit test added; Phase 36-01b/c invariants preserved.</done>
</task>

<task id="3" type="execute" autonomous="true">
  <name>Task 3: Per-plan 8-check close gate (D-43-E9) + Wave 2b baseline-aware CI gate + Phase 43 final close</name>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md
    - .planning/phases/43-upst5-sync-execution/43-05-CLOSE-GATE.md (Wave 2a precedent format)
    - .planning/phases/40-upst4-sync-execution/40-06-FP-PROXY-TLS-SUMMARY.md (close gate section + branch-specific smoke check lines 217-225 — terminal-Wave-2 plan)
  </read_first>
  <action>
    Execute D-43-E9 8-check close gate identical to prior plans. Gates 3+4 LOAD-BEARING (platform.rs has cfg-gated branches across all 3 OSes by this point) per frontmatter `skipped_gates_rationale`.

    Branch-specific smoke per Task 1 `resolved_disposition` (mirror Plan 43-05 Task 3 plus dual-commit verification if Branch A):
    - Branch A (will-sync, 2 cherry-picks): verify D-19 trailer count = 2; each SHA's trailer correct; W-5 chronological-order falsifiable check + W-7 atomic-landing check both pass
    - Branch B (fork-preserve, 1 combined replay): verify 5-section body + 2 `Upstream-replayed-from:` lines + ZERO `Upstream-commit:` trailer

    Plus Plan-43-06-specific verifications:
    - D-43-E1 4-condition addendum compliance: each Windows-specific hunk documented per Task 1's addendum table
    - Fork-only Windows file invariant: `git diff --stat <range>..HEAD -- crates/ | grep -E '_windows|exec_strategy_windows|nono-shell-broker' | wc -l` → 0
    - Cross-phase preservation (carry-forward from Plan 43-05): Phase 18.1 surface (45 grep matches), Phase 36-01b commands enumeration, Phase 36-01c bypass_protection — all unchanged
    - REG_DWORD parsing test passes (this is the bug 5d821c12 fixes; if it fails on Windows host, the cherry-pick is incomplete)

    Record into `.planning/phases/43-upst5-sync-execution/43-06-CLOSE-GATE.md`. Per-job CI table; baseline = `13cc0628`; zero green→red transitions required.

    Phase 43 final close-out activities (since Plan 43-06 is the terminal plan per D-43-A3 Wave 2b):
    - Verify all 6 plans complete: list `.planning/phases/43-upst5-sync-execution/43-*-SUMMARY.md` should return 6 files (43-01 through 43-06)
    - Cross-check umbrella PR body contains all 6 contribution sections (43-01..43-06): `gh pr view <pr-number> --json body -q .body | grep -cE '^## Plan 43-0[1-6] — '` → 6
    - Won't-sync handling (D-43-D1): per Phase 40 D-40-D1 pointer-only rationale, document Cluster 6 macOS lint inline in 43-SUMMARY.md (the Phase 43 close-out summary that the orchestrator authors separately from this Plan 43-06 SUMMARY). Plan 43-06 Task 4 SUMMARY notes "won't-sync cluster 6 inline section is Phase 43 close-out scope, not Plan 43-06 scope".
  </action>
  <acceptance_criteria>
    - Gates 1, 2, 5 exit 0 on Windows host
    - Gates 3, 4 either exit 0 OR `skipped_gates_load_bearing: [3, 4]` per checklist § PARTIAL Disposition (rationale in frontmatter)
    - Gates 6, 7, 8 either pass (Windows host gates 7+8 SHOULD run for Plan 43-06 specifically — Cluster 4 introduces Windows registry parsing that NEEDS Windows runtime to verify) OR `skipped_gates_environmental: [6, 7, 8]` (rationale in frontmatter notes the "SHOULD run on Windows host" preference)
    - Baseline CI gate: zero green→red transitions vs `13cc0628`
    - REG_DWORD parsing unit test passes (Branch A on at least one of the 2 cherry-picks; Branch B on the single replay commit)
    - D-43-E1 invariant verified: 0 fork-only Windows files touched
    - W-5 + W-7 falsifiable acceptance pass (Branch A only)
    - All 6 plan SUMMARYs exist in `.planning/phases/43-upst5-sync-execution/`
    - `.planning/phases/43-upst5-sync-execution/43-06-CLOSE-GATE.md` exists
  </acceptance_criteria>
  <done>Close gate + branch-specific smoke + 4-condition addendum compliance + W-5/W-7 falsifiable checks verified; baseline CI clean; Phase 43 terminal plan complete; all 6 plans' SUMMARYs accounted for.</done>
</task>

<task id="4" type="execute" autonomous="true">
  <name>Task 4: Append Plan 43-06 contribution section + Write SUMMARY.md + Phase 43 close marker</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt
    - .planning/phases/40-upst4-sync-execution/40-06-FP-PROXY-TLS-SUMMARY.md (PRIMARY SUMMARY skeleton — terminal Wave 2 plan SUMMARY shape)
    - All Tasks 1-3 artifacts
  </read_first>
  <action>
    1. Write `.planning/phases/43-upst5-sync-execution/43-06-PR-SECTION.md`:
       ```markdown
       ## Plan 43-06 — Cluster 4 Windows platform detection (registry queries + REG_DWORD fix)

       **Cluster:** 4 (Windows platform detection — 2 upstream commits as a unit: 0748cced robust Windows registry parsing + 5d821c12 REG_DWORD parsing fix)
       **Disposition:** <CANONICAL FROM TASK 1 VERDICT (resolved_disposition), CONSTRAINED BY PLAN 43-05 resolved_disposition: will-sync | fork-preserve>
       **Upstream commits:** 0748cced, 5d821c12 (landed as a unit per Phase 42 ledger Cluster 4 rationale via W-7 wrapped-transaction script with atomic-rollback on partial failure)
       **Files touched:** crates/nono-cli/src/platform.rs (Windows branch extended with registry parsing + REG_DWORD fix INSIDE cross-platform module; NOT in fork's *_windows.rs files per D-43-E1) + <profile/mod.rs WhenPredicate extension if 0748cced touched it and not deferred> + <wiring.rs WiringDirective::Skipped if applicable>
       **Key decision:** D-43-C1 diff-inspection authority applied; resolved_disposition <verdict>, CONSTRAINED by Plan 43-05's resolved_disposition <43-05 verdict>. D-43-E1 4-condition addendum applied per-hunk (table in SUMMARY): Windows-specific code lives INSIDE platform.rs's #[cfg(target_os = "windows")] branch (cross-platform module), NOT in fork's *_windows.rs files. Windows-fallback decision: <Option A uniform behavior | Option B preserve fork path with warning>. REG_DWORD panic-safety preserved via map_or("", |part| part) per 5d821c12 fix. Phase 36-01b/c invariants preserved. W-5 fix chronological-order falsifiable check + W-7 fix atomic-landing wrapped-transaction both passed.
       **CI baseline diff:** zero `success → failure` transitions vs baseline `13cc0628`
       ```
    2. Append to umbrella PR body (executor-mode) or defer to orchestrator (worktree-mode).
    3. Write `.planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md` mirroring Phase 40 Plan 40-06 SUMMARY skeleton verbatim. Critical sections:
       - Frontmatter `resolved_disposition:` matches PLAN.md + Task 1 verdict (CANONICAL value per W-8 fix)
       - "Accomplishments" enumerates `resolved_disposition` resolution + 2-commits-as-unit pattern + W-7 wrapped-transaction execution + W-5 chronological-order verification + 4-condition addendum compliance + Windows-fallback decision (per Phase 40 Plan 40-06 DEC-6) + REG_DWORD panic-safety
       - **D-43-E1 4-condition addendum table** explicit (per-hunk: required-cross-platform-field? cross-platform-default-factory? ≤5-lines-or-exception? documented?)
       - "Decisions Made" cites D-43-C1 + Phase 40 D-40-B1 verdict precedent + Phase 40 Plan 40-06 DEC-6 Windows-fallback Option A/B + W-5 fix + W-7 fix + W-8 fix
       - Per-job CI table per Wave 2b head commit vs baseline `13cc0628`
       - "Next Phase Readiness" section: Phase 43 closes (Plan 43-06 is terminal Wave 2b per D-43-A3); orchestrator handles 43-SUMMARY.md authoring with Cluster 6 won't-sync inline section per D-43-D1
    4. Phase 43 close marker (Plan 43-06 specific — terminal Wave 2b plan): document in SUMMARY that Phase 43 is structurally complete after Plan 43-06 close; ROADMAP.md update + STATE.md update + 43-SUMMARY.md (phase-level) + UPST6 hand-off note are downstream orchestrator scope.
    5. Commit: `git commit -m "docs(43-06): summarize cluster 4 windows-platform-detection per D-43-C1 verdict (Phase 43 terminal plan)" --signoff`
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-06-PR-SECTION.md` exists with verdict-driven disposition line (canonical value) + Windows-fallback decision documented
    - `.planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md` exists
    - SUMMARY frontmatter `resolved_disposition:` matches PLAN.md (CANONICAL value per W-8 fix)
    - SUMMARY contains explicit D-43-E1 4-condition addendum table (per-hunk evidence)
    - SUMMARY documents Windows-fallback decision (Option A or B with audit evidence per Phase 40 Plan 40-06 DEC-6)
    - SUMMARY cites D-43-C1 + Phase 40 D-40-B1 + Phase 40 Plan 40-06 DEC-6 + W-5/W-7/W-8 fixes
    - Phase 43 close marker present (Plan 43-06 is terminal Wave 2b per D-43-A3)
    - `git log -1 --format='%s' HEAD | grep -E '^docs\\(43-06\\):'` matches
    - Verify all 6 PLAN.md + SUMMARY.md pairs present: `ls .planning/phases/43-upst5-sync-execution/43-0[1-6]-*-PLAN.md | wc -l` → 6 AND `ls .planning/phases/43-upst5-sync-execution/43-0[1-6]-*-SUMMARY.md | wc -l` → 6
  </acceptance_criteria>
  <done>Plan 43-06 contribution section captured + SUMMARY.md written + committed; Phase 43 structurally complete; 43-SUMMARY.md + ROADMAP/STATE updates + UPST6 hand-off are downstream orchestrator scope.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Windows registry → fork's platform-detection module | Registry values are partially-controlled input (administrators can modify HKLM); parsing must be panic-safe and bound-checked |
| upstream `0748cced` + `5d821c12` Windows-specific hunks → fork's *_windows.rs / exec_strategy_windows/ / nono-shell-broker/ files (D-43-E1 invariant) | Cluster 4's Windows-specific code MUST land INSIDE platform.rs's #[cfg(target_os = "windows")] branch (cross-platform module), NOT in fork's *_windows.rs files |
| 4-condition addendum per Windows-specific hunk | Each cross-platform addition must verify: (1) consumed by cross-platform caller, (2) cross-platform default factory only, (3) ≤5 lines or documented exception, (4) documented in SUMMARY |
| REG_DWORD parsing → fork's panic-safety discipline (CLAUDE.md § Unwrap Policy) | `unwrap_or_default()` on malformed registry strings = panic; 5d821c12's fix replaces with `map_or("", |part| part)` |
| Plan 43-05 resolved_disposition → Plan 43-06 resolved_disposition (replay-when-foundation-is-also-replayed pattern) | If Plan 43-05 stayed fork-preserve, Plan 43-06 MUST also stay fork-preserve — cannot cherry-pick onto a partial platform.rs replay |
| Partial cherry-pick (0748cced lands without 5d821c12) → fork main with REG_DWORD parsing panic | Without wrapped-transaction rollback, a failure between commits 1 and 2 would leave the fork main with the bug 5d821c12 fixes. W-7 fix mitigation: trap-based rollback on partial failure |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-43-06-01 | DoS | REG_DWORD parsing panic on malformed registry strings (the bug 5d821c12 fixes) | mitigate | Both commits land as a unit per Phase 42 ledger Cluster 4 rationale; landing 0748cced without 5d821c12 leaves the panic on fork main. W-7 fix: wrapped-transaction with `trap ... ERR` rollback prevents partial-landing. Task 2 verifies REG_DWORD parsing test passes after the unit lands; Task 2 acceptance grep verifies `unwrap_or_default` count UNCHANGED or DECREASED and `map_or("", \|part\| part)` pattern ≥ 1 |
| T-43-06-02 | Tampering | fork-only Windows files (*_windows.rs, exec_strategy_windows/, crates/nono-shell-broker/) touched by Cluster 4 (D-43-E1 invariant) | mitigate | Task 1 Q6 catches at audit time; Task 2 step 3 (Branch A) / step 3 (Branch B) verify via grep; Windows-specific code MUST live in platform.rs's #[cfg(target_os = "windows")] branch (cross-platform module). Each Windows-specific hunk audited per D-43-E1 4-condition addendum in Task 1 |
| T-43-06-03 | Tampering | `platform.rs` Windows branch exports collide with broker dispatch's `WindowsTokenArm::BrokerLaunch` decision tree | mitigate | Task 1 Q7 grep returns 0 for `WindowsTokenArm|BrokerLaunch`. Cross-phase invariant per Phase 22 D-17 / Phase 34 D-34-E1 / Phase 40 D-40-E1 / Phase 42 D-42-E7 / D-43-E1 |
| T-43-06-04 | Tampering | Phase 36-01b From-impl exhaustive enumeration regression (silent drop of `commands: raw.commands` OR Plan 43-05's WhenPredicate arm) | mitigate | Task 1 Q2 + Task 2 explicit preservation; Task 3 close-gate verifies via grep |
| T-43-06-05 | Tampering | Phase 36-01c `bypass_protection` rename regression in 0748cced or 5d821c12 | mitigate | Task 1 Q5; Task 2 applies rename arm-by-arm |
| T-43-06-06 | Spoofing | Windows registry contains a forged value that bypasses platform-detection logic | accept | Registry values are HKLM (Local Machine) — modifiable only by Administrators. If an attacker has HKLM write access, they already own the platform-detection trust boundary. Fork's platform-detection is informational (used by WhenPredicate evaluation); it is NOT a privilege boundary. The cross-platform WhenPredicate consumer treats unknown/forged values as no-match per fail-secure |
| T-43-06-07 | Repudiation | Branch A: cherry-pick missing D-19 trailer / Branch B: replay missing 5-section body | mitigate | Task 3 branch-specific smoke verifies; W-5 fix additionally enforces chronological-order falsifiable check (HEAD = 5d821c12, HEAD~1 = 0748cced) |
| T-43-06-08 | Information Disclosure | Windows-specific code mistakenly logs registry values containing PII or machine identifiers | accept | Registry queries are product/version/edition (not user data); upstream's logging matches established `tracing::debug!` patterns per CLAUDE.md § Logging |
| T-43-06-09 | DoS | Windows registry query latency on slow hosts blocks process startup | accept | Same mitigation as Plan 40-04 Landlock ABI cache pattern — detection is one-time at process startup; cache per OnceLock if pattern repeats (defer to follow-up if perf becomes a concern) |
| T-43-06-10 | Tampering | Plan 43-05 resolved_disposition drift → Plan 43-06 attempts upgrade despite Plan 43-05 staying fork-preserve | mitigate | Task 1 step 4 enforces foundation-verdict constraint (replay-when-foundation-is-also-replayed pattern per 43-PATTERNS.md). If foundation resolved_disposition = fork-preserve, Plan 43-06 forced to fork-preserve regardless of Cluster 4's surface analysis |
| T-43-06-11 | DoS | Partial cherry-pick leaves fork main with REG_DWORD parsing bug (0748cced lands, 5d821c12 fails) | mitigate | **W-7 fix:** `<wrapped_transaction_protocol>` Task 2 Branch A wraps both cherry-picks in `trap 'git reset --hard $PRE_TASK_HEAD' ERR; set -e`. Any failure between commits triggers rollback to pre-task HEAD. Pre-flight `git cat-file -e` reachability check prevents starting the transaction with an unreachable SHA |
| T-43-06-12 | Repudiation | Chronological order check is non-falsifiable (the old "newer commit subject in HEAD" check) | mitigate | **W-5 fix:** replaced with explicit trailer-based check: `[[ "$(git log -1 --format=%B HEAD | grep '^Upstream-commit:' | awk '{print $2}')" == "5d821c12" ]]` AND `[[ "$(git log -1 --format=%B HEAD~1 | grep '^Upstream-commit:' | awk '{print $2}')" == "0748cced" ]]`. Falsifiable: if either trailer is missing or in wrong order, the check exits 1 |
| T-43-06-13 | Repudiation | non-canonical disposition value (e.g., `TBD-at-plan-open`) breaks downstream tooling | mitigate | **W-8 fix:** Task 1 step 9 writes canonical value (`will-sync` | `fork-preserve`) into `resolved_disposition:` field; frontmatter `disposition:` stays at conservative `fork-preserve` default |

**ASVS L1 disposition:** `high` threats (T-43-06-01 panic, T-43-06-02 Windows-files invariant, T-43-06-03 broker collision, T-43-06-04 From-impl, T-43-06-11 partial-cherry-pick) — mitigate. `medium` threats (T-43-06-05 rename, T-43-06-07 trailer/body, T-43-06-10 verdict constraint, T-43-06-12 chronological order, T-43-06-13 disposition canonical) — mitigate. `low` threats (T-43-06-06 registry forgery, T-43-06-08 logging, T-43-06-09 perf) — accept. Security gate satisfied.
</threat_model>

<verification>
Per-plan close gate (D-43-E9 = Phase 34 D-34-D2 8-check format):

| Gate | Description | Required | Disposition |
|------|-------------|----------|-------------|
| 1 | `cargo test --workspace --all-features` (Windows host) | required | execute (especially REG_DWORD parsing test) |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | required | execute |
| 3 | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped_gates_load_bearing → CI-verified |
| 4 | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped_gates_load_bearing → CI-verified |
| 5 | `cargo fmt --all -- --check` | required | execute |
| 6 | Phase 15 5-row detached-console smoke | environmental | skipped_gates_environmental |
| 7 | `wfp_port_integration` tests | environmental (Windows-host should run for Plan 43-06 — Cluster 4 is Windows-specific) | execute if possible OR skipped_gates_environmental |
| 8 | `learn_windows_integration` tests | environmental (Windows-host should run for Plan 43-06) | execute if possible OR skipped_gates_environmental |

Branch-specific smoke per Task 1 `resolved_disposition` (Branch A = 2 cherry-picks via W-7 wrapped-transaction + W-5 chronological-order check; Branch B = 1 combined replay).

D-43-E1 4-condition addendum compliance per Windows-specific hunk (Task 1 audit table).

Wave 2b baseline-aware CI gate: zero `success → failure` lane transitions vs baseline SHA `13cc0628` per D-43-E3.

Phase 43 terminal-plan additional verifications:
- All 6 PLAN.md + 6 SUMMARY.md pairs present (Task 4)
- Umbrella PR body contains 6 contribution sections (one per plan)
</verification>

<success_criteria>
- Plan 43-05 dependency honored (`crates/nono-cli/src/platform.rs` exists pre-Plan-43-06)
- Task 1 diff-inspection verdict CONSTRAINED by Plan 43-05 resolved_disposition; recorded in PLAN.md + SUMMARY.md frontmatter `resolved_disposition:` field via CANONICAL value per W-8 fix + docs-only commit
- W-7 fix SHA reachability pre-flight passed: both 0748cced + 5d821c12 confirmed reachable before Task 2
- BOTH commits 0748cced + 5d821c12 land as a unit (Branch A: 2 cherry-picks via W-7 wrapped-transaction with rollback-on-partial-failure; Branch B: 1 combined replay)
- W-5 fix falsifiable chronological-order check passed: HEAD's Upstream-commit = 5d821c12, HEAD~1's = 0748cced
- D-43-E1 invariant holds (0 fork-only Windows-file touches); Windows-specific code in platform.rs cross-platform module only
- D-43-E1 4-condition addendum applied per-hunk + documented in SUMMARY
- REG_DWORD parsing panic-safety preserved (no `unwrap_or_default` introductions; `map_or("", |part| part)` pattern present; unit test passes)
- Phase 36-01b/c invariants preserved (From-impl exhaustive enumeration + bypass_protection rename)
- Windows-fallback decision (Option A or B) documented per Phase 40 Plan 40-06 DEC-6 pattern
- D-43-E9 8-check close gate + branch-specific smoke + W-5/W-7 falsifiable checks clean
- Wave 2b baseline-aware CI gate: zero green→red transitions vs `13cc0628`
- Plan 43-06 contribution section appended to Phase 43 umbrella PR
- All 6 plan SUMMARYs present
- SUMMARY.md committed; Plan 43-06 is Phase 43 terminal plan; 43-SUMMARY.md (phase-close) + ROADMAP/STATE updates + UPST6 hand-off are downstream orchestrator scope
- REQ-UPST5-02 acceptance criteria #2 + #3 + #5 advanced for Cluster 4 (windows-touch:yes cluster handled per audit disposition; PR umbrella complete with all 6 contribution sections)
</success_criteria>

<output>
After completion, create `.planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md` per Task 4 specification.
</output>
</output>
