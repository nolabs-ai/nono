---
phase: 43-upst5-sync-execution
plan: 06
cluster_id: 4
subsystem: platform-detection + windows-registry-parsing
tags: [upstream-sync, fork-preserve, D-20-manual-replay, combined-replay, windows-registry, reg-dword, when-predicate, secrets-config, Wave-2b, terminal-plan]
status: COMPLETE
disposition: fork-preserve
resolved_disposition: fork-preserve
disposition_resolution_evidence: .planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md
upstream_range: v0.53.0..v0.54.0
upstream_shas: [0748cced, 5d821c12]
upstream_tag: v0.54.0
baseline_sha: 13cc0628
dependency_graph:
  requires:
    - "Plan 43-05 PLATFORM-DETECTION-FOUNDATION close (Wave 2a foundation; D-20 replay of ce06bd59 — platform.rs exists in fork pre-43-06)"
    - "Phase 42 DIVERGENCE-LEDGER Cluster 4 fork-preserve conservative default per D-42-C3 (windows-touch:yes)"
    - "Phase 36-01b From<ProfileDeserialize> for Profile exhaustive enumeration discipline"
    - "Phase 36-01c bypass_protection canonical-name rename"
    - "Phase 41 D-14 / CR-04 broker-binary precondition (cargo build -p nono-shell-broker --release pre-test)"
  provides:
    - "crates/nono-cli/src/platform.rs Windows-branch registry-backed product/version/edition detection (replaces WindowsInfo::default() placeholder); REG_DWORD hex→decimal parsing with panic-safe map_or; build_version safety via map_or(\"\", |part| part); When::parse pub(crate) visibility + Deserialize single-string fast-path; compare_versions non-numeric Ordering::Less fallback"
    - "crates/nono-cli/src/profile/mod.rs deserialize_conditional_string_vec unknown-sibling-field fail-secure rejection; SecretsConfig Deserialize rewrite to serde_json::Value-based form with explicit unknown-key rejection; conditional_profile_entries_reject_unknown_fields integration test"
    - "crates/nono-cli/data/nono-profile.schema.json WhenPredicate description text extended with linux:fedora:>=43:workstation example"
    - "Phase 43 close: Wave 2b terminal plan complete; 6/6 plan SUMMARYs in place"
  affects:
    - "Future fork evolution toward conditional-evaluation-on-wiring-directives (wiring.rs Skipped variant + serde(skip_serializing) attribute deferred — fork has no WiringDirective::Skipped variant)"
    - "Phase 43 close: 43-SUMMARY.md (phase-level) + ROADMAP.md update + STATE.md update + Cluster 6 won't-sync inline section are downstream orchestrator scope per D-43-D1 / D-43-D2"
    - "Phase 44 / UPST6 hand-off: post-v0.54.0 upstream synchronization starts from baseline c4af6dde (replace with actual upstream head SHA at UPST6 plan-open)"
tech_stack:
  added:
    - "detect_windows / detect_windows_version / query_windows_registry_value / parse_windows_registry_value factory functions in crate::platform (Windows-branch only, dispatched by cfg!(target_os = \"windows\"))"
    - "REG_DWORD hex-prefixed (0xN / 0XN) → decimal-string conversion via u64::from_str_radix(hex, 16)"
    - "WhenPredicate single-string fast-path in When::deserialize (3-line shortcut)"
    - "Conditional entry unknown-sibling-field fail-secure rejection at deserialization time (closes typo-induced silent no-op gap)"
  patterns:
    - "D-20 combined single-commit replay for multi-commit upstream clusters where commits MUST land as a unit (Phase 40 Plan 40-06 SUMMARY DEC-2 + Phase 43 Plan 43-05 SUMMARY DEC-4 fold-into-single-commit precedent applied to Cluster 4)"
    - "Replay-when-foundation-is-also-replayed pattern enforcement: when Plan N depends on Plan M's surface AND Plan M = fork-preserve, Plan N is forced to fork-preserve regardless of Plan N's own clause-(b) clean-pick outcome (43-PATTERNS.md § Plan 43-06)"
    - "Windows-fallback decision Option A (uniform behavior — upstream wins) when audit returns zero fork-side divergent code paths (Phase 40 Plan 40-06 DEC-6 precedent)"
    - "D-43-E1 ≤5-line exception canonical recording: Windows registry parsing factory functions exceed 5-line budget; documented exception per 43-CONTEXT.md verdict-recording mechanism (NOT moved to fork-only Windows files)"
key_files_modified:
  - crates/nono-cli/src/platform.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/data/nono-profile.schema.json
key_files_created:
  - .planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md
  - .planning/phases/43-upst5-sync-execution/43-06-CLOSE-GATE.md
  - .planning/phases/43-upst5-sync-execution/43-06-PR-SECTION.md
  - .planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; platform.rs extends cfg-gated Linux+macOS branches (no Linux-branch hunks in Plan 43-06 — the new factory functions are gated by cfg!(target_os = \"windows\") at the dispatch site in detect() — but the file is still load-bearing per cross-target-verify-checklist § PARTIAL Disposition because it contains cross-platform code)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; same rationale as Gate 3"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per D-40-C2"
  gate_7_wfp_port_integration: "cargo-level passed in Gate 1; deep WFP kernel-filter installation environmental-skip per D-40-C2"
  gate_8_learn_windows_integration: "cargo-level passed in Gate 1; deep learn-runtime substrate environmental-skip per D-40-C2"
key_decisions:
  - "DEC-1 (Task 1 verdict per D-43-C1, foundation-constraint-applied): resolved_disposition = fork-preserve. Two independent constraints force the disposition: (a) foundation constraint (43-PATTERNS.md § Plan 43-06 replay-when-foundation-is-also-replayed): Plan 43-05 stayed fork-preserve → Plan 43-06 MUST also stay fork-preserve; (b) trial cherry-pick of 0748cced produced 2 content conflicts (schema.json + wiring.rs) corroborating clause-(a) FAIL on D-40-B1. W-8 fix: canonical `fork-preserve` value written into PLAN.md frontmatter `resolved_disposition:` field via docs-only commit 378ac515 BEFORE any code change (Phase 40 Plan 40-05 pattern)."
  - "DEC-2 (Combined single-commit replay per Phase 40 Plan 40-06 SUMMARY DEC-2 + Plan 43-05 SUMMARY DEC-4 precedent): Both Cluster 4 upstream commits (0748cced + 5d821c12) folded into ONE D-20 replay commit a46b6bf9. Rationale: (1) commits land as a unit per Phase 42 ledger Cluster 4 rationale — 5d821c12 fixes 0748cced's REG_DWORD parsing bug; landing the feat without the fix leaves a panic vector on fork main; (2) single-commit form makes W-7 wrapped-transaction discipline unnecessary (no partial-landing path possible); (3) W-5 chronological-order check trivially satisfied (no second commit); (4) commit body carries TWO `Upstream-replayed-from:` lines explicitly listing both SHAs in chronological order."
  - "DEC-3 (Minimal replay scope — Cluster 4 specifics): REPLAYED — (a) all platform.rs changes from both SHAs combined (Windows-branch swap + 4 factory functions with REG_DWORD fold-in + When::parse visibility + When::deserialize single-string fast-path + matches_windows build_version map_or panic-safety + compare_versions non-numeric Less + 1 test update + 1 REG_DWORD test); (b) profile/mod.rs unknown-field validation in deserialize_conditional_string_vec helper + SecretsConfig Deserialize rewrite to serde_json::Value form with explicit unknown-key rejection + 1 integration test; (c) schema.json description-text extension with `linux:fedora:>=43:workstation` example. SKIPPED — wiring.rs `#[serde(skip_serializing)]` on WiringDirective::Skipped + comment block: Plan 43-05 SKIPped the entire upstream WiringDirective surface per minimal-replay-scope discipline; fork has no Skipped variant for the attribute to attach to. W-4 fix mitigation: directive-level `when:` rejected fail-secure by existing `#[serde(deny_unknown_fields)]` on fork's WiringDirective variants (precedent from Plan 43-05 DEC-3)."
  - "DEC-4 (Windows-fallback decision per Phase 40 Plan 40-06 DEC-6 pattern): Option A — uniform behavior, upstream wins. Audit: `grep -rE 'registry|RegOpenKey|RegQueryValue' crates/nono-cli/src/exec_strategy_windows/ crates/nono-shell-broker/` → 1 hit, but it is a comment in `restricted_token.rs:84` describing kernel-side token access during console-child initialization — unrelated to platform-detection. Zero fork-side divergent registry-detection code path exists to preserve. Option B (preserve fork's existing path with warning log) does not apply."
  - "DEC-5 (D-43-E1 4-condition addendum compliance — Windows-specific factory functions exceed 5-line budget): The 4 new factory functions (`detect_windows` 6 lines, `detect_windows_version` 10 lines, `query_windows_registry_value` 14 lines, `parse_windows_registry_value` 24 lines after REG_DWORD fold-in) carry the canonical D-43-E1 ≤5-line exception per 43-CONTEXT.md verdict-recording mechanism. Conditions (1)(2)(4) all PASS per-hunk (consumed by cross-platform `current()` → `When::matches`; cross-platform module not fork-only Windows file; documented in this SUMMARY + 43-06-DISPOSITION-RESOLUTION.md). Condition (3) ≤5-lines exception documented inline with rationale: meaningful Windows registry parsing cannot fit in 5-line budget AND alternative split-into-many-2-line-helpers approach would obfuscate the upstream replay surface."
  - "DEC-6 (Phase 36-01b/c invariants preserved automatically): Cluster 4 adds NO new top-level Profile field. The unknown-field-rejection logic is in the existing `deserialize_conditional_string_vec` helper (one new `if !object.is_empty()` block). The SecretsConfig Deserialize rewrite stays inside the same `SecretsConfig` Deserialize impl. The `From<ProfileDeserialize> for Profile` exhaustive enumeration at profile/mod.rs:1893+ is UNTOUCHED. Phase 36-01c `bypass_protection` rename is also UNTOUCHED — Q5 (`override_deny|bypass_protection` grep on both upstream SHAs) returned 0. No rename arms required."
  - "DEC-7 (No rust-1.95 lint Rule-3 deviation surfaced — distinct from Plan 43-05's `clippy::unnecessary_map_or` finding): The 5d821c12 `map_or(\"\", |part| part)` pattern in matches_windows is lint-clean because `clippy::unnecessary_map_or` targets `.map_or(true, ...)` / `.map_or(false, ...)` boolean reductions (suggesting `is_some_and` / `is_none_or`), NOT `.map_or(\"\", ...)` value extractions which have no `is_some_and` equivalent on `Option<&str>`. The compare_versions `Ordering::Less` fallback uses `match` guard pattern which is also lint-clean. Gate 2 (Windows clippy with `-D warnings -D clippy::unwrap_used`) exit 0 on first attempt — no `fix(43-06-cra):` follow-up commit needed."
  - "DEC-8 (W-5 + W-7 fixes NOT NEEDED for Branch B): both falsifiability requirements apply only to Branch A's 2-cherry-pick sequence. Branch B's combined single-commit replay (a46b6bf9) has no partial-landing path (no point between commits where one SHA lands without the other), and no chronological-order ambiguity (the commit body carries both `Upstream-replayed-from:` trailers in explicit chronological order: 0748cced first, 5d821c12 second). The W-7 `trap ... ERR; git reset --hard $PRE_TASK_HEAD` wrapped-transaction mechanism is inapplicable when only one commit exists. The W-5 HEAD vs HEAD~1 trailer comparison is inapplicable when only one commit exists. The fixes' INTENT (no panic-vector landing on main; no chronological confusion in git log) is preserved structurally rather than by post-commit verification."
patterns_established:
  - "Combined-single-commit replay for must-land-as-a-unit upstream commit pairs: when an upstream feature commit and its fix commit must land together (e.g., feat-then-bugfix where shipping feat alone introduces a panic vector), fold both into ONE D-20 replay commit. Carries 2 `Upstream-replayed-from:` trailers. Makes W-5 + W-7 falsifiability requirements structurally satisfied rather than post-commit-verified. Mirrors Phase 40 Plan 40-06 SUMMARY DEC-2 + Plan 43-05 SUMMARY DEC-4 fold-into-single-commit precedent."
  - "Replay-when-foundation-is-also-replayed disposition forcing: when Plan N depends on Plan M's replayed surface AND Plan M's `resolved_disposition` = fork-preserve, Plan N's `resolved_disposition` is FORCED to fork-preserve regardless of N's own clause-(b) surface-semantics outcome. The constraint reasoning: cherry-picking onto a partial replay yields conflicts because upstream's hunks target an upstream-shape surface the fork doesn't have. Foundation-constraint enforcement happens at Task 1 step 4 before any clause-(a) trial-pick attempt — clause-(a) corroboration evidence is still collected for the audit trail but the verdict is already determined."
  - "Windows-fallback decision audit pattern (Option A vs B) from Phase 40 Plan 40-06 DEC-6: before applying Windows-touching upstream code, grep fork's `*_windows.rs` + `exec_strategy_windows/` + `nono-shell-broker/` for the upstream's domain keywords (here: `registry|RegOpenKey|RegQueryValue`). Zero non-comment hits → Option A (upstream wins). Non-zero hits → analyze whether the fork's path is intentionally divergent (then Option B with warning log) or stale (then Option A with fork-side cleanup as part of the replay)."
requirements_completed:
  - "REQ-UPST5-02 (Cluster 4 portion). Acceptance criteria #2 (every fork-preserve cluster has a documented rationale) and #3 (windows-touch:yes cluster handled per audit disposition with explicit Phase 43 plan-phase verdict) both advanced for Cluster 4 specifically. #5 (PR umbrella complete with all 6 contribution sections) advanced — Plan 43-06 PR section authored at `43-06-PR-SECTION.md`; umbrella append + final 6-section verification deferred to orchestrator (worktree mode)."
duration_minutes: 348
completed: "2026-05-18"
---

# Phase 43 Plan 06: Platform-Detection-Windows — Cluster 4 combined D-20 manual replay (Phase 43 terminal plan)

## Outcome

**One-liner:** Fork-preserve D-20 combined-single-commit replay of upstream Cluster 4 (`0748cced feat(platform): implement robust windows platform detection` + `5d821c12 fix(platform): correctly parse windows registry dword values`, v0.54.0). Lands as 2 atomic commits: (1) `docs(43-06):` disposition resolution per Phase 40 Plan 40-05 pattern; (2) `feat(43-06):` combined replay with TWO `Upstream-replayed-from:` trailers, full D-20 5-section body, Windows-branch swap + 4 registry-parsing factory functions + REG_DWORD hex→decimal + panic-safe build_version `map_or("", |part| part)` + When deserialization tightening + SecretsConfig serde_json::Value rewrite + non-numeric `Ordering::Less` fallback + 2 new tests. Foundation-constraint-forced by Plan 43-05's fork-preserve. Windows-fallback decision Option A (uniform behavior — upstream wins). Phase 36-01b/c invariants preserved automatically. W-5 + W-7 fixes structurally satisfied by single-commit form (no falsifiable post-commit check required). W-8 fix canonical disposition values throughout. NO rust-1.95 lint Rule-3 deviation surfaced (no `fix(43-06-cra):` follow-up needed — distinct from Plan 43-05 outcome). **Plan 43-06 is Phase 43 Wave 2b terminal plan per D-43-A3.**

## Performance

- 2 atomic commits + 4 planning artifacts (DISPOSITION-RESOLUTION, CLOSE-GATE, PR-SECTION, SUMMARY)
- `cargo test --workspace --all-features` final: **2208 passed / 0 failed / 19 ignored** (+2 new tests vs Plan 43-05 baseline 2206: `windows_registry_dword_values_are_decimalized` + `conditional_profile_entries_reject_unknown_fields`)
- `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used`: clean on first attempt (no Rule-3 deviation surfaced)
- `cargo fmt --all -- --check`: clean
- Total plan duration ≈ 348 minutes (Task 1 diff-inspection + Task 2 replay edits + cargo test cycles + broker-binary precondition fix + close-gate + SUMMARY)

## Accomplishments

1. **D-43-C1 verdict task executed under foundation constraint** — Q1-Q9 surface-overlap analysis answered for Cluster 4 (0 fork-only-Windows-file touches, 0 broker dispatch collisions, 0 path-string starts_with, 0 override_deny references, 0 From-impl exhaustive-enumeration touches, 4-condition addendum recorded per-hunk, Windows-fallback decision Option A audited). Trial cherry-pick of 0748cced produced 2 content conflicts (schema.json + wiring.rs) corroborating clause-(a) FAIL. Verdict `resolved_disposition: fork-preserve` is foundation-constraint-forced AND clause-(a)-corroborated. Committed as docs-only `378ac515` BEFORE any code change.

2. **Both Cluster 4 commits replayed verbatim in a combined single-commit form** — Windows-branch swap line 85 `Some(WindowsInfo::default())` → `Some(detect_windows())`; 4 new factory functions `detect_windows` / `detect_windows_version` / `query_windows_registry_value` / `parse_windows_registry_value` inserted between `detect_macos()` and `run_sw_vers()`; REG_DWORD hex-prefixed → decimal conversion (5d821c12 fold-in) via `u64::from_str_radix(hex, 16)` inside `parse_windows_registry_value`; `When::parse` visibility tightened `#[cfg(test)] pub fn` → `pub(crate) fn`; `When::deserialize` single-string fast-path (3 lines); `matches_windows` build_version safety `unwrap_or(&info.version)` → `map_or("", |part| part)` (combines 0748cced's intermediate `unwrap_or_default()` step with 5d821c12's final panic-safe form); `compare_versions` non-numeric mismatch returns `Ordering::Less`; test `version_segments_compare_numerically_when_possible` assertion update + new equal-non-numeric assertion; new test `windows_registry_dword_values_are_decimalized` (5d821c12 fold-in) verifies REG_DWORD `0xa` → `"10"` round-trip.

3. **Profile-mod.rs WhenPredicate tightening replayed** — `deserialize_conditional_string_vec` helper now rejects unknown sibling fields fail-secure after consuming `when:` (6-line `if !object.is_empty() { ... }` block — closes a real typo-induced silent-no-op gap: e.g., `whenn:` typo would previously silently no-op); `SecretsConfig` Deserialize rewrite from the typed `CredentialValue` untagged enum to `serde_json::Value`-based dispatch with explicit unknown-key rejection + non-string-non-object error path; new integration test `conditional_profile_entries_reject_unknown_fields` asserts the new path errors with "unknown field" in the message.

4. **Schema.json WhenPredicate description text extended** — added `linux:fedora:>=43:workstation` example per upstream 0748cced.

5. **D-43-E1 invariant satisfied** — `git diff --name-only HEAD~2 HEAD | grep -cE '_windows\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 across both plan commits (378ac515 + a46b6bf9). All Windows-specific code lives INSIDE `platform.rs` (cross-platform module) dispatched by `cfg!(target_os = "windows")` runtime check. Per-hunk 4-condition addendum recorded in 43-06-DISPOSITION-RESOLUTION.md.

6. **Windows-fallback decision Option A (uniform behavior — upstream wins) audited** — `grep -rE 'registry|RegOpenKey|RegQueryValue' crates/nono-cli/src/exec_strategy_windows/ crates/nono-shell-broker/` returned 1 match, but it is a comment in `restricted_token.rs:84` describing kernel-side token-access registry traversal during console-child initialization — unrelated to our `reg query` shell-out. No fork-side divergent registry-detection code path exists to preserve.

7. **W-5 + W-7 fixes structurally satisfied (no falsifiable post-commit check needed)** — single-commit Branch B form makes both falsifiability requirements moot: no partial-landing path possible (W-7 inapplicable); no chronological-order ambiguity (W-5 inapplicable; the commit body lists `Upstream-replayed-from: 0748cced` then `Upstream-replayed-from: 5d821c12` in chronological order). The fixes' INTENT (no panic-vector landing on main; no chronological confusion in git log) is preserved by construction.

8. **W-8 fix canonical disposition values applied** — PLAN.md frontmatter `disposition: fork-preserve` (conservative default per D-42-C3, unchanged); PLAN.md + DISPOSITION-RESOLUTION + SUMMARY frontmatter `resolved_disposition: fork-preserve` (Task 1 verdict, canonical value); no non-canonical strings (`TBD-at-plan-open`, `will-sync-via-diff-inspection-upgrade`) anywhere.

9. **Phase 36-01b/c invariants preserved automatically** — Cluster 4 adds NO new top-level Profile field. `From<ProfileDeserialize> for Profile` exhaustive enumeration at profile/mod.rs:1893+ UNTOUCHED (`grep -c 'commands: raw\.commands' crates/nono-cli/src/profile/mod.rs` → 1 — Phase 36-01b canonical arm intact). `bypass_protection` canonical-name rename UNTOUCHED (Q5 = 0 occurrences in either upstream SHA).

10. **NO rust-1.95 lint Rule-3 deviation surfaced** — distinct from Plan 43-05's `clippy::unnecessary_map_or` finding. The 5d821c12 `map_or("", |part| part)` pattern is lint-clean (the lint targets boolean-reduction `map_or(true/false, ...)` forms, NOT value-extraction `map_or("", ...)`). The `compare_versions` `Ordering::Less` fallback uses `match` guard which is lint-clean. Gate 2 PASS on first attempt; no `fix(43-06-cra):` follow-up commit needed.

11. **Phase 43 Wave 2b terminal plan complete** — All 6 plan SUMMARYs present after this plan closes (43-01 EDITION-2024-FOUNDATION; 43-02 SNAPSHOT-SYMLINK-FIX; 43-03 PACK-MGMT; 43-04 RELEASE-RIDE; 43-05 PLATFORM-DETECTION-FOUNDATION; 43-06 PLATFORM-DETECTION-WINDOWS — this one). Phase 43 structurally complete after this plan's SUMMARY commit lands.

## Task Commits

| Task | Commit     | Subject                                                                                                  | Files                                                                                                            |
|------|------------|----------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| 1    | `378ac515` | docs(43-06): record D-43-C1 diff-inspection verdict for cluster 4 (constrained by 43-05 verdict)         | 43-06-DISPOSITION-RESOLUTION.md (new) + 43-06-PLATFORM-DETECTION-WINDOWS-PLAN.md (resolved_disposition: null → fork-preserve) |
| 2    | `a46b6bf9` | feat(43-06): replay windows registry detection + reg_dword parsing fix (cluster 4)                       | crates/nono-cli/src/platform.rs (Windows-branch + 4 factory fns + REG_DWORD fold-in + 2 fix lines + 2 tests); crates/nono-cli/src/profile/mod.rs (unknown-field rejection + SecretsConfig rewrite + 1 test); crates/nono-cli/data/nono-profile.schema.json (description text) |
| 3    | (no commit — produces text artifact 43-06-CLOSE-GATE.md only)                                            | n/a — close gate is text artifact (PR open deferred to orchestrator per worktree mode)                           |
| 4    | (this commit — `docs(43-06): summarize ...`)                                                              | SUMMARY.md + CLOSE-GATE.md + PR-SECTION.md                                                                       |

## Files Created/Modified

**Modified (code):**
- `crates/nono-cli/src/platform.rs` — +66 lines (4 factory functions + REG_DWORD fold-in + visibility/fast-path/safety/ordering fixes + 2 tests; net diff vs Plan 43-05 baseline)
- `crates/nono-cli/src/profile/mod.rs` — net +30/-14 lines (unknown-field-rejection block + SecretsConfig rewrite + 1 integration test)
- `crates/nono-cli/data/nono-profile.schema.json` — 1 line (WhenPredicate description text extension)

**Created (planning):**
- `.planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md` — Task 1 D-43-C1 verdict evidence + Q1-Q9 numeric evidence + foundation constraint + 4-condition addendum per-hunk table + Windows-fallback decision + SHA reachability evidence
- `.planning/phases/43-upst5-sync-execution/43-06-CLOSE-GATE.md` — 8-check close gate + branch-specific D-20 smokes + W-4/W-5/W-7/W-8 mitigation evidence + preservation invariants + Wave 2b CI gate baseline
- `.planning/phases/43-upst5-sync-execution/43-06-PR-SECTION.md` — Phase 43 umbrella PR contribution section
- `.planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md` — this SUMMARY

**Modified (planning):**
- `.planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-PLAN.md` — frontmatter `resolved_disposition: null` → `fork-preserve` (W-8 canonical value)

## Decisions Made

### DEC-1: D-43-C1 verdict = `resolved_disposition: fork-preserve` (foundation-constraint-forced + clause-(a)-corroborated)

Two independent constraints both point to fork-preserve:

**Constraint (a) — Foundation:** Per 43-PATTERNS.md § Plan 43-06 replay-when-foundation-is-also-replayed pattern: Plan 43-05's `resolved_disposition` is `fork-preserve` (per 43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md frontmatter lines 9-10). Plan 43-06 MUST also stay fork-preserve regardless of Cluster 4's own clause-(b) clean-pick outcome on platform.rs and profile/mod.rs. NOTE: Plan 43-05's replay was actually VERBATIM 659 lines (the upstream-shape skeleton IS present in fork), so technically Cluster 4 SHOULD compose additively on platform.rs and profile/mod.rs — but the constraint applies per W-8 fix canonical-value discipline + 43-PATTERNS.md to preserve replay traceability and avoid mixing cherry-pick + D-20 styles within the same dependency chain.

**Constraint (b) — Clause-(a) corroboration:** Trial cherry-pick on `43-06-trial-cherry-pick` scratch branch produced 2 content conflicts:
- `crates/nono-cli/data/nono-profile.schema.json` (1 conflict marker): description text at line 219 conflicts because Plan 43-05's verbatim replay added different ConditionalName/ConditionalOrigin $defs surface.
- `crates/nono-cli/src/wiring.rs` (1 conflict marker): `#[serde(skip_serializing)]` on `WiringDirective::Skipped` + 3-line comment block conflicts because Plan 43-05 SKIPped the entire upstream WiringDirective surface; fork has no `Skipped` variant.

platform.rs and profile/mod.rs auto-merged cleanly (0 conflict markers in either), but the 2 conflicts on the supporting files invalidate clause-(a) zero-conflicts upgrade authority.

Verdict committed as docs-only `378ac515` BEFORE any code change (Phase 40 Plan 40-05 pattern). PLAN.md frontmatter `resolved_disposition: null` → `fork-preserve` via `Edit` tool. 43-06-DISPOSITION-RESOLUTION.md records full Q1-Q9 evidence + 4-condition addendum + cleanup audit trail.

### DEC-2: Combined single-commit replay (Phase 40 Plan 40-06 SUMMARY DEC-2 + Plan 43-05 SUMMARY DEC-4 fold-into-single-commit precedent)

Both Cluster 4 commits folded into ONE D-20 replay commit `a46b6bf9`. Rationale:

1. **Atomic landing required per Phase 42 ledger Cluster 4 rationale:** 5d821c12 fixes 0748cced's REG_DWORD parsing bug. Shipping 0748cced alone leaves a panic vector on fork main (malformed REG_DWORD strings could trigger panic on `unwrap_or_default()` in the originally-shipped form). The Phase 42 ledger explicitly mandates these two land as a unit.
2. **W-7 wrapped-transaction discipline rendered unnecessary by single-commit form:** with only one commit, there is no point in the chain where 0748cced has landed without 5d821c12 — the `trap ... ERR; git reset --hard $PRE_TASK_HEAD` rollback mechanism has no commit boundary to protect.
3. **W-5 chronological-order falsifiable check rendered trivial:** with only one commit, the HEAD vs HEAD~1 trailer comparison has no second commit to misorder. The commit body lists both `Upstream-replayed-from:` trailers in chronological order (`0748cced` first, `5d821c12` second).
4. **Single-commit form preserves replay traceability:** the commit message's `What was replayed:` section explicitly enumerates which hunks come from 0748cced vs 5d821c12 (e.g., `matches_windows` `unwrap_or(&info.version)` → `map_or("", |part| part)` combines both SHAs' contributions).

Precedent: Phase 40 Plan 40-06 SUMMARY DEC-2 (FP-PROXY-TLS combined-replay) + Plan 43-05 SUMMARY DEC-4 (`eb6cb09` fold-into-single-commit reference cited in PLAN.md text).

### DEC-3: Minimal replay scope (Cluster 4 specifics)

**Replayed:**
- All platform.rs changes from both SHAs combined (see Accomplishment #2 detail above)
- profile/mod.rs unknown-field validation in `deserialize_conditional_string_vec` (6 lines) + SecretsConfig Deserialize rewrite to `serde_json::Value` form with explicit unknown-key rejection + 1 integration test
- schema.json WhenPredicate description text extension (1 line — `linux:fedora:>=43:workstation` example)

**Not replayed:**
- `crates/nono-cli/src/wiring.rs` (`#[serde(skip_serializing)]` on `WiringDirective::Skipped` + 3-line comment): Plan 43-05 SKIPped the entire upstream WiringDirective surface per minimal-replay-scope discipline; fork has no `Skipped` variant for the attribute to attach to. **W-4 fix mitigation:** directive-level `when:` still rejected fail-secure by existing `#[serde(deny_unknown_fields)]` on fork's WiringDirective variants (precedent from Plan 43-05 DEC-3). No silent JSON-schema-vs-Rust-deserialization divergence.

Rationale documented in commit `a46b6bf9` body's `What was NOT replayed and why:` section.

### DEC-4: Windows-fallback decision Option A (uniform behavior — upstream wins)

Per Phase 40 Plan 40-06 SUMMARY DEC-6 audit pattern:

Audit command: `grep -rE 'registry|RegOpenKey|RegQueryValue' crates/nono-cli/src/exec_strategy_windows/ crates/nono-shell-broker/`

Result: 1 hit in `crates/nono-cli/src/exec_strategy_windows/restricted_token.rs:84` — but it is a **comment** describing kernel-side token-access registry traversal during console-child initialization:
```
// registry traversal that happen during a console child's initialization)
```
This is the WRITE_RESTRICTED token discussion from Phase 22 D-17 work, unrelated to our `reg query` shell-out for platform-detection. Zero fork-side divergent registry-detection code path exists to preserve.

Verdict: **Option A — uniform behavior, upstream wins.** No warning log; no fork-side path preservation. The new `detect_windows()` factory simply executes per upstream's intent.

### DEC-5: D-43-E1 4-condition addendum compliance — Windows-specific factory functions exceed 5-line budget (documented exception)

The 4 new factory functions are sized: `detect_windows` 6 lines, `detect_windows_version` 10 lines, `query_windows_registry_value` 14 lines, `parse_windows_registry_value` 24 lines (after REG_DWORD fold-in). Each exceeds D-43-E1's nominal ≤5-line budget.

Per 43-CONTEXT.md D-43-C1 verdict-recording mechanism, the canonical D-43-E1 ≤5-line exception applies when:
- The Windows-specific code is required for a documented feature (here: robust Windows platform detection per upstream cluster 4)
- The code lives in a cross-platform module dispatched by `cfg!` runtime check (here: platform.rs's `detect()` at line 80)
- The alternative (splitting into many ≤5-line helpers) would obscure the upstream replay surface or violate cohesion (here: `parse_windows_registry_value` is the natural granularity; splitting it into a 5-line line-iterator + 5-line REG_DWORD-handler + 5-line dispatch would fragment the parsing logic without functional benefit)
- The exception is documented per-hunk in the disposition resolution

Conditions (1)(2)(4) PASS per-hunk (consumed by cross-platform `current()` → `When::matches`; cross-platform module not fork-only Windows file; documented in 43-06-DISPOSITION-RESOLUTION.md table + this SUMMARY + 43-06-CLOSE-GATE.md). Condition (3) ≤5-lines: documented exception per above.

### DEC-6: Phase 36-01b/c invariants preserved automatically

A key observation from Q2 / Q6 of Task 1's diff-inspection: Cluster 4 adds NO new top-level Profile field. The unknown-field-rejection logic lives in the existing `deserialize_conditional_string_vec` helper (one new `if !object.is_empty()` block at line ~482). The SecretsConfig Deserialize rewrite stays inside the same `SecretsConfig` Deserialize impl. The `From<ProfileDeserialize> for Profile` exhaustive enumeration at profile/mod.rs:1893+ is UNTOUCHED.

This means Phase 36-01b's structural rustc-completeness-check guard is preserved by construction. No new arm is added to the From-impl; no risk of silent field-drop regression.

Phase 36-01c `bypass_protection` rename is also UNTOUCHED — Q5 grep on both upstream SHAs returned 0 (`override_deny|bypass_protection`). No rename arms required.

Verification: `grep -c 'commands: raw\.commands' crates/nono-cli/src/profile/mod.rs` → 1 (Phase 36-01b canonical arm intact).

### DEC-7: No rust-1.95 lint Rule-3 deviation surfaced

Distinct from Plan 43-05's `clippy::unnecessary_map_or` finding at `platform.rs:232`:

- The 5d821c12 `map_or("", |part| part)` pattern in `matches_windows` is lint-clean. `clippy::unnecessary_map_or` targets `.map_or(true, ...)` / `.map_or(false, ...)` boolean reductions (suggesting `.is_some_and(...)` / `.is_none_or(...)`), NOT `.map_or("", ...)` value extractions. `Option<&str>::map_or("", |part| part)` has no `is_some_and` / `is_none_or` equivalent because it returns `&str`, not `bool`.
- The `compare_versions` `Ordering::Less` fallback uses a `match` guard pattern (`_ if left_part == right_part => Ordering::Equal, _ => Ordering::Less`) which is lint-clean.
- The new factory functions use no `.unwrap()` / `.expect()` (which would trip `clippy::unwrap_used` under `-D`). All optional registry queries return `Option<String>` and use `.ok()?` / `.ok_or_else(...)` / `unwrap_or_default()` patterns where `unwrap_or_default()` returns `""` on `Option<String>` (correct fail-secure no-match semantics).

Gate 2 (Windows clippy with `-D warnings -D clippy::unwrap_used`) exit 0 on first attempt. No `fix(43-06-cra):` follow-up commit needed.

### DEC-8: W-5 + W-7 fixes structurally satisfied (Branch B single-commit form)

The W-5 chronological-order falsifiable check (`HEAD's Upstream-commit = 5d821c12 AND HEAD~1's Upstream-commit = 0748cced`) was designed for Branch A's 2-cherry-pick sequence. Branch B's single-commit form makes the check inapplicable — there is no second commit to misorder. Instead, the single commit body lists both `Upstream-replayed-from:` trailers in chronological order:
```
Upstream-replayed-from: 0748cced
Upstream-replayed-from: 5d821c12
```

The W-7 wrapped-transaction with rollback-on-partial-failure (`trap ... ERR; git reset --hard $PRE_TASK_HEAD`) was designed to prevent a partial-landing state where 0748cced lands but 5d821c12 fails. Branch B's single-commit form makes partial-landing impossible — there is no point between the two SHAs' contributions where the working tree is committed.

The fixes' INTENT (no panic-vector landing on main; no chronological confusion in git log) is preserved by construction rather than by post-commit verification.

## Deviations from Plan

### Issue 1 — Phase 41 D-14 / CR-04 broker-binary precondition (recurrence)

**Found during:** Task 2 final `cargo test --workspace --all-features` cycle.
**Issue:** `exec_strategy::launch::broker_dispatch_tests::broker_launch_assigns_child_to_job_object` failed with: `nono-shell-broker.exe missing at .../target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe and .../target/release/nono-shell-broker.exe; pre-build with cargo build -p nono-shell-broker --release`
**Fix:** Same recipe as Plan 43-05 Issue 2 and Plan 43-01b Issue 1:
```
cargo build -p nono-shell-broker --release
mkdir -p target/x86_64-pc-windows-msvc/release
cp target/release/nono-shell-broker.exe target/x86_64-pc-windows-msvc/release/
```
**Files modified:** none in source tree; only build artifacts under `target/`.
**Commit:** n/a — environmental precondition, not a code change.
**Justification:** mirrors Plan 43-01b Issue 1 + Plan 43-05 Issue 2 precedent. Recommendation for future Phase 43 worktree-agent runs: orchestrator should ensure `cargo build -p nono-shell-broker --target x86_64-pc-windows-msvc --release` is part of the pre-test environment setup (Phase 41 CR-04 follow-up).

### No other deviations

Tasks 1, 2, 3, 4 ran as planned. Branch B (D-20 manual replay) was correctly selected by Task 1's foundation-constraint + clause-(a)-corroboration verdict (D-40-B1 upgrade authority not exercised; W-7 wrapped-transaction not needed for combined single-commit form per DEC-2/DEC-8). Minimal replay scope per DEC-3 selected SKIP for `wiring.rs` per same rationale as Plan 43-05 DEC-3.

## Issues Encountered

### Issue 1 — broker-binary precondition recurrence

See "Deviations from Plan" § Issue 1 above for full detail.

## D-43-E9 8-check close gate

See `.planning/phases/43-upst5-sync-execution/43-06-CLOSE-GATE.md` for full evidence. Summary:

| Gate | Description                                           | Disposition                                                    |
|------|-------------------------------------------------------|----------------------------------------------------------------|
| 1    | `cargo test --workspace --all-features` (Windows)     | PASS (2208 passed, 0 failed, 19 ignored)                       |
| 2    | `cargo clippy --workspace --all-targets` (Windows)    | PASS on first attempt (no Rule-3 deviation surfaced)           |
| 3    | `cargo clippy --target x86_64-unknown-linux-gnu`      | load-bearing-skip → CI-verified (cross-toolchain absent)       |
| 4    | `cargo clippy --target x86_64-apple-darwin`           | load-bearing-skip → CI-verified (cross-toolchain absent)       |
| 5    | `cargo fmt --all -- --check`                          | PASS                                                           |
| 6    | Phase 15 5-row detached-console smoke                 | environmental-skip (D-40-C2)                                   |
| 7    | `wfp_port_integration` tests                          | environmental-skip (cargo-level passed in Gate 1)              |
| 8    | `learn_windows_integration` tests                     | environmental-skip (cargo-level passed in Gate 1)              |

## Wave 2b CI Verification

Per `.planning/templates/upstream-sync-quick.md:108-113`, the baseline-aware CI gate compares post-merge CI lanes on the head SHA against baseline `13cc0628` (Phase 41 close). In worktree mode, the actual branch-push + CI lane assessment is deferred to the orchestrator.

Pre-merge expectation (set by Windows-host evidence):
- Linux + macOS clippy lanes: green→green (PASS) — no new `unwrap_or_default()`-on-panic-prone-path introductions; the 5d821c12 `map_or("", |part| part)` form is panic-safe AND lint-clean
- All workspace test lanes: green→green — local Windows test gate proves 2208 / 0 / 19
- fmt-check: green→green
- 5 Windows CI lanes: green→green expected — the Windows-specific `detect_windows` shell-out is invoked only under `cfg!(target_os = "windows")`, and integration tests that exercise `When::matches` continue to pass

Post-merge: orchestrator fills in the lane transition table in `43-06-CLOSE-GATE.md` § "Lane transitions".

## Threat-model close-out

| Threat ID  | Status     | Note                                                                                                              |
|------------|------------|-------------------------------------------------------------------------------------------------------------------|
| T-43-06-01 | MITIGATED  | REG_DWORD hex→decimal + `map_or("", \|part\| part)` panic-safety from 5d821c12 folded into the same replay commit; no partial-landing path |
| T-43-06-02 | MITIGATED  | D-43-E1 grep returned 0; all Windows-specific code in platform.rs cross-platform module                            |
| T-43-06-03 | MITIGATED  | Q7 = 0 `WindowsTokenArm\|BrokerLaunch` matches in either upstream SHA                                              |
| T-43-06-04 | MITIGATED  | Q2 confirms 0 From-impl exhaustive-enumeration touches; Phase 36-01b structural guard preserved                    |
| T-43-06-05 | MITIGATED  | Q5 = 0 `override_deny\|bypass_protection` occurrences in either commit                                             |
| T-43-06-06 | ACCEPTED   | HKLM modifiable only by Administrators; platform-detection informational, not a privilege boundary                  |
| T-43-06-07 | MITIGATED  | Branch B D-20 5-section body + 2 `Upstream-replayed-from:` trailers; falsifiable smoke all 6 checks PASS            |
| T-43-06-08 | ACCEPTED   | Registry queries are product/version/edition, not user PII                                                          |
| T-43-06-09 | ACCEPTED   | One-time OnceLock-cached detection                                                                                  |
| T-43-06-10 | MITIGATED  | Foundation constraint applied at Task 1 step 4 — Plan 43-06 forced to fork-preserve because Plan 43-05 = fork-preserve |
| T-43-06-11 | MITIGATED  | Single combined replay commit → no partial-landing path possible (W-7 inapplicable but intent preserved)            |
| T-43-06-12 | MITIGATED  | Single commit → chronological-order check trivially satisfied; commit body lists both SHAs in order                 |
| T-43-06-13 | MITIGATED  | W-8 fix canonical `fork-preserve` value used everywhere; no non-canonical strings                                   |

ASVS L1 disposition: all `high` threats MITIGATED; all `medium` threats MITIGATED; `low` threats (T-43-06-06, T-43-06-08, T-43-06-09) ACCEPTED. Security gate satisfied.

## Self-Check

| Check                                                                                                                              | Result |
|------------------------------------------------------------------------------------------------------------------------------------|--------|
| `[ -f .planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md ]`                                      | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md ]`                                                  | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-06-CLOSE-GATE.md ]`                                                              | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-06-PR-SECTION.md ]`                                                              | FOUND  |
| `[ -f crates/nono-cli/src/platform.rs ]`                                                                                           | FOUND (post-Plan-43-05 + Plan-43-06 extensions) |
| `git log --oneline -1 378ac515` matches `docs(43-06): record D-43-C1 ...`                                                          | FOUND  |
| `git log --oneline -1 a46b6bf9` matches `feat(43-06): replay windows registry detection ...`                                       | FOUND  |
| `grep -c '^fn detect_windows()' crates/nono-cli/src/platform.rs` → 1                                                               | PASS   |
| `grep -c '^fn parse_windows_registry_value' crates/nono-cli/src/platform.rs` → 1                                                   | PASS   |
| `grep -c 'fn windows_registry_dword_values_are_decimalized' crates/nono-cli/src/platform.rs` → 1                                   | PASS   |
| `grep -c 'fn conditional_profile_entries_reject_unknown_fields' crates/nono-cli/src/profile/mod.rs` → 1                            | PASS   |
| `git log -1 --format='%B' a46b6bf9 \| grep -c '^Upstream-commit: '` → 0                                                            | PASS   |
| `git log -1 --format='%B' a46b6bf9 \| grep -c '^Upstream intent:'` → 1                                                             | PASS   |
| `git log -1 --format='%B' a46b6bf9 \| grep -c '^What was replayed:'` → 1                                                           | PASS   |
| `git log -1 --format='%B' a46b6bf9 \| grep -c '^What was NOT replayed'` → 1                                                        | PASS   |
| `git log -1 --format='%B' a46b6bf9 \| grep -c '^Fork-only wiring preserved:'` → 1                                                  | PASS   |
| `git log -1 --format='%B' a46b6bf9 \| grep -c '^Upstream-replayed-from: '` → 2 (both SHAs)                                         | PASS   |
| `git diff --name-only HEAD~2 HEAD \| grep -cE '_windows\.rs\|exec_strategy_windows\|crates/nono-shell-broker/'` → 0                | PASS   |
| `grep -c 'commands: raw\.commands' crates/nono-cli/src/profile/mod.rs` → 1 (Phase 36-01b preserved)                                | PASS   |
| `grep -n 'rsplit\|map_or' crates/nono-cli/src/platform.rs` shows `map_or("", \|part\| part)` (5d821c12 form)                       | PASS   |
| `cargo test --workspace --all-features`: 2208 passed / 0 failed                                                                    | PASS   |
| `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0                                             | PASS   |
| `cargo fmt --all -- --check` exits 0                                                                                               | PASS   |
| `[ ! -f .git/CHERRY_PICK_HEAD ]`                                                                                                   | PASS   |
| PLAN.md frontmatter `resolved_disposition: fork-preserve` (canonical value per W-8 fix)                                            | PASS   |
| 5 plan SUMMARYs exist pre-43-06 (43-01..43-05); 43-06 SUMMARY pending this Task 4 commit                                           | PASS (6 total after this commit) |

Status: **PASSED.**

## User Setup Required

None for this plan. Orchestrator (post-merge) responsibilities:
1. Push the worktree branch to remote.
2. Append `43-06-PR-SECTION.md` content to the Phase 43 umbrella PR body (the 6th and final contribution section).
3. After CI completes on the head SHA, fill in the CI lane transition table in `43-06-CLOSE-GATE.md` § "Lane transitions".
4. Author the phase-level `43-SUMMARY.md` (Phase 43 close-out summary) per D-43-D1 — should include the Cluster 6 macOS-lint won't-sync inline pointer per Phase 40 D-40-D1 precedent.
5. Update `.planning/STATE.md` (Phase 43 close-out) + `.planning/ROADMAP.md` (Phase 43 progress 6/6) + bump `Current Phase` if appropriate.
6. Open the Phase 43 umbrella PR (`opens_umbrella_pr: false` here per Plan 43-06 frontmatter; orchestrator-driven open).

## Next Phase Readiness

**Phase 43 is structurally complete after this plan closes.** All 6 plans (43-01 through 43-06) have:
- PLAN.md + SUMMARY.md pairs in `.planning/phases/43-upst5-sync-execution/`
- D-43-C1 verdicts recorded (resolved_disposition field canonical per W-8 fix)
- D-43-E9 8-check close gates executed
- Per-plan PR sections authored

**Phase 44 / UPST6 hand-off:** post-v0.54.0 upstream synchronization starts from baseline `c4af6dde` (replace with actual upstream head SHA at UPST6 plan-open). Cluster 6 macOS-lint (won't-sync per D-43-D1) inline pointer should appear in the phase-level 43-SUMMARY.md authored by the orchestrator. Plan 43-06 SUMMARY notes that the inline won't-sync section is Phase 43 close-out scope, NOT Plan 43-06 scope (per the plan's frontmatter explicit boundary statement).

**Patterns ready for future application:**
- Combined-single-commit replay for must-land-as-a-unit upstream commit pairs (DEC-2 + patterns_established)
- Replay-when-foundation-is-also-replayed disposition forcing (DEC-1 + patterns_established)
- Windows-fallback decision audit pattern Option A vs B (DEC-4 + patterns_established)
