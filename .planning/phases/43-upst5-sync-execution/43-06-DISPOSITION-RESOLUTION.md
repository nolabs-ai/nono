---
phase: 43-upst5-sync-execution
plan: 06
upstream_shas: [0748cced, 5d821c12]
upstream_tag: v0.54.0
upstream_subjects:
  - "0748cced: feat(platform): implement robust windows platform detection"
  - "5d821c12: fix(platform): correctly parse windows registry dword values"
inspection_date: 2026-05-18
inspector: executor (worktree-agent-a123e5783ee35c0cc)
foundation_plan: 43-05
foundation_resolved_disposition: fork-preserve
resolved_disposition: fork-preserve
verdict_clause_a: FAIL  # trial cherry-pick of 0748cced produced 2 content conflicts (wiring.rs + schema.json)
verdict_clause_b: PASS_BUT_CONSTRAINED  # platform.rs auto-merges and surface semantics align with Plan 43-05's verbatim 659-line replay; however replay-when-foundation-is-also-replayed pattern overrides clause-(b)-driven upgrade
verdict_constraint: replay-when-foundation-is-also-replayed (43-PATTERNS.md § Plan 43-06)
windows_fallback_decision: Option A — uniform behavior (upstream wins)
---

# Plan 43-06 — D-43-C1 Disposition Resolution (Cluster 4)

**Date:** 2026-05-18
**Upstream commits:** `0748cced feat(platform): implement robust windows platform detection` + `5d821c12 fix(platform): correctly parse windows registry dword values` (v0.54.0)
**Verdict:** `resolved_disposition = fork-preserve`
**Constraint:** replay-when-foundation-is-also-replayed (Plan 43-05's `resolved_disposition = fork-preserve` forces Plan 43-06 to fork-preserve per 43-PATTERNS.md § Plan 43-06)

## Pre-flight prerequisites

| Check | Evidence | Status |
|-------|----------|--------|
| Plan 43-05 closed (ce06bd59 replay) | `git log --format='%B' HEAD~10..HEAD \| grep -cE '^Upstream-(commit\|replayed-from): ce06bd59'` → 2 | PASS |
| W-7 fix SHA reachability — 0748cced | `git cat-file -e 0748cced^{commit}` → exit 0 | PASS |
| W-7 fix SHA reachability — 5d821c12 | `git cat-file -e 5d821c12^{commit}` → exit 0 | PASS |
| Foundation `resolved_disposition` read from 43-05 SUMMARY frontmatter | `disposition: fork-preserve` + `resolved_disposition: fork-preserve` | READ |
| `crates/nono-cli/src/platform.rs` exists in fork (post-Plan-43-05) | `[ -f crates/nono-cli/src/platform.rs ]` AND `wc -l` → 659 | PASS |
| Working tree clean before trial | `git status --short` → empty | PASS |

## Foundation-constraint application

Per 43-PATTERNS.md § Plan 43-06 replay-when-foundation-is-also-replayed pattern:

> If foundation `resolved_disposition` = `fork-preserve`: Plan 43-06 MUST stay fork-preserve (the partial replay of Plan 43-05's platform.rs cannot cleanly accept Cluster 4's cherry-picks because the SHAs reference upstream's full 659-line shape that the fork doesn't have).

Plan 43-05's `resolved_disposition` is `fork-preserve` (per 43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md frontmatter line 9 + line 10). NOTE: Plan 43-05's replay was VERBATIM (659 lines, full upstream shape), so technically Cluster 4 SHOULD compose additively — but per W-8 fix canonical-value discipline + 43-PATTERNS.md replay-when-foundation-is-also-replayed pattern, the verdict is forced to fork-preserve regardless. The trial cherry-pick below provides corroborating evidence.

**`RESOLVED_DISPOSITION="fork-preserve"` (forced by foundation constraint).**

## D-43-C1 Q1-Q9 surface-overlap analysis

| Q  | Question | Evidence | Result |
|----|----------|----------|--------|
| Q1 | upstream touches `crates/nono-cli/src/terminal_approval.rs`? | `git show 0748cced 5d821c12 \| grep -cE 'terminal_approval\.rs'` → 0 | 0 (Phase 18.1 surface untouched) |
| Q2 | upstream touches `crates/nono-cli/src/profile/mod.rs`? | YES (0748cced only, +67 lines): adds unknown-field validation to `deserialize_conditional_*_vec` (lines 87-93); rewrites `SecretsConfig` Deserialize to use `serde_json::Value` (lines 1049-1097); adds 1 integration test (lines 6130-6151). **NO touches to the `From<ProfileDeserialize> for Profile` exhaustive enumeration at fork lines 1893+.** Phase 36-01b structural guard preserved. | YES (additive, no From-impl collision) |
| Q3 | upstream touches `crates/nono-cli/src/wiring.rs`? | YES (0748cced only, +4 lines): `#[serde(skip_serializing)]` on `WiringDirective::Skipped` variant + 3-line comment block above `RawWiringDirective` enum. | YES (trivial; SKIP per minimal-replay-scope discipline — wiring.rs replay was deferred in 43-05; this addendum is +1 attribute on the same un-replayed surface) |
| Q4 | path-string `starts_with` in upstream hunks? | `git show 0748cced 5d821c12 -- '*.rs' '*.json' \| grep -cE '\.starts_with\("/'` → 0 | SAFE (CLAUDE.md § Common Footguns #1 not triggered) |
| Q5 | `override_deny` vs `bypass_protection` count in upstream hunks? | `git show 0748cced 5d821c12 \| grep -cE 'override_deny\|bypass_protection'` → 0 | 0/0 (no rename arms required; Phase 36-01c preserved) |
| Q6 | fork-only Windows files touched (D-43-E1)? | `git show 0748cced 5d821c12 --name-only --pretty=format: \| grep -cE '_windows\.rs\|exec_strategy_windows\|crates/nono-shell-broker/'` → 0 | 0 — Windows-specific code lives INSIDE platform.rs's `#[cfg(target_os = "windows")]` branch (cross-platform module) |
| Q7 | broker dispatch collision? | `git show 0748cced 5d821c12 \| grep -cE 'WindowsTokenArm\|BrokerLaunch'` → 0 | 0 (Phase 22 D-17 / D-43-E1 invariant preserved) |
| Q8 | D-43-E1 4-condition addendum per Windows-specific hunk | See addendum table below | RECORDED |
| Q9 | Windows-fallback decision (Phase 40 Plan 40-06 DEC-6 pattern) | `grep -rE 'registry\|RegOpenKey\|RegQueryValue' crates/nono-cli/src/exec_strategy_windows/ crates/nono-shell-broker/` → 1 hit in `restricted_token.rs:84` BUT it is a **comment** describing kernel-side token-access "registry traversal" during console-child initialization — unrelated to our platform-detection `reg query` shell-out. **Option A applies by default — no fork-side divergent registry-detection code path to preserve.** | Option A — uniform behavior (upstream wins) |

## D-43-E1 4-condition addendum (per-hunk evidence)

| Hunk | File | Lines | Cond (1) cross-platform caller? | Cond (2) cross-platform default factory only? | Cond (3) ≤5 lines or documented exception? | Cond (4) documented? |
|------|------|-------|----------------------------------|------------------------------------------------|---------------------------------------------|----------------------|
| 0748cced: `detect()` Windows-branch swap (`WindowsInfo::default()` → `detect_windows()`) | platform.rs | line 85 (1 line) | YES — `current()` consumed by cross-platform `When::matches` evaluation | YES — `detect_windows()` is a fn in cross-platform module; only the `cfg!(target_os = "windows")` branch invokes it | YES — 1 line | YES (this table + SUMMARY) |
| 0748cced: `detect_windows()` factory | platform.rs | 6 lines | YES (consumed by `detect()` for `When` eval) | YES — cross-platform `fn`; calls `query_windows_registry_value` which also lives in cross-platform module | exception per D-43-E1: meaningful registry-parsing implementation cannot fit in ≤5 lines; documented exception per 43-CONTEXT.md D-43-C1 verdict-recording mechanism | YES |
| 0748cced: `detect_windows_version()` factory | platform.rs | 10 lines | YES (consumed by `detect_windows`) | YES | exception per D-43-E1: registry-key fallback logic requires explicit match | YES |
| 0748cced: `query_windows_registry_value()` factory | platform.rs | 14 lines | YES (transitively consumed) | YES — `std::process::Command::new("reg")` shell-out is cross-platform-safe (Command fails gracefully off Windows) | exception per D-43-E1: subprocess invocation requires args + status check | YES |
| 0748cced: `parse_windows_registry_value()` factory | platform.rs | 14 lines | YES | YES — pure function; no `#[cfg]` gating needed | exception per D-43-E1: registry line parser needs iteration logic | YES |
| 0748cced: `When::parse()` visibility change (`#[cfg(test)]` → `pub(crate)`) | platform.rs | 2 lines (cfg attr removed, vis tightened) | YES — used by `When::deserialize` single-string fast-path below | YES (already cross-platform) | YES — 2 lines | YES |
| 0748cced: `When::deserialize` single-string fast-path | platform.rs | 3 lines | YES (Deserialize impl is cross-platform) | YES | YES — 3 lines | YES |
| 0748cced: `matches_windows()` build_version fix (`unwrap_or(&info.version)` → `unwrap_or_default()`) | platform.rs | 1 line | YES (cross-platform `When::matches` consumer) | YES | YES — 1 line | YES |
| 0748cced: `compare_versions` ordering fix (non-numeric mismatch → `Ordering::Less`) | platform.rs | 2 lines | YES (cross-platform) | YES | YES — 2 lines | YES |
| 0748cced: test update + addition (`version_segments_compare_numerically_when_possible`) | platform.rs | 2 lines (assertion change + new assertion) | n/a (test module) | n/a | YES — 2 lines | YES |
| 0748cced: profile/mod.rs unknown-field validation in `deserialize_conditional_*_vec` | profile/mod.rs | 6 lines | YES (consumed by every list-deserializer) | YES — pure validation, no platform-specific code | YES — 6 lines (acceptable; closes a real fail-secure gap) | YES |
| 0748cced: `SecretsConfig` Deserialize swap to `serde_json::Value` + explicit unknown-key rejection | profile/mod.rs | +30/-14 net | YES (Profile-level surface) | YES — cross-platform | exception per D-43-E1: rewriting closed-grammar deserializer requires the full code-path | YES |
| 0748cced: integration test `conditional_profile_entries_reject_unknown_fields` | profile/mod.rs | +18 lines | n/a (test) | n/a | exception (test) | YES |
| 0748cced: wiring.rs `WiringDirective::Skipped` skip_serializing + comment | wiring.rs | +4 lines | YES (`WiringDirective` is consumed by lockfile serialization) | YES | YES — 4 lines | NOT REPLAYED — see "What was NOT replayed" |
| 0748cced: schema.json description text update | schema.json | 1 line | n/a (doc string) | n/a | YES — 1 line | YES |
| 5d821c12: `parse_windows_registry_value` REG_DWORD hex→decimal conversion | platform.rs | +10/-1 net | YES (consumed by `query_windows_registry_value`) | YES — pure function | exception per D-43-E1: hex-prefix conversion + safe `u64::from_str_radix` requires explicit handling | YES |
| 5d821c12: `matches_windows` build_version safety (`unwrap_or_default()` → `map_or("", \|part\| part)`) | platform.rs | 1 line | YES | YES | YES — 1 line | YES |
| 5d821c12: REG_DWORD test `windows_registry_dword_values_are_decimalized` | platform.rs | +12 lines | n/a (test) | n/a | exception (test) | YES |

**Conclusion:** D-43-E1 4-condition addendum satisfied per-hunk. Most hunks pass conditions (1)(2)(4) trivially; condition (3) "≤5 lines" exceptions are documented per 43-CONTEXT.md verdict-recording mechanism (Windows registry parsing inherently exceeds 5-line budget; the exception is canonical per D-43-C1 verdict authority).

## Trial cherry-pick (D-40-B1 clause-(a) corroborating evidence)

```
git switch -c 43-06-trial-cherry-pick
git -c core.editor=true cherry-pick --no-commit 0748cced
```

Output:
```
Auto-merging crates/nono-cli/data/nono-profile.schema.json
CONFLICT (content): Merge conflict in crates/nono-cli/data/nono-profile.schema.json
Auto-merging crates/nono-cli/src/platform.rs       ← clean merge
Auto-merging crates/nono-cli/src/profile/mod.rs    ← clean merge
Auto-merging crates/nono-cli/src/wiring.rs
CONFLICT (content): Merge conflict in crates/nono-cli/src/wiring.rs
error: could not apply 0748cced...
```

Index status (`git status --short`):
```
UU crates/nono-cli/data/nono-profile.schema.json   (conflict)
M  crates/nono-cli/src/platform.rs                  (clean merge, +66 lines applied)
M  crates/nono-cli/src/profile/mod.rs               (clean merge, +37 net lines applied)
UU crates/nono-cli/src/wiring.rs                    (conflict)
```

Conflict marker counts: schema.json = 1 marker; wiring.rs = 1 marker; platform.rs = 0; profile/mod.rs = 0.

**Result: 2 content conflicts (schema.json + wiring.rs). 0 modify/delete. Clause (a) FAIL (D-40-B1 zero-conflicts upgrade clause not satisfied).**

5d821c12 trial-pick NOT attempted (per W-7 wrapped-transaction protocol — if first SHA in the chain fails clause-(a), the whole transaction is rolled back; no point trying the second SHA on a polluted index).

Conflict-source analysis:
- **schema.json:** the description text change at line 219 conflicts because Plan 43-05's verbatim replay already included a different version of the WhenPredicate description (fork-side baseline includes additional ConditionalName/ConditionalOrigin $defs).
- **wiring.rs:** Plan 43-05 SKIPped wiring.rs per minimal-replay-scope; 0748cced's `#[serde(skip_serializing)]` attribute on `WiringDirective::Skipped` plus 3-line comment block conflict because fork's wiring.rs has the variant in a different position (no `Skipped` variant exists in fork's WiringDirective enum at all — Plan 43-05 SKIPped the entire upstream WiringDirective surface).

## Verdict

| Clause | Status |
|--------|--------|
| Foundation constraint (43-PATTERNS.md § Plan 43-06) | FORCED → `fork-preserve` |
| D-40-B1 clause (a) zero-conflicts | FAIL (2 content conflicts in trial cherry-pick) |
| D-40-B1 clause (b) surface-semantics identical | PASS for platform.rs+profile/mod.rs (auto-merge); FAIL for wiring.rs (Skipped variant absent in fork) |

Both the foundation constraint AND the trial-pick clause-(a) outcome point to fork-preserve. **`resolved_disposition` = `fork-preserve`** (W-8 fix canonical value).

## Cleanup audit trail

| Step | Evidence |
|------|----------|
| `git reset --hard HEAD` on trial branch | "HEAD is now at a9aea24a chore: merge executor worktree..." |
| Switch back to `worktree-agent-a123e5783ee35c0cc` | `git rev-parse --abbrev-ref HEAD` → `worktree-agent-a123e5783ee35c0cc` |
| `git branch -D 43-06-trial-cherry-pick` | "Deleted branch 43-06-trial-cherry-pick (was a9aea24a)" |
| State sealed | `[ ! -f .git/CHERRY_PICK_HEAD ]` → cleared; `git status --short` → empty |

## Frontmatter write

PLAN.md `resolved_disposition` field updated from `null` → `fork-preserve` (W-8 canonical value per D-43-E8).
PLAN.md `disposition` field STAYS at conservative `fork-preserve` (no change — W-8 fix mandates `disposition:` is the default, `resolved_disposition:` is the live verdict).

## Implications for Task 2 (Branch B — D-20 manual replay)

Per Phase 40 Plan 40-06 SUMMARY DEC-2 minimal-replay-scope discipline + Phase 43 Plan 43-05 precedent:

**Replay scope (1 combined replay commit per DEC-2 default — preferred for traceability):**
- `crates/nono-cli/src/platform.rs`:
  - swap line 85 `Some(WindowsInfo::default())` → `Some(detect_windows())`
  - add `detect_windows()` + `detect_windows_version()` + `query_windows_registry_value()` + `parse_windows_registry_value()` factory functions (inserted between `detect_macos()` and `run_sw_vers()`)
  - REG_DWORD hex→decimal conversion (5d821c12 fold-in) inside `parse_windows_registry_value()`
  - `When::parse()` visibility: `#[cfg(test)] pub fn` → `pub(crate) fn`
  - `When::deserialize` single-string fast-path (3 lines)
  - `matches_windows` build_version: `unwrap_or(&info.version)` → `map_or("", |part| part)` (5d821c12 fold-in)
  - `compare_versions` non-numeric ordering fix (2 lines)
  - test `version_segments_compare_numerically_when_possible` assertion update
  - test `windows_registry_dword_values_are_decimalized` (5d821c12 fold-in)

- `crates/nono-cli/src/profile/mod.rs`:
  - unknown-field validation in `deserialize_conditional_*_vec` helpers (5-6 lines × N callers, OR a single shared check at the right point — replay verbatim from upstream)
  - `SecretsConfig` Deserialize swap to `serde_json::Value` + explicit unknown-key rejection
  - integration test `conditional_profile_entries_reject_unknown_fields`

- `crates/nono-cli/data/nono-profile.schema.json`:
  - description text update at line 219 (`linux:fedora:>=43:workstation` example)

**NOT replayed:**
- `crates/nono-cli/src/wiring.rs` (`#[serde(skip_serializing)]` on `WiringDirective::Skipped` + comment block): SKIPped because Plan 43-05 SKIPped the entire wiring.rs surface (no `Skipped` variant in fork's WiringDirective enum). W-4 fix mitigation: directive-level `when:` still rejected fail-secure by existing `#[serde(deny_unknown_fields)]`. This addendum has no consumer in fork until WhenPredicate evaluation is wired into directive-level serialization (deferred to future fork-side refactor).

## Threat-model alignment

| Threat ID | Disposition | Rationale |
|-----------|-------------|-----------|
| T-43-06-01 | mitigated | REG_DWORD hex→decimal + `map_or("", \|part\| part)` panic-safety from 5d821c12 folded into the same replay commit as 0748cced. No partial-landing path (single combined commit). |
| T-43-06-02 | mitigated | Q6 = 0 fork-only Windows-file touches. All Windows-specific code lands INSIDE platform.rs `#[cfg(target_os = "windows")]` branch (cross-platform module). |
| T-43-06-03 | mitigated | Q7 = 0 broker dispatch collision. |
| T-43-06-04 | mitigated | Q2 confirms 0 touches to `From<ProfileDeserialize> for Profile` exhaustive enumeration. Phase 36-01b structural guard preserved. |
| T-43-06-05 | mitigated | Q5 = 0 `override_deny` occurrences in either commit. |
| T-43-06-06 | accept | HKLM modifiable only by Administrators; if attacker has HKLM write, they already own the trust boundary. Platform-detection is informational, not a privilege boundary. |
| T-43-06-07 | mitigated by Branch B | Combined replay commit uses full D-20 5-section body + 2 `Upstream-replayed-from:` trailers (0748cced + 5d821c12). |
| T-43-06-08 | accept | Registry queries are product/version/edition — not user PII. |
| T-43-06-09 | accept | One-time detection (OnceLock-cached); no per-deserialization cost. |
| T-43-06-10 | mitigated | Foundation constraint applied at step 4 — Plan 43-06 forced to fork-preserve because Plan 43-05 = fork-preserve. |
| T-43-06-11 | mitigated by Branch B | Combined single-commit replay → no partial-landing path possible. W-7 wrapped-transaction not needed for Branch B (Branch A only). |
| T-43-06-12 | mitigated by Branch B | Single-commit replay → chronological-order check is trivially satisfied (no second commit to be out of order). `Upstream-replayed-from:` trailers list both SHAs explicitly in the commit body. |
| T-43-06-13 | mitigated | This artifact + PLAN.md frontmatter use canonical `fork-preserve` value per W-8 fix. No non-canonical strings. |

ASVS L1 disposition: all `high` threats mitigated; all `medium` threats mitigated; `low` threats accepted. Security gate satisfied.
