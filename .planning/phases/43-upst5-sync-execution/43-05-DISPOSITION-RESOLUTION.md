---
phase: 43-upst5-sync-execution
plan: 05
upstream_sha: ce06bd59
upstream_tag: v0.54.0
upstream_subject: "feat(profile): add platform-conditional profile fields"
inspection_date: 2026-05-18
inspector: executor (worktree-agent-a8440f5aa665ed53b)
resolved_disposition: fork-preserve
verdict_clause_a: FAIL  # trial cherry-pick produced 7 conflicts (6 content + 1 modify/delete)
verdict_clause_b: FAIL  # surface semantics DIVERGE — fork lacks `GroupsConfig` struct; upstream Profile structure differs
---

# Plan 43-05 — D-43-C1 Disposition Resolution (Cluster 5)

**Date:** 2026-05-18
**Upstream commit:** `ce06bd59 feat(profile): add platform-conditional profile fields` (v0.54.0)
**Verdict:** `resolved_disposition = fork-preserve`

## Pre-flight prerequisites

| Check | Evidence | Status |
|-------|----------|--------|
| Plan 43-04 closed (release-ride `6b00932f` cherry-picked) | `git log --format='%B' HEAD~10..HEAD \| grep -c '^Upstream-commit: 6b00932f'` → 1 | PASS |
| `crates/nono-cli/src/platform.rs` absent in fork | `ls crates/nono-cli/src/platform.rs 2>/dev/null` → absent | PASS |
| Working tree clean before trial | `git status --short` → clean before scratch branch | PASS |

## D-43-C1 Q1-Q8 surface-overlap analysis

| Q  | Question | Evidence | Result |
|----|----------|----------|--------|
| Q1 | upstream touches `crates/nono-cli/src/terminal_approval.rs`? | `git show ce06bd59 --diff-filter=AMRD --name-only --pretty=format: \| grep -c terminal_approval` → 0 | 0 (expected; Phase 18.1 surface untouched) |
| Q2 | upstream touches `crates/nono-cli/src/profile/mod.rs`? | file in changed-list = YES (+217 lines); **hunks are at lines 29-31, 62-87, 102-180, 958-1036, 966-1044, 1215-1329, 5947-6061** — i.e., add field-level conditional deserializers in `FilesystemConfig` / `GroupsConfig` / `SecretsConfig` / `OpenUrlConfig` + add SecretsConfig manual Deserialize impl + one integration test. **NO touches to the `From<ProfileDeserialize> for Profile` exhaustive enumeration at fork lines 1893-1921.** | YES (file touched); 0 touches to From-impl |
| Q3 | upstream touches `crates/nono-cli/src/policy.rs`? | file in changed-list = YES (+28 lines) | YES |
| Q4 | upstream touches `crates/nono-cli/src/wiring.rs`? | file in changed-list = YES (+126 lines) | YES |
| Q5 | `override_deny` vs `bypass_protection` count in ce06bd59 hunks | `override_deny`: 0 lines in hunks; `bypass_protection`: 4 occurrences (all pre-existing context, none new). **No rename required** — Phase 36-01c bypass_protection canonical name is already what upstream references. | 0 / 4 |
| Q6 | collision with Phase 36-01b `From<ProfileDeserialize>` exhaustive enumeration at `profile/mod.rs:1893-1921`? | Cluster 5 adds NO new top-level Profile field; conditional logic is INSIDE field-level deserializers (`deserialize_conditional_path_vec`, `deserialize_conditional_name_vec`, `deserialize_conditional_origin_vec`) + SecretsConfig manual Deserialize impl. **Phase 36-01b From-impl exhaustive enumeration is untouched by upstream.** | NO collision |
| Q7 | `platform.rs` uses `String::starts_with` for path comparison? | `git show ce06bd59 -- crates/nono-cli/src/platform.rs \| grep -E '\.starts_with'` → 2 hits, both are `.starts_with('#')` (char literal for `/etc/os-release` comment parse) and `.starts_with(\|c: char\| !c.is_ascii_alphanumeric())` (closure on char). **NEITHER is path-string compare; CLAUDE.md § Common Footguns #1 is NOT triggered.** | SAFE — 0 path-string starts_with |
| Q8 | upstream introduces collisions with fork-only Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/`)? | `git show ce06bd59 \| grep -cE 'WindowsTokenArm\|BrokerLaunch\|nono-shell-broker\|exec_strategy_windows'` → 0 | 0 — no broker dispatch collision |

## Trial cherry-pick (D-40-B1 clause (a) evidence)

```
git switch -c 43-05-trial-cherry-pick
git -c core.editor=true cherry-pick --no-commit ce06bd59
```

Output:
```
Auto-merging crates/nono-cli/data/nono-profile.schema.json
CONFLICT (content): Merge conflict in crates/nono-cli/data/nono-profile.schema.json
Auto-merging crates/nono-cli/data/profile-authoring-guide.md
CONFLICT (content): Merge conflict in crates/nono-cli/data/profile-authoring-guide.md
Auto-merging crates/nono-cli/src/main.rs
Auto-merging crates/nono-cli/src/package_cmd.rs
CONFLICT (content): Merge conflict in crates/nono-cli/src/package_cmd.rs
Auto-merging crates/nono-cli/src/policy.rs
CONFLICT (content): Merge conflict in crates/nono-cli/src/policy.rs
Auto-merging crates/nono-cli/src/profile/mod.rs
CONFLICT (content): Merge conflict in crates/nono-cli/src/profile/mod.rs
Auto-merging crates/nono-cli/src/wiring.rs
CONFLICT (content): Merge conflict in crates/nono-cli/src/wiring.rs
CONFLICT (modify/delete): docs/cli/features/package-publishing.mdx deleted in HEAD and modified in ce06bd59 [...]
error: could not apply ce06bd59... feat(profile): add platform-conditional profile fields
```

**Result:**
- **6 content conflicts:** `nono-profile.schema.json`, `profile-authoring-guide.md`, `package_cmd.rs`, `policy.rs`, `profile/mod.rs`, `wiring.rs`
- **1 modify/delete conflict:** `docs/cli/features/package-publishing.mdx` (fork deleted the entire `docs/cli/` MDX subtree; upstream kept modifying it)
- **Index status:** 7 unmerged paths (`UU` × 6 + `DU` × 1)

Conflict marker counts (per file): profile/mod.rs = 9 markers; policy.rs = 3; wiring.rs = 6; package_cmd.rs = 3; schema.json = 3.

**Clause (a) `D-40-B1` (zero content conflicts AND zero modify/delete):** FAIL — 6 content + 1 modify/delete observed.

## Surface-semantics divergence (D-40-B1 clause (b) evidence)

**Major schema divergence — `GroupsConfig` struct absent in fork:**

Upstream (`ce06bd59^:crates/nono-cli/src/profile/mod.rs:104-110`) has:
```rust
pub struct GroupsConfig {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}
```
referenced from `Profile.groups: GroupsConfig` at line 1272.

Fork (`crates/nono-cli/src/profile/mod.rs`) has NO `GroupsConfig` struct. Fork uses flat `groups: Vec<String>` + `exclude_groups: Vec<String>` directly inside policy/security configs (verified via `grep -n 'GroupsConfig\|pub groups:' crates/nono-cli/src/profile/mod.rs`).

This is a **real schema-shape divergence** — upstream's GroupsConfig hunk cannot apply to fork because the target struct does not exist. The cherry-pick path would require either:
- Defining a brand-new `GroupsConfig` struct in fork (semantic restructure)
- Skipping the GroupsConfig hunks entirely and rewriting the conditional logic against fork's flat `groups: Vec<String>` field (no clean cherry-pick)

**Clause (b) `D-40-B1` (surface semantics IDENTICAL):** FAIL — fork lacks `GroupsConfig` target struct; semantic restructure required.

## Verdict

Both D-40-B1 clauses FAIL → `resolved_disposition` STAYS at conservative default **`fork-preserve`** (D-42-C3).

No upgrade to `will-sync` is granted. Task 2 proceeds with Branch B (D-20 manual replay) per the plan.

## Cleanup

| Step | Evidence |
|------|----------|
| `git reset --hard HEAD` on trial branch | "HEAD is now at 6354167a docs(phase-43): update tracking after wave 1" |
| Switch back to `worktree-agent-a8440f5aa665ed53b` | `git rev-parse --abbrev-ref HEAD` → `worktree-agent-a8440f5aa665ed53b` |
| `git branch -D 43-05-trial-cherry-pick` | "Deleted branch 43-05-trial-cherry-pick (was 6354167a)" |
| State sealed | `[ ! -f .git/CHERRY_PICK_HEAD ]` → no CHERRY_PICK_HEAD; `git status --short` → clean |

## Frontmatter write

PLAN.md `resolved_disposition` field updated from `null` → `fork-preserve` (W-8 canonical value per D-43-E8).
PLAN.md `disposition` field STAYS at conservative `fork-preserve` (no change — W-8 fix mandates `disposition:` is the default, `resolved_disposition:` is the live verdict).

## Implications for Task 2 (Branch B)

Minimal replay scope per Phase 40 Plan 40-05 DEC-2 — Cluster 5 specific:
- `crates/nono-cli/src/platform.rs` (NEW, partial): minimum surface to evaluate `when:` predicates (`pub fn current_os_name()` + `pub struct When` + `pub fn when_matches_current(...)`); defer the full 659-line distro/registry detection to a future plan or Plan 43-06
- `crates/nono-cli/src/profile/mod.rs`: add `deserialize_conditional_path_vec` family + SecretsConfig manual Deserialize that honors `when:`; the `From<ProfileDeserialize>` exhaustive enumeration at lines 1893-1921 is UNTOUCHED (no new top-level Profile field → Phase 36-01b discipline preserved automatically)
- `crates/nono-cli/src/main.rs`: add `pub mod platform;`
- `crates/nono-cli/data/nono-profile.schema.json`: add `WhenPredicate` schema definition (+99 lines)
- `crates/nono-cli/src/wiring.rs`: SKIP — fork's WiringDirective doesn't compose conditional evaluation yet; **W-4 fix mitigation:** verify that the JSON schema's `when:` predicate is rejected fail-secure at any deserialization site where the manual replay does NOT consume it (covered automatically because field-level `deserialize_with` functions in this replay scope DO consume `when:` — the only place a top-level `when:` would land is on a WiringDirective, which fork doesn't support; if such a directive appears in a profile, fork's existing `#[serde(deny_unknown_fields)]` on `WiringDirective` already rejects it). Document explicitly.
- `crates/nono-cli/src/policy.rs`: SKIP — fork's `Group::platform: Option<String>` already provides the platform-conditional concept at the group level; upstream's `policy.rs` extension would conflict (already a content conflict in the trial cherry-pick); explicit "What was NOT replayed and why" section in commit body.
- `crates/nono-cli/src/package_cmd.rs`: SKIP — package_cmd changes are downstream of pack-management surface (Cluster 1) and are not load-bearing for `when:` predicate evaluation.
- `docs/cli/features/package-publishing.mdx`: SKIP — fork deleted the `docs/cli/` MDX subtree; upstream's modify hunks are moot.

## Threat-model alignment

| Threat ID | Disposition | Rationale |
|-----------|-------------|-----------|
| T-43-05-01 | mitigated | From-impl exhaustive enumeration NOT touched by Cluster 5 (Q6 = no collision); no Phase 36-01b regression risk |
| T-43-05-02 | mitigated | Q5 = 0 `override_deny` occurrences; no rename required |
| T-43-05-03 | mitigated | Q7 = 0 path-string `starts_with`; only char-literal `starts_with('#')` for `/etc/os-release` parse (safe) |
| T-43-05-04 | mitigated | Q8 = 0 fork-only Windows file touches |
| T-43-05-05 | mitigated | Q8 = 0 broker dispatch collisions |
| T-43-05-06 | mitigated | fork preserves existing `#[serde(deny_unknown_fields)]` on top-level structs; field-level deserializers explicitly handle `when:` key |
| T-43-05-10 | mitigated by Branch B scope choice | wiring.rs SKIPped — JSON schema's `when:` on a top-level WiringDirective would land at the existing `#[serde(deny_unknown_fields)]` rejection point. Field-level `when:` in path/name/origin entries is fully consumed by the replayed `deserialize_conditional_*_vec` family. No silent divergence. |
| T-43-05-11 | mitigated | This artifact + PLAN.md frontmatter use canonical `fork-preserve` value per W-8 fix |
