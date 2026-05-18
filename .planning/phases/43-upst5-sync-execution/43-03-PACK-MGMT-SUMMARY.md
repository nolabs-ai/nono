---
phase: 43-upst5-sync-execution
plan: 03
plan_id: 43-03-PACK-MGMT
cluster_id: 1
disposition: will-sync
subsystem: pack-management-cli
tags: [upstream-sync, will-sync, cherry-pick-chain, pack-management, cra-class-regressions]
status: COMPLETE
dependency_graph:
  requires:
    - "Plan 43-01b foundation (5e5f1005 — MSRV 1.95 + workspace deps centralization + edition 2021)"
    - "Phase 41 baseline 13cc0628 (all CI lanes green)"
  provides:
    - "`nono update` top-level command"
    - "`nono pin` / `nono unpin` / `nono outdated` subcommands"
    - "`pack_update_hint` inline UX for `nono run` (refresh-on-first-run + unparsable-version-as-older)"
    - "Fork-side `crate::profile::list_pack_store_profiles` adapter (Rule 2 CR-A — fills upstream API surface gap from Phase 34 D-20 omission)"
  affects:
    - "Plan 43-04 RELEASE-RIDE (Wave 1 parallel — surface-disjoint per D-43-A2)"
    - "Plan 43-05 PLATFORM-DETECTION-FOUNDATION (Wave 2a; runs after both Wave 1 plans merge)"
tech_stack:
  added:
    - "fork-side `list_pack_store_profiles` adapter (73 lines additive in profile/mod.rs)"
  patterns:
    - "Multi-commit cherry-pick chain with verbatim 6-line D-19 trailer per commit (8 cherry-picks)"
    - "CR-A class regressions handled as SEPARATE commits per CLAUDE.md (never --amend; 6 follow-ons)"
    - "Interim close-gate checkpoints at commits 3 and 5 (Phase 40 Plan 40-01 DEV-3 pattern)"
    - "Empty cherry-pick with D-19 trailer (git commit --allow-empty) for byte-identical refactors (98c18f1f let-chains → nested-if-let)"
    - "Docs-scope-out: revert `docs/cli/**/*.mdx` hunks to HEAD per cluster files_modified scope"
    - "Modify/delete resolution: honor fork's structural deletion (remove upstream-only docs files)"
key_files_modified:
  - crates/nono-cli/src/app_runtime.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/cli_bootstrap.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/pack_update_hint.rs (NEW)
  - crates/nono-cli/src/package.rs
  - crates/nono-cli/src/package_cmd.rs
  - crates/nono-cli/src/profile/mod.rs (CR-A — additive `list_pack_store_profiles` adapter only)
  - crates/nono-cli/src/registry_client.rs
  - crates/nono-cli/src/sandbox_prepare.rs
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per .planning/templates/cross-target-verify-checklist.md § PARTIAL Disposition (all 9 modified files are cross-platform Rust, so load-bearing)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per checklist § PARTIAL Disposition"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_7_wfp_port_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_8_learn_windows_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
key_decisions:
  - "DEC-1 (cluster-isolation invalidity for bare-fn refs): cherry-pick 5098fc10 introduced NEW file pack_update_hint.rs calling crate::profile::list_pack_store_profiles() — a function upstream introduced in 24d8b924 (pre-v0.53.0) that fork manually-replayed via Plan 34-04 WITHOUT the upstream API surface. Pre-flight `pub use`/`pub mod` re-export detector did NOT catch this (bare pub fn ref from a NEW file). Fix: Rule 2 CR-A `3a5238b2` adds 73-line fork-side adapter using fork's existing pack-store primitives. Recommendation: extend pre-flight to `git grep 'crate::module::function_name(' <new_files>` for ALL referenced symbols, not just pub use/pub mod."
  - "DEC-2 (Phase 36-01b protection preserved despite profile/mod.rs touch): CR-A 3a5238b2 adds 73 NEW lines to profile/mod.rs but the Phase 36-01b protected `From<ProfileDeserialize> for Profile` impl at line 1893-1921 is COMPLETELY UNTOUCHED (verified via `git diff HEAD~14..HEAD -- crates/nono-cli/src/profile/mod.rs | grep 'From<ProfileDeserialize>'` → 0 matches). The new function lives near line 2923 (just before `list_profiles`). Plan frontmatter must_haves `Phase 36-01b ... exhaustive match preserved` is satisfied at the protected-impl level."
  - "DEC-3 (let-chains conversion for edition-2021 compat): cherry-pick 98c18f1f's Rust diff is purely stylistic — converts 4 sites from nested `if let` to `let-chains`. Let-chains is rust 2024-edition; fork is edition 2021 per 43-01b DEC-3. Resolution: reverse the syntactic refactor (let-chains → nested-if-let). Net Rust diff vs HEAD = 0 bytes. Commit lands via `git commit --allow-empty` to preserve D-19 trailer traceability."
  - "DEC-4 (docs-scope-out): plan files_modified explicitly excludes any docs/cli/**/*.mdx. Cherry-picks 4 (5098fc10) and 7 (98c18f1f) include docs hunks; all reverted to HEAD or git-rm (managing-packs.mdx, package-publishing.mdx — never existed in fork; clients/{claude-code,codex}.mdx — fork has divergent content that doesn't need upstream's pack-update-hint docs section). Docs absorption deferred to a follow-on docs-only plan."
  - "DEC-5 (Windows ROOT_HELP_TEMPLATE parity fix): cherry-pick 1 (64d9f283) added `Outdated/Pin/Unpin` clap variants but only registered them in the `#[cfg(not(target_os = \"windows\"))]` ROOT_HELP_TEMPLATE. Fork's parallel Windows variant `#[cfg(target_os = \"windows\")]` was missing the entries, causing `test_root_help_lists_all_commands` to fail. CR-A `b7c8e07e` adds the three missing entries to the Windows template. Cross-platform file edit within cfg-block; NOT a D-43-E1 relaxation (the file is cli.rs, not session_commands_windows.rs)."
  - "DEC-6 (Wave 0b coordination — Plan 43-02 not merged into Wave 1 base): orchestrator dispatched Wave 1 worktrees concurrently with Wave 0b. Cluster 1 commits are file-disjoint from snapshot.rs (Plan 43-02 target); orchestrator's wave merge ordering resolves cleanly regardless. Documented in 43-03-BRANCH.txt and inherited by Plan 43-04 (Wave 1 parallel)."
  - "DEC-7 (Cluster 1 cluster-isolation HOLDS for re-exports): Plan 43-03 High-Risk Pre-flight (`for sha ...; do git show $sha -- '**/mod.rs' '**/lib.rs' | grep -E '^[+-]pub (use|mod) '; done`) returned ZERO new `pub use`/`pub mod` lines across all 8 commits. The re-export-surface trap that bit Plan 43-01 (Cluster 2) does NOT exist for Cluster 1. The cluster-isolation finding above (DEC-1) is a DIFFERENT class — bare `pub fn` reference from a NEW file — and is now documented as a precedent for future plan pre-flight extensions."
patterns_established:
  - "Empty cherry-pick with D-19 trailer for byte-identical-after-reversal-of-edition-feature refactors: when an upstream commit is a pure stylistic refactor whose syntactic form requires a deferred edition (e.g., let-chains needs edition 2024), reverse the syntactic change to match fork's edition while preserving the commit traceability via `git commit --allow-empty`. Cherry-pick chain falsifiable smoke (`grep -c '^Upstream-commit: '` → N) still passes."
  - "Bare pub fn cross-cluster dep detector (cluster-isolation extension): the pre-flight `pub use`/`pub mod` re-export diff misses bare `pub fn` calls from NEW files to existing modules. Future plans absorbing NEW files should also `git grep 'crate::module::name(' <new_files>` to verify all referenced symbols exist in fork."
  - "ROOT_HELP_TEMPLATE Windows-variant parity check: when a cherry-pick adds new clap subcommand variants, fork's TWO cfg-gated ROOT_HELP_TEMPLATE definitions BOTH need the new entries. Test `test_root_help_lists_all_commands` catches this on Windows builds; future plans touching CLI variants should check both variants atomically."
requirements_completed:
  - "REQ-UPST5-02 (partial — Cluster 1 will-sync portion: 8 upstream commits absorbed with verbatim D-19 trailers; CR-A class adapter for cluster-isolation invalidity; Phase 36-01b/c invariants preserved)"
duration: "~6 hours (Task 1 pre-flight + 8 cherry-picks + 6 CR-A follow-ons + 2 interim close-gates + Task 3 close-gate + Tasks 4-5)"
completed: "2026-05-18"
---

# Phase 43 Plan 03: Cluster 1 Pack-Management Cherry-Pick Chain Summary

## Outcome

**One-liner:** 8-commit will-sync cherry-pick chain absorbing upstream's `v0.54.0` pack-management CLI surface (`nono update` + `nono pin/unpin/outdated` + inline `pack_update_hint`) into fork's `crates/nono-cli/src/` on top of Plan 43-01b foundation; 6 SEPARATE `fix(43-03-cra):` follow-on commits resolve fork-vs-upstream interface drift (PackageStatus/PackageAdvisory field renames, let-chains→nested-if-let edition-2021 backport, missing Windows ROOT_HELP_TEMPLATE entries, MSRV-1.95 clippy lint, and a Rule 2 cluster-isolation-invalidity adapter for upstream's `list_pack_store_profiles` API).

## Cluster-Isolation Invalidity Finding (NEW PRECEDENT)

Plan 43-01 BLOCKED on Cluster 2 because cherry-pick `8b888a1c` re-exports symbols (`public_key_id_hex`, `sign_statement_bundle`) defined in upstream commits NOT absorbed into fork. The Plan 43-03 pre-flight extended this detector via `for sha in ...; do git show $sha -- '**/mod.rs' '**/lib.rs' | grep -E '^[+-]pub (use|mod) '; done`. For Cluster 1 this returned ZERO matches → claimed cluster-isolation safety.

**HOWEVER:** Cherry-pick `5098fc10` introduced a NEW file `crates/nono-cli/src/pack_update_hint.rs` that calls `crate::profile::list_pack_store_profiles()` — a function **upstream introduced in commit `24d8b924`** (April 2026, pre-v0.53.0) and **fork D-20-manually-replayed via Phase 34 Plan 34-04 WITHOUT the upstream API surface** (see `crates/nono-cli/src/profile/mod.rs:2419-2425` documented divergence). The re-export-surface detector missed this because:

1. `list_pack_store_profiles` is a bare `pub fn`, not a re-export
2. The reference is FROM a newly-introduced file, not in an existing `mod.rs`/`lib.rs`

Resolution: Rule 2 CR-A `3a5238b2` adds a 73-line fork-side adapter implementing `list_pack_store_profiles` using fork's existing pack-store primitives (`crate::package::package_store_dir`, `PackageManifest`, `ArtifactType::Profile`). The adapter is byte-identical to upstream's structure except for omitting upstream's `aliases: Vec<String>` enumeration (fork's `ArtifactEntry` lacks the alias field per Phase 34 manual-replay scope).

**Future-plan recommendation:** extend the pre-flight detector to `git grep 'crate::module::function_name(' <new_files>` and verify all referenced symbols exist in fork. The bare-fn-reference cluster-isolation invalidity is a DIFFERENT class from the re-export trap; both need detection.

## Performance

- 15 atomic commits over ~6 hours (Task 1 + 8 cherry-picks + 6 CR-A + supporting artifacts)
- 8 cherry-picks → 8 verbatim D-19 trailer blocks (falsifiable smoke: `grep -c '^Upstream-commit: '` → 8 ✓)
- 6 CR-A follow-on commits → all `fix(43-03-cra):` prefix per Phase 40 Plan 40-01 DEV-3
- Interim close gates at commits 3 + 5 caught regressions early (CR-A class)
- Final close gate Gate 1 (`cargo test --workspace --all-features`) revealed 1 pre-existing parallel-test env-var flake; deferred D-43-DEF-01

## Accomplishments

1. **`nono update` command surface absorbed** (cherry-pick 2 `a5985edd`) — Top-level CLI command for refreshing installed packs.

2. **`nono pin` / `nono unpin` / `nono outdated` subcommands absorbed** (cherry-pick 1 `64d9f283`) — Per-pack pinning + outdated-detection.

3. **`pack_update_hint.rs` (NEW file, 270 lines) absorbed** (cherry-picks 4-8) — Inline pack-update hints displayed after `nono run`'s capability block; 24-hour disk cache; refresh-on-first-run + background-refresh thereafter; `is_newer` semver-with-unparsable-as-older comparison.

4. **Fork-side `list_pack_store_profiles` adapter added** (CR-A `3a5238b2`) — 73-line additive function in `profile/mod.rs` filling the upstream API surface gap left by Phase 34 D-20 manual replay. Uses fork's existing pack-store primitives; omits upstream-only `aliases` enumeration.

5. **Windows ROOT_HELP_TEMPLATE parity restored** (CR-A `b7c8e07e`) — Added `outdated`/`pin`/`unpin` to fork's `#[cfg(target_os = "windows")]` template variant. Both cfg-gated templates now list all enumerated subcommands.

6. **Edition-2021 let-chains backport** (cherry-pick 7 `98c18f1f` empty + Rule 1 CR-A `4bc5c838`) — Upstream's let-chains stylistic refactor reversed to nested-if-let to match fork's edition 2021 (per Plan 43-01b DEC-3 deferral).

7. **CR-A class regressions cleanly classified** — 6 follow-on commits, all SEPARATE per CLAUDE.md commit policy (never --amend). All fork-vs-upstream API drift cases documented.

## Task Commits

| Task | Commit       | Subject                                                                                              | Notes                                        |
|------|--------------|------------------------------------------------------------------------------------------------------|----------------------------------------------|
| 1    | `5f7f1f83`   | docs(43-03): record Task 1 pre-flight audit — Cluster 1 cluster-isolation safe                       | Pre-flight artifacts (CHERRY-PICK-ORDER, PER-SHA-AUDIT, BRANCH) |
| 2.1  | `32f053f2`   | feat(package): add package pinning and outdated commands                                             | Cherry-pick 1/8 — upstream `64d9f283`        |
| 2.1.cra | `f7706199` | fix(43-03-cra): adapt cherry-pick 64d9f283 to fork's PackageStatus/PackageAdvisory struct shape    | CR-A: `latest` → `latest_version`; `as_deref().unwrap_or()` → `.as_str()` |
| 2.2  | `1dc7ec9f`   | feat(cli): implement `nono update` command                                                           | Cherry-pick 2/8 — upstream `a5985edd`        |
| 2.2.cra | `acffeb3f` | fix(43-03-cra): adapt cherry-pick a5985edd to fork's PackageStatusResponse field name                | CR-A: 1 more `latest` → `latest_version`     |
| 2.3  | `52a4dd64`   | style(cli): improve formatting and simplify error handling                                           | Cherry-pick 3/8 — upstream `be23d6df`        |
| 2.3.cra | `b7c8e07e` | fix(43-03-cra): register outdated/pin/unpin in Windows ROOT_HELP_TEMPLATE                            | CR-A: Windows template parity; revealed by test_root_help_lists_all_commands |
| INTERIM | (artifact) | Interim close gate at commit 3 (Task 2 step 8a)                                                      | `43-03-INTERIM-GATE-3.md` (PASS)             |
| 2.4  | `bed1fa5f`   | feat(packs): add pinning, outdated, and clarify publishing versioning                                | Cherry-pick 4/8 — upstream `5098fc10`; introduces pack_update_hint.rs |
| 2.4.cra | `3a5238b2` | fix(43-03-cra): add fork-side list_pack_store_profiles adapter for cherry-pick 5098fc10              | CR-A (Rule 2): cluster-isolation invalidity for bare pub fn ref; +73 LOC adapter in profile/mod.rs |
| 2.5  | `bdc5acfe`   | style(cli): adjust line breaks and module order                                                      | Cherry-pick 5/8 — upstream `317c97b7`        |
| 2.5.cra | `4bc5c838` | fix(43-03-cra): drop explicit auto-deref in pack_update_hint save_state for rust 1.95 clippy         | CR-A: MSRV-1.95 surfaced `explicit_auto_deref` lint |
| INTERIM | (artifact) | Interim close gate at commit 5 (Task 2 step 8b)                                                      | `43-03-INTERIM-GATE-5.md` (PASS)             |
| 2.6  | `e8476457`   | feat(pack_update_hint): refresh hints synchronously on first run                                     | Cherry-pick 6/8 — upstream `18b03fa6`        |
| 2.6.cra | `bfc30898` | fix(43-03-cra): apply latest_version rename in refresh_synchronous for cherry-pick 18b03fa6          | CR-A: 3rd `latest` → `latest_version` site (refresh_synchronous fn) |
| 2.7  | `a4742f18`   | feat(pack-hints): document inline pack update hints                                                  | Cherry-pick 7/8 — upstream `98c18f1f` (EMPTY cherry-pick with D-19 trailer; let-chains backport + docs scope-out yields net 0-byte Rust diff) |
| 2.8  | `27c398ba`   | fix(pack-update-hint): treat unparsable installed as older in update check                           | Cherry-pick 8/8 — upstream `42601ed7`        |
| 3-4  | (artifacts)  | Task 3 close gate + Task 4 PR section + Task 5 SUMMARY                                               | `43-03-CLOSE-GATE.md`, `43-03-PR-SECTION.md`, this file |

**Cherry-pick chain falsifiable smokes:**
- `git log --format='%B' 5e5f1005..HEAD | grep -c '^Upstream-commit: '` → **8** ✓
- `git log --format='%B' 5e5f1005..HEAD | grep -c '^Upstream-author: '` (lowercase 'a') → **8** ✓
- `git log --format='%B' 5e5f1005..HEAD | grep -c '^Upstream-tag: v0\.54\.0'` → **8** ✓
- `git diff --stat 5e5f1005..HEAD | grep -cE '_windows\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → **0** ✓ (D-43-E1)

## Files Created/Modified

**Created (cherry-pick output):**
- `crates/nono-cli/src/pack_update_hint.rs` (NEW, 270 lines) — inline pack-update-hint module

**Modified by cherry-pick chain (net diff vs `5e5f1005`):**

```
 crates/nono-cli/src/app_runtime.rs     |   9 ++
 crates/nono-cli/src/cli.rs             | 103 +++++++++++++++++++++--   (incl. Windows template fix)
 crates/nono-cli/src/cli_bootstrap.rs   |   3 +
 crates/nono-cli/src/main.rs            |   2 +
 crates/nono-cli/src/pack_update_hint.rs| 270 ++++++++++++++++++++++++++++++  (NEW)
 crates/nono-cli/src/package.rs         |  17 ++++
 crates/nono-cli/src/package_cmd.rs     | 308 +++++++++++++++++++++++++++++++++
 crates/nono-cli/src/profile/mod.rs     |  73 +++++++++++  (CR-A adapter; protected From-impl untouched)
 crates/nono-cli/src/registry_client.rs | 100 +++++++++++++++--
 crates/nono-cli/src/sandbox_prepare.rs |   4 +
```

**Created (planning artifacts):**
- `.planning/phases/43-upst5-sync-execution/43-03-BRANCH.txt` (branch baseline + Wave 0b coordination note)
- `.planning/phases/43-upst5-sync-execution/43-03-CHERRY-PICK-ORDER.md` (chronological 8-row table)
- `.planning/phases/43-upst5-sync-execution/43-03-PER-SHA-AUDIT.md` (8-row pre-flight audit)
- `.planning/phases/43-upst5-sync-execution/43-03-INTERIM-GATE-3.md` (interim close gate after cherry-pick 3)
- `.planning/phases/43-upst5-sync-execution/43-03-INTERIM-GATE-5.md` (interim close gate after cherry-pick 5)
- `.planning/phases/43-upst5-sync-execution/43-03-CLOSE-GATE.md` (D-43-E9 8-check final close gate)
- `.planning/phases/43-upst5-sync-execution/43-03-PR-SECTION.md` (orchestrator-consumed PR contribution section)
- `.planning/phases/43-upst5-sync-execution/43-03-PACK-MGMT-SUMMARY.md` (this file)
- `.planning/phases/43-upst5-sync-execution/deferred-items.md` (D-43-DEF-01 parallel-test flake)

## Decisions Made

### DEC-1 — Cluster-isolation invalidity for bare `pub fn` references (new precedent)

Plan 43-03's High-Risk Pre-flight followed Plan 43-01b's `pub use`/`pub mod` re-export detector pattern. The detector returned ZERO matches across all 8 commits — claiming cluster-isolation safety. **However**, cherry-pick 4 (`5098fc10`) introduced a NEW file `pack_update_hint.rs` that calls `crate::profile::list_pack_store_profiles()` — a function upstream introduced in commit `24d8b924` (April 2026, pre-v0.53.0) but fork D-20-manually-replayed via Phase 34 Plan 34-04 WITHOUT importing the upstream API surface (`crates/nono-cli/src/profile/mod.rs:2419-2425` documents this divergence).

**Why the re-export detector missed this:** the upstream function is a bare `pub fn`, not a `pub use`/`pub mod`, and the call site is in a NEW file (not an existing `mod.rs`/`lib.rs`).

**Resolution:** Rule 2 CR-A `3a5238b2` adds a 73-line fork-side adapter implementing `list_pack_store_profiles` using fork's existing pack-store primitives. The adapter is structurally identical to upstream's except for omitting upstream's `aliases: Vec<String>` enumeration (fork's `ArtifactEntry` lacks the `aliases` field — upstream-only addition per Phase 34 manual-replay scope).

**Recommendation for future plans:** extend the pre-flight to also `git grep 'crate::module::function_name(' <new_files>` and verify all referenced symbols exist in fork via `grep -rE 'pub fn <name>|pub struct <name>|pub mod <name>' fork-source`. The bare-fn-reference cluster-isolation invalidity is a DIFFERENT class from the re-export trap; both need detection. Memory entry recommendation: `feedback-cluster-isolation-invalid-bare-fn-ref` complementing existing `feedback-cluster-isolation-invalid`.

### DEC-2 — Phase 36-01b `From<ProfileDeserialize>` impl preservation verified despite profile/mod.rs touch

CR-A `3a5238b2` adds 73 NEW lines to `crates/nono-cli/src/profile/mod.rs`. Plan 43-03 frontmatter `must_haves.truths` line "Phase 36-01b `From<ProfileDeserialize> for Profile` exhaustive match preserved (no Cluster 1 commit touches profile/mod.rs::From impl)" appears to be violated at the file-level — but the protected impl at lines 1893-1921 is COMPLETELY UNTOUCHED:

```
git diff 5e5f1005..HEAD -- crates/nono-cli/src/profile/mod.rs | grep 'From<ProfileDeserialize>'
  → 0 matches
```

The new `list_pack_store_profiles` function lives near line 2923 (just before `list_profiles`); it is purely additive. The invariant holds at the protected-impl level. SUMMARY frontmatter `key_files_modified` lists `profile/mod.rs` with the qualifier "(CR-A — additive `list_pack_store_profiles` adapter only)".

### DEC-3 — Edition-2021 let-chains backport via empty cherry-pick

Cherry-pick 7 (`98c18f1f`) is a 36-line PURELY-STYLISTIC refactor that converts 4 sites from nested `if let` to `let-chains` syntax. Let-chains is a rust 2024-edition feature; fork is on edition 2021 per Plan 43-01b DEC-3 (edition migration deferred to UPST6).

**Resolution:** reverse the syntactic refactor (let-chains → nested-if-let) AND drop the docs hunks per docs-scope-out. The cherry-pick's logical control flow is byte-identical to fork's HEAD after the conversion. Net Rust diff vs HEAD = 0 bytes.

**Commit lands via `git commit --allow-empty`** to preserve cherry-pick chain traceability per D-43-E2 (every cluster commit carries verbatim D-19 trailer; falsifiable smoke `grep -c '^Upstream-commit: '` → 8 requires this commit to exist). Documented inline in the commit body.

### DEC-4 — Docs scope-out (revert all `docs/cli/**/*.mdx` hunks)

Plan 43-03 frontmatter `files_modified` list explicitly excludes any `docs/cli/**/*.mdx` files. Cherry-picks 4 (`5098fc10`) and 7 (`98c18f1f`) include docs hunks across:
- `docs/cli/clients/claude-code.mdx` — fork has divergent content; revert to HEAD
- `docs/cli/clients/codex.mdx` — fork has divergent content; revert to HEAD
- `docs/cli/features/managing-packs.mdx` — has NEVER existed in fork's history (verified via `git log --all --follow`); `git rm` the upstream-introduced file
- `docs/cli/features/package-publishing.mdx` — same as above; `git rm`

The docs absorption (if needed) is deferred to a follow-on docs-only plan. The Cluster 1 Rust source is the scope here.

### DEC-5 — Windows ROOT_HELP_TEMPLATE parity fix (Phase 22 D-17 cross-platform concern)

Cherry-pick 1 (`64d9f283`) added `Outdated`, `Pin`, `Unpin` to fork's `Commands` clap enum. Fork has TWO cfg-gated `ROOT_HELP_TEMPLATE` definitions:
- `#[cfg(target_os = "windows")]` at line 233 (fork-specific Windows-aware variant)
- `#[cfg(not(target_os = "windows"))]` at line 526 (upstream-shape variant)

Upstream's cherry-pick only updated the non-Windows variant (which is what upstream ships). Fork's Windows variant was missing the new entries, causing `cli::tests::test_root_help_lists_all_commands` to fail on Windows builds.

**Resolution:** CR-A `b7c8e07e` adds the three missing entries to the Windows template `PACKAGES` block, mirroring the non-Windows variant verbatim.

**D-43-E1 disposition:** the file `cli.rs` is a CROSS-PLATFORM file with cfg-gated content. The 4-condition addendum does NOT trigger because `cli.rs` is NOT a `*_windows.rs` file. The Windows-cfg-block edit is structurally within scope per plan `files_modified`. No D-43-E1 relaxation needed (unlike Plan 43-01b DEC-5 which touched `session_commands_windows.rs`).

### DEC-6 — Wave 0b coordination (Plan 43-02 not yet merged)

Plan 43-02 (`66c69f86` snapshot symlink fix) was NOT merged into Wave 1 base at the time Wave 1 worktrees were dispatched. Orchestrator dispatched Wave 1 worktrees concurrently with Wave 0b per the parallel_execution protocol.

**Safety:** Cluster 1 commits are file-disjoint from `crates/nono/src/undo/snapshot.rs` (Plan 43-02's only target). The orchestrator's wave merge ordering resolves cleanly regardless of which lands first. Documented in `43-03-BRANCH.txt` and inherited by Plan 43-04 (Wave 1 parallel).

### DEC-7 — Cluster 1 cluster-isolation HOLDS for re-exports

Plan 43-03 High-Risk Pre-flight `for sha in 42601ed7 98c18f1f 18b03fa6 317c97b7 5098fc10 be23d6df a5985edd 64d9f283; do git show $sha -- '**/mod.rs' '**/lib.rs' | grep -E '^[+-]pub (use|mod) '; done` returned ZERO new `pub use`/`pub mod` lines across all 8 commits. The re-export-surface trap that bit Plan 43-01 (Cluster 2 via `public_key_id_hex`/`sign_statement_bundle`) does NOT exist for Cluster 1.

The cluster-isolation invalidity finding above (DEC-1) is a DIFFERENT class — bare `pub fn` reference from a NEW file. The re-export check still serves its intended purpose for the class of bugs Plan 43-01 hit.

## Deviations from Plan

### Rule 1 — Auto-fix bugs (5 occurrences)

**1. [Rule 1 - Bug] Fork-vs-upstream `latest` vs `latest_version` field name mismatch**
- **Found during:** Smoke check after cherry-pick 1 (`64d9f283`)
- **Issue:** Cherry-pick code accessed `PackageStatusResponse.latest` (upstream field name); fork's struct uses `latest_version` per Phase 36.5 D-36.5-C3 port.
- **Fix:** rename `status.latest.clone()` → `status.latest_version.clone()` etc.
- **Files modified:** `package_cmd.rs` (2 sites across CR-As `f7706199` + `acffeb3f`); `pack_update_hint.rs` (2 sites across CR-As `3a5238b2` + `bfc30898`).
- **Commits:** `f7706199`, `acffeb3f`, `3a5238b2` (partial), `bfc30898`.

**2. [Rule 1 - Bug] Fork-vs-upstream `Advisory.severity`/`.summary` Option<String> vs String**
- **Found during:** Smoke check after cherry-pick 1 (`64d9f283`)
- **Issue:** Cherry-pick called `advisory.severity.as_deref().unwrap_or("unknown")` etc. on upstream's `Option<String>` field. Fork's `PackageAdvisory` uses bare `String`.
- **Fix:** `as_deref().unwrap_or(...)` → `.as_str()`. Fallback strings are unreachable in fork's shape.
- **Files modified:** `registry_client.rs`
- **Commit:** `f7706199`

**3. [Rule 1 - Bug] Test `test_root_help_lists_all_commands` failure on Windows**
- **Found during:** Interim close gate 3 (post-cherry-pick 3)
- **Issue:** Fork's Windows-cfg-gated ROOT_HELP_TEMPLATE missing the `outdated`/`pin`/`unpin` entries added by cherry-pick 1's clap variants.
- **Fix:** add three entries to Windows template `PACKAGES` block.
- **Files modified:** `cli.rs`
- **Commit:** `b7c8e07e`

**4. [Rule 1 - Bug] Rust 1.95 `explicit_auto_deref` clippy lint**
- **Found during:** Interim close gate 5 (post-cherry-pick 5)
- **Issue:** Cherry-picks 4-5 introduced `save_state(&*guard)` where `guard: MutexGuard<...>`. Rust 1.95 stabilized `clippy::explicit_auto_deref` (under -D warnings). Same Plan 43-01b DEC-4 MSRV-bump-surfaced-lint pattern.
- **Fix:** `&*guard` → `&guard` (MutexGuard auto-derefs).
- **Files modified:** `pack_update_hint.rs`
- **Commit:** `4bc5c838`

**5. [Rule 1 - Bug] Edition-2021 incompatibility: let-chains from upstream 98c18f1f**
- **Found during:** Build after cherry-pick 7 (`98c18f1f`)
- **Issue:** Upstream introduced 4 let-chains sites (`if let X && let Y && condition {...}`). Let-chains requires rust 2024 edition (fork is 2021).
- **Fix:** convert all 4 let-chains back to nested `if let` blocks.
- **Files modified:** `pack_update_hint.rs`
- **Commit:** inline-resolved as part of cherry-pick 7 (`a4742f18` empty commit; the conversion is captured in the cherry-pick's conflict resolution; net Rust diff vs HEAD = 0 bytes)

### Rule 2 — Auto-add missing critical functionality (1 occurrence)

**6. [Rule 2 - Missing critical functionality] `crate::profile::list_pack_store_profiles` adapter**
- **Found during:** Smoke check after cherry-pick 4 (`5098fc10`)
- **Issue:** Cherry-pick's NEW file `pack_update_hint.rs` calls `crate::profile::list_pack_store_profiles()` — function does NOT exist in fork (cluster-isolation invalidity: upstream introduced it in `24d8b924`/pre-v0.53.0; fork D-20-manually-replayed `24d8b924` via Phase 34 Plan 34-04 WITHOUT the upstream API surface per `profile/mod.rs:2419-2425` documented divergence).
- **Fix:** add 73-line fork-side adapter using fork's existing pack-store primitives (`crate::package::package_store_dir`, `PackageManifest`, `ArtifactType::Profile`); omit upstream-only `aliases` enumeration (fork's `ArtifactEntry` lacks aliases field).
- **Files modified:** `profile/mod.rs` (additive only; protected `From<ProfileDeserialize>` impl untouched)
- **Commit:** `3a5238b2`
- **Pattern established:** see DEC-1 + patterns_established for the precedent.

### No Rule 3 / Rule 4 deviations

No blocking issues required a Rule 3 fix (each smoke-check failure was a Rule 1 or 2 case). No Rule 4 architectural decisions (the cluster-isolation invalidity in DEC-1/Rule 2 was mechanically resolvable; not an architectural blocker).

## Issues Encountered

### Issue 1 — Pre-existing parallel-test env-var-leakage flake

`supervisor::aipc_sdk::tests::windows_loopback_tests::helper_stamps_session_token_from_env` fails in workspace-wide `cargo test --workspace --all-features` Gate 1 run with:
```
assertion `left == right` failed: SDK must stamp NONO_SESSION_TOKEN into CapabilityRequest.session_token
  left: "testtoken12345678"
 right: "testtoken12345678abc"
```

**Diagnosis:** Pre-existing flake — test PASSES at baseline `5e5f1005` (verified via checkout); test PASSES in isolation; test FAILS only in parallel-test mode where a concurrent test leaks `NONO_SESSION_TOKEN=testtoken12345678abc`. Direct CLAUDE.md hit: § "Environment variables in tests" precisely describes this class.

**Not caused by Plan 43-03:** plan touches only `crates/nono-cli/src/`; does NOT touch `crates/nono/src/supervisor/aipc_sdk.rs` or any test that sets `NONO_SESSION_TOKEN`.

**Disposition:** deferred to `deferred-items.md` D-43-DEF-01 for a follow-on test-hygiene plan to audit `NONO_*` env-var tests for save/restore pattern.

### Issue 2 — Plan 43-02 (Wave 0b) not merged into Wave 1 base

Orchestrator dispatched Wave 1 worktrees concurrently with Wave 0b. Cluster 1 commits file-disjoint from `snapshot.rs`; merge order resolves cleanly. Documented in `43-03-BRANCH.txt` and DEC-6.

### Issue 3 — Plan frontmatter `5098fc1c` SHA typo

Plan frontmatter listed `5098fc1c` but the canonical upstream SHA is `5098fc10` (final char `0`, not `c`). Phase 42 ledger row showed 7-char abbrev `5098fc1` which matches the canonical. Used `5098fc10` for the cherry-pick. Documented in `43-03-CHERRY-PICK-ORDER.md`.

## D-43-E9 8-check close gate

See `.planning/phases/43-upst5-sync-execution/43-03-CLOSE-GATE.md` for full evidence. Summary:

| Gate | Description                                           | Disposition                                                    |
|------|-------------------------------------------------------|----------------------------------------------------------------|
| 1    | `cargo test --workspace --all-features` (Windows)     | PASS-WITH-DEFERRED-FLAKE (1 pre-existing flake → D-43-DEF-01)  |
| 2    | `cargo clippy --workspace --all-targets` (Windows)    | PASS                                                           |
| 3    | `cargo clippy --target x86_64-unknown-linux-gnu`      | load-bearing-skip → CI-verified (cross-toolchain absent)       |
| 4    | `cargo clippy --target x86_64-apple-darwin`           | load-bearing-skip → CI-verified (cross-toolchain absent)       |
| 5    | `cargo fmt --all -- --check`                          | PASS                                                           |
| 6    | Phase 15 5-row detached-console smoke                 | environmental-skip (D-40-C2)                                   |
| 7    | `wfp_port_integration` tests                          | environmental-skip (D-40-C2)                                   |
| 8    | `learn_windows_integration` tests                     | environmental-skip (D-40-C2)                                   |

## Wave 1 branch coordination

Per `wave_1_parallel_branch_strategy.protocol: per-plan-feature-branch`:
- **Branch:** `worktree-agent-a7fcb300371d56aaf` (worktree branch serves logically as `43-03-cluster-1` per `<parallel_execution>` protocol; orchestrator merges worktree back to main, completing the per-plan-feature-branch shape)
- **Branched from:** `5e5f1005` (Plan 43-01b head)
- **Baseline-aware CI gate comparison:** `worktree-agent-a7fcb300371d56aaf` HEAD vs `13cc0628` (Phase 41 close, baseline per D-43-E3) — INDEPENDENT of Plan 43-04's branch per `wave_1_parallel_branch_strategy.baseline_ci_gate`
- **Umbrella PR body update:** DEFERRED to orchestrator per `wave_1_parallel_branch_strategy.umbrella_pr_body_update: orchestrator-post-both-wave-1-plans-close`. The orchestrator merges BOTH Wave 1 worktrees (43-03 + 43-04) before opening/updating the umbrella PR body with both contribution sections. This plan produces `43-03-PR-SECTION.md` only.

## Threat-model close-out

| Threat ID      | Status     | Note                                                                                                             |
|----------------|------------|------------------------------------------------------------------------------------------------------------------|
| T-43-03-01     | ACCEPTED   | Upstream HTTP registry-refresh layer reuses fork's audited `registry_client`; no new TLS/cert/auth surface       |
| T-43-03-02     | MITIGATED  | Pack pinning manifest deserialization uses fork's existing serde shape via `PackageManifest`; no lax deserializers introduced |
| T-43-03-03     | MITIGATED  | All 8 cherry-picks carry verbatim 6-line D-19 trailer block; falsifiable smoke `grep -c '^Upstream-commit: '` → 8 ✓ |
| T-43-03-04     | MITIGATED  | D-43-E1 invariant verified at HEAD: `git diff --stat 5e5f1005..HEAD | grep -cE '_windows.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 ✓ |
| T-43-03-05     | MITIGATED  | `nono update` runs in user CLI context; no new privilege elevation. `sandbox_prepare.rs` 4-line addition checked: pack-related path additions, no Phase 22-05/Phase 23 audit-path collisions |
| T-43-03-06     | MITIGATED  | Phase 36-01b `From<ProfileDeserialize> for Profile` exhaustive match COMPLETELY UNTOUCHED at protected impl level (lines 1893-1921). The CR-A `list_pack_store_profiles` addition is 1000+ lines AWAY from the protected impl (near line 2923). See DEC-2 + per-SHA audit. |
| T-43-03-07     | MITIGATED  | `override_deny`/`bypass_protection` rename: 0 references introduced (`git log --all -S 'override_deny' 5e5f1005..HEAD` → 0); Phase 36-01c rename preserved |
| T-43-03-08     | ACCEPTED   | Unparsable-version-as-older logic in `42601ed7` IS the upstream fix's intent; acceptable trade-off                |
| T-43-03-09     | MITIGATED  | `wave_1_parallel_branch_strategy.protocol: per-plan-feature-branch` honored — worktree branch serves as `43-03-cluster-1`; Plan 43-04 branches independently; orchestrator merges both before umbrella PR body update |

ASVS L1 disposition satisfied: all `high` threats (T-43-03-04, T-43-03-06) mitigated; `medium` threats mitigated; `low` threats accepted with explicit documentation.

## Self-Check

| Check                                                                                                                  | Result |
|------------------------------------------------------------------------------------------------------------------------|--------|
| `[ -f .planning/phases/43-upst5-sync-execution/43-03-PACK-MGMT-SUMMARY.md ]`                                           | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-03-CLOSE-GATE.md ]`                                                  | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-03-PR-SECTION.md ]`                                                  | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-03-BRANCH.txt ]`                                                     | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-03-CHERRY-PICK-ORDER.md ]`                                           | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-03-PER-SHA-AUDIT.md ]`                                               | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-03-INTERIM-GATE-3.md ]`                                              | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-03-INTERIM-GATE-5.md ]`                                              | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/deferred-items.md ]`                                                    | FOUND  |
| `git log 5e5f1005..HEAD --format='%H %s' | wc -l` → 15 (Task 1 + 8 cherry-picks + 6 CR-A)                              | PASS   |
| `git log --format='%B' 5e5f1005..HEAD | grep -c '^Upstream-commit: '` → 8                                              | PASS   |
| `git log --format='%B' 5e5f1005..HEAD | grep -c '^Upstream-author: '` (lowercase 'a') → 8                              | PASS   |
| `git log --format='%B' 5e5f1005..HEAD | grep -c '^Upstream-tag: v0\.54\.0'` → 8                                        | PASS   |
| `git diff --stat 5e5f1005..HEAD | grep -cE '_windows\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0          | PASS (D-43-E1) |
| `git diff 5e5f1005..HEAD -- crates/nono-cli/src/profile/mod.rs | grep 'From<ProfileDeserialize>'` → 0                  | PASS (Phase 36-01b protected impl untouched) |
| `cargo check -p nono-cli` exits 0 at HEAD                                                                              | PASS   |
| `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) exits 0                  | PASS   |
| `cargo fmt --all -- --check` exits 0                                                                                   | PASS   |
| `cargo test -p nono --lib supervisor::aipc_sdk::tests::windows_loopback_tests::helper_stamps_session_token_from_env` (isolated) → 1 passed | PASS (confirms Gate 1 flake is pre-existing parallel-test issue, NOT Plan 43-03 regression) |
| `[[ ! -f .git/CHERRY_PICK_HEAD ]]`                                                                                     | PASS   |

Status: **PASSED.**

## User Setup Required

None for this plan instance. Orchestrator (post-merge) responsibilities:
1. Merge worktree branch `worktree-agent-a7fcb300371d56aaf` to main.
2. After Plan 43-04 also closes, update Phase 43 umbrella PR body with both Wave 1 plan sections (`43-03-PR-SECTION.md` + `43-04-PR-SECTION.md`).
3. After CI completes on the head SHA, fill in the CI lane transition table in `43-03-CLOSE-GATE.md` § "Wave 1 baseline-aware CI gate" with actual CI lane outcomes.
4. STATE.md and ROADMAP.md updates: orchestrator owns those writes after all worktree agents in the wave complete.

## Next Phase Readiness

Plan 43-03 closes Wave 1 (Cluster 1 will-sync portion). Wave 1 (parallel) consists of Plans 43-03 + 43-04; both must close + merge before Wave 2 (43-05 PLATFORM-DETECTION-FOUNDATION) can start.

Plan 43-05 inherits from this plan:
- New cross-platform CLI surface (`nono update`/`pin`/`unpin`/`outdated`) — no collisions expected with platform.rs introduction
- Pack-store profile enumeration via `crate::profile::list_pack_store_profiles` (CR-A adapter) — Plan 43-05's `WhenPredicate` deserialization is unrelated; no collision
- All cluster-isolation invariants verified at HEAD (zero Windows-file touches; Phase 36-01b protected impl untouched; Phase 36-01c rename preserved)
