# Phase 43: UPST5 sync execution - Pattern Map

**Mapped:** 2026-05-17
**Files analyzed:** 6 plans (43-01..43-06) + supporting code touchpoints
**Analogs found:** 6/6 plan analogs + 5/5 code-touchpoint analogs

## How to read this document

Phase 43 is NOT a feature phase. It is an upstream-sync execution phase that mirrors Phase 34 + Phase 40 verbatim. The "files to create or modify" are determined by upstream commits in `v0.53.0..v0.54.0`, not by fork-side design.

Each plan in Phase 43 produces:
- One PLAN.md and one SUMMARY.md in `.planning/phases/43-upst5-sync-execution/`
- A series of cherry-pick (or D-20 manual-replay) commits on fork's `main` (or a per-plan branch feeding into an umbrella PR)
- A contribution section appended to the umbrella PR body

The patterns mapped here therefore have two distinct shapes:
1. **Plan-skeleton patterns** — what each PLAN.md / SUMMARY.md must contain. Source: Phase 40 SUMMARYs (closest analogs by plan shape).
2. **Code-touchpoint patterns** — concrete fork-side artifacts the cherry-picks land on (Cargo.toml workspace, `profile/mod.rs` From impl, `snapshot.rs`, candidate analog for `platform.rs`).

---

## File Classification

### Plans (PLAN.md / SUMMARY.md pairs)

| Plan to be created | Role | Data Flow | Closest Phase 40 analog | Match Quality |
|--------------------|------|-----------|--------------------------|---------------|
| `43-01-EDITION-2024-FOUNDATION-PLAN.md` | sequential-gate single-cluster plan | atomic cherry-pick + Cargo.toml workspace edit | Phase 34 `34-04-PATH-CANON-SCHEMA` (Wave 0 sequential gate) + Phase 40 `40-01-PROXY-HARDENING` skeleton; no MSRV-bump analog exists | partial — skeleton match only; MSRV bump is novel |
| `43-02-SNAPSHOT-SYMLINK-FIX-PLAN.md` | single-commit will-sync cherry-pick | one upstream SHA → one commit | Phase 40 `40-02-CLI-ALLOW-VALIDATE` (Wave-0-equivalent single-area focused cherry-pick); Phase 40 `40-01-PROXY-HARDENING` for the trailer + close-gate skeleton | role match (single cluster, will-sync) |
| `43-03-PACK-MGMT-PLAN.md` | multi-commit will-sync cherry-pick chain | 8 commits, surface = `crates/nono-cli/src/` pack/CLI | Phase 40 `40-01-PROXY-HARDENING` (5-commit cherry-pick chain with D-19 trailers + Wave-1 baseline-aware CI gate + CR-A class regression handling) | exact — 8 vs 5 commits but identical pattern |
| `43-04-RELEASE-RIDE-PLAN.md` | release-ride + dep bump | CHANGELOG + nix dep absorption; reverts Cargo.toml version bumps | Phase 40 `40-04-RELEASE-RIDE` (precedent commit `64b231a7` for upstream v0.52.0; `8c7f9fda` for fork v2.3 pin) | exact — same pattern verbatim |
| `43-05-PLATFORM-DETECTION-FOUNDATION-PLAN.md` | fork-preserve default with diff-inspection-first upgrade authority; introduces NEW file `crates/nono-cli/src/platform.rs` (~659 lines) + extends `profile/mod.rs::WhenPredicate` + `wiring.rs` + `policy.rs` | single SHA `ce06bd59`; diff-inspection task at plan-open per D-43-C1 (Phase 40 D-40-B1 pattern) | Phase 40 `40-05-FP-PROFILE-SAVE` (D-20 manual replay with disposition resolution task + serde-alias discipline + From-impl exhaustive enumeration) | exact — D-40-B1 pattern; Cluster 5's WhenPredicate extension mirrors Plan 36-01b's CommandsConfig extension |
| `43-06-PLATFORM-DETECTION-WINDOWS-PLAN.md` | fork-preserve default with diff-inspection-first upgrade authority; builds on Cluster 5's platform.rs | 2 commits (`0748cced` + `5d821c12`); Windows registry queries + REG_DWORD fix | Phase 40 `40-06-FP-PROXY-TLS` (terminal-Wave-2 D-20 plan that also handles the Windows-fallback decision; D-40-B2 LOCK rationale; replay-when-surface-structurally-absent shape) | exact — D-40-B1/B2 pattern with sequential dependency on Cluster 5 |

### Code touchpoints (fork-side files modified by Phase 43 cherry-picks)

| File touched by Phase 43 | Cluster / Plan | Role | Data Flow | Closest existing analog | Match Quality |
|--------------------------|----------------|------|-----------|--------------------------|---------------|
| `Cargo.toml` (workspace root) + 5 crate `Cargo.toml` | Cluster 2 / Plan 43-01 | workspace config | edition + MSRV declaration via `edition.workspace = true` | self (existing shape at lines 11-17 of root `Cargo.toml`) | exact — same file, edit edition + rust-version lines atomically |
| `crates/nono/src/undo/snapshot.rs` | Cluster 7 / Plan 43-02 | core lib snapshot module | single-commit cherry-pick (security fix) | self (existing 1100+ line file; cherry-pick lands on top) | n/a — direct cherry-pick onto existing file |
| `crates/nono-cli/src/platform.rs` (NEW) | Cluster 5 / Plan 43-05 | module-level cross-platform detection utility | new file ~659 lines | `crates/nono-cli/src/instruction_deny.rs` (cross-platform module with cfg-gated per-platform implementations + cross-platform no-op default) AND `crates/nono-cli/src/trust_scan.rs` (cross-platform module taking `&Path` and returning `Result<TrustPolicy>`) | role match — both are cross-platform modules with cfg-gated implementations |
| `crates/nono-cli/src/profile/mod.rs::From<ProfileDeserialize> for Profile` | Cluster 5 / Plan 43-05 | trait impl with exhaustive struct-literal field enumeration | extends to include WhenPredicate-deserialized field | Phase 36-01b extended this same impl for `commands: CommandsConfig` (lines 1893-1921 today) | exact — same impl, same exhaustive-enumeration pattern, MUST NOT collide |
| `crates/nono-cli/src/wiring.rs` + `crates/nono-cli/src/policy.rs` | Cluster 5 / Plan 43-05 | wiring + policy extensions | conditional evaluation thread-through | `crates/nono-cli/src/policy.rs::Group::platform: Option<String>` already at lines 39-46 — existing platform-conditional concept | partial — Group::platform already conditions by platform string; WhenPredicate extends to richer predicate shape |

---

## Pattern Assignments

### Plan 43-01-EDITION-2024-FOUNDATION (Cluster 2, single SHA `8b888a1c`)

**Plan-skeleton analog:** Phase 40 `40-01-PROXY-HARDENING-SUMMARY.md` for the trailer + close-gate skeleton; Phase 40 `40-04-RELEASE-RIDE-SUMMARY.md` for Cargo.toml conflict-resolution discipline.

**Novel work (no analog):** MSRV bump 1.77 → 1.85+ atomic with the edition-2024 cherry-pick. Planner verifies upstream's exact MSRV at cherry-pick time by reading upstream's `Cargo.toml` workspace section (D-43-B2).

**Cargo.toml workspace edit target** (root `Cargo.toml`, lines 11-17):

```toml
[workspace.package]
edition = "2021"
rust-version = "1.77"
authors = ["Luke Hinds"]
license = "Apache-2.0"
repository = "https://github.com/always-further/nono"
homepage = "https://github.com/always-further/nono"
```

Per memory `project_workspace_crates`: all 5 member crates declare `edition.workspace = true` + `rust-version.workspace = true` (verified in `crates/nono/Cargo.toml:4-5`, `crates/nono-cli/Cargo.toml:4-5`, `crates/nono-proxy/Cargo.toml:4-5`, `crates/nono-shell-broker/Cargo.toml:4-5`, `bindings/c/Cargo.toml:4-5`). Atomic edit of the workspace block propagates to all 5 crates.

**D-19 trailer block (mandatory; per `.planning/templates/upstream-sync-quick.md:241-247`):**

```
Upstream-commit: 8b888a1c
Upstream-tag: v0.54.0
Upstream-author: <upstream name> <upstream email>
Co-Authored-By: <upstream name> <upstream email>
Signed-off-by: <fork author name> <fork author email>
Signed-off-by: <fork author handle> <fork author email>
```

**Cargo.toml conflict-resolution pattern** (from Phase 40 Plan 40-04 SUMMARY, DEV-2): if upstream's `8b888a1c` ALSO bumps the workspace version (it shouldn't — edition migration is feature commit, not release commit — but verify at cherry-pick time), apply the Phase 34 release-commit convention selectively:

> `git checkout HEAD -- Cargo.toml Cargo.lock bindings/c/Cargo.toml crates/nono/Cargo.toml crates/nono-cli/Cargo.toml crates/nono-proxy/Cargo.toml crates/nono-shell-broker/Cargo.toml` to revert version-bump hunks while KEEPING edition + rust-version changes.

NOTE: the Phase 40 release-ride convention (revert Cargo.toml entirely) does NOT apply here — Cluster 2 is a feature commit, not a release-bump. Only revert version hunks if accidentally present.

---

### Plan 43-02-SNAPSHOT-SYMLINK-FIX (Cluster 7, single SHA `66c69f86`)

**Plan-skeleton analog:** Phase 40 `40-02-CLI-ALLOW-VALIDATE-SUMMARY.md` (single-area focused cherry-pick with minimal conflict surface) + Phase 40 `40-01-PROXY-HARDENING-SUMMARY.md` for the trailer + close-gate skeleton.

**Code-touchpoint:** `crates/nono/src/undo/snapshot.rs` — existing 1100+ line file (header confirmed at lines 1-39 of the current file). Single cherry-pick lands on top.

**Security context (CLAUDE.md § Path Handling):** This is a TOCTOU race fix — an attacker creating a symlink between snapshot-taken and restore-invoked could redirect the restore write outside the tracked directory. The cherry-pick must honor CLAUDE.md § Common Footguns #1 (no string `starts_with` on paths; component-wise `Path::components()` iteration).

**D-19 trailer block** (verbatim 6-line shape per `.planning/templates/upstream-sync-quick.md:241-247`):

```
Upstream-commit: 66c69f86
Upstream-tag: v0.54.0
Upstream-author: <upstream name> <upstream email>
Co-Authored-By: <upstream name> <upstream email>
Signed-off-by: <fork author name> <fork author email>
Signed-off-by: <fork author handle> <fork author email>
```

**Close-gate (from Phase 40 Plan 40-01 SUMMARY, lines 148-161 verbatim 8-check):** Plan 43-02 inherits the full 8-check table. Gates 3+4 cross-target clippy must be categorized per Phase 40 anti-pattern #3 (`skipped_gates_load_bearing: [3, 4]` in SUMMARY frontmatter — cross-target clippy needed on `crates/nono/src/undo/snapshot.rs` because it's cross-platform Rust code).

---

### Plan 43-03-PACK-MGMT (Cluster 1, 8 commits on `crates/nono-cli/src/`)

**Plan-skeleton analog:** Phase 40 `40-01-PROXY-HARDENING-SUMMARY.md` — the closest match for a multi-commit cherry-pick chain across a single subsystem with baseline-aware CI gating.

**Cherry-pick chain pattern** (from 40-01 SUMMARY § "Task Commits", lines 82-92):

```
1. Task 2 cherry-pick 1/N: <upstream_sha_1> — <subject> → <fork_sha_1>
2. Task 2 cherry-pick 2/N: <upstream_sha_2> — <subject> → <fork_sha_2>
...
N. Task 2 cherry-pick N/N: <upstream_sha_N> — <subject> → <fork_sha_N>
```

**Critical ordering rule** (from 40-01 SUMMARY DEV-1, lines 113-119):

> Cherry-picks applied in TRUE upstream chronological order (commit date), not in the plan's listed-table order. Plan frontmatter `must_haves.truths` mandates chronological — that takes precedence over the action block when the two disagree.

Verify: `git log -1 --format='%H %ai %s' <sha>` for each of the 8 SHAs at plan-open; sort chronologically.

**CR-A class regression handling** (from 40-01 SUMMARY DEV-3, lines 129-134):

> If the Wave 1 baseline-aware CI gate catches a `success → failure` transition caused directly by a cherry-pick (e.g., feature-graph dead-code unmasked by `default-features = false`), classify as Rule 1 (mechanical, minimal-scope fix). Land the fix as a separate follow-on commit (NOT --amend) with explicit `fix(43-03): ...` prefix citing the CR-A class.

**D-19 trailer on EVERY cherry-pick** — falsifiable smoke: `git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: '` must equal 8.

**Umbrella PR body assembly** (D-43-E6 / memory `project_cross_fork_pr_pattern`): Plan 43-03 close appends a contribution section to the Phase 43 umbrella PR body. Section template (per Phase 40):

```
## Plan 43-03 (Cluster 1: pack management)

- Range: v0.53.0..v0.54.0 (8 commits)
- Disposition: will-sync (D-19 cherry-pick)
- Surface: crates/nono-cli/src/ pack + CLI
- Key decisions: [list]
```

---

### Plan 43-04-RELEASE-RIDE (Cluster 3, 2 commits: CHANGELOG + nix dep bump)

**Plan-skeleton analog:** Phase 40 `40-04-RELEASE-RIDE-SUMMARY.md` — verbatim. Cluster 3's commit `6b00932f chore: release v0.54.0` is the direct analog of Phase 40's c4b25b8 chore: release v0.53.0.

**Release-ride convention pattern** (from 40-04 SUMMARY DEV-2, lines 119-127):

> Each release commit modifies `Cargo.toml` + `Cargo.lock` + all crate-level `Cargo.toml` files to bump version. Fork tracks own version (currently `0.53.0` across all 5 crate Cargo.toml files — verified at `Cargo.toml:1-9`, `crates/nono/Cargo.toml:3`, `crates/nono-cli/Cargo.toml:3`, `crates/nono-proxy/Cargo.toml:3`, `crates/nono-shell-broker/Cargo.toml:3`, `bindings/c/Cargo.toml:3`).
>
> Apply convention:
> ```
> git checkout HEAD -- Cargo.toml Cargo.lock bindings/c/Cargo.toml \
>   crates/nono/Cargo.toml crates/nono-cli/Cargo.toml \
>   crates/nono-proxy/Cargo.toml crates/nono-shell-broker/Cargo.toml
> ```
> Resolve CHANGELOG.md conflict manually (keep fork's existing entries; insert upstream's new entry in chronological position).
> `git add CHANGELOG.md && git -c core.editor=true cherry-pick --continue`

**Document reverted hunks explicitly** in each release-commit body under "Reverted from upstream's release commit:" section (per D-43-E10 + Phase 40 precedent).

**Skipped-gate categorization** (from 40-04 SUMMARY DEC-4, lines 105 + close-gate at 142-153): release-ride is CHANGELOG-only; gates 6-8 are `skipped_gates_environmental`; gates 3+4 still `skipped_gates_load_bearing` for the nix dep bump on Linux/macOS targets.

**Workspace deps to verify** (root `Cargo.toml:19-55`): nix is NOT in workspace deps today (per-crate declaration in `crates/nono-cli/Cargo.toml:86,92` + `crates/nono/Cargo.toml:50,54`). If upstream's `chore(deps): bump nix` lands in workspace deps, fork must port it to per-crate declarations OR introduce a workspace `nix` entry first.

---

### Plan 43-05-PLATFORM-DETECTION-FOUNDATION (Cluster 5, single SHA `ce06bd59`; fork-preserve default, upgrade authority)

**Plan-skeleton analog:** Phase 40 `40-05-FP-PROFILE-SAVE-SUMMARY.md` — exact match for D-20 manual replay with disposition-resolution task at plan-open + serde-alias discipline + From-impl exhaustive-enumeration check.

**Diff-inspection-first task at plan-open** (from 40-05 SUMMARY § "Disposition resolution", DEC-1, lines 111):

> Trial cherry-pick `<sha>` to a scratch branch. If zero content conflicts AND zero modify/delete AND identical surface semantics → upgrade to `will-sync` (D-19 trailer). Otherwise: stay D-20 manual replay. Decision documented inline in PLAN.md `## Disposition resolution (D-43-C1)` section before any Task 2 code change.

For Plan 43-05 specifically, the diff-inspection MUST answer these surface-overlap questions (Q-Series mirrors Phase 40 D-40-B1):

- Q1: Does upstream `ce06bd59` touch `crates/nono-cli/src/terminal_approval.rs`? (Phase 18.1 D-04-locked surface — `build_prompt_text + HandleKind`, current count = 45 matches per 40-05 SUMMARY.)
- Q2: Does upstream `ce06bd59` touch `crates/nono-cli/src/profile/mod.rs::From<ProfileDeserialize> for Profile`? **YES** — Cluster 5's WhenPredicate field extends this impl. **Collision risk with Phase 36-01b's `CommandsConfig` extension MUST be verified** (see below).
- Q3: Does upstream `ce06bd59` touch `crates/nono-cli/src/policy.rs`? **YES** (28 lines per CONTEXT.md). Existing `Group::platform: Option<String>` at `policy.rs:43-46` is the pre-existing platform-conditional concept.
- Q4: Does upstream `ce06bd59` touch `crates/nono-cli/src/wiring.rs`? **YES** (126 lines per CONTEXT.md). Existing wiring.rs is Plan 36-02 yaml-merge directive surface (header at `wiring.rs:1-24`); extending it with conditional evaluation is a coexistence question.
- Q5: Does upstream `ce06bd59` reference the pre-rename name `override_deny`? Per Phase 36-01c (Plan 36-01c SUMMARY, lines 78-79), the canonical fork name is `bypass_protection`. If upstream still uses `override_deny`, cherry-pick MUST rename arm-by-arm. Verify via `git show ce06bd59 | grep -E 'override_deny|bypass_protection'`.
- Q6: Does upstream `ce06bd59` collide with the Plan 36-01b `commands: CommandsConfig` enumeration (current shape at `profile/mod.rs:1893-1921` below)?

**Current `From<ProfileDeserialize> for Profile` shape (MUST NOT collide)** — from `crates/nono-cli/src/profile/mod.rs:1893-1921`:

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
            // Exhaustively enumerated here so rustc's struct-literal completeness
            // check (T-36-01-CANONICAL) catches any future field additions.
            commands: raw.commands,
        }
    }
}
```

Cluster 5's WhenPredicate field (if it's a new struct field) extends this impl by adding ONE MORE arm. The pattern to follow (from Phase 36-01b SUMMARY § "From<ProfileDeserialize> Diff Snippet", lines 138-156):

```rust
// After (add new canonical section):
            packs: raw.packs,
            command_args: raw.command_args,
            commands: raw.commands,
            // Plan 43-05: WhenPredicate-bearing field per upstream ce06bd59 (v0.54.0).
            // Exhaustively enumerated here so rustc catches future field additions.
            <new_field>: raw.<new_field>,
        }
    }
}
```

**`override_deny → bypass_protection` rename precedent** (Phase 36-01c SUMMARY DEV-2, lines 128-133): if upstream cherry-pick mechanically renames `bypass_protection` → `override_deny` (or references `override_deny` as a field name), the fork's canonical post-rename name is `bypass_protection`. Serde alias direction (Phase 36-01c § "Serde alias direction after rename", line 67):

> Canonical field name is the Rust identifier; old name lives in alias string: `#[serde(default, alias = "override_deny")]` on `bypass_protection`.

**NEW file `crates/nono-cli/src/platform.rs` (~659 lines) — closest analog selection:**

The closest existing fork-side analog for a NEW module-level file that owns runtime platform detection is **`crates/nono-cli/src/instruction_deny.rs`** (cross-platform module with cfg-gated per-platform implementations + cross-platform no-op default). Excerpt from `instruction_deny.rs:1-60`:

```rust
//! Write-protection rules for verified files (macOS Seatbelt)
//!
//! After the pre-exec trust scan verifies files, this module injects
//! literal `(deny file-write-data ...)` rules into the Seatbelt profile
//! for each verified file. This makes verified files structurally immutable
//! at the kernel level — the agent cannot tamper with them even though the
//! parent directory has write access granted.

use nono::CapabilitySet;
use nono::Result;
#[cfg(target_os = "macos")]
use std::path::Path;

/// Write-protect verified files in the Seatbelt profile.
/// ...
#[cfg(target_os = "macos")]
pub fn write_protect_verified_files(
    caps: &mut CapabilitySet,
    verified_paths: &[std::path::PathBuf],
) -> Result<()> {
    for path in verified_paths {
        add_literal_write_deny(caps, path)?;
    }
    Ok(())
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn write_protect_verified_files(
    _caps: &mut CapabilitySet,
    _verified_paths: &[std::path::PathBuf],
) -> Result<()> {
    Ok(())
}
```

Key pattern elements that platform.rs cherry-pick should preserve:
- Module-level `//!` doc comment explaining purpose
- `use nono::{CapabilitySet, Result, NonoError}` style for fork's library re-exports
- `#[cfg(target_os = "...")]` per-platform implementations
- `#[cfg(not(target_os = "..."))]` no-op fallback
- Conservative `pub` exports (only what callers need)

**Module registration** — Cluster 5's `platform.rs` must be declared in `crates/nono-cli/src/main.rs` via `pub mod platform;`. Check existing main.rs structure at plan-open.

**D-20 commit body shape** (from 40-05 SUMMARY § "Task Commits", line 98 + § "Branch-specific smoke check" lines 167-173): if disposition stays D-20 manual replay, EVERY replay commit MUST have all 5 D-40-B3 sections (`Upstream intent:` / `What was replayed:` / `What was NOT replayed and why:` / `Fork-only wiring preserved:` / `Upstream-replayed-from:`) and ZERO `^Upstream-commit:` trailer lines. Falsifiable smoke checks:

```bash
git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-commit: '        # MUST be 0
git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream intent:'         # MUST be N
git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-replayed-from: ' # MUST be N
```

---

### Plan 43-06-PLATFORM-DETECTION-WINDOWS (Cluster 4, 2 commits: `0748cced` + `5d821c12`; depends on Plan 43-05)

**Plan-skeleton analog:** Phase 40 `40-06-FP-PROXY-TLS-SUMMARY.md` — exact match for terminal-Wave-2 D-20 plan with structural disposition lock + replay-when-surface-structurally-absent shape.

**Sequential dependency on Plan 43-05** (from CONTEXT.md D-43-A3 + D-43-C2 + Phase 40 Plan 40-06 SUMMARY dependency graph at lines 16-25):

```yaml
requires:
  - phase: 43-upst5-sync-execution
    plan: 43-05-PLATFORM-DETECTION-FOUNDATION
    provides: "crates/nono-cli/src/platform.rs module (Plan 43-05 D-20 replay or D-19 cherry-pick); WhenPredicate-bearing field on Profile (Plan 43-05)"
```

**Diff-inspection-first task at plan-open** (per D-43-C1; same shape as Plan 43-05). Special consideration: Cluster 4 commits build on Cluster 5's platform.rs. If Plan 43-05 stayed D-20 manual replay (didn't introduce platform.rs verbatim), Plan 43-06's cherry-pick will conflict at every reference to `crate::platform::*`. Resolution options:

1. If Plan 43-05 upgraded to D-19 cherry-pick → Plan 43-06 cherry-picks compose cleanly
2. If Plan 43-05 stayed D-20 manual replay → Plan 43-06 also stays D-20 manual replay (replay-when-foundation-is-also-replayed pattern)

**Windows-touch invariant carry-forward** (D-43-E1 = Phase 22 D-17 / Phase 34 D-34-E1 / Phase 40 D-40-E1 / Phase 42 D-42-E7):

> Phase 43 cherry-picks MUST NOT touch `*_windows.rs`, `crates/nono-cli/src/exec_strategy_windows/`, or `crates/nono-shell-broker/` UNLESS the 4-condition addendum applies: (1) required cross-platform struct field; (2) cross-platform default factory only; (3) ≤5 lines; (4) documented in SUMMARY + STATE.

Cluster 4's commits are Windows-touching by upstream's intent (registry queries + REG_DWORD fix). BUT the fork's `*_windows.rs` files are structurally invariant. The Cluster 4 cherry-pick must land its registry-query / REG_DWORD logic INSIDE `platform.rs` (introduced by Cluster 5) using `#[cfg(target_os = "windows")]` gates, NOT into `*_windows.rs` files. Verify with the same smoke check Phase 40 used (per 40-01 SUMMARY threat-table T-40-01-01, line 167):

```bash
git diff --stat HEAD~2 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
# MUST return 0
```

**Windows-fallback decision pattern** (from 40-06 SUMMARY DEC-6, lines 156-159): if Cluster 4 cherry-picks reference a "Windows fallback behavior" that the fork's existing `*_windows.rs` has its own version of, do NOT silently disable. Document the decision explicitly (Option A: uniform passthrough; Option B: preserve fork's existing path with warning). Audit evidence required.

---

## Shared Patterns

### Pattern 1: D-19 Trailer Block (mandatory on every will-sync cherry-pick)

**Source:** `.planning/templates/upstream-sync-quick.md:240-247`
**Apply to:** Every cherry-picked commit in Plans 43-01, 43-02, 43-03, 43-04 (and 43-05 / 43-06 if upgraded to D-19)

```
Upstream-commit: {upstream_sha_abbrev}
Upstream-tag: {upstream_tag}
Upstream-author: {upstream_author_name} <{upstream_author_email}>
Co-Authored-By: {upstream_author_name} <{upstream_author_email}>
Signed-off-by: {fork_author_name} <{fork_author_email}>
Signed-off-by: {fork_author_handle} <{fork_author_email}>
```

**Field rules** (verbatim from `.planning/templates/upstream-sync-quick.md:249-256`):
1. Trailer block separated from body by EXACTLY ONE blank line
2. Field order is FIXED: `Upstream-commit` → `Upstream-tag` → `Upstream-author` → `Co-Authored-By` → `Signed-off-by` (full name) → `Signed-off-by` (github handle)
3. `Upstream-author` LOWERCASE 'a' (NOT `Upstream-Author`) per Phase 40 standardization
4. Abbreviated 8-char SHA in `Upstream-commit:`

**Falsifiable smoke** (per Phase 40 Plan 40-01 SUMMARY threat-table T-40-01-02, line 168):

```bash
git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-commit: '
# Should equal N (the count of will-sync cherry-picks in the plan)
```

### Pattern 2: D-20 Manual Replay Commit Body (5 mandatory sections)

**Source:** Phase 40 Plan 40-05 SUMMARY § "Branch-specific smoke check" lines 167-173; Phase 40 Plan 40-06 SUMMARY § "Branch-specific smoke check" lines 217-225
**Apply to:** Plans 43-05 + 43-06 if disposition stays fork-preserve manual replay

Every D-20 manual-replay commit body MUST have all 5 sections:

```
Upstream intent: <one-sentence summary of the upstream commit's goal>

What was replayed: <list of fork-side changes that absorb upstream's intent>

What was NOT replayed and why: <list of upstream hunks deliberately skipped + rationale>

Fork-only wiring preserved: <fork-specific invariants that the replay protects>

Upstream-replayed-from: <upstream_sha_abbrev>
```

Plus `Co-Authored-By: Claude` + 2× `Signed-off-by:` DCO lines.

**Falsifiable smokes** (per 40-06 SUMMARY lines 218-225):

```bash
git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-commit: '          # MUST be 0
git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream intent:'           # MUST be N
git log --format='%B' HEAD~N..HEAD | grep -c '^What was replayed:'         # MUST be N
git log --format='%B' HEAD~N..HEAD | grep -c '^What was NOT replayed'      # MUST be N
git log --format='%B' HEAD~N..HEAD | grep -c '^Fork-only wiring preserved:' # MUST be N
git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-replayed-from: '   # MUST be N
git log --format='%B' HEAD~N..HEAD | grep -c '^Co-Authored-By: Claude'     # MUST be N
git log --format='%B' HEAD~N..HEAD | grep -cE '^Signed-off-by: '           # MUST be 2*N
```

### Pattern 3: Per-Plan 8-Check Close Gate (D-43-E9 = Phase 34 D-34-D2)

**Source:** Phase 40 Plan 40-01 SUMMARY lines 148-161 + Phase 40 Plan 40-04 SUMMARY lines 142-153 + Phase 40 Plan 40-05 SUMMARY lines 151-164
**Apply to:** All 6 Phase 43 plans (Plan 43-04 release-ride may skip individual checks with explicit categorization)

| Gate | Description | Plan 43-01 | 43-02 | 43-03 | 43-04 | 43-05 | 43-06 |
|------|-------------|------------|-------|-------|-------|-------|-------|
| 1 | `cargo test --workspace --all-features` (Windows host) | required | required | required | required | required | required |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | required | required | required | required | required | required |
| 3 | `cargo clippy --target x86_64-unknown-linux-gnu` | load-bearing | load-bearing | load-bearing | load-bearing | load-bearing | load-bearing |
| 4 | `cargo clippy --target x86_64-apple-darwin` | load-bearing | load-bearing | load-bearing | load-bearing | load-bearing | load-bearing |
| 5 | `cargo fmt --all -- --check` | required | required | required | required | required | required |
| 6 | Phase 15 5-row detached-console smoke | environmental | environmental | environmental | environmental | environmental | environmental |
| 7 | `wfp_port_integration` tests | environmental | environmental | environmental | environmental | environmental | environmental |
| 8 | `learn_windows_integration` tests | environmental | environmental | environmental | environmental | environmental | environmental |

**Load-bearing vs environmental categorization** (Phase 40 anti-pattern #3 / `.continue-here.md`): in SUMMARY frontmatter:

```yaml
skipped_gates_load_bearing: [3, 4]   # cross-target clippy linux-gnu/darwin (CI substitute required)
skipped_gates_environmental: [6, 7, 8]   # detached-console / wfp_port / learn_windows (Windows runtime missing in agent context)
```

**Critical: Plan 43-01 edition-2024 bump may need to lower MSRV gate temporarily.** If the post-edition fork triggers a `cargo build` failure on the Windows host due to insufficient rustc (1.77 → 1.85 jump), planner must document the rustup-update step in Plan 43-01 Task 1.

### Pattern 4: Cross-Target Clippy Verification (D-43-E4)

**Source:** `.planning/templates/cross-target-verify-checklist.md` (full file)
**Apply to:** All Phase 43 plans touching `#[cfg(target_os = "linux"|"macos")]` code

**Scope** (per checklist lines 13-20):
- Files containing `#[cfg(target_os = "linux")]` or `#[cfg(target_os = "macos")]` blocks
- Files containing `#[cfg(any(target_os = "linux", target_os = "macos"))]` blocks
- Files under `crates/nono-cli/src/exec_strategy/` (Unix supervisor code)
- Files under `bindings/c/src/` (FFI code consumed by macOS / Linux runtimes)

**Per-plan applicability:**

| Plan | In-scope | Reason |
|------|----------|--------|
| 43-01-EDITION-2024-FOUNDATION | YES | Edition bump touches every cfg-gated file in workspace |
| 43-02-SNAPSHOT-SYMLINK-FIX | YES | `crates/nono/src/undo/snapshot.rs` is cross-platform Rust |
| 43-03-PACK-MGMT | YES | `crates/nono-cli/src/` includes Linux-targeted files |
| 43-04-RELEASE-RIDE | partial | CHANGELOG-only is out-of-scope; nix dep bump IS in-scope |
| 43-05-PLATFORM-DETECTION-FOUNDATION | YES | platform.rs will contain `#[cfg(target_os = "linux"|"macos")]` blocks |
| 43-06-PLATFORM-DETECTION-WINDOWS | YES (transitively) | Windows-only registry queries land inside platform.rs which already has Linux/macOS branches from Cluster 5 |

**PARTIAL disposition** (per checklist lines 52-62): If cross-target clippy CANNOT run on Windows host due to missing toolchain (`x86_64-linux-gnu-gcc` for `aws-lc-sys`), mark gate as `skipped_gates_load_bearing` and document SKIPPED reason verbatim per checklist line 58-60.

### Pattern 5: Baseline-Aware CI Gate (D-43-E3, baseline SHA `13cc0628`)

**Source:** `.planning/templates/upstream-sync-quick.md:96-113`
**Apply to:** Wave 1+ plans (43-03, 43-04, 43-05, 43-06); Wave 0a (43-01) and Wave 0b (43-02) gate against the same baseline initially, then subsequent waves gate against the prior wave's head.

**Lane transition rules** (verbatim from template lines 108-113):

- Lane was green on baseline AND is green on PR head: PASS
- Lane was green on baseline AND is red on PR head: FAIL (real regression)
- Lane was red on baseline AND is red on PR head: PASS (carry-forward, not introduced by this PR)
- Lane was red on baseline AND is green on PR head: PASS + IMPROVEMENT

**Per-job comparison table template** (from Phase 40 Plan 40-04 SUMMARY lines 162-184): Each plan's SUMMARY § "Wave N CI Verification" enumerates all CI lanes with baseline vs head conclusion.

### Pattern 6: Umbrella PR Body Assembly (D-43-E6 / memory `project_cross_fork_pr_pattern`)

**Source:** Phase 40 Plan 40-01 SUMMARY § "Accomplishments" line 79 ("PR #922 body appended with Plan 40-01's contribution section"); 40-04 line 77; 40-05 line 184; 40-06 line 332
**Apply to:** Every Phase 43 plan close (6 contribution sections feed into one umbrella PR)

**Per-plan contribution section template:**

```markdown
## Plan 43-NN (Cluster X: <theme>)

- **Range:** v0.53.0..v0.54.0 (<N> commits)
- **Disposition:** <will-sync | fork-preserve manual replay | fork-preserve diff-inspection-upgraded to will-sync>
- **Surface:** <surface description>
- **Key decisions:** <list>
- **CI baseline diff:** zero `success → failure` transitions vs baseline `13cc0628` (or post-wave-N-1 head)
```

Per memory `project_cross_fork_pr_pattern`: GitHub's one-PR-per-branch-pair rule means per-plan upstream contribution sections require per-plan feature branches feeding into the umbrella PR body. Phase 43 opens its OWN umbrella PR (PR #922 was Phase 40's, closed at v2.4 ship).

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| MSRV-bump task (Plan 43-01) | atomic workspace.toml edit + `cargo update` cascade | n/a | No prior Phase 40 / Phase 34 plan included an MSRV bump. Closest reference: the v2.4 Phase 04 plan 02 bumped MSRV 1.74 → 1.77 for windows-sys 0.59. Planner should consult that phase if structural precedent needed. |
| Plan 43-01 close-gate cargo-test pass with new edition | atomic workspace edition validation | n/a | Phase 40 / 34 plans never crossed an edition boundary. If `cargo test` reveals edition-2024-only syntax errors in fork-only files (especially Windows-host code), Plan 43-01 must absorb the fixes inline or defer to a CR-A class follow-on. |

---

## Metadata

**Analog search scope:**
- `.planning/phases/40-upst4-sync-execution/` (6 SUMMARY files — primary plan-skeleton source)
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/` (Phase 34 root template; partial confirmation)
- `.planning/phases/36-upst3-deep-closure/36-01b-CANONICAL-PROFILE-SECTIONS-SUMMARY.md` (Phase 36-01b `CommandsConfig` extension precedent — directly relevant to Plan 43-05 `WhenPredicate` collision check)
- `.planning/phases/36-upst3-deep-closure/36-01c-OVERRIDE-DENY-RENAME-SUMMARY.md` (Phase 36-01c `override_deny → bypass_protection` rename — directly relevant to Plan 43-05 if cherry-pick references pre-rename name)
- `.planning/templates/upstream-sync-quick.md` (mandatory D-19 + baseline-aware CI gate scaffold)
- `.planning/templates/cross-target-verify-checklist.md` (Class F cross-target clippy template)
- `crates/nono-cli/src/` (66 .rs files scanned via Glob)
- `Cargo.toml` + 5 crate `Cargo.toml` files (workspace structure verification)
- `crates/nono-cli/src/profile/mod.rs` (`From<ProfileDeserialize> for Profile` impl at lines 1893-1921)
- `crates/nono-cli/src/{setup,wiring,policy,learn,instruction_deny,trust_scan}.rs` (platform.rs analog candidates)
- `crates/nono/src/undo/snapshot.rs` (Cluster 7 target file header)

**Files scanned:** ~80 across `.planning/` + `crates/`
**Pattern extraction date:** 2026-05-17
