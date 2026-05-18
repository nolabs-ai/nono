# Plan 43-04 Pre-Cherry-Pick Audit (Task 1)

## Branch state

- Branch: `worktree-agent-addcdb9c2805c07b9` (per Claude Code worktree-agent naming; orchestrator will materialize `43-04-cluster-3` post-merge)
- Base SHA: `5e5f1005` (post-Plan-43-01b foundation merge)
- Working tree: clean before any Task 2 action

## Per-crate version-pin shape inventory

All 5 per-crate Cargo.toml files carry a LITERAL `version = "0.53.0"` declaration. The root `Cargo.toml` `[workspace.package]` block does NOT define `version` (Plan 43-01b centralized `rust-version` and `edition` but did NOT centralize `version`).

| File | Shape | Line | Value |
|---|---|---|---|
| `Cargo.toml` (root) | (no version in `[workspace.package]`) | — | — |
| `crates/nono/Cargo.toml` | literal pin | 3 | `version = "0.53.0"` |
| `crates/nono-cli/Cargo.toml` | literal pin | 3 | `version = "0.53.0"` |
| `crates/nono-proxy/Cargo.toml` | literal pin | 3 | `version = "0.53.0"` |
| `crates/nono-shell-broker/Cargo.toml` | literal pin | 3 | `version = "0.53.0"` |
| `bindings/c/Cargo.toml` | literal pin | 3 | `version = "0.53.0"` |

**Implication for Task 3 (6b00932f release-commit revert):** the dynamic file list to `git checkout HEAD --` covers Cargo.lock + all 5 per-crate Cargo.toml files (the root has no version hunk in 6b00932f to revert). However, 6b00932f only modifies 4 of the per-crate files (`bindings/c`, `crates/nono-cli`, `crates/nono-proxy`, `crates/nono/Cargo.toml`); `crates/nono-shell-broker/Cargo.toml` is fork-only and not in upstream's diff.

Files modified by `git show --stat 6b00932f`:
- `CHANGELOG.md` (51+/0)
- `Cargo.lock` (4+/4)
- `bindings/c/Cargo.toml` (1+/1)
- `crates/nono-cli/Cargo.toml` (3+/3)
- `crates/nono-proxy/Cargo.toml` (2+/2)
- `crates/nono/Cargo.toml` (1+/1)

Task 3 revert list (only the files upstream actually touched in the version hunk):
- `Cargo.lock`
- `bindings/c/Cargo.toml`
- `crates/nono-cli/Cargo.toml`
- `crates/nono-proxy/Cargo.toml`
- `crates/nono/Cargo.toml`

## nix dep shape (post-Plan-43-01b)

Plan 43-01b centralized `nix` to the workspace level at `0.31.3`:

```
Cargo.toml:60:nix = "0.31.3"
crates/nono/Cargo.toml:50:nix = { workspace = true, features = ["fs", "user"] }
crates/nono/Cargo.toml:54:nix = { workspace = true, features = ["fs", "user"] }
crates/nono-cli/Cargo.toml:86:nix = { workspace = true, features = [...] }
crates/nono-cli/Cargo.toml:92:nix = { workspace = true, features = [...] }
```

**Critical implication for Task 2 (803c6947 nix dep bump cherry-pick):** the target state (nix = 0.31.3 in workspace deps, all per-crate inherit via `workspace = true`) is already in place. Upstream's 803c6947 bumps the per-crate literal pins from `"0.31.2"` to `"0.31.3"` — but those literal pins no longer exist in the fork (Plan 43-01b replaced them with `workspace = true` inheritance). The cherry-pick will produce an EMPTY DIFF (all upstream hunks resolve to no-op against fork's current shape).

## 803c6947 cherry-pick decision (DEC-N preview — formalized in SUMMARY)

Phase-context guidance offered two options:
- **Option A (--allow-empty):** still attempt the cherry-pick; if it produces an empty diff, commit with `--allow-empty` so the upstream D-19 trailer + commit lineage are preserved in the fork's git history. Zero functional change.
- **Option B (skip cherry-pick):** record in SUMMARY DEC-N that 43-01b already absorbed this dep at workspace level via a different mechanism (workspace-deps centralization rather than per-crate bump). No --allow-empty commit. Defer DIVERGENCE-LEDGER update to a separate plan-phase follow-up.

**Selected:** **Option A** (--allow-empty cherry-pick). Rationale:
1. Preserves D-19 trailer + Upstream-commit lineage falsifiability — future audits can grep `git log --format=%B | grep '^Upstream-commit: 803c6947'` and find the absorption record.
2. Keeps the Phase 43 cluster-3 contribution shape symmetric with Phase 40 Plan 40-04 (each upstream SHA in the cluster produces one commit).
3. The --allow-empty commit is harmless: zero diff, no behavior change, no cargo regression risk.
4. Avoids deferring DIVERGENCE-LEDGER cleanup work to a follow-up plan-phase.

**Conflict prediction for 803c6947:** none. The upstream hunks resolve to no-op against the fork's `workspace = true`-inherited shape — cherry-pick produces an empty commit (no merge conflict prompt; `--no-commit` then verify empty diff then commit with `--allow-empty`).

## 6b00932f cherry-pick predictions

**Conflict prediction:** upstream's per-crate version bumps (`0.53.0` → `0.54.0`) will conflict with fork's preserved `0.53.0` pin in 4 per-crate Cargo.toml files. Cargo.lock will also conflict on package-version lines. CHANGELOG.md conflicts at the top heading (fork has `[0.53.0] - 2026-05-14`, upstream inserts `[0.54.0] - 2026-05-13` above it).

**Hunks to revert per D-43-E10 + Phase 40 Plan 40-04 DEV-2 (precedent commit `64b231a7`):**
- `Cargo.lock` (full revert — fork's lockfile reflects fork's 0.53.0 pin + workspace-level nix 0.31.3, not upstream's 0.54.0 + per-crate nix)
- `bindings/c/Cargo.toml`
- `crates/nono/Cargo.toml`
- `crates/nono-cli/Cargo.toml`
- `crates/nono-proxy/Cargo.toml`

## Cross-plan SHA presence in upstream's v0.54.0 CHANGELOG entry

`git show 6b00932f -- CHANGELOG.md | grep -E '<SHA>'` returns 0 — the CHANGELOG entry uses subject lines, not SHAs. Cross-plan boundary tagging in Task 3 step 4 must annotate subject lines instead. Verified subjects present in upstream's v0.54.0 CHANGELOG entry:

| Subject (verbatim from upstream) | Cluster / Plan | Inline tag to add |
|---|---|---|
| `*(snapshot)* Validate restore targets against symlinks` | Cluster 7 / Plan 43-02 | "absorbed via Plan 43-02-SNAPSHOT-SYMLINK-FIX" |
| `*(platform)* Correctly parse windows registry dword values` | Cluster 4 / Plan 43-06 | "to be handled via Plan 43-06-PLATFORM-DETECTION-WINDOWS" |
| `Upgrade to Rust edition 2024, centralize workspace dependencies` | Cluster 2 / Plan 43-01b | "split-disposition absorbed via Plan 43-01b (workspace edits) + deferred source migration to v2.6 / UPST6" |
| `*(platform)* Implement robust windows platform detection` | Cluster 4 / Plan 43-06 | "to be handled via Plan 43-06-PLATFORM-DETECTION-WINDOWS" |
| `*(profile)* Add platform-conditional profile fields` | Cluster 5 / Plan 43-05 | "to be handled via Plan 43-05-PLATFORM-DETECTION-FOUNDATION" |
| `Macos lint` (3 entries) | Cluster 6 / won't-sync | "won't-sync per Phase 42 ledger Cluster 6 / D-43-D1" |
| `*(pack-update-hint)* Treat unparsable installed as older in update check` + pack-mgmt feature subjects | Cluster 1 / Plan 43-03 | "absorbed via Plan 43-03-PACK-MGMT" |
| `*(deps)* Bump nix from 0.31.2 to 0.31.3` | Cluster 3 / Plan 43-04 (this plan, prior commit) | "absorbed via this plan; effective via Plan 43-01b workspace-deps centralization" |

## Conflict prediction summary

| SHA | Conflict expected | Resolution shape |
|---|---|---|
| 803c6947 | none (empty diff) | --allow-empty commit per DEC-N Option A |
| 6b00932f | 5 conflicts (Cargo.lock + 4 per-crate Cargo.toml + CHANGELOG.md) | Revert Cargo.* files per D-43-E10; manual CHANGELOG resolution per Phase 40 Plan 40-04 DEC-3 |
