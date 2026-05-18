# Plan 43-02 — Pre-cherry-pick audit (Task 1)

**Date:** 2026-05-18
**Audit target:** Upstream commit `66c69f86` (`fix(snapshot): validate restore targets against symlinks`)
**Plan:** 43-02-SNAPSHOT-SYMLINK-FIX
**Wave:** 0b (sequential after Wave 0a baseline 43-01b)
**Auditor:** worktree executor agent (worktree-agent-a29744fba0d50cdd1)
**Base SHA:** `5e5f1005` (Plan 43-01b foundation: MSRV 1.95 + workspace deps centralized; edition 2021)

---

## 1. Wave 0a (predecessor) closure check

The orchestrator's prompt explicitly states this worktree's base `5e5f1005` already contains Plan 43-01b's foundation (MSRV 1.95 + workspace deps centralized + edition 2021). The plan frontmatter `depends_on: ["43-01-EDITION-2024-FOUNDATION"]` is the original pointer; the real predecessor is **43-01b** per the orchestrator context.

`git log --oneline 5e5f1005 | head -10` confirms:
- `5e5f1005 chore: merge executor worktree (worktree-agent-a8fee2900caf37b1b) — 43-01b foundation`

This is sufficient to start Wave 0b per D-43-A4.

**Status:** PASS — Wave 0a closed (via 43-01b supersession of 43-01).

---

## 2. Upstream commit shape verification

```
Commit: 66c69f863e66dc38a7174437e8d87855e282338d
Subject: fix(snapshot): validate restore targets against symlinks
Author: Luke Hinds <lukehinds@gmail.com>
Date: 2026-05-12T06:28:34+01:00
Tag: v0.54.0 (full SHA 6b00932fe80a52b65f3718bb900878287640cc31)
Files changed: 1 (crates/nono/src/undo/snapshot.rs)
Insertions / deletions: +175 / -0 (pure additive)
```

`git show 66c69f86 --name-only --format=''` returns exactly one file: `crates/nono/src/undo/snapshot.rs`. **D-43-E1 trivially honored** (single non-Windows file; no `*_windows.rs`).

**Status:** PASS — matches Phase 42 ledger Cluster 7 description.

---

## 3. Upstream diff shape (what the cherry-pick lands)

Upstream introduces:

1. **Pre-flight validation loop** at the start of `restore_to` (in upstream's pre-patch shape, before line 268's `// Restore files from manifest` comment in fork). Loops over `manifest.files` and calls `self.validate_restore_target(path)?` for each path that needs restoration.
2. **New private method `validate_restore_target(&self, path: &Path) -> Result<()>`** — 100-line helper that:
   - Finds the longest tracked-root prefix using `path.starts_with(tracked)` where both are `Path`/`PathBuf` → this is `Path::starts_with` (component-wise stdlib primitive), NOT string `starts_with`. Correct per CLAUDE.md § Common Footguns #1.
   - Checks `fs::symlink_metadata(tracked)` and rejects if the tracked root itself is a symlink, or is not a directory.
   - Treats `NotFound` as OK (tracked root may not yet exist; restore will create).
   - Strips `tracked` prefix from parent, then walks each `Component` via `relative_parent.components()`:
     - `CurDir` → continue
     - `Normal(name)` → push and `symlink_metadata` it; reject if symlink OR non-directory
     - `ParentDir / RootDir / Prefix` → reject as unsupported (defensive)
   - Treats per-component `NotFound` as OK (early termination — path doesn't exist yet).
3. **Two new Unix-only tests** (`#[cfg(unix)]`):
   - `restore_rejects_symlinked_parent_directory` — creates a tracked subdir, removes it, replaces with a symlink to an outside dir, asserts restore fails and outside dir is untouched.
   - `restore_rejects_symlink_before_create_dir_all` — nested-dir version that asserts no parent dir is created through the symlink.

**Path-handling style:** PURE component-wise iteration via `relative_parent.components()` + `Path::starts_with`. No `String::starts_with` anywhere in the new code. Verbatim compliance with CLAUDE.md § Common Footguns #1.

**Verdict on path handling:** `as-is` (no amendment required).

---

## 4. Fork-side divergence audit

`grep -nE 'restore_to|tracked_paths|validate_restore_target|symlink_metadata' crates/nono/src/undo/snapshot.rs` returns:

| Line | Symbol | Note |
|------|--------|------|
| 51   | `tracked_paths: Vec<PathBuf>,` | Field shape **matches upstream's expectation** exactly. |
| 69, 78, 93, 95, 101, 127 | constructors using `tracked_paths` | unchanged; no shape divergence |
| 197 | doc comment ref to `restore_to` in `dry_run` doc | no functional touch |
| 262 | `pub fn restore_to(&self, manifest: &SnapshotManifest) -> Result<Vec<Change>>` | fork's signature matches upstream's |
| 372 | `for tracked in &self.tracked_paths` in `create_baseline` | unrelated function |
| 564, 590, 599, 691 | `tracked_paths` in lexical-validate / walk helpers | unrelated functions; no overlap with insertion site |
| 0 hits for `validate_restore_target` | n/a | upstream-new helper; fork does not pre-define |
| 0 hits for `symlink_metadata` | n/a | fork does not currently use `fs::symlink_metadata` in this file |

**Fork-only divergence in `restore_to` body (relative to upstream's pre-patch shape):**

The fork's `restore_to` has been extended (Phase 22 / Phase 41 era) with **per-file error aggregation**:
- `let mut restore_failures: Vec<(std::path::PathBuf, String)> = Vec::new();` at line 266
- Each filesystem error in the per-file loop pushes to `restore_failures` and `continue`s rather than aborting
- Trailing `if restore_failures.is_empty() { Ok(applied_changes) } else { Err(NonoError::PartialRestore { applied, failures }) }` at line 337

Upstream's pre-patch `restore_to` does NOT have this aggregation — it returns `Err(...)?` on each per-file failure. The cherry-pick from upstream MAY conflict in the body of `restore_to` if the diff context isn't byte-identical.

**Inspection of upstream's diff context** (from `git show 66c69f86`):
```
@@ -258,6 +258,17 @@ impl SnapshotManager {
         let current_files = self.walk_current()?;
         let mut applied_changes = Vec::new();
 
+        for (path, state) in &manifest.files {
+            ... validate_restore_target loop ...
+        }
+
         // Restore files from manifest
         for (path, state) in &manifest.files {
```

Upstream's pre-image context lines are:
1. `let current_files = self.walk_current()?;`
2. `let mut applied_changes = Vec::new();`
3. `<blank>`
4. `        // Restore files from manifest`
5. `        for (path, state) in &manifest.files {`

Fork's actual context at line 264-269:
1. `let current_files = self.walk_current()?;`
2. `let mut applied_changes = Vec::new();`
3. `let mut restore_failures: Vec<(std::path::PathBuf, String)> = Vec::new();`  ← FORK-ONLY EXTRA LINE
4. `<blank>`
5. `        // Restore files from manifest`
6. `        for (path, state) in &manifest.files {`

**Predicted cherry-pick result:** The 3-line trailing context (`<blank>` + `// Restore files from manifest` + `for (path, state) ...`) matches; the 2-line leading context (`let current_files = ...` + `let mut applied_changes = ...`) also matches. Git's 3-line context window is satisfied. Cherry-pick should apply cleanly with the fork's extra `restore_failures` line preserved (it's not in the upstream pre-image hunk and not in the upstream post-image hunk → fork's line stays untouched).

For the `validate_restore_target` helper insertion at line 539-549 region (upstream pre-image line 539-550 → fork ~575-594): this is a pure helper-method insertion in the `impl SnapshotManager` block. The context lines around upstream's insertion are non-method-specific (`        Ok(())\n    }\n` from a previous fn closing → blank → `    /// Walk tracked paths and store all non-excluded files...`). Fork's nearby surface at line 575-594 includes the `filter_for_root` doc + impl. We expect a clean insertion with possible offset.

The two new `#[cfg(unix)]` tests are appended in the `mod tests` block around upstream pre-image line 1082+. Fork's tests around line 1117/1132/1160 include `restore_to` references. The test insertion should be a clean append.

**Verdict on fork divergence:** No conflicting divergence. Cherry-pick proceeds as-is; fork's `restore_failures` aggregation stays untouched (cherry-pick only adds the pre-flight loop above the existing restore body — does not modify the per-file failure handling).

---

## Audit verdict

**Path-handling discipline:** `as-is` (no amendment required; upstream uses `Path::starts_with` component-wise iteration verbatim per CLAUDE.md § Common Footguns #1).

**Fork-side conflict risk:** LOW. Surface divergence is the `restore_failures` aggregation in `restore_to` body, but the cherry-pick's hunk is upstream of that divergence and does not overlap with it. The `validate_restore_target` helper is a pure insertion. The two new tests are pure appends.

**Decision:** Proceed with cherry-pick using `git -c core.editor=true cherry-pick --no-commit 66c69f86`. If a conflict surfaces, resolve preserving fork's `restore_failures` aggregation. If no conflict, commit verbatim with the D-19 trailer block.

---

## Acceptance summary

- [x] Wave 0a (43-01b) closed: confirmed via base SHA `5e5f1005` (orchestrator handoff)
- [x] `git show 66c69f86 --name-only` returns exactly 1 file: `crates/nono/src/undo/snapshot.rs`
- [x] Upstream uses `Path::starts_with` + `relative_parent.components()` — NOT `String::starts_with`
- [x] Fork-only divergence identified: `restore_failures` aggregation in `restore_to` body (Phase 22/41 era); does not overlap with upstream's insertion site
- [x] Audit verdict recorded: `as-is`

---

*Pre-cherry-pick audit complete. Proceeding to Task 2 (cherry-pick).*
