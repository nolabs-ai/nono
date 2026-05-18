## Plan 43-02 — Cluster 7 snapshot restore symlink validation

**Cluster:** 7 (Snapshot restore symlink validation — security fix)
**Disposition:** will-sync (D-19 cherry-pick of single upstream SHA `66c69f86`)
**Upstream commits:** `66c69f86` (`fix(snapshot): validate restore targets against symlinks`)
**Upstream tag:** v0.54.0
**Files touched:** `crates/nono/src/undo/snapshot.rs` (1 file, +175 / -0 — pre-flight `validate_restore_target` symlink check in `restore_to` path + two new `#[cfg(unix)]` regression tests)

**Key decision:** Wave 0b sequencing per D-43-A4 — security-urgency outranks parallelization speed; post-edition-2024-baseline ordering avoids follow-up edit risk. Path-handling discipline per CLAUDE.md § Common Footguns #1 (upstream uses `Path::starts_with` component-wise stdlib primitive + `relative_parent.components()` iteration — verified in pre-cherry-pick audit; no amendment required).

**D-43-E1 invariant:** trivially honored — single-file cherry-pick on `crates/nono/src/undo/snapshot.rs`; zero `*_windows.rs` edits.

**No-interactive-editor protocol observed:** `git -c core.editor=true cherry-pick --no-commit 66c69f86` → explicit `git commit -F /tmp/43-02-cherry-pick-msg.txt` → `[ ! -f .git/CHERRY_PICK_HEAD ]` confirmed sealed. `git cherry-pick --continue` never invoked.

**Fork-side notes (commit body):**
- Cherry-pick applied as-is (no path-handling amendment required)
- Fork's `restore_to` body retains its fork-only `restore_failures` aggregation (Phase 22 / Phase 41 era — surfaces locked-file failures on Windows without aborting the whole restore); cherry-pick's pre-flight validation loop inserts upstream of that aggregation, preserving it untouched
- New helper `validate_restore_target` + two new `#[cfg(unix)]` regression tests added at upstream-byte-identical sites

**CI baseline diff:** zero `success → failure` lane transitions predicted vs baseline `13cc0628`. Gate 1 (`cargo test --workspace --all-features`) on Windows host: 2197 passed / 0 failed / 19 ignored. Gate 2 (workspace clippy): clean. Gate 5 (fmt-check): clean. Gates 3 + 4 (cross-target Linux + macOS clippy): load-bearing-skip → CI per `.planning/templates/cross-target-verify-checklist.md § PARTIAL Disposition` (toolchain absent on Windows host, same precondition as Plan 43-01b). Gates 6, 7, 8: environmental-skip per D-40-C2 (cargo-level wfp_port + learn_windows tests DID pass inside Gate 1 — 2 passed / 1 ignored and 60 passed / 14 ignored respectively).

**Worktree-mode deferral:** This worktree executor wrote `43-02-PR-SECTION.md`, `43-02-CLOSE-GATE.md`, and `43-02-SNAPSHOT-SYMLINK-FIX-SUMMARY.md`. The actual `gh pr edit <pr-number> --body-file ...` append to the Phase 43 umbrella PR body is deferred to the orchestrator post-merge (consistent with Plan 43-01b's deferral pattern; the Phase 43 umbrella PR is not yet opened at the time of this worktree's execution).

**REQ-UPST5-02 acceptance criteria progress:** Cluster 7 disposition fully discharged; cherry-pick + D-19 trailer landed; security-flavored fix sequenced per D-43-A4. One of six clusters from the v0.53.0..v0.54.0 audit now closed.
