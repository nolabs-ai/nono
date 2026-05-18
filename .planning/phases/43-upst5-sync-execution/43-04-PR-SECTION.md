## Plan 43-04 — Cluster 3 release v0.54.0 (CHANGELOG-only) + nix dep bump

**Cluster:** 3 (Release v0.54.0 + nix bump)
**Disposition:** will-sync (D-19 cherry-pick of 2 upstream SHAs with release-ride convention) on feature branch `43-04-cluster-3` (materialized by orchestrator post-merge from worktree branch `worktree-agent-addcdb9c2805c07b9`)
**Upstream commits:**
- `803c6947` (chore(deps): bump nix from 0.31.2 to 0.31.3) — `--allow-empty` cherry-pick per DEC-N Option A; effective absorption already shipped via Plan 43-01b's workspace-deps centralization (commit `b6aac925`, 2026-05-18) which promoted `nix` to `[workspace.dependencies]` at version `0.31.3`. Empty diff against fork shape; commit recorded to preserve upstream D-19 `Upstream-commit:` lineage for falsifiable audit.
- `6b00932f` (chore: release v0.54.0) — CHANGELOG-only per D-43-E10; Cargo.toml + Cargo.lock + 4 per-crate Cargo.toml version-bump hunks reverted per Phase 40 Plan 40-04 precedent commit `64b231a7`; single-pass `--no-commit` + revert + `git commit -F` workflow per CLAUDE.md commit policy (NO --amend, per B-3 fix in PLAN.md)

**Files touched:** `CHANGELOG.md` only (upstream v0.54.0 entries absorbed under fork's existing `[0.53.0] - 2026-05-14` heading per Phase 40 Plan 40-04 DEC-3 pattern, with 4 "absorbed from upstream v0.54.0 - 2026-05-13" subsection markers; version pins preserved at 0.53.0 across all 5 per-crate Cargo.toml files)

**Key decisions:**
- DEC-N (--allow-empty 803c6947 cherry-pick, Option A): preserves upstream D-19 trailer lineage despite empty diff; documented in 43-04-PRE-CHERRY-PICK-AUDIT.md
- D-43-E10 release-ride convention applied to 6b00932f — fork tracks own version (0.53.0) separately; only CHANGELOG entries absorbed
- Cross-plan boundary marking per Phase 40 Plan 40-04 DEC-3 precedent: subjects in upstream's v0.54.0 CHANGELOG entry inline-tagged with destination plan (43-02 / 43-03 / 43-05 / 43-06) or won't-sync status (Cluster 6 macOS lint per D-43-D1; sigstore-installer + tokio out-of-scope)
- Wave 1 per-plan-feature-branch protocol per `wave_1_parallel_branch_strategy` (D-43-E6 + memory `project_cross_fork_pr_pattern`); umbrella PR body update deferred to orchestrator after BOTH 43-03 + 43-04 close

**CI baseline diff:** zero `success → failure` transitions expected vs baseline `13cc0628` (independent `43-04-cluster-3`-head comparison per `wave_1_parallel_branch_strategy.baseline_ci_gate`). One pre-existing Gate 1 flake (`supervisor::aipc_sdk::tests::windows_loopback_tests::helper_stamps_session_token_from_env`) categorized as red→red PASS (carry-forward — unrelated to CHANGELOG-only change; passes in isolation; CLAUDE.md § "Environment variables in tests" precedent).
