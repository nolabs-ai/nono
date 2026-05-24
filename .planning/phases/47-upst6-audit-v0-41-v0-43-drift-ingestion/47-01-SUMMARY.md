---
phase: 47-upst6-audit-v0-41-v0-43-drift-ingestion
plan: 01
status: complete
requirements: [REQ-UPST6-01]
commits: [1d552fe6, 0da6d39d, 5236558c, 3e65e116]
date: 2026-05-24
must_haves_verified: 18
provides:
  - DIVERGENCE-LEDGER.md artifact for v0.54.0..v0.57.0 (42 commits / 9 clusters)
  - per-cluster dispositions: 8 will-sync + 1 fork-preserve + 0 won't-sync + 0 split
  - 0 windows-touch:yes commits this cycle (relief signal contrasting Phase 42's first-fire)
  - "## ADR review section with per-cell L/M/H verdicts on Option A continue — outcome: (a) confirm"
  - "## Empirical cross-check covering 5 fork-shared files (D-47-D1 raised >=4 threshold; D-47-E12 preferential sampling)"
  - "## Cross-cluster re-export deps detected: 0 across 7 will-sync clusters scanned (feedback_cluster_isolation_invalid lesson structurally closed)"
  - UPST7 stub queued at v2.6 § Future Cycles (D-47-E11 default location)
  - 47-01-LOCK-NOTES.md captures D-47-A3 upstream_head_at_audit lock for Plan 47-02 reference
tech-stack:
  added: []
  patterns:
    - Two-tier ledger (cluster headers + nested commit-row tables) — D-47-E3 inherited
    - windows-touch column on commit rows (zero-fire this cycle) — D-47-A5 inherited
    - Per-cell L/M/H ADR review verdict table — D-47-E8 MANDATORY
    - Empirical cross-check on Phase 43+45 absorption surfaces — D-47-E12 preferential sampling
    - Cross-cluster re-export scan on every will-sync cluster's lead commit — D-47-D1..D4 new structural closure
key-files:
  created:
    - .planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-01-LOCK-NOTES.md
    - .planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER.md
    - .planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-01-SUMMARY.md
  modified:
    - .planning/ROADMAP.md
    - .planning/STATE.md
decisions:
  - D-47-A1 range = v0.54.0..v0.57.0 (locked tag-pair boundary)
  - D-47-A3 upstream_head_at_audit locked at first commit of Plan 47-01 (sha 807fca38efc768c4e9856a0cb5c47d961b9287e5)
  - D-47-C3 4-disposition vocab used (will-sync / fork-preserve / won't-sync / split)
  - D-47-D1..D4 cross-cluster re-export hardening applied; 0 cross-cluster deps detected; no split-flips
  - D-47-E8 per-cell L/M/H verdict table; outcome (a) confirm Option A continue
  - D-47-E11 UPST7 stub location: v2.6 § Future Cycles holding section (new ## Future Cycles header created)
  - Cluster grouping: 9 themes (C1 profile shadowing 9 + C2 startup timeout 7 + C3 release-ride 3 + C4 Landlock v6 + af_unix 9 + C5 Linux policy polish 3 + C6 macOS grant restore 3 + C7 PTY + musl 4 + C8 proxy credential format 2 + C9 package install path 2 = 42)
  - C9 fork-preserve conservative default (trust-bundle schema fork-side intersection unverified); Phase 48 upgrade pathway documented
  - Cluster grouping auditor judgment override: drift-tool date-proximity grouped 0b05508f with Landlock cluster; auditor reassigned to Cluster C1 after diff inspection (pure pack-verification surface, not landlock)
metrics:
  duration_minutes: ~120
  completed_date: 2026-05-24
skipped_gates_load_bearing: []
skipped_gates_environmental:
  - make ci (Windows host — make not on PATH; Phase 33+39+42 Rule 3 deviation precedent; substituted D-47-B4 step 8 invariant git diff --name-only HEAD~5..HEAD -- crates/ bindings/ scripts/ | wc -l == 0; Phase 47 ships only docs edits with structurally zero clippy/fmt/test risk)
  - cross-target clippy linux + darwin (Phase 47 ships zero .rs files; cross-target-verify-checklist trivially N/A)
---

# Phase 47 Plan 47-01: UPST6 audit — DIVERGENCE-LEDGER for v0.54.0..v0.57.0 Summary

## Summary

Plan 47-01 produced the binding REQ-UPST6-01 artifact: `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER.md` covering 42 non-merge cross-platform upstream commits in `v0.54.0..v0.57.0` across 9 themed clusters with per-cluster dispositions (8 will-sync, 1 fork-preserve, 0 won't-sync, 0 split) and the new `windows-touch` column firing **zero** times this cycle. The 5 ROADMAP § Phase 47 success criteria are all met for Plan 47-01 scope (Plan 47-02 closes Phase 47 phase-level gate): (1) the ledger enumerates every upstream commit in `v0.54.0..v0.57.0` that touches a fork-shared file with anchor SHA `10cec984` and total_unique_commits exact-match coverage (42 ledger rows == 42 drift-tool commits); (2) every cluster has a disposition + windows-touch column entry + rationale; (3) the `## ADR review` section ships per-cell L/M/H verdicts for all 5 Phase-33 ADR dimensions on Option A `continue` with outcome (a) confirm — aggregate shape (H, H, M, M, M) identical to Phase 42's verdict, holding stable through the larger 42-commit evidence base; (4) `## Empirical cross-check` spot-checks 5 fork-shared files (raising Phase 42's 4-file minimum) preferentially sampling Phase 43 + 45 absorption surfaces per D-47-E12 (platform.rs, trust/signing.rs, policy.rs, profile/mod.rs, cli.rs); (5) zero `.rs` / `.toml` / `.sh` / `.ps1` / `Makefile` edits ship (D-47-E5 / D-47-B4 step 8 trivially honored). The D-47-D1..D4 cross-cluster re-export hardening was applied: 0 cross-cluster deps detected across 7 will-sync clusters scanned, structurally closing the `feedback_cluster_isolation_invalid` lesson.

## Artifacts Created

| Artifact | Purpose | Lines | Commits |
|----------|---------|-------|---------|
| `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-01-LOCK-NOTES.md` | D-47-A3 upstream_head_at_audit lock + UPST6 anchor tag verification | 47 | 1d552fe6 |
| `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER.md` | REQ-UPST6-01 binding inventory for Phase 48 | ~330 (scaffold 65 + audit body) | 0da6d39d + 5236558c |
| `.planning/ROADMAP.md` | Phase 47 plans counter (1/2) + UPST7 stub | (modified) | 3e65e116 |
| `.planning/STATE.md` | completed_plans bump + Key Decisions (v2.6) close entry | (modified) | (this commit) |
| `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-01-SUMMARY.md` | This file | (this commit) | (this commit) |

## Close-Gate Verification (D-47-B4 8-step gate, Plan 47-01 scope)

| # | Check | Evidence | Status |
|---|-------|----------|--------|
| 1 | drift-tool re-run exit 0 (idempotency) | `bash scripts/check-upstream-drift.sh --from v0.54.0 --to v0.57.0 --format json` exit 0 on re-run; total_unique_commits 42 stable | PASS |
| 2 | ledger row count >= drift-tool total_unique_commits | 42 ledger commit-rows == 42 drift count (exact coverage, zero gap) | PASS |
| 3 | every cluster has disposition + windows-touch + rationale | 9 clusters / 9 dispositions / 9 windows-touch lines / 9 rationales (grep-confirmable) | PASS |
| 4 | `## ADR review` grep-confirmable with per-cell L/M/H on 5 dimensions | `grep -c "^## ADR review$"` returns 1; `grep -cE "^\| (security\|windows\|maintenance\|divergence\|contributor) "` returns 5 | PASS |
| 5 | `## Empirical cross-check` >= 4 file walks + `## Cross-cluster re-export deps detected` summary | 5 file walks (D-47-D1 raised threshold honored) + summary subsection populated explicitly stating 0 deps across 7 scanned clusters | PASS |
| 6 | ROADMAP UPST7 stub committed | `grep -q "^### UPST7 — Upstream v0.57.0" .planning/ROADMAP.md` returns 0; Depends on Phase 48 + Plans 0 / TBD + Reference docs/architecture/upstream-parity-strategy.md § Future audit cadence | PASS |
| 7 | STATE.md updated (frontmatter + Key Decisions v2.6 close entry) | This commit | PASS |
| 8 | D-47-E5 zero-source-edits invariant | `git diff --name-only HEAD~5..HEAD -- crates/ bindings/ scripts/ \| wc -l` == 0 (Plan 47-01 ships zero source edits across all 4+1 commits prior to this SUMMARY commit) | PASS |

**All 8 D-47-B4 close-gate checks PASS at Plan 47-01 close.** Phase 47 phase-level gate awaits Plan 47-02 (v0.41–v0.43 backfill) per D-47-B4 strict-both-close.

## Disposition Breakdown

| Disposition | Count | Clusters | Notes |
|-------------|-------|----------|-------|
| will-sync | 8 | C1, C2, C3, C4, C5, C6, C7, C8 | Phase 48 cherry-pick / D-20 manual-replay queue |
| fork-preserve | 1 | C9 | Conservative default — Phase 48 plan-phase may upgrade to will-sync after diff inspection of `crates/nono-cli/src/package_cmd.rs` + `crates/nono/src/trust/policy.rs` + `crates/nono/src/manifest.rs` against `5f1c9c73` |
| won't-sync | 0 | — | No upstream-only macOS lint clusters this cycle (vs Phase 42's Cluster 6 won't-sync) |
| split | 0 | — | D-47-D4 default flip-to-split not triggered: zero cross-cluster re-export deps detected |

**windows-touch:yes count: 0** across all 42 commits. Mechanical D-47-A5 heuristic returns no matches; auditor judgment-override confirms (no edge case where heuristic missed Windows-specific work). Phase 43 + 45 absorbed Cluster 5 (`0748cced` + `5d821c12`) Windows platform-detection foundation; upstream has not iterated on that surface in v0.54.0..v0.57.0.

## ADR Review Outcome

**Outcome:** (a) Confirm Option A `continue`.

Per-cell L/M/H verdict table on 5 Phase 33 ADR dimensions:

| dimension | verdict |
|-----------|---------|
| security | High |
| windows | High |
| maintenance | Medium |
| divergence | Medium |
| contributor | Medium |

Aggregate shape (H, H, M, M, M) — 2 High / 3 Medium / 0 Low. Dominates Option B (1 H / 0 M / 4 L) and Option C (1 H / 2 M / 2 L) without invoking D-33-C3 tiebreaker. **Aggregate identical to Phase 42's verdict** — the larger 42-commit evidence base (vs Phase 42's 18) does NOT surface new amend candidates. Phase 33 ADR `Status: Accepted` remains in force; Phase 47 does NOT supersede.

## Cross-cluster Re-export Findings

**0 cross-cluster re-export deps detected across 7 will-sync clusters scanned** (C1, C2, C4, C5, C6, C7, C8; C3 release-ride skipped re-export scan per N/A; C9 fork-preserve deferred to Phase 48 plan-phase upgrade).

Only re-export edge observed: Cluster C4 lead commit `c2c6f2ca` exposes:
- `pub use sandbox::{DetectedAbi, LandlockScopePolicy, detect_abi, is_wsl2, landlock_scope_policy};` in `crates/nono/src/lib.rs`
- `pub use linux::{DetectedAbi, LandlockScopePolicy, detect_abi, landlock_scope_policy};` in `crates/nono/src/sandbox/mod.rs`

Both re-export the SAME set of symbols (`DetectedAbi`, `LandlockScopePolicy`, `detect_abi`, `landlock_scope_policy`, `is_wsl2`) which are INTRODUCED in `c2c6f2ca` itself via `pub struct LandlockScopePolicy { ... }` + `pub fn landlock_scope_policy(caps: &CapabilitySet) -> Result<LandlockScopePolicy> { ... }` + `pub struct DetectedAbi` definitions in `crates/nono/src/sandbox/linux.rs`. **INTRA-cluster re-export, NOT cross-cluster.** No D-47-D4 split-flip required this cycle.

**Empirical closure of `feedback_cluster_isolation_invalid`:** the Phase 43 Cluster 2 (`8b888a1c` re-exporting `public_key_id_hex` + `sign_statement_bundle` in `crates/nono/src/trust/mod.rs` from prerequisite upstream commits the fork hadn't absorbed) class is STRUCTURALLY PREVENTED by D-47-D1..D4 — the scan ran on every `will-sync` lead commit and surfaced the only re-export edge in `c2c6f2ca`; deep inspection confirmed intra-cluster origin; no flip-to-split required. Phase 48 inherits a cleaner UPST6 sync execution surface than Phase 43 did for UPST5.

## Empirical Cross-Check Files

5 files walked (D-47-D1 raises Phase 42's 4-file minimum; D-47-E12 preferential sampling honored):

| # | File | Upstream commits in range | Drift-tool coverage | Notable finding |
|---|------|---------------------------|---------------------|------------------|
| 1 | `crates/nono-cli/src/platform.rs` | 0 | PASS | Phase 43 Cluster 5 absorption surface — zero upstream churn this cycle; absorption holds |
| 2 | `crates/nono/src/trust/signing.rs` | 0 | PASS | Phase 43 Cluster 2 + Phase 45 Plan 45-01 source-migration target — zero upstream churn this cycle; split-disposition closure holds |
| 3 | `crates/nono-cli/src/policy.rs` | 3 (e6215f8b, 4fa9f6a6, a0222be2) | PASS | Cluster C5 + C4 coverage confirmed |
| 4 | `crates/nono-cli/src/profile/mod.rs` | 8 (multi-cluster: C1+C4+C6) | PASS | **Fork-divergence hot spot identified** — Phase 48 plan-phase MUST diff-inspect each commit's `profile/mod.rs` hunks against fork's Phase 36 `CommandsConfig` extensions to confirm no exhaustive-match regression |
| 5 | `crates/nono-cli/src/cli.rs` | 6 (cross-cluster: C2 + C4) | PASS | Most-touched cross-platform file this cycle; clap-arg surface area high churn |

**Findings summary:** All 5 sampled files PASS; drift tool's commit list is complete against the v0.54.0..v0.57.0 fork-shared surface for the sampled subsystems. **No drift-tool blind spots surfaced; no D-47-E10 quick-task spawn required.**

## Deviations

**None — no Rule 1/2/3/4 deviations surfaced during this audit walk.** Drift-tool ran cleanly on first invocation; all 4 anchor tags resolved to expected prefixes; the CONTEXT preview's ~75-commit estimate referenced pre-D-11-filter raw count (actual post-filter count: 42), but this is a CONTEXT framing nuance not a behavioral deviation — the audit-walk produced the authoritative drift-tool inventory per Plan 47-01 Task 2 protocol. Cluster grouping required one auditor-judgment-override (drift-tool date-proximity grouped `0b05508f fix(profile-verification)` with Landlock cluster C4 by chronological proximity; diff inspection revealed pure pack-verification surface, reassigned to Cluster C1 with documentation in the cluster body). This is a normal audit-walk judgment, not a Rule deviation.

## Authentication Gates

None — Plan 47-01 makes no network calls requiring authentication.

## Self-Check: PASSED

**Files claimed created/modified (all FOUND):**
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-01-LOCK-NOTES.md` — FOUND (commit 1d552fe6, 47 lines)
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER.md` — FOUND (commits 0da6d39d + 5236558c, ~330 lines)
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-01-SUMMARY.md` — FOUND (this file)
- `.planning/ROADMAP.md` — FOUND (modified at commit 3e65e116; UPST7 stub + plans counter)
- `.planning/STATE.md` — FOUND (modified at this commit; completed_plans 12→13 + Key Decisions v2.6 close entry)

**Commits claimed (all FOUND in git log):**
- `1d552fe6` — FOUND (Task 1: lock-notes)
- `0da6d39d` — FOUND (Task 3: ledger scaffold)
- `5236558c` — FOUND (Tasks 4+5+6+7: cluster sections + ADR review + Empirical cross-check + re-export scan)
- `3e65e116` — FOUND (Task 8: ROADMAP UPST7 stub)
- (this commit) — Task 9: STATE.md update + SUMMARY.md

**D-47-E5 / D-47-B4 step 8 invariant:** `git diff --name-only HEAD~4..HEAD -- crates/ bindings/ scripts/ | wc -l` == 0 (Plan 47-01 ships zero source-tree edits across all commits prior to this SUMMARY commit). PASS.

## Next Steps

1. **Plan 47-02 (v0.41–v0.43 backfill ledger)** unblocked. Per D-47-B3 sequential plan ordering, Plan 47-02 runs after Plan 47-01 closes (this commit). Plan 47-02 produces `DIVERGENCE-LEDGER-v041-v043-backfill.md` with `absorbed-via:` column reconstructing Phase 22/34 historical absorption + `## Phase 48 hand-off` subsection for unmatched candidates. SKIPS `## ADR review` per D-47-C4.
2. **Phase 47 phase close** awaits Plan 47-02 per D-47-B4 strict-both-close gate. REQ-UPST6-01 satisfied at Plan 47-01 close; REQ-DRIFT-INGEST-01 closes at Plan 47-02 close.
3. **Phase 48 inputs** are the immutable ledger Cluster Summary table + per-cluster dispositions + windows-touch column + `## Empirical cross-check` hot-spot findings. Phase 48 planner has full discretion to refine wave membership; Phase 47 hints are advisory per D-47-B5.
4. **UPST7 cadence trigger** already accumulating (19 post-v0.57.0 commits visible at audit-open). UPST7 plan-phase can fire any time after Phase 48 close per D-47-E6.
