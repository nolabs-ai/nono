---
phase: 46
phase_name: windows-squash-merge-post-merge-ci-verifications-uat-backlog
gathered: 2026-05-23
status: Ready for planning
requirements_locked_via: REQUIREMENTS.md § REQ-MERGE-01 + REQ-CI-FU-01..03 + REQ-UAT-BL-01..02 (no SPEC.md — phase has explicit success criteria in ROADMAP.md)
---

# Phase 46: windows-squash merge + post-merge CI verifications + UAT backlog - Context

**Gathered:** 2026-05-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 46 is the orchestrator-coordinated phase that drains v2.5's three-stream post-merge backlog plus the v2.4 UAT carry-forward. Six requirements span three plans:

1. **REQ-MERGE-01 (Plan 46-01) — `windows-squash` → `main` merge disposition.** Doc-only. Closed via the SC#1-explicit "feature-flag-equivalent rollout with the gate-state explicitly documented" path. The rebase scope exceeded the 260428-rsu runbook assumption (504 upstream commits / 77 conflicts, 16 of which are `*_runtime.rs` AA add/add parallel-evolution collisions, not drift); upstream PRs 725 + 726 remain OPEN + CONFLICTING + REVIEW_REQUIRED with no maintainer response since the 2026-04-29 outreach. The phase ships a new ADR at `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md` that captures alternative paths considered, the maintainer-response revival trigger set, and codifies the per-phase umbrella PR pattern (Phase 22/33/39/42/43/PR-922 precedent) as the fork's go-forward upstream-contribution mode. Plan 46-01 also flips `260428-rsu-SUMMARY.md` status `re-deferred → closed-via-v2.6-rollout` with a back-reference to the new ADR.

2. **REQ-CI-FU-01..03 (Plan 46-02) — Post-merge CI orchestration.** Four CI actions fired in parallel:
   - `gh workflow run phase-37-linux-resl.yml` — Phase 37 live run on ubuntu-24.04 (closes Success Criterion 6 of Phase 37 VERIFICATION.md `human_needed`)
   - `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` — Phase 45 RESL native re-validation live-run handoff per D-45-D1 (closes REQ-RESL-NIX-04 from STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN → passed)
   - `gh pr create` — Phase 43 umbrella PR against upstream `always-further/nono` with the 6 staged PR-SECTION.md contribution artifacts concatenated per memory `project_cross_fork_pr_pattern`
   - Observed last: baseline-aware CI lane diff vs Phase 41 close SHA `13cc0628` across the 8 SC#4 lanes (Linux Clippy, macOS Clippy, Windows Build, Integration, Regression, Security, Packaging, Smoke)

3. **REQ-UAT-BL-01..02 (Plan 46-03) — Phase 35 + 36 UAT backlog drain.** 11 UAT scenarios + 7 verification items inherited from v2.4 close, host-blocked since. New `phase-46-uat-backlog.yml` workflow_dispatch-only workflow (tactical, deletable in v3.0) runs the automatable subset on a ubuntu-24.04 + macos-latest matrix. Non-automatable items (interactive consent prompts, ETW capture, etc.) close via per-item `no-test-fixture` waivers documented in `46-03-SUMMARY.md` per SC#5 explicit allowance. Plan 46-03 backfills the missing `35-HUMAN-UAT.md` + `35-VERIFICATION.md` + `36-HUMAN-UAT.md` + `36-VERIFICATION.md` files with the canonical item lists and their verdicts so SC#5 ("Phase 35 + 36 HUMAN-UAT.md and VERIFICATION.md transition out of `human_needed` state") is honored literally.

**Three plans, parallel-safe (single wave, per D-46-B2):**

- **Plan 46-01** — `docs(46-01): v2.6 upstream-merge deferral ADR + 260428-rsu re-anchor` — doc-only. Touches `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md` (NEW) + `.planning/quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-SUMMARY.md` (status flip). REQUIREMENTS.md `[ ] REQ-MERGE-01 → [x]` (closed via feature-flag-equivalent path).
- **Plan 46-02** — `chore(46-02): post-merge CI orchestration (REQ-CI-FU-01..03)` — orchestrator actions. Four `gh` invocations + CI lane diff observation recorded in `46-02-SUMMARY.md`. Last task amends `.planning/templates/upstream-sync-quick.md:102` baseline registry to the Phase 46 close SHA per D-46-D3 so Phase 47 audit + Phase 48 sync inherit cleanly. REQUIREMENTS.md flips for REQ-CI-FU-01..03.
- **Plan 46-03** — `docs(46-03): phase 35+36 UAT backlog drain (REQ-UAT-BL-01..02)` — new `.github/workflows/phase-46-uat-backlog.yml` + Phase 35 + 36 HUMAN-UAT + VERIFICATION backfills + `46-03-SUMMARY.md` roll-up. REQUIREMENTS.md flips for REQ-UAT-BL-01..02.

**Phase 44 + 45 → Phase 46 sequencing:** ROADMAP declares Phase 46 sequential after Phase 44 + Phase 45 (both shipped 2026-05-20 / 2026-05-23). Phase 44 close SHA `aa510098` is the v2.6 quiet-baseline anchor per D-44-E1; ROADMAP SC#4 explicitly names `13cc0628` (Phase 41 close) as the diff anchor per D-46-D1.

**In scope:**
- ADR + `260428-rsu-SUMMARY.md` status flip + REQUIREMENTS.md `[x]` flip for REQ-MERGE-01 (Plan 46-01).
- Four parallel CI actions (Phase 37 live run, Phase 45 RESL workflow_dispatch, Phase 43 umbrella PR, baseline-aware CI diff) + `upstream-sync-quick.md:102` baseline registry update + REQUIREMENTS.md `[x]` flip for REQ-CI-FU-01..03 (Plan 46-02).
- New `.github/workflows/phase-46-uat-backlog.yml` + Phase 35/36 backfilled HUMAN-UAT + VERIFICATION files + `46-03-SUMMARY.md` per-item verdicts + REQUIREMENTS.md `[x]` flip for REQ-UAT-BL-01..02 (Plan 46-03).
- Phase 37 + Phase 43 VERIFICATION.md `status: human_needed → passed` flips at Plan 46-02 close.
- Phase 45 VERIFICATION.md `STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN` → `passed` flip on REQ-RESL-NIX-04 once `phase-45-resl-native-host.yml` reports green.
- Cross-target clippy verification skipped — no source touches in Phase 46.

**Out of scope (route elsewhere or explicitly defer):**
- **Phase 47 / 48 surfaces** — UPST6 audit, drift ingestion, UPST6 sync execution. Sequential after Phase 46.
- **Phase 49 / 50 surfaces** — already shipped (parallel-safe disjoint streams).
- **Active rebase resumption of PRs 725 / 726** (the 260428-rsu force-rebase path). Rejected at D-46-A1; defer to v3.0+ or maintainer-response trigger per D-46-A3.
- **Active fresh outreach to upstream maintainer.** Rejected at D-46-A1 — the 2026-04-29 outreach is the canonical comm; no fresh prompt added by Phase 46.
- **Strict-no-carve-outs CI gate threshold** (rejected at D-46-D2). Strict + categorized per Phase 40 anti-pattern #3 is the active threshold; `_environmental` skips (e.g., cross-target clippy on Windows host) do not block close.
- **Both-baselines CI diff** (rejected at D-46-D1). Single baseline `13cc0628` per SC#4 verbatim; `aa510098` quiet-baseline noted as v2.6-internal but not the SC#4 anchor.
- **Live-derived lane enumeration** (rejected at D-46-D4). SC#4's 8-lane list is verbatim; any lanes added between `13cc0628` and Phase 46 close are out-of-scope for the SC#4 success-criterion close but may be noted in 46-02-SUMMARY for future-phase awareness.
- **Permanent always-on UAT CI lane** (rejected at D-46-C2). `phase-46-uat-backlog.yml` is workflow_dispatch-only, mirroring Phase 45's tactical pattern; deletable in v3.0 once verdicts are recorded.
- **Re-anchoring non-automatable UAT items to v3.0 EDR bucket** (rejected at D-46-C3). Per-item `no-test-fixture` waivers in 46-03-SUMMARY are preferred over deferral; honors SC#5's "documented `no-test-fixture` waiver" language verbatim.
- **Backfilling 35 / 36 SUMMARYs** — only `HUMAN-UAT.md` + `VERIFICATION.md` get backfilled per D-46-C4; per-plan SUMMARYs (35-01..35-03, 36-01a..36-03) are not touched.
- **Personal native Linux/macOS host UAT** (rejected at D-46-C1). GH Actions only; user has no native host available.
- **v3.0 milestone calendar trigger for upstream merge revival** (rejected at D-46-A3). Maintainer-response triggers only; no fork-side calendar.
- **Drift-quantification revival trigger** (rejected at D-46-A3). Same reason.

</domain>

<decisions>
## Implementation Decisions

### REQ-MERGE-01 disposition (Area A — discussed)

- **D-46-A1: Feature-flag-equivalent rollout (defer).** Close REQ-MERGE-01 via SC#1's explicit alternative path. The rebase scope exceeded the 260428-rsu runbook assumption (504 upstream commits / 77 conflicts) and upstream PRs 725 + 726 remain OPEN + CONFLICTING + REVIEW_REQUIRED with no maintainer response since the 2026-04-29 outreach. Captures the work disposition without blocking phase close on indefinite external response. Re-anchor as a v3.0 candidate. PRs 725/726 remain OPEN with the 2026-04-29 outreach as the canonical comm. **User explicitly chose** option (a) over (b) "re-poll maintainer + decide on response" and (c) "resume 260428-rsu force-rebase".

- **D-46-A2: ADR + update existing 260428-rsu summary.** Land a new ADR at `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md` capturing: alternative paths considered (rebase resumption, re-poll, feature-flag), why feature-flag-equivalent chosen, re-trigger conditions, go-forward upstream-contribution mode. Plus flip `260428-rsu-SUMMARY.md` status `re-deferred → closed-via-v2.6-rollout` with back-reference to the new ADR. Highest auditability; mirrors Phase 33 ADR shape. **User explicitly chose** option (a) over (b) "update 260428-rsu summary only + Phase 46 SUMMARY section" and (c) "Phase 46 SUMMARY-only mention".

- **D-46-A3: Maintainer-response triggers only (external).** ADR codifies only external revival triggers: (a) maintainer comments on PRs 725/726 with directional guidance, (b) maintainer closes or merges either PR, (c) maintainer requests a different approach. No fork-side calendar trigger (no v3.0-milestone trigger, no drift-quantification trigger). Resume scope determined at trigger time. Mirrors the deferral conditions already in `260428-rsu-SUMMARY.md`. **User explicitly chose** option (a) over (b) "maintainer-response + v3.0-milestone trigger" and (c) "maintainer-response + drift-quantification trigger".

- **D-46-A4: Codify per-phase umbrella PR as go-forward + cite Phase 22/33/39/42/43 precedent.** ADR explicitly says: while PRs 725/726 remain held, the fork's upstream contribution mode is the per-phase umbrella PR pattern per memory `project_cross_fork_pr_pattern` inherited from Phases 22, 33, 39, 42, 43. PR 922 (Phase 40) + Phase 43 umbrella (REQ-CI-FU-02, this phase) are the active reference shapes. Prevents future drift in pattern. **User explicitly chose** option (a) over (b) "note the pattern but don't bind future phases" and (c) "don't address go-forward".

### Plan slicing + CI sequencing (Area B — discussed)

- **D-46-B1: 3 plans, per-requirement.** Plan 46-01 MERGE-doc (REQ-MERGE-01) doc-only, Plan 46-02 CI-FU orchestration (REQ-CI-FU-01..03), Plan 46-03 UAT-BL backlog (REQ-UAT-BL-01..02). Each plan owns a requirement-cluster; per-plan SUMMARY closes per-requirement REQ checkbox flips. Mirrors Phase 44 / 45 / 49 / 50 "one plan per requirement-cluster" slicing. **User explicitly chose** option (a) over (b) "per-stream: 5 plans", (c) "per-host-context: 2 plans" and (d) "single mega-plan with task-level breakdown".

- **D-46-B2: All 3 plans parallel-safe, single wave.** Surfaces fully disjoint: 46-01 is doc-only (`.planning/architecture/` + `.planning/quick/`); 46-02 is `gh` invocations (no source touches; commits already on `main`); 46-03 is `.github/workflows/phase-46-uat-backlog.yml` (NEW) + Phase 35/36 file backfills. No inter-plan ordering dependency. Mirror Phase 45's wave-1 parallel pattern. User picks plan execution order based on host availability + interactive convenience. **User explicitly chose** option (a) over (b) "sequential: 46-01 → 46-02 → 46-03" and (c) "hybrid: 46-01 doc first + parallel 46-02 / 46-03".

- **D-46-B3: Within Plan 46-02, all 4 CI actions in parallel; CI diff observed last.** Fire `gh workflow run phase-37-linux-resl.yml` + `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` + `gh pr create` (Phase 43 umbrella) concurrently. Wait for all to complete (workflows green, PR CI green). Then record baseline-aware CI lane diff from observed states. Fastest wall-clock; matches mid-2026 GH Actions concurrency model; per-action attribution captured via per-workflow run-id recorded in `46-02-SUMMARY.md`. **User explicitly chose** option (a) over (b) "sequential: Phase 43 PR first, then Phase 37 + 45 workflows" and (c) "two-stage: 37+45 workflow dispatches first, then Phase 43 PR + CI diff".

### Phase 35+36 UAT host strategy (Area C — discussed)

- **D-46-C1: GH Actions only (ubuntu-24.04 + macos-latest matrix).** No personal native Linux/macOS host available to the user. UAT items execute via GH Actions runners. Mirror Phase 45 D-45-D2 dispatcher pattern. Some interactive items (consent prompts, ETW capture) cannot be automated this way — those waive as `no-test-fixture` per D-46-C3. **User explicitly chose** option (a) over (b) "personal native Linux + GH Actions for macOS", (c) "personal native Linux + macOS hosts available", and (d) "no native host now — stretch GH Actions, document interactive items as `no-test-fixture`" (collapsed into (a) + D-46-C3).

- **D-46-C2: New `phase-46-uat-backlog.yml` workflow_dispatch-only (tactical).** Mirror Phase 45 RESL pattern. Single workflow with matrix (ubuntu-24.04 + macos-latest) + `workflow_dispatch` trigger only. Runs the runnable subset of 11 UAT + 7 verification items via `cargo test` + smoke-test invocations. Tactical, deletable after verdicts recorded (target v3.0). Smallest blast radius; aligns with `feedback_clippy_cross_target` + D-45-D2 pattern. **User explicitly chose** option (a) over (b) "extend `phase-37-linux-resl.yml` + `phase-45-resl-native-host.yml` with UAT job" and (c) "folded into existing `ci.yml` PR-triggered lanes".

- **D-46-C3: `no-test-fixture` waiver in 46-03-SUMMARY with explicit per-item rationale.** For each non-automatable item (interactive prompts, ETW capture, etc.): row in 46-03-SUMMARY with item description, why it cannot be automated, waiver status `no-test-fixture` per SC#5 explicit allowance. REQ-UAT-BL-01 closes with N/11 pass + M/11 waived (target: at least 8/11 pass, ≤3 waived; planner verifies at item inventory). REQ-UAT-BL-02 closes with N/7 pass + M/7 waived (target: at least 5/7 pass, ≤2 waived). Direct, audit-trail clean. **User explicitly chose** option (a) over (b) "defer non-automatable items to v3.0" and (c) "re-frame as `EDR/interactive` items — align with existing WR-02 EDR HUMAN-UAT pattern".

- **D-46-C4: Backfill Phase 35 + 36 HUMAN-UAT.md and VERIFICATION.md files; Plan 46-03 also writes a roll-up SUMMARY.** Plan 46-03 backfills missing `.planning/phases/35-upst3-closure-quick-wins/35-HUMAN-UAT.md` + `35-VERIFICATION.md` + `.planning/phases/36-upst3-deep-closure/36-HUMAN-UAT.md` + `36-VERIFICATION.md` with the canonical 11 + 7 items and their verdicts. Phase 35 + 36 VERIFICATION.md `status: human_needed → passed`. Phase 46 SUMMARY references the backfilled files. Honors SC#5 "Phase 35 + 36 HUMAN-UAT.md and VERIFICATION.md transition out of `human_needed` state" literally. **User explicitly chose** option (a) over (b) "Plan 46-03 SUMMARY only — don't touch Phase 35 + 36 dirs" and (c) "Phase 46 dedicated `46-PHASE-35-36-UAT.md` + brief stubs in Phase 35 + 36 dirs pointing to it".

### Baseline anchor + CI gate threshold (Area D — discussed)

- **D-46-D1: `13cc0628` (Phase 41 close) authoritative — honor ROADMAP SC#4 verbatim.** v2.6 work (Phase 44 + 45) lands on top of `13cc0628`; the lane diff captures `success → failure` transitions since v2.5 close. Same anchor used at Phase 43 close's deferred CI verification (REQ-CI-FU-03 was always anchored at `13cc0628`). v2.6 quiet-baseline anchor `aa510098` (Phase 44 close per D-44-E1) is noted as v2.6-internal observability but NOT the SC#4 anchor. SC#4 plain-reading honored. Phase 46 close SHA becomes the baseline for Phase 48 per ROADMAP Cross-Phase Invariants. **User explicitly chose** option (a) over (b) "`aa510098` (Phase 44 close) — honor D-44-E1 quiet-baseline" and (c) "both: report 2-column diff vs `13cc0628` AND `aa510098`".

- **D-46-D2: Strict + categorized threshold (Phase 40 anti-pattern #3 carve-out).** Strict by default. Any `success → failure` lane transition blocks Phase 46 close. Exception: lanes that legitimately skip due to environmental constraints (e.g., cross-target clippy on Windows-host lacking aws-lc-sys cross-compiler; load-bearing-vs-environmental classification per Phase 40 anti-pattern #3) get an `_environmental` classification; anything `_load_bearing` blocks. Categorization frontmatter in `46-02-SUMMARY.md` per `skipped_gates_load_bearing` vs `_environmental` distinction. Same rule inherited at Phase 48. **User explicitly chose** option (a) over (b) "strict-no-carve-outs" and (c) "lenient: track all transitions but don't gate close".

- **D-46-D3: Phase 46 SUMMARY records close SHA + `.planning/templates/upstream-sync-quick.md:102` baseline registry update.** Phase 46 SUMMARY captures the post-merge baseline SHA explicitly. Plan 46-02's last task amends `.planning/templates/upstream-sync-quick.md:102` (the canonical baseline registry per 45-CONTEXT canonical_refs) to point at the Phase 46 close SHA. Phase 47 audit + Phase 48 sync gate against this anchor. Matches the Phase 41 → v2.5 → v2.6 inheritance pattern. **User explicitly chose** option (a) over (b) "Phase 46 SUMMARY only — leave template registry update to Phase 47 plan-open" and (c) "skip explicit SHA recording — Phase 47 reads `git log main` at plan-open".

- **D-46-D4: SC#4 verbatim 8-lane list.** Lanes for the diff: `Linux Clippy`, `macOS Clippy`, `Windows Build`, `Integration`, `Regression`, `Security`, `Packaging`, `Smoke`. No reinterpretation; Phase 46 reports `success → failure` per lane against `13cc0628`. Phase 41 close baseline already captures these 8 lanes; clean inheritance. Any lanes added between `13cc0628` and Phase 46 close are out-of-scope for the SC#4 close but may be noted in 46-02-SUMMARY for future-phase awareness (informational, non-blocking). **User explicitly chose** option (a) over (b) "live-derived from `.github/workflows/ci.yml` jobs" and (c) "SC#4 verbatim + a `_added_since_13cc0628` row".

### Claude's Discretion

- **Exact path for the ADR file.** D-46-A2 names `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md`. Planner verifies whether `.planning/architecture/` exists (currently has `upstream-parity-strategy.md` per Phase 33 ADR — confirms the dir) and that the filename convention matches the existing ADR shape. May adjust filename to `.planning/architecture/v2.6-upstream-merge-deferral.md` (drop the `-ADR` suffix) if that's the convention in place; the existing `docs/architecture/upstream-parity-strategy.md` is the closest precedent.

- **ADR content depth.** D-46-A2 names the ADR; planner picks the depth — minimum: alternative paths considered, why feature-flag-equivalent chosen, the 4-bullet maintainer-response trigger set (D-46-A3), the go-forward umbrella PR pattern citation (D-46-A4), back-reference to `260428-rsu-SUMMARY.md`. Could optionally include a "drift cost over time" subsection (504 commits in April → N commits in May → projection); planner discretion.

- **Per-plan REQUIREMENTS.md flip semantics.** Each of Plans 46-01 / 46-02 / 46-03 flips a distinct subset of REQ checkboxes. Planner picks whether each plan flips its own REQs (per `project_workspace_crates`-style atomic ownership) or whether Plan 46-03 (latest to land if user picks that order) consolidates the flips. Default: each plan flips its own REQs at plan-close.

- **`phase-46-uat-backlog.yml` exact matrix + invocation specifics.** D-46-C2 names the workflow; planner picks the matrix shape (`ubuntu-24.04` + `macos-latest` per D-46-C1), the cargo invocation patterns (target-OS-specific test targets for each UAT item), the `workflow_dispatch` input shape (mirror Phase 45 `gh_runner_os: { type: choice }` or simpler), and the action versions (mirror `phase-37-linux-resl.yml` SHA-pinned actions per Phase 37 D-15 / WR-09 pattern).

- **UAT item inventory at plan-open.** Plan 46-03 inventories the canonical 11 UAT + 7 verification items at plan-open via grep across `.planning/milestones/v2.4-MILESTONE-AUDIT.md`, Phase 35/36 SUMMARYs, and any human-verify references. v2.4-MILESTONE-AUDIT.md `tech_debt` rows 116-121 confirm 2 Windows-runnable items in Phase 35 (env_filter_tests, profile_cli debug-syntax) + 1 host-agnostic item in Phase 36 (docs MDX bypass_protection) were exercised at v2.4 close — those are pre-pass. The remaining 8 UAT + 6 verification items (target: 11 + 7 total) need to be inventoried and assigned to either automated test invocations in `phase-46-uat-backlog.yml` or `no-test-fixture` waivers per D-46-C3. If inventory differs from 11 + 7 by more than ±1 per category, surface as a deviation to confirm scope.

- **Backfilled Phase 35 + 36 HUMAN-UAT.md / VERIFICATION.md shape.** D-46-C4 names the files; planner picks the canonical schema. Recommended: mirror Phase 37 + 41 + 43 HUMAN-UAT.md structure (frontmatter with `status: passed` post-execution, per-item rows with `expected` + `actual` + `verdict`). Phase 35 + 36 VERIFICATION.md frontmatter `status: human_needed → passed` flip at Plan 46-03 close.

- **Phase 43 umbrella PR body assembly.** D-46-B3 calls out `gh pr create` for the Phase 43 umbrella. Planner reads the 6 staged PR-SECTION.md artifacts at `.planning/phases/43-upst5-sync-execution/43-{01b,02,03,04,05,06}-PR-SECTION.md`, concatenates them in numerical order, picks the PR title (likely `feat: UPST5 sync execution (Phase 43)` mirroring PR 922 / Phase 40 pattern), and runs `gh pr create --base main --head <branch> --title ... --body "$(cat ...)"`. Captures resulting PR URL in `43-UMBRELLA-PR.txt` per 43-VERIFICATION.md deferral wording AND in `46-02-SUMMARY.md`. Branch strategy: per `project_cross_fork_pr_pattern` memory, one feature branch holds all Phase 43 commits; planner picks the branch name (e.g., `feat/phase-43-upst5-sync`).

- **`upstream-sync-quick.md:102` exact amendment shape.** D-46-D3 names the registry update site; planner reads the current line at plan-open and produces a minimal-context-safe edit (single-line replacement of `13cc0628` → Phase 46 close SHA with comment annotation referencing the v2.6 close + Phase 47/48 inheritance).

- **Plan numbering.** Plans 46-01 + 46-02 + 46-03 follow the `{padded_phase}-{NN}-{theme}` convention. Suggested slugs: `46-01-MERGE-DEFERRAL-ADR`, `46-02-POST-MERGE-CI-ORCHESTRATION`, `46-03-PHASE-35-36-UAT-DRAIN`. Planner may refine.

### Folded Todos

No todos folded in Phase 46. The two matches surfaced by `todo.match-phase 46` (both score 0.6, keyword-only) are reviewed below as deferred.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 46 scope sources
- `.planning/REQUIREMENTS.md` § REQ-MERGE-01 + REQ-CI-FU-01..03 + REQ-UAT-BL-01..02 — Acceptance criteria for the 6 in-phase requirements (lines 12-14, 26-27, 42).
- `.planning/ROADMAP.md` § Phase 46 (lines 120-131) — Goal + dependencies + 5 success criteria. SC#1 explicit feature-flag-equivalent rollout language; SC#4 verbatim 8-lane list + `13cc0628` baseline anchor; SC#5 `no-test-fixture` waiver + HUMAN-UAT/VERIFICATION transition language.
- `.planning/ROADMAP.md` § Cross-Phase Invariants (lines 219-229) — Baseline-aware CI gate inheritance (`Phase 48 gates vs the Phase 46 post-merge baseline SHA`); Windows-only-files invariant (trivially honored — no source touches); cross-target clippy required for cfg-gated Unix code (N/A — no source touches).
- `.planning/PROJECT.md` § v2.6 UPST6 + v2.5 Drain (lines 9-43) — milestone context, target features, deferred items.
- `.planning/MILESTONES.md` — v2.5 close context (carry-forward list for v2.6).
- `.planning/v2.6-MILESTONE-AUDIT.md` — mid-milestone health check (lines 43-60 list REQ-MERGE-01 + REQ-CI-FU-01..03 + REQ-UAT-BL-01..02 as `pending_by_design` for Phase 46).

### REQ-MERGE-01 sources (Plan 46-01)
- `.planning/quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-SUMMARY.md` — current `status: re-deferred`; Plan 46-01 amends to `closed-via-v2.6-rollout` with ADR back-reference per D-46-A2. Contains the 504-commit / 77-conflict scope quantification + 2026-04-29 outreach links.
- `.planning/quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-CONTEXT.md` — locked decisions from 2026-04-28 (timing vs upstream PRs, Phase 22 disposition, rebase shape, conflict resolution authority).
- `.planning/quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-PLAN.md` — 5-task runbook (rebase v2.0-pr, rebase v2.1-pr, smoke-test, force-push, cleanup); referenced in ADR as the abandoned-path runbook.
- `docs/architecture/upstream-parity-strategy.md` — Phase 33 ADR Option A `continue` strategy; closest precedent for new ADR shape per D-46-A2.
- `.planning/PROJECT.md` § `windows-squash → main merge` (line 26 + line 196) — re-deferral history (v2.3 / v2.4 / v2.5 scope-locks).
- **Upstream PRs (live state at plan-open via `gh pr view`):**
  - PR 725 `always-further/nono` — `feat(windows): windows gap closure (v2.0 milestone)` — OPEN + CONFLICTING + REVIEW_REQUIRED at discussion time
  - PR 726 `always-further/nono` — `feat(windows): resource limits + extended ipc + attach-streaming + cleanup (v2.1)` — OPEN + CONFLICTING + REVIEW_REQUIRED at discussion time
  - PR 583 `always-further/nono` — CLOSED unmerged (the "refresh" PR mentioned in PROJECT.md; predecessor to 725/726)
- **Memory anchors:**
  - `project_cross_fork_pr_pattern` — Fork uses ONE umbrella PR per phase to upstream (Phase 22/33/39/42/43 + PR 922 precedent). ADR codifies this per D-46-A4.
  - `gh_available` — `gh` CLI works in this environment; ADR may reference for future PR-status polling.

### REQ-CI-FU-01..03 sources (Plan 46-02)
- **Phase 37 deferred verification:**
  - `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-VERIFICATION.md` — Success Criterion 6 `human_needed`; `human_verification` block names the workflow + 9 integration tests + cpu-controller delegation gate. Plan 46-02 flips `human_needed → passed` once `phase-37-linux-resl.yml` reports green.
  - `.github/workflows/phase-37-linux-resl.yml` — the workflow Plan 46-02 dispatches via `gh workflow run`. 302 lines; matrix ubuntu-24.04; 2 jobs (`resl-nix` + `pkgs-auto-pull`); machinectl shell invocation; sigstore-sign keyless OIDC step with `id-token: write` permission.
- **Phase 43 deferred verification:**
  - `.planning/phases/43-upst5-sync-execution/43-VERIFICATION.md` — Truth #4 + Truth #5 `UNCERTAIN (HUMAN)` deferred to orchestrator; `deferred` frontmatter names umbrella PR + baseline-aware CI diff as the two open items.
  - `.planning/phases/43-upst5-sync-execution/43-{01b,02,03,04,05,06}-PR-SECTION.md` — 6 staged contribution artifacts. Plan 46-02 concatenates in numerical order for `gh pr create` body per memory `project_cross_fork_pr_pattern`.
- **Phase 45 RESL native re-validation handoff (D-45-D1 inheritance):**
  - `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` — protocol doc + SC#3 decision tree.
  - `.github/workflows/phase-45-resl-native-host.yml` — workflow_dispatch-only workflow with `gh_runner_os: { type: choice, options: [ubuntu-24.04, macos-latest, both], default: both }` input per D-45-D2.
  - `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-VERIFICATION.md` (planner verifies path) — Phase 45 close artifact recording REQ-RESL-NIX-04 as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN; Plan 46-02 flips → `passed` once `phase-45-resl-native-host.yml` reports green.
- **Baseline anchor:**
  - `.planning/templates/upstream-sync-quick.md:102` — canonical baseline registry; currently `13cc0628`; Plan 46-02 amends to Phase 46 close SHA per D-46-D3.
  - **Phase 41 close SHA `13cc0628`** — authoritative for SC#4 lane diff per D-46-D1.
- **Phase 40 anti-pattern #3 categorization:**
  - `.planning/phases/40-upst4-sync-execution/40-CONTEXT.md` § anti-pattern #3 (planner verifies path) — `skipped_gates_load_bearing` vs `_environmental` distinction codification per D-46-D2.
  - `.planning/templates/cross-target-verify-checklist.md` — environmental skip semantics for cross-target clippy on Windows host.

### REQ-UAT-BL-01..02 sources (Plan 46-03)
- **Phase 35 + 36 SUMMARYs (item inventory source):**
  - `.planning/phases/35-upst3-closure-quick-wins/35-01-WIN-ENV-FILTER-SUMMARY.md` — REQ-PORT-CLOSURE-01 + Windows env-filter wiring; 4 cfg-gated regression tests (`test_windows_empty_allow_denies_all_env_vars`, etc.).
  - `.planning/phases/35-upst3-closure-quick-wins/35-02-LINUX-LANDLOCK-PROFILES-SUMMARY.md` — REQ-PORT-CLOSURE-06 + Linux Landlock profiles-dir pre-creation.
  - `.planning/phases/35-upst3-closure-quick-wins/35-03-WIN-TEST-HYGIENE-SUMMARY.md` — REQ-PORT-CLOSURE-07 + profile_cli debug-syntax tests + UNC path flake fix.
  - `.planning/phases/36-upst3-deep-closure/36-01a..36-03-SUMMARY.md` — 6 plan summaries; REQ-PORT-CLOSURE-02 + 04 + 05; deprecated_schema port, yaml_merge wiring, ExecConfig refactor.
- **v2.4 audit canonical item rationale:**
  - `.planning/milestones/v2.4-MILESTONE-AUDIT.md` § partial_human_needed (lines 70-114) — per-REQ human_verify_blocker rationale for the 18 items.
  - `.planning/milestones/v2.4-MILESTONE-AUDIT.md` § tech_debt rows 116-121 — 3 items exercised at v2.4 close + passed (env_filter_tests, profile_cli debug-syntax, docs MDX bypass_protection).
  - `.planning/milestones/v2.4-MILESTONE-AUDIT.md` rows 273-274 — `UAT gaps | 11 | Phases 35 + 36 human_uat` + `Verification gaps | 7`.
- **v2.5 carry-forward:**
  - `.planning/milestones/v2.5-MILESTONE-AUDIT.md:195` — `Phase 35 + 36 human-verify backlog (11 UAT + 7 verification) | v2.4 close re-anchor | Carried to v2.6 native Linux host (out of scope for v2.5)`.
- **Phase 45 workflow_dispatch precedent:**
  - `.github/workflows/phase-45-resl-native-host.yml` — Plan 46-03 mirrors layout for `phase-46-uat-backlog.yml` per D-46-C2.
- **Existing Phase 37 + 41 + 43 HUMAN-UAT.md schema (backfill template per D-46-C4):**
  - `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-HUMAN-UAT.md`
  - `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-HUMAN-UAT.md`
  - `.planning/phases/43-upst5-sync-execution/43-HUMAN-UAT.md`

### Cross-phase invariants (inherited from ROADMAP § Cross-Phase Invariants)
- **D-19 trailer convention** — NOT applicable to Phase 46 (Plan 46-01 doc-only; Plan 46-02 orchestrator-only no source touches; Plan 46-03 doc + workflow YAML only). Phase 43 umbrella PR opened by Plan 46-02 inherits D-19 trailers from the existing Phase 43 cherry-picks (already in place at Phase 43 close).
- **D-34-E1 / D-40-E1 / D-43-E1 Windows-only-files invariant** — trivially honored across all 3 plans (no source-tree touches).
- **CLAUDE.md "lazy use of dead code"** — N/A; no source removals/additions.
- **Cross-target clippy verification protocol** — N/A; no source touches. `_environmental` skip classification per D-46-D2 inherits the Windows-host cross-target clippy carve-out for the CI lane diff.
- **DIVERGENCE-LEDGER cluster isolation** — N/A (no audit/sync execution in Phase 46).

### Coding & security standards (CLAUDE.md)
- `CLAUDE.md` § Coding Standards — DCO sign-off (`Signed-off-by:` lines on every commit) applies to all Phase 46 commits including doc-only and YAML-only commits.
- `CLAUDE.md` § GSD Workflow Enforcement — Phase 46 follows the `/gsd:execute-phase` pattern.

### Memory anchors
- Memory `project_cross_fork_pr_pattern` — Fork uses ONE umbrella PR per phase to upstream. Plan 46-02 follows this for Phase 43 umbrella; ADR per D-46-A4 codifies this as the go-forward.
- Memory `gh_available` — `gh` CLI usable for `gh workflow run`, `gh pr create`, `gh pr view` invocations across Plan 46-02.
- Memory `feedback_windows_worktree_cwd` — when `git worktree remove --force` fails (file lock), bash may implicitly target the stale worktree's branch ref on subsequent git ops. Plan 46-02 explicitly `cd /c/Users/OMack/Nono` + `pwd` + branch verify after each gh invocation.
- Memory `feedback_sdk_next_phase_skip` — `gsd-sdk query phase.complete <N>` advances numerically without re-checking ROADMAP completion. After Phase 46 close, verify ROADMAP "Status" column before trusting `next_phase` / STATE.md `## Current Position`. Affects parallel-safe milestone shapes (Phase 49 + 50 already shipped earlier in v2.6).
- Memory `feedback_clippy_cross_target` — cross-target Linux + macOS clippy from Windows host MUST for cfg-gated Unix code; N/A directly for Phase 46 (no source touches) but informs the `_environmental` carve-out per D-46-D2.
- Memory `project_pr643_doc_followup` — docs/drop-windows-preview-language branch holds commit 2173f93; reopen as 3-file PR after PR 583 merges. PR 583 is CLOSED; planner may flag this memory as stale post-Phase 46 close (PR 583 no longer the merge target).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`.github/workflows/phase-45-resl-native-host.yml`** — workflow_dispatch-only matrix workflow with `gh_runner_os: { type: choice, options: [ubuntu-24.04, macos-latest, both], default: both }` input per D-45-D2. Plan 46-03 mirrors this layout for `phase-46-uat-backlog.yml` per D-46-C2.
- **`.github/workflows/phase-37-linux-resl.yml`** — 302-line workflow with matrix ubuntu-24.04; 2 jobs (`resl-nix` + `pkgs-auto-pull`); cpu-controller delegation drop-in; machinectl shell invocation; sigstore-sign keyless OIDC step. Plan 46-02 dispatches via `gh workflow run`; no edits needed.
- **`.planning/quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-SUMMARY.md`** — current `status: re-deferred`; Plan 46-01 status flip target per D-46-A2. Contains the 504-commit / 77-conflict scope quantification, the 2026-04-29 outreach links, and the deferral conditions used to inform the new ADR's revival trigger set per D-46-A3.
- **`.planning/phases/43-upst5-sync-execution/43-{01b,02,03,04,05,06}-PR-SECTION.md`** — 6 staged contribution artifacts. Plan 46-02 concatenates for the `gh pr create` body per D-46-B3.
- **`.planning/templates/upstream-sync-quick.md:102`** — canonical baseline registry line; Plan 46-02 amends per D-46-D3.
- **`docs/architecture/upstream-parity-strategy.md`** — Phase 33 ADR; closest precedent for new `v2.6-upstream-merge-deferral-ADR.md` shape per D-46-A2.
- **Phase 37 + 41 + 43 HUMAN-UAT.md schema** — Plan 46-03 backfill template per D-46-C4. Frontmatter pattern: `status: passed` + `human_verification:` list of per-item rows with `test:` / `expected:` / `why_human:` keys.
- **Memory anchors `gh_available` + `project_cross_fork_pr_pattern`** — Plan 46-02 leverages both directly.

### Established Patterns

- **Per-requirement plan slicing (D-46-B1).** Plan 46-01 / 46-02 / 46-03 follow this pattern; mirrors Phase 44 / 45 / 49 / 50 precedent.
- **Single-wave parallel-safe plans (D-46-B2).** Plan 46-01 + 46-02 + 46-03 surfaces fully disjoint; mirrors Phase 45 wave-1 parallel pattern.
- **Workflow_dispatch-only tactical workflows (D-46-C2).** Mirrors Phase 45 D-45-D2 precedent; deletable in v3.0.
- **`no-test-fixture` waiver in plan SUMMARY (D-46-C3).** SC#5 explicit allowance; per-item rationale in 46-03-SUMMARY.
- **Backfilled HUMAN-UAT + VERIFICATION files (D-46-C4).** Honors SC#5 verbatim.
- **Baseline anchor inheritance (D-46-D1).** SC#4 verbatim `13cc0628`; Phase 41 → v2.5 → v2.6 → Phase 48 chain.
- **Strict + categorized CI gate threshold (D-46-D2).** Phase 40 anti-pattern #3 `_load_bearing` vs `_environmental` distinction.
- **`upstream-sync-quick.md:102` baseline registry update (D-46-D3).** Plan 46-02 last task; mirrors Phase 41 → v2.5 → v2.6 inheritance.
- **ADR + status-flip combo for deferral closures (D-46-A2).** Mirrors Phase 33 ADR shape + 260428-rsu summary deferral conditions.

### Integration Points

- **Phase 44 + 45 → Phase 46 (sequential dependency).** Both Phase 44 + Phase 45 closed (2026-05-20 + 2026-05-23). Phase 44 close SHA `aa510098` is the v2.6 quiet-baseline anchor (D-44-E1) but not the SC#4 diff anchor per D-46-D1.
- **Phase 46 → Phase 47 (UPST6 audit baseline).** Plan 46-02's `upstream-sync-quick.md:102` update per D-46-D3 sets the baseline for Phase 47 audit + Phase 48 sync execution per ROADMAP Cross-Phase Invariants.
- **Phase 46 → Phase 48 (post-merge baseline).** Phase 48's baseline-aware CI gate inherits Phase 46 close SHA per ROADMAP Cross-Phase Invariants line ("Baseline-aware CI gate — Phase 48 gates vs the Phase 46 post-merge baseline SHA, not the Phase 41 close SHA"). Recorded explicitly in `46-02-SUMMARY.md` + `upstream-sync-quick.md:102` per D-46-D3.
- **Phase 37 + 43 + 45 → Phase 46 (deferred verification handoff).** All three prior phases close one or more `human_needed` / `STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN` items in Plan 46-02. Phase 37 SC#6 → `passed`; Phase 43 Truths #4 + #5 → `passed`; Phase 45 REQ-RESL-NIX-04 → `passed`.
- **Phase 35 + 36 → Phase 46 (UAT backfill handoff).** Plan 46-03 backfills `35-HUMAN-UAT.md` + `35-VERIFICATION.md` + `36-HUMAN-UAT.md` + `36-VERIFICATION.md` per D-46-C4; both phases' VERIFICATION.md `status: human_needed → passed` at Plan 46-03 close.
- **Plan 46-01 ⇄ Plan 46-02 ⇄ Plan 46-03 (parallel, no inter-plan dependencies).** Surfaces fully disjoint:
  - 46-01 surface: `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md` (NEW) + `.planning/quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-SUMMARY.md` (UPDATE) + REQUIREMENTS.md `[x]` flip.
  - 46-02 surface: `gh` invocations (no source touches) + `46-02-SUMMARY.md` + `.planning/templates/upstream-sync-quick.md:102` (UPDATE) + REQUIREMENTS.md `[x]` flip.
  - 46-03 surface: `.github/workflows/phase-46-uat-backlog.yml` (NEW) + `.planning/phases/35-upst3-closure-quick-wins/35-HUMAN-UAT.md` (NEW) + `35-VERIFICATION.md` (NEW) + `.planning/phases/36-upst3-deep-closure/36-HUMAN-UAT.md` (NEW) + `36-VERIFICATION.md` (NEW) + `46-03-SUMMARY.md` + REQUIREMENTS.md `[x]` flip.

### Phase 46 plan + commit map (final)

```
Plan 46-01 (MERGE-doc deferral ADR)              Plan 46-02 (CI-FU orchestration)              Plan 46-03 (UAT-BL backfill)
   │  2-3 commits: ADR + summary flip + REQ        │  ~6 commits: 4 gh invocations + CI diff      │  ~5 commits: workflow + 4 backfill files
   │     [doc-only]                                 │   + upstream-sync-quick.md amendment           │   + summary + REQ
   │                                                │   + REQ
   ├─ docs(46-01): v2.6 upstream-merge              ├─ chore(46-02): gh workflow run                ├─ feat(46-03): .github/workflows/
   │     deferral ADR                               │   phase-37-linux-resl.yml (REQ-CI-FU-01)       │   phase-46-uat-backlog.yml (matrix
   ├─ docs(46-01): flip 260428-rsu summary          ├─ chore(46-02): gh workflow run                │   ubuntu-24.04 + macos-latest;
   │     status to closed-via-v2.6-rollout          │   phase-45-resl-native-host.yml -f             │   workflow_dispatch only)
   └─ docs(46-01): REQUIREMENTS.md [x]              │   gh_runner_os=both (REQ-RESL-NIX-04)         ├─ docs(46-03): backfill
         REQ-MERGE-01                               ├─ chore(46-02): gh pr create Phase 43          │   35-HUMAN-UAT.md +
                                                    │   umbrella (REQ-CI-FU-02; 6 PR-SECTION.md)    │   35-VERIFICATION.md
   Plan close: ADR landed; per-phase                ├─ docs(46-02): baseline-aware CI lane          ├─ docs(46-03): backfill
   umbrella PR pattern codified;                    │   diff vs 13cc0628 recorded (REQ-CI-FU-03)    │   36-HUMAN-UAT.md +
   REQ-MERGE-01 closed via feature-                 ├─ docs(46-02): upstream-sync-quick.md:102      │   36-VERIFICATION.md
   flag-equivalent rollout                          │   baseline registry update                    └─ docs(46-03): REQUIREMENTS.md [x]
                                                    └─ docs(46-02): REQUIREMENTS.md [x]                 REQ-UAT-BL-01..02 + 46-03-SUMMARY
                                                          REQ-CI-FU-01..03

  Three plans land on a Phase 46 feature branch → merge to main.
  No upstream PR umbrella for Phase 46 itself (consistent with Plan 46-01's
  feature-flag-equivalent rollout decision). Phase 43 umbrella PR is opened
  by Plan 46-02 as a separate event — it's the Phase 43 contribution to
  upstream, not a Phase 46 contribution.
```

</code_context>

<specifics>
## Specific Ideas

- **D-46-A1 chose feature-flag-equivalent rollout over rebase resumption.** Rationale: the 504-commit / 77-conflict scope is empirically not a runbook-sized task; the 16 `*_runtime.rs` AA add/add cluster is architectural collision, not drift; and maintainer-non-response since 2026-04-29 means the merge gate hasn't moved. Closing via the SC#1 alternative path preserves the work disposition without indefinite timeline risk.

- **D-46-A4 chose to codify the per-phase umbrella PR pattern explicitly.** Rationale: the pattern is already in use (Phase 22 / 33 / 39 / 42 / 43 + PR 922) but only documented in memory `project_cross_fork_pr_pattern`. Promoting it to the ADR makes the fork's upstream-contribution mode auditable and prevents future-phase drift. The Phase 43 umbrella PR opened by Plan 46-02 is the live exemplar.

- **D-46-B1 chose 3 plans over 5 plans.** Rationale: 5 plans (per-success-criterion) creates orchestration overhead without clearer per-plan SUMMARY closure; 3 plans (per-requirement) gives each plan a single REQ-cluster to close cleanly. Mirrors the Phase 44 / 45 / 49 / 50 precedent.

- **D-46-B3 chose all-4-CI-actions-in-parallel.** Rationale: GH Actions concurrency is the friend; the 4 actions are mutually independent (Phase 37 + 45 workflows don't share state with Phase 43 PR CI). The baseline-aware CI diff is observed last because it's an observation, not an action. Per-action attribution captured via per-workflow run-id in 46-02-SUMMARY.

- **D-46-C2 chose new `phase-46-uat-backlog.yml` over extending existing workflows.** Rationale: tactical-by-design, single-purpose, deletable in v3.0. Mirrors Phase 45 D-45-D2's "workflow_dispatch-only tactical workflow" pattern. Avoids conflating Phase 37 / 45 CI (verification of those phases' surfaces) with Phase 35 / 36 UAT (verification of older phases' surfaces).

- **D-46-D1 chose `13cc0628` over `aa510098`.** Rationale: ROADMAP SC#4 plain-reading is the load-bearing wording; v2.6 quiet-baseline `aa510098` is an internal-observability anchor for Phase 44 + 45 work, not the SC#4 anchor. The history captured by the SC#4 anchor (Phase 41 close → v2.5 close → Phase 46 close) is the canonical CI-lane-health timeline.

- **D-46-D2 chose strict + categorized over strict-no-carve-outs.** Rationale: `_environmental` skips are real (e.g., cross-target clippy on Windows-host lacking aws-lc-sys cross-compiler) and have already been codified at Phase 40 / 41 / 43 / 45. Treating them as blocking would force deviation-handling for non-actionable transitions. Phase 40 anti-pattern #3 is the canonical carve-out shape.

</specifics>

<deferred>
## Deferred Ideas

- **Active fresh outreach to upstream maintainer on PRs 725 / 726.** Could be useful if maintainer engagement is sought before the next milestone close. Not scoped for Phase 46 (rejected at D-46-A1). Could be a future quick-task if the user wants to nudge.

- **Two-baseline CI diff (`13cc0628` + `aa510098`).** Captures both the v2.5-to-v2.6 history + the v2.6-internal history. Rejected at D-46-D1 in favor of SC#4 plain-reading. Could be revisited at Phase 48 if the dual-baseline framing helps Phase 48 attribution.

- **Live-derived lane enumeration for the CI diff.** Catches any lanes added since `13cc0628` (e.g., Phase 49 / 50 may have added jobs). Rejected at D-46-D4 in favor of SC#4 verbatim. Any added lanes are noted informationally in 46-02-SUMMARY; not blocking.

- **Per-phase REQUIREMENTS.md flip consolidation.** Plan 46-03 could consolidate all REQ checkbox flips at its close (since it's last to land in some execution orders). Default per Claude's discretion: each plan flips its own REQs.

- **Drift-quantification revival trigger for the upstream merge.** Rejected at D-46-A3. Could be revisited at v3.0 milestone start if the user wants to track the rebase-cost cliff over time.

- **v3.0 milestone calendar trigger for upstream merge revival.** Rejected at D-46-A3. v3.0 planner may re-evaluate at milestone-start.

- **Re-anchoring non-automatable UAT items into the WR-02 EDR HUMAN-UAT bucket.** Rejected at D-46-C3 in favor of per-item `no-test-fixture` waivers in 46-03-SUMMARY. Could be revisited at v3.0 if the EDR bucket gets an instrumented runner and the non-automatable Phase 35 / 36 items fit there cleanly.

- **Permanent always-on UAT CI lane.** Rejected at D-46-C2 in favor of workflow_dispatch-only tactical workflow. Could be promoted to always-on in v3.0 if post-Phase-46 experience shows the Phase 35 / 36 surfaces are regression-prone.

- **Memory `project_pr643_doc_followup` staleness.** That memory says "reopen as 3-file PR after PR 583 merges." PR 583 is CLOSED unmerged at discussion time; the memory may need updating post-Phase 46 close. Not in scope for Phase 46 itself.

### Reviewed Todos (not folded)

Two todos surfaced by `todo.match-phase 46` (both score 0.6, keyword-only matches):

- **`44-class-d-validator-preflight-investigation.md`** — Phase 44 D-44-C3 follow-up about `validate_deny_overlaps` pre-flight in `crates/nono-cli/src/policy.rs:1032-1088`. Not folded — Phase 44 CONTEXT § Deferred Ideas explicitly tags this for "a future Linux-host phase (Phase 46 or beyond)" but Phase 46 is doc + orchestrator + workflow-only with no source touches per D-46-B1/B2/B3. The "Phase 46 or beyond" tag was authored before this discussion locked Plan 46-01..03 as source-untouching. Re-anchor target: a future Linux-host source phase. Score-0.6 keyword match (`opened, 2026, phase, req, test`) reflects the generic vocabulary of follow-up todos, not topical fit.

- **`44-validate-restore-target-fd-relative-hardening.md`** — Phase 44 D-44-B4 follow-up about TOCTOU hardening in `crates/nono/src/undo/snapshot.rs::validate_restore_target`. Not folded — Phase 44 CONTEXT § Deferred Ideas explicitly tags this as a "substantial cross-platform refactor: Linux + macOS + Windows have different fd-relative semantics" requiring its own security-scoped phase. Phase 46 is doc + orchestrator + workflow-only; would not fit. Score-0.6 keyword match (`opened, 2026, phase, req, security`) reflects the same generic vocabulary.

Both stay in `.planning/todos/pending/` for the appropriate future phase.

</deferred>

---

*Phase: 46-windows-squash-merge-post-merge-ci-verifications-uat-backlog*
*Context gathered: 2026-05-23*
