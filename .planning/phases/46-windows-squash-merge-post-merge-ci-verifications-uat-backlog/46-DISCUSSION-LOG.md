# Phase 46: windows-squash merge + post-merge CI verifications + UAT backlog - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-23
**Phase:** 46-windows-squash-merge-post-merge-ci-verifications-uat-backlog
**Areas discussed:** REQ-MERGE-01 disposition, Plan slicing + CI sequencing, Phase 35+36 UAT host strategy, Baseline anchor + CI gate threshold

---

## REQ-MERGE-01 disposition

### Q1: Which REQ-MERGE-01 disposition does Phase 46 close on?

| Option | Description | Selected |
|--------|-------------|----------|
| Feature-flag-equivalent rollout (defer) | Document the upstream-merge as deferred + close REQ-MERGE-01 via the SC#1 alternative path. PRs 725/726 remain OPEN with the 2026-04-29 outreach as canonical comm. Re-anchor as v3.0 candidate. | ✓ |
| Re-poll maintainer + decide on response | Post a fresh prompt to PRs 725/726 + N-day soft deadline. If maintainer responds, execute that path. Else fall back to feature-flag-equivalent. | |
| Resume 260428-rsu force-rebase | Re-attempt the rebase that aborted at 77 conflicts. Architectural review per AA add/add cluster (16 *_runtime.rs files). Major scope. | |

**User's choice:** Feature-flag-equivalent rollout (defer)
**Notes:** D-46-A1 captures rationale.

### Q2: What does the "feature-flag-equivalent rollout" doc actually look like?

| Option | Description | Selected |
|--------|-------------|----------|
| ADR + update existing 260428-rsu summary | New ADR at `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md` capturing alternative paths + revival triggers + go-forward mode. Plus update `260428-rsu-SUMMARY.md` status `re-deferred → closed-via-v2.6-rollout`. | ✓ |
| Update 260428-rsu summary only + Phase 46 SUMMARY section | Lighter: flip `260428-rsu-SUMMARY.md` status + add `## REQ-MERGE-01 disposition` section in Phase 46 SUMMARY. No standalone ADR. | |
| Phase 46 SUMMARY-only mention | Minimal 2-3 paragraphs in Phase 46 SUMMARY. 260428-rsu artifact untouched. Lowest auditability. | |

**User's choice:** ADR + update existing 260428-rsu summary
**Notes:** D-46-A2.

### Q3: What revival triggers does the ADR codify?

| Option | Description | Selected |
|--------|-------------|----------|
| Maintainer-response triggers only | (a) maintainer comments with directional guidance, (b) maintainer closes/merges either PR, (c) maintainer requests a different approach. No fork-side calendar. | ✓ |
| Maintainer-response + v3.0-milestone trigger | Adds a fork-side calendar trigger at v3.0 milestone start. | |
| Maintainer-response + drift-quantification trigger | Adds a periodic drift-quantification trigger; if scope exceeds N commits or M conflicts, escalate. | |

**User's choice:** Maintainer-response triggers only
**Notes:** D-46-A3.

### Q4: Does the ADR explicitly codify the per-phase umbrella PR pattern as go-forward?

| Option | Description | Selected |
|--------|-------------|----------|
| Codify per-phase umbrella PR as go-forward + cite Phase 22/33/39/42/43 precedent | ADR: while PRs 725/726 remain held, fork's upstream contribution mode is per-phase umbrella PR per memory `project_cross_fork_pr_pattern`. PR 922 (Phase 40) + Phase 43 umbrella (REQ-CI-FU-02) are active reference shapes. | ✓ |
| Note the pattern but don't bind future phases | Mentions the pattern as current de-facto mode but doesn't lock future phases into it. | |
| Don't address go-forward | ADR only addresses the deferral decision. Go-forward pattern is implicit per memory. | |

**User's choice:** Codify per-phase umbrella PR as go-forward + cite Phase 22/33/39/42/43 precedent
**Notes:** D-46-A4.

---

## Plan slicing + CI sequencing

### Q1: How should Phase 46 plans be sliced?

| Option | Description | Selected |
|--------|-------------|----------|
| Per-requirement: 3 plans (MERGE-doc / CI-FU / UAT-BL) | Plan 46-01 MERGE-doc + 46-02 CI-FU + 46-03 UAT-BL. Mirrors Phase 44 / 45 / 49 / 50. | ✓ |
| Per-stream: 5 plans (MERGE / CI-37+45 / CI-43-PR / CI-DIFF / UAT) | Finer-grained: per-stream plans. More orchestration overhead but easier per-stream partial-close. | |
| Per-host-context: 2 plans (Windows-host + Native-host) | Cleaner host-availability handoff. | |
| Single mega-plan with task-level breakdown | Least overhead but harder to mark partial-close per stream. | |

**User's choice:** Per-requirement: 3 plans (MERGE-doc / CI-FU / UAT-BL)
**Notes:** D-46-B1.

### Q2: Are the 3 plans parallel-safe (single wave) or sequential?

| Option | Description | Selected |
|--------|-------------|----------|
| Parallel-safe: all 3 in one wave | Surfaces fully disjoint; mirror Phase 45's wave-1 parallel pattern. | ✓ |
| Sequential: 46-01 → 46-02 → 46-03 | Force ordering: doc first, then CI orchestration, then UAT. | |
| Hybrid: 46-01 (doc, anywhere) + parallel 46-02 / 46-03 once doc lands | Plan 46-01 doc lands first; then 46-02 + 46-03 parallel. | |

**User's choice:** Parallel-safe: all 3 in one wave
**Notes:** D-46-B2.

### Q3: Within Plan 46-02, how are the 4 CI actions sequenced?

| Option | Description | Selected |
|--------|-------------|----------|
| All 4 in parallel: dispatch Phase 37 + Phase 45 workflows + open Phase 43 PR concurrently, observe CI diff last | Fastest wall-clock; matches GH Actions concurrency. | ✓ |
| Sequential: Phase 43 PR first (own branch), then Phase 37 + 45 workflows, then CI diff | Cleaner attribution: each CI lane has a known commit SHA driver. | |
| Two-stage: 37+45 workflow dispatches first (workflow_dispatch only), then Phase 43 PR + CI diff | Decouples "verification CI" from "contribution CI". | |

**User's choice:** All 4 in parallel
**Notes:** D-46-B3.

---

## Phase 35+36 UAT host strategy

### Q1: What native host(s) does Phase 46 have access to for the UAT execution?

| Option | Description | Selected |
|--------|-------------|----------|
| GitHub Actions only (ubuntu-24.04 + macos-latest matrix) | Items execute via GH Actions runners through dedicated workflow_dispatch workflows. Familiar pattern. Some interactive items waive as `no-test-fixture`. | ✓ |
| Personal native Linux host + GH Actions for macOS | Mixed-mode; interactive Linux + macOS dispatches to GH Actions. | |
| Personal native Linux + macOS hosts available | Items execute interactively on each host. Highest fidelity. | |
| No native host now — stretch GH Actions, document interactive items as `no-test-fixture` | Treat the entire UAT-BL stream as GH-Actions-or-bust. | |

**User's choice:** GitHub Actions only (ubuntu-24.04 + macos-latest matrix)
**Notes:** D-46-C1.

### Q2: What's the workflow shape for the UAT items?

| Option | Description | Selected |
|--------|-------------|----------|
| New workflow_dispatch-only `phase-46-uat-backlog.yml` (tactical, deletable in v3.0) | Mirror Phase 45 RESL pattern. Matrix ubuntu-24.04 + macos-latest. | ✓ |
| Extend `phase-37-linux-resl.yml` + `phase-45-resl-native-host.yml` with UAT job | Less file sprawl; co-locates with related verification work. Risk: conflates scopes. | |
| Folded into existing `ci.yml` PR-triggered lanes | Add UAT items as new test targets. Highest visibility; risk: turns tactical into ongoing CI cost. | |

**User's choice:** New workflow_dispatch-only `phase-46-uat-backlog.yml` (tactical, deletable in v3.0)
**Notes:** D-46-C2.

### Q3: How are non-automatable UAT items closed?

| Option | Description | Selected |
|--------|-------------|----------|
| `no-test-fixture` waiver in 46-03-SUMMARY with explicit per-item rationale | Each item gets a row with description + why-cannot-automate + waiver status per SC#5. | ✓ |
| Defer non-automatable items to v3.0 instead of waiving | REQ-UAT-BL-01 closes as PARTIAL. | |
| Re-frame as `EDR/interactive` items — align with existing WR-02 EDR HUMAN-UAT pattern | Single category for all manual UAT, single resolution event. | |

**User's choice:** `no-test-fixture` waiver in 46-03-SUMMARY with explicit per-item rationale
**Notes:** D-46-C3.

### Q4: Where do the canonical UAT item lists live after Phase 46 close?

| Option | Description | Selected |
|--------|-------------|----------|
| Backfill Phase 35 + 36 HUMAN-UAT.md and VERIFICATION.md files; Plan 46-03 also writes a roll-up SUMMARY | Phase 35 + 36 VERIFICATION.md `status: human_needed → passed`. Honors SC#5 literally. | ✓ |
| Plan 46-03 SUMMARY only — don't touch Phase 35 + 36 dirs | Single canonical roll-up in 46-03-SUMMARY. Lighter. Risk: violates SC#5 literal-reading. | |
| Phase 46 dedicated `46-PHASE-35-36-UAT.md` + brief stubs in Phase 35 + 36 dirs pointing to it | Honors SC#5 structurally without duplicating content. | |

**User's choice:** Backfill Phase 35 + 36 HUMAN-UAT.md and VERIFICATION.md files; Plan 46-03 also writes a roll-up SUMMARY
**Notes:** D-46-C4.

---

## Baseline anchor + CI gate threshold

### Q1: Which baseline SHA is authoritative for Phase 46's CI lane diff (REQ-CI-FU-03)?

| Option | Description | Selected |
|--------|-------------|----------|
| `13cc0628` (Phase 41 close) — honor ROADMAP SC#4 verbatim | v2.6 work lands on top of `13cc0628`; lane diff captures success → failure since v2.5 close. SC#4 plain-reading. | ✓ |
| `aa510098` (Phase 44 close) — honor D-44-E1 quiet-baseline | v2.6 work compared internally; ignores pre-v2.6 noise. SC#4 wording amended with editorial note. | |
| Both: report 2-column diff vs `13cc0628` AND `aa510098` | Plan 46-02 records both diffs side-by-side. Closes the literal-reading + internal-baseline question simultaneously. | |

**User's choice:** `13cc0628` (Phase 41 close) — honor ROADMAP SC#4 verbatim
**Notes:** D-46-D1.

### Q2: What's the threshold semantics for the CI lane diff?

| Option | Description | Selected |
|--------|-------------|----------|
| Strict + categorized: success→failure blocks UNLESS classified as load-bearing-skip per Phase 40 anti-pattern #3 | Strict by default. `_environmental` skips allowed. Same rule inherited at Phase 48. | ✓ |
| Strict-no-carve-outs: any success→failure blocks | No carve-outs. Highest signal, lowest false-negatives. | |
| Lenient: track all transitions but don't gate close | Record every transition in 46-02-SUMMARY with disposition. Phase 46 closes regardless. | |

**User's choice:** Strict + categorized
**Notes:** D-46-D2.

### Q3: Phase 46 close → Phase 48's baseline handoff: how is it recorded?

| Option | Description | Selected |
|--------|-------------|----------|
| Phase 46 SUMMARY records the close SHA + `.planning/templates/upstream-sync-quick.md:102` baseline registry update | Phase 46 SUMMARY captures close SHA + Plan 46-02 last task amends the registry. Matches Phase 41 → v2.5 → v2.6 inheritance pattern. | ✓ |
| Phase 46 SUMMARY only — leave template registry update to Phase 47 plan-open | SUMMARY captures close SHA; registry update at Phase 47 plan-open. | |
| Skip explicit SHA recording — Phase 47 reads `git log main` at plan-open | No persistent record; Phase 47 / 48 re-derive baseline from `git log`. | |

**User's choice:** Phase 46 SUMMARY records the close SHA + `.planning/templates/upstream-sync-quick.md:102` baseline registry update
**Notes:** D-46-D3.

### Q4: ROADMAP SC#4 names 8 GH Actions lanes. What's the canonical lane list for the diff?

| Option | Description | Selected |
|--------|-------------|----------|
| Verbatim from SC#4: Linux Clippy, macOS Clippy, Windows Build, Integration, Regression, Security, Packaging, Smoke | Use the exact 8-lane list from ROADMAP SC#4 line 128. | ✓ |
| Live-derived from `.github/workflows/ci.yml` jobs at Phase 46 close | Read `ci.yml` at Phase 46 close. Catches any lane additions. | |
| SC#4 verbatim + a `_added_since_13cc0628` row for any new lanes | Use SC#4's 8 lanes for the diff + separately document any added lanes. | |

**User's choice:** Verbatim from SC#4
**Notes:** D-46-D4.

---

## Claude's Discretion

The following items were noted as planner discretion:
- Exact path for the ADR file (`.planning/architecture/v2.6-upstream-merge-deferral-ADR.md` vs `.planning/architecture/v2.6-upstream-merge-deferral.md`).
- ADR content depth.
- Per-plan REQUIREMENTS.md flip semantics (each plan flips its own REQs vs consolidated flip at last plan close).
- `phase-46-uat-backlog.yml` exact matrix + invocation specifics.
- UAT item inventory at plan-open (canonical 11 + 7 list).
- Backfilled Phase 35 + 36 HUMAN-UAT.md / VERIFICATION.md schema.
- Phase 43 umbrella PR body assembly (branch name, title, exact `gh pr create` flags).
- `upstream-sync-quick.md:102` exact amendment shape.
- Plan numbering (suggested: 46-01-MERGE-DEFERRAL-ADR, 46-02-POST-MERGE-CI-ORCHESTRATION, 46-03-PHASE-35-36-UAT-DRAIN).

## Deferred Ideas

- Active fresh outreach to upstream maintainer on PRs 725 / 726.
- Two-baseline CI diff (`13cc0628` + `aa510098`).
- Live-derived lane enumeration for the CI diff.
- Per-phase REQUIREMENTS.md flip consolidation.
- Drift-quantification revival trigger for the upstream merge.
- v3.0 milestone calendar trigger for upstream merge revival.
- Re-anchoring non-automatable UAT items into the WR-02 EDR HUMAN-UAT bucket.
- Permanent always-on UAT CI lane.
- Memory `project_pr643_doc_followup` staleness (PR 583 is CLOSED unmerged; memory needs updating post-Phase 46 close).
- Two reviewed-but-not-folded todos: `44-class-d-validator-preflight-investigation.md`, `44-validate-restore-target-fd-relative-hardening.md` (both require Linux-host source phases; Phase 46 is doc + orchestrator-only).
