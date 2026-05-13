# Phase 39: UPST4 audit - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-13
**Phase:** 39-upst4-audit
**Areas discussed:** Audit upper bound, Plan shape, Windows-cluster flagging, Re-audit posture mid-phase

---

## Audit upper bound

### Q1: What's the upper bound for the v0.52.0..upstream-HEAD audit range?

| Option | Description | Selected |
|--------|-------------|----------|
| v0.53.0 release boundary | Cap at v0.53.0 (`c4b25b82`, 3 tags, ~27 non-merge commits). Matches Phase 33 pattern. Clean reproducibility. | ✓ |
| Upstream HEAD at phase-start | Include 7 post-v0.53.0 unreleased commits up to upstream HEAD `b4f21611` (~34 non-merge commits). | |
| Hybrid (release + flagged unreleased) | Cap clusters at v0.53.0 BUT add a § Post-release watch section flagging unreleased commits. | |

**User's choice:** v0.53.0 release boundary
**Notes:** Clean release-boundary audit; reproducibility for re-runners. Post-v0.53.0 commits roll into UPST5 per cadence rule.

### Q2: Should the ledger note what's known beyond v0.53.0?

| Option | Description | Selected |
|--------|-------------|----------|
| Strictly silent | Ledger covers v0.52.0..v0.53.0 only. Matches Phase 33's posture. | ✓ |
| One-line cadence note | One-line note "N additional commits exist post-v0.53.0; UPST5 covers them." | |
| Watch section | Dedicated § Post-v0.53.0 watch section with one-line dispositions. | |

**User's choice:** Strictly silent
**Notes:** Cadence rule is structural; mentioning post-range commits muddies the audit boundary.

### Q3: Frontmatter reproducibility — what to capture?

| Option | Description | Selected |
|--------|-------------|----------|
| Same as Phase 33 | Range + invocation + upstream HEAD sha + drift-tool shas. | ✓ |
| Lean (range + invocation only) | Drop the HEAD sha + drift-tool shas. | |
| Phase 33 + git-fetch timestamp | Add `audit_date` + git-fetch timestamp. | |

**User's choice:** Same as Phase 33 (recommended)
**Notes:** D-33-A1 + A2 inherited verbatim; drift-tool sha is still `0834aa66`, unchanged since Phase 24.

### Q4: ROADMAP next-cycle queue — should Phase 39 queue an UPST5 placeholder?

| Option | Description | Selected |
|--------|-------------|----------|
| Queue UPST5 placeholder | Phase 39 closes by adding UPST5 audit phase entry. Matches Phase 33. | ✓ |
| No queue — lazy fire | Don't queue; ADR's "lazily-evaluated" rule fires when needed. | |
| Queue conditional on backlog | Add to backlog section only, not active milestone. | |

**User's choice:** Queue UPST5 placeholder
**Notes:** Reader sees the cadence wheel turning.

### Q5: Where in ROADMAP does the UPST5 placeholder land?

| Option | Description | Selected |
|--------|-------------|----------|
| v2.5 backlog stub | Phase N (TBD-NN) under v2.5 or backlog. `Depends on: Phase 40`. | ✓ |
| Inline in v2.4 — audit+exec pair | Queue both UPST5-audit + UPST5-exec under v2.4 immediately. | |
| Just a one-line backlog note | Plain-text backlog note; no phase entry yet. | |

**User's choice:** v2.5 backlog stub (recommended)
**Notes:** Preserves cadence signal without committing v2.4 scope.

---

## Plan shape

### Q1: How many plans should Phase 39 ship?

| Option | Description | Selected |
|--------|-------------|----------|
| Single plan | One plan `39-01-DIVERGENCE-AUDIT` does drift run → curation → ledger → ADR review → ROADMAP. | ✓ |
| Two plans (audit + queue) | Plan 39-01 = drift run + ledger; Plan 39-02 = UPST5 ROADMAP stub + STATE.md + close. | |
| Four plans (Phase 33 shape) | Drift run / ledger curation / ADR review / ROADMAP queue. | |

**User's choice:** Single plan (recommended)
**Notes:** ~27 commits doesn't justify splitting; Phase 33's 4-plan shape was driven by ADR write + G-25 closure, neither of which Phase 39 has.

### Q2: What's the close-gate / done-check for the single audit plan?

| Option | Description | Selected |
|--------|-------------|----------|
| Phase 33 D-33-style (audit-only) | 5 standard checks; no cross-target clippy (Phase 39 ships zero .rs files). | |
| Phase 33 + ADR-review-section check | All Phase 33 checks PLUS explicit § ADR review section grep check. | ✓ |
| Phase 33 + cross-target clippy | All Phase 33 checks PLUS cross-target clippy gate. | |

**User's choice:** Phase 33 + ADR-review-section check
**Notes:** Falsifiable grep for `## ADR review` confirms cadence rule was honored.

### Q3: How should Phase 39 hand the disposition ledger to Phase 40?

| Option | Description | Selected |
|--------|-------------|----------|
| Disposition-complete at Phase 39 close | Every cluster's disposition locked; Phase 40 inherits immutable input. | |
| Disposition-proposed, Phase 40 locks | Phase 39 proposes; Phase 40 confirms ambiguous cases. | |
| Disposition-complete + suggested wave order | Like option 1 PLUS suggest wave/foundation order. | ✓ |

**User's choice:** Disposition-complete + suggested wave order
**Notes:** Phase 39 sees the commits and has the information; passing along reduces Phase 40 startup cost.

### Q4: How prescriptive should Phase 39's suggested wave order be?

| Option | Description | Selected |
|--------|-------------|----------|
| Hints + foundation flag | Tag largest cluster as `wave-hint: foundation`; flag inter-cluster dependencies; otherwise leave to Phase 40. | ✓ |
| Full Phase 33-style mapping | Wave 0/1/2/3 mapping a la D-34-A2. | |
| No wave hints — disposition only | Roll back the previous answer; disposition only. | |

**User's choice:** Hints + foundation flag
**Notes:** Lightweight guidance; Phase 40 planner retains full discretion to refine.

---

## Windows-cluster flagging

### Q1: How should the ledger flag upstream commits that ADD new Windows code outside D-11-excluded paths?

| Option | Description | Selected |
|--------|-------------|----------|
| Inline tag in commit rows | `windows-touch: yes/no` column in commit-row tables. | ✓ |
| Dedicated § Windows-touching upstream commits section | Separate section after clusters listing every Windows-relevant commit. | |
| Cluster-level disposition rationale only | No structural marker; rationale line covers it. | |

**User's choice:** Inline tag in commit rows (recommended)
**Notes:** Reader scans the column inside cluster tables; no drift risk between two views.

### Q2: How to determine `windows-touch: yes` — mechanical or judgment?

| Option | Description | Selected |
|--------|-------------|----------|
| Mechanical filename heuristic | `windows-touch: yes` iff filename matches pinned list. Easy, no judgment risk. | |
| Judgment + diff read | Auditor reads diffs for ambiguous cases. Higher curation cost. | |
| Both — mechanical pass + judgment override | Mechanical baseline; auditor confirms or overrides flagged commits. | ✓ |

**User's choice:** Both — mechanical pass + judgment override
**Notes:** Hybrid matches Phase 33's audit-walk methodology for ambiguous-disposition commits.

### Q3: If a commit is `windows-touch: yes`, does it change disposition decision logic?

| Option | Description | Selected |
|--------|-------------|----------|
| No — same 3-value enum applies | `windows-touch: yes` is purely informational. | |
| Windows-touching defaults to fork-preserve unless empty fork-side | Conservative default; protects D-11 invariant. | ✓ |
| Windows-touching forces ADR review | Any windows-touch cluster triggers automatic § ADR review entry. | |

**User's choice:** Windows-touching defaults to fork-preserve unless empty fork-side
**Notes:** Phase 40 inherits safer execution baseline; can upgrade to will-sync at plan-phase if audit caution turns out excessive. Reverse (downgrade mid-execution) is more expensive.

### Q4: Does the Windows-touch → fork-preserve default need an § ADR review section?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — explicit ADR review section | Section notes Phase 33 ADR didn't anticipate this shape; ADR remains Accepted. | ✓ |
| No — cluster rationale suffices | Inline per-cluster rationale only. | |
| Conditional — only if 2+ clusters trigger | Threshold-driven escalation. | |

**User's choice:** Yes — explicit ADR review section
**Notes:** Falsifiable via grep; reviewer confirms cadence rule was honored without reading every cluster rationale.

---

## Re-audit posture mid-phase

### Q1: If upstream ships v0.53.1 or v0.54.0 during Phase 39 audit week, what happens?

| Option | Description | Selected |
|--------|-------------|----------|
| Lock at phase-start | Audit range = `v0.52.0..<upstream-HEAD at phase-start>`. Matches Phase 33. | ✓ |
| Re-run on each plan close | Chase moving target; refresh ledger if upstream ships during the week. | |
| Re-run only if security-relevant tag lands | Compromise; auditor judges. | |

**User's choice:** Lock at phase-start (recommended)
**Notes:** Frontmatter `upstream_head_at_audit` sha makes snapshot reproducible.

### Q2: When is "phase-start" for the upstream-HEAD lock?

| Option | Description | Selected |
|--------|-------------|----------|
| First commit of Plan 39-01 | Auditor runs `git fetch upstream --tags` then captures sha as FIRST act of Plan 39-01. | ✓ |
| Phase 39 commit start (planner commit) | Lock at first Phase 39 commit (plan, context, or roadmap edit). | |
| Ledger-write commit (final curation) | Lock when ledger is being written. | |

**User's choice:** First commit of Plan 39-01 (recommended)
**Notes:** Matches Phase 33 D-33-A1 + A2 posture exactly.

### Q3: What if a security-relevant upstream commit lands AFTER the lock but BEFORE Phase 40 starts?

| Option | Description | Selected |
|--------|-------------|----------|
| Honor lock; UPST5 absorbs it | Lock is structural; preserve reproducibility. | ✓ |
| Append-only ledger addendum | Phase 39 stays locked; `## Addendum` section documents post-lock commits. | |
| Re-run audit at Phase 40 plan-phase | Phase 40 plan-phase re-runs drift tool; treats delta as Phase 40 input. | |

**User's choice:** Honor lock; UPST5 absorbs it (recommended)
**Notes:** Lock is structural; preserving reproducibility outweighs one absorption-cycle delay cost.

### Q4: If the auditor discovers a drift-tool bug mid-phase, what's the response?

| Option | Description | Selected |
|--------|-------------|----------|
| Document inline; defer fix | Audit ledger documents bug; tool fix in follow-up phase. | |
| Fix tool in Plan 39-01 | Fold tool fix into Phase 39 directly. | |
| Document + spawn tool-fix quick-task | Document inline AND create `.planning/quick/` quick-task entry. | ✓ |

**User's choice:** Document + spawn tool-fix quick-task
**Notes:** Preserves `drift_tool_sh_sha` frontmatter reproducibility; bug captured + scope preserved.

---

## Claude's Discretion

- **Cluster grouping heuristic** — auditor decides cluster boundaries during audit walk.
- **Per-cluster `wave-hint` granularity** — auditor decides which clusters warrant wave-hint annotation; foundation flag on largest cluster is high-value, per-cluster wave numbers are over-prescriptive.
- **UPST5 stub title wording** — `... audit` vs `... sync execution` based on Phase 39 ledger shape.
- **Whether to capture a Fork-only surface area delta section** — auditor decides based on what audit walk surfaces re: Phase 35/36/36.5 new fork-only Windows surface.
- **Ledger header exact wording** beyond the frontmatter fields locked in D-39-A2.
- **`make ci` re-run cadence** — auditor may run once at plan close OR per-commit.

## Deferred Ideas

- **Post-v0.53.0 commit absorption** — UPST5 absorbs per the lazily-evaluated cadence rule when v0.54.0 ships or maintainer decides accumulated labor warrants firing.
- **Drift-tool fixes surfaced mid-audit** — fixes land as `.planning/quick/` tasks, NOT folded into Phase 39.
- **Full wave-map for Phase 40** — Phase 40 planner decides full Wave 0/1/2/3 mapping.
- **Fork-only surface area delta enumeration** — Phase 39 may add a § Delta-since-Phase-33 section if needed; auditor's discretion.
- **Superseding ADR** — if § ADR review section surfaces evidence Option A no longer holds, that's a Phase-NN superseding ADR, NOT a Phase 39 inline edit.

### Reviewed Todos (not folded)

- `v24-cr-01-broker-not-found-ffi-mapping.md` — Phase 31 broker CR; unrelated to UPST4 audit.
- `v24-cr-02-broker-null-handle-validation.md` — Phase 31 broker CR; unrelated.
- `v24-cr-03-broker-empty-handle-list-path.md` — Phase 31 broker CR; unrelated.
- `v24-cr-04-job-object-test-skip-policy.md` — Phase 31 broker CR; unrelated.

All matched on generic "phase, review, planning, phases, architecture" keywords (score 0.6).
