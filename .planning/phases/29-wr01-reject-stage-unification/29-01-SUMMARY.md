---
phase: 29-wr01-reject-stage-unification
plan: 01
subsystem: audit-aipc-design
tags: [wr01, reject-stage, audit, design-decision, docs, locked]
status: complete
type: execute-summary
duration: ~15 min
completed: 2026-04-30
requirements_closed: [WRU-01, WRU-02]
key_files:
  modified:
    - .planning/PROJECT.md
    - crates/nono-cli/src/exec_strategy_windows/supervisor.rs
    - crates/nono-cli/src/audit_integrity.rs
  byte_identical_preserved:
    - crates/nono/  (entire crate; D-19)
    - crates/nono-cli/src/audit_commands.rs (Phase 23 counter rendering)
metrics:
  commits: 3
  files_modified: 3
  lines_added: 41
  lines_removed: 13
---

# Phase 29 Plan 01: WR-01 Reject-Stage Unification — Summary

**One-liner:** Locked the WR-01 reject-stage asymmetry as a permanent design property (Option c). The mask-gate-vs-broker-failure-flip distinction is structural — O(1) profile lookup vs O(syscall) post-approval — not a unifiable bug. Documentation-only closure of the longest-deferred v2.x product question.

## Outcome

REQ-WRU-01 + REQ-WRU-02 both closed. The fork's posture on the WR-01 reject-stage asymmetry is now explicit: Event/Mutex/JobObject reject `BeforePrompt` because their checkability is upfront (profile-mask lookup); Pipe/Socket reject `AfterPrompt` because their failure modes are only OS-observable (kernel-op attempt required). Forcing pre-prompt rejection for Pipe/Socket would require either re-implementing kernel checks in supervisor space (security regression — violates defense-in-depth) or deferring all approval prompts until after broker attempts (UX regression — breaks the approval-then-action contract Phase 18 shipped).

The decision was the longest-deferred v2.x product question — originally surfaced in v2.1 Phase 18.1 D-14, marked "deferred to v2.2", deferred again at v2.2 close into v2.3 backlog. Phase 29 closes it definitively.

## Verification gates (5/5 critical pass; 1 documented-skip)

| # | Gate | Expected | Actual | Status |
|---|------|----------|--------|--------|
| 1 | cargo build --workspace | clean | Finished dev profile in 1.75s | PASS |
| 2 | cargo test -p nono-cli --bin nono wr01_ | all 5 wr01_* tests pass with assertions UNCHANGED | 5 passed; 0 failed; 0 ignored | PASS |
| 3 | cargo fmt --all -- --check | clean | clean (empty output) | PASS |
| 4 | D-19: git diff --stat HEAD~3..HEAD -- crates/nono/ | empty | empty | PASS |
| 5 | Phase 23 counter rendering: git diff crates/nono-cli/src/audit_commands.rs | empty | empty | PASS |
| 6 | cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used | clean | 2 pre-existing errors in `crates/nono/src/manifest.rs:95+103` | DOCUMENTED-SKIP |

**Clippy documented-skip rationale:** The 2 clippy errors are `collapsible_match` warnings in `crates/nono/src/manifest.rs:95+103`, both pre-existing at v2.2 baseline and explicitly out-of-scope per Phase 23's `deferred-items.md`. Phase 29 did NOT touch `crates/nono/` (D-19 byte-identical preservation verified by gate 4). The Phase 23 precedent applies: pre-existing main-branch clippy issues are tracked separately and do not block phase closure.

## Commits Landed

| SHA | Message |
|---|---|
| `a3734bb3` | docs(29-01): close WR-01 reject-stage in PROJECT.md (Option c — locked design property) |
| `9fcdf123` | docs(29-01): reframe WR-01 reject-stage asymmetry as permanent design property |
| (this) | docs(29-01): SUMMARY documenting Phase 29 closure |

## Edits applied

### PROJECT.md (5 line flips, commit `a3734bb3`)

1. Active section REQ-WRU-01..02 row: `(unplanned)` → `✓ closed via Phase 29 Plan 29-01 (locked design property — Option c)` with structural rationale.
2. Active-section duplicate row: same flip pattern.
3. v2.2-deferred-items paragraph: WR-01 + Authenticode + AAH closure status added; deferral list refreshed for v2.4.
4. Context paragraph at line ~153: "deferred to v2.2" stale text removed; replaced with v2.3 Phase 29 design-property closure framing.
5. Key Decisions table row (WR-01 row): `⚠️ Revisit v2.2 — stage unification requires product decision, not bug fix` → `✓ Good — locked as permanent design property at v2.3 Phase 29 (Option c). Mask-gate is O(1) profile lookup; broker-failure flip is O(syscall) post-approval. Asymmetry is structural, not unifiable without security or UX regression.`

### Source-code docstrings (8 edits, commit `9fcdf123`)

- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs`:
  - **WR-01 module docstring** at lines 2176-2183: replaced "explicitly **deferred to v2.2 as a product decision**" with the Phase 29 design-property framing (12-line replacement preserving the regression-guard sentence at the end).
  - **5 `wr01_*` test docstrings** (lines 4320, 4418, 4516, 4619, 4722): each appended a single trailer line `/// Locked at Phase 29 as permanent design property (Option c) — see PROJECT.md § Key Decisions.` immediately above `#[test]`. Risk-1 mitigation: docstrings were descriptive (no "deferred" wording), so APPEND-not-REPLACE branch was taken.
- `crates/nono-cli/src/audit_integrity.rs`:
  - **`RejectStage` enum docstring** at lines 30-46: appended an 8-line paragraph explaining the structural rationale and locking the taxonomy for future HandleKinds.
  - **`AuditEventPayload::CapabilityDecision::reject_stage` field doc** at lines 69-79: appended a single back-reference line `/// Stage asymmetry is locked as permanent design property at Phase 29 — see RejectStage docstring.`

### Grep gate results (post-Task-2)

- `grep -c 'Phase 29\|design property' supervisor.rs`: **6** (target ≥ 5; 1 module + 5 tests)
- `grep -B 5 'fn wr01_' supervisor.rs | grep -c 'Phase 29'`: **5** (one per test)
- `grep -c 'Phase 29' audit_integrity.rs`: **3** (enum + field + serde rename)
- `grep -q 'deferred to v2.2 as a product decision' supervisor.rs`: **absent** (stale text removed)

## Deviations from plan

**None.** All 5 PROJECT.md edits applied exactly as specified; all 8 source-code docstring edits applied via the planned APPEND-or-REPLACE branch (all wr01_* docstrings hit the APPEND branch because none contained "deferred" wording, exactly as Risk 1 anticipated). No behavior change. No wire-shape change. No test-assertion change. No `crates/nono/` modifications. Phase 23 audit-show counter rendering preserved byte-identical.

## What this DOESN'T do

- **No behavior change.** Existing implementation already matches the locked verdict. The `RejectStage` enum + 5 `wr01_*` tests + `nono audit show` counter rendering all preserved verbatim.
- **No `crates/nono/` modifications.** D-19 byte-identical preservation held throughout.
- **No new tests.** REQ-WRU-02 acceptance #1 ("All 5 `wr01_*` tests pass with assertions matching the chosen matrix") satisfied because the chosen matrix IS the existing matrix.
- **No `RejectStage` wire shape change.** Phase 23's contract preserved verbatim. NDJSON consumers see the same kebab-case `reject_stage` field with the same `before-prompt | after-prompt | (omitted)` value space.

## What this enables

For future v2.4+ AIPC work:

- New HandleKinds inherit the locked taxonomy: BeforePrompt if checkability is upfront, AfterPrompt if only OS-observable. Adding HandleKind 6 (e.g., Timer, Semaphore) requires deciding which taxonomy bucket it falls into; no additional product decision needed.
- The `wr01_*` regression-guard pattern stays in place — any future refactor that accidentally moves a mask check pre/post-broker breaks CI.
- AIPC G-04 wire-protocol compile-time tightening (deferred to v2.4 backlog) operates within the locked stage-classification contract; G-04 doesn't reopen WR-01.

## Future re-litigation triggers

The decision is permanent under current architectural assumptions. Re-opening would require:

1. **AIPC subsystem grows new HandleKinds with mixed checkability** — e.g., a kind that is sometimes pre-checkable, sometimes only OS-observable. Currently no such kind is on the v2.4+ roadmap.
2. **A future kernel adds a primitive that moves Pipe/Socket checks earlier** — e.g., a hypothetical Linux/Windows API for "ask the kernel to validate this without performing the op." No such API exists today.
3. **The approval-then-action contract Phase 18 shipped is itself revisited** — would require milestone-level scope-lock.

Until any of those holds, Option (c) is the permanent verdict.

## Cross-references

- Phase 18.1 Plan 18.1-04 — original WR-01 verdict-matrix lock (CONTEXT D-14).
- Phase 23 Plan 23-01 — `RejectStage` discriminator wire-protocol locking.
- v2.2 Plan 22-05a — (no direct Phase 29 dependency; mentioned in audit-integrity context only).
- `.planning/PROJECT.md § Key Decisions` — WR-01 row updated by this plan.
- `.planning/REQUIREMENTS.md § WRU` — REQ-WRU-01..02 acceptance criteria; both closed by this plan.
