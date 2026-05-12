# Phase 35: UPST3-closure quick wins - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-12
**Phase:** 35-upst3-closure-quick-wins
**Areas discussed:** Plan slicing, REQ-01 test approach, REQ-07 UNC path test fix shape, PR shape at close

---

## Plan slicing

### Q1: How should Phase 35's three REQs be sliced into plans?

| Option | Description | Selected |
|--------|-------------|----------|
| 3 plans, one per REQ | 35-01-WIN-ENV-FILTER (REQ-01), 35-02-LINUX-LANDLOCK-PROFILES (REQ-06), 35-03-WIN-TEST-HYGIENE (REQ-07). Per-REQ traceability, mirrors Phase 34 D-34-A1. | ✓ |
| 2 plans by platform | 35-01-WIN-CLOSURE bundles REQ-01 + REQ-07; 35-02-LINUX-LANDLOCK-PROFILES holds REQ-06 alone. | |
| 1 combined plan | 35-01-UPST3-CLOSURE-QUICK-WINS does all three. | |

**Selected:** 3 plans, one per REQ → **D-35-A2** in CONTEXT.md.

### Q2: Should the 3 plans wave-parallelize or run sequentially?

| Option | Description | Selected |
|--------|-------------|----------|
| Wave-parallel (all 3 in one wave) | Surfaces are fully disjoint; no file overlap; Phase 22 D-09/D-10/D-12 precedent. | ✓ |
| Sequential by platform | Land Windows-touching plans first (35-01, 35-03), then Linux 35-02. | |
| REQ-06 first, then REQ-01 + REQ-07 parallel | Front-load the smallest unit. | |

**Selected:** Wave-parallel → **D-35-A3** in CONTEXT.md.

### Q3: How should the D-34-E1 inversion be expressed?

| Option | Description | Selected |
|--------|-------------|----------|
| New decision D-35-A1 'D-34-E1 explicitly inverted for Phase 35' | Phase-level decision, scoped to REQ-01 surface only. | ✓ |
| Inline carve-out inside Plan 35-01 PLAN.md | Smaller blast radius but easier for future audits to miss. | |
| Re-scope D-34-E1 to 'upstream-sync phases only' | Tightens carry-forward semantics project-wide. | |

**Selected:** New decision D-35-A1 → **D-35-A1** in CONTEXT.md.

### Q4: How should D-19 trailer convention apply in Phase 35?

| Option | Description | Selected |
|--------|-------------|----------|
| Trailers only where there's a direct upstream commit | REQ-06 full trailer; REQ-01 D-20 body reference; REQ-07 no trailer. | ✓ |
| D-19 trailers on every Phase 35 commit | Includes 'Upstream-commit: N/A (fork-local)'. | |
| No D-19 trailers — Phase 35 isn't an upstream-sync phase | Upstream references in CONTEXT/SUMMARY only. | |

**Selected:** Trailers only where direct upstream commit → **D-35-A4** in CONTEXT.md.

---

## REQ-01 test approach

### Q1: Where should the Windows env-filter regression tests live?

| Option | Description | Selected |
|--------|-------------|----------|
| Unit tests in exec_strategy_windows/ only | Function-call-boundary tests; no process spawn; avoids dirs::home_dir() Windows blocker. | ✓ |
| Both unit + run_nono integration | End-to-end via run_nono powershell -c '$env:KEY'. | |
| Unit + deferred integration to Phase 38 | Unit now; integration in Phase 38. | |

**Selected:** Unit tests in exec_strategy_windows/ only → **D-35-B1** in CONTEXT.md.

### Q2: How should Plan 35-01 reach the env-filter consumption point on Windows?

| Option | Description | Selected |
|--------|-------------|----------|
| Mirror Unix exec_strategy.rs env-filter call site | Symmetric call inside exec_strategy_windows/mod.rs; remove dead_code allow gates. | ✓ |
| Add a shared filter helper in exec_strategy/mod.rs | Extract env_filter::apply helper for both platforms. | |
| Inline the filter logic in the Windows env-block builder | Quickest path; risks Unix/Windows drift. | |

**Selected:** Mirror Unix exec_strategy.rs call site → **D-35-B2** in CONTEXT.md.

### Q3: How should the 780965d7 empty-allow fail-closed invariant be validated on Windows?

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated Windows-gated unit test + cross-platform invariant check | #[cfg(target_os = "windows")] test plus filter-helper cross-platform test. | ✓ |
| Unit test only | Just the Windows-gated unit test. | |
| Property test (proptest) for filter semantics | Generate (allow, deny, env) triples; assert invariants. | |

**Selected:** Windows-gated + cross-platform invariant check → **D-35-B3** in CONTEXT.md.

### Q4: Should Windows env-filter wiring update SessionMetadata audit records?

| Option | Description | Selected |
|--------|-------------|----------|
| No — stay surgical, audit out of scope | Plan 34-08a Unix doesn't emit audit events either; D-34-B2 inheritance. | ✓ |
| Yes — capability_decision audit event | Mirrors Phase 23 AUD-05 RejectStage::BeforePrompt; cross-platform asymmetry risk. | |
| Yes — supervisor stderr trace summary | Lightweight diagnostic; no SessionMetadata change. | |

**Selected:** No — stay surgical → **D-35-B4** in CONTEXT.md.

---

## REQ-07 UNC path test fix shape

### Q1: How should the Windows UNC long-path flake in test_query_path_denied be fixed?

| Option | Description | Selected |
|--------|-------------|----------|
| Strip UNC prefix in suggested_flag emission (production-code fix) | Mirror commit 400f8c90; test passes deterministically on all platforms; closes UX bug. | ✓ |
| Add Windows-specific test variant asserting UNC-prefixed form | Keeps Windows coverage; doesn't fix UX issue. | |
| Gate the test #[cfg(not(target_os = "windows"))] | Phase 22-style pattern; loses Windows coverage; UX bug remains. | |

**Selected:** Strip UNC prefix in production code → **D-35-C1** in CONTEXT.md.

### Q2: What JSON shape for Option<SignalMode> to fix the Debug leak?

| Option | Description | Selected |
|--------|-------------|----------|
| Some → snake_case string; None → omitted from JSON | Match upstream f3e7f885 shape per Plan 34-04b SUMMARY expectation. | ✓ |
| Some → snake_case string; None → explicit null | Always-present field; diverges from upstream's omit-when-None. | |
| Use serde_json::to_value directly | Let serde's default handling drive shape; risk if SignalMode lacks #[serde(rename_all)]. | |

**Selected:** Some → snake_case string; None → omitted → **D-35-C2** in CONTEXT.md.

### Q3: Should Plan 35-03 audit other Option<…> security fields for the same regression class?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — full audit of profile_cmd.rs format!("{:?}") sites | Closes entire regression class; ~30 min effort. | ✓ |
| Just the two flagged tests | Surgical fix; leaves latent regression class open. | |
| Add a structural regression test (AST-walker) | Strongest invariant lock; too heavy for quick-win plan. | |

**Selected:** Full audit of format!("{:?}") sites → **D-35-C3** in CONTEXT.md.

### Q4: How should P34-DEFER-09-3 (carry-forward duplicate of 01-1) be handled?

| Option | Description | Selected |
|--------|-------------|----------|
| Already covered — P34-DEFER-09-3 is the same test as 01-1 | Mark closed transitively in Plan 35-03 SUMMARY; no extra work. | ✓ |
| Treat 09-3 as separate — add explicit task | Plan 35-03 explicitly flips 09-3 alongside 01-1. | |
| Out of scope — Phase 36 housekeeping | Defer to Phase 36 ledger sweep. | |

**Selected:** Already covered (transitive closure) → **D-35-C4** in CONTEXT.md.

---

## PR shape at close

### Q1: How should Phase 35's plans land as PRs?

| Option | Description | Selected |
|--------|-------------|----------|
| 3 PRs, one per plan | Mirrors Phase 34 D-34-D1 direct-on-main; reviewer attention per REQ. | ✓ |
| 1 combined PR for whole phase | Small phase; less PR ceremony; risks reviewer fatigue across surfaces. | |
| 2 PRs by platform | Windows PR (35-01 + 35-03) + Linux PR (35-02). | |

**Selected:** 3 PRs, one per plan → **D-35-D1** in CONTEXT.md.

### Q2: Should Phase 35 inherit Phase 34's D-34-D2 close-gate verbatim or trim?

| Option | Description | Selected |
|--------|-------------|----------|
| Inherit verbatim | Same 8-step gate (Windows test + Windows clippy + Linux cross-target + macOS cross-target + fmt + Phase 15 smoke + wfp_port_integration + learn_windows_integration). | ✓ |
| Trim macOS clippy + learn_windows_integration | Phase 35 doesn't touch macOS or ETW surface. | |
| Minimal gate — just test + clippy + Linux cross-target + fmt | Quickest cycle; risks missing tangential regressions. | |

**Selected:** Inherit verbatim → **D-35-D2** in CONTEXT.md.

### Q3: How should Plan 35-02's Linux integration verification be handled?

| Option | Description | Selected |
|--------|-------------|----------|
| Cross-target clippy + landlock_integration #[ignore] on Windows, CI Linux lane runs | Dev-host clippy + CI Linux lane verification; mirrors Phase 25 deferred-to-host pattern. | ✓ |
| Block Plan 35-02 close until verified on Linux host | Conservative; means Phase 35 can't close until Linux host available. | |
| Trust the cherry-pick — close on Windows after clippy green | Pragmatic for 15-line hunk; riskier. | |

**Selected:** Cross-target clippy + CI Linux lane → **D-35-D3** in CONTEXT.md.

### Q4: Should the phase close flip Phase 34 deferred-items.md status entries?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — Plan 35-03 SUMMARY appends closure section to Phase 34 deferred-items.md | Each plan SUMMARY records its closure; Plan 35-03 (last to close) owns the consolidated append. | ✓ |
| Yes — add 35-PHASE-OUTCOMES.md | Mirror Phase 34 outcomes shape; doesn't modify Phase 34's deferred-items.md. | |
| No — leave Phase 34 deferred-items.md as historical artifact | Phase 35 VERIFICATION.md describes closures; requires cross-referencing. | |

**Selected:** Plan 35-03 SUMMARY appends closure section → **D-35-D4** in CONTEXT.md.

---

## Claude's Discretion

Captured in CONTEXT.md `<decisions>` § Claude's Discretion:

- Plan numbering suffix conventions inside the THEME-readable shape (`35-01-WIN-ENV-FILTER` etc.).
- Exact wave-parallel execution order (parallel allowed, not mandated).
- Whether `SignalMode` enum needs `#[serde(rename_all = "snake_case")]` attribute — verify and add if missing.
- Exact regression-test naming additions in Plan 35-03 beyond the two locked invariants.
- PR title conventions, draft vs ready-for-review state, reviewer assignment — inherit Phase 34 conventions.
- PROJECT.md drift fix timing — handled at Phase 35 close via `/gsd-progress`, not mid-phase.

---

## Deferred Ideas

Captured in CONTEXT.md `<deferred>`:

- REQ-PORT-CLOSURE-05 (P34-DEFER-08b-1 + 08b-2) — Phase 36.
- `run_nono` integration tests for Windows env-filter — Phase 37/38 (host-blocked).
- Audit-event emission for env-filter outcomes — new phase if needed.
- Structural regression test linting `format!("{:?}")` — too heavy for quick-win shape; reconsider on regression.
- Proptest-driven env-filter semantics — reconsider if filter logic complexity grows.
- `nono completion` MSI integration, `--allow-connect-port` ↔ WFP composition, `nono learn` ETW deprecation — Phase 34 deferred carry-forward; Phase 35 doesn't pick up.
- PROJECT.md line 19 stale-reference cleanup — `/gsd-progress` at phase close.

### Reviewed Todos (not folded)

None — no pending todos surfaced for Phase 35 scope.
