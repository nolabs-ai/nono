# Requirements: nono — v2.6 UPST6 + v2.5 Drain

**Defined:** 2026-05-20
**Core Value:** Windows security must be as structurally impossible and feature-complete as Unix platforms; every nono command that works on Linux/macOS should work on Windows with equivalent security guarantees, or be explicitly documented as intentionally unsupported with a clear rationale.

**Trigger:** v2.5 close on 2026-05-20 surfaced 32 acknowledged deferrals across 4 categories; 7 of those are carry-forward to v2.6 per `.planning/milestones/v2.5-MILESTONE-AUDIT.md`. 3 long-tail v2.4+ deferrals folded in to keep them from rotting further. UPST6 cadence trigger met (`v0.55.0` tag fetched 2026-05-17 during Phase 42 audit-open).

## v1 Requirements (v2.6 Scope)

### CI Follow-up (post-merge orchestrator coordination)

- [ ] **REQ-CI-FU-01**: Phase 37 `.github/workflows/phase-37-linux-resl.yml` live run on `ubuntu-24.04` completes green; Success Criterion 6 closed.
- [ ] **REQ-CI-FU-02**: Phase 43 umbrella PR opened with all 6 PR-SECTION.md contribution artifacts concatenated; orchestrator `gh pr create` executed.
- [ ] **REQ-CI-FU-03**: Baseline-aware CI lane diff vs Phase 41 close SHA `13cc0628` verified — zero `success → failure` transitions.

### Port Closure (Cluster 2 Edition 2024 source migration)

- [ ] **REQ-PORT-CLOSURE-08**: 39 `#[unsafe(no_mangle)]` rewrites in `bindings/c/src/` land per upstream Edition 2024 source migration; DIVERGENCE-LEDGER Cluster 2 split-disposition (Phase 43 Plan 43-01b DEC-3, commit `79715aa5`) resolved.

### RESL Native Re-validation

- [ ] **REQ-RESL-NIX-04**: Phase 38 REQ-AAHX-HOST-01 native re-validation executed on Linux + macOS host (one or both per host availability). Tactical confirmation pass; only needed if Phase 27's transitive closure leaves a host-native gap.

### UAT Backlog

- [ ] **REQ-UAT-BL-01**: Phase 35 + 36 human-UAT backlog (11 scenarios) executed on native Linux/macOS host; all items reach `pass` or documented `no-test-fixture` waiver.
- [ ] **REQ-UAT-BL-02**: Phase 35 + 36 verification backlog (7 items) executed on native Linux/macOS host.

### REVIEW.md Polish

- [x] **REQ-REVIEW-FU-01**: 16 REVIEW.md warnings resolved via single `chore(v2.6-followup):` plan — Phase 37 (10 warnings, incl. WR-09 OIDC issuer-pin production-verifier wiring) + Phase 43 (6 warnings, incl. WR-05 pack-update sync startup-latency CLAUDE.md hit, WR-04 platform.rs Ord antisymmetry, WR-06 case-sensitive registry name match).

### Test Hygiene

- [x] **REQ-TEST-HYG-01**: Class D Linux deny-overlap regression diagnosed and fixed.
- [x] **REQ-TEST-HYG-02**: Class E Windows `env_vars` parallel flakes (2) resolved via cargo-nextest follow-on (v2.5 Plan 41-10 deferral).
- [x] **REQ-TEST-HYG-03**: v24 broker CR-01 cross-binding lockstep with `../nono-py/` + `../nono-ts/` synced.
- [x] **REQ-TEST-HYG-04**: v24 broker CR-02 cross-binding lockstep with `../nono-py/` + `../nono-ts/` synced.

### Branch Merge

- [ ] **REQ-MERGE-01**: `windows-squash` → `main` merge landed with PR-583 maintainer response gate moved OR feature-flag-equivalent rollout documented. Re-deferred at v2.3 (2026-04-29 per quick-260428-rsu, commit `7911ef0e`) + v2.4 + v2.5 scope-locks.

### Drift Ingestion (DRIFT tooling exercise)

- [ ] **REQ-DRIFT-INGEST-01**: Upstream `v0.41`–`v0.43` ingestion executed via DRIFT-01/02 tooling (backfill cleanup, not parity-sync); inventory + per-cluster dispositions recorded. First real load of the DRIFT tooling shipped in v2.2 Phase 24; deferred at v2.3 scope-lock 2026-04-29.

### AIPC G-04 Wire-Protocol Tightening

- [ ] **REQ-AIPC-G04-01**: `Approved(ResourceGrant)` inlined at the wire type so `(Approved, grant=None)` is a compile-time error; `aipc_sdk.rs` child SDK demultiplexer + 23 pre-existing tests updated. Deferred from v2.1 Plan 18.1-02; reaffirmed at v2.3 and v2.4 scope-locks.

### UPST6 Cycle

- [ ] **REQ-UPST6-01**: Upstream `v0.54.0..v0.55.0+` audit — DIVERGENCE-LEDGER.md inventory + per-cluster dispositions + `## ADR review` per-cell L/M/H verdict table on 5 dimensions (security/windows/maintenance/divergence/contributor); outcome confirms or revises Phase 33 ADR Option A `continue` strategy.
- [ ] **REQ-UPST6-02**: Upstream `v0.54.0..v0.55.0+` sync execution — D-19 cherry-picks + D-20 manual replays per UPST6 audit dispositions; D-19 trailer convention + Windows-only-files invariant inherited from Phase 22+34+43; baseline-aware CI gate verified.

## v2 Requirements (Deferred)

Items acknowledged but not in v2.6 roadmap.

### EDR Telemetry

- **WR-02-EDR**: HUMAN-UAT item with EDR-instrumented runner. Deferred to v3.0 (re-affirmed at every milestone since v2.1).

### Sigstore Hardening

- **P32-DEFER-005**: `sigstore-verify` 0.6.5 → 0.6.6 upgrade. Stretch candidate if any v2.6 phase has space; otherwise defer to v2.7.

## Out of Scope

Explicitly excluded with reasoning. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Gap 6b (runtime trust interception via kernel minifilter) | Requires signed kernel driver; deferred to v3.0. |
| Full feature parity for experimental Unix features not yet stabilized | Out of scope for incremental parity-driven milestones; await upstream stabilization. |
| Job Object nesting; global kernel walk | Documented in `v2.0-REQUIREMENTS.md` archive. |
| Cross-phase architectural refactor of supervisor IPC | v2.6 is a drain + cadence milestone; structural redesign requires its own milestone. |

## Traceability

Populated 2026-05-20 by gsd-roadmapper during ROADMAP.md creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| REQ-REVIEW-FU-01 | Phase 44 | Complete |
| REQ-TEST-HYG-01 | Phase 44 | Complete |
| REQ-TEST-HYG-02 | Phase 44 | Complete |
| REQ-TEST-HYG-03 | Phase 44 | Complete |
| REQ-TEST-HYG-04 | Phase 44 | Complete |
| REQ-PORT-CLOSURE-08 | Phase 45 | Pending |
| REQ-AIPC-G04-01 | Phase 45 | Pending |
| REQ-RESL-NIX-04 | Phase 45 | Pending |
| REQ-MERGE-01 | Phase 46 | Pending |
| REQ-CI-FU-01 | Phase 46 | Pending |
| REQ-CI-FU-02 | Phase 46 | Pending |
| REQ-CI-FU-03 | Phase 46 | Pending |
| REQ-UAT-BL-01 | Phase 46 | Pending |
| REQ-UAT-BL-02 | Phase 46 | Pending |
| REQ-UPST6-01 | Phase 47 | Pending |
| REQ-DRIFT-INGEST-01 | Phase 47 | Pending |
| REQ-UPST6-02 | Phase 48 | Pending |

**Coverage:**
- v1 requirements: 17 total
- Mapped to phases: 17 (100%) ✓
- Unmapped: 0 ✓

---
*Requirements defined: 2026-05-20*
*Last updated: 2026-05-20 — traceability populated by gsd-roadmapper after `/gsd-new-milestone v2.6` roadmap creation (5 phases: 44, 45, 46, 47, 48).*
