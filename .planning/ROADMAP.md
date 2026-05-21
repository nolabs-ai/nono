---
milestone: v2.6
milestone_name: UPST6 + v2.5 Drain
status: active
created: 2026-05-20
granularity: standard
---

# Roadmap — nono

## Milestones

- ✅ **v1.0 Windows Alpha** — Phases 01-12 (shipped 2026-03-31) — see [`milestones/v1.0-*`](milestones/)
- ✅ **v2.0 Windows Gap Closure** — Phases 13-18 — see [`milestones/v2.0-ROADMAP.md`](milestones/v2.0-ROADMAP.md)
- ✅ **v2.1 Resource Limits / Extended IPC / Attach-Streaming** — see [`milestones/v2.1-ROADMAP.md`](milestones/v2.1-ROADMAP.md)
- ✅ **v2.2 Windows/macOS Parity Sweep** — see [`milestones/v2.2-ROADMAP.md`](milestones/v2.2-ROADMAP.md)
- ✅ **v2.3 Linux POC Unblock + Deferreds Closure** — see [`milestones/v2.3-ROADMAP.md`](milestones/v2.3-ROADMAP.md)
- ✅ **v2.4 Complete the Partial Ports + UPST4** — Phases 35, 36, 36.5, 39, 40 (shipped 2026-05-15) — see [`milestones/v2.4-ROADMAP.md`](milestones/v2.4-ROADMAP.md)
- ✅ **v2.5 Backlog Drain + UPST5** — Phases 37, 41, 42, 43 (shipped 2026-05-20) — see [`milestones/v2.5-ROADMAP.md`](milestones/v2.5-ROADMAP.md)
- 🚧 **v2.6 UPST6 + v2.5 Drain** — Phases 44, 45, 46, 47, 48 (active, started 2026-05-20)

## Phases

<details>
<summary>✅ v2.5 Backlog Drain + UPST5 (Phases 37, 41, 42, 43) — SHIPPED 2026-05-20</summary>

- [x] Phase 37: Linux RESL backends + PKGS auto-pull (6/6 plans) — completed 2026-05-20
- [x] Phase 41: CI cleanup + v24 broker code-review closure (11/10 plans) — completed 2026-05-16
- [x] Phase 42: UPST5 audit (1/1 plan) — completed 2026-05-17
- [x] Phase 43: UPST5 sync execution (7/7 plans) — completed 2026-05-19

Full details: [`milestones/v2.5-ROADMAP.md`](milestones/v2.5-ROADMAP.md)
Requirements: [`milestones/v2.5-REQUIREMENTS.md`](milestones/v2.5-REQUIREMENTS.md)
Audit: [`milestones/v2.5-MILESTONE-AUDIT.md`](milestones/v2.5-MILESTONE-AUDIT.md)

</details>

### 🚧 v2.6 UPST6 + v2.5 Drain (Active)

**Core Value:** Drain the 7 v2.5 carry-forward items + 3 long-tail v2.4+ deferrals, then absorb upstream `v0.54.0..v0.55.0+` via UPST6 — mirroring the v2.5 drain-then-sync pattern. Leaving the fork in a state where every cross-platform CI lane is green, the `windows-squash` → `main` merge is landed (or rationally deferred with a feature-flag-equivalent rollout), and the next milestone can be a feature milestone instead of another drain.

**Phase numbering:** continues from Phase 43 (v2.5 close). Phase 38 number reserved from v2.4 ROADMAP for REQ-AAHX-HOST-01 — folded into Phase 45 as REQ-RESL-NIX-04 native re-validation per scope-lock. v2.6 executes Phases 44, 45, 46, 47, 48.

- [x] **Phase 44: REVIEW polish + test hygiene drain** — Close 16 REVIEW.md warnings via a single chore plan and resolve the 4 test-hygiene follow-ups (Class D Linux deny-overlap + Class E Windows env_vars flakes + v24 broker CR-01/02 cross-binding lockstep). (completed 2026-05-20)
- [ ] **Phase 45: Source migration + AIPC G-04 + RESL native re-validation** — Rule-4 architectural items: 39 `#[unsafe(no_mangle)]` Edition 2024 rewrites in `bindings/c/src/` (Cluster 2 split-disposition closure); AIPC G-04 wire-protocol compile-time tightening (`Approved(ResourceGrant)` inline); Phase 38 REQ-AAHX-HOST-01 native re-validation on Linux/macOS host (folded in as RESL-NIX-04).
- [ ] **Phase 46: windows-squash merge + post-merge CI verifications + UAT backlog** — Orchestrator-coordinated: `windows-squash` → `main` merge (PR-583 gate moved OR feature-flag-equivalent rollout); Phase 37 workflow live run + Phase 43 umbrella PR + baseline-aware CI lane diff vs `13cc0628`; Phase 35 + 36 human-UAT backlog (11 scenarios + 7 verification items) on native Linux/macOS host.
- [ ] **Phase 47: UPST6 audit + v0.41–v0.43 drift ingestion** — Mirror Phase 33 / 39 / 42 audit shape for upstream `v0.54.0..v0.55.0+`; first real load of the v2.2 DRIFT-01/02 tooling on the long-deferred `v0.41–v0.43` backfill (treat as cleanup, not parity-sync).
- [ ] **Phase 48: UPST6 sync execution** — Cherry-picks + D-20 manual replays per UPST6 audit dispositions; D-19 trailer convention + Windows-only-files invariant + baseline-aware CI gate inherited from Phase 22/34/40/43.

## Phase Details

### Phase 44: REVIEW polish + test hygiene drain
**Goal**: Single-purpose drain plan to clear the 16-warning REVIEW.md backlog inherited from Phase 37 + 43 and resolve the 4 test-hygiene follow-up todos so subsequent v2.6 phases inherit a quiet baseline. No new features; pure quality + hygiene.
**Depends on**: Nothing. First phase of v2.6; runs in parallel with Phase 45 if both surfaces are disjoint.
**Requirements**: REQ-REVIEW-FU-01, REQ-TEST-HYG-01, REQ-TEST-HYG-02, REQ-TEST-HYG-03, REQ-TEST-HYG-04
**Success Criteria** (what must be TRUE):
  1. All 16 REVIEW.md warnings (Phase 37: 10 warnings incl. WR-09 OIDC issuer-pin production-verifier wiring + WR-05 sigstore-verify 0.7.0 `verify_sct` default pin-test; Phase 43: 6 warnings incl. WR-05 pack-update synchronous startup-latency CLAUDE.md hit + WR-04 `platform.rs::compare_versions` Ord antisymmetry + WR-06 case-sensitive registry value-name match) are resolved with explicit dispositions in a single `chore(v2.6-followup):` plan; no REVIEW.md item is closed by silent ignore.
  2. Class D Linux deny-overlap regression test is un-`#[ignore]`'d (or replaced with a structurally equivalent test) and emits the expected diagnostic string to stderr; the underlying Landlock runtime-deny guarantee remains intact (exit 1, no secret leak).
  3. Class E Windows `env_vars` parallel test flakes (2 — Plan 41-10 deferrals) are eliminated via cargo-nextest subprocess-per-test isolation follow-on; both flakes pass deterministically across 50 consecutive runs on a Windows host.
  4. v24 broker CR-01 (`BrokerNotFound` FFI remap) + CR-02 (broker-side FFI handle null/INVALID validation) cross-binding lockstep updates land in `../nono-py/` + `../nono-ts/` siblings; both bindings ship a regression test mirroring the fork-side coverage at `bindings/c/src/lib.rs:285-291` + `nono-shell-broker/src/main.rs:535,562`.
  5. Phase 44 close SHA is recorded as the v2.6 quiet-baseline anchor; STATE.md `## Deferred Items` is cleared of the 5 todos that motivated this phase (`41-10-linux-deny-overlap-regression.md`, `41-10-windows-integration-env-vars-flake.md`, `41-10-windows-regression-temp-vars-flake.md`, `v24-cr-01-broker-not-found-ffi-mapping.md`, `v24-cr-02-broker-null-handle-validation.md`).
**Plans**: 2 plans
- [x] 44-01-review-polish-PLAN.md — REVIEW.md polish drain (REQ-REVIEW-FU-01, 28-row canonical disposition table covering all 16 WARN + 12 INFO findings from Phase 37 + Phase 43)
- [x] 44-02-test-hygiene-drain-PLAN.md — test hygiene drain (REQ-TEST-HYG-01..04, Class D Linux deny-overlap + Class E Windows env_vars flakes + v24 broker CR-01/CR-02 cross-binding lockstep in nono-py + nono-ts siblings)
**UI hint**: no

### Phase 44.1: OIDC fail-closed remediation (REQ-REVIEW-FU-01 / T-44-01 / CR-01) (INSERTED)

**Goal**: Remediate the T-44-01 / CR-01 BLOCKER carried out of Phase 44. The WR-09 production-wiring of `NONO_TRUST_OIDC_ISSUER` in `trust_cmd.rs` keyless verify paths regressed the D-32-08 fail-closed contract by silently substituting the canonical GitHub Actions OIDC issuer (`https://token.actions.githubusercontent.com`) when both `--issuer` and the env-var are unset. Restore the pre-44 explicit fail-closed shape — verify MUST error when neither `--issuer` nor a non-empty `NONO_TRUST_OIDC_ISSUER` is provided — while preserving the env-var fallback as an opt-in trust anchor per D-44-B3. Update the regression-codifying unit test and the CLI doc that still labels `--issuer` as REQUIRED, then re-audit so T-44-01 flips to CLOSED.
**Depends on**: Phase 44 (inherits its head commit as baseline; both fix sites and the test that codifies the regression were introduced in Plan 44-01).
**Requirements**: REQ-REVIEW-FU-01
**Success Criteria** (what must be TRUE):
  1. Keyless `nono trust verify` (both multi-subject and single-file paths at `crates/nono-cli/src/trust_cmd.rs:976-984` + `1172-1180`) errors fail-closed with a clear "keyless bundle requires --issuer <OIDC_URL> or NONO_TRUST_OIDC_ISSUER" message when both `user_issuer == None` AND the env-var is unset (or whitespace-only). The hard-coded `GITHUB_ACTIONS_OIDC_ISSUER` constant is no longer used as a silent default at the verify boundary.
  2. The env-var fallback remains opt-in: when `NONO_TRUST_OIDC_ISSUER` is explicitly set to a non-empty value, verify uses it (after `url::Url::parse` URL-shape validation) without requiring `--issuer`. D-44-B3's "if set, asserts as the trusted OIDC issuer" half of the contract is preserved.
  3. The unit test `configured_oidc_issuer_falls_back_to_github_default_when_unset` in `crates/nono/src/trust/signing.rs:1217-1224` is replaced (or repurposed) so it no longer codifies the regression; a new regression test pins the fail-closed shape at the verify-callsite boundary (env-var unset + `--issuer` unset → error). The malformed-env branch (`configured_oidc_issuer_rejects_malformed_env_value`) and the explicit-set branch both retain coverage.
  4. The CLI doc at `crates/nono-cli/src/cli.rs:3046-3049` accurately reflects the restored contract (`--issuer` is REQUIRED unless `NONO_TRUST_OIDC_ISSUER` is explicitly set; the env-var alternative is documented).
  5. `/gsd-secure-phase` re-run on Phase 44 flips T-44-01 from OPEN to CLOSED; Phase 44 SECURITY.md verdict moves from `OPEN_THREATS` to `SECURED`. Re-running the Phase 44 code review on the changed sites no longer surfaces CR-01.
  6. Cross-target clippy passes per CLAUDE.md MUST/NEVER bullet: workspace clippy on Windows host AND `--target x86_64-unknown-linux-gnu` AND `--target x86_64-apple-darwin` (PARTIAL allowed only if cross-toolchain unavailable, per `.planning/templates/cross-target-verify-checklist.md`). No `#[allow(dead_code)]` introduced.
**Plans**: 1 plan
- [x] 44.1-01-oidc-fail-closed-remediation-PLAN.md — restore D-32-08 fail-closed contract on keyless trust verify; delete dead configured_oidc_issuer; update CLI doc
**UI hint**: no

### Phase 45: Source migration + AIPC G-04 + RESL native re-validation
**Goal**: Close three Rule-4 architectural items that have been deferred for multiple milestones: (a) the Cluster 2 split-disposition Edition 2024 source-file migration deferred from Phase 43 Plan 43-01b DEC-3, (b) the AIPC G-04 wire-protocol compile-time tightening deferred from v2.1 Plan 18.1-02 and reaffirmed at v2.3/v2.4/v2.5 scope-locks, and (c) the Phase 38 REQ-AAHX-HOST-01 native re-validation on Linux/macOS host that has been host-blocked since v2.4 close. All three are independent surface-touch operations; bundling avoids three single-purpose phases.
**Depends on**: Nothing in v2.6 directly. Can run in parallel with Phase 44 (surface areas disjoint: Phase 44 = REVIEW.md polish + tests; Phase 45 = `bindings/c/src/` Edition 2024 + `aipc_sdk.rs` wire-protocol + Linux/macOS host re-validation).
**Requirements**: REQ-PORT-CLOSURE-08, REQ-AIPC-G04-01, REQ-RESL-NIX-04
**Success Criteria** (what must be TRUE):
  1. All 39 `#[unsafe(no_mangle)]` rewrites in `bindings/c/src/` are applied per the upstream Edition 2024 source migration; `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` passes on Windows host AND `--target x86_64-unknown-linux-gnu` AND `--target x86_64-apple-darwin` from the dev host (or the related verification REQ is marked PARTIAL per `.planning/templates/cross-target-verify-checklist.md` if the cross-toolchain is unavailable); DIVERGENCE-LEDGER Cluster 2 disposition flipped from `split` to `closed` with a back-reference to commit `79715aa5`.
  2. `AuditEventPayload::CapabilityDecision` `Approved` variant is inlined to `Approved(ResourceGrant)` at the wire type so `(Approved, grant=None)` produces a compile-time error; `aipc_sdk.rs` child SDK demultiplexer is updated to construct the inlined variant; all 23 pre-existing tests that depended on the old `(Approved, grant=None)` shape are updated to construct the inlined variant; AUD-05 token-redaction regression test (`recorded_ledger_redacts_session_token`) still passes.
  3. Phase 38 REQ-AAHX-HOST-01 native re-validation runs on a Linux host (one or both per host availability) and reports either: (a) `audit-attestation` regression coverage matches the Phase 27.2 transitive closure, OR (b) a host-native gap is surfaced with a documented follow-up disposition. Tactical confirmation pass only — does not block phase close if no gap is found.
  4. No Windows-only-files invariant violations (D-34-E1 / D-40-E1) introduced; phase commits do not touch `*_windows.rs` / `exec_strategy_windows/` / `crates/nono-shell-broker/` beyond what is strictly required by Edition 2024 source-syntax migration (codified addendum exceptions allowed only under the Phase 40 4-condition rule).
  5. Workspace builds and tests green on Windows host (`cargo test --workspace`) post-phase close; cross-target Linux/macOS clippy verified per CLAUDE.md MUST/NEVER enforcement bullet.
**Plans**: TBD
**UI hint**: no

### Phase 46: windows-squash merge + post-merge CI verifications + UAT backlog
**Goal**: Land the `windows-squash` → `main` merge that has been re-deferred at v2.3 (2026-04-29 per quick-260428-rsu, commit `7911ef0e`), v2.4, and v2.5 scope-locks; close the 3 post-merge orchestrator CI verifications inherited from v2.5 close (Phase 37 workflow live run, Phase 43 umbrella PR, baseline-aware CI lane diff vs `13cc0628`); and execute the Phase 35 + 36 human-UAT backlog (11 UAT scenarios + 7 verification items) on a native Linux/macOS host. Orchestrator-coordinated because the merge gate, CI lanes, and UAT scenarios all require non-fork-Windows-host actions.
**Depends on**: Phase 44 (quiet-baseline anchor SHA is a precondition for clean baseline-aware CI lane diff) and Phase 45 (source migration must land before the merge so `bindings/c/src/` is at upstream's Edition 2024 syntax). Sequential after both.
**Requirements**: REQ-MERGE-01, REQ-CI-FU-01, REQ-CI-FU-02, REQ-CI-FU-03, REQ-UAT-BL-01, REQ-UAT-BL-02
**Success Criteria** (what must be TRUE):
  1. `windows-squash` is merged into `main` (either as a fast-forward if PR-583 maintainer response has moved, or via a feature-flag-equivalent rollout with the gate-state explicitly documented in the phase SUMMARY); `git log main..windows-squash` is empty after merge; the merge SHA is recorded in STATE.md `## Current Position` and in the v2.6 phase SUMMARY.
  2. Phase 37 `.github/workflows/phase-37-linux-resl.yml` executes a live run on `ubuntu-24.04` post-merge and completes green; Phase 37 VERIFICATION.md `status: human_needed` flag for Success Criterion 6 is flipped to `pass`.
  3. Phase 43 umbrella PR is opened against upstream (`gh pr create`) with all 6 PR-SECTION.md contribution artifacts concatenated into a single PR body per the fork's one-PR-per-branch-pair pattern (memory `project_cross_fork_pr_pattern`); PR URL recorded in the v2.6 phase SUMMARY.
  4. Baseline-aware CI lane diff vs Phase 41 close SHA `13cc0628` shows zero `success → failure` transitions across all 8 GH Actions lanes (Linux Clippy, macOS Clippy, Windows Build, Integration, Regression, Security, Packaging, Smoke); load-bearing skips categorized correctly in SUMMARY frontmatter per Phase 40 anti-pattern #3 (`skipped_gates_load_bearing` vs `_environmental`).
  5. All 11 Phase 35 + 36 human-UAT scenarios (REQ-UAT-BL-01) executed on native Linux/macOS host reach `pass` or carry a documented `no-test-fixture` waiver; all 7 verification items (REQ-UAT-BL-02) executed on native Linux/macOS host land with a verdict; Phase 35 + 36 HUMAN-UAT.md and VERIFICATION.md transition out of `human_needed` state.
**Plans**: TBD
**UI hint**: no

### Phase 47: UPST6 audit + v0.41–v0.43 drift ingestion
**Goal**: Produce DIVERGENCE-LEDGER.md for upstream `v0.54.0..v0.55.0+` with per-cluster dispositions and `windows-touch` column; concurrently, exercise the v2.2 Phase 24 DRIFT-01/02 tooling against the long-deferred `v0.41..v0.43` backfill range (deferred at v2.3 scope-lock 2026-04-29; backwards-looking absorb older than current upstream HEAD). The v0.41–v0.43 inventory is backfill-cleanup not parity-sync; the v0.54.0+ inventory follows the Phase 42 audit shape end-to-end and gates Phase 48's cherry-pick selection. Mirror Phase 33 / 39 / 42 audit shape; ADR review section confirms or amends Phase 33 ADR Option A `continue` strategy.
**Depends on**: Phase 46 (UPST6 audit gates on the post-merge baseline; the v0.41–v0.43 drift ingestion has no upstream-baseline dependency and could in principle run earlier, but bundling avoids fragmenting the audit phase). Sequential after Phase 46.
**Requirements**: REQ-UPST6-01, REQ-DRIFT-INGEST-01
**Success Criteria** (what must be TRUE):
  1. `DIVERGENCE-LEDGER.md` for upstream `v0.54.0..<anchor>` enumerates every upstream commit in the range that touches a fork-shared file (`crates/nono/`, `crates/nono-cli/` excluding `_windows.rs`/`exec_strategy_windows/`, `crates/nono-proxy/`); anchor SHA is locked at audit-open time per D-39-D1; every cluster has a disposition (will-sync / fork-preserve / won't-sync / split), a `windows-touch` column entry, and a rationale.
  2. `## ADR review` section is present (grep-confirmable) with per-cell L/M/H verdict table on 5 dimensions (security/windows/maintenance/divergence/contributor) and outcome (a) confirm or (b) amend the Phase 33 Option A `continue` strategy; per-cell L/M/H verdicts follow the Phase 42 worked-example shape.
  3. `## Empirical cross-check` section spot-checks at least 4 fork-shared files for any upstream path the drift tool missed, closing the `feedback_cluster_isolation_invalid` empirical lesson (DIVERGENCE-LEDGER cluster isolation can be empirically false; diff-inspect re-export surfaces, not just `--name-only`).
  4. Upstream `v0.41–v0.43` drift inventory produced via the same DRIFT-01/02 tooling; per-cluster dispositions recorded with a "backfill-cleanup, not parity-sync" framing in SUMMARY; the inventory either resolves the deferral by confirming no fork-side action needed (most likely outcome for a 1-year-stale backfill range) or flags any cherry-picks worth absorbing in Phase 48 alongside UPST6.
  5. Phase 47 ships zero `crates/` / `bindings/` / `scripts/` source-tree edits (audit-only output; D-39-E5 Windows-only-files invariant trivially honored).
**Plans**: TBD
**UI hint**: no

### Phase 48: UPST6 sync execution
**Goal**: Cherry-pick + D-20 manual-replay per UPST6 audit dispositions, with the baseline-aware CI gate verified against the Phase 46 post-merge baseline. Mirror of Phase 34 / 40 / 43 execution shape; PR umbrella convention inherited (one upstream PR holds all Phase 48 contribution sections per the fork's `project_cross_fork_pr_pattern` memory). Absorbs any v0.41–v0.43 backfill cherry-picks surfaced in Phase 47 alongside the v0.54.0+ UPST6 work.
**Depends on**: Phase 47 (audit dispositions). Sequential after Phase 47. Implicitly depends on Phase 46 (clean post-merge baseline anchor for the baseline-aware CI gate).
**Requirements**: REQ-UPST6-02
**Success Criteria** (what must be TRUE):
  1. Every Phase 47 audit `will-sync` cluster has a corresponding plan in Phase 48 with cherry-picks carrying verbatim 6-line D-19 `Upstream-commit:` trailers (lowercase per Phase 40 convention); every `fork-preserve` cluster has a documented "preserve fork because X" rationale at SUMMARY level; every `split` cluster has explicit fork-authored partial-advancement + deferred-source-migration dispositions per the Cluster 2 precedent from Phase 43.
  2. Any windows-touching cluster (where `windows-touch: yes` in the Phase 47 audit) is handled with explicit fork-side review — if `will-sync`, Windows CI is green post-merge; D-34-E1 / D-40-E1 / D-43-E1 Windows-only-files invariant respected with any addendum exceptions codified inline per the Phase 40 4-condition rule.
  3. D-20 manual-replays carry `Upstream-replayed-from:` trailers per Phase 43 convention; replays preserve fork-side defense-in-depth (e.g., `validate_path_within` precedent from v2.3 Phase 26-01, `snapshot.rs::validate_restore_target` per-file TOCTOU gate from Phase 43).
  4. Baseline-aware CI gate produces zero `success → failure` transitions vs the Phase 46 post-merge baseline SHA on every Wave 1+ head commit; load-bearing skips (cross-target clippy gates 3+4 absent `aws-lc-sys`/`ring` cross-compilers on Windows host) categorized correctly in SUMMARY frontmatter per Phase 40 anti-pattern #3.
  5. A single PR umbrella to upstream holds all Phase 48 plan contribution sections (PR #922 / Phase 43 fork pattern); 2200+ tests pass on Windows host post-merge with zero new failures.
**Plans**: TBD
**UI hint**: no

## Sequencing Rationale

```
Phase 44 (REVIEW polish + test hygiene) ──┐
                                          │ (parallel — disjoint surfaces)
Phase 45 (source migration + AIPC + RESL) ┴──► Phase 46 (merge + CI verifs + UAT) ──► Phase 47 (UPST6 audit + drift backfill) ──► Phase 48 (UPST6 sync)
```

- **Phase 44 + 45 in parallel** — surfaces are disjoint (44 = REVIEW.md + tests; 45 = `bindings/c/src/` Edition 2024 + `aipc_sdk.rs` + Linux/macOS host re-validation). User can route either first depending on host availability for REQ-RESL-NIX-04. Both close before Phase 46 because the post-merge CI gate diff (REQ-CI-FU-03) requires Phase 44's quiet-baseline anchor SHA and Phase 45's Edition 2024 source-syntax migration must land before the merge so `main` inherits the upstream-canonical syntax.
- **Phase 46 sequential after 44 + 45** — the merge gate is a load-bearing event that needs both phases' outputs as preconditions. UAT backlog (REQ-UAT-BL-01/02) folded into Phase 46 because it requires the same native Linux/macOS host coordination as the post-merge CI verifications; co-locating reduces host-context-switch overhead.
- **Phase 47 sequential after Phase 46** — UPST6 audit benefits from the post-merge baseline so the ADR-review section can reference green CI as evidence for `continue` strategy. v0.41–v0.43 drift ingestion folded in here (rather than as standalone phase) because the DRIFT-01/02 tooling is the same instrument; running both inventories in one phase amortizes the audit-shape overhead.
- **Phase 48 sequential after Phase 47** — D-19 cherry-pick discipline needs Phase 47's per-cluster dispositions to choose cherry-pick vs D-20 manual-replay. Phase 48 is the milestone-closing phase; v2.6 ships after its close.
- **Phase 38 number reservation closed** — REQ-AAHX-HOST-01 native re-validation folded into Phase 45 as REQ-RESL-NIX-04 (rescoped at milestone-start to clarify it's a confirmation pass, not a fresh investigation). No Phase 38 will be opened in v2.6.

## Requirement Coverage

17 in-milestone requirements; every one mapped to exactly one phase; zero unmapped; zero double-mapped.

| REQ-ID | Phase | Category |
|---|---|---|
| REQ-REVIEW-FU-01 | Phase 44 | REVIEW |
| REQ-TEST-HYG-01 | Phase 44 | TEST-HYG |
| REQ-TEST-HYG-02 | Phase 44 | TEST-HYG |
| REQ-TEST-HYG-03 | Phase 44 | TEST-HYG |
| REQ-TEST-HYG-04 | Phase 44 | TEST-HYG |
| REQ-PORT-CLOSURE-08 | Phase 45 | PORT-CLOSURE |
| REQ-AIPC-G04-01 | Phase 45 | AIPC |
| REQ-RESL-NIX-04 | Phase 45 | RESL-NIX |
| REQ-MERGE-01 | Phase 46 | MERGE |
| REQ-CI-FU-01 | Phase 46 | CI-FU |
| REQ-CI-FU-02 | Phase 46 | CI-FU |
| REQ-CI-FU-03 | Phase 46 | CI-FU |
| REQ-UAT-BL-01 | Phase 46 | UAT-BL |
| REQ-UAT-BL-02 | Phase 46 | UAT-BL |
| REQ-UPST6-01 | Phase 47 | UPST6 |
| REQ-DRIFT-INGEST-01 | Phase 47 | DRIFT |
| REQ-UPST6-02 | Phase 48 | UPST6 |

**Coverage: 17/17 ✓**

## Cross-Phase Invariants

These invariants are inherited from prior milestones and remain in force across v2.6:

- **D-19 (cross-platform byte-identity preserved when cherry-picking upstream commits)** — Phase 48 cherry-picks must carry the verbatim 6-line `Upstream-commit:` trailer (lowercase `Upstream-author:` per Phase 40 standardization). D-20 manual-replays carry `Upstream-replayed-from:` trailers per Phase 43 convention.
- **D-34-E1 / D-40-E1 / D-43-E1 (Windows-only-files invariant)** — upstream-sync commits in Phase 48 do not touch fork-Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/`). Codified addendum exceptions allowed only under the Phase 40 4-condition rule (required cross-platform struct field; cross-platform default factory only; ≤5 lines; documented in SUMMARY + STATE). Phase 45 Edition 2024 source migration is bounded to `bindings/c/src/` and does not extend this carve-out.
- **Phase 33 ADR Option A `continue` upstream-parity strategy** — Accepted, re-confirmed at v2.4 + v2.5 close. Phase 47 may amend but defaults to `continue`.
- **Baseline-aware CI gate** — Phase 48 gates vs the Phase 46 post-merge baseline SHA, not the Phase 41 close SHA. Categorize gate skips per the Phase 40 anti-pattern #3 distinction (`skipped_gates_load_bearing` vs `_environmental`).
- **CLAUDE.md "lazy use of dead code" rule** — Phase 44 + 45 dead-code orphans either deleted or wired; no `#[allow(dead_code)]` added without explicit justification.
- **Cross-target clippy required for cfg-gated Unix code** — Phases 44 + 45 + 48 all run `cargo clippy --workspace --target x86_64-unknown-linux-gnu` AND `--target x86_64-apple-darwin` from the dev host per CLAUDE.md § Coding Standards MUST/NEVER enforcement bullet + `.planning/templates/cross-target-verify-checklist.md` (promoted from advisory at v2.5 Phase 41 close after third miss). Windows-host workspace clippy alone is insufficient.
- **DIVERGENCE-LEDGER cluster isolation can be empirically false** — Phase 47 must diff-inspect re-export surfaces, not just `--name-only`, per the v2.5 close `feedback_cluster_isolation_invalid` empirical lesson hardened from Phase 43 Plan 43-01 (upstream `8b888a1c` cross-cluster re-export dependency). `split` is a valid fourth cluster disposition.

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 44. REVIEW polish + test hygiene | 2/2 | Complete    | 2026-05-20 |
| 45. Source migration + AIPC G-04 + RESL native re-validation | 0/TBD | Not started | — |
| 46. windows-squash merge + post-merge CI + UAT backlog | 0/TBD | Not started | — |
| 47. UPST6 audit + v0.41–v0.43 drift ingestion | 0/TBD | Not started | — |
| 48. UPST6 sync execution | 0/TBD | Not started | — |

(Prior milestones rolled up under `milestones/v*-ROADMAP.md`.)

## References

- `.planning/PROJECT.md` — milestone context, key decisions, deferred items.
- `.planning/REQUIREMENTS.md` — v2.6 requirements with acceptance criteria + traceability table.
- `.planning/MILESTONES.md` — v2.5 close context (4 phases shipped; 32 deferred items; 7 carry-forward to v2.6).
- `.planning/milestones/v2.5-MILESTONE-AUDIT.md` — v2.5 close audit (cross-phase integration clean; tech_debt status; carry-forward list).
- `.planning/milestones/v2.5-ROADMAP.md` — v2.5 phase shape (4 phases: 37, 41, 42, 43) used as v2.6 shape reference.
- `.planning/templates/upstream-sync-quick.md` — UPST6 sync template (baseline SHA updates at Phase 46 post-merge per REQ-CI-FU-03).
- `.planning/templates/cross-target-verify-checklist.md` — cross-target clippy verification protocol (promoted from advisory at v2.5 Phase 41 close).
- `docs/architecture/upstream-parity-strategy.md` — Phase 33 ADR (Option A `continue` Accepted, re-confirmed v2.4 + v2.5 close).
