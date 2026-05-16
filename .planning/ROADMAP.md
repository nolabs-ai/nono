---
milestone: v2.5
milestone_name: Backlog Drain + UPST5
status: active
created: 2026-05-15
granularity: standard
---

# Roadmap — v2.5 Backlog Drain + UPST5

**Core Value:** Drain the host-blocked v2.4 carry-forwards via Windows-coded + CI-executed Linux backends, clear the pre-existing CI red that has been masking real regressions, absorb upstream `v0.53.0..+` (first sync where Windows is touched), and resolve the v24 Windows broker code-review backlog — leaving the fork in a state where every cross-platform CI lane is green and Phase 38 + v2.6 work can proceed on a quiet baseline.

**Phase numbering:** continues from Phase 40 (v2.4 close). Phase 37 number reserved from v2.4 ROADMAP for the host-blocked carry-forward. Phase 38 (REQ-AAHX-HOST-01) re-deferred to v2.6. Phases 39 + 40 already shipped in v2.4. v2.5 executes Phases 37, 41, 42, 43.

## Phases

- [ ] **Phase 37: Linux RESL backends + PKGS auto-pull** — cgroup v2 `memory.max` / `cpu.max` / `pids.max` + `load_registry_profile` auto-pull; coded on Windows host, verified via GitHub Actions Linux runners.
- [x] **Phase 41: CI cleanup + v24 broker code-review closure** — Linux/macOS Clippy + Windows CI jobs back to green; baseline reset; 4 v24 Windows broker code-review todos absorbed. (completed 2026-05-16)
- [ ] **Phase 42: UPST5 audit** — DIVERGENCE-LEDGER.md inventory of upstream `v0.53.0..+`; first audit where the `windows-touch` column actually fires.
- [ ] **Phase 43: UPST5 sync execution** — Cherry-picks + D-20 manual replays per UPST5 audit dispositions; D-19 trailer convention + Windows-only-files invariant inherited; baseline-aware CI gate vs post-Phase-41 green baseline.

## Phase Details

### Phase 37: Linux RESL backends + PKGS auto-pull
**Goal**: Close the 3-year Linux silent-no-op for `--memory` / `--cpu-percent` / `--max-processes` and ship cargo-install-style auto-pull for registry profiles. Linux backends coded on Windows host; verification runs on GitHub Actions Linux runners (Ubuntu 24.04, cgroup v2 default — same pattern that landed Phase 35-02 Landlock profiles-dir fix).
**Depends on**: Nothing in v2.5 directly. Runs in parallel with Phase 41. macOS `setrlimit` portion of the v2.3 Plan 25-01 design is explicitly dropped from scope (macOS deprioritized this milestone).
**Requirements**: REQ-RESL-NIX-01, REQ-RESL-NIX-02, REQ-RESL-NIX-03, REQ-PKGS-04
**Success Criteria** (what must be TRUE):
  1. On a Linux cgroup v2 host, `nono run --memory 100M -- python -c 'a = bytearray(200_000_000)'` exits non-zero (kernel kills via `cgroup.kill`), and `nono inspect <id>` shows `memory: 100M (cgroup v2 memory.max)`.
  2. On a Linux cgroup v2 host, `nono run --cpu-percent 25 -- yes >/dev/null` averages ~25% CPU under sampling, and `nono inspect <id>` shows `cpu_percent: 25 (cgroup v2 cpu.max 25000 100000)`.
  3. On a Linux cgroup v2 host, `nono run --max-processes 5 -- bash -c ':(){ :|:& };:'` is contained at ~5 processes (fork-bomb kernel-rejected with `EAGAIN`), and `nono inspect <id>` shows `max_processes: 5 (cgroup v2 pids.max)`.
  4. On a cgroup v1 host, all three flags fail closed with `NonoError::UnsupportedKernelFeature` pointing to the `cgroup_no_v1` boot flag — no silent no-op path remains on Linux.
  5. `nono run --profile claude-code-edge -- cmd` (registry profile not yet installed) auto-pulls the signed artifact, verifies the signature, installs, and runs; `--no-auto-pull` falls back to the legacy "profile not found" error; unknown names fail closed with no implicit network.
  6. GitHub Actions Linux runner executes all four backends end-to-end as part of the Phase 37 close gate.
**Plans**: TBD (v2.3 Plan 25-01 + Plan 26-02 designs carry forward as planning inputs; cgroup v2 vs macOS split materially simplifies the Plan 25-01 surface)
**UI hint**: no

### Phase 41: CI cleanup + v24 broker code-review closure
**Goal**: Reset every CI lane to green and clear the v24 Windows broker code-review backlog so Phases 42 + 43 inherit a clean baseline. This is the v2.5 prerequisite phase: subsequent baseline-aware CI gates (REQ-UPST5-02) become unambiguously real regression detectors rather than baseline-drift trackers.
**Depends on**: Nothing. User explicitly chose Phase 41 as a v2.5 priority so subsequent phases get clean CI gates. Should land before Phase 43 sync execution.
**Requirements**: REQ-CI-01, REQ-CI-02, REQ-CI-03, REQ-BROKER-CR-01, REQ-BROKER-CR-02, REQ-BROKER-CR-03, REQ-BROKER-CR-04
**Success Criteria** (what must be TRUE):
  1. `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` exits 0 from the Windows host (per memory `feedback_clippy_cross_target`), and the GitHub Actions Linux + macOS Clippy jobs are green on the Phase 41 close SHA. No `#[allow(dead_code)]` was added — every orphan was either deleted or wired per the CLAUDE.md "lazy use of dead code" rule.
  2. All 5 Windows CI jobs (Build, Integration, Regression, Security, Packaging) are green on the Phase 41 close SHA; no `[ignored]` test markers added without an issue-linked justification; the MSI validator's `-BrokerPath` mandatory-parameter mismatch is resolved.
  3. The baseline-aware CI gate baseline SHA in `.planning/templates/upstream-sync-quick.md` is updated to the Phase 41 close SHA, and the SUMMARY frontmatter convention (`skipped_gates_load_bearing` vs `_environmental`) is documented at the top of Phase 41's SUMMARY for Phase 43's inheritance.
  4. `NonoError::BrokerNotFound` maps to a semantically correct C-FFI error code (per `.planning/todos/pending/v24-cr-01-broker-not-found-ffi-mapping.md`), broker-side FFI handle arguments are validated non-null before crossing the boundary (CR-02), and the empty-handle-list path is handled explicitly in the broker dispatch (CR-03).
  5. The Job-object test skip policy for `broker_launch_assigns_child_to_job_object` is resolved with an explicit decision (a/b/c per `.planning/todos/pending/v24-cr-04-job-object-test-skip-policy.md`), and STATE.md `## Deferred Items` is cleared of the v24 CR-A class entries that were waiting on a clean baseline.
**Plans**: 9 plans (7 original + 2 gap-closure)
Plans:
**Wave 1**
- [x] 41-01-PLAN.md — API migration: CapabilityRequest::path -> HandleTarget::FilePath helper (14 sites)
- [x] 41-03-PLAN.md — Windows MSI validator: thread mandatory -BrokerPath through validate-windows-msi-contract.ps1
- [x] 41-04-PLAN.md — Windows block-net probe triage: confirm cfg(debug_assertions) hypothesis + promote flag
- [x] 41-05-PLAN.md — env_vars parallel flake fix via EnvVarGuard::set_all
- [x] 41-06-PLAN.md — Broker hygiene CR-01 + CR-02 + CR-03 (FFI remap + null-handle reject + empty-list reject)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 41-02-PLAN.md — Unix simple: dead-code dispositions + disallowed_methods + unreachable expression (3 atomic commits)
- [x] 41-07-PLAN.md — Broker CR-04 + baseline reset close gate (SKIP->FAIL + build.rs + baseline SHA + skipped-gates convention + STATE.md cleanup)

**Wave 3** *(gap closure — extends Plan 41-03 to the second validator caller)*
- [x] 41-08-PLAN.md — REQ-CI-02 gap closure: thread mandatory -BrokerPath into windows-test-harness.ps1 build suite + regression guard

**Wave 4** *(gap closure — closes 6 cross-target -Dwarnings findings from CI run 25972316892)*
- [x] 41-09-PLAN.md — REQ-CI-01 gap closure: wire profile_runtime to canonical validate_env_var_patterns + cfg-gate Windows-only SetupRunner WFP surface + interactive_shell field + test_env mirror + map_err→inspect_err keystore swap (closes Gaps 1-6 + WR-06)
**UI hint**: no

### Phase 42: UPST5 audit
**Goal**: Produce DIVERGENCE-LEDGER.md for upstream `v0.53.0..+` with per-cluster dispositions and `windows-touch` column, gating Phase 43's cherry-pick selection. First audit cycle where the `windows-touch: yes` column actually fires per D-39-C3 conservative-default fork-preserve disposition: the two known Windows-touching commits (`5d821c12` + `0748cced`) land in `v0.54.0~5^2`. Mirror of Phase 33 / 39 audit shape; ADR review section confirms or amends the Phase 33 Option A `continue` strategy (Accepted, re-confirmed at v2.4 close per D-39-C4).
**Depends on**: Phase 41 (close gate). Phase 42 is audit-only and could in principle start earlier, but landing it after the baseline reset means the audit's "next-phase will inherit a green baseline" assumption holds. Sequential after Phase 41.
**Requirements**: REQ-UPST5-01
**Success Criteria** (what must be TRUE):
  1. `DIVERGENCE-LEDGER.md` enumerates every upstream commit in `v0.53.0..<anchor>` that touches a fork-shared file (`crates/nono/`, `crates/nono-cli/` excluding `_windows.rs`/`exec_strategy_windows/`, `crates/nono-proxy/`); anchor SHA is locked at audit-open time per D-39-D1.
  2. Every cluster has a disposition (will-sync / fork-preserve / won't-sync), a `windows-touch` column entry, and a rationale; `5d821c12` + `0748cced` are explicitly handled with a decision recorded.
  3. The `## ADR review` section is present (grep-confirmable) and either confirms or amends the Phase 33 Option A `continue` strategy with explicit per-cell L/M/H verdicts.
  4. Empirical cross-check: spot-check at least 3 fork-shared files for any upstream path the drift tool missed (Phase 39 empirical-cross-check pattern).
  5. The audit ships zero `crates/` / `bindings/` / `scripts/` source-tree edits (D-39-E5 Windows-only-files invariant trivially honored for audit-only output).
**Plans**: TBD (Phase 33 / 39 plan shape carries forward)
**UI hint**: no

### Phase 43: UPST5 sync execution
**Goal**: Cherry-pick + D-20 manual-replay per UPST5 audit dispositions, with the baseline-aware CI gate verified against the post-Phase-41 green baseline. First upstream-sync phase where the `windows-touch: yes` cluster requires real fork-side review (vs Phase 34 / 40 where windows-touch was structurally absent). Mirror of Phase 34 / 40 execution shape; PR umbrella convention inherited (PR #922 pattern: one upstream PR holds all phase contribution sections).
**Depends on**: Phase 41 (clean baseline) and Phase 42 (audit dispositions). Sequential after both.
**Requirements**: REQ-UPST5-02
**Success Criteria** (what must be TRUE):
  1. Every Phase 42 audit `will-sync` cluster has a corresponding plan in Phase 43 with cherry-picks carrying verbatim 6-line D-19 `Upstream-commit:` trailers (lowercase per Phase 40 convention).
  2. Every `fork-preserve` cluster has a documented "preserve fork because X" rationale at SUMMARY level; D-20 manual-replays preserve fork-side defense-in-depth (e.g. `validate_path_within` precedent from v2.3 Phase 26-01).
  3. The Windows-touching cluster (`5d821c12` + `0748cced` per Phase 42 disposition) is handled correctly — if `will-sync`, Windows CI is green post-merge; D-34-E1 / D-40-E1 Windows-only-files invariant respected with any addendum exceptions codified inline per the Phase 40 4-condition rule.
  4. Baseline-aware CI gate produces zero `success → failure` transitions vs the Phase 41 close SHA on every Wave 1+ head commit; load-bearing skips (cross-target clippy gates 3+4) categorized correctly in SUMMARY frontmatter per Phase 40 anti-pattern #3.
  5. A single PR umbrella to upstream holds all Phase 43 plan contribution sections (PR #922 / fork pattern per memory `project_cross_fork_pr_pattern`).
**Plans**: TBD (Phase 34 / 40 plan shape carries forward; wave structure derives from audit's `wave-hint:` annotations)
**UI hint**: no

## Sequencing Rationale

```
Phase 37 (Linux RESL + auto-pull) ──┐
                                    │   (parallel; both close before Phase 43)
Phase 41 (CI cleanup + broker CR) ──┴──► Phase 42 (UPST5 audit) ──► Phase 43 (UPST5 sync)
```

- **Phase 41 first by user directive** — pre-existing red on Linux/macOS Clippy + 5 Windows job classes was masking real regressions for at least a week (per PHASE-41-TRACKER.md). Resetting the baseline is the v2.5 prerequisite for clean baseline-aware gates in Phase 43.
- **Phase 37 in parallel with Phase 41** — Phase 37 is code-on-Windows + verify-on-Linux-CI. Its CI lanes are the same lanes Phase 41 is fixing (Linux Clippy + Linux integration tests); there is mild integration risk if both phases churn the same test surface simultaneously, but the surface areas are largely disjoint (Phase 37 touches `crates/nono/src/sandbox/linux.rs` + `crates/nono-cli/src/exec_strategy.rs` runtime path; Phase 41 touches `crates/nono-cli/src/exec_strategy.rs` API-migration call sites and `audit_ledger.rs` dead-code orphans). Coordinate on the API-migration commit (`CapabilityRequest::path` → `HandleTarget::FilePath`) — Phase 37 should rebase on Phase 41's API-migration sub-plan once it lands.
- **Phase 42 sequential after Phase 41** — audit is cheap (1 plan, ~1 week) and benefits from the clean baseline so the ADR-review section can reference green CI as evidence for `continue` strategy.
- **Phase 43 sequential after Phase 42** — D-19 cherry-pick discipline needs Phase 42's per-cluster dispositions to choose cherry-pick vs D-20 manual-replay.
- **BROKER-CR folded into Phase 41** — all 4 todos are Windows-broker hygiene that share the code area Phase 41 already needs to touch for the Windows CI fixes (`crates/nono-shell-broker/` + `bindings/c/`). CR-04 (Job-object test skip policy) is literally a CI-signal-quality decision that must land before the baseline reset. Folding into Phase 43 was rejected because it would dilute the "every Phase 43 commit traces to an upstream commit" D-19 discipline; a standalone Phase 44 was rejected because each todo is too small to justify phase overhead.

## Requirement Coverage

13 in-milestone requirements; every one mapped to exactly one phase; zero unmapped; zero double-mapped.

| REQ-ID | Phase | Category |
|---|---|---|
| REQ-RESL-NIX-01 | Phase 37 | RESL-NIX |
| REQ-RESL-NIX-02 | Phase 37 | RESL-NIX |
| REQ-RESL-NIX-03 | Phase 37 | RESL-NIX |
| REQ-PKGS-04 | Phase 37 | PKGS |
| REQ-CI-01 | Phase 41 | CI-CLEAN |
| REQ-CI-02 | Phase 41 | CI-CLEAN |
| REQ-CI-03 | Phase 41 | CI-CLEAN |
| REQ-BROKER-CR-01 | Phase 41 | BROKER-CR |
| REQ-BROKER-CR-02 | Phase 41 | BROKER-CR |
| REQ-BROKER-CR-03 | Phase 41 | BROKER-CR |
| REQ-BROKER-CR-04 | Phase 41 | BROKER-CR |
| REQ-UPST5-01 | Phase 42 | UPST5 |
| REQ-UPST5-02 | Phase 43 | UPST5 |

**Coverage: 13/13 ✓**

## Cross-Phase Invariants

These invariants are inherited from prior milestones and remain in force across v2.5:

- **D-19 (cross-platform byte-identity preserved when cherry-picking upstream commits)** — Phase 43 cherry-picks must carry the verbatim 6-line `Upstream-commit:` trailer (lowercase `Upstream-author:` per Phase 40 standardization).
- **D-34-E1 / D-40-E1 (Windows-only-files invariant)** — upstream-sync commits in Phase 43 do not touch fork-Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/`). Codified addendum exceptions allowed only under the Phase 40 4-condition rule (required cross-platform struct field; cross-platform default factory only; ≤5 lines; documented in SUMMARY + STATE).
- **Phase 33 ADR Option A `continue` upstream-parity strategy** — Accepted, re-confirmed at v2.4 close per D-39-C4. Phase 42 may amend but defaults to `continue`.
- **Baseline-aware CI gate** — Phase 43 gates vs the Phase 41 close SHA, not a pre-Phase-41 baseline. Categorize gate skips per the Phase 40 anti-pattern #3 distinction (`skipped_gates_load_bearing` vs `_environmental`).
- **CLAUDE.md "lazy use of dead code" rule** — Phase 41 dead-code orphans either deleted or wired; no `#[allow(dead_code)]` added without explicit justification.
- **Cross-target clippy required for cfg-gated Unix code** — Phase 37 + Phase 41 + Phase 43 all run `cargo clippy --workspace --target x86_64-unknown-linux-gnu` from the Windows host per memory `feedback_clippy_cross_target`. Windows-host workspace clippy alone is insufficient for Linux-touching plans.

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 37. Linux RESL + PKGS auto-pull | 0/TBD | Not started | - |
| 41. CI cleanup + broker CR | 10/9 | Complete   | 2026-05-16 |
| 42. UPST5 audit | 0/TBD | Not started | - |
| 43. UPST5 sync execution | 0/TBD | Not started | - |

## References

- `.planning/PROJECT.md` — milestone context, key decisions, deferred items.
- `.planning/REQUIREMENTS.md` — v2.5 requirements with acceptance criteria + traceability table.
- `.planning/PHASE-41-TRACKER.md` — pre-existing CI red error categorization (33 Linux/macOS Clippy + 5 Windows CI job failures) and suggested sub-plan structure.
- `.planning/todos/pending/v24-cr-01..04-*.md` — v24 Windows broker code-review todos (folded into Phase 41).
- `.planning/MILESTONES.md` — v2.4 close context (5 phases shipped; 5 requirements re-anchored to v2.5).
- `.planning/templates/upstream-sync-quick.md` — UPST5 sync template (baseline SHA updated at Phase 41 close per REQ-CI-03).
- `docs/architecture/upstream-parity-strategy.md` — Phase 33 ADR (Option A `continue` Accepted, re-confirmed v2.4 close).
