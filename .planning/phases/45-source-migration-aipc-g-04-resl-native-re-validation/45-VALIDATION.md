---
phase: 45
slug: source-migration-aipc-g-04-resl-native-re-validation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-21
---

# Phase 45 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Sourced from `45-RESEARCH.md` § Validation Architecture (lines 569–613).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test` (built-in harness) + GitHub Actions for native-host orchestration |
| **Config file** | `Cargo.toml` workspace `[workspace.lints.clippy] unwrap_used = "deny"` (Phase 43 Plan 43-01b); per-crate `[lints] workspace = true` |
| **Quick run command** | `cargo test --workspace` |
| **Full suite command** | `cargo test --workspace --all-features` (Phase 43 Plan 43-01b baseline: 2197 passed / 0 failed / 19 ignored) |
| **Estimated runtime** | ~180 seconds full suite on Windows host |

---

## Sampling Rate

- **After every task commit:** Run `cargo build` (fast feedback)
- **After every plan close:** Run `cargo test --workspace --all-features` + `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) + `cargo fmt --all -- --check`
- **Plan 45-01 close additionally:** `cargo build -p nono-ffi` + `git diff bindings/c/include/nono.h` (must be empty — cbindgen byte-identical gate per D-45-B3)
- **Plan 45-02 close additionally:** `cargo test --bin nono recorded_ledger_redacts_session_token -- --exact` (AUD-05 token-redaction regression spot-check)
- **Before `/gsd-verify-work`:** Full suite green + cross-target Linux + macOS clippy (PARTIAL per `.planning/templates/cross-target-verify-checklist.md`) + cbindgen byte-identical + 8-check close gate per Phase 43 D-43-E9 / Phase 44 close pattern
- **Max feedback latency:** ~180 seconds (full workspace test)

---

## Per-Requirement Verification Map

> Per-task rows are filled by the planner at plan-author time. The matrix below is the requirement-level contract from RESEARCH.md § Validation Architecture.

| Req ID | Plan | Behavior | Test Type | Automated Command | File Exists | Status |
|--------|------|----------|-----------|-------------------|-------------|--------|
| REQ-PORT-CLOSURE-08 | 45-01 | 39 `#[unsafe(no_mangle)]` rewrites land; cargo clippy clean on Windows host | build + clippy | `cargo build -p nono-ffi --release` AND `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` | ✅ | ⬜ pending |
| REQ-PORT-CLOSURE-08 | 45-01 | Cross-target Linux clippy clean (PARTIAL per checklist) | clippy | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` (Rust target ✓ installed, C linker ✗ — PARTIAL disposition) | ✅ runtime, ❌ toolchain | ⬜ pending |
| REQ-PORT-CLOSURE-08 | 45-01 | Cross-target macOS clippy clean (PARTIAL per checklist) | clippy | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` (Rust target ✓ installed, Darwin SDK ✗ — PARTIAL disposition) | ✅ runtime, ❌ toolchain | ⬜ pending |
| REQ-PORT-CLOSURE-08 | 45-01 | cbindgen header `bindings/c/include/nono.h` byte-identical post-migration | grep/diff | `git diff bindings/c/include/nono.h` returns empty | ✅ | ⬜ pending |
| REQ-PORT-CLOSURE-08 | 45-01 | DIVERGENCE-LEDGER Cluster 2 disposition `split → closed` with back-reference to `79715aa5` | grep | `grep -c 'closed' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` (verify amended line) | ✅ | ⬜ pending |
| REQ-AIPC-G04-01 | 45-02 | `Approved(ResourceGrant)` inlined; `(Approved, grant=None)` is compile-time error | compile-time gate | `cargo build --workspace --all-features` exits 0 AND `grep -rn 'grant: Option<ResourceGrant>' crates/ bindings/` returns 0 AND `grep -rn 'ApprovalDecision::Granted' crates/ bindings/` returns 0 | ✅ | ⬜ pending |
| REQ-AIPC-G04-01 | 45-02 | All 23+ pre-existing tests updated; full workspace green | test | `cargo test --workspace --all-features` (≥ 2197 tests pass) | ✅ | ⬜ pending |
| REQ-AIPC-G04-01 | 45-02 | AUD-05 token-redaction regression `recorded_ledger_redacts_session_token` passes | test (targeted) | `cargo test --bin nono recorded_ledger_redacts_session_token -- --exact` | ✅ at `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:5033` | ⬜ pending |
| REQ-AIPC-G04-01 | 45-02 | `aipc_sdk.rs:417` `ok_or_else` defense-in-depth branch removed | grep | `grep -c 'supervisor granted but returned no ResourceGrant' crates/` = 0 | ✅ | ⬜ pending |
| REQ-RESL-NIX-04 (STRUCTURAL) | 45-03 | `.github/workflows/phase-45-resl-native-host.yml` exists; YAML-valid; `workflow_dispatch`-only per D-45-D2 | grep + YAML lint | `test -f .github/workflows/phase-45-resl-native-host.yml` AND `grep -c 'workflow_dispatch:' .github/workflows/phase-45-resl-native-host.yml` = 1 AND `grep -cE '^  pull_request:\|^  push:' .github/workflows/phase-45-resl-native-host.yml` = 0 | ❌ Wave 0 (new) | ⬜ pending |
| REQ-RESL-NIX-04 (STRUCTURAL) | 45-03 | `45-03-NATIVE-RESL-PROTOCOL.md` exists; documents SC#3 decision tree | grep | `test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` | ❌ Wave 0 (new) | ⬜ pending |
| REQ-RESL-NIX-04 (LIVE-RUN, deferred to Phase 46) | 45-03 | Native Linux + macOS audit-attestation regression passes | manual GH Actions trigger | `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` then `gh run watch` | ⏸ Phase 46 | ⬜ pending |
| Cross-cutting SC#4 | phase-close | Windows-only-files invariant honored (D-34-E1 / D-40-E1) | grep + file scope | `git diff --stat <phase-base>..<phase-head> -- 'crates/**/*_windows.rs' 'crates/nono-cli/src/exec_strategy_windows/**' 'crates/nono-shell-broker/**'` lists only Plan 45-02 cascade in `exec_strategy_windows/supervisor.rs` (with documented justification per CONTEXT.md § cross-phase invariants) | N/A | ⬜ pending |
| Cross-cutting SC#5 | phase-close | Workspace builds + tests green on Windows host | build + test | `cargo build --workspace --all-features` AND `cargo test --workspace --all-features` (post `cargo build -p nono-shell-broker --release` per Phase 43-01b Issue 1 lesson) | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `.github/workflows/phase-45-resl-native-host.yml` — Plan 45-03 authors NEW. Covers REQ-RESL-NIX-04 structural artifact.
- [ ] `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` — Plan 45-03 authors NEW. Covers REQ-RESL-NIX-04 protocol doc.
- [ ] Plan-open inventory grep for Plan 45-02 — planner runs `grep -rn 'ApprovalDecision::Granted\|grant: Option<ResourceGrant>\|grant: None\|grant: Some' crates/ bindings/` and inventories test count (CONTEXT.md says 23 ±2 allowed; if delta > 2, surface as deviation). Already executed in RESEARCH.md § "Plan 45-02 Cascade Map"; planner re-runs at plan-open for sequence-of-record.
- [ ] Cross-target verifier-protocol close-gate artifacts (`44-01-CLIPPY-CROSS-TARGET.md` analog) — Plan 45-01 + 45-02 author `45-01-CLIPPY-CROSS-TARGET.md` and `45-02-CLIPPY-CROSS-TARGET.md` per cross-target-verify-checklist.md § Enforcement.

*No framework install needed — Cargo test harness + GitHub Actions are pre-existing.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Cross-target Linux clippy lane | REQ-PORT-CLOSURE-08 (cross-cutting SC#1) | Windows host lacks `x86_64-linux-gnu-gcc` C linker; the Rust target is installed but the C-toolchain cannot link. PARTIAL disposition per cross-target-verify-checklist.md. | Live verification via GH Actions Linux Clippy lane on Phase 45 head SHA after merge. |
| Cross-target macOS clippy lane | REQ-PORT-CLOSURE-08 (cross-cutting SC#1) | Windows host lacks Darwin SDK / `cc`. PARTIAL disposition per cross-target-verify-checklist.md. | Live verification via GH Actions macOS Clippy lane on Phase 45 head SHA after merge. |
| Phase 45-03 native RESL live run | REQ-RESL-NIX-04 (LIVE-RUN) | Windows host cannot execute the Linux/macOS `audit-attestation` test surface natively; requires GH Actions runner trigger. Tactical confirmation pass — `STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN` per D-45-D1; live run deferred to Phase 46 orchestrator action. | `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` then `gh run watch`; report verdict in `45-03-SUMMARY.md` § Closure Disposition (matches Phase 27.2 closure OR documented gap with v2.7 follow-up). |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies (planner enforces in PLAN.md `<acceptance_criteria>`)
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify (planner enforces via task ordering)
- [ ] Wave 0 covers all MISSING references (workflow file + protocol doc)
- [ ] No watch-mode flags (cargo test does not use watch mode — N/A)
- [ ] Feedback latency < 180s (full suite)
- [ ] `nyquist_compliant: true` set in frontmatter at planner close

**Approval:** pending (orchestrator will flip `nyquist_compliant: true` after planner produces PLAN.md files that map every Per-Requirement row to a `<task>` and the plan-checker verifies Dimension 8 coverage)
