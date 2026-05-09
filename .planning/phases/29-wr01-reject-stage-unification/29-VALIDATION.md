---
phase: 29
slug: wr01-reject-stage-unification
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-09
---

# Phase 29 — Validation Strategy

> Reconstructed retroactively (State B) from `29-01-WRU-PLAN.md` + `29-01-SUMMARY.md` plus current-HEAD verification on the Windows host. Phase 29 is **documentation-only** (zero behavioral / wire / API delta — Option c locks the WR-01 reject-stage asymmetry as a permanent design property). Every requirement-bearing behavior has automated verification: existing `wr01_*` regression guards + Phase 23's multi-kind ledger E2E + grep gates over docstrings and `.planning/PROJECT.md` + `git diff --stat` byte-identity gates on `crates/nono/` and `crates/nono-cli/src/audit_commands.rs`.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust + Cargo (built-in `#[test]` runner) + ripgrep / git for documentation gates |
| **Config file** | `Cargo.toml` (workspace + `crates/nono-cli/Cargo.toml`) |
| **Quick run command** | `cargo test -p nono-cli --bin nono wr01_` |
| **Full suite command** | `cargo test -p nono-cli` |
| **Estimated runtime** | ~1 s for the 5 `wr01_*` tests + 1 multi-kind ledger test; ~2–3 min for full nono-cli suite |
| **Test directory** | `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (inline `capability_handler_tests` module) |
| **Helper conventions** | `MockBackend` (in-test capability backend), `make_supervisor_session_with_mock_backend()`, `aipc_request_*()` request builders, `RejectStage` from `nono-cli/src/audit_integrity.rs` |

---

## Sampling Rate

- **After every task commit:** `cargo test -p nono-cli --bin nono wr01_` (~1 s) + the 12 grep / diff gates from PLAN Task 3.
- **After every plan wave:** `cargo test -p nono-cli` (full nono-cli suite).
- **Before `/gsd-verify-work`:** All 12 PLAN Task 3 verification commands green; `cargo build --workspace` clean; `cargo fmt --all -- --check` clean.
- **Max feedback latency:** ~1 s for the focused `wr01_` suite; ~30 s for grep / diff gate sweep.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 29-01-T1 | 01 | 1 | REQ-WRU-01 (AC1, AC2) | T-29-01-02 (Tampering) | PROJECT.md `(unplanned)` markers cleared for WRU-01..02; `⚠️ Revisit v2.2` marker cleared for WR-01; new text references `Phase 29`, `design property`, and `Option c` | grep gate | `! grep -nE 'WRU-0[12].*\(unplanned\)' .planning/PROJECT.md && ! grep -qE 'unification deferred to v2.2' .planning/PROJECT.md && ! grep -qE '⚠️ Revisit v2.2.*WR-01' .planning/PROJECT.md && grep -qE 'Phase 29\|design property\|Option c' .planning/PROJECT.md` | ✅ | ✅ green (PROJECT.md has 5 `Phase 29`/`design property`/`Option c` matches; `(unplanned)` and `⚠️ Revisit v2.2` markers absent) |
| 29-01-T2a | 01 | 1 | REQ-WRU-01 (AC1) | T-29-01-01 (Information Disclosure — accepted) | WR-01 module docstring reframes the asymmetry as a permanent design property; back-references Phase 29 + PROJECT.md | grep gate | `[ "$(grep -c 'design property\|Phase 29' crates/nono-cli/src/exec_strategy_windows/supervisor.rs)" -ge 2 ]` | ✅ | ✅ green (count = 6; module docstring + 5 wr01_ test docstrings) |
| 29-01-T2b | 01 | 1 | REQ-WRU-02 (AC1) | T-29-01-03 (Repudiation — accepted) | All 5 `wr01_*` test docstrings carry a `Phase 29` / `design property` closure note | grep gate | `[ "$(grep -B 5 'fn wr01_' crates/nono-cli/src/exec_strategy_windows/supervisor.rs \| grep -c 'design property\|locked at Phase 29\|Phase 29')" -ge 5 ]` | ✅ | ✅ green (count = 5; one match per test) |
| 29-01-T2c | 01 | 1 | REQ-WRU-01 (AC1, AC2) | — | `RejectStage` enum docstring + `reject_stage` field doc reference Phase 29 with structural-rationale framing | grep gate | `[ "$(grep -c 'Phase 29' crates/nono-cli/src/audit_integrity.rs)" -ge 1 ]` | ✅ | ✅ green (count = 3; enum + field + serde rename context) |
| 29-01-T2d | 01 | 1 | REQ-WRU-01 (AC1) | — | Stale "deferred to v2.2 as a product decision" wording removed from supervisor.rs | grep negation | `! grep -q 'deferred to v2.2 as a product decision' crates/nono-cli/src/exec_strategy_windows/supervisor.rs` | ✅ | ✅ green (zero matches; commit `9fcdf123`) |
| 29-01-T3a | 01 | 1 | REQ-WRU-02 (AC1) | T-29-01-03 (Repudiation — assertions UNCHANGED) | All 5 `wr01_*` regression tests pass — verdict matrix unchanged: Event/Mutex/JobObject reject `BeforePrompt`, Pipe/Socket reject `AfterPrompt` | unit (Rust) | `cargo test -p nono-cli --bin nono wr01_` → `5 passed; 0 failed; 0 ignored` | ✅ | ✅ green (5 passed; 0 failed; 0 ignored on Windows host 2026-05-09) |
| 29-01-T3b | 01 | 1 | REQ-WRU-02 (AC2) | — | Phase 23 multi-kind ledger E2E (`audit_integrity_records_5_handle_kinds_in_ledger`) still green — wire shape preserved | integration (Rust) | `cargo test -p nono-cli --bin nono audit_integrity_records_5_handle_kinds_in_ledger` → `1 passed; 0 failed` | ✅ | ✅ green (1 passed; 0 failed; 0 ignored on Windows host 2026-05-09) |
| 29-01-T3c | 01 | 1 | REQ-WRU-02 (AC3) | — | `nono audit show <id>` counter rendering preserved verbatim — `Capability Decisions: N (M before-prompt, K after-prompt rejections)` shape FROZEN | git diff stat | `[ -z "$(git diff --stat a3734bb3^..9fcdf123 -- crates/nono-cli/src/audit_commands.rs)" ]` | ✅ | ✅ green (empty diff across the two Phase 29 commits) |
| 29-01-T3d | 01 | 1 | (D-19 invariant) | — | `crates/nono/` byte-identity preserved — zero library deltas | git diff stat | `[ -z "$(git diff --stat a3734bb3^..9fcdf123 -- crates/nono/)" ]` | ✅ | ✅ green (empty diff; D-19 held) |
| 29-01-T3e | 01 | 1 | REQ-WRU-02 (AC1 — regression-guard integrity) | — | No `#[ignore]` attribute introduced inside any `wr01_*` test body | awk + grep | `[ "$(awk '/fn wr01_/,/^}/' crates/nono-cli/src/exec_strategy_windows/supervisor.rs \| grep -c '#\\[ignore')" = "0" ]` | ✅ | ✅ green (count = 0; all 5 tests run unconditionally) |
| 29-01-T3f | 01 | 1 | (Diff-scope sanity) | T-29-01-02 (Tampering) | Last 2 Phase 29 commits modify exactly 3 files: `PROJECT.md` + `audit_integrity.rs` + `supervisor.rs` — no scope creep | git name-only | `git diff --name-only a3734bb3^..9fcdf123 \| sort -u` returns exactly the 3 expected paths | ✅ | ✅ green (exactly 3 paths; no other files touched) |
| 29-01-T3g | 01 | 1 | (build invariant) | — | Workspace builds clean; clippy + fmt clean | cargo | `cargo build --workspace` → `Finished`; `cargo fmt --all -- --check` exit 0 | ✅ | ✅ green per `29-01-SUMMARY.md` Verification gates 1, 3 (build + fmt) — clippy DOCUMENTED-SKIP for the 2 pre-existing `crates/nono/src/manifest.rs` `collapsible_match` errors out-of-scope per Phase 23's `deferred-items.md` and orthogonal to Phase 29's docstring-only edits |

*Status legend: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky/deferred*

---

## Wave 0 Requirements

*Existing infrastructure covers all phase requirements.* No Wave 0 stubs needed — the 5 `wr01_*` regression tests + the `audit_integrity_records_5_handle_kinds_in_ledger` multi-kind E2E shipped in v2.1 Phase 18.1 + v2.2 Phase 23. Phase 29's contract is **assertions UNCHANGED** (REQ-WRU-02 acceptance #1: chosen verdict matrix is the existing matrix), which means the existing tests ARE the regression guard on the locked decision. Adding new tests would violate the documented `<out_of_scope>` block in `29-01-WRU-PLAN.md` ("No new tests, no new test files, no new test functions; the existing 5 `wr01_*` tests are sufficient regression guards on the locked matrix.").

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `make ci` end-to-end clean (clippy + fmt + workspace test all green) | (project-strict invariant) | Pre-existing `crates/nono/src/manifest.rs:95+103` `collapsible_match` clippy errors at v2.2 baseline; out-of-scope per Phase 23's `deferred-items.md` and orthogonal to Phase 29's docstring-only edits. Phase 29 did NOT touch `crates/nono/` (D-19 byte-identity verified by 29-01-T3d). | Run `make ci` after the `crates/nono/` clippy debt is cleared in a future phase. The Phase 29-modified files (supervisor.rs + audit_integrity.rs + PROJECT.md) themselves contribute zero clippy / fmt warnings. |
| Re-litigation triggers (e.g., new HandleKind with mixed checkability; kernel API change moving Pipe/Socket checks earlier; Phase 18 approval-then-action contract revisited) | REQ-WRU-01 (decision permanence under current architecture) | The locked verdict (Option c) is permanent **under current architectural assumptions**. Re-opening requires a new ADR — there is no automatable "watch for v2.4+ AIPC HandleKind additions" gate. | Documented in `29-01-SUMMARY.md` § "Future re-litigation triggers". When v2.4+ proposes a new HandleKind in `crates/nono-cli/src/exec_strategy_windows/aipc_sdk.rs::HandleKind`, the design author should manually consult the locked taxonomy before adding a sixth variant; if the kind has mixed checkability, they trigger a new ADR. |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or are accepted as Manual-Only with documented rationale
- [x] Sampling continuity: every PLAN must-have truth (1–8) maps to an automated grep / cargo / git-diff gate (Task 3 verification list, items 1–12)
- [x] Wave 0 covers all MISSING references — N/A (no MISSING gaps; no new tests permitted by `<out_of_scope>` block)
- [x] No watch-mode flags
- [x] Feedback latency < ~10 s for focused `wr01_` suite
- [x] `nyquist_compliant: true` set in frontmatter — every requirement-bearing behavior is automated; the two manual-only entries are explicit non-runtime concerns (workspace clippy debt orthogonal to Phase 29's surface; future re-litigation triggers under hypothetical v2.4+ architectural changes)

**Approval:** approved 2026-05-09

---

## Validation Audit 2026-05-09

| Metric | Count |
|--------|-------|
| Gaps found | 0 (runtime); 2 (manual-only / out-of-scope) |
| Resolved | 0 (no runtime gaps to resolve) |
| Escalated | 2 (workspace clippy debt → pre-existing v2.2 baseline / `deferred-items.md`; re-litigation triggers → future-ADR concern) |
| New tests written | 0 (PLAN `<out_of_scope>` block forbids new tests; existing `wr01_*` matrix IS the regression guard on the locked decision) |
| Existing tests verified | 6 (5 `wr01_*` + `audit_integrity_records_5_handle_kinds_in_ledger`; all green on Windows host) |
