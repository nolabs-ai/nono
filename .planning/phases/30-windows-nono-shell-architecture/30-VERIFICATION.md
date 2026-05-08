---
phase: 30-windows-nono-shell-architecture
verified: 2026-05-08T15:00:00Z
status: passed
score: 10/10 must-haves verified
overrides_applied: 0
---

# Phase 30: Windows nono shell Architecture Verification Report

**Phase Goal:** Investigate `nono shell --profile <name>` on Windows 10/11; either land OS-enforced filesystem write protection AND interactive TUI rendering, OR document that no user-mode token shape can deliver both and defer to v3.0 with institutional knowledge preserved. Per CONTEXT D-04: phase ships at end-of-timebox regardless of investigation depth.

**Verified:** 2026-05-08T15:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

This phase explicitly ships as a failure-mode finding (option 6e: defer to v3.0). The phase contract per CONTEXT D-04 explicitly accepts this outcome: "phase ships at end-of-timebox regardless of investigation depth — either with a sixth option implemented OR with a documented v3.0/kernel-driver deferral." The verification checks whether that negative result is properly institutionalized, not whether the technical goal was achieved in the positive sense.

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | D-10 first-half: SHELL-01 row flipped from ✔ validated to ⚠ needs-rework in PROJECT.md before Wave 1 implementation | VERIFIED | Commit `baebc3f0`; SUMMARY 30-01 documents the flip |
| 2 | D-10 second-half: SHELL-01 row reaches terminal ✘ deferred-to-v3.0 state in PROJECT.md | VERIFIED | PROJECT.md line 71: `✘ **SHELL-01** — ... deferred to v3.0 kernel mini-filter driver work` |
| 3 | D-01/D-02/D-03: Wave 1 cascade arm (`WindowsTokenArm::LowIlPrimary`) inserted for PTY+!detached path | VERIFIED | launch.rs: `WindowsTokenArm` enum, `select_windows_token_arm` helper, 6th match arm at LowIlPrimary; commit `a496734b` |
| 4 | Acceptance #1 FAIL documented: silent launch failure with STATUS_DLL_INIT_FAILED surface in field smoke | VERIFIED | 30-FIELD-SMOKE.md operator log row: `2026-05-07 | FAIL | UNTESTED...`; Checkpoint 1 reclassified as false-positive PASS in SUMMARY 30-04 |
| 5 | Wave 2 ProcMon investigation localized failure to CSRSS ALPC at Low-IL during KernelBase DllMain | VERIFIED | 30-WAVE-2-PROCMON.md: process exit `0xC0000142`, 6.8 ms window after KernelBase load with zero further Load Image events; RESEARCH Pitfall 2 confirmed in field |
| 6 | D-04: timebox honored; all viable user-mode options exceed budget; 6e (defer) selected | VERIFIED | 30-WAVE-2-PROCMON.md sixth-option table: 6a 1-2 weeks, 6b 1+ week, both exceed D-04; 6e chosen |
| 7 | Bookkeeping terminal state: STATE.md stopped_at + Key Decisions v2.3 entry reflect Phase 30 failure-mode finding | VERIFIED | STATE.md frontmatter: `stopped_at: "Phase 30 deferred to v3.0..."`, `last_updated: "2026-05-08T14:15:00.000Z"`; Key Decisions (v2.3) block contains full Phase 30 narrative |
| 8 | Debug session moved to .planning/debug/resolved/ with Resolution section | VERIFIED | `.planning/debug/nono-shell-status-dll-init-failed.md` does NOT exist; `.planning/debug/resolved/nono-shell-status-dll-init-failed.md` FOUND with `status: resolved`, `resolved_by: phase-30-plan-05`, and `## Resolution` section at line 424 |
| 9 | Cookbook reverted per Option Rev-B: old `nono shell` recommendation removed; new deferred-to-v3.0 section added; Known limitation section retained | VERIFIED | `windows-poc-handoff.mdx`: grep for `nono shell --profile claude-code` returns 0 matches; `## \`nono shell\` on Windows is deferred to v3.0` section present at line 212; `## Known limitation: \`nono run\` cannot host TUI agents on Windows` retained at line 204 |
| 10 | Wave 1 cascade arm code preserved in tree: `WindowsTokenArm::LowIlPrimary` + `select_windows_token_arm` + `pty_token_gate_tests` (6/6) + `low_integrity_primary_token_sets_low_il` runtime test + `low_integrity_primary_token_tests` module | VERIFIED | launch.rs: all four constructs present; 831/831 `cargo test -p nono-cli --bin nono` PASS |

**Score:** 10/10 truths verified

### D-Coverage Gate

| Decision | Addressed In | Evidence |
|----------|-------------|----------|
| D-01 Low-IL primary token for PTY path | Plan 30-02 | `WindowsTokenArm::LowIlPrimary` arm; `select_windows_token_arm` branches on `has_pty` before `has_session_sid` |
| D-02 Null token rejected for nono shell | Plan 30-02 | SUMMARY 30-02 `requirements-completed: [D-01, D-02, D-03]`; `WindowsTokenArm::Null` not taken on PTY path |
| D-03 Anonymous-pipe stdio rejected | Plan 30-02 | Same as D-02; ConPTY path preserved |
| D-04 Wave 2 timebox honored | Plan 30-05 | 6e selected; all viable user-mode options documented as exceeding 3-5 day budget; SUMMARY 30-05 `requirements-completed: [D-04, D-07, D-10]` |
| D-05 TUI rendering locked (acceptance criterion 2) | Plan 30-04 | Acceptance #2 UNTESTED — couldn't enter sandbox; documented as false-positive in Checkpoint 1 |
| D-06 OS-level write-deny locked (acceptance criterion 3) | Plan 30-04 | Acceptance #3 UNTESTED — couldn't enter sandbox |
| D-07 v2.3 not blocked | Plan 30-05 | Cookbook reverted; POC users redirected to `nono run`; v2.3 milestone unblocked |
| D-08 Hook-firing investigation out of scope | Plan 30-01 | SUMMARY 30-01 `requirements-completed: [D-10, D-08, D-09]`; explicit out-of-scope declaration in must_haves |
| D-09 AppliedLabelsGuard leak out of scope | Plan 30-01 | Same as D-08; separate debug session pointer |
| D-10 SHELL-01 bookkeeping correction | Plans 30-01 + 30-05 | First-half: Plan 30-01 `baebc3f0`; second-half: Plan 30-05 `5a79969a`; terminal ✘ state verified |

**D-coverage:** 10/10 decisions addressed across the 5 plans.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `.planning/PROJECT.md` | SHELL-01 row at terminal ✘ deferred state | VERIFIED | Line 71: `✘ **SHELL-01** — ... deferred to v3.0 kernel mini-filter driver work` |
| `.planning/STATE.md` | stopped_at Phase 30 deferred; Key Decisions v2.3 entry present | VERIFIED | `stopped_at: "Phase 30 deferred to v3.0 (Wave 2 exhausted; SHELL-01 → ✘; cookbook reverted per RESEARCH Option Rev-B)"`; dense v2.3 entry at line 93 |
| `.planning/debug/resolved/nono-shell-status-dll-init-failed.md` | status: resolved; Resolution section present | VERIFIED | `status: resolved`, `resolved_by: phase-30-plan-05`, `## Resolution` section at line 424 |
| `.planning/debug/nono-shell-status-dll-init-failed.md` (non-resolved path) | MUST NOT EXIST (moved via git mv) | VERIFIED | File confirmed absent |
| `docs/cli/development/windows-poc-handoff.mdx` | Option Rev-B revert applied; deferred-to-v3.0 section added; Known limitation retained | VERIFIED | Old `nono shell` recommendation absent; `## \`nono shell\` on Windows is deferred to v3.0` section at line 212; Known limitation section at line 204 |
| `crates/nono-cli/src/exec_strategy_windows/launch.rs` | Wave 1 cascade arm preserved; CR-01 fix applied | VERIFIED | `WindowsTokenArm` enum, `select_windows_token_arm`, `LowIlPrimary` arm, `pty_token_gate_tests`, `low_integrity_primary_token_tests` all present; `SecurityAnonymous` replaces `SecurityImpersonation` (CR-01 applied in commit `c60cc766`) |
| `.planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md` | ProcMon analysis + Final outcome section | VERIFIED | 256-line document; `## Final outcome` section at line 227; failure surface analysis, sixth-option table, and timebox tracking present |
| `.planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md` | Operator log row filled with 2026-05-07 FAIL | VERIFIED | Operator log row present: `2026-05-07 | FAIL | UNTESTED (Checkpoint 1 false-positive PASS) | UNTESTED | UNTESTED | Wave 1 field smoke...` |
| `.planning/phases/30-windows-nono-shell-architecture/30-REVIEW.md` | Code review report present; CR-01 BLOCKER documented | VERIFIED | 230-line file; CR-01 `DuplicateTokenEx` impersonation-level mismatch documented as CRITICAL; 4 WARNINGs, 2 INFOs |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| PROJECT.md SHELL-01 row | debug session | narrative citation `nono-shell-status-dll-init-failed` | VERIFIED | Commit `baebc3f0` added the reference; Plan 30-01 `key_links[0]` |
| debug session frontmatter | 30-CONTEXT.md | `resolution_doc` field | VERIFIED | `resolution_doc: .planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md` (updated to final doc); `related_phase: 30-windows-nono-shell-architecture` present |
| debug session | resolved/ location | git mv | VERIFIED | File present at resolved path; absent at original path |
| cookbook | deferred-to-v3.0 section | anchor link `#nono-shell-on-windows-is-deferred-to-v30` | VERIFIED | `<Note>` at line 11 links to the section; `Step 4` and `Step 5` cross-reference it |
| launch.rs cascade | LowIlPrimary arm | `match arm` when `has_pty && !is_detached` | VERIFIED | `select_windows_token_arm` returns `LowIlPrimary` for `pty.is_some() && !is_detached`; `spawn_windows_child` calls `select_windows_token_arm` with `pty.is_some()` |

### Code Preservation Check (Wave 1 Cascade Arm)

The following elements MUST exist in `crates/nono-cli/src/exec_strategy_windows/launch.rs` for Phase 31 / v3.0 inheritance:

| Element | Status | Line Reference |
|---------|--------|---------------|
| `WindowsTokenArm` enum with `LowIlPrimary` variant | PRESENT | Lines 1039-1051 |
| `select_windows_token_arm` pure helper | PRESENT | Lines 1056-1073 |
| 6th cascade arm dispatching to `create_low_integrity_primary_token()` | PRESENT | Lines 1232-1237 |
| `pty_token_gate_tests` module (6 tests) | PRESENT | Lines 1518-1603 |
| `low_integrity_primary_token_tests` module | PRESENT | Lines 1605-end |
| `low_integrity_primary_token_sets_low_il` runtime test | PRESENT | Line 1624 |
| CR-01: `SecurityAnonymous` (not `SecurityImpersonation`) in `create_low_integrity_primary_token` | APPLIED | Line 1106; commit `c60cc766` |

### Test Verification

| Command | Result | Status |
|---------|--------|--------|
| `cargo test -p nono-cli --bin nono` | 831 passed; 0 failed; 0 ignored | PASS |

### Acceptance Criteria Verdicts

Per the phase failure-mode path, acceptance criteria resolve as follows:

| Acceptance | Result | Documentation |
|------------|--------|---------------|
| #1: shell launches without 0xC0000142 | FAIL — silent launch | 30-FIELD-SMOKE.md operator log; 30-04-SUMMARY Checkpoint 2 manual diagnostics (same PID + Medium-IL + no nono process) |
| #2: claude TUI renders inside sandbox | UNTESTED — Checkpoint 1 was false-positive PASS (claude rendered in OUTER shell) | 30-04-SUMMARY § "Checkpoint 1 was a false positive"; RESEARCH Pitfall 2 realized |
| #3: write outside grant set denied at OS level | UNTESTED — couldn't enter sandbox | 30-04-SUMMARY; harness CLI mismatch also documented |
| #4: read of granted path still works | UNTESTED — couldn't enter sandbox | 30-04-SUMMARY |
| #5: PROJECT.md SHELL-01 entry reflects current reality | VERIFIED — ✘ deferred to v3.0 | PROJECT.md line 71 |
| #6: cookbook describes security envelope honestly | VERIFIED — deferred-to-v3.0 section added; old recommendation removed | `windows-poc-handoff.mdx` lines 212-225 |

Acceptance #1-#4 are FAILs or UNTESTEDs — but the phase contract (CONTEXT D-04) explicitly accepts this: the phase ships as failure-mode finding when no viable user-mode option is surfaced within the timebox. The failure is correctly documented, not silently ignored.

### Code Review Applied

| Finding | Severity | Status |
|---------|----------|--------|
| CR-01: `SecurityImpersonation` → `SecurityAnonymous` in `create_low_integrity_primary_token` | BLOCKER (latent, cascade arm dead code) | APPLIED — commit `c60cc766`; `SecurityAnonymous` confirmed in launch.rs line 1106 |
| WR-01: `Out-File` invalid syntax = always-PASS on write-deny test | WARNING | DOCUMENTED in 30-WAVE-2-PROCMON.md Critical caveat section; deferred to Phase 31 |
| WR-02: `Read-PassFail` regex incorrectly parenthesized | WARNING | Documented in 30-REVIEW.md; deferred to Phase 31 (harness is Phase 31 inheritance) |
| WR-03: `pty.is_none()` check redundant in `detached_stdio` allocation | WARNING | Documented; deferred to Phase 31 |
| WR-04: `$targetFile` interpolation inside `@"..."` here-string | WARNING | Documented; no behavioral defect |
| IN-01: `$USERPROFILE\Desktop` may not exist on folder-redirect enterprise setups | INFO | Documented; deferred to Phase 31 |
| IN-02: `Known limitation` cross-reference not anchor-linked in cookbook | INFO | Documented; minor UX |

**BLOCKER falsified empirically:** The review noted CR-01 is latent (cascade arm is dead code post-Phase-30 finding). It cannot block `CreateProcessAsUserW` because the cascade arm is never reached in production (Phase 30 confirmed `STATUS_DLL_INIT_FAILED` before `CreateProcessAsUserW` even completes child initialization). However, the fix was applied anyway per the review recommendation to guard Phase 31.

### Anti-Patterns Scan

No placeholder stubs, TODO/FIXME comments, or hardcoded empty data found in the Phase 30 code changes that would misrepresent what was delivered. The cascade arm code that "looks like dead code" is intentionally preserved as a Phase 31 guard, with explicit comments explaining this (launch.rs `LowIlPrimary` variant docstring: "Phase 30 D-01 supervised+PTY path").

The harness scripts `test-windows-shell-write-deny.ps1` and `test-windows-shell-tui.ps1` contain known pre-existing bugs (Out-File syntax, Read-PassFail regex) documented in 30-WAVE-2-PROCMON.md and 30-REVIEW.md. These are not stubs — the scripts were authored and used; the bugs are behavioral defects in test harnesses that are explicitly flagged for Phase 31 correction.

### Behavioral Spot-Checks

Step 7b: Skipped for the following items that cannot be verified programmatically on this non-Windows host:

- Acceptance #1-#4 (live Windows shell launch): requires Windows test box + built binary
- `low_integrity_primary_token_sets_low_il` test: `#[cfg(all(test, target_os = "windows"))]`-gated; not runnable on non-Windows host

Items verifiable programmatically:

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| 831/831 unit tests pass | `cargo test -p nono-cli --bin nono` | 831 passed; 0 failed | PASS |
| `WindowsTokenArm::LowIlPrimary` present in launch.rs | grep | 3+ matches | PASS |
| `select_windows_token_arm` helper present | grep | 1 definition + call site | PASS |
| `SecurityAnonymous` present (CR-01 applied) | grep | line 1106 | PASS |
| SHELL-01 row is ✘ (not ✔ or ⚠) in PROJECT.md | grep | line 71 | PASS |
| debug session at resolved path | file check | FOUND | PASS |
| debug session absent at non-resolved path | file check | NOT FOUND | PASS |

### Human Verification Required

None. The phase ships as a negative result (failure-mode finding). All bookkeeping artifacts have been verified programmatically. The technical claims in 30-WAVE-2-PROCMON.md (CSRSS ALPC denial, ProcMon trace interpretation) were made by the operator during live investigation and are supported by the diagnostic evidence table in the document. No further human verification is needed for phase acceptance — the operator already provided the field smoke results that drove the deferral decision.

### Gaps Summary

No gaps found. All four bookkeeping artifacts (PROJECT.md SHELL-01 row, STATE.md Key Decisions v2.3 entry, debug session at resolved/, cookbook Option Rev-B revert) are at their failure-path terminal state. Wave 1 cascade arm code is preserved. D-01..D-10 all addressed across the 5 plans. CR-01 hygiene fix applied. 831/831 tests pass.

The phase delivered the negative outcome it was contracted to deliver per CONTEXT D-04.

---

_Verified: 2026-05-08T15:00:00Z_
_Verifier: Claude (gsd-verifier)_
