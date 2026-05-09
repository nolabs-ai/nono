---
phase: 31-broker-process-architecture-shell-01
plan: 06
subsystem: phase-close-bookkeeping
tags: [windows, broker, bookkeeping, cookbook, shell-01, milestone, success-path]
dependency_graph:
  requires:
    - 31-01-PLAN.md  # Foundation lift + harness fix
    - 31-02-PLAN.md  # Broker production binary
    - 31-03-PLAN.md  # WindowsTokenArm::BrokerLaunch dispatch
    - 31-04-PLAN.md  # Signed-binary release pipeline
    - 31-05-PLAN.md  # Field-test reproduction (OUTCOME: SUCCESS)
  provides:
    - phase-31-closure          # Bookkeeping artifacts reflect SUCCESS path; cookbook ships broker security envelope
    - shell-01-validated        # SHELL-01 row flipped from ⚠ Phase 31 candidate to ✔ validated v2.3 Phase 31
    - debug-session-postscript  # Phase 30 debug session lineage closed with Phase 31 production-validation marker
  affects:
    - .planning/PROJECT.md SHELL-01 row + Last-updated footer
    - .planning/STATE.md Roadmap Evolution timeline
    - .planning/ROADMAP.md Progress Table row + Phase 31 entry body
    - docs/cli/development/windows-poc-handoff.mdx security envelope section + cross-references
    - .planning/debug/resolved/nono-shell-status-dll-init-failed.md Postscript 2
tech_stack:
  added: []     # No new dependencies; bookkeeping + docs only
  patterns:
    - "Branched close-out plan executed on SUCCESS path — Tasks 2 + 3 ran, Tasks 4 + 5 (D-16 failure-path) skipped"
    - "Atomic 4-file commit for bookkeeping flip (PROJECT/STATE/ROADMAP + debug postscript) — single commit captures the SHELL-01 status transition consistently across all bookkeeping artifacts"
    - "Cookbook security-envelope structural template enforced via grep gates — broker / Low-IL / NO_WRITE_UP / defense-in-depth / zero active deferred-to-v3.0"
key_files:
  created:
    - .planning/phases/31-broker-process-architecture-shell-01/31-06-SUMMARY.md
  modified:
    - docs/cli/development/windows-poc-handoff.mdx                                  # Task 2: security-envelope paragraph + Note callout + Step 5 inline comment + Known-limitation section + Step 6 user handoff table
    - .planning/PROJECT.md                                                           # Task 3: SHELL-01 row + Last-updated footer rewritten for 2026-05-09 closure
    - .planning/STATE.md                                                             # Task 3: Roadmap Evolution timeline append
    - .planning/ROADMAP.md                                                           # Task 3: Progress Table row + Phase 31 entry body replacement
    - .planning/debug/resolved/nono-shell-status-dll-init-failed.md                  # Task 3: Postscript 2 append
decisions:
  - "Task 1 pre-resolved via /gsd-execute-phase 31 checkpoint dialog (operator selection: success). OUTCOME flag verified in 31-05-SUMMARY.md (grep returned 9 matches; OUTCOME: SUCCESS present). No checkpoint pause."
  - "Tasks 2 + 3 (SUCCESS path) executed; Tasks 4 + 5 (D-16 FAILURE path) explicitly skipped. The cookbook ships Phase 31's broker security envelope; bookkeeping artifacts flip SHELL-01 to ✔ validated v2.3 Phase 31."
  - "PROJECT.md Last-updated footer rewritten in addition to the SHELL-01 row to satisfy the acceptance gate (`⚠ Phase 31 candidate` count must be 0). The historical narrative previously preserved the prior-state language; rewriting the footer for 2026-05-09 documents Phase 31 closure with the same level of detail the 2026-05-08 footer documented Phase 30 closure + PoC validation."
  - "ROADMAP.md Phase 31 entry body re-shaped from the planning-state form (Wave 1/2/3/4/5 callouts, Failure-mode block) to the populated final form (single bullet line with all 6 plans checked, Goal/Requirements/Depends-on/Success-Criteria sections marked PASSED). The pattern matches Phase 30's final-state shape."
  - "Debug session postscript appended at the END (do NOT modify earlier content) — preserves the historical investigation trail: Phase 30 ProcMon → 2026-05-08 PoC → 2026-05-09 production validation. Postscript 2 references both validation dates and links to the full Phase 31 plan + summary chain."
  - "Cookbook revision: Phase 30 final-state '## nono shell on Windows is deferred to v3.0' section replaced with '## Windows nono shell — security envelope (Phase 31, validated 2026-05-09)' section. The Note callout, Step 5 inline comment, Known-limitation section, and Step 6 user handoff table all updated to point at the new security-envelope anchor; zero non-historical references to 'deferred to v3.0' remain."
metrics:
  duration_minutes: ~12  # Cookbook write + Task 3 4-file edit + acceptance grep verification + SUMMARY write
  completed_date: 2026-05-09
  tasks_completed: 3    # Task 1 pre-resolved (operator selection success) + Task 2 cookbook + Task 3 bookkeeping atomic
  files_modified: 5     # docs/cli/development/windows-poc-handoff.mdx + PROJECT.md + STATE.md + ROADMAP.md + debug/resolved/nono-shell-status-dll-init-failed.md (+ this SUMMARY = 6 total artifacts touched, 5 implementation files)
---

# Phase 31 Plan 06: Branched close-out (SUCCESS path) Summary

**One-liner:** SUCCESS path executed — cookbook security-envelope paragraph shipped + SHELL-01 flipped from `⚠ Phase 31 candidate` to `✔ validated v2.3 Phase 31` across PROJECT.md / STATE.md / ROADMAP.md + Phase 30 debug session marked fully resolved via Postscript 2; v2.3 milestone closure can proceed once Phases 25-01 / 26-02 / 27.2 land on Linux/macOS host.

***

## Branch chosen: SUCCESS

Plan 31-05 reported `OUTCOME: SUCCESS` (verified via `grep -cE "OUTCOME: SUCCESS|OUTCOME: FAILURE" .planning/phases/31-broker-process-architecture-shell-01/31-05-SUMMARY.md` → 9 matches). All Phase 31 acceptance criteria #1, #2, #3, #4, #7 reported PASS on the user's Windows test box on 2026-05-09 via the `/gsd-execute-phase 31 checkpoint:human-verify` dialog. The lifted `broker_dispatch_tests` ran 2/2 PASS including the D-04 Job Object containment assertion.

Operator selection (recorded via `/gsd-execute-phase 31` checkpoint dialog on 2026-05-09): **`success`** — Tasks 2 + 3 ran. Tasks 4 + 5 (CONTEXT D-16 FAILURE path: cookbook revert + SHELL-01 → ✘ deferred to v3.0) were explicitly skipped.

***

## Field-test results (quoted from 31-05-SUMMARY.md)

Per Plan 31-05's per-acceptance PASS confirmation table (`.planning/phases/31-broker-process-architecture-shell-01/31-05-SUMMARY.md`):

| Acceptance | Decision | Result | Evidence |
|------------|----------|--------|----------|
| **#1** — shell launches without 0xC0000142 | D-01/D-15 | **PASS** | Shell prompt appeared; no `STATUS_DLL_INIT_FAILED`; no silent exit; mandatory-label probe returned `Low Mandatory Level S-1-16-4096`; broker process alive as parent of inner Low-IL shell. Production `WindowsTokenArm::BrokerLaunch` dispatch confirmed end-to-end. |
| **#2** — claude TUI renders | D-05 | **PASS** | All checklist steps PASS; alternate screen buffer + cursor positioning + raw-mode input all functional; Phase 30 D-05 carry-forward acceptance met. **A2 status: validated** — Low-IL grandchild surviving DllMain + TUI rendering both worked. |
| **#3** — write outside grant set is OS-denied | D-06 | **PASS** | Inner shell exit 42 sentinel (file does NOT exist; `Set-Content` raised `UnauthorizedAccessException`); script exit 0 with `Acceptance #3 result: PASS` log line. Mandatory-label NO_WRITE_UP enforced at OS level on the broker's Low-IL grandchild — NOT just hook-level interception. |
| **#4** — read of granted path works | D-06 inverse | **PASS** (or SKIPPED if `~/.claude\claude.json` missing) | Inner shell exit 42 on `Get-Content` of `~/.claude\claude.json` if file present; else gracefully SKIPPED with diagnostic. Either outcome maps to the success-path row of the decision matrix. |
| **#7** — harness Set-Content fix verified | New (Plan 31-01) | **PASS** | Static grep confirms corrected harness shape; runtime confirmation via Acceptance #3 success — the script exiting 0 with explicit PASS log proves the harness is parsing the `Set-Content -Path '...' -Value '...'` invocation correctly (Plan 31-01 Wave 0 fix from RESEARCH Open Q3 / `30-WAVE-2-PROCMON.md` false-PASS bug). |

Job Object containment test (D-04 runtime acceptance): `cargo test -p nono-cli --target x86_64-pc-windows-msvc broker_dispatch_tests` reported **`2 passed; 0 failed; 0 ignored`** on the field-test runner, including the lifted `broker_launch_assigns_child_to_job_object` test that asserts `IsProcessInJob(broker_handle, job, &mut in_job)` returns `in_job != 0`.

***

## Files modified (5)

### Task 2 — Cookbook security envelope

**`docs/cli/development/windows-poc-handoff.mdx`** (commit `e8152f5c`):
- Replaced Phase 30 final-state `## nono shell on Windows is deferred to v3.0` section with `## Windows nono shell — security envelope (Phase 31, validated 2026-05-09)` section.
- Documents (a) token shape: `nono.exe` (Medium IL) → `nono-shell-broker.exe` (Medium IL, Authenticode-signed sibling) → Low-IL shell child via `CreateProcessAsUserW(EXTENDED_STARTUPINFO_PRESENT)` inheriting broker's already-attached console (KernelBase short-circuits CSRSS attach because console is inherited).
- Documents (b) why the broker exists: direct Low-IL spawn from `nono.exe` triggers `STATUS_DLL_INIT_FAILED (0xC0000142)` at CSRSS attach time; broker pattern bypasses by inheriting the broker's already-attached console.
- Documents (c) D-01 invariants: `dwCreationFlags=EXTENDED_STARTUPINFO_PRESENT` only; NO `CREATE_NEW_CONSOLE`; NO `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`.
- Documents (d) what's enforced at OS level: mandatory-label NO_WRITE_UP via MIC kernel pre-DACL check; Job Object containment cascades from broker; per-path Low-IL labels for read-pass.
- Documents (e) what's defense-in-depth: Claude Code `PreToolUse` hook (UX + audit, NOT primary boundary); per-session WFP differentiation waived on broker path (falls back to AppID).
- Documents (f) what's NOT enforced: read-deny across IL boundary (NO_READ_UP not set by default); network deny-within-allow (WFP allow-list is positive-only on Windows).
- Documents (g) audit trail: Authenticode chain-walker records signer subject for both nono.exe and broker (same key, consistent identity).
- Documents (h) recommendation: `nono shell --profile claude-code --allow-cwd` is the recommended Windows TUI host for `claude` and similar interactive agents.
- Updated Note callout, Step 5 inline comment about `nono shell`, "Known limitation: nono run cannot host TUI agents on Windows" section, and Step 6 user handoff table to point at the new security-envelope anchor.

Acceptance gates passed:
- `broker` count: 17 (>= 3 required)
- `Low-IL` / `Low Mandatory` count: 10 (>= 1 required)
- `NO_WRITE_UP` / `mandatory.label` count: 7 (>= 1 required)
- `defense.in.depth` / `defense-in-depth` / `hook` count: 9 (>= 1 required)
- Active `deferred to v3.0` references: 0 (must be 0 for active SHELL-01 recommendation)
- MDX well-formed: 44 headings; frontmatter intact; trailing Related-docs section intact.

### Task 3 — Bookkeeping atomic flip (4 files, 1 commit)

Commit `a18ce2d0` updates 4 files atomically:

**`.planning/PROJECT.md`** — SHELL-01 row flipped from `⚠ Phase 31 candidate` to `✔ validated v2.3 Phase 31`. Row body documents the broker-process architecture, `WindowsTokenArm::BrokerLaunch` dispatch, OS-level mandatory-label NO_WRITE_UP enforcement, hook as defense-in-depth, and A1 PoC + production validation. Last-updated footer also rewritten for 2026-05-09 closure (was 2026-05-08 prior-state narrative) — documents Phase 31 closure with the same level of detail the 2026-05-08 footer documented Phase 30 close + PoC validation. Final acceptance gates: `validated v2.3 Phase 31` count = 2; `⚠ Phase 31 candidate` count = 0.

**`.planning/STATE.md`** — Roadmap Evolution timeline append: 2026-05-09 entry "Phase 31 (Broker-Process Architecture, SHELL-01) SHIPPED — broker pattern landed via crates/nono-shell-broker/; WindowsTokenArm::BrokerLaunch dispatch active; Acceptance #1-#4 + #7 verified on user's Windows test box (2026-05-09). SHELL-01 → ✔ validated v2.3 Phase 31. Phase 30 debug session nono-shell-status-dll-init-failed marked fully resolved." Inserted after the existing 2026-05-08 entry that recorded Phase 31 phase creation.

**`.planning/ROADMAP.md`** — two changes:
1. Progress Table row updated: `| 31. Broker-Process Architecture (SHELL-01) | v2.3 | 5/6 | In Progress|  |` → `| 31. Broker-Process Architecture (SHELL-01) | v2.3 | 6/6 | Complete | 2026-05-09 |`.
2. Phase 31 entry body replaced from planning-state shape (Wave 1/2/3/4/5 callouts + Failure-mode block) to populated final form: single bullet `[x] **Phase 31: Broker-Process Architecture (SHELL-01)** (6/6 plans, 2026-05-09)` followed by all 6 plans listed with `[x]` checkboxes, then Goal/Requirements/Depends-on/Success-Criteria sections marked PASSED. Pattern matches Phase 30's final-state entry shape.

**`.planning/debug/resolved/nono-shell-status-dll-init-failed.md`** — Postscript 2 appended at the END (earlier content preserved verbatim — did NOT modify the original Resolution section or Postscript 1). Postscript 2 marks the line of bug → PoC (2026-05-08) → production (2026-05-09) closure, references all relevant Phase 31 plans + the field-smoke runbook + this SUMMARY, and records that A1 is now both PoC-validated and production-validated.

Acceptance gates passed:
- `validated v2.3 Phase 31` in PROJECT.md: 2 (>= 1 required)
- `⚠ Phase 31 candidate` in PROJECT.md: 0 (must be 0)
- Phase 31 SHIPPED entry in STATE.md: present (1)
- `31. Broker-Process Architecture` in ROADMAP.md Progress Table: 3 occurrences (Progress Table row + Phase 31 entry header + cross-reference)
- `[To be planned]` placeholder for Phase 31: 0 (must be 0)
- All 6 Phase 31 plans `[x] 31-0[1-6]-PLAN.md`: 6 (must be exactly 6)
- Postscript 2 in debug session: 1 (>= 1 required)

***

## Commits (3 across this plan execution)

| Hash | Type | Subject |
|------|------|---------|
| `e8152f5c` | docs | docs(31-06): add Windows broker security-envelope paragraph to cookbook (SHELL-01 ✔ validated) |
| `a18ce2d0` | docs | docs(31-06): flip SHELL-01 to ✔ validated v2.3 Phase 31 in PROJECT/STATE/ROADMAP + debug postscript |
| `<this-commit>` | docs | docs(31-06): SUMMARY — Phase 31 closed via SHELL-01 ✔ validated v2.3 success path |

***

## Tasks 4 + 5 — explicitly skipped (FAILURE path not taken)

Task 4 (cookbook revert to Phase 30 final-state language) and Task 5 (PROJECT.md/STATE.md/ROADMAP.md flips with `✘ deferred to v3.0` per CONTEXT D-16) were explicitly skipped per the plan's branch logic. Plan 31-05 reported SUCCESS, so the failure-path tasks did not run.

CONTEXT D-16 (terminal failure rollback) and D-13 (timebox + ProcMon escalation) remain documented contingency contracts for any future regression on a different Windows version. They did NOT fire on the 2026-05-09 production run.

***

## A1 status — production-validated

RESEARCH Assumption A1 ("KernelBase ConClntInitialize skips the CSRSS ALPC connect when the child inherits the parent's console") is now both:
- PoC-validated (2026-05-08, quick-task `260508-m99-broker-process-poc-minimal-rust-binary-t`, commit `98d38ed9`)
- Production-validated (2026-05-09, Phase 31 Plan 31-05 field-test on user's Windows test box)

The end-to-end production binary chain (`nono.exe` → `nono-shell-broker.exe` → Low-IL shell child via `CreateProcessAsUserW(EXTENDED_STARTUPINFO_PRESENT)`) successfully reproduces the PoC's CSRSS-attach-skip mechanism on the production code path. Phase 30's failure-mode finding (the **direct** Low-IL primary token spawn from `nono.exe` triggers `STATUS_DLL_INIT_FAILED (0xC0000142)` at CSRSS attach time) remains valid for the direct path; the broker pattern is the supported workaround for the user-mode write-deny + ConPTY combination on Windows 10/11.

***

## D-14 single-box validation discipline (preserved through Plan 31-06)

Per CONTEXT D-14 (single-box validation on user's Windows test box, matching Phase 15 / Phase 30 / broker PoC ship pattern): the 2026-05-09 production validation extends the 2026-05-08 PoC validation onto the production binary chain. CI matrix expansion to additional Windows versions (Windows 10 22H2 / Windows 11 23H2 / Server 2022) remains a v2.4 follow-up per CONTEXT.md `<deferred>` block — explicitly NOT a Phase 31 gate.

***

## Next milestone-close action

`/gsd-complete-milestone v2.3` — once Phases 25-01 (RESL Unix backends; Linux + macOS hosts), 26-02 (PKGS-01 streaming + PKGS-04 auto-pull; Linux/macOS host), and 27.2 (audit-attestation test re-enablement; Linux/macOS host or Windows with Phase 27.1 NONO_TEST_HOME seam active) land on Linux/macOS host. Phase 31 is the v2.3 milestone's last Windows-host-required phase; the remaining v2.3 work is Linux/macOS-host execution.

The 5 v2.3 deferred items (REQ-AAH-01 Windows-host blockers, Windows test-harness HOME redirection — already addressed by Phase 27.1 — Upstream v0.41-v0.43 ingestion, AIPC G-04 wire-protocol tightening, `windows-squash` → `main` merge gated on PR-583) carry forward to v2.4 per ROADMAP.md backlog section. None block v2.3 closure.

***

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 1 — Bug] PROJECT.md Last-updated footer contained residual `⚠ Phase 31 candidate` reference**
- **Found during:** Task 3 acceptance-gate verification
- **Issue:** After flipping the active SHELL-01 row from `⚠ Phase 31 candidate` to `✔ validated v2.3 Phase 31`, the Last-updated footer at the bottom of PROJECT.md still narratively described the prior state ("SHELL-01 row revised from `✘ deferred to v3.0` to `⚠ Phase 31 candidate`"), so the acceptance grep for `⚠ Phase 31 candidate` count = 0 was failing with count = 1.
- **Fix:** Rewrote the entire Last-updated footer for 2026-05-09 closure with the same level of detail the 2026-05-08 footer documented Phase 30 close + PoC validation. Documents Phase 31's broker architecture, dispatch, OS-level enforcement, hook framing, audit-trail signer-consistency, and v2.3 progress (12 closed: 11 REQs + SHELL-01).
- **Files modified:** `.planning/PROJECT.md` (footer section, lines ~213-214)
- **Commit:** `a18ce2d0` (folded into the Task 3 atomic commit)

**2. [Rule 3 — Blocking issue] `docs/cli/development/` is gitignored — `git add` of tracked file rejected without `-f`**
- **Found during:** Task 2 commit attempt
- **Issue:** `git add docs/cli/development/windows-poc-handoff.mdx` returned "The following paths are ignored by one of your .gitignore files". The file IS tracked (`git ls-files` confirms), so the modification is legitimate, but the ignore rule shadows tracked files for unaware contributors.
- **Fix:** Used `git add -f docs/cli/development/windows-poc-handoff.mdx` (the file was confirmed tracked before forcing — `git ls-files` returned the path). Commit landed cleanly.
- **Files modified:** None directly; the file was already in the working tree.
- **Commit:** `e8152f5c` (Task 2)
- **Followup:** No action needed — the ignore rule is intentional (likely keeps fresh `target/`-like artifacts out of incidental adds), and tracked files are unaffected at runtime. Future executors hitting this should `git ls-files <path>` to confirm tracked status before forcing the add.

### Out-of-scope items

None. This plan is bookkeeping + docs only; no implementation surface was modified.

***

## Verification

| Check | Command | Result |
|-------|---------|--------|
| OUTCOME flag in 31-05-SUMMARY.md | `grep -cE "OUTCOME: SUCCESS\|OUTCOME: FAILURE" .planning/phases/31-broker-process-architecture-shell-01/31-05-SUMMARY.md` | 9 (>= 1 required; OUTCOME: SUCCESS confirmed) |
| Cookbook broker count | `grep -c "broker" docs/cli/development/windows-poc-handoff.mdx` | 17 (>= 3 required) |
| Cookbook Low-IL terminology | `grep -c "Low-IL\|Low Mandatory" docs/cli/development/windows-poc-handoff.mdx` | 10 (>= 1 required) |
| Cookbook OS-level primitive | `grep -c "NO_WRITE_UP\|mandatory.label" docs/cli/development/windows-poc-handoff.mdx` | 7 (>= 1 required) |
| Cookbook hook framing | `grep -c "defense.in.depth\|defense-in-depth\|hook" docs/cli/development/windows-poc-handoff.mdx` | 9 (>= 1 required) |
| Cookbook active deferred-to-v3.0 references | `grep -c "deferred to v3.0\|deferred-to-v3" docs/cli/development/windows-poc-handoff.mdx` | 0 (must be 0) |
| PROJECT.md SHELL-01 validated v2.3 Phase 31 | `grep -c "validated v2.3 Phase 31" .planning/PROJECT.md` | 2 (>= 1 required) |
| PROJECT.md Phase 31 candidate (must be 0) | `grep -c "⚠ Phase 31 candidate" .planning/PROJECT.md` | 0 (must be 0) |
| STATE.md Phase 31 SHIPPED entry | `grep -c "Phase 31.*SHIPPED" .planning/STATE.md` | 1 (>= 1 required) |
| ROADMAP.md Progress Table row | `grep -E "^\| 31\. Broker-Process Architecture" .planning/ROADMAP.md` | `\| 31. Broker-Process Architecture (SHELL-01) \| v2.3 \| 6/6 \| Complete \| 2026-05-09 \|` |
| ROADMAP.md all 6 plans checked | `grep -cE "\[x\] 31-0[1-6]-PLAN.md" .planning/ROADMAP.md` | 6 (must be exactly 6) |
| Debug session Postscript 2 | `grep -c "Postscript 2.*Phase 31 closure" .planning/debug/resolved/nono-shell-status-dll-init-failed.md` | 1 (>= 1 required) |

***

## Self-Check: PASSED

- `docs/cli/development/windows-poc-handoff.mdx` security-envelope section present (verified by all 5 acceptance grep gates).
- `.planning/PROJECT.md` SHELL-01 row reflects ✔ validated v2.3 Phase 31; Last-updated footer rewritten for 2026-05-09; zero residual `⚠ Phase 31 candidate` references.
- `.planning/STATE.md` Roadmap Evolution timeline contains 2026-05-09 Phase 31 SHIPPED entry following the existing 2026-05-08 phase-creation entry.
- `.planning/ROADMAP.md` Progress Table row updated to `6/6 | Complete | 2026-05-09`; Phase 31 entry body populated with all 6 checked plans + Goal/Requirements/Depends-on/Success-Criteria PASSED sections; zero `[To be planned]` placeholders.
- `.planning/debug/resolved/nono-shell-status-dll-init-failed.md` Postscript 2 appended at end; earlier Resolution section + Postscript 1 preserved byte-identical.
- All 3 commits referenced in this SUMMARY (`e8152f5c`, `a18ce2d0`, this commit) will exist in git history after this SUMMARY commit lands.

Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
