---
phase: 30-windows-nono-shell-architecture
plan: 03
subsystem: field-smoke-harness
tags: [windows, powershell, field-smoke, tui-verification, mandatory-integrity-control, write-deny, harness]

# Dependency graph
requires:
  - phase: 30
    provides: "Plan 30-02 token-cascade implementation (WindowsTokenArm::LowIlPrimary + Low-IL supervised shell path)"
provides:
  - "scripts/test-windows-shell-write-deny.ps1 — live-shell harness driving Out-File outside grant set; asserts UnauthorizedAccessException + Get-Content read-still-works companion; D-09 leaked-label clear prelude"
  - "scripts/test-windows-shell-tui.ps1 — interactive TUI checklist runbook with PASS/FAIL prompts at each step; Pitfall 2 (ConPTY+IL-mismatch) pinned in operator instructions; cmd.exe variant gated behind -IncludeCmd switch"
  - ".planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md — smoke-gate evidence table + decision matrix + expected-log-markers + operator log for Plan 30-04"
affects: [field-smoke-harness, acceptance-criteria-d05-d06, plan-30-04-input]

# Tech tracking
tech-stack:
  added: ["PowerShell 5.1 manual harness pattern for live-shell acceptance testing (no codebase analog existed; closest sibling scripts/windows-test-harness.ps1 is a cargo-test orchestrator, not an interactive-shell driver)"]
  patterns: ["Sentinel exit code 42 for PASS (write-blocked) vs 1 for FAIL (write-succeeded) vs 2 for INDETERMINATE — chosen to avoid false-pass on default shell exit 0; Tee-Object streaming for capturing child-connected-to-pipe log markers; Read-PassFail loop with regex matching for robust operator input"]

key-files:
  created:
    - scripts/test-windows-shell-write-deny.ps1
    - scripts/test-windows-shell-tui.ps1
    - .planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md
    - .planning/phases/30-windows-nono-shell-architecture/30-03-SUMMARY.md
  modified: []

key-decisions:
  - "$ErrorActionPreference = 'Continue' in write-deny harness (deliberate divergence from sibling scripts/windows-test-harness.ps1 which uses 'Stop'). Rationale: we WANT non-zero shell exits from the inner nono shell to surface in $LASTEXITCODE; 'Stop' would terminate the outer harness on the first failed cmdlet, masking the PASS/FAIL signal."
  - "Sentinel value 42 chosen for PASS (not 0) — 0 is the default shell exit code from many edge cases including Stop-driven exits. 42 is unambiguous: it means the injected script explicitly ran exit 42 after confirming Test-Path returned false."
  - "D-09 leaked-label clear prelude is HYGIENE ONLY — not a fix for the AppliedLabelsGuard Drop lifecycle bug (separate debug session nono-labels-guard-leak). The icacls /setintegritylevel '(NX)Medium' calls in the harness restore the clean-box state so field smoke avoids false-positive on stale labels from prior nono crashes."
  - "TUI runbook (test-windows-shell-tui.ps1) instructs operator to run nono shell in ANOTHER terminal window. Rationale: the harness cannot drive an interactive shell from inside its own ConPTY — PowerShell-as-harness cannot pipe stdin into a child PowerShell that owns its own ConPTY. The outer script only captures operator decisions, not the inner PTY session."
  - "Pitfall 2 (Microsoft-documented ConPTY+IL-mismatch failure mode) pinned verbatim in test-windows-shell-tui.ps1's operator instructions. Future maintainers see the rationale for why steps (3)-(5) are all mandatory — a clean launch (step 1) can silently fail at interactive input (step 5)."

patterns-established:
  - "Pattern: Three-outcome sentinel exit code for live-shell acceptance harness (42=PASS, 1=FAIL, 2=INDETERMINATE) — avoids false-pass on default-exit ambiguity"
  - "Pattern: Leaked-label clear prelude as skippable isolation hygiene in field-smoke harness (D-09 idiom)"
  - "Pattern: Read-PassFail function with regex match accepts 'p', 'pass', 'PASS' variants for robust operator input in manual runbooks"
  - "Pattern: Smoke-gate evidence table (Token | PTY | Detached | Expected | Observed) from Phase 15 windows-supervised-exec-cascade.md carried forward as Phase 30 runbook format"

requirements-completed: [D-05, D-06, D-09]

# Metrics
duration: ~25 min
completed: 2026-05-07
---

# Phase 30 Plan 03: Windows nono shell Field-Smoke Harness Summary

**Three new files created — live-shell write-deny harness (`scripts/test-windows-shell-write-deny.ps1`) with D-09 leaked-label clear prelude + read-still-works companion, interactive TUI checklist runbook (`scripts/test-windows-shell-tui.ps1`) with RESEARCH Pitfall 2 pinned in operator instructions, and field-smoke runbook + evidence table (`30-FIELD-SMOKE.md`) mirroring Phase 15 shape — giving Plan 30-04 everything needed to run field smoke on the Windows test box and decide the Wave 1 success vs Wave 2 pivot.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-05-07
- **Completed:** 2026-05-07
- **Tasks:** 3
- **Files created:** 3 harness/runbook files + this SUMMARY

## Accomplishments

- `scripts/test-windows-shell-write-deny.ps1` (222 lines) implements the full D-06 acceptance harness: (1) optional `cargo build -p nono-cli --release --target x86_64-pc-windows-msvc` build step; (2) skippable D-09 leaked-label clear prelude (icacls /setintegritylevel "(NX)Medium" on 9 known leaked paths); (3) Acceptance #3 -- injects `Out-File ~/Desktop/nono-acceptance3.txt` into sandboxed PowerShell and checks `Test-Path` to distinguish write-blocked (exit 42 PASS) from write-succeeded (exit 1 FAIL) from unexpected-shell-exit (exit 2 INDETERMINATE); (4) Acceptance #4 -- injects `Get-Content ~/.claude/claude.json -TotalCount 1` and asserts exit 42 PASS or 99 file-missing (non-fatal) or 1 FAIL; (5) Summary log and overall exit code (0=all-pass, 1=any-fail, 2=indeterminate). `Tee-Object -Variable` streaming captures `child connected to pipe` log markers and `label guard: skipping apply + revert` D-09 warnings.

- `scripts/test-windows-shell-tui.ps1` (155 lines) sequences the manual TUI checklist for a human operator. Key design: `Invoke-TuiChecklist` function accepts `-Shell` and `-Label` parameters so PowerShell 5.1 (default) and cmd.exe (`-IncludeCmd` switch, per RESEARCH Open Question 3) share identical sequencing. Four PASS/FAIL prompts per shell: (1-2) launch without 0xC0000142, (3-4) claude TUI renders with alt-screen + cursor + no leakage, (5) raw-mode input + response renders, (6-7) /quit + exit clean. RESEARCH Pitfall 2 (Microsoft Q&A: ConPTY integrity-mismatch = silent input drop) pinned verbatim in the operator instructions so future engineers know why all four prompts are mandatory.

- `.planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md` mirrors the Phase 15 `windows-supervised-exec-cascade.md` smoke-gate shape with: pre-test hygiene checklist (5 steps including D-09 label clear and Wave 1 binary verification); acceptance criteria table mapping each of Acceptance #1-#4 to harness command + expected result + gate mechanism; smoke-gate evidence table (5 token/PTY/detached rows including the new Low-IL primary row); expected-log-markers section (healthy vs failure); decision matrix (5 rows: 4 success/partial-success paths + Wave 2 trigger conditions); operator log table for Plan 30-04 to fill; references to Plans 30-02 through 30-05.

## Task Commits

Per the plan's `<output>` section: "Three new files created. None committed yet — Plan 30-04 commits them along with field-smoke evidence." The executor protocol requires per-task commits; however, Bash tool access was denied in this execution environment, preventing git operations. The three content files are present on disk in the worktree working tree and ready for staging.

NOTE: Bash was denied during this execution. The worktree branch safety assertion could not be run. Files are created and verified via Read/Write/Grep tools but no git commits were made. Plan 30-04 or the orchestrator should stage and commit these files:
  - scripts/test-windows-shell-write-deny.ps1
  - scripts/test-windows-shell-tui.ps1
  - .planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md
  - .planning/phases/30-windows-nono-shell-architecture/30-03-SUMMARY.md

## Deviations from Plan

### Execution Environment Constraint

**[Rule 3 - Blocking Issue] Bash tool denied — no git commits made**
- **Found during:** Task 1 commit step
- **Issue:** The Bash tool returned "Permission to use Bash has been denied" — not a script failure, but a tool-level permission gate. Without Bash, the worktree HEAD safety assertion cannot be run, git operations cannot be performed.
- **Impact:** Three task files and this SUMMARY exist on disk but are not committed. No commits were staged.
- **Resolution required:** The orchestrator or Plan 30-04's executor must stage and commit the four files above before proceeding with field smoke execution.
- **Note:** The plan's `<output>` section already anticipated "None committed yet (Plan 30-04 commits them along with field-smoke evidence)" — this aligns with the actual state.

## Acceptance Criteria Verification

All grep acceptance criteria passed:

| Check | Result |
|-------|--------|
| `exit 42` in write-deny harness | 2 matches (PASS) |
| `shell --profile claude-code --allow-cwd` in write-deny harness | 4 matches (PASS) |
| `ErrorActionPreference = 'Continue'` in write-deny harness | 1 match (PASS) |
| `icacls.*setintegritylevel` in write-deny harness | 1 match (PASS) |
| `claude.json` in write-deny harness | 4 matches (PASS) |
| `Read-PassFail` in TUI harness | 5 matches (function + 4 call sites) (PASS) |
| `shell --profile claude-code` in TUI harness | 4 matches (PASS) |
| `Pitfall 2\|integrity.?mismatch\|silent input` in TUI harness | 4 matches (PASS) |
| `IncludeCmd` in TUI harness | 3 matches (PASS) |
| `Acceptance #1\|#2\|#3\|#4` in FIELD-SMOKE.md | 7 matches (PASS) |
| `Wave 2 trigger` in FIELD-SMOKE.md | 4 matches (PASS) |
| `child connected to pipe` in FIELD-SMOKE.md | 1 match (PASS) |
| `STATUS_DLL_INIT_FAILED\|0xC0000142` in FIELD-SMOKE.md | 4 matches (PASS) |
| `test-windows-shell-write-deny.ps1` in FIELD-SMOKE.md | present (PASS) |
| `test-windows-shell-tui.ps1` in FIELD-SMOKE.md | present (PASS) |

## Known Stubs

None. The harness scripts are complete as specified. The `<operator fills>` rows in 30-FIELD-SMOKE.md's smoke-gate evidence table are intentional — Plan 30-04 fills them during actual field execution.

## Self-Check

Files exist on disk:
- `scripts/test-windows-shell-write-deny.ps1` — FOUND
- `scripts/test-windows-shell-tui.ps1` — FOUND  
- `.planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md` — FOUND
- `.planning/phases/30-windows-nono-shell-architecture/30-03-SUMMARY.md` — this file

Commits exist: NONE (Bash denied; see Deviations section)

## Self-Check: FAILED

No commits were made due to Bash tool permission denial. Files are on disk and verified but uncommitted. Orchestrator must commit before proceeding.
