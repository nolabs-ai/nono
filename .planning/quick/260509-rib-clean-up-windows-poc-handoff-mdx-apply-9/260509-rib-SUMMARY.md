---
phase: 260509-rib-clean-up-windows-poc-handoff-mdx-apply-9
plan: 01
type: execute
date: 2026-05-09
files_modified:
  - docs/cli/development/windows-poc-handoff.mdx
files_created:
  - .planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md
requirements:
  - DOCS-WPOC-FIX-01
  - DOCS-WPOC-FIX-02
  - DOCS-WPOC-FIX-03
  - DOCS-WPOC-FIX-04
  - DOCS-WPOC-FIX-05
  - DOCS-WPOC-FIX-06
  - DOCS-WPOC-FIX-07
  - DOCS-WPOC-FIX-08
  - DOCS-WPOC-FIX-09
---

# 260509-rib — Windows POC Handoff MDX cleanup (9 fixes)

One-liner: applied 9 pre-verified review fixes to `docs/cli/development/windows-poc-handoff.mdx` — 3 structural (PTY framing, fail-closed gate anchor, Phase 31 freshness) plus 6 polish (dry-run example, symlink cell, audit verification, References reorg, triage payload, machine-MSI Warning).

## What changed

Single-file MDX docs edit. No source code touched.

| # | Fix | Summary |
|---|---|---|
| 1 | Stale PTY framing | Replaced "conservative fix at the time disabled PTY allocation entirely" with the Phase-15-aware version that distinguishes detached supervised path (PTY disabled) from interactive `nono shell` (allocates ConPTY post-Phase 31 via the broker). |
| 2 | Step 5 must-fail anchor | Added an "Expected stderr (paraphrase)" block immediately after the two `nono run --network-profile` / `--allow-domain` example commands, quoting the run-time WFP-missing diagnostic and instructing operators to grep on the exact anchor string `This request remains fail-closed until WFP activation is implemented`. |
| 3 | Phase 31 freshness note | Inserted a blockquote `> **Freshness note:** ...` under the security-envelope section header, BEFORE `### Token shape`, noting same-day validation (2026-05-09), minimal soak time, and the recommendation to defer handoff 24-48h. |
| 4 | Dry-run example uses `claude --version` | Replaced the bare `claude` invocation in the dry-run example with `claude --version`. Per the plan's must-have ("No references to bare `claude` as a dry-run example remain"), updated BOTH dry-run sites: Step 4's `nono run --dry-run --profile claude-code -- claude` and Step 5's `nono run --dry-run --allow . --read $env:USERPROFILE\.claude -- claude`. Also updated the matching expected-output preview line `$ claude` → `$ claude --version` for internal consistency. |
| 5 | Step 6 symlink-cell update | Replaced the cell value with the version that mentions BOTH "Enable Developer Mode" AND "run `nono setup` once as admin" as alternatives. |
| 6 | Audit-trail verification paragraph | Appended an operator-visible verification paragraph to the audit-trail section. **Substituted real flags** — see "Audit flag confirmation" below. |
| 7 | References → Operator references (internal) | Renamed the `### References` heading inside the security-envelope section to `### Operator references (internal)` and added the one-line preamble blockquote about the references being internal-only. |
| 8 | Triage payload cell expansion | Replaced the Step 6 "Triage payload on a bug" cell with the expanded list including `claude --version` and Windows build commands (`(Get-CimInstance Win32_OperatingSystem).BuildNumber` / `[Environment]::OSVersion.Version.Build`). |
| 9 | Machine-MSI `<Warning>` rewrite | Replaced the entire `<Warning>` block per Fact B: the binary IS produced by `make build-release-cli`, but the MSI script defaults `-ServiceBinaryPath` to empty, so a machine MSI built without that flag installs but never registers the WFP service. New text instructs operators to pass `-ServiceBinaryPath .\target\x86_64-pc-windows-msvc\release\nono-wfp-service.exe` explicitly if doing a machine install (and recommends sticking with `-Scope user` for the POC). |

## Verified facts used (orchestrator-pre-verified — not re-verified by executor)

- **Fact A — Run-time WFP fail-closed diagnostic** (used in Fix #2): exact anchor string `This request remains fail-closed until WFP activation is implemented` from `crates/nono-cli/src/exec_strategy_windows/network.rs:412-451`. Transcribed verbatim.
- **Fact B — machine-MSI ServiceBinaryPath default** (used in Fix #9): `nono-wfp-service.exe` IS produced by `make build-release-cli` (CI proves this at `.github/workflows/ci.yml:336/343`); the actual gap is `scripts/build-windows-msi.ps1`'s `ServiceBinaryPath` default of `""` and the line-178 conditional that only fires when explicitly passed. Transcribed verbatim.

## Audit flag confirmation (Fix #6)

The plan's Fix #6 verbatim text proposed `nono audit --tail 5` and `nono audit --json`, with an explicit guardrail: "Confirm `nono audit --tail` flag exists ... If `--tail` doesn't exist, substitute whatever the actual recent-entries flag is, or fall back to plain `nono audit`. Do not invent flags."

I verified the actual CLI surface by reading `crates/nono-cli/src/cli.rs`:

- The `audit` command is a parent command with required subcommands: `list`, `show`, `verify`, `cleanup` (`AuditCommands` enum, lines 2314-2334). Bare `nono audit` is NOT a valid invocation — it requires a subcommand.
- `AuditListArgs` (lines 2338-2370): the recent-entries flag is `--recent N` (NOT `--tail`). `--json` exists for structured output.
- `AuditShowArgs` (lines 2374-2385): `--json` exists for per-session detail.

**Substitutions applied in the doc:**

- `nono audit --tail 5` → `nono audit list --recent 5` (real flag name, plus required `list` subcommand).
- `nono audit --json` → `nono audit list --json` (real flag, plus required subcommand). Also added `nono audit show <session-id> --json` for per-session detail since that's the more precise verification target.

The substitutions preserve the *intent* of Fix #6 (operator-visible, post-run, recent-entries verification with structured-output option) while using only real flags. No invented flags.

## Verification

All positive grep checks pass:

```
Fix #2 anchor count: 2          (>= 1 required)
Fix #1 Phase-15 fix count: 1    (>= 1 required)
Phase 31 count: 10              (>= 1 required)
Fix #3 Freshness note count: 1  (>= 1 required)
Fix #4+#8 claude --version: 10  (>= 2 required)
Fix #7 Operator references (internal) count: 1  (>= 1 required)
Fix #8 Win32_OperatingSystem count: 1           (>= 1 required)
Fix #9 ServiceBinaryPath count: 1               (>= 1 required)
Fix #6 nono audit count: 1                      (>= 1 required)
Fix #5 "once as admin" present in Step 6 symlink cell: PASS
```

All negative grep checks pass:

```
OK: 'release lane.*does not produce' false claim gone (Fix #9)
OK: bare '-- claude' line-end gone (Fix #4)
OK: stale "PTY allocation entirely on the Windows supervised path" framing gone (Fix #1)
```

`git status --porcelain` shows exactly:

```
 M docs/cli/development/windows-poc-handoff.mdx
?? .planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/
```

No source files (`.rs`, `.toml`, `.ps1`, `.sh`) modified. No other `.mdx` files modified.

## Out of scope / follow-ups

- **BrokerPath missing from Step 1 Option C MSI invocation.** Per the plan's `<verified_facts>` side note (Fact B context): `scripts/build-windows-msi.ps1` made `-BrokerPath` (for `nono-shell-broker.exe`) Mandatory in Phase 31, but the cookbook's Step 1 Option C example only passes `-BinaryPath`, `-VersionTag`, `-Scope`, `-OutputDir`. A user copy-pasting the example will hit a Mandatory-arg parse error from PowerShell. **Not in scope for the user's 9 fixes; flagged for a future docs pass.** Quick-fix would be: add `-BrokerPath .\target\x86_64-pc-windows-msvc\release\nono-shell-broker.exe \`` to the example invocation.
- **Audit flag substitution caveat.** The substitution from `nono audit --tail 5` → `nono audit list --recent 5` is correct for the current CLI, but Fix #6's verbatim text in the plan (and any downstream copies) still refers to `--tail`. If the team prefers to stay close to the plan-text, a future change could rename the CLI flag from `--recent` to `--tail`. Not recommended (the rename has migration cost; the substitution here is one-line and clearly documented).
- **Audit subcommand-required UX.** `nono audit` (no subcommand) prints help and exits non-zero. The doc text directs operators to `nono audit list --recent 5`, which is the intended UX, but a future polish could add a default subcommand alias.

## Self-Check

- [x] `docs/cli/development/windows-poc-handoff.mdx` exists and contains all 9 fixes — verified via positive greps above.
- [x] `.planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md` exists — this file.
- [x] No source code modified — `git status --porcelain` shows only the target `.mdx` plus the new `.planning/quick/...` directory.
- [x] All positive verify greps return >=1 for the required anchors.
- [x] All negative verify greps return 0 (no stale framing, no bare `-- claude`, no "release lane does not produce" claim).
- [x] Audit flag substitution documented with rationale.
- [x] BrokerPath follow-up flagged.

## Self-Check: PASSED

## Commit handling

The orchestrator owns the single atomic commit per Step 8 of the quick workflow. The executor did NOT run `git commit`. Files staged for the orchestrator's commit:

- `docs/cli/development/windows-poc-handoff.mdx` (modified)
- `.planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-PLAN.md` (untracked, created by planner)
- `.planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md` (untracked, this file)
