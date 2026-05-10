---
phase: 260509-rib-clean-up-windows-poc-handoff-mdx-apply-9
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - docs/cli/development/windows-poc-handoff.mdx
autonomous: true
requirements:
  - DOCS-WPOC-FIX-01  # Stale framing (PTY detached vs interactive)
  - DOCS-WPOC-FIX-02  # Step 5 expected-string anchor for fail-closed gate
  - DOCS-WPOC-FIX-03  # Phase 31 freshness note (validated same-day)
  - DOCS-WPOC-FIX-04  # Dry-run example uses claude --version (not bare TUI)
  - DOCS-WPOC-FIX-05  # Step 6 symlink cell mentions both Dev Mode and nono setup
  - DOCS-WPOC-FIX-06  # Audit-trail operator-visible verification command
  - DOCS-WPOC-FIX-07  # References section renamed + internal-only preamble
  - DOCS-WPOC-FIX-08  # Triage payload adds claude --version + Windows build
  - DOCS-WPOC-FIX-09  # Machine-MSI warning rewritten per Fact B

must_haves:
  truths:
    - "All 9 verified review fixes are applied to windows-poc-handoff.mdx"
    - "Stale PTY framing (Fix #1) is replaced with the Phase-31-aware version distinguishing detached vs interactive"
    - "Step 5 (Fix #2) includes the grep-stable anchor 'This request remains fail-closed until WFP activation is implemented'"
    - "Phase 31 freshness note (Fix #3) appears under the security-envelope header before 'Token shape'"
    - "Fix #4 changes the bare `claude` invocation in the dry-run example to `claude --version`"
    - "Fix #5 cell mentions BOTH Developer Mode AND `nono setup` as admin"
    - "Fix #6 appends an operator-visible verification paragraph using a real `nono audit` flag (not invented)"
    - "Fix #7 renames `### References` to `### Operator references (internal)` and adds the internal-only preamble"
    - "Fix #8 cell adds `claude --version` and Windows build number to the triage payload"
    - "Fix #9 rewrites the machine-MSI <Warning> block to reflect Fact B (binary IS produced; gap is the empty-default ServiceBinaryPath)"
    - "No claims about machine-MSI 'release lane does not produce that binary' remain in the file"
    - "No references to bare `claude` as a dry-run example remain"
  artifacts:
    - path: "docs/cli/development/windows-poc-handoff.mdx"
      provides: "Windows POC handoff cookbook with all 9 fixes applied"
      contains: "This request remains fail-closed until WFP activation is implemented"
    - path: ".planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md"
      provides: "Execution summary listing each of the 9 fixes applied + the BrokerPath follow-up flag"
  key_links:
    - from: "docs/cli/development/windows-poc-handoff.mdx (Step 5 must-fail block)"
      to: "Run-time diagnostic in crates/nono-cli/src/exec_strategy_windows/network.rs:412-451"
      via: "Verbatim quoted anchor string"
      pattern: "This request remains fail-closed until WFP activation is implemented"
    - from: "docs/cli/development/windows-poc-handoff.mdx (Fix #9 machine-MSI warning)"
      to: "scripts/build-windows-msi.ps1 ServiceBinaryPath default behavior"
      via: "Documented operator instruction to pass -ServiceBinaryPath explicitly"
      pattern: "-ServiceBinaryPath"
---

<objective>
Apply 9 pre-verified review fixes to `docs/cli/development/windows-poc-handoff.mdx` in a single atomic edit pass. The fixes correct stale framing, add operator-visible verification anchors, rewrite a factually-wrong machine-MSI warning per verified facts, and tighten the audit/triage guidance. This is pure docs cleanup — no code changes.

Purpose: The Windows POC handoff cookbook is the day-1 onboarding doc for pilot operators. The 9 fixes (3 structural, 6 smaller) eliminate one factual error (Fix #9), one self-contradictory paragraph (Fix #1), and a missing fail-closed-gate verification anchor (Fix #2), plus six smaller polish items. Without these fixes, operators may train wrong muscle memory (bare `claude` TUI in dry-run), miss the WFP service registration step on machine MSI builds, and have no way to confirm the fail-closed gate is functioning.

Output: A single commit modifying only `docs/cli/development/windows-poc-handoff.mdx`, plus a SUMMARY.md listing each fix applied and one follow-up flag (BrokerPath missing from Step 1 Option C — out of scope but worth noting).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@CLAUDE.md
@docs/cli/development/windows-poc-handoff.mdx

<verified_facts>
The orchestrator pre-verified the following. The executor MUST NOT re-verify these against the codebase — pass them through directly.

**Fact A — exact run-time diagnostic** (used in Fix #2):
Source: `crates/nono-cli/src/exec_strategy_windows/network.rs:412-415, 446-451`

> "Windows WFP runtime activation is required for {target} but the WFP service binary `{path}` is missing from this build output. Run `cargo build -p nono-cli --bins` first ({backend_summary}). This request remains fail-closed until WFP activation is implemented."

The grep-stable anchor string is: **`This request remains fail-closed until WFP activation is implemented`**

**Fact B — machine-MSI ServiceBinaryPath behavior** (used in Fix #9):
- `nono-wfp-service.exe` IS produced by `make build-release-cli` (auto-discovered from `crates/nono-cli/src/bin/nono-wfp-service.rs`).
- CI proof: `.github/workflows/ci.yml:336` runs `cargo build --release -p nono-cli`; line 343 validates `target\release\nono-wfp-service.exe`.
- The actual gap is in `scripts/build-windows-msi.ps1`:
  - `BinaryPath` (nono.exe) — Mandatory
  - `BrokerPath` (nono-shell-broker.exe) — Mandatory (since Phase 31)
  - `ServiceBinaryPath` — Optional, default `""` (line 22)
  - Machine-scope service registration only fires when `ServiceBinaryPath` is explicitly passed (line 178)
- Net effect: a machine MSI built without `-ServiceBinaryPath` succeeds but never registers the WFP service.

**Side note (NOT a fix in scope, but flag in SUMMARY.md):**
Step 1 Option C's invocation is missing `-BrokerPath`, which became Mandatory in Phase 31. The user's 9 fixes don't include this — surface it as a follow-up item in the SUMMARY.md "Out of scope / follow-ups" section.
</verified_facts>

<the_9_fixes_verbatim>

**STRUCTURAL (3):**

**Fix #1 — Stale framing on the PTY paragraph.**
Current text reads: *"The conservative fix at the time disabled PTY allocation entirely on the Windows supervised path. Restoring PTY allocation for non-detached `nono run` is feasible but needs a regression-proof debug session — out of scope for the POC cookbook."*

Replace with:

> "The conservative Phase-15 fix disabled PTY allocation on the **detached** Windows supervised path, where `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE + DETACHED_PROCESS` crashed grandchildren. Interactive `nono shell` does allocate ConPTY post-Phase 31 via the broker process — see security envelope below."

**Fix #2 — Step 5 "Must-fail loudly" needs an expected-string anchor.**
Add immediately after the two `nono run --network-profile` / `--allow-domain` example commands:

> Expected stderr (paraphrase — exact text varies by target/path/backend summary):
>
> ```text
> Windows WFP runtime activation is required for <target> but the WFP service binary
> `<path>` is missing from this build output. Run `cargo build -p nono-cli --bins` first
> (<backend_summary>). This request remains fail-closed until WFP activation is implemented.
> ```
>
> Grep operators can anchor on: `This request remains fail-closed until WFP activation is implemented`. If you see exit code 0 and no stderr line containing that anchor, the fail-closed gate has regressed — stop the POC.

**Fix #3 — Phase 31 freshness note.**
Under the security-envelope section header (which says "(Phase 31, validated 2026-05-09)"), add — BEFORE "### Token shape":

> > **Freshness note:** Phase 31 production validation completed on 2026-05-09 (the day this cookbook was written). The broker path has minimal soak time on `main`. Day-1 POC users should report any anomalies promptly via the [Windows Preview Pilot § Debugging Inputs](/cli/development/windows-preview-pilot#debugging-inputs) triage payload, and operators should consider deferring the actual handoff by 24-48h to allow follow-up patches to land.

**SMALLER (6):**

**Fix #4 — Dry-run example uses bare `claude` (TUI agent).**
Change:

```powershell
nono run --dry-run --allow . --read $env:USERPROFILE\.claude -- claude
```

to:

```powershell
nono run --dry-run --allow . --read $env:USERPROFILE\.claude -- claude --version
```

**Fix #5 — Step 6 table "First-time symlink warning" cell.**
Replace the cell value with:

> Enable Developer Mode (`Settings → System → For developers`) **or** run `nono setup` once as admin to create the symlink. Benign if skipped, but token refresh writes leak outside `~/.claude\`.

**Fix #6 — Audit-trail operator-visible verification.**
Append to the audit-trail section:

> Operators can verify post-run with `nono audit --tail 5` (or `nono audit --json` for structured output) to see the recorded `signer_subject` and SHA-1 thumbprint per launch. If the audit trail is empty after a `nono shell` invocation, the AUDC chain-walker is misconfigured — out of scope for the POC smoke but worth flagging in the triage payload.

> **IMPORTANT for executor:** Confirm `nono audit --tail` flag exists by running `nono audit --help` (or grepping for the audit subcommand definition in `crates/nono-cli/src/cli.rs`). If `--tail` doesn't exist, substitute whatever the actual recent-entries flag is, or fall back to plain `nono audit`. **Do not invent flags.** If `--json` doesn't exist either, drop the parenthetical. The verbatim text above is the *intent*; the exact flags must match the actual CLI.

**Fix #7 — References section reorg.**
Rename the heading inside the security-envelope section from `### References` to `### Operator references (internal)` and add a one-line preamble before the list:

> > These references live in the GSD `.planning/` tree; they are operator-internal and are not part of the POC user handoff bundle. Listed here for nono-team triage and history.

**Fix #8 — Step 6 table "Triage payload on a bug" cell.**
Replace the cell value with:

> Exact command line, full stdout, full stderr, `nono --version`, `claude --version`, `nono setup --check-only` output, Windows build (`(Get-CimInstance Win32_OperatingSystem).BuildNumber` or `[Environment]::OSVersion.Version.Build`), whether WFP was reported missing.

**Fix #9 — Machine-MSI `<Warning>` block (per Fact B).**
Replace the entire current `<Warning>` block with:

```mdx
<Warning>
The **machine** MSI (`-Scope machine`) registers `nono-wfp-service` only when you explicitly pass `-ServiceBinaryPath .\target\x86_64-pc-windows-msvc\release\nono-wfp-service.exe`. The release build DOES produce that binary (`make build-release-cli` → `cargo build --release -p nono-cli`), but the MSI script defaults `-ServiceBinaryPath` to empty — so a machine MSI built without that flag installs successfully but never registers the WFP service. Stay on `-Scope user` for the POC; per-user is the right choice anyway (no admin install, no service to undo).
</Warning>
```

</the_9_fixes_verbatim>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Apply all 9 review fixes to windows-poc-handoff.mdx</name>
  <files>docs/cli/development/windows-poc-handoff.mdx</files>
  <action>
Apply all 9 fixes specified in the `<the_9_fixes_verbatim>` block above to `docs/cli/development/windows-poc-handoff.mdx` in a single edit pass. Constraints from the planning prompt:

1. **Read the current file first** with the Read tool. The line numbers in the fix descriptions are from the user's review snapshot and may have drifted — DO NOT trust them. Use the **quoted phrases / content anchors** in each fix description as the source of truth for locating each edit site.

2. **For each Edit, the `old_string` MUST come from the current file** (per the Read), not copy-pasted from this plan. Use Grep/Read to find the actual current text, then craft each Edit so `old_string` is unique and unambiguous within the file.

3. **Order of operations** (suggested, to keep edits localized):
   - Fix #1 (PTY paragraph): grep for "conservative fix at the time disabled PTY allocation" — that paragraph gets the Phase-15/Phase-31 rewrite.
   - Fix #2 (Step 5 anchor): grep for "must-fail" or the two `nono run --network-profile`/`--allow-domain` example commands; insert the expected-stderr block immediately after them.
   - Fix #3 (freshness note): grep for "Phase 31, validated 2026-05-09" header; insert the freshness blockquote BEFORE "### Token shape".
   - Fix #4 (dry-run): grep for `nono run --dry-run --allow . --read $env:USERPROFILE\.claude -- claude` (the bare `claude` ending) and append ` --version` to that one invocation only.
   - Fix #5 (symlink cell): grep for the Step 6 table row about "symlink warning" / "Developer Mode" — replace the right-hand cell with the new text including the `nono setup` admin alternative.
   - Fix #6 (audit-trail): grep for the audit-trail section and append the verification paragraph. **Before writing the final text, run `nono audit --help` (or read `crates/nono-cli/src/cli.rs` for the audit subcommand) to confirm `--tail` and `--json` exist. If either flag is wrong, substitute the actual flag name or drop that part. Do not invent flags.**
   - Fix #7 (References reorg): grep for `### References` inside the security-envelope section; rename heading and add the one-line internal-only preamble.
   - Fix #8 (triage payload cell): grep for the Step 6 table row about "Triage payload" — replace the right-hand cell with the expanded version including `claude --version` and the Windows build number commands.
   - Fix #9 (machine-MSI Warning): grep for the existing `<Warning>` block near the MSI scope guidance — replace the ENTIRE `<Warning>...</Warning>` block with the new version per Fact B.

4. **No code changes.** This is purely an MDX docs edit. Do not touch any `.rs`, `.toml`, `.ps1`, `.sh`, or other source files.

5. **Per CLAUDE.md / Fact B side note:** After all edits land, write the SUMMARY.md (next task). The SUMMARY must include an "Out of scope / follow-ups" section noting that Step 1 Option C's MSI invocation is missing the now-Mandatory `-BrokerPath` argument (Phase 31) — this is NOT in the user's 9 fixes but should be tracked.

6. **Verbatim quoted text in the fix descriptions IS the source of truth for the new content.** When in doubt about wording, follow the planning prompt's quoted text exactly. Backtick code spans, blockquote markers, bold/italic, and `<Warning>` tags must match.

7. After all 9 edits, do a final pass:
   - Grep the file for `This request remains fail-closed until WFP activation is implemented` → must be present (Fix #2).
   - Grep for `### References` (case-sensitive, exact) → should NOT appear inside the security-envelope section anymore (Fix #7 renamed it). Note: `### References` may legitimately appear elsewhere in the doc (e.g. a top-level References section) — only the security-envelope occurrence is renamed.
   - Grep for `-- claude$` (line ending with bare `claude`) → should NOT match the dry-run example anymore (Fix #4).
   - Grep for `release lane` and `does not produce that binary` → should NOT match anymore (Fix #9 removed the false claim).
   - Grep for `Phase-15 fix` AND `Phase 31` → both should be present in the PTY paragraph (Fix #1).
  </action>
  <verify>
    <automated>
      cd C:/Users/OMack/Nono &amp;&amp; \
      grep -c "This request remains fail-closed until WFP activation is implemented" docs/cli/development/windows-poc-handoff.mdx | grep -v "^0$" &amp;&amp; \
      grep -c "Phase-15 fix" docs/cli/development/windows-poc-handoff.mdx | grep -v "^0$" &amp;&amp; \
      grep -c "Operator references (internal)" docs/cli/development/windows-poc-handoff.mdx | grep -v "^0$" &amp;&amp; \
      grep -c "claude --version" docs/cli/development/windows-poc-handoff.mdx | grep -v "^0$" &amp;&amp; \
      grep -c "Win32_OperatingSystem" docs/cli/development/windows-poc-handoff.mdx | grep -v "^0$" &amp;&amp; \
      grep -c "ServiceBinaryPath .\\\\target" docs/cli/development/windows-poc-handoff.mdx | grep -v "^0$" &amp;&amp; \
      grep -c "Freshness note" docs/cli/development/windows-poc-handoff.mdx | grep -v "^0$" &amp;&amp; \
      grep -c "nono setup\` once as admin\\|nono setup\\*\\* once as admin" docs/cli/development/windows-poc-handoff.mdx | grep -v "^0$" &amp;&amp; \
      ! grep -q "release lane.*does not produce that binary" docs/cli/development/windows-poc-handoff.mdx &amp;&amp; \
      ! grep -qE -- "-- claude$" docs/cli/development/windows-poc-handoff.mdx
    </automated>
  </verify>
  <done>
    All 9 fixes applied to `docs/cli/development/windows-poc-handoff.mdx`. Verification greps pass:
    - Fact-A anchor string present (Fix #2)
    - "Phase-15 fix" present in PTY paragraph (Fix #1)
    - "Operator references (internal)" heading present (Fix #7)
    - "claude --version" present (Fix #4 + Fix #8)
    - "Win32_OperatingSystem" present (Fix #8)
    - `-ServiceBinaryPath .\target` instruction present (Fix #9)
    - "Freshness note" present (Fix #3)
    - `nono setup` admin alternative present in symlink cell (Fix #5)
    - Old false claim about "release lane does not produce that binary" is GONE (Fix #9)
    - Bare `-- claude` (line-end) is GONE from dry-run example (Fix #4)
    No other files modified.
  </done>
</task>

<task type="auto">
  <name>Task 2: Write SUMMARY.md and prepare for orchestrator commit</name>
  <files>.planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md</files>
  <action>
Create `.planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md` documenting the 9 fixes applied. Required sections:

1. **What changed** — single-file MDX docs edit; list each of the 9 fixes one line each (Fix #1 through Fix #9), with a 1-line description of what was changed.

2. **Verified facts used** —
   - Fact A: WFP fail-closed diagnostic anchor string (used in Fix #2).
   - Fact B: machine-MSI `ServiceBinaryPath` defaults to empty; binary IS produced by `make build-release-cli` (used in Fix #9).

3. **Audit flag confirmation (Fix #6)** — record what `nono audit --help` actually returned, and which flags ended up in the final doc text. If `--tail`/`--json` exist as documented in the plan, say so; if substitutes were used, note them and why.

4. **Out of scope / follow-ups** — at minimum:
   - Step 1 Option C's MSI invocation is missing the now-Mandatory `-BrokerPath` argument (Phase 31). NOT in the user's 9 fixes; flagged here for a future docs pass.
   - Any other minor inconsistencies noticed in passing but deliberately not touched.

5. **Verification** — paste the grep output (or a one-line summary) confirming each of the verify checks passed.

6. **Commit handling** — note that the orchestrator (per `<output>` in the planning prompt and Step 8 of the quick workflow) will create the single atomic commit. The executor should NOT run `git commit`.
  </action>
  <verify>
    <automated>test -f .planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md &amp;&amp; grep -c "Fix #9" .planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md | grep -v "^0$" &amp;&amp; grep -c "BrokerPath" .planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md | grep -v "^0$"</automated>
  </verify>
  <done>
    SUMMARY.md exists at the prescribed path. Contains: enumeration of all 9 fixes, both verified facts, audit-flag confirmation result, BrokerPath follow-up flagged, verification results, and a note that the orchestrator owns the commit step.
  </done>
</task>

</tasks>

<verification>
Final phase check (run after both tasks complete):

```bash
# All 9 fixes verifiable via grep
cd C:/Users/OMack/Nono
grep -c "This request remains fail-closed until WFP activation is implemented" docs/cli/development/windows-poc-handoff.mdx  # >= 1 (Fix #2)
grep -c "Phase-15 fix" docs/cli/development/windows-poc-handoff.mdx                                                          # >= 1 (Fix #1)
grep -c "Phase 31" docs/cli/development/windows-poc-handoff.mdx                                                              # >= 1 (Fix #1, #3)
grep -c "Freshness note" docs/cli/development/windows-poc-handoff.mdx                                                        # >= 1 (Fix #3)
grep -c "claude --version" docs/cli/development/windows-poc-handoff.mdx                                                      # >= 2 (Fix #4 + Fix #8)
grep -c "Operator references (internal)" docs/cli/development/windows-poc-handoff.mdx                                        # >= 1 (Fix #7)
grep -c "Win32_OperatingSystem" docs/cli/development/windows-poc-handoff.mdx                                                 # >= 1 (Fix #8)
grep -c "ServiceBinaryPath" docs/cli/development/windows-poc-handoff.mdx                                                     # >= 1 (Fix #9)
grep -c "nono audit" docs/cli/development/windows-poc-handoff.mdx                                                            # >= 1 (Fix #6)

# Negative checks: stale content gone
! grep -q "release lane.*does not produce" docs/cli/development/windows-poc-handoff.mdx     # Fix #9 removed false claim
! grep -qE -- "-- claude$" docs/cli/development/windows-poc-handoff.mdx                     # Fix #4 removed bare claude
! grep -q "PTY allocation entirely on the Windows supervised path" docs/cli/development/windows-poc-handoff.mdx  # Fix #1 replaced

# Only one file modified
git status --porcelain | grep -v "^?? .planning/quick/260509-rib"
# Should show ONLY: " M docs/cli/development/windows-poc-handoff.mdx"
```

If any positive grep returns 0, or any negative grep matches, OR git status shows other modified files outside `.planning/quick/...`, the fix is incomplete.
</verification>

<success_criteria>
- All 9 fixes applied to `docs/cli/development/windows-poc-handoff.mdx`
- All positive grep checks pass; all negative grep checks pass
- SUMMARY.md exists with the 9-fix enumeration, fact references, audit-flag confirmation, and BrokerPath follow-up flag
- No source code (`.rs`, `.toml`, `.ps1`, `.sh`) modified
- No additional `.mdx` files modified beyond the target
- Orchestrator (not executor) creates the single atomic commit per the planning prompt
- Executor's git working tree shows exactly one modified file (the target `.mdx`) plus the new SUMMARY.md in `.planning/quick/...`
</success_criteria>

<output>
After completion, the SUMMARY.md at `.planning/quick/260509-rib-clean-up-windows-poc-handoff-mdx-apply-9/260509-rib-SUMMARY.md` documents the run. The orchestrator handles `git add` + `git commit` per Step 8 of the quick workflow.
</output>
