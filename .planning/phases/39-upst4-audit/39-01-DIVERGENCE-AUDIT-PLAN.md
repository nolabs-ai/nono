---
phase: 39-upst4-audit
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
  - .planning/phases/39-upst4-audit/39-01-SUMMARY.md
autonomous: false
requirements: [REQ-UPST4-01]
tags: [upstream-parity, drift-audit, ledger, windows-touch, upst4]

must_haves:
  truths:
    - "DIVERGENCE-LEDGER.md exists at .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md (D-39-E2 phase-local convention)"
    - "Ledger frontmatter records D-39-A2 reproducibility fields verbatim: range=v0.52.0..v0.53.0, upstream_head_at_audit captured at first commit per D-39-D1, drift_tool_sh_sha=0834aa664fbaf4c5e41af5debece292992211559, drift_tool_ps1_sha=0834aa664fbaf4c5e41af5debece292992211559, drift_tool_invocation locked, fork_baseline=v0.52.0 (Phase 34 UPST3 sync point — 2026-05-12), date"
    - "Every cluster header carries one of three dispositions: will-sync / fork-preserve / won't-sync (D-39-E3 enum at cluster level only)"
    - "Every cluster's commit-row table follows D-39-C1 / D-39-E4 EXTENDED schema: sha + subject + upstream-tag + categories + files-changed + windows-touch"
    - "windows-touch column resolves to 'yes' or 'no' per row using D-39-C2 mechanical heuristic (substring 'windows' in files_changed OR pinned list {platform.rs, registry.rs, wfp/*, win_*.rs} OR commit-subject keywords 'windows|wfp|registry|wsa|ntdll|kernel32') with judgment-override allowed"
    - "Two known windows-touch commits (5d821c12 'fix(platform): correctly parse windows registry dword values' and 0748cced 'feat(platform): implement robust windows platform detection') appear with windows-touch: yes"
    - "Windows-touch:yes commits default to fork-preserve cluster disposition unless empty fork-side proven by diff inspection (D-39-C3)"
    - "Explicit '## ADR review' section present in the ledger, falsifiable via grep (D-39-C4)"
    - "ADR review section affirms Phase 33 ADR Option A 'continue' remains Accepted; no superseding ADR (D-39-C4 point d)"
    - "Total row count across all cluster commit-row tables >= drift-tool total_unique_commits (REQ-UPST4-01 acceptance #1; D-39-B2 close-gate step 2)"
    - "ROADMAP.md gains '## v2.5 backlog' section with 'UPST5 — Upstream v0.53.0…+ sync audit' (or '… sync execution', auditor's discretion per D-39-B4 + CONTEXT § Claude's Discretion) stub: Depends on: Phase 40, Plans: 0 / TBD"
    - "ROADMAP.md Phase 39 v2.4 milestone-block entry flipped to [x] with '(completed YYYY-MM-DD)' appended; Phase Details Plans counter flipped to '1 / 1 plans complete' with checkbox sub-bullet listing [x] 39-01-DIVERGENCE-AUDIT-PLAN.md"
    - "STATE.md frontmatter completed_plans counter bumped; STATE.md Current Position flipped to Phase 39 (upst4-audit) — Phase complete — ready for verification"
    - "STATE.md Accumulated Context gains a Plan 39-01 close entry under Key Decisions (v2.4) capturing range, lock-sha, cluster count, commit count, disposition breakdown, windows-touch:yes count, ADR-review-section presence, UPST5 backlog stub commit sha, DCO sign-off"
    - "Drift-tool re-run is idempotent: make check-upstream-drift ARGS=\"--from v0.52.0 --to v0.53.0 --format json\" exits 0 after plan close (D-39-B2 close-gate step 1)"
    - "make ci passes after plan close (D-39-B2 close-gate step 7) — Phase 39 ships only docs + ROADMAP + STATE edits so failure would be a pre-existing condition; auditor may run once at plan close per CONTEXT § Claude's Discretion"
    - "D-39-E5 Windows-only-files invariant trivially honored: git diff --name-only <pre-Phase-39-base>..HEAD -- crates/ bindings/ scripts/ returns zero files (Phase 39 ships zero .rs / .toml / .sh / .ps1 / Makefile edits)"
  artifacts:
    - path: ".planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md"
      provides: "Audited inventory of v0.52.0..v0.53.0 fork-vs-upstream divergence with per-cluster dispositions, windows-touch column, and explicit ADR review section"
      contains: "## ADR review, ### Cluster:, - **Disposition:**, | sha | subject | upstream-tag | categories | files-changed | windows-touch |, windows-touch: yes"
    - path: ".planning/ROADMAP.md"
      provides: "v2.5 backlog section with UPST5 stub; Phase 39 v2.4 entry flipped to complete; Phase 39 detail Plans counter flipped to 1/1"
      contains: "## v2.5 backlog, UPST5 — Upstream v0.53.0, Depends on: Phase 40, Plans: 0 / TBD"
    - path: ".planning/STATE.md"
      provides: "Plan 39-01 close entry under Key Decisions (v2.4); completed_plans counter bumped; Current Position flipped to Phase 39 ready for verification"
      contains: "Phase 39 Plan 39-01"
    - path: ".planning/phases/39-upst4-audit/39-01-SUMMARY.md"
      provides: "Plan 39-01 close summary mirroring Phase 33 Plan 33-01-SUMMARY shape"
      contains: "REQ-UPST4-01, DIVERGENCE-LEDGER, windows-touch, ADR review"
  key_links:
    - from: "DIVERGENCE-LEDGER.md frontmatter"
      to: "drift-tool reproducibility (D-39-A2 / D-39-D1)"
      via: "frontmatter records range + upstream_head_at_audit + drift_tool shas + invocation verbatim; re-running the invocation against the same upstream HEAD reproduces the input set"
      pattern: "drift_tool_(sh|ps1)_sha|upstream_head_at_audit|drift_tool_invocation"
    - from: "DIVERGENCE-LEDGER.md ## ADR review section"
      to: "docs/architecture/upstream-parity-strategy.md (Phase 33 ADR, Accepted 2026-05-11)"
      via: "ADR review section confirms Option A 'continue' remains compatible with Phase 39 cluster dispositions; cadence rule honored"
      pattern: "## ADR review|Phase 33 ADR|Option A|Future audit cadence"
    - from: "DIVERGENCE-LEDGER.md cluster dispositions (will-sync, fork-preserve, won't-sync)"
      to: "Phase 40 UPST4 sync execution input (immutable per D-39-B3)"
      via: "Phase 40 plan-phase consumes the ledger's cluster summary table for plan slicing; auditor's optional wave-hint advisory but not prescriptive"
      pattern: "Disposition:.*will-sync|fork-preserve|won't-sync|Target phase:.*UPST4-sync|Phase 40"
    - from: "ROADMAP.md § v2.5 backlog UPST5 stub"
      to: "Phase 33 ADR § Future audit cadence rule (D-39-E6)"
      via: "stub Reference line cites docs/architecture/upstream-parity-strategy.md § Future audit cadence; preserves cadence-rule signal under v2.5 backlog without committing v2.4 slot"
      pattern: "UPST5 — Upstream v0.53.0|## v2.5 backlog|Future audit cadence"
---

<objective>
Run the D-39-A1-locked drift-tool invocation against the v0.52.0..v0.53.0 range, lock `upstream_head_at_audit` at first commit of this plan (D-39-D1), curate `DIVERGENCE-LEDGER.md` mirroring Phase 33's two-tier shape with the D-39-C1 `windows-touch` column extension, add an explicit `## ADR review` section (D-39-C4), queue an UPST5 placeholder in ROADMAP.md § v2.5 backlog (D-39-B4), update STATE.md, and ship the SUMMARY — all in one plan per D-39-B1.

Purpose: REQ-UPST4-01 demands a falsifiable, disposition-complete divergence inventory before Phase 40 UPST4 sync execution can begin. Phase 39's ledger is the binding input for Phase 40 (analog to how Phase 33's ledger was the binding input for Phase 34). The `windows-touch` column + `## ADR review` section are the Phase-39-specific extensions absorbing two upstream Windows-code-adding commits (`5d821c12` + `0748cced`) into the audit's parity-strategy lens; the Phase 33 v0.40.1..v0.52.0 range had ZERO such commits, so this is the first audit where the cross-platform surface absorbs new Windows-conditional code.

Output: 5 files committed across 2-3 atomic commits per the Phase 33 / Phase 36.5 precedent (D-39-PATTERNS § Atomic single-commit-per-artifact-set pattern):
1. `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` (NEW, ~150-200 lines)
2. `.planning/ROADMAP.md` (modified — § v2.5 backlog added + Phase 39 entry flipped to complete + Phase Details Plans counter flipped)
3. `.planning/STATE.md` (modified — frontmatter bump + Current Position flip + Plan 39-01 close entry)
4. `.planning/phases/39-upst4-audit/39-01-SUMMARY.md` (NEW)
5. ZERO `.rs` / `.toml` / `.sh` / `.ps1` / `Makefile` edits (D-39-E5 trivially honored).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/39-upst4-audit/39-CONTEXT.md
@.planning/phases/39-upst4-audit/39-PATTERNS.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/33-CONTEXT.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/33-01-PLAN.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@docs/architecture/upstream-parity-strategy.md
@.planning/phases/24-parity-drift-prevention/24-CONTEXT.md

<interfaces>
<!-- D-39-A2 locked frontmatter shape — every field below MUST appear in the ledger frontmatter -->

```yaml
---
slug: divergence-ledger-v052-v053
status: complete
type: audit-only
date: <YYYY-MM-DD: audit close date>
range: v0.52.0..v0.53.0
upstream_head_at_audit: <40-char sha captured at first commit of Plan 39-01 per D-39-D1>
drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559
drift_tool_ps1_sha: 0834aa664fbaf4c5e41af5debece292992211559
drift_tool_invocation: 'make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"'
fork_baseline: v0.52.0 (Phase 34 UPST3 sync point — 2026-05-12)
total_unique_commits: <integer; auditor fills exact at first commit of Plan 39-01; expected ~27>
---
```

<!-- D-39-C1 EXTENDED commit-row schema — every cluster commit-row table MUST use these 6 columns in this order -->

```markdown
| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| <sha7> | <commit subject> | <v0.52.1 | v0.52.2 | v0.53.0> | <comma-separated drift JSON categories[]> | <count> | <yes | no> |
```

<!-- D-39-C2 windows-touch detection heuristic (mechanical pass) -->

`windows-touch: yes` IFF any of:
- Any file in `files_changed` contains substring `windows`, OR
- Any file in `files_changed` matches pinned list `{platform.rs, registry.rs, wfp/*, win_*.rs}`, OR
- Commit subject contains any of: `windows`, `wfp`, `registry`, `wsa`, `ntdll`, `kernel32`

Auditor judgment-override permitted (and required) for ambiguous `feat(platform)` cases — read the diff and confirm/override.

<!-- D-39-C3 windows-touch disposition default -->

For each `windows-touch: yes` commit's cluster:
- DEFAULT disposition = `fork-preserve` (manual replay; protects D-11 invariant against accidental D-19 violation via cherry-pick collision with fork-only `*_windows.rs` files)
- EXCEPTION: if auditor confirms via diff inspection that upstream modifies an existing cross-platform file with a small Windows-conditional addition that composes cleanly with fork's existing code, disposition MAY flip to `will-sync`
- The reverse (downgrade `will-sync` to `fork-preserve` mid-execution) is more expensive; conservative-default is on purpose so Phase 40 inherits a safer execution baseline

<!-- D-39-C4 explicit ## ADR review section template (verbatim, fill placeholders) -->

```markdown
## ADR review

The Phase 33 strategic ADR (`docs/architecture/upstream-parity-strategy.md`, `Status: Accepted` 2026-05-11) chose Option A `continue`. This audit confirms compatibility:

(a) **Audit surfaced upstream Windows-code additions outside D-11-excluded paths.** <List the windows-touch:yes commits/clusters discovered, e.g., `5d821c12` + `0748cced` in cluster <N>.>

(b) **Phase 33 ADR Option A `continue` did not anticipate this shape explicitly.** The v0.40.1..v0.52.0 audit range had ZERO upstream commits touching Windows code outside D-11-excluded paths; Phase 39 is the first audit where the cross-platform surface absorbs new Windows-conditional code.

(c) **`fork-preserve` default applied per D-39-C3 to protect D-11 invariant.** All `windows-touch: yes` clusters disposition `fork-preserve` unless the auditor confirmed via diff inspection that straight cherry-pick is safe (D-39-C3 conservative default).

(d) **Phase 33 ADR remains `Accepted` — no superseding ADR needed yet.** Phase 39 does not supersede the ADR; future audits may revisit if Windows-touching cluster ratio grows.
```

<!-- Drift-tool JSON shape (inherited from Phase 33 — verified VERBATIM at Phase 24 ship; scripts/check-upstream-drift.sh L228-241) -->

```json
{
  "range": "v0.52.0..v0.53.0",
  "from": "v0.52.0",
  "to": "v0.53.0",
  "total_unique_commits": <N>,
  "by_category": {
    "profile": <int>, "policy": <int>, "package": <int>,
    "proxy": <int>, "audit": <int>, "other": <int>
  },
  "commits": [
    {
      "sha": "abcd1234...",
      "subject": "feat(profile): ...",
      "author": "Name",
      "date": "...",
      "additions": <int>,
      "deletions": <int>,
      "files_changed": ["crates/nono-cli/src/profile/mod.rs", ...],
      "categories": ["profile", "policy"]
    }
  ]
}
```

<!-- D-11 path filter (Phase 24) — drift tool EXCLUDES `*_windows.rs` + `crates/nono-cli/src/exec_strategy_windows/` from the walk. D-11 is necessary but NOT sufficient: Phase 39 still must detect upstream commits adding NEW Windows code OUTSIDE that filter (per D-39-C1/C2 — e.g., `5d821c12` lives in `crates/nono/src/platform.rs` or analog, which D-11 does not exclude). -->

<!-- ROADMAP § v2.5 backlog target shape (per 39-PATTERNS Pattern 2 — verbatim with placeholders) -->

```markdown
## v2.5 backlog

These entries are queued under v2.5 per the Phase 33 ADR `### Future audit cadence` rule — "per upstream release, lazily-evaluated". They activate when v2.5 scope locks; until then they live here as forward-cadence anchors.

### Phase TBD-NN: UPST5 — Upstream v0.53.0…+ sync audit

**Goal:** Mirror Phase 33 / Phase 39 audit shape. Inventory of upstream divergence from v0.53.0 forward (commits accumulated post-Phase 39 audit cutoff `c4b25b82`, including any subsequent v0.54.0+ tags). Per-cluster disposition + parity-strategy review against Phase 33 ADR.

**Depends on:** Phase 40 (UPST4 execution baseline lands fork at v0.53.0).

**Requirements:** TBD when v2.5 scope locks.

**Plans:** 0 / TBD — to be populated during `/gsd-plan-phase TBD-NN`.

**Estimated effort:** ~1 week (mirrors Phase 39 sizing).

**Reference:** `.planning/phases/33-windows-parity-upstream-0-52-divergence/` (audit-shape template), `.planning/phases/39-upst4-audit/` (Phase 39 worked example with `windows-touch` column), `docs/architecture/upstream-parity-strategy.md` § Future audit cadence (Phase 33 ADR cadence rule).
```

Title-wording discretion: auditor picks `… sync audit` (default — safer if Phase 39 surfaces any `fork-preserve` / `windows-touch: yes` complexity) vs `… sync execution` (only if Phase 39 ledger shows zero windows-touch + zero fork-preserve clusters → next cycle could plausibly skip a separate audit phase). Lock the choice at write time per Phase 39 ledger shape.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Lock provenance — fetch upstream + capture upstream_head_at_audit + run drift tool + extract per-commit data</name>
  <files>(none committed — drift JSON captured to scratch; per D-39-A2 raw JSON is NOT committed)</files>
  <read_first>
    - .planning/phases/39-upst4-audit/39-CONTEXT.md § D-39-A1 (range = v0.52.0..v0.53.0), D-39-A2 (frontmatter fields), D-39-D1 (lock at FIRST commit of Plan 39-01), D-39-A3 (silent on post-v0.53.0)
    - .planning/phases/39-upst4-audit/39-PATTERNS.md (Pattern 1 frontmatter shape + drift-tool JSON shape — both replicated in this plan's `<interfaces>` block)
    - .planning/phases/24-parity-drift-prevention/24-CONTEXT.md § D-11 (path filter; `*_windows.rs` + `crates/nono-cli/src/exec_strategy_windows/` EXCLUDED — Phase 39 still must detect Windows-touch commits outside this filter per D-39-C1/C2)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/33-01-PLAN.md § Task 1 (Phase 33 analog — same drift-tool invocation methodology; Phase 39 reuses the per-commit sha→tag mapping pattern)
  </read_first>
  <action>
    Execute the D-39-D1 "lock at first commit" protocol, then extract the structured commit data for cluster curation in Task 2.

    1. **Fetch upstream tags** (D-39-D1 — FIRST act of Plan 39-01):
       ```bash
       git fetch upstream --tags
       echo "fetch-exit=$?"
       ```
       Expected exit 0. The fetch is idempotent (already-fetched tags are no-ops). The `upstream` remote at `https://github.com/always-further/nono.git` was verified present 2026-05-13 (39-CONTEXT.md canonical_refs § Upstream source).

    2. **Capture upstream_head_at_audit** (D-39-D1):
       ```bash
       UPSTREAM_HEAD=$(git rev-parse upstream/main)
       echo "upstream_head_at_audit=$UPSTREAM_HEAD"
       ```
       Record this 40-char sha. This is the value Task 2 writes verbatim into the ledger frontmatter's `upstream_head_at_audit:` field. The expected approximate value is `b4f21611` at 2026-05-13 capture time (39-CONTEXT.md) but the actual value at execution time may differ if upstream commits land in the interim. The range stays `v0.52.0..v0.53.0` regardless (D-39-A1 + D-39-A3).

    3. **Run the D-39-A2 locked drift-tool invocation** (idempotent — drift tool is read-only against the local git repo):
       ```bash
       mkdir -p ci-logs-local/drift
       make check-upstream-drift ARGS='--from v0.52.0 --to v0.53.0 --format json' > ci-logs-local/drift/drift-v053.json 2>&1
       echo "drift-exit=$?"
       ```
       Expected exit 0. The Phase 33 Plan 33-01 deviation (Rule 3) is inherited: scratch JSON lands in `ci-logs-local/drift/` (Windows-host MSYS `/tmp/` is inaccessible to Python interpreters; `ci-logs-local/` is in `.gitignore` per Phase 33 33-01-SUMMARY § Deviations). If `make` is not on PATH (Windows host), dispatch directly: `bash scripts/check-upstream-drift.sh --from v0.52.0 --to v0.53.0 --format json > ci-logs-local/drift/drift-v053.json` — same output (Makefile is a thin wrapper).

       Per D-39-A2 the JSON is NOT committed. It exists only for Task 2's curation work.

    4. **Confirm shape and total commit count**:
       ```bash
       jq '.range, .from, .to, .total_unique_commits' ci-logs-local/drift/drift-v053.json
       jq '.by_category' ci-logs-local/drift/drift-v053.json
       jq '.commits | length' ci-logs-local/drift/drift-v053.json  # must match .total_unique_commits
       ```
       Record `total_unique_commits` (expected ~27 per 39-CONTEXT.md preview, but auditor confirms exact). This is the LOWER BOUND for the ledger's total row count (REQ-UPST4-01 acceptance #1; D-39-B2 close-gate step 2).

    5. **Map each commit to its introducing upstream-tag** (informs cluster grouping in Task 2):
       ```bash
       jq -r '.commits[].sha' ci-logs-local/drift/drift-v053.json | while read sha; do
         tag=$(git describe --tags --contains "$sha" 2>/dev/null | sed 's/[~^].*$//' | head -1)
         echo "$sha $tag"
       done > ci-logs-local/drift/drift-v053-tags.txt
       ```
       Expected: every sha maps to one of `v0.52.1` / `v0.52.2` / `v0.53.0`. The `--contains` form returns the first tag REACHABLE FROM the commit (the release that introduced it). The `sed` strip removes `~12` / `^2` suffixes that `--contains` appends.

    6. **Group commits by upstream-tag** (first-pass cluster heuristic):
       ```bash
       sort -k2 ci-logs-local/drift/drift-v053-tags.txt | awk '{print $2}' | uniq -c | sort -k2 -V
       ```
       Expected output: 3 lines, one per tag, showing commit counts. From 39-CONTEXT.md preview: v0.52.1 ~19 commits, v0.52.2 ~2 commits, v0.53.0 ~6 commits (rough; auditor confirms). Use as first-pass cluster table; Task 2 maintainer-walk may split a high-volume tag into themed sub-clusters or consolidate cross-tag themes.

    7. **Pre-flag windows-touch candidates** (D-39-C2 mechanical pass — informs cluster grouping AND Task 2's row windows-touch column):
       ```bash
       jq -r '.commits[] | select(
         (.subject | test("windows|wfp|registry|wsa|ntdll|kernel32"; "i"))
         or (.files_changed | map(test("windows|platform\\.rs$|registry\\.rs$|wfp/|win_.*\\.rs$"; "i")) | any)
       ) | "\(.sha) \(.subject)"' ci-logs-local/drift/drift-v053.json > ci-logs-local/drift/drift-v053-wintouch-candidates.txt
       cat ci-logs-local/drift/drift-v053-wintouch-candidates.txt
       ```
       Expected: at minimum the two known commits per 39-CONTEXT.md preview:
       - `5d821c12 fix(platform): correctly parse windows registry dword values`
       - `0748cced feat(platform): implement robust windows platform detection`
       If MORE commits surface, that's informational for Task 2's audit-walk (judgment-override allowed/required for ambiguous cases per D-39-C2).
  </action>
  <verify>
    <automated>jq -e '.total_unique_commits | numbers and . >= 1' ci-logs-local/drift/drift-v053.json &amp;&amp; jq -e '.commits | length == (.total_unique_commits)' ci-logs-local/drift/drift-v053.json &amp;&amp; test $(wc -l &lt; ci-logs-local/drift/drift-v053-tags.txt) -ge 1 &amp;&amp; grep -E "5d821c12|0748cced" ci-logs-local/drift/drift-v053-wintouch-candidates.txt &amp;&amp; echo OK</automated>
  </verify>
  <done>
    - `git fetch upstream --tags` exited 0
    - `upstream_head_at_audit` 40-char sha recorded (Task 2 will write this verbatim into ledger frontmatter)
    - `ci-logs-local/drift/drift-v053.json` contains well-formed drift JSON with non-zero `total_unique_commits`
    - `ci-logs-local/drift/drift-v053-tags.txt` maps each sha to v0.52.1 / v0.52.2 / v0.53.0
    - `ci-logs-local/drift/drift-v053-wintouch-candidates.txt` contains AT MINIMUM `5d821c12` + `0748cced`
    - Tag-frequency table captured in executor scratch for Task 2 cluster planning
    - `ci-logs-local/` is in `.gitignore` (verify; if not, append the line and commit it as a one-line ride-along in Task 4 — Phase 33 33-01-SUMMARY precedent)
  </done>
</task>

<task type="auto">
  <name>Task 2: Curate DIVERGENCE-LEDGER.md — header + cluster sections (with windows-touch column) + ## ADR review section</name>
  <files>.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md</files>
  <read_first>
    - .planning/phases/39-upst4-audit/39-CONTEXT.md (full file — every D-39-A1..E6 decision applies)
    - .planning/phases/39-upst4-audit/39-PATTERNS.md (Patterns 1-8 — verbatim Phase 33 shape excerpts + Phase 39 deltas)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md (the canonical 300-line worked example mandated by D-39-E3/E4 — read in full to internalize cluster section shape, rationale-paragraph style, fork-only surface section)
    - ci-logs-local/drift/drift-v053.json (Task 1 output — drift JSON to curate)
    - ci-logs-local/drift/drift-v053-tags.txt (Task 1 output — per-commit upstream-tag map)
    - ci-logs-local/drift/drift-v053-wintouch-candidates.txt (Task 1 output — mechanical windows-touch flag set)
    - docs/architecture/upstream-parity-strategy.md § Future audit cadence (Phase 33 ADR cadence rule — `## ADR review` section narrative quotes this)
  </read_first>
  <action>
    Write `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` with the EXACT structure below. Substitute every `<placeholder>` with values from `ci-logs-local/drift/drift-v053.json` + Task 1 scratch outputs + auditor judgment. Do NOT leave placeholder strings in the committed file.

    **Section A — YAML frontmatter (D-39-A2 locked fields, verbatim):**

    ```markdown
    ---
    slug: divergence-ledger-v052-v053
    status: complete
    type: audit-only
    date: <YYYY-MM-DD: today>
    range: v0.52.0..v0.53.0
    upstream_head_at_audit: <40-char sha from Task 1 step 2>
    drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559
    drift_tool_ps1_sha: 0834aa664fbaf4c5e41af5debece292992211559
    drift_tool_invocation: 'make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"'
    fork_baseline: v0.52.0 (Phase 34 UPST3 sync point — 2026-05-12)
    total_unique_commits: <integer from Task 1 step 4 — actual count>
    ---
    ```

    Note the EXACT shas (`0834aa66...`) are NOT placeholders — they are the Phase 24 drift-tool ship shas, unchanged since 2026-04-29, locked by D-39-A2.

    **Section B — Headline + Reproduction (mirrors Phase 33 Pattern 2 + 3 with v0.52.0..v0.53.0 substitution + D-39-C2 inspection-methodology note):**

    ```markdown
    # Upstream v0.52.0 → v0.53.0 divergence ledger

    ## Headline

    **<total_unique_commits> non-merge commits across 3 minor releases (v0.52.1 → v0.53.0); ~<additions sum> insertions / ~<deletions sum> deletions across drift-tool categories: <by_category one-liner from drift JSON>.**

    <Cluster-count> themed clusters span the range. <N> disposition `will-sync`; <M> `fork-preserve` (manual replay per D-20 and/or D-39-C3 windows-touch default); <K> `won't-sync`. <X> commits flagged `windows-touch: yes` against the D-39-C2 mechanical heuristic (auditor judgment-override applied where ambiguous) — see [§ ADR review](#adr-review) below.

    ## Reproduction

    This audit is regenerable from the values in the YAML frontmatter above (D-39-A2 / D-39-E1):

    ```bash
    git fetch upstream --tags
    # Drift-tool script pinned at sha 0834aa664fbaf4c5e41af5debece292992211559 (Phase 24 ship sha; unchanged at audit time):
    make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"
    # (On Windows hosts where `make` is not on PATH, the Makefile target dispatches to
    #  bash scripts/check-upstream-drift.sh ... — same shell command, same JSON output.)
    ```

    Per D-39-A2 / D-39-E1 the raw JSON output is NOT committed. The cluster tables below are the canonical artifact — the JSON is regenerable on demand from the locked invocation + the upstream HEAD sha + drift-tool script sha recorded in the frontmatter.

    Per D-11 (see [Phase 24 CONTEXT.md](../24-parity-drift-prevention/24-CONTEXT.md) D-11), `*_windows.rs` and `crates/nono-cli/src/exec_strategy_windows/` are EXCLUDED from drift-tool output. The `windows-touch` column on commit rows (D-39-C1) flags upstream commits adding NEW Windows code OUTSIDE the D-11-excluded paths — D-11 is necessary but not sufficient. Fork-only Windows surface added since Phase 33 is enumerated in [§ Fork-only surface area](#fork-only-surface-area) below (auditor's discretion whether to add a § Delta-since-Phase-33 subsection or reference Phase 33's enumeration unchanged); cluster dispositions cover only the cross-platform surface the tool walks plus the windows-touch:yes additions.

    **Inspection methodology** (mirrors Phase 33 Pattern 3 + D-39-C2 extension): each commit's `subject` + `categories` + `files_changed[]` length was read from the drift JSON for every row; per-commit diffs were read for the lead commit in each cluster (the one introducing the feature), any commit whose subject was ambiguous re: disposition, AND every commit flagged by the D-39-C2 mechanical windows-touch heuristic with an ambiguous subject (e.g., generic `feat(platform)` cases). The D-39-C2 mechanical pass set `windows-touch: yes` iff: (a) any file in `files_changed` matches `windows` substring or the pinned list `{platform.rs, registry.rs, wfp/*, win_*.rs}`, OR (b) commit subject contains `windows` / `wfp` / `registry` / `wsa` / `ntdll` / `kernel32` keywords. Auditor judgment-override applied where mechanical heuristic produced a false positive or false negative; overrides documented inline in cluster rationale where they fired.
    ```

    **Section C — Cluster Summary table (mirrors Phase 33 Pattern 4 — same 5-column shape, NO windows-touch column here per 39-PATTERNS Pattern 4 note):**

    ```markdown
    ## Cluster Summary

    | # | Cluster (introduced in) | Commit count | Disposition | One-line summary |
    |---|-------------------------|--------------|-------------|------------------|
    | 1 | <cluster 1 name> (<v0.5X.Y>) | <N> | `<disposition>` | <one-line summary> |
    | ... | ... | ... | ... | ... |
    ```

    **Section D — Per-cluster sections (D-39-E3/E4 two-tier; D-39-C1 EXTENDED row schema with windows-touch column):**

    For EACH cluster identified in Task 1 + Task 2 audit-walk, emit:

    ```markdown
    ### Cluster: <cluster name> (introduced in v0.5X.Y)

    - **Disposition:** <one of: will-sync | fork-preserve | won't-sync>
    - **Rationale:** <2-4 sentences. For windows-touch:yes clusters, EXPLICITLY note the D-39-C3 default and whether it was upheld or upgraded — e.g., "Per D-39-C3 default applied: this cluster contains upstream commit `5d821c12` adding new Windows-conditional code in `crates/nono/src/platform.rs` (D-11 does NOT exclude); cherry-pick risk is collision with fork's `*_windows.rs` Windows surface; fork-preserve disposition assigned conservatively per D-39-C3 to protect D-11 invariant; Phase 40 plan-phase may upgrade to will-sync after diff inspection confirms safe composition." For will-sync (windows-touch:no) clusters, cite what the cluster closes / why it composes with fork (Phase 33 Cluster 5 / 7 / 8 style rationale paragraph). For won't-sync, be specific not generic (Phase 33 Cluster 3 style — "Unix-only by construction" + reference to D-11 / D-19 / D-21).>
    - **Target phase:** <UPST4-sync (Phase 40) for will-sync and fork-preserve; — (n/a) for won't-sync>
    - **Wave-hint:** <OPTIONAL per D-39-B3 + CONTEXT § Claude's Discretion — auditor may add `foundation` for the largest/most-foundational cluster (analog to Phase 34 D-34-A2 "C7 first as Wave 0"), or `depends-on cluster-N final state` for clusters that share files with other clusters. Omit this bullet for clusters where wave shape is uninteresting. Phase 40 retains full discretion to refine.>

    | sha | subject | upstream-tag | categories | files-changed | windows-touch |
    |-----|---------|--------------|------------|---------------|---------------|
    | <sha-short-7> | <subject> | <upstream-tag from drift-v053-tags.txt> | <comma-separated categories from drift JSON .commits[].categories[]> | <length of .commits[].files_changed[]> | <yes or no per D-39-C2> |
    | ... | ... | ... | ... | ... | ... |
    ```

    **Disposition rationale guidance addenda (D-19/D-21 invariant prompts — REQ-UPST4-01 acceptance #2):**

    - **will-sync template addendum — D-19/D-21 invariant prompt:** if the cluster's surface intersects capability-enum / Windows-no-op-variant risk (D-19) or library-mutation-without-execution risk (D-21), cite the relevant decision ID inline. Phase 33 ledger Cluster 3 (Unix socket capability) cites D-19; Phase 33 Cluster 6/11 (fork-preserve clusters) cite D-20/D-21. Replicate that pattern when applicable.
    - **fork-preserve template addendum — D-19/D-21 invariant prompt:** if the cluster's surface intersects capability-enum / Windows-no-op-variant risk (D-19) or library-mutation-without-execution risk (D-21), cite the relevant decision ID inline. Phase 33 ledger Cluster 3 (Unix socket capability) cites D-19; Phase 33 Cluster 6/11 (fork-preserve clusters) cite D-20/D-21. Replicate that pattern when applicable.

    Sort clusters by introducing upstream-tag ascending (v0.52.1 first, v0.53.0 last). The two known windows-touch:yes commits (`5d821c12` + `0748cced`) MUST appear with `windows-touch: yes` in their commit rows.

    **Cluster grouping heuristic (CONTEXT § Claude's Discretion + Phase 33 precedent — 12 clusters / 97 commits = roughly 8 commits per cluster on average):**
    - One feature theme per cluster, 2-15 commits each. 39-CONTEXT.md preview lists likely themes: (1) Profile JSON schema + proxy server hardening (v0.52.1), (2) Sandbox/Landlock optimization (v0.52.1), (3) PTY scrollback fix (v0.52.1), (4) Proxy TLS trust / multi-route dispatch (v0.52.2), (5) Secret scrubbing + scrub refactor (v0.53.0), (6) Platform-conditional profile fields (v0.53.0), (7) Windows platform detection (v0.53.0 — DEFINITELY a separate cluster because windows-touch:yes ⇒ D-39-C3 fork-preserve default). Auditor confirms during audit-walk; planner does NOT pre-commit to grouping.
    - Within a single upstream-tag, split into themed sub-clusters if subjects span multiple concerns (e.g., v0.52.1 may split into multiple themes given its ~19-commit volume).
    - Within a theme that spans multiple tags, consolidate into one cluster (the upstream-tag column will show multiple values; that's fine).
    - Each commit MUST appear in exactly ONE cluster — no orphans, no duplicates. Total row count across all cluster tables MUST equal `total_unique_commits`.
    - Aim for 5-8 clusters total (smaller range than Phase 33's 12 clusters; ~27 commits vs 97).

    **Section E — `## ADR review` section (D-39-C4 — NEW; no Phase 33 analog; verbatim shape locked):**

    Place this section AFTER all cluster sections and BEFORE `## Fork-only surface area`:

    ```markdown
    ## ADR review

    The Phase 33 strategic ADR (`docs/architecture/upstream-parity-strategy.md`, `Status: Accepted` 2026-05-11) chose Option A `continue`. This audit confirms compatibility:

    (a) **Audit surfaced upstream Windows-code additions outside D-11-excluded paths.** <List the windows-touch:yes commits/clusters discovered, e.g., "Two commits in cluster <N> (Windows platform detection): `5d821c12 fix(platform): correctly parse windows registry dword values` adding/modifying `<files>`; `0748cced feat(platform): implement robust windows platform detection` adding/modifying `<files>`. Both land in `crates/nono/src/platform.rs` (or upstream's equivalent) — outside D-11's `*_windows.rs` and `crates/nono-cli/src/exec_strategy_windows/` exclusion."> <If audit-walk surfaces MORE windows-touch:yes commits than the two known ones, list them here too.>

    (b) **Phase 33 ADR Option A `continue` did not anticipate this shape explicitly.** The v0.40.1..v0.52.0 audit range had ZERO upstream commits touching Windows code outside D-11-excluded paths (verified against Phase 33 [DIVERGENCE-LEDGER.md](../33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md) — no `windows-touch` column was needed at that audit time). Phase 39 is the first audit where the cross-platform surface absorbs new Windows-conditional code; the new `windows-touch` column on commit rows (D-39-C1) is the structural carrier for this signal.

    (c) **`fork-preserve` default applied per D-39-C3 to protect D-11 invariant.** All `windows-touch: yes` clusters disposition `fork-preserve` <unless the auditor confirmed via diff inspection that straight cherry-pick is safe (D-39-C3 conservative default upgrade clause) — if no upgrades occurred, omit this clause>. <If the auditor upgraded any windows-touch:yes cluster from fork-preserve to will-sync after diff inspection, list those upgrades here with rationale; e.g., "Cluster N (Windows platform detection) upgraded from fork-preserve to will-sync after diff inspection of <sha> confirmed the new code lands entirely in a new file with no fork-side analog, so cherry-pick cannot collide with fork-only Windows surface.">

    (d) **Phase 33 ADR remains `Accepted` — no superseding ADR needed yet.** Phase 39 does not supersede the ADR; future audits may revisit if Windows-touching cluster ratio grows beyond <some threshold — auditor judgment>. The cadence rule from `docs/architecture/upstream-parity-strategy.md` § Future audit cadence holds: per upstream release, lazily-evaluated. UPST5 is queued in `.planning/ROADMAP.md` § v2.5 backlog (per D-39-B4) as the next absorption cycle.
    ```

    **Section F — `## Fork-only surface area` (D-39-A3 carry-forward; auditor's discretion per CONTEXT § Claude's Discretion):**

    Two options per the Discretion section:
    - **Option F.1 (terse — recommended if Phase 35/36/36.5 introduced no new fork-only Windows surface):** Single paragraph referencing Phase 33's enumeration:
      ```markdown
      ## Fork-only surface area

      Surface added since v0.40.1 with NO upstream analog. The drift tool's D-11 filter (`*_windows.rs` + `crates/nono-cli/src/exec_strategy_windows/` excluded) hides ALL of this from the audit walk. Phase 39 references Phase 33's enumeration unchanged — no new fork-only Windows surface was introduced in Phases 35, 36, 36.5 (verified by audit-walk against the phase SUMMARYs):

      See [Phase 33 ledger § Fork-only surface area](../33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md#fork-only-surface-area) for the full enumeration: `crates/nono-shell-broker/`, Phase 27.1 `NONO_TEST_HOME` seam, Phase 28 Authenticode chain-walker, Phase 31 `WindowsTokenArm::BrokerLaunch` arm, Phase 32 Sigstore TUF cached-root, Phase 32 broker self-trust-anchor, plus the 8 `*_windows.rs` files surfaced by `git ls-files | grep -E '_windows\.rs$'`.
      ```
    - **Option F.2 (full — only if Phase 35/36/36.5 DID introduce new fork-only Windows surface):** Add a `### Delta-since-Phase-33` subsection enumerating only the NEW seams, then reference Phase 33's enumeration for everything else.

    Pick at write-time based on Phase 35/36/36.5 SUMMARYs (audit-walk surfaces this — Phase 35/36/36.5 are UPST3 closure phases shipping non-Windows-surface ports per the entries in STATE.md L67-71, so Option F.1 is likely correct).

    **CRITICAL — coverage + falsifiability invariants before commit (D-39-B2 close-gate steps 2, 3, 4):**

    Verify before writing:
    1. `<total cluster rows>` ≥ `<total_unique_commits>` from drift JSON (step 2 — strict equality is the goal; ≥ accommodates judgment-driven duplications across clusters, but each commit MUST appear in exactly ONE cluster section, so equality is the strong invariant)
    2. Every cluster header has all three required bullets: `**Disposition:**`, `**Rationale:**`, `**Target phase:**` (step 3; `**Wave-hint:**` is OPTIONAL per D-39-B3)
    3. Every disposition is one of `will-sync` / `fork-preserve` / `won't-sync` — exactly (no other spellings)
    4. `## ADR review` section header present, grep-discoverable
    5. Every commit-row has `yes` or `no` in the windows-touch column — no blank cells (D-39-C1 schema invariant)
    6. The two known commits `5d821c12` + `0748cced` carry `windows-touch: yes`

    Use the Write tool with the full assembled content. Do NOT use heredoc / `cat <<EOF`. Expected file size: ~150-200 lines per 39-CONTEXT.md scope-shape estimate (smaller than Phase 33's 300 lines because the range is smaller).
  </action>
  <verify>
    <automated>test -f .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; grep -E "^drift_tool_invocation: 'make check-upstream-drift ARGS=\"--from v0.52.0 --to v0.53.0 --format json\"'$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; grep -E "^upstream_head_at_audit: [0-9a-f]{40}$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; grep -E "^drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; grep -E "^range: v0.52.0..v0.53.0$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; test $(grep -cE "^### Cluster: " .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md) -ge 3 &amp;&amp; test $(grep -cE "^- \*\*Disposition:\*\* \`?(will-sync|fork-preserve|won't-sync)\`?$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md) -ge 3 &amp;&amp; grep -E "^## ADR review$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; grep -E "5d821c12" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; grep -E "0748cced" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; grep -E "windows-touch" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; grep -E "^## Fork-only surface area$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md &amp;&amp; echo OK</automated>
  </verify>
  <done>
    - File exists at `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md`
    - YAML frontmatter has all D-39-A2 fields populated with real (non-placeholder) values; drift_tool shas are the locked Phase 24 ship shas; range is `v0.52.0..v0.53.0`; fork_baseline cites Phase 34 sync point
    - Cluster Summary table present with one row per cluster, one of three dispositions per row, NO windows-touch column at the summary level (windows-touch lives in per-row commit tables only — D-39-C1)
    - Per-cluster sections: each has `### Cluster: <name> (introduced in v0.5X.Y)` header + 3 required bullets (Disposition, Rationale, Target phase) + optional `**Wave-hint:**` bullet, then a commit-row table
    - Every cluster's commit-row table follows the D-39-C1 EXTENDED schema (6 columns: sha + subject + upstream-tag + categories + files-changed + windows-touch); every row has `yes` or `no` in the windows-touch column, no blanks
    - Total commit-row count across all clusters EQUALS `total_unique_commits` from drift JSON
    - `## ADR review` section present, grep-falsifiable, contains all 4 (a)/(b)/(c)/(d) points per D-39-C4 template
    - `## Fork-only surface area` section present (Option F.1 terse-reference OR F.2 full-enumeration per Phase 35/36/36.5 audit-walk)
    - The two known windows-touch:yes commits (`5d821c12` + `0748cced`) appear with `windows-touch: yes`
  </done>
</task>

<task type="auto">
  <name>Task 3: Update ROADMAP.md — flip Phase 39 entry to complete + append § v2.5 backlog with UPST5 stub</name>
  <files>.planning/ROADMAP.md</files>
  <read_first>
    - .planning/ROADMAP.md (full file — must understand current v2.4 milestone block at L107-116, Phase Details Phase 39 block at L209-221, and EOF position for appending § v2.5 backlog)
    - .planning/phases/39-upst4-audit/39-CONTEXT.md § D-39-B4 (UPST5 stub fields locked: title, depends-on, plans, target section)
    - .planning/phases/39-upst4-audit/39-PATTERNS.md § ROADMAP.md (Analog 2 + Phase 39 UPST5 backlog stub verbatim shape)
    - .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md (Task 2 output — auditor confirms title-wording discretion from the ledger shape: `… sync audit` default vs `… sync execution` if zero windows-touch + zero fork-preserve)
    - docs/architecture/upstream-parity-strategy.md § Future audit cadence (Phase 33 ADR cadence rule — referenced in UPST5 stub's `**Reference:**` line)
  </read_first>
  <action>
    Make THREE distinct edits to `.planning/ROADMAP.md`:

    **Edit 1 — Flip Phase 39 v2.4 milestone-block entry (currently at ROADMAP L115):**

    Current line:
    ```markdown
    - [ ] **Phase 39: UPST4 audit** — REQ-UPST4-01. Mirror Phase 33 shape. DIVERGENCE-LEDGER.md inventory of upstream v0.52.0..v0.53.0+ divergence (3 confirmed tags at milestone start: v0.52.1 `21bbb82e`, v0.52.2 `e8bf0148`, v0.53.0 `c4b25b82`; may grow). Per-cluster disposition + parity-strategy review against Phase 33 ADR. ~1 week.
    ```

    Replace `- [ ]` with `- [x]` and append ` (completed YYYY-MM-DD)` (today's date) at the end of the line, before the period that ends it. Final shape:
    ```markdown
    - [x] **Phase 39: UPST4 audit** — REQ-UPST4-01. Mirror Phase 33 shape. DIVERGENCE-LEDGER.md inventory of upstream v0.52.0..v0.53.0+ divergence (3 confirmed tags at milestone start: v0.52.1 `21bbb82e`, v0.52.2 `e8bf0148`, v0.53.0 `c4b25b82`; may grow). Per-cluster disposition + parity-strategy review against Phase 33 ADR. ~1 week. (completed YYYY-MM-DD)
    ```

    **Edit 2 — Flip Phase Details > Phase 39 block at L209-221 to show 1/1 plans complete with checkbox:**

    Current Plans line:
    ```markdown
    **Plans:** 0 plans — to be populated during `/gsd-plan-phase 39`.
    ```

    Replace with:
    ```markdown
    **Plans:** 1 / 1 plans complete

    - [x] 39-01-DIVERGENCE-AUDIT-PLAN.md — REQ-UPST4-01 (DIVERGENCE-LEDGER.md curated for v0.52.0..v0.53.0 with `windows-touch` column + `## ADR review` section; UPST5 stub queued under v2.5 backlog; Phase 33 ADR remains Accepted)
    ```

    **Edit 3 — Append `## v2.5 backlog` section AFTER the Phase 40 detail block (current ROADMAP EOF at L235):**

    Append the following block at end-of-file (after the Phase 40 `**Reference:**` line):

    ```markdown

    ## v2.5 backlog

    These entries are queued under v2.5 per the Phase 33 ADR `### Future audit cadence` rule — "per upstream release, lazily-evaluated". They activate when v2.5 scope locks; until then they live here as forward-cadence anchors.

    ### Phase TBD-NN: UPST5 — Upstream v0.53.0…+ <sync audit | sync execution> 

    **Goal:** Mirror Phase 33 / Phase 39 audit shape. Inventory of upstream divergence from v0.53.0 forward (commits accumulated post-Phase 39 audit cutoff `c4b25b82`, including any subsequent v0.54.0+ tags). Per-cluster disposition + parity-strategy review against Phase 33 ADR.

    **Depends on:** Phase 40 (UPST4 execution baseline lands fork at v0.53.0).

    **Requirements:** TBD when v2.5 scope locks.

    **Plans:** 0 / TBD — to be populated during `/gsd-plan-phase TBD-NN`.

    **Estimated effort:** ~1 week (mirrors Phase 39 sizing).

    **Reference:** `.planning/phases/33-windows-parity-upstream-0-52-divergence/` (audit-shape template), `.planning/phases/39-upst4-audit/` (Phase 39 worked example with `windows-touch` column), `docs/architecture/upstream-parity-strategy.md` § Future audit cadence (Phase 33 ADR cadence rule).
    ```

    **Title-wording discretion (D-39-B4 + CONTEXT § Claude's Discretion):** Pick `… sync audit` (DEFAULT — safer if Phase 39 surfaced any `fork-preserve` or `windows-touch: yes` complexity) vs `… sync execution` (ONLY if Phase 39 ledger shows zero windows-touch:yes AND zero fork-preserve clusters → next cycle could plausibly skip a separate audit phase and go straight to execution). Read the ledger written in Task 2 BEFORE writing this line — the cluster summary table is authoritative. Given the two known windows-touch:yes commits + D-39-C3 default-to-fork-preserve, the auditor will almost certainly pick `… sync audit`. Replace `<sync audit | sync execution>` with the chosen single phrase; remove the angle brackets.

    Use the Edit tool for each of the three edits (3 separate Edit calls; each touches a distinct hunk of ROADMAP.md). Do NOT rewrite the entire file via Write — Edit preserves surrounding content.
  </action>
  <verify>
    <automated>grep -E "^- \[x\] \*\*Phase 39: UPST4 audit\*\*.*\(completed [0-9]{4}-[0-9]{2}-[0-9]{2}\)" .planning/ROADMAP.md &amp;&amp; grep -E "^\*\*Plans:\*\* 1 / 1 plans complete$" .planning/ROADMAP.md &amp;&amp; grep -E "^- \[x\] 39-01-DIVERGENCE-AUDIT-PLAN\.md" .planning/ROADMAP.md &amp;&amp; grep -E "^## v2.5 backlog$" .planning/ROADMAP.md &amp;&amp; grep -E "^### Phase TBD-NN: UPST5 — Upstream v0.53.0" .planning/ROADMAP.md &amp;&amp; grep -E "^\*\*Depends on:\*\* Phase 40 " .planning/ROADMAP.md &amp;&amp; grep -E "^\*\*Plans:\*\* 0 / TBD" .planning/ROADMAP.md &amp;&amp; echo OK</automated>
  </verify>
  <done>
    - Phase 39 v2.4 milestone-block entry flipped `[ ]` → `[x]` with `(completed YYYY-MM-DD)` appended
    - Phase Details > Phase 39 block Plans counter flipped to `**Plans:** 1 / 1 plans complete` with `[x] 39-01-DIVERGENCE-AUDIT-PLAN.md` sub-bullet
    - `## v2.5 backlog` section appended at end-of-file with `### Phase TBD-NN: UPST5 — Upstream v0.53.0…+ <chosen-phrase>` stub
    - UPST5 stub has all 6 required fields (Goal, Depends on: Phase 40, Requirements: TBD, Plans: 0 / TBD, Estimated effort, Reference)
    - UPST5 stub `**Reference:**` line cites Phase 33 ledger + Phase 39 ledger + ADR § Future audit cadence
    - Title-wording chosen at write-time per Phase 39 ledger shape (most likely `… sync audit`; angle brackets removed)
  </done>
</task>

<task type="auto">
  <name>Task 4: Update STATE.md + write 39-01-SUMMARY.md + self-audit + commit (close-gate)</name>
  <files>
    - .planning/STATE.md
    - .planning/phases/39-upst4-audit/39-01-SUMMARY.md
  </files>
  <read_first>
    - .planning/STATE.md (full file — frontmatter at L1-13, Current Position at L26-31, Accumulated Context > Key Decisions (v2.4) at L65+ for the Plan 39-01 close entry insertion point, Session Continuity block near EOF)
    - .planning/phases/39-upst4-audit/39-CONTEXT.md § D-39-B2 (7-step close-gate)
    - .planning/phases/39-upst4-audit/39-PATTERNS.md § STATE.md (Patterns 1-4 — frontmatter bump, Current Position flip, Plan-closure log entry shape, Session Continuity bump)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/33-01-SUMMARY.md (analog for 39-01-SUMMARY.md shape — Phase 33 Plan 33-01 close summary)
    - .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md (Task 2 output — read cluster counts, disposition breakdown, windows-touch:yes count for the SUMMARY + STATE close entry)
    - .planning/ROADMAP.md (Task 3 output — verify Phase 39 entry is `[x]`; record UPST5 stub commit sha will land in the same commit as STATE/SUMMARY per Phase 33 § Atomic single-commit-per-artifact-set pattern)
  </read_first>
  <action>
    Four sub-tasks, sequenced:

    **Sub-task A — Update STATE.md (3 distinct edits):**

    *Edit A.1 — Frontmatter counter bump (L1-13):*

    Current frontmatter:
    ```yaml
    ---
    gsd_state_version: 1.0
    milestone: v2.4
    milestone_name: Complete the Partial Ports + UPST4
    status: verifying
    last_updated: "2026-05-13T18:43:53.911Z"
    last_activity: 2026-05-13
    progress:
      total_phases: 7
      completed_phases: 3
      total_plans: 10
      completed_plans: 10
      percent: 100
    ---
    ```

    Bumps required:
    - `last_updated`: stamp to current UTC ISO-8601 timestamp
    - `last_activity`: today's date YYYY-MM-DD
    - `progress.completed_phases`: 3 → 4 (Phase 39 complete)
    - `progress.total_plans`: 10 → 11 (Phase 39 added Plan 39-01)
    - `progress.completed_plans`: 10 → 11
    - `progress.percent`: 100 → 100 (still 100 since completed_plans == total_plans; if any phase in the v2.4 milestone block is incomplete the math may differ — verify against the actual phase/plan counter; the math is `total_plans` should reflect every plan that has been WRITTEN, including Plan 39-01)

    Note: If `total_plans` was tracking only WRITTEN plans (which it should be), then adding Plan 39-01 to the count gives total 11 / completed 11 / percent 100. If `total_plans` includes future-phase plans (Phase 37/38/40 stubs at 0 each), the math holds at 100. Verify against current STATE.md state immediately before editing.

    *Edit A.2 — Current Position block (L26-31):*

    Current:
    ```markdown
    ## Current Position

    Phase: 36.5 (profile-drafts-feature-absorption-optional) — EXECUTING
    Plan: 1 of 1
    Status: Phase complete — ready for verification
    Last activity: 2026-05-13
    ```

    Replace with:
    ```markdown
    ## Current Position

    Phase: 39 (upst4-audit) — EXECUTING
    Plan: 1 of 1
    Status: Phase complete — ready for verification
    Last activity: YYYY-MM-DD
    ```

    *Edit A.3 — Plan 39-01 close entry under `### Key Decisions (v2.4)`:*

    Insert a new single-paragraph entry at the TOP of the `### Key Decisions (v2.4)` block (just under the heading, before the existing Phase 36 entries — keep entries in reverse-chronological order). Shape (single paragraph mirroring Phase 33 Plan 33-01 close entry at STATE.md L77, with Phase 39 deltas):

    ```markdown
    - **Phase 39 Plan 39-01 (REQ-UPST4-01) — DIVERGENCE-LEDGER.md curated for v0.52.0..v0.53.0:** Wave 1 ledger curation completed YYYY-MM-DD. Drift-tool re-run (D-39-A1 locked invocation `make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"`, drift-tool sha `0834aa664fbaf4c5e41af5debece292992211559` unchanged since Phase 24 ship 2026-04-29, dispatched on Windows host via `bash scripts/check-upstream-drift.sh` per Phase 33 33-01-SUMMARY Rule 3 deviation precedent) produces <total_unique_commits> unique commits across 3 minor releases (v0.52.1 → v0.53.0). `upstream_head_at_audit` locked at first commit of Plan 39-01 per D-39-D1 (40-char sha `<sha>`). Curated <N> themed clusters: per-cluster dispositions <W will-sync> + <F fork-preserve> + <K won't-sync>. <X> commits flagged `windows-touch: yes` against the D-39-C2 mechanical heuristic + judgment-override pass; the two known windows-touch:yes commits (`5d821c12` Windows registry dword parse + `0748cced` robust Windows platform detection) carry the flag <plus any additional commits the audit-walk surfaced>. Per D-39-C3 conservative default, all windows-touch:yes clusters assigned `fork-preserve` disposition <unless / except those upgraded after diff inspection — auditor cites upgrades if any>. **D-39-C4 invention: `## ADR review` section present in ledger** (falsifiable via `grep -c "^## ADR review" DIVERGENCE-LEDGER.md` returning 1). The section confirms Phase 33 ADR Option A `continue` remains Accepted — Phase 39 does not supersede, but flags Windows-touching upstream additions as a new shape for future audit-cycle awareness. UPST5 stub queued in `.planning/ROADMAP.md § v2.5 backlog` (D-39-B4) with title `UPST5 — Upstream v0.53.0…+ <sync audit | sync execution>`, Depends on: Phase 40, Plans: 0 / TBD. **Validation (all 7 D-39-B2 close-gate checks pass):** (1) drift-tool re-run idempotent (exit 0), (2) ledger row count <N> ≥ drift-tool flagged count <total_unique_commits>, (3) every cluster has disposition + rationale, (4) `## ADR review` section grep-confirmable, (5) ROADMAP UPST5 stub committed under v2.5 backlog, (6) STATE.md updated (this entry), (7) `make ci` passes (Phase 39 ships only docs + ROADMAP + STATE edits so structurally zero clippy/fmt/test risk — auditor cites `make ci` exit 0 or substitute per Rule 3 deviation precedent if `make` not on PATH on Windows host). **D-39-E5 Windows-only-files invariant trivially honored:** `git diff --name-only <pre-Phase-39-base>..HEAD -- crates/ bindings/ scripts/` returns 0 files (Phase 39 ships zero .rs / .toml / .sh / .ps1 / Makefile edits). Commits: `<commit-A-sha>` (DIVERGENCE-LEDGER.md) + `<commit-B-sha>` (ROADMAP + STATE.md atomic close per Phase 33 § Atomic single-commit-per-artifact-set pattern) + `<commit-C-sha>` (39-01-SUMMARY.md). DCO sign-offs in all commits. Phase 39 closes: 1/1 plan executed, REQ-UPST4-01 landed, ready for `/gsd-verify-work` verifier pass.
    ```

    Auditor fills `<placeholders>` from the ledger written in Task 2 + the ROADMAP edits from Task 3. Commit shas are filled AFTER the commits land (this paragraph may be amended in the close commit itself, or pre-written with placeholders and amended post-commit per the auditor's preference — Phase 33 wrote it pre-commit with shas filled in the final commit).

    **Sub-task B — Write 39-01-SUMMARY.md:**

    Use the Write tool to create `.planning/phases/39-upst4-audit/39-01-SUMMARY.md`. Mirror Phase 33 Plan 33-01-SUMMARY.md shape (read it for structure). Required sections:
    - YAML frontmatter: `phase: 39-upst4-audit`, `plan: 01`, `status: complete`, `requirements: [REQ-UPST4-01]`, `commits: [<A-sha>, <B-sha>, <C-sha>]`, `date: YYYY-MM-DD`, `provides:` list (DIVERGENCE-LEDGER artifact, cluster count, commit count, disposition breakdown, windows-touch:yes count, ADR-review-section presence, UPST5 backlog stub presence)
    - `## Plan summary` — 1-paragraph statement of what was done
    - `## Decisions implemented` — bullet list of D-39-A1..E6 IDs with one-line implementation note each
    - `## Validation results` — table or bullet list of the 7 D-39-B2 close-gate checks with PASS / evidence
    - `## Deviations` — any auto-fixes (e.g., Rule 3 `make` substitution on Windows host — Phase 33 precedent); empty if none
    - `## Hand-off to Phase 40` — short paragraph: ledger is immutable input; cluster summary table at <line range> is plan-slicing input; wave-hints (if any) are advisory not prescriptive; UPST5 stub in v2.5 backlog is the next cadence anchor

    **Sub-task C — Self-audit (D-39-B2 7-step close-gate):**

    Run the 7 close-gate checks before committing:
    ```bash
    # Step 1: drift-tool re-run idempotent
    make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json" > /dev/null 2>&1
    echo "drift-exit=$?"  # expected 0

    # Step 2: ledger row count >= drift-tool surfaced count
    LEDGER_ROWS=$(grep -cE "^\| [0-9a-f]{7,40} \|" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md)
    DRIFT_COUNT=$(jq -r '.total_unique_commits' ci-logs-local/drift/drift-v053.json)
    test "$LEDGER_ROWS" -ge "$DRIFT_COUNT" && echo "row-coverage-ok: $LEDGER_ROWS >= $DRIFT_COUNT"

    # Step 3: every cluster has disposition + rationale
    CLUSTERS=$(grep -cE "^### Cluster: " .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md)
    DISPS=$(grep -cE "^- \*\*Disposition:\*\* \`?(will-sync|fork-preserve|won't-sync)\`?$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md)
    RATIONALES=$(grep -cE "^- \*\*Rationale:\*\* " .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md)
    test "$CLUSTERS" -eq "$DISPS" -a "$CLUSTERS" -eq "$RATIONALES" && echo "cluster-completeness-ok: $CLUSTERS clusters / $DISPS dispositions / $RATIONALES rationales"

    # Step 4: ADR review section present
    test $(grep -cE "^## ADR review$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md) -eq 1 && echo "adr-review-section-ok"

    # Step 5: ROADMAP UPST5 stub committed
    grep -E "^## v2.5 backlog$" .planning/ROADMAP.md && grep -E "^### Phase TBD-NN: UPST5 — Upstream v0.53.0" .planning/ROADMAP.md && echo "upst5-stub-ok"

    # Step 6: STATE.md updated (this is the work in progress — verify after edits land)
    grep -E "Phase 39 Plan 39-01" .planning/STATE.md && echo "state-md-ok"

    # Step 7: make ci passes (best-effort on Windows host — auditor cites Rule 3 substitute per CONTEXT § Claude's Discretion if make not on PATH)
    make ci > /tmp/ci-out.log 2>&1
    echo "make-ci-exit=$?"
    # If make not on PATH, substitute: `git diff --name-only -- crates/ bindings/ scripts/ | wc -l` returns 0 (D-39-E5 trivially honored)
    test $(git diff --name-only -- crates/ bindings/ scripts/ | wc -l) -eq 0 && echo "d39e5-invariant-ok"
    ```

    If ANY step fails, STOP — fix before committing. Step 7 (`make ci`) on Windows host: the Phase 33 precedent (Plan 33-01 Rule 3 deviation: `make` not on PATH) applies — auditor may substitute the D-39-E5 invariant grep as the structural equivalent, since Phase 39 ships only docs + ROADMAP + STATE edits with structurally zero clippy/fmt/test risk. Document the substitution in 39-01-SUMMARY.md § Deviations if applied.

    **Sub-task D — Commit (Phase 33 § Atomic single-commit-per-artifact-set pattern; D-39-B2 step 5 + 6 commit landing):**

    Three atomic commits per 39-PATTERNS § Atomic pattern (auditor discretion to fold B into A or split further):

    Commit A (DIVERGENCE-LEDGER.md only):
    ```
    docs(39-01): write DIVERGENCE-LEDGER for v0.52.0..v0.53.0

    Produces .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md per REQ-UPST4-01 /
    D-39-A1 (range v0.52.0..v0.53.0) / D-39-A2 (frontmatter reproducibility — drift-
    tool sha 0834aa66, upstream_head_at_audit locked at first commit per D-39-D1) /
    D-39-C1 (windows-touch column on commit rows) / D-39-C2 (mechanical detection
    heuristic + judgment override) / D-39-C3 (windows-touch defaults to fork-preserve
    unless empty fork-side) / D-39-C4 (explicit ## ADR review section).

    Audit invocation (D-39-A1): make check-upstream-drift ARGS="--from v0.52.0 \
    --to v0.53.0 --format json". Drift tool unchanged from Phase 24 ship; raw JSON
    not committed per D-39-A2 / D-39-E1.

    <N> clusters covering <total_unique_commits> commits across v0.52.1..v0.53.0.
    Per-cluster dispositions assigned from {will-sync, fork-preserve, won't-sync}.
    <X> commits flagged windows-touch: yes (including 5d821c12 + 0748cced).
    ## ADR review section confirms Phase 33 ADR Option A `continue` remains Accepted.

    Phase 40 (UPST4 sync execution) consumes this ledger as immutable input.

    Refs: REQ-UPST4-01, D-39-A1, D-39-A2, D-39-C1, D-39-C2, D-39-C3, D-39-C4, D-39-D1, D-39-E1
    Signed-off-by: <user-name> <user-email>
    ```

    Commit B (ROADMAP + STATE.md atomic close):
    ```
    docs(39-01): queue UPST5 + finalize STATE + ROADMAP

    ROADMAP: flip Phase 39 v2.4 entry to [x] (completed YYYY-MM-DD); flip Phase
    Details Plans counter to 1/1 with [x] 39-01-DIVERGENCE-AUDIT-PLAN.md sub-bullet;
    append new ## v2.5 backlog section with UPST5 — Upstream v0.53.0…+ <chosen-phrase>
    stub (Depends on: Phase 40, Plans: 0 / TBD, Reference: Phase 33 + Phase 39 +
    ADR § Future audit cadence).

    STATE.md: bump completed_phases 3→4, total_plans 10→11, completed_plans 10→11;
    flip Current Position to Phase 39 (upst4-audit) — Phase complete — ready for
    verification; insert Plan 39-01 close entry under Key Decisions (v2.4) with
    all 7 D-39-B2 close-gate checks confirmed PASS.

    Refs: REQ-UPST4-01, D-39-B2, D-39-B4, D-39-E6
    Signed-off-by: <user-name> <user-email>
    ```

    Commit C (39-01-SUMMARY.md):
    ```
    docs(39-01): SUMMARY

    Mirrors Phase 33 Plan 33-01-SUMMARY shape. Records the 7 D-39-B2 close-gate
    PASS evidence + decisions implemented (D-39-A1..E6) + Phase 40 hand-off.

    Refs: REQ-UPST4-01
    Signed-off-by: <user-name> <user-email>
    ```

    Auditor may fold (B) into (A) or split further per CONTEXT § Claude's Discretion + Phase 33 33-01 precedent (Phase 33 used 2 commits: 5fa0dca4 ledger + 63a37d17 SUMMARY; ROADMAP/STATE landed separately in 8f783c39 at Plan 33-03 close).

    After committing, run a final close-gate confirmation:
    ```bash
    # D-39-B2 step 7 substitute on Windows host: structural-zero-risk invariant
    test $(git diff --name-only HEAD~3..HEAD -- crates/ bindings/ scripts/ | wc -l) -eq 0 && echo "D-39-E5-invariant-final-ok"
    ```
  </action>
  <verify>
    <automated>grep -E "^Phase: 39 \(upst4-audit\)" .planning/STATE.md &amp;&amp; grep -E "Phase 39 Plan 39-01" .planning/STATE.md &amp;&amp; test -f .planning/phases/39-upst4-audit/39-01-SUMMARY.md &amp;&amp; grep -E "^phase: 39-upst4-audit$" .planning/phases/39-upst4-audit/39-01-SUMMARY.md &amp;&amp; grep -E "REQ-UPST4-01" .planning/phases/39-upst4-audit/39-01-SUMMARY.md &amp;&amp; test $(git diff --name-only HEAD~3..HEAD -- crates/ bindings/ scripts/ 2&gt;/dev/null | wc -l) -eq 0 &amp;&amp; echo OK</automated>
  </verify>
  <done>
    - STATE.md frontmatter bumped: completed_phases 3→4, total_plans 10→11, completed_plans 10→11, last_updated stamped, last_activity stamped
    - STATE.md Current Position flipped to `Phase: 39 (upst4-audit) — EXECUTING` / `Status: Phase complete — ready for verification`
    - STATE.md `### Key Decisions (v2.4)` block gains Plan 39-01 close entry at top (reverse-chronological order), single-paragraph shape mirroring Phase 33 Plan 33-01 entry, with all 7 D-39-B2 close-gate PASS evidence
    - `.planning/phases/39-upst4-audit/39-01-SUMMARY.md` exists with required frontmatter (phase, plan, status, requirements, commits, date, provides) + required sections (Plan summary, Decisions implemented, Validation results, Deviations, Hand-off to Phase 40)
    - All 7 D-39-B2 close-gate checks PASS (drift idempotent, row count >= drift count, cluster completeness, ADR review section grep, UPST5 stub grep, STATE.md updated, make ci or D-39-E5 invariant substitute)
    - 2-3 atomic commits landed with DCO sign-offs and Refs lines citing the relevant D-39-* decision IDs
    - D-39-E5 invariant final-confirm: `git diff --name-only HEAD~3..HEAD -- crates/ bindings/ scripts/` returns 0 files
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Drift-tool JSON → ledger curation | Tool output is regenerable from upstream git history; ledger curation is auditor judgment translating data → strategic dispositions (will-sync / fork-preserve / won't-sync). Same boundary as Phase 33 Plan 33-01. |
| `upstream/main` git refs → audit | Treats upstream commit history at `https://github.com/always-further/nono.git` as the source of truth — tampering at the upstream remote would silently propagate, but is detectable via the `upstream_head_at_audit` sha in the ledger frontmatter (D-39-D1 locked at first commit of Plan 39-01). |
| Auditor judgment → windows-touch column | Mechanical heuristic (D-39-C2) is deterministic; judgment-override is documented inline in cluster rationale where it fires. Override decisions are visible in code review. |

## STRIDE Threat Register

Phase 39 ships ONLY documentation + ROADMAP + STATE edits (zero `.rs` / `.toml` / `.sh` / `.ps1` / `Makefile` edits per D-39-E5). The threat model is trivial — no new attack surface introduced. Inherited from Phase 33 Plan 33-01 with one Phase-39-specific addition (T-39-01-05 for the windows-touch column).

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-39-01-01 | T (Tampering) | Ledger row data — sha / subject / categories / files-changed / windows-touch falsification | mitigate | Source-of-truth is drift-tool JSON output. Ledger frontmatter captures `drift_tool_sh_sha` + `upstream_head_at_audit` + locked invocation verbatim per D-39-A2. Re-running the invocation MUST produce the same row set (idempotent; D-39-B2 close-gate step 1 enforces this). Disposition assignments are auditor judgment NOT data — falsifying them would be visible in code review against the cluster rationale lines. windows-touch column values are reproducible from the D-39-C2 mechanical heuristic — overrides documented inline. |
| T-39-01-02 | I (Information Disclosure) | Drift JSON raw output | accept | Per D-39-A2 / D-39-E1, raw JSON is NOT committed (stored at `ci-logs-local/drift/drift-v053.json` per Phase 33 33-01 Rule 3 deviation precedent and discarded). Contains only public upstream commit data — no secrets. `ci-logs-local/` is in `.gitignore`. Acceptable. |
| T-39-01-03 | E (Elevation of Privilege) | `make check-upstream-drift` script execution | accept | The script is read-only against the local git repo (D-11 path filter, `--format json` output mode); does not write to the working tree, does not network beyond `upstream/main` ref reading. Phase 24 ship gate already audited this; drift-tool sha unchanged since 2026-04-29. |
| T-39-01-04 | R (Repudiation) | Per-cluster disposition rationale | mitigate | D-39-C3 windows-touch-defaults-to-fork-preserve invariant + the audit cadence rule (D-39-E6) require disposition rationales to be specific. Generic rationales fail code review at the SUMMARY-writeback stage; the `## ADR review` section (D-39-C4) provides a falsifiable confirmation that the Phase 33 ADR remains compatible. |
| T-39-01-05 | T (Tampering) | windows-touch column falsification (Phase 39-specific) | mitigate | D-39-C2 mechanical heuristic is deterministic and reproducible from drift JSON. Auditor judgment-overrides are documented inline in cluster rationale. D-39-C3 conservative-default (windows-touch:yes ⇒ fork-preserve) means falsifying `yes` → `no` to allow a will-sync cherry-pick would still require auditor diff-inspection sign-off in the rationale — the falsification surface is small and visible. Phase 40 plan-phase reviews the ledger and can downgrade dispositions if it surfaces wrong calls. |
</threat_model>

<verification>
**D-39-B2 close-gate (7 falsifiable checks; all must PASS before plan close):**

1. **Drift-tool idempotence:** `make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json" > /dev/null 2>&1; echo $?` returns 0.
2. **Row count coverage:** `grep -cE "^\| [0-9a-f]{7,40} \|" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` ≥ `jq -r '.total_unique_commits' ci-logs-local/drift/drift-v053.json`.
3. **Cluster completeness:** count of `### Cluster: ` headers == count of `**Disposition:** \`?(will-sync|fork-preserve|won't-sync)\`?$` lines == count of `**Rationale:** ` lines.
4. **ADR review section present:** `grep -c "^## ADR review$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` == 1.
5. **UPST5 stub committed:** `grep -E "^## v2.5 backlog$" .planning/ROADMAP.md && grep -E "^### Phase TBD-NN: UPST5 — Upstream v0.53.0" .planning/ROADMAP.md`.
6. **STATE.md updated:** `grep -E "Phase 39 Plan 39-01" .planning/STATE.md && grep -E "^Phase: 39 \(upst4-audit\)" .planning/STATE.md`.
7. **make ci passes** (or D-39-E5 invariant substitute on Windows host per Phase 33 33-01 Rule 3 precedent): `git diff --name-only HEAD~3..HEAD -- crates/ bindings/ scripts/ | wc -l` == 0 (Phase 39 ships zero .rs / .toml / .sh / .ps1 / Makefile edits — structurally zero clippy/fmt/test risk).

**Additional structural invariants:**

- `grep -E "^drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` returns 1 line.
- `grep -E "^range: v0.52.0..v0.53.0$" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` returns 1 line.
- `grep -E "5d821c12|0748cced" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` returns at least 2 lines (the two known windows-touch:yes commits).
- `grep -cE "\| (yes|no) \|" .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` returns at least N (where N == total_unique_commits) — every commit-row carries a windows-touch verdict.
</verification>

<success_criteria>
- REQ-UPST4-01 acceptance fully met: DIVERGENCE-LEDGER.md artifact exists with all v0.52.1..v0.53.0 commits dispositioned; per-cluster rationale references fork-only surface area + D-39-C3 windows-touch default where applicable; explicit `## ADR review` section present (D-39-C4) and confirms Phase 33 ADR Option A `continue` remains Accepted.
- Audit is reproducible from frontmatter: `range` + `upstream_head_at_audit` + `drift_tool_sh_sha` + `drift_tool_invocation` allow any reader to rerun the audit against the same input set (D-39-A2 / D-39-E1 satisfied).
- Phase 39 ledger is the immutable input for Phase 40 UPST4 sync execution (D-39-B3 disposition-complete-at-Phase-39-close + foundation/dependency hints).
- UPST5 placeholder queued in ROADMAP § v2.5 backlog with Depends on: Phase 40, Plans: 0 / TBD (D-39-B4); cadence rule from Phase 33 ADR § Future audit cadence is honored (D-39-E6).
- STATE.md reflects Plan 39-01 closure with all 7 D-39-B2 close-gate PASS evidence; ready for `/gsd-verify-work` verifier pass.
- D-39-E5 Windows-only-files invariant trivially honored: zero `.rs` / `.toml` / `.sh` / `.ps1` / `Makefile` edits across the Phase 39 commit chain.
</success_criteria>

<output>
After completion, the Phase 39 directory contains:
- `DIVERGENCE-LEDGER.md` (NEW, ~150-200 lines) — canonical audit artifact for v0.52.0..v0.53.0; binding input for Phase 40
- `39-01-SUMMARY.md` (NEW) — plan-close summary mirroring Phase 33 Plan 33-01 shape
- `39-CONTEXT.md` (UNCHANGED, locked at 2026-05-13)
- `39-PATTERNS.md` (UNCHANGED, locked at 2026-05-13)
- `39-DISCUSSION-LOG.md` (UNCHANGED)
- `39-01-DIVERGENCE-AUDIT-PLAN.md` (this plan, UNCHANGED post-write)

Project-level edits:
- `.planning/ROADMAP.md` — Phase 39 entry flipped to [x] complete; Phase Details Plans counter flipped to 1/1; new `## v2.5 backlog` section with UPST5 stub
- `.planning/STATE.md` — completed_phases counter bumped; Current Position flipped to Phase 39 ready for verification; Plan 39-01 close entry inserted under Key Decisions (v2.4)

Next step: `/gsd-verify-work 39` (gsd-verifier sub-agent will produce `39-VERIFICATION.md` with PASS/FAIL evidence against the must_haves block above; expected 17/17 PASS given the D-39-B2 close-gate already enforces the same checks).
</output>
