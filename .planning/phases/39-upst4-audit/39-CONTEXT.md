---
phase: 39
phase_name: upst4-audit
gathered: 2026-05-13
status: Ready for planning
requirements_locked_via: REQUIREMENTS.md § REQ-UPST4-01 (no SPEC.md — audit-only phase mirrors Phase 33 shape)
---

# Phase 39: UPST4 audit - Context

**Gathered:** 2026-05-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 39 ships ONE artifact: a falsifiable, disposition-complete `DIVERGENCE-LEDGER.md` inventory of every upstream commit in `v0.52.0..v0.53.0` (3 confirmed tags — `v0.52.1` `21bbb82e`, `v0.52.2` `e8bf0148`, `v0.53.0` `c4b25b82`; ~27 non-merge commits). Per-cluster disposition (`will-sync` / `fork-preserve` / `won't-sync`) + rationale, sized identically to Phase 33's audit-shape template. The ledger is the binding input for Phase 40 (UPST4 sync execution).

Phase 39 also queues an UPST5 placeholder phase entry in `ROADMAP.md` § v2.5 backlog so the cadence wheel keeps turning, per the Phase 33 ADR's "per upstream release, lazily-evaluated" rule (`docs/architecture/upstream-parity-strategy.md` § Future audit cadence).

**In scope:**
- Run `make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"` at phase-start and curate themed clusters with per-cluster disposition + rationale.
- Write `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` mirroring Phase 33's two-tier schema (cluster headers + nested commit-row tables).
- Add a `windows-touch: yes/no` column to commit-row tables — D-39-C1 (Phase 39-specific; Phase 33 range had ZERO upstream commits touching Windows code outside D-11-excluded paths, but the v0.52.0..v0.53.0 range adds new upstream Windows code in `feat(platform): robust windows platform detection` and `fix(platform): correctly parse windows registry dword values`).
- Document Windows-touching cluster disposition default (`fork-preserve` unless empty fork-side) in an `## ADR review` section.
- Queue an UPST5 placeholder phase entry in `ROADMAP.md` § v2.5 backlog: title `UPST5 — Upstream v0.53.0…+ sync audit`, `Depends on: Phase 40`, `Plans: 0 / TBD`.
- Update `.planning/STATE.md` at phase close.

**Out of scope (route elsewhere or explicitly defer):**
- **Any actual cherry-picks, manual replays, or code changes** — Phase 40 is the execution phase by construction; Phase 39 is audit + queue only.
- **Post-v0.53.0 commits** (7 unreleased commits between `c4b25b82` and upstream HEAD `b4f21611` at the time of context capture). UPST5 absorbs them per the lock-at-phase-start rule (D-39-D1).
- **Strategic ADR re-decision** — Phase 33 ADR Option A `continue` stays Accepted; Phase 39's ADR review section confirms or flags, doesn't supersede.
- **Drift-tool fixes** — if the audit surfaces a tool bug, the ledger documents the bug and the auditor creates a `.planning/quick/` follow-up task; Phase 39 itself stays untouched (D-39-D3).
- **Fork-only-surface re-enumeration** — Phase 33 already enumerated the fork-only Windows seams; Phase 39 references that section. Only delta-since-Phase-33 fork-only additions (e.g., Phase 35 + 36 + 36.5 Windows-touch points if any) get noted, not re-enumerated wholesale.
- **G-XX-DRIFT gap closure** — Phase 33's G-25-DRIFT-01 closed in Phase 34. Phase 39 has no equivalent upstream-gap to close.

</domain>

<decisions>
## Implementation Decisions

### Audit invocation, scope, and reproducibility (Area A)

- **D-39-A1:** **Upper bound = v0.53.0 release boundary, not upstream HEAD.** Audit range = `v0.52.0..v0.53.0` (sha `c4b25b82`, ~27 non-merge commits across 3 tags). Matches Phase 33 pattern (which capped at v0.52.0 release tag, not upstream HEAD). Clean reproducibility — any reader rerunning the audit against the same tag pair gets the same input set. Post-v0.53.0 commits roll into UPST5.

- **D-39-A2:** **Frontmatter reproducibility matches Phase 33 (D-33-A1 + D-33-A2 inherited).** Ledger frontmatter captures:
  - `range: v0.52.0..v0.53.0`
  - `upstream_head_at_audit: <sha captured at first commit of Plan 39-01>`
  - `drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559` (Phase 24 ship sha; unchanged at audit time)
  - `drift_tool_ps1_sha: 0834aa664fbaf4c5e41af5debece292992211559`
  - `drift_tool_invocation: 'make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"'`
  - `fork_baseline: v0.52.0 (Phase 34 UPST3 sync point — 2026-05-12)`
  - `date: 2026-MM-DD`
  Raw drift JSON is NOT committed (D-33-A2 inherited); the ledger is the canonical artifact.

- **D-39-A3:** **Strictly silent on post-v0.53.0 commits.** Ledger covers v0.52.0..v0.53.0 only. Anything past `c4b25b82` is UPST5's problem; mentioning it would muddy the audit boundary. Matches Phase 33's posture (it didn't mention any v0.53.0 commits known at audit time even though tags existed). The cadence rule is structural — each audit closes a defined range, next audit picks up where this one left off.

### Plan slicing, close-gate, and Phase 40 hand-off (Area B)

- **D-39-B1:** **Single plan (`39-01-DIVERGENCE-AUDIT`).** One plan does: drift run → cluster curation → ledger write → ADR review check → ROADMAP UPST5 stub → STATE.md update. Phase 33 had 4 plans because it also wrote a strategic ADR (Plan 33-02) and closed G-25-DRIFT-01 (Plan 33-03); Phase 39 has neither. ~27 commits is small enough that splitting adds overhead without traceability benefit.

- **D-39-B2:** **Close-gate = Phase 33 D-33-style + explicit ADR-review-section check:**
  1. `make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"` exits 0 (drift tool reproduces against the locked range).
  2. `DIVERGENCE-LEDGER.md` row count ≥ count of items the drift tool flagged.
  3. Every cluster has disposition (`will-sync` / `fork-preserve` / `won't-sync`) + one-line rationale.
  4. `## ADR review` section present (even a one-line "no clusters contradict Option A" stub) — falsifiable via grep for the section header.
  5. ROADMAP UPST5 stub committed under v2.5 backlog (D-39-B4 below).
  6. STATE.md updated.
  7. `make ci` passes (uneventful — Phase 39 ships only docs + ROADMAP edits).
  No cross-target clippy gate (Phase 25 CR-A lesson) needed — Phase 39 touches zero `.rs` files.

- **D-39-B3:** **Disposition-complete at Phase 39 close + foundation/dependency hints (no full wave map).** Every cluster's disposition is locked at Phase 39 close — Phase 40 inherits an immutable input (matches how Phase 34 inherited Phase 33's ledger). Additionally, Phase 39 ledger may tag the largest/most-foundational cluster as `wave-hint: foundation` (analog to Phase 33 D-33-B2 / Phase 34 D-34-A2 "C7 first") and may flag cluster dependencies inline (e.g., `wave-hint: depends-on cluster-N final state`). Phase 40 planner has full discretion to refine wave membership; Phase 39's hints are advisory, not prescriptive. No Phase 33-style "Wave 0/1/2/3" mapping — that's still Phase 40's call.

- **D-39-B4:** **UPST5 ROADMAP queue lands as v2.5 backlog stub.** Phase 39 closes by adding a Phase-N (TBD-NN) entry under `ROADMAP.md` § v2.5 backlog (NOT v2.4 active milestone). Stub shape:
  - Title: `UPST5 — Upstream v0.53.0… sync audit` (auditor picks `… audit` vs `… sync execution` based on Phase 39 ledger shape — if all clusters are clean cherry-picks, no separate audit needed for the next cycle; auditor judges)
  - `Depends on: Phase 40`
  - `Plans: 0 / TBD`
  - Cross-reference to `docs/architecture/upstream-parity-strategy.md` § Future audit cadence
  Backlog (not active milestone) preserves the cadence-rule signal without committing to a v2.4 slot.

### Windows-touching upstream commits (Area C — Phase 39-specific)

- **D-39-C1:** **Inline `windows-touch: yes/no` column on commit-row tables.** Add a column to the standard row schema (per D-33-B3) that marks commits touching Windows code outside D-11-excluded paths. Schema becomes: `sha + subject + upstream-tag + categories + files-changed-count + windows-touch`. Reader scans the column to spot Windows-touching upstream surface immediately. Known commits in the v0.52.0..v0.53.0 range that will trigger `windows-touch: yes`:
  - `5d821c12 fix(platform): correctly parse windows registry dword values` (v0.53.0)
  - `0748cced feat(platform): implement robust windows platform detection` (v0.53.0)
  Any more surface during audit-walk; auditor confirms.

- **D-39-C2:** **Detection methodology = mechanical filename heuristic + judgment override.**
  1. **Mechanical pass:** `windows-touch: yes` iff any file in `files_changed` matches `windows` substring, OR matches the pinned list `{platform.rs, registry.rs, wfp/*, win_*.rs}`, OR commit subject contains `windows` / `wfp` / `registry` / `wsa` / `ntdll` / `kernel32` keywords. Easy to apply uniformly.
  2. **Judgment override:** For any cluster's lead commit AND any flagged commit whose subject is ambiguous re: Windows-touch (e.g., a generic `feat(platform)` could be Windows-only or cross-platform), auditor reads the diff and confirms or overrides the mechanical flag. Same audit-walk-of-ambiguous-commits methodology Phase 33 used for disposition decisions (Phase 33 § Inspection methodology).

- **D-39-C3:** **Windows-touch defaults to `fork-preserve` UNLESS empty fork-side.** Disposition decision logic for `windows-touch: yes` commits:
  - If upstream introduces NEW Windows code in a path the fork doesn't have yet (e.g., upstream adds `crates/nono/src/platform.rs` with Windows-conditional logic and the fork has no `platform.rs` analog), default disposition = `fork-preserve` (manual replay). Rationale: protects against accidental D-11 breakage where straight cherry-pick could collide with fork-only `*_windows.rs` files.
  - If upstream modifies an existing cross-platform file with a small Windows-conditional addition that composes cleanly with fork's existing code, disposition CAN flip to `will-sync` — but ONLY after auditor confirms straight cherry-pick is safe via diff inspection.
  - This default is conservative on purpose: Phase 40 inherits a safer execution baseline, and any `fork-preserve` cluster always has the option to upgrade to `will-sync` at Phase 40 plan-phase if the auditor's caution turns out to be excessive. The reverse (downgrade `will-sync` to `fork-preserve` mid-execution) is more expensive.

- **D-39-C4:** **Explicit `## ADR review` section in the ledger.** When Phase 39 surfaces Windows-touch defaults (per D-39-C3), the ledger gains a dedicated `## ADR review` section near the end (before the Fork-only surface area section, if present). Section notes: (a) audit surfaced upstream Windows-code additions outside D-11-excluded paths, (b) Phase 33 ADR Option A `continue` did not anticipate this shape explicitly, (c) `fork-preserve` default applied per D-39-C3 to protect D-11 invariant, (d) Phase 33 ADR remains `Accepted` — no superseding ADR needed yet. Falsifiable: grep for `## ADR review` finds the section.

### Re-audit posture and mid-phase drift (Area D)

- **D-39-D1:** **Lock audit range at first commit of Plan 39-01.** Auditor runs `git fetch upstream --tags` then captures `upstream/main` sha into the ledger frontmatter (`upstream_head_at_audit`) as the FIRST act of Plan 39-01. Range = `v0.52.0..v0.53.0`; `upstream_head_at_audit` records the post-fetch HEAD for reproducibility against the historical fetch state. Matches Phase 33 D-33-A1 + A2 posture. New upstream commits landing during the audit week are ignored; they roll into UPST5.

- **D-39-D2:** **Post-lock upstream commits → UPST5 absorbs them.** If a security-relevant upstream commit lands between Phase 39 close and Phase 40 start, Phase 39 ledger stays frozen as historical record. Phase 40 plan-phase may re-run `make check-upstream-drift` if urgency demands faster turnaround — that's a Phase 40 scope re-evaluation, NOT a Phase 39 retroactive edit. Default: UPST5 (queued via D-39-B4) is the absorption vehicle. The lock is structural; preserving reproducibility outweighs the cost of one absorption-cycle delay.

- **D-39-D3:** **Drift-tool bugs documented inline + spawn `.planning/quick/` follow-up task.** If the auditor discovers a drift-tool bug mid-phase (category miscategorized, file filter misses a cross-platform path, etc.), the audit ledger documents the bug inline (e.g., "category `package` over-flagged 2 commits as profile-relevant due to D-05 heuristic limitation") AND the auditor creates a quick-task entry under `.planning/quick/YYMMDD-xxx-upstream-drift-tool-fix/` capturing the fix scope. Phase 39 itself stays untouched — fixing the drift tool mid-audit would invalidate the `drift_tool_sh_sha` frontmatter and break reproducibility. The fix lands in a separate phase or quick-task; Phase 40 may re-run with the fixed tool to confirm cluster boundaries hold, or carry forward the documented limitation.

### Carry-Forward From Phase 33 (still binding)

- **D-39-E1 (= Phase 33 D-33-A1/A2):** Drift-tool invocation in ledger frontmatter is the audit-of-record; raw JSON not committed; reproducible against tag pair + drift-tool sha.
- **D-39-E2 (= Phase 33 D-33-B1):** Phase-local ledger location (`.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md`). No cross-phase append.
- **D-39-E3 (= Phase 33 D-33-B2):** Two-tier structure (cluster headers + nested commit-row tables); reader sees strategic disposition at a glance via cluster headers; commit-level audit trail in nested tables.
- **D-39-E4 (= Phase 33 D-33-B3, extended):** Standard row schema = `sha + subject + upstream-tag + categories + files-changed-count + windows-touch`. The `windows-touch` column is the Phase 39 addition (D-39-C1). Disposition + rationale live at the CLUSTER level, not per-row.
- **D-39-E5 (= Phase 22 D-17 / Phase 34 D-34-E1):** Windows-only files structurally invariant. Phase 39 does not edit `*_windows.rs` or `exec_strategy_windows/`. Trivially honored (Phase 39 ships only docs + ROADMAP edits).
- **D-39-E6 (= Phase 33 ADR cadence rule):** "Per upstream release, lazily-evaluated" — Phase 39 closes when v0.52.0..v0.53.0 is fully dispositioned; UPST5 fires when v0.54.0+ ships or maintainer decides cherry-pick labor warrants absorbing accumulated post-v0.53.0 commits.

### Claude's Discretion

- **Cluster grouping heuristic.** D-33-B2 / D-39-E3 says cluster related commits, but cluster boundaries (e.g., "scrubbing optimization" as one cluster vs. split between feature commit and refactor commit) are the auditor's judgment call during the audit walk.
- **Per-cluster `wave-hint` granularity.** D-39-B3 allows but does not require wave hints on every cluster. The auditor decides whether a cluster's wave shape is interesting enough to flag (e.g., a `wave-hint: foundation` on the largest cluster is high-value; per-cluster wave numbers are over-prescriptive).
- **UPST5 stub title wording.** D-39-B4 names two candidate titles (`… sync audit` vs `… sync execution`). Auditor picks based on Phase 39 ledger shape — if dispositions are simple and the next cycle could be a single-plan execution phase without a separate audit, title flips to `… sync execution`. Otherwise default to `… audit`.
- **Whether to capture a `Fork-only surface area` delta section.** Phase 33 enumerated 6+ fork-only seams (broker, NONO_TEST_HOME, Authenticode chain-walker, broker dispatch arm, TUF cached-root, broker self-trust-anchor). Phase 39 may add a § Delta-since-Phase-33 fork-only surface section if Phase 35 / 36 / 36.5 introduced new fork-only Windows surface — or may reference Phase 33's enumeration unchanged. Auditor decides based on what the audit walk surfaces.
- **Ledger header exact wording** beyond the frontmatter fields locked in D-39-A2 (invocation, head sha, tool shas, range, date) — wording is the auditor's call. Phase 33's Headline section format is a good template; replicating that shape verbatim is acceptable.
- **`make ci` re-run cadence.** Standard project gate (D-39-B2 step 7) — auditor may run `make ci` once at plan close OR per-commit if the curation surfaces any tooling change concerns. Either is acceptable.

### Folded Todos

None — no pending todos matched Phase 39 scope. The 4 surfaced matches (`v24-cr-01..04`) are Phase 31 broker review CR carry-forwards (BrokerNotFound FFI mapping, null-handle validation, empty-handle-list path, job-object test-skip policy) that scored 0.6 on generic "phase, review, planning" keywords but are topically unrelated to UPST4 upstream audit work. See `<deferred>` § Reviewed Todos.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 39 scope sources
- `.planning/REQUIREMENTS.md` § REQ-UPST4-01 — Acceptance criteria (DIVERGENCE-LEDGER produced; per-cluster rationale references fork-only surface; explicit ADR review section if any cluster contradicts Option A). REQ-UPST4-02 lives in Phase 40.
- `.planning/ROADMAP.md` § Phase 39 (lines 209–221) — Goal, depends-on Phase 34, reference list (Phase 33 audit-shape template, parity-strategy ADR).
- `.planning/PROJECT.md` § Current Milestone — v2.4 scope-themes (Theme 3 — UPST4); Phase 39 is the v2.4 Theme 3 audit half.

### Phase 33 audit-shape template (MANDATORY reading)
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/33-SPEC.md` — 5 requirements + acceptance criteria for the audit-shape template; Phase 39 mirrors REQ-1 (drift audit) inheritance.
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/33-CONTEXT.md` — D-33-A1..D-33-D2 decision IDs (drift-tool invocation D-33-A1, raw JSON not committed D-33-A2, fork-only surface enumeration D-33-A3, phase-local ledger D-33-B1, two-tier structure D-33-B2, row schema D-33-B3, ADR convention D-33-C4, G-25 update shape D-33-D2). Phase 39 D-39-E1..E6 inherit verbatim or near-verbatim.
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md` — **the worked example.** 300-line ledger with frontmatter + Headline + Reproduction + Cluster Summary table + 12 cluster sections + Fork-only surface area section. Phase 39 mirrors this shape with the `windows-touch` column added per D-39-C1.

### Phase 34 execution-shape template (informs disposition decisions)
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md` — D-34-A1..E5 (per-cluster plan slicing, foundation gate, fork-preserve handling, surgical retrofit posture, Windows-only files invariant, D-19 trailer block, manual port for heavily-diverged files). Phase 39's `wave-hint: foundation` (D-39-B3) is the analog of D-34-A2 "C7 first as Wave 0 foundation".
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-VERIFICATION.md` — 10 NEEDS-FOLLOW-UP-PLAN deferrals surfaced; informs Phase 40 about the partial-port risk class Phase 39's dispositions should anticipate.

### Strategic ADR (LOCKED, do not supersede in Phase 39)
- `docs/architecture/upstream-parity-strategy.md` — **Phase 33 strategic ADR, `Status: Accepted` 2026-05-11.** Option A `continue` chosen. § Future audit cadence (line 94–96) defines the "per upstream release, lazily-evaluated" rule Phase 39 honors. Phase 39's § ADR review section (D-39-C4) confirms compatibility; does NOT supersede.

### Drift-tool infrastructure (Phase 24)
- `scripts/check-upstream-drift.sh` + `scripts/check-upstream-drift.ps1` — Drift-tool twin scripts. Sha `0834aa664fbaf4c5e41af5debece292992211559` (Phase 24 ship sha; unchanged since 2026-04-29). Phase 39 invokes via `make check-upstream-drift`.
- `Makefile` § `check-upstream-drift` target — dispatches platform-appropriate script.
- `.planning/phases/24-parity-drift-prevention/24-CONTEXT.md` — D-04..D-19 drift-tool decisions (categorization D-05, range auto-detect D-08, fork-only filter D-11, JSON schema D-07). D-11 path filter on `*_windows.rs` + `exec_strategy_windows/` is the key invariant Phase 39 honors when interpreting drift-tool output.
- `docs/cli/development/upstream-drift.mdx` — long-form runbook (output formats, categorization rules, fixture regeneration procedure, fork-divergence catalog rationale).

### Sync execution mechanics (referenced by Phase 40, mentioned for context)
- `.planning/templates/upstream-sync-quick.md` — MANDATORY scaffold for every Phase 40 plan; D-19 cherry-pick trailer block (verbatim 6-line shape with lowercase 'a' in `Upstream-author:`). Phase 39 does NOT use this directly (no cherry-picks); Phase 40 plans inherit it from the Phase 34 pattern.

### Coding & security standards
- `CLAUDE.md` § Coding Standards — no `.unwrap()`, DCO sign-off (`Signed-off-by:` lines), `#[must_use]` on critical Results, env-var save/restore in tests. Phase 39 ships only docs; trivially honored.
- `CLAUDE.md` § Security Considerations — path component comparison, fail-secure on any unsupported shape. Phase 39's audit interpretation lens for any cluster that touches path canonicalization or trust scanning.

### Upstream source (git-resolvable from `upstream` remote at `https://github.com/always-further/nono.git`)
- Tag `v0.52.0` (`5d15b50`) — Phase 34 UPST3 sync point; Phase 39 baseline.
- Tag `v0.52.1` (`21bbb82e`) — first tag in Phase 39 range.
- Tag `v0.52.2` (`e8bf0148`).
- Tag `v0.53.0` (`c4b25b82`) — Phase 39 upper bound.
- Upstream HEAD at context-capture time: `b4f21611` (2026-05-13). Phase 39 plan locks `upstream_head_at_audit` at first commit of Plan 39-01 (D-39-D1) — may shift from this value if upstream commits land before Plan 39-01 starts. Range stays `v0.52.0..v0.53.0` regardless.

### v2.4 milestone context
- `.planning/STATE.md` — current milestone v2.4 status; Phase 39 follows Phase 38 (Phase 27 reopen, optional).
- `.planning/milestones/v2.4-MILESTONE-CONTEXT.md` — scope-themes captured 2026-05-12; Theme 3 is UPST4.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`make check-upstream-drift` tooling (Phase 24)** — `scripts/check-upstream-drift.{sh,ps1}` (sha `0834aa66`, unchanged since Phase 24 ship 2026-04-29). Phase 39 invokes once for the audit (D-39-A2 captures invocation verbatim in ledger frontmatter).
- **Phase 33 DIVERGENCE-LEDGER.md as a worked template.** 300-line artifact with frontmatter + Headline + Reproduction + Cluster Summary + 12 cluster sections + Fork-only surface area. Phase 39 replicates the shape with the `windows-touch` column added (D-39-C1).
- **Phase 33 ADR `docs/architecture/upstream-parity-strategy.md`** — locked Accepted; § Future audit cadence defines the cadence rule Phase 39 honors. Phase 39's § ADR review section confirms cluster dispositions don't contradict Option A.
- **Phase 34 wave-hint precedent (D-34-A2 "C7 first as Wave 0 foundation").** Phase 39 may tag the largest/most-foundational cluster the same way (D-39-B3).

### Established Patterns

- **`upstream` git remote** at `https://github.com/always-further/nono.git`; tags v0.40.1..v0.53.0 fetched locally (verified 2026-05-13). No setup work.
- **Phase-local ledger convention (D-33-B1 / D-39-E2).** Each audit phase owns its own ledger artifact in its own phase dir. No cross-phase append.
- **D-11 fork-only Windows filter (Phase 24 D-08).** Drift tool excludes `*_windows.rs` and `crates/nono-cli/src/exec_strategy_windows/` from output. Phase 39 must STILL detect upstream commits adding NEW Windows code outside that filter (D-39-C1/C2) — D-11 is necessary but not sufficient.
- **Two-tier ledger structure (D-33-B2 / D-39-E3).** Cluster headers carry strategic disposition; nested commit-row tables carry audit trail. Phase 33 worked example shipped in 300 lines for 97 commits / 12 clusters; Phase 39's smaller range should ship in ~150–200 lines.
- **Lazily-evaluated cadence (D-39-E6).** ADR § Future audit cadence rule fires per upstream release; Phase 39 absorbs all 3 v0.52.1/v0.52.2/v0.53.0 tags in one cycle (~27 commits — Phase 33 absorbed 12 minor releases / 97 commits in one cycle; the cadence rule supports both granularities).

### Integration Points

- `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` — NEW file Phase 39 creates. Phase 40 reads this as its immutable input.
- `.planning/ROADMAP.md` § v2.5 backlog — Phase 39 appends an UPST5 placeholder phase entry (D-39-B4). New section if v2.5 backlog doesn't exist yet.
- `.planning/STATE.md` — Phase 39 plan-close appends a "Last activity" log entry (auditor's discretion on exact wording).
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md` — READ-ONLY reference. Phase 39 does NOT modify Phase 33's ledger.
- `docs/architecture/upstream-parity-strategy.md` — READ-ONLY reference. Phase 39 does NOT supersede this ADR.

### Drift signal preview (informational, NOT a disposition pre-commit)

Pre-audit commit listing for v0.52.0..upstream-HEAD (34 non-merge commits; 27 land in v0.52.0..v0.53.0 audit range):
- v0.52.1 tag (`21bbb82e`): `f6684e56 fix: match backend validation logic`, `bfe1fc63 fix(schema): add missing 'environment' property to profile JSON schema`, `5e6e7caa Update crates/nono-proxy/src/server.rs`, `eedfbcd6 Update crates/nono-proxy/src/server.rs`, `be8cd00d fix: provide more accurate warning message + doc comment update`, `f090d813 fix: preserve two keyboard-mode resets`, `d9dcf950 fix: documented concat! blocks instead of opaque byte blobs`, `c444c7f9 fix(pty): stop clearing terminal scrollback on exit for normal-mode sessions`, `f72ea317 fix(cli): validate --allow paths and persist domain allowlist in sandbox state`, `85f0acca fix(cli): make 'nono why --host' aware of proxy domain filtering`, `9b07bf77 feat(profile-save): suppress save-profile prompts for denied paths`, `c20de43e fix(policy): expand browser deny groups with missing Chromium-based browsers`, `5a618084 fix: return full failure diagnostic`, `5b619717 fix(sandbox): cache Landlock ABI detection with OnceLock`, `abc86f6d fix: prevent feature unification from linking libdbus in no-keyring builds`, `54f7c32a docs(agents): relax agent disclosure and expand campaign ban`, `d57375e7 fix(proxy): set NODE_USE_ENV_PROXY for Node 26`, `eb6cb092 fix(profile-save): address suppression review feedback`, `d0612f4b chore: release v0.52.1`
- v0.52.2 tag (`e8bf0148`): `8ddb143e feat: fix upstream TLS trust, intercept auth, and multi-route dispatch.`, `54c7552d fix: review comments`
- v0.53.0 tag (`c4b25b82`): `78114e6a refactor(scrub): optimize and simplify scrubbing logic`, `f77e0e3c fix: absolute match / 2 matches = deny / no match = passthrough w no creds`, `ce06bd59 feat(profile): add platform-conditional profile fields`, `6472011e feat(core): scrub command arguments for secrets`, `5d821c12 fix(platform): correctly parse windows registry dword values` ⚠ **windows-touch candidate**, `0748cced feat(platform): implement robust windows platform detection` ⚠ **windows-touch candidate**
- Post-v0.53.0 (out of Phase 39 scope, listed for UPST5 awareness only): `803c6947` nix bump, `fc965ccc` tokio bump, `089cf6a0` cosign-installer bump, `66c69f86 fix(snapshot): validate restore targets against symlinks` — UPST5 absorbs.

Likely cluster themes (auditor confirms during audit-walk):
- **Profile JSON schema + proxy server hardening** (v0.52.1) — schema fixes, profile-save suppression, --allow path validation, NODE_USE_ENV_PROXY for Node 26, browser deny-group expansion.
- **Sandbox / Landlock optimization** (v0.52.1) — ABI detection cache via OnceLock; libdbus feature-unification fix; sandbox-feature pluck.
- **PTY scrollback fix** (v0.52.1) — `c444c7f9 fix(pty)`: stop clearing terminal scrollback on exit — directly mirrors fork's Phase 17 attach-streaming concern (auditor's judgment call for fork-preserve vs will-sync given Phase 17 / Phase 18.1 fork-side already shipped its own scrollback fix shape).
- **Proxy TLS trust / multi-route dispatch** (v0.52.2) — likely follow-on to Phase 33 C11 fork-preserve cluster; auditor confirms fork-preserve continues or whether v0.52.2 commits compose cleanly.
- **Secret scrubbing in command arguments + scrub refactor** (v0.53.0) — new audit-event-relevant feature.
- **Platform-conditional profile fields** (v0.53.0) — `ce06bd59 feat(profile)`: could intersect with fork's Windows-conditional profile fields (Phase 22 `unsafe_macos_seatbelt_rules` + Phase 36 canonical sections).
- **Windows platform detection** (v0.53.0) — TWO commits adding new Windows code outside D-11; trigger D-39-C3 fork-preserve default.

These are **informational only** — the audit walk produces the authoritative cluster grouping + disposition per the methodology in D-39-A1..D-39-C4. Phase 39 plan-phase or research-phase may refine.

</code_context>

<specifics>
## Specific Ideas

- **Lock at first commit of Plan 39-01** (D-39-D1) — user explicitly chose first-commit-of-Plan lock over phase-commit-start or ledger-write-commit. Auditor runs `git fetch upstream --tags` then immediately captures `upstream/main` sha into the ledger frontmatter as the FIRST act of Plan 39-01.
- **Inline `windows-touch` column on commit rows** (D-39-C1) — user explicitly rejected the dedicated-section shape and the cluster-level-only shape. Reader scans the column inside each cluster's commit table; no separate § Windows-touching upstream commits section needed.
- **Windows-touch defaults to fork-preserve unless empty fork-side** (D-39-C3) — user chose conservative default over information-only flag. Phase 40 inherits a safer execution baseline; can upgrade to will-sync at plan-phase if audit caution turns out to be excessive.
- **Explicit `## ADR review` section** (D-39-C4) — user chose explicit section over cluster-rationale-only or conditional-threshold approaches. Falsifiable via grep; reviewer can confirm the cadence rule was honored without reading every cluster rationale.
- **Single plan over Phase-33's-4-plan shape** (D-39-B1) — user chose single plan; Phase 33's 4-plan shape was driven by the ADR write + G-25 closure, neither of which Phase 39 has.
- **Disposition-complete at Phase 39 close + foundation/dependency hints** (D-39-B3) — user chose option 3 (disposition-complete + suggested wave order) over disposition-only or full-wave-map. Phase 39 ships disposition + foundation flag + dependency hints; Phase 40 retains full discretion to refine.
- **Drift-tool bugs → document + quick-task, not fold into Phase 39** (D-39-D3) — user explicitly rejected folding tool fixes into Phase 39 to preserve `drift_tool_sh_sha` frontmatter reproducibility.
- **Strictly silent on post-v0.53.0 commits** (D-39-A3) — user rejected one-line cadence note and dedicated watch section. The cadence rule is structural; mentioning post-range commits would muddy the audit boundary.
- **UPST5 stub in v2.5 backlog, not v2.4 active** (D-39-B4) — user chose backlog over inline-v2.4 or one-line-note. Preserves cadence-rule signal without committing v2.4 scope.

</specifics>

<deferred>
## Deferred Ideas

- **Post-v0.53.0 commit absorption** — 7 unreleased commits between `c4b25b82` and upstream HEAD `b4f21611` at context-capture time. UPST5 absorbs per the lazily-evaluated cadence rule (D-39-E6) when v0.54.0 ships or maintainer decides accumulated cherry-pick labor warrants firing.
- **Drift-tool fixes surfaced mid-audit** — if Phase 39 audit-walk reveals a drift-tool category miscategorization or file-filter gap, the fix lands as a `.planning/quick/YYMMDD-xxx-upstream-drift-tool-fix/` quick-task (D-39-D3), NOT folded into Phase 39.
- **Full wave-map for Phase 40** — D-39-B3 ships foundation flag + dependency hints only; Phase 40 planner decides full Wave 0/1/2/3 mapping. If Phase 40 surfaces a recurring need for Phase-39-style wave maps, that's a future audit-shape refinement.
- **Fork-only surface area delta enumeration** — Phase 33 enumerated 6+ fork-only Windows seams; Phase 39 may add a § Delta-since-Phase-33 section if Phase 35/36/36.5 introduced new fork-only Windows surface. Auditor's discretion at audit walk; if nothing new surfaced, Phase 39 just references Phase 33's enumeration.
- **Superseding ADR** — if Phase 39's `## ADR review` section surfaces evidence that Option A `continue` is no longer the right call (e.g., 50% of clusters become fork-preserve), that's a Phase-NN superseding ADR, NOT a Phase 39 inline edit. Phase 33 ADR stays `Accepted` until explicitly superseded.

### Reviewed Todos (not folded)

- `v24-cr-01-broker-not-found-ffi-mapping.md` (score 0.6, area: general) — Re-map `NonoError::BrokerNotFound` to FFI `ErrSandboxInit`. Off-topic: Phase 31 broker CR carry-forward; unrelated to UPST4 upstream audit. Belongs in a Phase 31 follow-up or v2.4-stretch slot.
- `v24-cr-02-broker-null-handle-validation.md` (score 0.6, area: general) — Reject `--inherit-handle 0x0` in nono-shell-broker argv parser. Off-topic; Phase 31 broker CR.
- `v24-cr-03-broker-empty-handle-list-path.md` (score 0.6, area: general) — Document or fix broker's empty `--inherit-handle` list path. Off-topic; Phase 31 broker CR.
- `v24-cr-04-job-object-test-skip-policy.md` (score 0.6, area: general) — Decide silent-SKIP-as-PASS policy for `broker_launch_assigns_child_to_job_object`. Off-topic; Phase 31 broker CR.

All 4 matched on generic "phase, review, planning, phases, architecture" keywords. None topical to upstream-audit scope. Surfaced here for future-phase scoping awareness.

</deferred>

---

*Phase: 39-upst4-audit*
*Context gathered: 2026-05-13*
