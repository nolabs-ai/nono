# Roadmap: nono Windows Parity & Quality

This roadmap tracks the path to full Windows/Unix parity and ongoing quality-of-life work for `nono`.

## Milestones

- ✅ **v1.0 Windows Alpha** — Phases 1–4 (shipped 2026-03-31; tag `v1.0`)
- ✅ **v2.0 Windows Gap Closure** — Phases 5–15 (shipped 2026-04-18; tag `v2.0`)
- ✅ **v2.1 Resource Limits, Extended IPC, Attach-Streaming & Cleanup** — Phases 16–21 + 18.1 (shipped 2026-04-21; tag `v2.1`)
- ✅ **v2.2 Windows/macOS Parity Sweep** — Phases 22–24 (shipped 2026-04-29; tag `v2.2`)
- 🏗️ **v2.3 Linux POC Unblock + Deferreds Closure** — Phases 25–32 + 27.1 (started 2026-04-29)

## Phases

<details>
<summary>✅ v1.0 Windows Alpha (Phases 1–4) — SHIPPED 2026-03-31</summary>

- [x] Phase 1: Windows Control Foundation (3/3 plans) — completed 2026-04-04
- [x] Phase 2: Persistent Sessions (4/4 plans) — completed 2026-04-04
- [x] Phase 3: Network Sandboxing (4/4 plans) — completed 2026-04-04
- [x] Phase 4: State Integrity & Deployment (3/3 plans) — completed 2026-04-05

See `.planning/milestones/v1.0-*` if archived separately; the `v1.0` git tag points at the formal shipped state.

</details>

<details>
<summary>✅ v2.0 Windows Gap Closure (Phases 5–15) — SHIPPED 2026-04-18</summary>

- [x] Phase 5: Windows Detach Readiness Fix (1/1 plan) — completed 2026-04-05
- [x] Phase 6: WFP Enforcement Activation (2/2 plans) — completed 2026-04-06
- [x] Phase 7: Quick Wins (2/2 plans) — completed 2026-04-08
- [x] Phase 8: ConPTY Shell (1/1 plan, UAT-driven) — completed 2026-04-10
- [x] Phase 9: WFP Port-Level + Proxy Filtering (4/4 plans) — completed 2026-04-10
- [x] Phase 10: ETW-Based Learn Command (3/3 plans) — completed 2026-04-10
- [x] Phase 11: Runtime Capability Expansion — stretch (2/2 plans) — completed 2026-04-11
- [x] Phase 12: Milestone Bookkeeping Cleanup (3/3 plans) — completed 2026-04-11
- [x] Phase 13: v2.0 Human Verification UAT (1/1 plan) — resolved 2026-04-18
- [x] Phase 14: v2.0 Fix Pass (2/3 plans, 1 escalated to Phase 15) — complete-with-carry-forward 2026-04-18
- [x] Phase 15: Detached Console + ConPTY Architecture Investigation (3/3 plans) — completed 2026-04-18

Full details: `.planning/milestones/v2.0-ROADMAP.md`.

</details>

<details>
<summary>✅ v2.1 Resource Limits, Extended IPC, Attach-Streaming & Cleanup (Phases 16–21 + 18.1) — SHIPPED 2026-04-21</summary>

- [x] Phase 16: Resource Limits — RESL-01..04 (2/2 plans) — completed 2026-04-18
- [x] Phase 17: Attach-Streaming — ATCH-01 (2/2 plans) — completed 2026-04-19
- [x] Phase 18: Extended IPC — AIPC-01 (4/4 plans) — completed 2026-04-19
- [x] Phase 18.1: Extended IPC Gap Closure (4/4 plans) — completed 2026-04-21
- [x] Phase 19: Cleanup — CLEAN-01..04 (4/4 plans) — completed 2026-04-19
- [x] Phase 20: Upstream Parity Sync — UPST-01..04 (4/4 plans) — completed 2026-04-19
- [x] Phase 21: Windows Single-File Filesystem Grants — WSFG-01..03 (5/5 plans) — completed-with-issues 2026-04-20 (supervisor-pipe regression surfaced + resolved 2026-04-20; Phase 18.1 closed the 5 AIPC UAT gaps)

Full details: `.planning/milestones/v2.1-ROADMAP.md`.

</details>

<details>
<summary>✅ v2.2 Windows/macOS Parity Sweep (Phases 22–24) — SHIPPED 2026-04-29</summary>

- [x] Phase 22: UPST2 — Upstream v0.38–v0.40 Parity Sync (6/6 plans, PROF + POLY + PKG + OAUTH + AUD-01..04) — completed 2026-04-28
- [x] Phase 23: Windows Audit-Event Retrofit (1/1 plan, AUD-05) — completed 2026-04-29
- [x] Phase 24: Parity-Drift Prevention (2/2 plans, DRIFT-01 + DRIFT-02) — completed 2026-04-27

Full details: `.planning/milestones/v2.2-ROADMAP.md`.

</details>
<details>
<summary>✅ v2.3 Linux POC Unblock + Deferreds Closure (Phases 25–34, incl. 27.1, 27.2) — SHIPPED 2026-05-12</summary>

- [x] Phase 25: Cross-Platform RESL + AIPC Unix Design (6/6 plans, REQ-AIPC-NIX-01 shipped; REQ-RESL-NIX-01..03 host-blocked carry-forward to v2.4) — completed 2026-05-10
- [⚠️] Phase 26: PKG Streaming Follow-Up (1/2 plans, REQ-PKGS-02 + REQ-PKGS-03 shipped via Plan 26-01; REQ-PKGS-01 + REQ-PKGS-04 host-blocked carry-forward to v2.4) — partial 2026-05-01
- [⚠️] Phase 27: Audit-Attestation Hardening (1 plan, REQ-AAH-01 closed transitively via Phase 27.1 + 27.2) — partial 2026-04-29
- [x] Phase 27.1: NONO_TEST_HOME Seam (3/3 plans, REQ-NTH-01..03) — INSERTED + completed 2026-05-04
- [x] Phase 27.2: Audit-Attestation Test Re-Enablement (4/4 plans, REQ-AAHX-01..03) — INSERTED + completed 2026-05-05
- [x] Phase 28: Authenticode Chain-Walker Subject Extraction (1/1 plan, REQ-AUDC-01..03) — completed 2026-04-30
- [x] Phase 29: WR-01 Reject-Stage Unification (1/1 plan, REQ-WRU-01..02, locked-as-design Option c) — completed 2026-04-30
- [x] Phase 30: Windows nono shell Architecture Investigation (5/5 plans; failure-mode finding + broker-pattern PoC) — completed 2026-05-08
- [x] Phase 31: Broker-Process Architecture / SHELL-01 (6/6 plans; SHELL-01 → ✔ validated; operator field-test SUCCESS recorded 2026-05-09) — completed 2026-05-09
- [x] Phase 32: Sigstore Integration (5/5 plans, TUF cached-root + keyless hardening + broker self-trust-anchor; 16 D-32-* decisions) — completed 2026-05-10
- [x] Phase 33: Upstream v0.40.1..v0.52.0 audit + parity-strategy ADR (4/4 plans; Option A `continue` accepted; DIVERGENCE-LEDGER.md; G-25-DRIFT-01 empirically disproved) — completed 2026-05-11
- [x] Phase 34: UPST3 — Upstream v0.41–v0.52 Sync Execution (13/13 plans; 12 cluster dispositions resolved; ~75 commits; 2 mid-flight splits; 4 D-20 manual-replays; 13 deferrals tracked) — completed 2026-05-12

**Carry-forwards to v2.4** (captured in `.planning/MILESTONE-CONTEXT.md`):
- Theme 1 — Complete the partial upstream ports (10 P34-DEFER-* items: 04b-1/2, 06-1, 08a-1, 08b-1/2, 09-1/2, 01-1/10-1)
- Theme 2 — v2.3 host-blocked carry-forwards (Plans 25-01 RESL Unix backends + 26-02 PKGS streaming/auto-pull)
- Theme 3 — UPST4 (upstream v0.52.1 / v0.52.2 / v0.53.0 ingestion per "lazily-evaluated cadence" ADR rule)

**Audit verdict at close:** `gaps_found` from `.planning/milestones/v2.3-MILESTONE-AUDIT.md` (2026-05-09 + Phase 34 post-audit close 2026-05-12). Gate triggered by institutional artifact gaps (4 phases missing VERIFICATION.md final: 26, 27, 28, 29) + 5 host-blocked requirements + Phase 31 verification = human_needed. Substantively healthy: 14/14 integration points WIRED, 5/5 E2E flows PASS, 12/12 cluster dispositions resolved, 0 D-34-E1 violations across 75 Phase 34 commits.

Full details: `.planning/milestones/v2.3-ROADMAP.md`.

</details>


### 🏗️ v2.4 Complete the Partial Ports + UPST4 (Phases 35–40, incl. optional 36.5 + 38) — IN PROGRESS

**Goal:** Absorb the 10 Phase 34 NEEDS-FOLLOW-UP-PLAN deferrals (partial upstream ports + Windows test-hygiene), execute the v2.3 host-blocked carry-forwards (Plan 25-01 RESL Unix backends + Plan 26-02 PKGS streaming/auto-pull) on Linux/macOS host, and absorb upstream v0.52.1 / v0.52.2 / v0.53.0 via UPST4 per Phase 33 ADR's "lazily-evaluated cadence" rule.

**Trigger:** Phase 34 VERIFICATION.md strategic recommendation surfaced 10 NEEDS-FOLLOW-UP-PLAN deferrals. v2.3 audit had 5 host-blocked requirements (REQ-RESL-NIX-01..03 + REQ-PKGS-01 + REQ-PKGS-04). Upstream cadence rule fires for v0.52.1+ (3 new tags landed post-Phase-33-audit cutoff).

**Requirement coverage:** 14 requirements across 5 categories (PORT-CLOSURE-01..07, RESL-NIX-01..03, PKGS-01 + PKGS-04, UPST4-01..02, AAHX-HOST-01). All mapped; zero orphans.

**Estimated effort:** ~14-18 weeks. Phase numbering continues from Phase 34.

- [x] **Phase 35: UPST3-closure quick wins** — REQ-PORT-CLOSURE-01 (Windows env-filter wiring; P34-DEFER-08a-1) + REQ-PORT-CLOSURE-06 (Linux Landlock profiles-dir; P34-DEFER-09-1) + REQ-PORT-CLOSURE-07 (Windows test-harness hygiene; P34-DEFER-01-1 + 10-1) + half of REQ-PORT-CLOSURE-05 (escape-quote pipeline; P34-DEFER-08b-2 depends on 08b-1 ordering). ~2 weeks. Quick wins to keep deferral count down while Phase 36 absorbs the heavy items.
 (completed 2026-05-12)
- [ ] **Phase 36: UPST3 deep closure** — REQ-PORT-CLOSURE-02 (full deprecated_schema module port; P34-DEFER-04b-1) + REQ-PORT-CLOSURE-04 (yaml_merge wiring trio + wiring.rs base; P34-DEFER-06-1 + 09-2) + remainder of REQ-PORT-CLOSURE-05 (b5f0a3ab deep ExecConfig refactor; P34-DEFER-08b-1). ~4-6 weeks.
- [ ] **Phase 36.5: Profile drafts feature absorption (optional)** — REQ-PORT-CLOSURE-03 (upstream 829c341a `nono profile promote` + `--draft` + package_status.rs + profile-drafts directory infrastructure). ~1 week. Planner-discretion split from Phase 36 to keep the deep-closure plan from getting unwieldy.
- [ ] **Phase 37: v2.3 carry-forward Linux/macOS execution** — REQ-RESL-NIX-01..03 (Plan 25-01 cgroup v2 + setrlimit RESL backends) + REQ-PKGS-01 + REQ-PKGS-04 (Plan 26-02 streaming refactor + auto-pull). Plan + CONTEXT artifacts already committed in v2.3 (`3ed80d38` + `86efcdeb`); execution requires Linux/macOS host. ~2 weeks once host available.
- [ ] **Phase 38: REQ-AAH-01 native host re-validation (optional)** — REQ-AAHX-HOST-01. Tactical confirmation pass on Linux/macOS host that the Phase 27 transitive closure (via 27.1 + 27.2) holds without a host-native gap. Skip if field-validation surfaces no gap. ~2-3 days.
- [ ] **Phase 39: UPST4 audit** — REQ-UPST4-01. Mirror Phase 33 shape. DIVERGENCE-LEDGER.md inventory of upstream v0.52.0..v0.53.0+ divergence (3 confirmed tags at milestone start: v0.52.1 `21bbb82e`, v0.52.2 `e8bf0148`, v0.53.0 `c4b25b82`; may grow). Per-cluster disposition + parity-strategy review against Phase 33 ADR. ~1 week.
- [ ] **Phase 40: UPST4 sync execution** — REQ-UPST4-02. Mirror Phase 34 shape. Cherry-pick + D-20 manual replay per UPST4 audit dispositions. D-19 trailer convention + Windows-only-files invariant inherited from Phase 22+34. ~2-3 weeks.

**Out of scope (explicit deferrals to v2.5 or later):**
- **v2.5-FU-1** (audit-bundle shim removal) + **v2.5-FU-2** (cmd_verify v2 JSON schema) — Phase 27.2 deferrals tracked in `deferred-items.md`.
- **AIPC G-04 wire-protocol compile-time tightening** — cascades into 23 pre-existing tests + child SDK demultiplexer; v3.0 or later.
- **WR-02 EDR HUMAN-UAT** — v3.0-deferred pending EDR-instrumented runner.
- **P32-DEFER-005** (sigstore-verify 0.6.5 → 0.6.6 upgrade) — candidate v2.4 stretch item if a phase has space; otherwise v2.5.

**Reference:** `.planning/REQUIREMENTS.md`, `.planning/milestones/v2.4-MILESTONE-CONTEXT.md` (scope-themes provenance), `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` (effort-estimate provenance for Theme 1 REQs).

## Phase Details (v2.4)

### Phase 35: UPST3-closure quick wins

**Goal:** Land three discrete P34-DEFER quick wins: Windows execution-path env-filter wiring (REQ-PORT-CLOSURE-01 / P34-DEFER-08a-1), Linux Landlock profiles-dir pre-creation (REQ-PORT-CLOSURE-06 / P34-DEFER-09-1), and Windows test-harness hygiene (REQ-PORT-CLOSURE-07 / P34-DEFER-01-1 + 10-1). Keeps the deferral count down while Phase 36 absorbs the heavy ports.

**Depends on:** Phase 34 (UPST3) — COMPLETED 2026-05-12.

**Requirements:** REQ-PORT-CLOSURE-01, REQ-PORT-CLOSURE-06, REQ-PORT-CLOSURE-07. See `.planning/REQUIREMENTS.md`. **Scope note:** the v2.4 summary line mentions "half of REQ-PORT-CLOSURE-05 (escape-quote pipeline)" — that piece (P34-DEFER-08b-2) is **moved to Phase 36** because it depends on the 08b-1 ExecConfig refactor; Phase 35 ships 01 + 06 + 07 only.

**Plans:** 3/3 plans complete

- [x] 35-01-WIN-ENV-FILTER-PLAN.md — REQ-PORT-CLOSURE-01 (Windows execution-path env-filter wiring; closes P34-DEFER-08a-1)
- [x] 35-02-LINUX-LANDLOCK-PROFILES-PLAN.md — REQ-PORT-CLOSURE-06 (Linux Landlock profiles-dir pre-creation; cherry-picks upstream bdf183e9; closes P34-DEFER-09-1)
- [x] 35-03-WIN-TEST-HYGIENE-PLAN.md — REQ-PORT-CLOSURE-07 (UNC strip in suggested_flag + full format!("{:?}") JSON-emission audit + Phase 35 closure ledger append; closes P34-DEFER-01-1, 09-3, 10-1)

**Estimated effort:** ~2 weeks.

**Reference:** `.planning/REQUIREMENTS.md` § REQ-PORT-CLOSURE-01/06/07, `.planning/milestones/v2.4-MILESTONE-CONTEXT.md` (Theme 1 scope provenance), `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` (P34-DEFER-08a-1, 09-1, 01-1, 10-1).

### Phase 36: UPST3 deep closure

**Goal:** Absorb the heavy P34 deferrals: full `deprecated_schema` module port (REQ-PORT-CLOSURE-02 / P34-DEFER-04b-1), `yaml_merge` wiring trio plus `wiring.rs` base abstraction (REQ-PORT-CLOSURE-04 / P34-DEFER-06-1 + 09-2), and the `b5f0a3ab` deep ExecConfig refactor with the escape-quote pipeline rider (REQ-PORT-CLOSURE-05 / P34-DEFER-08b-1 + 08b-2).

**Depends on:** Phase 35 (UPST3-closure quick wins).

**Requirements:** REQ-PORT-CLOSURE-02, REQ-PORT-CLOSURE-04, REQ-PORT-CLOSURE-05. See `.planning/REQUIREMENTS.md`.

**Plans:** 4/6 plans executed

- [x] 36-01a-DEPRECATED-SCHEMA-MODULE-PLAN.md — REQ-PORT-CLOSURE-02 foundation (LegacyPolicyPatch + DeprecationCounter + --strict mode; Wave 1)
- [x] 36-01b-CANONICAL-PROFILE-SECTIONS-PLAN.md — REQ-PORT-CLOSURE-02 (canonical Profile struct sections: commands, filesystem.deny/bypass_protection; Wave 2; depends_on 36-01a)
- [ ] 36-01c-OVERRIDE-DENY-RENAME-PLAN.md — REQ-PORT-CLOSURE-02 (atomic 17-file rename override_deny → bypass_protection, 183 callsites, single commit per D-36-B4; Wave 2; depends_on 36-01b)
- [ ] 36-01d-PROFILE-DATA-DOCS-TOOLING-PLAN.md — REQ-PORT-CLOSURE-02 closure (built-in profile data + JSON schema + scripts/test-list-aliases.sh + scripts/lint-docs.sh + docs migration + Phase 34 deferred-items closure ledger; Wave 2; depends_on 36-01c)
- [x] 36-02-WIRING-YAML-MERGE-PLAN.md — REQ-PORT-CLOSURE-04 (stripped-down wiring.rs: yaml_merge directive + serde_yaml_ng 0.10.0 pin + reversal failure test; acceptance #1 scope-trimmed to v2.5-FU-3 per D-36-C1; Wave 1; depends_on [])
- [x] 36-03-EXECCFG-SURGICAL-PORT-PLAN.md — REQ-PORT-CLOSURE-05 (b5f0a3ab surgical helpers + bbdf7b85 escape-quote tail; 3 sequenced commits; Commit 3 is the ONLY D-19 cherry-pick in Phase 36 per D-36-D2; fork ExecConfig 17-field shape preserved per D-36-D1; Wave 1; depends_on [])

**Estimated effort:** ~4-6 weeks.

**Reference:** `.planning/REQUIREMENTS.md` § REQ-PORT-CLOSURE-02/04/05, `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` (P34-DEFER-04b-1, 06-1, 08b-1, 08b-2, 09-2), `.planning/phases/36-upst3-deep-closure/36-CONTEXT.md` (locked decisions D-36-A1..E2), `.planning/phases/36-upst3-deep-closure/36-RESEARCH.md` (drift findings + per-plan implementation approach), `.planning/phases/36-upst3-deep-closure/36-PATTERNS.md` (analog file maps), `.planning/phases/36-upst3-deep-closure/36-VALIDATION.md` (per-task verification map).

### Phase 36.5: Profile drafts feature absorption (optional)

**Goal:** Absorb upstream `829c341a` profile-drafts surface: `nono profile promote` subcommand, `--draft` flag plumbing, `package_status.rs` module, and `profile-drafts/` directory infrastructure (REQ-PORT-CLOSURE-03 / P34-DEFER-04b-2). Planner-discretion split from Phase 36 to keep the deep-closure plan tractable.

**Depends on:** Phase 36 (UPST3 deep closure).

**Requirements:** REQ-PORT-CLOSURE-03. See `.planning/REQUIREMENTS.md`.

**Plans:** 0 plans — to be populated during `/gsd-plan-phase 36.5`. **Skip if** Phase 36 absorbs the drafts surface cleanly without scope strain.

**Estimated effort:** ~1 week.

**Reference:** `.planning/REQUIREMENTS.md` § REQ-PORT-CLOSURE-03, `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` (P34-DEFER-04b-2).

### Phase 37: v2.3 carry-forward Linux/macOS execution

**Goal:** Execute the two v2.3 host-blocked carry-forwards on Linux/macOS host — Plan 25-01 cgroup v2 + `setrlimit` RESL backends (REQ-RESL-NIX-01..03) and Plan 26-02 streaming refactor + auto-pull (REQ-PKGS-01 + REQ-PKGS-04). Plan + CONTEXT artifacts already committed in v2.3 (`3ed80d38` + `86efcdeb`); this phase is execution-only.

**Depends on:** Linux/macOS host availability (not a phase dependency).

**Requirements:** REQ-RESL-NIX-01, REQ-RESL-NIX-02, REQ-RESL-NIX-03, REQ-PKGS-01, REQ-PKGS-04. See `.planning/REQUIREMENTS.md`.

**Plans:** 0 plans — to be populated during `/gsd-plan-phase 37`. Plan 25-01 and Plan 26-02 will be lifted from v2.3 phase directories and re-anchored here.

**Estimated effort:** ~2 weeks once host available.

**Reference:** `.planning/REQUIREMENTS.md` § REQ-RESL-NIX-01..03 + REQ-PKGS-01 + REQ-PKGS-04, `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-01-RESL-NIX-PLAN.md`, `.planning/phases/26-pkg-streaming-followup/26-02-PKGS-STREAM-AUTOPULL-PLAN.md` (if present in v2.3 phase dir).

### Phase 38: REQ-AAH-01 native host re-validation (optional)

**Goal:** Tactical confirmation pass on Linux/macOS host that the Phase 27 transitive closure (via Phase 27.1 `NONO_TEST_HOME` seam + Phase 27.2 audit-loader/bundle-target ADR) holds without a host-native gap (REQ-AAHX-HOST-01). Skip if field-validation during Phase 37 surfaces no Phase-27-related gap.

**Depends on:** Phase 37 (host availability).

**Requirements:** REQ-AAHX-HOST-01. See `.planning/REQUIREMENTS.md`.

**Plans:** 0 plans — to be populated during `/gsd-plan-phase 38` if not skipped.

**Estimated effort:** ~2-3 days.

**Reference:** `.planning/REQUIREMENTS.md` § REQ-AAHX-HOST-01, `.planning/phases/27-audit-attestation-hardening/`, `.planning/phases/27.1-nono-test-home-seam/`, `.planning/phases/27.2-audit-attestation-test-re-enablement/`.

### Phase 39: UPST4 audit

**Goal:** Mirror Phase 33 shape — produce a DIVERGENCE-LEDGER.md inventory of upstream divergence from v0.52.0 to v0.53.0+ (3 confirmed tags at milestone start: v0.52.1 `21bbb82e`, v0.52.2 `e8bf0148`, v0.53.0 `c4b25b82`; may grow). Per-cluster disposition + parity-strategy review against the Phase 33 ADR `continue` decision (REQ-UPST4-01).

**Depends on:** Phase 34 (UPST3 execution baseline). Independent of Phases 35–38.

**Requirements:** REQ-UPST4-01. See `.planning/REQUIREMENTS.md`.

**Plans:** 0 plans — to be populated during `/gsd-plan-phase 39`.

**Estimated effort:** ~1 week.

**Reference:** `.planning/REQUIREMENTS.md` § REQ-UPST4-01, `.planning/phases/33-audit-upstream-v0-40-1-v0-52-0-parity-strategy/` (Phase 33 audit-shape template), `docs/architecture/upstream-parity-strategy.md` (Phase 33 ADR with `continue` decision + future audit cadence rule).

### Phase 40: UPST4 sync execution

**Goal:** Mirror Phase 34 shape — execute cherry-picks and D-20 manual replays per the UPST4 audit dispositions from Phase 39 (REQ-UPST4-02). D-19 trailer convention + Windows-only-files invariant inherited from Phases 22 + 34.

**Depends on:** Phase 39 (UPST4 audit) — disposition ledger is the input.

**Requirements:** REQ-UPST4-02. See `.planning/REQUIREMENTS.md`.

**Plans:** 0 plans — to be populated during `/gsd-plan-phase 40`. Plan count and per-cluster disposition shape will be determined by Phase 39's ledger.

**Estimated effort:** ~2-3 weeks.

**Reference:** `.planning/REQUIREMENTS.md` § REQ-UPST4-02, `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/` (Phase 34 execution-shape template), `.planning/templates/upstream-sync-quick.md` (Option A continue base case).
