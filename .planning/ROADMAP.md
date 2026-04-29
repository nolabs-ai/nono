# Roadmap: nono Windows Parity & Quality

This roadmap tracks the path to full Windows/Unix parity and ongoing quality-of-life work for `nono`.

## Milestones

- ✅ **v1.0 Windows Alpha** — Phases 1–4 (shipped 2026-03-31; tag `v1.0`)
- ✅ **v2.0 Windows Gap Closure** — Phases 5–15 (shipped 2026-04-18; tag `v2.0`)
- ✅ **v2.1 Resource Limits, Extended IPC, Attach-Streaming & Cleanup** — Phases 16–21 + 18.1 (shipped 2026-04-21; tag `v2.1`)
- 🏗️ **v2.2 Windows/macOS Parity Sweep** — Phases 22–24 (started 2026-04-24)

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

### 🏗️ v2.2 Windows/macOS Parity Sweep (Phases 22–24) — IN PROGRESS

**Goal:** When v2.2 ships, a Windows user and a macOS user have the same `nono` commands available with the same flags and the same security guarantees. Close the current Windows-vs-macOS drift caused by upstream shipping v0.38 → v0.40 without Windows ports, and install a drift-prevention process so v0.42+ don't recreate the gap.

**Pre-milestone (not a v2.2 phase):** Merge `windows-squash` → `main` — separate quick task. Must land before Phase 22 cherry-picks begin so upstream parity work targets stable mainline.

**Requirement coverage:** 21 requirements across 6 categories (PROF, POLY, PKG, OAUTH, AUD, DRIFT). All mapped; zero orphans.

- [x] **Phase 22: UPST2 — Upstream v0.38–v0.40 Parity Sync** (6/6 plans, 2026-04-28) — ingest cross-platform feature clusters (profile struct, policy tightening, package manager, OAuth2 proxy, audit integrity) with Windows parity in lockstep. SECURED (`22-SECURITY.md` threats 41/41 closed); code-review fixes 7/7 in-scope landed (commit `33229adc`); UAT 10/10 + 1 spec-error skipped (commit `e60ab093`). 22-01 PROF (12 commits, d7fc4ed8); 22-02 POLY (7 commits, 490a8a5c); 22-03 PKG partial close (6/8 cherry-picks; 2 deferred to v2.3 backlog); 22-04 OAUTH (14 commits, 5c8df06a); **22-05 split** into 22-05a (audit core no rename — 13 commits, d15a3ab6, AUD-01/02/03 SHA-256 portion) + 22-05b (rename + Authenticode + CLEAN-04 sweep — 7 commits, b5640cd4, AUD-04 + AUD-03 Windows portion) after CONTEXT STOP trigger #3 on 4f9552ec cherry-pick. T-22-05-04 ABSOLUTE STOP guard held end-to-end. Authenticode chain-walker subject extraction deferred to v2.3 backlog (records discriminant only).
- [x] **Phase 23: Windows Audit-Event Retrofit** (1/1 plan, 2026-04-29) — wired Windows supervisor's 5 AIPC broker paths (File, Socket, Pipe, JobObject, Event, Mutex) into the Phase 22-05 ledger; RejectStage discriminator (BeforePrompt/AfterPrompt) locks WR-01 verdict-matrix asymmetry on the wire; `nono audit show <id>` surfaces capability_decisions counter + JSON array. Verified 8/8 must-haves; D-19/D-21/D-03 invariants hold; 60 tests passing. 3 commits (427e1283, a9307802, 263795a9).
- [x] **Phase 24: Parity-Drift Prevention** (2/2 plans, 2026-04-27) — `scripts/check-upstream-drift` tooling + GSD quick-task template for upstream-sync cadence

## Phase Details

### Phase 22: UPST2 — Upstream v0.38–v0.40 Parity Sync

**Goal:** Windows users run every cross-platform feature upstream shipped in v0.38–v0.40 with the same flags, same guarantees, and same failure modes as macOS users.

**Depends on:** Pre-milestone `windows-squash` → `main` merge (tracked as a separate quick task).

**Requirements:** PROF-01, PROF-02, PROF-03, PROF-04, POLY-01, POLY-02, POLY-03, PKG-01, PKG-02, PKG-03, PKG-04, OAUTH-01, OAUTH-02, OAUTH-03, AUD-01, AUD-02, AUD-03, AUD-04 (18 requirements).

**Plans** (locked sequencing, mirrors v2.1 Phase 20 UPST-01..04 pattern):

1. **Plan 22-01 — Profile struct alignment** (PROF-01..04). Lowest risk: deserialize-only changes to `Profile` struct (`unsafe_macos_seatbelt_rules`, `packs`, `command_args`, `custom_credentials.oauth2`) + ship `claude-no-keychain` built-in. Prerequisite for plans 22-03 (packs in profile) and 22-04 (`oauth2` parse).
2. **Plan 22-02 — Policy tightening** (POLY-01..03). Breaking CLI contract, small surface: orphan `override_deny` fails load; `--rollback` + `--no-audit` rejected; `.claude.lock` → `allow_file`. Independent of 22-01; can wave-parallel.
3. **Plan 22-03 — Package manager + packs** (PKG-01..04). New `nono package pull/remove/search/list` subcommand tree with Windows `%LOCALAPPDATA%` + long-path handling, hook registration via fork's `hooks.rs`, signed-artifact streaming download. Depends on Plan 22-01 (profile deserializes `packs`).
4. **Plan 22-04 — OAuth2 proxy + reverse-proxy upstream gating** (OAUTH-01..03). Port `OAuth2Config` + `nono-proxy/src/oauth2.rs` + `reverse.rs` HTTP-upstream loopback-only gating + `--allow-domain` strict-proxy composition. Depends on Plan 22-01 (profile deserializes `custom_credentials.oauth2`).
5. **Plan 22-05 — Audit integrity + attestation** (AUD-01..04). Highest risk, LAST: ~1.4k LOC port touching `rollback_runtime.rs` (+586 upstream), `supervised_runtime.rs` (+42), `exec_strategy.rs` (+144) — all heavily forked on `windows-squash`. Windows exec-identity via `GetModuleFileNameW` + Authenticode. `prune` → `session cleanup` rename preserves v2.1 Phase 19 CLEAN-04 invariants (`NONO_CAP_FILE` structural no-op, require-suffix `--older-than`, 100-file auto-sweep).

**Success Criteria** (what must be TRUE when Phase 22 completes):

1. A Windows user running `nono run --profile <any-cross-platform-profile> -- <cmd>` sees profile JSON containing `unsafe_macos_seatbelt_rules`, `packs`, `command_args`, or `custom_credentials.oauth2` fields parse without error — the same profiles macOS users already run today.
2. A Windows user running `nono run --rollback --no-audit -- <cmd>` or loading a profile with an orphan `override_deny` entry sees a fail-closed error at CLI parse / profile load time, matching macOS behavior.
3. A Windows user runs `nono package pull <name>` / `remove` / `search` / `list` and sees identical behavior to a macOS user on the same registry, with artifacts landing under `%LOCALAPPDATA%\nono\packages\<name>` and hooks registered through Claude Code.
4. A Windows user running `nono run --profile <with-oauth2> -- curl https://api.example.com` receives a `Bearer` token on the outbound request with the same token-cache + refresh semantics as macOS.
5. A Windows user running `nono run --audit-integrity --audit-sign-key <ref> -- <cmd>` produces a session with a populated `chain_head`, `merkle_root`, and `audit-attestation.bundle`, and `nono audit verify <id>` succeeds — all equivalent to macOS; v2.1 CLEAN-04 regressions (`auto_prune_is_noop_when_sandboxed`, suffix-required `--older-than`) still pass after the `prune` → `session cleanup` rename.

**Rationale for ordering:** 22-01 unblocks 22-03 + 22-04 via the profile struct changes. 22-05 must run last because its file-level overlap (`rollback_runtime.rs`, `supervised_runtime.rs`, `exec_strategy.rs`) is maximally forked on `windows-squash` — resolving those conflicts after 22-01..04 have stabilized the surrounding code minimizes re-work. 22-02 is independent and can land any time in the window.

**Plans:** TBD (drafted during `/gsd-plan-phase 22`)

### Phase 23: Windows Audit-Event Retrofit

**Goal:** A Windows user who inspects an audit session via `nono audit show <id>` sees supervisor decisions for every AIPC broker path recorded with the same structured shape macOS uses for its equivalent capability events.

**Depends on:** Phase 22 (specifically Plan 22-05, which lands the upstream ledger infrastructure; AUD-05 wires Windows-specific emissions into it).

**Requirements:** AUD-05.

**Plans** (1 plan):

1. **Plan 23-01 — AIPC broker audit emissions** — Thread ledger-append calls into each `handle_*_request` function in `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (File, Socket, Pipe, JobObject, Event, Mutex). Sanitize payloads via existing `sanitize_for_terminal`. Preserve WR-01 reject-stage asymmetry (BEFORE vs AFTER prompt) but record stage explicitly per event. Survive `AppliedLabelsGuard` Drop flush.

**Success Criteria** (what must be TRUE when Phase 23 completes):

1. A Windows user running the `aipc-demo.exe` integration test against a `--audit-integrity` session and then `nono audit show <id>` sees one capability-decision event per brokered handle (Event, Mutex, Pipe, Socket, JobObject) with HandleKind, access mask, and target PID.
2. A Windows user whose sandboxed child hits a privileged-port Socket request sees a Denied event with reason string `"broker failed: ... privileged port"` in the ledger — surfaced through `nono audit show` with no credential material leaked.
3. The v2.1-locked `wr01_*` regression tests still pass AND the ledger reflects each kind's reject stage (BEFORE-prompt kinds carry zero-backend-call markers; AFTER-prompt kinds carry one-backend-call markers), with no change to the WR-01 decision itself.

**Rationale:** Kept as a real phase in the roadmap (not collapsed into 22-05) because AUD-05 is a Windows-specific retrofit with a distinct acceptance shape — upstream's ledger covers supervisor events generically, but Windows' AIPC broker paths are fork-only surfaces that need explicit wiring. If Plan 22-05 discovers that the upstream ledger shape already covers AIPC HandleKinds cleanly, Phase 23 may collapse to a no-op closure during `/gsd-plan-phase 23`; for now, landing the requirement in a dedicated phase gives AUD-05 a home and avoids orphaning it.

**Plans:** 1 plan (locked 2026-04-28 by /gsd-plan-phase 23)

- [x] 23-01-PLAN.md — AIPC broker audit emissions: thread `audit_recorder` into `handle_windows_supervisor_message`, emit ledger events at all 5 push sites, encode reject_stage per WR-01 verdict matrix (AUD-05) — completed 2026-04-29 (commits 427e1283, a9307802, 263795a9)

### Phase 24: Parity-Drift Prevention

**Goal:** A maintainer opening a quick-task for the next upstream release (v0.41.0, v0.42.0, ...) has tooling that inventories the cross-platform commit range and a template that scaffolds a working sync PLAN.md in minutes, not hours.

**Depends on:** None structurally (independent of Phase 22 / 23 execution). Can start any time after Plan 22-01 lands the first plan, since the drift-check script will target v0.38+ commit range for its first real use.

**Requirements:** DRIFT-01, DRIFT-02.

**Plans** (1–2 plans; final count TBD during `/gsd-plan-phase 24`):

1. **Plan 24-01 — Upstream drift-check tooling** (DRIFT-01). `scripts/check-upstream-drift.ps1` + `scripts/check-upstream-drift.sh` report commits in `upstream/main..HEAD` touching cross-platform files (`crates/nono/src/`, `crates/nono-cli/src/` excluding `*_windows.rs`/`exec_strategy_windows/`, `crates/nono-proxy/src/`, `crates/nono/Cargo.toml`). Output groups commits by category (profile, policy, proxy, audit, other) in a table or JSON. Documented in `docs/cli/development/upstream-drift.md`.
2. **Plan 24-02 — GSD upstream-sync template** (DRIFT-02). Reusable template at `.planning/templates/upstream-sync-quick.md` (or equivalent). Scaffold includes: diff-range spec, cherry-pick-per-commit pattern with `Upstream-commit:` trailer, conflict-file inventory, Windows-specific retrofit checklist. Referenced from PROJECT.md.

(Plans may be combined into a single plan at `/gsd-plan-phase 24` if the tooling + template are small enough to land together; split as drafted if the scope diverges.)

**Success Criteria** (what must be TRUE when Phase 24 completes):

1. A maintainer runs `scripts/check-upstream-drift.sh` against the v0.37.1..v0.40.1 range and gets back a table reproducing the commit inventory from quick task 260424-upr's SUMMARY.md (same commits, same categorization).
2. A maintainer invokes the upstream-sync quick-task template for a hypothetical v0.41.0 sync and gets a functional PLAN.md skeleton with diff-range, conflict-file inventory, and Windows retrofit checklist pre-populated.
3. `docs/cli/development/upstream-drift.md` exists and PROJECT.md references the upstream-sync template — so the next milestone's maintainer doesn't have to rediscover the process from commit archaeology.

**Rationale:** Without this phase, v0.41+ will recreate the Windows-vs-macOS gap v2.2 just closed. The drift-check script + template make upstream absorption a weeks-scale quick task instead of a milestone-scale effort.

**Plans:** 2 plans (locked 2026-04-27 by /gsd-plan-phase 24)

- [x] 24-01-PLAN.md — Upstream drift-check tooling: twin .sh+.ps1 scripts, Makefile target, integration test, 3 fixtures (DRIFT-01)
- [x] 24-02-PLAN.md — GSD upstream-sync template + PROJECT.md cross-link + docs/cli/development/upstream-drift.mdx runbook (DRIFT-02)

## Progress Table

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Windows Control Foundation | v1.0 | 3/3 | Complete | 2026-04-04 |
| 2. Persistent Sessions | v1.0 | 4/4 | Complete | 2026-04-04 |
| 3. Network Sandboxing | v1.0 | 4/4 | Complete | 2026-04-04 |
| 4. State Integrity & Deployment | v1.0 | 3/3 | Complete | 2026-04-05 |
| 5. Windows Detach Readiness Fix | v2.0 | 1/1 | Complete | 2026-04-05 |
| 6. WFP Enforcement Activation | v2.0 | 2/2 | Complete | 2026-04-06 |
| 7. Quick Wins | v2.0 | 2/2 | Complete | 2026-04-08 |
| 8. ConPTY Shell | v2.0 | 1/1 | Complete | 2026-04-10 |
| 9. WFP Port-Level + Proxy Filtering | v2.0 | 4/4 | Complete | 2026-04-10 |
| 10. ETW-Based Learn Command | v2.0 | 3/3 | Complete | 2026-04-10 |
| 11. Runtime Capability Expansion | v2.0 | 2/2 | Complete | 2026-04-11 |
| 12. Milestone Bookkeeping Cleanup | v2.0 | 3/3 | Complete | 2026-04-11 |
| 13. v2.0 Human Verification UAT | v2.0 | 1/1 | Resolved | 2026-04-18 |
| 14. v2.0 Fix Pass | v2.0 | 2/3 | Complete-with-carry-forward | 2026-04-18 |
| 15. Detached Console + ConPTY Investigation | v2.0 | 3/3 | Complete | 2026-04-18 |
| 16. Resource Limits (RESL) | v2.1 | 2/2 | Complete | 2026-04-18 |
| 17. Attach-Streaming (ATCH) | v2.1 | 2/2 | Complete | 2026-04-19 |
| 18. Extended IPC (AIPC) | v2.1 | 4/4 | Complete | 2026-04-19 |
| 18.1. Extended IPC Gap Closure | v2.1 | 4/4 | Complete | 2026-04-21 |
| 19. Cleanup (CLEAN) | v2.1 | 4/4 | Complete | 2026-04-19 |
| 20. Upstream Parity Sync (UPST) | v2.1 | 4/4 | Complete | 2026-04-19 |
| 21. Windows Single-File Grants (WSFG) | v2.1 | 5/5 | Complete-with-issues (supervisor-pipe regression resolved in-flight; HUMAN-UAT folded into Phase 18.1) | 2026-04-20 |
| 22. UPST2 — Upstream v0.38–v0.40 Parity Sync | v2.2 | 6/6 | Complete (SECURED + REVIEW-FIX 7/7 + UAT 10/10 + 1 spec-error skipped; 22-03 partial close — 6/8 cherry-picks, 2 deferred to v2.3; Authenticode chain-walker deferred to v2.3) | 2026-04-28 |
| 23. Windows Audit-Event Retrofit | v2.2 | 0/1 | Pending | — |
| 24. Parity-Drift Prevention | v2.2 | 2/2 | Complete | 2026-04-27 |

## Backlog (v2.3 carry-forward)

- **PKG-streaming follow-up** (deferred from Plan 22-03, 2026-04-28). Land the two PKG cherry-picks held back from 22-03's chain: upstream `58b5a24e` (`validate_relative_path` input-string check) and `9ebad89a` (streaming `bytes`→`PathBuf` refactor + `tempfile::TempDir` + size limits + HTTP timeouts + `semver` dep). Prerequisites the follow-up plan must own:
  1. Introduce `ArtifactType::Plugin` enum variant + plumbing (closes the deferred-divergence comment at `crates/nono-cli/src/package_cmd.rs:631-643`).
  2. Decide explicitly whether the fork keeps `validate_path_within` (canonicalize-and-component-compare) as defense-in-depth alongside upstream's `validate_relative_path` input-string pre-check, or adopts upstream's pattern verbatim. **Recommendation: keep both** — fork's stance is stricter and matches CLAUDE.md § Path Handling.
  3. Cherry-pick `58b5a24e` with `validate_path_within` retained as belt-and-suspenders.
  4. Cherry-pick `9ebad89a` with the streaming + tempdir + semver machinery, plus the `bundle_json` field on `DownloadedArtifact` that 22-03's `73e1e3b8` skipped.
  5. Cherry-pick `115b5cfa` (`load_registry_profile` auto-pull) which Plan 22-01's empty provenance commit `3bde347c` deferred until package machinery landed.
  Rationale: each prerequisite is a Rule-4 architectural decision that exceeds cherry-pick scope. Hand-merging 9ebad89a (~+267/-109 LOC across 5 files) under cherry-pick pressure is the highest-risk option in the chain and is the wrong place to make those decisions. See `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-03-PKG-SUMMARY.md` § Deviations and `22-03-PKG-PROGRESS.md` for full context.

- **Audit-attestation D-13 fixtures re-enablement** (deferred from Plan 22-05b, 2026-04-28). The 2 `#[ignore]`'d tests in `crates/nono-cli/tests/audit_attestation.rs` blocked by KeyPair `from_pkcs8` re-enablement (sigstore-rs 0.6.4 doesn't expose it). Two viable paths: (a) sigstore-rs upgrade (architectural Rule 4 — may cascade through other crates); (b) fork-internal pkcs8 parser (architectural Rule 4 — adds parsing surface). Either approach should land before publishing v2.2 attestation as production-ready. Document as part of v2.3 audit-attestation hardening sweep.

  Companion deferral on the SAME backlog row: Plan 22-05b's `crates/nono-cli/src/exec_identity_windows.rs::parse_signer_subject` + `parse_thumbprint` chain walkers are similarly deferred — `windows-sys 0.59` does not expose `WTHelperProvDataFromStateData` / `WTHelperGetProvSignerFromChain` without the `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features (`CRYPT_PROVIDER_DATA` shape gated). Plan 22-05b records the `WinVerifyTrust` discriminant alone (Valid/Unsigned/InvalidSignature{hresult}) and sets `signer_subject = "<unknown>"` + empty thumbprint on Valid, plus marks the `authenticode_signed_records_subject` substring assertion test `#[ignore]`. Re-enable the chain walkers (either via Catalog/Sip features OR an in-tree pkcs8 parser providing equivalent walking) alongside the D-13 fixture re-enablement above.
