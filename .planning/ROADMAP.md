# Roadmap: nono Windows Parity & Quality

This roadmap tracks the path to full Windows/Unix parity and ongoing quality-of-life work for `nono`.

## Milestones

- ✅ **v1.0 Windows Alpha** — Phases 1–4 (shipped 2026-03-31; tag `v1.0`)
- ✅ **v2.0 Windows Gap Closure** — Phases 5–15 (shipped 2026-04-18; tag `v2.0`)
- ✅ **v2.1 Resource Limits, Extended IPC, Attach-Streaming & Cleanup** — Phases 16–21 + 18.1 (shipped 2026-04-21; tag `v2.1`)
- ✅ **v2.2 Windows/macOS Parity Sweep** — Phases 22–24 (shipped 2026-04-29; tag `v2.2`)
- 🏗️ **v2.3 Linux POC Unblock + Deferreds Closure** — Phases 25–30 + 27.1 (started 2026-04-29)

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

### 🏗️ v2.3 Linux POC Unblock + Deferreds Closure (Phases 25–30) — IN PROGRESS

**Goal:** A Linux user running fork-Linux-build sees real enforcement (not silent no-ops) for `--memory` / `--cpu-percent` / `--timeout` / `--max-processes`, and v2.2's deferred items (PKG streaming, audit-attestation hardening, Authenticode chain-walker) ship as production-ready surfaces.

**Trigger:** Linux POC gap analysis (2026-04-29, `.planning/quick/260429-gap-v039-linux-poc-vs-windows-fork-tip/PLAN.md`) showed RESL flags emit "not enforced on linux" warnings — credibility issue for the demo. v2.3 closes those + lands the WR-01 product decision deferred since v2.1.

**Requirement coverage:** 20 requirements across 8 categories (RESL-NIX, AIPC-NIX, PKGS, AAH, NTH, AAHX, AUDC, WRU). All mapped; zero orphans. Phase 27.1 (NTH-01..03) and Phase 27.2 (AAHX-01..03) inserted post-scope-lock — both pulled forward into v2.3 to close REQ-AAH-01 fully on Windows host without v2.4 deferral.

- [ ] **Phase 25: Cross-Platform RESL + AIPC Unix Design** (1/2 plans complete, 2026-04-29) — REQ-RESL-NIX-01..03 + REQ-AIPC-NIX-01. Plan 25-02 (AIPC Unix Futures ADR) shipped 2026-04-29 closing REQ-AIPC-NIX-01 (commit `30d6fdb1`); ADR at `docs/architecture/aipc-unix-futures.md` locks verdicts for all 6 HandleKind discriminants. Plan 25-01 (cgroup v2 Linux + setrlimit macOS RESL backends — REQ-RESL-NIX-01..03) execution deferred until next session has Linux/macOS-host coverage; plan + CONTEXT committed (commit `3ed80d38`). Subsumes v2.3 backlog row "Cross-platform RESL Unix backends" verbatim.
- [⚠️] **Phase 26: PKG Streaming Follow-Up** (1/2 plans, partial 2026-05-01) — REQ-PKGS-02 + REQ-PKGS-03 closed via Plan 26-01 (commits `e5e1f2d7`/`dd7b28b3`/`797f3295`/`8ff89923`/`1f47d0ee`/`464cd4d4`); Plan 26-02 (REQ-PKGS-01 streaming + REQ-PKGS-04 auto-pull) plan + CONTEXT committed (`86efcdeb`) with execution queued for Linux/macOS host. Plan 26-01 used D-20 manual replay for `58b5a24e` (cherry-pick would have deleted fork's `validate_path_within`, a security regression); both validators preserved as belt-and-suspenders. `ArtifactType::Plugin` added as 7th variant (Script was missed in v2.3 scope-lock).
- [⚠️] **Phase 27: Audit-Attestation Hardening** (1 plan, PARTIAL — REQ-AAH-01 deferred to v2.4) — Path B fixture redesign attempted on Windows 2026-04-29 (commits `c2247f79`, `16bae9ca`, `8aeabc08`, `329f313b`); 3 Windows-host test-harness blockers surfaced (`dirs::home_dir()` ignores `USERPROFILE`; `LOCALAPPDATA`/`USERPROFILE` path-mismatch under partial env redirection; pre-existing v2.2-baseline audit-integrity exit-cleanup "Session not found" issue). Tests re-`#[ignore]`'d with v2.4-deferral note; redesigned Test 1 body preserved in-tree for resumption; production code in `audit_attestation.rs` byte-identical preserved. Resumption path documented in `.planning/phases/27-audit-attestation-hardening/27-01-SUMMARY.md` — Linux/macOS host verification OR `NONO_TEST_HOME` production-code seam.
- [x] **Phase 28: Authenticode Chain-Walker Subject Extraction** (1/1 plan, 2026-04-30) — REQ-AUDC-01..03 all closed. 5 commits (`67ba4a99`/`70593110`/`5a4a8443`/`279c1b86`/`91a3f64a`). Chain walker live; replaces v2.2 Plan 22-05b Decision 4 `<unknown>` sentinel with `WTHelperProvDataFromStateData` → `WTHelperGetProvSignerFromChain` → `CertGetNameStringW(CERT_X500_NAME_STR)` + `CertGetCertificateContextProperty(CERT_HASH_PROP_ID)`. Fail-closed `?` propagation on chain-walk failure when `WinVerifyTrust=Valid` (REQ-AUDC-03 acceptance #2). Deferred test moved inline (PATH-4 per CONTEXT override; closes REQ-AUDC-02 fully). 4 new unit tests pass against `C:\Windows\explorer.exe` fixture (`notepad.exe` is catalog-signed on Win11 — D-AUDC-03 fixture switch). Reuses `NonoError::SandboxInit` (D-AUDC-02: `AuditIntegrity` variant doesn't exist on fork). 11 SAFETY blocks; D-19/D-21 invariants hold.
- [x] **Phase 29: WR-01 Reject-Stage Unification** (1/1 plan, 2026-04-30) — REQ-WRU-01..02 closed. 3 commits (`a3734bb3`/`9fcdf123` + SUMMARY). Locked as permanent design property (Option c): mask-gate vs broker-failure-flip is O(1) profile lookup vs O(syscall) post-approval; asymmetry is structural, not unifiable without security or UX regression. No behavior change, no wire-shape change, no test-assertion change — chosen verdict matrix is the existing matrix. All 5 `wr01_*` regression tests preserved as guards on the locked matrix.
- [ ] **Phase 30: Windows nono shell Interactive Enforcement Architecture** (planning, 2026-05-07) — Driver: debug session `nono-shell-status-dll-init-failed.md` (`nono shell --profile claude-code` on Windows fails with `STATUS_DLL_INIT_FAILED (0xC0000142)`); SHELL-01's "validated" claim is wrong and must be reality-checked. Wave 1 = Option 3 field-test (Low-IL primary token + ConPTY, no WRITE_RESTRICTED, no session-SID). Wave 2 (conditional) = ProcMon-driven Win32 investigation if Wave 1 fails. Either ships a working `nono shell` Windows path with mandatory-label NO_WRITE_UP write-deny intact, OR documents evidence that no user-mode token shape can deliver both ConPTY + write-deny (deferred to v3.0 kernel-driver work). See `.planning/phases/30-windows-nono-shell-architecture/30-CONTEXT.md` for D-01..D-10.

## Phase Details (v2.3)

### Phase 25: Cross-Platform RESL + AIPC Unix Design

**Goal:** Convert silent-no-op RESL flags on Linux/macOS into kernel-level enforcement (cgroup v2 / `setrlimit`), and ship an ADR documenting which AIPC HandleKinds admit Unix backends.

**Depends on:** None structurally. v2.1 Phase 16 (Windows RESL) provides the reference acceptance shape.

**Requirements:** REQ-RESL-NIX-01, REQ-RESL-NIX-02, REQ-RESL-NIX-03, REQ-AIPC-NIX-01 (4 reqs).

**Plans (planned):** 2

1. **Plan 25-01 — Cross-platform RESL Unix backends.** Linux cgroup v2 (`memory.max` / `cpu.max` / `pids.max` / `cgroup.kill`); macOS `setrlimit` (`RLIMIT_AS` / `RLIMIT_NPROC`; `RLIMIT_CPU` documented gap; `--cpu-percent` fail-closed unsupported on macOS). Removes 4 "not enforced on linux" stderr warnings. Reuses v2.1 Phase 16 acceptance shape.
2. **Plan 25-02 — AIPC Unix futures ADR.** Design-only document at `docs/architecture/aipc-unix-futures.md` (or equivalent). Decision per-HandleKind: Socket/Pipe admit Unix backends via Unix-domain socket + `SCM_RIGHTS`; JobObject/Event/Mutex are Windows-only by design. Cross-linked from PROJECT.md.

**Success Criteria** (what must be TRUE when Phase 25 completes):

1. A Linux user running `nono run --memory 256m -- bash -c "tail -c 1G </dev/urandom"` sees the child OOM-killed by cgroup v2 `memory.max`; `nono inspect <id>` shows `memory_kill: true`.
2. A Linux user running `nono run --max-processes 10 -- ...` sees fork failures after 10 processes (`pids.max`).
3. A macOS user running `nono run --memory 256m -- ...` sees the child aborted via `RLIMIT_AS` mmap failure.
4. None of the four "not enforced on linux" / "not enforced on macos" warnings emit on the supported flag set after this phase lands.
5. `docs/architecture/aipc-unix-futures.md` (or equivalent ADR) committed; PROJECT.md cross-links it; each of 5 HandleKinds has a yes/no verdict with rationale.

### Phase 26: PKG Streaming Follow-Up

**Goal:** Land the 2 PKG cherry-picks deferred from v2.2 Plan 22-03 plus the architectural decisions that blocked them.

**Depends on:** v2.2 Phase 22 Plan 22-03 (provides the 6/8 cherry-picks already landed).

**Requirements:** REQ-PKGS-01..04 (4 reqs).

**Plans:** TBD (1–2 plans; final count locked at `/gsd-plan-phase 26`).

**Success Criteria** (what must be TRUE when Phase 26 completes):

1. `nono pull <large-artifact>` of 200MB succeeds via streaming (memory profile peaks at ~10MB).
2. Pack manifest with `..` traversal rejected by both `validate_relative_path` (input-string) and `validate_path_within` (canonicalize-and-compare); deferred-divergence comment at `package_cmd.rs:631-643` resolved.
3. Profile extending `registry://vendor/pack@1.2.3` auto-pulls absent packs idempotently.
4. `ArtifactType::Plugin` variant deserializes; round-trips through `serde_json`.

### Phase 27: Audit-Attestation Hardening

**Goal:** Re-enable 2 `#[ignore]`'d fixture-driven tests in `crates/nono-cli/tests/audit_attestation.rs`; resolve the Rule-4 architectural decision (sigstore-rs upgrade vs fork-internal pkcs8 parser).

**Depends on:** v2.2 Plan 22-05a (provides the cryptographic DSSE bundle verification; the deferred tests sit on top).

**Requirements:** REQ-AAH-01 (1 req).

**Plans:** 1 (locked at `/gsd-plan-phase 27`).

**Success Criteria:**

1. Both `#[ignore]`'d tests run and pass.
2. Architectural decision documented in CONTEXT.md with cascade impact for future readers.
3. `cargo test -p nono-cli --test audit_attestation` exits 0 with no ignored tests.

### Phase 27.1: NONO_TEST_HOME Seam (INSERTED)

**Goal:** Add `NONO_TEST_HOME` env-var override to `dirs::home_dir()` callsites in `crates/nono-cli/src/` so Windows integration tests can redirect HOME without LOCALAPPDATA/USERPROFILE drift. Unblocks REQ-AAH-01 (Phase 27) and the queued v2.3 plans (Phase 26-02 PKGS-01/04, etc.) for Windows-host execution.

**Depends on:** v2.3 Phase 27 (partial close at 2026-04-29 surfaced this as the cleanest cross-platform unblock; Rule-4 architectural decision recorded in Phase 27 SUMMARY).

**Requirements:** REQ-NTH-01, REQ-NTH-02, REQ-NTH-03 (3 reqs; locked at `/gsd-plan-phase 27.1` 2026-05-04). See `.planning/REQUIREMENTS.md` § NTH for full acceptance criteria.

**Plans:** 3/3 plans complete

Plans:
- [x] 27.1-01-PLAN.md — `nono_home_dir()` helper + `user_state_dir()` extension + 4 unit tests (REQ-NTH-01 + REQ-NTH-02; foundation, Wave 1)
- [x] 27.1-02-PLAN.md — Migrate 15 home-dir callsites + remove `xdg-home` dep (REQ-NTH-01 reachability; Wave 2, depends on 27.1-01)
- [x] 27.1-03-PLAN.md — Re-enable Phase 27 audit-attestation tests via `NONO_TEST_HOME` seam (REQ-NTH-03; Wave 3, depends on 27.1-01 + 27.1-02; closes REQ-AAH-01 transitively)

**Cross-cutting constraints:**
- crates/nono/ remains byte-identical (D-19 invariant).

**Success Criteria:**

1. `dirs::home_dir()` callsites in `crates/nono-cli/src/` honor `NONO_TEST_HOME` when set, fall through to platform default otherwise.
2. Phase 27 redesigned Test 1 body (preserved under `#[ignore]`) runs to completion on Windows host with `NONO_TEST_HOME` set.
3. No production-path behavior change when `NONO_TEST_HOME` is unset (security-equivalent to status quo).

### Phase 27.2: Audit-Attestation Test Re-Enablement (INSERTED)

**Goal:** Close v2.4-FU-1 (audit-loader swap in `crates/nono-cli/src/audit_commands.rs:12` from `rollback_session::load_session` → `audit_session::load_session` for audit-only sessions) and v2.4-FU-2 (bundle-target architecture decision: mirror to audit_dir vs sign-to-session_dir vs dual-root verify), then remove the two `#[ignore]` attributes on `crates/nono-cli/tests/audit_attestation.rs` (FU-3) so REQ-AAH-01 (Phase 27) and REQ-NTH-03 (Phase 27.1) close fully on Windows host. Builds on the Phase 27.1 `NONO_TEST_HOME` seam.

**Depends on:** Phase 27.1 (NONO_TEST_HOME seam at `crates/nono-cli/src/config/mod.rs::nono_home_dir()`); Phase 27 (Path B redesigned test bodies preserved in-tree). Surfaced by Phase 27.1 D-27.1-14 large-fix branch — see `.planning/phases/27.1-nono-test-home-seam/27.1-03-SUMMARY.md` § "v2.4 production follow-ups" and `deferred-items.md`.

**Requirements:** REQ-AAHX-01 (audit-loader correctness for audit-only sessions), REQ-AAHX-02 (bundle-target architecture decision + ADR), REQ-AAHX-03 (audit-attestation test re-enablement closes REQ-AAH-01 + REQ-NTH-03 transitively). To be locked at `/gsd-plan-phase 27.2` per the planning-time requirements convention. See `.planning/REQUIREMENTS.md` § AAHX for full acceptance criteria.

**Plans:** 4 plans

Plans:
- [ ] 27.2-01-PLAN.md — `cmd_verify` audit-loader swap + one-shot legacy-bundle warning helper (REQ-AAHX-01; FU-1; Wave 1)
- [ ] 27.2-02-PLAN.md — `create_audit_state` bundle-target migration to `<audit_root>/<id>/` (REQ-AAHX-02 implementation half; FU-2; Wave 1)
- [ ] 27.2-03-PLAN.md — `docs/architecture/audit-bundle-target.md` ADR + v2.5 follow-up entries in `deferred-items.md` (REQ-AAHX-02 documentation half; FU-2; Wave 1)
- [ ] 27.2-04-PLAN.md — Re-enable both `#[ignore]`'d audit-attestation tests + ScopedEnvVar RAII guard (WR-05) + Test 2 flat-JSON assertions (WR-04) (REQ-AAHX-03; FU-3; Wave 2 — depends on 27.2-01 + 27.2-02)

**Cross-cutting constraints:**
- `crates/nono/` remains byte-identical (D-19 invariant).
- No regression on the seam: `nono_home_dir()` semantics from Phase 27.1 must not change.
- WR-01 split-brain disposition (Phase 27.1 review finding, accepted as intentional) is not in scope here — this phase is loader/bundle-target only.

**Success Criteria:**

1. `cargo test -p nono-cli --test audit_attestation` returns `2 passed; 0 failed; 0 ignored` on Windows host with `NONO_TEST_HOME` set.
2. `cmd_verify` in `audit_commands.rs` correctly resolves audit-only sessions via `audit_session::load_session`; rollback-only and dual-target sessions retain their existing loader correctness (no regressions).
3. Bundle-target architecture decision recorded as an ADR (e.g. `docs/architecture/audit-bundle-target.md`); chosen path implemented; `--audit-integrity --audit-sign-key --rollback` and `--audit-integrity --audit-sign-key` (no rollback) flows both produce verifiable bundles at the documented canonical path.

### Phase 28: Authenticode Chain-Walker Subject Extraction

**Goal:** Light up `parse_signer_subject` + `parse_thumbprint` on Windows; upgrade AUD-03 acceptance to require populated subject + non-empty thumbprint on `Valid` Authenticode signatures.

**Depends on:** v2.2 Plan 22-05b (provides the discriminant-only Authenticode integration; chain walker sits on top).

**Requirements:** REQ-AUDC-01, REQ-AUDC-02, REQ-AUDC-03 (3 reqs).

**Plans:** 1 (locked at `/gsd-plan-phase 28`).

**Success Criteria:**

1. `nono audit show <id>` on Windows for a signed binary shows populated `signer_subject` (CN substring) + non-empty 40-char hex SHA-1 thumbprint.
2. Chain-walk failure on `Valid` signature → audit-recording fail-closed (no silent `<unknown>` substitution).
3. `authenticode_signed_records_subject` test re-enabled and passing.

### Phase 29: WR-01 Reject-Stage Unification

**Goal:** Ship the product decision on AIPC HandleKind reject-stage (BEFORE vs AFTER prompt asymmetry deferred since v2.1) and update `wr01_*` regression tests + Phase 23 `RejectStage` ledger emission per the chosen verdict matrix.

**Depends on:** v2.1 Phase 18.1 (locks asymmetry in `wr01_*` tests); v2.2 Phase 23 (mirrors asymmetry on the audit-ledger wire via `RejectStage`).

**Requirements:** REQ-WRU-01, REQ-WRU-02 (2 reqs).

**Plans:** 1 (locked at `/gsd-plan-phase 29`).

**Success Criteria:**

1. CONTEXT D-14 (or equivalent ADR) updated with chosen option + rationale.
2. All 5 `wr01_*` tests pass with assertions matching the chosen matrix.
3. `audit_integrity_records_5_handle_kinds_in_ledger` (Phase 23 multi-kind E2E) passes; ledger reflects the chosen matrix.
4. PROJECT.md key-decisions table updated.

### Phase 30: Windows nono shell Interactive Enforcement Architecture

**Goal:** Land OS-enforced filesystem write protection AND interactive TUI rendering for `nono shell --profile <name>` on Windows 10/11; either ship a working path that launches PowerShell 5.1 / cmd.exe under ConPTY with mandatory-label write enforcement intact, OR document evidence that no user-mode token shape can deliver both (deferred to v3.0 kernel mini-filter driver work).

**Depends on:** v2.0 Phase 8 (ConPTY shell — invalidated SHELL-01 claim being reality-checked); v2.0 Phase 15 (detached console + WRITE_RESTRICTED+ConPTY 0xC0000142 precedent + token-cascade pattern Wave 1 extends).

**Requirements:** No formal REQ-IDs at scope-lock; phase tracked via CONTEXT.md decisions D-01..D-10 (token shape, investigation gating, TUI/security envelope acceptance, POC ship gating, bookkeeping correction). Decision-coverage gate enforces D-01..D-10 through plans.

**Plans:** 5 plans (Wave 1 prelude/edit/smoke/outcome + Wave 2 conditional ProcMon)

Plans:
**Wave 1**
- [ ] 30-01-PLAN.md — Bookkeeping prelude: SHELL-01 → needs-rework, debug-session frontmatter cross-link, STATE.md stopped_at update (D-10 first half + D-08/D-09 out-of-scope encoding)
- [ ] 30-02-PLAN.md — Token cascade 6th arm: WindowsTokenArm enum + select_windows_token_arm helper + pty_token_gate_tests (6 tests) + low_integrity_primary_token_sets_low_il (Windows-only FFI test, first runtime exercise of create_low_integrity_primary_token) (D-01 + D-02 + D-03)

**Wave 2** *(blocked on Wave 1 completion)*
- [ ] 30-03-PLAN.md — Field-smoke harness: scripts/test-windows-shell-write-deny.ps1 + scripts/test-windows-shell-tui.ps1 + 30-FIELD-SMOKE.md runbook (D-05 + D-06 + D-09 hygiene; manual-only, runs on Windows test box)

**Wave 3** *(blocked on Wave 2 completion)*
- [ ] 30-04-PLAN.md — Field-smoke execution + outcome flip (3 human checkpoints): runs Plan 30-03 harnesses; on success-path adds cookbook security-envelope paragraph + flips SHELL-01 → ✔ validated v2.X Phase 30 + moves debug session to resolved/; on Wave 2 trigger leaves cookbook unchanged + flags Plan 30-05 (D-05 + D-06 + D-07 + D-10 second half)

**Wave 4** *(blocked on Wave 3 completion)*
- [ ] 30-05-PLAN.md — Wave 2 ProcMon (CONDITIONAL — runs only on Wave 2 trigger from Plan 30-04): trace capture + analysis + sixth-option synthesis OR exhaust-without-fix; 3-5 working day timebox per D-04. Failure path triggers RESEARCH §Cookbook Rollback Path Option Rev-B (D-04 + D-07 failure path + D-10 terminal)

**Success Criteria:**

1. `.\nono.exe shell --profile claude-code --allow-cwd` on Windows 10/11 launches a sandboxed shell (no `0xC0000142`, no silent exit) — verified on the test box.
2. `claude` runs inside the sandboxed shell with full TUI rendering (alternate screen buffer, cursor positioning, raw-mode input).
3. From inside the sandboxed shell, `Out-File` (or any direct write) to a path outside the grant set fails with "Access is denied" at OS level (mandatory-label NO_WRITE_UP enforcement, NOT just hook-level interception).
4. From inside the sandboxed shell, reads of granted paths (e.g. `~/.claude\claude.json`) still succeed.
5. PROJECT.md's SHELL-01 entry reflects current reality (validated / needs-rework / deferred — whichever this phase ships).
6. `docs/cli/development/windows-poc-handoff.mdx` describes the security envelope honestly: which token shape, what's enforced at OS level, what relies on the Claude Code hook.

**Failure mode (explicit):** If Wave 2 (ProcMon) exhausts without surfacing a workable option, the phase ships with a documented finding that `nono shell` on Windows is structurally incompatible with simultaneous WRITE_RESTRICTED + ConPTY at user-mode and remains a v3.0 / kernel-driver concern. Cookbook reverts the `nono shell` recommendation; SHELL-01 status flips to "deferred to v3.0."

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
| 21. Windows Single-File Grants (WSFG) | v2.1 | 5/5 | Complete-with-issues | 2026-04-20 |
| 22. UPST2 — Upstream v0.38–v0.40 Parity Sync | v2.2 | 6/6 | Complete (SECURED + REVIEW-FIX 7/7 + UAT 10/10 + 1 spec-error skipped; 22-03 partial close — 6/8 cherry-picks, 2 deferred to v2.3; Authenticode chain-walker deferred to v2.3) | 2026-04-28 |
| 23. Windows Audit-Event Retrofit | v2.2 | 1/1 | Complete | 2026-04-29 |
| 24. Parity-Drift Prevention | v2.2 | 2/2 | Complete | 2026-04-27 |
| 25. Cross-Platform RESL + AIPC Unix Design | v2.3 | 1/2 | In progress (25-02 ADR done; 25-01 RESL Unix deferred to Linux/macOS host) | 25-02: 2026-04-29 |
| 26. PKG Streaming Follow-Up | v2.3 | 1/2 | Partial — Plan 26-01 PKGS-02 + PKGS-03 closed (D-20 manual replay; defense-in-depth preserved); Plan 26-02 PKGS-01 + PKGS-04 queued for Linux/macOS host | 26-01: 2026-05-01 |
| 27. Audit-Attestation Hardening | v2.3 | 0/1 | PARTIAL — Path B attempt 2026-04-29 surfaced 3 Windows-host test-harness blockers; REQ-AAH-01 deferred to v2.4 (production code byte-identical preserved; redesigned test body preserved in-tree under `#[ignore]` for v2.4 resumption) | 2026-04-29 (deferred) |
| 27.1. NONO_TEST_HOME Seam (INSERTED) | v2.3 | 3/3 | Complete    | 2026-05-05 |
| 28. Authenticode Chain-Walker Subject Extraction | v2.3 | 1/1 | Complete (REQ-AUDC-01..03 closed; D-AUDC-02 SandboxInit fallback + D-AUDC-03 explorer.exe fixture switch) | 2026-04-30 |
| 29. WR-01 Reject-Stage Unification | v2.3 | 1/1 | Complete (REQ-WRU-01..02 closed; Option c locked as permanent design property) | 2026-04-30 |
| 30. Windows nono shell Interactive Enforcement Architecture | v2.3 | 0/0 | Planning (CONTEXT locked 2026-05-07; D-01 Wave 1 = Low-IL primary token + ConPTY, Wave 2 ProcMon conditional) | — |

## Backlog (v2.4 carry-forward)

The four major v2.2-deferred items (PKG streaming, audit-attestation hardening, Authenticode chain-walker, WR-01 reject-stage unification, cross-platform RESL Unix backends) have been pulled into v2.3 as Phases 25–29. The backlog below is what remains for v2.4+.

- **REQ-AAH-01 (audit-attestation hardening) — re-deferred to v2.4 from v2.3 Phase 27 partial close** (2026-04-29). Path B fixture redesign attempted on Windows host; 3 platform-specific blockers (`dirs::home_dir()` not env-overridable on Windows, LOCALAPPDATA/USERPROFILE path-mismatch, pre-existing v2.2-baseline audit-integrity exit-cleanup). Resumption requires either (a) Linux/macOS host where `dirs::home_dir()` honors `HOME` env override (would close immediately with the in-tree redesigned Test 1 body), or (b) production-code seam adding `NONO_TEST_HOME` env-var override to `dirs::home_dir()` callsites in `crates/nono-cli/src/` (cleanest cross-platform path; Rule-4 architectural decision). Redesigned Test 1 body preserved in-tree under `#[ignore]` for v2.4 resumption. See `.planning/phases/27-audit-attestation-hardening/27-01-SUMMARY.md` for full context.

- **Windows test-harness blockers** (new, surfaced 2026-04-29 by Phase 27 attempt). The `run_nono` integration-test pattern that spawns the actual `nono` binary has Windows-specific gaps: `dirs::home_dir()` ignores `USERPROFILE` env override; partial env redirection causes `LOCALAPPDATA`/`USERPROFILE` path-mismatch; audit-integrity sessions emit "Session not found" warnings on exit cleanup at v2.2 baseline. These block end-to-end test verification on Windows hosts for any phase that needs full integration tests. Affects v2.3 Phases 26 (PKG streaming), 28 (Authenticode chain-walker), 29 (WR-01 unification) similarly; planning each on Windows is fine, execution may need Linux/macOS host until the harness is fixed. Candidate v2.4 phase: "Windows test-harness HOME redirection" via `NONO_TEST_HOME` production-code seam.

- **Upstream v0.41–v0.43 ingestion** (deferred from v2.3 scope-lock 2026-04-29). Use the DRIFT-01/02 tooling shipped in v2.2 Phase 24 (`make check-upstream-drift`) for first real load. Skipped in v2.3 to keep the milestone shippable in 2 weeks; the tooling stays warm regardless.

- **AIPC G-04 wire-protocol compile-time tightening** (deferred from v2.1 Plan 18.1-02; reaffirmed at v2.3 scope-lock). `Approved(ResourceGrant)` inline at the wire type so `(Approved, grant=None)` becomes a compile-time error. Cascades into `aipc_sdk.rs` child SDK demultiplexer + 23 pre-existing tests. Out of v2.3 scope due to test-cascade size.

- **`windows-squash` → `main` merge** (re-deferred 2026-04-29 per quick-260428-rsu). Gated on PR-583 maintainer response; cannot be pulled into v2.3 until that gate moves. Tracked separately as a quick task; not a milestone phase.

- **Cross-platform drift QA** (new, deferred from v2.3 scope-lock). After Phase 25 RESL Unix backends land, validate full Linux/macOS test-suite passes against fork tip. Bundle with v2.4 upstream-ingestion work.

- **Docs pass for v2.2 + v2.3 surfaces** (deferred from v2.3 scope-lock). Bring `docs/cli/*` Mintlify content current with audit-integrity, package management, OAuth2 proxy, RESL Unix backends. Bundle with v2.4 upstream-ingestion work.

- **WR-02 EDR HUMAN-UAT item** (v3.0). Requires EDR-instrumented runner; no host available.
