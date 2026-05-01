# Roadmap: nono Windows Parity & Quality

This roadmap tracks the path to full Windows/Unix parity and ongoing quality-of-life work for `nono`.

## Milestones

- ✅ **v1.0 Windows Alpha** — Phases 1–4 (shipped 2026-03-31; tag `v1.0`)
- ✅ **v2.0 Windows Gap Closure** — Phases 5–15 (shipped 2026-04-18; tag `v2.0`)
- ✅ **v2.1 Resource Limits, Extended IPC, Attach-Streaming & Cleanup** — Phases 16–21 + 18.1 (shipped 2026-04-21; tag `v2.1`)
- ✅ **v2.2 Windows/macOS Parity Sweep** — Phases 22–24 (shipped 2026-04-29; tag `v2.2`)
- 🏗️ **v2.3 Linux POC Unblock + Deferreds Closure** — Phases 25–29 (started 2026-04-29)

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

### 🏗️ v2.3 Linux POC Unblock + Deferreds Closure (Phases 25–29) — IN PROGRESS

**Goal:** A Linux user running fork-Linux-build sees real enforcement (not silent no-ops) for `--memory` / `--cpu-percent` / `--timeout` / `--max-processes`, and v2.2's deferred items (PKG streaming, audit-attestation hardening, Authenticode chain-walker) ship as production-ready surfaces.

**Trigger:** Linux POC gap analysis (2026-04-29, `.planning/quick/260429-gap-v039-linux-poc-vs-windows-fork-tip/PLAN.md`) showed RESL flags emit "not enforced on linux" warnings — credibility issue for the demo. v2.3 closes those + lands the WR-01 product decision deferred since v2.1.

**Requirement coverage:** 14 requirements across 6 categories (RESL-NIX, AIPC-NIX, PKGS, AAH, AUDC, WRU). All mapped; zero orphans.

- [ ] **Phase 25: Cross-Platform RESL + AIPC Unix Design** (1/2 plans complete, 2026-04-29) — REQ-RESL-NIX-01..03 + REQ-AIPC-NIX-01. Plan 25-02 (AIPC Unix Futures ADR) shipped 2026-04-29 closing REQ-AIPC-NIX-01 (commit `30d6fdb1`); ADR at `docs/architecture/aipc-unix-futures.md` locks verdicts for all 6 HandleKind discriminants. Plan 25-01 (cgroup v2 Linux + setrlimit macOS RESL backends — REQ-RESL-NIX-01..03) execution deferred until next session has Linux/macOS-host coverage; plan + CONTEXT committed (commit `3ed80d38`). Subsumes v2.3 backlog row "Cross-platform RESL Unix backends" verbatim.
- [⚠️] **Phase 26: PKG Streaming Follow-Up** (1/2 plans, partial 2026-05-01) — REQ-PKGS-02 + REQ-PKGS-03 closed via Plan 26-01 (commits `e5e1f2d7`/`dd7b28b3`/`797f3295`/`8ff89923`/`1f47d0ee`/`464cd4d4`); Plan 26-02 (REQ-PKGS-01 streaming + REQ-PKGS-04 auto-pull) plan + CONTEXT committed (`86efcdeb`) with execution queued for Linux/macOS host. Plan 26-01 used D-20 manual replay for `58b5a24e` (cherry-pick would have deleted fork's `validate_path_within`, a security regression); both validators preserved as belt-and-suspenders. `ArtifactType::Plugin` added as 7th variant (Script was missed in v2.3 scope-lock).
- [⚠️] **Phase 27: Audit-Attestation Hardening** (1 plan, PARTIAL — REQ-AAH-01 deferred to v2.4) — Path B fixture redesign attempted on Windows 2026-04-29 (commits `c2247f79`, `16bae9ca`, `8aeabc08`, `329f313b`); 3 Windows-host test-harness blockers surfaced (`dirs::home_dir()` ignores `USERPROFILE`; `LOCALAPPDATA`/`USERPROFILE` path-mismatch under partial env redirection; pre-existing v2.2-baseline audit-integrity exit-cleanup "Session not found" issue). Tests re-`#[ignore]`'d with v2.4-deferral note; redesigned Test 1 body preserved in-tree for resumption; production code in `audit_attestation.rs` byte-identical preserved. Resumption path documented in `.planning/phases/27-audit-attestation-hardening/27-01-SUMMARY.md` — Linux/macOS host verification OR `NONO_TEST_HOME` production-code seam.
- [x] **Phase 28: Authenticode Chain-Walker Subject Extraction** (1/1 plan, 2026-04-30) — REQ-AUDC-01..03 all closed. 5 commits (`67ba4a99`/`70593110`/`5a4a8443`/`279c1b86`/`91a3f64a`). Chain walker live; replaces v2.2 Plan 22-05b Decision 4 `<unknown>` sentinel with `WTHelperProvDataFromStateData` → `WTHelperGetProvSignerFromChain` → `CertGetNameStringW(CERT_X500_NAME_STR)` + `CertGetCertificateContextProperty(CERT_HASH_PROP_ID)`. Fail-closed `?` propagation on chain-walk failure when `WinVerifyTrust=Valid` (REQ-AUDC-03 acceptance #2). Deferred test moved inline (PATH-4 per CONTEXT override; closes REQ-AUDC-02 fully). 4 new unit tests pass against `C:\Windows\explorer.exe` fixture (`notepad.exe` is catalog-signed on Win11 — D-AUDC-03 fixture switch). Reuses `NonoError::SandboxInit` (D-AUDC-02: `AuditIntegrity` variant doesn't exist on fork). 11 SAFETY blocks; D-19/D-21 invariants hold.
- [x] **Phase 29: WR-01 Reject-Stage Unification** (1/1 plan, 2026-04-30) — REQ-WRU-01..02 closed. 3 commits (`a3734bb3`/`9fcdf123` + SUMMARY). Locked as permanent design property (Option c): mask-gate vs broker-failure-flip is O(1) profile lookup vs O(syscall) post-approval; asymmetry is structural, not unifiable without security or UX regression. No behavior change, no wire-shape change, no test-assertion change — chosen verdict matrix is the existing matrix. All 5 `wr01_*` regression tests preserved as guards on the locked matrix.

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
| 28. Authenticode Chain-Walker Subject Extraction | v2.3 | 1/1 | Complete (REQ-AUDC-01..03 closed; D-AUDC-02 SandboxInit fallback + D-AUDC-03 explorer.exe fixture switch) | 2026-04-30 |
| 29. WR-01 Reject-Stage Unification | v2.3 | 1/1 | Complete (REQ-WRU-01..02 closed; Option c locked as permanent design property) | 2026-04-30 |

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
