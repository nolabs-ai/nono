# nono - Windows Parity & Quality

## Current State

**Shipped:** v2.2 — Windows/macOS Parity Sweep (2026-04-29, tag `v2.2`).

v2.2 closed the Windows-vs-macOS drift opened by upstream `always-further/nono` shipping v0.38.0–v0.40.1 without Windows ports: profile struct alignment with `unsafe_macos_seatbelt_rules` / `packs` / `command_args` / `custom_credentials.oauth2` fields and the `claude-no-keychain` builtin; policy tightening with orphan-`override_deny` fail-closed and `--rollback`/`--no-audit` mutex; `nono pull/remove/update/search/list` flat-shape package subcommand tree on Windows; OAuth2 client-credentials Bearer-token injection in `nono-proxy` with reverse-proxy HTTP upstream loopback-only gating; hash-chained Merkle-rooted audit ledger with cryptographic DSSE attestation, Windows Authenticode exec-identity discriminant, AIPC broker emissions with WR-01 reject-stage discriminator on the wire, and `prune` → `session cleanup` rename preserving v2.1 CLEAN-04 invariants byte-identically; and parity-drift prevention via `make check-upstream-drift` twin scripts + GSD upstream-sync template. 21 v2.2 requirements closed (19 fully + 2 complete-partial: PKG-01 streaming and AUD-03 Authenticode chain-walker subject extraction pulled into v2.3).

## Current Milestone: v2.3 Linux POC Unblock + Deferreds Closure

**Goal:** A Linux user running fork-Linux-build sees real enforcement (not silent no-ops) for `--memory` / `--cpu-percent` / `--timeout` / `--max-processes`, and v2.2's deferred items (PKG streaming, audit-attestation hardening, Authenticode chain-walker) ship as production-ready surfaces.

**Trigger:** Linux POC gap analysis at `.planning/quick/260429-gap-v039-linux-poc-vs-windows-fork-tip/PLAN.md` (2026-04-29) showed RESL flags emit "not enforced on linux" warnings — credibility issue for the demo. v2.3 closes those + lands the WR-01 product decision deferred since v2.1.

**Phases:** 5 (Phases 25–29). 14 requirements across RESL-NIX / AIPC-NIX / PKGS / AAH / AUDC / WRU.

**Target features:**
- **Cross-platform RESL Unix backends (Phase 25 Plan 25-01)** — Linux cgroup v2 (`memory.max` / `cpu.max` / `pids.max` / `cgroup.kill`) + macOS `setrlimit` (`RLIMIT_AS` / `RLIMIT_NPROC`; CPU-percent fail-closed unsupported on macOS). Removes the four "not enforced" stderr warnings.
- **AIPC Unix futures ADR (Phase 25 Plan 25-02)** — design-only document deciding which 5 AIPC HandleKinds admit Unix backends. Socket/Pipe via `SCM_RIGHTS`; JobObject/Event/Mutex Windows-only by design.
- **PKG streaming follow-up (Phase 26)** — port upstream `58b5a24e` (`validate_relative_path`) + `9ebad89a` (streaming refactor) + `115b5cfa` (`load_registry_profile` auto-pull); add `ArtifactType::Plugin` enum variant + `bundle_json` field; resolve fork's `validate_path_within` belt-and-suspenders decision.
- **Audit-attestation hardening (Phase 27)** — re-enable 2 `#[ignore]`'d fixture-driven tests via Rule-4 architectural decision (sigstore-rs upgrade vs fork-internal pkcs8 parser). Required before publishing v2.2 attestation as production-ready.
- **Authenticode chain-walker subject extraction (Phase 28)** — add `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features to `windows-sys`; implement `parse_signer_subject` + `parse_thumbprint`; upgrade AUD-03 acceptance to require populated subject + non-empty thumbprint on Valid signature.
- **WR-01 reject-stage unification (Phase 29)** — ✓ closed via Phase 29 Plan 29-01 (locked design property — Option c). Mask-gate kinds (Event/Mutex/JobObject) reject BeforePrompt; broker-failure-flip kinds (Pipe/Socket) reject AfterPrompt by structural necessity (O(1) profile lookup vs O(syscall) post-approval). Existing `wr01_*` regression tests preserved as guards on the locked matrix; Phase 23 `RejectStage` wire shape unchanged.

**Out of scope (explicit deferrals to v2.4):**
- **Upstream v0.41–v0.43 ingestion** — DRIFT-01/02 tooling stays warm; first real load deferred one cycle to keep v2.3 shippable in 2 weeks.
- **AIPC G-04 wire-protocol compile-time tightening** — cascades into 23 pre-existing tests + child SDK demultiplexer; too large for v2.3.
- **`windows-squash` → `main` merge** — gated on PR-583 maintainer response per quick-260428-rsu; cannot be pulled into v2.3 until that gate moves.
- **Cross-platform drift QA** + **Docs pass** — bundle into v2.4 with the v0.41+ ingestion.
- **WR-02 EDR HUMAN-UAT item** — v3.0-deferred pending EDR-instrumented runner.

<details>
<summary>Previously Shipped</summary>

- **v2.2 Windows/macOS Parity Sweep** (2026-04-29, tag `v2.2`) — 3 phases (22–24), 9 plans, 21 requirements (PROF, POLY, PKG, OAUTH, AUD, DRIFT). 146 commits since `v2.1`.
- **v2.1 Resource Limits, Extended IPC, Attach-Streaming & Cleanup** (2026-04-21, tag `v2.1`) — 7 phases (16–21 + 18.1), 25 plans, 13 requirements (RESL, AIPC, ATCH, CLEAN, UPST, WSFG).
- **v2.0 Windows Gap Closure** (2026-04-18, tag `v2.0`; closed 2026-04-18 with Phase 15) — 7 Windows feature gaps closed (`nono wrap`, session commands, ConPTY shell, port-level WFP, proxy credential injection, ETW `learn`, runtime capability expansion stretch). Phase 15 closed the detached-console-grandchild `0xC0000142` carry-forward via direction-b fix (gated PTY-disable + null-token + AppID WFP on detached path only).
- **v1.0 Windows Alpha** (2026-03-31, tag `v1.0`) — signed release artifacts, WFP service packaging, supervisor parity, snapshot/rollback, MSI packaging.

</details>

---

## What This Is

nono is a capability-based sandboxing system for running untrusted AI agents with OS-enforced isolation. This project focuses on bringing the Windows implementation to full cross-platform parity with Linux and macOS, covering supervisor lifecycle, kernel-level network enforcement, interactive shell hosting, path discovery, and developer tooling.

## Core Value

Windows security must be as structurally impossible and feature-complete as Unix platforms, ensuring the dangerous bits are kernel-enforced without compromising the supervisor-led security model.

## Requirements

### Validated

- ✔ Landlock sandbox (Linux) — core library
- ✔ Seatbelt sandbox (macOS) — core library
- ✔ Windows capability subset enforcement (WFP network + Low Integrity filesystem)
- ✔ CLI capability builder (`--allow`, `--read`, `--block-net`, profile-backed policy)
- ✔ Built-in profiles (claude-code, codex, opencode, openclaw, swival)
- ✔ Windows alignment (WIN-1706): Library/CLI contract unified
- ✔ Windows release automation (signed .exe, machine MSI, user MSI, zip)
- ✔ C FFI bindings (nono-ffi)
- ✔ Windows CI lanes (build, smoke, integration, security, parity-regression, packaging)
- ✔ Supervisor parity (attach, detach, ps, stop) — v1.0 Phases 1–2
- ✔ WFP promotion to primary enforced network backend — v1.0 Phase 06
- ✔ Snapshot/rollback for Windows filesystems — v1.0 Phase 4
- ✔ MSI packaging and code signing automation — v1.0 Phase 4
- ✔ **WRAP-01** — `nono wrap` on Windows (Direct strategy + Job Object + WFP + canonical help text) — v2.0 Phases 07, 14-02
- ✔ **SESS-01/02/03** — `nono logs`, `nono inspect`, `nono prune` on Windows session records — v2.0 Phase 07 (SESS-03 live UAT waived as v2.0-known-issue)
- ✔ **SHELL-01** — `nono shell` interactive ConPTY on Windows 10 17763+ — v2.0 Phase 08
- ✔ **PORT-01** — port-level WFP allowlists (`--allow-port`, bind/connect) — v2.0 Phase 09
- ✔ **PROXY-01** — proxy credential injection via `--network-profile` / `--credential` / `--upstream-proxy` (runbook corrected in Phase 14-03) — v2.0 Phase 09; live UAT waived as `no-test-fixture`
- ✔ **LEARN-01** — `nono learn` on Windows via ETW — v2.0 Phase 10
- ✔ **TRUST-01** *(stretch)* — runtime capability expansion over named pipe — v2.0 Phase 11 (live supervised UAT promoted to pass by Phase 15 direction-b fix)
- ✔ **DETACHED-FIX-01** — detached-supervisor + ConPTY + restricted-token architecture fix (direction-b: gated PTY-disable + null-token + AppID WFP on the Windows detached path). Unblocks 4 Phase 13 UAT items (P05-HV-1, P07-HV-3, P11-HV-1, P11-HV-3) — all promoted to `pass`. v2.1 Phase 15 (the Phase 15 carrier moved into the v2.1 milestone bucket on scoping day 2026-04-18).
- ✔ **RESL-01** — CPU percentage cap on Windows Job Object (`--cpu-percent`) via `JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP`. Validated in Phase 16: Resource Limits.
- ✔ **RESL-02** — Memory cap on Windows Job Object (`--memory`) via `JobMemoryLimit` with `KILL_ON_JOB_CLOSE` preserved. Validated in Phase 16: Resource Limits.
- ✔ **RESL-03** — Wall-clock timeout (`--timeout`) via supervisor-side `Instant` deadline + `TerminateJobObject` (kernel `JOB_TIME` deliberately not used since it tracks CPU not wall-clock). Validated in Phase 16: Resource Limits.
- ✔ **RESL-04** — Process count cap (`--max-processes`) via `ActiveProcessLimit`. Validated in Phase 16: Resource Limits. `nono inspect` surfaces all four caps via the new `Limits:` block.
- ✔ **ATCH-01** — `nono attach <id>` on Windows detached sessions streams child stdout live, accepts stdin, supports clean detach (Ctrl-]d) + re-attach, and rejects a 2nd concurrent attach with a friendly busy error. Implemented via anonymous-pipe stdio at child spawn time bridged through the supervisor (no ConPTY on the detached path — preserves the Phase 15 `0xC0000142` fix structurally). Resize via `ResizePseudoConsole` explicitly downgraded to a documented limitation per D-07 (anonymous-pipe stdio is structurally exclusive of ConPTY). — v2.1 Phase 17.
- ✔ **AIPC-01** — Extended handle brokering on the Phase 11 capability pipe: Socket, Pipe, Job Object, Event, Mutex handles with `DuplicateHandle` MAP-DOWN semantics + access-mask validation + `capabilities.aipc` profile widening end-to-end (Profile threaded through `PreparedSandbox → LaunchPlan → execute_sandboxed → SupervisedRuntimeContext → WindowsSupervisorRuntime.resolved_aipc_allowlist`). Containment-Job runtime guard via `CompareObjectHandles`. Cross-platform child-side SDK with 5 `request_*` methods. — v2.1 Phases 18 + 18.1 (HUMAN-UAT item 3 WR-02 EDR deferred to v3.0).
- ✔ **CLEAN-01..04** — `cargo fmt --all` drift fix; 4 deterministic Windows test bugs fixed incl. UNC-prefix production bug in `query_path`; 10 WIP items triaged (6 backfilled, 2 reverted, 2 deleted); `is_prunable` retention predicate + `nono prune --older-than <DURATION>` + `--all-exited` + auto-sweep on `nono ps` (100-file threshold) + `NONO_CAP_FILE` structural no-op + one-shot cleanup of 1343 stale session files + `docs/session-retention.md`. — v2.1 Phase 19.
- ✔ **UPST-01** — `rustls-webpki` upgraded to 0.103.12 (clears RUSTSEC-2026-0098 + RUSTSEC-2026-0099); workspace crate versions bumped 0.30.1 → 0.37.1 across all 4 members. — v2.1 Phase 20.
- ✔ **UPST-02** — Upstream profile `extends` cycle guard + claude-code `.claude.json` symlink for token refresh. — v2.1 Phase 20.
- ✔ **UPST-03** — `keyring://service/account` URI + `?decode=go-keyring` + environment-variable filter flags + `command_blocking_deprecation` backport. — v2.1 Phase 20.
- ✔ **UPST-04** — `--allow-gpu` flag with 3-platform dispatch (Linux Landlock NVIDIA/DRM/AMD/WSL2 + NVIDIA procfs, macOS Seatbelt IOKit, Windows CLI-layer warning); GitLab ID tokens for trust signing with `validate_oidc_issuer` fail-closed validator. — v2.1 Phase 20.
- ✔ **WSFG-01** — `compile_filesystem_policy` emits rules for single-file Read/Write/ReadWrite + write-only-directory grants; `apply()` applies `SYSTEM_MANDATORY_LABEL_ACE` at `SECURITY_MANDATORY_LOW_RID` via `SetNamedSecurityInfoW` with mode-derived mask per D-01 encoding table. — v2.1 Phase 21.
- ✔ **WSFG-02** — `NonoError::LabelApplyFailed { path, hresult, hint }` + `AppliedLabelsGuard` RAII lifecycle wired into `prepare_live_windows_launch` (revert on `Drop`); ownership pre-check in `try_set_mandatory_label` skips system-owned paths (`C:\Windows`). — v2.1 Phase 21.
- ✔ **WSFG-03** — Phase 18 HUMAN-UAT Path B + Path C close-out; frontmatter transition achieved; live-CONIN$ pass verdicts folded into Phase 18.1 HUMAN-UAT items 1+2 pass via live dual-run. — v2.1 Phase 21 + 18.1.
- ✔ **PROF-01..04** — Profile struct alignment with upstream v0.38–v0.40: `unsafe_macos_seatbelt_rules`, `packs`, `command_args`, `custom_credentials.oauth2` deserialize on Windows; `claude-no-keychain` builtin profile shipped (verified `nono policy show claude-no-kc` resolves 31 security groups). — v2.2 Phase 22 (Plan 22-01, 12 commits, d7fc4ed8).
- ✔ **POLY-01..03** — Policy tightening: orphan `override_deny` fails closed at profile load (`NonoError::SandboxInit` + `.exists()` pre-filter); `--rollback` ↔ `--no-audit` clap-level mutex (parse-time conflict, post-CL-01-M carve-out preserves `--no-audit-integrity` orthogonality); `.claude.lock` moved to `allow_file` for both `claude-code` and `claude-no-kc` profiles. — v2.2 Phase 22 (Plan 22-02, 7 commits, 490a8a5c).
- ✔ **PKG-01..04 (partial)** — Package manager flat-shape subcommands `nono pull / remove / update / search / list` with Windows `%LOCALAPPDATA%` storage, Claude-Code hook registration, signed-artifact verification. 6/8 upstream cherry-picks landed. **Deferred to v2.3 backlog** (per ROADMAP.md): upstream `58b5a24e` `validate_relative_path` belt-and-suspenders + `9ebad89a` streaming `bytes`→`PathBuf` refactor with `tempfile::TempDir` + size limits + HTTP timeouts + `semver` dep + `ArtifactType::Plugin` variant + `bundle_json` field + `115b5cfa` `load_registry_profile` auto-pull. Each prerequisite is a Rule-4 architectural decision exceeding cherry-pick scope. — v2.2 Phase 22 (Plan 22-03).
- ✔ **OAUTH-01..03** — OAuth2 client-credentials Bearer-token injection in `nono-proxy` via `OAuth2Config` + `nono-proxy/src/oauth2.rs`; `custom_credentials.oauth2` parses in profiles; reverse-proxy HTTP upstream restricted to loopback-only (`127.0.0.1` / `localhost`) by default with `--allow-domain` strict-proxy composition for explicit external upstream. CL-03-M warns when literal `client_secret` value committed to profile JSON; CL-04-M skips OAuth2-only credentials in manifest export to prevent accidental token leak. HG-01-M redacts `OAuth2Config` secrets in `Debug` output. — v2.2 Phase 22 (Plan 22-04, 14 commits, 5c8df06a).
- ✔ **AUD-01** — `--audit-integrity` produces hash-chained Merkle-rooted event ledger: `audit-events.ndjson` per session with per-event leaf hash, hash-chain head, and Merkle root committed to `SessionMetadata.audit_integrity` (`hash_algorithm: "sha256"`, `event_count`, `chain_head`, `merkle_root`). `AuditRecorder` lifecycle integrated into supervisor; pre/post-merkle roots captured. — v2.2 Phase 22 (Plan 22-05a, 13 commits, d15a3ab6).
- ✔ **AUD-02** — `nono audit verify <id>` recomputes per-event leaves + chain head + Merkle root against `SessionMetadata.audit_integrity` and fails closed on any mismatch; `--public-key-file <PATH>` flag pins attestation verification to a specific signer (loops back to embedded `audit-attestation.bundle` public key when omitted, self-verification mode); HG-01-H upgrade — `verify_audit_attestation` now performs cryptographic DSSE bundle verification, not just structural shape check (commit cffb43b1). 2 fixture-driven tests `#[ignore]`'d pending sigstore-rs `KeyPair::from_pkcs8` re-enablement (deferred to v2.3 audit-attestation hardening sweep). — v2.2 Phase 22 (Plan 22-05a).
- ✔ **AUD-03 (SHA-256 portion + Windows Authenticode discriminant)** — `executable_identity` block (canonical `\\?\` path + SHA-256 file hash) recorded into `SessionMetadata`; on Windows, supervisor calls `WinVerifyTrust` and records the Authenticode validation discriminant (`Valid` / `Unsigned` / `InvalidSignature{hresult}`). **Deferred to v2.3 backlog**: chain-walker subject extraction (`signer_subject` + thumbprint) — `windows-sys 0.59` does not expose `WTHelperProvDataFromStateData` / `WTHelperGetProvSignerFromChain` without `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features; PR-555-era authenticode integration test left `#[ignore]` until Catalog/Sip features land or in-tree pkcs8 walker is added. — v2.2 Phase 22 (Plan 22-05a SHA-256 + Plan 22-05b Authenticode discriminant, 7 commits, b5640cd4).
- ✔ **AUD-04** — `prune` → `session cleanup` rename with v2.1 CLEAN-04 invariants byte-identical preservation guaranteed by formal `applied_labels_guard::audit_flush_before_drop` regression test (83 LOC). Five rename lifecycle items: (#1) new `nono session cleanup` subcommand with `--dry-run`/`--keep N`/`--older-than <DURATION>` matching legacy `prune` semantics; (#2) peer `nono audit cleanup` for ledger files; (#3) legacy `nono prune` hidden via `#[command(hide)]` + emits stderr deprecation warning on every invocation; (#4) `_` underscore-stamped ALL_SUBCOMMANDS test asserting hidden-prune contract; (#5) `NONO_CAP_FILE` structural no-op + 100-file auto-sweep on `nono ps` preserved across rename. — v2.2 Phase 22 (Plan 22-05b).
- ✔ **DRIFT-01** — Upstream-drift inventory tooling: twin `scripts/check-upstream-drift.{sh,ps1}` scripts + `make check-upstream-drift` target group commits in `upstream/main..HEAD` touching cross-platform files (`crates/nono/src/`, `crates/nono-cli/src/` excluding `*_windows.rs`/`exec_strategy_windows/`, `crates/nono-proxy/src/`, `crates/nono/Cargo.toml`) by category (profile, policy, proxy, audit, other). JSON output mode for templates and CI; default human table. Documented in `docs/cli/development/upstream-drift.mdx`. — v2.2 Phase 24 (Plan 24-01).
- ✔ **DRIFT-02** — GSD upstream-sync template at `.planning/templates/upstream-sync-quick.md` with diff-range spec, cherry-pick-per-commit pattern with `Upstream-commit:` 6-line trailer block, conflict-file inventory, Windows-specific retrofit checklist. Cross-linked from `PROJECT.md § Upstream Parity Process`. — v2.2 Phase 24 (Plan 24-02).
- ✔ **AUD-05** — Windows AIPC broker audit emissions. `handle_windows_supervisor_message` accepts `Option<&Arc<Mutex<AuditRecorder>>>` and emits a `capability_decision` ledger event at all 5 `audit_log.push` sites (File + 5 AIPC HandleKinds: Event, Mutex, Pipe, Socket, JobObject). New `RejectStage` discriminator (`BeforePrompt` / `AfterPrompt`) on `AuditEventPayload::CapabilityDecision` locks the WR-01 verdict-matrix asymmetry on the wire (Event/Mutex/JobObject mask gate → BeforePrompt; Pipe/Socket G-04 broker-failure flip → AfterPrompt; Approved + pre-stage rejections → None). `nono audit show <id>` surfaces a "Capability Decisions: N (M before-prompt, K after-prompt rejections)" counter line + `capability_decisions` JSON array via `read_capability_decisions_from_ledger` (BufReader+lines, best-effort degrade). Token redaction regression-guarded by `recorded_ledger_redacts_session_token`. D-19 (cross-platform byte-identical), D-21 (non-Windows behavior unchanged), D-03 (`SupervisorMessage::OpenUrl` arm untouched), and `AppliedLabelsGuard::Drop` ordering invariants all hold. — v2.2 Phase 23 (Plan 23-01, 3 commits 427e1283/a9307802/263795a9, 60 tests passing).

### Active (v2.3)

- **REQ-AIPC-NIX-01** — ✓ closed via Phase 25 Plan 25-02 (ADR shipped 2026-04-29).
- **REQ-AUDC-01..03** — ✓ all closed via Phase 28 Plan 28-01 (chain walker shipped 2026-04-30; behavior change: `<unknown>` sentinel fallback removed → fail-closed on chain-walk failure when `WinVerifyTrust=Valid`).
- **REQ-RESL-NIX-01..03** — Phase 25 Plan 25-01 (deferred to Linux/macOS-host session).
- **REQ-PKGS-01..04** — Phase 26: PKG Streaming Follow-Up (unplanned).
- **REQ-WRU-01..02** — ✓ closed (Phase 29 Plan 29-01 — locked design property; Option c).

(REQ-AAH-01 was Phase 27 active scope but re-deferred to v2.4 on 2026-04-29 after the Path B Windows-host attempt surfaced systemic test-harness blockers — see Deferred section below.)

### Deferred (v2.4+)

The five major v2.2-deferred items (PKG streaming, audit-attestation hardening, Authenticode chain-walker, WR-01 reject-stage unification, cross-platform RESL Unix backends) were pulled into v2.3 as Phases 25–29. After v2.3 execution started, audit-attestation hardening was re-deferred to v2.4 (Windows test-harness blockers); WR-01 closed at Phase 29 as locked design property (Option c — not unifiable without security or UX regression); Authenticode chain-walker closed at Phase 28. The deferral list below is what remains for v2.4+.

- **REQ-AAH-01 (audit-attestation hardening) — re-deferred from v2.3 Phase 27** (2026-04-29). Path B fixture redesign attempted on Windows; surfaced 3 systemic test-harness blockers (`dirs::home_dir()` ignores `USERPROFILE` on Windows, `LOCALAPPDATA`/`USERPROFILE` path-mismatch under partial env redirection, pre-existing v2.2-baseline audit-integrity exit-cleanup "Session not found"). Production code in `crates/nono-cli/src/audit_attestation.rs` byte-identical preserved; redesigned Test 1 body preserved in-tree under `#[ignore]` for v2.4 resumption. Resumption requires either (a) Linux/macOS host where `dirs::home_dir()` honors `HOME` env override, or (b) `NONO_TEST_HOME` production-code seam. See `.planning/phases/27-audit-attestation-hardening/27-01-SUMMARY.md`.
- **Windows test-harness HOME redirection** (new candidate v2.4 phase, surfaced 2026-04-29 by Phase 27). Add `NONO_TEST_HOME` env-var override to `dirs::home_dir()` callsites in `crates/nono-cli/src/` so integration tests can redirect home cleanly on Windows. Rule-4 architectural change with small surface (~5-10 callsites). Unblocks v2.3 test work on Windows hosts. Should land before any further v2.3 phase execution on Windows.
- **Upstream v0.41–v0.43 ingestion** (deferred at v2.3 scope-lock 2026-04-29) — first real load of the DRIFT-01/02 tooling shipped in v2.2 Phase 24. Skipped in v2.3 to keep the milestone shippable in 2 weeks; tooling stays warm regardless.
- **AIPC G-04 wire-protocol compile-time tightening** — `Approved(ResourceGrant)` inline at the wire type so `(Approved, grant=None)` becomes a compile-time error (deferred from v2.1 Plan 18.1-02; reaffirmed at v2.3 scope-lock). Cascades into `aipc_sdk.rs` child SDK demultiplexer + 23 pre-existing tests.
- **`windows-squash` → `main` merge** — re-deferred 2026-04-29 per quick-260428-rsu (commit `7911ef0e`); gated on PR-583 maintainer response. Cannot be pulled into v2.3 until that gate moves.
- **Cross-platform drift QA** + **Docs pass for v2.2 + v2.3 surfaces** (deferred at v2.3 scope-lock) — bundle into v2.4 alongside the v0.41+ upstream ingestion.
- **WR-02 EDR telemetry HUMAN-UAT item** — deferred to v3.0 pending EDR-instrumented runner.

### Out of Scope

- Gap 6b (runtime trust interception via kernel minifilter) — requires signed kernel driver; deferred to v3.0.
- Full feature parity for experimental Unix features not yet stabilized.
- Job Object nesting; global kernel walk (documented in v2.0-REQUIREMENTS.md archive).

## Context

- Windows parity is the current "honesty gap" in the product; users expect the same CLI experience across all supported OSs.
- The technically challenging core of this milestone is the Supervisor IPC (named pipes) and WFP driver/service orchestration.
- Previous work (PRs 530, 555, 583) has laid the foundation for native Windows functionality.
- Dark factory rules apply: fail closed, no silent fallback, no broadening claims beyond enforcement.

## Constraints

- **Security**: Fail secure on any unsupported shape â€” never silently degrade.
- **Compatibility**: Must support Windows 10/11 (modern Job Objects and WFP).
- **Performance**: Zero startup latency must be maintained for the Windows backend.

## Context

Shipped v2.1 on 2026-04-21 on `windows-squash` branch. Tech stack: Rust 1.77 (Edition 2021) across a 4-crate workspace (`nono`, `nono-cli`, `nono-proxy`, `nono-ffi`). Key runtime deps: `tokio` 1, `hyper` 1, `landlock` 0.4, `windows-sys` 0.59, `sigstore-rs`, `rustls-webpki` 0.103.12 (post-RUSTSEC-2026-0098/0099 upgrade). Windows-specific: WFP network enforcement, ConPTY interactive shell (Win10 17763+), ETW for `nono learn`, Low-IL mandatory-label filesystem sandboxing. Cross-platform: Landlock (Linux), Seatbelt (macOS), capability builder API with per-platform compile-down.

Workspace-internal LOC is growing but contained: v2.1 added ~17k lines across code + docs with the bulk in AIPC scaffolding, child SDK, WSFG label primitives, and upstream-parity ports. Branch `windows-squash` holds both v2.0 and v2.1; merge-to-main is a candidate task for the next milestone.

Feedback/observations from v2.1 shipping:
- AIPC handle brokering surfaced the need for end-to-end Profile wiring (Plan 18.1-03 closed the gap).
- Windows 11 26200 empirical finding: `WRITE_RESTRICTED` pipes need a logon-SID co-requirement ACE — MSDN-undocumented. Harness (`examples/pipe-repro.rs`) is now available for future SDDL investigations.
- WR-01 reject-stage asymmetry (Event/Mutex/JobObject reject BEFORE prompt, Pipe/Socket reject AFTER prompt) is a product decision, not a bug. Locked by `wr01_*` regression tests; stage unification decided at v2.3 Phase 29: locked as permanent design property (Option c) — the mask-gate vs broker-failure-flip distinction is structural (O(1) profile lookup vs O(syscall) post-approval), not unifiable without security or UX regression.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Supervisor Parity as Priority | Essential for "attach/detach" workflow used by long-running agents. | ✔ Good — attach/detach/ps/stop shipped in v1.0; v2.0 extended with `nono shell`, `nono wrap`, session commands; v2.1 added live-stream attach on detached path (Phase 17) |
| WFP over Temporary Firewall | Kernel-level enforcement is the "nono way"; temporary rules are a stopgap. | ✔ Complete — Phase 06 wired SID end-to-end, removed driver gate, cleaned duplicate activation path |
| Intentional `shell`/`wrap` omission | Lack of credible enforcement model on Windows; avoiding security over-claims. | ↶ Reversed in v2.0 — both now shipped with Job Object + WFP + ConPTY enforcement |
| Named Job Objects | Agent lifecycle management with atomic stop/list. | ✔ Good — v1.0 foundation; v2.1 Phase 16 extended with CPU/memory/timeout/process-count caps |
| WRITE_RESTRICTED token | Narrow the restricting-SID access-check gate to writes only so DLL loads and console init aren't blocked. | ✔ Good — fixes Bug #2 (`STATUS_ACCESS_DENIED`); residual Bug #3 on detached console grandchildren resolved by Phase 15 |
| Ship v2.0 with detached-console-grandchild bug as a documented known issue | Three fix directions attempted in Phase 14 plan 14-01 all failed the user smoke gate; real fix requires PTY + detached-supervisor architecture work which is its own investigation phase. Non-detached mode fully functional. | ✔ Resolved by Phase 15 (direction-b: gated PTY-disable + null-token + AppID WFP) on 2026-04-18 |
| Direction-b scoped waivers for detached Windows path (Phase 15) | The only empirically-working configuration is null token + no PTY. Non-detached keeps WRITE_RESTRICTED + session-SID + ConPTY unchanged. Low-IL isolation waived on detached path (Job Object + filesystem sandbox remain primary); per-session-SID WFP replaced by AppID WFP on detached path (still kernel-enforced; requires nono-wfp-service). | ✔ Good — waivers documented in commit `802c958` body; scope strictly detached-only |
| Phase 17 ATCH-01 anonymous-pipe stdio over ConPTY on detached path (D-07 resize downgrade) | ConPTY at detached-launch time trips Phase 15's `0xC0000142`; anonymous pipes preserve the fix structurally. Resize via `ResizePseudoConsole` is therefore unreachable; downgraded to documented limitation. | ✔ Good — `nono attach` streams live output + stdin; users needing full TUI fidelity use `nono shell` or non-detached `nono run` |
| AIPC `HandleKind` discriminators 0..=5 PINNED (Phase 18) | Wire-format stability lock so future cross-platform handle brokering doesn't need a migration. | ✔ Good — File=0, Socket=1, Pipe=2, JobObject=3, Event=4, Mutex=5 locked |
| AIPC access-mask MAP DOWN, not DUPLICATE_SAME_ACCESS (Phase 18) | `broker_*_to_process` pass `dwOptions=0` + explicit mask so child handle is the validated subset, not supervisor source's full ALL_ACCESS. | ✔ Good — T-18-01-11 mitigation; access-mask validation happens server-side |
| AIPC broker-failure flip via flow-control enforcement, not type-level (G-04 / Plan 18.1-02) | `Approved(ResourceGrant)` compile-time tightening would cascade into 23 pre-existing tests + child SDK demultiplexer; single-site `(decision, grant)` tuple construction keeps the shape illegal at the flow-control boundary. | ⚠️ Revisit v2.2 — D-09 + D-11 wire-protocol compile-time tightening deferred |
| AIPC privileged-port unconditional deny (Phase 18) | Socket broker rejects `port <= 1023` BEFORE any profile-widening check; cannot be widened by `capabilities.aipc`. | ✔ Good — structural; CONTEXT.md D-05 footnote |
| WRITE_RESTRICTED capability pipe requires logon-SID co-requirement ACE (Phase 21 debug) | Windows 11 26200's second-pass DACL access check requires BOTH a restricting-SID ACE AND a `SE_GROUP_MANDATORY` group-SID ACE. `OW` Owner Rights does NOT satisfy the co-requirement. | ✔ Empirical — fix in `build_capability_pipe_sddl` via `current_logon_sid()` helper (commit `938887f`); MSDN-undocumented; harness at `crates/nono-cli/examples/pipe-repro.rs` |
| CLEAN-04 auto-sweep threshold = 100 stale files + `NONO_CAP_FILE` structural no-op | Prevents sandboxed agent calling `nono ps` from triggering host-side session-file deletion. `--older-than` require-suffix parser rejects ambiguous bare integers. | ✔ Good — one-shot cleanup from 1392 to 49 stale files on dev host |
| Phase 20 `--allow-gpu` capability-routing deviation from upstream | Fork routes through `CapabilitySet` + sandbox backend layer, not upstream's `sandbox_prepare.rs::maybe_enable_*gpu` (fork 452 LOC vs upstream 1585 LOC — cherry-pick conflicts would dominate). D-21 Windows-invariance held (zero `*_windows.rs` touched). | ✔ Good — manual port preserved commit provenance via `Upstream-commit:` trailer |
| Phase 21 Low-IL ownership pre-check in `try_set_mandatory_label` (commit `da25619`) | Low-IL integrity is subtractive; Medium-IL system paths (e.g. `C:\Windows`) are already readable to Low-IL subjects through OS ACLs, so labeling them is unnecessary AND trips `ERROR_ACCESS_DENIED` for unprivileged users. | ✔ Good — inline comment preserved in source for future readers |
| WR-01 reject-stage asymmetry accepted as product decision (Plan 18.1-04, CONTEXT D-14) | Event/Mutex/JobObject reject BEFORE prompt (pre-broker mask gate); Pipe/Socket reject AFTER prompt (G-04-wrapped; direction/role/host checks post-approval). Locked by `wr01_*` regression tests. | ✓ Good — locked as permanent design property at v2.3 Phase 29 (Option c). Mask-gate is O(1) profile lookup; broker-failure flip is O(syscall) post-approval. Asymmetry is structural, not unifiable without security or UX regression. |
| Phase 22-05 split into 22-05a (audit core) + 22-05b (rename + Authenticode + CLEAN-04 sweep) on CONTEXT STOP trigger #3 (4f9552ec) | The `prune` → `session cleanup` rename touches `rollback_runtime.rs` / `supervised_runtime.rs` / `exec_strategy.rs`, all heavily forked on windows-squash; landing the rename atomically with the audit-core upstream port would have made the cherry-pick chain irreversible mid-plan. T-22-05-04 ABSOLUTE STOP guard required CLEAN-04 invariants byte-identical AFTER every source-code commit. | ✔ Good — split honored T-22-05-04; formal `applied_labels_guard::audit_flush_before_drop` regression test (83 LOC) prevents future Drop-flush regressions |
| Phase 22 POLY-02 mutex carve-out (CL-01-M, commit 27a5ff78) | `--rollback` ↔ `--no-audit` is the only POLY-02 mutex; `--no-audit-integrity` (cryptographic ledger only) is orthogonal to filesystem-snapshot rollback and now allowed alongside `--rollback`. Initial Plan 22-02 implementation conflated the two. | ✔ Good — code-review-fix flipped the conflict mask; rollback_audit_conflict.rs regression test re-targeted post-fix |
| Phase 22 PKG flat-shape over nested `nono package` parent | Upstream landed package operations as 5 flat top-level subcommands (`pull` / `remove` / `update` / `search` / `list`); the fork mirrors that shape verbatim per D-19 cross-phase byte-identical preservation. Nesting would have diverged from upstream and broken the hook-registration call sites that already assume flat dispatch. | ✔ Good — verified during Phase 22 UAT (Test 7 spec was wrong, 7b confirmed actual ship-shape) |
| Phase 22 Authenticode discriminant-only over chain-walker subject extraction (Decision 4 fallback) | `windows-sys 0.59` does not expose `WTHelperProvDataFromStateData` / `WTHelperGetProvSignerFromChain` without `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features (gates `CRYPT_PROVIDER_DATA` shape). Recording `Valid` / `Unsigned` / `InvalidSignature{hresult}` discriminant captures the security-relevant trust-decision boundary; subject + thumbprint are nice-to-have audit metadata. | ⚠️ Revisit v2.3 — chain-walker extraction deferred to audit-attestation hardening sweep (companion deferral with sigstore-rs `KeyPair::from_pkcs8` re-enablement) |
| Phase 22 audit-integrity verification upgraded to cryptographic DSSE (HG-01-H, commit cffb43b1) | Initial 22-05a Plan implementation only verified the *structural shape* of the `audit-attestation.bundle` — payload type, base64 envelope, signature presence. HG-01-H reviewer caught that this would silently accept a forged bundle whose signature was wrong. Cryptographic DSSE verification fail-closes on any signature mismatch. | ✔ Critical fix — landed via /gsd-code-review-fix flow; 2 fixture-driven tests `#[ignore]`'d pending sigstore-rs `KeyPair::from_pkcs8` re-enablement |

## Upstream Parity Process

To prevent the Windows-vs-macOS parity gap from re-opening as upstream ships v0.41+:

1. **Inventory drift** — `make check-upstream-drift` reports unabsorbed upstream commits grouped by file category. JSON output (`make check-upstream-drift ARGS="--from <tag> --to <tag> --format json"`) is suitable for templates and CI; default `--format table` for human review.
2. **Scaffold the sync** — copy `.planning/templates/upstream-sync-quick.md` to `.planning/quick/YYMMDD-xxx-upstream-sync-vX.Y/PLAN.md` and fill the single-brace `{placeholder}` markers (smoke check: `grep -oE '\{[a-z_]+\}' PLAN.md` returns zero).
3. **Cherry-pick per commit** — preserve the `Upstream-commit:` / `Upstream-tag:` / `Upstream-author:` / `Co-Authored-By:` / `Signed-off-by:` D-19 trailer block on every cherry-pick (template encodes the verbatim 6-line shape).
4. **Verify Windows retrofit** — for every cross-platform feature absorbed, confirm the Windows path either exists or is added behind `#[cfg(target_os = "windows")]`; the template's "Windows-specific retrofit checklist" enumerates the per-feature questions.

For the long-form runbook (output formats, categorization rules, fixture regeneration procedure, fork-divergence catalog rationale), see [`docs/cli/development/upstream-drift.mdx`](../docs/cli/development/upstream-drift.mdx).

- **AIPC Unix futures** — see [docs/architecture/aipc-unix-futures.md](../docs/architecture/aipc-unix-futures.md) for the locked decision on which AIPC HandleKinds admit Unix backends (File / Socket / Pipe = yes via SCM_RIGHTS; JobObject / Event / Mutex = Windows-only by design).

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? â†’ Move to Out of Scope with reason
2. Requirements validated? â†’ Move to Validated with phase reference
3. New requirements emerged? â†’ Add to Active
4. Decisions to log? â†’ Add to Key Decisions
5. "What This Is" still accurate? â†’ Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check â€” still the right priority?
3. Audit Out of Scope â€” reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-30 after Phase 28 close. v2.3 progress: 5/14 requirements closed — REQ-AIPC-NIX-01 (Phase 25 Plan 25-02 ADR, commit `30d6fdb1`); REQ-AUDC-01..03 (Phase 28 Plan 28-01 chain walker, commits `67ba4a99`/`70593110`/`5a4a8443`/`279c1b86`/`91a3f64a`). Phase 28 behavior change: `<unknown>` sentinel fallback on Valid+chain-walk-failure removed → fail-closed via `NonoError::SandboxInit` (D-AUDC-02: `AuditIntegrity` variant doesn't exist on fork). Phase 27 partial-deferred 2026-04-29 (REQ-AAH-01 to v2.4 due to Windows test-harness blockers); v2.4 candidate phase: "Windows test-harness HOME redirection" via `NONO_TEST_HOME` seam. Remaining v2.3 work: REQ-RESL-NIX-01..03 (Plan 25-01 awaits Linux/macOS host), REQ-PKGS-01..04 (Phase 26 unplanned), REQ-WRU-01..02 (Phase 29 unplanned). Earlier 2026-04-29 v2.2 close: 3 phases (22–24), 9 plans, 21 requirements; 146 commits since `v2.1`; +33,153 / −835 LOC.*
