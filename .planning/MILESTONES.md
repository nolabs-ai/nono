# Milestones

## v2.6 UPST6 + v2.5 Drain (Shipped: 2026-05-25)

**Phases completed:** 7 phases, 23 plans, 28 tasks

**Key accomplishments:**

- Drained the 16-WARNING + 12-INFO REVIEW.md backlog inherited from Phase 37 + Phase 43; wired NONO_TRUST_OIDC_ISSUER as production code; deleted the synchronous pack-update path; promoted CGROUP_V2_HINT to a single source of truth; closed every REVIEW finding with an explicit disposition.
- Drained the v2.5 test-hygiene backlog: Class D deny-overlap re-enabled with security-equivalent either-or assertion, Class E env_vars flakes pinned to subprocess isolation, and cross-binding regression tests landed in both nono-py and nono-ts to lock the v24 broker FFI mapping.
- 1. [Documentation polish] CLI doc grep gate
- One-liner:
- One-liner:
- One-liner:
- One-liner:
- URL:
- Outcome:
- Zero `absorbed-via: unmatched` rows detected across the v0.41.0..v0.43.0 backfill ledger.
- REQ-UPST6-02: IN PROGRESS — this plan closes 1 of 9 clusters.
- One-liner:
- Fork SHA:
- 1. linux.rs test section conflict (C5-01)
- 1. [Rule 1 - Bug] Edition 2024 `if let` guard syntax in `parse_capability_source`
- One-liner:
- One-liner:
- One-liner:
- One-liner:
- One-liner:
- `nono setup --from-file <PATH>` populates the cached Sigstore trusted root from a local JSON via the existing `load_trusted_root` + `check_trusted_root_freshness` pipeline (D-32-03 expiry gate); byte-identical `std::fs::copy` with best-effort cleanup on failure; clap-mutex with `--refresh-trust-root`. Exits the sigstore-verify dep-bump treadmill for POC users.
- 1. [Rule 1 - Bug] PowerShell exit-code corruption with `Write-Error` + `$ErrorActionPreference='Stop'`

---

## v2.5 Backlog Drain + UPST5 (Shipped: 2026-05-20)

**Phases:** 4 phases shipped (37, 41, 42, 43).

**Plans / Tasks:** 24 plans, 34 tasks.

**Stats:** 172 commits (`25e88e61..a9b64440`), 547 files changed, +35,299 / −138,869 LOC (net deletion dominated by Phase 43 upstream-sync churn). Timeline: 5 days (2026-05-15 → 2026-05-20).

**Requirements:** 13/13 satisfied (REQ-RESL-NIX-01/02/03 + REQ-PKGS-04 + REQ-CI-01/02/03 + REQ-BROKER-CR-01..04 + REQ-UPST5-01/02).

**Known deferred items at close:** 32 (see STATE.md `## Deferred Items`). Categories: 3 phase-level human-verification gaps (live CI on push for Phases 37/41/43), 3 partial UAT scenario sets (Phases 37/41/43 — 13 pending scenarios), 5 follow-up todos (Phase 41 Class D/E + v24 broker CR-01/02 lockstep), 21 historical quick-task slugs marked `missing`/`unknown` (mostly pre-v2.5 stragglers).

**Key accomplishments:**

- **Phase 37 — Linux RESL backends + PKGS auto-pull (6 plans).** Closed the 3-year Linux silent-no-op security regression for `--memory` / `--cpu-percent` / `--max-processes` by routing all 4-of-5 cgroup v2 detection sites through `NonoError::UnsupportedKernelFeature { feature, hint }` with the LOCKED `cgroup_no_v1=all` boot-flag hint; FFI exhaustive-match arm maps to `ErrUnsupportedPlatform` (ABI-stable). Limits-block emission via `format_limits_block` with LOCKED Linux strings (`memory: 100M (cgroup v2 memory.max)` / `cpu_percent: 25 (cgroup v2 cpu.max 25000 100000)` / `max_processes: 5 (cgroup v2 pids.max)`). NEW `linux_cpu_percent_throttles_yes_loop` integration test (FIRST functional CPU-throttle test) + `linux_max_processes_5_fork_bomb_contained` alongside existing N=10 boundary; `Delegate=cpu cpuset io memory pids` user-service drop-in for ubuntu-24.04 runner. Cargo-install-style registry-profile auto-pull (`nono run --profile claude-code-edge -- cmd`) with `--no-auto-pull` + `NONO_NO_AUTO_PULL` env-var opt-out, `ResolveContext` threading, DiagnosticFormatter footer, 5 e2e integration tests + multi-endpoint mock TCP server (no mockito per D-14), CI-time keyless sigstore-sign via GH Actions OIDC. Sigstore-rust v0.7.0 bump closes 2 pre-existing TUF-trust-root flakes carried since v2.3 Plan 26-02 (`trust::bundle` 31/31 tests pass post-bump). Closed REQ-RESL-NIX-01/02/03 + REQ-PKGS-04.
- **Phase 41 — CI cleanup + v24 broker code-review closure (10 plans + 1 gap-closure).** Reset every CI lane to green: Linux + macOS Clippy (cross-target verified via `--target x86_64-unknown-linux-gnu`), 5 Windows CI jobs (Build, Integration, Regression, Security, Packaging). Resolved MSI validator `-BrokerPath` mandatory parameter mismatch threaded from CI invocation through `windows-test-harness.ps1` to `build-windows-msi.ps1`. Codified cross-target clippy verification protocol as enforcement-shaped MUST/NEVER bullet in CLAUDE.md + new `.planning/templates/cross-target-verify-checklist.md`. v24 broker code-review closure: `BrokerNotFound` FFI remap (`-1 ErrPathNotFound` → `ErrSandboxInit`), broker FFI null/INVALID handle rejection pre-cross-boundary, empty `--inherit-handle` list rejection, Job-object test silent-SKIP→FAIL policy. Baseline SHA `13cc0628` recorded as Phase 43 baseline-aware CI gate anchor; SUMMARY frontmatter `skipped_gates_load_bearing` vs `_environmental` convention documented. Closed REQ-CI-01/02/03 + REQ-BROKER-CR-01..04.
- **Phase 42 — UPST5 audit (1 plan).** First audit cycle where the `windows-touch` column actually fires per D-39-C3 conservative-default disposition. DIVERGENCE-LEDGER.md for upstream `v0.53.0..v0.54.0` (anchor `94fc4c6a`): 7 clusters / 18 commits / 4 will-sync + 2 fork-preserve + 1 won't-sync. 3 windows-touch:yes commits dispositioned (5d821c12 + 0748cced + ce06bd59) with explicit fork-preserve conservative-default rationale + fork-side empty-state analysis. `## ADR review` per-cell L/M/H verdict table on 5 dimensions (security, windows, maintenance, divergence, contributor); outcome (a) confirm Phase 33 Option A `continue` strategy (Phase 33 ADR Accepted, re-confirmed v2.4 close). `## Empirical cross-check` covering 4 Phase-41-touched fork-shared files (closing the `feedback_cluster_isolation_invalid` empirical lesson). UPST6 backlog stub queued at v2.5 § Future Cycles per D-42-B4 (cadence trigger met by v0.55.0 tag fetched 2026-05-17 during audit-open). Closed REQ-UPST5-01.
- **Phase 43 — UPST5 sync execution (6 plans + 43-01b workspace foundation).** Cherry-pick + D-20 manual-replay execution across 6 plans. 11 D-19 cherry-picks across Clusters 1+3+7 with verbatim lowercase 6-line `Upstream-commit:` trailers (Phase 40 convention). 3 D-20 manual replays across Clusters 4+5 with `Upstream-replayed-from:` trailers in `a46b6bf9` (combined 0748cced + 5d821c12 Windows registry detection replay) + `fe04e887` (ce06bd59 cross-platform `platform.rs` foundation — 659 lines verbatim from upstream + Windows registry extension factory functions). Cluster 2 (`8b888a1c`) mid-flight reclassified `will-sync → split`: workspace edits (MSRV 1.95, nix/landlock/getrandom workspace deps) landed fork-authored in Plan 43-01b; Edition 2024 source-file migration (`#[unsafe(no_mangle)]` rewrites) deferred to v2.6/UPST6 per Plan 43-01b DEC-3. DIVERGENCE-LEDGER amendment committed at `79715aa5`. NEW `crates/nono-cli/src/pack_update_hint.rs` module with `show_pack_update_hints` / `refresh_synchronous` / `refresh_in_background`. NEW `nono update` / `nono pin` / `nono unpin` / `nono outdated` subcommands. `snapshot.rs::validate_restore_target` per-file TOCTOU gate added (best-effort against symlink swaps). D-43-E1 Windows-only-files invariant respected (only Plan 43-01b's 6-line MSRV `is_multiple_of()` relaxation in `session_commands_windows.rs`). 2208 tests pass / 0 failed / 19 ignored on Windows host. 6 PR-SECTION.md contribution artifacts staged for orchestrator umbrella PR. Closed REQ-UPST5-02 (umbrella PR open + baseline-aware CI lane diff vs `13cc0628` deferred to orchestrator post-merge per worktree-mode pattern).
- **v2.5 process hardening.** (1) Cross-target clippy verification codified in CLAUDE.md as MUST/NEVER enforcement rule + `.planning/templates/cross-target-verify-checklist.md` reference artifact — closes the third-miss risk where Windows-host workspace clippy silently passes while Linux/macOS cfg-gated code drifts. (2) `feedback_cluster_isolation_invalid` empirical lesson recorded: DIVERGENCE-LEDGER cluster isolation can be empirically false (Phase 43 Plan 43-01 proved upstream `8b888a1c` had cross-cluster re-export dependencies); UPST plan-phase must diff-inspect re-export surfaces, not just `--name-only`. (3) Cluster 2 split-disposition precedent established: when an audit `will-sync` cluster reveals architectural blocker mid-execution, split into fork-authored partial-advancement + deferred-source-migration is a valid third disposition.

---

## v2.4 Complete the Partial Ports + UPST4 (Shipped: 2026-05-15)

**Phases:** 5 shipped on Windows host (35, 36, 36.5, 39, 40); 2 re-anchored to v2.5 (37 + 38 — host-blocked Linux/macOS execution; carry forward to Phase 37 + 38 in v2.5 backlog).

**Plans / Tasks:** 17 plans, 62 tasks.

**Stats:** 148 commits (`24b0f0a3..9b172c0d`), 169 files changed, +35,949 / -2,590 LOC. Timeline: 4 days (2026-05-12 → 2026-05-15).

**Key accomplishments:**

- **Phase 35 — UPST3-closure quick wins (3 plans).** Windows env-filter wiring (`exec_strategy_windows/launch.rs::build_child_env` + 4 cfg-gated tests) closing P34-DEFER-08a-1, Linux Landlock profiles-dir pre-creation eliminating first-run "No such file or directory" UX bug closing P34-DEFER-09-1, Windows test-harness hygiene closing P34-DEFER-01-1 + 10-1. Closed REQ-PORT-CLOSURE-01, -06, -07.
- **Phase 36 — UPST3 deep closure (6 plans).** Full `deprecated_schema` module port (LegacyPolicyPatch serde rewriter + DeprecationCounter per-key AtomicBool + `--strict` fail-closed mode replacing Phase 34-04b's pragmatic seed), atomic mechanical rename of `override_deny` → `bypass_protection` across 17 fork-side source files with serde+clap alias backwards-compat per D-36-B3 indefinite, `yaml_merge` wiring trio + `wiring.rs` base abstraction + 11 tests, b5f0a3ab deep ExecConfig refactor + escape-quote pipeline rider. Closed REQ-PORT-CLOSURE-02, -04, -05.
- **Phase 36.5 — Profile drafts absorption (1 plan, optional).** Upstream `829c341a` absorbed as 3-commit D-20 manual replay: `nono profile init --draft` / `--refresh` / `promote` / `validate --draft` with SHA-256 sidecar integrity, refuse-always shadowing safeguards, `NonoError::ActionRequired` typed variant, C FFI mapping, advisory + strict `package_status.rs`. Closed REQ-PORT-CLOSURE-03.
- **Phase 39 — UPST4 audit (1 plan).** DIVERGENCE-LEDGER inventory of upstream v0.52.0..v0.53.0 with 7 themed clusters across 22 cross-platform commits and per-cluster dispositions (4 will-sync, 2 fork-preserve, 1 won't-sync). `windows-touch` column shows ZERO yes hits in v0.52..v0.53 range; § ADR review confirms Phase 33 Option A `continue` strategy remains Accepted. Empirical correction: 2 known windows-touch candidates (`5d821c12`, `0748cced`) land in `v0.54.0~5^2`, not v0.53.0 — absorbed by UPST5. Closed REQ-UPST4-01.
- **Phase 40 — UPST4 sync execution (6 plans).** 14 D-19 cherry-picks absorbed onto fork `main`: Cluster C1 (5 commits, v0.52.1 proxy hardening — libdbus isolated from no-keyring builds, NODE_USE_ENV_PROXY for Node 20.6+, accurate keystore warnings), Cluster C2 (2 commits, CLI `--allow` validation + SandboxState domain-allowlist + `nono why --host` proxy-domain awareness), Cluster C6 (2 commits, new `nono::scrub` module + lib.rs re-export + audit integration), Cluster C7 (5 commits, v0.52.1..v0.53.0 release-ride — Landlock ABI cache via OnceLock, full failure diagnostic, 3 release version bumps absorbed CHANGELOG-only per Phase 34 convention). 3 D-20 manual replays: Cluster C4 (FP-PROFILE-SAVE `filesystem.suppress_save_prompt` with `ignore` serde alias + canonical-path filter; D-40-B1 upgrade rule did NOT fire — 14 trial-cherry-pick conflicts + behavioral surprise) and Cluster C5 (FP-PROXY-TLS native CA loading + structural credential-match policy doc — D-40-B2 LOCKED). Cluster 3 (PTY scrollback) won't-sync per D-40-D1. Baseline-aware CI gate verified zero `success → failure` transitions vs baseline `4665ae75` on every Wave 1 + Wave 2 head commit. PR #922 holds all 6 plan contribution sections (umbrella to upstream). D-40-E1 invariant: 1 codified addendum exception (`96886ae9` +4 lines via `ScrubPolicy::secure_default()` factory). Closed REQ-UPST4-02.
- **Phase 40 process hardening.** Three blocking anti-patterns codified for future UPST sync phases: (1) cross-target clippy gates 3+4 are load-bearing on Windows host (`aws-lc-sys`/`ring` cross-compilers absent — CI substitute mandatory; categorize as `skipped_gates_load_bearing` in SUMMARY frontmatter, NOT `skipped_gates_environmental`); (2) PLAN COMPLETE not declarable until baseline-aware CI gate passes (Task 5 wait-for-CI gate baked into Wave 1+ plan templates from commit `be46f483`); (3) SUMMARY frontmatter must distinguish load-bearing skips from environmental skips so orchestrators can escalate CR-A-class regressions correctly. Memory note + plan templates updated.

**Requirements:** 14 in-milestone (PORT-CLOSURE-01..07, RESL-NIX-01..03, PKGS-04, UPST4-01..02, AAHX-HOST-01) + PKGS-01 retroactively closed via v2.3 Phase 26-02 = 15 total.

**Closed:** 10 (PORT-CLOSURE-01..07 + UPST4-01..02 + PKGS-01 retroactive).
**Re-anchored to v2.5:** 5 (RESL-NIX-01..03 + PKGS-04 → v2.5 Phase 37; AAHX-HOST-01 → v2.5 Phase 38 — Linux/macOS host availability gate).

**Cross-phase integration verdict:** clean (7/7 wiring claims PASS, 0 BLOCKERS per `.planning/milestones/v2.4-MILESTONE-AUDIT.md`).

**Audit verdict at close:** `gaps_found` (environmental + paperwork) — gaps are categorically host-blocked or audit-open cataloging glitches on completed quick-tasks, not functional regressions. **Acknowledged: proceed close with 5 host-blocked requirements re-anchored to v2.5 backlog (Phase 37 + 38) and 43 open artifact items deferred (see STATE.md § Deferred Items → v2.4 close).**

### Known Gaps

- **REQ-RESL-NIX-01..03** + **REQ-PKGS-04** — Linux/macOS host availability required; carry to v2.5 Phase 37.
- **REQ-AAHX-HOST-01** (optional) — Linux/macOS host availability required; carry to v2.5 Phase 38; skip if Phase 37 surfaces no Phase-27-related gap.
- **Phase 35 + 36 human-verify** — 11 UAT items + 7 verification items remain `human_needed`; mostly Linux/macOS or interactive Windows console gated. 3 of these (env_filter_tests, profile_cli debug-syntax, docs MDX bypass_protection inspection) were exercised at v2.4 close and passed.
- **4 v24 code-review todos** (broker FFI not-found mapping, broker null-handle validation, broker empty-handle-list path, job-object test skip policy) — small Windows-host follow-ups; carry to v2.5.
- **Phase 41 backlog** (Linux/macOS clippy + test pre-existing failures, Windows build/integration/packaging/regression/security) — out-of-scope baseline-aware reds; documented in Phase 40 SUMMARYs.

---

## v2.3 — Linux POC Unblock + Deferreds Closure

**Status:** ✅ SHIPPED 2026-05-12 with documented carry-forwards
**Started:** 2026-04-29
**Shipped:** 2026-05-12
**Branch:** `main` (v2.2's `windows-squash` fast-forwarded into `main` at `1ef30c63` mid-milestone)

**Goal:** A Linux user running fork-Linux-build sees real enforcement (not silent no-ops) for `--memory` / `--cpu-percent` / `--timeout` / `--max-processes`; v2.2's deferred items (PKG streaming, audit-attestation hardening, Authenticode chain-walker) ship as production-ready surfaces.

**Phases:** 12 phases (Phases 25–34, including 27.1 + 27.2 inserted post-scope-lock).
**Plans shipped:** 51 plans (25→6, 26→2, 27→1, 27.1→3, 27.2→4, 28→1, 29→1, 30→5, 31→6, 32→5, 33→4, 34→13).
**Requirements:** 20 — RESL-NIX-01..03, AIPC-NIX-01, PKGS-01..04, AAH-01, NTH-01..03, AAHX-01..03, AUDC-01..03, WRU-01..02. Closed: 15 substantively (12 direct + 3 transitive via 27.1+27.2). Host-blocked carry-forward to v2.4: 5 (REQ-RESL-NIX-01..03 + REQ-PKGS-01 + REQ-PKGS-04).

**Stats:**

- 422 commits since `v2.2` tag (~13 days, 2026-04-29 → 2026-05-12).
- 369 files changed; +91,624 / −5,506 LOC across code + docs + planning artifacts.
- 2 new ADRs (`audit-bundle-target.md`, `upstream-parity-strategy.md`) + 1 new crate (`crates/nono-shell-broker/`).

**Audit verdict at close:** `gaps_found` from `.planning/milestones/v2.3-MILESTONE-AUDIT.md` (audited 2026-05-09T21:15Z; Phase 34 post-audit close 2026-05-12). Gate triggered by institutional artifact gaps (4 phases missing VERIFICATION.md final: 26, 27, 28, 29) + 5 host-blocked requirements + Phase 31 verification = human_needed. Substantively healthy: 14/14 integration points WIRED, 5/5 E2E flows PASS, 12/12 cluster dispositions resolved in Phase 34, 0 D-34-E1 violations across 75 Phase 34 commits, `learn_windows.rs` byte-identity preserved start-to-end. **Acknowledged: proceed close with carry-forwards captured in `.planning/MILESTONE-CONTEXT.md` for v2.4 absorption.**

**Key accomplishments:**

- **Cross-platform RESL design (Phase 25)** — AIPC Unix Futures ADR shipped (`docs/architecture/aipc-unix-futures.md` locks Decision D-NN for 6 HandleKind discriminants — Socket/Pipe admit Unix backends via `SCM_RIGHTS`; JobObject/Event/Mutex Windows-only by design). Plan 25-01 (cgroup v2 + setrlimit RESL backends) plan + CONTEXT committed (`3ed80d38`); execution deferred to v2.4 pending Linux/macOS host coverage.
- **PKG streaming follow-up (Phase 26)** — REQ-PKGS-02 + REQ-PKGS-03 closed via Plan 26-01 with D-20 manual replay of `58b5a24e` (cherry-pick would have deleted fork's `validate_path_within` — security regression); both validators preserved as belt-and-suspenders. `ArtifactType::Plugin` added as 7th variant. Plan 26-02 (PKGS-01 streaming + PKGS-04 auto-pull) deferred to v2.4.
- **Audit-attestation hardening (Phases 27 + 27.1 + 27.2)** — `NONO_TEST_HOME` seam at `crates/nono-cli/src/config/mod.rs::nono_home_dir()` unblocks Windows-host integration tests. Audit-loader swap from `rollback_session::load_session` → `audit_session::load_session` for audit-only sessions. `audit-bundle-target.md` ADR (Option A: always at `<audit_root>/<id>/audit-attestation.bundle`) supersedes Plan 22-05a Decision 5. Both `#[ignore]` attributes removed from `audit_attestation.rs`. REQ-AAH-01 transitively closed.
- **Authenticode chain-walker (Phase 28)** — `WTHelperProvDataFromStateData` → `WTHelperGetProvSignerFromChain` → `CertGetNameStringW(CERT_X500_NAME_STR)` + `CertGetCertificateContextProperty(CERT_HASH_PROP_ID)` replaces v2.2 Plan 22-05b Decision 4 `<unknown>` sentinel. Fail-closed `?` propagation on chain-walk failure when `WinVerifyTrust=Valid`. 11 SAFETY blocks; D-19/D-21 invariants hold.
- **WR-01 reject-stage unification (Phase 29)** — Locked-as-design (Option c): mask-gate vs broker-failure-flip is O(1) profile lookup vs O(syscall) post-approval; asymmetry is structural. All 5 `wr01_*` regression tests preserved as guards on the locked matrix.
- **Windows broker pattern productionized (Phases 30 + 31, SHELL-01)** — Phase 30 surfaced CSRSS console-subsystem ALPC denial at Low-IL via ProcMon. Phase 30 postscript broker-PoC (`260508-m99`) validated RESEARCH A1 same day. Phase 31 productionized into `crates/nono-shell-broker/`: Medium-IL broker self-degrades, spawns Low-IL shell child via `CreateProcessAsUserW(dwCreationFlags=EXTENDED_STARTUPINFO_PRESENT)`. Authenticode chain-walker records consistent signer for `nono.exe` + `broker.exe`. SHELL-01 → ✔ validated (was v3.0-deferred).
- **Sigstore integration (Phase 32)** — TUF cached-root rewrite at `crates/nono/src/trust/bundle.rs::load_production_trusted_root` (verify-is-offline invariant: zero httpmock hits during keyless verify). `nono setup --refresh-trust-root` per-user no-admin cache. `nono trust verify --keyless` requires mandatory `--issuer` + `--identity` (regex via `regress` post-`extract_signer_identity`). Phase 31 broker trust loop closed via Phase 28 chain-walker self-introspection at BrokerLaunch dispatch. 16 D-32-* decisions; 2 ADRs (`broker-trust-anchor.md`, `sigstore-tuf-cache.md`).
- **Upstream v0.40.1..v0.52.0 audit (Phase 33)** — DIVERGENCE-LEDGER.md inventory of 12 themed clusters / 97 commits (8 will-sync + 2 fork-preserve + 2 won't-sync). Strategic ADR `upstream-parity-strategy.md` (Option A `continue` accepted; 3 options × 5 criteria L/M/H scoring). G-25-DRIFT-01 RESL-rename hypothesis empirically disproved (ZERO matching commits in v0.40.1..v0.52.0).
- **Upstream v0.41–v0.52 sync execution (Phase 34, UPST3)** — 13 plans / ~75 commits / 12 cluster dispositions resolved. 2 mid-flight plan splits (34-04 → 34-04b canonical-schema D-20 restructure; 34-08 → 34-08a/b env-surface partial-port discovery). 4 D-20 manual-replay plans absorbed upstream's heavily-diverged surface without deleting fork-only Windows wiring. `learn_windows.rs` byte-identity preserved across the full chain. 13 deferred items tracked (10 NEEDS-FOLLOW-UP-PLAN + 3 ACCEPTED-PERMANENT). `34-PHASE-OUTCOMES.md` documents C1 (PTY) + C3 (Unix-socket) won't-sync addendum.
- **windows-squash → main merged** — fast-forwarded at commit `1ef30c63` mid-milestone (per quick-260428-rsu PR-583 maintainer response).

**Known deferred items at close:** Captured in `.planning/MILESTONE-CONTEXT.md` for v2.4 absorption — Theme 1 (10 Phase 34 partial-port deferrals), Theme 2 (Plans 25-01 RESL Unix + 26-02 PKGS streaming/auto-pull, host-blocked), Theme 3 (UPST4 for upstream v0.52.1 / v0.52.2 / v0.53.0 ingestion).

Full details: `.planning/milestones/v2.3-ROADMAP.md` + `.planning/milestones/v2.3-REQUIREMENTS.md` + `.planning/milestones/v2.3-MILESTONE-AUDIT.md`.

---

## v2.2 — Windows/macOS Parity Sweep

**Status:** ✅ SHIPPED 2026-04-29
**Started:** 2026-04-24
**Shipped:** 2026-04-29
**Branch:** `windows-squash` (continuing from v2.1; merge-to-main pending per quick-260428-rsu)

**Goal:** When v2.2 ships, a Windows user and a macOS user have the same `nono` commands available with the same flags and the same security guarantees. Close the Windows-vs-macOS drift opened by upstream `always-further/nono` shipping v0.38.0–v0.40.1 without Windows ports, and install drift-prevention tooling so v0.41+ becomes a maintenance task instead of a milestone-scale sync.

**Phases:** 3 phases (Phases 22–24).
**Plans shipped:** 9 plans (22 → 6 plans including the 22-05a/b split; 23 → 1 plan; 24 → 2 plans).
**Requirements:** 21 — PROF-01..04, POLY-01..03, PKG-01..04, OAUTH-01..03, AUD-01..05, DRIFT-01..02. Closed: 19 fully + 2 complete-partial (PKG-01 has 2 streaming cherry-picks deferred; AUD-03 has Authenticode chain-walker subject extraction deferred).

**Stats:**

- 146 commits since `v2.1` tag (29 `feat(...)` commits across phases 22/23/24).
- 154 files changed; +33,153 / −835 LOC across code + docs + planning artifacts.
- ~+8.4k LOC of Rust code (53 source files in `crates/`).

**Key accomplishments:**

- **Profile struct alignment (PROF-01..04)** — `unsafe_macos_seatbelt_rules`, `packs`, `command_args`, `custom_credentials.oauth2` deserialize on Windows; `claude-no-keychain` builtin profile shipped (Phase 22 Plan 22-01, 12 commits, `d7fc4ed8`).
- **Policy tightening (POLY-01..03)** — orphan `override_deny` fails closed at profile load; `--rollback`/`--no-audit` clap-level mutex with CL-01-M `--no-audit-integrity` carve-out preserved; `.claude.lock` moved to `allow_file` for both `claude-code` and `claude-no-kc` (Phase 22 Plan 22-02, 7 commits, `490a8a5c`).
- **Package manager (PKG-01..04, partial)** — `nono pull/remove/update/search/list` flat-shape subcommand tree with Windows `%LOCALAPPDATA%\nono\packages\<name>` storage, Claude-Code hook registration via fork's `hooks.rs`, signed-artifact verification at install time (Phase 22 Plan 22-03; 6/8 cherry-picks landed, 2 deferred to v2.3 backlog).
- **OAuth2 proxy + reverse-proxy gating (OAUTH-01..03)** — `nono-proxy/src/oauth2.rs` client-credentials Bearer-token injection; reverse-proxy HTTP upstream restricted to loopback-only by default with `--allow-domain` strict-proxy composition; CL-03-M literal `client_secret` warning + CL-04-M manifest-export skip + HG-01-M Debug redaction (Phase 22 Plan 22-04, 14 commits, `5c8df06a`).
- **Audit integrity + DSSE attestation (AUD-01, AUD-02, AUD-03 SHA-256, AUD-04)** — hash-chained Merkle-rooted ledger; cryptographic DSSE bundle verification (HG-01-H upgrade, commit `cffb43b1`); `prune` → `session cleanup` rename with formal `applied_labels_guard::audit_flush_before_drop` regression test (83 LOC) guaranteeing v2.1 CLEAN-04 byte-identical preservation; hidden `nono prune` deprecation alias; `nono audit cleanup` peer subcommand (Phase 22 Plans 22-05a + 22-05b after CONTEXT-STOP-3 split, `d15a3ab6` + `b5640cd4`).
- **Windows Authenticode exec-identity discriminant (AUD-03 Windows portion)** — `WinVerifyTrust` records `Valid` / `Unsigned` / `InvalidSignature{hresult}`; chain-walker subject extraction deferred to v2.3 pending `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features in `windows-sys` (Phase 22 Plan 22-05b, commit `cb34a82a`).
- **Windows AIPC ledger emissions (AUD-05)** — `RejectStage` enum (`BeforePrompt | AfterPrompt`) on `AuditEventPayload::CapabilityDecision` locks the WR-01 verdict-matrix asymmetry on the wire; `handle_windows_supervisor_message` emits `capability_decision` events at all 5 push sites (File + 5 AIPC HandleKinds); `nono audit show <id>` surfaces a `Capability Decisions: N (M before-prompt, K after-prompt rejections)` counter + `capability_decisions` JSON array (Phase 23 Plan 23-01, 3 commits `427e1283` / `a9307802` / `263795a9`, 60 tests passing).
- **Parity-drift prevention (DRIFT-01, DRIFT-02)** — `make check-upstream-drift` twin scripts with `$(OS)==Windows_NT` Makefile dispatch + 6-category path-prefix lookup + 3 frozen golden JSON fixtures; GSD upstream-sync template at `.planning/templates/upstream-sync-quick.md` with byte-exact 6-line D-19 trailer; Mintlify long-form runbook at `docs/cli/development/upstream-drift.mdx`; PROJECT.md `## Upstream Parity Process` cross-link (Phase 24, 2026-04-27).

**Plan splits & deviations:**

- **Plan 22-05 → 22-05a + 22-05b** at CONTEXT STOP trigger #3 on upstream cherry-pick `4f9552ec`. T-22-05-04 ABSOLUTE STOP guard required CLEAN-04 invariants byte-identical AFTER every source-code commit; the split honored that gate and installed a permanent regression test as a future-regression guard.
- **Phase 23 layer-2 deviation** authorized by plan Step 7 — `aipc_handle_brokering_integration` cannot reach `pub(super)` `handle_windows_supervisor_message`; layer-1 multi-kind E2E in `capability_handler_tests` (`audit_integrity_records_5_handle_kinds_in_ledger`) provides the substitute coverage per the plan's authorized fallback clause.

**Known deferred items at close:** 20 (6 UAT bookkeeping gaps, 4 verification human_needed flags, 10 stale or pending quick-task index pointers including the 260428-rsu re-deferral pending PR-583 maintainer response). See STATE.md `## Deferred Items` for the full table. None block release.

**Deferred to v2.3 backlog:**

- PKG streaming follow-up (`58b5a24e` + `9ebad89a` + `115b5cfa` + `ArtifactType::Plugin` + `bundle_json` field).
- Audit-attestation hardening sweep (sigstore-rs `KeyPair::from_pkcs8` re-enablement; 2 `#[ignore]`'d fixture-driven tests).
- Authenticode chain-walker subject extraction (`Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features).
- WR-01 reject-stage unification.
- AIPC G-04 wire-protocol compile-time tightening.
- Cross-platform RESL Unix backends.

**Deferred to v3.0:** WR-02 EDR HUMAN-UAT item.

**Archive files:**

- `.planning/milestones/v2.2-ROADMAP.md`
- `.planning/milestones/v2.2-REQUIREMENTS.md`

Git tag: `v2.2`.

---

## v2.1 — Resource Limits, Extended IPC, Attach-Streaming & Cleanup

**Status:** ✅ SHIPPED 2026-04-21
**Started:** 2026-04-18
**Shipped:** 2026-04-21
**Branch:** `windows-squash` (continuing from v2.0 + Phase 15)

**Goal:** Deliver Job Object resource limits (CPU / memory / timeout / process-count), extend the Phase 11 capability pipe to broker additional handle types end-to-end, land attach-streaming on detached Windows sessions, sync to upstream v0.37.1 (including the rustls-webpki security upgrade), enable single-file filesystem grants on Windows so the `claude-code` profile runs cleanly, and clean up v2.0 WIP.

**Phases:** 7 phases (Phases 16–21 plus decimal Phase 18.1).
**Plans shipped:** 25 plans.
**Requirements:** 13 — RESL-01..04, AIPC-01, ATCH-01, CLEAN-01..04, UPST-01..04, WSFG-01..03.

**Key accomplishments:**

- Job Object resource limits — CPU/memory/timeout/process-count caps with kernel enforcement (Phase 16).
- `nono attach` on detached Windows sessions now streams child stdout live via anonymous-pipe stdio; friendly multi-attach error (Phase 17).
- AIPC handle brokering for Socket / Pipe / Job Object / Event / Mutex over the Phase 11 capability pipe + `capabilities.aipc` profile-widening schema + containment-Job runtime guard (Phases 18 + 18.1).
- 5 HUMAN-UAT gaps (G-02..G-06) closed in Phase 18.1 with live dual-run widening proof on rebuilt binary.
- Cleanup workstream — fmt drift, 4 Windows test flakes (incl. UNC-prefix `query_path` production bug), 10 WIP items triaged, `is_prunable` + `nono prune --older-than`/`--all-exited` + auto-sweep on `nono ps`, 1343-file one-shot prune on dev host (Phase 19).
- Upstream parity sync to v0.37.1 — rustls-webpki 0.103.12 security upgrade (RUSTSEC-2026-0098/0099), `keyring://` URIs, env-var filtering, `--allow-gpu` with NVIDIA Linux allowlist, GitLab ID tokens for trust signing (Phase 20).
- Windows single-file filesystem grants via per-file Low-IL mandatory-label ACEs + `AppliedLabelsGuard` RAII lifecycle + ownership-skip pre-check; unblocks `claude-code` profile's `git_config` group on Windows (Phase 21).

**Notable in-flight finding:** Windows 11 26200's `WRITE_RESTRICTED` tokens require BOTH a restricting-SID ACE AND a logon-SID ACE in the pipe DACL for the second-pass access check to pass — MSDN-undocumented; discovered via 13-variant systematic SDDL iteration in `crates/nono-cli/examples/pipe-repro.rs`. Fix in commit `938887f`.

**Known deferred items at close:** 17 (5 UAT bookkeeping gaps, 3 verification human_needed flags, 9 stale quick-task index pointers to already-removed directories). See STATE.md `## Deferred Items` for the full table. None block release.

**Archive files:**

- `.planning/milestones/v2.1-ROADMAP.md`
- `.planning/milestones/v2.1-REQUIREMENTS.md`

Git tag: `v2.1`.

---

## v2.0 — Windows Gap Closure (a.k.a. "Windows Parity")

**Status:** ✅ SHIPPED 2026-04-18 (with v2.0-known-issue carry-forward to Phase 15)
**Started:** 2026-04-06
**Shipped:** 2026-04-18
**Branch:** `windows-squash` (committed; push/merge-to-main pending per user)

**Goal:** Close the 7 remaining feature gaps between Windows and Unix platforms — `nono wrap`, session log commands, interactive ConPTY shell, port-granular WFP policy, proxy credential injection, ETW-based learn, and runtime capability expansion (stretch) — so everyday CLI usage reaches cross-platform parity.

**Phases:** 10 phases (Phases 5–14; Phase 15 created as v2.1 follow-up for the carry-forward).
**Plans shipped:** 28 firm plans. Plan 14-01 escalated to Phase 15.

**Key accomplishments:**

- WFP promoted to primary enforced network backend with SID-based filtering (Phase 06).
- `nono wrap` on Windows with Direct strategy + help-text correction (Phases 07, 14-02).
- Interactive `nono shell` via ConPTY on Windows 10 build 17763+ (Phase 08).
- Port-granular WFP policy + proxy credential injection (Phase 09).
- `nono learn` on Windows via ETW with Win32-format paths (Phase 10).
- Runtime capability expansion over named pipe with constant-time token auth (Phase 11).
- Human Verification UAT resolved with terminal verdicts on all 10 items (Phase 13).

**Known deferred items at close:**

- Detached-supervisor + ConPTY + restricted-token `0xC0000142 STATUS_DLL_INIT_FAILED` on sandboxed console grandchildren. Carried forward to Phase 15 per explicit user shipping decision.
- Affected UAT legs waived as `v2.0-known-issue`: P05-HV-1, P07-HV-3, P11-HV-1, P11-HV-3.
- P09-HV-1 live end-to-end waived as `no-test-fixture` (no built-in network-profile-with-credentials ships out of the box).

**Archive files:**

- `.planning/milestones/v2.0-ROADMAP.md`
- `.planning/milestones/v2.0-REQUIREMENTS.md`
- `.planning/milestones/v2.0-MILESTONE-AUDIT.md`

Git tag: `v2.0` (see `git show v2.0` for tagger signature).

---

## v1.0 — Windows Alpha (shipped 2026-03-31)

**Status:** ✅ SHIPPED 2026-03-31
**Git tag:** `v1.0`

**Delivered:** Windows is a first-class nono release target with signed artifacts, WFP service packaging, and no preview language anywhere.

**Key accomplishments:**

- Authenticode signing pipeline (sign-windows-artifacts.ps1 + release.yml gate).
- WFP service packaging via WiX 4 ServiceInstall/ServiceControl in machine MSI.
- All preview language removed from runtime, docs, CI, and README.
- Formal Windows promotion criteria (21 gates, all checked).
- Supervisor parity (attach, detach, ps, stop) — Phases 1–2.
- Snapshot/rollback for Windows filesystems — Phase 4.
- MSI packaging and code signing automation — Phase 4.

**Phases:** 4 (Phases 1–4). Requirements: SUPV-01..05, NETW-01..03, STAT-01..02, DEPL-01..02 (12 total).

(An earlier draft of this entry referred to this milestone as "v1.0 — WIN-1706 Option 1: Windows Library/Runtime Alignment" and was never properly closed; the real shipped content is what the `v1.0` git tag points at from 2026-03-31. That earlier draft is superseded by this entry.)
