---
milestone: v2.3
milestone_name: Linux POC Unblock + Deferreds Closure
status: active
created: 2026-04-29
---

# Requirements — v2.3 Linux POC Unblock + Deferreds Closure

**Defined:** 2026-04-29
**Core Value:** A Linux user running fork-Linux-build sees real enforcement (not silent no-ops) for resource limits, and v2.2's deferred items (PKG streaming, audit-attestation hardening, Authenticode chain-walker) ship as production-ready surfaces.

**Context:** v2.2 closed the upstream-v0.38–v0.40 cross-platform feature gap on Windows + installed a parity-drift prevention process. Three requirement clusters remained partially-deferred (PKG-01 streaming, AUD-03 Windows Authenticode chain-walker, audit-attestation fixture re-enablement). Plus the gap analysis at `.planning/quick/260429-gap-v039-linux-poc-vs-windows-fork-tip/PLAN.md` surfaced that fork-Linux-build's `--memory` / `--cpu-percent` / `--timeout` / `--max-processes` flags are silent no-ops with stderr warnings — a credibility issue for a Linux POC. v2.3 closes those + lands the WR-01 product decision that's been deferred since v2.1.

**Scope shape:** 5 phases (25–29), 14 requirements across 5 categories (RESL-NIX, AIPC-NIX, PKGS, AAH, AUDC, WRU). Cross-platform-first by construction. Mostly small/medium plans; longest is Phase 26 PKG streaming.

**Out of scope (explicit deferrals to v2.4 backlog):**
- Upstream v0.41–v0.43 ingestion (DRIFT tooling stays warm; first real load deferred one cycle).
- AIPC G-04 wire-protocol compile-time tightening (cascades into 23 tests + child SDK demultiplexer).
- `windows-squash` → `main` merge (gated on PR-583 maintainer response per quick-260428-rsu).
- Cross-platform drift QA (full Linux/macOS test-suite pass against fork tip).
- Docs pass (bring `docs/cli/*` current with v2.2+v2.3 surfaces).

---

## RESL-NIX — Cross-Platform RESL Unix Backends

Context: v2.1 Phase 16 shipped Job Object resource limits on Windows (CPU %, memory, wall-clock timeout, process count). The same flags were left as silent no-ops with stderr warnings on Linux/macOS — a deliberate scope cap at the time, but a Linux POC trips on the warnings and reads them as feature breakage. v2.3 lands real enforcement.

### REQ-RESL-NIX-01 — Linux cgroup v2 backends for memory / CPU / process count

- **What:** `--memory <bytes>` enforces via cgroup v2 `memory.max`; `--cpu-percent <0-100>` enforces via cgroup v2 `cpu.max` (`<quota> <period>` with period = 100000); `--max-processes <N>` enforces via cgroup v2 `pids.max`. Supervisor places the child PID into a fresh cgroup at launch time and writes the limits before `execve`. Removes the four "not enforced on linux" stderr warnings emitted today by `exec_strategy.rs:54-96`.
- **Enforcement:** Linux fork-Linux-build only. Requires cgroup v2 (mount at `/sys/fs/cgroup` with `cgroup2` filesystem). Supervisor verifies cgroup v2 availability at startup; fail-closed with clear error if cgroup v1 detected (no silent fallback).
- **Security:** Enforcement is kernel-level. Cgroup hierarchy created under `/sys/fs/cgroup/nono/<session-id>/`; cleaned up on session exit. Sandboxed agent cannot escape cgroup via fork (cgroup v2 propagates to descendants).
- **Acceptance:**
  1. `nono run --memory 256m -- bash -c "tail -c 1G </dev/urandom"` on Linux is killed by OOM (memory.max enforced); `nono inspect <id>` shows `memory_kill: true`.
  2. `nono run --cpu-percent 50 -- bash -c "yes >/dev/null"` on Linux pegs at ~50% CPU (cpu.max enforced); measurable via `top` or `/proc/<pid>/stat` time delta.
  3. `nono run --max-processes 10 -- bash -c "for i in {1..20}; do sleep 60 & done; wait"` on Linux fails after 10 forks (pids.max enforced); error contains `pids.max`.
  4. None of the four stderr warnings emit on Linux for these flags after this requirement lands.
  5. cgroup v1 system fails fast with `NonoError::UnsupportedPlatform` referencing cgroup v2.
- **Maps to:** v2.3 backlog "Cross-platform RESL Unix backends" (subsumed verbatim from PROJECT.md § Next Milestone).

### REQ-RESL-NIX-02 — Linux wall-clock timeout via supervisor + cgroup kill

- **What:** `--timeout <duration>` enforces wall-clock (not CPU-time) via supervisor-side `Instant` deadline + `cgroup.kill` on the cgroup tree at expiry. Mirrors v2.1 Phase 16 RESL-03 semantics on Windows (`TerminateJobObject`).
- **Enforcement:** Supervisor side, Linux only. Uses cgroup v2's `cgroup.kill` write to atomically SIGKILL all descendant processes.
- **Security:** No race window between deadline and kill — `cgroup.kill` is atomic. Sandboxed agent cannot race past the deadline by fork-storming.
- **Acceptance:**
  1. `nono run --timeout 5s -- sleep 60` on Linux exits with the documented timeout exit code at ~5s; `nono inspect <id>` shows `timeout_kill: true`.
  2. `nono run --timeout 5s -- bash -c "for i in {1..100}; do sleep 60 & done; wait"` on Linux kills all 100 child processes atomically at 5s.
- **Maps to:** v2.1 Phase 16 RESL-03 (Linux extension).

### REQ-RESL-NIX-03 — macOS `setrlimit` equivalents

- **What:** `--memory <bytes>` enforces via `RLIMIT_AS`; `--cpu-percent` *not supported on macOS* (no per-process CPU-quota equivalent; emit a clear NotSupportedOnPlatform error rather than silent no-op); `--max-processes <N>` enforces via `RLIMIT_NPROC`; `--timeout` enforces via supervisor `Instant` deadline + SIGKILL (no native wall-clock rlimit). Document the wall-clock-vs-CPU-time gap per RLIMIT_CPU semantics.
- **Enforcement:** macOS fork-macOS-build only. `setrlimit` called in pre-exec hook of fork.
- **Security:** Same kernel-level guarantees as Linux for the supported subset. `RLIMIT_AS` enforces address-space limit, not RSS — document the difference.
- **Acceptance:**
  1. `nono run --memory 256m -- bash -c "exec >/dev/null; <large alloc>"` on macOS aborts via `RLIMIT_AS` mmap failure.
  2. `nono run --max-processes 10 -- bash -c "for i in {1..20}; do sleep 60 & done; wait"` on macOS fails after 10 forks with `EAGAIN`.
  3. `nono run --cpu-percent 50 -- ...` on macOS fails fast with `NonoError::NotSupportedOnPlatform { feature: "cpu_percent_macos" }` — no silent degradation.
  4. `nono run --timeout 5s -- sleep 60` on macOS exits at ~5s via supervisor SIGKILL.
- **Maps to:** v2.1 Phase 16 RESL-01..04 (macOS extension; CPU-percent intentionally excluded).

---

## AIPC-NIX — AIPC Unix Futures Design

Context: AIPC handle brokering (Phase 18 + 18.1) is Windows-only by construction — Job Objects, Events, and Mutexes have no direct Unix analog. Sockets and Pipes plausibly admit Unix-domain socket + `SCM_RIGHTS` file-descriptor passing equivalents. The user-facing question for v2.4+ planning is which HandleKinds get Unix backends and which are documented as Windows-only by design. v2.3 produces an ADR-level decision document; no implementation.

### REQ-AIPC-NIX-01 — AIPC Unix futures ADR

- **What:** Design document at `docs/architecture/aipc-unix-futures.md` (or equivalent ADR location) documenting Decision D-NN: "AIPC HandleKinds 0–2 (File / Socket / Pipe) admit Unix backends via Unix-domain socket + `SCM_RIGHTS` file-descriptor passing; HandleKinds 3–5 (JobObject / Event / Mutex) are Windows-only by design — Linux equivalents (cgroup, eventfd, pthread mutex) don't broker the same way."
- **Enforcement:** Design-only; no code. ADR cross-linked from PROJECT.md and CONTEXT D-04 footnote.
- **Security:** N/A (documentation).
- **Acceptance:**
  1. ADR file committed; structure mirrors existing fork ADRs.
  2. PROJECT.md cross-links the ADR.
  3. Decision is falsifiable: each HandleKind has a yes/no verdict + 1-2 sentence rationale + (for "no") explicit alternate-mechanism note for users who need that primitive.
- **Maps to:** Derived from v2.2 close gap analysis (`.planning/quick/260429-gap-v039-linux-poc-vs-windows-fork-tip/PLAN.md`).

---

## PKGS — Package Manager Streaming Follow-Up

Context: v2.2 Phase 22 Plan 22-03 landed 6/8 cherry-picks of upstream's package management cluster. 2 cherry-picks were deferred because they required Rule-4 architectural decisions exceeding cherry-pick scope: `ArtifactType::Plugin` enum variant, `bundle_json` field, `validate_path_within` belt-and-suspenders alongside upstream's `validate_relative_path`. v2.3 closes those decisions + lands the streaming refactor.

### REQ-PKGS-01 — Streaming `bytes`→`PathBuf` refactor with size limits + HTTP timeouts + `semver` dep

- **What:** Port upstream `9ebad89a` — `nono package pull` streams artifact bytes directly to a `tempfile::TempDir` `PathBuf` rather than buffering full bytes in memory. Adds size limits enforced during stream (reject artifacts > configured cap), HTTP timeouts on `hyper` client (connect + idle), and a `semver` dep for version comparison in registry queries.
- **Enforcement:** Cross-platform (`hyper` + `rustls` are already in the workspace). Size cap default 500MB; configurable via `nono package pull --max-size <bytes>`.
- **Security:** Streaming verification (per existing PKG-04 acceptance) runs on streamed bytes; no full-buffer attack window. Tampered artifact rejected before install. HTTP timeouts prevent hung-connection DoS.
- **Acceptance:**
  1. `nono package pull <large-artifact>` of 200MB succeeds via streaming (memory profile peaks at ~10MB, not 200MB).
  2. Tampered mid-stream artifact rejected with clear error before install_dir placement.
  3. Artifact > `--max-size` cap rejected mid-stream with `NonoError::ArtifactTooLarge { actual, max }`.
  4. Connect timeout / idle timeout fires with clear error after configured threshold.
- **Maps to:** Upstream `9ebad89a refactor(pkg): stream package artifact downloads`. Deferred from v2.2 Plan 22-03.

### REQ-PKGS-02 — `validate_relative_path` belt-and-suspenders alongside fork's `validate_path_within`

- **What:** Port upstream `58b5a24e refactor(cli): improve artifact path validation`. Fork retains its existing `validate_path_within` (canonicalize-and-component-compare) as defense-in-depth alongside upstream's `validate_relative_path` (input-string pre-check). Both fire on every artifact path used in install_dir placement.
- **Enforcement:** Cross-platform. Order: input-string pre-check first (cheap rejection of obviously-bad shapes), canonicalize-and-component-compare second (definitive answer post-symlink-resolution).
- **Security:** Defense-in-depth. Fork's stance is stricter than upstream's verbatim pattern, matching CLAUDE.md § Path Handling guidance.
- **Acceptance:**
  1. Pack manifest with `..` traversal in path rejected by `validate_relative_path` input-string pre-check before any filesystem syscall.
  2. Pack manifest with symlink-traversal still rejected by `validate_path_within` canonicalize-and-compare path (post-symlink-resolution).
  3. Existing fork regression tests for `validate_path_within` still pass.
- **Maps to:** Upstream `58b5a24e`. Deferred from v2.2 Plan 22-03 pending Rule-4 architectural decision (kept fork's stricter check; recommended in v2.2 backlog).

### REQ-PKGS-03 — `ArtifactType::Plugin` enum variant + plumbing

- **What:** Add `Plugin` variant to `ArtifactType` enum (currently `Profile` + others); plumb through `package_cmd.rs`, `registry_client.rs`, manifest deserialization, install/remove paths. Closes the deferred-divergence comment at `crates/nono-cli/src/package_cmd.rs:631-643` introduced in v2.2 Plan 22-03's `73e1e3b8`.
- **Enforcement:** Cross-platform schema change; `#[serde(rename_all = "kebab-case")]` consistent with existing variants.
- **Security:** Plugin artifacts go through the same signed-artifact verification path as Profile. No new trust path introduced.
- **Acceptance:**
  1. `nono pull <plugin-pack>` deserializes the manifest's `artifact_type: plugin` field, places artifacts under `install_dir`, and registers any associated hooks.
  2. Round-trip serialization: `serde_json` produces `"plugin"` for the variant.
  3. Schema-validation rejects unknown `artifact_type` values fail-closed.
- **Maps to:** Deferred-divergence comment at `package_cmd.rs:631-643`. Required by REQ-PKGS-01 streaming work (the streaming path needs to know the artifact type to choose the install handler).

### REQ-PKGS-04 — `load_registry_profile` auto-pull

- **What:** Port upstream `115b5cfa feat(profile): load profiles from registry packs`. When a profile's `extends` chain references a registry-pack profile, `Profile::resolve` auto-pulls the pack via `nono package pull` (idempotent if already present locally) before resolving the extension.
- **Enforcement:** Cross-platform. Auto-pull triggers only when the referenced pack is absent locally; double-pull is a no-op (matches existing PKG-03 hook idempotency).
- **Security:** Auto-pull goes through the same signed-artifact verification path. No silent unauth'd network call — a profile resolve that requires registry access fails closed if registry credentials are missing.
- **Acceptance:**
  1. Profile with `extends: ["registry://vendor/pack@1.2.3"]` and pack absent locally triggers auto-pull, completes resolve.
  2. Profile resolve with no network access (and pack absent) fails with clear error pointing at the missing pack.
  3. Auto-pull respects the size limit + HTTP timeouts from REQ-PKGS-01.
- **Maps to:** Upstream `115b5cfa`. Deferred from v2.2 Plan 22-01's empty provenance commit `3bde347c`.

---

## AAH — Audit-Attestation Hardening

Context: v2.2 Plan 22-05a landed cryptographic DSSE bundle verification (HG-01-H, commit `cffb43b1`) but had to mark 2 fixture-driven tests `#[ignore]` because sigstore-rs 0.6.4 doesn't expose `KeyPair::from_pkcs8`. Required before publishing v2.2 attestation as production-ready.

### REQ-AAH-01 — Re-enable fixture-driven attestation tests

- **What:** Re-enable `#[ignore]`'d tests in `crates/nono-cli/tests/audit_attestation.rs`. Resolves the Rule-4 architectural decision: either upgrade sigstore-rs (may cascade through other crates) OR add a fork-internal pkcs8 parser (adds parsing surface, but contained scope). Plan-phase research documents both paths' cascade impact; chooses one with explicit rationale.
- **Enforcement:** Cross-platform. Either path delivers `KeyPair` reconstruction from a fixture-stored PKCS8-encoded key.
- **Security:** PKCS8 parsing must reject malformed input fail-closed. Whichever path chosen, the parsing surface is subjected to the same fuzz-test discipline as the rest of the trust path.
- **Acceptance:**
  1. Both `#[ignore]`'d tests in `audit_attestation.rs` run (no `#[ignore]` attribute) and pass.
  2. Whichever path is chosen, the architectural decision is documented in CONTEXT.md with the cascade impact for future readers.
  3. `cargo test -p nono-cli --test audit_attestation` exits 0 with no ignored tests.
  4. Threat model entry covers the new parsing surface (if path b) or the upgrade's known-issue ingestion (if path a).
- **Maps to:** v2.2 backlog "Audit-attestation D-13 fixtures re-enablement" (subsumed verbatim from PROJECT.md § Next Milestone).

---

## AUDC — Authenticode Chain-Walker Subject Extraction

Context: v2.2 Plan 22-05b ports `WinVerifyTrust` discriminant-only on Windows because `windows-sys 0.59` does not expose `WTHelperProvDataFromStateData` / `WTHelperGetProvSignerFromChain` without `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features (`CRYPT_PROVIDER_DATA` shape is gated). Records `Valid` / `Unsigned` / `InvalidSignature{hresult}` only, sets `signer_subject = "<unknown>"` and empty thumbprint on Valid signatures. v2.3 lights up the chain walker.

### REQ-AUDC-01 — Add windows-sys feature gates + chain-walker implementation

- **What:** Add `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features to `windows-sys` in workspace `Cargo.toml`. Implement `parse_signer_subject` + `parse_thumbprint` in `crates/nono-cli/src/exec_identity_windows.rs` using `WTHelperProvDataFromStateData` + `WTHelperGetProvSignerFromChain`.
- **Enforcement:** Windows-only (gated `#[cfg(target_os = "windows")]`). Linux/macOS paths unchanged.
- **Security:** Subject + thumbprint extraction adds parsing surface. Validate all extracted strings via existing `sanitize_for_terminal` before write into session metadata. SAFETY comments on every `unsafe` block.
- **Acceptance:**
  1. `nono audit show <id>` on Windows for a signed binary shows populated `signer_subject` (e.g., "CN=Anthropic Inc., ...") and non-empty SHA-1 thumbprint.
  2. `nono audit show <id>` on Windows for an unsigned binary still shows `Unsigned` discriminant (existing v2.2 behavior preserved); subject + thumbprint absent.
  3. `cargo build --workspace` on Windows succeeds with the new features enabled.
- **Maps to:** v2.2 backlog "Authenticode chain-walker subject extraction" (subsumed verbatim from PROJECT.md § Next Milestone).

### REQ-AUDC-02 — Re-enable `authenticode_signed_records_subject` substring assertion test

- **What:** Remove `#[ignore]` attribute from `authenticode_signed_records_subject` test in v2.2 Plan 22-05b. Test asserts `signer_subject` contains a non-empty CN substring on a signed test binary.
- **Enforcement:** Windows-only (test gated `#[cfg(target_os = "windows")]`).
- **Security:** N/A.
- **Acceptance:**
  1. Test runs (no `#[ignore]`) and passes against a fixture signed binary.
  2. `cargo test -p nono-cli --test authenticode_*` on Windows exits 0 with no ignored tests in this file.
- **Maps to:** Companion to REQ-AUDC-01.

### REQ-AUDC-03 — Update AUD-03 acceptance: populated `signer_subject` + thumbprint on Valid

- **What:** Update REQ-AUD-03 acceptance criteria 2 (in v2.2-REQUIREMENTS.md archive — informational; v2.3 adds an active criterion enforced by tests): on `Valid` Authenticode discriminant, `signer_subject` MUST be populated (non-empty after sanitization) and `thumbprint` MUST be non-empty (40-char hex SHA-1).
- **Enforcement:** Windows-only. Tested by REQ-AUDC-02 + new regression test asserting both fields populated.
- **Security:** Forces fail-closed: if chain walk fails to extract subject/thumbprint on a signature that `WinVerifyTrust` returned `Valid` for, audit recording fails-closed (not silently records "<unknown>").
- **Acceptance:**
  1. Signed binary: both fields populated; verified via `nono audit show <id> --json`.
  2. Chain-walk failure on Valid signature → audit-recording fail-closed with clear error (not silent "<unknown>").
  3. Unsigned binary: existing v2.2 behavior preserved (Unsigned discriminant; no subject/thumbprint extraction attempted).
- **Maps to:** Upgrade of v2.2 REQ-AUD-03 acceptance (Windows portion). Cross-references v2.2-REQUIREMENTS.md archive.

---

## WRU — WR-01 Reject-Stage Unification

Context: AIPC HandleKinds Event/Mutex/JobObject reject BEFORE the user prompt (mask gate); Pipe/Socket reject AFTER the user prompt (G-04 broker-failure flip). This asymmetry was locked by `wr01_*` regression tests in v2.1 Phase 18.1 and explicitly mirrored on the audit-ledger wire by Phase 23's `RejectStage` discriminator. v2.3 makes the product decision: align all 5 on a single stage OR lock the asymmetry as a permanent design property with explicit rationale.

### REQ-WRU-01 — Product decision on canonical reject stage

- **What:** Decision document at CONTEXT D-14 (or equivalent) recording one of:
  - **(a) Unify on BeforePrompt** — Pipe/Socket pre-checks move ahead of the prompt; G-04 broker-failure flip becomes unreachable for these kinds. Cleaner mental model; small refactor in Pipe/Socket helpers.
  - **(b) Unify on AfterPrompt** — Event/Mutex/JobObject mask-gate moves behind the prompt. User sees prompts they cannot approve; questionable UX.
  - **(c) Lock asymmetry as permanent** — accept that 3 kinds reject before, 2 reject after, with explicit rationale grounded in resource cost (mask-gate is cheap; broker-failure isn't). Update WR-01 docstring to call this a design property, not a bug.
- **Enforcement:** Decision-only at REQ level; REQ-WRU-02 lands implementation.
- **Security:** Whichever option chosen, no silent fallback. Audit ledger continues to record `reject_stage` per event (v2.2 Phase 23 invariant preserved).
- **Acceptance:**
  1. CONTEXT D-14 (or equivalent ADR) updated with the chosen option + 1-paragraph rationale.
  2. PROJECT.md key-decisions table updated with the outcome.
  3. Phase plan 29-NN cites the decision verbatim before implementation begins.
- **Maps to:** v2.1 Phase 18.1 deferred decision (CONTEXT D-14); v2.2 Phase 23 wire-protocol locking (PROJECT.md key-decisions).

### REQ-WRU-02 — Update `wr01_*` regression tests + ledger emission per chosen verdict matrix

- **What:** Whichever option from REQ-WRU-01 is chosen, update the 5 `wr01_*` regression tests in `capability_handler_tests` to reflect the new verdict matrix. Update the dispatcher's `RejectStage` emission at the 5 push sites in `handle_windows_supervisor_message` to match. Update Phase 23's `nono audit show <id>` rendering counter logic if the asymmetry shape changes (today: "M before-prompt, K after-prompt rejections").
- **Enforcement:** Cross-platform code path (RejectStage enum is on `AuditEventPayload`); Windows-only emission site.
- **Security:** No new security surface. Audit ledger contract preserved (events still emitted at all 5 push sites; only the stage classification changes).
- **Acceptance:**
  1. All 5 `wr01_*` tests pass with their assertions matching the chosen matrix.
  2. `audit_integrity_records_5_handle_kinds_in_ledger` (Phase 23 multi-kind E2E) still passes; ledger reflects the chosen matrix.
  3. `nono audit show <id>` counter line wording matches the chosen matrix (e.g., if option (a) Unify-on-BeforePrompt: counter shows only "M before-prompt rejections" with after-prompt count omitted entirely).
  4. CONTEXT.md D-14 updated with the implementation outcome.
- **Maps to:** Companion to REQ-WRU-01.

---

## Out of Scope (Explicit Deferrals to v2.4 backlog)

| Item | Reason | Destination |
|------|--------|-------------|
| Upstream v0.41–v0.43 ingestion | DRIFT-01/02 tooling (v2.2 Phase 24) stays warm; first real load deferred one cycle to keep v2.3 shippable in 2 weeks | v2.4 first phase |
| AIPC G-04 wire-protocol compile-time tightening (`Approved(ResourceGrant)`) | Cascades into 23 pre-existing tests + child SDK demultiplexer (`aipc_sdk.rs`); too large for v2.3 | v2.4+ |
| `windows-squash` → `main` merge | Gated on PR-583 maintainer response per quick-260428-rsu (re-deferred 2026-04-29) | When PR-583 unblocks |
| Cross-platform RESL drift QA (full test-suite pass on Linux/macOS) | New v2.3 RESL backends will surface flakes; QA after lands as v2.4 work | v2.4 |
| Docs pass (`docs/cli/*` for v2.2 + v2.3) | Mintlify doc surface maintenance is ongoing; bundle into v2.4 with the v0.41+ ingestion | v2.4 |
| WR-02 EDR HUMAN-UAT | Requires EDR-instrumented runner; no host available | v3.0 |

---

## Traceability

To be filled by gsd-roadmapper at v2.3 phase scope-lock (currently at REQUIREMENTS-write stage; phase mapping below is the planned shape).

| Requirement | Planned Phase | Status |
|-------------|---------------|--------|
| RESL-NIX-01 | Phase 25 (Plan 25-01) | Active |
| RESL-NIX-02 | Phase 25 (Plan 25-01) | Active |
| RESL-NIX-03 | Phase 25 (Plan 25-01) | Active |
| AIPC-NIX-01 | Phase 25 (Plan 25-02) | Active |
| PKGS-01 | Phase 26 | Active |
| PKGS-02 | Phase 26 | Active |
| PKGS-03 | Phase 26 | Active |
| PKGS-04 | Phase 26 | Active |
| AAH-01 | Phase 27 (PARTIAL) | Re-deferred to v2.4 (2026-04-29) — Path B Windows attempt surfaced 3 systemic test-harness blockers; production code byte-identical preserved; redesigned Test 1 body preserved in-tree under `#[ignore]` for v2.4 resumption. See `.planning/phases/27-audit-attestation-hardening/27-01-SUMMARY.md`. |
| AUDC-01 | Phase 28 (Plan 28-01) | Complete (2026-04-30; commits 67ba4a99/70593110/5a4a8443) — chain walker live; `parse_signer_subject` returns CERT_X500_NAME_STR keyed-RDN; `parse_thumbprint` returns 40-char UPPERCASE hex SHA-1 |
| AUDC-02 | Phase 28 (Plan 28-01) | Complete (2026-04-30; commit 279c1b86) — `authenticode_signed_records_subject` test relocated inline (PATH-4 per CONTEXT override) and re-enabled; #[ignore] count → 0 |
| AUDC-03 | Phase 28 (Plan 28-01) | Complete (2026-04-30; commit 70593110) — fail-closed `?` propagation in `query_authenticode_status` Valid branch; `<unknown>` sentinel fallback removed; reuses `NonoError::SandboxInit` (D-AUDC-02 deviation: `AuditIntegrity` variant doesn't exist on fork) |
| WRU-01 | Phase 29 | Active |
| WRU-02 | Phase 29 | Active |

**Coverage target:**
- v2.3 requirements: 14 total
- Mapped to phases: 14
- Unmapped: 0

---
*Requirements defined: 2026-04-29.*
*Scope-lock: 2026-04-29 at v2.3 milestone start (option Scope A from /gsd-new-milestone).*
