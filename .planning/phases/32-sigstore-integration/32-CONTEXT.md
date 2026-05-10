# Phase 32: Sigstore Integration - Context

**Gathered:** 2026-05-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Make the public-good (Sigstore Fulcio + Rekor) signing and verification path production-ready end-to-end on the Windows native build, AND close the broker-binary trust loop introduced by Phase 31. Phase 32 was added to ROADMAP.md as a stub on 2026-05-09; quick task `260509-s9m` (Sigstore verification on Windows MSVC) surfaced the concrete failure mode this phase addresses (`sigstore_verify::TrustedRoot::production().await` rejects bundled TUF metadata with "0 valid signatures of required 3"). The keyless CLI (`nono trust sign --keyless`) and the keyless verify path both already exist in code (`crates/nono-cli/src/trust_cmd.rs:259-1008`) but have zero test coverage and no usable production root.

**In scope (4 areas the user explicitly selected):**

- **A — Unblock the 2 failing trust unit tests** (`crates/nono/src/trust/bundle.rs:877` `load_production_trusted_root_succeeds` + `:914` `verify_bundle_with_invalid_digest`). Subsumed by C (root cause).
- **B — Public-good keyless signing CLI surface hardening.** Code already exists; phase adds test coverage, error-message polish, default verify policy, and release-pipeline audit.
- **C — TUF root refresh hardening** — design and ship the cached-root + setup-time-refresh + offline-verify story.
- **H — Verify `nono-shell-broker.exe` at launch** via Authenticode chain-walker (Phase 28 reuse), closing the broker dispatch trust loop introduced by Phase 31.

**Out of scope (explicitly):**

- **sigstore-rs version bump** (D-32-04). Stay on 0.6.5; fix in our code.
- **Interactive browser OAuth for keyless signing** (D-32-09). Keyless stays CI-only; local devs use `--keyref`.
- **Cosign compatibility** (Sigstore Bundle v0.3+ adoption beyond what 0.6.5 ships). Not a Phase 32 deliverable.
- **Verifying nono.exe itself** at launch (only the broker — nono.exe self-introspection is the trust anchor per D-32-13).
- **`#[cfg(feature = "online-tests")]` lane** (D-32-02). All keyless tests use mock Fulcio/Rekor + frozen TUF fixture.
- **Job Object / token-level network-blocking fallback for `--block-net`.** Surfaced in `260509-stb` SUMMARY as a candidate decision point but explicitly NOT in scope here — that's a network-enforcement concern, not a Sigstore concern.
- **Migrating audit-attestation bundle target.** Phase 27.2's D-27.2-01 / D-27.2-02 (audit bundle at `<audit_root>/<id>/audit-attestation.bundle` with back-compat shim) stay locked. Phase 32 builds on top of that surface, doesn't revisit it.

</domain>

<decisions>
## Implementation Decisions

### TUF root refresh & test unblock (areas A + C)

- **D-32-01 (Locked):** TUF trusted root is cached under `<NONO_TEST_HOME>/.nono/trust-root/` and refreshed via a new `nono setup --refresh-trust-root` subcommand (per-user, no admin required). Setup fetches fresh TUF root metadata from `https://tuf-repo-cdn.sigstore.dev` (sigstore-rs's default TUF repo) and caches the verified result. Setup fails fail-closed if the fetch fails. `crates/nono/src/trust/bundle.rs::load_production_trusted_root` is rewritten to load from the cache instead of calling `TrustedRoot::production()` directly (which today goes to the stale bundled-in-sigstore-rs root). Verify subsequently runs offline against the cached root.

- **D-32-02 (Locked):** The 2 failing unit tests (`load_production_trusted_root_succeeds` at `crates/nono/src/trust/bundle.rs:877`, `verify_bundle_with_invalid_digest` at `:914`) get a frozen TUF fixture decoupling them from live Sigstore infra. Fixture lives at `crates/nono/tests/fixtures/trust-root-frozen.json` (or equivalent under the existing test fixtures convention). New helper `load_test_trusted_root()` in the trust module's test scope returns a `TrustedRoot` parsed from the frozen fixture. Tests use the fixture; production code uses the cached refreshed root.

- **D-32-03 (Locked):** When the cached TUF root has expired and no network is available to refresh it, `nono trust verify --keyless` (and any other consumer) fails-closed with an explicit recovery message: `NonoError::TrustVerification` carrying text along the lines of "Sigstore trusted root expired YYYY-MM-DD; run `nono setup --refresh-trust-root` (requires network)." Matches the CLAUDE.md fail-secure principle and mirrors the existing `--block-net` WFP-required diagnostic pattern. Verify NEVER does inline network — the "verify is offline" invariant is preserved.

- **D-32-04 (Locked):** `sigstore-verify` and `sigstore-sign` stay pinned to 0.6.5. We do NOT bump as part of Phase 32 — the cache-refresh design works regardless of sigstore-rs's bundled root version. Avoids re-litigating the upstream-divergence we already accepted (PR #777/#778 closed unmerged upstream). If a future upstream sigstore-rs ships a relevant fix, revisit then.

- **D-32-05 (Locked):** First-run UX (cached root never initialized) is symmetric with D-32-03: hard fail-closed with `NonoError::TrustPolicy("Sigstore trusted root not initialized; run `nono setup --refresh-trust-root` (requires network).")`. One user-visible recovery command for both missing-and-stale cases.

- **D-32-06 (Locked):** The frozen test fixture is pinned indefinitely. We do NOT add a CI rotation job. Tests don't verify against current Sigstore infra — they need a syntactically-valid root that loads. TUF rotation in the live repo doesn't invalidate a captured-once-good frozen root for our test purposes. If sigstore-rs's expected root structure ever changes incompatibly, fixture is regenerated then; until then it's stable.

### Public-good keyless CLI hardening (area B)

- **D-32-07 (Locked):** Test coverage for the keyless flow uses **mock Fulcio/Rekor**, not live infra. Add `crates/nono-cli/tests/keyless_sign.rs` integration test that wraps a `MockSigningContext` (sigstore-rs supports test injection OR we wrap one ourselves) returning a deterministic local-CA-issued cert + a fake Rekor entry. Covers: OIDC discovery → predicate build → bundle write → verify roundtrip. No CI dependency on Sigstore uptime; no real Rekor entries created. Live-infra smoke is left to manual operator verification (cookbook addition per D-32-10).

- **D-32-08 (Locked):** Keyless verify (`nono trust verify --keyless <bundle>`) requires the user to pass **explicit** `--issuer` and `--identity` flags. No permissive default — verify fails-closed if the user did not provide them. Matches CLAUDE.md fail-secure. `--issuer` accepts the OIDC issuer URL (e.g. `https://token.actions.githubusercontent.com`); `--identity` accepts a regex pattern matching the SAN/OIDC identity claim (e.g. `^https://github\.com/always-further/nono/\.github/workflows/release\.yml@refs/tags/v.*$`). Phase 32 ships documented examples for the most common cases (GitHub Actions release, GitLab CI release).

- **D-32-09 (Locked):** Keyless signing stays **CI-only**. We do NOT add interactive browser OAuth (`cosign`-style flow). Local-developer signing uses the existing `nono trust sign --keyref <key>` keyed path. Phase 32 polishes the existing `discover_oidc_token` error message (`crates/nono-cli/src/trust_cmd.rs:658-674`) to suggest `--keyref` for local dev: "no ambient OIDC credentials found. Keyless signing requires a CI environment with OIDC ambient identity (GitHub Actions with `permissions: id-token: write`, GitLab CI, etc.). For local development, use `nono trust sign --keyref <key>` instead." No new flag; no browser wiring.

- **D-32-10 (Locked):** Phase 32 includes a release-pipeline audit task: read `.github/workflows/release.yml`, document current signing posture (keyed vs keyless), decide whether to migrate. **Recommendation pending audit** is to keep whatever current is and document it; if keyed, ship a baked-in `~/.nono/trust-policy.json` template wiring D-32-08's identity for the project's release pipeline, so users running `nono trust verify` against the official release artifacts get the right verification posture by default. Migration to keyless is itself out of scope for Phase 32 — that's a separate decision recorded as a v2.4+ candidate.

### Broker.exe Authenticode verification at launch (area H)

- **D-32-11 (Locked):** Broker verification mechanism is **Authenticode**, reusing Phase 28's chain-walker primitives (`crates/nono-cli/src/audit_attestation.rs` Authenticode path: `parse_signer_subject` + `parse_thumbprint` + the underlying `WTHelperProvDataFromStateData` → `WTHelperGetProvSignerFromChain` → `CertGetNameStringW` chain). NOT Sigstore (despite the phase name) — Windows-native, simpler, aligns with the existing MSI signing pipeline, no sidecar bundle file. The broker is a Windows-only spawn target; Authenticode is the platform-native trust mechanism for executables at launch time.

- **D-32-12 (Locked):** When Authenticode verification of `nono-shell-broker.exe` fails (signature invalid, chain unverifiable, or subject doesn't match expected — see D-32-13), `nono.exe` fails-closed with `NonoError::TrustVerification` carrying a clear diagnostic: "broker.exe Authenticode signature invalid — expected subject `…`, got `…`; refusing to spawn." No escape hatch (no `NONO_BROKER_VERIFY=off` env var, no flag). Same fail-closed-with-recovery pattern as `--block-net` WFP-required. **Implementation note (planner's discretion):** dev builds via `cargo build` produce unsigned brokers — the planner needs to handle this somehow (likely `#[cfg(debug_assertions)]` skip in the `BrokerLaunch` arm, OR an install-layout detector that distinguishes `target/debug/` from `<install_dir>/`). The user explicitly chose no escape-hatch flag, so the dev-build skip must be a structural decision, not a runtime override.

- **D-32-13 (Locked):** The expected Authenticode trust anchor is **nono.exe's own subject + thumbprint**. At launch, `nono.exe` extracts ITS OWN Authenticode signature via the Phase 28 chain-walker, then requires the broker's signature to match (subject and thumbprint). No baked-in expected-publisher constants; no config-file trust anchor. Self-bootstrapping: if `nono.exe` runs at all on Windows, its own subject is implicitly trusted by the OS (else CodeIntegrity would have refused to load it); piggybacking on that means broker trust = "broker is signed by whoever signed me." Naturally handles publisher-cert rotation since both binaries are signed by the same release pipeline (Phase 31 Plan 04 release.yml signs both `nono.exe` and `nono-shell-broker.exe` with the same identity).

- **D-32-14 (Locked):** Verify on **every** broker dispatch. No cache. The Authenticode chain walk costs ~50-200ms on modern Windows hardware; acceptable for shell launches (which are user-initiated and infrequent). No cache invalidation logic, no race window, no on-disk cache to attack. Simplest and most secure.

### Cross-cutting invariants

- **D-32-15 (carried forward, locked):** `crates/nono/` byte-identical D-19 invariant from Phase 27.x continues. Most Phase 32 changes live in `crates/nono-cli/src/{setup.rs, trust_cmd.rs, exec_strategy_windows/launch.rs}` plus new test files. The only `crates/nono/` changes are:
  1. The `bundle.rs::load_production_trusted_root` rewrite (read from cache instead of `TrustedRoot::production()`) and its 2 failing tests' fixture migration. This is a deliberate library API surface change since the function's contract changes ("returns the cached refreshed root" vs "returns the bundled-with-sigstore-rs root"). Documented in the function's doc-comment + an explicit changelog entry.
  2. The new `load_test_trusted_root()` test helper.
- **D-32-16 (carried forward, locked):** Phase 27.2's audit-attestation surface is untouched. Audit-attestation continues using its keyed bundle path with the FU-2 architecture (bundle at `<audit_root>/<id>/audit-attestation.bundle`). The keyless work in Phase 32 is a separate path on `nono trust sign` and `nono trust verify` — it does NOT affect `nono run --audit-integrity --audit-sign-key`.

### Claude's Discretion

- **Exact `nono setup --refresh-trust-root` argument shape and integration with `--check-only`.** Whether `--check-only` reports cached-trust-root staleness alongside WFP service status is implementation detail; the planner can decide based on existing `setup.rs` conventions.
- **Exact error-message wording** for D-32-03, D-32-05, D-32-09, D-32-12 — phrasing is the planner's call so long as the message names the problem AND the recovery command.
- **Mock Fulcio/Rekor implementation shape** — whether to wrap sigstore-sign's test machinery, build a minimal local mock, or use a recorded HTTP fixture is an implementation detail. The contract is "deterministic, hermetic, no network in CI."
- **Exact policy file format** for the baked-in `trust-policy.json` template (D-32-10) — match the existing `crates/nono/src/trust/policy.rs` format unless that format can't express keyless identity constraints (in which case extend it).
- **Dev-build broker-verification skip mechanism (D-32-12)** — `#[cfg(debug_assertions)]` vs install-layout detector vs other; planner picks based on what survives `cargo test` and `cargo build --release` semantics cleanly.
- **Order of waves.** A+C is foundational (everything else depends on the cached-root design landing first); B and H can run in parallel after C lands. Or C → A → B → H sequentially. Planner decides.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope and acceptance criteria
- `.planning/ROADMAP.md` § Phase 32: Sigstore Integration — phase entry (Goal/Requirements TBD; this CONTEXT.md becomes the de facto goal). Note that the ROADMAP entry should be backfilled with a concrete goal after Phase 32 plans land.
- `.planning/REQUIREMENTS.md` § AAH/AAHX/AUDC — adjacent attestation requirements that establish the existing trust-path conventions; Phase 32's keyless path is a NEW surface, not a REQ-AAH/AAHX revision.
- `.planning/quick/260509-s9m-verify-that-the-sigstore-functionality-i/260509-s9m-SUMMARY.md` — the verification finding that triggered Phase 32 scope. Lists the 2 failing unit tests and the TUF threshold root cause.

### Code (READ BEFORE PLANNING)
- `crates/nono/src/trust/bundle.rs` — `load_production_trusted_root` at :136 (the function rewritten by D-32-01); the 2 failing tests at :877 + :914 (D-32-02 fixture migration); `verify_bundle` + `verify_bundle_with_digest` (verify-side primitives). Also: `extract_signer_identity` + `parse_cert_info` for Fulcio cert handling.
- `crates/nono/src/trust/mod.rs` — module API surface; pub re-exports. Adding `load_test_trusted_root()` as a `#[cfg(test)]` helper here.
- `crates/nono/src/trust/signing.rs` — keyed signing primitives; D-32-09 keyed-fallback path uses these.
- `crates/nono/Cargo.toml` — `sigstore-verify = "0.6.5"` pin (D-32-04 stays on 0.6.5).
- `crates/nono-cli/src/trust_cmd.rs` — the existing `run_sign`, `run_sign_keyless` (:375), `sign_file_keyless` (:520), `discover_oidc_token` (:658), `run_verify` (:740), `run_sign_multi_keyless` (:449), `build_keyless_predicate` (:575), `gitlab_keyless_predicate` (:613). Phase 32 hardens these in place; doesn't rewrite them.
- `crates/nono-cli/src/setup.rs` — the existing `nono setup` flow; D-32-01 extends it with `--refresh-trust-root`.
- `crates/nono-cli/src/cli.rs` — `nono setup --install-wfp-service` etc. flag definitions; new `--refresh-trust-root` flag added here.
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` § `WindowsTokenArm::BrokerLaunch` (:2173+) — broker dispatch arm. D-32-13 + D-32-14 add Authenticode verification here before the `CreateProcessAsUserW` call.
- `crates/nono-cli/src/audit_attestation.rs` — Phase 28's Authenticode chain-walker primitives reused by D-32-11. Specifically the `parse_signer_subject` + `parse_thumbprint` extraction path.
- `crates/nono-cli/Cargo.toml` — `sigstore-sign = "0.6.5"` pin (D-32-04 stays on 0.6.5).

### Adjacent phase context (locked decisions Phase 32 builds on)
- `.planning/phases/27.2-audit-attestation-test-re-enablement/27.2-CONTEXT.md` — D-27.2-01..16 lock the audit-attestation surface; Phase 32 does NOT revisit them. The keyless work is a separate path.
- `.planning/phases/31-broker-process-architecture-shell-01/31-CONTEXT.md` — broker dispatch design + Phase 31 Plan 04 release pipeline that signs both `nono.exe` and `nono-shell-broker.exe`. D-32-13's "match nono.exe's own subject" assumes both are signed by the same identity, which Plan 31-04 guarantees.
- `.planning/phases/28-authenticode-chain-walker-subject-extraction/28-01-AUDC-PLAN.md` — chain-walker implementation Phase 32 reuses for D-32-11/12/13. `parse_signer_subject` + `parse_thumbprint` + the `WTHelperProvDataFromStateData` → `WTHelperGetProvSignerFromChain` → `CertGetNameStringW(CERT_X500_NAME_STR)` chain.

### Project conventions
- `CLAUDE.md` § Security Considerations + Coding Standards — D-19 invariant (`crates/nono/` byte-identical except deliberate API changes); fail-secure principle (D-32-03/05/09/12); no `unwrap()` / `expect()` (`clippy::unwrap_used` is enforced).
- `docs/architecture/audit-bundle-target.md` — Phase 27.2's ADR for audit-attestation bundle target (Option A); Phase 32 doesn't modify this surface but should reference its ADR-format-and-location convention if Phase 32 needs to record a TUF-refresh ADR.

### External (Sigstore-side documentation)
- Sigstore TUF repository: `https://tuf-repo-cdn.sigstore.dev/` — the source of truth for TUF root metadata that `nono setup --refresh-trust-root` fetches.
- sigstore-rs 0.6.5 source on docs.rs: `sigstore_verify::TrustedRoot::production()`, `sigstore_sign::SigningContext::production()`, `sigstore_sign::oidc::IdentityToken::detect_ambient()` — the upstream APIs this phase wraps. Researcher should verify the contract for each.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **Phase 28 Authenticode chain-walker** (`crates/nono-cli/src/audit_attestation.rs`): D-32-11/12/13 reuse `parse_signer_subject` + `parse_thumbprint` + the underlying `WTHelperProvDataFromStateData` → `WTHelperGetProvSignerFromChain` chain. No new chain-walker code is needed; Phase 32 just calls existing primitives at the broker dispatch site.
- **Existing keyless CLI flow** (`crates/nono-cli/src/trust_cmd.rs:259-1008`): `run_sign`, `run_sign_keyless`, `sign_file_keyless`, `run_sign_multi_keyless`, `discover_oidc_token`, `build_keyless_predicate`, `gitlab_keyless_predicate`, `run_verify`. Phase 32 ADDS test coverage + polish; does NOT rewrite these. The `--keyless` flag on `TrustSignArgs` already exists.
- **Existing `nono setup` flow** (`crates/nono-cli/src/setup.rs`): D-32-01 extends this with `--refresh-trust-root` following the existing pattern of `--install-wfp-service` / `--start-wfp-service` / `--check-only`. Likely a new function `refresh_trust_root() -> Result<()>` plus a CLI flag wire-up in `cli.rs`.
- **Existing `<NONO_TEST_HOME>/.nono/` convention** (Phase 27.1 D-27.1-08): `nono_home_dir()` returns the per-user nono home directory honoring `NONO_TEST_HOME`. D-32-01 uses this same helper to locate the trust-root cache directory: `<nono_home_dir()>/.nono/trust-root/`. No new HOME-resolution code needed.
- **Existing `WindowsTokenArm::BrokerLaunch` dispatch site** (`launch.rs:2173+`): D-32-13/14 wrap a verification call around the existing `CreateProcessAsUserW` invocation. The site already does sibling-resolution via `current_exe()`; Phase 32 just adds an Authenticode-verify gate before the spawn.
- **`NonoError::TrustPolicy` + `NonoError::TrustVerification` + `NonoError::TrustSigning`** variants: D-32-03/05/09/12 use these existing error variants; no new error types needed.

### Established Patterns

- **`nono setup` subcommand additivity**: existing flags (`--install-wfp-service`, `--start-wfp-service`, `--check-only`, `--profiles`, `--shell-integration`) are composable. D-32-01's `--refresh-trust-root` follows the same pattern: composable, idempotent (re-run is safe), per-user (no admin required for the trust-root variant).
- **Fail-closed + recovery hint diagnostic** (project precedent: `--block-net` WFP-required at `network.rs:425+`, `nono shell` broker-not-found at `error.rs::BrokerNotFound`, post-Phase-26 PKG-streaming offline-fail-closed): all four D-32-03/05/09/12 errors follow this exact pattern. Diagnostic message names the problem AND the recovery command.
- **D-19 invariant** (Phase 27.x): `crates/nono/` stays byte-identical except for deliberate API changes that are documented. D-32-15 enumerates the two intentional library changes (`load_production_trusted_root` rewrite + `load_test_trusted_root` helper); everything else stays in `crates/nono-cli/`.
- **Mock test infra for trust path**: existing keyed tests at `crates/nono-cli/tests/audit_attestation.rs` use a per-test ephemeral `<NONO_TEST_HOME>` + locally-generated keypair; D-32-07's mock-Fulcio-Rekor follows the same hermetic-test convention.
- **Frozen-fixture testing** (project precedent: Phase 28 chain-walker uses `C:\Windows\explorer.exe` as a captured-once-good Authenticode fixture; the audit-attestation tests use a checked-in P-256 keypair fixture): D-32-02's frozen TUF root fixture follows this same convention.

### Integration Points

- **Phase 27.2 audit-attestation surface (D-27.2-01..16)**: Phase 32 does NOT modify it. The keyless work in `nono trust sign --keyless` is a separate code path; audit-attestation continues using its keyed bundle path with the FU-2 architecture intact.
- **Phase 28 chain-walker (REQ-AUDC-01..03)**: Phase 32 reuses its primitives for D-32-11/12/13 broker verification. No changes to the chain-walker itself.
- **Phase 31 broker dispatch (D-31-04..15)**: Phase 32 wraps a verification gate around the existing dispatch site at `launch.rs:2173+` — the broker resolution / Job Object containment / spawn flow is unchanged; D-32-13/14 just adds an Authenticode check before the spawn.
- **Phase 31 Plan 04 release pipeline** (`.github/workflows/release.yml`): both `nono.exe` and `nono-shell-broker.exe` are signed by the same identity. D-32-13's "match nono.exe's own subject" assumes this; D-32-10 audits release.yml and may decide to migrate to keyless (recorded as a v2.4+ candidate, not a Phase 32 deliverable).
- **MSI install layout** (per-user Windows MSI): D-32-01's cache directory is per-user (no admin required for trust-root refresh). MSI doesn't need any new install-time action; cache initializes on first `nono setup --refresh-trust-root` call. POC handoff cookbook (per `260509-stb` precedent) gets a new prereq line: "Run `nono setup --refresh-trust-root` once before any `nono trust verify --keyless` smoke."

</code_context>

<specifics>
## Specific Ideas

- **POC handoff cookbook update.** The same cookbook updated by `260509-stb` (block-net WFP-service prereq) gets a parallel addition for trust-root refresh: `nono setup --refresh-trust-root` (per-user, no admin) before any keyless verify smoke, with the same fail-closed-correct callout pattern.
- **Documented `--issuer` + `--identity` examples in the cookbook.** D-32-08 ships fail-closed defaults; users need to know how to invoke verify correctly. Phase 32 documents the most common cases:
  - GitHub Actions release: `--issuer https://token.actions.githubusercontent.com --identity '^https://github\.com/<org>/<repo>/\.github/workflows/release\.yml@refs/tags/v.*$'`
  - GitLab CI release: `--issuer <gitlab-issuer-url> --identity '<gitlab-identity-pattern>'`
- **Self-trust-anchor pattern (D-32-13).** This is a novel trust pattern (broker is trusted because nono.exe is trusted, transitively). Worth recording in an ADR at `docs/architecture/broker-trust-anchor.md` per the Phase 27.2 / Phase 25-02 ADR convention. The ADR explains: why self-introspection over baked constants, the Phase 31 Plan 04 release-pipeline assumption, the dev-build skip mechanism (D-32-12 implementation note), threat model.

</specifics>

<deferred>
## Deferred Ideas

- **Interactive browser OAuth for keyless signing (cosign-style)** — explicitly out of scope per D-32-09. Could be a v2.4+ "Sigstore Local Developer Signing" phase if there's demand.
- **Migrating release.yml to keyless signing** — D-32-10 audits the current posture but explicitly defers the migration decision. Recorded as a v2.4+ candidate.
- **sigstore-rs version bump (0.6.5 → upstream-current)** — D-32-04 keeps us on 0.6.5. If a future bump becomes useful (e.g. fixes a real bug we're hitting OR adopts new Bundle v0.3+ features we want), it's a separate phase.
- **Cosign compatibility / Sigstore Bundle v0.3+ adoption** — Out of scope per phase boundary. If we want full bundle-format interop with cosign-signed artifacts, that's a separate v2.4+ "Bundle Format Modernization" phase.
- **Broker-trust caching (D-32-14 picked no-cache)** — If the ~50-200ms per-dispatch cost ever becomes a UX issue (e.g. agents spawning brokers in tight loops), revisit with a (path, mtime, size) in-process cache. Not a Phase 32 concern.
- **Verifying nono.exe itself at launch** — Out of scope. Self-verification creates a chicken-and-egg problem (the verifier is the thing being verified); we rely on Windows OS-level CodeIntegrity / SmartScreen to gate nono.exe execution at launch. If we ever want a separate trust-anchor for nono.exe (e.g. a TPM-bound measurement), that's a v3.0 conversation.
- **`#[cfg(feature = "online-tests")]` lane for live Sigstore smoke** — D-32-07 picked mocks. If a manual operator-driven live smoke ever needs to be automated, add an `online-tests` feature flag at that point.
- **CI rotation job for the frozen TUF fixture** — D-32-06 picked indefinite pin. If sigstore-rs's expected root structure ever drifts incompatibly, regenerate then.
- **Job Object / token-level `--block-net` fallback for unprivileged installs** — surfaced in `260509-stb` SUMMARY as a Phase 32 candidate but explicitly NOT in scope here. Network-enforcement concern, not Sigstore concern.
- **Centralized trust-policy.json under `<install_dir>` (D-32-10 alternative)** — placing the baked-in template under user home (`~/.nono/trust-policy.json`) per per-user-MSI convention; if multi-user shared install ever becomes a thing, revisit then.

</deferred>

---

*Phase: 32-sigstore-integration*
*Context gathered: 2026-05-10*
