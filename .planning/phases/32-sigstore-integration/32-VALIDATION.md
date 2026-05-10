---
phase: 32
slug: sigstore-integration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-10
---

# Phase 32 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust 1.77, Edition 2021) |
| **Config file** | `crates/nono/Cargo.toml`, `crates/nono-cli/Cargo.toml` |
| **Quick run command** | `cargo test --package nono trust::` (or scoped to changed module) |
| **Full suite command** | `make test` (workspace clippy + fmt + tests) |
| **Estimated runtime** | ~60–120 seconds quick; ~5–10 minutes full |

---

## Sampling Rate

- **After every task commit:** Run scoped `cargo test --package <crate> <module>::`
- **After every plan wave:** Run `make test`
- **Before `/gsd-verify-work`:** `make ci` must be green (clippy + fmt + tests)
- **Max feedback latency:** 120 seconds for scoped tests

---

## Per-Task Verification Map

> Mapping is derived from the Validation Architecture section of `32-RESEARCH.md`. The
> planner will populate Task IDs and File Exists columns once plans are finalized in
> step 8; this document is the contract the planner writes against. Each row maps a
> locked decision (D-32-XX) or research test stub to a `cargo test` command.

| D-32-XX | Validation Concern | Test Type | Automated Command (representative) | File Exists | Status |
|---------|--------------------|-----------|------------------------------------|-------------|--------|
| D-32-01 | TUF cache round-trip (write → load → verify) | unit | `cargo test -p nono trust::bundle::cache_round_trip` | ❌ W0 | ⬜ pending |
| D-32-01 | `load_production_trusted_root` reads cache, NOT `TrustedRoot::production()` | unit | `cargo test -p nono trust::bundle::load_uses_cache` | ❌ W0 | ⬜ pending |
| D-32-02 | Frozen TUF fixture loads syntactically + 2 unblock tests pass | unit | `cargo test -p nono trust::bundle::load_production_trusted_root_succeeds` + `verify_bundle_with_invalid_digest` | ❌ W0 | ⬜ pending |
| D-32-02 | New `load_test_trusted_root()` helper returns parseable `TrustedRoot` | unit | `cargo test -p nono trust::load_test_trusted_root_smoke` | ❌ W0 | ⬜ pending |
| D-32-03 | Verify-is-offline invariant (no network call during verify) | unit / integration | `cargo test -p nono trust::bundle::verify_makes_no_http_calls` (httpmock asserts zero hits) | ❌ W0 | ⬜ pending |
| D-32-03 | Cached-root expiry → fail-closed with recovery message | unit | `cargo test -p nono trust::bundle::expired_cache_fails_closed_with_recovery_hint` | ❌ W0 | ⬜ pending |
| D-32-05 | First-run (cache never initialized) → fail-closed `TrustPolicy` with recovery hint | unit | `cargo test -p nono trust::bundle::missing_cache_fails_closed` | ❌ W0 | ⬜ pending |
| D-32-06 | Frozen fixture is checked into the repo (path stable, byte-identical) | structural | `test -f crates/nono/tests/fixtures/trust-root-frozen.json && cargo test -p nono trust::bundle::load_test_trusted_root_smoke` | ❌ W0 | ⬜ pending |
| D-32-07 | Mock Fulcio/Rekor produces Bundle real verify accepts (cross-check) | integration | `cargo test -p nono-cli --test keyless_sign keyless_sign_verify_roundtrip` | ❌ W0 | ⬜ pending |
| D-32-07 | Hermetic test asserts zero outbound network calls | integration | `cargo test -p nono-cli --test keyless_sign mock_servers_only_no_real_network` | ❌ W0 | ⬜ pending |
| D-32-08 | Verify rejects when `--issuer` missing | integration | `cargo test -p nono-cli --test keyless_verify verify_rejects_missing_issuer` | ❌ W0 | ⬜ pending |
| D-32-08 | Verify rejects when `--identity` missing | integration | `cargo test -p nono-cli --test keyless_verify verify_rejects_missing_identity` | ❌ W0 | ⬜ pending |
| D-32-08 | Verify rejects when `--identity` regex does NOT match SAN | integration | `cargo test -p nono-cli --test keyless_verify verify_rejects_san_mismatch` | ❌ W0 | ⬜ pending |
| D-32-08 | Verify accepts when `--identity` regex matches SAN | integration | `cargo test -p nono-cli --test keyless_verify verify_accepts_san_match` | ❌ W0 | ⬜ pending |
| D-32-09 | `discover_oidc_token` error message names `--keyref` recovery for local dev | unit | `cargo test -p nono-cli trust_cmd::oidc_error_suggests_keyref` | ❌ W0 | ⬜ pending |
| D-32-10 | Baked-in `trust-policy.json` template syntactically loads via existing policy parser | unit | `cargo test -p nono trust::policy::default_template_parses` | ❌ W0 | ⬜ pending |
| D-32-11 / D-32-13 | `extract_self_authenticode` / equivalent extracts subject + thumbprint from `current_exe()` | integration (Windows-only, `#[cfg(windows)]`) | `cargo test -p nono-cli --test broker_authenticode self_authenticode_extracts_subject_and_thumbprint` | ❌ W0 | ⬜ pending |
| D-32-12 | Broker Authenticode mismatch refuses spawn — fail-closed with recovery message | integration (Windows-only) | `cargo test -p nono-cli --test broker_authenticode broker_signature_mismatch_refuses_spawn` | ❌ W0 | ⬜ pending |
| D-32-12 | Broker Authenticode signature missing refuses spawn (release builds) | integration (Windows-only) | `cargo test -p nono-cli --test broker_authenticode broker_unsigned_release_refuses_spawn` | ❌ W0 | ⬜ pending |
| D-32-12 | Dev-build broker skip mechanism does NOT bypass production builds | integration (Windows-only) | `cargo test -p nono-cli --test broker_authenticode dev_skip_does_not_bypass_release_layout` | ❌ W0 | ⬜ pending |
| D-32-13 | Broker dispatch with valid Authenticode signature succeeds (positive case) | integration (Windows-only) | `cargo test -p nono-cli --test broker_authenticode broker_valid_signature_spawns` | ❌ W0 | ⬜ pending |
| D-32-14 | Verify runs on every dispatch (no cache short-circuit) | integration (Windows-only) | `cargo test -p nono-cli --test broker_authenticode each_dispatch_revalidates` | ❌ W0 | ⬜ pending |
| D-32-15 | Library API surface change is documented in `bundle.rs` doc-comment | structural | `grep -E "Returns the cached refreshed Sigstore trusted root" crates/nono/src/trust/bundle.rs` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

**Cross-cut sign-offs (planner must include in `must_haves`):**
- All 23 rows above must transition to ✅ before `/gsd-verify-work` for Phase 32 can pass.
- The 2 originally-failing tests at `crates/nono/src/trust/bundle.rs:877` + `:914` are explicitly named — verify they go from ❌ to ✅, not just disappear.

---

## Wave 0 Requirements

- [ ] `crates/nono/tests/fixtures/trust-root-frozen.json` — frozen TUF root fixture (D-32-02 / D-32-06)
- [ ] `crates/nono/src/trust/mod.rs` — add `#[cfg(test)] pub fn load_test_trusted_root() -> Result<TrustedRoot, NonoError>` helper (D-32-15)
- [ ] `crates/nono-cli/tests/keyless_sign.rs` — new integration test file (D-32-07)
- [ ] `crates/nono-cli/tests/keyless_verify.rs` — new integration test file (D-32-08)
- [ ] `crates/nono-cli/tests/broker_authenticode.rs` — new integration test file (D-32-11..14, `#[cfg(windows)]`)
- [ ] `crates/nono-cli/Cargo.toml` `[dev-dependencies]` — `httpmock = "0.7"` for mock Fulcio/Rekor (D-32-07)
- [ ] (No new prod deps; `regress` for D-32-08 regex is already pulled in via `validate_oidc_issuer`)

---

## Manual-Only Verifications

| Behavior | D-32-XX | Why Manual | Test Instructions |
|----------|---------|------------|-------------------|
| Live Sigstore Fulcio/Rekor smoke (operator verification) | D-32-07 | CONTEXT.md explicitly defers live-infra smoke to manual operator verification (no `online-tests` cargo feature per D-32-07) | Run cookbook section "Sigstore keyless signing live smoke" — `nono trust sign --keyless` against tagged release artifact, then `nono trust verify --keyless --issuer <gh-actions-issuer> --identity <pattern> <bundle>`; verify Rekor entry appears at `https://search.sigstore.dev/?logIndex=<idx>` |
| `nono setup --refresh-trust-root` end-to-end on a real Windows install | D-32-01 | TUF refresh hits live `https://tuf-repo-cdn.sigstore.dev`; not run in CI | Cookbook section "First-run trust-root refresh" — `nono setup --refresh-trust-root` on a per-user MSI install, then verify `<NONO_TEST_HOME>/.nono/trust-root/` is populated and a subsequent `nono trust verify` runs offline successfully |
| POC handoff cookbook updates (parallel to `260509-stb` block-net prereq) | D-32-01, D-32-08 | Documentation correctness gate — exercising the cookbook end-to-end is a human task | Walk a fresh installer through the new cookbook section; capture output and confirm the fail-closed messages D-32-03 / D-32-05 / D-32-12 fire as documented |
| Release-pipeline audit findings + ADR placement decision (D-32-10) | D-32-10 | Reading `.github/workflows/release.yml` and authoring an ADR at `docs/architecture/broker-trust-anchor.md` is a human task | Auditor reviews release.yml, decides keyed-vs-keyless posture, writes/extends ADR, lands in PR for the phase |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (5 new test files + 1 fixture + 1 dev-dep)
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s for scoped runs
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
