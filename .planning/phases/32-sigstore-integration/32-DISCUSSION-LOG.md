# Phase 32: Sigstore Integration - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in `32-CONTEXT.md` — this log preserves the alternatives considered.

**Date:** 2026-05-10
**Phase:** 32-sigstore-integration
**Areas discussed:** Scope definition (initial multi-select), TUF root refresh & test unblock (A+C), Public-good keyless CLI hardening (B), Broker.exe Authenticode verification at launch (H)

---

## Scope definition (initial multi-select)

The ROADMAP entry for Phase 32 was a stub (Goal: TBD, Requirements: TBD). The user multi-selected the candidates that should be in scope. All four offered options were selected; remaining options (E sigstore-rs version bump, F cosign compatibility, G bundle v0.3+) were not selected — captured as deferred.

| Option | Description | Selected |
|--------|-------------|----------|
| A — Unblock the 2 failing trust unit tests | Narrow scope (~1-2 plans) | ✓ |
| B — Ship the public-good keyless signing CLI | Significant scope; later found existing in code, scope reframed to hardening | ✓ |
| C — TUF root refresh hardening | Medium scope; subsumes A | ✓ |
| H — Verify nono-shell-broker.exe at launch | Medium scope, Phase 31 dependency | ✓ |

**User's choice:** A + B + C + H all in scope.
**Notes:** Maximally-ambitious scope. A is a symptom of C (subsumed). B turned out to be already-coded but unexercised — scope reframed mid-discussion to "harden the existing-but-unexercised keyless CLI surface."

---

## A+C — TUF root refresh & test unblock

### TUF root location and refresh strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Refresh during `nono setup` | Cached under `<NONO_TEST_HOME>/.nono/trust-root/`; setup fails fail-closed if fetch fails; verify runs offline | ✓ |
| Embed at build time + auto-refresh on stale | build.rs fetches at compile time + runtime-refresh on expiry | |
| Runtime-only fetch with cache | Verify hits the CDN on first call | |
| Sigstore-rs version bump first | Defer the design decision until after a version bump | |

**User's choice:** Refresh during `nono setup`. (D-32-01)

### Failing tests after D-32-01 lands

| Option | Description | Selected |
|--------|-------------|----------|
| Bundle a frozen TUF fixture | Hermetic, deterministic, CI-stable, works offline | ✓ |
| Tests load from cached `<NONO_TEST_HOME>/.nono/trust-root/` | Closer to production code path; couples test runs to Sigstore infra | |
| Gate behind `#[cfg(feature = "online-tests")]` | Dedicated CI lane that requires Sigstore TUF reachability | |
| Delete the 2 tests | They test sigstore-rs, not our code | |

**User's choice:** Frozen TUF fixture. (D-32-02)

### Stale cached root + no network

| Option | Description | Selected |
|--------|-------------|----------|
| Fail-closed with explicit recovery hint | Hard refuse with `nono setup --refresh-trust-root` recovery message | ✓ |
| Fail-closed with grace window | Allow N days past expiry with warn; hard-fail after | |
| Best-effort online refresh + fail-closed if refresh fails | Verify does inline network on cold-stale path | |

**User's choice:** Fail-closed with explicit recovery hint. (D-32-03)

### sigstore-rs version posture

| Option | Description | Selected |
|--------|-------------|----------|
| Stay on 0.6.5; fix it ourselves | Avoids re-litigating upstream divergence | ✓ |
| Bump if upstream sigstore-rs >= 0.6.6 has shipped a fix | Adds research overhead; may save implementation work | |
| Bump aggressively | Furthest from upstream's pinned version; risk of API drift | |

**User's choice:** Stay on 0.6.5. (D-32-04)

### First-run UX with missing cached TUF root

| Option | Description | Selected |
|--------|-------------|----------|
| Hard fail-closed with recovery hint | Symmetric with D-32-03; one user-visible recovery command | ✓ |
| Auto-fetch on first verify, then cache | Easier UX but breaks "verify is offline" invariant | |
| Silent fall-back to keyed-only mode | Verify succeeds for keyed bundles only | |

**User's choice:** Hard fail-closed with recovery hint. (D-32-05)

### Frozen TUF fixture rotation policy

| Option | Description | Selected |
|--------|-------------|----------|
| Pin the fixture indefinitely | Lowest maintenance; closest to test purposes | ✓ |
| Add a dated CI job that refreshes the fixture quarterly | Adds infra surface; aligned with current sigstore-rs | |
| Generate the fixture at test compile time via build.rs | Build-time network requirement; cross-compile risk | |

**User's choice:** Pin the fixture indefinitely. (D-32-06)

---

## B — Public-good keyless CLI hardening

### Test coverage strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Unit + integration tests against a mock Fulcio/Rekor | Hermetic, no CI Sigstore dependency, no real Rekor entries | ✓ |
| Live keyless test on a CI lane that runs only on tag pushes | Couples release builds to Sigstore availability; creates real Rekor entries | |
| Manual smoke + a bash script in `scripts/` | Lowest cost; weakest signal | |

**User's choice:** Mock Fulcio/Rekor. (D-32-07)

### Default verify policy for keyless

| Option | Description | Selected |
|--------|-------------|----------|
| Fail-closed: require explicit `--issuer` + `--identity` flags | Forces security-relevant decision; matches CLAUDE.md fail-secure | ✓ |
| Permissive default — `VerificationPolicy::default()` | Trust comes from TUF root + transparency log only; allows ANY signed-with-Sigstore artifact | |
| Trust policy file: read constraints from `~/.nono/trust-policy.json` | Same machinery as keyed; keyless adds new policy fields | |

**User's choice:** Fail-closed; require explicit flags. (D-32-08)

### Developer-machine UX for keyless signing

| Option | Description | Selected |
|--------|-------------|----------|
| Keep CI-only — keyless is a release-pipeline feature | Smallest surface; documents `--keyref` for local dev | ✓ |
| Add interactive browser OAuth (cosign-style) | Maximum cosign UX parity; substantial scope | |
| Static token via flag — `--identity-token <jwt>` | Smaller scope than browser OAuth; middle ground | |

**User's choice:** Keep CI-only. (D-32-09)

### Release pipeline signing posture

| Option | Description | Selected |
|--------|-------------|----------|
| Keyed today; investigate switching to keyless in Phase 32 | Audit + decide; ship trust-policy.json template either way | ✓ |
| Keep release.yml on keyed signing; only `nono trust sign` users get keyless | No release.yml plan needed | |
| Migrate release.yml to keyless as a Phase 32 deliverable | Hard requirement; cleanest end-state but largest scope | |

**User's choice:** Audit current; defer migration decision. (D-32-10)

---

## H — Broker.exe Authenticode verification at launch

### Verification mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| Authenticode only (Windows-native) | Reuse Phase 28 chain-walker; aligns with MSI signing pipeline | ✓ |
| Sigstore bundle sidecar (cross-platform path) | Adds a 2nd file to the install layout | |
| Both — Authenticode AND Sigstore (defense-in-depth) | Maximum trust, maximum cost | |
| Hash-pinned (SHA-256 baked into nono.exe) | Simplest; couples broker rebuild to nono.exe rebuild | |

**User's choice:** Authenticode only. (D-32-11)

### Failure mode on Authenticode verification fail

| Option | Description | Selected |
|--------|-------------|----------|
| Fail-closed: refuse to launch the broker | CLAUDE.md fail-secure; no escape hatch | ✓ |
| Fail-closed only on subject mismatch; warn-but-continue on Unknown | Lets users running unsigned dev builds bypass; defeats purpose | |
| Configurable via `nono setup` and an env var | Adds surface; matches `--dangerous-force-wfp-ready` pattern | |

**User's choice:** Fail-closed; no escape hatch. (D-32-12)

### Expected Authenticode trust anchor

| Option | Description | Selected |
|--------|-------------|----------|
| Match nono.exe's own Authenticode subject | Self-bootstrapping; no baked constants; natural rotation | ✓ |
| Baked-in expected publisher subject + thumbprint constant | Most explicit; release-coordination friction | |
| Read from a config file (`<install_dir>/trust-anchor.json`) | Configurable; conflicts with per-user-MSI install model | |

**User's choice:** Match nono.exe's own subject. (D-32-13)

### Verification timing

| Option | Description | Selected |
|--------|-------------|----------|
| Every dispatch | ~50-200ms per launch; no cache; simplest and most secure | ✓ |
| Cache by (broker path, mtime, size) for nono.exe process lifetime | Saves ~50-200ms on repeated dispatches | |
| Cache to disk keyed on (path, sha256) | Fastest steady-state; cache integrity model | |

**User's choice:** Every dispatch; no cache. (D-32-14)

---

## Claude's Discretion

The user explicitly handed these to Claude (planner) to decide:

- Exact `nono setup --refresh-trust-root` argument shape and integration with `--check-only`
- Exact error-message wording for D-32-03/05/09/12 (so long as message names problem AND recovery command)
- Mock Fulcio/Rekor implementation shape (wrap sigstore-sign test machinery, build minimal local mock, or recorded HTTP fixture)
- Exact policy file format for the baked-in `trust-policy.json` template (D-32-10) — match existing `crates/nono/src/trust/policy.rs` format unless extension needed
- Dev-build broker-verification skip mechanism (`#[cfg(debug_assertions)]` vs install-layout detector vs other)
- Wave ordering — A+C foundational; B and H can run in parallel after C lands, OR sequential

## Deferred Ideas

Captured during discussion but explicitly out of scope for Phase 32:

- Interactive browser OAuth for keyless signing (cosign-style) — v2.4+ candidate
- Migrating release.yml to keyless signing — D-32-10 audits posture but defers migration decision
- sigstore-rs version bump (0.6.5 → upstream-current) — D-32-04 stays
- Cosign compatibility / Sigstore Bundle v0.3+ adoption — separate v2.4+ phase
- Broker-trust caching (process-lifetime or disk) — revisit only if per-dispatch cost becomes a UX issue
- Verifying nono.exe itself at launch — chicken-and-egg; v3.0 TPM conversation
- `#[cfg(feature = "online-tests")]` lane for live Sigstore smoke — add later if needed
- CI rotation job for the frozen TUF fixture — regenerate only if structure drifts
- Job Object / token-level `--block-net` fallback for unprivileged installs — surfaced in `260509-stb` but explicitly NOT in scope (network concern, not Sigstore)
- Centralized trust-policy.json under `<install_dir>` — per-user MSI convention is the default
