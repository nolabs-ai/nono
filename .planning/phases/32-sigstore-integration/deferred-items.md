# Phase 32 Deferred Items

## P32-DEFER-001: Full hermetic keyless sign+verify roundtrip test

**Tracking ID:** P32-DEFER-001
**Plan:** 32-03 (D-32-07)
**Deferred to:** Phase 32 follow-up plan
**Status:** open

### What is deferred

`keyless_sign_then_verify_roundtrip` in `crates/nono-cli/tests/keyless_sign.rs` is marked
`#[ignore]` and will `panic!()` if run without the full mock infrastructure.

### Why deferred

Completing the full roundtrip requires:

1. A `nono` binary built with `--features test-trust-overrides` (env-var shim for mock URLs).
2. A mock Fulcio endpoint returning a syntactically valid DER-encoded certificate for the
   rcgen-generated ECDSA keypair (with all required Fulcio v2 OID extensions).
3. A mock Rekor endpoint returning a syntactically valid Rekor v1/v2 log entry JSON that
   `sigstore-sign`'s client parses without error.
4. A test `TrustedRoot` with the rcgen CA's public key substituted for the real Fulcio CA
   public key, so `nono trust verify --keyless` accepts the generated bundle.

The env-var shim (`#[cfg(feature = "test-trust-overrides")]`) was implemented in Plan 03.
The mock infrastructure smoke test (`mock_servers_only_no_real_network`) is active and
passes in CI. The full roundtrip requires capturing real-world-shaped Rekor/Fulcio responses
against a staging environment.

### How to complete

See the capture procedure in `crates/nono-cli/tests/keyless_sign.rs` module-level doc:

1. Run `nono trust sign --keyless` against Fulcio staging (`https://fulcio.sigstage.dev`)
   with a test OIDC token from a GitHub Actions `workflow_dispatch` run.
2. Capture the Fulcio response (cert DER bytes) and Rekor entry JSON via a recording proxy
   or `sigstore-cli --debug`.
3. Feed those into the mock server responses in `keyless_sign.rs`.
4. Build the test binary with `--features test-trust-overrides` and lift the `#[ignore]`.

### Related files

- `crates/nono-cli/tests/keyless_sign.rs` — contains the deferred test + capture procedure doc
- `crates/nono-cli/src/trust_cmd.rs` — contains `#[cfg(feature = "test-trust-overrides")]` shim
- `crates/nono-cli/Cargo.toml` — `test-trust-overrides` feature gate definition

---

## P32-DEFER-002: v2.4+ candidate — keyless migration of `release.yml` signing

**Tracking ID:** P32-DEFER-002
**Plan:** 32-05 (D-32-10 audit half)
**Deferred to:** v2.4+ candidate (entry criteria below)
**Status:** open (audit complete, migration deliberately not in scope for Phase 32)
**Verdict signed off:** 2026-05-10 (Option A — keep keyed, record migration as v2.4+)

### Trigger

Phase 32 Plan 05 Task 2 release-pipeline audit. D-32-10 explicit:
> Audit `.github/workflows/release.yml` signing posture; recommendation defaults to "keep current and document." Migration to keyless explicitly out of scope.

### Current posture (Phase 32 audit findings, 2026-05-10)

`.github/workflows/release.yml` signs Windows artifacts via Authenticode with
**no Sigstore presence whatsoever**:

| Aspect | Current state |
|--------|---------------|
| Mechanism | Authenticode `signtool` via `scripts/sign-windows-artifacts.ps1` |
| Cert source | `WINDOWS_SIGNING_CERT` (base64) + `WINDOWS_SIGNING_CERT_PASSWORD` (GitHub repo secrets) |
| Artifacts signed | `nono.exe`, `nono-shell-broker.exe`, machine MSI, user MSI, zip payload |
| Timestamping | RFC 3161 (`signtool /tr /td sha256`) |
| Verification | `signtool verify` then `Get-AuthenticodeSignature` (D-13 fail-closed; both must pass) |
| Sigstore presence | **None.** No `cosign sign-blob`. No `id-token: write` permission (`permissions:` block only has `contents: write`). No Sigstore bundles next to release artifacts. |
| Linux/macOS signing | **Not signed.** `.tar.gz`, `.deb` artifacts ship unsigned beyond the GitHub-Release-level integrity (SHA256SUMS.txt). |

Phase 31 Plan 04 extended the existing Authenticode flow to the broker
(`nono-shell-broker.exe` is signed by the same identity as `nono.exe`,
which is what Phase 32 D-32-13's self-trust-anchor relies on).

### Why deferred to v2.4+

Migration to keyless entails:

1. **OIDC permission wiring.** Add `id-token: write` to the `release` job's
   `permissions:` block; verify GitHub's OIDC issuer surfaces a JWT to
   `sigstore-sign`/`cosign` at runtime.
2. **Sigstore Bundle artifact packaging.** Each signed binary needs a
   `.sigstore` bundle co-located in the release archive. Two bundles minimum
   (`nono.exe.sigstore` + `nono-shell-broker.exe.sigstore`) plus MSI bundles.
3. **Consumer-side verify wiring.** End users currently verify nothing
   directly — they trust Authenticode chain-of-trust. Keyless migration
   means publishing how to invoke `nono trust verify --keyless --issuer
   https://token.actions.githubusercontent.com --identity <regex>` against
   tagged release artifacts; the `docs/templates/trust-policy-keyless-template.json`
   landed in Plan 32-03 already wires the canonical identity convention,
   but the "run this command after install" step does not yet exist in
   user-facing docs.
4. **Secret rotation operations.** `WINDOWS_SIGNING_CERT` rotation today
   is a manual GitHub repo-secret update; replacing it with keyless removes
   the secret entirely (OIDC tokens are ephemeral, scoped per workflow run).
   This is a user-facing change in operational posture.
5. **Authenticode posture decision.** Either keep Authenticode AS WELL AS
   keyless (dual-sign — operationally heaviest but maximum compatibility)
   or replace Authenticode with keyless (cleanest but breaks Windows
   "verified publisher" SmartScreen experience for downloads). Authenticode
   is required for Windows code-signing chain-of-trust at install time;
   migrating it OUT entirely is a separate, larger decision.

D-32-10 anticipated this scope: "Migration to keyless explicitly out of
scope. That's a separate decision recorded as a v2.4+ candidate." The
audit verdict above honors that boundary.

### Entry criteria for v2.4+

Promote this from deferred to active milestone when ANY of:

1. **Compliance ask.** A customer or partner requires Sigstore-verifiable
   release artifacts for procurement / audit reasons (e.g., SLSA Level 3+
   provenance attestation, SBOM-with-signed-provenance frameworks).
2. **Secret-rotation operational pain.** `WINDOWS_SIGNING_CERT` rotation
   becomes painful enough (e.g., cert expiry mid-release, rotation-coordination
   fire drill) that the OIDC-ephemeral-token model's operational simplicity
   becomes worth the migration cost.
3. **Sigstore ecosystem maturity.** sigstore-rs / cosign release-pipeline
   patterns become as ergonomic as `actions/upload-artifact` is today —
   removing the "operationally novel" objection.

Until then: keep keyed. The Phase 32 work (cached TUF root + verify-is-offline
invariant + identity-pinned trust-policy template) is forward-compatible —
when the migration happens, the consumer-side verify path is already in place
from Phase 32 Plan 03.

### Closures (NOT carried forward as deferreds)

The following items were originally deferral candidates per Plan 32-05's
must-haves but were CLOSED during Plans 03 and 04 implementation:

- **Mock Fulcio/Rekor fixture capture (Plan 03 P32-CHK-005/008):** Plan 03
  Task 2 wired httpmock-based mock-Fulcio + mock-Rekor with rcgen at-test-time
  certificate generation. The `mock_servers_only_no_real_network` test runs
  in CI today. Only the FULL roundtrip (P32-DEFER-001 above) remains deferred,
  not the mock infrastructure itself.
- **Two-publisher `broker-mismatch-stub.exe` fixture (Plan 04 P32-CHK-010/011):**
  Plan 04 Task 2 used tempdir staging instead of a committed binary fixture.
  All 6 broker_authenticode tests run hermetically in CI without any committed
  Authenticode binary fixtures.

### Related files

- `.github/workflows/release.yml` — current keyed signing posture
- `scripts/sign-windows-artifacts.ps1` — signtool invocation referenced by release.yml
- `docs/templates/trust-policy-keyless-template.json` — Plan 03 baked-in template; the consumer-side trust policy that a future keyless migration would reference
- `docs/cli/development/windows-signing-guide.mdx` — referenced by release.yml's signing-secrets check; current operator docs for keyed posture
- `.planning/phases/32-sigstore-integration/32-CONTEXT.md` (D-32-10 verbatim)

---

## P32-DEFER-003: SystemDrive env corrupts child env on Windows (pre-existing CR-01)

**Tracking ID:** P32-DEFER-003
**Plan:** Out of Phase 32 scope (surfaced by Phase 32 code review; bug introduced 2026-04-10 commit `cf5a60a1`)
**Deferred to:** Standalone follow-up plan (next Windows-area phase or hotfix)
**Status:** open
**Severity:** Critical (corrupts child env)
**Surfaced:** 2026-05-10 by Phase 32 code review

### What is the bug

`crates/nono-cli/src/exec_strategy_windows/launch.rs:695-698` in
`append_windows_runtime_env` sets the `SystemDrive` child environment variable
to `windows_system32.display()` — which resolves to e.g. `C:\Windows\System32`.
The Windows convention for `SystemDrive` is the bare drive specifier (e.g.
`C:`). Any sandboxed child process that expands `%SystemDrive%\ProgramData`
gets `C:\Windows\System32\ProgramData` instead of `C:\ProgramData`, breaking
binaries that rely on `SystemDrive` for path construction (which is most of
them on Windows — installers, service-manager bootstrap, default-tool path
resolution, etc.).

### Why deferred from Phase 32

Phase 32 scope is sigstore integration + broker self-trust-anchor. The bug
is in `append_windows_runtime_env`, which is unrelated to Phase 32 trust
work — it predates Phase 32 by a month (commit `cf5a60a1` 2026-04-10) and
affects every sandboxed Windows invocation regardless of trust posture.
Including this fix in Phase 32 would expand scope and entangle the Phase 32
verification with an unrelated subsystem.

### Fix sketch (for future plan)

Derive the drive letter from `system_root` (which already comes from
`SystemRoot` / `windir`):

```rust
let system_drive = system_root
    .components()
    .next()
    .map(|c| c.as_os_str().to_string_lossy().trim_end_matches('\\').to_string())
    .unwrap_or_else(|| "C:".to_string());
env_pairs.push(("SystemDrive".to_string(), system_drive));
```

Add a regression test that asserts the env pair contains a 2-character
drive specifier (e.g., `C:`) rather than a path with separators.

### Related files

- `crates/nono-cli/src/exec_strategy_windows/launch.rs` (the bug)
- `.planning/phases/32-sigstore-integration/32-REVIEW.md` § CR-01 (full review writeup)

---

## P32-DEFER-004: trust_intercept.rs platform-conditional dead-code masking (pre-existing CR-04)

**Tracking ID:** P32-DEFER-004
**Plan:** Out of Phase 32 scope (surfaced by Phase 32 code review; attribute introduced 2026-04-10 commit `cf5a60a1`)
**Deferred to:** Standalone follow-up plan (next Windows-area phase or trust-system audit)
**Status:** open
**Severity:** Warning (CLAUDE.md violation, security-relevant gap)
**Surfaced:** 2026-05-10 by Phase 32 code review

### What is the violation

`crates/nono-cli/src/trust_intercept.rs` carries 7 instances of
`#[cfg_attr(target_os = "windows", allow(dead_code))]` on `CacheEntry`,
`CachedOutcome`, `TrustVerified`, `TrustInterceptor`, its `impl` block,
`load_signer`, and `format_outcome`. CLAUDE.md is explicit:

> "Avoid `#[allow(dead_code)]`. If code is unused, either remove it or
> write tests that use it."

Because the suppression is platform-conditional, the entire trust-interception
subsystem may be unused on Windows without any compile-time signal. If the
Windows supervisor loop never calls `TrustInterceptor::check_path`, Windows
sandboxed sessions silently get zero runtime trust enforcement while the
Unix path does — a security parity gap concealed by the attribute.

### Why deferred from Phase 32

The attribute predates Phase 32 by a month and is on a code path Phase 32
does not modify (Phase 32's broker Authenticode self-trust-anchor is at the
spawn site in `launch.rs`, not the file-instruction trust interceptor).
Investigating whether the Windows supervisor wires `TrustInterceptor` (and
fixing the wiring or gating the module appropriately) requires a focused
Windows-area audit that's outside Phase 32's sigstore scope.

### Fix path (for future plan)

Two acceptable resolutions:

**(a) Gate the entire module Linux/macOS-only** if the Windows supervisor
does not call it (and is not planned to call it):

```rust
// Top of trust_intercept.rs
#![cfg(not(target_os = "windows"))]
```

This documents the gap explicitly at the module boundary.

**(b) Wire `TrustInterceptor` into the Windows supervisor runtime** and add
an integration test that exercises the Windows path (`#[cfg(windows)]` test
that calls `check_path` and asserts the outcome).

A follow-up plan should pick one based on the broader Windows trust roadmap.

### Related files

- `crates/nono-cli/src/trust_intercept.rs` (the file with the masked code)
- `.planning/phases/32-sigstore-integration/32-REVIEW.md` § CR-04 (full review writeup)
