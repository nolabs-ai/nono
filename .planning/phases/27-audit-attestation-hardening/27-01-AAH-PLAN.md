---
phase: 27-audit-attestation-hardening
plan: 01
type: execute
wave: 1
depends_on: []
requirements: [AAH-01]
tags: [audit-attestation, sigstore, fixture-redesign, test, dsse]
tdd: true
risk: low
files_modified:
  - crates/nono-cli/tests/audit_attestation.rs
  # Optional, gated test-only addition if a `store_secret_for_test` helper is needed:
  - crates/nono/src/keystore.rs
autonomous: true

must_haves:
  truths:
    - "Both #[ignore] attributes at lines 112 and 163 of crates/nono-cli/tests/audit_attestation.rs are removed; `grep -c '#\\[ignore' crates/nono-cli/tests/audit_attestation.rs` returns 0"
    - "`cargo test -p nono-cli --test audit_attestation` exits 0 with both previously-ignored tests now passing under their existing function names (audit_verify_reports_signed_attestation_with_pinned_public_key, rollback_signed_session_verifies_from_audit_dir_bundle)"
    - "Tests use `nono::trust::signing::generate_signing_key` per-invocation; no `from_pkcs8` / `KeyPair::from_pkcs8` references introduced — `grep -rc 'from_pkcs8' crates/nono-cli/tests/` returns 0"
    - "Tests use `keystore://...` URI flow; no new `--audit-sign-key file://...` test setup paths added — `grep -c -- '--audit-sign-key' crates/nono-cli/tests/audit_attestation.rs | awk '{s+=$1} END {print s}'` matches the pre-plan count for `file://` callsites (only pre-existing comment-block lines remain)"
    - "Both redesigned tests assert bundle structural correctness: bundle file exists at `<session_dir>/audit-attestation.bundle`, deserializes as DSSE envelope, payload type non-empty, signatures array non-empty — verified via grep against the test source for `audit-attestation.bundle` AND `signatures` AND (`payload_type` OR `payloadType`)"
    - "Both redesigned tests assert fail-closed verification: passing a wrong public key to `nono audit verify` returns non-zero exit; verified via grep for `assert!(!verify_output.status.success())` (or equivalent negative-status assertion) in the test source"
    - "Both redesigned tests assert key_id_hex round-trip: extracted public-key hex from the generated KeyPair matches what `nono audit show <id> --json` reports under `attestation.key_id_hex`"
    - "Production code in `crates/nono-cli/src/audit_attestation.rs` is byte-identical to the pre-plan baseline — `git diff --stat <baseline>..HEAD -- crates/nono-cli/src/audit_attestation.rs` is empty across all plan commits"
    - "Test file gains a comment block above the redesigned tests documenting the Phase 27 Path B trade-off (structural-correctness + fail-closed vs byte-equality fixture testing) and the deferred restoration to v2.4"
    - "make ci passes: cargo clippy + cargo fmt --check + cargo test --workspace exit 0 on Linux runner"
  artifacts:
    - path: "crates/nono-cli/tests/audit_attestation.rs"
      provides: "Two re-enabled integration tests with structural-correctness + fail-closed assertion strategy"
      grep_pattern: "fn audit_verify_reports_signed_attestation_with_pinned_public_key"
      contains: "fn rollback_signed_session_verifies_from_audit_dir_bundle"
      not_contains: "#[ignore"
      not_contains_other: "from_pkcs8"
    - path: "crates/nono-cli/tests/audit_attestation.rs"
      provides: "Phase 27 deviation comment block above the redesigned tests"
      grep_pattern: "Phase 27"
      contains_substr: "Path B"
      contains_substr_other: "byte-equality"
    - path: "crates/nono-cli/src/audit_attestation.rs"
      provides: "Untouched production code (byte-identical to v2.2 Phase 22-05a baseline)"
      verify: "git diff --stat <baseline>..HEAD -- crates/nono-cli/src/audit_attestation.rs returns empty"
    - path: "crates/nono/src/keystore.rs"
      provides: "[OPTIONAL — only if needed] cfg(test)-gated `store_secret_for_test` helper for keystore:// URI seeding in integration tests"
      conditional: "Only modified IF the existing keystore API does not already provide a test-only seeding entry point"
      contains_attr: "#[cfg(test)]"
  key_links:
    - from: "crates/nono-cli/tests/audit_attestation.rs::audit_verify_reports_signed_attestation_with_pinned_public_key"
      to: "nono::trust::signing::generate_signing_key"
      via: "Per-invocation random ECDSA P-256 keypair generation; key_id_hex extracted via existing accessor"
      pattern: "generate_signing_key\\("
    - from: "crates/nono-cli/tests/audit_attestation.rs (both tests)"
      to: "nono audit verify CLI subcommand (--public-key-file flag)"
      via: "fail-closed verification: matching pubkey -> exit 0; wrong pubkey -> exit nonzero"
      pattern: "(audit.*verify|verify.*audit).*public-key-file"
    - from: "crates/nono-cli/tests/audit_attestation.rs (both tests)"
      to: "<session_dir>/audit-attestation.bundle on disk"
      via: "DSSE envelope deserialization (serde_json) + structural assertions on payload_type + signatures[] non-empty"
      pattern: "audit-attestation\\.bundle"
    - from: "crates/nono-cli/tests/audit_attestation.rs (both tests)"
      to: "Phase 22-05a Decision 5 deviation note in crates/nono-cli/src/audit_attestation.rs:8-15"
      via: "Test-file comment block cross-references the production module's deviation rationale and locks the v2.4 restoration path"
      pattern: "Phase 27.*Path B"
---

<objective>
Re-enable the two `#[ignore]`'d integration tests in `crates/nono-cli/tests/audit_attestation.rs` (`audit_verify_reports_signed_attestation_with_pinned_public_key` at line 112 and `rollback_signed_session_verifies_from_audit_dir_bundle` at line 163) by **redesigning their assertion strategy** rather than chasing upstream's `from_pkcs8` + `sign_statement_bundle` API surfaces.

Closes REQ-AAH-01 via **Path B — Fixture Test Redesign** (the architectural decision is locked; this plan does NOT re-litigate it).

Purpose: v2.2 Plan 22-05a landed cryptographic DSSE bundle verification (HG-01-H, commit `cffb43b1`) but had to mark these two tests `#[ignore]` because sigstore-rs 0.6.4 does not expose `KeyPair::from_pkcs8` and the fork's `crates/nono-cli/src/audit_attestation.rs` (per the module-level deviation note at lines 8-15) deliberately uses `nono::trust::signing::generate_signing_key` per-session instead of the upstream `--audit-sign-key file://...` -> PKCS8 -> `KeyPair::from_pkcs8` path. Re-enabling the tests with the upstream flow would require either (a) upgrading sigstore-rs (cascades through other crates) or (b) adding a fork-internal pkcs8 parser (adds parsing surface). Both options were rejected for v2.3 in favor of redesigning the tests to assert **structural correctness + fail-closed verification** against the production code's actual signing flow — the cryptographic invariants that matter (signature validity, key-id binding, tamper detection, fail-closed pubkey mismatch) are preserved without requiring a deterministic fixture key. The byte-equality fixture-driven assertion approach is explicitly deferred to v2.4 alongside any future sigstore-rs upgrade work.

Output: 1 modified file (the test file) plus an OPTIONAL test-only helper addition to `crates/nono/src/keystore.rs` (only if the existing keystore API does not already provide a test-only seeding entry point). Production code in `crates/nono-cli/src/audit_attestation.rs` is byte-identical to the pre-plan baseline. Two `#[ignore]` attributes removed; both tests pass under `cargo test -p nono-cli --test audit_attestation`. `make ci` clean.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@.planning/phases/27-audit-attestation-hardening/27-CONTEXT.md
@CLAUDE.md

<!-- Surface files (read these BEFORE making any change) -->
@crates/nono-cli/tests/audit_attestation.rs
@crates/nono-cli/src/audit_attestation.rs
@crates/nono/src/trust/signing.rs
@crates/nono/src/keystore.rs

<!-- Cross-reference: prior phase summary that locked the deferred-test rationale -->
@.planning/phases/22-windows-cross-platform-feature-gap/22-05a-SUMMARY.md

<interfaces>
<!-- Key types and contracts for this plan. Extracted from existing source. -->
<!-- Executor MUST use these directly — do not re-derive by exploration. -->

From crates/nono-cli/src/audit_attestation.rs:1-40 (production code — REUSE UNCHANGED, do not modify):

```text
//! DSSE/in-toto audit attestation signing and verification (AUD-02).
//!
//! Plan 22-05a Task 7 (upstream `6ecade2e`): when `--audit-sign-key` is set,
//! signs the audit-integrity Merkle root + chain head + session ID using
//! fork's existing `nono::trust::signing::sign_files` and writes the
//! resulting Sigstore bundle to `<session_dir>/audit-attestation.bundle`.
//!
//! ## Deviation from upstream `6ecade2e`
//!
//! Upstream's `audit_attestation.rs` (~519 LOC) calls
//! `nono::trust::signing::sign_statement_bundle` + `public_key_id_hex` and
//! relies on a refactored trust subsystem that exposes those helpers. The
//! v2.1 fork ships earlier `sign_files` + `key_id_hex` API surfaces and
//! does NOT yet expose `sign_statement_bundle` (RESEARCH plan baseline
//! claim is incorrect on this point). [...]
//!
//! - `prepare_audit_signer` resolves the `--audit-sign-key` URI through
//!   `nono::keystore::load_secret_by_ref`, then generates an ephemeral
//!   ECDSA P-256 keypair seeded by the keystore secret [...]
```

From crates/nono/src/trust/signing.rs (existing API surface — REUSE):

```rust
// generate_signing_key returns a fresh random ECDSA P-256 KeyPair.
// Tests use this per-invocation to avoid the fixture-key requirement.
pub fn generate_signing_key() -> Result<KeyPair>;

// key_id_hex extracts the deterministic SHA-256 hex key-id from the public
// key portion of a KeyPair; used for the round-trip assertion.
impl KeyPair {
    pub fn key_id_hex(&self) -> String;
    pub fn public_key_pem(&self) -> Result<String>;  // for --public-key-file flow
}
```

From crates/nono-cli/tests/audit_attestation.rs (existing test scaffold — REUSE the helpers; modify only the two #[ignore]'d test bodies):

```rust
// Existing helpers — reuse unchanged:
fn nono_bin() -> Command { ... }
fn run_nono(args: &[&str], home: &Path, cwd: &Path) -> Output { ... }
fn assert_success(output: &Output) { ... }
fn setup_isolated_home() -> (tempfile::TempDir, PathBuf, PathBuf) { ... }
fn only_audit_session_id(home: &Path) -> String { ... }

// EXISTING file-key helpers (kept; the redesigned tests SUPPLEMENT these
// rather than remove them — the trust keygen --keyref file:// path is
// still used to produce a public-key file on disk that `nono audit verify
// --public-key-file <path>` consumes; the *signing-side* deterministic
// fixture-key requirement is what we drop, NOT the verification-side
// public-key-file flow):
fn key_path(home: &Path) -> PathBuf { ... }
fn pub_key_path_for_file(private_key_path: &Path) -> PathBuf { ... }
fn generate_file_signing_key(home: &Path, cwd: &Path) -> PathBuf { ... }
```

From crates/nono-cli/tests/audit_attestation.rs:111-157 (TEST 1 — current shape; REPLACE the body but KEEP the function name):

```rust
#[test]
#[ignore = "Plan 22-05a deferred to 22-05b: requires from_pkcs8 KeyPair support + sign_statement_bundle (audit_ledger.rs)"]
fn audit_verify_reports_signed_attestation_with_pinned_public_key() {
    // [...current body uses --audit-sign-key file://... which the fork
    //  does NOT support per the production module's deviation note...]
}
```

From crates/nono-cli/tests/audit_attestation.rs:162-211 (TEST 2 — current shape; REPLACE the body but KEEP the function name):

```rust
#[test]
#[ignore = "Plan 22-05a deferred to 22-05b: requires from_pkcs8 KeyPair support + sign_statement_bundle (audit_ledger.rs)"]
fn rollback_signed_session_verifies_from_audit_dir_bundle() {
    // [...current body uses --audit-sign-key file://... + --rollback...]
}
```

Locked Path B test-redesign assertion matrix (Task 2 + Task 3 MUST implement exactly this shape):

| Assertion class | Both tests | Test 1 only | Test 2 only |
|-----------------|------------|-------------|-------------|
| Bundle file exists at `<session_dir>/audit-attestation.bundle` | yes | — | — |
| Bundle deserializes as DSSE envelope (payload type, signatures[] non-empty) | yes | — | — |
| `nono audit verify --public-key-file <matching>` exits 0 | yes | — | — |
| `nono audit verify --public-key-file <wrong>` exits non-zero (fail-closed) | yes | — | — |
| `key_id_hex` round-trip: KeyPair-extracted hex == `attestation.key_id_hex` in `audit show --json` | yes | — | — |
| Bundle does NOT live in rollback dir (Phase 22-05a invariant) | — | — | yes |
| Per-invocation UUID-suffixed `keystore://nono-test/audit-key-{uuid}` URI to avoid parallel-test collisions | yes | — | — |

Locked out-of-scope (DO NOT do these — they are deferred to v2.4):

- DO NOT upgrade `sigstore-rs` (cascades).
- DO NOT add a fork-internal pkcs8 parser (adds parsing surface).
- DO NOT port upstream's `sign_statement_bundle` API surface.
- DO NOT wire `--audit-sign-key file://...` URI handling on the signing side.
- DO NOT touch `crates/nono-cli/src/audit_attestation.rs` production code (byte-identical to v2.2 baseline).
- DO NOT modify any other test file in the workspace.
- DO NOT modify any production code in `crates/nono-cli/src/`, `crates/nono/src/trust/`, or anywhere outside the test file (the OPTIONAL `crates/nono/src/keystore.rs` test-helper is gated `#[cfg(test)]` and is the only allowed exception, and only if strictly required).
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1 (TDD-RED): Remove both #[ignore] attributes; capture baseline failure shape</name>
  <files>crates/nono-cli/tests/audit_attestation.rs</files>

  <behavior>
    - Test 1 (`audit_verify_reports_signed_attestation_with_pinned_public_key`): currently `#[ignore]`'d at line 112; after this task, runs and FAILS (because the body still uses `--audit-sign-key file://...` which the fork does not support).
    - Test 2 (`rollback_signed_session_verifies_from_audit_dir_bundle`): currently `#[ignore]`'d at line 163; after this task, runs and FAILS for the same reason.
    - This is the deliberate RED state. The next two tasks redesign each test to GREEN.
  </behavior>

  <action>
    Open `crates/nono-cli/tests/audit_attestation.rs`.

    1. At line 112, remove the entire `#[ignore = "Plan 22-05a deferred to 22-05b: requires from_pkcs8 KeyPair support + sign_statement_bundle (audit_ledger.rs)"]` attribute line. Leave the `#[test]` attribute and the existing function body untouched. The test body remains broken — that is intentional.

    2. At line 163, remove the entire `#[ignore = "Plan 22-05a deferred to 22-05b: requires from_pkcs8 KeyPair support + sign_statement_bundle (audit_ledger.rs)"]` attribute line. Leave `#[test]` and the existing function body untouched.

    3. Do NOT modify the comment blocks at lines 92-110 and 159-161 in this task — those are rewritten in Task 4 (documentation pass) once the GREEN state is achieved.

    4. Run `cargo test -p nono-cli --test audit_attestation -- --nocapture audit_verify_reports rollback_signed` and capture stderr/stdout for both failing tests. Save the captured failure output to a transient note in the commit message body (no separate fixture file — the failure shape is informational only and changes in Task 2 and Task 3).

    Commit message: `test(27-01): remove #[ignore] from audit-attestation deferred tests (RED)`

    Per CLAUDE.md, include DCO sign-off line.
  </action>

  <verify>
    <automated>cargo test -p nono-cli --test audit_attestation 2>&amp;1 | grep -E "(audit_verify_reports_signed_attestation_with_pinned_public_key|rollback_signed_session_verifies_from_audit_dir_bundle).*FAILED"</automated>
  </verify>

  <done>
    - `grep -c '#\[ignore' crates/nono-cli/tests/audit_attestation.rs` returns 0.
    - `cargo test -p nono-cli --test audit_attestation` exits non-zero with both tests reporting FAILED (not ignored, not passing yet).
    - One atomic commit on the working branch with message `test(27-01): remove #[ignore] from audit-attestation deferred tests (RED)`.
    - No other file modified.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 1.5 (CONDITIONAL): Add cfg(test)-gated `store_secret_for_test` helper to keystore.rs (only if absent)</name>
  <files>crates/nono/src/keystore.rs</files>

  <behavior>
    - IF `crates/nono/src/keystore.rs` already exposes a test-only seeding helper (search for `#[cfg(test)]` blocks containing a `store_secret`-shaped function), this task is a NO-OP — skip it and proceed to Task 2.
    - IF such a helper does NOT exist: add a `#[cfg(test)]`-gated `store_secret_for_test(uri: &str, secret: &[u8]) -> Result<()>` helper that writes a secret bytes payload addressable by the given `keystore://service/account` URI such that subsequent `nono::keystore::load_secret_by_ref(uri)` calls return the same bytes.
    - Helper MUST be `pub(crate)` or test-visible only; MUST NOT change any non-test public surface; MUST be `#[cfg(test)]`-gated so it does not ship in release builds.
  </behavior>

  <action>
    1. Open `crates/nono/src/keystore.rs`. Read the full file in one pass; identify whether a test-helper for seeding `keystore://...` URIs already exists.

    2. If present: skip this task entirely. Document the no-op in the Task 5 verification gate.

    3. If absent: add a `#[cfg(test)]` module (or extend an existing one) at the bottom of the file containing:

       ```rust
       #[cfg(test)]
       pub(crate) fn store_secret_for_test(uri: &str, secret: &[u8]) -> Result<()> {
           // Implementation: parse the keystore:// URI and write the secret
           // through the existing in-memory or platform-stub backend used by
           // the test harness. Must be symmetric with load_secret_by_ref:
           // round-trip MUST return the same bytes.
       }
       ```

       The exact implementation depends on the existing keystore backend shape — match the convention of any existing `#[cfg(test)]` blocks in the file. The helper MUST round-trip with `load_secret_by_ref`.

    4. Add a unit test `#[test] fn store_secret_for_test_round_trips()` adjacent to the helper that verifies `store_secret_for_test(uri, b"abc")` followed by `load_secret_by_ref(uri)` returns `Ok(b"abc")`.

    5. Run `cargo test -p nono` to confirm the helper compiles and the round-trip test passes.

    6. Per CLAUDE.md: no `.unwrap()` / `.expect()`; propagate via `?` and `Result<()>`.

    Commit message (only if this task is performed): `test(27-01): add cfg(test) keystore seeding helper for audit-attestation tests`
  </action>

  <verify>
    <automated>cargo test -p nono keystore::store_secret_for_test_round_trips</automated>
  </verify>

  <done>
    - Either: this task is a documented no-op (helper already exists; documented in Task 5 verification report), OR a single atomic commit lands the `#[cfg(test)]`-gated helper plus its round-trip unit test.
    - `cargo build --workspace --release` produces no warnings about an unused `#[cfg(test)]` symbol leaking into release builds.
    - No public-API surface change in `crates/nono/src/keystore.rs` (only `#[cfg(test)]` additions).
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 2 (TDD-GREEN): Redesign Test 1 with random keypair + structural assertions + fail-closed pubkey check</name>
  <files>crates/nono-cli/tests/audit_attestation.rs</files>

  <behavior>
    - After this task, `audit_verify_reports_signed_attestation_with_pinned_public_key` PASSES.
    - Test 2 (`rollback_signed_session_verifies_from_audit_dir_bundle`) still fails — that is intentional; Task 3 redesigns it.
    - The redesigned Test 1 asserts the locked Path B assertion matrix (see `<interfaces>` table) for the non-rollback case.
  </behavior>

  <action>
    Open `crates/nono-cli/tests/audit_attestation.rs`. Replace the body of `audit_verify_reports_signed_attestation_with_pinned_public_key` (lines 113-157 in the v2.2 baseline) with the redesigned implementation. KEEP the function name and the `#[test]` attribute exactly. The new body MUST follow this shape:

    ```rust
    #[test]
    fn audit_verify_reports_signed_attestation_with_pinned_public_key() {
        // 1. Set up isolated home/workspace via existing helper.
        let (_tmp, home, workspace) = setup_isolated_home();

        // 2. Generate a per-invocation random ECDSA P-256 KeyPair via
        //    nono::trust::signing::generate_signing_key. Avoid the fork's
        //    --audit-sign-key file://... path — the fork does not support
        //    PKCS8-on-disk signing-side reconstruction (see production
        //    module deviation note at audit_attestation.rs:8-15).
        let keypair = nono::trust::signing::generate_signing_key()
            .expect("generate ephemeral signing key");
        let key_id_hex_expected = keypair.key_id_hex();

        // 3. Write the public-key PEM to a temp file for the verify-side
        //    --public-key-file flow (verification-side file:// is supported;
        //    only the signing-side from_pkcs8 path is missing).
        let pub_key_pem = keypair.public_key_pem().expect("export pubkey pem");
        let pub_key_path = home.join("audit-pubkey.pem");
        std::fs::write(&pub_key_path, &pub_key_pem).expect("write pubkey pem");

        // 4. Seed a per-invocation keystore URI with secret bytes derived
        //    from the keypair (UUID-suffixed to avoid parallel-test
        //    collisions).
        let uuid = uuid::Uuid::new_v4();
        let keystore_uri = format!("keystore://nono-test/audit-key-{uuid}");
        // Use either the existing keystore test helper or the Task 1.5
        // addition (depending on whether one already existed).
        nono::keystore::store_secret_for_test(
            &keystore_uri,
            keypair.export_pkcs8().expect("export pkcs8 secret").as_ref(),
        )
        .expect("seed keystore");

        // 5. Run nono with --audit-sign-key <keystore-uri>. The fork's
        //    `prepare_audit_signer` resolves keystore:// URIs and seeds an
        //    ephemeral keypair from the secret bytes (per
        //    audit_attestation.rs:21-23).
        let run_output = run_nono(
            &[
                "run",
                "--allow-cwd",
                "--audit-sign-key",
                &keystore_uri,
                "--",
                "/bin/pwd",
            ],
            &home,
            &workspace,
        );
        assert_success(&run_output);

        let session_id = only_audit_session_id(&home);
        let session_dir = home.join(".nono").join("audit").join(&session_id);

        // 6. STRUCTURAL ASSERTION: bundle file exists.
        let bundle_path = session_dir.join("audit-attestation.bundle");
        assert!(bundle_path.exists(), "audit-attestation.bundle must exist at {bundle_path:?}");

        // 7. STRUCTURAL ASSERTION: bundle deserializes as DSSE envelope.
        let bundle_bytes = std::fs::read(&bundle_path).expect("read bundle");
        let bundle_json: serde_json::Value =
            serde_json::from_slice(&bundle_bytes).expect("bundle is valid JSON envelope");
        // DSSE shape: payload type non-empty, signatures array non-empty.
        // Field names follow the DSSE spec; check both camelCase and
        // snake_case for fork/upstream serde rename robustness.
        let payload_type = bundle_json["payloadType"]
            .as_str()
            .or_else(|| bundle_json["payload_type"].as_str())
            .or_else(|| bundle_json["dsseEnvelope"]["payloadType"].as_str());
        assert!(
            payload_type.map(|s| !s.is_empty()).unwrap_or(false),
            "DSSE payloadType must be present and non-empty; bundle: {bundle_json}"
        );
        let signatures = bundle_json["signatures"]
            .as_array()
            .or_else(|| bundle_json["dsseEnvelope"]["signatures"].as_array());
        assert!(
            signatures.map(|a| !a.is_empty()).unwrap_or(false),
            "DSSE signatures array must be non-empty; bundle: {bundle_json}"
        );

        // 8. FAIL-CLOSED ASSERTION: wrong public key -> verify fails.
        let wrong_keypair = nono::trust::signing::generate_signing_key()
            .expect("generate wrong-key");
        let wrong_pub_pem = wrong_keypair.public_key_pem().expect("export wrong-pub");
        let wrong_pub_path = home.join("audit-pubkey-wrong.pem");
        std::fs::write(&wrong_pub_path, &wrong_pub_pem).expect("write wrong pub");
        let wrong_verify_output = run_nono(
            &[
                "audit",
                "verify",
                &session_id,
                "--public-key-file",
                wrong_pub_path.to_str().expect("path utf8"),
                "--json",
            ],
            &home,
            &workspace,
        );
        assert!(
            !wrong_verify_output.status.success(),
            "audit verify with WRONG public key MUST fail closed; stdout: {}, stderr: {}",
            String::from_utf8_lossy(&wrong_verify_output.stdout),
            String::from_utf8_lossy(&wrong_verify_output.stderr)
        );

        // 9. POSITIVE VERIFY: correct public key -> exit 0 + JSON shape.
        let verify_output = run_nono(
            &[
                "audit",
                "verify",
                &session_id,
                "--public-key-file",
                pub_key_path.to_str().expect("path utf8"),
                "--json",
            ],
            &home,
            &workspace,
        );
        assert_success(&verify_output);
        let json: Value = serde_json::from_slice(&verify_output.stdout).expect("parse verify json");
        assert_eq!(json["session"]["records_verified"], true);
        assert_eq!(json["ledger"]["session_digest_matches"], true);
        assert_eq!(json["ledger"]["ledger_chain_verified"], true);
        assert_eq!(json["attestation"]["present"], true);
        assert_eq!(json["attestation"]["signature_verified"], true);
        assert_eq!(json["attestation"]["verification_error"], Value::Null);

        // 10. KEY_ID_HEX ROUND-TRIP: extracted hex matches `nono audit show`.
        let show_output = run_nono(
            &["audit", "show", &session_id, "--json"],
            &home,
            &workspace,
        );
        assert_success(&show_output);
        let show_json: Value = serde_json::from_slice(&show_output.stdout).expect("parse show json");
        let key_id_hex_observed = show_json["attestation"]["key_id_hex"]
            .as_str()
            .expect("key_id_hex present in show json");
        assert_eq!(
            key_id_hex_observed, key_id_hex_expected,
            "key_id_hex round-trip MUST match: KeyPair-extracted vs audit show output"
        );
    }
    ```

    Notes for the executor:
    - The ephemeral-keypair-from-keystore-secret seeding (`prepare_audit_signer`) is the FORK's existing flow per `audit_attestation.rs:21-23`. The test must NOT bypass it.
    - If the production code's `prepare_audit_signer` requires a specific shape for the keystore secret (e.g. raw pkcs8 bytes vs base64 vs hex), inspect it BEFORE writing the test and match. Do NOT modify the production code to fit the test.
    - If `KeyPair::export_pkcs8()` is not exposed on the fork, derive an alternative byte-encoding the seeding flow accepts (the production code's `prepare_audit_signer` is the source of truth for the expected secret shape).
    - The `uuid` crate may not be in `nono-cli` dev-dependencies; if absent, use a process-id + nanos timestamp suffix instead of UUID. Either approach satisfies the parallel-test-collision risk mitigation.
    - Per CLAUDE.md unwrap policy: tests are the documented exception (`#[allow(clippy::unwrap_used)]` is permitted in test modules). The `.expect("...")` calls in the snippet above are acceptable in this test file; do not use `.unwrap()`.

    Commit message: `test(27-01): redesign audit_verify pinned-pubkey test with random keypair + structural assertions (GREEN)`

    Include DCO sign-off line.
  </action>

  <verify>
    <automated>cargo test -p nono-cli --test audit_attestation audit_verify_reports_signed_attestation_with_pinned_public_key -- --exact</automated>
  </verify>

  <done>
    - `audit_verify_reports_signed_attestation_with_pinned_public_key` passes under `cargo test -p nono-cli --test audit_attestation -- --exact <name>`.
    - The other test (`rollback_signed_session_verifies_from_audit_dir_bundle`) still FAILS (Task 3 will fix it).
    - `grep -c 'from_pkcs8' crates/nono-cli/tests/audit_attestation.rs` returns 0.
    - One atomic commit with message `test(27-01): redesign audit_verify pinned-pubkey test with random keypair + structural assertions (GREEN)`.
    - No file other than the test file modified in this commit.
    - `crates/nono-cli/src/audit_attestation.rs` byte-identical to baseline.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 3 (TDD-GREEN): Redesign Test 2 (rollback_signed_session_verifies_from_audit_dir_bundle) with the same Path B strategy + rollback-dir invariant assertion</name>
  <files>crates/nono-cli/tests/audit_attestation.rs</files>

  <behavior>
    - After this task, `rollback_signed_session_verifies_from_audit_dir_bundle` PASSES.
    - The Phase 22-05a invariant "bundle lives in audit dir, NOT in rollback dir" continues to hold.
    - Same fail-closed-with-wrong-pubkey assertion as Test 1; same key_id_hex round-trip.
  </behavior>

  <action>
    Open `crates/nono-cli/tests/audit_attestation.rs`. Replace the body of `rollback_signed_session_verifies_from_audit_dir_bundle` (lines 164-211 in the v2.2 baseline) with a redesigned body following the same Path B pattern as Task 2, with these additions:

    1. Before the `nono run` invocation, write a tracked workspace file via `fs::write(workspace.join("tracked.txt"), "before\n").expect("write tracked file");` (preserves the rollback-test setup from the original).

    2. Add `--rollback` and `--no-rollback-prompt` to the run-invocation arg vector (preserves the rollback path-shape from the original).

    3. After the run completes, assert BOTH:
       - `audit_dir.join("audit-attestation.bundle").exists()` (bundle lives in audit dir).
       - `!rollback_dir.join("audit-attestation.bundle").exists()` (bundle does NOT live in rollback dir; this is the Phase 22-05a invariant the original test was checking).

    4. Apply the SAME structural-correctness + fail-closed + key_id_hex round-trip assertions as Task 2. Do NOT call `audit verify --public-key-file` with the matching key first and then NOT also include the wrong-key fail-closed assertion — both halves are mandatory.

    5. The verify-side JSON shape assertions are the rollback-test set from the v2.2 baseline (`merkle_root_matches`, `session_id_matches`, `verification_error == null`); preserve those because they exercise the rollback-bundle code path differently from Test 1.

    6. Use a DIFFERENT UUID/suffix for the keystore URI than Test 1 to guarantee no collision under `cargo test --jobs N` parallel execution.

    Commit message: `test(27-01): redesign rollback_signed_session test with random keypair + audit-dir-only invariant (GREEN)`

    Include DCO sign-off line.
  </action>

  <verify>
    <automated>cargo test -p nono-cli --test audit_attestation rollback_signed_session_verifies_from_audit_dir_bundle -- --exact</automated>
  </verify>

  <done>
    - `rollback_signed_session_verifies_from_audit_dir_bundle` passes under `cargo test -p nono-cli --test audit_attestation -- --exact <name>`.
    - Both tests pass under a single `cargo test -p nono-cli --test audit_attestation` invocation.
    - `grep -c '#\[ignore' crates/nono-cli/tests/audit_attestation.rs` returns 0.
    - `grep -c 'from_pkcs8' crates/nono-cli/tests/audit_attestation.rs` returns 0.
    - Audit-dir-only invariant grep verifiable: `grep -A2 'rollback_dir.join' crates/nono-cli/tests/audit_attestation.rs` shows the negative-existence assertion present.
    - One atomic commit with message `test(27-01): redesign rollback_signed_session test with random keypair + audit-dir-only invariant (GREEN)`.
    - `crates/nono-cli/src/audit_attestation.rs` byte-identical to baseline.
  </done>
</task>

<task type="auto">
  <name>Task 4: Documentation pass — Phase 27 deviation comment block above the redesigned tests</name>
  <files>crates/nono-cli/tests/audit_attestation.rs</files>

  <action>
    Open `crates/nono-cli/tests/audit_attestation.rs`. Replace the existing comment block at lines 92-110 (the Plan 22-05a deferral rationale) with an updated block that documents BOTH the original Phase 22-05a deferral AND the Phase 27 Path B redesign rationale.

    Suggested replacement comment block (place immediately above the first `#[test]` line, currently at line 111):

    ```rust
    // ============================================================================
    // Phase 27 Plan 01 (REQ-AAH-01): audit-attestation fixture-test redesign.
    // ============================================================================
    //
    // ## Background — Phase 22-05a deferral
    //
    // Plan 22-05a Task 8 imported the upstream 188 LOC integration test
    // fixture verbatim, but two tests below required upstream's
    // `KeyPair::from_pkcs8` + `sign_statement_bundle` API surfaces and
    // the corresponding `--audit-sign-key file://...` URI scheme handler.
    // Sigstore-rs 0.6.4 (the v2.1 baseline pin) does not expose
    // `from_pkcs8`, and the fork's `crates/nono-cli/src/audit_attestation.rs`
    // (per the deviation note at lines 8-15 in that file) deliberately
    // uses `nono::trust::signing::generate_signing_key` per-session
    // seeded by a `keystore://...` URI rather than reconstructing a
    // pinned PKCS8 key from a `file://...` URI. Both tests were marked
    // `#[ignore]` with a deferral note pointing at Plan 22-05b.
    //
    // ## Phase 27 — Path B (Fixture Test Redesign)
    //
    // Path A (upgrade sigstore-rs to a version that exposes
    // `KeyPair::from_pkcs8`) cascades through other crates and is
    // out-of-scope for v2.3.
    //
    // Path B (the strategy below) re-enables both tests by **redesigning
    // their assertion strategy** rather than chasing the upstream API.
    // Specifically:
    //   1. Each test invocation generates a fresh random ECDSA P-256
    //      keypair via `nono::trust::signing::generate_signing_key()`.
    //      No deterministic fixture key required.
    //   2. The `--audit-sign-key` flow uses the fork's existing
    //      `keystore://nono-test/audit-key-{uuid}` URI handling rather
    //      than `file://...`. UUID-suffixing avoids parallel-test
    //      collisions under `cargo test --jobs N`.
    //   3. Assertions check **structural correctness**: the DSSE bundle
    //      file exists at the expected path, deserializes as a valid
    //      envelope (payload type non-empty, signatures array non-empty),
    //      and the public-key-file verify path exits 0.
    //   4. Assertions check **fail-closed verification**: passing a
    //      WRONG public key to `nono audit verify --public-key-file`
    //      returns a non-zero exit. This catches signature-mismatch
    //      and key-id-binding bugs that byte-equality fixture testing
    //      would also catch.
    //   5. The `key_id_hex` accessor on the generated KeyPair must
    //      round-trip with the `attestation.key_id_hex` field reported
    //      by `nono audit show <id> --json`.
    //
    // ## Trade-off — explicit
    //
    // Path B catches all the cryptographic invariants that matter
    // (signature validity, key-id binding, fail-closed verify, tamper
    // detection via the wrong-pubkey case). It does NOT catch a
    // hypothetical regression that produces a *different but valid*
    // DSSE bundle byte-shape (e.g., a serialization-order change) — that
    // narrow class of regression is what byte-equality fixture testing
    // would uniquely catch.
    //
    // Re-introducing byte-equality fixture testing requires porting
    // upstream's `KeyPair::from_pkcs8` + `sign_statement_bundle`, which
    // is deferred to v2.4 alongside any future sigstore-rs upgrade. See
    // REQUIREMENTS.md REQ-AAH-01 acceptance criteria for the v2.3 close
    // criteria; the v2.4 backlog tracks the byte-equality restoration.
    //
    // Do NOT touch `crates/nono-cli/src/audit_attestation.rs` to make
    // these tests easier — production code is byte-identical to the
    // v2.2 Phase 22-05a baseline. Any change to production code that
    // shifts the bundle shape needs an explicit Plan 27-NN follow-up,
    // not a quiet test-side accommodation.
    // ============================================================================
    ```

    Also remove the now-stale 3-line comment block at lines 159-161 (the original "see note above" pointer for Test 2), since the consolidated comment block above the test pair makes it redundant. Replace it with a 1-line cross-reference if desired, e.g. `// See Phase 27 Plan 01 comment block above for Path B test-redesign rationale.`

    Run `cargo fmt --all` to ensure the comment block follows project formatting.

    Commit message: `docs(27-01): document Path B fixture-test redesign rationale in audit_attestation tests`

    Include DCO sign-off line.
  </action>

  <verify>
    <automated>grep -c "Phase 27" crates/nono-cli/tests/audit_attestation.rs &amp;&amp; grep -c "Path B" crates/nono-cli/tests/audit_attestation.rs &amp;&amp; grep -c "byte-equality" crates/nono-cli/tests/audit_attestation.rs</automated>
  </verify>

  <done>
    - The comment block above the redesigned tests contains the substrings "Phase 27", "Path B", "byte-equality", and "v2.4" (verifiable via grep).
    - `cargo test -p nono-cli --test audit_attestation` still exits 0 (comment-block edit must not break compilation or test logic).
    - `cargo fmt --check` exits 0.
    - One atomic commit with message `docs(27-01): document Path B fixture-test redesign rationale in audit_attestation tests`.
  </done>
</task>

<task type="auto">
  <name>Task 5: Verification gate — full make ci + production-code byte-identity check (read-only; no commit)</name>
  <files></files>

  <action>
    Read-only verification pass. No file edits and no new commit.

    1. Capture the pre-plan git revision of `crates/nono-cli/src/audit_attestation.rs`:
       ```bash
       git log --oneline -1 -- crates/nono-cli/src/audit_attestation.rs
       ```
       Record this baseline SHA in the verification report.

    2. Run `git diff --stat <baseline-sha>..HEAD -- crates/nono-cli/src/audit_attestation.rs` and assert the output is empty (production code byte-identical to v2.2 Phase 22-05a baseline). If non-empty, the plan has been violated — STOP and surface the diff in the verification report; do NOT proceed to commit any further changes.

    3. Run `make ci` (cargo clippy + cargo fmt --check + cargo test --workspace per the project Makefile). Capture exit code; require exit 0.

    4. Run `cargo test -p nono-cli --test audit_attestation` and capture both test names + PASSED status. Require both `audit_verify_reports_signed_attestation_with_pinned_public_key` and `rollback_signed_session_verifies_from_audit_dir_bundle` to report PASSED.

    5. Run the must_haves grep checks from the frontmatter:
       - `grep -c '#\[ignore' crates/nono-cli/tests/audit_attestation.rs` -> 0
       - `grep -rc 'from_pkcs8' crates/nono-cli/tests/` -> 0
       - `grep -c 'audit-attestation.bundle' crates/nono-cli/tests/audit_attestation.rs` -> >= 2
       - `grep -c 'signatures' crates/nono-cli/tests/audit_attestation.rs` -> >= 2
       - `grep -c 'Phase 27' crates/nono-cli/tests/audit_attestation.rs` -> >= 1

    6. Run a parallel-test-stress sanity check to surface keystore-URI collision flakes:
       ```bash
       for i in 1 2 3 4 5; do cargo test -p nono-cli --test audit_attestation -- --test-threads=4 || break; done
       ```
       Require all 5 iterations to pass. If any iteration fails with a flake-shaped error (keystore-URI conflict, file-system race), surface in the verification report — the UUID-suffix mitigation may need tightening.

    7. Produce a verification report at `.planning/phases/27-audit-attestation-hardening/27-01-VERIFY.md` summarizing each check above with PASS/FAIL status. Cite commit SHAs for each task's atomic commit.

    No commit on this task itself; the verification report is a planning-side artifact.
  </action>

  <verify>
    <automated>make ci &amp;&amp; cargo test -p nono-cli --test audit_attestation</automated>
  </verify>

  <done>
    - `make ci` exits 0.
    - Both redesigned tests pass under 5x stress-iteration with `--test-threads=4`.
    - `git diff --stat <baseline>..HEAD -- crates/nono-cli/src/audit_attestation.rs` is empty.
    - All 8 frontmatter `must_haves.truths` entries verified PASS in the verification report.
    - Verification report committed to `.planning/phases/27-audit-attestation-hardening/27-01-VERIFY.md` (separate `docs(27-01): verification report` commit is acceptable).
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| test process -> file system | Test creates temp directories, writes pubkey PEMs, reads bundle bytes; all under `target/test-artifacts/` (project-local). No cross-tenant exposure. |
| test process -> keystore backend | Test seeds `keystore://nono-test/{uuid}` URIs via `#[cfg(test)]` helper; helper is gated out of release builds. No production-keystore exposure. |
| test process -> nono CLI subprocess | Test runs `nono` binary with `HOME` and `XDG_CONFIG_HOME` overridden to the temp dir. Existing pattern (Phase 22-05a baseline); no new boundary. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-27-01 | Tampering | DSSE bundle on disk | mitigate | Test 1 fail-closed-with-wrong-pubkey check exercises the verify path's signature validation; a tampered bundle that survives signature validation would surface here. |
| T-27-02 | Spoofing | Signing key identity | mitigate | `key_id_hex` round-trip assertion (Test 1 step 10) ensures the public-key-id reported by `nono audit show` matches the KeyPair-extracted hex; a key-substitution bug that swaps the recorded hex without invalidating the signature would surface here. |
| T-27-03 | Information Disclosure | Test-only keystore secret | accept | Secret is per-invocation random ECDSA P-256 bytes seeded into a `keystore://nono-test/{uuid}` URI under a `#[cfg(test)]`-gated helper; never written to a persistent keystore backend; rotates per test invocation. Acceptable risk for test-only code. |
| T-27-04 | Repudiation | Audit ledger integrity | mitigate | Existing v2.2 `audit_integrity` verification (`session_digest_matches`, `ledger_chain_verified`) still asserted in Test 1. Path B redesign does NOT weaken these assertions. |
| T-27-05 | Denial of Service | Parallel-test keystore-URI collision | mitigate | UUID-suffixed keystore URIs (`keystore://nono-test/audit-key-{uuid}`) prevent test-process collisions under `cargo test --jobs N`. Task 5 step 6 stress-tests this with 5 iterations at `--test-threads=4`. |
| T-27-06 | Elevation of Privilege | `#[cfg(test)]` keystore helper leaking into release | mitigate | Helper is `#[cfg(test)]`-gated; Task 5 verification implicitly checks via `make ci` (release build of `cargo test --workspace` would surface a leak as a missing-symbol link error or a clippy `dead_code` warning). |
| T-27-07 | Tampering | Production code modification under test pressure | mitigate | Frontmatter must_have explicitly forbids modification of `crates/nono-cli/src/audit_attestation.rs`; Task 5 step 2 enforces byte-identity via `git diff --stat` against pre-plan baseline. |
</threat_model>

<verification>
Phase-wide verification gates (run after Task 5):

1. **`#[ignore]` removal:** `grep -c '#\[ignore' crates/nono-cli/tests/audit_attestation.rs` returns 0.
2. **Test pass:** `cargo test -p nono-cli --test audit_attestation` exits 0; both target tests show PASSED.
3. **No `from_pkcs8` regression:** `grep -rc 'from_pkcs8' crates/nono-cli/tests/` returns 0.
4. **Production code byte-identity:** `git diff --stat <baseline>..HEAD -- crates/nono-cli/src/audit_attestation.rs` is empty.
5. **make ci clean:** clippy + fmt + workspace test all green.
6. **Parallel-test stability:** 5 consecutive `cargo test -p nono-cli --test audit_attestation -- --test-threads=4` runs all pass.
7. **Documentation present:** Phase 27 / Path B / byte-equality / v2.4 substrings present in test-file comment block.
8. **Threat register coverage:** Every STRIDE entry above either has a mitigation that the test suite implicitly exercises, or is explicitly accepted with rationale.

If ANY gate fails, the plan is incomplete — STOP and surface the failure in `27-01-VERIFY.md` before declaring the plan done.
</verification>

<success_criteria>
- REQ-AAH-01 acceptance criterion 1: Both `#[ignore]`'d tests in `audit_attestation.rs` run (no `#[ignore]` attribute) and pass — **MET** by Tasks 1–3.
- REQ-AAH-01 acceptance criterion 2: The architectural decision is documented in CONTEXT (and in-source) with the cascade impact for future readers — **MET** by Task 4 + the Phase 27 CONTEXT.md decision record.
- REQ-AAH-01 acceptance criterion 3: `cargo test -p nono-cli --test audit_attestation` exits 0 with no ignored tests — **MET** by Task 5 verification gate.
- REQ-AAH-01 acceptance criterion 4: Threat-model entry covers the new parsing surface (none introduced under Path B; the `#[cfg(test)]` keystore helper is the only new test-side surface and is covered by T-27-03 + T-27-06) — **MET** by `<threat_model>` above.
- Production code in `crates/nono-cli/src/audit_attestation.rs` byte-identical to the v2.2 Phase 22-05a baseline — **MET** by Task 5 git-diff check.
- `make ci` clean — **MET** by Task 5 verification gate.
- 4 atomic commits land (Task 1 RED, Task 2 GREEN, Task 3 GREEN, Task 4 docs) plus 1 OPTIONAL commit (Task 1.5 keystore helper, only if needed) plus 1 OPTIONAL commit (Task 5 verification report). Each carries a DCO sign-off line per CLAUDE.md.
</success_criteria>

<output>
After completion, create `.planning/phases/27-audit-attestation-hardening/27-01-SUMMARY.md` documenting:
- Commit SHAs for each atomic commit
- Whether Task 1.5 was performed (keystore helper added) or skipped (helper already present)
- Verification report path: `.planning/phases/27-audit-attestation-hardening/27-01-VERIFY.md`
- Confirmation that `crates/nono-cli/src/audit_attestation.rs` is byte-identical to the pre-plan baseline (cite the baseline SHA)
- v2.4 deferral note: byte-equality fixture testing remains deferred; reference REQ-AAH-01 v2.4 backlog row when the milestone is opened
- Any open questions or surfaced flakes that need follow-up
</output>
