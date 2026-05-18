//! Integration tests for supervisor-side audit attestation.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn run_nono(args: &[&str], home: &Path, cwd: &Path) -> Output {
    let mut cmd = nono_bin();
    cmd.args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        // Phase 27.1 (REQ-NTH-03): NONO_TEST_HOME is the production-code seam
        // added in Plans 27.1-01 and 27.1-02. The supervisor calls
        // `crate::config::nono_home_dir()` instead of `dirs::home_dir()` and
        // honors this env var on all platforms (including Windows, which
        // ignores `USERPROFILE` overrides via `SHGetKnownFolderPath`). This
        // closes Phase 27 Blocker 1 (audit_root not env-overridable on
        // Windows) and Blocker 2 (audit/rollback path mismatch under
        // partial env redirection).
        .env("NONO_TEST_HOME", home);
    cmd.current_dir(cwd).output().expect("failed to run nono")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected success, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn setup_isolated_home() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp_root = std::env::current_dir()
        .expect("cwd")
        .join("target")
        .join("test-artifacts");
    fs::create_dir_all(&temp_root).expect("create temp root");
    let tmp = tempfile::Builder::new()
        .prefix("nono-audit-attestation-it-")
        .tempdir_in(&temp_root)
        .expect("tempdir");
    let home = tmp.path().join("home");
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(home.join(".config")).expect("create config dir");
    // Phase 27 Path B: pre-create Windows-style AppData dirs so the CLI's
    // `dirs::config_dir()` resolution (which reads %APPDATA%) finds a real
    // path. No-op on Unix.
    fs::create_dir_all(home.join("AppData").join("Roaming")).expect("create AppData\\Roaming dir");
    fs::create_dir_all(home.join("AppData").join("Local")).expect("create AppData\\Local dir");
    // Phase 27 Path B: pre-create the Windows rollback root so the
    // supervisor's `nono run` startup canonicalization doesn't fail. The
    // path resolution uses `crate::config::user_state_dir()` ->
    // `%LOCALAPPDATA%\nono\rollbacks`. No-op on Unix.
    fs::create_dir_all(
        home.join("AppData")
            .join("Local")
            .join("nono")
            .join("rollbacks"),
    )
    .expect("create rollback root");
    // Phase 27.1 Plan 03 (D-27.1-14 small fix): pre-create the
    // production-mirror rollback + audit roots under the NONO_TEST_HOME
    // override. The supervisor's `--audit-integrity` exit-cleanup path
    // canonicalizes `<home>/.nono/rollbacks` before that directory is
    // necessarily created (Phase 27 Blocker 3 surface). Pre-creating both
    // dirs here keeps the cleanup path's `canonicalize()` call happy on
    // sessions that don't take a rollback snapshot.
    fs::create_dir_all(home.join(".nono").join("rollbacks"))
        .expect("create NONO_TEST_HOME-rooted rollback dir");
    fs::create_dir_all(home.join(".nono").join("audit"))
        .expect("create NONO_TEST_HOME-rooted audit dir");
    fs::create_dir_all(&workspace).expect("create workspace dir");
    (tmp, home, workspace)
}

fn key_path(home: &Path) -> PathBuf {
    home.join("audit-signing-key.pk8.b64")
}

fn pub_key_path_for_file(private_key_path: &Path) -> PathBuf {
    let mut pub_path = private_key_path.as_os_str().to_owned();
    pub_path.push(".pub");
    PathBuf::from(pub_path)
}

fn generate_file_signing_key(home: &Path, cwd: &Path) -> PathBuf {
    let key_path = key_path(home);
    let keyref = format!("file://{}", key_path.display());
    let output = run_nono(
        &["trust", "keygen", "--force", "--keyref", &keyref],
        home,
        cwd,
    );
    assert_success(&output);
    assert!(key_path.exists(), "private key should exist");
    assert!(
        pub_key_path_for_file(&key_path).exists(),
        "public key should exist"
    );
    key_path
}

/// Cross-platform sandboxed test command. On Unix, `/bin/pwd` exists and
/// is a tiny no-op-style binary suitable for an audit session that just
/// needs to run *something* under the supervisor. On Windows there is no
/// `/bin/pwd`; use `cmd /c cd` (the `cd` builtin with no args prints the
/// current directory and exits cleanly).
#[cfg(target_os = "windows")]
fn run_command_args() -> Vec<&'static str> {
    // `cmd /c echo nono-test` is the proven cross-test cmd shape used by
    // `windows_run_executes_basic_command` in env_vars.rs. `cmd /c cd`
    // additionally requires `C:\` in the launch-path policy, which the
    // default Windows supervisor policy does NOT cover (Phase 27
    // discovery: causes "Windows filesystem policy does not cover the
    // absolute path argument required for launch: C:\").
    vec!["cmd", "/c", "echo", "nono-test"]
}

#[cfg(not(target_os = "windows"))]
fn run_command_args() -> Vec<&'static str> {
    vec!["/bin/pwd"]
}

/// Decode a lowercase hex string into bytes. Used by the Phase 27 Path B
/// redesigned tests to convert the hex-encoded SPKI DER stored in
/// session.json's audit_attestation.public_key into the raw DER bytes that
/// `nono audit verify --public-key-file` accepts.
fn hex_decode_test(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        out.push(u8::from_str_radix(hex_str, 16).ok()?);
    }
    Some(out)
}

/// Resolve the audit-root directory the supervisor will write into.
///
/// On Unix, the test's `HOME` override redirects `dirs::home_dir()` to the
/// per-test temp dir (`<home>/.nono/audit`).
///
/// On Windows, `dirs::home_dir()` consults Windows API
/// `SHGetKnownFolderPath(FOLDERID_Profile)` directly and IGNORES the
/// `USERPROFILE` env override (dirs 6.0.0 + dirs-sys 0.5.0 behavior). The
/// supervisor therefore writes to the real user profile's
/// `%USERPROFILE%\.nono\audit\` dir. The test pattern is to take a "before"
/// snapshot of session-ids in that dir, run the supervisor, and identify
/// the new session as the set difference. This mirrors the pattern already
/// used by the Windows env_vars.rs tests (e.g. `windows_run_read_only_allowlist_blocks_runtime_write_attempt`).
///
/// Phase 27.1: Now unused — the NONO_TEST_HOME seam routes the supervisor's
/// `audit_root()` to `<NONO_TEST_HOME>/.nono/audit` on all platforms, so
/// the simpler `only_audit_session_id` helper suffices. Kept for potential
/// future use (e.g., a test that intentionally coexists with parent-process
/// audit sessions).
#[allow(dead_code)]
fn audit_root_for_supervisor(home: &Path) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let _ = home;
        let userprofile = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .expect("USERPROFILE must be set on Windows host");
        userprofile.join(".nono").join("audit")
    }
    #[cfg(not(target_os = "windows"))]
    {
        home.join(".nono").join("audit")
    }
}

/// Snapshot the set of session-ids currently present in the audit root.
///
/// Used to identify the test's newly-created session as a set-difference
/// between a pre-run snapshot and a post-run scan. Robust to other audit
/// sessions that exist in the user's real profile on Windows.
///
/// Phase 27.1: Now unused — see `audit_root_for_supervisor` rationale.
#[allow(dead_code)]
fn audit_session_ids_snapshot(audit_root: &Path) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let entries = match fs::read_dir(audit_root) {
        Ok(e) => e,
        Err(_) => return out, // dir doesn't exist yet; empty snapshot
    };
    for entry in entries.flatten() {
        if let Ok(ft) = entry.file_type() {
            if ft.is_dir() {
                out.insert(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    out
}

/// Resolve the test's session id by computing the set-difference between
/// a pre-run snapshot and the current state of the audit root. Asserts
/// exactly one new directory was created.
///
/// Phase 27.1: Now unused — see `audit_root_for_supervisor` rationale.
#[allow(dead_code)]
fn new_session_id_after_run(
    audit_root: &Path,
    before: &std::collections::HashSet<String>,
) -> String {
    let after = audit_session_ids_snapshot(audit_root);
    let mut new_ids: Vec<String> = after.difference(before).cloned().collect();
    new_ids.sort();
    assert_eq!(
        new_ids.len(),
        1,
        "expected exactly one new audit session in {audit_root:?}; \
         before-count={} after-count={} new={:?}",
        before.len(),
        after.len(),
        new_ids
    );
    new_ids.remove(0)
}

fn only_audit_session_id(home: &Path) -> String {
    let audit_root = home.join(".nono").join("audit");
    let mut session_ids: Vec<String> = fs::read_dir(&audit_root)
        .expect("read audit root")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_dir() {
                return None;
            }
            Some(entry.file_name().to_string_lossy().to_string())
        })
        .collect();
    session_ids.sort();
    assert_eq!(session_ids.len(), 1, "expected exactly one audit session");
    session_ids.remove(0)
}

/// Local RAII env-var guard for the integration test (Phase 27.2 D-27.2-09).
///
/// `crate::test_env::EnvVarGuard` lives under `#[cfg(test)]` in
/// `crates/nono-cli/src/test_env.rs` and is therefore not visible from the
/// integration test compilation unit. Duplicating the Drop-restore shape
/// here is the lightest landing per CONTEXT § Claude's Discretion (single
/// test file; no shared `tests/common.rs` module yet).
///
/// The integration test uses dynamically-named env vars
/// (`format!("NONO_TEST_AUDIT_KEY_VERIFY_{suffix}")`) so the key type is
/// `String`, not `&'static str` like the unit-test guard. Restoration on
/// `Drop` ensures a panic in `run_nono` does not leak the test secret env
/// var (closes Phase 27.1 REVIEW WR-05).
struct ScopedEnvVar {
    key: String,
    original: Option<String>,
}

impl ScopedEnvVar {
    #[allow(clippy::disallowed_methods)] // This is the safe wrapper for env-var mutation.
    fn set(key: String, value: &str) -> Self {
        let original = std::env::var(&key).ok();
        std::env::set_var(&key, value);
        Self { key, original }
    }
}

impl Drop for ScopedEnvVar {
    #[allow(clippy::disallowed_methods)] // Restoration is the other half of the safe wrapper.
    fn drop(&mut self) {
        match &self.original {
            Some(value) => std::env::set_var(&self.key, value),
            None => std::env::remove_var(&self.key),
        }
    }
}

// Phase 27.2 (REQ-AAHX-01..03, 2026-05-05): the v2.4 follow-ups surfaced by
// Phase 27.1 D-27.1-14 — audit-loader swap (FU-1) and bundle-target
// migration (FU-2) — landed in Plans 27.2-01 and 27.2-02. Both
// previously-deferred ignore attributes are removed below; tests run
// end-to-end against the NONO_TEST_HOME seam on Windows host. Bundle
// target locked at <audit_root>/<id>/audit-attestation.bundle regardless
// of --rollback per docs/architecture/audit-bundle-target.md (D-27.2-01
// Option A).
#[test]
fn audit_verify_reports_signed_attestation_with_pinned_public_key() {
    let (_tmp, home, workspace) = setup_isolated_home();

    // Per-invocation env:// keystore URI seeding (Phase 27 Path B).
    // The fork's prepare_audit_signer touches the secret for fail-closed
    // semantics, then generates a fresh ECDSA P-256 keypair internally
    // (audit_attestation.rs:89-99). The test cannot pre-compute the
    // supervisor's public key — it extracts it from session.json AFTER
    // the supervisor signs.
    let suffix = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let env_var = format!("NONO_TEST_AUDIT_KEY_VERIFY_{suffix}");
    let secret = format!("phase-27-path-b-test-secret-{suffix}");
    // Per-invocation env-var name (PID + nanos suffix above) avoids
    // collisions across parallel test runs. Phase 27.2 D-27.2-09: wrap
    // the set/remove pair in a local ScopedEnvVar RAII guard so a panic
    // in run_nono doesn't leak the test secret env var (closes Phase 27.1
    // REVIEW WR-05).
    let _env_guard = ScopedEnvVar::set(env_var.clone(), &secret);
    let keyref = format!("env://{env_var}");

    let cmd_args = run_command_args();
    let mut args = vec![
        "run",
        "--audit-integrity",
        "--audit-sign-key",
        &keyref,
        "--",
    ];
    args.extend(cmd_args.iter().copied());
    let run_output = run_nono(&args, &home, &workspace);
    assert_success(&run_output);

    // Phase 27.1: NONO_TEST_HOME isolates the test's audit_root to <home>/.nono/audit
    // so the simple single-session lookup is unambiguous. The Windows
    // set-difference workaround (audit_root_for_supervisor +
    // new_session_id_after_run) is no longer needed.
    let session_id = only_audit_session_id(&home);
    let session_dir = home.join(".nono").join("audit").join(&session_id);

    // STRUCTURAL ASSERTION 1: bundle file exists at canonical path.
    let bundle_path = session_dir.join("audit-attestation.bundle");
    assert!(
        bundle_path.exists(),
        "audit-attestation.bundle must exist at {bundle_path:?}"
    );

    // STRUCTURAL ASSERTION 2: bundle deserializes as DSSE envelope.
    // sigstore-rs Sigstore Bundle v0.3 has dsseEnvelope.{payloadType,
    // signatures[]}. Both must be present and non-empty.
    let bundle_bytes = fs::read(&bundle_path).expect("read bundle");
    let bundle_json: Value =
        serde_json::from_slice(&bundle_bytes).expect("bundle is valid JSON envelope");
    let payload_type = bundle_json["dsseEnvelope"]["payloadType"]
        .as_str()
        .expect("DSSE payloadType must be present");
    assert!(
        !payload_type.is_empty(),
        "DSSE payloadType must be non-empty; bundle: {bundle_json}"
    );
    let signatures = bundle_json["dsseEnvelope"]["signatures"]
        .as_array()
        .expect("DSSE signatures array must be present");
    assert!(
        !signatures.is_empty(),
        "DSSE signatures array must be non-empty; bundle: {bundle_json}"
    );

    // Extract supervisor's public key from session.json. The fork's
    // AuditAttestationSummary records public_key as hex-encoded SPKI DER
    // (audit_attestation.rs:102 hex_encode); decode and write as raw DER
    // for --public-key-file (which accepts raw DER per audit_attestation.rs:329).
    let session_json_bytes = fs::read(session_dir.join("session.json")).expect("read session.json");
    let session_json: Value =
        serde_json::from_slice(&session_json_bytes).expect("parse session.json");
    let pub_key_hex = session_json["audit_attestation"]["public_key"]
        .as_str()
        .expect("audit_attestation.public_key in session.json");
    let session_key_id = session_json["audit_attestation"]["key_id"]
        .as_str()
        .expect("audit_attestation.key_id in session.json");
    assert!(
        !pub_key_hex.is_empty() && pub_key_hex.len().is_multiple_of(2),
        "public_key hex must be non-empty even-length"
    );
    let pub_key_der = hex_decode_test(pub_key_hex).expect("decode pubkey hex DER");
    let pub_key_path = home.join("audit-pubkey.der");
    fs::write(&pub_key_path, &pub_key_der).expect("write pubkey DER");

    // KEY_ID_HEX ROUND-TRIP: bundle's verificationMaterial.publicKey.hint
    // is the SHA-256 of the SPKI DER (signing.rs:445 hint = key_id_hex).
    // This must match session.json's audit_attestation.key_id.
    let bundle_hint = bundle_json["verificationMaterial"]["publicKey"]["hint"]
        .as_str()
        .expect("verificationMaterial.publicKey.hint in bundle");
    assert_eq!(
        bundle_hint, session_key_id,
        "key_id_hex round-trip MUST match: bundle hint vs session.json audit_attestation.key_id"
    );

    // FAIL-CLOSED ASSERTION: wrong public key -> verify exits non-zero.
    // Generate a fresh random ECDSA P-256 keypair, write its PEM, pass it
    // as --public-key-file. The DSSE signature was made by a different key,
    // so verification must fail closed.
    let wrong_kp =
        nono::trust::signing::generate_signing_key().expect("generate wrong-pubkey keypair");
    let wrong_der =
        nono::trust::signing::export_public_key(&wrong_kp).expect("export wrong pubkey DER");
    let wrong_pub_path = home.join("audit-pubkey-wrong.pem");
    fs::write(&wrong_pub_path, wrong_der.to_pem()).expect("write wrong pub PEM");
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

    // POSITIVE VERIFY: correct public key -> exit 0; JSON shape matches
    // the actual `audit verify --json` output (cmd_verify in audit_commands.rs:634).
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
    assert_eq!(json["integrity"]["records_verified"], true);
    assert_eq!(json["integrity"]["chain_head_matches"], true);
    assert_eq!(json["integrity"]["merkle_root_matches"], true);
    assert_eq!(json["integrity"]["event_count_matches"], true);
    assert_eq!(json["attestation_present"], true);
    assert_eq!(json["attestation_valid"], true);
}

#[test]
fn rollback_signed_session_verifies_from_audit_dir_bundle() {
    let (_tmp, home, workspace) = setup_isolated_home();
    fs::write(workspace.join("tracked.txt"), "before\n").expect("write tracked file");
    let key_path = generate_file_signing_key(&home, &workspace);
    let keyref = format!("file://{}", key_path.display());

    // Phase 27.1: use the cross-platform run_command_args() helper
    // (Unix `/bin/pwd` vs Windows `cmd /c echo nono-test`) instead of the
    // Unix-only `/bin/pwd`.
    let cmd_args = run_command_args();
    let mut args = vec![
        "run",
        "--audit-integrity",
        "--allow-cwd",
        "--rollback",
        "--no-rollback-prompt",
        "--audit-sign-key",
        &keyref,
        "--",
    ];
    args.extend(cmd_args.iter().copied());
    let run_output = run_nono(&args, &home, &workspace);
    assert_success(&run_output);

    let session_id = only_audit_session_id(&home);
    let audit_dir = home.join(".nono").join("audit").join(&session_id);
    let rollback_dir = home.join(".nono").join("rollbacks").join(&session_id);
    assert!(
        audit_dir.join("audit-attestation.bundle").exists(),
        "bundle should live in audit dir"
    );
    assert!(
        !rollback_dir.join("audit-attestation.bundle").exists(),
        "bundle should not be required in rollback dir"
    );

    let verify_output = run_nono(
        &["audit", "verify", &session_id, "--json"],
        &home,
        &workspace,
    );
    assert_success(&verify_output);

    let json: Value = serde_json::from_slice(&verify_output.stdout).expect("parse verify json");
    // Phase 27.2 D-27.2-08 (closes Phase 27.1 REVIEW WR-04): cmd_verify
    // emits a flat JSON shape (`attestation_present`, `attestation_valid`)
    // per audit_commands.rs:634-639. The richer nested shape (
    // `json["attestation"]["signature_verified"]` etc.) is deferred to
    // v2.5-FU-2 (cmd_verify v2 JSON schema) per
    // .planning/phases/27.1-nono-test-home-seam/deferred-items.md
    // § "Phase 27.2 v2.5 production follow-ups". Production JSON shape is
    // NOT changed in Phase 27.2; only the test assertion is corrected to
    // match the existing flat output.
    assert_eq!(json["attestation_present"], true);
    assert_eq!(json["attestation_valid"], true);
    // TODO(v2.5-FU-2): when cmd_verify ships the v2 nested schema, restore
    // assertions on signature_verified, merkle_root_matches,
    // session_id_matches, verification_error.
}

// ---------------------------------------------------------------------------
// Phase 27.2 BLOCKER regression tests (added 2026-05-09 by validation pass)
// ---------------------------------------------------------------------------
//
// The two BLOCKERs below were surfaced by 27.2-REVIEW.md and resolved
// inline by orchestrator commit 6e3a158f (`fix(27.2-CR): close BL-01 +
// BL-02 from code review`). The existing pre-fix tests
// (audit_verify_reports_signed_attestation_with_pinned_public_key and
// rollback_signed_session_verifies_from_audit_dir_bundle) DO NOT cover
// the BL-01/BL-02 surfaces because:
//
//   * Test 1 is audit-only (no `--rollback`), so finalize_supervised_exit
//     takes the audit-only branch (line 685+ in rollback_runtime.rs) which
//     has always written session.json directly to audit_state.session_dir.
//
//   * Test 2 uses `--allow-cwd`, which (per derive_tracked_paths in
//     rollback_runtime.rs:294-304) does NOT register as a User-source
//     Write|ReadWrite capability — so initialize_rollback_state returns
//     (None, Skipped), no snapshot is captured, and finalize_supervised_exit
//     also takes the audit-only branch. The combo (`--rollback`) flag is
//     set but the rollback-active code path is short-circuited.
//
// To exercise the BL-01 mirror block (rollback_runtime.rs:658-671) and the
// BL-02 canonical-rollback-root helper call (rollback_runtime.rs:244-252),
// these tests pass an explicit `--allow <writable_dir>` to make
// derive_tracked_paths return non-empty. That triggers
// initialize_rollback_state to capture a snapshot AND finalize_supervised_exit
// to take the rollback path (line 633+) which writes session.json to the
// rollback dir, then post-fix mirrors it to the audit dir.
//
// A future revert of either fix would silently regress both verify-
// correctness (`nono audit verify`) and rollback discoverability
// (`nono rollback list`) for combo sessions. These tests catch that.

/// REGRESSION TEST FOR BL-01 (REQ-AAHX-01):
///
/// Combo `--audit-integrity --rollback --allow <writable>` sessions write
/// session.json exclusively to the rollback dir BEFORE the post-review fix
/// at commit 6e3a158f. Without the mirror block at
/// rollback_runtime.rs:658-671, `audit_session::load_session` `?`-fails on
/// the missing audit-side session.json and `nono audit verify <id>`
/// returns "Session not found" instead of running verification.
///
/// This test fails closed (assert exit 0 from `nono audit verify`)
/// when the BL-01 mirror block is reverted or weakened.
#[test]
fn combo_rollback_audit_session_findable_by_audit_verify() {
    let (_tmp, home, workspace) = setup_isolated_home();

    // Reproduction recipe per 27.2-REVIEW.md §BL-01: the writable allow-dir
    // is what triggers derive_tracked_paths to return non-empty (the
    // strictly-writable User-source capability gate at
    // rollback_runtime.rs:294-304). Without it, `--rollback` short-circuits
    // to (None, Skipped) and finalize_supervised_exit takes the audit-only
    // branch — bypassing the BL-01 surface.
    //
    // The dir lives INSIDE the test's NONO_TEST_HOME tempdir so the
    // supervisor's canonicalize-then-starts_with path-traversal guard
    // accepts it.
    let writable_dir = home.join("workdir");
    fs::create_dir_all(&writable_dir).expect("create writable dir");
    let writable_str = writable_dir.to_str().expect("writable dir utf8");

    // Generate signing key so --audit-sign-key is satisfied. Reuses the
    // existing test helper (locked per D-27.2-13).
    let key_path = generate_file_signing_key(&home, &workspace);
    let keyref = format!("file://{}", key_path.display());

    // --no-rollback-prompt avoids the interactive review-and-restore TUI.
    // Reproduction recipe per 27.2-REVIEW.md §BL-01: BOTH `--allow-cwd`
    // (to whitelist the workspace as a valid launch directory for the
    // Windows execution-directory allowlist guard) AND
    // `--allow <writable_dir>` (to make derive_tracked_paths return
    // non-empty so the rollback-active code path runs end-to-end). With
    // only `--allow-cwd`, derive_tracked_paths is empty and finalize
    // takes the audit-only branch — bypassing the BL-01/BL-02 surfaces.
    let cmd_args = run_command_args();
    let mut args = vec![
        "run",
        "--audit-integrity",
        "--rollback",
        "--no-rollback-prompt",
        "--allow-cwd",
        "--allow",
        writable_str,
        "--audit-sign-key",
        &keyref,
        "--",
    ];
    args.extend(cmd_args.iter().copied());
    let run_output = run_nono(&args, &home, &workspace);
    assert_success(&run_output);

    // Resolve session id from audit dir (single-session per test).
    let session_id = only_audit_session_id(&home);
    let audit_session_dir = home.join(".nono").join("audit").join(&session_id);

    // STRUCTURAL ASSERTION: post-BL-01-fix, session.json is mirrored to
    // the audit dir. Pre-fix this file does NOT exist for combo sessions;
    // its presence is the structural signal that the mirror block ran.
    assert!(
        audit_session_dir.join("session.json").exists(),
        "BL-01 regression: session.json should be mirrored to audit dir at {:?} \
         for combo --audit-integrity --rollback sessions. Pre-fix, only the \
         rollback dir held session.json and `audit verify` returned \
         'Session not found'.",
        audit_session_dir.join("session.json"),
    );

    // BEHAVIORAL ASSERTION: `nono audit verify <id>` must succeed (exit 0)
    // and produce parseable JSON. Pre-fix, this fails with stderr
    // containing "Session not found: Failed to read session metadata
    // .../audit/<id>/session.json".
    let verify_output = run_nono(
        &["audit", "verify", &session_id, "--json"],
        &home,
        &workspace,
    );
    assert!(
        verify_output.status.success(),
        "BL-01 regression: `nono audit verify {}` should succeed for combo \
         --audit-integrity --rollback session. Pre-fix this failed with \
         'Session not found'. stderr: {}, stdout: {}",
        session_id,
        String::from_utf8_lossy(&verify_output.stderr),
        String::from_utf8_lossy(&verify_output.stdout),
    );

    let json: Value = serde_json::from_slice(&verify_output.stdout).expect("parse verify json");
    assert_eq!(
        json["attestation_present"], true,
        "verify output should report attestation_present=true; full json: {json}",
    );
    assert_eq!(
        json["attestation_valid"], true,
        "verify output should report attestation_valid=true; full json: {json}",
    );
}

/// REGRESSION TEST FOR BL-02 (REQ-AAHX-02):
///
/// Combo session's rollback dir was inlined to
/// `nono_home_dir().join(".nono").join("rollbacks")` BEFORE the post-review
/// fix at commit 6e3a158f. On Windows production this resolves to
/// %USERPROFILE% but the canonical `rollback_session::rollback_root()`
/// returns %LOCALAPPDATA% — so `nono rollback list` / `restore` cannot
/// see combo sessions on Windows. Post-fix, `create_audit_state` calls
/// `audit_session::ensure_rollback_session_dir(...)` which uses the
/// canonical helper, so combo sessions land where rollback discovery
/// expects them.
///
/// Under NONO_TEST_HOME, `nono_home_dir()` and `rollback_session::rollback_root()`
/// both honor the override and resolve to the same root, so the divergence
/// is masked at the path level. The structural regression-prevention is
/// that `nono rollback list --json` MUST surface combo sessions; a future
/// revert to inlined `nono_home_dir()` derivation would break BOTH
/// audit verify (BL-01) AND rollback list (this test). This test catches
/// the rollback list breakage end-to-end.
#[test]
fn combo_rollback_audit_session_findable_by_rollback_list() {
    let (_tmp, home, workspace) = setup_isolated_home();

    // Same combo-session shape as combo_rollback_audit_session_findable_by_audit_verify:
    // explicit `--allow <writable>` to drive derive_tracked_paths non-empty
    // and trigger the rollback-active code path that the BL-02 helper call
    // governs.
    let writable_dir = home.join("workdir");
    fs::create_dir_all(&writable_dir).expect("create writable dir");
    let writable_str = writable_dir.to_str().expect("writable dir utf8");

    let key_path = generate_file_signing_key(&home, &workspace);
    let keyref = format!("file://{}", key_path.display());

    // Touch a file inside the writable dir so the rollback baseline has
    // something to track (mirrors rollback_signed_session_verifies_from_audit_dir_bundle's
    // `tracked.txt` shape, but inside the --allow target).
    fs::write(writable_dir.join("tracked.txt"), "before\n").expect("write tracked file");

    // Reproduction recipe per 27.2-REVIEW.md §BL-01: BOTH `--allow-cwd`
    // (to whitelist the workspace as a valid launch directory for the
    // Windows execution-directory allowlist guard) AND
    // `--allow <writable_dir>` (to make derive_tracked_paths return
    // non-empty so the rollback-active code path runs end-to-end). With
    // only `--allow-cwd`, derive_tracked_paths is empty and finalize
    // takes the audit-only branch — bypassing the BL-01/BL-02 surfaces.
    let cmd_args = run_command_args();
    let mut args = vec![
        "run",
        "--audit-integrity",
        "--rollback",
        "--no-rollback-prompt",
        "--allow-cwd",
        "--allow",
        writable_str,
        "--audit-sign-key",
        &keyref,
        "--",
    ];
    args.extend(cmd_args.iter().copied());
    let run_output = run_nono(&args, &home, &workspace);
    assert_success(&run_output);

    let session_id = only_audit_session_id(&home);

    // BEHAVIORAL ASSERTION: `nono rollback list --json --all` must include
    // the session id in its output. The `--all` flag suppresses the
    // "filter to only sessions with actual changes" gate so we don't
    // depend on whether the cmd-args produce a real diff.
    //
    // Pre-fix, on Windows production, the rollback discovery helper would
    // not find the session because it lived at %USERPROFILE%\.nono\rollbacks\<id>
    // while discover_sessions reads from %LOCALAPPDATA%\nono\rollbacks. Under
    // NONO_TEST_HOME this divergence is masked, but a future revert to
    // inlined nono_home_dir() derivation would still break this test on
    // Windows production AND break the audit verify path
    // (combo_rollback_audit_session_findable_by_audit_verify).
    let list_output = run_nono(&["rollback", "list", "--all", "--json"], &home, &workspace);
    assert!(
        list_output.status.success(),
        "BL-02 regression: `nono rollback list --all --json` should succeed. \
         stderr: {}, stdout: {}",
        String::from_utf8_lossy(&list_output.stderr),
        String::from_utf8_lossy(&list_output.stdout),
    );

    let list_json: Value =
        serde_json::from_slice(&list_output.stdout).expect("parse rollback list json");
    let entries = list_json
        .as_array()
        .expect("rollback list json is an array");
    let session_ids: Vec<&str> = entries
        .iter()
        .filter_map(|entry| entry["session_id"].as_str())
        .collect();
    assert!(
        session_ids.contains(&session_id.as_str()),
        "BL-02 regression: combo --audit-integrity --rollback session id {} \
         should appear in `nono rollback list --all --json` output but did \
         not. Pre-fix, the create_audit_state helper used \
         `nono_home_dir().join(\".nono\").join(\"rollbacks\")` while \
         rollback_session::rollback_root() (the canonical helper used by \
         discover_sessions) used `user_state_dir().join(\"rollbacks\")` — \
         on Windows production those diverge to %USERPROFILE% vs \
         %LOCALAPPDATA%. session_ids returned: {:?}, full output: {}",
        session_id,
        session_ids,
        String::from_utf8_lossy(&list_output.stdout),
    );
}
