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
        .env("XDG_CONFIG_HOME", home.join(".config"));
    // Phase 27 Path B fix: on Windows, `dirs::home_dir()` resolves through
    // `USERPROFILE` (or `HOMEDRIVE`+`HOMEPATH`), NOT `HOME`. Without this
    // override the supervisor writes audit data to the real user profile
    // (`%USERPROFILE%\.nono\audit\...`), defeating test isolation. Setting
    // `USERPROFILE` to the test home redirects `dirs::home_dir()` to the
    // temp dir on Windows. No-op on Unix where the helper already covers
    // this via `HOME`.
    #[cfg(target_os = "windows")]
    {
        // Phase 27 Path B: on Windows, `dirs::home_dir()` resolves through
        // Windows API (`SHGetKnownFolderPath(FOLDERID_Profile)`) and IGNORES
        // any `USERPROFILE` env override (dirs 6.0.0 + dirs-sys 0.5.0). Audit
        // sessions are therefore unconditionally written under the real user's
        // `%USERPROFILE%\.nono\audit\`. Overriding `LOCALAPPDATA`/`APPDATA`
        // would create a path-mismatch: the supervisor would write the audit
        // session under real %USERPROFILE% but read rollback/config dirs from
        // the test temp dir, causing "Session not found" during shutdown.
        //
        // The redesigned tests instead identify their session via a
        // set-difference snapshot of the real audit root (see
        // `audit_root_for_supervisor` + `new_session_id_after_run`). This
        // matches the established Windows-test convention (e.g.
        // env_vars.rs::windows_run_read_only_allowlist_blocks_runtime_write_attempt).
        let _ = home;
    }
    cmd.current_dir(cwd)
        .output()
        .expect("failed to run nono")
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
    fs::create_dir_all(home.join("AppData").join("Roaming"))
        .expect("create AppData\\Roaming dir");
    fs::create_dir_all(home.join("AppData").join("Local"))
        .expect("create AppData\\Local dir");
    // Phase 27 Path B: pre-create the Windows rollback root so the
    // supervisor's `nono run` startup canonicalization doesn't fail. The
    // path resolution uses `crate::config::user_state_dir()` ->
    // `%LOCALAPPDATA%\nono\rollbacks`. No-op on Unix.
    fs::create_dir_all(home.join("AppData").join("Local").join("nono").join("rollbacks"))
        .expect("create rollback root");
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
    if s.len() % 2 != 0 {
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

#[allow(dead_code)]
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

// Plan 22-05a Task 8 (upstream `9db06336`): the 188 LOC integration test
// fixture imports verbatim from upstream but exercises features that
// require upstream's full audit_ledger.rs + nono::trust::signing
// `sign_statement_bundle` API surface, neither of which are available in
// the fork's v2.1 baseline (Decision 5 deferred audit_ledger to 22-05b
// and the trust signing API rename was never landed in v2.1).
//
// In particular both fixtures call `nono trust keygen --keyref file://...`
// which produces a PKCS8-format signing key on disk; the upstream
// `--audit-sign-key file://...` path then loads that PKCS8 via a from_pkcs8
// constructor on KeyPair. The fork's sigstore-crypto 0.6.4 has no such
// constructor (only generate_ecdsa_p256), so the manual port in
// `crates/nono-cli/src/audit_attestation.rs` uses generate_signing_key
// per-session instead.
//
// The fixtures are kept verbatim under #[ignore] so the file ports cleanly
// (D-13 satisfied) and they can be unignored in 22-05b after the trust
// signing refactor (RESEARCH Contradiction #2 deferred-cleanly path).
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
    std::env::set_var(&env_var, &secret);
    let keyref = format!("env://{env_var}");

    // Snapshot existing audit sessions BEFORE running so we can identify
    // the new session as a set-difference. Required on Windows where the
    // supervisor writes to %USERPROFILE%\.nono\audit\ and other sessions
    // may already exist.
    let audit_root = audit_root_for_supervisor(&home);
    let before = audit_session_ids_snapshot(&audit_root);

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
    std::env::remove_var(&env_var);
    assert_success(&run_output);

    let session_id = new_session_id_after_run(&audit_root, &before);
    let session_dir = audit_root.join(&session_id);

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
    let session_json_bytes =
        fs::read(session_dir.join("session.json")).expect("read session.json");
    let session_json: Value =
        serde_json::from_slice(&session_json_bytes).expect("parse session.json");
    let pub_key_hex = session_json["audit_attestation"]["public_key"]
        .as_str()
        .expect("audit_attestation.public_key in session.json");
    let session_key_id = session_json["audit_attestation"]["key_id"]
        .as_str()
        .expect("audit_attestation.key_id in session.json");
    assert!(
        !pub_key_hex.is_empty() && pub_key_hex.len() % 2 == 0,
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
    let wrong_kp = nono::trust::signing::generate_signing_key()
        .expect("generate wrong-pubkey keypair");
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
    let json: Value =
        serde_json::from_slice(&verify_output.stdout).expect("parse verify json");
    assert_eq!(json["integrity"]["records_verified"], true);
    assert_eq!(json["integrity"]["chain_head_matches"], true);
    assert_eq!(json["integrity"]["merkle_root_matches"], true);
    assert_eq!(json["integrity"]["event_count_matches"], true);
    assert_eq!(json["attestation_present"], true);
    assert_eq!(json["attestation_valid"], true);
}

// See note above on `audit_verify_reports_signed_attestation_with_pinned_public_key`:
// same upstream-feature-gap rationale; unignore in Plan 22-05b once the
// trust-signing refactor lands.
#[test]
fn rollback_signed_session_verifies_from_audit_dir_bundle() {
    let (_tmp, home, workspace) = setup_isolated_home();
    fs::write(workspace.join("tracked.txt"), "before\n").expect("write tracked file");
    let key_path = generate_file_signing_key(&home, &workspace);
    let keyref = format!("file://{}", key_path.display());

    let run_output = run_nono(
        &[
            "run",
            "--allow-cwd",
            "--rollback",
            "--no-rollback-prompt",
            "--audit-sign-key",
            &keyref,
            "--",
            "/bin/pwd",
        ],
        &home,
        &workspace,
    );
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
    assert_eq!(json["attestation"]["present"], true);
    assert_eq!(json["attestation"]["signature_verified"], true);
    assert_eq!(json["attestation"]["merkle_root_matches"], true);
    assert_eq!(json["attestation"]["session_id_matches"], true);
    assert_eq!(json["attestation"]["verification_error"], Value::Null);
}
