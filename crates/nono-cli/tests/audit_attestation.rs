//! Integration tests for supervisor-side audit attestation.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn run_nono(args: &[&str], home: &Path, cwd: &Path) -> Output {
    nono_bin()
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .current_dir(cwd)
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
    let key_path = generate_file_signing_key(&home, &workspace);
    let keyref = format!("file://{}", key_path.display());

    let run_output = run_nono(
        &[
            "run",
            "--allow-cwd",
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
    let pub_key_path = format!("{}", pub_key_path_for_file(&key_path).display());
    let verify_output = run_nono(
        &[
            "audit",
            "verify",
            &session_id,
            "--public-key-file",
            &pub_key_path,
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
    assert_eq!(json["attestation"]["key_id_matches"], true);
    assert_eq!(json["attestation"]["expected_public_key_matches"], true);
    assert_eq!(json["attestation"]["verification_error"], Value::Null);
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
