//! Integration tests for supervisor-side audit attestation.

use nono_test_support::{KeyRef, NonoTest, Rollback, nono_test};
use serde_json::Value;
use std::fs;

fn generate_file_signing_key(t: &NonoTest) -> KeyRef {
    let key = KeyRef::file(t.home().join("audit-signing-key.pk8.b64"));
    t.trust()
        .keygen(&key)
        .force()
        .output()
        .assert_success("trust keygen writes a file:// signing key");

    assert!(key.private_key_path().exists(), "private key should exist");
    assert!(key.public_key_path().exists(), "public key should exist");
    key
}

fn only_audit_session_id(t: &NonoTest) -> String {
    let mut session_ids: Vec<String> = fs::read_dir(t.audit_root())
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

#[test]
fn audit_verify_reports_signed_attestation_with_pinned_public_key() {
    let t = nono_test!("audit-attestation");
    let key = generate_file_signing_key(&t);

    t.run()
        .allow_cwd()
        .audit_sign_key(&key)
        .exec("/bin/pwd")
        .assert_success("a signed session runs to completion");

    let session_id = only_audit_session_id(&t);
    let json = t
        .audit()
        .verify(&session_id)
        .public_key_file(key.public_key_path())
        .json();

    assert_eq!(json["session"]["records_verified"], true);
    assert_eq!(json["ledger"]["session_digest_matches"], true);
    assert_eq!(json["ledger"]["ledger_chain_verified"], true);
    assert_eq!(json["attestation"]["present"], true);
    assert_eq!(json["attestation"]["signature_verified"], true);
    assert_eq!(json["attestation"]["key_id_matches"], true);
    assert_eq!(json["attestation"]["expected_public_key_matches"], true);
    assert_eq!(json["attestation"]["verification_error"], Value::Null);
}

#[test]
fn rollback_signed_session_verifies_from_audit_dir_bundle() {
    let t = nono_test!("audit-attestation-rollback");
    fs::write(t.workspace().join("tracked.txt"), "before\n").expect("write tracked file");
    let key = generate_file_signing_key(&t);

    t.run()
        .allow_cwd()
        .rollback(Rollback::new().no_prompt())
        .audit_sign_key(&key)
        .exec("/bin/pwd")
        .assert_success("a signed session with rollback runs to completion");

    let session_id = only_audit_session_id(&t);
    let audit_dir = t.audit_root().join(&session_id);
    let rollback_dir = t.state().join("nono").join("rollbacks").join(&session_id);
    assert!(
        audit_dir.join("audit-attestation.bundle").exists(),
        "bundle should live in audit dir"
    );
    assert!(
        !rollback_dir.join("audit-attestation.bundle").exists(),
        "bundle should not be required in rollback dir"
    );

    let json = t.audit().verify(&session_id).json();
    assert_eq!(json["attestation"]["present"], true);
    assert_eq!(json["attestation"]["signature_verified"], true);
    assert_eq!(json["attestation"]["merkle_root_matches"], true);
    assert_eq!(json["attestation"]["session_id_matches"], true);
    assert_eq!(json["attestation"]["verification_error"], Value::Null);
}
