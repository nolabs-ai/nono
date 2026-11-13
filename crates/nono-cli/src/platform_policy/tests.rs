use super::*;
use crate::test_env::{ENV_LOCK, EnvVarGuard};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};

fn state() -> PlatformState {
    PlatformState {
        protocol_version: "1".into(),
        platform_url: "http://127.0.0.1:1".into(),
        tenant_id: Uuid::now_v7().to_string(),
        subject_id: Uuid::now_v7().to_string(),
        subject_kind: "device".into(),
        management_mode: "audit_only".into(),
        key_algorithm: platform_client::KEY_ALGORITHM.into(),
        key_ref: "unavailable-key".into(),
        enrolled_at: chrono::Utc::now().to_rfc3339(),
    }
}
fn key() -> EcdsaKeyPair {
    let bytes =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, bytes.as_ref()).unwrap()
}
fn claims(state: &PlatformState) -> PolicyClaims {
    PolicyClaims {
        protocol_version: "1".into(),
        tenant_id: state.tenant_id.clone(),
        subject_id: state.subject_id.clone(),
        request_id: Uuid::new_v4().to_string(),
        issued_at: chrono::Utc::now(),
        source: "implicit_default".into(),
        source_name: None,
        policy: None,
    }
}
fn sign(key: &EcdsaKeyPair, claims: &PolicyClaims) -> SignedPolicy {
    let payload = serde_json::to_vec(claims).unwrap();
    SignedPolicy {
        algorithm: platform_client::KEY_ALGORITHM.into(),
        key_id: format!(
            "sha256:{}",
            platform_client::sha256_hex(key.public_key().as_ref())
        ),
        public_key: URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
        payload: URL_SAFE_NO_PAD.encode(&payload),
        signature: URL_SAFE_NO_PAD
            .encode(key.sign(&SystemRandom::new(), &payload).unwrap().as_ref()),
    }
}

#[test]
fn shared_fixture_verifies_and_tampered_document_is_rejected() {
    let _guard = ENV_LOCK.lock().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _env = EnvVarGuard::set_all(&[("XDG_STATE_HOME", home.path().to_str().unwrap())]);
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/local-policy-v1.json"
    ))
    .unwrap();
    let mut signed: SignedPolicy = serde_json::from_value(fixture["signed"].clone()).unwrap();
    let mut state = state();
    state.tenant_id = fixture["claims"]["tenant_id"].as_str().unwrap().into();
    state.subject_id = fixture["claims"]["subject_id"].as_str().unwrap().into();
    assert_eq!(
        verify(&state, &signed, None)
            .unwrap()
            .policy
            .unwrap()
            .profile_id,
        "development"
    );
    let mut claims: PolicyClaims = serde_json::from_value(fixture["claims"].clone()).unwrap();
    claims.policy.as_mut().unwrap().profile_json = "{}".into();
    signed.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    assert!(verify(&state, &signed, None).is_err());
}

#[test]
fn signatures_context_nonce_freshness_and_digest_are_required() {
    let _guard = ENV_LOCK.lock().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _env = EnvVarGuard::set_all(&[("XDG_STATE_HOME", home.path().to_str().unwrap())]);
    let state = state();
    let key = key();
    let original = claims(&state);
    let id = Uuid::parse_str(&original.request_id).unwrap();
    assert!(
        verify(&state, &sign(&key, &original), Some(id))
            .unwrap()
            .policy
            .is_none()
    );
    for field in [
        "tenant",
        "subject",
        "nonce",
        "time",
        "version",
        "source",
        "missing_document",
    ] {
        let mut altered = original.clone();
        match field {
            "tenant" => altered.tenant_id = Uuid::now_v7().to_string(),
            "subject" => altered.subject_id = Uuid::now_v7().to_string(),
            "nonce" => altered.request_id = Uuid::new_v4().to_string(),
            "time" => altered.issued_at -= chrono::Duration::minutes(10),
            "version" => altered.protocol_version = "2".into(),
            "source" => altered.source = "unknown".into(),
            _ => altered.source = "group".into(),
        }
        assert!(
            verify(&state, &sign(&key, &altered), Some(id)).is_err(),
            "{field}"
        );
    }
    let mut assigned = original.clone();
    assigned.source = "group".into();
    assigned.policy = Some(crate::platform_policy_protocol::PolicyDocument {
        profile_id: "development".into(),
        display_name: None,
        revision: 1,
        content_digest: format!("sha256:{}", platform_client::sha256_hex(b"{}")),
        profile_json: "{}".into(),
    });
    assert!(verify(&state, &sign(&key, &assigned), Some(id)).is_ok());
    assigned.policy.as_mut().unwrap().profile_json = "{\"network\":{\"block\":false}}".into();
    assert!(verify(&state, &sign(&key, &assigned), Some(id)).is_err());
    let mut forged = sign(&key, &original);
    forged.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
    assert!(verify(&state, &forged, Some(id)).is_err());
    let mut forged = sign(&key, &original);
    forged.key_id = "sha256:wrong".into();
    assert!(verify(&state, &forged, Some(id)).is_err());
    platform_client::write_json_secure(&pin_path(&state).unwrap(), &"different-instance-key")
        .unwrap();
    assert!(
        verify(&state, &sign(&key, &original), Some(id))
            .unwrap_err()
            .to_string()
            .contains("signing key changed")
    );
}

#[test]
fn cache_is_scoped_verified_and_does_not_substitute_for_a_failed_sync() {
    let _guard = ENV_LOCK.lock().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _env = EnvVarGuard::set_all(&[("XDG_STATE_HOME", home.path().to_str().unwrap())]);
    let mut state = state();
    state.key_ref = format!("file://{}", home.path().join("device-key").display());
    platform_client::load_or_create_signing_key_for_ref(
        &crate::trust_keystore::TrustKeyRef::parse(&state.key_ref).unwrap(),
    )
    .unwrap();
    let key = key();
    let original = claims(&state);
    let signed = sign(&key, &original);
    platform_client::write_json_secure(&pin_path(&state).unwrap(), &signed.public_key).unwrap();
    platform_client::write_json_secure(
        &cache_path(&state).unwrap(),
        &Cache {
            platform_url: state.platform_url.clone(),
            signed: signed.clone(),
        },
    )
    .unwrap();
    assert!(cached(&state).unwrap().unwrap().policy.is_none());
    for other in [
        PlatformState {
            tenant_id: Uuid::now_v7().to_string(),
            ..state.clone()
        },
        PlatformState {
            subject_id: Uuid::now_v7().to_string(),
            ..state.clone()
        },
        PlatformState {
            platform_url: "https://other.example".into(),
            ..state.clone()
        },
    ] {
        assert!(cached(&other).unwrap().is_none());
    }
    let mut forged = signed.clone();
    forged.signature.clear();
    platform_client::write_json_secure(
        &cache_path(&state).unwrap(),
        &Cache {
            platform_url: state.platform_url.clone(),
            signed: forged,
        },
    )
    .unwrap();
    assert!(cached(&state).is_err());
    assert!(
        sync(&state)
            .unwrap_err()
            .to_string()
            .contains("cannot reach the platform")
    );
}

#[test]
fn explicit_profile_overrides_unreachable_platform_without_loading_device_key() {
    let _guard = ENV_LOCK.lock().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _env = EnvVarGuard::set_all(&[
        ("XDG_STATE_HOME", home.path().to_str().unwrap()),
        ("XDG_CONFIG_HOME", home.path().to_str().unwrap()),
    ]);
    let state = state();
    platform_client::write_json_secure(
        &crate::state_paths::user_state_dir()
            .unwrap()
            .join("platform.json"),
        &state,
    )
    .unwrap();
    let mut args = SandboxArgs {
        profile: Some("default".into()),
        ..SandboxArgs::default()
    };
    select_for_run(&mut args).unwrap();
    let loaded = crate::profile::load_profile_with_extends("default", &[]).unwrap();
    record_resolved(&mut args, &loaded).unwrap();
    let selection = args.policy_selection.unwrap();
    assert!(!format!("{selection:?}").contains(&state.key_ref));
    assert!(!selection.platform);
    assert_eq!(selection.provenance["source"], "explicit_profile");
    assert!(
        selection.provenance["resolved_profile_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(selection.enrollment.unwrap().subject_id, state.subject_id);
    assert_eq!(args.profile.as_deref(), Some("default"));
    assert!(!cache_path(&state).unwrap().exists());
}

#[test]
fn platform_profiles_cannot_introduce_host_session_hooks() {
    let mut profile = crate::profile::Profile::default();
    assert!(validate_host_behavior(&profile).is_ok());
    for before in [true, false] {
        profile.session_hooks = crate::profile::SessionHooks::default();
        let hook = Some(crate::profile::SessionHook {
            script: "/must-not-execute".into(),
            timeout_secs: None,
            source_pack: None,
        });
        if before {
            profile.session_hooks.before = hook;
        } else {
            profile.session_hooks.after = hook;
        }
        assert!(
            validate_host_behavior(&profile)
                .unwrap_err()
                .to_string()
                .contains("host session hooks")
        );
    }
}

#[test]
fn conditional_confirmation_requires_matching_verified_cached_content() {
    let _guard = ENV_LOCK.lock().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _env = EnvVarGuard::set_all(&[("XDG_STATE_HOME", home.path().to_str().unwrap())]);
    let state = state();
    let key = key();
    let mut assigned = claims(&state);
    assigned.source = "group".into();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/local-policy-v1.json"
    ))
    .unwrap();
    assigned.policy = Some(serde_json::from_value(fixture["claims"]["policy"].clone()).unwrap());
    let document = assigned.policy.as_ref().unwrap().profile_json.clone();
    assigned.policy.as_mut().unwrap().profile_json.clear();
    let signed = sign(&key, &assigned);
    let bytes = URL_SAFE_NO_PAD.decode(&signed.payload).unwrap();
    assert!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["policy"]
            .get("profile_json")
            .is_none()
    );
    let nonce = Uuid::parse_str(&assigned.request_id).unwrap();
    let confirmed = verify(&state, &signed, Some(nonce)).unwrap();
    for cached in [None, Some("{}"), Some("")] {
        assert!(complete_document(&mut confirmed.clone(), cached).is_err());
    }
    let mut restored = confirmed.clone();
    complete_document(&mut restored, Some(&document)).unwrap();
    assert_eq!(restored.policy.unwrap().profile_json, document);
    assert!(verify(&state, &signed, Some(Uuid::now_v7())).is_err());
    let mut malformed = assigned.clone();
    malformed.policy.as_mut().unwrap().content_digest = "invalid".into();
    assert!(verify(&state, &sign(&key, &malformed), Some(nonce)).is_err());
    platform_client::write_json_secure(&pin_path(&state).unwrap(), &signed.public_key).unwrap();
    platform_client::write_json_secure(
        &cache_path(&state).unwrap(),
        &Cache {
            platform_url: state.platform_url.clone(),
            signed,
        },
    )
    .unwrap();
    let path = document_path(&state, &assigned.policy.unwrap().content_digest).unwrap();
    platform_client::write_json_secure(&path, &document).unwrap();
    assert_eq!(
        cached(&state)
            .unwrap()
            .unwrap()
            .policy
            .unwrap()
            .profile_json,
        document
    );
    platform_client::write_json_secure(&path, &"tampered").unwrap();
    assert!(cached(&state).is_err());
    std::fs::remove_file(path).unwrap();
    assert!(cached(&state).is_err());
}
