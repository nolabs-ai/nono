//! Fetch policy once per launch; cached state is for discovery, never offline authority.
pub(crate) mod display;
pub(crate) mod inputs;
pub(crate) mod protocol;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use nono::{NonoError, Result};
use protocol::*;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

use crate::{
    cli::SandboxArgs,
    platform_client::{self, PlatformState},
    profile,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PolicySession {
    pub management_mode: String,
    pub assignment_version: String,
    pub assigned_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_name: Option<String>,
    pub assigned_revision: Option<i64>,
    pub assigned_digest: Option<String>,
    pub policy_source: String,
    pub effective_profile_digest: Option<String>,
    pub overrides: Vec<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub override_sources: inputs::PolicyInputs,
}

#[derive(Default, Serialize, Deserialize)]
struct CachedPolicy {
    trust_root: Option<PolicyTrustRoot>,
    response: Option<SignedPolicyResponse>,
}

#[derive(Debug)]
enum RefreshFailure {
    Unavailable(String),
    ServiceUnavailable(String),
    Invalid(String),
}

impl RefreshFailure {
    fn allows_local_fallback(
        &self,
        explicit_local: bool,
        previous: Option<&PolicyClaims>,
        remembered_mode: Option<&str>,
    ) -> bool {
        match self {
            Self::Unavailable(_) => {
                explicit_local
                    || (remembered_mode != Some("advisory")
                        && previous.is_none_or(|policy| policy.management_mode == "audit_only"))
            }
            Self::ServiceUnavailable(_) => explicit_local,
            Self::Invalid(_) => false,
        }
    }

    fn error(self) -> NonoError {
        let message = match self {
            Self::Unavailable(message)
            | Self::ServiceUnavailable(message)
            | Self::Invalid(message) => message,
        };
        NonoError::ActionRequired(format!("platform policy: {message}"))
    }
}

impl From<NonoError> for RefreshFailure {
    fn from(error: NonoError) -> Self {
        Self::Invalid(error.to_string())
    }
}

fn state_path(state: &PlatformState) -> Result<PathBuf> {
    let scope = serde_json::to_vec(&(&state.platform_url, &state.tenant_id, &state.subject_id))
        .map_err(|error| NonoError::ConfigParse(error.to_string()))?;
    Ok(crate::state_paths::user_state_dir()?
        .join("platform-policy")
        .join(format!("{}.json", platform_client::sha256_hex(&scope))))
}

fn load(state: &PlatformState) -> Result<CachedPolicy> {
    let path = state_path(state)?;
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
            NonoError::ConfigParse(format!("invalid cached platform policy: {error}"))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(CachedPolicy::default()),
        Err(error) => Err(NonoError::ConfigParse(format!(
            "cannot read cached platform policy: {error}"
        ))),
    }
}

fn validate_root(root: &PolicyTrustRoot) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&root.public_key)
        .map_err(|_| NonoError::ConfigParse("invalid policy public key".into()))?;
    if root.algorithm != platform_client::KEY_ALGORITHM
        || bytes.len() != 65
        || bytes[0] != 4
        || root.key_id != format!("sha256:{}", platform_client::sha256_hex(&bytes))
    {
        return Err(NonoError::ConfigParse("invalid policy trust root".into()));
    }
    Ok(())
}

pub(crate) fn pin_enrollment_key(
    state: &PlatformState,
    root: Option<PolicyTrustRoot>,
) -> Result<()> {
    if let Some(root) = root {
        validate_root(&root)?;
        let mut cache = load(state)?;
        if cache
            .trust_root
            .as_ref()
            .is_some_and(|old| old.public_key != root.public_key)
        {
            return Err(NonoError::ActionRequired(
                "platform policy signing key changed; re-enrolment is required".into(),
            ));
        }
        cache.trust_root = Some(root);
        platform_client::write_json_secure(&state_path(state)?, &cache)?;
    }
    Ok(())
}

fn verify(
    response: &SignedPolicyResponse,
    root: &PolicyTrustRoot,
    state: &PlatformState,
    request_id: Option<&str>,
) -> Result<PolicyClaims> {
    validate_root(root)?;
    if response.algorithm != root.algorithm || response.key_id != root.key_id {
        return Err(NonoError::ConfigParse(
            "untrusted policy signing key".into(),
        ));
    }
    let decode = |value: &str| {
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| NonoError::ConfigParse("invalid signed policy encoding".into()))
    };
    let bytes = decode(&response.payload)?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, decode(&root.public_key)?)
        .verify(&bytes, &decode(&response.signature)?)
        .map_err(|_| NonoError::ConfigParse("invalid platform policy signature".into()))?;
    let claims: PolicyClaims = serde_json::from_slice(&bytes)
        .map_err(|error| NonoError::ConfigParse(format!("invalid policy claims: {error}")))?;
    if claims.protocol_version != PROTOCOL
        || claims.tenant_id != state.tenant_id
        || claims.subject_id != state.subject_id
        || request_id.is_some_and(|id| {
            claims.request_id != id
                || Utc::now()
                    .timestamp_millis()
                    .abs_diff(claims.issued_at.timestamp_millis())
                    > 300_000
        })
    {
        return Err(NonoError::ConfigParse(
            "policy response does not match this device, request or freshness window".into(),
        ));
    }
    match claims.management_mode.as_str() {
        "audit_only" if claims.policy.is_none() => {}
        "advisory" if claims.policy.is_some() => {}
        _ => {
            return Err(NonoError::ConfigParse(
                "unsupported platform management mode or policy shape".into(),
            ));
        }
    }
    if let Some(policy) = &claims.policy {
        if policy.content_digest
            != format!(
                "sha256:{}",
                platform_client::sha256_hex(policy.profile_json.as_bytes())
            )
        {
            return Err(NonoError::ConfigParse(
                "platform policy digest mismatch".into(),
            ));
        }
        profile::bundle::parse_delivered(&policy.profile_json)?;
    }
    Ok(claims)
}

fn request<T: serde::de::DeserializeOwned>(
    state: &PlatformState,
    method: &str,
    path: &str,
    body: &[u8],
    id: Uuid,
) -> std::result::Result<Option<T>, RefreshFailure> {
    let url = platform_client::endpoint_url(&state.platform_url, path)?;
    let target =
        url::Url::parse(&url).map_err(|error| RefreshFailure::Invalid(error.to_string()))?;
    let signed = platform_client::sign_request_v1(state, method, target.path(), id, body)?;
    let agent = platform_client::http_agent(Duration::from_secs(15));
    let request = ureq::http::Request::builder()
        .method(method)
        .uri(&url)
        .header("x-nono-protocol-version", "1")
        .header("x-nono-subject-id", &state.subject_id)
        .header("x-nono-timestamp", &signed.timestamp)
        .header("x-nono-request-id", &signed.request_id)
        .header("x-nono-content-sha256", &signed.body_digest)
        .header("x-nono-signature", &signed.signature)
        .header("content-type", "application/json")
        .body(body)
        .map_err(|error| RefreshFailure::Invalid(error.to_string()))?;
    let request = agent
        .configure_request(request)
        .http_status_as_error(false)
        .max_redirects(0)
        .build();
    let mut response = agent
        .run(request)
        .map_err(|error| RefreshFailure::Unavailable(error.to_string()))?;
    if response.status().as_u16() == 404 {
        return Ok(None);
    }
    if !response.status().is_success() {
        let message = format!("policy endpoint returned HTTP {}", response.status());
        return Err(
            if response.status().is_server_error()
                || matches!(response.status().as_u16(), 408 | 429)
            {
                RefreshFailure::ServiceUnavailable(message)
            } else {
                RefreshFailure::Invalid(message)
            },
        );
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(2 * 1024 * 1024)
        .read_to_vec()
        .map_err(|error| RefreshFailure::Invalid(error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| RefreshFailure::Invalid(format!("invalid policy response: {error}")))
}

fn refresh_inner(
    state: &PlatformState,
    remembered_mode: Option<&str>,
) -> std::result::Result<Option<PolicyClaims>, RefreshFailure> {
    let mut cache = load(state)?;
    if cache.trust_root.is_none() {
        // Existing audit-only enrollments bootstrap over their authenticated TLS connection.
        let Some(root) = request::<PolicyTrustRoot>(state, "GET", TRUST_PATH, &[], Uuid::new_v4())?
        else {
            if remembered_mode == Some("advisory") {
                return Err(RefreshFailure::Unavailable(
                    "platform no longer supports managed policy".into(),
                ));
            }
            return Ok(None);
        };
        validate_root(&root)?;
        cache.trust_root = Some(root);
        platform_client::write_json_secure(&state_path(state)?, &cache)?;
    }
    let context = PolicyRefreshRequest {
        protocol_version: PROTOCOL.into(),
        platform: std::env::consts::OS.into(),
        home: std::env::var("HOME").unwrap_or_default(),
        workdir: std::env::current_dir()
            .map_err(|error| RefreshFailure::Invalid(error.to_string()))?
            .to_string_lossy()
            .into_owned(),
    };
    let body =
        serde_json::to_vec(&context).map_err(|error| RefreshFailure::Invalid(error.to_string()))?;
    let id = Uuid::new_v4();
    let Some(response) = request::<SignedPolicyResponse>(state, "POST", REFRESH_PATH, &body, id)?
    else {
        return if cache.response.is_some() || remembered_mode == Some("advisory") {
            Err(RefreshFailure::Unavailable(
                "platform no longer supports managed policy".into(),
            ))
        } else {
            Ok(None)
        };
    };
    let root = cache
        .trust_root
        .as_ref()
        .ok_or_else(|| RefreshFailure::Invalid("missing policy trust root".into()))?;
    let claims = verify(&response, root, state, Some(&id.to_string()))?;
    // Keep the last verified mode outside the disposable bundle cache.
    platform_client::remember_policy_mode(state, &claims.management_mode)?;
    cache.response = Some(response);
    platform_client::write_json_secure(&state_path(state)?, &cache)?;
    Ok(Some(claims))
}

pub(crate) fn refresh(state: &PlatformState) -> Result<Option<PolicyClaims>> {
    let remembered_mode = platform_client::last_policy_mode(state)?;
    refresh_inner(state, remembered_mode.as_deref()).map_err(RefreshFailure::error)
}

pub(crate) fn cached(state: &PlatformState) -> Result<Option<PolicyClaims>> {
    let cache = load(state)?;
    match (&cache.response, &cache.trust_root) {
        (Some(response), Some(root)) => verify(response, root, state, None).map(Some),
        (None, _) => Ok(None),
        _ => Err(NonoError::ConfigParse(
            "cached policy has no trust root".into(),
        )),
    }
}

pub(crate) fn with_effective_profile<T: Serialize>(
    session: Option<&PolicySession>,
    profile: Option<&T>,
) -> Result<Option<PolicySession>> {
    let Some(mut session) = session.cloned() else {
        return Ok(None);
    };
    session.effective_profile_digest = profile
        .map(|profile| -> Result<String> {
            let value = serde_json::to_value(profile)
                .map_err(|error| NonoError::ConfigParse(error.to_string()))?;
            let bytes = serde_json::to_vec(&value)
                .map_err(|error| NonoError::ConfigParse(error.to_string()))?;
            Ok(format!("sha256:{}", platform_client::sha256_hex(&bytes)))
        })
        .transpose()?;
    Ok(Some(session))
}

pub(crate) fn prepare_start(args: &mut SandboxArgs, silent: bool) -> Result<()> {
    let Some(state) = platform_client::load_active_state()? else {
        return Ok(());
    };
    let local_override = args.profile.is_some() || args.config.is_some();
    let previous = cached(&state)?;
    let remembered_mode = platform_client::last_policy_mode(&state)?;
    let claims = match refresh_inner(&state, remembered_mode.as_deref()) {
        Ok(claims) => claims,
        Err(error)
            if error.allows_local_fallback(
                local_override,
                previous.as_ref(),
                remembered_mode.as_deref(),
            ) =>
        {
            if !silent {
                eprintln!(
                    "{}; using explicit or previously local policy",
                    error.error()
                );
            }
            None
        }
        Err(error) => return Err(error.error()),
    };
    let selected = claims.as_ref().or(previous.as_ref());
    let Some(mode) = selected
        .map(|policy| policy.management_mode.as_str())
        .or(remembered_mode.as_deref())
    else {
        return Ok(());
    };
    let assigned = selected.and_then(|policy| policy.policy.as_ref());
    let mut session = PolicySession {
        management_mode: mode.into(),
        assignment_version: selected
            .map(|policy| policy.assignment_version.clone())
            .unwrap_or_else(|| "unknown".into()),
        assigned_profile: assigned.map(|p| p.profile_id.clone()),
        assigned_name: assigned.map(display::policy_name),
        assigned_revision: assigned.map(|p| p.revision),
        assigned_digest: assigned.map(|p| p.content_digest.clone()),
        policy_source: "local".into(),
        effective_profile_digest: None,
        overrides: args.policy_inputs.keys().cloned().collect(),
        override_sources: args.policy_inputs.clone(),
    };
    if mode == "advisory" && !local_override {
        let policy = claims.as_ref().and_then(|c| c.policy.as_ref()).ok_or_else(|| NonoError::ActionRequired("platform policy could not be refreshed; explicitly choose --profile to run locally".into()))?;
        let loaded = profile::bundle::ManagedProfile::parse(&policy.profile_json)?;
        session.policy_source = "platform".into();
        args.managed_profile = Some(loaded);
    }
    if !silent {
        eprint!("{}", display::session_summary(&session));
    }
    args.policy_session = Some(session);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
    };

    fn state() -> PlatformState {
        PlatformState {
            protocol_version: "1".into(),
            platform_url: "https://platform.example".into(),
            tenant_id: "tenant-a".into(),
            subject_id: "device-a".into(),
            subject_kind: "device".into(),
            management_mode: "audit_only".into(),
            key_algorithm: platform_client::KEY_ALGORITHM.into(),
            key_ref: "unused".into(),
            enrolled_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    pub(super) fn claims() -> PolicyClaims {
        let profile_json = r#"{"meta":{"name":"managed"},"filesystem":{"read":["$HOME/shared"]},"network":{"block":true}}"#.to_string();
        PolicyClaims {
            protocol_version: "1".into(),
            tenant_id: "tenant-a".into(),
            subject_id: "device-a".into(),
            request_id: "request-a".into(),
            issued_at: Utc::now(),
            management_mode: "advisory".into(),
            assignment_version: "assignment-a".into(),
            resolved_via: serde_json::json!({"layer":"group"}),
            policy: Some(DeliveredPolicy {
                profile_id: "managed".into(),
                revision: 7,
                delta_version: 0,
                content_digest: format!(
                    "sha256:{}",
                    platform_client::sha256_hex(profile_json.as_bytes())
                ),
                profile_json,
            }),
        }
    }

    fn signed(claims: &PolicyClaims) -> (PolicyTrustRoot, SignedPolicyResponse) {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("key");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("key");
        let root = PolicyTrustRoot {
            algorithm: platform_client::KEY_ALGORITHM.into(),
            key_id: format!(
                "sha256:{}",
                platform_client::sha256_hex(key.public_key().as_ref())
            ),
            public_key: URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
        };
        let bytes = serde_json::to_vec(claims).expect("claims");
        let signature = key.sign(&rng, &bytes).expect("signature");
        let response = SignedPolicyResponse {
            algorithm: root.algorithm.clone(),
            key_id: root.key_id.clone(),
            payload: URL_SAFE_NO_PAD.encode(bytes),
            signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
        };
        (root, response)
    }

    #[test]
    fn signed_policy_preserves_device_paths_and_grants() {
        let (root, response) = signed(&claims());
        let accepted = verify(&response, &root, &state(), Some("request-a")).expect("verified");
        assert!(
            accepted
                .policy
                .expect("policy")
                .profile_json
                .contains("$HOME/shared")
        );
    }

    #[test]
    fn signature_binding_and_freshness_fail_closed() {
        let (root, response) = signed(&claims());
        assert!(verify(&response, &root, &state(), Some("other-request")).is_err());
        let mut other = state();
        other.subject_id = "other-device".into();
        assert!(verify(&response, &root, &other, Some("request-a")).is_err());
        other = state();
        other.tenant_id = "other-tenant".into();
        assert!(verify(&response, &root, &other, Some("request-a")).is_err());
        let (unknown, _) = signed(&claims());
        assert!(verify(&response, &unknown, &state(), Some("request-a")).is_err());
        let mut tampered = response.clone();
        tampered.payload.push('a');
        assert!(verify(&tampered, &root, &state(), Some("request-a")).is_err());
        let mut stale = claims();
        stale.issued_at -= chrono::Duration::minutes(6);
        let (root, response) = signed(&stale);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_err());
    }

    #[test]
    fn unsupported_modes_missing_policy_and_modified_documents_fail_closed() {
        for mode in ["enforced", "unknown", "audit_only"] {
            let mut value = claims();
            value.management_mode = mode.into();
            let (root, response) = signed(&value);
            assert!(
                verify(&response, &root, &state(), Some("request-a")).is_err(),
                "{mode}"
            );
        }
        let mut value = claims();
        value.policy = None;
        let (root, response) = signed(&value);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_err());
        value = claims();
        value
            .policy
            .as_mut()
            .expect("policy")
            .profile_json
            .push(' ');
        let (root, response) = signed(&value);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_err());
        value = claims();
        value.management_mode = "audit_only".into();
        value.policy = None;
        let (root, response) = signed(&value);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_ok());
    }

    #[test]
    fn unresolved_inheritance_is_never_loaded_from_local_state() {
        let mut value = claims();
        let policy = value.policy.as_mut().expect("policy");
        policy.profile_json = r#"{"meta":{"name":"managed"},"extends":"default"}"#.into();
        policy.content_digest = format!(
            "sha256:{}",
            platform_client::sha256_hex(policy.profile_json.as_bytes())
        );
        let (root, response) = signed(&value);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_err());
    }

    #[test]
    fn shared_signature_fixture_verifies_with_the_pinned_key() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/managed-policy-v1.json"
        ))
        .expect("fixture");
        let root = serde_json::from_value(fixture["trust_root"].clone()).expect("trust root");
        let response = serde_json::from_value(fixture["response"].clone()).expect("response");
        let claims = verify(&response, &root, &state(), None).expect("stored signature");
        assert_eq!(claims.management_mode, "advisory");
        assert_eq!(claims.policy.expect("document").profile_id, "shared-policy");
    }
    #[test]
    fn startup_fallback_distinguishes_offline_local_use_from_a_rejected_assignment() {
        let advisory = claims();
        let mut local = claims();
        local.management_mode = "audit_only".into();
        local.policy = None;
        let offline = RefreshFailure::Unavailable("offline".into());
        assert!(offline.allows_local_fallback(false, None, None));
        assert!(offline.allows_local_fallback(false, Some(&local), None));
        assert!(!offline.allows_local_fallback(false, Some(&advisory), None));
        assert!(offline.allows_local_fallback(true, Some(&advisory), None));
        assert!(!offline.allows_local_fallback(false, None, Some("advisory")));
        assert!(!offline.allows_local_fallback(false, Some(&local), Some("advisory")));
        assert!(offline.allows_local_fallback(true, None, Some("advisory")));
        assert!(offline.allows_local_fallback(false, None, Some("audit_only")));
        let service = RefreshFailure::ServiceUnavailable("export unavailable".into());
        assert!(!service.allows_local_fallback(false, None, None));
        assert!(!service.allows_local_fallback(false, Some(&local), None));
        assert!(service.allows_local_fallback(true, Some(&advisory), None));
        let invalid = RefreshFailure::Invalid("invalid signature or assignment".into());
        assert!(!invalid.allows_local_fallback(true, Some(&advisory), Some("advisory")));
    }
}
