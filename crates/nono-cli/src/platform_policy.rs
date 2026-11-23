//! Fetch policy once per launch; cached state is for discovery, never offline authority.
pub(crate) mod display;
pub(crate) mod enforced;
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
    response: Option<PolicyRefreshResponse>,
}

fn policy_sources(
    policy: &AssignedBundle,
    root: &PolicyTrustRoot,
) -> Result<profile::bundle::PolicySources> {
    let bundle = policy
        .bundle
        .as_ref()
        .ok_or_else(|| NonoError::ConfigParse("missing signed bundle".into()))?;
    profile::bundle::files::verify(bundle, root, &policy.content_digest, policy.revision)
}

#[derive(Debug)]
enum RefreshFailure {
    Unauthorized(String),
    Unavailable(String),
    ServiceUnavailable(String),
    Invalid(String),
}

impl RefreshFailure {
    fn allows_local_fallback(
        &self,
        explicit_local: bool,
        previous: Option<&AssignmentClaims>,
        remembered_mode: Option<&str>,
    ) -> bool {
        if remembered_mode == Some("enforced")
            || previous.is_some_and(|policy| policy.management_mode == "enforced")
        {
            return false;
        }
        let mode =
            remembered_mode.or_else(|| previous.map(|policy| policy.management_mode.as_str()));
        if !matches!(mode, Some("audit_only" | "advisory")) {
            return false;
        }
        match self {
            Self::Unavailable(_) => {
                explicit_local
                    || (remembered_mode != Some("advisory")
                        && (remembered_mode == Some("audit_only")
                            || previous
                                .is_some_and(|policy| policy.management_mode == "audit_only")))
            }
            Self::ServiceUnavailable(_) => explicit_local,
            Self::Invalid(_) | Self::Unauthorized(_) => false,
        }
    }

    fn error(self) -> NonoError {
        let message = match self {
            Self::Unauthorized(message) => format!(
                "{message}; device authentication was refused. Run `nono platform re-enroll` to authorize recovery; the existing enrollment and policy remain in place."
            ),
            Self::Unavailable(message)
            | Self::ServiceUnavailable(message)
            | Self::Invalid(message) => message,
        };
        NonoError::ActionRequired(format!("platform policy: {message}"))
    }
}

impl From<NonoError> for RefreshFailure {
    fn from(error: NonoError) -> Self {
        Self::Invalid(error_reason(error))
    }
}

fn error_reason(error: NonoError) -> String {
    match error {
        NonoError::ConfigParse(message) | NonoError::ActionRequired(message) => message,
        other => other.to_string(),
    }
}

fn state_path(state: &PlatformState) -> Result<PathBuf> {
    let scope = serde_json::to_vec(&(&state.platform_url, &state.tenant_id, &state.subject_id))
        .map_err(|error| NonoError::ConfigParse(error.to_string()))?;
    Ok(crate::state_paths::user_state_dir()?
        .join("platform-policy")
        .join(format!("{}.json", platform_client::sha256_hex(&scope))))
}

fn load_record(state: &PlatformState) -> Result<CachedPolicy> {
    match std::fs::read(state_path(state)?) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
            NonoError::ConfigParse(format!("invalid cached platform policy: {error}"))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(CachedPolicy::default()),
        Err(error) => Err(NonoError::ConfigParse(format!(
            "cannot read cached platform policy: {error}"
        ))),
    }
}

fn load(state: &PlatformState) -> Result<CachedPolicy> {
    let mut cache = load_record(state)?;
    hydrate_cache(state, &mut cache)?;
    Ok(cache)
}

fn hydrate_cache(state: &PlatformState, cache: &mut CachedPolicy) -> Result<()> {
    if let Some(response) = &cache.response {
        let payload = URL_SAFE_NO_PAD
            .decode(&response.payload)
            .map_err(|error| NonoError::ConfigParse(error.to_string()))?;
        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|error| NonoError::ConfigParse(error.to_string()))?;
        if claims["protocol_version"].as_str() != Some(PROTOCOL) {
            tracing::debug!(
                "Discarding obsolete cached assignment; a fresh verified assignment is required"
            );
            cache.response = None;
        }
    }
    if let Some(response) = &mut cache.response
        && let Some(bundle) = &response.bundle
    {
        let claims: AssignmentClaims = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&response.payload)
                .map_err(|e| NonoError::ConfigParse(e.to_string()))?,
        )
        .map_err(|e| NonoError::ConfigParse(e.to_string()))?;
        let policy = claims
            .policy
            .ok_or_else(|| NonoError::ConfigParse("cached bundle has no assignment".into()))?;
        let directory = profile::bundle::files::cache_path(
            &state_path(state)?.with_extension(""),
            bundle,
            &policy.content_digest,
            policy.revision,
        )?;
        let stored = profile::bundle::files::read_directory(&directory)?;
        if stored.signature != bundle.signature {
            tracing::debug!(file = "bundle.sig", directory = ?directory, "Cached signature differs from the recorded platform bundle signature");
            return Err(NonoError::ConfigParse(format!(
                "bundle verification failed: cached signature file {:?} differs from the recorded platform bundle signature",
                directory.join("bundle.sig")
            )));
        }
        response.bundle = Some(stored);
    }
    Ok(())
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
    response: &PolicyRefreshResponse,
    root: &PolicyTrustRoot,
    state: &PlatformState,
    request_id: Option<&str>,
) -> Result<AssignmentClaims> {
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
    let mut claims: AssignmentClaims = serde_json::from_slice(&bytes)
        .map_err(|error| NonoError::ConfigParse(format!("invalid policy claims: {error}")))?;
    let invalid = |reason: &str| NonoError::ConfigParse(reason.into());
    if claims.protocol_version != PROTOCOL {
        return Err(invalid(
            "platform assignment uses an unsupported delivery protocol; expected v2",
        ));
    }
    if claims.tenant_id != state.tenant_id {
        return Err(invalid("platform assignment belongs to a different tenant"));
    }
    if claims.subject_id != state.subject_id {
        return Err(invalid(
            "platform assignment belongs to a different device or workload",
        ));
    }
    if let Some(id) = request_id {
        if claims.request_id != id {
            return Err(invalid(
                "platform assignment answers a different request; possible replay",
            ));
        }
        if Utc::now()
            .timestamp_millis()
            .abs_diff(claims.issued_at.timestamp_millis())
            > 300_000
        {
            return Err(invalid(
                "platform assignment is outside the five-minute freshness window; check the device clock and retry",
            ));
        }
    }
    match claims.management_mode.as_str() {
        "audit_only" if claims.policy.is_none() => {}
        "advisory" | "enforced" if claims.policy.is_some() => {}
        _ => {
            return Err(NonoError::ConfigParse(
                "unsupported platform management mode or policy shape".into(),
            ));
        }
    }
    if response.bundle.is_some() && claims.policy.is_none() {
        return Err(NonoError::ConfigParse("unexpected file bundle".into()));
    }
    if let Some(policy) = &mut claims.policy {
        policy.bundle = response.bundle.clone();
    }
    if let Some(policy) = &claims.policy {
        policy_sources(policy, root)?;
    }
    Ok(claims)
}

fn request<T: serde::de::DeserializeOwned>(
    state: &PlatformState,
    method: &str,
    path: &str,
    body: &[u8],
    id: Uuid,
) -> std::result::Result<T, RefreshFailure> {
    tracing::debug!(method, endpoint = path, request_id = %id, "Requesting platform policy");
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
    tracing::debug!(endpoint = path, request_id = %id, status = response.status().as_u16(), "Received platform policy response");
    if !response.status().is_success() {
        let message = format!("policy endpoint returned HTTP {}", response.status());
        if response.status().as_u16() == 401 {
            return Err(RefreshFailure::Unauthorized(message));
        }
        return Err(
            if response.status().is_server_error()
                || matches!(response.status().as_u16(), 404 | 408 | 429)
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
        .limit(profile::bundle::files::MAX_RESPONSE_BYTES)
        .read_to_vec()
        .map_err(|error| RefreshFailure::Invalid(error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| RefreshFailure::Invalid(format!("invalid policy response: {error}")))
}

fn refresh_inner(
    state: &PlatformState,
    repair: bool,
) -> std::result::Result<Option<AssignmentClaims>, RefreshFailure> {
    let mut cache = if repair {
        load_record(state)?
    } else {
        load(state)?
    };
    if cache.trust_root.is_none() {
        // Existing audit-only enrollments bootstrap over their authenticated TLS connection.
        let root = request::<PolicyTrustRoot>(state, "GET", TRUST_PATH, &[], Uuid::new_v4())?;
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
    let mut response = request::<PolicyRefreshResponse>(state, "POST", REFRESH_PATH, &body, id)?;
    let root = cache
        .trust_root
        .as_ref()
        .ok_or_else(|| RefreshFailure::Invalid("missing policy trust root".into()))?;
    let claims = verify(&response, root, state, Some(&id.to_string()))?;
    tracing::info!(mode = ?claims.management_mode, revision = claims.policy.as_ref().map(|policy| policy.revision), "Verified fresh platform policy assignment");
    if let (Some(policy), Some(bundle)) = (&claims.policy, &mut response.bundle) {
        let directory = profile::bundle::files::cache_path(
            &state_path(state)?.with_extension(""),
            bundle,
            &policy.content_digest,
            policy.revision,
        )?;
        if !directory.exists()
            && let Err(error) = profile::bundle::files::write_directory(&directory, bundle)
            && !repair
            && !directory.exists()
        {
            return Err(error.into());
        }
        let read_verified = || -> Result<SignedBundle> {
            let stored = profile::bundle::files::read_directory(&directory)?;
            profile::bundle::files::verify(&stored, root, &policy.content_digest, policy.revision)?;
            Ok(stored)
        };
        let stored = match read_verified() {
            Ok(stored) => stored,
            Err(_) if repair => {
                tracing::warn!(directory = ?directory, "Replacing damaged policy cache with a freshly verified platform bundle");
                profile::bundle::files::replace_directory(&directory, bundle)?;
                read_verified()?
            }
            Err(error) => return Err(error.into()),
        };
        bundle.signature = stored.signature;
        bundle.files.clear();
    }
    // Keep the last verified mode outside the disposable bundle cache.
    platform_client::remember_policy_mode(state, &claims.management_mode)?;
    cache.response = Some(response);
    platform_client::write_json_secure(&state_path(state)?, &cache)?;
    Ok(Some(claims))
}

pub(crate) fn refresh(state: &PlatformState) -> Result<Option<AssignmentClaims>> {
    refresh_inner(state, true).map_err(RefreshFailure::error)
}

pub(crate) fn cached(state: &PlatformState) -> Result<Option<AssignmentClaims>> {
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
    prepare_start_inner(args, silent).map_err(|error| {
        tracing::error!(
            stage = "platform_policy_startup",
            "Platform policy startup rejected; session not started"
        );
        let reason = error_reason(error);
        let reason = reason.strip_prefix("platform policy: ").unwrap_or(&reason);
        NonoError::ActionRequired(format!(
            "platform policy startup failed: {reason}\nSession not started."
        ))
    })
}

fn prepare_start_inner(args: &mut SandboxArgs, silent: bool) -> Result<()> {
    let Some(state) = platform_client::load_policy_state()? else {
        return Ok(());
    };
    let local_override = args.profile.is_some() || args.config.is_some();
    let previous = cached(&state)?;
    let remembered_mode = platform_client::last_policy_mode(&state)?;
    let claims = match refresh_inner(&state, false) {
        Ok(claims) => claims,
        Err(error)
            if error.allows_local_fallback(
                local_override,
                previous.as_ref(),
                remembered_mode.as_deref(),
            ) =>
        {
            tracing::debug!(
                explicit_local = local_override,
                "Platform unavailable; using permitted local policy fallback"
            );
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
        assigned_name: selected
            .filter(|claims| claims.policy.is_some())
            .and_then(display::assigned_name),
        assigned_revision: assigned.map(|p| p.revision),
        assigned_digest: assigned.map(|p| p.content_digest.clone()),
        policy_source: "local".into(),
        effective_profile_digest: None,
        overrides: args.policy_inputs.keys().cloned().collect(),
        override_sources: args.policy_inputs.clone(),
    };
    if mode == "enforced" {
        enforced::validate_inputs(args)?;
    }
    if mode == "enforced" || (mode == "advisory" && !local_override) {
        let policy = claims.as_ref().and_then(|c| c.policy.as_ref()).ok_or_else(|| NonoError::ActionRequired("platform policy could not be refreshed; explicitly choose --profile to run locally".into()))?;
        let root = load(&state)?
            .trust_root
            .ok_or_else(|| NonoError::ConfigParse("missing policy trust root".into()))?;
        let loaded =
            profile::bundle::ManagedProfile::from_sources(&policy_sources(policy, &root)?)?;
        if mode == "enforced" {
            enforced::validate_profile(&loaded.profile, &state)?;
        }
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
        signature::{
            ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
        },
    };
    use base64::engine::general_purpose::STANDARD;
    use serde_json::{Value, json};

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

    fn fixture() -> (PolicyTrustRoot, PolicyRefreshResponse) {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/nono-bundle-v1.json"))
                .expect("fixture");
        (
            serde_json::from_value(fixture["trust_root"].clone()).expect("root"),
            serde_json::from_value(fixture["response"].clone()).expect("response"),
        )
    }

    pub(super) fn claims() -> AssignmentClaims {
        let (_, response) = fixture();
        let mut claims: AssignmentClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(response.payload).expect("payload"))
                .expect("claims");
        claims.issued_at = Utc::now();
        claims.policy.as_mut().expect("policy").bundle = response.bundle;
        claims
    }

    fn signed(claims: &AssignmentClaims) -> (PolicyTrustRoot, PolicyRefreshResponse) {
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
        let mut bundle = claims
            .policy
            .as_ref()
            .and_then(|policy| policy.bundle.clone());
        if let Some(bundle) = &mut bundle {
            let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
                .expect("bundle key");
            let payload = STANDARD
                .decode(
                    bundle.signature["dsseEnvelope"]["payload"]
                        .as_str()
                        .expect("payload"),
                )
                .expect("base64");
            let signature = key
                .sign(
                    &rng,
                    &nono::trust::pae(nono::trust::IN_TOTO_PAYLOAD_TYPE, &payload),
                )
                .expect("signature");
            bundle.signature["verificationMaterial"]["publicKey"]["hint"] = json!(root.key_id);
            bundle.signature["dsseEnvelope"]["signatures"] =
                json!([{"sig":STANDARD.encode(signature.as_ref())}]);
        }
        let bytes = serde_json::to_vec(claims).expect("claims");
        let signature = key.sign(&rng, &bytes).expect("signature");
        let response = PolicyRefreshResponse {
            algorithm: root.algorithm.clone(),
            key_id: root.key_id.clone(),
            payload: URL_SAFE_NO_PAD.encode(bytes),
            signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
            bundle,
        };
        (root, response)
    }

    #[test]
    fn canonical_bundle_fixture_preserves_device_paths_and_grants() {
        let (root, response) = fixture();
        let accepted = verify(&response, &root, &state(), None).expect("verified");
        let policy = accepted.policy.expect("policy");
        assert_eq!(display::policy_name(&policy), "Engineering");
        let sources = policy_sources(&policy, &root).expect("sources");
        let loaded = profile::bundle::ManagedProfile::from_sources(&sources).expect("profile");
        assert!(
            serde_json::to_string(&loaded.profile)
                .expect("profile")
                .contains("$HOME/shared.txt")
        );
    }

    #[test]
    fn signature_binding_and_freshness_fail_closed() {
        let (root, response) = signed(&claims());
        assert!(verify(&response, &root, &state(), Some("request-a")).is_ok());
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
    fn missing_bundles_unsupported_modes_and_legacy_documents_fail_closed() {
        for mode in ["unknown", "audit_only"] {
            let mut value = claims();
            value.management_mode = mode.into();
            let (root, response) = signed(&value);
            assert!(
                verify(&response, &root, &state(), Some("request-a")).is_err(),
                "{mode}"
            );
        }
        let mut value = claims();
        value.management_mode = "enforced".into();
        let (root, response) = signed(&value);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_ok());
        value.policy = None;
        let (root, response) = signed(&value);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_err());
        let mut value = claims();
        value.policy.as_mut().expect("policy").bundle = None;
        let (root, response) = signed(&value);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_err());
        let mut value = claims();
        value.protocol_version = "1".into();
        let (root, response) = signed(&value);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_err());
        let mut legacy = serde_json::to_value(claims()).expect("claims");
        legacy["policy"]["profile_json"] = json!("{}");
        assert!(serde_json::from_value::<AssignmentClaims>(legacy).is_err());
        let (root, mut response) = signed(&claims());
        response
            .bundle
            .as_mut()
            .expect("bundle")
            .files
            .insert("policy.json".into(), STANDARD.encode(b"{}"));
        assert!(verify(&response, &root, &state(), Some("request-a")).is_err());
        let mut local = claims();
        local.management_mode = "audit_only".into();
        local.policy = None;
        let (root, response) = signed(&local);
        assert!(verify(&response, &root, &state(), Some("request-a")).is_ok());
    }

    #[test]
    fn startup_fallback_distinguishes_offline_local_use_from_a_rejected_assignment() {
        let advisory = claims();
        let mut local = claims();
        local.management_mode = "audit_only".into();
        local.policy = None;
        let offline = RefreshFailure::Unavailable("offline".into());
        assert!(!offline.allows_local_fallback(false, None, None));
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
        let unauthorized = RefreshFailure::Unauthorized("HTTP 401".into());
        assert!(!unauthorized.allows_local_fallback(true, Some(&advisory), Some("advisory")));
        assert!(!unauthorized.allows_local_fallback(true, Some(&local), Some("audit_only")));
        let mut enforced = claims();
        enforced.management_mode = "enforced".into();
        for failure in [&offline, &service, &invalid, &unauthorized] {
            assert!(!failure.allows_local_fallback(true, None, None));
            assert!(!failure.allows_local_fallback(true, Some(&enforced), Some("advisory")));
            assert!(!failure.allows_local_fallback(true, Some(&advisory), Some("enforced")));
        }
    }
}
