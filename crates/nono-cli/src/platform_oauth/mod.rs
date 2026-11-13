//! OAuth 2.0 sign-in for the nono platform (NEP-0009, `cli-login-v1`).
//!
//! `nono platform login` signs a person in; the CLI is a public native client
//! (`client_id=nono-cli`). The session is a refresh token bound with DPoP to
//! a key the CLI generates for it, both kept in nono's protected state
//! directory. Remote commands turn the session into short-lived access tokens
//! for the current tenant, or the one `NONO_TENANT` names. Nothing here
//! enrolls a device directly; `login_cmd` coordinates separate device enrollment.

pub(crate) mod client;
pub(crate) mod dpop;
pub(crate) mod loopback;
pub(crate) mod session;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nono::{NonoError, Result};
use std::sync::Arc;
use url::Url;
use zeroize::Zeroizing;

use client::{Grant, OAuthClient, TokenOutcome, TokenResponse};
use dpop::DpopKey;

pub(crate) const SCOPE_OPENID: &str = "openid";
pub(crate) const SCOPE_CONNECT: &str = "nono:connect";
pub(crate) const SCOPE_RUNS: &str = "nono:runs";

/// The scope `nono platform login` always requests.
pub(crate) fn login_scope() -> String {
    format!("{SCOPE_OPENID} {SCOPE_CONNECT} {SCOPE_RUNS}")
}

/// 32 random bytes, base64url: used for `state`, PKCE verifiers and `jti`.
pub(crate) fn random_token() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| NonoError::ConfigParse("system random generator failed".to_string()))?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

/// A credential for platform and console APIs.
///
/// `Bearer` covers explicit token files, environment tokens and the
/// remote-attach-v1 device flow. `Dpop` is an access token from a
/// `nono platform login` session, presented with a fresh proof on every request.
pub(crate) enum ApiCredential {
    Bearer(Zeroizing<String>),
    Dpop {
        access_token: Zeroizing<String>,
        key: DpopKey,
    },
}

impl std::fmt::Debug for ApiCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("ApiCredential::Bearer(<redacted>)"),
            Self::Dpop { key, .. } => f
                .debug_struct("ApiCredential::Dpop")
                .field("access_token", &"<redacted>")
                .field("key", key)
                .finish(),
        }
    }
}

impl ApiCredential {
    /// The authentication headers for one request. DPoP proofs are bound to
    /// `method` and `target`, so build them per request.
    pub(crate) fn headers(
        &self,
        method: &str,
        target: &Url,
    ) -> Result<Vec<(&'static str, Zeroizing<String>)>> {
        match self {
            Self::Bearer(token) => Ok(vec![(
                "Authorization",
                Zeroizing::new(format!("Bearer {}", token.as_str())),
            )]),
            Self::Dpop { access_token, key } => {
                let proof = key.proof(method, target, None, Some(access_token.as_str()))?;
                Ok(vec![
                    (
                        "Authorization",
                        Zeroizing::new(format!("DPoP {}", access_token.as_str())),
                    ),
                    ("DPoP", Zeroizing::new(proof)),
                ])
            }
        }
    }
}

/// What a remote command needs from the signed-in session.
#[derive(Debug)]
pub(crate) struct SessionAccess {
    pub(crate) credential: Arc<ApiCredential>,
    pub(crate) platform_url: String,
    pub(crate) console_url: Option<Url>,
    pub(crate) organization: client::Organization,
}

/// Environment variable naming the tenant (name, slug, ID or personal) for one
/// remote command, instead of the saved one.
pub(crate) const TENANT_ENV: &str = "NONO_TENANT";

/// Resolve the command flag before the environment override. Empty environment means unset.
pub(crate) fn tenant_override(explicit: Option<&str>) -> Result<Option<String>> {
    if std::env::var_os("NONO_ORG").is_some() {
        return Err(NonoError::ActionRequired(
            "NONO_ORG has been replaced by NONO_TENANT; update your environment".into(),
        ));
    }
    if let Some(value) = explicit {
        if value.trim().is_empty() {
            return Err(NonoError::ActionRequired(
                "--tenant must not be empty".into(),
            ));
        }
        return Ok(Some(value.trim().to_string()));
    }
    match std::env::var(TENANT_ENV) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value.trim().to_string())),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(NonoError::ConfigParse(format!(
            "{TENANT_ENV} is not valid UTF-8"
        ))),
    }
}

/// Exchange the stored session for an access token in the resolved tenant.
///
/// Returns `Ok(None)` when nobody is signed in, so callers can fall back to
/// other credentials. A session the platform no longer accepts is removed
/// and reported, so the person knows to sign in again.
pub(crate) fn session_access(tenant: Option<&str>) -> Result<Option<SessionAccess>> {
    let tenant = tenant_override(tenant)?;
    let lock = session::lock()?;
    session_access_locked(&lock, tenant.as_deref())
}

/// [`session_access`] for a caller that already holds the session lock.
pub(crate) fn session_access_locked(
    lock: &session::SessionLock,
    org: Option<&str>,
) -> Result<Option<SessionAccess>> {
    let Some(mut record) = session::load_record()? else {
        return Ok(None);
    };
    let persist_selection = record.tenant_selection_pending && org.is_none();
    let tenant_id = match org {
        Some(name) => record.find_organization(name)?.tenant_id.clone(),
        None if persist_selection => crate::tenant_selector::select(&record)?
            .ok_or_else(|| NonoError::ActionRequired("no tenant selected".into()))?,
        None => record.tenant_id.clone(),
    };
    let (key, refresh_token) = load_session_credentials(lock, &record)?;
    let response = refresh(
        lock,
        &record,
        &key,
        refresh_token.as_str(),
        Some(&tenant_id),
    )?;
    let organization = response
        .session
        .organizations
        .iter()
        .find(|org| org.tenant_id == response.session.tenant_id)
        .cloned()
        .ok_or_else(|| NonoError::ConfigParse("platform returned an unknown tenant".to_string()))?;
    update_record(lock, &mut record, &response.session, persist_selection)?;
    if persist_selection {
        crate::platform_client::activate_login_enrollment(&record)?;
    }
    Ok(Some(SessionAccess {
        credential: Arc::new(ApiCredential::Dpop {
            access_token: response.access_token,
            key,
        }),
        platform_url: record.platform_url,
        console_url: response.session.console_url,
        organization,
    }))
}

pub(crate) fn refresh_memberships() -> Result<session::SessionRecord> {
    let lock = session::lock()?;
    let mut record = session::load_record()?.ok_or_else(|| {
        NonoError::ActionRequired("not signed in; run `nono platform login`".into())
    })?;
    let (key, token) = load_session_credentials(&lock, &record)?;
    let response = refresh(&lock, &record, &key, token.as_str(), None)?;
    update_record(&lock, &mut record, &response.session, false)?;
    Ok(record)
}

pub(crate) fn load_session_credentials(
    lock: &session::SessionLock,
    record: &session::SessionRecord,
) -> Result<(DpopKey, Zeroizing<String>)> {
    match (session::load_key()?, session::load_refresh_token()?) {
        (Some(key), Some(token)) if key.thumbprint() == record.key_thumbprint => Ok((key, token)),
        _ => {
            session::clear(lock)?;
            Err(NonoError::ActionRequired(
                "the local sign-in is incomplete; run `nono platform login`".to_string(),
            ))
        }
    }
}

fn update_record(
    lock: &session::SessionLock,
    record: &mut session::SessionRecord,
    info: &client::SessionInfo,
    persist_selection: bool,
) -> Result<()> {
    // Refresh memberships without persisting a command-specific override.
    record.organizations = info.organizations.clone();
    if persist_selection {
        record.tenant_id = info.tenant_id.clone();
        record.tenant_selection_pending = false;
    } else if record.active_organization().is_none() {
        record.tenant_selection_pending = true;
    }
    if info.tenant_id == record.tenant_id {
        record.console_url = info.console_url.as_ref().map(Url::to_string);
    }
    session::save_record(lock, record)
}

/// Run the refresh grant, storing the rotated refresh token before anything
/// uses the new access token. `invalid_grant` clears the local session.
///
/// When `tenant` is given, an access token for any other organization is
/// refused. The rotated refresh token is still stored first, so the session
/// stays usable; only the mis-scoped access token is discarded.
pub(crate) fn refresh(
    lock: &session::SessionLock,
    record: &session::SessionRecord,
    key: &DpopKey,
    refresh_token: &str,
    tenant: Option<&str>,
) -> Result<TokenResponse> {
    let server = client::discover(&record.platform_url)?;
    if server.issuer != record.issuer {
        return Err(NonoError::ConfigParse(
            "the platform's OAuth issuer changed since sign-in; run `nono platform login` again"
                .to_string(),
        ));
    }
    match OAuthClient::new(&server, key).token(&Grant::RefreshToken {
        refresh_token,
        tenant,
    })? {
        TokenOutcome::Issued(response) => {
            let rotated = response.refresh_token.as_ref().ok_or_else(|| {
                NonoError::ConfigParse("platform did not rotate the refresh token".to_string())
            })?;
            session::store_refresh_token(lock, rotated.as_str())?;
            if let Some(requested) = tenant
                && response.session.tenant_id != requested
            {
                return Err(NonoError::ConfigParse(
                    "the platform issued access for a different tenant than requested; \
                     refusing to use it"
                        .to_string(),
                ));
            }
            Ok(response)
        }
        TokenOutcome::Error(error) if error.code == "invalid_grant" => {
            session::clear(lock)?;
            Err(NonoError::ActionRequired(
                "your platform sign-in expired or was revoked; run `nono platform login`".to_string(),
            ))
        }
        TokenOutcome::Error(error) if error.code == "invalid_target" => {
            Err(NonoError::ActionRequired(
                "you cannot access that tenant; choose one with `nono platform tenant use <tenant>`"
                    .to_string(),
            ))
        }
        TokenOutcome::Error(error) => Err(NonoError::ConfigParse(format!(
            "could not refresh the platform sign-in: {error}"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

    #[test]
    fn random_tokens_are_43_char_base64url_and_unique() {
        let first = random_token().unwrap();
        let second = random_token().unwrap();
        assert_eq!(first.len(), 43);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert_ne!(first.as_str(), second.as_str());
    }

    #[test]
    fn login_requests_every_cli_login_scope() {
        let scope = login_scope();
        for required in [SCOPE_OPENID, SCOPE_CONNECT, SCOPE_RUNS] {
            assert!(
                scope.split(' ').any(|value| value == required),
                "{required}"
            );
        }
        assert!(!scope.contains("enroll"));
    }

    #[test]
    fn dpop_credentials_send_a_bound_proof_and_never_leak_in_debug() {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let key = DpopKey::new(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap(),
        )
        .unwrap();
        let credential = ApiCredential::Dpop {
            access_token: Zeroizing::new("secret-access".to_string()),
            key,
        };
        let target = Url::parse("https://console.example/api/v1/sessions").unwrap();
        let headers = credential.headers("GET", &target).unwrap();
        assert_eq!(headers[0].0, "Authorization");
        assert_eq!(headers[0].1.as_str(), "DPoP secret-access");
        assert_eq!(headers[1].0, "DPoP");
        assert!(!format!("{credential:?}").contains("secret"));

        let bearer = ApiCredential::Bearer(Zeroizing::new("secret-bearer".to_string()));
        assert_eq!(
            bearer.headers("GET", &target).unwrap()[0].1.as_str(),
            "Bearer secret-bearer"
        );
        assert!(!format!("{bearer:?}").contains("secret"));
    }
}

#[cfg(test)]
mod mock_server_tests;
