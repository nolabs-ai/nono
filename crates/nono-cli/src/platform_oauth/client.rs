//! OAuth 2.0 public-client calls to the nono platform authorization server.
//!
//! Covers authorization server metadata discovery ([RFC 8414]), the token
//! endpoint for the authorization code, device code ([RFC 8628]) and refresh
//! grants, device authorization, and token revocation ([RFC 7009]). Every
//! token-endpoint call carries a DPoP proof ([RFC 9449]) and retries once
//! with a server-supplied nonce.
//!
//! The CLI only ever talks to endpoints on the enrolled platform origin, never
//! follows redirects, and rejects any metadata it does not fully understand.
//!
//! [RFC 7009]: https://www.rfc-editor.org/rfc/rfc7009
//! [RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
//! [RFC 8628]: https://www.rfc-editor.org/rfc/rfc8628
//! [RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449

use super::dpop::{self, DpopKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

pub(crate) const CLIENT_ID: &str = "nono-cli";
const METADATA_WELL_KNOWN: &str = "/.well-known/oauth-authorization-server";
const RESPONSE_LIMIT_BYTES: u64 = 1024 * 1024;
const MAX_TOKEN_LEN: usize = 64 * 1024;
/// Access tokens are short-lived by design; anything longer is a contract
/// violation rather than a convenience.
const MAX_ACCESS_TOKEN_LIFETIME_SECS: u64 = 60 * 60;
/// RFC 8628 bounds the CLI enforces, matching remote-attach-v1.
const MAX_DEVICE_CODE_LIFETIME_SECS: u64 = 15 * 60;
const MAX_DEVICE_POLL_INTERVAL_SECS: u64 = 30;
const DEFAULT_DEVICE_POLL_INTERVAL_SECS: u64 = 5;
/// Tolerated clock skew when checking ID token expiry.
const ID_TOKEN_CLOCK_SKEW_SECS: u64 = 300;
/// Bounds on the `nono_session` member (cli-login-v1).
const MAX_ORGANIZATIONS: usize = 1000;
const MAX_IDENTIFIER_LEN: usize = 200;

/// Validated authorization server metadata for one platform origin.
#[derive(Debug, Clone)]
pub(crate) struct AuthorizationServer {
    pub(crate) issuer: String,
    pub(crate) enrollment_endpoint: Option<Url>,
    pub(crate) authorization_endpoint: Option<Url>,
    pub(crate) token_endpoint: Url,
    pub(crate) device_authorization_endpoint: Option<Url>,
    pub(crate) revocation_endpoint: Option<Url>,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    nono_enrollment_endpoint: Option<String>,
    issuer: String,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    dpop_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

/// The RFC 8414 metadata URL for `platform_url`. For an issuer with a path,
/// the well-known segment goes between the host and the path (§3.1).
pub(crate) fn metadata_url(platform_url: &str) -> Result<Url> {
    let mut url = parse_platform_url(platform_url)?;
    let issuer_path = url.path().trim_end_matches('/').to_string();
    url.set_path(&format!("{METADATA_WELL_KNOWN}{issuer_path}"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// Fetch and validate the platform's authorization server metadata.
pub(crate) fn discover(platform_url: &str) -> Result<AuthorizationServer> {
    let url = metadata_url(platform_url)?;
    let mut response = crate::platform_client::http_agent(Duration::from_secs(15))
        .get(url.as_str())
        .config()
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .header("Accept", "application/json")
        .call()
        .map_err(|error| {
            NonoError::ConfigParse(format!("authorization server discovery failed: {error}"))
        })?;
    if !response.status().is_success() {
        return Err(NonoError::ConfigParse(format!(
            "authorization server discovery returned HTTP {}; is {platform_url} a nono platform \
             with CLI login enabled?",
            response.status().as_u16()
        )));
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    if content_type != "application/json" {
        let shown = if content_type.is_empty() {
            "no content type".to_string()
        } else {
            content_type
        };
        return Err(NonoError::ConfigParse(format!(
            "{platform_url} did not return authorization server metadata (got {shown}); it is \
             not a nono platform with CLI login enabled. Pass the platform with --url or \
             NONO_PLATFORM_URL"
        )));
    }
    let body = read_body(&mut response, "authorization server metadata")?;
    let raw: RawMetadata = serde_json::from_str(&body).map_err(|error| {
        NonoError::ConfigParse(format!(
            "invalid authorization server metadata from {platform_url}: {error}"
        ))
    })?;
    validate_metadata(platform_url, raw)
}

fn validate_metadata(platform_url: &str, raw: RawMetadata) -> Result<AuthorizationServer> {
    let unsupported = |reason: &str| {
        Err(NonoError::ConfigParse(format!(
            "the platform's authorization server metadata is not supported: {reason}"
        )))
    };
    // RFC 8414 §3.3: the issuer must be identical to the identifier the
    // metadata was requested for. This is also the RFC 9207 mix-up anchor.
    if raw.issuer != platform_url {
        return unsupported("issuer does not match the platform URL");
    }
    if !raw
        .code_challenge_methods_supported
        .iter()
        .any(|m| m == "S256")
    {
        return unsupported("PKCE S256 is not supported");
    }
    if !raw
        .dpop_signing_alg_values_supported
        .iter()
        .any(|alg| alg == "ES256")
    {
        return unsupported("DPoP with ES256 is not supported");
    }
    if !raw.authorization_response_iss_parameter_supported {
        return unsupported("the authorization response iss parameter (RFC 9207) is not supported");
    }
    let platform = parse_platform_url(platform_url)?;
    let endpoint = |value: Option<String>| -> Result<Option<Url>> {
        value
            .map(|value| validate_endpoint(&platform, &value))
            .transpose()
    };
    let token_endpoint = endpoint(raw.token_endpoint)?
        .ok_or_else(|| NonoError::ConfigParse("metadata omits token_endpoint".to_string()))?;
    Ok(AuthorizationServer {
        enrollment_endpoint: endpoint(raw.nono_enrollment_endpoint)?,
        issuer: raw.issuer,
        authorization_endpoint: endpoint(raw.authorization_endpoint)?,
        token_endpoint,
        device_authorization_endpoint: endpoint(raw.device_authorization_endpoint)?,
        revocation_endpoint: endpoint(raw.revocation_endpoint)?,
    })
}

/// Every endpoint must share the platform's origin (scheme, host and port).
/// The platform URL was already restricted to HTTPS or loopback HTTP, so this
/// also enforces the transport rule.
fn validate_endpoint(platform: &Url, value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|error| {
        NonoError::ConfigParse(format!("invalid authorization server endpoint: {error}"))
    })?;
    if url.origin() != platform.origin() {
        return Err(NonoError::ConfigParse(format!(
            "authorization server endpoint {} is not on the platform origin",
            url.origin().ascii_serialization()
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NonoError::ConfigParse(
            "authorization server endpoints must not contain credentials, a query, or a fragment"
                .to_string(),
        ));
    }
    Ok(url)
}

fn parse_platform_url(platform_url: &str) -> Result<Url> {
    let url = Url::parse(platform_url)
        .map_err(|error| NonoError::ConfigParse(format!("invalid platform URL: {error}")))?;
    if url.cannot_be_a_base() {
        return Err(NonoError::ConfigParse(format!(
            "invalid platform URL: {platform_url}"
        )));
    }
    Ok(url)
}

/// A token-endpoint grant. Secret inputs are borrowed from zeroizing owners.
pub(crate) enum Grant<'a> {
    AuthorizationCode {
        code: &'a str,
        code_verifier: &'a str,
        redirect_uri: &'a str,
    },
    DeviceCode {
        device_code: &'a str,
    },
    RefreshToken {
        refresh_token: &'a str,
        /// Organization (tenant id) the new access token should be for.
        tenant: Option<&'a str>,
    },
}

/// A validated, DPoP-bound token response.
pub(crate) struct TokenResponse {
    pub(crate) access_token: Zeroizing<String>,
    pub(crate) expires_in: u64,
    pub(crate) refresh_token: Option<Zeroizing<String>>,
    pub(crate) id_token: Option<Zeroizing<String>>,
    pub(crate) scope: Option<String>,
    pub(crate) session: SessionInfo,
}

/// An organization the signed-in person belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Organization {
    pub(crate) tenant_id: String,
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) kind: String,
}

/// The validated `nono_session` member: which organization the access token
/// is for, the console to use, and every organization the person can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionInfo {
    pub(crate) tenant_id: String,
    pub(crate) console_url: Option<Url>,
    pub(crate) organizations: Vec<Organization>,
}

#[derive(Deserialize)]
struct RawSession {
    tenant_id: String,
    console_url: Option<String>,
    organizations: Vec<Organization>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field("scope", &self.scope)
            .field("session", &self.session)
            .finish()
    }
}

// Intentionally not Debug: it holds raw secrets before validation.
#[derive(Deserialize)]
struct RawTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
    nono_session: Option<RawSession>,
}

/// An OAuth error response, with its fields restricted to safe characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OAuthError {
    pub(crate) code: String,
    pub(crate) description: Option<String>,
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.description {
            Some(description) => write!(f, "{} ({description})", self.code),
            None => f.write_str(&self.code),
        }
    }
}

#[derive(Deserialize)]
struct RawOAuthError {
    error: String,
    error_description: Option<String>,
}

#[derive(Debug)]
pub(crate) enum TokenOutcome {
    Issued(TokenResponse),
    Error(OAuthError),
}

/// A pending RFC 8628 device authorization.
pub(crate) struct DeviceAuthorization {
    pub(crate) device_code: Zeroizing<String>,
    pub(crate) user_code: String,
    pub(crate) verification_uri: Url,
    pub(crate) expires_in: u64,
    pub(crate) interval: u64,
}

impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri.as_str())
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

#[derive(Deserialize)]
struct RawDeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

/// Token-endpoint client bound to one server and one DPoP key. It remembers
/// the most recent `DPoP-Nonce` the server supplied.
pub(crate) struct OAuthClient<'a> {
    server: &'a AuthorizationServer,
    key: &'a DpopKey,
    nonce: Option<String>,
}

struct FormResponse {
    status: u16,
    body: Zeroizing<String>,
}

impl<'a> OAuthClient<'a> {
    pub(crate) fn new(server: &'a AuthorizationServer, key: &'a DpopKey) -> Self {
        Self {
            server,
            key,
            nonce: None,
        }
    }

    /// Redeem a grant at the token endpoint.
    pub(crate) fn token(&mut self, grant: &Grant<'_>) -> Result<TokenOutcome> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        match grant {
            Grant::AuthorizationCode {
                code,
                code_verifier,
                redirect_uri,
            } => {
                form.append_pair("grant_type", "authorization_code")
                    .append_pair("code", code)
                    .append_pair("code_verifier", code_verifier)
                    .append_pair("redirect_uri", redirect_uri);
            }
            Grant::DeviceCode { device_code } => {
                form.append_pair("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                    .append_pair("device_code", device_code);
            }
            Grant::RefreshToken {
                refresh_token,
                tenant,
            } => {
                form.append_pair("grant_type", "refresh_token")
                    .append_pair("refresh_token", refresh_token);
                if let Some(tenant) = tenant {
                    form.append_pair("nono_tenant", tenant);
                }
            }
        }
        form.append_pair("client_id", CLIENT_ID);
        let form = Zeroizing::new(form.finish());
        let endpoint = self.server.token_endpoint.clone();
        let response = self.post_form(&endpoint, &form)?;
        match response.status {
            200 => {
                let raw: RawTokenResponse =
                    serde_json::from_str(&response.body).map_err(|error| {
                        NonoError::ConfigParse(format!("invalid token response: {error}"))
                    })?;
                validate_token_response(raw).map(TokenOutcome::Issued)
            }
            400 | 401 => parse_oauth_error(&response.body).map(TokenOutcome::Error),
            status => Err(NonoError::ConfigParse(format!(
                "token endpoint returned HTTP {status}"
            ))),
        }
    }

    /// Start an RFC 8628 device authorization. The DPoP proof lets the server
    /// record the key thumbprint on the pending request (cli-login-v1).
    pub(crate) fn device_authorization(
        &mut self,
        scope: &str,
        device_name: Option<&str>,
    ) -> Result<DeviceAuthorization> {
        let endpoint = self
            .server
            .device_authorization_endpoint
            .clone()
            .ok_or_else(|| {
                NonoError::ActionRequired(
                    "the platform does not support device-code sign-in; run `nono login --browser` \
                     on a machine with a browser"
                        .to_string(),
                )
            })?;
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("client_id", CLIENT_ID)
            .append_pair("scope", scope);
        if let Some(name) = device_name {
            form.append_pair("device_name", name);
        }
        let form = Zeroizing::new(form.finish());
        let response = self.post_form(&endpoint, &form)?;
        if response.status != 200 {
            return Err(match parse_oauth_error(&response.body) {
                Ok(error) => {
                    NonoError::ActionRequired(format!("device sign-in was refused: {error}"))
                }
                Err(_) => NonoError::ConfigParse(format!(
                    "device authorization endpoint returned HTTP {}",
                    response.status
                )),
            });
        }
        let raw: RawDeviceAuthorization =
            serde_json::from_str(&response.body).map_err(|error| {
                NonoError::ConfigParse(format!("invalid device authorization response: {error}"))
            })?;
        let platform = parse_platform_url(&self.server.issuer)?;
        validate_device_authorization(&platform, raw)
    }

    /// Revoke a refresh token (RFC 7009). Success means the server accepted
    /// the request; RFC 7009 also answers 200 for an already-invalid token.
    pub(crate) fn revoke_refresh_token(&mut self, refresh_token: &str) -> Result<()> {
        let endpoint = self.server.revocation_endpoint.clone().ok_or_else(|| {
            NonoError::ConfigParse("the platform does not advertise a revocation endpoint".into())
        })?;
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("token", refresh_token)
            .append_pair("token_type_hint", "refresh_token")
            .append_pair("client_id", CLIENT_ID);
        let form = Zeroizing::new(form.finish());
        let response = self.post_form(&endpoint, &form)?;
        if response.status == 200 {
            Ok(())
        } else {
            Err(NonoError::ConfigParse(format!(
                "revocation endpoint returned HTTP {}",
                response.status
            )))
        }
    }

    /// POST a form with a DPoP proof, retrying once if the server demands a
    /// nonce (RFC 9449 §8).
    fn post_form(&mut self, endpoint: &Url, form: &str) -> Result<FormResponse> {
        self.post_body(endpoint, "application/x-www-form-urlencoded", form)
    }

    pub(crate) fn enroll(
        &mut self,
        request: &crate::login_enrollment::LoginEnrollmentRequest,
    ) -> Result<crate::platform_client::EnrollmentExchangeResponse> {
        let endpoint = self.server.enrollment_endpoint.clone().ok_or_else(|| {
            NonoError::ActionRequired(
                "this platform does not support enrollment during login".into(),
            )
        })?;
        let body = Zeroizing::new(
            serde_json::to_string(request)
                .map_err(|_| NonoError::ConfigParse("cannot encode enrollment request".into()))?,
        );
        let response = self.post_body(&endpoint, "application/json", &body)?;
        if response.status != 200 {
            let message = parse_oauth_error(&response.body)
                .map(|error| error.to_string())
                .unwrap_or_else(|_| format!("HTTP {}", response.status));
            return Err(NonoError::ActionRequired(format!(
                "device enrollment failed: {message}"
            )));
        }
        serde_json::from_str(&response.body)
            .map_err(|_| NonoError::ConfigParse("invalid enrollment response".into()))
    }

    fn post_body(
        &mut self,
        endpoint: &Url,
        content_type: &str,
        body: &str,
    ) -> Result<FormResponse> {
        let mut retried = false;
        loop {
            let proof = self
                .key
                .proof("POST", endpoint, self.nonce.as_deref(), None)?;
            let mut response = crate::platform_client::http_agent(Duration::from_secs(30))
                .post(endpoint.as_str())
                .config()
                .max_redirects(0)
                .http_status_as_error(false)
                .build()
                .header("Content-Type", content_type)
                .header("Accept", "application/json")
                .header("DPoP", &proof)
                .send(body.as_bytes())
                .map_err(|error| {
                    NonoError::ConfigParse(format!("authorization server request failed: {error}"))
                })?;
            let new_nonce = match response.headers().get("DPoP-Nonce") {
                Some(value) => {
                    let value = value.to_str().map_err(|_| {
                        NonoError::ConfigParse("platform returned an invalid DPoP nonce".into())
                    })?;
                    dpop::validate_nonce(value)?;
                    Some(value.to_string())
                }
                None => None,
            };
            let status = response.status().as_u16();
            let body = Zeroizing::new(read_body(&mut response, "authorization server response")?);
            let nonce_changed = new_nonce.is_some() && new_nonce != self.nonce;
            if new_nonce.is_some() {
                self.nonce = new_nonce;
            }
            if !retried
                && status == 400
                && nonce_changed
                && parse_oauth_error(&body).is_ok_and(|error| error.code == "use_dpop_nonce")
            {
                retried = true;
                continue;
            }
            return Ok(FormResponse { status, body });
        }
    }
}

fn validate_token_response(raw: RawTokenResponse) -> Result<TokenResponse> {
    // A bearer token would be replayable from any copy; fail closed.
    if !raw.token_type.eq_ignore_ascii_case("DPoP") {
        return Err(NonoError::ConfigParse(
            "platform issued a token that is not DPoP-bound".to_string(),
        ));
    }
    let expires_in = raw
        .expires_in
        .ok_or_else(|| NonoError::ConfigParse("token response omits expires_in".to_string()))?;
    if expires_in == 0 || expires_in > MAX_ACCESS_TOKEN_LIFETIME_SECS {
        return Err(NonoError::ConfigParse(
            "platform issued an access token with an unsupported lifetime".to_string(),
        ));
    }
    Ok(TokenResponse {
        access_token: validate_token_value("access token", raw.access_token)?,
        expires_in,
        refresh_token: raw
            .refresh_token
            .map(|token| validate_token_value("refresh token", token))
            .transpose()?,
        id_token: raw
            .id_token
            .map(|token| validate_token_value("ID token", token))
            .transpose()?,
        scope: raw.scope,
        session: validate_session(raw.nono_session.ok_or_else(|| {
            NonoError::ConfigParse("token response omits nono_session".to_string())
        })?)?,
    })
}

fn validate_session(raw: RawSession) -> Result<SessionInfo> {
    let invalid = |reason: &str| {
        NonoError::ConfigParse(format!("platform returned an invalid session: {reason}"))
    };
    if raw.organizations.is_empty() || raw.organizations.len() > MAX_ORGANIZATIONS {
        return Err(invalid("unexpected number of organizations"));
    }
    let mut organizations = Vec::with_capacity(raw.organizations.len());
    for org in raw.organizations {
        if !is_identifier(&org.tenant_id)
            || !is_identifier(&org.slug)
            || !matches!(org.kind.as_str(), "personal" | "organization")
        {
            return Err(invalid("malformed organization"));
        }
        let display_name = display_safe(&org.display_name);
        organizations.push(Organization {
            display_name: if display_name.is_empty() {
                org.slug.clone()
            } else {
                display_name
            },
            ..org
        });
    }
    if !organizations
        .iter()
        .any(|org| org.tenant_id == raw.tenant_id)
    {
        return Err(invalid("the active organization is not one of yours"));
    }
    let console_url = raw
        .console_url
        .map(|value| validate_service_url(&value))
        .transpose()?;
    Ok(SessionInfo {
        tenant_id: raw.tenant_id,
        console_url,
        organizations,
    })
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// A console origin from the platform: `https`, or `http` on loopback, with
/// no credentials, query or fragment.
fn validate_service_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)
        .map_err(|error| NonoError::ConfigParse(format!("invalid console URL: {error}")))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NonoError::ConfigParse(
            "platform returned an unsupported console URL".to_string(),
        ));
    }
    Ok(url)
}

/// Tokens end up in HTTP headers and form bodies; reject anything that is
/// not a plain visible-ASCII string.
pub(crate) fn validate_token_value(name: &str, value: String) -> Result<Zeroizing<String>> {
    let value = Zeroizing::new(value);
    let valid = !value.is_empty()
        && value.len() <= MAX_TOKEN_LEN
        && value.bytes().all(|byte| byte.is_ascii_graphic());
    if valid {
        Ok(value)
    } else {
        Err(NonoError::ConfigParse(format!(
            "platform issued an invalid {name}"
        )))
    }
}

fn validate_device_authorization(
    platform: &Url,
    raw: RawDeviceAuthorization,
) -> Result<DeviceAuthorization> {
    let device_code = validate_token_value("device code", raw.device_code)?;
    // The user types this code, so keep it short and unambiguous.
    let user_code_valid = !raw.user_code.is_empty()
        && raw.user_code.len() <= 32
        && raw
            .user_code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if !user_code_valid {
        return Err(NonoError::ConfigParse(
            "platform returned an invalid user code".to_string(),
        ));
    }
    // The CLI prints this URL for the user to visit; it must be the platform.
    let verification_uri = Url::parse(&raw.verification_uri)
        .map_err(|error| NonoError::ConfigParse(format!("invalid verification URI: {error}")))?;
    if verification_uri.origin() != platform.origin()
        || !verification_uri.username().is_empty()
        || verification_uri.password().is_some()
        || verification_uri.fragment().is_some()
    {
        return Err(NonoError::ConfigParse(
            "platform returned a verification URI outside its own origin".to_string(),
        ));
    }
    let interval = raw.interval.unwrap_or(DEFAULT_DEVICE_POLL_INTERVAL_SECS);
    if raw.expires_in == 0
        || raw.expires_in > MAX_DEVICE_CODE_LIFETIME_SECS
        || interval == 0
        || interval > MAX_DEVICE_POLL_INTERVAL_SECS
    {
        return Err(NonoError::ConfigParse(
            "platform returned an unsupported device authorization contract".to_string(),
        ));
    }
    Ok(DeviceAuthorization {
        device_code,
        user_code: raw.user_code,
        verification_uri,
        expires_in: raw.expires_in,
        interval,
    })
}

pub(crate) fn parse_oauth_error(body: &str) -> Result<OAuthError> {
    let raw: RawOAuthError = serde_json::from_str(body).map_err(|error| {
        NonoError::ConfigParse(format!("invalid OAuth error response: {error}"))
    })?;
    let code = validate_error_code(&raw.error)?;
    let description = raw.error_description.map(|description| {
        let clean = crate::terminal_approval::sanitize_for_terminal(&description);
        clean.chars().take(200).collect::<String>()
    });
    Ok(OAuthError { code, description })
}

/// RFC 6749 error codes are a restricted ASCII set; accept a conservative
/// subset so codes are safe to print and to place in a URL query.
pub(crate) fn validate_error_code(code: &str) -> Result<String> {
    let valid = !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(code.to_string())
    } else {
        Err(NonoError::ConfigParse(
            "platform returned an invalid OAuth error code".to_string(),
        ))
    }
}

/// The signed-in human, as described by the ID token. Display-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) subject: String,
    pub(crate) display: String,
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    email: Option<String>,
    preferred_username: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

/// Read the signed-in identity from an ID token.
///
/// The ID token came straight from the token endpoint over a validated TLS
/// connection, so per OpenID Connect Core §3.1.3.7 the TLS server check stands
/// in for signature validation. The result is used only to tell the user who
/// they signed in as; no authorization decision depends on it.
pub(crate) fn identity_from_id_token(
    id_token: &str,
    issuer: &str,
    now_secs: u64,
) -> Result<Identity> {
    let invalid = |reason: &str| NonoError::ConfigParse(format!("invalid ID token: {reason}"));
    let mut segments = id_token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(invalid("not a compact JWS"));
    };
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid("payload is not base64url"))?;
    let claims: IdTokenClaims =
        serde_json::from_slice(&payload).map_err(|error| invalid(&error.to_string()))?;
    if claims.iss != issuer {
        return Err(invalid("issuer does not match the platform"));
    }
    let audience_ok = match &claims.aud {
        Audience::One(aud) => aud == CLIENT_ID,
        Audience::Many(auds) => auds.iter().any(|aud| aud == CLIENT_ID),
    };
    if !audience_ok {
        return Err(invalid("audience does not include nono-cli"));
    }
    if claims.exp.saturating_add(ID_TOKEN_CLOCK_SKEW_SECS) <= now_secs {
        return Err(invalid("expired"));
    }
    let subject = display_safe(&claims.sub);
    if subject.is_empty() {
        return Err(invalid("empty subject"));
    }
    let display = [claims.email, claims.preferred_username, claims.name]
        .into_iter()
        .flatten()
        .map(|value| display_safe(&value))
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| subject.clone());
    Ok(Identity { subject, display })
}

fn display_safe(value: &str) -> String {
    crate::terminal_approval::sanitize_for_terminal(value)
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect()
}

fn read_body(response: &mut ureq::http::Response<ureq::Body>, name: &str) -> Result<String> {
    response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT_BYTES)
        .read_to_string()
        .map_err(|error| NonoError::ConfigParse(format!("invalid {name}: {error}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn raw_metadata(issuer: &str) -> RawMetadata {
        RawMetadata {
            nono_enrollment_endpoint: None,
            issuer: issuer.to_string(),
            authorization_endpoint: Some(format!("{issuer}/oauth/authorize")),
            token_endpoint: Some(format!("{issuer}/oauth/token")),
            device_authorization_endpoint: Some(format!("{issuer}/oauth/device")),
            revocation_endpoint: Some(format!("{issuer}/oauth/revoke")),
            code_challenge_methods_supported: vec!["S256".to_string()],
            dpop_signing_alg_values_supported: vec!["ES256".to_string()],
            authorization_response_iss_parameter_supported: true,
        }
    }

    fn id_token(claims: serde_json::Value) -> String {
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    #[test]
    fn metadata_url_inserts_well_known_before_the_issuer_path() {
        assert_eq!(
            metadata_url("https://nono.example.com").unwrap().as_str(),
            "https://nono.example.com/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            metadata_url("https://example.com/platform")
                .unwrap()
                .as_str(),
            "https://example.com/.well-known/oauth-authorization-server/platform"
        );
    }

    #[test]
    fn valid_metadata_is_accepted() {
        let server = validate_metadata(
            "https://nono.example.com",
            raw_metadata("https://nono.example.com"),
        )
        .unwrap();
        assert_eq!(
            server.token_endpoint.as_str(),
            "https://nono.example.com/oauth/token"
        );
        assert!(server.authorization_endpoint.is_some());
    }

    #[test]
    fn metadata_with_a_different_issuer_is_rejected() {
        assert!(
            validate_metadata(
                "https://nono.example.com",
                raw_metadata("https://evil.example")
            )
            .is_err()
        );
        // Trailing-slash and path differences are different issuers too.
        assert!(
            validate_metadata(
                "https://nono.example.com",
                raw_metadata("https://nono.example.com/")
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_missing_required_capabilities_is_rejected() {
        let issuer = "https://nono.example.com";
        let mut raw = raw_metadata(issuer);
        raw.code_challenge_methods_supported = vec!["plain".to_string()];
        assert!(validate_metadata(issuer, raw).is_err());

        let mut raw = raw_metadata(issuer);
        raw.dpop_signing_alg_values_supported = vec!["RS256".to_string()];
        assert!(validate_metadata(issuer, raw).is_err());

        let mut raw = raw_metadata(issuer);
        raw.authorization_response_iss_parameter_supported = false;
        assert!(validate_metadata(issuer, raw).is_err());

        let mut raw = raw_metadata(issuer);
        raw.token_endpoint = None;
        assert!(validate_metadata(issuer, raw).is_err());
    }

    #[test]
    fn endpoints_off_the_platform_origin_are_rejected() {
        let issuer = "https://nono.example.com";
        for endpoint in [
            "https://evil.example/oauth/token",
            "http://nono.example.com/oauth/token",
            "https://nono.example.com:8443/oauth/token",
            "https://user:pw@nono.example.com/oauth/token",
            "https://nono.example.com/oauth/token?x=1",
        ] {
            let mut raw = raw_metadata(issuer);
            raw.token_endpoint = Some(endpoint.to_string());
            assert!(validate_metadata(issuer, raw).is_err(), "{endpoint}");
        }
    }

    fn test_session() -> RawSession {
        RawSession {
            tenant_id: "t-1".to_string(),
            console_url: Some("https://console.example.com".to_string()),
            organizations: vec![Organization {
                tenant_id: "t-1".to_string(),
                slug: "alice".to_string(),
                display_name: "Alice".to_string(),
                kind: "personal".to_string(),
            }],
        }
    }

    #[test]
    fn session_member_is_validated() {
        assert!(validate_session(test_session()).is_ok());

        let mut stranger = test_session();
        stranger.tenant_id = "t-2".to_string();
        assert!(validate_session(stranger).is_err(), "active org not listed");

        let mut empty = test_session();
        empty.organizations.clear();
        assert!(validate_session(empty).is_err());

        let mut bad_slug = test_session();
        bad_slug.organizations[0].slug = "acme\nX: y".to_string();
        assert!(validate_session(bad_slug).is_err());

        let mut bad_kind = test_session();
        bad_kind.organizations[0].kind = "admin".to_string();
        assert!(validate_session(bad_kind).is_err());

        for console in [
            "http://console.example.com",
            "https://user:pw@console.example.com",
            "https://console.example.com/?x=1",
            "javascript:alert(1)",
        ] {
            let mut session = test_session();
            session.console_url = Some(console.to_string());
            assert!(validate_session(session).is_err(), "{console}");
        }
        let mut no_console = test_session();
        no_console.console_url = None;
        assert!(validate_session(no_console).unwrap().console_url.is_none());

        let mut escapes = test_session();
        escapes.organizations[0].display_name = "Acme\u{1b}[2J".to_string();
        let name = &validate_session(escapes).unwrap().organizations[0].display_name;
        assert!(!name.contains('\u{1b}'), "{name}");
    }

    #[test]
    fn bearer_tokens_are_rejected() {
        let raw = RawTokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(300),
            refresh_token: None,
            id_token: None,
            scope: None,
            nono_session: Some(test_session()),
        };
        assert!(validate_token_response(raw).is_err());
    }

    #[test]
    fn token_lifetime_and_values_are_bounded() {
        let raw = |expires_in, access_token: &str| RawTokenResponse {
            access_token: access_token.to_string(),
            token_type: "dpop".to_string(),
            expires_in,
            refresh_token: None,
            id_token: None,
            scope: None,
            nono_session: Some(test_session()),
        };
        assert!(validate_token_response(raw(Some(300), "at")).is_ok());
        assert!(validate_token_response(raw(None, "at")).is_err());
        assert!(validate_token_response(raw(Some(0), "at")).is_err());
        assert!(validate_token_response(raw(Some(7200), "at")).is_err());
        assert!(validate_token_response(raw(Some(300), "")).is_err());
        assert!(validate_token_response(raw(Some(300), "a b")).is_err());
        assert!(validate_token_response(raw(Some(300), "a\r\nX: y")).is_err());
    }

    #[test]
    fn token_response_debug_redacts_secrets() {
        let response = validate_token_response(RawTokenResponse {
            access_token: "secret-access".to_string(),
            token_type: "DPoP".to_string(),
            expires_in: Some(300),
            refresh_token: Some("secret-refresh".to_string()),
            id_token: Some("secret-id".to_string()),
            scope: None,
            nono_session: Some(test_session()),
        })
        .unwrap();
        let debug = format!("{response:?}");
        assert!(!debug.contains("secret"), "{debug}");
    }

    #[test]
    fn oauth_errors_are_parsed_and_restricted() {
        let error = parse_oauth_error(
            r#"{"error":"authorization_pending","error_description":"wait\u001b[2J"}"#,
        )
        .unwrap();
        assert_eq!(error.code, "authorization_pending");
        assert!(!error.description.unwrap().contains('\u{1b}'));
        assert!(parse_oauth_error(r#"{"error":"bad code"}"#).is_err());
        assert!(parse_oauth_error(r#"{"error":"x&redirect=evil"}"#).is_err());
        assert!(parse_oauth_error("not json").is_err());
    }

    #[test]
    fn device_authorization_contract_is_enforced() {
        let platform = Url::parse("https://nono.example.com").unwrap();
        let raw = |uri: &str, user_code: &str, expires_in, interval| RawDeviceAuthorization {
            device_code: "dc".to_string(),
            user_code: user_code.to_string(),
            verification_uri: uri.to_string(),
            expires_in,
            interval,
        };
        let ok = validate_device_authorization(
            &platform,
            raw("https://nono.example.com/device", "WDJB-MJHT", 600, None),
        )
        .unwrap();
        assert_eq!(ok.interval, DEFAULT_DEVICE_POLL_INTERVAL_SECS);
        assert!(
            validate_device_authorization(
                &platform,
                raw("https://phish.example/device", "WDJB-MJHT", 600, Some(5))
            )
            .is_err()
        );
        assert!(
            validate_device_authorization(
                &platform,
                raw("https://nono.example.com/device", "<script>", 600, Some(5))
            )
            .is_err()
        );
        assert!(
            validate_device_authorization(
                &platform,
                raw("https://nono.example.com/device", "WDJB", 3600, Some(5))
            )
            .is_err()
        );
        assert!(
            validate_device_authorization(
                &platform,
                raw("https://nono.example.com/device", "WDJB", 600, Some(120))
            )
            .is_err()
        );
    }

    #[test]
    fn id_token_identity_is_checked_and_sanitized() {
        let issuer = "https://nono.example.com";
        let now = 1_800_000_000;
        let token = id_token(serde_json::json!({
            "iss": issuer, "sub": "user-1", "aud": ["nono-cli", "console"],
            "exp": now + 60, "email": "dev@example.com\u{1b}[31m"
        }));
        let identity = identity_from_id_token(&token, issuer, now).unwrap();
        assert_eq!(identity.subject, "user-1");
        assert!(identity.display.starts_with("dev@example.com"));
        assert!(!identity.display.contains('\u{1b}'));

        let wrong_issuer = id_token(serde_json::json!({
            "iss": "https://evil.example", "sub": "u", "aud": "nono-cli", "exp": now + 60
        }));
        assert!(identity_from_id_token(&wrong_issuer, issuer, now).is_err());

        let wrong_audience = id_token(serde_json::json!({
            "iss": issuer, "sub": "u", "aud": "someone-else", "exp": now + 60
        }));
        assert!(identity_from_id_token(&wrong_audience, issuer, now).is_err());

        let expired = id_token(serde_json::json!({
            "iss": issuer, "sub": "u", "aud": "nono-cli", "exp": now - 3600
        }));
        assert!(identity_from_id_token(&expired, issuer, now).is_err());

        assert!(identity_from_id_token("only.two", issuer, now).is_err());
    }
}
