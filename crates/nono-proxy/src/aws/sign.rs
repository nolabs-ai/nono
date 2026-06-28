//! SigV4 signing for outbound AWS requests.
//!
//! Strips incoming AWS auth headers from the agent, resolves credentials via
//! the route's provider, and returns the signed headers to inject instead.
//!
//! ## Header strip policy
//!
//! Only the five auth-bearing headers are stripped (case-insensitive exact match):
//! - `Authorization`
//! - `X-Amz-Date`
//! - `X-Amz-Content-Sha256`
//! - `X-Amz-Security-Token`
//! - `X-Amz-Signature`
//!
//! All other `x-amz-*` headers (e.g., `X-Amz-Target`, `X-Amz-Meta-*`,
//! `X-Amz-Server-Side-Encryption`) are **preserved** and included in the
//! canonical request when re-signed. This is a deliberate divergence from a
//! blanket `x-amz-*` strip, which would break Bedrock and S3 metadata.
//!
//! ## Caching & refresh
//!
//! Each `AwsRoute` holds a `SharedCredentialsProvider`. Smithy's internal
//! `LazyCredentialsCache` caches resolved `Credentials` and refreshes ~5 min
//! before expiry for STS/SSO/IMDS/web-identity. Static env creds are
//! non-refreshable: on expiry AWS returns 403; user re-runs nono with fresh env.

use super::route::AwsRoute;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SessionTokenMode, SignableBody, SignableRequest,
    SigningSettings, UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use std::time::SystemTime;
use tracing::debug;

/// The set of auth-bearing header names that must be stripped before signing.
///
/// These are the only headers stripped — all other `x-amz-*` headers are
/// preserved and included in the canonical request.
const AUTH_HEADERS_TO_STRIP: &[&str] = &[
    "authorization",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
    "x-amz-signature",
];

/// Returns `true` if `name` is one of the five auth-bearing headers that must
/// be stripped before re-signing (case-insensitive exact match).
///
/// Unlike the spike's blanket `x-amz-*` predicate, this only matches the
/// specific auth headers. `X-Amz-Target`, `X-Amz-Meta-*`,
/// `X-Amz-Server-Side-Encryption`, and other request-content headers are
/// intentionally preserved so they participate in the canonical request.
pub fn is_aws_auth_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    AUTH_HEADERS_TO_STRIP.iter().any(|h| *h == lower)
}

/// Compute a fresh SigV4 signature and return the headers to inject.
///
/// # Parameters
/// - `route`: the resolved `AwsRoute` for this upstream.
/// - `method`: HTTP method (e.g., `"POST"`).
/// - `url`: full URL including scheme, host, path, and query string
///   (e.g., `"https://bedrock-runtime.us-east-1.amazonaws.com/model/.../invoke"`).
/// - `clean_headers`: request headers with the five auth-bearing headers already
///   removed. These are included in the `SignedHeaders` list and the canonical
///   request.
/// - `body`: the complete request body bytes (full buffer; 16 MiB cap upheld
///   by caller).
///
/// # Returns
///
/// A `Vec<(String, String)>` of headers to add to the request:
/// `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, and optionally
/// `X-Amz-Security-Token`. The caller injects these into the outbound request.
///
/// # Errors
///
/// Returns a human-readable error string on credential failure or signing
/// failure. The caller should map this to a 503 with
/// `ManagedCredentialUnavailable`.
pub async fn sign_request(
    route: &AwsRoute,
    method: &str,
    url: &str,
    clean_headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<(String, String)>, String> {
    // Resolve credentials from the provider.
    // smithy's LazyCredentialsCache handles refresh for STS/SSO/IMDS/web-identity.
    let credentials = route.provider.provide_credentials().await.map_err(|e| {
        format!(
            "AWS credential resolution failed for route '{}': {}",
            route.service, e
        )
    })?;

    debug!(
        "aws::sign: signing {} {} for service={} region={}",
        method, url, route.service, route.region
    );

    // Build the signing identity from the resolved credentials.
    let identity = credentials.into();

    // Build signing settings:
    // - `XAmzSha256`: include X-Amz-Content-Sha256 (required for S3, correct
    //   for all other services).
    // - `SessionTokenMode::Include`: include X-Amz-Security-Token in the
    //   canonical request when a session token is present (STS / IMDS / SSO).
    // - `PercentEncodingMode::Single`: standard single-encode mode.
    // - `UriPathNormalizationMode::Disabled`: required for S3 key correctness.
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    settings.session_token_mode = SessionTokenMode::Include;
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;

    // Build signing parameters with pinned behavior version.
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&route.region)
        .name(&route.service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|e| format!("failed to build SigV4 signing params: {}", e))?
        .into();

    // Build the signable request. Headers are passed as `(&str, &str)` pairs.
    let header_pairs: Vec<(&str, &str)> = clean_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let signable = SignableRequest::new(
        method,
        url,
        header_pairs.into_iter(),
        SignableBody::Bytes(body),
    )
    .map_err(|e| format!("failed to build signable request: {}", e))?;

    // Sign and extract the instructions.
    let (instructions, _signature) = sign(signable, &params)
        .map_err(|e| format!("SigV4 signing failed: {}", e))?
        .into_parts();

    // Collect the new headers to inject.
    let new_headers: Vec<(String, String)> = instructions
        .headers()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    debug!(
        "aws::sign: produced {} signing headers: {:?}",
        new_headers.len(),
        new_headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
    );

    Ok(new_headers)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use aws_credential_types::Credentials;
    use aws_credential_types::provider::SharedCredentialsProvider;

    // =========================================================================
    // Header strip predicate
    // =========================================================================

    #[test]
    fn auth_header_strip_matches_authorization_case_insensitive() {
        assert!(is_aws_auth_header("Authorization"));
        assert!(is_aws_auth_header("authorization"));
        assert!(is_aws_auth_header("AUTHORIZATION"));
    }

    #[test]
    fn auth_header_strip_matches_all_five_headers() {
        assert!(is_aws_auth_header("X-Amz-Date"));
        assert!(is_aws_auth_header("x-amz-date"));
        assert!(is_aws_auth_header("X-Amz-Content-Sha256"));
        assert!(is_aws_auth_header("x-amz-content-sha256"));
        assert!(is_aws_auth_header("X-Amz-Security-Token"));
        assert!(is_aws_auth_header("x-amz-security-token"));
        assert!(is_aws_auth_header("X-Amz-Signature"));
        assert!(is_aws_auth_header("x-amz-signature"));
    }

    #[test]
    fn auth_header_strip_preserves_x_amz_target() {
        // X-Amz-Target is request content for Bedrock — must NOT be stripped.
        assert!(!is_aws_auth_header("X-Amz-Target"));
        assert!(!is_aws_auth_header("x-amz-target"));
    }

    #[test]
    fn auth_header_strip_preserves_x_amz_meta_headers() {
        // S3 metadata headers must NOT be stripped.
        assert!(!is_aws_auth_header("X-Amz-Meta-Custom"));
        assert!(!is_aws_auth_header("x-amz-meta-custom-header"));
    }

    #[test]
    fn auth_header_strip_preserves_x_amz_server_side_encryption() {
        assert!(!is_aws_auth_header("X-Amz-Server-Side-Encryption"));
        assert!(!is_aws_auth_header("x-amz-server-side-encryption"));
    }

    #[test]
    fn auth_header_strip_does_not_match_other_headers() {
        assert!(!is_aws_auth_header("Content-Type"));
        assert!(!is_aws_auth_header("Host"));
        assert!(!is_aws_auth_header("Accept"));
        assert!(!is_aws_auth_header("X-Custom-Header"));
    }

    // =========================================================================
    // Signing produces well-formed Authorization header
    // =========================================================================

    fn make_static_route(service: &str, region: &str) -> super::AwsRoute {
        // Use hardcoded-credentials feature: Credentials::new() creates
        // non-refreshable static credentials for tests.
        let creds = Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None, // no session token
            None, // no expiry
            "test",
        );
        let provider = SharedCredentialsProvider::new(creds);

        super::AwsRoute {
            upstream: format!("https://{}.{}.amazonaws.com", service, region),
            region: region.to_string(),
            service: service.to_string(),
            profile_key: None,
            provider,
        }
    }

    #[tokio::test]
    async fn sign_request_produces_authorization_header() {
        let route = make_static_route("bedrock", "us-east-1");
        let url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke";
        let clean_headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "X-Amz-Target".to_string(),
                "bedrock.InvokeModel".to_string(),
            ),
        ];
        let body = b"{\"prompt\": \"hello\"}";

        let result = sign_request(&route, "POST", url, &clean_headers, body).await;

        let headers = result.expect("signing should succeed with static creds");

        // Must include Authorization header
        let auth = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str());
        assert!(auth.is_some(), "Authorization header must be present");
        let auth_value = auth.unwrap();
        assert!(
            auth_value.starts_with("AWS4-HMAC-SHA256"),
            "Authorization must use AWS4-HMAC-SHA256 algorithm, got: {}",
            auth_value
        );
        assert!(
            auth_value.contains("Credential="),
            "Authorization must contain Credential=, got: {}",
            auth_value
        );
        assert!(
            auth_value.contains("SignedHeaders="),
            "Authorization must contain SignedHeaders=, got: {}",
            auth_value
        );
        assert!(
            auth_value.contains("Signature="),
            "Authorization must contain Signature=, got: {}",
            auth_value
        );

        // Must include X-Amz-Date
        let has_date = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"));
        assert!(has_date, "X-Amz-Date header must be present");

        // Must include X-Amz-Content-Sha256
        let has_sha256 = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-content-sha256"));
        assert!(has_sha256, "X-Amz-Content-Sha256 header must be present");
    }

    #[tokio::test]
    async fn sign_request_no_session_token_when_static_creds() {
        let route = make_static_route("s3", "eu-west-1");
        let url = "https://s3.eu-west-1.amazonaws.com/mybucket/mykey";
        let clean_headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
        let body = b"hello world";

        let headers = sign_request(&route, "PUT", url, &clean_headers, body)
            .await
            .expect("signing should succeed");

        // Static creds have no session token
        let has_security_token = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-security-token"));
        assert!(
            !has_security_token,
            "X-Amz-Security-Token should not be present for static creds without session token"
        );
    }

    #[tokio::test]
    async fn sign_request_with_session_token_includes_security_token_header() {
        let creds = Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Some("session-token-value".to_string()),
            None,
            "test",
        );
        let provider = SharedCredentialsProvider::new(creds);
        let route = super::AwsRoute {
            upstream: "https://bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            region: "us-east-1".to_string(),
            service: "bedrock".to_string(),
            profile_key: None,
            provider,
        };
        let url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke";
        let clean_headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let headers = sign_request(&route, "POST", url, &clean_headers, b"{}")
            .await
            .expect("signing should succeed");

        let has_security_token = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-security-token"));
        assert!(
            has_security_token,
            "X-Amz-Security-Token must be present when session token is provided"
        );
    }
}
