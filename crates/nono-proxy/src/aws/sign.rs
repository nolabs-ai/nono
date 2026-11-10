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
//! Each `AwsRoute` holds one `SharedCredentialsProvider`, or one per allowed
//! profile. These providers are not wrapped in an identity cache, so every
//! signed request resolves credentials again (re-running `credential_process`,
//! STS AssumeRole, or SSO GetRoleCredentials as the profile requires). Static
//! env creds are non-refreshable: on expiry AWS returns 403; user re-runs nono
//! with fresh env.

use super::route::AwsRoute;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
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

/// Returns `true` if `id` has the shape of an AWS access key ID: 16 to 128
/// ASCII uppercase letters or digits (IAM `AccessKeyIdType`, restricted to the
/// alphabet AWS actually issues).
pub(crate) fn is_access_key_id(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Extract the access key ID from the agent's SigV4 `Authorization` header.
///
/// Reads the `Credential=<AKID>/<date>/<region>/<service>/aws4_request` scope
/// of an `AWS4-HMAC-SHA256` header. Returns `None` when there is no such
/// header, when it appears more than once, or when the key ID is malformed,
/// so callers that select a signing identity from it fail closed.
pub fn sigv4_access_key_id(headers: &[(String, String)]) -> Option<String> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str());
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }

    let rest = value.trim().strip_prefix("AWS4-HMAC-SHA256 ")?;
    let credential = rest
        .split(',')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("Credential="))?;
    let (access_key_id, scope) = credential.split_once('/')?;
    if scope.is_empty() || !is_access_key_id(access_key_id) {
        return None;
    }
    Some(access_key_id.to_string())
}

/// Compute a fresh SigV4 signature and return the headers to inject.
///
/// # Parameters
/// - `route`: the resolved `AwsRoute` for this upstream.
/// - `region`: the SigV4 region for this request (the route's fixed region, or
///   the one derived from the request host for wildcard-region routes).
/// - `provider`: the credential provider chosen for this request by
///   [`AwsRoute::select_provider`].
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
    region: &str,
    provider: &SharedCredentialsProvider,
    method: &str,
    url: &str,
    clean_headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<(String, String)>, String> {
    // Resolve credentials from the provider (uncached; see module docs).
    let credentials = provider.provide_credentials().await.map_err(|e| {
        format!(
            "AWS credential resolution failed for route '{}': {}",
            route.service, e
        )
    })?;

    debug!(
        "aws::sign: signing {} {} for service={} region={}",
        method, url, route.service, region
    );

    // Build the signing identity from the resolved credentials.
    let identity = credentials.into();

    // Build signing settings:
    // - `XAmzSha256`: include X-Amz-Content-Sha256 (required for S3, correct
    //   for all other services).
    // - `SessionTokenMode::Include`: include X-Amz-Security-Token in the
    //   canonical request when a session token is present (STS / IMDS / SSO).
    // - `PercentEncodingMode`: Almost all AWS services use double encoding, except S3
    //   This means that a : character in the URL should encode once to %3A, and then again to %253A
    //   Failing to do so will cause signing errors. The only exception to this rule is S3, which uses single encoding
    // - `UriPathNormalizationMode` - Similarly, most uri's are normalized first (e.g. a path with ../.) before any encoding.
    //   S3 is again the exception where these paths should be passed as-is
    let is_s3 = route.service == "s3";
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    settings.session_token_mode = SessionTokenMode::Include;
    settings.percent_encoding_mode = if is_s3 {
        PercentEncodingMode::Single
    } else {
        PercentEncodingMode::Double
    };
    settings.uri_path_normalization_mode = if is_s3 {
        UriPathNormalizationMode::Disabled
    } else {
        UriPathNormalizationMode::Enabled
    };

    // Build signing parameters with pinned behavior version.
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
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
    use crate::aws::endpoints::SigningRegion;
    use aws_credential_types::Credentials;

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
    // Access key ID extraction from the agent's Authorization header
    // =========================================================================

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn access_key_id_extracted_from_sigv4_authorization() {
        let h = headers(&[
            ("Content-Type", "application/json"),
            (
                "Authorization",
                "AWS4-HMAC-SHA256 Credential=NONOPROFILE0DEVRO01/20261105/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123",
            ),
        ]);
        assert_eq!(
            sigv4_access_key_id(&h).as_deref(),
            Some("NONOPROFILE0DEVRO01")
        );
    }

    #[test]
    fn access_key_id_header_name_is_case_insensitive() {
        let h = headers(&[(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=NONOPROFILE0DEVRO01/20261105/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
        )]);
        assert_eq!(
            sigv4_access_key_id(&h).as_deref(),
            Some("NONOPROFILE0DEVRO01")
        );
    }

    #[test]
    fn access_key_id_tolerates_no_space_after_comma() {
        // botocore and the Rust SDK both emit ", " but the separator is not
        // load-bearing for the Credential scope, which comes first.
        let h = headers(&[(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=NONOPROFILE0DEVRO01/20261105/us-east-1/sts/aws4_request,SignedHeaders=host,Signature=abc",
        )]);
        assert_eq!(
            sigv4_access_key_id(&h).as_deref(),
            Some("NONOPROFILE0DEVRO01")
        );
    }

    #[test]
    fn access_key_id_none_without_authorization() {
        let h = headers(&[("Content-Type", "application/json")]);
        assert_eq!(sigv4_access_key_id(&h), None);
    }

    #[test]
    fn access_key_id_none_for_non_sigv4_scheme() {
        for value in [
            "Bearer NONOPROFILE0DEVRO01",
            "AWS NONOPROFILE0DEVRO01:signature",
            "AWS4-HMAC-SHA256",
            "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abc",
        ] {
            let h = headers(&[("Authorization", value)]);
            assert_eq!(sigv4_access_key_id(&h), None, "value: {value}");
        }
    }

    #[test]
    fn access_key_id_none_for_empty_or_malformed_key() {
        for value in [
            "AWS4-HMAC-SHA256 Credential=/20261105/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
            "AWS4-HMAC-SHA256 Credential=NONOPROFILE0DEVRO01, SignedHeaders=host, Signature=abc",
            "AWS4-HMAC-SHA256 Credential=nono-profile/20261105/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
        ] {
            let h = headers(&[("Authorization", value)]);
            assert_eq!(sigv4_access_key_id(&h), None, "value: {value}");
        }
    }

    #[test]
    fn access_key_id_none_for_scheme_case_or_separator_variants() {
        // Only the exact scheme token followed by a space is accepted, so
        // case or whitespace games cannot reach a different parse.
        for value in [
            "aws4-hmac-sha256 Credential=NONOPROFILE0DEVRO01/20261105/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
            "AWS4-HMAC-SHA256\tCredential=NONOPROFILE0DEVRO01/20261105/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
            "AWS4-HMAC-SHA256Credential=NONOPROFILE0DEVRO01/20261105/us-east-1/sts/aws4_request",
        ] {
            let h = headers(&[("Authorization", value)]);
            assert_eq!(sigv4_access_key_id(&h), None, "value: {value:?}");
        }
    }

    #[test]
    fn access_key_id_none_for_obs_fold_header() {
        // An obs-fold continuation is dropped by header parsing, leaving only
        // the first physical line; the scheme alone must not select a key.
        let raw = b"POST / HTTP/1.1\r\nHost: sts.amazonaws.com\r\nAuthorization: AWS4-HMAC-SHA256\r\n Credential=NONOPROFILE0DEVRO01/20261105/us-east-1/sts/aws4_request\r\n\r\n";
        let h = crate::reverse::filter_headers(raw, "");
        assert_eq!(sigv4_access_key_id(&h), None, "headers: {h:?}");
    }

    #[test]
    fn access_key_id_none_when_authorization_repeated() {
        // Two Authorization headers are ambiguous: refuse to pick one.
        let value = "AWS4-HMAC-SHA256 Credential=NONOPROFILE0DEVRO01/20261105/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc";
        let h = headers(&[("Authorization", value), ("authorization", value)]);
        assert_eq!(sigv4_access_key_id(&h), None);
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
            region: SigningRegion::Fixed(region.to_string()),
            service_label: None,
            service: service.to_string(),
            credentials: super::super::route::AwsRouteCredentials::Single {
                profile_key: None,
                provider,
            },
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

        let result = sign_request(
            &route,
            "us-east-1",
            route.select_provider(&[]).unwrap().provider,
            "POST",
            url,
            &clean_headers,
            body,
        )
        .await;

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

        let headers = sign_request(
            &route,
            "eu-west-1",
            route.select_provider(&[]).unwrap().provider,
            "PUT",
            url,
            &clean_headers,
            body,
        )
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
            region: SigningRegion::Fixed("us-east-1".to_string()),
            service_label: None,
            service: "bedrock".to_string(),
            credentials: super::super::route::AwsRouteCredentials::Single {
                profile_key: None,
                provider,
            },
        };
        let url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke";
        let clean_headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let headers = sign_request(
            &route,
            "us-east-1",
            route.select_provider(&[]).unwrap().provider,
            "POST",
            url,
            &clean_headers,
            b"{}",
        )
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

    #[tokio::test]
    async fn sign_request_scope_follows_supplied_region() {
        let route = make_static_route("eks", "us-east-1");
        let url = "https://eks.eu-central-1.amazonaws.com/clusters";
        let auth = |h: Vec<(String, String)>| {
            h.into_iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v)
                .unwrap()
        };
        let a = auth(
            sign_request(
                &route,
                "eu-central-1",
                route.select_provider(&[]).unwrap().provider,
                "GET",
                url,
                &[],
                b"",
            )
            .await
            .unwrap(),
        );
        let b = auth(
            sign_request(
                &route,
                "us-west-2",
                route.select_provider(&[]).unwrap().provider,
                "GET",
                url,
                &[],
                b"",
            )
            .await
            .unwrap(),
        );
        assert!(a.contains("/eu-central-1/eks/aws4_request"), "{a}");
        assert!(b.contains("/us-west-2/eks/aws4_request"), "{b}");
    }
}
