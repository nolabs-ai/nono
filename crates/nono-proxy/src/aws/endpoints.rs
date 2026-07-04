//! AWS endpoint parsing: extract the SigV4 region and service from an `amazonaws.com` hostname.
//!
//! Supported hostname shapes:
//! - Regional:   `{service}.{region}.amazonaws.com`
//! - Global:     `{service}.amazonaws.com`
//! - FIPS:       `{service}-fips.{region}.amazonaws.com` (`-fips` is stripped)
//!
//! `api.aws` dual-stack endpoints are not supported; supply explicit
//! `aws_auth.region` and `aws_auth.service` config values for those.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use tracing::warn;

fn region_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[a-z]{2,3}-(?:[a-z]+-)?[a-z]+-\d+$").expect("static regex is valid")
    })
}

fn service_map() -> &'static HashMap<&'static str, &'static str> {
    // Maps hostname service segment to SigV4 signing name. Some segments differ
    // from the signing name (e.g. "bedrock-runtime" signs as "bedrock", "email" as "ses").
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            // Bedrock: multiple host prefixes, one signing name.
            ("bedrock", "bedrock"),
            ("bedrock-runtime", "bedrock"),
            ("bedrock-agent", "bedrock"),
            ("bedrock-agent-runtime", "bedrock"),
            ("bedrock-data-automation", "bedrock"),
            ("bedrock-data-automation-runtime", "bedrock"),
            // Core services
            ("dynamodb", "dynamodb"),
            ("s3", "s3"),
            ("lambda", "lambda"),
            ("sqs", "sqs"),
            ("sns", "sns"),
            ("logs", "logs"), // CloudWatch Logs
            // API Gateway
            ("execute-api", "execute-api"),
            // Identity / signing
            ("sts", "sts"),
            ("iam", "iam"),
            // Email: host prefix differs from signing name
            ("email", "ses"),
            ("ses", "ses"),
        ])
    })
}

/// Parsed components of an `amazonaws.com` hostname.
#[derive(Debug, PartialEq, Eq)]
pub struct AwsUrlParts<'a> {
    /// Service segment with any `-fips` suffix stripped (e.g. `"bedrock-runtime"`, `"iam"`).
    pub normalized_service: &'a str,
    /// Region code, or `None` for global endpoints.
    pub region: Option<&'a str>,
}

impl<'a> AwsUrlParts<'a> {
    /// Parse an `amazonaws.com` hostname into its service and region components.
    /// Returns `None` for unrecognised shapes or invalid region codes.
    #[must_use]
    pub fn parse(host: &'a str) -> Option<Self> {
        match host.split('.').collect::<Vec<_>>().as_slice() {
            [service_raw, region, "amazonaws", "com"] => {
                if !region_re().is_match(region) {
                    return None;
                }
                Some(AwsUrlParts {
                    normalized_service: service_raw.strip_suffix("-fips").unwrap_or(service_raw),
                    region: Some(region),
                })
            }
            [service_raw, "amazonaws", "com"] => Some(AwsUrlParts {
                normalized_service: service_raw.strip_suffix("-fips").unwrap_or(service_raw),
                region: None,
            }),
            _ => None,
        }
    }

    /// Look up the SigV4 signing service name for this endpoint.
    /// Returns `None` for unrecognised service segments.
    #[must_use]
    pub fn signing_service(&self) -> Option<&'static str> {
        service_map().get(self.normalized_service).copied()
    }
}

/// Resolve the SigV4 `(region, service)` pair for an AWS route.
///
/// Config values in `aws_auth` take precedence. When either is absent, the
/// host of `upstream` is parsed as an `amazonaws.com` endpoint to fill in the
/// missing value. Returns `None` and emits a warning if resolution fails.
#[must_use]
pub fn resolve_signing_params(
    prefix: &str,
    aws_auth: &crate::config::AwsAuthConfig,
    upstream: &str,
) -> Option<(String, String)> {
    let upstream_host: String;
    let parsed_host = if aws_auth.region.is_none() || aws_auth.service.is_none() {
        upstream_host = match url::Url::parse(upstream)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
        {
            Some(h) => h,
            None => {
                warn!(
                    "AWS route '{}': upstream '{}' is not a valid URL with a \
                     host component; fix the upstream or set aws_auth.region \
                     and aws_auth.service explicitly — skipping this route.",
                    prefix, upstream
                );
                return None;
            }
        };
        let h = AwsUrlParts::parse(&upstream_host);
        if h.is_none() {
            warn!(
                "AWS route '{}': upstream host '{}' is not a recognised \
                 amazonaws.com endpoint; set aws_auth.region and \
                 aws_auth.service explicitly — skipping this route.",
                prefix, upstream_host
            );
            return None;
        }
        h
    } else {
        None
    };

    // Region: explicit config wins; otherwise derive from the parsed host.
    let region = match aws_auth.region.as_deref() {
        Some(r) => r.to_owned(),
        None => match parsed_host.as_ref().and_then(|h| h.region) {
            Some(r) => r.to_owned(),
            None => {
                warn!(
                    "AWS route '{}': could not determine region from upstream \
                     host '{}' (global endpoint?); set aws_auth.region \
                     explicitly — skipping this route.",
                    prefix, upstream
                );
                return None;
            }
        },
    };

    // Service: explicit config wins; otherwise look up from the parsed host.
    let service = match aws_auth.service.as_deref() {
        Some(s) => s.to_owned(),
        None => {
            let seg = parsed_host
                .as_ref()
                .map(|h| h.normalized_service)
                .unwrap_or("");
            match parsed_host.as_ref().and_then(|h| h.signing_service()) {
                Some(s) => s.to_owned(),
                None => {
                    warn!(
                        "AWS route '{}': service segment '{}' from upstream \
                         host '{}' is not in the signing-name table; set \
                         aws_auth.service explicitly — skipping this route.",
                        prefix, seg, upstream
                    );
                    return None;
                }
            }
        }
    };

    Some((region, service))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // =========================================================================
    // AwsUrlParts::parse — valid inputs
    // =========================================================================

    /// Canonical hostname shapes and region varieties that must parse correctly.
    #[test]
    fn parse_valid_hosts() {
        // (host, expected_normalized_service, expected_region)
        let cases: &[(&str, &str, Option<&str>)] = &[
            // Regional — standard
            (
                "bedrock-runtime.us-east-1.amazonaws.com",
                "bedrock-runtime",
                Some("us-east-1"),
            ),
            ("s3.eu-west-2.amazonaws.com", "s3", Some("eu-west-2")),
            (
                "lambda.ap-southeast-1.amazonaws.com",
                "lambda",
                Some("ap-southeast-1"),
            ),
            // Regional — newer geo prefixes
            (
                "sts.il-central-1.amazonaws.com",
                "sts",
                Some("il-central-1"),
            ),
            (
                "sts.ap-southeast-7.amazonaws.com",
                "sts",
                Some("ap-southeast-7"),
            ),
            // Regional — GovCloud (extra word in region code)
            (
                "s3.us-gov-east-1.amazonaws.com",
                "s3",
                Some("us-gov-east-1"),
            ),
            // Regional — ISO partition
            (
                "s3.us-iso-east-1.amazonaws.com",
                "s3",
                Some("us-iso-east-1"),
            ),
            // Regional — FIPS suffix stripped
            (
                "bedrock-runtime-fips.us-east-1.amazonaws.com",
                "bedrock-runtime",
                Some("us-east-1"),
            ),
            // Global (no region)
            ("iam.amazonaws.com", "iam", None),
            ("sts.amazonaws.com", "sts", None),
        ];
        for &(host, expected_service, expected_region) in cases {
            let h = AwsUrlParts::parse(host).unwrap();
            assert_eq!(h.normalized_service, expected_service, "host={host:?}");
            assert_eq!(h.region, expected_region, "host={host:?}");
        }
    }

    // =========================================================================
    // AwsUrlParts::parse — rejected inputs
    // =========================================================================

    /// Inputs that must return None, with the reason documented inline.
    #[test]
    fn parse_rejects_invalid_hosts() {
        let cases: &[(&str, &str)] = &[
            ("api.openai.com", "non-amazonaws TLD"),
            (
                "bedrock-runtime.us-east-1.api.aws",
                "api.aws dual-stack not handled",
            ),
            ("localhost", "bare hostname"),
            ("", "empty string"),
            ("amazonaws.com", "too few segments"),
            (
                "extra.bedrock-runtime.us-east-1.amazonaws.com",
                "too many segments",
            ),
            ("s3.US-EAST-1.amazonaws.com", "uppercase region"),
            ("s3.us-east.amazonaws.com", "region missing trailing digit"),
            ("s3.useast1.amazonaws.com", "region missing hyphens"),
            (
                "iam.amazonaws.amazonaws.com",
                "\"amazonaws\" is not a region",
            ),
        ];
        for &(host, reason) in cases {
            assert!(
                AwsUrlParts::parse(host).is_none(),
                "expected None for {host:?} ({reason})"
            );
        }
    }

    // =========================================================================
    // AwsUrlParts::signing_service
    // =========================================================================

    #[test]
    fn signing_service_maps_known_segments() {
        // Identity: segment equals signing name
        let s3 = AwsUrlParts {
            normalized_service: "s3",
            region: None,
        };
        assert_eq!(s3.signing_service(), Some("s3"));

        // Non-obvious: host prefix differs from signing name
        let email = AwsUrlParts {
            normalized_service: "email",
            region: None,
        };
        assert_eq!(email.signing_service(), Some("ses"));

        // Multi-prefix family: bedrock-runtime signs as bedrock
        let runtime = AwsUrlParts {
            normalized_service: "bedrock-runtime",
            region: None,
        };
        assert_eq!(runtime.signing_service(), Some("bedrock"));
    }

    #[test]
    fn signing_service_returns_none_for_unknown_segment() {
        let unknown = AwsUrlParts {
            normalized_service: "unknownsvc",
            region: None,
        };
        assert!(unknown.signing_service().is_none());
    }
}
