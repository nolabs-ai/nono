//! AWS endpoint parsing: extract the SigV4 region and service from an `amazonaws.com` hostname.
//!
//! Supported hostname shapes:
//! - Regional:   `{service}.{region}.amazonaws.com`
//! - Global:     `{service}.amazonaws.com`
//! - FIPS:       `{service}-fips.{region}.amazonaws.com` (`-fips` is stripped)
//!
//! `api.aws` dual-stack endpoints are not supported; supply explicit
//! `aws_auth.region` and `aws_auth.service` config values for those.
//!
//! A route upstream may also be `https://{service}.*.amazonaws.com`, where `*`
//! is the whole region label. The SigV4 region is then derived per request
//! from the intercepted host by [`derive_region`], limited to commercial-partition
//! region codes. Every other wildcard shape on an `amazonaws` host is rejected.

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

fn derived_region_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^[a-z]{2}-(?:central|north|south|east|west|northeast|northwest|southeast|southwest)-[1-9][0-9]?$",
        )
        .expect("static regex is valid")
    })
}

/// Commercial-partition region grammar for derived regions; `cn-` is excluded.
fn is_derived_region(region: &str) -> bool {
    !region.starts_with("cn-") && derived_region_re().is_match(region)
}

fn service_label_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").expect("static regex is valid"))
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

/// How the SigV4 region of an AWS route is determined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningRegion {
    /// Region fixed when the route loads.
    Fixed(String),
    /// Region derived from each request's host (`{service}.*.amazonaws.com`).
    FromRequestHost,
}

/// A validated `https://{service}.*.amazonaws.com` upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsUpstreamPattern {
    /// The literal service label that precedes the wildcard region label.
    pub service_label: String,
}

/// Validate the wildcard shape of an `aws_auth` route upstream.
///
/// Returns `Ok(None)` when the legacy resolution path applies (no `*` in the
/// host, or a wildcard on a non-AWS host), `Ok(Some(_))` for the accepted
/// `{service}.*.amazonaws.com` shape on port 443, and `Err` for any other
/// wildcard on an AWS host or an explicit `region` combined with the wildcard.
///
/// # Errors
///
/// Returns a human-readable message describing the violation.
pub fn validate_aws_upstream(
    upstream: &str,
    aws_auth: &crate::config::AwsAuthConfig,
) -> Result<Option<AwsUpstreamPattern>, String> {
    let Ok(url) = url::Url::parse(upstream) else {
        return Ok(None);
    };
    let Some(host) = url.host_str() else {
        return Ok(None);
    };
    if !host.contains('*') {
        return Ok(None);
    }
    let is_aws_host = host.contains("amazonaws") || host.ends_with(".api.aws");
    if !is_aws_host {
        return Ok(None);
    }

    const SHAPE: &str =
        "the only accepted wildcard upstream is `https://{service}.*.amazonaws.com`";
    let reject = |why: &str| Err(format!("upstream '{upstream}': {why}; {SHAPE}"));

    if url.scheme() != "https" {
        return reject("scheme must be https");
    }
    if url.port().is_some_and(|p| p != 443) {
        return reject("port must be 443");
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return reject("userinfo, path, query, and fragment are not allowed");
    }
    let service_label = match host.split('.').collect::<Vec<_>>().as_slice() {
        [service_label, "*", "amazonaws", "com"] => *service_label,
        _ => return reject("host does not match the accepted shape"),
    };
    if !service_label_re().is_match(service_label)
        || service_label.starts_with("ec2-")
        || matches!(service_label, "compute" | "elb")
    {
        return reject(&format!("service label '{service_label}' is not allowed"));
    }
    if aws_auth.region.is_some() {
        return Err(format!(
            "upstream '{upstream}': aws_auth.region must be omitted with a wildcard region; \
             the region is taken from each request's host"
        ));
    }
    if aws_auth.service.is_none() {
        let base = service_label.strip_suffix("-fips").unwrap_or(service_label);
        if !service_map().contains_key(base) {
            return Err(format!(
                "upstream '{upstream}': service '{base}' is not in the signing-name table; \
                 set aws_auth.service explicitly"
            ));
        }
    }
    Ok(Some(AwsUpstreamPattern {
        service_label: service_label.to_owned(),
    }))
}

/// Derive the SigV4 region from the raw request host of a wildcard-region route.
///
/// `host` must be canonical (lowercase ASCII, no trailing dot, no punycode) so
/// the derived region, the signed host, and the connected host are the same
/// string. The host must be exactly `{service_label}.{region}.amazonaws.com` on
/// port 443, with `region` in the commercial-partition grammar.
#[must_use]
pub fn derive_region(host: &str, port: u16, service_label: &str) -> Option<String> {
    if port != 443
        || host.is_empty()
        || !host.is_ascii()
        || host.split('.').any(|l| l.starts_with("xn--"))
        || nono::net_filter::HostFilter::normalize_authority_host(host) != host
    {
        return None;
    }
    match host.split('.').collect::<Vec<_>>().as_slice() {
        [svc, region, "amazonaws", "com"] if *svc == service_label && is_derived_region(region) => {
            Some((*region).to_owned())
        }
        _ => None,
    }
}

/// Resolve the SigV4 `(region, service)` pair for an AWS route.
///
/// Config values in `aws_auth` take precedence. When either is absent, the
/// host of `upstream` is parsed as an `amazonaws.com` endpoint to fill in the
/// missing value. For a `{service}.*.amazonaws.com` upstream the region is
/// [`SigningRegion::FromRequestHost`]. Returns `None` and emits a warning if
/// resolution fails.
#[must_use]
pub fn resolve_signing_params(
    prefix: &str,
    aws_auth: &crate::config::AwsAuthConfig,
    upstream: &str,
) -> Option<(SigningRegion, String)> {
    if let Ok(Some(pattern)) = validate_aws_upstream(upstream, aws_auth) {
        let service = match aws_auth.service.as_deref() {
            Some(s) => s.to_owned(),
            None => {
                let base = pattern
                    .service_label
                    .strip_suffix("-fips")
                    .unwrap_or(&pattern.service_label);
                service_map().get(base).map(|s| (*s).to_owned())?
            }
        };
        return Some((SigningRegion::FromRequestHost, service));
    }

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

    Some((SigningRegion::Fixed(region), service))
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

    // =========================================================================
    // Wildcard-region routes
    // =========================================================================

    fn cfg(region: Option<&str>, service: Option<&str>) -> crate::config::AwsAuthConfig {
        crate::config::AwsAuthConfig {
            profile: None,
            region: region.map(str::to_owned),
            service: service.map(str::to_owned),
        }
    }

    #[test]
    fn validate_accepts_wildcard_region_shape() {
        for (upstream, service) in [
            ("https://s3.*.amazonaws.com", None),
            ("https://bedrock-runtime-fips.*.amazonaws.com", None),
            ("https://eks.*.amazonaws.com", Some("eks")),
            ("https://eks.*.amazonaws.com:443", Some("eks")),
            ("https://eks.*.amazonaws.com/", Some("eks")),
        ] {
            let got = validate_aws_upstream(upstream, &cfg(None, service)).unwrap();
            assert!(got.is_some(), "{upstream}");
        }
    }

    #[test]
    fn validate_rejects_other_wildcard_shapes() {
        for upstream in [
            "https://*.amazonaws.com",
            "https://*.*.amazonaws.com",
            "https://*.s3.*.amazonaws.com",
            "https://*.eks.us-east-1.amazonaws.com",
            "https://eks.*.amazonaws.com.cn",
            "https://eks.*.api.aws",
            "https://eks.*.amazonaws.eu",
            "https://e*s.*.amazonaws.com",
            "https://eks.us-*.amazonaws.com",
            "http://eks.*.amazonaws.com",
            "https://eks.*.amazonaws.com:8443",
            "https://user@eks.*.amazonaws.com",
            "https://eks.*.amazonaws.com/path",
            "https://eks.*.amazonaws.com/?q=1",
            "https://eks.*.amazonaws.com/#f",
            "https://ec2-1.*.amazonaws.com",
            "https://elb.*.amazonaws.com",
        ] {
            assert!(
                validate_aws_upstream(upstream, &cfg(None, Some("eks"))).is_err(),
                "{upstream}"
            );
        }
    }

    #[test]
    fn validate_requires_known_service_or_explicit_service() {
        assert!(validate_aws_upstream("https://eks.*.amazonaws.com", &cfg(None, None)).is_err());
        assert!(
            validate_aws_upstream("https://eks.*.amazonaws.com", &cfg(None, Some("eks"))).is_ok()
        );
    }

    #[test]
    fn validate_rejects_explicit_region_with_wildcard() {
        assert!(
            validate_aws_upstream(
                "https://eks.*.amazonaws.com",
                &cfg(Some("us-east-1"), Some("eks"))
            )
            .is_err()
        );
    }

    #[test]
    fn validate_ignores_concrete_and_non_aws_hosts() {
        let c = cfg(Some("us-east-1"), Some("bedrock"));
        for upstream in [
            "https://s3.us-gov-east-1.amazonaws.com",
            "https://*.example.com",
        ] {
            assert_eq!(validate_aws_upstream(upstream, &c).unwrap(), None);
        }
    }

    #[test]
    fn resolve_wildcard_returns_request_host_region() {
        let (region, service) = resolve_signing_params(
            "p",
            &cfg(None, None),
            "https://bedrock-runtime.*.amazonaws.com",
        )
        .unwrap();
        assert_eq!(region, SigningRegion::FromRequestHost);
        assert_eq!(service, "bedrock");
    }

    #[test]
    fn derived_region_grammar() {
        for ok in [
            "us-east-1",
            "ap-southeast-7",
            "il-central-1",
            "mx-central-1",
            "ca-west-1",
        ] {
            assert!(is_derived_region(ok), "{ok}");
        }
        for bad in [
            "us-gov-west-1",
            "us-iso-east-1",
            "us-isob-east-1",
            "cn-north-1",
            "eusc-de-east-1",
            "us-east-0",
            "us-east-100",
            "compute-1",
            "US-EAST-1",
        ] {
            assert!(!is_derived_region(bad), "{bad}");
        }
    }

    #[test]
    fn derive_region_accepts_canonical_host() {
        assert_eq!(
            derive_region("eks.eu-west-1.amazonaws.com", 443, "eks").as_deref(),
            Some("eu-west-1")
        );
    }

    #[test]
    fn derive_region_rejects_noncanonical_or_wrong_shape() {
        for (host, port) in [
            ("EKS.us-west-2.amazonaws.com", 443),
            ("eks.us-west-2.amazonaws.com.", 443),
            ("eks.us-west-2.amazonaws.com", 8443),
            ("xn--eks.us-west-2.amazonaws.com", 443),
            ("eks.xn--us-west-2.amazonaws.com", 443),
            ("ekş.us-west-2.amazonaws.com", 443),
            ("lambda.us-west-2.amazonaws.com", 443),
            ("eks.amazonaws.com", 443),
            ("a.eks.us-west-2.amazonaws.com", 443),
            ("eks..amazonaws.com", 443),
            ("eks.us-gov-west-1.amazonaws.com", 443),
            ("127.0.0.1", 443),
            ("[::1]", 443),
            ("", 443),
            // T6: customer-controlled names under amazonaws.com
            ("ec2-1-2-3-4.compute-1.amazonaws.com", 443),
            ("ec2-1-2-3-4.us-west-2.compute.amazonaws.com", 443),
            ("x.us-east-1.elb.amazonaws.com", 443),
            ("id.execute-api.us-east-1.amazonaws.com", 443),
            ("bucket.s3.us-east-1.amazonaws.com", 443),
        ] {
            assert_eq!(derive_region(host, port, "eks"), None, "{host}:{port}");
        }
    }
}
