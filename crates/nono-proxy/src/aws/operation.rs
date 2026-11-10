//! Resolve the AWS operation name of a request for `endpoint_policy`
//! `operations` matching.
//!
//! The wire protocol is detected the way the AWS front end claims requests
//! (Smithy claim rules), and the operation is read only from that protocol's
//! location. A request that also carries another protocol's operation field,
//! or whose operation location is missing, malformed or ambiguous, resolves
//! to [`UNKNOWN_OPERATION`].
//!
//! Inputs must be the exact bytes that are signed and forwarded upstream.

pub use crate::config::UNKNOWN_OPERATION;

/// Wire protocol detected for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsProtocol {
    /// `awsJson1_0` / `awsJson1_1`: operation in `X-Amz-Target`.
    Json,
    /// `awsQuery` / `ec2Query` POST: `Action` in the form body.
    Query,
    /// `awsQuery` / `ec2Query` GET: `Action` in the query string.
    QueryGet,
    /// `rpcv2Cbor` / `rpcv2Json`: operation in the URL path.
    RpcV2,
    /// Not claimed by a supported protocol (REST services and the like).
    None,
}

impl AwsProtocol {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Query => "query",
            Self::QueryGet => "query-get",
            Self::RpcV2 => "rpcv2",
            Self::None => "none",
        }
    }
}

/// Operation name (or `Unknown`) with the protocol it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOperation {
    pub name: String,
    pub protocol: AwsProtocol,
}

impl ResolvedOperation {
    fn unknown(protocol: AwsProtocol) -> Self {
        Self {
            name: UNKNOWN_OPERATION.to_string(),
            protocol,
        }
    }

    fn named(name: &str, protocol: AwsProtocol) -> Self {
        if valid_op(name) {
            Self {
                name: name.to_string(),
                protocol,
            }
        } else {
            Self::unknown(protocol)
        }
    }
}

/// ASCII control characters other than horizontal tab.
fn is_ctl(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7f
}

/// Smithy identifier: `[A-Za-z_][A-Za-z0-9_]{0,255}`.
#[must_use]
pub fn valid_op(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    name.len() <= 256 && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn field_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

/// Parsed `Content-Type`: lowercase `type/subtype` and the `charset` parameter.
struct MediaType {
    essence: String,
    charset: Option<String>,
}

fn parse_media_type(value: &str) -> MediaType {
    let mut parts = value.split(';');
    let essence = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let mut charsets = parts.filter_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| v.trim().trim_matches('"').trim().to_ascii_lowercase())
    });
    let mut charset = charsets.next();
    // Repeated charset parameters are ambiguous; treat as unreadable.
    if charsets.next().is_some() {
        charset = Some("ambiguous".to_string());
    }
    MediaType { essence, charset }
}

/// Query-string values for `Action`, in order. `None` when no `Action` key.
fn action_values(pairs: url::form_urlencoded::Parse<'_>) -> Vec<String> {
    pairs
        .filter(|(k, _)| k == "Action")
        .map(|(_, v)| v.into_owned())
        .collect()
}

/// Operation from repeated `Action` values: equal values collapse to one,
/// differing values are ambiguous.
fn single_action(values: &[String], protocol: AwsProtocol) -> ResolvedOperation {
    match values.split_first() {
        Some((first, rest)) if rest.iter().all(|v| v == first) => {
            ResolvedOperation::named(first, protocol)
        }
        _ => ResolvedOperation::unknown(protocol),
    }
}

/// Resolve the operation for a request.
///
/// `headers` is the forwarded+signed list, `raw_path` the request target as
/// written upstream, `strict_ok` whether the strict header parser accepted
/// the head, and `body` the buffered body.
#[must_use]
pub fn resolve(
    method: &str,
    raw_path: &str,
    headers: &[(String, String)],
    strict_ok: bool,
    body: &[u8],
) -> ResolvedOperation {
    use AwsProtocol as P;
    if !strict_ok {
        return ResolvedOperation::unknown(P::None);
    }
    // Control characters (a bare CR, for one) can be read as line breaks by
    // other HTTP parsers, so the header and path split would be ambiguous.
    if raw_path.bytes().any(is_ctl)
        || headers
            .iter()
            .any(|(n, v)| n.bytes().any(is_ctl) || v.bytes().any(is_ctl))
    {
        return ResolvedOperation::unknown(P::None);
    }
    let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
    let has_target = !field_values(headers, "x-amz-target").is_empty()
        || !field_values(headers, "x-amzn-target").is_empty();
    let query_has_action =
        url::form_urlencoded::parse(query.as_bytes()).any(|(k, _)| k == "Action");
    let post = method == "POST";

    // 1. RPCv2.
    let smithy = field_values(headers, "smithy-protocol");
    if smithy.len() > 1 {
        return ResolvedOperation::unknown(P::None);
    }
    if post
        && smithy.first().is_some_and(|v| {
            let v = v.trim();
            v.eq_ignore_ascii_case("rpc-v2-cbor") || v.eq_ignore_ascii_case("rpc-v2-json")
        })
    {
        if has_target || query_has_action {
            return ResolvedOperation::unknown(P::RpcV2);
        }
        return resolve_rpcv2(path);
    }

    let content_types = field_values(headers, "content-type");
    if content_types.len() > 1 {
        return ResolvedOperation::unknown(P::None);
    }
    let media = content_types.first().map(|v| parse_media_type(v));

    if let Some(media) = &media {
        // 2. JSON.
        if post
            && matches!(
                media.essence.as_str(),
                "application/x-amz-json-1.0" | "application/x-amz-json-1.1"
            )
        {
            let targets = field_values(headers, "x-amz-target");
            if targets.len() != 1
                || !field_values(headers, "x-amzn-target").is_empty()
                || query_has_non_empty_action(query)
            {
                return ResolvedOperation::unknown(P::Json);
            }
            return match targets[0].trim().split_once('.') {
                Some((svc, op)) if valid_op(svc) && valid_op(op) => {
                    ResolvedOperation::named(op, P::Json)
                }
                _ => ResolvedOperation::unknown(P::Json),
            };
        }

        // 3. Query POST.
        if post && media.essence == "application/x-www-form-urlencoded" {
            let encoded = field_values(headers, "content-encoding")
                .iter()
                .any(|v| !v.trim().eq_ignore_ascii_case("identity"));
            let bad_charset = media
                .charset
                .as_deref()
                .is_some_and(|c| c != "utf-8" && c != "us-ascii");
            if encoded || bad_charset || has_target || query_has_action {
                return ResolvedOperation::unknown(P::Query);
            }
            let values = action_values(url::form_urlencoded::parse(body));
            return single_action(&values, P::Query);
        }
        return ResolvedOperation::unknown(P::None);
    }

    // 4. Query GET.
    if method == "GET" && body.is_empty() {
        if has_target {
            return ResolvedOperation::unknown(P::QueryGet);
        }
        let values = action_values(url::form_urlencoded::parse(query.as_bytes()));
        return single_action(&values, P::QueryGet);
    }

    // 5. Anything else.
    ResolvedOperation::unknown(P::None)
}

fn query_has_non_empty_action(query: &str) -> bool {
    url::form_urlencoded::parse(query.as_bytes()).any(|(k, v)| k == "Action" && !v.is_empty())
}

fn resolve_rpcv2(path: &str) -> ResolvedOperation {
    let unknown = || ResolvedOperation::unknown(AwsProtocol::RpcV2);
    let Some(rest) = path.strip_prefix('/') else {
        return unknown();
    };
    if path.contains('%') {
        return unknown();
    }
    let segments: Vec<&str> = rest.split('/').collect();
    if segments
        .iter()
        .any(|s| s.is_empty() || *s == "." || *s == "..")
    {
        return unknown();
    }
    match segments.as_slice() {
        [.., "service", svc, "operation", op] if valid_op(svc) => {
            ResolvedOperation::named(op, AwsProtocol::RpcV2)
        }
        _ => unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AwsProtocol as P;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn check(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        name: &str,
        protocol: AwsProtocol,
    ) {
        let got = resolve(method, path, &h(headers), true, body);
        assert_eq!(
            got,
            ResolvedOperation {
                name: name.to_string(),
                protocol
            },
            "{method} {path} {headers:?}"
        );
    }

    const JSON11: (&str, &str) = ("Content-Type", "application/x-amz-json-1.1");
    const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");

    #[test]
    fn json_target() {
        check(
            "POST",
            "/",
            &[JSON11, ("X-Amz-Target", "AmazonSSM.GetParameter")],
            b"{}",
            "GetParameter",
            P::Json,
        );
        check(
            "POST",
            "/",
            &[
                ("content-type", "Application/X-Amz-JSON-1.1; charset=UTF-8"),
                ("x-amz-target", "AmazonSSM.GetParameter"),
            ],
            b"{}",
            "GetParameter",
            P::Json,
        );
    }

    #[test]
    fn json_content_type_is_exact_media_type() {
        check(
            "POST",
            "/",
            &[
                ("Content-Type", "text/plain; x=application/x-amz-json-1.1"),
                ("X-Amz-Target", "AmazonSSM.GetParameter"),
            ],
            b"",
            "Unknown",
            P::None,
        );
        check(
            "GET",
            "/",
            &[JSON11, ("X-Amz-Target", "A.B")],
            b"",
            "Unknown",
            P::None,
        );
    }

    #[test]
    fn json_malformed_target() {
        for t in ["AmazonSSM", "A.B.C", "Svc.", ".Op", "Svc.Op-x", ""] {
            check(
                "POST",
                "/",
                &[JSON11, ("X-Amz-Target", t)],
                b"",
                "Unknown",
                P::Json,
            );
        }
    }

    #[test]
    fn json_duplicate_target_is_unknown() {
        for (a, b) in [("A.Get", "A.Get"), ("A.Get", "A.Delete")] {
            check(
                "POST",
                "/",
                &[JSON11, ("X-Amz-Target", a), ("x-amz-target", b)],
                b"",
                "Unknown",
                P::Json,
            );
        }
    }

    #[test]
    fn json_cross_protocol_action_is_unknown() {
        check(
            "POST",
            "/?Action=DeleteParameter",
            &[JSON11, ("X-Amz-Target", "A.GetParameter")],
            b"",
            "Unknown",
            P::Json,
        );
        // A JSON body is not form data.
        check(
            "POST",
            "/",
            &[JSON11, ("X-Amz-Target", "A.GetParameter")],
            b"x=1&Action=DeleteParameter",
            "GetParameter",
            P::Json,
        );
    }

    #[test]
    fn query_post_action() {
        check(
            "POST",
            "/",
            &[FORM],
            b"Action=DescribeInstances&Version=2016-11-15",
            "DescribeInstances",
            P::Query,
        );
        check(
            "POST",
            "/",
            &[FORM],
            b"Action=Describe%49nstances",
            "DescribeInstances",
            P::Query,
        );
        check(
            "POST",
            "/",
            &[FORM],
            b"Action=Describe+Instances",
            "Unknown",
            P::Query,
        );
        check("POST", "/", &[FORM], b"Action=", "Unknown", P::Query);
        check("POST", "/", &[FORM], b"Version=1", "Unknown", P::Query);
        check(
            "POST",
            "/",
            &[FORM],
            b"action=DeleteThing",
            "Unknown",
            P::Query,
        );
    }

    #[test]
    fn query_post_repeated_action() {
        check("POST", "/", &[FORM], b"Action=A&Action=A", "A", P::Query);
        check(
            "POST",
            "/",
            &[FORM],
            b"Action=A&Action=B",
            "Unknown",
            P::Query,
        );
    }

    #[test]
    fn query_post_cross_protocol_is_unknown() {
        check(
            "POST",
            "/?Action=A",
            &[FORM],
            b"Action=A",
            "Unknown",
            P::Query,
        );
        check(
            "POST",
            "/",
            &[FORM, ("X-Amz-Target", "S.Delete")],
            b"Action=A",
            "Unknown",
            P::Query,
        );
    }

    #[test]
    fn query_post_unreadable_body_is_unknown() {
        check(
            "POST",
            "/",
            &[(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-16",
            )],
            b"Action=A",
            "Unknown",
            P::Query,
        );
        check(
            "POST",
            "/",
            &[FORM, ("Content-Encoding", "gzip")],
            b"Action=A",
            "Unknown",
            P::Query,
        );
        check(
            "POST",
            "/",
            &[FORM, ("Content-Encoding", "identity")],
            b"Action=A",
            "A",
            P::Query,
        );
        check("POST", "/", &[FORM], b"Action=A\xff", "Unknown", P::Query);
    }

    #[test]
    fn control_characters_in_headers_or_path_are_unknown() {
        for (path, header) in [
            ("/", "a\rX-Amz-Target: AmazonSSM.DeleteParameter"),
            ("/", "a\nb"),
            ("/", "a\0b"),
            ("/\r?x", "ok"),
        ] {
            let got = resolve(
                "POST",
                path,
                &h(&[
                    JSON11,
                    ("X-Amz-Target", "A.GetParameter"),
                    ("X-Foo", header),
                ]),
                true,
                b"",
            );
            assert_eq!(
                got,
                ResolvedOperation::unknown(P::None),
                "{path:?} {header:?}"
            );
        }
        // Horizontal tab is a legal field-value character.
        check(
            "POST",
            "/",
            &[
                JSON11,
                ("X-Amz-Target", "A.GetParameter"),
                ("X-Foo", "a\tb"),
            ],
            b"",
            "GetParameter",
            P::Json,
        );
    }

    #[test]
    fn json_with_amzn_target_is_unknown() {
        check(
            "POST",
            "/",
            &[
                JSON11,
                ("X-Amz-Target", "A.GetParameter"),
                ("X-Amzn-Target", "A.DeleteParameter"),
            ],
            b"",
            "Unknown",
            P::Json,
        );
    }

    #[test]
    fn repeated_charset_is_unknown() {
        check(
            "POST",
            "/",
            &[(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8; charset=utf-16",
            )],
            b"Action=A",
            "Unknown",
            P::Query,
        );
    }

    #[test]
    fn duplicate_content_type_is_none() {
        check("POST", "/", &[FORM, FORM], b"Action=A", "Unknown", P::None);
    }

    #[test]
    fn query_get() {
        check(
            "GET",
            "/?Action=DescribeInstances&Version=2016-11-15",
            &[],
            b"",
            "DescribeInstances",
            P::QueryGet,
        );
        check("GET", "/?Action=A", &[], b"x", "Unknown", P::None);
        check(
            "GET",
            "/?Action=A",
            &[("Content-Type", "text/plain")],
            b"",
            "Unknown",
            P::None,
        );
        check("GET", "/bucket/key", &[], b"", "Unknown", P::QueryGet);
        check(
            "GET",
            "/?Action=A",
            &[("X-Amz-Target", "S.B")],
            b"",
            "Unknown",
            P::QueryGet,
        );
    }

    const RPC: (&str, &str) = ("Smithy-Protocol", "rpc-v2-cbor");

    #[test]
    fn rpcv2_path() {
        let p = "/service/GraniteServiceVersion20100801/operation/GetMetricData";
        check("POST", p, &[RPC], b"", "GetMetricData", P::RpcV2);
        check(
            "POST",
            &format!("/prefix{p}"),
            &[RPC],
            b"",
            "GetMetricData",
            P::RpcV2,
        );
        check(
            "POST",
            &format!("{p}?x=1"),
            &[RPC],
            b"",
            "GetMetricData",
            P::RpcV2,
        );
    }

    #[test]
    fn rpcv2_ambiguity_is_unknown() {
        let p = "/service/Svc/operation/GetMetricData";
        check(
            "POST",
            p,
            &[RPC, ("X-Amz-Target", "S.Delete")],
            b"",
            "Unknown",
            P::RpcV2,
        );
        check(
            "POST",
            p,
            &[RPC, ("X-Amzn-Target", "S.Delete")],
            b"",
            "Unknown",
            P::RpcV2,
        );
        check(
            "POST",
            &format!("{p}?Action=Delete"),
            &[RPC],
            b"",
            "Unknown",
            P::RpcV2,
        );
        for bad in [
            "/service/Svc/operation/../operation/Get",
            "/service/Svc/operation/Get%41",
            "/service/Svc/./operation/Get",
            "/service/Svc/operation//Get",
            "/service/Svc/other/Get",
        ] {
            check("POST", bad, &[RPC], b"", "Unknown", P::RpcV2);
        }
        check("POST", p, &[RPC, RPC], b"", "Unknown", P::None);
    }

    #[test]
    fn strict_parse_failure_is_unknown() {
        let got = resolve(
            "POST",
            "/",
            &h(&[JSON11, ("X-Amz-Target", "A.Get")]),
            false,
            b"",
        );
        assert_eq!(got, ResolvedOperation::unknown(P::None));
    }

    #[test]
    fn literal_unknown_is_unknown() {
        check("POST", "/", &[FORM], b"Action=Unknown", "Unknown", P::Query);
    }

    #[test]
    fn valid_op_rules() {
        assert!(valid_op("GetParameter"));
        assert!(valid_op("_x1"));
        assert!(!valid_op(""));
        assert!(!valid_op("1abc"));
        assert!(!valid_op("a.b"));
        assert!(!valid_op(&"a".repeat(257)));
    }
}
