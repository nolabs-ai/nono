use super::OAuthCaptureStore;
use super::endpoint::{LoadedOAuthEndpoint, ResponseField, ResponseFieldFormat, provider_consumer};
use crate::config::OAuthTokenRequestBodyFormat;
use crate::error::{ProxyError, Result};
use crate::jwt_phantom::jwt_shaped_phantom;
use crate::token::NonceResolver;
use serde_json::Value;
use std::collections::HashSet;
use tracing::debug;

impl OAuthCaptureStore {
    /// Resolve an OAuth-capture phantom in a token endpoint request header
    /// value (e.g. `Authorization: Bearer <phantom>`) back to the real token
    /// for this endpoint's provider. `None` leaves the value unchanged.
    pub fn rewrite_request_header_value(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        value: &str,
    ) -> Option<String> {
        let consumer = provider_consumer(&endpoint.provider);
        self.rewrite_header_value(value, &consumer)
    }

    pub fn rewrite_request_body(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        if body.is_empty() || endpoint.request_nonce_fields.is_empty() {
            return Ok(body.to_vec());
        }

        match endpoint.request_body {
            OAuthTokenRequestBodyFormat::Json => self.rewrite_json_request_body(endpoint, body),
            OAuthTokenRequestBodyFormat::Form => self.rewrite_form_request_body(endpoint, body),
            OAuthTokenRequestBodyFormat::Auto => {
                if serde_json::from_slice::<Value>(body).is_ok() {
                    self.rewrite_json_request_body(endpoint, body)
                } else {
                    self.rewrite_form_request_body(endpoint, body)
                }
            }
        }
    }

    fn rewrite_json_request_body(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let mut json: Value = serde_json::from_slice(body).map_err(|err| {
            ProxyError::HttpParse(format!(
                "OAuth token request body is not JSON for provider '{}': {err}",
                endpoint.provider
            ))
        })?;
        let mut changed = false;
        let consumer = provider_consumer(&endpoint.provider);
        for field in &endpoint.request_nonce_fields {
            let Some(value) = value_at_path_mut(&mut json, field) else {
                continue;
            };
            let Some(phantom) = value.as_str() else {
                continue;
            };
            let Some(real) = self.resolve(phantom, &consumer) else {
                continue;
            };
            let real = std::str::from_utf8(&real).map_err(|_| {
                ProxyError::HttpParse(format!(
                    "OAuth phantom for provider '{}' resolved to non-UTF-8 material",
                    endpoint.provider
                ))
            })?;
            *value = Value::String(real.to_string());
            changed = true;
        }

        if changed {
            serde_json::to_vec(&json).map_err(|err| {
                ProxyError::HttpParse(format!(
                    "failed to encode rewritten OAuth request JSON: {err}"
                ))
            })
        } else {
            Ok(body.to_vec())
        }
    }

    fn rewrite_form_request_body(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let parsed = url::form_urlencoded::parse(body).collect::<Vec<_>>();
        if parsed.is_empty() {
            if self.contains_phantom(body) {
                return Err(ProxyError::HttpParse(format!(
                    "OAuth token request body for provider '{}' contains a phantom but is neither JSON nor form-urlencoded",
                    endpoint.provider
                )));
            }
            return Ok(body.to_vec());
        }

        let request_fields = endpoint
            .request_nonce_fields
            .iter()
            .filter(|field| !field.contains('.'))
            .cloned()
            .collect::<HashSet<_>>();
        let consumer = provider_consumer(&endpoint.provider);
        let mut changed = false;
        let mut serialized = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in parsed {
            if request_fields.contains(name.as_ref())
                && let Some(real) = self.resolve(value.as_ref(), &consumer)
            {
                let real = std::str::from_utf8(&real).map_err(|_| {
                    ProxyError::HttpParse(format!(
                        "OAuth phantom for provider '{}' resolved to non-UTF-8 material",
                        endpoint.provider
                    ))
                })?;
                serialized.append_pair(&name, real);
                changed = true;
                continue;
            }
            serialized.append_pair(&name, &value);
        }

        if changed {
            Ok(serialized.finish().into_bytes())
        } else {
            Ok(body.to_vec())
        }
    }

    pub fn rewrite_response_body(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        if body.is_empty() {
            return Ok(body.to_vec());
        }

        // config.rs documents that a Content-Type matching neither encoding is
        // rejected rather than guessed at, in every mode, not only Auto.
        let hint = match content_type_hint(headers) {
            Some(ContentTypeHint::Other) => {
                return Err(ProxyError::HttpParse(format!(
                    "OAuth token response for provider '{}' has a Content-Type that is neither \
                     JSON nor form-urlencoded",
                    endpoint.provider
                )));
            }
            hint => hint,
        };
        match endpoint.response_body {
            OAuthTokenRequestBodyFormat::Json => {
                if matches!(hint, Some(ContentTypeHint::Form)) {
                    return Err(ProxyError::HttpParse(format!(
                        "OAuth token response for provider '{}' is configured as JSON but the \
                         Content-Type header indicates form-urlencoded",
                        endpoint.provider
                    )));
                }
                self.rewrite_json_response_body(endpoint, body)
            }
            OAuthTokenRequestBodyFormat::Form => {
                if matches!(hint, Some(ContentTypeHint::Json)) {
                    return Err(ProxyError::HttpParse(format!(
                        "OAuth token response for provider '{}' is configured as form-urlencoded \
                         but the Content-Type header indicates JSON",
                        endpoint.provider
                    )));
                }
                self.rewrite_form_response_body(endpoint, body)
            }
            OAuthTokenRequestBodyFormat::Auto => {
                if matches!(hint, Some(ContentTypeHint::Json)) {
                    self.rewrite_json_response_body(endpoint, body)
                } else if matches!(hint, Some(ContentTypeHint::Form)) {
                    self.rewrite_form_response_body(endpoint, body)
                } else {
                    if serde_json::from_slice::<Value>(body).is_ok() {
                        return self.rewrite_json_response_body(endpoint, body);
                    }
                    if looks_like_json(body) {
                        // A body that opens like JSON but fails to parse is far
                        // more likely truncated (e.g. from a peer closing
                        // without TLS close_notify mid-response) than
                        // genuinely form-urlencoded. `url::form_urlencoded`
                        // accepts almost any bytes, so treating this as a form
                        // body risks forwarding a real token still present in
                        // the unparsed JSON text. Fail closed instead.
                        return Err(ProxyError::HttpParse(format!(
                            "OAuth token response for provider '{}' looks like JSON but failed \
                             to parse; refusing to reinterpret as form-urlencoded",
                            endpoint.provider
                        )));
                    }
                    self.rewrite_form_response_body(endpoint, body)
                }
            }
        }
    }

    fn rewrite_json_response_body(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let mut json: Value = serde_json::from_slice(body).map_err(|err| {
            ProxyError::HttpParse(format!(
                "OAuth token response body is not JSON for provider '{}': {err}",
                endpoint.provider
            ))
        })?;
        let configured_paths = endpoint
            .response_fields
            .iter()
            .map(|field| field.path.as_str())
            .collect::<HashSet<_>>();
        let mut changed = false;
        let mut rewritten_fields = 0usize;
        for field in &endpoint.response_fields {
            let Some(value) = value_at_path_mut(&mut json, &field.path) else {
                continue;
            };
            let Some(real) = value.as_str() else {
                continue;
            };
            if real.is_empty() {
                continue;
            }
            let (key, visible) = mint_response_phantom(&endpoint.provider, field, real)?;
            self.store_phantom(&key, real.as_bytes(), &endpoint.admitted_consumers)?;
            *value = Value::String(visible);
            changed = true;
            rewritten_fields += 1;
        }
        reject_unrewritten_token_fields(
            &json,
            &configured_paths,
            &format!("provider '{}'", endpoint.provider),
        )?;

        if !changed {
            debug!(
                "OAuth token response for provider '{}' did not contain configured token fields",
                endpoint.provider
            );
            return Ok(body.to_vec());
        }

        debug!(
            provider = %endpoint.provider,
            fields = rewritten_fields,
            "rewrote OAuth token response fields to phantoms"
        );

        serde_json::to_vec(&json).map_err(|err| {
            ProxyError::HttpParse(format!(
                "failed to encode rewritten OAuth response JSON: {err}"
            ))
        })
    }

    /// Rewrite a form-urlencoded OAuth token response.
    ///
    /// `url::form_urlencoded::parse` accepts almost any byte string as *some*
    /// sequence of pairs, so unlike the JSON path a parse failure can never be
    /// relied on to fail closed. Instead every parsed key is checked against
    /// every configured field name and every generically sensitive token field
    /// name (case-insensitively and by substring, since the structured rewrite
    /// above is exact-case) and must have actually been rewritten; anything
    /// else is rejected rather than forwarded.
    fn rewrite_form_response_body(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let response_fields = endpoint
            .response_fields
            .iter()
            .filter(|field| !field.path.contains('.'))
            .map(|field| (field.path.as_str(), field))
            .collect::<std::collections::HashMap<_, _>>();

        let parsed = url::form_urlencoded::parse(body).collect::<Vec<_>>();
        let mut changed = false;
        let mut rewritten_fields = 0usize;
        let mut rewritten_names = HashSet::new();

        // Phase 1: mint phantoms for the whole body before storing anything,
        // so a body the marker check below rejects leaves no orphaned,
        // unreachable secrets in the store.
        enum Slot {
            Plain,
            Phantom { key: String, visible: String },
        }
        let mut slots = Vec::with_capacity(parsed.len());
        for (name, value) in &parsed {
            if let Some(field) = response_fields.get(name.as_ref())
                && !value.is_empty()
            {
                let (key, visible) = mint_response_phantom(&endpoint.provider, field, value)?;
                slots.push(Slot::Phantom { key, visible });
                changed = true;
                rewritten_fields += 1;
                rewritten_names.insert(name.to_string());
                continue;
            }
            slots.push(Slot::Plain);
        }

        let mut marker_names: Vec<String> = vec![
            "access_token".to_string(),
            "refresh_token".to_string(),
            "id_token".to_string(),
        ];
        for field in &endpoint.response_fields {
            // Dotted paths describe nested JSON fields with no rewrite as a
            // flat form pair, so they join the markers: a literal occurrence
            // as a form key is token-shaped material this path must reject.
            marker_names.push(field.path.to_ascii_lowercase());
        }
        marker_names.sort_unstable();
        marker_names.dedup();
        let token_shaped = |field: &str| {
            marker_names
                .iter()
                .any(|marker| field.contains(marker.as_str()))
        };
        for (name, value) in &parsed {
            if rewritten_names.contains(name.as_ref()) {
                continue;
            }
            let lname = name.to_ascii_lowercase();
            // Substring, not just exact or suffix: form_urlencoded folds a
            // body with no `=` into a pair whose name is the entire blob, so
            // token material can hide in a name while the value stays empty.
            if token_shaped(&lname) && !is_expiry_metadata(&lname, value, &marker_names) {
                return Err(ProxyError::HttpParse(format!(
                    "OAuth token response for provider '{}' contains unrewritten or \
                     unrecognized token-shaped material",
                    endpoint.provider
                )));
            }
            // A pair value that is itself a JSON document is not opaque text,
            // so token-shaped material inside it must fail closed rather
            // than reach the sandbox hidden under a benign form name. Values
            // inside pairs are never rewritten, so no configured path is
            // exempt from the walk.
            if let Ok(json) = serde_json::from_slice::<Value>(value.as_bytes()) {
                reject_unrewritten_token_fields(
                    &json,
                    &HashSet::new(),
                    &format!("provider '{}'", endpoint.provider),
                )?;
            }
        }

        if !changed {
            debug!(
                "OAuth token response for provider '{}' did not contain configured form token fields",
                endpoint.provider
            );
            return Ok(body.to_vec());
        }

        // Phase 2: the body passed every check, so the minted phantoms can
        // now be committed and the response serialized.
        let mut serialized = url::form_urlencoded::Serializer::new(String::new());
        for ((name, value), slot) in parsed.iter().zip(&slots) {
            match slot {
                Slot::Plain => {
                    serialized.append_pair(name, value);
                }
                Slot::Phantom { key, visible } => {
                    self.store_phantom(key, value.as_bytes(), &endpoint.admitted_consumers)?;
                    serialized.append_pair(name, visible);
                }
            }
        }

        debug!(
            provider = %endpoint.provider,
            fields = rewritten_fields,
            "rewrote OAuth token response form fields to phantoms"
        );

        Ok(serialized.finish().into_bytes())
    }

    pub fn inspect_capture_host_response(
        &self,
        host_port: &str,
        path: &str,
        status: u16,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        match serde_json::from_slice::<Value>(body) {
            Ok(json) => {
                reject_unrewritten_token_fields(
                    &json,
                    &HashSet::new(),
                    &format!("capture host '{host_port}' path '{path}' status {status}"),
                )?;
                Ok(body.to_vec())
            }
            Err(_) if body_contains_token_field_marker(body) => {
                Err(ProxyError::HttpParse(format!(
                    "capture host '{host_port}' path '{path}' status {status} returned token-shaped material"
                )))
            }
            Err(_) => Ok(body.to_vec()),
        }
    }
}

impl OAuthCaptureStore {
    /// Whether `body` carries a phantom this store could have minted. Templated
    /// phantoms carry no `nono_` marker, so the templates must be checked too.
    fn contains_phantom(&self, body: &[u8]) -> bool {
        crate::token::contains_phantom(body, &self.templates)
    }
}

fn value_at_path_mut<'a>(root: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    let mut current = root;
    for part in path.split('.') {
        if part.is_empty() {
            return None;
        }
        current = current.as_object_mut()?.get_mut(part)?;
    }
    Some(current)
}

fn reject_unrewritten_token_fields(
    value: &Value,
    configured_paths: &HashSet<&str>,
    context: &str,
) -> Result<()> {
    let mut path = Vec::new();
    reject_unrewritten_token_fields_inner(value, configured_paths, context, &mut path)
}

fn reject_unrewritten_token_fields_inner(
    value: &Value,
    configured_paths: &HashSet<&str>,
    context: &str,
    path: &mut Vec<String>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                path.push(key.clone());
                if is_sensitive_token_field(key)
                    && !configured_paths.contains(path.join(".").as_str())
                    && child.as_str().is_some_and(|token| !token.is_empty())
                {
                    return Err(ProxyError::HttpParse(format!(
                        "OAuth capture {context} response contained unrewritten token field '{}'",
                        path.join(".")
                    )));
                }
                reject_unrewritten_token_fields_inner(child, configured_paths, context, path)?;
                path.pop();
            }
        }
        Value::Array(items) => {
            for child in items {
                reject_unrewritten_token_fields_inner(child, configured_paths, context, path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether `body` opens with a JSON container after leading whitespace, used
/// to distinguish "truncated JSON" from "genuinely not JSON" when a strict
/// parse has already failed.
fn looks_like_json(body: &[u8]) -> bool {
    // A UTF-8 BOM breaks strict serde_json parsing but is still a JSON body,
    // so skip it before deciding; otherwise a BOM-prefixed token response
    // falls through to the form path and its blob-shaped pair names.
    let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body);
    matches!(
        body.iter().find(|b| !b.is_ascii_whitespace()),
        Some(b'{') | Some(b'[')
    )
}

fn body_contains_token_field_marker(body: &[u8]) -> bool {
    let haystack = String::from_utf8_lossy(body).to_ascii_lowercase();
    ["access_token", "refresh_token", "id_token"]
        .iter()
        .any(|needle| haystack.contains(needle))
}

/// `<marker>_expires_in` with a numeric value, such as
/// `refresh_token_expires_in=15897600`, is lifetime metadata, not token material.
fn is_expiry_metadata(name: &str, value: &str, markers: &[String]) -> bool {
    markers
        .iter()
        .any(|marker| name.strip_suffix("_expires_in") == Some(marker.as_str()))
        && !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
}

fn is_sensitive_token_field(field: &str) -> bool {
    matches!(field, "access_token" | "refresh_token" | "id_token")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentTypeHint {
    Json,
    Form,
    Other,
}

/// Classify a response's `Content-Type` header for format selection.
///
/// Returns `None` when no `Content-Type` header is present, so callers can
/// fall back to their own default rather than treating an absent header the
/// same as an unrecognized one.
///
/// The media type must match exactly once parameters are stripped: a
/// substring match would let a type smuggled into a parameter value or a
/// lookalike such as `application/jsonx` select a rewrite path. Every
/// `Content-Type` header is consulted and all must agree, so conflicting
/// duplicates are unclassifiable and the caller fails closed rather than
/// trusting whichever header arrived first.
fn content_type_hint(headers: &[(String, String)]) -> Option<ContentTypeHint> {
    let mut hint: Option<ContentTypeHint> = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-type") {
            continue;
        }
        let media_type = value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let this = if media_type == "application/json" {
            ContentTypeHint::Json
        } else if media_type == "application/x-www-form-urlencoded" {
            ContentTypeHint::Form
        } else {
            ContentTypeHint::Other
        };
        match hint {
            None => hint = Some(this),
            Some(prev) if prev == this => {}
            Some(_) => return Some(ContentTypeHint::Other),
        }
    }
    hint
}

/// Mint a phantom for a real token value captured from a response field,
/// per the field's configured template or opaque/JWT shape. Shared by the
/// JSON and form-urlencoded response paths so a token is classified
/// identically regardless of the wire encoding it arrived in.
fn mint_response_phantom(
    provider: &str,
    field: &ResponseField,
    real: &str,
) -> Result<(String, String)> {
    match &field.template {
        Some(template) => {
            if !template.matches(real) {
                tracing::warn!(
                    provider = %provider,
                    path = %field.path,
                    "OAuth capture format does not match the captured token shape; \
                     a prefix-sniffing client may classify the phantom wrongly"
                );
            }
            let phantom = template.render(&super::generate_phantom_body()?);
            Ok((phantom.clone(), phantom))
        }
        None => {
            let phantom = super::generate_phantom()?;
            match field.format {
                ResponseFieldFormat::Opaque => Ok((phantom.clone(), phantom)),
                ResponseFieldFormat::Jwt => {
                    let visible = jwt_shaped_phantom(&phantom)?;
                    Ok((phantom, visible))
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{
        OAuthCaptureConfig, OAuthTokenEndpointConfig, OAuthTokenResponseFieldConfig,
        OAuthTokenResponseFieldKind,
    };

    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn templated_store() -> OAuthCaptureStore {
        OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "anthropic".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://platform.claude.com".to_string(),
                path: "/v1/oauth/token".to_string(),
                response_fields: vec![OAuthTokenResponseFieldConfig {
                    path: "access_token".to_string(),
                    kind: OAuthTokenResponseFieldKind::Opaque,
                    format: Some("sk-ant-oat01-{}".to_string()),
                }],
                request_body: OAuthTokenRequestBodyFormat::Auto,
                response_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.anthropic".to_string()],
        }])
        .unwrap()
    }

    #[test]
    fn contains_phantom_sees_templated_phantom_without_marker() {
        let store = templated_store();
        assert!(store.contains_phantom(format!("nono_{HEX64}").as_bytes()));
        assert!(store.contains_phantom(format!("token=sk-ant-oat01-{HEX64}").as_bytes()));
    }

    #[test]
    fn contains_phantom_ignores_non_phantom_material() {
        let store = templated_store();
        assert!(!store.contains_phantom(b"grant_type=refresh_token&device_code=abc"));
        // Template prefix without a 64-hex body is not a phantom.
        assert!(!store.contains_phantom(b"sk-ant-oat01-nothexatall"));
    }

    #[test]
    fn contains_phantom_without_templates_still_sees_bare_nonce() {
        let store = OAuthCaptureStore::empty();
        assert!(store.contains_phantom(format!("nono_{HEX64}").as_bytes()));
        assert!(!store.contains_phantom(format!("sk-ant-oat01-{HEX64}").as_bytes()));
    }

    fn form_store() -> OAuthCaptureStore {
        OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "github".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://github.com".to_string(),
                path: "/login/oauth/access_token".to_string(),
                response_fields: vec![OAuthTokenResponseFieldConfig {
                    path: "access_token".to_string(),
                    kind: OAuthTokenResponseFieldKind::Opaque,
                    format: None,
                }],
                request_body: OAuthTokenRequestBodyFormat::Auto,
                response_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec![],
            }],
            admitted_consumers: vec!["proxy.github".to_string()],
        }])
        .unwrap()
    }

    fn form_endpoint(store: &OAuthCaptureStore) -> LoadedOAuthEndpoint {
        store
            .lookup("github.com:443", "/login/oauth/access_token")
            .unwrap()
            .clone()
    }

    #[test]
    fn form_response_rewrites_configured_field_and_resolves_only_for_admitted_consumer() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let rewritten = store
            .rewrite_response_body(
                &endpoint,
                &[],
                b"access_token=real-access-token&token_type=bearer&scope=repo",
            )
            .unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();
        let parsed = url::form_urlencoded::parse(rewritten.as_bytes())
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        let phantom = parsed.get("access_token").unwrap();
        assert!(phantom.starts_with("nono_"));
        assert_ne!(phantom, "real-access-token");
        assert_eq!(parsed.get("token_type").unwrap(), "bearer");

        assert_eq!(
            std::str::from_utf8(&store.resolve(phantom, "proxy.github").unwrap()).unwrap(),
            "real-access-token"
        );
        assert!(store.resolve(phantom, "proxy.other").is_none());
    }

    #[test]
    fn form_response_rejects_sensitive_unconfigured_field() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[],
                b"access_token=real-access-token&id_token=real-id-token",
            )
            .expect_err("unconfigured sensitive field must fail closed");
        assert!(
            err.to_string().contains("unrewritten or unrecognized"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_rejects_non_form_non_json_body_with_sensitive_key() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[],
                b"<html><body>access_token=real-access-token</body></html>",
            )
            .expect_err("HTML body containing a sensitive key must fail closed");
        assert!(
            err.to_string().contains("unrewritten or unrecognized"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_rejection_leaves_no_stored_phantom() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[],
                b"access_token=real-access-token&id_token=real-id-token",
            )
            .expect_err("unconfigured sensitive field must fail closed");
        assert!(
            err.to_string().contains("unrewritten or unrecognized"),
            "unexpected error: {err}"
        );
        // The `access_token` phantom is minted before the `id_token` marker
        // check rejects the body, so rejection must also discard it: an
        // unreachable secret left in the store serves no one.
        assert!(
            store.phantoms.lock().unwrap().is_empty(),
            "a rejected form response must not leave phantoms in the store"
        );
    }

    #[test]
    fn form_response_rewrites_every_duplicate_key_occurrence() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let rewritten = store
            .rewrite_response_body(
                &endpoint,
                &[],
                b"access_token=real-one&access_token=real-two",
            )
            .unwrap();
        let rewritten_str = String::from_utf8(rewritten).unwrap();
        assert!(!rewritten_str.contains("real-one"));
        assert!(!rewritten_str.contains("real-two"));
    }

    #[test]
    fn form_response_allows_numeric_token_expiry_metadata() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let rewritten = store
            .rewrite_response_body(
                &endpoint,
                &[],
                b"access_token=real-access-token&expires_in=28800&refresh_token_expires_in=15897600",
            )
            .expect("numeric expiry metadata is not token material");
        let rewritten_str = String::from_utf8(rewritten).unwrap();
        assert!(!rewritten_str.contains("real-access-token"));
        assert!(rewritten_str.contains("refresh_token_expires_in=15897600"));
    }

    #[test]
    fn form_response_rejects_non_numeric_or_blob_shaped_expiry_names() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        for body in [
            &b"access_token=real-access-token&refresh_token_expires_in=real-refresh-token"[..],
            b"access_token=real-access-token&refresh_token_expires_in=",
            b"access_token=real-access-token&refresh_token%3Dreal-refresh_expires_in=1",
            b"access_token=real-access-token&refresh_token_secret_expires_in=1",
        ] {
            assert!(
                store.rewrite_response_body(&endpoint, &[], body).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn form_response_rejects_mixed_case_unconfigured_sensitive_key() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[],
                b"access_token=real-access-token&Refresh_Token=real-refresh-token",
            )
            .expect_err("mixed-case unconfigured sensitive field must fail closed");
        assert!(
            err.to_string().contains("unrewritten or unrecognized"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_rejects_case_variant_duplicate_of_a_configured_field() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[],
                b"access_token=real-one&Access_Token=real-two",
            )
            .expect_err("differently-cased duplicate of a rewritten field must fail closed");
        assert!(
            err.to_string().contains("unrewritten or unrecognized"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_does_not_false_positive_on_marker_substring_in_a_value() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let body =
            b"error=invalid_request&error_description=missing+access_token&scope=read:access_token";
        let rewritten = store.rewrite_response_body(&endpoint, &[], body).unwrap();
        assert_eq!(rewritten, body);
    }

    #[test]
    fn response_body_auto_rejects_truncated_json_instead_of_reinterpreting_as_form() {
        // A JSON body truncated before any `=`/`&`-shaped delimiter appears
        // (e.g. cut off mid-value) fails strict serde_json parsing. Without
        // the looks_like_json guard, Auto-mode would silently fall back to
        // form parsing, which folds the whole blob into one pair with an
        // empty value that the form path's own scans skip entirely, letting
        // the real token in the unparsed JSON text reach the client
        // untouched. It must fail closed instead.
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let body = br#"{"access_token":"real-access-token-value","token_typ"#;
        let err = store
            .rewrite_response_body(&endpoint, &[], body)
            .expect_err("truncated JSON containing a real token must fail closed");
        assert!(
            err.to_string()
                .contains("looks like JSON but failed to parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_with_nothing_to_rewrite_is_returned_byte_identical() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let body = b"error=authorization_pending&error_description=pending";
        let rewritten = store.rewrite_response_body(&endpoint, &[], body).unwrap();
        assert_eq!(rewritten, body);
    }

    #[test]
    fn response_body_auto_rejects_content_type_that_is_neither_json_nor_form() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[("Content-Type".to_string(), "text/html".to_string())],
                b"access_token=real-access-token",
            )
            .expect_err("unrecognized Content-Type must fail closed");
        assert!(
            err.to_string().contains("neither"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn content_type_hint_requires_an_exact_media_type() {
        // A media type smuggled into a parameter value, or a lookalike that
        // merely contains the string, must not select a rewrite path.
        assert_eq!(
            content_type_hint(&[(
                "Content-Type".to_string(),
                "text/plain; charset=application/json".to_string()
            )]),
            Some(ContentTypeHint::Other)
        );
        assert_eq!(
            content_type_hint(&[("Content-Type".to_string(), "application/jsonx".to_string())]),
            Some(ContentTypeHint::Other)
        );
        assert_eq!(
            content_type_hint(&[("Content-Type".to_string(), "json".to_string())]),
            Some(ContentTypeHint::Other)
        );
    }

    #[test]
    fn content_type_hint_treats_conflicting_duplicate_headers_as_other() {
        // Two Content-Type headers naming different encodings cannot be
        // trusted, whichever arrives first.
        assert_eq!(
            content_type_hint(&[
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ]),
            Some(ContentTypeHint::Other)
        );
    }

    #[test]
    fn content_type_hint_strips_parameters_and_matches_case_insensitively() {
        assert_eq!(
            content_type_hint(&[(
                "Content-Type".to_string(),
                "Application/JSON; charset=utf-8".to_string()
            )]),
            Some(ContentTypeHint::Json)
        );
        assert_eq!(
            content_type_hint(&[(
                "content-type".to_string(),
                " application/x-www-form-urlencoded ".to_string()
            )]),
            Some(ContentTypeHint::Form)
        );
        // Duplicate headers that agree remain classifiable.
        assert_eq!(
            content_type_hint(&[
                ("Content-Type".to_string(), "application/json".to_string()),
                (
                    "Content-Type".to_string(),
                    "application/json; charset=utf-8".to_string()
                ),
            ]),
            Some(ContentTypeHint::Json)
        );
        assert_eq!(content_type_hint(&[]), None);
    }

    #[test]
    fn response_body_form_configured_rejects_json_content_type() {
        let store = OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "github".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://github.com".to_string(),
                path: "/login/oauth/access_token".to_string(),
                response_fields: vec![OAuthTokenResponseFieldConfig {
                    path: "access_token".to_string(),
                    kind: OAuthTokenResponseFieldKind::Opaque,
                    format: None,
                }],
                request_body: OAuthTokenRequestBodyFormat::Auto,
                response_body: OAuthTokenRequestBodyFormat::Form,
                request_nonce_fields: vec![],
            }],
            admitted_consumers: vec!["proxy.github".to_string()],
        }])
        .unwrap();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[("Content-Type".to_string(), "application/json".to_string())],
                br#"{"access_token":"real-access-token"}"#,
            )
            .expect_err("form-configured endpoint must reject a JSON Content-Type");
        assert!(
            err.to_string().contains("form-urlencoded"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_rejects_configured_dotted_path_present_as_a_form_key() {
        // A dotted path describes a nested JSON field and has no rewrite as a
        // flat form pair, so a literal occurrence as a form key is token-shaped
        // material that must fail closed rather than forward.
        let store = OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "github".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://github.com".to_string(),
                path: "/login/oauth/access_token".to_string(),
                response_fields: vec![OAuthTokenResponseFieldConfig {
                    path: "credentials.token".to_string(),
                    kind: OAuthTokenResponseFieldKind::Opaque,
                    format: None,
                }],
                request_body: OAuthTokenRequestBodyFormat::Auto,
                response_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec![],
            }],
            admitted_consumers: vec!["proxy.github".to_string()],
        }])
        .unwrap();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(&endpoint, &[], b"credentials.token=real-access-token")
            .expect_err("configured dotted path arriving as a form key must fail closed");
        assert!(
            err.to_string().contains("unrewritten or unrecognized"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_rejects_token_material_hidden_in_a_pair_value() {
        // Auto mode's form fallback accepts almost any bytes; a value that
        // is itself a JSON document is not opaque text, so a token field
        // inside it must fail closed rather than forward unchanged.
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(&endpoint, &[], br#"x={"access_token":"real-access-token"}"#)
            .expect_err("token material in a JSON value under a benign name must fail closed");
        assert!(
            err.to_string().contains("unrewritten token field"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_without_token_material_passes_through_unchanged() {
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let body = b"error=authorization_pending&error_description=slow+down";
        let out = store.rewrite_response_body(&endpoint, &[], body).unwrap();
        assert_eq!(out, body.to_vec());
    }

    #[test]
    fn form_response_forwards_marker_mentions_alongside_rewritten_fields() {
        // Once the token itself is rewritten, remaining values are opaque
        // text exactly as string values are in the JSON path; an error
        // description quoting the field name must not block the response.
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let body = b"access_token=real-access-token&error_description=the+access_token+was+rotated";
        let out = store.rewrite_response_body(&endpoint, &[], body).unwrap();
        let parsed = url::form_urlencoded::parse(&out)
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_ne!(
            parsed.get("access_token").unwrap(),
            "real-access-token",
            "the configured field must be rewritten"
        );
        assert_eq!(
            parsed.get("error_description").unwrap(),
            "the access_token was rotated"
        );
    }

    #[test]
    fn response_body_auto_rejects_bom_prefixed_json_instead_of_reinterpreting_as_form() {
        // A UTF-8 BOM breaks strict serde_json parsing, so without BOM handling
        // in looks_like_json the body falls to the form path, which folds the
        // whole blob into one pair with an empty value and forwards the real
        // token untouched. It must fail closed like any other unparseable JSON.
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let mut body = b"\xEF\xBB\xBF".to_vec();
        body.extend_from_slice(br#"{"access_token":"real-access-token"}"#);
        let err = store
            .rewrite_response_body(&endpoint, &[], &body)
            .expect_err("BOM-prefixed JSON containing a real token must fail closed");
        assert!(
            err.to_string()
                .contains("looks like JSON but failed to parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn form_response_rejects_token_marker_smuggled_in_a_pair_name() {
        // form_urlencoded folds a body with no `=` into a single pair whose
        // name is the whole blob, so token material can hide in a name while
        // the value stays empty; a marker in a non-rewritten name must reject
        // regardless of the pair's value.
        let store = form_store();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(&endpoint, &[], br#"x{"access_token":"real-token"}"#)
            .expect_err("token material smuggled in a pair name must fail closed");
        assert!(
            err.to_string().contains("unrewritten or unrecognized"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn response_body_json_configured_rejects_other_content_type() {
        // config.rs documents that a Content-Type matching neither JSON nor
        // form is rejected rather than guessed at; an explicit Json setting
        // must not be looser than Auto.
        let store = OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "github".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://github.com".to_string(),
                path: "/login/oauth/access_token".to_string(),
                response_fields: vec![OAuthTokenResponseFieldConfig {
                    path: "access_token".to_string(),
                    kind: OAuthTokenResponseFieldKind::Opaque,
                    format: None,
                }],
                request_body: OAuthTokenRequestBodyFormat::Auto,
                response_body: OAuthTokenRequestBodyFormat::Json,
                request_nonce_fields: vec![],
            }],
            admitted_consumers: vec!["proxy.github".to_string()],
        }])
        .unwrap();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[("Content-Type".to_string(), "text/plain".to_string())],
                br#"{"access_token":"real-access-token"}"#,
            )
            .expect_err("explicit Json mode must reject an unrecognized Content-Type");
        assert!(
            err.to_string().contains("neither"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn response_body_form_configured_rejects_other_content_type() {
        let store = OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "github".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://github.com".to_string(),
                path: "/login/oauth/access_token".to_string(),
                response_fields: vec![OAuthTokenResponseFieldConfig {
                    path: "access_token".to_string(),
                    kind: OAuthTokenResponseFieldKind::Opaque,
                    format: None,
                }],
                request_body: OAuthTokenRequestBodyFormat::Auto,
                response_body: OAuthTokenRequestBodyFormat::Form,
                request_nonce_fields: vec![],
            }],
            admitted_consumers: vec!["proxy.github".to_string()],
        }])
        .unwrap();
        let endpoint = form_endpoint(&store);
        let err = store
            .rewrite_response_body(
                &endpoint,
                &[("Content-Type".to_string(), "text/plain".to_string())],
                b"access_token=real-access-token",
            )
            .expect_err("explicit Form mode must reject an unrecognized Content-Type");
        assert!(
            err.to_string().contains("neither"),
            "unexpected error: {err}"
        );
    }
}
