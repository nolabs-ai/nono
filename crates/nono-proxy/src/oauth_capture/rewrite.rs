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

        let hint = content_type_hint(headers);
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
            OAuthTokenRequestBodyFormat::Auto => match hint {
                Some(ContentTypeHint::Json) => self.rewrite_json_response_body(endpoint, body),
                Some(ContentTypeHint::Form) => self.rewrite_form_response_body(endpoint, body),
                Some(ContentTypeHint::Other) => Err(ProxyError::HttpParse(format!(
                    "OAuth token response for provider '{}' has a Content-Type that is neither \
                     JSON nor form-urlencoded",
                    endpoint.provider
                ))),
                None => {
                    if serde_json::from_slice::<Value>(body).is_ok() {
                        self.rewrite_json_response_body(endpoint, body)
                    } else {
                        self.rewrite_form_response_body(endpoint, body)
                    }
                }
            },
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
    /// relied on to fail closed. Instead this scans the raw body for every
    /// configured field name and every generically sensitive token field name
    /// (case-insensitively, since the structured parse above is exact-case)
    /// and requires that every occurrence actually got rewritten; anything
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
        let mut serialized = url::form_urlencoded::Serializer::new(String::new());

        for (name, value) in &parsed {
            if let Some(field) = response_fields.get(name.as_ref())
                && !value.is_empty()
            {
                let (key, visible) = mint_response_phantom(&endpoint.provider, field, value)?;
                self.store_phantom(&key, value.as_bytes(), &endpoint.admitted_consumers)?;
                serialized.append_pair(name, &visible);
                changed = true;
                rewritten_fields += 1;
                rewritten_names.insert(name.to_string());
                continue;
            }
            serialized.append_pair(name, value);
        }

        let mut marker_names: Vec<String> = vec![
            "access_token".to_string(),
            "refresh_token".to_string(),
            "id_token".to_string(),
        ];
        for field in endpoint
            .response_fields
            .iter()
            .filter(|f| !f.path.contains('.'))
        {
            marker_names.push(field.path.to_ascii_lowercase());
        }
        marker_names.sort_unstable();
        marker_names.dedup();
        for (name, value) in &parsed {
            if value.is_empty() {
                continue;
            }
            if rewritten_names.contains(name.as_ref()) {
                continue;
            }
            let lname = name.to_ascii_lowercase();
            if marker_names
                .iter()
                .any(|marker| lname == marker.as_str() || lname.ends_with(marker.as_str()))
            {
                return Err(ProxyError::HttpParse(format!(
                    "OAuth token response for provider '{}' contains unrewritten or \
                     unrecognized token-shaped material",
                    endpoint.provider
                )));
            }
        }

        if !changed {
            debug!(
                "OAuth token response for provider '{}' did not contain configured form token fields",
                endpoint.provider
            );
            return Ok(body.to_vec());
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

fn body_contains_token_field_marker(body: &[u8]) -> bool {
    let haystack = String::from_utf8_lossy(body).to_ascii_lowercase();
    ["access_token", "refresh_token", "id_token"]
        .iter()
        .any(|needle| haystack.contains(needle))
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
fn content_type_hint(headers: &[(String, String)]) -> Option<ContentTypeHint> {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_ascii_lowercase())?;
    if value.contains("application/json") {
        Some(ContentTypeHint::Json)
    } else if value.contains("application/x-www-form-urlencoded") {
        Some(ContentTypeHint::Form)
    } else {
        Some(ContentTypeHint::Other)
    }
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
}
