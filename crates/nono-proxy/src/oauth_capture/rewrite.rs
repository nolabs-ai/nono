use super::OAuthCaptureStore;
use super::endpoint::{LoadedOAuthEndpoint, ResponseFieldFormat, provider_consumer};
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
            if contains_phantom(body) {
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
        body: &[u8],
    ) -> Result<Vec<u8>> {
        if body.is_empty() {
            return Ok(body.to_vec());
        }

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
            let phantom = self.store_phantom(real.as_bytes(), &endpoint.admitted_consumers)?;
            let visible = match field.format {
                ResponseFieldFormat::Opaque => phantom,
                ResponseFieldFormat::Jwt => jwt_shaped_phantom(&phantom)?,
            };
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

fn contains_phantom(body: &[u8]) -> bool {
    body.windows(5).any(|window| window == b"nono_")
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
