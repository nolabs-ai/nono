//! Delegation of OAuth token custody to a command-backed credential provider.

use super::endpoint::{LoadedOAuthEndpoint, ResponseField, ResponseFieldFormat};
use crate::audit::{self, CredentialCaptureAudit, ProxyMode, SharedAuditLog};
use crate::error::{ProxyError, Result};
use crate::jwt_phantom::jwt_shaped_phantom;
use crate::token::{BARE_NONCE_PREFIX, PHANTOM_BODY_HEX_LEN};
use nono::undo::NetworkAuditDecision;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// A real token captured from one configured response field.
#[derive(Serialize)]
pub struct OAuthCapturedField<'a> {
    /// Configured response path.
    pub path: &'a str,
    /// Real token material. This is sent only to the trusted host helper.
    pub value: &'a str,
}

/// A successful OAuth refresh returned by the trusted helper.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthRefresh {
    /// Visible phantoms indexed by configured response path.
    pub phantoms: BTreeMap<String, String>,
    /// Lifetime of the access token in seconds.
    pub expires_in: Option<u64>,
    /// Lifetime of the refresh token in seconds.
    pub refresh_token_expires_in: Option<u64>,
    /// OAuth token type, when supplied by the helper.
    pub token_type: Option<String>,
    /// Scopes granted by the authorization server.
    pub scope: Option<Zeroizing<String>>,
}

/// A credential provider bound to one OAuth provider and its configured routes.
pub trait OAuthTokenStoreBackend: std::fmt::Debug + Send + Sync {
    /// Named entry in credential_capture.
    fn credential_name(&self) -> &str;
    /// Maximum lifetime of a resolved token in the proxy's memory.
    fn cache_ttl(&self) -> Duration;
    /// Store a response atomically and return one visible phantom per field.
    fn put(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        fields: &[OAuthCapturedField<'_>],
    ) -> Result<Vec<String>>;
    /// Resolve an admitted phantom. A missing mapping returns None.
    fn resolve(&self, phantom: &str, consumer: &str) -> Result<Option<Zeroizing<String>>>;
    /// Refresh at the provider and return only phantoms and response metadata.
    fn refresh(&self, endpoint: &LoadedOAuthEndpoint, phantom: &str) -> Result<OAuthRefresh>;
}

struct CachedToken {
    resolved_at: Instant,
    real: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
struct Cache {
    tokens: HashMap<(String, String), CachedToken>,
    invalidated_at: Option<Instant>,
}

pub(super) struct CommandTokenStore {
    backend: Arc<dyn OAuthTokenStoreBackend>,
    cache: Mutex<Cache>,
    consumers: HashSet<String>,
    fields: Vec<ResponseField>,
}

impl CommandTokenStore {
    pub(super) fn new(
        backend: Arc<dyn OAuthTokenStoreBackend>,
        consumers: HashSet<String>,
        endpoints: &[LoadedOAuthEndpoint],
    ) -> Self {
        Self {
            backend,
            cache: Mutex::default(),
            consumers,
            fields: endpoints
                .iter()
                .flat_map(|endpoint| endpoint.response_fields.clone())
                .collect(),
        }
    }

    pub(super) fn put(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        fields: &[(&ResponseField, &str)],
        log: Option<&SharedAuditLog>,
    ) -> Result<Vec<String>> {
        let input: Vec<_> = fields
            .iter()
            .map(|(field, value)| OAuthCapturedField {
                path: &field.path,
                value,
            })
            .collect();
        let start = Instant::now();
        self.invalidate_cache()?;
        let result = self.backend.put(endpoint, &input).and_then(|phantoms| {
            let mut assigned = HashMap::new();
            if phantoms.len() != fields.len()
                || phantoms.iter().zip(fields).any(|(phantom, (field, real))| {
                    !valid_visible_phantom(phantom, field)
                        || fields.iter().any(|(_, real)| phantom == real)
                        || assigned
                            .insert(phantom, real)
                            .is_some_and(|previous| previous != real)
                })
            {
                return Err(invalid_reply());
            }
            Ok(phantoms)
        });
        self.invalidate_cache()?;
        self.audit(
            log,
            Some(endpoint),
            &super::provider_consumer(&endpoint.provider),
            "put",
            start,
            result.is_ok(),
        );
        result
    }

    pub(super) fn accepts_phantom(&self, phantom: &str) -> bool {
        self.fields.iter().any(|field| {
            valid_visible_phantom(phantom, field)
                || (field.format == ResponseFieldFormat::Jwt && is_bare_phantom(phantom))
        })
    }

    pub(super) fn resolve(
        &self,
        phantom: &str,
        consumer: &str,
        log: Option<&SharedAuditLog>,
    ) -> Option<Zeroizing<Vec<u8>>> {
        if !self.consumers.contains(consumer) || !self.accepts_phantom(phantom) {
            return None;
        }
        let start = Instant::now();
        let ttl = self.backend.cache_ttl();
        let key = (phantom.to_owned(), consumer.to_owned());
        {
            let mut cache = self.cache.lock().ok()?;
            if let Some(token) = cache.tokens.get(&key)
                && token.resolved_at.elapsed() < ttl
            {
                return Some(token.real.clone());
            }
            cache.tokens.remove(&key);
        }
        let result = self
            .backend
            .resolve(phantom, consumer)
            .and_then(|value| match value {
                Some(value)
                    if !value.is_empty()
                        && !value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) =>
                {
                    Ok(Some(Zeroizing::new(value.as_bytes().to_vec())))
                }
                Some(_) => Err(invalid_reply()),
                None => Ok(None),
            });
        let real = result.ok().flatten().and_then(|real| {
            let mut cache = self.cache.lock().ok()?;
            if cache.invalidated_at.is_some_and(|refresh| refresh >= start) {
                // A concurrent refresh may have rotated the token we just fetched.
                return None;
            }
            if !ttl.is_zero() {
                cache
                    .tokens
                    .retain(|_, token| token.resolved_at.elapsed() < ttl);
                if cache.tokens.len() < super::MAX_PERSISTED_PHANTOMS {
                    cache.tokens.insert(
                        key,
                        CachedToken {
                            resolved_at: Instant::now(),
                            real: real.clone(),
                        },
                    );
                }
            }
            Some(real)
        });
        self.audit(log, None, consumer, "resolve", start, real.is_some());
        real
    }

    pub(super) fn refresh<T>(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        phantom: &str,
        log: Option<&SharedAuditLog>,
        encode: impl FnOnce(OAuthRefresh) -> Result<T>,
    ) -> Result<T> {
        let start = Instant::now();
        self.invalidate_cache()?;
        let result = self.backend.refresh(endpoint, phantom).and_then(encode);
        // Even a failed operation may have rotated upstream before the helper
        // failed, so discard recently resolved tokens on every attempt.
        self.invalidate_cache()?;
        self.audit(
            log,
            Some(endpoint),
            &super::provider_consumer(&endpoint.provider),
            "refresh",
            start,
            result.is_ok(),
        );
        result
    }

    fn invalidate_cache(&self) -> Result<()> {
        let mut cache = self.cache.lock().map_err(|_| invalid_reply())?;
        cache.tokens.clear();
        cache.invalidated_at = Some(Instant::now());
        Ok(())
    }

    fn audit(
        &self,
        log: Option<&SharedAuditLog>,
        endpoint: Option<&LoadedOAuthEndpoint>,
        consumer: &str,
        action: &str,
        start: Instant,
        allowed: bool,
    ) {
        audit::log_credential_capture(
            log,
            ProxyMode::ConnectIntercept,
            CredentialCaptureAudit {
                route_id: consumer.strip_prefix("proxy.").unwrap_or(consumer),
                credential_name: self.backend.credential_name(),
                action,
                decision: if allowed {
                    NetworkAuditDecision::Allow
                } else {
                    NetworkAuditDecision::Deny
                },
                command: None,
                argv: None,
                exit_status: None,
                duration_ms: u64::try_from(start.elapsed().as_millis()).ok(),
                stdout_bytes: None,
                stderr_redacted: None,
                cache_scope: None,
                output_format: Some("provider_json"),
                header_names: None,
                stdin_mode: Some("request_json"),
                interactive: Some(false),
                upstream: None,
                request_host: endpoint.map_or("", LoadedOAuthEndpoint::host_port),
                request_port: None,
                request_method: if endpoint.is_some() { "POST" } else { "" },
                request_path: endpoint.map_or("", LoadedOAuthEndpoint::path),
                reason: (!allowed).then_some("OAuth credential provider operation failed"),
            },
        );
    }
}

pub(super) fn valid_visible_phantom(phantom: &str, field: &ResponseField) -> bool {
    if let Some(template) = &field.template {
        return template.matches_at(phantom.as_bytes(), 0) == Some(phantom.len());
    }
    match field.format {
        ResponseFieldFormat::Opaque => is_bare_phantom(phantom),
        ResponseFieldFormat::Jwt => phantom.rsplit_once('.').is_some_and(|(_, signature)| {
            is_bare_phantom(signature)
                && jwt_shaped_phantom(signature).is_ok_and(|visible| visible == phantom)
        }),
    }
}

fn is_bare_phantom(phantom: &str) -> bool {
    phantom.strip_prefix(BARE_NONCE_PREFIX).is_some_and(|body| {
        body.len() == PHANTOM_BODY_HEX_LEN && body.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

pub(super) fn invalid_reply() -> ProxyError {
    ProxyError::Credential("invalid OAuth credential provider reply".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn visible_phantoms_must_match_the_response_field_shape() {
        let bare = format!("nono_{}", "a".repeat(64));
        let jwt = jwt_shaped_phantom(&bare).unwrap();
        let mut field = ResponseField {
            path: "access_token".into(),
            format: ResponseFieldFormat::Opaque,
            template: None,
        };
        assert!(valid_visible_phantom(&bare, &field));
        assert!(!valid_visible_phantom(&jwt, &field));

        field.format = ResponseFieldFormat::Jwt;
        assert!(valid_visible_phantom(&jwt, &field));
        assert!(!valid_visible_phantom(&bare, &field));

        field.format = ResponseFieldFormat::Opaque;
        field.template = Some(crate::token::PhantomTemplate::parse("service-{}-token").unwrap());
        assert!(!valid_visible_phantom(&bare, &field));
        assert!(valid_visible_phantom(
            &format!("service-{}-token", "a".repeat(64)),
            &field
        ));
        for malformed in [
            "service--token".to_string(),
            format!("service-{}-token", "g".repeat(64)),
            format!("service-{}-token", "a".repeat(65)),
        ] {
            assert!(!valid_visible_phantom(&malformed, &field));
        }
    }
}
