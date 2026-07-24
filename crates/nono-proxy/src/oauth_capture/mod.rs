//! OAuth token endpoint capture and phantom-token resolution.
//!
//! The capture store is intentionally small and data-driven: profile config
//! declares token endpoints, response fields, request fields, and API route
//! consumers. The proxy then rewrites real OAuth tokens to `nono_<64hex>`
//! phantoms before responses reach the sandbox, and resolves those phantoms
//! only for admitted consumers on egress.

mod endpoint;
mod jwt;
mod persist;
mod rewrite;

use self::endpoint::{LoadedOAuthEndpoint, PhantomTemplate, load_endpoint, provider_consumer};
use self::persist::{load_persisted_tokens, persist_tokens};
use crate::config::OAuthCaptureConfig;
use crate::error::{ProxyError, Result};
use crate::token::{NonceResolver, PHANTOM_BODY_HEX_LEN, rewrite_first_phantom};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;
use zeroize::Zeroizing;

#[derive(Debug)]
pub(super) struct StoredOAuthToken {
    pub(super) real: Zeroizing<Vec<u8>>,
    pub(super) admitted_consumers: HashSet<String>,
    pub(super) created_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthCaptureHostPolicy {
    pub route_id: String,
    pub force_http1: bool,
}

/// In-memory OAuth phantom token store.
#[derive(Debug, Default)]
pub struct OAuthCaptureStore {
    endpoints: Vec<LoadedOAuthEndpoint>,
    by_host: HashMap<String, Vec<usize>>,
    phantoms: Mutex<HashMap<String, StoredOAuthToken>>,
    persist_path: Option<PathBuf>,
    /// Distinct visible-phantom templates declared across all endpoints, used
    /// to recognise and replace templated phantoms on egress.
    templates: Vec<PhantomTemplate>,
}

const MAX_PERSISTED_PHANTOMS: usize = 4096;
const PHANTOM_TTL_SECS: u64 = 90 * 24 * 60 * 60;

impl OAuthCaptureStore {
    pub fn load(configs: &[OAuthCaptureConfig]) -> Result<Self> {
        Self::load_with_persistence(configs, None)
    }

    pub fn load_with_persistence(
        configs: &[OAuthCaptureConfig],
        persist_path: Option<PathBuf>,
    ) -> Result<Self> {
        let mut endpoints = Vec::new();
        let mut by_host: HashMap<String, Vec<usize>> = HashMap::new();

        for config in configs {
            let mut admitted = config
                .admitted_consumers
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            admitted.insert(provider_consumer(&config.provider));
            for endpoint in &config.token_endpoints {
                let loaded = load_endpoint(&config.provider, endpoint, admitted.clone())?;
                debug!(
                    provider = %loaded.provider,
                    host_port = %loaded.host_port,
                    path = %loaded.path,
                    "configured OAuth capture endpoint"
                );
                let index = endpoints.len();
                by_host
                    .entry(loaded.host_port.clone())
                    .or_default()
                    .push(index);
                endpoints.push(loaded);
            }
        }

        let phantoms = if let Some(path) = persist_path.as_deref() {
            let mut phantoms = load_persisted_tokens(path)?;
            prune_phantoms(&mut phantoms);
            phantoms
        } else {
            HashMap::new()
        };

        let mut templates: Vec<PhantomTemplate> = Vec::new();
        for endpoint in &endpoints {
            for template in endpoint.templates() {
                if !templates.contains(template) {
                    templates.push(template.clone());
                }
            }
        }

        Ok(Self {
            endpoints,
            by_host,
            phantoms: Mutex::new(phantoms),
            persist_path,
            templates,
        })
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn host_ports(&self) -> Vec<String> {
        self.by_host.keys().cloned().collect()
    }

    pub fn host_policy(&self, host_port: &str) -> Option<OAuthCaptureHostPolicy> {
        let host_port = host_port.to_lowercase();
        let index = if let Some(indexes) = self.by_host.get(&host_port) {
            indexes.first()?
        } else {
            let host = host_from_host_port(&host_port)?;
            self.by_host.iter().find_map(|(configured, indexes)| {
                if host_from_host_port(configured) == Some(host) {
                    indexes.first()
                } else {
                    None
                }
            })?
        };
        Some(OAuthCaptureHostPolicy {
            route_id: format!("oauth.{}", self.endpoints[*index].provider),
            force_http1: true,
        })
    }

    pub fn lookup(&self, host_port: &str, path_and_query: &str) -> Option<&LoadedOAuthEndpoint> {
        let path = path_and_query.split('?').next().unwrap_or(path_and_query);
        let host_port = host_port.to_lowercase();
        let indexes = self.by_host.get(&host_port)?;
        let endpoint = indexes
            .iter()
            .map(|index| &self.endpoints[*index])
            .find(|endpoint| endpoint.path == path);
        if let Some(endpoint) = endpoint {
            debug!(
                provider = %endpoint.provider,
                host_port = %endpoint.host_port,
                path = %path,
                "matched OAuth capture endpoint"
            );
        } else {
            let configured_paths = indexes
                .iter()
                .map(|index| self.endpoints[*index].path.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            debug!(
                host_port = %host_port,
                path = %path,
                configured_paths = %configured_paths,
                "OAuth capture host request did not match configured endpoint path"
            );
        }
        endpoint
    }

    /// Store `real` under the phantom key `phantom` (the string the sandbox
    /// sees and later resents), admitting it for `admitted_consumers`.
    pub(super) fn store_phantom(
        &self,
        phantom: &str,
        real: &[u8],
        admitted_consumers: &HashSet<String>,
    ) -> Result<()> {
        let token = StoredOAuthToken {
            real: Zeroizing::new(real.to_vec()),
            admitted_consumers: admitted_consumers.clone(),
            created_at_secs: now_secs(),
        };
        let mut guard = self
            .phantoms
            .lock()
            .map_err(|_| ProxyError::Config("OAuth capture store lock poisoned".to_string()))?;
        guard.insert(phantom.to_string(), token);
        prune_phantoms(&mut guard);
        self.persist_locked(&guard)?;
        Ok(())
    }

    fn persist_locked(&self, tokens: &HashMap<String, StoredOAuthToken>) -> Result<()> {
        let Some(path) = self.persist_path.as_deref() else {
            return Ok(());
        };
        persist_tokens(path, tokens)
    }
}

fn prune_phantoms(tokens: &mut HashMap<String, StoredOAuthToken>) {
    let now = now_secs();
    tokens.retain(|_, token| now.saturating_sub(token.created_at_secs) <= PHANTOM_TTL_SECS);
    if tokens.len() <= MAX_PERSISTED_PHANTOMS {
        return;
    }

    let mut by_age = tokens
        .iter()
        .map(|(phantom, token)| (phantom.clone(), token.created_at_secs))
        .collect::<Vec<_>>();
    by_age.sort_by_key(|(_, created_at_secs)| *created_at_secs);
    let remove_count = tokens.len() - MAX_PERSISTED_PHANTOMS;
    for (phantom, _) in by_age.into_iter().take(remove_count) {
        tokens.remove(&phantom);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn host_from_host_port(host_port: &str) -> Option<&str> {
    host_port.rsplit_once(':').map(|(host, _)| host)
}

impl NonceResolver for OAuthCaptureStore {
    fn resolve(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>> {
        let guard = self.phantoms.lock().ok()?;
        let token = guard.get(nonce)?;
        if !token.admitted_consumers.contains(consumer) {
            return None;
        }
        debug!(
            consumer = %consumer,
            phantom = %phantom_fingerprint(nonce),
            "resolved OAuth phantom token for admitted consumer"
        );
        Some(Zeroizing::new(token.real.to_vec()))
    }

    fn rewrite_header_value(&self, value: &str, consumer: &str) -> Option<String> {
        rewrite_first_phantom(value, &self.templates, |nonce| {
            self.resolve(nonce, consumer)
        })
    }
}

fn phantom_fingerprint(phantom: &str) -> String {
    // Take chars, not bytes: a templated phantom's prefix may be non-ASCII, and
    // byte-slicing a multibyte boundary would panic in this log helper.
    let head: String = phantom.chars().take(14).collect();
    format!("{head}...")
}

/// Generate a random 64-hex phantom body (32 bytes of entropy).
fn generate_phantom_body() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| ProxyError::Config(format!("OAuth phantom token RNG failure: {err}")))?;
    let mut out = String::with_capacity(PHANTOM_BODY_HEX_LEN);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 0x0f) as usize]);
    }
    bytes.fill(0);
    Ok(out)
}

/// Generate a bare `nono_<64hex>` phantom.
fn generate_phantom() -> Result<String> {
    Ok(format!("nono_{}", generate_phantom_body()?))
}

const HEX: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{
        OAuthCaptureConfig, OAuthTokenEndpointConfig, OAuthTokenRequestBodyFormat,
        OAuthTokenResponseFieldConfig, OAuthTokenResponseFieldKind,
    };
    use serde_json::Value;
    use std::{fs, path::PathBuf};

    fn store() -> OAuthCaptureStore {
        OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "codex".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://auth.openai.com".to_string(),
                path: "/oauth/token".to_string(),
                response_fields: opaque_fields(["access_token", "refresh_token"]),
                request_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.openai_oauth".to_string()],
        }])
        .unwrap()
    }

    fn store_with_persistence(path: PathBuf) -> OAuthCaptureStore {
        OAuthCaptureStore::load_with_persistence(
            &[OAuthCaptureConfig {
                provider: "codex".to_string(),
                token_endpoints: vec![OAuthTokenEndpointConfig {
                    host: "https://auth.openai.com".to_string(),
                    path: "/oauth/token".to_string(),
                    response_fields: opaque_fields(["access_token", "refresh_token"]),
                    request_body: OAuthTokenRequestBodyFormat::Auto,
                    request_nonce_fields: vec!["refresh_token".to_string()],
                }],
                admitted_consumers: vec!["proxy.openai_oauth".to_string()],
            }],
            Some(path),
        )
        .unwrap()
    }

    #[test]
    fn response_rewrite_mints_phantoms_and_resolves_only_admitted_consumers() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                br#"{"access_token":"real-access","refresh_token":"real-refresh"}"#,
            )
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let access = json["access_token"].as_str().unwrap();
        let refresh = json["refresh_token"].as_str().unwrap();
        assert!(access.starts_with("nono_"));
        assert!(refresh.starts_with("nono_"));
        assert_eq!(
            std::str::from_utf8(
                &store
                    .resolve(access, "proxy.openai_oauth")
                    .expect("admitted consumer resolves")
            )
            .unwrap(),
            "real-access"
        );
        assert!(
            store.resolve(access, "proxy.other").is_none(),
            "unadmitted consumers must not resolve"
        );
    }

    #[test]
    fn response_rewrite_mints_phantoms_for_extra_token_fields() {
        let store = OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "codex".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://auth.openai.com".to_string(),
                path: "/oauth/token".to_string(),
                response_fields: opaque_fields(["access_token", "refresh_token", "id_token"]),
                request_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.codex_oauth".to_string()],
        }])
        .unwrap();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                br#"{"access_token":"real-access","refresh_token":"real-refresh","id_token":"real-id"}"#,
            )
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        for field in ["access_token", "refresh_token", "id_token"] {
            let phantom = json[field].as_str().unwrap();
            assert!(
                phantom.starts_with("nono_"),
                "{field} should be rewritten to a phantom"
            );
            assert!(
                store.resolve(phantom, "proxy.codex_oauth").is_some(),
                "{field} phantom should resolve for admitted consumer"
            );
        }
    }

    #[test]
    fn response_rewrite_mints_jwt_shaped_phantoms_for_jwt_token_fields() {
        let store = OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "codex".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://auth.openai.com".to_string(),
                path: "/oauth/token".to_string(),
                response_fields: {
                    let mut fields = opaque_fields(["access_token", "refresh_token"]);
                    fields.push(jwt_field("id_token"));
                    fields
                },
                request_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.codex_oauth".to_string()],
        }])
        .unwrap();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                br#"{"access_token":"real-access","refresh_token":"real-refresh","id_token":"real-id"}"#,
            )
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let id_token = json["id_token"].as_str().unwrap();
        let parts = id_token.split('.').collect::<Vec<_>>();

        assert_eq!(parts.len(), 3, "JWT phantom should have three segments");
        assert!(parts[2].starts_with("nono_"));
        assert_eq!(
            std::str::from_utf8(
                &store
                    .resolve(parts[2], "proxy.codex_oauth")
                    .expect("JWT phantom signature resolves for admitted consumer")
            )
            .unwrap(),
            "real-id"
        );
        assert!(
            !id_token.contains("real-id"),
            "JWT-shaped phantom must not expose original id token"
        );
    }

    #[test]
    fn response_rewrite_rejects_unlisted_token_fields() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();

        let err = store
            .rewrite_response_body(
                endpoint,
                br#"{"access_token":"real-access","refresh_token":"real-refresh","id_token":"real-id"}"#,
            )
            .expect_err("unlisted token fields must fail closed");

        assert!(
            err.to_string().contains("unrewritten token field"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn request_rewrite_resolves_refresh_phantom() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                br#"{"access_token":"real-access","refresh_token":"real-refresh"}"#,
            )
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let refresh = json["refresh_token"].as_str().unwrap();
        let request = format!(r#"{{"grant_type":"refresh_token","refresh_token":"{refresh}"}}"#);
        let resolved = store
            .rewrite_request_body(endpoint, request.as_bytes())
            .unwrap();
        let json: Value = serde_json::from_slice(&resolved).unwrap();
        assert_eq!(json["refresh_token"], "real-refresh");
    }

    #[test]
    fn host_policy_matches_capture_host_on_any_port() {
        let store = store();

        assert!(store.host_policy("auth.openai.com:443").is_some());
        assert!(store.host_policy("auth.openai.com:8443").is_some());
        assert!(store.host_policy("other.openai.com:443").is_none());
        assert!(
            store
                .lookup("auth.openai.com:8443", "/oauth/token")
                .is_none()
        );
    }

    #[test]
    fn request_rewrite_passes_form_body_without_phantom() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let body =
            b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=abc";

        let rewritten = store
            .rewrite_request_body(endpoint, body)
            .expect("form body without phantom should pass through");

        assert_eq!(rewritten, body);
    }

    #[test]
    fn request_rewrite_resolves_form_refresh_phantom() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let phantom = generate_phantom().unwrap();
        store
            .store_phantom(
                &phantom,
                b"real refresh/value",
                &endpoint.admitted_consumers,
            )
            .unwrap();
        let body = format!("grant_type=refresh_token&refresh_token={phantom}");

        let rewritten = store
            .rewrite_request_body(endpoint, body.as_bytes())
            .expect("form phantom should rewrite");
        let parsed = url::form_urlencoded::parse(&rewritten)
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(
            parsed.get("refresh_token").map(String::as_str),
            Some("real refresh/value")
        );
    }

    #[test]
    fn capture_host_response_fails_closed_on_token_fields() {
        let store = store();

        let safe = store
            .inspect_capture_host_response(
                "auth.openai.com:443",
                "/api/accounts/deviceauth/usercode",
                200,
                br#"{"device_code":"abc","user_code":"XYZ"}"#,
            )
            .expect("non-token response should pass");
        assert_eq!(safe, br#"{"device_code":"abc","user_code":"XYZ"}"#);

        let err = store
            .inspect_capture_host_response(
                "auth.openai.com:443",
                "/oauth/token/",
                200,
                br#"{"access_token":"real-access","refresh_token":"real-refresh"}"#,
            )
            .expect_err("token response on unmatched path must fail closed");
        assert!(
            err.to_string().contains("unrewritten token field"),
            "unexpected error: {err}"
        );

        let err = store
            .inspect_capture_host_response(
                "auth.openai.com:443",
                "/oauth/token",
                400,
                br#"{"error":"invalid_grant","refresh_token":"real-refresh"}"#,
            )
            .expect_err("token-shaped error body must fail closed");
        assert!(
            err.to_string().contains("unrewritten token field"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phantom_pruning_drops_expired_and_caps_oldest_entries() {
        let now = now_secs();
        let mut tokens = HashMap::new();
        let mut admitted = HashSet::new();
        admitted.insert("proxy.test".to_string());

        tokens.insert(
            "expired".to_string(),
            StoredOAuthToken {
                real: Zeroizing::new(b"expired".to_vec()),
                admitted_consumers: admitted.clone(),
                created_at_secs: now.saturating_sub(PHANTOM_TTL_SECS + 1),
            },
        );
        for index in 0..(MAX_PERSISTED_PHANTOMS + 1) {
            tokens.insert(
                format!("fresh-{index:04}"),
                StoredOAuthToken {
                    real: Zeroizing::new(format!("fresh-{index}").into_bytes()),
                    admitted_consumers: admitted.clone(),
                    created_at_secs: now.saturating_sub(index as u64),
                },
            );
        }

        prune_phantoms(&mut tokens);

        assert_eq!(tokens.len(), MAX_PERSISTED_PHANTOMS);
        assert!(!tokens.contains_key("expired"));
        assert!(!tokens.contains_key("fresh-4096"));
        assert!(tokens.contains_key("fresh-0000"));
    }

    #[test]
    fn persisted_capture_store_resolves_phantom_after_reload() {
        let dir =
            std::env::temp_dir().join(format!("nono-oauth-capture-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("providers.json");

        let store = store_with_persistence(path.clone());
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                br#"{"access_token":"real-access","refresh_token":"real-refresh"}"#,
            )
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let access = json["access_token"].as_str().unwrap().to_string();
        drop(store);

        let reloaded = store_with_persistence(path);
        assert_eq!(
            std::str::from_utf8(
                &reloaded
                    .resolve(&access, "proxy.openai_oauth")
                    .expect("persisted phantom resolves after reload")
            )
            .unwrap(),
            "real-access"
        );
        assert!(
            reloaded.resolve(&access, "proxy.other").is_none(),
            "persisted admitted consumers are enforced"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    fn opaque_fields<const N: usize>(paths: [&str; N]) -> Vec<OAuthTokenResponseFieldConfig> {
        paths
            .into_iter()
            .map(|path| OAuthTokenResponseFieldConfig {
                path: path.to_string(),
                kind: OAuthTokenResponseFieldKind::Opaque,
                format: None,
            })
            .collect()
    }

    fn jwt_field(path: &str) -> OAuthTokenResponseFieldConfig {
        OAuthTokenResponseFieldConfig {
            path: path.to_string(),
            kind: OAuthTokenResponseFieldKind::Jwt,
            format: None,
        }
    }

    fn templated_store(template: &str) -> OAuthCaptureStore {
        OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "anthropic".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://platform.claude.com".to_string(),
                path: "/v1/oauth/token".to_string(),
                response_fields: vec![OAuthTokenResponseFieldConfig {
                    path: "access_token".to_string(),
                    kind: OAuthTokenResponseFieldKind::Opaque,
                    format: Some(template.to_string()),
                }],
                request_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.anthropic".to_string()],
        }])
        .unwrap()
    }

    #[test]
    fn templated_phantom_follows_template_and_round_trips_via_header() {
        let store = templated_store("sk-ant-oat01-{}");
        let endpoint = store
            .lookup("platform.claude.com:443", "/v1/oauth/token")
            .unwrap();
        let rewritten = store
            .rewrite_response_body(endpoint, br#"{"access_token":"real-oauth-token"}"#)
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let phantom = json["access_token"].as_str().unwrap();

        // Visible phantom follows the template exactly: prefix + 64 hex, no marker.
        assert!(phantom.starts_with("sk-ant-oat01-"));
        assert!(!phantom.contains("nono_"));
        let body = phantom.strip_prefix("sk-ant-oat01-").unwrap();
        assert_eq!(body.len(), 64);
        assert!(body.bytes().all(|b| b.is_ascii_hexdigit()));

        // On egress the whole templated span resolves to the real token, with
        // no leftover template text.
        let header = format!("Bearer {phantom}");
        let resolved = store
            .rewrite_header_value(&header, "proxy.anthropic")
            .expect("admitted consumer resolves templated phantom");
        assert_eq!(resolved, "Bearer real-oauth-token");
    }

    #[test]
    fn templated_phantom_does_not_resolve_for_unadmitted_consumer() {
        let store = templated_store("sk-ant-oat01-{}");
        let endpoint = store
            .lookup("platform.claude.com:443", "/v1/oauth/token")
            .unwrap();
        let rewritten = store
            .rewrite_response_body(endpoint, br#"{"access_token":"real-oauth-token"}"#)
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let phantom = json["access_token"].as_str().unwrap();
        let header = format!("Bearer {phantom}");
        assert!(
            store.rewrite_header_value(&header, "proxy.other").is_none(),
            "unadmitted consumer must not resolve"
        );
    }

    #[test]
    fn format_rejected_with_jwt_kind() {
        let err = OAuthCaptureStore::load(&[OAuthCaptureConfig {
            provider: "anthropic".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://platform.claude.com".to_string(),
                path: "/v1/oauth/token".to_string(),
                response_fields: vec![OAuthTokenResponseFieldConfig {
                    path: "access_token".to_string(),
                    kind: OAuthTokenResponseFieldKind::Jwt,
                    format: Some("sk-ant-oat01-{}".to_string()),
                }],
                request_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.anthropic".to_string()],
        }]);
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("only valid with kind 'opaque'"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn templated_capture_warns_on_drift_but_still_mints_and_resolves() {
        // Real token does not match the declared prefix (drift). The phantom is
        // still minted following the template and round-trips on egress.
        let store = templated_store("sk-ant-oat01-{}");
        let endpoint = store
            .lookup("platform.claude.com:443", "/v1/oauth/token")
            .unwrap();
        let rewritten = store
            .rewrite_response_body(endpoint, br#"{"access_token":"totally-different-shape"}"#)
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let phantom = json["access_token"].as_str().unwrap();
        assert!(phantom.starts_with("sk-ant-oat01-"));
        assert!(!phantom.contains("nono_"));
        let resolved = store
            .rewrite_header_value(&format!("Bearer {phantom}"), "proxy.anthropic")
            .expect("drifted-format phantom still resolves");
        assert_eq!(resolved, "Bearer totally-different-shape");
    }

    #[test]
    fn multiple_templates_resolve_independently() {
        // Two providers, two distinct template shapes on the same store.
        let store = OAuthCaptureStore::load(&[
            OAuthCaptureConfig {
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
                    request_nonce_fields: vec!["refresh_token".to_string()],
                }],
                admitted_consumers: vec!["proxy.anthropic".to_string()],
            },
            OAuthCaptureConfig {
                provider: "other".to_string(),
                token_endpoints: vec![OAuthTokenEndpointConfig {
                    host: "https://auth.other.com".to_string(),
                    path: "/token".to_string(),
                    response_fields: vec![OAuthTokenResponseFieldConfig {
                        path: "access_token".to_string(),
                        kind: OAuthTokenResponseFieldKind::Opaque,
                        format: Some("oth_{}".to_string()),
                    }],
                    request_body: OAuthTokenRequestBodyFormat::Auto,
                    request_nonce_fields: vec!["refresh_token".to_string()],
                }],
                admitted_consumers: vec!["proxy.other".to_string()],
            },
        ])
        .unwrap();

        let mint = |host: &str, path: &str, consumer: &str, real: &str| {
            let endpoint = store.lookup(host, path).unwrap();
            let body = format!(r#"{{"access_token":"{real}"}}"#);
            let rewritten = store
                .rewrite_response_body(endpoint, body.as_bytes())
                .unwrap();
            let json: Value = serde_json::from_slice(&rewritten).unwrap();
            let phantom = json["access_token"].as_str().unwrap().to_string();
            let resolved = store
                .rewrite_header_value(&format!("Bearer {phantom}"), consumer)
                .expect("resolves");
            (phantom, resolved)
        };

        let (p_a, r_a) = mint(
            "platform.claude.com:443",
            "/v1/oauth/token",
            "proxy.anthropic",
            "A",
        );
        let (p_o, r_o) = mint("auth.other.com:443", "/token", "proxy.other", "B");
        assert!(p_a.starts_with("sk-ant-oat01-"));
        assert!(p_o.starts_with("oth_"));
        assert_eq!(r_a, "Bearer A");
        assert_eq!(r_o, "Bearer B");
    }
}
