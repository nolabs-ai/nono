//! OAuth token endpoint capture and phantom-token resolution.
//!
//! The capture store is intentionally small and data-driven: profile config
//! declares token endpoints, response fields, request fields, and API route
//! consumers. The proxy then rewrites real OAuth tokens to `nono_<64hex>`
//! phantoms before responses reach the sandbox, and resolves those phantoms
//! only for admitted consumers on egress.

mod command_store;
mod endpoint;
mod persist;
mod rewrite;

use self::command_store::CommandTokenStore;
pub use self::command_store::{OAuthCapturedField, OAuthRefresh, OAuthTokenStoreBackend};
pub use self::endpoint::LoadedOAuthEndpoint;
use self::endpoint::{ResponseField, load_endpoint, provider_consumer};
use self::persist::{load_persisted_tokens, persist_tokens};
use crate::config::OAuthCaptureConfig;
use crate::error::{ProxyError, Result};
use crate::secret_registry::SecretRegistry;
use crate::token::{NonceResolver, PHANTOM_BODY_HEX_LEN, PhantomTemplate, rewrite_first_phantom};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;
use zeroize::Zeroizing;

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
#[derive(Default)]
pub struct OAuthCaptureStore {
    endpoints: Vec<LoadedOAuthEndpoint>,
    by_host: HashMap<String, Vec<usize>>,
    phantoms: Mutex<HashMap<String, StoredOAuthToken>>,
    persist_path: Option<PathBuf>,
    command_stores: HashMap<String, CommandTokenStore>,
    /// Distinct visible-phantom templates declared across all endpoints, used
    /// to recognise and replace templated phantoms on egress.
    templates: Vec<PhantomTemplate>,
    /// Session secret registry. Real tokens are registered when captured and
    /// when resolved for injection (NEP-0010 §3.1).
    secret_registry: Option<SecretRegistry>,
    audit_log: Option<crate::audit::SharedAuditLog>,
}

impl std::fmt::Debug for OAuthCaptureStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCaptureStore")
            .field("endpoints", &self.endpoints.len())
            .field("command_stores", &self.command_stores.len())
            .finish_non_exhaustive()
    }
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
        Self::load_with_command_stores(configs, persist_path, HashMap::new())
    }

    pub(crate) fn load_with_command_stores(
        configs: &[OAuthCaptureConfig],
        persist_path: Option<PathBuf>,
        mut backends: HashMap<String, std::sync::Arc<dyn OAuthTokenStoreBackend>>,
    ) -> Result<Self> {
        let mut command_stores = HashMap::new();
        let mut endpoints = Vec::new();
        let mut by_host: HashMap<String, Vec<usize>> = HashMap::new();

        for config in configs {
            let mut admitted = config
                .admitted_consumers
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            admitted.insert(provider_consumer(&config.provider));
            let first_endpoint = endpoints.len();
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
            if let Some(backend) = backends.remove(&config.provider) {
                command_stores.insert(
                    config.provider.clone(),
                    CommandTokenStore::new(backend, admitted, &endpoints[first_endpoint..]),
                );
            }
        }

        if !backends.is_empty() {
            return Err(ProxyError::Config(
                "OAuth command token store has no provider".into(),
            ));
        }
        let persist_path = if configs.len() == command_stores.len() && !configs.is_empty() {
            None
        } else {
            persist_path
        };
        let phantoms = if let Some(path) = persist_path.as_deref() {
            let mut phantoms = load_persisted_tokens(path)?;
            phantoms.retain(|_, token| {
                !command_stores.keys().any(|provider| {
                    token
                        .admitted_consumers
                        .contains(&provider_consumer(provider))
                })
            });
            prune_phantoms(&mut phantoms, MAX_PERSISTED_PHANTOMS);
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
            command_stores,
            templates,
            secret_registry: None,
            audit_log: None,
        })
    }

    /// Register real tokens in `registry` as they are captured from token
    /// responses or resolved from phantoms (including phantoms persisted by
    /// earlier sessions) so they can be redacted from terminal recordings.
    pub fn set_secret_registry(&mut self, registry: Option<SecretRegistry>) {
        self.secret_registry = registry;
    }

    pub(crate) fn set_audit_log(&mut self, log: Option<crate::audit::SharedAuditLog>) {
        self.audit_log = log;
    }

    pub(crate) fn has_command_store(&self, endpoint: &LoadedOAuthEndpoint) -> bool {
        self.command_stores.contains_key(&endpoint.provider)
    }

    fn register_real(&self, name: &str, real: &[u8]) {
        if let Some(registry) = &self.secret_registry
            && let Ok(real) = std::str::from_utf8(real)
        {
            registry.register(name, real);
        }
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

    /// Commit all token fields from a validated response before returning phantoms.
    fn capture_fields(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        fields: &[(&ResponseField, &str)],
    ) -> Result<Vec<String>> {
        for (_, real) in fields {
            self.register_real(
                &format!("oauth_capture:{}", endpoint.provider),
                real.as_bytes(),
            );
        }
        if let Some(store) = self.command_stores.get(&endpoint.provider) {
            return store.put(endpoint, fields, self.audit_log.as_ref());
        }
        let mut visible = Vec::with_capacity(fields.len());
        let mut mappings = Vec::with_capacity(fields.len());
        for (field, real) in fields {
            let (phantom, value) = rewrite::mint_response_phantom(&endpoint.provider, field, real)?;
            visible.push(value);
            mappings.push((phantom, *real));
        }
        self.store_local_phantoms(endpoint, &mappings)?;
        Ok(visible)
    }

    fn store_local_phantoms(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        mappings: &[(String, &str)],
    ) -> Result<()> {
        let mut guard = self
            .phantoms
            .lock()
            .map_err(|_| ProxyError::Config("OAuth capture store lock poisoned".to_string()))?;
        if mappings.len() > MAX_PERSISTED_PHANTOMS
            || mappings
                .iter()
                .any(|(phantom, _)| guard.contains_key(phantom))
        {
            return Err(ProxyError::Config(
                "invalid OAuth response token mappings".into(),
            ));
        }
        let pruned = prune_phantoms(&mut guard, MAX_PERSISTED_PHANTOMS - mappings.len());
        let keys: Vec<_> = mappings
            .iter()
            .map(|(phantom, _)| phantom.clone())
            .collect();
        for (phantom, real) in mappings {
            guard.insert(
                phantom.clone(),
                StoredOAuthToken {
                    real: Zeroizing::new(real.as_bytes().to_vec()),
                    admitted_consumers: endpoint.admitted_consumers.clone(),
                    created_at_secs: now_secs(),
                },
            );
        }
        if let Err(err) = self.persist_locked(&guard) {
            guard.extend(pruned);
            for key in keys {
                guard.remove(&key);
            }
            return Err(err);
        }
        Ok(())
    }

    fn persist_locked(&self, tokens: &HashMap<String, StoredOAuthToken>) -> Result<()> {
        let Some(path) = self.persist_path.as_deref() else {
            return Ok(());
        };
        persist_tokens(path, tokens)
    }
}

fn prune_phantoms(
    tokens: &mut HashMap<String, StoredOAuthToken>,
    max_entries: usize,
) -> Vec<(String, StoredOAuthToken)> {
    let now = now_secs();
    let mut pruned: Vec<_> = tokens
        .extract_if(|_, token| now.saturating_sub(token.created_at_secs) > PHANTOM_TTL_SECS)
        .collect();
    let remove_count = tokens.len().saturating_sub(max_entries);
    if remove_count > 0 {
        let mut by_age: Vec<_> = tokens
            .iter()
            .map(|(phantom, token)| (phantom.clone(), token.created_at_secs))
            .collect();
        by_age.sort_unstable_by_key(|(_, created_at_secs)| *created_at_secs);
        for (phantom, _) in by_age.into_iter().take(remove_count) {
            if let Some(token) = tokens.remove(&phantom) {
                pruned.push((phantom, token));
            }
        }
    }
    pruned
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
        let local = {
            let guard = self.phantoms.lock().ok()?;
            if let Some(token) = guard.get(nonce) {
                if !token.admitted_consumers.contains(consumer) {
                    return None;
                }
                Some(token.real.clone())
            } else {
                None
            }
        };
        let real = local.or_else(|| {
            self.command_stores
                .values()
                .find_map(|store| store.resolve(nonce, consumer, self.audit_log.as_ref()))
        })?;
        self.register_real(&format!("oauth_capture:{consumer}"), &real);
        debug!(
            consumer = %consumer,
            phantom = %phantom_fingerprint(nonce),
            "resolved OAuth phantom token for admitted consumer"
        );
        Some(real)
    }

    fn rewrite_header_value(&self, value: &str, consumer: &str) -> Option<String> {
        rewrite_first_phantom(value, &self.templates, |nonce| {
            self.resolve(nonce, consumer)
        })
    }

    fn contains_phantom(&self, value: &str) -> bool {
        crate::token::contains_phantom(value.as_bytes(), &self.templates)
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

    fn codex_config() -> OAuthCaptureConfig {
        OAuthCaptureConfig {
            provider: "codex".to_string(),
            token_endpoints: vec![OAuthTokenEndpointConfig {
                host: "https://auth.openai.com".to_string(),
                path: "/oauth/token".to_string(),
                response_fields: opaque_fields(["access_token", "refresh_token"]),
                request_body: OAuthTokenRequestBodyFormat::Auto,
                response_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.openai_oauth".to_string()],
        }
    }

    fn store() -> OAuthCaptureStore {
        OAuthCaptureStore::load(&[codex_config()]).unwrap()
    }

    fn store_with_persistence(path: PathBuf) -> OAuthCaptureStore {
        OAuthCaptureStore::load_with_persistence(&[codex_config()], Some(path)).unwrap()
    }

    #[derive(Default)]
    struct TestCommandStore {
        tokens: Mutex<HashMap<String, Zeroizing<String>>>,
        reject_put: std::sync::atomic::AtomicBool,
        resolve_calls: std::sync::atomic::AtomicUsize,
    }

    impl std::fmt::Debug for TestCommandStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("TestCommandStore")
        }
    }

    fn store_phantom(digit: char) -> String {
        format!("nono_{digit:0>64}")
    }

    impl OAuthTokenStoreBackend for TestCommandStore {
        fn credential_name(&self) -> &str {
            "codex_broker"
        }

        fn cache_ttl(&self) -> std::time::Duration {
            std::time::Duration::from_secs(60)
        }

        fn put(
            &self,
            _: &LoadedOAuthEndpoint,
            fields: &[OAuthCapturedField<'_>],
        ) -> Result<Vec<String>> {
            assert_eq!(fields.len(), 2, "put the whole response together");
            if self.reject_put.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(ProxyError::Credential("test helper refused put".into()));
            }
            let mut tokens = self.tokens.lock().unwrap();
            let phantoms = [store_phantom('a'), store_phantom('b')];
            for (phantom, field) in phantoms.iter().zip(fields) {
                tokens.insert(phantom.clone(), Zeroizing::new(field.value.into()));
            }
            Ok(phantoms.to_vec())
        }

        fn resolve(&self, phantom: &str, _: &str) -> Result<Option<Zeroizing<String>>> {
            self.resolve_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.tokens.lock().unwrap().get(phantom).cloned())
        }

        fn refresh(&self, _: &LoadedOAuthEndpoint, phantom: &str) -> Result<OAuthRefresh> {
            assert_eq!(phantom, store_phantom('b'));
            self.tokens
                .lock()
                .unwrap()
                .insert(store_phantom('a'), Zeroizing::new("rotated-access".into()));
            Ok(OAuthRefresh {
                phantoms: [
                    ("access_token".into(), store_phantom('a')),
                    ("refresh_token".into(), store_phantom('b')),
                ]
                .into(),
                expires_in: Some(120),
                refresh_token_expires_in: None,
                token_type: Some("Bearer".into()),
                scope: None,
            })
        }
    }

    #[test]
    fn command_store_delegates_capture_resolution_and_refresh() {
        use std::sync::atomic::Ordering;
        let backend = std::sync::Arc::new(TestCommandStore::default());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("providers.json");
        let audit = crate::audit::new_audit_log();
        let registry = SecretRegistry::new();
        let start = || {
            let backend: std::sync::Arc<dyn OAuthTokenStoreBackend> = backend.clone();
            let mut store = OAuthCaptureStore::load_with_command_stores(
                &[codex_config()],
                Some(path.clone()),
                HashMap::from([("codex".into(), backend)]),
            )
            .unwrap();
            store.set_audit_log(Some(audit.clone()));
            store.set_secret_registry(Some(registry.clone()));
            store
        };
        let store = start();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let login = || {
            store.rewrite_response_body(
                endpoint,
                &[],
                br#"{"access_token":"real-access","refresh_token":"real-refresh"}"#,
            )
        };
        backend.reject_put.store(true, Ordering::Relaxed);
        assert!(login().is_err());
        assert!(backend.tokens.lock().unwrap().is_empty());
        backend.reject_put.store(false, Ordering::Relaxed);
        let login: Value = serde_json::from_slice(&login().unwrap()).unwrap();
        let access = login["access_token"].as_str().unwrap();
        let refresh = login["refresh_token"].as_str().unwrap();
        assert_eq!(access, store_phantom('a'));
        assert_eq!(refresh, store_phantom('b'));
        assert!(!path.exists());
        drop(store);

        let store = start();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        assert!(store.resolve(access, "proxy.wrong_route").is_none());
        assert_eq!(backend.resolve_calls.load(Ordering::Relaxed), 0);
        for _ in 0..2 {
            assert_eq!(
                store
                    .resolve(access, "proxy.openai_oauth")
                    .unwrap()
                    .as_slice(),
                b"real-access"
            );
        }
        assert_eq!(backend.resolve_calls.load(Ordering::Relaxed), 1);
        let request = format!("grant_type=refresh_token&refresh_token={refresh}");
        let (content_type, body) = store
            .command_refresh(endpoint, request.as_bytes(), None, true)
            .unwrap()
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(content_type, "application/json");
        assert_eq!(body["refresh_token"], refresh);
        assert_eq!(body["access_token"], access);
        assert_eq!(body["expires_in"], 120);
        assert_eq!(
            store
                .resolve(access, "proxy.openai_oauth")
                .unwrap()
                .as_slice(),
            b"rotated-access"
        );
        assert_eq!(backend.resolve_calls.load(Ordering::Relaxed), 2);
        assert!(
            registry
                .snapshot()
                .1
                .iter()
                .any(|secret| secret.value.as_str() == "rotated-access")
        );
        let events = crate::audit::snapshot_audit_events(&audit);
        assert_eq!(
            events
                .iter()
                .filter_map(|event| event.credential_capture_action.as_deref())
                .collect::<Vec<_>>(),
            ["put", "put", "resolve", "refresh", "resolve"]
        );
        assert!(
            !serde_json::to_string(&events)
                .unwrap()
                .contains("real-access")
        );
        assert!(!path.exists());

        let mut nested_endpoint = endpoint.clone();
        nested_endpoint.request_nonce_fields = vec!["credentials.refresh_token".into()];
        let request = serde_json::json!({
            "grant_type": "refresh_token",
            "credentials": { "refresh_token": refresh },
        });
        let (_, body) = store
            .command_refresh(
                &nested_endpoint,
                &serde_json::to_vec(&request).unwrap(),
                Some("application/json"),
                true,
            )
            .unwrap()
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["refresh_token"], refresh);
    }

    #[test]
    fn command_store_ignores_old_file_mappings_in_mixed_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("providers.json");
        let local = store_with_persistence(path.clone());
        let endpoint = local.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let phantom = store_phantom('d');
        local
            .store_local_phantoms(endpoint, &[(phantom.clone(), "old-file-token")])
            .unwrap();
        assert!(local.resolve(&phantom, "proxy.openai_oauth").is_some());
        drop(local);

        let mut local_provider = codex_config();
        local_provider.provider = "other".into();
        local_provider.token_endpoints[0].host = "https://other.example".into();
        local_provider.admitted_consumers = vec!["proxy.other".into()];
        let broker: std::sync::Arc<dyn OAuthTokenStoreBackend> =
            std::sync::Arc::new(TestCommandStore::default());
        let mixed = OAuthCaptureStore::load_with_command_stores(
            &[codex_config(), local_provider],
            Some(path.clone()),
            HashMap::from([("codex".into(), broker)]),
        )
        .unwrap();
        assert!(mixed.resolve(&phantom, "proxy.openai_oauth").is_none());

        let other = mixed.lookup("other.example:443", "/oauth/token").unwrap();
        mixed
            .store_local_phantoms(other, &[(store_phantom('e'), "other-file-token")])
            .unwrap();
        let persisted = fs::read_to_string(path).unwrap();
        assert!(!persisted.contains(&phantom));
        assert!(persisted.contains(&store_phantom('e')));
    }

    #[test]
    fn response_rewrite_mints_phantoms_and_resolves_only_admitted_consumers() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                &[],
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
    fn captured_and_resolved_real_tokens_are_registered() {
        let mut store = store();
        let registry = SecretRegistry::new();
        store.set_secret_registry(Some(registry.clone()));
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let _rewritten = store
            .rewrite_response_body(
                endpoint,
                &[],
                br#"{"access_token":"real-access-registry","refresh_token":"real-refresh-registry"}"#,
            )
            .unwrap();
        let entries: Vec<(String, String)> = registry
            .snapshot()
            .1
            .into_iter()
            .map(|e| (e.name, e.value.to_string()))
            .collect();
        assert!(entries.contains(&(
            "oauth_capture:codex".to_string(),
            "real-access-registry".to_string()
        )));
        assert!(entries.contains(&(
            "oauth_capture:codex".to_string(),
            "real-refresh-registry".to_string()
        )));
        assert!(
            !entries.iter().any(|(_, v)| v.starts_with("nono_")),
            "phantoms are not registered"
        );

        // A phantom whose real value was never captured in this process (as
        // when persisted by an earlier session) is registered on resolution.
        let phantom = generate_phantom().unwrap();
        store.phantoms.lock().unwrap().insert(
            phantom.clone(),
            StoredOAuthToken {
                real: Zeroizing::new(b"persisted-real-token".to_vec()),
                admitted_consumers: endpoint.admitted_consumers.clone(),
                created_at_secs: now_secs(),
            },
        );
        assert!(store.resolve(&phantom, "proxy.openai_oauth").is_some());
        assert!(registry.snapshot().1.iter().any(|e| {
            e.name == "oauth_capture:proxy.openai_oauth"
                && e.value.as_str() == "persisted-real-token"
        }));
    }

    #[test]
    fn capture_store_without_registry_is_unchanged() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(endpoint, &[], br#"{"access_token":"real-access"}"#)
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        assert!(json["access_token"].as_str().unwrap().starts_with("nono_"));
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
                response_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.codex_oauth".to_string()],
        }])
        .unwrap();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                &[],
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
                response_body: OAuthTokenRequestBodyFormat::Auto,
                request_nonce_fields: vec!["refresh_token".to_string()],
            }],
            admitted_consumers: vec!["proxy.codex_oauth".to_string()],
        }])
        .unwrap();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                &[],
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
                &[],
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
                &[],
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
    fn request_header_rewrite_resolves_provider_phantom() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                endpoint,
                &[],
                br#"{"access_token":"real-access","refresh_token":"real-refresh"}"#,
            )
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let phantom = json["access_token"].as_str().unwrap();

        let resolved = store
            .rewrite_request_header_value(endpoint, &format!("Bearer {phantom}"))
            .expect("provider consumer resolves the minted phantom");
        assert_eq!(resolved, "Bearer real-access");
    }

    #[test]
    fn request_header_rewrite_passes_plain_and_unknown_values_through() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let unknown = format!("nono_{}", "f".repeat(64));

        assert_eq!(
            store.rewrite_request_header_value(endpoint, "Bearer plain-token"),
            None
        );
        assert!(
            store
                .rewrite_request_header_value(endpoint, &format!("Bearer {unknown}"))
                .is_none(),
            "an unknown phantom must pass through unchanged"
        );
    }

    #[test]
    fn request_header_rewrite_does_not_resolve_other_providers_phantom() {
        let store = OAuthCaptureStore::load(&[
            OAuthCaptureConfig {
                provider: "github".to_string(),
                token_endpoints: vec![OAuthTokenEndpointConfig {
                    host: "https://github.com".to_string(),
                    path: "/login/oauth/access_token".to_string(),
                    response_fields: opaque_fields(["access_token"]),
                    request_body: OAuthTokenRequestBodyFormat::Auto,
                    response_body: OAuthTokenRequestBodyFormat::Auto,
                    request_nonce_fields: vec!["refresh_token".to_string()],
                }],
                admitted_consumers: vec!["proxy.github".to_string()],
            },
            OAuthCaptureConfig {
                provider: "other".to_string(),
                token_endpoints: vec![OAuthTokenEndpointConfig {
                    host: "https://auth.other.com".to_string(),
                    path: "/oauth/token".to_string(),
                    response_fields: opaque_fields(["access_token"]),
                    request_body: OAuthTokenRequestBodyFormat::Auto,
                    response_body: OAuthTokenRequestBodyFormat::Auto,
                    request_nonce_fields: vec!["refresh_token".to_string()],
                }],
                admitted_consumers: vec!["proxy.other".to_string()],
            },
        ])
        .unwrap();

        let github_endpoint = store
            .lookup("github.com:443", "/login/oauth/access_token")
            .unwrap();
        let other_endpoint = store.lookup("auth.other.com:443", "/oauth/token").unwrap();
        let rewritten = store
            .rewrite_response_body(
                other_endpoint,
                &[],
                br#"{"access_token":"other-provider-token"}"#,
            )
            .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let other_phantom = json["access_token"].as_str().unwrap();

        assert!(
            store
                .rewrite_request_header_value(github_endpoint, &format!("Bearer {other_phantom}"))
                .is_none(),
            "a phantom minted for another provider must not resolve on this endpoint"
        );
    }

    #[test]
    fn request_rewrite_resolves_form_refresh_phantom() {
        let store = store();
        let endpoint = store.lookup("auth.openai.com:443", "/oauth/token").unwrap();
        let phantom = generate_phantom().unwrap();
        store
            .store_local_phantoms(endpoint, &[(phantom.clone(), "real refresh/value")])
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

        prune_phantoms(&mut tokens, MAX_PERSISTED_PHANTOMS);

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
                &[],
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
                response_body: OAuthTokenRequestBodyFormat::Auto,
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
            .rewrite_response_body(endpoint, &[], br#"{"access_token":"real-oauth-token"}"#)
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
            .rewrite_response_body(endpoint, &[], br#"{"access_token":"real-oauth-token"}"#)
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
                response_body: OAuthTokenRequestBodyFormat::Auto,
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
            .rewrite_response_body(
                endpoint,
                &[],
                br#"{"access_token":"totally-different-shape"}"#,
            )
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
                    response_body: OAuthTokenRequestBodyFormat::Auto,
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
                    response_body: OAuthTokenRequestBodyFormat::Auto,
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
                .rewrite_response_body(endpoint, &[], body.as_bytes())
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
