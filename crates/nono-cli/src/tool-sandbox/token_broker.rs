/// Tool-sandbox token broker for credential isolation.
///
/// The token broker prevents real credential values from appearing in the
/// agent process's address space. At session setup, any credential value that
/// would be visible to the agent is replaced with a nonce string of the form
/// `nono_<64 hex chars>` (32 random bytes, hex-encoded). Real values live
/// only in the broker, which is held in the supervisor process.
///
/// When a tool-sandbox child is launched, `resolve_env_entry` replaces nonce env-var
/// values with their real counterparts immediately before `execve`. When a
/// `Capture` action returns stdout to the agent, `scan_and_reissue` redacts
/// any broker nonce or broker-held value found in the captured output.
///
/// All stored values are zeroed on drop via the `zeroize` crate.
///
/// # Capability-bound nonces
///
/// Every nonce carries a `GrantSet` that declares which consumers are allowed
/// to redeem it. `GrantSet::All` is unscoped (the previous behaviour). A
/// specific grant set limits redemption to named consumers of the form
/// `"cmd.<command_name>"` (env-var promotion path) or `"proxy.<route_id>"`
/// (L7 header-injection path). A consumer not in the grant set receives `None`.
#[cfg(target_os = "macos")]
use super::broker_store::{BrokerStore, PersistedRecord};
use rand::RngExt;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Hook used by [`TokenBroker::with_store_and_reader`] to inspect claude's
/// own `Claude Code-credentials` keychain entry at hydrate time. Returns
/// the access-token field from the entry (typically a `nono_<hex>` nonce
/// or a `sk-ant-…` real token), or `None` if the entry is missing /
/// unreadable / lacks the field.
///
/// Production callers pass the real reader from
/// [`super::broker_store::current_claude_access_token`]. Tests pass a
/// closure returning a known value so the orphan-GC paths are exercised
/// without touching the user's keychain.
#[cfg(target_os = "macos")]
pub(crate) type ClaudeAccessTokenReader = Box<dyn Fn() -> Option<String>>;

/// A shared, thread-safe token broker that can be held by both the proxy
/// runtime and the tool-sandbox runtime.
pub(crate) type SharedBroker = Arc<Mutex<TokenBroker>>;

/// Create a new shared broker.
pub(crate) fn new_shared_broker() -> SharedBroker {
    Arc::new(Mutex::new(TokenBroker::new()))
}

/// The prefix for all broker-issued nonce tokens.
/// No policy-defined env var may use this prefix; it is rejected at validation time.
pub(crate) const NONCE_PREFIX: &str = "nono_";

/// Length of the hex-encoded nonce suffix (32 bytes → 64 hex chars).
const NONCE_HEX_LEN: usize = 64;

/// Total length of a well-formed nonce: "nono_" + 64 hex chars.
const NONCE_LEN: usize = NONCE_PREFIX.len() + NONCE_HEX_LEN;

/// Declares which consumers may redeem a nonce.
///
/// Consumer IDs use the form `"cmd.<name>"` for command-env promotion and
/// `"proxy.<route_id>"` for L7 proxy header injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantSet {
    /// Any consumer may redeem. Default for backward compatibility.
    All,
    /// Only the listed consumer IDs may redeem.
    Specific(Vec<String>),
}

impl GrantSet {
    fn admits(&self, consumer: &str) -> bool {
        match self {
            GrantSet::All => true,
            GrantSet::Specific(ids) => ids.iter().any(|id| id == consumer),
        }
    }
}

/// Holds real credential values in the supervisor's memory.
/// All stored values are zeroed when the broker is dropped.
pub(crate) struct TokenBroker {
    map: std::collections::HashMap<String, (Zeroizing<Vec<u8>>, GrantSet)>,
    named: std::collections::HashMap<String, (Zeroizing<Vec<u8>>, GrantSet)>,
    /// Optional durable backing for OAuth cross-session resume. `None`
    /// for command-mediation-only brokers (the original behaviour).
    #[cfg(target_os = "macos")]
    store: Option<Arc<dyn BrokerStore>>,
    /// Nonces of the currently-live OAuth pair, if any. Tracked separately
    /// from `map` so [`capture_oauth_pair`](Self::capture_oauth_pair) can
    /// prune the previous pair on a refresh rotation. `None` if no OAuth
    /// pair has been captured or hydrated this run.
    current_pair: Option<(String, String)>,
}

impl TokenBroker {
    pub(crate) fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            named: std::collections::HashMap::new(),
            #[cfg(target_os = "macos")]
            store: None,
            current_pair: None,
        }
    }

    /// Construct a broker backed by `store`, hydrating from any previously
    /// persisted OAuth pair with orphan-GC disabled (no-op reader). Test-only
    /// convenience; production always uses
    /// [`with_store_and_reader`](Self::with_store_and_reader) with the real
    /// `Claude Code-credentials` reader.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn with_store(store: Arc<dyn BrokerStore>) -> nono::Result<Self> {
        Self::with_store_and_reader(store, Box::new(|| None))
    }

    #[cfg(target_os = "macos")]
    /// Construct a broker backed by `store`, cross-referencing the
    /// persisted record against `claude_access_token_reader` to detect
    /// orphaned records.
    ///
    /// On startup:
    /// 1. Load the persisted record. If empty, return an empty broker.
    /// 2. Read claude's own `Claude Code-credentials` access token.
    /// 3. If it matches the stored `access_nonce`, the record is live —
    ///    hydrate the in-memory map and set `current_pair`.
    /// 4. Otherwise (entry missing, holds a real `sk-ant-…` token, or a
    ///    different nonce), the record is stale — clear it and return an
    ///    empty broker. The next `/login` capture creates a fresh record.
    ///
    /// Rationale: when the user runs `/logout` inside claude, the
    /// `Claude Code-credentials` entry is wiped but our persisted record
    /// still holds the real refresh token. Without this GC the broker
    /// would keep hydrating dead tokens for as long as Anthropic considers
    /// them valid (~1 year), violating the user's "logout means tokens are
    /// gone" mental model.
    ///
    /// Returns an error only if the store's `load` itself fails — read
    /// failures from `claude_access_token_reader` are treated as "entry
    /// missing" (the GC-stale path), the conservative choice: better to
    /// drop a live record and force a re-`/login` than to leak a real
    /// token because we couldn't tell.
    pub(crate) fn with_store_and_reader(
        store: Arc<dyn BrokerStore>,
        claude_access_token_reader: ClaudeAccessTokenReader,
    ) -> nono::Result<Self> {
        let mut broker = Self {
            map: std::collections::HashMap::new(),
            named: std::collections::HashMap::new(),
            store: Some(store.clone()),
            current_pair: None,
        };

        let Some(record) = store.load()? else {
            return Ok(broker);
        };

        let claude_access = claude_access_token_reader();
        let live = matches!(claude_access.as_deref(), Some(t) if t == record.access_nonce);

        if !live {
            tracing::info!(
                "OAuth broker persisted record does not match Claude Code-credentials \
                 entry (claude_access_present={}); clearing stale record",
                claude_access.is_some()
            );
            if let Err(e) = store.clear() {
                tracing::warn!(
                    "OAuth broker stale-record clear failed (continuing without hydration): {e}"
                );
            }
            return Ok(broker);
        }

        // Re-register the previous session's nonces so the keychain entry
        // the sandboxed claude reads continues to resolve. OAuth nonces are
        // unscoped (`GrantSet::All`): the proxy redeems them on egress.
        broker.map.insert(
            record.access_nonce.clone(),
            (
                Zeroizing::new(record.access_token.as_bytes().to_vec()),
                GrantSet::All,
            ),
        );
        broker.map.insert(
            record.refresh_nonce.clone(),
            (
                Zeroizing::new(record.refresh_token.as_bytes().to_vec()),
                GrantSet::All,
            ),
        );
        broker.current_pair = Some((record.access_nonce, record.refresh_nonce));
        Ok(broker)
    }

    /// Capture an OAuth `(access_token, refresh_token)` pair: mint a nonce
    /// for each, register them in memory, and persist the pair to the
    /// configured store (if any) so the mapping survives this session.
    ///
    /// If a previous OAuth pair is currently live (hydrated on startup or
    /// minted by a prior call this session), its nonces are removed from
    /// the in-memory map before the new pair is issued. This handles the
    /// refresh-rotation case so the map does not grow with refresh count.
    ///
    /// Returns `(access_nonce, refresh_nonce)` so the caller can splice the
    /// nonces into the response body bound for the sandboxed client.
    ///
    /// Persistence is best-effort: a store error is logged at `warn!` and
    /// swallowed. The in-memory side always succeeds, so capture-and-rewrite
    /// continues to work in the current session even when durable storage is
    /// unavailable.
    pub(crate) fn capture_oauth_pair(
        &mut self,
        access: Zeroizing<String>,
        refresh: Zeroizing<String>,
    ) -> (String, String) {
        // Prune the previous pair, if any, before minting the new one, to
        // keep the map bounded over a long session with many rotations.
        if let Some((old_access_nonce, old_refresh_nonce)) = self.current_pair.take() {
            self.map.remove(&old_access_nonce);
            self.map.remove(&old_refresh_nonce);
        }

        let access_nonce = self.issue(Zeroizing::new(access.as_bytes().to_vec()));
        let refresh_nonce = self.issue(Zeroizing::new(refresh.as_bytes().to_vec()));
        self.current_pair = Some((access_nonce.clone(), refresh_nonce.clone()));

        #[cfg(target_os = "macos")]
        if let Some(store) = self.store.as_ref() {
            let record = PersistedRecord {
                access_nonce: access_nonce.clone(),
                refresh_nonce: refresh_nonce.clone(),
                access_token: access,
                refresh_token: refresh,
            };
            if let Err(e) = store.save(&record) {
                tracing::warn!("OAuth broker persistence failed (continuing in-memory only): {e}");
            }
        }
        (access_nonce, refresh_nonce)
    }

    /// Issue a nonce for `value` with no consumer restriction.
    ///
    /// The nonce resolves for any consumer. Use `issue_granted` to scope
    /// redemption to a specific set of consumers.
    pub(crate) fn issue(&mut self, value: Zeroizing<Vec<u8>>) -> String {
        self.issue_granted(value, GrantSet::All)
    }

    /// Issue a capability-bound nonce for `value`.
    ///
    /// Only consumers listed in `grants` may redeem the nonce via
    /// `resolve_env_entry` or `resolve_nonce`. `GrantSet::All` is equivalent
    /// to the unscoped `issue`.
    pub(crate) fn issue_granted(&mut self, value: Zeroizing<Vec<u8>>, grants: GrantSet) -> String {
        let mut raw = [0u8; 32];
        rand::rng().fill(&mut raw);
        let nonce = format!(
            "{}{}",
            NONCE_PREFIX,
            raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        self.map.insert(nonce.clone(), (value, grants));
        nonce
    }

    /// Store or replace a named supervisor credential and issue a nonce for it.
    ///
    /// `grants` scopes which consumers may redeem nonces issued for this credential.
    pub(crate) fn store_named(&mut self, name: String, value: Vec<u8>, grants: GrantSet) -> String {
        let zeroized = Zeroizing::new(value);
        self.named.insert(name, (zeroized.clone(), grants.clone()));
        self.issue_granted(zeroized, grants)
    }

    /// Issue a fresh nonce for a previously stored named supervisor credential.
    ///
    /// The new nonce inherits the grant set from the stored credential.
    /// Returns `None` if the credential is not registered.
    pub(crate) fn issue_named(&mut self, name: &str) -> Option<String> {
        let (value, grants) = self.named.get(name)?;
        let value = value.clone();
        let grants = grants.clone();
        Some(self.issue_granted(value, grants))
    }

    /// If `env_entry` has the form `NAME=nono_<64hex>` and the nonce is known to
    /// the broker and admitted for `consumer`, return a new env entry with the
    /// real value substituted. Returns `None` if the entry is not a broker nonce,
    /// not recognised, or not admitted for `consumer`.
    ///
    /// `consumer` should be `"cmd.<command_name>"` for command-env promotion.
    pub(crate) fn resolve_env_entry(&self, env_entry: &[u8], consumer: &str) -> Option<Vec<u8>> {
        let eq = env_entry.iter().position(|&b| b == b'=')?;
        let value = &env_entry[eq.saturating_add(1)..];
        let value_str = std::str::from_utf8(value).ok()?;
        if !is_nonce(value_str) {
            return None;
        }
        let (real, grants) = self.map.get(value_str)?;
        if !grants.admits(consumer) {
            return None;
        }
        let mut out = Vec::with_capacity(eq.saturating_add(1).saturating_add(real.len()));
        out.extend_from_slice(&env_entry[..=eq]);
        out.extend_from_slice(real);
        Some(out)
    }

    /// Resolve a raw nonce value for `consumer`, returning the real value if
    /// the nonce is known and the consumer is admitted by the grant set.
    ///
    /// `consumer` should be `"proxy.<route_id>"` for L7 header-injection.
    pub(crate) fn resolve_nonce(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>> {
        if !is_nonce(nonce) {
            return None;
        }
        let (real, grants) = self.map.get(nonce)?;
        if !grants.admits(consumer) {
            return None;
        }
        Some(real.clone())
    }

    /// Scan `input` for broker nonces or broker-held values and issue fresh
    /// nonces for each one found, returning the substituted buffer.
    ///
    /// Used for `Capture` action output: a captured nonce is re-issued as a new
    /// nonce before the buffered response is sent to the agent, so the real value
    /// never appears in the agent's address space even in captured stdout.
    ///
    /// New nonces inherit the grant set of the original.
    pub(crate) fn scan_and_reissue(&mut self, input: &[u8]) -> Vec<u8> {
        // Fast path: if the input is too short to contain either a nonce or any
        // stored secret value, return as-is.
        let shortest_secret = self
            .map
            .values()
            .filter(|(value, _)| !value.is_empty())
            .map(|(value, _)| value.len())
            .min();
        let shortest_match = shortest_secret.map_or(NONCE_LEN, |len| len.min(NONCE_LEN));
        if input.len() < shortest_match {
            return input.to_vec();
        }

        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        let prefix = NONCE_PREFIX.as_bytes();

        while i < input.len() {
            // Look for the nonce prefix starting at i
            if input[i..].starts_with(prefix) && i + NONCE_LEN <= input.len() {
                let candidate = &input[i..i + NONCE_LEN];
                if let Ok(s) = std::str::from_utf8(candidate)
                    && is_nonce(s)
                    && let Some((real, grants)) = self.map.get(s).cloned()
                {
                    // Re-issue a fresh nonce for the real value, inheriting grants
                    let new_nonce = self.issue_granted(real, grants);
                    out.extend_from_slice(new_nonce.as_bytes());
                    i += NONCE_LEN;
                    continue;
                }
            }

            if let Some((real, grants)) = self.longest_secret_value_at(&input[i..]) {
                let len = real.len();
                let new_nonce = self.issue_granted(real, grants);
                out.extend_from_slice(new_nonce.as_bytes());
                i += len;
                continue;
            }

            out.push(input[i]);
            i = i.saturating_add(1);
        }
        out
    }

    fn longest_secret_value_at(&self, input: &[u8]) -> Option<(Zeroizing<Vec<u8>>, GrantSet)> {
        self.map
            .values()
            .filter(|(value, _)| !value.is_empty() && input.starts_with(value.as_slice()))
            .max_by_key(|(value, _)| value.len())
            .cloned()
    }

    #[cfg(target_os = "macos")]
    /// Rewrite a JSON-envelope capture: parse `raw` as JSON and replace the
    /// string value at each dotted `secret_paths` entry with a freshly minted,
    /// unscoped nonce, leaving every other field untouched.
    ///
    /// **Fail-closed contract** — every error path returns
    /// [`JsonCaptureOutcome::FailClosed`] with a sandbox-safe message rather
    /// than the raw stdout (which is the real credential the agent must not
    /// see):
    ///
    /// - Malformed JSON → fail-closed; we never return `raw` unchanged.
    /// - A path resolving to a non-string value → fail-closed; a misconfigured
    ///   profile must not leak string-credential siblings it *did* expect to
    ///   nonce.
    /// - A path whose parent is missing or is not an object → treated as
    ///   "missing" and silently skipped.
    ///
    /// The caller must ensure `secret_paths` is non-empty (enforced at config
    /// load by `validate_intercept_rules`); an empty list would re-serialise
    /// the envelope unchanged and leak the credential.
    pub(crate) fn rewrite_json_secrets(
        &mut self,
        raw: &[u8],
        secret_paths: &[String],
    ) -> JsonCaptureOutcome {
        let mut value: serde_json::Value = match serde_json::from_slice(raw) {
            Ok(v) => v,
            Err(e) => {
                // Report line/column only. The serde_json message can echo a
                // snippet of the input on some errors, and we must never let
                // any `raw` content into our error string.
                return JsonCaptureOutcome::FailClosed(format!(
                    "nono: capture format=json: stdout is not valid JSON \
                     (at line {} column {}); refusing to return raw output",
                    e.line(),
                    e.column()
                ));
            }
        };

        for path in secret_paths {
            match self.substitute_one_path(&mut value, path) {
                Ok(()) => {}
                Err(SubstituteErr::NonString) => {
                    return JsonCaptureOutcome::FailClosed(format!(
                        "nono: capture format=json: secret_path '{path}' resolved \
                         to a non-string value; refusing to return raw output \
                         to avoid leaking unrelated string credentials"
                    ));
                }
                Err(SubstituteErr::MissingPath) => {
                    // Silent skip — documented behaviour.
                }
            }
        }

        match serde_json::to_vec(&value) {
            Ok(bytes) => JsonCaptureOutcome::Rewritten(bytes),
            Err(e) => JsonCaptureOutcome::FailClosed(format!(
                "nono: capture format=json: could not re-serialise JSON ({e}); \
                 refusing to return raw output"
            )),
        }
    }

    #[cfg(target_os = "macos")]
    /// Walk `dotted` (dot-separated object keys) to a leaf string and replace
    /// it with a freshly minted unscoped nonce. Object keys containing literal
    /// dots are not supported.
    fn substitute_one_path(
        &mut self,
        value: &mut serde_json::Value,
        dotted: &str,
    ) -> std::result::Result<(), SubstituteErr> {
        let segments: Vec<&str> = dotted.split('.').collect();
        let Some((last, parents)) = segments.split_last() else {
            return Err(SubstituteErr::MissingPath);
        };

        let mut cursor = value;
        for seg in parents {
            cursor = match cursor.as_object_mut().and_then(|m| m.get_mut(*seg)) {
                Some(child) => child,
                None => return Err(SubstituteErr::MissingPath),
            };
        }

        let Some(obj) = cursor.as_object_mut() else {
            return Err(SubstituteErr::MissingPath);
        };
        let Some(leaf) = obj.get_mut(*last) else {
            return Err(SubstituteErr::MissingPath);
        };
        let serde_json::Value::String(secret) = leaf else {
            return Err(SubstituteErr::NonString);
        };

        // Move the secret out (leaving "" behind) so the real value is owned by
        // the broker and zeroed on drop, then overwrite the leaf with the nonce.
        let nonce = self.issue(Zeroizing::new(std::mem::take(secret).into_bytes()));
        *leaf = serde_json::Value::String(nonce);
        Ok(())
    }
}

/// Outcome of [`TokenBroker::rewrite_json_secrets`].
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(crate) enum JsonCaptureOutcome {
    /// The JSON envelope with each targeted secret replaced by a nonce.
    Rewritten(Vec<u8>),
    /// A sandbox-safe error message. The caller must return this to the agent
    /// in place of the captured stdout — never the raw output.
    FailClosed(String),
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum SubstituteErr {
    /// A path segment does not exist or its parent is not an object. The
    /// caller treats this as a no-op for that path.
    MissingPath,
    /// The leaf value at the path is not a JSON string.
    NonString,
}

/// Returns true if `s` is a well-formed broker nonce: `nono_` + exactly 64 hex chars.
pub(crate) fn is_nonce(s: &str) -> bool {
    s.len() == NONCE_LEN
        && s.starts_with(NONCE_PREFIX)
        && s[NONCE_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn as_utf8(bytes: &[u8]) -> &str {
        match std::str::from_utf8(bytes) {
            Ok(value) => value,
            Err(err) => panic!("test output must be UTF-8: {err}"),
        }
    }

    fn find_nonce(value: &str) -> &str {
        let Some(start) = value.find(NONCE_PREFIX) else {
            panic!("test output must contain a broker nonce");
        };
        let end = start.saturating_add(NONCE_LEN);
        if end > value.len() {
            panic!("test output contains a truncated broker nonce");
        }
        &value[start..end]
    }

    fn resolve_entry(broker: &TokenBroker, entry: &[u8], consumer: &str) -> Vec<u8> {
        match broker.resolve_env_entry(entry, consumer) {
            Some(value) => value,
            None => panic!("broker nonce must resolve for consumer '{consumer}'"),
        }
    }

    #[test]
    fn issue_and_resolve_env_entry() {
        let mut broker = TokenBroker::new();
        let secret = b"hunter2".to_vec();
        let nonce = broker.issue(Zeroizing::new(secret));
        assert!(is_nonce(&nonce), "issued nonce must be well-formed");

        let entry = format!("MY_SECRET={nonce}").into_bytes();
        let resolved = resolve_entry(&broker, &entry, "cmd.any");
        assert_eq!(resolved, b"MY_SECRET=hunter2");
    }

    #[test]
    fn named_credential_issues_fresh_resolvable_nonces() {
        let mut broker = TokenBroker::new();
        let first = broker.store_named("github".to_string(), b"ghp_real".to_vec(), GrantSet::All);
        let second = match broker.issue_named("github") {
            Some(value) => value,
            None => panic!("named credential must issue nonce"),
        };

        assert_ne!(first, second, "named credential should issue fresh nonces");
        let first_resolved =
            resolve_entry(&broker, format!("GH_TOKEN={first}").as_bytes(), "cmd.gh");
        let second_resolved =
            resolve_entry(&broker, format!("GH_TOKEN={second}").as_bytes(), "cmd.gh");
        assert_eq!(first_resolved, b"GH_TOKEN=ghp_real");
        assert_eq!(second_resolved, b"GH_TOKEN=ghp_real");
    }

    #[test]
    fn resolve_non_nonce_returns_none() {
        let broker = TokenBroker::new();
        let entry = b"MY_VAR=plain_value".to_vec();
        assert!(broker.resolve_env_entry(&entry, "cmd.any").is_none());
    }

    #[test]
    fn resolve_unknown_nonce_returns_none() {
        let broker = TokenBroker::new();
        // Valid format but not in the broker
        let fake = format!("K={}", "nono_".to_string() + &"a".repeat(64));
        assert!(
            broker
                .resolve_env_entry(fake.as_bytes(), "cmd.any")
                .is_none()
        );
    }

    #[test]
    fn scan_and_reissue_replaces_nonce_in_output() {
        let mut broker = TokenBroker::new();
        let secret = b"s3cr3t".to_vec();
        let nonce = broker.issue(Zeroizing::new(secret));

        let captured = format!("output contains {nonce} here").into_bytes();
        let result = broker.scan_and_reissue(&captured);
        let result_str = as_utf8(&result);

        // The original nonce must be replaced with a fresh nonce
        assert!(
            !result_str.contains(&nonce),
            "original nonce must not appear in output"
        );
        // But the fresh nonce is there and resolves to the same secret
        let new_nonce = find_nonce(result_str);
        let resolved = resolve_entry(&broker, format!("X={new_nonce}").as_bytes(), "cmd.x");
        assert_eq!(resolved, b"X=s3cr3t");
    }

    #[test]
    fn scan_and_reissue_replaces_real_secret_in_output() {
        let mut broker = TokenBroker::new();
        let secret = b"s3cr3t".to_vec();
        let _nonce = broker.issue(Zeroizing::new(secret.clone()));

        let captured = b"token=s3cr3t\n".to_vec();
        let result = broker.scan_and_reissue(&captured);
        let result_str = as_utf8(&result);

        assert!(
            !result
                .windows(secret.len())
                .any(|window| window == secret.as_slice()),
            "real secret must not appear in output"
        );
        let new_nonce = find_nonce(result_str);
        let resolved = resolve_entry(&broker, format!("X={new_nonce}").as_bytes(), "cmd.x");
        assert_eq!(resolved, b"X=s3cr3t");
    }

    #[test]
    fn scan_and_reissue_prefers_longest_secret_match() {
        let mut broker = TokenBroker::new();
        let _short = broker.issue(Zeroizing::new(b"abc".to_vec()));
        let _long = broker.issue(Zeroizing::new(b"abcdef".to_vec()));

        let result = broker.scan_and_reissue(b"abcdef");
        let result_str = as_utf8(&result);
        let new_nonce = &result_str[..NONCE_LEN];
        let resolved = resolve_entry(&broker, format!("X={new_nonce}").as_bytes(), "cmd.x");
        assert_eq!(resolved, b"X=abcdef");
    }

    #[test]
    fn scan_and_reissue_passthrough_when_no_nonces() {
        let mut broker = TokenBroker::new();
        let input = b"no secrets here".to_vec();
        let result = broker.scan_and_reissue(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn is_nonce_rejects_wrong_length() {
        assert!(!is_nonce("nono_abc"));
        assert!(!is_nonce(&("nono_".to_string() + &"a".repeat(63))));
        assert!(!is_nonce(&("nono_".to_string() + &"a".repeat(65))));
    }

    #[test]
    fn is_nonce_rejects_wrong_prefix() {
        assert!(!is_nonce(&("NONO_".to_string() + &"a".repeat(64))));
    }

    #[test]
    fn is_nonce_rejects_non_hex() {
        // 'g' is not a hex digit
        assert!(!is_nonce(&("nono_".to_string() + &"g".repeat(64))));
    }

    #[test]
    fn nonce_prefix_constant() {
        assert_eq!(NONCE_PREFIX, "nono_");
    }

    // --- Capability-bound nonce tests ---

    #[test]
    fn granted_consumer_resolves_nonce() {
        let mut broker = TokenBroker::new();
        let nonce = broker.issue_granted(
            Zeroizing::new(b"secret".to_vec()),
            GrantSet::Specific(vec!["cmd.gh".to_string()]),
        );
        let entry = format!("GH_TOKEN={nonce}").into_bytes();
        let resolved = broker.resolve_env_entry(&entry, "cmd.gh");
        assert_eq!(resolved, Some(b"GH_TOKEN=secret".to_vec()));
    }

    #[test]
    fn ungrantend_consumer_cannot_resolve() {
        let mut broker = TokenBroker::new();
        let nonce = broker.issue_granted(
            Zeroizing::new(b"secret".to_vec()),
            GrantSet::Specific(vec!["cmd.gh".to_string()]),
        );
        let entry = format!("GH_TOKEN={nonce}").into_bytes();
        assert!(
            broker.resolve_env_entry(&entry, "cmd.curl").is_none(),
            "ungranted consumer must not resolve"
        );
    }

    #[test]
    fn resolve_nonce_proxy_consumer() {
        let mut broker = TokenBroker::new();
        let nonce = broker.issue_granted(
            Zeroizing::new(b"sk-ant-real".to_vec()),
            GrantSet::Specific(vec!["proxy.anthropic".to_string()]),
        );
        let resolved = broker.resolve_nonce(&nonce, "proxy.anthropic");
        assert_eq!(
            resolved.as_deref().map(|v| v.as_slice()),
            Some(b"sk-ant-real".as_slice())
        );
        // cmd.curl must not get it
        assert!(broker.resolve_nonce(&nonce, "cmd.curl").is_none());
    }

    #[test]
    fn all_grant_admits_any_consumer() {
        let mut broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new(b"val".to_vec()));
        assert!(broker.resolve_nonce(&nonce, "cmd.gh").is_some());
        assert!(broker.resolve_nonce(&nonce, "proxy.foo").is_some());
    }

    #[test]
    fn store_named_with_specific_grant() {
        let mut broker = TokenBroker::new();
        let n = broker.store_named(
            "gitlab".to_string(),
            b"glpat-real".to_vec(),
            GrantSet::Specific(vec!["cmd.glab".to_string()]),
        );
        // Admitted
        assert!(broker.resolve_nonce(&n, "cmd.glab").is_some());
        // Not admitted
        assert!(broker.resolve_nonce(&n, "cmd.curl").is_none());
        // issue_named inherits grants
        let n2 = broker
            .issue_named("gitlab")
            .expect("stored gitlab credential should be available");
        assert!(broker.resolve_nonce(&n2, "cmd.glab").is_some());
        assert!(broker.resolve_nonce(&n2, "cmd.curl").is_none());
    }

    // ── rewrite_json_secrets (capture format=json) — macOS only ─────────────

    #[cfg(target_os = "macos")]
    /// Keychain-shaped envelope: an Anthropic OAuth token we intend to nonce,
    /// alongside an unrelated Slack token that must pass through untouched.
    fn keychain_envelope() -> &'static str {
        r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-REAL","refreshToken":"sk-ant-ort01-REAL"},"mcp":{"slack":{"token":"xoxb-UNRELATED"}}}"#
    }

    #[cfg(target_os = "macos")]
    fn rewritten(outcome: JsonCaptureOutcome) -> Vec<u8> {
        match outcome {
            JsonCaptureOutcome::Rewritten(bytes) => bytes,
            JsonCaptureOutcome::FailClosed(msg) => {
                panic!("expected Rewritten, got FailClosed: {msg}")
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn json_capture_substitutes_targeted_paths_only() {
        let mut broker = TokenBroker::new();
        let paths = vec![
            "claudeAiOauth.accessToken".to_string(),
            "claudeAiOauth.refreshToken".to_string(),
        ];
        let out = rewritten(broker.rewrite_json_secrets(keychain_envelope().as_bytes(), &paths));
        let out_str = as_utf8(&out);

        // Real Anthropic tokens are gone; the unrelated Slack token is intact.
        assert!(!out_str.contains("sk-ant-oat01-REAL"));
        assert!(!out_str.contains("sk-ant-ort01-REAL"));
        assert!(out_str.contains("xoxb-UNRELATED"));

        // The substituted access-token nonce resolves back to the real value.
        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("rewritten output must be valid JSON");
        let nonce = parsed["claudeAiOauth"]["accessToken"]
            .as_str()
            .expect("accessToken must be a string nonce");
        assert!(is_nonce(nonce), "leaf must be replaced by a broker nonce");
        let real = broker
            .resolve_nonce(nonce, "proxy.anthropic")
            .expect("nonce must resolve to the captured secret");
        assert_eq!(real.as_slice(), b"sk-ant-oat01-REAL");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn json_capture_missing_path_silently_skipped() {
        let mut broker = TokenBroker::new();
        let paths = vec![
            "claudeAiOauth.accessToken".to_string(),
            "claudeAiOauth.doesNotExist".to_string(),
            "absent.parent.leaf".to_string(),
        ];
        let out = rewritten(broker.rewrite_json_secrets(keychain_envelope().as_bytes(), &paths));
        let out_str = as_utf8(&out);
        // The present path is rewritten; the missing ones are no-ops.
        assert!(!out_str.contains("sk-ant-oat01-REAL"));
        assert!(out_str.contains("sk-ant-ort01-REAL"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn json_capture_non_string_value_fails_closed() {
        let mut broker = TokenBroker::new();
        // accessToken is targeted but resolves to an object, not a string.
        let raw = r#"{"claudeAiOauth":{"accessToken":{"nested":"x"}}}"#;
        let paths = vec!["claudeAiOauth.accessToken".to_string()];
        match broker.rewrite_json_secrets(raw.as_bytes(), &paths) {
            JsonCaptureOutcome::FailClosed(msg) => {
                assert!(msg.contains("non-string"));
                // The error must not echo any input content.
                assert!(!msg.contains("nested"));
            }
            JsonCaptureOutcome::Rewritten(_) => panic!("non-string leaf must fail closed"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn json_capture_malformed_input_fails_closed_without_leak() {
        let mut broker = TokenBroker::new();
        let raw = b"sk-ant-oat01-REAL not json at all";
        let paths = vec!["accessToken".to_string()];
        match broker.rewrite_json_secrets(raw, &paths) {
            JsonCaptureOutcome::FailClosed(msg) => {
                // Never return the raw stdout, and never echo it in the error.
                assert!(!msg.contains("sk-ant-oat01-REAL"));
                assert!(msg.contains("not valid JSON"));
            }
            JsonCaptureOutcome::Rewritten(_) => panic!("malformed input must fail closed"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn json_capture_each_call_mints_fresh_nonces() {
        let mut broker = TokenBroker::new();
        let paths = vec!["claudeAiOauth.accessToken".to_string()];
        let first = rewritten(broker.rewrite_json_secrets(keychain_envelope().as_bytes(), &paths));
        let second = rewritten(broker.rewrite_json_secrets(keychain_envelope().as_bytes(), &paths));
        let first_nonce = find_nonce(as_utf8(&first));
        let second_nonce = find_nonce(as_utf8(&second));
        assert_ne!(
            first_nonce, second_nonce,
            "each capture must mint a fresh nonce"
        );
        // Both still resolve to the same real secret.
        assert_eq!(
            broker
                .resolve_nonce(first_nonce, "any")
                .expect("first nonce resolves")
                .as_slice(),
            b"sk-ant-oat01-REAL"
        );
        assert_eq!(
            broker
                .resolve_nonce(second_nonce, "any")
                .expect("second nonce resolves")
                .as_slice(),
            b"sk-ant-oat01-REAL"
        );
    }

    // ── OAuth pair capture + cross-session persistence ───────────────────────

    #[cfg(target_os = "macos")]
    use crate::tool_sandbox::broker_store::test_support::MemoryBrokerStore;

    #[test]
    fn capture_oauth_pair_without_store_issues_two_resolvable_nonces() {
        let mut broker = TokenBroker::new();
        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );
        assert!(is_nonce(&access_nonce));
        assert!(is_nonce(&refresh_nonce));
        assert_ne!(access_nonce, refresh_nonce);
        assert_eq!(
            broker
                .resolve_nonce(&access_nonce, "any")
                .unwrap()
                .as_slice(),
            b"real_access"
        );
        assert_eq!(
            broker
                .resolve_nonce(&refresh_nonce, "any")
                .unwrap()
                .as_slice(),
            b"real_refresh"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn capture_oauth_pair_with_store_persists_record() {
        let store = Arc::new(MemoryBrokerStore::new());
        let mut broker = TokenBroker::with_store(store.clone()).expect("empty store loads OK");
        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );

        let persisted = store.current().expect("save wrote a record");
        assert_eq!(persisted.access_nonce, access_nonce);
        assert_eq!(persisted.refresh_nonce, refresh_nonce);
        assert_eq!(persisted.access_token.as_str(), "real_access");
        assert_eq!(persisted.refresh_token.as_str(), "real_refresh");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn with_store_hydrates_when_claude_keychain_matches() {
        // resolve_nonce only resolves well-formed `nono_<64hex>` nonces, so
        // the persisted nonces must be the real shape (unlike the fork's
        // looser map-lookup resolve).
        let access_nonce = format!("nono_{}", "a".repeat(64));
        let refresh_nonce = format!("nono_{}", "b".repeat(64));
        let preloaded = PersistedRecord {
            access_nonce: access_nonce.clone(),
            refresh_nonce: refresh_nonce.clone(),
            access_token: Zeroizing::new("real_access".to_string()),
            refresh_token: Zeroizing::new("real_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let access_for_reader = access_nonce.clone();
        let matching: ClaudeAccessTokenReader = Box::new(move || Some(access_for_reader.clone()));
        let broker = TokenBroker::with_store_and_reader(store.clone(), matching).expect("hydrate");

        assert_eq!(
            broker
                .resolve_nonce(&access_nonce, "any")
                .unwrap()
                .as_slice(),
            b"real_access"
        );
        assert_eq!(
            broker
                .resolve_nonce(&refresh_nonce, "any")
                .unwrap()
                .as_slice(),
            b"real_refresh"
        );
        assert!(store.current().is_some(), "live record stays in store");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn with_store_clears_orphan_when_claude_keychain_missing() {
        let preloaded = PersistedRecord {
            access_nonce: "nono_orphan_access".to_string(),
            refresh_nonce: "nono_orphan_refresh".to_string(),
            access_token: Zeroizing::new("real_orphan_access".to_string()),
            refresh_token: Zeroizing::new("real_orphan_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let empty: ClaudeAccessTokenReader = Box::new(|| None);
        let broker = TokenBroker::with_store_and_reader(store.clone(), empty).expect("GC path");

        assert!(store.current().is_none(), "orphan record must be cleared");
        assert!(broker.resolve_nonce("nono_orphan_access", "any").is_none());
        assert!(broker.resolve_nonce("nono_orphan_refresh", "any").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn with_store_clears_orphan_when_claude_keychain_holds_real_token() {
        let preloaded = PersistedRecord {
            access_nonce: "nono_orphan_access".to_string(),
            refresh_nonce: "nono_orphan_refresh".to_string(),
            access_token: Zeroizing::new("real_orphan_access".to_string()),
            refresh_token: Zeroizing::new("real_orphan_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let real_token: ClaudeAccessTokenReader =
            Box::new(|| Some("sk-ant-oat01-fresh-real-token".to_string()));
        let broker = TokenBroker::with_store_and_reader(store.clone(), real_token).expect("GC");

        assert!(
            store.current().is_none(),
            "stale record cleared when claude holds a real token"
        );
        assert!(broker.resolve_nonce("nono_orphan_access", "any").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn capture_oauth_pair_prunes_previous_pair() {
        let store = Arc::new(MemoryBrokerStore::new());
        let mut broker = TokenBroker::with_store(store).expect("empty store loads OK");

        let (old_access, old_refresh) = broker.capture_oauth_pair(
            Zeroizing::new("real_access_v1".to_string()),
            Zeroizing::new("real_refresh_v1".to_string()),
        );
        assert!(broker.resolve_nonce(&old_access, "any").is_some());

        let (new_access, new_refresh) = broker.capture_oauth_pair(
            Zeroizing::new("real_access_v2".to_string()),
            Zeroizing::new("real_refresh_v2".to_string()),
        );

        assert!(
            broker.resolve_nonce(&old_access, "any").is_none(),
            "old access nonce must be pruned"
        );
        assert!(
            broker.resolve_nonce(&old_refresh, "any").is_none(),
            "old refresh nonce must be pruned"
        );
        assert_eq!(
            broker.resolve_nonce(&new_access, "any").unwrap().as_slice(),
            b"real_access_v2"
        );
        assert_eq!(
            broker
                .resolve_nonce(&new_refresh, "any")
                .unwrap()
                .as_slice(),
            b"real_refresh_v2"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn hydrate_then_capture_prunes_hydrated_pair() {
        let access_nonce = format!("nono_{}", "c".repeat(64));
        let refresh_nonce = format!("nono_{}", "d".repeat(64));
        let preloaded = PersistedRecord {
            access_nonce: access_nonce.clone(),
            refresh_nonce: refresh_nonce.clone(),
            access_token: Zeroizing::new("real_old".to_string()),
            refresh_token: Zeroizing::new("real_old_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let access_for_reader = access_nonce.clone();
        let matching: ClaudeAccessTokenReader = Box::new(move || Some(access_for_reader.clone()));
        let mut broker = TokenBroker::with_store_and_reader(store, matching).expect("hydrate");
        assert!(broker.resolve_nonce(&access_nonce, "any").is_some());

        let _ = broker.capture_oauth_pair(
            Zeroizing::new("real_new_access".to_string()),
            Zeroizing::new("real_new_refresh".to_string()),
        );

        assert!(
            broker.resolve_nonce(&access_nonce, "any").is_none(),
            "hydrated nonce must be pruned after the post-hydrate capture"
        );
        assert!(broker.resolve_nonce(&refresh_nonce, "any").is_none());
    }

    /// Store whose `load` always fails — construction must propagate it.
    #[cfg(target_os = "macos")]
    struct FailingLoadStore;
    #[cfg(target_os = "macos")]
    impl BrokerStore for FailingLoadStore {
        fn load(&self) -> nono::Result<Option<PersistedRecord>> {
            Err(nono::NonoError::KeystoreAccess(
                "simulated load failure".to_string(),
            ))
        }
        fn save(&self, _record: &PersistedRecord) -> nono::Result<()> {
            Ok(())
        }
        fn clear(&self) -> nono::Result<()> {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn with_store_propagates_load_errors() {
        let store: Arc<dyn BrokerStore> = Arc::new(FailingLoadStore);
        let err = match TokenBroker::with_store(store) {
            Ok(_) => panic!("load failure must propagate"),
            Err(e) => e,
        };
        assert!(
            format!("{err}").contains("simulated load failure"),
            "error must surface store's message: {err}"
        );
    }

    /// Store whose `save` always fails — capture must still work in-memory.
    #[cfg(target_os = "macos")]
    struct FailingSaveStore;
    #[cfg(target_os = "macos")]
    impl BrokerStore for FailingSaveStore {
        fn load(&self) -> nono::Result<Option<PersistedRecord>> {
            Ok(None)
        }
        fn save(&self, _record: &PersistedRecord) -> nono::Result<()> {
            Err(nono::NonoError::KeystoreAccess(
                "simulated save failure".to_string(),
            ))
        }
        fn clear(&self) -> nono::Result<()> {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn capture_oauth_pair_swallows_save_errors() {
        let store: Arc<dyn BrokerStore> = Arc::new(FailingSaveStore);
        let mut broker = TokenBroker::with_store(store).expect("empty store loads OK");
        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );
        assert_eq!(
            broker
                .resolve_nonce(&access_nonce, "any")
                .unwrap()
                .as_slice(),
            b"real_access"
        );
        assert_eq!(
            broker
                .resolve_nonce(&refresh_nonce, "any")
                .unwrap()
                .as_slice(),
            b"real_refresh"
        );
    }
}
