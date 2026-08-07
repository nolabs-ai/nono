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
use rand::RngExt;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

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
    /// Nonce → credential name (named credentials only). Gate by name, not
    /// value: one name (e.g. `ddtool-token`) holds different per-audience values.
    nonce_names: std::collections::HashMap<String, String>,
}

impl TokenBroker {
    pub(crate) fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            named: std::collections::HashMap::new(),
            nonce_names: std::collections::HashMap::new(),
        }
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
        self.named
            .insert(name.clone(), (zeroized.clone(), grants.clone()));
        let nonce = self.issue_granted(zeroized, grants);
        self.nonce_names.insert(nonce.clone(), name);
        nonce
    }

    /// Issue a fresh nonce for a previously stored named supervisor credential.
    ///
    /// The new nonce inherits the grant set from the stored credential.
    /// Returns `None` if the credential is not registered.
    pub(crate) fn issue_named(&mut self, name: &str) -> Option<String> {
        let (value, grants) = self.named.get(name)?;
        let value = value.clone();
        let grants = grants.clone();
        let nonce = self.issue_granted(value, grants);
        self.nonce_names.insert(nonce.clone(), name.to_string());
        Some(nonce)
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

    /// Resolve a nonce iff its credential name is in `allowed_credentials`.
    ///
    /// Grant set is not consulted (route's `redeem_phantoms` is the authority).
    /// Only named-credential nonces resolve. Gates by name, not value: one name
    /// (e.g. `ddtool-token`) holds different per-audience values over time.
    pub(crate) fn resolve_nonce_for_credentials(
        &self,
        nonce: &str,
        allowed_credentials: &[String],
    ) -> Option<Zeroizing<Vec<u8>>> {
        if !is_nonce(nonce) {
            return None;
        }
        let name = self.nonce_names.get(nonce)?;
        if !allowed_credentials.iter().any(|a| a == name) {
            return None;
        }
        let (real, _grants) = self.map.get(nonce)?;
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
                    // Inherit the credential name so redeem_phantoms still resolves the reissue.
                    let name = self.nonce_names.get(s).cloned();
                    let new_nonce = self.issue_granted(real, grants);
                    if let Some(name) = name {
                        self.nonce_names.insert(new_nonce.clone(), name);
                    }
                    out.extend_from_slice(new_nonce.as_bytes());
                    i += NONCE_LEN;
                    continue;
                }
            }

            if let Some((real, grants)) = self.longest_secret_value_at(&input[i..]) {
                let len = real.len();
                // Preserve the credential name so a redacted raw value stays
                // redeemable by redeem_phantoms, like the nonce path above.
                let name = self.credential_name_for_value(&real);
                let new_nonce = self.issue_granted(real, grants);
                if let Some(name) = name {
                    self.nonce_names.insert(new_nonce.clone(), name);
                }
                out.extend_from_slice(new_nonce.as_bytes());
                i += len;
                continue;
            }

            out.push(input[i]);
            i = i.saturating_add(1);
        }
        out
    }

    /// Credential name for a raw `value`, via an existing nonce that carries it.
    /// Uses `nonce_names` (which keeps every issued nonce's name) rather than
    /// `named` (latest value per name only), so a historical/overwritten value
    /// still relabels correctly. Ambiguous ties resolve to any match (same secret).
    fn credential_name_for_value(&self, value: &[u8]) -> Option<String> {
        self.map.iter().find_map(|(nonce, (v, _))| {
            if v.as_slice() == value {
                self.nonce_names.get(nonce).cloned()
            } else {
                None
            }
        })
    }

    fn longest_secret_value_at(&self, input: &[u8]) -> Option<(Zeroizing<Vec<u8>>, GrantSet)> {
        self.map
            .values()
            .filter(|(value, _)| !value.is_empty() && input.starts_with(value.as_slice()))
            .max_by_key(|(value, _)| value.len())
            .cloned()
    }
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

    #[test]
    fn resolve_nonce_for_credentials_gates_by_name() {
        let mut broker = TokenBroker::new();
        // GrantSet::All: the name allow-list, not the grant set, is the gate.
        let dealership = broker.store_named(
            "ddtool-token".to_string(),
            b"real-dealership-jwt".to_vec(),
            GrantSet::All,
        );
        let other = broker.store_named(
            "orgstore".to_string(),
            b"other-secret".to_vec(),
            GrantSet::All,
        );

        // Listed credential resolves.
        let allowed = vec!["ddtool-token".to_string()];
        let resolved = broker
            .resolve_nonce_for_credentials(&dealership, &allowed)
            .expect("listed credential must resolve");
        assert_eq!(resolved.as_slice(), b"real-dealership-jwt");
        // A phantom for a credential the route does not list fails closed.
        assert!(
            broker
                .resolve_nonce_for_credentials(&other, &allowed)
                .is_none()
        );
        // Empty allow-list never resolves.
        assert!(
            broker
                .resolve_nonce_for_credentials(&dealership, &[])
                .is_none()
        );
        // Non-nonce input fails closed.
        assert!(
            broker
                .resolve_nonce_for_credentials("not-a-nonce", &allowed)
                .is_none()
        );
        // An anonymous nonce (no credential name) never resolves route-side.
        let anon = broker.issue(Zeroizing::new(b"anon".to_vec()));
        assert!(
            broker
                .resolve_nonce_for_credentials(&anon, &allowed)
                .is_none()
        );
    }

    #[test]
    fn resolve_nonce_for_credentials_gates_by_name_not_value() {
        // An earlier nonce must resolve to its own value even after a later
        // store_named overwrites the name's value.
        let mut broker = TokenBroker::new();
        let allowed = vec!["ddtool-token".to_string()];
        let first = broker.store_named(
            "ddtool-token".to_string(),
            b"audience-A".to_vec(),
            GrantSet::All,
        );
        // A later capture under the same name with a different value.
        let second = broker.store_named(
            "ddtool-token".to_string(),
            b"audience-B".to_vec(),
            GrantSet::All,
        );

        let r1 = broker
            .resolve_nonce_for_credentials(&first, &allowed)
            .expect("first nonce resolves by name");
        let r2 = broker
            .resolve_nonce_for_credentials(&second, &allowed)
            .expect("second nonce resolves by name");
        assert_eq!(r1.as_slice(), b"audience-A");
        assert_eq!(r2.as_slice(), b"audience-B");
    }

    #[test]
    fn reissued_nonce_keeps_credential_name() {
        let mut broker = TokenBroker::new();
        let allowed = vec!["ddtool-token".to_string()];
        let original = broker.store_named(
            "ddtool-token".to_string(),
            b"jwt-value".to_vec(),
            GrantSet::All,
        );
        let reissued_buf = broker.scan_and_reissue(original.as_bytes());
        let reissued = std::str::from_utf8(&reissued_buf).expect("utf8 nonce");
        assert_ne!(reissued, original, "reissue mints a fresh nonce");
        let resolved = broker
            .resolve_nonce_for_credentials(reissued, &allowed)
            .expect("reissued nonce resolves by inherited name");
        assert_eq!(resolved.as_slice(), b"jwt-value");
    }

    #[test]
    fn reissued_raw_value_keeps_credential_name() {
        // A raw credential value in captured stdout is redacted to a fresh
        // nonce that stays redeemable by name — even for a historical value
        // after store_named overwrote the name's current value.
        let mut broker = TokenBroker::new();
        let allowed = vec!["ddtool-token".to_string()];
        broker.store_named(
            "ddtool-token".to_string(),
            b"audience-A".to_vec(),
            GrantSet::All,
        );
        // Overwrite the name's current value with a newer audience.
        broker.store_named(
            "ddtool-token".to_string(),
            b"audience-B".to_vec(),
            GrantSet::All,
        );

        let reissued_buf = broker.scan_and_reissue(b"prefix audience-A suffix");
        let reissued = std::str::from_utf8(&reissued_buf).expect("utf8");
        assert!(
            !reissued.contains("audience-A"),
            "historical raw value must be redacted"
        );
        let nonce = reissued
            .split_whitespace()
            .find(|w| is_nonce(w))
            .expect("a nonce replaced the raw value");
        let resolved = broker
            .resolve_nonce_for_credentials(nonce, &allowed)
            .expect("historical raw value resolves by inherited name");
        assert_eq!(resolved.as_slice(), b"audience-A");
    }
}
