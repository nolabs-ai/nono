/// ETI token broker for credential isolation.
///
/// The token broker prevents real credential values from appearing in the
/// agent process's address space. At session setup, any credential value that
/// would be visible to the agent is replaced with a nonce string of the form
/// `nono_<64 hex chars>` (32 random bytes, hex-encoded). Real values live
/// only in the broker, which is held in the supervisor process.
///
/// When an ETI child is launched, `resolve_env_entry` replaces nonce env-var
/// values with their real counterparts immediately before `execve`. When a
/// `Capture` action returns stdout to the agent, `scan_and_replace` redacts
/// any nonce patterns found in the captured output.
///
/// All stored values are zeroed on drop via the `zeroize` crate.
use rand::RngExt;
use zeroize::Zeroizing;

/// The prefix for all broker-issued nonce tokens.
/// No policy-defined env var may use this prefix; it is rejected at validation time.
pub(crate) const NONCE_PREFIX: &str = "nono_";

/// Length of the hex-encoded nonce suffix (32 bytes → 64 hex chars).
const NONCE_HEX_LEN: usize = 64;

/// Total length of a well-formed nonce: "nono_" + 64 hex chars.
const NONCE_LEN: usize = NONCE_PREFIX.len() + NONCE_HEX_LEN;

/// Holds real credential values in the supervisor's memory.
/// All stored values are zeroed when the broker is dropped.
pub(crate) struct TokenBroker {
    map: std::collections::HashMap<String, Zeroizing<Vec<u8>>>,
}

impl TokenBroker {
    pub(crate) fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
        }
    }

    /// Issue a nonce for `value`. Returns the nonce string. Subsequent calls to
    /// `resolve_env_entry` or `scan_and_replace` with this nonce will return the
    /// real value.
    pub(crate) fn issue(&mut self, value: Vec<u8>) -> String {
        let mut raw = [0u8; 32];
        rand::rng().fill(&mut raw);
        let nonce = format!(
            "{}{}",
            NONCE_PREFIX,
            raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        self.map.insert(nonce.clone(), Zeroizing::new(value));
        nonce
    }

    /// If `env_entry` has the form `NAME=nono_<64hex>` and the nonce is known to
    /// the broker, return a new env entry with the real value substituted.
    /// Returns `None` if the entry is not a broker nonce or is not recognised.
    pub(crate) fn resolve_env_entry(&self, env_entry: &[u8]) -> Option<Vec<u8>> {
        let eq = env_entry.iter().position(|&b| b == b'=')?;
        let value = &env_entry[eq.saturating_add(1)..];
        let value_str = std::str::from_utf8(value).ok()?;
        if !is_nonce(value_str) {
            return None;
        }
        let real = self.map.get(value_str)?;
        let mut out = Vec::with_capacity(eq.saturating_add(1).saturating_add(real.len()));
        out.extend_from_slice(&env_entry[..=eq]);
        out.extend_from_slice(real);
        Some(out)
    }

    /// Scan `input` for nonce patterns and issue fresh nonces for each one found,
    /// returning the substituted buffer and the new nonce→real mapping.
    ///
    /// Used for `Capture` action output: a captured nonce is re-issued as a new
    /// nonce before the buffered response is sent to the agent, so the real value
    /// never appears in the agent's address space even in captured stdout.
    pub(crate) fn scan_and_reissue(&mut self, input: &[u8]) -> Vec<u8> {
        // Fast path: if the input is too short to contain a nonce, return as-is.
        if input.len() < NONCE_LEN {
            return input.to_vec();
        }

        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        let prefix = NONCE_PREFIX.as_bytes();

        while i < input.len() {
            // Look for the nonce prefix starting at i
            if input[i..].starts_with(prefix) && i + NONCE_LEN <= input.len() {
                let candidate = &input[i..i + NONCE_LEN];
                if let Ok(s) = std::str::from_utf8(candidate) {
                    if is_nonce(s) {
                        if let Some(real) = self.map.get(s).map(|v| v.to_vec()) {
                            // Re-issue a fresh nonce for the real value
                            let new_nonce = self.issue(real);
                            out.extend_from_slice(new_nonce.as_bytes());
                            i += NONCE_LEN;
                            continue;
                        }
                    }
                }
            }
            out.push(input[i]);
            i = i.saturating_add(1);
        }
        out
    }
}

/// Returns true if `s` is a well-formed broker nonce: `nono_` + exactly 64 hex chars.
fn is_nonce(s: &str) -> bool {
    s.len() == NONCE_LEN
        && s.starts_with(NONCE_PREFIX)
        && s[NONCE_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_resolve_env_entry() {
        let mut broker = TokenBroker::new();
        let secret = b"hunter2".to_vec();
        let nonce = broker.issue(secret.clone());
        assert!(is_nonce(&nonce), "issued nonce must be well-formed");

        let entry = format!("MY_SECRET={nonce}").into_bytes();
        let resolved = broker
            .resolve_env_entry(&entry)
            .expect("nonce should resolve");
        assert_eq!(resolved, b"MY_SECRET=hunter2");
    }

    #[test]
    fn resolve_non_nonce_returns_none() {
        let broker = TokenBroker::new();
        let entry = b"MY_VAR=plain_value".to_vec();
        assert!(broker.resolve_env_entry(&entry).is_none());
    }

    #[test]
    fn resolve_unknown_nonce_returns_none() {
        let broker = TokenBroker::new();
        // Valid format but not in the broker
        let fake = format!("K={}", "nono_".to_string() + &"a".repeat(64));
        assert!(broker.resolve_env_entry(fake.as_bytes()).is_none());
    }

    #[test]
    fn scan_and_reissue_replaces_nonce_in_output() {
        let mut broker = TokenBroker::new();
        let secret = b"s3cr3t".to_vec();
        let nonce = broker.issue(secret.clone());

        let captured = format!("output contains {nonce} here").into_bytes();
        let result = broker.scan_and_reissue(&captured);
        let result_str = std::str::from_utf8(&result).expect("utf8");

        // The original nonce must be replaced with a fresh nonce
        assert!(
            !result_str.contains(&nonce),
            "original nonce must not appear in output"
        );
        // But the fresh nonce is there and resolves to the same secret
        let new_nonce_start = result_str.find(NONCE_PREFIX).expect("new nonce in output");
        let new_nonce = &result_str[new_nonce_start..new_nonce_start + NONCE_LEN];
        let resolved = broker
            .resolve_env_entry(format!("X={new_nonce}").as_bytes())
            .expect("new nonce resolves");
        assert_eq!(resolved, b"X=s3cr3t");
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
}
