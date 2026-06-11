/// Resolved network intent from CLI flags and profile config, before the proxy
/// starts. Separates policy intent from `NetworkMode` enforcement details.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum NetworkIntent {
    #[default]
    /// No network restrictions.
    Unrestricted,
    /// All network blocked at OS level (`--block-net` / `network.block`).
    BlockAll,
    /// Traffic filtered through a local proxy (domain filter or network profile).
    /// Credentials alone do not produce this variant — they inject headers
    /// without imposing OS-level isolation.
    ProxyFiltered {
        /// When true the proxy denies unlisted hosts; when false it is a
        /// transparent pass-through for credential injection only.
        strict_filter: bool,
    },
}

/// Resolve network intent from CLI flags and profile config. Block flags take
/// precedence; `allow_net` (deprecated explicit-unrestricted flag) overrides
/// profile proxy settings; proxy-activating flags (domain filter, upstream
/// proxy, network profile) produce `ProxyFiltered`. Credentials alone yield
/// `Unrestricted`.
pub(crate) fn resolve_network_intent(
    block_net: bool,
    allow_net: bool,
    has_proxy_flags: bool,
    profile_block: bool,
    profile_has_proxy: bool,
) -> NetworkIntent {
    if block_net || profile_block {
        NetworkIntent::BlockAll
    } else if allow_net {
        // Deprecated flag: explicitly forces unrestricted even if the profile
        // has proxy settings.
        NetworkIntent::Unrestricted
    } else if has_proxy_flags || profile_has_proxy {
        NetworkIntent::ProxyFiltered {
            strict_filter: false,
        }
    } else {
        NetworkIntent::Unrestricted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_by_default() {
        assert_eq!(
            resolve_network_intent(false, false, false, false, false),
            NetworkIntent::Unrestricted
        );
    }

    #[test]
    fn block_net_flag_wins() {
        assert_eq!(
            resolve_network_intent(true, false, false, false, false),
            NetworkIntent::BlockAll
        );
    }

    #[test]
    fn profile_block_wins() {
        assert_eq!(
            resolve_network_intent(false, false, false, true, false),
            NetworkIntent::BlockAll
        );
    }

    #[test]
    fn block_net_wins_over_proxy_flags() {
        assert_eq!(
            resolve_network_intent(true, false, true, false, false),
            NetworkIntent::BlockAll
        );
    }

    #[test]
    fn proxy_flags_set_proxy_filtered() {
        assert_eq!(
            resolve_network_intent(false, false, true, false, false),
            NetworkIntent::ProxyFiltered {
                strict_filter: false
            }
        );
    }

    #[test]
    fn profile_proxy_flags_set_proxy_filtered() {
        assert_eq!(
            resolve_network_intent(false, false, false, false, true),
            NetworkIntent::ProxyFiltered {
                strict_filter: false
            }
        );
    }

    #[test]
    fn allow_net_overrides_profile_proxy() {
        // --allow-net (deprecated) forces unrestricted even when the profile
        // has proxy settings.
        assert_eq!(
            resolve_network_intent(false, true, false, false, true),
            NetworkIntent::Unrestricted
        );
    }
}
