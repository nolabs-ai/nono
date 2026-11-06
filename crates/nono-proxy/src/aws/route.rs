//! `AwsRoute` and `AwsRouteTable` — per-route AWS SigV4 state.
//!
//! `AwsRoute` holds the resolved region, service, upstream URL, and
//! `SharedCredentialsProvider` for one SigV4-enabled route.  `AwsRouteTable`
//! maps route prefixes to `AwsRoute` entries and maintains a provider cache
//! so routes sharing the same AWS profile reuse the same provider.

use std::collections::{BTreeMap, HashMap};

use aws_credential_types::provider::SharedCredentialsProvider;
use tracing::debug;

/// A fully-resolved AWS SigV4 route entry.
pub struct AwsRoute {
    /// The upstream URL (e.g., `https://bedrock-runtime.us-east-1.amazonaws.com`).
    /// Used to extract `Host` when building the signable URL.
    pub upstream: String,

    /// SigV4 signing region (e.g., `"us-east-1"`).
    pub region: String,

    /// SigV4 service name (e.g., `"bedrock"`).
    pub service: String,

    /// The identity (or operator-approved identities) this route signs with.
    pub credentials: AwsRouteCredentials,
}

/// How an `AwsRoute` chooses the credentials it signs with.
pub enum AwsRouteCredentials {
    /// One provider for every request (`aws_auth.profile`, or the default
    /// chain when `profile_key` is `None`).
    Single {
        /// The profile used when building the provider, if any.
        /// Stored so the `Debug` impl can report which identity source is active.
        profile_key: Option<String>,
        /// Shared across routes with the same `profile_key` to avoid
        /// duplicate STS/SSO refreshes.
        provider: SharedCredentialsProvider,
    },
    /// One provider per operator-approved profile (`aws_auth.profiles`),
    /// keyed by the placeholder access key ID the agent signs with.
    ByAccessKeyId(BTreeMap<String, ProfileProvider>),
}

/// A named host profile and its credential provider.
pub struct ProfileProvider {
    /// Host profile name, reported in logs instead of the placeholder key.
    pub profile: String,
    /// Shared with every other route that uses the same profile.
    pub provider: SharedCredentialsProvider,
}

/// Why no provider could be selected for a request on a multi-profile route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSelectionError {
    /// The request carried no single, well-formed SigV4 `Authorization` header.
    MissingAccessKeyId,
    /// The request's access key ID is not in the route's `profiles` map.
    UnknownAccessKeyId,
}

impl std::fmt::Display for ProviderSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAccessKeyId => f.write_str(
                "request has no SigV4 Authorization header to select a signing profile from",
            ),
            Self::UnknownAccessKeyId => {
                f.write_str("request access key ID is not mapped to an allowed signing profile")
            }
        }
    }
}

impl AwsRoute {
    /// Choose the credential provider for one request.
    ///
    /// `agent_headers` are the request headers as the agent sent them, before
    /// the auth headers are stripped. A single-provider route ignores them.
    /// A multi-profile route reads the access key ID from the agent's
    /// `Authorization` header and fails closed when it is missing or unlisted.
    ///
    /// # Errors
    ///
    /// Returns a [`ProviderSelectionError`] on a multi-profile route when the
    /// request cannot be mapped to an allowed profile.
    pub fn select_provider(
        &self,
        agent_headers: &[(String, String)],
    ) -> Result<&SharedCredentialsProvider, ProviderSelectionError> {
        match &self.credentials {
            AwsRouteCredentials::Single { provider, .. } => Ok(provider),
            AwsRouteCredentials::ByAccessKeyId(profiles) => {
                let access_key_id = super::sign::sigv4_access_key_id(agent_headers)
                    .ok_or(ProviderSelectionError::MissingAccessKeyId)?;
                profiles
                    .get(&access_key_id)
                    .map(|p| &p.provider)
                    .ok_or(ProviderSelectionError::UnknownAccessKeyId)
            }
        }
    }
}

impl std::fmt::Debug for AwsRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("AwsRoute");
        s.field("upstream", &self.upstream)
            .field("region", &self.region)
            .field("service", &self.service);
        match &self.credentials {
            AwsRouteCredentials::Single { profile_key, .. } => {
                s.field("profile_key", profile_key);
            }
            AwsRouteCredentials::ByAccessKeyId(profiles) => {
                // Placeholder key IDs are not secret, but log the host profile
                // names: they are what an operator recognises.
                let names: Vec<&str> = profiles.values().map(|p| p.profile.as_str()).collect();
                s.field("profiles", &names);
            }
        }
        s.field("provider", &"[SharedCredentialsProvider]").finish()
    }
}

/// Maps route prefixes to the full AWS SigV4 state needed to sign requests on
/// each route.  A provider cache is maintained internally so that routes
/// sharing the same AWS profile reuse the same `SharedCredentialsProvider`
/// instance.
#[derive(Debug)]
pub struct AwsRouteTable {
    routes: HashMap<String, AwsRoute>,
    providers: HashMap<Option<String>, SharedCredentialsProvider>,
}

impl AwsRouteTable {
    /// Create an empty table (no AWS routes configured).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            routes: HashMap::new(),
            providers: HashMap::new(),
        }
    }

    /// Return the `AwsRoute` for the given normalised prefix, if present.
    pub fn get(&self, prefix: &str) -> Option<&AwsRoute> {
        self.routes.get(prefix)
    }

    /// Returns `true` if no AWS routes are configured.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns the number of configured AWS routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Iterate over the normalised prefix keys of all configured routes.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.routes.keys()
    }

    /// Return the cached provider for `profile`, building it on first use.
    ///
    /// Routes sharing a profile within one load pass share one provider and
    /// avoid duplicate STS/SSO/IMDS refreshes.
    async fn provider_for(
        &mut self,
        profile: Option<&str>,
    ) -> Result<SharedCredentialsProvider, String> {
        let profile_key: Option<String> = profile.map(str::to_owned);
        if let Some(provider) = self.providers.get(&profile_key) {
            debug!("aws::route: reusing provider for profile={:?}", profile_key);
            return Ok(provider.clone());
        }
        debug!(
            "aws::route: building provider for profile={:?}",
            profile_key
        );
        let provider = new_provider(profile).await?;
        self.providers.insert(profile_key, provider.clone());
        Ok(provider)
    }

    /// Build (or reuse) a provider for `profile`, then insert the route.
    ///
    /// # Errors
    ///
    /// Returns an error string if the credential provider cannot be constructed.
    pub(crate) async fn insert_route(
        &mut self,
        prefix: String,
        profile: Option<&str>,
        upstream: String,
        region: String,
        service: String,
    ) -> Result<(), String> {
        let provider = self.provider_for(profile).await?;
        self.routes.insert(
            prefix,
            AwsRoute {
                upstream,
                region,
                service,
                credentials: AwsRouteCredentials::Single {
                    profile_key: profile.map(str::to_owned),
                    provider,
                },
            },
        );
        Ok(())
    }

    /// Build (or reuse) one provider per entry of `profiles`, then insert a
    /// route that selects among them by placeholder access key ID.
    ///
    /// All-or-nothing: if any profile's provider cannot be built, no route is
    /// inserted, so the route is denied rather than silently narrowed.
    ///
    /// # Errors
    ///
    /// Returns an error string naming the profile whose provider failed.
    pub(crate) async fn insert_multi_profile_route(
        &mut self,
        prefix: String,
        profiles: &BTreeMap<String, String>,
        upstream: String,
        region: String,
        service: String,
    ) -> Result<(), String> {
        let mut by_key = BTreeMap::new();
        for (access_key_id, profile) in profiles {
            let provider = self
                .provider_for(Some(profile))
                .await
                .map_err(|e| format!("profile '{profile}': {e}"))?;
            by_key.insert(
                access_key_id.clone(),
                ProfileProvider {
                    profile: profile.clone(),
                    provider,
                },
            );
        }
        self.routes.insert(
            prefix,
            AwsRoute {
                upstream,
                region,
                service,
                credentials: AwsRouteCredentials::ByAccessKeyId(by_key),
            },
        );
        Ok(())
    }
}

/// Build a `SharedCredentialsProvider` for the given profile, or the default
/// credential chain if `profile` is `None`.
async fn new_provider(profile: Option<&str>) -> Result<SharedCredentialsProvider, String> {
    debug!("aws::route: building provider for profile={:?}", profile);

    let mut loader = aws_config::from_env();
    if let Some(name) = profile {
        loader = loader.profile_name(name);
    }

    let sdk_config = loader.load().await;
    let provider = sdk_config
        .credentials_provider()
        .ok_or_else(|| {
            "default AWS credential chain yielded no provider; \
             set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or configure an AWS profile"
                .to_string()
        })?
        .clone();
    Ok(provider)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use aws_credential_types::Credentials;
    use aws_credential_types::provider::ProvideCredentials;
    use std::collections::BTreeMap;

    fn static_provider(access_key_id: &str) -> SharedCredentialsProvider {
        SharedCredentialsProvider::new(Credentials::new(
            access_key_id,
            "secret",
            None,
            None,
            "test",
        ))
    }

    fn route_with(credentials: AwsRouteCredentials) -> AwsRoute {
        AwsRoute {
            upstream: "https://sts.us-east-1.amazonaws.com".to_string(),
            region: "us-east-1".to_string(),
            service: "sts".to_string(),
            credentials,
        }
    }

    fn multi_profile_route() -> AwsRoute {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "NONOPROFILE0DEVRO01".to_string(),
            ProfileProvider {
                profile: "dev-ro".to_string(),
                provider: static_provider("AKIAREALDEVRO000001"),
            },
        );
        profiles.insert(
            "NONOPROFILE0STGRO01".to_string(),
            ProfileProvider {
                profile: "staging-ro".to_string(),
                provider: static_provider("AKIAREALSTGRO000001"),
            },
        );
        route_with(AwsRouteCredentials::ByAccessKeyId(profiles))
    }

    fn agent_auth(access_key_id: &str) -> Vec<(String, String)> {
        vec![(
            "Authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={access_key_id}/20261105/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc"
            ),
        )]
    }

    async fn resolved_key(provider: &SharedCredentialsProvider) -> String {
        provider
            .provide_credentials()
            .await
            .unwrap()
            .access_key_id()
            .to_string()
    }

    #[tokio::test]
    async fn single_provider_ignores_agent_access_key_id() {
        let route = route_with(AwsRouteCredentials::Single {
            profile_key: None,
            provider: static_provider("AKIAREALDEFAULT0001"),
        });
        // No Authorization header at all: today's behaviour is preserved.
        let provider = route.select_provider(&[]).unwrap();
        assert_eq!(resolved_key(provider).await, "AKIAREALDEFAULT0001");
    }

    #[tokio::test]
    async fn multi_profile_selects_provider_by_placeholder_key() {
        let route = multi_profile_route();

        let dev = route
            .select_provider(&agent_auth("NONOPROFILE0DEVRO01"))
            .unwrap();
        assert_eq!(resolved_key(dev).await, "AKIAREALDEVRO000001");

        let staging = route
            .select_provider(&agent_auth("NONOPROFILE0STGRO01"))
            .unwrap();
        assert_eq!(resolved_key(staging).await, "AKIAREALSTGRO000001");
    }

    #[test]
    fn multi_profile_rejects_unlisted_access_key_id() {
        let route = multi_profile_route();
        let err = route
            .select_provider(&agent_auth("NONOPROFILE0OTHER01"))
            .err()
            .unwrap();
        assert_eq!(err, ProviderSelectionError::UnknownAccessKeyId);
    }

    #[test]
    fn multi_profile_rejects_missing_authorization() {
        let route = multi_profile_route();
        let err = route.select_provider(&[]).err().unwrap();
        assert_eq!(err, ProviderSelectionError::MissingAccessKeyId);
    }

    #[test]
    fn debug_lists_profile_names_not_placeholder_keys() {
        let rendered = format!("{:?}", multi_profile_route());
        assert!(rendered.contains("dev-ro"), "{rendered}");
        assert!(rendered.contains("staging-ro"), "{rendered}");
        assert!(!rendered.contains("NONOPROFILE0DEVRO01"), "{rendered}");
    }
}
