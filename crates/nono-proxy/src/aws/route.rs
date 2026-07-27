//! `AwsRoute` and `AwsRouteTable` — per-route AWS SigV4 state.
//!
//! `AwsRoute` holds the resolved region, service, upstream URL, and
//! `SharedCredentialsProvider` for one SigV4-enabled route.  `AwsRouteTable`
//! maps route prefixes to `AwsRoute` entries and maintains a provider cache
//! so routes sharing the same AWS profile reuse the same provider.

use std::collections::HashMap;

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

    /// The profile used when building the provider, if any.
    /// `None` means the default credential chain was used.
    /// Stored so the `Debug` impl can report which identity source is active.
    pub profile_key: Option<String>,

    /// Credential provider. Shared across routes with the same `profile_key`
    /// to avoid duplicate STS/SSO refreshes.
    pub provider: SharedCredentialsProvider,
}

impl std::fmt::Debug for AwsRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsRoute")
            .field("upstream", &self.upstream)
            .field("region", &self.region)
            .field("service", &self.service)
            .field("profile_key", &self.profile_key)
            .field("provider", &"[SharedCredentialsProvider]")
            .finish()
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

    /// Build (or reuse) a provider for `profile`, then insert the route.
    ///
    /// If a provider for the same profile has already been built during this
    /// load pass it is reused, so routes sharing a profile share one
    /// `LazyCredentialsCache` and avoid duplicate STS/SSO/IMDS refreshes.
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
        let profile_key: Option<String> = profile.map(str::to_owned);

        if !self.providers.contains_key(&profile_key) {
            debug!(
                "aws::route: building provider for profile={:?}",
                profile_key
            );
            let provider = new_provider(profile).await?;
            self.providers.insert(profile_key.clone(), provider);
        } else {
            debug!("aws::route: reusing provider for profile={:?}", profile_key);
        }

        let provider = self.providers[&profile_key].clone();
        self.routes.insert(
            prefix,
            AwsRoute {
                upstream,
                region,
                service,
                profile_key,
                provider,
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
