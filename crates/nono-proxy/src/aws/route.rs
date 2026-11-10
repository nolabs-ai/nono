//! `AwsRoute` and `AwsRouteTable` — per-route AWS SigV4 state.
//!
//! `AwsRoute` holds the resolved region, service, upstream URL, and
//! `SharedCredentialsProvider` for one SigV4-enabled route.  `AwsRouteTable`
//! maps route prefixes to `AwsRoute` entries and maintains a provider cache
//! so routes sharing the same AWS profile reuse the same provider.

use std::collections::{BTreeMap, HashMap};

use aws_credential_types::provider::SharedCredentialsProvider;
use tracing::debug;

use super::endpoints::SigningRegion;

/// A fully-resolved AWS SigV4 route entry.
pub struct AwsRoute {
    /// The upstream URL (e.g., `https://bedrock-runtime.us-east-1.amazonaws.com`).
    /// Used to extract `Host` when building the signable URL.
    pub upstream: String,

    /// SigV4 signing region: fixed, or derived from each request's host.
    pub region: SigningRegion,

    /// Literal service label of a `{service}.*.amazonaws.com` upstream.
    /// `Some` exactly when `region` is [`SigningRegion::FromRequestHost`].
    pub service_label: Option<String>,

    /// SigV4 service name (e.g., `"bedrock"`).
    pub service: String,

    /// The identity (or operator-approved identities) this route signs with.
    pub credentials: AwsRouteCredentials,

    /// Session secret registry. Each resolved secret access key and session
    /// token is registered here before signing (NEP-0010 §3.1).
    pub(crate) secret_registry: Option<crate::secret_registry::SecretRegistry>,
}

/// How an `AwsRoute` chooses the credentials it signs with.
#[non_exhaustive]
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

impl AwsRoute {
    /// Non-secret name resolved AWS credentials are registered under.
    pub(crate) fn registry_name(&self) -> String {
        match &self.credentials {
            AwsRouteCredentials::Single { profile_key, .. } => {
                format!("aws:{}", profile_key.as_deref().unwrap_or("default"))
            }
            AwsRouteCredentials::ByAccessKeyId(_) => "aws:profiles".to_string(),
        }
    }
}

/// The identity chosen for one request by [`AwsRoute::select_provider`].
#[derive(Clone, Copy)]
pub struct SelectedProvider<'a> {
    /// Host profile the request signs as, or `None` for the default chain.
    /// Not secret; logged so operators can tell which identity signed.
    pub profile: Option<&'a str>,
    /// Credential provider to sign with.
    pub provider: &'a SharedCredentialsProvider,
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
                "request has no single well-formed SigV4 Authorization header \
                 to select a signing profile from",
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
    ) -> Result<SelectedProvider<'_>, ProviderSelectionError> {
        match &self.credentials {
            AwsRouteCredentials::Single {
                profile_key,
                provider,
            } => Ok(SelectedProvider {
                profile: profile_key.as_deref(),
                provider,
            }),
            AwsRouteCredentials::ByAccessKeyId(profiles) => {
                let access_key_id = super::sign::sigv4_access_key_id(agent_headers)
                    .ok_or(ProviderSelectionError::MissingAccessKeyId)?;
                profiles
                    .get(&access_key_id)
                    .map(|p| SelectedProvider {
                        profile: Some(p.profile.as_str()),
                        provider: &p.provider,
                    })
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
            .field("service_label", &self.service_label)
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
    /// Profile-only providers for `aws_auth.profiles` entries, kept apart from
    /// `providers` because those resolve through the default chain.
    named_profile_providers: HashMap<String, SharedCredentialsProvider>,
    secret_registry: Option<crate::secret_registry::SecretRegistry>,
}

impl AwsRouteTable {
    /// Create an empty table (no AWS routes configured).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            routes: HashMap::new(),
            providers: HashMap::new(),
            named_profile_providers: HashMap::new(),
            secret_registry: None,
        }
    }

    /// Set the registry that routes inserted after this call register their
    /// resolved AWS secrets in.
    pub(crate) fn set_secret_registry(
        &mut self,
        registry: Option<crate::secret_registry::SecretRegistry>,
    ) {
        self.secret_registry = registry;
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

    /// Return the cached profile-only provider for `profile`, building it on
    /// first use.
    ///
    /// Unlike [`Self::provider_for`], the provider never consults the default
    /// chain, so host `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` cannot
    /// shadow the profile an `aws_auth.profiles` entry names. The profile must
    /// exist in the shared config files when the route loads.
    async fn named_profile_provider(
        &mut self,
        profile: &str,
    ) -> Result<SharedCredentialsProvider, String> {
        if let Some(provider) = self.named_profile_providers.get(profile) {
            debug!("aws::route: reusing named-profile provider for profile={profile}");
            return Ok(provider.clone());
        }
        debug!("aws::route: building named-profile provider for profile={profile}");
        let provider = new_named_profile_provider(profile).await?;
        self.named_profile_providers
            .insert(profile.to_string(), provider.clone());
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
        region: SigningRegion,
        service_label: Option<String>,
        service: String,
    ) -> Result<(), String> {
        let provider = self.provider_for(profile).await?;
        self.routes.insert(
            prefix,
            AwsRoute {
                upstream,
                region,
                service_label,
                service,
                credentials: AwsRouteCredentials::Single {
                    profile_key: profile.map(str::to_owned),
                    provider,
                },
                secret_registry: self.secret_registry.clone(),
            },
        );
        Ok(())
    }

    /// Build (or reuse) one provider per entry of `profiles`, then insert a
    /// route that selects among them by placeholder access key ID.
    ///
    /// Each provider resolves only its named profile, never host environment
    /// credentials. All-or-nothing: if any profile is missing from the shared
    /// config files, no route is inserted, so the route is denied rather than
    /// silently narrowed. Credentials are still fetched per request.
    ///
    /// # Errors
    ///
    /// Returns an error string naming the profile that failed to load.
    pub(crate) async fn insert_multi_profile_route(
        &mut self,
        prefix: String,
        profiles: &BTreeMap<String, String>,
        upstream: String,
        region: SigningRegion,
        service_label: Option<String>,
        service: String,
    ) -> Result<(), String> {
        let mut by_key = BTreeMap::new();
        for (access_key_id, profile) in profiles {
            let provider = self
                .named_profile_provider(profile)
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
                service_label,
                service,
                credentials: AwsRouteCredentials::ByAccessKeyId(by_key),
                secret_registry: self.secret_registry.clone(),
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

/// Build a provider that resolves credentials only from the named profile in
/// the shared config files (static keys, SSO, `credential_process`,
/// `login_session`, `role_arn` chains), never from the environment or the
/// rest of the default chain.
///
/// The profile files are parsed once here so a profile that does not exist
/// fails the route at load time instead of on the first request.
async fn new_named_profile_provider(profile: &str) -> Result<SharedCredentialsProvider, String> {
    let env = aws_types::os_shim_internal::Env::real();
    let fs = aws_types::os_shim_internal::Fs::real();
    let profile_files = aws_runtime::env_config::file::EnvConfigFiles::default();
    let profiles = aws_config::profile::load(&fs, &env, &profile_files, None)
        .await
        .map_err(|e| format!("could not load AWS shared config files: {e}"))?;
    if profiles.get_profile(profile).is_none() {
        return Err(format!(
            "profile '{profile}' is not defined in the AWS shared config files"
        ));
    }

    // Region feeds STS/SSO client calls inside the provider (assume-role, SSO
    // portal). Resolved like `aws_config::from_env().profile_name(..)`:
    // AWS_REGION / AWS_DEFAULT_REGION, then this profile's `region`, then IMDS.
    let region = aws_config::default_provider::region::DefaultRegionChain::builder()
        .profile_name(profile)
        .build()
        .region()
        .await;
    let conf = aws_config::provider_config::ProviderConfig::without_region()
        .with_region(region)
        .with_behavior_version(Some(aws_config::BehaviorVersion::latest()));
    let provider = aws_config::profile::ProfileFileCredentialsProvider::builder()
        .configure(&conf)
        .profile_name(profile)
        .build();
    Ok(SharedCredentialsProvider::new(provider))
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
            region: SigningRegion::Fixed("us-east-1".to_string()),
            service_label: None,
            service: "sts".to_string(),
            credentials,
            secret_registry: None,
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
        let selected = route.select_provider(&[]).unwrap();
        assert_eq!(selected.profile, None);
        assert_eq!(resolved_key(selected.provider).await, "AKIAREALDEFAULT0001");
    }

    #[tokio::test]
    async fn multi_profile_selects_provider_by_placeholder_key() {
        let route = multi_profile_route();

        let dev = route
            .select_provider(&agent_auth("NONOPROFILE0DEVRO01"))
            .unwrap();
        assert_eq!(dev.profile, Some("dev-ro"));
        assert_eq!(resolved_key(dev.provider).await, "AKIAREALDEVRO000001");

        let staging = route
            .select_provider(&agent_auth("NONOPROFILE0STGRO01"))
            .unwrap();
        assert_eq!(staging.profile, Some("staging-ro"));
        assert_eq!(resolved_key(staging.provider).await, "AKIAREALSTGRO000001");
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod load_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn write_profiles(dir: &std::path::Path) -> (String, String) {
        let config = dir.join("config");
        std::fs::write(&config, "[profile dev-ro]\nregion = us-east-1\n").unwrap();
        let credentials = dir.join("credentials");
        std::fs::write(
            &credentials,
            "[dev-ro]\naws_access_key_id = AKIAREALDEVRO000001\naws_secret_access_key = s\n",
        )
        .unwrap();
        (
            config.to_str().unwrap().to_string(),
            credentials.to_str().unwrap().to_string(),
        )
    }

    #[test]
    fn multi_profile_route_rejects_profile_missing_from_config_files() {
        let _lock = crate::test_env::ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (config, credentials) = write_profiles(dir.path());
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("AWS_CONFIG_FILE", &config),
            ("AWS_SHARED_CREDENTIALS_FILE", &credentials),
            ("AWS_EC2_METADATA_DISABLED", "true"),
        ]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut table = AwsRouteTable::empty();
            let profiles: BTreeMap<String, String> = [
                ("NONOPROFILE0DEVRO01".to_string(), "dev-ro".to_string()),
                (
                    "NONOPROFILE0NOPE001".to_string(),
                    "does-not-exist".to_string(),
                ),
            ]
            .into_iter()
            .collect();
            let err = table
                .insert_multi_profile_route(
                    "sts".to_string(),
                    &profiles,
                    "https://sts.us-east-1.amazonaws.com".to_string(),
                    SigningRegion::Fixed("us-east-1".to_string()),
                    None,
                    "sts".to_string(),
                )
                .await
                .unwrap_err();
            assert!(err.contains("does-not-exist"), "{err}");
            assert!(table.get("sts").is_none(), "route must not be inserted");
        });
    }

    /// `credential_process` profiles resolve
    /// through the profile-only provider, and host env credentials do not
    /// shadow them.
    #[test]
    fn named_profile_provider_resolves_credential_process_over_host_env() {
        let _lock = crate::test_env::ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("creds.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho '{\"Version\":1,\"AccessKeyId\":\"AKIAPROCESS00000001\",\"SecretAccessKey\":\"s\",\"SessionToken\":\"t\"}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = dir.path().join("config");
        std::fs::write(
            &config,
            format!(
                "[profile proc]\nregion = us-east-1\ncredential_process = {}\n",
                script.display()
            ),
        )
        .unwrap();
        let empty = dir.path().join("credentials");
        std::fs::write(&empty, "").unwrap();
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("AWS_CONFIG_FILE", config.to_str().unwrap()),
            ("AWS_SHARED_CREDENTIALS_FILE", empty.to_str().unwrap()),
            ("AWS_ACCESS_KEY_ID", "AKIAHOSTENVIRON0001"),
            ("AWS_SECRET_ACCESS_KEY", "host-env-secret"),
            ("AWS_EC2_METADATA_DISABLED", "true"),
        ]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            use aws_credential_types::provider::ProvideCredentials;
            let provider = new_named_profile_provider("proc").await.unwrap();
            let creds = provider.provide_credentials().await.unwrap();
            assert_eq!(creds.access_key_id(), "AKIAPROCESS00000001");
        });
    }

    #[test]
    fn multi_profile_route_loads_when_every_profile_exists() {
        let _lock = crate::test_env::ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (config, credentials) = write_profiles(dir.path());
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("AWS_CONFIG_FILE", &config),
            ("AWS_SHARED_CREDENTIALS_FILE", &credentials),
            ("AWS_EC2_METADATA_DISABLED", "true"),
        ]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut table = AwsRouteTable::empty();
            let profiles: BTreeMap<String, String> =
                [("NONOPROFILE0DEVRO01".to_string(), "dev-ro".to_string())]
                    .into_iter()
                    .collect();
            table
                .insert_multi_profile_route(
                    "sts".to_string(),
                    &profiles,
                    "https://sts.us-east-1.amazonaws.com".to_string(),
                    SigningRegion::Fixed("us-east-1".to_string()),
                    None,
                    "sts".to_string(),
                )
                .await
                .unwrap();
            assert!(table.get("sts").is_some());
        });
    }
}
