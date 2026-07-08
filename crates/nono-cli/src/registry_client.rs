//! Registry client for package hosting.

use crate::package::{
    PackageRef, PackageSearchResponse, PackageSearchResult, PackageStatusResponse, PullResponse,
    YankedErrorResponse,
};
use nono::{NonoError, Result};
use serde::de::DeserializeOwned;
use sha2::Digest;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_REGISTRY_URL: &str = "https://registry.nono.sh";
const REGISTRY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REGISTRY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const REGISTRY_BODY_TIMEOUT: Duration = Duration::from_secs(300);
const REGISTRY_CALL_TIMEOUT: Duration = Duration::from_secs(300);
const REGISTRY_JSON_LIMIT_BYTES: u64 = 2 * 1024 * 1024;
const REGISTRY_BUNDLE_LIMIT_BYTES: u64 = 8 * 1024 * 1024;
const REGISTRY_ARTIFACT_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

pub struct RegistryClient {
    base_url: String,
    http: ureq::Agent,
}

/// Build the installation-context headers to attach to every registry request.
///
/// Headers included:
/// - `X-Nono-UUID`: installation UUID if a state file exists (omitted otherwise)
/// - `X-Nono-Platform`: OS name (`std::env::consts::OS`)
/// - `X-Nono-Arch`: CPU architecture (`std::env::consts::ARCH`)
/// - `X-Nono-CI`: `"true"` when a recognised CI environment is detected
/// - `X-Nono-CI-Provider`: CI provider name when detected
/// - `X-Nono-Install-Source`: install method (`homebrew`, `cargo`, `github_release`, `manual`, `unknown`)
///
/// This function never creates or writes any files.
pub(crate) fn build_context_headers() -> Vec<(&'static str, String)> {
    let mut headers: Vec<(&'static str, String)> = Vec::new();
    if let Some(uuid) = crate::update_check::read_installation_uuid() {
        headers.push(("X-Nono-UUID", uuid));
    }
    headers.push(("X-Nono-Platform", std::env::consts::OS.to_string()));
    headers.push(("X-Nono-Arch", std::env::consts::ARCH.to_string()));
    let ci_provider = crate::update_check::detect_ci_provider();
    if ci_provider.is_some() {
        headers.push(("X-Nono-CI", "true".to_string()));
    }
    if let Some(provider) = ci_provider {
        headers.push(("X-Nono-CI-Provider", provider.to_string()));
    }
    headers.push((
        "X-Nono-Install-Source",
        crate::update_check::detect_install_source(),
    ));
    headers
}

/// Why a `/pull` request was made. Sent only on that request via the
/// `X-Nono-Pull-Reason` header, so the registry can distinguish a
/// deliberate user-initiated install from a CI-driven or implicit one.
/// Unlike the installation-context headers above, this doesn't apply to
/// every registry call — only `/pull` has more than one possible trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullReason {
    /// `nono pull <ns>/<name>` invoked directly.
    Explicit,
    /// `nono update` re-pulling an outdated pack.
    Update,
    /// First-run legacy-config migration auto-installing a suggested pack.
    Migration,
    /// Silent implicit pull because a `--profile <ns>/<name>` reference
    /// (including an `extends` chain) wasn't installed locally.
    ProfileAuto,
}

impl PullReason {
    fn header_value(self) -> &'static str {
        match self {
            PullReason::Explicit => "explicit",
            PullReason::Update => "update",
            PullReason::Migration => "migration",
            PullReason::ProfileAuto => "profile-auto",
        }
    }
}

impl RegistryClient {
    /// Build a registry client whose TLS verifier delegates to the OS-native
    /// trust store at handshake time (SecTrust on macOS, system CA stores on
    /// Linux). This picks up corporate or MDM-installed root CAs — including
    /// the kind injected by VPN-based TLS-inspecting proxies — that the bundled
    /// webpki roots wouldn't recognize, without any startup-time enumeration of
    /// the keychain (which can spuriously fail in restricted environments).
    ///
    /// Installation-context headers (`X-Nono-UUID`, `X-Nono-Platform`,
    /// `X-Nono-Arch`, `X-Nono-CI`, `X-Nono-CI-Provider`,
    /// `X-Nono-Install-Source`) are attached via a middleware registered on the
    /// agent at construction time. The middleware only injects these headers
    /// when the request host matches the registry host — preventing them from
    /// being forwarded to CDN or other third-party hosts that may appear in
    /// bundle or artifact download URLs.
    #[must_use]
    pub fn new(base_url: String) -> Self {
        let version = env!("CARGO_PKG_VERSION");
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let ctx_headers = build_context_headers();
        // Extract the registry host once at construction; the middleware uses
        // it to guard header injection so context headers are never forwarded
        // to CDN hosts in bundle/artifact download URLs.
        let registry_host = url::Url::parse(&base_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
            .unwrap_or_default();
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(REGISTRY_CALL_TIMEOUT))
            .timeout_resolve(Some(REGISTRY_CONNECT_TIMEOUT))
            .timeout_connect(Some(REGISTRY_CONNECT_TIMEOUT))
            .timeout_recv_response(Some(REGISTRY_RESPONSE_TIMEOUT))
            .timeout_recv_body(Some(REGISTRY_BODY_TIMEOUT))
            .tls_config(tls_config)
            .user_agent(format!("nono-cli/{version}"))
            .middleware(
                move |mut req: ureq::http::Request<ureq::SendBody>,
                      next: ureq::middleware::MiddlewareNext<'_>| {
                    let req_host = req
                        .uri()
                        .host()
                        .map(|h| h.to_ascii_lowercase())
                        .unwrap_or_default();
                    if req_host == registry_host {
                        for (name, value) in &ctx_headers {
                            if let Ok(hv) =
                                ureq::http::header::HeaderValue::try_from(value.as_str())
                            {
                                req.headers_mut().insert(*name, hv);
                            }
                        }
                    }
                    next.handle(req)
                },
            )
            .build()
            .new_agent();
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        }
    }

    pub fn fetch_pull_response(
        &self,
        package_ref: &PackageRef,
        version: &str,
        reason: PullReason,
    ) -> Result<PullResponse> {
        let url = format!(
            "{}/api/v1/packages/{}/{}/versions/{version}/pull",
            self.base_url, package_ref.namespace, package_ref.name
        );
        let mut response = self
            .http
            .get(&url)
            .header("X-Nono-Pull-Reason", reason.header_value())
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(map_ureq_error)?;

        if response.status().as_u16() == 410 {
            enforce_content_length(
                response.body().content_length(),
                REGISTRY_JSON_LIMIT_BYTES,
                &url,
            )?;
            let body = response
                .body_mut()
                .with_config()
                .limit(REGISTRY_JSON_LIMIT_BYTES)
                .read_to_string()
                .map_err(|e| {
                    NonoError::RegistryError(format!(
                        "failed to read registry response from {}: {}",
                        url, e
                    ))
                })?;
            let yanked: YankedErrorResponse =
                serde_json::from_str(&body).unwrap_or(YankedErrorResponse {
                    error: None,
                    yanked: true,
                    yank_reason: None,
                    advisory: None,
                });
            let mut msg = format!(
                "{}/{}@{} has been yanked",
                package_ref.namespace, package_ref.name, version
            );
            if let Some(reason) = &yanked.yank_reason {
                msg.push_str(&format!(" (reason: {reason})"));
            }
            if let Some(advisory) = &yanked.advisory {
                let severity = advisory.severity.as_deref().unwrap_or("unknown");
                let summary = advisory.summary.as_deref().unwrap_or("");
                if !summary.is_empty() {
                    msg.push_str(&format!("\nadvisory: {severity} — {summary}"));
                } else {
                    msg.push_str(&format!("\nadvisory severity: {severity}"));
                }
            }
            msg.push_str(&format!(
                "\ninstall the latest safe release: nono pull {}/{}",
                package_ref.namespace, package_ref.name
            ));
            return Err(NonoError::RegistryError(msg));
        }

        if !response.status().is_success() {
            return Err(NonoError::RegistryError(format!(
                "registry returned HTTP {} for {}/{}@{}",
                response.status().as_u16(),
                package_ref.namespace,
                package_ref.name,
                version
            )));
        }

        enforce_content_length(
            response.body().content_length(),
            REGISTRY_JSON_LIMIT_BYTES,
            &url,
        )?;
        let body = response
            .body_mut()
            .with_config()
            .limit(REGISTRY_JSON_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::RegistryError(format!(
                    "failed to read registry response from {}: {}",
                    url, e
                ))
            })?;
        serde_json::from_str(&body).map_err(|e| {
            NonoError::RegistryError(format!("failed to decode registry response: {e}"))
        })
    }

    pub fn search_packages(&self, query: &str) -> Result<Vec<PackageSearchResult>> {
        let response: PackageSearchResponse =
            self.get_json(&format!("/api/v1/packages?q={query}"))?;
        Ok(response.packages)
    }

    pub fn fetch_package_status(
        &self,
        package_ref: &PackageRef,
        installed: Option<&str>,
    ) -> Result<PackageStatusResponse> {
        let mut path = format!(
            "/api/v1/packages/{}/{}/status",
            package_ref.namespace, package_ref.name
        );
        if let Some(installed) = installed {
            let encoded: String =
                url::form_urlencoded::byte_serialize(installed.as_bytes()).collect();
            path.push_str("?installed=");
            path.push_str(&encoded);
        }
        self.get_json(&path)
    }

    /// Look up which packs (if any) ship a profile with the given
    /// `install_as` name. Used by the migration prompt to discover
    /// which pack to offer when `--profile <name>` misses every local
    /// resolver. Returns `Ok(vec![])` if the registry has no providers
    /// for that name.
    pub fn fetch_profile_providers(
        &self,
        profile_name: &str,
    ) -> Result<Vec<crate::package::ProfileProvider>> {
        let response: crate::package::ProfileProvidersResponse =
            self.get_json(&format!("/api/v1/profiles/{profile_name}/providers"))?;
        Ok(response.providers)
    }

    pub fn download_bundle(&self, url: &str) -> Result<String> {
        let resolved_url = self.resolve_url(url);
        let mut response = self
            .http
            .get(&resolved_url)
            .call()
            .map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_BUNDLE_LIMIT_BYTES,
            &resolved_url,
        )?;
        response
            .body_mut()
            .with_config()
            .limit(REGISTRY_BUNDLE_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::RegistryError(format!(
                    "failed to read registry response from {}: {}",
                    resolved_url, e
                ))
            })
    }

    pub fn download_artifact_to_path(&self, url: &str, dest: &Path) -> Result<String> {
        let resolved_url = self.resolve_url(url);
        let mut response = self
            .http
            .get(&resolved_url)
            .call()
            .map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_ARTIFACT_LIMIT_BYTES,
            &resolved_url,
        )?;

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(NonoError::Io)?;
        }

        let mut reader = response
            .body_mut()
            .with_config()
            .limit(REGISTRY_ARTIFACT_LIMIT_BYTES)
            .reader();
        let mut file = fs::File::create(dest).map_err(NonoError::Io)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0_u8; 8192];

        loop {
            let bytes_read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(error) => {
                    let _ = fs::remove_file(dest);
                    return Err(NonoError::RegistryError(format!(
                        "failed to read registry response from {}: {}",
                        resolved_url, error
                    )));
                }
            };
            file.write_all(&buffer[..bytes_read])
                .map_err(NonoError::Io)?;
            use sha2::Digest as _;
            hasher.update(&buffer[..bytes_read]);
        }

        let digest = hasher.finalize();
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut response = self.http.get(&url).call().map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_JSON_LIMIT_BYTES,
            &url,
        )?;
        let body = response
            .body_mut()
            .with_config()
            .limit(REGISTRY_JSON_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::RegistryError(format!(
                    "failed to read registry response from {}: {}",
                    url, e
                ))
            })?;
        serde_json::from_str(&body).map_err(|e| {
            NonoError::RegistryError(format!("failed to decode registry response: {e}"))
        })
    }

    fn resolve_url(&self, url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("{}{}", self.base_url, url)
        }
    }
}

pub fn resolve_registry_url(override_url: Option<&str>) -> String {
    override_url
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("NONO_REGISTRY").ok())
        .unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string())
}

fn map_ureq_error(error: ureq::Error) -> NonoError {
    NonoError::RegistryError(error.to_string())
}

fn enforce_content_length(content_length: Option<u64>, limit: u64, url: &str) -> Result<()> {
    if let Some(content_length) = content_length
        && content_length > limit
    {
        return Err(NonoError::RegistryError(format!(
            "registry response from {} exceeds {} bytes",
            url, limit
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};

    #[test]
    fn registry_client_normalizes_base_url() {
        // Trailing slash should be stripped. Construction is infallible because
        // TLS verification is delegated to the OS verifier at handshake time.
        let client = RegistryClient::new("https://example.invalid/".to_string());
        assert_eq!(client.base_url, "https://example.invalid");
    }

    #[test]
    fn context_headers_contain_platform_and_arch() {
        let headers = build_context_headers();
        let platform = headers.iter().find(|(k, _)| *k == "X-Nono-Platform");
        let arch = headers.iter().find(|(k, _)| *k == "X-Nono-Arch");
        assert_eq!(
            platform.map(|(_, v)| v.as_str()),
            Some(std::env::consts::OS)
        );
        assert_eq!(arch.map(|(_, v)| v.as_str()), Some(std::env::consts::ARCH));
    }

    #[test]
    fn context_headers_omit_ci_fields_outside_ci() {
        let _lock = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Unset all recognised CI env vars so detect_ci_provider returns None.
        let ci_vars: &[(&'static str, &str)] = &[
            ("GITHUB_ACTIONS", ""),
            ("GITLAB_CI", ""),
            ("CIRCLECI", ""),
            ("BUILDKITE", ""),
            ("TF_BUILD", ""),
            ("TRAVIS", ""),
            ("JENKINS_URL", ""),
            ("JENKINS_HOME", ""),
            ("BITBUCKET_BUILD_NUMBER", ""),
            ("APPVEYOR", ""),
            ("TEAMCITY_VERSION", ""),
            ("DRONE", ""),
            ("SEMAPHORE", ""),
            ("CODESHIP", ""),
            ("WOODPECKER", ""),
            ("NETLIFY", ""),
            ("VERCEL", ""),
            ("RENDER", ""),
            ("CI", ""),
        ];
        let guard = EnvVarGuard::set_all(ci_vars);
        for (k, _) in ci_vars {
            guard.remove(k);
        }

        let headers = build_context_headers();
        assert!(
            !headers.iter().any(|(k, _)| *k == "X-Nono-CI"),
            "X-Nono-CI should be absent outside CI"
        );
        assert!(
            !headers.iter().any(|(k, _)| *k == "X-Nono-CI-Provider"),
            "X-Nono-CI-Provider should be absent outside CI"
        );
    }

    #[test]
    fn context_headers_include_ci_fields_in_ci() {
        let _lock = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _guard = EnvVarGuard::set_all(&[("GITHUB_ACTIONS", "true")]);

        let headers = build_context_headers();
        let ci = headers.iter().find(|(k, _)| *k == "X-Nono-CI");
        let provider = headers.iter().find(|(k, _)| *k == "X-Nono-CI-Provider");
        assert_eq!(
            ci.map(|(_, v)| v.as_str()),
            Some("true"),
            "X-Nono-CI should be 'true' in CI"
        );
        assert_eq!(
            provider.map(|(_, v)| v.as_str()),
            Some("github_actions"),
            "X-Nono-CI-Provider should be 'github_actions'"
        );
    }

    #[test]
    fn pull_reason_header_values_are_distinct_and_stable() {
        assert_eq!(PullReason::Explicit.header_value(), "explicit");
        assert_eq!(PullReason::Update.header_value(), "update");
        assert_eq!(PullReason::Migration.header_value(), "migration");
        assert_eq!(PullReason::ProfileAuto.header_value(), "profile-auto");
    }
}
