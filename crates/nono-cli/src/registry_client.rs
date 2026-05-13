//! Registry client for package hosting.

use crate::package::{
    PackageRef, PackageSearchResponse, PackageSearchResult, PackageStatusResponse, PullResponse,
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

impl RegistryClient {
    /// Build a registry client whose TLS verifier delegates to the OS-native
    /// trust store at handshake time (SecTrust on macOS, system CA stores on
    /// Linux). This picks up corporate or MDM-installed root CAs — including
    /// the kind injected by VPN-based TLS-inspecting proxies — that the bundled
    /// webpki roots wouldn't recognize, without any startup-time enumeration of
    /// the keychain (which can spuriously fail in restricted environments).
    #[must_use]
    pub fn new(base_url: String) -> Self {
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(REGISTRY_CALL_TIMEOUT))
            .timeout_resolve(Some(REGISTRY_CONNECT_TIMEOUT))
            .timeout_connect(Some(REGISTRY_CONNECT_TIMEOUT))
            .timeout_recv_response(Some(REGISTRY_RESPONSE_TIMEOUT))
            .timeout_recv_body(Some(REGISTRY_BODY_TIMEOUT))
            .tls_config(tls_config)
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
    ) -> Result<PullResponse> {
        self.get_json(&format!(
            "/api/v1/packages/{}/{}/versions/{version}/pull",
            package_ref.namespace, package_ref.name
        ))
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

    #[test]
    fn registry_client_normalizes_base_url() {
        // Trailing slash should be stripped. Construction is infallible because
        // TLS verification is delegated to the OS verifier at handshake time.
        let client = RegistryClient::new("https://example.invalid/".to_string());
        assert_eq!(client.base_url, "https://example.invalid");
    }
}
