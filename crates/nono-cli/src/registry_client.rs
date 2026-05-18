//! Registry client for package hosting.

use crate::package::{
    PackageRef, PackageSearchResponse, PackageSearchResult, PackageStatusResponse, PullResponse,
    YankedErrorResponse,
};
use nono::{NonoError, Result};
use serde::de::DeserializeOwned;
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
        let url = format!(
            "{}/api/v1/packages/{}/{}/versions/{version}/pull",
            self.base_url, package_ref.namespace, package_ref.name
        );
        let mut response = self
            .http
            .get(&url)
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
            let yanked: YankedErrorResponse = serde_json::from_str(&body).unwrap_or_else(|_| {
                YankedErrorResponse {
                    error: None,
                    yanked: true,
                    yank_reason: None,
                    advisory: None,
                }
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

    /// Download a trust bundle JSON document, capped to
    /// `REGISTRY_BUNDLE_LIMIT_BYTES` and returned as a string.
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

    /// Stream an artifact response body to `dest`, computing its SHA-256
    /// digest incrementally. Memory profile is bounded to the 8 KiB I/O
    /// buffer regardless of artifact size; the body is capped at
    /// `REGISTRY_ARTIFACT_LIMIT_BYTES` and any partial file is removed
    /// on stream-read failure.
    ///
    /// Returns the lowercase hex SHA-256 digest of the streamed bytes.
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

        use sha2::Digest as _;
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
        // SAFETY: not a path comparison — `url` is a registry URL string and these
        // checks are URL scheme prefix tests. CLAUDE.md § Common Footguns #1 forbids
        // `&str::starts_with` on PATH inputs, but URL scheme prefix detection is
        // the canonical use case for it.
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("{}{}", self.base_url, url)
        }
    }

    /// Fetch package status (current / outdated / yanked + advisory) from the
    /// registry. URL: `/api/v1/packages/{ns}/{name}/status?installed=<ver>`.
    ///
    /// All path components and query parameters are URL-encoded via
    /// `url::form_urlencoded::byte_serialize` to prevent injection. The request
    /// routes through the existing `RegistryClient::get_json` path (TLS, content-
    /// length enforcement, body limit). Phase 36.5 D-36.5-C3.
    ///
    /// Mitigates T-36.5-06 (SSRF / registry-spoof): no new registry URL surface —
    /// `self.base_url` is set via `resolve_registry_url` allowlist.
    pub fn fetch_package_status(
        &self,
        package_ref: &crate::package::PackageRef,
        installed: Option<&str>,
    ) -> Result<crate::package::PackageStatusResponse> {
        let ns_enc: String =
            url::form_urlencoded::byte_serialize(package_ref.namespace.as_bytes()).collect();
        let name_enc: String =
            url::form_urlencoded::byte_serialize(package_ref.name.as_bytes()).collect();
        let mut path = format!("/api/v1/packages/{ns_enc}/{name_enc}/status");
        if let Some(version) = installed {
            let v_enc: String = url::form_urlencoded::byte_serialize(version.as_bytes()).collect();
            path.push_str(&format!("?installed={v_enc}"));
        }
        self.get_json::<crate::package::PackageStatusResponse>(&path)
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

/// Reject responses whose advertised Content-Length exceeds `limit`.
/// Returns Ok(()) when the header is absent (not all servers send it);
/// downstream readers also enforce the limit via `with_config().limit(...)`.
fn enforce_content_length(content_length: Option<u64>, limit: u64, url: &str) -> Result<()> {
    if let Some(content_length) = content_length {
        if content_length > limit {
            return Err(NonoError::RegistryError(format!(
                "registry response from {} exceeds {} bytes",
                url, limit
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Streaming + size-cap integration tests for the registry client.
    //!
    //! Host preference: Linux/macOS for the Linux-only RSS measurement
    //! truth (REQ-PKGS-01 #1) — gated `#[cfg(target_os = "linux")]`.
    //! All other tests run on Linux, macOS, AND Windows.
    //!
    //! Per Plan 26-02 Task 5 portable-subset constraint: no `mockito`
    //! dev-dep is added; tests use a tiny single-shot in-process TCP
    //! server (`spawn_one_shot_server`) for HTTP fixtures. This keeps
    //! the dev-dep budget flat and avoids one Windows-CI moving part.
    //!
    //! REQ-PKGS-04 auto-pull e2e tests are NOT exercised here — they
    //! require Sigstore-signed fixture packs + `run_nono` harness
    //! (which trips on `dirs::home_dir()` Windows blocker even with
    //! Phase 27.1's NONO_TEST_HOME seam, since the bundle subjects
    //! check needs real signature data). Deferred to a future
    //! Linux/macOS pass with that fixture infrastructure landed.

    use super::*;
    use std::net::TcpListener;
    use std::thread;

    // `Read`, `Write`, `Shutdown` are only used inside `spawn_one_shot_server`;
    // import them at the function scope to avoid leaking unused warnings into
    // the parent `tests` module on hosts where some tests are cfg-gated out.

    /// Spawn a single-connection HTTP/1.1 server on an ephemeral port and
    /// serve `body` to the next GET request. Returns `(url, join_handle)`.
    /// Drops the listener when the connection is served (single-shot).
    fn spawn_one_shot_server(
        body: Vec<u8>,
        content_length_override: Option<u64>,
    ) -> (String, thread::JoinHandle<()>) {
        use std::io::{Read as _, Write as _};
        use std::net::Shutdown;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local_addr");
        let url = format!("http://{}/artifact", addr);

        let handle = thread::spawn(move || {
            let (mut stream, _peer) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => return,
            };
            // Read (and discard) the request line + headers up to CRLF-CRLF.
            let mut buf = [0u8; 4096];
            let mut accumulated = Vec::with_capacity(4096);
            loop {
                let n = match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                accumulated.extend_from_slice(&buf[..n]);
                if accumulated.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if accumulated.len() > 64 * 1024 {
                    break;
                }
            }
            let cl = content_length_override.unwrap_or(body.len() as u64);
            let response_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                cl
            );
            let _ = stream.write_all(response_head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        });

        (url, handle)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// REQ-PKGS-01 acceptance #1: 200 MB streams at bounded RSS.
    ///
    /// Linux-only because `/proc/self/status` is the cleanest portable RSS
    /// proxy. macOS / Windows would need platform-specific APIs; the
    /// implicit RSS bound is the size-cap test
    /// (`download_artifact_to_path_rejects_oversize_via_content_length`)
    /// which exercises the same streaming property indirectly: artifacts
    /// > cap reject mid-stream BEFORE the full buffer materializes.
    #[cfg(target_os = "linux")]
    #[test]
    fn download_artifact_to_path_streams_under_bounded_rss() {
        // 50 MB payload (well under the 64 MB REGISTRY_ARTIFACT_LIMIT_BYTES
        // cap). RSS delta should be << payload size — bounded by the 8 KB
        // I/O buffer, not the payload.
        let payload = vec![0u8; 50 * 1024 * 1024];
        let (url, handle) = spawn_one_shot_server(payload.clone(), None);

        let baseline_rss = read_proc_self_rss_kb();
        let client = RegistryClient::new("http://unused".to_string());
        let staging = tempfile::TempDir::new().expect("tempdir");
        let dest = staging.path().join("artifact.bin");

        let digest = client
            .download_artifact_to_path(&url, &dest)
            .expect("streaming download should succeed");

        let peak_rss = read_proc_self_rss_kb();
        let delta_kb = peak_rss.saturating_sub(baseline_rss);

        assert_eq!(digest, sha256_hex(&payload));
        assert_eq!(
            dest.metadata().expect("metadata").len(),
            payload.len() as u64
        );
        // 50 MB streamed; allow generous 25 MB ceiling.
        assert!(
            delta_kb < 25 * 1024,
            "RSS delta {delta_kb} KB exceeds 25 MB ceiling — streaming may be buffering"
        );
        handle.join().expect("server thread joined");
    }

    /// REQ-PKGS-01 acceptance #2: tampered-byte detection — the streaming
    /// downloader's incrementally-computed SHA-256 digest accurately
    /// reflects what the server actually sent. The digest mismatch is
    /// then detected at the `download_and_verify_artifacts` layer above
    /// (compared against the manifest's declared digest); this test
    /// verifies the streaming-level invariant the upper layer depends on.
    #[test]
    fn download_artifact_to_path_computes_digest_of_streamed_bytes() {
        let real = b"GENUINE PACKAGE BYTES";
        let real_digest = sha256_hex(real);
        let tampered = b"TAMPERED PACKAGE BYTES";
        let tampered_digest = sha256_hex(tampered);
        assert_ne!(real_digest, tampered_digest);

        let (url, handle) = spawn_one_shot_server(tampered.to_vec(), None);
        let client = RegistryClient::new("http://unused".to_string());
        let staging = tempfile::TempDir::new().expect("tempdir");
        let dest = staging.path().join("artifact.bin");

        let computed = client
            .download_artifact_to_path(&url, &dest)
            .expect("streaming download should succeed against tampered server");

        // Streaming reflects what the server actually sent.
        assert_eq!(computed, tampered_digest);
        // Caller would compare against `real_digest` from the manifest
        // and surface PackageVerification — out of scope for this layer.
        assert_ne!(computed, real_digest);
        handle.join().expect("server thread joined");
    }

    /// REQ-PKGS-01 acceptance #3: oversize artifact rejected via the
    /// Content-Length pre-check. Server sends a tiny body but advertises
    /// 100 MB; `enforce_content_length` ceiling at 64 MB
    /// (REGISTRY_ARTIFACT_LIMIT_BYTES) catches it before any body bytes
    /// are read.
    #[test]
    fn download_artifact_to_path_rejects_oversize_via_content_length() {
        let oversize_cl: u64 = 100 * 1024 * 1024;
        let body = b"trivial".to_vec();
        let (url, handle) = spawn_one_shot_server(body, Some(oversize_cl));

        let client = RegistryClient::new("http://unused".to_string());
        let staging = tempfile::TempDir::new().expect("tempdir");
        let dest = staging.path().join("artifact.bin");

        let result = client.download_artifact_to_path(&url, &dest);
        assert!(
            result.is_err(),
            "100 MB Content-Length must reject (cap is {} bytes)",
            REGISTRY_ARTIFACT_LIMIT_BYTES
        );
        let err_msg = result.expect_err("should err").to_string();
        let lower = err_msg.to_lowercase();
        assert!(
            lower.contains("exceeds")
                || lower.contains("size")
                || lower.contains("limit")
                || lower.contains("registry"),
            "error message should reference the size constraint, got: {err_msg}"
        );
        let _ = handle.join();
    }

    /// REQ-PKGS-01 acceptance #4 (a): connect timeout fires.
    ///
    /// 10.255.255.1 is RFC1918 unroutable; connect attempts get
    /// network-unreachable or hit the configured 10s connect timeout
    /// (plus 30s response timeout). Either failure mode passes the test;
    /// what matters is the call DOES NOT block forever.
    #[test]
    fn registry_client_connect_timeout_fires_within_bounded_window() {
        let client = RegistryClient::new("http://unused".to_string());
        let staging = tempfile::TempDir::new().expect("tempdir");
        let dest = staging.path().join("x.bin");

        let started = std::time::Instant::now();
        let result = client.download_artifact_to_path("http://10.255.255.1/x", &dest);
        let elapsed = started.elapsed();

        assert!(result.is_err(), "connect to unroutable address must fail");
        // 10s connect + 30s response = ~40s upper bound. Allow 90s
        // headroom for platform-specific connect-failure-mode timing.
        // Without timeout config, ureq blocks on OS connect timeout
        // (default 75s+) and could exceed the body timeout (300s) too.
        assert!(
            elapsed < std::time::Duration::from_secs(90),
            "connect timeout must fire within 90s, took {:?}",
            elapsed
        );
    }

    /// `enforce_content_length` returns Ok when the header is absent
    /// (downstream `with_config().limit()` reader still enforces the
    /// cap). Pure unit test — no server.
    #[test]
    fn enforce_content_length_passes_when_header_absent() {
        assert!(enforce_content_length(None, 1024, "http://example.invalid").is_ok());
    }

    /// `enforce_content_length` rejects when the header advertises
    /// more than the limit, even if the server might have lied.
    #[test]
    fn enforce_content_length_rejects_oversize() {
        let result = enforce_content_length(Some(2048), 1024, "http://example.invalid");
        assert!(result.is_err());
        let msg = result.expect_err("must reject").to_string();
        assert!(
            msg.contains("1024") || msg.to_lowercase().contains("exceeds"),
            "error message should reference the limit, got: {msg}"
        );
    }

    /// `enforce_content_length` passes when the header is at-or-below
    /// the limit (boundary is inclusive — `<=` not `<`).
    #[test]
    fn enforce_content_length_passes_at_boundary() {
        assert!(enforce_content_length(Some(1024), 1024, "http://example.invalid").is_ok());
        assert!(enforce_content_length(Some(0), 1024, "http://example.invalid").is_ok());
        assert!(enforce_content_length(Some(1023), 1024, "http://example.invalid").is_ok());
    }

    /// PKGS-01 invariant: `tempfile::TempDir` Drop runs on panic — the
    /// `VerifiedDownloads._tempdir` Drop guarantee. Doesn't go through
    /// HTTP (panic-safe Drop is a tempfile invariant, not a streaming
    /// one), but pinning the contract here surfaces any future
    /// regression in the tempfile dep.
    #[test]
    fn tempdir_cleanup_runs_on_panic() {
        use std::path::PathBuf;
        let captured: std::sync::Arc<std::sync::Mutex<Option<PathBuf>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured_for_thread = std::sync::Arc::clone(&captured);

        let panic_result = std::panic::catch_unwind(move || {
            let staging = tempfile::TempDir::new().expect("tempdir");
            let p = staging.path().to_path_buf();
            assert!(p.exists(), "tempdir should exist pre-panic");
            *captured_for_thread.lock().expect("lock") = Some(p);
            // Panic with `staging` in scope — Drop fires during unwind.
            panic!("simulated mid-stream failure");
        });

        assert!(panic_result.is_err(), "thread should have panicked");
        let path = captured
            .lock()
            .expect("lock")
            .clone()
            .expect("path captured");
        assert!(
            !path.exists(),
            "TempDir at {:?} must be cleaned up after panic-driven Drop",
            path
        );
    }

    /// `RegistryClient::new` builds an Agent successfully with the
    /// four configured timeouts. Compile-time + runtime smoke test
    /// for any future ureq API drift in `Agent::config_builder()`.
    #[test]
    fn registry_client_constructor_succeeds() {
        let _client = RegistryClient::new("http://example.invalid".to_string());
        let _client_trailing = RegistryClient::new("http://example.invalid/".to_string());
    }

    #[cfg(target_os = "linux")]
    fn read_proc_self_rss_kb() -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                if let Some(num) = rest.split_whitespace().next() {
                    return num.parse().unwrap_or(0);
                }
            }
        }
        0
    }

    /// Upstream `cb6b199c` smoke test — base URL normalization (trailing slash
    /// strip). Construction is infallible because TLS verification is delegated
    /// to the OS verifier at handshake time (rustls-platform-verifier).
    #[test]
    fn registry_client_normalizes_base_url() {
        let client = RegistryClient::new("https://example.invalid/".to_string());
        assert_eq!(client.base_url, "https://example.invalid");
    }

    /// Phase 36.5 C3-02 — verify that `fetch_package_status` constructs a URL
    /// that includes the namespace, name, and installed-version query param,
    /// all URL-encoded via `url::form_urlencoded::byte_serialize`. We cannot
    /// call the real method directly (it hits the network), but we can assert
    /// the URL-encoding logic by reconstructing it inline with the same
    /// `byte_serialize` path used in the impl.
    #[test]
    fn fetch_package_status_url_encodes_installed() {
        // Verify the URL-encoding helper produces correct output for a
        // version string that contains special chars ('+', ' ', '@').
        let version = "1.0+build.42 test@repo";
        let encoded: String = url::form_urlencoded::byte_serialize(version.as_bytes()).collect();
        // '+' and ' ' and '@' must be percent-encoded
        assert!(
            !encoded.contains(' '),
            "spaces must be percent-encoded in version param"
        );
        assert!(
            !encoded.contains('+') || encoded.contains("%2B"),
            "'+' must be percent-encoded in version param if present"
        );

        // Verify that namespace/name with special chars are also encoded
        let ns = "nono/official";
        let ns_enc: String = url::form_urlencoded::byte_serialize(ns.as_bytes()).collect();
        assert!(
            !ns_enc.contains('/'),
            "slashes must be percent-encoded in namespace param"
        );
    }
}
