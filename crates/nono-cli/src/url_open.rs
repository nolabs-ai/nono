//! Shared URL validation and browser-opening helpers.
//!
//! Both the supervisor (for the directly-launched process) and the
//! tool-sandbox runtime (for brokered `command_policies` children) delegate
//! browser opens to an unsandboxed process. Because the browser is launched
//! outside the sandbox, the origin/scheme allow-list is the only gate between
//! the sandboxed child and an arbitrary `open`/`xdg-open` invocation.
//!
//! This module is the single source of truth for that gate so the two call
//! sites cannot drift on the security-critical check.

/// Maximum URL length to prevent abuse via oversized URLs.
pub(crate) const MAX_URL_LENGTH: usize = 8192;

/// Validate a URL against an allow-list of origins and scheme rules.
///
/// Returns `Ok(())` if the URL passes all checks. Does not open the browser.
///
/// Rules (fail-secure — anything not explicitly allowed is rejected):
/// - URL must be at most [`MAX_URL_LENGTH`] bytes.
/// - `localhost`/`127.0.0.1`/`::1` are only allowed when `allow_localhost` is
///   set, and only over http/https (for OAuth2 loopback callbacks).
/// - Every other origin must use `https` and exactly match an entry in
///   `allow_origins` (origin = scheme + host + port).
pub(crate) fn validate_url(
    url: &str,
    allow_origins: &[String],
    allow_localhost: bool,
) -> std::result::Result<(), String> {
    if url.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL exceeds maximum length ({} > {})",
            url.len(),
            MAX_URL_LENGTH
        ));
    }

    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if is_localhost {
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "Localhost URL must use http or https scheme, got: {scheme}"
            ));
        }
        if !allow_localhost {
            return Err("Localhost URLs are not allowed by this profile".to_string());
        }
    } else {
        // Non-localhost: must be https
        if scheme != "https" {
            return Err(format!(
                "Only https:// URLs are allowed (got {scheme}://). \
                 file://, javascript:, data:, and other schemes are blocked."
            ));
        }

        let url_origin = parsed.origin().unicode_serialization();
        if !allow_origins.iter().any(|origin| origin == &url_origin) {
            return Err(format!(
                "Origin {url_origin} is not in the profile's open_urls.allow_origins list"
            ));
        }
    }

    Ok(())
}

/// Open a URL in the user's default browser.
///
/// Uses `open` on macOS and `xdg-open` on Linux. Must be called from an
/// unsandboxed process so the browser has full system access. `outer_caps`
/// is the sandbox's write policy: PATH entries the sandbox could write to
/// are stripped before this bare-name lookup runs, so a sandboxed process
/// cannot plant a trojan `open`/`xdg-open` for this host-side broker to run.
pub(crate) fn open_url_in_browser(
    url: &str,
    outer_caps: &nono::CapabilitySet,
) -> std::result::Result<(), String> {
    #[cfg(target_os = "macos")]
    const BROWSER_OPENER: &str = "open";
    #[cfg(target_os = "linux")]
    const BROWSER_OPENER: &str = "xdg-open";
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let safe_path = nono::sanitize_broker_path_for_binary(
        &std::env::var("PATH").unwrap_or_default(),
        BROWSER_OPENER,
        outer_caps,
    );

    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open")
        .arg(url)
        .env("PATH", &safe_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open")
        .arg(url)
        .env("PATH", &safe_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: std::result::Result<std::process::ExitStatus, std::io::Error> =
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "URL opening not supported on this platform",
        ));

    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("Browser opener exited with status: {status}")),
        Err(e) => Err(format!("Failed to launch browser: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_url() {
        let url = format!("https://example.com/{}", "a".repeat(MAX_URL_LENGTH));
        let err = validate_url(&url, &["https://example.com".to_string()], false)
            .expect_err("oversized URL must be rejected");
        assert!(err.contains("maximum length"), "got: {err}");
    }

    #[test]
    fn allows_exact_origin_match_over_https() {
        validate_url(
            "https://github.com/login/oauth",
            &["https://github.com".to_string()],
            false,
        )
        .expect("exact origin over https should be allowed");
    }

    #[test]
    fn rejects_unlisted_origin() {
        let err = validate_url(
            "https://evil.example.com/oauth",
            &["https://github.com".to_string()],
            false,
        )
        .expect_err("unlisted origin must be rejected");
        assert!(err.contains("not in the profile's"), "got: {err}");
    }

    #[test]
    fn rejects_non_https_for_remote_origin() {
        let err = validate_url(
            "http://github.com/oauth",
            &["https://github.com".to_string()],
            false,
        )
        .expect_err("plain http to a remote origin must be rejected");
        assert!(err.contains("Only https"), "got: {err}");
    }

    #[test]
    fn rejects_dangerous_schemes() {
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>",
        ] {
            assert!(
                validate_url(url, &["https://github.com".to_string()], true).is_err(),
                "scheme in {url} must be rejected"
            );
        }
    }

    #[test]
    fn localhost_gated_on_flag() {
        let allowed = &["https://github.com".to_string()];
        assert!(
            validate_url("http://localhost:8080/callback", allowed, false).is_err(),
            "localhost must be denied when allow_localhost is false"
        );
        validate_url("http://localhost:8080/callback", allowed, true)
            .expect("localhost must be allowed when allow_localhost is true");
        validate_url("http://127.0.0.1:53682/", allowed, true)
            .expect("127.0.0.1 must be allowed when allow_localhost is true");
    }

    #[test]
    fn origin_includes_port() {
        // A listed origin without a port must not match a URL with a port.
        let err = validate_url(
            "https://github.com:8443/oauth",
            &["https://github.com".to_string()],
            false,
        )
        .expect_err("differing port is a different origin");
        assert!(err.contains("not in the profile's"), "got: {err}");
    }
}
