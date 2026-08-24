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

    /// Live manual/regression test: plant a trojan `open`/`xdg-open` in a
    /// directory the sandbox has write access to, and confirm
    /// `open_url_in_browser` doesn't execute it. A real fallback binary
    /// sits in a separate, non-granted directory so the sanitized PATH still
    /// resolves to something real.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn open_url_in_browser_skips_trojan_in_writable_path_dir() {
        use nono::{AccessMode, CapabilitySource, FsCapability};
        use std::os::unix::fs::PermissionsExt;

        #[cfg(target_os = "macos")]
        const OPENER: &str = "open";
        #[cfg(target_os = "linux")]
        const OPENER: &str = "xdg-open";

        let root = tempfile::tempdir().expect("tempdir");

        let writable_dir = root.path().join("writable_path_dir");
        std::fs::create_dir_all(&writable_dir).expect("mkdir writable");
        let marker = root.path().join("marker");
        let trojan = writable_dir.join(OPENER);
        std::fs::write(
            &trojan,
            format!("#!/bin/sh\n/usr/bin/touch {}\nexit 0\n", marker.display()),
        )
        .expect("write trojan");
        let mut perms = std::fs::metadata(&trojan).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&trojan, perms).expect("chmod trojan");

        // A real fallback binary in a directory the sandbox has no grant on
        // at all, standing in for the real `open`/`xdg-open` so we don't
        // launch an actual browser during the test.
        let real_dir = root.path().join("real_bin_dir");
        std::fs::create_dir_all(&real_dir).expect("mkdir real");
        let real_marker = root.path().join("real_marker");
        let real_bin = real_dir.join(OPENER);
        std::fs::write(
            &real_bin,
            format!(
                "#!/bin/sh\n/usr/bin/touch {}\nexit 0\n",
                real_marker.display()
            ),
        )
        .expect("write real bin");
        let mut perms = std::fs::metadata(&real_bin).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&real_bin, perms).expect("chmod real");

        let mut caps = nono::CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: writable_dir.clone(),
            resolved: nono::try_canonicalize(&writable_dir),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::User,
        });

        let poisoned_path = format!("{}:{}", writable_dir.display(), real_dir.display());
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[("PATH", &poisoned_path)]);

        open_url_in_browser("https://example.com/callback", &caps)
            .expect("real fallback binary should run and succeed");

        assert!(
            !marker.exists(),
            "trojan {OPENER} in a sandbox-writable PATH dir must not run"
        );
        assert!(
            real_marker.exists(),
            "the real (fallback) {OPENER} binary should have run instead"
        );
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
