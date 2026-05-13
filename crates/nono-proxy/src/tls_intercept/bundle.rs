//! Trust bundle composition for the sandboxed child.
//!
//! When TLS interception is active the proxy writes a PEM file containing:
//!
//! 1. The contents of the parent process's `SSL_CERT_FILE` (if set), so that
//!    a corporate / private CA configured on the host continues to be
//!    trusted by the agent.
//! 2. The host's system trust store (via `rustls-native-certs`), so that
//!    the agent retains trust for normal public CAs after we override
//!    `SSL_CERT_FILE` to point at this bundle.
//! 3. The proxy's ephemeral session CA, so the minted leaf certificates
//!    served by the intercept acceptor are accepted by the agent.
//!
//! ## Why all three layers
//!
//! `SSL_CERT_FILE` (and friends) **replaces** the default trust store for
//! most runtimes (Python `requests`, OpenSSL, curl). If we wrote only the
//! ephemeral CA, the agent would lose trust for every other host. If we
//! wrote only system roots + ephemeral CA, we would silently strip any
//! corporate CA the host had configured. Layering all three preserves the
//! host's existing trust posture and additively adds nono's intercept CA.
//!
//! ## File permissions
//!
//! The bundle is written with mode `0o400` (owner read-only). The CA private
//! key is **never** written to disk — it lives only in memory inside
//! [`super::ca::EphemeralCa`].

use crate::error::{ProxyError, Result};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Inputs to [`write_bundle`].
pub struct BundleInputs<'a> {
    /// Directory the bundle will be written into. Caller is responsible for
    /// ensuring the directory exists with appropriate permissions
    /// (e.g. `~/.nono/sessions/<session_id>/` at `0o700`).
    pub dir: &'a Path,
    /// Filename inside `dir`. Conventionally `intercept-ca.pem`.
    pub filename: &'a str,
    /// Optional contents of the parent process's `SSL_CERT_FILE`. When
    /// `Some`, prepended verbatim to the bundle so that any corporate CA
    /// trust the host had configured is preserved.
    pub parent_ssl_cert_file: Option<&'a [u8]>,
    /// PEM-encoded ephemeral session CA cert (from
    /// [`super::ca::EphemeralCa::cert_pem`]).
    pub ephemeral_ca_pem: &'a str,
}

/// Compose the trust bundle and write it to disk.
///
/// Returns the absolute path to the written file. Errors include:
/// * unable to read the system trust store
/// * unable to create the file with restrictive permissions
/// * unable to write
pub fn write_bundle(inputs: BundleInputs<'_>) -> Result<PathBuf> {
    let mut pem = String::new();

    if let Some(parent_pem) = inputs.parent_ssl_cert_file {
        // Pass through verbatim; we don't try to parse and re-emit because
        // any non-cert lines (comments, etc.) would be lost on re-emission.
        match std::str::from_utf8(parent_pem) {
            Ok(s) => {
                debug!(
                    "tls_intercept: merging parent SSL_CERT_FILE contents \
                     ({} bytes) into trust bundle",
                    s.len()
                );
                pem.push_str(s);
                if !pem.ends_with('\n') {
                    pem.push('\n');
                }
            }
            Err(_) => {
                warn!(
                    "tls_intercept: parent SSL_CERT_FILE contents are not valid UTF-8; \
                     skipping merge — corporate CAs configured on the host may not be \
                     trusted by the sandboxed child"
                );
            }
        }
    }

    // System trust store. We read full DER certs (rustls-native-certs returns
    // CertificateDer<'static>) and PEM-encode each one ourselves rather than
    // depending on a base64 helper crate.
    let system_certs = rustls_native_certs::load_native_certs();
    if !system_certs.errors.is_empty() {
        // Non-fatal: some certs may have failed to parse, but we keep the
        // ones that did. Log so an operator can see the count if it ever
        // matters.
        debug!(
            "tls_intercept: rustls-native-certs reported {} non-fatal errors while \
             loading system trust store",
            system_certs.errors.len()
        );
    }
    if system_certs.certs.is_empty() && inputs.parent_ssl_cert_file.is_none() {
        // No system roots and no parent file — the agent would lose trust
        // for every public CA. Refuse rather than ship a broken bundle.
        return Err(ProxyError::Config(
            "tls_intercept: failed to load any system trust roots; \
             refusing to write a bundle that would strip the agent's TLS trust"
                .to_string(),
        ));
    }
    debug!(
        "tls_intercept: appending {} certs from the system trust store to bundle",
        system_certs.certs.len()
    );
    for cert in system_certs.certs {
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        pem.push_str(&base64_chunked(cert.as_ref()));
        pem.push_str("-----END CERTIFICATE-----\n");
    }

    // Ephemeral CA cert.
    if !inputs.ephemeral_ca_pem.contains("BEGIN CERTIFICATE") {
        return Err(ProxyError::Config(
            "tls_intercept: ephemeral CA PEM is not in the expected format".to_string(),
        ));
    }
    pem.push_str(inputs.ephemeral_ca_pem);
    if !pem.ends_with('\n') {
        pem.push('\n');
    }

    // Write atomically with restrictive permissions.
    let path = inputs.dir.join(inputs.filename);
    write_with_restrictive_perms(&path, pem.as_bytes())?;
    debug!(
        "tls_intercept: wrote trust bundle ({} bytes) to {}",
        pem.len(),
        path.display()
    );
    Ok(path)
}

/// Write bytes to `path` with mode `0o400` on Unix. On Windows this falls
/// back to a plain write; nono is currently Unix-only but the FFI bindings
/// don't enforce that at the proxy crate boundary, so we keep the cfg
/// fence narrow.
fn write_with_restrictive_perms(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    // Remove any pre-existing file so we don't inherit permissions from a
    // previous session (defence in depth — the parent dir should be 0o700
    // anyway).
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| {
            ProxyError::Config(format!(
                "tls_intercept: cannot remove stale bundle '{}': {}",
                path.display(),
                e
            ))
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(path)
            .map_err(|e| {
                ProxyError::Config(format!(
                    "tls_intercept: cannot create bundle '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        file.write_all(contents).map_err(|e| {
            ProxyError::Config(format!(
                "tls_intercept: cannot write bundle '{}': {}",
                path.display(),
                e
            ))
        })?;
        file.flush().ok();
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents).map_err(|e| {
            ProxyError::Config(format!(
                "tls_intercept: cannot write bundle '{}': {}",
                path.display(),
                e
            ))
        })?;
    }
    Ok(())
}

/// Encode `bytes` as base64 with 64-character lines, matching the convention
/// used by OpenSSL and most CA bundles. Implemented inline to avoid pulling
/// in a base64 helper just for cert emission (the `base64` crate is already
/// a dep but its config API has churned across versions; doing it ourselves
/// keeps this stable).
fn base64_chunked(bytes: &[u8]) -> String {
    use base64::engine::{Engine, general_purpose::STANDARD};
    let encoded = STANDARD.encode(bytes);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 64 + 1);
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tls_intercept::ca::EphemeralCa;

    #[test]
    fn bundle_contains_ephemeral_and_system_roots() {
        let dir = tempfile::tempdir().unwrap();
        let ca = EphemeralCa::generate().unwrap();
        let path = write_bundle(BundleInputs {
            dir: dir.path(),
            filename: "intercept-ca.pem",
            parent_ssl_cert_file: None,
            ephemeral_ca_pem: ca.cert_pem(),
        })
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let cert_count = contents.matches("BEGIN CERTIFICATE").count();
        assert!(
            cert_count >= 2,
            "bundle should contain at least one system root + the ephemeral CA, got {}",
            cert_count
        );
        assert!(
            contents.contains(ca.cert_pem().trim()),
            "ephemeral CA PEM must appear verbatim in bundle"
        );
    }

    #[test]
    fn bundle_merges_parent_file() {
        let dir = tempfile::tempdir().unwrap();
        let ca = EphemeralCa::generate().unwrap();
        let parent = b"# corporate roots\n-----BEGIN CERTIFICATE-----\nMIIBcorpfake\n-----END CERTIFICATE-----\n";
        let path = write_bundle(BundleInputs {
            dir: dir.path(),
            filename: "intercept-ca.pem",
            parent_ssl_cert_file: Some(parent),
            ephemeral_ca_pem: ca.cert_pem(),
        })
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("MIIBcorpfake"));
    }

    #[test]
    fn bundle_rejects_malformed_ephemeral_pem() {
        let dir = tempfile::tempdir().unwrap();
        let result = write_bundle(BundleInputs {
            dir: dir.path(),
            filename: "intercept-ca.pem",
            parent_ssl_cert_file: None,
            ephemeral_ca_pem: "not a certificate",
        });
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn bundle_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ca = EphemeralCa::generate().unwrap();
        let path = write_bundle(BundleInputs {
            dir: dir.path(),
            filename: "intercept-ca.pem",
            parent_ssl_cert_file: None,
            ephemeral_ca_pem: ca.cert_pem(),
        })
        .unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "bundle must be owner-read-only");
    }
}
