//! Trust signing key storage backends.
//!
//! Trust commands use the OS keyring by default (`keystore://`). A file-backed
//! backend (`file://`) is available for headless, containerized, and CI
//! environments where the system keystore is unavailable or impractical.
//!
//! Integration tests can also opt into a directory-backed store by setting
//! `NONO_TRUST_TEST_KEYSTORE_DIR`, which avoids interactive keychain prompts.

#[cfg(feature = "test-trust-overrides")]
use std::path::Path;
use std::path::PathBuf;

use nono::{NonoError, Result};
use zeroize::Zeroizing;

/// Test-only override for trust key storage directory.
#[cfg(feature = "test-trust-overrides")]
pub(crate) const TEST_KEYSTORE_DIR_ENV: &str = "NONO_TRUST_TEST_KEYSTORE_DIR";

// TrustKeyRef — user-facing key reference

const KEYSTORE_URI_PREFIX: &str = "keystore://";

/// A parsed reference to a trust signing key.
///
/// Constructed from `--keyref <uri>` or from the legacy `--id <name>` flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrustKeyRef {
    /// System keyring (macOS Keychain / Linux Secret Service).
    /// Parsed from `keystore://<name>` or bare `--id <name>`.
    Keystore(String),
    /// File-backed key at an explicit absolute path.
    /// Parsed from `file:///absolute/path/to/key.pem`.
    File(PathBuf),
}

impl TrustKeyRef {
    /// Parse a `--keyref` value into a [`TrustKeyRef`].
    ///
    /// Accepted forms:
    /// - `keystore://<name>` → [`TrustKeyRef::Keystore`]
    /// - `file:///absolute/path` → [`TrustKeyRef::File`]
    pub(crate) fn parse(uri: &str) -> Result<Self> {
        if let Some(name) = uri.strip_prefix(KEYSTORE_URI_PREFIX) {
            if name.is_empty() {
                return Err(NonoError::ConfigParse(
                    "keystore:// URI has empty key name".to_string(),
                ));
            }
            // Key names must be simple identifiers — no path separators or shell-special chars.
            if let Some(bad) = name
                .chars()
                .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
            {
                return Err(NonoError::ConfigParse(format!(
                    "keystore:// key name contains invalid character {bad:?}: {uri}"
                )));
            }
            Ok(Self::Keystore(name.to_string()))
        } else if nono::is_file_uri(uri) {
            nono::validate_file_uri(uri)?;
            let path_str = uri
                .strip_prefix("file://")
                .ok_or_else(|| NonoError::ConfigParse(format!("invalid file URI: {uri}")))?;
            Ok(Self::File(PathBuf::from(path_str)))
        } else {
            Err(NonoError::ConfigParse(format!(
                "unrecognized key reference scheme: {uri} \
                 (expected keystore://<name> or file:///path)"
            )))
        }
    }

    /// Return the key identifier string embedded in bundles and trust policies.
    ///
    /// For keystore refs this is the key name (e.g. `"default"`).
    /// For file refs this is the full `file:///path` URI, so that the verify
    /// path can dispatch on the URI scheme instead of guessing from path shape.
    ///
    /// Returns an error if a file path is not valid UTF-8.
    pub(crate) fn key_id(&self) -> Result<String> {
        match self {
            Self::Keystore(name) => Ok(name.clone()),
            Self::File(path) => {
                let path_str = path.to_str().ok_or_else(|| {
                    NonoError::ConfigParse(format!(
                        "key path is not valid UTF-8: {}",
                        path.display()
                    ))
                })?;
                Ok(format!("file://{path_str}"))
            }
        }
    }

    /// Build a [`TrustKeyRef`] from a bare `--id` value (legacy compat).
    pub(crate) fn from_id(id: &str) -> Self {
        Self::Keystore(id.to_string())
    }

    /// Resolve from `--keyref` or `--id` (used by keygen, export-key).
    ///
    /// If `keyref` is `Some`, parse it. Otherwise fall back to `id`.
    pub(crate) fn resolve_id(keyref: Option<&str>, id: &str) -> Result<Self> {
        match keyref {
            Some(uri) => Self::parse(uri),
            None => Ok(Self::from_id(id)),
        }
    }

    /// Resolve from `--keyref` or `--key` (used by sign, sign-policy, init).
    ///
    /// If `keyref` is `Some`, parse it. Otherwise fall back to `key`
    /// (defaulting to `"default"` when `key` is `None`).
    pub(crate) fn resolve_key(keyref: Option<&str>, key: Option<&str>) -> Result<Self> {
        match keyref {
            Some(uri) => Self::parse(uri),
            None => Ok(Self::from_id(key.unwrap_or("default"))),
        }
    }
}

impl std::fmt::Display for TrustKeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keystore(name) => write!(f, "keystore://{name}"),
            Self::File(path) => {
                debug_assert!(
                    path.is_absolute(),
                    "TrustKeyRef::File must hold an absolute path"
                );
                write!(f, "file://{}", path.display())
            }
        }
    }
}

// TrustKeyStore — internal backend dispatcher

enum TrustKeyStore {
    /// OS keyring (Keychain / Secret Service).
    System,
    /// File-backed store using a directory with hex-encoded service/account paths.
    /// Used by tests (`NONO_TRUST_TEST_KEYSTORE_DIR`).
    #[cfg(feature = "test-trust-overrides")]
    Directory(PathBuf),
    /// Direct file path — the user specifies the exact file for each key.
    /// Used by `file://` key references.
    DirectFile(PathBuf),
}

impl TrustKeyStore {
    /// Select a backend from a [`TrustKeyRef`].
    ///
    /// The test directory override only applies to `Keystore` refs — `File`
    /// refs always use the direct file path so that integration tests exercise
    /// the `DirectFile` code path.
    fn from_ref(key_ref: &TrustKeyRef) -> Self {
        match key_ref {
            TrustKeyRef::Keystore(_) => {
                #[cfg(feature = "test-trust-overrides")]
                if let Some(dir) = std::env::var_os(TEST_KEYSTORE_DIR_ENV).filter(|d| !d.is_empty())
                {
                    return Self::Directory(PathBuf::from(dir));
                }
                Self::System
            }
            TrustKeyRef::File(path) => Self::DirectFile(path.clone()),
        }
    }

    /// Select the default backend (system keystore, or test override).
    fn selected() -> Self {
        #[cfg(feature = "test-trust-overrides")]
        match std::env::var_os(TEST_KEYSTORE_DIR_ENV) {
            Some(dir) if !dir.is_empty() => return Self::Directory(PathBuf::from(dir)),
            _ => {}
        }

        Self::System
    }

    fn description(&self, service: &str) -> String {
        match self {
            Self::System => format!("system keystore (service: {service})"),
            #[cfg(feature = "test-trust-overrides")]
            Self::Directory(root) => format!("file keystore directory ({})", root.display()),
            Self::DirectFile(path) => format!("file ({})", path.display()),
        }
    }

    fn contains(&self, service: &str, account: &str) -> Result<bool> {
        match self {
            Self::System => {
                #[cfg(not(feature = "system-keyring"))]
                {
                    let _ = (service, account);
                    return Err(NonoError::KeystoreAccess(
                        "system keyring is not available (built without system-keyring feature)"
                            .to_string(),
                    ));
                }
                #[cfg(feature = "system-keyring")]
                {
                    let entry = keyring::Entry::new(service, account).map_err(|e| {
                        NonoError::KeystoreAccess(format!("failed to access keystore: {e}"))
                    })?;
                    match entry.get_password() {
                        Ok(_) => Ok(true),
                        Err(keyring::Error::NoEntry) => Ok(false),
                        Err(other) => Err(NonoError::KeystoreAccess(format!(
                            "failed to access key '{account}': {other}"
                        ))),
                    }
                }
            }
            #[cfg(feature = "test-trust-overrides")]
            Self::Directory(root) => Ok(directory_path(root, service, account).exists()),
            Self::DirectFile(path) => Ok(path.exists()),
        }
    }

    fn load(&self, service: &str, account: &str) -> Result<Zeroizing<String>> {
        match self {
            Self::System => {
                #[cfg(not(feature = "system-keyring"))]
                {
                    let _ = (service, account);
                    return Err(NonoError::KeystoreAccess(
                        "system keyring is not available (built without system-keyring feature)"
                            .to_string(),
                    ));
                }
                #[cfg(feature = "system-keyring")]
                {
                    let entry = keyring::Entry::new(service, account).map_err(|e| {
                        NonoError::KeystoreAccess(format!("failed to access keystore: {e}"))
                    })?;
                    entry
                        .get_password()
                        .map(Zeroizing::new)
                        .map_err(|e| match e {
                            keyring::Error::NoEntry => NonoError::SecretNotFound(format!(
                                "key '{account}' not found in keystore"
                            )),
                            other => NonoError::KeystoreAccess(format!(
                                "failed to load key '{account}': {other}"
                            )),
                        })
                }
            }
            #[cfg(feature = "test-trust-overrides")]
            Self::Directory(root) => {
                let path = directory_path(root, service, account);
                nono::load_secret_file(&path).map_err(|e| match e {
                    NonoError::SecretNotFound(_) => NonoError::SecretNotFound(format!(
                        "key '{account}' not found in file keystore"
                    )),
                    NonoError::KeystoreAccess(_) => NonoError::KeystoreAccess(format!(
                        "failed to load key '{account}' from {}",
                        path.display()
                    )),
                    other => other,
                })
            }
            Self::DirectFile(path) => nono::load_secret_file(path).map_err(|e| match e {
                NonoError::SecretNotFound(_) => {
                    NonoError::SecretNotFound(format!("key not found at {}", path.display()))
                }
                NonoError::KeystoreAccess(_) => {
                    NonoError::KeystoreAccess(format!("failed to load key from {}", path.display()))
                }
                other => other,
            }),
        }
    }

    fn store(&self, service: &str, account: &str, secret: &str) -> Result<()> {
        match self {
            Self::System => {
                #[cfg(not(feature = "system-keyring"))]
                {
                    let _ = (service, account, secret);
                    return Err(NonoError::KeystoreAccess(
                        "system keyring is not available (built without system-keyring feature)"
                            .to_string(),
                    ));
                }
                #[cfg(feature = "system-keyring")]
                {
                    let entry = keyring::Entry::new(service, account).map_err(|e| {
                        NonoError::KeystoreAccess(format!("failed to access keystore: {e}"))
                    })?;
                    entry
                        .set_password(secret)
                        .map_err(|e| NonoError::KeystoreAccess(format!("failed to store key: {e}")))
                }
            }
            #[cfg(feature = "test-trust-overrides")]
            Self::Directory(root) => {
                let path = directory_path(root, service, account);
                nono::store_secret_file(&path, secret).map_err(|e| match e {
                    NonoError::KeystoreAccess(_) => NonoError::KeystoreAccess(format!(
                        "failed to store key '{account}' at {}",
                        path.display()
                    )),
                    other => other,
                })
            }
            Self::DirectFile(path) => nono::store_secret_file(path, secret).map_err(|e| match e {
                NonoError::KeystoreAccess(_) => {
                    NonoError::KeystoreAccess(format!("failed to store key at {}", path.display()))
                }
                other => other,
            }),
        }
    }
}

// Helpers

#[cfg(feature = "test-trust-overrides")]
fn directory_path(root: &Path, service: &str, account: &str) -> PathBuf {
    root.join(hex_component(service))
        .join(hex_component(account))
}

#[cfg(feature = "test-trust-overrides")]
fn hex_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len().saturating_mul(2));
    for byte in value.as_bytes() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

// Public API — used by trust_cmd.rs

/// Human-readable description of the backend for a given key reference.
pub(crate) fn backend_description_for_ref(key_ref: &TrustKeyRef, service: &str) -> String {
    TrustKeyStore::from_ref(key_ref).description(service)
}

/// Check whether a key exists for the given reference.
pub(crate) fn contains_secret_for_ref(
    key_ref: &TrustKeyRef,
    service: &str,
    account: &str,
) -> Result<bool> {
    TrustKeyStore::from_ref(key_ref).contains(service, account)
}

/// Store a secret for the given key reference.
pub(crate) fn store_secret_for_ref(
    key_ref: &TrustKeyRef,
    service: &str,
    account: &str,
    secret: &str,
) -> Result<()> {
    TrustKeyStore::from_ref(key_ref).store(service, account, secret)
}

// Legacy API — used by `load_signing_key` and `load_public_key_bytes` which are
// called from the `Keystore` branch of the `_for_ref` dispatchers in trust_cmd.rs.

pub(crate) fn load_secret(service: &str, account: &str) -> Result<Zeroizing<String>> {
    TrustKeyStore::selected().load(service, account)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // -- TrustKeyRef parsing ------------------------------------------------

    #[test]
    fn parse_keystore_uri() {
        let key_ref = TrustKeyRef::parse("keystore://default").ok();
        assert_eq!(key_ref, Some(TrustKeyRef::Keystore("default".to_string())));
    }

    #[test]
    fn parse_keystore_uri_with_hyphens_and_underscores() {
        let key_ref = TrustKeyRef::parse("keystore://my-key_2").ok();
        assert_eq!(key_ref, Some(TrustKeyRef::Keystore("my-key_2".to_string())));
    }

    #[test]
    fn parse_keystore_uri_empty_name_rejected() {
        assert!(TrustKeyRef::parse("keystore://").is_err());
    }

    #[test]
    fn parse_keystore_uri_bad_chars_rejected() {
        assert!(TrustKeyRef::parse("keystore://foo/bar").is_err());
        assert!(TrustKeyRef::parse("keystore://foo bar").is_err());
        assert!(TrustKeyRef::parse("keystore://foo;bar").is_err());
    }

    #[test]
    fn parse_file_uri() {
        let key_ref = TrustKeyRef::parse("file:///home/user/.config/nono/trust/key.pem").ok();
        assert_eq!(
            key_ref,
            Some(TrustKeyRef::File(PathBuf::from(
                "/home/user/.config/nono/trust/key.pem"
            )))
        );
    }

    #[test]
    fn parse_file_uri_relative_rejected() {
        assert!(TrustKeyRef::parse("file://relative/path").is_err());
    }

    #[test]
    fn parse_file_uri_traversal_rejected() {
        assert!(TrustKeyRef::parse("file:///home/user/../etc/passwd").is_err());
    }

    #[test]
    fn parse_file_uri_empty_path_rejected() {
        assert!(TrustKeyRef::parse("file:///").is_err());
    }

    #[test]
    fn parse_unknown_scheme_rejected() {
        assert!(TrustKeyRef::parse("s3://bucket/key").is_err());
        assert!(TrustKeyRef::parse("just-a-name").is_err());
    }

    #[test]
    fn from_id_produces_keystore_ref() {
        assert_eq!(
            TrustKeyRef::from_id("default"),
            TrustKeyRef::Keystore("default".to_string())
        );
    }

    #[test]
    fn key_id_returns_name_for_keystore() {
        let key_ref = TrustKeyRef::Keystore("default".to_string());
        assert_eq!(key_ref.key_id().ok().as_deref(), Some("default"));
    }

    #[test]
    fn key_id_returns_file_uri_for_file() {
        let key_ref = TrustKeyRef::File(PathBuf::from("/home/user/key.pem"));
        assert_eq!(
            key_ref.key_id().ok().as_deref(),
            Some("file:///home/user/key.pem")
        );
    }

    #[test]
    fn display_roundtrip_keystore() {
        let key_ref = TrustKeyRef::Keystore("default".to_string());
        assert_eq!(key_ref.to_string(), "keystore://default");
    }

    #[test]
    fn display_roundtrip_file() {
        let key_ref = TrustKeyRef::File(PathBuf::from("/tmp/key.pem"));
        assert_eq!(key_ref.to_string(), "file:///tmp/key.pem");
    }

    // -- Directory file backend ---------------------------------------------

    #[test]
    #[cfg(feature = "test-trust-overrides")]
    fn directory_backend_roundtrips_secret() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("failed to create tempdir: {e}"),
        };
        let store = TrustKeyStore::Directory(dir.path().to_path_buf());

        assert!(!store.contains("service", "account").unwrap_or(true));
        assert!(store.store("service", "account", "secret-value").is_ok());
        assert!(store.contains("service", "account").unwrap_or(false));

        let loaded = match store.load("service", "account") {
            Ok(loaded) => loaded,
            Err(e) => panic!("failed to load test secret: {e}"),
        };
        assert_eq!(loaded.as_str(), "secret-value");
    }

    #[test]
    #[cfg(feature = "test-trust-overrides")]
    fn directory_backend_missing_secret_is_not_found() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("failed to create tempdir: {e}"),
        };
        let store = TrustKeyStore::Directory(dir.path().to_path_buf());

        match store.load("service", "missing") {
            Err(NonoError::SecretNotFound(msg)) => {
                assert!(msg.contains("missing"));
            }
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("expected missing secret to fail"),
        }
    }

    #[test]
    #[cfg(feature = "test-trust-overrides")]
    fn directory_backend_separates_service_namespaces() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("failed to create tempdir: {e}"),
        };
        let store = TrustKeyStore::Directory(dir.path().to_path_buf());

        assert!(store.store("service-a", "account", "secret-a").is_ok());
        assert!(store.store("service-b", "account", "secret-b").is_ok());

        let a = match store.load("service-a", "account") {
            Ok(value) => value,
            Err(e) => panic!("failed to load service-a secret: {e}"),
        };
        let b = match store.load("service-b", "account") {
            Ok(value) => value,
            Err(e) => panic!("failed to load service-b secret: {e}"),
        };

        assert_eq!(a.as_str(), "secret-a");
        assert_eq!(b.as_str(), "secret-b");
    }

    // -- Direct file backend ------------------------------------------------

    #[test]
    fn direct_file_backend_roundtrips_secret() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("failed to create tempdir: {e}"),
        };
        let path = dir.path().join("key.pem");
        let store = TrustKeyStore::DirectFile(path.clone());

        assert!(!store.contains("ignored", "ignored").unwrap_or(true));
        assert!(store.store("ignored", "ignored", "my-secret-key").is_ok());
        assert!(store.contains("ignored", "ignored").unwrap_or(false));

        let loaded = match store.load("ignored", "ignored") {
            Ok(loaded) => loaded,
            Err(e) => panic!("failed to load secret: {e}"),
        };
        assert_eq!(loaded.as_str(), "my-secret-key");
    }

    #[test]
    fn direct_file_backend_missing_file_is_not_found() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("failed to create tempdir: {e}"),
        };
        let path = dir.path().join("nonexistent.pem");
        let store = TrustKeyStore::DirectFile(path);

        match store.load("ignored", "ignored") {
            Err(NonoError::SecretNotFound(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("expected missing file to fail"),
        }
    }
}
