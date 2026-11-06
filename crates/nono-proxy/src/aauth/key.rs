//! Loading existing Ed25519 keys without copying them into a second store.

use aauth_core::keys::PrivateKey;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::error::{ProxyError, Result};

const MAX_KEY_BYTES: u64 = 64 * 1024;

/// Resolve a file reference, accepting an absolute path or a file:// URI.
/// Other supported references return None. Relative paths are rejected.
pub fn key_file_path(key_ref: &str) -> Result<Option<PathBuf>> {
    if key_ref.starts_with("env://") || key_ref.starts_with("keyring://") {
        return Ok(None);
    }
    let path = Path::new(key_ref.strip_prefix("file://").unwrap_or(key_ref));
    if !path.is_absolute() {
        return Err(ProxyError::Config(
            "aauth key_ref must be an absolute path, file:///absolute/path, keyring://, or env://"
                .to_string(),
        ));
    }
    Ok(Some(path.to_path_buf()))
}

/// Read a regular, owner-only private-key file without following a final symlink.
fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            ProxyError::Credential(format!("cannot open aauth key '{}': {e}", path.display()))
        })?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ProxyError::Credential(format!(
            "aauth key '{}' must be a regular file owned by the current user with no group/other permissions (use mode 0600)",
            path.display()
        )));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_KEY_BYTES {
        return Err(ProxyError::Credential(
            "aauth key file is too large".to_string(),
        ));
    }
    Ok(bytes)
}

/// Decode an unencrypted PKCS#8 Ed25519 PEM, DER, or legacy base64 DER key.
fn decode_private_key(bytes: &[u8]) -> Result<PrivateKey> {
    let invalid = || {
        ProxyError::Credential(
            "aauth key must be an unencrypted PKCS#8 Ed25519 key (PEM, DER, or base64 DER)"
                .to_string(),
        )
    };
    if bytes.first() == Some(&0x30) {
        return PrivateKey::from_pkcs8_der(bytes).map_err(|_| invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?.trim();
    if text.starts_with("-----BEGIN") {
        PrivateKey::from_pkcs8_pem(text).map_err(|_| invalid())
    } else {
        let der = Zeroizing::new(BASE64.decode(text).map_err(|_| invalid())?);
        PrivateKey::from_pkcs8_der(&der).map_err(|_| invalid())
    }
}

/// Load a signing key. File references read the existing file in place.
pub fn load_private_key(key_ref: &str) -> Result<PrivateKey> {
    if let Some(path) = key_file_path(key_ref)? {
        return decode_private_key(&read_key_file(&path)?);
    }
    let secret = nono::keystore::load_secret_by_ref(nono::keystore::DEFAULT_SERVICE, key_ref, None)
        .map_err(|e| {
            ProxyError::Credential(format!("aauth key reference could not be loaded: {e}"))
        })?;
    decode_private_key(secret.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn loads_existing_pem_der_and_legacy_base64_without_changing_source() {
        let (private, _) = aauth_core::keys::generate_ed25519_keypair();
        let der = private.to_pkcs8_der().expect("DER");
        let b64 = BASE64.encode(&*der);
        let lines = b64
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).expect("base64"))
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{lines}\n-----END PRIVATE KEY-----\n");
        let root = tempfile::tempdir().expect("tempdir");
        for (name, bytes) in [
            ("key.der", der.as_slice()),
            ("key.b64", b64.as_bytes()),
            ("key.pem", pem.as_bytes()),
        ] {
            let path = root.path().join(name);
            std::fs::write(&path, bytes).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            for reference in [
                path.to_string_lossy().into_owned(),
                format!("file://{}", path.display()),
            ] {
                let loaded = load_private_key(&reference).expect("load in place");
                assert_eq!(
                    super::super::jwk_thumbprint(&loaded).expect("thumbprint"),
                    super::super::jwk_thumbprint(&private).expect("thumbprint")
                );
            }
            assert_eq!(std::fs::read(&path).expect("read"), bytes);
        }
    }

    #[test]
    fn rejects_public_permissions_symlinks_directories_and_oversized_files() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("key");
        std::fs::write(&path, b"invalid private key should never appear in errors").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(read_key_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = root.path().join("link");
        symlink(&path, &link).expect("symlink");
        assert!(read_key_file(&link).is_err());
        assert!(read_key_file(root.path()).is_err());
        std::fs::write(&path, vec![b'a'; MAX_KEY_BYTES as usize + 1]).expect("write oversized");
        assert!(read_key_file(&path).is_err());
        let error = match decode_private_key(b"private material not to echo") {
            Err(error) => error.to_string(),
            Ok(_) => panic!("invalid material must fail"),
        };
        assert!(!error.contains("private material not to echo"));
        assert!(key_file_path("relative/key.pem").is_err());
        assert!(key_file_path("file://relative/key.pem").is_err());
    }
}
