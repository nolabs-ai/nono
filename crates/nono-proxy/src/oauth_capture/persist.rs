use super::StoredOAuthToken;
use crate::error::{ProxyError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;
use zeroize::Zeroizing;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct PersistedOAuthStore {
    pub(super) version: u8,
    #[serde(default)]
    pub(super) tokens: HashMap<String, PersistedOAuthToken>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PersistedOAuthToken {
    pub(super) real: Zeroizing<String>,
    #[serde(default)]
    pub(super) admitted_consumers: Vec<String>,
    #[serde(default = "now_secs")]
    pub(super) created_at_secs: u64,
}

/// Decode a `PersistedOAuthStore` JSON payload into the in-memory phantom
/// map. Shared by the file backend (this module) and the macOS Keychain
/// backend (`keychain_persist`), which both persist the same JSON shape.
pub(super) fn decode_tokens(raw: &[u8]) -> Result<HashMap<String, StoredOAuthToken>> {
    if raw.is_empty() {
        return Ok(HashMap::new());
    }
    let persisted: PersistedOAuthStore = serde_json::from_slice(raw)
        .map_err(|err| ProxyError::Config(format!("failed to parse OAuth capture store: {err}")))?;
    let mut tokens = HashMap::new();
    for (phantom, token) in persisted.tokens {
        tokens.insert(
            phantom,
            StoredOAuthToken {
                real: Zeroizing::new(token.real.as_bytes().to_vec()),
                admitted_consumers: token.admitted_consumers.into_iter().collect(),
                created_at_secs: token.created_at_secs,
            },
        );
        // `token.real` (a `Zeroizing<String>`) is dropped here, scrubbing the
        // intermediate copy now that its bytes have been re-wrapped above.
    }
    Ok(tokens)
}

/// Encode the in-memory phantom map into the `PersistedOAuthStore` JSON
/// payload shared by the file and macOS Keychain backends.
///
/// Both the intermediate `PersistedOAuthStore`/`PersistedOAuthToken` and the
/// returned serialized buffer hold real token material, so the buffer is
/// `Zeroizing`-wrapped and `persisted` is dropped (scrubbing its
/// `Zeroizing<String>` fields) before returning.
pub(super) fn encode_tokens(
    tokens: &HashMap<String, StoredOAuthToken>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut persisted = PersistedOAuthStore {
        version: 1,
        tokens: HashMap::new(),
    };
    for (phantom, token) in tokens {
        let real = std::str::from_utf8(&token.real).map_err(|_| {
            ProxyError::Config("OAuth capture token material is not UTF-8".to_string())
        })?;
        persisted.tokens.insert(
            phantom.clone(),
            PersistedOAuthToken {
                real: Zeroizing::new(real.to_string()),
                admitted_consumers: token.admitted_consumers.iter().cloned().collect(),
                created_at_secs: token.created_at_secs,
            },
        );
    }
    let raw = serde_json::to_vec_pretty(&persisted)
        .map_err(|err| ProxyError::Config(format!("failed to encode OAuth capture store: {err}")));
    drop(persisted);
    Ok(Zeroizing::new(raw?))
}

pub(super) fn load_persisted_tokens(path: &Path) -> Result<HashMap<String, StoredOAuthToken>> {
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => {
            return Err(ProxyError::Config(format!(
                "failed to read OAuth capture store '{}': {err}",
                path.display()
            )));
        }
    };
    let tokens = decode_tokens(&raw)
        .map_err(|err| ProxyError::Config(format!("'{}': {err}", path.display())))?;
    debug!(
        path = %path.display(),
        count = tokens.len(),
        "loaded persisted OAuth phantom mappings"
    );
    Ok(tokens)
}

pub(super) fn persist_tokens(
    path: &Path,
    tokens: &HashMap<String, StoredOAuthToken>,
) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(ProxyError::Config(format!(
            "OAuth capture store path '{}' has no parent directory",
            path.display()
        )));
    };
    fs::create_dir_all(parent).map_err(|err| {
        ProxyError::Config(format!(
            "failed to create OAuth capture store directory '{}': {err}",
            parent.display()
        ))
    })?;
    set_owner_only_dir(parent)?;

    let raw = encode_tokens(tokens)?;
    let tmp = path.with_extension("json.tmp");
    write_owner_only_file(&tmp, &raw).map_err(|err| {
        ProxyError::Config(format!(
            "failed to write OAuth capture store '{}': {err}",
            tmp.display()
        ))
    })?;
    fs::rename(&tmp, path).map_err(|err| {
        let _ = fs::remove_file(&tmp);
        ProxyError::Config(format!(
            "failed to install OAuth capture store '{}': {err}",
            path.display()
        ))
    })?;
    set_owner_only_file(path)?;
    Ok(())
}

fn write_owner_only_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let _ = fs::remove_file(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn set_owner_only_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
        ProxyError::Config(format!(
            "failed to set OAuth capture store directory permissions '{}': {err}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_owner_only_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        ProxyError::Config(format!(
            "failed to set OAuth capture store file permissions '{}': {err}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_owner_only_file(_path: &Path) -> Result<()> {
    tracing::warn!("OAuth capture store file permissions are not enforced on this platform");
    Ok(())
}
