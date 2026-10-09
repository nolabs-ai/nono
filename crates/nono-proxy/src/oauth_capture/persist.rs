use super::StoredOAuthToken;
use crate::error::{ProxyError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;
use zeroize::Zeroizing;

/// How long a writer waits for another nono session to release the store lock
/// before failing closed. Holders only keep it for one read-merge-write cycle.
const STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const STORE_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// Identity of one installed version of the store file.
///
/// Every write installs a fresh file via rename, so on Unix the inode alone
/// distinguishes versions; length and mtime cover platforms without inodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StoreFingerprint {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    len: u64,
    modified: Option<SystemTime>,
}

impl StoreFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            #[cfg(unix)]
            dev: metadata.dev(),
            #[cfg(unix)]
            ino: metadata.ino(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}

/// Exclusive advisory lock serializing read-merge-write cycles on the store
/// across concurrent nono sessions. Released when dropped.
pub(super) struct StoreLock {
    file: File,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Current fingerprint of the store file, or `None` if it does not exist.
pub(super) fn store_fingerprint(path: &Path) -> Result<Option<StoreFingerprint>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(StoreFingerprint::from_metadata(&metadata))),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(ProxyError::Config(format!(
            "failed to stat OAuth capture store '{}': {err}",
            path.display()
        ))),
    }
}

/// Take the store's exclusive lock, creating the owner-only store directory
/// if needed. Fails closed if another session holds it past the timeout.
pub(super) fn lock_store(path: &Path) -> Result<StoreLock> {
    ensure_store_dir(path)?;
    let lock_path = lock_path(path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&lock_path).map_err(|err| {
        ProxyError::Config(format!(
            "failed to open OAuth capture store lock '{}': {err}",
            lock_path.display()
        ))
    })?;
    let deadline = Instant::now() + STORE_LOCK_TIMEOUT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(StoreLock { file }),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(STORE_LOCK_RETRY_INTERVAL);
            }
            Err(TryLockError::WouldBlock) => {
                return Err(ProxyError::Config(format!(
                    "timed out waiting for OAuth capture store lock '{}'",
                    lock_path.display()
                )));
            }
            Err(TryLockError::Error(err)) => {
                return Err(ProxyError::Config(format!(
                    "failed to lock OAuth capture store '{}': {err}",
                    lock_path.display()
                )));
            }
        }
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedOAuthStore {
    version: u8,
    #[serde(default)]
    tokens: HashMap<String, PersistedOAuthToken>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedOAuthToken {
    real: String,
    #[serde(default)]
    admitted_consumers: Vec<String>,
    #[serde(default = "now_secs")]
    created_at_secs: u64,
}

/// Load the store file along with the fingerprint of the exact version read.
///
/// The fingerprint comes from the open file handle, not a separate `stat`, so
/// a concurrent rename cannot pair new metadata with old contents.
pub(super) fn load_persisted_tokens(
    path: &Path,
) -> Result<(HashMap<String, StoredOAuthToken>, Option<StoreFingerprint>)> {
    let read_err = |err: std::io::Error| {
        ProxyError::Config(format!(
            "failed to read OAuth capture store '{}': {err}",
            path.display()
        ))
    };
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok((HashMap::new(), None)),
        Err(err) => return Err(read_err(err)),
    };
    let fingerprint = StoreFingerprint::from_metadata(&file.metadata().map_err(read_err)?);
    let mut raw = Zeroizing::new(Vec::new());
    file.read_to_end(&mut raw).map_err(read_err)?;
    if raw.is_empty() {
        return Ok((HashMap::new(), Some(fingerprint)));
    }
    let persisted: PersistedOAuthStore = serde_json::from_slice(&raw).map_err(|err| {
        ProxyError::Config(format!(
            "failed to parse OAuth capture store '{}': {err}",
            path.display()
        ))
    })?;
    let mut tokens = HashMap::new();
    for (phantom, token) in persisted.tokens {
        tokens.insert(
            phantom,
            StoredOAuthToken {
                real: Zeroizing::new(token.real.into_bytes()),
                admitted_consumers: token.admitted_consumers.into_iter().collect(),
                created_at_secs: token.created_at_secs,
            },
        );
    }
    debug!(
        path = %path.display(),
        count = tokens.len(),
        "loaded persisted OAuth phantom mappings"
    );
    Ok((tokens, Some(fingerprint)))
}

/// Atomically replace the store file with `tokens` and return the installed
/// version's fingerprint. Callers must hold the [`StoreLock`].
pub(super) fn persist_tokens(
    _lock: &StoreLock,
    path: &Path,
    tokens: &HashMap<String, StoredOAuthToken>,
) -> Result<Option<StoreFingerprint>> {
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
                real: real.to_string(),
                admitted_consumers: token.admitted_consumers.iter().cloned().collect(),
                created_at_secs: token.created_at_secs,
            },
        );
    }
    let raw = serde_json::to_vec_pretty(&persisted).map_err(|err| {
        ProxyError::Config(format!("failed to encode OAuth capture store: {err}"))
    })?;
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
    store_fingerprint(path)
}

fn ensure_store_dir(path: &Path) -> Result<()> {
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
    set_owner_only_dir(parent)
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
