//! Local storage for a `nono login` session.
//!
//! Three owner-only files in nono's state directory (`$XDG_STATE_HOME/nono`):
//!
//! - `platform-login-key`: the session's P-256 private key (PKCS#8, base64);
//! - `platform-login-refresh-token`: the current refresh token;
//! - `platform-login.json`: the non-secret record (platform, person, active
//!   organization, organization list, console URL, key thumbprint).
//!
//! The state directory is a protected root that no sandbox capability can
//! grant, so an agent running under nono cannot read the session. No OS
//! keyring is involved, so sign-in works over SSH and in containers.

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nix::fcntl::{Flock, FlockArg};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::client::Organization;
use super::dpop::DpopKey;

const SESSION_PROTOCOL_V1: &str = "1";
const RECORD_FILENAME: &str = "platform-login.json";
const KEY_FILENAME: &str = "platform-login-key";
const REFRESH_TOKEN_FILENAME: &str = "platform-login-refresh-token";
const LOCK_FILENAME: &str = "platform-login.lock";
const MAX_SECRET_BYTES: u64 = 64 * 1024;

/// The non-secret description of the signed-in session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SessionRecord {
    pub(crate) protocol_version: String,
    pub(crate) platform_url: String,
    pub(crate) issuer: String,
    pub(crate) key_thumbprint: String,
    pub(crate) user_subject: String,
    pub(crate) user_display: String,
    /// The organization remote commands use unless `NONO_ORG` says otherwise.
    pub(crate) tenant_id: String,
    pub(crate) organizations: Vec<Organization>,
    pub(crate) console_url: Option<String>,
    pub(crate) signed_in_at: String,
}

impl SessionRecord {
    pub(crate) fn active_organization(&self) -> Option<&Organization> {
        self.organizations
            .iter()
            .find(|org| org.tenant_id == self.tenant_id)
    }

    /// Resolve an organization by ID, slug, or (unambiguous, case-insensitive)
    /// display name.
    pub(crate) fn find_organization(&self, name: &str) -> Result<&Organization> {
        if let Some(org) = self
            .organizations
            .iter()
            .find(|org| org.tenant_id == name || org.slug == name)
        {
            return Ok(org);
        }
        let mut matches = self
            .organizations
            .iter()
            .filter(|org| org.display_name.eq_ignore_ascii_case(name));
        match (matches.next(), matches.next()) {
            (Some(org), None) => Ok(org),
            (Some(_), Some(_)) => Err(NonoError::ActionRequired(format!(
                "more than one organization is named '{name}'; use its slug: {}",
                self.organization_slugs()
            ))),
            _ => Err(NonoError::ActionRequired(format!(
                "you are not a member of an organization called '{name}'; your organizations: {}",
                self.organization_slugs()
            ))),
        }
    }

    fn organization_slugs(&self) -> String {
        self.organizations
            .iter()
            .map(|org| org.slug.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn state_dir() -> Result<PathBuf> {
    crate::state_paths::user_state_dir()
}

/// An exclusive, interprocess lock on the local session.
///
/// Refresh tokens rotate on every use and reuse of a rotated token revokes the
/// whole session, so two nono processes must never refresh concurrently. Every
/// function that changes the session takes this lock as proof it is held; it
/// is released when dropped (or when the process exits).
pub(crate) struct SessionLock {
    _file: Flock<fs::File>,
}

/// Block until this process holds the session lock.
pub(crate) fn lock() -> Result<SessionLock> {
    let dir = state_dir()?;
    ensure_private_dir(&dir)?;
    let path = dir.join(LOCK_FILENAME);
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    let file = options
        .open(&path)
        .map_err(|source| NonoError::ConfigWrite {
            path: path.clone(),
            source,
        })?;
    let file = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, errno)| {
        NonoError::ConfigWrite {
            path,
            source: std::io::Error::from(errno),
        }
    })?;
    Ok(SessionLock { _file: file })
}

pub(crate) fn load_record() -> Result<Option<SessionRecord>> {
    let path = state_dir()?.join(RECORD_FILENAME);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(NonoError::ConfigRead { path, source }),
    };
    let record: SessionRecord = serde_json::from_str(&contents)
        .map_err(|error| NonoError::ConfigParse(format!("invalid {}: {error}", path.display())))?;
    if record.protocol_version != SESSION_PROTOCOL_V1 {
        return Err(NonoError::ConfigParse(
            "unsupported local sign-in record; run `nono logout` and sign in again".to_string(),
        ));
    }
    Ok(Some(record))
}

pub(crate) fn save_record(_lock: &SessionLock, record: &SessionRecord) -> Result<()> {
    crate::platform_client::write_json_secure(&state_dir()?.join(RECORD_FILENAME), record)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn new_record(
    platform_url: &str,
    issuer: &str,
    key: &DpopKey,
    identity: &super::client::Identity,
    session: &super::client::SessionInfo,
) -> SessionRecord {
    SessionRecord {
        protocol_version: SESSION_PROTOCOL_V1.to_string(),
        platform_url: platform_url.to_string(),
        issuer: issuer.to_string(),
        key_thumbprint: key.thumbprint().to_string(),
        user_subject: identity.subject.clone(),
        user_display: identity.display.clone(),
        tenant_id: session.tenant_id.clone(),
        organizations: session.organizations.clone(),
        console_url: session.console_url.as_ref().map(|url| url.to_string()),
        signed_in_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

/// A freshly generated session key, held in memory until sign-in succeeds.
pub(crate) struct NewKey {
    pub(crate) key: DpopKey,
    encoded: Zeroizing<String>,
}

/// Generate a fresh session key. Nothing is written until [`store_session`],
/// so an abandoned sign-in never disturbs an existing session.
pub(crate) fn create_key() -> Result<NewKey> {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map_err(|_| {
                NonoError::KeystoreAccess("failed to generate a session key".to_string())
            })?;
    let encoded = Zeroizing::new(STANDARD.encode(pkcs8.as_ref()));
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .map_err(|_| NonoError::KeystoreAccess("failed to load the session key".to_string()))?;
    Ok(NewKey {
        key: DpopKey::new(key_pair)?,
        encoded,
    })
}

/// Replace the local session with a new one: key and refresh token first,
/// then the record that says a session exists.
pub(crate) fn store_session(
    lock: &SessionLock,
    key: &NewKey,
    refresh_token: &str,
    record: &SessionRecord,
) -> Result<()> {
    let dir = state_dir()?;
    // A record left from an earlier session must not pair with the new key.
    remove_if_present(&dir.join(RECORD_FILENAME))?;
    write_secret(&dir.join(KEY_FILENAME), &key.encoded)?;
    store_refresh_token(lock, refresh_token)?;
    save_record(lock, record)
}

pub(crate) fn load_key() -> Result<Option<DpopKey>> {
    let Some(encoded) = read_secret(&state_dir()?.join(KEY_FILENAME))? else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| NonoError::KeystoreAccess("the session key is corrupt".to_string()))?,
    );
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes)
        .map_err(|_| NonoError::KeystoreAccess("the session key is corrupt".to_string()))?;
    DpopKey::new(key_pair).map(Some)
}

pub(crate) fn store_refresh_token(_lock: &SessionLock, token: &str) -> Result<()> {
    write_secret(&state_dir()?.join(REFRESH_TOKEN_FILENAME), token)
}

pub(crate) fn load_refresh_token() -> Result<Option<Zeroizing<String>>> {
    read_secret(&state_dir()?.join(REFRESH_TOKEN_FILENAME))
}

/// Remove the whole local session. Each removal is idempotent; the record
/// goes first so a partial failure never leaves a record without secrets.
pub(crate) fn clear(_lock: &SessionLock) -> Result<()> {
    let dir = state_dir()?;
    for name in [RECORD_FILENAME, REFRESH_TOKEN_FILENAME, KEY_FILENAME] {
        remove_if_present(&dir.join(name))?;
    }
    Ok(())
}

/// Whether any session secret is on disk, readable or not.
pub(crate) fn secrets_present() -> Result<bool> {
    let dir = state_dir()?;
    for name in [REFRESH_TOKEN_FILENAME, KEY_FILENAME] {
        let path = dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(NonoError::ConfigRead { path, source }),
        }
    }
    Ok(false)
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Create `dir` if needed and make it owner-only.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(|source| NonoError::ConfigWrite {
        path: dir.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
        NonoError::ConfigWrite {
            path: dir.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

/// Atomically write an owner-only secret file in an owner-only directory.
fn write_secret(path: &Path, secret: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| NonoError::ConfigParse(format!("path has no parent: {}", path.display())))?;
    ensure_private_dir(parent)?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&tmp)
        .map_err(|source| NonoError::ConfigWrite {
            path: tmp.clone(),
            source,
        })?;
    let written = file
        .write_all(secret.as_bytes())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(source) = written.and_then(|_| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Read an owner-only secret file. A file another user could read is refused
/// rather than trusted: its contents may already be compromised.
fn read_secret(path: &Path) -> Result<Option<Zeroizing<String>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(NonoError::ConfigRead {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_SECRET_BYTES {
        return Err(NonoError::KeystoreAccess(format!(
            "{} is not a regular file of the expected size",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(NonoError::ActionRequired(format!(
            "{} is accessible to other users; run `nono logout` and sign in again",
            path.display()
        )));
    }
    let contents =
        Zeroizing::new(
            fs::read_to_string(path).map_err(|source| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source,
            })?,
        );
    let trimmed = Zeroizing::new(contents.trim().to_string());
    Ok((!trimmed.is_empty()).then_some(trimmed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    fn org(tenant_id: &str, slug: &str, name: &str) -> Organization {
        Organization {
            tenant_id: tenant_id.to_string(),
            slug: slug.to_string(),
            display_name: name.to_string(),
            kind: "organization".to_string(),
        }
    }

    pub(crate) fn record() -> SessionRecord {
        SessionRecord {
            protocol_version: SESSION_PROTOCOL_V1.to_string(),
            platform_url: "https://nono.example.com".to_string(),
            issuer: "https://nono.example.com".to_string(),
            key_thumbprint: "k".to_string(),
            user_subject: "u".to_string(),
            user_display: "Alice".to_string(),
            tenant_id: "t-1".to_string(),
            organizations: vec![
                org("t-1", "alice", "Alice"),
                org("t-2", "acme", "Acme"),
                org("t-3", "acme-eu", "ACME"),
            ],
            console_url: None,
            signed_in_at: "2026-11-02T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn organizations_resolve_by_id_slug_or_unambiguous_name() {
        let record = record();
        assert_eq!(record.active_organization().unwrap().slug, "alice");
        assert_eq!(record.find_organization("t-2").unwrap().slug, "acme");
        assert_eq!(
            record.find_organization("acme-eu").unwrap().tenant_id,
            "t-3"
        );
        assert_eq!(record.find_organization("alice").unwrap().tenant_id, "t-1");
        assert_eq!(record.find_organization("acme").unwrap().tenant_id, "t-2");
        // "Acme" and "ACME" collide case-insensitively, so the name is refused.
        assert!(
            record.find_organization("Acme").is_err(),
            "ambiguous display name"
        );
        // A miss names the organizations the person can use.
        let error = record.find_organization("other").unwrap_err().to_string();
        assert!(error.contains("alice, acme, acme-eu"), "{error}");
    }

    #[test]
    fn the_session_lock_excludes_other_holders_until_dropped() {
        let _env = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = tempfile::tempdir().unwrap();
        let _guard = crate::test_env::EnvVarGuard::set_all(&[(
            "XDG_STATE_HOME",
            state.path().to_str().unwrap(),
        )]);
        let held = lock().unwrap();
        let acquired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&acquired);
        // flock locks belong to the open file, so a second open in this
        // process contends exactly like another nono process would.
        let waiter = std::thread::spawn(move || {
            let _second = lock().unwrap();
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!acquired.load(std::sync::atomic::Ordering::SeqCst));
        drop(held);
        waiter.join().unwrap();
        assert!(acquired.load(std::sync::atomic::Ordering::SeqCst));
        #[cfg(unix)]
        {
            let mode = fs::metadata(state.path().join("nono").join(LOCK_FILENAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn secrets_are_owner_only_and_loose_permissions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("secret");
        write_secret(&path, "s3cret").unwrap();
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert_eq!(read_secret(&path).unwrap().unwrap().as_str(), "s3cret");
        write_secret(&path, "rotated").unwrap();
        assert_eq!(read_secret(&path).unwrap().unwrap().as_str(), "rotated");
        #[cfg(unix)]
        {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_secret(&path).is_err());
        }
        assert!(read_secret(&dir.path().join("missing")).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_secret_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        write_secret(&target, "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_secret(&link).is_err());
    }
}
