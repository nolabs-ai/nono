//! Persistent storage for the OAuth token broker (macOS only).
//!
//! OAuth capture mints `nono_<hex>` nonces and substitutes them for real
//! `(access_token, refresh_token)` pairs in the response body claude
//! receives. Without persistence the mapping is destroyed when nono exits,
//! so the nonces written to `Claude Code-credentials` by the rewritten
//! OAuth response have nothing to resolve to in the next nono session —
//! the user would have to `/login` again every time.
//!
//! This module persists captured pairs to the macOS Keychain under service
//! [`SERVICE_NAME`] (shared with nono's credential-injection feature),
//! account [`CLAUDE_OAUTH_ACCOUNT`]. On startup the broker hydrates from
//! the persisted record and re-registers the same nonces it issued in the
//! previous session (see [`super::token_broker::TokenBroker::with_store`]),
//! so the keychain entry the sandboxed claude reads continues to resolve.
//!
//! ## Protection model: two layers, neither alone sufficient
//!
//! The broker entry persists real OAuth tokens. Two mechanisms keep them
//! unreachable from a prompt-injected agent:
//!
//! ### Primary: subprocess mediation refusal
//!
//! A profile that enables OAuth capture also refuses subprocess
//! `security find-generic-password` reads of this entry. The shim returns
//! `errSecItemNotFound` in the unsandboxed parent process before any call
//! reaches macOS securityd. No dialog. No Allow button. No social-engineering
//! surface. This is the protection the realistic threat model relies on.
//!
//! ### Defense-in-depth: legacy ACL on the keychain entry
//!
//! The entry is also created with a `SecAccess` ACL listing only the nono
//! binary in the trusted-apps list. This catches attempts that bypass the
//! mediation shim — most notably a binary linked against Security framework
//! that calls `SecItemCopyMatching` via Mach IPC directly. But the legacy
//! ACL does NOT silently deny non-trusted callers: it triggers a system
//! dialog ("X wants to access key 'nono' in your keychain") the user can
//! click Allow on. So this layer is visible alerting against the Mach-IPC
//! bypass, not silent denial.
//!
//! ### Invariant
//!
//! Every save path through this module MUST go through
//! [`save_with_nono_acl`], which:
//! 1. Calls [`create_nono_access`] with `current_exe()` to build a
//!    `SecAccessRef` listing only nono's binary.
//! 2. Sets the resulting access on the new entry via
//!    `kSecAttrAccess` before calling `SecItemAdd`.
//!
//! Future maintainers: do not introduce a new save path that bypasses
//! [`save_with_nono_acl`]. In particular, do not use
//! `keyring::set_password` for the broker entry on macOS — the keyring
//! crate's apple-native backend creates entries with the default ACL.
//! `keyring` is intentionally not imported by this module's macOS code.
//! Dropping the ACL would not break the primary mediation protection but
//! would lose the defense-in-depth layer against Mach IPC.
//!
//! All Security framework operations run in-process (the nono binary,
//! which is in the ACL). No `security` CLI subprocess is used, removing
//! both the argv-leak risk and the 128-byte `readpassphrase(3)` cap.
//!
//! ## Binary-path staleness
//!
//! The stored `nono_path` field in the JSON record records the absolute
//! path of the nono binary at save time. On load it is compared against
//! `current_exe()`. A mismatch (upgrade, reinstall to a different
//! prefix, `cargo install` rebuild) means the existing entry's ACL
//! is keyed to a binary that no longer matches the running nono, so
//! subsequent reads would prompt. The broker treats this as a stale
//! entry: it deletes the old record and returns `None`, which leaves
//! the broker empty until the next `claude /login` triggers a fresh
//! capture with the correct ACL.
//!
//! ## Linux
//!
//! Not supported. Linux's keyring backends (secret-service,
//! gnome-keyring via the `keyring` crate) have no per-entry ACL —
//! entries are readable by any process running as the same user,
//! defeating the protection model that motivates persistence in the
//! first place. Linux callers always get an in-memory-only broker.

#![cfg(target_os = "macos")]

use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Keychain service name shared with nono's credential-injection feature.
/// New account names introduced here must not collide with documented
/// account names from that feature (e.g. `openai_api_key`,
/// `anthropic_api_key`, `github_token`).
pub(crate) const SERVICE_NAME: &str = nono::keystore::DEFAULT_SERVICE;

/// Account name for the OAuth-capture broker's persisted record.
///
/// Holds a JSON object with both broker-issued nonces and the real
/// upstream tokens. Distinct from any user-managed account names so
/// `security add-generic-password` for unrelated services never
/// overwrites it and vice versa.
pub(crate) const CLAUDE_OAUTH_ACCOUNT: &str = "claude_oauth_broker";

/// One captured OAuth credential pair.
///
/// `access_nonce` and `refresh_nonce` are the broker-issued
/// `nono_<hex>` strings that the sandboxed client reads from its
/// own credential file (macOS keychain `Claude Code-credentials`).
/// `access_token` and `refresh_token` are the real upstream secrets
/// the broker forwards to Anthropic on behalf of the client.
#[derive(Debug, Clone)]
pub(crate) struct PersistedRecord {
    pub access_nonce: String,
    pub refresh_nonce: String,
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
}

/// Persistence backend for the broker.
///
/// Implementations are responsible for storing exactly one record per
/// service+account pair. `save` overwrites any existing record; `clear`
/// removes it. `load` returns `None` if no record is stored.
pub(crate) trait BrokerStore: Send + Sync {
    fn load(&self) -> Result<Option<PersistedRecord>>;
    fn save(&self, record: &PersistedRecord) -> Result<()>;
    fn clear(&self) -> Result<()>;
}

/// On-disk JSON shape. Kept private so callers go through `BrokerStore`
/// and hold the secret as `Zeroizing<String>` once decoded.
///
/// `nono_path` records the absolute path of the nono binary at save
/// time. On load it is compared against `current_exe()` to detect
/// binary-path changes. A mismatch triggers deletion of the stale
/// record so a fresh capture can rebuild the ACL for the new path.
/// Entries written by older nono versions lack this field; they are
/// also treated as stale and deleted on first load.
#[derive(Serialize, Deserialize)]
struct PersistedJson {
    access_nonce: String,
    refresh_nonce: String,
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    nono_path: Option<String>,
}

impl PersistedJson {
    fn from_record(record: &PersistedRecord, nono_exe: &std::path::Path) -> Self {
        Self {
            access_nonce: record.access_nonce.clone(),
            refresh_nonce: record.refresh_nonce.clone(),
            access_token: record.access_token.as_str().to_string(),
            refresh_token: record.refresh_token.as_str().to_string(),
            nono_path: Some(nono_exe.to_string_lossy().into_owned()),
        }
    }

    fn into_record(self) -> PersistedRecord {
        PersistedRecord {
            access_nonce: self.access_nonce,
            refresh_nonce: self.refresh_nonce,
            access_token: Zeroizing::new(self.access_token),
            refresh_token: Zeroizing::new(self.refresh_token),
        }
    }
}

// ── macOS: in-process Security framework helpers ─────────────────────────────

/// FFI bindings for legacy Keychain Services ACL APIs not exposed by
/// `security-framework-sys`. Security.framework is already linked by that
/// crate's `lib.rs` `#[link]` attribute, so no additional link attribute
/// is needed here.
#[cfg(target_os = "macos")]
mod macos_ffi {
    use core_foundation_sys::array::CFArrayRef;
    use core_foundation_sys::base::OSStatus;
    use core_foundation_sys::string::CFStringRef;
    use security_framework_sys::base::SecAccessRef;

    /// Opaque CF type for a trusted-application reference.
    pub type SecTrustedApplicationRef = *mut std::ffi::c_void;

    unsafe extern "C" {
        /// Creates a `SecTrustedApplicationRef` for the binary at `path`.
        /// On success `*app` is set to a Create-rule CF reference.
        pub fn SecTrustedApplicationCreateFromPath(
            path: *const std::ffi::c_char,
            app: *mut SecTrustedApplicationRef,
        ) -> OSStatus;

        /// Creates a `SecAccessRef` with `trustedlist` as the only apps that
        /// may access the item silently. On success `*access` holds a
        /// Create-rule CF reference.
        pub fn SecAccessCreate(
            descriptor: CFStringRef,
            trustedlist: CFArrayRef,
            access: *mut SecAccessRef,
        ) -> OSStatus;

        /// Attribute key used with `SecItemAdd` to associate a `SecAccessRef`
        /// with a new keychain item (legacy macOS Keychain Services attribute).
        pub static kSecAttrAccess: CFStringRef;
    }
}

/// Build a `SecAccess` that only lists the nono binary as a trusted
/// application. `securityd` silently allows reads from nono and presents
/// a system dialog ("X wants to access key 'nono' in your keychain")
/// for any other caller. The dialog is defense-in-depth against direct
/// Mach IPC bypasses of the mediation shim — primary protection comes
/// from the subprocess mediation refusal, which refuses subprocess reads
/// in the parent before they reach securityd at all.
#[cfg(target_os = "macos")]
fn create_nono_access(
    exe_path: &std::path::Path,
) -> Result<security_framework::os::macos::access::SecAccess> {
    use core_foundation::base::TCFType;
    use core_foundation_sys::array::{CFArrayCreate, kCFTypeArrayCallBacks};
    use core_foundation_sys::base::{CFRelease, kCFAllocatorDefault};
    use core_foundation_sys::string::{CFStringCreateWithBytes, kCFStringEncodingUTF8};
    use macos_ffi::{
        SecAccessCreate, SecTrustedApplicationCreateFromPath, SecTrustedApplicationRef,
    };
    use security_framework::os::macos::access::SecAccess;
    use security_framework_sys::base::SecAccessRef;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path_cstr = CString::new(exe_path.as_os_str().as_bytes()).map_err(|e| {
        NonoError::KeystoreAccess(format!("nono binary path has interior NUL: {e}"))
    })?;

    // SAFETY: path_cstr is a valid NUL-terminated C string. trusted_app
    // receives a Create-rule CF reference that we release after the array retains it.
    let mut trusted_app: SecTrustedApplicationRef = std::ptr::null_mut();
    let status =
        unsafe { SecTrustedApplicationCreateFromPath(path_cstr.as_ptr(), &mut trusted_app) };
    if status != 0 {
        return Err(NonoError::KeystoreAccess(format!(
            "SecTrustedApplicationCreateFromPath: OSStatus {status}"
        )));
    }

    // Wrap in a single-element CFArray. kCFTypeArrayCallBacks calls CFRetain
    // on insertion, so the array owns its own reference to trusted_app.
    // SAFETY: trusted_app is a valid non-null CF object from the call above.
    let items = [trusted_app as *const std::ffi::c_void];
    let array = unsafe {
        CFArrayCreate(
            kCFAllocatorDefault,
            items.as_ptr(),
            1,
            &kCFTypeArrayCallBacks,
        )
    };

    // Release our Create-rule reference; the array now owns the only reference.
    // SAFETY: trusted_app is a Create-rule reference (must be released exactly once).
    unsafe { CFRelease(trusted_app as *const _) };

    if array.is_null() {
        return Err(NonoError::KeystoreAccess(
            "CFArrayCreate for trusted-apps list returned null".to_string(),
        ));
    }

    // Descriptor string for the access object (shown in Keychain Access.app).
    // SAFETY: bytes are valid UTF-8; returns a Create-rule CFStringRef.
    let descriptor_bytes = b"nono oauth broker";
    let descriptor = unsafe {
        CFStringCreateWithBytes(
            kCFAllocatorDefault,
            descriptor_bytes.as_ptr(),
            descriptor_bytes.len() as isize,
            kCFStringEncodingUTF8,
            false as u8,
        )
    };
    if descriptor.is_null() {
        // SAFETY: array is a Create-rule reference from CFArrayCreate above.
        unsafe { CFRelease(array as *const _) };
        return Err(NonoError::KeystoreAccess(
            "CFStringCreateWithBytes for access descriptor returned null".to_string(),
        ));
    }

    let mut access_ref: SecAccessRef = std::ptr::null_mut();
    // SAFETY: descriptor and array are valid CF objects; access_ref receives
    // a Create-rule reference on success.
    let status = unsafe { SecAccessCreate(descriptor, array, &mut access_ref) };

    // Release temporaries regardless of outcome.
    // SAFETY: both are Create-rule references from above.
    unsafe {
        CFRelease(descriptor as *const _);
        CFRelease(array as *const _);
    }

    if status != 0 {
        if !access_ref.is_null() {
            // SAFETY: access_ref is a Create-rule reference from SecAccessCreate.
            unsafe { CFRelease(access_ref as *const _) };
        }
        return Err(NonoError::KeystoreAccess(format!(
            "SecAccessCreate: OSStatus {status}"
        )));
    }

    // SAFETY: access_ref is a non-null Create-rule reference; wrap_under_create_rule
    // takes ownership and will call CFRelease on drop.
    Ok(unsafe { SecAccess::wrap_under_create_rule(access_ref) })
}

/// Write the broker record to the keychain with a nono-only ACL.
///
/// Any existing entry for `service`/`account` is deleted first so that
/// the ACL on the new entry is always set correctly (rather than
/// inheriting the ACL from a prior write that might have used `-A`).
#[cfg(target_os = "macos")]
fn save_with_nono_acl(service: &str, account: &str, payload: &Zeroizing<String>) -> Result<()> {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::SecItemAdd;

    let exe_path = std::env::current_exe()
        .map_err(|e| NonoError::KeystoreAccess(format!("resolve nono binary path: {e}")))?;

    let access = create_nono_access(&exe_path)?;

    // Delete any pre-existing entry so the new one gets a fresh ACL.
    // Ignore "not found" — this is a best-effort cleanup.
    delete_broker_entry_in_process(service, account);

    let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
    let class_val = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    let svc_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
    let svc_val = CFString::from(service);
    let acct_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
    let acct_val = CFString::from(account);
    let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
    let data_val = CFData::from_buffer(payload.as_bytes());
    let access_key = unsafe { CFString::wrap_under_get_rule(macos_ffi::kSecAttrAccess) };

    let mut dict = CFMutableDictionary::from_CFType_pairs(&[]);
    dict.add(&class_key.as_CFTypeRef(), &class_val.as_CFTypeRef());
    dict.add(&svc_key.as_CFTypeRef(), &svc_val.as_CFTypeRef());
    dict.add(&acct_key.as_CFTypeRef(), &acct_val.as_CFTypeRef());
    dict.add(&data_key.as_CFTypeRef(), &data_val.as_CFTypeRef());
    dict.add(&access_key.as_CFTypeRef(), &access.as_CFTypeRef());

    // SAFETY: dict is a valid CFDictionaryRef.
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status != 0 {
        if is_locked_keychain_status(status) {
            return Err(NonoError::KeystoreAccess(locked_keychain_message(
                "save", service, account, status,
            )));
        }
        return Err(NonoError::KeystoreAccess(format!(
            "SecItemAdd for {service}/{account}: OSStatus {status}"
        )));
    }

    Ok(())
}

/// macOS OSStatus codes that indicate the keychain is locked or the
/// caller cannot present UI to unlock it. The default login keychain
/// is auto-unlocked at login but locks again after sleep and is
/// generally not unlocked under SSH. We treat all three as the same
/// failure mode for the user.
///
/// Codes are not re-exported as constants by `security-framework-sys`;
/// see <https://developer.apple.com/documentation/security/1542001-security_framework_result_codes>
/// for the canonical list.
#[cfg(target_os = "macos")]
const LOCKED_KEYCHAIN_STATUSES: &[i32] = &[
    -25308, // errSecInteractionNotAllowed: UI required but not allowed (SSH/headless).
    -25293, // errSecAuthFailed: authentication failed (keychain locked).
    -25304, // errSecNotAvailable: no keychain is available (rare; defensive).
];

/// Whether `status` denotes a locked-keychain condition.
#[cfg(target_os = "macos")]
fn is_locked_keychain_status(status: i32) -> bool {
    LOCKED_KEYCHAIN_STATUSES.contains(&status)
}

/// Single user-facing message for any locked-keychain situation.
/// Surfaced through both load (via the error) and save (via `warn!`).
#[cfg(target_os = "macos")]
fn locked_keychain_message(op: &str, service: &str, account: &str, status: i32) -> String {
    format!(
        "broker record {op} for {service}/{account} blocked: keychain is locked \
         (OSStatus {status}). Common causes: SSH session, post-sleep without GUI \
         unlock, or Keychain Access set to lock on inactivity. Cross-session \
         resume is disabled until the login keychain is unlocked."
    )
}

/// Load the raw JSON string for `service`/`account` using an in-process
/// Security framework call. Running in the nono process ensures the
/// nono-only ACL is satisfied silently — no `security` CLI subprocess,
/// no prompts.
///
/// A locked-keychain condition (SSH, post-sleep, etc.) returns
/// [`NonoError::KeystoreAccess`] with an actionable message rather than
/// a generic error so the user understands why cross-session resume is
/// not working this run. The caller falls back to in-memory.
#[cfg(target_os = "macos")]
fn load_in_process(service: &str, account: &str) -> Result<Option<String>> {
    use security_framework::os::macos::passwords::find_generic_password;

    match find_generic_password(None, service, account) {
        Ok((password_bytes, _item)) => {
            let s = std::str::from_utf8(password_bytes.as_ref()).map_err(|e| {
                NonoError::KeystoreAccess(format!(
                    "broker record at {service}/{account} contains non-UTF8 bytes: {e}"
                ))
            })?;
            Ok(Some(s.to_owned()))
        }
        Err(e) => {
            // errSecItemNotFound (-25300) → no entry yet; any other error is real.
            use security_framework_sys::base::errSecItemNotFound;
            if e.code() == errSecItemNotFound {
                Ok(None)
            } else if is_locked_keychain_status(e.code()) {
                Err(NonoError::KeystoreAccess(locked_keychain_message(
                    "load",
                    service,
                    account,
                    e.code(),
                )))
            } else {
                Err(NonoError::KeystoreAccess(format!(
                    "broker record load from {service}/{account}: {e}"
                )))
            }
        }
    }
}

/// Delete the broker keychain entry in-process. Errors (including
/// "item not found") are silently swallowed — callers use this as a
/// best-effort cleanup before writing a fresh entry.
#[cfg(target_os = "macos")]
fn delete_broker_entry_in_process(service: &str, account: &str) {
    use core_foundation::base::TCFType;
    use security_framework::os::macos::passwords::find_generic_password;
    use security_framework_sys::keychain_item::SecKeychainItemDelete;

    // The item was saved via SecItemAdd + kSecAttrAccess (file-based login.keychain).
    // SecItemDelete (used by delete_generic_password) searches the data-protection
    // keychain and returns errSecItemNotFound (-25300) for file-based items, so it
    // cannot delete our entry. Instead, use find_generic_password (old API) to locate
    // the item in the file-based keychain by its ref, then SecKeychainItemDelete it
    // directly — matching the same API family as save_with_nono_acl and load_in_process.
    // The ACL on the item allows the nono binary, so find_generic_password succeeds
    // in-process without a user dialog.
    match find_generic_password(None, service, account) {
        Ok((_password, item)) => {
            // SAFETY: item is a valid SecKeychainItemRef obtained from
            // find_generic_password.
            let status = unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) };
            if status != 0 {
                tracing::warn!(
                    "OAuth broker keychain delete failed \
                     (service={service:?} account={account:?} code={status})"
                );
            }
        }
        Err(e) if e.code() == -25300 => {} // errSecItemNotFound — already gone, expected
        Err(e) => {
            tracing::warn!(
                "OAuth broker keychain find-for-delete failed \
                 (service={service:?} account={account:?} code={})",
                e.code()
            );
        }
    }
}

/// Read the `claudeAiOauth.accessToken` field from claude's own
/// `Claude Code-credentials` keychain entry, if present.
///
/// Used by [`super::token_broker::TokenBroker::with_store_and_reader`] to
/// detect stale broker records (the user `/logout`-ed inside claude
/// but our persisted record still holds the real refresh token).
///
/// All failure modes (keychain missing, locked, malformed JSON, no
/// access token in the envelope) collapse to `None` — the caller
/// treats both "no entry" and "couldn't read entry" identically:
/// drop the broker record and force a re-login. This is the
/// conservative choice: better to drop a live record than to leak a
/// real token because we couldn't tell.
#[cfg(target_os = "macos")]
pub(crate) fn current_claude_access_token() -> Option<String> {
    // Claude Code stores its OAuth credentials in either the macOS keychain
    // (`Claude Code-credentials`) or, on some installs, a file at
    // `~/.claude/.credentials.json`. Check both so the orphan-GC cross-
    // reference works regardless of which backend this install uses — without
    // the file fallback, a file-based install always looks "logged out" to the
    // broker, so the persisted record is wrongly cleared and cross-session
    // resume never resolves the nonce (→ "401 Invalid bearer token").
    claude_access_token_from_keychain().or_else(claude_access_token_from_file)
}

#[cfg(target_os = "macos")]
fn claude_access_token_from_keychain() -> Option<String> {
    use security_framework::os::macos::passwords::find_generic_password;

    let service = claude_credentials_service_name()?;

    // Claude Code writes its `Claude Code-credentials` entry under account
    // "unknown" (its default when it has no user identity) on current
    // versions, and historically under the OS username. Try both — using the
    // wrong account silently misses the entry, which makes hydration think
    // the user is logged out and wrongly clears the persisted record.
    let user = std::env::var("USER").unwrap_or_default();
    let candidates = ["unknown", user.as_str(), "claude-code-user"];
    for account in candidates {
        if account.is_empty() {
            continue;
        }
        if let Ok((password_bytes, _item)) = find_generic_password(None, &service, account)
            && let Ok(raw) = std::str::from_utf8(password_bytes.as_ref())
            && let Some(token) = claude_access_token_from_envelope(raw)
        {
            return Some(token);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn claude_access_token_from_file() -> Option<String> {
    let dir = if let Some(custom) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        std::path::PathBuf::from(custom)
    } else {
        std::path::PathBuf::from(std::env::var_os("HOME")?).join(".claude")
    };
    let raw = std::fs::read_to_string(dir.join(".credentials.json")).ok()?;
    claude_access_token_from_envelope(&raw)
}

/// Extract `claudeAiOauth.accessToken` from a Claude credentials JSON
/// envelope (same shape in the keychain entry and the credentials file).
#[cfg(target_os = "macos")]
fn claude_access_token_from_envelope(raw: &str) -> Option<String> {
    let envelope: serde_json::Value = serde_json::from_str(raw).ok()?;
    envelope
        .get("claudeAiOauth")?
        .get("accessToken")?
        .as_str()
        .map(str::to_owned)
}

/// Derive the macOS keychain service name claude uses for its OAuth
/// credentials (custom-oauth, staging/local toggles, explicit
/// `CLAUDE_CONFIG_DIR` hash suffix).
#[cfg(target_os = "macos")]
fn claude_credentials_service_name() -> Option<String> {
    use sha2::{Digest, Sha256};

    let (config_dir, explicit) = if let Some(custom) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        (std::path::PathBuf::from(custom), true)
    } else {
        let home = std::env::var_os("HOME")?;
        (std::path::PathBuf::from(home).join(".claude"), false)
    };

    let suffix = claude_oauth_suffix();
    let dir_hash = if explicit {
        let digest = Sha256::digest(config_dir.to_string_lossy().as_bytes());
        let prefix = digest[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("-{prefix}")
    } else {
        String::new()
    };
    Some(format!("Claude Code{suffix}-credentials{dir_hash}"))
}

#[cfg(target_os = "macos")]
fn claude_oauth_suffix() -> &'static str {
    if std::env::var_os("CLAUDE_CODE_CUSTOM_OAUTH_URL").is_some() {
        return "-custom-oauth";
    }
    if std::env::var("USER_TYPE").ok().as_deref() == Some("ant") {
        let truthy = |key: &str| {
            std::env::var(key).ok().is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
        };
        if truthy("USE_LOCAL_OAUTH") {
            return "-local-oauth";
        }
        if truthy("USE_STAGING_OAUTH") {
            return "-staging-oauth";
        }
    }
    ""
}

// ── KeystoreBrokerStore ───────────────────────────────────────────────────────

/// macOS Keychain-backed store. Not available on other platforms.
#[cfg(target_os = "macos")]
pub(crate) struct KeystoreBrokerStore {
    service: String,
    account: String,
}

#[cfg(target_os = "macos")]
impl KeystoreBrokerStore {
    /// Construct a store keyed by `service` and `account`.
    pub(crate) fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    /// Default store: nono's credential-injection service, OAuth account.
    pub(crate) fn default_for_claude_oauth() -> Self {
        Self::new(SERVICE_NAME, CLAUDE_OAUTH_ACCOUNT)
    }
}

#[cfg(target_os = "macos")]
impl BrokerStore for KeystoreBrokerStore {
    fn load(&self) -> Result<Option<PersistedRecord>> {
        let exe_path = std::env::current_exe()
            .map_err(|e| NonoError::KeystoreAccess(format!("resolve nono binary path: {e}")))?;

        let maybe_json = load_in_process(&self.service, &self.account)?;
        let json = match maybe_json {
            None => return Ok(None),
            Some(j) => j,
        };

        let parsed = serde_json::from_str::<PersistedJson>(&json).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "broker record at {}/{} is not valid JSON: {e}",
                self.service, self.account
            ))
        })?;

        // Validate the stored nono binary path. A mismatch means either an
        // upgrade changed the install location, or the entry pre-dates the
        // nono_path field. In both cases the ACL on the existing entry may
        // not match the current binary, so we delete it and return None —
        // the next OAuth capture will create a fresh entry with the correct ACL.
        let stored_path = match &parsed.nono_path {
            Some(p) => p.as_str(),
            None => {
                tracing::info!(
                    "broker record at {}/{} has no nono_path; deleting stale entry",
                    self.service,
                    self.account
                );
                delete_broker_entry_in_process(&self.service, &self.account);
                return Ok(None);
            }
        };

        if stored_path != exe_path.to_string_lossy().as_ref() as &str {
            tracing::info!(
                "nono binary path changed ({stored_path} → {}); deleting stale broker entry",
                exe_path.display()
            );
            delete_broker_entry_in_process(&self.service, &self.account);
            return Ok(None);
        }

        Ok(Some(parsed.into_record()))
    }

    fn save(&self, record: &PersistedRecord) -> Result<()> {
        let exe_path = std::env::current_exe()
            .map_err(|e| NonoError::KeystoreAccess(format!("resolve nono binary path: {e}")))?;

        let json: Zeroizing<String> = Zeroizing::new(
            serde_json::to_string(&PersistedJson::from_record(record, &exe_path))
                .map_err(|e| NonoError::KeystoreAccess(format!("broker record serialise: {e}")))?,
        );

        save_with_nono_acl(&self.service, &self.account, &json)
    }

    fn clear(&self) -> Result<()> {
        delete_broker_entry_in_process(&self.service, &self.account);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! In-memory `BrokerStore` for unit tests.

    use super::*;
    use std::sync::Mutex;

    pub struct MemoryBrokerStore {
        record: Mutex<Option<PersistedRecord>>,
    }

    impl MemoryBrokerStore {
        pub fn new() -> Self {
            Self {
                record: Mutex::new(None),
            }
        }

        pub fn preload(record: PersistedRecord) -> Self {
            Self {
                record: Mutex::new(Some(record)),
            }
        }

        pub fn current(&self) -> Option<PersistedRecord> {
            self.record
                .lock()
                .expect("MemoryBrokerStore poisoned")
                .clone()
        }
    }

    impl BrokerStore for MemoryBrokerStore {
        fn load(&self) -> Result<Option<PersistedRecord>> {
            Ok(self
                .record
                .lock()
                .expect("MemoryBrokerStore poisoned")
                .clone())
        }

        fn save(&self, record: &PersistedRecord) -> Result<()> {
            *self.record.lock().expect("MemoryBrokerStore poisoned") = Some(record.clone());
            Ok(())
        }

        fn clear(&self) -> Result<()> {
            *self.record.lock().expect("MemoryBrokerStore poisoned") = None;
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn persisted_json_payload_exceeds_readpassphrase_buffer() {
        // Regression guard: the macOS save path uses SecItemAdd directly
        // (no `readpassphrase(3)` cap), but the serialised payload still
        // exceeds 128 bytes. If a future refactor reintroduces a
        // `security ... -w` (stdin-pipe to readpassphrase) backend, this test
        // makes the silent-truncation failure mode visible at build time.
        let exe_path = std::path::Path::new("/usr/local/bin/nono");
        let record = PersistedRecord {
            access_nonce: format!("nono_{}", "a".repeat(64)),
            refresh_nonce: format!("nono_{}", "b".repeat(64)),
            // Anthropic OAuth tokens are JWT-shaped, typically 150-300
            // bytes. Use a representative 200-byte string here.
            access_token: Zeroizing::new("sk-ant-oat01-".to_string() + &"x".repeat(187)),
            refresh_token: Zeroizing::new("sk-ant-ort01-".to_string() + &"y".repeat(187)),
        };
        let json = serde_json::to_string(&PersistedJson::from_record(&record, exe_path))
            .expect("serialise persisted json");
        assert!(
            json.len() > 128,
            "payload must exceed 128 bytes (got {} bytes); \
             update the test or verify the backend handles large values",
            json.len()
        );
    }

    #[test]
    fn nono_path_round_trips_through_json() {
        let exe_path = std::path::Path::new("/old/path/to/nono");
        let record = PersistedRecord {
            access_nonce: format!("nono_{}", "a".repeat(64)),
            refresh_nonce: format!("nono_{}", "b".repeat(64)),
            access_token: Zeroizing::new("real_access".to_string()),
            refresh_token: Zeroizing::new("real_refresh".to_string()),
        };
        let json = serde_json::to_string(&PersistedJson::from_record(&record, exe_path)).unwrap();
        let parsed: PersistedJson = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nono_path.as_deref(), Some("/old/path/to/nono"));
    }

    #[test]
    fn missing_nono_path_deserialises_as_none() {
        // Entries written by older versions of nono omit the nono_path field.
        // `serde(default)` should deserialise them with `nono_path = None`,
        // which `KeystoreBrokerStore::load` treats as stale and deletes.
        let legacy_json = r#"{
            "access_nonce": "nono_aaaa",
            "refresh_nonce": "nono_bbbb",
            "access_token": "real_access",
            "refresh_token": "real_refresh"
        }"#;
        let parsed: PersistedJson = serde_json::from_str(legacy_json).unwrap();
        assert!(
            parsed.nono_path.is_none(),
            "legacy entries must deserialise with nono_path = None"
        );
    }

    #[test]
    fn memory_store_round_trips_save_load_clear() {
        use test_support::MemoryBrokerStore;
        let store = MemoryBrokerStore::new();
        assert!(store.load().unwrap().is_none(), "fresh store is empty");

        let record = PersistedRecord {
            access_nonce: "nono_a".to_string(),
            refresh_nonce: "nono_b".to_string(),
            access_token: Zeroizing::new("real_a".to_string()),
            refresh_token: Zeroizing::new("real_b".to_string()),
        };
        store.save(&record).unwrap();
        let loaded = store.load().unwrap().expect("save then load");
        assert_eq!(loaded.access_nonce, "nono_a");
        assert_eq!(loaded.access_token.as_str(), "real_a");

        store.clear().unwrap();
        assert!(store.load().unwrap().is_none(), "cleared store is empty");
    }

    // ── Locked-keychain detection ────────────────────────────────────────

    #[test]
    #[cfg(target_os = "macos")]
    fn claude_access_token_from_envelope_extracts_field() {
        let raw = r#"{"claudeAiOauth":{"accessToken":"nono_abc","refreshToken":"nono_def"}}"#;
        assert_eq!(
            claude_access_token_from_envelope(raw).as_deref(),
            Some("nono_abc")
        );
        // Missing field / malformed → None (treated as "logged out").
        assert_eq!(claude_access_token_from_envelope(r#"{"other":1}"#), None);
        assert_eq!(claude_access_token_from_envelope("not json"), None);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn locked_keychain_status_recognised_for_known_codes() {
        assert!(
            is_locked_keychain_status(-25308),
            "errSecInteractionNotAllowed must be classified as locked"
        );
        assert!(
            is_locked_keychain_status(-25293),
            "errSecAuthFailed must be classified as locked"
        );
        assert!(
            is_locked_keychain_status(-25304),
            "errSecNotAvailable must be classified as locked"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn locked_keychain_status_rejects_other_codes() {
        // errSecItemNotFound is the no-entry sentinel, not a locked state.
        assert!(!is_locked_keychain_status(-25300));
        // OSStatus 0 is success.
        assert!(!is_locked_keychain_status(0));
        // Random unrelated error.
        assert!(!is_locked_keychain_status(-1));
        // errSecParam (-50) — wrong arguments, not locked.
        assert!(!is_locked_keychain_status(-50));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn locked_keychain_message_is_actionable() {
        // The user-facing message must name the failure mode and the
        // typical cause (SSH/sleep) so the user knows the cross-session
        // resume regression is environmental, not a nono bug.
        let msg = locked_keychain_message("load", "nono", "claude_oauth_broker", -25308);
        assert!(msg.contains("locked"), "msg must say what happened: {msg}");
        assert!(msg.contains("SSH"), "msg must list a common cause: {msg}");
        assert!(
            msg.contains("Cross-session resume is disabled"),
            "msg must explain the consequence: {msg}"
        );
        assert!(
            msg.contains("-25308"),
            "msg must include the OSStatus for debuggability: {msg}"
        );
        // The credential itself must not leak through this path.
        assert!(
            !msg.contains("sk-ant-"),
            "msg must not contain any real token: {msg}"
        );
    }

    // ── ACL invariant ────────────────────────────────────────────────────
    //
    // The module-level docstring states that every save MUST go through
    // `save_with_nono_acl`, which always calls `create_nono_access` with
    // `current_exe()`. The tests below exercise that constructor for both
    // success and failure paths. The full ACL-contents round-trip is gated
    // behind `#[ignore]` because it requires writing to the user's keychain.

    #[test]
    #[cfg(target_os = "macos")]
    fn create_nono_access_succeeds_for_current_exe() {
        // The happy path: the running binary always exists on disk, so
        // `SecTrustedApplicationCreateFromPath` resolves it and
        // `SecAccessCreate` returns an access object. This is the path
        // every save in production takes.
        let exe = std::env::current_exe().expect("test binary path");
        let access = create_nono_access(&exe).expect("ACL build must succeed for current exe");
        // A non-null wrapper is sufficient to prove SecAccessCreate
        // returned successfully — anything else would have been Err above.
        drop(access);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn create_nono_access_fails_for_nonexistent_path() {
        // `SecTrustedApplicationCreateFromPath` requires the path to
        // resolve to a real binary on disk. A nonexistent path must
        // surface as Err rather than silently producing a SecAccess
        // tied to a dangling reference.
        let bogus = std::path::Path::new("/this/path/does/not/exist/nono-bogus-test");
        let result = create_nono_access(bogus);
        assert!(
            result.is_err(),
            "ACL build must fail for nonexistent path; got Ok"
        );
    }

    /// Manual ACL round-trip integration test.
    ///
    /// Writes a record to a unique test-only keychain entry, reads it
    /// back, and asserts the save/load path works against the real
    /// macOS Security framework.
    ///
    /// **Gated behind `#[ignore]`** because it writes to the user's
    /// login keychain and most CI environments do not have an unlocked
    /// login keychain available. Run manually before a release that
    /// changes anything in `save_with_nono_acl`, `create_nono_access`,
    /// or the macOS FFI bindings:
    ///
    /// ```bash
    /// cargo test -p nono-cli --bin nono \
    ///     tool_sandbox::broker_store::tests::acl_round_trip_manual_only \
    ///     -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "writes to login keychain; run manually before release"]
    #[cfg(target_os = "macos")]
    fn acl_round_trip_manual_only() {
        // Unique service/account so we don't collide with the real
        // broker entry under the same login keychain.
        let service = format!("nono-acl-roundtrip-test-{}", std::process::id());
        let account = "test_acl_roundtrip";

        let record = PersistedRecord {
            access_nonce: "nono_test_access".to_string(),
            refresh_nonce: "nono_test_refresh".to_string(),
            access_token: Zeroizing::new("not-a-real-token-access".to_string()),
            refresh_token: Zeroizing::new("not-a-real-token-refresh".to_string()),
        };
        let store = KeystoreBrokerStore::new(service.clone(), account.to_string());

        // Save → load round-trip.
        store.save(&record).expect("save under unique service");
        let loaded = store
            .load()
            .expect("load after save")
            .expect("loaded record present");
        assert_eq!(loaded.access_nonce, "nono_test_access");
        assert_eq!(loaded.access_token.as_str(), "not-a-real-token-access");

        // Clean up so the entry doesn't linger.
        store.clear().expect("clear after roundtrip");
        assert!(store.load().expect("post-clear load").is_none());
    }
}
