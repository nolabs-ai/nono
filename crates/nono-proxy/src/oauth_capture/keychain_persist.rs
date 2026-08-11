//! macOS Keychain persistence for the OAuth-capture phantom-token map.
//!
//! `oauth_capture` mints `nono_<hex>` phantom nonces and substitutes them for
//! real OAuth token material in responses the sandboxed agent sees. Without
//! persistence the mapping is lost when nono exits, forcing a fresh login on
//! every session. This module persists the same JSON shape the file backend
//! (`persist.rs`) uses, but as a single macOS Keychain generic-password item
//! under service [`KEYCHAIN_SERVICE`], account [`OAUTH_CAPTURE_ACCOUNT`],
//! instead of a file.
//!
//! ## Protection model: two layers, neither alone sufficient
//!
//! ### Primary: subprocess mediation refusal
//!
//! A profile that enables OAuth capture also refuses subprocess
//! `security find-generic-password` reads of this entry. The shim returns
//! `errSecItemNotFound` in the unsandboxed parent process before any call
//! reaches macOS securityd — no dialog, no Allow button, no social
//! engineering surface. This is the protection the realistic threat model
//! relies on.
//!
//! ### Defense-in-depth: legacy ACL on the keychain entry
//!
//! The entry is also created with a `SecAccess` ACL listing only the nono
//! binary as a trusted application. This catches attempts that bypass the
//! mediation shim — most notably a binary linked against Security.framework
//! that calls `SecItemCopyMatching` via Mach IPC directly. The legacy ACL
//! does not silently deny non-trusted callers: it triggers a system dialog
//! ("X wants to access key 'nono' in your keychain") the user can click
//! Allow on. So this layer is visible alerting against the Mach-IPC bypass,
//! not silent denial.
//!
//! ### Invariant
//!
//! Every save path through this module MUST go through
//! [`save_with_nono_acl`], which sets a `SecAccess` listing only
//! `current_exe()` before calling `SecItemAdd`.
//!
//! Future maintainers: do not introduce a new save path that bypasses
//! [`save_with_nono_acl`]. In particular, do not use `keyring::set_password`
//! for this entry on macOS — the `keyring` crate's `apple-native` backend
//! creates entries with the default ACL, which any app can prompt the user
//! to allow. `keyring` is intentionally not imported by this module.
//!
//! All Security framework operations run in-process (the nono binary, which
//! is in the ACL). No `security` CLI subprocess is used.
//!
//! ## Binary-path staleness
//!
//! The persisted JSON records `nono_path`, the absolute path of the nono
//! binary at save time. On load it is compared against `current_exe()`. A
//! mismatch (upgrade, reinstall to a different prefix, local rebuild) means
//! the entry's ACL is keyed to a binary that no longer matches the running
//! nono, so subsequent reads would prompt. Such an entry is treated as
//! stale: it is deleted and treated as empty, forcing a fresh capture with
//! the correct ACL.
//!
//! ## Retention
//!
//! `oauth_capture::mod` already enforces a 4096-entry cap and 90-day TTL at
//! the phantom level before persistence is ever called, so this module does
//! not duplicate a separate record-level TTL.
//!
//! ## Attribution
//!
//! The ACL technique (`create_nono_access`, `save_with_nono_acl`,
//! `load_in_process`, `delete_broker_entry_in_process`, and the
//! locked-keychain handling) is ported from the closed, unmerged
//! `nolabs-ai/nono#1267` ("oauth-capture routes with phantom-token broker"),
//! `crates/nono-cli/src/tool-sandbox/broker_store.rs`. That PR was closed in
//! favor of the simpler flat-file design that shipped as `#1343`, not
//! because the Keychain approach was wrong. This module generalizes it from
//! a single Claude-specific access/refresh token record to the current
//! multi-provider `HashMap<phantom, StoredOAuthToken>` schema, and drops the
//! Claude-specific `/logout` detection helpers, which are out of scope here.
//!
//! ## Linux
//!
//! Not supported by this module (macOS-only, `#[cfg(target_os = "macos")]`).
//! Linux's keyring backends (Secret Service, gnome-keyring) have no
//! per-entry ACL — entries are readable by any process running as the same
//! user, defeating the protection model that motivates this design. Linux
//! stays on the file backend (`persist.rs`).

use super::StoredOAuthToken;
use super::persist::{decode_tokens, encode_tokens};
use crate::error::{ProxyError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Keychain service name shared with nono's credential-injection feature.
/// New account names here must not collide with documented account names
/// from that feature (e.g. `openai_api_key`, `anthropic_api_key`,
/// `github_token`).
pub(super) const KEYCHAIN_SERVICE: &str = nono::keystore::DEFAULT_SERVICE;

/// Account name for the OAuth-capture phantom-token map. Distinct from any
/// user-managed account names so `security add-generic-password` for
/// unrelated services never overwrites it and vice versa.
///
/// Re-exported from [`crate::config::OAUTH_CAPTURE_STORE_ACCOUNT`] so the
/// Keychain item this module creates and the `security` mediation nono-cli
/// derives always name the same account.
pub(super) const OAUTH_CAPTURE_ACCOUNT: &str = crate::config::OAUTH_CAPTURE_STORE_ACCOUNT;

/// On-disk (well, on-keychain) JSON envelope: the same `PersistedOAuthStore`
/// payload the file backend uses, plus the binary-path staleness stamp.
///
/// `nono_path` records the absolute path of the nono binary at save time.
/// Entries written before this field existed, or with a path that no longer
/// matches `current_exe()`, are treated as stale and deleted on load.
#[derive(Serialize, Deserialize)]
struct KeychainEnvelope {
    #[serde(flatten)]
    store: serde_json::Value,
    #[serde(default)]
    nono_path: Option<String>,
}

/// Resolve the running nono binary's path for staleness comparison and ACL
/// binding.
///
/// Canonicalizes away symlinks (best-effort) so that launching nono via a
/// symlink vs. its resolved target — or vice versa on a later run — compares
/// equal instead of looking like a binary-path mismatch. An uncanonicalizable
/// path (e.g. the binary was deleted or replaced mid-run) falls back to the
/// raw `current_exe()` path rather than failing the caller.
fn resolved_exe_path() -> Result<std::path::PathBuf> {
    let exe_path = std::env::current_exe()
        .map_err(|e| ProxyError::Keystore(format!("resolve nono binary path: {e}")))?;
    Ok(std::fs::canonicalize(&exe_path).unwrap_or(exe_path))
}

/// Load the persisted phantom map from the Keychain, or an empty map if no
/// entry exists or the entry is stale (binary-path mismatch).
///
/// A locked keychain is **not** treated as empty: it returns
/// `Err(ProxyError::Keystore(..))` so the caller fails closed rather than
/// silently continuing without persistence. There is no in-memory fallback —
/// capture is unavailable until the login keychain is unlocked.
pub(super) fn load_persisted_tokens() -> Result<HashMap<String, StoredOAuthToken>> {
    let Some(raw) = load_in_process(KEYCHAIN_SERVICE, OAUTH_CAPTURE_ACCOUNT)? else {
        return Ok(HashMap::new());
    };

    let envelope: KeychainEnvelope = serde_json::from_str(&raw).map_err(|err| {
        ProxyError::Keystore(format!(
            "failed to parse OAuth capture keychain entry: {err}"
        ))
    })?;

    let exe_path = resolved_exe_path()?;
    let is_stale = match envelope.nono_path.as_deref() {
        Some(saved_path) => saved_path != exe_path.to_string_lossy(),
        None => true,
    };
    if is_stale {
        delete_broker_entry_in_process(KEYCHAIN_SERVICE, OAUTH_CAPTURE_ACCOUNT);
        return Ok(HashMap::new());
    }

    let store_raw = serde_json::to_vec(&envelope.store).map_err(|err| {
        ProxyError::Keystore(format!(
            "failed to re-encode OAuth capture keychain entry: {err}"
        ))
    })?;
    decode_tokens(&store_raw)
}

/// Persist the phantom map to the Keychain with a nono-only ACL, tagged with
/// the current binary path for staleness detection on the next load.
pub(super) fn persist_tokens(tokens: &HashMap<String, StoredOAuthToken>) -> Result<()> {
    let raw = encode_tokens(tokens)?;
    let store: serde_json::Value = serde_json::from_slice(&raw).map_err(|err| {
        ProxyError::Keystore(format!("failed to encode OAuth capture store: {err}"))
    })?;

    let exe_path = resolved_exe_path()?;
    let envelope = KeychainEnvelope {
        store,
        nono_path: Some(exe_path.to_string_lossy().into_owned()),
    };
    let payload = Zeroizing::new(serde_json::to_string(&envelope).map_err(|err| {
        ProxyError::Keystore(format!(
            "failed to encode OAuth capture keychain entry: {err}"
        ))
    })?);

    save_with_nono_acl(KEYCHAIN_SERVICE, OAUTH_CAPTURE_ACCOUNT, &payload)
}

// ── macOS: in-process Security framework helpers ───────────────────────────
//
// Ported from nolabs-ai/nono#1267's `broker_store.rs`. See module doc for
// attribution and the two-layer protection model these implement.

/// FFI bindings for legacy Keychain Services ACL APIs not exposed by
/// `security-framework-sys`. Security.framework is already linked by that
/// crate's `lib.rs` `#[link]` attribute, so no additional link attribute is
/// needed here.
mod macos_ffi {
    use core_foundation_sys::array::CFArrayRef;
    use core_foundation_sys::base::OSStatus;
    use core_foundation_sys::string::CFStringRef;
    use security_framework_sys::base::SecAccessRef;

    /// Opaque CF type for a trusted-application reference.
    pub type SecTrustedApplicationRef = *mut std::ffi::c_void;

    unsafe extern "C" {
        /// Creates a `SecTrustedApplicationRef` for the binary at `path`. On
        /// success `*app` is set to a Create-rule CF reference.
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
        /// with a new keychain item (legacy macOS Keychain Services
        /// attribute).
        pub static kSecAttrAccess: CFStringRef;
    }
}

/// Build a `SecAccess` that only lists the nono binary as a trusted
/// application. `securityd` silently allows reads from nono and presents a
/// system dialog for any other caller. The dialog is defense-in-depth
/// against direct Mach IPC bypasses of the mediation shim — primary
/// protection comes from the subprocess mediation refusal, which refuses
/// subprocess reads in the parent before they reach securityd at all.
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

    let path_cstr = CString::new(exe_path.as_os_str().as_bytes())
        .map_err(|e| ProxyError::Keystore(format!("nono binary path has interior NUL: {e}")))?;

    // SAFETY: path_cstr is a valid NUL-terminated C string. trusted_app
    // receives a Create-rule CF reference that we release after the array
    // retains it.
    let mut trusted_app: SecTrustedApplicationRef = std::ptr::null_mut();
    let status =
        unsafe { SecTrustedApplicationCreateFromPath(path_cstr.as_ptr(), &mut trusted_app) };
    if status != 0 {
        return Err(ProxyError::Keystore(format!(
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

    // Release our Create-rule reference; the array now owns the only
    // reference.
    // SAFETY: trusted_app is a Create-rule reference (must be released
    // exactly once).
    unsafe { CFRelease(trusted_app as *const _) };

    if array.is_null() {
        return Err(ProxyError::Keystore(
            "CFArrayCreate for trusted-apps list returned null".to_string(),
        ));
    }

    // Descriptor string for the access object (shown in Keychain Access.app).
    // SAFETY: bytes are valid UTF-8; returns a Create-rule CFStringRef.
    let descriptor_bytes = b"nono oauth capture";
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
        return Err(ProxyError::Keystore(
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
            // SAFETY: access_ref is a Create-rule reference from
            // SecAccessCreate.
            unsafe { CFRelease(access_ref as *const _) };
        }
        return Err(ProxyError::Keystore(format!(
            "SecAccessCreate: OSStatus {status}"
        )));
    }

    // SAFETY: access_ref is a non-null Create-rule reference;
    // wrap_under_create_rule takes ownership and will call CFRelease on
    // drop.
    Ok(unsafe { SecAccess::wrap_under_create_rule(access_ref) })
}

/// Write the OAuth capture store to the keychain with a nono-only ACL.
///
/// Any existing entry for `service`/`account` is deleted first so the ACL on
/// the new entry is always set correctly (rather than inheriting the ACL
/// from a prior write that might have used `-A`).
fn save_with_nono_acl(service: &str, account: &str, payload: &Zeroizing<String>) -> Result<()> {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::SecItemAdd;

    let exe_path = resolved_exe_path()?;

    let access = create_nono_access(&exe_path)?;

    // Delete any pre-existing entry so the new one gets a fresh ACL. Ignore
    // "not found" — this is a best-effort cleanup.
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
            return Err(ProxyError::Keystore(locked_keychain_message(
                "save", service, account, status,
            )));
        }
        return Err(ProxyError::Keystore(format!(
            "SecItemAdd for {service}/{account}: OSStatus {status}"
        )));
    }

    Ok(())
}

/// macOS OSStatus codes that indicate the keychain is locked or the caller
/// cannot present UI to unlock it. The default login keychain is
/// auto-unlocked at login but locks again after sleep and is generally not
/// unlocked under SSH. We treat all three as the same failure mode for the
/// user.
///
/// Codes are not re-exported as constants by `security-framework-sys`; see
/// <https://developer.apple.com/documentation/security/1542001-security_framework_result_codes>
/// for the canonical list.
const LOCKED_KEYCHAIN_STATUSES: &[i32] = &[
    -25308, // errSecInteractionNotAllowed: UI required but not allowed (SSH/headless).
    -25293, // errSecAuthFailed: authentication failed (keychain locked).
    -25304, // errSecNotAvailable: no keychain is available (rare; defensive).
];

/// Whether `status` denotes a locked-keychain condition.
fn is_locked_keychain_status(status: i32) -> bool {
    LOCKED_KEYCHAIN_STATUSES.contains(&status)
}

/// Single user-facing message for any locked-keychain situation.
fn locked_keychain_message(op: &str, service: &str, account: &str, status: i32) -> String {
    format!(
        "OAuth capture store {op} for {service}/{account} blocked: keychain is locked \
         (OSStatus {status}). Common causes: SSH session, post-sleep without GUI \
         unlock, or Keychain Access set to lock on inactivity. OAuth capture fails \
         closed and is unavailable until the login keychain is unlocked; there is no \
         in-memory fallback."
    )
}

/// Load the raw JSON string for `service`/`account` using an in-process
/// Security framework call. Running in the nono process ensures the
/// nono-only ACL is satisfied silently — no `security` CLI subprocess, no
/// prompts.
fn load_in_process(service: &str, account: &str) -> Result<Option<String>> {
    use security_framework::os::macos::passwords::find_generic_password;

    match find_generic_password(None, service, account) {
        Ok((password_bytes, _item)) => {
            let s = std::str::from_utf8(password_bytes.as_ref()).map_err(|e| {
                ProxyError::Keystore(format!(
                    "OAuth capture store at {service}/{account} contains non-UTF8 bytes: {e}"
                ))
            })?;
            Ok(Some(s.to_owned()))
        }
        Err(e) => {
            // errSecItemNotFound (-25300) → no entry yet; any other error is
            // real.
            use security_framework_sys::base::errSecItemNotFound;
            if e.code() == errSecItemNotFound {
                Ok(None)
            } else if is_locked_keychain_status(e.code()) {
                Err(ProxyError::Keystore(locked_keychain_message(
                    "load",
                    service,
                    account,
                    e.code(),
                )))
            } else {
                Err(ProxyError::Keystore(format!(
                    "OAuth capture store load from {service}/{account}: {e}"
                )))
            }
        }
    }
}

/// Delete the OAuth capture keychain entry in-process. Errors (including
/// "item not found") are silently swallowed — callers use this as a
/// best-effort cleanup before writing a fresh entry, or to drop a stale
/// (binary-path-mismatched) entry.
fn delete_broker_entry_in_process(service: &str, account: &str) {
    use core_foundation::base::TCFType;
    use security_framework::os::macos::passwords::find_generic_password;
    use security_framework_sys::keychain_item::SecKeychainItemDelete;

    // The item was saved via SecItemAdd + kSecAttrAccess (file-based
    // login.keychain). SecItemDelete (used by delete_generic_password)
    // searches the data-protection keychain and returns errSecItemNotFound
    // (-25300) for file-based items, so it cannot delete our entry. Instead,
    // use find_generic_password (old API) to locate the item in the
    // file-based keychain by its ref, then SecKeychainItemDelete it
    // directly — matching the same API family as save_with_nono_acl and
    // load_in_process. The ACL on the item allows the nono binary, so
    // find_generic_password succeeds in-process without a user dialog.
    match find_generic_password(None, service, account) {
        Ok((_password, item)) => {
            // SAFETY: item is a valid SecKeychainItemRef obtained from
            // find_generic_password.
            let status = unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) };
            if status != 0 {
                tracing::warn!(
                    "OAuth capture keychain delete failed \
                     (service={service:?} account={account:?} code={status})"
                );
            }
        }
        Err(e) if e.code() == -25300 => {} // errSecItemNotFound — already gone, expected
        Err(e) => {
            tracing::warn!(
                "OAuth capture keychain find-for-delete failed \
                 (service={service:?} account={account:?} code={})",
                e.code()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_json() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let store = serde_json::json!({"version": 1, "tokens": {}});
        let envelope = KeychainEnvelope {
            store: store.clone(),
            nono_path: Some("/opt/shadowfax/bin/nono".to_string()),
        };
        let raw = serde_json::to_string(&envelope)?;
        let decoded: KeychainEnvelope = serde_json::from_str(&raw)?;
        assert_eq!(
            decoded.nono_path.as_deref(),
            Some("/opt/shadowfax/bin/nono")
        );
        assert_eq!(decoded.store, store);
        Ok(())
    }

    #[test]
    fn missing_nono_path_deserialises_as_none()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let raw = r#"{"version":1,"tokens":{}}"#;
        let decoded: KeychainEnvelope = serde_json::from_str(raw)?;
        assert_eq!(decoded.nono_path, None);
        Ok(())
    }

    #[test]
    fn locked_keychain_message_names_operation_and_status() {
        let message = locked_keychain_message("load", "nono", "oauth_capture_store", -25308);
        assert!(message.contains("load"));
        assert!(message.contains("nono"));
        assert!(message.contains("oauth_capture_store"));
        assert!(message.contains("-25308"));
    }

    #[test]
    fn is_locked_keychain_status_matches_known_codes() {
        assert!(is_locked_keychain_status(-25308));
        assert!(is_locked_keychain_status(-25293));
        assert!(is_locked_keychain_status(-25304));
        assert!(!is_locked_keychain_status(-25300));
    }
}
