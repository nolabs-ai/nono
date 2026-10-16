//! macOS system trust store integration for nono's proxy CA.
//!
//! Persists the CA private key in macOS Keychain and the public cert in the
//! user trust store via Security.framework. Regenerates when expired.
//!
//! This enables Go CLI tools (`gh`, `terraform`, etc.) that ignore
//! `SSL_CERT_FILE` and only use `com.apple.trustd` for TLS verification.

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::date::CFDate;
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::string::CFString;
use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::OSStatus;
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::date::CFDateRef;
use core_foundation_sys::dictionary::CFDictionaryRef;
use nono::{NonoError, Result};
use nono_proxy::config::PreloadedCa;
use security_framework::certificate::SecCertificate;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::os::macos::access::SecAccess;
use security_framework::os::macos::keychain::SecKeychain;

use security_framework::os::macos::keychain_item::SecKeychainItem;
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
use security_framework_sys::base::{
    SecAccessRef, SecCertificateRef, SecKeychainItemRef, errSecDuplicateItem, errSecItemNotFound,
};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecReturnAttributes,
    kSecReturnData, kSecReturnPersistentRef, kSecReturnRef, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemUpdate};
use security_framework_sys::trust_settings::{SecTrustSettingsDomain, kSecTrustSettingsDomainUser};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, info, warn};
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroizing;

use crate::macos_ca_renewal::{BACKOFF_AFTER_FAILURE, RenewalLock};

/// Internal error type to distinguish user-cancelled trust prompts, and prompts
/// that couldn't be shown at all, from other failures without relying on string
/// matching.
enum TrustCertError {
    UserCancelled,
    /// No interactive session exists to show the prompt (e.g. a headless `nono
    /// proxy`). Unlike a decline, a later retry with the same session can't
    /// succeed either — only a new interactive session can.
    NoInteractionAvailable,
    Other(NonoError),
}

/// The result of a completed trust/rotate attempt, stripped of everything
/// that isn't relevant to deciding what happens next. `TrustCertError::Other`
/// (a genuine failure, not a user decision) never reaches this type — callers
/// propagate it with `?` before converting the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustAttemptOutcome {
    Trusted,
    Declined,
    NoInteraction,
}

/// What the launch/renewal path should do, decided purely from already-known
/// facts about the stored cert — no Keychain or Security-framework access.
/// This is the single seam both the lock-free fast check and the re-check
/// taken under the [`RenewalLock`] call, so a decline (or a renewal by
/// another process) recorded in the gap between the two is always honored:
/// see `try_ensure_trusted_ca`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenewalGate {
    /// Serve the stored cert as-is: it's Valid and trusted, or a recent
    /// decline is still in its backoff window and the stored cert still has
    /// life left to serve (untrusted, if this was a re-trust attempt).
    ServeStored,
    /// A recent decline is still in its backoff window and the stored cert
    /// has no life left to fall back on.
    ServeNone,
    /// Take the lock (if not already held) and attempt to re-trust (Valid,
    /// untrusted) or re-mint (RenewDue/Expired) the stored cert.
    Attempt,
}

fn renewal_gate(state: CertValidity, trusted: bool, backed_off: bool) -> RenewalGate {
    if state == CertValidity::Valid && trusted {
        return RenewalGate::ServeStored;
    }
    if backed_off {
        return if state == CertValidity::Expired {
            RenewalGate::ServeNone
        } else {
            RenewalGate::ServeStored
        };
    }
    RenewalGate::Attempt
}

/// Whether a completed attempt should record a backoff marker. Only an
/// affirmative decline throttles the next automatic retry (in this process or
/// any other); a missing interactive session is a per-session limitation, not
/// a decision to throttle future attempts.
fn should_record_backoff(outcome: TrustAttemptOutcome) -> bool {
    matches!(outcome, TrustAttemptOutcome::Declined)
}

/// What to hand back to the caller after a completed attempt, purely from the
/// outcome and the state the stored cert was in going into the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostAttemptAction {
    /// Trust succeeded: adopt whatever was just installed.
    AdoptNewlyTrusted,
    /// Declined (or no interactive session), but the previously stored cert
    /// still has life left: keep serving it.
    KeepStored,
    /// Declined (or no interactive session) and the previously stored cert
    /// has no life left to fall back on.
    Unavailable,
}

fn post_attempt_action(outcome: TrustAttemptOutcome, state: CertValidity) -> PostAttemptAction {
    match outcome {
        TrustAttemptOutcome::Trusted => PostAttemptAction::AdoptNewlyTrusted,
        TrustAttemptOutcome::Declined | TrustAttemptOutcome::NoInteraction => {
            if state == CertValidity::Expired {
                PostAttemptAction::Unavailable
            } else {
                PostAttemptAction::KeepStored
            }
        }
    }
}

fn trust_attempt_outcome(
    result: std::result::Result<(), TrustCertError>,
) -> Result<TrustAttemptOutcome> {
    match result {
        Ok(()) => Ok(TrustAttemptOutcome::Trusted),
        Err(TrustCertError::UserCancelled) => Ok(TrustAttemptOutcome::Declined),
        Err(TrustCertError::NoInteractionAvailable) => Ok(TrustAttemptOutcome::NoInteraction),
        Err(TrustCertError::Other(e)) => Err(e),
    }
}

// Service name for Keychain items. Sufficiently specific to avoid collision
// with other apps. Duplicate items are gated and updated in place (desired).
const KEYCHAIN_SERVICE: &str = "nono-proxy-ca";
const KEYCHAIN_ACCOUNT: &str = "ca-bundle";

// Fingerprint-keyed, so a marker from a since-rotated cert never suppresses
// renewal of the cert actually in use.
fn backoff_marker_path(fingerprint: &str) -> Result<PathBuf> {
    let dir = crate::state_paths::user_state_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        NonoError::SandboxInit(format!("cannot create state dir '{}': {e}", dir.display()))
    })?;
    Ok(dir.join(format!("proxy-ca-renewal-backoff-{fingerprint}")))
}

// Hashes the DER, not the PEM text, so re-encoding the same cert never changes the fingerprint.
fn cert_fingerprint(cert_pem: &str) -> Result<String> {
    let der = pem_to_der(cert_pem)?;
    let digest = Sha256::digest(&der);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn renewal_backed_off(cert_pem: &str) -> Result<bool> {
    let path = backoff_marker_path(&cert_fingerprint(cert_pem)?)?;
    let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
        return Ok(false);
    };
    let elapsed = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO);
    Ok(elapsed < BACKOFF_AFTER_FAILURE)
}

fn record_renewal_backoff(cert_pem: &str) -> Result<()> {
    let path = backoff_marker_path(&cert_fingerprint(cert_pem)?)?;
    std::fs::write(&path, []).map_err(|e| {
        NonoError::SandboxInit(format!(
            "cannot write renewal backoff marker '{}': {e}",
            path.display()
        ))
    })
}

// --- CA-bundle item access control ----------------------------------------
//
// The bundle is a generic-password item holding the interception CA's
// private key. Data-only updates never touch an item's access list: an
// item created without one (`SecItemAdd` without `kSecAttrAccess`)
// leaves every other process to prompt for each read, and macOS records
// the user's "Always Allow" grants in the very access list a naive
// rewrite would discard. All ACL work happens under the renewal lock, so
// exactly one process repairs at a time. Reads and writes are bound to
// the item reference the gate resolved and verified, so a replacement
// item cannot slip between the gate and the bytes.

/// How long a gated read waits for another process's repair or renewal to
/// release the lock before giving up. Failing closed (ephemeral CA) keeps
/// a launch from hanging on an unattended prompt elsewhere.
const ACCESS_GATE_WAIT: Duration = Duration::from_secs(60);

/// One repair attempt per window after a failed authorization, so a
/// machine where the repair keeps being declined isn't re-prompted on
/// every launch. Mirrors the renewal backoff cadence.
const ACCESS_REPAIR_BACKOFF: Duration = Duration::from_secs(6 * 3600);

fn access_repair_marker_path() -> Result<PathBuf> {
    let dir = crate::state_paths::user_state_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        NonoError::SandboxInit(format!("cannot create state dir '{}': {e}", dir.display()))
    })?;
    Ok(dir.join("proxy-ca-access-repair-backoff"))
}

fn access_repair_backed_off() -> Result<bool> {
    let path = access_repair_marker_path()?;
    let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
        return Ok(false);
    };
    let elapsed = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO);
    Ok(elapsed < ACCESS_REPAIR_BACKOFF)
}

fn record_access_repair_backoff() -> Result<()> {
    let path = access_repair_marker_path()?;
    std::fs::write(&path, []).map_err(|e| {
        NonoError::SandboxInit(format!(
            "cannot write access-repair backoff marker '{}': {e}",
            path.display()
        ))
    })
}

/// Marker file recording which CA item's access list was last verified (or
/// established). Reading an item's access list with
/// `SecKeychainItemCopyAccess` prompts for non-Apple-anchored binaries even
/// when the caller is in the access list, so launches cannot verify on
/// every start; they consult this marker instead and only take the renewal
/// lock (prompting at most once, machine-wide) when the item changed since
/// the last verification. The item is identified by its creation date
/// together with its persistent reference: creation dates have second
/// resolution, so a replacement created in the same second would otherwise
/// inherit the marker, while the reference is unique to the item instance.
/// Data-only updates change neither, so renewals never invalidate it.
///
/// The marker is keyed by item, not by binary. A different binary that
/// arrives while the marker is fresh skips the verifying read deliberately:
/// its grant is the user's call (the platform prompts once for the data
/// read, or the launch fails closed when unattended) rather than the binary
/// editing the access list to admit itself.
const ACL_STATE_MARKER: &str = "proxy-ca-acl-state";

/// The access-management policy the marker was written under. Kept as a
/// marker line so the format can distinguish policies without a format
/// change if one is ever introduced.
const ACL_STATE_POLICY_ID: &str = "preserve";

/// What the ACL state marker keys on: the item's creation-date epoch and
/// the hex of its persistent reference, read from the item itself so the
/// marker and the verified item can never disagree.
struct ItemIdentity {
    epoch: f64,
    persistent_ref: String,
}

fn acl_state_marker_path() -> Result<PathBuf> {
    let dir = crate::state_paths::user_state_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        NonoError::SandboxInit(format!("cannot create state dir '{}': {e}", dir.display()))
    })?;
    Ok(dir.join(ACL_STATE_MARKER))
}

/// Whether a stored marker still covers this item and policy. Pure so the
/// matching rules can be unit-tested.
fn marker_matches(stored: Option<&str>, item: &ItemIdentity, policy_id: &str) -> bool {
    let Some(content) = stored else { return false };
    let Some((epoch_str, rest)) = content.split_once('\n') else {
        return false;
    };
    let Some((ref_str, policy_str)) = rest.split_once('\n') else {
        return false;
    };
    let Ok(stored_epoch) = epoch_str.trim().parse::<f64>() else {
        return false;
    };
    stored_epoch == item.epoch
        && ref_str.trim() == item.persistent_ref
        && policy_str.trim_end_matches(['\n', '\r']) == policy_id
}

fn acl_state_marker_satisfied(item: &ItemIdentity) -> bool {
    let Ok(path) = acl_state_marker_path() else {
        return false;
    };
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    marker_matches(Some(&content), item, ACL_STATE_POLICY_ID)
}

fn write_acl_state_marker(item: &ItemIdentity) -> Result<()> {
    let path = acl_state_marker_path()?;
    std::fs::write(
        &path,
        format!(
            "{}\n{}\n{ACL_STATE_POLICY_ID}",
            item.epoch, item.persistent_ref
        ),
    )
    .map_err(|e| {
        NonoError::SandboxInit(format!(
            "cannot write proxy-CA access state marker '{}': {e}",
            path.display()
        ))
    })
}

/// The shared query prefix for operations bound to one item: the item the
/// gate resolved (and verified), never whatever a fresh attribute search
/// would resolve to, so no read or write can land on a replacement item
/// this process never gated.
fn item_bound_query(item: &SecKeychainItem) -> CFMutableDictionary {
    // SAFETY: `CFRetain` on a valid reference so the array can own it.
    unsafe { core_foundation_sys::base::CFRetain(item.as_concrete_TypeRef() as CFTypeRef) };
    // SAFETY: the retain above made this a Create-rule reference.
    let item_cf =
        unsafe { CFType::wrap_under_create_rule(item.as_concrete_TypeRef() as CFTypeRef) };
    let items = CFArray::from_CFTypes(&[item_cf]);
    let mut query = CFMutableDictionary::from_CFType_pairs(&[]);
    let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
    let class_val = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    let items_key = unsafe { CFString::wrap_under_get_rule(acl_ffi::kSecMatchItemList) };
    query.add(&class_key.as_CFTypeRef(), &class_val.as_CFTypeRef());
    query.add(&items_key.as_CFTypeRef(), &items.as_CFTypeRef());
    query
}

/// The item's identity for the ACL state marker: creation-date epoch plus
/// persistent reference, read from the item itself in one bound query.
/// Reading them from the resolved reference keeps the marker and the
/// verified item from ever disagreeing.
fn item_identity(item: &SecKeychainItem) -> Result<ItemIdentity> {
    let mut query = item_bound_query(item);
    let attrs_key = unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) };
    query.add(
        &attrs_key.as_CFTypeRef(),
        &CFBoolean::true_value().as_CFTypeRef(),
    );
    let ref_req_key = unsafe { CFString::wrap_under_get_rule(kSecReturnPersistentRef) };
    query.add(
        &ref_req_key.as_CFTypeRef(),
        &CFBoolean::true_value().as_CFTypeRef(),
    );
    let mut out: CFTypeRef = std::ptr::null_mut();
    // SAFETY: `query` is a valid CFMutableDictionaryRef; `out` receives a
    // Create-rule reference on success.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut out) };
    if status != 0 || out.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "cannot read the proxy-CA item's identity (OSStatus {status})"
        )));
    }
    // SAFETY: `out` is a Create-rule CFDictionary of the item's attributes.
    let dict =
        unsafe { CFDictionary::<CFString, CFType>::wrap_under_create_rule(out as CFDictionaryRef) };
    let creation_key = unsafe { CFString::wrap_under_get_rule(acl_ffi::kSecAttrCreationDate) };
    let ref_attr_key = unsafe { CFString::wrap_under_get_rule(acl_ffi::kSecValuePersistentRef) };
    let (keys, values) = dict.get_keys_and_values();
    let mut epoch = None;
    let mut persistent_ref = None;
    for (k, v) in keys.iter().zip(values.iter()) {
        let key = unsafe { CFString::wrap_under_get_rule((*k).cast()) };
        if key == creation_key {
            // kSecAttrCreationDate is a CFDate for generic passwords; the
            // type check keeps a malformed result from misreading memory.
            if unsafe { core_foundation_sys::base::CFGetTypeID(*v) } != CFDate::type_id() {
                continue;
            }
            let date = unsafe { CFDate::wrap_under_get_rule(*v as CFDateRef) };
            epoch = Some(date.abs_time());
        } else if key == ref_attr_key {
            // kSecValuePersistentRef comes back as CFData; same type-check
            // discipline as the date above.
            if unsafe { core_foundation_sys::base::CFGetTypeID(*v) } != CFData::type_id() {
                continue;
            }
            let data = unsafe { CFData::wrap_under_get_rule(*v as CFDataRef) };
            persistent_ref = Some(data.bytes().iter().map(|b| format!("{b:02x}")).collect());
        }
    }
    match (epoch, persistent_ref) {
        (Some(epoch), Some(persistent_ref)) => Ok(ItemIdentity {
            epoch,
            persistent_ref,
        }),
        _ => Err(NonoError::SandboxInit(
            "the proxy-CA keychain item carries no creation date or persistent reference"
                .to_string(),
        )),
    }
}

/// Read the CA bundle's bytes from exactly this item: the reference the
/// gate verified. Attribute-based reads could resolve to a replacement
/// item whose access list this process never verified. `Ok(None)` means
/// the item was definitively deleted (the reference went stale between
/// the gate and this read); every other failure, an authorization denial
/// above all, stays an error so callers fail closed instead of treating
/// an unreadable item as absent.
fn read_item_data(item: &SecKeychainItem) -> Result<Option<Vec<u8>>> {
    let mut query = item_bound_query(item);
    let data_key = unsafe { CFString::wrap_under_get_rule(kSecReturnData) };
    query.add(
        &data_key.as_CFTypeRef(),
        &CFBoolean::true_value().as_CFTypeRef(),
    );
    let mut out: CFTypeRef = std::ptr::null_mut();
    // SAFETY: `query` is a valid CFMutableDictionaryRef; `out` receives a
    // Create-rule reference on success.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut out) };
    if status == errSecItemNotFound {
        return Ok(None);
    }
    if status != 0 || out.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "cannot read the proxy-CA bundle from Keychain (OSStatus {status})"
        )));
    }
    // SAFETY: `out` is a Create-rule CFData holding the bundle's bytes.
    let data =
        unsafe { CFData::wrap_under_create_rule(out as core_foundation_sys::data::CFDataRef) };
    Ok(Some(data.bytes().to_vec()))
}

/// Replace the item's data through the verified reference. Data-only, so
/// the access list and the creation date the ACL state marker keys on
/// survive the update.
fn update_item_data(item: &SecKeychainItem, data: &[u8]) -> Result<()> {
    let query = item_bound_query(item);
    let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
    let data_val = CFData::from_buffer(data);
    let mut update = CFMutableDictionary::from_CFType_pairs(&[]);
    update.add(&data_key.as_CFTypeRef(), &data_val.as_CFTypeRef());
    // SAFETY: both dictionaries are valid for the duration of the call.
    let status =
        unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
    if status != 0 {
        return Err(NonoError::SandboxInit(format!(
            "failed to update the proxy-CA bundle in Keychain (OSStatus {status})"
        )));
    }
    Ok(())
}

// Keychain ACL APIs `security-framework` does not wrap.
mod acl_ffi {
    use core_foundation::array::CFArrayRef;
    use core_foundation::base::OSStatus;
    use core_foundation::data::CFDataRef;
    use core_foundation::string::CFStringRef;
    use security_framework_sys::base::{SecAccessRef, SecKeychainItemRef};

    /// Opaque CF type for a trusted-application record.
    pub type SecTrustedApplicationRef = *mut std::ffi::c_void;
    /// Opaque CF type for one ACL entry.
    pub type SecACLRef = *mut std::ffi::c_void;
    /// `SecKeychainPromptSelector` (`CF_OPTIONS(uint16, ...)` in SecACL.h).
    pub type SecKeychainPromptSelector = u16;
    /// `CSSM_ACL_AUTHORIZATION_TAG` (`int` in SecACL.h): the CSSM_WORDID_*
    /// values, 24 decrypt and 35 encrypt among them, plus Apple's
    /// vendor-defined tags from 65536 (change ACL) up.
    pub type AclAuthorizationTag = i32;
    /// The only authorization a standard keychain item hands to every
    /// application: the app-less encrypt entry. Any other tag on an
    /// any-application entry leaves the secret itself unrestricted.
    pub const ACL_AUTHORIZATION_ENCRYPT: AclAuthorizationTag = 35;
    /// The authorization that reveals the stored secret; an entry carrying
    /// it gates the item's data, and only such entries' records count as
    /// grants.
    pub const ACL_AUTHORIZATION_DECRYPT: AclAuthorizationTag = 24;
    /// The remaining data-rights tags observed on the secret-gating entry
    /// of a real generic-password item (derive, both exports, MAC, sign).
    /// An application may hold these together with decrypt on a canonical
    /// item; anything else, change-acl (65536) above all, it may not.
    ///
    /// Whether the tag belongs to the observed data-rights set that the
    /// secret-gating entry of a real item carries: decrypt, derive, both
    /// exports, MAC, sign.
    pub fn is_data_right(tag: AclAuthorizationTag) -> bool {
        matches!(tag, 24 | 28 | 37 | 38 | 59 | 115)
    }
    /// Whether the tag extracts the stored secret from the item: both
    /// exports, clear (37) and wrapped (38).
    pub fn is_export_right(tag: AclAuthorizationTag) -> bool {
        matches!(tag, 37 | 38)
    }
    /// Whether the tag reveals the stored secret itself: decrypt reads
    /// it, and either export extracts it.
    pub fn is_secret_right(tag: AclAuthorizationTag) -> bool {
        tag == ACL_AUTHORIZATION_DECRYPT || is_export_right(tag)
    }

    unsafe extern "C" {
        pub fn SecTrustedApplicationCreateFromPath(
            path: *const std::ffi::c_char,
            app: *mut SecTrustedApplicationRef,
        ) -> OSStatus;
        pub fn SecAccessCreate(
            descriptor: CFStringRef,
            trustedlist: CFArrayRef,
            access: *mut SecAccessRef,
        ) -> OSStatus;
        pub fn SecKeychainItemCopyAccess(
            item: SecKeychainItemRef,
            access: *mut SecAccessRef,
        ) -> OSStatus;
        pub fn SecKeychainItemSetAccess(item: SecKeychainItemRef, access: SecAccessRef)
        -> OSStatus;
        pub fn SecAccessCopyACLList(access: SecAccessRef, acls: *mut CFArrayRef) -> OSStatus;
        /// `SecACLCopyTrustedApplications` was removed from the framework;
        /// this is the supported way to read an entry's application list.
        pub fn SecACLCopyContents(
            acl: SecACLRef,
            application_list: *mut CFArrayRef,
            description: *mut CFStringRef,
            prompt_selector: *mut SecKeychainPromptSelector,
        ) -> OSStatus;
        /// Caller-provided tag buffer with in/out capacity (`int *` per
        /// SecACL.h); entries hold a handful of tags, so 32 slots bound it
        /// far above the enum's range.
        pub fn SecACLGetAuthorizations(
            acl: SecACLRef,
            tags: *mut AclAuthorizationTag,
            tag_count: *mut u32,
        ) -> OSStatus;
        pub fn SecTrustedApplicationCopyData(
            app: SecTrustedApplicationRef,
            data: *mut CFDataRef,
        ) -> OSStatus;
        /// Attribute key attaching a `SecAccessRef` to a new item in
        /// `SecItemAdd` (legacy Keychain Services attribute).
        pub static kSecAttrAccess: CFStringRef;
        /// Creation-date attribute key of SecItem results; a CFDate.
        pub static kSecAttrCreationDate: CFStringRef;
        /// Result-dictionary key under which `SecItemCopyMatching` returns
        /// the persistent reference when `kSecReturnPersistentRef` is set;
        /// a CFData unique to the item instance. Not exposed by the
        /// security-framework crate.
        pub static kSecValuePersistentRef: CFStringRef;
        /// Query key selecting the exact items named by the query instead
        /// of searching, so a read or update lands on the item the gate
        /// verified and never on whatever a fresh search would resolve to.
        pub static kSecMatchItemList: CFStringRef;

    }
}

/// An owned `SecTrustedApplicationRef` (Create rule, released on drop)
/// together with its requirement bytes, copied out once so every access
/// decision is a plain byte comparison.
struct TrustedAppRecord {
    app: CFType,
    data: Vec<u8>,
}

fn trusted_app_data(app: acl_ffi::SecTrustedApplicationRef) -> Result<Vec<u8>> {
    let mut data: core_foundation_sys::data::CFDataRef = std::ptr::null_mut();
    // SAFETY: `app` is a valid reference; `data` is an out-param receiving
    // a Create-rule reference on success.
    let status = unsafe { acl_ffi::SecTrustedApplicationCopyData(app, &mut data) };
    if status != 0 || data.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "cannot copy a trusted-application record (OSStatus {status})"
        )));
    }
    // SAFETY: `data` is a Create-rule reference.
    let cf_data = unsafe { CFData::wrap_under_create_rule(data) };
    Ok(cf_data.bytes().to_vec())
}

/// The running binary's trusted-application record.
fn current_trusted_application() -> Result<TrustedAppRecord> {
    let exe = std::env::current_exe().map_err(|e| {
        NonoError::SandboxInit(format!("cannot resolve the running binary's path: {e}"))
    })?;
    let path =
        std::ffi::CString::new(exe.as_os_str().as_encoded_bytes().to_vec()).map_err(|e| {
            NonoError::SandboxInit(format!("running binary path is not C-representable: {e}"))
        })?;
    let mut app: acl_ffi::SecTrustedApplicationRef = std::ptr::null_mut();
    // SAFETY: `path` is a valid NUL-terminated C string for the duration of
    // the call; `app` is an out-param receiving a Create-rule reference on
    // success.
    let status = unsafe { acl_ffi::SecTrustedApplicationCreateFromPath(path.as_ptr(), &mut app) };
    if status != 0 || app.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "SecTrustedApplicationCreateFromPath failed for the running binary (OSStatus {status})"
        )));
    }
    // SAFETY: `app` is a Create-rule reference on success, wrapped before
    // any fallible work so an error path releases it.
    let owned = unsafe { CFType::wrap_under_create_rule(app as CFTypeRef) };
    let data = trusted_app_data(app)?;
    Ok(TrustedAppRecord { app: owned, data })
}

/// Find the CA-bundle generic-password item. Metadata search only: no data
/// access, so no prompt.
fn find_ca_bundle_item() -> Result<Option<SecKeychainItem>> {
    let results = match ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(KEYCHAIN_SERVICE)
        .account(KEYCHAIN_ACCOUNT)
        .load_refs(true)
        .limit(Limit::Max(1))
        .search()
    {
        Ok(results) => results,
        // Nothing stored yet on this machine: the create path attaches the
        // access list at SecItemAdd time.
        Err(e) if e.code() == errSecItemNotFound => return Ok(None),
        Err(e) => {
            return Err(NonoError::SandboxInit(format!(
                "keychain search for the CA bundle failed: {e}"
            )));
        }
    };
    Ok(results.into_iter().find_map(|result| match result {
        SearchResult::Ref(Reference::KeychainItem(item)) => Some(item),
        _ => None,
    }))
}

/// One copied ACL entry: its trusted applications, whether its
/// application list was absent (an any-application grant, versus a list
/// that merely names no applications) and the authorization tags it gates.
struct AclEntry {
    apps: Vec<TrustedAppRecord>,
    any_application: bool,
    tags: Vec<acl_ffi::AclAuthorizationTag>,
}

/// The verify/repair flow's classification of keychain failures, so an
/// unavailable interaction never rate-limits the whole machine.
enum ItemAccessError {
    /// errSecInteractionNotAllowed: no interactive session exists to show
    /// the authorization prompt. Nobody declined anything, and a later
    /// interactive launch can still be asked.
    NoInteraction,
    Other(NonoError),
}

impl ItemAccessError {
    /// Only a declined authorization or a genuinely broken keychain backs
    /// the machine off; an unavailable interaction must not.
    fn should_back_off(&self) -> bool {
        !matches!(self, Self::NoInteraction)
    }
}

fn item_access_call_failed(what: &str, status: i32) -> ItemAccessError {
    if status == ERR_SEC_INTERACTION_NOT_ALLOWED {
        ItemAccessError::NoInteraction
    } else {
        ItemAccessError::Other(NonoError::SandboxInit(format!(
            "cannot {what} (OSStatus {status})"
        )))
    }
}

/// Copy the item's access list and reduce it to per-entry owned records.
fn collect_item_access(
    item: &SecKeychainItem,
) -> std::result::Result<Vec<AclEntry>, ItemAccessError> {
    let mut access: SecAccessRef = std::ptr::null_mut();
    // SAFETY: `item` is a valid SecKeychainItemRef; `access` is an out-param
    // receiving a Create-rule reference on success.
    let status =
        unsafe { acl_ffi::SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &mut access) };
    if status != 0 || access.is_null() {
        return Err(item_access_call_failed(
            "read the proxy-CA item's access list",
            status,
        ));
    }
    // SAFETY: `access` is a Create-rule reference.
    let access = unsafe { SecAccess::wrap_under_create_rule(access) };

    let mut acl_list: CFArrayRef = std::ptr::null_mut();
    // SAFETY: `access` is valid; `acl_list` is an out-param receiving a
    // Create-rule reference on success.
    let status =
        unsafe { acl_ffi::SecAccessCopyACLList(access.as_concrete_TypeRef(), &mut acl_list) };
    if status != 0 || acl_list.is_null() {
        return Err(ItemAccessError::Other(NonoError::SandboxInit(format!(
            "cannot enumerate the proxy-CA item's ACL entries (OSStatus {status})"
        ))));
    }
    // SAFETY: `acl_list` is a Create-rule reference.
    let acl_list = unsafe { CFArray::<CFType>::wrap_under_create_rule(acl_list) };

    let mut entries = Vec::new();
    for index in 0..acl_list.len() {
        // A NULL slot in the copied list (never expected): abort rather
        // than fold a partial view into the plan, since a rebuild driven
        // by incomplete facts could drop grants this process never saw.
        let Some(acl) = acl_list.get(index) else {
            return Err(ItemAccessError::Other(NonoError::SandboxInit(
                "the proxy-CA item's access list could not be copied completely".to_string(),
            )));
        };
        let acl_ref = acl.as_concrete_TypeRef() as acl_ffi::SecACLRef;
        let mut apps: CFArrayRef = std::ptr::null_mut();
        let mut description: core_foundation::string::CFStringRef = std::ptr::null();
        let mut prompt_selector: acl_ffi::SecKeychainPromptSelector = 0;
        // SAFETY: `acl_ref` came from the copied ACL list; the out-params
        // receive Create-rule references on success.
        let status = unsafe {
            acl_ffi::SecACLCopyContents(acl_ref, &mut apps, &mut description, &mut prompt_selector)
        };
        // The description is a byproduct we don't use.
        if !description.is_null() {
            // SAFETY: Create-rule reference from the call above.
            unsafe { core_foundation_sys::base::CFRelease(description as CFTypeRef) };
        }
        if status != 0 {
            // An entry macOS won't enumerate aborts the whole copy: a
            // rebuild must never run on partial facts.
            return Err(ItemAccessError::Other(NonoError::SandboxInit(format!(
                "cannot read an entry of the proxy-CA item's access list (OSStatus {status})"
            ))));
        }
        // SAFETY: `apps` is a Create-rule reference, wrapped before any
        // fallible work so an error path releases it. A null list grants
        // the entry's authorizations to every application; the standard
        // item keeps only the harmless encrypt entry in that shape.
        let apps = if apps.is_null() {
            None
        } else {
            Some(unsafe { CFArray::<CFType>::wrap_under_create_rule(apps) })
        };
        let tags = entry_authorizations(acl_ref).map_err(ItemAccessError::Other)?;
        let Some(apps) = apps else {
            entries.push(AclEntry {
                apps: Vec::new(),
                any_application: true,
                tags,
            });
            continue;
        };
        let mut records = Vec::new();
        for app_index in 0..apps.len() {
            let Some(record) = apps.get(app_index) else {
                continue;
            };
            let app_ref = record.as_concrete_TypeRef() as acl_ffi::SecTrustedApplicationRef;
            if app_ref.is_null() {
                continue;
            }
            let data = trusted_app_data(app_ref).map_err(ItemAccessError::Other)?;
            // SAFETY: `CFRetain` on a valid reference so the record outlives
            // the borrowed array; the wrapper releases it on drop.
            unsafe { core_foundation_sys::base::CFRetain(app_ref as CFTypeRef) };
            // SAFETY: the retain above made this a Create-rule reference.
            let owned = unsafe { CFType::wrap_under_create_rule(app_ref as CFTypeRef) };
            records.push(TrustedAppRecord { app: owned, data });
        }
        entries.push(AclEntry {
            apps: records,
            any_application: false,
            tags,
        });
    }
    Ok(entries)
}

/// Copy one entry's authorization tags. A non-zero status aborts the whole
/// verification like the other entry reads: a rebuild must never run on
/// partial facts, and the tags decide whether an any-application entry is
/// harmless.
fn entry_authorizations(acl: acl_ffi::SecACLRef) -> Result<Vec<acl_ffi::AclAuthorizationTag>> {
    const MAX_TAGS: usize = 32;
    let mut tags = [0 as acl_ffi::AclAuthorizationTag; MAX_TAGS];
    let mut count: u32 = MAX_TAGS as u32;
    // SAFETY: `acl` came from the copied ACL list; `tags` has room for the
    // full in/out capacity declared to the call.
    let status = unsafe { acl_ffi::SecACLGetAuthorizations(acl, tags.as_mut_ptr(), &mut count) };
    if status != 0 || count as usize > MAX_TAGS {
        return Err(NonoError::SandboxInit(format!(
            "cannot read the authorizations of an access-list entry (OSStatus {status})"
        )));
    }
    Ok(tags[..count as usize].to_vec())
}

/// Decision about the item's access list, computed from copied facts.
enum AccessPlan {
    /// The list already has its canonical shape: nothing to do, no prompt.
    Canonical,
    /// Rebuild. `keep` holds the requirement bytes of the existing records
    /// that gate the secret; the running binary's own record is always
    /// added on top by the caller.
    Rebuild { keep: Vec<Vec<u8>> },
}

/// One entry of a copied access list, reduced to what the plan decides on:
/// the applications an entry names by their requirement bytes together
/// with the authorizations it grants them, or, when the entry names no
/// application list at all, the authorization tags it hands to every
/// application.
enum PlanEntry {
    /// Names applications (possibly none: an empty list grants nothing)
    /// holding these authorization tags.
    Named {
        tags: Vec<acl_ffi::AclAuthorizationTag>,
        apps: Vec<Vec<u8>>,
    },
    /// Grants every application these authorization tags.
    Any(Vec<acl_ffi::AclAuthorizationTag>),
}

impl PlanEntry {
    fn named(tags: Vec<acl_ffi::AclAuthorizationTag>, apps: Vec<Vec<u8>>) -> Self {
        PlanEntry::Named { tags, apps }
    }
}

/// Whether an entry's authorizations include revealing the stored secret:
/// decrypt reads it, and either export extracts it. Records on such
/// entries are grants of the secret itself; records held only for
/// harmless rights (encrypt) grant nothing and must never be promoted
/// onto the secret-gating entry by a rebuild.
fn gates_secret(tags: &[acl_ffi::AclAuthorizationTag]) -> bool {
    tags.iter().any(|tag| acl_ffi::is_secret_right(*tag))
}

/// Whether a named entry may grant this right to an application and still
/// count as canonical: the standard encrypt right and the data rights. A
/// named application holding anything else (change-acl above all, which
/// could rewrite the list and grant itself the secret) forces a rebuild,
/// even when the entry also gates the secret.
fn canonical_named_right(tag: acl_ffi::AclAuthorizationTag) -> bool {
    tag == acl_ffi::ACL_AUTHORIZATION_ENCRYPT || acl_ffi::is_data_right(tag)
}

/// Pure decision over the item's current access list. `current` is the
/// running binary's own requirement bytes.
///
/// Every keychain item carries standard entries that never gate the secret
/// (the any-application encrypt entry, the empty-listed change-acl entry),
/// and records only ever appear on the entry that does gate it: macOS
/// grants and repairs all land there. So an access list where no
/// secret-gating entry carries any record is one where no application is
/// pre-authorized and every read prompts: the state this fix exists to
/// repair away. An any-application entry is harmless only while it gates
/// nothing but the standard encrypt right; a decrypt or export tag on one
/// leaves the secret readable by every application, so it always forces a
/// rebuild. A named entry may name applications only for the standard
/// encrypt right and the data rights; any other right handed to a named
/// application (change-acl above all) forces a rebuild too: that
/// application could rewrite the list and grant itself the secret. Rebuilds
/// keep records only from secret-gating entries, so a record held for
/// harmless rights alone is dropped rather than promoted.
fn plan_item_access(entries: &[PlanEntry], current: &[u8]) -> AccessPlan {
    let granted = |apps: &Vec<Vec<u8>>| !apps.is_empty();
    let mut union: Vec<&[u8]> = Vec::new();
    let mut any_granted = false;
    for entry in entries {
        let PlanEntry::Named { tags, apps } = entry else {
            continue;
        };
        if !gates_secret(tags) {
            continue;
        }
        any_granted = any_granted || granted(apps);
        for data in apps {
            if !union.contains(&data.as_slice()) {
                union.push(data.as_slice());
            }
        }
    }
    let contains_current = union.contains(&current);
    let appless_harmless = entries.iter().all(|entry| match entry {
        PlanEntry::Any(tags) => tags
            .iter()
            .all(|tag| *tag == acl_ffi::ACL_AUTHORIZATION_ENCRYPT),
        PlanEntry::Named { .. } => true,
    });
    let named_harmless = entries.iter().all(|entry| match entry {
        PlanEntry::Named { tags, apps } => {
            apps.is_empty() || tags.iter().all(|tag| canonical_named_right(*tag))
        }
        PlanEntry::Any(_) => true,
    });
    let harmless = appless_harmless && named_harmless;
    if any_granted && contains_current && harmless {
        AccessPlan::Canonical
    } else {
        AccessPlan::Rebuild {
            keep: union.iter().map(|existing| existing.to_vec()).collect(),
        }
    }
}

/// Verify the item's access list has its canonical shape, rebuilding it
/// when it doesn't, and record the outcome in the ACL state marker. The
/// caller must be the renewal-lock holder (the gate below, a renewal, or a
/// sweep): exactly one process repairs at a time, and the others wait for
/// that holder instead of prompting independently. The marker write is what
/// lets later launches skip this prompting read entirely.
fn verify_or_repair_item_access(item: &SecKeychainItem, identity: &ItemIdentity) -> Result<()> {
    let result: std::result::Result<(), ItemAccessError> = (|| {
        let entries = collect_item_access(item)?;
        let current = current_trusted_application().map_err(ItemAccessError::Other)?;
        let facts: Vec<PlanEntry> = entries
            .iter()
            .map(|entry| {
                if entry.any_application {
                    PlanEntry::Any(entry.tags.clone())
                } else {
                    PlanEntry::named(
                        entry.tags.clone(),
                        entry.apps.iter().map(|app| app.data.clone()).collect(),
                    )
                }
            })
            .collect();
        match plan_item_access(&facts, &current.data) {
            AccessPlan::Canonical => Ok(()),
            AccessPlan::Rebuild { keep } => rebuild_item_access(item, entries, current, &keep),
        }
    })();
    if let Err(e) = &result {
        // A failed attempt must not become a prompt per launch: back the
        // whole machine off for the window. An unavailable interaction is
        // excluded: nobody declined, and a later interactive launch can
        // still be asked.
        if e.should_back_off() {
            let _ = record_access_repair_backoff();
        }
    }
    match result {
        Err(ItemAccessError::NoInteraction) => {
            return Err(NonoError::SandboxInit(
                "no interactive session is available to verify the proxy-CA item's \
                 access list; no authorization was declined"
                    .to_string(),
            ));
        }
        Err(ItemAccessError::Other(e)) => return Err(e),
        Ok(()) => {}
    }
    // Verification (or repair) succeeded: record this item as settled so
    // launches skip the prompting access-list read until the item is
    // recreated. The identity is the one this process read from this
    // exact item before verifying it, so the marker can only ever bless
    // that item: a replacement carries a different persistent reference,
    // leaves the marker unsatisfied, and forces the next launch to verify
    // from scratch.
    if let Err(e) = write_acl_state_marker(identity) {
        // Without the marker every launch would repeat the prompting
        // verification, so back off like a failed attempt. A state dir too
        // broken to record this either fails the renewal lock first (no
        // verification, no prompt) or leaves serialized, wait-bounded
        // verifies as the floor: the lock still prevents simultaneous
        // prompts, and no other channel exists to record state in.
        let _ = record_access_repair_backoff();
        return Err(e);
    }
    Ok(())
}

/// Replace the item's access list with the canonical set: the surviving
/// records named by `keep` plus the running binary. May prompt once for
/// authorization on machines whose item predates ACL-aware nono; the
/// caller holds the renewal lock, so that prompt is bounded to one
/// process at a time.
fn rebuild_item_access(
    item: &SecKeychainItem,
    entries: Vec<AclEntry>,
    current: TrustedAppRecord,
    keep: &[Vec<u8>],
) -> std::result::Result<(), ItemAccessError> {
    let mut available: Vec<TrustedAppRecord> =
        entries.into_iter().flat_map(|entry| entry.apps).collect();
    let mut selected: Vec<TrustedAppRecord> = Vec::new();
    for data in keep {
        if let Some(pos) = available.iter().position(|app| app.data == *data) {
            selected.push(available.swap_remove(pos));
        }
    }
    // The keep set names the running binary whenever the item already
    // granted it, so add the current record only when the selection does
    // not already carry these bytes: a rebuild must never install
    // duplicate records.
    if !selected.iter().any(|app| app.data == current.data) {
        match available.iter().position(|app| app.data == current.data) {
            Some(pos) => selected.push(available.swap_remove(pos)),
            None => selected.push(current),
        }
    }
    let records: Vec<CFType> = selected.iter().map(|app| app.app.clone()).collect();
    replace_item_access(item, &records)
}

/// Build a fresh `SecAccess` over `records` and install it on the item.
fn replace_item_access(
    item: &SecKeychainItem,
    records: &[CFType],
) -> std::result::Result<(), ItemAccessError> {
    let descriptor = CFString::new("nono proxy CA bundle");
    let trusted_list = CFArray::from_CFTypes(records);
    let mut access: SecAccessRef = std::ptr::null_mut();
    // SAFETY: `descriptor` and `trusted_list` are valid for the duration of
    // the call; `access` is an out-param receiving a Create-rule reference
    // on success.
    let status = unsafe {
        acl_ffi::SecAccessCreate(
            descriptor.as_concrete_TypeRef(),
            trusted_list.as_concrete_TypeRef(),
            &mut access,
        )
    };
    if status != 0 || access.is_null() {
        return Err(ItemAccessError::Other(NonoError::SandboxInit(format!(
            "cannot build a replacement access list for the proxy-CA item (OSStatus {status})"
        ))));
    }
    // SAFETY: `access` is a Create-rule reference.
    let access = unsafe { SecAccess::wrap_under_create_rule(access) };
    // SAFETY: both references are valid for the duration of the call.
    let status = unsafe {
        acl_ffi::SecKeychainItemSetAccess(item.as_concrete_TypeRef(), access.as_concrete_TypeRef())
    };
    if status != 0 {
        return Err(item_access_call_failed(
            "install the repaired access list on the proxy-CA item",
            status,
        ));
    }
    info!("Repaired the proxy-CA keychain item's access list to its canonical form");
    Ok(())
}

/// Gate every read and write of the CA bundle: make the item's access list
/// canonical before the first byte is read, so a burst of concurrent
/// launches can't turn into a burst of per-process prompts. Returns the
/// gated item's reference: callers read and write through it, bound to the
/// exact item this gate verified, so a replacement item can never slip
/// between the gate and the bytes.
///
/// Reading the access list itself prompts (securityd gates the owner read
/// for non-Apple binaries even when the caller is in the list), so
/// verification is keyed to the ACL state marker: while the marker says the
/// current item was last verified, the gated read proceeds straight to the
/// data. When it doesn't, one process takes the renewal lock and verifies
/// or repairs for everyone; the others wait up to [`ACCESS_GATE_WAIT`]
/// instead of prompting independently, then fail closed. Calls from a
/// thread that already holds the lock (renewal, sweep, the launch
/// re-check) verify in place, since a second exclusive flock from the same
/// process would block on itself.
fn ensure_bundle_access() -> Result<Option<SecKeychainItem>> {
    let Some(item) = find_ca_bundle_item()? else {
        // Nothing to gate yet: the create path attaches the access list
        // at SecItemAdd time.
        return Ok(None);
    };
    let identity = item_identity(&item)?;
    if acl_state_marker_satisfied(&identity) {
        // The last verification (or creation) still covers this item;
        // skip the prompting access-list read.
        return Ok(Some(item));
    }
    if access_repair_backed_off()? {
        return Err(NonoError::SandboxInit(
            "proxy-CA keychain access repair is rate-limited after a failed \
             authorization; will retry later"
                .to_string(),
        ));
    }
    if crate::macos_ca_renewal::renewal_lock_held_by_current_thread() {
        verify_or_repair_item_access(&item, &identity)?;
        return Ok(Some(item));
    }
    let deadline = Instant::now() + ACCESS_GATE_WAIT;
    loop {
        if access_repair_backed_off()? {
            // The lock holder we waited for failed its attempt; don't line
            // up behind it just to fail (or prompt) the same way.
            return Err(NonoError::SandboxInit(
                "proxy-CA keychain access repair is rate-limited after a failed \
                 authorization; will retry later"
                    .to_string(),
            ));
        }
        if acl_state_marker_satisfied(&identity) {
            // The holder verified or repaired while we waited; its work
            // covers this reader too.
            return Ok(Some(item));
        }
        match RenewalLock::acquire()? {
            Some(_lock) => {
                if acl_state_marker_satisfied(&identity) {
                    return Ok(Some(item));
                }
                // The previous holder may have failed and recorded the
                // backoff after this waiter's last check; re-read it under
                // the lock so its failure rate-limits this attempt too
                // instead of prompting again inside the window.
                if access_repair_backed_off()? {
                    return Err(NonoError::SandboxInit(
                        "proxy-CA keychain access repair is rate-limited after a failed \
                         authorization; will retry later"
                            .to_string(),
                    ));
                }
                verify_or_repair_item_access(&item, &identity)?;
                return Ok(Some(item));
            }
            None => {
                if Instant::now() >= deadline {
                    return Err(NonoError::SandboxInit(
                        "timed out waiting for another process to finish repairing the \
                         proxy-CA keychain item"
                            .to_string(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Store a freshly created CA bundle, attaching the canonical access list
/// at creation so the item is readable by the running binary from its
/// first moment, with no authorization prompt. An existing item (possible
/// when a concurrent creator raced us to the keychain before we took the
/// lock) is gated and updated in place; the item's access list is never
/// rewritten blind.
fn store_bundle_with_access(combined: &Zeroizing<String>) -> Result<()> {
    let current = current_trusted_application()?;
    // A concurrent creator's duplicate item is gated and updated through
    // the verified reference inside the create call below; the gate
    // records the marker there. Only the fresh-create path needs the
    // marker written here.
    if let Some(created) = replace_item_access_create(combined, &[current.app])? {
        // The access list was just established at creation; record the
        // item as settled so the first gated read (possibly one
        // of a concurrent burst of launches) skips the prompting
        // access-list read. The identity is read from the reference the
        // add returned, so the marker can only name the item this process
        // just created.
        let identity = item_identity(&created)?;
        write_acl_state_marker(&identity)?;
    }
    Ok(())
}

/// Store a freshly created CA bundle, attaching the canonical access list
/// at creation so the item is readable by the running binary from its
/// first moment, with no authorization prompt. An existing item (possible
/// when a concurrent creator raced us to the keychain before we took the
/// lock) is gated first, then updated in place, so the CA key is only ever
/// written through an access list this process verified. Returns the
/// created item's reference, or `None` when a duplicate was gated and
/// updated in place.
fn replace_item_access_create(
    combined: &Zeroizing<String>,
    records: &[CFType],
) -> Result<Option<SecKeychainItem>> {
    let descriptor = CFString::new("nono proxy CA bundle");
    let trusted_list = CFArray::from_CFTypes(records);
    let mut access: SecAccessRef = std::ptr::null_mut();
    // SAFETY: `descriptor` and `trusted_list` are valid for the duration of
    // the call; `access` is an out-param receiving a Create-rule reference
    // on success.
    let status = unsafe {
        acl_ffi::SecAccessCreate(
            descriptor.as_concrete_TypeRef(),
            trusted_list.as_concrete_TypeRef(),
            &mut access,
        )
    };
    if status != 0 || access.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "cannot build the access list for a new proxy-CA item (OSStatus {status})"
        )));
    }
    // SAFETY: `access` is a Create-rule reference.
    let access = unsafe { SecAccess::wrap_under_create_rule(access) };

    let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
    let class_val = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    let svc_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
    let svc_val = CFString::from(KEYCHAIN_SERVICE);
    let acct_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
    let acct_val = CFString::from(KEYCHAIN_ACCOUNT);
    let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
    let data_val = CFData::from_buffer(combined.as_bytes());
    let access_key = unsafe { CFString::wrap_under_get_rule(acl_ffi::kSecAttrAccess) };

    let mut query = CFMutableDictionary::from_CFType_pairs(&[]);
    query.add(&class_key.as_CFTypeRef(), &class_val.as_CFTypeRef());
    query.add(&svc_key.as_CFTypeRef(), &svc_val.as_CFTypeRef());
    query.add(&acct_key.as_CFTypeRef(), &acct_val.as_CFTypeRef());
    query.add(&data_key.as_CFTypeRef(), &data_val.as_CFTypeRef());
    query.add(&access_key.as_CFTypeRef(), &access.as_CFTypeRef());
    let ref_key = unsafe { CFString::wrap_under_get_rule(kSecReturnRef) };
    query.add(
        &ref_key.as_CFTypeRef(),
        &CFBoolean::true_value().as_CFTypeRef(),
    );
    let mut created: CFTypeRef = std::ptr::null_mut();
    // SAFETY: `query` is a valid CFMutableDictionaryRef; `created` receives
    // a Create-rule reference to the new item on success.
    let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), &mut created) };
    if status == errSecDuplicateItem {
        // The item appeared between the gated read and the add. Its
        // creator is unknown to this process, so verify (or repair) its
        // access list before writing the CA key through it; the caller
        // holds the renewal lock, which makes this an in-place verify.
        // A failure fails the create path closed rather than storing the
        // key in an item whose list this process could not vouch for.
        // The write goes through the reference the gate just verified, so
        // it can only land on the item that was verified.
        let item = ensure_bundle_access()?.ok_or_else(|| {
            NonoError::SandboxInit(
                "the proxy-CA keychain item disappeared during creation".to_string(),
            )
        })?;
        return update_item_data(&item, combined.as_bytes())
            .map(|_| None)
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "failed to store the proxy CA bundle in Keychain: {e}"
                ))
            });
    }
    if status != 0 || created.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "failed to create the proxy CA bundle in Keychain (OSStatus {status})"
        )));
    }
    // SAFETY: `created` is a Create-rule reference to the item this add
    // just made.
    let item = unsafe { SecKeychainItem::wrap_under_create_rule(created as SecKeychainItemRef) };
    Ok(Some(item))
}

/// Load or generate a shared CA and ensure it's trusted in the macOS user
/// trust store. Returns `Some(PreloadedCa)` on success, `None` if the user
/// cancelled the auth prompt or setup failed (fallback to ephemeral CA).
///
/// All logging happens internally — the caller just checks the Option.
pub(crate) fn load_or_generate_proxy_ca(validity: Duration) -> Option<PreloadedCa> {
    match try_ensure_trusted_ca(validity) {
        Ok(Some(ca)) => Some(ca),
        Ok(None) => None,
        Err(e) => {
            warn!("Shared CA setup failed: {e}. Falling back to ephemeral CA.");
            None
        }
    }
}

/// What `try_ensure_trusted_ca`'s lock-free fast check, and its re-check once
/// the lock is held, both decide from freshly re-read facts about the stored
/// cert — the thin, Security-framework-touching wrapper around the pure
/// [`renewal_gate`].
enum LaunchStep {
    Serve(PreloadedCa),
    ServeNone,
    Attempt,
}

fn launch_gate(key_der: &Zeroizing<Vec<u8>>, cert_pem: &str) -> Result<LaunchStep> {
    let state = cert_validity(cert_pem)?;
    let trusted = state == CertValidity::Valid && stored_cert_is_trusted(cert_pem)?;
    let backed_off = renewal_backed_off(cert_pem)?;
    Ok(match renewal_gate(state, trusted, backed_off) {
        RenewalGate::ServeStored => LaunchStep::Serve(PreloadedCa {
            key_der: key_der.clone(),
            cert_pem: cert_pem.to_string(),
        }),
        RenewalGate::ServeNone => LaunchStep::ServeNone,
        RenewalGate::Attempt => LaunchStep::Attempt,
    })
}

fn try_ensure_trusted_ca(validity: Duration) -> Result<Option<PreloadedCa>> {
    // Best-effort cleanup of stale `nono-proxy-ca` certs left by prior
    // rotations; a sweep failure must never block launch on the CA it's
    // actually there to serve.
    if let Err(e) = sweep_stale_ca_certs() {
        warn!("Stale-CA sweep failed (non-fatal): {e}");
    }

    let Some((key_der, cert_pem)) = load_existing_ca()? else {
        debug!("no existing proxy CA in Keychain; generating new one");
        return generate_new_trusted_ca(validity);
    };

    // Lock-free fast check: avoids taking the lock at all on the common paths
    // (already trusted, or a recent decline still in its backoff window).
    match launch_gate(&key_der, &cert_pem)? {
        LaunchStep::Serve(ca) => return Ok(Some(ca)),
        LaunchStep::ServeNone => return Ok(None),
        LaunchStep::Attempt => {}
    }

    // A prompt is on the table; serialize with any other process attempting
    // the same thing so at most one prompt happens machine-wide.
    let Some(_lock) = RenewalLock::acquire()? else {
        debug!("another process is acting on the proxy CA; serving current cert");
        return Ok(Some(PreloadedCa { key_der, cert_pem }));
    };

    // Re-read and re-decide now that the lock is held: another process may
    // have renewed, re-trusted, or recorded a decline in the gap between the
    // lock-free check above and actually acquiring the lock. This is the
    // fix for the marker/lock TOCTOU — the decision is never taken on the
    // stale, lock-free answer.
    let Some((key_der, cert_pem)) = load_existing_ca()? else {
        return generate_and_trust_new_ca(validity);
    };
    match launch_gate(&key_der, &cert_pem)? {
        LaunchStep::Serve(ca) => return Ok(Some(ca)),
        LaunchStep::ServeNone => return Ok(None),
        LaunchStep::Attempt => {}
    }

    let state = cert_validity(&cert_pem)?;
    if state == CertValidity::Valid {
        retrust_stored_ca(key_der, cert_pem)
    } else {
        match rotate_ca(&key_der, &cert_pem, validity, state)? {
            RotateOutcome::Cert(ca) => Ok(Some(ca)),
            RotateOutcome::NoInteraction { fallback } => Ok(fallback),
            RotateOutcome::Unavailable => Ok(None),
        }
    }
}

/// Re-trust an already-Valid stored cert in place, no re-mint. Shares the
/// `TrustAttemptOutcome`/`should_record_backoff`/`post_attempt_action` core
/// with [`rotate_ca`], so a decline here is throttled by the same backoff
/// marker (Fix 4) instead of re-prompting on every launch.
fn retrust_stored_ca(key_der: Zeroizing<Vec<u8>>, cert_pem: String) -> Result<Option<PreloadedCa>> {
    let cert_der = pem_to_der(&cert_pem)?;
    let cert = SecCertificate::from_der(&cert_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse stored CA cert: {e}")))?;

    info!("Re-trusting proxy CA (you may be prompted for authentication)...");
    let outcome = trust_attempt_outcome(trust_cert(&cert))?;

    if should_record_backoff(outcome) {
        record_renewal_backoff(&cert_pem)?;
    }

    match post_attempt_action(outcome, CertValidity::Valid) {
        // `state` is always `Valid` here, so `post_attempt_action` never
        // returns `Unavailable` — a declined re-trust always has a valid (if
        // untrusted) cert to keep serving (L2).
        PostAttemptAction::Unavailable => {
            unreachable!("post_attempt_action never returns Unavailable for CertValidity::Valid")
        }
        PostAttemptAction::AdoptNewlyTrusted => {
            info!("Proxy CA re-trusted successfully");
            Ok(Some(PreloadedCa { key_der, cert_pem }))
        }
        PostAttemptAction::KeepStored => {
            warn!(
                "Trust store auth cancelled or unavailable; continuing on the current \
                 certificate untrusted. Retry is rate-limited; it won't re-prompt on \
                 every launch."
            );
            Ok(Some(PreloadedCa { key_der, cert_pem }))
        }
    }
}

/// Generate a brand-new CA and trust it, under the same [`RenewalLock`] as
/// every other prompting path (Fix 5), so two processes racing to create the
/// very first CA don't both mint one and both prompt.
fn generate_new_trusted_ca(validity: Duration) -> Result<Option<PreloadedCa>> {
    let Some(_lock) = RenewalLock::acquire()? else {
        debug!("another process is creating the proxy CA; nothing to serve yet");
        return Ok(None);
    };
    // Someone may have created (and trusted) one while we waited for the lock.
    if let Some((key_der, cert_pem)) = load_existing_ca()? {
        return Ok(Some(PreloadedCa { key_der, cert_pem }));
    }
    generate_and_trust_new_ca(validity)
}

/// The CA shared through Keychain, as `(key DER, cert PEM)`. Gated like
/// every other read: the access repair runs before the first byte.
pub(crate) fn read_shared_ca() -> Result<Option<(Zeroizing<Vec<u8>>, String)>> {
    load_existing_ca()
}

/// Outcome of a mid-session renewal attempt via [`renew_shared_ca`].
pub(crate) enum RenewOutcome {
    /// A new certificate was installed.
    Renewed(PreloadedCa),
    /// Nothing changed: no stored CA, a declined prompt, or a failed trust
    /// write. Safe to retry later — the same session may succeed next time.
    Unchanged,
    /// No interactive session exists to show the trust prompt (e.g. a headless
    /// `nono proxy`). Retrying later in the same session can't succeed either.
    NoInteraction,
}

/// Re-issue the shared CA over its stored key and retire the previous certificate.
pub(crate) fn renew_shared_ca(validity: Duration) -> Result<RenewOutcome> {
    let Some((key_der, cert_pem)) = load_existing_ca()? else {
        return Ok(RenewOutcome::Unchanged);
    };
    // Shares `launch_gate`'s decision core: the marker is keyed to this exact
    // cert and shared across processes, so a supervisor that hasn't itself
    // seen a decline yet must still honor one written moments ago by a
    // different session, rather than showing a second prompt. It also means
    // the supervisor never re-mints a cert that's still Valid, even if the
    // session that triggered this check is itself due for renewal — only the
    // stored cert's own state decides whether to act.
    let state = cert_validity(&cert_pem)?;
    match launch_gate(&key_der, &cert_pem)? {
        LaunchStep::Serve(_) | LaunchStep::ServeNone => return Ok(RenewOutcome::Unchanged),
        // A Valid-but-untrusted cert needs re-trusting, not re-minting; that's
        // the launch path's job (`retrust_stored_ca`), not a mid-session
        // renewal. `rotate_ca` always re-issues, so only hand it a stored
        // cert that's actually due for renewal.
        LaunchStep::Attempt if state == CertValidity::Valid => return Ok(RenewOutcome::Unchanged),
        LaunchStep::Attempt => {}
    }
    match rotate_ca(&key_der, &cert_pem, validity, state)? {
        RotateOutcome::Cert(ca) if ca.cert_pem != cert_pem => Ok(RenewOutcome::Renewed(ca)),
        // A headless session can't satisfy the trust prompt now or later in this
        // session, regardless of whether the launch path has a still-valid cert
        // to fall back on; the supervisor backs off on this outcome either way.
        RotateOutcome::NoInteraction { .. } => Ok(RenewOutcome::NoInteraction),
        RotateOutcome::Cert(_) | RotateOutcome::Unavailable => Ok(RenewOutcome::Unchanged),
    }
}

/// Whether adopting `candidate` gains runway over `current`.
///
/// Requires a matching SPKI: same-key re-issue is the invariant that makes
/// mid-session rotation safe, since a process's children may already have
/// loaded `current`'s anchor. A later-expiring cert under a *different* key
/// (e.g. the `generate_and_trust_new_ca` fallback that `rotate_ca` takes when
/// it can't re-issue over the stored key) is never worth adopting into a live
/// session — only a restart picks that one up.
pub(crate) fn supersedes(candidate: &str, current: &str) -> Result<bool> {
    if spki_of(candidate)? != spki_of(current)? {
        return Ok(false);
    }
    Ok(not_after_of(candidate)? > not_after_of(current)?)
}

pub(crate) fn stored_cert_is_trusted(cert_pem: &str) -> Result<bool> {
    let der = pem_to_der(cert_pem)?;
    let cert = SecCertificate::from_der(&der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse stored CA cert: {e}")))?;
    Ok(is_cert_trusted(&cert))
}

fn not_after_of(cert_pem: &str) -> Result<i64> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse CA cert PEM: {e}")))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse X.509 from PEM: {e}")))?;
    Ok(cert.validity().not_after.timestamp())
}

/// SubjectPublicKeyInfo bytes, so two certs can be compared for same-key re-issue.
fn spki_of(cert_pem: &str) -> Result<Vec<u8>> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse CA cert PEM: {e}")))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse X.509 from PEM: {e}")))?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

/// The single gated read of the CA bundle: every read of the item from
/// every entry point (launch fast path, launch re-check, adoption,
/// renewal, sweep) goes through here, so the access repair always runs
/// before the first byte is read and a burst of concurrent launches
/// can't turn into a burst of per-process prompts. The bytes come
/// through the reference the gate verified, never a fresh attribute
/// search, so a replacement item cannot slip between them.
fn load_existing_ca() -> Result<Option<(Zeroizing<Vec<u8>>, String)>> {
    let Some(item) = ensure_bundle_access()? else {
        return Ok(None);
    };
    let bundle = match read_item_data(&item)? {
        // Deleted or replaced between the gate's resolve and this bound
        // read: reads as absent, and the create path's duplicate branch
        // re-gates whatever appeared next.
        None => return Ok(None),
        Some(data) => data,
    };
    let combined = String::from_utf8(bundle)
        .map_err(|e| NonoError::SandboxInit(format!("stored CA bundle is not valid UTF-8: {e}")))?;
    nono_proxy::tls_intercept::ca::split_key_cert_pem(&combined)
        .map(Some)
        .map_err(|e| NonoError::SandboxInit(format!("{e}")))
}

/// Outcome of attempting to re-issue and re-trust the shared CA over its
/// stored key. Internal to the rotate/generate fallback chain — callers see
/// [`RenewOutcome`] (mid-session) or a plain `Option` (launch).
enum RotateOutcome {
    /// A certificate to serve: either genuinely re-issued, or (when the
    /// prompt was declined but the old one still has life left) the
    /// unchanged previous certificate.
    Cert(PreloadedCa),
    /// Declined or failed, and the previous certificate has expired; caller
    /// falls back to an ephemeral CA.
    Unavailable,
    /// No interactive session exists to show the trust prompt (e.g. a
    /// headless `nono proxy`). Retrying later in the same session can't
    /// succeed either. Carries the still-valid previous certificate when one
    /// exists, so the launch path can keep serving it instead of dropping to
    /// an untrusted ephemeral CA.
    NoInteraction { fallback: Option<PreloadedCa> },
}

/// Re-issue the CA certificate over the stored key and hand the new one over.
///
/// Trust the new cert before retiring the old, so nothing fails mid-swap. The key is
/// unchanged, so leaves minted under the old cert still chain to the new one.
fn rotate_ca(
    key_der: &Zeroizing<Vec<u8>>,
    old_cert_pem: &str,
    validity: Duration,
    state: CertValidity,
) -> Result<RotateOutcome> {
    let ca = match nono_proxy::tls_intercept::ca::EphemeralCa::reissue_with_cn(
        key_der,
        "nono-proxy-ca",
        validity,
    ) {
        Ok(ca) => ca,
        Err(e) => {
            // No usable stored key: only a whole new anchor can recover.
            warn!("Cannot re-issue over the stored proxy CA key ({e}); generating a new CA.");
            remove_cert_from_keychain(old_cert_pem);
            delete_existing_ca();
            return Ok(match generate_and_trust_new_ca(validity)? {
                Some(ca) => RotateOutcome::Cert(ca),
                None => RotateOutcome::Unavailable,
            });
        }
    };
    let cert_pem = ca.cert_pem().to_string();

    let cert_der = pem_to_der(&cert_pem)?;
    let sec_cert = SecCertificate::from_der(&cert_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to create SecCertificate: {e}")))?;

    info!("Renewing proxy CA (you may be prompted for authentication)...");
    let outcome = trust_attempt_outcome(trust_cert(&sec_cert))?;

    if should_record_backoff(outcome) {
        record_renewal_backoff(old_cert_pem)?;
    }

    match post_attempt_action(outcome, state) {
        PostAttemptAction::Unavailable => {
            warn!(
                "Proxy CA renewal cancelled or unavailable and the stored certificate \
                 has expired. Falling back to ephemeral CA; Go CLI tools won't validate \
                 proxy certs."
            );
            return Ok(RotateOutcome::Unavailable);
        }
        PostAttemptAction::KeepStored => {
            // The old cert is untouched, so declining costs nothing until it expires.
            let fallback = PreloadedCa {
                key_der: key_der.clone(),
                cert_pem: old_cert_pem.to_string(),
            };
            return Ok(match outcome {
                TrustAttemptOutcome::NoInteraction => {
                    warn!(
                        "Proxy CA renewal needs authentication but no interactive \
                         session is available to authorize it. Continuing on the \
                         current certificate."
                    );
                    RotateOutcome::NoInteraction {
                        fallback: Some(fallback),
                    }
                }
                _ => {
                    warn!(
                        "Proxy CA renewal cancelled; continuing on the current \
                         certificate. Retry is rate-limited; it won't re-prompt on \
                         every launch."
                    );
                    RotateOutcome::Cert(fallback)
                }
            });
        }
        PostAttemptAction::AdoptNewlyTrusted => {}
    }

    let key_pem = ca.key_pem();
    let combined = Zeroizing::new(format!("{}{}", *key_pem, cert_pem));
    // Write through the gate's verified reference: this flow holds the
    // renewal lock, so the gate verifies in place when the marker does not
    // cover the item, and the update lands on exactly that item.
    let item = ensure_bundle_access()?.ok_or_else(|| {
        NonoError::SandboxInit("the proxy-CA keychain item disappeared during renewal".to_string())
    })?;
    update_item_data(&item, combined.as_bytes()).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to store renewed CA bundle in Keychain: {e}"
        ))
    })?;
    // The update above replaces only the data attribute, so the access
    // list survives it and the ACL state marker stays valid: the item's
    // creation date, which the marker keys on, is unchanged. Re-reading
    // the access list here would prompt on every renewal (securityd
    // gates the owner read even for access-list members), so it is left
    // to the gate, which verifies when the item changes.

    // Same-key renewal (Fix 6): the old cert's trust settings apply to a key
    // that's still current, so leave it in the keychain rather than dropping
    // it — only the key-change fallback above (a fresh anchor, unrelated key)
    // needs the old entry actively removed.

    info!("Proxy CA renewed");
    Ok(RotateOutcome::Cert(PreloadedCa {
        key_der: Zeroizing::new(ca.key_der().to_vec()),
        cert_pem,
    }))
}

fn generate_and_trust_new_ca(validity: Duration) -> Result<Option<PreloadedCa>> {
    let ca =
        nono_proxy::tls_intercept::ca::EphemeralCa::generate_with_cn("nono-proxy-ca", validity)
            .map_err(|e| NonoError::SandboxInit(format!("failed to generate CA: {e}")))?;
    let key_der = Zeroizing::new(ca.key_der().to_vec());
    let cert_pem = ca.cert_pem().to_string();

    // Single atomic write — concurrent processes race, but the bundle is always
    // a coherent key+cert pair (second writer wins, no mismatch possible).
    // The access list is attached at creation, so the item is readable by
    // the running binary from its first moment, no prompt.
    let key_pem = ca.key_pem();
    let combined = Zeroizing::new(format!("{}{}", *key_pem, cert_pem));
    store_bundle_with_access(&combined)?;

    let cert_der = pem_to_der(&cert_pem)?;
    let sec_cert = SecCertificate::from_der(&cert_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to create SecCertificate: {e}")))?;

    info!("Adding proxy CA to macOS trust store (you may be prompted for authentication)...");
    let outcome = trust_attempt_outcome(trust_cert(&sec_cert))?;

    if should_record_backoff(outcome) {
        // Keyed to this cert's own fingerprint: the bundle stays in Keychain
        // (see below), so a later launch loads this exact cert and consults
        // the same marker via `renewal_gate` instead of re-prompting.
        record_renewal_backoff(&cert_pem)?;
    }

    if outcome != TrustAttemptOutcome::Trusted {
        // Declined or no interactive session: keep the bundle rather than
        // deleting it (Fix 5) — an untrusted-but-Valid cert is still useful
        // to serve, and deleting it would throw away the backoff marker's
        // referent, forcing a re-mint (and a re-prompt) on the very next
        // launch instead of honoring the backoff window.
        warn!(
            "Trust store auth cancelled or unavailable. Falling back to ephemeral CA. \
             Go CLI tools won't validate proxy certs; other tools still work."
        );
        return Ok(None);
    }

    info!("Proxy CA added to macOS trust store");
    Ok(Some(PreloadedCa { key_der, cert_pem }))
}

fn ensure_cert_in_keychain(cert: &SecCertificate) -> Result<()> {
    let keychain = SecKeychain::default()
        .map_err(|e| NonoError::SandboxInit(format!("failed to open default keychain: {e}")))?;
    if let Err(e) = cert.add_to_keychain(Some(keychain)) {
        // errSecDuplicateItem (-25299) — cert already imported from a prior run.
        if e.code() != -25299 {
            return Err(NonoError::SandboxInit(format!(
                "failed to add CA cert to keychain: {e}"
            )));
        }
    }
    Ok(())
}

/// OSStatus codes that indicate the user refused the authentication prompt.
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
/// No interactive session exists to show the prompt at all (e.g. a headless
/// `nono proxy`). Distinct from a decline: retrying later in the same session
/// can't succeed either, since there's still nobody to ask.
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

fn is_user_cancelled_osstatus(code: i32) -> bool {
    matches!(code, ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED)
}

fn trust_cert(cert: &SecCertificate) -> std::result::Result<(), TrustCertError> {
    // Trust before import: a cancelled/failed prompt then leaves nothing orphaned.
    TrustSettings::new(Domain::User)
        .set_trust_settings_always(cert)
        .map_err(|e| {
            if e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED {
                TrustCertError::NoInteractionAvailable
            } else if is_user_cancelled_osstatus(e.code()) {
                TrustCertError::UserCancelled
            } else {
                TrustCertError::Other(NonoError::SandboxInit(format!(
                    "failed to set trust settings: {e}"
                )))
            }
        })?;
    if let Err(e) = ensure_cert_in_keychain(cert) {
        // Import failed after trust succeeded — drop the now-orphaned trust settings.
        if let Err(status) = remove_trust_settings(cert) {
            warn!("Failed to roll back trust settings after import failure (OSStatus {status})");
        }
        return Err(TrustCertError::Other(e));
    }
    Ok(())
}

/// Trust-settings APIs don't report keychain presence, so we search for it.
fn find_keychain_cert(target_der: &[u8]) -> Option<SecCertificate> {
    let results = match ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .limit(Limit::All)
        .search()
    {
        Ok(results) => results,
        Err(e) => {
            debug!("keychain certificate search failed: {e}");
            return None;
        }
    };
    results.into_iter().find_map(|item| match item {
        SearchResult::Ref(Reference::Certificate(c)) if c.to_der() == target_der => Some(c),
        _ => None,
    })
}

fn cert_in_keychain(cert: &SecCertificate) -> bool {
    find_keychain_cert(&cert.to_der()).is_some()
}

fn trust_settings_report_trusted(cert: &SecCertificate) -> bool {
    let ts = TrustSettings::new(Domain::User);
    match ts.tls_trust_settings_for_certificate(cert) {
        Ok(Some(r)) => {
            let trusted = matches!(
                r,
                TrustSettingsForCertificate::TrustRoot | TrustSettingsForCertificate::TrustAsRoot
            );
            debug!("trust store lookup: {:?}, trusted={}", r, trusted);
            trusted
        }
        Ok(None) => {
            // Empty settings means unconditional trust, per Apple docs.
            debug!("trust store lookup: unconditionally trusted (empty settings)");
            true
        }
        Err(e) => {
            debug!("trust store lookup: {e} (cert not in trust store)");
            false
        }
    }
}

/// `trustd` needs both; trust-settings alone can be an orphaned entry.
fn cert_is_trusted(in_keychain: bool, trust_settings_trusted: bool) -> bool {
    in_keychain && trust_settings_trusted
}

fn is_cert_trusted(cert: &SecCertificate) -> bool {
    cert_is_trusted(cert_in_keychain(cert), trust_settings_report_trusted(cert))
}

fn remove_cert_from_keychain(cert_pem: &str) {
    let Ok(der) = pem_to_der(cert_pem) else {
        warn!("Failed to parse stored CA cert PEM while removing it; skipping cleanup.");
        return;
    };
    let Ok(cert) = SecCertificate::from_der(&der) else {
        warn!("Failed to reconstruct stored CA cert while removing it; skipping cleanup.");
        return;
    };

    match find_keychain_cert(&der) {
        Some(keychain_cert) => {
            if let Err(e) = keychain_cert.delete() {
                warn!(
                    "Failed to remove expired CA cert from keychain: {e}. \
                     Run: security delete-certificate -c \"nono-proxy-ca\""
                );
            }
        }
        None => debug!("no matching CA cert found in keychain; nothing to remove there"),
    }

    // Separate store, keyed by content — not removed by deleting the keychain item.
    if let Err(status) = remove_trust_settings(&cert) {
        warn!(
            "Failed to remove trust-settings entry for expired CA cert (OSStatus {status}). \
             Run: security remove-trusted-cert -d <exported-cert.pem>"
        );
    }
}

// Not wrapped by `security-framework`.
#[cfg_attr(target_vendor = "apple", link(name = "Security", kind = "framework"))]
unsafe extern "C" {
    fn SecTrustSettingsRemoveTrustSettings(
        cert_ref: SecCertificateRef,
        domain: SecTrustSettingsDomain,
    ) -> OSStatus;
}

fn remove_trust_settings(cert: &SecCertificate) -> std::result::Result<(), OSStatus> {
    // SAFETY: `cert` outlives the call; the ref is borrowed, not owned.
    let status = unsafe {
        SecTrustSettingsRemoveTrustSettings(cert.as_concrete_TypeRef(), kSecTrustSettingsDomainUser)
    };
    if status == 0 { Ok(()) } else { Err(status) }
}

fn delete_existing_ca() {
    let _ =
        security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
}

/// Remaining life below which the CA is renewed at launch, so every session starts
/// with runway.
const RENEWAL_HEADROOM: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertValidity {
    Valid,
    RenewDue,
    Expired,
}

pub(crate) fn cert_validity(cert_pem: &str) -> Result<CertValidity> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse stored CA cert PEM: {e}")))?;
    let cert = pem.parse_x509().map_err(|e| {
        NonoError::SandboxInit(format!("failed to parse X.509 from stored PEM: {e}"))
    })?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| NonoError::SandboxInit(format!("system clock before UNIX epoch: {e}")))?
        .as_secs() as i64;
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    Ok(classify_validity(
        not_after,
        now,
        renewal_headroom(not_after.saturating_sub(not_before)),
    ))
}

/// Proportional, so a 7-day cert prompts at most weekly and a short-lived one still
/// gets warning.
pub(crate) fn renewal_headroom(lifetime_secs: i64) -> Duration {
    let quarter = Duration::from_secs(lifetime_secs.max(0) as u64 / 4);
    quarter.min(RENEWAL_HEADROOM)
}

fn classify_validity(not_after: i64, now: i64, headroom: Duration) -> CertValidity {
    if now >= not_after {
        CertValidity::Expired
    } else if not_after - now <= headroom.as_secs() as i64 {
        CertValidity::RenewDue
    } else {
        CertValidity::Valid
    }
}

fn pem_to_der(cert_pem: &str) -> Result<Vec<u8>> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse CA cert PEM: {e}")))?;
    Ok(pem.contents.to_vec())
}

// --- Fix 7: stale-CA-cert sweep -------------------------------------------
//
// Cleans up `nono-proxy-ca` certs left behind by prior key rotations or
// interrupted renewals. Runs at launch, under the same `RenewalLock` as the
// other prompting paths, scoped to the default (login) keychain only.
// Deletes keychain items only — never calls `SecTrustSettingsRemoveTrustSettings`,
// which Apple's header documents as itself prompting.

/// At most one sweep run per day, enforced via a marker file (same pattern
/// as the renewal backoff marker), so a busy machine launching nono
/// repeatedly doesn't re-enumerate and re-classify the whole keychain on
/// every launch.
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Ceiling on deletions in a single run, so a misclassification (or an
/// unexpectedly large keychain) can't cascade into an unbounded purge.
const SWEEP_MAX_DELETIONS: usize = 100;

/// The commonName attribute OID (2.5.4.3), compared as a dotted string so the
/// exact-identity check below doesn't depend on any OID registry constant
/// being linked in.
const OID_COMMON_NAME: &str = "2.5.4.3";

/// One RDN attribute as (attribute-type OID, value) rather than a
/// display-formatted DN string, so the exact-identity check is a structural
/// comparison instead of a summary-string/substring match.
type DnAttrs = Vec<(String, String)>;

/// True only for a DN consisting of exactly one RDN of type commonName with
/// value exactly `"nono-proxy-ca"` — never a superset DN, a different CN, or
/// a value that merely contains that string.
fn is_exact_nono_ca_dn(dn: &DnAttrs) -> bool {
    matches!(dn.as_slice(), [(oid, value)] if oid == OID_COMMON_NAME && value == "nono-proxy-ca")
}

/// A keychain certificate under consideration for the stale-CA sweep,
/// already reduced to the facts the classifier needs. Everything below this
/// point is pure — no Security-framework or Keychain access.
#[derive(Debug, Clone)]
struct SweepCandidate {
    spki: Vec<u8>,
    der: Vec<u8>,
    issuer: DnAttrs,
    subject: DnAttrs,
    /// The certificate's signature verifies against its own public key.
    self_signed: bool,
    not_after: i64,
    /// This is literally the cert currently stored as the shared proxy CA —
    /// never a deletion candidate, whatever tier it would otherwise match.
    is_currently_stored: bool,
    /// Defense in depth: the real enumeration is scoped to the default
    /// (login) keychain, but the classifier refuses a non-default-keychain
    /// candidate too, so a future change to the enumeration call can't
    /// silently widen the sweep's blast radius without also changing this.
    is_default_keychain: bool,
}

/// Which tier of the stale-cert sweep selected a candidate for deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepTier {
    /// Same public key as the currently-stored cert, different DER: an
    /// artifact of a prior same-key renewal. Only fires when the currently
    /// stored cert is itself trusted — deleting a same-key sibling while the
    /// stored cert is untrusted could delete the only trusted anchor still
    /// standing.
    SameKeySibling,
    /// Different public key, expired: not provable as nono's own (public
    /// keys are public), but low-risk since an expired cert can't anchor
    /// anything.
    ExpiredForeignKey,
}

/// Decide whether `candidate` should be deleted, and under which tier,
/// purely from already-known facts — no Keychain access.
fn classify_sweep_candidate(
    candidate: &SweepCandidate,
    stored_spki: &[u8],
    stored_der: &[u8],
    stored_trusted: bool,
    now: i64,
) -> Option<SweepTier> {
    if candidate.is_currently_stored || candidate.der == stored_der {
        return None;
    }
    if !candidate.is_default_keychain {
        return None;
    }
    if !candidate.self_signed {
        return None;
    }
    if candidate.issuer != candidate.subject || !is_exact_nono_ca_dn(&candidate.issuer) {
        return None;
    }
    if candidate.spki == stored_spki {
        stored_trusted.then_some(SweepTier::SameKeySibling)
    } else if candidate.not_after <= now {
        Some(SweepTier::ExpiredForeignKey)
    } else {
        None
    }
}

/// Classify every candidate and cap the result at [`SWEEP_MAX_DELETIONS`].
/// Returns the index into `candidates` and the tier that selected it, in
/// input order, so the caller can stop partway through a batch and still
/// know exactly which ones were already acted on.
fn plan_stale_ca_sweep(
    candidates: &[SweepCandidate],
    stored_spki: &[u8],
    stored_der: &[u8],
    stored_trusted: bool,
    now: i64,
) -> Vec<(usize, SweepTier)> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            classify_sweep_candidate(c, stored_spki, stored_der, stored_trusted, now)
                .map(|t| (i, t))
        })
        .take(SWEEP_MAX_DELETIONS)
        .collect()
}

fn sweep_marker_path() -> Result<PathBuf> {
    let dir = crate::state_paths::user_state_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        NonoError::SandboxInit(format!("cannot create state dir '{}': {e}", dir.display()))
    })?;
    Ok(dir.join("proxy-ca-sweep-last-run"))
}

/// Whether the sweep already ran within [`SWEEP_INTERVAL`] — at most once a
/// day, so every launch doesn't re-enumerate the whole keychain.
fn sweep_ran_recently() -> Result<bool> {
    let path = sweep_marker_path()?;
    let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
        return Ok(false);
    };
    let elapsed = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO);
    Ok(elapsed < SWEEP_INTERVAL)
}

fn record_sweep_ran() -> Result<()> {
    let path = sweep_marker_path()?;
    std::fs::write(&path, []).map_err(|e| {
        NonoError::SandboxInit(format!(
            "cannot write sweep marker '{}': {e}",
            path.display()
        ))
    })
}

/// Verify a certificate's signature against its own public key — true only
/// for a genuinely self-signed cert, never a look-alike signed by something
/// else. No Keychain or Security-framework access; pure DER parsing + `ring`
/// (via x509-parser's `verify` feature).
fn cert_is_self_signed(der: &[u8]) -> Result<bool> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse candidate cert DER: {e}")))?;
    Ok(cert.verify_signature(None).is_ok())
}

/// Extract a DN's attributes in structural form for [`is_exact_nono_ca_dn`].
/// No Keychain or Security-framework access; pure DER parsing.
fn dn_attrs(name: &x509_parser::x509::X509Name<'_>) -> DnAttrs {
    name.iter_rdn()
        .flat_map(|rdn| rdn.iter())
        .map(|atv| {
            (
                atv.attr_type().to_id_string(),
                atv.as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Enumerate `nono-proxy-ca` certs in the default (login) keychain, delete the
/// ones [`plan_stale_ca_sweep`] selects, and record the marker. Thin by
/// design, like `trust_cert`/`find_keychain_cert` — this touches Security
/// framework and Keychain APIs directly and stays untested by unit tests; all
/// the actual decision logic lives in `classify_sweep_candidate`/
/// `plan_stale_ca_sweep`.
pub(crate) fn sweep_stale_ca_certs() -> Result<()> {
    if sweep_ran_recently()? {
        return Ok(());
    }

    // Serialize with the other prompting/mutating paths under the same lock;
    // if another process is already busy, skip rather than wait — the sweep
    // is opportunistic cleanup, not something worth blocking launch on.
    let Some(_lock) = RenewalLock::acquire()? else {
        debug!("another process holds the renewal lock; skipping the stale-CA sweep");
        return Ok(());
    };
    // Another process may have just run the sweep while we waited for the lock.
    if sweep_ran_recently()? {
        return Ok(());
    }

    let Some((_key_der, stored_cert_pem)) = load_existing_ca()? else {
        debug!("no stored proxy CA; nothing to sweep against");
        record_sweep_ran()?;
        return Ok(());
    };
    let stored_der = pem_to_der(&stored_cert_pem)?;
    let stored_spki = spki_of(&stored_cert_pem)?;
    let stored_trusted = stored_cert_is_trusted(&stored_cert_pem)?;

    let default_keychain = SecKeychain::default()
        .map_err(|e| NonoError::SandboxInit(format!("failed to open default keychain: {e}")))?;
    let results = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .limit(Limit::All)
        .keychains(&[default_keychain])
        .search()
        .map_err(|e| NonoError::SandboxInit(format!("keychain certificate search failed: {e}")))?;

    let certs: Vec<SecCertificate> = results
        .into_iter()
        .filter_map(|item| match item {
            SearchResult::Ref(Reference::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    // Certs we couldn't parse are simply excluded (never a deletion
    // candidate); `certs_by_candidate` keeps the two lists in lockstep so a
    // plan index still refers to the right `SecCertificate`.
    let mut candidates = Vec::with_capacity(certs.len());
    let mut certs_by_candidate = Vec::with_capacity(certs.len());
    for cert in &certs {
        let der = cert.to_der();
        let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&der) else {
            continue;
        };
        let spki = parsed.public_key().subject_public_key.data.to_vec();
        let issuer = dn_attrs(parsed.issuer());
        let subject = dn_attrs(parsed.subject());
        let self_signed = cert_is_self_signed(&der).unwrap_or(false);
        let not_after = parsed.validity().not_after.timestamp();
        let is_currently_stored = der == stored_der;
        candidates.push(SweepCandidate {
            spki,
            der,
            issuer,
            subject,
            self_signed,
            not_after,
            is_currently_stored,
            is_default_keychain: true,
        });
        certs_by_candidate.push(cert);
    }

    let plan = plan_stale_ca_sweep(&candidates, &stored_spki, &stored_der, stored_trusted, now);
    for (index, tier) in plan {
        let cert = certs_by_candidate[index];
        match cert.delete() {
            Ok(()) => debug!("stale-CA sweep: deleted a {tier:?} candidate"),
            Err(e)
                if is_user_cancelled_osstatus(e.code())
                    || e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED =>
            {
                warn!(
                    "Stale-CA sweep interrupted by an auth prompt cancel/failure \
                     (OSStatus {}); stopping this run rather than continuing through \
                     the rest of the batch.",
                    e.code()
                );
                break;
            }
            Err(e) => warn!("Failed to delete a stale CA cert during the sweep: {e}"),
        }
    }

    record_sweep_ran()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono_proxy::tls_intercept::ca::EphemeralCa;

    fn generate_test_ca() -> EphemeralCa {
        EphemeralCa::generate_with_cn(
            "nono-proxy-ca",
            nono_proxy::tls_intercept::ca::CA_VALIDITY_DEFAULT,
        )
        .unwrap()
    }

    #[test]
    fn supersedes_requires_matching_spki() {
        let key =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(3600)).unwrap();
        let live = key.cert_pem().to_string();
        let same_key_renewal = EphemeralCa::reissue_with_cn(
            key.key_der(),
            "nono-proxy-ca",
            Duration::from_secs(86400),
        )
        .unwrap();
        // A later-expiring cert minted under a brand new key, standing in for
        // the `generate_and_trust_new_ca` fallback path.
        let different_key =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86400)).unwrap();

        assert!(
            supersedes(same_key_renewal.cert_pem(), &live).unwrap(),
            "a same-key re-issue with more runway is adoptable"
        );
        assert!(
            !supersedes(different_key.cert_pem(), &live).unwrap(),
            "a different-SPKI cert must never supersede the live CA, however long-lived"
        );
    }

    #[test]
    fn combined_pem_roundtrips() {
        use nono_proxy::tls_intercept::ca::split_key_cert_pem;

        let ca = generate_test_ca();
        let combined = format!("{}{}", *ca.key_pem(), ca.cert_pem());

        let (key_der, cert_pem) = split_key_cert_pem(&combined).unwrap();
        assert_eq!(&*key_der, ca.key_der());
        assert_eq!(cert_pem, ca.cert_pem());
        EphemeralCa::from_existing(&key_der, &cert_pem).unwrap();
    }

    #[test]
    fn cert_validity_sees_a_week_old_cert_as_valid() {
        let ca =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(7 * 86400)).unwrap();
        assert_eq!(cert_validity(ca.cert_pem()).unwrap(), CertValidity::Valid);
    }

    #[test]
    fn cert_validity_scales_the_headroom_to_a_short_lived_cert() {
        // A 120s cert must not be born renew-due, or every launch rotates.
        let ca = EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(120)).unwrap();
        assert_eq!(cert_validity(ca.cert_pem()).unwrap(), CertValidity::Valid);

        let not_after = not_after_of(ca.cert_pem()).unwrap();
        assert_eq!(
            classify_validity(not_after, not_after - 20, renewal_headroom(120)),
            CertValidity::RenewDue,
            "20s of life left on a 120s cert is inside the 30s headroom"
        );
    }

    #[test]
    fn renewal_headroom_is_a_quarter_of_life_capped_at_a_day() {
        assert_eq!(renewal_headroom(120), Duration::from_secs(30));
        assert_eq!(
            renewal_headroom(7 * 86400),
            Duration::from_secs(24 * 60 * 60),
            "a week-long cert renews a day out, not 42 hours out"
        );
        assert_eq!(renewal_headroom(-1), Duration::ZERO);
    }

    #[test]
    fn cert_validity_rejects_garbage() {
        assert!(cert_validity("not a cert").is_err());
    }

    #[test]
    fn classify_validity_boundaries() {
        let headroom = Duration::from_secs(86400);
        // not_after exactly now, and one second past it, are both expired.
        assert_eq!(
            classify_validity(1_000, 1_000, headroom),
            CertValidity::Expired
        );
        assert_eq!(
            classify_validity(1_000, 1_001, headroom),
            CertValidity::Expired
        );
        // Exactly one headroom of life left still counts as due.
        assert_eq!(
            classify_validity(1_000 + 86_400, 1_000, headroom),
            CertValidity::RenewDue
        );
        assert_eq!(
            classify_validity(1_000 + 86_401, 1_000, headroom),
            CertValidity::Valid
        );
    }

    #[test]
    fn pem_to_der_roundtrips() {
        use x509_parser::prelude::FromDer;

        let ca = generate_test_ca();
        let der = pem_to_der(ca.cert_pem()).unwrap();
        assert!(!der.is_empty());
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "nono-proxy-ca"
        );
    }

    #[test]
    fn cert_is_trusted_requires_both_keychain_presence_and_trust_settings() {
        assert!(cert_is_trusted(true, true));
        assert!(!cert_is_trusted(true, false));
        assert!(!cert_is_trusted(false, true)); // orphaned trust-settings entry
        assert!(!cert_is_trusted(false, false));
    }

    #[test]
    fn is_user_cancelled_osstatus_detects_known_codes() {
        assert!(is_user_cancelled_osstatus(ERR_SEC_USER_CANCELED));
        assert!(is_user_cancelled_osstatus(ERR_SEC_AUTH_FAILED));
        assert!(!is_user_cancelled_osstatus(-25299)); // errSecDuplicateItem
        assert!(!is_user_cancelled_osstatus(0));
        // interaction-not-allowed is a distinct case, handled separately in trust_cert
        assert!(!is_user_cancelled_osstatus(ERR_SEC_INTERACTION_NOT_ALLOWED));
    }

    #[test]
    fn item_access_call_failure_separates_unavailable_interaction() {
        assert!(matches!(
            item_access_call_failed("read", ERR_SEC_INTERACTION_NOT_ALLOWED),
            ItemAccessError::NoInteraction
        ));
        assert!(matches!(
            item_access_call_failed("read", ERR_SEC_AUTH_FAILED),
            ItemAccessError::Other(_)
        ));
        assert!(matches!(
            item_access_call_failed("install", -25299),
            ItemAccessError::Other(_)
        ));
    }

    #[test]
    fn item_access_backoff_ignores_unavailable_interaction() {
        assert!(!ItemAccessError::NoInteraction.should_back_off());
        assert!(ItemAccessError::Other(NonoError::SandboxInit("x".to_string())).should_back_off());
    }

    fn with_fake_state_home<T>(f: impl FnOnce() -> T) -> T {
        let home = tempfile::tempdir().unwrap();
        let _env_lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _guard = crate::test_env::EnvVarGuard::set_all(&[(
            "XDG_STATE_HOME",
            &home.path().display().to_string(),
        )]);
        f()
    }

    #[test]
    fn cert_fingerprint_differs_for_different_certs() {
        let a = generate_test_ca();
        let b = generate_test_ca();
        assert_ne!(
            cert_fingerprint(a.cert_pem()).unwrap(),
            cert_fingerprint(b.cert_pem()).unwrap()
        );
        assert_eq!(
            cert_fingerprint(a.cert_pem()).unwrap(),
            cert_fingerprint(a.cert_pem()).unwrap()
        );
    }

    #[test]
    fn renewal_backoff_is_keyed_to_the_specific_cert() {
        with_fake_state_home(|| {
            let a = generate_test_ca();
            let b = generate_test_ca();

            assert!(!renewal_backed_off(a.cert_pem()).unwrap());
            record_renewal_backoff(a.cert_pem()).unwrap();

            assert!(
                renewal_backed_off(a.cert_pem()).unwrap(),
                "a just-declined cert must be backed off"
            );
            assert!(
                !renewal_backed_off(b.cert_pem()).unwrap(),
                "a marker for one cert must never suppress renewal of a different cert"
            );
        });
    }

    // --- renewal_gate: the pure check-then-lock decision core (Fix 3/4/5) ---
    //
    // These are the seam that fixes the launch-path TOCTOU: `try_ensure_trusted_ca`
    // calls this same function once lock-free (fast path) and once again after
    // acquiring `RenewalLock`, re-reading `state`/`trusted`/`backed_off` fresh each
    // time. Because both calls go through one tested decision core, a decline (or a
    // renewal by another process) recorded in the gap between the two calls is
    // always honored on the re-check — nothing tests the lock-free path's stale
    // answer twice.

    #[test]
    fn renewal_gate_serves_a_valid_trusted_cert_without_acting() {
        assert_eq!(
            renewal_gate(CertValidity::Valid, true, false),
            RenewalGate::ServeStored
        );
        // Even a stale backoff marker is irrelevant once the cert is trusted again.
        assert_eq!(
            renewal_gate(CertValidity::Valid, true, true),
            RenewalGate::ServeStored
        );
    }

    #[test]
    fn renewal_gate_attempts_when_nothing_is_backed_off() {
        assert_eq!(
            renewal_gate(CertValidity::Valid, false, false),
            RenewalGate::Attempt,
            "an untrusted-but-valid cert must be re-trusted"
        );
        assert_eq!(
            renewal_gate(CertValidity::RenewDue, false, false),
            RenewalGate::Attempt
        );
        assert_eq!(
            renewal_gate(CertValidity::Expired, false, false),
            RenewalGate::Attempt
        );
    }

    #[test]
    fn renewal_gate_serves_the_stored_cert_untrusted_when_a_retrust_was_just_declined() {
        // This is the L2 row: a Valid-but-untrusted cert whose re-trust was
        // just declined is still served (untrusted) rather than dropped to an
        // ephemeral CA, until the backoff window lapses.
        assert_eq!(
            renewal_gate(CertValidity::Valid, false, true),
            RenewalGate::ServeStored
        );
    }

    #[test]
    fn renewal_gate_serves_the_old_cert_when_a_renewal_was_just_declined() {
        assert_eq!(
            renewal_gate(CertValidity::RenewDue, false, true),
            RenewalGate::ServeStored
        );
    }

    #[test]
    fn renewal_gate_gives_up_when_an_expired_cert_renewal_was_just_declined() {
        // L4: unlike RenewDue, an expired cert has nothing left to fall back
        // on, so a recent decline must not re-prompt, but also can't serve
        // anything — the caller falls back to an ephemeral CA.
        assert_eq!(
            renewal_gate(CertValidity::Expired, false, true),
            RenewalGate::ServeNone
        );
    }

    #[test]
    fn should_record_backoff_only_for_an_actual_decline() {
        assert!(should_record_backoff(TrustAttemptOutcome::Declined));
        assert!(!should_record_backoff(TrustAttemptOutcome::Trusted));
        assert!(
            !should_record_backoff(TrustAttemptOutcome::NoInteraction),
            "a missing interactive session isn't a decision to throttle later attempts"
        );
    }

    #[test]
    fn post_attempt_action_adopts_on_success_regardless_of_prior_state() {
        for state in [
            CertValidity::Valid,
            CertValidity::RenewDue,
            CertValidity::Expired,
        ] {
            assert_eq!(
                post_attempt_action(TrustAttemptOutcome::Trusted, state),
                PostAttemptAction::AdoptNewlyTrusted
            );
        }
    }

    #[test]
    fn post_attempt_action_keeps_a_still_valid_stored_cert_on_decline() {
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::Declined, CertValidity::Valid),
            PostAttemptAction::KeepStored,
            "L2: a declined re-trust still has a valid (if untrusted) cert to serve"
        );
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::Declined, CertValidity::RenewDue),
            PostAttemptAction::KeepStored,
            "a declined renewal still has runway on the old cert"
        );
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::NoInteraction, CertValidity::RenewDue),
            PostAttemptAction::KeepStored
        );
    }

    #[test]
    fn post_attempt_action_gives_up_only_once_the_stored_cert_has_expired() {
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::Declined, CertValidity::Expired),
            PostAttemptAction::Unavailable
        );
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::NoInteraction, CertValidity::Expired),
            PostAttemptAction::Unavailable
        );
    }

    #[test]
    fn trust_attempt_outcome_maps_every_trust_cert_error_variant() {
        assert_eq!(
            trust_attempt_outcome(Ok(())).unwrap(),
            TrustAttemptOutcome::Trusted
        );
        assert_eq!(
            trust_attempt_outcome(Err(TrustCertError::UserCancelled)).unwrap(),
            TrustAttemptOutcome::Declined
        );
        assert_eq!(
            trust_attempt_outcome(Err(TrustCertError::NoInteractionAvailable)).unwrap(),
            TrustAttemptOutcome::NoInteraction
        );
        assert!(
            trust_attempt_outcome(Err(TrustCertError::Other(NonoError::SandboxInit(
                "boom".to_string()
            ))))
            .is_err(),
            "a genuine failure must propagate as an error, not a decision outcome"
        );
    }

    fn nono_ca_dn() -> DnAttrs {
        vec![(OID_COMMON_NAME.to_string(), "nono-proxy-ca".to_string())]
    }

    /// A candidate that would be selected by neither tier unless a test
    /// deliberately changes one field to make it match.
    fn base_sweep_candidate() -> SweepCandidate {
        SweepCandidate {
            spki: b"candidate-spki".to_vec(),
            der: b"candidate-der".to_vec(),
            issuer: nono_ca_dn(),
            subject: nono_ca_dn(),
            self_signed: true,
            not_after: 1_000,
            is_currently_stored: false,
            is_default_keychain: true,
        }
    }

    const STORED_SPKI: &[u8] = b"stored-spki";
    const STORED_DER: &[u8] = b"stored-der";
    const NOW: i64 = 2_000;

    #[test]
    fn classify_sweep_candidate_selects_a_same_key_sibling_only_when_stored_is_trusted() {
        let candidate = SweepCandidate {
            spki: STORED_SPKI.to_vec(),
            not_after: NOW + 1, // still valid — tier 1 doesn't care about validity
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, true, NOW),
            Some(SweepTier::SameKeySibling)
        );
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, false, NOW),
            None,
            "a same-key sibling is never deleted while the stored cert is itself untrusted"
        );
    }

    #[test]
    fn classify_sweep_candidate_selects_an_expired_foreign_key_only_when_expired() {
        let candidate = SweepCandidate {
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, true, NOW),
            Some(SweepTier::ExpiredForeignKey)
        );
        let still_valid = SweepCandidate {
            not_after: NOW + 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&still_valid, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "a foreign-key cert that hasn't expired yet is never deleted"
        );
    }

    #[test]
    fn classify_sweep_candidate_never_deletes_the_currently_stored_cert() {
        let flagged = SweepCandidate {
            spki: STORED_SPKI.to_vec(),
            is_currently_stored: true,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&flagged, STORED_SPKI, STORED_DER, true, NOW),
            None
        );

        // Belt-and-suspenders: matching DER is also treated as "the stored
        // cert", even if the enumeration wrapper failed to set the flag.
        let matching_der = SweepCandidate {
            der: STORED_DER.to_vec(),
            spki: STORED_SPKI.to_vec(),
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&matching_der, STORED_SPKI, STORED_DER, true, NOW),
            None
        );
    }

    #[test]
    fn classify_sweep_candidate_rejects_a_bad_self_signature_look_alike() {
        let candidate = SweepCandidate {
            self_signed: false,
            not_after: NOW - 1, // otherwise a clean tier-2 match
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "the right CN with a bad self-signature must never be deleted"
        );
    }

    #[test]
    fn classify_sweep_candidate_rejects_a_dn_that_is_not_exactly_nono_proxy_ca() {
        let wrong_cn = SweepCandidate {
            issuer: vec![(OID_COMMON_NAME.to_string(), "not-nono-proxy-ca".to_string())],
            subject: vec![(OID_COMMON_NAME.to_string(), "not-nono-proxy-ca".to_string())],
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&wrong_cn, STORED_SPKI, STORED_DER, true, NOW),
            None
        );

        let extra_rdn = SweepCandidate {
            issuer: {
                let mut dn = nono_ca_dn();
                dn.push(("2.5.4.10".to_string(), "Extra Org".to_string()));
                dn
            },
            subject: {
                let mut dn = nono_ca_dn();
                dn.push(("2.5.4.10".to_string(), "Extra Org".to_string()));
                dn
            },
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&extra_rdn, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "a DN with the right CN plus another attribute is not an exact match"
        );

        let mismatched_issuer_subject = SweepCandidate {
            issuer: nono_ca_dn(),
            subject: vec![(OID_COMMON_NAME.to_string(), "nono-proxy-ca".to_string())],
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        // Structurally equal in this case, so assert the inequality path
        // separately by constructing a genuine mismatch.
        let issuer_differs = SweepCandidate {
            issuer: vec![("2.5.4.3".to_string(), "nono-proxy-ca".to_string())],
            subject: vec![("2.5.4.3".to_string(), "nono-proxy-ca ".to_string())],
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(
                &mismatched_issuer_subject,
                STORED_SPKI,
                STORED_DER,
                true,
                NOW
            ),
            Some(SweepTier::ExpiredForeignKey),
            "sanity: identical issuer/subject content is still an exact match"
        );
        assert_eq!(
            classify_sweep_candidate(&issuer_differs, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "issuer and subject must match exactly, not just both resemble the CA CN"
        );
    }

    #[test]
    fn classify_sweep_candidate_rejects_a_non_default_keychain_item() {
        let candidate = SweepCandidate {
            is_default_keychain: false,
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "the sweep must never touch an item outside the default (login) keychain"
        );
    }

    #[test]
    fn plan_stale_ca_sweep_caps_deletions_at_the_limit() {
        let candidates: Vec<SweepCandidate> = (0..150)
            .map(|i| SweepCandidate {
                der: format!("der-{i}").into_bytes(),
                not_after: NOW - 1,
                ..base_sweep_candidate()
            })
            .collect();

        let plan = plan_stale_ca_sweep(&candidates, STORED_SPKI, STORED_DER, true, NOW);

        assert_eq!(plan.len(), SWEEP_MAX_DELETIONS);
        assert_eq!(
            plan.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            (0..SWEEP_MAX_DELETIONS).collect::<Vec<_>>(),
            "the cap takes the first matches in input order, not an arbitrary subset"
        );
    }

    #[test]
    fn sweep_marker_throttles_to_once_a_day() {
        with_fake_state_home(|| {
            assert!(!sweep_ran_recently().unwrap());
            record_sweep_ran().unwrap();
            assert!(
                sweep_ran_recently().unwrap(),
                "a run recorded moments ago must suppress another run today"
            );
        });
    }

    #[test]
    fn cert_is_self_signed_detects_a_genuine_self_signed_cert() {
        let ca = generate_test_ca();
        let der = pem_to_der(ca.cert_pem()).unwrap();
        assert!(cert_is_self_signed(&der).unwrap());
    }

    #[test]
    fn cert_is_self_signed_rejects_a_tampered_signature() {
        let ca = generate_test_ca();
        let mut der = pem_to_der(ca.cert_pem()).unwrap();
        // The signature BIT STRING is the certificate's last field; flipping
        // its final byte changes the signature without changing any ASN.1
        // length or tag, so the DER still parses but no longer verifies.
        let last = der.len() - 1;
        der[last] ^= 0xFF;
        assert!(
            !cert_is_self_signed(&der).unwrap_or(true),
            "a tampered signature must never be reported as self-signed"
        );
    }

    #[test]
    fn dn_attrs_extracts_the_exact_common_name_of_a_generated_ca() {
        let ca = generate_test_ca();
        let der = pem_to_der(ca.cert_pem()).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

        let subject = dn_attrs(cert.subject());
        let issuer = dn_attrs(cert.issuer());

        assert_eq!(subject, nono_ca_dn());
        assert_eq!(issuer, nono_ca_dn());
        assert!(is_exact_nono_ca_dn(&subject));
        assert!(is_exact_nono_ca_dn(&issuer));
    }

    #[test]
    fn is_exact_nono_ca_dn_rejects_look_alikes() {
        assert!(!is_exact_nono_ca_dn(&vec![]));
        assert!(!is_exact_nono_ca_dn(&vec![(
            OID_COMMON_NAME.to_string(),
            "nono-proxy-ca-evil".to_string()
        )]));
        assert!(!is_exact_nono_ca_dn(&vec![
            (OID_COMMON_NAME.to_string(), "nono-proxy-ca".to_string()),
            ("2.5.4.10".to_string(), "Extra Org".to_string()),
        ]));
        assert!(!is_exact_nono_ca_dn(&vec![(
            "2.5.4.10".to_string(),
            "nono-proxy-ca".to_string()
        )]));
        assert!(is_exact_nono_ca_dn(&nono_ca_dn()));
    }

    // --- access-plan decisions (pure, no Keychain) ---------------------------

    /// The authorization-tag set of the entry that gates the secret, as
    /// observed on real items: decrypt, derive, both exports, MAC, sign.
    fn data_rights() -> Vec<acl_ffi::AclAuthorizationTag> {
        vec![24, 28, 37, 38, 59, 115]
    }

    fn entry_sets(entries: &[&[&[u8]]]) -> Vec<PlanEntry> {
        entries
            .iter()
            .map(|entry| {
                PlanEntry::named(
                    data_rights(),
                    entry.iter().map(|app| app.to_vec()).collect(),
                )
            })
            .collect()
    }

    /// The item shape a creating launch installs: the data entry naming its
    /// record, the any-application encrypt entry (35), and the empty-listed
    /// change-acl entry.
    fn standard_shape(current: &[u8]) -> Vec<PlanEntry> {
        vec![
            PlanEntry::named(data_rights(), vec![current.to_vec()]),
            PlanEntry::Any(vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT]),
            PlanEntry::named(vec![65536], Vec::new()),
        ]
    }

    #[test]
    fn a_listed_item_with_user_grants_is_canonical() {
        let current = b"current-binary".as_slice();
        let facts = entry_sets(&[&[b"user-granted-app".as_slice(), current]]);
        assert!(matches!(
            plan_item_access(&facts, current),
            AccessPlan::Canonical
        ));
    }

    #[test]
    fn a_missing_current_binary_rebuilds_while_keeping_user_grants() {
        let current = b"current-binary".as_slice();
        let facts = entry_sets(&[&[b"user-granted-app".as_slice()]]);
        let AccessPlan::Rebuild { keep } = plan_item_access(&facts, current) else {
            panic!("a missing current-binary entry must force a rebuild");
        };
        assert_eq!(
            keep,
            vec![b"user-granted-app".to_vec()],
            "user grants are kept and only the current binary is added"
        );
    }

    #[test]
    fn an_item_with_no_granted_applications_forces_a_rebuild() {
        let current = b"current-binary".as_slice();
        // The pre-fix shape: the secret-gating entry carries no records
        // (every read prompts), plus the standard encrypt and change-acl
        // entries every keychain item has.
        let facts = vec![
            PlanEntry::named(data_rights(), Vec::new()),
            PlanEntry::Any(vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT]),
            PlanEntry::named(vec![65536], Vec::new()),
        ];
        let AccessPlan::Rebuild { keep } = plan_item_access(&facts, current) else {
            panic!("an ungranted item must force a rebuild");
        };
        assert!(
            keep.is_empty(),
            "there are no user grants to preserve on an ungranted item"
        );
    }

    #[test]
    fn the_standard_keychain_shape_is_canonical() {
        let current = b"current-binary".as_slice();
        // The shape SecItemAdd with an access list produces: the secret
        // entry carries the binary's record, plus the standard encrypt and
        // change-acl entries. Misreading those as all-app grants would
        // force a pointless repair prompt on every item.
        let facts = standard_shape(current);
        assert!(matches!(
            plan_item_access(&facts, current),
            AccessPlan::Canonical
        ));
    }

    #[test]
    fn user_grants_alongside_the_standard_shape_stay_canonical() {
        let current = b"current-binary".as_slice();
        let facts = vec![
            PlanEntry::named(
                data_rights(),
                vec![current.to_vec(), b"security-cli".to_vec()],
            ),
            PlanEntry::Any(vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT]),
            PlanEntry::named(vec![65536], Vec::new()),
        ];
        assert!(matches!(
            plan_item_access(&facts, current),
            AccessPlan::Canonical
        ));
    }

    #[test]
    fn a_record_held_only_for_the_encrypt_right_is_never_promoted() {
        let current = b"current-binary".as_slice();
        // A crafted split: another application is named for the encrypt
        // right only. In place that is harmless, but the moment a rebuild
        // is needed (here: the running binary is missing from the data
        // entry) the encrypt-only record must be dropped, not
        // re-installed with full secret access.
        let facts = vec![
            PlanEntry::named(data_rights(), vec![b"user-granted-app".to_vec()]),
            PlanEntry::named(
                vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT],
                vec![b"backup-tool".to_vec()],
            ),
        ];
        let AccessPlan::Rebuild { keep } = plan_item_access(&facts, current) else {
            panic!("a missing current-binary grant must force a rebuild");
        };
        assert_eq!(
            keep,
            vec![b"user-granted-app".to_vec()],
            "records gating only harmless rights are dropped, never promoted"
        );
        // With the running binary granted, the same shape is safe as it
        // stands: an encrypt-only record grants nothing.
        let facts = vec![
            PlanEntry::named(data_rights(), vec![current.to_vec()]),
            PlanEntry::named(
                vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT],
                vec![b"backup-tool".to_vec()],
            ),
        ];
        assert!(matches!(
            plan_item_access(&facts, current),
            AccessPlan::Canonical
        ));
    }

    #[test]
    fn records_only_on_entries_that_gate_nothing_are_a_storm_state() {
        let current = b"current-binary".as_slice();
        // The data entry is ungranted; a record held only for encrypt
        // grants no access to the secret, so every read still prompts and
        // the item must be rebuilt.
        let facts = vec![
            PlanEntry::named(data_rights(), Vec::new()),
            PlanEntry::named(
                vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT],
                vec![current.to_vec()],
            ),
            PlanEntry::Any(vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT]),
        ];
        let AccessPlan::Rebuild { keep } = plan_item_access(&facts, current) else {
            panic!("a record on an encrypt-only entry cannot gate the secret");
        };
        assert!(
            keep.is_empty(),
            "the encrypt-only record is not a grant of the secret"
        );
    }

    #[test]
    fn an_any_application_entry_gating_the_secret_forces_a_rebuild() {
        let current = b"current-binary".as_slice();
        // A crafted hybrid: the data entry is granted, but a second
        // any-application entry also carries the decrypt tag (24), which
        // leaves the secret readable by every application.
        let mut facts = standard_shape(current);
        facts.push(PlanEntry::Any(vec![24]));
        let AccessPlan::Rebuild { keep } = plan_item_access(&facts, current) else {
            panic!("an any-application decrypt entry must never be canonical");
        };
        assert_eq!(
            keep,
            vec![current.to_vec()],
            "the rebuild preserves granted records while dropping the wildcard entry"
        );
    }

    #[test]
    fn a_named_change_acl_grant_forces_a_rebuild() {
        let current = b"current-binary".as_slice();
        // A crafted item: the data entry names the current binary, but a
        // second entry hands the change-acl right to another application,
        // which could rewrite the list and grant itself the secret.
        let facts = vec![
            PlanEntry::named(data_rights(), vec![current.to_vec()]),
            PlanEntry::named(vec![65536], vec![b"rogue-tool".to_vec()]),
        ];
        let AccessPlan::Rebuild { keep } = plan_item_access(&facts, current) else {
            panic!("a named change-acl grant must never be canonical");
        };
        assert_eq!(
            keep,
            vec![current.to_vec()],
            "the rebuild keeps the data grant and drops the admin grant"
        );
    }

    #[test]
    fn a_mixed_data_and_admin_grant_forces_a_rebuild() {
        let current = b"current-binary".as_slice();
        // The data entry grants the current binary, but a second entry
        // hands another application decrypt together with change-acl: the
        // mixed entry must not pass as canonical just because it gates the
        // secret, since its holder could rewrite the list and grant
        // itself more.
        let facts = vec![
            PlanEntry::named(data_rights(), vec![current.to_vec()]),
            PlanEntry::named(vec![24, 65536], vec![b"admin-tool".to_vec()]),
        ];
        let AccessPlan::Rebuild { keep } = plan_item_access(&facts, current) else {
            panic!("a mixed decrypt and change-acl grant must never be canonical");
        };
        assert_eq!(
            keep,
            vec![current.to_vec(), b"admin-tool".to_vec()],
            "the rebuild keeps the admin-tool data grant but strips its admin right"
        );
    }

    #[test]
    fn an_any_application_export_right_forces_a_rebuild() {
        let current = b"current-binary".as_slice();
        // Tag 37 is export-clear, part of the secret-gating set.
        let facts = vec![
            PlanEntry::named(data_rights(), vec![current.to_vec()]),
            PlanEntry::Any(vec![37]),
        ];
        assert!(matches!(
            plan_item_access(&facts, current),
            AccessPlan::Rebuild { .. }
        ));
    }

    #[test]
    fn named_export_grants_are_grants_of_the_secret() {
        let current = b"current-binary".as_slice();
        // Export rights (37 export-clear, 38 export-wrapped) extract the
        // key material from the item, so an application named for them
        // holds a grant of the secret: a rebuild keeps its record, exactly
        // like a decrypt grant, instead of silently dropping it.
        for tag in [37i32, 38] {
            let facts = vec![
                PlanEntry::named(vec![tag], vec![b"key-extractor".to_vec()]),
                PlanEntry::Any(vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT]),
            ];
            let AccessPlan::Rebuild { keep } = plan_item_access(&facts, current) else {
                panic!("a missing current-binary grant must force a rebuild");
            };
            assert_eq!(
                keep,
                vec![b"key-extractor".to_vec()],
                "tag {tag}: a named export grant is a grant of the secret"
            );
        }
    }

    #[test]
    fn user_export_grants_alongside_the_current_binary_stay_canonical() {
        let current = b"current-binary".as_slice();
        // An export grant behaves like every other data right a user
        // granted through macOS: with the current binary granted, the
        // state is canonical and must not prompt.
        let facts = vec![
            PlanEntry::named(data_rights(), vec![current.to_vec()]),
            PlanEntry::named(vec![38], vec![b"key-extractor".to_vec()]),
            PlanEntry::Any(vec![acl_ffi::ACL_AUTHORIZATION_ENCRYPT]),
        ];
        assert!(matches!(
            plan_item_access(&facts, current),
            AccessPlan::Canonical
        ));
    }

    fn identity(epoch: f64, persistent_ref: &str) -> ItemIdentity {
        ItemIdentity {
            epoch,
            persistent_ref: persistent_ref.to_string(),
        }
    }

    #[test]
    fn acl_state_marker_matches_only_the_same_item_and_policy() {
        let policy = "preserve";
        let item = identity(725011200.5, "aabbccdd");
        let content = format!("725011200.5\naabbccdd\n{policy}");
        assert!(
            marker_matches(Some(&content), &item, policy),
            "same item and policy: no verification prompt"
        );
        assert!(
            !marker_matches(Some(&content), &identity(725011200.6, "aabbccdd"), policy),
            "a recreated item must be re-verified"
        );
        assert!(
            !marker_matches(Some(&content), &identity(725011200.5, "11223344"), policy),
            "a replacement created in the same second carries a different \
             persistent reference and must be re-verified"
        );
        assert!(
            !marker_matches(Some(&content), &item, "other-policy"),
            "a changed policy line must be re-verified"
        );
        assert!(
            !marker_matches(None, &item, policy),
            "no stored marker: first launch verifies"
        );
        assert!(
            !marker_matches(Some(""), &item, policy),
            "empty marker content never matches"
        );
        assert!(
            !marker_matches(Some("not-a-date\naabbccdd\npreserve"), &item, policy),
            "malformed marker content never matches"
        );
        assert!(
            !marker_matches(Some("725011200.5\naabbccdd\n"), &item, policy),
            "a marker without a policy line never matches"
        );
        assert!(
            marker_matches(
                Some(&format!("725011200.5\naabbccdd\n{policy}\n")),
                &item,
                policy
            ),
            "a trailing newline in the stored marker never defeats the match"
        );
        assert!(
            !marker_matches(Some("725011200.5\npreserve"), &item, policy),
            "a marker in the two-line format never matches: the ref line is \
             structural, and an unknown format is never treated as satisfied"
        );
    }
}
