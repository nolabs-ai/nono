//! C FFI bindings for the nono capability-based sandboxing library.
//!
//! Provides a stable C ABI for any language with C FFI support (Go, Swift,
//! Ruby, Java, C#, Zig, etc.).
//!
//! # Memory ownership
//!
//! - Opaque pointers (`NonoCapabilitySet*`, `NonoQueryContext*`,
//!   `NonoSandboxState*`) are caller-owned. Free with the corresponding
//!   `_free()` function. All `_free()` functions are NULL-safe.
//!
//! - Returned `char*` strings are caller-owned. Free with
//!   `nono_string_free()`. NULL is safe to pass.
//!
//! - `nono_last_error()` returns a caller-owned string. Free with
//!   `nono_string_free()`. Returns NULL if no error has occurred.
//!
//! - Input `const char*` parameters are borrowed. The library copies what
//!   it needs.

pub mod capability_set;
pub mod fs_capability;
pub mod query;
pub mod sandbox;
pub mod state;
pub mod types;

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Re-export all public FFI symbols so they appear in the cdylib.
pub use capability_set::*;
pub use fs_capability::*;
pub use query::*;
pub use sandbox::*;
pub use state::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Thread-local error store
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Store an error message for the current thread.
pub(crate) fn set_last_error(msg: &str) {
    LAST_ERROR.with(|cell| {
        let cstr = match CString::new(msg) {
            Ok(s) => s,
            Err(nul_err) => {
                let pos = nul_err.nul_position();
                let mut bytes = nul_err.into_vec();
                bytes.truncate(pos);
                match CString::new(bytes) {
                    Ok(s) => s,
                    Err(_) => return,
                }
            }
        };
        *cell.borrow_mut() = Some(cstr);
    });
}

/// Map a `NonoError` to an error code and store the message.
///
/// Every `NonoError` variant is matched explicitly so the compiler will flag
/// new variants that need a mapping, instead of silently falling through to
/// `ErrUnknown`.
pub(crate) fn map_error(e: &nono::NonoError) -> types::NonoErrorCode {
    use types::NonoErrorCode;
    set_last_error(&e.to_string());
    match e {
        nono::NonoError::PathNotFound(_) => NonoErrorCode::ErrPathNotFound,
        nono::NonoError::ExpectedDirectory(_) => NonoErrorCode::ErrExpectedDirectory,
        nono::NonoError::ExpectedFile(_) => NonoErrorCode::ErrExpectedFile,
        nono::NonoError::PathCanonicalization { .. } => NonoErrorCode::ErrPathCanonicalization,
        nono::NonoError::NoCapabilities | nono::NonoError::NoCommand => {
            NonoErrorCode::ErrNoCapabilities
        }
        nono::NonoError::CwdPromptRequired => NonoErrorCode::ErrInvalidArg,
        nono::NonoError::SandboxInit(_) => NonoErrorCode::ErrSandboxInit,
        nono::NonoError::UnsupportedPlatform(_) => NonoErrorCode::ErrUnsupportedPlatform,
        nono::NonoError::BlockedCommand { .. } => NonoErrorCode::ErrBlockedCommand,
        #[cfg(target_os = "linux")]
        nono::NonoError::Landlock(_) | nono::NonoError::LandlockPath(_) => {
            NonoErrorCode::ErrSandboxInit
        }
        nono::NonoError::KeystoreAccess(_) | nono::NonoError::SecretNotFound(_) => {
            NonoErrorCode::ErrIo
        }
        nono::NonoError::ConfigParse(_)
        | nono::NonoError::AttachBusy
        | nono::NonoError::ConfigWrite { .. }
        | nono::NonoError::ConfigRead { .. }
        // Phase 36.5 D-36.5-B3: ActionRequired maps to ErrConfigParse uniformly
        // across base-hash / shadow / package-status callsites. C consumers
        // pattern-match on the Display string if structured distinction is needed.
        | nono::NonoError::ActionRequired { .. } => NonoErrorCode::ErrConfigParse,
        nono::NonoError::ProfileNotFound(_)
        | nono::NonoError::ProfileRead { .. }
        | nono::NonoError::ProfileParse(_)
        | nono::NonoError::ProfileInheritance(_) => NonoErrorCode::ErrProfileParse,
        nono::NonoError::HomeNotFound
        | nono::NonoError::Setup(_)
        | nono::NonoError::LearnError(_)
        | nono::NonoError::HookInstall(_) => NonoErrorCode::ErrConfigParse,
        nono::NonoError::EnvVarValidation { .. } => NonoErrorCode::ErrInvalidArg,
        nono::NonoError::CapFileValidation { .. } | nono::NonoError::CapFileTooLarge { .. } => {
            NonoErrorCode::ErrInvalidArg
        }
        nono::NonoError::VersionDowngrade { .. } => NonoErrorCode::ErrConfigParse,
        nono::NonoError::Io(_) | nono::NonoError::CommandExecution(_) => NonoErrorCode::ErrIo,
        nono::NonoError::ObjectStore(_)
        | nono::NonoError::Snapshot(_)
        | nono::NonoError::HashMismatch { .. }
        | nono::NonoError::SessionNotFound(_) => NonoErrorCode::ErrIo,
        nono::NonoError::TrustVerification { .. }
        | nono::NonoError::TrustSigning { .. }
        | nono::NonoError::TrustPolicy(_)
        | nono::NonoError::BlocklistBlocked { .. }
        | nono::NonoError::InstructionFileDenied { .. }
        | nono::NonoError::PackageVerification { .. } => NonoErrorCode::ErrTrustVerification,
        nono::NonoError::PackageInstall(_) | nono::NonoError::RegistryError(_) => {
            NonoErrorCode::ErrConfigParse
        }
        nono::NonoError::NetworkFilterUnsupported { .. } => NonoErrorCode::ErrUnsupportedPlatform,
        nono::NonoError::PartialRestore { .. } => NonoErrorCode::ErrIo,
        nono::NonoError::LabelApplyFailed { .. } => NonoErrorCode::ErrSandboxInit,
        // Phase 41 D-09 (CR-01): BrokerNotFound is an installation/runtime
        // defect — the broker.exe sibling is missing from disk where
        // current_exe().parent() expected it. This is structurally a sandbox-
        // init failure (the supervisor cannot stand up its enforcement
        // primitive), NOT a user-input path-resolution failure. Map to
        // ErrSandboxInit alongside LabelApplyFailed.
        nono::NonoError::BrokerNotFound { .. } => NonoErrorCode::ErrSandboxInit,
        // Phase 25-01: platform-specific feature rejection (e.g., --cpu-percent on macOS).
        // Maps to ErrUnsupportedPlatform so FFI consumers see the same code as
        // UnsupportedPlatform but with a structured feature field in the message.
        nono::NonoError::NotSupportedOnPlatform { .. } => NonoErrorCode::ErrUnsupportedPlatform,
        // Phase 37 D-06: kernel feature missing because the OS is misconfigured
        // (cgroup v1 instead of v2). Reuses ErrUnsupportedPlatform per D-06; the
        // FFI consumer reads the typed feature+hint via nono_last_error() Display
        // string. NO new NonoErrorCode is added (ABI-stable).
        nono::NonoError::UnsupportedKernelFeature { .. } => NonoErrorCode::ErrUnsupportedPlatform,
    }
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/// Convert a Rust `String` to a caller-owned C string.
///
/// Returns NULL and sets the last error if the string contains an interior
/// NUL byte (which would cause silent truncation in C).
pub(crate) fn rust_string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cstr) => cstr.into_raw(),
        Err(nul_err) => {
            set_last_error(&format!(
                "string contains interior NUL byte at position {}",
                nul_err.nul_position()
            ));
            std::ptr::null_mut()
        }
    }
}

/// Convert a C string pointer to a Rust `&str`.
///
/// Returns `None` if the pointer is null or the string is not valid UTF-8.
///
/// # Safety
///
/// The pointer must be null or point to a valid null-terminated C string
/// that remains valid for the lifetime `'a`.
pub(crate) unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees ptr is a valid null-terminated C string.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

// ---------------------------------------------------------------------------
// Public FFI: Error and string management
// ---------------------------------------------------------------------------

/// Get the last error message for the current thread.
///
/// Returns a caller-owned copy of the last error message as a
/// null-terminated UTF-8 string, or NULL if no error has occurred.
///
/// Caller must free the returned string with `nono_string_free()`.
#[unsafe(no_mangle)]
pub extern "C" fn nono_last_error() -> *mut c_char {
    LAST_ERROR.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            Some(cstr) => {
                // Return an independent copy so the caller owns the memory.
                // This avoids dangling pointers if set_last_error() is called
                // before the caller is done with the string.
                match CString::new(cstr.as_bytes().to_vec()) {
                    Ok(copy) => copy.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    })
}

/// Clear the last error for the current thread.
#[unsafe(no_mangle)]
pub extern "C" fn nono_clear_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Free a string previously returned by a nono FFI function.
///
/// NULL-safe (no-op on NULL). Call this on any string whose documentation
/// says "Caller must free with `nono_string_free()`", including
/// `nono_last_error()` and `nono_version()`.
///
/// # Safety
///
/// `s` must be NULL or a pointer previously returned by a nono FFI function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: The pointer was created by CString::into_raw() in this
        // library. The caller is required to only pass pointers from nono
        // FFI functions.
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

/// Get the nono library version string.
///
/// Caller must free the returned string with `nono_string_free()`.
#[unsafe(no_mangle)]
pub extern "C" fn nono_version() -> *mut c_char {
    rust_string_to_c(env!("CARGO_PKG_VERSION").to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Phase 36.5 D-36.5-B3: ActionRequired maps to ErrConfigParse (-9) in the
    /// C FFI layer. No new error code value is introduced.
    #[test]
    fn action_required_maps_to_err_config_parse() {
        let err = nono::NonoError::ActionRequired {
            expected: String::new(),
            actual: String::new(),
            resolve_via: "x".into(),
        };
        let code = map_error(&err);
        assert!(
            matches!(code, types::NonoErrorCode::ErrConfigParse),
            "ActionRequired must map to ErrConfigParse; got {code:?}"
        );
    }

    /// Phase 41 D-09 (CR-01): BrokerNotFound maps to ErrSandboxInit (-6),
    /// NOT ErrPathNotFound (-1). The broker-discovery failure is an
    /// installation/runtime defect (sandbox cannot init), not a user-input
    /// path-resolution failure. Locks the D-09 mapping against regression.
    #[test]
    fn broker_not_found_maps_to_err_sandbox_init() {
        let err = nono::NonoError::BrokerNotFound {
            path: std::path::PathBuf::from(r"C:\fake\nono-shell-broker.exe"),
        };
        let code = map_error(&err);
        assert!(
            matches!(code, types::NonoErrorCode::ErrSandboxInit),
            "BrokerNotFound must map to ErrSandboxInit; got {code:?}"
        );
    }

    /// Phase 37 D-06: `UnsupportedKernelFeature` reuses
    /// `ErrUnsupportedPlatform` — NO new FFI error code is added (ABI
    /// stability). FFI consumers read the typed `feature` + `hint` via the
    /// `nono_last_error()` Display string.
    #[test]
    fn map_error_unsupported_kernel_feature_returns_err_unsupported_platform() {
        let err = nono::NonoError::UnsupportedKernelFeature {
            feature: "cgroup_v2".into(),
            hint: "cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all".into(),
        };
        let code = map_error(&err);
        assert!(
            matches!(code, types::NonoErrorCode::ErrUnsupportedPlatform),
            "Phase 37 D-06: UnsupportedKernelFeature must map to ErrUnsupportedPlatform; got {code:?}"
        );
    }

    #[test]
    fn test_last_error_initially_null() {
        nono_clear_error();
        assert!(nono_last_error().is_null());
    }

    #[test]
    fn test_set_and_get_error() {
        set_last_error("test error message");
        let ptr = nono_last_error();
        assert!(!ptr.is_null());
        // SAFETY: ptr is a caller-owned CString, just returned above.
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or_default();
        assert_eq!(msg, "test error message");
        // SAFETY: ptr was returned by nono_last_error().
        unsafe { nono_string_free(ptr) };
        nono_clear_error();
        assert!(nono_last_error().is_null());
    }

    #[test]
    fn test_last_error_independent_copies() {
        // Each call to nono_last_error returns an independent copy, so
        // overwriting the stored error does not invalidate earlier pointers.
        set_last_error("first error");
        let ptr1 = nono_last_error();
        assert!(!ptr1.is_null());

        set_last_error("second error");

        // SAFETY: ptr1 is caller-owned, not tied to the thread-local.
        let msg1 = unsafe { CStr::from_ptr(ptr1) }.to_str().unwrap_or_default();
        assert_eq!(msg1, "first error");

        let ptr2 = nono_last_error();
        // SAFETY: ptr2 is caller-owned.
        let msg2 = unsafe { CStr::from_ptr(ptr2) }.to_str().unwrap_or_default();
        assert_eq!(msg2, "second error");

        // SAFETY: both pointers were returned by nono_last_error().
        unsafe {
            nono_string_free(ptr1);
            nono_string_free(ptr2);
        }
        nono_clear_error();
    }

    #[test]
    fn test_string_free_null_safe() {
        // SAFETY: deliberate NULL.
        unsafe { nono_string_free(std::ptr::null_mut()) };
    }

    #[test]
    fn test_version_not_null() {
        let v = nono_version();
        assert!(!v.is_null());
        // SAFETY: v was just returned by nono_version().
        let s = unsafe { CStr::from_ptr(v) }.to_str().unwrap_or_default();
        assert!(!s.is_empty());
        // SAFETY: v was returned by nono_version().
        unsafe { nono_string_free(v) };
    }

    #[test]
    fn test_rust_string_to_c_roundtrip() {
        let original = "hello nono".to_string();
        let c_ptr = rust_string_to_c(original);
        assert!(!c_ptr.is_null());
        // SAFETY: c_ptr was just created from a valid Rust string.
        let recovered = unsafe { CStr::from_ptr(c_ptr) }
            .to_str()
            .unwrap_or_default();
        assert_eq!(recovered, "hello nono");
        // SAFETY: c_ptr was created by rust_string_to_c.
        unsafe { nono_string_free(c_ptr) };
    }

    #[test]
    fn test_rust_string_to_c_rejects_interior_nul() {
        nono_clear_error();
        let with_nul = "hello\0world".to_string();
        let c_ptr = rust_string_to_c(with_nul);
        assert!(c_ptr.is_null());

        let err = nono_last_error();
        assert!(!err.is_null());
        // SAFETY: err was just returned by nono_last_error().
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap_or_default();
        assert!(
            msg.contains("interior NUL"),
            "error should mention interior NUL: {msg}"
        );
        // SAFETY: err was returned by nono_last_error().
        unsafe { nono_string_free(err) };
        nono_clear_error();
    }
}
