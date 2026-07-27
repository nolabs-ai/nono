//! FFI wrapper for `nono::Sandbox` static functions.

use crate::capability_set::NonoCapabilitySet;
use crate::types::{NonoErrorCode, NonoSupportInfo};
use crate::{map_error, rust_string_to_c, set_last_error};

/// Apply the sandbox with the given capabilities.
///
/// This is **irreversible**. Once applied, the current process and all
/// children can only access resources granted by the capabilities.
///
/// Returns `Ok` on success.
///
/// # Safety
///
/// `caps` must be a valid pointer from `nono_capability_set_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_sandbox_apply(caps: *const NonoCapabilitySet) -> NonoErrorCode {
    if caps.is_null() {
        set_last_error("caps pointer is NULL");
        return NonoErrorCode::ErrInvalidArg;
    }
    let caps = unsafe { &*caps };
    match nono::Sandbox::apply_auto(&caps.inner) {
        Ok(_) => NonoErrorCode::Ok,
        Err(e) => map_error(&e),
    }
}

/// Check if sandboxing is supported on this platform.
#[unsafe(no_mangle)]
pub extern "C" fn nono_sandbox_is_supported() -> bool {
    nono::Sandbox::is_supported()
}

/// Get detailed platform support information.
///
/// Caller must free `platform` and `details` fields with
/// `nono_string_free()`.
#[unsafe(no_mangle)]
pub extern "C" fn nono_sandbox_support_info() -> NonoSupportInfo {
    let info = nono::Sandbox::support_info();
    NonoSupportInfo {
        is_supported: info.is_supported,
        platform: rust_string_to_c(info.platform.to_string()),
        details: rust_string_to_c(info.details),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_is_supported() {
        // Just verify it does not panic.
        let _ = nono_sandbox_is_supported();
    }

    #[test]
    fn test_support_info() {
        let info = nono_sandbox_support_info();
        assert!(!info.platform.is_null());
        assert!(!info.details.is_null());
        // SAFETY: pointers are valid, just returned.
        unsafe {
            let platform = CStr::from_ptr(info.platform).to_str().unwrap_or_default();
            assert!(!platform.is_empty());
        }
        // SAFETY: pointers were returned by nono_sandbox_support_info().
        unsafe {
            crate::nono_string_free(info.platform);
            crate::nono_string_free(info.details);
        }
    }

    #[test]
    fn test_apply_null_safe() {
        // SAFETY: deliberate NULL.
        unsafe {
            let rc = nono_sandbox_apply(std::ptr::null());
            assert_eq!(rc, NonoErrorCode::ErrInvalidArg);
        }
    }
}
