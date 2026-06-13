//! FFI wrapper for `nono::query::QueryContext`.

use std::os::raw::c_char;

use crate::capability_set::NonoCapabilitySet;
use crate::types::{
    NonoErrorCode, NonoQueryReason, NonoQueryResult, NonoQueryStatus, validate_access_mode,
};
use crate::{c_str_to_str, rust_string_to_c, set_last_error};

/// Opaque handle to a query context.
///
/// Created with `nono_query_context_new()`.
/// Freed with `nono_query_context_free()`.
pub struct NonoQueryContext {
    inner: nono::query::QueryContext,
}

/// Convert a library `QueryResult` to a C-compatible `NonoQueryResult`.
fn query_result_to_c(result: &nono::query::QueryResult) -> NonoQueryResult {
    match result {
        nono::query::QueryResult::Allowed(reason) => match reason {
            nono::query::AllowReason::GrantedPath {
                granted_path,
                access,
            } => NonoQueryResult {
                status: NonoQueryStatus::Allowed,
                reason: NonoQueryReason::GrantedPath,
                granted_path: rust_string_to_c(granted_path.clone()),
                access: rust_string_to_c(access.clone()),
                granted: std::ptr::null_mut(),
                requested: std::ptr::null_mut(),
            },
            nono::query::AllowReason::NetworkAllowed => NonoQueryResult {
                status: NonoQueryStatus::Allowed,
                reason: NonoQueryReason::NetworkAllowed,
                granted_path: std::ptr::null_mut(),
                access: std::ptr::null_mut(),
                granted: std::ptr::null_mut(),
                requested: std::ptr::null_mut(),
            },
        },
        nono::query::QueryResult::Denied(reason) => match reason {
            nono::query::DenyReason::PathNotGranted => NonoQueryResult {
                status: NonoQueryStatus::Denied,
                reason: NonoQueryReason::PathNotGranted,
                granted_path: std::ptr::null_mut(),
                access: std::ptr::null_mut(),
                granted: std::ptr::null_mut(),
                requested: std::ptr::null_mut(),
            },
            nono::query::DenyReason::InsufficientAccess { granted, requested } => NonoQueryResult {
                status: NonoQueryStatus::Denied,
                reason: NonoQueryReason::InsufficientAccess,
                granted_path: std::ptr::null_mut(),
                access: std::ptr::null_mut(),
                granted: rust_string_to_c(granted.clone()),
                requested: rust_string_to_c(requested.clone()),
            },
            nono::query::DenyReason::NetworkBlocked => NonoQueryResult {
                status: NonoQueryStatus::Denied,
                reason: NonoQueryReason::NetworkBlocked,
                granted_path: std::ptr::null_mut(),
                access: std::ptr::null_mut(),
                granted: std::ptr::null_mut(),
                requested: std::ptr::null_mut(),
            },
        },
    }
}

/// Create a query context from a capability set.
///
/// The capability set is cloned internally.
/// Caller must free with `nono_query_context_free()`.
///
/// # Safety
///
/// `caps` must be a valid pointer from `nono_capability_set_new()`.
/// Returns NULL if `caps` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_query_context_new(
    caps: *const NonoCapabilitySet,
) -> *mut NonoQueryContext {
    if caps.is_null() {
        return std::ptr::null_mut();
    }
    let caps = unsafe { &*caps };
    let ctx = NonoQueryContext {
        inner: nono::query::QueryContext::new(caps.inner.clone()),
    };
    Box::into_raw(Box::new(ctx))
}

/// Free a query context.
///
/// NULL-safe (no-op on NULL).
///
/// # Safety
///
/// `ctx` must be NULL or a pointer previously returned by
/// `nono_query_context_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_query_context_free(ctx: *mut NonoQueryContext) {
    if !ctx.is_null() {
        // SAFETY: The pointer was created by Box::into_raw() in
        // nono_query_context_new().
        unsafe {
            drop(Box::from_raw(ctx));
        }
    }
}

/// Query whether a path operation is permitted.
///
/// Writes the result to `out_result`. Returns `Ok` on success.
///
/// Caller must free non-NULL string fields in `out_result` with
/// `nono_string_free()`.
///
/// # Safety
///
/// - `ctx` must be a valid pointer from `nono_query_context_new()`.
/// - `path` must be a valid null-terminated UTF-8 string.
/// - `out_result` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_query_context_query_path(
    ctx: *const NonoQueryContext,
    path: *const c_char,
    mode: u32,
    out_result: *mut NonoQueryResult,
) -> NonoErrorCode {
    if ctx.is_null() || out_result.is_null() {
        set_last_error("ctx or out_result pointer is NULL");
        return NonoErrorCode::ErrInvalidArg;
    }

    let access = match validate_access_mode(mode) {
        Some(m) => m,
        None => {
            set_last_error(&format!("invalid access mode: {mode}"));
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    let path_str = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => {
            set_last_error("path is NULL or invalid UTF-8");
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    let ctx = unsafe { &*ctx };
    let result = ctx.inner.query_path(std::path::Path::new(path_str), access);

    // SAFETY: caller guarantees out_result is valid and writable.
    unsafe { *out_result = query_result_to_c(&result) };
    NonoErrorCode::Ok
}

/// Query whether network access is permitted.
///
/// Writes the result to `out_result`. Returns `Ok` on success.
///
/// # Safety
///
/// - `ctx` must be a valid pointer from `nono_query_context_new()`.
/// - `out_result` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_query_context_query_network(
    ctx: *const NonoQueryContext,
    out_result: *mut NonoQueryResult,
) -> NonoErrorCode {
    if ctx.is_null() || out_result.is_null() {
        set_last_error("ctx or out_result pointer is NULL");
        return NonoErrorCode::ErrInvalidArg;
    }

    let ctx = unsafe { &*ctx };
    let result = ctx.inner.query_network();

    // SAFETY: caller guarantees out_result is valid and writable.
    unsafe { *out_result = query_result_to_c(&result) };
    NonoErrorCode::Ok
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_set::{
        nono_capability_set_allow_path, nono_capability_set_free, nono_capability_set_new,
        nono_capability_set_set_network_blocked,
    };
    use std::ffi::CString;

    #[test]
    fn test_query_context_lifecycle() {
        let caps = nono_capability_set_new();
        // SAFETY: caps is valid.
        unsafe {
            let ctx = nono_query_context_new(caps);
            assert!(!ctx.is_null());
            nono_query_context_free(ctx);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_query_context_null_safe() {
        // SAFETY: deliberate NULL.
        unsafe {
            assert!(nono_query_context_new(std::ptr::null()).is_null());
            nono_query_context_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn test_query_network_blocked() {
        let caps = nono_capability_set_new();
        // SAFETY: caps is valid.
        unsafe {
            nono_capability_set_set_network_blocked(caps, true);
            let ctx = nono_query_context_new(caps);

            let mut result = std::mem::zeroed::<NonoQueryResult>();
            let rc = nono_query_context_query_network(ctx, &mut result);
            assert_eq!(rc, NonoErrorCode::Ok);
            assert_eq!(result.status, NonoQueryStatus::Denied);
            assert_eq!(result.reason, NonoQueryReason::NetworkBlocked);

            nono_query_context_free(ctx);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_query_network_allowed() {
        let caps = nono_capability_set_new();
        // SAFETY: caps is valid.
        unsafe {
            let ctx = nono_query_context_new(caps);

            let mut result = std::mem::zeroed::<NonoQueryResult>();
            let rc = nono_query_context_query_network(ctx, &mut result);
            assert_eq!(rc, NonoErrorCode::Ok);
            assert_eq!(result.status, NonoQueryStatus::Allowed);
            assert_eq!(result.reason, NonoQueryReason::NetworkAllowed);

            nono_query_context_free(ctx);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_query_path_granted() {
        let caps = nono_capability_set_new();
        let path = CString::new("/tmp").unwrap_or_default();
        // SAFETY: caps and path are valid.
        unsafe {
            nono_capability_set_allow_path(
                caps,
                path.as_ptr(),
                crate::types::NONO_ACCESS_MODE_READ_WRITE,
            );
            let ctx = nono_query_context_new(caps);

            // On macOS /tmp canonicalizes to /private/tmp, so query with
            // the canonical path to match the resolved capability.
            let canonical_tmp =
                std::fs::canonicalize("/tmp").unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
            let query_str = format!("{}/test.txt", canonical_tmp.display());
            let query_path = CString::new(query_str).unwrap_or_default();
            let mut result = std::mem::zeroed::<NonoQueryResult>();
            let rc = nono_query_context_query_path(
                ctx,
                query_path.as_ptr(),
                crate::types::NONO_ACCESS_MODE_READ,
                &mut result,
            );
            assert_eq!(rc, NonoErrorCode::Ok);
            assert_eq!(result.status, NonoQueryStatus::Allowed);
            assert_eq!(result.reason, NonoQueryReason::GrantedPath);
            assert!(!result.granted_path.is_null());
            assert!(!result.access.is_null());

            crate::nono_string_free(result.granted_path);
            crate::nono_string_free(result.access);
            nono_query_context_free(ctx);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_query_path_denied() {
        let caps = nono_capability_set_new();
        // SAFETY: caps is valid.
        unsafe {
            let ctx = nono_query_context_new(caps);

            let query_path = CString::new("/secret/data").unwrap_or_default();
            let mut result = std::mem::zeroed::<NonoQueryResult>();
            let rc = nono_query_context_query_path(
                ctx,
                query_path.as_ptr(),
                crate::types::NONO_ACCESS_MODE_READ,
                &mut result,
            );
            assert_eq!(rc, NonoErrorCode::Ok);
            assert_eq!(result.status, NonoQueryStatus::Denied);
            assert_eq!(result.reason, NonoQueryReason::PathNotGranted);

            nono_query_context_free(ctx);
            nono_capability_set_free(caps);
        }
    }
}
