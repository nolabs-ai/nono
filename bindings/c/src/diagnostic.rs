//! C FFI for session diagnostics and error remediation.

use crate::types::NonoDiagnosticCode;
use crate::{map_error, rust_string_to_c, set_last_error};
use std::os::raw::c_char;

/// Return the diagnostic code for the most recently mapped error on this thread.
///
/// Returns `NonoDiagnosticCode::Other` when no error has been mapped.
#[unsafe(no_mangle)]
pub extern "C" fn nono_last_diagnostic_code() -> NonoDiagnosticCode {
    crate::last_diagnostic_code()
}

/// Return JSON for the remediation attached to the most recently mapped error.
///
/// Caller must free with `nono_string_free()`. Returns NULL when no remediation exists.
#[unsafe(no_mangle)]
pub extern "C" fn nono_last_remediation_json() -> *mut c_char {
    match crate::last_remediation_json() {
        Some(json) => rust_string_to_c(json),
        None => std::ptr::null_mut(),
    }
}

/// Build a session diagnostic report JSON object from serialized denial inputs.
///
/// Each `*_json` argument may be NULL, an empty string, or a JSON array of
/// denial, IPC denial, or violation records.
///
/// # Safety
///
/// Pointer arguments must be null or valid null-terminated UTF-8 for the
/// duration of the call. Caller frees the returned string with `nono_string_free()`.
/// Returns NULL on failure; call `nono_last_error()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_session_diagnostic_report_to_json(
    exit_code: i32,
    denials_json: *const c_char,
    ipc_denials_json: *const c_char,
    violations_json: *const c_char,
) -> *mut c_char {
    let denials = match parse_denials(denials_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&e);
            return std::ptr::null_mut();
        }
    };
    let ipc_denials = match parse_ipc_denials(ipc_denials_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&e);
            return std::ptr::null_mut();
        }
    };
    let violations = match parse_violations(violations_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&e);
            return std::ptr::null_mut();
        }
    };

    let report = nono::SessionDiagnosticReport::from_merged_session(
        exit_code,
        denials,
        ipc_denials,
        violations,
    );
    match report.to_json() {
        Ok(json) => rust_string_to_c(json),
        Err(e) => {
            map_error(&e);
            std::ptr::null_mut()
        }
    }
}

/// Merge session report JSON with an optional proxy diagnostics JSON array.
///
/// `session_json` must be a report object from `nono_session_diagnostic_report_to_json`
/// or `SessionDiagnosticReport::to_json()`. `proxy_diagnostics_json` may be NULL
/// or empty to return `{ "session": ... }` only.
///
/// # Safety
///
/// Pointer arguments must be null or valid null-terminated UTF-8 for the
/// duration of the call. Caller frees the returned string with `nono_string_free()`.
/// Returns NULL on failure; call `nono_last_error()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_merge_diagnostic_report_json(
    session_json: *const c_char,
    proxy_diagnostics_json: *const c_char,
) -> *mut c_char {
    if session_json.is_null() {
        set_last_error("session_json is null");
        return std::ptr::null_mut();
    }
    let Some(session_text) = (unsafe { crate::c_str_to_str(session_json) }) else {
        set_last_error("invalid UTF-8 in session_json");
        return std::ptr::null_mut();
    };
    let proxy_text = if proxy_diagnostics_json.is_null() {
        None
    } else {
        unsafe { crate::c_str_to_str(proxy_diagnostics_json) }
    };
    match nono::SessionDiagnosticReport::merge_with_proxy_json(session_text, proxy_text) {
        Ok(json) => rust_string_to_c(json),
        Err(e) => {
            map_error(&e);
            std::ptr::null_mut()
        }
    }
}

fn parse_json_array<T: serde::de::DeserializeOwned>(
    ptr: *const c_char,
    label: &str,
) -> Result<Vec<T>, String> {
    if ptr.is_null() {
        return Ok(Vec::new());
    }
    let Some(text) = (unsafe { crate::c_str_to_str(ptr) }) else {
        return Err(format!("invalid UTF-8 in {label}"));
    };
    if text.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(text).map_err(|e| format!("invalid {label} JSON array: {e}"))
}

fn parse_denials(ptr: *const c_char) -> Result<Vec<nono::DenialRecord>, String> {
    parse_json_array(ptr, "denial")
}

fn parse_ipc_denials(ptr: *const c_char) -> Result<Vec<nono::IpcDenialRecord>, String> {
    parse_json_array(ptr, "IPC denial")
}

fn parse_violations(ptr: *const c_char) -> Result<Vec<nono::SandboxViolation>, String> {
    parse_json_array(ptr, "violation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NonoDiagnosticCode;
    use std::ffi::CStr;

    #[test]
    fn last_diagnostic_code_defaults_to_other() {
        assert_eq!(nono_last_diagnostic_code(), NonoDiagnosticCode::Other);
    }

    #[test]
    fn session_report_json_from_empty_arrays() {
        let json_ptr = unsafe {
            nono_session_diagnostic_report_to_json(
                1,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert!(!json_ptr.is_null());
        // SAFETY: returned by nono_session_diagnostic_report_to_json in this test.
        let json = unsafe { CStr::from_ptr(json_ptr) }.to_str().expect("utf8");
        assert!(json.contains("\"exit_code\":1"));
        unsafe { crate::nono_string_free(json_ptr) };
    }

    #[test]
    fn session_report_json_from_denial_array() {
        let denials = r#"[{"path":"/tmp/x","access":"Read","reason":"PolicyBlocked"}]"#;
        let denials_c = std::ffi::CString::new(denials).expect("cstr");
        let json_ptr = unsafe {
            nono_session_diagnostic_report_to_json(
                2,
                denials_c.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert!(!json_ptr.is_null());
        let json = unsafe { CStr::from_ptr(json_ptr) }.to_str().expect("utf8");
        assert!(json.contains("sandbox_denied_path"));
        assert!(json.contains("grant_path"));
        unsafe { crate::nono_string_free(json_ptr) };
    }

    #[test]
    fn merge_diagnostic_report_json_rejects_null_session() {
        let json_ptr =
            unsafe { nono_merge_diagnostic_report_json(std::ptr::null(), std::ptr::null()) };
        assert!(json_ptr.is_null());
        let err = unsafe { CStr::from_ptr(crate::nono_last_error()) }
            .to_str()
            .expect("utf8");
        assert!(err.contains("session_json is null"));
    }

    #[test]
    fn merge_diagnostic_report_json_wraps_proxy_array() {
        let session = std::ffi::CString::new(
            r#"{"exit_code":1,"denials":[],"ipc_denials":[],"violations":[],"diagnostics":[]}"#,
        )
        .expect("cstr");
        let proxy = std::ffi::CString::new(
            r#"[{"code":"credential_not_found","severity":"warning","route_prefix":"openai","message":"missing"}]"#,
        )
        .expect("cstr");
        let json_ptr =
            unsafe { nono_merge_diagnostic_report_json(session.as_ptr(), proxy.as_ptr()) };
        assert!(!json_ptr.is_null());
        let json = unsafe { CStr::from_ptr(json_ptr) }.to_str().expect("utf8");
        assert!(json.contains("\"session\""));
        assert!(json.contains("credential_not_found"));
        unsafe { crate::nono_string_free(json_ptr) };
    }
}
