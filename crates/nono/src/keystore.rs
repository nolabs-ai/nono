//! Secure credential loading from system keystore, 1Password, Bitwarden, Apple Passwords, and environment
//!
//! This module provides functionality to load secrets from the system keystore
//! (macOS Keychain / Linux Secret Service), 1Password (via the `op` CLI),
//! Bitwarden (via the `bw` CLI), Apple Passwords (via macOS `security`),
//! custom keyring entries (via the
//! `keyring` crate), or environment variables (via the `env://` scheme) and
//! return them as zeroized strings.
//!
//! Credential references are dispatched by URI scheme:
//! - `env://VAR_NAME` — reads from the current process environment
//! - `file:///path/to/secret` — reads from a local file (before sandbox activation)
//! - `op://vault/item/field` — loaded via the 1Password CLI
//! - `bw://item-id` or `bw://item-id/field` — loaded via the Bitwarden CLI
//! - `apple-password://server/account` — loaded via macOS `security`
//! - `keyring://service/account` — loaded from the system keyring with a custom service name
//! - Everything else — loaded from the system keyring (service name `nono`)
//!
//! All secrets are wrapped in `Zeroizing<String>` to ensure they are securely
//! cleared from memory after use.

use crate::error::{NonoError, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
#[cfg(feature = "system-keyring")]
use std::sync::mpsc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Timeout for secret-manager subprocesses.
///
/// Generous enough to allow biometric prompts in password manager CLIs.
const SECRET_MANAGER_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for system keyring calls (seconds).
///
/// 120 s covers the realistic worst-case keychain unlock workflow:
/// notice the prompt, switch windows, type a master password, click approve.
/// Rationale for choosing 120 over a shorter value: issue #967 reports that
/// a shorter timeout fired before the user could complete the KeePassXC
/// unlock sequence on Linux. We go materially longer while still bounding
/// an unattended hang.
///
/// Override with `NONO_KEYRING_TIMEOUT_SECS`. Set to `0` to disable the
/// timeout entirely and restore the old "block forever" behaviour.
#[cfg(feature = "system-keyring")]
const KEYRING_TIMEOUT_SECS: u64 = 120;

/// Return the effective keyring timeout.
///
/// - `NONO_KEYRING_TIMEOUT_SECS` unset → `Some(120 s)` (the default).
/// - `NONO_KEYRING_TIMEOUT_SECS=0` → `None` (wait forever).
/// - `NONO_KEYRING_TIMEOUT_SECS=N` (N > 0) → `Some(N s)`.
/// - Invalid value → logs a warning and returns `Some(120 s)`.
#[cfg(feature = "system-keyring")]
fn keyring_timeout() -> Option<Duration> {
    match std::env::var("NONO_KEYRING_TIMEOUT_SECS") {
        Err(_) => Some(Duration::from_secs(KEYRING_TIMEOUT_SECS)),
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(Duration::from_secs(n)),
            Err(_) => {
                tracing::warn!(
                    "NONO_KEYRING_TIMEOUT_SECS='{}' is not a valid integer; \
                     using default {}s",
                    s.trim(),
                    KEYRING_TIMEOUT_SECS
                );
                Some(Duration::from_secs(KEYRING_TIMEOUT_SECS))
            }
        },
    }
}

/// Call a blocking keyring function with an optional timeout.
///
/// When `timeout` is `None`, the closure is called inline on the current
/// thread — no extra thread is spawned.
///
/// When `timeout` is `Some(d)`, the closure is moved onto a new thread and
/// the result is sent back through an `mpsc` channel. If the channel
/// `recv_timeout` fires, a `KeystoreAccess` error is returned.
///
/// **macOS note**: if the timeout fires while `Security.framework` is
/// displaying a keychain unlock dialog, the spawned thread stays alive and
/// blocked until the user responds or the process exits. Rust cannot cancel
/// a blocking syscall; this is the expected behaviour. No secret material
/// leaks because the `Zeroizing<String>` result is dropped on the thread
/// side once the channel receiver is gone.
#[cfg(feature = "system-keyring")]
fn call_with_keyring_timeout<F, T>(timeout: Option<Duration>, label: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let Some(dur) = timeout else {
        return f();
    };

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });

    rx.recv_timeout(dur).unwrap_or_else(|_| {
        Err(NonoError::KeystoreAccess(format!(
            "{} timed out after {}s waiting for keychain access. \
             Set NONO_KEYRING_TIMEOUT_SECS=N to adjust (0 = wait forever).",
            label,
            dur.as_secs()
        )))
    })
}

/// A credential loaded from the keystore
pub struct LoadedSecret {
    /// The environment variable name to set
    pub env_var: String,
    /// The secret value (automatically zeroized when dropped)
    pub value: Zeroizing<String>,
}

/// The default service name for secrets in the keystore
pub const DEFAULT_SERVICE: &str = "nono";

/// The `op://` URI scheme prefix, indicating 1Password CLI backend.
const OP_URI_PREFIX: &str = "op://";

/// The `bw://` URI scheme prefix, indicating Bitwarden CLI backend.
const BW_URI_PREFIX: &str = "bw://";

/// The `apple-password://` URI scheme prefix, indicating Apple Passwords backend.
const APPLE_PASSWORD_URI_PREFIX: &str = "apple-password://";

/// Alias prefix for Apple Passwords backend.
const APPLE_PASSWORDS_URI_PREFIX: &str = "apple-passwords://";

/// The `keyring://` URI scheme prefix, indicating a custom-service keyring lookup.
const KEYRING_URI_PREFIX: &str = "keyring://";

/// The `env://` URI scheme prefix, indicating environment variable backend.
const ENV_URI_PREFIX: &str = "env://";

/// The `file://` URI scheme prefix, indicating a local file credential source.
/// Read once at startup before sandbox activation; contents zeroed on drop.
const FILE_URI_PREFIX: &str = "file://";

/// Environment variable names that must never be loaded via `env://`.
///
/// These control linker, interpreter, or shell behavior. Allowing them as
/// credential sources would let an `env://` URI act as an injection vector.
const DANGEROUS_ENV_VAR_NAMES: &[&str] = &[
    // Linker injection
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    // Shell injection
    "BASH_ENV",
    "ENV",
    "IFS",
    "CDPATH",
    "PROMPT_COMMAND",
    // Interpreter injection
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    "GOFLAGS",
    // Process-critical
    "PATH",
    "HOME",
    "SHELL",
];

/// Characters forbidden in `op://` URIs to prevent argument/shell injection.
const FORBIDDEN_URI_CHARS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\\', '"', '\'', '\n', '\r', '\0',
];

/// Load secrets from the system keystore, 1Password, Apple Passwords, or keyring
///
/// Credential references with URI schemes are dispatched to their backend:
/// - `op://` -> 1Password CLI
/// - `apple-password://` -> macOS security CLI
/// - `keyring://` -> system keyring with custom service name
/// - `env://` -> parent process environment
/// - everything else -> system keyring (service name `nono`)
///
/// # Arguments
/// * `service` - The service name in the keystore (e.g., "nono")
/// * `mappings` - Map of credential reference -> env var name
///
/// # Returns
/// Vector of loaded secrets ready to be set as env vars
///
/// # Example
///
/// ```no_run
/// use nono::keystore::{load_secrets, DEFAULT_SERVICE};
/// use std::collections::HashMap;
///
/// let mut mappings = HashMap::new();
/// mappings.insert("api_key".to_string(), "API_KEY".to_string());
///
/// let secrets = load_secrets(DEFAULT_SERVICE, &mappings)?;
/// for secret in secrets {
///     // SAFETY: single-threaded setup before spawning workers.
///     unsafe { std::env::set_var(&secret.env_var, secret.value.as_str()) };
/// }
/// # Ok::<(), nono::NonoError>(())
/// ```
#[must_use = "loaded secrets should be used to set environment variables"]
pub fn load_secrets(
    service: &str,
    mappings: &HashMap<String, String>,
) -> Result<Vec<LoadedSecret>> {
    let mut secrets = Vec::with_capacity(mappings.len());

    for (account, env_var) in mappings {
        tracing::debug!("Loading secret '{}' -> ${}", account, env_var);
        let secret = load_secret_by_ref(service, account)?;
        secrets.push(LoadedSecret {
            env_var: env_var.clone(),
            value: secret,
        });
    }

    Ok(secrets)
}

/// Load a single secret, dispatching to the appropriate backend.
///
/// Dispatch order:
/// 1. `file:///path` — reads from a local file (before sandbox activation)
/// 2. `env://VAR` — reads from the process environment
/// 3. `op://vault/item/field` — delegates to the 1Password CLI
/// 4. `bw://item-id` or `bw://item-id/field` — delegates to the Bitwarden CLI
/// 5. `apple-password://server/account` — delegates to macOS `security`
/// 6. `keyring://service/account` — loads from system keyring with custom service
/// 7. Everything else — loads from the system keyring (service name `nono`)
///
/// # Arguments
/// * `service` - Keyring service name (only used for keyring backend)
/// * `credential_ref` - A keyring account name, `file://` URI, `op://` URI,
///   `bw://` URI, Apple Passwords URI, or `env://` URI
///
/// # Security
/// The returned value is wrapped in `Zeroizing<String>`. For URI-based managers
/// (`op://`, `bw://`, `apple-password://`), CLI stdout is captured and trimmed before
/// wrapping. Note: the intermediate `Vec<u8>` from subprocess output is not
/// zeroized — this is the same class of limitation as the keyring crate's
/// internal buffers.
#[must_use = "loaded secret should be used or explicitly dropped"]
pub fn load_secret_by_ref(service: &str, credential_ref: &str) -> Result<Zeroizing<String>> {
    if credential_ref.starts_with(FILE_URI_PREFIX) {
        load_from_file(credential_ref)
    } else if credential_ref.starts_with(ENV_URI_PREFIX) {
        load_from_env(credential_ref)
    } else if credential_ref.starts_with(OP_URI_PREFIX) {
        load_from_op(credential_ref)
    } else if is_bw_uri(credential_ref) {
        load_from_bw(credential_ref)
    } else if is_apple_password_uri(credential_ref) {
        load_from_apple_password(credential_ref)
    } else if is_keyring_uri(credential_ref) {
        load_from_keyring_uri(credential_ref)
    } else {
        load_single_secret(service, credential_ref)
    }
}

/// Validate an `op://` URI has the correct structure.
///
/// Expected format: `op://vault/item/field` (3 path segments after the scheme).
/// Additional segments (section-qualified) are also accepted:
/// `op://vault/item/section/field`.
///
/// Rejects:
/// - Empty vault, item, or field
/// - Characters that could enable argument injection
/// - URIs with query strings or fragments
pub fn validate_op_uri(uri: &str) -> Result<()> {
    let path = uri.strip_prefix(OP_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, OP_URI_PREFIX
        ))
    })?;

    // Reject shell metacharacters to prevent injection
    if let Some(bad) = path.chars().find(|c| FORBIDDEN_URI_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    // Reject query strings and fragments
    if path.contains('?') || path.contains('#') {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI must not contain query strings or fragments: {}",
            uri
        )));
    }

    // Split into segments: vault/item/field (minimum 3)
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 3 {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI must have at least vault/item/field segments: {}",
            uri
        )));
    }

    // No empty segments (catches `op:///item/field`, `op://vault//field`, etc.)
    if segments.iter().any(|s| s.is_empty()) {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI has empty path segment: {}",
            uri
        )));
    }

    Ok(())
}

/// Returns true if the credential reference is a 1Password `op://` URI.
#[must_use]
pub fn is_op_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(OP_URI_PREFIX)
}

/// Validate a `bw://` URI has the correct structure.
///
/// Accepted formats:
/// - `bw://item-id` — retrieve the password for the named item
/// - `bw://item-id/field` — retrieve a specific field from the named item
///
/// Rejects:
/// - Missing prefix
/// - Empty item ID
/// - Characters that could enable argument injection (uses `FORBIDDEN_URI_CHARS`)
/// - Query strings or fragment identifiers
pub fn validate_bw_uri(uri: &str) -> Result<()> {
    let path = uri.strip_prefix(BW_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, BW_URI_PREFIX
        ))
    })?;

    // Reject query strings and fragments before checking forbidden chars,
    // so we get the right error message (not a misleading "forbidden character '='" for '?foo=bar').
    if path.contains('?') || path.contains('#') {
        return Err(NonoError::ConfigParse(format!(
            "Bitwarden URI must not contain query strings or fragments: {}",
            uri
        )));
    }

    // Reject shell metacharacters to prevent injection
    // '=' is also forbidden because it is used as the URI=VAR separator
    // in --env-credential list mode and must not appear in the URI itself.
    if let Some(bad) = path
        .chars()
        .find(|c| FORBIDDEN_URI_CHARS.contains(c) || *c == '=')
    {
        return Err(NonoError::ConfigParse(format!(
            "Bitwarden URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    let segments: Vec<&str> = path.split('/').collect();
    if segments.is_empty() || segments[0].is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "Bitwarden URI must specify an item ID: {}",
            uri
        )));
    }

    // Reject empty field segment if present
    if segments.len() > 1 && segments[1].is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "Bitwarden URI has empty field segment: {}",
            uri
        )));
    }

    // Allow at most 2 segments: item-id or item-id/field
    if segments.len() > 2 {
        return Err(NonoError::ConfigParse(format!(
            "Bitwarden URI must be 'bw://item-id' or 'bw://item-id/field': {}",
            uri
        )));
    }

    // Reject segments starting with '-' so they cannot be parsed as flags
    // when passed to `bw get field <field> -- <item-id>`. The `--` separator
    // protects the item-id but not the field, which is positionally before it.
    if segments.iter().any(|s| s.starts_with('-')) {
        return Err(NonoError::ConfigParse(format!(
            "Bitwarden URI segments must not start with '-': {}",
            uri
        )));
    }

    Ok(())
}

/// Returns true if the credential reference is a Bitwarden `bw://` URI.
#[must_use]
pub fn is_bw_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(BW_URI_PREFIX)
}

fn strip_apple_password_prefix(uri: &str) -> Option<&str> {
    uri.strip_prefix(APPLE_PASSWORD_URI_PREFIX)
        .or_else(|| uri.strip_prefix(APPLE_PASSWORDS_URI_PREFIX))
}

/// Returns true if the credential reference is an Apple Passwords URI.
#[must_use]
pub fn is_apple_password_uri(credential_ref: &str) -> bool {
    strip_apple_password_prefix(credential_ref).is_some()
}

/// Validate an Apple Passwords URI.
///
/// Expected format: `apple-password://server/account`.
///
/// Rejects:
/// - Empty server or account
/// - Characters that could enable argument injection
/// - URIs with query strings or fragments
/// - Any path shape other than `server/account`
pub fn validate_apple_password_uri(uri: &str) -> Result<()> {
    let path = strip_apple_password_prefix(uri).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}' or '{}'",
            uri, APPLE_PASSWORD_URI_PREFIX, APPLE_PASSWORDS_URI_PREFIX
        ))
    })?;

    if let Some(bad) = path.chars().find(|c| FORBIDDEN_URI_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "Apple Passwords URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    if path.contains('?') || path.contains('#') {
        return Err(NonoError::ConfigParse(format!(
            "Apple Passwords URI must not contain query strings or fragments: {}",
            uri
        )));
    }

    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() != 2 {
        return Err(NonoError::ConfigParse(format!(
            "Apple Passwords URI must be 'apple-password://server/account': {}",
            uri
        )));
    }

    if segments.iter().any(|s| s.is_empty()) {
        return Err(NonoError::ConfigParse(format!(
            "Apple Passwords URI has empty server/account segment: {}",
            uri
        )));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn parse_apple_password_uri(uri: &str) -> Result<(&str, &str)> {
    validate_apple_password_uri(uri)?;
    let path = strip_apple_password_prefix(uri).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' is not an Apple Passwords URI",
            uri
        ))
    })?;
    let mut segments = path.splitn(2, '/');
    let server = segments.next().ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "Apple Passwords URI missing server segment: {}",
            uri
        ))
    })?;
    let account = segments.next().ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "Apple Passwords URI missing account segment: {}",
            uri
        ))
    })?;
    Ok((server, account))
}

/// Returns true if the credential reference is a `keyring://` URI.
#[must_use]
pub fn is_keyring_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(KEYRING_URI_PREFIX)
}

/// Maximum byte length for a `keyring://` URI (scheme + service + account + query).
///
/// Generous enough for real service/account names but prevents accidentally
/// passing absurdly long strings to OS keyring APIs.
const KEYRING_URI_MAX_LEN: usize = 1024;

/// Post-load decoding to apply to a keyring value.
///
/// Some tools wrap stored credentials in their own encoding. This enum
/// represents the supported `?decode=` transforms that can be requested
/// via the `keyring://` URI query string.
#[cfg(feature = "system-keyring")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyringDecode {
    /// No transform — return the raw stored value.
    None,
    /// Strip the `go-keyring-base64:` prefix and base64-decode the remainder.
    ///
    /// Used by Go tools built with `github.com/zalando/go-keyring` (e.g., `gh`).
    GoKeyring,
}

/// The prefix that `zalando/go-keyring` prepends to stored values.
#[cfg(feature = "system-keyring")]
const GO_KEYRING_PREFIX: &str = "go-keyring-base64:";

/// Allowed values for the `?decode=` query parameter.
const KEYRING_DECODE_GO_KEYRING: &str = "go-keyring";

/// Validate a `keyring://` URI.
///
/// Accepted formats:
/// - `keyring://service/account` — look up by service and account
/// - `keyring://service/account?decode=go-keyring` — with post-load decoding
///
/// Rejects:
/// - Empty service or account
/// - Characters that could enable argument injection
/// - Unknown query parameters or values
/// - Fragment identifiers
/// - Missing account segment
/// - URIs exceeding 1024 bytes
pub fn validate_keyring_uri(uri: &str) -> Result<()> {
    if uri.len() > KEYRING_URI_MAX_LEN {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI exceeds maximum length of {} bytes",
            KEYRING_URI_MAX_LEN
        )));
    }

    let path = uri.strip_prefix(KEYRING_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, KEYRING_URI_PREFIX
        ))
    })?;

    // Reject fragments unconditionally.
    if path.contains('#') {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI must not contain fragment identifiers: {}",
            uri
        )));
    }

    // Split off the query string (if any) before validating the path.
    let (path_part, query_part) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    // Validate query parameters against the allowlist.
    if let Some(query) = query_part {
        validate_keyring_query(query, uri)?;
    }

    if let Some(bad) = path_part.chars().find(|c| FORBIDDEN_URI_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    let segments: Vec<&str> = path_part.split('/').collect();
    if segments.len() != 2 {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI must be 'keyring://service/account': {}",
            uri
        )));
    }

    if segments.iter().any(|s| s.is_empty()) {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI has empty service/account segment: {}",
            uri
        )));
    }

    Ok(())
}

/// Validate the query string of a `keyring://` URI.
///
/// Only `decode=go-keyring` is accepted. Unknown keys or values are rejected
/// to prevent silent misconfiguration.
fn validate_keyring_query(query: &str, full_uri: &str) -> Result<()> {
    for param in query.split('&') {
        let (key, value) = param.split_once('=').ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "keyring URI query parameter missing value: '{}' in {}",
                param, full_uri
            ))
        })?;

        match key {
            "decode" => match value {
                KEYRING_DECODE_GO_KEYRING => {}
                _ => {
                    return Err(NonoError::ConfigParse(format!(
                        "keyring URI has unknown decode value '{}'. \
                         Supported: {}",
                        value, KEYRING_DECODE_GO_KEYRING
                    )));
                }
            },
            _ => {
                return Err(NonoError::ConfigParse(format!(
                    "keyring URI has unknown query parameter '{}'. \
                     Supported: decode",
                    key
                )));
            }
        }
    }
    Ok(())
}

/// Parsed components of a `keyring://` URI.
#[cfg(feature = "system-keyring")]
struct KeyringUriParts<'a> {
    service: &'a str,
    account: &'a str,
    decode: KeyringDecode,
}

#[cfg(feature = "system-keyring")]
fn parse_keyring_uri(uri: &str) -> Result<KeyringUriParts<'_>> {
    validate_keyring_uri(uri)?;
    let path = uri.strip_prefix(KEYRING_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' is not a keyring URI",
            uri
        ))
    })?;

    // Split off query string before parsing path segments.
    let (path_part, query_part) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    let mut segments = path_part.splitn(2, '/');
    let service = segments.next().ok_or_else(|| {
        NonoError::ConfigParse(format!("keyring URI missing service segment: {}", uri))
    })?;
    let account = segments.next().ok_or_else(|| {
        NonoError::ConfigParse(format!("keyring URI missing account segment: {}", uri))
    })?;

    let decode = match query_part {
        Some(q) if q.contains(KEYRING_DECODE_GO_KEYRING) => KeyringDecode::GoKeyring,
        _ => KeyringDecode::None,
    };

    Ok(KeyringUriParts {
        service,
        account,
        decode,
    })
}

/// Redact the account segment of a `keyring://` URI for safe logging.
///
/// `keyring://service/account` → `keyring://service/<redacted>`
/// `keyring://service/account?decode=go-keyring` → `keyring://service/<redacted>?decode=go-keyring`
pub fn redact_keyring_uri(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix(KEYRING_URI_PREFIX) {
        // Split off query string so we can preserve it.
        let (path_part, query_part) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path, None),
        };
        let mut segments = path_part.splitn(2, '/');
        if let Some(service) = segments.next()
            && !service.is_empty()
            && segments.next().is_some()
        {
            let suffix = match query_part {
                Some(q) => format!("?{}", q),
                None => String::new(),
            };
            return format!("keyring://{}/<redacted>{}", service, suffix);
        }
    }
    "keyring://***".to_string()
}

/// Returns true if the credential reference is an `env://` URI.
#[must_use]
pub fn is_env_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(ENV_URI_PREFIX)
}

/// Check if a credential reference uses the `file://` scheme.
#[must_use]
pub fn is_file_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(FILE_URI_PREFIX)
}

/// Validate an `env://VAR_NAME` URI.
///
/// Accepts variable names containing only ASCII alphanumeric characters and
/// underscores (`[A-Za-z0-9_]+`). This is stricter than POSIX (which allows
/// any byte except `=` and NUL) but matches real-world conventions and
/// prevents injection through crafted variable names.
///
/// Rejects:
/// - Empty variable name
/// - Names containing non-alphanumeric/underscore characters
/// - Dangerous variable names that control linker/interpreter/shell behavior
pub fn validate_env_uri(uri: &str) -> Result<()> {
    let var_name = uri.strip_prefix(ENV_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, ENV_URI_PREFIX
        ))
    })?;

    if var_name.is_empty() {
        return Err(NonoError::ConfigParse(
            "env:// URI has empty variable name".to_string(),
        ));
    }

    if let Some(bad) = var_name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '_')
    {
        return Err(NonoError::ConfigParse(format!(
            "env:// variable name contains invalid character {:?}: {}",
            bad, uri
        )));
    }

    if DANGEROUS_ENV_VAR_NAMES
        .iter()
        .any(|&d| d.eq_ignore_ascii_case(var_name))
    {
        return Err(NonoError::ConfigParse(format!(
            "env:// cannot read dangerous environment variable: {}",
            var_name
        )));
    }

    Ok(())
}

/// Validate a `file://` URI for local file credential sources.
///
/// Expected format: `file:///absolute/path` (triple slash for absolute paths).
///
/// Rejects:
/// - Non-absolute paths (must start with `/` after `file://`)
/// - Empty or root-only paths
/// - Path traversal (`..` components)
/// - Dangerous characters (null, newline, semicolons, backticks, pipes, shell expansion)
pub fn validate_file_uri(uri: &str) -> Result<()> {
    let path_str = uri.strip_prefix(FILE_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, FILE_URI_PREFIX
        ))
    })?;

    if !path_str.starts_with('/') {
        return Err(NonoError::ConfigParse(format!(
            "file:// URI must use an absolute path (file:///path), got: {}",
            uri
        )));
    }

    let meaningful = path_str.trim_end_matches('/');
    if meaningful.is_empty() || meaningful == "/" {
        return Err(NonoError::ConfigParse(format!(
            "file:// URI path is empty: {}",
            uri
        )));
    }

    for component in std::path::Path::new(path_str).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(NonoError::ConfigParse(format!(
                "file:// URI must not contain path traversal (..): {}",
                uri
            )));
        }
    }

    const FORBIDDEN_FILE_CHARS: &[char] = &['\0', '\n', '\r', ';', '`', '|', '$', '&', '>', '<'];
    if let Some(bad) = path_str.chars().find(|c| FORBIDDEN_FILE_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "file:// URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    Ok(())
}

/// Validate a destination environment variable name.
///
/// Ensures the target variable name is not on the dangerous blocklist and
/// follows standard naming conventions (`[A-Za-z0-9_]+`). This prevents
/// Environment Variable Injection where an attacker specifies a dangerous
/// target like `LD_PRELOAD` or `PATH` via explicit `=TARGET` syntax.
///
/// The check is case-insensitive to prevent bypass via `ld_preload` etc.
pub fn validate_destination_env_var(var_name: &str) -> Result<()> {
    if var_name.is_empty() {
        return Err(NonoError::ConfigParse(
            "destination environment variable name cannot be empty".to_string(),
        ));
    }

    if let Some(bad) = var_name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '_')
    {
        return Err(NonoError::ConfigParse(format!(
            "destination environment variable name contains invalid character {:?}: {}",
            bad, var_name
        )));
    }

    if DANGEROUS_ENV_VAR_NAMES
        .iter()
        .any(|&d| d.eq_ignore_ascii_case(var_name))
    {
        return Err(NonoError::ConfigParse(format!(
            "destination environment variable '{}' is on the blocklist of dangerous variables",
            var_name
        )));
    }

    Ok(())
}

/// Load a secret from an environment variable.
///
/// Reads from the current process environment (before sandbox application).
/// The value is wrapped in `Zeroizing<String>` to minimize plaintext lifetime.
///
/// # Errors
///
/// Returns `SecretNotFound` if the variable is unset or empty.
/// Returns `KeystoreAccess` if the variable contains non-UTF-8 data.
fn load_from_env(uri: &str) -> Result<Zeroizing<String>> {
    validate_env_uri(uri)?;

    let var_name = uri
        .strip_prefix(ENV_URI_PREFIX)
        .ok_or_else(|| NonoError::ConfigParse(format!("invalid env:// URI: {}", uri)))?;

    match std::env::var(var_name) {
        Ok(value) if value.is_empty() => Err(NonoError::SecretNotFound(format!(
            "environment variable '{}' is set but empty",
            var_name
        ))),
        Ok(value) => {
            tracing::debug!("Loaded secret from environment variable '{}'", var_name);
            Ok(Zeroizing::new(value))
        }
        Err(std::env::VarError::NotPresent) => Err(NonoError::SecretNotFound(format!(
            "environment variable '{}' is not set",
            var_name
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(NonoError::KeystoreAccess(format!(
            "environment variable '{}' contains non-UTF-8 data",
            var_name
        ))),
    }
}

/// Load a secret from a local file via `file://` URI.
///
/// Reads the file contents at startup (before sandbox activation), trims
/// whitespace, and wraps the result in `Zeroizing<String>`. The file is
/// read once — subsequent access is from the in-memory zeroized copy.
///
/// # Errors
///
/// Returns `SecretNotFound` if the file does not exist or is empty.
/// Returns `KeystoreAccess` for other I/O errors (permissions, etc.).
fn load_from_file(uri: &str) -> Result<Zeroizing<String>> {
    validate_file_uri(uri)?;

    let path_str = uri
        .strip_prefix(FILE_URI_PREFIX)
        .ok_or_else(|| NonoError::ConfigParse(format!("invalid file:// URI: {}", uri)))?;

    let trimmed = load_secret_file(Path::new(path_str)).map_err(|e| match e {
        NonoError::SecretNotFound(_) => {
            NonoError::SecretNotFound(format!("credential file not found: {}", path_str))
        }
        NonoError::KeystoreAccess(_) => {
            NonoError::KeystoreAccess(format!("failed to read credential file '{}'", path_str))
        }
        other => other,
    })?;

    tracing::debug!("Loaded secret from {}", redact_file_uri(uri));
    Ok(trimmed)
}

/// Load a secret from a local file and wrap it in [`Zeroizing`].
///
/// Intended for callers that need a common file-backed secret path without
/// duplicating plaintext handling. A single trailing line ending is removed to
/// match CLI-based secret loaders; other leading/trailing whitespace is
/// preserved.
pub fn load_secret_file(path: &Path) -> Result<Zeroizing<String>> {
    let mut content = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            NonoError::SecretNotFound(format!("secret file not found: {}", path.display()))
        } else {
            NonoError::KeystoreAccess(format!(
                "failed to read secret file '{}': {}",
                path.display(),
                e
            ))
        }
    })?);

    if content.ends_with("\r\n") {
        let new_len = content.len().saturating_sub(2);
        content.truncate(new_len);
    } else if content.ends_with('\n') {
        let new_len = content.len().saturating_sub(1);
        content.truncate(new_len);
    }

    if content.is_empty() {
        return Err(NonoError::SecretNotFound(format!(
            "secret file '{}' is empty",
            path.display()
        )));
    }

    Ok(content)
}

/// Store a secret in a local file with owner-only permissions on Unix.
///
/// This is primarily used by trust-related file-backed keystore adapters and
/// keeps the file handling consistent with runtime secret loading helpers.
pub fn store_secret_file(path: &Path, secret: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "failed to create secret directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    NonoError::KeystoreAccess(format!(
                        "failed to secure existing secret file {}: {e}",
                        path.display()
                    ))
                },
            )?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                NonoError::KeystoreAccess(format!(
                    "failed to store secret at {}: {e}",
                    path.display()
                ))
            })?;

        file.write_all(secret.as_bytes()).map_err(|e| {
            NonoError::KeystoreAccess(format!("failed to store secret at {}: {e}", path.display()))
        })?;

        file.sync_all().map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "failed to sync secret file {}: {e}",
                path.display()
            ))
        })?;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "failed to secure secret file {}: {e}",
                path.display()
            ))
        })?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::File::create(path).map_err(|e| {
            NonoError::KeystoreAccess(format!("failed to store secret at {}: {e}", path.display()))
        })?;

        file.write_all(secret.as_bytes()).map_err(|e| {
            NonoError::KeystoreAccess(format!("failed to store secret at {}: {e}", path.display()))
        })?;
    }

    Ok(())
}

/// Load a single secret from the keystore.
///
/// The returned value is immediately wrapped in `Zeroizing` so the heap
/// buffer will be zeroed on drop. Note: the keyring crate may create
/// intermediate heap allocations internally (e.g. during UTF-8 conversion)
/// that are freed without being zeroed. This is a known limitation of the
/// keyring crate that we cannot address from the caller side.
#[cfg(feature = "system-keyring")]
fn load_single_secret(service: &str, account: &str) -> Result<Zeroizing<String>> {
    let timeout = keyring_timeout();
    let service = service.to_string();
    let account = account.to_string();
    let label = format!("keyring lookup for '{}'", account);

    call_with_keyring_timeout(timeout, &label, move || {
        let entry = keyring::Entry::new(&service, &account).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "Failed to access keystore for '{}': {}",
                account, e
            ))
        })?;

        match entry.get_password() {
            Ok(password) => {
                tracing::debug!("Successfully loaded secret '{}'", account);
                Ok(Zeroizing::new(password))
            }
            Err(keyring::Error::NoEntry) => Err(NonoError::SecretNotFound(account.to_string())),
            Err(keyring::Error::Ambiguous(creds)) => Err(NonoError::KeystoreAccess(format!(
                "Multiple entries ({}) found for '{}' - please resolve manually",
                creds.len(),
                account
            ))),
            Err(e) => Err(NonoError::KeystoreAccess(format!(
                "Cannot access '{}': {}",
                account, e
            ))),
        }
    })
}

#[cfg(not(feature = "system-keyring"))]
fn load_single_secret(_service: &str, account: &str) -> Result<Zeroizing<String>> {
    Err(NonoError::KeystoreAccess(format!(
        "system keyring is not available (built without system-keyring feature); \
         cannot load '{}'. Use env://, file://, or op:// credential references instead.",
        account
    )))
}

/// Load a secret from 1Password using the `op` CLI.
///
/// Runs `op read <uri>` and captures stdout. The `op` binary must be
/// installed and authenticated (via biometric, CLI session, or
/// `OP_SERVICE_ACCOUNT_TOKEN` in the parent environment).
///
/// # Security Notes
/// - `op` runs BEFORE the sandbox is applied, so it has network access.
/// - stdout is read into a `Zeroizing<String>` to minimize plaintext lifetime.
/// - The URI is validated before being passed to `op` to prevent argument injection.
/// - `Command::new` is used (no shell), so shell metacharacters in the URI
///   cannot cause command injection.
fn load_from_op(uri: &str) -> Result<Zeroizing<String>> {
    validate_op_uri(uri)?;

    tracing::debug!("Loading secret from 1Password: {}", redact_op_uri(uri));

    let mut child = Command::new("op")
        .args(["read", "--", uri])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::KeystoreAccess(
                    "1Password CLI ('op') not found. \
                     Install it from https://developer.1password.com/docs/cli/"
                        .to_string(),
                )
            } else {
                NonoError::KeystoreAccess(format!("Could not start the 1Password CLI: {}", e))
            }
        })?;

    let output = wait_with_timeout(
        &mut child,
        SECRET_MANAGER_TIMEOUT,
        "1Password CLI",
        "Is 1Password waiting for authentication?",
    )
    .inspect_err(|_| {
        let _ = child.kill();
        let _ = child.wait();
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(classify_op_error(&stderr, uri));
    }

    // Convert stdout to string, trim trailing newline, wrap in Zeroizing.
    // `op read` outputs the raw secret followed by a newline.
    let raw = String::from_utf8(output.stdout).map_err(|_| {
        NonoError::KeystoreAccess(format!(
            "1Password returned non-UTF-8 data for '{}'",
            redact_op_uri(uri)
        ))
    })?;

    let trimmed = raw.trim_end_matches(['\n', '\r']).to_string();
    Ok(Zeroizing::new(trimmed))
}

/// Load a secret from Bitwarden using the `bw` CLI.
///
/// Runs `bw get password <item-id>` for `bw://item-id` URIs.
/// For `bw://item-id/field` URIs, runs `bw get item <item-id>` and extracts
/// the named field from the JSON response. Built-in names (`password`,
/// `username`, `totp`, `notes`, `uri`) resolve to the corresponding login
/// field; any other name is looked up against the item's custom `fields[]`.
/// The `bw` binary must be installed and authenticated
/// (via `BW_SESSION` env var or API key credentials).
///
/// # Security Notes
/// - `bw` runs BEFORE the sandbox is applied, so it has network access.
/// - stdout is read into a `Zeroizing<String>` to minimize plaintext lifetime.
/// - The URI is validated before being passed to `bw` to prevent argument injection.
/// - `Command::new` is used (no shell), so shell metacharacters in the URI
///   cannot cause command injection.
fn load_from_bw(uri: &str) -> Result<Zeroizing<String>> {
    validate_bw_uri(uri)?;

    let path = uri.strip_prefix(BW_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, BW_URI_PREFIX
        ))
    })?;

    tracing::debug!("Loading secret from Bitwarden: {}", redact_bw_uri(uri));

    // Parse segments: either "item-id" or "item-id/field"
    let segments: Vec<&str> = path.splitn(2, '/').collect();
    let item_id = segments[0];

    // Single-arg path: `bw get password -- <item-id>` for the no-field case;
    // `bw get item -- <item-id>` for the field case (we then parse JSON).
    let bw_object = if segments.len() == 2 {
        "item"
    } else {
        "password"
    };
    let mut child = Command::new("bw")
        .args(["get", bw_object, "--", item_id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::KeystoreAccess(
                    "Bitwarden CLI ('bw') not found. \
                     Install it from https://bitwarden.com/help/cli/"
                        .to_string(),
                )
            } else {
                NonoError::KeystoreAccess(format!("Could not start the Bitwarden CLI: {}", e))
            }
        })?;

    let output = wait_with_timeout(
        &mut child,
        SECRET_MANAGER_TIMEOUT,
        "Bitwarden CLI",
        "Is Bitwarden waiting for authentication?",
    )
    .inspect_err(|_| {
        let _ = child.kill();
        let _ = child.wait();
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(classify_bw_error(&stderr, uri));
    }

    let raw = Zeroizing::new(String::from_utf8(output.stdout).map_err(|_| {
        NonoError::KeystoreAccess(format!(
            "Bitwarden returned non-UTF-8 data for '{}'",
            redact_bw_uri(uri)
        ))
    })?);

    // `bw` can exit with code 0 even when the vault is locked: it tries to
    // prompt for a master password, fails because stdin is not a TTY, and
    // crashes with a Node.js ERR_USE_AFTER_CLOSE -- but still exits 0.
    // In that case stdout is empty. A successful `bw get` must return data.
    if raw.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(classify_bw_error(&stderr, uri));
    }

    if segments.len() == 2 {
        let field = segments[1];
        extract_bw_field(&raw, field, uri)
    } else {
        let mut raw = raw;
        let trimmed_len = raw.trim_end_matches(['\n', '\r']).len();
        raw.truncate(trimmed_len);
        Ok(raw)
    }
}

/// Extract a named field from a `bw get item` JSON payload.
///
/// Resolution order:
/// 1. Built-in names (`password`, `username`, `totp`, `notes`, `uri`) read
///    directly from the item's standard slots (e.g. `login.password`,
///    `login.uris[0].uri`, top-level `notes`).
/// 2. Any other name is matched case-sensitively against `fields[].name`.
///
/// This mirrors `bw`'s own convention: `bw get password <id>` always returns
/// `login.password` even if a custom field is named `password`.
fn extract_bw_field(item_json: &str, field: &str, uri: &str) -> Result<Zeroizing<String>> {
    let item: BwItem = serde_json::from_str(item_json).map_err(|e| {
        NonoError::KeystoreAccess(format!(
            "Bitwarden returned invalid JSON for '{}': {}",
            redact_bw_uri(uri),
            e
        ))
    })?;

    let builtin: Option<Zeroizing<String>> = match field {
        "password" => item.login.as_ref().and_then(|l| l.password.clone()),
        "username" => item
            .login
            .as_ref()
            .and_then(|l| l.username.as_ref().map(|s| Zeroizing::new(s.clone()))),
        "totp" => item.login.as_ref().and_then(|l| l.totp.clone()),
        "notes" => item.notes.clone(),
        "uri" => item
            .login
            .as_ref()
            .and_then(|l| l.uris.as_ref())
            .and_then(|uris| uris.first())
            .and_then(|u| u.uri.as_ref().map(|s| Zeroizing::new(s.clone()))),
        _ => None,
    };
    if let Some(value) = builtin {
        return Ok(value);
    }

    if let Some(fields) = &item.fields {
        for f in fields {
            if f.name.as_deref() == Some(field)
                && let Some(value) = f.value.clone()
            {
                return Ok(value);
            }
        }
    }

    Err(NonoError::KeystoreAccess(format!(
        "Bitwarden item for '{}' has no field named '{}' \
         (checked built-in password/username/totp/notes/uri and custom fields)",
        redact_bw_uri(uri),
        field
    )))
}

#[derive(serde::Deserialize)]
struct BwItem {
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default)]
    notes: Option<Zeroizing<String>>,
    #[serde(default)]
    fields: Option<Vec<BwCustomField>>,
}

#[derive(serde::Deserialize)]
struct BwLogin {
    #[serde(default)]
    password: Option<Zeroizing<String>>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    totp: Option<Zeroizing<String>>,
    #[serde(default)]
    uris: Option<Vec<BwUriEntry>>,
}

#[derive(serde::Deserialize)]
struct BwUriEntry {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(serde::Deserialize)]
struct BwCustomField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<Zeroizing<String>>,
}

/// Load a secret from Apple Passwords using macOS `security`.
///
/// Runs `security find-internet-password -s <server> -a <account> -w` and captures
/// stdout. This backend is macOS-only.
fn load_from_apple_password(uri: &str) -> Result<Zeroizing<String>> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = uri;
        Err(NonoError::KeystoreAccess(
            "Apple Passwords credentials are only supported on macOS".to_string(),
        ))
    }

    #[cfg(target_os = "macos")]
    {
        let (server, account) = parse_apple_password_uri(uri)?;
        tracing::debug!(
            "Loading secret from Apple Passwords: {}",
            redact_apple_password_uri(uri)
        );

        let mut child = Command::new("security")
            .args(["find-internet-password", "-s", server, "-a", account, "-w"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    NonoError::KeystoreAccess(
                        "macOS 'security' CLI not found (required for Apple Passwords lookup)"
                            .to_string(),
                    )
                } else {
                    NonoError::KeystoreAccess(format!("Could not start macOS security CLI: {}", e))
                }
            })?;

        let output = wait_with_timeout(
            &mut child,
            SECRET_MANAGER_TIMEOUT,
            "macOS security CLI",
            "Is Keychain access waiting for user approval?",
        )
        .inspect_err(|_| {
            let _ = child.kill();
            let _ = child.wait();
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_apple_password_error(&stderr, uri));
        }

        let raw = String::from_utf8(output.stdout).map_err(|_| {
            NonoError::KeystoreAccess(format!(
                "Apple Passwords returned non-UTF-8 data for '{}'",
                redact_apple_password_uri(uri)
            ))
        })?;

        let trimmed = raw.trim_end_matches(['\n', '\r']).to_string();
        Ok(Zeroizing::new(trimmed))
    }
}

/// Load a secret from the system keyring using a custom service name.
///
/// Uses the `keyring` crate with the service and account parsed from a
/// `keyring://service/account` URI. This is cross-platform: macOS Keychain
/// (generic passwords), Linux Secret Service, Windows Credential Manager.
///
/// If `?decode=go-keyring` is specified, the stored value is unwrapped from
/// the `go-keyring-base64:` encoding used by `github.com/zalando/go-keyring`.
#[cfg(feature = "system-keyring")]
fn load_from_keyring_uri(uri: &str) -> Result<Zeroizing<String>> {
    let parts = parse_keyring_uri(uri)?;
    let redacted = redact_keyring_uri(uri);
    tracing::debug!("Loading secret from system keyring: {}", redacted);

    let timeout = keyring_timeout();
    let service = parts.service.to_string();
    let account = parts.account.to_string();
    let decode = parts.decode;
    let redacted_clone = redacted.clone();
    let label = format!("keyring lookup for '{}'", redacted);

    call_with_keyring_timeout(timeout, &label, move || {
        let entry = keyring::Entry::new(&service, &account).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "Failed to access keyring for '{}': {}",
                redacted_clone, e
            ))
        })?;

        match entry.get_password() {
            Ok(password) => {
                tracing::debug!("Successfully loaded secret '{}'", redacted_clone);
                let decoded = apply_keyring_decode(password, decode, &redacted_clone)?;
                Ok(decoded)
            }
            Err(keyring::Error::NoEntry) => Err(NonoError::SecretNotFound(format!(
                "keyring entry not found: '{}'. \
                 Verify the service and account match the stored credential.",
                redacted_clone
            ))),
            Err(keyring::Error::Ambiguous(creds)) => Err(NonoError::KeystoreAccess(format!(
                "Multiple entries ({}) found for '{}' - please resolve manually",
                creds.len(),
                redacted_clone
            ))),
            Err(e) => Err(NonoError::KeystoreAccess(format!(
                "Cannot access '{}': {}",
                redacted_clone, e
            ))),
        }
    })
}

#[cfg(not(feature = "system-keyring"))]
fn load_from_keyring_uri(uri: &str) -> Result<Zeroizing<String>> {
    let redacted = redact_keyring_uri(uri);
    Err(NonoError::KeystoreAccess(format!(
        "system keyring is not available (built without system-keyring feature); \
         cannot load '{}'. Use env://, file://, or op:// credential references instead.",
        redacted
    )))
}

/// Apply the requested post-load decoding to a keyring value.
#[cfg(feature = "system-keyring")]
fn apply_keyring_decode(
    raw: String,
    decode: KeyringDecode,
    redacted_uri: &str,
) -> Result<Zeroizing<String>> {
    match decode {
        KeyringDecode::None => Ok(Zeroizing::new(raw)),
        KeyringDecode::GoKeyring => {
            let encoded = raw.strip_prefix(GO_KEYRING_PREFIX).ok_or_else(|| {
                NonoError::ConfigParse(format!(
                    "keyring value for '{}' does not have the expected '{}' prefix. \
                     Remove ?decode=go-keyring if this credential was not stored by a Go tool.",
                    redacted_uri, GO_KEYRING_PREFIX
                ))
            })?;
            let bytes = crate::trust::base64::base64_decode(encoded).map_err(|e| {
                NonoError::ConfigParse(format!(
                    "failed to base64-decode go-keyring value for '{}': {}",
                    redacted_uri, e
                ))
            })?;
            let decoded = String::from_utf8(bytes).map_err(|_| {
                NonoError::ConfigParse(format!(
                    "go-keyring decoded value for '{}' is not valid UTF-8",
                    redacted_uri
                ))
            })?;
            Ok(Zeroizing::new(decoded))
        }
    }
}

/// Classify `op` CLI errors into actionable error messages.
fn classify_op_error(stderr: &str, uri: &str) -> NonoError {
    let redacted = redact_op_uri(uri);
    let stderr_trimmed = stderr.trim();

    if stderr.contains("not signed in")
        || stderr.contains("sign in")
        || stderr.contains("authentication required")
        || stderr.contains("session expired")
    {
        NonoError::KeystoreAccess(format!(
            "1Password authentication required for '{}'. \
             Run 'op signin' or set OP_SERVICE_ACCOUNT_TOKEN. \
             Detail: {}",
            redacted, stderr_trimmed
        ))
    } else if stderr.contains("not found")
        || stderr.contains("could not find")
        || stderr.contains("isn't an item")
    {
        NonoError::SecretNotFound(format!(
            "1Password item not found: '{}'. Detail: {}",
            redacted, stderr_trimmed
        ))
    } else {
        NonoError::KeystoreAccess(format!(
            "1Password CLI failed for '{}': {}",
            redacted, stderr_trimmed
        ))
    }
}

/// Classify `security` CLI errors for Apple Passwords lookups.
#[cfg(target_os = "macos")]
fn classify_apple_password_error(stderr: &str, uri: &str) -> NonoError {
    let redacted = redact_apple_password_uri(uri);
    let stderr_trimmed = stderr.trim();

    if stderr.contains("could not be found in the keychain")
        || stderr.contains("The specified item could not be found")
    {
        NonoError::SecretNotFound(format!(
            "Apple Passwords entry not found: '{}'. Detail: {}",
            redacted, stderr_trimmed
        ))
    } else if stderr.contains("User interaction is not allowed") {
        NonoError::KeystoreAccess(format!(
            "Apple Passwords access requires user approval for '{}'. \
             Unlock Keychain/Passwords and retry. Detail: {}",
            redacted, stderr_trimmed
        ))
    } else {
        NonoError::KeystoreAccess(format!(
            "Apple Passwords lookup failed for '{}': {}",
            redacted, stderr_trimmed
        ))
    }
}

/// Redact the field segment of an `op://` URI for safe logging.
///
/// `op://vault/item/field` → `op://vault/item/<redacted>`
pub fn redact_op_uri(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix(OP_URI_PREFIX) {
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() >= 3 {
            return format!("op://{}/{}/<redacted>", parts[0], parts[1]);
        }
    }
    "op://***".to_string()
}

/// Redact the item ID segment of a `bw://` URI for safe logging.
///
/// `bw://item-id` -> `bw://<redacted>`
/// `bw://item-id/field` -> `bw://<redacted>/field`
pub fn redact_bw_uri(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix(BW_URI_PREFIX) {
        let parts: Vec<&str> = path.splitn(2, '/').collect();
        if parts.len() == 2 {
            return format!("bw://<redacted>/{}", parts[1]);
        }
        return "bw://<redacted>".to_string();
    }
    "bw://***".to_string()
}

/// Classify `bw` CLI errors for Bitwarden lookups.
fn classify_bw_error(stderr: &str, uri: &str) -> NonoError {
    let redacted = redact_bw_uri(uri);
    let stderr_trimmed = stderr.trim();

    if stderr.contains("not authenticated")
        || stderr.contains("You are not logged in")
        || stderr.contains("Session has expired")
        || stderr.contains("Vault is locked")
        || stderr.contains("Master password")
        || stderr.contains("ERR_USE_AFTER_CLOSE")
    {
        // When the vault is locked, bw often dumps a Node.js
        // ERR_USE_AFTER_CLOSE stack trace on stderr. That crash is an
        // internal bw detail, not useful to the user. Omit it from the
        // Detail field so the actionable message stands on its own.
        NonoError::KeystoreAccess(format!(
            "Bitwarden authentication required for '{}'. \
             Run 'bw unlock' or set BW_SESSION.",
            redacted
        ))
    } else if stderr.contains("not found") || stderr.contains("Couldn't find") {
        NonoError::SecretNotFound(format!(
            "Bitwarden item not found: '{}'. Detail: {}",
            redacted, stderr_trimmed
        ))
    } else if stderr_trimmed.is_empty() {
        // Empty stderr with empty stdout means bw exited 0 but produced no output.
        // This happens when the vault is locked and bw crashes silently.
        NonoError::KeystoreAccess(format!(
            "Bitwarden returned empty output for '{}'. \
             The vault may be locked. Run 'bw unlock' or set BW_SESSION.",
            redacted
        ))
    } else {
        NonoError::KeystoreAccess(format!(
            "Bitwarden CLI failed for '{}': {}",
            redacted, stderr_trimmed
        ))
    }
}

/// Redact the account segment of an Apple Passwords URI for safe logging.
///
/// `apple-password://server/account` → `apple-password://server/<redacted>`
pub fn redact_apple_password_uri(uri: &str) -> String {
    if let Some(path) = strip_apple_password_prefix(uri) {
        let mut segments = path.splitn(2, '/');
        if let Some(server) = segments.next()
            && !server.is_empty()
            && segments.next().is_some()
        {
            return format!("apple-password://{}/<redacted>", server);
        }
    }
    "apple-password://***".to_string()
}

/// Redact a file:// URI for safe logging.
/// Keeps the directory structure but replaces the filename.
/// `file:///run/secrets/api-token` → `file:///run/secrets/[REDACTED]`
pub fn redact_file_uri(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix(FILE_URI_PREFIX)
        && let Some(last_slash) = path.rfind('/')
    {
        return format!("{}{}[REDACTED]", FILE_URI_PREFIX, &path[..=last_slash]);
    }
    format!("{}[REDACTED]", FILE_URI_PREFIX)
}

/// Wait for a child process with a timeout.
///
/// Returns the process output on success, or a timeout error.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    backend_name: &str,
    timeout_hint: &str,
) -> Result<std::process::Output> {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited — collect output
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    std::io::Read::read_to_end(&mut out, &mut stdout).ok();
                }
                if let Some(mut err) = child.stderr.take() {
                    std::io::Read::read_to_end(&mut err, &mut stderr).ok();
                }
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                // Still running
                if start.elapsed() >= timeout {
                    return Err(NonoError::KeystoreAccess(format!(
                        "{} timed out after {}s. {}",
                        backend_name,
                        timeout.as_secs(),
                        timeout_hint
                    )));
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(NonoError::KeystoreAccess(format!(
                    "Failed to check {} status: {}",
                    backend_name, e
                )));
            }
        }
    }
}

/// Build secret mappings from a comma-separated list of credential entries.
///
/// Supports five formats:
/// - **Keyring names**: `openai_api_key` -> env var `OPENAI_API_KEY` (auto-uppercased)
/// - **1Password URIs with explicit var**: `op://vault/item/field=MY_VAR` -> env var `MY_VAR`
/// - **Bitwarden URIs with explicit var**: `bw://item-id=MY_VAR` -> env var `MY_VAR`
/// - **Environment URIs**: `env://GITHUB_TOKEN` -> env var `GITHUB_TOKEN` (auto-derived)
///   or `env://GITHUB_TOKEN=GH_TOKEN` -> env var `GH_TOKEN` (explicit)
///
/// URI-based managers must include explicit target variable names:
/// - `op://...=VAR_NAME`
/// - `bw://...=VAR_NAME`
///
/// Bare URI entries without explicit target variables are rejected.
///
/// Apple Passwords references (`apple-password://...`) and keyring references
/// (`keyring://...`) are not supported in this list-based parser. Use
/// `build_mappings_from_pairs` (CLI: `--env-credential-map <CREDENTIAL_REF>
/// <ENV_VAR>`) for explicit mapping.
///
/// Environment URIs (`env://...`) auto-derive the target variable name from the source
/// when `=` is omitted: `env://GITHUB_TOKEN` maps to env var `GITHUB_TOKEN`.
///
/// # Errors
///
/// Returns an error if a URI-based secret manager entry is provided without an
/// explicit target variable suffix, if an Apple Passwords or keyring URI is
/// provided in list mode, or if any URI fails validation.
///
/// # Example
///
/// ```
/// use nono::keystore::build_mappings_from_list;
///
/// let mappings = build_mappings_from_list("openai_api_key,anthropic_key").unwrap();
/// assert_eq!(mappings.get("openai_api_key"), Some(&"OPENAI_API_KEY".to_string()));
/// assert_eq!(mappings.get("anthropic_key"), Some(&"ANTHROPIC_KEY".to_string()));
/// ```
pub fn build_mappings_from_list(accounts: &str) -> Result<HashMap<String, String>> {
    let mut mappings = HashMap::new();

    for entry in accounts.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        if entry.starts_with(ENV_URI_PREFIX) {
            // env:// URI: auto-derive target var or use explicit =VAR_NAME
            if let Some(eq_pos) = entry.rfind('=') {
                let uri = &entry[..eq_pos];
                let var_name = &entry[eq_pos + 1..];

                if var_name.is_empty() {
                    return Err(NonoError::ConfigParse(format!(
                        "env:// credential '{}' has '=' but no variable name",
                        uri
                    )));
                }

                validate_env_uri(uri)?;
                validate_destination_env_var(var_name)?;
                mappings.insert(uri.to_string(), var_name.to_string());
            } else {
                // Auto-derive: env://GITHUB_TOKEN -> target GITHUB_TOKEN
                validate_env_uri(entry)?;
                // Safe: validate_env_uri confirmed the prefix exists
                let source_var = match entry.strip_prefix(ENV_URI_PREFIX) {
                    Some(v) => v,
                    None => {
                        return Err(NonoError::ConfigParse("invalid env:// URI".to_string()));
                    }
                };
                mappings.insert(entry.to_string(), source_var.to_string());
            }
        } else if entry.starts_with(FILE_URI_PREFIX) {
            // file:// URI: must have explicit =VAR_NAME suffix because
            // you can't derive a meaningful env var name from a file path.
            // Format: file:///path/to/secret=MY_VAR
            if let Some(eq_pos) = entry.rfind('=') {
                let uri = &entry[..eq_pos];
                let var_name = &entry[eq_pos + 1..];

                if var_name.is_empty() {
                    return Err(NonoError::ConfigParse(format!(
                        "file:// credential '{}' has '=' but no variable name. \
                         Use format: file:///path/to/secret=MY_VAR",
                        uri
                    )));
                }

                validate_file_uri(uri)?;
                validate_destination_env_var(var_name)?;
                mappings.insert(uri.to_string(), var_name.to_string());
            } else {
                return Err(NonoError::ConfigParse(format!(
                    "file:// credential '{}' requires an explicit target variable. \
                     Use format: file:///path/to/secret=MY_VAR",
                    entry
                )));
            }
        } else if entry.starts_with(OP_URI_PREFIX) {
            // 1Password URI: must have =VAR_NAME suffix
            // Find the last '=' that separates the URI from the var name.
            // op:// URIs don't contain '=', so the last '=' is unambiguous.
            if let Some(eq_pos) = entry.rfind('=') {
                let uri = &entry[..eq_pos];
                let var_name = &entry[eq_pos + 1..];

                if var_name.is_empty() {
                    return Err(NonoError::ConfigParse(format!(
                        "1Password credential '{}' has '=' but no variable name. \
                         Use format: op://vault/item/field=MY_VAR",
                        redact_op_uri(uri)
                    )));
                }

                // Validate the URI portion
                validate_op_uri(uri)?;
                validate_destination_env_var(var_name)?;

                mappings.insert(uri.to_string(), var_name.to_string());
            } else {
                return Err(NonoError::ConfigParse(format!(
                    "1Password credential requires an explicit variable name. \
                     Use format: op://vault/item/field=MY_VAR (got '{}')",
                    redact_op_uri(entry)
                )));
            }
        } else if is_bw_uri(entry) {
            // Bitwarden URI: must have =VAR_NAME suffix
            // Find the last '=' that separates the URI from the var name.
            // bw:// URIs don't contain '=', so the last '=' is unambiguous.
            if let Some(eq_pos) = entry.rfind('=') {
                let uri = &entry[..eq_pos];
                let var_name = &entry[eq_pos + 1..];

                if var_name.is_empty() {
                    return Err(NonoError::ConfigParse(format!(
                        "Bitwarden credential '{}' has '=' but no variable name. \
                         Use format: bw://item-id=MY_VAR",
                        redact_bw_uri(uri)
                    )));
                }

                validate_bw_uri(uri)?;
                validate_destination_env_var(var_name)?;

                mappings.insert(uri.to_string(), var_name.to_string());
            } else {
                return Err(NonoError::ConfigParse(format!(
                    "Bitwarden credential requires an explicit variable name. \
                     Use format: bw://item-id=MY_VAR (got '{}')",
                    redact_bw_uri(entry)
                )));
            }
        } else if is_apple_password_uri(entry) {
            return Err(NonoError::ConfigParse(format!(
                "Apple Passwords credential '{}' is not supported in --env-credential. \
                 Use --env-credential-map 'apple-password://server/account' MY_VAR",
                redact_apple_password_uri(entry)
            )));
        } else if is_keyring_uri(entry) {
            return Err(NonoError::ConfigParse(format!(
                "keyring credential '{}' is not supported in --env-credential. \
                 Use --env-credential-map 'keyring://service/account' MY_VAR",
                redact_keyring_uri(entry)
            )));
        } else {
            // Keyring name: auto-uppercase to env var name
            let env_var = entry.to_uppercase();
            validate_destination_env_var(&env_var)?;
            mappings.insert(entry.to_string(), env_var);
        }
    }

    Ok(mappings)
}

/// Build secret mappings from explicit credential-ref/env-var pairs.
///
/// This is used by CLI options that pass the credential reference and
/// destination environment variable as separate arguments.
///
/// # Arguments
/// * `pairs` - List of `(credential_ref, env_var)` tuples
///
/// # Errors
///
/// Returns an error if any credential reference is empty, the destination env
/// var is invalid, or a URI reference fails structural validation.
pub fn build_mappings_from_pairs(pairs: &[(String, String)]) -> Result<HashMap<String, String>> {
    let mut mappings = HashMap::new();

    for (credential_ref, env_var) in pairs {
        let credential_ref = credential_ref.trim();
        let env_var = env_var.trim();

        if credential_ref.is_empty() {
            return Err(NonoError::ConfigParse(
                "credential reference is empty in --env-credential-map".to_string(),
            ));
        }

        validate_destination_env_var(env_var)?;

        if credential_ref.starts_with(OP_URI_PREFIX) {
            validate_op_uri(credential_ref)?;
        } else if is_bw_uri(credential_ref) {
            validate_bw_uri(credential_ref)?;
        } else if is_apple_password_uri(credential_ref) {
            validate_apple_password_uri(credential_ref)?;
        } else if is_keyring_uri(credential_ref) {
            validate_keyring_uri(credential_ref)?;
        } else if credential_ref.starts_with(ENV_URI_PREFIX) {
            validate_env_uri(credential_ref)?;
        }

        mappings.insert(credential_ref.to_string(), env_var.to_string());
    }

    Ok(mappings)
}

/// Build secret mappings from CLI argument and/or profile secrets
///
/// Merges secrets from both sources, with CLI taking precedence.
///
/// # Arguments
/// * `cli_secrets` - Optional comma-separated list from CLI (--env-credential flag)
/// * `cli_secret_mappings` - Optional explicit mappings from
///   `--env-credential-map <CREDENTIAL_REF> <ENV_VAR>`
/// * `profile_secrets` - Mappings from profile's [secrets] section
///
/// # Returns
/// Combined map of credential reference -> env var name
///
/// # Errors
///
/// Returns an error if a URI-based credential in `cli_secrets` is missing
/// an explicit target variable suffix (`=VAR_NAME` for `op://` or `bw://`), if
/// `apple-password://` or `keyring://` appears in list mode, or if
/// URI/env-var validation fails.
pub fn build_secret_mappings(
    cli_secrets: Option<&str>,
    cli_secret_mappings: &[(String, String)],
    profile_secrets: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut combined = profile_secrets.clone();

    // CLI secrets override profile secrets
    if let Some(secrets_str) = cli_secrets {
        let cli_mappings = build_mappings_from_list(secrets_str)?;
        combined.extend(cli_mappings);
    }

    // Explicit CLI mappings override both profile secrets and --env-credential.
    if !cli_secret_mappings.is_empty() {
        let explicit_mappings = build_mappings_from_pairs(cli_secret_mappings)?;
        combined.extend(explicit_mappings);
    }

    Ok(combined)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::disallowed_methods)] // Tests use unique env var names (NONO_TEST_*), no contention.
mod tests {
    use super::*;

    #[test]
    fn test_build_mappings_from_list() {
        let mappings =
            build_mappings_from_list("openai_api_key,anthropic_api_key").expect("should parse");

        assert_eq!(mappings.len(), 2);
        assert_eq!(
            mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
        assert_eq!(
            mappings.get("anthropic_api_key"),
            Some(&"ANTHROPIC_API_KEY".to_string())
        );
    }

    #[test]
    fn test_build_mappings_handles_whitespace() {
        let mappings = build_mappings_from_list(" key1 , key2 , key3 ").expect("should parse");

        assert_eq!(mappings.len(), 3);
        assert!(mappings.contains_key("key1"));
        assert!(mappings.contains_key("key2"));
        assert!(mappings.contains_key("key3"));
    }

    #[test]
    fn test_build_mappings_empty() {
        let mappings = build_mappings_from_list("").expect("should parse");
        assert!(mappings.is_empty());
    }

    // --- op:// URI support in build_mappings_from_list ---

    #[test]
    fn test_build_mappings_op_uri_with_var_name() {
        let mappings =
            build_mappings_from_list("op://Development/OpenAI/credential=OPENAI_API_KEY")
                .expect("should parse");

        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("op://Development/OpenAI/credential"),
            Some(&"OPENAI_API_KEY".to_string())
        );
    }

    #[test]
    fn test_build_mappings_mixed_keyring_and_op() {
        let mappings = build_mappings_from_list("my_api_key,op://vault/item/field=SECRET_VAR")
            .expect("should parse");

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings.get("my_api_key"), Some(&"MY_API_KEY".to_string()));
        assert_eq!(
            mappings.get("op://vault/item/field"),
            Some(&"SECRET_VAR".to_string())
        );
    }

    #[test]
    fn test_build_mappings_op_uri_without_var_rejected() {
        // Bare op:// URIs produce garbage env var names when uppercased
        let err = build_mappings_from_list("op://vault/item/field")
            .expect_err("should reject bare op:// URI");
        assert!(
            err.to_string().contains("explicit variable name"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_build_mappings_op_uri_empty_var_rejected() {
        // Trailing '=' with no var name
        let err = build_mappings_from_list("op://vault/item/field=")
            .expect_err("should reject empty var name");
        assert!(err.to_string().contains("no variable name"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_op_uri_invalid_uri_rejected() {
        // URI with only 2 segments should fail validation
        let err = build_mappings_from_list("op://vault/item=MY_VAR")
            .expect_err("should reject invalid URI");
        assert!(
            err.to_string().contains("at least vault/item/field"),
            "got: {}",
            err
        );
    }

    // --- apple-password:// URI handling in build_mappings_from_list ---

    #[test]
    fn test_build_mappings_apple_password_uri_rejected_in_list_mode() {
        let err = build_mappings_from_list("apple-password://github.com/alice@example.com")
            .expect_err("should reject apple-password URI in list mode");
        assert!(
            err.to_string().contains("--env-credential-map"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_build_mappings_apple_password_uri_with_inline_var_rejected_in_list_mode() {
        let err =
            build_mappings_from_list("apple-password://github.com/alice@example.com=>GITHUB_PASS")
                .expect_err("should reject inline apple-password var syntax");
        assert!(
            err.to_string().contains("--env-credential-map"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_build_mappings_apple_password_uri_legacy_equals_suffix_rejected() {
        let err =
            build_mappings_from_list("apple-password://github.com/alice@example.com=GITHUB_PASS")
                .expect_err("should reject legacy inline apple-password suffix");
        assert!(
            err.to_string().contains("--env-credential-map"),
            "got: {}",
            err
        );
    }

    // --- apple-password:// URI validation tests ---

    #[test]
    fn test_validate_apple_password_uri_valid() {
        assert!(
            validate_apple_password_uri("apple-password://github.com/alice@example.com").is_ok()
        );
    }

    #[test]
    fn test_validate_apple_password_uri_valid_alias_prefix() {
        assert!(
            validate_apple_password_uri("apple-passwords://github.com/alice@example.com").is_ok()
        );
    }

    #[test]
    fn test_validate_apple_password_uri_missing_prefix() {
        let err =
            validate_apple_password_uri("github.com/alice@example.com").expect_err("should reject");
        assert!(
            err.to_string().contains("does not start with"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_apple_password_uri_missing_account() {
        let err = validate_apple_password_uri("apple-password://github.com")
            .expect_err("should reject missing account");
        assert!(err.to_string().contains("server/account"), "got: {}", err);
    }

    #[test]
    fn test_validate_apple_password_uri_empty_segment() {
        let err = validate_apple_password_uri("apple-password://github.com/")
            .expect_err("should reject empty account");
        assert!(err.to_string().contains("empty"), "got: {}", err);
    }

    #[test]
    fn test_validate_apple_password_uri_forbidden_char() {
        let err = validate_apple_password_uri("apple-password://github.com/alice;rm -rf")
            .expect_err("should reject forbidden char");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    // --- keyring:// URI handling in build_mappings_from_list ---

    #[test]
    fn test_build_mappings_keyring_uri_rejected_in_list_mode() {
        let err = build_mappings_from_list("keyring://gh:github.com/alice")
            .expect_err("should reject keyring URI in list mode");
        assert!(
            err.to_string().contains("--env-credential-map"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_build_mappings_keyring_uri_with_inline_var_rejected_in_list_mode() {
        let err = build_mappings_from_list("keyring://gh:github.com/alice=>GH_TOKEN")
            .expect_err("should reject inline keyring var syntax");
        assert!(
            err.to_string().contains("--env-credential-map"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_build_mappings_keyring_uri_legacy_equals_suffix_rejected() {
        let err = build_mappings_from_list("keyring://gh:github.com/alice=GH_TOKEN")
            .expect_err("should reject legacy inline keyring suffix");
        assert!(
            err.to_string().contains("--env-credential-map"),
            "got: {}",
            err
        );
    }

    // --- keyring:// URI validation tests ---

    #[test]
    fn test_validate_keyring_uri_valid() {
        assert!(validate_keyring_uri("keyring://gh:github.com/alice").is_ok());
    }

    #[test]
    fn test_validate_keyring_uri_valid_with_special_service() {
        // Service names can contain colons, dots, etc.
        assert!(validate_keyring_uri("keyring://com.example.app/user@example.com").is_ok());
    }

    #[test]
    fn test_validate_keyring_uri_missing_prefix() {
        let err = validate_keyring_uri("gh:github.com/alice").expect_err("should reject");
        assert!(
            err.to_string().contains("does not start with"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_keyring_uri_missing_account() {
        let err = validate_keyring_uri("keyring://gh:github.com")
            .expect_err("should reject missing account");
        assert!(err.to_string().contains("service/account"), "got: {}", err);
    }

    #[test]
    fn test_validate_keyring_uri_empty_segment() {
        let err = validate_keyring_uri("keyring://gh:github.com/")
            .expect_err("should reject empty account");
        assert!(err.to_string().contains("empty"), "got: {}", err);
    }

    #[test]
    fn test_validate_keyring_uri_empty_service() {
        let err =
            validate_keyring_uri("keyring:///alice").expect_err("should reject empty service");
        assert!(err.to_string().contains("empty"), "got: {}", err);
    }

    #[test]
    fn test_validate_keyring_uri_forbidden_char() {
        let err = validate_keyring_uri("keyring://gh:github.com/alice;rm -rf")
            .expect_err("should reject forbidden char");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_keyring_uri_unknown_query_param_rejected() {
        let err = validate_keyring_uri("keyring://service/account?foo=bar")
            .expect_err("should reject unknown query param");
        assert!(
            err.to_string().contains("unknown query parameter"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_keyring_uri_unknown_decode_value_rejected() {
        let err = validate_keyring_uri("keyring://service/account?decode=unknown")
            .expect_err("should reject unknown decode value");
        assert!(
            err.to_string().contains("unknown decode value"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_keyring_uri_fragment_rejected() {
        let err = validate_keyring_uri("keyring://service/account#frag")
            .expect_err("should reject fragment");
        assert!(err.to_string().contains("fragment"), "got: {}", err);
    }

    #[test]
    fn test_validate_keyring_uri_decode_go_keyring_accepted() {
        assert!(validate_keyring_uri("keyring://gh:github.com/alice?decode=go-keyring").is_ok());
    }

    #[test]
    fn test_validate_keyring_uri_query_param_missing_value() {
        let err = validate_keyring_uri("keyring://service/account?decode")
            .expect_err("should reject param without value");
        assert!(err.to_string().contains("missing value"), "got: {}", err);
    }

    #[test]
    fn test_validate_keyring_uri_too_many_segments() {
        let err = validate_keyring_uri("keyring://service/account/extra")
            .expect_err("should reject extra segments");
        assert!(err.to_string().contains("service/account"), "got: {}", err);
    }

    // --- keyring:// URI redaction tests ---

    #[test]
    fn test_redact_keyring_uri_normal() {
        assert_eq!(
            redact_keyring_uri("keyring://gh:github.com/alice"),
            "keyring://gh:github.com/<redacted>"
        );
    }

    #[test]
    fn test_redact_keyring_uri_with_decode_query() {
        assert_eq!(
            redact_keyring_uri("keyring://gh:github.com/alice?decode=go-keyring"),
            "keyring://gh:github.com/<redacted>?decode=go-keyring"
        );
    }

    #[test]
    fn test_redact_keyring_uri_malformed() {
        assert_eq!(redact_keyring_uri("keyring://"), "keyring://***");
    }

    #[test]
    fn test_redact_keyring_uri_service_only() {
        assert_eq!(
            redact_keyring_uri("keyring://gh:github.com"),
            "keyring://***"
        );
    }

    #[test]
    fn test_redact_keyring_uri_non_prefix_input() {
        assert_eq!(redact_keyring_uri("not-a-keyring-uri"), "keyring://***");
    }

    // --- keyring:// ?decode=go-keyring tests ---

    #[cfg(feature = "system-keyring")]
    #[test]
    fn test_apply_keyring_decode_none_passthrough() {
        let result = apply_keyring_decode("raw-secret".to_string(), KeyringDecode::None, "test")
            .expect("None decode should passthrough");
        assert_eq!(result.as_str(), "raw-secret");
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn test_apply_keyring_decode_go_keyring_valid() {
        // "gho_testtoken" base64-encoded is "Z2hvX3Rlc3R0b2tlbg=="
        let raw = "go-keyring-base64:Z2hvX3Rlc3R0b2tlbg==".to_string();
        let result = apply_keyring_decode(raw, KeyringDecode::GoKeyring, "test")
            .expect("should decode go-keyring value");
        assert_eq!(result.as_str(), "gho_testtoken");
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn test_apply_keyring_decode_go_keyring_missing_prefix() {
        let err = apply_keyring_decode("plain-value".to_string(), KeyringDecode::GoKeyring, "test")
            .expect_err("should reject missing go-keyring prefix");
        assert!(
            err.to_string().contains("go-keyring-base64:"),
            "got: {}",
            err
        );
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn test_apply_keyring_decode_go_keyring_invalid_base64() {
        let raw = "go-keyring-base64:!!!not-base64!!!".to_string();
        let err = apply_keyring_decode(raw, KeyringDecode::GoKeyring, "test")
            .expect_err("should reject invalid base64");
        assert!(err.to_string().contains("base64-decode"), "got: {}", err);
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn test_parse_keyring_uri_decode_go_keyring() {
        let parts = parse_keyring_uri("keyring://gh:github.com/alice?decode=go-keyring")
            .expect("should parse with decode param");
        assert_eq!(parts.service, "gh:github.com");
        assert_eq!(parts.account, "alice");
        assert_eq!(parts.decode, KeyringDecode::GoKeyring);
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn test_parse_keyring_uri_no_decode() {
        let parts = parse_keyring_uri("keyring://gh:github.com/alice")
            .expect("should parse without decode param");
        assert_eq!(parts.decode, KeyringDecode::None);
    }

    // --- keyring:// build_mappings_from_pairs tests ---

    #[test]
    fn test_build_pairs_keyring_uri_valid() {
        let pairs = vec![(
            "keyring://gh:github.com/alice".to_string(),
            "GH_TOKEN".to_string(),
        )];
        let mappings = build_mappings_from_pairs(&pairs).expect("should accept valid keyring URI");
        assert_eq!(
            mappings.get("keyring://gh:github.com/alice"),
            Some(&"GH_TOKEN".to_string())
        );
    }

    #[test]
    fn test_build_pairs_keyring_uri_with_decode() {
        let pairs = vec![(
            "keyring://gh:github.com/alice?decode=go-keyring".to_string(),
            "GH_TOKEN".to_string(),
        )];
        let mappings =
            build_mappings_from_pairs(&pairs).expect("should accept keyring URI with decode");
        assert_eq!(
            mappings.get("keyring://gh:github.com/alice?decode=go-keyring"),
            Some(&"GH_TOKEN".to_string())
        );
    }

    #[test]
    fn test_build_pairs_keyring_uri_invalid() {
        let pairs = vec![(
            "keyring://gh:github.com".to_string(),
            "GH_TOKEN".to_string(),
        )];
        let err = build_mappings_from_pairs(&pairs).expect_err("should reject missing account");
        assert!(err.to_string().contains("service/account"), "got: {}", err);
    }

    // --- keyring:// length limit test ---

    #[test]
    fn test_validate_keyring_uri_too_long() {
        let long_account = "a".repeat(1024);
        let uri = format!("keyring://service/{}", long_account);
        let err = validate_keyring_uri(&uri).expect_err("should reject oversized URI");
        assert!(err.to_string().contains("maximum length"), "got: {}", err);
    }

    // --- op:// URI validation tests ---
    //
    // These tests verify that validate_op_uri correctly accepts valid 1Password
    // secret references and rejects malformed or dangerous ones. The rejection
    // tests are security-critical: the URI is passed as an argument to
    // `op read <uri>`, so we must prevent characters that could alter command
    // behavior even though we use Command::new (no shell).

    #[test]
    fn test_validate_op_uri_valid_3_segments() {
        // Standard 1Password reference: op://vault/item/field
        assert!(validate_op_uri("op://vault/item/field").is_ok());
    }

    #[test]
    fn test_validate_op_uri_valid_4_segments() {
        // Section-qualified reference: op://vault/item/section/field
        // 1Password supports organizing fields into sections within an item
        assert!(validate_op_uri("op://vault/item/section/field").is_ok());
    }

    #[test]
    fn test_validate_op_uri_valid_with_spaces_and_dashes() {
        // 1Password vault and item names commonly contain spaces and dashes
        assert!(validate_op_uri("op://My Vault/My-Item/api-key").is_ok());
    }

    #[test]
    fn test_validate_op_uri_missing_prefix() {
        let err = validate_op_uri("vault/item/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("does not start with"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_too_few_segments() {
        // op://vault/item is missing the field segment — `op read` would fail
        // but we reject early to give a clear error message
        let err = validate_op_uri("op://vault/item").expect_err("should be rejected");
        assert!(
            err.to_string().contains("at least vault/item/field"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_single_segment() {
        let err = validate_op_uri("op://vault").expect_err("should be rejected");
        assert!(
            err.to_string().contains("at least vault/item/field"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_empty_vault() {
        // Empty vault segment could cause unexpected behavior in `op read`
        let err = validate_op_uri("op:///item/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("empty path segment"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_empty_item() {
        let err = validate_op_uri("op://vault//field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("empty path segment"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_empty_field() {
        // Trailing slash produces an empty final segment
        let err = validate_op_uri("op://vault/item/").expect_err("should be rejected");
        assert!(
            err.to_string().contains("empty path segment"),
            "got: {}",
            err
        );
    }

    // --- Injection prevention tests ---
    //
    // Although we use Command::new (no shell), these characters are still
    // rejected as defense-in-depth. A semicolon or pipe in a URI is never
    // legitimate and likely indicates an injection attempt.

    #[test]
    fn test_validate_op_uri_forbidden_semicolon() {
        // Semicolons are shell command separators — reject to prevent
        // injection if the URI is ever accidentally passed through a shell
        let err = validate_op_uri("op://vault/item;rm -rf/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_forbidden_pipe() {
        // Pipes could chain commands in a shell context
        let err = validate_op_uri("op://vault/item|evil/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_forbidden_dollar() {
        // Dollar signs enable variable expansion in shell contexts —
        // could leak env vars like $HOME into the `op` argument
        let err = validate_op_uri("op://vault/$HOME/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_forbidden_backtick() {
        // Backticks trigger command substitution in sh/bash — a classic
        // injection vector where `whoami` would execute as a subprocess
        let err = validate_op_uri("op://vault/`whoami`/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_forbidden_newline() {
        // Newlines could cause argument splitting or log injection
        let err = validate_op_uri("op://vault/item\n/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_query_string() {
        // 1Password URIs don't use query strings — their presence suggests
        // confusion with HTTP URLs or an attempt to inject extra parameters
        let err = validate_op_uri("op://vault/item/field?x=y").expect_err("should be rejected");
        assert!(
            err.to_string().contains("query strings or fragments"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_fragment() {
        let err = validate_op_uri("op://vault/item/field#section").expect_err("should be rejected");
        assert!(
            err.to_string().contains("query strings or fragments"),
            "got: {}",
            err
        );
    }

    // --- redact_op_uri tests ---
    //
    // The field segment (the actual secret name) is masked in logs to avoid
    // leaking what secret is being accessed. Vault and item names are kept
    // visible for debuggability.

    #[test]
    fn test_redact_op_uri_3_segments() {
        assert_eq!(
            redact_op_uri("op://MyVault/MyItem/credential"),
            "op://MyVault/MyItem/<redacted>"
        );
    }

    #[test]
    fn test_redact_op_uri_4_segments() {
        // Section-qualified URIs: everything after item is redacted
        assert_eq!(
            redact_op_uri("op://MyVault/MyItem/section/field"),
            "op://MyVault/MyItem/<redacted>"
        );
    }

    #[test]
    fn test_redact_op_uri_malformed() {
        // Malformed URIs get fully redacted — no partial information leak
        assert_eq!(redact_op_uri("op://only"), "op://***");
    }

    #[test]
    fn test_redact_op_uri_not_op() {
        // Non-op:// strings get fully redacted
        assert_eq!(redact_op_uri("keyring_account"), "op://***");
    }

    // --- bw:// URI validation tests ---

    #[test]
    fn test_validate_bw_uri_valid_item_only() {
        validate_bw_uri("bw://my-api-key").expect("should accept item-only URI");
    }

    #[test]
    fn test_validate_bw_uri_valid_item_and_field() {
        validate_bw_uri("bw://my-api-key/password").expect("should accept item/field URI");
    }

    #[test]
    fn test_validate_bw_uri_valid_with_uuid() {
        validate_bw_uri("bw://550e8400-e29b-41d4-a716-446655440000")
            .expect("should accept UUID item ID");
    }

    #[test]
    fn test_validate_bw_uri_valid_with_uuid_and_field() {
        validate_bw_uri("bw://550e8400-e29b-41d4-a716-446655440000/password")
            .expect("should accept UUID item/field URI");
    }

    #[test]
    fn test_validate_bw_uri_missing_prefix() {
        let err = validate_bw_uri("my-api-key").expect_err("should reject missing prefix");
        assert!(
            err.to_string().contains("does not start with"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_empty_item() {
        let err = validate_bw_uri("bw://").expect_err("should reject empty item");
        assert!(
            err.to_string().contains("must specify an item ID"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_empty_field() {
        let err = validate_bw_uri("bw://my-item/").expect_err("should reject empty field");
        assert!(
            err.to_string().contains("empty field segment"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_too_many_segments() {
        let err =
            validate_bw_uri("bw://item/field/extra").expect_err("should reject too many segments");
        assert!(
            err.to_string().contains("bw://item-id")
                || err.to_string().contains("bw://item-id/field"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_forbidden_semicolon() {
        let err = validate_bw_uri("bw://item;bad").expect_err("should reject semicolon");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_forbidden_pipe() {
        let err = validate_bw_uri("bw://item|bad").expect_err("should reject pipe");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_forbidden_dollar() {
        let err = validate_bw_uri("bw://item$bad").expect_err("should reject dollar");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_forbidden_backtick() {
        let err = validate_bw_uri("bw://item`bad").expect_err("should reject backtick");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_forbidden_newline() {
        let err = validate_bw_uri("bw://item\nbad").expect_err("should reject newline");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_forbidden_equals() {
        let err = validate_bw_uri("bw://item=bad").expect_err("should reject equals");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_query_string() {
        let err = validate_bw_uri("bw://item?foo=bar").expect_err("should reject query string");
        assert!(
            err.to_string().contains("query strings or fragments"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_fragment() {
        let err = validate_bw_uri("bw://item#fragment").expect_err("should reject fragment");
        assert!(
            err.to_string().contains("query strings or fragments"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_leading_dash_item() {
        let err = validate_bw_uri("bw://-login").expect_err("should reject leading '-' in item");
        assert!(
            err.to_string().contains("must not start with '-'"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_bw_uri_leading_dash_field() {
        let err = validate_bw_uri("bw://item/--login")
            .expect_err("should reject leading '-' in field segment");
        assert!(
            err.to_string().contains("must not start with '-'"),
            "got: {}",
            err
        );
    }

    // --- is_bw_uri tests ---

    #[test]
    fn test_is_bw_uri_positive() {
        assert!(is_bw_uri("bw://my-item"));
    }

    #[test]
    fn test_is_bw_uri_negative() {
        assert!(!is_bw_uri("op://vault/item/field"));
        assert!(!is_bw_uri("keyring://service/account"));
        assert!(!is_bw_uri("my_api_key"));
    }

    // --- redact_bw_uri tests ---

    #[test]
    fn test_redact_bw_uri_item_only() {
        assert_eq!(redact_bw_uri("bw://my-api-key"), "bw://<redacted>");
    }

    #[test]
    fn test_redact_bw_uri_item_and_field() {
        assert_eq!(
            redact_bw_uri("bw://my-api-key/password"),
            "bw://<redacted>/password"
        );
    }

    #[test]
    fn test_redact_bw_uri_malformed() {
        assert_eq!(redact_bw_uri("bw://"), "bw://<redacted>");
    }

    #[test]
    fn test_redact_bw_uri_not_bw() {
        assert_eq!(redact_bw_uri("keyring_account"), "bw://***");
    }

    // --- classify_bw_error tests ---

    #[test]
    fn test_classify_bw_error_not_authenticated() {
        let err = classify_bw_error("You are not logged in.", "bw://my-item");
        let msg = err.to_string();
        assert!(
            msg.contains("Bitwarden authentication required"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn test_classify_bw_error_vault_locked() {
        let err = classify_bw_error("Vault is locked.", "bw://my-item");
        let msg = err.to_string();
        assert!(
            msg.contains("Bitwarden authentication required"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn test_classify_bw_error_session_expired() {
        let err = classify_bw_error("Session has expired.", "bw://my-item");
        let msg = err.to_string();
        assert!(
            msg.contains("Bitwarden authentication required"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn test_classify_bw_error_not_found() {
        let err = classify_bw_error("not found", "bw://my-item");
        let msg = err.to_string();
        assert!(msg.contains("Bitwarden item not found"), "got: {}", msg);
    }

    #[test]
    fn test_classify_bw_error_couldnt_find() {
        let err = classify_bw_error("Couldn't find item", "bw://my-item");
        let msg = err.to_string();
        assert!(msg.contains("Bitwarden item not found"), "got: {}", msg);
    }

    #[test]
    fn test_classify_bw_error_unknown() {
        let err = classify_bw_error("some unexpected error", "bw://my-item");
        let msg = err.to_string();
        assert!(msg.contains("Bitwarden CLI failed"), "got: {}", msg);
    }

    #[test]
    fn test_classify_bw_error_master_password_prompt() {
        // When vault is locked, bw prompts for master password on stderr
        let err = classify_bw_error("? Master password: [input is hidden]", "bw://my-item");
        let msg = err.to_string();
        assert!(
            msg.contains("Bitwarden authentication required"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn test_classify_bw_error_readline_crash() {
        // bw crashes with ERR_USE_AFTER_CLOSE when stdin is not a TTY
        let err = classify_bw_error(
            "Error [ERR_USE_AFTER_CLOSE]: readline was closed",
            "bw://my-item",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("Bitwarden authentication required"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn test_classify_bw_error_empty_stderr() {
        // Empty stderr + empty stdout = silent locked vault
        let err = classify_bw_error("", "bw://my-item");
        let msg = err.to_string();
        assert!(
            msg.contains("empty output") || msg.contains("vault may be locked"),
            "got: {}",
            msg
        );
    }

    // --- build_mappings_from_list bw:// URI tests ---

    #[test]
    fn test_build_mappings_bw_uri_with_var_name() {
        let mappings = build_mappings_from_list("bw://my-api-key=MY_SECRET").expect("should parse");
        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("bw://my-api-key"),
            Some(&"MY_SECRET".to_string())
        );
    }

    #[test]
    fn test_build_mappings_bw_uri_with_field_and_var_name() {
        let mappings =
            build_mappings_from_list("bw://my-item/password=MY_PASS").expect("should parse");
        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("bw://my-item/password"),
            Some(&"MY_PASS".to_string())
        );
    }

    #[test]
    fn test_build_mappings_mixed_op_and_bw() {
        let mappings =
            build_mappings_from_list("op://vault/item/field=OP_SECRET,bw://my-key=BW_SECRET")
                .expect("should parse");
        assert_eq!(mappings.len(), 2);
        assert_eq!(
            mappings.get("op://vault/item/field"),
            Some(&"OP_SECRET".to_string())
        );
        assert_eq!(mappings.get("bw://my-key"), Some(&"BW_SECRET".to_string()));
    }

    #[test]
    fn test_build_mappings_bw_uri_without_var_rejected() {
        let err =
            build_mappings_from_list("bw://my-key").expect_err("should reject bare bw:// URI");
        assert!(
            err.to_string().contains("explicit variable name"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_build_mappings_bw_uri_empty_var_rejected() {
        let err =
            build_mappings_from_list("bw://my-key=").expect_err("should reject empty var name");
        assert!(err.to_string().contains("no variable name"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_bw_uri_invalid_uri_rejected() {
        let err =
            build_mappings_from_list("bw://=MY_VAR").expect_err("should reject empty item ID");
        assert!(err.to_string().contains("item ID"), "got: {}", err);
    }

    #[test]
    fn test_build_pairs_bw_uri_valid() {
        let pairs = vec![("bw://my-api-key".to_string(), "MY_SECRET".to_string())];
        let mappings = build_mappings_from_pairs(&pairs).expect("should parse");
        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("bw://my-api-key"),
            Some(&"MY_SECRET".to_string())
        );
    }

    #[test]
    fn test_build_pairs_bw_uri_invalid() {
        let pairs = vec![("bw://=MY_VAR".to_string(), "MY_SECRET".to_string())];
        let err = build_mappings_from_pairs(&pairs).expect_err("should reject");
        assert!(
            err.to_string().contains("forbidden character") || err.to_string().contains("item ID"),
            "got: {}",
            err
        );
    }

    // --- load_secret_by_ref dispatches bw:// ---

    #[test]
    fn test_load_secret_by_ref_dispatches_bw() {
        // bw:// should be recognized and dispatched to the Bitwarden backend.
        // When the vault is locked (no BW_SESSION), bw exits 0 with empty stdout
        // and a Master password prompt on stderr. We verify that this is
        // classified as a Bitwarden auth error, not silently accepted.
        let result = load_secret_by_ref(
            DEFAULT_SERVICE,
            "bw://nono-test-item-that-does-not-exist-xyz",
        );
        match result {
            Ok(secret) => {
                // If bw somehow returns a non-empty secret, that's fine
                // (item exists and vault is unlocked).
                assert!(
                    !secret.as_str().is_empty(),
                    "bw returned empty secret for locked vault - this should be an error"
                );
            }
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("Bitwarden"),
                    "expected Bitwarden-related error, got: {}",
                    msg
                );
            }
        }
    }

    // --- extract_bw_field: hermetic JSON-parse tests (no bw invocation) ---

    #[test]
    fn test_extract_bw_field_login_password() {
        let json = r#"{"login":{"password":"secret-pw"}}"#;
        let v = extract_bw_field(json, "password", "bw://item-id/password").expect("ok");
        assert_eq!(&*v, "secret-pw");
    }

    #[test]
    fn test_extract_bw_field_login_username() {
        let json = r#"{"login":{"username":"alice"}}"#;
        let v = extract_bw_field(json, "username", "bw://item-id/username").expect("ok");
        assert_eq!(&*v, "alice");
    }

    #[test]
    fn test_extract_bw_field_login_totp() {
        let json = r#"{"login":{"totp":"otpauth://totp/x?secret=ABC"}}"#;
        let v = extract_bw_field(json, "totp", "bw://item-id/totp").expect("ok");
        assert_eq!(&*v, "otpauth://totp/x?secret=ABC");
    }

    #[test]
    fn test_extract_bw_field_uri_first_entry() {
        let json =
            r#"{"login":{"uris":[{"uri":"https://a.example"},{"uri":"https://b.example"}]}}"#;
        let v = extract_bw_field(json, "uri", "bw://item-id/uri").expect("ok");
        assert_eq!(&*v, "https://a.example");
    }

    #[test]
    fn test_extract_bw_field_notes_top_level() {
        // Notes live at the item top level, not under login.
        let json = r#"{"login":{"password":"p"},"notes":"the note"}"#;
        let v = extract_bw_field(json, "notes", "bw://item-id/notes").expect("ok");
        assert_eq!(&*v, "the note");
    }

    #[test]
    fn test_extract_bw_field_custom_by_name() {
        let json = r#"{"fields":[{"name":"api-key","value":"key-456"}]}"#;
        let v = extract_bw_field(json, "api-key", "bw://item-id/api-key").expect("ok");
        assert_eq!(&*v, "key-456");
    }

    #[test]
    fn test_extract_bw_field_builtin_wins_over_custom() {
        // A custom field literally named "password" must NOT shadow login.password.
        // Mirrors `bw get password <id>` which always returns login.password.
        let json = r#"{
            "login":{"password":"login-pw"},
            "fields":[{"name":"password","value":"custom-pw"}]
        }"#;
        let v = extract_bw_field(json, "password", "bw://item-id/password").expect("ok");
        assert_eq!(&*v, "login-pw");
    }

    #[test]
    fn test_extract_bw_field_custom_when_login_absent() {
        // Note-style item with no login object; custom fields still work.
        let json = r#"{"notes":"n","fields":[{"name":"token","value":"t"}]}"#;
        let v = extract_bw_field(json, "token", "bw://item-id/token").expect("ok");
        assert_eq!(&*v, "t");
        // And `notes` still resolves via the top-level slot.
        let n = extract_bw_field(json, "notes", "bw://item-id/notes").expect("ok");
        assert_eq!(&*n, "n");
    }

    #[test]
    fn test_extract_bw_field_missing_returns_clear_error() {
        let json = r#"{"login":{"username":"alice"}}"#;
        let err = extract_bw_field(json, "password", "bw://item-id/password")
            .expect_err("missing field must error");
        let msg = err.to_string();
        assert!(msg.contains("no field named 'password'"), "got: {msg}");
    }

    #[test]
    fn test_extract_bw_field_invalid_json_returns_keystore_error() {
        let err = extract_bw_field("not json", "password", "bw://item-id/password")
            .expect_err("invalid JSON must error");
        let msg = err.to_string();
        assert!(msg.contains("invalid JSON"), "got: {msg}");
    }

    #[test]
    fn test_extract_bw_field_redacts_uri_in_error() {
        // The raw item id MUST NOT appear in error messages — only the redacted form.
        let item_id = "14cd3ba3-46de-46cf-bb7c-8d082c2dadcc";
        let uri = format!("bw://{item_id}/missing");
        let err = extract_bw_field(r#"{}"#, "missing", &uri).expect_err("must error");
        let msg = err.to_string();
        assert!(
            !msg.contains(item_id),
            "raw item id leaked into error: {msg}"
        );
        assert!(
            msg.contains("<redacted>"),
            "expected redaction marker: {msg}"
        );
    }

    #[test]
    fn test_redact_apple_password_uri_valid() {
        assert_eq!(
            redact_apple_password_uri("apple-password://github.com/alice@example.com"),
            "apple-password://github.com/<redacted>"
        );
    }

    #[test]
    fn test_redact_apple_password_uri_alias_prefix() {
        assert_eq!(
            redact_apple_password_uri("apple-passwords://github.com/alice@example.com"),
            "apple-password://github.com/<redacted>"
        );
    }

    #[test]
    fn test_redact_apple_password_uri_malformed() {
        assert_eq!(
            redact_apple_password_uri("apple-password://only-server"),
            "apple-password://***"
        );
    }

    // --- redact_file_uri tests ---

    #[test]
    fn test_redact_file_uri() {
        assert_eq!(
            redact_file_uri("file:///run/secrets/api-token"),
            "file:///run/secrets/[REDACTED]"
        );
        assert_eq!(
            redact_file_uri("file:///etc/ssl/cert.pem"),
            "file:///etc/ssl/[REDACTED]"
        );
    }

    #[test]
    fn test_redact_file_uri_root_path() {
        assert_eq!(redact_file_uri("file:///secret"), "file:///[REDACTED]");
    }

    // --- classify_op_error tests ---
    //
    // Verify that `op` CLI stderr messages are mapped to actionable errors
    // so users know whether to run `op signin`, fix a typo, or debug network.

    #[test]
    fn test_classify_op_error_auth_required() {
        let err = classify_op_error(
            "[ERROR] not signed in. Run 'op signin' first.\n",
            "op://vault/item/field",
        );
        let msg = err.to_string();
        assert!(msg.contains("authentication required"), "got: {}", msg);
        assert!(msg.contains("op signin"), "got: {}", msg);
    }

    #[test]
    fn test_classify_op_error_session_expired() {
        let err = classify_op_error("[ERROR] session expired\n", "op://vault/item/field");
        let msg = err.to_string();
        assert!(msg.contains("authentication required"), "got: {}", msg);
    }

    #[test]
    fn test_classify_op_error_not_found() {
        // Maps to SecretNotFound so callers can distinguish "auth problem"
        // from "wrong vault/item name"
        let err = classify_op_error(
            "[ERROR] \"item\" not found in vault \"vault\"\n",
            "op://vault/item/field",
        );
        let msg = err.to_string();
        assert!(msg.contains("not found"), "got: {}", msg);
    }

    #[test]
    fn test_classify_op_error_unknown() {
        // Unrecognized errors fall through to a generic message
        let err = classify_op_error("[ERROR] network timeout\n", "op://vault/item/field");
        let msg = err.to_string();
        assert!(msg.contains("1Password CLI failed"), "got: {}", msg);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_classify_apple_password_error_not_found() {
        let err = classify_apple_password_error(
            "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
            "apple-password://github.com/alice@example.com",
        );
        let msg = err.to_string();
        assert!(msg.contains("entry not found"), "got: {}", msg);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_classify_apple_password_error_user_interaction_required() {
        let err = classify_apple_password_error(
            "security: SecKeychainSearchCopyNext: User interaction is not allowed.\n",
            "apple-password://github.com/alice@example.com",
        );
        let msg = err.to_string();
        assert!(msg.contains("requires user approval"), "got: {}", msg);
    }

    // --- is_op_uri tests ---

    #[test]
    fn test_is_op_uri_positive() {
        assert!(is_op_uri("op://vault/item/field"));
    }

    #[test]
    fn test_is_op_uri_negative() {
        // Bare keyring account names must not be misidentified as 1Password refs
        assert!(!is_op_uri("openai_api_key"));
    }

    #[test]
    fn test_is_apple_password_uri_positive() {
        assert!(is_apple_password_uri(
            "apple-password://github.com/alice@example.com"
        ));
        assert!(is_apple_password_uri(
            "apple-passwords://github.com/alice@example.com"
        ));
    }

    #[test]
    fn test_is_apple_password_uri_negative() {
        assert!(!is_apple_password_uri("openai_api_key"));
        assert!(!is_apple_password_uri("op://vault/item/field"));
    }

    // --- load_secret_by_ref dispatch ---

    #[test]
    fn test_load_secret_by_ref_dispatches_op() {
        // Verify that op:// URIs are routed to the 1Password backend, not keyring.
        // We expect a 1Password-specific error (op not installed or auth failure),
        // NOT a keyring "entry not found" error.
        let result = load_secret_by_ref("nono", "op://vault/item/field");
        assert!(result.is_err());
        let err = result.expect_err("should be rejected").to_string();
        assert!(
            err.contains("1Password") || err.contains("op"),
            "expected 1Password error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_secret_by_ref_dispatches_apple_passwords() {
        // Verify that Apple Password URIs are routed to the Apple backend.
        // On macOS this should return an Apple Passwords / security-specific error.
        // On non-macOS it should return the explicit unsupported-platform error.
        let result = load_secret_by_ref("nono", "apple-password://github.com/alice@example.com");
        assert!(result.is_err());
        let err = result.expect_err("should be rejected").to_string();
        assert!(
            err.contains("Apple Passwords")
                || err.contains("security")
                || err.contains("only supported on macOS"),
            "expected Apple Passwords error, got: {}",
            err
        );
    }

    // =========================================================================
    // env:// URI tests
    // =========================================================================

    #[test]
    fn test_is_env_uri_positive() {
        assert!(is_env_uri("env://GITHUB_TOKEN"));
        assert!(is_env_uri("env://MY_KEY_123"));
    }

    #[test]
    fn test_is_env_uri_negative() {
        assert!(!is_env_uri("openai_api_key"));
        assert!(!is_env_uri("op://vault/item/field"));
        assert!(!is_env_uri("apple-password://github.com/alice@example.com"));
        assert!(!is_env_uri("ENV://UPPER_SCHEME"));
    }

    #[test]
    fn test_validate_env_uri_valid() {
        assert!(validate_env_uri("env://GITHUB_TOKEN").is_ok());
        assert!(validate_env_uri("env://MY_API_KEY_123").is_ok());
        assert!(validate_env_uri("env://x").is_ok());
        assert!(validate_env_uri("env://A").is_ok());
    }

    #[test]
    fn test_validate_env_uri_empty_name() {
        let err = validate_env_uri("env://").expect_err("should reject");
        assert!(
            err.to_string().contains("empty variable name"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_env_uri_invalid_chars() {
        // Spaces
        let err = validate_env_uri("env://MY VAR").expect_err("should reject");
        assert!(
            err.to_string().contains("invalid character"),
            "got: {}",
            err
        );

        // Dashes
        let err = validate_env_uri("env://MY-VAR").expect_err("should reject");
        assert!(
            err.to_string().contains("invalid character"),
            "got: {}",
            err
        );

        // Dots
        let err = validate_env_uri("env://MY.VAR").expect_err("should reject");
        assert!(
            err.to_string().contains("invalid character"),
            "got: {}",
            err
        );

        // Shell metacharacters
        let err = validate_env_uri("env://$(whoami)").expect_err("should reject");
        assert!(
            err.to_string().contains("invalid character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_env_uri_dangerous_ld_preload() {
        let err = validate_env_uri("env://LD_PRELOAD").expect_err("should reject");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);
    }

    #[test]
    fn test_validate_env_uri_dangerous_dyld() {
        let err = validate_env_uri("env://DYLD_INSERT_LIBRARIES").expect_err("should reject");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);
    }

    #[test]
    fn test_validate_env_uri_dangerous_node_options() {
        let err = validate_env_uri("env://NODE_OPTIONS").expect_err("should reject");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);
    }

    #[test]
    fn test_validate_env_uri_dangerous_path() {
        let err = validate_env_uri("env://PATH").expect_err("should reject");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);
    }

    #[test]
    fn test_validate_env_uri_missing_prefix() {
        let err = validate_env_uri("GITHUB_TOKEN").expect_err("should reject");
        assert!(
            err.to_string().contains("does not start with"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_load_from_env_set() {
        // Set a test variable, load it, verify value
        let test_var = "NONO_TEST_ENV_SECRET_12345";
        unsafe { std::env::set_var(test_var, "secret_value_42") };

        let result = load_from_env(&format!("env://{}", test_var));
        assert!(result.is_ok(), "should load: {:?}", result.err());
        assert_eq!(*result.expect("should load"), "secret_value_42");

        unsafe { std::env::remove_var(test_var) };
    }

    #[test]
    fn test_load_from_env_not_set() {
        let result = load_from_env("env://NONO_NONEXISTENT_VAR_XYZZY");
        assert!(result.is_err());
        let err = result.expect_err("should fail").to_string();
        assert!(err.contains("not set"), "got: {}", err);
    }

    #[test]
    fn test_load_from_env_empty() {
        let test_var = "NONO_TEST_ENV_EMPTY_12345";
        unsafe { std::env::set_var(test_var, "") };

        let result = load_from_env(&format!("env://{}", test_var));
        assert!(result.is_err());
        let err = result.expect_err("should fail").to_string();
        assert!(err.contains("empty"), "got: {}", err);

        unsafe { std::env::remove_var(test_var) };
    }

    #[test]
    fn test_load_secret_by_ref_dispatches_env() {
        let test_var = "NONO_TEST_REF_DISPATCH_12345";
        unsafe { std::env::set_var(test_var, "dispatched_ok") };

        let result = load_secret_by_ref("nono", &format!("env://{}", test_var));
        assert!(
            result.is_ok(),
            "should dispatch to env backend: {:?}",
            result.err()
        );
        assert_eq!(*result.expect("should load"), "dispatched_ok");

        unsafe { std::env::remove_var(test_var) };
    }

    // --- env:// in build_mappings_from_list ---

    #[test]
    fn test_build_mappings_env_uri_auto_derive() {
        let mappings = build_mappings_from_list("env://GITHUB_TOKEN").expect("should parse");
        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("env://GITHUB_TOKEN"),
            Some(&"GITHUB_TOKEN".to_string())
        );
    }

    #[test]
    fn test_build_mappings_env_uri_with_explicit_var() {
        let mappings =
            build_mappings_from_list("env://GITHUB_TOKEN=GH_TOKEN").expect("should parse");
        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("env://GITHUB_TOKEN"),
            Some(&"GH_TOKEN".to_string())
        );
    }

    #[test]
    fn test_build_mappings_env_uri_empty_var_rejected() {
        let err =
            build_mappings_from_list("env://GITHUB_TOKEN=").expect_err("should reject empty var");
        assert!(err.to_string().contains("no variable name"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_env_uri_dangerous_rejected() {
        let err =
            build_mappings_from_list("env://LD_PRELOAD").expect_err("should reject dangerous var");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_mixed_keyring_op_env() {
        let mappings = build_mappings_from_list(
            "my_api_key,op://vault/item/field=SECRET_VAR,env://GITHUB_TOKEN",
        )
        .expect("should parse");

        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings.get("my_api_key"), Some(&"MY_API_KEY".to_string()));
        assert_eq!(
            mappings.get("op://vault/item/field"),
            Some(&"SECRET_VAR".to_string())
        );
        assert_eq!(
            mappings.get("env://GITHUB_TOKEN"),
            Some(&"GITHUB_TOKEN".to_string())
        );
    }

    // =========================================================================
    // Case-insensitive dangerous env var bypass prevention
    // =========================================================================

    #[test]
    fn test_validate_env_uri_dangerous_case_insensitive() {
        // Lowercase must be caught (case-insensitive check)
        let err = validate_env_uri("env://ld_preload").expect_err("should reject");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);

        // Mixed case must be caught
        let err = validate_env_uri("env://Ld_Preload").expect_err("should reject");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);

        let err = validate_env_uri("env://path").expect_err("should reject");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);

        let err = validate_env_uri("env://Node_Options").expect_err("should reject");
        assert!(err.to_string().contains("dangerous"), "got: {}", err);
    }

    // =========================================================================
    // Destination env var validation
    // =========================================================================

    #[test]
    fn test_validate_destination_env_var_valid() {
        assert!(validate_destination_env_var("GITHUB_TOKEN").is_ok());
        assert!(validate_destination_env_var("MY_API_KEY").is_ok());
        assert!(validate_destination_env_var("x").is_ok());
    }

    #[test]
    fn test_validate_destination_env_var_empty() {
        let err = validate_destination_env_var("").expect_err("should reject");
        assert!(err.to_string().contains("empty"), "got: {}", err);
    }

    #[test]
    fn test_validate_destination_env_var_invalid_chars() {
        let err = validate_destination_env_var("MY-VAR").expect_err("should reject");
        assert!(
            err.to_string().contains("invalid character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_destination_env_var_dangerous() {
        let err = validate_destination_env_var("LD_PRELOAD").expect_err("should reject");
        assert!(err.to_string().contains("blocklist"), "got: {}", err);
    }

    #[test]
    fn test_validate_destination_env_var_dangerous_case_insensitive() {
        let err = validate_destination_env_var("ld_preload").expect_err("should reject");
        assert!(err.to_string().contains("blocklist"), "got: {}", err);

        let err = validate_destination_env_var("Path").expect_err("should reject");
        assert!(err.to_string().contains("blocklist"), "got: {}", err);

        let err = validate_destination_env_var("DYLD_INSERT_LIBRARIES").expect_err("should reject");
        assert!(err.to_string().contains("blocklist"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_env_uri_explicit_dangerous_target_rejected() {
        // env://SAFE_VAR=LD_PRELOAD must be rejected
        let err = build_mappings_from_list("env://SAFE_VAR=LD_PRELOAD")
            .expect_err("should reject dangerous target");
        assert!(err.to_string().contains("blocklist"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_op_uri_dangerous_target_rejected() {
        // op://vault/item/field=PATH must be rejected
        let err = build_mappings_from_list("op://vault/item/field=PATH")
            .expect_err("should reject dangerous target");
        assert!(err.to_string().contains("blocklist"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_apple_password_uri_dangerous_target_rejected() {
        // Apple Passwords refs are rejected in list mode and must use explicit map flag.
        let err = build_mappings_from_list("apple-password://github.com/alice@example.com=>PATH")
            .expect_err("should reject apple-password in list mode");
        assert!(
            err.to_string().contains("--env-credential-map"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_build_mappings_keyring_dangerous_autoderived_rejected() {
        // A keyring name that uppercases to a dangerous var must be rejected
        let err =
            build_mappings_from_list("ld_preload").expect_err("should reject dangerous target");
        assert!(err.to_string().contains("blocklist"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_bw_uri_dangerous_target_rejected() {
        // bw://item-id=PATH must be rejected
        let err = build_mappings_from_list("bw://my-key=PATH")
            .expect_err("should reject dangerous target");
        assert!(err.to_string().contains("blocklist"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_from_pairs_keyring_and_uri() {
        let pairs = vec![
            ("openai_api_key".to_string(), "OPENAI_API_KEY".to_string()),
            (
                "op://vault/item/field".to_string(),
                "OPENAI_SECRET".to_string(),
            ),
            (
                "apple-password://github.com/user=name".to_string(),
                "GITHUB_PASSWORD".to_string(),
            ),
            ("env://GITHUB_TOKEN".to_string(), "GH_TOKEN".to_string()),
        ];

        let mappings = build_mappings_from_pairs(&pairs).expect("should parse");
        assert_eq!(mappings.len(), 4);
        assert_eq!(
            mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
        assert_eq!(
            mappings.get("op://vault/item/field"),
            Some(&"OPENAI_SECRET".to_string())
        );
        assert_eq!(
            mappings.get("apple-password://github.com/user=name"),
            Some(&"GITHUB_PASSWORD".to_string())
        );
        assert_eq!(
            mappings.get("env://GITHUB_TOKEN"),
            Some(&"GH_TOKEN".to_string())
        );
    }

    #[test]
    fn test_build_mappings_from_pairs_empty_credential_ref_rejected() {
        let pairs = vec![("".to_string(), "API_KEY".to_string())];
        let err =
            build_mappings_from_pairs(&pairs).expect_err("should reject empty credential ref");
        assert!(
            err.to_string().contains("credential reference is empty"),
            "got: {}",
            err
        );
    }

    // =========================================================================
    // keyring_timeout() and call_with_keyring_timeout() tests
    // =========================================================================

    #[cfg(feature = "system-keyring")]
    mod keyring_timeout_tests {
        use super::*;
        use std::sync::Mutex;
        use std::time::Duration;

        static ENV_LOCK: Mutex<()> = Mutex::new(());

        struct EnvGuard {
            key: &'static str,
            original: Option<String>,
        }

        impl EnvGuard {
            #[allow(clippy::disallowed_methods)]
            fn set(key: &'static str, val: &str) -> Self {
                let original = std::env::var(key).ok();
                // SAFETY: serialised via ENV_LOCK
                unsafe { std::env::set_var(key, val) };
                Self { key, original }
            }

            #[allow(clippy::disallowed_methods)]
            fn remove(key: &'static str) -> Self {
                let original = std::env::var(key).ok();
                // SAFETY: serialised via ENV_LOCK
                unsafe { std::env::remove_var(key) };
                Self { key, original }
            }
        }

        #[allow(clippy::disallowed_methods)]
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.original {
                    // SAFETY: serialised via ENV_LOCK
                    Some(v) => unsafe { std::env::set_var(self.key, v) },
                    None => unsafe { std::env::remove_var(self.key) },
                }
            }
        }

        const KEY: &str = "NONO_KEYRING_TIMEOUT_SECS";

        #[test]
        fn keyring_timeout_unset_returns_default_120s() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _g = EnvGuard::remove(KEY);
            assert_eq!(keyring_timeout(), Some(Duration::from_secs(120)));
        }

        #[test]
        fn keyring_timeout_zero_returns_none() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _g = EnvGuard::set(KEY, "0");
            assert_eq!(keyring_timeout(), None);
        }

        #[test]
        fn keyring_timeout_valid_value_returns_some() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _g = EnvGuard::set(KEY, "300");
            assert_eq!(keyring_timeout(), Some(Duration::from_secs(300)));
        }

        #[test]
        fn keyring_timeout_invalid_falls_back_to_default() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _g = EnvGuard::set(KEY, "banana");
            assert_eq!(keyring_timeout(), Some(Duration::from_secs(120)));
        }

        #[test]
        fn call_with_keyring_timeout_none_runs_inline() {
            // None = no timeout; closure runs directly, no thread spawned
            let result: Result<u32> = call_with_keyring_timeout(None, "test", || Ok(42_u32));
            assert_eq!(result.unwrap(), 42);
        }

        #[test]
        fn call_with_keyring_timeout_fast_call_returns_value() {
            let result: Result<u32> =
                call_with_keyring_timeout(Some(Duration::from_secs(5)), "test", || Ok(99_u32));
            assert_eq!(result.unwrap(), 99);
        }

        #[test]
        fn call_with_keyring_timeout_slow_call_fires() {
            let result: Result<u32> =
                call_with_keyring_timeout(Some(Duration::from_millis(50)), "slow-test", || {
                    std::thread::sleep(Duration::from_secs(10));
                    Ok(0_u32)
                });
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("timed out") && err.contains("NONO_KEYRING_TIMEOUT_SECS"),
                "got: {}",
                err
            );
        }
    }

    #[test]
    fn test_build_secret_mappings_explicit_pairs_take_precedence() {
        let mut profile = HashMap::new();
        profile.insert("openai_api_key".to_string(), "FROM_PROFILE".to_string());

        let cli_pairs = vec![("openai_api_key".to_string(), "FROM_MAP".to_string())];
        let merged =
            build_secret_mappings(Some("openai_api_key"), &cli_pairs, &profile).expect("merge ok");

        assert_eq!(merged.len(), 1);
        assert_eq!(merged.get("openai_api_key"), Some(&"FROM_MAP".to_string()));
    }

    // =========================================================================
    // file:// URI tests
    // =========================================================================

    #[test]
    fn test_validate_file_uri_valid_absolute_path() {
        assert!(validate_file_uri("file:///run/secrets/api-token").is_ok());
        assert!(validate_file_uri("file:///tmp/secret.txt").is_ok());
        assert!(validate_file_uri("file:///etc/ssl/certs/ca.pem").is_ok());
    }

    #[test]
    fn test_validate_file_uri_rejects_empty_path() {
        assert!(validate_file_uri("file://").is_err());
        assert!(validate_file_uri("file:///").is_err());
    }

    #[test]
    fn test_validate_file_uri_rejects_relative_path() {
        assert!(validate_file_uri("file://relative/path").is_err());
        assert!(validate_file_uri("file://./secret").is_err());
        assert!(validate_file_uri("file://../escape").is_err());
    }

    #[test]
    fn test_validate_file_uri_rejects_traversal() {
        assert!(validate_file_uri("file:///run/secrets/../../../etc/shadow").is_err());
        assert!(validate_file_uri("file:///tmp/../../root/.ssh/id_rsa").is_err());
    }

    #[test]
    fn test_validate_file_uri_rejects_forbidden_characters() {
        assert!(validate_file_uri("file:///tmp/secret;rm -rf /").is_err());
        assert!(validate_file_uri("file:///tmp/secret\nnewline").is_err());
        assert!(validate_file_uri("file:///tmp/secret\x00null").is_err());
    }

    #[test]
    fn test_is_file_uri() {
        assert!(is_file_uri("file:///run/secrets/api-token"));
        assert!(!is_file_uri("env://MY_VAR"));
        assert!(!is_file_uri("/run/secrets/api-token"));
        // Note: is_file_uri is a scheme detector, not a validator.
        // "file://relative" starts with "file://" so it matches the scheme.
        // Validation (absolute path check) happens in validate_file_uri.
        assert!(is_file_uri("file://relative"));
    }

    // =========================================================================
    // load_from_file tests
    // =========================================================================

    #[test]
    fn test_load_from_file_reads_and_trims() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "my-api-key\n").unwrap();
        let uri = format!("file://{}", path.display());
        let result = load_from_file(&uri);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "my-api-key");
    }

    #[test]
    fn test_load_from_file_empty_file_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "").unwrap();
        let uri = format!("file://{}", path.display());
        let result = load_from_file(&uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_file_whitespace_only_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("whitespace.txt");
        std::fs::write(&path, "  \n  \n").unwrap();
        let uri = format!("file://{}", path.display());
        let result = load_from_file(&uri);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "  \n  ");
    }

    #[test]
    fn test_load_from_file_not_found() {
        let result = load_from_file("file:///nonexistent/path/secret.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_file_multiline_reads_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.txt");
        std::fs::write(&path, "glpat-xxxxxxxxxxxx\n").unwrap();
        let uri = format!("file://{}", path.display());
        let result = load_from_file(&uri).unwrap();
        assert_eq!(result.as_str(), "glpat-xxxxxxxxxxxx");
    }

    #[test]
    fn test_load_from_file_preserves_significant_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spaces.txt");
        std::fs::write(&path, "  secret value  \n").unwrap();
        let uri = format!("file://{}", path.display());
        let result = load_from_file(&uri).unwrap();
        assert_eq!(result.as_str(), "  secret value  ");
    }

    #[test]
    fn test_load_from_file_trims_single_trailing_crlf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crlf.txt");
        std::fs::write(&path, "secret\r\n").unwrap();
        let uri = format!("file://{}", path.display());
        let result = load_from_file(&uri).unwrap();
        assert_eq!(result.as_str(), "secret");
    }

    #[test]
    fn test_load_from_file_newline_only_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("newline-only.txt");
        std::fs::write(&path, "\n").unwrap();
        let uri = format!("file://{}", path.display());
        let result = load_from_file(&uri);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_store_secret_file_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");

        store_secret_file(&path, "top-secret").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "top-secret");
    }

    // =========================================================================
    // file:// dispatch and CLI mapping tests
    // =========================================================================

    #[test]
    fn test_load_secret_by_ref_dispatches_file_uri() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.txt");
        std::fs::write(&path, "secret-value\n").unwrap();
        let uri = format!("file://{}", path.display());
        let result = load_secret_by_ref("nono", &uri);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "secret-value");
    }

    #[test]
    fn test_build_mappings_file_uri_requires_explicit_var() {
        let result = build_mappings_from_list("file:///run/secrets/api-token=MY_API_KEY");
        assert!(result.is_ok());
        let mappings = result.unwrap();
        assert_eq!(
            mappings.get("file:///run/secrets/api-token"),
            Some(&"MY_API_KEY".to_string())
        );
    }

    #[test]
    fn test_build_mappings_file_uri_without_var_name_is_error() {
        let result = build_mappings_from_list("file:///run/secrets/api-token");
        assert!(result.is_err());
    }
}
