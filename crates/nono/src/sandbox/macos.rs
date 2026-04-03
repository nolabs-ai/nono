//! macOS sandbox implementation using Seatbelt
//!
//! This is a pure sandboxing primitive - it applies ONLY the capabilities provided.
//! The caller is responsible for:
//! - Adding system paths (e.g., /usr, /lib, /System/Library) if executables need to run
//! - Implementing any security policy (sensitive path blocking, etc.)

use crate::capability::{AccessMode, CapabilitySet, NetworkMode};
use crate::error::{NonoError, Result};
use crate::sandbox::SupportInfo;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;
use tracing::{debug, info};

// FFI bindings to macOS sandbox API
// These are private APIs but have been stable for years
// Reference: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf

extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

// FFI bindings for sandbox extension API (runtime capability expansion)
// These are documented in <sandbox.h> and stable across macOS versions.
// Extensions allow an unsandboxed supervisor to issue tokens that expand
// a sandboxed process's access for specific paths.
extern "C" {
    fn sandbox_extension_issue_file(
        extension_class: *const c_char,
        path: *const c_char,
        flags: u32,
    ) -> *mut c_char;

    fn sandbox_extension_consume(token: *const c_char) -> i64;

    fn sandbox_extension_release(handle: i64) -> i32;
}

/// Extension class for read-only access
const EXT_CLASS_READ: &str = "com.apple.app-sandbox.read";

/// Extension class for read+write access
const EXT_CLASS_READ_WRITE: &str = "com.apple.app-sandbox.read-write";

/// Extension class for execute access
const EXT_CLASS_EXECUTE: &str = "com.apple.app-sandbox.execute";

/// Issue a sandbox extension token for a path.
///
/// Called by the unsandboxed supervisor to create a token that a sandboxed
/// process can consume to expand its access for the given path.
///
/// The token is HMAC-SHA256 authenticated with a per-boot kernel key and
/// cannot be forged. It is path-specific and class-specific.
///
/// # Arguments
/// * `path` - The filesystem path to grant access to
/// * `access` - The access mode (Read -> read-only token, Write/ReadWrite -> read-write token, Execute -> execute token)
///
/// # Errors
/// Returns an error if the path contains null bytes or if the kernel rejects the request.
pub fn extension_issue_file(path: &Path, access: AccessMode) -> Result<String> {
    let class = match access {
        AccessMode::Read => EXT_CLASS_READ,
        AccessMode::Write | AccessMode::ReadWrite => EXT_CLASS_READ_WRITE,
        AccessMode::Execute => EXT_CLASS_EXECUTE,
    };

    let class_c = CString::new(class)
        .map_err(|_| NonoError::SandboxInit("Extension class contains null byte".to_string()))?;

    let path_str = path.to_str().ok_or_else(|| {
        NonoError::SandboxInit(format!("Path contains non-UTF-8 bytes: {}", path.display()))
    })?;

    let path_c = CString::new(path_str).map_err(|_| {
        NonoError::SandboxInit(format!("Path contains null byte: {}", path.display()))
    })?;

    // SAFETY: sandbox_extension_issue_file takes valid C strings for class and path,
    // and a flags argument (0 for default behavior). Returns a heap-allocated C string
    // token on success, or NULL on failure. The returned string must be freed with free().
    let token_ptr = unsafe { sandbox_extension_issue_file(class_c.as_ptr(), path_c.as_ptr(), 0) };

    if token_ptr.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "sandbox_extension_issue_file failed for path: {}",
            path.display()
        )));
    }

    // SAFETY: token_ptr is a valid, non-null C string returned by sandbox_extension_issue_file.
    let token = unsafe { CStr::from_ptr(token_ptr) }
        .to_string_lossy()
        .into_owned();

    // SAFETY: token_ptr was allocated by sandbox_extension_issue_file and must be freed.
    unsafe { libc::free(token_ptr.cast::<libc::c_void>()) };

    debug!(
        "Issued extension token for {} ({:?})",
        path.display(),
        access
    );
    Ok(token)
}

/// Consume a sandbox extension token to expand the current process's sandbox.
///
/// Called inside a sandboxed process (typically by the DYLD shim) to activate
/// a token received from the supervisor. After consumption, the sandbox allows
/// access to the token's path with the token's access class.
///
/// Consumed extensions survive `fork()` and `exec()` -- all child processes
/// inherit the expanded access.
///
/// Returns a handle that can be passed to [`extension_release`] to revoke the grant.
///
/// # Errors
/// Returns an error if the token is invalid, expired, or if consumption fails.
pub fn extension_consume(token: &str) -> Result<i64> {
    let token_c = CString::new(token)
        .map_err(|_| NonoError::SandboxInit("Extension token contains null byte".to_string()))?;

    // SAFETY: sandbox_extension_consume takes a valid C string token.
    // Returns a non-negative handle on success, or -1 on failure.
    let handle = unsafe { sandbox_extension_consume(token_c.as_ptr()) };

    if handle < 0 {
        return Err(NonoError::SandboxInit(format!(
            "sandbox_extension_consume failed (handle={})",
            handle
        )));
    }

    debug!("Consumed extension token (handle={})", handle);
    Ok(handle)
}

/// Release a consumed sandbox extension, revoking the dynamically-granted access.
///
/// # Errors
/// Returns an error if the handle is invalid or if the release fails.
pub fn extension_release(handle: i64) -> Result<()> {
    // SAFETY: sandbox_extension_release takes a handle from sandbox_extension_consume.
    // Returns 0 on success, -1 on failure.
    let result = unsafe { sandbox_extension_release(handle) };

    if result != 0 {
        return Err(NonoError::SandboxInit(format!(
            "sandbox_extension_release failed for handle {}",
            handle
        )));
    }

    debug!("Released extension (handle={})", handle);
    Ok(())
}

/// Check if Seatbelt sandboxing is supported
pub fn is_supported() -> bool {
    // Seatbelt is available on all modern macOS versions
    true
}

/// Get information about sandbox support
pub fn support_info() -> SupportInfo {
    SupportInfo {
        is_supported: true,
        platform: "macos",
        details: "macOS Seatbelt sandbox available".to_string(),
    }
}

/// Collect parent directories that need metadata access for path resolution.
///
/// Programs need to lstat() each path component when resolving paths.
/// For example, to access /Users/luke/.claude, Node.js needs to lstat:
/// - /Users
/// - /Users/luke
///
/// This function returns those parent directories so we can allow metadata
/// (but not data) access to them.
fn collect_parent_dirs(caps: &CapabilitySet) -> std::collections::HashSet<String> {
    let mut parents = std::collections::HashSet::new();

    for cap in caps.fs_capabilities() {
        // Collect parents for both resolved and original paths.
        // On macOS, /tmp is a symlink to /private/tmp. If the user passes
        // --allow /tmp, we need metadata access to / for the symlink itself.
        // The original path's parents handle this.
        let paths_to_walk: Vec<&std::path::Path> = if cap.original != cap.resolved {
            vec![cap.resolved.as_path(), cap.original.as_path()]
        } else {
            vec![cap.resolved.as_path()]
        };

        for path in paths_to_walk {
            let mut current = path.parent();
            while let Some(parent) = current {
                let parent_str = parent.to_string_lossy().to_string();

                // Stop at root
                if parent_str == "/" || parent_str.is_empty() {
                    break;
                }

                // If already present, ancestors were processed too - early exit
                if !parents.insert(parent_str) {
                    break;
                }
                current = parent.parent();
            }
        }
    }

    parents
}

/// Build Seatbelt path filters for a capability.
///
/// On macOS, symlinks like `/tmp` -> `/private/tmp` mean the user's original
/// path may differ from the canonicalized resolved path. Seatbelt operates on
/// literal paths, not resolved symlinks, so we must emit rules for both.
/// Returns one or two `(subpath "...")` or `(literal "...")` strings.
fn path_filters_for_cap(cap: &crate::capability::FsCapability) -> Result<Vec<String>> {
    let mut filters = Vec::with_capacity(2);

    let resolved_str = cap.resolved.to_str().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "path contains non-UTF-8 bytes: {}",
            cap.resolved.display()
        ))
    })?;
    let escaped_resolved = escape_path(resolved_str)?;
    let kind = if cap.is_file { "literal" } else { "subpath" };
    filters.push(format!("{} \"{}\"", kind, escaped_resolved));

    // If the original path differs (e.g. /tmp vs /private/tmp), emit a rule
    // for the original too so Seatbelt allows traversing the symlink.
    if cap.original != cap.resolved {
        if let Some(original_str) = cap.original.to_str() {
            let escaped_original = escape_path(original_str)?;
            filters.push(format!("{} \"{}\"", kind, escaped_original));
        }
    }

    Ok(filters)
}

/// Returns true if the capability set explicitly grants access to a keychain DB.
///
/// This is a narrow opt-in for tools that need OAuth/session refresh via macOS Keychain.
fn has_explicit_keychain_db_access(caps: &CapabilitySet) -> bool {
    let user_keychain_dbs = std::env::var("HOME").ok().map(|home| {
        [
            Path::new(&home).join("Library/Keychains/login.keychain-db"),
            Path::new(&home).join("Library/Keychains/metadata.keychain-db"),
        ]
    });
    let system_keychain_dbs = [
        Path::new("/Library/Keychains/login.keychain-db").to_path_buf(),
        Path::new("/Library/Keychains/metadata.keychain-db").to_path_buf(),
    ];

    let is_keychain_db = |path: &Path| -> bool {
        if system_keychain_dbs
            .iter()
            .any(|candidate| path == candidate)
        {
            return true;
        }
        if let Some(ref user_keychain_dbs) = user_keychain_dbs {
            if user_keychain_dbs.iter().any(|candidate| path == candidate) {
                return true;
            }
        }
        false
    };

    caps.fs_capabilities()
        .iter()
        .any(|cap| is_keychain_db(&cap.original) || is_keychain_db(&cap.resolved))
}

/// Escape a path for use in Seatbelt profile strings.
///
/// Paths are placed inside double-quoted S-expression strings where `\` and `"`
/// are the significant characters. Control characters (0x00-0x1F, 0x7F) are
/// rejected because silently stripping them would cause the sandbox rule to
/// target a different path than intended.
fn escape_path(path: &str) -> Result<String> {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            c if c.is_control() => {
                return Err(NonoError::SandboxInit(format!(
                    "path contains control character 0x{:02X}: {}",
                    c as u32, path
                )));
            }
            _ => result.push(c),
        }
    }
    Ok(result)
}

/// Escape a filesystem path for use inside a Seatbelt `regex` clause.
///
/// Used for non-recursive directory socket grants: a directory `/d` is
/// emitted as `(regex "^<escaped>/[^/]+$")` so only direct-child sockets
/// are matched.
///
/// Escaping strategy, by character:
///
/// | Char | Rendered Scheme source | Regex engine sees | Matches |
/// |------|------------------------|-------------------|---------|
/// | `.`, `+`, `*`, `?`, `(`, `)`, `{`, `}`, `|`, `^`, `$` | `[.]` etc. | char class | literal `.` etc. |
/// | `[`  | `\\[`  | `\[`  | literal `[` |
/// | `]`  | `\\]`  | `\]`  | literal `]` |
/// | `\`  | `\\\\` | `\\`  | literal `\` |
/// | `"`  | `\"`   | `"`   | literal `"` |
/// | other | verbatim | verbatim | as written |
///
/// The character-class form (`[.]`) is unambiguous across both raw and
/// cooked Scheme string readers (the §13 spike verified this for `.`).
/// For the three chars that can't appear literally inside `[ ]` (`[`,
/// `]`, `\`), we fall back to Scheme-level backslash escaping: the
/// Scheme reader collapses `\\` → `\`, and the regex engine then
/// interprets `\<char>` as a literal. Backslash itself needs a second
/// layer of escaping (`\\\\` → `\\` → literal `\`).
///
/// Control characters are rejected outright, matching `escape_path`'s
/// policy.
fn regex_escape_path_for_seatbelt(path: &str) -> Result<String> {
    for c in path.chars() {
        if c.is_control() {
            return Err(NonoError::SandboxInit(format!(
                "path contains control character 0x{:02X}: {}",
                c as u32, path
            )));
        }
    }
    let mut result = String::with_capacity(path.len() * 2);
    for c in path.chars() {
        match c {
            '.' | '+' | '*' | '?' | '(' | ')' | '{' | '}' | '|' | '^' | '$' => {
                result.push('[');
                result.push(c);
                result.push(']');
            }
            // `[`, `]`: can't appear in a character class literal. Emit
            // `\\<char>` (3 source chars); Scheme reduces to `\<char>`
            // which is a regex-literal match.
            '[' | ']' => {
                result.push('\\');
                result.push('\\');
                result.push(c);
            }
            // `\`: needs double escaping — emit `\\\\` (4 source chars).
            // Scheme reduces to `\\`, which the regex engine interprets
            // as a literal backslash.
            '\\' => result.push_str("\\\\\\\\"),
            // `"`: Scheme string escape only; regex engine sees the
            // bare quote as a literal character.
            '"' => result.push_str("\\\""),
            _ => result.push(c),
        }
    }
    Ok(result)
}

/// Emit Seatbelt `(allow network-outbound …)` and `(allow network-bind …)`
/// rules for each [`UnixSocketCapability`] in `caps`.
///
/// On macOS, `connect(2)` and `bind(2)` are classified as **separate**
/// Seatbelt operations (`network-outbound` and `network-bind`), so each
/// needs its own allow-rule. Mode enforcement:
///
/// - `Connect` mode: emit `network-outbound` only. `bind(2)` stays
///   denied by the base `(deny network*)` clause.
/// - `ConnectBind` mode: emit **both** `network-outbound` and
///   `network-bind`.
///
/// Path form:
///
/// - File-scoped grants emit `(… (path "…"))`.
/// - Directory-scoped grants emit `(… (regex "^<dir>/[^/]+$"))` —
///   non-recursive (direct children only), per §5 / §13 spike.
///
/// For both forms, the `original` path is emitted too when it differs
/// from `resolved` (`/tmp` vs `/private/tmp`), preserving the dual-path
/// symlink pattern.
///
/// `FsCapability` entries intentionally **do not** trigger either rule.
/// Filesystem grants and unix-socket grants are orthogonal layers per
/// #696; the CLI-side sugar in `nono-cli` auto-registers the fs grant
/// that `bind(2)`/`connect(2)` need.
fn emit_unix_socket_rules(profile: &mut String, caps: &CapabilitySet) -> Result<()> {
    for cap in caps.unix_socket_capabilities() {
        let resolved_str = cap.resolved.to_str().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "unix socket path contains non-UTF-8 bytes: {}",
                cap.resolved.display()
            ))
        })?;
        let original_str = if cap.original != cap.resolved {
            cap.original.to_str()
        } else {
            None
        };

        // Always emit for connect (network-outbound). Bind (network-bind)
        // is only emitted for ConnectBind — Connect-only grants intentionally
        // leave `bind(2)` denied by the base `(deny network*)` clause.
        let operations: &[&str] = if cap.mode.permits_bind() {
            &["network-outbound", "network-bind"]
        } else {
            &["network-outbound"]
        };

        if cap.is_directory {
            let escaped = regex_escape_path_for_seatbelt(resolved_str)?;
            let escaped_orig = original_str
                .map(regex_escape_path_for_seatbelt)
                .transpose()?;
            for op in operations {
                profile.push_str(&format!("(allow {} (regex \"^{}/[^/]+$\"))\n", op, escaped));
                if let Some(ref e) = escaped_orig {
                    profile.push_str(&format!("(allow {} (regex \"^{}/[^/]+$\"))\n", op, e));
                }
            }
        } else {
            let escaped = escape_path(resolved_str)?;
            let escaped_orig = original_str.map(escape_path).transpose()?;
            for op in operations {
                profile.push_str(&format!("(allow {} (path \"{}\"))\n", op, escaped));
                if let Some(ref e) = escaped_orig {
                    profile.push_str(&format!("(allow {} (path \"{}\"))\n", op, e));
                }
            }
        }
    }
    Ok(())
}

/// Generate a Seatbelt profile from capabilities
///
/// This is a pure primitive - it generates rules ONLY for paths in the CapabilitySet.
/// The caller must include all necessary paths (system paths, temp dirs, etc.).
///
/// Returns an error if any path contains non-UTF-8 bytes (which would produce
/// incorrect Seatbelt rules via lossy conversion).
fn generate_profile(caps: &CapabilitySet) -> Result<String> {
    let mut profile = String::new();

    // Profile version
    profile.push_str("(version 1)\n");

    // Start with deny default
    profile.push_str("(deny default)\n");
    if caps.seatbelt_debug_deny() {
        profile.push_str("(debug deny)\n");
    }

    // Allow specific process operations needed for process management
    profile.push_str("(allow process-fork)\n");

    // Process execution: scoped to paths with Execute access.
    // This prevents executing arbitrary binaries outside the granted execute paths.
    for cap in caps.fs_capabilities() {
        if matches!(
            cap.access,
            AccessMode::Execute | AccessMode::ReadExecute | AccessMode::ReadWriteExecute
        ) {
            for filter in path_filters_for_cap(cap)? {
                profile.push_str(&format!("(allow process-exec ({}))\n", filter));
            }
        }
    }

    // Process info: allow self-inspection and same-sandbox inspection for both
    // Isolated and AllowSameSandbox, matching Linux behaviour where Landlock
    // cannot distinguish the two. Denying process-info for same-sandbox children
    // would break health checks via proc_pidinfo() / sysctl(KERN_PROC) that
    // Node.js modules use to monitor child process state.
    //
    // We emit (target self) alongside (target same-sandbox) because Seatbelt's
    // same-sandbox filter may not subsume self — being explicit ensures the
    // process can always inspect itself regardless of implementation details.
    match caps.process_info_mode() {
        crate::capability::ProcessInfoMode::Isolated
        | crate::capability::ProcessInfoMode::AllowSameSandbox => {
            profile.push_str("(allow process-info* (target self))\n");
            profile.push_str("(allow process-info* (target same-sandbox))\n");
        }
        crate::capability::ProcessInfoMode::AllowAll => {
            profile.push_str("(allow process-info*)\n");
        }
    }

    // Allow specific system operations
    profile.push_str("(allow sysctl-read)\n");

    // Mach IPC: allow service resolution. Deny Keychain/security services by default.
    // If a keychain DB is explicitly granted, skip these denies so profiles that
    // intentionally rely on macOS Keychain OAuth refresh can work.
    //
    // Without these denies, blanket mach-lookup can permit Keychain retrieval via
    // Mach IPC, bypassing file-level deny rules in profiles that do NOT opt in.
    profile.push_str("(allow mach-lookup)\n");
    if !has_explicit_keychain_db_access(caps) {
        // Legacy keychain daemon names (macOS < 13)
        profile.push_str("(deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n");
        profile.push_str("(deny mach-lookup (global-name \"com.apple.securityd\"))\n");
        // Modern keychain daemon (macOS 13 Ventura+). Legacy SecKeychain APIs
        // route here on Ventura and later, bypassing the legacy service denies above.
        // Without this deny, FFI/ctypes callers can read keychain entries despite
        // the file-level deny on ~/Library/Keychains.
        profile.push_str("(deny mach-lookup (global-name \"com.apple.security.keychaind\"))\n");
        // Modern security daemon (macOS 10.10+). SecItem APIs ("Data Protection"
        // keychain) route through secd. Blocking this prevents access to iCloud
        // Keychain and modern keychain items that bypass the legacy daemon paths.
        profile.push_str("(deny mach-lookup (global-name \"com.apple.secd\"))\n");
        // Security agent: shows keychain authorization dialogs. Without this deny, the
        // agent can act as a proxy — presenting a user prompt and returning the credential
        // on behalf of the sandboxed process even when the direct daemon paths are blocked.
        profile.push_str("(deny mach-lookup (global-name \"com.apple.security.agent\"))\n");
    }
    profile.push_str("(allow mach-per-user-lookup)\n");
    profile.push_str("(allow mach-task-name)\n");
    profile.push_str("(deny mach-priv*)\n");

    // IPC: always allow POSIX shared memory operations
    profile.push_str("(allow ipc-posix-shm-read-data)\n");
    profile.push_str("(allow ipc-posix-shm-write-data)\n");
    profile.push_str("(allow ipc-posix-shm-write-create)\n");

    // IPC: conditionally allow all POSIX semaphore operations (IpcMode::Full).
    // Required by multiprocessing runtimes (Python multiprocessing, joblib, etc.)
    // that use sem_open/sem_wait/sem_post/sem_close for worker coordination.
    // We use the wildcard to cover all sem operations (open, close, create,
    // post, wait, unlink) since Seatbelt's internal operation taxonomy is
    // not fully documented and individual enumeration risks missing operations.
    if caps.ipc_mode() == crate::capability::IpcMode::Full {
        profile.push_str("(allow ipc-posix-sem*)\n");
    }

    // Signal isolation: both Isolated and AllowSameSandbox emit
    // (target self) + (target same-sandbox). This matches Linux behaviour
    // where Landlock's LANDLOCK_SCOPE_SIGNAL scopes to the sandbox domain,
    // not to the calling process alone — making Isolated and AllowSameSandbox
    // equivalent.
    //
    // Emitting only (target self) for Isolated would prevent the sandboxed
    // process from signaling its own forked children, causing orphan process
    // accumulation when the parent calls kill(child_pid, SIGTERM) and gets
    // EPERM. Terminal-generated signals (Ctrl+C → SIGINT) bypass Seatbelt
    // since they are delivered by the kernel to the foreground process group.
    //
    // We emit both (target self) and (target same-sandbox) because Seatbelt's
    // same-sandbox filter may not subsume self — being explicit ensures the
    // process can always signal itself regardless of implementation details.
    match caps.signal_mode() {
        crate::capability::SignalMode::Isolated
        | crate::capability::SignalMode::AllowSameSandbox => {
            profile.push_str("(allow signal (target self))\n");
            profile.push_str("(allow signal (target same-sandbox))\n");
        }
        crate::capability::SignalMode::AllowAll => {
            profile.push_str("(allow signal)\n");
        }
    }
    // system-socket is NOT granted globally — each NetworkMode branch emits
    // only the socket domains it needs (AF_UNIX for DNS, AF_INET/AF_INET6
    // for TCP). AllowAll emits the blanket rule. This prevents restricted
    // modes from creating arbitrary socket types.
    profile.push_str("(allow system-fsctl)\n");
    profile.push_str("(allow system-info)\n");

    // Allow reading the root directory entry itself (required for exec path resolution)
    profile.push_str("(allow file-read* (literal \"/\"))\n");

    // Allow metadata access to parent directories of granted paths (for path resolution)
    let parent_dirs = collect_parent_dirs(caps);
    for parent in &parent_dirs {
        let escaped = escape_path(parent)?;
        profile.push_str(&format!(
            "(allow file-read-metadata (literal \"{}\"))\n",
            escaped
        ));
    }

    // Allow mapping executables into memory, restricted to paths with Read or Execute access.
    // This prevents loading arbitrary shared libraries via DYLD_INSERT_LIBRARIES
    // from paths outside the sandbox's read/execute set.
    for cap in caps.fs_capabilities() {
        if matches!(
            cap.access,
            AccessMode::Execute | AccessMode::ReadExecute | AccessMode::ReadWriteExecute
        ) {
            for filter in path_filters_for_cap(cap)? {
                profile.push_str(&format!("(allow file-map-executable ({}))\n", filter));
            }
        }
    }

    // Allow file ioctl restricted to TTY/PTY devices and granted paths
    profile.push_str("(allow file-ioctl (literal \"/dev/tty\"))\n");
    profile.push_str("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))\n");
    profile.push_str("(allow file-ioctl (regex #\"^/dev/pty[a-z][0-9a-f]+$\"))\n");
    // Also allow ioctl on explicitly granted paths (for interactive programs)
    for cap in caps.fs_capabilities() {
        for filter in path_filters_for_cap(cap)? {
            profile.push_str(&format!("(allow file-ioctl ({}))\n", filter));
        }
    }

    // Allow pseudo-terminal operations
    profile.push_str("(allow pseudo-tty)\n");

    // Add read rules for all capabilities with Read or ReadWrite access.
    // Emits rules for both original and resolved paths when they differ
    // (e.g. /tmp vs /private/tmp) so Seatbelt allows traversing symlinks.
    for cap in caps.fs_capabilities() {
        match cap.access {
            AccessMode::Read
            | AccessMode::ReadWrite
            | AccessMode::ReadExecute
            | AccessMode::ReadWriteExecute => {
                for filter in path_filters_for_cap(cap)? {
                    profile.push_str(&format!("(allow file-read* ({}))\n", filter));
                }
            }
            AccessMode::Write | AccessMode::Execute => {
                // Write-only or Execute-only doesn't need read access
            }
        }
    }

    // Extension filter rules for runtime capability expansion via supervisor.
    // These allow sandbox_extension_consume() tokens to dynamically expand access.
    // The rules are inert unless a matching token is consumed -- they add no access
    // by themselves. The supervisor checks protected roots and deny groups before issuing
    // tokens, so the pre-issuance check is the enforcement point.
    if caps.extensions_enabled() {
        profile.push_str("(allow file-read* (extension \"com.apple.app-sandbox.read\"))\n");
        profile.push_str("(allow file-read* (extension \"com.apple.app-sandbox.read-write\"))\n");
        profile.push_str("(allow file-write* (extension \"com.apple.app-sandbox.read-write\"))\n");
        profile.push_str("(allow process-exec (extension \"com.apple.app-sandbox.execute\"))\n");
    }

    // SECURITY: Platform deny rules are placed BETWEEN read and write rules.
    // This matches the research CLI pattern where sensitive path denials come
    // after read allows but before write allows. In Seatbelt, more specific rules
    // always win regardless of order; for equal specificity, last-match wins.
    // Placing deny rules here ensures they override read allows when equally specific,
    // while write allows below can still override deny-unlink for user-granted paths.
    for rule in caps.platform_rules() {
        profile.push_str(rule);
        profile.push('\n');
    }

    // Add write rules for all capabilities with Write or ReadWrite access.
    // These come AFTER platform deny rules so user-granted write paths can
    // override global denials like (deny file-write-unlink).
    // Emits rules for both original and resolved paths when they differ.
    for cap in caps.fs_capabilities() {
        match cap.access {
            AccessMode::Write | AccessMode::ReadWrite | AccessMode::ReadWriteExecute => {
                for filter in path_filters_for_cap(cap)? {
                    profile.push_str(&format!("(allow file-write* ({}))\n", filter));
                }
            }
            AccessMode::Read | AccessMode::Execute | AccessMode::ReadExecute => {
                // Read-only or Execute-only doesn't need write access
            }
        }
    }

    // Network rules
    //
    // DNS resolution rules for restricted modes (Blocked/ProxyOnly):
    // macOS resolves all DNS through /var/run/mDNSResponder (a Unix domain
    // socket). Seatbelt classifies connect(2) on Unix sockets as
    // network-outbound, so (deny network*) blocks DNS. These rules allow
    // AF_UNIX socket creation and outbound to the mDNSResponder path (both
    // /var/run and /private/var/run since /var is a symlink on macOS).
    const MDNS_RULES: &str = "\
(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))\n\
(allow network-outbound (path \"/private/var/run/mDNSResponder\"))\n\
(allow network-outbound (path \"/var/run/mDNSResponder\"))\n";

    let localhost_ports = caps.localhost_ports();
    match caps.network_mode() {
        NetworkMode::Blocked => {
            profile.push_str("(deny network*)\n");
            profile.push_str(MDNS_RULES);
            // Unix socket grants (see #685 / #696). Only explicit
            // UnixSocketCapability entries emit network-outbound rules;
            // generic FsCapability grants no longer implicitly grant
            // `connect()`/`bind()` to sockets inside them. Directory
            // grants use a non-recursive regex.
            emit_unix_socket_rules(&mut profile, caps)?;
            if !localhost_ports.is_empty() {
                // Allow system-socket for TCP (required for connect/bind)
                profile.push_str(
                    "(allow system-socket (socket-domain AF_INET) (socket-type SOCK_STREAM))\n",
                );
                profile.push_str(
                    "(allow system-socket (socket-domain AF_INET6) (socket-type SOCK_STREAM))\n",
                );
                for lp in localhost_ports {
                    profile.push_str(&format!(
                        "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
                        lp
                    ));
                }
                // Seatbelt cannot filter bind/inbound by port
                profile.push_str("(allow network-bind)\n");
                profile.push_str("(allow network-inbound)\n");
            }
        }
        NetworkMode::ProxyOnly { port, bind_ports } => {
            // Block all network, then allow only localhost TCP to the proxy port.
            profile.push_str("(deny network*)\n");
            profile.push_str(MDNS_RULES);
            // Unix socket grants (see Blocked branch above).
            emit_unix_socket_rules(&mut profile, caps)?;
            profile.push_str(&format!(
                "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
                port
            ));
            for lp in localhost_ports {
                profile.push_str(&format!(
                    "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
                    lp
                ));
            }
            // Scope system-socket for TCP (required for connect/bind to proxy).
            profile.push_str(
                "(allow system-socket (socket-domain AF_INET) (socket-type SOCK_STREAM))\n",
            );
            profile.push_str(
                "(allow system-socket (socket-domain AF_INET6) (socket-type SOCK_STREAM))\n",
            );
            // If bind ports or localhost IPC ports are specified, allow network-bind
            // and network-inbound. Seatbelt cannot filter bind/inbound by port,
            // so this is a blanket allow.
            if !bind_ports.is_empty() || !localhost_ports.is_empty() {
                profile.push_str("(allow network-bind)\n");
                profile.push_str("(allow network-inbound)\n");
            }
        }
        NetworkMode::AllowAll => {
            profile.push_str("(allow system-socket)\n");
            profile.push_str("(allow network-outbound)\n");
            profile.push_str("(allow network-inbound)\n");
            profile.push_str("(allow network-bind)\n");
        }
    }

    // Per-port TCP rules are not supported on macOS (Seatbelt cannot filter by port alone).
    // ProxyOnly mode IS supported via `(remote tcp "localhost:PORT")`.
    if !caps.tcp_connect_ports().is_empty() || !caps.tcp_bind_ports().is_empty() {
        return Err(NonoError::NetworkFilterUnsupported {
            platform: "macOS".to_string(),
            reason: "Seatbelt cannot filter by TCP port. Use --allow-domain for host-level \
                     filtering (routed through the proxy) or ProxyOnly mode instead."
                .to_string(),
        });
    }

    Ok(profile)
}

/// Apply Seatbelt sandbox with the given capabilities
///
/// This is a pure primitive - it applies ONLY the capabilities provided.
/// The caller is responsible for including all necessary paths.
pub fn apply(caps: &CapabilitySet) -> Result<()> {
    let profile = generate_profile(caps)?;

    debug!("Generated Seatbelt profile:\n{}", profile);

    let profile_cstr = CString::new(profile)
        .map_err(|e| NonoError::SandboxInit(format!("Invalid profile string: {}", e)))?;

    let mut error_buf: *mut c_char = ptr::null_mut();

    // SAFETY: sandbox_init is a stable macOS API. We pass:
    // - A valid null-terminated C string for the profile
    // - 0 for raw profile mode (not a named profile)
    // - A pointer to receive any error message
    let result = unsafe {
        sandbox_init(
            profile_cstr.as_ptr(),
            0, // Raw profile mode
            &mut error_buf,
        )
    };

    if result != 0 {
        let error_msg = if !error_buf.is_null() {
            // SAFETY: sandbox_init sets error_buf to a valid C string on error
            let msg = unsafe {
                std::ffi::CStr::from_ptr(error_buf)
                    .to_string_lossy()
                    .into_owned()
            };
            // SAFETY: sandbox_free_error expects a pointer from sandbox_init
            unsafe { sandbox_free_error(error_buf) };
            msg
        } else {
            format!("sandbox_init returned error code {}", result)
        };

        return Err(NonoError::SandboxInit(error_msg));
    }

    info!("Seatbelt sandbox applied successfully");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySource, FsCapability};
    use std::path::PathBuf;

    #[test]
    fn test_generate_profile_empty() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        // Network is allowed by default
        assert!(profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn test_generate_profile_with_dir() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test"),
            resolved: PathBuf::from("/test"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(allow file-read* (subpath \"/test\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/test\"))"));
        assert!(profile.contains("(allow file-map-executable (subpath \"/test\"))"));
    }

    #[test]
    fn test_generate_profile_with_file() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test.txt"),
            resolved: PathBuf::from("/test.txt"),
            access: AccessMode::Write,
            is_file: true,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("file-write*"));
        assert!(profile.contains("literal \"/test.txt\""));
        // Write-only paths must NOT get file-map-executable
        assert!(!profile.contains("file-map-executable"));
    }

    #[test]
    fn test_generate_profile_no_global_file_map_executable() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps).unwrap();

        // Must not contain a global (unrestricted) file-map-executable
        assert!(!profile.contains("(allow file-map-executable)\n"));
    }

    #[test]
    fn test_generate_profile_network_blocked() {
        let caps = CapabilitySet::new().block_network();

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny network*)"));
        // Should NOT have general outbound allow (only mDNSResponder path allows)
        assert!(!profile.contains("(allow network-outbound)\n"));
    }

    #[test]
    fn test_support_info() {
        let info = support_info();
        assert!(info.is_supported);
        assert_eq!(info.platform, "macos");
    }

    #[test]
    fn test_collect_parent_dirs() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/Users/test/.claude"),
            resolved: PathBuf::from("/Users/test/.claude"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let parents = collect_parent_dirs(&caps);

        assert!(parents.contains("/Users"));
        assert!(parents.contains("/Users/test"));
        assert!(!parents.contains("/"));
    }

    #[test]
    fn test_escape_path() {
        assert_eq!(escape_path("/simple/path").unwrap(), "/simple/path");
        assert_eq!(
            escape_path("/path with\\slash").unwrap(),
            "/path with\\\\slash"
        );
        assert_eq!(escape_path("/path\"quoted").unwrap(), "/path\\\"quoted");
    }

    #[test]
    fn test_escape_path_rejects_control_characters() {
        assert!(escape_path("/path\0with\0nulls").is_err());
        assert!(escape_path("/path\nwith\nnewlines").is_err());
        assert!(escape_path("/path\rwith\rreturns").is_err());
        assert!(escape_path("/path\twith\ttabs").is_err());
        assert!(escape_path("/path\x0bwith\x0cfeeds").is_err());
        assert!(escape_path("/path\x1bwith\x1bescape").is_err());
        assert!(escape_path("/path\x7fwith\x7fdel").is_err());
    }

    #[test]
    fn test_generate_profile_with_platform_rules() {
        let mut caps = CapabilitySet::new();
        caps.add_platform_rule("(deny file-read-data (subpath \"/private/var/db\"))")
            .unwrap();
        caps.add_platform_rule("(deny file-write-unlink)").unwrap();

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny file-read-data (subpath \"/private/var/db\"))"));
        assert!(profile.contains("(deny file-write-unlink)"));
        // Platform deny rules should appear before network rules
        let platform_pos = profile
            .find("(deny file-write-unlink)")
            .expect("platform rule not found");
        let network_pos = profile
            .find("(allow network-outbound)")
            .expect("network rule not found");
        assert!(
            platform_pos < network_pos,
            "platform rules must appear before network rules"
        );
    }

    #[test]
    fn test_generate_profile_platform_rules_between_reads_and_writes() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test"),
            resolved: PathBuf::from("/test"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_platform_rule("(deny file-write-unlink)").unwrap();

        let profile = generate_profile(&caps).unwrap();

        let read_pos = profile
            .find("(allow file-read* (subpath \"/test\"))")
            .expect("read rule not found");
        let deny_pos = profile
            .find("(deny file-write-unlink)")
            .expect("deny rule not found");
        let write_pos = profile
            .find("(allow file-write* (subpath \"/test\"))")
            .expect("write rule not found");

        // Order: read rules -> platform deny rules -> write rules
        assert!(
            read_pos < deny_pos,
            "read rules must come before platform deny rules"
        );
        assert!(
            deny_pos < write_pos,
            "platform deny rules must come before write rules"
        );
    }

    #[test]
    fn test_generate_profile_platform_rules_empty() {
        let caps = CapabilitySet::new();
        let profile = generate_profile(&caps).unwrap();

        // Should still generate a valid profile without platform rules
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn test_generate_profile_with_gpu_iokit_rules() {
        let mut caps = CapabilitySet::new();
        // Minimal IOKit surface: AGXDeviceUserClient is the only class required
        // for Metal compute on Apple Silicon. IOSurfaceRootUserClient is tried
        // opportunistically but Metal continues without it when denied.
        caps.add_platform_rule(
            "(allow iokit-open \
                (iokit-user-client-class \
                    \"AGXDeviceUserClient\"))",
        )
        .unwrap();
        caps.add_platform_rule("(allow iokit-get-properties)")
            .unwrap();

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(allow iokit-open"));
        assert!(profile.contains("AGXDeviceUserClient"));
        assert!(!profile.contains("IOGPU"));
        assert!(!profile.contains("AGXSharedUserClient"));
        assert!(!profile.contains("IOSurfaceRootUserClient"));
        assert!(profile.contains("(allow iokit-get-properties)"));
    }

    #[test]
    fn test_generate_profile_gpu_rules_ordering() {
        // GPU rules (as platform rules) should appear between read and write rules
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test"),
            resolved: PathBuf::from("/test"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_platform_rule("(allow iokit-get-properties)")
            .unwrap();

        let profile = generate_profile(&caps).unwrap();

        let read_pos = profile
            .find("(allow file-read* (subpath \"/test\"))")
            .expect("read rule not found");
        let iokit_pos = profile
            .find("(allow iokit-get-properties)")
            .expect("iokit rule not found");
        let write_pos = profile
            .find("(allow file-write* (subpath \"/test\"))")
            .expect("write rule not found");

        assert!(
            read_pos < iokit_pos,
            "read rules must come before GPU/IOKit platform rules"
        );
        assert!(
            iokit_pos < write_pos,
            "GPU/IOKit platform rules must come before write rules"
        );
    }

    #[test]
    fn test_escape_path_injection_via_newline() {
        // An attacker embeds a newline to break out of the quoted string and inject
        // a new S-expression. This must be rejected, not silently altered.
        let malicious = "/tmp/evil\n(allow file-read* (subpath \"/\"))";
        assert!(escape_path(malicious).is_err());
    }

    #[test]
    fn test_escape_path_injection_via_quote() {
        // An attacker embeds a double-quote to terminate the string early and inject
        // a new rule: /tmp/evil")(allow file-read* (subpath "/"))("
        // Quotes are escaped (not control chars), so this must succeed with escaping.
        let malicious = "/tmp/evil\")(allow file-read* (subpath \"/\"))(\"";
        let escaped = escape_path(malicious).unwrap();
        // Every " in the escaped output must be preceded by \ so Seatbelt
        // treats it as a literal quote inside the string, not a terminator.
        let chars: Vec<char> = escaped.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if c == '"' {
                assert!(
                    i > 0 && chars[i - 1] == '\\',
                    "unescaped quote at position {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_generate_profile_rejects_malicious_path() {
        let mut caps = CapabilitySet::new();
        // A path with embedded newline + Seatbelt injection attempt
        caps.add_fs(FsCapability {
            original: PathBuf::from("/tmp/evil"),
            resolved: PathBuf::from("/tmp/evil\n(allow file-read* (subpath \"/\"))"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        assert!(
            generate_profile(&caps).is_err(),
            "paths with control characters must be rejected"
        );
    }

    #[test]
    fn test_capability_source_tagging() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr"),
            resolved: PathBuf::from("/usr"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("system_read_macos".to_string()),
        });

        // Group-sourced capabilities should generate the same profile rules
        let profile = generate_profile(&caps).unwrap();
        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
    }

    #[test]
    fn test_generate_profile_extensions_disabled_by_default() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps).unwrap();

        assert!(!profile.contains("extension"));
    }

    #[test]
    fn test_generate_profile_extensions_enabled() {
        let caps = CapabilitySet::new().enable_extensions();
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(allow file-read* (extension \"com.apple.app-sandbox.read\"))"));
        assert!(
            profile.contains("(allow file-read* (extension \"com.apple.app-sandbox.read-write\"))")
        );
        assert!(profile
            .contains("(allow file-write* (extension \"com.apple.app-sandbox.read-write\"))"));
    }

    #[test]
    fn test_generate_profile_extensions_before_platform_deny_rules() {
        let mut caps = CapabilitySet::new().enable_extensions();
        caps.add_platform_rule("(deny file-write-unlink)").unwrap();

        let profile = generate_profile(&caps).unwrap();

        let ext_pos = profile
            .find("(allow file-read* (extension \"com.apple.app-sandbox.read\"))")
            .expect("extension rule not found");
        let deny_pos = profile
            .find("(deny file-write-unlink)")
            .expect("deny rule not found");

        assert!(
            ext_pos < deny_pos,
            "extension rules must appear before platform deny rules"
        );
    }

    #[test]
    fn test_generate_profile_denies_keychain_mach_by_default() {
        let caps = CapabilitySet::new();
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny mach-lookup (global-name \"com.apple.SecurityServer\"))"));
        assert!(profile.contains("(deny mach-lookup (global-name \"com.apple.securityd\"))"));
        // Modern keychain daemon (macOS 13 Ventura+)
        assert!(
            profile.contains("(deny mach-lookup (global-name \"com.apple.security.keychaind\"))")
        );
        // Modern security daemon (macOS 10.10+)
        assert!(profile.contains("(deny mach-lookup (global-name \"com.apple.secd\"))"));
        assert!(profile.contains("(deny mach-lookup (global-name \"com.apple.security.agent\"))"));
    }

    #[test]
    fn test_generate_profile_skips_keychain_mach_deny_when_explicitly_granted() {
        let mut caps = CapabilitySet::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/test".to_string());
        let keychain = PathBuf::from(home).join("Library/Keychains/login.keychain-db");
        caps.add_fs(FsCapability {
            original: keychain.clone(),
            resolved: keychain,
            access: AccessMode::Read,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(!profile.contains("(deny mach-lookup (global-name \"com.apple.SecurityServer\"))"));
        assert!(!profile.contains("(deny mach-lookup (global-name \"com.apple.securityd\"))"));
        assert!(
            !profile.contains("(deny mach-lookup (global-name \"com.apple.security.keychaind\"))")
        );
        assert!(!profile.contains("(deny mach-lookup (global-name \"com.apple.secd\"))"));
        assert!(!profile.contains("(deny mach-lookup (global-name \"com.apple.security.agent\"))"));
    }

    #[test]
    fn test_generate_profile_skips_keychain_mach_deny_for_metadata_keychain_db() {
        let mut caps = CapabilitySet::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/test".to_string());
        let metadata_keychain_db =
            PathBuf::from(home).join("Library/Keychains/metadata.keychain-db");
        caps.add_fs(FsCapability {
            original: metadata_keychain_db.clone(),
            resolved: metadata_keychain_db,
            access: AccessMode::Read,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(!profile.contains("(deny mach-lookup (global-name \"com.apple.SecurityServer\"))"));
        assert!(!profile.contains("(deny mach-lookup (global-name \"com.apple.securityd\"))"));
        assert!(
            !profile.contains("(deny mach-lookup (global-name \"com.apple.security.keychaind\"))")
        );
        assert!(!profile.contains("(deny mach-lookup (global-name \"com.apple.secd\"))"));
        assert!(!profile.contains("(deny mach-lookup (global-name \"com.apple.security.agent\"))"));
    }

    #[test]
    fn test_generate_profile_proxy_only_mode() {
        let caps = CapabilitySet::new().proxy_only(54321);
        let profile = generate_profile(&caps).unwrap();

        // Should deny all network
        assert!(profile.contains("(deny network*)"));
        // Should allow only localhost TCP to proxy port
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:54321\"))"));
        // Should allow system-socket for TCP connect
        assert!(profile.contains("(allow system-socket"));
        // Should allow DNS via mDNSResponder Unix socket (#588)
        assert!(
            profile.contains("(allow network-outbound (path \"/private/var/run/mDNSResponder\"))")
        );
        assert!(profile.contains("(allow network-outbound (path \"/var/run/mDNSResponder\"))"));
        assert!(profile
            .contains("(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))"));
        // Should NOT have general outbound allow
        assert!(!profile.contains("(allow network-outbound)\n"));
        // Should NOT have bind/inbound without bind_ports
        assert!(!profile.contains("(allow network-bind)"));
        assert!(!profile.contains("(allow network-inbound)"));
    }

    #[test]
    fn test_generate_profile_proxy_only_with_bind_ports() {
        let caps = CapabilitySet::new().proxy_only_with_bind(54321, vec![18789, 3000]);
        let profile = generate_profile(&caps).unwrap();

        // Should deny all network first (deny before allow)
        assert!(profile.contains("(deny network*)"));
        // Should allow only localhost TCP to proxy port
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:54321\"))"));
        // Should allow system-socket for TCP connect
        assert!(profile.contains("(allow system-socket"));
        // Should allow DNS via mDNSResponder Unix socket (#588)
        assert!(
            profile.contains("(allow network-outbound (path \"/private/var/run/mDNSResponder\"))")
        );
        assert!(profile.contains("(allow network-outbound (path \"/var/run/mDNSResponder\"))"));
        // Should have bind and inbound allowed (blanket, since Seatbelt can't filter by port)
        assert!(profile.contains("(allow network-bind)"));
        assert!(profile.contains("(allow network-inbound)"));
        // Should NOT have general outbound allow
        assert!(!profile.contains("(allow network-outbound)\n"));
    }

    #[test]
    fn test_generate_profile_allow_all_network() {
        let caps = CapabilitySet::new();
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(allow network-outbound)"));
        assert!(profile.contains("(allow network-inbound)"));
        assert!(profile.contains("(allow network-bind)"));
        assert!(!profile.contains("(deny network*)"));
    }

    /// Regression test for #687 (+ #696 narrowing): Unix domain socket
    /// paths explicitly granted via `--allow-unix-socket` must remain
    /// reachable in ProxyOnly and Blocked modes. On macOS, connect(2) to
    /// a Unix socket is classified as network-outbound by Seatbelt, so
    /// `(deny network*)` blocks it unless a per-path rule is emitted.
    /// Only explicit `UnixSocketCapability` entries trigger the emission
    /// — generic `FsCapability` grants no longer implicitly do.
    #[test]
    fn test_generate_profile_unix_socket_allowed_in_proxy_only_mode() {
        let mut caps = CapabilitySet::new().proxy_only(54321);
        caps.add_unix_socket(crate::UnixSocketCapability {
            original: PathBuf::from("/tmp/test.sock"),
            resolved: PathBuf::from("/private/tmp/test.sock"),
            is_directory: false,
            mode: crate::UnixSocketMode::Connect,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:54321\"))"));
        assert!(
            profile.contains("(allow network-outbound (path \"/private/tmp/test.sock\"))"),
            "must allow network-outbound to resolved socket path"
        );
        assert!(
            profile.contains("(allow network-outbound (path \"/tmp/test.sock\"))"),
            "must allow network-outbound to original (symlink) socket path"
        );
    }

    #[test]
    fn test_generate_profile_unix_socket_allowed_in_blocked_mode() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_unix_socket(crate::UnixSocketCapability {
            original: PathBuf::from("/var/run/app.sock"),
            resolved: PathBuf::from("/private/var/run/app.sock"),
            is_directory: false,
            mode: crate::UnixSocketMode::ConnectBind,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny network*)"));
        // ConnectBind must emit BOTH network-outbound (connect) AND
        // network-bind (bind) — they're distinct Seatbelt operations.
        assert!(
            profile.contains("(allow network-outbound (path \"/private/var/run/app.sock\"))"),
            "must allow network-outbound to resolved socket path"
        );
        assert!(
            profile.contains("(allow network-outbound (path \"/var/run/app.sock\"))"),
            "must allow network-outbound to original socket path"
        );
        assert!(
            profile.contains("(allow network-bind (path \"/private/var/run/app.sock\"))"),
            "ConnectBind must also allow network-bind on resolved path"
        );
        assert!(
            profile.contains("(allow network-bind (path \"/var/run/app.sock\"))"),
            "ConnectBind must also allow network-bind on original path"
        );
        assert!(!profile.contains("(allow network-outbound)\n"));
    }

    /// Regression: Connect-only mode must emit `network-outbound` but
    /// NOT `network-bind`. bind(2) stays denied by the base
    /// `(deny network*)` clause — this is the separate-read-write
    /// invariant at the socket layer.
    #[test]
    fn test_generate_profile_unix_socket_connect_only_does_not_emit_bind() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_unix_socket(crate::UnixSocketCapability {
            original: PathBuf::from("/var/run/client.sock"),
            resolved: PathBuf::from("/private/var/run/client.sock"),
            is_directory: false,
            mode: crate::UnixSocketMode::Connect,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(
            profile.contains("(allow network-outbound (path \"/private/var/run/client.sock\"))"),
            "Connect mode must emit network-outbound"
        );
        assert!(
            !profile.contains("(allow network-bind"),
            "Connect-only mode must NOT emit any network-bind rule: {profile}"
        );
    }

    /// Directory-form unix socket grants must emit a NON-RECURSIVE
    /// regex — `[^/]+$` matches only direct children, not grandchildren.
    /// #696 scope tightening.
    #[test]
    fn test_generate_profile_unix_socket_dir_emits_non_recursive_regex() {
        let mut caps = CapabilitySet::new().proxy_only(54321);
        caps.add_unix_socket(crate::UnixSocketCapability {
            original: PathBuf::from("/tmp/mydir"),
            resolved: PathBuf::from("/private/tmp/mydir"),
            is_directory: true,
            mode: crate::UnixSocketMode::ConnectBind,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(
            profile.contains("(allow network-outbound (regex \"^/private/tmp/mydir/[^/]+$\"))"),
            "directory unix socket grants must emit non-recursive regex: {profile}"
        );
        assert!(
            profile.contains("(allow network-outbound (regex \"^/tmp/mydir/[^/]+$\"))"),
            "symlinked original must also emit regex form"
        );
        // ConnectBind mode also emits network-bind with matching regex.
        assert!(
            profile.contains("(allow network-bind (regex \"^/private/tmp/mydir/[^/]+$\"))"),
            "ConnectBind directory grant must emit network-bind regex"
        );
        assert!(
            !profile.contains("(allow network-outbound (subpath"),
            "directory unix socket grants must NOT use recursive subpath"
        );
    }

    /// #696 core contract: a plain `FsCapability` grant on a socket path
    /// must NOT trigger any `network-outbound` or `network-bind` rule.
    /// Only explicit `UnixSocketCapability` grants do.
    #[test]
    fn test_generate_profile_fs_capability_does_not_grant_network_outbound() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/var/run"),
            resolved: PathBuf::from("/private/var/run"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny network*)"));
        assert!(
            !profile.contains("(allow network-outbound (subpath \"/private/var/run\"))"),
            "FsCapability must not implicitly grant network-outbound on its subpath"
        );
        assert!(
            !profile.contains("(allow network-outbound (path \"/var/run\"))"),
            "FsCapability must not implicitly grant network-outbound on its path"
        );
        assert!(
            !profile.contains("(allow network-bind"),
            "FsCapability must not implicitly grant any network-bind rule"
        );
    }

    #[test]
    fn test_regex_escape_metacharacters_wrapped_in_character_class() {
        // Literal `.` in a directory name must be wrapped as `[.]`.
        let escaped = regex_escape_path_for_seatbelt("/tmp/foo.bar-1000").unwrap();
        assert_eq!(escaped, "/tmp/foo[.]bar-1000");
    }

    #[test]
    fn test_regex_escape_handles_bracket_and_backslash_via_backslash_escape() {
        // These chars can't appear literally inside `[ ]` so we fall
        // back to Scheme-level `\\<c>` → regex-level `\<c>` → literal.
        assert_eq!(
            regex_escape_path_for_seatbelt("/tmp/foo[bar").unwrap(),
            "/tmp/foo\\\\[bar"
        );
        assert_eq!(
            regex_escape_path_for_seatbelt("/tmp/foo]bar").unwrap(),
            "/tmp/foo\\\\]bar"
        );
        // Literal backslash: `\\\\\\\\` in Rust source (4 chars emitted)
        // → Scheme reads `\\`, regex engine sees `\\` → matches literal `\`.
        assert_eq!(
            regex_escape_path_for_seatbelt("/tmp/foo\\bar").unwrap(),
            "/tmp/foo\\\\\\\\bar"
        );
    }

    #[test]
    fn test_regex_escape_rejects_control_characters() {
        // Control characters stay rejected — escape_path's policy too.
        assert!(regex_escape_path_for_seatbelt("/tmp/foo\x00bar").is_err());
        assert!(regex_escape_path_for_seatbelt("/tmp/foo\nbar").is_err());
    }

    #[test]
    fn test_generate_profile_unix_socket_rules_not_emitted_in_allow_all() {
        // AllowAll already permits all network-outbound — emit_unix_socket_rules
        // is only called in Blocked/ProxyOnly branches, so there's no per-path noise.
        let mut caps = CapabilitySet::new(); // default = AllowAll
        caps.add_unix_socket(crate::UnixSocketCapability {
            original: PathBuf::from("/tmp/test.sock"),
            resolved: PathBuf::from("/private/tmp/test.sock"),
            is_directory: false,
            mode: crate::UnixSocketMode::Connect,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(
            profile.contains("(allow network-outbound)\n"),
            "AllowAll must still emit blanket rule"
        );
        assert!(
            !profile.contains("(allow network-outbound (path \"/private/tmp/test.sock\"))"),
            "AllowAll must not emit per-path socket rules"
        );
    }

    #[test]
    fn test_generate_profile_rejects_per_port_rules() {
        let caps = CapabilitySet::new().allow_tcp_connect(443);
        let result = generate_profile(&caps);
        assert!(result.is_err());

        let err = result.err().unwrap();
        assert!(
            err.to_string().contains("macOS"),
            "error should mention macOS: {}",
            err
        );
    }

    #[test]
    fn test_generate_profile_rejects_per_port_bind_rules() {
        let caps = CapabilitySet::new().allow_tcp_bind(8080);
        let result = generate_profile(&caps);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_profile_signal_isolated_allows_same_sandbox() {
        // Isolated now emits same-sandbox rules (matching Linux behaviour)
        // to allow signaling child processes that inherited the sandbox.
        let caps = CapabilitySet::new(); // default = Isolated
        let profile = generate_profile(&caps).unwrap();
        assert!(profile.contains("(allow signal (target self))"));
        assert!(profile.contains("(allow signal (target same-sandbox))"));
        assert!(!profile.contains("(allow signal)\n"));
    }

    #[test]
    fn test_generate_profile_signal_allow_same_sandbox() {
        use crate::capability::SignalMode;
        let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
        let profile = generate_profile(&caps).unwrap();
        assert!(profile.contains("(allow signal (target self))"));
        assert!(profile.contains("(allow signal (target same-sandbox))"));
        assert!(!profile.contains("(allow signal)\n"));
    }

    #[test]
    fn test_generate_profile_process_info_isolated() {
        // Isolated now emits same-sandbox rules (matching Linux behaviour)
        // instead of denying others, to allow child process health checks.
        let caps = CapabilitySet::new(); // default = Isolated
        let profile = generate_profile(&caps).unwrap();
        assert!(profile.contains("(allow process-info* (target self))"));
        assert!(profile.contains("(allow process-info* (target same-sandbox))"));
        assert!(!profile.contains("(deny process-info* (target others))"));
    }

    #[test]
    fn test_generate_profile_process_info_allow_same_sandbox() {
        use crate::capability::ProcessInfoMode;
        let caps = CapabilitySet::new().set_process_info_mode(ProcessInfoMode::AllowSameSandbox);
        let profile = generate_profile(&caps).unwrap();
        assert!(profile.contains("(allow process-info* (target self))"));
        assert!(profile.contains("(allow process-info* (target same-sandbox))"));
        assert!(!profile.contains("(deny process-info* (target others))"));
    }

    #[test]
    fn test_generate_profile_process_info_allow_all() {
        use crate::capability::ProcessInfoMode;
        let caps = CapabilitySet::new().set_process_info_mode(ProcessInfoMode::AllowAll);
        let profile = generate_profile(&caps).unwrap();
        // AllowAll emits the wildcard rule only — no redundant (target self)
        assert!(profile.contains("(allow process-info*)\n"));
        assert!(!profile.contains("(allow process-info* (target self))"));
        assert!(!profile.contains("(deny process-info* (target others))"));
    }

    #[test]
    fn test_generate_profile_ipc_shared_memory_only_no_semaphores() {
        let caps = CapabilitySet::new(); // default = SharedMemoryOnly
        let profile = generate_profile(&caps).unwrap();
        // Shared memory is always present
        assert!(profile.contains("(allow ipc-posix-shm-read-data)"));
        assert!(profile.contains("(allow ipc-posix-shm-write-data)"));
        assert!(profile.contains("(allow ipc-posix-shm-write-create)"));
        // Semaphores should NOT be present in default mode
        assert!(!profile.contains("ipc-posix-sem"));
    }

    #[test]
    fn test_generate_profile_ipc_full_includes_semaphores() {
        use crate::capability::IpcMode;
        let caps = CapabilitySet::new().set_ipc_mode(IpcMode::Full);
        let profile = generate_profile(&caps).unwrap();
        // Shared memory still present
        assert!(profile.contains("(allow ipc-posix-shm-read-data)"));
        // Semaphore wildcard present
        assert!(profile.contains("(allow ipc-posix-sem*)"));
    }

    #[test]
    fn test_generate_profile_blocked_with_localhost_ports() {
        let caps = CapabilitySet::new()
            .block_network()
            .allow_localhost_port(3000)
            .allow_localhost_port(5000);
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:3000\"))"));
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:5000\"))"));
        assert!(profile.contains("(allow network-bind)"));
        assert!(profile.contains("(allow network-inbound)"));
        assert!(profile.contains("(allow system-socket"));
        // Should allow DNS via mDNSResponder Unix socket (#588)
        assert!(
            profile.contains("(allow network-outbound (path \"/private/var/run/mDNSResponder\"))")
        );
        assert!(profile.contains("(allow network-outbound (path \"/var/run/mDNSResponder\"))"));
        assert!(profile
            .contains("(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))"));
    }

    #[test]
    fn test_generate_profile_proxy_with_localhost_ports() {
        let caps = CapabilitySet::new()
            .proxy_only(54321)
            .allow_localhost_port(3000);
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny network*)"));
        // Proxy port
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:54321\"))"));
        // Localhost IPC port
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:3000\"))"));
        // Bind/inbound enabled because localhost_ports is non-empty
        assert!(profile.contains("(allow network-bind)"));
        assert!(profile.contains("(allow network-inbound)"));
    }

    #[test]
    fn test_generate_profile_allow_all_with_localhost_ports() {
        // AllowAll is unchanged by localhost ports — all network already allowed
        let caps = CapabilitySet::new().allow_localhost_port(3000);
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(allow network-outbound)"));
        assert!(profile.contains("(allow network-inbound)"));
        assert!(profile.contains("(allow network-bind)"));
        assert!(!profile.contains("(deny network*)"));
    }

    #[test]
    fn test_generate_profile_dns_allowed_in_proxy_mode() {
        // Regression test for #588: proxy mode must allow DNS resolution
        // via the mDNSResponder Unix socket, otherwise all name resolution
        // fails inside the sandbox.
        let caps = CapabilitySet::new().proxy_only(12345);
        let profile = generate_profile(&caps).unwrap();

        // mDNSResponder socket must be reachable (both symlink and real path)
        assert!(
            profile.contains("(allow network-outbound (path \"/private/var/run/mDNSResponder\"))"),
            "must allow mDNSResponder at canonical path"
        );
        assert!(
            profile.contains("(allow network-outbound (path \"/var/run/mDNSResponder\"))"),
            "must allow mDNSResponder at symlink path"
        );
        // AF_UNIX system-socket is needed to create the Unix domain socket
        assert!(
            profile.contains(
                "(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))"
            ),
            "must allow AF_UNIX SOCK_STREAM for mDNSResponder"
        );
    }

    #[test]
    fn test_generate_profile_dns_allowed_in_blocked_mode() {
        // Regression test for #588: blocked mode with (deny network*) must
        // also allow DNS resolution via mDNSResponder.
        let caps = CapabilitySet::new().block_network();
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny network*)"));
        assert!(
            profile.contains("(allow network-outbound (path \"/private/var/run/mDNSResponder\"))"),
            "blocked mode must allow mDNSResponder at canonical path"
        );
        assert!(
            profile.contains("(allow network-outbound (path \"/var/run/mDNSResponder\"))"),
            "blocked mode must allow mDNSResponder at symlink path"
        );
        assert!(
            profile.contains(
                "(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))"
            ),
            "blocked mode must allow AF_UNIX SOCK_STREAM for mDNSResponder"
        );
    }

    #[test]
    fn test_generate_profile_dns_not_needed_in_allow_all() {
        // AllowAll already permits all network — no special mDNSResponder
        // rules needed (and none should appear since there's no deny network*).
        let caps = CapabilitySet::new();
        let profile = generate_profile(&caps).unwrap();

        assert!(!profile.contains("(deny network*)"));
        assert!(!profile.contains("mDNSResponder"));
    }
}
