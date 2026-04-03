//! Capability model for filesystem and network access
//!
//! This module defines the capability types used to specify what resources
//! a sandboxed process can access.

use crate::error::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// Source of a filesystem capability for diagnostics
///
/// Tracks whether a capability was added by the user directly,
/// from a profile's filesystem section, resolved from a named
/// policy group, or is a system-level path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilitySource {
    /// Added directly by the user via CLI flags (--allow, --read, --allow-cwd)
    #[default]
    User,
    /// Added from a profile's filesystem section (allow, read, etc.)
    Profile,
    /// Resolved from a named policy group
    Group(String),
    /// System-level path required for execution (e.g., /usr, /bin, /lib)
    System,
}

impl CapabilitySource {
    /// Whether this source represents explicit user intent (CLI flags or profile config).
    /// Used by deduplication to prefer user-intentional entries over system/group entries.
    #[must_use]
    pub fn is_user_intent(&self) -> bool {
        matches!(self, CapabilitySource::User | CapabilitySource::Profile)
    }
}

impl std::fmt::Display for CapabilitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilitySource::User => write!(f, "user"),
            CapabilitySource::Profile => write!(f, "profile"),
            CapabilitySource::Group(name) => write!(f, "group:{}", name),
            CapabilitySource::System => write!(f, "system"),
        }
    }
}

/// Filesystem access mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessMode {
    /// Read-only access
    Read,
    /// Write-only access
    Write,
    /// Read and write access
    ReadWrite,
    /// Execute access
    Execute,
    /// Read and execute access
    ReadExecute,
    /// Read, write, and execute access
    ReadWriteExecute,
}

impl AccessMode {
    /// Returns true if `self` provides at least the permissions in `required`.
    ///
    /// ReadWrite contains Read, Write, and ReadWrite.
    /// Read contains only Read. Write contains only Write.
    #[must_use]
    pub fn contains(self, required: AccessMode) -> bool {
        match (self, required) {
            (AccessMode::ReadWriteExecute, _) => true,
            (
                AccessMode::ReadWrite,
                AccessMode::ReadWrite | AccessMode::Read | AccessMode::Write,
            ) => true,
            (
                AccessMode::ReadExecute,
                AccessMode::ReadExecute | AccessMode::Read | AccessMode::Execute,
            ) => true,
            (AccessMode::ReadWrite, _) => false,
            (AccessMode::ReadExecute, _) => false,
            (AccessMode::Write, AccessMode::Write) => true,
            (AccessMode::Read, AccessMode::Read) => true,
            (AccessMode::Execute, AccessMode::Execute) => true,
            _ => self == required,
        }
    }
}

impl std::fmt::Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessMode::Read => write!(f, "read"),
            AccessMode::Write => write!(f, "write"),
            AccessMode::ReadWrite => write!(f, "read+write"),
            AccessMode::Execute => write!(f, "execute"),
            AccessMode::ReadExecute => write!(f, "read+execute"),
            AccessMode::ReadWriteExecute => write!(f, "read+write+execute"),
        }
    }
}

/// A filesystem capability - grants access to a specific path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapability {
    /// The original path as specified by the caller
    pub original: PathBuf,
    /// The canonicalized absolute path
    pub resolved: PathBuf,
    /// The access mode granted
    pub access: AccessMode,
    /// True if this is a single file, false if directory (recursive)
    pub is_file: bool,
    /// Where this capability came from (user CLI flags or a policy group)
    #[serde(default)]
    pub source: CapabilitySource,
}

impl FsCapability {
    /// Create a new directory capability, canonicalizing the path
    ///
    /// Canonicalizes first, then checks metadata on the resolved path
    /// to avoid TOCTOU races between exists() and canonicalize().
    pub fn new_dir(path: impl AsRef<Path>, access: AccessMode) -> Result<Self> {
        let path = path.as_ref();

        // Canonicalize first - this atomically resolves symlinks and verifies existence.
        // No separate exists() check needed, eliminating TOCTOU window.
        let resolved = path.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::PathNotFound(path.to_path_buf())
            } else {
                NonoError::PathCanonicalization {
                    path: path.to_path_buf(),
                    source: e,
                }
            }
        })?;

        // Verify type on the already-resolved path (no TOCTOU: same inode)
        if !resolved.is_dir() {
            return Err(NonoError::ExpectedDirectory(path.to_path_buf()));
        }

        Ok(Self {
            original: path.to_path_buf(),
            resolved,
            access,
            is_file: false,
            source: CapabilitySource::User,
        })
    }

    /// Create a new single file capability, canonicalizing the path
    ///
    /// Canonicalizes first, then checks metadata on the resolved path
    /// to avoid TOCTOU races between exists() and canonicalize().
    pub fn new_file(path: impl AsRef<Path>, access: AccessMode) -> Result<Self> {
        let path = path.as_ref();

        // Canonicalize first - this atomically resolves symlinks and verifies existence.
        // No separate exists() check needed, eliminating TOCTOU window.
        let resolved = path.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::PathNotFound(path.to_path_buf())
            } else {
                NonoError::PathCanonicalization {
                    path: path.to_path_buf(),
                    source: e,
                }
            }
        })?;

        // Verify type on the already-resolved path (no TOCTOU: same inode)
        if resolved.is_dir() {
            return Err(NonoError::ExpectedFile(path.to_path_buf()));
        }

        Ok(Self {
            original: path.to_path_buf(),
            resolved,
            access,
            is_file: true,
            source: CapabilitySource::User,
        })
    }
}

impl std::fmt::Display for FsCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.resolved.display(), self.access)
    }
}

/// Which operations are permitted on a pathname AF_UNIX socket.
///
/// Mirrors [`AccessMode`] for files: `Connect` is the read-analog
/// (client-side use of an existing socket), `ConnectBind` is the write-analog
/// (also permits `bind(2)`, which creates the socket file — i.e. offering a
/// service at that path). Default grants should omit bind; use `ConnectBind`
/// only when the sandboxed program creates the socket itself (e.g. `tsx`'s
/// self-IPC pipe in issue #685).
///
/// Invariant `separate-read-write` (see `proj/invariants.yaml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnixSocketMode {
    /// Allow `connect(2)` only. The socket must already exist.
    Connect,
    /// Allow both `connect(2)` and `bind(2)`. `bind(2)` creates the socket
    /// file at grant time so the path need not exist yet.
    ConnectBind,
}

impl UnixSocketMode {
    /// True if this mode permits `bind(2)` on the granted path.
    #[must_use]
    pub fn permits_bind(self) -> bool {
        matches!(self, UnixSocketMode::ConnectBind)
    }
}

impl std::fmt::Display for UnixSocketMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnixSocketMode::Connect => write!(f, "connect"),
            UnixSocketMode::ConnectBind => write!(f, "connect+bind"),
        }
    }
}

/// Operation being queried against a [`UnixSocketCapability`].
///
/// Kept distinct from [`UnixSocketMode`] so the grant-side (what a
/// capability permits) and the query-side (what the caller is about to
/// do) are not conflated. The supervisor's seccomp-notify handler maps
/// `SYS_CONNECT` → `Connect`, `SYS_BIND` → `Bind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSocketOp {
    /// About to call `connect(2)`.
    Connect,
    /// About to call `bind(2)`.
    Bind,
}

impl std::fmt::Display for UnixSocketOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnixSocketOp::Connect => write!(f, "connect"),
            UnixSocketOp::Bind => write!(f, "bind"),
        }
    }
}

/// A capability granting AF_UNIX socket access on a filesystem path.
///
/// Only pathname sockets (filesystem-backed) are grantable through this
/// type. Abstract-namespace sockets (`sun_path[0] == '\0'`) and unnamed
/// sockets are never covered by a grant — see issue #685 for the design
/// note. Those kinds are denied by the sandbox's `decide_network_notification`
/// policy on Linux and have no analog on macOS.
///
/// Invariants:
/// - `path-canonicalize`: canonicalised at construction. For `ConnectBind`
///   grants where the socket itself doesn't yet exist, we canonicalise the
///   parent directory and re-append the final component (bind creates the
///   socket file).
/// - `lib-policy-free`: this is a pure data type. Policy coupling (e.g.
///   auto-granting an implied `FsCapability`) lives in `nono-cli`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixSocketCapability {
    /// Original path as specified by the caller, pre-canonicalisation.
    /// Retained for diagnostic output and for macOS dual-path emission
    /// (`/tmp/foo.sock` vs `/private/tmp/foo.sock`).
    pub original: PathBuf,
    /// Canonical absolute path.
    pub resolved: PathBuf,
    /// If `true`, the grant covers any pathname socket *directly* within
    /// `resolved` (non-recursive: children only, not grandchildren).
    /// If `false`, the grant is file-scoped and matches only `resolved`.
    pub is_directory: bool,
    /// Which socket operations are permitted.
    pub mode: UnixSocketMode,
    /// Where this capability originated.
    #[serde(default)]
    pub source: CapabilitySource,
}

impl UnixSocketCapability {
    /// Grant for a single socket file.
    ///
    /// If `mode == Connect`, the path must already exist and must not be
    /// a directory.
    ///
    /// If `mode == ConnectBind`, the path may not yet exist (bind creates
    /// it). In that case the parent directory must exist; canonicalisation
    /// resolves the parent and re-appends the final path component.
    pub fn new_file(path: impl AsRef<Path>, mode: UnixSocketMode) -> Result<Self> {
        let path = path.as_ref();

        let resolved = match path.canonicalize() {
            Ok(p) if p.is_dir() => {
                return Err(NonoError::ExpectedFile(path.to_path_buf()));
            }
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // ConnectBind is allowed to grant paths that do not exist
                // yet — bind(2) will create the socket file. Canonicalise
                // the parent and re-append the final component so the
                // resolved path is anchored in a real directory.
                if !mode.permits_bind() {
                    return Err(NonoError::PathNotFound(path.to_path_buf()));
                }
                let parent = path
                    .parent()
                    .ok_or_else(|| NonoError::PathCanonicalization {
                        path: path.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "socket path has no parent directory",
                        ),
                    })?;
                let file_name =
                    path.file_name()
                        .ok_or_else(|| NonoError::PathCanonicalization {
                            path: path.to_path_buf(),
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "socket path has no final component",
                            ),
                        })?;
                let resolved_parent = parent.canonicalize().map_err(|parent_err| {
                    if parent_err.kind() == std::io::ErrorKind::NotFound {
                        NonoError::PathNotFound(parent.to_path_buf())
                    } else {
                        NonoError::PathCanonicalization {
                            path: parent.to_path_buf(),
                            source: parent_err,
                        }
                    }
                })?;
                if !resolved_parent.is_dir() {
                    return Err(NonoError::ExpectedDirectory(parent.to_path_buf()));
                }
                resolved_parent.join(file_name)
            }
            Err(e) => {
                return Err(NonoError::PathCanonicalization {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        };

        Ok(Self {
            original: path.to_path_buf(),
            resolved,
            is_directory: false,
            mode,
            source: CapabilitySource::User,
        })
    }

    /// Grant for any pathname socket directly within a directory.
    ///
    /// Non-recursive: a socket one level deeper (e.g. `<dir>/subdir/foo.sock`)
    /// is not covered. The directory itself must already exist.
    ///
    /// Rejects the filesystem root (`/`) as defence-in-depth against
    /// accidental grants that would cover sockets anywhere at top level
    /// (cf. [`validate_platform_rule`]'s rejection of root-level subpath
    /// grants for filesystem rules). Use explicit subdirectory paths.
    pub fn new_dir(path: impl AsRef<Path>, mode: UnixSocketMode) -> Result<Self> {
        let path = path.as_ref();

        let resolved = path.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::PathNotFound(path.to_path_buf())
            } else {
                NonoError::PathCanonicalization {
                    path: path.to_path_buf(),
                    source: e,
                }
            }
        })?;

        if !resolved.is_dir() {
            return Err(NonoError::ExpectedDirectory(path.to_path_buf()));
        }

        if resolved.parent().is_none() {
            return Err(NonoError::SandboxInit(
                "unix socket directory grant at filesystem root is not permitted".to_string(),
            ));
        }

        Ok(Self {
            original: path.to_path_buf(),
            resolved,
            is_directory: true,
            mode,
            source: CapabilitySource::User,
        })
    }

    /// True if `sockaddr_path` is covered by this grant.
    ///
    /// - File grants: `sockaddr_path == resolved` exactly.
    /// - Directory grants: `sockaddr_path`'s parent equals `resolved`,
    ///   component-wise (non-recursive). Subdirectories are not covered.
    ///
    /// Uses `Path` component semantics; never string prefix
    /// (`path-component-compare` invariant).
    #[must_use]
    pub fn covers(&self, sockaddr_path: &Path) -> bool {
        if self.is_directory {
            sockaddr_path.parent() == Some(self.resolved.as_path())
        } else {
            sockaddr_path == self.resolved.as_path()
        }
    }
}

impl std::fmt::Display for UnixSocketCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scope = if self.is_directory { "dir " } else { "" };
        write!(f, "{}{} ({})", scope, self.resolved.display(), self.mode)
    }
}

/// Validate a platform-specific rule for obvious security issues.
///
/// Rejects rules that:
/// - Don't start with `(` (malformed S-expressions)
/// - Contain unbalanced parentheses
/// - Grant root-level filesystem access `(allow file-read* (subpath "/"))`
/// - Grant root-level write access `(allow file-write* (subpath "/"))`
///
/// Validation is performed on tokenized S-expression content with comments
/// stripped, so whitespace variations and `#| ... |#` block comments cannot
/// bypass the checks.
fn validate_platform_rule(rule: &str) -> Result<()> {
    let trimmed = rule.trim();

    if !trimmed.starts_with('(') {
        return Err(NonoError::SandboxInit(format!(
            "platform rule must be an S-expression starting with '(': {}",
            rule
        )));
    }

    let tokens = tokenize_sexp(trimmed)?;

    // Check for balanced parentheses
    let mut depth: i32 = 0;
    for tok in &tokens {
        match tok.as_str() {
            "(" => depth = depth.saturating_add(1),
            ")" => {
                depth = depth.saturating_sub(1);
                if depth < 0 {
                    return Err(NonoError::SandboxInit(format!(
                        "platform rule has unbalanced parentheses: {rule}"
                    )));
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(NonoError::SandboxInit(format!(
            "platform rule has unbalanced parentheses: {rule}"
        )));
    }

    // Look for dangerous patterns: (allow file-read* (subpath "/"))
    // and (allow file-write* (subpath "/"))
    // We check the non-parenthesis tokens for the sequence:
    // "allow", file-read*/file-write*, "subpath", "/"
    let content_tokens: Vec<&str> = tokens
        .iter()
        .map(String::as_str)
        .filter(|t| *t != "(" && *t != ")")
        .collect();
    for window in content_tokens.windows(4) {
        if window[0] == "allow"
            && (window[1] == "file-read*" || window[1] == "file-write*")
            && window[2] == "subpath"
            && window[3] == "/"
        {
            let kind = if window[1] == "file-read*" {
                "read"
            } else {
                "write"
            };
            return Err(NonoError::SandboxInit(format!(
                "platform rule must not grant root-level {kind} access"
            )));
        }
    }

    Ok(())
}

/// Tokenize an S-expression string, stripping `#| ... |#` block comments
/// and `;` line comments. Parentheses and quoted strings are returned as
/// individual tokens.
fn tokenize_sexp(input: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            // Whitespace: skip
            c if c.is_ascii_whitespace() => {
                chars.next();
            }
            // Block comment: #| ... |#
            '#' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    let mut closed = false;
                    while let Some(cc) = chars.next() {
                        if cc == '|' && chars.peek() == Some(&'#') {
                            chars.next();
                            closed = true;
                            break;
                        }
                    }
                    if !closed {
                        return Err(NonoError::SandboxInit(
                            "platform rule has unterminated block comment".to_string(),
                        ));
                    }
                } else {
                    // Bare '#' is part of a token
                    let mut tok = String::from('#');
                    while let Some(&nc) = chars.peek() {
                        if nc.is_ascii_whitespace() || nc == '(' || nc == ')' || nc == '"' {
                            break;
                        }
                        tok.push(nc);
                        chars.next();
                    }
                    tokens.push(tok);
                }
            }
            // Line comment: ; until end of line
            ';' => {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '\n' {
                        break;
                    }
                }
            }
            // Parentheses: individual tokens
            '(' | ')' => {
                tokens.push(String::from(c));
                chars.next();
            }
            // Quoted string: extract content without quotes
            '"' => {
                chars.next();
                let mut s = String::new();
                let mut closed = false;
                while let Some(sc) = chars.next() {
                    if sc == '\\' {
                        // Consume escaped character
                        if let Some(esc) = chars.next() {
                            s.push(esc);
                        }
                    } else if sc == '"' {
                        closed = true;
                        break;
                    } else {
                        s.push(sc);
                    }
                }
                if !closed {
                    return Err(NonoError::SandboxInit(
                        "platform rule has unterminated string".to_string(),
                    ));
                }
                tokens.push(s);
            }
            // Bare token
            _ => {
                let mut tok = String::new();
                while let Some(&nc) = chars.peek() {
                    if nc.is_ascii_whitespace() || nc == '(' || nc == ')' || nc == '"' {
                        break;
                    }
                    tok.push(nc);
                    chars.next();
                }
                tokens.push(tok);
            }
        }
    }

    Ok(tokens)
}

/// Network access mode for the sandbox.
///
/// Determines how network traffic is filtered at the OS level.
/// `ProxyOnly` restricts outbound connections to a single localhost port,
/// Signal isolation mode for the sandbox.
///
/// Controls whether the sandboxed process can send signals to processes
/// outside its own sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalMode {
    /// Signals restricted to the current sandbox.
    ///
    /// On macOS: emits `(allow signal (target self))` and
    /// `(allow signal (target same-sandbox))` in Seatbelt — permits
    /// `kill()` on the process itself and on any child that inherited the
    /// same sandbox. External processes cannot be signaled. Terminal-
    /// generated signals (e.g., Ctrl+C delivering SIGINT to the foreground
    /// process group) are delivered by the kernel and bypass the sandbox.
    ///
    /// On Linux: Landlock V6 `LANDLOCK_SCOPE_SIGNAL` restricts signaling
    /// to processes in the same sandbox. Landlock cannot distinguish "self
    /// only" from "same sandbox", so `Isolated` and `AllowSameSandbox`
    /// produce identical enforcement.
    #[default]
    Isolated,
    /// Signals allowed to child processes in the same sandbox only.
    ///
    /// On macOS: `(allow signal (target same-sandbox))` in Seatbelt.
    /// Permits signaling any process that inherited the sandbox (i.e., forked
    /// or exec'd children), but blocks signals to external processes.
    ///
    /// On Linux: enforced on Landlock V6+ with `LANDLOCK_SCOPE_SIGNAL`.
    /// This blocks signaling processes outside the current sandbox while
    /// still allowing signals to same-sandbox descendants.
    AllowSameSandbox,
    /// Signals allowed to any process (no filtering).
    AllowAll,
}

/// Process inspection mode for the sandbox.
///
/// Controls whether the sandboxed process can read process information
/// (e.g., via `ps`, `proc_pidinfo`, `proc_listpids`) about processes
/// outside its own sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessInfoMode {
    /// Process inspection restricted to the current sandbox.
    ///
    /// On macOS: emits `(allow process-info* (target self))` and
    /// `(allow process-info* (target same-sandbox))` in Seatbelt — permits
    /// inspection of the process itself and children that inherited the
    /// sandbox, while blocking inspection of external processes.
    ///
    /// On Linux: no-op (Landlock does not restrict process inspection).
    #[default]
    Isolated,
    /// Process inspection allowed for child processes in the same sandbox only.
    ///
    /// On macOS: emits `(allow process-info* (target same-sandbox))` in Seatbelt.
    /// Permits `ps` and `proc_pidinfo` on processes that inherited the sandbox,
    /// while blocking inspection of external processes.
    ///
    /// On Linux: no-op (Landlock does not restrict process inspection).
    AllowSameSandbox,
    /// Process inspection allowed for any process.
    ///
    /// On macOS: omits the `(deny process-info* (target others))` rule entirely.
    AllowAll,
}

/// IPC mode for the sandbox.
///
/// Controls whether the sandboxed process can use POSIX IPC primitives
/// (semaphores) beyond shared memory. Shared memory (`shm_open`) is always
/// allowed; this mode gates semaphore operations needed by multiprocessing
/// runtimes (e.g., Python `multiprocessing`, Ruby `parallel`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcMode {
    /// POSIX shared memory only (default). Semaphore operations are denied.
    ///
    /// On macOS: only `ipc-posix-shm-*` rules emitted. `sem_open()` etc.
    /// are blocked by the `(deny default)` baseline.
    ///
    /// On Linux: no-op (Landlock does not restrict IPC primitives).
    #[default]
    SharedMemoryOnly,
    /// Full POSIX IPC: shared memory + semaphores.
    ///
    /// On macOS: adds `ipc-posix-sem-*` rules to the Seatbelt profile.
    /// Required for Python `multiprocessing`, Node `worker_threads` with
    /// shared memory, and similar multiprocess coordination.
    ///
    /// On Linux: no-op (Landlock does not restrict IPC primitives).
    Full,
}

/// forcing all traffic through the nono proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    /// All network access blocked (Landlock deny-all TCP, Seatbelt deny network*)
    Blocked,
    /// All network access allowed (no filtering)
    #[default]
    AllowAll,
    /// Only localhost TCP to the specified port is allowed for outbound.
    /// Optionally allows binding and accepting inbound on specific ports.
    ///
    /// On macOS: `(allow network-outbound (remote tcp "localhost:PORT"))`.
    /// If bind_ports is non-empty, also adds `(allow network-bind)` and
    /// `(allow network-inbound)` (Seatbelt cannot filter by port).
    ///
    /// On Linux: Landlock `NetPort` rule for the proxy port (ConnectTcp) plus
    /// per-port BindTcp rules for each bind_port.
    ProxyOnly {
        /// The localhost port the proxy listens on
        port: u16,
        /// Ports the sandboxed process is allowed to bind and accept connections on.
        /// This enables servers like OpenClaw gateway to listen while still routing
        /// outbound HTTP through the credential proxy.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        bind_ports: Vec<u16>,
    },
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkMode::Blocked => write!(f, "blocked"),
            NetworkMode::AllowAll => write!(f, "allowed"),
            NetworkMode::ProxyOnly { port, bind_ports } => {
                if bind_ports.is_empty() {
                    write!(f, "proxy-only (localhost:{})", port)
                } else {
                    let ports_str: Vec<String> = bind_ports.iter().map(|p| p.to_string()).collect();
                    write!(
                        f,
                        "proxy-only (localhost:{}, bind: {})",
                        port,
                        ports_str.join(", ")
                    )
                }
            }
        }
    }
}

/// The complete set of capabilities granted to the sandbox
///
/// Use the builder pattern to construct a capability set:
///
/// ```no_run
/// use nono::{CapabilitySet, AccessMode};
///
/// let caps = CapabilitySet::new()
///     .allow_path("/usr", AccessMode::Read)?
///     .allow_path("/project", AccessMode::ReadWrite)?
///     .block_network();
/// # Ok::<(), nono::NonoError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    /// Filesystem capabilities
    fs: Vec<FsCapability>,
    /// AF_UNIX socket capabilities (pathname grants only; see
    /// [`UnixSocketCapability`] and issue #685).
    unix_sockets: Vec<UnixSocketCapability>,
    /// Network access mode (default: AllowAll)
    network_mode: NetworkMode,
    /// Per-port TCP connect allowlist (Linux Landlock V4+ only).
    /// Adding any entry implies Blocked base with specific port exceptions.
    tcp_connect_ports: Vec<u16>,
    /// Per-port TCP bind allowlist (Linux Landlock V4+ only).
    tcp_bind_ports: Vec<u16>,
    /// TCP ports allowed for bidirectional IPC (connect + bind).
    /// These apply regardless of NetworkMode.
    ///
    /// On macOS (Seatbelt), outbound is scoped to localhost per-port.
    /// On Linux (Landlock), ConnectTcp/BindTcp filter by port only, not
    /// by destination IP. Use with `--block-net` or proxy mode to ensure
    /// only localhost is reachable.
    localhost_ports: Vec<u16>,
    /// Commands explicitly allowed (overrides blocklists - for CLI use)
    allowed_commands: Vec<String>,
    /// Additional commands to block (extends blocklists - for CLI use)
    blocked_commands: Vec<String>,
    /// Raw platform-specific rules injected verbatim into the sandbox profile.
    /// On macOS these are Seatbelt S-expression strings; ignored on Linux.
    platform_rules: Vec<String>,
    /// Signal isolation mode (default: Isolated).
    signal_mode: SignalMode,
    /// Process inspection mode (default: Isolated).
    process_info_mode: ProcessInfoMode,
    /// IPC mode (default: SharedMemoryOnly).
    ipc_mode: IpcMode,
    /// Enable sandbox extension support for runtime capability expansion.
    /// On macOS, adds extension filter rules to the Seatbelt profile so that
    /// `sandbox_extension_consume()` tokens can expand the sandbox dynamically.
    /// On Linux, this flag is informational (seccomp-notify is installed separately).
    extensions_enabled: bool,
    /// Enable macOS Seatbelt denial logging for supervised diagnostics.
    /// When set, the generated Seatbelt profile emits `(debug deny)` so
    /// sandboxd records denial events in the unified log.
    seatbelt_debug_deny: bool,
}

impl CapabilitySet {
    /// Create a new empty capability set
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // Builder methods (consume self and return Result<Self>)

    /// Add directory access permission (builder pattern)
    ///
    /// The path is canonicalized and validated. Returns an error if the path
    /// does not exist or is not a directory.
    pub fn allow_path(mut self, path: impl AsRef<Path>, mode: AccessMode) -> Result<Self> {
        let cap = FsCapability::new_dir(path, mode)?;
        self.fs.push(cap);
        Ok(self)
    }

    /// Add file access permission (builder pattern)
    ///
    /// The path is canonicalized and validated. Returns an error if the path
    /// does not exist or is not a file.
    pub fn allow_file(mut self, path: impl AsRef<Path>, mode: AccessMode) -> Result<Self> {
        let cap = FsCapability::new_file(path, mode)?;
        self.fs.push(cap);
        Ok(self)
    }

    /// Add a file-scoped AF_UNIX socket capability (builder pattern).
    ///
    /// The path is canonicalized. If `mode` is [`UnixSocketMode::Connect`],
    /// the path must exist; if `mode` is [`UnixSocketMode::ConnectBind`],
    /// the path may not exist yet (bind creates it) but the parent must.
    pub fn allow_unix_socket(
        mut self,
        path: impl AsRef<Path>,
        mode: UnixSocketMode,
    ) -> Result<Self> {
        let cap = UnixSocketCapability::new_file(path, mode)?;
        self.unix_sockets.push(cap);
        Ok(self)
    }

    /// Add a directory-scoped AF_UNIX socket capability (builder pattern).
    ///
    /// Grants cover any pathname socket directly within the directory
    /// (non-recursive). The directory must exist at grant time.
    pub fn allow_unix_socket_dir(
        mut self,
        path: impl AsRef<Path>,
        mode: UnixSocketMode,
    ) -> Result<Self> {
        let cap = UnixSocketCapability::new_dir(path, mode)?;
        self.unix_sockets.push(cap);
        Ok(self)
    }

    /// Block network access (builder pattern)
    ///
    /// By default, network access is allowed. Call this to block all network.
    #[must_use]
    pub fn block_network(mut self) -> Self {
        self.network_mode = NetworkMode::Blocked;
        self
    }

    /// Set network mode (builder pattern)
    #[must_use]
    pub fn set_network_mode(mut self, mode: NetworkMode) -> Self {
        self.network_mode = mode;
        self
    }

    /// Restrict network to localhost proxy port only (builder pattern)
    ///
    /// On macOS: `(allow network-outbound (remote tcp "localhost:PORT"))`.
    /// On Linux: Landlock `NetPort` rule for the specified port.
    #[must_use]
    pub fn proxy_only(mut self, port: u16) -> Self {
        self.network_mode = NetworkMode::ProxyOnly {
            port,
            bind_ports: Vec::new(),
        };
        self
    }

    /// Restrict network to localhost proxy port only, with additional bind ports (builder pattern)
    ///
    /// Like `proxy_only`, but also allows the sandboxed process to bind and accept
    /// inbound connections on the specified ports. This is useful for servers that
    /// need to listen (e.g., OpenClaw gateway on port 18789) while still routing
    /// outbound HTTP through the credential injection proxy.
    ///
    /// On macOS: Seatbelt cannot filter by port, so this adds blanket
    /// `(allow network-bind)` and `(allow network-inbound)`.
    ///
    /// On Linux: Landlock adds per-port BindTcp rules.
    #[must_use]
    pub fn proxy_only_with_bind(mut self, proxy_port: u16, bind_ports: Vec<u16>) -> Self {
        self.network_mode = NetworkMode::ProxyOnly {
            port: proxy_port,
            bind_ports,
        };
        self
    }

    /// Allow TCP connect to a specific port (builder pattern)
    ///
    /// Linux Landlock V4+ only. Adding any port rule automatically blocks
    /// all other network access (allowlist model). Returns an error on macOS.
    #[must_use]
    pub fn allow_tcp_connect(mut self, port: u16) -> Self {
        self.tcp_connect_ports.push(port);
        self
    }

    /// Allow TCP bind on a specific port (builder pattern)
    ///
    /// Linux Landlock V4+ only. Returns an error on macOS.
    #[must_use]
    pub fn allow_tcp_bind(mut self, port: u16) -> Self {
        self.tcp_bind_ports.push(port);
        self
    }

    /// Allow bidirectional localhost TCP on a specific port (builder pattern).
    ///
    /// The sandboxed process can both connect to and bind/listen on
    /// `127.0.0.1:port`. Works across all network modes.
    ///
    /// On macOS: outbound is per-port via Seatbelt; bind/inbound is blanket
    /// (same tradeoff as `--allow-bind`).
    /// On Linux: per-port ConnectTcp + BindTcp via Landlock.
    #[must_use]
    pub fn allow_localhost_port(mut self, port: u16) -> Self {
        self.localhost_ports.push(port);
        self
    }

    /// Allow TCP connect to standard HTTPS ports (443, 8443)
    ///
    /// Convenience method. Linux Landlock V4+ only.
    #[must_use]
    pub fn allow_https(self) -> Self {
        self.allow_tcp_connect(443).allow_tcp_connect(8443)
    }

    /// Set signal isolation mode (builder pattern)
    ///
    /// By default, signals are isolated to the sandbox's own process subtree.
    /// Use `SignalMode::AllowAll` to permit signaling any process.
    #[must_use]
    pub fn set_signal_mode(mut self, mode: SignalMode) -> Self {
        self.signal_mode = mode;
        self
    }

    /// Set process inspection mode (builder pattern)
    ///
    /// Controls whether the sandboxed process can read process info (e.g., via
    /// `ps`, `proc_pidinfo`) for processes outside the sandbox.
    #[must_use]
    pub fn set_process_info_mode(mut self, mode: ProcessInfoMode) -> Self {
        self.process_info_mode = mode;
        self
    }

    /// Set IPC mode (builder pattern)
    ///
    /// Controls whether the sandboxed process can use POSIX semaphores.
    /// Shared memory is always allowed; `IpcMode::Full` additionally enables
    /// semaphore operations required by multiprocessing runtimes.
    #[must_use]
    pub fn set_ipc_mode(mut self, mode: IpcMode) -> Self {
        self.ipc_mode = mode;
        self
    }

    /// Allow signals to any process (builder pattern)
    ///
    /// Disables signal isolation. By default, sandboxed processes can only
    /// signal their own process subtree.
    #[must_use]
    pub fn allow_signals(mut self) -> Self {
        self.signal_mode = SignalMode::AllowAll;
        self
    }

    /// Enable sandbox extensions for runtime capability expansion (builder pattern)
    ///
    /// On macOS, this adds extension filter rules to the Seatbelt profile so that
    /// `sandbox_extension_consume()` tokens can dynamically expand access. The rules
    /// are inert until a matching token is consumed -- they add no access by themselves.
    ///
    /// On Linux, this flag is informational only; seccomp-notify is installed
    /// separately in the child process.
    #[must_use]
    pub fn enable_extensions(mut self) -> Self {
        self.extensions_enabled = true;
        self
    }

    /// Add a command to the allow list (builder pattern)
    ///
    /// Allowed commands override any blocklist. This is primarily for CLI use.
    #[must_use]
    pub fn allow_command(mut self, cmd: impl Into<String>) -> Self {
        self.allowed_commands.push(cmd.into());
        self
    }

    /// Add a command to the block list (builder pattern)
    ///
    /// Blocked commands extend any existing blocklist. This is primarily for CLI use.
    #[must_use]
    pub fn block_command(mut self, cmd: impl Into<String>) -> Self {
        self.blocked_commands.push(cmd.into());
        self
    }

    /// Add a raw platform-specific rule (builder pattern)
    ///
    /// On macOS, these are Seatbelt S-expression strings injected verbatim
    /// into the generated profile. Ignored on Linux.
    ///
    /// Returns an error if the rule is malformed or grants root-level access.
    pub fn platform_rule(mut self, rule: impl Into<String>) -> Result<Self> {
        let rule = rule.into();
        validate_platform_rule(&rule)?;
        self.platform_rules.push(rule);
        Ok(self)
    }

    // Mutable methods (for advanced/programmatic use)

    /// Add a filesystem capability directly
    pub fn add_fs(&mut self, cap: FsCapability) {
        self.fs.push(cap);
    }

    /// Add an AF_UNIX socket capability directly.
    ///
    /// Mirrors [`Self::add_fs`]; used by `SandboxState::to_caps` and other
    /// programmatic callers that already hold a constructed
    /// [`UnixSocketCapability`].
    pub fn add_unix_socket(&mut self, cap: UnixSocketCapability) {
        self.unix_sockets.push(cap);
    }

    /// Set network blocking state
    ///
    /// `true` sets `NetworkMode::Blocked`, `false` sets `NetworkMode::AllowAll`.
    /// For finer control, use `set_network_mode_mut()`.
    pub fn set_network_blocked(&mut self, blocked: bool) {
        self.network_mode = if blocked {
            NetworkMode::Blocked
        } else {
            NetworkMode::AllowAll
        };
    }

    /// Set network mode (mutable)
    pub fn set_network_mode_mut(&mut self, mode: NetworkMode) {
        self.network_mode = mode;
    }

    /// Set signal isolation mode (mutable)
    pub fn set_signal_mode_mut(&mut self, mode: SignalMode) {
        self.signal_mode = mode;
    }

    /// Set process inspection mode (mutable)
    pub fn set_process_info_mode_mut(&mut self, mode: ProcessInfoMode) {
        self.process_info_mode = mode;
    }

    /// Set IPC mode (mutable)
    pub fn set_ipc_mode_mut(&mut self, mode: IpcMode) {
        self.ipc_mode = mode;
    }

    /// Add a TCP connect port to the allowlist (mutable)
    pub fn add_tcp_connect_port(&mut self, port: u16) {
        self.tcp_connect_ports.push(port);
    }

    /// Add a TCP bind port to the allowlist (mutable)
    pub fn add_tcp_bind_port(&mut self, port: u16) {
        self.tcp_bind_ports.push(port);
    }

    /// Add a localhost IPC port (mutable)
    pub fn add_localhost_port(&mut self, port: u16) {
        self.localhost_ports.push(port);
    }

    /// Set sandbox extensions state
    pub fn set_extensions_enabled(&mut self, enabled: bool) {
        self.extensions_enabled = enabled;
    }

    /// Enable or disable macOS Seatbelt denial logging.
    pub fn set_seatbelt_debug_deny(&mut self, enabled: bool) {
        self.seatbelt_debug_deny = enabled;
    }

    /// Add to allowed commands list
    pub fn add_allowed_command(&mut self, cmd: impl Into<String>) {
        self.allowed_commands.push(cmd.into());
    }

    /// Add to blocked commands list
    pub fn add_blocked_command(&mut self, cmd: impl Into<String>) {
        self.blocked_commands.push(cmd.into());
    }

    /// Add a raw platform-specific rule
    ///
    /// Returns an error if the rule is malformed or grants root-level access.
    pub fn add_platform_rule(&mut self, rule: impl Into<String>) -> Result<()> {
        let rule = rule.into();
        validate_platform_rule(&rule)?;
        self.platform_rules.push(rule);
        Ok(())
    }

    /// Remove exact file capabilities whose original or resolved path matches
    /// any of the provided denied paths.
    ///
    /// Directory capabilities are preserved so platform-specific deny rules can
    /// still narrow access within an allowed tree.
    pub fn remove_exact_file_caps_for_paths(&mut self, denied_paths: &[PathBuf]) -> usize {
        let before = self.fs.len();
        self.fs.retain(|cap| {
            !cap.is_file
                || !denied_paths
                    .iter()
                    .any(|denied| cap.original == *denied || cap.resolved == *denied)
        });
        before.saturating_sub(self.fs.len())
    }

    // Accessors

    /// Get filesystem capabilities
    #[must_use]
    pub fn fs_capabilities(&self) -> &[FsCapability] {
        &self.fs
    }

    /// Get AF_UNIX socket capabilities.
    #[must_use]
    pub fn unix_socket_capabilities(&self) -> &[UnixSocketCapability] {
        &self.unix_sockets
    }

    /// True if any AF_UNIX socket capability covers `sockaddr_path` and
    /// permits `op` on it.
    ///
    /// Used by the Linux supervisor's seccomp-notify handler:
    /// `SYS_CONNECT` → [`UnixSocketOp::Connect`], `SYS_BIND`
    /// → [`UnixSocketOp::Bind`].
    #[must_use]
    pub fn unix_socket_allowed(&self, sockaddr_path: &Path, op: UnixSocketOp) -> bool {
        self.unix_sockets.iter().any(|cap| {
            cap.covers(sockaddr_path)
                && match op {
                    UnixSocketOp::Connect => true, // any grant allows connect
                    UnixSocketOp::Bind => cap.mode.permits_bind(),
                }
        })
    }

    /// Rewrite self-referential procfs capabilities for a specific process.
    ///
    /// This is needed when capabilities are prepared in one process and then
    /// applied in a different child after `fork()`. Paths such as `/proc/self`
    /// and `/dev/fd` must resolve to the sandboxed child, not the parent that
    /// originally canonicalized them.
    pub fn remap_procfs_self_references(&mut self, process_pid: u32, thread_pid: Option<u32>) {
        for cap in &mut self.fs {
            if let Some(rewritten) =
                rewrite_procfs_self_reference(&cap.original, process_pid, thread_pid)
            {
                cap.resolved = rewritten;
            }
        }
        self.deduplicate();
    }

    /// Widen `/proc/<pid>` READ-only Landlock rules to `/proc` so that
    /// grandchild processes can access their own procfs entries.
    ///
    /// This is needed because Landlock rules are fixed at sandbox setup time with
    /// the direct child's PID. When a grandchild (e.g. nono→sh→bun) forks, it
    /// gets a new PID and its `/proc/self` resolves to a different inode than the
    /// direct child's `/proc/<sh_pid>`. By widening to `/proc`, we allow any
    /// descendant to read its own procfs entries.
    ///
    /// Only applies to READ capabilities at the `/proc/self` level (not
    /// subdirectories like `/proc/self/fd` which may have write access).
    pub fn widen_procfs_self_to_proc(&mut self) {
        for cap in &mut self.fs {
            if cap.access == AccessMode::Read {
                let is_proc_self_dir = cap
                    .original
                    .to_str()
                    .map(|s| s == "/proc/self" || s == "/proc/self/")
                    .unwrap_or(false);
                if is_proc_self_dir {
                    cap.resolved = std::path::PathBuf::from("/proc");
                }
            }
        }
        self.deduplicate();
    }

    /// Check if network access is blocked
    ///
    /// Returns `true` for both `Blocked` and `ProxyOnly` modes, since both
    /// restrict general outbound network access at the OS level.
    #[must_use]
    pub fn is_network_blocked(&self) -> bool {
        matches!(
            self.network_mode,
            NetworkMode::Blocked | NetworkMode::ProxyOnly { .. }
        )
    }

    /// Get the signal isolation mode
    #[must_use]
    pub fn signal_mode(&self) -> SignalMode {
        self.signal_mode
    }

    /// Get the process inspection mode
    #[must_use]
    pub fn process_info_mode(&self) -> ProcessInfoMode {
        self.process_info_mode
    }

    /// Get the IPC mode
    #[must_use]
    pub fn ipc_mode(&self) -> IpcMode {
        self.ipc_mode
    }

    /// Get the network mode
    #[must_use]
    pub fn network_mode(&self) -> &NetworkMode {
        &self.network_mode
    }

    /// Get per-port TCP connect allowlist
    #[must_use]
    pub fn tcp_connect_ports(&self) -> &[u16] {
        &self.tcp_connect_ports
    }

    /// Get per-port TCP bind allowlist
    #[must_use]
    pub fn tcp_bind_ports(&self) -> &[u16] {
        &self.tcp_bind_ports
    }

    /// Get localhost IPC ports
    #[must_use]
    pub fn localhost_ports(&self) -> &[u16] {
        &self.localhost_ports
    }

    /// Check if sandbox extensions are enabled for runtime capability expansion
    #[must_use]
    pub fn extensions_enabled(&self) -> bool {
        self.extensions_enabled
    }

    /// Check whether macOS Seatbelt denial logging is enabled.
    #[must_use]
    pub fn seatbelt_debug_deny(&self) -> bool {
        self.seatbelt_debug_deny
    }

    /// Get allowed commands
    #[must_use]
    pub fn allowed_commands(&self) -> &[String] {
        &self.allowed_commands
    }

    /// Get blocked commands
    #[must_use]
    pub fn blocked_commands(&self) -> &[String] {
        &self.blocked_commands
    }

    /// Get platform-specific rules
    #[must_use]
    pub fn platform_rules(&self) -> &[String] {
        &self.platform_rules
    }

    /// Check if this set has any filesystem capabilities
    #[must_use]
    pub fn has_fs(&self) -> bool {
        !self.fs.is_empty()
    }

    /// Deduplicate filesystem capabilities by resolved path.
    ///
    /// Priority rules:
    /// 1. **User source wins over System/Group**: if the user explicitly chose
    ///    `--read /tmp`, a system default of ReadWrite must not override it.
    /// 2. **Among same-source entries**, highest access level wins
    ///    (ReadWrite > Read/Write).
    /// 3. **Symlink originals are preserved**: if any duplicate has
    ///    `original != resolved` (e.g., `/tmp` -> `/private/tmp`), the surviving
    ///    entry inherits that original so Seatbelt profile generation can emit
    ///    rules for both the symlink and target paths.
    pub fn deduplicate(&mut self) {
        use std::collections::HashMap;

        // Group by (resolved path, is_file)
        let mut seen: HashMap<(PathBuf, bool), usize> = HashMap::new();
        let mut to_remove = Vec::new();
        // Deferred updates: (target_index, new_original) to apply after iteration
        let mut original_updates: Vec<(usize, PathBuf)> = Vec::new();
        // Deferred access upgrades: (target_index, new_access) for Read+Write merges
        let mut access_upgrades: Vec<(usize, AccessMode)> = Vec::new();

        for (i, cap) in self.fs.iter().enumerate() {
            let key = (cap.resolved.clone(), cap.is_file);
            if let Some(&existing_idx) = seen.get(&key) {
                let existing = &self.fs[existing_idx];

                // Determine which entry to keep and whether to merge access modes.
                // User-intent entries (User/Profile) always win over
                // system/group entries regardless of access level.
                let new_is_user = cap.source.is_user_intent();
                let existing_is_user = existing.source.is_user_intent();

                let keep_new = if new_is_user && !existing_is_user {
                    // New is User, existing is System/Group -> keep User
                    true
                } else if !new_is_user && existing_is_user {
                    // Existing is User, new is System/Group -> keep existing
                    false
                } else {
                    // Same source category: highest access wins
                    cap.access == AccessMode::ReadWrite && existing.access != AccessMode::ReadWrite
                };

                // Merge complementary access modes.
                let merged_access = match (existing.access, cap.access) {
                    (AccessMode::ReadWriteExecute, _) | (_, AccessMode::ReadWriteExecute) => {
                        Some(AccessMode::ReadWriteExecute)
                    }
                    (AccessMode::Read, AccessMode::Write)
                    | (AccessMode::Write, AccessMode::Read) => Some(AccessMode::ReadWrite),
                    (AccessMode::Read, AccessMode::Execute)
                    | (AccessMode::Execute, AccessMode::Read) => Some(AccessMode::ReadExecute),
                    (AccessMode::ReadWrite, AccessMode::Execute)
                    | (AccessMode::Execute, AccessMode::ReadWrite)
                    | (AccessMode::ReadWrite, AccessMode::ReadExecute)
                    | (AccessMode::ReadExecute, AccessMode::ReadWrite)
                    | (AccessMode::ReadExecute, AccessMode::Write)
                    | (AccessMode::Write, AccessMode::ReadExecute) => {
                        Some(AccessMode::ReadWriteExecute)
                    }
                    _ => None,
                };

                if keep_new {
                    to_remove.push(existing_idx);
                    seen.insert(key, i);
                    // Preserve symlink original from the removed entry
                    if cap.original == cap.resolved && existing.original != existing.resolved {
                        original_updates.push((i, existing.original.clone()));
                    }
                    // Apply merged access to the new (kept) entry
                    if let Some(access) = merged_access {
                        access_upgrades.push((i, access));
                    }
                } else {
                    // Inherit symlink original from the entry being discarded
                    if existing.original == existing.resolved && cap.original != cap.resolved {
                        original_updates.push((existing_idx, cap.original.clone()));
                    }
                    to_remove.push(i);
                    // Apply merged access to the existing (kept) entry
                    if let Some(access) = merged_access {
                        access_upgrades.push((existing_idx, access));
                    }
                }
            } else {
                seen.insert(key, i);
            }
        }

        // Apply deferred symlink original updates
        for (idx, original) in original_updates {
            self.fs[idx].original = original;
        }

        // Apply deferred access upgrades (Read + Write -> ReadWrite)
        for (idx, access) in access_upgrades {
            self.fs[idx].access = access;
        }

        // Remove duplicates in reverse order to maintain indices
        to_remove.sort_unstable();
        to_remove.reverse();
        for idx in to_remove {
            self.fs.remove(idx);
        }

        self.deduplicate_unix_sockets();
    }

    /// Deduplicate [`UnixSocketCapability`] entries in-place.
    ///
    /// Two entries collide when they share `(resolved, is_directory)`.
    /// Merge rules match [`Self::deduplicate`]'s user-intent policy:
    ///
    /// - **User-intent beats system/group.** When a user- or profile-
    ///   sourced entry collides with a system/group entry, the user entry
    ///   is kept with *its own* mode unchanged. A user choosing `Connect`
    ///   for a path is deliberately narrowing the grant; dedup must not
    ///   silently re-widen it to `ConnectBind` just because an
    ///   unsolicited system grant also covers the path.
    /// - **Same-provenance collisions merge to the superset.** Two user-
    ///   intent entries (or two system entries) differing in mode end up
    ///   as `ConnectBind`, since `Connect` is a subset. This is the
    ///   socket-layer analog of the fs dedup's `Read + Write → ReadWrite`
    ///   rule, but one-directional: `Connect` never strengthens a
    ///   `ConnectBind` grant.
    fn deduplicate_unix_sockets(&mut self) {
        use std::collections::HashMap;

        let mut seen: HashMap<(PathBuf, bool), usize> = HashMap::new();
        let mut to_remove: Vec<usize> = Vec::new();
        let mut mode_upgrades: Vec<(usize, UnixSocketMode)> = Vec::new();
        let mut original_updates: Vec<(usize, PathBuf)> = Vec::new();

        for (i, cap) in self.unix_sockets.iter().enumerate() {
            let key = (cap.resolved.clone(), cap.is_directory);
            if let Some(&existing_idx) = seen.get(&key) {
                let existing = &self.unix_sockets[existing_idx];

                let new_is_user = cap.source.is_user_intent();
                let existing_is_user = existing.source.is_user_intent();

                // Only merge modes when both entries share provenance.
                // Across tiers, the user-intent entry's literal mode wins
                // — a user narrowing to Connect must not be silently
                // upgraded because a group also granted ConnectBind.
                let same_provenance = new_is_user == existing_is_user;
                let merged_mode = if same_provenance
                    && (existing.mode.permits_bind() || cap.mode.permits_bind())
                {
                    UnixSocketMode::ConnectBind
                } else {
                    // Keep whichever mode the retained entry had; decided
                    // per-branch below.
                    UnixSocketMode::Connect
                };

                let keep_new = match (new_is_user, existing_is_user) {
                    (true, false) => true,
                    (false, true) => false,
                    // Same provenance: prefer the stronger-mode entry, or
                    // the existing one when modes are equal.
                    _ => cap.mode.permits_bind() && !existing.mode.permits_bind(),
                };

                if keep_new {
                    to_remove.push(existing_idx);
                    seen.insert(key, i);
                    if cap.original == cap.resolved && existing.original != existing.resolved {
                        original_updates.push((i, existing.original.clone()));
                    }
                    // Mode upgrade only applies in the same-provenance
                    // case; otherwise cap.mode stays as-is.
                    if same_provenance && merged_mode != cap.mode {
                        mode_upgrades.push((i, merged_mode));
                    }
                } else {
                    if existing.original == existing.resolved && cap.original != cap.resolved {
                        original_updates.push((existing_idx, cap.original.clone()));
                    }
                    to_remove.push(i);
                    if same_provenance && merged_mode != existing.mode {
                        mode_upgrades.push((existing_idx, merged_mode));
                    }
                }
            } else {
                seen.insert(key, i);
            }
        }

        for (idx, original) in original_updates {
            self.unix_sockets[idx].original = original;
        }
        for (idx, mode) in mode_upgrades {
            self.unix_sockets[idx].mode = mode;
        }

        to_remove.sort_unstable();
        to_remove.reverse();
        for idx in to_remove {
            self.unix_sockets.remove(idx);
        }
    }

    /// Check if the given path is already covered by an existing directory capability.
    ///
    /// Uses component-wise Path::starts_with() to prevent path traversal issues
    /// (e.g., "/home" must not match "/homeevil").
    #[must_use]
    pub fn path_covered(&self, path: &Path) -> bool {
        self.fs
            .iter()
            .any(|cap| !cap.is_file && path.starts_with(&cap.resolved))
    }

    /// Check if the given path is already covered with at least the specified access mode.
    ///
    /// Like [`path_covered`](Self::path_covered), but also verifies the existing
    /// capability provides sufficient permissions. A read-only parent does not
    /// satisfy a readwrite requirement.
    #[must_use]
    pub fn path_covered_with_access(&self, path: &Path, required: AccessMode) -> bool {
        self.fs.iter().any(|cap| {
            !cap.is_file && path.starts_with(&cap.resolved) && cap.access.contains(required)
        })
    }

    /// Display a summary of capabilities (plain text)
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();

        if !self.fs.is_empty() {
            lines.push("Filesystem:".to_string());
            for cap in &self.fs {
                let kind = if cap.is_file { "file" } else { "dir" };
                lines.push(format!(
                    "  {} [{}] ({})",
                    cap.resolved.display(),
                    cap.access,
                    kind
                ));
            }
        }

        if !self.unix_sockets.is_empty() {
            lines.push("Unix sockets:".to_string());
            for cap in &self.unix_sockets {
                let scope = if cap.is_directory { "dir" } else { "file" };
                lines.push(format!(
                    "  {} [{}] ({})",
                    cap.resolved.display(),
                    cap.mode,
                    scope
                ));
            }
        }

        if lines.is_empty() {
            lines.push("(no capabilities granted)".to_string());
        }

        lines.push("Network:".to_string());
        lines.push(format!("  outbound: {}", self.network_mode));
        if !self.tcp_connect_ports.is_empty() {
            let ports: Vec<String> = self
                .tcp_connect_ports
                .iter()
                .map(|p| p.to_string())
                .collect();
            lines.push(format!("  tcp connect ports: {}", ports.join(", ")));
        }
        if !self.tcp_bind_ports.is_empty() {
            let ports: Vec<String> = self.tcp_bind_ports.iter().map(|p| p.to_string()).collect();
            lines.push(format!("  tcp bind ports: {}", ports.join(", ")));
        }

        lines.join("\n")
    }
}

fn rewrite_procfs_self_reference(
    original: &Path,
    process_pid: u32,
    thread_pid: Option<u32>,
) -> Option<PathBuf> {
    let thread_pid = thread_pid.unwrap_or(process_pid);

    match original {
        path if path == Path::new("/dev/fd") => {
            return Some(PathBuf::from(format!("/proc/{process_pid}/fd")));
        }
        path if path == Path::new("/dev/stdin") => {
            return Some(PathBuf::from(format!("/proc/{process_pid}/fd/0")));
        }
        path if path == Path::new("/dev/stdout") => {
            return Some(PathBuf::from(format!("/proc/{process_pid}/fd/1")));
        }
        path if path == Path::new("/dev/stderr") => {
            return Some(PathBuf::from(format!("/proc/{process_pid}/fd/2")));
        }
        _ => {}
    }

    let mut components = original.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal(std::ffi::OsStr::new("proc")))
    {
        return None;
    }

    let proc_component = components.next()?;
    let mut rewritten = PathBuf::from("/proc");

    match proc_component {
        Component::Normal(part) if part == std::ffi::OsStr::new("self") => {
            rewritten.push(process_pid.to_string());
        }
        Component::Normal(part) if part == std::ffi::OsStr::new("thread-self") => {
            rewritten.push(process_pid.to_string());
            rewritten.push("task");
            rewritten.push(thread_pid.to_string());
        }
        _ => return None,
    }

    for component in components {
        match component {
            Component::Normal(part) => rewritten.push(part),
            Component::CurDir => rewritten.push("."),
            Component::ParentDir => rewritten.push(".."),
            Component::RootDir | Component::Prefix(_) => {}
        }
    }

    Some(rewritten)
}

#[cfg(test)]
mod procfs_remap_tests {
    use super::*;

    #[test]
    fn remap_procfs_self_rewrites_proc_self_capability() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/proc/self"),
            resolved: PathBuf::from("/proc/111/self-was-parent"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("system_read_linux".to_string()),
        });

        caps.remap_procfs_self_references(4242, None);

        assert_eq!(
            caps.fs_capabilities()[0].original,
            PathBuf::from("/proc/self")
        );
        assert_eq!(
            caps.fs_capabilities()[0].resolved,
            PathBuf::from("/proc/4242")
        );
    }

    #[test]
    fn remap_procfs_self_rewrites_dev_fd_aliases() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/dev/fd"),
            resolved: PathBuf::from("/proc/111/fd"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("system_read_linux".to_string()),
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/dev/stdout"),
            resolved: PathBuf::from("/proc/111/fd/1"),
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Group("system_read_linux".to_string()),
        });

        caps.remap_procfs_self_references(4242, None);

        assert_eq!(
            caps.fs_capabilities()[0].resolved,
            PathBuf::from("/proc/4242/fd")
        );
        assert_eq!(
            caps.fs_capabilities()[1].resolved,
            PathBuf::from("/proc/4242/fd/1")
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_fs_capability_new_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path();

        let cap = FsCapability::new_dir(path, AccessMode::Read).unwrap();
        assert_eq!(cap.access, AccessMode::Read);
        assert!(cap.resolved.is_absolute());
        assert!(!cap.is_file);
    }

    #[test]
    fn test_fs_capability_new_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let cap = FsCapability::new_file(&file_path, AccessMode::Read).unwrap();
        assert_eq!(cap.access, AccessMode::Read);
        assert!(cap.resolved.is_absolute());
        assert!(cap.is_file);
    }

    #[test]
    fn test_fs_capability_nonexistent() {
        let result = FsCapability::new_dir("/nonexistent/path/12345", AccessMode::Read);
        assert!(matches!(result, Err(NonoError::PathNotFound(_))));
    }

    #[test]
    fn test_fs_capability_file_as_dir_error() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = FsCapability::new_dir(&file_path, AccessMode::Read);
        assert!(matches!(result, Err(NonoError::ExpectedDirectory(_))));
    }

    #[test]
    fn test_fs_capability_dir_as_file_error() {
        let dir = tempdir().unwrap();
        let path = dir.path();

        let result = FsCapability::new_file(path, AccessMode::Read);
        assert!(matches!(result, Err(NonoError::ExpectedFile(_))));
    }

    #[test]
    fn test_capability_set_builder() {
        let dir = tempdir().unwrap();

        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .unwrap()
            .block_network()
            .allow_command("allowed_cmd")
            .block_command("blocked_cmd");

        assert_eq!(caps.fs_capabilities().len(), 1);
        assert!(caps.is_network_blocked());
        assert_eq!(caps.allowed_commands(), &["allowed_cmd"]);
        assert_eq!(caps.blocked_commands(), &["blocked_cmd"]);
    }

    #[test]
    fn test_capability_set_deduplicate() {
        let dir = tempdir().unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).unwrap());
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).unwrap());

        assert_eq!(caps.fs_capabilities().len(), 2);
        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        // Should keep ReadWrite (higher access)
        assert_eq!(caps.fs_capabilities()[0].access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_deduplicate_user_wins_over_system() {
        // User says --read /path, system says ReadWrite for same path.
        // User intent must win: surviving entry should be Read.
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
    }

    #[test]
    fn test_deduplicate_user_wins_over_system_reverse_order() {
        // Same as above but system entry added first.
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
    }

    #[test]
    fn test_deduplicate_merges_read_and_write_to_readwrite() {
        // Two system/group entries for the same path with Read and Write
        // should merge to ReadWrite (e.g., /dev from system_read + system_write).
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_deduplicate_merges_write_then_read_to_readwrite() {
        // Same merge but with Write added first, Read second.
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_deduplicate_preserves_symlink_original() {
        // User adds --read /tmp (original: /tmp, resolved: /private/tmp, Read)
        // System adds /private/tmp (original: /private/tmp, resolved: /private/tmp, ReadWrite)
        // User wins: surviving entry should be Read with symlink original preserved
        let symlink_path = PathBuf::from("/symlink/path");
        let real_path = PathBuf::from("/real/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: real_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        // User wins with Read access
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
        // Symlink original preserved
        assert_eq!(surviving.original, symlink_path);
        assert_eq!(surviving.resolved, real_path);
    }

    #[test]
    fn test_deduplicate_preserves_symlink_original_keep_existing() {
        // System entry first (original == resolved),
        // User entry second via symlink — User wins and inherits symlink
        let symlink_path = PathBuf::from("/symlink/path");
        let real_path = PathBuf::from("/real/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: real_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        // The symlink original must be inherited from the discarded entry
        assert_eq!(surviving.original, symlink_path);
        assert_eq!(surviving.resolved, real_path);
    }

    #[test]
    fn test_deduplicate_user_upgrades_group_read_to_readwrite() {
        // Group sets ~/.npm as Read, user passes --allow ~/.npm (ReadWrite).
        // User intent must win: surviving entry should be ReadWrite with User source.
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        // Group entry first (e.g., from node_runtime security group)
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("node_runtime".to_string()),
        });
        // User entry second (e.g., from --allow CLI flag)
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::ReadWrite);
        assert!(matches!(surviving.source, CapabilitySource::User));
    }

    #[test]
    fn test_deduplicate_user_write_merges_with_group_read() {
        // Group sets a path as Read, user passes --write for same path.
        // Should merge to ReadWrite since User wins and Read+Write=ReadWrite.
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        // Group entry first (e.g., from profile security group)
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("node_runtime".to_string()),
        });
        // User entry second (e.g., from --write CLI flag)
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::User,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        // User wins, and Read+Write should merge to ReadWrite
        assert_eq!(surviving.access, AccessMode::ReadWrite);
        assert!(matches!(surviving.source, CapabilitySource::User));
    }

    #[cfg(unix)]
    #[test]
    fn test_fs_capability_symlink_resolution() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real");
        let symlink = dir.path().join("link");

        fs::create_dir(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink).unwrap();

        let cap = FsCapability::new_dir(&symlink, AccessMode::Read).unwrap();
        // Symlink should be resolved to real path
        assert_eq!(cap.resolved, real_dir.canonicalize().unwrap());
    }

    #[test]
    fn test_extensions_flag() {
        let caps = CapabilitySet::new();
        assert!(!caps.extensions_enabled());

        let caps = caps.enable_extensions();
        assert!(caps.extensions_enabled());
    }

    #[test]
    fn test_extensions_flag_mutable() {
        let mut caps = CapabilitySet::new();
        assert!(!caps.extensions_enabled());

        caps.set_extensions_enabled(true);
        assert!(caps.extensions_enabled());

        caps.set_extensions_enabled(false);
        assert!(!caps.extensions_enabled());
    }

    #[test]
    fn test_platform_rule_validation_valid_deny() {
        let mut caps = CapabilitySet::new();
        assert!(caps.add_platform_rule("(deny file-write-unlink)").is_ok());
        assert!(caps
            .add_platform_rule("(deny file-read-data (subpath \"/secret\"))")
            .is_ok());
    }

    #[test]
    fn test_platform_rule_validation_rejects_malformed() {
        let mut caps = CapabilitySet::new();
        assert!(caps.add_platform_rule("not an s-expression").is_err());
        assert!(caps.add_platform_rule("").is_err());
    }

    #[test]
    fn test_platform_rule_validation_rejects_root_access() {
        let mut caps = CapabilitySet::new();
        assert!(caps
            .add_platform_rule("(allow file-read* (subpath \"/\"))")
            .is_err());
        assert!(caps
            .add_platform_rule("(allow file-write* (subpath \"/\"))")
            .is_err());
        // Specific subpaths should be fine
        assert!(caps
            .add_platform_rule("(allow file-read* (subpath \"/usr\"))")
            .is_ok());
    }

    #[test]
    fn test_platform_rule_validation_rejects_whitespace_bypass() {
        let mut caps = CapabilitySet::new();
        // Tab-separated
        assert!(caps
            .add_platform_rule("(allow\tfile-read*\t(subpath\t\"/\"))")
            .is_err());
        // Extra spaces
        assert!(caps
            .add_platform_rule("(allow  file-read*  (subpath  \"/\"))")
            .is_err());
        // Mixed whitespace
        assert!(caps
            .add_platform_rule("(allow \t file-write* \t (subpath \"/\"))")
            .is_err());
    }

    #[test]
    fn test_platform_rule_validation_rejects_comment_bypass() {
        let mut caps = CapabilitySet::new();
        // Block comment between tokens
        assert!(caps
            .add_platform_rule("(allow file-read* #| comment |# (subpath \"/\"))")
            .is_err());
        // Block comment inside nested expression
        assert!(caps
            .add_platform_rule("(allow #| sneaky |# file-write* (subpath \"/\"))")
            .is_err());
    }

    #[test]
    fn test_platform_rule_validation_rejects_unbalanced_parens() {
        let mut caps = CapabilitySet::new();
        assert!(caps.add_platform_rule("(deny file-read*").is_err());
        assert!(caps.add_platform_rule("(deny file-read*))").is_err());
    }

    #[test]
    fn test_platform_rule_validation_rejects_unterminated_constructs() {
        let mut caps = CapabilitySet::new();
        assert!(caps
            .add_platform_rule("(deny file-read* #| unterminated comment")
            .is_err());
        assert!(caps
            .add_platform_rule("(deny file-read* (subpath \"/usr))")
            .is_err());
    }

    #[test]
    fn test_platform_rule_validation_accepts_gpu_iokit_rules() {
        let mut caps = CapabilitySet::new();
        // Minimal IOKit surface: AGXDeviceUserClient is the only class required
        // for Metal compute on Apple Silicon. IOSurfaceRootUserClient is tried
        // opportunistically but Metal continues without it when denied.
        assert!(caps
            .add_platform_rule(
                "(allow iokit-open \
                    (iokit-user-client-class \
                        \"AGXDeviceUserClient\"))"
            )
            .is_ok());
        assert!(caps
            .add_platform_rule("(allow iokit-get-properties)")
            .is_ok());
        assert_eq!(caps.platform_rules().len(), 2);
    }

    // NetworkMode tests

    #[test]
    fn test_network_mode_default_is_allow_all() {
        let caps = CapabilitySet::new();
        assert_eq!(*caps.network_mode(), NetworkMode::AllowAll);
        assert!(!caps.is_network_blocked());
    }

    #[test]
    fn test_block_network_sets_blocked_mode() {
        let caps = CapabilitySet::new().block_network();
        assert_eq!(*caps.network_mode(), NetworkMode::Blocked);
        assert!(caps.is_network_blocked());
    }

    #[test]
    fn test_proxy_only_mode() {
        let caps = CapabilitySet::new().proxy_only(8080);
        assert_eq!(
            *caps.network_mode(),
            NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![]
            }
        );
        // ProxyOnly counts as blocked for general network access
        assert!(caps.is_network_blocked());
    }

    #[test]
    fn test_proxy_only_with_bind_ports() {
        let caps = CapabilitySet::new().proxy_only_with_bind(8080, vec![18789, 3000]);
        assert_eq!(
            *caps.network_mode(),
            NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![18789, 3000]
            }
        );
        assert!(caps.is_network_blocked());
    }

    #[test]
    fn test_set_network_mode_builder() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::ProxyOnly {
            port: 54321,
            bind_ports: vec![],
        });
        assert_eq!(
            *caps.network_mode(),
            NetworkMode::ProxyOnly {
                port: 54321,
                bind_ports: vec![]
            }
        );
    }

    #[test]
    fn test_set_network_blocked_backward_compat() {
        let mut caps = CapabilitySet::new();
        caps.set_network_blocked(true);
        assert_eq!(*caps.network_mode(), NetworkMode::Blocked);
        assert!(caps.is_network_blocked());

        caps.set_network_blocked(false);
        assert_eq!(*caps.network_mode(), NetworkMode::AllowAll);
        assert!(!caps.is_network_blocked());
    }

    #[test]
    fn test_tcp_connect_ports() {
        let caps = CapabilitySet::new()
            .allow_tcp_connect(443)
            .allow_tcp_connect(8443);
        assert_eq!(caps.tcp_connect_ports(), &[443, 8443]);
    }

    #[test]
    fn test_tcp_bind_ports() {
        let caps = CapabilitySet::new()
            .allow_tcp_bind(8080)
            .allow_tcp_bind(3000);
        assert_eq!(caps.tcp_bind_ports(), &[8080, 3000]);
    }

    #[test]
    fn test_allow_https_convenience() {
        let caps = CapabilitySet::new().allow_https();
        assert_eq!(caps.tcp_connect_ports(), &[443, 8443]);
    }

    #[test]
    fn test_tcp_ports_mutable() {
        let mut caps = CapabilitySet::new();
        caps.add_tcp_connect_port(443);
        caps.add_tcp_bind_port(8080);
        assert_eq!(caps.tcp_connect_ports(), &[443]);
        assert_eq!(caps.tcp_bind_ports(), &[8080]);
    }

    #[test]
    fn test_localhost_port_builder() {
        let caps = CapabilitySet::new()
            .allow_localhost_port(3000)
            .allow_localhost_port(5000);
        assert_eq!(caps.localhost_ports(), &[3000, 5000]);
    }

    #[test]
    fn test_localhost_port_mutable() {
        let mut caps = CapabilitySet::new();
        caps.add_localhost_port(8080);
        caps.add_localhost_port(9090);
        assert_eq!(caps.localhost_ports(), &[8080, 9090]);
    }

    #[test]
    fn test_network_mode_display() {
        assert_eq!(format!("{}", NetworkMode::Blocked), "blocked");
        assert_eq!(format!("{}", NetworkMode::AllowAll), "allowed");
        assert_eq!(
            format!(
                "{}",
                NetworkMode::ProxyOnly {
                    port: 8080,
                    bind_ports: vec![]
                }
            ),
            "proxy-only (localhost:8080)"
        );
        assert_eq!(
            format!(
                "{}",
                NetworkMode::ProxyOnly {
                    port: 8080,
                    bind_ports: vec![18789]
                }
            ),
            "proxy-only (localhost:8080, bind: 18789)"
        );
        assert_eq!(
            format!(
                "{}",
                NetworkMode::ProxyOnly {
                    port: 8080,
                    bind_ports: vec![18789, 3000]
                }
            ),
            "proxy-only (localhost:8080, bind: 18789, 3000)"
        );
    }

    #[test]
    fn test_network_mode_serialization() {
        let mode = NetworkMode::ProxyOnly {
            port: 54321,
            bind_ports: vec![],
        };
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: NetworkMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn test_network_mode_serialization_with_bind_ports() {
        let mode = NetworkMode::ProxyOnly {
            port: 54321,
            bind_ports: vec![18789, 3000],
        };
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: NetworkMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn test_summary_includes_network_mode() {
        let caps = CapabilitySet::new().proxy_only(8080);
        let summary = caps.summary();
        assert!(summary.contains("proxy-only (localhost:8080)"));
    }

    #[test]
    fn test_summary_includes_tcp_ports() {
        let caps = CapabilitySet::new()
            .allow_tcp_connect(443)
            .allow_tcp_bind(8080);
        let summary = caps.summary();
        assert!(summary.contains("tcp connect ports: 443"));
        assert!(summary.contains("tcp bind ports: 8080"));
    }

    #[test]
    fn test_signal_mode_allow_same_sandbox_roundtrip() {
        let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
        assert_eq!(caps.signal_mode(), SignalMode::AllowSameSandbox);
    }

    #[test]
    fn test_process_info_mode_default_is_isolated() {
        let caps = CapabilitySet::new();
        assert_eq!(caps.process_info_mode(), ProcessInfoMode::Isolated);
    }

    #[test]
    fn test_process_info_mode_allow_same_sandbox() {
        let caps = CapabilitySet::new().set_process_info_mode(ProcessInfoMode::AllowSameSandbox);
        assert_eq!(caps.process_info_mode(), ProcessInfoMode::AllowSameSandbox);
    }

    #[test]
    fn test_process_info_mode_allow_all() {
        let caps = CapabilitySet::new().set_process_info_mode(ProcessInfoMode::AllowAll);
        assert_eq!(caps.process_info_mode(), ProcessInfoMode::AllowAll);
    }

    #[test]
    fn test_ipc_mode_default_is_shared_memory_only() {
        let caps = CapabilitySet::new();
        assert_eq!(caps.ipc_mode(), IpcMode::SharedMemoryOnly);
    }

    #[test]
    fn test_ipc_mode_full() {
        let caps = CapabilitySet::new().set_ipc_mode(IpcMode::Full);
        assert_eq!(caps.ipc_mode(), IpcMode::Full);
    }

    #[test]
    fn test_ipc_mode_mutable_setter() {
        let mut caps = CapabilitySet::new();
        assert_eq!(caps.ipc_mode(), IpcMode::SharedMemoryOnly);
        caps.set_ipc_mode_mut(IpcMode::Full);
        assert_eq!(caps.ipc_mode(), IpcMode::Full);
    }

    #[test]
    fn test_access_mode_contains() {
        // ReadWrite subsumes everything
        assert!(AccessMode::ReadWrite.contains(AccessMode::Read));
        assert!(AccessMode::ReadWrite.contains(AccessMode::Write));
        assert!(AccessMode::ReadWrite.contains(AccessMode::ReadWrite));

        // Read only subsumes Read
        assert!(AccessMode::Read.contains(AccessMode::Read));
        assert!(!AccessMode::Read.contains(AccessMode::Write));
        assert!(!AccessMode::Read.contains(AccessMode::ReadWrite));

        // Write only subsumes Write
        assert!(AccessMode::Write.contains(AccessMode::Write));
        assert!(!AccessMode::Write.contains(AccessMode::Read));
        assert!(!AccessMode::Write.contains(AccessMode::ReadWrite));
    }

    #[test]
    fn test_path_covered_basic() {
        let dir = tempdir().unwrap();
        let parent = dir.path();
        let child = parent.join("subdir");
        fs::create_dir(&child).unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(parent, AccessMode::Read).unwrap());

        assert!(caps.path_covered(&child.canonicalize().unwrap()));
    }

    #[test]
    fn test_path_covered_not_matching() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir1.path(), AccessMode::Read).unwrap());

        assert!(!caps.path_covered(&dir2.path().canonicalize().unwrap()));
    }

    #[test]
    fn test_path_covered_with_access_read_parent_does_not_satisfy_readwrite() {
        // Regression: a read-only parent (e.g. /Volumes from system_read_macos)
        // must not suppress a readwrite workdir grant for a child path.
        let dir = tempdir().unwrap();
        let parent = dir.path();
        let child = parent.join("project");
        fs::create_dir(&child).unwrap();
        let child_canonical = child.canonicalize().unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(parent, AccessMode::Read).unwrap());

        // path_covered (access-unaware) says yes
        assert!(caps.path_covered(&child_canonical));
        // path_covered_with_access correctly says no for write/readwrite
        assert!(caps.path_covered_with_access(&child_canonical, AccessMode::Read));
        assert!(!caps.path_covered_with_access(&child_canonical, AccessMode::Write));
        assert!(!caps.path_covered_with_access(&child_canonical, AccessMode::ReadWrite));
    }

    #[test]
    fn test_path_covered_with_access_readwrite_parent_satisfies_all() {
        let dir = tempdir().unwrap();
        let parent = dir.path();
        let child = parent.join("project");
        fs::create_dir(&child).unwrap();
        let child_canonical = child.canonicalize().unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(parent, AccessMode::ReadWrite).unwrap());

        assert!(caps.path_covered_with_access(&child_canonical, AccessMode::Read));
        assert!(caps.path_covered_with_access(&child_canonical, AccessMode::Write));
        assert!(caps.path_covered_with_access(&child_canonical, AccessMode::ReadWrite));
    }

    #[test]
    fn test_path_covered_with_access_file_caps_ignored() {
        // File capabilities should not count as covering a directory path.
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("file.txt");
        fs::write(&file_path, "data").unwrap();
        let file_canonical = file_path.canonicalize().unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file_path, AccessMode::ReadWrite).unwrap());

        assert!(!caps.path_covered_with_access(&file_canonical, AccessMode::Read));
    }

    #[test]
    fn test_remove_exact_file_caps_for_paths_matches_original_and_resolved() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, "secret").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&link, AccessMode::Read).unwrap());
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).unwrap());

        let removed = caps.remove_exact_file_caps_for_paths(&[link.clone(), target.clone()]);

        assert_eq!(removed, 1);
        assert_eq!(caps.fs_capabilities().len(), 1);
        assert!(!caps.fs_capabilities()[0].is_file);
    }

    // --- UnixSocketCapability / UnixSocketMode tests -------------------------

    #[test]
    fn test_unix_socket_mode_permits_bind() {
        assert!(!UnixSocketMode::Connect.permits_bind());
        assert!(UnixSocketMode::ConnectBind.permits_bind());
    }

    #[test]
    fn test_unix_socket_connect_requires_existing_path() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("ghost.sock");

        let result = UnixSocketCapability::new_file(&missing, UnixSocketMode::Connect);
        assert!(
            matches!(result, Err(NonoError::PathNotFound(_))),
            "connect grant on non-existent path must fail: {result:?}"
        );
    }

    #[test]
    fn test_unix_socket_connect_on_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("existing.sock");
        fs::write(&path, b"").unwrap(); // stand-in for a real socket file

        let cap = UnixSocketCapability::new_file(&path, UnixSocketMode::Connect).unwrap();
        assert_eq!(cap.mode, UnixSocketMode::Connect);
        assert!(!cap.is_directory);
        assert!(cap.resolved.is_absolute());
    }

    #[test]
    fn test_unix_socket_connect_bind_allows_nonexistent_path() {
        // The #685 use case: tsx grants `/tmp/tsx-1000/<pid>.pipe` before
        // the process has even started. Path doesn't exist yet; parent does.
        let dir = tempdir().unwrap();
        let missing = dir.path().join("pending.sock");

        let cap = UnixSocketCapability::new_file(&missing, UnixSocketMode::ConnectBind).unwrap();
        assert_eq!(cap.mode, UnixSocketMode::ConnectBind);
        assert!(!cap.is_directory);
        // Resolved path is canonical-parent + final component
        assert_eq!(cap.resolved.file_name().unwrap(), "pending.sock");
        assert!(cap.resolved.parent().unwrap().is_absolute());
    }

    #[test]
    fn test_unix_socket_connect_bind_fails_when_parent_missing() {
        let result = UnixSocketCapability::new_file(
            "/definitely/does/not/exist/12345/x.sock",
            UnixSocketMode::ConnectBind,
        );
        assert!(
            matches!(result, Err(NonoError::PathNotFound(_))),
            "bind grant must fail when parent is missing: {result:?}"
        );
    }

    #[test]
    fn test_unix_socket_file_rejects_directory_path() {
        let dir = tempdir().unwrap();

        let result = UnixSocketCapability::new_file(dir.path(), UnixSocketMode::Connect);
        assert!(
            matches!(result, Err(NonoError::ExpectedFile(_))),
            "new_file must reject a directory path: {result:?}"
        );
    }

    #[test]
    fn test_unix_socket_dir_on_existing_directory() {
        let dir = tempdir().unwrap();

        let cap = UnixSocketCapability::new_dir(dir.path(), UnixSocketMode::Connect).unwrap();
        assert!(cap.is_directory);
        assert!(cap.resolved.is_absolute());
    }

    #[test]
    fn test_unix_socket_dir_rejects_file_path() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("regular.txt");
        fs::write(&file, "not a dir").unwrap();

        let result = UnixSocketCapability::new_dir(&file, UnixSocketMode::Connect);
        assert!(
            matches!(result, Err(NonoError::ExpectedDirectory(_))),
            "new_dir must reject a file path: {result:?}"
        );
    }

    #[test]
    fn test_unix_socket_dir_nonexistent() {
        let result = UnixSocketCapability::new_dir(
            "/nonexistent/dir/for/tests/99999",
            UnixSocketMode::Connect,
        );
        assert!(matches!(result, Err(NonoError::PathNotFound(_))));
    }

    #[test]
    fn test_unix_socket_dir_rejects_filesystem_root() {
        let result = UnixSocketCapability::new_dir("/", UnixSocketMode::Connect);
        assert!(
            matches!(result, Err(NonoError::SandboxInit(_))),
            "filesystem root must be rejected as a directory grant: {result:?}"
        );
    }

    #[test]
    fn test_unix_socket_covers_file_exact_match() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.sock");
        fs::write(&path, b"").unwrap();
        let cap = UnixSocketCapability::new_file(&path, UnixSocketMode::Connect).unwrap();

        // Exact match covers; anything else does not.
        assert!(cap.covers(&cap.resolved));
        assert!(!cap.covers(&dir.path().canonicalize().unwrap()));
        let sibling = dir.path().canonicalize().unwrap().join("b.sock");
        assert!(!cap.covers(&sibling));
    }

    #[test]
    fn test_unix_socket_covers_directory_one_level() {
        let dir = tempdir().unwrap();
        let cap = UnixSocketCapability::new_dir(dir.path(), UnixSocketMode::Connect).unwrap();

        // Direct child is covered.
        let child = cap.resolved.join("x.sock");
        assert!(cap.covers(&child), "direct child should be covered");

        // Grandchild is NOT (non-recursive).
        let grandchild = cap.resolved.join("sub").join("x.sock");
        assert!(!cap.covers(&grandchild), "grandchild must not be covered");

        // The directory itself, with no filename component, isn't a socket.
        assert!(!cap.covers(&cap.resolved));
    }

    #[test]
    fn test_unix_socket_covers_does_not_string_prefix() {
        // Regression: a directory grant for /tmp/foo must NOT cover
        // /tmp/foobar/x.sock, which a naive string starts_with would match.
        let dir = tempdir().unwrap();
        let foo = dir.path().join("foo");
        let foobar = dir.path().join("foobar");
        fs::create_dir(&foo).unwrap();
        fs::create_dir(&foobar).unwrap();

        let cap = UnixSocketCapability::new_dir(&foo, UnixSocketMode::Connect).unwrap();
        let evil = foobar.canonicalize().unwrap().join("x.sock");
        assert!(!cap.covers(&evil), "string-prefix match must not leak");
    }

    #[test]
    fn test_unix_socket_display() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.sock");
        fs::write(&path, b"").unwrap();

        let file_cap = UnixSocketCapability::new_file(&path, UnixSocketMode::Connect).unwrap();
        let rendered = format!("{file_cap}");
        assert!(rendered.contains("connect"));
        assert!(!rendered.starts_with("dir"));

        let dir_cap =
            UnixSocketCapability::new_dir(dir.path(), UnixSocketMode::ConnectBind).unwrap();
        let rendered = format!("{dir_cap}");
        assert!(rendered.contains("connect+bind"));
        assert!(rendered.starts_with("dir "));
    }

    #[test]
    fn test_capability_set_allow_unix_socket_accumulates() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.sock");
        let b = dir.path().join("b.sock");
        fs::write(&a, b"").unwrap();

        let caps = CapabilitySet::new()
            .allow_unix_socket(&a, UnixSocketMode::Connect)
            .unwrap()
            .allow_unix_socket(&b, UnixSocketMode::ConnectBind)
            .unwrap();

        assert_eq!(caps.unix_socket_capabilities().len(), 2);
        assert_eq!(
            caps.unix_socket_capabilities()[0].mode,
            UnixSocketMode::Connect
        );
        assert_eq!(
            caps.unix_socket_capabilities()[1].mode,
            UnixSocketMode::ConnectBind
        );
    }

    #[test]
    fn test_capability_set_unix_socket_allowed_mode_split() {
        // Invariant `separate-read-write`: Connect entries must not
        // accidentally permit bind.
        let dir = tempdir().unwrap();
        let connect_sock = dir.path().join("connect-only.sock");
        let bind_sock = dir.path().join("bind.sock");
        fs::write(&connect_sock, b"").unwrap();
        // bind_sock deliberately does not exist — allow_unix_socket with
        // ConnectBind must accept that.

        let caps = CapabilitySet::new()
            .allow_unix_socket(&connect_sock, UnixSocketMode::Connect)
            .unwrap()
            .allow_unix_socket(&bind_sock, UnixSocketMode::ConnectBind)
            .unwrap();

        let resolved_connect = connect_sock.canonicalize().unwrap();
        let resolved_bind = dir.path().canonicalize().unwrap().join("bind.sock");

        // Connect-only entry: connect ok, bind denied.
        assert!(caps.unix_socket_allowed(&resolved_connect, UnixSocketOp::Connect));
        assert!(!caps.unix_socket_allowed(&resolved_connect, UnixSocketOp::Bind));

        // ConnectBind entry: both ok.
        assert!(caps.unix_socket_allowed(&resolved_bind, UnixSocketOp::Connect));
        assert!(caps.unix_socket_allowed(&resolved_bind, UnixSocketOp::Bind));

        // Unrelated path: nothing allowed.
        let other = dir.path().canonicalize().unwrap().join("other.sock");
        assert!(!caps.unix_socket_allowed(&other, UnixSocketOp::Connect));
        assert!(!caps.unix_socket_allowed(&other, UnixSocketOp::Bind));
    }

    #[test]
    fn test_capability_set_unix_socket_allowed_directory_grant() {
        let dir = tempdir().unwrap();

        let caps = CapabilitySet::new()
            .allow_unix_socket_dir(dir.path(), UnixSocketMode::Connect)
            .unwrap();

        let resolved_dir = dir.path().canonicalize().unwrap();
        let direct_child = resolved_dir.join("x.sock");
        let grandchild = resolved_dir.join("sub").join("x.sock");

        assert!(caps.unix_socket_allowed(&direct_child, UnixSocketOp::Connect));
        assert!(!caps.unix_socket_allowed(&grandchild, UnixSocketOp::Connect));
        assert!(!caps.unix_socket_allowed(&direct_child, UnixSocketOp::Bind));
    }

    #[test]
    fn test_deduplicate_unix_sockets_merges_identical_grants() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("a.sock");
        fs::write(&sock, b"").unwrap();

        let mut caps = CapabilitySet::new()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .unwrap()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .unwrap();
        assert_eq!(caps.unix_socket_capabilities().len(), 2);

        caps.deduplicate();
        assert_eq!(caps.unix_socket_capabilities().len(), 1);
    }

    #[test]
    fn test_deduplicate_unix_sockets_promotes_connect_to_connect_bind() {
        // When Connect and ConnectBind grants collide on the same resolved
        // path, the retained entry ends up as ConnectBind (superset).
        let dir = tempdir().unwrap();
        let sock = dir.path().join("a.sock");
        fs::write(&sock, b"").unwrap();

        let mut caps = CapabilitySet::new()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .unwrap()
            .allow_unix_socket(&sock, UnixSocketMode::ConnectBind)
            .unwrap();

        caps.deduplicate();
        let socks = caps.unix_socket_capabilities();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::ConnectBind);
    }

    #[test]
    fn test_deduplicate_unix_sockets_does_not_widen_user_intent() {
        // Security-critical: a user explicitly narrowing a path to
        // Connect must not be silently upgraded to ConnectBind just
        // because a group/default also covers it.
        let dir = tempdir().unwrap();
        let sock = dir.path().join("a.sock");
        fs::write(&sock, b"").unwrap();

        let group_cap = UnixSocketCapability {
            original: sock.clone(),
            resolved: sock.canonicalize().unwrap(),
            is_directory: false,
            mode: UnixSocketMode::ConnectBind,
            source: CapabilitySource::Group("example_group".to_string()),
        };
        let user_cap = UnixSocketCapability {
            original: sock.clone(),
            resolved: sock.canonicalize().unwrap(),
            is_directory: false,
            mode: UnixSocketMode::Connect,
            source: CapabilitySource::User,
        };

        let mut caps = CapabilitySet::new();
        caps.add_unix_socket(group_cap);
        caps.add_unix_socket(user_cap);
        caps.deduplicate();

        let socks = caps.unix_socket_capabilities();
        assert_eq!(socks.len(), 1);
        assert_eq!(
            socks[0].mode,
            UnixSocketMode::Connect,
            "user-intent Connect must not be upgraded to ConnectBind by dedup"
        );
        assert!(matches!(socks[0].source, CapabilitySource::User));
    }

    #[test]
    fn test_deduplicate_unix_sockets_keeps_file_and_dir_grants_separate() {
        // File grant on /path/foo.sock and dir grant on /path/ are
        // different keys — both should survive.
        let dir = tempdir().unwrap();
        let sock = dir.path().join("a.sock");
        fs::write(&sock, b"").unwrap();

        let mut caps = CapabilitySet::new()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .unwrap()
            .allow_unix_socket_dir(dir.path(), UnixSocketMode::Connect)
            .unwrap();

        caps.deduplicate();
        assert_eq!(caps.unix_socket_capabilities().len(), 2);
    }

    #[test]
    fn test_summary_includes_unix_sockets() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("a.sock");
        fs::write(&sock, b"").unwrap();

        let caps = CapabilitySet::new()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .unwrap()
            .allow_unix_socket_dir(dir.path(), UnixSocketMode::ConnectBind)
            .unwrap();

        let summary = caps.summary();
        assert!(
            summary.contains("Unix sockets:"),
            "summary must include unix socket section: {summary}"
        );
        assert!(summary.contains("connect"));
        assert!(summary.contains("connect+bind"));
        assert!(summary.contains("file"));
        assert!(summary.contains("dir"));
    }
}
