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
}

impl AccessMode {
    /// Returns true if `self` provides at least the permissions in `required`.
    ///
    /// ReadWrite contains Read, Write, and ReadWrite.
    /// Read contains only Read. Write contains only Write.
    #[must_use]
    pub fn contains(self, required: AccessMode) -> bool {
        match self {
            AccessMode::ReadWrite => true,
            AccessMode::Read => required == AccessMode::Read,
            AccessMode::Write => required == AccessMode::Write,
        }
    }
}

impl std::fmt::Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessMode::Read => write!(f, "read"),
            AccessMode::Write => write!(f, "write"),
            AccessMode::ReadWrite => write!(f, "read+write"),
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
/// Controls whether the sandboxed process can use IPC primitives beyond
/// shared memory. Shared memory (`shm_open`) is always allowed; this mode gates
/// semaphore operations needed by multiprocessing runtimes (e.g., Python
/// `multiprocessing`, Ruby `parallel`) and Linux abstract UNIX socket access.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcMode {
    /// POSIX shared memory only (default). Semaphore operations are denied.
    ///
    /// On macOS: only `ipc-posix-shm-*` rules emitted. `sem_open()` etc.
    /// are blocked by the `(deny default)` baseline.
    ///
    /// On Linux: requests Landlock V6 abstract UNIX socket scoping when
    /// available. Older kernels cannot enforce this and continue without it.
    #[default]
    SharedMemoryOnly,
    /// Full POSIX IPC: shared memory + semaphores.
    ///
    /// On macOS: adds `ipc-posix-sem-*` rules to the Seatbelt profile.
    /// Required for Python `multiprocessing`, Node `worker_threads` with
    /// shared memory, and similar multiprocess coordination.
    ///
    /// On Linux: does not request abstract UNIX socket scoping, preserving
    /// compatibility with runtimes that use external abstract socket IPC.
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
    /// Grant the sandboxed process access to GPU devices.
    ///
    /// Cross-platform upstream parity port (upstream v0.31–0.34, D-12 + D-13):
    ///
    /// - **Linux (Landlock):** adds an allowlist for NVIDIA compute device
    ///   nodes (`/dev/nvidia*`, `/dev/nvidiactl`, `/dev/nvidia-uvm`,
    ///   `/dev/nvidia-uvm-tools`, `/dev/nvidia-caps`), DRM render nodes
    ///   (`/dev/dri/renderD*`), AMD KFD (`/dev/kfd`), and NVIDIA procfs
    ///   (`/proc/driver/nvidia`, `/proc/driver/nvidia-uvm`) required for
    ///   CUDA initialisation under driver 570+. Gated by
    ///   `cfg(target_os = "linux")` at the sandbox backend.
    /// - **macOS (Seatbelt):** emits IOKit rules for Metal/AGX GPU user
    ///   clients (`IOGPU`, `AGXDeviceUserClient`, `AGXSharedUserClient`,
    ///   `IOSurfaceRootUserClient`) and `iokit-get-properties`.
    /// - **Windows (WFP + Job Object):** accepted but not enforced. The
    ///   CLI layer (`crates/nono-cli/src/cli.rs`) emits a `tracing::warn!`
    ///   at flag-parse time. The sandbox backend is a no-op on Windows —
    ///   `sandbox/windows.rs` never reads this field (D-21 invariant).
    gpu: bool,
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

    /// Grant GPU access to the sandboxed process (builder pattern).
    ///
    /// Upstream parity port D-12 (v0.31–0.33) + D-13 (v0.34):
    ///
    /// - **Linux (Landlock):** allowlists NVIDIA device nodes, NVIDIA
    ///   procfs entries, DRM render nodes, and AMD KFD.
    /// - **macOS (Seatbelt):** emits IOKit Metal/AGX GPU user-client rules.
    /// - **Windows:** accepted but not enforced (D-21 invariant — the CLI
    ///   layer emits a `tracing::warn!`; the sandbox backend is a no-op).
    ///
    /// Default is `false`. Granted only when the caller (typically the
    /// `--allow-gpu` CLI flag) explicitly opts in.
    #[must_use]
    pub fn allow_gpu(mut self) -> Self {
        self.gpu = true;
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

    /// Enable or disable GPU access (mutable).
    ///
    /// See [`CapabilitySet::allow_gpu`] for the per-platform semantics.
    pub fn set_gpu(&mut self, enabled: bool) {
        self.gpu = enabled;
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

    /// Check whether GPU access is granted.
    ///
    /// Inspected by the Linux Landlock backend (emits NVIDIA + DRM + AMD
    /// device-node rules) and the macOS Seatbelt backend (emits IOKit
    /// Metal/AGX rules). Windows backend ignores this field by design —
    /// the `--allow-gpu` warning is emitted at the CLI layer (D-21).
    #[must_use]
    pub fn gpu(&self) -> bool {
        self.gpu
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

    /// Deduplicate filesystem capabilities in-place.
    ///
    /// The dedup key is **platform-specific** because the two sandbox
    /// backends enforce path rules differently:
    ///
    /// - **macOS (Seatbelt)** — key is `(original, is_file)`.  Seatbelt
    ///   matches rules against the *literal* path the process presents to
    ///   the kernel, before symlink resolution.  Two distinct symlinks that
    ///   resolve to the same canonical target therefore each need their own
    ///   allow rule and must not be collapsed.  Non-symlink entries are
    ///   unaffected because their `original` equals their `resolved`.
    ///
    /// - **Non-macOS (Landlock / Linux)** — key is `(resolved, is_file)`.
    ///   Landlock rules are inode-based and the kernel unions all rules for
    ///   the same inode.  If two symlinks to the same target survived with
    ///   different access levels (e.g. User/Read and System/ReadWrite),
    ///   Landlock would silently widen to ReadWrite, bypassing user intent.
    ///   Keying on `resolved` ensures user-intent policy is enforced.  When
    ///   a symlink entry is discarded its `original` is copied into the
    ///   surviving entry so that logging and struct consumers stay accurate.
    ///
    /// Priority rules (both platforms):
    /// 1. **User/Profile source beats System/Group** regardless of access level.
    /// 2. **Same-source collisions** keep the highest access
    ///    (`ReadWrite > Read | Write`); complementary modes merge
    ///    (`Read + Write → ReadWrite`).
    pub fn deduplicate(&mut self) {
        use std::collections::HashMap;

        // Dedup key strategy differs by platform because the two sandboxes
        // enforce path rules in fundamentally different ways:
        //
        // macOS / Seatbelt — key on (original, is_file)
        //   Seatbelt evaluates rules against the *literal* path the process
        //   presents to the kernel, before symlink resolution.  Two distinct
        //   symlinks that point to the same canonical target therefore each
        //   need their own allow rule.  Example:
        //     ~/.local/state/nix/profiles  (symlink → /nix/var/…)
        //     ~/.local/state/nix/profile   (symlink → …/profiles)
        //   Both resolve to the same canonical path.  If we keyed on `resolved`
        //   the second entry would be silently discarded, and Seatbelt would
        //   deny any access made through that literal path.
        //   Non-symlink entries (original == resolved) are unaffected.
        //
        // Linux / Landlock — key on (resolved, is_file)  [original behaviour]
        //   Landlock rules are attached to inodes (resolved paths).  If we
        //   kept two entries for the same resolved path but with different
        //   access levels (e.g. User/Read via symlink-A and System/ReadWrite
        //   via symlink-B), Landlock would union the two rules to ReadWrite,
        //   silently bypassing the user-intent Read restriction.  Keying on
        //   `resolved` ensures the user-intent policy (User/Read beats
        //   System/ReadWrite for the same inode) is correctly enforced.
        let mut seen: HashMap<(PathBuf, bool), usize> = HashMap::new();
        let mut to_remove = Vec::new();
        // Deferred updates: (target_index, new_original) to apply after iteration.
        // Only used on Linux, where we dedup by `resolved`: when merging
        // duplicates for the same resolved path, we may still carry over a
        // symlink-based `original` for diagnostics, logging, and struct semantics.
        #[cfg(target_os = "linux")]
        let mut original_updates: Vec<(usize, PathBuf)> = Vec::new();
        // Deferred access upgrades: (target_index, new_access) for Read+Write merges
        let mut access_upgrades: Vec<(usize, AccessMode)> = Vec::new();

        for (i, cap) in self.fs.iter().enumerate() {
            // Platform-specific dedup key (see comment above).
            #[cfg(target_os = "macos")]
            let key = (cap.original.clone(), cap.is_file);
            #[cfg(target_os = "linux")]
            let key = (cap.resolved.clone(), cap.is_file);
            // Windows: key on `resolved` to match the conservative
            // Linux/Landlock behavior. Windows does not have macOS Seatbelt's
            // literal-path evaluation quirk (Seatbelt evaluates paths
            // pre-resolution, so two symlinks to the same target need
            // separate rules); Windows path enforcement (WFP for network,
            // Job Objects + path validation for filesystem) acts on the
            // canonical/resolved path. Keying on `resolved` also prevents
            // user-intent rules from being silently widened by a
            // system-source rule with the same target.
            //
            // Fork divergence (Plan 34-04 cluster commit 16, dbc10da8):
            // upstream's commit leaves Windows uncovered. The fork's
            // dunce-based canonicalization (Phase 25 G-25-PARITY-01
            // pattern) operates on `resolved`, so the Linux-style key is
            // the correct choice. Do not remove without security review.
            #[cfg(target_os = "windows")]
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

                // Merge complementary access modes (Read + Write = ReadWrite).
                // When two entries from the same source category have different
                // non-ReadWrite modes, upgrade the kept entry to ReadWrite.
                let merged_access = match (existing.access, cap.access) {
                    (AccessMode::Read, AccessMode::Write)
                    | (AccessMode::Write, AccessMode::Read) => Some(AccessMode::ReadWrite),
                    _ => None,
                };

                if keep_new {
                    to_remove.push(existing_idx);
                    seen.insert(key, i);
                    // On Linux: preserve symlink original from the removed
                    // entry into the kept entry so `original` stays meaningful.
                    #[cfg(target_os = "linux")]
                    if cap.original == cap.resolved && existing.original != existing.resolved {
                        original_updates.push((i, existing.original.clone()));
                    }
                    // Apply merged access to the new (kept) entry
                    if let Some(access) = merged_access {
                        access_upgrades.push((i, access));
                    }
                } else {
                    // On Linux: inherit symlink original from the entry
                    // being discarded into the surviving entry.
                    #[cfg(target_os = "linux")]
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

        // Apply deferred symlink original updates (Linux only)
        #[cfg(target_os = "linux")]
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
    fn test_deduplicate_symlink_and_direct_are_kept_separately() {
        // macOS only: Seatbelt enforces on literal (pre-resolution) paths.
        // A symlink entry (original=/symlink/path → resolved=/real/path) and a
        // direct entry (original=/real/path, resolved=/real/path) have different
        // original paths.  Dedup keys on `original` on macOS, so both entries
        // survive and each gets its own Seatbelt allow rule.
        #[cfg(target_os = "macos")]
        {
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
            // Both entries survive because they have different original paths.
            assert_eq!(caps.fs_capabilities().len(), 2);
            let originals: Vec<&PathBuf> =
                caps.fs_capabilities().iter().map(|c| &c.original).collect();
            assert!(originals.contains(&&symlink_path));
            assert!(originals.contains(&&real_path));
        }

        // Linux: dedup keys on `resolved`, so a symlink entry and its direct
        // counterpart collapse to one entry.  User-intent wins.
        #[cfg(target_os = "linux")]
        {
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
            // Collapsed to one entry; User/Read beats System/ReadWrite.
            assert_eq!(caps.fs_capabilities().len(), 1);
            let surviving = &caps.fs_capabilities()[0];
            assert_eq!(surviving.access, AccessMode::Read);
            assert!(matches!(surviving.source, CapabilitySource::User));
            // Symlink original preserved into the surviving entry.
            assert_eq!(surviving.original, symlink_path);
            assert_eq!(surviving.resolved, real_path);
        }
    }

    /// macOS only: the concrete bug that prompted this fix.
    /// Two distinct symlinks resolving to the same canonical path
    /// (e.g. ~/.local/state/nix/profile and ~/.local/state/nix/profiles
    /// both pointing into the nix store) must each survive dedup so that
    /// Seatbelt emits allow rules for both literal symlink paths.
    ///
    /// On Linux the Landlock sandbox uses resolved paths; having both
    /// entries would union the Landlock rules, which is harmless when both
    /// have the same access level but could bypass a user-intent restriction
    /// if they differed.  The resolved-path key already prevents that.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_deduplicate_two_symlinks_same_target_both_kept() {
        {
            let link1 = PathBuf::from("/Users/me/.local/state/nix/profiles");
            let link2 = PathBuf::from("/Users/me/.local/state/nix/profile");
            let real_path = PathBuf::from("/nix/var/nix/profiles/per-user/me/profile");

            let mut caps = CapabilitySet::new();
            caps.add_fs(FsCapability {
                original: link1.clone(),
                resolved: real_path.clone(),
                access: AccessMode::Read,
                is_file: false,
                source: CapabilitySource::User,
            });
            caps.add_fs(FsCapability {
                original: link2.clone(),
                resolved: real_path.clone(),
                access: AccessMode::Read,
                is_file: false,
                source: CapabilitySource::User,
            });

            caps.deduplicate();
            assert_eq!(
                caps.fs_capabilities().len(),
                2,
                "both symlink entries must survive"
            );
            let originals: Vec<&PathBuf> =
                caps.fs_capabilities().iter().map(|c| &c.original).collect();
            assert!(originals.contains(&&link1), "link1 (profiles) must be kept");
            assert!(originals.contains(&&link2), "link2 (profile) must be kept");
        }
    }

    /// Linux-only: when a direct-path entry (original == resolved) survives
    /// dedup over a discarded symlink entry, the surviving entry should adopt
    /// the symlink's original so that `original` stays meaningful for logging
    /// and any future consumers.
    ///
    /// Exercises the `original_updates` branch:
    ///   `existing.original == existing.resolved && cap.original != cap.resolved`
    /// (keep_new = false path — existing wins, discarded entry is the symlink).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_deduplicate_linux_surviving_direct_entry_inherits_symlink_original() {
        let symlink_path = PathBuf::from("/symlink/path");
        let real_path = PathBuf::from("/real/path");

        let mut caps = CapabilitySet::new();
        // Direct entry added first — becomes `existing` in the dedup loop.
        // User source so it wins over the incoming System entry.
        caps.add_fs(FsCapability {
            original: real_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        // Symlink entry added second — same resolved path, System source.
        // keep_new = false: User direct entry survives, symlink entry is discarded.
        caps.add_fs(FsCapability {
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        // User wins with its access level.
        assert_eq!(surviving.access, AccessMode::ReadWrite);
        assert!(matches!(surviving.source, CapabilitySource::User));
        // The surviving entry must have adopted the discarded symlink's original.
        assert_eq!(
            surviving.original, symlink_path,
            "surviving direct entry must inherit the discarded symlink's original"
        );
        assert_eq!(surviving.resolved, real_path);
    }

    /// Linux-only: mirror of the above but with insertion order reversed —
    /// the symlink entry is `existing` and is discarded in favour of the
    /// incoming direct User entry.  Exercises the `original_updates` branch:
    ///   `cap.original == cap.resolved && existing.original != existing.resolved`
    /// (keep_new = true path — new direct entry wins, discarded entry is the symlink).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_deduplicate_linux_incoming_direct_entry_inherits_symlink_original_from_existing() {
        let symlink_path = PathBuf::from("/symlink/path");
        let real_path = PathBuf::from("/real/path");

        let mut caps = CapabilitySet::new();
        // Symlink entry added first — becomes `existing` in the dedup loop.
        // System source so it loses to the incoming User entry.
        caps.add_fs(FsCapability {
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        // Direct entry added second — same resolved path, User source.
        // keep_new = true: User direct entry survives, symlink entry is discarded.
        caps.add_fs(FsCapability {
            original: real_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        // User wins with its access level.
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
        // The surviving entry must have adopted the discarded symlink's original.
        assert_eq!(
            surviving.original, symlink_path,
            "surviving direct entry must inherit the discarded symlink's original"
        );
        assert_eq!(surviving.resolved, real_path);
    }

    #[test]
    fn test_deduplicate_identical_symlink_entries_collapsed() {
        // Two entries with the *same* original symlink path are true duplicates
        // and should still be collapsed to one.
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
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        // User wins: Read is kept, not the system's ReadWrite
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
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

    /// Linux-only: verify that two different symlinks pointing to the same
    /// resolved path with different access levels are collapsed to one entry
    /// so that the user-intent Read restriction is not bypassed by a system
    /// ReadWrite rule for the same inode.
    ///
    /// On macOS both entries would survive (Seatbelt needs literal-path rules
    /// for each symlink), but on Linux Landlock unions all rules for the same
    /// resolved path, so we must dedup by `resolved` to uphold the policy.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_deduplicate_linux_two_symlinks_same_resolved_user_intent_wins() {
        let link1 = PathBuf::from("/link1");
        let link2 = PathBuf::from("/link2");
        let real_path = PathBuf::from("/real");

        let mut caps = CapabilitySet::new();
        // User grants Read via one symlink
        caps.add_fs(FsCapability {
            original: link1.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        // System grants ReadWrite via a different symlink to the same target
        caps.add_fs(FsCapability {
            original: link2.clone(),
            resolved: real_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        // Must collapse to one entry so Landlock only sees one rule (Read).
        // If both survived, Landlock would union them to ReadWrite, bypassing
        // the user-intent Read restriction.
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(
            surviving.access,
            AccessMode::Read,
            "user-intent Read must not be widened to ReadWrite by a system grant"
        );
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

    #[cfg(unix)]
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

    // GPU capability (D-12 upstream parity port).
    //
    // These tests verify the CapabilitySet builder surface only. Per-platform
    // sandbox-backend behavior is exercised in the backend modules'
    // (`sandbox::linux`, `sandbox::macos`) unit tests.

    #[test]
    fn test_gpu_default_is_false() {
        let caps = CapabilitySet::new();
        assert!(
            !caps.gpu(),
            "GPU must be opt-in; default CapabilitySet must not grant GPU access"
        );
    }

    #[test]
    fn test_allow_gpu_builder_sets_flag() {
        let caps = CapabilitySet::new().allow_gpu();
        assert!(caps.gpu());
    }

    #[test]
    fn test_set_gpu_toggles_flag() {
        let mut caps = CapabilitySet::new();
        assert!(!caps.gpu());
        caps.set_gpu(true);
        assert!(caps.gpu());
        caps.set_gpu(false);
        assert!(!caps.gpu());
    }

    #[test]
    fn test_allow_gpu_does_not_affect_other_capabilities() {
        // T-20-04-01 mitigation: turning on GPU must not silently broaden
        // any other sandbox dimension (network, signals, commands, etc.).
        let baseline = CapabilitySet::new();
        let with_gpu = CapabilitySet::new().allow_gpu();

        assert_eq!(baseline.network_mode(), with_gpu.network_mode());
        assert_eq!(baseline.signal_mode(), with_gpu.signal_mode());
        assert_eq!(baseline.process_info_mode(), with_gpu.process_info_mode());
        assert_eq!(baseline.ipc_mode(), with_gpu.ipc_mode());
        assert_eq!(baseline.is_network_blocked(), with_gpu.is_network_blocked());
        assert_eq!(
            baseline.fs_capabilities().len(),
            with_gpu.fs_capabilities().len()
        );
        assert_eq!(baseline.allowed_commands(), with_gpu.allowed_commands());
        assert_eq!(baseline.blocked_commands(), with_gpu.blocked_commands());
        assert_eq!(baseline.extensions_enabled(), with_gpu.extensions_enabled());
        assert_eq!(
            baseline.seatbelt_debug_deny(),
            with_gpu.seatbelt_debug_deny()
        );
    }
}
