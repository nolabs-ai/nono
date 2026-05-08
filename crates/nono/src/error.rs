//! Error types for the nono library

use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur in the nono library
#[derive(Error, Debug)]
pub enum NonoError {
    // Path errors
    #[error("Path does not exist: {0}")]
    PathNotFound(PathBuf),

    #[error("Expected a directory but got a file: {0}")]
    ExpectedDirectory(PathBuf),

    #[error("Expected a file but got a directory: {0}")]
    ExpectedFile(PathBuf),

    #[error("Failed to canonicalize path {path}: {source}")]
    PathCanonicalization {
        path: PathBuf,
        source: std::io::Error,
    },

    // Capability errors
    #[error("No filesystem capabilities specified")]
    NoCapabilities,

    #[error("No command specified")]
    NoCommand,

    #[error("CWD access requires --allow-cwd in silent mode")]
    CwdPromptRequired,

    // Sandbox errors
    #[error("Sandbox initialization failed: {0}")]
    SandboxInit(String),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("Command '{command}' is blocked: {reason}")]
    BlockedCommand { command: String, reason: String },

    /// Broker binary (`nono-shell-broker.exe`) not found as sibling of the
    /// running `nono.exe`. Resolved via `std::env::current_exe()` parent +
    /// platform-specific filename (Phase 31 D-07).
    ///
    /// No env-var override surface (D-07): env-poisoning would let an attacker
    /// redirect the broker to a malicious binary.
    #[error("Broker binary not found: {path:?}")]
    BrokerNotFound { path: PathBuf },

    // Landlock errors (Linux only)
    #[cfg(target_os = "linux")]
    #[error("Landlock error: {0}")]
    Landlock(#[from] landlock::RulesetError),

    #[cfg(target_os = "linux")]
    #[error("Landlock path error: {0}")]
    LandlockPath(#[from] landlock::PathFdError),

    // Keystore errors
    #[error("Failed to access system keystore: {0}")]
    KeystoreAccess(String),

    #[error("Secret not found in keystore: {0}")]
    SecretNotFound(String),

    // Configuration errors (CLI-level but useful in library)
    #[error("Configuration parse error: {0}")]
    ConfigParse(String),

    #[error("Failed to write config to {path}: {source}")]
    ConfigWrite {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Profile read error at {path}: {source}")]
    ProfileRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Profile parse error: {0}")]
    ProfileParse(String),

    #[error("Profile inheritance error: {0}")]
    ProfileInheritance(String),

    #[error("Home directory not found")]
    HomeNotFound,

    #[error("Setup error: {0}")]
    Setup(String),

    #[error("Learn mode error: {0}")]
    LearnError(String),

    #[error("Hook installation error: {0}")]
    HookInstall(String),

    #[error("Environment variable '{var}' validation failed: {reason}")]
    EnvVarValidation { var: String, reason: String },

    #[error("Capability state file validation failed: {reason}")]
    CapFileValidation { reason: String },

    #[error("Capability state file too large: {size} bytes (max: {max} bytes)")]
    CapFileTooLarge { size: u64, max: u64 },

    // Configuration read errors
    #[error("Failed to read config at {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        source: std::io::Error,
    },

    // Version tracking errors
    #[error("Version downgrade detected for {config}: {current} -> {attempted}")]
    VersionDowngrade {
        config: String,
        current: u64,
        attempted: u64,
    },

    // Command execution errors
    #[error("Command execution failed: {0}")]
    CommandExecution(#[source] std::io::Error),

    // Undo/snapshot errors
    #[error("Object store error: {0}")]
    ObjectStore(String),

    #[error("Snapshot error: {0}")]
    Snapshot(String),

    #[error("Hash integrity mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session already has an active attached client")]
    AttachBusy,

    /// Failed to apply (or revert) a Windows mandatory integrity label on a path.
    ///
    /// Fail-closed: any `SetNamedSecurityInfoW` non-zero return surfaces here.
    /// The `hint` field carries a human-actionable diagnostic string (e.g.
    /// "Ensure the target file is writable by the current user and is on NTFS
    /// (not ReFS or a network share).") that callers can show to end users.
    #[error("Failed to apply integrity label to {path}: {hint} (HRESULT: 0x{hresult:08X})")]
    LabelApplyFailed {
        /// The exact path that failed.
        path: PathBuf,
        /// The Win32 HRESULT (or raw error code) returned by the OS.
        hresult: u32,
        /// Human-actionable hint for remediation.
        hint: String,
    },

    /// One or more files could not be restored (e.g. locked on Windows).
    ///
    /// Carries the list of successfully applied changes along with per-file
    /// failure details so callers can surface exactly which files are stuck
    /// without claiming full rollback success.
    #[error("Partial rollback: {applied} file(s) restored, {failed} file(s) failed: {summary}")]
    PartialRestore {
        /// Number of files successfully restored.
        applied: usize,
        /// Number of files that could not be restored.
        failed: usize,
        /// Human-readable summary of the first few failures.
        summary: String,
    },

    // Trust/attestation errors
    #[error("Trust verification failed for {path}: {reason}")]
    TrustVerification { path: String, reason: String },

    #[error("Signing failed for {path}: {reason}")]
    TrustSigning { path: String, reason: String },

    #[error("Trust policy error: {0}")]
    TrustPolicy(String),

    #[error("Blocked by trust policy: {path} matches blocklist entry: {reason}")]
    BlocklistBlocked { path: String, reason: String },

    #[error("Instruction file denied: {path}: {reason}")]
    InstructionFileDenied { path: String, reason: String },

    #[error("Package install error: {0}")]
    PackageInstall(String),

    #[error("Package verification failed for {package}: {reason}")]
    PackageVerification { package: String, reason: String },

    #[error("Registry error: {0}")]
    RegistryError(String),

    // Network errors
    #[error("Per-port network filtering not supported on {platform}: {reason}")]
    NetworkFilterUnsupported { platform: String, reason: String },

    // I/O errors
    #[error("I/O error: {0}")]
    Io(std::io::Error),
}

/// Result type alias for nono operations
pub type Result<T> = std::result::Result<T, NonoError>;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn label_apply_failed_display_includes_path_hresult_and_hint() {
        let err = NonoError::LabelApplyFailed {
            path: PathBuf::from(r"C:\Users\test\.gitconfig"),
            hresult: 5,
            hint: "Ensure the target file is writable by the current user.".into(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains(r"C:\Users\test\.gitconfig"),
            "Display missing path: {msg}"
        );
        assert!(
            msg.contains("0x00000005"),
            "Display missing hex HRESULT: {msg}"
        );
        assert!(
            msg.contains("writable by the current user"),
            "Display missing hint: {msg}"
        );
    }

    #[test]
    fn label_apply_failed_is_propagatable_via_result_alias() {
        fn producer() -> Result<()> {
            Err(NonoError::LabelApplyFailed {
                path: PathBuf::from("/tmp/x"),
                hresult: 0xDEADBEEF,
                hint: "test".into(),
            })
        }
        let err = producer().expect_err("must error");
        assert!(matches!(err, NonoError::LabelApplyFailed { .. }));
    }
}

#[cfg(test)]
mod broker_not_found_tests {
    use super::NonoError;
    use std::path::PathBuf;

    /// Phase 31 D-07: BrokerNotFound display surfaces the resolved path so
    /// operators can see exactly which sibling lookup failed.
    #[test]
    fn broker_not_found_displays_path() {
        let err = NonoError::BrokerNotFound {
            path: PathBuf::from("/tmp/missing-broker.exe"),
        };
        let s = err.to_string();
        assert!(
            s.contains("missing-broker.exe"),
            "BrokerNotFound display should include the path; got: {s}"
        );
    }

    /// Phase 31 D-07: BrokerNotFound carries Debug derivation through
    /// `#[derive(Error, Debug)]` on NonoError. Smoke check that
    /// formatting the error via `{err:?}` does not panic.
    #[test]
    fn broker_not_found_is_debug() {
        let err = NonoError::BrokerNotFound {
            path: PathBuf::from("foo.exe"),
        };
        let _ = format!("{err:?}");
    }
}
