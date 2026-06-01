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

    #[error("CWD access requires --allow-cwd in non-interactive mode")]
    CwdPromptRequired,

    // Sandbox errors
    #[error("Sandbox initialization failed: {0}")]
    SandboxInit(String),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("Command '{command}' is blocked: {reason}")]
    BlockedCommand { command: String, reason: String },

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

    #[error("Session exited before attach could complete")]
    SessionGone,

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

    #[error("Invalid configuration: {reason}")]
    InvalidConfig { reason: String },

    #[error("Package install error: {0}")]
    PackageInstall(String),

    /// User-facing stop where nono needs the user to take an explicit
    /// corrective action before continuing.
    #[error("{0}")]
    ActionRequired(String),

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

    /// User-initiated clean stop. The CLI's main error handler renders
    /// this without the `ERROR` log line and `nono:` prefix — the call
    /// site has already printed whatever the user needs to see. Exit
    /// code is still non-zero (the run did not complete) but the output
    /// reads as an intentional cancellation, not a fault.
    #[error("{0}")]
    Cancelled(String),
}

/// Result type alias for nono operations
pub type Result<T> = std::result::Result<T, NonoError>;
