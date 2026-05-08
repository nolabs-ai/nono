//! nono - Capability-based sandboxing library
//!
//! This library provides OS-level sandboxing using Landlock (Linux) and
//! Seatbelt (macOS) for capability-based filesystem and network isolation.
//!
//! # Overview
//!
//! nono is a pure sandboxing primitive - it provides the mechanism for
//! OS-enforced isolation without imposing any security policy. Clients
//! (CLI tools, language bindings) define their own policies.
//!
//! # Example
//!
//! ```no_run
//! use nono::{CapabilitySet, AccessMode, Sandbox};
//!
//! fn main() -> nono::Result<()> {
//!     // Build capability set - client must add ALL paths, including system paths
//!     let caps = CapabilitySet::new()
//!         // System paths for executables to run
//!         .allow_path("/usr", AccessMode::Read)?
//!         .allow_path("/lib", AccessMode::Read)?
//!         .allow_path("/bin", AccessMode::Read)?
//!         // User paths
//!         .allow_path("/project", AccessMode::ReadWrite)?
//!         .block_network();
//!
//!     // Check platform support
//!     let support = Sandbox::support_info();
//!     if !support.is_supported {
//!         eprintln!("Warning: {}", support.details);
//!     }
//!
//!     // Apply sandbox - this is irreversible
//!     Sandbox::apply(&caps)?;
//!
//!     // Now running sandboxed...
//!     Ok(())
//! }
//! ```
//!
//! # Platform Support
//!
//! - **Linux**: Uses Landlock LSM (kernel 5.13+)
//! - **macOS**: Uses Seatbelt sandbox
//! - **Other platforms**: Returns `UnsupportedPlatform` error

pub mod capability;
pub mod diagnostic;
pub mod error;
pub mod keystore;
pub mod manifest;
pub mod manifest_convert;
pub mod net_filter;
pub mod query;
pub mod sandbox;
pub mod state;
pub mod supervisor;
pub mod trust;
pub mod undo;

// Re-exports for convenience
pub use capability::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, IpcMode, NetworkMode,
    ProcessInfoMode, SignalMode,
};
pub use diagnostic::{
    CommandContext, DenialReason, DenialRecord, DiagnosticFormatter, DiagnosticMode,
    SandboxViolation,
};
pub use error::{NonoError, Result};
pub use keystore::{
    is_apple_password_uri, is_env_uri, is_file_uri, is_keyring_uri, is_op_uri, load_secret_by_ref,
    load_secret_file, load_secrets, redact_apple_password_uri, redact_file_uri, redact_keyring_uri,
    redact_op_uri, store_secret_file, validate_apple_password_uri, validate_destination_env_var,
    validate_env_uri, validate_file_uri, validate_keyring_uri, validate_op_uri, LoadedSecret,
};
pub use net_filter::{FilterResult, HostFilter};
#[cfg(target_os = "windows")]
pub use sandbox::windows::{
    create_low_integrity_primary_token, label_mask_for_access_mode, low_integrity_label_and_mask,
    path_is_owned_by_current_user, try_set_mandatory_label, OwnedHandle,
};
#[cfg(target_os = "linux")]
pub use sandbox::{detect_abi, is_wsl2, DetectedAbi};
pub use sandbox::{PreviewRuntimeStatus, Sandbox, SupportInfo, SupportStatus};
#[cfg(target_os = "windows")]
pub use sandbox::{
    WindowsFilesystemPolicy, WindowsFilesystemRule, WindowsNetworkBackendKind,
    WindowsNetworkLaunchSupport, WindowsNetworkPolicy, WindowsNetworkPolicyMode,
    WindowsPreviewContext, WindowsPreviewEntryPoint, WindowsSupervisorContext,
    WindowsSupervisorFeatureKind, WindowsSupervisorSupport,
};
pub use state::SandboxState;
#[cfg(target_os = "windows")]
pub use supervisor::BrokerTargetProcess;
pub use supervisor::{
    ApprovalBackend, ApprovalDecision, CapabilityRequest, GrantedResourceKind, ResourceGrant,
    ResourceTransferKind, SupervisorSocket, UrlOpenRequest,
};
pub use trust::{
    Enforcement, IncludePatterns, Publisher, SignerIdentity, TrustPolicy, VerificationOutcome,
    VerificationResult,
};
