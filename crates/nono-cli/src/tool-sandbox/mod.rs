//! Tool sandbox runtime support.
//!
//! The profile resolver lives in `command_policy`; this module owns the
//! Linux/macOS runtime pieces: private shim materialisation, outer exec gating,
//! shim IPC, caller resolution, and brokered command launch.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) struct PreparedToolSandboxRuntime;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl PreparedToolSandboxRuntime {
    pub(crate) fn emitted_error_response(&self) -> bool {
        false
    }

    pub(crate) fn cleanup_runtime_dir(&self) {}
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn maybe_run_internal_tool_sandbox_entrypoint() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn record_main_start() {}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn log_main_total() {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod audit_context;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod broker_store;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod credentials;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod dynamic_providers;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod env;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod launch;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod policy;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod protocol;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod token_broker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod url_shim;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct ToolSandboxPrepare<'a> {
    pub(crate) config: &'a crate::command_policy::CommandPoliciesConfig,
    pub(crate) audit_context: ToolSandboxAuditContext,
    pub(crate) allowed_commands: &'a [String],
    pub(crate) blocked_commands: &'a [String],
    pub(crate) outer_caps: &'a nono::CapabilitySet,
    pub(crate) policy_root: &'a std::path::Path,
    pub(crate) proxy_credential_env_vars:
        &'a std::collections::BTreeMap<String, Vec<(String, String)>>,
    pub(crate) proxy_trust_bundle_paths: &'a [std::path::PathBuf],
    /// Shared token broker for nonce-at-L7 resolution. When `None` a new
    /// private broker is created for this session.
    pub(crate) shared_broker: Option<crate::tool_sandbox::token_broker::SharedBroker>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use self::audit_context::ToolSandboxAuditContext;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use self::policy::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use self::policy::{InvocationPolicyOutcome, evaluate_invocation_policy};

#[cfg(target_os = "linux")]
#[path = "platform/linux.rs"]
mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::{
    PreparedToolSandboxRuntime, TOOL_SANDBOX_PARENT_MONOTONIC_ENV, log_main_total,
    maybe_run_internal_tool_sandbox_entrypoint, record_main_start,
};

#[cfg(target_os = "macos")]
#[path = "platform/macos.rs"]
mod macos;

#[cfg(target_os = "macos")]
pub(crate) use macos::{
    PreparedToolSandboxRuntime, log_main_total, maybe_run_internal_tool_sandbox_entrypoint,
    record_main_start,
};
