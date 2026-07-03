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
mod credentials;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod dynamic_providers;
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
    /// Resolved filesystem deny paths from the agent's sandbox. A mediated
    /// command's live working directory is rejected if it falls under any of
    /// these, so a command can't be steered into a directory the agent is denied.
    pub(crate) deny_paths: &'a [std::path::PathBuf],
    pub(crate) policy_root: &'a std::path::Path,
    pub(crate) proxy_credential_env_vars:
        &'a std::collections::BTreeMap<String, Vec<(String, String)>>,
    pub(crate) proxy_trust_bundle_paths: &'a [std::path::PathBuf],
    /// Shared token broker for nonce-at-L7 resolution. When `None` a new
    /// private broker is created for this session.
    pub(crate) shared_broker: Option<crate::tool_sandbox::token_broker::SharedBroker>,
}

/// Does `caps` grant `mode` access to `path`, via a directory subtree grant or
/// an exact-file grant?
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn caps_grant(caps: &nono::CapabilitySet, path: &std::path::Path, mode: nono::AccessMode) -> bool {
    caps.fs_capabilities().iter().any(|cap| {
        cap.access.contains(mode)
            && if cap.is_file {
                cap.resolved == path
            } else {
                path.starts_with(&cap.resolved)
            }
    })
}

/// Admit a mediated command's live working directory, returning whether the
/// agent can also *write* it.
///
/// A command may only run where the launching agent itself is granted access —
/// inside the agent's effective read region (allow − deny). The agent always
/// owns its `--workdir` (`policy_root`); any other `cwd` must be within the
/// agent's read grants and not under any deny path (the agent's broad allow can
/// otherwise cover a denied subtree). This keeps the live-cwd resolution of
/// `.`/`@git:*` from ever handing a command filesystem reach the agent lacks —
/// e.g. steering a network-capable command into a credential directory the
/// agent is denied. Errors (rejecting the command) when the cwd is outside the
/// agent's granted filesystem; the returned bool lets callers cap the command's
/// cwd write access at the agent's own (write non-escalation).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn admit_command_cwd(
    command: &str,
    cwd: &std::path::Path,
    policy_root: &std::path::Path,
    outer_caps: &nono::CapabilitySet,
    deny_paths: &[std::path::PathBuf],
) -> nono::Result<bool> {
    let cwd_denied = deny_paths.iter().any(|deny| cwd.starts_with(deny));
    let cwd_under_workdir = cwd.starts_with(policy_root);
    if cwd_denied || (!cwd_under_workdir && !caps_grant(outer_caps, cwd, nono::AccessMode::Read)) {
        return Err(nono::NonoError::SandboxInit(format!(
            "'{command}' was invoked in {}, which is outside the agent's granted filesystem. nono \
             will not run a mediated command in a directory the agent itself cannot access. Grant \
             this directory to the agent's sandbox if it should be usable.",
            cwd.display()
        )));
    }
    Ok(cwd_under_workdir || caps_grant(outer_caps, cwd, nono::AccessMode::Write))
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
