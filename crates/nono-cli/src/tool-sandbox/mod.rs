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

/// Lexically resolve `.`/`..` components in `path` without touching the
/// filesystem.
///
/// Callers compare a policy-resolved path against an already-canonical
/// prefix via `starts_with` to decide whether a grant falls inside a
/// directory (e.g. the command's live cwd). `starts_with` compares path
/// *components*, not resolved locations, so an unnormalized `..` segment
/// (e.g. `cwd.join("../out")`) lexically starts with `cwd` even though it
/// actually resolves outside it. Normalizing first fixes that without
/// requiring the path to exist (unlike `Path::canonicalize`).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn lexically_normalize(path: &std::path::Path) -> std::path::PathBuf {
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(std::path::Component::Normal(_))
                ) {
                    normalized.pop();
                } else {
                    normalized.push(component);
                }
            }
            other => normalized.push(other),
        }
    }
    normalized
}

/// Whether the agent's own filesystem grants admit *writing* `path` directly.
///
/// True when `path` is (or is under) the agent's own `--workdir`
/// (`policy_root`, always writable by the agent), or when the agent holds an
/// explicit write grant covering `path` and no deny path covers it. Used to
/// check each policy write-grant against the agent's actual capabilities
/// individually, rather than a single verdict for the whole live cwd — a
/// grant on a subdirectory the agent can write should stay writable even
/// when the surrounding cwd itself is not agent-writable.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn agent_can_write(
    path: &std::path::Path,
    policy_root: &std::path::Path,
    outer_caps: &nono::CapabilitySet,
    deny_paths: &[std::path::PathBuf],
) -> bool {
    let denied = deny_paths.iter().any(|deny| path.starts_with(deny));
    !denied
        && (path.starts_with(policy_root) || caps_grant(outer_caps, path, nono::AccessMode::Write))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(test)]
mod agent_can_write_tests {
    use super::agent_can_write;
    use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability};
    use std::path::PathBuf;

    fn write_cap(resolved: &str) -> FsCapability {
        FsCapability {
            original: PathBuf::from(resolved),
            resolved: PathBuf::from(resolved),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        }
    }

    #[test]
    fn path_under_workdir_is_writable() {
        let caps = CapabilitySet::new();
        let policy_root = PathBuf::from("/work");

        assert!(agent_can_write(
            &PathBuf::from("/work/sub"),
            &policy_root,
            &caps,
            &[]
        ));
    }

    #[test]
    fn subdirectory_with_explicit_write_grant_is_writable_even_outside_workdir() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(write_cap("/data/repo/cache"));
        let policy_root = PathBuf::from("/work");

        assert!(agent_can_write(
            &PathBuf::from("/data/repo/cache"),
            &policy_root,
            &caps,
            &[]
        ));
    }

    #[test]
    fn path_without_any_grant_is_not_writable() {
        let caps = CapabilitySet::new();
        let policy_root = PathBuf::from("/work");

        assert!(!agent_can_write(
            &PathBuf::from("/data/repo"),
            &policy_root,
            &caps,
            &[]
        ));
    }

    #[test]
    fn denied_path_is_not_writable_even_with_a_grant() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(write_cap("/data/repo"));
        let policy_root = PathBuf::from("/work");
        let deny_paths = vec![PathBuf::from("/data/repo/secret")];

        assert!(!agent_can_write(
            &PathBuf::from("/data/repo/secret"),
            &policy_root,
            &caps,
            &deny_paths
        ));
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(test)]
mod lexically_normalize_tests {
    use super::lexically_normalize;
    use std::path::PathBuf;

    #[test]
    fn parent_dir_walks_back_out_of_prefix() {
        let normalized = lexically_normalize(&PathBuf::from("/work/sub/../out"));

        assert_eq!(normalized, PathBuf::from("/work/out"));
        assert!(!normalized.starts_with("/work/sub"));
    }

    #[test]
    fn cur_dir_is_dropped() {
        let normalized = lexically_normalize(&PathBuf::from("/work/./sub"));

        assert_eq!(normalized, PathBuf::from("/work/sub"));
    }

    #[test]
    fn path_with_no_dot_components_is_unchanged() {
        let normalized = lexically_normalize(&PathBuf::from("/work/sub/dir"));

        assert_eq!(normalized, PathBuf::from("/work/sub/dir"));
    }

    #[test]
    fn parent_dir_past_root_is_kept_literal() {
        let normalized = lexically_normalize(&PathBuf::from("/../escaped"));

        assert_eq!(normalized, PathBuf::from("/../escaped"));
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(test)]
mod admit_command_cwd_tests {
    use super::admit_command_cwd;
    use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability};
    use std::path::PathBuf;

    fn read_cap(resolved: &str) -> FsCapability {
        FsCapability {
            original: PathBuf::from(resolved),
            resolved: PathBuf::from(resolved),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        }
    }

    fn read_write_cap(resolved: &str) -> FsCapability {
        FsCapability {
            original: PathBuf::from(resolved),
            resolved: PathBuf::from(resolved),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        }
    }

    #[test]
    fn cwd_under_workdir_is_admitted_and_writable() {
        let caps = CapabilitySet::new();
        let policy_root = PathBuf::from("/work");
        let cwd = PathBuf::from("/work/sub");

        let writable = admit_command_cwd("cmd", &cwd, &policy_root, &caps, &[])
            .expect("cwd should be admitted");

        assert!(writable);
    }

    #[test]
    fn cwd_in_read_grant_outside_workdir_is_admitted_but_not_writable() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(read_cap("/data"));
        let policy_root = PathBuf::from("/work");
        let cwd = PathBuf::from("/data/repo");

        let writable = admit_command_cwd("cmd", &cwd, &policy_root, &caps, &[])
            .expect("cwd should be admitted");

        assert!(!writable);
    }

    #[test]
    fn cwd_in_read_write_grant_outside_workdir_is_writable() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(read_write_cap("/data"));
        let policy_root = PathBuf::from("/work");
        let cwd = PathBuf::from("/data/repo");

        let writable = admit_command_cwd("cmd", &cwd, &policy_root, &caps, &[])
            .expect("cwd should be admitted");

        assert!(writable);
    }

    #[test]
    fn cwd_outside_all_grants_is_rejected() {
        let caps = CapabilitySet::new();
        let policy_root = PathBuf::from("/work");
        let cwd = PathBuf::from("/etc/secrets");

        let err = admit_command_cwd("cmd", &cwd, &policy_root, &caps, &[])
            .expect_err("cwd should be rejected");

        assert!(matches!(err, nono::NonoError::SandboxInit(_)));
    }

    #[test]
    fn cwd_under_deny_path_inside_broad_allow_grant_is_rejected() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(read_write_cap("/data"));
        let policy_root = PathBuf::from("/work");
        let cwd = PathBuf::from("/data/secret");
        let deny_paths = vec![PathBuf::from("/data/secret")];

        let err = admit_command_cwd("cmd", &cwd, &policy_root, &caps, &deny_paths)
            .expect_err("cwd should be rejected");

        assert!(matches!(err, nono::NonoError::SandboxInit(_)));
    }

    #[test]
    fn cwd_under_workdir_but_also_under_deny_path_is_rejected() {
        let caps = CapabilitySet::new();
        let policy_root = PathBuf::from("/work");
        let cwd = PathBuf::from("/work/secret");
        let deny_paths = vec![PathBuf::from("/work/secret")];

        let err = admit_command_cwd("cmd", &cwd, &policy_root, &caps, &deny_paths)
            .expect_err("cwd should be rejected");

        assert!(matches!(err, nono::NonoError::SandboxInit(_)));
    }
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
