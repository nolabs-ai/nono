//! Restrictions applied only after a verified enforced assignment.
use super::{PolicySession, inputs::InputSource};
use crate::cli::{
    Commands, PlatformCommands, ProfileCommands, SandboxArgs, TenantCommands, TrustCommands,
};
use crate::command_policy::{ApprovalBackendAuth, ApprovalBackendConfig, ApprovalBackendType};
use crate::platform_client::{self, PlatformState};
use nono::{NonoError, Result};
use std::collections::BTreeMap;

pub(crate) fn active(args: &SandboxArgs) -> bool {
    args.policy_session
        .as_ref()
        .is_some_and(|session| session.management_mode == "enforced")
}

pub(crate) struct PlatformApprovalRequired;

impl nono::ApprovalBackend for PlatformApprovalRequired {
    fn request_approval(&self, _: &nono::ApprovalRequest) -> Result<nono::ApprovalDecision> {
        Ok(nono::ApprovalDecision::Denied {
            reason: "enforced platform policy: no platform approval backend is configured; local approvals are not permitted".into(),
        })
    }

    fn backend_name(&self) -> &str {
        "platform-required"
    }
}

fn denied(reason: impl std::fmt::Display) -> NonoError {
    NonoError::ActionRequired(format!("enforced platform policy: {reason}"))
}

fn allowed_option(name: &str) -> bool {
    matches!(
        name,
        "block-net"
            | "deny-domain"
            | "block-command"
            | "memory"
            | "max-processes"
            | "isolate"
            | "strict-broker-path"
            | "workdir"
            | "record"
            | "record-required"
            | "deliver-to"
            | "audit-integrity"
            | "shell"
    )
}

pub(super) fn validate_inputs(args: &SandboxArgs) -> Result<()> {
    for variable in [
        "NONO_PLATFORM_URL",
        "NONO_TENANT",
        "NONO_ORG",
        "NONO_REGISTRY",
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(denied(format!(
                "environment variable {variable} is not permitted; the enrolled platform and signed bundle select the policy"
            )));
        }
    }
    for (name, source) in &args.policy_inputs {
        if !allowed_option(name) {
            let source = match source {
                InputSource::CommandLine => format!("command-line option --{name}"),
                InputSource::Environment => format!(
                    "environment variable NONO_{} (--{name})",
                    name.replace('-', "_").to_uppercase()
                ),
            };
            return Err(denied(format!(
                "{source} is not permitted; access and policy are managed by the platform"
            )));
        }
    }
    Ok(())
}

fn validate_backends(
    backends: &BTreeMap<String, ApprovalBackendConfig>,
    state: &PlatformState,
) -> Result<()> {
    let endpoint = platform_client::endpoint_url(
        &state.platform_url,
        crate::approval_runtime::PLATFORM_APPROVALS_PATH,
    )?;
    for (name, backend) in backends {
        if backend.backend_type != ApprovalBackendType::Webhook
            || backend.auth != Some(ApprovalBackendAuth::Platform)
            || backend.url.as_ref().is_some_and(|url| url != &endpoint)
        {
            return Err(denied(format!(
                "approval backend {name:?} must use the enrolled platform (type webhook, auth platform, no alternate URL)"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_profile(
    profile: &crate::profile::Profile,
    state: &PlatformState,
) -> Result<()> {
    validate_backends(&profile.security.approval_backends, state)?;
    validate_backends(&profile.network.approval_backends, state)?;
    if let Some(commands) = &profile.command_policies {
        validate_backends(&commands.approval_backends, state)?;
    }
    if profile.security.capability_elevation.unwrap_or(false)
        && profile.security.approval_backends.is_empty()
    {
        return Err(denied(
            "runtime elevation requires a platform approval backend; local prompts are not permitted",
        ));
    }
    Ok(())
}

pub(crate) fn reject_wrap(session: Option<&PolicySession>) -> Result<()> {
    if session.is_some_and(|session| session.management_mode == "enforced") {
        return Err(denied("wrap has no supervisor; use nono run instead"));
    }
    Ok(())
}

pub(crate) fn validate_resource_limits(
    existing: &nono::ResourceLimits,
    requested: &nono::ResourceLimits,
) -> Result<()> {
    let raised = |old: Option<u64>, new: Option<u64>| {
        old.is_some_and(|limit| new.is_none_or(|value| value > limit))
    };
    if raised(existing.memory_bytes, requested.memory_bytes)
        || raised(existing.max_processes, requested.max_processes)
    {
        return Err(denied("resource flags may only lower the policy's limits"));
    }
    Ok(())
}

pub(crate) fn guard_command(command: &Commands) -> Result<()> {
    let restricted = match command {
        Commands::Profile(args) => matches!(
            args.command,
            ProfileCommands::Init(_) | ProfileCommands::Promote(_)
        ),
        Commands::Trust(args) => !matches!(
            args.command,
            TrustCommands::Verify(_) | TrustCommands::List(_) | TrustCommands::ExportKey(_)
        ),
        Commands::Platform(args) => !matches!(
            &args.command,
            PlatformCommands::Status(_)
                | PlatformCommands::ReEnroll(_)
                | PlatformCommands::Tenant(crate::cli::TenantArgs {
                    command: TenantCommands::List(_),
                    ..
                })
        ),
        Commands::Run(_)
        | Commands::Shell(_)
        | Commands::Wrap(_)
        | Commands::Why(_)
        | Commands::Rollback(_)
        | Commands::Audit(_)
        | Commands::Remote(_)
        | Commands::Ps(_)
        | Commands::Stop(_)
        | Commands::Detach(_)
        | Commands::Attach(_)
        | Commands::Logs(_)
        | Commands::Inspect(_)
        | Commands::Replay(_)
        | Commands::Transcript(_)
        | Commands::Session(_)
        | Commands::Pull(_)
        | Commands::Remove(_)
        | Commands::Update(_)
        | Commands::Search(_)
        | Commands::List(_)
        | Commands::Pin(_)
        | Commands::Unpin(_)
        | Commands::Outdated(_)
        | Commands::OpenUrlHelper(_)
        | Commands::PackUpdateHintHelper(_)
        | Commands::Completions(_) => false,
        _ => true,
    };
    if !restricted {
        return Ok(());
    }
    let Some(state) = platform_client::load_state()? else {
        return Ok(());
    };
    let remembered = platform_client::last_policy_mode(&state)?;
    let enforced = match super::refresh_inner(&state, false) {
        Ok(Some(claims)) => claims.management_mode == "enforced",
        Ok(None) => {
            return Err(denied(
                "a fresh assignment is required before changing local policy or enrollment",
            ));
        }
        Err(error) if error.allows_local_fallback(true, None, remembered.as_deref()) => false,
        Err(error @ super::RefreshFailure::Unauthorized(_)) => return Err(error.error()),
        Err(error) if remembered.as_deref() == Some("enforced") => {
            return Err(denied(format!(
                "this command needs a fresh platform release from enforced mode; {}",
                error.error()
            )));
        }
        Err(error) => return Err(error.error()),
    };
    if enforced {
        return Err(denied(
            "this command is unavailable while the device is enforced; an administrator must change its assignment on the platform first",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreviewed_options_are_never_implicitly_allowed() {
        for name in [
            "future-grant",
            "profile",
            "no-audit",
            "allow",
            "allow-endpoint",
        ] {
            assert!(!allowed_option(name), "{name}");
        }
        for name in [
            "block-net",
            "memory",
            "strict-broker-path",
            "record-required",
        ] {
            assert!(allowed_option(name), "{name}");
        }
    }

    #[test]
    fn resource_limits_may_only_be_tightened() {
        let policy = nono::ResourceLimits {
            memory_bytes: Some(256 * 1024 * 1024),
            max_processes: Some(32),
        };
        let tighter = nono::ResourceLimits {
            memory_bytes: Some(128 * 1024 * 1024),
            max_processes: Some(16),
        };
        assert!(validate_resource_limits(&policy, &tighter).is_ok());
        assert!(validate_resource_limits(&policy, &policy).is_ok());
        assert!(validate_resource_limits(&tighter, &policy).is_err());
        assert!(validate_resource_limits(&policy, &nono::ResourceLimits::default()).is_err());
        assert!(
            validate_resource_limits(
                &policy,
                &nono::ResourceLimits {
                    memory_bytes: policy.memory_bytes,
                    max_processes: Some(33)
                }
            )
            .is_err()
        );
        assert!(validate_resource_limits(&nono::ResourceLimits::default(), &policy).is_ok());
    }
}
