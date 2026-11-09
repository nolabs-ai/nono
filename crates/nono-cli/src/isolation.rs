//! Opt-in Linux namespace isolation policy (NEP-0004).
//!
//! The mechanism (namespace spec, raw child entry, id maps, bridge validation,
//! probe) lives in `nono::sandbox`. This module owns every policy decision:
//! which network modes and grants isolation can be combined with, how the
//! proxy bridge is wired, and how a host refusal is explained to the user.

use crate::cli::SandboxArgs;
use crate::profile::LinuxIsolateConfig;
use crate::sandbox_prepare::{PreparedSandbox, has_proxy_intent};
use nono::{CapabilitySet, NamespaceProbe, NamespaceProbeStage, NamespaceSpec, NetworkMode};
use nono::{NonoError, Result, Sandbox};

/// Reject configurations that namespace isolation cannot satisfy, before
/// anything is started.
///
/// With `network` isolation the only path out of the namespace is the session
/// proxy. Allow-all networking and every grant of direct reachability would
/// silently stop working, so each is a configuration error instead.
pub(crate) fn validate_config(args: &SandboxArgs, prepared: &PreparedSandbox) -> Result<()> {
    let isolate = prepared.isolate;
    reject_loopback_without_network(isolate).map_err(NonoError::ConfigParse)?;
    if !isolate.network {
        return Ok(());
    }
    let blocked = args.block_net || prepared.profile_network_block;
    if !blocked && !has_proxy_intent(args, prepared) {
        return Err(NonoError::ConfigParse(
            "linux.isolate.network (--isolate net) cannot be combined with unrestricted \
             network access: the isolated namespace has no route out except the nono proxy. \
             Use --block-net, or a proxied network policy (--allow-domain, --network-profile, \
             or credentials)."
                .to_string(),
        ));
    }
    let mut conflicts = direct_grants(&prepared.caps);
    if !prepared.listen_ports.is_empty() || !args.allow_bind.is_empty() {
        conflicts.push("network.listen_port / --listen-port (inbound listeners)");
    }
    if !prepared.no_proxy.is_empty() {
        conflicts.push("network.no_proxy (hosts that bypass the proxy)");
    }
    reject_direct_grants(&conflicts)
}

/// `loopback` lifts TCP enforcement on the grounds that the network namespace
/// confines TCP to its own loopback. Without that namespace it would grant
/// host-loopback reachability, so it is always an error on its own.
fn reject_loopback_without_network(isolate: LinuxIsolateConfig) -> std::result::Result<(), String> {
    if isolate.loopback && !isolate.network {
        return Err(
            "linux.isolate.loopback (--isolate loopback) requires linux.isolate.network \
             (--isolate net): it allows TCP only on the isolated namespace's own loopback, and \
             without that namespace it would reach host localhost services."
                .to_string(),
        );
    }
    Ok(())
}

fn direct_grants(caps: &CapabilitySet) -> Vec<&'static str> {
    let mut conflicts = Vec::new();
    if !caps.localhost_ports().is_empty() || !caps.localhost_port_ranges().is_empty() {
        conflicts.push("network.open_port / --open-port (host localhost ports)");
    }
    if !caps.tcp_connect_ports().is_empty() {
        conflicts.push("network.connect_port / --allow-connect-port (direct outbound TCP)");
    }
    conflicts
}

fn reject_direct_grants(conflicts: &[&str]) -> Result<()> {
    if conflicts.is_empty() {
        return Ok(());
    }
    Err(NonoError::ConfigParse(format!(
        "linux.isolate.network (--isolate net) cannot be combined with direct network \
         access, which cannot reach outside the isolated namespace:\n  - {}\n\
         Remove these grants, or do not use network isolation.",
        conflicts.join("\n  - ")
    )))
}

/// Build the namespace spec for the final capability set, then prove the host
/// can provide it.
///
/// Runs just before launch, once the proxy (if any) has fixed the network
/// mode. It re-checks the network constraints against the final mode rather
/// than trusting the earlier validation, then probes the real operations.
///
/// # Errors
///
/// Returns an error if the final network mode conflicts with isolation, or if
/// the host refuses any requested namespace. Never downgrades.
pub(crate) fn prepare_namespaces(
    isolate: LinuxIsolateConfig,
    caps: &CapabilitySet,
) -> Result<NamespaceSpec> {
    reject_loopback_without_network(isolate).map_err(NonoError::SandboxInit)?;
    let mut spec = NamespaceSpec::new()
        .network(isolate.network)
        .loopback_tcp(isolate.loopback)
        .ipc(isolate.ipc)
        .uts(isolate.uts);
    if isolate.network {
        match caps.network_mode() {
            NetworkMode::AllowAll => {
                return Err(NonoError::SandboxInit(
                    "linux.isolate.network requires a blocked or proxied network, but the \
                     final network mode allows all traffic"
                        .to_string(),
                ));
            }
            NetworkMode::ProxyOnly { bind_ports, .. } if !bind_ports.is_empty() => {
                return Err(NonoError::SandboxInit(
                    "linux.isolate.network cannot be combined with inbound listen ports: \
                     they would be unreachable from the host"
                        .to_string(),
                ));
            }
            NetworkMode::ProxyOnly { port, .. } => spec = spec.loopback_bridge(*port),
            NetworkMode::Blocked => {}
        }
        reject_direct_grants(&direct_grants(caps))
            .map_err(|error| NonoError::SandboxInit(error.to_string()))?;
    }
    spec.validate()?;
    match Sandbox::probe_namespaces(&spec)? {
        NamespaceProbe::Available => Ok(spec),
        NamespaceProbe::Unavailable { stage, errno } => Err(NonoError::SandboxInit(
            explain_refusal(isolate, stage, errno),
        )),
    }
}

/// Explain which layer refused namespace creation and how to fix it.
///
/// The probe decides availability by attempting the operation; sysctls and
/// process status are read here only to explain an observed failure.
fn explain_refusal(isolate: LinuxIsolateConfig, stage: NamespaceProbeStage, errno: i32) -> String {
    let requested = isolate.labels().join(",");
    let step = match stage {
        NamespaceProbeStage::Unshare => "creating the namespaces",
        NamespaceProbeStage::IdMap => "writing the user namespace id maps",
        NamespaceProbeStage::LoopbackUp => "using capabilities inside the new namespace",
        NamespaceProbeStage::BridgeListener => "creating a loopback listener in the new namespace",
        NamespaceProbeStage::Child | _ => "running the namespace probe",
    };
    let error = if errno == 0 {
        String::from("refused")
    } else if errno == nix::libc::ENOSPC {
        // The kernel reports a namespace count limit as ENOSPC, whose strerror
        // ("No space left on device") reads like a disk problem.
        String::from("ENOSPC: namespace limit reached")
    } else {
        std::io::Error::from_raw_os_error(errno).to_string()
    };
    format!(
        "namespace isolation ({requested}) is not available on this host: {step} failed ({error}).\n\
         Cause: {}\n\
         nono does not fall back to running without the requested isolation.",
        likely_cause(stage, errno)
    )
}

fn likely_cause(stage: NamespaceProbeStage, errno: i32) -> String {
    let sysctl = |name: &str| {
        std::fs::read_to_string(format!("/proc/sys/{name}"))
            .ok()
            .map(|value| value.trim().to_string())
    };
    if errno == nix::libc::ENOSPC {
        return namespace_limit_cause(sysctl("user/max_user_namespaces").as_deref());
    }
    if sysctl("kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        return "AppArmor restricts unprivileged user namespaces \
                (kernel.apparmor_restrict_unprivileged_userns = 1, Ubuntu 23.10+). Install an \
                AppArmor profile that grants `userns` to the nono binary; see \
                https://nono.sh/docs/cli/features/namespace-isolation"
            .to_string();
    }
    if sysctl("kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return "unprivileged user namespaces are disabled \
                (kernel.unprivileged_userns_clone = 0)."
            .to_string();
    }
    if sysctl("user/max_user_namespaces").as_deref() == Some("0") {
        return "user namespaces are disabled (user.max_user_namespaces = 0).".to_string();
    }
    let seccomp_filtered = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Seccomp:").map(|v| v.trim() == "2"))
        })
        .unwrap_or(false);
    if seccomp_filtered && stage == NamespaceProbeStage::Unshare {
        return "a seccomp filter on nono itself blocks unshare(2). Container runtimes \
                (Docker, Kubernetes) install one by default. Run namespace isolation outside \
                the container, or provision the namespace externally; see \
                https://nono.sh/docs/cli/features/namespace-isolation"
            .to_string();
    }
    "the kernel or a security module refused the operation; no known restriction was \
     detected."
        .to_string()
}

fn namespace_limit_cause(max_user_namespaces: Option<&str>) -> String {
    match max_user_namespaces {
        Some("0") => "user namespaces are disabled (user.max_user_namespaces = 0).".to_string(),
        Some(limit) => format!(
            "the user namespace limit is reached (user.max_user_namespaces = {limit}). Another \
             process may be holding or leaking namespaces; raise the limit or stop those \
             processes."
        ),
        None => "a namespace count limit is reached (user.max_user_namespaces or a per-type \
                 limit under /proc/sys/user)."
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolate_network() -> LinuxIsolateConfig {
        LinuxIsolateConfig {
            network: true,
            ..Default::default()
        }
    }

    #[test]
    fn allow_all_is_rejected_at_launch() {
        let caps = CapabilitySet::new();
        assert_eq!(caps.network_mode(), &NetworkMode::AllowAll);
        let error = prepare_namespaces(isolate_network(), &caps).expect_err("allow-all");
        assert!(error.to_string().contains("allows all traffic"));
    }

    #[test]
    fn loopback_without_network_is_rejected_at_launch() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        let isolate = LinuxIsolateConfig {
            loopback: true,
            ipc: true,
            ..Default::default()
        };
        let error = prepare_namespaces(isolate, &caps).expect_err("loopback without net");
        assert!(error.to_string().contains("requires linux.isolate.network"));
    }

    #[test]
    fn loopback_is_carried_on_the_spec() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        let isolate = LinuxIsolateConfig {
            network: true,
            loopback: true,
            ..Default::default()
        };
        match prepare_namespaces(isolate, &caps) {
            Ok(spec) => {
                assert!(spec.has_network());
                assert!(spec.loopback_tcp_enabled());
            }
            Err(error) => assert!(error.to_string().contains("not available on this host")),
        }
    }

    #[test]
    fn loopback_does_not_relax_direct_grant_rejection() {
        let mut caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        caps.add_localhost_port(5432);
        let isolate = LinuxIsolateConfig {
            network: true,
            loopback: true,
            ..Default::default()
        };
        let error = prepare_namespaces(isolate, &caps).expect_err("direct grants");
        assert!(error.to_string().contains("open_port"));
    }

    #[test]
    fn listen_ports_are_rejected_at_launch() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::ProxyOnly {
            port: 3128,
            bind_ports: vec![8080],
        });
        let error = prepare_namespaces(isolate_network(), &caps).expect_err("bind ports");
        assert!(error.to_string().contains("inbound listen ports"));
    }

    #[test]
    fn direct_grants_are_rejected_at_launch() {
        let mut caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        caps.add_localhost_port(5432);
        caps.add_tcp_connect_port(22);
        let error = prepare_namespaces(isolate_network(), &caps).expect_err("direct grants");
        let message = error.to_string();
        assert!(message.contains("open_port"), "{message}");
        assert!(message.contains("connect_port"), "{message}");
    }

    #[test]
    fn non_network_isolation_ignores_network_mode() {
        // ipc/uts isolation leaves the network alone, so allow-all is fine;
        // only host support decides the outcome.
        let caps = CapabilitySet::new();
        let isolate = LinuxIsolateConfig {
            ipc: true,
            ..Default::default()
        };
        if let Err(error) = prepare_namespaces(isolate, &caps) {
            assert!(error.to_string().contains("not available on this host"));
        }
    }

    #[test]
    fn proxy_mode_requests_a_bridge_on_the_proxy_port() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::ProxyOnly {
            port: 3128,
            bind_ports: vec![],
        });
        match prepare_namespaces(isolate_network(), &caps) {
            Ok(spec) => assert_eq!(spec.bridge_port(), Some(3128)),
            Err(error) => assert!(error.to_string().contains("not available on this host")),
        }
    }

    #[test]
    fn refusal_names_the_failed_step_and_never_downgrades() {
        let message = explain_refusal(
            isolate_network(),
            NamespaceProbeStage::Unshare,
            nix::libc::EPERM,
        );
        assert!(message.contains("creating the namespaces"));
        assert!(message.contains("does not fall back"));
    }

    #[test]
    fn enospc_refusal_names_the_namespace_limit_not_disk_space() {
        let message = explain_refusal(
            isolate_network(),
            NamespaceProbeStage::Unshare,
            nix::libc::ENOSPC,
        );
        assert!(message.contains("namespace limit reached"), "{message}");
        assert!(!message.contains("No space left on device"), "{message}");
        assert!(message.contains("max_user_namespaces"), "{message}");
    }

    #[test]
    fn namespace_limit_cause_distinguishes_disabled_from_exhausted() {
        assert!(namespace_limit_cause(Some("0")).contains("disabled"));
        let exhausted = namespace_limit_cause(Some("125986"));
        assert!(exhausted.contains("limit is reached"), "{exhausted}");
        assert!(exhausted.contains("125986"), "{exhausted}");
        assert!(namespace_limit_cause(None).contains("limit is reached"));
    }
}
