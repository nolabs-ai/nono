//! Opt-in Linux namespace isolation policy (NEP-0004).
//!
//! The mechanism (namespace spec, raw child entry, id maps, bridge validation,
//! mount masks, probe) lives in `nono::sandbox`. This module owns every policy
//! decision: which network modes and grants isolation can be combined with,
//! how the proxy bridge is wired, which host paths are masked, and how a host
//! refusal is explained to the user.

use crate::cli::SandboxArgs;
use crate::profile::LinuxIsolateConfig;
use crate::sandbox_prepare::{PreparedSandbox, has_proxy_intent};
use nono::sandbox::{MountSkipReason, PreparedMountMask};
use nono::{CapabilitySet, NamespaceProbe, NamespaceProbeStage, NamespaceSpec, NetworkMode};
use nono::{MountMask, NonoError, Result, Sandbox};
use std::path::{Path, PathBuf};

/// System IPC endpoints masked by `linux.isolate.mounts`, besides the user's
/// runtime directory and `/tmp`. Pathname `connect(2)` is not governed by
/// Landlock below ABI 9, so these sockets are hidden rather than mediated.
/// Any change to this list is a security change.
///
/// A directory is preferred over the socket inside it where the daemon owns
/// the whole directory: a directory mask also hides sockets created after
/// launch, and is not lost when the daemon recreates its socket. Sockets that
/// live directly in a shared directory (`/run/docker.sock`) can only be masked
/// as files; the session's mount watch terminates the sandbox if the host
/// removes one of those masks.
const DEFAULT_SYSTEM_MASKS: &[&str] = &[
    // D-Bus system bus.
    "/run/dbus",
    // Container and VM managers: each socket grants root-equivalent control.
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/docker",
    "/run/containerd",
    "/run/k3s",
    "/run/crio",
    "/run/podman",
    "/run/libvirt",
    "/var/lib/incus/unix.socket",
    "/var/lib/lxd/unix.socket",
    "/var/snap/lxd/common/lxd/unix.socket",
    // snapd and the systemd system manager's private socket.
    "/run/snapd.socket",
    "/run/systemd/private",
    // Smart cards and hardware tokens (pcscd).
    "/run/pcscd",
];
/// Mode of the tmpfs over the user's runtime directory, matching systemd.
const RUNTIME_DIR_MODE: u32 = 0o700;
/// Mode of the per-session `/tmp`.
const PRIVATE_TMP_MODE: u32 = 0o1777;
/// Mode of the tmpfs over other masked directories.
const SYSTEM_DIR_MODE: u32 = 0o755;
/// Size and inode limits of the tmpfs over the user's runtime directory. A
/// grant of the whole directory makes it writable, so it gets room for
/// sockets and small state files, but not half of RAM.
const RUNTIME_DIR_SIZE: u64 = 16 << 20;
/// Size limit of the tmpfs over other masked directories, which hold only
/// re-bind mount points.
const SYSTEM_DIR_SIZE: u64 = 1 << 20;
/// Inode limit of every non-`/tmp` mask tmpfs: enough for the mount points
/// of every re-bind a plan can hold.
const MASK_INODES: u64 = 16_384;

/// Reject configurations that namespace isolation cannot satisfy, before
/// anything is started.
///
/// With `network` isolation the only path out of the namespace is the session
/// proxy. Allow-all networking and every grant of direct reachability would
/// silently stop working, so each is a configuration error instead.
pub(crate) fn validate_config(args: &SandboxArgs, prepared: &PreparedSandbox) -> Result<()> {
    let isolate = &prepared.isolate;
    reject_loopback_without_network(isolate).map_err(NonoError::ConfigParse)?;
    reject_masks_without_mounts(isolate).map_err(NonoError::ConfigParse)?;
    if isolate.mounts && prepared.capability_elevation {
        return Err(NonoError::ConfigParse(
            "linux.isolate.mounts (--isolate mounts) cannot be combined with capability \
             elevation: approved paths are opened by the supervisor outside the sandbox's \
             mount namespace, so they would bypass the masks and the private /tmp. Grant the \
             paths up front instead."
                .to_string(),
        ));
    }
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
    reject_direct_grants(&conflicts)?;
    reject_command_network_grants(isolate, prepared.command_policies.as_ref())
}

/// Commands with direct grants stay on the host and bypass isolation; proxied ones join it and lose host localhost.
fn reject_command_network_grants(
    isolate: &LinuxIsolateConfig,
    policies: Option<&crate::command_policy::CommandPoliciesConfig>,
) -> Result<()> {
    let networks: Vec<_> = policies
        .into_iter()
        .flat_map(|p| &p.commands)
        .filter_map(|(name, c)| Some((name.as_str(), c.sandbox.as_ref()?.network.as_ref()?)))
        .collect();
    let names = |grants: fn(&crate::command_policy::CommandNetworkConfig) -> bool| {
        networks
            .iter()
            .filter(|(_, n)| grants(n))
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let direct =
        names(|n| n.allow_all || !n.tcp_connect_ports.is_empty() || !n.tcp_bind_ports.is_empty());
    if !direct.is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "linux.isolate.network (--isolate net) cannot be combined with command \
             network.allow_all, network.tcp_connect_ports or network.tcp_bind_ports, because \
             those commands would reach the network directly from the host: {direct}. Use \
             network.allow_domain, or do not use network isolation."
        )));
    }
    let callbacks = names(|n| !n.open_port.is_empty() || !n.open_port_range.is_empty());
    if isolate.loopback || callbacks.is_empty() {
        return Ok(());
    }
    Err(NonoError::ConfigParse(format!(
        "linux.isolate.network (--isolate net) cannot be combined with command \
         network.open_port or network.open_port_range, because mediated commands run in the \
         isolated namespace where host localhost ports are unreachable: {callbacks}. Remove \
         these grants, add linux.isolate.loopback, or do not use network isolation."
    )))
}

/// `loopback` lifts TCP enforcement on the grounds that the network namespace
/// confines TCP to its own loopback. Without that namespace it would grant
/// host-loopback reachability, so it is always an error on its own.
fn reject_loopback_without_network(
    isolate: &LinuxIsolateConfig,
) -> std::result::Result<(), String> {
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

/// `extra_masks` only has meaning inside a mount namespace. Without one it
/// would be a mask the profile believes is applied but is not.
fn reject_masks_without_mounts(isolate: &LinuxIsolateConfig) -> std::result::Result<(), String> {
    if !isolate.extra_masks.is_empty() && !isolate.mounts {
        return Err(
            "linux.isolate.extra_masks requires linux.isolate.mounts (--isolate mounts): \
             masks are applied only inside the isolated mount namespace."
                .to_string(),
        );
    }
    Ok(())
}

/// Build the mount mask plan for the final capability set.
///
/// Masks nono's default host IPC endpoints, the profile's `extra_masks`, and
/// `/tmp` (made private to the session). Every path the capability set grants,
/// including `unix_socket` grants, is re-bound through the masks so explicit
/// grants keep working. A grant of a whole masked directory does not re-bind
/// it; the directory stays masked.
///
/// # Errors
///
/// Returns an error if an extra mask does not expand to an absolute path, or
/// if any path cannot be prepared. Never drops a requested mask silently:
/// only masks whose path does not exist on this host are skipped.
pub(crate) fn prepare_mount_mask(
    isolate: &LinuxIsolateConfig,
    caps: &CapabilitySet,
    workdir: &Path,
) -> Result<PreparedMountMask> {
    let plan = plan_mount_mask(isolate, caps, workdir)?;
    for skipped in plan.skipped() {
        let under_mask = plan
            .masked_paths()
            .any(|mask| skipped.path.starts_with(mask));
        match skipped.reason {
            MountSkipReason::Missing | MountSkipReason::Inaccessible if skipped.is_mask => {
                tracing::debug!(
                    "mount mask {} not applied: path does not exist or is not reachable by this \
                     user",
                    skipped.path.display()
                );
            }
            MountSkipReason::Missing if under_mask => tracing::warn!(
                "granted path {} does not exist, so it cannot be re-bound through the mount mask",
                skipped.path.display()
            ),
            MountSkipReason::ReplacesDirectoryMask => tracing::info!(
                "grant of masked directory {} applies to the session's private copy; host \
                 contents stay masked",
                skipped.path.display()
            ),
            _ => {}
        }
    }
    Ok(plan)
}

/// Build the plan without logging, for `nono why` and the sandbox state. It
/// inspects paths only; nothing is mounted until a child applies it.
pub(crate) fn plan_mount_mask(
    isolate: &LinuxIsolateConfig,
    caps: &CapabilitySet,
    workdir: &Path,
) -> Result<PreparedMountMask> {
    let masks = mask_list(isolate, workdir)?;
    let rebinds: Vec<PathBuf> = caps
        .fs_capabilities()
        .iter()
        .map(|cap| cap.resolved.clone())
        .chain(
            caps.unix_socket_capabilities()
                .iter()
                .map(|cap| cap.resolved.clone()),
        )
        .collect();
    PreparedMountMask::prepare(&masks, &rebinds)
}

/// The masked and re-bound paths of `plan`, as the sandbox state records
/// them and `nono why` reads them.
pub(crate) fn mount_view(plan: &PreparedMountMask) -> (Vec<PathBuf>, Vec<PathBuf>) {
    (
        plan.masked_paths().map(Path::to_path_buf).collect(),
        plan.rebound_paths().map(Path::to_path_buf).collect(),
    )
}

/// The mask that hides `path` in the sandbox, if any: the deepest masked or
/// re-bound path at or above it decides, as the mounts stack.
pub(crate) fn hiding_mask<'a>(plan: &'a PreparedMountMask, path: &Path) -> Option<&'a Path> {
    let depth = |p: &Path| p.components().count();
    let mask = plan
        .masked_paths()
        .filter(|mask| path.starts_with(mask))
        .max_by_key(|mask| depth(mask))?;
    let rebound = plan
        .rebound_paths()
        .filter(|rebind| path.starts_with(rebind))
        .any(|rebind| depth(rebind) > depth(mask));
    (!rebound).then_some(mask)
}

/// Refuse to launch in a working directory the masks hide: it does not exist
/// in the sandbox, and the launch would otherwise fail with a bare EACCES.
pub(crate) fn reject_hidden_workdir(plan: &PreparedMountMask, current_dir: &Path) -> Result<()> {
    match hiding_mask(plan, current_dir) {
        None => Ok(()),
        Some(mask) => Err(NonoError::SandboxInit(format!(
            "the working directory {} is hidden by the linux.isolate.mounts mask over {}. \
             Grant it (--allow-cwd, or workdir access in the profile) so it is re-bound \
             through the mask, or start from a directory outside the mask.",
            current_dir.display(),
            mask.display()
        ))),
    }
}

/// `$XDG_RUNTIME_DIR`, if it names a directory the caller owns. The variable
/// is untrusted: honouring any absolute path would let it replace an
/// arbitrary directory (`/usr`) with an empty tmpfs.
fn trusted_runtime_dir() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let runtime = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    if !runtime.is_absolute() {
        return None;
    }
    let runtime = nono::try_canonicalize(&runtime);
    let metadata = std::fs::symlink_metadata(&runtime).ok()?;
    let owned = metadata.is_dir()
        && metadata.uid() == nix::unistd::getuid().as_raw()
        && runtime.parent().is_some();
    if !owned {
        tracing::debug!(
            "XDG_RUNTIME_DIR {} is not a directory owned by this user; not masking it",
            runtime.display()
        );
    }
    owned.then_some(runtime)
}

/// The full mask list: user runtime directory, private `/tmp`, system IPC
/// endpoints, then the profile's extra masks. Paths are canonicalized so a
/// symlinked location (`/var/run` -> `/run`) masks the real target.
fn mask_list(isolate: &LinuxIsolateConfig, workdir: &Path) -> Result<Vec<MountMask>> {
    let mut masks: Vec<MountMask> = Vec::new();
    let mut push = |path: PathBuf, mask: fn(PathBuf) -> MountMask| {
        let path = nono::try_canonicalize(&path);
        if !masks.iter().any(|existing| existing.path() == path) {
            masks.push(mask(path));
        }
    };
    let runtime_mask = |path| {
        MountMask::new(path)
            .tmpfs_mode(RUNTIME_DIR_MODE)
            .tmpfs_limits(RUNTIME_DIR_SIZE, MASK_INODES)
    };
    let system_mask = |path| {
        MountMask::new(path)
            .tmpfs_mode(SYSTEM_DIR_MODE)
            .tmpfs_limits(SYSTEM_DIR_SIZE, MASK_INODES)
    };
    // The environment is untrusted: mask the standard per-user runtime
    // directory whether or not $XDG_RUNTIME_DIR points at it.
    push(
        PathBuf::from(format!("/run/user/{}", nix::unistd::getuid())),
        runtime_mask,
    );
    if let Some(runtime) = trusted_runtime_dir() {
        push(runtime, runtime_mask);
    }
    // The private /tmp keeps the kernel's default size, like a host tmpfs /tmp.
    push(PathBuf::from("/tmp"), |path| {
        MountMask::new(path).tmpfs_mode(PRIVATE_TMP_MODE)
    });
    for path in DEFAULT_SYSTEM_MASKS {
        push(PathBuf::from(path), system_mask);
    }
    for raw in &isolate.extra_masks {
        let expanded = crate::profile::expand_vars(raw, workdir)?;
        if !expanded.is_absolute() {
            return Err(NonoError::ConfigParse(format!(
                "linux.isolate.extra_masks entry {raw:?} does not expand to an absolute path \
                 ({}); is a variable it uses unset?",
                expanded.display()
            )));
        }
        push(expanded, system_mask);
    }
    Ok(masks)
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
    isolate: &LinuxIsolateConfig,
    caps: &CapabilitySet,
) -> Result<NamespaceSpec> {
    reject_loopback_without_network(isolate).map_err(NonoError::SandboxInit)?;
    reject_masks_without_mounts(isolate).map_err(NonoError::SandboxInit)?;
    let mut spec = NamespaceSpec::new()
        .network(isolate.network)
        .loopback_tcp(isolate.loopback)
        .ipc(isolate.ipc)
        .uts(isolate.uts)
        .mounts(isolate.mounts);
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
fn explain_refusal(isolate: &LinuxIsolateConfig, stage: NamespaceProbeStage, errno: i32) -> String {
    let requested = isolate.labels().join(",");
    let step = match stage {
        NamespaceProbeStage::Unshare => "creating the namespaces",
        NamespaceProbeStage::IdMap => "writing the user namespace id maps",
        NamespaceProbeStage::LoopbackUp => "using capabilities inside the new namespace",
        NamespaceProbeStage::BridgeListener => "creating a loopback listener in the new namespace",
        NamespaceProbeStage::Mount => "mounting a tmpfs in the new mount namespace",
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
    if stage == NamespaceProbeStage::Mount {
        return "the namespaces were created but mounting inside them was refused. A security \
                module (AppArmor or SELinux mount rules) or a seccomp filter on nono that blocks \
                the mount API (fsopen, fsmount, move_mount) can cause this. Run without \
                linux.isolate.mounts, or allow mounts in unprivileged user namespaces."
            .to_string();
    }
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
        let error = prepare_namespaces(&isolate_network(), &caps).expect_err("allow-all");
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
        let error = prepare_namespaces(&isolate, &caps).expect_err("loopback without net");
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
        match prepare_namespaces(&isolate, &caps) {
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
        let error = prepare_namespaces(&isolate, &caps).expect_err("direct grants");
        assert!(error.to_string().contains("open_port"));
    }

    #[test]
    fn listen_ports_are_rejected_at_launch() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::ProxyOnly {
            port: 3128,
            bind_ports: vec![8080],
        });
        let error = prepare_namespaces(&isolate_network(), &caps).expect_err("bind ports");
        assert!(error.to_string().contains("inbound listen ports"));
    }

    #[test]
    fn direct_grants_are_rejected_at_launch() {
        let mut caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        caps.add_localhost_port(5432);
        caps.add_tcp_connect_port(22);
        let error = prepare_namespaces(&isolate_network(), &caps).expect_err("direct grants");
        let message = error.to_string();
        assert!(message.contains("open_port"), "{message}");
        assert!(message.contains("connect_port"), "{message}");
    }

    #[test]
    fn command_network_grants_are_rejected_under_isolation() {
        use crate::command_policy::{
            CommandNetworkConfig, CommandPoliciesConfig, CommandPolicyConfig, CommandSandboxConfig,
        };
        let policies = |network: CommandNetworkConfig| {
            let sandbox = CommandSandboxConfig {
                network: Some(network),
                ..Default::default()
            };
            let mut policies = CommandPoliciesConfig::default();
            policies.commands.insert(
                "tool".into(),
                CommandPolicyConfig {
                    sandbox: Some(sandbox),
                    ..Default::default()
                },
            );
            policies
                .commands
                .insert("git".into(), CommandPolicyConfig::default());
            policies
        };
        let loopback = LinuxIsolateConfig {
            loopback: true,
            ..isolate_network()
        };
        let callback = policies(CommandNetworkConfig {
            open_port: vec![8250],
            ..Default::default()
        });
        let message = reject_command_network_grants(&isolate_network(), Some(&callback))
            .expect_err("open_port")
            .to_string();
        assert!(
            message.contains("unreachable: tool") && !message.contains("git"),
            "{message}"
        );
        assert!(reject_command_network_grants(&loopback, Some(&callback)).is_ok());
        for direct in [
            CommandNetworkConfig {
                allow_all: true,
                ..Default::default()
            },
            CommandNetworkConfig {
                tcp_connect_ports: vec![22],
                ..Default::default()
            },
            CommandNetworkConfig {
                tcp_bind_ports: vec![8080],
                ..Default::default()
            },
        ] {
            for isolate in [&isolate_network(), &loopback] {
                let error = reject_command_network_grants(isolate, Some(&policies(direct.clone())));
                assert!(
                    error
                        .expect_err("direct")
                        .to_string()
                        .contains("directly from the host: tool")
                );
            }
        }
        assert!(reject_command_network_grants(&isolate_network(), None).is_ok());
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
        if let Err(error) = prepare_namespaces(&isolate, &caps) {
            assert!(error.to_string().contains("not available on this host"));
        }
    }

    #[test]
    fn proxy_mode_requests_a_bridge_on_the_proxy_port() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::ProxyOnly {
            port: 3128,
            bind_ports: vec![],
        });
        match prepare_namespaces(&isolate_network(), &caps) {
            Ok(spec) => assert_eq!(spec.bridge_port(), Some(3128)),
            Err(error) => assert!(error.to_string().contains("not available on this host")),
        }
    }

    #[test]
    fn refusal_names_the_failed_step_and_never_downgrades() {
        let message = explain_refusal(
            &isolate_network(),
            NamespaceProbeStage::Unshare,
            nix::libc::EPERM,
        );
        assert!(message.contains("creating the namespaces"));
        assert!(message.contains("does not fall back"));
    }

    #[test]
    fn enospc_refusal_names_the_namespace_limit_not_disk_space() {
        let message = explain_refusal(
            &isolate_network(),
            NamespaceProbeStage::Unshare,
            nix::libc::ENOSPC,
        );
        assert!(message.contains("namespace limit reached"), "{message}");
        assert!(!message.contains("No space left on device"), "{message}");
        assert!(message.contains("max_user_namespaces"), "{message}");
    }

    #[test]
    fn extra_masks_require_mounts() {
        let caps = CapabilitySet::new();
        let isolate = LinuxIsolateConfig {
            ipc: true,
            extra_masks: vec!["/opt/agent.sock".to_string()],
            ..Default::default()
        };
        let error = prepare_namespaces(&isolate, &caps).expect_err("masks without mounts");
        assert!(error.to_string().contains("requires linux.isolate.mounts"));
    }

    #[test]
    fn mounts_are_carried_on_the_spec() {
        let caps = CapabilitySet::new();
        let isolate = LinuxIsolateConfig {
            mounts: true,
            ..Default::default()
        };
        match prepare_namespaces(&isolate, &caps) {
            Ok(spec) => assert!(spec.has_mounts()),
            Err(error) => assert!(error.to_string().contains("not available on this host")),
        }
    }

    #[test]
    fn default_masks_cover_runtime_dir_tmp_and_system_sockets() {
        let isolate = LinuxIsolateConfig {
            mounts: true,
            extra_masks: vec!["$WORKDIR/agent.sock".to_string()],
            ..Default::default()
        };
        let workdir = std::env::temp_dir();
        let masks = mask_list(&isolate, &workdir).expect("mask list");
        let paths: Vec<_> = masks.iter().map(|mask| mask.path().to_path_buf()).collect();
        let uid = nix::unistd::getuid();
        assert!(paths.contains(&nono::try_canonicalize(Path::new(&format!(
            "/run/user/{uid}"
        )))));
        assert!(paths.contains(&nono::try_canonicalize(Path::new("/tmp"))));
        assert!(paths.contains(&nono::try_canonicalize(Path::new("/run/dbus"))));
        assert!(paths.contains(&nono::try_canonicalize(Path::new("/var/run/docker.sock"))));
        assert!(
            paths
                .iter()
                .any(|path| path.ends_with("agent.sock") && path.is_absolute()),
            "extra masks are expanded: {paths:?}"
        );
    }

    #[test]
    fn unexpandable_extra_mask_is_an_error() {
        let isolate = LinuxIsolateConfig {
            mounts: true,
            extra_masks: vec!["relative/agent.sock".to_string()],
            ..Default::default()
        };
        let error = mask_list(&isolate, Path::new("/")).expect_err("relative mask");
        assert!(error.to_string().contains("absolute path"));
    }

    #[test]
    fn mount_mask_rebinds_grants_beneath_masks_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonical");
        let masked = root.join("runtime");
        let granted = masked.join("agent");
        std::fs::create_dir_all(&granted).expect("mkdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(nono::FsCapability::new_dir(&granted, nono::AccessMode::Read).expect("grant"));
        let isolate = LinuxIsolateConfig {
            mounts: true,
            extra_masks: vec![masked.display().to_string()],
            ..Default::default()
        };
        let plan = prepare_mount_mask(&isolate, &caps, &root).expect("plan");
        // The extra mask, or a default mask above it (the tempdir may sit
        // under the masked /tmp), hides the granted path.
        assert!(plan.masked_paths().any(|path| masked.starts_with(path)));
        assert_eq!(
            plan.rebound_paths().collect::<Vec<_>>(),
            vec![granted.as_path()]
        );
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
