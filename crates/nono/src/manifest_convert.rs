//! Conversion from capability manifest types to internal `CapabilitySet`.
//!
//! This module bridges the schema-generated manifest types with nono's internal
//! enforcement types. `CapabilitySet` is constructed by mapping each manifest
//! domain (filesystem, network, process) to the corresponding builder calls.

use crate::capability::{
    AccessMode as InternalAccessMode, CapabilitySet, IpcMode as InternalIpcMode,
    NetworkMode as InternalNetworkMode, ProcessInfoMode as InternalProcessInfoMode,
    SignalMode as InternalSignalMode,
};
use crate::manifest::{
    AccessMode, CapabilityManifest, FsEntryType, IpcMode, NetworkMode, ProcessInfoMode, Resources,
    SignalMode,
};
use crate::resource::ResourceLimits;
use crate::{NonoError, Result};

impl TryFrom<&CapabilityManifest> for CapabilitySet {
    type Error = NonoError;

    fn try_from(manifest: &CapabilityManifest) -> Result<Self> {
        manifest.validate()?;

        let mut caps = CapabilitySet::new();

        // Filesystem grants
        if let Some(ref fs) = manifest.filesystem {
            for grant in &fs.grants {
                let mode = convert_access_mode(grant.access);
                let path = grant.path.as_str();
                caps = match grant.type_ {
                    FsEntryType::File => caps.allow_file(path, mode)?,
                    FsEntryType::Directory => caps.allow_path(path, mode)?,
                };
            }
            // Note: deny rules are handled at the CLI/profile level, not in CapabilitySet.
            // On Linux/Landlock, deny is expressed by omitting grants (allow-list model).
            // On macOS/Seatbelt, deny rules are injected into the profile by the CLI layer.
        }

        // Network
        if let Some(ref net) = manifest.network {
            caps = match net.mode {
                NetworkMode::Blocked => caps.block_network(),
                // Proxy mode blocks direct network access at the OS level; the CLI
                // layer sets up the reverse proxy separately and allows its port.
                // Port 0 is a placeholder — the CLI fills in the actual proxy port.
                NetworkMode::Proxy => caps.set_network_mode(InternalNetworkMode::ProxyOnly {
                    port: 0,
                    bind_ports: vec![],
                }),
                NetworkMode::Unrestricted => caps.set_network_mode(InternalNetworkMode::AllowAll),
            };

            // Port allowlists
            if let Some(ref ports) = net.ports {
                for port in &ports.connect {
                    let p = u16::try_from(port.get()).map_err(|_| {
                        NonoError::ConfigParse(format!("port {} exceeds u16 range", port))
                    })?;
                    caps = caps.allow_tcp_connect(p);
                }
                for port in &ports.bind {
                    let p = u16::try_from(port.get()).map_err(|_| {
                        NonoError::ConfigParse(format!("port {} exceeds u16 range", port))
                    })?;
                    caps = caps.allow_tcp_bind(p);
                }
                for port in &ports.localhost {
                    let p = u16::try_from(port.get()).map_err(|_| {
                        NonoError::ConfigParse(format!("port {} exceeds u16 range", port))
                    })?;
                    caps = caps.allow_localhost_port(p);
                }
            }
        }

        // Process
        if let Some(ref proc) = manifest.process {
            caps = caps.set_signal_mode(convert_signal_mode(proc.signal_mode));
            caps = caps.set_process_info_mode(convert_process_info_mode(proc.process_info_mode));
            caps = caps.set_ipc_mode(convert_ipc_mode(proc.ipc_mode));

            for cmd in &proc.allowed_commands {
                caps = caps.allow_command(cmd.clone());
            }
            for cmd in &proc.blocked_commands {
                caps = caps.block_command(cmd.clone());
            }
        }

        // Resources
        if let Some(ref res) = manifest.resources {
            caps = caps.with_resource_limits(convert_resources(res));
        }

        Ok(caps)
    }
}

fn convert_resources(res: &Resources) -> ResourceLimits {
    ResourceLimits {
        memory_bytes: res.memory_bytes.map(|n| n.get()),
    }
}

fn convert_access_mode(mode: AccessMode) -> InternalAccessMode {
    match mode {
        AccessMode::Read => InternalAccessMode::Read,
        AccessMode::Write => InternalAccessMode::Write,
        AccessMode::Readwrite => InternalAccessMode::ReadWrite,
    }
}

fn convert_signal_mode(mode: SignalMode) -> InternalSignalMode {
    match mode {
        SignalMode::Isolated => InternalSignalMode::Isolated,
        SignalMode::AllowSameSandbox => InternalSignalMode::AllowSameSandbox,
        SignalMode::AllowAll => InternalSignalMode::AllowAll,
    }
}

fn convert_process_info_mode(mode: ProcessInfoMode) -> InternalProcessInfoMode {
    match mode {
        ProcessInfoMode::Isolated => InternalProcessInfoMode::Isolated,
        ProcessInfoMode::AllowSameSandbox => InternalProcessInfoMode::AllowSameSandbox,
        ProcessInfoMode::AllowAll => InternalProcessInfoMode::AllowAll,
    }
}

fn convert_ipc_mode(mode: IpcMode) -> InternalIpcMode {
    match mode {
        IpcMode::SharedMemoryOnly => InternalIpcMode::SharedMemoryOnly,
        IpcMode::Full => InternalIpcMode::Full,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn manifest_resources_map_into_capability_set() {
        let json = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "supervised" },
            "resources": { "memory_bytes": 1048576 }
        }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let caps = CapabilitySet::try_from(&manifest).unwrap();
        let limits = caps.resource_limits().expect("limits present");
        assert_eq!(limits.memory_bytes, Some(1048576));
    }

    #[test]
    fn manifest_without_resources_has_no_limits() {
        let json = r#"{ "version": "0.1.0" }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let caps = CapabilitySet::try_from(&manifest).unwrap();
        assert!(caps.resource_limits().is_none());
    }

    // ---- TryFrom enforces validate(); empty resources maps clean ----

    #[test]
    fn try_from_runs_validate_and_rejects_unsupervised_memory() {
        // CapabilitySet::try_from(&manifest) calls manifest.validate() first, so a
        // memory ceiling under the default (monitor) strategy must surface the same
        // ConfigParse rather than silently building an unenforceable set.
        let json = r#"{ "version": "0.1.0", "resources": { "memory_bytes": 1024 } }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let err = CapabilitySet::try_from(&manifest)
            .expect_err("unsupervised memory limit must be rejected by TryFrom");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    fn empty_resources_object_maps_to_no_ceiling() {
        // `resources: {}` is present-but-empty: the conversion still attaches a
        // ResourceLimits, but it must carry no ceiling (is_empty), never a phantom
        // limit. Distinct from manifest_without_resources_has_no_limits, which omits
        // the resources key entirely.
        let json = r#"{ "version": "0.1.0", "resources": {} }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let caps = CapabilitySet::try_from(&manifest).unwrap();
        // The conversion must attach a ResourceLimits (assert Some first, so this
        // can't pass vacuously if conversion ever returned None for `{}`)...
        let limits = caps
            .resource_limits()
            .expect("empty resources must still attach a ResourceLimits");
        // ...and that ResourceLimits must carry no ceiling, never a phantom limit.
        assert!(
            limits.is_empty(),
            "empty resources must not produce a ceiling, got {limits:?}"
        );
    }
}
