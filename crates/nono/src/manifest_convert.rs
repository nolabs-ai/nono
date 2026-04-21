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
    AccessMode, CapabilityManifest, FsEntryType, IpcMode, NetworkMode, ProcessInfoMode, SignalMode,
};
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

        Ok(caps)
    }
}

fn convert_access_mode(mode: AccessMode) -> InternalAccessMode {
    match mode {
        AccessMode::Read => InternalAccessMode::Read,
        AccessMode::Write => InternalAccessMode::Write,
        AccessMode::Readwrite => InternalAccessMode::ReadWrite,
        AccessMode::Execute => InternalAccessMode::Execute,
        AccessMode::Readexecute => InternalAccessMode::ReadExecute,
        AccessMode::Readwriteexecute => InternalAccessMode::ReadWriteExecute,
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
