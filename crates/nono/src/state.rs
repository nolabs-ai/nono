//! Sandbox state persistence
//!
//! This module provides serialization of capability state for diagnostic purposes.

use crate::capability::{
    AccessMode, CapabilitySet, FsCapability, SocketScope, UnixSocketCapability, UnixSocketMode,
};
use crate::resource::ResourceLimits;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Serializable representation of sandbox state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxState {
    /// Filesystem capabilities
    pub fs: Vec<FsCapState>,
    /// AF_UNIX socket capabilities (may be absent in states persisted
    /// by older nono builds; `#[serde(default)]` preserves backward compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unix_sockets: Vec<UnixSocketCapState>,
    /// Whether network is blocked
    pub net_blocked: bool,
    /// Resource ceilings (memory, CPU bandwidth, process count). Absent in states persisted
    /// by older nono builds; `#[serde(default)]` preserves backward compat.
    /// These are plain numbers, so unlike paths they need no re-validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,
}

/// Serializable representation of a filesystem capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapState {
    /// Original path as specified
    pub original: PathBuf,
    /// Resolved canonical path
    pub resolved: PathBuf,
    /// Access mode
    pub access: String,
    /// Whether this is a file (vs directory)
    pub is_file: bool,
}

/// Serializable representation of a [`UnixSocketCapability`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixSocketCapState {
    /// Original path as specified
    pub original: PathBuf,
    /// Resolved canonical path
    pub resolved: PathBuf,
    /// Path matching scope for this socket grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SocketScope>,
    /// Legacy state field from before `SocketScope`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_directory: Option<bool>,
    /// Mode string: "connect" or "connect+bind"
    pub mode: String,
}

impl SandboxState {
    /// Create state from a capability set
    #[must_use]
    pub fn from_caps(caps: &CapabilitySet) -> Self {
        Self {
            fs: caps
                .fs_capabilities()
                .iter()
                .map(|cap| FsCapState {
                    original: cap.original.clone(),
                    resolved: cap.resolved.clone(),
                    access: cap.access.to_string(),
                    is_file: cap.is_file,
                })
                .collect(),
            unix_sockets: caps
                .unix_socket_capabilities()
                .iter()
                .map(|cap| UnixSocketCapState {
                    original: cap.original.clone(),
                    resolved: cap.resolved.clone(),
                    scope: Some(cap.scope),
                    is_directory: None,
                    mode: cap.mode.to_string(),
                })
                .collect(),
            net_blocked: caps.is_network_blocked(),
            resource_limits: caps.resource_limits().copied(),
        }
    }

    /// Convert state back to a capability set
    ///
    /// Paths are re-validated through the standard constructors (`new_dir`/`new_file`)
    /// which canonicalize paths and verify existence. This prevents crafted JSON from
    /// injecting arbitrary paths that bypass validation.
    ///
    /// Returns an error if any path no longer exists or fails validation.
    pub fn to_caps(&self) -> crate::error::Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();

        for fs_cap in &self.fs {
            let access = match fs_cap.access.as_str() {
                "read" => AccessMode::Read,
                "write" => AccessMode::Write,
                "read+write" => AccessMode::ReadWrite,
                other => {
                    return Err(crate::error::NonoError::ConfigParse(format!(
                        "invalid access mode in sandbox state: {other}"
                    )));
                }
            };

            // Re-validate through the standard constructors to ensure
            // path canonicalization and existence checks are applied.
            let cap = if fs_cap.is_file {
                FsCapability::new_file(&fs_cap.original, access)?
            } else {
                FsCapability::new_dir(&fs_cap.original, access)?
            };
            caps.add_fs(cap);
        }

        for sock in &self.unix_sockets {
            let mode = match sock.mode.as_str() {
                "connect" => UnixSocketMode::Connect,
                "connect+bind" => UnixSocketMode::ConnectBind,
                other => {
                    return Err(crate::error::NonoError::ConfigParse(format!(
                        "invalid unix socket mode in sandbox state: {other}"
                    )));
                }
            };

            // Reconstruct from the caller-supplied `original` so the
            // stored alias survives the roundtrip (macOS Seatbelt uses
            // it for dual-path emission when original != resolved).
            // Then validate that canonicalisation produced the same
            // `resolved` as was serialized. The check rejects two
            // failure modes with one test:
            //
            // - Filesystem drift between save and reload (symlink moved,
            //   ConnectBind pending path now exists, etc.).
            // - Crafted JSON smuggling: attacker sets an evil `original`
            //   and legit `resolved`; the reconstructed cap's actual
            //   resolved won't match the crafted one, so we reject.
            let scope = sock.scope.unwrap_or_else(|| {
                if sock.is_directory.unwrap_or(false) {
                    SocketScope::DirChildren
                } else {
                    SocketScope::File
                }
            });

            let cap = match scope {
                SocketScope::File => UnixSocketCapability::new_file(&sock.original, mode)?,
                SocketScope::DirChildren => UnixSocketCapability::new_dir(&sock.original, mode)?,
                SocketScope::DirSubtree => {
                    UnixSocketCapability::new_dir_subtree(&sock.original, mode)?
                }
            };
            if cap.resolved != sock.resolved {
                return Err(crate::error::NonoError::ConfigParse(format!(
                    "unix socket grant canonical path drifted at state reload: \
                     serialized resolved={}, actual resolved={}",
                    sock.resolved.display(),
                    cap.resolved.display(),
                )));
            }
            caps.add_unix_socket(cap);
        }

        caps.set_network_blocked(self.net_blocked);

        if let Some(limits) = self.resource_limits {
            caps = caps.with_resource_limits(limits);
        }

        Ok(caps)
    }

    /// Serialize state to JSON
    pub fn to_json(&self) -> crate::error::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            crate::error::NonoError::ConfigParse(format!("Failed to serialize sandbox state: {e}"))
        })
    }

    /// Deserialize state from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_state_roundtrip() {
        let caps = CapabilitySet::new().block_network();
        let state = SandboxState::from_caps(&caps);

        assert!(state.net_blocked);
        assert!(state.fs.is_empty());

        let json = state.to_json().expect("serialize state");
        let restored = SandboxState::from_json(&json).expect("deserialize state");
        assert!(restored.net_blocked);
    }

    #[test]
    fn test_resource_limits_roundtrip() {
        use crate::resource::ResourceLimits;

        let caps = CapabilitySet::new().with_resource_limits(ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            cpu_max_percent: Some(150),
            max_procs: Some(64),
        });
        let state = SandboxState::from_caps(&caps);
        assert_eq!(
            state.resource_limits.and_then(|l| l.memory_bytes),
            Some(512 * 1024 * 1024)
        );

        let json = state.to_json().expect("serialize state");
        let restored = SandboxState::from_json(&json).expect("deserialize state");
        let limits = restored.resource_limits.expect("limits survive roundtrip");
        assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(limits.cpu_max_percent, Some(150));
        assert_eq!(limits.max_procs, Some(64));

        // And back into a CapabilitySet.
        let caps2 = restored.to_caps().expect("to_caps");
        assert_eq!(caps2.resource_limits(), caps.resource_limits());
    }

    #[test]
    fn test_resource_limits_absent_in_legacy_state() {
        // A state JSON written before resource limits existed must still load.
        let json = r#"{ "fs": [], "net_blocked": false }"#;
        let state = SandboxState::from_json(json).expect("legacy state");
        assert!(state.resource_limits.is_none());
    }

    #[test]
    fn test_to_caps_rejects_nonexistent_path() {
        let json = r#"{
            "fs": [{
                "original": "/nonexistent/crafted/path",
                "resolved": "/nonexistent/crafted/path",
                "access": "read+write",
                "is_file": false
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject nonexistent paths"
        );
    }

    #[test]
    fn test_to_caps_rejects_invalid_access_mode() {
        let json = r#"{
            "fs": [{
                "original": "/tmp",
                "resolved": "/tmp",
                "access": "root-access",
                "is_file": false
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject invalid access modes"
        );
    }

    #[test]
    fn test_unix_socket_state_roundtrip_preserves_original_and_resolved() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("a.sock");
        std::fs::write(&sock, b"").expect("stub");

        let caps = CapabilitySet::new()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .expect("grant");
        let state = SandboxState::from_caps(&caps);
        let restored = state.to_caps().expect("to_caps");

        let round = restored.unix_socket_capabilities();
        assert_eq!(round.len(), 1);
        let before = &caps.unix_socket_capabilities()[0];
        let after = &round[0];
        assert_eq!(after.resolved, before.resolved);
        assert_eq!(after.original, before.original);
        assert_eq!(after.mode, before.mode);
        assert_eq!(after.scope, before.scope);
    }

    #[test]
    fn test_unix_socket_state_legacy_is_directory_maps_to_dir_children() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let json = format!(
            r#"{{
            "fs": [],
            "unix_sockets": [{{
                "original": "{}",
                "resolved": "{}",
                "is_directory": true,
                "mode": "connect"
            }}],
            "net_blocked": false
        }}"#,
            dir.path().display(),
            dir.path().canonicalize().expect("canonicalize").display()
        );
        let state = SandboxState::from_json(&json).expect("state json");
        let caps = state.to_caps().expect("to_caps");
        let sockets = caps.unix_socket_capabilities();
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].scope, SocketScope::DirChildren);
    }

    #[test]
    fn test_unix_socket_state_rejects_invalid_mode() {
        let json = r#"{
            "fs": [],
            "unix_sockets": [{
                "original": "/tmp",
                "resolved": "/tmp",
                "is_directory": true,
                "mode": "bind-only"
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject unknown unix socket modes"
        );
    }
}
