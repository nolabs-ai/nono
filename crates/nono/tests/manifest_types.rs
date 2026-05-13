//! Tests for the manifest module (typify-generated types) and manifest_convert
//! (TryFrom<&CapabilityManifest> for CapabilitySet).

use nono::CapabilitySet;
use nono::capability::{
    AccessMode as InternalAccessMode, IpcMode as InternalIpcMode,
    NetworkMode as InternalNetworkMode, ProcessInfoMode as InternalProcessInfoMode,
    SignalMode as InternalSignalMode,
};
use nono::manifest::CapabilityManifest;

// ─── manifest deserialization ───

#[test]
fn minimal_manifest_deserializes() {
    let json = r#"{ "version": "0.1.0" }"#;
    let manifest = CapabilityManifest::from_json(json).expect("should parse minimal manifest");
    assert!(manifest.filesystem.is_none());
    assert!(manifest.network.is_none());
    assert!(manifest.process.is_none());
    assert!(manifest.rollback.is_none());
    assert!(manifest.credentials.is_empty());
}

#[test]
fn round_trip_minimal() {
    let json = r#"{ "version": "0.1.0" }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let serialized = manifest.to_json().expect("serialize");
    let reparsed = CapabilityManifest::from_json(&serialized).expect("reparse");
    assert_eq!(manifest.version.as_str(), reparsed.version.as_str());
}

#[test]
fn invalid_version_rejected() {
    let json = r#"{ "version": "abc" }"#;
    assert!(CapabilityManifest::from_json(json).is_err());
}

#[test]
fn missing_version_rejected() {
    let json = r#"{}"#;
    assert!(CapabilityManifest::from_json(json).is_err());
}

#[test]
fn filesystem_grants_deserialize() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/tmp", "access": "read" },
                { "path": "/var/log/app.log", "access": "readwrite", "type": "file" }
            ]
        }
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let fs = manifest.filesystem.as_ref().expect("filesystem present");
    assert_eq!(fs.grants.len(), 2);
    assert_eq!(fs.grants[0].path.as_str(), "/tmp");
}

#[test]
fn network_modes_deserialize() {
    for mode in &["blocked", "proxy", "unrestricted"] {
        let json = format!(
            r#"{{ "version": "0.1.0", "network": {{ "mode": "{}" }} }}"#,
            mode
        );
        let manifest = CapabilityManifest::from_json(&json).expect("parse");
        assert!(manifest.network.is_some());
    }
}

#[test]
fn credential_inject_validation_url_path_requires_pattern() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [{
            "name": "test",
            "source": "env://TOKEN",
            "upstream": "https://api.example.com",
            "inject": { "mode": "url_path" }
        }]
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let result = manifest.validate();
    assert!(result.is_err());
    let err = format!("{}", result.expect_err("should be an error"));
    assert!(
        err.contains("url_path"),
        "error should mention url_path: {err}"
    );
}

#[test]
fn credential_inject_validation_query_param_requires_name() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [{
            "name": "test",
            "source": "env://TOKEN",
            "upstream": "https://api.example.com",
            "inject": { "mode": "query_param" }
        }]
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let result = manifest.validate();
    assert!(result.is_err());
    let err = format!("{}", result.expect_err("should be an error"));
    assert!(
        err.contains("query_param"),
        "error should mention query_param: {err}"
    );
}

#[test]
fn credential_inject_header_mode_passes_validation() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [{
            "name": "test",
            "source": "env://TOKEN",
            "upstream": "https://api.example.com",
            "inject": { "mode": "header" }
        }]
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    manifest
        .validate()
        .expect("header mode should pass validation");
}

// ─── manifest → CapabilitySet conversion ───

#[test]
fn convert_minimal_manifest() {
    let json = r#"{ "version": "0.1.0" }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let caps = CapabilitySet::try_from(&manifest).expect("convert");
    // Minimal manifest: no fs caps, default network (AllowAll)
    assert!(caps.fs_capabilities().is_empty());
    assert_eq!(*caps.network_mode(), InternalNetworkMode::AllowAll);
}

#[test]
fn convert_filesystem_grants() {
    // Use real paths that exist on any system
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/tmp", "access": "read" },
                { "path": "/tmp", "access": "readwrite" }
            ]
        }
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let caps = CapabilitySet::try_from(&manifest).expect("convert");
    assert_eq!(caps.fs_capabilities().len(), 2);
    assert_eq!(caps.fs_capabilities()[0].access, InternalAccessMode::Read);
    assert_eq!(
        caps.fs_capabilities()[1].access,
        InternalAccessMode::ReadWrite
    );
}

#[test]
fn convert_network_blocked() {
    let json = r#"{ "version": "0.1.0", "network": { "mode": "blocked" } }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let caps = CapabilitySet::try_from(&manifest).expect("convert");
    assert_eq!(*caps.network_mode(), InternalNetworkMode::Blocked);
}

#[test]
fn convert_network_ports() {
    let json = r#"{
        "version": "0.1.0",
        "network": {
            "mode": "unrestricted",
            "ports": {
                "connect": [443, 8443],
                "bind": [8080],
                "localhost": [3000]
            }
        }
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let caps = CapabilitySet::try_from(&manifest).expect("convert");
    assert_eq!(caps.tcp_connect_ports(), &[443, 8443]);
    assert_eq!(caps.tcp_bind_ports(), &[8080]);
    assert_eq!(caps.localhost_ports(), &[3000]);
}

#[test]
fn convert_process_modes() {
    let json = r#"{
        "version": "0.1.0",
        "process": {
            "signal_mode": "allow_all",
            "process_info_mode": "allow_same_sandbox",
            "ipc_mode": "full",
            "allowed_commands": ["git", "npm"],
            "blocked_commands": ["rm"]
        }
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let caps = CapabilitySet::try_from(&manifest).expect("convert");
    assert_eq!(caps.signal_mode(), InternalSignalMode::AllowAll);
    assert_eq!(
        caps.process_info_mode(),
        InternalProcessInfoMode::AllowSameSandbox
    );
    assert_eq!(caps.ipc_mode(), InternalIpcMode::Full);
    assert_eq!(caps.allowed_commands(), &["git", "npm"]);
    assert_eq!(caps.blocked_commands(), &["rm"]);
}

#[test]
fn convert_nonexistent_path_fails() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/this/path/does/not/exist/at/all", "access": "read" }
            ]
        }
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let result = CapabilitySet::try_from(&manifest);
    assert!(result.is_err(), "nonexistent path should fail conversion");
}

#[test]
fn convert_validation_failure_propagates() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [{
            "name": "test",
            "source": "env://TOKEN",
            "upstream": "https://api.example.com",
            "inject": { "mode": "url_path" }
        }]
    }"#;
    let manifest = CapabilityManifest::from_json(json).expect("parse");
    let result = CapabilitySet::try_from(&manifest);
    assert!(
        result.is_err(),
        "semantic validation errors should propagate"
    );
}
