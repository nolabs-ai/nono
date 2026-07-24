//! Sandbox state persistence for `nono why --self`
//!
//! When nono runs a command, it writes the capability state to a temp file
//! and passes the path via NONO_CAP_FILE. This allows sandboxed processes
//! to query their own capabilities using `nono why --self`.

#[cfg(target_os = "macos")]
use crate::capability_ext::new_exact_path_capability;
use nono::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, ResourceLimits, Result,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::debug;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Sandbox state stored for `nono why --self`
#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxState {
    /// Filesystem capabilities
    pub fs: Vec<FsCapState>,
    /// Whether network is blocked
    pub net_blocked: bool,
    /// Commands explicitly allowed
    pub allowed_commands: Vec<String>,
    /// Commands explicitly blocked
    pub blocked_commands: Vec<String>,
    /// Paths exempted from deny groups via bypass_protection (canonicalized)
    /// ALIAS(canonical="bypass_protection_paths", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default, alias = "override_deny_paths")]
    pub bypass_protection_paths: Vec<String>,
    /// Proxy domain allowlist at sandbox creation time
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Endpoint-restricted domains with method+path rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_endpoints: Vec<DomainEndpointState>,
    /// Resource ceilings (memory and max processes) in effect for this sandbox,
    /// so `nono why --self` can report them. Absent in states written by older
    /// nono builds; `#[serde(default)]` keeps those loadable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,
}

/// Serializable domain endpoint restriction state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainEndpointState {
    /// Domain hostname
    pub domain: String,
    /// Allowed method+path rules (default-deny when non-empty)
    pub endpoints: Vec<EndpointRuleState>,
}

/// Serializable endpoint rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRuleState {
    /// HTTP method ("GET", "POST", "*", etc.)
    pub method: String,
    /// URL path glob pattern
    pub path: String,
}

/// Serializable filesystem capability state
#[derive(Debug, Serialize, Deserialize)]
pub struct FsCapState {
    /// Original path as specified
    pub original: String,
    /// Resolved absolute path
    pub path: String,
    /// Access level: "read", "write", or "readwrite"
    pub access: String,
    /// Whether this is a single file (vs directory)
    pub is_file: bool,
    /// Capability source for diagnostics (`user`, `profile`, `group:<name>`, `system`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Device number of the resolved path at sandbox start (Linux file grants
    /// only). Landlock rules bind to the inode that was open at ruleset build
    /// time, not to the path, so a file replaced via write-temp-then-rename
    /// carries no rule even though the grant still names it. `nono why`
    /// compares this against a fresh stat to surface such stale grants.
    /// Absent in states written by older builds and on non-Linux platforms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<u64>,
    /// Inode number of the resolved path at sandbox start (see `dev`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ino: Option<u64>,
}

/// Stat the resolved path of a file-level grant so its identity at sandbox
/// start can be recorded, as a `(dev, ino)` pair — one is meaningless
/// without the other. Landlock is the only backend that binds rules to
/// inodes (macOS Seatbelt rules are path-based), so this is Linux-only.
#[cfg(target_os = "linux")]
fn grant_time_inode(cap: &nono::FsCapability) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    if !cap.is_file {
        return None;
    }
    std::fs::metadata(&cap.resolved)
        .ok()
        .map(|md| (md.dev(), md.ino()))
}

#[cfg(not(target_os = "linux"))]
fn grant_time_inode(_cap: &nono::FsCapability) -> Option<(u64, u64)> {
    None
}

impl SandboxState {
    /// Create sandbox state from a CapabilitySet, bypass_protection paths, and domain allowlist
    pub fn from_caps(
        caps: &CapabilitySet,
        bypass_protection_paths: &[PathBuf],
        allowed_domains: &[String],
        domain_endpoints: &[DomainEndpointState],
    ) -> Self {
        Self {
            fs: caps
                .fs_capabilities()
                .iter()
                .map(|c| {
                    let inode = grant_time_inode(c);
                    FsCapState {
                        original: c.original.display().to_string(),
                        path: c.resolved.display().to_string(),
                        access: match c.access {
                            AccessMode::Read => "read".to_string(),
                            AccessMode::Write => "write".to_string(),
                            AccessMode::ReadWrite => "readwrite".to_string(),
                        },
                        is_file: c.is_file,
                        source: Some(c.source.to_string()),
                        dev: inode.map(|(dev, _)| dev),
                        ino: inode.map(|(_, ino)| ino),
                    }
                })
                .collect(),
            net_blocked: caps.is_network_blocked(),
            allowed_commands: caps.allowed_commands().to_vec(),
            blocked_commands: caps.blocked_commands().to_vec(),
            bypass_protection_paths: bypass_protection_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            allowed_domains: allowed_domains.to_vec(),
            domain_endpoints: domain_endpoints.to_vec(),
            resource_limits: caps.resource_limits().copied(),
        }
    }

    /// Get bypass_protection paths as PathBufs for query use
    pub fn bypass_protection_as_paths(&self) -> Vec<PathBuf> {
        self.bypass_protection_paths
            .iter()
            .map(PathBuf::from)
            .collect()
    }

    /// Convert back to a CapabilitySet
    ///
    /// Paths are re-validated through the standard constructors whenever
    /// possible. On macOS, exact-file grants for missing leaf paths are
    /// reconstructed with the same future-file logic used at profile load time.
    /// In all cases, the reconstructed canonical path must match the path
    /// serialized in the state file.
    ///
    /// Returns an error if a stored grant fails validation or if the current
    /// filesystem state no longer matches the serialized grant.
    pub fn to_caps(&self) -> Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();

        for fs_cap in &self.fs {
            let access = parse_access_mode(&fs_cap.access)?;
            let source = parse_capability_source(fs_cap.source.as_deref())?;

            let cap = if fs_cap.is_file {
                restore_exact_path_capability(fs_cap, access, &source)?
            } else {
                restore_directory_capability(fs_cap, access, &source)?
            };
            caps.add_fs(cap);
        }

        if !self.allowed_domains.is_empty() {
            caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
                port: 0,
                bind_ports: vec![],
            });
        } else {
            caps.set_network_blocked(self.net_blocked);
        }
        for cmd in &self.allowed_commands {
            caps.add_allowed_command(cmd.clone());
        }
        for cmd in &self.blocked_commands {
            caps.add_blocked_command(cmd.clone());
        }

        if let Some(limits) = self.resource_limits {
            caps = caps.with_resource_limits(limits);
        }

        Ok(caps)
    }

    /// Write sandbox state to a file with secure permissions
    ///
    /// # Security
    /// This function implements multiple defenses against temp file attacks:
    /// - Uses `create_new(true)` to fail if file exists (prevents symlink attacks)
    /// - Sets `mode(0o600)` for owner-only read/write permissions (Unix)
    /// - Atomic write operation (no TOCTOU window)
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            NonoError::ConfigParse(format!("Failed to serialize sandbox state: {}", e))
        })?;

        // SECURITY: Use OpenOptions with create_new(true) to prevent symlink attacks
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        file.write_all(json.as_bytes())
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        Ok(())
    }
}

fn parse_access_mode(access: &str) -> Result<AccessMode> {
    match access {
        "read" => Ok(AccessMode::Read),
        "write" => Ok(AccessMode::Write),
        "readwrite" => Ok(AccessMode::ReadWrite),
        other => Err(NonoError::ConfigParse(format!(
            "invalid access mode in sandbox state: {other}"
        ))),
    }
}

fn parse_capability_source(source: Option<&str>) -> Result<CapabilitySource> {
    match source {
        None | Some("") | Some("user") => Ok(CapabilitySource::User),
        Some("profile") => Ok(CapabilitySource::Profile),
        Some("system") => Ok(CapabilitySource::System),
        Some(group) if let Some(name) = group.strip_prefix("group:") => {
            if name.is_empty() {
                return Err(NonoError::ConfigParse(
                    "invalid capability source in sandbox state: empty group name".to_string(),
                ));
            }
            Ok(CapabilitySource::Group(name.to_string()))
        }
        Some(other) => Err(NonoError::ConfigParse(format!(
            "invalid capability source in sandbox state: {other}"
        ))),
    }
}

fn validate_restored_path(fs_cap: &FsCapState, actual: &Path) -> Result<()> {
    let serialized = Path::new(&fs_cap.path);
    if actual != serialized {
        return Err(NonoError::ConfigParse(format!(
            "sandbox state path drifted at reload: serialized resolved={}, actual resolved={}",
            serialized.display(),
            actual.display(),
        )));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_exact_path_capability(
    fs_cap: &FsCapState,
    access: AccessMode,
    source: &CapabilitySource,
) -> Result<FsCapability> {
    let mut cap = new_exact_path_capability(Path::new(&fs_cap.original), access)?;
    validate_restored_path(fs_cap, &cap.resolved)?;
    cap.source = source.clone();
    Ok(cap)
}

#[cfg(not(target_os = "macos"))]
fn restore_exact_path_capability(
    fs_cap: &FsCapState,
    access: AccessMode,
    source: &CapabilitySource,
) -> Result<FsCapability> {
    let mut cap = FsCapability::new_file(&fs_cap.original, access)?;
    validate_restored_path(fs_cap, &cap.resolved)?;
    cap.source = source.clone();
    Ok(cap)
}

fn restore_directory_capability(
    fs_cap: &FsCapState,
    access: AccessMode,
    source: &CapabilitySource,
) -> Result<FsCapability> {
    let mut cap = FsCapability::new_dir(&fs_cap.original, access)?;
    validate_restored_path(fs_cap, &cap.resolved)?;
    cap.source = source.clone();
    Ok(cap)
}

/// Maximum size for capability state files (1 MB is more than enough)
const MAX_CAP_FILE_SIZE: u64 = 1_048_576;

/// Collect the set of acceptable temp-directory roots a capability state file
/// may legitimately live under.
///
/// The capability file is created by the outer `nono` process under *its*
/// `std::env::temp_dir()`, but `nono why --self` may run in a child shell whose
/// `$TMPDIR` was overridden (e.g. Claude Code sets a per-session `/tmp/...`).
/// Validating against only the reading process's temp dir then rejects a
/// perfectly valid file. We instead accept any of the known per-user,
/// OS-provided temp roots:
///
/// - `std::env::temp_dir()` — honors the reading process's `$TMPDIR`.
/// - `/tmp` — canonicalizes to `/private/tmp` on macOS; standard on Linux.
/// - macOS only: `/var/folders` — canonicalizes to `/private/var/folders`, the
///   parent of the OS-native per-user temp dir (`/var/folders/.../T/`).
///
/// Each root is canonicalized so symlinks (`/tmp` -> `/private/tmp`) resolve;
/// roots that fail to canonicalize are skipped. This stays within safe Rust and
/// preserves the security property that `NONO_CAP_FILE` cannot point outside a
/// trusted temp location. If no root can be canonicalized the set is empty and
/// the containment check fails closed.
fn acceptable_temp_roots() -> Vec<PathBuf> {
    // On macOS the OS-native per-user temp dir lives under `/var/folders`
    // (e.g. `/var/folders/.../T/`), so include it as an accepted root.
    #[cfg(target_os = "macos")]
    let candidates = vec![
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/folders"),
    ];
    #[cfg(not(target_os = "macos"))]
    let candidates = vec![std::env::temp_dir(), PathBuf::from("/tmp")];

    let mut roots: Vec<PathBuf> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if let Ok(canonical) = candidate.canonicalize()
            && !roots.contains(&canonical)
        {
            roots.push(canonical);
        }
    }
    roots
}

/// Validate the NONO_CAP_FILE path for security
fn validate_cap_file_path(path_str: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path_str);
    if !path.is_absolute() {
        return Err(NonoError::EnvVarValidation {
            var: "NONO_CAP_FILE".to_string(),
            reason: "path must be absolute".to_string(),
        });
    }

    let canonical = path
        .canonicalize()
        .map_err(|e| NonoError::CapFileValidation {
            reason: format!("failed to canonicalize path: {}", e),
        })?;

    // Must be under one of the known per-user temp roots. The file may have
    // been created under a different $TMPDIR than the reading process has, so
    // we accept any acceptable temp root rather than only the current one.
    let roots = acceptable_temp_roots();
    if !roots.iter().any(|root| canonical.starts_with(root)) {
        return Err(NonoError::CapFileValidation {
            reason: format!(
                "path must be in a temp directory, got: {}",
                canonical.display()
            ),
        });
    }

    // Must match expected naming pattern
    let file_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| NonoError::CapFileValidation {
            reason: "invalid file name".to_string(),
        })?;

    if !file_name.starts_with(".nono-") || !file_name.ends_with(".json") {
        return Err(NonoError::CapFileValidation {
            reason: format!(
                "file name must match pattern .nono-*.json, got: {}",
                file_name
            ),
        });
    }

    // File size must be reasonable
    let metadata = std::fs::metadata(&canonical).map_err(|e| NonoError::CapFileValidation {
        reason: format!("failed to read file metadata: {}", e),
    })?;

    if metadata.len() > MAX_CAP_FILE_SIZE {
        return Err(NonoError::CapFileTooLarge {
            size: metadata.len(),
            max: MAX_CAP_FILE_SIZE,
        });
    }

    if !metadata.is_file() {
        return Err(NonoError::CapFileValidation {
            reason: "path must be a regular file".to_string(),
        });
    }

    Ok(canonical)
}

/// Lenient variant of [`load_sandbox_state`] for opportunistic consumers,
/// such as the stale-file-grant hints in non-`--self` `nono why` queries.
///
/// Returns `None` on any failure (unset env var, validation failure,
/// unreadable file, parse error) instead of exiting. Callers of this variant
/// worked without the state file before it was consulted and must not grow a
/// hard dependency on its readability — inside a sandbox the state file is
/// frequently not covered by any read grant. The fallback only means fewer
/// diagnostics; enforcement is unaffected. `--self` queries, whose whole
/// answer comes from the state file, keep the strict fail-loud loader.
pub fn try_load_sandbox_state() -> Option<SandboxState> {
    let cap_file_str = std::env::var("NONO_CAP_FILE").ok()?;

    let validated_path = match validate_cap_file_path(&cap_file_str) {
        Ok(path) => path,
        Err(e) => {
            debug!("Skipping sandbox state for diagnostics: {}", e);
            return None;
        }
    };

    let content = match std::fs::read_to_string(&validated_path) {
        Ok(content) => content,
        Err(e) => {
            debug!(
                "Skipping sandbox state for diagnostics: cannot read {}: {}",
                validated_path.display(),
                e
            );
            return None;
        }
    };

    match serde_json::from_str(&content) {
        Ok(state) => Some(state),
        Err(e) => {
            debug!("Skipping sandbox state for diagnostics: parse error: {}", e);
            None
        }
    }
}

/// Load sandbox state from NONO_CAP_FILE environment variable
///
/// Returns None if not running inside a nono sandbox (env var not set).
pub fn load_sandbox_state() -> Option<SandboxState> {
    let cap_file_str = std::env::var("NONO_CAP_FILE").ok()?;

    let validated_path = validate_cap_file_path(&cap_file_str).unwrap_or_else(|e| {
        eprintln!("SECURITY: NONO_CAP_FILE validation failed: {}", e);
        eprintln!("SECURITY: This may indicate an attack attempt or a bug in nono");
        std::process::exit(1);
    });

    let content = std::fs::read_to_string(&validated_path).unwrap_or_else(|e| {
        eprintln!("Error reading capability state file: {}", e);
        std::process::exit(1);
    });

    let state: SandboxState = serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Error parsing capability state file: {}", e);
        std::process::exit(1);
    });

    Some(state)
}

/// Check if a process with the given PID is currently running
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);
    match kill(nix_pid, None) {
        Ok(()) => true,
        Err(nix::errno::Errno::ESRCH) => false,
        Err(nix::errno::Errno::EPERM) => true,
        _ => true,
    }
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    true
}

/// Clean up stale sandbox state files from previous nono runs
pub fn cleanup_stale_state_files() {
    let temp_dir = std::env::temp_dir();

    let entries = match std::fs::read_dir(&temp_dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!("Failed to read temp directory for cleanup: {}", e);
            return;
        }
    };

    let current_pid = std::process::id();
    let mut cleaned_count = 0;
    let mut skipped_count = 0;

    for entry in entries.flatten() {
        let file_name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => continue,
        };

        if !file_name.starts_with(".nono-") || !file_name.ends_with(".json") {
            continue;
        }

        let pid_str = file_name
            .trim_start_matches(".nono-")
            .trim_end_matches(".json");

        let pid = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => {
                debug!("Skipping state file with invalid PID: {}", file_name);
                continue;
            }
        };

        if pid == current_pid {
            continue;
        }

        if is_process_running(pid) {
            skipped_count += 1;
            continue;
        }

        let file_path = temp_dir.join(&file_name);
        match std::fs::remove_file(&file_path) {
            Ok(()) => {
                debug!("Cleaned up stale state file for PID {}: {}", pid, file_name);
                cleaned_count += 1;
            }
            Err(e) => {
                debug!("Failed to remove stale state file {}: {}", file_name, e);
            }
        }
    }

    if cleaned_count > 0 {
        debug!(
            "Cleanup complete: removed {} stale state file(s), {} active",
            cleaned_count, skipped_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::CapabilitySource;
    use tempfile::tempdir;

    #[test]
    fn test_sandbox_state_roundtrip() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_allowed_command("pip".to_string());

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        assert!(state.net_blocked);
        assert_eq!(state.allowed_commands, vec!["pip"]);

        let restored = state
            .to_caps()
            .expect("to_caps failed on network-only state");
        assert!(restored.is_network_blocked());
        assert_eq!(restored.allowed_commands(), vec!["pip"]);
    }

    #[test]
    fn test_sandbox_state_write_and_read() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join("test_state.json");

        let caps = CapabilitySet::new().block_network();

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        state
            .write_to_file(&file_path)
            .expect("Failed to write state");

        let content = std::fs::read_to_string(&file_path).expect("Failed to read file");
        let loaded: SandboxState = serde_json::from_str(&content).expect("Failed to parse state");

        assert!(loaded.net_blocked);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_from_caps_records_inode_for_file_grants_only() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("granted.txt");
        std::fs::write(&file_path, b"ok").expect("write test file");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file_path, AccessMode::Read).expect("file cap"));
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).expect("dir cap"));

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let file_state = state.fs.iter().find(|c| c.is_file).expect("file grant");
        let dir_state = state.fs.iter().find(|c| !c.is_file).expect("dir grant");

        let md = std::fs::metadata(&file_path).expect("stat");
        assert_eq!(file_state.dev, Some(md.dev()));
        assert_eq!(file_state.ino, Some(md.ino()));
        assert_eq!(dir_state.dev, None);
        assert_eq!(dir_state.ino, None);

        // Directory grants must omit the keys entirely so states stay readable
        // by older builds that don't know the fields.
        let json = serde_json::to_string(&state).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let dir_obj = v["fs"]
            .as_array()
            .expect("fs array")
            .iter()
            .find(|c| c["is_file"] == serde_json::Value::Bool(false))
            .expect("dir entry");
        assert!(dir_obj.get("ino").is_none());
        assert!(dir_obj.get("dev").is_none());
    }

    #[test]
    fn test_state_without_inode_fields_still_loads() {
        // States written by older builds have no dev/ino keys on fs entries;
        // strip them from a freshly serialized state to reproduce that shape.
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("granted.txt");
        std::fs::write(&file_path, b"ok").expect("write test file");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file_path, AccessMode::Read).expect("file cap"));
        let state = SandboxState::from_caps(&caps, &[], &[], &[]);

        let mut v = serde_json::to_value(&state).expect("serialize state");
        for entry in v["fs"].as_array_mut().expect("fs array") {
            let obj = entry.as_object_mut().expect("fs entry object");
            obj.remove("dev");
            obj.remove("ino");
        }

        let legacy: SandboxState = serde_json::from_value(v).expect("legacy state loads");
        assert_eq!(legacy.fs[0].dev, None);
        assert_eq!(legacy.fs[0].ino, None);
        legacy.to_caps().expect("legacy state converts to caps");
    }

    #[test]
    fn test_sandbox_state_roundtrip_preserves_source() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("granted.txt");
        std::fs::write(&file_path, b"ok").expect("write test file");

        let mut cap = FsCapability::new_file(&file_path, AccessMode::Read).expect("create cap");
        cap.source = CapabilitySource::Group("system_read_macos".to_string());

        let mut caps = CapabilitySet::new();
        caps.add_fs(cap);

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let restored = state.to_caps().expect("restore caps");

        assert_eq!(restored.fs_capabilities().len(), 1);
        assert_eq!(
            restored.fs_capabilities()[0].source,
            CapabilitySource::Group("system_read_macos".to_string())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_state_restores_missing_future_file() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("future.lock");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: missing.clone(),
            resolved: dir
                .path()
                .canonicalize()
                .expect("canonicalize dir")
                .join("future.lock"),
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let restored = state.to_caps().expect("restore future file cap");

        assert_eq!(restored.fs_capabilities().len(), 1);
        assert_eq!(restored.fs_capabilities()[0].original, missing);
        assert_eq!(restored.fs_capabilities()[0].access, AccessMode::ReadWrite);
        assert_eq!(
            restored.fs_capabilities()[0].source,
            CapabilitySource::Profile
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_state_restores_exact_directory_literal_path() {
        let dir = tempdir().expect("tempdir");
        let lock_dir = dir.path().join("claude.lock");
        std::fs::create_dir_all(&lock_dir).expect("create lock dir");
        let child = lock_dir.join("child.txt");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: lock_dir.clone(),
            resolved: lock_dir.canonicalize().expect("canonicalize lock dir"),
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let restored = state.to_caps().expect("restore exact directory literal");

        assert_eq!(restored.fs_capabilities().len(), 1);
        assert_eq!(restored.fs_capabilities()[0].original, lock_dir);
        assert!(restored.fs_capabilities()[0].is_file);
        assert_eq!(
            restored.fs_capabilities()[0].source,
            CapabilitySource::Profile
        );
        assert!(
            !restored.path_covered(&child),
            "exact-path directory literal must not recursively cover descendants"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_state_rejects_drifted_future_file_path() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("future.lock");

        let state = SandboxState {
            fs: vec![FsCapState {
                original: missing.display().to_string(),
                path: dir
                    .path()
                    .canonicalize()
                    .expect("canonicalize dir")
                    .join("other.lock")
                    .display()
                    .to_string(),
                access: "readwrite".to_string(),
                is_file: true,
                source: Some("profile".to_string()),
                dev: None,
                ino: None,
            }],
            net_blocked: false,
            allowed_commands: vec![],
            blocked_commands: vec![],
            bypass_protection_paths: vec![],
            allowed_domains: vec![],
            domain_endpoints: vec![],
            resource_limits: None,
        };

        let err = state
            .to_caps()
            .expect_err("drifted future file must be rejected");
        assert!(
            format!("{err}").contains("sandbox state path drifted"),
            "error should mention path drift"
        );
    }
}

#[cfg(test)]
mod cap_file_validation_tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};

    /// Write a valid `.nono-<hex>.json` capability file into `dir`.
    fn write_cap_file(dir: &Path) -> PathBuf {
        let caps = CapabilitySet::new().block_network();
        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let path = dir.join(".nono-abcdef0123456789.json");
        state.write_to_file(&path).expect("write cap file");
        path
    }

    #[test]
    fn test_acceptable_temp_roots_non_empty_and_deduped() {
        let roots = acceptable_temp_roots();
        assert!(
            !roots.is_empty(),
            "should have at least one acceptable temp root"
        );
        let mut seen = std::collections::HashSet::new();
        for root in &roots {
            assert!(
                seen.insert(root.clone()),
                "acceptable_temp_roots must not contain duplicates: {roots:?}"
            );
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_acceptable_temp_roots_includes_var_folders_on_macos() {
        let var_folders = PathBuf::from("/var/folders")
            .canonicalize()
            .expect("canonicalize /var/folders");
        let roots = acceptable_temp_roots();
        assert!(
            roots.contains(&var_folders),
            "macOS roots should include {}, got {roots:?}",
            var_folders.display()
        );
    }

    #[test]
    fn test_validate_accepts_file_in_tempdir() {
        let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
        let path = write_cap_file(dir.path());
        let path_str = path.to_str().expect("utf8 path");

        let validated = validate_cap_file_path(path_str).expect("valid cap file accepted");
        let expected = path.canonicalize().expect("canonicalize cap file");
        assert_eq!(validated, expected);
    }

    #[test]
    fn test_validate_accepts_file_when_reading_tmpdir_differs() {
        // Reproduces issue #1054: the file lives under the system temp dir, but
        // the reading process's $TMPDIR points somewhere else. Validation must
        // still accept the file.
        let _lock = ENV_LOCK.lock().expect("env lock");

        // Anchor both directories under `/tmp` explicitly rather than the
        // ambient $TMPDIR. `/tmp` is a hardcoded accepted root, so the test is
        // independent of whatever $TMPDIR the host/CI sets (e.g. a non-standard
        // `/mnt/ephemeral/tmp` would otherwise leave the file under no root once
        // $TMPDIR is overridden, spuriously failing this test).
        let file_dir = tempfile::tempdir_in("/tmp").expect("file tempdir");
        let path = write_cap_file(file_dir.path());
        let path_str = path.to_str().expect("utf8 path").to_string();

        // Point $TMPDIR at a *different* existing directory.
        let other_dir = tempfile::tempdir_in("/tmp").expect("other tempdir");
        let other = other_dir.path().to_str().expect("utf8 other");
        let _env = EnvVarGuard::set_all(&[("TMPDIR", other)]);

        // The cap file's canonical path is not under the overridden $TMPDIR, but
        // it is under the canonicalized `/tmp` root, so it is accepted.
        validate_cap_file_path(&path_str)
            .expect("cap file under a known temp root accepted despite TMPDIR mismatch");
    }

    #[test]
    fn test_validate_rejects_relative_path() {
        let err = validate_cap_file_path(".nono-abcdef0123456789.json")
            .expect_err("relative path rejected");
        assert!(
            format!("{err}").contains("must be absolute"),
            "error should mention absolute path requirement: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_nonexistent_file() {
        let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
        let missing = dir.path().join(".nono-0000000000000000.json");
        let err = validate_cap_file_path(missing.to_str().expect("utf8"))
            .expect_err("nonexistent file rejected");
        assert!(
            format!("{err}").contains("canonicalize"),
            "error should mention canonicalize failure: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_path_outside_temp() {
        // /etc/hosts exists on both macOS and Linux and is outside any temp root.
        if !Path::new("/etc/hosts").exists() {
            return;
        }
        let err = validate_cap_file_path("/etc/hosts").expect_err("path outside temp dir rejected");
        assert!(
            format!("{err}").contains("temp directory"),
            "error should mention temp directory: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_wrong_filename_pattern() {
        // Anchor under `/tmp` so the test is immune to parallel tests that
        // modify `$TMPDIR` — a bare `tempdir()` would inherit the altered
        // `$TMPDIR` and the backing directory may be deleted by the other
        // test's TempDir drop, causing `canonicalize` to fail with ENOENT
        // before the filename-pattern check is reached.
        let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
        let caps = CapabilitySet::new().block_network();
        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let path = dir.path().join("not-a-nono-file.json");
        state.write_to_file(&path).expect("write file");

        let err = validate_cap_file_path(path.to_str().expect("utf8"))
            .expect_err("wrong filename pattern rejected");
        assert!(
            format!("{err}").contains(".nono-"),
            "error should mention filename pattern: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_directory() {
        let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
        let err = validate_cap_file_path(dir.path().to_str().expect("utf8"))
            .expect_err("directory rejected");
        // A directory in a temp root fails the filename-pattern check before the
        // regular-file check; either rejection is acceptable.
        let msg = format!("{err}");
        assert!(
            msg.contains("regular file") || msg.contains(".nono-"),
            "directory should be rejected: {msg}"
        );
    }

    #[test]
    fn test_try_load_returns_none_instead_of_exiting_on_bad_cap_file() {
        // Non-`--self` `nono why` consults the state only for staleness hints;
        // a NONO_CAP_FILE that fails validation or cannot be read must degrade
        // to None (pre-hint behavior), not abort the query like the strict
        // loader does.
        let _lock = match ENV_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Unset: not in a sandbox.
        {
            let env = EnvVarGuard::set_all(&[("NONO_CAP_FILE", "placeholder")]);
            env.remove("NONO_CAP_FILE");
            assert!(try_load_sandbox_state().is_none());
        }

        // Validation failure (wrong location / pattern).
        {
            let _env = EnvVarGuard::set_all(&[("NONO_CAP_FILE", "/etc/hosts")]);
            assert!(try_load_sandbox_state().is_none());
        }

        // Nonexistent file under a valid root.
        {
            let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
            let missing = dir.path().join(".nono-0000000000000000.json");
            let missing_str = missing.to_str().expect("utf8");
            let _env = EnvVarGuard::set_all(&[("NONO_CAP_FILE", missing_str)]);
            assert!(try_load_sandbox_state().is_none());
        }

        // And a valid file still loads. Use env::temp_dir() rather than the
        // /tmp anchor the other tests use: this case reads the file's
        // contents (not just metadata), and sandboxed dev environments may
        // grant /tmp write-only. Holding ENV_LOCK keeps TMPDIR stable here.
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = write_cap_file(dir.path());
            let path_str = path.to_str().expect("utf8");
            let _env = EnvVarGuard::set_all(&[("NONO_CAP_FILE", path_str)]);
            assert!(try_load_sandbox_state().is_some());
        }
    }

    #[test]
    fn resource_limits_round_trip_through_self_state() {
        // Both ceilings must be captured in the self-state, survive the JSON
        // round-trip, and reconstruct into caps so `nono why --self` can report them.
        let caps = CapabilitySet::new().with_resource_limits(nono::ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            max_processes: Some(64),
        });
        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        assert_eq!(
            state.resource_limits.and_then(|l| l.memory_bytes),
            Some(512 * 1024 * 1024)
        );
        assert_eq!(
            state.resource_limits.and_then(|l| l.max_processes),
            Some(64)
        );

        let json = serde_json::to_string(&state).expect("serialize");
        let restored: SandboxState = serde_json::from_str(&json).expect("deserialize");
        let caps2 = restored.to_caps().expect("to_caps");
        assert_eq!(
            caps2.resource_limits().and_then(|l| l.memory_bytes),
            Some(512 * 1024 * 1024)
        );
        assert_eq!(
            caps2.resource_limits().and_then(|l| l.max_processes),
            Some(64)
        );
    }

    #[test]
    fn self_state_without_limits_omits_key_and_is_back_compatible() {
        // With no limit the key is omitted, so this serialized state is identical
        // to one an older nono build (without the field) would have written.
        let state = SandboxState::from_caps(&CapabilitySet::new(), &[], &[], &[]);
        assert!(state.resource_limits.is_none());
        let json = serde_json::to_string(&state).expect("serialize");
        assert!(
            !json.contains("resource_limits"),
            "no-limit state must omit the key, got {json}"
        );

        // That legacy-shaped JSON (no resource_limits key) still loads, defaulting
        // the field to None via #[serde(default)] — the back-compat guarantee.
        let reloaded: SandboxState = serde_json::from_str(&json).expect("loads");
        assert!(reloaded.resource_limits.is_none());
    }
}
