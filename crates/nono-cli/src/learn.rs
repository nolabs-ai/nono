//! Learn mode: trace file accesses and network connections to discover required paths
//!
//! Uses strace (Linux) or fs_usage + nettop (macOS) to monitor a command's file system
//! and network accesses and produces a list of paths and connections that would need
//! to be allowed in a nono profile.

use crate::cli::LearnArgs;
use nono::{try_canonicalize, AccessMode, NonoError, Result};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::profile::{self, Profile};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::HashMap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::HashSet;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::{BufRead, BufReader};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};
#[cfg(target_os = "macos")]
use tracing::{debug, info, warn};

/// Result of learning file access patterns
#[derive(Debug)]
pub struct LearnResult {
    /// Paths that need read access
    pub read_paths: BTreeSet<PathBuf>,
    /// Files that need read access
    pub read_files: BTreeSet<PathBuf>,
    /// Paths that need write access
    pub write_paths: BTreeSet<PathBuf>,
    /// Files that need write access
    pub write_files: BTreeSet<PathBuf>,
    /// Paths that need read+write access
    pub readwrite_paths: BTreeSet<PathBuf>,
    /// Files that need read+write access
    pub readwrite_files: BTreeSet<PathBuf>,
    /// Paths that were accessed but are already covered by system paths
    pub system_covered: BTreeSet<PathBuf>,
    /// Paths that were accessed but are already covered by profile
    pub profile_covered: BTreeSet<PathBuf>,
    /// Outbound network connections observed
    pub outbound_connections: Vec<NetworkConnectionSummary>,
    /// Listening ports observed
    pub listening_ports: Vec<NetworkConnectionSummary>,
}

impl LearnResult {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn new() -> Self {
        Self {
            read_paths: BTreeSet::new(),
            read_files: BTreeSet::new(),
            write_paths: BTreeSet::new(),
            write_files: BTreeSet::new(),
            readwrite_paths: BTreeSet::new(),
            readwrite_files: BTreeSet::new(),
            system_covered: BTreeSet::new(),
            profile_covered: BTreeSet::new(),
            outbound_connections: Vec::new(),
            listening_ports: Vec::new(),
        }
    }

    /// Check if any paths were discovered
    pub fn has_paths(&self) -> bool {
        !self.read_paths.is_empty()
            || !self.read_files.is_empty()
            || !self.write_paths.is_empty()
            || !self.write_files.is_empty()
            || !self.readwrite_paths.is_empty()
            || !self.readwrite_files.is_empty()
    }

    /// Check if any network activity was observed
    pub fn has_network_activity(&self) -> bool {
        !self.outbound_connections.is_empty() || !self.listening_ports.is_empty()
    }

    /// Format as JSON fragment for profile
    pub fn to_json(&self) -> Result<String> {
        let allow: Vec<String> = self
            .readwrite_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let allow_file: Vec<String> = self
            .readwrite_files
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let read: Vec<String> = self
            .read_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let read_file: Vec<String> = self
            .read_files
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let write: Vec<String> = self
            .write_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let write_file: Vec<String> = self
            .write_files
            .iter()
            .map(|p| p.display().to_string())
            .collect();

        let outbound: Vec<serde_json::Value> = self
            .outbound_connections
            .iter()
            .map(|c| {
                let mut obj = serde_json::json!({
                    "addr": c.endpoint.addr.to_string(),
                    "port": c.endpoint.port,
                    "count": c.count,
                });
                if let Some(ref hostname) = c.endpoint.hostname {
                    obj["hostname"] = serde_json::Value::String(hostname.clone());
                }
                obj
            })
            .collect();

        let listening: Vec<serde_json::Value> = self
            .listening_ports
            .iter()
            .map(|c| {
                let mut obj = serde_json::json!({
                    "addr": c.endpoint.addr.to_string(),
                    "port": c.endpoint.port,
                    "count": c.count,
                });
                if let Some(ref hostname) = c.endpoint.hostname {
                    obj["hostname"] = serde_json::Value::String(hostname.clone());
                }
                obj
            })
            .collect();

        let fragment = serde_json::json!({
            "filesystem": {
                "allow": allow,
                "read": read,
                "write": write,
                "allow_file": allow_file,
                "read_file": read_file,
                "write_file": write_file
            },
            "network": {
                "outbound": outbound,
                "listening": listening
            }
        });

        serde_json::to_string_pretty(&fragment)
            .map_err(|e| nono::NonoError::LearnError(format!("Failed to serialize JSON: {}", e)))
    }

    /// Generate a profile patch containing only learned filesystem grants.
    pub fn to_profile_patch(&self) -> Result<Profile> {
        let home = crate::config::validated_home()?;
        let home_path = std::path::Path::new(&home);

        let mut profile = Profile::default();
        profile.filesystem.allow = shortened_paths(&self.readwrite_paths, home_path);
        profile.filesystem.allow_file = shortened_paths(&self.readwrite_files, home_path);
        profile.filesystem.read = shortened_paths(&self.read_paths, home_path);
        profile.filesystem.read_file = shortened_paths(&self.read_files, home_path);
        profile.filesystem.write = shortened_paths(&self.write_paths, home_path);
        profile.filesystem.write_file = shortened_paths(&self.write_files, home_path);
        profile.filesystem.bypass_protection = learned_bypass_protection_paths(self, home_path)?;

        Ok(profile)
    }

    /// Generate a named profile from discovered paths.
    pub fn to_named_profile(
        &self,
        name: &str,
        command: &str,
        extends: Option<Vec<String>>,
    ) -> Result<Profile> {
        let mut profile = self.to_profile_patch()?;
        let has_base = extends.is_some();
        profile.extends = extends;
        profile.meta = profile::ProfileMeta {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: Some(if has_base {
                format!("Learned path additions for {}", command)
            } else {
                format!("Auto-generated profile for {}", command)
            }),
            author: None,
        };

        if !has_base {
            profile.network.block = !self.has_network_activity();
            profile.workdir.access = profile::WorkdirAccess::ReadWrite;
        }

        Ok(profile)
    }

    /// Format as human-readable summary with clear visual separation
    pub fn to_summary(&self) -> String {
        use colored::Colorize;

        let mut lines = Vec::new();
        let separator = "=".repeat(60);

        lines.push(String::new());
        lines.push(format!("{}", separator.dimmed()));
        lines.push(format!("{}", " nono learn - Discovered Paths".bold()));
        lines.push(format!("{}", separator.dimmed()));

        if !self.has_paths() && !self.has_network_activity() {
            lines.push(String::new());
            lines.push("  No additional paths needed.".to_string());
            lines.push(String::new());
            return lines.join("\n");
        }

        push_fs_summary_section(
            &mut lines,
            "READ".cyan().bold(),
            "--read",
            &self.read_paths,
            "--read-file",
            &self.read_files,
        );
        push_fs_summary_section(
            &mut lines,
            "WRITE".yellow().bold(),
            "--write",
            &self.write_paths,
            "--write-file",
            &self.write_files,
        );
        push_fs_summary_section(
            &mut lines,
            "READ+WRITE".green().bold(),
            "--allow",
            &self.readwrite_paths,
            "--allow-file",
            &self.readwrite_files,
        );

        if !self.system_covered.is_empty() || !self.profile_covered.is_empty() {
            lines.push(String::new());
            if !self.system_covered.is_empty() {
                lines.push(format!(
                    " {} {} paths already covered by system defaults",
                    "i".dimmed(),
                    self.system_covered.len()
                ));
            }
            if !self.profile_covered.is_empty() {
                lines.push(format!(
                    " {} {} paths already covered by profile",
                    "i".dimmed(),
                    self.profile_covered.len()
                ));
            }
        }

        // Network sections
        if !self.outbound_connections.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                " {} ({} endpoints)",
                "OUTBOUND NETWORK".magenta().bold(),
                self.outbound_connections.len()
            ));
            lines.push(format!(" {}", "-".repeat(40).dimmed()));
            for conn in &self.outbound_connections {
                lines.push(format_network_summary(conn));
            }
        }

        if !self.listening_ports.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                " {} ({} ports)",
                "LISTENING PORTS".magenta().bold(),
                self.listening_ports.len()
            ));
            lines.push(format!(" {}", "-".repeat(40).dimmed()));
            for conn in &self.listening_ports {
                lines.push(format_network_summary(conn));
            }
        }

        lines.push(String::new());
        lines.push(format!("{}", separator.dimmed()));

        lines.join("\n")
    }
}

fn push_fs_summary_section(
    lines: &mut Vec<String>,
    label: colored::ColoredString,
    dir_flag: &str,
    dir_paths: &BTreeSet<PathBuf>,
    file_flag: &str,
    file_paths: &BTreeSet<PathBuf>,
) {
    use colored::Colorize;

    let count = dir_paths.len() + file_paths.len();
    if count == 0 {
        return;
    }

    lines.push(String::new());
    lines.push(format!(" {} ({} grants)", label, count));
    lines.push(format!(" {}", "-".repeat(40).dimmed()));
    for path in dir_paths {
        lines.push(format!("  {} {}", dir_flag, path.display()));
    }
    for path in file_paths {
        lines.push(format!("  {} {}", file_flag, path.display()));
    }
}

fn shortened_paths(paths: &BTreeSet<PathBuf>, home_path: &Path) -> Vec<String> {
    paths
        .iter()
        .map(|path| crate::profile_save_runtime::shorten_path_for_profile(path, home_path))
        .collect()
}

fn learned_bypass_protection_paths(result: &LearnResult, home_path: &Path) -> Result<Vec<String>> {
    let mut bypass_protection = Vec::new();

    for path in result
        .readwrite_paths
        .iter()
        .chain(result.readwrite_files.iter())
        .chain(result.read_paths.iter())
        .chain(result.read_files.iter())
        .chain(result.write_paths.iter())
        .chain(result.write_files.iter())
    {
        let shortened = crate::profile_save_runtime::shorten_path_for_profile(path, home_path);
        if crate::config::check_sensitive_path(&shortened)?.is_some()
            && !bypass_protection.contains(&shortened)
        {
            bypass_protection.push(shortened);
        }
    }

    Ok(bypass_protection)
}

pub(crate) fn merge_learned_profile_patch(profile: &mut Profile, patch: &Profile) {
    crate::profile_save_runtime::merge_profile_patch(profile, patch);
}

/// Format a single network connection summary line
fn format_network_summary(conn: &NetworkConnectionSummary) -> String {
    let count_str = if conn.count > 1 {
        format!(" ({}x)", conn.count)
    } else {
        String::new()
    };

    if let Some(ref hostname) = conn.endpoint.hostname {
        format!(
            "  {} ({}):{}{}",
            hostname, conn.endpoint.addr, conn.endpoint.port, count_str
        )
    } else {
        format!(
            "  {}:{}{}",
            conn.endpoint.addr, conn.endpoint.port, count_str
        )
    }
}

/// Check if strace is available
#[cfg(target_os = "linux")]
fn check_strace() -> Result<()> {
    match Command::new("strace").arg("--version").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(NonoError::LearnError(
            "strace not found. Install with: apt install strace".to_string(),
        )),
    }
}

/// Run learn mode (unsupported platform stub)
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn run_learn(_args: &LearnArgs) -> Result<LearnResult> {
    Err(NonoError::LearnError(
        "nono learn is only available on Linux (strace) and macOS (fs_usage)".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// macOS implementation (fs_usage)
// ---------------------------------------------------------------------------

/// Check if fs_usage is available
#[cfg(target_os = "macos")]
fn check_fs_usage() -> Result<()> {
    if std::path::Path::new("/usr/bin/fs_usage").exists() {
        Ok(())
    } else {
        Err(NonoError::LearnError(
            "fs_usage not found at /usr/bin/fs_usage".to_string(),
        ))
    }
}

/// Acquire sudo credentials before spawning the child command.
///
/// `sudo -v` validates and caches credentials while the terminal is still
/// available for password input. Without this, TUI applications paint over
/// the sudo password prompt making it impossible to authenticate.
#[cfg(target_os = "macos")]
fn acquire_sudo() -> Result<()> {
    let status = Command::new("sudo")
        .arg("-v")
        .status()
        .map_err(|e| NonoError::LearnError(format!("Failed to run sudo: {}", e)))?;

    if !status.success() {
        return Err(NonoError::LearnError(
            "Failed to acquire sudo credentials. fs_usage requires root access.".to_string(),
        ));
    }
    Ok(())
}

/// Run learn mode (macOS implementation)
#[cfg(target_os = "macos")]
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    check_fs_usage()?;
    acquire_sudo()?;

    // Load profile if specified
    let profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name)?)
    } else {
        None
    };

    // Run fs_usage (filesystem) and nettop (network) concurrently
    let (file_accesses, network_accesses) = run_fs_usage_and_nettop(&args.command, args.timeout)?;

    // Process and categorize file paths
    let mut result = process_accesses(file_accesses, profile.as_ref(), args.all)?;

    // Process network accesses with reverse DNS (no forward DNS correlation on macOS
    // since we don't have DNS query interception like strace provides)
    let (outbound, listening) = process_network_accesses(network_accesses, vec![], !args.no_rdns);
    result.outbound_connections = outbound;
    result.listening_ports = listening;

    Ok(result)
}

/// Run fs_usage (filesystem) and nettop (network) concurrently to trace a command.
///
/// Starts `sudo fs_usage` first (while the terminal is clean), then spawns
/// the target command, then starts nettop filtered by the child's PID.
/// fs_usage is started before the child to avoid missing early filesystem
/// activity. nettop is started after the child because it requires a numeric
/// PID to follow the entire process tree (capturing subprocesses like `node`
/// spawned by wrapper binaries).
///
/// nettop runs in CSV logging mode (`-L 0`) polling at 1-second intervals.
#[cfg(target_os = "macos")]
fn run_fs_usage_and_nettop(
    command: &[String],
    timeout: Option<u64>,
) -> Result<(Vec<FileAccess>, Vec<NetworkAccess>)> {
    use std::time::Duration;

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    // Extract the command basename for fs_usage's process name filter.
    // fs_usage matches against the kernel process name, which is the
    // resolved binary name — not the symlink name. For example,
    // `.venv/bin/python3` may resolve to `python3.11` via a symlink chain.
    // We must follow symlinks to get the actual binary name.
    let cmd_path = std::path::Path::new(&command[0]);
    let resolved_path = std::fs::canonicalize(cmd_path).unwrap_or_else(|_| cmd_path.to_path_buf());
    let cmd_name = resolved_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| NonoError::LearnError("Invalid command name".to_string()))?;

    // Validate cmd_name: must be a simple process name (alphanumeric, hyphens,
    // underscores, dots). Reject wildcards or shell metacharacters to prevent
    // fs_usage from matching unintended processes.
    if !cmd_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(NonoError::LearnError(format!(
            "Command name '{}' contains invalid characters for fs_usage filter",
            cmd_name
        )));
    }

    // Start fs_usage FIRST — before the child command.
    // This ensures the sudo prompt (if needed) appears on a clean terminal,
    // not hidden behind a TUI.
    //
    // fs_usage fully buffers stdout when writing to a pipe, so trace data
    // accumulates in an internal buffer and is lost when fs_usage is killed
    // via SIGTERM. To work around this, we redirect output to a temp file
    // via shell-level redirection inside sudo, then read the file after
    // fs_usage exits.
    let fs_usage_outfile = tempfile::NamedTempFile::new().map_err(|e| {
        NonoError::LearnError(format!("Failed to create temp file for fs_usage: {e}"))
    })?;
    let fs_usage_out_path = fs_usage_outfile.path().to_path_buf();

    let fs_usage_errfile = tempfile::NamedTempFile::new().map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to create temp file for fs_usage stderr: {e}"
        ))
    })?;
    let fs_usage_err_path = fs_usage_errfile.path().to_path_buf();

    let mut fs_usage = Command::new("sudo")
        .args([
            "bash",
            "-c",
            &format!(
                "exec fs_usage -w -f filesys -f pathname {} > '{}' 2> '{}'",
                cmd_name,
                fs_usage_out_path.display(),
                fs_usage_err_path.display()
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            NonoError::LearnError(format!("Failed to spawn fs_usage (sudo required): {}", e))
        })?;

    // Wait for fs_usage to attach the kernel trace facility before
    // spawning the child. A fixed sleep is acceptable here: the previous
    // pipe+peek approach was unreliable due to stdout buffering.
    std::thread::sleep(Duration::from_secs(2));

    // Now spawn the target command
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| NonoError::LearnError(format!("Failed to spawn command: {}", e)))?;

    let child_pid = child.id();
    debug!("Spawned child process with PID {}", child_pid);

    // Start nettop AFTER the child so we can filter by PID. nettop with a
    // numeric PID follows the process tree, capturing network activity from
    // the child and all its descendants (e.g. node spawned by claude).
    let nettop_result = start_nettop(child_pid);
    let (nettop_process, nettop_reader_handle) = match nettop_result {
        Ok((proc, handle)) => (Some(proc), Some(handle)),
        Err(e) => {
            info!("nettop unavailable, skipping network tracing: {}", e);
            (None, None)
        }
    };

    // Wait for child to exit. Use a dedicated thread for timeout so
    // the main thread can block on child.wait() instead of polling.
    let timeout_duration = timeout.map(Duration::from_secs);
    if let Some(timeout) = timeout_duration {
        let child_id = child.id();
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            warn!("Timeout reached, sending SIGTERM to child PID {}", child_id);
            // SAFETY: sending a signal to a known child PID. If the process
            // has already exited, kill() returns ESRCH which we ignore.
            unsafe {
                nix::libc::kill(child_id as i32, nix::libc::SIGTERM);
            }
            // Grace period: if the child ignores SIGTERM, escalate to SIGKILL
            std::thread::sleep(Duration::from_secs(3));
            unsafe {
                nix::libc::kill(child_id as i32, nix::libc::SIGKILL);
            }
        });
    }
    let _ = child.wait();
    debug!("Child process exited");

    // Kill fs_usage. The sudo bash wrapper spawns fs_usage as a child,
    // so we kill both the wrapper and its children.
    kill_fs_usage(&fs_usage);
    let _ = fs_usage.wait();

    // Kill nettop if it was started
    if let Some(mut nettop) = nettop_process {
        let _ = nettop.kill();
        let _ = nettop.wait();
    }

    // Check fs_usage stderr for errors
    if let Ok(err_content) = std::fs::read_to_string(&fs_usage_err_path) {
        let trimmed = err_content.trim();
        if !trimmed.is_empty() {
            debug!("fs_usage stderr: {}", trimmed);
        }
    }

    // Read fs_usage output from the temp file
    let file_accesses = {
        let file = std::fs::File::open(&fs_usage_out_path)
            .map_err(|e| NonoError::LearnError(format!("Failed to read fs_usage output: {e}")))?;
        let reader = BufReader::new(file);
        let mut accesses = Vec::new();
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if let Some(access) = parse_fs_usage_line(&l) {
                        accesses.push(access);
                    }
                }
                Err(e) => {
                    debug!("Error reading fs_usage line: {}", e);
                }
            }
        }
        debug!(
            "Parsed {} file accesses from fs_usage output",
            accesses.len()
        );
        accesses
    };

    // Collect network results from nettop reader thread
    let network_accesses = match nettop_reader_handle {
        Some(handle) => match handle.join() {
            Ok(accesses) => accesses,
            Err(_) => {
                warn!("nettop reader thread panicked, returning partial results");
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    Ok((file_accesses, network_accesses))
}

/// Start nettop in CSV logging mode to trace network connections for a process tree.
///
/// Uses a numeric PID filter (`-p <pid>`) which causes nettop to follow the
/// entire process tree rooted at that PID, capturing network activity from
/// the child and all its descendants.
///
/// Returns the nettop child process and a thread handle that produces results.
#[cfg(target_os = "macos")]
fn start_nettop(
    child_pid: u32,
) -> Result<(
    std::process::Child,
    std::thread::JoinHandle<Vec<NetworkAccess>>,
)> {
    let pid_str = child_pid.to_string();
    let mut nettop = Command::new("nettop")
        .args([
            "-L", "0",  // Unlimited samples (CSV logging mode)
            "-n", // Numeric addresses (no DNS resolution)
            "-p", &pid_str, // Filter by child PID (follows process tree)
            "-s", "1", // 1-second polling interval
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| NonoError::LearnError(format!("Failed to spawn nettop: {}", e)))?;

    let nettop_stdout = nettop
        .stdout
        .take()
        .ok_or_else(|| NonoError::LearnError("Failed to capture nettop stdout".to_string()))?;

    let reader_handle = std::thread::spawn(move || {
        let reader = BufReader::new(nettop_stdout);
        let mut accesses = Vec::new();
        // Track seen connections to avoid duplicates from repeated polling
        let mut seen: HashSet<(IpAddr, u16, bool)> = HashSet::new();
        // Track listening ports to avoid misclassifying accepted connections
        let mut listening_ports: HashSet<u16> = HashSet::new();

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    debug!("Error reading nettop line: {}", e);
                    continue;
                }
            };

            if let Some(access) = parse_nettop_line(&line, &listening_ports) {
                let is_bind = matches!(access.kind, NetworkAccessKind::Bind);
                if is_bind {
                    listening_ports.insert(access.port);
                }
                let key = (access.addr, access.port, is_bind);
                if seen.insert(key) {
                    accesses.push(access);
                }
            }
        }

        accesses
    });

    Ok((nettop, reader_handle))
}

/// Parse a nettop CSV line to extract network connection information.
///
/// nettop CSV format (with -L flag):
/// ```text
/// time,,interface,state,...
/// 06:54:20.708439,apsd.358,,,179190,282920,...          <- process summary (skip)
/// 06:54:20.707620,tcp4 192.168.178.103:63660<->17.57.146.10:5223,en0,Established,...  <- connection
/// 06:54:20.706434,tcp4 127.0.0.1:8021<->*:*,lo0,Listen,...  <- listening
/// 06:54:20.700522,udp4 *:56734<->*:*,lo0,,,...          <- UDP bind
/// ```
///
/// Connection field format: `proto local_addr:port<->remote_addr:port`
/// For IPv6: `tcp6 [::1]:port<->*:*` or `tcp6 addr.port<->addr.port`
/// (nettop uses `.` as port separator for IPv6)
///
/// `listening_ports` tracks ports already seen in Listen state. Established
/// connections whose local port matches a known listener are server-side
/// accepted connections (inbound), not outbound — they are skipped to avoid
/// polluting the learned policy with client ephemeral ports.
#[cfg(target_os = "macos")]
fn parse_nettop_line(line: &str, listening_ports: &HashSet<u16>) -> Option<NetworkAccess> {
    let fields: Vec<&str> = line.split(',').collect();
    if fields.len() < 4 {
        return None;
    }

    let conn_field = fields[1].trim();

    // Must start with a protocol prefix to be a connection line
    if !conn_field.starts_with("tcp4 ")
        && !conn_field.starts_with("tcp6 ")
        && !conn_field.starts_with("udp4 ")
        && !conn_field.starts_with("udp6 ")
    {
        return None;
    }

    let state = fields[3].trim();

    // Split off the protocol prefix
    let addr_part = &conn_field[5..]; // skip "tcp4 " or similar

    // Split on "<->" to get local and remote parts
    let parts: Vec<&str> = addr_part.split("<->").collect();
    if parts.len() != 2 {
        return None;
    }

    let local_part = parts[0];
    let remote_part = parts[1];
    let is_ipv6 = conn_field.starts_with("tcp6 ") || conn_field.starts_with("udp6 ");

    // Determine connection type based on state and remote address
    if state == "Listen" || remote_part == "*:*" || remote_part == "*.*" {
        // Listening socket — extract local address and port
        let (addr, port) = parse_nettop_endpoint(local_part, is_ipv6)?;

        // Skip wildcard listeners on port 0
        if port == 0 {
            return None;
        }

        Some(NetworkAccess {
            addr,
            port,
            kind: NetworkAccessKind::Bind,
            queried_hostname: None,
        })
    } else if state == "Established" || !remote_part.contains('*') {
        // Check if this is a server-side accepted connection (inbound) rather
        // than an outbound connection. If the local port matches a known
        // listening port, this is an accepted client connection — the remote
        // address is the client, not a server we're connecting to.
        if let Some((_, local_port)) = parse_nettop_endpoint(local_part, is_ipv6) {
            if listening_ports.contains(&local_port) {
                return None;
            }
        }

        // Outbound connection — extract remote address and port
        let (addr, port) = parse_nettop_endpoint(remote_part, is_ipv6)?;

        // Skip port 0
        if port == 0 {
            return None;
        }

        // Skip loopback addresses (local IPC, not external network)
        if addr.is_loopback() {
            return None;
        }

        Some(NetworkAccess {
            addr,
            port,
            kind: NetworkAccessKind::Connect,
            queried_hostname: None,
        })
    } else {
        None
    }
}

/// Parse a nettop address:port endpoint string.
///
/// IPv4 format: `192.168.1.1:443` or `*:8080`
/// IPv6 format: `::1.443` or `fe80::1%en0.443` (nettop uses `.` as port separator for IPv6)
#[cfg(target_os = "macos")]
fn parse_nettop_endpoint(endpoint: &str, is_ipv6: bool) -> Option<(IpAddr, u16)> {
    if endpoint == "*:*" || endpoint == "*.*" {
        return None;
    }

    if is_ipv6 {
        // IPv6: port is after the last '.' (nettop uses dot separator for IPv6)
        // Handle scope IDs like %en0 by stripping them first
        if let Some(pct_pos) = endpoint.find('%') {
            // Find the dot-port after the scope ID: "fe80::1%en0.443" -> strip "%en0"
            let after_scope = &endpoint[pct_pos..];
            if let Some(dot_pos) = after_scope.rfind('.') {
                let port_str = &after_scope[dot_pos + 1..];
                let addr_str = &endpoint[..pct_pos];
                return parse_addr_port_pair(addr_str, port_str);
            }
            return None;
        }

        // No scope ID, find the last '.' which separates address from port
        let dot_pos = endpoint.rfind('.')?;
        let addr_str = &endpoint[..dot_pos];
        let port_str = &endpoint[dot_pos + 1..];
        parse_addr_port_pair(addr_str, port_str)
    } else {
        // IPv4: standard addr:port format
        // Handle wildcard address
        let colon_pos = endpoint.rfind(':')?;
        let addr_str = &endpoint[..colon_pos];
        let port_str = &endpoint[colon_pos + 1..];

        if addr_str == "*" {
            let port: u16 = port_str.parse().ok()?;
            // Use 0.0.0.0 for wildcard
            Some(("0.0.0.0".parse().ok()?, port))
        } else {
            parse_addr_port_pair(addr_str, port_str)
        }
    }
}

/// Parse an address string and port string into (IpAddr, u16).
#[cfg(target_os = "macos")]
fn parse_addr_port_pair(addr_str: &str, port_str: &str) -> Option<(IpAddr, u16)> {
    let port: u16 = port_str.parse().ok()?;
    let addr: IpAddr = addr_str.parse().ok()?;
    Some((addr, port))
}

/// Kill an fs_usage process tree running under sudo.
///
/// `fs_usage.id()` returns the PID of the `sudo` wrapper, not fs_usage itself.
/// We use `sudo pkill -P <sudo_pid>` to kill child processes (the actual
/// fs_usage), then kill the sudo wrapper. Failures are ignored since the
/// processes may have already exited.
#[cfg(target_os = "macos")]
fn kill_fs_usage(fs_usage: &std::process::Child) {
    let sudo_pid = fs_usage.id().to_string();
    // Kill children of the sudo process (the actual fs_usage)
    let _ = Command::new("sudo")
        .args(["pkill", "-P", &sudo_pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // Then kill the sudo wrapper itself
    let _ = Command::new("sudo")
        .args(["kill", &sudo_pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Parse a single fs_usage output line to extract file access information
///
/// fs_usage -w output format (wide mode):
/// ```text
/// 14:23:45.123456  open              /path/to/file    0.000012  ProcessName.123
/// 14:23:45.123456  stat64            /path/to/file    0.000003  ProcessName.123
/// 14:23:45.123456  getattrlist       /path/to/file    0.000005  ProcessName.123
/// ```
///
/// The path is between the operation name and the elapsed time.
/// Some lines include file descriptors like `F=5` or byte counts like `B=4096`.
#[cfg(target_os = "macos")]
fn parse_fs_usage_line(line: &str) -> Option<FileAccess> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Split into whitespace-delimited tokens
    // Format: TIMESTAMP  OPERATION  [F=n]  [(FLAGS)]  PATH  ELAPSED  PROCESS.tid
    // The path starts with '/' and is the key field we need to extract
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();

    // Need at least: timestamp, operation, path, elapsed, process
    if tokens.len() < 4 {
        return None;
    }

    // Token 0 = timestamp (HH:MM:SS.microseconds)
    // Token 1 = operation name
    let operation = tokens[1];

    // Skip operations we don't care about
    let tracked_ops = [
        "open",
        "open_nocancel",
        "stat64",
        "stat64_extended",
        "lstat64",
        "lstat64_extended",
        "getattrlist",
        "getxattr",
        "listxattr",
        "readlink",
        "access",
        "access_extended",
        "execve",
        "posix_spawn",
        "mkdir",
        "mkdir_extended",
        "rename",
        "unlink",
        "rmdir",
        "link",
        "symlink",
        "write",
        "write_nocancel",
        "pwrite",
        "ftruncate",
        "truncate",
    ];

    if !tracked_ops.contains(&operation) {
        return None;
    }

    // Find the path — look for a token starting with '/'
    // Path can contain spaces, so we need to be careful.
    // Strategy: find the first token starting with '/' and collect until
    // we hit what looks like the elapsed time (a decimal number at end of line)
    let path = extract_fs_usage_path(trimmed)?;

    // Skip pseudo-paths and kernel internals
    if path.starts_with("/dev/") || path == "/dev" {
        return None;
    }

    // Determine if this is a write operation
    let is_write = is_fs_usage_write(operation, trimmed);

    Some(FileAccess {
        path: PathBuf::from(path),
        is_write,
    })
}

/// Extract the file path from an fs_usage line
///
/// Paths start with '/' and may contain spaces. The path is followed by
/// the elapsed time (a decimal number) and the process name.
#[cfg(target_os = "macos")]
fn extract_fs_usage_path(line: &str) -> Option<String> {
    // Find the first '/' that starts a path
    // Skip any '/' that appears inside timestamps or other fields
    let path_start = line.find("  /")?;
    let path_region = &line[path_start..].trim_start();

    // The path ends before the elapsed time, which is a decimal number
    // Pattern: /some/path    0.000123   ProcessName.tid
    // We look for the last sequence of: whitespace + decimal number + whitespace
    // Working backwards from the end to find the elapsed time

    // Find the path by looking for the pattern: spaces + digits.digits + spaces
    // The elapsed time is always in the format N.NNNNNN
    let mut end = path_region.len();

    // Scan backwards to find the elapsed time field
    // The line ends with: ELAPSED_TIME  PROCESS_NAME
    // or: ELAPSED_TIME W PROCESS_NAME (W = was scheduled out)
    // We need to find where the path ends (before trailing whitespace + elapsed time)

    // Find the last occurrence of a path-like region
    // Strategy: find sequences that match elapsed time pattern (digits.digits)
    // and take everything before the whitespace preceding it as the path
    for (i, window) in path_region.as_bytes().windows(3).enumerate().rev() {
        // Look for pattern: space + digit + '.'  (start of elapsed time like " 0.000123")
        if window[0] == b' ' && window[1].is_ascii_digit() && window[2] == b'.' {
            // Verify this is actually an elapsed time by checking more context
            let candidate = &path_region[i + 1..];
            if candidate.split_whitespace().next().is_some_and(|s| {
                s.contains('.') && s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            }) {
                end = i;
                break;
            }
        }
    }

    let path = path_region[..end].trim_end();
    if path.is_empty() || !path.starts_with('/') {
        return None;
    }

    // Handle paths with [errno] annotations like "/path/to/file  [2]"
    // Strip trailing bracketed errno
    let path = if let Some(bracket_pos) = path.rfind("  [") {
        path[..bracket_pos].trim_end()
    } else {
        path
    };

    Some(path.to_string())
}

/// Determine if an fs_usage operation represents a write access
#[cfg(target_os = "macos")]
fn is_fs_usage_write(operation: &str, line: &str) -> bool {
    match operation {
        "mkdir" | "mkdir_extended" | "rename" | "unlink" | "rmdir" | "link" | "symlink"
        | "write" | "write_nocancel" | "pwrite" | "ftruncate" | "truncate" => true,
        "open" | "open_nocancel" => {
            // Check for write flags in the line
            // fs_usage shows flags like (RW____) or (W_____) or O_WRONLY etc.
            line.contains("(W")
                || line.contains("O_WRONLY")
                || line.contains("O_RDWR")
                || line.contains("O_CREAT")
                || line.contains("O_TRUNC")
        }
        _ => false,
    }
}

/// Run learn mode (Linux implementation)
#[cfg(target_os = "linux")]
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    check_strace()?;

    // Load profile if specified
    let profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name)?)
    } else {
        None
    };

    // Run strace and collect file accesses, network accesses, and DNS queries
    let (raw_file_accesses, raw_network_accesses, dns_queries) =
        run_strace(&args.command, args.timeout)?;

    // Process and categorize file paths
    let mut result = process_accesses(raw_file_accesses, profile.as_ref(), args.all)?;

    // Process network accesses with forward DNS correlation
    let (outbound, listening) =
        process_network_accesses(raw_network_accesses, dns_queries, !args.no_rdns);
    result.outbound_connections = outbound;
    result.listening_ports = listening;

    Ok(result)
}

/// Represents a file access observed by tracing
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct FileAccess {
    path: PathBuf,
    is_write: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LearnedPathEntry {
    access: AccessMode,
    is_file: bool,
}

/// Kind of network access observed via tracing
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
enum NetworkAccessKind {
    Connect,
    Bind,
}

/// A single network access observed via tracing
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct NetworkAccess {
    addr: IpAddr,
    port: u16,
    kind: NetworkAccessKind,
    /// Hostname from the most recent DNS query (timing-based correlation)
    queried_hostname: Option<String>,
}

/// A resolved network endpoint with optional reverse DNS hostname
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkEndpoint {
    pub addr: IpAddr,
    pub port: u16,
    pub hostname: Option<String>,
}

/// Summary of connections to a single endpoint (with count)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkConnectionSummary {
    pub endpoint: NetworkEndpoint,
    pub count: usize,
}

/// Unified type for parsed strace accesses
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
enum TracedAccess {
    File(FileAccess),
    Network(NetworkAccess),
    DnsQuery(String),
}

/// Run strace on the command and collect file accesses, network accesses, and DNS queries
#[cfg(target_os = "linux")]
fn run_strace(
    command: &[String],
    timeout: Option<u64>,
) -> Result<(Vec<FileAccess>, Vec<NetworkAccess>, Vec<String>)> {
    use std::time::{Duration, Instant};

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut strace_args = vec![
        "-f".to_string(),  // Follow forks
        "-s".to_string(),  // Increase max string size for DNS packet capture
        "256".to_string(),
        "-e".to_string(),  // Trace these syscalls
        "openat,open,access,stat,lstat,readlink,execve,creat,mkdir,rename,unlink,connect,bind,sendto,sendmsg"
            .to_string(),
        "-o".to_string(),
        "/dev/stderr".to_string(), // Output to stderr so we can capture it
        "--".to_string(),
    ];
    strace_args.extend(command.iter().cloned());

    info!("Running strace with args: {:?}", strace_args);

    let mut child = Command::new("strace")
        .args(&strace_args)
        .stdout(Stdio::inherit()) // Let command output go to terminal
        .stderr(Stdio::piped()) // Capture strace output
        .spawn()
        .map_err(|e| NonoError::LearnError(format!("Failed to spawn strace: {}", e)))?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| NonoError::LearnError("Failed to capture strace stderr".to_string()))?;

    let start = Instant::now();
    let timeout_duration = timeout.map(Duration::from_secs);

    let mut file_accesses = Vec::new();
    let mut network_accesses = Vec::new();
    let mut dns_queries = Vec::new();
    // Track the most recently queried hostname per PID for timing-based
    // correlation. strace -f interleaves output from multiple PIDs, so a
    // global "last hostname" would incorrectly pair a DNS query from one
    // thread with a connect() from another.
    let mut pid_hostnames: HashMap<u32, String> = HashMap::new();
    let reader = BufReader::new(stderr);

    for line in reader.lines() {
        // Check timeout
        if let Some(timeout) = timeout_duration {
            if start.elapsed() > timeout {
                warn!("Timeout reached, killing child process");
                let _ = child.kill();
                break;
            }
        }

        let line = match line {
            Ok(l) => l,
            Err(e) => {
                debug!("Error reading strace line: {}", e);
                continue;
            }
        };

        let pid = extract_strace_pid(&line);

        // Parse strace output
        if let Some(access) = parse_strace_line(&line) {
            match access {
                TracedAccess::File(fa) => file_accesses.push(fa),
                TracedAccess::Network(mut na) => {
                    na.queried_hostname =
                        pid.and_then(|p| pid_hostnames.get(&p).cloned())
                            .or_else(|| {
                                // Fallback for single-process traces (no PID prefix)
                                if pid.is_none() && pid_hostnames.len() == 1 {
                                    pid_hostnames.values().next().cloned()
                                } else {
                                    None
                                }
                            });
                    network_accesses.push(na);
                }
                TracedAccess::DnsQuery(hostname) => {
                    if let Some(p) = pid {
                        pid_hostnames.insert(p, hostname.clone());
                    } else if pid_hostnames.is_empty() {
                        // Single-process trace with no PID prefix: use PID 0 as sentinel
                        pid_hostnames.insert(0, hostname.clone());
                    }
                    dns_queries.push(hostname);
                }
            }
        }
    }

    // Wait for child to finish
    let _ = child.wait();

    Ok((file_accesses, network_accesses, dns_queries))
}

/// Extract the PID from a strace line with `-f` (follow forks).
///
/// strace prefixes multi-process lines with `[pid NNNNN] `. Returns None
/// for single-process traces (no prefix).
#[cfg(target_os = "linux")]
fn extract_strace_pid(line: &str) -> Option<u32> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("[pid ")?;
    let end = rest.find(']')?;
    rest[..end].trim().parse().ok()
}

/// Parse a single strace line to extract file or network access
#[cfg(target_os = "linux")]
fn parse_strace_line(line: &str) -> Option<TracedAccess> {
    // strace output format examples:
    // openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
    // openat(AT_FDCWD, "/tmp/foo", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
    // access("/etc/ld.so.preload", R_OK) = -1 ENOENT
    // stat("/usr/bin/bash", {st_mode=...) = 0
    // execve("/usr/bin/ls", ["ls"], ...) = 0
    // connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
    // bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
    // sendto(5, "\xab\x12...\7example\3com\0...", 29, 0, {sa_family=AF_INET, sin_port=htons(53), ...}, 16) = 29

    // DNS/resolver query detection via sendto or sendmsg
    if line.contains("sendto(") || line.contains("sendmsg(") {
        if let Some(hostname) = parse_dns_sendto(line) {
            return Some(TracedAccess::DnsQuery(hostname));
        }
        // Check for systemd-resolved Varlink JSON protocol
        if let Some(hostname) = parse_resolved_sendto(line) {
            return Some(TracedAccess::DnsQuery(hostname));
        }
        return None;
    }

    // Network syscalls
    let network_syscalls = ["connect", "bind"];
    for &syscall in &network_syscalls {
        if line.contains(&format!("{}(", syscall)) {
            let kind = match syscall {
                "connect" => NetworkAccessKind::Connect,
                _ => NetworkAccessKind::Bind,
            };
            if let Some(na) = parse_network_syscall(line, kind) {
                return Some(TracedAccess::Network(na));
            }
            return None;
        }
    }

    // File syscalls
    let file_syscalls = [
        "openat", "open", "access", "stat", "lstat", "readlink", "execve", "creat", "mkdir",
        "rename", "unlink",
    ];

    let syscall = file_syscalls
        .iter()
        .find(|&s| line.contains(&format!("{}(", s)))?;

    // Extract the path from the syscall
    let path = extract_path_from_syscall(line, syscall)?;

    // Determine if this is a write access
    let is_write = is_write_access(line, syscall);

    // Filter out invalid paths
    if path.is_empty() || path == "." || path == ".." {
        return None;
    }

    Some(TracedAccess::File(FileAccess {
        path: PathBuf::from(path),
        is_write,
    }))
}

/// Extract path from strace syscall line
#[cfg(target_os = "linux")]
fn extract_path_from_syscall(line: &str, syscall: &str) -> Option<String> {
    // Find the opening paren after syscall
    let start_idx = line.find(&format!("{}(", syscall))?;
    let after_paren = &line[start_idx + syscall.len() + 1..];

    // For openat, skip AT_FDCWD
    let path_start = if syscall == "openat" {
        // Skip "AT_FDCWD, " or similar
        if let Some(comma_idx) = after_paren.find(',') {
            comma_idx + 2 // Skip ", "
        } else {
            return None;
        }
    } else {
        0
    };

    let remaining = &after_paren[path_start..];

    // Path should be in quotes
    if !remaining.starts_with('"') {
        return None;
    }

    // Find closing quote
    let end_quote = remaining[1..].find('"')?;
    let path = &remaining[1..end_quote + 1];

    // Unescape C-style escapes from strace output
    let path = unescape_strace_string(path);

    Some(path)
}

/// Unescape C-style escape sequences from strace output.
/// Handles: \n \t \r \\ \" \0 \xNN (hex) \NNN (octal)
///
/// Invalid or incomplete escape sequences are passed through literally
/// to avoid data loss.
#[cfg(target_os = "linux")]
fn unescape_strace_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('n') => {
                    chars.next();
                    result.push('\n');
                }
                Some('t') => {
                    chars.next();
                    result.push('\t');
                }
                Some('r') => {
                    chars.next();
                    result.push('\r');
                }
                Some('\\') => {
                    chars.next();
                    result.push('\\');
                }
                Some('"') => {
                    chars.next();
                    result.push('"');
                }
                Some(c) if ('0'..='7').contains(c) => {
                    // Octal escape \NNN (1-3 digits, including \0 for null)
                    let mut octal = String::new();
                    while octal.len() < 3 && chars.peek().is_some_and(|c| ('0'..='7').contains(c)) {
                        if let Some(c) = chars.next() {
                            octal.push(c);
                        }
                    }
                    if let Ok(val) = u8::from_str_radix(&octal, 8) {
                        result.push(val as char);
                    } else {
                        // Malformed octal - pass through literally
                        result.push('\\');
                        result.push_str(&octal);
                    }
                }
                Some('x') => {
                    chars.next(); // consume 'x'
                                  // Hex escape \xNN - must have exactly 2 hex digits
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                            if let Some(c) = chars.next() {
                                hex.push(c);
                            }
                        } else {
                            break;
                        }
                    }
                    if hex.len() == 2 {
                        if let Ok(val) = u8::from_str_radix(&hex, 16) {
                            result.push(val as char);
                        } else {
                            // Malformed hex - pass through literally
                            result.push('\\');
                            result.push('x');
                            result.push_str(&hex);
                        }
                    } else {
                        // Invalid/incomplete hex escape - pass through literally
                        result.push('\\');
                        result.push('x');
                        result.push_str(&hex);
                    }
                }
                _ => {
                    // Unknown escape, keep as-is
                    result.push('\\');
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Determine if a syscall represents a write access
#[cfg(target_os = "linux")]
fn is_write_access(line: &str, syscall: &str) -> bool {
    match syscall {
        "creat" | "mkdir" | "unlink" | "rename" => true,
        "openat" | "open" => {
            // Check flags for write intent
            line.contains("O_WRONLY")
                || line.contains("O_RDWR")
                || line.contains("O_CREAT")
                || line.contains("O_TRUNC")
        }
        _ => false,
    }
}

/// Process raw accesses into categorized result
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn process_accesses(
    accesses: Vec<FileAccess>,
    profile: Option<&Profile>,
    show_all: bool,
) -> Result<LearnResult> {
    let mut result = LearnResult::new();

    // Get system paths that are already allowed (from policy.json groups)
    let loaded_policy = crate::policy::load_embedded_policy()?;
    let system_read_paths = crate::policy::get_system_read_paths(&loaded_policy);
    let system_read_set: HashSet<&str> = system_read_paths.iter().map(|s| s.as_str()).collect();

    // Get profile paths if available
    let profile_paths: HashSet<String> = if let Some(prof) = profile {
        let mut paths = HashSet::new();
        paths.extend(prof.filesystem.allow.iter().cloned());
        paths.extend(prof.filesystem.read.iter().cloned());
        paths.extend(prof.filesystem.write.iter().cloned());
        paths.extend(prof.filesystem.allow_file.iter().cloned());
        paths.extend(prof.filesystem.read_file.iter().cloned());
        paths.extend(prof.filesystem.write_file.iter().cloned());
        paths
    } else {
        HashSet::new()
    };

    // Track unique learned grants so overlapping reads and writes can be
    // promoted to read+write and redundant descendants can be removed.
    let mut learned_entries: BTreeMap<PathBuf, LearnedPathEntry> = BTreeMap::new();

    for access in accesses {
        let canonical = canonicalize_existing_path(&access.path);

        // Check if covered by system paths
        if is_covered_by_set(&canonical, &system_read_set)? {
            if show_all {
                result.system_covered.insert(canonical);
            }
            continue;
        }

        // Check if covered by profile
        if is_covered_by_profile(&canonical, &profile_paths)? {
            if show_all {
                result.profile_covered.insert(canonical);
            }
            continue;
        }

        let access_mode = if access.is_write {
            AccessMode::Write
        } else {
            AccessMode::Read
        };
        let (target_path, is_file) = learned_target_for_access(&access.path, access.is_write);
        observe_learned_path(&mut learned_entries, target_path, is_file, access_mode);
    }

    minimize_learned_entries(&mut learned_entries);

    for (path, entry) in learned_entries {
        match (entry.access, entry.is_file) {
            (AccessMode::Read, true) => {
                result.read_files.insert(path);
            }
            (AccessMode::Read, false) => {
                result.read_paths.insert(path);
            }
            (AccessMode::Write, true) => {
                result.write_files.insert(path);
            }
            (AccessMode::Write, false) => {
                result.write_paths.insert(path);
            }
            (AccessMode::ReadWrite, true) => {
                result.readwrite_files.insert(path);
            }
            (AccessMode::ReadWrite, false) => {
                result.readwrite_paths.insert(path);
            }
        }
    }

    Ok(result)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn canonicalize_existing_path(path: &Path) -> PathBuf {
    try_canonicalize(path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn learned_target_for_access(path: &Path, is_write: bool) -> (PathBuf, bool) {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            let canonical = canonicalize_existing_path(path);
            (canonical, !metadata.is_dir())
        }
        Err(_) if is_write => match path.parent() {
            Some(parent) => (canonicalize_existing_path(parent), false),
            None => (path.to_path_buf(), false),
        },
        Err(_) => (path.to_path_buf(), true),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn merge_access_modes(existing: AccessMode, new: AccessMode) -> AccessMode {
    if existing == new {
        existing
    } else {
        AccessMode::ReadWrite
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn observe_learned_path(
    learned_entries: &mut BTreeMap<PathBuf, LearnedPathEntry>,
    path: PathBuf,
    is_file: bool,
    access: AccessMode,
) {
    match learned_entries.get_mut(&path) {
        Some(entry) => {
            entry.access = merge_access_modes(entry.access, access);
            if !is_file {
                entry.is_file = false;
            }
        }
        None => {
            learned_entries.insert(path, LearnedPathEntry { access, is_file });
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn minimize_learned_entries(learned_entries: &mut BTreeMap<PathBuf, LearnedPathEntry>) {
    let directory_entries: Vec<(PathBuf, AccessMode)> = learned_entries
        .iter()
        .filter_map(|(path, entry)| (!entry.is_file).then_some((path.clone(), entry.access)))
        .collect();

    let redundant_children: Vec<PathBuf> = learned_entries
        .iter()
        .filter_map(|(candidate_path, candidate_entry)| {
            directory_entries
                .iter()
                .any(|(dir_path, dir_access)| {
                    candidate_path != dir_path
                        && candidate_path.starts_with(dir_path)
                        && dir_access.contains(candidate_entry.access)
                })
                .then_some(candidate_path.clone())
        })
        .collect();

    for child in redundant_children {
        learned_entries.remove(&child);
    }
}

/// Check if a path is covered by a set of allowed paths
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_covered_by_set(path: &Path, allowed: &HashSet<&str>) -> Result<bool> {
    for allowed_path in allowed {
        let allowed_expanded = expand_home(allowed_path)?;
        if let Ok(allowed_canonical) = std::fs::canonicalize(&allowed_expanded) {
            if path.starts_with(&allowed_canonical) {
                return Ok(true);
            }
        }
        // Also check without canonicalization for paths that may not exist
        let allowed_path_buf = PathBuf::from(&allowed_expanded);
        if path.starts_with(&allowed_path_buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check if a path is covered by profile paths
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_covered_by_profile(path: &Path, profile_paths: &HashSet<String>) -> Result<bool> {
    for profile_path in profile_paths {
        let expanded = expand_home(profile_path)?;
        if let Ok(canonical) = std::fs::canonicalize(&expanded) {
            if path.starts_with(&canonical) {
                return Ok(true);
            }
        }
        let path_buf = PathBuf::from(&expanded);
        if path.starts_with(&path_buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Expand ~ to home directory
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn expand_home(path: &str) -> Result<String> {
    use crate::config;

    if path.starts_with('~') {
        let home = config::validated_home()?;
        return Ok(path.replacen('~', &home, 1));
    }
    if path.starts_with("$HOME") {
        let home = config::validated_home()?;
        return Ok(path.replacen("$HOME", &home, 1));
    }
    Ok(path.to_string())
}

/// Extract a substring between a prefix and suffix
#[cfg(target_os = "linux")]
fn extract_between<'a>(s: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let start = s.find(prefix)?;
    let after = &s[start + prefix.len()..];
    let end = after.find(suffix)?;
    Some(&after[..end])
}

/// Parse a network syscall (connect or bind) from strace output
#[cfg(target_os = "linux")]
fn parse_network_syscall(line: &str, kind: NetworkAccessKind) -> Option<NetworkAccess> {
    // Skip Unix domain sockets — local IPC, not network
    if line.contains("sa_family=AF_UNIX") || line.contains("sa_family=AF_LOCAL") {
        return None;
    }

    let (addr, port) = if line.contains("sa_family=AF_INET6") {
        // IPv6: inet_pton(AF_INET6, "::1") and sin6_port=htons(443)
        let port_str = extract_between(line, "sin6_port=htons(", ")")?;
        let addr_str = extract_between(line, "inet_pton(AF_INET6, \"", "\"")?;
        let port: u16 = port_str.parse().ok()?;
        let addr: IpAddr = addr_str.parse().ok()?;
        (addr, port)
    } else if line.contains("sa_family=AF_INET") {
        // IPv4: inet_addr("93.184.216.34") and sin_port=htons(443)
        let port_str = extract_between(line, "sin_port=htons(", ")")?;
        let addr_str = extract_between(line, "inet_addr(\"", "\"")?;
        let port: u16 = port_str.parse().ok()?;
        let addr: IpAddr = addr_str.parse().ok()?;
        (addr, port)
    } else {
        return None;
    };

    // Filter out port 0 (ephemeral/OS-assigned)
    if port == 0 {
        return None;
    }

    Some(NetworkAccess {
        addr,
        port,
        kind,
        queried_hostname: None,
    })
}

/// Parse a DNS query from a sendto syscall to extract the queried hostname.
///
/// Only processes sendto calls to port 53 (DNS). Extracts the query
/// hostname from the DNS wire format in the buffer argument.
#[cfg(target_os = "linux")]
fn parse_dns_sendto(line: &str) -> Option<String> {
    // Only interested in DNS (port 53)
    if !line.contains("htons(53)") {
        return None;
    }
    // Must be IP family (not unix socket)
    if !line.contains("AF_INET") {
        return None;
    }

    let buf_str = extract_sendto_buffer(line)?;
    let bytes = unescape_strace_bytes(&buf_str);
    parse_dns_query_hostname(&bytes)
}

/// Parse a systemd-resolved Varlink hostname resolution request.
///
/// systemd-resolved uses a JSON-based Varlink protocol over a Unix socket.
/// The sendto buffer contains JSON like:
/// `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"example.com",...}}`
///
/// In strace output, quotes inside the buffer are C-escaped as `\"`, so we
/// must extract and unescape the buffer before parsing the JSON.
#[cfg(target_os = "linux")]
fn parse_resolved_sendto(line: &str) -> Option<String> {
    // Quick filter: ResolveHostname is plain ASCII, visible in raw strace output
    if !line.contains("ResolveHostname") {
        return None;
    }

    // Extract the buffer content and unescape C-style escapes (\" → ", etc.)
    let buf_str = extract_sendto_buffer(line)?;
    let unescaped = unescape_strace_string(&buf_str);

    // The unescaped buffer may contain a trailing null byte from the Varlink
    // protocol. Strip it before parsing as JSON.
    let json_str = unescaped.trim_end_matches('\0');

    // Parse with serde_json for robust handling of whitespace and escaping
    let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let name_str = parsed.pointer("/parameters/name")?.as_str()?;

    // Validate: must look like a hostname (not empty, contains a dot, ASCII only)
    if name_str.is_empty() || !name_str.contains('.') {
        return None;
    }
    if !name_str
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return None;
    }

    Some(name_str.to_string())
}

/// Extract the buffer string from a sendto or sendmsg syscall line.
///
/// For `sendto(fd, "BUFFER", len, ...)`, extracts BUFFER from the second arg.
/// For `sendmsg(fd, {msg_name=..., msg_iov=[{iov_base="BUFFER", ...}], ...})`,
/// extracts BUFFER from the iov_base field.
#[cfg(target_os = "linux")]
fn extract_sendto_buffer(line: &str) -> Option<String> {
    // Determine where to start looking for the quoted buffer
    let search_start = line.find("iov_base=").or_else(|| line.find("sendto("))?;

    let after = &line[search_start..];

    // Find first '"' — start of buffer
    let q_start = after.find('"')? + 1;
    let remaining = &after[q_start..];

    // Find unescaped closing '"'
    let bytes = remaining.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2; // skip escape sequence
        } else if bytes[i] == b'"' {
            return Some(remaining[..i].to_string());
        } else {
            i += 1;
        }
    }
    None
}

/// Convert a C-escaped strace string to raw bytes.
///
/// Reuses the char-level unescaping from `unescape_strace_string` and
/// converts each char back to its byte value (all values are 0–255).
#[cfg(target_os = "linux")]
fn unescape_strace_bytes(s: &str) -> Vec<u8> {
    unescape_strace_string(s).chars().map(|c| c as u8).collect()
}

/// Parse a hostname from DNS wire format query data.
///
/// Expects at least the 12-byte DNS header followed by the question section.
/// Returns the queried hostname (e.g., "example.com") or None if the data
/// is malformed or truncated.
#[cfg(target_os = "linux")]
fn parse_dns_query_hostname(data: &[u8]) -> Option<String> {
    // Minimum: 12-byte header + at least 1 label byte
    if data.len() < 13 {
        return None;
    }

    let mut pos = 12; // skip DNS header
    let mut labels = Vec::new();

    loop {
        if pos >= data.len() {
            return None; // truncated
        }

        let len = data[pos] as usize;
        pos += 1;

        if len == 0 {
            break; // root label — end of hostname
        }

        // Compression pointer (high 2 bits set) — shouldn't appear in queries
        if len & 0xC0 != 0 {
            return None;
        }

        // DNS labels are max 63 bytes
        if len > 63 {
            return None;
        }

        if pos + len > data.len() {
            return None; // truncated
        }

        // Label must be valid ASCII
        let label = std::str::from_utf8(&data[pos..pos + len]).ok()?;

        // Validate: DNS labels contain alphanumeric, hyphen, underscore
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }

        labels.push(label.to_string());
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

/// Process raw network accesses into categorized summaries.
///
/// Uses forward DNS correlation from captured DNS queries to map IPs to
/// hostnames. Falls back to reverse DNS for unmatched IPs when `resolve_dns`
/// is true.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn process_network_accesses(
    accesses: Vec<NetworkAccess>,
    dns_queries: Vec<String>,
    resolve_dns: bool,
) -> (Vec<NetworkConnectionSummary>, Vec<NetworkConnectionSummary>) {
    let mut connect_counts: HashMap<(IpAddr, u16), usize> = HashMap::new();
    let mut bind_counts: HashMap<(IpAddr, u16), usize> = HashMap::new();

    for access in &accesses {
        let key = (access.addr, access.port);
        match access.kind {
            NetworkAccessKind::Connect => {
                *connect_counts.entry(key).or_insert(0) += 1;
            }
            NetworkAccessKind::Bind => {
                *bind_counts.entry(key).or_insert(0) += 1;
            }
        }
    }

    // Build IP → hostname mapping using three strategies (in priority order):
    // 1. Timing-based: hostname attached directly from preceding DNS query
    // 2. Forward DNS: resolve captured hostnames to IPs
    // 3. Reverse DNS: lookup IP → hostname as last resort
    let hostnames = if resolve_dns {
        // Strategy 1: Use hostnames attached during tracing (timing correlation)
        let mut map: HashMap<IpAddr, String> = HashMap::new();
        for access in &accesses {
            if let Some(ref hostname) = access.queried_hostname {
                map.entry(access.addr).or_insert_with(|| hostname.clone());
            }
        }

        // Strategy 2: Forward DNS for IPs not covered by timing correlation
        let all_ips: HashSet<IpAddr> = accesses.iter().map(|a| a.addr).collect();
        let unresolved_after_timing: HashSet<IpAddr> = all_ips
            .iter()
            .filter(|ip| !map.contains_key(ip))
            .copied()
            .collect();

        if !unresolved_after_timing.is_empty() && !dns_queries.is_empty() {
            let forward = resolve_forward_dns(&dns_queries);
            for (ip, hostname) in forward {
                map.entry(ip).or_insert(hostname);
            }
        }

        // Strategy 3: Reverse DNS for anything still unresolved
        let unresolved_after_forward: HashSet<IpAddr> = all_ips
            .iter()
            .filter(|ip| !map.contains_key(ip))
            .copied()
            .collect();

        if !unresolved_after_forward.is_empty() {
            let reverse = resolve_reverse_dns(&unresolved_after_forward);
            map.extend(reverse);
        }

        map
    } else {
        HashMap::new()
    };

    let build_summaries =
        |counts: &HashMap<(IpAddr, u16), usize>| -> Vec<NetworkConnectionSummary> {
            let mut summaries: Vec<NetworkConnectionSummary> = counts
                .iter()
                .map(|(&(addr, port), &count)| NetworkConnectionSummary {
                    endpoint: NetworkEndpoint {
                        addr,
                        port,
                        hostname: hostnames.get(&addr).cloned(),
                    },
                    count,
                })
                .collect();
            summaries.sort();
            summaries
        };

    (
        build_summaries(&connect_counts),
        build_summaries(&bind_counts),
    )
}

/// Resolve captured DNS query hostnames to IPs via forward DNS lookup.
///
/// For each hostname the traced program queried, resolves it to its current
/// IPs to build an IP→hostname mapping. This gives the actual hostname the
/// program intended to reach (e.g., "google.com") rather than infrastructure
/// names from reverse DNS (e.g., "jr-in-f100.1e100.net").
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_forward_dns(hostnames: &[String]) -> HashMap<IpAddr, String> {
    let mut result = HashMap::new();
    let unique: HashSet<&String> = hostnames.iter().collect();

    for hostname in unique {
        match dns_lookup::lookup_host(hostname) {
            Ok(ips) => {
                for ip in ips {
                    // First hostname to resolve to this IP wins
                    result.entry(ip).or_insert_with(|| hostname.clone());
                }
            }
            Err(e) => {
                debug!("Forward DNS lookup failed for {}: {}", hostname, e);
            }
        }
    }

    result
}

/// Resolve IP addresses to hostnames via reverse DNS (fallback)
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_reverse_dns(ips: &HashSet<IpAddr>) -> HashMap<IpAddr, String> {
    let mut result = HashMap::new();

    for &ip in ips {
        match dns_lookup::lookup_addr(&ip) {
            Ok(hostname) => {
                // Skip if the hostname is just the IP address stringified
                if hostname != ip.to_string() {
                    result.insert(ip, hostname);
                }
            }
            Err(e) => {
                debug!("Reverse DNS lookup failed for {}: {}", ip, e);
            }
        }
    }

    result
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::Builder;

    /// Helper to extract FileAccess from TracedAccess
    fn expect_file_access(traced: Option<TracedAccess>) -> FileAccess {
        match traced {
            Some(TracedAccess::File(fa)) => fa,
            other => panic!("Expected File, got {:?}", other),
        }
    }

    /// Helper to extract NetworkAccess from TracedAccess
    fn expect_network_access(traced: Option<TracedAccess>) -> NetworkAccess {
        match traced {
            Some(TracedAccess::Network(na)) => na,
            other => panic!("Expected Network, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_strace_openat() {
        let line = r#"openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3"#;
        let access = expect_file_access(parse_strace_line(line));
        assert_eq!(access.path, PathBuf::from("/etc/passwd"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_strace_openat_write() {
        let line = r#"openat(AT_FDCWD, "/tmp/test", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4"#;
        let access = expect_file_access(parse_strace_line(line));
        assert_eq!(access.path, PathBuf::from("/tmp/test"));
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_strace_stat() {
        let line = r#"stat("/usr/bin/bash", {st_mode=S_IFREG|0755, ...}) = 0"#;
        let access = expect_file_access(parse_strace_line(line));
        assert_eq!(access.path, PathBuf::from("/usr/bin/bash"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_strace_execve() {
        let line = r#"execve("/usr/bin/ls", ["ls", "-la"], 0x...) = 0"#;
        let access = expect_file_access(parse_strace_line(line));
        assert_eq!(access.path, PathBuf::from("/usr/bin/ls"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_extract_path_from_openat() {
        let line = r#"openat(AT_FDCWD, "/some/path", O_RDONLY) = 3"#;
        let path = extract_path_from_syscall(line, "openat").expect("should extract");
        assert_eq!(path, "/some/path");
    }

    #[test]
    fn test_is_write_access() {
        assert!(is_write_access(
            "openat(..., O_WRONLY|O_CREAT, ...)",
            "openat"
        ));
        assert!(is_write_access("openat(..., O_RDWR, ...)", "openat"));
        assert!(!is_write_access("openat(..., O_RDONLY, ...)", "openat"));
        assert!(is_write_access("creat(...)", "creat"));
        assert!(is_write_access("mkdir(...)", "mkdir"));
    }

    #[test]
    fn test_expand_home() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[("HOME", "/home/test")]);

        assert_eq!(expand_home("~/foo").expect("valid home"), "/home/test/foo");
        assert_eq!(
            expand_home("$HOME/bar").expect("valid home"),
            "/home/test/bar"
        );
        assert_eq!(
            expand_home("/absolute/path").expect("no expansion needed"),
            "/absolute/path"
        );
    }

    #[test]
    fn test_learned_target_for_missing_write_uses_parent_directory() {
        let path = PathBuf::from("/some/dir/file.txt");
        let (target, is_file) = learned_target_for_access(&path, true);
        assert_eq!(target, PathBuf::from("/some/dir"));
        assert!(!is_file);
    }

    #[test]
    fn test_learned_target_for_existing_file_preserves_file_path() {
        let cwd = std::env::current_dir().expect("cwd should be available");
        let tempdir = Builder::new()
            .prefix("learn-target-")
            .tempdir_in(&cwd)
            .expect("tempdir should be created");
        let file_path = tempdir.path().join("config.json");
        std::fs::write(&file_path, "{}").expect("file should be created");

        let (target, is_file) = learned_target_for_access(&file_path, false);
        assert_eq!(
            target,
            file_path
                .canonicalize()
                .expect("file should canonicalize successfully")
        );
        assert!(is_file);
    }

    #[test]
    fn test_learn_result_to_json() -> Result<()> {
        let mut result = LearnResult::new();
        result.read_paths.insert(PathBuf::from("/some/read/path"));
        result.write_paths.insert(PathBuf::from("/some/write/path"));
        result
            .read_files
            .insert(PathBuf::from("/some/read/file.txt"));

        let json = result.to_json()?;
        assert!(json.contains("filesystem"));
        assert!(json.contains("/some/read/path"));
        assert!(json.contains("/some/write/path"));
        assert!(json.contains("read_file"));
        assert!(json.contains("/some/read/file.txt"));
        Ok(())
    }

    #[test]
    fn test_learn_result_to_profile_includes_file_permissions() -> Result<()> {
        let mut result = LearnResult::new();
        result.write_files.insert(PathBuf::from("/tmp/output.txt"));

        let profile = result.to_named_profile("touch", "touch", None)?;
        let profile_json =
            serde_json::to_string_pretty(&profile).expect("profile should serialize successfully");
        assert!(profile_json.contains("\"write_file\""));
        assert!(profile_json.contains("/tmp/output.txt"));
        Ok(())
    }

    #[test]
    fn test_unescape_simple() {
        assert_eq!(unescape_strace_string(r#"hello"#), "hello");
        assert_eq!(unescape_strace_string(r#"hello\nworld"#), "hello\nworld");
        assert_eq!(unescape_strace_string(r#"hello\tworld"#), "hello\tworld");
        assert_eq!(unescape_strace_string(r#"hello\\world"#), "hello\\world");
        assert_eq!(unescape_strace_string(r#"hello\"world"#), "hello\"world");
    }

    #[test]
    fn test_unescape_hex() {
        // \x41 = 'A'
        assert_eq!(unescape_strace_string(r#"\x41"#), "A");
        // \x2f = '/'
        assert_eq!(
            unescape_strace_string(r#"/path\x2fwith\x2fslash"#),
            "/path/with/slash"
        );
    }

    #[test]
    fn test_unescape_octal() {
        // \101 = 'A' (octal 101 = 65 decimal)
        assert_eq!(unescape_strace_string(r#"\101"#), "A");
        // \040 = ' ' (space)
        assert_eq!(unescape_strace_string(r#"hello\040world"#), "hello world");
    }

    #[test]
    fn test_unescape_null() {
        // \0 alone is null
        assert_eq!(unescape_strace_string(r#"hello\0world"#), "hello\0world");
    }

    #[test]
    fn test_unescape_incomplete_hex() {
        // Incomplete hex escape should be passed through literally
        assert_eq!(unescape_strace_string(r#"\x1"#), r#"\x1"#);
        // Note: \x1e would be valid (1e are both hex digits), so use \x1g instead
        assert_eq!(unescape_strace_string(r#"path\x1gnd"#), r#"path\x1gnd"#);
    }

    #[test]
    fn test_unescape_invalid_hex() {
        // Invalid hex digits should be passed through literally
        assert_eq!(unescape_strace_string(r#"\xZZ"#), r#"\xZZ"#);
        assert_eq!(unescape_strace_string(r#"\xGH"#), r#"\xGH"#);
    }

    #[test]
    fn test_unescape_invalid_octal() {
        // 8 and 9 are not valid octal digits
        // \18 should parse \1 as octal (= 0x01) and leave '8' as literal
        assert_eq!(unescape_strace_string(r#"\18"#), "\x018");
        // \19 should parse \1 as octal (= 0x01) and leave '9' as literal
        assert_eq!(unescape_strace_string(r#"\19"#), "\x019");
    }

    #[test]
    fn test_unescape_trailing_backslash() {
        // Trailing backslash should be passed through
        assert_eq!(unescape_strace_string(r#"hello\"#), r#"hello\"#);
    }

    // --- Network parsing tests ---

    #[test]
    fn test_parse_connect_ipv4() {
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 443);
        assert!(matches!(access.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_connect_ipv6() {
        let line = r#"connect(3, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946"), sin6_scope_id=0}, 28) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(
            access.addr,
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse::<IpAddr>()
                .unwrap()
        );
        assert_eq!(access.port, 443);
        assert!(matches!(access.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_connect_unix_ignored() {
        let line =
            r#"connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT"#;
        assert!(parse_strace_line(line).is_none());
    }

    #[test]
    fn test_parse_bind_ipv4() {
        let line = r#"bind(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 8080);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_bind_ipv6() {
        let line = r#"bind(4, {sa_family=AF_INET6, sin6_port=htons(3000), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::"), sin6_scope_id=0}, 28) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "::".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 3000);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_connect_failed() {
        // Failed connections should still be captured — they reveal intent
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 80);
    }

    #[test]
    fn test_parse_connect_port_zero_ignored() {
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("0.0.0.0")}, 16) = 0"#;
        assert!(parse_strace_line(line).is_none());
    }

    #[test]
    fn test_existing_file_parsing_unchanged() {
        // Regression: ensure file syscalls still parse correctly after refactor
        let lines = [
            (
                r#"openat(AT_FDCWD, "/etc/hosts", O_RDONLY|O_CLOEXEC) = 3"#,
                "/etc/hosts",
                false,
            ),
            (
                r#"access("/etc/ld.so.preload", R_OK) = -1 ENOENT"#,
                "/etc/ld.so.preload",
                false,
            ),
            (r#"mkdir("/tmp/newdir", 0755) = 0"#, "/tmp/newdir", true),
        ];

        for (line, expected_path, expected_write) in &lines {
            let access = expect_file_access(parse_strace_line(line));
            assert_eq!(access.path, PathBuf::from(expected_path));
            assert_eq!(access.is_write, *expected_write);
        }
    }

    #[test]
    fn test_network_dedup() {
        // Duplicate endpoints should be merged with count
        let accesses = vec![
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
        ];

        let (outbound, listening) = process_network_accesses(accesses, vec![], false);
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].count, 3);
        assert!(listening.is_empty());
    }

    #[test]
    fn test_learn_result_network_json() -> Result<()> {
        let mut result = LearnResult::new();
        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 5,
        });
        result.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 3000,
                hostname: None,
            },
            count: 1,
        });

        let json = result.to_json()?;
        assert!(json.contains("\"network\""));
        assert!(json.contains("\"outbound\""));
        assert!(json.contains("\"listening\""));
        assert!(json.contains("93.184.216.34"));
        assert!(json.contains("443"));
        assert!(json.contains("example.com"));
        assert!(json.contains("0.0.0.0"));
        assert!(json.contains("3000"));
        Ok(())
    }

    #[test]
    fn test_learn_result_network_summary() {
        let mut result = LearnResult::new();
        result.read_files.insert(PathBuf::from("/etc/hostname"));
        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 12,
        });
        result.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 3000,
                hostname: None,
            },
            count: 1,
        });

        let summary = result.to_summary();
        assert!(summary.contains("--read-file /etc/hostname"));
        assert!(summary.contains("OUTBOUND NETWORK"));
        assert!(summary.contains("example.com (93.184.216.34):443 (12x)"));
        assert!(summary.contains("LISTENING PORTS"));
        assert!(summary.contains("0.0.0.0:3000"));
        // Count of 1 should NOT show "(1x)"
        assert!(!summary.contains("(1x)"));
    }

    #[test]
    fn test_has_network_activity() {
        let mut result = LearnResult::new();
        assert!(!result.has_network_activity());

        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "10.0.0.1".parse().unwrap(),
                port: 80,
                hostname: None,
            },
            count: 1,
        });
        assert!(result.has_network_activity());

        let mut result2 = LearnResult::new();
        result2.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 8080,
                hostname: None,
            },
            count: 1,
        });
        assert!(result2.has_network_activity());
    }

    #[test]
    fn test_process_accesses_promotes_file_to_readwrite() {
        let cwd = std::env::current_dir().expect("cwd should be available");
        let tempdir = Builder::new()
            .prefix("learn-process-")
            .tempdir_in(&cwd)
            .expect("tempdir should be created");
        let file_path = tempdir.path().join("state.txt");
        std::fs::write(&file_path, "state").expect("file should be created");
        let canonical = file_path
            .canonicalize()
            .expect("file should canonicalize successfully");

        let accesses = vec![
            FileAccess {
                path: file_path.clone(),
                is_write: false,
            },
            FileAccess {
                path: file_path,
                is_write: true,
            },
        ];

        let result = process_accesses(accesses, None, false).expect("accesses should process");
        assert!(result.read_files.is_empty());
        assert!(result.write_files.is_empty());
        assert!(result.readwrite_files.contains(&canonical));
    }

    #[test]
    fn test_process_accesses_drops_children_covered_by_directory() {
        let cwd = std::env::current_dir().expect("cwd should be available");
        let tempdir = Builder::new()
            .prefix("learn-min-")
            .tempdir_in(&cwd)
            .expect("tempdir should be created");
        let nested_dir = tempdir.path().join("nested");
        std::fs::create_dir_all(&nested_dir).expect("nested dir should be created");
        let nested_file = nested_dir.join("file.txt");
        std::fs::write(&nested_file, "hello").expect("nested file should be created");

        let root = tempdir
            .path()
            .canonicalize()
            .expect("tempdir should canonicalize successfully");
        let nested = nested_dir
            .canonicalize()
            .expect("nested dir should canonicalize successfully");
        let file = nested_file
            .canonicalize()
            .expect("nested file should canonicalize successfully");

        let accesses = vec![
            FileAccess {
                path: tempdir.path().to_path_buf(),
                is_write: false,
            },
            FileAccess {
                path: nested_dir,
                is_write: false,
            },
            FileAccess {
                path: nested_file,
                is_write: false,
            },
        ];

        let result = process_accesses(accesses, None, false).expect("accesses should process");
        assert!(result.read_paths.contains(&root));
        assert!(!result.read_paths.contains(&nested));
        assert!(!result.read_files.contains(&file));
    }

    #[test]
    fn test_extract_between() {
        assert_eq!(extract_between("htons(443)", "htons(", ")"), Some("443"));
        assert_eq!(
            extract_between(r#"inet_addr("1.2.3.4")"#, r#"inet_addr(""#, r#"""#),
            Some("1.2.3.4")
        );
        assert_eq!(extract_between("no match here", "foo(", ")"), None);
        assert_eq!(extract_between("prefix(", "prefix(", ")"), None);
    }

    #[test]
    fn test_parse_connect_af_local_ignored() {
        // AF_LOCAL is an alias for AF_UNIX, should also be ignored
        let line = r#"connect(3, {sa_family=AF_LOCAL, sun_path="/tmp/socket"}, 110) = 0"#;
        assert!(parse_strace_line(line).is_none());
    }

    #[test]
    fn test_format_network_summary_with_hostname() {
        let conn = NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 5,
        };
        let line = format_network_summary(&conn);
        assert_eq!(line, "  example.com (93.184.216.34):443 (5x)");
    }

    #[test]
    fn test_format_network_summary_without_hostname() {
        let conn = NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "10.0.0.1".parse().unwrap(),
                port: 8080,
                hostname: None,
            },
            count: 1,
        };
        let line = format_network_summary(&conn);
        assert_eq!(line, "  10.0.0.1:8080");
    }

    // --- DNS query parsing tests ---

    #[test]
    fn test_parse_dns_query_hostname_simple() {
        // DNS wire format for "example.com"
        // Header (12 bytes) + \x07example\x03com\x00 + type A + class IN
        let mut data = vec![
            0xab, 0x12, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.push(7); // length of "example"
        data.extend_from_slice(b"example");
        data.push(3); // length of "com"
        data.extend_from_slice(b"com");
        data.push(0); // root label
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN

        let hostname = parse_dns_query_hostname(&data).expect("should parse");
        assert_eq!(hostname, "example.com");
    }

    #[test]
    fn test_parse_dns_query_hostname_subdomain() {
        // DNS wire format for "api.example.com"
        let mut data = vec![0; 12]; // header
        data.push(3);
        data.extend_from_slice(b"api");
        data.push(7);
        data.extend_from_slice(b"example");
        data.push(3);
        data.extend_from_slice(b"com");
        data.push(0);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let hostname = parse_dns_query_hostname(&data).expect("should parse");
        assert_eq!(hostname, "api.example.com");
    }

    #[test]
    fn test_parse_dns_query_hostname_truncated() {
        // Data too short for header
        assert!(parse_dns_query_hostname(&[0; 10]).is_none());
        // Header only, no labels
        assert!(parse_dns_query_hostname(&[0; 12]).is_none());
    }

    #[test]
    fn test_unescape_strace_bytes() {
        let bytes = unescape_strace_bytes(r#"\7example\3com\0"#);
        assert_eq!(bytes[0], 7);
        assert_eq!(&bytes[1..8], b"example");
        assert_eq!(bytes[8], 3);
        assert_eq!(&bytes[9..12], b"com");
        assert_eq!(bytes[12], 0);
    }

    #[test]
    fn test_extract_sendto_buffer() {
        let line = r#"sendto(5, "\7example\3com\0", 13, 0, {}, 16) = 13"#;
        let buf = extract_sendto_buffer(line).expect("should extract");
        assert_eq!(buf, r#"\7example\3com\0"#);
    }

    #[test]
    fn test_extract_sendto_buffer_with_escaped_backslash() {
        // Buffer containing \\  (escaped backslash)
        let line = r#"sendto(5, "hello\\world", 11, 0, {}, 16) = 11"#;
        let buf = extract_sendto_buffer(line).expect("should extract");
        assert_eq!(buf, r#"hello\\world"#);
    }

    #[test]
    fn test_parse_dns_sendto_ipv4() {
        let line = r#"sendto(5, "\xab\x12\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1", 29, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 29"#;
        let hostname = parse_dns_sendto(line).expect("should parse DNS query");
        assert_eq!(hostname, "example.com");
    }

    #[test]
    fn test_parse_dns_sendto_ipv6_dest() {
        // DNS query sent to IPv6 DNS server (AF_INET6 contains "AF_INET" as substring)
        let line = r#"sendto(5, "\xab\x12\1\0\0\1\0\0\0\0\0\0\6google\3com\0\0\1\0\1", 28, 0, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:4860:4860::8888"), sin6_scope_id=0}, 28) = 28"#;
        let hostname = parse_dns_sendto(line).expect("should parse DNS query via IPv6");
        assert_eq!(hostname, "google.com");
    }

    #[test]
    fn test_parse_dns_sendto_non_dns_ignored() {
        // sendto to port 80, not DNS
        let line = r#"sendto(5, "GET / HTTP/1.1\r\n", 16, 0, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("93.184.216.34")}, 16) = 16"#;
        assert!(parse_dns_sendto(line).is_none());
    }

    #[test]
    fn test_parse_strace_line_dns_query() {
        let line = r#"sendto(5, "\xab\x12\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1", 29, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 29"#;
        match parse_strace_line(line) {
            Some(TracedAccess::DnsQuery(hostname)) => assert_eq!(hostname, "example.com"),
            other => panic!("Expected DnsQuery, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_strace_line_sendto_non_dns_returns_none() {
        // sendto to non-DNS port should return None (not a file or network access we track)
        let line = r#"sendto(5, "data", 4, 0, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("10.0.0.1")}, 16) = 4"#;
        assert!(parse_strace_line(line).is_none());
    }

    #[test]
    fn test_dns_timing_correlation_maps_hostname() {
        // Simulate: program queried "example.com", then connected to an IP.
        // The queried_hostname attached during tracing should map directly.
        let accesses = vec![NetworkAccess {
            addr: "93.184.216.34".parse().unwrap(),
            port: 443,
            kind: NetworkAccessKind::Connect,
            queried_hostname: Some("example.com".to_string()),
        }];
        let dns_queries = vec!["example.com".to_string()];

        let (outbound, _) = process_network_accesses(accesses, dns_queries, true);
        assert_eq!(outbound.len(), 1);
        // Timing correlation attaches the hostname directly — no DNS lookup needed
        assert_eq!(
            outbound[0].endpoint.hostname,
            Some("example.com".to_string())
        );
    }

    // --- PID extraction tests ---

    #[test]
    fn test_extract_strace_pid_with_prefix() {
        let line = r#"[pid 12345] sendto(5, "data", 4, 0, {sa_family=AF_INET, ...}, 16) = 4"#;
        assert_eq!(extract_strace_pid(line), Some(12345));
    }

    #[test]
    fn test_extract_strace_pid_without_prefix() {
        let line = r#"sendto(5, "data", 4, 0, {sa_family=AF_INET, ...}, 16) = 4"#;
        assert_eq!(extract_strace_pid(line), None);
    }

    #[test]
    fn test_extract_strace_pid_padded() {
        // strace sometimes pads PID with spaces
        let line = r#"[pid  1234] openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3"#;
        assert_eq!(extract_strace_pid(line), Some(1234));
    }

    // --- sendmsg buffer extraction tests ---

    #[test]
    fn test_extract_sendmsg_buffer() {
        let line = r#"sendmsg(5, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16, msg_iov=[{iov_base="\7example\3com\0", iov_len=13}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 13"#;
        let buf = extract_sendto_buffer(line).expect("should extract from sendmsg");
        assert_eq!(buf, r#"\7example\3com\0"#);
    }

    #[test]
    fn test_parse_resolved_sendto_json() {
        // systemd-resolved Varlink protocol with proper JSON parsing
        let line = r#"sendto(5, "{\"method\":\"io.systemd.Resolve.ResolveHostname\",\"parameters\":{\"name\":\"example.com\",\"flags\":0}}\0", 94, MSG_DONTWAIT|MSG_NOSIGNAL, NULL, 0) = 94"#;
        let hostname = parse_resolved_sendto(line).expect("should parse resolved JSON");
        assert_eq!(hostname, "example.com");
    }

    #[test]
    fn test_parse_sendmsg_dns_query() {
        // DNS query sent via sendmsg instead of sendto
        let line = r#"sendmsg(5, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16, msg_iov=[{iov_base="\xab\x12\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1", iov_len=29}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 29"#;
        let hostname = parse_dns_sendto(line).expect("should parse DNS query from sendmsg");
        assert_eq!(hostname, "example.com");
    }
}

#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::unwrap_used)]
mod macos_tests {
    use super::*;

    #[test]
    fn test_parse_fs_usage_open_read() {
        let line = "14:23:45.123456  open              /etc/passwd    0.000012   ls.12345";
        let access = parse_fs_usage_line(line).expect("should parse open");
        assert_eq!(access.path, PathBuf::from("/etc/passwd"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_stat64() {
        let line =
            "14:23:45.123456  stat64            /usr/lib/libSystem.B.dylib    0.000003   ls.12345";
        let access = parse_fs_usage_line(line).expect("should parse stat64");
        assert_eq!(access.path, PathBuf::from("/usr/lib/libSystem.B.dylib"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_mkdir_is_write() {
        let line = "14:23:45.123456  mkdir             /tmp/test_dir    0.000008   my_app.12345";
        let access = parse_fs_usage_line(line).expect("should parse mkdir");
        assert_eq!(access.path, PathBuf::from("/tmp/test_dir"));
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_unlink_is_write() {
        let line = "14:23:45.123456  unlink            /tmp/test_file    0.000005   my_app.12345";
        let access = parse_fs_usage_line(line).expect("should parse unlink");
        assert_eq!(access.path, PathBuf::from("/tmp/test_file"));
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_rename_is_write() {
        let line = "14:23:45.123456  rename            /tmp/old_name    0.000005   my_app.12345";
        let access = parse_fs_usage_line(line).expect("should parse rename");
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_skips_dev_paths() {
        let line = "14:23:45.123456  open              /dev/null    0.000002   my_app.12345";
        assert!(parse_fs_usage_line(line).is_none());
    }

    #[test]
    fn test_parse_fs_usage_skips_unknown_ops() {
        let line = "14:23:45.123456  mmap              /some/file    0.000002   my_app.12345";
        assert!(parse_fs_usage_line(line).is_none());
    }

    #[test]
    fn test_parse_fs_usage_empty_line() {
        assert!(parse_fs_usage_line("").is_none());
        assert!(parse_fs_usage_line("   ").is_none());
    }

    #[test]
    fn test_parse_fs_usage_getattrlist() {
        let line =
            "14:23:45.123456  getattrlist       /Applications/Safari.app    0.000004   Finder.12345";
        let access = parse_fs_usage_line(line).expect("should parse getattrlist");
        assert_eq!(access.path, PathBuf::from("/Applications/Safari.app"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_readlink() {
        let line = "14:23:45.123456  readlink          /var    0.000002   ls.12345";
        let access = parse_fs_usage_line(line).expect("should parse readlink");
        assert_eq!(access.path, PathBuf::from("/var"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_write_op() {
        let line = "14:23:45.123456  write             /tmp/output.log    0.000010   my_app.12345";
        let access = parse_fs_usage_line(line).expect("should parse write");
        assert_eq!(access.path, PathBuf::from("/tmp/output.log"));
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_execve() {
        let line = "14:23:45.123456  execve            /usr/bin/env    0.000015   bash.12345";
        let access = parse_fs_usage_line(line).expect("should parse execve");
        assert_eq!(access.path, PathBuf::from("/usr/bin/env"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_fs_usage_path_with_spaces() {
        let line = "14:23:45.123456  stat64            /Users/test/Library/Application Support    0.000003   my_app.12345";
        let access = parse_fs_usage_line(line).expect("should parse path with spaces");
        assert_eq!(
            access.path,
            PathBuf::from("/Users/test/Library/Application Support")
        );
    }

    #[test]
    fn test_parse_fs_usage_with_errno() {
        let line =
            "14:23:45.123456  stat64            /nonexistent/path  [2]    0.000003   my_app.12345";
        let access = parse_fs_usage_line(line).expect("should parse line with errno");
        assert_eq!(access.path, PathBuf::from("/nonexistent/path"));
    }

    #[test]
    fn test_extract_fs_usage_path_basic() {
        let line = "14:23:45.123456  open              /etc/hosts    0.000012   ls.12345";
        let path = extract_fs_usage_path(line).expect("should extract path");
        assert_eq!(path, "/etc/hosts");
    }

    #[test]
    fn test_is_fs_usage_write_open_flags() {
        assert!(is_fs_usage_write(
            "open",
            "open  (W_____)  /tmp/file  0.000001  app.1"
        ));
        assert!(is_fs_usage_write(
            "open",
            "open  O_WRONLY  /tmp/file  0.000001  app.1"
        ));
        assert!(is_fs_usage_write(
            "open",
            "open  O_RDWR  /tmp/file  0.000001  app.1"
        ));
        assert!(!is_fs_usage_write(
            "open",
            "open  (R_____)  /tmp/file  0.000001  app.1"
        ));
    }

    #[test]
    fn test_is_fs_usage_write_operations() {
        assert!(is_fs_usage_write("mkdir", ""));
        assert!(is_fs_usage_write("unlink", ""));
        assert!(is_fs_usage_write("rename", ""));
        assert!(is_fs_usage_write("write", ""));
        assert!(is_fs_usage_write("truncate", ""));
        assert!(!is_fs_usage_write("stat64", ""));
        assert!(!is_fs_usage_write("readlink", ""));
        assert!(!is_fs_usage_write("access", ""));
    }

    // --- nettop parsing tests ---

    #[test]
    fn test_parse_nettop_tcp4_established() {
        let no_listen = HashSet::new();
        let line = "06:54:20.707620,tcp4 192.168.178.103:63660<->17.57.146.10:5223,en0,Established,179190,282920,6632,0,2362,18.41 ms,131072,164736,RD,-,cubic,-,-,-,-,so,";
        let access = parse_nettop_line(line, &no_listen).expect("should parse established TCP4");
        assert_eq!(access.addr, "17.57.146.10".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 5223);
        assert!(matches!(access.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_nettop_tcp4_listen() {
        let no_listen = HashSet::new();
        let line =
            "06:54:20.706434,tcp4 127.0.0.1:8021<->*:*,lo0,Listen,,,,,,,,,,-,cubic,-,-,-,-,so,";
        let access = parse_nettop_line(line, &no_listen).expect("should parse listening TCP4");
        assert_eq!(access.addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 8021);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_nettop_tcp4_listen_wildcard() {
        let no_listen = HashSet::new();
        let line = "06:54:20.706434,tcp4 *:3000<->*:*,en0,Listen,,,,,,,,,,,,,,,,,";
        let access = parse_nettop_line(line, &no_listen).expect("should parse wildcard listen");
        assert_eq!(access.addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 3000);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_nettop_udp4_bind() {
        let no_listen = HashSet::new();
        let line = "06:54:20.700522,udp4 *:56734<->*:*,lo0,,0,15678,,,,,786896,,BE,,,,,,,so,";
        let access = parse_nettop_line(line, &no_listen).expect("should parse UDP4 bind");
        assert_eq!(access.addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 56734);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_nettop_tcp6_established() {
        let no_listen = HashSet::new();
        let line = "06:54:20.707869,tcp6 fe80::73:3e64:c6b8:6476%en0.63975<->fe80::1402:4271:cc19:5e6f%en0.50715,en0,Established,1860,2955,0,0,0,22.31 ms,131072,130752,BE,-,cubic,-,-,-,-,so,";
        // IPv6 link-local with scope IDs — parser strips the scope ID and
        // extracts the address and port correctly
        let access = parse_nettop_line(line, &no_listen)
            .expect("should parse established TCP6 with scope ID");
        assert_eq!(
            access.addr,
            "fe80::1402:4271:cc19:5e6f".parse::<IpAddr>().unwrap()
        );
        assert_eq!(access.port, 50715);
        assert!(matches!(access.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_nettop_tcp6_listen() {
        let no_listen = HashSet::new();
        let line = "06:54:20.706413,tcp6 ::1.8021<->*.*,lo0,Listen,,,,,,,,,,-,cubic,-,-,-,-,so,";
        let access = parse_nettop_line(line, &no_listen).expect("should parse IPv6 listen");
        assert_eq!(access.addr, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 8021);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_nettop_skips_process_summary() {
        let no_listen = HashSet::new();
        let line = "06:54:20.708439,apsd.358,,,179190,282920,6632,0,2362,,,,,,,,,,,,";
        assert!(parse_nettop_line(line, &no_listen).is_none());
    }

    #[test]
    fn test_parse_nettop_skips_header() {
        let no_listen = HashSet::new();
        let line = "time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,";
        assert!(parse_nettop_line(line, &no_listen).is_none());
    }

    #[test]
    fn test_parse_nettop_skips_loopback_connect() {
        let no_listen = HashSet::new();
        // Loopback connections (local IPC) should be filtered out
        let line = "06:54:20.707620,tcp4 127.0.0.1:49152<->127.0.0.1:8080,lo0,Established,100,200,0,0,0,0.5 ms,,,,,,,,,,so,";
        assert!(parse_nettop_line(line, &no_listen).is_none());
    }

    #[test]
    fn test_parse_nettop_skips_port_zero() {
        let no_listen = HashSet::new();
        let line = "06:54:20.700522,udp4 *:0<->*:*,lo0,,0,0,,,,,,,,,,,,,,,";
        assert!(parse_nettop_line(line, &no_listen).is_none());
    }

    #[test]
    fn test_parse_nettop_skips_accepted_connection() {
        // If local port 3000 is a known listener, an established connection
        // on that port is server-side (accepted), not outbound
        let mut listening = HashSet::new();
        listening.insert(3000u16);
        let line = "06:54:20.707620,tcp4 192.168.1.1:3000<->10.0.0.5:52431,en0,Established,1000,2000,0,0,0,1.0 ms,,,,,,,,,,so,";
        assert!(parse_nettop_line(line, &listening).is_none());
    }

    #[test]
    fn test_parse_nettop_allows_outbound_on_non_listen_port() {
        // Established connection on a non-listening port is outbound
        let mut listening = HashSet::new();
        listening.insert(3000u16);
        let line = "06:54:20.707620,tcp4 192.168.1.1:49999<->93.184.216.34:443,en0,Established,1000,2000,0,0,0,1.0 ms,,,,,,,,,,so,";
        let access = parse_nettop_line(line, &listening).expect("should parse outbound");
        assert_eq!(access.addr, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 443);
        assert!(matches!(access.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_nettop_endpoint_ipv4() {
        let (addr, port) = parse_nettop_endpoint("192.168.1.1:443", false).unwrap();
        assert_eq!(addr, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_nettop_endpoint_ipv4_wildcard() {
        let (addr, port) = parse_nettop_endpoint("*:8080", false).unwrap();
        assert_eq!(addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_nettop_endpoint_ipv6() {
        let (addr, port) = parse_nettop_endpoint("::1.443", true).unwrap();
        assert_eq!(addr, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_nettop_endpoint_wildcard_star() {
        assert!(parse_nettop_endpoint("*:*", false).is_none());
        assert!(parse_nettop_endpoint("*.*", true).is_none());
    }

    #[test]
    fn test_nettop_network_dedup() {
        // Verify that process_network_accesses deduplicates correctly
        let accesses = vec![
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
        ];

        let (outbound, listening) = process_network_accesses(accesses, vec![], false);
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].count, 3);
        assert!(listening.is_empty());
    }
}
