//! Diagnostic output formatter for sandbox policy.
//!
//! This module provides human and agent-readable diagnostic output
//! when sandboxed commands fail. The output helps identify whether
//! the failure was due to sandbox restrictions.
//!
//! # Design Principles
//!
//! - **Unmistakable boundary**: Diagnostics render as a dedicated `nono diagnostic`
//!   block so they remain easy to distinguish from command output
//! - **May vs was**: Phrased as "may be due to" not "was caused by"
//!   because the non-zero exit could be unrelated to the sandbox
//! - **Actionable**: Provides specific flags to grant additional access
//! - **Mode-aware**: Different guidance for supervised vs standard mode
//! - **Library code**: No process management, no CLI assumptions

use crate::capability::{AccessMode, CapabilitySet, CapabilitySource};
use crate::path::try_canonicalize;
use std::path::{Path, PathBuf};

/// Why a path access was denied during a supervised session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// Path is blocked by sandbox policy before approval is consulted
    PolicyBlocked,
    /// Path matches a capability but the requested access mode is not granted
    InsufficientAccess,
    /// User declined the interactive approval prompt
    UserDenied,
    /// Request was rate limited (too many requests)
    RateLimited,
    /// Approval backend returned an error
    BackendError,
}

/// Record of a denied access attempt during a supervised session.
#[derive(Debug, Clone)]
pub struct DenialRecord {
    /// The path that was denied
    pub path: PathBuf,
    /// Access mode requested
    pub access: AccessMode,
    /// Why it was denied
    pub reason: DenialReason,
}

/// Best-effort sandbox violation recovered from OS-native logging.
///
/// On macOS, Seatbelt does not stream deny events back to the supervisor like
/// Linux seccomp-notify does, so diagnostics can supplement denials with
/// unified-log records recovered from sandboxd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxViolation {
    /// Denied operation, such as `file-read-data` or `mach-lookup`.
    pub operation: String,
    /// Optional path or resource associated with the violation.
    pub target: Option<String>,
}

/// Policy explanation for a denied path, resolved from `nono why` logic.
///
/// This carries the enriched query result so the diagnostic can show
/// group names, policy details, and suggested fixes inline rather than
/// asking the user to run `nono why` separately.
#[derive(Debug, Clone)]
pub struct PolicyExplanation {
    /// The denied path.
    pub path: PathBuf,
    /// Access mode that was denied.
    pub access: AccessMode,
    /// Why it was denied: "sensitive_path", "insufficient_access", or "path_not_granted".
    pub reason: String,
    /// Human-readable explanation (e.g. "blocked by group 'ssh' (SSH keys and config)").
    pub details: Option<String>,
    /// Policy source identifier (e.g. "group:ssh").
    pub policy_source: Option<String>,
    /// Suggested CLI flag to fix (e.g. "--read ~/.ssh/id_rsa").
    pub suggested_flag: Option<String>,
}

/// Path-level hint extracted from a command's own error output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPathHint {
    /// The path mentioned in the error output.
    pub path: PathBuf,
    /// Best-effort access mode inferred from the error text.
    pub access: AccessMode,
}

/// Primary classification derived from a command's own error output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorVerdict {
    /// The command likely hit a sandbox-relevant path access issue.
    LikelySandbox(ObservedPathHint),
    /// The command reported a missing path, which is not itself a sandbox denial.
    MissingPath(PathBuf),
    /// The command reported an application-level failure unrelated to permissions.
    NonSandboxFailure(String),
}

/// Best-effort observations extracted from a command's stderr output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorObservation {
    /// Primary diagnosis extracted from the command output.
    pub primary_verdict: Option<ErrorVerdict>,
    /// Name of a protected file referenced in the error output, if any.
    pub blocked_protected_file: Option<String>,
    /// Paths that look like sandbox-denied accesses from stderr.
    pub path_hints: Vec<ObservedPathHint>,
    /// Paths that look missing according to stderr output.
    pub missing_paths: Vec<PathBuf>,
    /// Error text that strongly suggests a non-sandbox application failure.
    pub non_sandbox_failure: Option<String>,
}

impl ErrorObservation {
    #[must_use]
    pub fn has_findings(&self) -> bool {
        self.primary_verdict.is_some()
            || self.blocked_protected_file.is_some()
            || !self.path_hints.is_empty()
            || !self.missing_paths.is_empty()
            || self.non_sandbox_failure.is_some()
    }
}

/// Execution mode for diagnostic context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticMode {
    /// Standard mode: suggest --allow flags for re-run
    Standard,
    /// Supervised mode: interactive expansion available, show denials
    Supervised,
}

/// Context about the command that was executed.
///
/// Used to generate more specific diagnostic messages when a
/// sandboxed command fails.
#[derive(Debug, Clone)]
pub struct CommandContext {
    /// The program name as the user typed it (e.g. "ps", "./script.sh")
    pub program: String,
    /// The resolved absolute path to the binary
    pub resolved_path: PathBuf,
    /// Original argv passed to the top-level command
    pub args: Vec<String>,
}

/// Strip control characters and ANSI escape sequences from a string.
///
/// Prevents terminal injection from attacker-controlled program names
/// or paths appearing in diagnostic output.
fn sanitize_for_diagnostic(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ESC and the entire escape sequence
            if let Some(next) = chars.next() {
                if next == '[' {
                    for seq_char in chars.by_ref() {
                        if seq_char.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            }
        } else if c.is_control() {
            // Strip all control characters
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse best-effort denial hints from a command's stderr output.
#[must_use]
pub fn analyze_error_output(
    error_output: &str,
    protected_paths: &[PathBuf],
    current_dir: Option<&Path>,
) -> ErrorObservation {
    let mut blocked_protected_file = None;
    let mut observed = std::collections::BTreeMap::<PathBuf, AccessMode>::new();
    let mut missing = std::collections::BTreeSet::<PathBuf>::new();
    let mut pending_relative_write: Option<PathBuf> = None;
    let mut non_sandbox_failure = None;

    for line in error_output.lines() {
        if blocked_protected_file.is_none() {
            blocked_protected_file = detect_protected_file_in_error_line(protected_paths, line);
        }

        if non_sandbox_failure.is_none() {
            non_sandbox_failure = detect_non_sandbox_failure_line(line);
        }

        if let Some(path) =
            current_dir.and_then(|cwd| extract_relative_write_path_from_line(line, cwd))
        {
            pending_relative_write = Some(path);
        }

        if looks_like_missing_path(line) {
            if let Some(path) = extract_denied_path_from_error_line(line) {
                missing.insert(path);
            }
            continue;
        }

        if !looks_like_access_denial(line) {
            continue;
        }

        let Some(path) =
            extract_denied_path_from_error_line(line).or_else(|| pending_relative_write.clone())
        else {
            continue;
        };
        let access = if extract_denied_path_from_error_line(line).is_some() {
            infer_access_from_error_line(line, &path)
        } else {
            AccessMode::Write
        };

        observed
            .entry(path)
            .and_modify(|existing| *existing = merge_access_modes(*existing, access))
            .or_insert(access);
        pending_relative_write = None;
    }

    let path_hints = observed
        .into_iter()
        .map(|(path, access)| ObservedPathHint { path, access })
        .collect::<Vec<_>>();
    let primary_verdict = missing
        .iter()
        .next()
        .cloned()
        .map(ErrorVerdict::MissingPath)
        .or_else(|| {
            non_sandbox_failure
                .clone()
                .map(ErrorVerdict::NonSandboxFailure)
        })
        .or_else(|| path_hints.first().cloned().map(ErrorVerdict::LikelySandbox));

    ErrorObservation {
        primary_verdict,
        blocked_protected_file,
        path_hints,
        missing_paths: missing.into_iter().collect(),
        non_sandbox_failure,
    }
}

fn detect_non_sandbox_failure_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("eexist")
        || lower.contains("file already exists")
        || lower.contains("already exists")
    {
        return Some(trimmed.to_string());
    }

    // Version requirement errors are never sandbox-related
    if lower.contains("version must be at least")
        || lower.contains("requires version")
        || lower.contains("minimum version")
        || lower.contains("upgrade your")
    {
        return Some(trimmed.to_string());
    }

    None
}

fn detect_protected_file_in_error_line(
    protected_paths: &[PathBuf],
    error_line: &str,
) -> Option<String> {
    for path in protected_paths {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if error_line.contains(name) {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn looks_like_access_denial(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("read-only file system")
}

fn looks_like_missing_path(line: &str) -> bool {
    line.to_ascii_lowercase()
        .contains("no such file or directory")
}

fn render_diagnostic_block(body: &str) -> String {
    let mut lines = Vec::new();

    for line in body.lines() {
        if line == "[nono]" {
            lines.push(String::new());
        } else if let Some(stripped) = line.strip_prefix("[nono] ") {
            lines.push(stripped.to_string());
        } else if let Some(stripped) = line.strip_prefix("[nono]") {
            lines.push(stripped.to_string());
        } else {
            lines.push(line.to_string());
        }
    }

    lines.join("\n")
}

fn format_command_failed_line(exit_code: i32) -> String {
    format!("[nono] Command exited with code {}.", exit_code)
}

fn format_command_failed_not_sandbox_line(exit_code: i32) -> String {
    format!(
        "[nono] The command failed, but this does not look like a sandbox denial. (exit code {})",
        exit_code
    )
}

fn format_command_succeeded_with_stderr_line() -> String {
    "[nono] The command succeeded, but stderr showed a likely sandbox-related access issue."
        .to_string()
}

fn extract_denied_path_from_error_line(line: &str) -> Option<PathBuf> {
    let denial_markers = [
        "Operation not permitted",
        "Permission denied",
        "Read-only file system",
    ];

    let prefix = denial_markers
        .iter()
        .find_map(|marker| line.find(marker).map(|idx| &line[..idx]))
        .unwrap_or(line);

    for segment in prefix.rsplit(':') {
        if let Some(path) = extract_path_from_segment(segment) {
            return Some(path);
        }
    }

    extract_path_from_segment(prefix)
}

fn extract_relative_write_path_from_line(line: &str, current_dir: &Path) -> Option<PathBuf> {
    let lower = line.to_ascii_lowercase();
    let markers = ["creating empty ", "creating ", "create ", "writing "];

    let marker = markers.iter().find(|marker| lower.contains(**marker))?;
    let start = lower.find(marker)? + marker.len();
    let candidate = line.get(start..)?.split_whitespace().next()?;
    let candidate = candidate
        .trim_matches(|c: char| {
            matches!(
                c,
                '\'' | '"' | '`' | ',' | ':' | ';' | '(' | ')' | '[' | ']'
            )
        })
        .trim_end_matches('.')
        .trim();

    if candidate.is_empty()
        || candidate.starts_with('/')
        || candidate.starts_with('~')
        || candidate.starts_with('-')
        || candidate.chars().any(char::is_control)
    {
        return None;
    }

    Some(current_dir.join(candidate))
}

fn extract_path_from_segment(segment: &str) -> Option<PathBuf> {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Strip a leading quote if the path is quoted (e.g. '/bin/ls' or "/bin/ls")
    let (unquoted, closing_quote) = if trimmed.starts_with('\'') || trimmed.starts_with('"') {
        let quote = trimmed.as_bytes()[0] as char;
        (&trimmed[1..], Some(quote))
    } else {
        (trimmed, None)
    };

    let tilde_idx = unquoted.find("~/");
    let slash_idx = unquoted.find('/');
    let start = match (tilde_idx, slash_idx) {
        (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }?;

    let after_start = &unquoted[start..];

    // Terminate the path at the closing quote (if we stripped an opening one)
    // or at any character that cannot appear in a filesystem path.
    let end = if let Some(q) = closing_quote {
        after_start.find(q).unwrap_or(after_start.len())
    } else {
        after_start
            .find(['\'', '"', '`', ')', '(', '<', '>'])
            .unwrap_or(after_start.len())
    };

    let candidate = after_start[..end].trim();
    if candidate.is_empty() || candidate.chars().any(char::is_control) {
        return None;
    }

    Some(PathBuf::from(candidate))
}

fn infer_access_from_error_line(line: &str, path: &Path) -> AccessMode {
    let lower = line.to_ascii_lowercase();

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if matches!(
            name,
            ".profile" | ".bash_profile" | ".bashrc" | ".zprofile" | ".zshrc" | ".zlogin"
        ) {
            return AccessMode::Read;
        }
    }

    if lower.contains("cannot create")
        || lower.contains("can't create")
        || lower.contains("write error")
        || lower.contains("read-only file system")
        || lower.starts_with("tee:")
        || lower.starts_with("touch:")
        || lower.starts_with("mkdir:")
        || lower.starts_with("mktemp:")
        || lower.starts_with("install:")
        || lower.starts_with("cp:")
        || lower.starts_with("mv:")
        || lower.starts_with("rm:")
        || lower.starts_with("ln:")
        || lower.starts_with("chmod:")
        || lower.starts_with("chown:")
        || lower.starts_with("truncate:")
    {
        return AccessMode::Write;
    }

    if lower.contains("cannot open")
        || lower.contains("can't open")
        || lower.starts_with("cat:")
        || lower.starts_with("grep:")
        || lower.starts_with("sed:")
        || lower.starts_with("awk:")
        || lower.starts_with("head:")
        || lower.starts_with("tail:")
        || lower.starts_with("less:")
        || lower.starts_with("more:")
        || lower.starts_with("find:")
        || lower.starts_with("ls:")
    {
        return AccessMode::Read;
    }

    AccessMode::ReadWrite
}

/// Formats diagnostic information about sandbox policy.
///
/// This is library code that can be used by any parent process
/// that wants to explain sandbox denials to users or AI agents.
pub struct DiagnosticFormatter<'a> {
    caps: &'a CapabilitySet,
    mode: DiagnosticMode,
    denials: &'a [DenialRecord],
    sandbox_violations: &'a [SandboxViolation],
    /// Paths that are write-protected due to trust verification
    protected_paths: &'a [PathBuf],
    /// Primary verdict extracted from the command output.
    primary_verdict: Option<ErrorVerdict>,
    /// Name of a protected file that was detected in the error output
    blocked_protected_file: Option<String>,
    /// Best-effort path hints extracted from the command's own error output.
    observed_path_hints: Vec<ObservedPathHint>,
    /// Best-effort missing path hints extracted from the command's own error output.
    missing_path_hints: Vec<PathBuf>,
    /// Error text that strongly suggests a non-sandbox application failure.
    non_sandbox_failure: Option<String>,
    /// Command that was executed (for context-aware diagnostics)
    command: Option<CommandContext>,
    /// Directory the child process started in.
    current_dir: Option<&'a Path>,
    /// Session ID for `nono grant` suggestions in supervised mode.
    session_id: Option<String>,
    /// Policy explanations for denied paths, resolved from `query_path`.
    policy_explanations: Vec<PolicyExplanation>,
}

impl<'a> DiagnosticFormatter<'a> {
    /// Create a new formatter for the given capability set.
    #[must_use]
    pub fn new(caps: &'a CapabilitySet) -> Self {
        Self {
            caps,
            mode: DiagnosticMode::Standard,
            denials: &[],
            sandbox_violations: &[],
            protected_paths: &[],
            primary_verdict: None,
            blocked_protected_file: None,
            observed_path_hints: Vec::new(),
            missing_path_hints: Vec::new(),
            non_sandbox_failure: None,
            command: None,
            current_dir: None,
            session_id: None,
            policy_explanations: Vec::new(),
        }
    }

    /// Set the diagnostic mode (standard or supervised).
    #[must_use]
    pub fn with_mode(mut self, mode: DiagnosticMode) -> Self {
        self.mode = mode;
        self
    }

    /// Add denial records from a supervised session.
    #[must_use]
    pub fn with_denials(mut self, denials: &'a [DenialRecord]) -> Self {
        self.denials = denials;
        self
    }

    /// Add OS-native sandbox violation records.
    #[must_use]
    pub fn with_sandbox_violations(mut self, violations: &'a [SandboxViolation]) -> Self {
        self.sandbox_violations = violations;
        self
    }

    /// Add paths that are write-protected due to trust verification.
    ///
    /// These are signed instruction files that the sandbox protects from
    /// modification even when the parent directory has write access.
    #[must_use]
    pub fn with_protected_paths(mut self, paths: &'a [PathBuf]) -> Self {
        self.protected_paths = paths;
        self
    }

    /// Set the name of a protected file that was detected in the error output.
    ///
    /// When set, the diagnostic will highlight that a write to a signed
    /// instruction file was blocked.
    #[must_use]
    pub fn with_blocked_protected_file(mut self, name: Option<String>) -> Self {
        self.blocked_protected_file = name;
        self
    }

    /// Set best-effort observations extracted from the command's stderr output.
    #[must_use]
    pub fn with_error_observation(mut self, observation: ErrorObservation) -> Self {
        self.primary_verdict = observation.primary_verdict;
        self.blocked_protected_file = observation.blocked_protected_file;
        self.observed_path_hints = observation.path_hints;
        self.missing_path_hints = observation.missing_paths;
        self.non_sandbox_failure = observation.non_sandbox_failure;
        self
    }

    /// Set command context for more specific diagnostics.
    #[must_use]
    pub fn with_command(mut self, command: CommandContext) -> Self {
        self.command = Some(command);
        self
    }

    /// Set the child process working directory for cwd-relative diagnostics.
    #[must_use]
    pub fn with_current_dir(mut self, current_dir: &'a Path) -> Self {
        self.current_dir = Some(current_dir);
        self
    }

    /// Set the session ID for `nono grant` suggestions in supervised mode.
    #[must_use]
    pub fn with_session_id(mut self, session_id: Option<String>) -> Self {
        self.session_id = session_id;
        self
    }

    /// Add policy explanations for denied paths.
    ///
    /// These are resolved from `query_path` in the CLI layer and provide
    /// group names, policy details, and suggested fixes so the diagnostic
    /// can show them inline.
    #[must_use]
    pub fn with_policy_explanations(mut self, explanations: Vec<PolicyExplanation>) -> Self {
        self.policy_explanations = explanations;
        self
    }

    /// Check if an error line mentions any protected file and return the filename.
    ///
    /// This is used by the output processor to detect when a permission error
    /// is specifically due to a signed instruction file being write-protected.
    #[must_use]
    pub fn detect_protected_file_in_error(&self, error_line: &str) -> Option<String> {
        detect_protected_file_in_error_line(self.protected_paths, error_line)
    }

    /// Format the diagnostic footer for a failed command.
    ///
    /// Returns a multi-line string formatted as a dedicated diagnostic block.
    /// The output is designed to be printed to stderr.
    #[must_use]
    pub fn format_footer(&self, exit_code: i32) -> String {
        let body = match self.mode {
            DiagnosticMode::Standard => self.format_standard_footer(exit_code),
            DiagnosticMode::Supervised => self.format_supervised_footer(exit_code),
        };
        render_diagnostic_block(&body)
    }

    /// Check whether the resolved binary path falls under any allowed read path.
    fn is_binary_path_readable(&self) -> bool {
        let cmd = match &self.command {
            Some(c) => c,
            None => return true, // no context, assume readable
        };
        let binary_path = &cmd.resolved_path;
        for cap in self.caps.fs_capabilities() {
            if cap.access == AccessMode::Read || cap.access == AccessMode::ReadWrite {
                if cap.is_file {
                    if *binary_path == cap.resolved {
                        return true;
                    }
                } else if binary_path.starts_with(&cap.resolved) {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether the binary's parent directory is readable in the sandbox.
    fn is_binary_dir_readable(&self) -> bool {
        let cmd = match &self.command {
            Some(c) => c,
            None => return true,
        };
        let binary_dir = match cmd.resolved_path.parent() {
            Some(d) => d,
            None => return false,
        };
        for cap in self.caps.fs_capabilities() {
            if !cap.is_file
                && (cap.access == AccessMode::Read || cap.access == AccessMode::ReadWrite)
                && binary_dir.starts_with(&cap.resolved)
            {
                return true;
            }
        }
        false
    }

    /// Format context-aware explanation for the exit code.
    ///
    /// Returns a vec of diagnostic lines explaining what likely
    /// happened and what the user can do about it.
    fn format_exit_explanation(&self, exit_code: i32) -> Vec<String> {
        let mut lines = Vec::new();

        match exit_code {
            127 => {
                // 127 = command not found (shell convention) or execve failed.
                // When we resolved the program path, prefer the broader wording.
                let headline = if self.command.is_some() {
                    "[nono] Failed to execute command (exit code 127)."
                } else {
                    "[nono] Command not found (exit code 127)."
                };
                lines.push(headline.to_string());
                lines.push("[nono]".to_string());

                if let Some(ref cmd) = self.command {
                    let program = sanitize_for_diagnostic(&cmd.program);
                    let path = sanitize_for_diagnostic(&cmd.resolved_path.display().to_string());
                    if !self.is_binary_path_readable() {
                        // The binary exists (we resolved it) but the sandbox
                        // can't read it.
                        lines.push(format!(
                            "[nono] The executable '{}' was resolved at:",
                            program,
                        ));
                        lines.push(format!("[nono]   {}", path));
                        lines.push(
                            "[nono] but its directory is not readable inside the sandbox."
                                .to_string(),
                        );
                        lines.push("[nono]".to_string());

                        if let Some(parent) = cmd.resolved_path.parent() {
                            let parent_path =
                                sanitize_for_diagnostic(&parent.display().to_string());
                            lines.push(
                                "[nono] Fix: grant read access to the binary's directory:"
                                    .to_string(),
                            );
                            lines.push(format!("[nono]   nono run --read {} ...", parent_path,));
                        }
                    } else if !self.is_binary_dir_readable() {
                        // Binary itself is allowed but its directory isn't
                        // (unlikely but possible with file-level grants)
                        lines.push(format!(
                            "[nono] '{}' resolved to {} but the directory",
                            program, path,
                        ));
                        lines.push(
                            "[nono] may not be accessible. The sandbox needs read access to"
                                .to_string(),
                        );
                        lines.push("[nono] the directory containing the binary.".to_string());
                    } else {
                        // Binary path is readable — the command may depend on
                        // a dynamic linker, shared libraries, or shell that
                        // isn't accessible.
                        lines.push(format!(
                            "[nono] '{}' resolved to {} and is readable,",
                            program, path,
                        ));
                        lines.push("[nono] but execution still failed. Common causes:".to_string());
                        lines.push(
                            "[nono]   - A shared library or dynamic linker path is not accessible"
                                .to_string(),
                        );
                        lines.push(
                            "[nono]   - The binary is a script whose interpreter is not accessible"
                                .to_string(),
                        );
                        lines.push(
                            "[nono]   - The binary depends on a path not in the sandbox"
                                .to_string(),
                        );
                        lines.push("[nono]".to_string());
                        lines.push(
                            "[nono] Run with -v to see all allowed paths and check if".to_string(),
                        );
                        lines.push("[nono] required system directories are included.".to_string());
                    }
                } else {
                    lines.push(
                        "[nono] The command binary could not be found or executed inside"
                            .to_string(),
                    );
                    lines.push(
                        "[nono] the sandbox. Ensure the binary's directory is readable."
                            .to_string(),
                    );
                }
            }
            126 => {
                // 126 = command found but not executable
                lines.push("[nono] Permission denied (exit code 126).".to_string());
                lines.push("[nono]".to_string());

                if let Some(ref cmd) = self.command {
                    let program = sanitize_for_diagnostic(&cmd.program);
                    let path = sanitize_for_diagnostic(&cmd.resolved_path.display().to_string());
                    lines.push(format!(
                        "[nono] '{}' was found at {} but could not be executed.",
                        program, path,
                    ));
                    lines.push(
                        "[nono] The file may not have execute permission, or the sandbox"
                            .to_string(),
                    );
                    lines.push(
                        "[nono] may be blocking execution of binaries in that directory."
                            .to_string(),
                    );
                } else {
                    lines.push(
                        "[nono] The command was found but could not be executed.".to_string(),
                    );
                    lines.push(
                        "[nono] Check file permissions and sandbox access to the binary's directory."
                            .to_string(),
                    );
                }
            }
            code if (129..=192).contains(&code) => {
                // Signal-based exit: 128 + signal number
                let sig = code - 128;
                // SIGSYS is platform-dependent: 31 on Linux, 12 on macOS
                let sigsys: i32 = libc::SIGSYS;
                let sig_name = match sig {
                    1 => "SIGHUP",
                    2 => "SIGINT",
                    4 => "SIGILL",
                    6 => "SIGABRT",
                    9 => "SIGKILL",
                    11 => "SIGSEGV",
                    13 => "SIGPIPE",
                    15 => "SIGTERM",
                    s if s == sigsys => "SIGSYS",
                    _ => "",
                };

                if sig == sigsys {
                    // SIGSYS = seccomp/sandbox killed it
                    lines.push(format!(
                        "[nono] Command killed by {} (exit code {}).",
                        sig_name, code,
                    ));
                    lines.push("[nono]".to_string());
                    lines.push(
                        "[nono] SIGSYS typically means a blocked system call. The command tried"
                            .to_string(),
                    );
                    lines.push("[nono] an operation that the sandbox does not permit.".to_string());
                } else if sig == 9 {
                    lines.push(format!(
                        "[nono] Command killed by {} (exit code {}).",
                        sig_name, code,
                    ));
                    lines.push("[nono]".to_string());
                    lines.push(
                        "[nono] The process was forcefully terminated. This is usually not"
                            .to_string(),
                    );
                    lines.push("[nono] caused by sandbox restrictions.".to_string());
                } else if !sig_name.is_empty() {
                    lines.push(format!(
                        "[nono] Command killed by signal {} / {} (exit code {}).",
                        sig, sig_name, code,
                    ));
                } else {
                    lines.push(format!(
                        "[nono] Command killed by signal {} (exit code {}).",
                        sig, code,
                    ));
                }
            }
            code => {
                lines.push(format_command_failed_line(code));
            }
        }

        lines
    }

    /// Standard mode footer: concise policy summary with --allow suggestions.
    fn format_standard_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();
        let observed_hints = self.actionable_observed_path_hints();
        let primary_verdict = self.primary_observation_verdict();
        let has_observation = self.has_error_observation();

        // Check if this was a protected file write attempt
        if let Some(ref blocked_file) = self.blocked_protected_file {
            lines.push(format!(
                "[nono] Write to '{}' blocked: file is a signed instruction file.",
                blocked_file
            ));
            lines.push(
                "[nono] Signed instruction files are write-protected to prevent tampering."
                    .to_string(),
            );
            lines.push("[nono]".to_string());
            lines.push(format!(
                "[nono] The command failed. (exit code {})",
                exit_code
            ));
        } else if matches!(
            primary_verdict.as_ref(),
            Some(ErrorVerdict::MissingPath(_)) | Some(ErrorVerdict::NonSandboxFailure(_))
        ) {
            lines.push(format_command_failed_not_sandbox_line(exit_code));
        } else if exit_code == 0 && has_observation {
            lines.push(format_command_succeeded_with_stderr_line());
        } else {
            lines.extend(self.format_exit_explanation(exit_code));
        }
        lines.push("[nono]".to_string());

        if self.blocked_protected_file.is_none() {
            if let Some(verdict) = primary_verdict.as_ref() {
                self.format_primary_verdict_guidance(&mut lines, verdict);
                lines.push("[nono]".to_string());
            }
        }

        // Concise policy summary: show user paths, summarize system/group paths
        lines.push("[nono] Sandbox policy:".to_string());

        self.format_allowed_paths_concise(&mut lines);
        self.format_network_status(&mut lines);
        self.format_protected_paths(&mut lines);
        let additional_hints = if observed_hints.len() > 1 {
            &observed_hints[1..]
        } else {
            &[]
        };
        self.format_observed_path_hints(&mut lines, additional_hints);

        // Help section (skip if the failure was specifically due to protected file)
        if self.blocked_protected_file.is_none()
            && observed_hints.is_empty()
            && primary_verdict.is_none()
        {
            lines.push("[nono]".to_string());
            self.format_grant_help(&mut lines);
            lines.push("[nono]".to_string());
            self.format_follow_up_guidance(&mut lines, None);
        }

        lines.join("\n")
    }

    /// Supervised mode footer: show denials and mode-specific guidance.
    fn format_supervised_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();
        let primary_verdict = self.primary_observation_verdict();
        let has_observation = self.has_error_observation();

        if self.denials.is_empty()
            && matches!(
                primary_verdict.as_ref(),
                Some(ErrorVerdict::MissingPath(_)) | Some(ErrorVerdict::NonSandboxFailure(_))
            )
        {
            lines.push(format_command_failed_not_sandbox_line(exit_code));
        } else if exit_code == 0 && has_observation && self.denials.is_empty() {
            lines.push(format_command_succeeded_with_stderr_line());
        } else {
            lines.extend(self.format_exit_explanation(exit_code));
        }
        lines.push("[nono]".to_string());

        // Convert macOS Seatbelt violations (operation + target) into
        // DenialRecords so the same rendering logic handles both platforms.
        let (violation_denials, non_fs_violations) = violations_to_denials(self.sandbox_violations);

        // Merge supervisor denials (Linux seccomp) with violation-derived
        // denials (macOS Seatbelt) into a single unified list.
        let all_denials: Vec<DenialRecord> = self
            .denials
            .iter()
            .cloned()
            .chain(violation_denials)
            .collect();

        if all_denials.is_empty() {
            // No denials from either source.
            if !non_fs_violations.is_empty() {
                // Non-filesystem violations (mach-lookup, signal, etc.) —
                // show them with human-readable descriptions.
                lines.push("[nono] Sandbox blocked system services:".to_string());
                format_non_fs_violations(&mut lines, &non_fs_violations);
                lines.push("[nono]".to_string());
                format_non_fs_guidance(&mut lines, &non_fs_violations);
            } else {
                // Genuinely no denials observed.
                if let Some(verdict) = primary_verdict.as_ref() {
                    self.format_primary_verdict_guidance(&mut lines, verdict);
                    lines.push("[nono]".to_string());
                }
                lines.push("[nono] No path denials were observed during this session.".to_string());
                lines.push(
                    "[nono] The failure may be unrelated to sandbox restrictions.".to_string(),
                );
            }
            lines.push("[nono]".to_string());
            self.format_grant_help(&mut lines);
            lines.push("[nono]".to_string());
            self.format_follow_up_guidance(&mut lines, None);
        } else {
            // Deduplicate by path, merging access modes. Classification into
            // actionable vs. policy-blocked is done by the consolidated
            // formatter using policy_explanations when available.
            let deduped = dedupe_denials(&all_denials);
            self.format_consolidated_denial_guidance(&mut lines, &deduped);

            // Show non-filesystem violations (mach-lookup, etc.) if any
            if !non_fs_violations.is_empty() {
                lines.push("[nono]".to_string());
                lines.push("[nono] Also blocked (system services):".to_string());
                format_non_fs_violations(&mut lines, &non_fs_violations);
                lines.push("[nono]".to_string());
                format_non_fs_guidance(&mut lines, &non_fs_violations);
            }

            // Note: `nono grant` suggestions are shown via desktop
            // notifications during the session, not in the post-exit footer.
        }

        lines.join("\n")
    }

    fn actionable_observed_path_hints(&self) -> Vec<ObservedPathHint> {
        self.observed_path_hints
            .iter()
            .filter_map(|hint| {
                self.actionable_observed_access(&hint.path, hint.access)
                    .map(|access| ObservedPathHint {
                        path: hint.path.clone(),
                        access,
                    })
            })
            .collect()
    }

    fn primary_observation_verdict(&self) -> Option<ErrorVerdict> {
        self.missing_path_hints
            .first()
            .cloned()
            .map(ErrorVerdict::MissingPath)
            .or_else(|| {
                self.non_sandbox_failure
                    .clone()
                    .map(ErrorVerdict::NonSandboxFailure)
            })
            .or_else(|| {
                self.actionable_observed_path_hints()
                    .first()
                    .cloned()
                    .map(ErrorVerdict::LikelySandbox)
            })
    }

    fn has_error_observation(&self) -> bool {
        self.primary_verdict.is_some()
            || self.blocked_protected_file.is_some()
            || !self.observed_path_hints.is_empty()
            || !self.missing_path_hints.is_empty()
            || self.non_sandbox_failure.is_some()
    }

    fn actionable_observed_access(&self, path: &Path, inferred: AccessMode) -> Option<AccessMode> {
        let Some(cap) = self.closest_covering_capability_any(path) else {
            return Some(inferred);
        };

        if cap.access.contains(inferred) {
            return None;
        }

        match (cap.access, inferred) {
            (AccessMode::Read, AccessMode::ReadWrite) => Some(AccessMode::Write),
            (AccessMode::Write, AccessMode::ReadWrite) => Some(AccessMode::Read),
            _ => Some(inferred),
        }
    }

    fn closest_covering_capability_any(
        &self,
        path: &Path,
    ) -> Option<&crate::capability::FsCapability> {
        let canonical = try_canonicalize(path);
        let mut best_covering: Option<&crate::capability::FsCapability> = None;
        let mut best_covering_score = 0usize;

        for cap in self.caps.fs_capabilities() {
            let covers = if cap.is_file {
                cap.resolved == canonical
            } else {
                canonical.starts_with(&cap.resolved)
            };

            if !covers {
                continue;
            }

            let score = cap.resolved.as_os_str().len();
            if score >= best_covering_score {
                best_covering = Some(cap);
                best_covering_score = score;
            }
        }

        best_covering
    }

    fn format_follow_up_guidance(
        &self,
        lines: &mut Vec<String>,
        _hint: Option<(&Path, AccessMode)>,
    ) {
        lines.push("[nono] Next steps:".to_string());
        if let Some(command) = self.format_command_for_learn() {
            lines.push(format!(
                "[nono]   Discover paths: nono learn -- {}",
                command
            ));
        } else {
            lines.push("[nono]   Discover paths: nono learn -- <your command>".to_string());
        }
        lines.push(
            "[nono]   Query policy: nono why --path <path> --op <read|write|readwrite>".to_string(),
        );
    }

    fn format_primary_observed_guidance(&self, lines: &mut Vec<String>, hint: &ObservedPathHint) {
        lines.push("[nono] Sandbox denial:".to_string());
        if self.observed_hint_points_to_read_only_cwd(hint) {
            lines.push(
                "[nono]   The command appears to be writing inside the current working directory,"
                    .to_string(),
            );
            lines.push(
                "[nono]   but the current working directory is read-only in this sandbox."
                    .to_string(),
            );
        }
        lines.push(format!(
            "[nono]   {} ({})",
            hint.path.display(),
            access_str(hint.access),
        ));
        lines.push(format!(
            "[nono]   Try: {}",
            self.suggested_flag_for_hint(&hint.path, hint.access)
        ));
    }

    fn format_primary_verdict_guidance(&self, lines: &mut Vec<String>, verdict: &ErrorVerdict) {
        match verdict {
            ErrorVerdict::LikelySandbox(hint) => {
                self.format_primary_observed_guidance(lines, hint);
            }
            ErrorVerdict::MissingPath(path) => {
                self.format_primary_missing_path_guidance(lines, path);
            }
            ErrorVerdict::NonSandboxFailure(failure) => {
                self.format_non_sandbox_failure_guidance(lines, failure);
            }
        }
    }

    fn format_primary_missing_path_guidance(&self, lines: &mut Vec<String>, path: &Path) {
        lines.push("[nono] Missing path:".to_string());
        lines.push(format!("[nono]   {}", path.display()));
        lines.push("[nono]   The command reported \"No such file or directory\".".to_string());
        lines.push(
            "[nono]   Path flags only apply to paths that already exist when nono starts."
                .to_string(),
        );
        lines.push(
            "[nono]   Create the path first, or grant an existing parent directory if the command needs to create it."
                .to_string(),
        );
    }

    fn format_non_sandbox_failure_guidance(&self, lines: &mut Vec<String>, failure: &str) {
        lines.push("[nono] Application error:".to_string());
        lines.push(format!("[nono]   {}", sanitize_for_diagnostic(failure)));
        lines.push(
            "[nono]   The command's own output suggests this failure is unrelated to sandbox permissions."
                .to_string(),
        );
    }

    /// Render the consolidated denial block.
    ///
    /// Shows every denied path (truncated past `MAX_INLINE_LIST` entries) with
    /// a `[permanently restricted]` marker for paths that are blocked by the
    /// sensitive-path policy, and emits a single `Fix:` line combining the
    /// `--read`/`--write`/`--allow` flags for all actionable denials.
    ///
    /// Classification: if a policy explanation with `reason == "sensitive_path"`
    /// exists for a path, it is treated as policy-blocked and cannot be fixed
    /// via flags. Everything else is actionable, including macOS Seatbelt
    /// denials whose `DenialReason` defaults to `PolicyBlocked` (that reason
    /// is over-broad on macOS — we trust the query_path result instead).
    fn format_consolidated_denial_guidance(
        &self,
        lines: &mut Vec<String>,
        denials: &[DenialRecord],
    ) {
        const MAX_INLINE_LIST: usize = 10;

        let total = denials.len();
        let mut actionable: Vec<&DenialRecord> = Vec::new();
        let mut policy_blocked: Vec<&DenialRecord> = Vec::new();

        for denial in denials {
            if self.is_denial_policy_blocked(denial) {
                policy_blocked.push(denial);
            } else {
                actionable.push(denial);
            }
        }

        let plural_s = if total == 1 { "" } else { "s" };
        lines.push(format!(
            "[nono] Sandbox denial: {} path{} blocked.",
            total, plural_s
        ));

        for (idx, denial) in denials.iter().enumerate() {
            if idx >= MAX_INLINE_LIST {
                lines.push(format!("[nono]   … and {} more", total - idx));
                break;
            }
            let suffix = if self.is_denial_policy_blocked(denial) {
                "  [permanently restricted]"
            } else {
                ""
            };
            lines.push(format!(
                "[nono]   {} ({}){}",
                denial.path.display(),
                access_str(denial.access),
                suffix,
            ));
        }

        if !actionable.is_empty() {
            let flags: Vec<String> = actionable
                .iter()
                .map(|d| self.suggested_flag_for_denial(d))
                .collect();
            lines.push(format!("[nono] Fix: {}", flags.join(" ")));
        }

        if !policy_blocked.is_empty() {
            let n = policy_blocked.len();
            let (subject, verb) = if n == 1 {
                ("1 path is", "")
            } else {
                ("paths are", "")
            };
            let count_prefix = if n == 1 {
                String::from(subject)
            } else {
                format!("{} {}", n, subject)
            };
            lines.push("[nono]".to_string());
            lines.push(format!(
                "[nono] {}{} permanently restricted — override via a user profile with filesystem.bypass_protection.",
                count_prefix, verb,
            ));
        }
    }

    /// Return true when the denial cannot be fixed by a path flag alone —
    /// i.e. the path is blocked by the sensitive-path policy and requires a
    /// profile with `filesystem.bypass_protection`.
    fn is_denial_policy_blocked(&self, denial: &DenialRecord) -> bool {
        if let Some(expl) = self
            .policy_explanations
            .iter()
            .find(|e| e.path == denial.path)
        {
            return expl.reason == "sensitive_path";
        }
        // No explanation (e.g. Linux seccomp path without a matching lookup):
        // trust the DenialRecord reason.
        denial.reason == DenialReason::PolicyBlocked
    }

    /// Build the CLI flag suggestion for a single denial. Prefers the
    /// explanation's `suggested_flag` (which knows about parent-directory
    /// canonicalization) and falls back to a local computation otherwise.
    fn suggested_flag_for_denial(&self, denial: &DenialRecord) -> String {
        if let Some(flag) = self
            .policy_explanations
            .iter()
            .find(|e| e.path == denial.path)
            .and_then(|e| e.suggested_flag.clone())
        {
            // explanations' suggested_flag is of the form "--read /path".
            // Strip any leading "Fix: " that callers may have prepended.
            return flag
                .strip_prefix("Fix: ")
                .map(str::to_string)
                .unwrap_or(flag);
        }
        suggested_flag_for_path(&denial.path, denial.access)
    }

    fn format_grant_help(&self, lines: &mut Vec<String>) {
        lines.push("[nono] To grant additional access, re-run with:".to_string());
        lines.push("[nono]   --allow <path>     read+write access to directory".to_string());
        lines.push("[nono]   --read <path>      read-only access to directory".to_string());
        lines.push("[nono]   --write <path>     write-only access to directory".to_string());

        if self.caps.is_network_blocked() {
            lines.push(
                "[nono]   --allow-net        unrestricted network for this session".to_string(),
            );
        }
    }

    fn format_command_for_learn(&self) -> Option<String> {
        let command = self.command.as_ref()?;
        if command.args.is_empty() {
            return None;
        }

        Some(
            command
                .args
                .iter()
                .map(|arg| shell_quote(arg))
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    fn suggested_flag_for_hint(&self, path: &Path, requested: AccessMode) -> String {
        if let Some(flag) = self.suggested_upgrade_flag_for_existing_capability(path, requested) {
            flag
        } else if self.observed_hint_points_to_ungranted_cwd(path) {
            "--allow-cwd".to_string()
        } else {
            suggested_flag_for_path(path, requested)
        }
    }

    fn observed_hint_points_to_read_only_cwd(&self, hint: &ObservedPathHint) -> bool {
        let Some(current_dir) = self.current_dir else {
            return false;
        };

        hint.path.starts_with(current_dir)
            && self
                .suggested_upgrade_flag_for_existing_capability(&hint.path, hint.access)
                .is_some()
    }

    fn suggested_upgrade_flag_for_existing_capability(
        &self,
        path: &Path,
        requested: AccessMode,
    ) -> Option<String> {
        let cap = self.closest_covering_capability_any(path)?;
        if cap.access.contains(requested) {
            return None;
        }

        let target = cap.resolved.clone();

        let requested = match (cap.access, requested) {
            (AccessMode::Read, AccessMode::ReadWrite) => AccessMode::Write,
            (AccessMode::Write, AccessMode::ReadWrite) => AccessMode::Read,
            _ => requested,
        };

        Some(suggested_flag_for_existing_target(
            &target,
            cap.is_file,
            requested,
        ))
    }

    fn observed_hint_points_to_ungranted_cwd(&self, path: &Path) -> bool {
        let Some(current_dir) = self.current_dir else {
            return false;
        };

        if !path.starts_with(current_dir) {
            return false;
        }

        self.closest_covering_capability_any(current_dir).is_none()
    }

    /// Format allowed paths concisely: show user/profile paths explicitly,
    /// summarize group/system paths with a count.
    fn format_allowed_paths_concise(&self, lines: &mut Vec<String>) {
        let caps = self.caps.fs_capabilities();
        if caps.is_empty() {
            lines.push("[nono]   Allowed paths: (none)".to_string());
            return;
        }

        let mut user_paths = Vec::new();
        let mut group_count: usize = 0;

        for cap in caps {
            match &cap.source {
                CapabilitySource::User | CapabilitySource::Profile => {
                    let kind = if cap.is_file { "file" } else { "dir" };
                    user_paths.push(format!(
                        "[nono]     {} ({}, {})",
                        cap.resolved.display(),
                        access_str(cap.access),
                        kind,
                    ));
                }
                CapabilitySource::Group(_) | CapabilitySource::System => {
                    group_count += 1;
                }
            }
        }

        if user_paths.is_empty() && group_count == 0 {
            lines.push("[nono]   Allowed paths: (none)".to_string());
        } else {
            lines.push("[nono]   Allowed paths:".to_string());
            for p in &user_paths {
                lines.push(p.clone());
            }
            if group_count > 0 {
                lines.push(format!("[nono]     + {} system/group path(s)", group_count));
            }
        }
    }

    fn format_observed_path_hints(&self, lines: &mut Vec<String>, hints: &[ObservedPathHint]) {
        if hints.is_empty() {
            return;
        }

        lines.push("[nono]   Likely blocked paths seen in the command output:".to_string());
        for hint in hints {
            lines.push(format!(
                "[nono]     {} ({})",
                hint.path.display(),
                access_str(hint.access),
            ));
        }
    }

    /// Format the network status.
    fn format_network_status(&self, lines: &mut Vec<String>) {
        use crate::NetworkMode;
        match self.caps.network_mode() {
            NetworkMode::Blocked => {
                lines.push("[nono]   Network: blocked".to_string());
            }
            NetworkMode::ProxyOnly { port, bind_ports } => {
                if bind_ports.is_empty() {
                    lines.push(format!("[nono]   Network: proxy (localhost:{})", port));
                } else {
                    let ports_str: Vec<String> = bind_ports.iter().map(|p| p.to_string()).collect();
                    lines.push(format!(
                        "[nono]   Network: proxy (localhost:{}), bind: {}",
                        port,
                        ports_str.join(", ")
                    ));
                }
            }
            NetworkMode::AllowAll => {
                lines.push("[nono]   Network: allowed".to_string());
            }
        }
    }

    /// Format write-protected paths (signed instruction files).
    fn format_protected_paths(&self, lines: &mut Vec<String>) {
        if self.protected_paths.is_empty() {
            return;
        }

        lines.push("[nono]   Write-protected (signed instruction files):".to_string());
        for path in self.protected_paths {
            // Show just the filename for brevity
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            lines.push(format!("[nono]     {}", name));
        }
    }

    /// Format a concise single-line summary of the policy.
    ///
    /// Useful for logging or brief status messages.
    #[must_use]
    pub fn format_summary(&self) -> String {
        let path_count = self.caps.fs_capabilities().len();
        let network_status = if self.caps.is_network_blocked() {
            "blocked"
        } else {
            "allowed"
        };

        format!(
            "[nono] Policy: {} path(s), network {}",
            path_count, network_status
        )
    }
}

/// Human-readable descriptions for commonly denied macOS mach services.
fn describe_mach_service(service: &str) -> Option<&'static str> {
    Some(match service {
        s if s.starts_with("com.apple.security") || s == "com.apple.secd" => {
            "Keychain / Security framework"
        }
        "com.apple.logd" => "System logging",
        "com.apple.system.notification_center" | "com.apple.distributed_notifications" => {
            "Distributed notifications"
        }
        "com.apple.CoreServices.coreservicesd" | "com.apple.lsd.mapdb" => "Launch Services",
        s if s.starts_with("com.apple.windowserver") => "Window Server / GUI",
        s if s.starts_with("com.apple.cfprefsd") => "Preferences (NSUserDefaults)",
        s if s.starts_with("com.apple.pasteboard") => "Pasteboard / clipboard",
        s if s.starts_with("com.apple.coreservices") => "Core Services",
        _ => return None,
    })
}

/// Format non-filesystem violations with human-readable service descriptions.
fn format_non_fs_violations(lines: &mut Vec<String>, violations: &[&SandboxViolation]) {
    for v in violations {
        let desc = v.target.as_deref().and_then(describe_mach_service);
        match (&v.target, desc) {
            (Some(target), Some(description)) => {
                lines.push(format!(
                    "[nono]   {} ({}) — {}",
                    v.operation, target, description
                ));
            }
            (Some(target), None) => {
                lines.push(format!("[nono]   {} ({})", v.operation, target));
            }
            (None, _) => {
                lines.push(format!("[nono]   {}", v.operation));
            }
        }
    }
}

/// Generate actionable guidance for non-filesystem violations.
fn format_non_fs_guidance(lines: &mut Vec<String>, violations: &[&SandboxViolation]) {
    let has_keychain = violations.iter().any(|v| {
        v.target
            .as_deref()
            .is_some_and(|t| t.contains("SecurityServer") || t.contains("securityd"))
    });

    if has_keychain {
        lines.push("[nono] Keychain access requires granting the login keychain path:".to_string());
        lines.push("[nono]   --read ~/Library/Keychains/login.keychain-db".to_string());
    }
}

/// Deduplicate denials by path, merging access modes. When the same path
/// appears with multiple reasons, the most restrictive reason wins
/// (`PolicyBlocked` > `InsufficientAccess` > `UserDenied` > `RateLimited` >
/// `BackendError`). Output is sorted by path for stable rendering.
fn dedupe_denials(denials: &[DenialRecord]) -> Vec<DenialRecord> {
    let mut by_path = std::collections::BTreeMap::<PathBuf, (AccessMode, DenialReason)>::new();

    for denial in denials {
        by_path
            .entry(denial.path.clone())
            .and_modify(|(access, reason)| {
                *access = merge_access_modes(*access, denial.access);
                *reason = stricter_reason(reason.clone(), denial.reason.clone());
            })
            .or_insert_with(|| (denial.access, denial.reason.clone()));
    }

    by_path
        .into_iter()
        .map(|(path, (access, reason))| DenialRecord {
            path,
            access,
            reason,
        })
        .collect()
}

fn stricter_reason(a: DenialReason, b: DenialReason) -> DenialReason {
    fn rank(r: &DenialReason) -> u8 {
        match r {
            DenialReason::PolicyBlocked => 5,
            DenialReason::InsufficientAccess => 4,
            DenialReason::UserDenied => 3,
            DenialReason::RateLimited => 2,
            DenialReason::BackendError => 1,
        }
    }
    if rank(&a) >= rank(&b) {
        a
    } else {
        b
    }
}

/// Map a Seatbelt operation name to an `AccessMode`.
///
/// Returns `None` for non-filesystem operations (e.g. `mach-lookup`,
/// `signal`, `process-exec`) that cannot be expressed as path grants.
pub fn seatbelt_operation_to_access(operation: &str) -> Option<AccessMode> {
    match operation {
        "file-read-data" | "file-read-metadata" | "file-read-xattr" => Some(AccessMode::Read),
        "file-write-data" | "file-write-create" | "file-write-unlink" | "file-write-flags"
        | "file-write-mode" | "file-write-owner" | "file-write-times" | "file-write-xattr" => {
            Some(AccessMode::Write)
        }
        _ => None,
    }
}

/// Convert `SandboxViolation`s with filesystem targets into `DenialRecord`s.
///
/// Non-filesystem violations (mach-lookup, signal, etc.) are returned
/// separately since they can't be expressed as path grants.
fn violations_to_denials(
    violations: &[SandboxViolation],
) -> (Vec<DenialRecord>, Vec<&SandboxViolation>) {
    let mut denials = Vec::new();
    let mut non_fs = Vec::new();
    // Deduplicate: multiple operations on the same path merge into one denial
    let mut seen = std::collections::BTreeMap::<PathBuf, AccessMode>::new();

    for v in violations {
        if let (Some(access), Some(target)) =
            (seatbelt_operation_to_access(&v.operation), &v.target)
        {
            let path = PathBuf::from(target);
            seen.entry(path)
                .and_modify(|existing| *existing = merge_access_modes(*existing, access))
                .or_insert(access);
        } else {
            non_fs.push(v);
        }
    }

    for (path, access) in seen {
        denials.push(DenialRecord {
            path,
            access,
            reason: DenialReason::PolicyBlocked,
        });
    }

    (denials, non_fs)
}

fn access_str(access: AccessMode) -> &'static str {
    match access {
        AccessMode::Read => "read",
        AccessMode::Write => "write",
        AccessMode::ReadWrite => "read+write",
    }
}

fn merge_access_modes(existing: AccessMode, new: AccessMode) -> AccessMode {
    if existing == new {
        existing
    } else {
        AccessMode::ReadWrite
    }
}

fn suggested_flag_for_path(path: &Path, requested: AccessMode) -> String {
    let (flag, target) = suggested_flag_parts(path, requested);
    format!("{flag} {}", target.display())
}

fn suggested_flag_for_existing_target(
    target: &Path,
    is_file: bool,
    requested: AccessMode,
) -> String {
    let flag = if is_file {
        match requested {
            AccessMode::Read => "--read-file",
            AccessMode::Write => "--write-file",
            AccessMode::ReadWrite => "--allow-file",
        }
    } else {
        match requested {
            AccessMode::Read => "--read",
            AccessMode::Write => "--write",
            AccessMode::ReadWrite => "--allow",
        }
    };

    format!("{flag} {}", target.display())
}

fn suggested_flag_parts(path: &Path, requested: AccessMode) -> (&'static str, PathBuf) {
    let flag = if path.is_file() {
        match requested {
            AccessMode::Read => "--read-file",
            AccessMode::Write => "--write-file",
            AccessMode::ReadWrite => "--allow-file",
        }
    } else {
        match requested {
            AccessMode::Read => "--read",
            AccessMode::Write => "--write",
            AccessMode::ReadWrite => "--allow",
        }
    };

    let target = if path.exists() || path.is_dir() || path.parent().is_none() {
        path.to_path_buf()
    } else if let Some(parent) = path.parent() {
        parent.to_path_buf()
    } else {
        path.to_path_buf()
    };

    (flag, target)
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
    {
        return s.to_string();
    }

    let mut quoted = String::with_capacity(s.len() + 2);
    quoted.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySource, FsCapability};
    use tempfile::tempdir;

    fn make_test_caps() -> CapabilitySet {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps
    }

    fn make_mixed_caps() -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/home/user/project"),
            resolved: PathBuf::from("/home/user/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr/bin"),
            resolved: PathBuf::from("/usr/bin"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("base_read".to_string()),
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr/lib"),
            resolved: PathBuf::from("/usr/lib"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("base_read".to_string()),
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/tmp"),
            resolved: PathBuf::from("/tmp"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps
    }

    // --- Standard mode tests ---

    #[test]
    fn test_standard_footer_contains_exit_code() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Command exited with code 1."));
    }

    #[test]
    fn test_standard_footer_uses_may_not_was() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(!output.contains("may be due to sandbox restrictions"));
        assert!(!output.contains("was caused by"));
    }

    #[test]
    fn test_standard_footer_has_block_header() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(!output.starts_with("nono diagnostic"));
        assert!(!output.contains("[nono]"));
    }

    #[test]
    fn test_standard_footer_shows_user_paths() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("/test/project"));
        assert!(output.contains("read+write"));
    }

    #[test]
    fn test_standard_footer_summarizes_group_paths() {
        let caps = make_mixed_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        // User path shown explicitly
        assert!(output.contains("/home/user/project"));
        // Group/system paths summarized, not listed individually
        assert!(output.contains("3 system/group path(s)"));
        assert!(!output.contains("/usr/bin"));
        assert!(!output.contains("/usr/lib"));
    }

    #[test]
    fn test_standard_footer_shows_network_blocked() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: blocked"));
    }

    #[test]
    fn test_standard_footer_shows_network_allowed() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: allowed"));
    }

    #[test]
    fn test_standard_footer_shows_network_proxy() {
        use crate::NetworkMode;
        let mut caps = CapabilitySet::new().block_network();
        caps.set_network_mode_mut(NetworkMode::ProxyOnly {
            port: 12345,
            bind_ports: vec![],
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: proxy (localhost:12345)"));
    }

    #[test]
    fn test_standard_footer_shows_help() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("--allow <path>"));
        assert!(output.contains("--read <path>"));
        assert!(output.contains("--write <path>"));
    }

    #[test]
    fn test_standard_footer_shows_network_help_when_blocked() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("--allow-net"));
    }

    #[test]
    fn test_standard_footer_no_network_help_when_allowed() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(!output.contains("--allow-net"));
    }

    #[test]
    fn test_analyze_error_output_detects_read_path() {
        let observation = analyze_error_output(
            "/bin/sh: /Users/alice/.profile: Operation not permitted\n",
            &[],
            None,
        );

        assert_eq!(
            observation.path_hints,
            vec![ObservedPathHint {
                path: PathBuf::from("/Users/alice/.profile"),
                access: AccessMode::Read,
            }]
        );
    }

    #[test]
    fn test_analyze_error_output_detects_write_path_with_spaces() {
        let observation = analyze_error_output(
            "sh: cannot create '/tmp/file with spaces.txt': Operation not permitted\n",
            &[],
            None,
        );

        assert_eq!(
            observation.path_hints,
            vec![ObservedPathHint {
                path: PathBuf::from("/tmp/file with spaces.txt"),
                access: AccessMode::Write,
            }]
        );
    }

    #[test]
    fn test_analyze_error_output_merges_access_modes() {
        let observation = analyze_error_output(
            "cat: /tmp/shared.txt: Permission denied\ntee: /tmp/shared.txt: Operation not permitted\n",
            &[],
            None,
        );

        assert_eq!(
            observation.path_hints,
            vec![ObservedPathHint {
                path: PathBuf::from("/tmp/shared.txt"),
                access: AccessMode::ReadWrite,
            }]
        );
    }

    #[test]
    fn test_analyze_error_output_detects_missing_path() {
        let observation = analyze_error_output(
            "sh: /tmp/missing/file.txt: No such file or directory\n",
            &[],
            None,
        );

        assert_eq!(observation.path_hints, Vec::<ObservedPathHint>::new());
        assert_eq!(
            observation.missing_paths,
            vec![PathBuf::from("/tmp/missing/file.txt")]
        );
    }

    #[test]
    fn test_analyze_error_output_handles_quoted_execvp_path() {
        // Regression: "sandbox-exec: execvp() of '/bin/ls' failed: Permission denied"
        // must extract /bin/ls, not "/bin/ls' failed".
        let observation = analyze_error_output(
            "sandbox-exec: execvp() of '/bin/ls' failed: Permission denied\n",
            &[],
            None,
        );

        assert_eq!(
            observation.path_hints,
            vec![ObservedPathHint {
                path: PathBuf::from("/bin/ls"),
                access: AccessMode::ReadWrite,
            }]
        );
    }

    #[test]
    fn test_analyze_error_output_handles_double_quoted_path() {
        let observation = analyze_error_output(
            "error: cannot open \"/etc/shadow\" for reading: Permission denied\n",
            &[],
            None,
        );

        assert_eq!(
            observation.path_hints,
            vec![ObservedPathHint {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
            }]
        );
    }

    #[test]
    fn test_analyze_error_output_infers_relative_write_path_from_cwd() {
        let cwd = Path::new("/Users/luke/project");
        let observation = analyze_error_output(
            "Creating empty tessl.json...\nPermission denied. Please check file permissions and try again.\n",
            &[],
            Some(cwd),
        );

        assert_eq!(
            observation.path_hints,
            vec![ObservedPathHint {
                path: PathBuf::from("/Users/luke/project/tessl.json"),
                access: AccessMode::Write,
            }]
        );
        assert_eq!(
            observation.primary_verdict,
            Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: PathBuf::from("/Users/luke/project/tessl.json"),
                access: AccessMode::Write,
            }))
        );
    }

    #[test]
    fn test_analyze_error_output_detects_non_sandbox_failure() {
        let observation = analyze_error_output(
            "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'\n",
            &[],
            None,
        );

        assert_eq!(
            observation.non_sandbox_failure.as_deref(),
            Some("EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'")
        );
        assert_eq!(
            observation.primary_verdict,
            Some(ErrorVerdict::NonSandboxFailure(
                "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                    .to_string(),
            ))
        );
        assert!(observation.path_hints.is_empty());
        assert!(observation.missing_paths.is_empty());
    }

    #[test]
    fn test_standard_footer_empty_caps() {
        let caps = CapabilitySet::new();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("(none)"));
    }

    #[test]
    fn test_standard_footer_file_vs_dir() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/file.txt"),
            resolved: PathBuf::from("/test/file.txt"),
            access: AccessMode::Read,
            is_file: true,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/dir"),
            resolved: PathBuf::from("/test/dir"),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::User,
        });

        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("file.txt (read, file)"));
        assert!(output.contains("dir (write, dir)"));
    }

    #[test]
    fn test_format_summary() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let summary = formatter.format_summary();

        assert!(summary.contains("1 path(s)"));
        assert!(summary.contains("network blocked"));
    }

    #[test]
    fn test_standard_footer_shows_observed_path_hint_suggestions() {
        let temp = match tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("tempdir failed: {e}"),
        };
        let denied = temp.path().join("denied.txt");
        if let Err(e) = std::fs::write(&denied, "secret") {
            panic!("write failed: {e}");
        }
        let caps = make_test_caps();

        let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            })),
            blocked_protected_file: None,
            path_hints: vec![ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            }],
            missing_paths: Vec::new(),
            non_sandbox_failure: None,
        });
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox denial:"));
        assert!(output.contains(&denied.display().to_string()));
        assert!(output.contains(&format!("Try: --read-file {}", denied.display())));
        assert!(output.contains("Sandbox policy:"));
    }

    #[test]
    fn test_standard_footer_exit_zero_with_observed_hint_still_surfaces_diagnostic() {
        let denied = PathBuf::from("/Users/alice/.profile");
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            })),
            blocked_protected_file: None,
            path_hints: vec![ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            }],
            missing_paths: Vec::new(),
            non_sandbox_failure: None,
        });
        let output = formatter.format_footer(0);

        assert!(output.contains(
            "The command succeeded, but stderr showed a likely sandbox-related access issue."
        ));
        assert!(output.contains("Sandbox denial:"));
        assert!(output.contains(&denied.display().to_string()));
    }

    #[test]
    fn test_standard_footer_surfaces_missing_path_before_policy() {
        let caps = make_test_caps();
        let missing = PathBuf::from("/tmp/missing/file.txt");
        let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::MissingPath(missing.clone())),
            blocked_protected_file: None,
            path_hints: Vec::new(),
            missing_paths: vec![missing.clone()],
            non_sandbox_failure: None,
        });
        let output = formatter.format_footer(1);
        let missing_idx = match output.find("Missing path:") {
            Some(idx) => idx,
            None => panic!("missing path block missing: {output}"),
        };
        let policy_idx = match output.find("Sandbox policy:") {
            Some(idx) => idx,
            None => panic!("policy block missing: {output}"),
        };

        assert!(
            output.contains("The command failed, but this does not look like a sandbox denial.")
        );
        assert!(output.contains(&missing.display().to_string()));
        assert!(output.contains("Path flags only apply to paths that already exist"));
        assert!(missing_idx < policy_idx);
        assert!(!output.contains("To grant additional access, re-run with:"));
        assert!(!output.contains("Why: nono why"));
    }

    #[test]
    fn test_standard_footer_surfaces_non_sandbox_failure_before_policy() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::NonSandboxFailure(
                "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                    .to_string(),
            )),
            blocked_protected_file: None,
            path_hints: Vec::new(),
            missing_paths: Vec::new(),
            non_sandbox_failure: Some(
                "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                    .to_string(),
            ),
        });
        let output = formatter.format_footer(1);

        assert!(
            output.contains("The command failed, but this does not look like a sandbox denial.")
        );
        assert!(output.contains("Application error:"));
        assert!(output.contains("EEXIST: file already exists"));
        assert!(!output.contains("To grant additional access, re-run with:"));
        assert!(!output.contains("Why: nono why"));
    }

    #[test]
    fn test_standard_footer_observed_hint_narrows_to_missing_write_access() {
        let temp = match tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("tempdir failed: {e}"),
        };
        let denied = temp.path().join("denied.txt");
        if let Err(e) = std::fs::write(&denied, "secret") {
            panic!("write failed: {e}");
        }

        let canonical_temp = match temp.path().canonicalize() {
            Ok(path) => path,
            Err(e) => panic!("canonicalize failed: {e}"),
        };

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: temp.path().to_path_buf(),
            resolved: canonical_temp.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::ReadWrite,
            })),
            blocked_protected_file: None,
            path_hints: vec![ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::ReadWrite,
            }],
            missing_paths: Vec::new(),
            non_sandbox_failure: None,
        });
        let output = formatter.format_footer(1);

        assert!(output.contains(&format!("{} (write)", denied.display())));
        assert!(output.contains(&format!("--write {}", canonical_temp.display())));
        assert!(!output.contains(&format!("--allow-file {}", denied.display())));
    }

    #[test]
    fn test_standard_footer_prefers_explicit_write_upgrade_for_read_only_cwd_write() {
        let cwd = PathBuf::from("/Users/luke/project");
        let denied = cwd.join("tessl.json");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: cwd.clone(),
            resolved: cwd.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        let formatter = DiagnosticFormatter::new(&caps)
            .with_current_dir(&cwd)
            .with_error_observation(ErrorObservation {
                primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                    path: denied.clone(),
                    access: AccessMode::Write,
                })),
                blocked_protected_file: None,
                path_hints: vec![ObservedPathHint {
                    path: denied.clone(),
                    access: AccessMode::Write,
                }],
                missing_paths: Vec::new(),
                non_sandbox_failure: None,
            });
        let output = formatter.format_footer(1);

        assert!(output.contains("current working directory is read-only"));
        assert!(output.contains(&format!("Try: --write {}", cwd.display())));
        assert!(!output.contains("Try: --allow-cwd"));
    }

    #[test]
    fn test_standard_footer_skips_observed_hint_already_covered() {
        let temp = match tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("tempdir failed: {e}"),
        };
        let denied = temp.path().join("denied.txt");
        if let Err(e) = std::fs::write(&denied, "secret") {
            panic!("write failed: {e}");
        }

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: temp.path().to_path_buf(),
            resolved: match temp.path().canonicalize() {
                Ok(path) => path,
                Err(e) => panic!("canonicalize failed: {e}"),
            },
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            })),
            blocked_protected_file: None,
            path_hints: vec![ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            }],
            missing_paths: Vec::new(),
            non_sandbox_failure: None,
        });
        let output = formatter.format_footer(1);

        assert!(!output.contains("Likely blocked paths seen in the command output"));
        assert!(!output.contains(&denied.display().to_string()));
        assert!(!output.contains("--read-file"));
    }

    // --- Supervised mode tests ---

    #[test]
    fn test_supervised_no_denials_no_extensions() {
        let caps = make_test_caps(); // extensions_enabled defaults to false
        let formatter = DiagnosticFormatter::new(&caps).with_mode(DiagnosticMode::Supervised);
        let output = formatter.format_footer(1);

        assert!(output.contains("No path denials were observed during this session."));
        assert!(output.contains("The failure may be unrelated to sandbox restrictions."));
        assert!(output.contains("To grant additional access, re-run with:"));
        assert!(output.contains("--allow <path>"));
        assert!(!output.contains("Sandbox policy:"));
    }

    #[test]
    fn test_supervised_no_denials_no_extensions_uses_observed_hints() {
        let temp = match tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("tempdir failed: {e}"),
        };
        let denied = temp.path().join("startup.txt");
        if let Err(e) = std::fs::write(&denied, "secret") {
            panic!("write failed: {e}");
        }
        let caps = make_test_caps();

        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_error_observation(ErrorObservation {
                primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                    path: denied.clone(),
                    access: AccessMode::Read,
                })),
                blocked_protected_file: None,
                path_hints: vec![ObservedPathHint {
                    path: denied.clone(),
                    access: AccessMode::Read,
                }],
                missing_paths: Vec::new(),
                non_sandbox_failure: None,
            });
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox denial:"));
        assert!(output.contains(&format!("Try: --read-file {}", denied.display())));
        assert!(output.contains("No path denials were observed during this session."));
        assert!(output.contains("Discover paths: nono learn -- <your command>"));
        assert!(!output.contains("Sandbox policy:"));
    }

    #[test]
    fn test_supervised_exit_zero_with_observed_hint_still_surfaces_diagnostic() {
        let denied = PathBuf::from("/Users/alice/.profile");
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_error_observation(ErrorObservation {
                primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                    path: denied.clone(),
                    access: AccessMode::Read,
                })),
                blocked_protected_file: None,
                path_hints: vec![ObservedPathHint {
                    path: denied.clone(),
                    access: AccessMode::Read,
                }],
                missing_paths: Vec::new(),
                non_sandbox_failure: None,
            });
        let output = formatter.format_footer(0);

        assert!(output.contains(
            "The command succeeded, but stderr showed a likely sandbox-related access issue."
        ));
        assert!(output.contains("Sandbox denial:"));
        assert!(output.contains(&denied.display().to_string()));
        assert!(output.contains("Discover paths: nono learn -- <your command>"));
    }

    #[test]
    fn test_supervised_no_denials_no_extensions_surfaces_missing_path() {
        let caps = make_test_caps();
        let missing = PathBuf::from("/tmp/missing/file.txt");
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_error_observation(ErrorObservation {
                primary_verdict: Some(ErrorVerdict::MissingPath(missing.clone())),
                blocked_protected_file: None,
                path_hints: Vec::new(),
                missing_paths: vec![missing.clone()],
                non_sandbox_failure: None,
            });
        let output = formatter.format_footer(1);

        assert!(
            output.contains("The command failed, but this does not look like a sandbox denial.")
        );
        assert!(output.contains(&missing.display().to_string()));
        assert!(output.contains("To grant additional access, re-run with:"));
        assert!(output.contains("Query policy: nono why --path <path> --op <read|write|readwrite>"));
    }

    #[test]
    fn test_supervised_no_denials_no_extensions_surfaces_non_sandbox_failure() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_error_observation(ErrorObservation {
                primary_verdict: Some(ErrorVerdict::NonSandboxFailure(
                    "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                        .to_string(),
                )),
                blocked_protected_file: None,
                path_hints: Vec::new(),
                missing_paths: Vec::new(),
                non_sandbox_failure: Some(
                    "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                        .to_string(),
                ),
            });
        let output = formatter.format_footer(1);

        assert!(
            output.contains("The command failed, but this does not look like a sandbox denial.")
        );
        assert!(output.contains("Application error:"));
        assert!(output.contains("EEXIST: file already exists"));
        assert!(output.contains("To grant additional access, re-run with:"));
        assert!(output.contains("Discover paths: nono learn -- <your command>"));
    }

    #[test]
    fn test_supervised_no_denials_extensions_active() {
        let mut caps = make_test_caps();
        caps.set_extensions_enabled(true);
        let formatter = DiagnosticFormatter::new(&caps).with_mode(DiagnosticMode::Supervised);
        let output = formatter.format_footer(1);

        assert!(output.contains("No path denials were observed during this session."));
        assert!(output.contains("may be unrelated"));
        assert!(output.contains("--allow <path>"));
    }

    #[test]
    fn test_supervised_uses_sandbox_violations_when_available() {
        let caps = make_test_caps();
        let violations = vec![
            SandboxViolation {
                operation: "file-read-data".to_string(),
                target: Some("/Users/alice/.ssh/id_rsa".to_string()),
            },
            SandboxViolation {
                operation: "mach-lookup".to_string(),
                target: Some("com.apple.logd".to_string()),
            },
        ];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_sandbox_violations(&violations);
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox denial:"));
        assert!(output.contains("/Users/alice/.ssh/id_rsa (read)"));
        assert!(output.contains("Also blocked (system services):"));
        assert!(output.contains("mach-lookup (com.apple.logd)"));
        assert!(output.contains("System logging"));
    }

    #[test]
    fn test_supervised_policy_blocked_denial() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox denial: 1 path blocked."));
        assert!(output.contains("/etc/shadow (read)  [permanently restricted]"));
        assert!(output.contains("permanently restricted — override via a user profile"));
        // Policy-blocked paths cannot be fixed with a path flag.
        assert!(!output.contains("Fix: --read /etc/shadow"));
        assert!(!output.contains("--allow <path>"));
    }

    #[test]
    fn test_supervised_user_denied() {
        let caps = make_test_caps();
        let dir = tempdir().expect("tempdir should be created");
        let denied_path = dir.path().join("secret.txt");
        std::fs::write(&denied_path, "secret").expect("denied file should be created");
        let denials = vec![DenialRecord {
            path: denied_path.clone(),
            access: AccessMode::Read,
            reason: DenialReason::UserDenied,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox denial: 1 path blocked."));
        assert!(output.contains(&denied_path.display().to_string()));
        assert!(output.contains(&format!("Fix: --read-file {}", denied_path.display())));
        // User-denied paths are actionable, not policy-blocked.
        assert!(!output.contains("[permanently restricted]"));
    }

    #[test]
    fn test_supervised_mixed_denials() {
        let caps = make_test_caps();
        let denials = vec![
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
            DenialRecord {
                path: PathBuf::from("/home/user/data.txt"),
                access: AccessMode::Read,
                reason: DenialReason::UserDenied,
            },
        ];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox denial: 2 paths blocked."));
        // Policy-blocked path gets the marker.
        assert!(output.contains("/etc/shadow (read)  [permanently restricted]"));
        // Actionable path is listed without the marker.
        assert!(output.contains("/home/user/data.txt (read)"));
        assert!(!output.contains("/home/user/data.txt (read)  [permanently restricted]"));
        // Consolidated Fix line covers only the actionable path. The suggested
        // target falls back to the nearest existing parent directory since the
        // path itself doesn't exist in the test environment.
        assert!(output.contains("Fix: --read "));
        assert!(!output.contains("Fix: --read /etc/shadow"));
        // The permanent-restriction note appears once for the policy-blocked path.
        assert!(output.contains("1 path is permanently restricted"));
    }

    #[test]
    fn test_supervised_deduplicates_paths() {
        let caps = make_test_caps();
        let denials = vec![
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
        ];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        let count = output.matches("/etc/shadow").count();
        assert_eq!(count, 1, "Path should be deduplicated");
        assert!(!output.contains("Denied paths during this session:"));
    }

    #[test]
    fn test_supervised_consolidated_fix_combines_all_actionable() {
        let caps = make_test_caps();
        let dir = tempdir().expect("tempdir should be created");
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, "a").expect("write a");
        std::fs::write(&b, "b").expect("write b");
        let denials = vec![
            DenialRecord {
                path: a.clone(),
                access: AccessMode::Read,
                reason: DenialReason::UserDenied,
            },
            DenialRecord {
                path: b.clone(),
                access: AccessMode::Write,
                reason: DenialReason::InsufficientAccess,
            },
        ];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        // Single Fix line covers both paths.
        let fix_lines: Vec<&str> = output
            .lines()
            .filter(|line| line.contains("Fix: "))
            .collect();
        assert_eq!(
            fix_lines.len(),
            1,
            "expected one consolidated Fix line: {output}"
        );
        assert!(fix_lines[0].contains(&format!("--read-file {}", a.display())));
        assert!(fix_lines[0].contains(&format!("--write-file {}", b.display())));
        assert!(!output.contains("[permanently restricted]"));
    }

    #[test]
    fn test_supervised_consolidated_list_truncates_beyond_cap() {
        // Zero-pad the index so paths sort in numeric order.
        let caps = make_test_caps();
        let denials: Vec<DenialRecord> = (0..15)
            .map(|i| DenialRecord {
                path: PathBuf::from(format!("/tmp/denied-{i:02}")),
                access: AccessMode::Read,
                reason: DenialReason::UserDenied,
            })
            .collect();
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox denial: 15 paths blocked."));
        // First 10 paths listed, remaining 5 collapsed.
        assert!(output.contains("/tmp/denied-00 "));
        assert!(output.contains("/tmp/denied-09 "));
        assert!(!output.contains("/tmp/denied-10 "));
        assert!(output.contains("… and 5 more"));
        // Fix line still covers all 15 paths.
        assert_eq!(
            output.lines().filter(|l| l.contains("Fix: ")).count(),
            1,
            "expected one consolidated Fix line"
        );
    }

    #[test]
    fn test_supervised_has_block_header() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(!output.starts_with("nono diagnostic"));
        assert!(!output.contains("[nono]"));
    }

    #[test]
    fn test_supervised_rate_limited_denial() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/tmp/flood"),
            access: AccessMode::Read,
            reason: DenialReason::RateLimited,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox denial: 1 path blocked."));
        assert!(output.contains("/tmp/flood (read)"));
        // Rate-limited denials are still actionable via a path flag. The
        // suggested target falls back to the nearest existing parent since
        // /tmp/flood itself doesn't exist.
        assert!(output.contains("Fix: --read "));
        assert!(!output.contains("[permanently restricted]"));
    }

    #[test]
    fn test_supervised_insufficient_access_shows_closest_grant_and_fix() {
        let dir = tempdir().expect("tempdir should be created");
        let denied_path = dir.path().join("output.txt");
        std::fs::write(&denied_path, "output").expect("output file should be created");
        let dir_path = dir
            .path()
            .canonicalize()
            .expect("tempdir should canonicalize");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: dir.path().to_path_buf(),
            resolved: dir_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("project_read".to_string()),
        });

        let denials = vec![DenialRecord {
            path: denied_path.clone(),
            access: AccessMode::Write,
            reason: DenialReason::InsufficientAccess,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        // The "Closest grant" hint moved out of the consolidated footer;
        // users can recover it with `nono why` if they want the detail.
        assert!(!output.contains("Closest grant:"));
        assert!(output.contains(&format!("Fix: --write-file {}", denied_path.display())));
        assert!(!output.contains("Denied paths during this session:"));
    }

    // --- Protected paths tests ---

    #[test]
    fn test_protected_paths_shown_in_footer() {
        let caps = make_test_caps();
        let protected = vec![
            PathBuf::from("/project/SKILLS.md"),
            PathBuf::from("/project/helper.py"),
        ];
        let formatter = DiagnosticFormatter::new(&caps).with_protected_paths(&protected);
        let output = formatter.format_footer(1);

        assert!(output.contains("Write-protected"));
        assert!(output.contains("SKILLS.md"));
        assert!(output.contains("helper.py"));
    }

    #[test]
    fn test_protected_paths_empty_no_section() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps).with_protected_paths(&[]);
        let output = formatter.format_footer(1);

        assert!(!output.contains("Write-protected"));
    }

    #[test]
    fn test_protected_paths_shown_in_supervised_macos_fallback() {
        let caps = make_test_caps(); // extensions_enabled defaults to false
        let protected = vec![PathBuf::from("/project/config.json")];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_protected_paths(&protected);
        let output = formatter.format_footer(1);

        assert!(!output.contains("Write-protected"));
    }

    // --- Exit code explanation tests ---

    fn make_command_context(program: &str, path: &str) -> CommandContext {
        CommandContext {
            program: program.to_string(),
            resolved_path: PathBuf::from(path),
            args: vec![program.to_string()],
        }
    }

    #[test]
    fn test_exit_127_binary_not_readable() {
        // Binary resolved to /opt/bin/foo but sandbox has no read access there
        let caps = make_test_caps(); // only /test/project
        let cmd = make_command_context("foo", "/opt/bin/foo");
        let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
        let output = formatter.format_footer(127);

        assert!(output.contains("Failed to execute command (exit code 127)"));
        assert!(output.contains("The executable 'foo' was resolved at:"));
        assert!(output.contains("/opt/bin/foo"));
        assert!(output.contains("not readable inside the sandbox"));
        assert!(output.contains("nono run --read /opt/bin"));
    }

    #[test]
    fn test_exit_127_binary_readable_but_exec_fails() {
        // Binary at /usr/bin/ps, sandbox has /usr/bin readable
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr/bin"),
            resolved: PathBuf::from("/usr/bin"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("system_read".to_string()),
        });
        let cmd = make_command_context("ps", "/usr/bin/ps");
        let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
        let output = formatter.format_footer(127);

        assert!(output.contains("'ps' resolved to /usr/bin/ps and is readable"));
        assert!(output.contains("execution still failed. Common causes:"));
        assert!(output.contains("shared library"));
        assert!(output.contains("Run with -v"));
    }

    #[test]
    fn test_exit_127_file_level_grant_dir_not_readable() {
        // Binary granted as a file-level read, but parent dir not readable
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/opt/custom/mybin"),
            resolved: PathBuf::from("/opt/custom/mybin"),
            access: AccessMode::Read,
            is_file: true,
            source: CapabilitySource::User,
        });
        let cmd = make_command_context("mybin", "/opt/custom/mybin");
        let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
        let output = formatter.format_footer(127);

        // is_binary_path_readable returns true (file-level match)
        // is_binary_dir_readable returns false (/opt/custom not granted)
        assert!(output.contains("'mybin' resolved to /opt/custom/mybin but the directory"));
        assert!(output.contains("read access to"));
    }

    #[test]
    fn test_exit_127_no_command_context() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(127);

        assert!(output.contains("Command not found (exit code 127)"));
        assert!(output.contains("could not be found or executed"));
    }

    #[test]
    fn test_exit_126_permission_denied() {
        let caps = make_test_caps();
        let cmd = make_command_context("script.sh", "/test/project/script.sh");
        let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
        let output = formatter.format_footer(126);

        assert!(output.contains("Permission denied (exit code 126)"));
        assert!(output.contains("'script.sh' was found at /test/project/script.sh"));
        assert!(output.contains("execute permission"));
    }

    #[test]
    fn test_exit_126_no_command_context() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(126);

        assert!(output.contains("Permission denied (exit code 126)"));
        assert!(output.contains("found but could not be executed"));
    }

    #[test]
    fn test_exit_1_generic() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Command exited with code 1."));
    }

    #[test]
    fn test_exit_sigkill() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(128 + 9);

        assert!(output.contains("SIGKILL"));
        assert!(output.contains("forcefully terminated"));
        assert!(output.contains("usually not"));
    }

    #[test]
    fn test_exit_sigsys_platform_correct() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(128 + libc::SIGSYS);

        assert!(output.contains("SIGSYS"));
        assert!(output.contains("blocked system call"));
    }

    #[test]
    fn test_exit_sigterm() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(128 + 15);

        assert!(output.contains("SIGTERM"));
        // SIGTERM gets the generic signal line, not a special explanation
        assert!(!output.contains("blocked system call"));
        assert!(!output.contains("forcefully terminated"));
    }

    #[test]
    fn test_exit_unknown_signal() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(128 + 33);

        assert!(output.contains("killed by signal 33"));
        assert!(!output.contains("SIGKILL"));
        assert!(!output.contains("SIGSYS"));
    }

    #[test]
    fn test_exit_other_code() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(42);

        assert!(output.contains("Command exited with code 42."));
    }
}
