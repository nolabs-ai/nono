use crate::capability_ext::{self, CapabilitySetExt};
use crate::cli::SandboxArgs;
use crate::command_blocking_deprecation;
#[cfg(unix)]
use crate::config;
use crate::credential_runtime::load_env_credentials;
use crate::network_policy;
use crate::output;
use crate::profile;
use crate::profile::WorkdirAccess;
use crate::profile_runtime::{prepare_profile, prepare_profile_for_preflight};
use crate::{DETACHED_CWD_PROMPT_RESPONSE_ENV, DETACHED_LAUNCH_ENV};
use crate::{policy, protected_paths, sandbox_state};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result, Sandbox};
#[cfg(target_os = "macos")]
use serde::Deserialize;
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use tracing::{info, warn};

fn print_allow_domain_port_warnings(entries: &[String], context: &str, silent: bool) {
    if silent {
        return;
    }

    for warning in network_policy::collect_allow_domain_port_warnings(entries, context) {
        output::print_warning(&warning);
    }
}

/// Returns `true` if `profile_name` is `"claude-code"` or transitively extends it.
fn is_claude_code_profile(profile_name: &str) -> bool {
    fn check(name: &str, visited: &mut Vec<String>) -> bool {
        if name == "claude-code" {
            return true;
        }
        if visited.iter().any(|v| v == name) {
            return false; // cycle — bail out
        }
        visited.push(name.to_string());
        let bases = match profile::load_profile_extends(name) {
            Some(bases) => bases,
            None => return false,
        };
        bases.iter().any(|base| check(base, visited))
    }
    check(profile_name, &mut Vec::new())
}

fn collect_missing_cli_requested_paths(args: &SandboxArgs) -> Vec<String> {
    let mut missing = Vec::new();

    for path in &args.allow {
        if !path.exists() {
            missing.push(format!("--allow {}", path.display()));
        }
    }
    for path in &args.read {
        if !path.exists() {
            missing.push(format!("--read {}", path.display()));
        }
    }
    for path in &args.write {
        if !path.exists() {
            missing.push(format!("--write {}", path.display()));
        }
    }
    for path in &args.allow_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--allow-file {}", path.display()));
        }
    }
    for path in &args.read_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--read-file {}", path.display()));
        }
    }
    for path in &args.write_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--write-file {}", path.display()));
        }
    }

    missing
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
struct ClaudeStoredAuth {
    #[serde(rename = "claudeAiOauth")]
    claude_ai_oauth: Option<ClaudeOauthState>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
struct ClaudeOauthState {
    #[serde(rename = "accessToken")]
    access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
struct ClaudeGlobalConfig {
    #[serde(rename = "primaryApiKey")]
    primary_api_key: Option<String>,
}

#[cfg(target_os = "macos")]
fn claude_oauth_suffix() -> &'static str {
    if std::env::var_os("CLAUDE_CODE_CUSTOM_OAUTH_URL").is_some() {
        return "-custom-oauth";
    }
    if std::env::var("USER_TYPE").ok().as_deref() == Some("ant") {
        if env_truthy("USE_LOCAL_OAUTH") {
            return "-local-oauth";
        }
        if env_truthy("USE_STAGING_OAUTH") {
            return "-staging-oauth";
        }
    }
    ""
}

#[cfg(target_os = "macos")]
fn env_truthy(key: &str) -> bool {
    std::env::var(key).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(target_os = "macos")]
fn env_non_empty(key: &str) -> bool {
    std::env::var_os(key).is_some_and(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
fn claude_config_dir() -> std::result::Result<(PathBuf, bool), String> {
    if let Some(config_dir) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Ok((PathBuf::from(config_dir), true));
    }
    let home = config::validated_home().map_err(|err| err.to_string())?;
    Ok((PathBuf::from(home).join(".claude"), false))
}

#[cfg(target_os = "macos")]
fn claude_global_config_path(
    config_dir: &Path,
    config_dir_explicit: bool,
) -> std::result::Result<PathBuf, String> {
    let legacy = config_dir.join(".config.json");
    if legacy.is_file() {
        return Ok(legacy);
    }
    let suffix = claude_oauth_suffix();
    if config_dir_explicit {
        return Ok(config_dir.join(format!(".claude{suffix}.json")));
    }
    let home = config::validated_home().map_err(|err| err.to_string())?;
    Ok(PathBuf::from(home).join(format!(".claude{suffix}.json")))
}

#[cfg(target_os = "macos")]
fn claude_keychain_service_name(
    config_dir: &Path,
    config_dir_explicit: bool,
    service_suffix: &str,
) -> String {
    let dir_hash = if config_dir_explicit {
        let digest = Sha256::digest(config_dir.to_string_lossy().as_bytes());
        let prefix = digest[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("-{prefix}")
    } else {
        String::new()
    };
    format!(
        "Claude Code{}{}{}",
        claude_oauth_suffix(),
        service_suffix,
        dir_hash
    )
}

#[cfg(target_os = "macos")]
fn claude_keychain_account_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| "claude-code-user".to_string())
}

#[cfg(target_os = "macos")]
fn read_keychain_item(account: &str, service_name: &str) -> Option<String> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-a",
            account,
            "-w",
            "-s",
            service_name,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    Some(stdout.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(target_os = "macos")]
fn parse_claude_oauth_state_json(
    raw: &str,
    source_label: &str,
) -> std::result::Result<Option<ClaudeOauthState>, String> {
    serde_json::from_str::<ClaudeStoredAuth>(raw)
        .map(|parsed| parsed.claude_ai_oauth)
        .map_err(|err| format!("failed to parse {source_label}: {err}"))
}

#[cfg(target_os = "macos")]
fn load_claude_oauth_state_from_raw_sources(
    keychain_raw: Option<&str>,
    file_raw: Option<(&str, &str)>,
) -> std::result::Result<Option<ClaudeOauthState>, String> {
    if let Some(raw) = keychain_raw
        && let Some(oauth) = parse_claude_oauth_state_json(raw, "Claude OAuth keychain JSON")?
    {
        return Ok(Some(oauth));
    }

    if let Some((raw, source_label)) = file_raw {
        return parse_claude_oauth_state_json(raw, source_label);
    }

    Ok(None)
}

#[cfg(target_os = "macos")]
fn load_claude_oauth_state() -> std::result::Result<Option<ClaudeOauthState>, String> {
    let (config_dir, config_dir_explicit) = claude_config_dir()?;
    let account = claude_keychain_account_name();
    let oauth_service =
        claude_keychain_service_name(&config_dir, config_dir_explicit, "-credentials");

    let keychain_raw = read_keychain_item(&account, &oauth_service);
    let credentials_path = config_dir.join(".credentials.json");
    match std::fs::read_to_string(&credentials_path) {
        Ok(raw) => load_claude_oauth_state_from_raw_sources(
            keychain_raw.as_deref(),
            Some((&raw, &credentials_path.display().to_string())),
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            load_claude_oauth_state_from_raw_sources(keychain_raw.as_deref(), None)
        }
        Err(err) => Err(format!(
            "failed to read {}: {err}",
            credentials_path.display()
        )),
    }
}

#[cfg(target_os = "macos")]
fn claude_has_saved_api_key_auth() -> std::result::Result<bool, String> {
    let (config_dir, config_dir_explicit) = claude_config_dir()?;
    let account = claude_keychain_account_name();
    let api_key_service = claude_keychain_service_name(&config_dir, config_dir_explicit, "");

    if read_keychain_item(&account, &api_key_service).is_some_and(|value| !value.trim().is_empty())
    {
        return Ok(true);
    }

    let global_config = claude_global_config_path(&config_dir, config_dir_explicit)?;
    match std::fs::read_to_string(&global_config) {
        Ok(raw) => {
            let parsed = serde_json::from_str::<ClaudeGlobalConfig>(&raw)
                .map_err(|err| format!("failed to parse {}: {err}", global_config.display()))?;
            Ok(parsed
                .primary_api_key
                .is_some_and(|value| !value.trim().is_empty()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("failed to read {}: {err}", global_config.display())),
    }
}

#[cfg(target_os = "macos")]
fn command_is_claude(program: &std::ffi::OsStr) -> bool {
    std::path::Path::new(program)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        == Some("claude")
}

#[cfg(target_os = "macos")]
fn claude_session_has_non_browser_auth(cmd_args: &[std::ffi::OsString]) -> bool {
    env_non_empty("CLAUDE_CODE_OAUTH_TOKEN")
        || env_non_empty("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR")
        || env_non_empty("CLAUDE_CODE_OAUTH_REFRESH_TOKEN")
        || env_non_empty("ANTHROPIC_API_KEY")
        || env_non_empty("ANTHROPIC_AUTH_TOKEN")
        || env_non_empty("CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR")
        || env_non_empty("ANTHROPIC_UNIX_SOCKET")
        || env_truthy("CLAUDE_CODE_USE_BEDROCK")
        || env_truthy("CLAUDE_CODE_USE_VERTEX")
        || env_truthy("CLAUDE_CODE_USE_FOUNDRY")
        || env_truthy("CLAUDE_CODE_SIMPLE")
        || args_request_bare_mode(cmd_args)
}

#[cfg(target_os = "macos")]
fn args_request_bare_mode(cmd_args: &[std::ffi::OsString]) -> bool {
    cmd_args.iter().any(|arg| arg == "--bare")
}

#[cfg(target_os = "macos")]
pub(crate) fn should_auto_enable_claude_launch_services(
    args: &SandboxArgs,
    program: &std::ffi::OsStr,
    cmd_args: &[std::ffi::OsString],
) -> bool {
    if args.allow_launch_services
        || !args.profile.as_deref().is_some_and(is_claude_code_profile)
        || !command_is_claude(program)
        || claude_session_has_non_browser_auth(cmd_args)
    {
        return false;
    }

    match claude_has_saved_api_key_auth() {
        Ok(true) => return false,
        Ok(false) => {}
        Err(err) => {
            warn!(
                "Skipping Claude LaunchServices preflight auto-enable because API-key auth detection failed: {}",
                err
            );
            return false;
        }
    }

    match load_claude_oauth_state() {
        Ok(Some(oauth)) => {
            let has_access = oauth
                .access_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
            let has_refresh = oauth
                .refresh_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
            !has_access || !has_refresh
        }
        Ok(None) => true,
        Err(err) => {
            warn!(
                "Skipping Claude LaunchServices preflight auto-enable because OAuth state detection failed: {}",
                err
            );
            false
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn should_auto_enable_claude_launch_services(
    _args: &SandboxArgs,
    _program: &std::ffi::OsStr,
    _cmd_args: &[std::ffi::OsString],
) -> bool {
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetachedCwdPromptResponse {
    Allow,
    Deny,
}

impl DetachedCwdPromptResponse {
    pub(crate) const fn as_env_value(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    fn from_env_value(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingCwdAccessRequest {
    cwd_canonical: PathBuf,
    access: AccessMode,
}

/// Result of sandbox preparation.
pub(crate) struct PreparedSandbox {
    pub(crate) caps: CapabilitySet,
    /// Resolved filesystem deny paths (groups + profile `filesystem.deny`).
    /// Threaded to the tool-sandbox so a mediated command's live cwd can be
    /// rejected when it falls under a directory the agent is denied.
    pub(crate) deny_paths: Vec<PathBuf>,
    pub(crate) secrets: Vec<nono::LoadedSecret>,
    pub(crate) profile_display_name: Option<String>,
    pub(crate) command_policies: Option<crate::command_policy::CommandPoliciesConfig>,
    /// Command binaries already resolved while validating `command_policies`.
    /// Reused by the tool-sandbox plan build so every controlled binary is
    /// only read and hashed once per invocation, not twice.
    pub(crate) resolved_command_binaries: Option<crate::command_policy::ResolvedCommandBinaries>,
    pub(crate) session_hooks: profile::SessionHooks,
    pub(crate) rollback_exclude_patterns: Vec<String>,
    pub(crate) rollback_exclude_globs: Vec<String>,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<profile::AllowDomainEntry>,
    pub(crate) deny_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    pub(crate) credential_capture: HashMap<String, profile::CredentialCaptureEntry>,
    pub(crate) credential_providers: HashMap<String, profile::CredentialProviderDef>,
    pub(crate) credential_routes: Vec<profile::CredentialRouteDef>,
    pub(crate) tls_intercept: Option<profile::TlsInterceptConfig>,
    pub(crate) no_proxy: Vec<String>,
    pub(crate) upstream_proxy: Option<String>,
    pub(crate) upstream_bypass: Vec<String>,
    pub(crate) listen_ports: Vec<u16>,
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    #[cfg(target_os = "linux")]
    pub(crate) af_unix_mediation: crate::profile::LinuxAfUnixMediation,
    #[cfg(target_os = "linux")]
    pub(crate) sandbox_policy: crate::profile::LinuxSandboxPolicy,
    #[cfg(target_os = "linux")]
    pub(crate) explicit_sandbox_policy: Option<crate::profile::LinuxSandboxPolicy>,
    pub(crate) allow_launch_services_active: bool,
    pub(crate) allow_gpu_active: bool,
    /// True when NVIDIA GPU support needs supervisor-mediated writes to
    /// `/proc/<tgid>/task/<tid>/comm` for driver thread naming.
    #[cfg(target_os = "linux")]
    pub(crate) proc_comm_notify: bool,
    pub(crate) open_url_origins: Vec<String>,
    pub(crate) open_url_allow_localhost: bool,
    pub(crate) bypass_protection_paths: Vec<PathBuf>,
    pub(crate) ignored_denial_paths: Vec<PathBuf>,
    pub(crate) suppressed_system_service_operations: Vec<String>,
    pub(crate) allowed_env_vars: Option<Vec<String>>,
    pub(crate) denied_env_vars: Option<Vec<String>>,
    /// Expanded `environment.set_vars` (key, expanded-value), `None` if absent.
    pub(crate) set_vars: Option<Vec<(String, String)>>,
    /// True when the profile's `network.block` is set. The CLI `--block-net`
    /// flag is read directly from `SandboxArgs` at proxy-launch time, so only
    /// the profile's contribution needs to be carried through.
    pub(crate) profile_network_block: bool,
    /// True when the profile or CLI requested HTTP/2 to upstream servers
    /// (`network.allow_http2` or `--allow-http2`).
    pub(crate) allow_http2_requested: bool,
}

fn resolved_workdir(args: &SandboxArgs) -> PathBuf {
    if let Some(ref workdir) = args.workdir {
        let path = workdir.clone();
        // Ensure the CLI-supplied path is absolute (preserving symlinks) so
        // macOS Seatbelt always receives a literal absolute path.
        if path.is_relative() {
            return std::env::current_dir()
                .map(|cwd| cwd.join(&path))
                .unwrap_or(path);
        }
        return path;
    }

    // No --workdir supplied: prefer $PWD over getcwd().
    //
    // The shell sets $PWD to the path the user typed (preserving symlinks),
    // while getcwd() / current_dir() always returns the canonical real path.
    // When the user `cd`s into a symlinked directory, $PWD holds the symlink
    // path and current_dir() holds the resolved target — we want the symlink
    // path so that Seatbelt literal-path rules cover it.
    //
    // Safety: validate that $PWD canonicalises to the same path as getcwd()
    // before trusting it, so a stale or spoofed $PWD is ignored.
    let canonical_cwd = std::env::current_dir().ok();

    if let Some(pwd) = std::env::var_os("PWD").map(PathBuf::from)
        && pwd.is_absolute()
        && let Ok(pwd_canonical) = pwd.canonicalize()
        && canonical_cwd
            .as_ref()
            .is_some_and(|cwd| cwd == &pwd_canonical)
    {
        return pwd;
    }

    canonical_cwd.unwrap_or_else(|| PathBuf::from("."))
}

fn cwd_access_requirement(profile_workdir_access: Option<&WorkdirAccess>) -> Option<AccessMode> {
    if let Some(access) = profile_workdir_access {
        match access {
            WorkdirAccess::Read => Some(AccessMode::Read),
            WorkdirAccess::Write => Some(AccessMode::Write),
            WorkdirAccess::ReadWrite => Some(AccessMode::ReadWrite),
            WorkdirAccess::None => None,
        }
    } else {
        Some(AccessMode::Read)
    }
}

fn pending_cwd_access_request(
    caps: &CapabilitySet,
    workdir: &Path,
    profile_workdir_access: Option<&WorkdirAccess>,
) -> Result<Option<PendingCwdAccessRequest>> {
    let Some(access) = cwd_access_requirement(profile_workdir_access) else {
        return Ok(None);
    };

    let cwd_canonical = workdir
        .canonicalize()
        .map_err(|e| NonoError::PathCanonicalization {
            path: workdir.to_path_buf(),
            source: e,
        })?;

    if caps.path_covered_with_access(&cwd_canonical, access) {
        Ok(None)
    } else {
        Ok(Some(PendingCwdAccessRequest {
            cwd_canonical,
            access,
        }))
    }
}

fn detached_cwd_prompt_response() -> Option<DetachedCwdPromptResponse> {
    std::env::var(DETACHED_CWD_PROMPT_RESPONSE_ENV)
        .ok()
        .as_deref()
        .and_then(DetachedCwdPromptResponse::from_env_value)
}

pub(crate) fn resolve_detached_cwd_prompt_response(
    args: &SandboxArgs,
    silent: bool,
) -> Result<Option<DetachedCwdPromptResponse>> {
    if silent || args.allow_cwd || args.config.is_some() {
        return Ok(None);
    }

    let workdir = resolved_workdir(args);
    let crate::profile_runtime::PreparedProfile {
        loaded_profile,
        workdir_access: profile_workdir_access,
        ..
    } = prepare_profile_for_preflight(args, &workdir)?;

    let prepared = if let Some(ref profile) = loaded_profile {
        CapabilitySet::from_profile(profile, &workdir, args)?
    } else {
        CapabilitySet::from_args(args)?
    };
    let caps = prepared.caps;

    let Some(request) =
        pending_cwd_access_request(&caps, &workdir, profile_workdir_access.as_ref())?
    else {
        return Ok(None);
    };

    let confirmed = output::prompt_cwd_sharing(&request.cwd_canonical, &request.access)?;
    Ok(Some(if confirmed {
        DetachedCwdPromptResponse::Allow
    } else {
        DetachedCwdPromptResponse::Deny
    }))
}

fn finalize_prepared_sandbox(
    mut prepared: PreparedSandbox,
    blocked_grants: &[(PathBuf, Option<String>)],
    args: &SandboxArgs,
    silent: bool,
) -> Result<PreparedSandbox> {
    // Attach resource limits from CLI flags. The manifest path already set caps via
    // `CapabilitySet::try_from`, and flags conflict with `--config`, so this only
    // runs on the flag path. Enforcement is later, in the supervised runtime; here
    // we just attach the parsed limits to the capability set (also in --dry-run).
    // `--memory` and `--max-processes` layer over any limits a profile already set
    // (see merge_flag_resource_limits); None means no flag was given — leave them be.
    if let Some(limits) = merge_flag_resource_limits(
        prepared.caps.resource_limits(),
        args.memory.as_deref(),
        args.max_processes,
    )? {
        prepared.caps = prepared.caps.with_resource_limits(limits);
    }

    // SECURITY: the caps live in cgroup control files under /sys/fs/cgroup. Write
    // access to any part of that tree lets the child rewrite its own memory.max /
    // pids.max (or migrate to a cgroup it makes) and defeat the limit. Landlock is
    // allow-list and can't carve the cgroup tree out of a broad grant like `/sys`,
    // so refuse the run rather than enforce a limit the sandbox can lift.
    reject_cgroup_writable_grants_under_resource_limit(&prepared.caps)?;

    output::print_skipped_requested_paths(&collect_missing_cli_requested_paths(args), silent);
    let proxy_intent = has_proxy_intent(args, &prepared);
    let block_wins = args.block_net || (prepared.profile_network_block && !proxy_intent);
    let proxy_pending = !block_wins && !args.allow_net && proxy_intent;
    output::print_capabilities(
        &prepared.caps,
        blocked_grants,
        args.verbose,
        silent,
        proxy_pending,
    );

    if let Some(ref profile_name) = args.profile {
        crate::pack_update_hint::show_pack_update_hints(profile_name, silent);
    }

    #[cfg(target_os = "linux")]
    output::print_abi_info(silent);
    #[cfg(target_os = "linux")]
    output::print_landlock_scope_policy(&prepared.caps, args.verbose, silent);

    if !Sandbox::is_supported() {
        return Err(NonoError::SandboxInit(Sandbox::support_info().details));
    }

    info!("{}", Sandbox::support_info().details);

    Ok(prepared)
}

/// Smallest `--memory` ceiling the CLI accepts. A bare number is bytes, so
/// `--memory 512` means 512 B — which OOM-kills any real process the instant it
/// starts, almost always a unit slip for `512M`. Refuse anything below this floor
/// with a hint instead of silently enforcing an unusable cap. (Manifests carry an
/// already-resolved byte count guarded by the schema's `minimum: 1`.)
const MIN_MEMORY_LIMIT_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Parse the `--memory` flag and reject implausibly small ceilings (see
/// [`MIN_MEMORY_LIMIT_BYTES`]). Surfaces the parse error for malformed sizes.
fn parse_memory_limit_flag(s: &str) -> Result<u64> {
    let bytes = nono::resource::parse_size(s)?;
    if bytes < MIN_MEMORY_LIMIT_BYTES {
        let digits: String = s
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        let hint = if digits.is_empty() {
            "use a size unit like M or G (e.g. 512M, 2G)".to_string()
        } else {
            format!("a bare number is bytes — did you mean {digits}M? use a unit like M or G")
        };
        return Err(NonoError::ConfigParse(format!(
            "--memory {s} is {}, below the 1 MiB minimum; {hint}",
            nono::resource::format_bytes(bytes)
        )));
    }
    Ok(bytes)
}

/// Validate the `--max-processes` count. clap already rejects negatives and
/// non-integers (the flag is a `u64`); this rejects 0, which would forbid the
/// sandbox from creating *any* task at all — always a mistake, never "unlimited"
/// (omit the flag for no limit). Mirrors the schema's `minimum: 1`.
fn validate_max_processes_flag(n: u64) -> Result<u64> {
    if n == 0 {
        return Err(NonoError::ConfigParse(
            "--max-processes must be at least 1; 0 would forbid the sandbox from \
             creating any process or thread. Omit the flag for no limit."
                .to_string(),
        ));
    }
    Ok(n)
}

/// Merge the CLI resource flags over any limits already attached (e.g. from a
/// profile) into the `ResourceLimits` to enforce. `--memory` and `--max-processes`
/// combine, and each overrides only its own field — so passing one flag never drops
/// a limit the profile set for the other. Returns `None` when neither flag is given,
/// leaving any profile limits untouched (the caller then attaches nothing).
fn merge_flag_resource_limits(
    existing: Option<&nono::ResourceLimits>,
    memory: Option<&str>,
    max_processes: Option<u64>,
) -> Result<Option<nono::ResourceLimits>> {
    if memory.is_none() && max_processes.is_none() {
        return Ok(None);
    }
    let mut limits = existing.copied().unwrap_or_default();
    if let Some(s) = memory {
        limits.memory_bytes = Some(parse_memory_limit_flag(s)?);
    }
    if let Some(n) = max_processes {
        limits.max_processes = Some(validate_max_processes_flag(n)?);
    }
    Ok(Some(limits))
}

/// True when a filesystem grant gives the sandbox WRITE access over any part of
/// the cgroup v2 hierarchy (`/sys/fs/cgroup`) that enforces resource limits.
/// Dangerous either way the paths nest: the grant is inside the tree, or a broad
/// ancestor (`/sys`, `/`) containing it. Read-only is safe — defeating a limit
/// needs writing the knobs or `cgroup.procs`. Component-based `Path::starts_with`,
/// not a string prefix, so `/sys/fs/cgroupX` doesn't match `/sys/fs/cgroup`.
fn grant_opens_cgroup_control_plane(resolved: &Path, access: AccessMode) -> bool {
    if !matches!(access, AccessMode::Write | AccessMode::ReadWrite) {
        return false;
    }
    let cgroup_mount = Path::new("/sys/fs/cgroup");
    resolved.starts_with(cgroup_mount) || cgroup_mount.starts_with(resolved)
}

/// Refuse a run whose resource limit (`--memory` / `--max-processes`) could be
/// defeated because the sandbox is also granted write access over the cgroup
/// hierarchy enforcing it (the child could raise its own `memory.max` / `pids.max`
/// or migrate out of the leaf). Only fires when a limit is set.
fn reject_cgroup_writable_grants_under_resource_limit(caps: &CapabilitySet) -> Result<()> {
    if caps
        .resource_limits()
        .is_none_or(|limits| limits.is_empty())
    {
        return Ok(());
    }
    for cap in caps.fs_capabilities() {
        if grant_opens_cgroup_control_plane(&cap.resolved, cap.access) {
            return Err(NonoError::ConfigParse(format!(
                "refusing write access to '{}' while a resource limit (--memory / \
                 --max-processes) is enforced: it overlaps the cgroup hierarchy \
                 (/sys/fs/cgroup) that enforces the limit, so the sandbox could rewrite \
                 its own cap and escape it. Make the grant read-only, scope it more \
                 narrowly, or drop the limit.",
                cap.resolved.display()
            )));
        }
    }
    Ok(())
}

/// Returns true if any CLI flag or profile field requires the proxy to run.
fn has_proxy_intent(args: &SandboxArgs, prepared: &PreparedSandbox) -> bool {
    args.has_proxy_flags()
        || !prepared.credentials.is_empty()
        || !prepared.custom_credentials.is_empty()
        || prepared.network_profile.is_some()
        || !prepared.allow_domain.is_empty()
        || prepared.upstream_proxy.is_some()
}

pub(crate) fn validate_external_proxy_bypass(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> Result<()> {
    let has_bypass = !args.external_proxy_bypass.is_empty() || !prepared.upstream_bypass.is_empty();
    let has_external_proxy = args.external_proxy.is_some() || prepared.upstream_proxy.is_some();

    if has_bypass && !has_external_proxy {
        return Err(NonoError::ConfigParse(
            "--upstream-bypass requires --upstream-proxy \
             (or upstream_proxy in profile network config)"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validate that `--block-net` is not combined with flags that imply proxy
/// mode, and that `--allow-endpoint` always has a matching credential.
///
/// These combinations are logically contradictory: `--block-net` prevents all
/// outbound traffic, so proxy-mode flags would be silently ignored.
pub(crate) fn validate_block_net_conflicts(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> Result<()> {
    let block_net = args.block_net || prepared.profile_network_block;

    if block_net {
        // Credential injection requires the proxy to be reachable.
        let has_credentials = !args.proxy_credential.is_empty() || !prepared.credentials.is_empty();
        if has_credentials {
            return Err(NonoError::ConfigParse(
                "--block-net and --credential are contradictory: \
                 credential injection requires the proxy to be reachable"
                    .to_string(),
            ));
        }

        // A network profile configures proxy-mode filtering.
        let has_network_profile =
            args.network_profile.is_some() || prepared.network_profile.is_some();
        if has_network_profile {
            return Err(NonoError::ConfigParse(
                "--block-net and --network-profile are contradictory: \
                 a network profile requires proxy mode"
                    .to_string(),
            ));
        }

        // --allow-domain implies proxy-filtered mode.
        let has_allow_domain = !args.allow_proxy.is_empty() || !prepared.allow_domain.is_empty();
        if has_allow_domain {
            return Err(NonoError::ConfigParse(
                "--block-net and --allow-domain are contradictory: \
                 domain filtering requires proxy mode"
                    .to_string(),
            ));
        }
    }

    // --allow-endpoint without any credential is a no-op (and almost certainly
    // a user error: the service name doesn't match any loaded credential).
    if !args.allow_endpoint.is_empty() {
        let has_credentials = !args.proxy_credential.is_empty()
            || !prepared.credentials.is_empty()
            || !prepared.custom_credentials.is_empty();
        if !has_credentials {
            return Err(NonoError::ConfigParse(
                "--allow-endpoint requires at least one --credential \
                 (no credential loaded for the named service)"
                    .to_string(),
            ));
        }
    }

    // --proxy-port without any proxy-triggering flag is almost certainly a
    // mistake: the port would be set but the proxy would never start.
    if args.proxy_port.is_some() && !has_proxy_intent(args, prepared) {
        return Err(NonoError::ConfigParse(
            "--proxy-port has no effect without a proxy-mode flag \
             (e.g. --credential, --network-profile, --allow-domain)"
                .to_string(),
        ));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn maybe_enable_macos_launch_services(
    caps: &mut CapabilitySet,
    cli_requested: bool,
    profile_allowed: bool,
    open_url_origins: &[String],
    open_url_allow_localhost: bool,
) -> Result<bool> {
    if !cli_requested {
        return Ok(false);
    }

    if !profile_allowed {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services requires a profile that opts into allow_launch_services"
                .to_string(),
        ));
    }

    if open_url_origins.is_empty() && !open_url_allow_localhost {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services requires the selected profile to configure open_urls"
                .to_string(),
        ));
    }

    caps.add_platform_rule("(allow lsopen)")?;
    tracing::debug!(
        "--allow-launch-services enabled: allowing direct LaunchServices opens on macOS"
    );
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn maybe_enable_macos_launch_services(
    _caps: &mut CapabilitySet,
    cli_requested: bool,
    _profile_allowed: bool,
    _open_url_origins: &[String],
    _open_url_allow_localhost: bool,
) -> Result<bool> {
    if cli_requested {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services is only supported on macOS".to_string(),
        ));
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
pub(crate) fn maybe_enable_macos_gpu(
    caps: &mut CapabilitySet,
    cli_requested: bool,
    profile_allowed: bool,
) -> Result<bool> {
    if !cli_requested {
        return Ok(false);
    }

    if !profile_allowed {
        return Err(NonoError::ConfigParse(
            "--allow-gpu requires the selected profile to opt into allow_gpu".to_string(),
        ));
    }

    // Minimal IOKit surface for Metal compute on Apple Silicon.
    // `AGXDeviceUserClient` is the only class required. Verified with
    // Metal compute, offscreen rendering, llama.cpp inference, and GUI
    // apps. `IOSurfaceRootUserClient` is tried opportunistically by
    // Metal but continues without it when denied. Intel Macs use
    // `IGAccelDevice` and `IGAccelSharedUserClient` (via `IntelAccelerator`)
    // for integrated GPUs, and `AMDRadeonX*` classes for discrete GPUs,
    // both of which are not yet supported.
    caps.add_platform_rule(
        "(allow iokit-open \
            (iokit-user-client-class \
                \"AGXDeviceUserClient\"))",
    )?;
    warn!("--allow-gpu enabled: allowing access to GPU");
    Ok(true)
}

#[cfg(all(not(target_os = "macos"), test))]
pub(crate) fn maybe_enable_macos_gpu(
    _caps: &mut CapabilitySet,
    cli_requested: bool,
    _profile_allowed: bool,
) -> Result<bool> {
    if cli_requested {
        return Err(NonoError::ConfigParse(
            "--allow-gpu is only supported on macOS".to_string(),
        ));
    }
    Ok(false)
}

pub(crate) fn print_allow_launch_services_warning(silent: bool) {
    if silent {
        return;
    }

    eprintln!(
        "  {}",
        "WARNING: --allow-launch-services permits the sandboxed process to ask macOS \
         LaunchServices to open URLs, files, or apps."
            .yellow()
    );
    eprintln!("  Use this only for temporary login/setup flows, then exit and rerun without it.");
    eprintln!("  Prefer using it from a trusted directory, not inside an untrusted project.");
}

fn missing_cwd_prompt_must_fail(
    silent: bool,
    detached_launch: bool,
    detached_prompt_response: Option<DetachedCwdPromptResponse>,
) -> bool {
    silent || (detached_launch && detached_prompt_response.is_none())
}

/// Grant the procfs paths that the NVIDIA driver needs for CUDA initialisation.
///
/// Scoped narrowly to the NVIDIA stack — not called on pure DRM render-node,
/// AMD ROCm, or WSL `/dev/dxg` setups.
///
/// - `/proc/driver/nvidia`, `/proc/driver/nvidia-uvm` (read, when present):
///   CUDA's UVM subsystem reads these during init. We grant each individually
///   rather than the parent `/proc/driver` to avoid exposing metadata about
///   unrelated kernel drivers.
/// - `/proc/self` (read): CUDA init reads `/proc/self/maps`, `/proc/self/status`
///   and other per-process files.
/// - `/proc/self/task` (read): NVIDIA driver 570+ enumerates task entries and
///   writes to `/proc/self/task/<tid>/comm` during thread startup to set thread
///   names. The write is handled by the seccomp-notify supervisor's
///   `proc_comm_notify` fast-path so the broader task subtree stays read-only.
#[cfg(target_os = "linux")]
fn grant_nvidia_gpu_procfs(caps: &mut CapabilitySet) -> Result<()> {
    for name in ["nvidia", "nvidia-uvm"] {
        let path = std::path::PathBuf::from("/proc/driver").join(name);
        if path.is_dir() {
            let cap = FsCapability::new_dir(&path, AccessMode::Read)?;
            caps.add_fs(cap);
        }
    }

    // /proc/self and /proc/self/task are guaranteed on Linux; propagate any
    // error rather than silently skipping (fail-secure: if the kernel ever
    // fails to present these, the sandbox should fail rather than grant
    // less-than-intended access).
    caps.add_fs(FsCapability::new_dir(
        std::path::Path::new("/proc/self"),
        AccessMode::Read,
    )?);
    // Read-only: NVIDIA driver 570+ comm writes are mediated by the
    // supervisor's proc_comm_notify path.
    caps.add_fs(FsCapability::new_dir(
        std::path::Path::new("/proc/self/task"),
        AccessMode::Read,
    )?);
    Ok(())
}

/// Returns true for `/dev/` filenames that correspond to NVIDIA compute device
/// nodes that should be granted by `--allow-gpu`.
///
/// Matches:
///   - `nvidiactl` — control device, required for all CUDA operations
///   - `nvidia-uvm` — Unified Virtual Memory, required for CUDA managed memory
///   - `nvidia-uvm-tools` — opened by driver 570+ during UVM init
///   - `nvidia<N>` where `N` is one or more ASCII digits — per-GPU device nodes
///
/// Deliberately rejects `nvidia-modeset` (display, not compute) and any other
/// non-enumerated `nvidia-*` suffix. Keep in sync with the comment block in
/// `maybe_enable_gpu`.
#[cfg(target_os = "linux")]
fn is_nvidia_compute_device(name: &str) -> bool {
    if name == "nvidiactl" || name == "nvidia-uvm" || name == "nvidia-uvm-tools" {
        return true;
    }
    if let Some(suffix) = name.strip_prefix("nvidia") {
        return !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

#[cfg(target_os = "linux")]
pub(crate) struct GpuActivation {
    pub(crate) active: bool,
    pub(crate) proc_comm_notify: bool,
}

#[cfg(target_os = "linux")]
pub(crate) fn maybe_enable_gpu(
    caps: &mut CapabilitySet,
    cli_requested: bool,
    profile_allowed: bool,
) -> Result<GpuActivation> {
    if !cli_requested {
        return Ok(GpuActivation {
            active: false,
            proc_comm_notify: false,
        });
    }

    if !profile_allowed {
        return Err(NonoError::ConfigParse(
            "--allow-gpu: the active profile does not permit GPU access (set allow_gpu: true)"
                .to_string(),
        ));
    }

    // Track how many GPU device nodes we grant so we can fail if none are found.
    let mut gpu_device_count: usize = 0;

    // DRM render nodes (compute-only, no modesetting).
    // Render nodes (/dev/dri/renderD*) are the safe minimum for GPU compute —
    // they don't grant display control, only shader dispatch and buffer management.
    // Optional: some headless CUDA/ROCm setups have no DRM render nodes.
    if let Ok(dri_entries) = std::fs::read_dir("/dev/dri") {
        let render_nodes: Vec<_> = dri_entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("renderD"))
            })
            .map(|e| e.path())
            .collect();

        for node in &render_nodes {
            let cap = FsCapability::new_file(node.clone(), AccessMode::ReadWrite)?;
            caps.add_fs(cap);
        }
        gpu_device_count = gpu_device_count.saturating_add(render_nodes.len());
    }

    // NVIDIA proprietary driver devices (if present).
    // We enumerate /dev/nvidia* to support multi-GPU systems (e.g. 8×A100).
    // Only compute-relevant devices are included:
    //   - nvidia[0-N]: per-GPU device nodes
    //   - nvidiactl: control device (required for all CUDA operations)
    //   - nvidia-uvm: Unified Virtual Memory (required for CUDA managed memory)
    // Deliberately excluded:
    //   - nvidia-modeset: display control, not compute (same rationale as /dev/dri/card*)
    //
    // Note: nvidia-uvm has been the target of privilege escalation CVEs
    // (e.g. CVE-2024-0090). We grant it because CUDA doesn't work without it,
    // but this is a higher-risk surface than DRM render nodes.
    let mut have_nvidia = false;
    if let Ok(dev_entries) = std::fs::read_dir("/dev") {
        let nvidia_devices: Vec<_> = dev_entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_str().is_some_and(is_nvidia_compute_device))
            .map(|e| e.path())
            .collect();
        gpu_device_count = gpu_device_count.saturating_add(nvidia_devices.len());
        if !nvidia_devices.is_empty() {
            have_nvidia = true;
        }
        for dev in &nvidia_devices {
            let cap = FsCapability::new_file(dev.clone(), AccessMode::ReadWrite)?;
            caps.add_fs(cap);
        }
    }

    // NVIDIA capability devices for MIG (Multi-Instance GPU) on A100/H100.
    // These are required when MIG mode is enabled. Enumerate individual devices
    // rather than granting the entire directory.
    if let Ok(cap_entries) = std::fs::read_dir("/dev/nvidia-caps") {
        let mut caps_found = 0;
        for entry in cap_entries.filter_map(|e| e.ok()) {
            let cap = FsCapability::new_file(entry.path(), AccessMode::ReadWrite)?;
            caps.add_fs(cap);
            caps_found += 1;
        }
        gpu_device_count = gpu_device_count.saturating_add(caps_found);
        // MIG-only hosts (no plain /dev/nvidia* node, caps only) still need
        // the NVIDIA procfs grants for CUDA init.
        if caps_found > 0 {
            have_nvidia = true;
        }
    }

    // AMD KFD (Kernel Fusion Driver) for ROCm/HIP compute.
    // /dev/kfd is a single shared device node used by all AMD GPUs on the system.
    // The per-GPU isolation is handled via DRM render nodes (already granted above).
    let kfd = std::path::Path::new("/dev/kfd");
    if kfd.exists() {
        let cap = FsCapability::new_file(kfd, AccessMode::ReadWrite)?;
        caps.add_fs(cap);
        gpu_device_count = gpu_device_count.saturating_add(1);
    }

    // WSL2 GPU passthrough via DirectX (/dev/dxg).
    // WSL2 exposes the host GPU through a paravirtualized DirectX device
    // rather than standard DRM render nodes or NVIDIA device files.
    // The CUDA/D3D12 libraries live in /usr/lib/wsl/lib/ (mounted by WSL2 init).
    let dxg = std::path::Path::new("/dev/dxg");
    if dxg.exists() {
        let cap = FsCapability::new_file(dxg, AccessMode::ReadWrite)?;
        caps.add_fs(cap);
        gpu_device_count = gpu_device_count.saturating_add(1);
    }
    let wsl_lib = std::path::Path::new("/usr/lib/wsl/lib");
    if wsl_lib.is_dir() {
        let cap = FsCapability::new_dir(wsl_lib, AccessMode::Read)?;
        caps.add_fs(cap);
    }

    if gpu_device_count == 0 {
        return Err(NonoError::SandboxInit(
            "--allow-gpu: no GPU devices found (checked /dev/dri/renderD*, \
             /dev/nvidia* (incl. nvidiactl, nvidia-uvm, nvidia-uvm-tools), \
             /dev/nvidia-caps/*, /dev/kfd, /dev/dxg)"
                .to_string(),
        ));
    }

    // Vulkan/Mesa ICD manifests (read-only, needed for Vulkan driver discovery)
    // and GPU-specific sysfs (read-only). We use /sys/class/drm rather than
    // /sys/devices to avoid exposing the full device tree (CPU, USB, PCI, ACPI).
    for dir in &["/usr/share/vulkan", "/etc/vulkan", "/sys/class/drm"] {
        let path = std::path::Path::new(dir);
        if path.is_dir() {
            let cap = FsCapability::new_dir(path, AccessMode::Read)?;
            caps.add_fs(cap);
        }
    }

    // NVIDIA-only procfs grants (see grant_nvidia_gpu_procfs for rationale).
    if have_nvidia {
        grant_nvidia_gpu_procfs(caps)?;
    }

    warn!(
        "--allow-gpu enabled: allowing {} GPU device(s) on Linux",
        gpu_device_count
    );
    Ok(GpuActivation {
        active: true,
        proc_comm_notify: have_nvidia,
    })
}

pub(crate) fn print_allow_gpu_warning(silent: bool) {
    if silent {
        return;
    }

    #[cfg(target_os = "macos")]
    {
        eprintln!(
            "  {}",
            "WARNING: --allow-gpu permits the sandboxed process to access Metal GPU \
             devices via IOKit (Apple Silicon only)."
                .yellow()
        );
        eprintln!("  This grants IOKit connections for GPU compute (IOGPU, AGX, IOSurface).");
    }

    #[cfg(target_os = "linux")]
    {
        eprintln!(
            "  {}",
            "WARNING: --allow-gpu permits the sandboxed process to access GPU render nodes."
                .yellow()
        );
        eprintln!(
            "  This grants read/write access to /dev/dri/renderD* and NVIDIA compute devices.\n  \
             On NVIDIA systems, additionally: read access to /proc/driver/nvidia,\n  \
             /proc/driver/nvidia-uvm, /proc/self, and /proc/self/task; writes to\n  \
             /proc/<pid>/task/<tid>/comm are mediated by the sandbox supervisor."
        );
    }
}

pub(crate) fn prepare_sandbox(args: &SandboxArgs, silent: bool) -> Result<PreparedSandbox> {
    sandbox_state::cleanup_stale_state_files();
    let detached_launch = std::env::var_os(DETACHED_LAUNCH_ENV).is_some();
    let detached_prompt_response = detached_cwd_prompt_response();
    let workdir = resolved_workdir(args);

    if let Some(ref config_path) = args.config {
        let json = std::fs::read_to_string(config_path).map_err(|e| {
            NonoError::ConfigParse(format!(
                "failed to read manifest file '{}': {e}",
                config_path.display()
            ))
        })?;
        let mut manifest = nono::manifest::CapabilityManifest::from_json(&json)?;
        manifest.validate()?;
        let manifest_warnings =
            command_blocking_deprecation::collect_manifest_warnings(&manifest, config_path);
        command_blocking_deprecation::print_warnings(&manifest_warnings, silent);

        if let Some(ref mut fs) = manifest.filesystem {
            for grant in &mut fs.grants {
                let expanded = profile::expand_vars(grant.path.as_str(), &workdir)?;
                grant.path = expanded
                    .to_string_lossy()
                    .parse()
                    .map_err(|e| NonoError::ConfigParse(format!("invalid path: {e}")))?;
            }
            for deny in &mut fs.deny {
                let expanded = profile::expand_vars(deny.path.as_str(), &workdir)?;
                deny.path = expanded
                    .to_string_lossy()
                    .parse()
                    .map_err(|e| NonoError::ConfigParse(format!("invalid path: {e}")))?;
            }
        }

        let mut caps = CapabilitySet::try_from(&manifest)?;
        let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
        protected_paths::validate_caps_against_protected_roots(
            &caps,
            protected_roots.as_paths(),
            false,
        )?;
        protected_paths::emit_protected_root_deny_rules(protected_roots.as_paths(), &mut caps)?;

        let (rollback_exclude_patterns, rollback_exclude_globs) =
            if let Some(ref rb) = manifest.rollback {
                (rb.exclude_patterns.clone(), rb.exclude_globs.clone())
            } else {
                (Vec::new(), Vec::new())
            };

        let manifest_allow_domain_strs: Vec<String> = manifest
            .network
            .as_ref()
            .map(|network| network.allow_domains.clone())
            .unwrap_or_default();
        print_allow_domain_port_warnings(
            &manifest_allow_domain_strs,
            "manifest allow_domain",
            silent,
        );
        let allow_domain: Vec<profile::AllowDomainEntry> = manifest_allow_domain_strs
            .into_iter()
            .map(profile::AllowDomainEntry::Plain)
            .collect();
        let credentials = manifest
            .credentials
            .iter()
            .map(|credential| credential.name.as_str().to_string())
            .collect();

        return finalize_prepared_sandbox(
            PreparedSandbox {
                caps,
                deny_paths: Vec::new(),
                secrets: Vec::new(),
                profile_display_name: None,
                command_policies: None,
                resolved_command_binaries: None,
                session_hooks: profile::SessionHooks::default(),
                rollback_exclude_patterns,
                rollback_exclude_globs,
                network_profile: None,
                allow_domain,
                deny_domain: Vec::new(),
                credentials,
                custom_credentials: HashMap::new(),
                credential_capture: HashMap::new(),
                credential_providers: HashMap::new(),
                credential_routes: Vec::new(),
                tls_intercept: None,
                no_proxy: Vec::new(),
                upstream_proxy: None,
                upstream_bypass: Vec::new(),
                listen_ports: Vec::new(),
                capability_elevation: false,
                #[cfg(target_os = "linux")]
                wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::default(),
                #[cfg(target_os = "linux")]
                af_unix_mediation: crate::profile::LinuxAfUnixMediation::default(),
                #[cfg(target_os = "linux")]
                sandbox_policy: crate::profile::LinuxSandboxPolicy::default(),
                #[cfg(target_os = "linux")]
                explicit_sandbox_policy: None,
                allow_launch_services_active: false,
                allow_gpu_active: false,
                #[cfg(target_os = "linux")]
                proc_comm_notify: false,
                open_url_origins: Vec::new(),
                open_url_allow_localhost: false,
                bypass_protection_paths: Vec::new(),
                ignored_denial_paths: Vec::new(),
                suppressed_system_service_operations: Vec::new(),
                allowed_env_vars: None,
                denied_env_vars: None,
                set_vars: None,
                profile_network_block: false,
                allow_http2_requested: args.allow_http2,
            },
            &[],
            args,
            silent,
        );
    }

    let prepared_profile = prepare_profile(args, silent, &workdir)?;
    let crate::profile_runtime::PreparedProfile {
        mut loaded_profile,
        mut command_policies,
        capability_elevation,
        #[cfg(target_os = "linux")]
        wsl2_proxy_policy,
        #[cfg(target_os = "linux")]
        af_unix_mediation,
        #[cfg(target_os = "linux")]
        sandbox_policy,
        #[cfg(target_os = "linux")]
        explicit_sandbox_policy,
        workdir_access: profile_workdir_access,
        rollback_exclude_patterns: profile_rollback_patterns,
        rollback_exclude_globs: profile_rollback_globs,
        network_profile: profile_network_profile,
        allow_domain: profile_allow_domain,
        deny_domain: profile_deny_domain,
        credentials: profile_credentials,
        custom_credentials: profile_custom_credentials,
        credential_providers: profile_credential_providers,
        credential_routes: profile_credential_routes,
        tls_intercept: profile_tls_intercept,
        no_proxy: profile_no_proxy,
        upstream_proxy: profile_upstream_proxy,
        upstream_bypass: profile_upstream_bypass,
        listen_ports: profile_listen_ports,
        open_url_origins,
        open_url_allow_localhost,
        allow_launch_services: profile_allow_launch_services,
        allow_gpu: profile_allow_gpu,
        allow_parent_of_protected: profile_allow_parent_of_protected,
        bypass_protection_paths,
        ignored_denial_paths,
        suppressed_system_service_operations,
        allowed_env_vars: profile_allowed_env_vars,
        denied_env_vars: profile_denied_env_vars,
        set_vars: profile_set_vars,
        resolved_command_binaries: profile_resolved_command_binaries,
    } = prepared_profile;

    // Raw Seatbelt rules (`unsafe_macos_seatbelt_rules`) are as powerful as
    // an arbitrary `binary` override, so honour them only for user-authored
    // profiles — same trust boundary as `resolve_profile_binary`. Strip them
    // (top-level and nested in command/from/intercept sandboxes) for
    // pack/registry/built-in profiles before they can reach emission.
    if let (Some(profile_name), Some(profile)) = (args.profile.as_deref(), loaded_profile.as_mut())
    {
        crate::command_runtime::strip_untrusted_unsafe_seatbelt_rules(
            profile_name,
            profile,
            command_policies.as_mut(),
            silent,
        );
    }

    let session_hooks = loaded_profile
        .as_ref()
        .map(|p| p.session_hooks.clone())
        .unwrap_or_default();

    if let Some(profile) = loaded_profile.as_ref() {
        let profile_warnings = command_blocking_deprecation::collect_profile_warnings(profile);
        command_blocking_deprecation::print_warnings(&profile_warnings, silent);
    }
    let profile_allow_domain_strs: Vec<String> = profile_allow_domain
        .iter()
        .map(|e| e.domain().to_string())
        .collect();
    print_allow_domain_port_warnings(&profile_allow_domain_strs, "profile allow_domain", silent);
    print_allow_domain_port_warnings(&args.allow_proxy, "--allow-domain", silent);
    print_allow_domain_port_warnings(&profile_deny_domain, "profile deny_domain", silent);
    print_allow_domain_port_warnings(&args.deny_proxy, "--deny-domain", silent);

    #[cfg(unix)]
    if args.profile.as_deref().is_some_and(is_claude_code_profile) {
        let home = config::validated_home()?;
        let home_path = std::path::Path::new(&home);

        let precreate = |path: &std::path::Path, is_dir: bool| {
            let result = if is_dir {
                std::fs::create_dir_all(path)
            } else {
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(path)
                    .map(|_| ())
            };
            if let Err(e) = result
                && e.kind() != std::io::ErrorKind::AlreadyExists
            {
                warn!("Failed to pre-create {}: {}", path.display(), e);
            }
        };

        precreate(&home_path.join(".claude.json.lock"), false);
        precreate(&home_path.join(".cache/claude-cli-nodejs"), true);

        // Claude Code writes ~/.claude.json atomically via temp files named
        // ~/.claude.json.tmp.<pid>.<timestamp>.  Landlock/Seatbelt cannot
        // grant permission for these dynamically-named files in ~/, so token
        // refreshes silently fail and the user is logged out.
        //
        // Fix: redirect ~/.claude.json to ~/.claude/claude.json via a
        // symlink.  Claude Code resolves symlinks before computing the temp
        // file path, so temp files land in ~/.claude/ (already readwrite)
        // instead of ~/ (not writable inside the sandbox).
        let claude_json = home_path.join(".claude.json");
        let claude_dir = home_path.join(".claude");
        let redirect_target = claude_dir.join("claude.json");

        if let Err(e) = std::fs::create_dir_all(&claude_dir) {
            warn!("Failed to create ~/.claude: {}", e);
        } else if !claude_json.is_symlink() {
            if claude_json.exists() {
                // Regular file present — move it into ~/.claude/ then symlink.
                if let Err(e) = std::fs::rename(&claude_json, &redirect_target) {
                    warn!(
                        "Failed to move ~/.claude.json to ~/.claude/claude.json: {}",
                        e
                    );
                } else if let Err(e) =
                    std::os::unix::fs::symlink(".claude/claude.json", &claude_json)
                {
                    warn!("Failed to create ~/.claude.json symlink: {}", e);
                }
            } else {
                // File doesn't exist yet — pre-create the target so the
                // sandbox can attach a path rule to it, then symlink.
                precreate(&redirect_target, false);
                if let Err(e) = std::os::unix::fs::symlink(".claude/claude.json", &claude_json)
                    && e.kind() != std::io::ErrorKind::AlreadyExists
                {
                    warn!("Failed to create ~/.claude.json symlink: {}", e);
                }
            }
        }
    }

    let prepared = if let Some(ref profile) = loaded_profile {
        CapabilitySet::from_profile(profile, &workdir, args)?
    } else {
        CapabilitySet::from_args(args)?
    };
    let mut caps = prepared.caps;
    let needs_unlink_overrides = prepared.needs_unlink_overrides;
    // Resolved policy denies (groups + profile add_deny_access). Used to
    // re-run validate_deny_overlaps after CWD/pack grants are added below,
    // because Landlock cannot enforce a deny that lives under a later allow.
    let prepared_deny_paths = prepared.deny_paths;
    // User grants silently blocked by deny groups (macOS); folded into the
    // capability summary instead of emitting one warning per path.
    let blocked_grants = prepared.blocked_grants;

    // Apply raw Seatbelt rules from the profile (macOS only).
    #[cfg(target_os = "macos")]
    if let Some(ref profile) = loaded_profile
        && !profile.unsafe_macos_seatbelt_rules.is_empty()
    {
        info!(
            "Profile uses {} raw Seatbelt rule(s) via unsafe_macos_seatbelt_rules — review carefully",
            profile.unsafe_macos_seatbelt_rules.len()
        );
        for rule in &profile.unsafe_macos_seatbelt_rules {
            caps.add_platform_rule(rule).map_err(|e| {
                NonoError::ConfigParse(format!(
                    "unsafe_macos_seatbelt_rules: invalid rule {rule:?}: {e}"
                ))
            })?;
        }
    }

    let allow_launch_services_active = maybe_enable_macos_launch_services(
        &mut caps,
        args.allow_launch_services,
        profile_allow_launch_services,
        &open_url_origins,
        open_url_allow_localhost,
    )?;

    // CLI --sandbox-policy overrides the profile value; both default to Auto.
    #[cfg(target_os = "linux")]
    let sandbox_policy = args.sandbox_policy.unwrap_or(sandbox_policy);
    #[cfg(target_os = "linux")]
    let explicit_sandbox_policy = args.sandbox_policy.or(explicit_sandbox_policy);

    // GPU access: macOS uses IOKit platform rules (tightened to AGXDeviceUserClient only),
    // Linux uses filesystem capabilities for render nodes and compute devices.
    #[cfg(target_os = "macos")]
    let allow_gpu_active = maybe_enable_macos_gpu(
        &mut caps,
        args.allow_gpu,
        loaded_profile.is_none() || profile_allow_gpu,
    )?;
    #[cfg(target_os = "linux")]
    let gpu_activation = maybe_enable_gpu(
        &mut caps,
        args.allow_gpu,
        loaded_profile.is_none() || profile_allow_gpu,
    )?;
    #[cfg(target_os = "linux")]
    let allow_gpu_active = gpu_activation.active;
    #[cfg(target_os = "linux")]
    let proc_comm_notify = gpu_activation.proc_comm_notify;

    if let Some(request) =
        pending_cwd_access_request(&caps, &workdir, profile_workdir_access.as_ref())?
    {
        if args.allow_cwd
            || matches!(
                detached_prompt_response,
                Some(DetachedCwdPromptResponse::Allow)
            )
        {
            let reason = if args.allow_cwd {
                "(--allow-cwd)"
            } else {
                "(detached launch preflight)"
            };
            info!(
                "Auto-including CWD with {} access {}",
                request.access, reason
            );
            let cap = FsCapability::new_dir(&workdir, request.access)?;
            caps.add_fs(cap);
        } else if matches!(
            detached_prompt_response,
            Some(DetachedCwdPromptResponse::Deny)
        ) {
            info!("Detached launch declined CWD sharing. Continuing without automatic CWD access.");
        } else if missing_cwd_prompt_must_fail(silent, detached_launch, detached_prompt_response) {
            return Err(NonoError::CwdPromptRequired);
        } else {
            let confirmed = output::prompt_cwd_sharing(&request.cwd_canonical, &request.access)?;
            if confirmed {
                let cap = FsCapability::new_dir(&workdir, request.access)?;
                caps.add_fs(cap);
            } else {
                info!("User declined CWD sharing. Continuing without automatic CWD access.");
            }
        }
        caps.deduplicate();
    }

    // Grant read access to pack directories declared by the profile
    if let Some(ref profile) = loaded_profile {
        for pack_ref in &profile.packs {
            let parts: Vec<&str> = pack_ref.splitn(2, '/').collect();
            if parts.len() == 2
                && let Ok(pack_dir) = crate::package::package_install_dir(parts[0], parts[1])
                && pack_dir.exists()
                && let Ok(canonical) = pack_dir.canonicalize()
                && !caps.path_covered_with_access(&canonical, nono::AccessMode::Read)
                && let Ok(cap) = FsCapability::new_dir(canonical, nono::AccessMode::Read)
            {
                caps.add_fs(cap);
            }
        }
        caps.deduplicate();
    }

    // On macOS, Seatbelt uses literal path matching rather than inode lookup,
    // so a symlinked CWD (e.g. ~/project -> /real/path/project) requires an
    // explicit rule for the symlink path even when the canonical target is
    // already covered by a profile grant (in which case pending_cwd_access_request
    // returns None and the block above is skipped entirely).
    // deduplicate() preserves symlink originals when merging, so adding this cap
    // on top of an existing profile cap is safe.
    #[cfg(target_os = "macos")]
    if let Ok(cwd_canonical) = workdir.canonicalize()
        && cwd_canonical != workdir
        && let Some(access) = cwd_access_requirement(profile_workdir_access.as_ref())
        && let Ok(cap) = FsCapability::new_dir(&workdir, access)
    {
        caps.add_fs(cap);
        caps.deduplicate();
    }

    // Re-validate against the full deny set (groups + profile add_deny_access)
    // now that CWD, pack dirs, and any GPU/launch-services grants have been
    // added on top of the caps produced by from_profile/from_args. The initial
    // validation inside finalize_caps did not see those later grants, so a
    // profile deny that lands under e.g. --allow-cwd would otherwise be a
    // silent no-op on Linux (Landlock cannot deny under an allow).
    policy::validate_deny_overlaps(&prepared_deny_paths, &caps)?;
    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
    let allow_parent_of_protected = profile_allow_parent_of_protected;
    protected_paths::validate_caps_against_protected_roots(
        &caps,
        protected_roots.as_paths(),
        allow_parent_of_protected,
    )?;
    protected_paths::emit_protected_root_deny_rules(protected_roots.as_paths(), &mut caps)?;

    if needs_unlink_overrides {
        policy::apply_unlink_overrides(&mut caps);
    }

    if !caps.has_fs() && caps.is_network_blocked() {
        return Err(NonoError::NoCapabilities);
    }

    // Capture the profile's `network.block` intent before `loaded_profile`
    // is consumed below.
    let profile_network_block = loaded_profile
        .as_ref()
        .map(|p| p.network.block)
        .unwrap_or(false);

    // Capture the profile's `network.allow_http2` intent alongside the CLI flag.
    let profile_allow_http2 = loaded_profile
        .as_ref()
        .map(|p| p.network.allow_http2)
        .unwrap_or(false);
    let allow_http2_requested = args.allow_http2 || profile_allow_http2;

    let profile_secrets = loaded_profile
        .as_ref()
        .map(|profile| profile.env_credentials.mappings.clone())
        .unwrap_or_default();
    let profile_display_name = loaded_profile
        .as_ref()
        .map(|profile| profile.meta.name.clone())
        .filter(|name| !name.is_empty());
    let profile_credential_capture = loaded_profile
        .as_ref()
        .map(|profile| profile.credential_capture.clone())
        .unwrap_or_default();
    let loaded_secrets = load_env_credentials(args, &profile_secrets, silent)?;

    finalize_prepared_sandbox(
        PreparedSandbox {
            caps,
            deny_paths: prepared_deny_paths,
            secrets: loaded_secrets,
            profile_display_name,
            command_policies,
            resolved_command_binaries: profile_resolved_command_binaries,
            session_hooks,
            rollback_exclude_patterns: profile_rollback_patterns,
            rollback_exclude_globs: profile_rollback_globs,
            network_profile: profile_network_profile,
            allow_domain: profile_allow_domain,
            deny_domain: profile_deny_domain,
            credentials: profile_credentials,
            custom_credentials: profile_custom_credentials,
            credential_capture: profile_credential_capture,
            credential_providers: profile_credential_providers,
            credential_routes: profile_credential_routes,
            tls_intercept: profile_tls_intercept,
            no_proxy: profile_no_proxy,
            upstream_proxy: profile_upstream_proxy,
            upstream_bypass: profile_upstream_bypass,
            listen_ports: profile_listen_ports,
            capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy,
            #[cfg(target_os = "linux")]
            af_unix_mediation,
            #[cfg(target_os = "linux")]
            sandbox_policy,
            #[cfg(target_os = "linux")]
            explicit_sandbox_policy,
            allow_launch_services_active,
            allow_gpu_active,
            #[cfg(target_os = "linux")]
            proc_comm_notify,
            open_url_origins,
            open_url_allow_localhost,
            bypass_protection_paths,
            ignored_denial_paths,
            suppressed_system_service_operations,
            allowed_env_vars: profile_allowed_env_vars,
            denied_env_vars: profile_denied_env_vars,
            set_vars: profile_set_vars,
            profile_network_block,
            allow_http2_requested,
        },
        &blocked_grants,
        args,
        silent,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use std::fs;
    use tempfile::tempdir;

    #[cfg(target_os = "linux")]
    #[test]
    fn nvidia_compute_device_predicate_accepts_known_names() {
        for name in [
            "nvidiactl",
            "nvidia-uvm",
            "nvidia-uvm-tools",
            "nvidia0",
            "nvidia7",
            "nvidia15",
        ] {
            assert!(
                is_nvidia_compute_device(name),
                "expected {name} to be granted"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn grant_nvidia_gpu_procfs_keeps_proc_self_task_read_only() {
        // Regression test for the NVIDIA-scoped procfs grants:
        //   /proc/self       Read        (CUDA init reads maps/status/etc.)
        //   /proc/self/task  Read        (driver comm writes go via proc_comm_notify)
        // Plus any of /proc/driver/{nvidia,nvidia-uvm} that exist.
        //
        // /proc/self and /proc/self/task always exist on Linux, so those
        // checks are unconditional. /proc/driver/nvidia entries are only
        // present when the NVIDIA kernel module is loaded, so we just
        // assert no unexpected /proc/driver parent grant was added.
        //
        // FsCapability.original is used instead of path_covered_with_access:
        // /proc/self is a symlink to /proc/<pid> which canonicalizes
        // per-process, and we want to verify the grant intent.
        let mut caps = CapabilitySet::default();
        grant_nvidia_gpu_procfs(&mut caps).expect("grant_nvidia_gpu_procfs failed");

        let find = |p: &str| -> Option<&nono::FsCapability> {
            caps.fs_capabilities()
                .iter()
                .find(|c| c.original == std::path::Path::new(p))
        };

        let proc_self = find("/proc/self")
            .expect("/proc/self must be granted read so CUDA init can read maps/status");
        assert_eq!(
            proc_self.access,
            AccessMode::Read,
            "/proc/self must be read-only"
        );
        assert!(!proc_self.is_file);

        let proc_self_task = find("/proc/self/task")
            .expect("/proc/self/task must be granted read so the NVIDIA driver can list tasks");
        assert_eq!(
            proc_self_task.access,
            AccessMode::Read,
            "/proc/self/task must stay read-only; comm writes are supervisor mediated"
        );
        assert!(!proc_self_task.is_file);

        // Least-privilege regression guard: no parent /proc/driver grant.
        // Only /proc/driver/nvidia and /proc/driver/nvidia-uvm should appear
        // (and only when their subdirectories exist).
        assert!(
            find("/proc/driver").is_none(),
            "/proc/driver must not be granted as a parent (would leak other drivers)"
        );
        for entry in caps.fs_capabilities() {
            if entry.original.starts_with("/proc/driver/") {
                let name = entry
                    .original
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                assert!(
                    matches!(name, "nvidia" | "nvidia-uvm"),
                    "unexpected /proc/driver grant: {}",
                    entry.original.display()
                );
                assert_eq!(entry.access, AccessMode::Read);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nvidia_compute_device_predicate_rejects_non_compute_and_unknown() {
        for name in [
            "nvidia",           // bare prefix, no digits
            "nvidia-modeset",   // display, not compute
            "nvidia-nvswitch0", // not yet supported
            "nvidia-uvm-other", // unknown -tools-style suffix
            "nvidiaX",          // non-digit suffix
            "nvidia0a",         // mixed suffix
            "not-nvidia",       // wrong prefix
            "",                 // empty
        ] {
            assert!(
                !is_nvidia_compute_device(name),
                "expected {name} to be rejected"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn missing_exact_file_cli_grants_are_not_reported_as_skipped() {
        let dir = tempdir().expect("tmpdir");
        let args = SandboxArgs {
            allow_file: vec![dir.path().join("future.lock")],
            ..SandboxArgs::default()
        };

        assert!(
            collect_missing_cli_requested_paths(&args).is_empty(),
            "macOS exact-file grants should not be reported as skipped when the file is absent"
        );
    }

    #[cfg(target_os = "macos")]
    fn claude_preflight_env(home: &Path, config_dir: &Path) -> crate::test_env::EnvVarGuard {
        let env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", home.to_str().unwrap_or("/tmp")),
            (
                "CLAUDE_CONFIG_DIR",
                config_dir.to_str().unwrap_or("/tmp/.claude"),
            ),
            ("USER", "nono-test-user"),
            ("ANTHROPIC_API_KEY", "placeholder"),
            ("ANTHROPIC_AUTH_TOKEN", "placeholder"),
            ("CLAUDE_CODE_OAUTH_TOKEN", "placeholder"),
            ("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "9"),
            ("CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR", "9"),
            ("CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "placeholder"),
            ("CLAUDE_CODE_CUSTOM_OAUTH_URL", "placeholder"),
            ("USER_TYPE", "placeholder"),
            ("USE_LOCAL_OAUTH", "0"),
            ("USE_STAGING_OAUTH", "0"),
            ("CLAUDE_CODE_USE_BEDROCK", "0"),
            ("CLAUDE_CODE_USE_VERTEX", "0"),
            ("CLAUDE_CODE_USE_FOUNDRY", "0"),
            ("ANTHROPIC_UNIX_SOCKET", "placeholder"),
            ("CLAUDE_CODE_SIMPLE", "0"),
        ]);
        for key in [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
            "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
            "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
            "CLAUDE_CODE_CUSTOM_OAUTH_URL",
            "USER_TYPE",
            "ANTHROPIC_UNIX_SOCKET",
            "CLAUDE_CODE_SIMPLE",
        ] {
            env.remove(key);
        }
        env
    }

    #[cfg(target_os = "macos")]
    fn claude_args() -> SandboxArgs {
        SandboxArgs {
            profile: Some("claude-code".to_string()),
            ..SandboxArgs::default()
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn claude_oauth_falls_back_to_file_when_keychain_only_has_mcp_oauth() {
        let oauth = load_claude_oauth_state_from_raw_sources(
            Some(r#"{"mcpOAuth":{"example":{"accessToken":"mcp-token"}}}"#),
            Some((
                r#"{"claudeAiOauth":{"accessToken":"access","refreshToken":"refresh"}}"#,
                "plaintext credentials",
            )),
        )
        .expect("oauth state should parse")
        .expect("plaintext oauth should win when keychain lacks claudeAiOauth");

        assert_eq!(oauth.access_token.as_deref(), Some("access"));
        assert_eq!(oauth.refresh_token.as_deref(), Some("refresh"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn claude_launch_services_auto_enable_when_auth_missing() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("tmpdir");
        let home = dir.path().join("home");
        let config_dir = dir.path().join("claude-config");
        fs::create_dir_all(&home).expect("mkdir home");
        let _env = claude_preflight_env(&home, &config_dir);
        let program = std::ffi::OsString::from("claude");
        let cmd_args = Vec::new();

        assert!(should_auto_enable_claude_launch_services(
            &claude_args(),
            &program,
            &cmd_args
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn claude_launch_services_stays_off_when_refreshable_oauth_exists() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("tmpdir");
        let home = dir.path().join("home");
        let config_dir = dir.path().join("claude-config");
        fs::create_dir_all(&config_dir).expect("mkdir config");
        let _env = claude_preflight_env(&home, &config_dir);
        fs::write(
            config_dir.join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"access","refreshToken":"refresh"}}"#,
        )
        .expect("write credentials");
        let program = std::ffi::OsString::from("claude");
        let cmd_args = Vec::new();

        assert!(!should_auto_enable_claude_launch_services(
            &claude_args(),
            &program,
            &cmd_args
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn claude_launch_services_auto_enable_when_refresh_token_missing() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("tmpdir");
        let home = dir.path().join("home");
        let config_dir = dir.path().join("claude-config");
        fs::create_dir_all(&config_dir).expect("mkdir config");
        let _env = claude_preflight_env(&home, &config_dir);
        fs::write(
            config_dir.join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"access"}}"#,
        )
        .expect("write credentials");
        let program = std::ffi::OsString::from("claude");
        let cmd_args = Vec::new();

        assert!(should_auto_enable_claude_launch_services(
            &claude_args(),
            &program,
            &cmd_args
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn claude_launch_services_stays_off_when_api_key_auth_exists() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("tmpdir");
        let home = dir.path().join("home");
        let config_dir = dir.path().join("claude-config");
        fs::create_dir_all(&config_dir).expect("mkdir config");
        let _env = claude_preflight_env(&home, &config_dir);
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"primaryApiKey":"sk-ant-api-key"}"#,
        )
        .expect("write global config");
        let program = std::ffi::OsString::from("claude");
        let cmd_args = Vec::new();

        assert!(!should_auto_enable_claude_launch_services(
            &claude_args(),
            &program,
            &cmd_args
        ));
    }

    #[test]
    fn missing_directory_cli_grants_are_reported_as_skipped() {
        let dir = tempdir().expect("tmpdir");
        let args = SandboxArgs {
            allow: vec![dir.path().join("future-dir")],
            ..SandboxArgs::default()
        };

        assert_eq!(
            collect_missing_cli_requested_paths(&args),
            vec![format!(
                "--allow {}",
                dir.path().join("future-dir").display()
            )]
        );
    }

    #[test]
    fn missing_cwd_prompt_fails_in_silent_mode() {
        assert!(missing_cwd_prompt_must_fail(true, false, None));
    }

    #[test]
    fn missing_cwd_prompt_fails_for_unresolved_detached_launches() {
        assert!(missing_cwd_prompt_must_fail(false, true, None));
    }

    #[test]
    fn missing_cwd_prompt_does_not_fail_after_detached_preflight_decision() {
        assert!(!missing_cwd_prompt_must_fail(
            false,
            true,
            Some(DetachedCwdPromptResponse::Deny)
        ));
        assert!(!missing_cwd_prompt_must_fail(
            false,
            true,
            Some(DetachedCwdPromptResponse::Allow)
        ));
    }

    #[test]
    fn missing_cwd_prompt_can_interactively_prompt_when_attached() {
        assert!(!missing_cwd_prompt_must_fail(false, false, None));
    }

    #[cfg(unix)]
    #[test]
    fn resolved_workdir_prefers_pwd_symlink_over_getcwd_when_valid() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("tmpdir");

        // Create a symlink that points to the real current working directory.
        // $PWD must canonicalise to the same path as getcwd() for the guard to
        // accept it — that is only true when the symlink target IS the cwd.
        let cwd = std::env::current_dir().expect("getcwd");
        let link_dir = dir.path().join("link");
        std::os::unix::fs::symlink(&cwd, &link_dir).expect("symlink");

        // Simulate a shell that set $PWD to the symlink path.
        let _env = crate::test_env::EnvVarGuard::set_all(&[(
            "PWD",
            link_dir.to_str().expect("valid utf-8"),
        )]);

        let args = SandboxArgs {
            workdir: None,
            ..SandboxArgs::default()
        };

        // resolved_workdir must return the symlink path, not the canonical one.
        let result = resolved_workdir(&args);
        assert_eq!(
            result, link_dir,
            "resolved_workdir should return $PWD (symlink path) when it is valid"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolved_workdir_ignores_stale_pwd() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("tmpdir");

        // $PWD points somewhere that does NOT resolve to current_dir().
        let stale = dir.path().join("stale");
        std::fs::create_dir_all(&stale).expect("mkdir stale");
        let _env =
            crate::test_env::EnvVarGuard::set_all(&[("PWD", stale.to_str().expect("valid utf-8"))]);

        let args = SandboxArgs {
            workdir: None,
            ..SandboxArgs::default()
        };

        let result = resolved_workdir(&args);
        // Must fall back to current_dir(), not the stale $PWD.
        assert_ne!(
            result, stale,
            "resolved_workdir must not trust a stale $PWD"
        );
    }

    #[test]
    fn pending_cwd_access_request_uses_default_read_access() {
        let dir = tempdir().expect("tmpdir");
        let caps = CapabilitySet::new();
        let request = pending_cwd_access_request(&caps, dir.path(), None)
            .expect("request should evaluate")
            .expect("request should be required");

        assert_eq!(
            request.cwd_canonical,
            dir.path().canonicalize().expect("canonical")
        );
        assert_eq!(request.access, AccessMode::Read);
    }

    #[test]
    fn pending_cwd_access_request_is_skipped_when_caps_cover_workdir() {
        let dir = tempdir().expect("tmpdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(
            FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).expect("dir capability"),
        );

        assert!(
            pending_cwd_access_request(&caps, dir.path(), None)
                .expect("request should evaluate")
                .is_none()
        );
    }

    #[test]
    fn detached_cwd_prompt_response_env_values_round_trip() {
        assert_eq!(
            DetachedCwdPromptResponse::from_env_value(
                DetachedCwdPromptResponse::Allow.as_env_value()
            ),
            Some(DetachedCwdPromptResponse::Allow)
        );
        assert_eq!(
            DetachedCwdPromptResponse::from_env_value(
                DetachedCwdPromptResponse::Deny.as_env_value()
            ),
            Some(DetachedCwdPromptResponse::Deny)
        );
    }

    #[test]
    fn cgroup_write_grant_detection_is_component_based() {
        let (w, rw, r) = (AccessMode::Write, AccessMode::ReadWrite, AccessMode::Read);

        // Inside or equal to the cgroup mount -> dangerous (writable).
        assert!(grant_opens_cgroup_control_plane(
            Path::new("/sys/fs/cgroup"),
            w
        ));
        assert!(grant_opens_cgroup_control_plane(
            Path::new("/sys/fs/cgroup/user.slice/user-1000.slice"),
            rw
        ));
        // A broad ancestor that subsumes the cgroup mount -> dangerous.
        assert!(grant_opens_cgroup_control_plane(Path::new("/sys"), w));
        assert!(grant_opens_cgroup_control_plane(Path::new("/sys/fs"), w));
        assert!(grant_opens_cgroup_control_plane(Path::new("/"), w));

        // Read-only is safe even over the cgroup tree (cannot write the knobs).
        assert!(!grant_opens_cgroup_control_plane(
            Path::new("/sys/fs/cgroup"),
            r
        ));
        assert!(!grant_opens_cgroup_control_plane(Path::new("/sys"), r));

        // Unrelated or sibling write grants are safe.
        assert!(!grant_opens_cgroup_control_plane(
            Path::new("/sys/devices"),
            w
        ));
        assert!(!grant_opens_cgroup_control_plane(Path::new("/tmp"), rw));

        // Component-based: a look-alike sibling must NOT match. A string
        // `starts_with` would wrongly flag this — the bug this guards against.
        assert!(!grant_opens_cgroup_control_plane(
            Path::new("/sys/fs/cgroupX"),
            w
        ));
    }

    #[test]
    fn cgroup_grant_guard_only_fires_with_a_resource_limit() {
        // No limit -> always Ok (guard short-circuits before inspecting grants).
        assert!(reject_cgroup_writable_grants_under_resource_limit(&CapabilitySet::new()).is_ok());
        // A memory limit set but no filesystem grants -> Ok.
        let caps = CapabilitySet::new().with_resource_limits(nono::ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
            max_processes: None,
        });
        assert!(reject_cgroup_writable_grants_under_resource_limit(&caps).is_ok());
        // A process-only limit also arms the guard (is_empty covers both fields),
        // but with no grants it still passes.
        let caps = CapabilitySet::new().with_resource_limits(nono::ResourceLimits {
            memory_bytes: None,
            max_processes: Some(64),
        });
        assert!(reject_cgroup_writable_grants_under_resource_limit(&caps).is_ok());
    }

    // The guard's whole point: with a limit active, a writable grant that overlaps
    // the cgroup tree is refused — otherwise the sandbox could rewrite its own
    // memory.max / pids.max and lift the cap. Linux-only because we need the real
    // cgroup mount to canonicalize a grant over it; skip gracefully if absent.
    // Uses a process-only limit to prove the guard is not memory-specific.
    #[test]
    #[cfg(target_os = "linux")]
    fn cgroup_write_grant_under_a_resource_limit_is_refused() {
        let Ok(grant) = FsCapability::new_dir("/sys/fs/cgroup", AccessMode::Write) else {
            return; // no cgroup mount on this host — nothing to exercise
        };
        let mut caps = CapabilitySet::new().with_resource_limits(nono::ResourceLimits {
            memory_bytes: None,
            max_processes: Some(64),
        });
        caps.add_fs(grant);

        let err = reject_cgroup_writable_grants_under_resource_limit(&caps)
            .expect_err("a writable /sys/fs/cgroup grant under a resource limit must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("/sys/fs/cgroup"),
            "error must name the overlapping path: {msg}"
        );
        assert!(
            msg.contains("--memory") || msg.contains("--max-processes"),
            "error should mention the limit: {msg}"
        );
    }

    #[test]
    fn memory_flag_rejects_below_one_mib_with_unit_hint() {
        // Bare bytes that are almost certainly a unit slip for 512M.
        let err = parse_memory_limit_flag("512").expect_err("512 B must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("1 MiB minimum"), "msg: {msg}");
        assert!(msg.contains("512M"), "should echo the unit form: {msg}");

        // Sub-MiB even with a unit is refused (512K = 512 KiB).
        assert!(parse_memory_limit_flag("512K").is_err());
        // The floor itself and anything above it are accepted.
        assert_eq!(
            parse_memory_limit_flag("1M").expect("1 MiB is at the floor"),
            1024 * 1024
        );
        assert_eq!(
            parse_memory_limit_flag("512M").expect("512M is well above the floor"),
            512 * 1024 * 1024
        );
        // Malformed sizes still surface the parser's error.
        assert!(parse_memory_limit_flag("abc").is_err());
        assert!(parse_memory_limit_flag("0").is_err());
    }

    #[test]
    fn max_processes_flag_rejects_zero_but_accepts_positive() {
        // 0 is refused with a message that says why and points at the fix.
        let err = validate_max_processes_flag(0).expect_err("0 must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("at least 1"), "msg: {msg}");
        assert!(msg.contains("Omit the flag"), "should hint the fix: {msg}");

        // Any positive count passes through unchanged (1, and a larger value).
        assert_eq!(validate_max_processes_flag(1).expect("1 is the floor"), 1);
        assert_eq!(
            validate_max_processes_flag(1024).expect("large counts are fine"),
            1024
        );
    }

    #[test]
    fn merge_flag_resource_limits_layers_flags_over_profile_without_clobbering() {
        use nono::ResourceLimits;

        // No flag: nothing to attach — even when a profile already set limits, they
        // are left untouched (the caller attaches nothing on None).
        assert_eq!(
            merge_flag_resource_limits(None, None, None).expect("ok"),
            None
        );
        let profile = ResourceLimits {
            memory_bytes: Some(1 << 20),
            max_processes: Some(8),
        };
        assert_eq!(
            merge_flag_resource_limits(Some(&profile), None, None).expect("ok"),
            None,
            "no flag must not disturb profile-provided limits"
        );

        // A lone flag with no existing limits sets only its own field.
        let mem = merge_flag_resource_limits(None, Some("512M"), None)
            .expect("ok")
            .expect("some");
        assert!(mem.memory_bytes.is_some());
        assert_eq!(mem.max_processes, None);
        assert_eq!(
            merge_flag_resource_limits(None, None, Some(64)).expect("ok"),
            Some(ResourceLimits {
                memory_bytes: None,
                max_processes: Some(64),
            })
        );

        // Don't-clobber: a profile MEMORY cap + a CLI --max-processes yields BOTH,
        // not just the flag's field.
        let profile_mem = ResourceLimits {
            memory_bytes: Some(256 * 1024 * 1024),
            max_processes: None,
        };
        let merged = merge_flag_resource_limits(Some(&profile_mem), None, Some(32))
            .expect("ok")
            .expect("some");
        assert_eq!(
            merged.memory_bytes,
            Some(256 * 1024 * 1024),
            "adding --max-processes must not drop the profile's memory cap"
        );
        assert_eq!(merged.max_processes, Some(32));

        // Symmetric: a profile PIDS cap + a CLI --memory keeps the pids cap.
        let profile_pids = ResourceLimits {
            memory_bytes: None,
            max_processes: Some(16),
        };
        let merged = merge_flag_resource_limits(Some(&profile_pids), Some("128M"), None)
            .expect("ok")
            .expect("some");
        assert_eq!(merged.max_processes, Some(16));
        assert!(merged.memory_bytes.is_some());

        // A flag overrides the same field the profile set.
        let overridden = merge_flag_resource_limits(Some(&profile), None, Some(2))
            .expect("ok")
            .expect("some");
        assert_eq!(
            overridden.max_processes,
            Some(2),
            "the flag overrides the profile's pids cap"
        );

        // Invalid flag values propagate as errors (0 processes; sub-MiB memory).
        assert!(merge_flag_resource_limits(None, None, Some(0)).is_err());
        assert!(merge_flag_resource_limits(None, Some("0"), None).is_err());
    }

    fn empty_prepared() -> PreparedSandbox {
        PreparedSandbox {
            caps: CapabilitySet::default(),
            deny_paths: Vec::new(),
            secrets: Vec::new(),
            profile_display_name: None,
            command_policies: None,
            resolved_command_binaries: None,
            session_hooks: profile::SessionHooks::default(),
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            network_profile: None,
            allow_domain: Vec::new(),
            deny_domain: Vec::new(),
            credentials: Vec::new(),
            custom_credentials: std::collections::HashMap::new(),
            credential_capture: std::collections::HashMap::new(),
            credential_providers: std::collections::HashMap::new(),
            credential_routes: Vec::new(),
            tls_intercept: None,
            no_proxy: Vec::new(),
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            listen_ports: Vec::new(),
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: profile::Wsl2ProxyPolicy::default(),
            #[cfg(target_os = "linux")]
            af_unix_mediation: profile::LinuxAfUnixMediation::default(),
            #[cfg(target_os = "linux")]
            sandbox_policy: profile::LinuxSandboxPolicy::default(),
            #[cfg(target_os = "linux")]
            explicit_sandbox_policy: None,
            allow_launch_services_active: false,
            allow_gpu_active: false,
            #[cfg(target_os = "linux")]
            proc_comm_notify: false,
            open_url_origins: Vec::new(),
            open_url_allow_localhost: false,
            bypass_protection_paths: Vec::new(),
            ignored_denial_paths: Vec::new(),
            suppressed_system_service_operations: Vec::new(),
            allowed_env_vars: None,
            denied_env_vars: None,
            set_vars: None,
            profile_network_block: false,
            allow_http2_requested: false,
        }
    }

    #[test]
    fn block_net_with_credential_errors() {
        let args = SandboxArgs {
            block_net: true,
            proxy_credential: vec!["openai".to_string()],
            ..Default::default()
        };
        let prepared = empty_prepared();
        let err = validate_block_net_conflicts(&args, &prepared)
            .expect_err("expected error for --block-net + --credential");
        assert!(
            err.to_string().contains("--block-net") && err.to_string().contains("--credential"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn block_net_with_network_profile_errors() {
        let args = SandboxArgs {
            block_net: true,
            network_profile: Some("strict".to_string()),
            ..Default::default()
        };
        let prepared = empty_prepared();
        let err = validate_block_net_conflicts(&args, &prepared)
            .expect_err("expected error for --block-net + --network-profile");
        assert!(
            err.to_string().contains("--block-net")
                && err.to_string().contains("--network-profile"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn block_net_with_allow_domain_errors() {
        let args = SandboxArgs {
            block_net: true,
            allow_proxy: vec!["example.com".to_string()],
            ..Default::default()
        };
        let prepared = empty_prepared();
        let err = validate_block_net_conflicts(&args, &prepared)
            .expect_err("expected error for --block-net + --allow-domain");
        assert!(
            err.to_string().contains("--block-net") && err.to_string().contains("--allow-domain"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn block_net_alone_is_valid() {
        let args = SandboxArgs {
            block_net: true,
            ..Default::default()
        };
        let prepared = empty_prepared();
        assert!(validate_block_net_conflicts(&args, &prepared).is_ok());
    }

    #[test]
    fn profile_network_block_with_credential_from_profile_errors() {
        let args = SandboxArgs::default();
        let mut prepared = empty_prepared();
        prepared.profile_network_block = true;
        prepared.credentials = vec!["github".to_string()];
        let err = validate_block_net_conflicts(&args, &prepared)
            .expect_err("expected error for profile network block + profile credential");
        assert!(
            err.to_string().contains("--block-net") && err.to_string().contains("--credential"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn allow_endpoint_without_credential_errors() {
        let args = SandboxArgs {
            allow_endpoint: vec!["openai:GET:/v1/chat/completions".to_string()],
            ..Default::default()
        };
        let prepared = empty_prepared();
        let err = validate_block_net_conflicts(&args, &prepared)
            .expect_err("expected error for --allow-endpoint without --credential");
        assert!(
            err.to_string().contains("--allow-endpoint")
                && err.to_string().contains("--credential"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn allow_endpoint_with_credential_is_valid() {
        let args = SandboxArgs {
            allow_endpoint: vec!["openai:GET:/v1/chat/completions".to_string()],
            proxy_credential: vec!["openai".to_string()],
            ..Default::default()
        };
        let prepared = empty_prepared();
        assert!(validate_block_net_conflicts(&args, &prepared).is_ok());
    }

    #[test]
    fn proxy_port_without_proxy_intent_errors() {
        let args = SandboxArgs {
            proxy_port: Some(8080),
            ..Default::default()
        };
        let prepared = empty_prepared();
        let err = validate_block_net_conflicts(&args, &prepared)
            .expect_err("expected error for --proxy-port without proxy mode");
        assert!(
            err.to_string().contains("--proxy-port"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn proxy_port_with_credential_is_valid() {
        let args = SandboxArgs {
            proxy_port: Some(8080),
            proxy_credential: vec!["openai".to_string()],
            ..Default::default()
        };
        let prepared = empty_prepared();
        assert!(validate_block_net_conflicts(&args, &prepared).is_ok());
    }
}
