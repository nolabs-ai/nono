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
use crate::{policy, protected_paths, sandbox_state};
use crate::{DETACHED_CWD_PROMPT_RESPONSE_ENV, DETACHED_LAUNCH_ENV};
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

/// Returns `true` if `profile_name` is `"claude-code"` or `"claude-no-kc"`, or
/// transitively extends either.
fn is_claude_code_profile(profile_name: &str) -> bool {
    fn check(name: &str, visited: &mut Vec<String>) -> bool {
        if name == "claude-code" || name == "claude-no-kc" {
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
    if let Some(raw) = keychain_raw {
        if let Some(oauth) = parse_claude_oauth_state_json(raw, "Claude OAuth keychain JSON")? {
            return Ok(Some(oauth));
        }
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
    pub(crate) secrets: Vec<nono::LoadedSecret>,
    pub(crate) rollback_exclude_patterns: Vec<String>,
    pub(crate) rollback_exclude_globs: Vec<String>,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    pub(crate) upstream_proxy: Option<String>,
    pub(crate) upstream_bypass: Vec<String>,
    pub(crate) listen_ports: Vec<u16>,
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    pub(crate) allow_launch_services_active: bool,
    pub(crate) allow_gpu_active: bool,
    pub(crate) open_url_origins: Vec<String>,
    pub(crate) open_url_allow_localhost: bool,
    pub(crate) bypass_protection_paths: Vec<PathBuf>,
    pub(crate) allowed_env_vars: Option<Vec<String>>,
    pub(crate) denied_env_vars: Option<Vec<String>>,
}

fn resolved_workdir(args: &SandboxArgs) -> PathBuf {
    args.workdir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
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
    prepared: PreparedSandbox,
    args: &SandboxArgs,
    silent: bool,
) -> Result<PreparedSandbox> {
    output::print_skipped_requested_paths(&collect_missing_cli_requested_paths(args), silent);
    output::print_capabilities(&prepared.caps, args.verbose, silent);

    #[cfg(target_os = "linux")]
    output::print_abi_info(silent);

    if !Sandbox::is_supported() {
        return Err(NonoError::SandboxInit(Sandbox::support_info().details));
    }

    info!("{}", Sandbox::support_info().details);

    Ok(prepared)
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
/// - `/proc/self/task` (read+write): NVIDIA driver 570+ writes to
///   `/proc/self/task/<tid>/comm` during thread startup to set thread names.
///   Without write access this returns EACCES and the driver treats it as a
///   fatal OS error, surfacing as CUDA Error 304 (`cudaErrorOperatingSystem`).
///   Narrowing write access to the `task` subtree keeps other per-process
///   procfs entries read-only.
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
    caps.add_fs(FsCapability::new_dir(
        std::path::Path::new("/proc/self/task"),
        AccessMode::ReadWrite,
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
pub(crate) fn maybe_enable_gpu(
    caps: &mut CapabilitySet,
    cli_requested: bool,
    profile_allowed: bool,
) -> Result<bool> {
    if !cli_requested {
        return Ok(false);
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
    Ok(true)
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
             /proc/driver/nvidia-uvm, and /proc/self; read/write access to\n  \
             /proc/self/task (for CUDA thread-name initialisation)."
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

        let allow_domain = manifest
            .network
            .as_ref()
            .map(|network| network.allow_domains.clone())
            .unwrap_or_default();
        print_allow_domain_port_warnings(&allow_domain, "manifest allow_domain", silent);
        let credentials = manifest
            .credentials
            .iter()
            .map(|credential| credential.name.as_str().to_string())
            .collect();

        return finalize_prepared_sandbox(
            PreparedSandbox {
                caps,
                secrets: Vec::new(),
                rollback_exclude_patterns,
                rollback_exclude_globs,
                network_profile: None,
                allow_domain,
                credentials,
                custom_credentials: HashMap::new(),
                upstream_proxy: None,
                upstream_bypass: Vec::new(),
                listen_ports: Vec::new(),
                capability_elevation: false,
                #[cfg(target_os = "linux")]
                wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::default(),
                allow_launch_services_active: false,
                allow_gpu_active: false,
                open_url_origins: Vec::new(),
                open_url_allow_localhost: false,
                bypass_protection_paths: Vec::new(),
                allowed_env_vars: None,
                denied_env_vars: None,
            },
            args,
            silent,
        );
    }

    let prepared_profile = prepare_profile(args, silent, &workdir)?;
    let crate::profile_runtime::PreparedProfile {
        loaded_profile,
        capability_elevation,
        #[cfg(target_os = "linux")]
        wsl2_proxy_policy,
        workdir_access: profile_workdir_access,
        rollback_exclude_patterns: profile_rollback_patterns,
        rollback_exclude_globs: profile_rollback_globs,
        network_profile: profile_network_profile,
        allow_domain: profile_allow_domain,
        credentials: profile_credentials,
        custom_credentials: profile_custom_credentials,
        upstream_proxy: profile_upstream_proxy,
        upstream_bypass: profile_upstream_bypass,
        listen_ports: profile_listen_ports,
        open_url_origins,
        open_url_allow_localhost,
        allow_launch_services: profile_allow_launch_services,
        allow_gpu: profile_allow_gpu,
        allow_parent_of_protected: profile_allow_parent_of_protected,
        bypass_protection_paths,
        allowed_env_vars: profile_allowed_env_vars,
        denied_env_vars: profile_denied_env_vars,
    } = prepared_profile;

    if let Some(profile) = loaded_profile.as_ref() {
        let profile_warnings = command_blocking_deprecation::collect_profile_warnings(profile);
        command_blocking_deprecation::print_warnings(&profile_warnings, silent);
    }
    print_allow_domain_port_warnings(&profile_allow_domain, "profile allow_domain", silent);
    print_allow_domain_port_warnings(&args.allow_proxy, "--allow-domain", silent);

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
            if let Err(e) = result {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    warn!("Failed to pre-create {}: {}", path.display(), e);
                }
            }
        };

        precreate(&home_path.join(".claude.json.lock"), false);
        precreate(&home_path.join(".cache/claude-cli-nodejs"), true);

        // When CLAUDE_CONFIG_DIR is set, Claude Code reads/writes
        // $CLAUDE_CONFIG_DIR/.claude.json directly and ignores ~/.claude.json.
        // The symlink redirect is only relevant for the default-path case.
        // The caller is expected to `--allow $CLAUDE_CONFIG_DIR` separately.
        if std::env::var_os("CLAUDE_CONFIG_DIR").is_none() {
            // Claude Code writes ~/.claude.json atomically via temp files named
            // ~/.claude.json.tmp.<pid>.<timestamp>.  Landlock/Seatbelt cannot
            // grant permission for these dynamically-named files in ~/, so
            // token refreshes silently fail and the user is logged out.
            //
            // Fix: redirect ~/.claude.json to ~/.claude/claude.json via a
            // symlink.  Claude Code resolves symlinks before computing the
            // temp file path, so temp files land in ~/.claude/ (already
            // readwrite) instead of ~/ (not writable inside the sandbox).
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
                    if let Err(e) =
                        std::os::unix::fs::symlink(".claude/claude.json", &claude_json)
                    {
                        if e.kind() != std::io::ErrorKind::AlreadyExists {
                            warn!("Failed to create ~/.claude.json symlink: {}", e);
                        }
                    }
                }
            }
        }

        // Precreate Claude Code's token-refresh lock directory at the path
        // Claude Code actually uses: "${effective_config_dir}.lock/" where
        // effective_config_dir = $CLAUDE_CONFIG_DIR if set, else ~/.claude.
        // Claude Code mkdirs this to acquire the lock and rmdirs it afterwards;
        // the sandbox can only attach a path rule to an existing inode, so
        // pre-create it on every run.  Use string concatenation (not
        // `with_extension`) to match Claude Code's "${config_dir}.lock"
        // naming — `with_extension` would replace a pre-existing extension.
        let lock_base = std::env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_path.join(".claude"));
        let lock_dir = {
            let mut s = lock_base.into_os_string();
            s.push(".lock");
            PathBuf::from(s)
        };
        precreate(&lock_dir, true);
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

    // Apply raw Seatbelt rules from the profile (macOS only).
    #[cfg(target_os = "macos")]
    if let Some(ref profile) = loaded_profile {
        if !profile.unsafe_macos_seatbelt_rules.is_empty() {
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
    }

    let allow_launch_services_active = maybe_enable_macos_launch_services(
        &mut caps,
        args.allow_launch_services,
        profile_allow_launch_services,
        &open_url_origins,
        open_url_allow_localhost,
    )?;

    // GPU access: macOS uses IOKit platform rules (tightened to AGXDeviceUserClient only),
    // Linux uses filesystem capabilities for render nodes and compute devices.
    #[cfg(target_os = "macos")]
    let allow_gpu_active = maybe_enable_macos_gpu(
        &mut caps,
        args.allow_gpu,
        loaded_profile.is_none() || profile_allow_gpu,
    )?;
    #[cfg(target_os = "linux")]
    let allow_gpu_active = maybe_enable_gpu(
        &mut caps,
        args.allow_gpu,
        loaded_profile.is_none() || profile_allow_gpu,
    )?;

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
            let cap = FsCapability::new_dir(request.cwd_canonical.clone(), request.access)?;
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
                let cap = FsCapability::new_dir(request.cwd_canonical.clone(), request.access)?;
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
            if parts.len() == 2 {
                if let Ok(pack_dir) = crate::package::package_install_dir(parts[0], parts[1]) {
                    if pack_dir.exists() {
                        if let Ok(canonical) = pack_dir.canonicalize() {
                            if !caps.path_covered_with_access(&canonical, nono::AccessMode::Read) {
                                if let Ok(cap) =
                                    FsCapability::new_dir(canonical, nono::AccessMode::Read)
                                {
                                    caps.add_fs(cap);
                                }
                            }
                        }
                    }
                }
            }
        }
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

    let profile_secrets = loaded_profile
        .map(|profile| profile.env_credentials.mappings)
        .unwrap_or_default();
    let loaded_secrets = load_env_credentials(args, &profile_secrets, silent)?;

    finalize_prepared_sandbox(
        PreparedSandbox {
            caps,
            secrets: loaded_secrets,
            rollback_exclude_patterns: profile_rollback_patterns,
            rollback_exclude_globs: profile_rollback_globs,
            network_profile: profile_network_profile,
            allow_domain: profile_allow_domain,
            credentials: profile_credentials,
            custom_credentials: profile_custom_credentials,
            upstream_proxy: profile_upstream_proxy,
            upstream_bypass: profile_upstream_bypass,
            listen_ports: profile_listen_ports,
            capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy,
            allow_launch_services_active,
            allow_gpu_active,
            open_url_origins,
            open_url_allow_localhost,
            bypass_protection_paths,
            allowed_env_vars: profile_allowed_env_vars,
            denied_env_vars: profile_denied_env_vars,
        },
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
    fn grant_nvidia_gpu_procfs_scopes_proc_self_reads_with_task_writes() {
        // Regression test for the NVIDIA-scoped procfs grants:
        //   /proc/self       Read        (CUDA init reads maps/status/etc.)
        //   /proc/self/task  ReadWrite   (driver writes task/<tid>/comm)
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
            "/proc/self must be read-only (writes are scoped to /proc/self/task)"
        );
        assert!(!proc_self.is_file);

        let proc_self_task = find("/proc/self/task").expect(
            "/proc/self/task must be granted read+write so the NVIDIA driver \
             can write task/<tid>/comm (CUDA Error 304 root cause)",
        );
        assert_eq!(
            proc_self_task.access,
            AccessMode::ReadWrite,
            "/proc/self/task must be granted read+write"
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

        assert!(pending_cwd_access_request(&caps, dir.path(), None)
            .expect("request should evaluate")
            .is_none());
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
}
