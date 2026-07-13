use crate::audit_integrity::{
    AuditRecorder, CommandPolicyAuditEvent, CommandPolicyEnvAuditEntry, CommandPolicyStdioAudit,
    CommandPolicyStdioStreamAudit,
};
use crate::command_policy::{
    CommandFromConfig, CommandPoliciesConfig, CommandSandboxConfig, ResolvedCommandBinaries,
    ResolvedCommandBinary, ResolvedExecutableKind, has_explicit_self_invocation_entry,
};
use crate::profile;
use crate::tool_sandbox::credentials::{ResolvedCredential, resolve_credentials};
use crate::tool_sandbox::env::{
    apply_environment_set_vars, default_env_allow_patterns, effective_argv_for_binary,
    env_shebang_target_interpreter, inject_chaining_control_env, inject_url_open_env,
    split_env_entry,
};
use crate::tool_sandbox::launch::{
    exit_status_code, prepare_launcher_command, remove_launch_spec, write_launch_spec,
};
use crate::tool_sandbox::protocol::{
    ChildCapsSpec, FsGrantSpec, StdioFds, StdioLimitActionSpec, StdioLimitSpec,
    StdioStreamLimitSpec, TOOL_SANDBOX_LAUNCH_SPEC_ENV, TOOL_SANDBOX_SHIM_DIR_ENV,
    TOOL_SANDBOX_SOCKET_ENV, TOOL_SANDBOX_URL_IO_TIMEOUT, ToolSandboxChildLaunchSpec,
    ToolSandboxOpenUrlRequest, ToolSandboxOpenUrlResponse, ToolSandboxShimRequest,
    ToolSandboxShimResponse, UnixSocketGrantSpec, read_frame, recv_frame_ack, recv_stdio_fds,
    send_frame_ack, send_stdio_fds, validate_ipc_request, write_frame, write_response,
};
use landlock::{
    AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr,
};
use nix::libc;
use nono::supervisor::socket::peer_credentials;
use nono::{
    AccessMode, CapabilitySet, FsCapability, NetworkMode, NonoError, Result, Sandbox,
    UnixSocketCapability, UnixSocketMode,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Diagnostic-only: parent's CLOCK_MONOTONIC nanos at the latest pre-fork point.
/// Set by exec_strategy on the supervised child's exec env when TOOL_SANDBOX_PROFILE_HOTPATH
/// is active, read by run_shim() on entry to measure shim Rust-runtime startup.
pub(crate) const TOOL_SANDBOX_PARENT_MONOTONIC_ENV: &str = "NONO_TOOL_SANDBOX_PARENT_MONOTONIC";

const MAX_ACTIVE_TOOL_SANDBOX_CHILDREN: usize = 64;
// Max raw bytes the Capture action may buffer before broker scanning.
// Each byte serialises to ~4 chars in JSON; 256 KiB raw → ~1 MiB frame.
const MAX_CAPTURE_STDOUT: usize = 256 * 1024;
const MAX_QUEUED_SHIM_REQUESTS: usize = 128;
const ANCESTRY_DEPTH_LIMIT: usize = 64;

macro_rules! tool_sandbox_profile_log {
        ($($arg:tt)*) => {
            if std::env::var_os("TOOL_SANDBOX_PROFILE_HOTPATH").is_some() {
                eprintln!("[tool-sandbox-prof] {}", format_args!($($arg)*));
            }
        };
    }

pub(crate) static MAIN_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub(crate) fn record_main_start() {
    if std::env::var_os("TOOL_SANDBOX_PROFILE_HOTPATH").is_some() {
        let _ = MAIN_START.get_or_init(std::time::Instant::now);
    }
}

pub(crate) fn log_main_total() {
    if let Some(start) = MAIN_START.get() {
        tool_sandbox_profile_log!("main_total: {:?}", start.elapsed());
    }
}

#[derive(Clone)]
pub(crate) struct PreparedToolSandboxRuntime {
    inner: Arc<ToolSandboxState>,
    listener: Arc<UnixListener>,
    /// URL-open listener, present only when a command declares `open_urls`.
    url_listener: Option<Arc<UnixListener>>,
}

struct ToolSandboxState {
    runtime_dir: PathBuf,
    socket_path: PathBuf,
    /// Dedicated URL-open listener socket path, present only when a command
    /// declares `open_urls`. Kept separate from `socket_path` so the shim
    /// handshake protocol is untouched.
    url_socket_path: Option<PathBuf>,
    shim_dir: PathBuf,
    /// The browser-open shim (a copy of the nono binary named `open`),
    /// materialized only when a command declares `open_urls`.
    url_open_shim: Option<ShimIdentity>,
    session_path: String,
    profile_display_name: Option<String>,
    redaction_policy: nono::ScrubPolicy,
    policy_root: PathBuf,
    /// The agent's own capability set. Used to bound a mediated command's live
    /// working directory: a command may only run where the agent itself is
    /// granted access, so `.`/`@git:*` resolving against the live cwd can never
    /// hand a command filesystem reach the agent lacks.
    outer_caps: CapabilitySet,
    /// Agent's resolved filesystem deny paths; a command's live cwd under any of
    /// these is rejected (the agent's broad allow may otherwise cover them).
    deny_paths: Vec<PathBuf>,
    plan: ResolvedToolSandboxPlan,
    shims_by_command: BTreeMap<String, ShimIdentity>,
    credential_handles: BTreeMap<String, ResolvedCredential>,
    allowed_outer_exec_files: Vec<PathBuf>,
    landlock_abi: nono::DetectedAbi,
    baseline_cache: BaselineCache,
    proxy_trust_bundle_paths: Vec<PathBuf>,
    active_children: Mutex<HashMap<u32, ActiveChild>>,
    active_count: AtomicUsize,
    queued_requests: AtomicUsize,
    emitted_error_response: AtomicBool,
    /// Token broker for credential isolation. Holds real credential values;
    /// nonces in the agent env are resolved to real values by filter_child_env.
    token_broker: crate::tool_sandbox::token_broker::SharedBroker,
    /// Approval backend registry for invocation-policy and intercept approvals.
    approval_backends: nono_proxy::approval::ApprovalBackendRegistry,
}

/// Pre-computed runtime-baseline files (ELF dependency closures + system files)
/// granted to every tool-sandbox child. Built once at supervisor startup so the per-request
/// hot path does no recursive ELF parsing or directory walking.
struct BaselineCache {
    closures: BTreeMap<PathBuf, Vec<PathBuf>>,
    system_files: Vec<(PathBuf, AccessMode)>,
}

struct ResolvedToolSandboxPlan {
    config: CommandPoliciesConfig,
    resolved: ResolvedCommandBinaries,
    /// Pre-resolved `exec` intercept helpers, keyed by their env-expanded path
    /// as written in the profile. Identity expectations are captured here so
    /// the helper launch is TOCTOU-protected like a command binary.
    exec_helpers: BTreeMap<PathBuf, ResolvedCommandBinary>,
    executable_dirs: Vec<PathBuf>,
    deny_only: BTreeMap<String, ResolvedDenyOnlyCommand>,
    allowed_direct_bypasses: Vec<PathBuf>,
    allowed_direct_bypass_ids: HashSet<FileId>,
}

#[derive(Debug, Clone)]
struct ResolvedDenyOnlyCommand {
    path: PathBuf,
    id: FileId,
}

#[derive(Debug, Clone)]
struct ShimIdentity {
    path: PathBuf,
    id: FileId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FileId {
    dev: u64,
    ino: u64,
}

#[derive(Debug, Clone)]
enum Caller {
    Session { pid: u32 },
    Command { command: String, pid: u32 },
}

struct ActiveChild {
    command: String,
    pidfd: OwnedFd,
    /// The caller this command was launched under (its policy edge). A URL-open
    /// request from this command resolves its policy via this caller, not via a
    /// fresh ancestry walk — which would treat the command as its own caller and
    /// check a nonexistent `<cmd>.can_use[<cmd>]` self-edge.
    launch_caller: Caller,
}

struct ChildLaunchResult {
    exit_code: i32,
    stdio: Option<CommandPolicyStdioAudit>,
    blocked_reason: Option<String>,
}

impl ResolvedToolSandboxPlan {
    fn build(
        config: &CommandPoliciesConfig,
        _allowed_commands: &[String],
        _blocked_commands: &[String],
        outer_caps: &CapabilitySet,
        precomputed: Option<&crate::command_policy::ResolvedCommandBinaries>,
    ) -> Result<Self> {
        let path_env = std::env::var_os("PATH");
        let resolved = match precomputed {
            Some(resolved) => resolved.clone(),
            None => {
                crate::command_policy::resolve_policy_command_binaries(config, path_env.clone())?
            }
        };
        for w in &resolved.warnings {
            if w.code == "command_not_found" {
                eprintln!("  [nono] Warning: {}", w.message);
            }
        }
        // Validate PATH/configured executable directories before using them
        // for deny-only resolution and the outer executable identity gate.
        // The gate allows non-controlled executables while excluding
        // controlled command identities by path/inode.
        let search_dirs = command_search_dirs(config, path_env, outer_caps)?;
        validate_trusted_executable_dirs(&search_dirs, outer_caps)?;
        // BMETE command policies are scoped to command_policies.commands.
        // Legacy startup command denies must not be folded into tool-sandbox as
        // deny-only commands; doing so makes inherited dangerous-command
        // entries part of the child sandbox trust boundary.
        let deny_only = resolve_deny_only_commands(config, &[], &[], &search_dirs)?;
        validate_controlled_binary_immutability(config, &resolved, &deny_only, outer_caps)?;
        let exec_helpers = crate::command_policy::resolve_policy_exec_helpers(config)?;
        validate_controlled_exec_helper_immutability(config, &exec_helpers, outer_caps)?;
        let governance_denies = resolve_governance_denies(config)?;
        let allowed_direct_bypasses =
            resolve_allowed_direct_bypasses(config, &resolved, &deny_only, &governance_denies)?;
        let allowed_direct_bypass_ids = resolve_file_ids(&allowed_direct_bypasses)?;
        Ok(Self {
            config: config.clone(),
            resolved,
            exec_helpers,
            executable_dirs: search_dirs,
            deny_only,
            allowed_direct_bypasses,
            allowed_direct_bypass_ids,
        })
    }
}

impl PreparedToolSandboxRuntime {
    pub(crate) fn prepare(input: super::ToolSandboxPrepare<'_>) -> Result<Self> {
        let super::ToolSandboxPrepare {
            config,
            resolved_command_binaries,
            audit_context,
            allowed_commands,
            blocked_commands,
            outer_caps,
            deny_paths,
            policy_root,
            proxy_credential_env_vars,
            proxy_trust_bundle_paths,
            shared_broker,
        } = input;

        let start_total = std::time::Instant::now();
        if let Some(start) = MAIN_START.get() {
            tool_sandbox_profile_log!("main_to_prepare: {:?}", start.elapsed());
        }

        let start_plan = std::time::Instant::now();
        let landlock_abi = detect_supported_exec_gate_abi()?;
        let plan = ResolvedToolSandboxPlan::build(
            config,
            allowed_commands,
            blocked_commands,
            outer_caps,
            resolved_command_binaries,
        )?;
        tool_sandbox_profile_log!(
            "prepare:plan_build: {:?} ({} commands, {} deny_only)",
            start_plan.elapsed(),
            plan.resolved.commands.len(),
            plan.deny_only.len()
        );

        let start_runtime_dir = std::time::Instant::now();
        let runtime_dir = create_runtime_dir()?;
        let mut runtime_cleanup = RuntimeDirCleanup::new(runtime_dir.clone());
        let socket_path = runtime_dir.join("supervisor.sock");
        let listener = bind_runtime_socket(&socket_path)?;
        // Bind a dedicated URL-open listener only when a command needs it.
        let (url_socket_path, url_listener) = if config.any_command_allows_url_open() {
            let url_socket_path = runtime_dir.join("url.sock");
            let url_listener = bind_runtime_socket(&url_socket_path)?;
            (Some(url_socket_path), Some(Arc::new(url_listener)))
        } else {
            (None, None)
        };
        let shim_dir = create_shim_dir(&runtime_dir)?;
        let session_path = build_session_path(&shim_dir);
        tool_sandbox_profile_log!(
            "prepare:runtime_dir_and_socket: {:?}",
            start_runtime_dir.elapsed()
        );

        let start_credentials = std::time::Instant::now();
        let credential_handles =
            resolve_credentials(&plan.config.credentials, proxy_credential_env_vars)?;
        tool_sandbox_profile_log!(
            "prepare:resolve_credentials: {:?}",
            start_credentials.elapsed()
        );

        let start_shims = std::time::Instant::now();
        let mut shims_by_command = BTreeMap::new();
        let mut shim_names: BTreeSet<String> = plan.resolved.commands.keys().cloned().collect();
        shim_names.extend(plan.deny_only.keys().cloned());
        let shim_source = materialize_shim_source(&shim_dir)?;
        let shim_count = shim_names.len();
        for name in shim_names {
            let identity = materialize_shim(&shim_source, &shim_dir, &name)?;
            shims_by_command.insert(name, identity);
        }
        // Materialize the browser-open shim only when URL opening is enabled.
        let url_open_shim = if url_socket_path.is_some() {
            Some(materialize_shim(
                &shim_source,
                &shim_dir,
                crate::tool_sandbox::url_shim::URL_OPEN_SHIM_NAME,
            )?)
        } else {
            None
        };
        seal_shim_dir(&shim_dir)?;
        tool_sandbox_profile_log!(
            "prepare:materialize_shims: {:?} ({} shims)",
            start_shims.elapsed(),
            shim_count
        );

        // Reset once so the ELF-resolution memo caches span both closure-building
        // batches below (outer-exec gate + baseline cache): each shared object is
        // canonicalized / resolved / read / stat'd once per launch, not per batch.
        reset_elf_resolution_cache();
        let start_outer_exec = std::time::Instant::now();
        let allowed_outer_exec_files = build_outer_exec_files(
            shims_by_command.values().chain(url_open_shim.iter()),
            &plan,
            &shim_source,
        )?;
        tool_sandbox_profile_log!(
            "prepare:build_outer_exec_files: {:?} ({} paths)",
            start_outer_exec.elapsed(),
            allowed_outer_exec_files.len()
        );

        let start_baseline_cache = std::time::Instant::now();
        let baseline_cache = build_baseline_cache(
            &plan,
            shims_by_command.values().chain(url_open_shim.iter()),
            &shim_source,
        )?;
        tool_sandbox_profile_log!(
            "build_baseline_cache: {:?} ({} closures cached)",
            start_baseline_cache.elapsed(),
            baseline_cache.closures.len()
        );

        let approval_backends = crate::approval_runtime::build_approval_registry(&plan.config)?;
        let runtime = Self {
            inner: Arc::new(ToolSandboxState {
                runtime_dir,
                socket_path,
                url_socket_path,
                shim_dir,
                url_open_shim,
                session_path,
                profile_display_name: audit_context.profile_display_name,
                redaction_policy: audit_context.redaction_policy,
                policy_root: policy_root.to_path_buf(),
                outer_caps: outer_caps.clone(),
                deny_paths: deny_paths.to_vec(),
                plan,
                shims_by_command,
                credential_handles,
                allowed_outer_exec_files,
                landlock_abi,
                baseline_cache,
                proxy_trust_bundle_paths: proxy_trust_bundle_paths.to_vec(),
                active_children: Mutex::new(HashMap::new()),
                active_count: AtomicUsize::new(0),
                queued_requests: AtomicUsize::new(0),
                emitted_error_response: AtomicBool::new(false),
                token_broker: shared_broker
                    .unwrap_or_else(crate::tool_sandbox::token_broker::new_shared_broker),
                approval_backends,
            }),
            listener: Arc::new(listener),
            url_listener,
        };
        runtime_cleanup.disarm();
        tool_sandbox_profile_log!("prepare:total: {:?}", start_total.elapsed());
        Ok(runtime)
    }

    /// Best-effort removal of the runtime dir. Safe to call multiple times and from
    /// any exit path: on the success path it must be invoked explicitly before
    /// `process::exit` (which bypasses Drop chains); on Rust unwind paths
    /// `ToolSandboxState::Drop` provides a fallback that finds a stale dir already gone.
    pub(crate) fn cleanup_runtime_dir(&self) {
        if let Err(err) = guarded_remove_runtime_dir(&self.inner.runtime_dir) {
            debug!(
                "tool-sandbox runtime dir cleanup skipped for {}: {}",
                self.inner.runtime_dir.display(),
                err
            );
        }
    }

    pub(crate) fn env_overrides(&self) -> Vec<(String, String)> {
        vec![
            ("PATH".to_string(), self.inner.session_path.clone()),
            (
                TOOL_SANDBOX_SOCKET_ENV.to_string(),
                self.inner.socket_path.display().to_string(),
            ),
            (
                TOOL_SANDBOX_SHIM_DIR_ENV.to_string(),
                self.inner.shim_dir.display().to_string(),
            ),
        ]
    }

    pub(crate) fn broker_secret_env_vars(
        &self,
        secrets: &[nono::LoadedSecret],
    ) -> Result<Vec<(String, String)>> {
        let mut broker = self.inner.token_broker.lock().map_err(|_| {
            NonoError::SandboxInit("tool-sandbox token broker lock poisoned".to_string())
        })?;
        Ok(secrets
            .iter()
            .map(|secret| {
                (
                    secret.env_var.clone(),
                    broker.issue(Zeroizing::new(secret.value.as_bytes().to_vec())),
                )
            })
            .collect())
    }

    pub(crate) fn grant_outer_caps(&self, caps: &mut CapabilitySet) -> Result<()> {
        caps.add_fs(FsCapability::new_dir(
            &self.inner.shim_dir,
            AccessMode::Read,
        )?);
        for shim in self.inner.shims_by_command.values() {
            caps.add_fs(FsCapability::new_file(&shim.path, AccessMode::Read)?);
        }
        caps.add_unix_socket(UnixSocketCapability::new_file(
            &self.inner.socket_path,
            UnixSocketMode::Connect,
        )?);
        caps.add_fs(FsCapability::new_file(
            &self.inner.socket_path,
            AccessMode::Read,
        )?);
        caps.deduplicate();
        Ok(())
    }

    pub(crate) fn apply_outer_exec_gate(&self) -> Result<()> {
        apply_outer_exec_gate(
            &self.inner.allowed_outer_exec_files,
            self.inner.landlock_abi,
        )
    }

    pub(crate) fn landlock_abi_version(&self) -> &'static str {
        self.inner.landlock_abi.version_string()
    }

    pub(crate) fn shim_for_initial_command(&self, program: &str) -> Option<&Path> {
        if program.contains('/') {
            return None;
        }
        self.inner
            .shims_by_command
            .get(program)
            .map(|identity| identity.path.as_path())
    }

    /// Initial command identity gate when tool-sandbox is active.
    ///
    /// Allowed cases:
    /// - bare command name (no `/`) that is a policy command — runs through its shim
    /// - any path or name whose canonical inode is in `allow_direct_exec_bypass`
    /// - non-controlled executable identities, which continue under the
    ///   outer session sandbox
    ///
    /// Direct execution of a controlled or deny-only binary is rejected by
    /// the binary identity, independent of the wrapper that attempted it.
    pub(crate) fn validate_initial_exec(
        &self,
        original_program: &str,
        resolved_program: &Path,
    ) -> Result<Option<NonoError>> {
        // Bare name in shims_by_command resolves through a shim (policy or
        // deny-only — denied by select_effective_policy if the latter).
        if !original_program.contains('/')
            && self.inner.shims_by_command.contains_key(original_program)
        {
            return Ok(None);
        }

        let canonical =
            resolved_program
                .canonicalize()
                .map_err(|source| NonoError::PathCanonicalization {
                    path: resolved_program.to_path_buf(),
                    source,
                })?;
        let metadata = fs::metadata(&canonical).map_err(|source| NonoError::ConfigRead {
            path: canonical.clone(),
            source,
        })?;
        let id = file_id(&metadata);
        Ok(check_exec_gate(
            &self.inner.plan.allowed_direct_bypass_ids,
            &self.inner.plan.resolved.commands,
            &self.inner.plan.deny_only,
            original_program,
            resolved_program,
            id,
        ))
    }

    pub(crate) fn listener_fd(&self) -> i32 {
        self.listener.as_raw_fd()
    }

    /// Raw fd of the URL-open listener, if one was bound (a command declares
    /// `open_urls`). Polled by the supervisor loop alongside `listener_fd`.
    pub(crate) fn url_listener_fd(&self) -> Option<i32> {
        self.url_listener.as_ref().map(|l| l.as_raw_fd())
    }

    /// Drain pending URL-open connections (level-triggered poll dispatch).
    pub(crate) fn handle_url_listener(
        &self,
        session_root_pid: u32,
        session_id: &str,
        audit_recorder: Option<Arc<Mutex<AuditRecorder>>>,
    ) -> Result<()> {
        let Some(url_listener) = self.url_listener.as_ref() else {
            return Ok(());
        };
        loop {
            match url_listener.accept() {
                Ok((stream, _addr)) => {
                    handle_url_open_stream(
                        &self.inner,
                        stream,
                        session_root_pid,
                        session_id,
                        audit_recorder.clone(),
                    );
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    return Err(NonoError::SandboxInit(format!(
                        "tool-sandbox URL listener accept failed: {err}"
                    )));
                }
            }
        }
    }

    pub(crate) fn emitted_error_response(&self) -> bool {
        self.inner.emitted_error_response.load(Ordering::SeqCst)
    }

    pub(crate) fn handle_listener(
        &self,
        session_root_pid: u32,
        session_id: &str,
        audit_recorder: Option<Arc<Mutex<AuditRecorder>>>,
    ) -> Result<()> {
        loop {
            match self.listener.accept() {
                Ok((stream, _addr)) => self.handle_stream(
                    stream,
                    session_root_pid,
                    session_id,
                    audit_recorder.clone(),
                )?,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    return Err(NonoError::SandboxInit(format!(
                        "tool-sandbox supervisor accept failed: {err}"
                    )));
                }
            }
        }
    }

    fn handle_stream(
        &self,
        mut stream: UnixStream,
        session_root_pid: u32,
        session_id: &str,
        audit_recorder: Option<Arc<Mutex<AuditRecorder>>>,
    ) -> Result<()> {
        let previous = self.inner.queued_requests.fetch_add(1, Ordering::SeqCst);
        if previous >= MAX_QUEUED_SHIM_REQUESTS {
            self.inner.queued_requests.fetch_sub(1, Ordering::SeqCst);
            write_response(
                &mut stream,
                126,
                Some("tool-sandbox shim request queue limit exceeded".to_string()),
                Vec::new(),
            )?;
            return Ok(());
        }
        let state = Arc::clone(&self.inner);
        let session_id = session_id.to_string();
        std::thread::spawn(move || {
            let result =
                handle_shim_stream(state, stream, session_root_pid, &session_id, audit_recorder);
            if let Err(err) = result {
                warn!("tool-sandbox shim handling failed: {err}");
            }
        });
        Ok(())
    }
}

impl Drop for ToolSandboxState {
    fn drop(&mut self) {
        if let Err(err) = guarded_remove_runtime_dir(&self.runtime_dir) {
            debug!(
                "tool-sandbox runtime dir cleanup skipped for {}: {err}",
                self.runtime_dir.display()
            );
        }
    }
}

struct RuntimeDirCleanup {
    path: PathBuf,
    active: bool,
}

impl RuntimeDirCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for RuntimeDirCleanup {
    fn drop(&mut self) {
        if self.active {
            let _ = guarded_remove_runtime_dir(&self.path);
        }
    }
}

pub(crate) fn maybe_run_internal_tool_sandbox_entrypoint() -> bool {
    if std::env::var_os(TOOL_SANDBOX_LAUNCH_SPEC_ENV).is_some() {
        exit_from_result(run_child_launcher());
        return true;
    }

    // The browser-open shim is also a copy of the nono binary; detect it before
    // the generic shim path since it does not use the shim handshake socket.
    if crate::tool_sandbox::url_shim::current_exe_is_url_open_shim() {
        exit_from_result(crate::tool_sandbox::url_shim::run_url_open_shim());
        return true;
    }

    if std::env::var_os(TOOL_SANDBOX_SOCKET_ENV).is_some()
        && std::env::var_os(TOOL_SANDBOX_SHIM_DIR_ENV).is_some()
        && current_exe_is_tool_sandbox_shim()
    {
        exit_from_result(run_shim());
        return true;
    }

    false
}

fn exit_from_result(result: Result<()>) {
    match result {
        Ok(()) => std::process::exit(0),
        Err(err) => {
            eprintln!("nono: {err}");
            std::process::exit(126);
        }
    }
}

fn log_cross_process_shim_startup() {
    let Some(parent) = std::env::var_os(TOOL_SANDBOX_PARENT_MONOTONIC_ENV) else {
        return;
    };
    let Some(parent_str) = parent.to_str() else {
        return;
    };
    let Ok(parent_nanos) = parent_str.parse::<i128>() else {
        return;
    };
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return;
    }
    let now_nanos = (ts.tv_sec as i128)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as i128);
    let delta = now_nanos.saturating_sub(parent_nanos);
    let delta_clamped = delta.max(0).min(i128::from(u64::MAX)) as u64;
    let dur = std::time::Duration::from_nanos(delta_clamped);
    tool_sandbox_profile_log!(
        "shim:cross_process_startup: {:?} (parent_pre_fork → shim entry)",
        dur
    );
}

fn current_exe_is_tool_sandbox_shim() -> bool {
    let Some(shim_dir) = std::env::var_os(TOOL_SANDBOX_SHIM_DIR_ENV).map(PathBuf::from) else {
        return false;
    };
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    exe.starts_with(shim_dir)
}

fn run_shim() -> Result<()> {
    let start_shim = std::time::Instant::now();
    log_cross_process_shim_startup();
    let socket_path = std::env::var_os(TOOL_SANDBOX_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            NonoError::SandboxInit("tool-sandbox shim socket env missing".to_string())
        })?;
    let shim_exe = std::env::current_exe().map_err(|err| {
        NonoError::SandboxInit(format!(
            "tool-sandbox shim failed to locate current executable: {err}"
        ))
    })?;
    let command = shim_exe
        .file_name()
        .map(OsStr::to_os_string)
        .and_then(|name| name.into_string().ok())
        .ok_or_else(|| {
            NonoError::SandboxInit("tool-sandbox shim command name invalid".to_string())
        })?;
    let start_env = std::time::Instant::now();
    let argv = std::env::args_os()
        .map(OsStringExt::into_vec)
        .collect::<Vec<_>>();
    let env = std::env::vars_os()
        .map(|(key, value)| {
            let mut entry = key.into_vec();
            entry.push(b'=');
            entry.extend(value.into_vec());
            entry
        })
        .collect::<Vec<_>>();
    let cwd = std::env::current_dir()
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "tool-sandbox shim cwd failed: {err}. '{command}' is running in a directory its \
                 sandbox does not grant read on (getcwd needs to resolve the cwd). If '{command}' \
                 was invoked in a directory outside its policy — e.g. a sibling git worktree — add \
                 \".\" to the command's fs_read so its live working directory is readable."
            ))
        })?
        .into_os_string()
        .into_vec();
    tool_sandbox_profile_log!(
        "shim:env_collect: {:?} ({} args, {} env entries)",
        start_env.elapsed(),
        argv.len(),
        env.len()
    );

    let request = ToolSandboxShimRequest {
        command,
        argv,
        env,
        cwd,
        stdio_tty: [
            is_tty(libc::STDIN_FILENO),
            is_tty(libc::STDOUT_FILENO),
            is_tty(libc::STDERR_FILENO),
        ],
    };
    validate_ipc_request(&request)?;

    let start_connect = std::time::Instant::now();
    let mut stream = UnixStream::connect(&socket_path).map_err(|err| {
        NonoError::SandboxInit(format!(
            "tool-sandbox shim failed to connect to {}: {err}",
            socket_path.display()
        ))
    })?;
    tool_sandbox_profile_log!("shim:socket_connect: {:?}", start_connect.elapsed());
    let start_send = std::time::Instant::now();
    send_shim_identity_fd(&stream, &shim_exe)?;
    write_frame(&mut stream, &request)?;
    recv_frame_ack(&mut stream)?;
    send_stdio_fds(&stream)?;
    tool_sandbox_profile_log!(
        "shim:send_request: {:?} (entry-to-request: {:?})",
        start_send.elapsed(),
        start_shim.elapsed()
    );
    let response: ToolSandboxShimResponse = read_frame(&mut stream)?;
    if let Some(error) = response.error {
        eprintln!("nono: tool-sandbox denied {}: {error}", request.command);
    }
    if !response.captured_stdout.is_empty() {
        use std::io::Write;
        let _ = std::io::stdout().write_all(&response.captured_stdout);
    }
    std::process::exit(response.exit_code);
}

fn run_child_launcher() -> Result<()> {
    // The launcher re-exec returns from main() before init_tracing() runs, so
    // install a stderr subscriber here (honoring the forwarded RUST_LOG) — this
    // surfaces the library's generated-ruleset debug log for the brokered child.
    // No-op unless RUST_LOG is set.
    crate::cli_bootstrap::init_internal_entrypoint_tracing();
    let start_launcher = std::time::Instant::now();
    let spec_path = std::env::var_os(TOOL_SANDBOX_LAUNCH_SPEC_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            NonoError::SandboxInit("tool-sandbox launch spec env missing".to_string())
        })?;
    let start_parse = std::time::Instant::now();
    let bytes = fs::read(&spec_path).map_err(|err| NonoError::ConfigRead {
        path: spec_path.clone(),
        source: err,
    })?;
    let spec: ToolSandboxChildLaunchSpec = serde_json::from_slice(&bytes).map_err(|err| {
        NonoError::ConfigParse(format!("failed to parse tool-sandbox launch spec: {err}"))
    })?;
    tool_sandbox_profile_log!(
        "launcher:read_and_parse_spec: {:?} ({} bytes)",
        start_parse.elapsed(),
        bytes.len()
    );
    match spec.stdio_mode.as_str() {
        "pty" => unsafe {
            crate::pty_proxy::setup_child_pty(libc::STDIN_FILENO);
        },
        "direct_fds" => {
            let result = unsafe { libc::setpgid(0, 0) };
            if result != 0 {
                return Err(NonoError::SandboxInit(format!(
                    "tool-sandbox direct_fds setpgid failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        other => {
            return Err(NonoError::ConfigParse(format!(
                "invalid tool-sandbox stdio mode '{other}'"
            )));
        }
    }
    let real_binary = OsString::from_vec(spec.real_binary.clone());
    let cwd = OsString::from_vec(spec.cwd.clone());
    std::env::set_current_dir(&cwd).map_err(|err| {
        NonoError::SandboxInit(format!(
            "tool-sandbox child chdir failed before sandbox: {err}"
        ))
    })?;

    // R3: Open the binary with O_RDONLY|O_NOFOLLOW, verify identity by
    // fstat'ing and hashing the SAME fd we will exec, then execveat via
    // that fd. The supervisor's earlier verify_binary_identity is only a
    // pre-flight; THIS check is the integrity boundary because the fd we
    // open here is the inode the kernel will execute (via AT_EMPTY_PATH).
    let start_verify = std::time::Instant::now();
    let binary_fd = open_and_verify_binary(&real_binary, &spec)?;
    tool_sandbox_profile_log!("launcher:verify_binary_fd: {:?}", start_verify.elapsed());

    let start_caps_from = std::time::Instant::now();
    let caps = caps_from_spec(&spec.caps)?;
    tool_sandbox_profile_log!("launcher:caps_from_spec: {:?}", start_caps_from.elapsed());
    let start_sandbox_apply = std::time::Instant::now();
    Sandbox::apply_auto(&caps)?;
    tool_sandbox_profile_log!(
        "launcher:sandbox_apply: {:?}",
        start_sandbox_apply.elapsed()
    );

    // Stack a second Landlock layer restricting execute access.
    // AccessMode::Read maps to AccessFs::Execute in the Linux sandbox, so
    // any fs_read dir grant (e.g. fs_read:["."] in the git profile) would
    // otherwise let the child exec arbitrary workspace binaries. This layer
    // confines exec to the specific binary, interpreter (if any), and tool-sandbox
    // shims listed in allowed_exec_paths by the supervisor.
    let exec_paths: Vec<PathBuf> = spec
        .allowed_exec_paths
        .iter()
        .map(|bytes| PathBuf::from(OsString::from_vec(bytes.clone())))
        .collect();
    let start_exec_restrict = std::time::Instant::now();
    Sandbox::restrict_execute(&exec_paths)?;
    tool_sandbox_profile_log!(
        "launcher:restrict_execute: {:?}",
        start_exec_restrict.elapsed()
    );
    tool_sandbox_profile_log!("launcher:total_to_exec: {:?}", start_launcher.elapsed());

    // Build argv / envp as CString arrays. NUL-byte rejection is enforced
    // earlier (validate_ipc_request, env builder) but we re-check defensively.
    let mut argv_c: Vec<CString> = Vec::with_capacity(spec.argv.len());
    for arg in &spec.argv {
        argv_c.push(
            CString::new(arg.as_slice()).map_err(|_| {
                NonoError::SandboxInit("tool-sandbox argv contains NUL".to_string())
            })?,
        );
    }
    let argv_ptrs: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let mut envp_c: Vec<CString> = Vec::with_capacity(spec.env.len());
    for entry in &spec.env {
        envp_c.push(CString::new(entry.as_slice()).map_err(|_| {
            NonoError::SandboxInit("tool-sandbox env entry contains NUL".to_string())
        })?);
    }
    let envp_ptrs: Vec<*const libc::c_char> = envp_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let empty_path = CString::new("").map_err(|_| {
        NonoError::SandboxInit("tool-sandbox: failed to build empty path CString".to_string())
    })?;

    // For shebang scripts, execveat(AT_EMPTY_PATH) passes the fd to the
    // interpreter via /proc/self/fd/<N>. FD_CLOEXEC would close the fd at
    // the execveat boundary, making that path inaccessible to the
    // interpreter (ENOENT). Clear the flag now; the fd is fully verified
    // and is about to be exec'd — the leak window is the exec itself.
    if spec.executable_kind == "ShebangScript" {
        unsafe {
            libc::fcntl(binary_fd.as_raw_fd(), libc::F_SETFD, 0);
        }
    }

    // execveat(fd, "", argv, envp, AT_EMPTY_PATH) — the kernel uses the
    // open fd as the binary, so a path-based swap between verification and
    // exec cannot redirect us to a different inode.
    //
    // The libc binding on Linux GNU declares argv/envp as *const *mut c_char
    // (POSIX convention: outer pointer is const, inner is mutable) while
    // CString::as_ptr() yields *const c_char. The kernel does not mutate
    // the strings; cast at the call site to satisfy the type checker.
    //
    // Use syscall() directly rather than libc::execveat() to avoid a link
    // dependency on the glibc execveat wrapper, which was only added in
    // glibc 2.34. The syscall number (SYS_execveat) is a compile-time
    // constant and syscall() itself is available in all glibc versions.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            binary_fd.as_raw_fd() as libc::c_long,
            empty_path.as_ptr(),
            argv_ptrs.as_ptr().cast::<*mut libc::c_char>(),
            envp_ptrs.as_ptr().cast::<*mut libc::c_char>(),
            libc::AT_EMPTY_PATH,
        );
    }
    let err = std::io::Error::last_os_error();
    if spec.executable_kind == "ShebangScript" {
        let interpreter = spec
            .interpreter
            .map(OsString::from_vec)
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<unknown>".to_string());
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox execveat failed for script {} using interpreter {}: {err}. The selected child policy must grant the script, interpreter, interpreter ELF dependencies, and any required language runtime/package directories.",
            PathBuf::from(real_binary).display(),
            interpreter
        )));
    }
    Err(NonoError::CommandExecution(err))
}

/// Open the binary with `O_RDONLY|O_NOFOLLOW`, verify dev/ino/size/mtime
/// against the supervisor's plan-build snapshot, then read content from the
/// same fd to verify the SHA-256 captured at plan-build. The returned fd is
/// what `execveat(AT_EMPTY_PATH)` runs — verified-object equals
/// executed-object, no path-based TOCTOU window.
fn open_and_verify_binary(path: &OsStr, spec: &ToolSandboxChildLaunchSpec) -> Result<OwnedFd> {
    use std::io::Read;

    let path_c = CString::new(path.as_bytes())
        .map_err(|_| NonoError::SandboxInit("tool-sandbox binary path contains NUL".to_string()))?;
    let raw_fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(NonoError::ConfigRead {
            path: PathBuf::from(path),
            source: std::io::Error::last_os_error(),
        });
    }
    let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox fstat failed for {}: {}",
            PathBuf::from(path).display(),
            std::io::Error::last_os_error()
        )));
    }
    if (st.st_dev as u64) != spec.expected_dev || (st.st_ino as u64) != spec.expected_ino {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox binary inode changed before launch: {}",
            PathBuf::from(path).display()
        )));
    }
    if (st.st_size as u64) != spec.expected_size {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox binary size changed before launch: {}",
            PathBuf::from(path).display()
        )));
    }
    let mtime_nanos = (st.st_mtime as i128)
        .saturating_mul(1_000_000_000)
        .saturating_add(st.st_mtime_nsec as i128);
    if mtime_nanos != spec.expected_mtime_nanos {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox binary mtime changed before launch: {}",
            PathBuf::from(path).display()
        )));
    }

    // Hash content via a duplicate fd so the original fd's offset stays at 0
    // for execveat. (execveat doesn't actually depend on offset, but keeping
    // the original untouched avoids relying on undocumented kernel behavior.)
    let dup_fd = fd
        .try_clone()
        .map_err(|err| NonoError::SandboxInit(format!("tool-sandbox fd dup for hash: {err}")))?;
    let mut file = std::fs::File::from(dup_fd);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|err| NonoError::SandboxInit(format!("tool-sandbox binary fd read: {err}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual_sha256: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual_sha256 != spec.expected_sha256 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox binary content changed before launch: {}",
            PathBuf::from(path).display()
        )));
    }

    Ok(fd)
}

/// Handle a single URL-open request on the dedicated URL listener socket.
///
/// The requesting command is resolved from the connecting PID via the same
/// trusted ancestry walk used for shim requests; the `command` field on the
/// request is advisory only. The command's `open_urls` policy gates the open;
/// the browser is launched by this unsandboxed runtime process.
fn handle_url_open_stream(
    state: &ToolSandboxState,
    mut stream: UnixStream,
    session_root_pid: u32,
    session_id: &str,
    audit_recorder: Option<Arc<Mutex<AuditRecorder>>>,
) {
    // Bound the time a single client can hold this handler. On Linux this runs
    // on the single-threaded supervisor loop, so an idle/slow client would
    // otherwise stall signal handling, other shims, and PTY traffic.
    if stream
        .set_read_timeout(Some(TOOL_SANDBOX_URL_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TOOL_SANDBOX_URL_IO_TIMEOUT)))
        .is_err()
    {
        debug!("tool-sandbox URL open: failed to set socket timeout");
        return;
    }

    let peer_pid = match peer_credentials(stream.as_raw_fd()) {
        Ok(creds) => creds.pid,
        Err(err) => {
            debug!("tool-sandbox URL open: peer pid resolution failed: {err}");
            return;
        }
    };

    let request: ToolSandboxOpenUrlRequest = match read_frame(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            debug!("tool-sandbox URL open: malformed request: {err}");
            return;
        }
    };

    let (success, error) = match validate_url_open(state, peer_pid, session_root_pid, &request.url)
    {
        Ok(()) => match crate::url_open::open_url_in_browser(&request.url) {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(reason)),
        },
        Err(reason) => (false, Some(reason)),
    };

    // Surface the outcome on the runtime's (unsandboxed) stderr. The brokered
    // child collapses every shim failure into exit 126 and the calling tool
    // often captures the shim's stderr, so this is the only place an operator
    // can see WHY an open was denied (e.g. an origin missing from allow_origins).
    match &error {
        Some(reason) => warn!(
            "tool-sandbox URL open denied (pid {peer_pid}): {} — {reason}",
            request.url
        ),
        None => debug!(
            "tool-sandbox URL open allowed (pid {peer_pid}): {}",
            request.url
        ),
    }

    let response = ToolSandboxOpenUrlResponse {
        success,
        error: error.clone(),
    };
    if let Err(err) = write_frame(&mut stream, &response) {
        debug!("tool-sandbox URL open: failed to send response: {err}");
    }

    if let Some(recorder) = audit_recorder.as_ref()
        && let Ok(mut recorder) = recorder.lock()
    {
        let _ = recorder.record_open_url(
            nono::supervisor::types::UrlOpenRequest {
                request_id: format!("tool-sandbox-url-{peer_pid}"),
                url: request.url,
                child_pid: peer_pid,
                session_id: session_id.to_string(),
            },
            success,
            error,
        );
    }
}

/// Resolve the requesting command from the connecting PID and validate the URL
/// against that command's `open_urls` policy. Returns `Ok(())` if permitted, or
/// a denial reason otherwise. Does not open the browser.
fn validate_url_open(
    state: &ToolSandboxState,
    peer_pid: u32,
    _session_root_pid: u32,
    url: &str,
) -> std::result::Result<(), String> {
    // The URL-open shim is a child of the requesting command (e.g. gk). Resolve
    // that command and the caller IT was launched under, then select the
    // command's own running policy. Using the command as its own caller would
    // check a nonexistent `<cmd>.can_use[<cmd>]` self-edge.
    let (command_name, launch_caller) = resolve_url_open_command(peer_pid, state)
        .map_err(|err| format!("caller resolution failed: {err}"))?
        .ok_or_else(|| "URL open is only permitted from an active brokered command".to_string())?;

    let policy = select_effective_policy(&state.plan.config, &command_name, &launch_caller)
        .map_err(|err| format!("policy resolution failed: {err}"))?;

    let open_urls = policy
        .open_urls
        .as_ref()
        .ok_or_else(|| format!("command '{command_name}' does not permit opening URLs"))?;

    crate::url_open::validate_url(url, &open_urls.allow_origins, open_urls.allow_localhost)
}

fn handle_shim_stream(
    state: Arc<ToolSandboxState>,
    mut stream: UnixStream,
    session_root_pid: u32,
    session_id: &str,
    audit_recorder: Option<Arc<Mutex<AuditRecorder>>>,
) -> Result<()> {
    let outcome = handle_shim_stream_inner(
        &state,
        &mut stream,
        session_root_pid,
        session_id,
        audit_recorder,
    );
    state.queued_requests.fetch_sub(1, Ordering::SeqCst);
    match outcome {
        Ok((exit_code, captured_stdout)) => {
            write_response(&mut stream, exit_code, None, captured_stdout)
        }
        Err(err) => {
            state.emitted_error_response.store(true, Ordering::SeqCst);
            write_response(
                &mut stream,
                126,
                Some(super::shim_error_message(&err)),
                Vec::new(),
            )
        }
    }
}

fn handle_shim_stream_inner(
    state: &Arc<ToolSandboxState>,
    stream: &mut UnixStream,
    session_root_pid: u32,
    session_id: &str,
    audit_recorder: Option<Arc<Mutex<AuditRecorder>>>,
) -> Result<(i32, Vec<u8>)> {
    let peer_pid = peer_credentials(stream.as_raw_fd())?.pid;
    let shim_fd = recv_fd_via_socket(stream.as_raw_fd())?;
    let request: ToolSandboxShimRequest = read_frame(stream)?;
    send_frame_ack(stream)?;
    validate_ipc_request(&request)?;
    let auth = authenticate_shim(peer_pid, shim_fd, &request.command, state)?;
    let stdio = recv_stdio_fds(stream)?;

    let caller = match resolve_caller(auth.peer_pid, session_root_pid, state, &request.command) {
        Ok(caller) => caller,
        Err(err) => {
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                &state.redaction_policy,
                session_id,
                auth.peer_pid,
                session_root_pid,
                None,
                "denied",
                Some(err.to_string()),
                None,
            )?;
            return Err(err);
        }
    };

    if state.plan.deny_only.contains_key(&request.command) {
        record_command_policy_audit(
            audit_recorder.as_ref(),
            &request,
            &state.redaction_policy,
            session_id,
            auth.peer_pid,
            session_root_pid,
            Some(&caller),
            "denied",
            Some("legacy_blocked_command".to_string()),
            None,
        )?;
        return Err(NonoError::BlockedCommand {
            command: request.command,
            reason: "legacy_blocked_command".to_string(),
        });
    }

    let policy = match select_effective_policy(&state.plan.config, &request.command, &caller) {
        Ok(policy) => policy,
        Err(err) => {
            let err = if let Some(reason) = super::format_tool_chain_denial(
                &request.command,
                caller_command(Some(&caller)).as_deref(),
                state.profile_display_name.as_deref(),
                &err,
            ) {
                NonoError::BlockedCommand {
                    command: request.command.clone(),
                    reason,
                }
            } else {
                err
            };
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                &state.redaction_policy,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some(err.to_string()),
                None,
            )?;
            return Err(err);
        }
    };
    if let Err(err) = super::reject_unenforced_resources(&request.command, policy) {
        record_command_policy_audit(
            audit_recorder.as_ref(),
            &request,
            &state.redaction_policy,
            session_id,
            auth.peer_pid,
            session_root_pid,
            Some(&caller),
            "denied",
            Some(err.to_string()),
            None,
        )?;
        return Err(err);
    }

    if let Some(invocation_policy) =
        select_invocation_policy(&state.plan.config, &request.command, &caller)
    {
        let child_env = match filter_child_env(state, &request, policy) {
            Ok(env) => env,
            Err(err) => {
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "invocation_denied",
                    Some(err.to_string()),
                    None,
                )?;
                return Err(err);
            }
        };
        let outcome =
            match super::evaluate_invocation_policy(invocation_policy, &request.argv, &child_env) {
                Ok(outcome) => outcome,
                Err(err) => {
                    record_command_policy_audit(
                        audit_recorder.as_ref(),
                        &request,
                        &state.redaction_policy,
                        session_id,
                        auth.peer_pid,
                        session_root_pid,
                        Some(&caller),
                        "invocation_denied",
                        Some(err.to_string()),
                        None,
                    )?;
                    return Err(err);
                }
            };
        match outcome {
            super::InvocationPolicyOutcome::Allow => {
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "invocation_allowed",
                    None,
                    None,
                )?;
            }
            super::InvocationPolicyOutcome::Deny { reason } => {
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "invocation_denied",
                    Some(reason.clone()),
                    None,
                )?;
                return Err(NonoError::BlockedCommand {
                    command: request.command,
                    reason,
                });
            }
            super::InvocationPolicyOutcome::Approve {
                backend,
                timeout_secs,
                reason,
                rule_label,
            } => {
                let approval_route = match super::resolve_approval_route(
                    &state.plan.config,
                    backend.as_deref(),
                    timeout_secs,
                ) {
                    Ok(timeout_secs) => timeout_secs,
                    Err(err) => {
                        record_command_policy_audit(
                            audit_recorder.as_ref(),
                            &request,
                            &state.redaction_policy,
                            session_id,
                            auth.peer_pid,
                            session_root_pid,
                            Some(&caller),
                            "invocation_approve_denied",
                            Some(err.to_string()),
                            None,
                        )?;
                        return Err(NonoError::BlockedCommand {
                            command: request.command,
                            reason: err.to_string(),
                        });
                    }
                };
                let backend = match state
                    .approval_backends
                    .resolve(Some(&approval_route.backend))
                {
                    Ok((_, backend)) => backend,
                    Err(err) => {
                        record_command_policy_audit(
                            audit_recorder.as_ref(),
                            &request,
                            &state.redaction_policy,
                            session_id,
                            auth.peer_pid,
                            session_root_pid,
                            Some(&caller),
                            "invocation_approve_denied",
                            Some(err.to_string()),
                            None,
                        )?;
                        return Err(NonoError::BlockedCommand {
                            command: request.command,
                            reason: err.to_string(),
                        });
                    }
                };
                let argv_display: Vec<String> = request
                    .argv
                    .iter()
                    .filter_map(|a| std::str::from_utf8(a).ok().map(str::to_owned))
                    .collect();
                let approval_request = nono::supervisor::ApprovalRequest::Command {
                    request_id: format!(
                        "tool-sandbox-invocation-approve-{}-{}",
                        request.command,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos())
                            .unwrap_or(0)
                    ),
                    command: request.command.clone(),
                    args: argv_display,
                    caller: caller_label(&caller),
                    intercept_rule: rule_label,
                    reason,
                    child_pid: auth.peer_pid,
                    session_id: session_id.to_string(),
                };
                let decision = run_with_timeout(
                    std::time::Duration::from_secs(approval_route.timeout_secs),
                    move || backend.request_approval(&approval_request),
                )?;
                let (audit_decision, deny_reason) = if decision.is_granted() {
                    ("invocation_approve_granted", None)
                } else {
                    (
                        "invocation_approve_denied",
                        Some("approval_denied".to_string()),
                    )
                };
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    audit_decision,
                    deny_reason.clone(),
                    None,
                )?;
                if !decision.is_granted() {
                    return Err(NonoError::BlockedCommand {
                        command: request.command,
                        reason: deny_reason.unwrap_or_else(|| "approval_denied".to_string()),
                    });
                }
            }
        }
    }

    // Resolve intercept action before consuming the active-count slot so
    // that Respond can return without forking a child process.
    let command_config = state.plan.config.commands.get(&request.command);
    let intercept = command_config
        .map(|cc| super::resolve_intercept_action(cc, &request.argv))
        .unwrap_or_else(super::ResolvedInterceptAction::passthrough);
    let intercept_action = intercept.action;

    // A matched intercept rule may carry a sandbox that replaces the command's
    // selected sandbox for the process this rule launches (every action except
    // `respond`, which launches nothing). Absent -> the command's selected sandbox.
    let effective_sandbox = intercept.sandbox.unwrap_or(policy);

    if let crate::command_policy::InterceptActionConfig::Respond { stdout } = intercept_action {
        // Write the static payload to the shim's stdout fd, then respond.
        let stdout_bytes = stdout.as_bytes();
        use std::io::Write;
        let mut stdout_file = std::fs::File::from(stdio.stdout);
        if let Err(e) = stdout_file.write_all(stdout_bytes) {
            // Non-fatal: log and continue to send the response.
            debug!("tool-sandbox Respond: failed to write static stdout: {e}");
        }
        record_command_policy_audit(
            audit_recorder.as_ref(),
            &request,
            &state.redaction_policy,
            session_id,
            auth.peer_pid,
            session_root_pid,
            Some(&caller),
            "respond",
            None,
            Some(0),
        )?;
        return Ok((0, Vec::new()));
    }

    if let crate::command_policy::InterceptActionConfig::Approve { timeout_secs } = intercept_action
    {
        let argv_display: Vec<String> = request
            .argv
            .iter()
            .filter_map(|a| std::str::from_utf8(a).ok().map(str::to_owned))
            .collect();
        let approval_request = nono::supervisor::ApprovalRequest::Command {
            request_id: format!(
                "tool-sandbox-approve-{}-{}",
                request.command,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ),
            command: request.command.clone(),
            args: argv_display,
            caller: caller_label(&caller),
            intercept_rule: intercept.rule_label(),
            reason: None,
            child_pid: auth.peer_pid,
            session_id: session_id.to_string(),
        };

        let approval_route =
            super::resolve_approval_route(&state.plan.config, None, *timeout_secs)?;
        let (_, backend) = state
            .approval_backends
            .resolve(Some(&approval_route.backend))
            .map_err(|err| NonoError::BlockedCommand {
                command: request.command.clone(),
                reason: err.to_string(),
            })?;
        let timeout = std::time::Duration::from_secs(approval_route.timeout_secs);
        let decision =
            run_with_timeout(timeout, move || backend.request_approval(&approval_request))?;

        let (audit_decision, deny_reason) = if decision.is_granted() {
            ("approve_granted", None)
        } else {
            ("approve_denied", Some("approval_denied".to_string()))
        };
        record_command_policy_audit(
            audit_recorder.as_ref(),
            &request,
            &state.redaction_policy,
            session_id,
            auth.peer_pid,
            session_root_pid,
            Some(&caller),
            audit_decision,
            deny_reason.clone(),
            None,
        )?;
        if !decision.is_granted() {
            return Err(NonoError::BlockedCommand {
                command: request.command,
                reason: deny_reason.unwrap_or_else(|| "approval_denied".to_string()),
            });
        }
    }

    if let crate::command_policy::InterceptActionConfig::CaptureCredential {
        credential,
        grant_to,
    } = intercept_action
    {
        let grants = if grant_to.is_empty() {
            crate::tool_sandbox::token_broker::GrantSet::All
        } else {
            crate::tool_sandbox::token_broker::GrantSet::Specific(grant_to.clone())
        };
        if let Some(nonce) =
            issue_existing_ambient_credential_nonce(state, credential, grants.clone())?
        {
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                &state.redaction_policy,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "capture_credential_cached",
                None,
                Some(0),
            )?;
            return Ok((0, nonce_stdout(nonce)));
        }

        let active = state.active_count.fetch_add(1, Ordering::SeqCst);
        if active >= MAX_ACTIVE_TOOL_SANDBOX_CHILDREN {
            state.active_count.fetch_sub(1, Ordering::SeqCst);
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                &state.redaction_policy,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some("resource_limit".to_string()),
                None,
            )?;
            return Err(NonoError::SandboxInit(
                "tool-sandbox active child limit exceeded".to_string(),
            ));
        }
        let result = (|| {
            let launch = build_child_launch_spec(state, &request, effective_sandbox)?;
            launch_child_with_capture(state, &request.command, &caller, launch, stdio)
        })();
        state.active_count.fetch_sub(1, Ordering::SeqCst);
        return match result {
            Ok((exit_code, raw_output)) => {
                if exit_code != 0 {
                    record_command_policy_audit(
                        audit_recorder.as_ref(),
                        &request,
                        &state.redaction_policy,
                        session_id,
                        auth.peer_pid,
                        session_root_pid,
                        Some(&caller),
                        "denied",
                        Some("credential_capture_failed".to_string()),
                        Some(exit_code),
                    )?;
                    return Err(NonoError::SandboxInit(format!(
                        "tool-sandbox credential capture command failed with exit code {exit_code}"
                    )));
                }
                let captured = normalize_captured_credential(raw_output);
                let nonce = {
                    let mut broker = state.token_broker.lock().map_err(|_| {
                        NonoError::SandboxInit(
                            "tool-sandbox token broker lock poisoned".to_string(),
                        )
                    })?;
                    broker.store_named(credential.clone(), captured, grants.clone())
                };
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "capture_credential",
                    None,
                    Some(0),
                )?;
                Ok((0, nonce_stdout(nonce)))
            }
            Err(err) => {
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "denied",
                    Some(err.to_string()),
                    None,
                )?;
                Err(err)
            }
        };
    }

    if matches!(
        intercept_action,
        crate::command_policy::InterceptActionConfig::Capture
    ) {
        let active = state.active_count.fetch_add(1, Ordering::SeqCst);
        if active >= MAX_ACTIVE_TOOL_SANDBOX_CHILDREN {
            state.active_count.fetch_sub(1, Ordering::SeqCst);
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                &state.redaction_policy,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some("resource_limit".to_string()),
                None,
            )?;
            return Err(NonoError::SandboxInit(
                "tool-sandbox active child limit exceeded".to_string(),
            ));
        }
        let result = (|| {
            let launch = build_child_launch_spec(state, &request, effective_sandbox)?;
            launch_child_with_capture(state, &request.command, &caller, launch, stdio)
        })();
        state.active_count.fetch_sub(1, Ordering::SeqCst);
        match &result {
            Ok((exit_code, raw_output)) => {
                let captured = {
                    let mut broker = state.token_broker.lock().map_err(|_| {
                        NonoError::SandboxInit(
                            "tool-sandbox token broker lock poisoned".to_string(),
                        )
                    })?;
                    broker.scan_and_reissue(raw_output)
                };
                if captured.len() > MAX_CAPTURE_STDOUT {
                    return Err(NonoError::SandboxInit(
                        "tool-sandbox Capture: output exceeds limit".to_string(),
                    ));
                }
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "capture",
                    None,
                    Some(*exit_code),
                )?;
                return Ok((*exit_code, captured));
            }
            Err(err) => {
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "denied",
                    Some(err.to_string()),
                    None,
                )?;
            }
        }
        return result.map(|(c, _)| (c, Vec::new()));
    }

    if let crate::command_policy::InterceptActionConfig::Exec { command } = intercept_action {
        let active = state.active_count.fetch_add(1, Ordering::SeqCst);
        if active >= MAX_ACTIVE_TOOL_SANDBOX_CHILDREN {
            state.active_count.fetch_sub(1, Ordering::SeqCst);
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                &state.redaction_policy,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some("resource_limit".to_string()),
                None,
            )?;
            return Err(NonoError::SandboxInit(
                "tool-sandbox active child limit exceeded".to_string(),
            ));
        }
        let result = (|| {
            let (helper, extra_args) =
                super::policy::resolve_exec_helper(&state.plan.exec_helpers, command)?;
            let launch = build_child_launch_spec_for_binary(
                state,
                &request,
                policy,
                helper,
                &extra_args,
                false,
            )?;
            launch_child(state, &request.command, &caller, launch, stdio)
        })();
        state.active_count.fetch_sub(1, Ordering::SeqCst);
        return match result {
            Ok(launch_result) => {
                if let Some(reason) = launch_result.blocked_reason.clone() {
                    record_command_policy_audit_with_stdio(
                        audit_recorder.as_ref(),
                        &request,
                        &state.redaction_policy,
                        session_id,
                        auth.peer_pid,
                        session_root_pid,
                        Some(&caller),
                        "denied",
                        Some(reason.clone()),
                        None,
                        launch_result.stdio,
                    )?;
                    return Err(NonoError::BlockedCommand {
                        command: request.command,
                        reason,
                    });
                }
                record_command_policy_audit_with_stdio(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "exec",
                    None,
                    Some(launch_result.exit_code),
                    launch_result.stdio,
                )?;
                Ok((launch_result.exit_code, Vec::new()))
            }
            Err(err) => {
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "denied",
                    Some(err.to_string()),
                    None,
                )?;
                Err(err)
            }
        };
    }

    let active = state.active_count.fetch_add(1, Ordering::SeqCst);
    if active >= MAX_ACTIVE_TOOL_SANDBOX_CHILDREN {
        state.active_count.fetch_sub(1, Ordering::SeqCst);
        record_command_policy_audit(
            audit_recorder.as_ref(),
            &request,
            &state.redaction_policy,
            session_id,
            auth.peer_pid,
            session_root_pid,
            Some(&caller),
            "denied",
            Some("resource_limit".to_string()),
            None,
        )?;
        return Err(NonoError::SandboxInit(
            "tool-sandbox active child limit exceeded".to_string(),
        ));
    }

    let result = (|| {
        let launch = build_child_launch_spec(state, &request, effective_sandbox)?;
        launch_child(state, &request.command, &caller, launch, stdio)
    })();
    state.active_count.fetch_sub(1, Ordering::SeqCst);
    match result {
        Ok(launch_result) => {
            if let Some(reason) = launch_result.blocked_reason.clone() {
                record_command_policy_audit_with_stdio(
                    audit_recorder.as_ref(),
                    &request,
                    &state.redaction_policy,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "denied",
                    Some(reason.clone()),
                    None,
                    launch_result.stdio,
                )?;
                return Err(NonoError::BlockedCommand {
                    command: request.command,
                    reason,
                });
            }
            record_command_policy_audit_with_stdio(
                audit_recorder.as_ref(),
                &request,
                &state.redaction_policy,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "allowed",
                None,
                Some(launch_result.exit_code),
                launch_result.stdio,
            )?;
            Ok((launch_result.exit_code, Vec::new()))
        }
        Err(err) => {
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                &state.redaction_policy,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some(err.to_string()),
                None,
            )?;
            Err(err)
        }
    }
}

struct ShimAuth {
    peer_pid: u32,
}

fn authenticate_shim(
    peer_pid: u32,
    shim_fd: OwnedFd,
    command: &str,
    state: &ToolSandboxState,
) -> Result<ShimAuth> {
    let shim_file = File::from(shim_fd);
    let metadata = shim_file.metadata().map_err(|err| {
            NonoError::SandboxInit(format!(
                "tool-sandbox shim authentication failed for pid {peer_pid}: fstat received shim fd failed: {err}"
            ))
        })?;
    if !metadata.is_file() {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox shim authentication failed for pid {peer_pid}: received shim fd is not a regular file"
        )));
    }
    let id = file_id(&metadata);
    let identity = state.shims_by_command.get(command).ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "tool-sandbox shim authentication failed for pid {peer_pid}: missing shim identity for {command}"
        ))
    })?;
    if identity.id != id {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox shim authentication failed for pid {peer_pid}: inode mismatch for {command}"
        )));
    }
    Ok(ShimAuth { peer_pid })
}

fn send_shim_identity_fd(stream: &UnixStream, shim_exe: &Path) -> Result<()> {
    let shim_file = File::open(shim_exe).map_err(|source| NonoError::ConfigRead {
        path: shim_exe.to_path_buf(),
        source,
    })?;
    send_fd_via_socket(stream.as_raw_fd(), shim_file.as_raw_fd())
}

fn resolve_caller(
    peer_pid: u32,
    session_root_pid: u32,
    state: &ToolSandboxState,
    command_name: &str,
) -> Result<Caller> {
    let mut pid = peer_pid;
    for _ in 0..ANCESTRY_DEPTH_LIMIT {
        if let Some((command, launch_caller)) = live_active_child(pid, state)? {
            if command == command_name
                && !has_explicit_self_invocation_entry(&state.plan.config, command_name)
            {
                return Ok(launch_caller);
            }
            return Ok(Caller::Command { command, pid });
        }
        if pid == session_root_pid {
            return Ok(Caller::Session {
                pid: session_root_pid,
            });
        }
        if pid <= 1 {
            break;
        }
        pid = parent_pid(pid)?;
    }
    Err(NonoError::SandboxInit(
        "tool-sandbox caller ancestry could not be trusted".to_string(),
    ))
}

/// Returns the active command for `pid` and the caller it was launched under.
/// Self-invocation with no explicit self-invocation entry uses the launch caller so
/// recursive tool calls keep the current effective policy instead of requiring
/// a `<cmd>.can_use[<cmd>]` edge.
fn live_active_child(pid: u32, state: &ToolSandboxState) -> Result<Option<(String, Caller)>> {
    let map = state
        .active_children
        .lock()
        .map_err(|_| NonoError::SandboxInit("tool-sandbox pid map lock poisoned".to_string()))?;
    let Some(active) = map.get(&pid) else {
        return Ok(None);
    };
    if active_child_is_live(pid, active)? {
        Ok(Some((active.command.clone(), active.launch_caller.clone())))
    } else {
        Ok(None)
    }
}

/// Resolve the active command that owns the URL-open shim at `peer_pid`, along
/// with the caller that command was launched under. Walks the process ancestry
/// the same way [`resolve_caller`] does, but returns the command's launch caller
/// so its own running policy can be selected — resolving the command as its own
/// caller would check a nonexistent `<cmd>.can_use[<cmd>]` self-edge.
fn resolve_url_open_command(
    peer_pid: u32,
    state: &ToolSandboxState,
) -> Result<Option<(String, Caller)>> {
    let mut pid = peer_pid;
    for _ in 0..ANCESTRY_DEPTH_LIMIT {
        if let Some(found) = live_active_child(pid, state)? {
            return Ok(Some(found));
        }
        if pid <= 1 {
            break;
        }
        pid = parent_pid(pid)?;
    }
    Ok(None)
}

fn active_child_is_live(pid: u32, active: &ActiveChild) -> Result<bool> {
    let mut pfd = libc::pollfd {
        fd: active.pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let status = unsafe { libc::poll(&mut pfd, 1, 0) };
    if status < 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox pidfd poll failed for pid {pid}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(status == 0)
}

/// Run `f` in a background thread and block until it returns or the timeout
/// elapses. On timeout the thread is abandoned (detached) and
/// `ApprovalDecision::Timeout` is returned, which the caller treats as a
/// denial.
fn run_with_timeout<F>(timeout: std::time::Duration, f: F) -> Result<nono::ApprovalDecision>
where
    F: FnOnce() -> Result<nono::ApprovalDecision> + Send + 'static,
{
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = f();
        // Ignore send error: receiver may have dropped on timeout.
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Ok(nono::ApprovalDecision::Timeout),
    }
}

fn parent_pid(pid: u32) -> Result<u32> {
    let status_path = PathBuf::from(format!("/proc/{pid}/status"));
    let status = fs::read_to_string(&status_path).map_err(|err| NonoError::ConfigRead {
        path: status_path.clone(),
        source: err,
    })?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().map_err(|err| {
                NonoError::SandboxInit(format!(
                    "failed to parse PPid from {}: {err}",
                    status_path.display()
                ))
            });
        }
    }
    Err(NonoError::SandboxInit(format!(
        "missing PPid in {}",
        status_path.display()
    )))
}

fn select_effective_policy<'a>(
    config: &'a CommandPoliciesConfig,
    command_name: &str,
    caller: &Caller,
) -> Result<&'a CommandSandboxConfig> {
    let command = config.commands.get(command_name).ok_or_else(|| {
        NonoError::SandboxInit(format!("unknown tool-sandbox command '{command_name}'"))
    })?;

    match caller {
        Caller::Session { .. } => {
            if let Some(from) = command.from.get("session") {
                return from.sandbox().ok_or_else(|| NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: "from.session explicit deny".to_string(),
                });
            }
            command
                .sandbox
                .as_ref()
                .ok_or_else(|| NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: "missing session sandbox".to_string(),
                })
        }
        Caller::Command {
            command: caller_name,
            ..
        } => {
            let caller_command = config.commands.get(caller_name).ok_or_else(|| {
                NonoError::SandboxInit(format!("unknown tool-sandbox caller '{caller_name}'"))
            })?;
            if !caller_command
                .can_use
                .iter()
                .any(|name| name == command_name)
            {
                return Err(NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: format!("{caller_name}.can_use missing"),
                });
            }
            match command.from.get(caller_name) {
                Some(from) => from.sandbox().ok_or_else(|| NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: format!("from.{caller_name} explicit deny"),
                }),
                None => Err(NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: format!("missing from.{caller_name}"),
                }),
            }
        }
    }
}

fn select_invocation_policy<'a>(
    config: &'a CommandPoliciesConfig,
    command_name: &str,
    caller: &Caller,
) -> Option<&'a crate::command_policy::InvocationPolicyConfig> {
    let command = config.commands.get(command_name)?;
    match caller {
        Caller::Session { .. } => match command.from.get("session") {
            Some(CommandFromConfig::Edge(edge)) => edge.invocation_policy.as_ref(),
            _ => None,
        },
        Caller::Command {
            command: caller_name,
            ..
        } => match command.from.get(caller_name) {
            Some(CommandFromConfig::Edge(edge)) => edge.invocation_policy.as_ref(),
            _ => None,
        },
    }
}

fn caller_label(caller: &Caller) -> String {
    match caller {
        Caller::Session { .. } => "session".to_string(),
        Caller::Command { command, .. } => command.clone(),
    }
}

fn caller_kind(caller: Option<&Caller>) -> String {
    match caller {
        Some(Caller::Session { .. }) => "session".to_string(),
        Some(Caller::Command { .. }) => "command".to_string(),
        None => "untrusted".to_string(),
    }
}

fn caller_command(caller: Option<&Caller>) -> Option<String> {
    match caller {
        Some(Caller::Command { command, .. }) => Some(command.clone()),
        _ => None,
    }
}

fn caller_pid(caller: Option<&Caller>) -> Option<u32> {
    match caller {
        Some(Caller::Session { pid }) | Some(Caller::Command { pid, .. }) => Some(*pid),
        None => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn record_command_policy_audit(
    recorder: Option<&Arc<Mutex<AuditRecorder>>>,
    request: &ToolSandboxShimRequest,
    redaction_policy: &nono::ScrubPolicy,
    session_id: &str,
    shim_pid: u32,
    session_root_pid: u32,
    caller: Option<&Caller>,
    decision: &str,
    reason: Option<String>,
    exit_code: Option<i32>,
) -> Result<()> {
    record_command_policy_audit_with_stdio(
        recorder,
        request,
        redaction_policy,
        session_id,
        shim_pid,
        session_root_pid,
        caller,
        decision,
        reason,
        exit_code,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn record_command_policy_audit_with_stdio(
    recorder: Option<&Arc<Mutex<AuditRecorder>>>,
    request: &ToolSandboxShimRequest,
    redaction_policy: &nono::ScrubPolicy,
    session_id: &str,
    shim_pid: u32,
    session_root_pid: u32,
    caller: Option<&Caller>,
    decision: &str,
    reason: Option<String>,
    exit_code: Option<i32>,
    stdio: Option<CommandPolicyStdioAudit>,
) -> Result<()> {
    let Some(recorder) = recorder else {
        return Ok(());
    };
    let event = CommandPolicyAuditEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: Some(session_id.to_string()),
        command: request.command.clone(),
        caller: caller
            .map(caller_label)
            .unwrap_or_else(|| "untrusted".to_string()),
        caller_kind: Some(caller_kind(caller)),
        caller_command: caller_command(caller),
        caller_pid: caller_pid(caller),
        shim_pid: Some(shim_pid),
        session_root_pid: Some(session_root_pid),
        decision: decision.to_string(),
        reason,
        stdio_mode: selected_stdio_mode(request).to_string(),
        argv_hash: hash_byte_fields(&request.argv),
        env_name_hash: hash_env_names(&request.env),
        cwd_hash: hash_bytes(&request.cwd),
        argv_display: argv_display(&request.argv, redaction_policy),
        env_names_display: env_names_display(&request.env, redaction_policy),
        env_display: env_display(&request.env, redaction_policy),
        cwd_display: cwd_display(&request.cwd, redaction_policy),
        exit_code,
        stdio,
    };
    let mut recorder = recorder
        .lock()
        .map_err(|_| NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
    recorder.record_command_policy_event(event)
}

fn hash_byte_fields(fields: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hex_hash(hasher.finalize())
}

fn hash_env_names(env: &[Vec<u8>]) -> String {
    let mut names = Vec::new();
    for entry in env {
        if let Some((name, _value)) = split_env_entry(entry) {
            names.push(name.to_vec());
        }
    }
    hash_byte_fields(&names)
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_hash(hasher.finalize())
}

fn hex_hash(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn argv_display(argv: &[Vec<u8>], redaction_policy: &nono::ScrubPolicy) -> Vec<String> {
    let args = argv
        .iter()
        .take(16)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect::<Vec<_>>();
    nono::scrub_argv_with_policy(&args, redaction_policy)
        .into_iter()
        .map(|arg| bounded_display_str(&arg, 128))
        .collect()
}

fn env_names_display(env: &[Vec<u8>], redaction_policy: &nono::ScrubPolicy) -> Vec<String> {
    env.iter()
        .filter_map(|entry| {
            split_env_entry(entry).map(|(name, _value)| {
                let name_display = bounded_display_bytes(name, 128);
                let scrubbed = nono::scrub_env_name_with_policy(&name_display, redaction_policy);
                bounded_display_str(scrubbed.as_ref(), 128)
            })
        })
        .take(64)
        .collect()
}

fn env_display(
    env: &[Vec<u8>],
    redaction_policy: &nono::ScrubPolicy,
) -> Vec<CommandPolicyEnvAuditEntry> {
    env.iter()
        .filter_map(|entry| {
            split_env_entry(entry).map(|(name, value)| {
                let name_display = bounded_display_bytes(name, 128);
                let value_lossy = String::from_utf8_lossy(value);
                let value_display = nono::scrub_env_value_with_policy(
                    &name_display,
                    &value_lossy,
                    redaction_policy,
                );
                let name_display =
                    nono::scrub_env_name_with_policy(&name_display, redaction_policy);
                CommandPolicyEnvAuditEntry {
                    name: bounded_display_str(name_display.as_ref(), 128),
                    value_display: bounded_display_str(value_display.as_ref(), 256),
                }
            })
        })
        .take(64)
        .collect()
}

fn cwd_display(cwd: &[u8], redaction_policy: &nono::ScrubPolicy) -> String {
    let lossy = String::from_utf8_lossy(cwd);
    let scrubbed = nono::scrub_value_with_policy(&lossy, redaction_policy);
    bounded_display_str(scrubbed.as_ref(), 256)
}

fn bounded_display_bytes(bytes: &[u8], max_chars: usize) -> String {
    let lossy = String::from_utf8_lossy(bytes);
    bounded_display_str(&lossy, max_chars)
}

fn bounded_display_str(value: &str, max_chars: usize) -> String {
    let truncated = value.chars().count() > max_chars;
    let mut display = value.chars().take(max_chars).collect::<String>();
    if truncated {
        display.push_str("...");
    }
    display
}

// ── Plan/runtime preparation helpers ─────────────────────────────────────

fn detect_supported_exec_gate_abi() -> Result<nono::DetectedAbi> {
    let abi = Sandbox::detect_abi()?;
    if !abi.has_execute() {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox outer exec gate requires Landlock ABI V3+; detected {}",
            abi.version_string()
        )));
    }
    Ok(abi)
}

fn build_session_path(shim_dir: &Path) -> String {
    let original = std::env::var("PATH").unwrap_or_default();
    if original.is_empty() {
        shim_dir.display().to_string()
    } else {
        format!("{}:{original}", shim_dir.display())
    }
}

fn command_search_dirs(
    config: &CommandPoliciesConfig,
    path_env: Option<OsString>,
    outer_caps: &CapabilitySet,
) -> Result<Vec<PathBuf>> {
    let mut dirs = BTreeSet::new();
    if let Some(path_env) = path_env {
        for dir in std::env::split_paths(&path_env) {
            if dir.as_os_str().is_empty() || !dir.exists() {
                continue;
            }
            if let Ok(canonical) = dir.canonicalize()
                && canonical.is_dir()
                && implicit_executable_dir_is_trusted(&canonical, outer_caps)
            {
                dirs.insert(canonical);
            }
        }
    }

    for dir in &config.executable_dirs {
        let path = PathBuf::from(dir);
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization { path, source })?;
        if !canonical.is_dir() {
            return Err(NonoError::ExpectedDirectory(canonical));
        }
        dirs.insert(canonical);
    }

    Ok(dirs.into_iter().collect())
}

fn implicit_executable_dir_is_trusted(dir: &Path, outer_caps: &CapabilitySet) -> bool {
    let Ok(metadata) = fs::metadata(dir) else {
        return false;
    };
    metadata.permissions().mode() & 0o022 == 0 && !outer_caps_grant_write(outer_caps, dir)
}

fn validate_trusted_executable_dirs(dirs: &[PathBuf], outer_caps: &CapabilitySet) -> Result<()> {
    for dir in dirs {
        let metadata = fs::metadata(dir).map_err(|source| NonoError::ConfigRead {
            path: dir.clone(),
            source,
        })?;
        reject_group_or_world_writable_path(dir, &metadata, "tool-sandbox executable directory")?;
        if outer_caps_grant_write(outer_caps, dir) {
            return Err(NonoError::SandboxInit(format!(
                "tool-sandbox executable directory is writable by the outer session capability set: {}",
                dir.display()
            )));
        }
    }
    Ok(())
}

fn resolve_deny_only_commands(
    config: &CommandPoliciesConfig,
    blocked_commands: &[String],
    allowed_commands: &[String],
    dirs: &[PathBuf],
) -> Result<BTreeMap<String, ResolvedDenyOnlyCommand>> {
    let allowed: HashSet<&String> = allowed_commands.iter().collect();
    let mut deny_only = BTreeMap::new();
    for name in blocked_commands {
        if allowed.contains(name) || config.commands.contains_key(name) {
            continue;
        }
        if let Some(path) = find_first_executable(name, dirs)? {
            let metadata = fs::metadata(&path).map_err(|source| NonoError::ConfigRead {
                path: path.clone(),
                source,
            })?;
            deny_only.insert(
                name.clone(),
                ResolvedDenyOnlyCommand {
                    path,
                    id: file_id(&metadata),
                },
            );
        }
    }
    Ok(deny_only)
}

fn validate_controlled_binary_immutability(
    config: &CommandPoliciesConfig,
    resolved: &ResolvedCommandBinaries,
    deny_only: &BTreeMap<String, ResolvedDenyOnlyCommand>,
    outer_caps: &CapabilitySet,
) -> Result<()> {
    for (command_name, binary) in &resolved.commands {
        let allow_writable_path = config.allow_writable_executables
            || config
                .commands
                .get(command_name)
                .is_some_and(command_allows_writable_executable);
        validate_controlled_file(
            &binary.canonical_path,
            outer_caps,
            "policy command",
            allow_writable_path,
        )?;
    }
    for entry in deny_only.values() {
        validate_controlled_file(
            &entry.path,
            outer_caps,
            "deny-only command",
            config.allow_writable_executables,
        )?;
    }
    Ok(())
}

/// Apply the same non-writable-executable trust gate to resolved `exec`
/// intercept helpers as to command binaries (see the macOS twin for rationale).
fn validate_controlled_exec_helper_immutability(
    config: &CommandPoliciesConfig,
    exec_helpers: &BTreeMap<PathBuf, ResolvedCommandBinary>,
    outer_caps: &CapabilitySet,
) -> Result<()> {
    for binary in exec_helpers.values() {
        let allow_writable_path = config.allow_writable_executables
            || super::policy::command_referencing_exec_helper_allows_writable(
                config,
                &binary.canonical_path,
            );
        validate_controlled_file(
            &binary.canonical_path,
            outer_caps,
            "exec intercept helper",
            allow_writable_path,
        )?;
    }
    Ok(())
}

fn command_allows_writable_executable(
    command: &crate::command_policy::CommandPolicyConfig,
) -> bool {
    command.allow_writable_executable
        && command
            .executable
            .as_ref()
            .is_some_and(|executable| Path::new(executable).is_absolute())
}

fn validate_controlled_file(
    path: &Path,
    outer_caps: &CapabilitySet,
    label: &str,
    allow_writable_path: bool,
) -> Result<()> {
    if !allow_writable_path && outer_caps_grant_file_write(outer_caps, path) {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox {label} binary is writable by the outer session capability set: {}",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "tool-sandbox {label} binary has no parent directory: {}",
            path.display()
        ))
    })?;
    if !allow_writable_path && outer_caps_grant_write(outer_caps, parent) {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox {label} binary is replaceable through writable parent directory: {}",
            parent.display()
        )));
    }
    Ok(())
}

fn reject_group_or_world_writable_path(
    path: &Path,
    metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox {label} is group/world writable: {}",
            path.display()
        )));
    }
    Ok(())
}

fn outer_caps_grant_write(caps: &CapabilitySet, path: &Path) -> bool {
    caps.fs_capabilities().iter().any(|cap| {
        cap.access.contains(AccessMode::Write)
            && if cap.is_file {
                cap.resolved == path
            } else {
                path.starts_with(&cap.resolved)
            }
    })
}

fn outer_caps_grant_file_write(caps: &CapabilitySet, path: &Path) -> bool {
    caps.fs_capabilities()
        .iter()
        .any(|cap| cap.access.contains(AccessMode::Write) && cap.is_file && cap.resolved == path)
}

fn resolve_governance_denies(config: &CommandPoliciesConfig) -> Result<HashMap<FileId, PathBuf>> {
    let mut denies = HashMap::new();
    for entry in &config.deny_direct_exec_bypass {
        let path = PathBuf::from(entry);
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: path.clone(),
                source,
            })?;
        let metadata = fs::metadata(&canonical).map_err(|source| NonoError::ConfigRead {
            path: canonical.clone(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(NonoError::ExpectedFile(canonical));
        }
        denies.insert(file_id(&metadata), canonical);
    }
    Ok(denies)
}

fn resolve_allowed_direct_bypasses(
    config: &CommandPoliciesConfig,
    resolved: &ResolvedCommandBinaries,
    deny_only: &BTreeMap<String, ResolvedDenyOnlyCommand>,
    governance_denies: &HashMap<FileId, PathBuf>,
) -> Result<Vec<PathBuf>> {
    let blocked_ids: HashSet<FileId> = deny_only.values().map(|entry| entry.id).collect();
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for (command_name, command) in &config.commands {
        let Some(policy_binary) = resolved.commands.get(command_name) else {
            // Command was skipped during resolution (not found on PATH); skip here too.
            continue;
        };
        let policy_id = FileId {
            dev: policy_binary.dev,
            ino: policy_binary.ino,
        };
        for entry in &command.allow_direct_exec_bypass {
            let path = PathBuf::from(entry);
            let canonical =
                path.canonicalize()
                    .map_err(|source| NonoError::PathCanonicalization {
                        path: path.clone(),
                        source,
                    })?;
            let metadata = fs::metadata(&canonical).map_err(|source| NonoError::ConfigRead {
                path: canonical.clone(),
                source,
            })?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
                return Err(NonoError::ConfigParse(format!(
                    "allow_direct_exec_bypass for '{command_name}' is not an executable file: {}",
                    canonical.display()
                )));
            }
            let id = file_id(&metadata);
            if id != policy_id {
                return Err(NonoError::ConfigParse(format!(
                    "allow_direct_exec_bypass for '{command_name}' must reference the resolved policy-controlled binary {}; got {}",
                    policy_binary.canonical_path.display(),
                    canonical.display()
                )));
            }
            if blocked_ids.contains(&id) {
                return Err(NonoError::ConfigParse(format!(
                    "allow_direct_exec_bypass for '{command_name}' intersects a deny-only blocked command: {}",
                    canonical.display()
                )));
            }
            if let Some(denied) = governance_denies.get(&id) {
                return Err(NonoError::ConfigParse(format!(
                    "allow_direct_exec_bypass for '{command_name}' intersects inherited deny_direct_exec_bypass {}",
                    denied.display()
                )));
            }
            if seen.insert(id) {
                paths.push(canonical);
            }
        }
    }
    Ok(paths)
}

fn resolve_file_ids(paths: &[PathBuf]) -> Result<HashSet<FileId>> {
    let mut ids = HashSet::new();
    for path in paths {
        let metadata = fs::metadata(path).map_err(|source| NonoError::ConfigRead {
            path: path.clone(),
            source,
        })?;
        ids.insert(file_id(&metadata));
    }
    Ok(ids)
}

fn find_first_executable(name: &str, dirs: &[PathBuf]) -> Result<Option<PathBuf>> {
    for dir in dirs {
        let candidate = dir.join(name);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return candidate.canonicalize().map(Some).map_err(|source| {
                NonoError::PathCanonicalization {
                    path: candidate,
                    source,
                }
            });
        }
    }
    Ok(None)
}

fn create_runtime_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    for _ in 0..32 {
        let path = unique_runtime_path(&base, "nono-tool-sandbox", "");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(NonoError::ConfigWrite { path, source }),
        }
    }
    Err(NonoError::SandboxInit(
        "failed to allocate tool-sandbox runtime dir".to_string(),
    ))
}

fn unique_runtime_path(base: &Path, prefix: &str, suffix: &str) -> PathBuf {
    let nonce = rand::random::<u64>();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut name = format!("{prefix}-{}-{now}-{nonce:x}", std::process::id());
    if !suffix.is_empty() {
        name.push('.');
        name.push_str(suffix);
    }
    base.join(name)
}

fn bind_runtime_socket(socket_path: &Path) -> Result<UnixListener> {
    if socket_path.exists() {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox runtime socket already exists: {}",
            socket_path.display()
        )));
    }
    let listener = UnixListener::bind(socket_path).map_err(|err| {
        NonoError::SandboxInit(format!(
            "tool-sandbox bind socket {}: {err}",
            socket_path.display()
        ))
    })?;
    listener.set_nonblocking(true).map_err(|err| {
        NonoError::SandboxInit(format!(
            "tool-sandbox set nonblocking on socket {}: {err}",
            socket_path.display()
        ))
    })?;
    Ok(listener)
}

fn create_shim_dir(runtime_dir: &Path) -> Result<PathBuf> {
    let shim_dir = runtime_dir.join("shims");
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&shim_dir)
        .map_err(|source| NonoError::ConfigWrite {
            path: shim_dir.clone(),
            source,
        })?;
    Ok(shim_dir)
}

fn materialize_shim_source(shim_dir: &Path) -> Result<PathBuf> {
    let nono_exe = std::env::current_exe()
        .map_err(|err| NonoError::SandboxInit(format!("tool-sandbox current_exe failed: {err}")))?;
    let dest = shim_dir.join("nono-shim-src");
    fs::copy(&nono_exe, &dest).map_err(|source| NonoError::ConfigWrite {
        path: dest.clone(),
        source,
    })?;
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o500)).map_err(|source| {
        NonoError::ConfigWrite {
            path: dest.clone(),
            source,
        }
    })?;
    Ok(dest)
}

fn materialize_shim(shim_source: &Path, shim_dir: &Path, name: &str) -> Result<ShimIdentity> {
    let shim_path = shim_dir.join(name);
    fs::hard_link(shim_source, &shim_path).map_err(|source| NonoError::ConfigWrite {
        path: shim_path.clone(),
        source,
    })?;
    fs::set_permissions(&shim_path, fs::Permissions::from_mode(0o500)).map_err(|source| {
        NonoError::ConfigWrite {
            path: shim_path.clone(),
            source,
        }
    })?;
    let canonical_path =
        shim_path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: shim_path.clone(),
                source,
            })?;
    let metadata = fs::metadata(&canonical_path).map_err(|source| NonoError::ConfigRead {
        path: canonical_path.clone(),
        source,
    })?;
    Ok(ShimIdentity {
        path: canonical_path,
        id: file_id(&metadata),
    })
}

fn seal_shim_dir(shim_dir: &Path) -> Result<()> {
    fs::set_permissions(shim_dir, fs::Permissions::from_mode(0o500)).map_err(|source| {
        NonoError::ConfigWrite {
            path: shim_dir.to_path_buf(),
            source,
        }
    })
}

fn build_outer_exec_files<'a>(
    shims: impl IntoIterator<Item = &'a ShimIdentity>,
    plan: &ResolvedToolSandboxPlan,
    shim_source: &Path,
) -> Result<Vec<PathBuf>> {
    let controlled_ids = controlled_exec_ids(plan);
    let mut seen = HashSet::new();
    let mut paths = Vec::new();

    for shim in shims {
        add_outer_exec_file_with_deps(&shim.path, &mut seen, &mut paths)?;
    }
    add_outer_exec_file_with_deps(shim_source, &mut seen, &mut paths)?;
    for path in &plan.allowed_direct_bypasses {
        add_outer_exec_file_with_deps(path, &mut seen, &mut paths)?;
    }

    for dir in &plan.executable_dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry.map_err(|source| NonoError::ConfigRead {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
            if controlled_ids.contains(&file_id(&metadata)) {
                continue;
            }
            let canonical = path
                .canonicalize()
                .map_err(|source| NonoError::PathCanonicalization { path, source })?;
            if let Err(err) = add_outer_exec_file_with_deps(&canonical, &mut seen, &mut paths) {
                debug!(
                    "tool-sandbox outer exec gate skipped {}: {}",
                    canonical.display(),
                    err
                );
            }
        }
    }

    Ok(paths)
}

fn controlled_exec_ids(plan: &ResolvedToolSandboxPlan) -> HashSet<FileId> {
    let mut ids = HashSet::new();
    for binary in plan.resolved.commands.values() {
        let id = FileId {
            dev: binary.dev,
            ino: binary.ino,
        };
        if !plan.allowed_direct_bypass_ids.contains(&id) {
            ids.insert(id);
        }
    }
    ids.extend(plan.deny_only.values().map(|entry| entry.id));
    ids
}

fn add_outer_exec_file_with_deps(
    path: &Path,
    seen: &mut HashSet<FileId>,
    paths: &mut Vec<PathBuf>,
) -> Result<()> {
    for dep in elf_dependency_closure(path)? {
        let metadata = fs::metadata(&dep).map_err(|source| NonoError::ConfigRead {
            path: dep.clone(),
            source,
        })?;
        if seen.insert(file_id(&metadata)) {
            paths.push(dep);
        }
    }
    Ok(())
}

fn apply_outer_exec_gate(paths: &[PathBuf], abi: nono::DetectedAbi) -> Result<()> {
    if !abi.has_execute() {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox outer exec gate requires Landlock ABI V3+; detected {}",
            abi.version_string()
        )));
    }

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::Execute)
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "tool-sandbox outer exec gate cannot handle Landlock Execute: {err}"
            ))
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .create()
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "tool-sandbox outer exec gate ruleset create failed: {err}"
            ))
        })?;

    for path in paths {
        let fd = PathFd::new(path).map_err(|err| {
            NonoError::SandboxInit(format!(
                "tool-sandbox outer exec gate cannot open {}: {err}",
                path.display()
            ))
        })?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, AccessFs::Execute))
            .map_err(|err| {
                NonoError::SandboxInit(format!(
                    "tool-sandbox outer exec gate add_rule for {}: {err}",
                    path.display()
                ))
            })?;
    }

    let status = ruleset.restrict_self().map_err(|err| {
        NonoError::SandboxInit(format!(
            "tool-sandbox outer exec gate restrict_self failed: {err}"
        ))
    })?;
    ensure_outer_exec_gate_fully_enforced(status.ruleset)
}

fn ensure_outer_exec_gate_fully_enforced(status: landlock::RulesetStatus) -> Result<()> {
    match status {
        landlock::RulesetStatus::FullyEnforced => Ok(()),
        landlock::RulesetStatus::PartiallyEnforced => Err(NonoError::SandboxInit(
            "tool-sandbox outer exec gate was only partially enforced".to_string(),
        )),
        landlock::RulesetStatus::NotEnforced => Err(NonoError::SandboxInit(
            "tool-sandbox outer exec gate was not enforced".to_string(),
        )),
    }
}

fn send_fd_via_socket(socket_fd: RawFd, fd_to_send: RawFd) -> Result<()> {
    let mut byte = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control = vec![0_u8; cmsg_space(std::mem::size_of::<RawFd>())];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as MsgControlLen;

    unsafe {
        let cmsg = msg.msg_control.cast::<libc::cmsghdr>();
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len(std::mem::size_of::<RawFd>());
        let data = cmsg_data(cmsg).cast::<RawFd>();
        *data = fd_to_send;
        msg.msg_controllen = (*cmsg).cmsg_len;
    }

    let sent = unsafe { libc::sendmsg(socket_fd, &msg, 0) };
    if sent < 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox sendmsg(SCM_RIGHTS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn recv_fd_via_socket(socket_fd: RawFd) -> Result<OwnedFd> {
    let mut byte = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control = vec![0_u8; cmsg_space(std::mem::size_of::<RawFd>())];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as MsgControlLen;

    let received = unsafe { libc::recvmsg(socket_fd, &mut msg, 0) };
    if received < 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox recvmsg(SCM_RIGHTS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if received == 0 {
        return Err(NonoError::SandboxInit(
            "tool-sandbox recvmsg(SCM_RIGHTS) received EOF".to_string(),
        ));
    }

    let cmsg = msg.msg_control.cast::<libc::cmsghdr>();
    if msg.msg_controllen < std::mem::size_of::<libc::cmsghdr>() as MsgControlLen
        || unsafe { (*cmsg).cmsg_level } != libc::SOL_SOCKET
        || unsafe { (*cmsg).cmsg_type } != libc::SCM_RIGHTS
        || unsafe { (*cmsg).cmsg_len } < cmsg_len(std::mem::size_of::<RawFd>())
    {
        return Err(NonoError::SandboxInit(
            "tool-sandbox recvmsg(SCM_RIGHTS) missing file descriptor".to_string(),
        ));
    }

    let fd = unsafe { *cmsg_data(cmsg).cast::<RawFd>() };
    if fd < 0 {
        return Err(NonoError::SandboxInit(
            "tool-sandbox recvmsg(SCM_RIGHTS) received invalid file descriptor".to_string(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// msghdr::msg_controllen and cmsghdr::cmsg_len are usize on glibc and u32 on
// musl. This alias lets the cmsg helpers compile correctly on both without
// per-site casts.
#[cfg(target_env = "musl")]
type MsgControlLen = u32;
#[cfg(not(target_env = "musl"))]
type MsgControlLen = usize;

fn cmsg_align(len: usize) -> usize {
    let align = std::mem::size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

fn cmsg_space(data_len: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + cmsg_align(data_len)
}

fn cmsg_len(data_len: usize) -> MsgControlLen {
    (cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + data_len) as MsgControlLen
}

unsafe fn cmsg_data(cmsg: *mut libc::cmsghdr) -> *mut u8 {
    unsafe {
        cmsg.cast::<u8>()
            .add(cmsg_align(std::mem::size_of::<libc::cmsghdr>()))
    }
}

fn build_child_launch_spec(
    state: &ToolSandboxState,
    request: &ToolSandboxShimRequest,
    policy: &CommandSandboxConfig,
) -> Result<ToolSandboxChildLaunchSpec> {
    let binary = state
        .plan
        .resolved
        .commands
        .get(&request.command)
        .ok_or_else(|| {
            NonoError::SandboxInit(format!("missing resolved binary for {}", request.command))
        })?;
    build_child_launch_spec_for_binary(state, request, policy, binary, &[], true)
}

/// Build a child launch spec that runs `binary` (the command's real binary OR
/// an `exec` intercept helper) inside the matched command's sandbox (`policy`).
/// `extra_args` are inserted between argv[0] and the forwarded original args —
/// used by the `exec` action for the helper's fixed leading args.
/// `preserve_caller_argv0` is true for the command's own binary, false for
/// `exec` helpers. The fs-read cap, Landlock execute
/// allowlist (binary + its ELF/interpreter closure), runtime baseline, and
/// identity expectations are all bound to `binary`, while
/// network/credentials/proxy/fs/env come from `policy`.
fn build_child_launch_spec_for_binary(
    state: &ToolSandboxState,
    request: &ToolSandboxShimRequest,
    policy: &CommandSandboxConfig,
    binary: &ResolvedCommandBinary,
    extra_args: &[Vec<u8>],
    preserve_caller_argv0: bool,
) -> Result<ToolSandboxChildLaunchSpec> {
    let start_vbi = std::time::Instant::now();
    verify_binary_identity(binary)?;
    tool_sandbox_profile_log!(
        "verify_binary_identity({}): {:?}",
        binary.canonical_path.display(),
        start_vbi.elapsed()
    );
    let cwd = PathBuf::from(OsString::from_vec(request.cwd.clone()));
    let cwd = cwd
        .canonicalize()
        .map_err(|source| NonoError::PathCanonicalization {
            path: cwd.clone(),
            source,
        })?;

    // Bound the command's live cwd to the agent's own granted filesystem;
    // rejects a cwd outside it (write non-escalation for cwd-scoped policy
    // grants is enforced per-path in add_policy_fs).
    super::admit_command_cwd(
        &request.command,
        &cwd,
        &state.policy_root,
        &state.outer_caps,
        &state.deny_paths,
    )?;

    let start_caps = std::time::Instant::now();
    let mut caps = build_child_caps(state, binary, policy, request, &cwd)?;
    tool_sandbox_profile_log!("build_child_caps total: {:?}", start_caps.elapsed());
    caps.deduplicate();

    let env = filter_child_env(state, request, policy)?;

    // Build the execute allowlist. AccessMode::Read includes
    // AccessFs::Execute in the Landlock mapping; without an explicit
    // execute restriction, fs_read:["."] grants exec on arbitrary workspace
    // binaries. We list only what the child is permitted to exec.
    //
    // For dynamically-linked ELF binaries the kernel must also exec the ELF
    // interpreter (dynamic linker, e.g. ld-linux-x86-64.so.2) recorded in
    // PT_INTERP. The Landlock Execute layer applies to that exec too; if the
    // linker path is not in the allowlist, the kernel returns ENOENT and the
    // shell reports "command not found" (exit 127). Include the full ELF
    // dependency closure (which the baseline cache already captures) so
    // every dynamically-linked binary we permit to exec can actually load.
    let mut allowed_exec_paths: Vec<Vec<u8>> =
        vec![binary.canonical_path.as_os_str().as_bytes().to_vec()];
    if let Some(closure) = state.baseline_cache.closures.get(&binary.canonical_path) {
        for dep in closure {
            allowed_exec_paths.push(dep.as_os_str().as_bytes().to_vec());
        }
    }
    if let Some(interp) = binary.shape.interpreter.as_ref() {
        allowed_exec_paths.push(interp.as_os_str().as_bytes().to_vec());
        if let Ok(canonical_interp) = interp.canonicalize()
            && let Some(closure) = state.baseline_cache.closures.get(&canonical_interp)
        {
            for dep in closure {
                allowed_exec_paths.push(dep.as_os_str().as_bytes().to_vec());
            }
        }
        // `env` re-exec's `<interp>`, so grant it and its ELF closure too.
        if let Some(real_interp) =
            env_shebang_target_interpreter(interp, &binary.shape.interpreter_args)
        {
            debug!(
                "env-shebang: granting re-exec target {} (interp {}, args {:?})",
                real_interp.display(),
                interp.display(),
                binary.shape.interpreter_args
            );
            allowed_exec_paths.push(real_interp.as_os_str().as_bytes().to_vec());
            if let Ok(canonical_real) = real_interp.canonicalize()
                && let Some(closure) = state.baseline_cache.closures.get(&canonical_real)
            {
                for dep in closure {
                    allowed_exec_paths.push(dep.as_os_str().as_bytes().to_vec());
                }
            }
        }
    }
    for shim in state.shims_by_command.values() {
        allowed_exec_paths.push(shim.path.as_os_str().as_bytes().to_vec());
    }
    // Allow execing the browser-open shim only when this command may open URLs
    // without direct LaunchServices (which is macOS-only and a no-op here).
    if policy.open_urls.is_some()
        && !policy.allow_launch_services
        && let Some(shim) = state.url_open_shim.as_ref()
    {
        allowed_exec_paths.push(shim.path.as_os_str().as_bytes().to_vec());
    }
    // All shims are hard links to the same nono binary; include the shim's
    // ELF dependency closure once so the dynamic linker can be exec'd when
    // a child process (e.g. sh) execs a shim.
    if let Some(shim) = state.shims_by_command.values().next()
        && let Some(closure) = state.baseline_cache.closures.get(&shim.path)
    {
        for dep in closure {
            allowed_exec_paths.push(dep.as_os_str().as_bytes().to_vec());
        }
    }
    // Let multi-call tools (e.g. git) exec the helpers they invoke by
    // absolute path.
    for path in resolve_exec_paths(&policy.exec_paths, &state.policy_root, &cwd)? {
        allowed_exec_paths.push(path.as_os_str().as_bytes().to_vec());
    }

    Ok(ToolSandboxChildLaunchSpec {
        real_binary: binary.canonical_path.as_os_str().as_bytes().to_vec(),
        executable_kind: format!("{:?}", binary.shape.kind),
        interpreter: binary
            .shape
            .interpreter
            .as_ref()
            .map(|path| path.as_os_str().as_bytes().to_vec()),
        interpreter_args: binary.shape.interpreter_args.clone(),
        argv: effective_argv_for_binary(
            binary,
            request,
            policy,
            extra_args,
            preserve_caller_argv0,
        )?,
        env,
        cwd: cwd.as_os_str().as_bytes().to_vec(),
        stdio_mode: selected_stdio_mode(request).to_string(),
        stdio_limits: stdio_limits_from_policy(policy),
        caps: caps_to_spec(&caps),
        allowed_exec_paths,
        expected_dev: binary.dev,
        expected_ino: binary.ino,
        expected_size: binary.size,
        expected_mtime_nanos: binary.mtime_nanos,
        expected_sha256: binary.sha256.clone(),
    })
}

fn stdio_limits_from_policy(policy: &CommandSandboxConfig) -> Option<StdioLimitSpec> {
    let stdio = policy.stdio.as_ref()?;
    Some(StdioLimitSpec {
        stdout: stdio.stdout.as_ref().map(stdio_stream_limit_from_policy),
        stderr: stdio.stderr.as_ref().map(stdio_stream_limit_from_policy),
    })
}

fn stdio_stream_limit_from_policy(
    stream: &crate::command_policy::CommandStdioStreamConfig,
) -> StdioStreamLimitSpec {
    StdioStreamLimitSpec {
        max_bytes: stream.max_bytes,
        on_limit: match stream.on_limit {
            crate::command_policy::CommandStdioLimitAction::Truncate => {
                StdioLimitActionSpec::Truncate
            }
            crate::command_policy::CommandStdioLimitAction::Terminate => {
                StdioLimitActionSpec::Terminate
            }
            crate::command_policy::CommandStdioLimitAction::Deny => StdioLimitActionSpec::Deny,
        },
    }
}

fn build_child_caps(
    state: &ToolSandboxState,
    binary: &ResolvedCommandBinary,
    policy: &CommandSandboxConfig,
    request: &ToolSandboxShimRequest,
    cwd: &Path,
) -> Result<CapabilitySet> {
    let mut caps = CapabilitySet::new().block_network();
    caps.add_fs(FsCapability::new_file(
        &binary.canonical_path,
        AccessMode::Read,
    )?);
    add_runtime_baseline(&mut caps, &state.baseline_cache, &binary.canonical_path)?;
    add_executable_shape_baseline(&mut caps, state, binary)?;
    add_chaining_control_caps(&mut caps, state)?;
    add_policy_fs(
        &mut caps,
        policy,
        &state.policy_root,
        cwd,
        &state.outer_caps,
        &state.deny_paths,
    )?;
    add_policy_network(&mut caps, policy)?;
    add_policy_proxy_network(&mut caps, state, request, policy)?;
    add_proxy_trust_bundle_caps(&mut caps, state, policy)?;
    add_policy_credentials(&mut caps, state, policy)?;
    add_url_open_caps(&mut caps, state, policy)?;
    Ok(caps)
}

/// Grant the brokered child connect access to the URL listener socket and read
/// access to the open shim, when the command declares `open_urls` and did not
/// opt into direct LaunchServices. The shim is added to the Landlock execute
/// allowlist in `build_child_launch_spec`.
fn add_url_open_caps(
    caps: &mut CapabilitySet,
    state: &ToolSandboxState,
    policy: &CommandSandboxConfig,
) -> Result<()> {
    if policy.open_urls.is_none() || policy.allow_launch_services {
        return Ok(());
    }
    let (Some(url_socket_path), Some(shim)) =
        (state.url_socket_path.as_ref(), state.url_open_shim.as_ref())
    else {
        return Ok(());
    };
    caps.add_unix_socket(UnixSocketCapability::new_file(
        url_socket_path,
        UnixSocketMode::Connect,
    )?);
    caps.add_fs(FsCapability::new_file(url_socket_path, AccessMode::Read)?);
    caps.add_fs(FsCapability::new_file(&shim.path, AccessMode::Read)?);
    add_runtime_baseline(caps, &state.baseline_cache, &shim.path)?;
    Ok(())
}

fn add_executable_shape_baseline(
    caps: &mut CapabilitySet,
    state: &ToolSandboxState,
    binary: &ResolvedCommandBinary,
) -> Result<()> {
    if binary.shape.kind != ResolvedExecutableKind::ShebangScript {
        return Ok(());
    }
    let Some(interpreter) = binary.shape.interpreter.as_ref() else {
        return Ok(());
    };
    let interpreter =
        interpreter
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: interpreter.clone(),
                source,
            })?;
    caps.add_fs(FsCapability::new_file(&interpreter, AccessMode::Read)?);
    add_runtime_baseline(caps, &state.baseline_cache, &interpreter)?;
    // Landlock intersects the filesystem and execute layers, so the re-exec'd
    // `<interp>` (and its ELF closure) must be present in the fs layer too.
    if let Some(real_interp) =
        env_shebang_target_interpreter(&interpreter, &binary.shape.interpreter_args)
        && let Ok(canonical_real) = real_interp.canonicalize()
    {
        caps.add_fs(FsCapability::new_file(&canonical_real, AccessMode::Read)?);
        add_runtime_baseline(caps, &state.baseline_cache, &canonical_real)?;
    }
    Ok(())
}

fn add_chaining_control_caps(caps: &mut CapabilitySet, state: &ToolSandboxState) -> Result<()> {
    caps.add_fs(FsCapability::new_dir(&state.shim_dir, AccessMode::Read)?);
    for shim in state.shims_by_command.values() {
        caps.add_fs(FsCapability::new_file(&shim.path, AccessMode::Read)?);
    }
    if let Some(shim) = state.shims_by_command.values().next() {
        add_runtime_baseline(caps, &state.baseline_cache, &shim.path)?;
    }
    caps.add_unix_socket(UnixSocketCapability::new_file(
        &state.socket_path,
        UnixSocketMode::Connect,
    )?);
    caps.add_fs(FsCapability::new_file(
        &state.socket_path,
        AccessMode::Read,
    )?);
    Ok(())
}

fn add_policy_fs(
    caps: &mut CapabilitySet,
    policy: &CommandSandboxConfig,
    policy_root: &Path,
    cwd: &Path,
    outer_caps: &CapabilitySet,
    deny_paths: &[PathBuf],
) -> Result<()> {
    use super::dynamic_providers::expand_dynamic_tokens;
    // A write grant that resolves under the live cwd is downgraded to read
    // unless the agent itself can write that exact resolved path, so a
    // command's cwd access never exceeds the agent's own (write
    // non-escalation). Checked per resolved path, not just the cwd as a
    // whole, so a subdirectory the agent can explicitly write stays
    // writable even when the surrounding cwd itself is not. Grants outside
    // the cwd (e.g. `$WORKDIR`, absolute paths) are unaffected.
    let write_access = |path: &Path| {
        let normalized = super::lexically_normalize(path);
        if normalized.starts_with(cwd)
            && !super::agent_can_write(&normalized, policy_root, outer_caps, deny_paths)
        {
            AccessMode::Read
        } else {
            AccessMode::ReadWrite
        }
    };
    // `@git:*` tokens run git in the command's live cwd so they resolve to the
    // repo the command is actually operating in (e.g. its worktree / .git
    // common-dir), not the repo the agent was launched in.
    for entry in &expand_dynamic_tokens(&policy.fs_read, Some(cwd))? {
        let path = resolve_policy_path(entry, policy_root, cwd)?;
        add_optional_dir(caps, path, AccessMode::Read)?;
    }
    for entry in &expand_dynamic_tokens(&policy.fs_write, Some(cwd))? {
        let path = resolve_policy_path(entry, policy_root, cwd)?;
        let access = write_access(&path);
        add_optional_dir(caps, path, access)?;
    }
    for entry in &expand_dynamic_tokens(&policy.fs_read_file, Some(cwd))? {
        let path = resolve_policy_path(entry, policy_root, cwd)?;
        add_optional_read_file(caps, path)?;
    }
    for entry in &expand_dynamic_tokens(&policy.fs_write_file, Some(cwd))? {
        let path = resolve_policy_path(entry, policy_root, cwd)?;
        if matches!(write_access(&path), AccessMode::Read) {
            add_optional_read_file(caps, path)?;
        } else {
            caps.add_fs(FsCapability::new_file(path, AccessMode::ReadWrite)?);
        }
    }
    Ok(())
}

fn add_optional_dir(caps: &mut CapabilitySet, path: PathBuf, access: AccessMode) -> Result<()> {
    match FsCapability::new_dir(&path, access) {
        Ok(capability) => {
            caps.add_fs(capability);
            Ok(())
        }
        Err(NonoError::PathNotFound(_)) => Ok(()),
        Err(err) => Err(err),
    }
}

fn add_optional_read_file(caps: &mut CapabilitySet, path: PathBuf) -> Result<()> {
    match FsCapability::new_file(&path, AccessMode::Read) {
        Ok(capability) => {
            caps.add_fs(capability);
            Ok(())
        }
        Err(NonoError::PathNotFound(_)) => Ok(()),
        Err(err) => Err(err),
    }
}

fn resolve_policy_path(entry: &str, workdir: &Path, cwd: &Path) -> Result<PathBuf> {
    let expanded = profile::expand_vars(entry, workdir)?;
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        Ok(cwd.join(expanded))
    }
}

/// Resolve a command's `exec_paths` for the execute allowlist. Non-existent
/// paths are skipped so a profile can list per-distro candidates.
fn resolve_exec_paths(
    exec_paths: &[String],
    policy_root: &Path,
    cwd: &Path,
) -> Result<Vec<PathBuf>> {
    let mut resolved = Vec::new();
    for entry in &super::dynamic_providers::expand_dynamic_tokens(exec_paths, Some(cwd))? {
        let path = resolve_policy_path(entry, policy_root, cwd)?;
        if path.exists() {
            resolved.push(path);
        } else {
            warn!(
                "tool-sandbox: skipping exec_path '{}' (resolved from '{}'): path does not exist",
                path.display(),
                entry
            );
        }
    }
    Ok(resolved)
}

fn add_policy_network(caps: &mut CapabilitySet, policy: &CommandSandboxConfig) -> Result<()> {
    let Some(network) = &policy.network else {
        return Ok(());
    };
    if network.allow_all {
        caps.set_network_mode_mut(NetworkMode::AllowAll);
        return Ok(());
    }
    for port in &network.tcp_connect_ports {
        caps.add_tcp_connect_port(*port);
    }
    for port in &network.tcp_bind_ports {
        caps.add_tcp_bind_port(*port);
    }
    Ok(())
}

fn add_policy_proxy_network(
    caps: &mut CapabilitySet,
    state: &ToolSandboxState,
    request: &ToolSandboxShimRequest,
    policy: &CommandSandboxConfig,
) -> Result<()> {
    if matches!(caps.network_mode(), NetworkMode::AllowAll) {
        return Ok(());
    }
    if !policy_uses_proxy_route(state, policy) {
        return Ok(());
    }
    let port = super::proxy_port_from_env(&request.env).ok_or_else(|| {
        NonoError::SandboxInit(
            "tool-sandbox proxy-routed network policy was granted but no loopback proxy env was present"
                .to_string(),
        )
    })?;
    caps.set_network_mode_mut(NetworkMode::ProxyOnly {
        port,
        bind_ports: Vec::new(),
    });
    Ok(())
}

fn policy_uses_proxy_route(state: &ToolSandboxState, policy: &CommandSandboxConfig) -> bool {
    let uses_proxy_credential = super::policy_credential_names(policy).iter().any(|handle| {
        matches!(
            state.credential_handles.get(*handle),
            Some(ResolvedCredential::Proxy { .. })
        )
    });
    let uses_proxy_domain = policy
        .network
        .as_ref()
        .is_some_and(|network| !network.allow_domain.is_empty());
    uses_proxy_credential || uses_proxy_domain
}

fn add_proxy_trust_bundle_caps(
    caps: &mut CapabilitySet,
    state: &ToolSandboxState,
    policy: &CommandSandboxConfig,
) -> Result<()> {
    if !policy_uses_proxy_route(state, policy) {
        return Ok(());
    }
    for path in &state.proxy_trust_bundle_paths {
        caps.add_fs(FsCapability::new_file(path, AccessMode::Read)?);
    }
    Ok(())
}

fn add_policy_credentials(
    caps: &mut CapabilitySet,
    state: &ToolSandboxState,
    policy: &CommandSandboxConfig,
) -> Result<()> {
    for handle in super::policy_credential_names(policy) {
        match state.credential_handles.get(handle) {
            Some(ResolvedCredential::LocalSocket {
                path: Some(socket_path),
                ..
            }) => {
                caps.add_unix_socket(UnixSocketCapability::new_file(
                    socket_path,
                    UnixSocketMode::Connect,
                )?);
                caps.add_fs(FsCapability::new_file(socket_path, AccessMode::Read)?);
            }
            Some(ResolvedCredential::LocalSocket {
                path: None,
                unavailable_reason,
                ..
            }) => {
                let reason = unavailable_reason
                    .as_deref()
                    .unwrap_or("local socket unavailable");
                return Err(NonoError::ConfigParse(format!(
                    "tool-sandbox credential '{handle}' is unavailable: {reason}"
                )));
            }
            Some(ResolvedCredential::RawFile { path }) => {
                caps.add_fs(FsCapability::new_file(path, AccessMode::Read)?);
            }
            Some(ResolvedCredential::Proxy { .. }) => {}
            Some(ResolvedCredential::Ambient { .. }) => {}
            None => {
                return Err(NonoError::SandboxInit(format!(
                    "tool-sandbox credential handle '{handle}' was not resolved"
                )));
            }
        }
    }
    Ok(())
}

fn add_runtime_baseline(
    caps: &mut CapabilitySet,
    baseline: &BaselineCache,
    binary: &Path,
) -> Result<()> {
    let start_baseline = std::time::Instant::now();
    let closure = baseline.closures.get(binary).ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "tool-sandbox runtime baseline cache missing entry for {}",
            binary.display()
        ))
    })?;
    for file in closure {
        caps.add_fs(FsCapability::new_file(file, AccessMode::Read)?);
    }
    for (path, access) in &baseline.system_files {
        caps.add_fs(FsCapability::new_file(path, *access)?);
    }
    tool_sandbox_profile_log!(
        "add_runtime_baseline({}): {:?} ({} closure files)",
        binary.display(),
        start_baseline.elapsed(),
        closure.len()
    );
    Ok(())
}

fn build_baseline_cache<'a>(
    plan: &ResolvedToolSandboxPlan,
    shims: impl IntoIterator<Item = &'a ShimIdentity>,
    shim_source: &Path,
) -> Result<BaselineCache> {
    let system_files = compute_system_baseline_files()?;
    let mut closures: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();

    // Command binaries and exec intercept helpers are launched the same way, so
    // cache the ELF dependency closure for both (plus their script interpreters).
    let cacheable = plan
        .resolved
        .commands
        .values()
        .chain(plan.exec_helpers.values());
    for binary in cacheable {
        if !closures.contains_key(&binary.canonical_path) {
            closures.insert(
                binary.canonical_path.clone(),
                elf_dependency_closure(&binary.canonical_path)?,
            );
        }
        if let Some(interpreter) = binary.shape.interpreter.as_ref() {
            let canonical =
                interpreter
                    .canonicalize()
                    .map_err(|source| NonoError::PathCanonicalization {
                        path: interpreter.clone(),
                        source,
                    })?;
            if !closures.contains_key(&canonical) {
                closures.insert(canonical.clone(), elf_dependency_closure(&canonical)?);
            }
            // Cache the re-exec'd `<interp>`'s closure so the exec allowlist can
            // grant it.
            if let Some(real_interp) =
                env_shebang_target_interpreter(interpreter, &binary.shape.interpreter_args)
                && let Ok(canonical_real) = real_interp.canonicalize()
                && !closures.contains_key(&canonical_real)
            {
                closures.insert(
                    canonical_real.clone(),
                    elf_dependency_closure(&canonical_real)?,
                );
            }
        }
    }

    let shim_closure = elf_dependency_closure(shim_source)?;
    for shim in shims {
        closures.insert(shim.path.clone(), shim_closure.clone());
    }

    Ok(BaselineCache {
        closures,
        system_files,
    })
}

fn compute_system_baseline_files() -> Result<Vec<(PathBuf, AccessMode)>> {
    let mut files = Vec::new();
    for file in [
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/passwd",
        "/etc/group",
    ] {
        let path = Path::new(file);
        if path.exists() && path.is_file() {
            files.push((path.to_path_buf(), AccessMode::Read));
        }
    }
    for (file, access) in [
        ("/dev/null", AccessMode::ReadWrite),
        ("/dev/zero", AccessMode::Read),
        ("/dev/urandom", AccessMode::Read),
    ] {
        let path = Path::new(file);
        if path.exists() {
            files.push((path.to_path_buf(), access));
        }
    }
    if Path::new("/etc/ld.so.conf.d").is_dir() {
        for entry in fs::read_dir("/etc/ld.so.conf.d").map_err(|source| NonoError::ConfigRead {
            path: PathBuf::from("/etc/ld.so.conf.d"),
            source,
        })? {
            let entry = entry.map_err(|source| NonoError::ConfigRead {
                path: PathBuf::from("/etc/ld.so.conf.d"),
                source,
            })?;
            let path = entry.path();
            if path.is_file() {
                files.push((path, AccessMode::Read));
            }
        }
    }
    Ok(files)
}

fn filter_child_env(
    state: &ToolSandboxState,
    request: &ToolSandboxShimRequest,
    policy: &CommandSandboxConfig,
) -> Result<Vec<Vec<u8>>> {
    let allowed_patterns: Vec<String> = policy
        .environment
        .as_ref()
        .and_then(|env| env.allow_vars.clone())
        .unwrap_or_else(default_env_allow_patterns);

    let broker = state.token_broker.lock().map_err(|_| {
        NonoError::SandboxInit("tool-sandbox token broker lock poisoned".to_string())
    })?;

    let mut env = Vec::new();
    let mut has_path = false;
    for entry in &request.env {
        let Some((key, _value)) = split_env_entry(entry) else {
            continue;
        };
        let key_str = std::str::from_utf8(key).map_err(|_| {
            NonoError::SandboxInit("tool-sandbox env var name is not UTF-8".to_string())
        })?;
        if key_str.starts_with("NONO_") {
            continue;
        }
        // Drop linker/shell/interpreter injection vectors regardless of policy
        // allow_vars. A broad pattern like "*" or "LD_*" must NOT let
        // LD_PRELOAD / PYTHONPATH / NODE_OPTIONS / BASH_ENV / etc. through to
        // a credential-bearing tool-sandbox child.
        if crate::exec_strategy::env_sanitization::is_dangerous_env_var(key_str) {
            continue;
        }
        if key_str == "PATH" {
            has_path = true;
        }
        if crate::exec_strategy::is_env_var_allowed(key_str, &allowed_patterns) {
            // Resolve broker nonces to real values immediately before execve.
            let consumer = format!("cmd.{}", request.command);
            let resolved = broker.resolve_env_entry(entry, &consumer);
            env.push(resolved.unwrap_or_else(|| entry.clone()));
        }
    }
    drop(broker);
    if !has_path {
        env.push(format!("PATH={}", state.session_path).into_bytes());
    } else {
        env.retain(|entry| !entry.starts_with(b"PATH="));
        env.push(format!("PATH={}", state.session_path).into_bytes());
    }
    inject_chaining_control_env(&mut env, &state.socket_path, &state.shim_dir);
    inject_url_open_env(
        &mut env,
        policy,
        state.url_socket_path.as_deref(),
        state.url_open_shim.as_ref().map(|shim| shim.path.as_path()),
    );
    apply_environment_set_vars(&mut env, policy)?;
    for handle in super::policy_credential_names(policy) {
        match state.credential_handles.get(handle) {
            Some(ResolvedCredential::LocalSocket {
                path: Some(socket_path),
                env_var,
                ..
            }) => {
                if let Some(env_var) = env_var {
                    let prefix = format!("{env_var}=").into_bytes();
                    env.retain(|entry| !entry.starts_with(&prefix));
                    env.push(format!("{env_var}={}", socket_path.display()).into_bytes());
                }
            }
            Some(ResolvedCredential::LocalSocket {
                path: None,
                unavailable_reason,
                ..
            }) => {
                let reason = unavailable_reason
                    .as_deref()
                    .unwrap_or("local socket unavailable");
                return Err(NonoError::ConfigParse(format!(
                    "tool-sandbox credential '{handle}' is unavailable: {reason}"
                )));
            }
            Some(ResolvedCredential::RawFile { .. }) => {}
            Some(ResolvedCredential::Proxy { env_vars }) => {
                for (name, value) in env_vars {
                    let prefix = format!("{name}=").into_bytes();
                    env.retain(|entry| !entry.starts_with(&prefix));
                    env.push(format!("{name}={value}").into_bytes());
                }
            }
            Some(ResolvedCredential::Ambient { .. }) => {}
            None => {
                return Err(NonoError::SandboxInit(format!(
                    "tool-sandbox credential handle '{handle}' was not resolved"
                )));
            }
        }
    }
    Ok(env)
}

fn launch_child(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    spec: ToolSandboxChildLaunchSpec,
    stdio: StdioFds,
) -> Result<ChildLaunchResult> {
    let start_total = std::time::Instant::now();
    let start_write = std::time::Instant::now();
    let spec_path = write_launch_spec(&state.runtime_dir, &spec)?;
    tool_sandbox_profile_log!("launch_child:write_spec: {:?}", start_write.elapsed());
    let start_spawn_wait = std::time::Instant::now();
    let result = match spec.stdio_mode.as_str() {
        "pty" => launch_child_with_pty(state, command_name, launch_caller, &spec_path, stdio),
        "direct_fds" => launch_child_with_direct_fds(
            state,
            command_name,
            launch_caller,
            &spec_path,
            &spec,
            stdio,
        ),
        other => Err(NonoError::ConfigParse(format!(
            "invalid tool-sandbox stdio mode '{other}'"
        ))),
    };
    tool_sandbox_profile_log!(
        "launch_child:spawn_and_wait: {:?}",
        start_spawn_wait.elapsed()
    );
    remove_launch_spec(&spec_path);
    tool_sandbox_profile_log!("launch_child:total: {:?}", start_total.elapsed());
    result
}

fn launch_child_with_direct_fds(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    spec_path: &Path,
    spec: &ToolSandboxChildLaunchSpec,
    stdio: StdioFds,
) -> Result<ChildLaunchResult> {
    if spec.stdio_limits.is_some() {
        return launch_child_with_brokered_stdio(
            state,
            command_name,
            launch_caller,
            spec_path,
            spec,
            stdio,
        );
    }
    let mut command = prepare_launcher_command(spec_path)?;
    command
        .stdin(Stdio::from(File::from(stdio.stdin)))
        .stdout(Stdio::from(File::from(stdio.stdout)))
        .stderr(Stdio::from(File::from(stdio.stderr)));
    let mut child = command.spawn().map_err(NonoError::CommandExecution)?;
    drop(command);
    let exit_code = wait_for_tracked_child(state, command_name, launch_caller, &mut child)?;
    Ok(ChildLaunchResult {
        exit_code,
        stdio: None,
        blocked_reason: None,
    })
}

fn launch_child_with_brokered_stdio(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    spec_path: &Path,
    spec: &ToolSandboxChildLaunchSpec,
    stdio: StdioFds,
) -> Result<ChildLaunchResult> {
    let limits = spec.stdio_limits.clone().ok_or_else(|| {
        NonoError::SandboxInit("tool-sandbox brokered stdio missing limits".to_string())
    })?;
    let (stdout_read, stdout_write) = create_pipe("stdout")?;
    let (stderr_read, stderr_write) = create_pipe("stderr")?;
    let StdioFds {
        stdin,
        stdout,
        stderr,
    } = stdio;

    let mut command = prepare_launcher_command(spec_path)?;
    command
        .stdin(Stdio::from(File::from(stdin)))
        .stdout(Stdio::from(File::from(stdout_write)))
        .stderr(Stdio::from(File::from(stderr_write)));

    let mut child = command.spawn().map_err(NonoError::CommandExecution)?;
    drop(command);
    track_spawned_child(state, command_name, launch_caller, &mut child)?;

    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_exceeded = exceeded.clone();
    let stdout_limit = limits.stdout;
    let stdout_thread = std::thread::spawn(move || {
        relay_limited_output("stdout", stdout_read, stdout, stdout_limit, stdout_exceeded)
    });
    let stderr_exceeded = exceeded.clone();
    let stderr_limit = limits.stderr;
    let stderr_thread = std::thread::spawn(move || {
        relay_limited_output("stderr", stderr_read, stderr, stderr_limit, stderr_exceeded)
    });

    let status = loop {
        if exceeded.load(Ordering::SeqCst) {
            let _ = child.kill();
            break child.wait().map_err(NonoError::CommandExecution)?;
        }
        if let Some(status) = child.try_wait().map_err(NonoError::CommandExecution)? {
            break status;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    untrack_child(state, child.id())?;

    let stdout_result = join_relay_thread(stdout_thread, "stdout")?;
    let stderr_result = join_relay_thread(stderr_thread, "stderr")?;
    let stdio_audit = Some(CommandPolicyStdioAudit {
        stdout: Some(stdout_result.audit()),
        stderr: Some(stderr_result.audit()),
    });
    let blocked_reason = if stdout_result.should_deny() || stderr_result.should_deny() {
        Some(format!(
            "stdio limit exceeded: stdout={} bytes, stderr={} bytes",
            stdout_result.total_bytes, stderr_result.total_bytes
        ))
    } else {
        None
    };

    Ok(ChildLaunchResult {
        exit_code: exit_status_code(status),
        stdio: stdio_audit,
        blocked_reason,
    })
}

struct OutputRelayResult {
    total_bytes: u64,
    forwarded_bytes: u64,
    max_bytes: Option<u64>,
    limit_exceeded: bool,
    on_limit: Option<StdioLimitActionSpec>,
}

impl OutputRelayResult {
    fn audit(&self) -> CommandPolicyStdioStreamAudit {
        CommandPolicyStdioStreamAudit {
            total_bytes: self.total_bytes,
            forwarded_bytes: self.forwarded_bytes,
            max_bytes: self.max_bytes,
            limit_exceeded: self.limit_exceeded,
            on_limit: self.on_limit.map(stdio_limit_action_name),
        }
    }

    fn should_deny(&self) -> bool {
        self.limit_exceeded
            && self
                .on_limit
                .map(|action| action != StdioLimitActionSpec::Truncate)
                .unwrap_or(false)
    }
}

fn create_pipe(stream_name: &str) -> Result<(OwnedFd, OwnedFd)> {
    let mut pipe_fds = [-1i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox brokered stdio {stream_name} pipe() failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: pipe() returned fresh file descriptors.
    let read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
    // SAFETY: pipe() returned fresh file descriptors.
    let write = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
    Ok((read, write))
}

fn relay_limited_output(
    stream_name: &'static str,
    source: OwnedFd,
    target: OwnedFd,
    limit: Option<StdioStreamLimitSpec>,
    exceeded: Arc<AtomicBool>,
) -> Result<OutputRelayResult> {
    let mut source = File::from(source);
    let mut target = File::from(target);
    let mut buf = [0_u8; 8192];
    let mut total_bytes = 0_u64;
    let mut forwarded_bytes = 0_u64;
    let mut limit_exceeded = false;

    loop {
        let n = source.read(&mut buf).map_err(|err| {
            NonoError::SandboxInit(format!(
                "tool-sandbox brokered stdio {stream_name} read failed: {err}"
            ))
        })?;
        if n == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(n as u64);
        let allowed = limit
            .map(|limit| limit.max_bytes.saturating_sub(forwarded_bytes))
            .unwrap_or(n as u64);
        let to_forward = usize::try_from(allowed.min(n as u64)).unwrap_or(n);
        if to_forward > 0 {
            target.write_all(&buf[..to_forward]).map_err(|err| {
                NonoError::SandboxInit(format!(
                    "tool-sandbox brokered stdio {stream_name} write failed: {err}"
                ))
            })?;
            forwarded_bytes = forwarded_bytes.saturating_add(to_forward as u64);
        }
        if let Some(limit) = limit
            && total_bytes > limit.max_bytes
        {
            limit_exceeded = true;
            if limit.on_limit != StdioLimitActionSpec::Truncate {
                exceeded.store(true, Ordering::SeqCst);
            }
        }
    }

    Ok(OutputRelayResult {
        total_bytes,
        forwarded_bytes,
        max_bytes: limit.map(|limit| limit.max_bytes),
        limit_exceeded,
        on_limit: limit.map(|limit| limit.on_limit),
    })
}

fn stdio_limit_action_name(action: StdioLimitActionSpec) -> String {
    match action {
        StdioLimitActionSpec::Truncate => "truncate",
        StdioLimitActionSpec::Terminate => "terminate",
        StdioLimitActionSpec::Deny => "deny",
    }
    .to_string()
}

fn join_relay_thread(
    handle: std::thread::JoinHandle<Result<OutputRelayResult>>,
    stream_name: &str,
) -> Result<OutputRelayResult> {
    handle.join().map_err(|_| {
        NonoError::SandboxInit(format!(
            "tool-sandbox brokered stdio {stream_name} relay panicked"
        ))
    })?
}

fn issue_existing_ambient_credential_nonce(
    state: &ToolSandboxState,
    credential: &str,
    grants: crate::tool_sandbox::token_broker::GrantSet,
) -> Result<Option<String>> {
    {
        let mut broker = state.token_broker.lock().map_err(|_| {
            NonoError::SandboxInit("tool-sandbox token broker lock poisoned".to_string())
        })?;
        if let Some(nonce) = broker.issue_named(credential) {
            return Ok(Some(nonce));
        }
    }

    let Some(value) = load_ambient_credential_source(state, credential)? else {
        return Ok(None);
    };
    let mut broker = state.token_broker.lock().map_err(|_| {
        NonoError::SandboxInit("tool-sandbox token broker lock poisoned".to_string())
    })?;
    Ok(Some(broker.store_named(
        credential.to_string(),
        value,
        grants,
    )))
}

fn load_ambient_credential_source(
    state: &ToolSandboxState,
    credential: &str,
) -> Result<Option<Vec<u8>>> {
    match state.credential_handles.get(credential) {
        Some(ResolvedCredential::Ambient {
            source: Some(source),
        }) => Ok(Some(super::load_supervisor_credential_source(source)?)),
        Some(ResolvedCredential::Ambient { source: None }) => Ok(None),
        Some(_) => Err(NonoError::SandboxInit(format!(
            "tool-sandbox credential '{credential}' is not ambient"
        ))),
        None => Err(NonoError::SandboxInit(format!(
            "tool-sandbox credential handle '{credential}' was not resolved"
        ))),
    }
}

fn normalize_captured_credential(mut output: Vec<u8>) -> Vec<u8> {
    if output.ends_with(b"\n") {
        output.pop();
        if output.ends_with(b"\r") {
            output.pop();
        }
    }
    output
}

fn nonce_stdout(nonce: String) -> Vec<u8> {
    let mut output = nonce.into_bytes();
    output.push(b'\n');
    output
}

fn launch_child_with_capture(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    spec: ToolSandboxChildLaunchSpec,
    stdio: StdioFds,
) -> Result<(i32, Vec<u8>)> {
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    let mut pipe_fds = [-1i32; 2]; // [read_end, write_end]
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox Capture: pipe() failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: pipe() returned fresh file descriptors above.
    let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
    let pipe_write = unsafe { File::from_raw_fd(pipe_fds[1]) };

    let spec_path = write_launch_spec(&state.runtime_dir, &spec)?;
    let mut command = prepare_launcher_command(&spec_path)?;
    command
        .stdin(Stdio::from(File::from(stdio.stdin)))
        .stdout(Stdio::from(pipe_write))
        .stderr(Stdio::from(File::from(stdio.stderr)));
    // stdio.stdout is not used for capture; drop it so the fd is closed.
    drop(stdio.stdout);

    let mut child = command.spawn().map_err(NonoError::CommandExecution)?;
    drop(command);
    // The write end was moved into the child's Stdio and is now closed in
    // the parent, so reading from pipe_read will yield EOF when the child
    // closes its stdout (on exit or explicit close).

    if let Err(err) = track_spawned_child(state, command_name, launch_caller, &mut child) {
        remove_launch_spec(&spec_path);
        return Err(err);
    }

    let mut captured = Vec::new();
    let mut pipe_reader =
        std::io::BufReader::new(File::from(pipe_read)).take((MAX_CAPTURE_STDOUT as u64) + 1);
    let read_result = pipe_reader.read_to_end(&mut captured);
    // Drop the reader (closes the read end) before waiting.
    drop(pipe_reader);

    let status = child.wait().map_err(NonoError::CommandExecution);
    untrack_child(state, child.id())?;
    remove_launch_spec(&spec_path);

    read_result.map_err(|e| {
        NonoError::SandboxInit(format!("tool-sandbox Capture: pipe read failed: {e}"))
    })?;
    if captured.len() > MAX_CAPTURE_STDOUT {
        return Err(NonoError::SandboxInit(
            "tool-sandbox Capture: output exceeds limit".to_string(),
        ));
    }

    Ok((exit_status_code(status?), captured))
}

fn launch_child_with_pty(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    spec_path: &Path,
    stdio: StdioFds,
) -> Result<ChildLaunchResult> {
    let pty = crate::pty_proxy::open_pty()?;
    let stdin_slave = nix::unistd::dup(&pty.slave).map_err(|err| {
        NonoError::SandboxInit(format!("tool-sandbox PTY dup stdin failed: {err}"))
    })?;
    let stdout_slave = nix::unistd::dup(&pty.slave).map_err(|err| {
        NonoError::SandboxInit(format!("tool-sandbox PTY dup stdout failed: {err}"))
    })?;
    let stderr_slave = nix::unistd::dup(&pty.slave).map_err(|err| {
        NonoError::SandboxInit(format!("tool-sandbox PTY dup stderr failed: {err}"))
    })?;
    let mut command = prepare_launcher_command(spec_path)?;
    command
        .stdin(Stdio::from(File::from(stdin_slave)))
        .stdout(Stdio::from(File::from(stdout_slave)))
        .stderr(Stdio::from(File::from(stderr_slave)));
    let mut child = command.spawn().map_err(NonoError::CommandExecution)?;
    drop(command);
    drop(pty.slave);
    track_spawned_child(state, command_name, launch_caller, &mut child)?;
    let status = relay_pty_and_wait(&mut child, pty.master, stdio);
    untrack_child(state, child.id())?;
    Ok(ChildLaunchResult {
        exit_code: status?,
        stdio: None,
        blocked_reason: None,
    })
}

fn wait_for_tracked_child(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    child: &mut Child,
) -> Result<i32> {
    track_spawned_child(state, command_name, launch_caller, child)?;
    let status = child.wait().map_err(NonoError::CommandExecution);
    untrack_child(state, child.id())?;
    status.map(exit_status_code)
}

fn track_spawned_child(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    child: &mut Child,
) -> Result<()> {
    if let Err(err) = track_child(state, child.id(), command_name, launch_caller) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err);
    }
    Ok(())
}

fn track_child(
    state: &ToolSandboxState,
    child_pid: u32,
    command_name: &str,
    launch_caller: &Caller,
) -> Result<()> {
    let pidfd = open_pidfd(child_pid)?;
    let mut map = state
        .active_children
        .lock()
        .map_err(|_| NonoError::SandboxInit("tool-sandbox pid map lock poisoned".to_string()))?;
    map.insert(
        child_pid,
        ActiveChild {
            command: command_name.to_string(),
            pidfd,
            launch_caller: launch_caller.clone(),
        },
    );
    Ok(())
}

fn untrack_child(state: &ToolSandboxState, child_pid: u32) -> Result<()> {
    let mut map = state
        .active_children
        .lock()
        .map_err(|_| NonoError::SandboxInit("tool-sandbox pid map lock poisoned".to_string()))?;
    map.remove(&child_pid);
    Ok(())
}

fn open_pidfd(pid: u32) -> Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd >= 0 {
        // SAFETY: pidfd_open returned a fresh owned file descriptor on success.
        return Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) });
    }
    let err = std::io::Error::last_os_error();
    let reason = match err.raw_os_error() {
        Some(code) if code == libc::ENOSYS => {
            "kernel does not support pidfd_open (requires Linux 5.3+)"
        }
        Some(code) if code == libc::EINVAL => "pidfd_open rejected flags",
        _ => "pidfd_open failed",
    };
    Err(NonoError::SandboxInit(format!(
        "tool-sandbox child liveness requires pidfd_open for pid {pid} to avoid PID reuse races; {reason}: {err}"
    )))
}

fn relay_pty_and_wait(child: &mut Child, master: OwnedFd, stdio: StdioFds) -> Result<i32> {
    let master_fd = master.as_raw_fd();
    let stdin_fd = stdio.stdin.as_raw_fd();
    let stdout_fd = stdio.stdout.as_raw_fd();
    let _raw_guard = TerminalRawGuard::enter(stdin_fd);
    set_nonblocking_fd(master_fd)?;
    let mut stdin_active = true;
    let mut master_active = true;
    let mut last_winsize = None;

    loop {
        apply_terminal_winsize(stdin_fd, master_fd, &mut last_winsize);
        let mut pfds = [
            libc::pollfd {
                fd: if stdin_active { stdin_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if master_active { master_fd } else { -1 },
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
        ];
        let poll_status = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, 50) };
        if poll_status < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(NonoError::SandboxInit(format!(
                    "tool-sandbox PTY poll failed: {err}"
                )));
            }
        } else if poll_status > 0 {
            if stdin_active && pfds[0].revents & libc::POLLIN != 0 {
                match read_fd(stdin_fd)? {
                    Some(bytes) if bytes.is_empty() => stdin_active = false,
                    Some(bytes) => write_all_fd(master_fd, &bytes)?,
                    None => {}
                }
            }
            if master_active && pfds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                match read_fd(master_fd)? {
                    Some(bytes) if bytes.is_empty() => master_active = false,
                    Some(bytes) => write_all_fd(stdout_fd, &bytes)?,
                    None => {}
                }
            }
        }

        if let Some(status) = child.try_wait().map_err(NonoError::CommandExecution)? {
            drain_pty(master_fd, stdout_fd)?;
            return Ok(exit_status_code(status));
        }
    }
}

struct TerminalRawGuard {
    fd: i32,
    original: libc::termios,
    original_flags: i32,
    active: bool,
}

impl TerminalRawGuard {
    fn enter(fd: i32) -> Option<Self> {
        if !is_tty(fd) {
            return None;
        }
        let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
            return None;
        }
        let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if original_flags < 0 {
            return None;
        }
        let original = termios;
        unsafe {
            libc::cfmakeraw(&mut termios);
        }
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
            return None;
        }
        Some(Self {
            fd,
            original,
            original_flags,
            active: true,
        })
    }
}

impl Drop for TerminalRawGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
                libc::fcntl(self.fd, libc::F_SETFL, self.original_flags);
            }
        }
    }
}

fn drain_pty(master_fd: i32, stdout_fd: i32) -> Result<()> {
    for _ in 0..16 {
        match read_fd(master_fd)? {
            Some(bytes) if bytes.is_empty() => break,
            Some(bytes) => write_all_fd(stdout_fd, &bytes)?,
            None => break,
        }
    }
    Ok(())
}

fn read_fd(fd: i32) -> Result<Option<Vec<u8>>> {
    let mut buf = [0_u8; 8192];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            return Ok(Some(buf[..n as usize].to_vec()));
        }
        if n == 0 {
            return Ok(Some(Vec::new()));
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => return Ok(None),
            _ if err.raw_os_error() == Some(libc::EIO) => return Ok(Some(Vec::new())),
            _ => {
                return Err(NonoError::SandboxInit(format!(
                    "tool-sandbox PTY fd read failed: {err}"
                )));
            }
        }
    }
}

fn write_all_fd(fd: i32, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox PTY fd write failed: {err}"
        )));
    }
    Ok(())
}

fn set_nonblocking_fd(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox fcntl(F_GETFL) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox fcntl(F_SETFL) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn apply_terminal_winsize(stdin_fd: i32, pty_master_fd: i32, last: &mut Option<(u16, u16)>) {
    let mut ws = unsafe { std::mem::zeroed::<libc::winsize>() };
    if unsafe { libc::ioctl(stdin_fd, libc::TIOCGWINSZ, &mut ws) } != 0 {
        return;
    }
    if ws.ws_row == 0 || ws.ws_col == 0 {
        return;
    }
    let current = (ws.ws_row, ws.ws_col);
    if *last == Some(current) {
        return;
    }
    unsafe {
        libc::ioctl(pty_master_fd, libc::TIOCSWINSZ, &ws);
    }
    *last = Some(current);
}

fn verify_binary_identity(binary: &ResolvedCommandBinary) -> Result<()> {
    let metadata =
        fs::metadata(&binary.canonical_path).map_err(|source| NonoError::ConfigRead {
            path: binary.canonical_path.clone(),
            source,
        })?;
    if metadata.dev() != binary.dev || metadata.ino() != binary.ino {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox command binary changed inode before launch: {}",
            binary.canonical_path.display()
        )));
    }
    if metadata.size() != binary.size || mtime_nanos(&metadata) != binary.mtime_nanos {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox command binary changed metadata before launch: {}",
            binary.canonical_path.display()
        )));
    }
    Ok(())
}

fn mtime_nanos(metadata: &fs::Metadata) -> i128 {
    let secs = metadata.mtime() as i128;
    let nanos = metadata.mtime_nsec() as i128;
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

fn file_id(metadata: &fs::Metadata) -> FileId {
    FileId {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

/// Core gate for `validate_initial_exec` after the caller has resolved the
/// canonical path to a `FileId`. Extracted so the ordering invariant (bypass
/// before policy-command rejection) can be tested without touching the
/// filesystem.
fn check_exec_gate(
    allowed_bypass_ids: &HashSet<FileId>,
    resolved_commands: &BTreeMap<String, ResolvedCommandBinary>,
    deny_only: &BTreeMap<String, ResolvedDenyOnlyCommand>,
    original_program: &str,
    _resolved_program: &Path,
    id: FileId,
) -> Option<NonoError> {
    if allowed_bypass_ids.contains(&id) {
        return None;
    }
    for (name, command) in resolved_commands {
        if command.dev == id.dev && command.ino == id.ino {
            return Some(NonoError::BlockedCommand {
                command: original_program.to_string(),
                reason: format!(
                    "tool-sandbox direct exec bypass denied for policy-controlled command '{name}'"
                ),
            });
        }
    }
    for (name, command) in deny_only {
        if command.id == id {
            return Some(NonoError::BlockedCommand {
                command: original_program.to_string(),
                reason: format!(
                    "tool-sandbox direct exec denied for legacy blocked command '{name}'"
                ),
            });
        }
    }
    None
}

fn is_tty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

fn selected_stdio_mode(request: &ToolSandboxShimRequest) -> &'static str {
    if request.stdio_tty.iter().all(|value| *value) {
        "pty"
    } else {
        "direct_fds"
    }
}

fn caps_to_spec(caps: &CapabilitySet) -> ChildCapsSpec {
    ChildCapsSpec {
        fs: caps
            .fs_capabilities()
            .iter()
            .map(|cap| FsGrantSpec {
                path: cap.resolved.as_os_str().as_bytes().to_vec(),
                original_path: (cap.original.is_absolute() && cap.original != cap.resolved)
                    .then(|| cap.original.as_os_str().as_bytes().to_vec()),
                access: cap.access.to_string(),
                is_file: cap.is_file,
            })
            .collect(),
        unix_sockets: caps
            .unix_socket_capabilities()
            .iter()
            .map(|cap| UnixSocketGrantSpec {
                path: cap.resolved.as_os_str().as_bytes().to_vec(),
                original_path: (cap.original.is_absolute() && cap.original != cap.resolved)
                    .then(|| cap.original.as_os_str().as_bytes().to_vec()),
                mode: cap.mode.to_string(),
                is_directory: cap.is_directory(),
            })
            .collect(),
        platform_rules: caps.platform_rules().to_vec(),
        network_blocked: caps.is_network_blocked(),
        proxy_port: match caps.network_mode() {
            NetworkMode::ProxyOnly { port, .. } => Some(*port),
            _ => None,
        },
        proxy_bind_ports: match caps.network_mode() {
            NetworkMode::ProxyOnly { bind_ports, .. } => bind_ports.clone(),
            _ => Vec::new(),
        },
        tcp_connect_ports: caps.tcp_connect_ports().to_vec(),
        tcp_bind_ports: caps.tcp_bind_ports().to_vec(),
    }
}

fn caps_from_spec(spec: &ChildCapsSpec) -> Result<CapabilitySet> {
    let mut caps = CapabilitySet::new();
    if let Some(port) = spec.proxy_port {
        caps.set_network_mode_mut(NetworkMode::ProxyOnly {
            port,
            bind_ports: spec.proxy_bind_ports.clone(),
        });
    } else if spec.network_blocked {
        caps.set_network_mode_mut(NetworkMode::Blocked);
    }
    for fs_grant in &spec.fs {
        caps.add_fs(fs_cap_from_spec(fs_grant)?);
    }
    for socket_grant in &spec.unix_sockets {
        caps.add_unix_socket(unix_socket_cap_from_spec(socket_grant)?);
    }
    for rule in &spec.platform_rules {
        caps.add_platform_rule(rule.clone())?;
    }
    for port in &spec.tcp_connect_ports {
        caps.add_tcp_connect_port(*port);
    }
    for port in &spec.tcp_bind_ports {
        caps.add_tcp_bind_port(*port);
    }
    Ok(caps)
}

fn fs_cap_from_spec(fs_grant: &FsGrantSpec) -> Result<FsCapability> {
    let access = parse_access(&fs_grant.access)?;
    let path = PathBuf::from(OsString::from_vec(fs_grant.path.clone()));
    let mut cap = if fs_grant.is_file {
        FsCapability::new_file(&path, access)?
    } else {
        FsCapability::new_dir(&path, access)?
    };
    if let Some(original) = &fs_grant.original_path {
        let original = PathBuf::from(OsString::from_vec(original.clone()));
        if !original.is_absolute() {
            return Err(NonoError::SandboxInit(format!(
                "tool-sandbox child filesystem grant original path {} is not absolute",
                original.display()
            )));
        }
        let original_resolved =
            original
                .canonicalize()
                .map_err(|source| NonoError::PathCanonicalization {
                    path: original.clone(),
                    source,
                })?;
        if original_resolved != cap.resolved {
            return Err(NonoError::SandboxInit(format!(
                "tool-sandbox child filesystem grant original path {} resolves to {}, expected {}",
                original.display(),
                original_resolved.display(),
                cap.resolved.display()
            )));
        }
        cap.original = original;
    }
    Ok(cap)
}

fn unix_socket_cap_from_spec(socket_grant: &UnixSocketGrantSpec) -> Result<UnixSocketCapability> {
    let mode = parse_socket_mode(&socket_grant.mode)?;
    let path = PathBuf::from(OsString::from_vec(socket_grant.path.clone()));
    let mut cap = if socket_grant.is_directory {
        UnixSocketCapability::new_dir(&path, mode)?
    } else {
        UnixSocketCapability::new_file(&path, mode)?
    };
    if let Some(original) = &socket_grant.original_path {
        let original = PathBuf::from(OsString::from_vec(original.clone()));
        if !original.is_absolute() {
            return Err(NonoError::SandboxInit(format!(
                "tool-sandbox child unix socket grant original path {} is not absolute",
                original.display()
            )));
        }
        let original_cap = if socket_grant.is_directory {
            UnixSocketCapability::new_dir(&original, mode)?
        } else {
            UnixSocketCapability::new_file(&original, mode)?
        };
        if original_cap.resolved != cap.resolved {
            return Err(NonoError::SandboxInit(format!(
                "tool-sandbox child unix socket grant original path {} resolves to {}, expected {}",
                original.display(),
                original_cap.resolved.display(),
                cap.resolved.display()
            )));
        }
        cap.original = original;
    }
    Ok(cap)
}

fn parse_access(value: &str) -> Result<AccessMode> {
    match value {
        "read" => Ok(AccessMode::Read),
        "write" => Ok(AccessMode::Write),
        "read+write" => Ok(AccessMode::ReadWrite),
        other => Err(NonoError::ConfigParse(format!(
            "invalid tool-sandbox access mode '{other}'"
        ))),
    }
}

fn parse_socket_mode(value: &str) -> Result<UnixSocketMode> {
    match value {
        "connect" => Ok(UnixSocketMode::Connect),
        "connect+bind" => Ok(UnixSocketMode::ConnectBind),
        other => Err(NonoError::ConfigParse(format!(
            "invalid tool-sandbox unix socket mode '{other}'"
        ))),
    }
}

fn guarded_remove_runtime_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || (metadata.permissions().mode() & 0o077) != 0
    {
        return Err(NonoError::SandboxInit(format!(
            "unsafe tool-sandbox runtime dir shape: {}",
            path.display()
        )));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if !file_name.starts_with("nono-tool-sandbox-") {
        return Err(NonoError::SandboxInit(format!(
            "refusing to clean non-tool-sandbox dir {}",
            path.display()
        )));
    }
    fs::remove_dir_all(path).map_err(|source| NonoError::ConfigWrite {
        path: path.to_path_buf(),
        source,
    })
}

thread_local! {
    /// Memoizes `canonicalize` during a single tool-sandbox prep pass.
    ///
    /// Shared-library resolution canonicalizes the same system paths (libc,
    /// ld-linux, libglib, …) inside *every* binary's dependency closure, and the
    /// closure is recomputed per command/interpreter/shim. Without this cache a
    /// dense NSS/glib dependency graph re-canonicalizes the same handful of libs
    /// tens of thousands of times — a readlink/statx storm that dominates Linux
    /// launch latency. Canonicalization is a pure function of the (read-only,
    /// during prep) filesystem, so caching is safe within a pass.
    static ELF_CANON_CACHE: RefCell<HashMap<PathBuf, PathBuf>> = RefCell::new(HashMap::new());
    /// Memoizes shared-library name resolution, keyed by `(soname, search_dirs)`
    /// — the only inputs that determine the result.
    static ELF_LIB_CACHE: RefCell<HashMap<(String, Vec<String>), PathBuf>> =
        RefCell::new(HashMap::new());
    /// Memoizes `parse_elf` (which reads the whole file) keyed by canonical path,
    /// so each shared object is read+parsed once per pass rather than once per
    /// dependency closure that references it.
    static ELF_PARSE_CACHE: RefCell<HashMap<PathBuf, ParsedElf>> = RefCell::new(HashMap::new());
    /// Memoizes file identity (dev+ino) keyed by canonical path, so the per-edge
    /// `statx` used for closure dedup runs once per file per pass.
    static ELF_FILEID_CACHE: RefCell<HashMap<PathBuf, FileId>> = RefCell::new(HashMap::new());
}

/// Clears the per-pass ELF-resolution memo caches. Called at the start of each
/// batch that computes dependency closures so a fresh pass (or a later run in
/// the same process, e.g. tests) never observes a stale resolution.
fn reset_elf_resolution_cache() {
    ELF_CANON_CACHE.with(|cache| cache.borrow_mut().clear());
    ELF_LIB_CACHE.with(|cache| cache.borrow_mut().clear());
    ELF_PARSE_CACHE.with(|cache| cache.borrow_mut().clear());
    ELF_FILEID_CACHE.with(|cache| cache.borrow_mut().clear());
}

/// Canonicalize `path`, memoized via [`ELF_CANON_CACHE`] for the current pass.
fn cached_canonicalize(path: &Path) -> Result<PathBuf> {
    if let Some(canonical) = ELF_CANON_CACHE.with(|cache| cache.borrow().get(path).cloned()) {
        return Ok(canonical);
    }
    let canonical = path
        .canonicalize()
        .map_err(|source| NonoError::PathCanonicalization {
            path: path.to_path_buf(),
            source,
        })?;
    ELF_CANON_CACHE.with(|cache| {
        cache
            .borrow_mut()
            .insert(path.to_path_buf(), canonical.clone());
    });
    Ok(canonical)
}

/// File identity (dev+ino) for `canonical`, memoized via [`ELF_FILEID_CACHE`].
fn cached_file_id(canonical: &Path) -> Result<FileId> {
    if let Some(id) = ELF_FILEID_CACHE.with(|cache| cache.borrow().get(canonical).copied()) {
        return Ok(id);
    }
    let metadata = fs::metadata(canonical).map_err(|source| NonoError::ConfigRead {
        path: canonical.to_path_buf(),
        source,
    })?;
    let id = file_id(&metadata);
    ELF_FILEID_CACHE.with(|cache| {
        cache.borrow_mut().insert(canonical.to_path_buf(), id);
    });
    Ok(id)
}

fn elf_dependency_closure(binary: &Path) -> Result<Vec<PathBuf>> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    resolve_elf_recursive(binary, &mut seen, &mut result)?;
    Ok(result)
}

fn resolve_elf_recursive(
    path: &Path,
    seen: &mut HashSet<FileId>,
    result: &mut Vec<PathBuf>,
) -> Result<()> {
    let canonical = cached_canonicalize(path)?;
    if !seen.insert(cached_file_id(&canonical)?) {
        return Ok(());
    }
    result.push(canonical.clone());
    let parsed = parse_elf_cached(&canonical)?;
    if let Some(interpreter) = parsed.interpreter {
        resolve_elf_recursive(&interpreter, seen, result)?;
    }
    for needed in parsed.needed {
        let dep = resolve_shared_library(&needed, &parsed.search_dirs, &canonical)?;
        resolve_elf_recursive(&dep, seen, result)?;
    }
    Ok(())
}

#[derive(Clone)]
struct ParsedElf {
    interpreter: Option<PathBuf>,
    needed: Vec<String>,
    search_dirs: Vec<String>,
}

/// `parse_elf`, memoized via [`ELF_PARSE_CACHE`] for the current pass. `canonical`
/// must already be canonicalized (the cache key is the canonical path).
fn parse_elf_cached(canonical: &Path) -> Result<ParsedElf> {
    if let Some(parsed) = ELF_PARSE_CACHE.with(|cache| cache.borrow().get(canonical).cloned()) {
        return Ok(parsed);
    }
    let parsed = parse_elf(canonical)?;
    ELF_PARSE_CACHE.with(|cache| {
        cache
            .borrow_mut()
            .insert(canonical.to_path_buf(), parsed.clone());
    });
    Ok(parsed)
}

#[derive(Clone, Copy)]
struct LoadSegment {
    vaddr: u64,
    offset: u64,
    filesz: u64,
}

fn parse_elf(path: &Path) -> Result<ParsedElf> {
    let data = fs::read(path).map_err(|source| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Ok(ParsedElf {
            interpreter: None,
            needed: Vec::new(),
            search_dirs: Vec::new(),
        });
    }
    if data[5] != 1 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox supports little-endian ELF only: {}",
            path.display()
        )));
    }
    match data[4] {
        1 => parse_elf32(path, &data),
        2 => parse_elf64(path, &data),
        _ => Err(NonoError::SandboxInit(format!(
            "unknown ELF class for {}",
            path.display()
        ))),
    }
}

fn parse_elf64(path: &Path, data: &[u8]) -> Result<ParsedElf> {
    let phoff = le_u64(data, 32)? as usize;
    let phentsize = le_u16(data, 54)? as usize;
    let phnum = le_u16(data, 56)? as usize;
    let mut interpreter = None;
    let mut dynamic = None;
    let mut loads = Vec::new();
    for idx in 0..phnum {
        let off = phoff.saturating_add(idx.saturating_mul(phentsize));
        let p_type = le_u32(data, off)?;
        let p_offset = le_u64(data, off + 8)?;
        let p_vaddr = le_u64(data, off + 16)?;
        let p_filesz = le_u64(data, off + 32)?;
        match p_type {
            1 => loads.push(LoadSegment {
                vaddr: p_vaddr,
                offset: p_offset,
                filesz: p_filesz,
            }),
            2 => dynamic = Some((p_offset as usize, p_filesz as usize)),
            3 => interpreter = Some(read_cstr_path(data, p_offset as usize, p_filesz as usize)?),
            _ => {}
        }
    }
    parse_dynamic(path, data, dynamic, &loads, interpreter, 16)
}

fn parse_elf32(path: &Path, data: &[u8]) -> Result<ParsedElf> {
    let phoff = le_u32(data, 28)? as usize;
    let phentsize = le_u16(data, 42)? as usize;
    let phnum = le_u16(data, 44)? as usize;
    let mut interpreter = None;
    let mut dynamic = None;
    let mut loads = Vec::new();
    for idx in 0..phnum {
        let off = phoff.saturating_add(idx.saturating_mul(phentsize));
        let p_type = le_u32(data, off)?;
        let p_offset = le_u32(data, off + 4)? as u64;
        let p_vaddr = le_u32(data, off + 8)? as u64;
        let p_filesz = le_u32(data, off + 16)? as u64;
        match p_type {
            1 => loads.push(LoadSegment {
                vaddr: p_vaddr,
                offset: p_offset,
                filesz: p_filesz,
            }),
            2 => dynamic = Some((p_offset as usize, p_filesz as usize)),
            3 => interpreter = Some(read_cstr_path(data, p_offset as usize, p_filesz as usize)?),
            _ => {}
        }
    }
    parse_dynamic(path, data, dynamic, &loads, interpreter, 8)
}

fn parse_dynamic(
    path: &Path,
    data: &[u8],
    dynamic: Option<(usize, usize)>,
    loads: &[LoadSegment],
    interpreter: Option<PathBuf>,
    entry_size: usize,
) -> Result<ParsedElf> {
    let Some((dyn_off, dyn_size)) = dynamic else {
        return Ok(ParsedElf {
            interpreter,
            needed: Vec::new(),
            search_dirs: Vec::new(),
        });
    };
    let mut needed_offsets = Vec::new();
    let mut rpath_offsets = Vec::new();
    let mut strtab = None;
    let mut strsz = None;
    let mut cursor = dyn_off;
    while cursor.saturating_add(entry_size) <= dyn_off.saturating_add(dyn_size) {
        let (tag, value) = if entry_size == 16 {
            (le_u64(data, cursor)? as i64, le_u64(data, cursor + 8)?)
        } else {
            (
                le_u32(data, cursor)? as i32 as i64,
                le_u32(data, cursor + 4)? as u64,
            )
        };
        match tag {
            0 => break,
            1 => needed_offsets.push(value as usize),
            5 => strtab = vaddr_to_offset(value, loads),
            10 => strsz = Some(value as usize),
            15 | 29 => rpath_offsets.push(value as usize),
            _ => {}
        }
        cursor = cursor.saturating_add(entry_size);
    }
    let strtab = strtab.ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "ELF dynamic string table missing for {}",
            path.display()
        ))
    })?;
    let strsz = strsz.unwrap_or(data.len().saturating_sub(strtab));
    let str_end = strtab.saturating_add(strsz).min(data.len());
    let strings = &data[strtab..str_end];
    let mut needed = Vec::new();
    for offset in needed_offsets {
        needed.push(read_cstr_string(strings, offset)?);
    }
    let mut search_dirs = Vec::new();
    for offset in rpath_offsets {
        let value = read_cstr_string(strings, offset)?;
        for entry in value.split(':') {
            if entry.is_empty() {
                continue;
            }
            let origin = path.parent().unwrap_or_else(|| Path::new("/"));
            let expanded = entry.replace("$ORIGIN", &origin.display().to_string());
            search_dirs.push(expanded);
        }
    }
    Ok(ParsedElf {
        interpreter,
        needed,
        search_dirs,
    })
}

fn resolve_shared_library(name: &str, search_dirs: &[String], binary: &Path) -> Result<PathBuf> {
    // The result depends only on (soname, search_dirs); memoize it so a library
    // referenced by many objects in the closure is searched + canonicalized once
    // rather than once per referencing edge.
    let cache_key = (name.to_string(), search_dirs.to_vec());
    if let Some(resolved) = ELF_LIB_CACHE.with(|cache| cache.borrow().get(&cache_key).cloned()) {
        return Ok(resolved);
    }
    let defaults = [
        "/lib",
        "/lib64",
        "/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/local/lib",
        "/usr/local/lib64",
    ];
    for dir in search_dirs
        .iter()
        .map(String::as_str)
        .chain(defaults.iter().copied())
    {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            let resolved = cached_canonicalize(&candidate)?;
            ELF_LIB_CACHE.with(|cache| {
                cache.borrow_mut().insert(cache_key, resolved.clone());
            });
            return Ok(resolved);
        }
    }
    Err(NonoError::SandboxInit(format!(
        "failed to resolve ELF dependency '{name}' for {}",
        binary.display()
    )))
}

fn vaddr_to_offset(vaddr: u64, loads: &[LoadSegment]) -> Option<usize> {
    loads.iter().find_map(|load| {
        let end = load.vaddr.checked_add(load.filesz)?;
        if vaddr >= load.vaddr && vaddr < end {
            Some(load.offset.saturating_add(vaddr.saturating_sub(load.vaddr)) as usize)
        } else {
            None
        }
    })
}

fn read_cstr_path(data: &[u8], offset: usize, max_len: usize) -> Result<PathBuf> {
    PathBuf::from(read_cstr_string(data, offset.min(data.len()))?)
        .canonicalize()
        .map_err(|source| NonoError::PathCanonicalization {
            path: PathBuf::from(
                String::from_utf8_lossy(
                    &data[offset..offset.saturating_add(max_len).min(data.len())],
                )
                .to_string(),
            ),
            source,
        })
}

fn read_cstr_string(data: &[u8], offset: usize) -> Result<String> {
    if offset >= data.len() {
        return Err(NonoError::SandboxInit(
            "ELF string offset out of range".to_string(),
        ));
    }
    let end = data[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|pos| offset + pos)
        .ok_or_else(|| NonoError::SandboxInit("unterminated ELF string".to_string()))?;
    String::from_utf8(data[offset..end].to_vec())
        .map_err(|err| NonoError::SandboxInit(format!("ELF string is not UTF-8: {err}")))
}

fn le_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| NonoError::SandboxInit("ELF read out of range".to_string()))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| NonoError::SandboxInit("ELF read out of range".to_string()))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| NonoError::SandboxInit("ELF read out of range".to_string()))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::command_policy::{
        CommandEnvironmentConfig, CommandPolicyConfig, CommandSandboxConfig, InterceptActionConfig,
        InterceptRuleConfig, ResolvedCommandBinaries, ResolvedCommandBinary,
        ResolvedExecutableKind, ResolvedExecutableShape,
    };
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    fn make_binary(dev: u64, ino: u64) -> ResolvedCommandBinary {
        ResolvedCommandBinary {
            name: "cmd".to_string(),
            canonical_path: PathBuf::from("/usr/bin/cmd"),
            dev,
            ino,
            size: 0,
            mtime_nanos: 0,
            sha256: String::new(),
            duplicate_paths: vec![],
            shape: ResolvedExecutableShape {
                kind: ResolvedExecutableKind::Elf,
                interpreter: None,
                interpreter_args: vec![],
            },
        }
    }

    fn make_deny_only(dev: u64, ino: u64) -> ResolvedDenyOnlyCommand {
        ResolvedDenyOnlyCommand {
            path: PathBuf::from("/usr/bin/cmd"),
            id: FileId { dev, ino },
        }
    }

    fn test_tempdir() -> Result<tempfile::TempDir> {
        tempfile::tempdir().map_err(|source| NonoError::ConfigWrite {
            path: PathBuf::from("/tmp"),
            source,
        })
    }

    fn create_dir(path: &Path) -> Result<()> {
        fs::create_dir(path).map_err(|source| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        })
    }

    #[test]
    fn resolve_exec_paths_includes_existing_and_skips_missing() -> Result<()> {
        let tmp = test_tempdir()?;
        let present = tmp.path().join("git-core");
        create_dir(&present)?;
        let missing = tmp.path().join("does-not-exist");

        let resolved = resolve_exec_paths(
            &[
                present.to_string_lossy().into_owned(),
                missing.to_string_lossy().into_owned(),
            ],
            tmp.path(),
            tmp.path(),
        )?;

        assert!(
            resolved.contains(&present),
            "existing exec_path must be included: {resolved:?}"
        );
        assert!(
            !resolved.iter().any(|p| p == &missing),
            "missing exec_path must be skipped, not fatal: {resolved:?}"
        );
        Ok(())
    }

    #[test]
    fn resolve_exec_paths_empty_yields_empty() -> Result<()> {
        let tmp = test_tempdir()?;
        assert!(resolve_exec_paths(&[], tmp.path(), tmp.path())?.is_empty());
        Ok(())
    }

    fn create_executable(path: &Path) -> Result<()> {
        File::create(path).map_err(|source| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source,
            }
        })
    }

    fn test_binary(name: &str, path: &Path) -> Result<ResolvedCommandBinary> {
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source,
            })?;
        let metadata = fs::metadata(&canonical).map_err(|source| NonoError::ConfigRead {
            path: canonical.clone(),
            source,
        })?;
        Ok(ResolvedCommandBinary {
            name: name.to_string(),
            canonical_path: canonical,
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime_nanos: mtime_nanos(&metadata),
            sha256: String::new(),
            duplicate_paths: vec![],
            shape: ResolvedExecutableShape {
                kind: ResolvedExecutableKind::Elf,
                interpreter: None,
                interpreter_args: vec![],
            },
        })
    }

    fn symlink_path(target: &Path, link: &Path) -> Result<()> {
        std::os::unix::fs::symlink(target, link).map_err(|source| NonoError::ConfigWrite {
            path: link.to_path_buf(),
            source,
        })
    }

    fn test_state_with_chaining_paths(
        runtime_dir: PathBuf,
        socket_path: PathBuf,
        shim_dir: PathBuf,
        shim: ShimIdentity,
    ) -> ToolSandboxState {
        ToolSandboxState {
            runtime_dir,
            socket_path,
            url_socket_path: None,
            shim_dir: shim_dir.clone(),
            url_open_shim: None,
            session_path: format!("{}:/usr/bin", shim_dir.display()),
            profile_display_name: None,
            redaction_policy: nono::ScrubPolicy::secure_default(),
            policy_root: PathBuf::from("/tmp"),
            outer_caps: CapabilitySet::new(),
            deny_paths: Vec::new(),
            plan: ResolvedToolSandboxPlan {
                config: CommandPoliciesConfig::default(),
                resolved: ResolvedCommandBinaries {
                    commands: BTreeMap::new(),
                    warnings: Vec::new(),
                },
                exec_helpers: BTreeMap::new(),
                executable_dirs: Vec::new(),
                deny_only: BTreeMap::new(),
                allowed_direct_bypasses: Vec::new(),
                allowed_direct_bypass_ids: HashSet::new(),
            },
            shims_by_command: BTreeMap::from([("git".to_string(), shim.clone())]),
            credential_handles: BTreeMap::new(),
            allowed_outer_exec_files: Vec::new(),
            landlock_abi: nono::DetectedAbi::new(landlock::ABI::V3),
            baseline_cache: BaselineCache {
                closures: BTreeMap::from([(shim.path, Vec::new())]),
                system_files: Vec::new(),
            },
            proxy_trust_bundle_paths: Vec::new(),
            active_children: Mutex::new(HashMap::new()),
            active_count: AtomicUsize::new(0),
            queued_requests: AtomicUsize::new(0),
            emitted_error_response: AtomicBool::new(false),
            token_broker: crate::tool_sandbox::token_broker::new_shared_broker(),
            approval_backends: nono_proxy::approval::ApprovalBackendRegistry::singleton(Arc::new(
                crate::terminal_approval::TerminalApproval,
            )),
        }
    }

    #[test]
    fn outer_exec_gate_rejects_partial_enforcement() {
        let result =
            ensure_outer_exec_gate_fully_enforced(landlock::RulesetStatus::PartiallyEnforced);
        assert!(matches!(result, Err(err) if err.to_string().contains("partially enforced")));
    }

    #[test]
    fn resolve_caller_prefers_active_command_for_different_invocation() -> Result<()> {
        let state = test_state_with_chaining_paths(
            PathBuf::from("/tmp/nono-tool-sandbox-test"),
            PathBuf::from("/tmp/nono-tool-sandbox-test/supervisor.sock"),
            PathBuf::from("/tmp/nono-tool-sandbox-test/shims"),
            ShimIdentity {
                path: PathBuf::from("/tmp/nono-tool-sandbox-test/shims/git"),
                id: FileId { dev: 1, ino: 1 },
            },
        );
        let pid = std::process::id();
        track_child(&state, pid, "git", &Caller::Session { pid })?;

        let caller = resolve_caller(pid, pid, &state, "ssh")?;

        assert!(matches!(caller, Caller::Command { command, .. } if command == "git"));
        Ok(())
    }

    #[test]
    fn resolve_caller_uses_launch_caller_for_self_invocation() -> Result<()> {
        let state = test_state_with_chaining_paths(
            PathBuf::from("/tmp/nono-tool-sandbox-test"),
            PathBuf::from("/tmp/nono-tool-sandbox-test/supervisor.sock"),
            PathBuf::from("/tmp/nono-tool-sandbox-test/shims"),
            ShimIdentity {
                path: PathBuf::from("/tmp/nono-tool-sandbox-test/shims/git"),
                id: FileId { dev: 1, ino: 1 },
            },
        );
        let pid = std::process::id();
        track_child(&state, pid, "git", &Caller::Session { pid })?;

        let caller = resolve_caller(pid, pid, &state, "git")?;

        assert!(matches!(caller, Caller::Session { .. }));
        Ok(())
    }

    #[test]
    fn resolve_caller_honors_explicit_self_edge() -> Result<()> {
        let mut state = test_state_with_chaining_paths(
            PathBuf::from("/tmp/nono-tool-sandbox-test"),
            PathBuf::from("/tmp/nono-tool-sandbox-test/supervisor.sock"),
            PathBuf::from("/tmp/nono-tool-sandbox-test/shims"),
            ShimIdentity {
                path: PathBuf::from("/tmp/nono-tool-sandbox-test/shims/git"),
                id: FileId { dev: 1, ino: 1 },
            },
        );
        state.plan.config.commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                can_use: vec!["git".to_string()],
                ..Default::default()
            },
        );
        let pid = std::process::id();
        track_child(&state, pid, "git", &Caller::Session { pid })?;

        let caller = resolve_caller(pid, pid, &state, "git")?;

        assert!(matches!(caller, Caller::Command { command, .. } if command == "git"));
        Ok(())
    }

    #[test]
    fn writable_policy_command_override_is_explicit_for_sandbox_writable_paths() -> Result<()> {
        let temp = test_tempdir()?;
        let bin_dir = temp.path().join("bin");
        create_dir(&bin_dir)?;
        let tool = bin_dir.join("tool");
        create_executable(&tool)?;

        let mut config = CommandPoliciesConfig::default();
        config.commands.insert(
            "tool".to_string(),
            CommandPolicyConfig {
                executable: Some(tool.to_string_lossy().into_owned()),
                ..Default::default()
            },
        );
        let mut resolved = ResolvedCommandBinaries {
            commands: BTreeMap::new(),
            warnings: Vec::new(),
        };
        resolved
            .commands
            .insert("tool".to_string(), test_binary("tool", &tool)?);

        let caps = CapabilitySet::new();
        validate_controlled_binary_immutability(&config, &resolved, &BTreeMap::new(), &caps)?;

        let mut file_write_caps = CapabilitySet::new();
        file_write_caps.add_fs(FsCapability::new_file(&tool, AccessMode::ReadWrite)?);
        let err = validate_controlled_binary_immutability(
            &config,
            &resolved,
            &BTreeMap::new(),
            &file_write_caps,
        )
        .err()
        .ok_or_else(|| {
            NonoError::SandboxInit("expected sandbox-writable executable rejection".to_string())
        })?;
        assert!(
            err.to_string()
                .contains("writable by the outer session capability set")
        );

        let mut parent_write_caps = CapabilitySet::new();
        parent_write_caps.add_fs(FsCapability::new_dir(&bin_dir, AccessMode::ReadWrite)?);
        let err = validate_controlled_binary_immutability(
            &config,
            &resolved,
            &BTreeMap::new(),
            &parent_write_caps,
        )
        .err()
        .ok_or_else(|| {
            NonoError::SandboxInit("expected sandbox-writable parent rejection".to_string())
        })?;
        assert!(
            err.to_string()
                .contains("replaceable through writable parent directory")
        );

        config.allow_writable_executables = true;
        validate_controlled_binary_immutability(
            &config,
            &resolved,
            &BTreeMap::new(),
            &parent_write_caps,
        )?;
        config.allow_writable_executables = false;

        let command = config
            .commands
            .get_mut("tool")
            .ok_or_else(|| NonoError::SandboxInit("missing test command policy".to_string()))?;
        command.allow_writable_executable = true;

        validate_controlled_binary_immutability(
            &config,
            &resolved,
            &BTreeMap::new(),
            &file_write_caps,
        )?;

        Ok(())
    }

    #[test]
    fn writable_exec_helper_override_is_explicit_for_sandbox_writable_paths() -> Result<()> {
        let temp = test_tempdir()?;
        let bin_dir = temp.path().join("bin");
        create_dir(&bin_dir)?;
        let helper = bin_dir.join("helper");
        create_executable(&helper)?;

        let mut config = CommandPoliciesConfig::default();
        config.commands.insert(
            "tool".to_string(),
            CommandPolicyConfig {
                intercept: vec![InterceptRuleConfig {
                    args: vec![],
                    action: InterceptActionConfig::Exec {
                        command: vec![helper.to_string_lossy().into_owned()],
                    },
                    sandbox: None,
                }],
                ..Default::default()
            },
        );

        let mut exec_helpers = BTreeMap::new();
        exec_helpers.insert(helper.clone(), test_binary("helper", &helper)?);

        let caps = CapabilitySet::new();
        validate_controlled_exec_helper_immutability(&config, &exec_helpers, &caps)?;

        let mut file_write_caps = CapabilitySet::new();
        file_write_caps.add_fs(FsCapability::new_file(&helper, AccessMode::ReadWrite)?);
        let err =
            validate_controlled_exec_helper_immutability(&config, &exec_helpers, &file_write_caps)
                .err()
                .ok_or_else(|| {
                    NonoError::SandboxInit("expected sandbox-writable helper rejection".to_string())
                })?;
        assert!(
            err.to_string()
                .contains("writable by the outer session capability set")
        );

        let mut parent_write_caps = CapabilitySet::new();
        parent_write_caps.add_fs(FsCapability::new_dir(&bin_dir, AccessMode::ReadWrite)?);
        let err = validate_controlled_exec_helper_immutability(
            &config,
            &exec_helpers,
            &parent_write_caps,
        )
        .err()
        .ok_or_else(|| {
            NonoError::SandboxInit("expected sandbox-writable parent rejection".to_string())
        })?;
        assert!(
            err.to_string()
                .contains("replaceable through writable parent directory")
        );

        config.allow_writable_executables = true;
        validate_controlled_exec_helper_immutability(&config, &exec_helpers, &parent_write_caps)?;
        config.allow_writable_executables = false;

        let command = config
            .commands
            .get_mut("tool")
            .ok_or_else(|| NonoError::SandboxInit("missing test command policy".to_string()))?;
        command.allow_writable_executable = true;

        validate_controlled_exec_helper_immutability(&config, &exec_helpers, &file_write_caps)?;

        Ok(())
    }

    // ── check_exec_gate: bypass ordering ──────────────────────────────────

    #[test]
    fn bypass_wins_over_policy_command_same_inode() {
        // The resolver ensures bypass IDs can equal policy command inodes.
        // After the fix, bypass is checked first so the exec is allowed.
        let id = FileId { dev: 1, ino: 42 };
        let mut bypass = HashSet::new();
        bypass.insert(id);
        let mut resolved = BTreeMap::new();
        resolved.insert("python".to_string(), make_binary(1, 42));
        let deny_only = BTreeMap::new();

        let result = check_exec_gate(
            &bypass,
            &resolved,
            &deny_only,
            "/usr/bin/python3",
            Path::new("/usr/bin/python3"),
            id,
        );
        assert!(result.is_none(), "bypass id must be allowed: {result:?}");
    }

    #[test]
    fn policy_command_without_bypass_is_blocked() {
        let id = FileId { dev: 1, ino: 99 };
        let bypass = HashSet::new();
        let mut resolved = BTreeMap::new();
        resolved.insert("node".to_string(), make_binary(1, 99));
        let deny_only = BTreeMap::new();

        let result = check_exec_gate(
            &bypass,
            &resolved,
            &deny_only,
            "/usr/bin/node",
            Path::new("/usr/bin/node"),
            id,
        );
        assert!(result.is_some(), "policy command must be blocked");
    }

    #[test]
    fn deny_only_command_is_blocked() {
        let id = FileId { dev: 2, ino: 77 };
        let bypass = HashSet::new();
        let resolved = BTreeMap::new();
        let mut deny_only = BTreeMap::new();
        deny_only.insert("bash".to_string(), make_deny_only(2, 77));

        let result = check_exec_gate(
            &bypass,
            &resolved,
            &deny_only,
            "/bin/bash",
            Path::new("/bin/bash"),
            id,
        );
        assert!(result.is_some(), "deny_only command must be blocked");
    }

    #[test]
    fn unknown_inode_is_allowed_as_non_controlled_executable() {
        let id = FileId { dev: 3, ino: 1 };
        let bypass = HashSet::new();
        let resolved = BTreeMap::new();
        let deny_only = BTreeMap::new();

        let result = check_exec_gate(
            &bypass,
            &resolved,
            &deny_only,
            "/tmp/unknown",
            Path::new("/tmp/unknown"),
            id,
        );
        assert!(
            result.is_none(),
            "non-controlled executable identities must not be blocked by tool-sandbox policy"
        );
    }

    #[test]
    fn child_cap_spec_serializes_resolved_filesystem_paths() -> Result<()> {
        let temp = test_tempdir()?;
        let real = temp.path().join("real");
        let link = temp.path().join("link");
        create_dir(&real)?;
        symlink_path(&real, &link)?;
        let resolved = real
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: real.clone(),
                source,
            })?;

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(&link, AccessMode::Read)?);

        let spec = caps_to_spec(&caps);
        let grant = spec.fs.first().ok_or_else(|| {
            NonoError::SandboxInit("missing filesystem grant in child spec".to_string())
        })?;
        let serialized_path = PathBuf::from(OsString::from_vec(grant.path.clone()));
        assert_eq!(serialized_path, resolved);
        assert_ne!(serialized_path, link);
        let serialized_original = grant
            .original_path
            .as_ref()
            .map(|path| PathBuf::from(OsString::from_vec(path.clone())))
            .ok_or_else(|| {
                NonoError::SandboxInit("missing filesystem original path in child spec".to_string())
            })?;
        assert_eq!(serialized_original, link);

        let restored = caps_from_spec(&spec)?;
        let restored_cap = restored.fs_capabilities().first().ok_or_else(|| {
            NonoError::SandboxInit("missing restored filesystem grant".to_string())
        })?;
        assert_eq!(restored_cap.original, link);
        assert_eq!(restored_cap.resolved, resolved);

        Ok(())
    }

    #[test]
    fn child_cap_spec_serializes_resolved_unix_socket_paths() -> Result<()> {
        let temp = test_tempdir()?;
        let real = temp.path().join("sockets-real");
        let link = temp.path().join("sockets-link");
        create_dir(&real)?;
        symlink_path(&real, &link)?;
        let resolved = real
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: real.clone(),
                source,
            })?;

        let mut caps = CapabilitySet::new();
        caps.add_unix_socket(UnixSocketCapability::new_dir(
            &link,
            UnixSocketMode::Connect,
        )?);

        let spec = caps_to_spec(&caps);
        let grant = spec.unix_sockets.first().ok_or_else(|| {
            NonoError::SandboxInit("missing unix socket grant in child spec".to_string())
        })?;
        let serialized_path = PathBuf::from(OsString::from_vec(grant.path.clone()));
        assert_eq!(serialized_path, resolved);
        assert_ne!(serialized_path, link);
        let serialized_original = grant
            .original_path
            .as_ref()
            .map(|path| PathBuf::from(OsString::from_vec(path.clone())))
            .ok_or_else(|| {
                NonoError::SandboxInit(
                    "missing unix socket original path in child spec".to_string(),
                )
            })?;
        assert_eq!(serialized_original, link);

        let restored = caps_from_spec(&spec)?;
        let restored_cap = restored.unix_socket_capabilities().first().ok_or_else(|| {
            NonoError::SandboxInit("missing restored unix socket grant".to_string())
        })?;
        assert_eq!(restored_cap.original, link);
        assert_eq!(restored_cap.resolved, resolved);

        Ok(())
    }

    #[test]
    fn child_cap_spec_rejects_mismatched_filesystem_original_path() -> Result<()> {
        let temp = test_tempdir()?;
        let real = temp.path().join("real");
        let other = temp.path().join("other");
        create_dir(&real)?;
        create_dir(&other)?;
        let resolved = real
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: real.clone(),
                source,
            })?;

        let spec = ChildCapsSpec {
            fs: vec![FsGrantSpec {
                path: resolved.as_os_str().as_bytes().to_vec(),
                original_path: Some(other.as_os_str().as_bytes().to_vec()),
                access: AccessMode::Read.to_string(),
                is_file: false,
            }],
            unix_sockets: Vec::new(),
            platform_rules: Vec::new(),
            network_blocked: false,
            proxy_port: None,
            proxy_bind_ports: Vec::new(),
            tcp_connect_ports: Vec::new(),
            tcp_bind_ports: Vec::new(),
        };

        let err = caps_from_spec(&spec).err().ok_or_else(|| {
            NonoError::SandboxInit(
                "expected mismatched filesystem original path to fail".to_string(),
            )
        })?;
        assert!(err.to_string().contains("resolves to"));

        Ok(())
    }

    #[test]
    fn child_chaining_caps_do_not_grant_runtime_launch_specs() -> Result<()> {
        let runtime_dir = create_runtime_dir()?;
        let _cleanup = RuntimeDirCleanup::new(runtime_dir.clone());
        let socket_path = runtime_dir.join("supervisor.sock");
        let _listener = bind_runtime_socket(&socket_path)?;
        let shim_dir = create_shim_dir(&runtime_dir)?;
        let shim_source = materialize_shim_source(&shim_dir)?;
        let shim = materialize_shim(&shim_source, &shim_dir, "git")?;
        let launch_spec = runtime_dir.join("launch-test.json");
        fs::write(&launch_spec, br#"{"secret":"must-not-be-readable"}"#).map_err(|source| {
            NonoError::ConfigWrite {
                path: launch_spec.clone(),
                source,
            }
        })?;
        let state = test_state_with_chaining_paths(
            runtime_dir.clone(),
            socket_path,
            shim_dir.clone(),
            shim,
        );
        let mut caps = CapabilitySet::new();

        add_chaining_control_caps(&mut caps, &state)?;
        let spec = caps_to_spec(&caps);

        assert!(
            spec.fs.iter().any(|grant| {
                !grant.is_file && grant.path.as_slice() == shim_dir.as_os_str().as_bytes()
            }),
            "child must retain read access to immutable shim directory"
        );
        assert!(
            !spec.fs.iter().any(|grant| {
                !grant.is_file
                    && matches!(grant.access.as_str(), "read" | "read+write")
                    && launch_spec.starts_with(Path::new(OsStr::from_bytes(&grant.path)))
            }),
            "child must not receive a recursive read grant covering launch specs"
        );
        Ok(())
    }

    // ── apply_environment_set_vars: dangerous key rejection ───────────────

    fn policy_with_set_var(key: &str, val: &str) -> CommandSandboxConfig {
        let mut set_vars = BTreeMap::new();
        set_vars.insert(key.to_string(), val.to_string());
        CommandSandboxConfig {
            environment: Some(CommandEnvironmentConfig {
                allow_vars: None,
                set_vars,
            }),
            ..CommandSandboxConfig::default()
        }
    }

    #[test]
    fn set_vars_rejects_ld_preload() {
        let policy = policy_with_set_var("LD_PRELOAD", "/evil.so");
        let result = apply_environment_set_vars(&mut vec![], &policy);
        assert!(result.is_err(), "LD_PRELOAD in set_vars must be rejected");
    }

    #[test]
    fn set_vars_rejects_pythonpath() {
        let policy = policy_with_set_var("PYTHONPATH", "/evil");
        let result = apply_environment_set_vars(&mut vec![], &policy);
        assert!(result.is_err(), "PYTHONPATH in set_vars must be rejected");
    }

    #[test]
    fn set_vars_rejects_node_options() {
        let policy = policy_with_set_var("NODE_OPTIONS", "--require /evil.js");
        let result = apply_environment_set_vars(&mut vec![], &policy);
        assert!(result.is_err(), "NODE_OPTIONS in set_vars must be rejected");
    }

    #[test]
    fn set_vars_allows_safe_var() {
        let policy = policy_with_set_var("MY_APP_CONFIG", "value");
        let mut env = vec![];
        let result = apply_environment_set_vars(&mut env, &policy);
        assert!(result.is_ok());
        assert!(env.iter().any(|e| e == b"MY_APP_CONFIG=value"));
    }
}
