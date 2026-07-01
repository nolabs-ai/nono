use crate::audit_integrity::{
    CommandPolicyAuditEvent, CommandPolicyEnvAuditEntry, CommandPolicyStdioAudit,
    CommandPolicyStdioStreamAudit,
};
use crate::command_policy::{
    CommandPoliciesConfig, CommandSandboxConfig, InterceptActionConfig, ResolvedCommandBinaries,
    ResolvedCommandBinary, has_explicit_self_invocation_entry,
};
use crate::tool_sandbox::credentials::{ResolvedCredential, resolve_credentials};
use crate::tool_sandbox::env::{
    apply_environment_set_vars, default_env_allow_patterns, effective_argv,
    inject_chaining_control_env, inject_url_open_env, split_env_entry,
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
use nix::libc;
use nono::supervisor::ApprovalRequest;
use nono::{
    AccessMode, CapabilitySet, FsCapability, NetworkMode, NonoError, Result, Sandbox,
    UnixSocketCapability, UnixSocketMode,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};
use zeroize::Zeroizing;

// ── Constants ────────────────────────────────────────────────────────────

const MAX_ACTIVE_TOOL_SANDBOX_CHILDREN: usize = 64;
const MAX_CAPTURE_STDOUT: usize = 256 * 1024;
const MAX_QUEUED_SHIM_REQUESTS: usize = 128;
const ANCESTRY_DEPTH_LIMIT: usize = 64;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
const PROC_PIDTBSDINFO: i32 = 3;

// ── FFI ──────────────────────────────────────────────────────────────────

unsafe extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: i32,
    ) -> i32;
}

#[repr(C)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    _reserved: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

// ── State ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FileId {
    dev: u64,
    ino: u64,
}

struct ShimIdentity {
    path: PathBuf,
    /// (st_dev, st_ino) captured at materialisation.
    id: FileId,
}

struct ActiveChild {
    command: String,
    /// The caller this command was launched under (its policy edge). A URL-open
    /// request from this command resolves its policy via this caller, not via a
    /// fresh ancestry walk — which would treat the command as its own caller and
    /// check a nonexistent `<cmd>.can_use[<cmd>]` self-edge.
    launch_caller: Caller,
    /// Monotonic start time (pbi_start_tvsec * 1_000_000 + pbi_start_tvusec)
    /// used to detect stale pid map entries.
    start_usec: u64,
}

struct ChildLaunchResult {
    exit_code: i32,
    stdio: Option<CommandPolicyStdioAudit>,
    blocked_reason: Option<String>,
}

struct ToolSandboxState {
    runtime_dir: PathBuf,
    socket_path: PathBuf,
    /// Dedicated URL-open listener socket path, present only when at least one
    /// command declares `open_urls`. Kept separate from `socket_path` so the
    /// shim handshake protocol is untouched.
    url_socket_path: Option<PathBuf>,
    shim_dir: PathBuf,
    /// The browser-open shim (a copy of the nono binary named `open`),
    /// materialized only when a command declares `open_urls`. Brokered children
    /// exec this to delegate URL opens to the runtime's URL listener.
    url_open_shim: Option<ShimIdentity>,
    session_path: String,
    profile_display_name: Option<String>,
    redaction_policy: nono::ScrubPolicy,
    policy_root: PathBuf,
    plan: ResolvedToolSandboxPlan,
    shims_by_command: BTreeMap<String, ShimIdentity>,
    shims_by_path: BTreeMap<PathBuf, String>,
    credential_handles: BTreeMap<String, ResolvedCredential>,
    proxy_trust_bundle_paths: Vec<PathBuf>,
    active_children: Mutex<HashMap<u32, ActiveChild>>,
    active_count: AtomicUsize,
    queued_requests: AtomicUsize,
    emitted_error_response: AtomicBool,
    token_broker: crate::tool_sandbox::token_broker::SharedBroker,
    approval_backends: nono_proxy::approval::ApprovalBackendRegistry,
}

struct ResolvedToolSandboxPlan {
    config: CommandPoliciesConfig,
    resolved: ResolvedCommandBinaries,
    deny_only: BTreeMap<String, ResolvedDenyOnlyCommand>,
    allowed_direct_bypass_ids: HashSet<FileId>,
}

#[derive(Debug, Clone)]
struct ResolvedDenyOnlyCommand {
    path: PathBuf,
    id: FileId,
}

// ── PreparedToolSandboxRuntime ───────────────────────────────────────────────────

pub(crate) struct PreparedToolSandboxRuntime {
    inner: Arc<ToolSandboxState>,
    listener: Arc<UnixListener>,
    /// URL-open listener, present only when a command declares `open_urls`.
    url_listener: Option<Arc<UnixListener>>,
}

impl ResolvedToolSandboxPlan {
    fn build(
        config: &CommandPoliciesConfig,
        _allowed_commands: &[String],
        _blocked_commands: &[String],
        outer_caps: &CapabilitySet,
    ) -> Result<Self> {
        let path_env = std::env::var_os("PATH");
        let resolved =
            crate::command_policy::resolve_policy_command_binaries(config, path_env.clone())?;
        for w in &resolved.warnings {
            if w.code == "command_not_found" {
                eprintln!("  [nono] Warning: {}", w.message);
            }
        }
        let search_dirs = command_search_dirs(config, path_env, outer_caps)?;
        validate_trusted_executable_dirs(&search_dirs, outer_caps)?;
        // BMETE command policies are scoped to command_policies.commands.
        // Legacy startup command denies must not be folded into tool-sandbox as
        // deny-only commands; doing so makes inherited dangerous-command
        // entries part of the child sandbox trust boundary.
        let deny_only = resolve_deny_only_commands(config, &[], &[], &search_dirs)?;
        validate_controlled_binary_immutability(config, &resolved, &deny_only, outer_caps)?;
        let governance_denies = resolve_governance_denies(config)?;
        let allowed_direct_bypasses =
            resolve_allowed_direct_bypasses(config, &resolved, &deny_only, &governance_denies)?;
        let allowed_direct_bypass_ids = resolve_file_ids(&allowed_direct_bypasses)?;
        Ok(Self {
            config: config.clone(),
            resolved,
            deny_only,
            allowed_direct_bypass_ids,
        })
    }
}

impl PreparedToolSandboxRuntime {
    pub(crate) fn prepare(input: super::ToolSandboxPrepare<'_>) -> Result<Self> {
        let super::ToolSandboxPrepare {
            config,
            audit_context,
            allowed_commands,
            blocked_commands,
            outer_caps,
            policy_root,
            proxy_credential_env_vars,
            proxy_trust_bundle_paths,
            shared_broker,
        } = input;

        validate_platform_requirements(config)?;

        let plan =
            ResolvedToolSandboxPlan::build(config, allowed_commands, blocked_commands, outer_caps)?;

        let runtime_dir = create_runtime_dir()?;
        let mut cleanup = RuntimeDirCleanup::new(runtime_dir.clone());
        let socket_path = runtime_dir.join("supervisor.sock");
        let listener = bind_runtime_socket(&socket_path)?;
        // Bind a dedicated URL-open listener only when a command needs it, so
        // the attack surface is zero for profiles that don't use open_urls.
        let (url_socket_path, url_listener) = if config.any_command_allows_url_open() {
            let url_socket_path = runtime_dir.join("url.sock");
            let url_listener = bind_runtime_socket(&url_socket_path)?;
            (Some(url_socket_path), Some(Arc::new(url_listener)))
        } else {
            (None, None)
        };
        let shim_dir = create_shim_dir(&runtime_dir)?;
        let session_path = build_session_path(&shim_dir);

        let credential_handles =
            resolve_credentials(&plan.config.credentials, proxy_credential_env_vars)?;

        let mut shims_by_command = BTreeMap::new();
        let mut shims_by_path = BTreeMap::new();
        let mut shim_names: BTreeSet<String> = plan.resolved.commands.keys().cloned().collect();
        shim_names.extend(plan.deny_only.keys().cloned());
        let shim_source = materialize_shim_source(&shim_dir)?;
        for name in shim_names {
            let identity = materialize_shim(&shim_source, &shim_dir, &name)?;
            shims_by_path.insert(identity.path.clone(), name.clone());
            shims_by_command.insert(name, identity);
        }
        // Materialize the browser-open shim only when URL opening is enabled.
        // It is a distinct copy of the nono binary named `open`, so a brokered
        // child that runs `open <url>` (or `$BROWSER`) reaches the URL listener.
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
                plan,
                shims_by_command,
                shims_by_path,
                credential_handles,
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
        cleanup.disarm();
        Ok(runtime)
    }

    pub(crate) fn emitted_error_response(&self) -> bool {
        self.inner.emitted_error_response.load(Ordering::SeqCst)
    }

    pub(crate) fn cleanup_runtime_dir(&self) {
        if let Err(err) = guarded_remove_runtime_dir(&self.inner.runtime_dir) {
            debug!("tool-sandbox runtime dir cleanup skipped: {err}");
        }
    }

    /// Returns environment overrides to inject into the child process.
    /// Prepends the shim directory to PATH and sets tool-sandbox socket vars.
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

    /// Grants Seatbelt capabilities for shim dir execution, socket access,
    /// and metadata-only cwd traversal so getcwd() works inside the sandbox.
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
        add_macos_cwd_metadata_rules(caps, &self.inner.policy_root)?;
        add_outer_process_exec_gate(caps, &self.inner)?;
        caps.deduplicate();
        Ok(())
    }

    /// Returns the shim path for the given top-level command name,
    /// or `None` if the command is not intercepted by tool-sandbox.
    pub(crate) fn shim_for_initial_command<'a>(&'a self, program: &str) -> Option<&'a Path> {
        if program.contains('/') {
            return None;
        }
        self.inner
            .shims_by_command
            .get(program)
            .map(|identity| identity.path.as_path())
    }

    /// Initial command identity gate when macOS tool-sandbox is active.
    pub(crate) fn validate_initial_exec(
        &self,
        original_program: &str,
        resolved_program: &Path,
    ) -> Result<Option<NonoError>> {
        if !original_program.contains('/')
            && self.inner.shims_by_command.contains_key(original_program)
        {
            return Ok(None);
        }

        let resolved_canonical =
            resolved_program
                .canonicalize()
                .map_err(|source| NonoError::PathCanonicalization {
                    path: resolved_program.to_path_buf(),
                    source,
                })?;
        let metadata =
            fs::metadata(&resolved_canonical).map_err(|source| NonoError::ConfigRead {
                path: resolved_canonical.clone(),
                source,
            })?;
        Ok(check_exec_gate(
            &self.inner.plan.allowed_direct_bypass_ids,
            &self.inner.plan.resolved.commands,
            &self.inner.plan.deny_only,
            original_program,
            resolved_program,
            file_id(&metadata),
        ))
    }

    /// Starts the IPC accept loop in a background thread. Returns immediately;
    /// connections are served by the background thread until the listener is dropped.
    pub(crate) fn handle_listener(
        &self,
        session_root_pid: u32,
        session_id: &str,
        audit_recorder: Option<Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
    ) -> Result<()> {
        self.spawn_url_listener(session_root_pid, session_id, audit_recorder.clone());
        let state = Arc::clone(&self.inner);
        let listener = Arc::clone(&self.listener);
        let session_id = session_id.to_string();
        std::thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        if let Err(err) = stream.set_nonblocking(false) {
                            debug!("tool-sandbox listener stream blocking mode error: {err}");
                            continue;
                        }
                        let state = Arc::clone(&state);
                        let session_id = session_id.clone();
                        let audit_recorder = audit_recorder.clone();
                        let prev = state.queued_requests.fetch_add(1, Ordering::SeqCst);
                        if prev >= MAX_QUEUED_SHIM_REQUESTS {
                            state.queued_requests.fetch_sub(1, Ordering::SeqCst);
                            // Drop the stream — shim will see a closed connection.
                            drop(stream);
                            continue;
                        }
                        std::thread::spawn(move || {
                            handle_shim_stream(
                                state,
                                stream,
                                session_root_pid,
                                &session_id,
                                audit_recorder,
                            );
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(err) => {
                        debug!("tool-sandbox listener error: {err}");
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    /// Spawn the dedicated URL-open accept loop, if a URL listener was bound.
    fn spawn_url_listener(
        &self,
        session_root_pid: u32,
        session_id: &str,
        audit_recorder: Option<Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
    ) {
        let Some(url_listener) = self.url_listener.as_ref().map(Arc::clone) else {
            return;
        };
        let state = Arc::clone(&self.inner);
        let session_id = session_id.to_string();
        std::thread::spawn(move || {
            loop {
                match url_listener.accept() {
                    Ok((stream, _addr)) => {
                        if let Err(err) = stream.set_nonblocking(false) {
                            debug!("tool-sandbox URL listener blocking mode error: {err}");
                            continue;
                        }
                        let state = Arc::clone(&state);
                        let session_id = session_id.clone();
                        let audit_recorder = audit_recorder.clone();
                        std::thread::spawn(move || {
                            handle_url_open_stream(
                                &state,
                                stream,
                                session_root_pid,
                                &session_id,
                                audit_recorder,
                            );
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(err) => {
                        debug!("tool-sandbox URL listener error: {err}");
                        break;
                    }
                }
            }
        });
    }
}

// ── Shim / child launcher entrypoints ────────────────────────────────────

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

pub(crate) fn record_main_start() {}
pub(crate) fn log_main_total() {}

fn exit_from_result(result: Result<()>) {
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("nono: {e}");
            std::process::exit(126);
        }
    }
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
    let socket_path = std::env::var_os(TOOL_SANDBOX_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            NonoError::SandboxInit("tool-sandbox shim socket env missing".to_string())
        })?;
    let command = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(OsStr::to_os_string))
        .and_then(|n| n.into_string().ok())
        .ok_or_else(|| {
            NonoError::SandboxInit("tool-sandbox shim command name invalid".to_string())
        })?;

    let argv = std::env::args_os()
        .map(OsStringExt::into_vec)
        .collect::<Vec<_>>();
    let env = std::env::vars_os()
        .map(|(k, v)| {
            let mut e = k.into_vec();
            e.push(b'=');
            e.extend(v.into_vec());
            e
        })
        .collect::<Vec<_>>();
    let cwd = std::env::current_dir()
        .map_err(|e| NonoError::SandboxInit(format!("tool-sandbox shim cwd failed: {e}")))?
        .into_os_string()
        .into_vec();

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

    let mut stream = UnixStream::connect(&socket_path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "tool-sandbox shim connect to {}: {e}",
            socket_path.display()
        ))
    })?;
    write_frame(&mut stream, &request)?;
    recv_frame_ack(&mut stream)?;
    send_stdio_fds(&stream)?;
    let response: ToolSandboxShimResponse = read_frame(&mut stream)?;

    if let Some(error) = response.error {
        eprintln!("nono: tool-sandbox denied {}: {error}", request.command);
        std::process::exit(response.exit_code);
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
    // is what surfaces the library's generated-Seatbelt-profile debug log for
    // the brokered child. No-op unless RUST_LOG is set.
    crate::cli_bootstrap::init_internal_entrypoint_tracing();
    let spec_path = std::env::var_os(TOOL_SANDBOX_LAUNCH_SPEC_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            NonoError::SandboxInit("tool-sandbox launch spec env missing".to_string())
        })?;
    let bytes = fs::read(&spec_path).map_err(|source| NonoError::ConfigRead {
        path: spec_path.clone(),
        source,
    })?;
    let spec: ToolSandboxChildLaunchSpec = serde_json::from_slice(&bytes).map_err(|err| {
        NonoError::ConfigParse(format!("failed to parse tool-sandbox launch spec: {err}"))
    })?;
    if spec.stdio_mode != "direct_fds" {
        return Err(NonoError::ConfigParse(format!(
            "invalid tool-sandbox stdio mode '{}'",
            spec.stdio_mode
        )));
    }

    let real_binary = OsString::from_vec(spec.real_binary.clone());
    let cwd = OsString::from_vec(spec.cwd.clone());
    std::env::set_current_dir(&cwd).map_err(|err| {
        NonoError::SandboxInit(format!(
            "tool-sandbox child chdir failed before sandbox: {err}"
        ))
    })?;

    // macOS lacks fexecve/execveat, so verification can open and hash one
    // object but the final exec is still path-based. Default immutability
    // checks reject paths writable by the sandboxed agent; allowing writable
    // executable targets is therefore a deliberate trust downgrade.
    verify_launch_binary(&spec)?;
    let caps = caps_from_spec(&spec.caps)?;
    Sandbox::apply_auto(&caps)?;

    let binary = CString::new(real_binary.as_bytes()).map_err(|_| {
        NonoError::SandboxInit("tool-sandbox real binary path contains NUL".to_string())
    })?;
    let mut argv_c = Vec::with_capacity(spec.argv.len());
    for arg in &spec.argv {
        argv_c.push(
            CString::new(arg.as_slice()).map_err(|_| {
                NonoError::SandboxInit("tool-sandbox argv contains NUL".to_string())
            })?,
        );
    }
    let argv_ptrs: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let mut env_c = Vec::with_capacity(spec.env.len());
    for entry in &spec.env {
        env_c
            .push(CString::new(entry.as_slice()).map_err(|_| {
                NonoError::SandboxInit("tool-sandbox env contains NUL".to_string())
            })?);
    }
    let env_ptrs: Vec<*const libc::c_char> = env_c
        .iter()
        .map(|entry| entry.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::execve(binary.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    let err = std::io::Error::last_os_error();
    if spec.executable_kind == "ShebangScript" {
        let interpreter = spec
            .interpreter
            .map(OsString::from_vec)
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<unknown>".to_string());
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox execve failed for script {} using interpreter {}: {err}. The selected child policy must grant the script, interpreter, and any required language runtime/package directories.",
            PathBuf::from(real_binary).display(),
            interpreter
        )));
    }
    Err(NonoError::CommandExecution(err))
}

// ── IPC handler ──────────────────────────────────────────────────────────

/// Handle a single URL-open request on the dedicated URL listener socket.
///
/// The requesting command is resolved from the connecting PID via the same
/// trusted ancestry walk used for shim requests — the `command` field on the
/// request is advisory only. The command's `open_urls` policy gates the open;
/// the browser is launched by this unsandboxed runtime process.
fn handle_url_open_stream(
    state: &ToolSandboxState,
    mut stream: UnixStream,
    session_root_pid: u32,
    session_id: &str,
    audit_recorder: Option<Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
) {
    // Bound how long a single client can hold this connection so a slow or idle
    // client cannot pin a handler thread indefinitely.
    if stream
        .set_read_timeout(Some(TOOL_SANDBOX_URL_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TOOL_SANDBOX_URL_IO_TIMEOUT)))
        .is_err()
    {
        debug!("tool-sandbox URL open: failed to set socket timeout");
        return;
    }

    let peer_pid = match peer_pid_from_stream(&stream) {
        Ok(pid) => pid,
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
/// against that command's `open_urls` policy. Returns `Ok(())` if the open is
/// permitted, or a denial reason otherwise. Does not open the browser.
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
    audit_recorder: Option<Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
) {
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
            let _ = write_response(&mut stream, exit_code, None, captured_stdout);
        }
        Err(err) => {
            state.emitted_error_response.store(true, Ordering::SeqCst);
            let _ = write_response(
                &mut stream,
                126,
                Some(super::shim_error_message(&err)),
                Vec::new(),
            );
        }
    }
}

fn handle_shim_stream_inner(
    state: &Arc<ToolSandboxState>,
    stream: &mut UnixStream,
    session_root_pid: u32,
    session_id: &str,
    audit_recorder: Option<Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
) -> Result<(i32, Vec<u8>)> {
    let auth = authenticate_shim(stream, state)?;
    let request: ToolSandboxShimRequest = read_frame(stream)?;
    // Ack before receiving stdio FDs: on macOS, sendmsg with SCM_RIGHTS ancillary
    // data returns EMSGSIZE if the peer's receive buffer still holds unread frame
    // bytes. Sending the ack proves the buffer is drained so the shim's sendmsg
    // can always queue its ancillary data atomically.
    send_frame_ack(stream)?;
    validate_ipc_request(&request)?;
    if request.command != auth.command {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox shim command mismatch: requested {}, authenticated {}",
            request.command, auth.command
        )));
    }
    let stdio = recv_stdio_fds(stream)?;

    if state.plan.deny_only.contains_key(&request.command) {
        record_command_policy_audit(
            audit_recorder.as_ref(),
            &request,
            &state.redaction_policy,
            session_id,
            auth.peer_pid,
            session_root_pid,
            None,
            "denied",
            Some("legacy_blocked_command".to_string()),
            None,
        )?;
        return Err(NonoError::BlockedCommand {
            command: request.command,
            reason: "legacy_blocked_command".to_string(),
        });
    }

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
                let approval_request = ApprovalRequest::Command {
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

    let command_config = state
        .plan
        .config
        .commands
        .get(&request.command)
        .ok_or_else(|| {
            NonoError::SandboxInit(format!("missing command config for {}", request.command))
        })?;

    let intercept = super::resolve_intercept_action(command_config, &request.argv);
    let intercept_action = intercept.action;

    // ── Respond ──────────────────────────────────────────────────────────
    if let InterceptActionConfig::Respond { stdout } = intercept_action {
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
        return Ok((0, stdout.as_bytes().to_vec()));
    }

    // ── Approve ──────────────────────────────────────────────────────────
    if let InterceptActionConfig::Approve { timeout_secs } = intercept_action {
        let argv_display: Vec<String> = request
            .argv
            .iter()
            .filter_map(|a| std::str::from_utf8(a).ok().map(str::to_owned))
            .collect();
        let approval_request = ApprovalRequest::Command {
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

    // ── Capture credential ──────────────────────────────────────────────
    if let InterceptActionConfig::CaptureCredential {
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
            let launch = build_child_launch_spec(state, &request, policy)?;
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

    // ── Capture ──────────────────────────────────────────────────────────
    if matches!(intercept_action, InterceptActionConfig::Capture) {
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
            let launch = build_child_launch_spec(state, &request, policy)?;
            launch_child_with_capture(state, &request.command, &caller, launch, stdio)
        })();
        state.active_count.fetch_sub(1, Ordering::SeqCst);
        return match result {
            Ok((exit_code, raw_output)) => {
                let captured = {
                    let mut broker = state.token_broker.lock().map_err(|_| {
                        NonoError::SandboxInit(
                            "tool-sandbox token broker lock poisoned".to_string(),
                        )
                    })?;
                    broker.scan_and_reissue(&raw_output)
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
                    Some(exit_code),
                )?;
                Ok((exit_code, captured))
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

    // ── Passthrough (and Approve→granted) ────────────────────────────────
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
        let launch = build_child_launch_spec(state, &request, policy)?;
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

// ── Shim authentication ───────────────────────────────────────────────────

struct ShimAuth {
    peer_pid: u32,
    command: String,
}

fn authenticate_shim(stream: &UnixStream, state: &ToolSandboxState) -> Result<ShimAuth> {
    let peer_pid = peer_pid_from_stream(stream)?;
    let exe_path = exe_path_for_pid(peer_pid)?;
    let command = state.shims_by_path.get(&exe_path).cloned().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "tool-sandbox shim auth failed for pid {peer_pid}: untrusted path {}",
            exe_path.display()
        ))
    })?;
    let identity = state.shims_by_command.get(&command).ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "tool-sandbox shim auth: missing identity for {command}"
        ))
    })?;
    let meta = fs::metadata(&exe_path).map_err(|e| NonoError::ConfigRead {
        path: exe_path.clone(),
        source: e,
    })?;
    if identity.id != file_id(&meta) {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox shim auth: inode mismatch for {}",
            exe_path.display()
        )));
    }
    Ok(ShimAuth { peer_pid, command })
}

fn peer_pid_from_stream(stream: &UnixStream) -> Result<u32> {
    // SAFETY: getsockopt with LOCAL_PEERPID is stable on macOS.
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox: getsockopt(LOCAL_PEERPID) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(pid as u32)
}

fn exe_path_for_pid(pid: u32) -> Result<PathBuf> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: proc_pidpath writes at most PROC_PIDPATHINFO_MAXSIZE bytes into buf.
    let ret = unsafe {
        proc_pidpath(
            pid as i32,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };
    if ret <= 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox: proc_pidpath({pid}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    buf.truncate(ret as usize);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

// ── Caller ancestry ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Caller {
    Session,
    Command { name: String },
}

fn resolve_caller(
    peer_pid: u32,
    session_root_pid: u32,
    state: &ToolSandboxState,
    command_name: &str,
) -> Result<Caller> {
    let mut pid = peer_pid;
    for _ in 0..ANCESTRY_DEPTH_LIMIT {
        if let Some((cmd, launch_caller)) = live_active_child(pid, state)? {
            if cmd == command_name
                && !has_explicit_self_invocation_entry(&state.plan.config, command_name)
            {
                return Ok(launch_caller);
            }
            return Ok(Caller::Command { name: cmd });
        }
        if pid == session_root_pid {
            return Ok(Caller::Session);
        }
        if pid == 0 || pid == 1 {
            break;
        }
        pid = match parent_pid(pid) {
            Ok(p) => p,
            // If proc_pidinfo fails partway up the chain the process likely
            // exited; stop walking rather than returning an opaque error.
            Err(_) => break,
        };
    }
    Err(NonoError::BlockedCommand {
        command: "unknown".to_string(),
        reason: "caller ancestry did not reach session root".to_string(),
    })
}

fn parent_pid(pid: u32) -> Result<u32> {
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcBsdInfo>() as i32;
    // SAFETY: proc_pidinfo writes exactly `size` bytes into info on success.
    let ret = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if ret == size {
        Ok(info.pbi_ppid)
    } else {
        Err(NonoError::SandboxInit(format!(
            "tool-sandbox: proc_pidinfo({pid}) failed: ret={ret} expected={size} errno={}",
            std::io::Error::last_os_error()
        )))
    }
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
    let Some(child) = map.get(&pid) else {
        return Ok(None);
    };
    if !is_pid_alive_with_start(pid, child.start_usec) {
        return Ok(None);
    }
    Ok(Some((child.command.clone(), child.launch_caller.clone())))
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
    if let Some(found) = live_active_child(peer_pid, state)? {
        return Ok(Some(found));
    }
    let mut pid = peer_pid;
    for _ in 0..ANCESTRY_DEPTH_LIMIT {
        pid = match parent_pid(pid) {
            Ok(p) => p,
            Err(_) => break,
        };
        if pid == 0 || pid == 1 {
            break;
        }
        if let Some(found) = live_active_child(pid, state)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn is_pid_alive_with_start(pid: u32, expected_start_usec: u64) -> bool {
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcBsdInfo>() as i32;
    // SAFETY: same as parent_pid.
    let ret = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if ret != size {
        return false;
    }
    let start_usec = info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec as u64;
    start_usec == expected_start_usec
}

fn track_child(
    state: &ToolSandboxState,
    child_pid: u32,
    command_name: &str,
    launch_caller: &Caller,
) -> Result<()> {
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcBsdInfo>() as i32;
    // SAFETY: same as parent_pid.
    let ret = unsafe {
        proc_pidinfo(
            child_pid as i32,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    let start_usec = if ret == size {
        info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec as u64
    } else {
        0
    };
    let mut map = state
        .active_children
        .lock()
        .map_err(|_| NonoError::SandboxInit("tool-sandbox pid map lock poisoned".to_string()))?;
    map.retain(|pid, child| is_pid_alive_with_start(*pid, child.start_usec));
    map.insert(
        child_pid,
        ActiveChild {
            command: command_name.to_string(),
            launch_caller: launch_caller.clone(),
            start_usec,
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

fn file_id(metadata: &fs::Metadata) -> FileId {
    FileId {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

// ── Child launch spec builder ─────────────────────────────────────────────

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
    verify_binary_identity(binary)?;
    let cwd = PathBuf::from(OsString::from_vec(request.cwd.clone()));
    let cwd = cwd
        .canonicalize()
        .map_err(|source| NonoError::PathCanonicalization {
            path: cwd.clone(),
            source,
        })?;
    let mut caps = build_child_caps(state, binary, policy, request, &cwd)?;
    caps.deduplicate();

    Ok(ToolSandboxChildLaunchSpec {
        real_binary: binary.canonical_path.as_os_str().as_bytes().to_vec(),
        executable_kind: format!("{:?}", binary.shape.kind),
        interpreter: binary
            .shape
            .interpreter
            .as_ref()
            .map(|path| path.as_os_str().as_bytes().to_vec()),
        interpreter_args: binary.shape.interpreter_args.clone(),
        argv: effective_argv(binary, request, policy)?,
        env: filter_child_env(state, request, policy)?,
        cwd: cwd.as_os_str().as_bytes().to_vec(),
        stdio_mode: selected_stdio_mode(request).to_string(),
        stdio_limits: stdio_limits_from_policy(policy),
        caps: caps_to_spec(&caps),
        allowed_exec_paths: Vec::new(),
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
    add_macos_runtime_baseline(&mut caps)?;
    add_executable_shape_baseline(&mut caps, binary)?;
    add_chaining_control_caps(&mut caps, state)?;
    add_macos_cwd_metadata_rules(&mut caps, cwd)?;
    add_policy_fs(&mut caps, policy, &state.policy_root)?;
    // When the command was granted a keychain DB file (e.g. login.keychain-db),
    // reuse the main-path keychain mechanism: add the WAL/SHM/`.fl`/`user.kb`
    // sibling-file exceptions the Security framework touches. The library
    // profile separately auto-unlocks the securityd/SecurityServer mach-lookups
    // when a keychain DB cap is present (see has_explicit_keychain_db_access).
    // No-op when no keychain DB grant exists.
    crate::policy::apply_macos_keychain_db_exception(&mut caps);
    add_policy_network(&mut caps, policy)?;
    add_policy_proxy_network(&mut caps, state, request, policy)?;
    add_proxy_trust_bundle_caps(&mut caps, state, policy)?;
    add_policy_credentials(&mut caps, state, policy)?;
    add_url_open_caps(&mut caps, state, policy)?;
    add_launch_services_caps(&mut caps, policy)?;
    add_child_process_exec_gate_with_policy(&mut caps, state, binary, Some(policy))?;
    Ok(caps)
}

/// When a command opts into direct LaunchServices (`allow_launch_services`),
/// grant the brokered child the mach-lookup access LaunchServices needs and
/// permit execing `/usr/bin/open`. Exec of `/usr/bin/open` is added to the
/// child's exec-gate allowlist below; here we add the mach-lookup rules.
///
/// NOTE: macOS-only and verified-by-design rather than test: a real browser
/// launch under Seatbelt is required to confirm the LaunchServices mach-lookup
/// set is complete. The runtime-delegated shim path (open_urls without
/// allow_launch_services) is the validated default.
fn add_launch_services_caps(caps: &mut CapabilitySet, policy: &CommandSandboxConfig) -> Result<()> {
    if !policy.allow_launch_services {
        return Ok(());
    }
    // LaunchServices client lookups required to resolve and dispatch an open.
    for global_name in [
        "com.apple.coreservices.launchservicesd",
        "com.apple.lsd.mapdb",
        "com.apple.lsd.modifydb",
        "com.apple.lsd.advertisingidentifiers",
        "com.apple.coreservices.quarantine-resolver",
    ] {
        caps.add_platform_rule(format!(
            "(allow mach-lookup (global-name \"{global_name}\"))"
        ))?;
    }
    Ok(())
}

/// Grant the brokered child connect access to the URL listener socket and read
/// access to the open shim, when the command declares `open_urls` and did not
/// opt into direct LaunchServices. The shim is added to the exec gate by
/// [`add_child_process_exec_gate_with_policy`].
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
    Ok(())
}

fn add_executable_shape_baseline(
    caps: &mut CapabilitySet,
    binary: &ResolvedCommandBinary,
) -> Result<()> {
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
    if let Some(bundle) = python_framework_app_bundle_path(&interpreter)
        && bundle.is_file()
    {
        caps.add_fs(FsCapability::new_file(bundle, AccessMode::Read)?);
    }
    caps.add_fs(FsCapability::new_file(interpreter, AccessMode::Read)?);
    Ok(())
}

fn add_chaining_control_caps(caps: &mut CapabilitySet, state: &ToolSandboxState) -> Result<()> {
    caps.add_fs(FsCapability::new_dir(&state.shim_dir, AccessMode::Read)?);
    for shim in state.shims_by_command.values() {
        caps.add_fs(FsCapability::new_file(&shim.path, AccessMode::Read)?);
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

fn add_macos_cwd_metadata_rules(caps: &mut CapabilitySet, cwd: &Path) -> Result<()> {
    for path in cwd.ancestors().filter(|path| *path != Path::new("/")) {
        let escaped = crate::policy::escape_seatbelt_path(crate::policy::path_to_utf8(path)?)?;
        caps.add_platform_rule(format!(
            "(allow file-read-metadata (literal \"{escaped}\"))"
        ))?;
    }
    Ok(())
}

fn add_outer_process_exec_gate(caps: &mut CapabilitySet, state: &ToolSandboxState) -> Result<()> {
    let mut denied = BTreeSet::new();
    for binary in state.plan.resolved.commands.values() {
        let id = FileId {
            dev: binary.dev,
            ino: binary.ino,
        };
        if !state.plan.allowed_direct_bypass_ids.contains(&id) {
            denied.insert(binary.canonical_path.clone());
        }
    }
    for deny_only in state.plan.deny_only.values() {
        denied.insert(deny_only.path.clone());
    }
    // The child sandbox is a routing guard, not the tool policy sandbox.
    // It permits ordinary agent process execution, then denies configured
    // policy command binaries by exact path so those tools must be reached
    // through the broker shim on PATH. The supervisor applies the actual
    // command sandbox to the approved grandchild invocation.
    caps.add_platform_rule("(allow process-exec*)")?;
    add_controlled_source_denies(caps, denied)
}

/// Given the canonical path of a Python framework interpreter binary such as
/// `.../Frameworks/Python.framework/Versions/3.14/bin/python3.14`, returns the
/// sibling app bundle executable path:
/// `.../Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python`.
fn python_framework_app_bundle_path(interpreter: &Path) -> Option<PathBuf> {
    let file_name = interpreter.file_name()?;
    if !file_name.as_bytes().starts_with(b"python") {
        return None;
    }

    let bin_dir = interpreter.parent()?;
    if bin_dir.file_name()? != OsStr::new("bin") {
        return None;
    }

    let version_dir = bin_dir.parent()?;
    let versions_dir = version_dir.parent()?;
    if versions_dir.file_name()? != OsStr::new("Versions") {
        return None;
    }

    let framework_dir = versions_dir.parent()?;
    if framework_dir.file_name()? != OsStr::new("Python.framework") {
        return None;
    }

    let frameworks_dir = framework_dir.parent()?;
    if frameworks_dir.file_name()? != OsStr::new("Frameworks") {
        return None;
    }

    Some(
        version_dir
            .join("Resources")
            .join("Python.app")
            .join("Contents")
            .join("MacOS")
            .join("Python"),
    )
}

fn add_child_process_exec_gate_with_policy(
    caps: &mut CapabilitySet,
    state: &ToolSandboxState,
    binary: &ResolvedCommandBinary,
    policy: Option<&CommandSandboxConfig>,
) -> Result<()> {
    let mut allowed = vec![binary.canonical_path.clone()];
    if let Some(interpreter) = binary.shape.interpreter.as_ref() {
        let interpreter =
            interpreter
                .canonicalize()
                .map_err(|source| NonoError::PathCanonicalization {
                    path: interpreter.clone(),
                    source,
                })?;
        if let Some(bundle) = python_framework_app_bundle_path(&interpreter)
            && bundle.is_file()
        {
            allowed.push(bundle);
        }
        allowed.push(interpreter);
    }
    allowed.extend(
        state
            .shims_by_command
            .values()
            .map(|identity| identity.path.clone()),
    );
    if let Some(policy) = policy {
        // Allow execing the browser-open shim only when this command may open
        // URLs without direct LaunchServices.
        if policy.open_urls.is_some()
            && !policy.allow_launch_services
            && let Some(shim) = state.url_open_shim.as_ref()
        {
            allowed.push(shim.path.clone());
        }
        // Direct LaunchServices opt-in: permit execing /usr/bin/open.
        if policy.allow_launch_services {
            let open_path = Path::new("/usr/bin/open");
            if open_path.exists() {
                allowed.push(open_path.to_path_buf());
            }
        }
    }
    add_process_exec_gate(caps, allowed)
}

fn add_process_exec_gate(
    caps: &mut CapabilitySet,
    allowed_paths: impl IntoIterator<Item = PathBuf>,
) -> Result<()> {
    let mut allowed = BTreeSet::new();
    for path in allowed_paths {
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: path.clone(),
                source,
            })?;
        add_macos_path_variants(&canonical, &mut allowed)?;
        allowed.insert(canonical);
    }

    caps.add_platform_rule("(deny process-exec*)")?;
    for path in allowed {
        let escaped = crate::policy::escape_seatbelt_path(crate::policy::path_to_utf8(&path)?)?;
        caps.add_platform_rule(format!("(allow process-exec* (literal \"{escaped}\"))"))?;
    }
    Ok(())
}

fn add_controlled_source_denies(
    caps: &mut CapabilitySet,
    denied_paths: impl IntoIterator<Item = PathBuf>,
) -> Result<()> {
    let mut denied = BTreeSet::new();
    for path in denied_paths {
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: path.clone(),
                source,
            })?;
        denied.insert(canonical);
    }

    for path in denied {
        let escaped = crate::policy::escape_seatbelt_path(crate::policy::path_to_utf8(&path)?)?;
        caps.add_platform_rule(format!("(deny file-read-data (literal \"{escaped}\"))"))?;
        caps.add_platform_rule(format!(
            "(deny file-map-executable (literal \"{escaped}\"))"
        ))?;
        caps.add_platform_rule(format!("(deny process-exec* (literal \"{escaped}\"))"))?;
    }
    Ok(())
}

fn add_macos_path_variants(path: &Path, variants: &mut BTreeSet<PathBuf>) -> Result<()> {
    if path == Path::new("/bin/sh") && Path::new("/bin/bash").exists() {
        variants.insert(
            PathBuf::from("/bin/bash")
                .canonicalize()
                .map_err(|source| NonoError::PathCanonicalization {
                    path: PathBuf::from("/bin/bash"),
                    source,
                })?,
        );
        for selector in ["/private/var/select/sh", "/var/select/sh"] {
            let selector = PathBuf::from(selector);
            if selector.exists() {
                variants.insert(selector);
            }
        }
    }
    if path == Path::new("/usr/bin/git") {
        for variant in [
            "/Library/Developer/CommandLineTools/usr/bin/git",
            "/Library/Developer/CommandLineTools/usr/libexec/git-core/git",
        ] {
            let variant = PathBuf::from(variant);
            if variant.exists() {
                variants.insert(variant);
            }
        }
    }
    Ok(())
}

fn add_macos_runtime_baseline(caps: &mut CapabilitySet) -> Result<()> {
    for dir in [
        "/usr/lib",
        "/usr/share",
        "/System/Library",
        "/System/Cryptexes",
        // Do not grant /System/Volumes recursively: modern macOS exposes
        // user data under /System/Volumes/Data.
        "/System/Cryptexes/App",
        "/System/Cryptexes/OS",
        "/private/var/db/dyld",
        "/var/db/dyld",
        "/private/var/select",
        "/var/select",
        "/var/db/timezone",
        "/usr/share/zoneinfo",
        "/usr/share/locale",
        "/usr/share/terminfo",
        "/Library/Developer/CommandLineTools",
        "/private/etc",
        "/etc",
    ] {
        add_read_dir_if_exists(caps, dir)?;
    }
    add_xcode_selector_rules(caps)?;
    for (file, access) in [
        ("/dev/null", AccessMode::ReadWrite),
        ("/dev/tty", AccessMode::ReadWrite),
        ("/dev/zero", AccessMode::Read),
        ("/dev/random", AccessMode::Read),
        ("/dev/urandom", AccessMode::Read),
    ] {
        add_file_if_exists(caps, file, access)?;
    }
    Ok(())
}

fn add_xcode_selector_rules(caps: &mut CapabilitySet) -> Result<()> {
    for selector in [
        "/private/var/db/xcode_select_link",
        "/var/db/xcode_select_link",
    ] {
        let selector_path = Path::new(selector);
        if selector_path.exists() || selector_path.symlink_metadata().is_ok() {
            let escaped = crate::policy::escape_seatbelt_path(selector)?;
            caps.add_platform_rule(format!("(allow file-read* (literal \"{escaped}\"))"))?;
        }
    }
    Ok(())
}

fn add_read_dir_if_exists(caps: &mut CapabilitySet, path: &str) -> Result<()> {
    let path = Path::new(path);
    if path.is_dir() {
        caps.add_fs(FsCapability::new_dir(path, AccessMode::Read)?);
    }
    Ok(())
}

fn add_file_if_exists(caps: &mut CapabilitySet, path: &str, access: AccessMode) -> Result<()> {
    let path = Path::new(path);
    if path.exists() && !path.is_dir() {
        caps.add_fs(FsCapability::new_file(path, access)?);
    }
    Ok(())
}

fn add_policy_fs(
    caps: &mut CapabilitySet,
    policy: &CommandSandboxConfig,
    policy_root: &Path,
) -> Result<()> {
    use super::dynamic_providers::expand_dynamic_tokens;
    for entry in &expand_dynamic_tokens(&policy.fs_read, Some(policy_root))? {
        let path = resolve_policy_path(entry, policy_root)?;
        add_optional_dir(caps, path, AccessMode::Read)?;
    }
    for entry in &expand_dynamic_tokens(&policy.fs_write, Some(policy_root))? {
        let path = resolve_policy_path(entry, policy_root)?;
        add_optional_dir(caps, path, AccessMode::ReadWrite)?;
    }
    for entry in &expand_dynamic_tokens(&policy.fs_read_file, Some(policy_root))? {
        let path = resolve_policy_path(entry, policy_root)?;
        add_optional_read_file(caps, path)?;
    }
    for entry in &expand_dynamic_tokens(&policy.fs_write_file, Some(policy_root))? {
        let path = resolve_policy_path(entry, policy_root)?;
        caps.add_fs(FsCapability::new_file(path, AccessMode::ReadWrite)?);
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

fn add_policy_network(caps: &mut CapabilitySet, policy: &CommandSandboxConfig) -> Result<()> {
    let Some(network) = &policy.network else {
        return Ok(());
    };
    if network.allow_all {
        caps.set_network_mode_mut(NetworkMode::AllowAll);
        return Ok(());
    }
    if !network.tcp_connect_ports.is_empty() || !network.tcp_bind_ports.is_empty() {
        return Err(NonoError::NetworkFilterUnsupported {
            platform: "macOS".to_string(),
            reason: "Seatbelt cannot enforce raw per-port TCP rules for tool-sandbox children"
                .to_string(),
        });
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

fn resolve_policy_path(entry: &str, cwd: &Path) -> Result<PathBuf> {
    let expanded = crate::profile::expand_vars(entry, cwd)?;
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        Ok(cwd.join(expanded))
    }
}

// ── Environment filtering ─────────────────────────────────────────────────

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

    let mut result: Vec<Vec<u8>> = Vec::new();
    for entry in &request.env {
        let Some((name, _value)) = split_env_entry(entry) else {
            continue;
        };
        let Ok(name_str) = std::str::from_utf8(name) else {
            continue;
        };
        // Block NONO_ reserved prefix.
        if name_str.starts_with("NONO_") {
            continue;
        }
        if crate::exec_strategy::env_sanitization::is_dangerous_env_var(name_str) {
            continue;
        }
        if crate::exec_strategy::env_sanitization::is_env_var_allowed(name_str, &allowed_patterns) {
            // Resolve broker nonces.
            let broker = state.token_broker.lock().map_err(|_| {
                NonoError::SandboxInit("tool-sandbox token broker lock poisoned".to_string())
            })?;
            let consumer = format!("cmd.{}", request.command);
            if let Some(resolved) = broker.resolve_env_entry(entry, &consumer) {
                result.push(resolved);
            } else {
                result.push(entry.clone());
            }
            drop(broker);
        }
    }

    result.retain(|entry| !entry.starts_with(b"PATH="));
    result.push(format!("PATH={}", state.session_path).into_bytes());
    inject_chaining_control_env(&mut result, &state.socket_path, &state.shim_dir);
    inject_url_open_env(
        &mut result,
        policy,
        state.url_socket_path.as_deref(),
        state.url_open_shim.as_ref().map(|shim| shim.path.as_path()),
    );
    apply_environment_set_vars(&mut result, policy)?;

    // Inject resolved credentials.
    for cred_name in super::policy_credential_names(policy) {
        match state.credential_handles.get(cred_name) {
            Some(ResolvedCredential::LocalSocket {
                path: Some(socket_path),
                env_var,
                ..
            }) => {
                if let Some(env_var) = env_var {
                    let prefix = format!("{env_var}=").into_bytes();
                    result.retain(|entry| !entry.starts_with(&prefix));
                    let mut entry = format!("{env_var}=").into_bytes();
                    entry.extend_from_slice(socket_path.as_os_str().as_bytes());
                    result.push(entry);
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
                    "tool-sandbox credential '{cred_name}' is unavailable: {reason}"
                )));
            }
            Some(ResolvedCredential::RawFile { .. }) => {}
            Some(ResolvedCredential::Proxy { env_vars }) => {
                for (name, value) in env_vars {
                    let prefix = format!("{name}=").into_bytes();
                    result.retain(|entry| !entry.starts_with(&prefix));
                    result.push(format!("{name}={value}").into_bytes());
                }
            }
            Some(ResolvedCredential::Ambient { .. }) => {}
            None => {
                return Err(NonoError::SandboxInit(format!(
                    "tool-sandbox credential handle '{cred_name}' was not resolved"
                )));
            }
        }
    }

    Ok(result)
}

fn launch_child(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    spec: ToolSandboxChildLaunchSpec,
    stdio: StdioFds,
) -> Result<ChildLaunchResult> {
    let spec_path = write_launch_spec(&state.runtime_dir, &spec)?;
    let result =
        launch_child_with_direct_fds(state, command_name, launch_caller, &spec_path, &spec, stdio);
    remove_launch_spec(&spec_path);
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
    track_child(state, child.id(), command_name, launch_caller)?;

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
    let read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
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
    let mut pipe_fds = [-1i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox Capture: pipe() failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
    let pipe_write = unsafe { File::from_raw_fd(pipe_fds[1]) };

    let spec_path = write_launch_spec(&state.runtime_dir, &spec)?;
    let mut command = prepare_launcher_command(&spec_path)?;
    command
        .stdin(Stdio::from(File::from(stdio.stdin)))
        .stdout(Stdio::from(pipe_write))
        .stderr(Stdio::from(File::from(stdio.stderr)));
    drop(stdio.stdout);

    let mut child = command.spawn().map_err(NonoError::CommandExecution)?;
    drop(command);
    track_child(state, child.id(), command_name, launch_caller)?;

    let mut captured = Vec::new();
    let mut pipe_reader =
        std::io::BufReader::new(File::from(pipe_read)).take((MAX_CAPTURE_STDOUT as u64) + 1);
    let read_result = pipe_reader.read_to_end(&mut captured);
    drop(pipe_reader);

    let status = child.wait().map_err(NonoError::CommandExecution);
    untrack_child(state, child.id())?;
    remove_launch_spec(&spec_path);

    read_result.map_err(|err| {
        NonoError::SandboxInit(format!("tool-sandbox Capture: pipe read failed: {err}"))
    })?;
    if captured.len() > MAX_CAPTURE_STDOUT {
        return Err(NonoError::SandboxInit(
            "tool-sandbox Capture: output exceeds limit".to_string(),
        ));
    }

    Ok((exit_status_code(status?), captured))
}

fn wait_for_tracked_child(
    state: &ToolSandboxState,
    command_name: &str,
    launch_caller: &Caller,
    child: &mut Child,
) -> Result<i32> {
    track_child(state, child.id(), command_name, launch_caller)?;
    let status = child.wait().map_err(NonoError::CommandExecution);
    untrack_child(state, child.id())?;
    status.map(exit_status_code)
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

fn verify_launch_binary(spec: &ToolSandboxChildLaunchSpec) -> Result<()> {
    let path = PathBuf::from(OsString::from_vec(spec.real_binary.clone()));
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|source| NonoError::ConfigRead {
            path: path.clone(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| NonoError::ConfigRead {
        path: path.clone(),
        source,
    })?;
    if metadata.dev() != spec.expected_dev || metadata.ino() != spec.expected_ino {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox command binary changed inode before launch: {}",
            path.display()
        )));
    }
    if metadata.size() != spec.expected_size || mtime_nanos(&metadata) != spec.expected_mtime_nanos
    {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox command binary changed metadata before launch: {}",
            path.display()
        )));
    }

    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|err| NonoError::SandboxInit(format!("tool-sandbox binary read: {err}")))?;
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
            path.display()
        )));
    }
    Ok(())
}

fn mtime_nanos(metadata: &fs::Metadata) -> i128 {
    let secs = metadata.mtime() as i128;
    let nanos = metadata.mtime_nsec() as i128;
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

fn selected_stdio_mode(_request: &ToolSandboxShimRequest) -> &'static str {
    "direct_fds"
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

// ── Policy selection ──────────────────────────────────────────────────────

fn select_effective_policy<'a>(
    plan: &'a CommandPoliciesConfig,
    command_name: &str,
    caller: &Caller,
) -> Result<&'a CommandSandboxConfig> {
    let command = plan.commands.get(command_name).ok_or_else(|| {
        NonoError::SandboxInit(format!("unknown tool-sandbox command '{command_name}'"))
    })?;
    match caller {
        Caller::Session => {
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
        Caller::Command { name } => {
            let caller_command = plan.commands.get(name.as_str()).ok_or_else(|| {
                NonoError::SandboxInit(format!("unknown tool-sandbox caller '{name}'"))
            })?;
            if !caller_command.can_use.iter().any(|n| n == command_name) {
                return Err(NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: format!("{name}.can_use missing"),
                });
            }
            match command.from.get(name.as_str()) {
                Some(from) => from.sandbox().ok_or_else(|| NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: format!("from.{name} explicit deny"),
                }),
                None => Err(NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: format!("missing from.{name}"),
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
        Caller::Session => match command.from.get("session") {
            Some(crate::command_policy::CommandFromConfig::Edge(edge)) => {
                edge.invocation_policy.as_ref()
            }
            _ => None,
        },
        Caller::Command { name } => match command.from.get(name.as_str()) {
            Some(crate::command_policy::CommandFromConfig::Edge(edge)) => {
                edge.invocation_policy.as_ref()
            }
            _ => None,
        },
    }
}

// ── Caller helpers ────────────────────────────────────────────────────────

fn caller_label(caller: &Caller) -> String {
    match caller {
        Caller::Session => "session".to_string(),
        Caller::Command { name } => name.clone(),
    }
}

fn caller_kind(caller: Option<&Caller>) -> String {
    match caller {
        Some(Caller::Session) => "session".to_string(),
        Some(Caller::Command { .. }) => "command".to_string(),
        None => "untrusted".to_string(),
    }
}

fn caller_command(caller: Option<&Caller>) -> Option<String> {
    match caller {
        Some(Caller::Command { name }) => Some(name.clone()),
        Some(Caller::Session) | None => None,
    }
}

// ── Approval timeout ──────────────────────────────────────────────────────

fn run_with_timeout<F>(timeout: std::time::Duration, f: F) -> Result<nono::ApprovalDecision>
where
    F: FnOnce() -> Result<nono::ApprovalDecision> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Ok(nono::ApprovalDecision::Denied {
            reason: "approval timeout".to_string(),
        }),
    }
}

// ── Audit ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn record_command_policy_audit(
    recorder: Option<&Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
    request: &ToolSandboxShimRequest,
    redaction_policy: &nono::ScrubPolicy,
    session_id: &str,
    peer_pid: u32,
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
        peer_pid,
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
    recorder: Option<&Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
    request: &ToolSandboxShimRequest,
    redaction_policy: &nono::ScrubPolicy,
    session_id: &str,
    peer_pid: u32,
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
        caller_pid: Some(peer_pid),
        shim_pid: Some(peer_pid),
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

// ── Plan resolution helpers ───────────────────────────────────────────────

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
        let canonical = PathBuf::from(dir).canonicalize().map_err(|source| {
            NonoError::PathCanonicalization {
                path: PathBuf::from(dir),
                source,
            }
        })?;
        if !canonical.is_dir() {
            return Err(NonoError::ExpectedDirectory(canonical));
        }
        let metadata = fs::metadata(&canonical).map_err(|source| NonoError::ConfigRead {
            path: canonical.clone(),
            source,
        })?;
        reject_group_or_world_writable_path(
            &canonical,
            &metadata,
            "tool-sandbox executable directory",
        )?;
        if outer_caps_grant_write(outer_caps, &canonical) {
            return Err(NonoError::SandboxInit(format!(
                "tool-sandbox executable directory is writable by the outer session capability set: {}",
                canonical.display()
            )));
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
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
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

// ── Runtime dir + socket ──────────────────────────────────────────────────

fn create_runtime_dir() -> Result<PathBuf> {
    let base = if Path::new("/private/tmp").is_dir() {
        PathBuf::from("/private/tmp")
    } else {
        std::env::temp_dir()
    };
    for _ in 0..32 {
        let path = unique_runtime_path(&base, "nono-tool-sandbox", "");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(NonoError::ConfigWrite { path, source });
            }
        }
    }
    Err(NonoError::SandboxInit(
        "failed to allocate tool-sandbox runtime dir".to_string(),
    ))
}

fn bind_runtime_socket(socket_path: &Path) -> Result<UnixListener> {
    if socket_path.exists() {
        return Err(NonoError::SandboxInit(format!(
            "tool-sandbox runtime socket already exists: {}",
            socket_path.display()
        )));
    }
    let listener = UnixListener::bind(socket_path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "tool-sandbox: bind socket {}: {e}",
            socket_path.display()
        ))
    })?;
    listener.set_nonblocking(true).map_err(|e| {
        NonoError::SandboxInit(format!(
            "tool-sandbox: set nonblocking on socket {}: {e}",
            socket_path.display()
        ))
    })?;
    Ok(listener)
}

fn guarded_remove_runtime_dir(dir: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(NonoError::ConfigRead {
                path: dir.to_path_buf(),
                source,
            });
        }
    };
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != unsafe { libc::geteuid() }
        || (meta.permissions().mode() & 0o077) != 0
    {
        return Err(NonoError::SandboxInit(format!(
            "unsafe tool-sandbox runtime dir shape: {}",
            dir.display()
        )));
    }
    let file_name = dir.file_name().and_then(|name| name.to_str()).unwrap_or("");
    if !file_name.starts_with("nono-tool-sandbox-") {
        return Err(NonoError::SandboxInit(format!(
            "refusing to clean non-tool-sandbox dir {}",
            dir.display()
        )));
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
        NonoError::ConfigWrite {
            path: dir.to_path_buf(),
            source: e,
        }
    })?;
    fs::remove_dir_all(dir).map_err(|e| NonoError::ConfigWrite {
        path: dir.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

fn create_shim_dir(runtime_dir: &Path) -> Result<PathBuf> {
    let shim_dir = runtime_dir.join("shims");
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&shim_dir)
        .map_err(|e| NonoError::ConfigWrite {
            path: shim_dir.clone(),
            source: e,
        })?;
    Ok(shim_dir)
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

struct RuntimeDirCleanup {
    path: PathBuf,
    armed: bool,
}

impl RuntimeDirCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RuntimeDirCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = guarded_remove_runtime_dir(&self.path);
        }
    }
}

// ── Shim materialisation ──────────────────────────────────────────────────

fn materialize_shim_source(runtime_dir: &Path) -> Result<PathBuf> {
    let nono_exe = std::env::current_exe()
        .map_err(|e| NonoError::SandboxInit(format!("tool-sandbox: current_exe failed: {e}")))?;
    let dest = runtime_dir.join("nono-shim-src");
    fs::copy(&nono_exe, &dest).map_err(|e| NonoError::ConfigWrite {
        path: dest.clone(),
        source: e,
    })?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o500)).map_err(|e| {
        NonoError::ConfigWrite {
            path: dest.clone(),
            source: e,
        }
    })?;
    Ok(dest)
}

fn materialize_shim(shim_source: &Path, runtime_dir: &Path, name: &str) -> Result<ShimIdentity> {
    let shim_path = runtime_dir.join(name);
    // macOS proc_pidpath may report any sibling hardlink for a shared inode,
    // so each shim must be a distinct copied file for command authentication.
    fs::copy(shim_source, &shim_path).map_err(|e| NonoError::ConfigWrite {
        path: shim_path.clone(),
        source: e,
    })?;
    fs::set_permissions(&shim_path, fs::Permissions::from_mode(0o500)).map_err(|e| {
        NonoError::ConfigWrite {
            path: shim_path.clone(),
            source: e,
        }
    })?;
    // Canonicalize so the registered path matches what proc_pidpath returns
    // on macOS (/var/folders is a symlink to /private/var/folders).
    let canonical_path = shim_path.canonicalize().unwrap_or(shim_path.clone());
    let meta = fs::metadata(&canonical_path).map_err(|e| NonoError::ConfigRead {
        path: canonical_path.clone(),
        source: e,
    })?;
    Ok(ShimIdentity {
        path: canonical_path,
        id: file_id(&meta),
    })
}

fn seal_shim_dir(shim_dir: &Path) -> Result<()> {
    fs::set_permissions(shim_dir, fs::Permissions::from_mode(0o500)).map_err(|e| {
        NonoError::ConfigWrite {
            path: shim_dir.to_path_buf(),
            source: e,
        }
    })
}

// ── Credentials ───────────────────────────────────────────────────────────

// ── Platform requirements ─────────────────────────────────────────────────

fn validate_platform_requirements(_config: &CommandPoliciesConfig) -> Result<()> {
    // macOS tool-sandbox v2: no Landlock probing needed. Seatbelt is always available.
    Ok(())
}

// ── IPC framing ───────────────────────────────────────────────────────────

fn is_tty(fd: i32) -> bool {
    // SAFETY: isatty is async-signal-safe and always returns 0 or 1.
    unsafe { libc::isatty(fd) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_policy::{
        CommandEnvironmentConfig, CommandFromConfig, CommandPolicyConfig, ResolvedExecutableKind,
        ResolvedExecutableShape,
    };

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
                kind: ResolvedExecutableKind::Other,
                interpreter: None,
                interpreter_args: vec![],
            },
        })
    }

    fn test_state() -> ToolSandboxState {
        let runtime_dir = PathBuf::from("/tmp/nono-tool-sandbox-test");
        let shim_dir = runtime_dir.join("shims");
        ToolSandboxState {
            runtime_dir: runtime_dir.clone(),
            socket_path: runtime_dir.join("supervisor.sock"),
            url_socket_path: None,
            shim_dir: shim_dir.clone(),
            url_open_shim: None,
            session_path: format!("{}:/usr/bin", shim_dir.display()),
            profile_display_name: None,
            redaction_policy: nono::ScrubPolicy::secure_default(),
            policy_root: PathBuf::from("/tmp"),
            plan: ResolvedToolSandboxPlan {
                config: CommandPoliciesConfig::default(),
                resolved: ResolvedCommandBinaries {
                    commands: BTreeMap::new(),
                    warnings: Vec::new(),
                },
                deny_only: BTreeMap::new(),
                allowed_direct_bypass_ids: HashSet::new(),
            },
            shims_by_command: BTreeMap::new(),
            shims_by_path: BTreeMap::new(),
            credential_handles: BTreeMap::new(),
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

    fn request_with_env(env: Vec<Vec<u8>>) -> ToolSandboxShimRequest {
        ToolSandboxShimRequest {
            command: "git".to_string(),
            argv: vec![b"git".to_vec()],
            env,
            cwd: b"/tmp".to_vec(),
            stdio_tty: [false; 3],
        }
    }

    #[test]
    fn command_policy_audit_records_macos_event() -> Result<()> {
        let temp = test_tempdir()?;
        let recorder = crate::audit_integrity::AuditRecorder::new(temp.path().to_path_buf())?;
        let recorder = Arc::new(Mutex::new(recorder));
        let mut redactions = nono::ScrubPolicy::secure_default();
        redactions.add_env_var("CONFIGURED_ENV");
        let request = ToolSandboxShimRequest {
            command: "terraform".to_string(),
            argv: vec![b"terraform".to_vec(), b"plan".to_vec()],
            env: vec![
                b"PATH=/bin".to_vec(),
                b"OBSERVED_ENV=value".to_vec(),
                b"CONFIGURED_ENV=redacted-value".to_vec(),
                b"OPENAI_API_KEY=provider-secret".to_vec(),
            ],
            cwd: b"/tmp/work".to_vec(),
            stdio_tty: [false; 3],
        };

        record_command_policy_audit(
            Some(&recorder),
            &request,
            &redactions,
            "sess-1",
            42,
            41,
            Some(&Caller::Command {
                name: "claude".to_string(),
            }),
            "invocation_approve_granted",
            None,
            Some(0),
        )?;

        let path = temp
            .path()
            .join(crate::audit_integrity::AUDIT_EVENTS_FILENAME);
        let contents = fs::read_to_string(&path).map_err(|source| NonoError::ConfigRead {
            path: path.clone(),
            source,
        })?;
        let line = contents.lines().next().ok_or_else(|| {
            NonoError::Snapshot("missing command policy audit record".to_string())
        })?;
        let record: serde_json::Value = serde_json::from_str(line).map_err(|err| {
            NonoError::Snapshot(format!("invalid command policy audit record: {err}"))
        })?;

        assert_eq!(record["event"]["type"], "command_policy");
        assert_eq!(record["event"]["event"]["command"], "terraform");
        assert_eq!(record["event"]["event"]["caller"], "claude");
        assert_eq!(record["event"]["event"]["caller_kind"], "command");
        assert_eq!(record["event"]["event"]["caller_command"], "claude");
        assert_eq!(
            record["event"]["event"]["decision"],
            "invocation_approve_granted"
        );
        assert_eq!(record["event"]["event"]["shim_pid"], 42);
        assert_eq!(record["event"]["event"]["session_root_pid"], 41);
        assert_eq!(record["event"]["event"]["argv_display"][1], "plan");
        assert_eq!(
            record["event"]["event"]["env_names_display"][1],
            "OBSERVED_ENV"
        );
        assert_eq!(
            record["event"]["event"]["env_display"][1]["value_display"],
            "value"
        );
        assert_eq!(
            record["event"]["event"]["env_display"][2]["name"],
            "[REDACTED]"
        );
        assert_eq!(
            record["event"]["event"]["env_display"][2]["value_display"],
            "[REDACTED]"
        );
        assert_eq!(
            record["event"]["event"]["env_names_display"][3],
            "[REDACTED]"
        );
        assert_eq!(
            record["event"]["event"]["env_display"][3]["name"],
            "[REDACTED]"
        );
        assert_eq!(
            record["event"]["event"]["env_display"][3]["value_display"],
            "[REDACTED]"
        );
        assert_eq!(record["event"]["event"]["cwd_display"], "/tmp/work");
        Ok(())
    }

    fn policy_with_env(
        allow_vars: Option<Vec<String>>,
        set_vars: BTreeMap<String, String>,
    ) -> CommandSandboxConfig {
        CommandSandboxConfig {
            environment: Some(CommandEnvironmentConfig {
                allow_vars,
                set_vars,
            }),
            ..CommandSandboxConfig::default()
        }
    }

    fn contains_entry(env: &[Vec<u8>], expected: &[u8]) -> bool {
        env.iter().any(|entry| entry.as_slice() == expected)
    }

    fn contains_prefix(env: &[Vec<u8>], prefix: &[u8]) -> bool {
        env.iter().any(|entry| entry.starts_with(prefix))
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

    fn create_dir_all(path: &Path) -> Result<()> {
        fs::create_dir_all(path).map_err(|source| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        })
    }

    fn create_executable(path: &Path) -> Result<()> {
        File::create(path).map_err(|source| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        })?;
        set_mode(path, 0o700)
    }

    fn set_mode(path: &Path, mode: u32) -> Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
            NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source,
            }
        })
    }

    fn symlink_path(target: &Path, link: &Path) -> Result<()> {
        std::os::unix::fs::symlink(target, link).map_err(|source| NonoError::ConfigWrite {
            path: link.to_path_buf(),
            source,
        })
    }

    fn create_python_framework_tree(temp: &Path) -> Result<(PathBuf, PathBuf)> {
        let version_dir = temp
            .join("Frameworks")
            .join("Python.framework")
            .join("Versions")
            .join("3.14");
        let bin_dir = version_dir.join("bin");
        let bundle_dir = version_dir
            .join("Resources")
            .join("Python.app")
            .join("Contents")
            .join("MacOS");
        create_dir_all(&bin_dir)?;
        create_dir_all(&bundle_dir)?;

        let interpreter = bin_dir.join("python3.14");
        let bundle = bundle_dir.join("Python");
        create_executable(&interpreter)?;
        create_executable(&bundle)?;
        Ok((interpreter, bundle))
    }

    fn with_interpreter(
        mut binary: ResolvedCommandBinary,
        interpreter: PathBuf,
    ) -> ResolvedCommandBinary {
        binary.shape = ResolvedExecutableShape {
            kind: ResolvedExecutableKind::ShebangScript,
            interpreter: Some(interpreter),
            interpreter_args: vec![],
        };
        binary
    }

    fn has_read_file_cap(caps: &CapabilitySet, path: &Path) -> Result<bool> {
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(caps
            .fs_capabilities()
            .iter()
            .any(|cap| cap.resolved == canonical && cap.is_file && cap.access == AccessMode::Read))
    }

    fn has_exec_rule(caps: &CapabilitySet, path: &Path) -> Result<bool> {
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source,
            })?;
        let escaped =
            crate::policy::escape_seatbelt_path(crate::policy::path_to_utf8(&canonical)?)?;
        let expected = format!("(allow process-exec* (literal \"{escaped}\"))");
        Ok(caps.platform_rules().iter().any(|rule| rule == &expected))
    }

    #[test]
    fn outer_caps_grant_cwd_metadata_without_recursive_workdir_read() -> Result<()> {
        let temp = test_tempdir()?;
        let workdir = temp.path().join("workspace");
        create_dir(&workdir)?;
        let policy_root =
            workdir
                .canonicalize()
                .map_err(|source| NonoError::PathCanonicalization {
                    path: workdir.clone(),
                    source,
                })?;
        let mut caps = CapabilitySet::new();
        add_macos_cwd_metadata_rules(&mut caps, &policy_root)?;

        assert!(
            caps.fs_capabilities().is_empty(),
            "cwd traversal must be represented as metadata-only platform rules, not filesystem read caps"
        );

        let escaped =
            crate::policy::escape_seatbelt_path(crate::policy::path_to_utf8(&policy_root)?)?;
        assert!(caps.platform_rules().contains(&format!(
            "(allow file-read-metadata (literal \"{escaped}\"))"
        )));
        Ok(())
    }

    #[test]
    fn process_exec_gate_denies_by_default_and_allows_exact_paths() -> Result<()> {
        let mut caps = CapabilitySet::new();
        add_process_exec_gate(&mut caps, vec![PathBuf::from("/bin/sh")])?;

        let rules = caps.platform_rules();
        assert!(
            rules
                .iter()
                .any(|rule| rule.as_str() == "(deny process-exec*)")
        );
        assert!(
            rules
                .iter()
                .any(|rule| rule.as_str() == "(allow process-exec* (literal \"/bin/sh\"))")
        );
        if Path::new("/bin/bash").exists() {
            assert!(
                rules
                    .iter()
                    .any(|rule| rule.as_str() == "(allow process-exec* (literal \"/bin/bash\"))")
            );
        }
        if Path::new("/private/var/select/sh").exists() {
            assert!(rules.iter().any(|rule| {
                rule.as_str() == "(allow process-exec* (literal \"/private/var/select/sh\"))"
            }));
        }
        Ok(())
    }

    #[test]
    fn python_framework_app_bundle_path_requires_framework_interpreter_shape() {
        let interpreter = Path::new(
            "/opt/homebrew/Cellar/python@3.14/3.14.5/Frameworks/Python.framework/Versions/3.14/bin/python3.14",
        );
        assert_eq!(
            python_framework_app_bundle_path(interpreter),
            Some(PathBuf::from(
                "/opt/homebrew/Cellar/python@3.14/3.14.5/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python"
            ))
        );

        assert_eq!(
            python_framework_app_bundle_path(Path::new("/opt/homebrew/bin/python3")),
            None
        );
        assert_eq!(
            python_framework_app_bundle_path(Path::new(
                "/opt/homebrew/Frameworks/Python.framework/Versions/3.14/bin/ruby"
            )),
            None
        );
        assert_eq!(
            python_framework_app_bundle_path(Path::new(
                "/opt/homebrew/Frameworks/Other.framework/Versions/3.14/bin/python3.14"
            )),
            None
        );
    }

    #[test]
    fn executable_shape_baseline_grants_python_framework_app_bundle_read() -> Result<()> {
        let temp = test_tempdir()?;
        let command = temp.path().join("tool");
        create_executable(&command)?;
        let (interpreter, bundle) = create_python_framework_tree(temp.path())?;
        let binary = with_interpreter(test_binary("tool", &command)?, interpreter.clone());

        let mut caps = CapabilitySet::new();
        add_executable_shape_baseline(&mut caps, &binary)?;

        assert!(has_read_file_cap(&caps, &interpreter)?);
        assert!(has_read_file_cap(&caps, &bundle)?);
        Ok(())
    }

    #[test]
    fn executable_shape_baseline_ignores_missing_python_framework_app_bundle() -> Result<()> {
        let temp = test_tempdir()?;
        let command = temp.path().join("tool");
        create_executable(&command)?;
        let (interpreter, bundle) = create_python_framework_tree(temp.path())?;
        fs::remove_file(&bundle).map_err(|source| NonoError::ConfigWrite {
            path: bundle.clone(),
            source,
        })?;
        let binary = with_interpreter(test_binary("tool", &command)?, interpreter.clone());

        let mut caps = CapabilitySet::new();
        add_executable_shape_baseline(&mut caps, &binary)?;

        assert!(has_read_file_cap(&caps, &interpreter)?);
        assert!(!has_read_file_cap(&caps, &bundle).unwrap_or(false));
        Ok(())
    }

    #[test]
    fn child_exec_gate_allows_python_framework_app_bundle_exec() -> Result<()> {
        let temp = test_tempdir()?;
        let command = temp.path().join("tool");
        create_executable(&command)?;
        let (interpreter, bundle) = create_python_framework_tree(temp.path())?;
        let binary = with_interpreter(test_binary("tool", &command)?, interpreter.clone());

        let state = test_state();
        let mut caps = CapabilitySet::new();
        add_child_process_exec_gate_with_policy(&mut caps, &state, &binary, None)?;

        assert!(
            caps.platform_rules()
                .iter()
                .any(|rule| rule.as_str() == "(deny process-exec*)")
        );
        assert!(has_exec_rule(&caps, &command)?);
        assert!(has_exec_rule(&caps, &interpreter)?);
        assert!(has_exec_rule(&caps, &bundle)?);
        Ok(())
    }

    #[test]
    fn outer_process_exec_gate_allows_exec_but_denies_controlled_paths() -> Result<()> {
        let temp = test_tempdir()?;
        let bin_dir = temp.path().join("bin");
        create_dir(&bin_dir)?;

        let controlled = bin_dir.join("git");
        create_executable(&controlled)?;
        set_mode(&bin_dir, 0o500)?;

        let mut state = test_state();
        state
            .plan
            .resolved
            .commands
            .insert("git".to_string(), test_binary("git", &controlled)?);
        let mut caps = CapabilitySet::new();
        add_outer_process_exec_gate(&mut caps, &state)?;

        let rules = caps.platform_rules();
        assert!(
            rules
                .iter()
                .any(|rule| rule.as_str() == "(allow process-exec*)")
        );
        assert!(
            rules
                .iter()
                .any(|rule| rule.contains("deny file-read-data") && rule.contains("/git"))
        );
        Ok(())
    }

    #[test]
    fn command_search_dirs_skip_unsafe_implicit_path_dirs() -> Result<()> {
        let temp = test_tempdir()?;
        let bin_dir = temp.path().join("bin");
        create_dir(&bin_dir)?;
        set_mode(&bin_dir, 0o777)?;

        let caps = CapabilitySet::new();
        let implicit_dirs = command_search_dirs(
            &CommandPoliciesConfig::default(),
            Some(bin_dir.as_os_str().to_os_string()),
            &caps,
        )?;
        assert!(implicit_dirs.is_empty());

        let config = CommandPoliciesConfig {
            executable_dirs: vec![bin_dir.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let err = command_search_dirs(&config, None, &caps)
            .err()
            .ok_or_else(|| {
                NonoError::SandboxInit("expected explicit executable_dir rejection".to_string())
            })?;
        assert!(err.to_string().contains("group/world writable"));

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
    fn exec_gate_allows_non_controlled_initial_exec() {
        let id = FileId { dev: 42, ino: 7 };
        let result = check_exec_gate(
            &HashSet::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            "/usr/bin/env",
            Path::new("/usr/bin/env"),
            id,
        );
        assert!(result.is_none());
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
    fn child_cap_spec_preserves_platform_exec_gate() -> Result<()> {
        let mut caps = CapabilitySet::new();
        add_process_exec_gate(&mut caps, vec![PathBuf::from("/bin/sh")])?;

        let spec = caps_to_spec(&caps);
        assert!(
            spec.platform_rules
                .iter()
                .any(|rule| rule.as_str() == "(deny process-exec*)")
        );

        let restored = caps_from_spec(&spec)?;
        assert!(
            restored
                .platform_rules()
                .iter()
                .any(|rule| rule.as_str() == "(deny process-exec*)")
        );
        Ok(())
    }

    #[test]
    fn macos_runtime_baseline_does_not_grant_system_volumes_data() -> Result<()> {
        let mut caps = CapabilitySet::new();
        add_macos_runtime_baseline(&mut caps)?;

        let system_volumes = Path::new("/System/Volumes");
        let system_volumes_data = Path::new("/System/Volumes/Data");
        for cap in caps.fs_capabilities() {
            assert_ne!(
                cap.original, system_volumes,
                "runtime baseline must not grant recursive read of /System/Volumes"
            );
            assert_ne!(
                cap.resolved, system_volumes,
                "runtime baseline must not grant recursive read of /System/Volumes"
            );
            assert!(
                !cap.original.starts_with(system_volumes_data),
                "runtime baseline must not grant paths under /System/Volumes/Data: {}",
                cap.original.display()
            );
            assert!(
                !cap.resolved.starts_with(system_volumes_data),
                "runtime baseline must not grant paths under /System/Volumes/Data: {}",
                cap.resolved.display()
            );
            assert!(
                cap.is_file
                    || (!system_volumes_data.starts_with(&cap.original)
                        && !system_volumes_data.starts_with(&cap.resolved)),
                "runtime baseline directory grant covers /System/Volumes/Data: original={}, resolved={}",
                cap.original.display(),
                cap.resolved.display()
            );
        }

        if Path::new("/System/Cryptexes/OS").is_dir() {
            let cryptex_os =
                Path::new("/System/Cryptexes/OS")
                    .canonicalize()
                    .map_err(|source| NonoError::PathCanonicalization {
                        path: PathBuf::from("/System/Cryptexes/OS"),
                        source,
                    })?;
            assert!(
                caps.fs_capabilities().iter().any(|cap| {
                    cap.original == Path::new("/System/Cryptexes/OS") && cap.resolved == cryptex_os
                }),
                "runtime baseline should grant the explicit OS cryptex path instead of /System/Volumes"
            );
        }

        Ok(())
    }

    #[test]
    fn materialized_shims_have_distinct_inodes() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| NonoError::ConfigWrite {
            path: PathBuf::from("/tmp"),
            source,
        })?;
        let source_path = dir.path().join("shim-source");
        fs::write(&source_path, b"shim").map_err(|source| NonoError::ConfigWrite {
            path: source_path.clone(),
            source,
        })?;
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o500)).map_err(|source| {
            NonoError::ConfigWrite {
                path: source_path.clone(),
                source,
            }
        })?;

        let first = materialize_shim(&source_path, dir.path(), "awk")?;
        let second = materialize_shim(&source_path, dir.path(), "xargs")?;

        assert_ne!(first.id, second.id);
        Ok(())
    }

    #[test]
    fn selected_stdio_mode_uses_supervisor_direct_fds() {
        let request = request_with_env(Vec::new());
        assert_eq!(selected_stdio_mode(&request), "direct_fds");
    }

    #[test]
    fn resolve_caller_prefers_active_command_for_peer_pid() -> Result<()> {
        let state = test_state();
        let pid = std::process::id();
        track_child(&state, pid, "git", &Caller::Session)?;

        let caller = resolve_caller(pid, pid, &state, "ssh")?;

        assert!(matches!(caller, Caller::Command { name } if name == "git"));
        Ok(())
    }

    #[test]
    fn resolve_caller_uses_launch_caller_for_self_invocation() -> Result<()> {
        let state = test_state();
        let pid = std::process::id();
        track_child(&state, pid, "git", &Caller::Session)?;

        let caller = resolve_caller(pid, pid, &state, "git")?;

        assert!(matches!(caller, Caller::Session));
        Ok(())
    }

    #[test]
    fn resolve_caller_honors_explicit_self_edge() -> Result<()> {
        let mut state = test_state();
        state.plan.config.commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                can_use: vec!["git".to_string()],
                ..Default::default()
            },
        );
        let pid = std::process::id();
        track_child(&state, pid, "git", &Caller::Session)?;

        let caller = resolve_caller(pid, pid, &state, "git")?;

        assert!(matches!(caller, Caller::Command { name } if name == "git"));
        Ok(())
    }

    #[test]
    fn filter_child_env_uses_safe_default_and_chaining_env() -> Result<()> {
        let state = test_state();
        let request = request_with_env(vec![
            b"PATH=/usr/bin".to_vec(),
            b"HOME=/Users/test".to_vec(),
            b"CUSTOM=value".to_vec(),
            b"LD_PRELOAD=/evil.dylib".to_vec(),
            b"NONO_TOOL_SANDBOX_SOCKET=/old.sock".to_vec(),
            b"NONO_TOOL_SANDBOX_LAUNCH_SPEC=/old.json".to_vec(),
        ]);

        let env = filter_child_env(&state, &request, &CommandSandboxConfig::default())?;

        assert!(contains_entry(&env, b"HOME=/Users/test"));
        assert!(contains_entry(
            &env,
            format!("PATH={}", state.session_path).as_bytes()
        ));
        assert!(contains_entry(
            &env,
            format!("{TOOL_SANDBOX_SOCKET_ENV}={}", state.socket_path.display()).as_bytes()
        ));
        assert!(contains_entry(
            &env,
            format!("{TOOL_SANDBOX_SHIM_DIR_ENV}={}", state.shim_dir.display()).as_bytes()
        ));
        assert!(!contains_prefix(&env, b"CUSTOM="));
        assert!(!contains_prefix(&env, b"LD_PRELOAD="));
        assert!(!contains_entry(&env, b"NONO_TOOL_SANDBOX_SOCKET=/old.sock"));
        assert!(!contains_entry(
            &env,
            b"NONO_TOOL_SANDBOX_LAUNCH_SPEC=/old.json"
        ));

        Ok(())
    }

    #[test]
    fn filter_child_env_passes_tls_ca_vars_by_default() -> Result<()> {
        let bundle = "/tmp/intercept-ca.pem";
        let state = test_state();
        let request = request_with_env(vec![
            format!("SSL_CERT_FILE={bundle}").into_bytes(),
            format!("CURL_CA_BUNDLE={bundle}").into_bytes(),
            format!("NODE_EXTRA_CA_CERTS={bundle}").into_bytes(),
            format!("REQUESTS_CA_BUNDLE={bundle}").into_bytes(),
            format!("GIT_SSL_CAINFO={bundle}").into_bytes(),
            b"UNRELATED=should-be-stripped".to_vec(),
        ]);

        let env = filter_child_env(&state, &request, &CommandSandboxConfig::default())?;

        assert!(contains_entry(
            &env,
            format!("SSL_CERT_FILE={bundle}").as_bytes()
        ));
        assert!(contains_entry(
            &env,
            format!("CURL_CA_BUNDLE={bundle}").as_bytes()
        ));
        assert!(contains_entry(
            &env,
            format!("NODE_EXTRA_CA_CERTS={bundle}").as_bytes()
        ));
        assert!(contains_entry(
            &env,
            format!("REQUESTS_CA_BUNDLE={bundle}").as_bytes()
        ));
        assert!(contains_entry(
            &env,
            format!("GIT_SSL_CAINFO={bundle}").as_bytes()
        ));
        assert!(!contains_prefix(&env, b"UNRELATED="));

        Ok(())
    }

    #[test]
    fn filter_child_env_resolves_broker_nonces() -> Result<()> {
        let state = test_state();
        let nonce = {
            let mut broker = state.token_broker.lock().map_err(|_| {
                NonoError::SandboxInit("tool-sandbox token broker lock poisoned".to_string())
            })?;
            broker.issue(Zeroizing::new(b"s3cr3t".to_vec()))
        };
        let nonce_entry = format!("API_TOKEN={nonce}").into_bytes();
        let request = request_with_env(vec![nonce_entry.clone()]);
        let policy = policy_with_env(Some(vec!["API_TOKEN".to_string()]), BTreeMap::new());

        let env = filter_child_env(&state, &request, &policy)?;

        assert!(contains_entry(&env, b"API_TOKEN=s3cr3t"));
        assert!(!contains_entry(&env, &nonce_entry));

        Ok(())
    }

    #[test]
    fn filter_child_env_injects_schema2_local_socket_credential() -> Result<()> {
        let mut state = test_state();
        let socket_path = PathBuf::from("/tmp/nono-test-ssh-agent.sock");
        state.credential_handles.insert(
            "agent".to_string(),
            ResolvedCredential::LocalSocket {
                path: Some(socket_path.clone()),
                env_var: Some("SSH_AUTH_SOCK".to_string()),
                unavailable_reason: None,
            },
        );
        let policy = CommandSandboxConfig {
            credentials: vec![crate::command_policy::CommandCredentialGrantConfig::Name(
                "agent".to_string(),
            )],
            ..CommandSandboxConfig::default()
        };
        let request = request_with_env(Vec::new());

        let env = filter_child_env(&state, &request, &policy)?;

        assert!(contains_entry(
            &env,
            format!("SSH_AUTH_SOCK={}", socket_path.display()).as_bytes()
        ));
        Ok(())
    }

    #[test]
    fn session_caller_uses_command_sandbox_without_entrypoint() -> Result<()> {
        let sandbox = CommandSandboxConfig {
            fs_read: vec![".".to_string()],
            ..CommandSandboxConfig::default()
        };
        let mut config = CommandPoliciesConfig::default();
        config.commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                sandbox: Some(sandbox.clone()),
                ..CommandPolicyConfig::default()
            },
        );

        let selected = select_effective_policy(&config, "git", &Caller::Session)?;

        assert_eq!(selected.fs_read, sandbox.fs_read);
        Ok(())
    }

    #[test]
    fn session_caller_prefers_from_session_edge_without_entrypoint() -> Result<()> {
        let root_sandbox = CommandSandboxConfig {
            fs_read: vec!["root".to_string()],
            ..CommandSandboxConfig::default()
        };
        let edge_sandbox = CommandSandboxConfig {
            fs_read: vec!["edge".to_string()],
            ..CommandSandboxConfig::default()
        };
        let mut config = CommandPoliciesConfig::default();
        config.commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                sandbox: Some(root_sandbox),
                from: BTreeMap::from([(
                    "session".to_string(),
                    CommandFromConfig::Policy(Box::new(edge_sandbox.clone())),
                )]),
                ..CommandPolicyConfig::default()
            },
        );

        let selected = select_effective_policy(&config, "git", &Caller::Session)?;

        assert_eq!(selected.fs_read, edge_sandbox.fs_read);
        Ok(())
    }

    #[test]
    fn apply_environment_set_vars_rejects_reserved_and_dangerous_names() {
        let mut reserved = BTreeMap::new();
        reserved.insert(
            "NONO_TOOL_SANDBOX_SOCKET".to_string(),
            "/tmp/socket".to_string(),
        );
        let reserved_policy = policy_with_env(None, reserved);
        assert!(apply_environment_set_vars(&mut vec![], &reserved_policy).is_err());

        let mut dangerous = BTreeMap::new();
        dangerous.insert(
            "DYLD_INSERT_LIBRARIES".to_string(),
            "/evil.dylib".to_string(),
        );
        let dangerous_policy = policy_with_env(None, dangerous);
        assert!(apply_environment_set_vars(&mut vec![], &dangerous_policy).is_err());
    }
}
