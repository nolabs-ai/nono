//! Ephemeral Tool Isolation runtime support.
//!
//! The profile resolver lives in `command_policy`; this module owns the
//! Linux-only runtime pieces: private shim materialisation, the outer exec
//! Landlock gate, shim IPC, caller resolution, and brokered command launch.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) struct PreparedEtiRuntime;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl PreparedEtiRuntime {
    pub(crate) fn emitted_error_response(&self) -> bool {
        false
    }

    pub(crate) fn cleanup_runtime_dir(&self) {}
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn maybe_run_internal_eti_entrypoint() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn record_main_start() {}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn log_main_total() {}

#[cfg(target_os = "linux")]
mod linux {
    use crate::audit_integrity::{AuditRecorder, CommandPolicyAuditEvent};
    use crate::command_policy::{
        CommandCredentialConfig, CommandCredentialType, CommandFromConfig, CommandPoliciesConfig,
        CommandSandboxConfig, ResolvedCommandBinaries, ResolvedCommandBinary,
        ResolvedExecutableKind,
    };
    use crate::profile;
    use landlock::{
        Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr,
    };
    use nix::libc;
    use nono::supervisor::socket::{peer_credentials, recv_fd_via_socket, send_fd_via_socket};
    use nono::{
        AccessMode, CapabilitySet, FsCapability, NetworkMode, NonoError, Result, Sandbox,
        UnixSocketCapability, UnixSocketMode,
    };
    use rand::Rng;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{
        DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
    };
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::{debug, warn};

    pub(crate) const ETI_SOCKET_ENV: &str = "NONO_ETI_SOCKET";
    pub(crate) const ETI_SHIM_DIR_ENV: &str = "NONO_ETI_SHIM_DIR";
    pub(crate) const ETI_LAUNCH_SPEC_ENV: &str = "NONO_ETI_LAUNCH_SPEC";
    /// Diagnostic-only: parent's CLOCK_MONOTONIC nanos at the latest pre-fork point.
    /// Set by exec_strategy on the supervised child's exec env when ETI_PROFILE_HOTPATH
    /// is active, read by run_shim() on entry to measure shim Rust-runtime startup.
    pub(crate) const ETI_PARENT_MONOTONIC_ENV: &str = "NONO_ETI_PARENT_MONOTONIC";

    const MAX_FRAME: usize = 1024 * 1024;
    const MAX_ARGC: usize = 4096;
    const MAX_ARG: usize = 128 * 1024;
    const MAX_ENV: usize = 4096;
    const MAX_ENV_ENTRY: usize = 128 * 1024;
    const MAX_CWD: usize = 4096;
    const MAX_ACTIVE_ETI_CHILDREN: usize = 64;
    // Max raw bytes the Capture action may buffer before broker scanning.
    // Each byte serialises to ~4 chars in JSON; 256 KiB raw → ~1 MiB frame.
    const MAX_CAPTURE_STDOUT: usize = 256 * 1024;
    const MAX_QUEUED_SHIM_REQUESTS: usize = 128;
    const ANCESTRY_DEPTH_LIMIT: usize = 64;

    const DEFAULT_ENV_ALLOW: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "COLORTERM",
        "LANG",
        "LC_*",
        "TZ",
    ];

    macro_rules! eti_profile_log {
        ($($arg:tt)*) => {
            if std::env::var_os("ETI_PROFILE_HOTPATH").is_some() {
                eprintln!("[eti-prof] {}", format_args!($($arg)*));
            }
        };
    }

    pub(crate) static MAIN_START: std::sync::OnceLock<std::time::Instant> =
        std::sync::OnceLock::new();

    pub(crate) fn record_main_start() {
        if std::env::var_os("ETI_PROFILE_HOTPATH").is_some() {
            let _ = MAIN_START.get_or_init(std::time::Instant::now);
        }
    }

    pub(crate) fn log_main_total() {
        if let Some(start) = MAIN_START.get() {
            eti_profile_log!("main_total: {:?}", start.elapsed());
        }
    }

    #[derive(Clone)]
    pub(crate) struct PreparedEtiRuntime {
        inner: Arc<EtiState>,
        listener: Arc<UnixListener>,
    }

    struct EtiState {
        runtime_dir: PathBuf,
        socket_path: PathBuf,
        shim_dir: PathBuf,
        session_path: String,
        policy_root: PathBuf,
        plan: ResolvedEtiPlan,
        shims_by_command: BTreeMap<String, ShimIdentity>,
        shims_by_path: BTreeMap<PathBuf, String>,
        credential_handles: BTreeMap<String, ResolvedCredential>,
        allowed_outer_exec_files: Vec<PathBuf>,
        baseline_cache: BaselineCache,
        active_children: Mutex<HashMap<u32, ActiveChild>>,
        active_count: AtomicUsize,
        queued_requests: AtomicUsize,
        emitted_error_response: AtomicBool,
        /// Token broker for credential isolation. Holds real credential values;
        /// nonces in the agent env are resolved to real values by filter_child_env.
        token_broker: Mutex<crate::eti_token_broker::TokenBroker>,
        /// Approval backend for the `Approve` intercept action.
        /// Defaults to `TerminalApproval`; callers may replace it before
        /// calling `handle_listener`.
        approval_backend: Arc<dyn nono::ApprovalBackend>,
    }

    /// Pre-computed runtime-baseline files (ELF dependency closures + system files)
    /// granted to every ETI child. Built once at supervisor startup so the per-request
    /// hot path does no recursive ELF parsing or directory walking.
    struct BaselineCache {
        closures: BTreeMap<PathBuf, Vec<PathBuf>>,
        system_files: Vec<(PathBuf, AccessMode)>,
    }

    struct ResolvedEtiPlan {
        config: CommandPoliciesConfig,
        resolved: ResolvedCommandBinaries,
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

    #[derive(Debug, Clone)]
    enum ResolvedCredential {
        SshAgent {
            socket: Option<PathBuf>,
            unavailable_reason: Option<String>,
        },
        RawFile {
            path: PathBuf,
        },
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct FileId {
        dev: u64,
        ino: u64,
    }

    #[derive(Debug)]
    enum Caller {
        Session { pid: u32 },
        Command { command: String, pid: u32 },
    }

    struct ActiveChild {
        command: String,
        pidfd: Option<OwnedFd>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct EtiShimRequest {
        command: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
        cwd: Vec<u8>,
        stdio_tty: [bool; 3],
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct EtiShimResponse {
        exit_code: i32,
        error: Option<String>,
        /// Captured stdout bytes for the `Capture` intercept action.
        /// Empty for `Passthrough` and `Respond` actions.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        captured_stdout: Vec<u8>,
        /// macOS Seatbelt extension tokens issued by the supervisor.
        /// Empty on Linux; populated on macOS for per-command capability grants.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extension_tokens: Vec<String>,
    }

    impl EtiShimResponse {
        fn ok(exit_code: i32) -> Self {
            Self {
                exit_code,
                error: None,
                captured_stdout: Vec::new(),
                extension_tokens: Vec::new(),
            }
        }

        fn err(exit_code: i32, error: String) -> Self {
            Self {
                exit_code,
                error: Some(error),
                captured_stdout: Vec::new(),
                extension_tokens: Vec::new(),
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct EtiChildLaunchSpec {
        real_binary: Vec<u8>,
        executable_kind: String,
        interpreter: Option<Vec<u8>>,
        interpreter_args: Vec<String>,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
        cwd: Vec<u8>,
        stdio_mode: String,
        caps: ChildCapsSpec,
        // Explicit execute allowlist applied as a second Landlock layer after
        // the main sandbox. AccessMode::Read includes AccessFs::Execute, so
        // fs_read/fs_write grants would otherwise let the child exec arbitrary
        // workspace binaries. This list restricts execute to the command binary,
        // interpreter (if any), and ETI shims only.
        allowed_exec_paths: Vec<Vec<u8>>,
        // Expected identity captured at plan-build time. The launcher opens
        // the binary with O_RDONLY|O_NOFOLLOW, verifies dev/ino/size/mtime/sha256
        // against these values, and execs via execveat on that fd to close the
        // path-based TOCTOU.
        expected_dev: u64,
        expected_ino: u64,
        expected_size: u64,
        expected_mtime_nanos: i128,
        expected_sha256: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct ChildCapsSpec {
        fs: Vec<FsGrantSpec>,
        unix_sockets: Vec<UnixSocketGrantSpec>,
        network_blocked: bool,
        tcp_connect_ports: Vec<u16>,
        tcp_bind_ports: Vec<u16>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct FsGrantSpec {
        path: Vec<u8>,
        access: String,
        is_file: bool,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct UnixSocketGrantSpec {
        path: Vec<u8>,
        mode: String,
        is_directory: bool,
    }

    struct StdioFds {
        stdin: OwnedFd,
        stdout: OwnedFd,
        stderr: OwnedFd,
    }

    impl ResolvedEtiPlan {
        fn build(
            config: &CommandPoliciesConfig,
            allowed_commands: &[String],
            blocked_commands: &[String],
            outer_caps: &CapabilitySet,
        ) -> Result<Self> {
            let path_env = std::env::var_os("PATH");
            let resolved =
                crate::command_policy::resolve_policy_command_binaries(config, path_env.clone())?;
            // Validate that PATH directories used by the deny_only resolver are
            // not group/world writable. We no longer sweep PATH into the outer
            // exec gate, but resolve_deny_only_commands still uses these dirs to
            // shadow dangerous binaries with deny shims, so the trust still
            // matters.
            let search_dirs = command_search_dirs(config, path_env)?;
            validate_trusted_executable_dirs(&search_dirs)?;
            let deny_only = resolve_deny_only_commands(config, blocked_commands, allowed_commands)?;
            validate_controlled_binary_immutability(&resolved, &deny_only, outer_caps)?;
            let governance_denies = resolve_governance_denies(config)?;
            let allowed_direct_bypasses =
                resolve_allowed_direct_bypasses(config, &resolved, &deny_only, &governance_denies)?;
            let allowed_direct_bypass_ids = resolve_file_ids(&allowed_direct_bypasses)?;
            Ok(Self {
                config: config.clone(),
                resolved,
                deny_only,
                allowed_direct_bypasses,
                allowed_direct_bypass_ids,
            })
        }
    }

    impl PreparedEtiRuntime {
        pub(crate) fn prepare(
            config: &CommandPoliciesConfig,
            allowed_commands: &[String],
            blocked_commands: &[String],
            outer_caps: &CapabilitySet,
            policy_root: &Path,
        ) -> Result<Self> {
            let start_total = std::time::Instant::now();
            if let Some(start) = MAIN_START.get() {
                eti_profile_log!("main_to_prepare: {:?}", start.elapsed());
            }

            let start_plan = std::time::Instant::now();
            let plan =
                ResolvedEtiPlan::build(config, allowed_commands, blocked_commands, outer_caps)?;
            eti_profile_log!(
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
            let shim_dir = runtime_dir.clone();
            let session_path = build_session_path(&shim_dir);
            eti_profile_log!(
                "prepare:runtime_dir_and_socket: {:?}",
                start_runtime_dir.elapsed()
            );

            let start_credentials = std::time::Instant::now();
            let credential_handles = resolve_credentials(&plan.config.credentials)?;
            eti_profile_log!(
                "prepare:resolve_credentials: {:?}",
                start_credentials.elapsed()
            );

            let start_shims = std::time::Instant::now();
            let mut shims_by_command = BTreeMap::new();
            let mut shims_by_path = BTreeMap::new();
            let mut shim_names: BTreeSet<String> = plan.resolved.commands.keys().cloned().collect();
            shim_names.extend(plan.deny_only.keys().cloned());
            let shim_source = materialize_shim_source(&runtime_dir)?;
            let shim_count = shim_names.len();
            for name in shim_names {
                let identity = materialize_shim(&shim_source, &runtime_dir, &name)?;
                shims_by_path.insert(identity.path.clone(), name.clone());
                shims_by_command.insert(name, identity);
            }
            eti_profile_log!(
                "prepare:materialize_shims: {:?} ({} shims)",
                start_shims.elapsed(),
                shim_count
            );

            let start_outer_exec = std::time::Instant::now();
            let allowed_outer_exec_files = build_outer_exec_files(
                shims_by_command.values(),
                &plan.allowed_direct_bypasses,
                &shim_source,
            )?;
            eti_profile_log!(
                "prepare:build_outer_exec_files: {:?} ({} paths)",
                start_outer_exec.elapsed(),
                allowed_outer_exec_files.len()
            );

            let start_baseline_cache = std::time::Instant::now();
            let baseline_cache = build_baseline_cache(&plan, &shims_by_command, &shim_source)?;
            eti_profile_log!(
                "build_baseline_cache: {:?} ({} closures cached)",
                start_baseline_cache.elapsed(),
                baseline_cache.closures.len()
            );

            let runtime = Self {
                inner: Arc::new(EtiState {
                    runtime_dir,
                    socket_path,
                    shim_dir,
                    session_path,
                    policy_root: policy_root.to_path_buf(),
                    plan,
                    shims_by_command,
                    shims_by_path,
                    credential_handles,
                    allowed_outer_exec_files,
                    baseline_cache,
                    active_children: Mutex::new(HashMap::new()),
                    active_count: AtomicUsize::new(0),
                    queued_requests: AtomicUsize::new(0),
                    emitted_error_response: AtomicBool::new(false),
                    token_broker: Mutex::new(crate::eti_token_broker::TokenBroker::new()),
                    approval_backend: Arc::new(crate::terminal_approval::TerminalApproval),
                }),
                listener: Arc::new(listener),
            };
            runtime_cleanup.disarm();
            eti_profile_log!("prepare:total: {:?}", start_total.elapsed());
            Ok(runtime)
        }

        /// Best-effort removal of the runtime dir. Safe to call multiple times and from
        /// any exit path: on the success path it must be invoked explicitly before
        /// `process::exit` (which bypasses Drop chains); on Rust unwind paths
        /// `EtiState::Drop` provides a fallback that finds a stale dir already gone.
        pub(crate) fn cleanup_runtime_dir(&self) {
            if let Err(err) = guarded_remove_runtime_dir(&self.inner.runtime_dir) {
                debug!(
                    "ETI runtime dir cleanup skipped for {}: {}",
                    self.inner.runtime_dir.display(),
                    err
                );
            }
        }

        pub(crate) fn env_overrides(&self) -> Vec<(String, String)> {
            vec![
                ("PATH".to_string(), self.inner.session_path.clone()),
                (
                    ETI_SOCKET_ENV.to_string(),
                    self.inner.socket_path.display().to_string(),
                ),
                (
                    ETI_SHIM_DIR_ENV.to_string(),
                    self.inner.shim_dir.display().to_string(),
                ),
            ]
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
            apply_outer_exec_gate(&self.inner.allowed_outer_exec_files)
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

        /// Default-deny gate for the initial command when ETI is active.
        ///
        /// Allowed cases:
        /// - bare command name (no `/`) that is a policy command — runs through its shim
        /// - any path or name whose canonical inode is in `allow_direct_exec_bypass`
        ///
        /// Everything else is rejected. In particular, this prevents
        /// `session_can_use` from being bypassed by invoking a non-policy
        /// executable on `PATH` (e.g. `python`, `node`, `openssl`) or by
        /// targeting a controlled / deny-only binary directly by path.
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

            let canonical = resolved_program.canonicalize().map_err(|source| {
                NonoError::PathCanonicalization {
                    path: resolved_program.to_path_buf(),
                    source,
                }
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
                            "ETI supervisor accept failed: {err}"
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
                    Some("ETI shim request queue limit exceeded".to_string()),
                    Vec::new(),
                )?;
                return Ok(());
            }
            let state = Arc::clone(&self.inner);
            let session_id = session_id.to_string();
            std::thread::spawn(move || {
                let result = handle_shim_stream(
                    state,
                    stream,
                    session_root_pid,
                    &session_id,
                    audit_recorder,
                );
                if let Err(err) = result {
                    warn!("ETI shim handling failed: {err}");
                }
            });
            Ok(())
        }
    }

    impl Drop for EtiState {
        fn drop(&mut self) {
            if let Err(err) = guarded_remove_runtime_dir(&self.runtime_dir) {
                debug!(
                    "ETI runtime dir cleanup skipped for {}: {err}",
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

    pub(crate) fn maybe_run_internal_eti_entrypoint() -> bool {
        if std::env::var_os(ETI_LAUNCH_SPEC_ENV).is_some() {
            exit_from_result(run_child_launcher());
            return true;
        }

        if std::env::var_os(ETI_SOCKET_ENV).is_some()
            && std::env::var_os(ETI_SHIM_DIR_ENV).is_some()
            && current_exe_is_eti_shim()
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
        let Some(parent) = std::env::var_os(ETI_PARENT_MONOTONIC_ENV) else {
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
        eti_profile_log!(
            "shim:cross_process_startup: {:?} (parent_pre_fork → shim entry)",
            dur
        );
    }

    fn current_exe_is_eti_shim() -> bool {
        let Some(shim_dir) = std::env::var_os(ETI_SHIM_DIR_ENV).map(PathBuf::from) else {
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
        let socket_path = std::env::var_os(ETI_SOCKET_ENV)
            .map(PathBuf::from)
            .ok_or_else(|| NonoError::SandboxInit("ETI shim socket env missing".to_string()))?;
        let command = std::env::current_exe()
            .ok()
            .and_then(|path| path.file_name().map(OsStr::to_os_string))
            .and_then(|name| name.into_string().ok())
            .ok_or_else(|| NonoError::SandboxInit("ETI shim command name invalid".to_string()))?;
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
            .map_err(|err| NonoError::SandboxInit(format!("ETI shim cwd failed: {err}")))?
            .into_os_string()
            .into_vec();
        eti_profile_log!(
            "shim:env_collect: {:?} ({} args, {} env entries)",
            start_env.elapsed(),
            argv.len(),
            env.len()
        );

        let request = EtiShimRequest {
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
                "ETI shim failed to connect to {}: {err}",
                socket_path.display()
            ))
        })?;
        eti_profile_log!("shim:socket_connect: {:?}", start_connect.elapsed());
        let start_send = std::time::Instant::now();
        write_frame(&mut stream, &request)?;
        send_stdio_fds(&stream)?;
        eti_profile_log!(
            "shim:send_request: {:?} (entry-to-request: {:?})",
            start_send.elapsed(),
            start_shim.elapsed()
        );
        let response: EtiShimResponse = read_frame(&mut stream)?;
        if let Some(error) = response.error {
            eprintln!("nono: ETI denied {}: {error}", request.command);
        }
        if !response.captured_stdout.is_empty() {
            use std::io::Write;
            let _ = std::io::stdout().write_all(&response.captured_stdout);
        }
        std::process::exit(response.exit_code);
    }

    fn run_child_launcher() -> Result<()> {
        let start_launcher = std::time::Instant::now();
        let spec_path = std::env::var_os(ETI_LAUNCH_SPEC_ENV)
            .map(PathBuf::from)
            .ok_or_else(|| NonoError::SandboxInit("ETI launch spec env missing".to_string()))?;
        let start_parse = std::time::Instant::now();
        let bytes = fs::read(&spec_path).map_err(|err| NonoError::ConfigRead {
            path: spec_path.clone(),
            source: err,
        })?;
        let spec: EtiChildLaunchSpec = serde_json::from_slice(&bytes).map_err(|err| {
            NonoError::ConfigParse(format!("failed to parse ETI launch spec: {err}"))
        })?;
        eti_profile_log!(
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
                        "ETI direct_fds setpgid failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
            }
            other => {
                return Err(NonoError::ConfigParse(format!(
                    "invalid ETI stdio mode '{other}'"
                )));
            }
        }
        let real_binary = OsString::from_vec(spec.real_binary.clone());
        let cwd = OsString::from_vec(spec.cwd.clone());
        std::env::set_current_dir(&cwd).map_err(|err| {
            NonoError::SandboxInit(format!("ETI child chdir failed before sandbox: {err}"))
        })?;

        // R3: Open the binary with O_RDONLY|O_NOFOLLOW, verify identity by
        // fstat'ing and hashing the SAME fd we will exec, then execveat via
        // that fd. The supervisor's earlier verify_binary_identity is only a
        // pre-flight; THIS check is the integrity boundary because the fd we
        // open here is the inode the kernel will execute (via AT_EMPTY_PATH).
        let start_verify = std::time::Instant::now();
        let binary_fd = open_and_verify_binary(&real_binary, &spec)?;
        eti_profile_log!("launcher:verify_binary_fd: {:?}", start_verify.elapsed());

        let start_caps_from = std::time::Instant::now();
        let caps = caps_from_spec(&spec.caps)?;
        eti_profile_log!("launcher:caps_from_spec: {:?}", start_caps_from.elapsed());
        let start_sandbox_apply = std::time::Instant::now();
        Sandbox::apply(&caps)?;
        eti_profile_log!(
            "launcher:sandbox_apply: {:?}",
            start_sandbox_apply.elapsed()
        );

        // Stack a second Landlock layer restricting execute access.
        // AccessMode::Read maps to AccessFs::Execute in the Linux sandbox, so
        // any fs_read dir grant (e.g. fs_read:["."] in the git profile) would
        // otherwise let the child exec arbitrary workspace binaries. This layer
        // confines exec to the specific binary, interpreter (if any), and ETI
        // shims listed in allowed_exec_paths by the supervisor.
        let exec_paths: Vec<PathBuf> = spec
            .allowed_exec_paths
            .iter()
            .map(|bytes| PathBuf::from(OsString::from_vec(bytes.clone())))
            .collect();
        let start_exec_restrict = std::time::Instant::now();
        Sandbox::restrict_execute(&exec_paths)?;
        eti_profile_log!(
            "launcher:restrict_execute: {:?}",
            start_exec_restrict.elapsed()
        );
        eti_profile_log!("launcher:total_to_exec: {:?}", start_launcher.elapsed());

        // Build argv / envp as CString arrays. NUL-byte rejection is enforced
        // earlier (validate_ipc_request, env builder) but we re-check defensively.
        let mut argv_c: Vec<CString> = Vec::with_capacity(spec.argv.len());
        for arg in &spec.argv {
            argv_c.push(
                CString::new(arg.as_slice())
                    .map_err(|_| NonoError::SandboxInit("ETI argv contains NUL".to_string()))?,
            );
        }
        let argv_ptrs: Vec<*const libc::c_char> = argv_c
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let mut envp_c: Vec<CString> = Vec::with_capacity(spec.env.len());
        for entry in &spec.env {
            envp_c.push(
                CString::new(entry.as_slice()).map_err(|_| {
                    NonoError::SandboxInit("ETI env entry contains NUL".to_string())
                })?,
            );
        }
        let envp_ptrs: Vec<*const libc::c_char> = envp_c
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let empty_path = CString::new("").map_err(|_| {
            NonoError::SandboxInit("ETI: failed to build empty path CString".to_string())
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
        unsafe {
            libc::execveat(
                binary_fd.as_raw_fd(),
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
                "ETI execveat failed for script {} using interpreter {}: {err}. The selected child policy must grant the script, interpreter, interpreter ELF dependencies, and any required language runtime/package directories.",
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
    fn open_and_verify_binary(path: &OsStr, spec: &EtiChildLaunchSpec) -> Result<OwnedFd> {
        use std::io::Read;

        let path_c = CString::new(path.as_bytes())
            .map_err(|_| NonoError::SandboxInit("ETI binary path contains NUL".to_string()))?;
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
                "ETI fstat failed for {}: {}",
                PathBuf::from(path).display(),
                std::io::Error::last_os_error()
            )));
        }
        if (st.st_dev as u64) != spec.expected_dev || (st.st_ino as u64) != spec.expected_ino {
            return Err(NonoError::SandboxInit(format!(
                "ETI binary inode changed before launch: {}",
                PathBuf::from(path).display()
            )));
        }
        if (st.st_size as u64) != spec.expected_size {
            return Err(NonoError::SandboxInit(format!(
                "ETI binary size changed before launch: {}",
                PathBuf::from(path).display()
            )));
        }
        let mtime_nanos = (st.st_mtime as i128)
            .saturating_mul(1_000_000_000)
            .saturating_add(st.st_mtime_nsec as i128);
        if mtime_nanos != spec.expected_mtime_nanos {
            return Err(NonoError::SandboxInit(format!(
                "ETI binary mtime changed before launch: {}",
                PathBuf::from(path).display()
            )));
        }

        // Hash content via a duplicate fd so the original fd's offset stays at 0
        // for execveat. (execveat doesn't actually depend on offset, but keeping
        // the original untouched avoids relying on undocumented kernel behavior.)
        let dup_fd = fd
            .try_clone()
            .map_err(|err| NonoError::SandboxInit(format!("ETI fd dup for hash: {err}")))?;
        let mut file = std::fs::File::from(dup_fd);
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|err| NonoError::SandboxInit(format!("ETI binary fd read: {err}")))?;
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
                "ETI binary content changed before launch: {}",
                PathBuf::from(path).display()
            )));
        }

        Ok(fd)
    }

    fn handle_shim_stream(
        state: Arc<EtiState>,
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
                write_response(&mut stream, 126, Some(err.to_string()), Vec::new())
            }
        }
    }

    fn handle_shim_stream_inner(
        state: &Arc<EtiState>,
        stream: &mut UnixStream,
        session_root_pid: u32,
        session_id: &str,
        audit_recorder: Option<Arc<Mutex<AuditRecorder>>>,
    ) -> Result<(i32, Vec<u8>)> {
        let auth = authenticate_shim(stream, state)?;
        let request: EtiShimRequest = read_frame(stream)?;
        validate_ipc_request(&request)?;
        if request.command != auth.command {
            return Err(NonoError::SandboxInit(format!(
                "ETI shim command mismatch: requested {}, authenticated {}",
                request.command, auth.command
            )));
        }
        let stdio = recv_stdio_fds(stream)?;

        let caller = match resolve_caller(auth.peer_pid, session_root_pid, state) {
            Ok(caller) => caller,
            Err(err) => {
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
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
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
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

        // Resolve intercept action before consuming the active-count slot so
        // that Respond can return without forking a child process.
        let command_config = state.plan.config.commands.get(&request.command);
        let intercept_action = command_config
            .map(|cc| resolve_intercept_action(cc, &request.argv))
            .unwrap_or(&crate::command_policy::InterceptActionConfig::Passthrough);

        if let crate::command_policy::InterceptActionConfig::Respond { stdout } = intercept_action {
            // Write the static payload to the shim's stdout fd, then respond.
            let stdout_bytes = stdout.as_bytes();
            use std::io::Write;
            let mut stdout_file = std::fs::File::from(stdio.stdout);
            if let Err(e) = stdout_file.write_all(stdout_bytes) {
                // Non-fatal: log and continue to send the response.
                debug!("ETI Respond: failed to write static stdout: {e}");
            }
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
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

        if let crate::command_policy::InterceptActionConfig::Approve { timeout_secs } =
            intercept_action
        {
            let argv_display: Vec<String> = request
                .argv
                .iter()
                .filter_map(|a| std::str::from_utf8(a).ok().map(str::to_owned))
                .collect();
            let approval_request = nono::supervisor::ApprovalRequest::Command {
                request_id: format!(
                    "eti-approve-{}-{}",
                    request.command,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                ),
                command: request.command.clone(),
                args: argv_display,
                caller: caller_label(&caller),
                intercept_rule: "approve".to_string(),
                reason: None,
                child_pid: auth.peer_pid,
                session_id: session_id.to_string(),
            };

            let backend = Arc::clone(&state.approval_backend);
            let timeout = std::time::Duration::from_secs(timeout_secs.unwrap_or(60));
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

        if matches!(
            intercept_action,
            crate::command_policy::InterceptActionConfig::Capture
        ) {
            let active = state.active_count.fetch_add(1, Ordering::SeqCst);
            if active >= MAX_ACTIVE_ETI_CHILDREN {
                state.active_count.fetch_sub(1, Ordering::SeqCst);
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "denied",
                    Some("resource_limit".to_string()),
                    None,
                )?;
                return Err(NonoError::SandboxInit(
                    "ETI active child limit exceeded".to_string(),
                ));
            }
            let result = (|| {
                let launch = build_child_launch_spec(state, &request, policy)?;
                launch_child_with_capture(state, &request.command, launch, stdio)
            })();
            state.active_count.fetch_sub(1, Ordering::SeqCst);
            match &result {
                Ok((exit_code, raw_output)) => {
                    let captured = {
                        let mut broker = state.token_broker.lock().map_err(|_| {
                            NonoError::SandboxInit("ETI token broker lock poisoned".to_string())
                        })?;
                        broker.scan_and_reissue(raw_output)
                    };
                    if captured.len() > MAX_CAPTURE_STDOUT {
                        return Err(NonoError::SandboxInit(
                            "ETI Capture: output exceeds limit".to_string(),
                        ));
                    }
                    record_command_policy_audit(
                        audit_recorder.as_ref(),
                        &request,
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

        let active = state.active_count.fetch_add(1, Ordering::SeqCst);
        if active >= MAX_ACTIVE_ETI_CHILDREN {
            state.active_count.fetch_sub(1, Ordering::SeqCst);
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some("resource_limit".to_string()),
                None,
            )?;
            return Err(NonoError::SandboxInit(
                "ETI active child limit exceeded".to_string(),
            ));
        }

        let result = (|| {
            let launch = build_child_launch_spec(state, &request, policy)?;
            launch_child(state, &request.command, launch, stdio)
        })();
        state.active_count.fetch_sub(1, Ordering::SeqCst);
        match &result {
            Ok(exit_code) => record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "allowed",
                None,
                Some(*exit_code),
            )?,
            Err(err) => record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some(err.to_string()),
                None,
            )?,
        }
        result.map(|c| (c, Vec::new()))
    }

    struct ShimAuth {
        command: String,
        peer_pid: u32,
    }

    fn authenticate_shim(stream: &UnixStream, state: &EtiState) -> Result<ShimAuth> {
        let credentials = peer_credentials(stream.as_raw_fd())?;
        let peer_pid = credentials.pid;
        let exe_link = PathBuf::from(format!("/proc/{peer_pid}/exe"));
        let metadata = fs::metadata(&exe_link).map_err(|err| NonoError::ConfigRead {
            path: exe_link.clone(),
            source: err,
        })?;
        let id = file_id(&metadata);
        let exe_path = fs::read_link(&exe_link).map_err(|source| NonoError::ConfigRead {
            path: exe_link.clone(),
            source,
        })?;
        let command = state.shims_by_path.get(&exe_path).cloned().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "ETI shim authentication failed for pid {peer_pid}: untrusted executable path {}",
                exe_path.display()
            ))
        })?;
        let identity = state.shims_by_command.get(&command).ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "ETI shim authentication failed for pid {peer_pid}: missing shim identity for {command}"
            ))
        })?;
        if identity.id != id {
            return Err(NonoError::SandboxInit(format!(
                "ETI shim authentication failed for pid {peer_pid}: inode mismatch for {}",
                exe_path.display()
            )));
        }
        Ok(ShimAuth { command, peer_pid })
    }

    fn resolve_caller(peer_pid: u32, session_root_pid: u32, state: &EtiState) -> Result<Caller> {
        let mut pid = peer_pid;
        for _ in 0..ANCESTRY_DEPTH_LIMIT {
            if pid == session_root_pid {
                return Ok(Caller::Session {
                    pid: session_root_pid,
                });
            }
            if let Some(command) = live_active_child_command(pid, state)? {
                return Ok(Caller::Command { command, pid });
            }
            if pid <= 1 {
                break;
            }
            pid = parent_pid(pid)?;
        }
        Err(NonoError::SandboxInit(
            "ETI caller ancestry could not be trusted".to_string(),
        ))
    }

    fn live_active_child_command(pid: u32, state: &EtiState) -> Result<Option<String>> {
        let map = state
            .active_children
            .lock()
            .map_err(|_| NonoError::SandboxInit("ETI pid map lock poisoned".to_string()))?;
        let Some(active) = map.get(&pid) else {
            return Ok(None);
        };
        if active_child_is_live(pid, active)? {
            Ok(Some(active.command.clone()))
        } else {
            Ok(None)
        }
    }

    fn active_child_is_live(pid: u32, active: &ActiveChild) -> Result<bool> {
        if let Some(pidfd) = active.pidfd.as_ref() {
            let mut pfd = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let status = unsafe { libc::poll(&mut pfd, 1, 0) };
            if status < 0 {
                return Err(NonoError::SandboxInit(format!(
                    "ETI pidfd poll failed for pid {pid}: {}",
                    std::io::Error::last_os_error()
                )));
            }
            return Ok(status == 0);
        }
        Ok(Path::new(&format!("/proc/{pid}")).exists())
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
            NonoError::SandboxInit(format!("unknown ETI command '{command_name}'"))
        })?;

        match caller {
            Caller::Session { .. } => {
                if !config
                    .session_can_use
                    .iter()
                    .any(|name| name == command_name)
                {
                    return Err(NonoError::BlockedCommand {
                        command: command_name.to_string(),
                        reason: "session_can_use missing".to_string(),
                    });
                }
                if let Some(from) = command.from.get("session") {
                    match from {
                        CommandFromConfig::Policy(policy) => Ok(policy),
                        CommandFromConfig::Deny(_) => Err(NonoError::BlockedCommand {
                            command: command_name.to_string(),
                            reason: "from.session explicit deny".to_string(),
                        }),
                    }
                } else {
                    command
                        .sandbox
                        .as_ref()
                        .ok_or_else(|| NonoError::BlockedCommand {
                            command: command_name.to_string(),
                            reason: "missing session sandbox".to_string(),
                        })
                }
            }
            Caller::Command {
                command: caller_name,
                ..
            } => {
                let caller_command = config.commands.get(caller_name).ok_or_else(|| {
                    NonoError::SandboxInit(format!("unknown ETI caller '{caller_name}'"))
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
                    Some(CommandFromConfig::Policy(policy)) => Ok(policy),
                    Some(CommandFromConfig::Deny(_)) => Err(NonoError::BlockedCommand {
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

    /// Resolve the intercept action for a shim invocation.
    ///
    /// Matches `argv[1..]` against the command policy's `intercept` rules in
    /// order; the first matching prefix wins. An empty `args` list is a
    /// catch-all. Returns `Passthrough` when no rule matches or the policy has
    /// no intercept rules.
    fn resolve_intercept_action<'a>(
        command_config: &'a crate::command_policy::CommandPolicyConfig,
        argv: &[Vec<u8>],
    ) -> &'a crate::command_policy::InterceptActionConfig {
        use crate::command_policy::InterceptActionConfig;

        static PASSTHROUGH: InterceptActionConfig = InterceptActionConfig::Passthrough;

        // argv[0] is the synthesised command name; match against argv[1..]
        let shim_args: Vec<&[u8]> = argv.iter().skip(1).map(|v| v.as_slice()).collect();

        for rule in &command_config.intercept {
            if rule.args.is_empty() {
                // catch-all
                return &rule.action;
            }
            if shim_args.len() >= rule.args.len()
                && rule
                    .args
                    .iter()
                    .zip(shim_args.iter())
                    .all(|(expected, actual)| expected.as_bytes() == *actual)
            {
                return &rule.action;
            }
        }
        &PASSTHROUGH
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

    fn record_command_policy_audit(
        recorder: Option<&Arc<Mutex<AuditRecorder>>>,
        request: &EtiShimRequest,
        session_id: &str,
        shim_pid: u32,
        session_root_pid: u32,
        caller: Option<&Caller>,
        decision: &str,
        reason: Option<String>,
        exit_code: Option<i32>,
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
            argv_display: argv_display(&request.argv),
            env_names_display: env_names_display(&request.env),
            cwd_display: cwd_display(&request.cwd),
            exit_code,
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

    fn argv_display(argv: &[Vec<u8>]) -> Vec<String> {
        argv.iter()
            .take(16)
            .map(|arg| redacted_display(arg, 128))
            .collect()
    }

    fn env_names_display(env: &[Vec<u8>]) -> Vec<String> {
        env.iter()
            .filter_map(|entry| {
                split_env_entry(entry).map(|(name, _value)| redacted_display(name, 128))
            })
            .take(64)
            .collect()
    }

    fn cwd_display(cwd: &[u8]) -> String {
        redacted_display(cwd, 256)
    }

    fn redacted_display(bytes: &[u8], max_chars: usize) -> String {
        let lossy = String::from_utf8_lossy(bytes);
        let lower = lossy.to_ascii_lowercase();
        if lower.contains("token")
            || lower.contains("secret")
            || lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("credential")
        {
            return "<redacted>".to_string();
        }
        let mut value = lossy.chars().take(max_chars).collect::<String>();
        if lossy.chars().count() > max_chars {
            value.push_str("...");
        }
        value
    }

    fn build_child_launch_spec(
        state: &EtiState,
        request: &EtiShimRequest,
        policy: &CommandSandboxConfig,
    ) -> Result<EtiChildLaunchSpec> {
        let binary = state
            .plan
            .resolved
            .commands
            .get(&request.command)
            .ok_or_else(|| {
                NonoError::SandboxInit(format!("missing resolved binary for {}", request.command))
            })?;
        let start_vbi = std::time::Instant::now();
        verify_binary_identity(binary)?;
        eti_profile_log!(
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

        let start_caps = std::time::Instant::now();
        let mut caps = build_child_caps(state, binary, policy)?;
        eti_profile_log!("build_child_caps total: {:?}", start_caps.elapsed());
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
            if let Ok(canonical_interp) = interp.canonicalize() {
                if let Some(closure) = state.baseline_cache.closures.get(&canonical_interp) {
                    for dep in closure {
                        allowed_exec_paths.push(dep.as_os_str().as_bytes().to_vec());
                    }
                }
            }
        }
        for shim in state.shims_by_command.values() {
            allowed_exec_paths.push(shim.path.as_os_str().as_bytes().to_vec());
        }
        // All shims are hard links to the same nono binary; include the shim's
        // ELF dependency closure once so the dynamic linker can be exec'd when
        // a child process (e.g. sh) execs a shim.
        if let Some(shim) = state.shims_by_command.values().next() {
            if let Some(closure) = state.baseline_cache.closures.get(&shim.path) {
                for dep in closure {
                    allowed_exec_paths.push(dep.as_os_str().as_bytes().to_vec());
                }
            }
        }

        Ok(EtiChildLaunchSpec {
            real_binary: binary.canonical_path.as_os_str().as_bytes().to_vec(),
            executable_kind: format!("{:?}", binary.shape.kind),
            interpreter: binary
                .shape
                .interpreter
                .as_ref()
                .map(|path| path.as_os_str().as_bytes().to_vec()),
            interpreter_args: binary.shape.interpreter_args.clone(),
            argv: effective_argv(binary, request, policy)?,
            env,
            cwd: cwd.as_os_str().as_bytes().to_vec(),
            stdio_mode: selected_stdio_mode(request).to_string(),
            caps: caps_to_spec(&caps),
            allowed_exec_paths,
            expected_dev: binary.dev,
            expected_ino: binary.ino,
            expected_size: binary.size,
            expected_mtime_nanos: binary.mtime_nanos,
            expected_sha256: binary.sha256.clone(),
        })
    }

    fn build_child_caps(
        state: &EtiState,
        binary: &ResolvedCommandBinary,
        policy: &CommandSandboxConfig,
    ) -> Result<CapabilitySet> {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_fs(FsCapability::new_file(
            &binary.canonical_path,
            AccessMode::Read,
        )?);
        add_runtime_baseline(&mut caps, &state.baseline_cache, &binary.canonical_path)?;
        add_executable_shape_baseline(&mut caps, state, binary)?;
        add_chaining_control_caps(&mut caps, state)?;
        add_policy_fs(&mut caps, policy, &state.policy_root)?;
        add_policy_network(&mut caps, policy);
        add_policy_credentials(&mut caps, state, policy)?;
        Ok(caps)
    }

    fn add_executable_shape_baseline(
        caps: &mut CapabilitySet,
        state: &EtiState,
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
        add_runtime_baseline(caps, &state.baseline_cache, &interpreter)
    }

    fn add_chaining_control_caps(caps: &mut CapabilitySet, state: &EtiState) -> Result<()> {
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
    ) -> Result<()> {
        for entry in &policy.fs_read {
            let path = resolve_policy_path(entry, policy_root)?;
            caps.add_fs(FsCapability::new_dir(path, AccessMode::Read)?);
        }
        for entry in &policy.fs_write {
            let path = resolve_policy_path(entry, policy_root)?;
            caps.add_fs(FsCapability::new_dir(path, AccessMode::ReadWrite)?);
        }
        for entry in &policy.fs_read_file {
            let path = resolve_policy_path(entry, policy_root)?;
            add_optional_read_file(caps, path)?;
        }
        for entry in &policy.fs_write_file {
            let path = resolve_policy_path(entry, policy_root)?;
            caps.add_fs(FsCapability::new_file(path, AccessMode::ReadWrite)?);
        }
        Ok(())
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

    fn resolve_policy_path(entry: &str, cwd: &Path) -> Result<PathBuf> {
        let expanded = profile::expand_vars(entry, cwd)?;
        if expanded.is_absolute() {
            Ok(expanded)
        } else {
            Ok(cwd.join(expanded))
        }
    }

    fn add_policy_network(caps: &mut CapabilitySet, policy: &CommandSandboxConfig) {
        let Some(network) = &policy.network else {
            return;
        };
        for port in &network.tcp_connect_ports {
            caps.add_tcp_connect_port(*port);
        }
        for port in &network.tcp_bind_ports {
            caps.add_tcp_bind_port(*port);
        }
    }

    fn add_policy_credentials(
        caps: &mut CapabilitySet,
        state: &EtiState,
        policy: &CommandSandboxConfig,
    ) -> Result<()> {
        for handle in &policy.use_credentials {
            match state.credential_handles.get(handle) {
                Some(ResolvedCredential::SshAgent {
                    socket: Some(socket),
                    ..
                }) => {
                    caps.add_unix_socket(UnixSocketCapability::new_file(
                        socket,
                        UnixSocketMode::Connect,
                    )?);
                    caps.add_fs(FsCapability::new_file(socket, AccessMode::Read)?);
                }
                Some(ResolvedCredential::SshAgent {
                    socket: None,
                    unavailable_reason,
                }) => {
                    let reason = unavailable_reason
                        .as_deref()
                        .unwrap_or("ssh-agent socket unavailable");
                    return Err(NonoError::ConfigParse(format!(
                        "ETI credential '{handle}' is unavailable: {reason}"
                    )));
                }
                Some(ResolvedCredential::RawFile { path }) => {
                    caps.add_fs(FsCapability::new_file(path, AccessMode::Read)?);
                }
                None => {
                    return Err(NonoError::SandboxInit(format!(
                        "ETI credential handle '{handle}' was not resolved"
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
                "ETI runtime baseline cache missing entry for {}",
                binary.display()
            ))
        })?;
        for file in closure {
            caps.add_fs(FsCapability::new_file(file, AccessMode::Read)?);
        }
        for (path, access) in &baseline.system_files {
            caps.add_fs(FsCapability::new_file(path, *access)?);
        }
        eti_profile_log!(
            "add_runtime_baseline({}): {:?} ({} closure files)",
            binary.display(),
            start_baseline.elapsed(),
            closure.len()
        );
        Ok(())
    }

    fn build_baseline_cache(
        plan: &ResolvedEtiPlan,
        shims_by_command: &BTreeMap<String, ShimIdentity>,
        shim_source: &Path,
    ) -> Result<BaselineCache> {
        let system_files = compute_system_baseline_files()?;
        let mut closures: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();

        for binary in plan.resolved.commands.values() {
            if !closures.contains_key(&binary.canonical_path) {
                closures.insert(
                    binary.canonical_path.clone(),
                    elf_dependency_closure(&binary.canonical_path)?,
                );
            }
            if let Some(interpreter) = binary.shape.interpreter.as_ref() {
                let canonical = interpreter.canonicalize().map_err(|source| {
                    NonoError::PathCanonicalization {
                        path: interpreter.clone(),
                        source,
                    }
                })?;
                if !closures.contains_key(&canonical) {
                    closures.insert(canonical.clone(), elf_dependency_closure(&canonical)?);
                }
            }
        }

        let shim_closure = elf_dependency_closure(shim_source)?;
        for shim in shims_by_command.values() {
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
            for entry in
                fs::read_dir("/etc/ld.so.conf.d").map_err(|source| NonoError::ConfigRead {
                    path: PathBuf::from("/etc/ld.so.conf.d"),
                    source,
                })?
            {
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

    fn effective_argv(
        binary: &ResolvedCommandBinary,
        request: &EtiShimRequest,
        policy: &CommandSandboxConfig,
    ) -> Result<Vec<Vec<u8>>> {
        if request.argv.is_empty() {
            return Err(NonoError::SandboxInit(
                "ETI request had empty argv".to_string(),
            ));
        }
        let mut argv = Vec::with_capacity(request.argv.len() + policy.argv_prepend.len());
        argv.push(binary.canonical_path.as_os_str().as_bytes().to_vec());
        for arg in &policy.argv_prepend {
            if arg.as_bytes().contains(&0) {
                return Err(NonoError::ConfigParse(
                    "ETI policy argv_prepend contains NUL".to_string(),
                ));
            }
            argv.push(arg.as_bytes().to_vec());
        }
        argv.extend(request.argv.iter().skip(1).cloned());
        Ok(argv)
    }

    fn filter_child_env(
        state: &EtiState,
        request: &EtiShimRequest,
        policy: &CommandSandboxConfig,
    ) -> Result<Vec<Vec<u8>>> {
        let allowed_patterns: Vec<String> = policy
            .environment
            .as_ref()
            .and_then(|env| env.allow_vars.clone())
            .unwrap_or_else(|| {
                DEFAULT_ENV_ALLOW
                    .iter()
                    .map(|value| value.to_string())
                    .collect()
            });

        let broker = state
            .token_broker
            .lock()
            .map_err(|_| NonoError::SandboxInit("ETI token broker lock poisoned".to_string()))?;

        let mut env = Vec::new();
        let mut has_path = false;
        for entry in &request.env {
            let Some((key, _value)) = split_env_entry(entry) else {
                continue;
            };
            let key_str = std::str::from_utf8(key)
                .map_err(|_| NonoError::SandboxInit("ETI env var name is not UTF-8".to_string()))?;
            if key_str.starts_with("NONO_") {
                continue;
            }
            // Drop linker/shell/interpreter injection vectors regardless of policy
            // allow_vars. A broad pattern like "*" or "LD_*" must NOT let
            // LD_PRELOAD / PYTHONPATH / NODE_OPTIONS / BASH_ENV / etc. through to
            // a credential-bearing ETI child.
            if crate::exec_strategy::env_sanitization::is_dangerous_env_var(key_str) {
                continue;
            }
            if key_str == "PATH" {
                has_path = true;
            }
            if crate::exec_strategy::is_env_var_allowed(key_str, &allowed_patterns) {
                // Resolve broker nonces to real values immediately before execve.
                let resolved = broker.resolve_env_entry(entry);
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
        inject_chaining_control_env(&mut env, state);
        apply_environment_set_vars(&mut env, policy)?;
        for handle in &policy.use_credentials {
            match state.credential_handles.get(handle) {
                Some(ResolvedCredential::SshAgent {
                    socket: Some(socket),
                    ..
                }) => {
                    env.retain(|entry| !entry.starts_with(b"SSH_AUTH_SOCK="));
                    env.push(format!("SSH_AUTH_SOCK={}", socket.display()).into_bytes());
                }
                Some(ResolvedCredential::SshAgent {
                    socket: None,
                    unavailable_reason,
                }) => {
                    let reason = unavailable_reason
                        .as_deref()
                        .unwrap_or("ssh-agent socket unavailable");
                    return Err(NonoError::ConfigParse(format!(
                        "ETI credential '{handle}' is unavailable: {reason}"
                    )));
                }
                _ => {}
            }
        }
        Ok(env)
    }

    fn apply_environment_set_vars(
        env: &mut Vec<Vec<u8>>,
        policy: &CommandSandboxConfig,
    ) -> Result<()> {
        let Some(environment) = &policy.environment else {
            return Ok(());
        };
        for (name, value) in &environment.set_vars {
            if name.is_empty()
                || name == "PATH"
                || name.starts_with("NONO_")
                || name.contains('*')
                || name.contains('=')
                || name.as_bytes().contains(&0)
                || value.as_bytes().contains(&0)
            {
                return Err(NonoError::ConfigParse(format!(
                    "invalid ETI environment.set_vars entry '{name}'"
                )));
            }
            // Refuse known code-injection vectors even if a policy explicitly
            // names them in set_vars. There is no legitimate reason for a policy
            // to set LD_PRELOAD / BASH_ENV / PYTHONPATH / NODE_OPTIONS / etc.
            if crate::exec_strategy::env_sanitization::is_dangerous_env_var(name) {
                return Err(NonoError::ConfigParse(format!(
                    "ETI environment.set_vars rejects dangerous key '{name}'"
                )));
            }
            let prefix = format!("{name}=");
            env.retain(|entry| !entry.starts_with(prefix.as_bytes()));
            let mut entry = name.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend(value.as_bytes());
            env.push(entry);
        }
        Ok(())
    }

    fn inject_chaining_control_env(env: &mut Vec<Vec<u8>>, state: &EtiState) {
        let socket_prefix = format!("{ETI_SOCKET_ENV}=");
        let shim_dir_prefix = format!("{ETI_SHIM_DIR_ENV}=");
        let launch_spec_prefix = format!("{ETI_LAUNCH_SPEC_ENV}=");
        env.retain(|entry| {
            !entry.starts_with(socket_prefix.as_bytes())
                && !entry.starts_with(shim_dir_prefix.as_bytes())
                && !entry.starts_with(launch_spec_prefix.as_bytes())
        });
        env.push(format!("{ETI_SOCKET_ENV}={}", state.socket_path.display()).into_bytes());
        env.push(format!("{ETI_SHIM_DIR_ENV}={}", state.shim_dir.display()).into_bytes());
    }

    fn launch_child(
        state: &EtiState,
        command_name: &str,
        spec: EtiChildLaunchSpec,
        stdio: StdioFds,
    ) -> Result<i32> {
        let start_total = std::time::Instant::now();
        let start_write = std::time::Instant::now();
        let spec_path = write_launch_spec(&state.runtime_dir, &spec)?;
        eti_profile_log!("launch_child:write_spec: {:?}", start_write.elapsed());
        let start_spawn_wait = std::time::Instant::now();
        let result = match spec.stdio_mode.as_str() {
            "pty" => launch_child_with_pty(state, command_name, &spec_path, stdio),
            "direct_fds" => launch_child_with_direct_fds(state, command_name, &spec_path, stdio),
            other => Err(NonoError::ConfigParse(format!(
                "invalid ETI stdio mode '{other}'"
            ))),
        };
        eti_profile_log!(
            "launch_child:spawn_and_wait: {:?}",
            start_spawn_wait.elapsed()
        );
        let _ = fs::remove_file(&spec_path);
        eti_profile_log!("launch_child:total: {:?}", start_total.elapsed());
        result
    }

    fn prepare_launcher_command(spec_path: &Path) -> Result<Command> {
        let nono_exe = std::env::current_exe().map_err(|err| {
            NonoError::SandboxInit(format!("failed to locate nono executable: {err}"))
        })?;
        let mut command = Command::new(nono_exe);
        command.env_clear().env(ETI_LAUNCH_SPEC_ENV, spec_path);
        if let Some(value) = std::env::var_os("ETI_PROFILE_HOTPATH") {
            command.env("ETI_PROFILE_HOTPATH", value);
        }
        Ok(command)
    }

    fn launch_child_with_direct_fds(
        state: &EtiState,
        command_name: &str,
        spec_path: &Path,
        stdio: StdioFds,
    ) -> Result<i32> {
        let mut command = prepare_launcher_command(spec_path)?;
        command
            .stdin(Stdio::from(File::from(stdio.stdin)))
            .stdout(Stdio::from(File::from(stdio.stdout)))
            .stderr(Stdio::from(File::from(stdio.stderr)));
        let mut child = command.spawn().map_err(NonoError::CommandExecution)?;
        wait_for_tracked_child(state, command_name, &mut child)
    }

    fn launch_child_with_capture(
        state: &EtiState,
        command_name: &str,
        spec: EtiChildLaunchSpec,
        stdio: StdioFds,
    ) -> Result<(i32, Vec<u8>)> {
        use std::io::Read;
        use std::os::unix::io::FromRawFd;

        let mut pipe_fds = [-1i32; 2]; // [read_end, write_end]
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(NonoError::SandboxInit(format!(
                "ETI Capture: pipe() failed: {}",
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
        // The write end was moved into the child's Stdio and is now closed in
        // the parent, so reading from pipe_read will yield EOF when the child
        // closes its stdout (on exit or explicit close).

        track_child(state, child.id(), command_name)?;

        let mut captured = Vec::new();
        let mut pipe_reader =
            std::io::BufReader::new(File::from(pipe_read)).take((MAX_CAPTURE_STDOUT as u64) + 1);
        let read_result = pipe_reader.read_to_end(&mut captured);
        // Drop the reader (closes the read end) before waiting.
        drop(pipe_reader);

        let status = child.wait().map_err(NonoError::CommandExecution);
        untrack_child(state, child.id())?;
        let _ = fs::remove_file(&spec_path);

        read_result
            .map_err(|e| NonoError::SandboxInit(format!("ETI Capture: pipe read failed: {e}")))?;
        if captured.len() > MAX_CAPTURE_STDOUT {
            return Err(NonoError::SandboxInit(
                "ETI Capture: output exceeds limit".to_string(),
            ));
        }

        Ok((exit_status_code(status?), captured))
    }

    fn launch_child_with_pty(
        state: &EtiState,
        command_name: &str,
        spec_path: &Path,
        stdio: StdioFds,
    ) -> Result<i32> {
        let pty = crate::pty_proxy::open_pty()?;
        let stdin_slave = nix::unistd::dup(&pty.slave)
            .map_err(|err| NonoError::SandboxInit(format!("ETI PTY dup stdin failed: {err}")))?;
        let stdout_slave = nix::unistd::dup(&pty.slave)
            .map_err(|err| NonoError::SandboxInit(format!("ETI PTY dup stdout failed: {err}")))?;
        let stderr_slave = nix::unistd::dup(&pty.slave)
            .map_err(|err| NonoError::SandboxInit(format!("ETI PTY dup stderr failed: {err}")))?;
        let mut command = prepare_launcher_command(spec_path)?;
        command
            .stdin(Stdio::from(File::from(stdin_slave)))
            .stdout(Stdio::from(File::from(stdout_slave)))
            .stderr(Stdio::from(File::from(stderr_slave)));
        let mut child = command.spawn().map_err(NonoError::CommandExecution)?;
        drop(pty.slave);
        track_child(state, child.id(), command_name)?;
        let status = relay_pty_and_wait(&mut child, pty.master, stdio);
        untrack_child(state, child.id())?;
        status
    }

    fn wait_for_tracked_child(
        state: &EtiState,
        command_name: &str,
        child: &mut Child,
    ) -> Result<i32> {
        track_child(state, child.id(), command_name)?;
        let status = child.wait().map_err(NonoError::CommandExecution);
        untrack_child(state, child.id())?;
        status.map(exit_status_code)
    }

    fn track_child(state: &EtiState, child_pid: u32, command_name: &str) -> Result<()> {
        let pidfd = open_pidfd(child_pid)?;
        let mut map = state
            .active_children
            .lock()
            .map_err(|_| NonoError::SandboxInit("ETI pid map lock poisoned".to_string()))?;
        map.insert(
            child_pid,
            ActiveChild {
                command: command_name.to_string(),
                pidfd,
            },
        );
        Ok(())
    }

    fn untrack_child(state: &EtiState, child_pid: u32) -> Result<()> {
        let mut map = state
            .active_children
            .lock()
            .map_err(|_| NonoError::SandboxInit("ETI pid map lock poisoned".to_string()))?;
        map.remove(&child_pid);
        Ok(())
    }

    fn open_pidfd(pid: u32) -> Result<Option<OwnedFd>> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd >= 0 {
            // SAFETY: pidfd_open returned a fresh owned file descriptor on success.
            return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code) if code == libc::ENOSYS || code == libc::EINVAL => Ok(None),
            _ => Err(NonoError::SandboxInit(format!(
                "ETI pidfd_open failed for pid {pid}: {err}"
            ))),
        }
    }

    fn exit_status_code(status: std::process::ExitStatus) -> i32 {
        status
            .code()
            .or_else(|| status.signal().map(|sig| 128 + sig))
            .unwrap_or(126)
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
                        "ETI PTY poll failed: {err}"
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
                _ => {
                    return Err(NonoError::SandboxInit(format!(
                        "ETI PTY fd read failed: {err}"
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
                "ETI PTY fd write failed: {err}"
            )));
        }
        Ok(())
    }

    fn set_nonblocking_fd(fd: i32) -> Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(NonoError::SandboxInit(format!(
                "ETI fcntl(F_GETFL) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
            return Err(NonoError::SandboxInit(format!(
                "ETI fcntl(F_SETFL) failed: {}",
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
            libc::ioctl(pty_master_fd, libc::TIOCSWINSZ as libc::c_ulong, &ws);
        }
        *last = Some(current);
    }

    fn write_launch_spec(runtime_dir: &Path, spec: &EtiChildLaunchSpec) -> Result<PathBuf> {
        let path = unique_runtime_path(runtime_dir, "launch", "json");
        let json = serde_json::to_vec(spec).map_err(|err| {
            NonoError::ConfigParse(format!("failed to serialize ETI launch spec: {err}"))
        })?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|source| NonoError::ConfigWrite {
                path: path.clone(),
                source,
            })?;
        file.write_all(&json)
            .map_err(|source| NonoError::ConfigWrite {
                path: path.clone(),
                source,
            })?;
        Ok(path)
    }

    fn validate_ipc_request(request: &EtiShimRequest) -> Result<()> {
        if request.argv.is_empty() {
            return Err(NonoError::SandboxInit(
                "ETI IPC rejected empty argv".to_string(),
            ));
        }
        if request.argv.len() > MAX_ARGC {
            return Err(NonoError::SandboxInit(
                "ETI IPC argc limit exceeded".to_string(),
            ));
        }
        if request.env.len() > MAX_ENV {
            return Err(NonoError::SandboxInit(
                "ETI IPC env limit exceeded".to_string(),
            ));
        }
        if request.cwd.len() > MAX_CWD || request.cwd.contains(&0) {
            return Err(NonoError::SandboxInit("ETI IPC cwd rejected".to_string()));
        }
        for arg in &request.argv {
            if arg.len() > MAX_ARG || arg.contains(&0) {
                return Err(NonoError::SandboxInit("ETI IPC argv rejected".to_string()));
            }
        }
        for entry in &request.env {
            if entry.len() > MAX_ENV_ENTRY || entry.contains(&0) {
                return Err(NonoError::SandboxInit("ETI IPC env rejected".to_string()));
            }
        }
        Ok(())
    }

    fn write_response(
        stream: &mut UnixStream,
        exit_code: i32,
        error: Option<String>,
        captured_stdout: Vec<u8>,
    ) -> Result<()> {
        let mut resp = match error {
            None => EtiShimResponse::ok(exit_code),
            Some(e) => EtiShimResponse::err(exit_code, e),
        };
        resp.captured_stdout = captured_stdout;
        write_frame(stream, &resp)
    }

    fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
        let payload = serde_json::to_vec(value).map_err(|err| {
            NonoError::SandboxInit(format!("failed to serialize ETI IPC frame: {err}"))
        })?;
        if payload.len() > MAX_FRAME {
            return Err(NonoError::SandboxInit(
                "ETI IPC frame too large".to_string(),
            ));
        }
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .map_err(|err| {
                NonoError::SandboxInit(format!("failed to write ETI IPC length: {err}"))
            })?;
        stream.write_all(&payload).map_err(|err| {
            NonoError::SandboxInit(format!("failed to write ETI IPC payload: {err}"))
        })
    }

    fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
        let mut len = [0_u8; 4];
        stream.read_exact(&mut len).map_err(|err| {
            NonoError::SandboxInit(format!("failed to read ETI IPC length: {err}"))
        })?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_FRAME {
            return Err(NonoError::SandboxInit(
                "ETI IPC frame too large".to_string(),
            ));
        }
        let mut payload = vec![0_u8; len];
        stream.read_exact(&mut payload).map_err(|err| {
            NonoError::SandboxInit(format!("failed to read ETI IPC payload: {err}"))
        })?;
        serde_json::from_slice(&payload)
            .map_err(|err| NonoError::SandboxInit(format!("failed to parse ETI IPC frame: {err}")))
    }

    fn send_stdio_fds(stream: &UnixStream) -> Result<()> {
        for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            send_fd_via_socket(stream.as_raw_fd(), fd)?;
        }
        Ok(())
    }

    fn recv_stdio_fds(stream: &UnixStream) -> Result<StdioFds> {
        let stdin = recv_fd_via_socket(stream.as_raw_fd())?;
        let stdout = recv_fd_via_socket(stream.as_raw_fd())?;
        let stderr = recv_fd_via_socket(stream.as_raw_fd())?;
        Ok(StdioFds {
            stdin,
            stdout,
            stderr,
        })
    }

    fn resolve_credentials(
        credentials: &BTreeMap<String, CommandCredentialConfig>,
    ) -> Result<BTreeMap<String, ResolvedCredential>> {
        let mut resolved = BTreeMap::new();
        for (name, credential) in credentials {
            match credential.credential_type {
                CommandCredentialType::SshAgent => {
                    let socket_template = credential.socket.as_ref().ok_or_else(|| {
                        NonoError::ConfigParse(format!(
                            "ssh-agent credential '{name}' missing socket"
                        ))
                    })?;
                    let (socket, unavailable_reason) =
                        match resolve_ssh_agent_socket(socket_template) {
                            Ok(socket) => (Some(socket), None),
                            Err(reason) => (None, Some(reason)),
                        };
                    resolved.insert(
                        name.clone(),
                        ResolvedCredential::SshAgent {
                            socket,
                            unavailable_reason,
                        },
                    );
                }
                CommandCredentialType::RawFile => {
                    let path = credential
                        .path
                        .as_ref()
                        .ok_or_else(|| {
                            NonoError::ConfigParse(format!(
                                "raw-file credential '{name}' missing path"
                            ))
                        })
                        .map(PathBuf::from)?;
                    let canonical =
                        path.canonicalize()
                            .map_err(|source| NonoError::PathCanonicalization {
                                path: path.clone(),
                                source,
                            })?;
                    if !canonical.is_file() {
                        return Err(NonoError::ExpectedFile(path));
                    }
                    resolved.insert(
                        name.clone(),
                        ResolvedCredential::RawFile { path: canonical },
                    );
                }
            }
        }
        Ok(resolved)
    }

    fn resolve_ssh_agent_socket(value: &str) -> std::result::Result<PathBuf, String> {
        let path = if value == "$SSH_AUTH_SOCK" {
            match std::env::var_os("SSH_AUTH_SOCK") {
                Some(value) => PathBuf::from(value),
                None => return Err("SSH_AUTH_SOCK is unset".to_string()),
            }
        } else {
            PathBuf::from(value)
        };
        let canonical = path
            .canonicalize()
            .map_err(|source| format!("failed to resolve {}: {source}", path.display()))?;
        let metadata = fs::metadata(&canonical)
            .map_err(|source| format!("failed to stat {}: {source}", canonical.display()))?;
        if !metadata.file_type().is_socket() {
            return Err(format!("{} is not a socket", canonical.display()));
        }
        Ok(canonical)
    }

    fn bind_runtime_socket(path: &Path) -> Result<UnixListener> {
        if path.exists() {
            return Err(NonoError::SandboxInit(format!(
                "ETI runtime socket already exists: {}",
                path.display()
            )));
        }
        let listener = UnixListener::bind(path).map_err(|err| {
            NonoError::SandboxInit(format!(
                "failed to bind ETI socket {}: {err}",
                path.display()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            NonoError::SandboxInit(format!("failed to set ETI socket nonblocking: {err}"))
        })?;
        Ok(listener)
    }

    fn create_runtime_dir() -> Result<PathBuf> {
        let base = runtime_base_dir()?;
        for _ in 0..32 {
            let path = unique_runtime_path(&base, "nono-eti", "");
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
            "failed to allocate ETI runtime dir".to_string(),
        ))
    }

    fn runtime_base_dir() -> Result<PathBuf> {
        if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
            let path = PathBuf::from(xdg);
            if secure_runtime_base(&path)? && runtime_base_has_capacity(&path)? {
                return Ok(path);
            }
        }
        Ok(std::env::temp_dir())
    }

    fn runtime_base_has_capacity(path: &Path) -> Result<bool> {
        let current_exe = std::env::current_exe().map_err(|err| {
            NonoError::SandboxInit(format!("failed to locate current executable: {err}"))
        })?;
        let exe_size = fs::metadata(&current_exe)
            .map_err(|source| NonoError::ConfigRead {
                path: current_exe,
                source,
            })?
            .len();
        let required = exe_size.saturating_add(1024 * 1024);
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            NonoError::SandboxInit(format!(
                "ETI runtime base contains NUL byte: {}",
                path.display()
            ))
        })?;
        let mut stats = unsafe { std::mem::zeroed::<libc::statvfs>() };
        if unsafe { libc::statvfs(c_path.as_ptr(), &mut stats) } != 0 {
            return Err(NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
        let block_size = if stats.f_frsize == 0 {
            stats.f_bsize
        } else {
            stats.f_frsize
        };
        let available = (stats.f_bavail as u128).saturating_mul(block_size as u128);
        Ok(available >= required as u128)
    }

    fn secure_runtime_base(path: &Path) -> Result<bool> {
        let metadata = fs::metadata(path).map_err(|source| NonoError::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;
        let mode = metadata.permissions().mode();
        Ok(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && (mode & 0o022) == 0,
        )
    }

    fn unique_runtime_path(base: &Path, prefix: &str, suffix: &str) -> PathBuf {
        let mut random = [0_u8; 8];
        rand::rng().fill_bytes(&mut random);
        let nonce = u64::from_ne_bytes(random);
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

    fn materialize_shim_source(runtime_dir: &Path) -> Result<PathBuf> {
        let current_exe = std::env::current_exe().map_err(|err| {
            NonoError::SandboxInit(format!("failed to locate current executable: {err}"))
        })?;
        let shim_source = runtime_dir.join(".nono-shim");
        fs::copy(&current_exe, &shim_source).map_err(|source| NonoError::ConfigWrite {
            path: shim_source.clone(),
            source,
        })?;
        fs::set_permissions(&shim_source, fs::Permissions::from_mode(0o700)).map_err(|source| {
            NonoError::ConfigWrite {
                path: shim_source.clone(),
                source,
            }
        })?;
        Ok(shim_source)
    }

    fn materialize_shim(
        shim_source: &Path,
        runtime_dir: &Path,
        name: &str,
    ) -> Result<ShimIdentity> {
        let shim_path = runtime_dir.join(name);
        fs::hard_link(shim_source, &shim_path).map_err(|source| NonoError::ConfigWrite {
            path: shim_path.clone(),
            source,
        })?;
        let metadata = fs::metadata(&shim_path).map_err(|source| NonoError::ConfigRead {
            path: shim_path.clone(),
            source,
        })?;
        Ok(ShimIdentity {
            path: shim_path,
            id: file_id(&metadata),
        })
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
    ) -> Result<Vec<PathBuf>> {
        let mut dirs = BTreeSet::new();
        if let Some(path_env) = path_env {
            for dir in std::env::split_paths(&path_env) {
                if dir.as_os_str().is_empty() || !dir.exists() {
                    continue;
                }
                if let Ok(canonical) = dir.canonicalize() {
                    if canonical.is_dir() {
                        dirs.insert(canonical);
                    }
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
            dirs.insert(canonical);
        }
        Ok(dirs.into_iter().collect())
    }

    /// PATH directories used by the deny-only resolver must not be writable by
    /// other users. Group/world-writable directories allow an untrusted user to
    /// plant a binary that shadows a deny-only name, causing the deny shim to
    /// resolve to the planted inode; the actual system binary then lacks a
    /// deny-inode match. User-owned writable directories (e.g. `~/.cargo/bin`,
    /// `~/.local/bin`) are intentionally permitted: ETI's threat model trusts
    /// the human user who owns the session, and the default-deny exec gate in
    /// `validate_initial_exec` blocks any binary not explicitly in the policy
    /// regardless of PATH shadowing.
    fn validate_trusted_executable_dirs(dirs: &[PathBuf]) -> Result<()> {
        for dir in dirs {
            let metadata = fs::metadata(dir).map_err(|source| NonoError::ConfigRead {
                path: dir.clone(),
                source,
            })?;
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(NonoError::SandboxInit(format!(
                    "ETI executable directory is group/world writable: {}",
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
    ) -> Result<BTreeMap<String, ResolvedDenyOnlyCommand>> {
        let allowed: HashSet<&String> = allowed_commands.iter().collect();
        let dirs = command_search_dirs(config, std::env::var_os("PATH"))?;
        let mut deny_only = BTreeMap::new();
        for name in blocked_commands {
            if allowed.contains(name) || config.commands.contains_key(name) {
                continue;
            }
            if let Some(path) = find_first_executable(name, &dirs)? {
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
        resolved: &ResolvedCommandBinaries,
        deny_only: &BTreeMap<String, ResolvedDenyOnlyCommand>,
        outer_caps: &CapabilitySet,
    ) -> Result<()> {
        for binary in resolved.commands.values() {
            validate_controlled_file(&binary.canonical_path, outer_caps, "policy command")?;
        }
        for entry in deny_only.values() {
            validate_controlled_file(&entry.path, outer_caps, "deny-only command")?;
        }
        Ok(())
    }

    fn validate_controlled_file(
        path: &Path,
        outer_caps: &CapabilitySet,
        label: &str,
    ) -> Result<()> {
        let metadata = fs::metadata(path).map_err(|source| NonoError::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;
        reject_user_writable_path(path, &metadata, label)?;
        if outer_caps_grant_write(outer_caps, path) {
            return Err(NonoError::SandboxInit(format!(
                "ETI {label} binary is writable by the outer session capability set: {}",
                path.display()
            )));
        }
        let parent = path.parent().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "ETI {label} binary has no parent directory: {}",
                path.display()
            ))
        })?;
        let parent_metadata = fs::metadata(parent).map_err(|source| NonoError::ConfigRead {
            path: parent.to_path_buf(),
            source,
        })?;
        reject_user_writable_path(parent, &parent_metadata, "ETI executable parent directory")?;
        if outer_caps_grant_write(outer_caps, parent) {
            return Err(NonoError::SandboxInit(format!(
                "ETI {label} binary is replaceable through writable parent directory: {}",
                parent.display()
            )));
        }
        Ok(())
    }

    fn reject_user_writable_path(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
        let mode = metadata.permissions().mode();
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        let owner_writable_by_supervisor = metadata.uid() == euid && mode & 0o200 != 0;
        let group_writable_by_supervisor = metadata.gid() == egid && mode & 0o020 != 0;
        let group_or_world_writable = mode & 0o022 != 0;
        if owner_writable_by_supervisor || group_writable_by_supervisor || group_or_world_writable {
            return Err(NonoError::SandboxInit(format!(
                "{label} is writable by the supervisor user or an untrusted class: {}",
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

    fn resolve_governance_denies(
        config: &CommandPoliciesConfig,
    ) -> Result<HashMap<FileId, PathBuf>> {
        let mut denies = HashMap::new();
        for entry in &config.deny_direct_exec_bypass {
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
                return Err(NonoError::SandboxInit(format!(
                    "missing resolved binary for command '{command_name}'"
                )));
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
                let metadata =
                    fs::metadata(&canonical).map_err(|source| NonoError::ConfigRead {
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

    /// Build the Landlock execute allow-list applied in the supervised child.
    ///
    /// When ETI is active we deliberately do NOT sweep `PATH`. The supervised
    /// child only execs one of: a shim (for policy commands) or an explicit
    /// `allow_direct_exec_bypass` path. Allowing every executable on `PATH`
    /// would let non-policy binaries (python, node, openssl, …) run under
    /// outer caps, bypassing `session_can_use`, and would also trust binaries
    /// that the session may have outer write access to (e.g. `~/.local/bin`).
    fn build_outer_exec_files<'a>(
        shims: impl Iterator<Item = &'a ShimIdentity>,
        allowed_direct_bypasses: &[PathBuf],
        shim_source: &Path,
    ) -> Result<Vec<PathBuf>> {
        let mut seen = HashSet::new();
        let mut files = Vec::new();
        for shim in shims {
            add_exact_exec_file(&mut files, &mut seen, &shim.path)?;
        }
        // Include the shim binary's ELF dependency closure (dynamic linker, glibc,
        // etc.) so the kernel can load them when the supervised child execs a shim.
        // All shims are hard links to shim_source, so one closure covers all.
        let shim_closure = elf_dependency_closure(shim_source)?;
        for dep in &shim_closure {
            let _ = add_exact_exec_file(&mut files, &mut seen, dep);
        }
        for bypass in allowed_direct_bypasses {
            add_exact_exec_file(&mut files, &mut seen, bypass)?;
        }
        files.sort();
        Ok(files)
    }

    fn add_exact_exec_file(
        files: &mut Vec<PathBuf>,
        seen: &mut HashSet<FileId>,
        path: &Path,
    ) -> Result<()> {
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
        let id = file_id(&metadata);
        if seen.insert(id) {
            files.push(canonical);
        }
        Ok(())
    }

    fn apply_outer_exec_gate(allowed_exec_files: &[PathBuf]) -> Result<()> {
        let start_total = std::time::Instant::now();
        let abi = nono::detect_abi()?.abi;
        let handled: BitFlags<AccessFs> =
            BitFlags::from_flag(AccessFs::Execute) & AccessFs::from_all(abi);
        if handled.is_empty() {
            return Err(NonoError::SandboxInit(
                "Landlock execute right unavailable for ETI".to_string(),
            ));
        }
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(handled)
            .map_err(|err| {
                NonoError::SandboxInit(format!("failed to prepare ETI exec gate: {err}"))
            })?
            .set_compatibility(CompatLevel::BestEffort)
            .create()
            .map_err(|err| {
                NonoError::SandboxInit(format!("failed to create ETI exec gate: {err}"))
            })?;
        let start_rules = std::time::Instant::now();
        for path in allowed_exec_files {
            let path_fd = PathFd::new(path)?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(path_fd, handled))
                .map_err(|err| {
                    NonoError::SandboxInit(format!(
                        "failed to add ETI exec rule for {}: {err}",
                        path.display()
                    ))
                })?;
        }
        eti_profile_log!(
            "apply_outer_exec_gate:add_rules: {:?} ({} paths)",
            start_rules.elapsed(),
            allowed_exec_files.len()
        );
        let start_restrict = std::time::Instant::now();
        let status = ruleset
            .restrict_self()
            .map_err(|err| NonoError::SandboxInit(format!("ETI exec gate failed: {err}")))?;
        eti_profile_log!(
            "apply_outer_exec_gate:restrict_self: {:?}",
            start_restrict.elapsed()
        );
        eti_profile_log!("apply_outer_exec_gate:total: {:?}", start_total.elapsed());
        if !matches!(
            status.ruleset,
            landlock::RulesetStatus::FullyEnforced | landlock::RulesetStatus::PartiallyEnforced
        ) {
            return Err(NonoError::SandboxInit(format!(
                "ETI exec gate was not enforced: {:?}",
                status.ruleset
            )));
        }
        Ok(())
    }

    fn verify_binary_identity(binary: &ResolvedCommandBinary) -> Result<()> {
        let metadata =
            fs::metadata(&binary.canonical_path).map_err(|source| NonoError::ConfigRead {
                path: binary.canonical_path.clone(),
                source,
            })?;
        if metadata.dev() != binary.dev || metadata.ino() != binary.ino {
            return Err(NonoError::SandboxInit(format!(
                "ETI command binary changed inode before launch: {}",
                binary.canonical_path.display()
            )));
        }
        if metadata.size() != binary.size || mtime_nanos(&metadata) != binary.mtime_nanos {
            return Err(NonoError::SandboxInit(format!(
                "ETI command binary changed metadata before launch: {}",
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
        resolved_program: &Path,
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
                        "ETI direct exec bypass denied for policy-controlled command '{name}'"
                    ),
                });
            }
        }
        for (name, command) in deny_only {
            if command.id == id {
                return Some(NonoError::BlockedCommand {
                    command: original_program.to_string(),
                    reason: format!("ETI direct exec denied for legacy blocked command '{name}'"),
                });
            }
        }
        Some(NonoError::BlockedCommand {
            command: original_program.to_string(),
            reason: format!(
                "ETI denies non-policy initial exec of '{}'; add the command name to \
                 command_policies.session_can_use or its canonical path to \
                 allow_direct_exec_bypass",
                resolved_program.display()
            ),
        })
    }

    fn is_tty(fd: i32) -> bool {
        unsafe { libc::isatty(fd) == 1 }
    }

    fn selected_stdio_mode(request: &EtiShimRequest) -> &'static str {
        if request.stdio_tty.iter().all(|value| *value) {
            "pty"
        } else {
            "direct_fds"
        }
    }

    fn split_env_entry(entry: &[u8]) -> Option<(&[u8], &[u8])> {
        let idx = entry.iter().position(|byte| *byte == b'=')?;
        Some((&entry[..idx], &entry[idx + 1..]))
    }

    fn caps_to_spec(caps: &CapabilitySet) -> ChildCapsSpec {
        ChildCapsSpec {
            fs: caps
                .fs_capabilities()
                .iter()
                .map(|cap| FsGrantSpec {
                    path: cap.original.as_os_str().as_bytes().to_vec(),
                    access: cap.access.to_string(),
                    is_file: cap.is_file,
                })
                .collect(),
            unix_sockets: caps
                .unix_socket_capabilities()
                .iter()
                .map(|cap| UnixSocketGrantSpec {
                    path: cap.original.as_os_str().as_bytes().to_vec(),
                    mode: cap.mode.to_string(),
                    is_directory: cap.is_directory,
                })
                .collect(),
            network_blocked: caps.is_network_blocked(),
            tcp_connect_ports: caps.tcp_connect_ports().to_vec(),
            tcp_bind_ports: caps.tcp_bind_ports().to_vec(),
        }
    }

    fn caps_from_spec(spec: &ChildCapsSpec) -> Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();
        if spec.network_blocked {
            caps.set_network_mode_mut(NetworkMode::Blocked);
        }
        for fs_grant in &spec.fs {
            let access = parse_access(&fs_grant.access)?;
            let path = OsString::from_vec(fs_grant.path.clone());
            let cap = if fs_grant.is_file {
                FsCapability::new_file(PathBuf::from(path), access)?
            } else {
                FsCapability::new_dir(PathBuf::from(path), access)?
            };
            caps.add_fs(cap);
        }
        for socket_grant in &spec.unix_sockets {
            let mode = parse_socket_mode(&socket_grant.mode)?;
            let path = PathBuf::from(OsString::from_vec(socket_grant.path.clone()));
            let cap = if socket_grant.is_directory {
                UnixSocketCapability::new_dir(path, mode)?
            } else {
                UnixSocketCapability::new_file(path, mode)?
            };
            caps.add_unix_socket(cap);
        }
        for port in &spec.tcp_connect_ports {
            caps.add_tcp_connect_port(*port);
        }
        for port in &spec.tcp_bind_ports {
            caps.add_tcp_bind_port(*port);
        }
        Ok(caps)
    }

    fn parse_access(value: &str) -> Result<AccessMode> {
        match value {
            "read" => Ok(AccessMode::Read),
            "write" => Ok(AccessMode::Write),
            "read+write" => Ok(AccessMode::ReadWrite),
            other => Err(NonoError::ConfigParse(format!(
                "invalid ETI access mode '{other}'"
            ))),
        }
    }

    fn parse_socket_mode(value: &str) -> Result<UnixSocketMode> {
        match value {
            "connect" => Ok(UnixSocketMode::Connect),
            "connect+bind" => Ok(UnixSocketMode::ConnectBind),
            other => Err(NonoError::ConfigParse(format!(
                "invalid ETI unix socket mode '{other}'"
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
                "unsafe ETI runtime dir shape: {}",
                path.display()
            )));
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !file_name.starts_with("nono-eti-") {
            return Err(NonoError::SandboxInit(format!(
                "refusing to clean non-ETI dir {}",
                path.display()
            )));
        }
        fs::remove_dir_all(path).map_err(|source| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        })
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
        if !seen.insert(file_id(&metadata)) {
            return Ok(());
        }
        result.push(canonical.clone());
        let parsed = parse_elf(&canonical)?;
        if let Some(interpreter) = parsed.interpreter {
            resolve_elf_recursive(&interpreter, seen, result)?;
        }
        for needed in parsed.needed {
            let dep = resolve_shared_library(&needed, &parsed.search_dirs, &canonical)?;
            resolve_elf_recursive(&dep, seen, result)?;
        }
        for library in parsed.literal_shared_libraries {
            if let Ok(dep) = resolve_shared_library(&library, &parsed.search_dirs, &canonical) {
                resolve_elf_recursive(&dep, seen, result)?;
            }
        }
        Ok(())
    }

    struct ParsedElf {
        interpreter: Option<PathBuf>,
        needed: Vec<String>,
        literal_shared_libraries: Vec<String>,
        search_dirs: Vec<String>,
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
                literal_shared_libraries: Vec::new(),
                search_dirs: Vec::new(),
            });
        }
        if data[5] != 1 {
            return Err(NonoError::SandboxInit(format!(
                "ETI supports little-endian ELF only: {}",
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
                3 => {
                    interpreter = Some(read_cstr_path(data, p_offset as usize, p_filesz as usize)?)
                }
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
                3 => {
                    interpreter = Some(read_cstr_path(data, p_offset as usize, p_filesz as usize)?)
                }
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
                literal_shared_libraries: Vec::new(),
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
        let literal_shared_libraries = literal_shared_library_names(data, &needed);
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
            literal_shared_libraries,
            search_dirs,
        })
    }

    fn literal_shared_library_names(data: &[u8], dt_needed: &[String]) -> Vec<String> {
        let needed = dt_needed.iter().map(String::as_str).collect::<HashSet<_>>();
        let mut names = BTreeSet::new();
        for raw in data.split(|byte| *byte == 0) {
            if raw.len() < "libx.so".len() || raw.len() > 255 {
                continue;
            }
            let Ok(candidate) = std::str::from_utf8(raw) else {
                continue;
            };
            if !candidate.starts_with("lib")
                || !candidate.contains(".so")
                || candidate.contains('/')
                || needed.contains(candidate)
                || !candidate.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
                })
            {
                continue;
            }
            names.insert(candidate.to_string());
        }
        names.into_iter().collect()
    }

    fn resolve_shared_library(
        name: &str,
        search_dirs: &[String],
        binary: &Path,
    ) -> Result<PathBuf> {
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
                return candidate.canonicalize().map_err(|source| {
                    NonoError::PathCanonicalization {
                        path: candidate,
                        source,
                    }
                });
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
        Ok(
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
                })?,
        )
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
            CommandEnvironmentConfig, CommandSandboxConfig, ResolvedCommandBinaries,
            ResolvedCommandBinary, ResolvedExecutableKind, ResolvedExecutableShape,
        };
        use std::collections::BTreeMap;
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
        fn unknown_inode_is_blocked() {
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
            assert!(result.is_some(), "unknown inode must be blocked");
        }

        // ── apply_environment_set_vars: dangerous key rejection ───────────────

        fn policy_with_set_var(key: &str, val: &str) -> CommandSandboxConfig {
            let mut set_vars = BTreeMap::new();
            set_vars.insert(key.to_string(), val.to_string());
            CommandSandboxConfig {
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                use_credentials: vec![],
                argv_prepend: vec![],
                network: None,
                environment: Some(CommandEnvironmentConfig {
                    allow_vars: None,
                    set_vars,
                }),
                allow_raw_file_credentials_in_chained_policy: false,
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
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{
    ETI_PARENT_MONOTONIC_ENV, PreparedEtiRuntime, log_main_total,
    maybe_run_internal_eti_entrypoint, record_main_start,
};

#[cfg(target_os = "macos")]
mod macos {
    use crate::command_policy::{
        CommandCredentialType, CommandPoliciesConfig, CommandSandboxConfig, InterceptActionConfig,
    };
    use crate::terminal_approval::TerminalApproval;
    use nix::libc;
    use nono::supervisor::ApprovalRequest;
    use nono::{AccessMode, CapabilitySet, NonoError, Result};
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tracing::debug;

    // ── Constants ────────────────────────────────────────────────────────────

    const MAX_FRAME: usize = 1024 * 1024;
    const MAX_ARGC: usize = 4096;
    const MAX_ARG: usize = 128 * 1024;
    const MAX_ENV: usize = 4096;
    const MAX_ENV_ENTRY: usize = 128 * 1024;
    const MAX_CWD: usize = 4096;
    const MAX_ACTIVE_ETI_CHILDREN: usize = 64;
    const MAX_CAPTURE_STDOUT: usize = 256 * 1024;
    const MAX_QUEUED_SHIM_REQUESTS: usize = 128;
    const ANCESTRY_DEPTH_LIMIT: usize = 64;
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    const PROC_PIDTBSDINFO: i32 = 3;

    const ETI_SOCKET_ENV: &str = "NONO_ETI_SOCKET";
    const ETI_SHIM_MARKER_ENV: &str = "NONO_ETI_SHIM";

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

    // ── IPC wire types ───────────────────────────────────────────────────────

    #[derive(Debug, Serialize, Deserialize)]
    struct EtiShimRequest {
        command: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
        cwd: Vec<u8>,
        stdio_tty: [bool; 3],
    }

    /// macOS exec spec returned to the shim for Passthrough/Approve actions.
    /// The shim consumes extension tokens, then execve()s real_binary directly.
    #[derive(Debug, Serialize, Deserialize)]
    struct MacosExecSpec {
        real_binary: Vec<u8>,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct EtiShimResponse {
        exit_code: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        captured_stdout: Vec<u8>,
        /// Sandbox extension tokens for the shim to consume before execve.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extension_tokens: Vec<String>,
        /// Populated for Passthrough/Approve actions; absent for Capture/Respond/error.
        #[serde(skip_serializing_if = "Option::is_none")]
        exec_spec: Option<MacosExecSpec>,
    }

    impl EtiShimResponse {
        fn exec(exec_spec: MacosExecSpec, extension_tokens: Vec<String>) -> Self {
            Self {
                exit_code: 0,
                error: None,
                captured_stdout: Vec::new(),
                extension_tokens,
                exec_spec: Some(exec_spec),
            }
        }
        fn capture(exit_code: i32, captured_stdout: Vec<u8>) -> Self {
            Self {
                exit_code,
                error: None,
                captured_stdout,
                extension_tokens: Vec::new(),
                exec_spec: None,
            }
        }
        fn err(exit_code: i32, error: String) -> Self {
            Self {
                exit_code,
                error: Some(error),
                captured_stdout: Vec::new(),
                extension_tokens: Vec::new(),
                exec_spec: None,
            }
        }
    }

    // ── State ────────────────────────────────────────────────────────────────

    struct ShimIdentity {
        path: PathBuf,
        /// (st_dev, st_ino) captured at materialisation.
        dev: u64,
        ino: u64,
    }

    struct ActiveChild {
        command: String,
        /// Monotonic start time (pbi_start_tvsec * 1_000_000 + pbi_start_tvusec)
        /// used to detect stale pid map entries.
        start_usec: u64,
    }

    struct EtiState {
        runtime_dir: PathBuf,
        socket_path: PathBuf,
        shim_dir: PathBuf,
        workdir: PathBuf,
        plan: ResolvedEtiPlan,
        shims_by_command: BTreeMap<String, ShimIdentity>,
        shims_by_path: BTreeMap<PathBuf, String>,
        credential_handles: BTreeMap<String, ResolvedCredential>,
        active_children: Mutex<HashMap<u32, ActiveChild>>,
        active_count: AtomicUsize,
        queued_requests: AtomicUsize,
        emitted_error_response: AtomicBool,
        token_broker: Mutex<crate::eti_token_broker::TokenBroker>,
        approval_backend: Arc<dyn nono::ApprovalBackend>,
    }

    struct ResolvedEtiPlan {
        config: CommandPoliciesConfig,
        deny_only_commands: BTreeSet<String>,
    }

    #[derive(Debug, Clone)]
    enum ResolvedCredential {
        SshAgent { socket_path: PathBuf },
    }

    // ── PreparedEtiRuntime ───────────────────────────────────────────────────

    pub(crate) struct PreparedEtiRuntime {
        inner: Arc<EtiState>,
        listener: Arc<UnixListener>,
    }

    impl PreparedEtiRuntime {
        pub(crate) fn prepare(
            config: &CommandPoliciesConfig,
            _allowed_commands: &[String],
            _blocked_commands: &[String],
            _outer_caps: &CapabilitySet,
            workdir: &Path,
        ) -> Result<Self> {
            validate_platform_requirements(config)?;

            let deny_only_commands: BTreeSet<String> = _blocked_commands.iter().cloned().collect();
            let plan = ResolvedEtiPlan {
                config: config.clone(),
                deny_only_commands,
            };

            let runtime_dir = create_runtime_dir()?;
            let mut cleanup = RuntimeDirCleanup::new(runtime_dir.clone());
            let socket_path = runtime_dir.join("supervisor.sock");
            let listener = bind_runtime_socket(&socket_path)?;
            let shim_dir = runtime_dir.clone();

            let credential_handles = resolve_credentials(&plan.config.credentials)?;

            let mut shims_by_command = BTreeMap::new();
            let mut shims_by_path = BTreeMap::new();
            let mut shim_names: BTreeSet<String> = plan.config.commands.keys().cloned().collect();
            for name in &plan.deny_only_commands {
                shim_names.insert(name.clone());
            }
            let shim_source = materialize_shim_source(&runtime_dir)?;
            for name in shim_names {
                let identity = materialize_shim(&shim_source, &runtime_dir, &name)?;
                shims_by_path.insert(identity.path.clone(), name.clone());
                shims_by_command.insert(name, identity);
            }

            let runtime = Self {
                inner: Arc::new(EtiState {
                    runtime_dir,
                    socket_path,
                    shim_dir,
                    workdir: workdir.to_path_buf(),
                    plan,
                    shims_by_command,
                    shims_by_path,
                    credential_handles,
                    active_children: Mutex::new(HashMap::new()),
                    active_count: AtomicUsize::new(0),
                    queued_requests: AtomicUsize::new(0),
                    emitted_error_response: AtomicBool::new(false),
                    token_broker: Mutex::new(crate::eti_token_broker::TokenBroker::new()),
                    approval_backend: Arc::new(TerminalApproval),
                }),
                listener: Arc::new(listener),
            };
            cleanup.disarm();
            Ok(runtime)
        }

        pub(crate) fn emitted_error_response(&self) -> bool {
            self.inner.emitted_error_response.load(Ordering::SeqCst)
        }

        pub(crate) fn cleanup_runtime_dir(&self) {
            if let Err(err) = guarded_remove_runtime_dir(&self.inner.runtime_dir) {
                debug!("ETI runtime dir cleanup skipped: {err}");
            }
        }

        /// Returns environment overrides to inject into the child process.
        /// Prepends the shim directory to PATH and sets ETI socket/marker vars.
        pub(crate) fn env_overrides(&self) -> Vec<(String, String)> {
            let current_path = std::env::var("PATH").unwrap_or_default();
            let new_path = format!("{}:{current_path}", self.inner.shim_dir.display());
            vec![
                ("PATH".to_string(), new_path),
                (
                    ETI_SOCKET_ENV.to_string(),
                    self.inner.socket_path.display().to_string(),
                ),
                (ETI_SHIM_MARKER_ENV.to_string(), "1".to_string()),
            ]
        }

        /// Grants Seatbelt capabilities for shim dir execution, socket access,
        /// and workdir read (so getcwd() works inside the sandbox).
        pub(crate) fn grant_outer_caps(&self, caps: &mut CapabilitySet) -> Result<()> {
            caps.add_fs(nono::FsCapability::new_dir(
                &self.inner.shim_dir,
                AccessMode::Read,
            )?);
            for shim in self.inner.shims_by_command.values() {
                caps.add_fs(nono::FsCapability::new_file(&shim.path, AccessMode::Read)?);
            }
            caps.add_unix_socket(nono::UnixSocketCapability::new_file(
                &self.inner.socket_path,
                nono::UnixSocketMode::Connect,
            )?);
            // Seatbelt's (deny default) blocks getcwd() if the shim's cwd is not
            // reachable via file-read-metadata. Adding the workdir here ensures its
            // ancestor chain gets file-read-metadata via collect_parent_dirs, so the
            // shim can call getcwd() when the child process is in this directory.
            if self.inner.workdir != Path::new("/") {
                caps.add_fs(nono::FsCapability::new_dir(
                    &self.inner.workdir,
                    AccessMode::Read,
                )?);
            }
            caps.deduplicate();
            Ok(())
        }

        /// Returns the shim path for the given top-level command name,
        /// or `None` if the command is not intercepted by ETI.
        pub(crate) fn shim_for_initial_command<'a>(&'a self, program: &str) -> Option<&'a Path> {
            if program.contains('/') {
                return None;
            }
            self.inner
                .shims_by_command
                .get(program)
                .map(|identity| identity.path.as_path())
        }

        /// Starts the IPC accept loop in a background thread. Returns immediately;
        /// connections are served by the background thread until the listener is dropped.
        pub(crate) fn handle_listener(
            &self,
            session_root_pid: u32,
            session_id: &str,
            audit_recorder: Option<Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
        ) -> Result<()> {
            let state = Arc::clone(&self.inner);
            let listener = Arc::clone(&self.listener);
            let session_id = session_id.to_string();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
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
                        Err(err) => {
                            debug!("ETI listener error: {err}");
                            break;
                        }
                    }
                }
            });
            Ok(())
        }
    }

    // ── Shim / child launcher entrypoints ────────────────────────────────────

    pub(crate) fn maybe_run_internal_eti_entrypoint() -> bool {
        if std::env::var_os(ETI_SHIM_MARKER_ENV).is_some() {
            exit_from_result(run_shim());
            true
        } else {
            false
        }
    }

    pub(crate) fn record_main_start() {}
    pub(crate) fn log_main_total() {}

    fn exit_from_result(result: Result<()>) {
        match result {
            Ok(()) => {}
            Err(e) => {
                eprintln!("nono: ETI shim error: {e}");
                std::process::exit(126);
            }
        }
    }

    fn run_shim() -> Result<()> {
        let socket_path = std::env::var_os(ETI_SOCKET_ENV)
            .map(PathBuf::from)
            .ok_or_else(|| NonoError::SandboxInit("ETI shim socket env missing".to_string()))?;
        let command = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(OsStr::to_os_string))
            .and_then(|n| n.into_string().ok())
            .ok_or_else(|| NonoError::SandboxInit("ETI shim command name invalid".to_string()))?;

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
            .map_err(|e| NonoError::SandboxInit(format!("ETI shim cwd failed: {e}")))?
            .into_os_string()
            .into_vec();

        let request = EtiShimRequest {
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
                "ETI shim connect to {}: {e}",
                socket_path.display()
            ))
        })?;
        write_frame(&mut stream, &request)?;

        let response: EtiShimResponse = read_frame(&mut stream)?;
        drop(stream);

        if let Some(error) = response.error {
            eprintln!("nono: ETI denied {}: {error}", request.command);
            std::process::exit(response.exit_code);
        }

        // Consume extension tokens before execve so the sandboxed process
        // inherits the expanded access.
        for token in &response.extension_tokens {
            nono::sandbox::extension_consume(token).map_err(|e| {
                NonoError::SandboxInit(format!("ETI extension_consume failed: {e}"))
            })?;
        }

        // Passthrough/Approve: exec the real binary in place.
        if let Some(exec) = response.exec_spec {
            let binary = CString::new(exec.real_binary).map_err(|_| {
                NonoError::SandboxInit("ETI exec spec binary contains NUL".to_string())
            })?;
            let argv_c = exec
                .argv
                .iter()
                .map(|a| CString::new(a.clone()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| {
                    NonoError::SandboxInit("ETI exec spec argv contains NUL".to_string())
                })?;
            let env_c = exec
                .env
                .iter()
                .map(|e| CString::new(e.clone()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| {
                    NonoError::SandboxInit("ETI exec spec env contains NUL".to_string())
                })?;

            let mut argv_ptrs: Vec<*const libc::c_char> =
                argv_c.iter().map(|a| a.as_ptr()).collect();
            argv_ptrs.push(std::ptr::null());
            let mut env_ptrs: Vec<*const libc::c_char> = env_c.iter().map(|e| e.as_ptr()).collect();
            env_ptrs.push(std::ptr::null());

            // SAFETY: binary, argv_ptrs, env_ptrs are valid null-terminated C strings.
            // execve does not return on success.
            unsafe {
                libc::execve(binary.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
            }
            return Err(NonoError::SandboxInit(format!(
                "ETI execve failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Capture/Respond: write buffered output and exit.
        if !response.captured_stdout.is_empty() {
            use std::io::Write;
            let _ = std::io::stdout().write_all(&response.captured_stdout);
        }
        std::process::exit(response.exit_code);
    }

    // ── IPC handler ──────────────────────────────────────────────────────────

    fn handle_shim_stream(
        state: Arc<EtiState>,
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
        let resp = match outcome {
            Ok(r) => r,
            Err(err) => {
                state.emitted_error_response.store(true, Ordering::SeqCst);
                EtiShimResponse::err(126, err.to_string())
            }
        };
        let _ = write_frame(&mut stream, &resp);
    }

    fn handle_shim_stream_inner(
        state: &Arc<EtiState>,
        stream: &mut UnixStream,
        session_root_pid: u32,
        session_id: &str,
        audit_recorder: Option<Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
    ) -> Result<EtiShimResponse> {
        let request: EtiShimRequest = read_frame(stream)?;
        validate_ipc_request(&request)?;

        let auth = authenticate_shim(stream, state)?;

        // Deny-only blocked commands.
        if state.plan.config.commands.get(&request.command).is_none() {
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                session_id,
                auth.peer_pid,
                session_root_pid,
                None,
                "denied",
                Some("blocked_command".to_string()),
                None,
            )?;
            return Err(NonoError::BlockedCommand {
                command: request.command,
                reason: "blocked_command".to_string(),
            });
        }

        let caller = resolve_caller(auth.peer_pid, session_root_pid, state)?;
        let command_config = state
            .plan
            .config
            .commands
            .get(&request.command)
            .ok_or_else(|| {
                NonoError::SandboxInit(format!("missing command config for {}", request.command))
            })?;
        let policy = select_effective_policy(&caller, &request.command, command_config)?;

        let intercept_action = resolve_intercept_action(command_config, &request.argv);

        // ── Respond ──────────────────────────────────────────────────────────
        if let InterceptActionConfig::Respond { stdout } = intercept_action {
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "respond",
                None,
                Some(0),
            )?;
            return Ok(EtiShimResponse {
                exit_code: 0,
                error: None,
                captured_stdout: stdout.as_bytes().to_vec(),
                extension_tokens: Vec::new(),
                exec_spec: None,
            });
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
                    "eti-approve-{}-{}",
                    request.command,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                ),
                command: request.command.clone(),
                args: argv_display,
                caller: caller_label(&caller),
                intercept_rule: "approve".to_string(),
                reason: None,
                child_pid: auth.peer_pid,
                session_id: session_id.to_string(),
            };
            let backend = Arc::clone(&state.approval_backend);
            let timeout = std::time::Duration::from_secs(timeout_secs.unwrap_or(60));
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

        // ── Capture ──────────────────────────────────────────────────────────
        if matches!(intercept_action, InterceptActionConfig::Capture) {
            let active = state.active_count.fetch_add(1, Ordering::SeqCst);
            if active >= MAX_ACTIVE_ETI_CHILDREN {
                state.active_count.fetch_sub(1, Ordering::SeqCst);
                record_command_policy_audit(
                    audit_recorder.as_ref(),
                    &request,
                    session_id,
                    auth.peer_pid,
                    session_root_pid,
                    Some(&caller),
                    "denied",
                    Some("resource_limit".to_string()),
                    None,
                )?;
                return Err(NonoError::SandboxInit(
                    "ETI active child limit exceeded".to_string(),
                ));
            }
            let result = capture_child(state, &request, policy);
            state.active_count.fetch_sub(1, Ordering::SeqCst);
            return match result {
                Ok((exit_code, raw_output)) => {
                    let captured = {
                        let mut broker = state.token_broker.lock().map_err(|_| {
                            NonoError::SandboxInit("ETI token broker lock poisoned".to_string())
                        })?;
                        broker.scan_and_reissue(&raw_output)
                    };
                    if captured.len() > MAX_CAPTURE_STDOUT {
                        return Err(NonoError::SandboxInit(
                            "ETI Capture: output exceeds limit".to_string(),
                        ));
                    }
                    record_command_policy_audit(
                        audit_recorder.as_ref(),
                        &request,
                        session_id,
                        auth.peer_pid,
                        session_root_pid,
                        Some(&caller),
                        "capture",
                        None,
                        Some(exit_code),
                    )?;
                    Ok(EtiShimResponse::capture(exit_code, captured))
                }
                Err(err) => {
                    record_command_policy_audit(
                        audit_recorder.as_ref(),
                        &request,
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
        if active >= MAX_ACTIVE_ETI_CHILDREN {
            state.active_count.fetch_sub(1, Ordering::SeqCst);
            record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some("resource_limit".to_string()),
                None,
            )?;
            return Err(NonoError::SandboxInit(
                "ETI active child limit exceeded".to_string(),
            ));
        }
        let result = build_exec_response(state, &request, policy);
        state.active_count.fetch_sub(1, Ordering::SeqCst);
        match &result {
            Ok(_) => record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "allowed",
                None,
                None,
            )?,
            Err(err) => record_command_policy_audit(
                audit_recorder.as_ref(),
                &request,
                session_id,
                auth.peer_pid,
                session_root_pid,
                Some(&caller),
                "denied",
                Some(err.to_string()),
                None,
            )?,
        }
        result
    }

    // ── Shim authentication ───────────────────────────────────────────────────

    struct ShimAuth {
        peer_pid: u32,
    }

    fn authenticate_shim(stream: &UnixStream, state: &EtiState) -> Result<ShimAuth> {
        let peer_pid = peer_pid_from_stream(stream)?;
        let exe_path = exe_path_for_pid(peer_pid)?;
        let command = state.shims_by_path.get(&exe_path).cloned().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "ETI shim auth failed for pid {peer_pid}: untrusted path {}",
                exe_path.display()
            ))
        })?;
        let identity = state.shims_by_command.get(&command).ok_or_else(|| {
            NonoError::SandboxInit(format!("ETI shim auth: missing identity for {command}"))
        })?;
        let meta = fs::metadata(&exe_path).map_err(|e| NonoError::ConfigRead {
            path: exe_path.clone(),
            source: e,
        })?;
        use std::os::unix::fs::MetadataExt;
        let (dev, ino) = (meta.dev(), meta.ino());
        if identity.dev != dev || identity.ino != ino {
            return Err(NonoError::SandboxInit(format!(
                "ETI shim auth: inode mismatch for {}",
                exe_path.display()
            )));
        }
        let _ = command; // verified above via shims_by_command lookup
        Ok(ShimAuth { peer_pid })
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
                "ETI: getsockopt(LOCAL_PEERPID) failed: {}",
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
                "ETI: proc_pidpath({pid}) failed: {}",
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

    fn resolve_caller(peer_pid: u32, session_root_pid: u32, state: &EtiState) -> Result<Caller> {
        // Fast path: the shim IS the session root (simple exec, no intermediate shell).
        if peer_pid == session_root_pid {
            return Ok(Caller::Session);
        }
        let mut pid = peer_pid;
        for _ in 0..ANCESTRY_DEPTH_LIMIT {
            pid = match parent_pid(pid) {
                Ok(p) => p,
                // If proc_pidinfo fails partway up the chain the process likely
                // exited; stop walking rather than returning an opaque error.
                Err(_) => break,
            };
            if pid == 0 || pid == 1 {
                break;
            }
            if pid == session_root_pid {
                return Ok(Caller::Session);
            }
            if let Some(cmd) = live_active_child_command(pid, state)? {
                return Ok(Caller::Command { name: cmd });
            }
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
                "ETI: proc_pidinfo({pid}) failed: ret={ret} expected={size} errno={}",
                std::io::Error::last_os_error()
            )))
        }
    }

    fn live_active_child_command(pid: u32, state: &EtiState) -> Result<Option<String>> {
        let map = state
            .active_children
            .lock()
            .map_err(|_| NonoError::SandboxInit("ETI pid map lock poisoned".to_string()))?;
        let Some(child) = map.get(&pid) else {
            return Ok(None);
        };
        if !is_pid_alive_with_start(pid, child.start_usec) {
            return Ok(None);
        }
        Ok(Some(child.command.clone()))
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

    fn track_child(state: &EtiState, child_pid: u32, command_name: &str) -> Result<()> {
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
            .map_err(|_| NonoError::SandboxInit("ETI pid map lock poisoned".to_string()))?;
        map.insert(
            child_pid,
            ActiveChild {
                command: command_name.to_string(),
                start_usec,
            },
        );
        Ok(())
    }

    fn untrack_child(state: &EtiState, child_pid: u32) -> Result<()> {
        let mut map = state
            .active_children
            .lock()
            .map_err(|_| NonoError::SandboxInit("ETI pid map lock poisoned".to_string()))?;
        map.remove(&child_pid);
        Ok(())
    }

    // ── Exec spec builder (Passthrough/Approve) ───────────────────────────────

    fn build_exec_response(
        state: &EtiState,
        request: &EtiShimRequest,
        policy: &CommandSandboxConfig,
    ) -> Result<EtiShimResponse> {
        let command_config = state
            .plan
            .config
            .commands
            .get(&request.command)
            .ok_or_else(|| {
                NonoError::SandboxInit(format!("missing command config for {}", request.command))
            })?;
        let executable = command_config.executable.as_deref().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "command '{}' has no executable configured",
                request.command
            ))
        })?;

        // Build effective argv: synthesized argv[0] + policy argv_prepend + shim argv[1..]
        let mut effective_argv: Vec<Vec<u8>> = Vec::new();
        effective_argv.push(executable.as_bytes().to_vec());
        for arg in &policy.argv_prepend {
            effective_argv.push(arg.as_bytes().to_vec());
        }
        if request.argv.len() > 1 {
            effective_argv.extend_from_slice(&request.argv[1..]);
        }

        // Filter environment through policy + token broker.
        let effective_env = filter_child_env(state, request, policy)?;

        // Issue extension tokens for the binary and credential paths.
        let mut extension_tokens = Vec::new();
        issue_token_for_path(
            Path::new(executable),
            AccessMode::Read,
            &mut extension_tokens,
        );
        issue_credential_tokens(state, policy, &mut extension_tokens);

        Ok(EtiShimResponse::exec(
            MacosExecSpec {
                real_binary: executable.as_bytes().to_vec(),
                argv: effective_argv,
                env: effective_env,
            },
            extension_tokens,
        ))
    }

    fn issue_token_for_path(path: &Path, access: AccessMode, tokens: &mut Vec<String>) {
        match nono::sandbox::extension_issue_file(path, access) {
            Ok(token) => tokens.push(token),
            Err(e) => debug!(
                "ETI: failed to issue extension token for {}: {e}",
                path.display()
            ),
        }
    }

    fn issue_credential_tokens(
        state: &EtiState,
        policy: &CommandSandboxConfig,
        tokens: &mut Vec<String>,
    ) {
        for cred_name in &policy.use_credentials {
            if let Some(cred) = state.credential_handles.get(cred_name) {
                match cred {
                    ResolvedCredential::SshAgent { socket_path } => {
                        issue_token_for_path(socket_path, AccessMode::ReadWrite, tokens);
                    }
                }
            }
        }
        for path_entry in &policy.fs_read_file {
            if let Ok(path) = resolve_policy_path(path_entry, Path::new(".")) {
                issue_token_for_path(&path, AccessMode::Read, tokens);
            }
        }
    }

    fn resolve_policy_path(entry: &str, cwd: &Path) -> Result<PathBuf> {
        let expanded = crate::profile::expand_vars(entry, cwd)?;
        if expanded.is_absolute() {
            Ok(expanded)
        } else {
            Ok(cwd.join(expanded))
        }
    }

    // ── Capture action ────────────────────────────────────────────────────────

    fn capture_child(
        state: &EtiState,
        request: &EtiShimRequest,
        policy: &CommandSandboxConfig,
    ) -> Result<(i32, Vec<u8>)> {
        let command_config = state
            .plan
            .config
            .commands
            .get(&request.command)
            .ok_or_else(|| {
                NonoError::SandboxInit(format!("missing command config for {}", request.command))
            })?;
        let executable = command_config.executable.as_deref().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "command '{}' has no executable configured",
                request.command
            ))
        })?;

        let mut effective_argv: Vec<Vec<u8>> = Vec::new();
        effective_argv.push(executable.as_bytes().to_vec());
        for arg in &policy.argv_prepend {
            effective_argv.push(arg.as_bytes().to_vec());
        }
        if request.argv.len() > 1 {
            effective_argv.extend_from_slice(&request.argv[1..]);
        }

        let effective_env = filter_child_env(state, request, policy)?;

        // Build std::process::Command
        let mut cmd = Command::new(executable);
        cmd.env_clear();
        for entry in &effective_env {
            if let Some(eq) = entry.iter().position(|&b| b == b'=') {
                let key = OsString::from_vec(entry[..eq].to_vec());
                let val = OsString::from_vec(entry[eq + 1..].to_vec());
                cmd.env(key, val);
            }
        }
        for arg in effective_argv.iter().skip(1) {
            cmd.arg(OsString::from_vec(arg.clone()));
        }

        let mut pipe_fds = [-1i32; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(NonoError::SandboxInit(format!(
                "ETI Capture: pipe() failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: pipe() returned fresh fds.
        let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let pipe_write = unsafe { File::from_raw_fd(pipe_fds[1]) };

        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(pipe_write))
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().map_err(NonoError::CommandExecution)?;
        track_child(state, child.id(), &request.command)?;

        let mut captured = Vec::new();
        {
            use std::io::Read;
            let mut reader = std::io::BufReader::new(File::from(pipe_read))
                .take((MAX_CAPTURE_STDOUT as u64) + 1);
            reader
                .read_to_end(&mut captured)
                .map_err(|e| NonoError::SandboxInit(format!("ETI Capture pipe read: {e}")))?;
        }

        let status = child.wait().map_err(NonoError::CommandExecution)?;
        untrack_child(state, child.id())?;

        if captured.len() > MAX_CAPTURE_STDOUT {
            return Err(NonoError::SandboxInit(
                "ETI Capture: output exceeds limit".to_string(),
            ));
        }

        let exit_code = status.code().unwrap_or(1);
        Ok((exit_code, captured))
    }

    // ── Environment filtering ─────────────────────────────────────────────────

    fn filter_child_env(
        state: &EtiState,
        request: &EtiShimRequest,
        policy: &CommandSandboxConfig,
    ) -> Result<Vec<Vec<u8>>> {
        let allow = if let Some(env_config) = &policy.environment {
            env_config.allow_vars.as_deref()
        } else {
            None
        };

        let mut result: Vec<Vec<u8>> = Vec::new();
        for entry in &request.env {
            let Some(eq) = entry.iter().position(|&b| b == b'=') else {
                continue;
            };
            let name = &entry[..eq];
            let Ok(name_str) = std::str::from_utf8(name) else {
                continue;
            };
            // Block NONO_ reserved prefix.
            if name_str.starts_with("NONO_") {
                continue;
            }
            if env_name_allowed(name_str, allow) {
                // Resolve broker nonces.
                let broker = state.token_broker.lock().map_err(|_| {
                    NonoError::SandboxInit("ETI token broker lock poisoned".to_string())
                })?;
                if let Some(resolved) = broker.resolve_env_entry(entry) {
                    result.push(resolved);
                } else {
                    result.push(entry.clone());
                }
                drop(broker);
            }
        }

        // Inject set_vars from policy.
        if let Some(env_config) = &policy.environment {
            for (k, v) in &env_config.set_vars {
                let mut entry = k.as_bytes().to_vec();
                entry.push(b'=');
                entry.extend_from_slice(v.as_bytes());
                result.push(entry);
            }
        }

        // Inject resolved credentials.
        for cred_name in &policy.use_credentials {
            if let Some(cred) = state.credential_handles.get(cred_name) {
                match cred {
                    ResolvedCredential::SshAgent { socket_path } => {
                        let mut entry = b"SSH_AUTH_SOCK=".to_vec();
                        entry.extend_from_slice(socket_path.as_os_str().as_bytes());
                        result.push(entry);
                    }
                }
            }
        }

        Ok(result)
    }

    fn env_name_allowed(name: &str, allow: Option<&[String]>) -> bool {
        let Some(allow) = allow else {
            // No allow list configured — use safe default (empty env).
            return false;
        };
        for pattern in allow {
            if pattern == "*" {
                return true;
            }
            if let Some(prefix) = pattern.strip_suffix('*') {
                if name.starts_with(prefix) {
                    return true;
                }
            }
            if pattern == name {
                return true;
            }
        }
        false
    }

    // ── Policy selection ──────────────────────────────────────────────────────

    fn select_effective_policy<'a>(
        caller: &Caller,
        command_name: &str,
        config: &'a crate::command_policy::CommandPolicyConfig,
    ) -> Result<&'a CommandSandboxConfig> {
        match caller {
            Caller::Session => {
                // Top-level sandbox shorthand: if `sandbox` is set, use it.
                if let Some(ref s) = config.sandbox {
                    return Ok(s);
                }
                if let Some(policy) = config.from.get("session") {
                    match policy {
                        crate::command_policy::CommandFromConfig::Policy(p) => return Ok(p),
                        crate::command_policy::CommandFromConfig::Deny(_) => {
                            return Err(NonoError::BlockedCommand {
                                command: command_name.to_string(),
                                reason: "session caller denied".to_string(),
                            });
                        }
                    }
                }
                Err(NonoError::BlockedCommand {
                    command: command_name.to_string(),
                    reason: "missing_from".to_string(),
                })
            }
            Caller::Command { name } => {
                if let Some(policy) = config.from.get(name.as_str()) {
                    match policy {
                        crate::command_policy::CommandFromConfig::Policy(p) => Ok(p),
                        crate::command_policy::CommandFromConfig::Deny(_) => {
                            Err(NonoError::BlockedCommand {
                                command: command_name.to_string(),
                                reason: format!("{name} caller denied"),
                            })
                        }
                    }
                } else {
                    Err(NonoError::BlockedCommand {
                        command: command_name.to_string(),
                        reason: "missing_from".to_string(),
                    })
                }
            }
        }
    }

    fn resolve_intercept_action<'a>(
        config: &'a crate::command_policy::CommandPolicyConfig,
        argv: &[Vec<u8>],
    ) -> &'a InterceptActionConfig {
        static PASSTHROUGH: InterceptActionConfig = InterceptActionConfig::Passthrough;
        let args_tail: Vec<&[u8]> = argv.iter().skip(1).map(|a| a.as_slice()).collect();
        for rule in &config.intercept {
            if rule.args.is_empty() {
                return &rule.action;
            }
            if args_tail.len() >= rule.args.len() {
                let matches = rule
                    .args
                    .iter()
                    .zip(args_tail.iter())
                    .all(|(pat, arg)| arg == &pat.as_bytes());
                if matches {
                    return &rule.action;
                }
            }
        }
        &PASSTHROUGH
    }

    // ── Caller helpers ────────────────────────────────────────────────────────

    fn caller_label(caller: &Caller) -> String {
        match caller {
            Caller::Session => "session".to_string(),
            Caller::Command { name } => name.clone(),
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
        _recorder: Option<&Arc<Mutex<crate::audit_integrity::AuditRecorder>>>,
        _request: &EtiShimRequest,
        _session_id: &str,
        _peer_pid: u32,
        _session_root_pid: u32,
        _caller: Option<&Caller>,
        _action: &str,
        _deny_reason: Option<String>,
        _exit_code: Option<i32>,
    ) -> Result<()> {
        // TODO: wire up audit recording for macOS (same structure as Linux).
        Ok(())
    }

    // ── Runtime dir + socket ──────────────────────────────────────────────────

    fn create_runtime_dir() -> Result<PathBuf> {
        let base = std::env::temp_dir();
        let uid = unsafe { libc::getuid() };
        let dir = base.join(format!("nono-eti-{uid}"));
        for i in 0..16u32 {
            let candidate = dir.join(format!("{i:04x}"));
            match fs::create_dir_all(&candidate) {
                Ok(()) => {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).map_err(
                        |e| NonoError::ConfigWrite {
                            path: candidate.clone(),
                            source: e,
                        },
                    )?;
                    return Ok(candidate);
                }
                Err(_) => continue,
            }
        }
        Err(NonoError::SandboxInit(
            "ETI: failed to create runtime dir".to_string(),
        ))
    }

    fn bind_runtime_socket(socket_path: &Path) -> Result<UnixListener> {
        // Remove a stale socket left by a previous crashed run before binding.
        if socket_path.exists() {
            let _ = fs::remove_file(socket_path);
        }
        UnixListener::bind(socket_path).map_err(|e| {
            NonoError::SandboxInit(format!("ETI: bind socket {}: {e}", socket_path.display()))
        })
    }

    fn guarded_remove_runtime_dir(dir: &Path) -> Result<()> {
        let meta = match fs::metadata(dir) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let uid = unsafe { libc::getuid() };
        if meta.uid() != uid {
            return Err(NonoError::SandboxInit(
                "ETI: runtime dir owner mismatch, skipping cleanup".to_string(),
            ));
        }
        if meta.permissions().mode() & 0o777 != 0o700 {
            return Err(NonoError::SandboxInit(
                "ETI: runtime dir mode unexpected, skipping cleanup".to_string(),
            ));
        }
        fs::remove_dir_all(dir).map_err(|e| NonoError::ConfigWrite {
            path: dir.to_path_buf(),
            source: e,
        })?;
        Ok(())
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
            .map_err(|e| NonoError::SandboxInit(format!("ETI: current_exe failed: {e}")))?;
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

    fn materialize_shim(
        shim_source: &Path,
        runtime_dir: &Path,
        name: &str,
    ) -> Result<ShimIdentity> {
        let shim_path = runtime_dir.join(name);
        // Hard link so the shim has its own name (argv[0]) while sharing the binary.
        if let Err(_) = fs::hard_link(shim_source, &shim_path) {
            // Fallback: copy (cross-device or unsupported FS).
            fs::copy(shim_source, &shim_path).map_err(|e| NonoError::ConfigWrite {
                path: shim_path.clone(),
                source: e,
            })?;
        }
        // Canonicalize so the registered path matches what proc_pidpath returns
        // on macOS (/var/folders is a symlink to /private/var/folders).
        let canonical_path = shim_path.canonicalize().unwrap_or(shim_path.clone());
        let meta = fs::metadata(&canonical_path).map_err(|e| NonoError::ConfigRead {
            path: canonical_path.clone(),
            source: e,
        })?;
        use std::os::unix::fs::MetadataExt;
        Ok(ShimIdentity {
            path: canonical_path,
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    // ── Credentials ───────────────────────────────────────────────────────────

    fn resolve_credentials(
        credentials: &BTreeMap<String, crate::command_policy::CommandCredentialConfig>,
    ) -> Result<BTreeMap<String, ResolvedCredential>> {
        let mut result = BTreeMap::new();
        for (name, cred) in credentials {
            match cred.credential_type {
                CommandCredentialType::SshAgent => {
                    let socket_env = cred
                        .socket
                        .as_deref()
                        .unwrap_or("SSH_AUTH_SOCK")
                        .trim_start_matches('$');
                    let socket_str = std::env::var(socket_env).unwrap_or_default();
                    if !socket_str.is_empty() {
                        result.insert(
                            name.clone(),
                            ResolvedCredential::SshAgent {
                                socket_path: PathBuf::from(socket_str),
                            },
                        );
                    }
                }
                CommandCredentialType::RawFile => {} // not resolved on macOS ETI
            }
        }
        Ok(result)
    }

    // ── Platform requirements ─────────────────────────────────────────────────

    fn validate_platform_requirements(_config: &CommandPoliciesConfig) -> Result<()> {
        // macOS ETI v2: no Landlock probing needed. Seatbelt is always available.
        Ok(())
    }

    // ── IPC framing ───────────────────────────────────────────────────────────

    fn validate_ipc_request(request: &EtiShimRequest) -> Result<()> {
        if request.argv.is_empty() {
            return Err(NonoError::SandboxInit("ETI IPC: empty argv".to_string()));
        }
        if request.argv.len() > MAX_ARGC {
            return Err(NonoError::SandboxInit("ETI IPC: argc limit".to_string()));
        }
        if request.env.len() > MAX_ENV {
            return Err(NonoError::SandboxInit("ETI IPC: env limit".to_string()));
        }
        if request.cwd.len() > MAX_CWD || request.cwd.contains(&0) {
            return Err(NonoError::SandboxInit("ETI IPC: cwd rejected".to_string()));
        }
        for arg in &request.argv {
            if arg.len() > MAX_ARG || arg.contains(&0) {
                return Err(NonoError::SandboxInit(
                    "ETI IPC: argv entry rejected".to_string(),
                ));
            }
        }
        for entry in &request.env {
            if entry.len() > MAX_ENV_ENTRY || entry.contains(&0) {
                return Err(NonoError::SandboxInit(
                    "ETI IPC: env entry rejected".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
        let payload = serde_json::to_vec(value)
            .map_err(|e| NonoError::SandboxInit(format!("ETI IPC serialize: {e}")))?;
        if payload.len() > MAX_FRAME {
            return Err(NonoError::SandboxInit(
                "ETI IPC frame too large".to_string(),
            ));
        }
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .map_err(|e| NonoError::SandboxInit(format!("ETI IPC write len: {e}")))?;
        stream
            .write_all(&payload)
            .map_err(|e| NonoError::SandboxInit(format!("ETI IPC write payload: {e}")))
    }

    fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| NonoError::SandboxInit(format!("ETI IPC read len: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME {
            return Err(NonoError::SandboxInit(
                "ETI IPC frame too large".to_string(),
            ));
        }
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .map_err(|e| NonoError::SandboxInit(format!("ETI IPC read payload: {e}")))?;
        serde_json::from_slice(&buf)
            .map_err(|e| NonoError::SandboxInit(format!("ETI IPC deserialize: {e}")))
    }

    fn is_tty(fd: i32) -> bool {
        // SAFETY: isatty is async-signal-safe and always returns 0 or 1.
        unsafe { libc::isatty(fd) != 0 }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use macos::{
    PreparedEtiRuntime, log_main_total, maybe_run_internal_eti_entrypoint, record_main_start,
};
