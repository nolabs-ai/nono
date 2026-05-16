use super::*;

// Phase 17: Anonymous-pipe stdio for the Windows detached path.
// These imports are NOT in the parent module (mod.rs) by default — they live
// only in launch.rs because they are exclusively used by the new
// DetachedStdioPipes struct + spawn_windows_child wiring.
use windows_sys::Win32::Foundation::{
    SetHandleInformation, BOOL, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;

// Phase 31 D-06: `OwnedHandle` and its `raw()` / `Drop` impls were lifted into
// the `nono` crate (`nono::OwnedHandle`); both `nono-cli` and
// `nono-shell-broker` consume the same RAII wrapper. The local impls were
// removed (orphan-rule incompatible after the lift); see the
// `pub(crate) use nono::OwnedHandle;` re-export in
// `crates/nono-cli/src/exec_strategy_windows/mod.rs`.

impl Drop for ProcessContainment {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe {
                // SAFETY: `self.job` was returned by CreateJobObjectW and is
                // owned by this struct. Closing the handle releases the job.
                CloseHandle(self.job);
            }
        }
    }
}

/// Phase 17: Anonymous-pipe stdio for the Windows detached path (ATCH-01).
///
/// Holds three pairs of anonymous pipe handles (stdin, stdout, stderr).
/// At spawn time:
///   - The CHILD-end handles (`stdin_read`, `stdout_write`, `stderr_write`) are
///     bound to `STARTUPINFOW.hStd*` and inherited by the child via
///     `CreateProcessW(.., bInheritHandles=TRUE, ..)`.
///   - The PARENT-end handles (`stdout_read`, `stderr_read`, `stdin_write`) are
///     flipped non-inheritable via `SetHandleInformation(HANDLE_FLAG_INHERIT, 0)`
///     so the child does NOT receive duplicates of them.
///   - After `CreateProcessW` returns successfully, the supervisor calls
///     `close_child_ends()` to release its copy of the child-end handles. The
///     child still holds its own duplicates (inherited at spawn).
///
/// Lifetime: parent-end handles must outlive the bridge threads in
/// `start_logging` / `start_data_pipe_server`. Owned by `WindowsSupervisorRuntime`
/// for the duration of the child process. `Drop` closes every handle exactly once,
/// guarded by `INVALID_HANDLE_VALUE` / null checks so post-`close_child_ends`
/// fields are not double-closed.
///
/// See `.planning/phases/17-attach-streaming/17-RESEARCH.md` Code Example 1
/// and 17-PATTERNS.md § DetachedStdioPipes for the full mechanical contract.
#[derive(Debug)]
pub(super) struct DetachedStdioPipes {
    /// Parent end — supervisor reads child stdout from this.
    pub stdout_read: HANDLE,
    /// Parent end — supervisor reads child stderr from this.
    pub stderr_read: HANDLE,
    /// Parent end — supervisor writes child stdin to this.
    pub stdin_write: HANDLE,
    /// Child end — set in STARTUPINFOW.hStdInput; closed by supervisor after CreateProcess.
    pub stdin_read: HANDLE,
    /// Child end — set in STARTUPINFOW.hStdOutput; closed by supervisor after CreateProcess.
    pub stdout_write: HANDLE,
    /// Child end — set in STARTUPINFOW.hStdError; closed by supervisor after CreateProcess.
    pub stderr_write: HANDLE,
}

impl DetachedStdioPipes {
    pub fn create() -> Result<Self> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            // Both ends inheritable initially; flip parent ends OFF below via
            // SetHandleInformation. This is the canonical Win32 idiom for
            // "child sees one end, parent sees the other" (RESEARCH.md A1).
            bInheritHandle: 1,
        };

        let (stdin_read, stdin_write) = create_one_pipe(&sa, "stdin")?;
        let (stdout_read, stdout_write) = create_one_pipe(&sa, "stdout").inspect_err(|_| {
            // SAFETY: stdin_read / stdin_write were returned by CreatePipe in the
            // same scope and not yet returned to caller; close on the error path
            // before propagating to avoid leaking on the failure cascade.
            unsafe {
                CloseHandle(stdin_read);
                CloseHandle(stdin_write);
            }
        })?;
        let (stderr_read, stderr_write) = create_one_pipe(&sa, "stderr").inspect_err(|_| {
            // SAFETY: same scope, same lifetime guarantees as the stdout-error
            // arm above; close all four prior handles before propagating.
            unsafe {
                CloseHandle(stdin_read);
                CloseHandle(stdin_write);
                CloseHandle(stdout_read);
                CloseHandle(stdout_write);
            }
        })?;

        // SAFETY: parent-end handles are owned by this thread and not yet
        // inherited by any child. Flipping HANDLE_FLAG_INHERIT off here ensures
        // the supervisor-side ends are NOT duplicated into the child during
        // CreateProcessW(.., bInheritHandles=TRUE, ..). Threat T-17-01.
        unsafe {
            SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);
        }

        Ok(Self {
            stdout_read,
            stderr_read,
            stdin_write,
            stdin_read,
            stdout_write,
            stderr_write,
        })
    }

    /// Close the child-end handles after `CreateProcess` inherits them.
    ///
    /// Must be called AFTER `CreateProcessW` returns successfully (so the child
    /// already holds its own duplicates) and BEFORE `ResumeThread` (so the child
    /// observes EOF on stdin only when the supervisor's parent-end write handle
    /// is closed later). After this call, the three child-end fields equal
    /// `INVALID_HANDLE_VALUE`; the call is idempotent.
    ///
    /// # Safety
    /// Caller must guarantee `CreateProcessW` has returned successfully and the
    /// child already holds its own duplicate of the inheritable handles.
    pub unsafe fn close_child_ends(&mut self) {
        if self.stdin_read != INVALID_HANDLE_VALUE {
            CloseHandle(self.stdin_read);
            self.stdin_read = INVALID_HANDLE_VALUE;
        }
        if self.stdout_write != INVALID_HANDLE_VALUE {
            CloseHandle(self.stdout_write);
            self.stdout_write = INVALID_HANDLE_VALUE;
        }
        if self.stderr_write != INVALID_HANDLE_VALUE {
            CloseHandle(self.stderr_write);
            self.stderr_write = INVALID_HANDLE_VALUE;
        }
    }
}

impl Drop for DetachedStdioPipes {
    fn drop(&mut self) {
        // SAFETY: every handle was returned by CreatePipe in `create()` and is
        // owned by Self. `close_child_ends` may have already zeroed three of
        // them — guarded by the INVALID / null check below. Each close happens
        // at most once across the struct's lifetime.
        unsafe {
            for h in [
                self.stdin_read,
                self.stdout_write,
                self.stderr_write,
                self.stdin_write,
                self.stdout_read,
                self.stderr_read,
            ] {
                if h != INVALID_HANDLE_VALUE && !h.is_null() {
                    CloseHandle(h);
                }
            }
        }
    }
}

fn create_one_pipe(sa: &SECURITY_ATTRIBUTES, label: &str) -> Result<(HANDLE, HANDLE)> {
    let mut read: HANDLE = INVALID_HANDLE_VALUE;
    let mut write: HANDLE = INVALID_HANDLE_VALUE;
    // SAFETY: CreatePipe writes into the two HANDLE locals (out-params) and
    // returns nonzero on success. `sa` is a valid SECURITY_ATTRIBUTES with
    // non-null nLength constructed by the caller.
    let ok = unsafe { CreatePipe(&mut read, &mut write, sa as *const _, 0) };
    if ok == 0 {
        return Err(NonoError::SandboxInit(format!(
            "CreatePipe({label}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((read, write))
}

pub(super) fn create_process_containment(session_id: Option<&str>) -> Result<ProcessContainment> {
    let name_u16 = session_id.map(|id| {
        let name = format!(r"Local\nono-session-{}", id);
        to_u16_null_terminated(&name)
    });

    let job = unsafe {
        // SAFETY: If session_id is provided, we create a named job object using
        // the Local\ namespace. If None, we create an unnamed job object.
        // Null security attributes are valid for both.
        CreateJobObjectW(
            std::ptr::null(),
            name_u16
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
        )
    };
    if job.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "Failed to create Windows process containment job object (name={:?}, error={})",
            session_id,
            unsafe { GetLastError() }
        )));
    }

    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe {
        // SAFETY: JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a plain Win32 FFI
        // struct. Zero-initialization is the standard baseline before setting
        // the specific fields we rely on below.
        std::mem::zeroed()
    };
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    let ok = unsafe {
        // SAFETY: `limits` points to initialized memory of the exact struct
        // type required for JobObjectExtendedLimitInformation.
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        unsafe {
            // SAFETY: `job` is an owned handle created above.
            CloseHandle(job);
        }
        return Err(NonoError::SandboxInit(
            "Failed to configure Windows process containment job object".to_string(),
        ));
    }

    Ok(ProcessContainment { job })
}

pub(super) fn apply_process_handle_to_containment(
    containment: &ProcessContainment,
    process: HANDLE,
) -> Result<()> {
    let ok = unsafe {
        // SAFETY: `containment.job` is a live job handle owned by the current
        // process, and `process` is a live process handle returned by
        // CreateProcessW/CreateProcessAsUserW.
        AssignProcessToJobObject(containment.job, process)
    };
    if ok == 0 {
        return Err(NonoError::SandboxInit(
            "Failed to assign Windows child process to process containment job object".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn terminate_suspended_process(process: HANDLE, reason: &str) {
    let _ = unsafe {
        // SAFETY: `process` is a live process handle that the caller owns for the
        // duration of this cleanup path. Best-effort termination preserves fail-closed behavior.
        TerminateProcess(process, 1)
    };
    tracing::debug!("terminated suspended Windows child after containment failure: {reason}");
}

/// Exit code embedded in the Job Object when the supervisor terminates the
/// tree for a `--timeout` wall-clock expiry. Equals `STATUS_TIMEOUT` /
/// `WAIT_TIMEOUT` (`0x00000102` = 258 decimal). Users see this as the
/// supervisor's exit code when the `--timeout` deadline fires.
pub(super) const STATUS_TIMEOUT_EXIT_CODE: u32 = 0x0000_0102;

/// Terminate every process in the given Job Object with the supplied exit code.
/// Used by the supervisor to honor `--timeout` (RESL-03) and potentially by any
/// future supervisor-initiated kill paths.
///
/// Returns `Err(NonoError::CommandExecution(...))` when the FFI call fails.
/// The Job Object's `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` flag (set by
/// `create_process_containment`) remains the safety-net if this FFI call
/// misfires — when `ProcessContainment` drops, the kernel still tears the
/// tree down. See `.planning/phases/16-resource-limits/16-CONTEXT.md`
/// § Failure Modes.
pub(super) fn terminate_job_object(job: HANDLE, exit_code: u32) -> Result<()> {
    let ok = unsafe {
        // SAFETY: `job` is a live Job Object handle borrowed from
        // `ProcessContainment`. `TerminateJobObject` requires
        // JOB_OBJECT_TERMINATE access, which the handle returned by
        // `CreateJobObjectW` has by default.
        TerminateJobObject(job, exit_code)
    };
    if ok == 0 {
        return Err(NonoError::CommandExecution(std::io::Error::other(format!(
            "TerminateJobObject failed (exit_code={}, GetLastError={})",
            exit_code,
            unsafe { GetLastError() }
        ))));
    }
    Ok(())
}

pub(super) fn resume_contained_process(process: HANDLE, thread: HANDLE) -> Result<()> {
    let resume_result = unsafe {
        // SAFETY: `thread` is the live primary thread handle returned by
        // CreateProcessW/CreateProcessAsUserW. Resuming it starts execution only
        // after containment has already been attached.
        ResumeThread(thread)
    };
    if resume_result == u32::MAX {
        terminate_suspended_process(process, "ResumeThread failed");
        return Err(NonoError::SandboxInit(
            "Failed to resume Windows child process after attaching containment".to_string(),
        ));
    }
    Ok(())
}

/// Apply Phase-16 resource limits (CPU / memory / process-count) to the given
/// Job Object via `SetInformationJobObject`. Must be called AFTER
/// `apply_process_handle_to_containment` and BEFORE `resume_contained_process`
/// so the child never executes without the caps in effect.
///
/// * **CPU (RESL-01):** `JobObjectCpuRateControlInformation` with
///   `ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | HARD_CAP` and
///   `CpuRate = percent * 100`.
/// * **Memory (RESL-02) + max-processes (RESL-04):** Read-modify-write on
///   `JobObjectExtendedLimitInformation` so the OR-in of new flag bits
///   preserves `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
///   JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` that
///   `create_process_containment` set.
///
/// RESL-03 (wall-clock timeout) is NOT applied here — it is enforced by a
/// supervisor-side timer in Plan 16-02 Task 1 via `TerminateJobObject`.
///
/// Fail-closed: any `SetInformationJobObject` or `QueryInformationJobObject`
/// failure returns `Err(NonoError::SandboxInit(...))` naming the failing limit
/// and the Win32 last-error; the caller is expected to run
/// `terminate_suspended_process` on the child.
pub(super) fn apply_resource_limits(
    containment: &ProcessContainment,
    limits: &crate::launch_runtime::ResourceLimits,
) -> Result<()> {
    if limits.is_empty() {
        return Ok(());
    }

    // CPU — separate info class from the extended-limit struct.
    if let Some(percent) = limits.cpu_percent {
        let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe {
            // SAFETY: FFI POD struct, zero-init is valid.
            std::mem::zeroed()
        };
        info.ControlFlags =
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        // CpuRate field lives inside an anonymous union representing CpuRate xor MinRate/MaxRate.
        // 100% == 10000; percent * 100 is safe for u16 → u32 since 1..=100 * 100 <= 10000.
        info.Anonymous.CpuRate = u32::from(percent) * 100;
        let ok = unsafe {
            // SAFETY: `containment.job` is a live Job Object handle; `info` is a
            // fully-initialized FFI struct owned by this frame; size matches the info class.
            SetInformationJobObject(
                containment.job,
                JobObjectCpuRateControlInformation,
                std::ptr::addr_of!(info) as *const _,
                size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(NonoError::SandboxInit(format!(
                "Failed to apply --cpu-percent={percent} to Windows Job Object (GetLastError={})",
                unsafe { GetLastError() }
            )));
        }
    }

    // Memory + max-processes share JobObjectExtendedLimitInformation.
    if limits.memory_bytes.is_some() || limits.max_processes.is_some() {
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe {
            // SAFETY: FFI POD struct, zero-init is valid prior to the readback.
            std::mem::zeroed()
        };
        let mut returned: u32 = 0;
        let ok = unsafe {
            // SAFETY: `containment.job` is live; `info` is writable for
            // size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() bytes; size matches info class.
            QueryInformationJobObject(
                containment.job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of_mut!(info) as *mut _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut returned,
            )
        };
        if ok == 0 {
            return Err(NonoError::SandboxInit(format!(
                "Failed to read current Windows Job Object extended limit info (GetLastError={})",
                unsafe { GetLastError() }
            )));
        }

        if let Some(mem) = limits.memory_bytes {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = mem as usize;
        }
        if let Some(procs) = limits.max_processes {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = procs;
        }

        let ok = unsafe {
            // SAFETY: `info` was populated by Query above and mutated in place; size matches.
            SetInformationJobObject(
                containment.job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info) as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            let which = match (
                limits.memory_bytes.is_some(),
                limits.max_processes.is_some(),
            ) {
                (true, true) => "--memory + --max-processes",
                (true, false) => "--memory",
                (false, true) => "--max-processes",
                (false, false) => "(none)",
            };
            return Err(NonoError::SandboxInit(format!(
                "Failed to apply {which} to Windows Job Object (GetLastError={})",
                unsafe { GetLastError() }
            )));
        }
    }

    Ok(())
}

pub(super) fn prepare_runtime_hardened_args(
    resolved_program: &Path,
    args: &[String],
    interactive: bool,
) -> Vec<String> {
    let program_name = resolved_program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match program_name.as_str() {
        "cmd.exe" | "cmd" => {
            if interactive
                || args
                    .first()
                    .is_some_and(|arg| arg.eq_ignore_ascii_case("/d"))
            {
                args.to_vec()
            } else {
                let mut hardened = Vec::with_capacity(args.len() + 1);
                hardened.push("/d".to_string());
                hardened.extend_from_slice(args);
                hardened
            }
        }
        "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh" => {
            let mut hardened = Vec::with_capacity(args.len() + 3);
            let mut has_no_logo = false;

            if !interactive {
                let mut has_no_profile = false;
                let mut has_non_interactive = false;

                for arg in args {
                    if arg.eq_ignore_ascii_case("-NoProfile") {
                        has_no_profile = true;
                    } else if arg.eq_ignore_ascii_case("-NonInteractive") {
                        has_non_interactive = true;
                    } else if arg.eq_ignore_ascii_case("-NoLogo") {
                        has_no_logo = true;
                    }
                }

                if !has_no_profile {
                    hardened.push("-NoProfile".to_string());
                }
                if !has_non_interactive {
                    hardened.push("-NonInteractive".to_string());
                }
            } else {
                for arg in args {
                    if arg.eq_ignore_ascii_case("-NoLogo") {
                        has_no_logo = true;
                    }
                }
            }

            if !has_no_logo {
                hardened.push("-NoLogo".to_string());
            }
            hardened.extend_from_slice(args);
            hardened
        }
        "cscript.exe" | "cscript" => {
            if interactive {
                return args.to_vec();
            }
            let mut hardened = Vec::with_capacity(args.len() + 2);
            let mut has_no_logo = false;
            let mut has_batch = false;

            for arg in args {
                if arg.eq_ignore_ascii_case("//NoLogo") {
                    has_no_logo = true;
                } else if arg.eq_ignore_ascii_case("//B") {
                    has_batch = true;
                }
            }

            if !has_no_logo {
                hardened.push("//NoLogo".to_string());
            }
            if !has_batch {
                hardened.push("//B".to_string());
            }
            hardened.extend_from_slice(args);
            hardened
        }
        "wscript.exe" | "wscript" => {
            if interactive {
                return args.to_vec();
            }
            if args.iter().any(|arg| arg.eq_ignore_ascii_case("//NoLogo")) {
                args.to_vec()
            } else {
                let mut hardened = Vec::with_capacity(args.len() + 1);
                hardened.push("//NoLogo".to_string());
                hardened.extend_from_slice(args);
                hardened
            }
        }
        _ => args.to_vec(),
    }
}

pub(super) fn build_child_env(config: &ExecConfig<'_>) -> Vec<(String, String)> {
    let mut env_pairs = Vec::new();
    for (key, value) in std::env::vars() {
        if !should_skip_env_var(
            &key,
            &config.env_vars,
            &[
                "NONO_CAP_FILE",
                "PATH",
                "PATHEXT",
                "COMSPEC",
                "SystemRoot",
                "windir",
                "SystemDrive",
                "NoDefaultCurrentDirectoryInExePath",
                "TMP",
                "TEMP",
                "TMPDIR",
                "APPDATA",
                "LOCALAPPDATA",
                "HOME",
                "USERPROFILE",
                "HOMEDRIVE",
                "HOMEPATH",
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
                "PROGRAMDATA",
                "ALLUSERSPROFILE",
                "PUBLIC",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramW6432",
                "CommonProgramFiles",
                "CommonProgramFiles(x86)",
                "CommonProgramW6432",
                "OneDrive",
                "OneDriveConsumer",
                "OneDriveCommercial",
                "INETCACHE",
                "INETCOOKIES",
                "INETHISTORY",
                "PSModulePath",
                "PSModuleAnalysisCachePath",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "DOTNET_CLI_HOME",
                "NUGET_PACKAGES",
                "NUGET_HTTP_CACHE_PATH",
                "NUGET_PLUGINS_CACHE_PATH",
                "ChocolateyInstall",
                "ChocolateyToolsLocation",
                "VCPKG_ROOT",
                "NPM_CONFIG_CACHE",
                "NPM_CONFIG_USERCONFIG",
                "YARN_CACHE_FOLDER",
                "PIP_CACHE_DIR",
                "PIP_CONFIG_FILE",
                "PIP_BUILD_TRACKER",
                "PYTHONPYCACHEPREFIX",
                "PYTHONUSERBASE",
                "GOCACHE",
                "GOMODCACHE",
                "GOPATH",
                "HISTFILE",
                "LESSHISTFILE",
                "NODE_REPL_HISTORY",
                "PYTHONHISTFILE",
                "SQLITE_HISTORY",
                "IPYTHONDIR",
                "GEM_HOME",
                "GEM_PATH",
                "BUNDLE_USER_HOME",
                "BUNDLE_USER_CACHE",
                "BUNDLE_USER_CONFIG",
                "BUNDLE_APP_CONFIG",
                "COMPOSER_HOME",
                "COMPOSER_CACHE_DIR",
                "GRADLE_USER_HOME",
                "MAVEN_USER_HOME",
                "RIPGREP_CONFIG_PATH",
                "AWS_SHARED_CREDENTIALS_FILE",
                "AWS_CONFIG_FILE",
                "AZURE_CONFIG_DIR",
                "KUBECONFIG",
                "DOCKER_CONFIG",
                "CLOUDSDK_CONFIG",
                "GIT_CONFIG_GLOBAL",
                "GNUPGHOME",
                "TF_CLI_CONFIG_FILE",
                "TF_DATA_DIR",
            ],
        ) {
            // Plan 35-01 (REQ-PORT-CLOSURE-01 / P34-DEFER-08a-1 closure):
            // mirror the Unix env-filter precedence from
            // exec_strategy.rs:443-456 (Plan 34-08a Wave 2 / D-20 replay
            // of upstream 1b412a7 + 3657c935). Deny-list checked BEFORE
            // allow-list; both bypassed by nono-injected credentials
            // (config.env_vars appended unconditionally below).
            if let Some(ref denied) = config.denied_env_vars {
                if is_env_var_denied(&key, denied) {
                    continue;
                }
            }
            if let Some(ref allowed) = config.allowed_env_vars {
                if !is_env_var_allowed(&key, allowed) {
                    continue;
                }
            }
            env_pairs.push((key, value));
        }
    }

    if let Some(cap_file) = config.cap_file {
        env_pairs.push((
            "NONO_CAP_FILE".to_string(),
            cap_file.to_string_lossy().into_owned(),
        ));
    }

    for (key, value) in &config.env_vars {
        env_pairs.push(((*key).to_string(), (*value).to_string()));
    }

    append_windows_runtime_env(&mut env_pairs, config);

    env_pairs
}

fn append_windows_runtime_env(env_pairs: &mut Vec<(String, String)>, config: &ExecConfig<'_>) {
    let system_root = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows"));
    let windows_system32 = system_root.join("System32");

    env_pairs.push((
        "PATH".to_string(),
        format!(
            r"{win}\System32;{win};{win}\System32\Wbem;{win}\System32\WindowsPowerShell\v1.0",
            win = system_root.display()
        ),
    ));
    env_pairs.push((
        "PATHEXT".to_string(),
        ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC".to_string(),
    ));
    env_pairs.push((
        "COMSPEC".to_string(),
        format!(r"{win}\System32\cmd.exe", win = system_root.display()),
    ));
    env_pairs.push((
        "SystemRoot".to_string(),
        system_root.to_string_lossy().into_owned(),
    ));
    env_pairs.push((
        "windir".to_string(),
        system_root.to_string_lossy().into_owned(),
    ));
    env_pairs.push((
        "SystemDrive".to_string(),
        windows_system32.display().to_string(),
    ));
    env_pairs.push((
        "NoDefaultCurrentDirectoryInExePath".to_string(),
        "1".to_string(),
    ));

    let Some(runtime_root) = choose_windows_runtime_root(config) else {
        return;
    };

    let runtime_dirs = [
        ("TMP", runtime_root.join("tmp")),
        ("TEMP", runtime_root.join("tmp")),
        ("TMPDIR", runtime_root.join("tmp")),
        ("APPDATA", runtime_root.join("roaming")),
        ("LOCALAPPDATA", runtime_root.join("local")),
        ("HOME", runtime_root.join("home")),
        ("USERPROFILE", runtime_root.join("home")),
        ("XDG_CONFIG_HOME", runtime_root.join("config")),
        ("XDG_CACHE_HOME", runtime_root.join("cache")),
        ("XDG_DATA_HOME", runtime_root.join("data")),
        ("XDG_STATE_HOME", runtime_root.join("state")),
        ("PROGRAMDATA", runtime_root.join("programdata")),
        ("ALLUSERSPROFILE", runtime_root.join("programdata")),
        ("PUBLIC", runtime_root.join("public")),
        ("ProgramFiles", runtime_root.join("programfiles")),
        ("ProgramFiles(x86)", runtime_root.join("programfiles-x86")),
        ("ProgramW6432", runtime_root.join("programfiles-w6432")),
        (
            "CommonProgramFiles",
            runtime_root.join("common-programfiles"),
        ),
        (
            "CommonProgramFiles(x86)",
            runtime_root.join("common-programfiles-x86"),
        ),
        (
            "CommonProgramW6432",
            runtime_root.join("common-programfiles-w6432"),
        ),
        ("OneDrive", runtime_root.join("onedrive")),
        ("OneDriveConsumer", runtime_root.join("onedrive-consumer")),
        (
            "OneDriveCommercial",
            runtime_root.join("onedrive-commercial"),
        ),
        ("INETCACHE", runtime_root.join("inetcache")),
        ("INETCOOKIES", runtime_root.join("inetcookies")),
        ("INETHISTORY", runtime_root.join("inethistory")),
        ("PSModulePath", runtime_root.join("psmodules")),
        (
            "PSModuleAnalysisCachePath",
            runtime_root
                .join("psmodule-cache")
                .join("ModuleAnalysisCache"),
        ),
        ("CARGO_HOME", runtime_root.join("cargo")),
        ("RUSTUP_HOME", runtime_root.join("rustup")),
        ("DOTNET_CLI_HOME", runtime_root.join("dotnet")),
        (
            "NUGET_PACKAGES",
            runtime_root.join("nuget").join("packages"),
        ),
        (
            "NUGET_HTTP_CACHE_PATH",
            runtime_root.join("nuget").join("http-cache"),
        ),
        (
            "NUGET_PLUGINS_CACHE_PATH",
            runtime_root.join("nuget").join("plugins-cache"),
        ),
        (
            "ChocolateyInstall",
            runtime_root.join("chocolatey").join("install"),
        ),
        (
            "ChocolateyToolsLocation",
            runtime_root.join("chocolatey").join("tools"),
        ),
        ("VCPKG_ROOT", runtime_root.join("vcpkg")),
        ("NPM_CONFIG_CACHE", runtime_root.join("npm").join("cache")),
        (
            "NPM_CONFIG_USERCONFIG",
            runtime_root.join("npm").join("config").join("npmrc"),
        ),
        ("YARN_CACHE_FOLDER", runtime_root.join("yarn").join("cache")),
        ("PIP_CACHE_DIR", runtime_root.join("pip").join("cache")),
        (
            "PIP_CONFIG_FILE",
            runtime_root.join("pip").join("config").join("pip.ini"),
        ),
        (
            "PIP_BUILD_TRACKER",
            runtime_root.join("pip").join("build-tracker"),
        ),
        (
            "PYTHONPYCACHEPREFIX",
            runtime_root.join("python").join("pycache"),
        ),
        (
            "PYTHONUSERBASE",
            runtime_root.join("python").join("userbase"),
        ),
        ("GOCACHE", runtime_root.join("go").join("cache")),
        ("GOMODCACHE", runtime_root.join("go").join("modcache")),
        ("GOPATH", runtime_root.join("go").join("path")),
        ("HISTFILE", runtime_root.join("history").join("shell")),
        ("LESSHISTFILE", runtime_root.join("history").join("less")),
        (
            "NODE_REPL_HISTORY",
            runtime_root.join("history").join("node-repl"),
        ),
        (
            "PYTHONHISTFILE",
            runtime_root.join("history").join("python"),
        ),
        (
            "SQLITE_HISTORY",
            runtime_root.join("history").join("sqlite"),
        ),
        ("IPYTHONDIR", runtime_root.join("ipython")),
        ("GEM_HOME", runtime_root.join("ruby").join("gems")),
        ("GEM_PATH", runtime_root.join("ruby").join("gems-path")),
        ("BUNDLE_USER_HOME", runtime_root.join("bundle").join("home")),
        (
            "BUNDLE_USER_CACHE",
            runtime_root.join("bundle").join("cache"),
        ),
        (
            "BUNDLE_USER_CONFIG",
            runtime_root.join("bundle").join("config"),
        ),
        (
            "BUNDLE_APP_CONFIG",
            runtime_root.join("bundle").join("app-config"),
        ),
        ("COMPOSER_HOME", runtime_root.join("composer").join("home")),
        (
            "COMPOSER_CACHE_DIR",
            runtime_root.join("composer").join("cache"),
        ),
        ("GRADLE_USER_HOME", runtime_root.join("gradle")),
        ("MAVEN_USER_HOME", runtime_root.join("maven")),
        (
            "RIPGREP_CONFIG_PATH",
            runtime_root.join("ripgrep").join("ripgreprc"),
        ),
        (
            "AWS_SHARED_CREDENTIALS_FILE",
            runtime_root.join("aws").join("credentials"),
        ),
        ("AWS_CONFIG_FILE", runtime_root.join("aws").join("config")),
        ("AZURE_CONFIG_DIR", runtime_root.join("azure")),
        ("KUBECONFIG", runtime_root.join("kube").join("config")),
        ("DOCKER_CONFIG", runtime_root.join("docker")),
        ("CLOUDSDK_CONFIG", runtime_root.join("gcloud")),
        ("GIT_CONFIG_GLOBAL", runtime_root.join("git").join("config")),
        ("GNUPGHOME", runtime_root.join("gnupg")),
        (
            "TF_CLI_CONFIG_FILE",
            runtime_root.join("terraform").join("terraform.rc"),
        ),
        ("TF_DATA_DIR", runtime_root.join("terraform").join("data")),
    ];

    let file_targets = ["NPM_CONFIG_USERCONFIG", "PIP_CONFIG_FILE"];
    for (key, path) in &runtime_dirs {
        let dir = if file_targets.contains(key) {
            path.parent().unwrap_or(path.as_path())
        } else {
            path.as_path()
        };
        let _ = std::fs::create_dir_all(dir);
    }

    for (key, path) in runtime_dirs {
        env_pairs.push((key.to_string(), path.to_string_lossy().into_owned()));
    }
}

fn choose_windows_runtime_root(config: &ExecConfig<'_>) -> Option<std::path::PathBuf> {
    let policy = Sandbox::windows_filesystem_policy(config.caps);
    let preferred = policy.preferred_runtime_dir(config.current_dir)?;

    if Sandbox::windows_supports_direct_writable_dir(&preferred) {
        return Some(preferred.join(".nono-runtime"));
    }

    let managed = preferred.join(".nono-runtime-low");
    if prepare_low_integrity_runtime_root(&managed) {
        return Some(managed);
    }

    let low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .map(|local| local.join("Temp").join("Low"))?;
    let fallback = low_root
        .join("nono")
        .join(sanitize_windows_runtime_label(&preferred));
    if prepare_low_integrity_runtime_root(&fallback) {
        return Some(fallback);
    }

    None
}

fn sanitize_windows_runtime_label(path: &Path) -> String {
    path.to_string_lossy().replace(['\\', '/', ':'], "_")
}

fn prepare_low_integrity_runtime_root(path: &Path) -> bool {
    if std::fs::create_dir_all(path).is_err() {
        return false;
    }
    if Sandbox::windows_supports_direct_writable_dir(path) {
        return true;
    }

    let Ok(output) = Command::new(super::system32_exe("icacls"))
        .arg(path)
        .args(["/setintegritylevel", "(OI)(CI)L"])
        .output()
    else {
        return false;
    };

    output.status.success() && Sandbox::windows_supports_direct_writable_dir(path)
}

pub(super) fn build_windows_environment_block(env_pairs: &[(String, String)]) -> Vec<u16> {
    let mut deduped = Vec::with_capacity(env_pairs.len());
    let mut seen_keys = HashSet::with_capacity(env_pairs.len());
    for (key, value) in env_pairs.iter().rev() {
        let folded = key.to_ascii_lowercase();
        if seen_keys.insert(folded) {
            deduped.push((key.clone(), value.clone()));
        }
    }
    deduped.reverse();

    let mut sorted = deduped;
    sorted.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
    });

    let mut block = Vec::new();
    for (key, value) in sorted {
        let pair = format!("{key}={value}");
        block.extend(OsStr::new(&pair).encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

pub(super) fn quote_windows_arg(arg: &str) -> String {
    if !arg.contains([' ', '\t', '"']) && !arg.is_empty() {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn normalize_windows_launch_path(path: &Path) -> std::path::PathBuf {
    let raw = path.as_os_str().to_string_lossy();

    if let Some(stripped) = raw.strip_prefix(r"\?\UNC") {
        return std::path::PathBuf::from(format!(r"\{stripped}"));
    }
    if let Some(stripped) = raw.strip_prefix(r"\?") {
        return std::path::PathBuf::from(stripped);
    }

    path.to_path_buf()
}

pub(super) fn build_command_line(resolved_program: &Path, args: &[String]) -> Vec<u16> {
    let resolved_program = normalize_windows_launch_path(resolved_program);
    let mut command_line = quote_windows_arg(&resolved_program.to_string_lossy());
    for arg in args {
        command_line.push(' ');
        command_line.push_str(&quote_windows_arg(arg));
    }
    OsStr::new(&command_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Build a Win32 command line for spawning `nono-shell-broker.exe` with flat
/// argv. Mirrors `build_command_line`'s quoting rules but accepts `OsString`
/// values so the broker's `--shell` payload (a `Path`) and the `--cwd` value
/// (also a `Path`) round-trip cleanly through OS-specific path encoding.
///
/// Quoting follows the existing `quote_windows_arg` rules: any argument
/// containing whitespace, quotes, or other special characters is double-quoted
/// with embedded quotes doubled. The broker's argv parser (Plan 31-02) treats
/// every value after a flag as an opaque string; it does NOT re-parse values
/// as flags (T-31-20 mitigation).
///
/// Phase 31 D-08 contract.
pub(super) fn build_broker_command_line(
    broker_exe: &Path,
    args: &[std::ffi::OsString],
) -> Vec<u16> {
    let broker_exe = normalize_windows_launch_path(broker_exe);
    let mut command_line = quote_windows_arg(&broker_exe.to_string_lossy());
    for a in args {
        command_line.push(' ');
        command_line.push_str(&quote_windows_arg(&a.to_string_lossy()));
    }
    OsStr::new(&command_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(super) fn should_use_low_integrity_windows_launch(caps: &CapabilitySet) -> bool {
    let policy = Sandbox::windows_filesystem_policy(caps);
    policy.has_rules()
}

/// Discriminant identifying which token-construction arm of `spawn_windows_child`'s
/// cascade applies to a given (env, config, pty) triple. Pure-function output;
/// no FFI side effects.
///
/// Branch ordering matters and is enforced here:
///   1. Detached launch (NONO_DETACHED_LAUNCH=1) → Null token (Phase 15 waiver)
///   2. PTY allocated (`pty.is_some()`) → BrokerLaunch (Phase 31 D-15;
///      replaces Phase 30's direct LowIlPrimary spawn)
///   3. Per-session SID present → WRITE_RESTRICTED (existing non-PTY supervised)
///   4. Caps demand Low-IL (legacy Direct path) → LowIlPrimary (D-15 fallback)
///   5. Fallback → Null (caller's identity)
///
/// (2) precedes (3) because `config.session_sid` is unconditionally `Some(...)`
/// for Windows supervised launches (`execution_runtime.rs:334`); the new arm
/// is reached *because* it short-circuits before the WRITE_RESTRICTED arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsTokenArm {
    /// Caller's identity (CreateProcessW with null token). Phase 15 detached
    /// path or final fallback.
    Null,
    /// WRITE_RESTRICTED + per-session restricting SID. Existing non-PTY
    /// supervised path. Triggers STATUS_DLL_INIT_FAILED (0xC0000142) under
    /// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE — hence Phase 30 D-01 routes
    /// PTY-allocating launches to BrokerLaunch instead.
    WriteRestricted,
    /// Low-IL primary token. Phase 30 D-01 supervised+PTY path; mandatory
    /// label NO_WRITE_UP enforces write-deny via MIC pre-DACL kernel check.
    ///
    /// Phase 31 D-15: This arm is RETAINED as a structurally-unreachable
    /// fallback for the legacy Direct path (`config.session_sid.is_none()
    /// && caps_demand_low_il`) and as the carrier for the only direct
    /// runtime exercise of `nono::create_low_integrity_primary_token`
    /// (the `low_integrity_primary_token_tests` module). The PTY+supervised
    /// path now routes through `BrokerLaunch`.
    LowIlPrimary,
    /// Phase 31 D-01/D-15: spawn `nono-shell-broker.exe` (Medium IL) as the
    /// caller's identity; broker self-degrades to Low IL via
    /// `nono::create_low_integrity_primary_token` and spawns the actual
    /// shell child. Replaces the Phase 30 LowIlPrimary direct-Low-IL spawn
    /// for the PTY+supervised path because the direct path triggered
    /// STATUS_DLL_INIT_FAILED (0xC0000142) at CSRSS console-attach time
    /// (RESEARCH §1b — broker pattern is the validated path; PoC PASS
    /// 2026-05-08).
    BrokerLaunch,
}

/// Pure decision function for the `spawn_windows_child` cascade. Returns the
/// token-construction arm that applies to the given inputs. No FFI calls; no
/// env reads other than the explicit `is_detached` parameter.
pub(super) fn select_windows_token_arm(
    is_detached: bool,
    has_pty: bool,
    has_session_sid: bool,
    caps_demand_low_il: bool,
) -> WindowsTokenArm {
    if is_detached {
        WindowsTokenArm::Null
    } else if has_pty {
        // Phase 31 D-15: was LowIlPrimary; PTY-allocating launches now route
        // through nono-shell-broker.exe (broker spawn at Medium IL → broker
        // self-degrades to Low IL via nono::create_low_integrity_primary_token
        // and spawns the actual sandboxed child). Rationale: the direct
        // CreateProcessAsUserW(low_il_token, ...) + PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
        // shape from Phase 30 triggered STATUS_DLL_INIT_FAILED (0xC0000142)
        // at CSRSS console-attach time during KernelBase.dll DllMain on
        // freshly-attached consoles. The broker pattern was empirically
        // validated by the PoC at .planning/quick/260508-m99-... on 2026-05-08.
        WindowsTokenArm::BrokerLaunch
    } else if has_session_sid {
        WindowsTokenArm::WriteRestricted
    } else if caps_demand_low_il {
        // Phase 31 D-15: kept as Direct-path fallback (structurally unreachable
        // today because Windows supervised launches have session_sid=Some(...)
        // unconditionally per execution_runtime.rs:334, but pinned by the
        // pty_none_caps_demand_low_il_selects_low_il test for future readers
        // and as the only direct runtime exercise of the lifted FFI primitive).
        WindowsTokenArm::LowIlPrimary
    } else {
        WindowsTokenArm::Null
    }
}

// Phase 31 D-06: `create_low_integrity_primary_token` was lifted into the `nono`
// crate as `nono::create_low_integrity_primary_token` so that both `nono-cli`
// and `nono-shell-broker` consume the same source-of-truth implementation.
// The local definition was removed; callsites here use the re-exported symbol.

pub(super) fn spawn_windows_child(
    config: &ExecConfig<'_>,
    launch_program: &Path,
    containment: &ProcessContainment,
    cmd_args: &[String],
    pty: Option<&pty_proxy::PtyPair>,
    limits: &crate::launch_runtime::ResourceLimits,
    _session_id: Option<&str>,
) -> Result<(WindowsSupervisedChild, Option<DetachedStdioPipes>)> {
    let env_pairs = build_child_env(config);
    let mut environment_block = build_windows_environment_block(&env_pairs);

    // Bind each potential holder to a named local so its Drop does NOT run
    // until after CreateProcess{AsUser}W uses the raw HANDLE. Previously,
    // `?.h_token` / `?.raw()` returned a raw HANDLE from a temporary which
    // dropped (closing the handle) before it was passed to the Win32 API,
    // yielding ERROR_INVALID_HANDLE (6).
    let _restricted_holder: Option<restricted_token::RestrictedToken>;
    let _low_integrity_holder: Option<nono::OwnedHandle>;
    // On the Windows detached launch path, the WRITE_RESTRICTED + session-SID
    // token combines with DETACHED_PROCESS + no-PTY to trigger STATUS_DLL_INIT_FAILED
    // (0xC0000142) in console-application grandchildren. The only configuration that
    // initializes the loader cleanly is a null token. Kernel-level network enforcement
    // falls back to AppID-based WFP filtering; per-session SID WFP is not available
    // on this path. See .planning/debug/resolved/windows-supervised-exec-cascade.md.
    //
    // Phase 30 D-01: When PTY is allocated (interactive `nono shell`), the cascade
    // uses a Low-IL primary token instead of WRITE_RESTRICTED + session-SID. The
    // WRITE_RESTRICTED + ConPTY combination triggers STATUS_DLL_INIT_FAILED
    // (0xC0000142) — same class of bug Phase 15 hit on the detached path with
    // DETACHED_PROCESS. Mandatory-label NO_WRITE_UP enforces write-deny because
    // Low-IL subjects do not dominate Medium-IL files (MIC pre-DACL kernel check).
    // Per-session WFP differentiation via FWPM_CONDITION_ALE_USER_ID is waived
    // on this path (falls back to AppID-based filtering, same as Phase 15
    // detached-path waiver). See .planning/phases/30-windows-nono-shell-architecture/30-CONTEXT.md.
    let is_windows_detached_launch = is_windows_detached_launch();
    let arm = select_windows_token_arm(
        is_windows_detached_launch,
        pty.is_some(),
        config.session_sid.is_some(),
        should_use_low_integrity_windows_launch(config.caps),
    );
    let h_token: HANDLE = match arm {
        WindowsTokenArm::Null => {
            _restricted_holder = None;
            _low_integrity_holder = None;
            std::ptr::null_mut()
        }
        WindowsTokenArm::WriteRestricted => {
            // Safe: the cascade reaches this arm only when config.session_sid.is_some(),
            // verified by select_windows_token_arm's has_session_sid input above.
            let sid = config.session_sid.as_ref().ok_or_else(|| {
                NonoError::SandboxInit(
                    "session_sid disappeared between gate decision and use".into(),
                )
            })?;
            let holder = restricted_token::create_restricted_token_with_sid(sid)?;
            let raw = holder.h_token;
            _restricted_holder = Some(holder);
            _low_integrity_holder = None;
            raw
        }
        WindowsTokenArm::LowIlPrimary => {
            // Phase 31 D-06: function moved to nono::create_low_integrity_primary_token
            let holder = nono::create_low_integrity_primary_token()?;
            let raw = holder.0;
            _low_integrity_holder = Some(holder);
            _restricted_holder = None;
            raw
        }
        WindowsTokenArm::BrokerLaunch => {
            // Phase 31 D-15: Broker spawns at caller's identity (Medium IL =
            // nono.exe's token), so h_token must be null on the downstream
            // CreateProcess* call. The broker self-degrades to Low IL inside
            // its own process via `nono::create_low_integrity_primary_token`
            // and spawns the actual sandboxed shell child. The actual
            // CreateProcessW(broker, ...) + PROC_THREAD_ATTRIBUTE_HANDLE_LIST
            // dispatch lives in the `if let Some(pty_pair) = pty` PTY branch
            // below — this match arm only owns the token (none) selection.
            _restricted_holder = None;
            _low_integrity_holder = None;
            std::ptr::null_mut()
        }
    };
    // NOTE: do NOT re-wrap h_token in a fresh OwnedHandle — the holder above
    // already owns the close. A second wrapper would double-close on Drop.

    let launch_program = normalize_windows_launch_path(launch_program);
    let current_dir = normalize_windows_launch_path(config.current_dir);
    let application_name = to_u16_null_terminated(&launch_program.to_string_lossy());
    let mut command_line = build_command_line(&launch_program, cmd_args);
    let current_dir_u16 = to_u16_null_terminated(&current_dir.to_string_lossy());

    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Phase 17: parent-end stdio handles for the Windows detached path.
    // Allocated lazily inside the non-PTY arm of `let created = ...` below;
    // declared here so it remains in scope for the post-CreateProcess
    // close_child_ends() call and the eventual return.
    let mut detached_stdio: Option<DetachedStdioPipes> = None;

    // Phase 31 D-01/D-15: BrokerLaunch path replaces the Phase 30 direct
    // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE+CreateProcessAsUserW(low_il_token)
    // shape (which triggered STATUS_DLL_INIT_FAILED 0xC0000142 at CSRSS
    // console-attach time during KernelBase.dll DllMain). The broker spawns
    // at caller's identity (Medium IL), inherits ONLY the ConPTY pipe handles
    // via PROC_THREAD_ATTRIBUTE_HANDLE_LIST (D-02; capability-pipe handles
    // are NOT inheritable past nono.exe), self-degrades to Low IL via
    // `nono::create_low_integrity_primary_token`, and spawns the actual
    // sandboxed shell child. PoC validation: 2026-05-08 broker-pattern
    // PASSED on Windows test box (RESEARCH §1b A1 empirically validated).
    //
    // The legacy PSEUDOCONSOLE block (else-arm below) is preserved per D-15
    // as a structurally-unreachable fallback for the legacy LowIlPrimary
    // Direct path; it remains the only direct runtime exercise of the lifted
    // `nono::create_low_integrity_primary_token` via the
    // `low_integrity_primary_token_tests` module.
    let created = if let Some(pty_pair) = pty {
        if matches!(arm, WindowsTokenArm::BrokerLaunch) {
            // D-07: Resolve broker path as sibling of the running nono.exe.
            // No env-var override surface — env-poisoning attack rejected.
            // Plan 31-01 added `NonoError::BrokerNotFound { path }` for the
            // fail-fast structured error.
            let nono_exe = std::env::current_exe().map_err(|e| {
                NonoError::SandboxInit(format!(
                    "Failed to resolve current_exe for broker location: {e}"
                ))
            })?;
            let exe_dir = nono_exe.parent().ok_or_else(|| {
                NonoError::SandboxInit(format!(
                    "Failed to resolve parent dir for broker location: {}",
                    nono_exe.display()
                ))
            })?;
            let broker_path = exe_dir.join("nono-shell-broker.exe");
            if !broker_path.exists() {
                return Err(NonoError::BrokerNotFound { path: broker_path });
            }

            // Phase 32 D-32-11/13/14: Authenticode self-trust-anchor.
            // On every dispatch (no cache, D-32-14), require broker.exe's Authenticode
            // signer subject + thumbprint to match nono.exe's own. Fail-closed; no
            // escape hatch (D-32-12). Dev-build skip via install-layout detector
            // (Pitfall 6 — #[cfg(debug_assertions)] would false-trigger under cargo
            // test --release).
            if !is_dev_build_layout(&nono_exe) {
                verify_broker_authenticode(&nono_exe, &broker_path)?;
            } else {
                tracing::info!(
                    target: "broker_authenticode",
                    "skipping broker Authenticode verify: dev-build layout detected at {}",
                    nono_exe.display()
                );
            }

            // D-02: Mark ConPTY pipe handles inheritable BEFORE CreateProcessW;
            // unmark AFTER (so they don't accidentally leak into other spawns).
            // PtyPair shape per crates/nono-cli/src/pty_proxy_windows.rs:11-15:
            //   pub struct PtyPair {
            //       pub hpcon: HPCON,
            //       pub input_write: HANDLE,
            //       pub output_read: HANDLE,
            //   }
            // The two pipe HANDLEs (NOT hpcon — that is a pseudoconsole, not
            // a pipe) are the values HANDLE_LIST whitelists for inheritance.
            let inherit_handles: [HANDLE; 2] = [pty_pair.input_write, pty_pair.output_read];

            // Flip ConPTY pipe handles to inheritable. Track for cleanup
            // along the success AND error paths so they don't leak into
            // unrelated CreateProcess calls (T-31-17 mitigation).
            for h in &inherit_handles {
                let ok = unsafe {
                    // SAFETY: Each handle is owned by `pty_pair` and lives
                    // for at least the duration of this scope. Setting the
                    // inheritance flag is documented to succeed on a valid
                    // open handle. The matching unset call below restores
                    // the prior state on both success and error paths.
                    SetHandleInformation(*h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
                };
                if ok == 0 {
                    let last = unsafe { GetLastError() };
                    // Best-effort revert on the partially-flipped handles
                    // before propagating the error (defense-in-depth).
                    for cleanup_h in &inherit_handles {
                        unsafe {
                            // SAFETY: same handle ownership rationale as above.
                            let _ = SetHandleInformation(*cleanup_h, HANDLE_FLAG_INHERIT, 0);
                        }
                    }
                    return Err(NonoError::SandboxInit(format!(
                        "SetHandleInformation(HANDLE_FLAG_INHERIT) failed (error={last})"
                    )));
                }
            }

            // Build PROC_THREAD_ATTRIBUTE_HANDLE_LIST for nono.exe → broker.
            let mut attr_size: usize = 0;
            unsafe {
                // SAFETY: First call with null list queries required size
                // (Win32 idiom). The probe always returns 0 with
                // ERROR_INSUFFICIENT_BUFFER; we don't read the return value.
                InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
            }
            let mut attr_buf = vec![0u8; attr_size];
            let attr_list: LPPROC_THREAD_ATTRIBUTE_LIST =
                attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
            let ok = unsafe {
                // SAFETY: `attr_list` points into `attr_buf` sized by the
                // probe call above for exactly one attribute slot.
                InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
            };
            if ok == 0 {
                let last = unsafe { GetLastError() };
                // Cleanup inheritance flags before propagating.
                for h in &inherit_handles {
                    unsafe {
                        // SAFETY: handle ownership rationale as above.
                        let _ = SetHandleInformation(*h, HANDLE_FLAG_INHERIT, 0);
                    }
                }
                return Err(NonoError::SandboxInit(format!(
                    "InitializeProcThreadAttributeList failed (error={last})"
                )));
            }
            let ok = unsafe {
                // SAFETY: `attr_list` initialized above; `inherit_handles`
                // outlives the UpdateProcThreadAttribute call (still in
                // scope through the CreateProcessW call below).
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    inherit_handles.as_ptr() as *mut _,
                    std::mem::size_of_val(&inherit_handles[..]),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let last = unsafe { GetLastError() };
                unsafe {
                    // SAFETY: `attr_list` initialized above; safe to release.
                    DeleteProcThreadAttributeList(attr_list);
                }
                for h in &inherit_handles {
                    unsafe {
                        // SAFETY: handle ownership rationale as above.
                        let _ = SetHandleInformation(*h, HANDLE_FLAG_INHERIT, 0);
                    }
                }
                return Err(NonoError::SandboxInit(format!(
                    "UpdateProcThreadAttribute(HANDLE_LIST) failed (error={last})"
                )));
            }

            // Build broker command line per D-08 contract (Plan 31-02 parses):
            //   "<broker_exe>" --shell "<launch_program>" \
            //     --shell-arg "<arg>"... \
            //     --inherit-handle 0x<input_hex> --inherit-handle 0x<output_hex> \
            //     --cwd "<cwd>"
            let mut broker_args: Vec<std::ffi::OsString> = Vec::new();
            broker_args.push(std::ffi::OsString::from("--shell"));
            broker_args.push(launch_program.as_os_str().to_owned());
            for a in cmd_args {
                broker_args.push(std::ffi::OsString::from("--shell-arg"));
                broker_args.push(std::ffi::OsString::from(a));
            }
            for h in &inherit_handles {
                broker_args.push(std::ffi::OsString::from("--inherit-handle"));
                broker_args.push(std::ffi::OsString::from(format!("0x{:016x}", *h as usize)));
            }
            broker_args.push(std::ffi::OsString::from("--cwd"));
            broker_args.push(current_dir.as_os_str().to_owned());

            let mut broker_command_line = build_broker_command_line(&broker_path, &broker_args);
            let broker_application_name = to_u16_null_terminated(&broker_path.to_string_lossy());

            let mut startup_info_ex: STARTUPINFOEXW = unsafe {
                // SAFETY: STARTUPINFOEXW is a plain Win32 FFI struct;
                // zero-init is documented in the Win32 SDK.
                std::mem::zeroed()
            };
            startup_info_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup_info_ex.lpAttributeList = attr_list;
            let lp_startup_info = &startup_info_ex.StartupInfo as *const STARTUPINFOW;

            // CreateProcessW (NOT AsUserW) — broker runs at caller's identity
            // (Medium IL = nono.exe's token). dwCreationFlags: CREATE_SUSPENDED
            // + CREATE_UNICODE_ENVIRONMENT + EXTENDED_STARTUPINFO_PRESENT.
            // bInheritHandles=1 because HANDLE_LIST gates the actual inherited
            // set (only the two ConPTY pipe handles flipped inheritable above).
            let created_local = unsafe {
                // SAFETY: All pointers are valid for the duration of the call.
                // The startup struct uses EXTENDED_STARTUPINFO_PRESENT which
                // matches the STARTUPINFOEXW layout we initialized.
                CreateProcessW(
                    broker_application_name.as_ptr(),
                    broker_command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1, // bInheritHandles=TRUE; HANDLE_LIST gates which handles inherit.
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                    environment_block.as_mut_ptr() as *mut _,
                    current_dir_u16.as_ptr(),
                    lp_startup_info,
                    &mut process_info,
                )
            };

            unsafe {
                // SAFETY: `attr_list` initialized above; safe to release
                // after CreateProcessW (the kernel has copied the relevant
                // attribute data into the new process's PEB).
                DeleteProcThreadAttributeList(attr_list);
            }

            // T-31-17 mitigation: unmark the ConPTY pipe handles non-inheritable
            // on BOTH success and failure paths so subsequent CreateProcess
            // calls in the supervisor don't accidentally leak them.
            for h in &inherit_handles {
                unsafe {
                    // SAFETY: handle ownership rationale as above.
                    let _ = SetHandleInformation(*h, HANDLE_FLAG_INHERIT, 0);
                }
            }

            created_local
        } else {
            // Phase 30 LEGACY path (structurally unreachable today but
            // preserved per D-15 fallback): direct Low-IL primary token spawn
            // with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE. Kept verbatim from
            // pre-Plan-31-03 source.
            let mut attr_size: usize = 0;
            unsafe {
                // SAFETY: First call with a null list queries the required buffer size.
                InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
            }

            let mut attr_buf = vec![0u8; attr_size];
            let attr_list: LPPROC_THREAD_ATTRIBUTE_LIST =
                attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;

            let ok = unsafe {
                // SAFETY: `attr_list` points to `attr_buf`, which was sized by the
                // probe call immediately above for exactly one attribute.
                InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
            };
            if ok == 0 {
                return Err(NonoError::SandboxInit(format!(
                    "InitializeProcThreadAttributeList failed (error={})",
                    unsafe { GetLastError() }
                )));
            }

            let hpcon_value = pty_pair.hpcon;
            let ok = unsafe {
                // SAFETY: `attr_list` is initialized above and `hpcon_value` remains
                // valid for the duration of process creation.
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                    std::ptr::addr_of!(hpcon_value) as *mut _,
                    size_of::<windows_sys::Win32::System::Console::HPCON>(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                unsafe {
                    // SAFETY: `attr_list` was initialized successfully above.
                    DeleteProcThreadAttributeList(attr_list);
                }
                return Err(NonoError::SandboxInit(format!(
                    "UpdateProcThreadAttribute (PSEUDOCONSOLE) failed (error={})",
                    unsafe { GetLastError() }
                )));
            }

            let mut startup_info_ex: STARTUPINFOEXW = unsafe {
                // SAFETY: STARTUPINFOEXW is a plain Win32 FFI struct; zero-init is valid.
                std::mem::zeroed()
            };
            startup_info_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup_info_ex.lpAttributeList = attr_list;

            let lp_startup_info = &startup_info_ex.StartupInfo as *const STARTUPINFOW;

            let created = if !h_token.is_null() {
                unsafe {
                    // SAFETY: All pointers are valid for the duration of the call and
                    // EXTENDED_STARTUPINFO_PRESENT matches the provided startup struct.
                    CreateProcessAsUserW(
                        h_token,
                        application_name.as_ptr(),
                        command_line.as_mut_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        0,
                        CREATE_SUSPENDED
                            | CREATE_UNICODE_ENVIRONMENT
                            | EXTENDED_STARTUPINFO_PRESENT,
                        environment_block.as_mut_ptr() as *mut _,
                        current_dir_u16.as_ptr(),
                        lp_startup_info,
                        &mut process_info,
                    )
                }
            } else {
                unsafe {
                    // SAFETY: All pointers are valid for the duration of the call and
                    // EXTENDED_STARTUPINFO_PRESENT matches the provided startup struct.
                    CreateProcessW(
                        application_name.as_ptr(),
                        command_line.as_mut_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        0,
                        CREATE_SUSPENDED
                            | CREATE_UNICODE_ENVIRONMENT
                            | EXTENDED_STARTUPINFO_PRESENT,
                        environment_block.as_mut_ptr() as *mut _,
                        current_dir_u16.as_ptr(),
                        lp_startup_info,
                        &mut process_info,
                    )
                }
            };

            unsafe {
                // SAFETY: `attr_list` was initialized above and can now be released.
                DeleteProcThreadAttributeList(attr_list);
            }
            created
        }
    } else {
        // Phase 17 (ATCH-01): on the Windows detached path (no PTY,
        // NONO_DETACHED_LAUNCH=1), allocate three anonymous pipe pairs and
        // bind the child-end handles to STARTUPINFOW.hStd*. The PTY branch
        // above is unchanged — pipe + ConPTY are mutually exclusive at the
        // gate (RESEARCH.md A6 + supervised_runtime.rs:88-94 should_allocate_pty).
        detached_stdio = if pty.is_none() && is_windows_detached_launch {
            Some(DetachedStdioPipes::create()?)
        } else {
            None
        };

        let mut startup_info: STARTUPINFOW = unsafe {
            // SAFETY: STARTUPINFOW is a plain Win32 FFI struct; zero-init is valid.
            std::mem::zeroed()
        };
        startup_info.cb = size_of::<STARTUPINFOW>() as u32;

        if let Some(ref pipes) = detached_stdio {
            // D-04 + CONTEXT.md <specifics> line 127: merge stderr into stdout
            // for visual consistency with the PTY path. The kernel routes child
            // fd 1 and fd 2 writes through the same pipe write end; supported
            // by Win32 (RESEARCH.md A5). The unused stderr_write child end
            // is still closed by close_child_ends() / Drop.
            startup_info.dwFlags = STARTF_USESTDHANDLES;
            startup_info.hStdInput = pipes.stdin_read;
            startup_info.hStdOutput = pipes.stdout_write;
            startup_info.hStdError = pipes.stdout_write;
        }

        // CRITICAL: bInheritHandles MUST be 1 when STARTF_USESTDHANDLES is set
        // with inheritable handles (RESEARCH.md Pitfall 3 / A1). The PTY
        // branch passes 0 (uses PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE instead)
        // and stays at 0. Detached-stdio branch passes 1 — but only the three
        // child-end pipe handles are inheritable; parent ends were flipped
        // non-inheritable in DetachedStdioPipes::create() (threat T-17-08).
        let inherit_handles: BOOL = if detached_stdio.is_some() { 1 } else { 0 };

        if !h_token.is_null() {
            unsafe {
                // SAFETY: All pointers are valid for the duration of the call.
                CreateProcessAsUserW(
                    h_token,
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    inherit_handles,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    environment_block.as_mut_ptr() as *mut _,
                    current_dir_u16.as_ptr(),
                    &startup_info,
                    &mut process_info,
                )
            }
        } else {
            unsafe {
                // SAFETY: All pointers are valid for the duration of the call.
                CreateProcessW(
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    inherit_handles,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    environment_block.as_mut_ptr() as *mut _,
                    current_dir_u16.as_ptr(),
                    &startup_info,
                    &mut process_info,
                )
            }
        }
    };

    if created == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to launch Windows child process (error={})",
            unsafe { GetLastError() }
        )));
    }

    let process = OwnedHandle(process_info.hProcess);
    let thread = OwnedHandle(process_info.hThread);

    // Phase 17: close the supervisor's copy of the child-end pipe handles AFTER
    // CreateProcess succeeded (so the child holds its own duplicates) and BEFORE
    // ResumeThread (so the child observes EOF on stdin only when supervisor's
    // parent-end write handle closes later). RESEARCH.md Code Example 2,
    // Pitfall 3 ordering. No-op when detached_stdio is None.
    if let Some(ref mut pipes) = detached_stdio {
        // SAFETY: CreateProcess succeeded above; the child has its own duplicates
        // of the inheritable handles. close_child_ends is idempotent.
        unsafe {
            pipes.close_child_ends();
        }
    }

    if let Err(err) = apply_process_handle_to_containment(containment, process.raw()) {
        terminate_suspended_process(process.raw(), "AssignProcessToJobObject failed");
        return Err(err);
    }
    // Phase 16 RESL-01/02/04: apply the four resource-limit info classes BEFORE
    // ResumeThread so the child never runs with an uncapped Job Object. Any
    // failure here is fail-closed — terminate the suspended child and propagate.
    if let Err(err) = apply_resource_limits(containment, limits) {
        terminate_suspended_process(process.raw(), "apply_resource_limits failed");
        return Err(err);
    }
    resume_contained_process(process.raw(), thread.raw())?;

    Ok((
        WindowsSupervisedChild::Native {
            process,
            _thread: thread,
        },
        detached_stdio,
    ))
}

/// Returns `true` when `nono.exe` is running from a Cargo `target` directory
/// (dev build layout). Returns `false` for production install layouts such as
/// `Program Files\nono\` or `LocalAppData\Programs\nono\`.
///
/// Used to skip broker Authenticode self-trust-anchor verification in dev builds
/// (Phase 32 D-32-12 implementation note + Pitfall 6). Using an install-layout
/// substring detector instead of `#[cfg(debug_assertions)]` is critical:
/// `cargo test --release` compiles WITHOUT debug_assertions, so a
/// `#[cfg(debug_assertions)]` gate would falsely apply strict Authenticode checks
/// to release-mode test runs where `nono-shell-broker.exe` is unsigned.
///
/// Detection strings cover Windows-style backslashes AND Unix-style forward
/// slashes (the latter for macOS/Linux test suite runs).
fn is_dev_build_layout(nono_exe_path: &std::path::Path) -> bool {
    let s = nono_exe_path.to_string_lossy();
    s.contains(r"\target\debug\")
        || s.contains(r"\target\release\")
        || s.contains("/target/debug/")
        || s.contains("/target/release/")
}

/// Perform the Authenticode self-trust-anchor verification for broker.exe.
///
/// Extracts `nono.exe`'s own Authenticode signer subject + thumbprint via the
/// Phase 28 chain-walker, then requires `broker.exe`'s signature to match
/// (subject AND thumbprint). Fails-closed on any non-Valid status or mismatch
/// (Phase 32 D-32-12 / D-32-13). No caching — called on every dispatch
/// (D-32-14). No escape hatch: there is no env-var or CLI flag that bypasses
/// this check in production-layout builds.
///
/// The `tracing::debug!` event with `target: "broker_authenticode"` on success
/// is the dynamic sentinel for `each_dispatch_revalidates` (P32-CHK-009 —
/// structural grep for absence of any per-process cache).
pub(crate) fn verify_broker_authenticode(
    nono_exe: &std::path::Path,
    broker_path: &std::path::Path,
) -> nono::Result<()> {
    use crate::exec_identity::AuthenticodeStatus;
    use crate::exec_identity_windows::query_authenticode_status;

    let nono_status = query_authenticode_status(nono_exe)?;
    let broker_status = query_authenticode_status(broker_path)?;

    let (nono_subject, nono_thumbprint) = match nono_status {
        AuthenticodeStatus::Valid {
            signer_subject,
            thumbprint,
        } => (signer_subject, thumbprint),
        other => {
            return Err(nono::NonoError::TrustVerification {
                path: nono_exe.display().to_string(),
                reason: format!(
                    "nono.exe Authenticode status is {other:?} (expected Valid). \
                     Self-trust-anchor unavailable; refusing to spawn broker."
                ),
            })
        }
    };
    let (broker_subject, broker_thumbprint) = match broker_status {
        AuthenticodeStatus::Valid {
            signer_subject,
            thumbprint,
        } => (signer_subject, thumbprint),
        other => {
            return Err(nono::NonoError::TrustVerification {
                path: broker_path.display().to_string(),
                reason: format!(
                    "broker.exe Authenticode status is {other:?} (expected Valid). \
                     Refusing to spawn."
                ),
            })
        }
    };
    if nono_subject != broker_subject || nono_thumbprint != broker_thumbprint {
        return Err(nono::NonoError::TrustVerification {
            path: broker_path.display().to_string(),
            reason: format!(
                "broker.exe Authenticode signature does not match nono.exe — \
                 expected subject `{nono_subject}` thumbprint `{nono_thumbprint}`, \
                 got subject `{broker_subject}` thumbprint `{broker_thumbprint}`. \
                 Refusing to spawn."
            ),
        });
    }
    tracing::debug!(
        target: "broker_authenticode",
        "broker.exe Authenticode self-trust-anchor verified: subject={nono_subject} thumbprint={nono_thumbprint}"
    );
    Ok(())
}

/// Returns true when the current process is the inner detached supervisor launched by
/// `startup_runtime::run_detached_launch`. The outer `nono run --detached` invocation
/// re-execs itself with `NONO_DETACHED_LAUNCH=1` + `DETACHED_PROCESS`; the inner
/// supervisor then spawns the sandboxed grandchild via `spawn_windows_child`. Only the
/// inner path requires the null-token shape — outer invocations and non-detached runs
/// keep their WRITE_RESTRICTED + session-SID token.
pub(crate) fn is_windows_detached_launch() -> bool {
    std::env::var("NONO_DETACHED_LAUNCH")
        .map(|v| v == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod detached_token_gate_tests {
    use super::is_windows_detached_launch;
    use crate::test_env::{lock_env, EnvVarGuard};

    #[test]
    fn returns_false_when_env_unset() {
        let _lock = lock_env();
        // Ensure the env var is cleared for the duration of the assertion.
        let g = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "1")]);
        g.remove("NONO_DETACHED_LAUNCH");
        assert!(!is_windows_detached_launch());
    }

    #[test]
    fn returns_true_when_env_is_one() {
        let _lock = lock_env();
        let _g = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "1")]);
        assert!(is_windows_detached_launch());
    }

    #[test]
    fn returns_false_when_env_is_other_value() {
        let _lock = lock_env();
        let _g = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "0")]);
        assert!(!is_windows_detached_launch());
        let _g2 = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "true")]);
        assert!(!is_windows_detached_launch());
    }
}

#[cfg(test)]
mod broker_authenticode_layout_tests {
    use super::is_dev_build_layout;

    /// D-32-12 dev-skip mechanism unit acceptance.
    /// Verifies that the install-layout substring detector matches Cargo
    /// target directories (dev-build) and does NOT match production install
    /// paths (Program Files, AppData).
    #[test]
    fn is_dev_build_layout_detection() {
        // Dev-build paths (should match → true)
        assert!(
            is_dev_build_layout(std::path::Path::new(
                r"C:\Users\dev\nono\target\debug\nono.exe"
            )),
            "Windows debug target path should be detected as dev-build"
        );
        assert!(
            is_dev_build_layout(std::path::Path::new(
                r"C:\Users\dev\nono\target\release\nono.exe"
            )),
            "Windows release target path should be detected as dev-build"
        );
        assert!(
            is_dev_build_layout(std::path::Path::new("/home/dev/nono/target/debug/nono")),
            "Unix debug target path should be detected as dev-build"
        );
        assert!(
            is_dev_build_layout(std::path::Path::new("/home/dev/nono/target/release/nono")),
            "Unix release target path should be detected as dev-build"
        );
        // Production install paths (should NOT match → false)
        assert!(
            !is_dev_build_layout(std::path::Path::new(r"C:\Program Files\nono\nono.exe")),
            "Program Files install path must NOT be detected as dev-build"
        );
        assert!(
            !is_dev_build_layout(std::path::Path::new(
                r"C:\Users\op\AppData\Local\Programs\nono\nono.exe"
            )),
            "AppData local install path must NOT be detected as dev-build"
        );
        assert!(
            !is_dev_build_layout(std::path::Path::new("/usr/local/bin/nono")),
            "/usr/local/bin/nono must NOT be detected as dev-build"
        );
        assert!(
            !is_dev_build_layout(std::path::Path::new("/opt/nono/nono")),
            "/opt/nono/nono must NOT be detected as dev-build"
        );
    }
}

#[cfg(test)]
mod pty_token_gate_tests {
    use super::{select_windows_token_arm, WindowsTokenArm};

    /// Phase 31 D-15 / D-01 NEW path: PTY allocation triggers the broker spawn,
    /// even when session_sid is also Some (which it always is on Windows supervised).
    /// This test pins the branch-ordering rule documented in 31-CONTEXT D-01.
    /// Replaces Phase 30's pty-some-no-detach LowIlPrimary assertion (commit 9c226dcf)
    /// which asserted `LowIlPrimary` — that path triggered STATUS_DLL_INIT_FAILED
    /// (0xC0000142) on the supervised+ConPTY shape per Phase 30 30-WAVE-2-PROCMON.md.
    #[test]
    fn pty_some_no_detach_selects_broker_launch() {
        let arm = select_windows_token_arm(
            /* is_detached */ false, /* has_pty */ true,
            /* has_session_sid */ true, // always true on Windows supervised
            /* caps_demand_low_il */ false,
        );
        assert_eq!(arm, WindowsTokenArm::BrokerLaunch);
    }

    /// Phase 31 D-15: explicit guard that has_pty=true OVERRIDES has_session_sid=true
    /// AND caps_demand_low_il=true in the cascade, ensuring the BrokerLaunch arm
    /// fires for the PTY+supervised path rather than falling through to
    /// WriteRestricted or the LowIlPrimary fallback. Defense-in-depth for the
    /// rule that the PTY signal precedes both other supervised-path signals.
    #[test]
    fn broker_launch_takes_precedence_over_session_sid_on_pty_path() {
        let arm = select_windows_token_arm(
            /* is_detached */ false, /* has_pty */ true, /* has_session_sid */ true,
            /* caps_demand_low_il */
            true, // even if caps_demand_low_il, BrokerLaunch wins
        );
        assert_eq!(arm, WindowsTokenArm::BrokerLaunch);
    }

    /// Detached path short-circuits BEFORE the PTY arm. Phase 15 waiver:
    /// detached children get a null token regardless of PTY allocation.
    #[test]
    fn pty_some_with_detach_selects_null() {
        let arm = select_windows_token_arm(
            /* is_detached */ true, /* has_pty */ true, /* has_session_sid */ true,
            /* caps_demand_low_il */ false,
        );
        assert_eq!(arm, WindowsTokenArm::Null);
    }

    /// Existing non-PTY supervised path (`nono run` without --interactive).
    /// Wave 1 must NOT regress this — the new arm only fires when has_pty=true.
    #[test]
    fn pty_none_with_session_sid_selects_write_restricted() {
        let arm = select_windows_token_arm(
            /* is_detached */ false, /* has_pty */ false,
            /* has_session_sid */ true, /* caps_demand_low_il */ false,
        );
        assert_eq!(arm, WindowsTokenArm::WriteRestricted);
    }

    /// Final fallback. Structurally unreachable today on Windows (session_sid
    /// is always Some per execution_runtime.rs:334) but pinned for future
    /// readers and for non-Windows platforms where the helper compiles cleanly.
    #[test]
    fn pty_none_no_session_sid_selects_null_fallback() {
        let arm = select_windows_token_arm(
            /* is_detached */ false, /* has_pty */ false,
            /* has_session_sid */ false, /* caps_demand_low_il */ false,
        );
        assert_eq!(arm, WindowsTokenArm::Null);
    }

    /// Legacy Direct path (caps demand Low-IL, no session SID). Structurally
    /// unreachable today (session_sid always Some) but kept testable so a
    /// future refactor that loosens session_sid wiring doesn't silently
    /// land in the wrong arm.
    #[test]
    fn pty_none_caps_demand_low_il_selects_low_il() {
        let arm = select_windows_token_arm(
            /* is_detached */ false, /* has_pty */ false,
            /* has_session_sid */ false, /* caps_demand_low_il */ true,
        );
        assert_eq!(arm, WindowsTokenArm::LowIlPrimary);
    }

    /// Detached + session_sid + caps_demand_low_il → Null still wins.
    /// Pins detached-arm priority across all input combinations.
    #[test]
    fn detach_dominates_other_signals() {
        let arm = select_windows_token_arm(
            /* is_detached */ true, /* has_pty */ false, /* has_session_sid */ true,
            /* caps_demand_low_il */ true,
        );
        assert_eq!(arm, WindowsTokenArm::Null);
    }
}

#[cfg(all(test, target_os = "windows"))]
mod low_integrity_primary_token_tests {
    // Phase 31 D-06: function lifted to the `nono` crate; the test exercises
    // the re-exported symbol so the LowIlPrimary arm's behavior is still pinned
    // here for nono-cli regression coverage.
    use nono::create_low_integrity_primary_token;
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
        TOKEN_MANDATORY_LABEL,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_LOW_RID;

    /// Phase 30 D-01: Wave 1 is the FIRST live runtime use of
    /// `create_low_integrity_primary_token`. The legacy Direct path callsite at
    /// launch.rs (~1150 post-edit) (`should_use_low_integrity_windows_launch` arm) is
    /// structurally unreachable today because `config.session_sid` is
    /// unconditionally `Some(...)` for Windows supervised launches
    /// (`execution_runtime.rs:334`). This test ensures the function actually
    /// produces a Low-IL token, NOT silently a Medium-IL one. Acceptance #3
    /// (write-deny) depends on this — RESEARCH Assumption A2.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn low_integrity_primary_token_sets_low_il() {
        let token = create_low_integrity_primary_token().expect(
            "create_low_integrity_primary_token must succeed in a normal user-logon test process",
        );
        assert!(
            !token.0.is_null(),
            "low-integrity primary token handle is non-null"
        );

        // Two-call GetTokenInformation pattern: first probe with null buffer
        // to discover the required size, then fetch into an allocated buffer.
        let mut needed: u32 = 0;
        unsafe {
            // SAFETY: First call with null buffer is the documented size-probe
            // pattern. ERROR_INSUFFICIENT_BUFFER is expected and unchecked here;
            // the buffer-size out-param `needed` is what we read.
            GetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        assert!(
            needed >= std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
            "TokenIntegrityLevel buffer size should be at least \
             size_of::<TOKEN_MANDATORY_LABEL>(); got {needed}"
        );

        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            // SAFETY: `buf` is sized by the probe call above and the allocation
            // is non-null. `token.0` is a valid token handle owned by `token`.
            GetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                buf.as_mut_ptr() as *mut _,
                needed,
                &mut needed,
            )
        };
        assert!(
            ok != 0,
            "GetTokenInformation(TokenIntegrityLevel) must succeed on a duplicated token"
        );

        // SAFETY: `buf` was populated by GetTokenInformation with a
        // TOKEN_MANDATORY_LABEL prefix; layout is documented in the Win32 SDK.
        let label = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
        // SAFETY: `label.Label.Sid` is a valid SID pointer for the duration of
        // `buf`'s lifetime; `GetSidSubAuthorityCount` returns a pointer to a
        // u8 within that SID structure.
        let sub_authority_count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
        assert!(
            sub_authority_count > 0,
            "integrity-label SID must have at least one sub-authority; got {sub_authority_count}"
        );
        // SAFETY: same SID pointer is still valid; `(count - 1)` is in-range.
        let last_sub_authority =
            unsafe { *GetSidSubAuthority(label.Label.Sid, (sub_authority_count - 1) as u32) };
        assert_eq!(
            last_sub_authority, SECURITY_MANDATORY_LOW_RID as u32,
            "duplicated token must be at Low integrity (RID 0x1000); got 0x{last_sub_authority:x}"
        );
    }

    /// Smoke-test for `OwnedHandle` Drop discipline. Explicit drop after
    /// a successful construction must not panic or trigger an FFI failure.
    /// This pins Pitfall 1 (UAF) and Pitfall 5 (double-close) at the unit-test
    /// boundary.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn low_integrity_primary_token_drop_is_safe() {
        let token = create_low_integrity_primary_token()
            .expect("create_low_integrity_primary_token must succeed");
        assert!(!token.0.is_null());
        // Explicit drop closes the handle exactly once. If `OwnedHandle::Drop`
        // were ill-formed, this would panic, abort, or surface in a later
        // test as ERROR_INVALID_HANDLE on a recycled handle value.
        drop(token);
    }
}

#[cfg(all(test, target_os = "windows"))]
mod apply_resource_limits_tests {
    use super::*;
    use crate::launch_runtime::ResourceLimits;

    fn read_extended(job: HANDLE) -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut returned: u32 = 0;
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of_mut!(info) as *mut _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut returned,
            )
        };
        assert_ne!(
            ok, 0,
            "QueryInformationJobObject(ExtendedLimitInformation) must succeed"
        );
        info
    }

    fn read_cpu(job: HANDLE) -> JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        let mut returned: u32 = 0;
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectCpuRateControlInformation,
                std::ptr::addr_of_mut!(info) as *mut _,
                size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                &mut returned,
            )
        };
        assert_ne!(
            ok, 0,
            "QueryInformationJobObject(CpuRateControl) must succeed"
        );
        info
    }

    #[test]
    fn cpu_rate_control_readback_matches_applied_value() {
        let containment = create_process_containment(None).expect("create containment");
        let limits = ResourceLimits {
            cpu_percent: Some(25),
            ..ResourceLimits::default()
        };
        apply_resource_limits(&containment, &limits).expect("apply cpu limit");

        let info = read_cpu(containment.job);
        assert_eq!(unsafe { info.Anonymous.CpuRate }, 25 * 100);
        assert!(info.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE != 0);
        assert!(info.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP != 0);
    }

    #[test]
    fn memory_readback_matches_applied_value() {
        let containment = create_process_containment(None).expect("create containment");
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::default()
        };
        apply_resource_limits(&containment, &limits).expect("apply memory limit");

        let info = read_extended(containment.job);
        assert_eq!(info.JobMemoryLimit, 512 * 1024 * 1024);
        assert!(info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0);
    }

    #[test]
    fn max_processes_readback_matches_applied_value() {
        let containment = create_process_containment(None).expect("create containment");
        let limits = ResourceLimits {
            max_processes: Some(10),
            ..ResourceLimits::default()
        };
        apply_resource_limits(&containment, &limits).expect("apply max-processes limit");

        let info = read_extended(containment.job);
        assert_eq!(info.BasicLimitInformation.ActiveProcessLimit, 10);
        assert!(info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0);
    }

    #[test]
    fn all_three_limits_coexist() {
        let containment = create_process_containment(None).expect("create containment");
        let limits = ResourceLimits {
            cpu_percent: Some(50),
            memory_bytes: Some(256 * 1024 * 1024),
            max_processes: Some(20),
            timeout: None,
        };
        apply_resource_limits(&containment, &limits).expect("apply all three limits");

        let ext = read_extended(containment.job);
        assert_eq!(ext.JobMemoryLimit, 256 * 1024 * 1024);
        assert_eq!(ext.BasicLimitInformation.ActiveProcessLimit, 20);
        assert!(ext.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0);
        assert!(ext.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0);

        let cpu = read_cpu(containment.job);
        assert_eq!(unsafe { cpu.Anonymous.CpuRate }, 50 * 100);
        assert!(cpu.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE != 0);
        assert!(cpu.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP != 0);
    }

    #[test]
    fn empty_limits_is_noop() {
        let containment = create_process_containment(None).expect("create containment");
        apply_resource_limits(&containment, &ResourceLimits::default())
            .expect("empty limits is a no-op and must succeed");
        // Readback should show the defaults from create_process_containment (no memory/process caps),
        // i.e. JobMemoryLimit == 0 and ActiveProcessLimit == 0.
        let info = read_extended(containment.job);
        assert_eq!(info.JobMemoryLimit, 0);
        assert_eq!(info.BasicLimitInformation.ActiveProcessLimit, 0);
    }

    /// Regression guard: `apply_resource_limits` must preserve the flags set by
    /// `create_process_containment` (KILL_ON_JOB_CLOSE + DIE_ON_UNHANDLED_EXCEPTION).
    /// The implementation read-modifies-writes the ExtendedLimitInformation struct;
    /// a naive write-only would clear these.
    #[test]
    fn preserves_kill_on_job_close() {
        let containment = create_process_containment(None).expect("create containment");
        let limits = ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
            max_processes: Some(8),
            ..ResourceLimits::default()
        };
        apply_resource_limits(&containment, &limits).expect("apply");

        let info = read_extended(containment.job);
        assert!(
            info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
            "KILL_ON_JOB_CLOSE must be preserved after apply_resource_limits"
        );
        assert!(
            info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                != 0,
            "DIE_ON_UNHANDLED_EXCEPTION must be preserved after apply_resource_limits"
        );
    }

    #[test]
    fn idempotent_same_limits_twice() {
        let containment = create_process_containment(None).expect("create containment");
        let limits = ResourceLimits {
            cpu_percent: Some(30),
            memory_bytes: Some(128 * 1024 * 1024),
            ..ResourceLimits::default()
        };
        apply_resource_limits(&containment, &limits).expect("first apply");
        apply_resource_limits(&containment, &limits).expect("second apply must also succeed");
    }
}

#[cfg(all(test, target_os = "windows"))]
#[allow(clippy::unwrap_used)]
mod detached_stdio_tests {
    use super::DetachedStdioPipes;
    use windows_sys::Win32::Foundation::{
        GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };

    fn handle_inherit_flag(handle: HANDLE) -> u32 {
        let mut flags: u32 = 0;
        let ok = unsafe { GetHandleInformation(handle, &mut flags) };
        assert_ne!(ok, 0, "GetHandleInformation failed for handle {:?}", handle);
        flags & HANDLE_FLAG_INHERIT
    }

    #[test]
    fn detached_stdio_pipes_create_succeeds() {
        let pipes = DetachedStdioPipes::create().expect("create DetachedStdioPipes");
        for (label, h) in [
            ("stdin_read", pipes.stdin_read),
            ("stdin_write", pipes.stdin_write),
            ("stdout_read", pipes.stdout_read),
            ("stdout_write", pipes.stdout_write),
            ("stderr_read", pipes.stderr_read),
            ("stderr_write", pipes.stderr_write),
        ] {
            assert_ne!(h, INVALID_HANDLE_VALUE, "{label} should not be INVALID");
            assert!(!h.is_null(), "{label} should not be null");
        }
    }

    #[test]
    fn parent_ends_are_non_inheritable() {
        let pipes = DetachedStdioPipes::create().expect("create DetachedStdioPipes");
        assert_eq!(
            handle_inherit_flag(pipes.stdin_write),
            0,
            "parent stdin_write must NOT be inheritable"
        );
        assert_eq!(
            handle_inherit_flag(pipes.stdout_read),
            0,
            "parent stdout_read must NOT be inheritable"
        );
        assert_eq!(
            handle_inherit_flag(pipes.stderr_read),
            0,
            "parent stderr_read must NOT be inheritable"
        );
    }

    #[test]
    fn child_ends_are_inheritable() {
        let pipes = DetachedStdioPipes::create().expect("create DetachedStdioPipes");
        assert_ne!(
            handle_inherit_flag(pipes.stdin_read),
            0,
            "child stdin_read MUST be inheritable"
        );
        assert_ne!(
            handle_inherit_flag(pipes.stdout_write),
            0,
            "child stdout_write MUST be inheritable"
        );
        assert_ne!(
            handle_inherit_flag(pipes.stderr_write),
            0,
            "child stderr_write MUST be inheritable"
        );
    }

    #[test]
    fn close_child_ends_zeroes_them() {
        let mut pipes = DetachedStdioPipes::create().expect("create DetachedStdioPipes");
        unsafe { pipes.close_child_ends() };
        assert_eq!(pipes.stdin_read, INVALID_HANDLE_VALUE);
        assert_eq!(pipes.stdout_write, INVALID_HANDLE_VALUE);
        assert_eq!(pipes.stderr_write, INVALID_HANDLE_VALUE);
        // Idempotent — second call must not panic / double-close.
        unsafe { pipes.close_child_ends() };
        assert_eq!(pipes.stdin_read, INVALID_HANDLE_VALUE);
    }

    #[test]
    fn drop_closes_all_remaining_handles_without_panic() {
        // Construct + immediate drop must not panic and must not propagate any
        // CloseHandle errors. Drop always runs at scope exit.
        {
            let _pipes = DetachedStdioPipes::create().expect("create DetachedStdioPipes");
        }
        // Repeat to ensure no global state was corrupted.
        {
            let mut pipes2 =
                DetachedStdioPipes::create().expect("create second DetachedStdioPipes");
            unsafe { pipes2.close_child_ends() };
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
#[allow(clippy::unwrap_used)]
mod broker_dispatch_tests {
    // `IsProcessInJob` is the runtime acceptance for Plan 31-03 D-04: the
    // broker process — and by Win32-cascade its spawned child — is contained
    // by the Job Object created by `nono.exe`. Plan 31-05 lifts the
    // `#[ignore]` and exercises the assertion against the production
    // `nono-shell-broker.exe` artifact built by Plan 31-04's release pipeline.
    use nono::NonoError;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, BOOL, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, ResumeThread, TerminateProcess, CREATE_SUSPENDED, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    /// Phase 31 D-07: `NonoError::BrokerNotFound { path }` is the structured
    /// error variant returned when the sibling broker binary is absent. This
    /// test pins the variant's wire shape (display-formats the path payload,
    /// includes the literal "Broker binary not found" prefix) so future
    /// readers can rely on the exact error text in operator-facing diagnostics.
    ///
    /// The full end-to-end "dispatch fails fast when sibling broker.exe is
    /// missing" path is exercised by Plan 31-05 field-test against a real
    /// `nono shell` invocation; this unit test is the always-on guarantor
    /// that the variant is wired into the error chain and Plan 31-01's
    /// contract is satisfied for use by the cascade.
    #[test]
    fn broker_not_found_error_variant_is_constructible_and_displays_path() {
        let err = NonoError::BrokerNotFound {
            path: PathBuf::from(r"C:\does\not\exist\nono-shell-broker.exe"),
        };
        let s = err.to_string();
        assert!(
            s.contains("nono-shell-broker.exe"),
            "BrokerNotFound display should include the sibling filename; got: {s}"
        );
        assert!(
            s.contains("Broker binary not found"),
            "BrokerNotFound display should carry the canonical prefix; got: {s}"
        );
    }

    /// Phase 31 D-04 acceptance: the broker process — and via Win32 cascade
    /// its spawned shell child — is in the Job Object created by the supervisor.
    ///
    /// **Test shape (Plan 31-05 lift):** spawn the production
    /// `nono-shell-broker.exe` via `CreateProcessW` (Medium IL = caller's
    /// identity, mirroring the production `BrokerLaunch` dispatch in
    /// `spawn_windows_child`) with `CREATE_SUSPENDED` so we can call
    /// `AssignProcessToJobObject(job, broker.hProcess)` BEFORE the broker
    /// executes a single instruction (D-04 ordering). Then call
    /// `IsProcessInJob(broker.hProcess, job, &mut in_job)` and assert
    /// `in_job != 0`. The broker's spawned child inherits Job membership
    /// automatically because `JOB_OBJECT_LIMIT_*BREAKAWAY*` flags are unset
    /// per the Phase 16 RESL invariant in `create_process_containment` — the
    /// production dispatch verifies this same cascade in the field via Plan
    /// 31-05's Acceptance #1.
    ///
    /// **Synthetic vs. production scope:** this test exercises the Win32 Job
    /// Object containment call sequence against the production broker
    /// artifact. The full BrokerLaunch dispatch wiring (HANDLE_LIST + ConPTY
    /// pipe inheritance + sibling broker resolution + capability-pipe
    /// preservation) is exercised end-to-end by Plan 31-05's field-smoke
    /// Acceptance #1 (`.\nono.exe shell --profile claude-code --allow-cwd`)
    /// — that's the operator-attested acceptance gate per CONTEXT D-14.
    ///
    /// **Pre-condition:** `cargo build -p nono-shell-broker --release
    /// --target x86_64-pc-windows-msvc` (or the host default target) before
    /// running this test. If the broker artifact is absent the test prints a
    /// SKIP diagnostic and returns cleanly so the default `cargo test
    /// -p nono-cli` stays green for developers who haven't built the broker
    /// yet. The Plan 31-05 field-test runner has Plan 31-04's release
    /// pipeline guarantee that the artifact is present.
    #[test]
    fn broker_launch_assigns_child_to_job_object() {
        // Resolve the broker artifact relative to the workspace root. The
        // test binary lives at e.g.
        // `target/x86_64-pc-windows-msvc/debug/deps/<crate-hash>.exe`; the
        // broker is at `target/<triple>/release/nono-shell-broker.exe` per
        // Plan 31-04. CARGO_MANIFEST_DIR for `nono-cli` is
        // `crates/nono-cli`; workspace root is two levels up.
        let manifest =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
        let workspace_root = PathBuf::from(&manifest).join("..").join("..");
        // Try the cross-compile triple first (matches Plan 31-05 build
        // instructions); fall back to the host default target dir for
        // developer convenience.
        let candidate_triple = workspace_root
            .join("target")
            .join("x86_64-pc-windows-msvc")
            .join("release")
            .join("nono-shell-broker.exe");
        let candidate_default = workspace_root
            .join("target")
            .join("release")
            .join("nono-shell-broker.exe");
        let broker_path = if candidate_triple.exists() {
            candidate_triple
        } else if candidate_default.exists() {
            candidate_default
        } else {
            panic!(
                "nono-shell-broker.exe missing at {} and {}; pre-build with \
                 `cargo build -p nono-shell-broker --release` (or set the broker pre-build \
                 via crates/nono-cli/build.rs per Phase 41 D-14). This test asserts \
                 Job Object containment is enforced before ResumeThread and cannot be \
                 silently skipped — see Phase 41 CR-04 disposition.",
                candidate_triple.display(),
                candidate_default.display()
            );
        };

        // Create a fresh Job Object (no resource limits — pure containment
        // assertion). `JOB_OBJECT_LIMIT_*BREAKAWAY*` flags are NOT set, so a
        // process assigned here cannot escape via CreateProcess(BREAKAWAY)
        // and any child it spawns inherits Job membership.
        let job: HANDLE = unsafe {
            // SAFETY: CreateJobObjectW with null name + null security
            // attributes is documented to succeed unless out-of-memory.
            // Returns a valid HANDLE on success or null on failure.
            CreateJobObjectW(std::ptr::null(), std::ptr::null())
        };
        assert!(!job.is_null(), "CreateJobObjectW returned null handle");

        // Build a noop broker invocation. The broker's argv parser
        // (`crates/nono-shell-broker/src/main.rs::parse_args`) requires
        // `--shell <path> --cwd <path>` at minimum; `--shell-arg` is
        // optional and repeatable. `exit 0` makes the broker's spawned
        // PowerShell child exit immediately so the test does not hang.
        // Even if the broker hits an early failure path (e.g., its
        // Low-IL token construction fails on this CI runner), the Job
        // Object assertion is still valid — the broker is in the Job
        // BEFORE ResumeThread fires.
        let cwd = std::env::current_dir()
            .expect("current_dir")
            .to_string_lossy()
            .into_owned();
        let cmd = format!(
            "\"{broker}\" --shell C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe \
             --shell-arg -NoProfile --shell-arg -Command --shell-arg \"exit 0\" --cwd \"{cwd}\"",
            broker = broker_path.display(),
            cwd = cwd,
        );
        let mut cmd_buf: Vec<u16> = std::ffi::OsStr::new(&cmd)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let mut si: STARTUPINFOW = unsafe {
            // SAFETY: STARTUPINFOW is a plain Win32 struct safe to
            // zero-initialize; cb is set immediately below.
            std::mem::zeroed()
        };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe {
            // SAFETY: PROCESS_INFORMATION is a plain Win32 struct safe to
            // zero-initialize; populated by CreateProcessW on success.
            std::mem::zeroed()
        };

        let created = unsafe {
            // SAFETY: cmd_buf is null-terminated UTF-16 (chained 0 above);
            // si and pi are valid mutable references; null lpApplicationName
            // means the executable is parsed from the first whitespace-
            // delimited token of cmd_buf (which we double-quote). Suspended
            // creation is required so we can assign to the Job Object before
            // any code runs.
            CreateProcessW(
                std::ptr::null(),
                cmd_buf.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_SUSPENDED,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        if created == 0 {
            let err = unsafe {
                // SAFETY: GetLastError is a thread-local lookup with no
                // safety preconditions.
                GetLastError()
            };
            unsafe {
                // SAFETY: `job` is a valid HANDLE we just created; CloseHandle
                // releases the OS resource. We must clean up before panicking.
                CloseHandle(job);
            }
            panic!("CreateProcessW(broker) failed; GetLastError={err}; cmd was: {cmd}");
        }

        // D-04: assign to Job Object BEFORE ResumeThread so the broker is
        // contained from instruction zero.
        let assigned = unsafe {
            // SAFETY: `job` and `pi.hProcess` are both valid HANDLEs we own
            // for the duration of this call. AssignProcessToJobObject does
            // not consume either handle.
            AssignProcessToJobObject(job, pi.hProcess)
        };
        assert!(
            assigned != 0,
            "AssignProcessToJobObject failed; GetLastError={}",
            unsafe {
                // SAFETY: GetLastError is a thread-local lookup.
                GetLastError()
            }
        );

        // The acceptance assertion: the broker process is in the Job Object.
        let mut in_job: BOOL = 0;
        let probed = unsafe {
            // SAFETY: `pi.hProcess` and `job` are valid; `&mut in_job` is a
            // valid out-pointer to a stack-local BOOL.
            IsProcessInJob(pi.hProcess, job, &mut in_job)
        };
        assert!(
            probed != 0,
            "IsProcessInJob FFI call failed; GetLastError={}",
            unsafe {
                // SAFETY: GetLastError is a thread-local lookup.
                GetLastError()
            }
        );
        assert!(
            in_job != 0,
            "broker process must be in the Job Object after AssignProcessToJobObject (D-04)"
        );

        // Resume; broker exits quickly via `exit 0` in the PowerShell child.
        // We do NOT wait for the broker to exit — the assertion above is
        // sufficient. The broker may print a transient error to stderr if
        // its Low-IL token construction fails on this runner; that's
        // acceptable — the Job Object containment is the only invariant
        // this test pins.
        unsafe {
            // SAFETY: `pi.hThread` is a valid suspended thread handle. The
            // u32 return is the previous suspend count which we ignore.
            let _ = ResumeThread(pi.hThread);
        }

        // Cleanup: terminate broker (defensive — child may already have exited)
        // and close all four handles. `TerminateProcess` is safe to call on
        // an already-exited process; it's a no-op error in that case.
        unsafe {
            // SAFETY: All HANDLEs are valid for the duration of these calls.
            // CloseHandle on the Job Object releases the kernel object;
            // because the broker (and its child) are still members, they may
            // be terminated by the Job's KILL_ON_JOB_CLOSE policy if set —
            // but we did NOT set that policy on this synthetic Job, so the
            // processes remain runnable. The explicit TerminateProcess
            // ensures the broker doesn't outlive this test.
            let _ = TerminateProcess(pi.hProcess, 0);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(job);
        }
    }

    // ------------------------------------------------------------------
    // Phase 31 Plan 31-03 — Nyquist gap-fill: pin `build_broker_command_line`'s
    // quoting + UTF-16 encoding behavior. The end-to-end shape is exercised by
    // Plan 31-05's field-test; these tests guard against regressions at the
    // unit-test layer.
    //
    // `quote_windows_arg` only quotes args containing whitespace, tabs, or
    // quotes (and quotes empty strings). Non-whitespace paths pass through
    // unquoted — the broker path with spaces (`C:\Program Files\...`) IS
    // quoted, but the system32 powershell path is not.
    // ------------------------------------------------------------------

    /// Decode the trailing-null UTF-16 buffer back to a `String` for
    /// human-readable assertions. Drops the trailing 0 terminator.
    fn decode_wide(wide: &[u16]) -> String {
        assert!(
            !wide.is_empty(),
            "command line must have at least the null terminator"
        );
        String::from_utf16_lossy(&wide[..wide.len() - 1])
    }

    /// D-08: a broker path containing whitespace (typical Windows install
    /// location `C:\Program Files\...`) MUST be enclosed in literal
    /// double-quotes so `CreateProcessW` parses the executable token
    /// correctly. Without quoting, the path would be split at the first
    /// space, picking up the wrong executable.
    #[test]
    fn build_broker_command_line_emits_quoted_broker_path() {
        let broker = std::path::Path::new(r"C:\Program Files\nono\nono-shell-broker.exe");
        let wide = super::build_broker_command_line(broker, &[]);
        let s = decode_wide(&wide);
        assert!(
            s.starts_with("\"C:\\Program Files\\nono\\nono-shell-broker.exe\""),
            "whitespace-bearing broker path must be enclosed in literal quotes; got: {s}"
        );
    }

    /// D-08: argv values are appended in order, each independently quoted
    /// per `quote_windows_arg` rules. A `--cwd` value containing whitespace
    /// (e.g. `C:\Users\u name`) MUST be quoted; a `--shell` value without
    /// whitespace (e.g. `C:\Windows\System32\powershell.exe`) is appended
    /// raw. This pins both branches of the quoting policy in one assertion.
    #[test]
    fn build_broker_command_line_appends_argv_args_with_quoting() {
        let broker = std::path::Path::new(r"C:\Program Files\nono\nono-shell-broker.exe");
        let argv = vec![
            std::ffi::OsString::from("--shell"),
            std::ffi::OsString::from(r"C:\Windows\System32\powershell.exe"),
            std::ffi::OsString::from("--cwd"),
            std::ffi::OsString::from(r"C:\Users\u name"),
        ];
        let wide = super::build_broker_command_line(broker, &argv);
        let s = decode_wide(&wide);

        // The flag tokens themselves contain no whitespace — appended raw.
        assert!(
            s.contains(" --shell "),
            "--shell flag must be appended unquoted; got: {s}"
        );
        assert!(
            s.contains(" --cwd "),
            "--cwd flag must be appended unquoted; got: {s}"
        );
        // Whitespace-free shell path passes through unquoted per
        // `quote_windows_arg`'s policy.
        assert!(
            s.contains(r"C:\Windows\System32\powershell.exe"),
            "whitespace-free shell path must appear in command line; got: {s}"
        );
        assert!(
            !s.contains("\"C:\\Windows\\System32\\powershell.exe\""),
            "whitespace-free path MUST NOT be quoted by quote_windows_arg; got: {s}"
        );
        // Whitespace-bearing cwd MUST be quoted.
        assert!(
            s.contains("\"C:\\Users\\u name\""),
            "whitespace-bearing cwd value must be quoted; got: {s}"
        );
    }

    /// Win32 CommandLine MUST be null-terminated UTF-16. Without the
    /// trailing null, `CreateProcessW` reads past the buffer end.
    #[test]
    fn build_broker_command_line_terminates_with_null() {
        let broker = std::path::Path::new(r"C:\nono\nono-shell-broker.exe");
        let wide = super::build_broker_command_line(broker, &[]);
        assert_eq!(
            wide.last(),
            Some(&0),
            "command line buffer must be null-terminated UTF-16"
        );
    }
}

/// Plan 35-01 (REQ-PORT-CLOSURE-01 / P34-DEFER-08a-1): Windows-gated regression
/// tests locking the empty-allow fail-closed invariant + deny/allow precedence +
/// nono-injected-credential bypass. All four tests mirror the Unix env-filter
/// behavior specified in exec_strategy.rs:435-457 (D-20 replay of upstream
/// 1b412a7 + 3657c935 + 780965d7).
///
/// Per CLAUDE.md "Environment variables in tests": each test that seeds a fixture
/// env var uses the project-wide `EnvVarGuard` RAII struct (crate::test_env) which
/// saves and restores the prior value on Drop, and acquires `ENV_LOCK` to prevent
/// data races between parallel test threads. Tests are parallel-safe.
#[cfg(all(test, target_os = "windows"))]
#[allow(clippy::unwrap_used)]
mod env_filter_tests {
    use super::{build_child_env, ExecConfig};
    use crate::test_env::{lock_env, EnvVarGuard};
    use nono::CapabilitySet;
    use std::path::Path;

    /// Construct a minimal `ExecConfig` for env-filter unit testing.
    /// Fields not relevant to `build_child_env`'s env-filter logic are
    /// set to safe sentinel values (empty command, stub resolved_program,
    /// empty CapabilitySet, no cap_file, no session state).
    fn make_minimal_exec_config<'a>(
        command: &'a [String],
        resolved_program: &'a Path,
        caps: &'a CapabilitySet,
        current_dir: &'a Path,
        allowed_env_vars: Option<Vec<String>>,
        denied_env_vars: Option<Vec<String>>,
        env_vars: Vec<(&'a str, &'a str)>,
    ) -> ExecConfig<'a> {
        ExecConfig {
            command,
            resolved_program,
            caps,
            env_vars,
            cap_file: None,
            current_dir,
            session_sid: None,
            interactive_shell: false,
            session_token: None,
            cap_pipe_rendezvous_path: None,
            allowed_env_vars,
            denied_env_vars,
        }
    }

    /// Plan 35-01 T-35-01-01 mitigation: empty allow-list MUST fail closed —
    /// all inherited user env vars are stripped (the only vars that survive are
    /// the Windows runtime block from `append_windows_runtime_env` and
    /// nono-injected credentials, both of which bypass the filter by construction).
    ///
    /// Locks upstream 780965d7's fail-closed invariant on the Windows execution
    /// path (REQ-PORT-CLOSURE-01 Acceptance Criterion 3).
    #[test]
    fn test_windows_empty_allow_denies_all_env_vars() {
        let _lock = lock_env();
        let _guard =
            EnvVarGuard::set_all(&[("NONO_TEST_EMPTY_ALLOW_FIXTURE", "should_be_stripped")]);

        let command: Vec<String> = vec![];
        let resolved_program = Path::new(r"C:\tools\agent.exe");
        let caps = CapabilitySet::new();
        let current_dir = Path::new(r"C:\workspace");
        let config = make_minimal_exec_config(
            &command,
            resolved_program,
            &caps,
            current_dir,
            /* allowed */ Some(vec![]),
            /* denied */ None,
            /* env_vars */ vec![],
        );

        let env_pairs = build_child_env(&config);

        // The runtime allowlist (PATH, SystemRoot, etc.) and
        // append_windows_runtime_env both bypass the new allow/deny filter,
        // but the fixture key (which is NOT in the runtime allowlist) MUST NOT
        // appear when the allow-list is empty.
        assert!(
            !env_pairs
                .iter()
                .any(|(k, _)| k == "NONO_TEST_EMPTY_ALLOW_FIXTURE"),
            "Empty allow-list MUST strip non-runtime inherited env vars \
             (fail-closed invariant from upstream 780965d7)"
        );
    }

    /// Plan 35-01 T-35-01-02 mitigation (deny wins): a key matching the deny-list
    /// MUST be stripped from the child environment regardless of allow-list state.
    /// Locks the deny-before-allow precedence mirrored from exec_strategy.rs:443-456.
    #[test]
    fn test_windows_deny_strips_matching_env_vars() {
        let _lock = lock_env();
        let _guard = EnvVarGuard::set_all(&[("NONO_TEST_DENY_FIXTURE_A", "should_be_stripped")]);

        let command: Vec<String> = vec![];
        let resolved_program = Path::new(r"C:\tools\agent.exe");
        let caps = CapabilitySet::new();
        let current_dir = Path::new(r"C:\workspace");
        let config = make_minimal_exec_config(
            &command,
            resolved_program,
            &caps,
            current_dir,
            /* allowed */ None,
            /* denied */ Some(vec!["NONO_TEST_DENY_FIXTURE_*".to_string()]),
            /* env_vars */ vec![],
        );

        let env_pairs = build_child_env(&config);

        assert!(
            !env_pairs
                .iter()
                .any(|(k, _)| k == "NONO_TEST_DENY_FIXTURE_A"),
            "deny_vars pattern 'NONO_TEST_DENY_FIXTURE_*' must strip \
             NONO_TEST_DENY_FIXTURE_A from the child env"
        );
    }

    /// Plan 35-01 (REQ-PORT-CLOSURE-01 Acceptance Criterion 2): allow-list with
    /// specific keys MUST pass through the matching key and strip unmatched keys.
    #[test]
    fn test_windows_allow_passes_only_matching_env_vars() {
        let _lock = lock_env();
        let _guard = EnvVarGuard::set_all(&[
            ("NONO_TEST_ALLOW_FIXTURE_KEEP", "passes"),
            ("NONO_TEST_ALLOW_FIXTURE_DROP", "stripped"),
        ]);

        let command: Vec<String> = vec![];
        let resolved_program = Path::new(r"C:\tools\agent.exe");
        let caps = CapabilitySet::new();
        let current_dir = Path::new(r"C:\workspace");
        let config = make_minimal_exec_config(
            &command,
            resolved_program,
            &caps,
            current_dir,
            /* allowed */ Some(vec!["NONO_TEST_ALLOW_FIXTURE_KEEP".to_string()]),
            /* denied */ None,
            /* env_vars */ vec![],
        );

        let env_pairs = build_child_env(&config);

        assert!(
            env_pairs
                .iter()
                .any(|(k, v)| k == "NONO_TEST_ALLOW_FIXTURE_KEEP" && v == "passes"),
            "NONO_TEST_ALLOW_FIXTURE_KEEP must pass through the allow-list filter"
        );
        assert!(
            !env_pairs
                .iter()
                .any(|(k, _)| k == "NONO_TEST_ALLOW_FIXTURE_DROP"),
            "NONO_TEST_ALLOW_FIXTURE_DROP must be stripped when not in allow-list"
        );
    }

    /// Plan 35-01 T-35-01-04 mitigation: nono-injected credentials (config.env_vars)
    /// MUST bypass BOTH the deny-list and the allow-list. The credentials are
    /// appended unconditionally after the filter loop (launch.rs:672-674).
    ///
    /// This locks the documented invariant from exec_strategy.rs:465-467 on the
    /// Windows execution path. Operators relying on --env-deny to strip
    /// nono-injected secrets would be misled; by design, injected creds are
    /// always forwarded to the sandboxed child.
    #[test]
    fn test_windows_nono_injected_credentials_bypass_both() {
        let command: Vec<String> = vec![];
        let resolved_program = Path::new(r"C:\tools\agent.exe");
        let caps = CapabilitySet::new();
        let current_dir = Path::new(r"C:\workspace");
        let config = make_minimal_exec_config(
            &command,
            resolved_program,
            &caps,
            current_dir,
            /* allowed */ Some(vec![]),
            /* denied */ Some(vec!["NONO_INJECTED_CRED".to_string()]),
            /* env_vars */ vec![("NONO_INJECTED_CRED", "secret")],
        );

        let env_pairs = build_child_env(&config);

        assert!(
            env_pairs
                .iter()
                .any(|(k, v)| k == "NONO_INJECTED_CRED" && v == "secret"),
            "Nono-injected credentials MUST bypass both allow-list and deny-list \
             filters (config.env_vars appended unconditionally per design)"
        );
    }
}
