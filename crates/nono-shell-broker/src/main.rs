//! `nono-shell-broker` — Phase 31 D-05 broker binary.
//!
//! Medium-IL intermediary spawned by `nono.exe` for the `nono shell` command on
//! Windows. The broker:
//!
//! 1. Inherits a console attachment from `nono.exe` at Medium IL (KernelBase
//!    skips CSRSS attach for already-inherited consoles — RESEARCH A1, validated
//!    by the 2026-05-08 PoC at `.planning/quick/260508-m99-.../`).
//! 2. Constructs a Low-IL primary token via `nono::create_low_integrity_primary_token`
//!    (D-06: single source of truth shared with `nono-cli`).
//! 3. Spawns the actual sandboxed shell child via `CreateProcessAsUserW` with
//!    `dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT` only (D-01: NO new
//!    console flag, NO pseudoconsole proc-thread attribute — child inherits
//!    broker's console without re-triggering CSRSS attach at Low IL).
//! 4. Restricts inherited handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to
//!    only those passed by `nono.exe` via `--inherit-handle <hex>` (D-02:
//!    capability-pipe and other supervisor handles are NEVER inheritable past
//!    `nono.exe`).
//! 5. Waits for the child via `WaitForSingleObject(INFINITE)` and propagates
//!    the exit code via `std::process::exit(child_exit_code as i32)` (D-03).
//!
//! No JSON parsing surface; argv is the only IPC channel from `nono.exe` (D-08).

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "nono-shell-broker is a Windows-only binary; \
         this build target should not ship it. \
         Phase 31 D-05: cross-compile parity stub."
    );
    std::process::exit(1);
}

#[cfg(windows)]
mod broker {
    use std::ffi::{OsStr, OsString};
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    use nono::{NonoError, OwnedHandle, Result as NonoResult};
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
    use windows_sys::Win32::System::Console::AllocConsole;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
        EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTUPINFOEXW, STARTUPINFOW,
    };

    /// D-08: argv-only IPC. CapabilitySet/Profile NOT passed (RESEARCH §3a —
    /// labels applied supervisor-side BEFORE the broker is spawned).
    #[derive(Debug)]
    pub struct BrokerArgs {
        pub shell_path: PathBuf,
        pub shell_args: Vec<String>,
        pub inherit_handles: Vec<HANDLE>,
        pub cwd: PathBuf,
    }

    /// Manual argv loop. No `clap` — RESEARCH §4a: broker attack surface MUST
    /// be minimal. Parse errors fail fast; no positional args, every arg is
    /// flag-prefixed.
    pub fn parse_args(raw: &[OsString]) -> NonoResult<BrokerArgs> {
        let mut shell_path: Option<PathBuf> = None;
        let mut shell_args: Vec<String> = Vec::new();
        let mut inherit_handles: Vec<HANDLE> = Vec::new();
        let mut cwd: Option<PathBuf> = None;

        // Skip argv[0] (the broker binary path).
        let mut iter = raw.iter().skip(1);
        while let Some(flag) = iter.next() {
            let flag_str = flag.to_string_lossy();
            match flag_str.as_ref() {
                "--shell" => {
                    let v = iter
                        .next()
                        .ok_or_else(|| NonoError::SandboxInit("--shell requires a value".into()))?;
                    shell_path = Some(PathBuf::from(v));
                }
                "--shell-arg" => {
                    let v = iter.next().ok_or_else(|| {
                        NonoError::SandboxInit("--shell-arg requires a value".into())
                    })?;
                    shell_args.push(v.to_string_lossy().into_owned());
                }
                "--inherit-handle" => {
                    let v = iter.next().ok_or_else(|| {
                        NonoError::SandboxInit("--inherit-handle requires a hex value".into())
                    })?;
                    let hex_str = v.to_string_lossy();
                    let stripped = hex_str.trim_start_matches("0x").trim_start_matches("0X");
                    let raw_value = usize::from_str_radix(stripped, 16).map_err(|e| {
                        NonoError::SandboxInit(format!(
                            "--inherit-handle parse error for '{hex_str}': {e}"
                        ))
                    })?;
                    // Phase 41 D-11 (CR-02): reject null (0) and INVALID_HANDLE_VALUE
                    // (usize::MAX on the pointer width — (HANDLE)-1 on 64-bit Windows).
                    // Passing null HANDLE to PROC_THREAD_ATTRIBUTE_HANDLE_LIST is undefined
                    // Win32 behavior; pseudo-handle confusion at (HANDLE)0 could resolve
                    // to the calling process's pseudo-handle in some Win32 paths.
                    if raw_value == 0 || raw_value == usize::MAX {
                        return Err(NonoError::SandboxInit(format!(
                            "--inherit-handle value '{hex_str}' is null or INVALID_HANDLE_VALUE; reject"
                        )));
                    }
                    inherit_handles.push(raw_value as HANDLE);
                }
                "--cwd" => {
                    let v = iter
                        .next()
                        .ok_or_else(|| NonoError::SandboxInit("--cwd requires a value".into()))?;
                    cwd = Some(PathBuf::from(v));
                }
                other => {
                    return Err(NonoError::SandboxInit(format!(
                        "unknown broker arg: '{other}'"
                    )));
                }
            }
        }

        let shell_path =
            shell_path.ok_or_else(|| NonoError::SandboxInit("missing required --shell".into()))?;
        let cwd = cwd.ok_or_else(|| NonoError::SandboxInit("missing required --cwd".into()))?;
        // Phase 41 D-12 (CR-03): reject empty --inherit-handle list. The broker
        // requires at least one inheritable handle so the child has a valid
        // PROC_THREAD_ATTRIBUTE_HANDLE_LIST to bind against. Supersedes Plan 31-02
        // SUMMARY's "empty list = most-restrictive" claim — the broker now makes
        // this state correct-by-construction-rejected, not correct-by-runtime-error.
        if inherit_handles.is_empty() {
            return Err(NonoError::SandboxInit(
                "--inherit-handle list is empty; broker requires at least one inheritable handle"
                    .into(),
            ));
        }
        Ok(BrokerArgs {
            shell_path,
            shell_args,
            inherit_handles,
            cwd,
        })
    }

    /// Build a Win32 command line: `"<shell_path>" arg1 arg2 ...`.
    /// Quoting policy: shell_path always quoted; args quoted if they contain
    /// whitespace or `"`. This matches the PoC's implicit shape (PoC used a
    /// single literal string `"powershell.exe -NoLogo"`).
    pub fn build_command_line(args: &BrokerArgs) -> Vec<u16> {
        let mut cmd = String::new();
        cmd.push('"');
        cmd.push_str(&args.shell_path.to_string_lossy());
        cmd.push('"');
        for a in &args.shell_args {
            cmd.push(' ');
            if a.contains(' ') || a.contains('"') {
                cmd.push('"');
                // Escape embedded quotes by doubling them (PowerShell convention).
                cmd.push_str(&a.replace('"', "\"\""));
                cmd.push('"');
            } else {
                cmd.push_str(a);
            }
        }
        OsStr::new(&cmd).encode_wide().chain(Some(0)).collect()
    }

    fn to_u16_null_terminated(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    /// 8-step sequence. Mechanism MUST stay byte-equivalent to the validated
    /// PoC at `.planning/quick/260508-m99-.../poc-broker/src/main.rs:36-186`,
    /// with token construction unified through `nono::create_low_integrity_primary_token`
    /// per D-06 and HANDLE_LIST discipline added per D-02.
    pub fn run(args: BrokerArgs) -> NonoResult<i32> {
        // Step 1: AllocConsole — non-fatal if parent already attached.
        // rc=0 means console inherited (expected when spawned by nono.exe);
        // rc != 0 means new console (when broker invoked standalone for testing).
        let alloc_rc = unsafe {
            // SAFETY: AllocConsole takes no arguments; safe to call unconditionally.
            AllocConsole()
        };
        tracing::info!(alloc_console_rc = alloc_rc, "broker: console attach probe");

        // Steps 2-5: Construct Low-IL primary token via the lifted library function (D-06).
        // The OwnedHandle returned manages CloseHandle on drop — RAII per Pattern S-07.
        let low_il_token: OwnedHandle = nono::create_low_integrity_primary_token()?;
        tracing::info!("broker: Low-IL primary token constructed");

        // Step 6: Build PROC_THREAD_ATTRIBUTE_HANDLE_LIST per D-02 (production hardening over PoC).
        // Probe required size for one attribute slot.
        let mut attr_size: usize = 0;
        unsafe {
            // SAFETY: First call with null list queries required size; documented Win32 idiom.
            // Documented to return ERROR_INSUFFICIENT_BUFFER and write the required size.
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
        }
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list: LPPROC_THREAD_ATTRIBUTE_LIST =
            attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        let ok = unsafe {
            // SAFETY: attr_list points to attr_buf, sized by the probe call above for one attribute.
            InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
        };
        if ok == 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            return Err(NonoError::SandboxInit(format!(
                "InitializeProcThreadAttributeList failed (GetLastError={err})"
            )));
        }

        // D-02: HANDLE_LIST = exactly the inheritable handles passed via --inherit-handle.
        // Phase 41 D-12 (CR-03): the empty-list case is now rejected by parse_args()
        // before reaching here, so inherit_handles is guaranteed non-empty at this point.
        let handles_array: Vec<HANDLE> = args.inherit_handles.clone();
        let handles_byte_size = std::mem::size_of_val(handles_array.as_slice());
        let ok = unsafe {
            // SAFETY: attr_list initialized above; handles_array lives for the duration of the call.
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles_array.as_ptr() as *mut _,
                handles_byte_size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            unsafe {
                // SAFETY: attr_list was initialized successfully above.
                DeleteProcThreadAttributeList(attr_list);
            }
            return Err(NonoError::SandboxInit(format!(
                "UpdateProcThreadAttribute(HANDLE_LIST) failed (GetLastError={err})"
            )));
        }

        // Step 7: CreateProcessAsUserW with dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT only.
        // D-01: no new-console flag, no pseudoconsole proc-thread attribute — child inherits
        // the broker's already-attached console; KernelBase skips CSRSS attach at Low IL because
        // a console handle is already inherited (RESEARCH A1, PoC-validated 2026-05-08).
        let mut command_line = build_command_line(&args);
        let cwd_wide = to_u16_null_terminated(args.cwd.as_os_str());

        let mut startup_info_ex: STARTUPINFOEXW = unsafe {
            // SAFETY: STARTUPINFOEXW is #[repr(C)] POD; zero-init is documented Win32 idiom.
            std::mem::zeroed()
        };
        startup_info_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup_info_ex.lpAttributeList = attr_list;

        let mut process_info: PROCESS_INFORMATION = unsafe {
            // SAFETY: PROCESS_INFORMATION zero-init is documented Win32 idiom.
            std::mem::zeroed()
        };

        let lp_startup_info = &startup_info_ex.StartupInfo as *const STARTUPINFOW;

        let created = unsafe {
            // SAFETY: low_il_token.raw() is a valid primary token (RAII-owned by OwnedHandle).
            // command_line is null-terminated UTF-16. cwd_wide is null-terminated. The startup
            // struct is correctly initialized with EXTENDED_STARTUPINFO_PRESENT semantics.
            // bInheritHandles=1 is required when PROC_THREAD_ATTRIBUTE_HANDLE_LIST is set;
            // the HANDLE_LIST attribute restricts the actual inherited set to args.inherit_handles.
            CreateProcessAsUserW(
                low_il_token.raw(),
                std::ptr::null(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,                            // bInheritHandles=TRUE (HANDLE_LIST gates)
                EXTENDED_STARTUPINFO_PRESENT, // dwCreationFlags (D-01: no new-console flag)
                std::ptr::null(),             // lpEnvironment: inherit broker env
                cwd_wide.as_ptr(),
                lp_startup_info,
                &mut process_info,
            )
        };

        unsafe {
            // SAFETY: attr_list was initialized above and is no longer needed
            // after CreateProcessAsUserW.
            DeleteProcThreadAttributeList(attr_list);
        }

        if created == 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            return Err(NonoError::SandboxInit(format!(
                "CreateProcessAsUserW failed (GetLastError={err})"
            )));
        }

        // Wrap child handles in OwnedHandle for RAII cleanup.
        let child_process = OwnedHandle(process_info.hProcess);
        let _child_thread = OwnedHandle(process_info.hThread);
        tracing::info!(
            child_pid = process_info.dwProcessId,
            "broker: spawned Low-IL child"
        );

        // Step 8: Wait + propagate exit code (D-03).
        let wait_rc = unsafe {
            // SAFETY: child_process.raw() is a valid process handle from CreateProcessAsUserW.
            WaitForSingleObject(child_process.raw(), INFINITE)
        };
        if wait_rc != 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            return Err(NonoError::SandboxInit(format!(
                "WaitForSingleObject failed (rc={wait_rc}, GetLastError={err})"
            )));
        }

        let mut exit_code: u32 = 0;
        let ok = unsafe {
            // SAFETY: child_process.raw() is still valid; exit_code is a valid out-pointer.
            GetExitCodeProcess(child_process.raw(), &mut exit_code)
        };
        if ok == 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            return Err(NonoError::SandboxInit(format!(
                "GetExitCodeProcess failed (GetLastError={err})"
            )));
        }

        tracing::info!(child_exit_code = exit_code, "broker: child exited");
        // OwnedHandle Drop closes child_process, child_thread, and low_il_token automatically.
        Ok(exit_code as i32)
    }

    /// Phase 31 Plan 31-02 Task 2 — Nyquist gap-fill: pin the broker argv
    /// parser's behavior at the unit-test layer. Plan 31-05's field-test
    /// validates the end-to-end shape; these tests pin the contract so future
    /// regressions surface at unit-test time, not field-test time.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod parse_args_tests {
        use super::*;
        use nono::NonoError;

        fn os(s: &str) -> OsString {
            OsString::from(s)
        }

        /// Helper: argv0 ("broker.exe") followed by the actual flags. The parser
        /// skips argv[0], so the first OsString must always be a placeholder.
        fn argv(rest: &[&str]) -> Vec<OsString> {
            let mut v = vec![os("broker.exe")];
            v.extend(rest.iter().map(|s| os(s)));
            v
        }

        /// D-08: `--shell` is required; absence is fatal with a structured
        /// `SandboxInit` error mentioning the missing flag. Guards against
        /// regressions that would let the broker spawn an arbitrary or
        /// defaulted shell when nono.exe forgets to pass `--shell`.
        #[test]
        fn parse_args_missing_shell_returns_error() {
            let raw = argv(&["--cwd", r"C:\foo"]);
            let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
                panic!("expected SandboxInit error when --shell is omitted");
            };
            assert!(
                msg.contains("missing required --shell"),
                "error message must explicitly call out missing --shell; got: {msg}"
            );
        }

        /// D-08: `--cwd` is required; absence is fatal. Guards against
        /// regressions that would let the broker default the cwd (e.g. to
        /// the broker's own working dir, which is the supervisor's cwd —
        /// a capability leak).
        #[test]
        fn parse_args_missing_cwd_returns_error() {
            let raw = argv(&["--shell", r"C:\Windows\System32\notepad.exe"]);
            let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
                panic!("expected SandboxInit error when --cwd is omitted");
            };
            assert!(
                msg.contains("missing required --cwd"),
                "error message must explicitly call out missing --cwd; got: {msg}"
            );
        }

        /// T-31-20 mitigation: unknown flags MUST hard-fail. The broker is a
        /// minimal-attack-surface binary; silently accepting unknown flags
        /// would let a future bug in nono.exe pass attacker-controlled data
        /// through.
        #[test]
        fn parse_args_unknown_flag_returns_error() {
            let raw = argv(&[
                "--unknown-flag",
                "value",
                "--shell",
                r"C:\foo.exe",
                "--cwd",
                r"C:\",
            ]);
            let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
                panic!("expected SandboxInit error on unknown flag");
            };
            assert!(
                msg.contains("unknown broker arg"),
                "error message must call out 'unknown broker arg'; got: {msg}"
            );
        }

        /// D-08: `--inherit-handle` values are hex-encoded HANDLE values.
        /// Non-hex inputs MUST fail-fast — silently coercing them to 0 would
        /// either break inheritance or worse, accidentally reference a
        /// real handle in the broker's table.
        #[test]
        fn parse_args_invalid_hex_inherit_handle_returns_error() {
            let raw = argv(&[
                "--inherit-handle",
                "xyz",
                "--shell",
                r"C:\foo.exe",
                "--cwd",
                r"C:\",
            ]);
            let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
                panic!("expected SandboxInit error on non-hex --inherit-handle");
            };
            assert!(
                msg.contains("--inherit-handle parse error"),
                "error message must mention --inherit-handle parse error; got: {msg}"
            );
        }

        /// D-08: `--shell-arg` is repeatable and order-preserving. Argv order
        /// determines argv order in the spawned shell — re-ordering would
        /// silently change the meaning of the spawn (e.g. moving `-Command`
        /// past its payload).
        ///
        /// Note: includes one `--inherit-handle` value to satisfy the Phase 41
        /// D-12 (CR-03) requirement that the list be non-empty.
        #[test]
        fn parse_args_shell_arg_preserves_order() {
            let raw = argv(&[
                "--shell",
                "foo.exe",
                "--shell-arg",
                "-A",
                "--shell-arg",
                "-B",
                "--shell-arg",
                "--foo",
                "--inherit-handle",
                "0xa",
                "--cwd",
                r"C:\",
            ]);
            let parsed = parse_args(&raw).expect("parse must succeed");
            assert_eq!(
                parsed.shell_args,
                vec!["-A".to_string(), "-B".to_string(), "--foo".to_string()],
                "shell_args order must match argv order; reordering would silently \
                 change the spawned command's meaning"
            );
        }

        /// D-08: `--inherit-handle` accepts both `0x` and `0X` prefixes (and
        /// strips them before hex parsing). Both are accumulated in argv
        /// order. Guards against the prefix-matching bug where only one case
        /// was stripped → the other case would parse as a different value
        /// (or fail entirely).
        #[test]
        fn parse_args_multiple_inherit_handles_accumulate() {
            let raw = argv(&[
                "--inherit-handle",
                "0xa",
                "--inherit-handle",
                "0X10",
                "--shell",
                "foo",
                "--cwd",
                r"C:\",
            ]);
            let parsed = parse_args(&raw).expect("parse must succeed");
            assert_eq!(
                parsed.inherit_handles.len(),
                2,
                "both --inherit-handle flags must accumulate"
            );
            assert_eq!(
                parsed.inherit_handles[0] as usize, 0xa,
                "first handle must parse from lowercase 0x prefix"
            );
            assert_eq!(
                parsed.inherit_handles[1] as usize, 0x10,
                "second handle must parse from uppercase 0X prefix"
            );
        }

        /// Phase 41 D-12 (CR-03): an empty inherit-handle list is REJECTED at the
        /// broker argv parser. Supersedes Plan 31-02 SUMMARY's "most-restrictive"
        /// claim — the broker now requires at least one inheritable handle, making
        /// the empty-list shape correct-by-construction-rejected.
        #[test]
        fn parse_args_empty_inherit_handle_list_returns_error() {
            let raw = argv(&["--shell", "foo", "--cwd", r"C:\"]);
            let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
                panic!("expected SandboxInit error on empty --inherit-handle list");
            };
            assert!(
                msg.contains("empty"),
                "error message must indicate empty-list rejection, got: {msg}"
            );
        }

        /// Phase 41 D-11 (CR-02): a null or INVALID_HANDLE_VALUE handle is REJECTED
        /// at the broker argv parser. Pseudo-handle confusion at `(HANDLE)0` and
        /// the `(HANDLE)-1` sentinel are blocked before any UpdateProcThreadAttribute
        /// call. Locks the CR-02 fix against regression.
        #[test]
        fn parse_args_null_inherit_handle_returns_error() {
            let raw = argv(&["--shell", "foo", "--cwd", r"C:\", "--inherit-handle", "0x0"]);
            let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
                panic!("expected SandboxInit error on --inherit-handle 0x0");
            };
            assert!(
                msg.contains("null") || msg.contains("INVALID_HANDLE_VALUE"),
                "error message must indicate null-handle rejection, got: {msg}"
            );
        }

        /// Phase 41 D-11 (CR-02): the INVALID_HANDLE_VALUE sentinel (0xFFFFFFFFFFFFFFFF on
        /// 64-bit Windows) is also REJECTED. Defense-in-depth alongside the null check.
        #[test]
        fn parse_args_invalid_handle_value_inherit_handle_returns_error() {
            let raw = argv(&["--shell", "foo", "--cwd", r"C:\", "--inherit-handle", "0xFFFFFFFFFFFFFFFF"]);
            let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
                panic!("expected SandboxInit error on --inherit-handle 0xFFFFFFFFFFFFFFFF");
            };
            assert!(
                msg.contains("null") || msg.contains("INVALID_HANDLE_VALUE"),
                "error message must indicate INVALID_HANDLE_VALUE rejection, got: {msg}"
            );
        }

        /// Defensive parse: a flag at the end of argv with no following value
        /// MUST fail — silently treating it as an empty string would let a
        /// truncated argv slip through (e.g., from a corrupted IPC channel).
        #[test]
        fn parse_args_dangling_flag_value_returns_error() {
            // `--shell` is the last token; no value follows.
            let raw = argv(&["--cwd", r"C:\", "--shell"]);
            let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
                panic!("expected SandboxInit error when --shell has no value");
            };
            assert!(
                msg.contains("--shell requires a value"),
                "dangling --shell must report 'requires a value'; got: {msg}"
            );
        }
    }

    /// Phase 31 Plan 31-02 Task 2 — Nyquist gap-fill: pin the broker
    /// command-line builder's quoting behavior. The Win32 CommandLine grammar
    /// is fragile; quoting bugs here would silently mis-tokenize the spawned
    /// shell's argv on the other side of `CreateProcessAsUserW`.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod build_command_line_tests {
        use super::*;
        use std::path::PathBuf;

        fn args(shell_path: &str, shell_args: Vec<String>) -> BrokerArgs {
            BrokerArgs {
                shell_path: PathBuf::from(shell_path),
                shell_args,
                inherit_handles: vec![],
                cwd: PathBuf::from(r"C:\"),
            }
        }

        /// Decode the trailing-null UTF-16 buffer back to a `String` for
        /// human-readable assertions. Drops the trailing 0 terminator.
        fn decode(wide: &[u16]) -> String {
            assert!(
                !wide.is_empty(),
                "command line must have at least the null terminator"
            );
            String::from_utf16_lossy(&wide[..wide.len() - 1])
        }

        /// D-08 contract: shell_path is ALWAYS quoted, even if it contains no
        /// whitespace, so the path-with-spaces case (e.g. `C:\Program Files\...`)
        /// can never be silently mis-tokenized.
        #[test]
        fn build_command_line_quotes_shell_path() {
            let a = args(r"C:\Windows\System32\powershell.exe", vec![]);
            let wide = build_command_line(&a);
            let s = decode(&wide);
            assert_eq!(
                s, "\"C:\\Windows\\System32\\powershell.exe\"",
                "shell_path must always be enclosed in literal double-quotes"
            );
        }

        /// Simple args (no whitespace, no quotes) round-trip without quoting.
        /// Order matches argv order.
        #[test]
        fn build_command_line_appends_simple_args() {
            let a = args(
                r"C:\foo.exe",
                vec!["-NoLogo".to_string(), "-NoProfile".to_string()],
            );
            let wide = build_command_line(&a);
            let s = decode(&wide);
            assert_eq!(
                s, "\"C:\\foo.exe\" -NoLogo -NoProfile",
                "simple args must be appended unquoted in argv order"
            );
        }

        /// Args containing whitespace MUST be enclosed in double-quotes so the
        /// child's CRT command-line parser tokenizes them as a single argv
        /// entry. Without this, "hello world" would arrive as two separate args.
        #[test]
        fn build_command_line_quotes_args_with_whitespace() {
            let a = args(r"C:\foo.exe", vec!["hello world".to_string()]);
            let wide = build_command_line(&a);
            let s = decode(&wide);
            assert!(
                s.contains("\"hello world\""),
                "whitespace-bearing args must be quoted; got: {s}"
            );
        }

        /// Embedded literal quotes in args must be doubled (PowerShell
        /// convention). Failure here would either truncate the arg at the
        /// embedded quote or leave the command line unbalanced.
        #[test]
        fn build_command_line_doubles_embedded_quotes() {
            let a = args(r"C:\foo.exe", vec!["a\"b".to_string()]);
            let wide = build_command_line(&a);
            let s = decode(&wide);
            assert!(
                s.contains("\"a\"\"b\""),
                "embedded quotes must be doubled (PowerShell convention); got: {s}"
            );
        }

        /// Win32 CommandLine MUST be null-terminated UTF-16. Without the
        /// trailing null, `CreateProcessAsUserW` reads past the buffer end.
        #[test]
        fn build_command_line_terminates_with_null() {
            let a = args(r"C:\foo.exe", vec!["a".to_string()]);
            let wide = build_command_line(&a);
            assert_eq!(
                wide.last(),
                Some(&0),
                "command line buffer must be null-terminated UTF-16"
            );
        }
    }
}

#[cfg(windows)]
fn main() {
    // Tracing → broker's stderr; nono.exe's WindowsSupervisorRuntime captures
    // broker stderr per existing log routing (Claude's Discretion: stderr-only,
    // no separate file).
    //
    // EnvFilter resolution: explicit `match` (not `unwrap_or_else`) — CLAUDE.md
    // § Unwrap Policy. RUST_LOG override → use it; otherwise default to "info".
    let env_filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::new("info"),
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .init();

    let raw: Vec<std::ffi::OsString> = std::env::args_os().collect();
    match broker::parse_args(&raw).and_then(broker::run) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            tracing::error!(error = %e, "broker: fatal error");
            eprintln!("nono-shell-broker: {e}");
            std::process::exit(2);
        }
    }
}
