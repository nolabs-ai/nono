use super::*;
use crate::exec_strategy::{SeccompPolicy, SupervisorConfig, ThreadingContext, supervisor_linux};
use nono::{AccessMode, FsCapability};
use std::ffi::CString;
use std::path::Path;
use std::time::{Duration, Instant};

fn isolated(name: &str, test: impl FnOnce() -> Result<()>) -> Result<()> {
    if std::env::var("NONO_CLONE_TEST").ok().as_deref() == Some(name) {
        return test();
    }
    let executable = std::env::current_exe().map_err(NonoError::Io)?;
    let mut process = std::process::Command::new(executable);
    if name == "tool_gate_with_combined_notifications" {
        process.env("PATH", "");
    }
    if name.starts_with("live_") {
        process.arg("--ignored");
    }
    let mut child = process
        .args([
            "--exact",
            &format!("exec_strategy::clone_files::tests::{name}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env("NONO_CLONE_TEST", name)
        .spawn()
        .map_err(NonoError::Io)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = child.try_wait().map_err(NonoError::Io)? {
            assert!(status.success(), "isolated {name}: {status}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill().map_err(NonoError::Io)?;
            child.wait().map_err(NonoError::Io)?;
            return Err(failure("isolated test exceeded timeout"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn config(caps: &CapabilitySet, filesystem: bool, proxy: bool) -> ExecConfig<'_> {
    ExecConfig {
        command: &[],
        resolved_program: Path::new("/usr/bin/python3"),
        caps,
        env_vars: vec![],
        cap_file: Path::new("/unused"),
        current_dir: Path::new("/"),
        child_pwd: None,
        host_pwd: None,
        no_diagnostics: true,
        diagnostics_json: false,
        proxy_diagnostics: None,
        diagnostic_verbosity: 0,
        threading: ThreadingContext::Strict,
        protected_paths: &[],
        profile_save_base: None,
        ignored_denial_paths: &[],
        suppressed_system_service_operations: &[],
        startup_timeout: None,
        seccomp_policy: SeccompPolicy {
            capability_elevation: filesystem,
            proxy_fallback: proxy,
            af_unix_mediation: true,
            proc_comm_notify: filesystem,
        },
        sandbox_policy: LinuxSandboxPolicy::Auto,
        allowed_env_vars: None,
        denied_env_vars: None,
        case_insensitive_env_vars: false,
        set_vars: vec![],
        tool_sandbox_runtime: None,
    }
}

fn capabilities(port: u16, bind: u16) -> Result<CapabilitySet> {
    let mut caps = CapabilitySet::new().proxy_only_with_bind(port, vec![bind]);
    for directory in ["/usr", "/lib", "/lib64", "/etc", "/proc/self/fd"] {
        if Path::new(directory).exists() {
            caps.add_fs(FsCapability::new_dir(directory, AccessMode::Read)?);
        }
    }
    caps.add_fs(FsCapability::new_file(
        "/proc/self/status",
        AccessMode::Read,
    )?);
    caps.add_fs(FsCapability::new_file("/dev/null", AccessMode::ReadWrite)?);
    caps.deduplicate();
    Ok(caps)
}

struct Deny;
impl nono::ApprovalBackend for Deny {
    fn request_approval(
        &self,
        _: &nono::supervisor::ApprovalRequest,
    ) -> Result<nono::supervisor::ApprovalDecision> {
        Ok(nono::supervisor::ApprovalDecision::Denied {
            reason: "test".into(),
        })
    }
    fn backend_name(&self) -> &str {
        "test-deny"
    }
}

fn supervise(
    bootstrap: &Bootstrap,
    caps: &CapabilitySet,
    policy: SeccompPolicy,
    port: u16,
    bind: u16,
) -> Result<i32> {
    let scrub = nono::ScrubPolicy::secure_default();
    let config = SupervisorConfig {
        protected_roots: &[],
        approval_backend: &Deny,
        session_id: "clone-test",
        attach_initial_client: false,
        detach_sequence: None,
        caps,
        open_url_origins: &[],
        open_url_allow_localhost: false,
        audit_recorder: None,
        network_audit_events: None,
        redaction_policy: &scrub,
        allow_launch_services_active: false,
        seccomp_policy: policy,
        proxy_port: port,
        proxy_bind_ports: vec![bind],
        proxy_bind_port_ranges: vec![],
        unix_socket_allowlist: caps.unix_socket_capabilities(),
        tool_sandbox_runtime: None,
    };
    let mut child_caps = caps.clone();
    child_caps.remap_procfs_self_references(bootstrap.child.as_raw() as u32, None);
    child_caps.widen_procfs_self_to_proc();
    let initial: Vec<_> = child_caps
        .fs_capabilities()
        .iter()
        .map(|cap| supervisor_linux::InitialCapability {
            path: cap.resolved.clone(),
            access: cap.access,
            is_file: cap.is_file,
        })
        .collect();
    let mut limiter = supervisor_linux::RateLimiter::new(10000, 10000);
    let mut denials = vec![];
    let mut ipc_denials = vec![];
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut status = 0;
        // SAFETY: direct test child, status points to valid storage.
        let waited = unsafe { libc::waitpid(bootstrap.child.as_raw(), &mut status, libc::WNOHANG) };
        if waited == bootstrap.child.as_raw() {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            });
        }
        if Instant::now() >= deadline {
            kill_and_reap(bootstrap.child.as_raw());
            return Err(failure("test supervisor timed out"));
        }
        let mut polls = [libc::pollfd {
            fd: bootstrap.network.as_ref().map_or(-1, AsRawFd::as_raw_fd),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: initialized poll array; no borrowed buffer outlives this call.
        if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 20) } < 0 {
            continue;
        }
        if polls[0].revents & libc::POLLIN != 0 {
            supervisor_linux::handle_combined_notification(
                polls[0].fd,
                bootstrap.child,
                &config,
                &initial,
                supervisor_linux::SeccompNotificationState {
                    rate_limiter: &mut limiter,
                    denials: &mut denials,
                    trust_interceptor: None,
                    pty: None,
                },
                &mut ipc_denials,
            )?;
        }
    }
}

fn run(
    config: &ExecConfig<'_>,
    script: &str,
    abi: landlock::ABI,
    fault: Fault,
    supervisor_fd: Option<RawFd>,
    pty: Option<RawFd>,
    resource: Option<RawFd>,
) -> Result<Bootstrap> {
    let program = CString::new("/usr/bin/python3").map_err(|_| failure("program CString"))?;
    let arg = CString::new("-c").map_err(|_| failure("argument CString"))?;
    let script = CString::new(script).map_err(|_| failure("script CString"))?;
    let argv = [
        program.as_ptr(),
        arg.as_ptr(),
        script.as_ptr(),
        std::ptr::null(),
    ];
    let environment = c"PYTHONDONTWRITEBYTECODE=1";
    let envp = [environment.as_ptr(), std::ptr::null()];
    spawn(
        config,
        Command {
            program: &program,
            argv: &argv,
            envp: &envp,
            cwd: c"/",
            supervisor_fd,
            pty_slave: pty,
            resource_procs: resource,
            fault,
        },
        config.caps,
        DetectedAbi::new(abi),
    )
}

fn fd_count() -> Result<usize> {
    Ok(std::fs::read_dir("/proc/self/fd")
        .map_err(NonoError::Io)?
        .count())
}

#[test]
fn proxy_and_combined_notifications() -> Result<()> {
    isolated("proxy_and_combined_notifications", || {
        let _lock = lock_listener_ownership()?;
        let status = std::fs::read_to_string("/proc/self/status").map_err(NonoError::Io)?;
        let effective = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:\t"))
            .ok_or_else(|| failure("missing CapEff"))?;
        let effective =
            u64::from_str_radix(effective, 16).map_err(|_| failure("invalid CapEff"))?;
        assert_eq!(
            effective & (1 << 19),
            0,
            "test must run without CAP_SYS_PTRACE"
        );
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").map_err(NonoError::Io)?;
        let direct = std::net::TcpListener::bind("127.0.0.1:0").map_err(NonoError::Io)?;
        let spare = std::net::TcpListener::bind("127.0.0.1:0").map_err(NonoError::Io)?;
        let port = proxy.local_addr().map_err(NonoError::Io)?.port();
        let denied_port = direct.local_addr().map_err(NonoError::Io)?.port();
        let bind = spare.local_addr().map_err(NonoError::Io)?.port();
        drop(spare);
        let dir = tempfile::tempdir().map_err(NonoError::Io)?;
        let unix_path = dir.path().join("allowed.sock");
        let denied_unix_path = dir.path().join("denied.sock");
        let _unix = std::os::unix::net::UnixListener::bind(&unix_path).map_err(NonoError::Io)?;
        let _denied_unix =
            std::os::unix::net::UnixListener::bind(&denied_unix_path).map_err(NonoError::Io)?;
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "must stay inaccessible").map_err(NonoError::Io)?;
        let mut caps = capabilities(port, bind)?;
        caps.add_unix_socket(nono::UnixSocketCapability::new_file(
            &unix_path,
            nono::UnixSocketMode::Connect,
        )?);
        let before = fd_count()?;
        for (abi, filesystem) in [
            (landlock::ABI::V3, false),
            (landlock::ABI::V3, true),
            (landlock::ABI::V4, false),
            (landlock::ABI::V4, true),
        ] {
            let config = config(&caps, filesystem, abi == landlock::ABI::V3);
            let script = format!(
                r#"
import errno, os, socket
leaks = []
for fd in range(3, 2048):
    try: os.fstat(fd)
    except OSError: continue
    leaks.append(fd)
assert not leaks, leaks
socket.create_connection(('127.0.0.1', {port}), timeout=2).close()
try: socket.create_connection(('127.0.0.1', {denied_port}), timeout=2)
except PermissionError: pass
else: raise AssertionError('direct TCP escaped')
s = socket.socket(); s.bind(('127.0.0.1', {bind})); s.close()
try: socket.socket().bind(('127.0.0.1', 0))
except PermissionError: pass
else: raise AssertionError('ungranted bind escaped')
s = socket.socket(socket.AF_UNIX); s.connect({unix_path:?}); s.close()
try: socket.socket(socket.AF_UNIX).connect({denied_unix_path:?})
except PermissionError: pass
else: raise AssertionError('ungranted AF_UNIX escaped')
try: open({secret:?})
except PermissionError: pass
else: raise AssertionError('filesystem escaped')
assert 'Pid:\t' + str(os.getpid()) + '\n' in open('/proc/self/status').read()
try: open('/proc/{parent}/status')
except PermissionError: pass
else: raise AssertionError('parent procfs accidentally granted')
"#,
                unix_path = unix_path.to_string_lossy(),
                denied_unix_path = denied_unix_path.to_string_lossy(),
                secret = secret.to_string_lossy(),
                parent = std::process::id()
            );
            let bootstrap = run(&config, &script, abi, Fault::Fragmented, None, None, None)?;
            assert_eq!(
                supervise(&bootstrap, &caps, config.seccomp_policy, port, bind)?,
                0,
                "{abi:?}, filesystem={filesystem}"
            );
            drop(bootstrap);
            assert_eq!(
                fd_count()?,
                before,
                "fd leak after {abi:?}, filesystem={filesystem}"
            );
        }
        Ok(())
    })
}

#[test]
fn failure_cleanup() -> Result<()> {
    isolated("failure_cleanup", || {
        let _lock = lock_listener_ownership()?;
        let caps = capabilities(34567, 34568)?;
        let config = config(&caps, true, true);
        let sentinel = std::fs::File::open("/dev/null").map_err(NonoError::Io)?;
        let existing = preexisting_listener()?;
        let before = fd_count()?;
        for fault in [
            Fault::BeforeListener,
            Fault::AfterFilesystem,
            Fault::AfterListener,
            Fault::BeforeDetach,
            Fault::AfterDetach,
            Fault::InvalidReport,
            Fault::FailedAck,
        ] {
            assert!(
                run(
                    &config,
                    "raise AssertionError('must not exec')",
                    landlock::ABI::V3,
                    fault,
                    Some(sentinel.as_raw_fd()),
                    None,
                    None
                )
                .is_err()
            );
            assert_eq!(fd_count()?, before);
            assert!(
                !sentinel
                    .metadata()
                    .map_err(NonoError::Io)?
                    .file_type()
                    .is_file()
            );
        }
        assert!(
            run(
                &config,
                "raise AssertionError('must not exec')",
                landlock::ABI::V3,
                Fault::InvalidReport,
                Some(existing.as_raw_fd()),
                None,
                None
            )
            .is_err()
        );
        assert_eq!(fd_count()?, before);
        assert!(listener_target(
            &std::fs::read_link(format!("/proc/self/fd/{}", existing.as_raw_fd()))
                .map_err(NonoError::Io)?
        ));
        let argv = [
            c"/nonexistent-nono-clone-command".as_ptr(),
            std::ptr::null(),
        ];
        let envp = [std::ptr::null()];
        let bootstrap = spawn(
            &config,
            Command {
                program: c"/nonexistent-nono-clone-command",
                argv: &argv,
                envp: &envp,
                cwd: c"/",
                supervisor_fd: None,
                pty_slave: None,
                resource_procs: None,
                fault: Fault::None,
            },
            &caps,
            DetectedAbi::new(landlock::ABI::V3),
        )?;
        assert_eq!(
            supervise(&bootstrap, &caps, config.seccomp_policy, 34567, 34568)?,
            127
        );
        drop(bootstrap);
        assert_eq!(fd_count()?, before);
        for fault in [Fault::BadAck, Fault::AfterAck] {
            let bootstrap = run(
                &config,
                "raise AssertionError('must not exec')",
                landlock::ABI::V3,
                fault,
                None,
                None,
                None,
            )?;
            assert_eq!(
                supervise(&bootstrap, &caps, config.seccomp_policy, 34567, 34568)?,
                126
            );
            drop(bootstrap);
            assert_eq!(fd_count()?, before);
        }
        Ok(())
    })
}

#[test]
fn fd_churn_signals_and_late_descriptors() -> Result<()> {
    isolated("fd_churn_signals_and_late_descriptors", || {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        static SIGNALS: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn handler(_: i32) {
            SIGNALS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: actions are initialized before installation; the handler
        // only performs an atomic operation, and is restored on every exit.
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handler as *const () as usize;
        // SAFETY: both signal action pointers are valid.
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut previous) },
            0
        );
        struct Restore(libc::sigaction);
        impl Drop for Restore {
            fn drop(&mut self) {
                // SAFETY: restore the action saved by sigaction.
                unsafe {
                    libc::sigaction(libc::SIGUSR1, &self.0, std::ptr::null_mut());
                }
            }
        }
        let _restore = Restore(previous);
        let _lock = lock_listener_ownership()?;
        let caps = capabilities(34567, 34568)?;
        let config = config(&caps, false, true);
        let before = fd_count()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let parent = std::process::id() as libc::pid_t;
        let worker = std::thread::spawn(move || -> Result<()> {
            while !worker_stop.load(Ordering::Relaxed) {
                let file = std::fs::File::open("/dev/null").map_err(NonoError::Io)?;
                // SAFETY: allocate and close only a descriptor owned by this
                // worker. This deliberately races the shared-table bootstrap.
                let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 768) };
                if high < 0 {
                    return Err(failure("fd churn could not allocate high descriptor"));
                }
                // SAFETY: checked, freshly allocated descriptor and our own PID.
                unsafe {
                    libc::close(high);
                    libc::kill(parent, libc::SIGUSR1);
                }
                std::thread::sleep(Duration::from_micros(100));
            }
            Ok(())
        });
        let exercise = (|| -> Result<()> {
            for _ in 0..24 {
                let bootstrap = run(
                    &config,
                    r#"
import os
for name in os.listdir('/proc/self/fd'):
    try: target = os.readlink('/proc/self/fd/' + name)
    except FileNotFoundError: continue
    assert int(name) <= 2, (name, target)
"#,
                    landlock::ABI::V3,
                    Fault::LateFd,
                    None,
                    None,
                    None,
                )?;
                assert_eq!(
                    supervise(&bootstrap, &caps, config.seccomp_policy, 34567, 34568)?,
                    0
                );
            }
            let bootstrap = run(
                &config,
                "raise AssertionError('pending SIGUSR1 must terminate before exec')",
                landlock::ABI::V3,
                Fault::PendingSignal,
                None,
                None,
                None,
            )?;
            assert_eq!(
                supervise(&bootstrap, &caps, config.seccomp_policy, 34567, 34568)?,
                128 + libc::SIGUSR1
            );
            Ok(())
        })();
        stop.store(true, Ordering::Relaxed);
        worker
            .join()
            .map_err(|_| failure("fd churn thread panicked"))??;
        exercise?;
        assert!(SIGNALS.load(Ordering::Relaxed) > 0);
        assert_eq!(fd_count()?, before);
        Ok(())
    })
}

#[test]
fn pty_cgroup_write_and_supervisor_inheritance() -> Result<()> {
    isolated("pty_cgroup_write_and_supervisor_inheritance", || {
        use std::io::{Read, Seek};
        let _lock = lock_listener_ownership()?;
        let caps = capabilities(34567, 34568)?;
        let config = config(&caps, true, true);
        let pty = crate::pty_proxy::open_pty()?;
        let (supervisor, _peer) = UnixStream::pair().map_err(NonoError::Io)?;
        let mut procs = tempfile::tempfile().map_err(NonoError::Io)?;
        let script = format!(
            r#"
import os
assert all(os.isatty(fd) for fd in (0, 1, 2))
assert os.getsid(0) == os.getpid()
assert os.get_inheritable({fd})
live = []
for number in range(3, 2048):
    try: os.fstat(number)
    except OSError: continue
    live.append(number)
assert live == [{fd}], live
"#,
            fd = supervisor.as_raw_fd()
        );
        let bootstrap = run(
            &config,
            &script,
            landlock::ABI::V3,
            Fault::None,
            Some(supervisor.as_raw_fd()),
            Some(pty.slave.as_raw_fd()),
            Some(procs.as_raw_fd()),
        )?;
        let code = supervise(&bootstrap, &caps, config.seccomp_policy, 34567, 34568)?;
        if code != 0 {
            let mut output = [0_u8; 8192];
            // SAFETY: owned PTY master and initialized output buffer.
            let read = unsafe {
                libc::fcntl(pty.master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
                libc::read(
                    pty.master.as_raw_fd(),
                    output.as_mut_ptr().cast(),
                    output.len(),
                )
            };
            if read > 0 {
                eprintln!(
                    "PTY child output: {}",
                    String::from_utf8_lossy(&output[..read as usize])
                );
            }
        }
        assert_eq!(code, 0);
        procs.rewind().map_err(NonoError::Io)?;
        let mut written = String::new();
        procs.read_to_string(&mut written).map_err(NonoError::Io)?;
        assert_eq!(written, bootstrap.child.as_raw().to_string());
        // This verifies the exact cgroup.procs write path; a real delegated
        // cgroup is covered separately by resource_cgroup's live kernel tests.
        let bootstrap = run(
            &config,
            "raise AssertionError('invalid cgroup fd must prevent exec')",
            landlock::ABI::V3,
            Fault::None,
            None,
            None,
            Some(-1),
        )?;
        assert_eq!(
            supervise(&bootstrap, &caps, config.seccomp_policy, 34567, 34568)?,
            126
        );
        Ok(())
    })
}

fn deny_syscalls(syscalls: &[libc::c_long]) -> Result<()> {
    let mut filter = vec![libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    for syscall in syscalls {
        filter.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: *syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | libc::EPERM as u32,
        });
    }
    filter.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    });
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: test-only restrictive filter; array and header live through the
    // syscall. Installed only inside the isolated test subprocess.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
            || libc::syscall(libc::SYS_seccomp, 1, 0, &program) < 0
        {
            return Err(failure("cannot install regression syscall denial filter"));
        }
    }
    Ok(())
}

#[test]
fn kernel_detachment_failure_is_closed() -> Result<()> {
    isolated("kernel_detachment_failure_is_closed", || {
        let _lock = lock_listener_ownership()?;
        deny_syscalls(&[libc::SYS_close_range, libc::SYS_unshare])?;
        let caps = capabilities(34567, 34568)?;
        let config = config(&caps, true, true);
        let before = fd_count()?;
        for _ in 0..8 {
            assert!(
                run(
                    &config,
                    "raise AssertionError('must not exec')",
                    landlock::ABI::V3,
                    Fault::None,
                    None,
                    None,
                    None
                )
                .is_err()
            );
            assert_eq!(fd_count()?, before);
        }
        Ok(())
    })
}

#[test]
fn closed_stdio_and_unshare_fallback() -> Result<()> {
    isolated("closed_stdio_and_unshare_fallback", || {
        // Exercise the older-kernel detachment path and prove there is no
        // dependency on either pidfd syscall even when explicitly denied.
        deny_syscalls(&[
            libc::SYS_close_range,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_getfd,
        ])?;
        let _lock = lock_listener_ownership()?;
        let caps = capabilities(34567, 34568)?;
        let config = config(&caps, false, true);
        let mut saved = Vec::new();
        for fd in 0..=2 {
            // SAFETY: save each original stdio slot before closing it.
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                return Err(failure("cannot save test stdio"));
            }
            // SAFETY: checked, fresh owned duplicate.
            saved.push(unsafe { OwnedFd::from_raw_fd(duplicate) });
        }
        struct Restore(Vec<OwnedFd>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (fd, saved) in self.0.iter().enumerate() {
                    // SAFETY: restore only the stdio slots this test closed.
                    unsafe {
                        libc::dup2(saved.as_raw_fd(), fd as i32);
                    }
                }
            }
        }
        let restore = Restore(saved);
        for fd in 0..=2 {
            // SAFETY: saved copies above remain alive until restoration.
            unsafe {
                libc::close(fd);
            }
        }
        let (left, right) = nono::SupervisorSocket::pair()?;
        let left = promote_supervisor_socket(left)?;
        let right = promote_supervisor_socket(right)?;
        assert!(left.as_raw_fd() >= 3 && right.as_raw_fd() >= 3);
        drop(left);
        drop(right);
        let outcome = (|| -> Result<i32> {
            let bootstrap = run(
                &config,
                r#"
import os
for fd in range(0, 2048):
    try: os.fstat(fd)
    except OSError: continue
    raise AssertionError(('unexpected inherited fd', fd))
"#,
                landlock::ABI::V3,
                Fault::None,
                None,
                None,
                None,
            )?;
            for fd in 0..=2 {
                // SAFETY: query only; parent placeholders must have been released.
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
            }
            supervise(&bootstrap, &caps, config.seccomp_policy, 34567, 34568)
        })();
        drop(restore);
        assert_eq!(outcome?, 0);
        Ok(())
    })
}

#[test]
fn full_cli_supervisor_combined_path() -> Result<()> {
    isolated("full_cli_supervisor_combined_path", || {
        deny_syscalls(&[libc::SYS_pidfd_getfd])?;
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").map_err(NonoError::Io)?;
        let direct = std::net::TcpListener::bind("127.0.0.1:0").map_err(NonoError::Io)?;
        let port = proxy.local_addr().map_err(NonoError::Io)?.port();
        let denied = direct.local_addr().map_err(NonoError::Io)?.port();
        let caps = capabilities(port, 34568)?;
        let mut config = config(&caps, true, true);
        let script = format!(
            "import socket\nsocket.create_connection(('127.0.0.1',{port})).close()\ntry: socket.create_connection(('127.0.0.1',{denied}))\nexcept PermissionError: pass\nelse: raise AssertionError('direct TCP escaped')\n"
        );
        let argv = vec![
            std::ffi::OsString::from("/usr/bin/python3"),
            "-c".into(),
            script.into(),
        ];
        config.command = &argv;
        // The Rust test runner itself has a worker thread; the CLI's normal
        // known-thread budget already covers this context.
        config.threading = ThreadingContext::CryptoExpected;
        let scrub = nono::ScrubPolicy::secure_default();
        let supervisor = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &Deny,
            session_id: "clone-test",
            attach_initial_client: false,
            detach_sequence: None,
            caps: &caps,
            open_url_origins: &[],
            open_url_allow_localhost: false,
            audit_recorder: None,
            network_audit_events: None,
            redaction_policy: &scrub,
            allow_launch_services_active: false,
            seccomp_policy: config.seccomp_policy,
            proxy_port: port,
            proxy_bind_ports: vec![34568],
            proxy_bind_port_ranges: vec![],
            unix_socket_allowlist: &[],
            tool_sandbox_runtime: None,
        };
        let before = fd_count()?;
        let code = crate::exec_strategy::execute_supervised(
            &config,
            Some(&supervisor),
            None,
            None,
            None,
            None,
            None,
            None::<fn(i32) -> bool>,
        )?;
        assert_eq!(code, 0);
        assert_eq!(fd_count()?, before);
        Ok(())
    })
}

#[test]
fn tool_gate_with_combined_notifications() -> Result<()> {
    isolated("tool_gate_with_combined_notifications", || {
        let _lock = lock_listener_ownership()?;
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").map_err(NonoError::Io)?;
        let port = proxy.local_addr().map_err(NonoError::Io)?.port();
        let mut caps = capabilities(port, 34568)?;
        let directory = tempfile::tempdir().map_err(NonoError::Io)?;
        std::os::unix::fs::symlink("/usr/bin/python3", directory.path().join("python3"))
            .map_err(NonoError::Io)?;
        std::os::unix::fs::symlink("/usr/bin/true", directory.path().join("true"))
            .map_err(NonoError::Io)?;
        let mut policy = crate::command_policy::CommandPoliciesConfig {
            executable_dirs: vec![directory.path().to_string_lossy().into_owned()],
            ..Default::default()
        };
        policy.commands.insert(
            "true".into(),
            crate::command_policy::CommandPolicyConfig {
                executable: Some("/usr/bin/true".into()),
                ..Default::default()
            },
        );
        let credentials = std::collections::BTreeMap::new();
        let runtime = crate::tool_sandbox::PreparedToolSandboxRuntime::prepare(
            crate::tool_sandbox::ToolSandboxPrepare {
                config: &policy,
                resolved_command_binaries: None,
                audit_context: crate::tool_sandbox::ToolSandboxAuditContext::new(
                    None,
                    nono::ScrubPolicy::secure_default(),
                ),
                allowed_commands: &[],
                blocked_commands: &[],
                outer_caps: &caps,
                deny_paths: &[],
                policy_root: directory.path(),
                proxy_credential_env_vars: &credentials,
                proxy_trust_bundle_paths: &[],
                shared_broker: None,
            },
        )?;
        let outcome = (|| -> Result<()> {
            runtime.grant_outer_caps(&mut caps)?;
            let mut config = config(&caps, true, true);
            config.tool_sandbox_runtime = Some(&runtime);
            let script = format!(
                "import os, socket\ntry: os.execv('/usr/bin/true', ['true'])\nexcept PermissionError: pass\nelse: raise AssertionError('tool execution gate escaped')\nsocket.create_connection(('127.0.0.1',{port})).close()\n"
            );
            let bootstrap = run(
                &config,
                &script,
                landlock::ABI::V3,
                Fault::None,
                None,
                None,
                None,
            )?;
            assert_eq!(
                supervise(&bootstrap, &caps, config.seccomp_policy, port, 34568)?,
                0
            );
            // A gate created while stdin is closed must not occupy a stdio
            // slot that later setup could replace or accidentally inherit.
            // SAFETY: save only our original stdin, then restore it below.
            let saved = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
            if saved < 0 {
                return Err(failure("cannot save stdin for gate test"));
            }
            // SAFETY: checked fresh owned duplicate.
            let saved = unsafe { OwnedFd::from_raw_fd(saved) };
            // SAFETY: original stdin has been saved.
            unsafe {
                libc::close(0);
            }
            let closed = run(
                &config,
                &script,
                landlock::ABI::V3,
                Fault::None,
                None,
                None,
                None,
            );
            // SAFETY: restore the exact slot saved above even if launch failed.
            let restored = unsafe { libc::dup2(saved.as_raw_fd(), 0) };
            assert_eq!(restored, 0);
            let bootstrap = closed?;
            assert_eq!(
                supervise(&bootstrap, &caps, config.seccomp_policy, port, 34568)?,
                0
            );
            Ok(())
        })();
        runtime.cleanup_runtime_dir();
        outcome
    })
}

// Produce an unrelated listener in the parent table without installing its
// filter in the parent. The temporary trusted raw child exits immediately.
fn preexisting_listener() -> Result<OwnedFd> {
    let snapshot = listeners()?;
    let filter = sandbox::prepare_seccomp_proxy_filter(false);
    let mut signals = Signals::block()?;
    // SAFETY: only the fd table is shared, and the child calls raw APIs then exits.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_FILES | libc::SIGCHLD,
            0,
            0,
            0,
            0,
        )
    };
    if pid == 0 {
        arm_allocator_guard();
        if filter.install_raw().is_err() {
            die(126);
        }
        die(0);
    }
    if pid < 0 {
        return Err(failure("cannot create pre-existing test listener"));
    }
    signals.restore()?;
    loop {
        let mut status = 0;
        // SAFETY: wait for our exact direct child, retaining the shared table.
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
        if waited < 0 && errno() == libc::EINTR {
            continue;
        }
        assert_eq!(waited, pid as i32);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        break;
    }
    let current = listeners()?;
    let created: Vec<_> = current.difference(&snapshot).copied().collect();
    assert_eq!(created.len(), 1);
    // SAFETY: child reaped, exclusive parent table ownership and validated listener.
    Ok(unsafe { OwnedFd::from_raw_fd(created[0]) })
}

#[test]
fn explicit_network_backends_with_af_unix() -> Result<()> {
    isolated("explicit_network_backends_with_af_unix", || {
        let _lock = lock_listener_ownership()?;
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").map_err(NonoError::Io)?;
        let port = tcp.local_addr().map_err(NonoError::Io)?.port();
        let directory = tempfile::tempdir().map_err(NonoError::Io)?;
        let socket_path = directory.path().join("denied.sock");
        let _unix = std::os::unix::net::UnixListener::bind(&socket_path).map_err(NonoError::Io)?;
        let caps = capabilities(port, 34568)?.set_network_mode(nono::NetworkMode::AllowAll);
        for policy in [LinuxSandboxPolicy::External, LinuxSandboxPolicy::Landlock] {
            let mut config = config(&caps, true, false);
            config.sandbox_policy = policy;
            let script = format!(
                "import socket\nsocket.create_connection(('127.0.0.1',{port})).close()\nsocket.socket(socket.AF_INET, socket.SOCK_DGRAM).close()\ntry: socket.socket(socket.AF_UNIX).connect({path:?})\nexcept PermissionError: pass\nelse: raise AssertionError('ungranted Unix socket escaped')\n",
                path = socket_path.to_string_lossy()
            );
            let bootstrap = run(
                &config,
                &script,
                landlock::ABI::V3,
                Fault::None,
                None,
                None,
                None,
            )?;
            assert_eq!(
                supervise(&bootstrap, &caps, config.seccomp_policy, port, 34568)?,
                0
            );
        }
        Ok(())
    })
}

#[test]
#[ignore = "requires live cgroup v2 memory delegation; run with --ignored"]
fn live_cgroup_with_combined_notifications() -> Result<()> {
    isolated("live_cgroup_with_combined_notifications", || {
        let _lock = lock_listener_ownership()?;
        let leaf = crate::resource_cgroup::CgroupLeaf::create(&nono::ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
            max_processes: None,
        })?;
        let procs = std::fs::read_link(format!("/proc/self/fd/{}", leaf.procs_raw_fd()))
            .map_err(NonoError::Io)?;
        let path = procs
            .parent()
            .ok_or_else(|| failure("missing cgroup directory"))?;
        let name = path
            .file_name()
            .ok_or_else(|| failure("missing cgroup name"))?
            .to_string_lossy();
        let mut caps = capabilities(34567, 34568)?;
        caps.add_fs(FsCapability::new_file(
            "/proc/self/cgroup",
            AccessMode::Read,
        )?);
        let config = config(&caps, true, true);
        let script = format!("assert '/{name}' in open('/proc/self/cgroup').read()\n");
        let bootstrap = run(
            &config,
            &script,
            landlock::ABI::V3,
            Fault::None,
            None,
            None,
            Some(leaf.procs_raw_fd()),
        )?;
        assert_eq!(
            supervise(&bootstrap, &caps, config.seccomp_policy, 34567, 34568)?,
            0
        );
        assert!(
            std::fs::read_to_string(&procs)
                .map_err(NonoError::Io)?
                .trim()
                .is_empty()
        );
        drop(bootstrap);
        drop(leaf);
        assert!(!path.exists());
        Ok(())
    })
}
