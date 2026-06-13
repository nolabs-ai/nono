//! Linux seccomp-notify supervisor boundary.
//!
//! Threat model:
//! - The child process is sandboxed but untrusted.
//! - All seccomp notifications must be fail-closed on parse/validation errors.
//! - Path opens performed by the supervisor must re-validate policy boundaries.
//! - Security boundary: the supervisor's `open_path_for_access()` + `inject_fd()`
//!   is authoritative. `notif_id_valid()` only proves notification liveness.
//! - Instruction files undergo trust verification with TOCTOU protection via
//!   digest re-check at fd open time.

use super::*;
use crate::trust_intercept::TrustInterceptor;
use nono::{AccessMode, UnixSocketCapability, UnixSocketOp, try_canonicalize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InitialCapability {
    pub(super) path: std::path::PathBuf,
    pub(super) access: AccessMode,
    pub(super) is_file: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitialCapabilityMatch<'a> {
    Sufficient(&'a InitialCapability),
    Insufficient(&'a InitialCapability),
    None,
}

/// Token-bucket rate limiter for supervisor expansion requests.
///
/// Prevents a compromised agent from flooding the terminal with approval prompts.
/// Defaults to 10 requests/second with a burst of 5.
pub(super) struct RateLimiter {
    /// Maximum tokens (burst capacity)
    capacity: u32,
    /// Current available tokens
    tokens: u32,
    /// Tokens added per second
    rate: u32,
    /// Last token refill time
    last_refill: std::time::Instant,
}

impl RateLimiter {
    pub(super) fn new(rate: u32, burst: u32) -> Self {
        Self {
            capacity: burst,
            tokens: burst,
            rate,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    pub(super) fn try_acquire(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Refill tokens based on elapsed time
        let new_tokens = (elapsed.as_millis() as u64)
            .saturating_mul(self.rate as u64)
            .saturating_div(1000);
        if new_tokens > 0 {
            self.tokens = self.capacity.min(
                self.tokens
                    .saturating_add(u32::try_from(new_tokens).unwrap_or(u32::MAX)),
            );
            self.last_refill = now;
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Read the TGID (thread group ID / process ID) of a thread from /proc/<tid>/status.
///
/// `seccomp_data.pid` is the TID of the requesting thread, not the TGID. `/proc/self`
/// is a symlink to `/proc/<tgid>`, so for correct procfs self-resolution we need the TGID.
/// This matters when a grandchild process (e.g. nono→sh→bun) makes an openat syscall:
/// `notif.pid` is bun's TID, not sh's PID, so we must look up bun's TGID to resolve
/// `/proc/self/maps` to `/proc/<bun_tgid>/maps` instead of `/proc/<sh_pid>/maps`.
///
/// Runs in the unsandboxed supervisor context. Falls back to `tid` if the status file
/// cannot be read (process already exited; the subsequent TOCTOU check will reject it).
fn read_tgid(tid: u32) -> u32 {
    std::fs::read_to_string(format!("/proc/{}/status", tid))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Tgid:\t"))
                .and_then(|l| l["Tgid:\t".len()..].trim().parse::<u32>().ok())
        })
        .unwrap_or(tid)
}

/// Handle a seccomp notification on Linux.
///
/// Flow:
/// 1. Receive notification (blocking recv from kernel)
/// 2. Read path from child's /proc/PID/mem
/// 3. TOCTOU check: verify notification still valid
/// 4. Check protected nono state roots -> deny (BEFORE initial-set fast-path)
/// 5. Fast-path: if path is in initial set, open + inject fd immediately
/// 6. Rate limit check -> deny if exceeded
/// 7. Trust verification for instruction files (if trust_interceptor present)
/// 8. Delegate to approval backend
/// 9. Second TOCTOU check before inject/deny
/// 10. If approved: open path + inject fd (with TOCTOU digest re-check for
///     instruction files). If denied: deny notification.
///
/// TOCTOU boundary note:
/// - The child controls userspace pointers until syscall completion.
/// - We treat notification ID validation as a liveness guard only.
/// - Authorization is bound to the file descriptor opened by the supervisor.
/// - Instruction files undergo additional TOCTOU protection: the verified
///   digest is re-checked against the opened fd to detect races between
///   trust verification and file open.
///
/// The initial_caps parameter contains the static capabilities applied to the
/// sandbox, allowing the supervisor to distinguish "path not granted" from
/// "path granted, but only with a narrower access mode".
pub(super) fn handle_seccomp_notification(
    notify_fd: std::os::fd::RawFd,
    child: Pid,
    config: &SupervisorConfig<'_>,
    initial_caps: &[InitialCapability],
    rate_limiter: &mut RateLimiter,
    denials: &mut Vec<DenialRecord>,
    mut trust_interceptor: Option<&mut TrustInterceptor>,
) -> Result<()> {
    use nono::sandbox::{
        SYS_OPENAT, SYS_OPENAT2, classify_access_from_flags, continue_notif, deny_notif, inject_fd,
        notif_id_valid, read_notif_path, read_open_how, recv_notif, resolve_notif_path,
        respond_notif_errno, validate_openat2_size,
    };

    // 1. Receive the notification
    let notif = recv_notif(notify_fd)?;

    // 2. Read the path from the child's memory (args[1] = pathname for openat/openat2)
    //    Then resolve dirfd-relative paths using /proc/PID/fd/DIRFD or /proc/PID/cwd.
    let path = match read_notif_path(notif.pid, notif.data.args[1]) {
        Ok(raw_path) => {
            // args[0] is dirfd for both openat and openat2
            match resolve_notif_path(notif.pid, notif.data.args[0], &raw_path) {
                Ok(resolved) => resolved,
                Err(e) => {
                    debug!(
                        "Failed to resolve dirfd-relative path '{}': {}",
                        raw_path.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                    return Ok(());
                }
            }
        }
        Err(e) => {
            debug!("Failed to read path from seccomp notification: {}", e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // 3. First TOCTOU check: verify notification still valid
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Seccomp notification expired (first TOCTOU check)");
        return Ok(());
    }

    // Determine access mode from open flags. The two syscalls have different layouts:
    //   - openat(dirfd, pathname, flags, mode): args[2] is the flags integer
    //   - openat2(dirfd, pathname, how, size): args[2] is a pointer to struct open_how
    let access = match notif.data.nr {
        SYS_OPENAT => {
            // openat: args[2] is the flags integer directly
            classify_access_from_flags(notif.data.args[2] as i32)
        }
        SYS_OPENAT2 => {
            // openat2: args[2] is a pointer to struct open_how, args[3] is the size
            let how_size = notif.data.args[3] as usize;
            if !validate_openat2_size(how_size) {
                debug!(
                    "openat2 size {} outside accepted range, denying malformed request",
                    how_size
                );
                let _ = deny_notif(notify_fd, notif.id);
                return Ok(());
            }

            match read_open_how(notif.pid, notif.data.args[2]) {
                Ok(open_how) => classify_access_from_flags(open_how.flags as i32),
                Err(e) => {
                    // Fail closed: deny when flags cannot be determined
                    warn!("Failed to read open_how struct for openat2, denying: {}", e);
                    let _ = deny_notif(notify_fd, notif.id);
                    return Ok(());
                }
            }
        }
        other => {
            // Unexpected syscall (shouldn't happen with our BPF filter)
            warn!("Unexpected syscall {} in seccomp handler, denying", other);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // Use the requesting process's TGID (not TID) as process_pid so that /proc/self
    // resolves to /proc/<tgid>/... for grandchild processes (e.g. nono→sh→bun).
    // notif.pid is the TID; for single-threaded processes TID==TGID, but for
    // multithreaded or grandchild processes we need the actual process leader PID.
    let child_pid = child.as_raw() as u32;
    let notifying_tgid = if notif.pid == child_pid {
        child_pid
    } else {
        read_tgid(notif.pid)
    };
    let procfs_context = ProcfsAccessContext::new(notifying_tgid, Some(notif.pid));
    let resolved_path = match resolve_procfs_path_for_child(&path, Some(procfs_context)) {
        Ok(resolved) => resolved,
        Err(e) => {
            debug!("Failed to resolve procfs path '{}': {}", path.display(), e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };
    let canonicalized = try_canonicalize(&resolved_path);

    // For the initial capability match, map a grandchild's /proc/<tgid> path back to the
    // direct child's /proc/<child_pid>, because initial_caps are built from the direct
    // child's /proc/self remapping (remap_procfs_self_references uses child.as_raw()).
    // Any descendant process should benefit from the same proc-self read policy.
    //
    // Security note: this substitution only affects the policy LOOKUP KEY. The actual file
    // opened by open_path_for_access continues to use `procfs_context` with notifying_tgid,
    // so the correct /proc/<notifying_tgid>/... file is opened. validate_procfs_access also
    // uses notifying_tgid as allowed_pid, blocking cross-process procfs reads.
    let cap_check_path: std::borrow::Cow<std::path::Path> = if notifying_tgid != child_pid {
        let notifying_prefix = format!("/proc/{}", notifying_tgid);
        if let Ok(rel) = canonicalized.strip_prefix(&notifying_prefix) {
            let mut p = std::path::PathBuf::from(format!("/proc/{}", child_pid));
            p.push(rel);
            std::borrow::Cow::Owned(p)
        } else {
            std::borrow::Cow::Borrowed(canonicalized.as_path())
        }
    } else {
        std::borrow::Cow::Borrowed(canonicalized.as_path())
    };

    // 4. Check protected roots BEFORE initial-set fast-path.
    let protected_root = crate::protected_paths::overlapping_protected_root(
        &canonicalized,
        false,
        config.protected_roots,
    )
    .or_else(|| {
        crate::protected_paths::overlapping_protected_root(
            &resolved_path,
            false,
            config.protected_roots,
        )
    });
    if let Some(protected_root) = protected_root {
        debug!(
            "Seccomp: path {} blocked by protected root {}",
            canonicalized.display(),
            protected_root.display()
        );
        record_denial(
            denials,
            DenialRecord {
                path: canonicalized.clone(),
                access,
                reason: DenialReason::PolicyBlocked,
            },
        );
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // 5. Fast-path: if the path is covered by the initial capability set and
    // the requested access mode is already granted, proceed immediately. If the
    // path matches but only with narrower access, record the denial here so the
    // footer can explain the near-miss precisely.
    match match_initial_capability(&cap_check_path, access, initial_caps) {
        InitialCapabilityMatch::Insufficient(cap) => {
            debug!(
                "Seccomp: path {} matched initial capability {} but {} access was requested",
                canonicalized.display(),
                cap.path.display(),
                access,
            );
            record_denial(
                denials,
                DenialRecord {
                    path: canonicalized.clone(),
                    access,
                    reason: DenialReason::InsufficientAccess,
                },
            );
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
        InitialCapabilityMatch::Sufficient(_) => {
            if canonicalized.starts_with("/proc") {
                match open_path_for_access(
                    &path,
                    &access,
                    config.protected_roots,
                    None,
                    Some(procfs_context),
                ) {
                    Ok(file) => {
                        if notif_id_valid(notify_fd, notif.id)?
                            && let Err(e) = inject_fd(notify_fd, notif.id, file.as_raw_fd())
                        {
                            debug!(
                                "inject_fd failed for initial-set proc path {}: {}",
                                path.display(),
                                e
                            );
                            let _ = deny_notif(notify_fd, notif.id);
                        }
                    }
                    Err(e) => {
                        debug!(
                            "Failed to open initial-set proc path {}: {}",
                            path.display(),
                            e
                        );
                        if e.is_policy_blocked() {
                            record_denial(
                                denials,
                                DenialRecord {
                                    path: canonicalized.clone(),
                                    access,
                                    reason: DenialReason::PolicyBlocked,
                                },
                            );
                            let _ = deny_notif(notify_fd, notif.id);
                        } else {
                            let _ = respond_notif_errno(notify_fd, notif.id, e.errno());
                        }
                    }
                }
            } else if notif_id_valid(notify_fd, notif.id)?
                && let Err(e) = continue_notif(notify_fd, notif.id)
            {
                debug!(
                    "continue_notif failed for initial-set path {}: {}",
                    path.display(),
                    e
                );
                let _ = deny_notif(notify_fd, notif.id);
            }
            return Ok(());
        }
        InitialCapabilityMatch::None => {}
    }

    // Preserve native ENOENT/ENOTDIR behavior for nonexistent paths. Runtimes
    // frequently probe optional locations (e.g. Bun's /$bunfs assets) and
    // expect a normal "not found" result rather than a policy denial. This is
    // safe because Landlock will still block any path that appears after the
    // check but remains outside the initial allow-list.
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            if notif_id_valid(notify_fd, notif.id)?
                && let Err(send_err) = continue_notif(notify_fd, notif.id)
            {
                debug!(
                    "continue_notif failed for missing path {}: {}",
                    path.display(),
                    send_err
                );
                let _ = deny_notif(notify_fd, notif.id);
            }
            return Ok(());
        }
        Err(_) => {}
    }

    // 6. Rate limit check
    if !rate_limiter.try_acquire() {
        debug!("Rate limited seccomp notification for {}", path.display());
        record_denial(
            denials,
            DenialRecord {
                path: path.clone(),
                access,
                reason: DenialReason::RateLimited,
            },
        );
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // 7. Trust verification for instruction files (TOCTOU protection)
    // If the path is an instruction file, verify it and stash the digest
    // for re-verification at open time. Failed verification results in early denial.
    let verified_digest: Option<String> = if let Some(trust_result) = trust_interceptor
        .as_mut()
        .and_then(|ti| ti.check_path(&path))
    {
        match trust_result {
            Ok(verified) => {
                debug!(
                    "Seccomp: instruction file {} verified (publisher: {})",
                    path.display(),
                    verified.publisher,
                );
                Some(verified.digest)
            }
            Err(reason) => {
                // Instruction file failed trust verification — auto-deny
                debug!(
                    "Seccomp: instruction file {} failed trust verification: {}",
                    path.display(),
                    reason
                );
                record_denial(
                    denials,
                    DenialRecord {
                        path: path.clone(),
                        access,
                        reason: DenialReason::PolicyBlocked,
                    },
                );
                let _ = deny_notif(notify_fd, notif.id);
                return Ok(());
            }
        }
    } else {
        None
    };

    // 8. Delegate to approval backend (for both instruction and non-instruction files)
    let request = nono::supervisor::CapabilityRequest {
        request_id: format!("seccomp-{}", unique_request_id()),
        path: path.clone(),
        access,
        reason: Some("Sandbox intercepted file operation (seccomp-notify)".to_string()),
        child_pid: child.as_raw() as u32,
        session_id: config.session_id.to_string(),
    };

    let decision = match config.approval_backend.request_capability(&request) {
        Ok(d) => {
            if d.is_denied() {
                record_denial(
                    denials,
                    DenialRecord {
                        path: path.clone(),
                        access,
                        reason: DenialReason::UserDenied,
                    },
                );
            }
            d
        }
        Err(e) => {
            warn!("Approval backend error for seccomp notification: {}", e);
            record_denial(
                denials,
                DenialRecord {
                    path: path.clone(),
                    access,
                    reason: DenialReason::BackendError,
                },
            );
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // 9. Second TOCTOU check before acting on the decision
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Seccomp notification expired (second TOCTOU check)");
        return Ok(());
    }

    // 10. Act on the decision
    // Pass verified_digest to enable TOCTOU re-verification for instruction files
    if decision.is_granted() {
        match open_path_for_access(
            &path,
            &access,
            config.protected_roots,
            verified_digest.as_deref(),
            Some(procfs_context),
        ) {
            Ok(file) => {
                if let Err(e) = inject_fd(notify_fd, notif.id, file.as_raw_fd()) {
                    debug!(
                        "inject_fd failed for approved path {}: {}",
                        canonicalized.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
            }
            Err(e) => {
                warn!(
                    "Failed to open approved path {}: {}",
                    canonicalized.display(),
                    e
                );
                if e.is_policy_blocked() {
                    let _ = deny_notif(notify_fd, notif.id);
                } else {
                    let _ = respond_notif_errno(notify_fd, notif.id, e.errno());
                }
            }
        }
    } else {
        let _ = deny_notif(notify_fd, notif.id);
    }

    Ok(())
}

/// Decision produced by [`decide_network_notification`].
///
/// Split out as an explicit type so the (testable) policy logic is decoupled
/// from the (untestable) seccomp-notify response plumbing. Callers translate
/// `Allow` to `continue_notif(…)` and `Deny` to `respond_notif_errno(…, EACCES)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkDecision {
    /// Allow the operation.
    Allow,
    /// Fail the syscall with `EACCES`.
    Deny,
}

/// Pure policy function: given a trapped syscall and the sockaddr the child
/// passed in, decide whether the supervisor should allow or deny it.
///
/// Factored out of [`handle_network_notification`] so it can be unit-tested
/// without a live seccomp-notify fd.
///
/// Policy:
///
/// 1. **Pathname `AF_UNIX` is allowlist-mediated.** Filesystem-backed Unix
///    sockets like `/tmp/test.sock` are IPC bound to a real path, so the
///    supervisor canonicalizes that path and checks it against explicit
///    [`UnixSocketCapability`] grants.
///
///    **Abstract and unnamed `AF_UNIX` are denied.** The abstract namespace
///    (`sun_path[0] == '\0'`) lives outside the filesystem, so pathname
///    capabilities cannot mediate it. Unnamed sockets (addrlen == 2) have
///    no path to check.
///
/// 2. For `AF_INET`/`AF_INET6`:
///    - `connect()` is allowed only to `127.0.0.1:proxy_port` (the nono proxy).
///    - `bind()` is allowed only on ports in `proxy_bind_ports`.
///    - Everything else is denied.
pub(super) fn decide_network_notification(
    child_pid: u32,
    syscall: i32,
    sockaddr: &nono::sandbox::SockaddrInfo,
    config: &SupervisorConfig<'_>,
) -> NetworkDecision {
    use nono::sandbox::{SYS_BIND, SYS_CONNECT, UnixSocketKind};

    // AF_UNIX: allow only filesystem-backed (pathname) sockets that match an
    // explicit socket capability. Abstract/unnamed sockets bypass pathname
    // mediation, so deny them.
    if sockaddr.family == libc::AF_UNIX as u16 {
        match sockaddr.unix_kind {
            Some(UnixSocketKind::Pathname) => {
                return decide_af_unix_pathname(child_pid, syscall, sockaddr, config);
            }
            Some(UnixSocketKind::Abstract) => {
                debug!(
                    "Proxy seccomp: denying AF_UNIX abstract-namespace syscall (nr={}); \
                     not mediated by pathname socket capabilities",
                    syscall
                );
                return NetworkDecision::Deny;
            }
            Some(UnixSocketKind::Unnamed) | None => {
                debug!(
                    "Proxy seccomp: denying AF_UNIX unnamed/unclassified syscall (nr={})",
                    syscall
                );
                return NetworkDecision::Deny;
            }
        }
    }

    if matches!(
        config.linux_network_notify_mode,
        LinuxNetworkNotifyMode::AfUnixOnly
    ) {
        debug!(
            "AF_UNIX-only seccomp mediation: allowing non-AF_UNIX syscall family={} nr={}",
            sockaddr.family, syscall
        );
        return NetworkDecision::Allow;
    }

    match syscall {
        SYS_CONNECT => {
            // Allow connect only to loopback + proxy port
            if sockaddr.is_loopback && sockaddr.port == config.proxy_port {
                debug!(
                    "Proxy seccomp: allowing connect to loopback:{}",
                    sockaddr.port
                );
                NetworkDecision::Allow
            } else {
                debug!(
                    "Proxy seccomp: denying connect to family={} port={} loopback={}",
                    sockaddr.family, sockaddr.port, sockaddr.is_loopback
                );
                NetworkDecision::Deny
            }
        }
        SYS_BIND => {
            // Allow bind only on configured bind ports
            if config.proxy_bind_ports.contains(&sockaddr.port) {
                debug!("Proxy seccomp: allowing bind on port {}", sockaddr.port);
                NetworkDecision::Allow
            } else {
                debug!(
                    "Proxy seccomp: denying bind on port {} (allowed: {:?})",
                    sockaddr.port, config.proxy_bind_ports
                );
                NetworkDecision::Deny
            }
        }
        other => {
            warn!(
                "Unexpected syscall {} in proxy seccomp handler, denying",
                other
            );
            NetworkDecision::Deny
        }
    }
}

fn decide_af_unix_pathname(
    child_pid: u32,
    syscall: i32,
    sockaddr: &nono::sandbox::SockaddrInfo,
    config: &SupervisorConfig<'_>,
) -> NetworkDecision {
    let Some(path) = sockaddr.unix_path.as_deref() else {
        debug!(
            "Proxy seccomp: denying AF_UNIX pathname syscall (nr={}) without parsed path",
            syscall
        );
        return NetworkDecision::Deny;
    };

    let Some(op) = unix_socket_op_for_syscall(syscall) else {
        warn!(
            "Unexpected AF_UNIX syscall {} in proxy seccomp handler, denying",
            syscall
        );
        return NetworkDecision::Deny;
    };

    let resolved_path = match resolve_af_unix_sockaddr_path(child_pid, path) {
        Ok(path) => path,
        Err(err) => {
            debug!(
                "Proxy seccomp: denying AF_UNIX {} on {}: child-relative resolution failed: {}",
                op,
                path.display(),
                err
            );
            return NetworkDecision::Deny;
        }
    };

    let canonical = match op {
        UnixSocketOp::Connect => match resolved_path.canonicalize() {
            Ok(path) => path,
            Err(err) => {
                debug!(
                    "Proxy seccomp: denying AF_UNIX connect to {}: canonicalize failed: {}",
                    resolved_path.display(),
                    err
                );
                return NetworkDecision::Deny;
            }
        },
        UnixSocketOp::Bind => match canonicalize_unix_socket_bind_path(&resolved_path) {
            Ok(path) => path,
            Err(err) => {
                debug!(
                    "Proxy seccomp: denying AF_UNIX bind to {}: canonicalize failed: {}",
                    resolved_path.display(),
                    err
                );
                return NetworkDecision::Deny;
            }
        },
    };

    if unix_socket_allowlist_allows(config.unix_socket_allowlist, canonical.as_path(), op) {
        debug!(
            "Proxy seccomp: allowing AF_UNIX {} on {}",
            op,
            canonical.display()
        );
        NetworkDecision::Allow
    } else {
        debug!(
            "Proxy seccomp: denying AF_UNIX {} on {}: no matching capability",
            op,
            canonical.display()
        );
        NetworkDecision::Deny
    }
}

fn resolve_af_unix_sockaddr_path(
    child_pid: u32,
    path: &std::path::Path,
) -> nono::Result<std::path::PathBuf> {
    use nono::sandbox::resolve_notif_path;

    let at_fdcwd = libc::AT_FDCWD as i64 as u64;
    resolve_notif_path(child_pid, at_fdcwd, path)
}

fn unix_socket_op_for_syscall(syscall: i32) -> Option<UnixSocketOp> {
    use nono::sandbox::{SYS_BIND, SYS_CONNECT};

    match syscall {
        SYS_CONNECT => Some(UnixSocketOp::Connect),
        SYS_BIND => Some(UnixSocketOp::Bind),
        _ => None,
    }
}

fn unix_socket_allowlist_allows(
    allowlist: &[UnixSocketCapability],
    path: &std::path::Path,
    op: UnixSocketOp,
) -> bool {
    allowlist.iter().any(|cap| {
        cap.covers(path)
            && match op {
                UnixSocketOp::Connect => true,
                UnixSocketOp::Bind => cap.mode.permits_bind(),
            }
    })
}

fn canonicalize_unix_socket_bind_path(
    path: &std::path::Path,
) -> std::io::Result<std::path::PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "socket path has no parent directory",
                )
            })?;
            let file_name = path.file_name().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "socket path has no final component",
                )
            })?;
            let resolved_parent = parent.canonicalize()?;
            if !resolved_parent.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "socket parent is not a directory",
                ));
            }
            Ok(resolved_parent.join(file_name))
        }
        Err(err) => Err(err),
    }
}

/// Handle a seccomp notification for connect() or bind() syscalls.
///
/// This is the proxy-only fallback for kernels without Landlock AccessNet.
/// The BPF filter routes connect/bind to USER_NOTIF; this function reads
/// the sockaddr from the child's memory and delegates the allow/deny
/// decision to [`decide_network_notification`].
///
/// Denials return `EACCES` directly. Approvals currently use
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, which preserves platform compatibility
/// but carries the documented userspace-pointer TOCTOU limitation described
/// by `read_notif_sockaddr`.
pub(super) fn handle_network_notification(
    notify_fd: std::os::fd::RawFd,
    config: &SupervisorConfig<'_>,
    rate_limiter: &mut RateLimiter,
    denials: &mut Vec<DenialRecord>,
    ipc_denials: &mut Vec<nono::diagnostic::IpcDenialRecord>,
) -> nono::error::Result<()> {
    use nono::sandbox::{
        continue_notif, deny_notif, notif_id_valid, read_notif_sockaddr, recv_notif,
        respond_notif_errno,
    };

    let notif = recv_notif(notify_fd)?;

    // Rate limit to prevent flooding
    if !rate_limiter.try_acquire() {
        debug!("Rate limited network seccomp notification, denying");
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // Read sockaddr from child's memory: args[1] = sockaddr*, args[2] = addrlen
    let sockaddr = match read_notif_sockaddr(notif.pid, notif.data.args[1], notif.data.args[2]) {
        Ok(info) => info,
        Err(e) => {
            debug!("Failed to read sockaddr from seccomp notification: {}", e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // TOCTOU check
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Network seccomp notification expired (TOCTOU check)");
        return Ok(());
    }

    match decide_network_notification(notif.pid, notif.data.nr, &sockaddr, config) {
        NetworkDecision::Allow => {
            if let Err(e) = continue_notif(notify_fd, notif.id) {
                debug!("continue_notif failed for network notification: {}", e);
                // Must respond to avoid leaving the child blocked. Propagate if
                // deny also fails — the notification is orphaned.
                return deny_notif(notify_fd, notif.id);
            }
        }
        NetworkDecision::Deny => {
            record_af_unix_ipc_denial(&sockaddr, notif.pid, notif.data.nr, denials, ipc_denials);
            respond_notif_errno(notify_fd, notif.id, libc::EACCES)?;
            if let Err(err) = record_network_audit_denial(config, &sockaddr, notif.data.nr) {
                warn!("Failed to record network denial audit event: {}", err);
            }
        }
    }

    Ok(())
}

fn record_af_unix_ipc_denial(
    sockaddr: &nono::sandbox::SockaddrInfo,
    child_pid: u32,
    syscall: i32,
    denials: &mut Vec<DenialRecord>,
    ipc_denials: &mut Vec<nono::diagnostic::IpcDenialRecord>,
) {
    if sockaddr.family != libc::AF_UNIX as u16 {
        return;
    }

    let op = unix_socket_op_for_syscall(syscall);
    let operation = op
        .map(|op| op.to_string())
        .unwrap_or_else(|| format!("syscall {syscall}"));
    let (target, reason, suggested_flag, path_record) = ipc_denial_details(sockaddr, child_pid, op);

    ipc_denials.push(nono::diagnostic::IpcDenialRecord {
        target,
        operation,
        reason,
        suggested_flag,
    });

    let Some((display_path, op)) = path_record else {
        return;
    };
    let access = match op {
        UnixSocketOp::Connect => AccessMode::Read,
        UnixSocketOp::Bind => AccessMode::ReadWrite,
    };

    record_denial(
        denials,
        DenialRecord {
            path: display_path,
            access,
            reason: DenialReason::UnixSocketDenied,
        },
    );
}

type PathIpcDenial = Option<(std::path::PathBuf, UnixSocketOp)>;

fn ipc_denial_details(
    sockaddr: &nono::sandbox::SockaddrInfo,
    child_pid: u32,
    op: Option<UnixSocketOp>,
) -> (String, String, Option<String>, PathIpcDenial) {
    match sockaddr.unix_kind {
        Some(nono::sandbox::UnixSocketKind::Pathname) => {
            let Some(path) = sockaddr.unix_path.as_deref() else {
                return (
                    "unix:<unparsed-pathname>".to_string(),
                    "pathname not parsed".to_string(),
                    None,
                    None,
                );
            };
            let Some(op) = op else {
                return (
                    path.display().to_string(),
                    "unexpected syscall".to_string(),
                    None,
                    None,
                );
            };
            let resolved = resolve_af_unix_sockaddr_path(child_pid, path)
                .unwrap_or_else(|_| path.to_path_buf());
            let canonical = match op {
                UnixSocketOp::Connect => resolved.canonicalize(),
                UnixSocketOp::Bind => canonicalize_unix_socket_bind_path(&resolved),
            };
            let Ok(display_path) = canonical else {
                return (
                    resolved.display().to_string(),
                    "no matching unix_socket capability; target could not be canonicalized"
                        .to_string(),
                    None,
                    None,
                );
            };
            let flag = match op {
                UnixSocketOp::Connect => "--allow-unix-socket",
                UnixSocketOp::Bind => "--allow-unix-socket-bind",
            };
            (
                display_path.display().to_string(),
                "no matching unix_socket capability".to_string(),
                Some(format!("{flag} {}", display_path.display())),
                Some((display_path, op)),
            )
        }
        Some(nono::sandbox::UnixSocketKind::Abstract) => (
            "unix:<abstract>".to_string(),
            "abstract namespace is not covered by pathname capabilities".to_string(),
            None,
            None,
        ),
        Some(nono::sandbox::UnixSocketKind::Unnamed) | None => (
            "unix:<unnamed>".to_string(),
            "no pathname to authorize".to_string(),
            None,
            None,
        ),
    }
}

fn record_network_audit_denial(
    config: &SupervisorConfig<'_>,
    sockaddr: &nono::sandbox::SockaddrInfo,
    syscall: i32,
) -> nono::Result<()> {
    let target = network_audit_target(sockaddr);
    let reason = network_audit_denial_reason(sockaddr, syscall);
    let event = nono::undo::NetworkAuditEvent {
        timestamp_unix_ms: current_unix_millis(),
        mode: nono::undo::NetworkAuditMode::Connect,
        decision: nono::undo::NetworkAuditDecision::Deny,
        route_id: None,
        auth_mechanism: None,
        auth_outcome: None,
        managed_credential_active: None,
        injection_mode: None,
        denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
        target,
        port: if sockaddr.port == 0 {
            None
        } else {
            Some(sockaddr.port)
        },
        method: None,
        path: None,
        status: None,
        reason: Some(reason),
    };

    if let Some(events_mutex) = config.network_audit_events {
        let mut events = events_mutex
            .lock()
            .map_err(|_| NonoError::Snapshot("Network audit event lock poisoned".to_string()))?;
        events.push(event.clone());
    }

    if let Some(recorder_mutex) = config.audit_recorder {
        let mut recorder = recorder_mutex
            .lock()
            .map_err(|_| NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
        recorder.record_network_event(event)?;
    }

    Ok(())
}

fn network_audit_target(sockaddr: &nono::sandbox::SockaddrInfo) -> String {
    if sockaddr.family == libc::AF_UNIX as u16 {
        return match sockaddr.unix_kind {
            Some(nono::sandbox::UnixSocketKind::Pathname) => sockaddr
                .unix_path
                .as_ref()
                .map(|path| format!("unix:{}", path.display()))
                .unwrap_or_else(|| "unix:<unparsed>".to_string()),
            Some(nono::sandbox::UnixSocketKind::Abstract) => "unix:<abstract>".to_string(),
            Some(nono::sandbox::UnixSocketKind::Unnamed) | None => "unix:<unnamed>".to_string(),
        };
    }

    format!(
        "family={} loopback={}",
        sockaddr.family, sockaddr.is_loopback
    )
}

fn network_audit_denial_reason(sockaddr: &nono::sandbox::SockaddrInfo, syscall: i32) -> String {
    if sockaddr.family == libc::AF_UNIX as u16 {
        let op = unix_socket_op_for_syscall(syscall)
            .map(|op| op.to_string())
            .unwrap_or_else(|| format!("syscall {syscall}"));
        return match sockaddr.unix_kind {
            Some(nono::sandbox::UnixSocketKind::Pathname) => {
                format!("pathname AF_UNIX {op} denied: no matching unix_socket capability")
            }
            Some(nono::sandbox::UnixSocketKind::Abstract) => {
                format!("abstract AF_UNIX {op} denied: not covered by pathname capabilities")
            }
            Some(nono::sandbox::UnixSocketKind::Unnamed) | None => {
                format!("unnamed AF_UNIX {op} denied: no pathname to authorize")
            }
        };
    }

    format!(
        "network syscall {syscall} denied for family={} port={}",
        sockaddr.family, sockaddr.port
    )
}

fn current_unix_millis() -> u64 {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let wall_clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);

    let mut previous = LAST.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = wall_clock.max(previous.saturating_add(1));
        match LAST.compare_exchange_weak(
            previous,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(observed) => previous = observed,
        }
    }
}

/// Check if a path matches any capability in the initial set.
///
/// Prefers the most specific capability. If the path is covered but the
/// requested access mode is not granted, returns
/// `InitialCapabilityMatch::Insufficient`.
fn match_initial_capability<'a>(
    path: &std::path::Path,
    requested: AccessMode,
    initial_caps: &'a [InitialCapability],
) -> InitialCapabilityMatch<'a> {
    let mut best_covering: Option<&'a InitialCapability> = None;
    let mut best_sufficient: Option<&'a InitialCapability> = None;
    let mut best_covering_score = 0usize;
    let mut best_sufficient_score = 0usize;

    for cap in initial_caps {
        let covers = if cap.is_file {
            path == cap.path
        } else {
            path.starts_with(&cap.path)
        };

        if !covers {
            continue;
        }

        let score = cap.path.as_os_str().len();
        if score >= best_covering_score {
            best_covering = Some(cap);
            best_covering_score = score;
        }

        if cap.access.contains(requested) && score >= best_sufficient_score {
            best_sufficient = Some(cap);
            best_sufficient_score = score;
        }
    }

    if let Some(cap) = best_sufficient {
        InitialCapabilityMatch::Sufficient(cap)
    } else if let Some(cap) = best_covering {
        InitialCapabilityMatch::Insufficient(cap)
    } else {
        InitialCapabilityMatch::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_rate_limiter_allows_burst() {
        let mut limiter = RateLimiter::new(10, 5);
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new(10, 3);
        for _ in 0..3 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());
        limiter.last_refill -= std::time::Duration::from_millis(500);
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_file_capability_exact_match_only() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/config.json"),
            access: AccessMode::Read,
            is_file: true,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/config.json"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/config.json/subpath"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/other.json"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_directory_capability_allows_subpaths() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/project"),
            access: AccessMode::Read,
            is_file: false,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/src/main.rs"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/home/user/other"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_file_capability_does_not_authorize_fake_subpath() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/foo/bar"),
            access: AccessMode::Read,
            is_file: true,
        }];

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/foo/bar"), AccessMode::Read, &caps),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(&PathBuf::from("/foo/bar/subpath"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));
        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/foo/bar/deep/nested/path"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_mixed_file_and_directory_capabilities() {
        let caps = vec![
            InitialCapability {
                path: PathBuf::from("/etc/passwd"),
                access: AccessMode::Read,
                is_file: true,
            },
            InitialCapability {
                path: PathBuf::from("/home/user/project"),
                access: AccessMode::Read,
                is_file: false,
            },
        ];

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/etc/passwd"), AccessMode::Read, &caps),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(&PathBuf::from("/etc/passwd/fake"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/src/lib.rs"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));
    }

    #[test]
    fn test_directory_capability_reports_insufficient_access() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/project"),
            access: AccessMode::Read,
            is_file: false,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/output.txt"),
                AccessMode::Write,
                &caps
            ),
            InitialCapabilityMatch::Insufficient(_)
        ));
    }

    // decide_network_notification tests
    //
    // These exercise the proxy-only seccomp fallback path that runs on
    // Landlock < V4 kernels. The key invariant: pathname `AF_UNIX` must be
    // checked against the explicit Unix-socket allowlist instead of being
    // decided by TCP proxy ports.

    mod network_decision {
        use super::super::{
            LinuxNetworkNotifyMode, NetworkDecision, SupervisorConfig, decide_network_notification,
        };
        use nix::libc;
        use nono::sandbox::{SYS_BIND, SYS_CONNECT, SockaddrInfo, UnixSocketKind};
        use nono::supervisor::{ApprovalDecision, CapabilityRequest};
        use nono::{ApprovalBackend, UnixSocketCapability, UnixSocketMode};
        use std::os::unix::net::UnixListener;
        use std::path::{Path, PathBuf};

        struct DenyAllBackend;
        impl ApprovalBackend for DenyAllBackend {
            fn request_capability(
                &self,
                _req: &CapabilityRequest,
            ) -> nono::Result<ApprovalDecision> {
                Ok(ApprovalDecision::Denied {
                    reason: "test".to_string(),
                })
            }
            fn backend_name(&self) -> &str {
                "deny-all-test"
            }
        }

        fn make_config<'a>(
            backend: &'a DenyAllBackend,
            proxy_port: u16,
            proxy_bind_ports: Vec<u16>,
            unix_socket_allowlist: &'a [UnixSocketCapability],
        ) -> SupervisorConfig<'a> {
            static REDACTION_POLICY: std::sync::LazyLock<nono::ScrubPolicy> =
                std::sync::LazyLock::new(nono::ScrubPolicy::secure_default);
            SupervisorConfig {
                protected_roots: &[],
                approval_backend: backend,
                session_id: "test-net-decision",
                attach_initial_client: false,
                detach_sequence: None,
                open_url_origins: &[],
                open_url_allow_localhost: false,
                audit_recorder: None,
                network_audit_events: None,
                redaction_policy: &REDACTION_POLICY,
                allow_launch_services_active: false,
                proxy_port,
                proxy_bind_ports,
                unix_socket_allowlist,
                linux_network_notify_mode: LinuxNetworkNotifyMode::ProxyOnly,
            }
        }

        fn unix_pathname(path: &Path) -> SockaddrInfo {
            // Matches what read_notif_sockaddr() produces for a
            // filesystem-backed AF_UNIX socket (e.g. /tmp/test.sock).
            SockaddrInfo {
                family: libc::AF_UNIX as u16,
                port: 0,
                is_loopback: true,
                unix_kind: Some(UnixSocketKind::Pathname),
                unix_path: Some(path.to_path_buf()),
            }
        }

        fn unix_abstract() -> SockaddrInfo {
            SockaddrInfo {
                family: libc::AF_UNIX as u16,
                port: 0,
                is_loopback: true,
                unix_kind: Some(UnixSocketKind::Abstract),
                unix_path: None,
            }
        }

        fn unix_unnamed() -> SockaddrInfo {
            SockaddrInfo {
                family: libc::AF_UNIX as u16,
                port: 0,
                is_loopback: true,
                unix_kind: Some(UnixSocketKind::Unnamed),
                unix_path: None,
            }
        }

        fn inet_loopback(port: u16) -> SockaddrInfo {
            SockaddrInfo {
                family: libc::AF_INET as u16,
                port,
                is_loopback: true,
                unix_kind: None,
                unix_path: None,
            }
        }

        fn inet_external(port: u16) -> SockaddrInfo {
            SockaddrInfo {
                family: libc::AF_INET as u16,
                port,
                is_loopback: false,
                unix_kind: None,
                unix_path: None,
            }
        }

        fn socket_path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
            dir.path().join(name)
        }

        fn test_pid() -> u32 {
            std::process::id()
        }

        fn make_af_unix_only_config<'a>(
            backend: &'a DenyAllBackend,
            unix_socket_allowlist: &'a [UnixSocketCapability],
        ) -> SupervisorConfig<'a> {
            let mut config = make_config(backend, 0, Vec::new(), unix_socket_allowlist);
            config.linux_network_notify_mode = LinuxNetworkNotifyMode::AfUnixOnly;
            config
        }

        /// Pathname `bind(AF_UNIX, "/tmp/…")` is mediated by explicit
        /// Unix-socket grants, not TCP bind ports.
        #[test]
        fn af_unix_pathname_bind_is_allowed_by_connect_bind_grant() {
            let backend = DenyAllBackend;
            let dir = tempfile::tempdir().expect("tempdir");
            let path = socket_path(&dir, "test.sock");
            let allowlist = vec![
                UnixSocketCapability::new_file(&path, UnixSocketMode::ConnectBind)
                    .expect("socket grant"),
            ];
            let config = make_config(&backend, 0, Vec::new(), &allowlist);
            assert_eq!(
                decide_network_notification(test_pid(), SYS_BIND, &unix_pathname(&path), &config),
                NetworkDecision::Allow,
                "pathname AF_UNIX bind must be allowed when a connect+bind grant covers it"
            );
        }

        /// Pathname `connect(AF_UNIX, "/tmp/…")` is allowed only when the
        /// canonical socket path matches the explicit allowlist.
        #[test]
        fn af_unix_pathname_connect_is_allowed_by_grant() {
            let backend = DenyAllBackend;
            let dir = tempfile::tempdir().expect("tempdir");
            let path = socket_path(&dir, "test.sock");
            let _listener = UnixListener::bind(&path).expect("bind unix listener");
            let allowlist = vec![
                UnixSocketCapability::new_file(&path, UnixSocketMode::Connect)
                    .expect("socket grant"),
            ];
            let config = make_config(&backend, 8080, Vec::new(), &allowlist);
            assert_eq!(
                decide_network_notification(
                    test_pid(),
                    SYS_CONNECT,
                    &unix_pathname(&path),
                    &config,
                ),
                NetworkDecision::Allow,
                "pathname AF_UNIX connect must be allowed when a connect grant covers it"
            );
        }

        #[test]
        fn af_unix_pathname_connect_without_grant_is_denied() {
            let backend = DenyAllBackend;
            let dir = tempfile::tempdir().expect("tempdir");
            let path = socket_path(&dir, "test.sock");
            let _listener = UnixListener::bind(&path).expect("bind unix listener");
            let config = make_config(&backend, 8080, Vec::new(), &[]);
            assert_eq!(
                decide_network_notification(
                    test_pid(),
                    SYS_CONNECT,
                    &unix_pathname(&path),
                    &config,
                ),
                NetworkDecision::Deny
            );
        }

        #[test]
        fn af_unix_pathname_bind_requires_connect_bind_grant() {
            let backend = DenyAllBackend;
            let dir = tempfile::tempdir().expect("tempdir");
            let path = socket_path(&dir, "test.sock");
            let _listener = UnixListener::bind(&path).expect("bind unix listener");
            let allowlist = vec![
                UnixSocketCapability::new_file(&path, UnixSocketMode::Connect)
                    .expect("socket grant"),
            ];
            let config = make_config(&backend, 0, Vec::new(), &allowlist);
            assert_eq!(
                decide_network_notification(test_pid(), SYS_BIND, &unix_pathname(&path), &config),
                NetworkDecision::Deny
            );
        }

        #[test]
        fn af_unix_dir_children_does_not_allow_nested_path() {
            let backend = DenyAllBackend;
            let dir = tempfile::tempdir().expect("tempdir");
            let nested = dir.path().join("nested");
            std::fs::create_dir(&nested).expect("create nested dir");
            let direct_path = socket_path(&dir, "direct.sock");
            let nested_path = nested.join("nested.sock");
            let allowlist = vec![
                UnixSocketCapability::new_dir(dir.path(), UnixSocketMode::ConnectBind)
                    .expect("socket dir grant"),
            ];
            let config = make_config(&backend, 0, Vec::new(), &allowlist);
            assert_eq!(
                decide_network_notification(
                    test_pid(),
                    SYS_BIND,
                    &unix_pathname(&direct_path),
                    &config,
                ),
                NetworkDecision::Allow
            );
            assert_eq!(
                decide_network_notification(
                    test_pid(),
                    SYS_BIND,
                    &unix_pathname(&nested_path),
                    &config,
                ),
                NetworkDecision::Deny
            );
        }

        #[test]
        fn af_unix_dir_subtree_allows_nested_path() {
            let backend = DenyAllBackend;
            let dir = tempfile::tempdir().expect("tempdir");
            let nested = dir.path().join("nested");
            std::fs::create_dir(&nested).expect("create nested dir");
            let nested_path = nested.join("nested.sock");
            let allowlist = vec![
                UnixSocketCapability::new_dir_subtree(dir.path(), UnixSocketMode::ConnectBind)
                    .expect("socket subtree grant"),
            ];
            let config = make_config(&backend, 0, Vec::new(), &allowlist);
            assert_eq!(
                decide_network_notification(
                    test_pid(),
                    SYS_BIND,
                    &unix_pathname(&nested_path),
                    &config,
                ),
                NetworkDecision::Allow
            );
        }

        /// Scope-limit test: abstract-namespace AF_UNIX (`sun_path[0] == 0`)
        /// is not covered by pathname socket capabilities, so it stays
        /// denied.
        #[test]
        fn af_unix_abstract_is_denied() {
            let backend = DenyAllBackend;
            let config = make_config(&backend, 0, Vec::new(), &[]);
            assert_eq!(
                decide_network_notification(test_pid(), SYS_BIND, &unix_abstract(), &config),
                NetworkDecision::Deny,
                "abstract AF_UNIX must be denied because pathname grants do not cover it"
            );
            assert_eq!(
                decide_network_notification(test_pid(), SYS_CONNECT, &unix_abstract(), &config),
                NetworkDecision::Deny,
            );
        }

        /// Unnamed AF_UNIX (`addrlen == 2`) has no path to check, so fail
        /// closed — consistent with abstract handling.
        #[test]
        fn af_unix_unnamed_is_denied() {
            let backend = DenyAllBackend;
            let config = make_config(&backend, 0, Vec::new(), &[]);
            assert_eq!(
                decide_network_notification(test_pid(), SYS_BIND, &unix_unnamed(), &config),
                NetworkDecision::Deny
            );
        }

        /// Security-critical: the `AF_UNIX → Allow` short-circuit must not
        /// leak into AF_INET. A child connecting to an external host on
        /// `proxy_port` must still be denied — otherwise the proxy could be
        /// bypassed.
        #[test]
        fn af_inet_connect_to_external_host_denied() {
            let backend = DenyAllBackend;
            let config = make_config(&backend, 8080, Vec::new(), &[]);
            assert_eq!(
                decide_network_notification(test_pid(), SYS_CONNECT, &inet_external(8080), &config),
                NetworkDecision::Deny
            );
        }

        /// Proves the refactor didn't collapse AF_INET bind to unconditional
        /// Allow. A port not in `proxy_bind_ports` must still fail.
        #[test]
        fn af_inet_bind_on_disallowed_port_denied() {
            let backend = DenyAllBackend;
            let config = make_config(&backend, 0, vec![3000], &[]);
            assert_eq!(
                decide_network_notification(test_pid(), SYS_BIND, &inet_loopback(4000), &config),
                NetworkDecision::Deny
            );
        }

        #[test]
        fn af_unix_only_mode_allows_non_af_unix_to_continue() {
            let backend = DenyAllBackend;
            let config = make_af_unix_only_config(&backend, &[]);
            assert_eq!(
                decide_network_notification(test_pid(), SYS_CONNECT, &inet_external(8080), &config),
                NetworkDecision::Allow
            );
            assert_eq!(
                decide_network_notification(test_pid(), SYS_BIND, &inet_loopback(4000), &config),
                NetworkDecision::Allow
            );
        }
    }
}
