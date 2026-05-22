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
use nono::{try_canonicalize, AccessMode};

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
        classify_access_from_flags, continue_notif, deny_notif, inject_fd, notif_id_valid,
        read_notif_path, read_open_how, recv_notif, resolve_notif_path, respond_notif_errno,
        validate_openat2_size, SYS_OPENAT, SYS_OPENAT2,
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

    let procfs_context = ProcfsAccessContext::new(child.as_raw() as u32, Some(notif.pid));
    let resolved_path = match resolve_procfs_path_for_child(&path, Some(procfs_context)) {
        Ok(resolved) => resolved,
        Err(e) => {
            debug!("Failed to resolve procfs path '{}': {}", path.display(), e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };
    let canonicalized = try_canonicalize(&resolved_path);

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
    match match_initial_capability(&canonicalized, access, initial_caps) {
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
                        if notif_id_valid(notify_fd, notif.id)? {
                            if let Err(e) = inject_fd(notify_fd, notif.id, file.as_raw_fd()) {
                                debug!(
                                    "inject_fd failed for initial-set proc path {}: {}",
                                    path.display(),
                                    e
                                );
                                let _ = deny_notif(notify_fd, notif.id);
                            }
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
            } else if notif_id_valid(notify_fd, notif.id)? {
                if let Err(e) = continue_notif(notify_fd, notif.id) {
                    debug!(
                        "continue_notif failed for initial-set path {}: {}",
                        path.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
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
            if notif_id_valid(notify_fd, notif.id)? {
                if let Err(send_err) = continue_notif(notify_fd, notif.id) {
                    debug!(
                        "continue_notif failed for missing path {}: {}",
                        path.display(),
                        send_err
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
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
    #[allow(deprecated)]
    let request = nono::supervisor::CapabilityRequest {
        request_id: format!("seccomp-{}", unique_request_id()),
        path: path.clone(),
        access,
        reason: Some("Sandbox intercepted file operation (seccomp-notify)".to_string()),
        child_pid: child.as_raw() as u32,
        session_id: config.session_id.to_string(),
        session_token: String::new(),
        kind: nono::supervisor::types::HandleKind::File,
        target: None,
        access_mask: 0,
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

/// Handle a seccomp notification for connect() or bind() syscalls.
///
/// This is the proxy-only fallback for kernels without Landlock AccessNet.
/// The BPF filter routes connect/bind to USER_NOTIF; this function reads
/// the sockaddr from the child's memory and allows or denies based on
/// the configured proxy port and bind ports.
///
/// For connect: allow only loopback + proxy port. Deny everything else.
/// For bind: allow only ports in the bind_ports list. Deny everything else.
///
/// Uses SECCOMP_USER_NOTIF_FLAG_CONTINUE on approval (safe for connect/bind
/// because the kernel has already copied sockaddr into kernel memory).
pub(super) fn handle_network_notification(
    notify_fd: std::os::fd::RawFd,
    config: &SupervisorConfig<'_>,
    rate_limiter: &mut RateLimiter,
) -> nono::error::Result<()> {
    use nono::sandbox::{
        continue_notif, deny_notif, notif_id_valid, read_notif_sockaddr, recv_notif,
        respond_notif_errno, SYS_BIND, SYS_CONNECT,
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

    let allowed = match notif.data.nr {
        SYS_CONNECT => {
            // Allow connect only to loopback + proxy port
            let port_match = sockaddr.port == config.proxy_port;
            if sockaddr.is_loopback && port_match {
                debug!(
                    "Proxy seccomp: allowing connect to loopback:{}",
                    sockaddr.port
                );
                true
            } else {
                debug!(
                    "Proxy seccomp: denying connect to family={} port={} loopback={}",
                    sockaddr.family, sockaddr.port, sockaddr.is_loopback
                );
                false
            }
        }
        SYS_BIND => {
            // Allow bind only on configured bind ports
            let port_allowed = config.proxy_bind_ports.contains(&sockaddr.port);
            if port_allowed {
                debug!("Proxy seccomp: allowing bind on port {}", sockaddr.port);
                true
            } else {
                debug!(
                    "Proxy seccomp: denying bind on port {} (allowed: {:?})",
                    sockaddr.port, config.proxy_bind_ports
                );
                false
            }
        }
        other => {
            warn!(
                "Unexpected syscall {} in proxy seccomp handler, denying",
                other
            );
            false
        }
    };

    if allowed {
        // SECCOMP_USER_NOTIF_FLAG_CONTINUE: let the kernel proceed with its
        // already-copied sockaddr. Safe for connect/bind (move_addr_to_kernel).
        if let Err(e) = continue_notif(notify_fd, notif.id) {
            debug!("continue_notif failed for network notification: {}", e);
            // Must respond to avoid leaving the child blocked. Propagate if
            // deny also fails — the notification is orphaned.
            return deny_notif(notify_fd, notif.id);
        }
    } else {
        respond_notif_errno(notify_fd, notif.id, libc::EACCES)?;
    }

    Ok(())
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
}

/// cgroup v2 session management for Linux resource limits.
///
/// This submodule implements the cgroup v2 delegated-hierarchy lifecycle:
/// detect → mkdir → enable controllers → write limits → place child PID → cleanup.
///
/// # Cgroup v2 Delegation Model
///
/// On systemd-managed Linux systems, each user session has a delegated cgroup subtree
/// under `/sys/fs/cgroup/<slice>/`. The supervisor reads `/proc/self/cgroup` to find
/// its delegated cgroup path, then creates a child cgroup for the sandboxed process.
///
/// # Fail-Fast Guarantee
///
/// On cgroup v1 hosts or systems without systemd delegation, `CgroupSession::new`
/// returns `Err(NonoError::UnsupportedKernelFeature { feature: "cgroup_v2", hint })`
/// BEFORE any child is spawned (Phase 37 D-05; the hint points the user at the
/// `cgroup_no_v1=all` boot flag). This is intentional per REQ-RESL-NIX-01 criterion 5.
/// The path-traversal guard in `detect_from_str` is the lone exception that still
/// returns `NonoError::UnsupportedPlatform(...)` (Phase 37 D-07).
/// Cgroup-v2 detection sites (Phase 44 IN-06 P37, REQ-REVIEW-FU-01 D-44-A4).
///
/// All six `NonoError::UnsupportedKernelFeature { feature: "cgroup_v2", ... }`
/// constructions in this module share the LOCKED hint string from
/// [`nono::CGROUP_V2_HINT`] (Phase 44 WR-02 P37 promoted it from a
/// test-mod-local literal). The seventh detection branch
/// (`detect_from_str` path-traversal guard at ~line 946) intentionally
/// stays `NonoError::UnsupportedPlatform` because the kernel is fine —
/// the boot-flag hint would mislead an operator chasing a `/proc`
/// tampering signal.
///
/// Site map:
///
/// 1. `detect_from_str` early empty-content guard
/// 2. `detect_from_str` multi-line guard (cgroup v1/hybrid)
/// 3. `detect_from_str` missing `0::` prefix guard
/// 4. (intentionally UnsupportedPlatform — `detect_from_str` traversal guard)
/// 5. `detect` cases:
///    5a. `detect` failed to read `/proc/self/cgroup`
///    5b. `detect` resolved path is not a directory
///    5c. `detect` resolved path metadata failed
pub(super) mod cgroup {
    use crate::launch_runtime::ResourceLimits;
    use nono::{NonoError, Result, CGROUP_V2_HINT};
    use std::io;
    use std::path::PathBuf;
    use tracing::warn;

    /// RAII guard for a cgroup v2 session.
    ///
    /// Creates and manages a cgroup for a sandboxed process tree. On drop, removes
    /// the cgroup directory unconditionally (panic-safe cleanup).
    ///
    /// # RAII Guarantee
    ///
    /// The cgroup directory is removed when this struct is dropped, regardless of
    /// whether the session completed successfully or panicked. This prevents leftover
    /// cgroup directories that would waste kernel resources.
    pub(crate) struct CgroupSession {
        /// Absolute path to the nono-<session-id> cgroup directory.
        pub(crate) path: PathBuf,
        /// Resource limits to apply (stored for `apply_limits`).
        pub(crate) limits: ResourceLimits,
    }

    impl CgroupSession {
        /// Parse a `/proc/self/cgroup` contents string and extract the delegated cgroup path.
        ///
        /// # cgroup v2 format
        ///
        /// A pure cgroup v2 system produces exactly ONE line:
        /// ```text
        /// 0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.scope
        /// ```
        ///
        /// A cgroup v1 or hybrid system produces multiple lines (one per hierarchy) or
        /// lines with a non-zero hierarchy ID. Both cases cause a fail-fast error.
        ///
        /// # Errors
        ///
        /// Returns `Err(NonoError::UnsupportedKernelFeature { .. })` (with the
        /// LOCKED `cgroup_no_v1=all` boot-flag hint per Phase 37 D-07) when:
        /// - The contents are empty
        /// - There are multiple lines (cgroup v1 or hybrid mode)
        /// - The single line does not start with `0::` (not pure cgroup v2)
        ///
        /// Returns `Err(NonoError::UnsupportedPlatform(...))` only for the
        /// path-traversal guard below (kernel is fine; /proc content is
        /// malformed/malicious — the boot-flag hint would mislead the user).
        pub(crate) fn detect_from_str(contents: &str) -> Result<PathBuf> {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                // Phase 37 D-05 / D-07 site 1: empty /proc/self/cgroup is a
                // kernel-misconfig signal (cgroup-v1 host or no delegation).
                return Err(NonoError::UnsupportedKernelFeature {
                    feature: "cgroup_v2".into(),
                    hint: CGROUP_V2_HINT.into(),
                });
            }
            let mut lines = trimmed.lines();
            let first = lines.next().unwrap_or("");
            if lines.next().is_some() {
                // Phase 37 D-05 / D-07 site 2: multi-line content = cgroup v1
                // or hybrid mode; pure v2 emits exactly one line.
                return Err(NonoError::UnsupportedKernelFeature {
                    feature: "cgroup_v2".into(),
                    hint: CGROUP_V2_HINT.into(),
                });
            }
            // Pure cgroup v2 has exactly one line starting with "0::"
            let cgroup_rel = first.strip_prefix("0::").ok_or_else(|| {
                // Phase 37 D-05 / D-07 site 3: missing `0::` prefix = cgroup v1
                // or hybrid mode (still a kernel-misconfig signal).
                NonoError::UnsupportedKernelFeature {
                    feature: "cgroup_v2".into(),
                    hint: CGROUP_V2_HINT.into(),
                }
            })?;
            let abs_path = PathBuf::from("/sys/fs/cgroup")
                .join(cgroup_rel.trim_start_matches('/').trim_end_matches('/'));
            // WR-03: Validate the constructed path stays within /sys/fs/cgroup.
            //
            // We perform two complementary component-level checks (NOT string
            // operations) per CLAUDE.md § Path Handling:
            //
            //   1. `Path::starts_with("/sys/fs/cgroup")` rejects entries that, after
            //      `trim_start_matches('/')`, somehow produce a path that does not
            //      have `/sys/fs/cgroup` as a component prefix. Note that this check
            //      alone is NOT sufficient to catch `..` traversal because
            //      `Path::starts_with` does not normalize parent-dir references —
            //      `/sys/fs/cgroup/../../etc` has the components `[/, sys, fs,
            //      cgroup, .., .., etc]` and DOES start with `/sys/fs/cgroup`.
            //
            //   2. We additionally reject any path containing a `Component::ParentDir`
            //      (`..`). A well-formed cgroup-v2 delegated path from
            //      `/proc/self/cgroup` never contains `..`; its presence indicates a
            //      malicious or compromised /proc entry attempting to redirect path
            //      construction outside `/sys/fs/cgroup` (e.g., `0::/../../etc`).
            //
            // Both checks fail closed with `NonoError::UnsupportedPlatform`
            // (Phase 37 D-07: KEEP — this site is /proc-tampering, not kernel misconfig).
            use std::path::Component;
            if !abs_path.starts_with("/sys/fs/cgroup")
                || abs_path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir))
            {
                // Phase 37 D-07: KEEP as UnsupportedPlatform — /proc tampering, not kernel misconfig.
                // The cgroup_no_v1=all boot-flag hint would mislead the user here because the
                // kernel is fine — /proc/self/cgroup content is malformed/malicious. This is the
                // 1-of-5 detection site intentionally NOT swapped to UnsupportedKernelFeature.
                return Err(NonoError::UnsupportedPlatform(format!(
                    "cgroup_v2: constructed cgroup path {abs_path:?} escapes /sys/fs/cgroup \
                     (path traversal detected in /proc/self/cgroup content)"
                )));
            }
            Ok(abs_path)
        }

        /// Detect the systemd-delegated cgroup v2 path for the current process.
        ///
        /// Reads `/proc/self/cgroup`, validates it is pure cgroup v2, and returns
        /// the absolute path to the delegated cgroup directory under `/sys/fs/cgroup`.
        ///
        /// # Fail-fast guarantee
        ///
        /// If the system is not running pure cgroup v2 with systemd delegation,
        /// returns `Err(NonoError::UnsupportedKernelFeature { feature: "cgroup_v2", hint })`
        /// (Phase 37 D-05) BEFORE any child is spawned. This is the enforcement point
        /// for REQ-RESL-NIX-01 acceptance criterion 5. The path-traversal guard inside
        /// `detect_from_str` is the one exception that still returns
        /// `NonoError::UnsupportedPlatform(...)` (Phase 37 D-07).
        ///
        /// # Errors
        ///
        /// Returns `Err` if:
        /// - `/proc/self/cgroup` cannot be read
        /// - The contents indicate cgroup v1 or hybrid mode
        /// - The resolved path does not exist as a directory
        pub(crate) fn detect() -> Result<PathBuf> {
            // Phase 37 D-05 / D-07 site 5a: failure to read /proc/self/cgroup is
            // treated as a kernel-misconfig signal (no /proc, no procfs mount,
            // or v1 host without cgroup-v2 controller).
            let contents = std::fs::read_to_string("/proc/self/cgroup").map_err(|_e| {
                NonoError::UnsupportedKernelFeature {
                    feature: "cgroup_v2".into(),
                    hint: CGROUP_V2_HINT.into(),
                }
            })?;
            let delegated = Self::detect_from_str(&contents)?;
            // Verify the resolved path is an accessible directory.
            // Phase 37 D-05 / D-07 sites 5b + 5c: missing/non-directory delegated
            // cgroup path is treated as kernel-misconfig (v2 unified hierarchy
            // not mounted or delegation not granted by systemd).
            match std::fs::metadata(&delegated) {
                Ok(m) if m.is_dir() => Ok(delegated),
                Ok(_) => Err(NonoError::UnsupportedKernelFeature {
                    feature: "cgroup_v2".into(),
                    hint: CGROUP_V2_HINT.into(),
                }),
                Err(_e) => Err(NonoError::UnsupportedKernelFeature {
                    feature: "cgroup_v2".into(),
                    hint: CGROUP_V2_HINT.into(),
                }),
            }
        }

        /// Create a new cgroup session for the given session ID and resource limits.
        ///
        /// # Steps
        ///
        /// 1. Calls `detect()` to locate the delegated cgroup.
        /// 2. Enables `+memory +cpu +pids` in the parent's `cgroup.subtree_control`
        ///    (read-modify-write to avoid clobbering existing controllers).
        /// 3. Creates `<delegated>/nono-<session-id>/` — fails fast on `EEXIST`
        ///    (duplicate session ID is a bug, not a retry target).
        /// 4. Stores the path and limits for later use.
        ///
        /// # Errors
        ///
        /// - `UnsupportedKernelFeature { feature: "cgroup_v2", .. }`: cgroup v2
        ///   not available (see `detect()`; Phase 37 D-05). The path-traversal
        ///   guard inside `detect_from_str` still surfaces `UnsupportedPlatform`
        ///   per Phase 37 D-07.
        /// - `SandboxInit`: controller enablement or directory creation failed.
        pub(crate) fn new(session_id: &str, limits: &ResourceLimits) -> Result<Self> {
            let delegated = Self::detect()?;
            // Enable required controllers in the PARENT's cgroup.subtree_control.
            // Per cgroup v2 docs: controllers must be enabled in the parent cgroup
            // before child cgroups can use them.
            let subtree_control = delegated.join("cgroup.subtree_control");
            // Read existing controllers; if the file is unreadable treat as empty
            // (some delegated cgroups may not have subtree_control initially).
            let current_controllers = std::fs::read_to_string(&subtree_control).unwrap_or_default();
            // Build the write string: only add controllers not already present.
            let mut additions = String::new();
            for controller in &["memory", "cpu", "pids"] {
                if !current_controllers.contains(controller) {
                    if !additions.is_empty() {
                        additions.push(' ');
                    }
                    additions.push('+');
                    additions.push_str(controller);
                }
            }
            if !additions.is_empty() {
                std::fs::write(&subtree_control, &additions).map_err(|e| {
                    let cgroup_contents =
                        std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
                    NonoError::SandboxInit(format!(
                        "cgroup_v2: failed to enable controllers ({additions}) in \
                         {subtree_control:?}: {e}\n\
                         /proc/self/cgroup: {cgroup_contents}"
                    ))
                })?;
            }
            // Construct the child cgroup path: <delegated>/nono-<session-id>/
            let child_name = format!("nono-{session_id}");
            let child_path = delegated.join(&child_name);
            // Fail fast on EEXIST: reusing leftover state is a security bug.
            if let Err(e) = std::fs::create_dir(&child_path) {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    return Err(NonoError::SandboxInit(format!(
                        "cgroup_v2: cgroup directory {child_path:?} already exists \
                         (duplicate session ID '{session_id}' — leftover state from a \
                         previous crash?). Remove it manually: rmdir {child_path:?}"
                    )));
                }
                return Err(NonoError::SandboxInit(format!(
                    "cgroup_v2: failed to create cgroup directory {child_path:?}: {e}"
                )));
            }
            Ok(Self {
                path: child_path,
                limits: limits.clone(),
            })
        }

        /// Apply resource limits to the cgroup pseudo-files.
        ///
        /// # Limit-to-file mapping
        ///
        /// | ResourceLimits field | Kernel file   | Format                     |
        /// |----------------------|---------------|----------------------------|
        /// | `memory_bytes`       | `memory.max`  | decimal bytes + newline    |
        /// | `cpu_percent`        | `cpu.max`     | `<quota> <period>\n`       |
        /// | `max_processes`      | `pids.max`    | decimal count + newline    |
        /// | `timeout`            | (not here)    | Task 5 watchdog handles it |
        ///
        /// # cpu.max format
        ///
        /// `<quota> <period>` where period = 100000 µs (100ms) and quota = percent * period / 100.
        /// Example: `--cpu-percent 50` → `"50000 100000\n"`.
        ///
        /// # Errors
        ///
        /// Returns `Err(NonoError::SandboxInit(...))` naming the failing limit and the kernel error.
        pub(crate) fn apply_limits(&self) -> Result<()> {
            if let Some(bytes) = self.limits.memory_bytes {
                let content = format!("{bytes}\n");
                std::fs::write(self.path.join("memory.max"), &content).map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "cgroup_v2: failed to write memory.max ({bytes} bytes) to {:?}: {e}",
                        self.path
                    ))
                })?;
            }
            if let Some(percent) = self.limits.cpu_percent {
                const PERIOD: u64 = 100_000; // 100ms in µs
                let quota = (percent as u64)
                    .checked_mul(PERIOD)
                    .map(|q| q / 100)
                    .ok_or_else(|| {
                        NonoError::SandboxInit(format!(
                            "cgroup_v2: cpu_percent {percent} * {PERIOD} overflows u64"
                        ))
                    })?;
                let content = format!("{quota} {PERIOD}\n");
                std::fs::write(self.path.join("cpu.max"), &content).map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "cgroup_v2: failed to write cpu.max ({content:?}) to {:?}: {e}",
                        self.path
                    ))
                })?;
            }
            if let Some(n) = self.limits.max_processes {
                let content = format!("{n}\n");
                std::fs::write(self.path.join("pids.max"), &content).map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "cgroup_v2: failed to write pids.max ({n}) to {:?}: {e}",
                        self.path
                    ))
                })?;
            }
            Ok(())
        }

        /// Install a `pre_exec` hook on `cmd` that places the child PID in this cgroup.
        ///
        /// The hook runs in the forked child, post-fork pre-exec (before `execve`),
        /// writing the child's own PID to `<self.path>/cgroup.procs`.
        ///
        /// # Race window
        ///
        /// Between `fork()` returning in the parent and this `pre_exec` hook running
        /// in the child, the child is a Rust runtime stub with NO user code running —
        /// kernel scheduler latency only. The parent has ALREADY called `apply_limits`
        /// BEFORE fork, so the cgroup is fully configured when the child enters it.
        ///
        /// # SAFETY
        ///
        /// The closure passed to `pre_exec` runs in the forked child in a
        /// async-signal-unsafe context (memory model: single-threaded, but
        /// allocator may be in an inconsistent state from the parent's state at
        /// fork time). Therefore:
        ///
        /// - Only raw libc syscalls are used: `libc::getpid`, `libc::open`,
        ///   `libc::write`, `libc::close`. These are all async-signal-safe.
        /// - PID is formatted into a stack-allocated `[u8; 20]` buffer (no
        ///   `format!` macro, no heap allocation).
        /// - The cgroup.procs path is pre-computed into a `Vec<u8>` in the parent
        ///   (before fork, where allocation is safe) and moved into the closure
        ///   as an owned value.
        pub(crate) fn install_pre_exec(&self, cmd: &mut std::process::Command) {
            use std::os::unix::process::CommandExt;
            // Build the cgroup.procs path as bytes in the parent (before fork, allocation OK).
            let procs_path = self.procs_path_nul();

            // SAFETY: This closure runs in the forked child, post-fork pre-exec.
            // `place_self_in_cgroup_raw` uses only async-signal-safe libc calls
            // (getpid, open, write, close). No Rust allocator, no Mutex.
            // The procs_path Vec is moved in by value (heap allocation happened
            // in the parent before fork).
            //
            // Race window: between fork() returning in the parent and this pre_exec
            // running in the child, the child is a Rust runtime stub with no user
            // code. The parent MUST call apply_limits() before fork so the cgroup
            // is fully configured.
            unsafe {
                cmd.pre_exec(move || -> std::io::Result<()> {
                    CgroupSession::place_self_in_cgroup_raw(&procs_path)
                });
            }
        }

        /// Place the calling process (child after fork, before execve) in this cgroup.
        ///
        /// This is the async-signal-safe equivalent of `install_pre_exec` for use in
        /// the supervised execution path where raw `fork()` + `execve()` is used
        /// instead of `std::process::Command`. Must be called in the forked child,
        /// after `fork()` returns but before `execve()`.
        ///
        /// # SAFETY
        ///
        /// Called in the forked child, post-fork pre-exec. Uses only raw libc calls
        /// (async-signal-safe). No Rust allocator, no Mutex.
        ///
        /// Returns `Ok(())` on success, `Err(io::Error)` on failure. The caller
        /// in the child branch should convert this to a libc write + `_exit(126)`.
        pub(crate) fn place_self_in_cgroup_raw(procs_path_nul: &[u8]) -> std::io::Result<()> {
            // SAFETY: we are in the forked child, post-fork pre-exec.
            // getpid, open, write, close are all async-signal-safe per POSIX.
            unsafe {
                use nix::libc;
                let pid = libc::getpid();
                // Format PID + '\n' into a stack buffer (no allocation).
                let mut buf = [0u8; 21];
                buf[20] = b'\n';
                let mut n = pid as u64;
                let mut idx = 20usize;
                if n == 0 {
                    idx -= 1;
                    buf[idx] = b'0';
                } else {
                    while n > 0 {
                        idx -= 1;
                        buf[idx] = b'0' + (n % 10) as u8;
                        n /= 10;
                    }
                }
                let pid_bytes = &buf[idx..];
                let fd = libc::open(
                    procs_path_nul.as_ptr().cast::<libc::c_char>(),
                    libc::O_WRONLY | libc::O_CLOEXEC,
                );
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let written = libc::write(
                    fd,
                    pid_bytes.as_ptr().cast::<libc::c_void>(),
                    pid_bytes.len(),
                );
                libc::close(fd);
                if written < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        }

        /// Build the null-terminated cgroup.procs path bytes for use in `place_self_in_cgroup_raw`.
        ///
        /// Returns a `Vec<u8>` with a trailing `\0` byte, suitable for passing to
        /// `libc::open`. This must be pre-computed in the PARENT before fork (where
        /// Rust allocation is safe).
        pub(crate) fn procs_path_nul(&self) -> Vec<u8> {
            use std::os::unix::ffi::OsStrExt;
            let mut v: Vec<u8> = self.path.as_os_str().as_bytes().to_vec();
            v.extend_from_slice(b"/cgroup.procs\0");
            v
        }

        /// Atomically kill all processes in this cgroup tree by writing `1\n` to
        /// `<self.path>/cgroup.kill`.
        ///
        /// The kernel delivers SIGKILL to every process in the cgroup and all
        /// descendant cgroups simultaneously. This is the correct mechanism for
        /// timeout enforcement (REQ-RESL-NIX-02) because it avoids any race window
        /// between identifying child PIDs and sending signals.
        ///
        /// # Errors
        ///
        /// Returns `Err(NonoError::SandboxInit(...))` if the write fails. On a
        /// session that has already been cleaned up, this will fail with ENOENT —
        /// callers should treat that as a no-op (the cgroup is already gone).
        #[cfg(test)]
        pub(crate) fn kill_all(&self) -> Result<()> {
            let kill_path = self.path.join("cgroup.kill");
            std::fs::write(&kill_path, "1\n").map_err(|e| {
                NonoError::SandboxInit(format!("cgroup_v2: failed to write to {kill_path:?}: {e}"))
            })
        }
    }

    impl Drop for CgroupSession {
        fn drop(&mut self) {
            // Check for surviving processes (should be empty after cgroup.kill).
            let procs_path = self.path.join("cgroup.procs");
            if let Ok(contents) = std::fs::read_to_string(&procs_path) {
                let surviving = contents.trim();
                if !surviving.is_empty() {
                    warn!(
                        "cgroup_v2: Drop: {} still has processes: [{}] — \
                         supervisor bug (cgroup.kill should have cleared them)",
                        self.path.display(),
                        surviving.lines().collect::<Vec<_>>().join(", ")
                    );
                }
            }
            // Remove the cgroup directory. Errors are logged but not propagated
            // (Drop cannot return Result).
            if let Err(e) = std::fs::remove_dir(&self.path) {
                warn!(
                    "cgroup_v2: Drop: failed to remove cgroup directory {:?}: {e}",
                    self.path
                );
            }
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    #[allow(clippy::unwrap_used)]
    mod tests {
        use super::*;

        // ── detect_from_str unit tests ───────────────────────────────────────────

        #[test]
        fn detect_from_str_valid_cgroup_v2() {
            let contents =
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.scope\n";
            let path = CgroupSession::detect_from_str(contents).unwrap();
            assert_eq!(
                path,
                std::path::PathBuf::from(
                    "/sys/fs/cgroup/user.slice/user-1000.slice/\
                     user@1000.service/app.slice/app-foo.scope"
                )
            );
        }

        #[test]
        fn detect_from_str_cgroup_v1_rejected() {
            // Phase 37 D-05 / D-07: missing `0::` prefix on a v1 host now
            // returns the typed UnsupportedKernelFeature variant.
            let contents = "1:cpu:/foo\n";
            let err = CgroupSession::detect_from_str(contents).unwrap_err();
            assert!(
                matches!(err, NonoError::UnsupportedKernelFeature { .. }),
                "expected UnsupportedKernelFeature, got: {err:?}"
            );
        }

        #[test]
        fn detect_from_str_hybrid_rejected() {
            // Phase 37 D-05 / D-07: hybrid (multi-line) content now returns
            // the typed UnsupportedKernelFeature variant.
            let contents = "0::/user.slice/foo\n1:cpu:/foo\n";
            let err = CgroupSession::detect_from_str(contents).unwrap_err();
            assert!(
                matches!(err, NonoError::UnsupportedKernelFeature { .. }),
                "expected UnsupportedKernelFeature, got: {err:?}"
            );
        }

        #[test]
        fn detect_from_str_empty_rejected() {
            // Phase 37 D-05 / D-07: empty /proc/self/cgroup now returns the
            // typed UnsupportedKernelFeature variant.
            let err = CgroupSession::detect_from_str("").unwrap_err();
            assert!(
                matches!(err, NonoError::UnsupportedKernelFeature { .. }),
                "expected UnsupportedKernelFeature, got: {err:?}"
            );
        }

        // ── WR-03 traversal-guard regression tests ──────────────────────────────
        //
        // These tests defend the fix for code-review finding WR-03: a malicious
        // /proc/self/cgroup entry containing `..` components could redirect the
        // path-construction in `detect_from_str` outside `/sys/fs/cgroup`. The
        // production fix uses `Path::starts_with("/sys/fs/cgroup")` (component-
        // level comparison, NOT string `starts_with`) per CLAUDE.md § Path Handling.

        #[test]
        fn cgroup_path_rejects_parent_dir_traversal() {
            // Attacker-controlled /proc/self/cgroup with .. to escape /sys/fs/cgroup.
            let err = CgroupSession::detect_from_str("0::/../../etc")
                .expect_err("must reject path traversal");
            match err {
                NonoError::UnsupportedPlatform(msg) => {
                    assert!(
                        msg.contains("path traversal") || msg.contains("escapes"),
                        "error message must mention traversal, got: {msg}"
                    );
                }
                other => panic!("expected UnsupportedPlatform, got: {other:?}"),
            }
        }

        #[test]
        fn cgroup_path_rejects_encoded_traversal() {
            // Variant: leading ../ after trim_start_matches strips the slash.
            let err = CgroupSession::detect_from_str("0::/../../../proc/self")
                .expect_err("must reject path traversal with leading slash");
            assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
        }

        #[test]
        fn cgroup_path_accepts_normal_path() {
            // Normal systemd-delegated cgroup path must still construct successfully.
            // detect_from_str does NOT check filesystem existence — that is detect()'s job.
            let path =
                CgroupSession::detect_from_str("0::/user.slice/user-1000.slice/session-1.scope")
                    .expect("normal cgroup path must be accepted");
            assert!(
                path.starts_with("/sys/fs/cgroup"),
                "path must be under /sys/fs/cgroup, got: {path:?}"
            );
        }

        /// Helper: attempt to create a real cgroup session. Returns None and
        /// prints a skip message if cgroup v2 delegation is not available.
        fn try_cgroup_session(session_id: &str) -> Option<CgroupSession> {
            let limits = ResourceLimits {
                memory_bytes: Some(256 * 1024 * 1024),
                cpu_percent: Some(50),
                max_processes: Some(10),
                timeout: None,
            };
            match CgroupSession::new(session_id, &limits) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("skipping: no cgroup v2 delegation ({e})");
                    None
                }
            }
        }

        #[test]
        fn cgroup_session_lifecycle() {
            let Some(session) = try_cgroup_session("test-lifecycle-001") else {
                return;
            };
            let path = session.path.clone();
            assert!(path.is_dir(), "cgroup directory must exist after creation");
            drop(session);
            assert!(
                !path.exists(),
                "cgroup directory must be removed after Drop"
            );
        }

        #[test]
        fn cgroup_session_apply_limits() -> Result<(), Box<dyn std::error::Error>> {
            let Some(session) = try_cgroup_session("test-apply-001") else {
                return Ok(());
            };
            session.apply_limits()?;
            let memory_max = std::fs::read_to_string(session.path.join("memory.max"))?;
            assert_eq!(
                memory_max.trim(),
                "268435456",
                "memory.max should be 256*1024*1024 bytes"
            );
            let cpu_max = std::fs::read_to_string(session.path.join("cpu.max"))?;
            assert_eq!(
                cpu_max.trim(),
                "50000 100000",
                "cpu.max should be quota=50000 period=100000"
            );
            let pids_max = std::fs::read_to_string(session.path.join("pids.max"))?;
            assert_eq!(pids_max.trim(), "10", "pids.max should be 10");
            Ok(())
        }

        #[test]
        fn cgroup_session_pre_exec_places_pid() -> Result<(), Box<dyn std::error::Error>> {
            let Some(session) = try_cgroup_session("test-pre-exec-001") else {
                return Ok(());
            };
            session.apply_limits()?;
            let mut cmd = std::process::Command::new("sleep");
            cmd.arg("5");
            session.install_pre_exec(&mut cmd);
            let mut child = cmd.spawn()?;
            let child_pid = child.id();
            // Poll cgroup.procs for up to 500ms for the PID to appear.
            let procs_path = session.path.join("cgroup.procs");
            let found = (0..50).any(|_| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                std::fs::read_to_string(&procs_path)
                    .map(|c| c.lines().any(|l| l.trim() == child_pid.to_string()))
                    .unwrap_or(false)
            });
            // Kill the child and reap regardless of assertion result —
            // closes clippy::zombie_processes by waiting on the Child handle.
            let _ = session.kill_all();
            let _ = child.kill();
            let _ = child.wait();
            assert!(
                found,
                "child PID {child_pid} should appear in cgroup.procs within 500ms"
            );
            Ok(())
        }

        #[test]
        fn cgroup_kill_terminates_grandchildren() -> Result<(), Box<dyn std::error::Error>> {
            let Some(session) = try_cgroup_session("test-kill-001") else {
                return Ok(());
            };
            session.apply_limits()?;
            let mut cmd = std::process::Command::new("bash");
            cmd.args(["-c", "for i in 1 2 3; do sleep 60 & done; wait"]);
            session.install_pre_exec(&mut cmd);
            let mut child = cmd.spawn()?;
            // Give bash time to fork the sleep children.
            std::thread::sleep(std::time::Duration::from_millis(200));
            session.kill_all()?;
            let result = child.wait()?;
            assert!(
                !result.success(),
                "bash should have been killed (non-zero exit)"
            );
            Ok(())
        }
    }

    /// Phase 37 D-05 / D-07 swap tests: 4-of-5 cgroup-v2 detection sites now
    /// emit `NonoError::UnsupportedKernelFeature` with the LOCKED
    /// `cgroup_no_v1=all` boot-flag hint. Site 4 (path-traversal guard)
    /// INTENTIONALLY remains `UnsupportedPlatform` per D-07 (kernel is fine;
    /// /proc content is malformed — boot flag would mislead the user).
    #[cfg(all(test, target_os = "linux"))]
    #[allow(clippy::unwrap_used)]
    mod unsupported_kernel_feature_swap_tests {
        use super::*;

        const LOCKED_HINT_SUBSTR: &str = "cgroup_no_v1=all";

        #[test]
        fn detect_from_str_empty_returns_unsupported_kernel_feature() {
            let err = CgroupSession::detect_from_str("").unwrap_err();
            match err {
                NonoError::UnsupportedKernelFeature { feature, hint } => {
                    assert_eq!(feature, "cgroup_v2");
                    assert!(
                        hint.contains(LOCKED_HINT_SUBSTR),
                        "hint must contain LOCKED substring; got: {hint}"
                    );
                }
                other => panic!("expected UnsupportedKernelFeature; got {other:?}"),
            }
        }

        #[test]
        fn detect_from_str_v1_multiline_returns_unsupported_kernel_feature() {
            let err = CgroupSession::detect_from_str("11:cpu:/\n10:memory:/\n").unwrap_err();
            assert!(matches!(err, NonoError::UnsupportedKernelFeature { .. }));
        }

        #[test]
        fn detect_from_str_missing_zero_prefix_returns_unsupported_kernel_feature() {
            let err = CgroupSession::detect_from_str("1::/some/path").unwrap_err();
            assert!(matches!(err, NonoError::UnsupportedKernelFeature { .. }));
        }

        #[test]
        fn detect_from_str_path_traversal_returns_unsupported_platform_not_kernel_feature() {
            // Phase 37 D-07: site 4 INTENTIONALLY kept as UnsupportedPlatform.
            // The kernel is fine; /proc/self/cgroup content is malformed
            // (or malicious), so the cgroup_no_v1=all hint would mislead.
            let err = CgroupSession::detect_from_str("0::/../../etc").unwrap_err();
            assert!(
                matches!(err, NonoError::UnsupportedPlatform(_)),
                "site 4 (path-traversal guard) must remain UnsupportedPlatform per D-07; got {err:?}"
            );
        }
    }
}
