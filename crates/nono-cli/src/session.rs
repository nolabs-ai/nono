//! Session registry for the nono capability runtime.
//!
//! Each `nono run` or `nono shell` invocation in supervised mode creates a session
//! file at `$XDG_STATE_HOME/nono/sessions/{session_id}.json` (default
//! `~/.local/state/nono/sessions/`). This enables `nono ps`, `nono stop`,
//! `nono logs`, and `nono inspect` to discover and manage running sandboxes.

use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

/// Session state persisted to `$XDG_STATE_HOME/nono/sessions/{session_id}.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub name: Option<String>,
    pub supervisor_pid: u32,
    pub child_pid: u32,
    pub started: String,
    pub started_epoch: u64,
    pub status: SessionStatus,
    #[serde(default)]
    pub attachment: SessionAttachment,
    pub exit_code: Option<i32>,
    pub command: Vec<String>,
    pub profile: Option<String>,
    pub workdir: PathBuf,
    pub network: String,
    pub rollback_session: Option<String>,
}

/// Session lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Running,
    Paused,
    Exited,
}

/// Whether a human client is currently attached to the running session.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionAttachment {
    #[default]
    Attached,
    Detached,
}

/// RAII guard that writes session state on creation and updates on drop.
///
/// Ensures the session file is always updated, even on panic.
pub struct SessionGuard {
    record: SessionRecord,
    path: PathBuf,
}

impl SessionGuard {
    /// Create a new session guard, writing the initial session file.
    ///
    /// The file is created with `O_CREAT | O_EXCL` and mode `0o600` to prevent
    /// symlink attacks and ensure owner-only access.
    pub fn new(record: SessionRecord) -> Result<Self> {
        let dir = ensure_sessions_dir()?;
        let path = session_record_path(&dir, &record.session_id)?;

        write_session_file(&path, &record)?;
        debug!("Session file created: {}", path.display());

        Ok(Self { record, path })
    }

    /// Update the child PID and persist to disk.
    ///
    /// Called after fork when the child PID is known. Updates the session
    /// file immediately so `nono ps` shows the correct PID.
    pub fn set_child_pid(&mut self, pid: u32) {
        self.record.child_pid = pid;
        if let Err(e) = update_session_file(&self.path, &self.record) {
            warn!("Failed to update session file with child PID: {}", e);
        }
    }

    /// Mark the session as exited with the given exit code.
    pub fn set_exited(&mut self, exit_code: i32) {
        self.record.status = SessionStatus::Exited;
        self.record.exit_code = Some(exit_code);
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        // If still Running on drop (e.g. panic), mark as exited with -1
        if self.record.status == SessionStatus::Running {
            self.record.status = SessionStatus::Exited;
            self.record.exit_code = Some(-1);
        }
        if let Err(e) = update_session_file(&self.path, &self.record) {
            warn!("Failed to update session file on drop: {}", e);
        }
    }
}

#[cfg(target_os = "macos")]
const PROC_PIDTBSDINFO: i32 = 3;
#[cfg(target_os = "macos")]
const SSTOP: u32 = 4;
#[cfg(target_os = "macos")]
const PROC_BSD_INFO_SIZE: usize = 136;

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
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

#[cfg(target_os = "macos")]
const _: [(); PROC_BSD_INFO_SIZE] = [(); std::mem::size_of::<ProcBsdInfo>()];

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
}

#[cfg(target_os = "macos")]
fn proc_bsd_info(pid: u32) -> Option<ProcBsdInfo> {
    use std::mem;

    let mut info: ProcBsdInfo = unsafe { mem::zeroed() };
    let size = mem::size_of::<ProcBsdInfo>() as i32;
    let ret = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut std::ffi::c_void,
            size,
        )
    };
    if ret == size { Some(info) } else { None }
}

fn reconcile_session_record(record: &mut SessionRecord) -> bool {
    let original_status = record.status.clone();
    let original_exit_code = record.exit_code;

    if !is_process_alive(record.supervisor_pid, record.started_epoch) {
        record.status = SessionStatus::Exited;
        record.attachment = SessionAttachment::Detached;
        if record.exit_code.is_none() {
            record.exit_code = Some(-1);
        }
    } else if is_process_stopped(record.supervisor_pid) {
        record.status = SessionStatus::Paused;
        record.exit_code = None;
    } else {
        record.status = SessionStatus::Running;
        record.exit_code = None;
    }

    record.status != original_status || record.exit_code != original_exit_code
}

fn load_reconciled_session_file(path: &Path) -> Result<SessionRecord> {
    let mut record = load_session_file(path)?;
    if reconcile_session_record(&mut record) {
        let _ = update_session_file(path, &record);
    }
    Ok(record)
}

/// Returns the canonical session registry without creating it.
///
/// Use [`ensure_sessions_dir()`] when writing session files.
pub fn sessions_dir() -> Result<PathBuf> {
    crate::state_paths::sessions_dir()
}

/// Returns the canonical session registry, creating with mode 0o700 if needed.
pub(crate) fn ensure_sessions_dir() -> Result<PathBuf> {
    let dir = sessions_dir()?;
    ensure_private_dir(&dir)
}

fn ensure_private_dir(dir: &Path) -> Result<PathBuf> {
    if dir.exists() {
        validate_sessions_dir(dir)?;
        return Ok(dir.to_path_buf());
    }
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(dir).map_err(|e| NonoError::ConfigWrite {
            path: dir.to_path_buf(),
            source: e,
        })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|e| NonoError::ConfigWrite {
            path: dir.to_path_buf(),
            source: e,
        })?;
    }
    Ok(dir.to_path_buf())
}

fn validate_sessions_dir(dir: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(dir).map_err(|e| NonoError::ConfigWrite {
        path: dir.to_path_buf(),
        source: e,
    })?;

    if metadata.file_type().is_symlink() {
        return Err(NonoError::ConfigParse(format!(
            "{} must not be a symlink",
            dir.display()
        )));
    }

    if !metadata.is_dir() {
        return Err(NonoError::ConfigParse(format!(
            "{} exists but is not a directory. Remove it and retry.",
            dir.display()
        )));
    }

    #[cfg(unix)]
    {
        let current_uid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != current_uid {
            return Err(NonoError::ConfigParse(format!(
                "{} is owned by uid {}, expected {}",
                dir.display(),
                metadata.uid(),
                current_uid
            )));
        }

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(NonoError::ConfigParse(format!(
                "{} must not be group/world accessible; chmod 700 and retry",
                dir.display()
            )));
        }
    }

    Ok(())
}

/// Generate a 16-character hex session ID.
pub fn generate_session_id() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let bytes: [u8; 8] = rng.random();
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
    )
}

/// Generate a random two-word name (adjective-noun) for unnamed sessions.
pub fn generate_random_name() -> String {
    use rand::RngExt;
    let adjectives = [
        "bold", "calm", "dark", "fast", "gold", "keen", "lean", "mild", "neat", "pale", "pure",
        "rare", "safe", "tall", "warm", "wise",
    ];
    let nouns = [
        "arch", "beam", "core", "dart", "edge", "flux", "gate", "haze", "iris", "jade", "knot",
        "link", "mesa", "node", "opus", "pine",
    ];
    let mut rng = rand::rng();
    let adj = adjectives[rng.random_range(0..adjectives.len())];
    let noun = nouns[rng.random_range(0..nouns.len())];
    format!("{}-{}", adj, noun)
}

/// List all sessions, enriched with liveness checks.
///
/// Returns sessions sorted by start time (newest first).
pub fn list_sessions() -> Result<Vec<SessionRecord>> {
    let mut sessions = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let legacy_roots = crate::state_paths::LegacyRootSet::resolve()?;

    for dir in crate::state_paths::session_registry_dirs_for_read()? {
        if !dir.exists() {
            continue;
        }
        validate_sessions_dir(&dir)?;

        let entries = std::fs::read_dir(&dir).map_err(|e| NonoError::ConfigWrite {
            path: dir.clone(),
            source: e,
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".events.json"))
            {
                continue;
            }

            match load_reconciled_session_file(&path) {
                Ok(record) => {
                    if seen_ids.insert(record.session_id.clone()) {
                        legacy_roots.warn_if_legacy_session_file_read(&path);
                        sessions.push(record);
                    }
                }
                Err(e) => {
                    debug!("Skipping corrupt session file {}: {}", path.display(), e);
                }
            }
        }
    }

    sessions.sort_by(|a, b| b.started.cmp(&a.started));
    Ok(sessions)
}

/// Load a session by ID prefix or name match.
///
/// First tries to match the query as a session ID prefix. If no ID matches,
/// tries matching against session names. Returns an error if no match or
/// multiple matches are found.
pub fn load_session(query: &str) -> Result<SessionRecord> {
    let mut id_matches = Vec::new();
    let mut name_matches = Vec::new();
    let legacy_roots = crate::state_paths::LegacyRootSet::resolve()?;

    for dir in crate::state_paths::session_registry_dirs_for_read()? {
        if !dir.exists() {
            continue;
        }
        validate_sessions_dir(&dir)?;
        let entries = std::fs::read_dir(&dir).map_err(|e| NonoError::ConfigWrite {
            path: dir.clone(),
            source: e,
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".events.json"))
            {
                continue;
            }
            let file_name = match path.file_stem().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            if file_name.starts_with(query) {
                match load_reconciled_session_file(&path) {
                    Ok(record) => {
                        legacy_roots.warn_if_legacy_session_file_read(&path);
                        id_matches.push(record);
                    }
                    Err(e) => debug!("Skipping corrupt session file {}: {}", path.display(), e),
                }
            } else {
                match load_reconciled_session_file(&path) {
                    Ok(record) => {
                        if record.name.as_deref() == Some(query) {
                            legacy_roots.warn_if_legacy_session_file_read(&path);
                            name_matches.push(record);
                        }
                    }
                    Err(e) => debug!("Skipping corrupt session file {}: {}", path.display(), e),
                }
            }
        }
    }

    if id_matches.is_empty() && name_matches.is_empty() {
        return Err(NonoError::SessionNotFound(query.to_string()));
    }

    // Prefer ID matches over name matches; canonical dir is scanned first so
    // duplicates resolve to the XDG registry entry.
    let matches = if !id_matches.is_empty() {
        id_matches
    } else {
        name_matches
    };

    match matches.len() {
        0 => Err(NonoError::SessionNotFound(query.to_string())),
        1 => Ok(matches.into_iter().next().unwrap_or_else(|| {
            // SAFETY: we just checked len() == 1
            unreachable!()
        })),
        n => Err(NonoError::ConfigParse(format!(
            "Ambiguous query '{}': matches {} sessions. Use the session ID instead.",
            query, n
        ))),
    }
}

/// Update the attachment state of a session on disk.
pub fn update_session_attachment(
    session_id: &str,
    new_attachment: SessionAttachment,
) -> Result<()> {
    let dir = ensure_sessions_dir()?;
    let path = session_record_path(&dir, session_id)?;
    let mut record = load_session_file(&path)?;
    record.attachment = new_attachment;
    update_session_file(&path, &record)
}

/// Check if a process is alive and matches the expected start time.
///
/// Returns `false` if the PID is dead or has been recycled (start time mismatch).
pub fn is_process_alive(pid: u32, expected_start_epoch: u64) -> bool {
    process_matches_session(
        pid_liveness(pid),
        get_process_start_time(pid),
        expected_start_epoch,
    )
}

fn is_process_stopped(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let stat_path = format!("/proc/{}/stat", pid);
        let content = match std::fs::read_to_string(stat_path) {
            Ok(content) => content,
            Err(_) => return false,
        };
        let after_comm = match content.rfind(')') {
            Some(idx) => idx + 1,
            None => return false,
        };
        let mut fields = content[after_comm..].split_whitespace();
        matches!(fields.next(), Some("T" | "t"))
    }

    #[cfg(target_os = "macos")]
    {
        proc_bsd_info(pid).is_some_and(|info| info.pbi_status == SSTOP)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessLiveness {
    Running,
    RunningNoPermission,
    NotRunning,
}

/// Check if a PID is currently running (signal 0 check).
fn pid_liveness(pid: u32) -> ProcessLiveness {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);
    match kill(nix_pid, None) {
        Ok(()) => ProcessLiveness::Running,
        Err(nix::errno::Errno::ESRCH) => ProcessLiveness::NotRunning,
        Err(nix::errno::Errno::EPERM) => ProcessLiveness::RunningNoPermission,
        _ => ProcessLiveness::Running,
    }
}

fn process_matches_session(
    liveness: ProcessLiveness,
    actual_start_epoch: Option<u64>,
    expected_start_epoch: u64,
) -> bool {
    match liveness {
        ProcessLiveness::NotRunning => false,
        ProcessLiveness::Running => match actual_start_epoch {
            Some(actual_start) => actual_start == expected_start_epoch,
            None => false,
        },
        ProcessLiveness::RunningNoPermission => match actual_start_epoch {
            Some(actual_start) => actual_start == expected_start_epoch,
            None => false,
        },
    }
}

/// Get the process start time for PID recycling defense.
///
/// Returns the start time as an opaque u64 value that can be compared for equality.
/// The exact semantics differ by platform:
/// - Linux: start time in clock ticks from `/proc/{pid}/stat` field 22
/// - macOS: start time in microseconds from `proc_pidinfo(PROC_PIDTASKINFO)`
#[cfg(target_os = "linux")]
pub fn get_process_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = std::fs::read_to_string(stat_path).ok()?;

    // Field 22 (1-indexed) is starttime. The comm field (2) can contain spaces
    // and parens, so find the last ')' to skip past it.
    let after_comm = content.rfind(')')? + 1;
    let fields: Vec<&str> = content[after_comm..].split_whitespace().collect();
    // After comm closing paren, fields are 0-indexed starting from field 3 (state).
    // starttime is field 22, so index 22-3 = 19.
    fields.get(19)?.parse::<u64>().ok()
}

#[cfg(target_os = "macos")]
pub fn get_process_start_time(pid: u32) -> Option<u64> {
    let info = proc_bsd_info(pid)?;
    Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

/// Get the current process's start time (for recording in session state).
pub fn current_process_start_epoch() -> u64 {
    get_process_start_time(std::process::id()).unwrap_or(0)
}

// --- File I/O helpers ---

fn validate_session_id(session_id: &str) -> Result<()> {
    let valid = !session_id.is_empty()
        && session_id.len() <= 64
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(NonoError::ConfigParse(format!(
            "Invalid session id '{}'",
            session_id
        )))
    }
}

fn session_record_path(dir: &Path, session_id: &str) -> Result<PathBuf> {
    validate_session_id(session_id)?;
    Ok(dir.join(format!("{session_id}.json")))
}

pub(crate) fn session_file_path(session_id: &str) -> Result<PathBuf> {
    let dir = ensure_sessions_dir()?;
    session_record_path(&dir, session_id)
}

pub(crate) fn session_socket_path(session_id: &str) -> Result<PathBuf> {
    validate_session_id(session_id)?;
    Ok(ensure_sessions_dir()?.join(format!("{session_id}.sock")))
}

/// Usable bytes in an AF_UNIX `sockaddr_un.sun_path`, i.e. `sizeof(sun_path) - 1`
///
/// `std`'s socket-address builder rejects any `bind(2)`/`connect(2)` path whose length is `>=
/// sizeof(sun_path)`. See `man 4 unix` (macOS) / `man 7 unix` (Linux).
#[cfg(target_os = "macos")]
pub(crate) const SUN_PATH_MAX: usize = 103;
#[cfg(not(target_os = "macos"))]
pub(crate) const SUN_PATH_MAX: usize = 107;

/// Path used to `bind(2)`/`connect(2)` a session's attach socket.
///
/// The socket itself always lives at [`session_socket_path`]
/// (`$XDG_STATE_HOME/nono/sessions/<id>.sock`), but that absolute path can exceed
/// [`SUN_PATH_MAX`] when `$XDG_STATE_HOME` is too long, which makes `bind`/`connect`
/// fail with `ENAMETOOLONG`. There is no `bindat`/`connectat` to anchor a
/// relative address, so instead we route through a short, per-user directory
/// symlink (`<short-base>/nono-<uid>` → the sessions directory). Addressing the
/// socket as `<link>/<id>.sock` keeps the `sun_path` the kernel sees within the
/// limit while it resolves to the same socket inode.
#[cfg(unix)]
pub(crate) fn session_socket_bind_path(session_id: &str) -> Result<PathBuf> {
    validate_session_id(session_id)?;
    let sessions = ensure_sessions_dir()?;
    let leaf = format!("{session_id}.sock");
    let uid = nix::unistd::geteuid().as_raw();
    let link = ensure_socket_link(&sessions, uid, leaf.len())?;
    let bind_path = link.join(&leaf);
    if bind_path.as_os_str().len() > SUN_PATH_MAX {
        return Err(NonoError::ConfigParse(format!(
            "Session socket path {} exceeds the {}-byte sun_path limit even via the short link",
            bind_path.display(),
            SUN_PATH_MAX
        )));
    }
    Ok(bind_path)
}

/// Short, per-user base directory that holds the session-socket symlink.
///
/// The base must itself be short, so we prefer a private `$XDG_RUNTIME_DIR` (i.e.
/// `/run/user/<uid>`) and fall back to `/tmp`.
#[cfg(unix)]
fn socket_link_base(link_name: &str, leaf_len: usize) -> PathBuf {
    let fits = |base: &Path| {
        base.as_os_str()
            .len()
            .saturating_add(1)
            .saturating_add(link_name.len())
            .saturating_add(1)
            .saturating_add(leaf_len)
            <= SUN_PATH_MAX
    };
    if let Ok(raw) = std::env::var("XDG_RUNTIME_DIR") {
        let base = PathBuf::from(&raw);
        if base.is_absolute() && fits(&base) {
            return base;
        }
    }
    PathBuf::from("/tmp")
}

/// Create (or reuse) the short directory symlink pointing at `sessions`, and
/// return its path.
///
/// The link is keyed by both `uid` and a short hash of the target.
#[cfg(unix)]
fn ensure_socket_link(sessions: &Path, uid: u32, leaf_len: usize) -> Result<PathBuf> {
    use std::hash::{Hash, Hasher};

    let target_canon = std::fs::canonicalize(sessions).map_err(|e| NonoError::ConfigWrite {
        path: sessions.to_path_buf(),
        source: e,
    })?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    target_canon.as_os_str().hash(&mut hasher);
    let tag = hasher.finish() as u32;
    let link_name = format!("nono-{uid}-{tag:08x}");
    let link = socket_link_base(&link_name, leaf_len).join(&link_name);
    create_socket_link(&link, &target_canon, uid)?;
    Ok(link)
}

/// Establish `link` as a symlink to `target`.
#[cfg(unix)]
fn create_socket_link(link: &Path, target: &Path, uid: u32) -> Result<()> {
    let target_canon = std::fs::canonicalize(target).map_err(|e| NonoError::ConfigWrite {
        path: target.to_path_buf(),
        source: e,
    })?;

    for _ in 0..8 {
        match std::os::unix::fs::symlink(target, link) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(link).map_err(|e| NonoError::ConfigWrite {
                    path: link.to_path_buf(),
                    source: e,
                })?;
                if !meta.file_type().is_symlink() {
                    return Err(NonoError::ConfigParse(format!(
                        "Refusing to use session socket link {}: not a symlink",
                        link.display()
                    )));
                }
                if meta.uid() != uid {
                    return Err(NonoError::ConfigParse(format!(
                        "Refusing to use session socket link {} owned by uid {}, expected {}",
                        link.display(),
                        meta.uid(),
                        uid
                    )));
                }
                match std::fs::canonicalize(link) {
                    Ok(current) if current == target_canon => return Ok(()),
                    _ => {
                        std::fs::remove_file(link).map_err(|e| NonoError::ConfigWrite {
                            path: link.to_path_buf(),
                            source: e,
                        })?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(NonoError::ConfigWrite {
                    path: link.to_path_buf(),
                    source: e,
                });
            }
        }
    }
    Err(NonoError::ConfigParse(format!(
        "Failed to establish session socket link {} after repeated races",
        link.display()
    )))
}

pub(crate) fn session_events_path(session_id: &str) -> Result<PathBuf> {
    validate_session_id(session_id)?;
    Ok(sessions_dir()?.join(format!("{session_id}.events.ndjson")))
}

fn create_temp_session_file(path: &Path) -> Result<(PathBuf, File)> {
    let parent = path.parent().ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "Session file path {} has no parent directory",
            path.display()
        ))
    })?;
    validate_sessions_dir(parent)?;

    for _ in 0..16 {
        let candidate = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("session"),
            generate_session_id()
        ));

        #[cfg(unix)]
        let file_result = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&candidate);

        #[cfg(not(unix))]
        let file_result = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate);

        match file_result {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(NonoError::ConfigWrite {
                    path: candidate,
                    source: e,
                });
            }
        }
    }

    Err(NonoError::ConfigParse(format!(
        "Failed to allocate secure temporary session file for {}",
        path.display()
    )))
}

/// Write a session file atomically using create_new (O_EXCL).
fn write_session_file(path: &Path, record: &SessionRecord) -> Result<()> {
    let json = serde_json::to_string_pretty(record)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to serialize session: {}", e)))?;

    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source: e,
        })?;

    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source: e,
        })?;

    file.write_all(json.as_bytes())
        .map_err(|e| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source: e,
        })?;
    sync_file(&file, path)?;
    sync_parent_dir(path)
}

/// Update a session file using write-to-temp + rename for atomicity.
fn update_session_file(path: &Path, record: &SessionRecord) -> Result<()> {
    let json = serde_json::to_string_pretty(record)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to serialize session: {}", e)))?;

    let (tmp_path, mut file) = create_temp_session_file(path)?;

    file.write_all(json.as_bytes())
        .map_err(|e| NonoError::ConfigWrite {
            path: tmp_path.clone(),
            source: e,
        })?;
    sync_file(&file, &tmp_path)?;

    std::fs::rename(&tmp_path, path).map_err(|e| NonoError::ConfigWrite {
        path: path.to_path_buf(),
        source: e,
    })?;
    sync_parent_dir(path)
}

fn sync_file(file: &File, path: &Path) -> Result<()> {
    file.sync_all().map_err(|e| NonoError::ConfigWrite {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    let dir = File::open(parent).map_err(|e| NonoError::ConfigWrite {
        path: parent.to_path_buf(),
        source: e,
    })?;
    dir.sync_all().map_err(|e| NonoError::ConfigWrite {
        path: parent.to_path_buf(),
        source: e,
    })
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

/// Load a session record from a JSON file.
fn load_session_file(path: &Path) -> Result<SessionRecord> {
    #[cfg(unix)]
    {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source: e,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(NonoError::ConfigParse(format!(
                "Refusing to load session file symlink {}",
                path.display()
            )));
        }
        if metadata.file_type().is_socket() {
            return Err(NonoError::ConfigParse(format!(
                "Refusing to load session socket {} as session file",
                path.display()
            )));
        }
    }

    let content = std::fs::read_to_string(path).map_err(|e| NonoError::ConfigWrite {
        path: path.to_path_buf(),
        source: e,
    })?;
    serde_json::from_str(&content)
        .map_err(|e| NonoError::ConfigParse(format!("Invalid session file: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn make_private_dir(path: &Path) {
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, perms).expect("chmod 700");
    }

    #[cfg(unix)]
    #[test]
    fn create_socket_link_creates_symlink_to_target() {
        let base = tempdir().expect("tempdir");
        let target = tempdir().expect("tempdir");
        let uid = nix::unistd::geteuid().as_raw();
        let link = base.path().join("nono-link");

        create_socket_link(&link, target.path(), uid).expect("link is created");

        let meta = std::fs::symlink_metadata(&link).expect("link exists");
        assert!(meta.file_type().is_symlink(), "entry must be a symlink");
        assert_eq!(
            std::fs::canonicalize(&link).expect("resolves"),
            std::fs::canonicalize(target.path()).expect("resolves"),
            "link must resolve to the target sessions dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_socket_link_reuses_matching_link() {
        let base = tempdir().expect("tempdir");
        let target = tempdir().expect("tempdir");
        let uid = nix::unistd::geteuid().as_raw();
        let link = base.path().join("nono-link");

        create_socket_link(&link, target.path(), uid).expect("first create");

        create_socket_link(&link, target.path(), uid).expect("reuse existing link");
        assert_eq!(
            std::fs::canonicalize(&link).expect("resolves"),
            std::fs::canonicalize(target.path()).expect("resolves"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_socket_link_replaces_stale_target() {
        let base = tempdir().expect("tempdir");
        let old_target = tempdir().expect("tempdir");
        let new_target = tempdir().expect("tempdir");
        let uid = nix::unistd::geteuid().as_raw();
        let link = base.path().join("nono-link");

        // A link we own that points at a since-abandoned dir (e.g. after
        // `$XDG_STATE_HOME` changed) is repointed at the current target.
        std::os::unix::fs::symlink(old_target.path(), &link).expect("seed stale link");
        create_socket_link(&link, new_target.path(), uid).expect("stale link is replaced");
        assert_eq!(
            std::fs::canonicalize(&link).expect("resolves"),
            std::fs::canonicalize(new_target.path()).expect("resolves"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_socket_link_refuses_non_symlink() {
        let base = tempdir().expect("tempdir");
        let target = tempdir().expect("tempdir");
        let uid = nix::unistd::geteuid().as_raw();
        let link = base.path().join("nono-link");

        // A plain file where the link should be is refused, not removed.
        std::fs::write(&link, b"not a symlink").expect("seed regular file");
        let err =
            create_socket_link(&link, target.path(), uid).expect_err("must refuse non-symlink");
        assert!(
            matches!(err, NonoError::ConfigParse(_)),
            "expected a refusal, got {err:?}"
        );
        assert!(link.exists(), "the refused entry must be left untouched");
    }

    #[cfg(unix)]
    #[test]
    fn create_socket_link_refuses_foreign_owner() {
        let base = tempdir().expect("tempdir");
        let target = tempdir().expect("tempdir");
        let link = base.path().join("nono-link");
        std::os::unix::fs::symlink(target.path(), &link).expect("seed our link");

        let foreign = nix::unistd::geteuid().as_raw().wrapping_add(1);
        let err = create_socket_link(&link, target.path(), foreign)
            .expect_err("must refuse a link owned by another uid");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    fn test_session_record_roundtrip() {
        let record = SessionRecord {
            session_id: "a3f7c2".to_string(),
            name: Some("test".to_string()),
            supervisor_pid: 1234,
            child_pid: 1235,
            started: "2026-03-07T10:00:00+00:00".to_string(),
            started_epoch: 12345678,
            status: SessionStatus::Running,
            attachment: SessionAttachment::Attached,
            exit_code: None,
            command: vec!["claude".to_string()],
            profile: Some("developer".to_string()),
            workdir: PathBuf::from("/home/user/project"),
            network: "allowed".to_string(),
            rollback_session: None,
        };

        let json = serde_json::to_string(&record).expect("serialize");
        let restored: SessionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.session_id, "a3f7c2");
        assert_eq!(restored.name, Some("test".to_string()));
        assert_eq!(restored.status, SessionStatus::Running);
        assert_eq!(restored.attachment, SessionAttachment::Attached);
        assert!(restored.exit_code.is_none());
    }

    #[test]
    fn test_session_status_serde() {
        let running: SessionStatus = serde_json::from_str("\"running\"").expect("parse");
        assert_eq!(running, SessionStatus::Running);

        let exited: SessionStatus = serde_json::from_str("\"exited\"").expect("parse");
        assert_eq!(exited, SessionStatus::Exited);
    }

    #[test]
    fn test_write_and_load_session_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.json");

        let record = SessionRecord {
            session_id: "abc123".to_string(),
            name: None,
            supervisor_pid: 100,
            child_pid: 101,
            started: "2026-03-07T10:00:00+00:00".to_string(),
            started_epoch: 99999,
            status: SessionStatus::Running,
            attachment: SessionAttachment::Attached,
            exit_code: None,
            command: vec!["echo".to_string(), "hello".to_string()],
            profile: None,
            workdir: PathBuf::from("/tmp"),
            network: "blocked".to_string(),
            rollback_session: None,
        };

        write_session_file(&path, &record).expect("write");
        let loaded = load_session_file(&path).expect("load");
        assert_eq!(loaded.session_id, "abc123");
        assert_eq!(loaded.command, vec!["echo", "hello"]);
        assert_eq!(loaded.network, "blocked");
    }

    #[test]
    fn test_update_session_file() {
        let dir = tempdir().expect("tempdir");
        #[cfg(unix)]
        make_private_dir(dir.path());
        let path = dir.path().join("update.json");

        let mut record = SessionRecord {
            session_id: "def456".to_string(),
            name: None,
            supervisor_pid: 200,
            child_pid: 201,
            started: "2026-03-07T10:00:00+00:00".to_string(),
            started_epoch: 88888,
            status: SessionStatus::Running,
            attachment: SessionAttachment::Attached,
            exit_code: None,
            command: vec!["sleep".to_string(), "10".to_string()],
            profile: None,
            workdir: PathBuf::from("/tmp"),
            network: "allowed".to_string(),
            rollback_session: None,
        };

        write_session_file(&path, &record).expect("write");

        record.status = SessionStatus::Exited;
        record.exit_code = Some(0);
        update_session_file(&path, &record).expect("update");

        let loaded = load_session_file(&path).expect("load");
        assert_eq!(loaded.status, SessionStatus::Exited);
        assert_eq!(loaded.exit_code, Some(0));
    }

    #[test]
    fn test_generate_session_id_length() {
        let id = generate_session_id();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_session_guard_drop_marks_exited() {
        let dir = tempdir().expect("tempdir");
        #[cfg(unix)]
        make_private_dir(dir.path());
        let path = dir.path().join("sessions");
        std::fs::create_dir_all(&path).expect("mkdir");
        #[cfg(unix)]
        make_private_dir(&path);

        // We can't easily test SessionGuard::new because it uses sessions_dir().
        // Instead, test the update_session_file + load roundtrip that Drop uses.
        let mut record = SessionRecord {
            session_id: "guard1".to_string(),
            name: None,
            supervisor_pid: 300,
            child_pid: 301,
            started: "2026-03-07T10:00:00+00:00".to_string(),
            started_epoch: 77777,
            status: SessionStatus::Running,
            attachment: SessionAttachment::Attached,
            exit_code: None,
            command: vec!["test".to_string()],
            profile: None,
            workdir: PathBuf::from("/tmp"),
            network: "allowed".to_string(),
            rollback_session: None,
        };

        let file_path = path.join("guard1.json");
        write_session_file(&file_path, &record).expect("write");

        // Simulate what Drop does
        record.status = SessionStatus::Exited;
        record.exit_code = Some(-1);
        update_session_file(&file_path, &record).expect("update");

        let loaded = load_session_file(&file_path).expect("load");
        assert_eq!(loaded.status, SessionStatus::Exited);
        assert_eq!(loaded.exit_code, Some(-1));
    }

    #[test]
    fn test_get_current_process_start_time() {
        let start = get_process_start_time(std::process::id());
        assert!(start.is_some(), "Should be able to get own start time");
    }

    #[test]
    fn test_pid_recycling_dead_pid() {
        // PID 1 (init/launchd) is always running but has a different start time
        // PID 999999 is almost certainly not running
        assert!(!is_process_alive(999999, 0));
    }

    #[test]
    fn test_process_matches_session_requires_start_time_on_eperm() {
        assert!(!process_matches_session(
            ProcessLiveness::RunningNoPermission,
            None,
            123
        ));
    }

    #[test]
    fn test_process_matches_session_accepts_matching_start_time_on_eperm() {
        assert!(process_matches_session(
            ProcessLiveness::RunningNoPermission,
            Some(123),
            123
        ));
    }

    #[test]
    fn test_process_matches_session_requires_start_time_when_accessible() {
        assert!(!process_matches_session(
            ProcessLiveness::Running,
            None,
            123
        ));
    }

    #[test]
    fn test_load_session_prefix_match() {
        let dir = tempdir().expect("tempdir");
        let sessions_path = dir.path().join("sessions");
        std::fs::create_dir_all(&sessions_path).expect("mkdir");

        let record = SessionRecord {
            session_id: "aabbcc".to_string(),
            name: None,
            supervisor_pid: 400,
            child_pid: 401,
            started: "2026-03-07T10:00:00+00:00".to_string(),
            started_epoch: 66666,
            status: SessionStatus::Exited,
            attachment: SessionAttachment::Detached,
            exit_code: Some(0),
            command: vec!["echo".to_string()],
            profile: None,
            workdir: PathBuf::from("/tmp"),
            network: "allowed".to_string(),
            rollback_session: None,
        };

        write_session_file(&sessions_path.join("aabbcc.json"), &record).expect("write");

        // load_session uses sessions_dir() which points to ~/.nono/sessions,
        // so we can't test prefix matching here without mocking. The file I/O
        // roundtrip is tested above.
    }
}
