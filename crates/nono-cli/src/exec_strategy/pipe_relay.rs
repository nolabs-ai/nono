//! Supervised non-PTY pipe relay for session terminal capture (NEP-0010 §2.1, §3.2).
//!
//! When a supervised session runs without a PTY (`pty_pair` is `None`), this
//! relay interposes pipes on the child's stdout and stderr (and stdin when
//! `input` capture is enabled), forwards bytes unchanged to the supervisor's
//! stdio, and feeds the protected capture pipeline.

use crate::terminal_capture::events::OutputStream;
use crate::terminal_capture::{CaptureSummary, InputCapture, TerminalCapture};
use nix::errno::Errno;
use nix::libc;
use nono::{NonoError, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

const RELAY_BUF_SIZE: usize = 8192;

/// Child-side raw descriptors passed across `fork()` / `clone_files::spawn()`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PipeChildFds {
    pub(crate) stdin_read: Option<RawFd>,
    pub(crate) stdout_write: RawFd,
    pub(crate) stderr_write: RawFd,
}

impl PipeChildFds {
    /// Record descriptors that the forked child must preserve until `setup_child_pipes()`.
    pub(crate) fn push_keep_fds(self, keep: &mut Vec<i32>) {
        if let Some(fd) = self.stdin_read {
            keep.push(fd);
        }
        keep.push(self.stdout_write);
        keep.push(self.stderr_write);
    }

    /// Redirect stdin/stdout/stderr onto the capture pipes in the `fork()` child.
    ///
    /// # Safety
    ///
    /// Must be called only in the post-fork child process with valid pipe
    /// descriptors owned by this launch (`>= 3`). Uses async-signal-safe syscalls only.
    pub(crate) unsafe fn setup_child_pipes(self) {
        unsafe {
            dup2_and_close_raw(self.stdout_write, libc::STDOUT_FILENO);
            dup2_and_close_raw(self.stderr_write, libc::STDERR_FILENO);
            if let Some(stdin_fd) = self.stdin_read {
                dup2_and_close_raw(stdin_fd, libc::STDIN_FILENO);
            }
        }
    }
}

/// Async-signal-safe `dup2` + close for the post-fork child.
///
/// # Safety
///
/// `src` must be a valid descriptor `>= 3` in the child process.
unsafe fn dup2_and_close_raw(src: RawFd, target: RawFd) {
    if src == target {
        // Clear FD_CLOEXEC if somehow already on target.
        // SAFETY: async-signal-safe fcntl on valid descriptor.
        let _ = unsafe { libc::fcntl(src, libc::F_SETFD, 0) };
        return;
    }
    loop {
        // SAFETY: async-signal-safe dup2; clears FD_CLOEXEC on `target`.
        let rc = unsafe { libc::dup2(src, target) };
        if rc >= 0 {
            break;
        }
        if Errno::last() != Errno::EINTR {
            const MSG: &[u8] = b"nono: failed to redirect stdio capture pipe\n";
            // SAFETY: write and _exit are async-signal-safe.
            unsafe {
                libc::write(
                    libc::STDERR_FILENO,
                    MSG.as_ptr().cast::<libc::c_void>(),
                    MSG.len(),
                );
                libc::_exit(126);
            }
        }
    }
    // SAFETY: src >= 3 and was duplicated onto target.
    unsafe {
        libc::close(src);
    }
}

/// Parent-side relay owning the pipe endpoints and [`TerminalCapture`].
pub(crate) struct PipeCaptureRelay {
    stdout_read: Option<OwnedFd>,
    stderr_read: Option<OwnedFd>,
    stdin_write: Option<OwnedFd>,
    stdin_pending: Vec<u8>,
    stdin_eof: bool,
    child_stdin_read: Option<OwnedFd>,
    child_stdout_write: Option<OwnedFd>,
    child_stderr_write: Option<OwnedFd>,
    capture: Option<TerminalCapture>,
}

impl PipeCaptureRelay {
    /// Create stdio pipes before `fork()` / `clone_files::spawn()`.
    pub(crate) fn new(capture: TerminalCapture) -> Result<Self> {
        let (stdout_read, child_stdout_write) = make_pipe_above_stdio()?;
        set_nonblocking(&stdout_read)?;

        let (stderr_read, child_stderr_write) = make_pipe_above_stdio()?;
        set_nonblocking(&stderr_read)?;

        let (child_stdin_read, stdin_write) = if capture.input_mode() == InputCapture::On {
            let (read_end, write_end) = make_pipe_above_stdio()?;
            set_nonblocking(&write_end)?;
            (Some(read_end), Some(write_end))
        } else {
            (None, None)
        };

        Ok(Self {
            stdout_read: Some(stdout_read),
            stderr_read: Some(stderr_read),
            stdin_write,
            stdin_pending: Vec::new(),
            stdin_eof: false,
            child_stdin_read,
            child_stdout_write: Some(child_stdout_write),
            child_stderr_write: Some(child_stderr_write),
            capture: Some(capture),
        })
    }

    /// Borrow child-side FD numbers for the child setup path.
    pub(crate) fn child_fds(&self) -> Option<PipeChildFds> {
        Some(PipeChildFds {
            stdin_read: self.child_stdin_read.as_ref().map(AsRawFd::as_raw_fd),
            stdout_write: self.child_stdout_write.as_ref()?.as_raw_fd(),
            stderr_write: self.child_stderr_write.as_ref()?.as_raw_fd(),
        })
    }

    /// Close child-side pipe ends in the parent immediately after spawning the child.
    pub(crate) fn release_child_ends(&mut self) {
        self.child_stdin_read = None;
        self.child_stdout_write = None;
        self.child_stderr_write = None;
    }

    /// Start the recorder thread after `fork()`.
    ///
    /// If starting a required recording fails, returns an error so the caller can
    /// terminate the child and abort. If optional, drops capture with a warning
    /// while keeping the stdio relay alive so the child's pipes do not break.
    pub(crate) fn activate_capture(&mut self) -> Result<()> {
        let Some(capture) = self.capture.as_mut() else {
            return Ok(());
        };
        if let Err(e) = capture.activate() {
            if capture.is_required() {
                return Err(NonoError::SandboxInit(format!(
                    "required session recording cannot start: {e}"
                )));
            }
            eprintln!("[nono] Warning: session recording is off for this session: {e}");
            self.capture = None;
        }
        Ok(())
    }

    /// Descriptors to include in `poll()`: `(stdout_read, stderr_read, stdin_in, stdin_out)`.
    pub(crate) fn poll_fds(&self) -> (RawFd, RawFd, RawFd, RawFd) {
        let stdout_fd = self.stdout_read.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let stderr_fd = self.stderr_read.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let stdin_in_fd =
            if self.stdin_write.is_some() && !self.stdin_eof && self.stdin_pending.is_empty() {
                libc::STDIN_FILENO
            } else {
                -1
            };
        let stdin_out_fd = if self.stdin_pending.is_empty() {
            -1
        } else {
            self.stdin_write.as_ref().map_or(-1, AsRawFd::as_raw_fd)
        };
        (stdout_fd, stderr_fd, stdin_in_fd, stdin_out_fd)
    }

    /// Whether either output pipe is still open.
    pub(crate) fn has_active_output(&self) -> bool {
        self.stdout_read.is_some() || self.stderr_read.is_some()
    }

    /// Service ready pipe events from `poll()`.
    pub(crate) fn handle_poll_events(
        &mut self,
        stdout_revents: i16,
        stderr_revents: i16,
        stdin_in_revents: i16,
        stdin_out_revents: i16,
    ) {
        if stdout_revents != 0 {
            self.relay_output_once(OutputStream::Stdout, stdout_revents);
        }
        if stderr_revents != 0 {
            self.relay_output_once(OutputStream::Stderr, stderr_revents);
        }
        if stdin_out_revents != 0 {
            self.flush_stdin_pending(stdin_out_revents);
        }
        if stdin_in_revents != 0 {
            self.relay_stdin_once(stdin_in_revents);
        }
    }

    /// Poll the capture writer for fatal failures on required destinations.
    pub(crate) fn service_capture(&mut self) -> Option<String> {
        self.capture.as_mut().and_then(TerminalCapture::tick)
    }

    /// Drain remaining child stdout/stderr after exit until EOF or `quiet_timeout`.
    pub(crate) fn drain_output(&mut self, quiet_timeout: Duration) {
        // Close parent->child stdin if still open; child has exited.
        self.stdin_write = None;
        self.stdin_pending.clear();

        let mut quiet_deadline = Instant::now() + quiet_timeout;
        while self.has_active_output() {
            let now = Instant::now();
            if now >= quiet_deadline {
                break;
            }
            let remaining = quiet_deadline.saturating_duration_since(now);
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            let stdout_fd = self.stdout_read.as_ref().map_or(-1, AsRawFd::as_raw_fd);
            let stderr_fd = self.stderr_read.as_ref().map_or(-1, AsRawFd::as_raw_fd);
            let mut pfds = [
                libc::pollfd {
                    fd: stdout_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stderr_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: pfds is a valid 2-element array.
            let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, timeout_ms) };
            if ret > 0 {
                let mut got_data = false;
                if pfds[0].revents != 0 {
                    got_data |= self.relay_output_once(OutputStream::Stdout, pfds[0].revents);
                }
                if pfds[1].revents != 0 {
                    got_data |= self.relay_output_once(OutputStream::Stderr, pfds[1].revents);
                }
                if got_data {
                    quiet_deadline = Instant::now() + quiet_timeout;
                }
            } else if ret < 0 {
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            } else {
                break;
            }
        }
    }

    /// Finish capture and return its summary.
    pub(crate) fn finish_capture(mut self, status: String) -> Option<CaptureSummary> {
        self.capture.take().map(|capture| capture.finish(status))
    }

    fn relay_output_once(&mut self, stream: OutputStream, revents: i16) -> bool {
        let (slot, target_fd) = match stream {
            OutputStream::Stdout => (&mut self.stdout_read, libc::STDOUT_FILENO),
            OutputStream::Stderr => (&mut self.stderr_read, libc::STDERR_FILENO),
            OutputStream::Pty => return false,
        };
        let Some(raw_fd) = slot.as_ref().map(AsRawFd::as_raw_fd) else {
            return false;
        };
        if revents & libc::POLLNVAL != 0 {
            *slot = None;
            return false;
        }
        let mut buf = [0_u8; RELAY_BUF_SIZE];
        let mut got_data = false;
        loop {
            match read_fd_nonblocking(raw_fd, &mut buf) {
                ReadOutcome::Data(n) => {
                    got_data = true;
                    let chunk = &buf[..n];
                    if let Some(capture) = self.capture.as_mut() {
                        capture.output(stream, chunk);
                    }
                    if !write_all_fd(target_fd, chunk) {
                        // Downstream consumer closed our stdout/stderr; drop pipe end so
                        // child sees EPIPE/SIGPIPE naturally.
                        *slot = None;
                        break;
                    }
                }
                ReadOutcome::WouldBlock => {
                    if revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                        *slot = None;
                    }
                    break;
                }
                ReadOutcome::Closed => {
                    *slot = None;
                    break;
                }
            }
        }
        got_data
    }

    fn relay_stdin_once(&mut self, revents: i16) {
        if revents & libc::POLLNVAL != 0 {
            self.stdin_eof = true;
            if self.stdin_pending.is_empty() {
                self.stdin_write = None;
            }
            return;
        }
        let mut buf = [0_u8; RELAY_BUF_SIZE];
        match read_fd_nonblocking(libc::STDIN_FILENO, &mut buf) {
            ReadOutcome::Data(n) => {
                let chunk = &buf[..n];
                if let Some(capture) = self.capture.as_mut() {
                    capture.input("local", chunk);
                }
                self.write_child_stdin(chunk);
            }
            ReadOutcome::WouldBlock => {
                if revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    self.stdin_eof = true;
                    if self.stdin_pending.is_empty() {
                        self.stdin_write = None;
                    }
                }
            }
            ReadOutcome::Closed => {
                self.stdin_eof = true;
                if self.stdin_pending.is_empty() {
                    self.stdin_write = None;
                }
            }
        }
    }

    fn write_child_stdin(&mut self, chunk: &[u8]) {
        let Some(fd) = self.stdin_write.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        let mut offset = 0;
        while offset < chunk.len() {
            // SAFETY: valid write end of pipe and valid slice pointer/len.
            let written = unsafe {
                libc::write(
                    fd,
                    chunk[offset..].as_ptr().cast::<libc::c_void>(),
                    chunk.len() - offset,
                )
            };
            if written > 0 {
                offset += written as usize;
                continue;
            }
            let err = Errno::last();
            if err == Errno::EINTR {
                continue;
            }
            if err == Errno::EAGAIN || err == Errno::EWOULDBLOCK {
                self.stdin_pending.extend_from_slice(&chunk[offset..]);
                return;
            }
            // Broken pipe or write error: child closed stdin.
            self.stdin_write = None;
            self.stdin_pending.clear();
            return;
        }
    }

    fn flush_stdin_pending(&mut self, revents: i16) {
        if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            self.stdin_write = None;
            self.stdin_pending.clear();
            return;
        }
        let Some(fd) = self.stdin_write.as_ref().map(AsRawFd::as_raw_fd) else {
            self.stdin_pending.clear();
            return;
        };
        let mut offset = 0;
        while offset < self.stdin_pending.len() {
            // SAFETY: valid write end of pipe and valid slice pointer/len.
            let written = unsafe {
                libc::write(
                    fd,
                    self.stdin_pending[offset..].as_ptr().cast::<libc::c_void>(),
                    self.stdin_pending.len() - offset,
                )
            };
            if written > 0 {
                offset += written as usize;
                continue;
            }
            let err = Errno::last();
            if err == Errno::EINTR {
                continue;
            }
            if err == Errno::EAGAIN || err == Errno::EWOULDBLOCK {
                break;
            }
            self.stdin_write = None;
            self.stdin_pending.clear();
            return;
        }
        if offset > 0 {
            self.stdin_pending.drain(..offset);
        }
        if self.stdin_pending.is_empty() && self.stdin_eof {
            self.stdin_write = None;
        }
    }
}

enum ReadOutcome {
    Data(usize),
    WouldBlock,
    Closed,
}

fn read_fd_nonblocking(fd: RawFd, buf: &mut [u8]) -> ReadOutcome {
    loop {
        // SAFETY: fd is open and buf is a valid mutable byte slice.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            return ReadOutcome::Data(n as usize);
        }
        if n == 0 {
            return ReadOutcome::Closed;
        }
        let err = Errno::last();
        if err == Errno::EINTR {
            continue;
        }
        if err == Errno::EAGAIN || err == Errno::EWOULDBLOCK {
            return ReadOutcome::WouldBlock;
        }
        return ReadOutcome::Closed;
    }
}

/// Write all bytes to a parent stdio descriptor, tolerating `EINTR` and `EAGAIN`.
/// Returns `false` if the downstream descriptor broke (`EPIPE`) or errored.
fn write_all_fd(fd: RawFd, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        // SAFETY: fd is parent stdout/stderr and data pointer/len are valid.
        let n = unsafe { libc::write(fd, data.as_ptr().cast::<libc::c_void>(), data.len()) };
        if n > 0 {
            data = &data[n as usize..];
            continue;
        }
        if n == 0 {
            return false;
        }
        let err = Errno::last();
        if err == Errno::EINTR {
            continue;
        }
        if err == Errno::EAGAIN || err == Errno::EWOULDBLOCK {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: pfd is a valid 1-element pollfd struct.
            let _ = unsafe { libc::poll(&mut pfd, 1, 50) };
            continue;
        }
        return false;
    }
    true
}

fn make_pipe_above_stdio() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0_i32; 2];
    // SAFETY: fds is a valid 2-element array for pipe().
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to create capture pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: both descriptors were created by pipe() and are uniquely owned.
    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((
        above_stdio_cloexec(read_fd)?,
        above_stdio_cloexec(write_fd)?,
    ))
}

fn above_stdio_cloexec(fd: OwnedFd) -> Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        // SAFETY: fd is owned and valid.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(NonoError::SandboxInit(format!(
                "Failed to set FD_CLOEXEC on capture pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        return Ok(fd);
    }
    // SAFETY: fd is owned and valid; F_DUPFD_CLOEXEC duplicates >= 3 with FD_CLOEXEC.
    let duped = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duped < 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to move capture pipe above stdio: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: duped was checked >= 0 and is uniquely owned.
    Ok(unsafe { OwnedFd::from_raw_fd(duped) })
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    // SAFETY: fd is owned and valid.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to read capture pipe flags: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd is owned and valid.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to set O_NONBLOCK on capture pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::audit_integrity::AuditRecorder;
    use crate::terminal_capture::audit_events::{
        RecordingAuditEvent, parse_recording_event, terminal_chunk_file_name,
    };
    use crate::terminal_capture::writer::recording_dir;
    use crate::terminal_capture::{
        CaptureConfig, DEFAULT_CHUNK_MAX_BYTES, DEFAULT_CHUNK_MAX_DURATION, DEFAULT_MAX_BYTES,
    };
    use nono_proxy::SecretRegistry;
    use std::io::Write as _;
    use std::sync::{Arc, Mutex};

    #[test]
    fn drain_output_collects_stdout_and_stderr_independently() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-11-25T00:00:00Z".to_string(), vec!["cmd".to_string()])
            .unwrap();
        let audit = Arc::new(Mutex::new(recorder));
        let registry = SecretRegistry::new();
        let secret = "ghp_pipe_secret_0123456789abcdef";
        registry.register("TOKEN", secret);

        let capture = TerminalCapture::start(
            CaptureConfig {
                session_id: "pipe01".to_string(),
                audit_session_id: "20261125-000000-1".to_string(),
                audit_session_dir: dir.path().to_path_buf(),
                pty: false,
                input: InputCapture::Off,
                required: false,
                max_bytes: DEFAULT_MAX_BYTES,
                chunk_max_bytes: DEFAULT_CHUNK_MAX_BYTES,
                chunk_max_duration: DEFAULT_CHUNK_MAX_DURATION,
                initial_size: None,
            },
            registry,
            audit.clone(),
            Vec::new(),
        )
        .unwrap();

        let mut relay = PipeCaptureRelay::new(capture).unwrap();
        // Write split secret to child stdout and interleaved text to child stderr.
        let (a, b) = secret.split_at(12);
        let child_fds = relay.child_fds().unwrap();
        let mut out_w = unsafe { std::fs::File::from_raw_fd(libc::dup(child_fds.stdout_write)) };
        let mut err_w = unsafe { std::fs::File::from_raw_fd(libc::dup(child_fds.stderr_write)) };
        relay.release_child_ends();
        relay.activate_capture().unwrap();

        out_w.write_all(a.as_bytes()).unwrap();
        err_w.write_all(b"stderr noise\n").unwrap();
        out_w.write_all(b.as_bytes()).unwrap();
        drop(out_w);
        drop(err_w);

        relay.drain_output(Duration::from_millis(200));
        let summary = relay.finish_capture("exited:0".to_string()).unwrap();
        assert_eq!(summary.writer.redactions, 1);

        let audit_text = std::fs::read_to_string(
            dir.path()
                .join(crate::audit_integrity::AUDIT_EVENTS_FILENAME),
        )
        .unwrap();
        let mut cast = Vec::new();
        for line in audit_text.lines() {
            let rec: crate::audit_integrity::AuditEventRecord = serde_json::from_str(line).unwrap();
            if let Some(RecordingAuditEvent::TerminalChunk { chunk }) =
                parse_recording_event(&rec).unwrap()
            {
                let stored = std::fs::read(
                    recording_dir(dir.path()).join(terminal_chunk_file_name(chunk.index)),
                )
                .unwrap();
                cast.extend(zstd::stream::decode_all(stored.as_slice()).unwrap());
            }
        }
        let text = String::from_utf8(cast).unwrap();
        assert!(!text.contains(secret));
        assert!(text.contains("[redacted:credential:TOKEN]"));
        assert!(text.contains("stderr noise"));
    }
}
