//! PTY proxy for detachable sandboxed sessions.
//!
//! The supervisor interposes a PTY between the real terminal and the sandboxed
//! child process. This enables:
//! - `nono detach`: detach from the terminal while the child keeps running
//! - `nono attach`: reattach from any terminal
//!
//! Architecture:
//! ```text
//!   real terminal <---> supervisor (PTY proxy) <---> PTY master/slave <---> child
//!                       |
//!                       +--- attach socket (~/.nono/sessions/{id}.sock)
//! ```
//!
//! The attach socket allows `nono attach` to connect from a different terminal.
//! The supervisor proxies I/O between whoever is connected and the PTY master.

use nix::libc;
use nix::pty::{openpty, OpenptyResult, Winsize};
use nix::sys::signal::{self, SigHandler, Signal};
use nono::{NonoError, Result};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;
use tracing::{debug, info, warn};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

const ATTACH_HANDSHAKE_MAGIC: [u8; 4] = *b"NNOA";
const ATTACH_HANDSHAKE_LEN: usize = 8;
const RESIZE_MESSAGE_LEN: usize = 4;
const SCROLLBACK_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const VT_SCROLLBACK_ROWS: usize = 10_000;
const DEFAULT_DETACH_SEQUENCE: [u8; 2] = [0x1d, b'd'];
const MAX_ENHANCED_KEY_SEQUENCE_LEN: usize = 32;
const ATTACH_ACK_OK: u8 = 0;
const ATTACH_ACK_BUSY: u8 = 1;
const ATTACH_ACK_DENIED: u8 = 2;
const ATTACH_REQUEST_ATTACH: u8 = 0;
const ATTACH_REQUEST_DETACH: u8 = 1;
const ATTACH_SCREEN_ENTER_ESCAPE: &[u8] =
    b"\x1b[0m\x1b(B\x1b)B\x0f\x1b[r\x1b[?6l\x1b[?1049h\x1b[?25h\x1b[2J\x1b[H";
const TERMINAL_RESTORE_ESCAPE: &[u8] = b"\x1b[<u\x1b[>0n\x1b[>1n\x1b[>2n\x1b[>3n\x1b[>4n\x1b[>6n\x1b[>7n\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[?2004l\x1b[?1049l\x1b[?25h";
const TERMINAL_RESTORE_AND_CLEAR_ESCAPE: &[u8] =
    b"\x1b[<u\x1b[>0n\x1b[>1n\x1b[>2n\x1b[>3n\x1b[>4n\x1b[>6n\x1b[>7n\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[?2004l\x1b[?1l\x1b>\x1b[?1049l\x1b[?25h\x1b[2J\x1b[H";

static ATTACH_RESIZE_PIPE_READ: AtomicI32 = AtomicI32::new(-1);
static ATTACH_RESIZE_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

/// PTY pair with the attach socket path.
pub struct PtyPair {
    /// Master side — held by the supervisor for I/O proxying.
    pub master: OwnedFd,
    /// Slave side — becomes the child's stdin/stdout/stderr.
    pub slave: OwnedFd,
}

/// State for a connected terminal client (the real terminal or an attach connection).
enum AttachedClient {
    /// Initial terminal attached to the current process.
    Terminal { read_fd: RawFd, write_fd: RawFd },
    /// Reattached client over the session Unix socket.
    Socket(OwnedFd),
}

enum ReadFdOutcome {
    Data(usize),
    Eof,
    Retry,
}

impl AttachedClient {
    fn terminal(read_fd: RawFd, write_fd: RawFd) -> Self {
        Self::Terminal { read_fd, write_fd }
    }

    fn socket(socket: OwnedFd) -> Self {
        Self::Socket(socket)
    }

    fn read_fd(&self) -> RawFd {
        match self {
            Self::Terminal { read_fd, .. } => *read_fd,
            Self::Socket(socket) => socket.as_raw_fd(),
        }
    }

    fn write_fd(&self) -> RawFd {
        match self {
            Self::Terminal { write_fd, .. } => *write_fd,
            Self::Socket(socket) => socket.as_raw_fd(),
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal { .. })
    }
}

struct ScreenState {
    parser: vt100::Parser,
}

impl ScreenState {
    fn new(rows: usize, cols: usize) -> Self {
        let rows = rows.max(1).min(u16::MAX as usize) as u16;
        let cols = cols.max(1).min(u16::MAX as usize) as u16;
        Self {
            parser: vt100::Parser::new(rows, cols, VT_SCROLLBACK_ROWS),
        }
    }

    fn resize(&mut self, rows: usize, cols: usize) {
        let rows = rows.max(1).min(u16::MAX as usize) as u16;
        let cols = cols.max(1).min(u16::MAX as usize) as u16;
        self.parser.screen_mut().set_size(rows, cols);
    }

    fn apply_bytes(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    fn render(&self) -> Vec<u8> {
        self.parser.screen().state_formatted()
    }

    fn render_plaintext(&self) -> String {
        self.parser.screen().contents()
    }

    fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    fn cursor_position(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }

    fn alternate_screen_active(&self) -> bool {
        self.parser.screen().alternate_screen()
    }
}

/// The running PTY proxy state managed by the supervisor.
pub struct PtyProxy {
    /// PTY master fd
    master: OwnedFd,
    /// Session identifier for updating registry state on detach.
    session_id: String,
    /// Attach socket for `nono attach`
    attach_listener: UnixListener,
    /// Path to the attach socket (for cleanup)
    attach_path: PathBuf,
    /// Currently attached client (None when detached)
    client: Option<AttachedClient>,
    /// Resize updates from a reattached terminal client.
    resize_notifier: Option<UnixDatagram>,
    /// Saved terminal settings (restored on detach)
    saved_termios: Option<nix::sys::termios::Termios>,
    /// Recent PTY output replayed to newly attached clients.
    scrollback: VecDeque<u8>,
    /// Last visible screen state for attach restoration.
    screen: ScreenState,
    /// Configured in-band detach byte sequence.
    detach_sequence: Vec<u8>,
    /// Number of bytes currently matched against `detach_sequence`.
    pending_detach_match_len: usize,
    /// Buffered enhanced key report bytes for the current detach key.
    pending_detach_escape: Vec<u8>,
    /// In-band detach requested from the attached client.
    detach_requested: bool,
}

/// Open a PTY pair, inheriting the current terminal's window size.
pub fn open_pty() -> Result<PtyPair> {
    // Get current terminal window size if available
    let winsize = get_terminal_winsize();

    let OpenptyResult { master, slave } = openpty(winsize.as_ref(), None)
        .map_err(|e| NonoError::SandboxInit(format!("openpty() failed: {}", e)))?;

    Ok(PtyPair { master, slave })
}

/// Set up the slave PTY as the child's controlling terminal.
///
/// Must be called in the child after fork, before exec.
/// This is async-signal-safe (only uses raw libc calls).
///
/// # Safety
/// Must be called in the child process after fork. The slave_fd must be valid.
unsafe fn child_setup_pty_fatal(message: &[u8]) -> ! {
    let _ = libc::write(
        libc::STDERR_FILENO,
        message.as_ptr().cast::<libc::c_void>(),
        message.len(),
    );
    libc::_exit(126);
}

/// # Safety
/// Must be called in the child process after fork. The slave_fd must be valid.
pub unsafe fn setup_child_pty(slave_fd: RawFd) {
    // Create a new session so the child can acquire a controlling terminal.
    if libc::setsid() < 0 {
        child_setup_pty_fatal(b"nono: setsid() failed while configuring child PTY\n");
    }

    // Set the slave as the controlling terminal (TIOCSCTTY).
    // The arg 0 means "don't steal if another process has it".
    if libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
        child_setup_pty_fatal(b"nono: ioctl(TIOCSCTTY) failed while configuring child PTY\n");
    }

    // Redirect stdin/stdout/stderr to the slave PTY
    if libc::dup2(slave_fd, libc::STDIN_FILENO) < 0 {
        child_setup_pty_fatal(b"nono: dup2(stdin) failed while configuring child PTY\n");
    }
    if libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0 {
        child_setup_pty_fatal(b"nono: dup2(stdout) failed while configuring child PTY\n");
    }
    if libc::dup2(slave_fd, libc::STDERR_FILENO) < 0 {
        child_setup_pty_fatal(b"nono: dup2(stderr) failed while configuring child PTY\n");
    }

    // Close the original slave fd if it's not one of 0/1/2
    if slave_fd > 2 {
        libc::close(slave_fd);
    }
}

/// Get the current terminal window size, if available.
fn get_terminal_winsize() -> Option<Winsize> {
    let mut ws: Winsize = unsafe { std::mem::zeroed() };
    // SAFETY: ioctl with TIOCGWINSZ reads window size into ws
    let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        Some(ws)
    } else {
        None
    }
}

impl PtyProxy {
    /// Create a new PTY proxy with an attach socket.
    pub fn new(
        master: OwnedFd,
        session_id: &str,
        attach_initial_client: bool,
        detach_sequence: Option<&[u8]>,
    ) -> Result<Self> {
        let attach_path = crate::session::session_socket_path(session_id)?;
        remove_stale_attach_socket(&attach_path)?;
        let attach_listener = bind_attach_listener(&attach_path)?;
        attach_listener.set_nonblocking(true).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to set attach socket nonblocking: {}", e))
        })?;

        let winsize = current_winsize(master.as_raw_fd()).unwrap_or(Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        });

        let (saved_termios, client) = if attach_initial_client {
            (
                set_terminal_raw(),
                Some(AttachedClient::terminal(
                    libc::STDIN_FILENO,
                    libc::STDOUT_FILENO,
                )),
            )
        } else {
            (None, None)
        };

        Ok(Self {
            master,
            session_id: session_id.to_string(),
            attach_listener,
            attach_path,
            client,
            resize_notifier: None,
            saved_termios,
            scrollback: VecDeque::with_capacity(SCROLLBACK_LIMIT_BYTES.min(64 * 1024)),
            screen: ScreenState::new(winsize.ws_row as usize, winsize.ws_col as usize),
            detach_sequence: detach_sequence
                .filter(|sequence| !sequence.is_empty())
                .map_or_else(|| DEFAULT_DETACH_SEQUENCE.to_vec(), ToOwned::to_owned),
            pending_detach_match_len: 0,
            pending_detach_escape: Vec::new(),
            detach_requested: false,
        })
    }

    /// Detach the current client.
    ///
    /// Restores terminal settings and drops the client connection.
    pub fn detach(&mut self) -> bool {
        let mut detached_terminal = false;
        let mut detached_client_kind = None;
        if let Some(client) = self.client.take() {
            detached_client_kind = Some(if client.is_terminal() {
                "terminal"
            } else {
                "socket"
            });
            if client.is_terminal() {
                detached_terminal = true;
                self.restore_terminal();
            }
        }
        self.resize_notifier = None;
        self.pending_detach_match_len = 0;
        self.pending_detach_escape.clear();
        self.persist_attachment_state(crate::session::SessionAttachment::Detached);
        match detached_client_kind {
            Some(kind) => info!(
                "PTY proxy detached {kind} client for session {}",
                self.session_id
            ),
            None => debug!(
                "PTY proxy detach requested with no active client for session {}",
                self.session_id
            ),
        }
        detached_terminal
    }

    /// Release the local terminal for a final supervisor-owned prompt.
    ///
    /// This leaves the attach screen, restores cooked terminal mode, and
    /// drops the terminal client so later teardown does not redraw or clear it.
    pub fn release_terminal_for_prompt(&mut self) -> bool {
        let had_terminal_client = self
            .client
            .as_ref()
            .is_some_and(AttachedClient::is_terminal);
        if !had_terminal_client {
            return false;
        }

        leave_attach_screen();
        self.restore_terminal();
        self.client = None;
        self.resize_notifier = None;
        self.pending_detach_match_len = 0;
        self.pending_detach_escape.clear();
        self.persist_attachment_state(crate::session::SessionAttachment::Detached);
        true
    }

    /// Accept an attach connection.
    ///
    /// Returns true if a client was attached.
    pub fn try_accept(&mut self) -> bool {
        match self.attach_listener.accept() {
            Ok((mut stream, _addr)) => {
                if let Err(e) = authenticate_attach_peer(stream.as_raw_fd()) {
                    warn!(
                        "PTY proxy: rejected unauthorized attach for {}: {}",
                        self.session_id, e
                    );
                    let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                    return false;
                }

                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let mut request_kind = [0u8; 1];
                match stream.read_exact(&mut request_kind) {
                    Ok(()) => {}
                    Err(e) => {
                        debug!("PTY proxy: failed to read attach request kind: {}", e);
                        let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                        return false;
                    }
                }

                match request_kind[0] {
                    ATTACH_REQUEST_ATTACH => {
                        if self.client.is_some() {
                            let _ = stream.write_all(&[ATTACH_ACK_BUSY]);
                            debug!("PTY proxy: rejected attach while another client is active");
                            return false;
                        }

                        let mut handshake = [0u8; ATTACH_HANDSHAKE_LEN];
                        match stream.read_exact(&mut handshake) {
                            Ok(()) => {
                                if let Some(winsize) = decode_attach_handshake(&handshake) {
                                    let _ = self.apply_winsize(&winsize);
                                } else {
                                    debug!("PTY proxy: invalid attach handshake");
                                    let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                                    return false;
                                }
                            }
                            Err(e) => {
                                debug!("PTY proxy: failed to read attach handshake: {}", e);
                                let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                                return false;
                            }
                        }
                    }
                    ATTACH_REQUEST_DETACH => {
                        let detached_terminal = self.detach();
                        if detached_terminal {
                            write_detach_terminal_reset(libc::STDOUT_FILENO);
                            write_detach_notice(libc::STDERR_FILENO);
                        }
                        let _ = stream.write_all(&[ATTACH_ACK_OK]);
                        info!(
                            "PTY detach requested via attach control socket for session {}",
                            self.session_id
                        );
                        return false;
                    }
                    other => {
                        debug!("PTY proxy: invalid attach request kind: {}", other);
                        let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                        return false;
                    }
                }
                let _ = stream.set_read_timeout(None);

                let (supervisor_resize, client_resize) = match UnixDatagram::pair() {
                    Ok(pair) => pair,
                    Err(e) => {
                        debug!("PTY proxy: failed to create resize channel: {}", e);
                        let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                        return false;
                    }
                };
                if !set_nonblocking(supervisor_resize.as_raw_fd()) {
                    debug!("PTY proxy: failed to set resize channel nonblocking");
                    let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                    return false;
                }

                // Acknowledge the attach first so the client can proceed into
                // its proxy loop, then pass the resize channel fd, then replay
                // buffered PTY output to rebuild the terminal view before live
                // traffic resumes.
                let _ = stream.write_all(&[ATTACH_ACK_OK]);
                if send_fd_over_stream(&stream, client_resize.as_raw_fd()).is_err() {
                    debug!("PTY proxy: failed to send resize fd to attached client");
                    let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                    return false;
                }
                self.write_debug_capture();
                let replay = self.attach_replay_bytes();
                let (rows, cols) = self.screen.size();
                let (cursor_row, cursor_col) = self.screen.cursor_position();
                info!(
                    "PTY proxy preparing attach replay for session {}: replay_bytes={}, scrollback_bytes={}, alt_screen={}, rows={}, cols={}, cursor_row={}, cursor_col={}",
                    self.session_id,
                    replay.len(),
                    self.scrollback.len(),
                    self.screen.alternate_screen_active(),
                    rows,
                    cols,
                    cursor_row,
                    cursor_col
                );
                if !replay.is_empty() && stream.write_all(&replay).is_err() {
                    debug!("PTY proxy: failed to replay scrollback to attached client");
                }

                let socket_fd = stream.into_raw_fd();
                // SAFETY: `socket_fd` came from `UnixStream::into_raw_fd`, so
                // ownership is transferred exactly once into `OwnedFd`.
                let socket = unsafe { OwnedFd::from_raw_fd(socket_fd) };
                self.client = Some(AttachedClient::socket(socket));
                self.resize_notifier = Some(supervisor_resize);
                self.persist_attachment_state(crate::session::SessionAttachment::Attached);
                info!(
                    "PTY proxy attached socket client for session {}",
                    self.session_id
                );
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(e) => {
                debug!("PTY proxy: accept error: {}", e);
                false
            }
        }
    }

    /// Get poll fds for the supervisor loop.
    ///
    /// Returns (master_fd, client_read_fd, attach_listener_fd, resize_fd).
    /// client_read_fd is -1 if no client is attached.
    pub fn poll_fds(&self) -> (RawFd, RawFd, RawFd, RawFd) {
        let client_fd = self.client.as_ref().map_or(-1, AttachedClient::read_fd);
        let resize_fd = self.resize_notifier.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        (
            self.master.as_raw_fd(),
            client_fd,
            self.attach_listener.as_raw_fd(),
            resize_fd,
        )
    }

    /// Proxy data from the PTY master to the attached client (child → user).
    ///
    /// Returns false if the PTY master became unavailable.
    #[must_use = "false indicates the PTY master is no longer usable"]
    pub fn proxy_master_to_client(&mut self) -> bool {
        let client = self
            .client
            .as_ref()
            .map(|c| (c.write_fd(), c.is_terminal()));

        let mut buf = [0u8; 4096];
        let n = match read_fd_once(self.master.as_raw_fd(), &mut buf) {
            Ok(ReadFdOutcome::Data(n)) => n,
            Ok(ReadFdOutcome::Eof) => return false,
            Ok(ReadFdOutcome::Retry) => return true,
            Err(err) => {
                debug!("PTY proxy: failed reading PTY master: {}", err);
                return false;
            }
        };

        self.record_output(&buf[..n]);

        if let Some((write_fd, is_terminal)) = client {
            if let Err(err) = write_all_fd(write_fd, &buf[..n]) {
                if is_terminal {
                    warn!(
                        "PTY proxy: terminal output write failed for session {}: {}; detaching terminal client",
                        self.session_id, err
                    );
                    self.detach();
                    return true;
                } else {
                    debug!("PTY proxy: attached socket client disconnected: {}", err);
                    self.detach();
                    return true;
                }
            }
        }

        true
    }

    /// Proxy data from the attached client to the PTY master (user → child).
    ///
    /// Returns false if the PTY master became unavailable.
    #[must_use = "false indicates the PTY master is no longer usable"]
    pub fn proxy_client_to_master(&mut self) -> bool {
        let client = match self.client.as_ref() {
            Some(c) => (c.read_fd(), c.is_terminal()),
            None => return true,
        };

        let mut buf = [0u8; 4096];
        let n = match read_fd_once(client.0, &mut buf) {
            Ok(ReadFdOutcome::Data(n)) => n,
            Ok(ReadFdOutcome::Eof) => {
                if client.1 {
                    info!(
                        "PTY proxy observed terminal stdin EOF for session {}; detaching terminal client",
                        self.session_id
                    );
                } else {
                    debug!("PTY proxy: attached socket client closed input");
                }
                self.detach();
                return true;
            }
            Ok(ReadFdOutcome::Retry) => return true,
            Err(err) => {
                if client.1 {
                    warn!(
                        "PTY proxy: terminal input read failed for session {}: {}; detaching terminal client",
                        self.session_id, err
                    );
                    self.detach();
                    return true;
                } else {
                    debug!("PTY proxy: attached socket client read failed: {}", err);
                    self.detach();
                    return true;
                }
            }
        };

        let forwarded = self.filter_client_input(&buf[..n]);
        if !forwarded.is_empty() {
            if let Err(err) = write_all_fd(self.master.as_raw_fd(), &forwarded) {
                warn!(
                    "PTY proxy: failed forwarding client input to PTY master for session {}: {}",
                    self.session_id, err
                );
                return false;
            }
        }

        true
    }

    /// Returns true once for each in-band detach request.
    pub fn take_detach_request(&mut self) -> bool {
        std::mem::take(&mut self.detach_requested)
    }

    /// Temporarily restore the local terminal so the parent can print a message.
    pub fn pause_terminal_for_prompt(&mut self) -> bool {
        if self
            .client
            .as_ref()
            .is_some_and(AttachedClient::is_terminal)
        {
            leave_attach_screen();
            self.restore_terminal();
            true
        } else {
            false
        }
    }

    /// Restore terminal settings.
    fn restore_terminal(&mut self) {
        if let Some(ref termios) = self.saved_termios {
            let _ = nix::sys::termios::tcsetattr(
                std::io::stdin(),
                nix::sys::termios::SetArg::TCSANOW,
                termios,
            );
            self.saved_termios = None;
        }
    }

    pub fn sync_current_terminal_winsize(&mut self) {
        if self
            .client
            .as_ref()
            .is_some_and(AttachedClient::is_terminal)
        {
            if let Some(winsize) = get_terminal_winsize() {
                let _ = self.apply_winsize(&winsize);
            }
        }
    }

    pub fn apply_resize_update(&mut self) {
        if self.resize_notifier.is_none() {
            return;
        }

        let mut buf = [0u8; RESIZE_MESSAGE_LEN];
        loop {
            let recv_result = match self.resize_notifier.as_ref() {
                Some(notifier) => notifier.recv(&mut buf),
                None => return,
            };
            match recv_result {
                Ok(RESIZE_MESSAGE_LEN) => {
                    if let Some(winsize) = decode_resize_message(&buf) {
                        let _ = self.apply_winsize(&winsize);
                    }
                }
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.resize_notifier = None;
                    break;
                }
            }
        }
    }

    fn apply_winsize(&mut self, winsize: &Winsize) -> bool {
        if winsize.ws_row == 0 || winsize.ws_col == 0 {
            return false;
        }

        let target_rows = winsize.ws_row.max(1);
        let target_cols = winsize.ws_col.max(1);
        let (current_rows, current_cols) = self.screen.size();
        if current_rows == target_rows && current_cols == target_cols {
            return false;
        }

        unsafe {
            let _ = libc::ioctl(
                self.master.as_raw_fd(),
                libc::TIOCSWINSZ as libc::c_ulong,
                winsize as *const Winsize,
            );
        }
        self.screen
            .resize(target_rows as usize, target_cols as usize);
        true
    }

    fn persist_attachment_state(&self, attachment: crate::session::SessionAttachment) {
        if let Err(e) = crate::session::update_session_attachment(&self.session_id, attachment) {
            warn!(
                "Failed to update session {} attachment state: {}",
                self.session_id, e
            );
        }
    }

    fn record_output(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        let first_output = self.scrollback.is_empty();
        self.screen.apply_bytes(bytes);

        if bytes.len() >= SCROLLBACK_LIMIT_BYTES {
            self.scrollback.clear();
            self.scrollback.extend(
                bytes[bytes.len() - SCROLLBACK_LIMIT_BYTES..]
                    .iter()
                    .copied(),
            );
            if first_output {
                info!(
                    "PTY proxy observed first PTY output for session {} ({} bytes, screen snapshot saturated)",
                    self.session_id,
                    bytes.len()
                );
            }
            return;
        }

        let overflow = self
            .scrollback
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(SCROLLBACK_LIMIT_BYTES);
        if overflow > 0 {
            drop(self.scrollback.drain(..overflow));
        }
        self.scrollback.extend(bytes.iter().copied());
        if first_output {
            info!(
                "PTY proxy observed first PTY output for session {} ({} bytes)",
                self.session_id,
                bytes.len()
            );
        }
    }

    fn scrollback_snapshot(&self) -> Vec<u8> {
        self.screen.render()
    }

    /// Return the current screen content as plain text for diagnostic analysis.
    ///
    /// Called after the child exits so the supervisor can search for
    /// sandbox-related error messages in the terminal output.
    pub fn screen_plaintext(&self) -> String {
        self.screen.render_plaintext()
    }

    /// Returns true once the child has rendered visible terminal content.
    pub fn has_visible_output(&self) -> bool {
        self.screen
            .render_plaintext()
            .chars()
            .any(|ch| !ch.is_whitespace())
    }

    /// Returns true once the child has entered alt-screen mode. This is the
    /// reliable signal that a TUI has become interactive. Plain log lines or
    /// startup banners written to the PTY do not activate alt-screen and do
    /// not count, so a process that prints output and then hangs is still
    /// subject to the startup timeout.
    pub fn is_interactive(&self) -> bool {
        self.screen.alternate_screen_active()
    }

    fn attach_replay_bytes(&self) -> Vec<u8> {
        select_attach_replay_bytes(
            self.screen.alternate_screen_active(),
            self.scrollback.iter().copied().collect(),
            self.scrollback_snapshot(),
            self.screen.render_plaintext(),
        )
    }

    fn write_debug_capture(&self) {
        let Some(dir) = std::env::var_os("NONO_PTY_DEBUG_DIR").map(PathBuf::from) else {
            return;
        };

        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        let prefix = format!(
            "{}-{}",
            self.session_id,
            chrono::Utc::now().timestamp_millis()
        );
        let scrollback_path = dir.join(format!("{prefix}-scrollback.bin"));
        let snapshot_path = dir.join(format!("{prefix}-snapshot.bin"));
        let plaintext_path = dir.join(format!("{prefix}-screen.txt"));
        let metadata_path = dir.join(format!("{prefix}-meta.txt"));

        let scrollback: Vec<u8> = self.scrollback.iter().copied().collect();
        let snapshot = self.scrollback_snapshot();
        let plaintext = self.screen.render_plaintext();
        let (rows, cols) = self.screen.size();
        let (cursor_row, cursor_col) = self.screen.cursor_position();
        let metadata = format!(
            "session_id={}\nrows={}\ncols={}\ncursor_row={}\ncursor_col={}\nalternate_screen_active={}\nscrollback_len={}\n",
            self.session_id,
            rows,
            cols,
            cursor_row,
            cursor_col,
            self.screen.alternate_screen_active(),
            self.scrollback.len()
        );

        let _ = std::fs::write(scrollback_path, scrollback);
        let _ = std::fs::write(snapshot_path, snapshot);
        let _ = std::fs::write(plaintext_path, plaintext);
        let _ = std::fs::write(metadata_path, metadata);
    }
    fn filter_client_input(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut forwarded = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            if self.maybe_consume_enhanced_detach_byte(byte, &mut forwarded) {
                continue;
            }

            if self.detach_sequence.is_empty() {
                forwarded.push(byte);
                continue;
            }

            if byte == self.detach_sequence[self.pending_detach_match_len] {
                self.pending_detach_match_len += 1;
                if self.pending_detach_match_len == self.detach_sequence.len() {
                    self.detach_requested = true;
                    info!(
                        "PTY proxy in-band detach sequence matched for session {}",
                        self.session_id
                    );
                    self.pending_detach_match_len = 0;
                }
                continue;
            }

            if self.should_start_enhanced_detach_match(byte) {
                self.pending_detach_escape.push(byte);
                continue;
            }

            if self.pending_detach_match_len > 0 {
                forwarded.extend_from_slice(&self.detach_sequence[..self.pending_detach_match_len]);
                self.pending_detach_match_len = 0;
                if byte == self.detach_sequence[0] {
                    self.pending_detach_match_len = 1;
                    continue;
                }
            }

            forwarded.push(byte);
        }
        forwarded
    }

    fn should_start_enhanced_detach_match(&self, byte: u8) -> bool {
        byte == b'\x1b'
            && self
                .detach_sequence
                .get(self.pending_detach_match_len)
                .copied()
                .is_some_and(detach_key_supports_enhanced_match)
    }

    fn maybe_consume_enhanced_detach_byte(&mut self, byte: u8, forwarded: &mut Vec<u8>) -> bool {
        if self.pending_detach_escape.is_empty() {
            return false;
        }

        self.pending_detach_escape.push(byte);
        let Some(expected_key) = self
            .detach_sequence
            .get(self.pending_detach_match_len)
            .copied()
        else {
            self.flush_pending_detach_escape(forwarded);
            return true;
        };

        match match_enhanced_key_sequence(&self.pending_detach_escape, expected_key) {
            EnhancedKeyMatch::Pending => {
                if self.pending_detach_escape.len() > MAX_ENHANCED_KEY_SEQUENCE_LEN {
                    self.flush_pending_detach_escape(forwarded);
                }
            }
            EnhancedKeyMatch::Matched => {
                self.pending_detach_escape.clear();
                self.pending_detach_match_len += 1;
                if self.pending_detach_match_len == self.detach_sequence.len() {
                    self.pending_detach_match_len = 0;
                    self.detach_requested = true;
                    info!(
                        "PTY proxy in-band detach sequence matched for session {}",
                        self.session_id
                    );
                }
            }
            EnhancedKeyMatch::Invalid => self.flush_pending_detach_escape(forwarded),
        }

        true
    }

    fn flush_pending_detach_escape(&mut self, forwarded: &mut Vec<u8>) {
        if self.pending_detach_match_len > 0 {
            forwarded.extend_from_slice(&self.detach_sequence[..self.pending_detach_match_len]);
            self.pending_detach_match_len = 0;
        }
        forwarded.extend_from_slice(&self.pending_detach_escape);
        self.pending_detach_escape.clear();
    }
}

enum EnhancedKeyMatch {
    Pending,
    Matched,
    Invalid,
}

fn detach_key_supports_enhanced_match(key: u8) -> bool {
    key.is_ascii_graphic() || key == b' ' || control_key_candidates(key).is_some()
}

fn match_enhanced_key_sequence(bytes: &[u8], expected_key: u8) -> EnhancedKeyMatch {
    if bytes.is_empty() {
        return EnhancedKeyMatch::Pending;
    }
    if bytes[0] != b'\x1b' {
        return EnhancedKeyMatch::Invalid;
    }
    if bytes.len() == 1 {
        return EnhancedKeyMatch::Pending;
    }
    if bytes[1] != b'[' {
        return EnhancedKeyMatch::Invalid;
    }
    if bytes.len() == 2 {
        return EnhancedKeyMatch::Pending;
    }

    let payload = &bytes[2..];
    let Some((&last, body)) = payload.split_last() else {
        return EnhancedKeyMatch::Pending;
    };

    if last == b'u' {
        if body.is_empty()
            || !body
                .iter()
                .all(|b| b.is_ascii_digit() || matches!(b, b';' | b':'))
        {
            return EnhancedKeyMatch::Invalid;
        }
        let mut fields = body.split(|b| matches!(b, b';' | b':'));
        let Some(first_field) = fields.next() else {
            return EnhancedKeyMatch::Invalid;
        };
        if first_field.is_empty() {
            return EnhancedKeyMatch::Invalid;
        }
        let Some(codepoint) = parse_ascii_u32(first_field) else {
            return EnhancedKeyMatch::Invalid;
        };
        let modifiers = fields.find_map(parse_ascii_u32).unwrap_or(1);
        return if enhanced_key_matches(expected_key, codepoint, modifiers) {
            EnhancedKeyMatch::Matched
        } else {
            EnhancedKeyMatch::Invalid
        };
    }

    if last == b'~' {
        let fields: Vec<&[u8]> = body.split(|b| *b == b';').collect();
        if fields.len() == 3
            && fields[0] == b"27"
            && fields[1].iter().all(|b| b.is_ascii_digit())
            && fields[2].iter().all(|b| b.is_ascii_digit())
        {
            let Some(modifiers) = parse_ascii_u32(fields[1]) else {
                return EnhancedKeyMatch::Invalid;
            };
            let Some(codepoint) = parse_ascii_u32(fields[2]) else {
                return EnhancedKeyMatch::Invalid;
            };
            return if enhanced_key_matches(expected_key, codepoint, modifiers) {
                EnhancedKeyMatch::Matched
            } else {
                EnhancedKeyMatch::Invalid
            };
        }
    }

    if (last.is_ascii_digit() || matches!(last, b';' | b':'))
        && body
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b';' | b':' | b'~'))
    {
        return EnhancedKeyMatch::Pending;
    }

    EnhancedKeyMatch::Invalid
}

fn parse_ascii_u32(bytes: &[u8]) -> Option<u32> {
    std::str::from_utf8(bytes).ok()?.parse::<u32>().ok()
}

fn enhanced_key_matches(expected_key: u8, codepoint: u32, modifiers: u32) -> bool {
    if modifiers == 1 {
        return codepoint == u32::from(expected_key)
            && expected_key.is_ascii_graphic().then_some(()).is_some()
            || (expected_key == b' ' && codepoint == u32::from(expected_key));
    }

    if modifiers == 5 {
        return control_key_candidates(expected_key).is_some_and(|candidates| {
            candidates
                .into_iter()
                .any(|candidate| codepoint == candidate)
        });
    }

    false
}

fn control_key_candidates(expected_key: u8) -> Option<[u32; 2]> {
    match expected_key {
        0x01..=0x1a => Some([
            u32::from(expected_key + 0x40),
            u32::from(expected_key + 0x60),
        ]),
        0x1b..=0x1f => Some([
            u32::from(expected_key + 0x40),
            u32::from(expected_key + 0x40),
        ]),
        _ => None,
    }
}

fn select_attach_replay_bytes(
    alternate_screen_active: bool,
    raw_scrollback: Vec<u8>,
    rendered_snapshot: Vec<u8>,
    rendered_plaintext: String,
) -> Vec<u8> {
    if alternate_screen_active {
        if raw_scrollback.is_empty() {
            rendered_snapshot
        } else if rendered_plaintext.trim().is_empty() {
            raw_scrollback
        } else {
            let mut replay = raw_scrollback;
            replay.extend_from_slice(&rendered_snapshot);
            replay
        }
    } else if rendered_snapshot.is_empty() || rendered_plaintext.trim().is_empty() {
        raw_scrollback
    } else {
        rendered_snapshot
    }
}

fn current_winsize(fd: RawFd) -> Option<Winsize> {
    let mut ws: Winsize = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        Some(ws)
    } else {
        None
    }
}

fn remove_stale_attach_socket(attach_path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(attach_path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(NonoError::ConfigWrite {
                path: attach_path.to_path_buf(),
                source: e,
            });
        }
    };

    if !metadata.file_type().is_socket() {
        return Err(NonoError::ConfigParse(format!(
            "Refusing to replace non-socket attach path {}",
            attach_path.display()
        )));
    }

    std::fs::remove_file(attach_path).map_err(|e| NonoError::ConfigWrite {
        path: attach_path.to_path_buf(),
        source: e,
    })
}

fn bind_attach_listener(attach_path: &Path) -> Result<UnixListener> {
    struct UmaskGuard(libc::mode_t);

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    let _umask_guard = UmaskGuard(unsafe { libc::umask(0o177) });
    let listener = UnixListener::bind(attach_path).map_err(|e| NonoError::ConfigWrite {
        path: attach_path.to_path_buf(),
        source: e,
    })?;

    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(attach_path, perms).map_err(|e| NonoError::ConfigWrite {
            path: attach_path.to_path_buf(),
            source: e,
        })?;
    }

    Ok(listener)
}

fn authenticate_attach_peer(sock_fd: RawFd) -> Result<()> {
    let current_uid = unsafe { libc::geteuid() } as u32;
    let peer = nono::supervisor::socket::peer_credentials(sock_fd)?;
    if peer.uid != current_uid {
        Err(NonoError::ConfigParse(format!(
            "attach peer uid {} does not match current uid {}",
            peer.uid, current_uid
        )))
    } else if !nono::supervisor::socket::peer_in_same_user_namespace(peer.pid)? {
        Err(NonoError::ConfigParse(format!(
            "attach peer pid {} is not in the current user namespace",
            peer.pid
        )))
    } else {
        Ok(())
    }
}

impl Drop for PtyProxy {
    fn drop(&mut self) {
        if self
            .client
            .as_ref()
            .is_some_and(AttachedClient::is_terminal)
        {
            write_detach_terminal_reset(libc::STDOUT_FILENO);
        }
        self.restore_terminal();
        // Clean up the attach socket
        let _ = std::fs::remove_file(&self.attach_path);
    }
}

/// Put the terminal into raw mode, returning the saved settings.
fn set_terminal_raw() -> Option<nix::sys::termios::Termios> {
    use nix::sys::termios;

    let stdin_fd = std::io::stdin();

    let original = match termios::tcgetattr(&stdin_fd) {
        Ok(t) => t,
        Err(_) => return None, // Not a terminal
    };

    let mut raw = original.clone();
    termios::cfmakeraw(&mut raw);

    if let Err(e) = termios::tcsetattr(&stdin_fd, termios::SetArg::TCSANOW, &raw) {
        warn!("Failed to set raw terminal mode: {}", e);
        return None;
    }

    Some(original)
}

fn get_fd_flags(fd: RawFd) -> Option<libc::c_int> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return None;
    }
    Some(flags)
}

fn set_fd_flags(fd: RawFd, flags: libc::c_int) -> bool {
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) == 0 }
}

fn set_nonblocking(fd: RawFd) -> bool {
    let Some(flags) = get_fd_flags(fd) else {
        return false;
    };
    set_fd_flags(fd, flags | libc::O_NONBLOCK)
}

fn drain_socket_replay(sock_fd: RawFd) {
    let original_flags = match get_fd_flags(sock_fd) {
        Some(flags) => flags,
        None => return,
    };

    let needs_restore = original_flags & libc::O_NONBLOCK == 0;
    if needs_restore && !set_fd_flags(sock_fd, original_flags | libc::O_NONBLOCK) {
        return;
    }

    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(sock_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };

        if n > 0 {
            if write_all_fd(libc::STDOUT_FILENO, &buf[..n as usize]).is_err() {
                break;
            }
            continue;
        }

        if n == 0 {
            break;
        }

        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => break,
            _ => break,
        }
    }

    if needs_restore {
        let _ = set_fd_flags(sock_fd, original_flags);
    }
}

fn encode_attach_handshake(winsize: Option<Winsize>) -> [u8; ATTACH_HANDSHAKE_LEN] {
    let ws = match winsize {
        Some(ws) => ws,
        None => Winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    };

    let mut buf = [0u8; ATTACH_HANDSHAKE_LEN];
    buf[..4].copy_from_slice(&ATTACH_HANDSHAKE_MAGIC);
    buf[4..6].copy_from_slice(&ws.ws_row.to_be_bytes());
    buf[6..8].copy_from_slice(&ws.ws_col.to_be_bytes());
    buf
}

fn decode_attach_handshake(buf: &[u8; ATTACH_HANDSHAKE_LEN]) -> Option<Winsize> {
    if buf[..4] != ATTACH_HANDSHAKE_MAGIC {
        return None;
    }

    Some(Winsize {
        ws_row: u16::from_be_bytes([buf[4], buf[5]]),
        ws_col: u16::from_be_bytes([buf[6], buf[7]]),
        ws_xpixel: 0,
        ws_ypixel: 0,
    })
}

fn encode_resize_message(winsize: Winsize) -> [u8; RESIZE_MESSAGE_LEN] {
    let mut buf = [0u8; RESIZE_MESSAGE_LEN];
    buf[..2].copy_from_slice(&winsize.ws_row.to_be_bytes());
    buf[2..4].copy_from_slice(&winsize.ws_col.to_be_bytes());
    buf
}

fn decode_resize_message(buf: &[u8; RESIZE_MESSAGE_LEN]) -> Option<Winsize> {
    let ws_row = u16::from_be_bytes([buf[0], buf[1]]);
    let ws_col = u16::from_be_bytes([buf[2], buf[3]]);
    if ws_row == 0 || ws_col == 0 {
        return None;
    }
    Some(Winsize {
        ws_row,
        ws_col,
        ws_xpixel: 0,
        ws_ypixel: 0,
    })
}

fn send_attach_handshake(stream: &mut UnixStream) -> Result<()> {
    stream
        .write_all(&[ATTACH_REQUEST_ATTACH])
        .map_err(|e| NonoError::ConfigParse(format!("Failed to send attach request: {}", e)))?;
    let handshake = encode_attach_handshake(get_terminal_winsize());
    stream
        .write_all(&handshake)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to send attach handshake: {}", e)))
}

fn send_attach_resize(socket: &UnixDatagram, winsize: Winsize) -> Result<()> {
    let msg = encode_resize_message(winsize);
    socket.send(&msg).map_err(|e| {
        NonoError::SandboxInit(format!("Failed to send attach resize update: {}", e))
    })?;
    Ok(())
}

fn recv_fd_over_stream(stream: &UnixStream) -> Result<OwnedFd> {
    nono::supervisor::socket::recv_fd_via_socket(stream.as_raw_fd())
}

fn send_fd_over_stream(stream: &UnixStream, fd: RawFd) -> Result<()> {
    nono::supervisor::socket::send_fd_via_socket(stream.as_raw_fd(), fd)
}

fn recv_attach_resize_socket(stream: &UnixStream) -> Result<Option<UnixDatagram>> {
    let fd = recv_fd_over_stream(stream)?;
    let raw_fd = fd.into_raw_fd();
    let socket = unsafe { UnixDatagram::from_raw_fd(raw_fd) };
    if !set_nonblocking(socket.as_raw_fd()) {
        return Err(NonoError::SandboxInit(
            "Failed to set attach resize socket nonblocking".to_string(),
        ));
    }
    Ok(Some(socket))
}

fn enter_attach_screen() {
    unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            ATTACH_SCREEN_ENTER_ESCAPE.as_ptr().cast(),
            ATTACH_SCREEN_ENTER_ESCAPE.len(),
        );
    }
}

fn leave_attach_screen() {
    let esc = terminal_restore_escape(false);
    let _ = write_all_fd(libc::STDOUT_FILENO, esc);
}

pub(crate) fn write_detach_terminal_reset(fd: RawFd) {
    let esc = terminal_restore_escape(true);
    unsafe {
        libc::write(fd, esc.as_ptr().cast(), esc.len());
    }
}

pub(crate) fn write_detach_notice(fd: RawFd) {
    unsafe {
        let msg = b"\r\n[nono] Session detached.\r\n";
        libc::write(fd, msg.as_ptr().cast(), msg.len());
    }
}

pub(crate) fn terminal_restore_escape(clear_screen: bool) -> &'static [u8] {
    if clear_screen {
        TERMINAL_RESTORE_AND_CLEAR_ESCAPE
    } else {
        TERMINAL_RESTORE_ESCAPE
    }
}

fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written =
            unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
        if written > 0 {
            bytes = &bytes[written as usize..];
            continue;
        }

        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => wait_for_fd_writable(fd)?,
            _ => return Err(err),
        }
    }

    Ok(())
}

fn read_fd_once(fd: RawFd, buf: &mut [u8]) -> std::io::Result<ReadFdOutcome> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            return Ok(ReadFdOutcome::Data(n as usize));
        }
        if n == 0 {
            return Ok(ReadFdOutcome::Eof);
        }

        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => return Ok(ReadFdOutcome::Retry),
            _ => return Err(err),
        }
    }
}

fn wait_for_fd_writable(fd: RawFd) -> std::io::Result<()> {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, -1) };
        if ret > 0 {
            if pfd.revents & libc::POLLOUT != 0 {
                return Ok(());
            }
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            continue;
        }
        if ret == 0 {
            continue;
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

fn is_socket_disconnect(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Connect to a running session's attach socket.
///
/// Used by `nono attach` to connect to the supervisor's PTY proxy.
pub fn connect_to_session(session_id: &str) -> Result<UnixStream> {
    let sock_path = crate::session::session_socket_path(session_id)?;

    if !sock_path.exists() {
        return Err(NonoError::ConfigParse(format!(
            "Session {} has no attach socket (not a PTY session or already exited)",
            session_id
        )));
    }

    let mut stream = UnixStream::connect(&sock_path).map_err(|e| {
        NonoError::ConfigParse(format!(
            "Failed to connect to session {} attach socket: {}",
            session_id, e
        ))
    })?;

    send_attach_handshake(&mut stream)?;
    Ok(stream)
}

pub fn request_session_detach(session_id: &str) -> Result<()> {
    let sock_path = crate::session::session_socket_path(session_id)?;

    if !sock_path.exists() {
        return Err(NonoError::ConfigParse(format!(
            "Session {} has no attach socket (not a PTY session or already exited)",
            session_id
        )));
    }

    let mut stream = UnixStream::connect(&sock_path).map_err(|e| {
        NonoError::ConfigParse(format!(
            "Failed to connect to session {} attach socket: {}",
            session_id, e
        ))
    })?;
    stream
        .write_all(&[ATTACH_REQUEST_DETACH])
        .map_err(|e| NonoError::ConfigParse(format!("Failed to send detach request: {}", e)))?;
    wait_for_detach_ready(stream.as_raw_fd(), 1000)
}

/// Wait for the supervisor to accept an attach socket.
pub fn wait_for_attach_ready(sock_fd: RawFd, timeout_ms: i32) -> Result<()> {
    let mut pfd = libc::pollfd {
        fd: sock_fd,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "poll() error waiting for attach readiness: {}",
            std::io::Error::last_os_error()
        )));
    }
    if ret == 0 {
        return Err(NonoError::ConfigParse(
            "Timed out waiting for session attach".to_string(),
        ));
    }
    let mut ack = [0u8; 1];
    let n = unsafe { libc::read(sock_fd, ack.as_mut_ptr().cast::<libc::c_void>(), ack.len()) };
    if n != 1 {
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Err(NonoError::ConfigParse(
                "Session attach socket closed before attach completed".to_string(),
            ));
        }
        return Err(NonoError::ConfigParse(
            "Failed to confirm session attach readiness".to_string(),
        ));
    }

    match ack[0] {
        ATTACH_ACK_OK => Ok(()),
        ATTACH_ACK_BUSY => Err(NonoError::AttachBusy),
        ATTACH_ACK_DENIED => Err(NonoError::ConfigParse(
            "Session attach was rejected by supervisor".to_string(),
        )),
        _ => Err(NonoError::ConfigParse(
            "Received invalid attach acknowledgement from supervisor".to_string(),
        )),
    }
}

fn wait_for_detach_ready(sock_fd: RawFd, timeout_ms: i32) -> Result<()> {
    let mut pfd = libc::pollfd {
        fd: sock_fd,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "poll() error waiting for detach acknowledgement: {}",
            std::io::Error::last_os_error()
        )));
    }
    if ret == 0 {
        return Err(NonoError::ConfigParse(
            "Timed out waiting for session detach acknowledgement".to_string(),
        ));
    }

    let mut ack = [0u8; 1];
    let n = unsafe { libc::read(sock_fd, ack.as_mut_ptr().cast::<libc::c_void>(), ack.len()) };
    if n != 1 {
        return Err(NonoError::ConfigParse(
            "Failed to confirm session detach acknowledgement".to_string(),
        ));
    }

    match ack[0] {
        ATTACH_ACK_OK => Ok(()),
        ATTACH_ACK_DENIED => Err(NonoError::ConfigParse(
            "Session detach was rejected by supervisor".to_string(),
        )),
        _ => Err(NonoError::ConfigParse(
            "Received invalid detach acknowledgement from supervisor".to_string(),
        )),
    }
}

fn create_attach_resize_pipe() -> i32 {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return -1;
    }
    unsafe {
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
    }
    ATTACH_RESIZE_PIPE_READ.store(fds[0], Ordering::SeqCst);
    ATTACH_RESIZE_PIPE_WRITE.store(fds[1], Ordering::SeqCst);
    fds[0]
}

fn close_attach_resize_pipe() {
    let read_fd = ATTACH_RESIZE_PIPE_READ.swap(-1, Ordering::SeqCst);
    let write_fd = ATTACH_RESIZE_PIPE_WRITE.swap(-1, Ordering::SeqCst);
    if read_fd >= 0 {
        unsafe {
            libc::close(read_fd);
        }
    }
    if write_fd >= 0 {
        unsafe {
            libc::close(write_fd);
        }
    }
}

fn drain_attach_resize_pipe() {
    let read_fd = ATTACH_RESIZE_PIPE_READ.load(Ordering::SeqCst);
    if read_fd < 0 {
        return;
    }

    let mut buf = [0u8; 16];
    loop {
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
}

extern "C" fn forward_attach_resize_signal(sig: libc::c_int) {
    if sig != libc::SIGWINCH {
        return;
    }
    let write_fd = ATTACH_RESIZE_PIPE_WRITE.load(Ordering::SeqCst);
    if write_fd >= 0 {
        unsafe {
            libc::write(write_fd, b"R".as_ptr().cast(), 1);
        }
    }
}

struct AttachResizeSignalGuard {
    previous_handler: SigHandler,
}

impl AttachResizeSignalGuard {
    fn install() -> Result<Self> {
        let read_fd = create_attach_resize_pipe();
        if read_fd < 0 {
            return Err(NonoError::SandboxInit(
                "Failed to create attach resize pipe".to_string(),
            ));
        }

        let previous_handler = unsafe {
            signal::signal(
                Signal::SIGWINCH,
                SigHandler::Handler(forward_attach_resize_signal),
            )
        }
        .map_err(|e| {
            close_attach_resize_pipe();
            NonoError::SandboxInit(format!("Failed to install attach SIGWINCH handler: {e}"))
        })?;

        Ok(Self { previous_handler })
    }

    fn read_fd(&self) -> RawFd {
        ATTACH_RESIZE_PIPE_READ.load(Ordering::SeqCst)
    }
}

impl Drop for AttachResizeSignalGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = signal::signal(Signal::SIGWINCH, self.previous_handler);
        }
        close_attach_resize_pipe();
    }
}

/// Attach to an already connected session socket.
pub fn attach_to_stream(stream: UnixStream) -> Result<()> {
    let resize_socket = recv_attach_resize_socket(&stream)?;
    attach_to_stream_with_init(stream, resize_socket, || Ok(()))
}

/// Attach to an already connected session socket after running an init hook.
///
/// The init hook runs after the local terminal has entered raw mode but before
/// the attach loop starts, which is important for TUIs that probe the terminal
/// immediately when they are resumed.
pub fn attach_to_stream_with_init<F>(
    stream: UnixStream,
    resize_socket: Option<UnixDatagram>,
    init: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let sock_fd = stream.as_raw_fd();

    // Put our terminal in raw mode
    let saved_termios = set_terminal_raw();
    enter_attach_screen();

    // Render any queued replay bytes before the child is resumed. This keeps
    // the restored screen and cursor state coherent before new live output
    // starts arriving from the PTY.
    drain_socket_replay(sock_fd);

    let init_result = init();

    // Proxy I/O between our terminal and the socket
    let result = match init_result {
        Ok(()) => run_attach_loop(
            sock_fd,
            resize_socket.as_ref(),
            Some(Duration::from_millis(250)),
        ),
        Err(e) => Err(e),
    };

    // Restore terminal
    leave_attach_screen();
    if let Some(ref termios) = saved_termios {
        let _ = nix::sys::termios::tcsetattr(
            std::io::stdin(),
            nix::sys::termios::SetArg::TCSANOW,
            termios,
        );
    }

    // Keep stream alive until we're done
    drop(stream);

    result
}

/// Connect to a running session's attach socket and proxy I/O.
pub fn attach_to_session(session_id: &str) -> Result<()> {
    let stream = connect_to_session(session_id)?;
    wait_for_attach_ready(stream.as_raw_fd(), 1000)?;
    attach_to_stream(stream)
}

/// Run the attach client I/O loop.
fn run_attach_loop(
    sock_fd: RawFd,
    resize_socket: Option<&UnixDatagram>,
    stdin_delay: Option<Duration>,
) -> Result<()> {
    let resize_signal_guard = if resize_socket.is_some() {
        Some(AttachResizeSignalGuard::install()?)
    } else {
        None
    };
    let mut pfds = [
        libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: resize_signal_guard
                .as_ref()
                .map_or(-1, AttachResizeSignalGuard::read_fd),
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut buf = [0u8; 4096];
    let stdin_deadline = stdin_delay.and_then(|delay| std::time::Instant::now().checked_add(delay));
    let mut last_winsize = get_terminal_winsize();

    loop {
        if let Some(deadline) = stdin_deadline {
            if std::time::Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
                let mut warmup_pfd = libc::pollfd {
                    fd: sock_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ret = unsafe { libc::poll(&mut warmup_pfd, 1, timeout_ms) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(NonoError::SandboxInit(format!(
                        "poll() error in attach warm-up: {}",
                        err
                    )));
                }
                if warmup_pfd.revents & libc::POLLIN != 0 {
                    match read_fd_once(sock_fd, &mut buf) {
                        Ok(ReadFdOutcome::Data(n)) => {
                            if let Err(err) = write_all_fd(libc::STDOUT_FILENO, &buf[..n]) {
                                return Err(NonoError::SandboxInit(format!(
                                    "attach stdout write failed: {}",
                                    err
                                )));
                            }
                        }
                        Ok(ReadFdOutcome::Eof) => break,
                        Ok(ReadFdOutcome::Retry) => continue,
                        Err(err) if is_socket_disconnect(&err) => break,
                        Err(err) => {
                            return Err(NonoError::SandboxInit(format!(
                                "attach socket read failed: {}",
                                err
                            )));
                        }
                    }
                }
                if warmup_pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    info!("PTY attach client observed attach socket close during warm-up");
                    break;
                }
                continue;
            }
        }

        // SAFETY: pfds is a valid array on the stack
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 250) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(NonoError::SandboxInit(format!(
                "poll() error in attach loop: {}",
                err
            )));
        }

        // stdin → socket (user input)
        if pfds[0].revents & libc::POLLIN != 0 {
            match read_fd_once(libc::STDIN_FILENO, &mut buf) {
                Ok(ReadFdOutcome::Data(n)) => {
                    if let Err(err) = write_all_fd(sock_fd, &buf[..n]) {
                        if is_socket_disconnect(&err) {
                            info!("PTY attach client socket disconnected while writing stdin");
                            break;
                        }
                        return Err(NonoError::SandboxInit(format!(
                            "attach socket write failed: {}",
                            err
                        )));
                    }
                }
                Ok(ReadFdOutcome::Eof) => {
                    info!("PTY attach client stdin reached EOF");
                    break;
                }
                Ok(ReadFdOutcome::Retry) => continue,
                Err(err) => {
                    return Err(NonoError::SandboxInit(format!(
                        "attach stdin read failed: {}",
                        err
                    )));
                }
            }
        }

        // socket → stdout (child output)
        if pfds[1].revents & libc::POLLIN != 0 {
            match read_fd_once(sock_fd, &mut buf) {
                Ok(ReadFdOutcome::Data(n)) => {
                    if let Err(err) = write_all_fd(libc::STDOUT_FILENO, &buf[..n]) {
                        return Err(NonoError::SandboxInit(format!(
                            "attach stdout write failed: {}",
                            err
                        )));
                    }
                }
                Ok(ReadFdOutcome::Eof) => {
                    info!("PTY attach client observed attach socket EOF");
                    break;
                }
                Ok(ReadFdOutcome::Retry) => continue,
                Err(err) if is_socket_disconnect(&err) => {
                    info!(
                        "PTY attach client observed attach socket disconnect: {}",
                        err
                    );
                    break;
                }
                Err(err) => {
                    return Err(NonoError::SandboxInit(format!(
                        "attach socket read failed: {}",
                        err
                    )));
                }
            }
        }

        // Connection closed
        if pfds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            info!("PTY attach client observed POLLHUP/POLLERR on attach socket");
            break;
        }

        if pfds[2].revents & libc::POLLIN != 0 {
            drain_attach_resize_pipe();
            if let Some(socket) = resize_socket {
                if let Some(winsize) = get_terminal_winsize() {
                    let changed = last_winsize
                        .map(|last| last.ws_row != winsize.ws_row || last.ws_col != winsize.ws_col)
                        .unwrap_or(true);
                    if changed {
                        let _ = send_attach_resize(socket, winsize);
                        last_winsize = Some(winsize);
                    }
                }
            }
        }
    }

    eprintln!("\n[nono] Detached from session.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        read_fd_once, select_attach_replay_bytes, terminal_restore_escape, write_all_fd,
        AttachedClient, PtyProxy, ReadFdOutcome, ScreenState, DEFAULT_DETACH_SEQUENCE,
    };
    use nix::libc;
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixListener;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration;

    fn build_test_proxy_with_master(master: OwnedFd, sequence: &[u8]) -> PtyProxy {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let attach_path = temp_dir.path().join("attach.sock");
        let attach_listener = UnixListener::bind(&attach_path).expect("bind attach socket");

        PtyProxy {
            master,
            session_id: "test-session".to_string(),
            attach_listener,
            attach_path,
            client: None,
            resize_notifier: None,
            saved_termios: None,
            scrollback: VecDeque::new(),
            screen: ScreenState::new(24, 80),
            detach_sequence: sequence.to_vec(),
            pending_detach_match_len: 0,
            pending_detach_escape: Vec::new(),
            detach_requested: false,
        }
    }

    fn build_test_proxy(sequence: &[u8]) -> PtyProxy {
        let dup_fd = unsafe { libc::dup(libc::STDIN_FILENO) };
        assert!(dup_fd >= 0);
        let master = unsafe { OwnedFd::from_raw_fd(dup_fd) };
        build_test_proxy_with_master(master, sequence)
    }

    #[test]
    fn terminal_restore_escape_disables_mouse_modes() {
        let esc = std::str::from_utf8(terminal_restore_escape(false)).unwrap_or("");
        for mode in ["1000", "1002", "1003", "1005", "1006", "1015"] {
            assert!(esc.contains(&format!("\u{1b}[?{mode}l")));
        }
        assert!(esc.contains("\u{1b}[?1049l"));
    }

    #[test]
    fn terminal_restore_escape_disables_keyboard_enhancement_modes() {
        let esc = std::str::from_utf8(terminal_restore_escape(false)).unwrap_or("");
        assert!(esc.contains("\u{1b}[<u"));
        for mode in ["0", "1", "2", "3", "4", "6", "7"] {
            assert!(esc.contains(&format!("\u{1b}[>{mode}n")));
        }
    }

    #[test]
    fn terminal_restore_escape_can_clear_screen() {
        let esc = std::str::from_utf8(terminal_restore_escape(true)).unwrap_or("");
        assert!(esc.ends_with("\u{1b}[2J\u{1b}[H"));
    }

    #[test]
    fn attach_replay_uses_rendered_snapshot_for_alternate_screen() {
        let replay = select_attach_replay_bytes(
            true,
            b"raw".to_vec(),
            b"rendered".to_vec(),
            "visible text".to_string(),
        );
        assert_eq!(replay, b"rawrendered");
    }

    #[test]
    fn attach_replay_uses_rendered_snapshot_for_normal_screen() {
        let replay = select_attach_replay_bytes(
            false,
            b"raw".to_vec(),
            b"rendered".to_vec(),
            "visible text".to_string(),
        );
        assert_eq!(replay, b"rendered");
    }

    #[test]
    fn attach_replay_falls_back_to_raw_if_alternate_snapshot_is_empty() {
        let replay = select_attach_replay_bytes(true, b"raw".to_vec(), Vec::new(), "".to_string());
        assert_eq!(replay, b"raw");
    }

    #[test]
    fn attach_replay_falls_back_to_raw_if_alternate_plaintext_is_blank() {
        let replay = select_attach_replay_bytes(
            true,
            b"raw".to_vec(),
            b"rendered".to_vec(),
            "   ".to_string(),
        );
        assert_eq!(replay, b"raw");
    }

    #[test]
    fn apply_winsize_is_noop_when_dimensions_are_unchanged() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        proxy.screen.apply_bytes(b"\x1b[?1049h\x1b[2J\x1b[Hhello");

        let before = proxy.screen.render();
        let changed = proxy.apply_winsize(&nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        });
        let after = proxy.screen.render();

        assert!(!changed);
        assert_eq!(before, after);
    }

    #[test]
    fn apply_winsize_ignores_zero_dimensions() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let before = proxy.screen.size();
        let changed = proxy.apply_winsize(&nix::pty::Winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        });

        assert!(!changed);
        assert_eq!(before, proxy.screen.size());
    }

    #[test]
    fn detach_clears_partial_detach_sequence_state() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(&[DEFAULT_DETACH_SEQUENCE[0]]);
        assert!(forwarded.is_empty());
        assert_eq!(proxy.pending_detach_match_len, 1);

        let _ = proxy.detach();

        assert_eq!(proxy.pending_detach_match_len, 0);
        assert!(proxy.pending_detach_escape.is_empty());
        let forwarded = proxy.filter_client_input(b"x");
        assert_eq!(forwarded, b"x");
        assert!(!proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_on_default_sequence() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(&DEFAULT_DETACH_SEQUENCE);
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_on_custom_sequence() {
        let mut proxy = build_test_proxy(&[0x01, b'x']);
        let forwarded = proxy.filter_client_input(&[0x01, b'x']);
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_forwards_partial_mismatch() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(&[0x1d, b'x']);
        assert_eq!(forwarded, vec![0x1d, b'x']);
        assert!(!proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_on_enhanced_csi_u_suffix() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(b"\x1d\x1b[100;1u");
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_on_chunked_enhanced_csi_u_suffix() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(b"\x1d\x1b[10");
        assert!(forwarded.is_empty());
        assert!(!proxy.take_detach_request());

        let forwarded = proxy.filter_client_input(b"0;1u");
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_forwards_invalid_enhanced_suffix() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(b"\x1d\x1b[120;1u");
        assert_eq!(forwarded, b"\x1d\x1b[120;1u");
        assert!(!proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_when_control_prefix_arrives_as_enhanced_csi_u() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(b"\x1b[93;5ud");
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_when_both_keys_arrive_as_enhanced_csi_u() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(b"\x1b[93;5u\x1b[100;1u");
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_when_control_prefix_arrives_as_xterm_modify_other_keys() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(b"\x1b[27;5;93~d");
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn read_fd_once_returns_retry_for_nonblocking_would_block() {
        let (reader, _writer) = UnixStream::pair().expect("socket pair");
        assert!(super::set_nonblocking(reader.as_raw_fd()));

        let mut buf = [0u8; 8];
        let result = read_fd_once(reader.as_raw_fd(), &mut buf).expect("read should not fail");
        assert!(matches!(result, ReadFdOutcome::Retry));
    }

    #[test]
    fn write_all_fd_retries_after_would_block() {
        let (reader, mut writer) = UnixStream::pair().expect("socket pair");
        assert!(super::set_nonblocking(writer.as_raw_fd()));
        let (result_tx, result_rx) = std::sync::mpsc::channel();

        let fill_buf = vec![b'x'; 8192];
        loop {
            match writer.write(&fill_buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("failed to fill socket buffer: {err}"),
            }
        }

        let reader_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let mut reader = reader;
            reader
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("set read timeout");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut buf = [0u8; 16 * 1024];
            let mut saw_ok = false;

            while std::time::Instant::now() < deadline {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if buf[..n].windows(2).any(|window| window == b"ok") {
                            saw_ok = true;
                            break;
                        }
                    }
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            || err.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(err) => {
                        let _ = result_tx.send(Err(format!("reader failed: {err}")));
                        return;
                    }
                }
            }

            let _ = result_tx.send(if saw_ok {
                Ok(())
            } else {
                Err("reader never observed retried write".to_string())
            });
        });

        write_all_fd(writer.as_raw_fd(), b"ok").expect("write_all_fd should retry");
        match result_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("{err}"),
            Err(err) => panic!("reader thread timed out: {err}"),
        }
        reader_thread.join().expect("reader thread");
    }

    #[test]
    fn proxy_client_to_master_detaches_terminal_on_eof() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let (reader, writer) = UnixStream::pair().expect("socket pair");
        proxy.client = Some(AttachedClient::terminal(
            reader.as_raw_fd(),
            libc::STDOUT_FILENO,
        ));

        drop(writer);

        assert!(proxy.proxy_client_to_master());
        assert!(proxy.client.is_none());
    }

    #[test]
    fn proxy_master_to_client_detaches_terminal_on_write_error() {
        let (master_reader, mut master_writer) = UnixStream::pair().expect("socket pair");
        let master = unsafe { OwnedFd::from_raw_fd(master_reader.into_raw_fd()) };
        let mut proxy = build_test_proxy_with_master(master, &DEFAULT_DETACH_SEQUENCE);
        proxy.client = Some(AttachedClient::terminal(libc::STDIN_FILENO, -1));

        master_writer.write_all(b"hello").expect("write PTY output");

        assert!(proxy.proxy_master_to_client());
        assert!(proxy.client.is_none());
    }
}
