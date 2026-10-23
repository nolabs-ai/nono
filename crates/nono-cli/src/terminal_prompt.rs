//! Guarded terminal input for security-sensitive line prompts.

use nono::{NonoError, Result};
use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

const CONSENT_INPUT_DELAY: Duration = Duration::from_secs(1);

/// Return whether a controlling terminal is available for a consent prompt.
pub(crate) fn consent_prompt_available() -> bool {
    open_tty().is_ok_and(|tty| tty.is_terminal())
}

/// Read a line from the controlling terminal after discarding type-ahead.
pub(crate) fn read_consent_line(prompt: &str) -> Result<String> {
    read_consent_line_from(open_tty()?, prompt, CONSENT_INPUT_DELAY, None)?
        .ok_or_else(|| NonoError::SandboxInit("Terminal consent prompt timed out".to_string()))
}

/// Read consent until an absolute deadline. Expiry closes the reader and
/// restores terminal state before returning `None`; no background read survives.
pub(crate) fn read_consent_line_until(prompt: &str, deadline: Instant) -> Result<Option<String>> {
    read_consent_line_from(open_tty()?, prompt, CONSENT_INPUT_DELAY, Some(deadline))
}

fn open_tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(NonoError::Io)
}

pub(crate) fn read_consent_line_from(
    mut tty: std::fs::File,
    prompt: &str,
    delay: Duration,
    deadline: Option<Instant>,
) -> Result<Option<String>> {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        return Ok(None);
    }
    let saved = nix::sys::termios::tcgetattr(&tty).map_err(termios_error)?;
    let restore_tty = tty.try_clone().map_err(NonoError::Io)?;
    let flags = nix::fcntl::fcntl(&tty, nix::fcntl::FcntlArg::F_GETFL).map_err(termios_error)?;
    let _guard = TermiosRestoreGuard {
        tty: restore_tty,
        saved: saved.clone(),
        flags,
    };
    // Readiness is only a snapshot: another terminal consumer can drain input
    // before our read. Nonblocking I/O keeps even that race deadline-bounded.
    nix::fcntl::fcntl(
        &tty,
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_retain(flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )
    .map_err(termios_error)?;

    let mut prompt_termios = saved;
    configure_line_input(&mut prompt_termios);
    nix::sys::termios::tcsetattr(&tty, nix::sys::termios::SetArg::TCSANOW, &prompt_termios)
        .map_err(termios_error)?;

    write!(tty, "Input enables in 1 second · early keys ignored").map_err(NonoError::Io)?;
    tty.flush().map_err(NonoError::Io)?;
    std::thread::sleep(deadline.map_or(delay, |end| {
        delay.min(end.saturating_duration_since(Instant::now()))
    }));
    if deadline.is_some_and(|end| Instant::now() >= end) {
        return Ok(None);
    }

    nix::sys::termios::tcflush(&tty, nix::sys::termios::FlushArg::TCIFLUSH)
        .map_err(termios_error)?;
    write!(tty, "\r\x1b[2K{prompt}").map_err(NonoError::Io)?;
    tty.flush().map_err(NonoError::Io)?;

    let mut input = Vec::new();
    loop {
        let timeout_ms = match deadline {
            Some(end) => {
                let remaining = end.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                // Round up so a sub-millisecond remainder does not busy-spin.
                remaining
                    .as_millis()
                    .saturating_add(1)
                    .min(i32::MAX as u128) as i32
            }
            None => -1,
        };
        let mut descriptor = nix::libc::pollfd {
            fd: tty.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd and its owned
        // file descriptor stays open throughout this synchronous call.
        let ready = unsafe { nix::libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(NonoError::Io(error));
        }
        if deadline.is_some_and(|end| Instant::now() >= end) {
            return Ok(None);
        }
        if ready == 0 {
            continue;
        }
        // Read one byte at a time so a complete answer never consumes input
        // intended for a subsequent prompt. Canonical mode still owns editing.
        let mut byte = [0];
        match tty.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                input.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if input.len() >= 4096 {
                    return Err(NonoError::SandboxInit(
                        "Terminal consent response is too long".to_string(),
                    ));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(NonoError::Io(error)),
        }
    }
    if deadline.is_some_and(|end| Instant::now() >= end) {
        return Ok(None);
    }
    String::from_utf8(input)
        .map(Some)
        .map_err(|error| NonoError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error)))
}

fn termios_error(error: nix::errno::Errno) -> NonoError {
    NonoError::Io(std::io::Error::from_raw_os_error(error as i32))
}

fn configure_line_input(termios: &mut nix::sys::termios::Termios) {
    use nix::sys::termios::{
        ControlFlags, InputFlags, LocalFlags, OutputFlags, SpecialCharacterIndices,
    };

    termios.input_flags.remove(
        InputFlags::IGNBRK
            | InputFlags::BRKINT
            | InputFlags::PARMRK
            | InputFlags::ISTRIP
            | InputFlags::INLCR
            | InputFlags::IGNCR,
    );
    termios
        .input_flags
        .insert(InputFlags::ICRNL | InputFlags::IXON);
    termios.output_flags.insert(OutputFlags::OPOST);
    termios.local_flags.insert(
        LocalFlags::ECHO
            | LocalFlags::ECHONL
            | LocalFlags::ICANON
            | LocalFlags::ISIG
            | LocalFlags::IEXTEN,
    );
    termios
        .control_flags
        .remove(ControlFlags::CSIZE | ControlFlags::PARENB);
    termios.control_flags.insert(ControlFlags::CS8);
    termios.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    termios.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
}

struct TermiosRestoreGuard {
    tty: std::fs::File,
    saved: nix::sys::termios::Termios,
    flags: i32,
}

impl Drop for TermiosRestoreGuard {
    fn drop(&mut self) {
        // Discard an incomplete or late answer before another prompt can use
        // this terminal. Restore both line discipline and descriptor flags.
        let _ = nix::sys::termios::tcflush(&self.tty, nix::sys::termios::FlushArg::TCIFLUSH);
        let _ = nix::fcntl::fcntl(
            &self.tty,
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::from_bits_retain(self.flags)),
        );
        let _ = nix::sys::termios::tcsetattr(
            &self.tty,
            nix::sys::termios::SetArg::TCSANOW,
            &self.saved,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::pty::{OpenptyResult, openpty};

    #[test]
    fn deadline_restores_terminal_state_and_descriptor_flags() {
        for (delay, initially_nonblocking) in [
            (Duration::ZERO, false),
            (Duration::from_secs(1), false),
            (Duration::ZERO, true),
            (Duration::from_secs(1), true),
        ] {
            let OpenptyResult {
                master: _master,
                slave,
            } = openpty(None, None).expect("openpty");
            let observer = nix::unistd::dup(&slave).expect("observe terminal");
            let mut saved = nix::sys::termios::tcgetattr(&observer).expect("read terminal state");
            nix::sys::termios::cfmakeraw(&mut saved);
            nix::sys::termios::tcsetattr(&observer, nix::sys::termios::SetArg::TCSANOW, &saved)
                .expect("set distinct initial terminal state");
            let mut flags = nix::fcntl::OFlag::from_bits_retain(
                nix::fcntl::fcntl(&observer, nix::fcntl::FcntlArg::F_GETFL)
                    .expect("read descriptor flags"),
            );
            flags.set(nix::fcntl::OFlag::O_NONBLOCK, initially_nonblocking);
            nix::fcntl::fcntl(&observer, nix::fcntl::FcntlArg::F_SETFL(flags))
                .expect("set initial descriptor flags");
            let flags = nix::fcntl::OFlag::from_bits_truncate(
                nix::fcntl::fcntl(&observer, nix::fcntl::FcntlArg::F_GETFL)
                    .expect("read initial descriptor flags"),
            );
            assert_eq!(
                flags.contains(nix::fcntl::OFlag::O_NONBLOCK),
                initially_nonblocking
            );
            let start = Instant::now();
            let result = read_consent_line_from(
                std::fs::File::from(slave),
                "Approve? ",
                delay,
                Some(start + Duration::from_millis(20)),
            )
            .expect("deadline-aware read");
            assert!(result.is_none());
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "delay is deadline-bounded too"
            );
            assert_eq!(
                nix::sys::termios::tcgetattr(&observer).expect("restored state"),
                saved
            );
            // Darwin exposes kernel bookkeeping such as FWASWRITTEN through
            // F_GETFL after writing the prompt. Compare public status flags,
            // including O_NONBLOCK, rather than that non-restorable history.
            assert_eq!(
                nix::fcntl::OFlag::from_bits_truncate(
                    nix::fcntl::fcntl(&observer, nix::fcntl::FcntlArg::F_GETFL)
                        .expect("restored flags"),
                ),
                flags
            );
        }
    }

    #[test]
    fn incomplete_answer_does_not_extend_deadline() {
        let OpenptyResult { master, slave } = openpty(None, None).expect("openpty");
        let writer_master = nix::unistd::dup(&master).expect("duplicate master");
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            nix::unistd::write(writer_master, b"y").expect("write without newline");
        });
        let result = read_consent_line_from(
            std::fs::File::from(slave),
            "Approve? ",
            Duration::ZERO,
            Some(Instant::now() + Duration::from_millis(50)),
        )
        .expect("deadline-aware read");
        writer.join().expect("join writer");
        assert!(
            result.is_none(),
            "partial consent must time out, not grant or block"
        );
    }

    #[test]
    fn consent_reader_discards_early_input_and_accepts_fresh_response() {
        let OpenptyResult { master, slave } = openpty(None, None).expect("openpty");
        nix::unistd::write(&master, b"y\n").expect("queue early approval");

        let writer_master = nix::unistd::dup(&master).expect("duplicate pty master");
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            nix::unistd::write(writer_master, b"n\n").expect("write fresh response");
        });

        let response = read_consent_line_from(
            std::fs::File::from(slave),
            "Continue? [y/N] ",
            Duration::ZERO,
            Some(Instant::now() + Duration::from_secs(5)),
        )
        .expect("read guarded response")
        .expect("response before deadline");
        writer.join().expect("join response writer");

        assert_eq!(response.trim(), "n");
    }
}
