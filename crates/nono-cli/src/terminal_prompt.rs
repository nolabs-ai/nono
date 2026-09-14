//! Guarded terminal input for security-sensitive line prompts.

use nono::{NonoError, Result};
use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

const CONSENT_INPUT_DELAY: Duration = Duration::from_secs(1);

/// Return whether a controlling terminal is available for a consent prompt.
pub(crate) fn consent_prompt_available() -> bool {
    open_tty().is_ok_and(|tty| tty.is_terminal())
}

/// Read a line from the controlling terminal after discarding type-ahead.
pub(crate) fn read_consent_line(prompt: &str) -> Result<String> {
    read_consent_line_from(open_tty()?, prompt, CONSENT_INPUT_DELAY)
}

fn open_tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(NonoError::Io)
}

fn read_consent_line_from(mut tty: std::fs::File, prompt: &str, delay: Duration) -> Result<String> {
    let saved = nix::sys::termios::tcgetattr(&tty).map_err(termios_error)?;
    let restore_tty = tty.try_clone().map_err(NonoError::Io)?;
    let _guard = TermiosRestoreGuard {
        tty: restore_tty,
        saved: saved.clone(),
    };

    let mut prompt_termios = saved;
    configure_line_input(&mut prompt_termios);
    nix::sys::termios::tcsetattr(&tty, nix::sys::termios::SetArg::TCSANOW, &prompt_termios)
        .map_err(termios_error)?;

    write!(tty, "Input enables in 1 second · early keys ignored").map_err(NonoError::Io)?;
    tty.flush().map_err(NonoError::Io)?;
    std::thread::sleep(delay);

    nix::sys::termios::tcflush(&tty, nix::sys::termios::FlushArg::TCIFLUSH)
        .map_err(termios_error)?;
    write!(tty, "\r\x1b[2K{prompt}").map_err(NonoError::Io)?;
    tty.flush().map_err(NonoError::Io)?;

    let mut input = String::new();
    std::io::BufReader::new(tty)
        .read_line(&mut input)
        .map_err(NonoError::Io)?;
    Ok(input)
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
}

impl Drop for TermiosRestoreGuard {
    fn drop(&mut self) {
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
        )
        .expect("read guarded response");
        writer.join().expect("join response writer");

        assert_eq!(response.trim(), "n");
    }
}
