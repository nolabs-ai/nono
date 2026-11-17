//! Shared terminal picker for tenant selection and remote session attachment.

use std::io::{self, IsTerminal, Write};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd};

use colored::Colorize;
use nono::{NonoError, Result};

const HEADER_ROWS: u16 = 7;
const ROWS_PER_ITEM: u16 = 2;

pub(crate) struct Item {
    pub(crate) label: String,
    pub(crate) context: String,
    pub(crate) status: String,
    pub(crate) metadata: String,
    pub(crate) marker: Option<String>,
}

pub(crate) struct Picker<'a> {
    pub(crate) title: &'a str,
    pub(crate) context: &'a str,
    pub(crate) summary: &'a str,
    pub(crate) prompt: &'a str,
    pub(crate) confirm_label: &'a str,
}

pub(crate) fn select(picker: &Picker<'_>, items: &[Item]) -> Result<Option<usize>> {
    let count = NonZeroUsize::new(items.len())
        .ok_or_else(|| NonoError::ActionRequired("no choices are available".into()))?;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(NonoError::ActionRequired(
            "selection requires an interactive terminal".into(),
        ));
    }
    let _terminal = SelectionTerminal::enter()?;
    run_selector(&io::stdin(), count, |selected| {
        let (columns, rows) = terminal_size();
        let mut output = io::stdout().lock();
        draw(&mut output, picker, items, selected, columns, rows)
    })
}

fn run_selector(
    input: &impl AsFd,
    count: NonZeroUsize,
    mut draw: impl FnMut(usize) -> Result<()>,
) -> Result<Option<usize>> {
    let count = count.get();
    let mut selected = 0;
    loop {
        draw(selected)?;
        match read_selector_key(input)? {
            SelectorKey::Up => selected = selected.checked_sub(1).unwrap_or(count - 1),
            SelectorKey::Down => selected = (selected + 1) % count,
            SelectorKey::Home => selected = 0,
            SelectorKey::End => selected = count - 1,
            SelectorKey::Select => return Ok(Some(selected)),
            SelectorKey::Cancel => return Ok(None),
            SelectorKey::Ignore => {}
        }
    }
}

struct SelectionTerminal {
    _raw_terminal: RawTerminal,
}

impl SelectionTerminal {
    fn enter() -> Result<Self> {
        let terminal = Self {
            _raw_terminal: RawTerminal::enter()?,
        };
        let mut output = io::stdout().lock();
        output
            .write_all(b"\x1b[?1049h\x1b[?25l")
            .map_err(NonoError::Io)?;
        output.flush().map_err(NonoError::Io)?;
        Ok(terminal)
    }
}

impl Drop for SelectionTerminal {
    fn drop(&mut self) {
        let mut output = io::stdout().lock();
        let _ = output.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = output.flush();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectorKey {
    Up,
    Down,
    Home,
    End,
    Select,
    Cancel,
    Ignore,
}

fn draw(
    output: &mut impl Write,
    picker: &Picker<'_>,
    items: &[Item],
    selected: usize,
    columns: u16,
    rows: u16,
) -> Result<()> {
    let columns = usize::from(columns);
    let visible = usize::from(rows.saturating_sub(HEADER_ROWS) / ROWS_PER_ITEM)
        .max(1)
        .min(items.len());
    let first = selected
        .saturating_sub(visible / 2)
        .min(items.len().saturating_sub(visible));
    let last = first + visible;
    let theme = crate::theme::current();
    let clean = crate::terminal_approval::sanitize_for_terminal;
    output.write_all(b"\x1b[2J\x1b[H").map_err(NonoError::Io)?;
    write_terminal_line(
        output,
        &format!(
            "  {}  {}  {}",
            clean(picker.title).bold(),
            clean(picker.context).bold(),
            clean(picker.summary).dimmed()
        ),
    )?;
    write_terminal_line(output, "")?;
    write_terminal_line(output, &format!("  {}", clean(picker.prompt).bold()))?;
    write_terminal_line(
        output,
        &format!(
            "  {}",
            format!(
                "↑/↓ or j/k move  ·  enter {}  ·  q cancel",
                clean(picker.confirm_label)
            )
            .dimmed()
        ),
    )?;
    write_terminal_line(output, "")?;
    for (index, item) in items.iter().enumerate().take(last).skip(first) {
        let active = index == selected;
        let pointer = if active {
            crate::theme::fg("❯", theme.brand).bold().to_string()
        } else {
            " ".into()
        };
        let mut budget = columns.saturating_sub(8).max(12);
        let label = crate::command_display::truncate_chars(&clean(&item.label), budget);
        budget = budget.saturating_sub(label.chars().count() + 2);
        let context = crate::command_display::truncate_chars(&clean(&item.context), budget);
        budget = budget.saturating_sub(context.chars().count() + 2);
        let status = crate::command_display::truncate_chars(&clean(&item.status), budget);
        let label = if active {
            label.bold().to_string()
        } else {
            label
        };
        let marker = item
            .marker
            .as_ref()
            .map(|marker| format!(" {marker}"))
            .unwrap_or_default();
        write_terminal_line(
            output,
            &format!(
                "  {pointer}{marker} {label}  {}  {status}",
                context.dimmed()
            ),
        )?;
        let metadata = crate::command_display::truncate_chars(
            &clean(&item.metadata),
            columns.saturating_sub(7).max(12),
        );
        write_terminal_line(output, &format!("      {}", metadata.dimmed()))?;
    }
    if visible < items.len() {
        write_terminal_line(
            output,
            &format!(
                "  {}",
                format!("showing {}–{} of {}", first + 1, last, items.len()).dimmed()
            ),
        )?;
    }
    output.flush().map_err(NonoError::Io)
}

fn write_terminal_line(output: &mut impl Write, line: &str) -> Result<()> {
    output.write_all(line.as_bytes()).map_err(NonoError::Io)?;
    output.write_all(b"\r\n").map_err(NonoError::Io)
}

// Read directly from the descriptor that we poll. Buffered stdin can read ahead
// past Escape, making an arrow key look like a standalone Escape to poll().
fn read_selector_byte(input: &impl AsFd) -> Result<u8> {
    let mut byte = [0_u8; 1];
    loop {
        match nix::unistd::read(input, &mut byte) {
            Ok(0) => {
                return Err(NonoError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "terminal input closed",
                )));
            }
            Ok(_) => return Ok(byte[0]),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(NonoError::Io(error.into())),
        }
    }
}

fn read_selector_key(input: &impl AsFd) -> Result<SelectorKey> {
    match read_selector_byte(input)? {
        b'k' | b'K' => Ok(SelectorKey::Up),
        b'j' | b'J' => Ok(SelectorKey::Down),
        b'g' => Ok(SelectorKey::Home),
        b'G' => Ok(SelectorKey::End),
        b'\r' | b'\n' => Ok(SelectorKey::Select),
        b'q' | b'Q' | 0x03 => Ok(SelectorKey::Cancel),
        0x1b => read_escape_key(input),
        _ => Ok(SelectorKey::Ignore),
    }
}

fn read_escape_key(input: &impl AsFd) -> Result<SelectorKey> {
    if !selector_input_pending(input, 40)? {
        return Ok(SelectorKey::Cancel);
    }
    let prefix = read_selector_byte(input)?;
    if !matches!(prefix, b'[' | b'O') {
        return Ok(SelectorKey::Ignore);
    }
    match read_selector_byte(input)? {
        b'A' => Ok(SelectorKey::Up),
        b'B' => Ok(SelectorKey::Down),
        b'H' => Ok(SelectorKey::Home),
        b'F' => Ok(SelectorKey::End),
        _ => Ok(SelectorKey::Ignore),
    }
}

fn selector_input_pending(input: &impl AsFd, timeout_ms: i32) -> Result<bool> {
    let mut descriptor = nix::libc::pollfd {
        fd: input.as_fd().as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `descriptor` points to one initialized `pollfd`, the count is
    // exactly one, and `poll` only mutates its `revents` field.
    let result = unsafe { nix::libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        return Err(NonoError::Io(io::Error::last_os_error()));
    }
    Ok(result > 0 && descriptor.revents & nix::libc::POLLIN != 0)
}

pub(crate) struct RawTerminal {
    original: nix::sys::termios::Termios,
    pub(crate) screen: crate::pty_proxy::AltScreenTracker,
}

impl RawTerminal {
    pub(crate) fn enter() -> Result<Self> {
        use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};
        let stdin = io::stdin();
        let original = tcgetattr(&stdin).map_err(|error| {
            NonoError::ConfigParse(format!("could not read terminal mode: {error}"))
        })?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&stdin, SetArg::TCSANOW, &raw).map_err(|error| {
            NonoError::ConfigParse(format!("could not enter raw terminal mode: {error}"))
        })?;
        Ok(Self {
            original,
            screen: Default::default(),
        })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        crate::pty_proxy::restore_terminal_modes_after_attach(
            self.screen.in_alt_screen,
            terminal_size().1,
        );
        let stdin = io::stdin();
        let _ = nix::sys::termios::tcsetattr(
            &stdin,
            nix::sys::termios::SetArg::TCSANOW,
            &self.original,
        );
    }
}

pub(crate) fn terminal_size() -> (u16, u16) {
    let mut size = nix::libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ only writes the fixed-size `winsize` structure.
    let result =
        unsafe { nix::libc::ioctl(nix::libc::STDOUT_FILENO, nix::libc::TIOCGWINSZ, &mut size) };
    if result == 0 && size.ws_col > 0 && size.ws_row > 0 {
        (size.ws_col, size.ws_row)
    } else {
        (80, 24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_reads_queued_arrow_sequences_without_cancelling() -> Result<()> {
        let (input, mut writer) = std::os::unix::net::UnixStream::pair().map_err(NonoError::Io)?;
        writer
            .write_all(b"\x1b[B\x1b[A\x1bOB\x1bOA\x1b[H\x1b[F\r")
            .map_err(NonoError::Io)?;
        for expected in [
            SelectorKey::Down,
            SelectorKey::Up,
            SelectorKey::Down,
            SelectorKey::Up,
            SelectorKey::Home,
            SelectorKey::End,
            SelectorKey::Select,
        ] {
            assert_eq!(read_selector_key(&input)?, expected);
        }
        Ok(())
    }

    #[test]
    fn selector_standalone_escape_still_cancels() -> Result<()> {
        let (input, mut writer) = std::os::unix::net::UnixStream::pair().map_err(NonoError::Io)?;
        writer.write_all(b"\x1b").map_err(NonoError::Io)?;
        assert_eq!(read_selector_key(&input)?, SelectorKey::Cancel);
        Ok(())
    }
    #[test]
    fn navigation_wraps_and_confirms_the_highlighted_item() -> Result<()> {
        for (keys, expected) in [
            (&b"k\r"[..], 2),
            (&b"jjj\r"[..], 0),
            (&b"j\r"[..], 1),
            (&b"Gk\r"[..], 1),
            (&b"jg\r"[..], 0),
            (&b"\x1b[B\x1b[B\r"[..], 2),
        ] {
            let (input, mut writer) =
                std::os::unix::net::UnixStream::pair().map_err(NonoError::Io)?;
            writer.write_all(keys).map_err(NonoError::Io)?;
            assert_eq!(
                run_selector(&input, NonZeroUsize::new(3).expect("choices"), |_| Ok(()))?,
                Some(expected),
            );
        }
        Ok(())
    }

    #[test]
    fn cancellation_and_input_or_render_errors_never_select_an_item() -> Result<()> {
        for keys in [&b"q"[..], &b"\x03"[..], &b"\x1b"[..]] {
            let (input, mut writer) =
                std::os::unix::net::UnixStream::pair().map_err(NonoError::Io)?;
            writer.write_all(keys).map_err(NonoError::Io)?;
            assert_eq!(run_selector(&input, NonZeroUsize::MIN, |_| Ok(()))?, None);
        }
        let (input, writer) = std::os::unix::net::UnixStream::pair().map_err(NonoError::Io)?;
        drop(writer);
        assert!(run_selector(&input, NonZeroUsize::MIN, |_| Ok(())).is_err());
        assert!(
            run_selector(&input, NonZeroUsize::MIN, |_| {
                Err(NonoError::Io(io::Error::other("render failed")))
            })
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn scrolling_keeps_selection_visible_and_removes_terminal_controls() -> Result<()> {
        let picker = Picker {
            title: "NONO LOGIN",
            context: "platform",
            summary: "5 tenants",
            prompt: "Choose a tenant",
            confirm_label: "select",
        };
        let items = (0..5)
            .map(|index| Item {
                label: format!("Tenant {index}\x1b[31m"),
                context: "slug".into(),
                status: "organization".into(),
                metadata: "\x1b]0;untrusted title\x07".into(),
                marker: None,
            })
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        draw(&mut output, &picker, &items, 4, 80, 11)?;
        let output = String::from_utf8(output).expect("terminal text");
        assert!(output.contains("Tenant 4"));
        assert!(!output.contains("Tenant 0"));
        assert!(output.contains("showing 4–5 of 5"));
        assert!(output.contains("enter select"));
        assert!(!output.contains("\x1b[31m"));
        assert!(!output.contains("untrusted title"));
        Ok(())
    }
}
