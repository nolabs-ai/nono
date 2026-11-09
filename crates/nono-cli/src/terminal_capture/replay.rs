//! `nono replay`: play a recording back in the terminal (NEP-0010 §8).
//!
//! Recorded output is never written to the viewer's terminal as it was
//! captured. It runs through a vt100 screen model, and the viewer receives
//! only the model's own redraw sequences (text, colour and cursor
//! position). Sequences the agent printed that act on the terminal itself,
//! such as clipboard writes (OSC 52), titles, mode changes or device
//! queries, therefore never reach whoever watches the replay.
//!
//! The viewer's terminal is rarely the size the session was recorded at.
//! Each frame is drawn row by row with explicit cursor positioning and
//! clipped to the viewer's terminal, so a recording wider or taller than it
//! never wraps or scrolls the viewer's screen out of step with the model;
//! the top-left part that fits is shown.

use super::recording::{CastEvent, Recording, parse_marker};
use nono::{NonoError, Result};
use std::io::Write;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Where playback starts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ReplayStart {
    Beginning,
    /// Seconds from the start of the session.
    Time(f64),
    /// The first `nono:<name>` marker, or the first lifecycle event with
    /// this name.
    Marker(String),
}

impl ReplayStart {
    /// Parse `--from`: `SECS`, `MM:SS`, `HH:MM:SS`, or a marker name.
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(Self::Beginning);
        }
        if value
            .chars()
            .all(|c| c.is_ascii_digit() || c == ':' || c == '.')
        {
            let mut seconds = 0.0f64;
            for part in value.split(':') {
                let part: f64 = part
                    .parse()
                    .map_err(|_| NonoError::ConfigParse(format!("invalid --from time: {value}")))?;
                seconds = seconds * 60.0 + part;
            }
            return Ok(Self::Time(seconds));
        }
        Ok(Self::Marker(value.to_string()))
    }
}

/// Playback settings.
#[derive(Clone, Debug)]
pub(crate) struct ReplayOptions {
    pub(crate) speed: f64,
    pub(crate) idle_limit: Option<f64>,
    pub(crate) start: ReplayStart,
    /// The viewer's terminal as `(cols, rows)`; `None` when output is not a
    /// terminal, in which case the whole recorded screen is drawn.
    pub(crate) viewport: Option<(u16, u16)>,
}

fn size(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap_or(NonZeroU16::MIN)
}

fn marker_matches(label: &str, wanted: &str) -> bool {
    match parse_marker(label) {
        Some((name, body)) => name == wanted || body["event"].as_str() == Some(wanted),
        None => false,
    }
}

/// Index of the first event playback should show at full speed.
fn start_index(recording: &Recording, start: &ReplayStart) -> Result<usize> {
    let found = match start {
        ReplayStart::Beginning => Some(0),
        ReplayStart::Time(seconds) => recording
            .events
            .iter()
            .position(|e| e.time() >= *seconds)
            .or(Some(recording.events.len())),
        ReplayStart::Marker(wanted) => recording.events.iter().position(|e| match e {
            CastEvent::Marker { label, .. } => marker_matches(label, wanted),
            _ => false,
        }),
    };
    found.ok_or_else(|| match start {
        ReplayStart::Marker(wanted) => {
            NonoError::ConfigParse(format!("no `{wanted}` marker in this recording"))
        }
        _ => NonoError::ConfigParse("invalid replay start".to_string()),
    })
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_interrupt(_: nix::libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Stop at Ctrl-C between frames, so the terminal is always left tidy.
fn catch_interrupt() {
    let action = nix::sys::signal::SigAction::new(
        nix::sys::signal::SigHandler::Handler(on_interrupt),
        nix::sys::signal::SaFlags::empty(),
        nix::sys::signal::SigSet::empty(),
    );
    // SAFETY: the handler only stores to an atomic, which is
    // async-signal-safe.
    let _ = unsafe { nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGINT, &action) };
}

fn wait(seconds: f64) {
    let mut remaining = Duration::from_secs_f64(seconds.max(0.0));
    let step = Duration::from_millis(50);
    while !remaining.is_zero() && !INTERRUPTED.load(Ordering::SeqCst) {
        let nap = remaining.min(step);
        std::thread::sleep(nap);
        remaining = remaining.saturating_sub(nap);
    }
}

/// Rows already on the viewer's screen, so unchanged rows are not resent.
#[derive(Default)]
struct Drawn {
    rows: Vec<String>,
}

impl Drawn {
    /// Append to `out` the bytes that bring the viewer's screen to `screen`,
    /// clipped to `viewport`. Every changed row is cleared and rewritten
    /// from its first column at an absolute position, and no row is wider
    /// than the viewer's terminal, so the viewer never wraps or scrolls.
    fn draw(
        &mut self,
        screen: &vt100::Screen,
        viewport: Option<(u16, u16)>,
        full: bool,
        out: &mut String,
    ) {
        let (rows, cols) = screen.size();
        let (mut show_cols, mut show_rows) = (cols.get(), rows.get());
        if let Some((view_cols, view_rows)) = viewport {
            show_cols = show_cols.min(view_cols.max(1));
            show_rows = show_rows.min(view_rows.max(1));
        }
        if full {
            out.push_str("\x1b[0m\x1b[H\x1b[2J");
            self.rows.clear();
        }
        // A cleared row and a blank row format the same, so a row the
        // viewer has never been sent counts as blank.
        self.rows.resize(usize::from(show_rows), String::new());
        for (index, row) in screen
            .rows_formatted(0, show_cols)
            .take(usize::from(show_rows))
            .enumerate()
        {
            if self.rows[index] == row {
                continue;
            }
            out.push_str(&format!("\x1b[{};1H\x1b[0m\x1b[2K", index + 1));
            out.push_str(&row);
            self.rows[index] = row;
        }
        out.push_str("\x1b[0m");
        let (cursor_row, cursor_col) = screen.cursor_position();
        if !screen.hide_cursor() && cursor_row < show_rows && cursor_col < show_cols {
            out.push_str(&format!(
                "\x1b[{};{}H\x1b[?25h",
                cursor_row + 1,
                cursor_col + 1
            ));
        } else {
            out.push_str("\x1b[?25l");
        }
    }
}

/// The largest screen in the recording, as `(cols, rows)`.
fn largest_size(recording: &Recording) -> (u16, u16) {
    recording
        .events
        .iter()
        .filter_map(|event| match event {
            CastEvent::Resize { cols, rows, .. } => Some((*cols, *rows)),
            _ => None,
        })
        .fold((recording.cols, recording.rows), |(c, r), (cols, rows)| {
            (c.max(cols), r.max(rows))
        })
}

/// Produce the frames of a replay: the delay before each frame and the
/// bytes to write. Kept separate from the clock so it can be tested.
pub(crate) fn frames(recording: &Recording, options: &ReplayOptions) -> Result<Vec<(f64, String)>> {
    let first = start_index(recording, &options.start)?;
    let mut parser = vt100::Parser::new(size(recording.rows), size(recording.cols), 0);
    let mut drawn = Drawn::default();
    let mut frames = Vec::new();
    let mut pending = String::new();
    let mut last_time: Option<f64> = None;
    for (position, event) in recording.events.iter().enumerate() {
        let live = position >= first;
        let mut redraw = false;
        match event {
            CastEvent::Output { data, .. } => parser.process(data.as_bytes()),
            CastEvent::Resize { cols, rows, .. } => {
                parser.set_size(size(*rows), size(*cols));
                redraw = true;
            }
            CastEvent::Input { .. } | CastEvent::Marker { .. } => continue,
        }
        if !live {
            continue;
        }
        // The first frame clears the viewer's screen and draws in full.
        let full = redraw || last_time.is_none();
        drawn.draw(parser.screen(), options.viewport, full, &mut pending);
        let time = event.time();
        let mut delay = match last_time {
            Some(previous) => (time - previous).max(0.0),
            None => 0.0,
        };
        if let Some(limit) = options.idle_limit {
            delay = delay.min(limit);
        }
        frames.push((delay / options.speed, std::mem::take(&mut pending)));
        last_time = Some(time);
    }
    if frames.is_empty() {
        // Nothing after the start point: show the screen as it stood.
        drawn.draw(parser.screen(), options.viewport, true, &mut pending);
        frames.push((0.0, pending));
    }
    Ok(frames)
}

/// Play a recording to stdout.
pub(crate) fn play(recording: &Recording, options: &ReplayOptions) -> Result<()> {
    let frames = frames(recording, options)?;
    catch_interrupt();
    let mut stdout = std::io::stdout().lock();
    let io = |e: std::io::Error| NonoError::Snapshot(format!("replay output failed: {e}"));
    for (delay, bytes) in frames {
        wait(delay);
        if INTERRUPTED.load(Ordering::SeqCst) {
            break;
        }
        stdout.write_all(bytes.as_bytes()).map_err(io)?;
        stdout.flush().map_err(io)?;
    }
    // Leave the cursor below the replayed screen, visible, with default
    // attributes.
    let mut rows = recording
        .events
        .iter()
        .rev()
        .find_map(|e| match e {
            CastEvent::Resize { rows, .. } => Some(*rows),
            _ => None,
        })
        .unwrap_or(recording.rows);
    if let Some((_, view_rows)) = options.viewport {
        rows = rows.min(view_rows);
    }
    write!(stdout, "\x1b[0m\x1b[?25h\x1b[{rows};1H\r\n").map_err(io)?;
    stdout.flush().map_err(io)?;
    if INTERRUPTED.load(Ordering::SeqCst) {
        eprintln!("[nono] Replay stopped.");
    }
    if let Some((view_cols, view_rows)) = options.viewport {
        let (cols, rows) = largest_size(recording);
        if cols > view_cols || rows > view_rows {
            eprintln!(
                "[nono] The session was recorded at {cols}x{rows} and this terminal is \
                 {view_cols}x{view_rows}; only the top-left part was shown. Enlarge the \
                 terminal, or use `nono transcript` to read the whole session."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn recording(events: Vec<CastEvent>) -> Recording {
        Recording {
            header: serde_json::json!({}),
            cols: 20,
            rows: 4,
            events,
            report: Default::default(),
        }
    }

    fn out(time: f64, data: &str) -> CastEvent {
        CastEvent::Output {
            time,
            data: data.to_string(),
        }
    }

    fn options(start: ReplayStart) -> ReplayOptions {
        ReplayOptions {
            speed: 1.0,
            idle_limit: None,
            start,
            viewport: None,
        }
    }

    #[test]
    fn terminal_control_sequences_are_not_replayed() {
        let rec = recording(vec![out(
            0.0,
            "\x1b]52;c;cm0gLXJmIH4=\x07\x1b]0;evil title\x07\x1b[?1000h\x1bP+q544e\x1b\\hello",
        )]);
        let all: String = frames(&rec, &options(ReplayStart::Beginning))
            .unwrap()
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect();
        assert!(all.contains("hello"));
        for forbidden in ["\x1b]52", "\x1b]0;", "evil title", "\x1b[?1000h", "\x1bP"] {
            assert!(!all.contains(forbidden), "replay leaked {forbidden:?}");
        }
    }

    #[test]
    fn delays_follow_the_recording_with_speed_and_idle_limit() {
        let rec = recording(vec![out(0.0, "a"), out(1.0, "b"), out(31.0, "c")]);
        let opts = ReplayOptions {
            speed: 2.0,
            idle_limit: Some(2.0),
            start: ReplayStart::Beginning,
            viewport: None,
        };
        let delays: Vec<f64> = frames(&rec, &opts).unwrap().iter().map(|f| f.0).collect();
        assert_eq!(delays, vec![0.0, 0.5, 1.0]);
    }

    #[test]
    fn starting_later_fast_forwards_to_the_screen_at_that_point() {
        let rec = recording(vec![
            out(0.0, "one\r\n"),
            CastEvent::Marker {
                time: 5.0,
                label: r#"nono:lifecycle:{"event":"suspended"}"#.to_string(),
            },
            out(6.0, "two\r\n"),
            out(9.0, "three\r\n"),
        ]);
        let frames = frames(&rec, &options(ReplayStart::Marker("suspended".to_string()))).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, 0.0, "first frame is shown at once");
        assert!(frames[0].1.contains("one") && frames[0].1.contains("two"));
        assert_eq!(frames[1].0, 3.0);

        let by_time = super::frames(&rec, &options(ReplayStart::parse("0:09").unwrap())).unwrap();
        assert_eq!(by_time.len(), 1);
        assert!(by_time[0].1.contains("three"));

        assert!(super::frames(&rec, &options(ReplayStart::Marker("nope".to_string()))).is_err());
    }

    /// Play `frames` into a terminal of `cols` x `rows` and return its rows.
    fn viewer_rows(frames: &[(f64, String)], cols: u16, rows: u16) -> Vec<String> {
        let mut viewer = vt100::Parser::new(size(rows), size(cols), 0);
        for (_, bytes) in frames {
            viewer.process(bytes.as_bytes());
        }
        viewer.screen().rows(0, cols).collect()
    }

    #[test]
    fn a_recording_wider_than_the_viewer_is_clipped_not_wrapped() {
        // Recorded at 20x4; the viewer is 8x3. Lines longer than the viewer
        // are redrawn and partially overwritten, the case that left stale
        // text on screen when rows wrapped in the narrower terminal.
        let rec = recording(vec![
            out(
                0.0,
                "abcdefghijklmnopqrst\r\n0123456789ABCDEFGHIJ\r\nline three\r\nlast",
            ),
            out(
                1.0,
                "\x1b[1;1Hxyz\x1b[2;5H----\x1b[4;1H\x1b[2K\x1b[3;1H\x1b[2Kshort",
            ),
            out(2.0, "\x1b[2J\x1b[1;3Hnew"),
        ]);
        let mut opts = options(ReplayStart::Beginning);
        opts.viewport = Some((8, 3));
        let frames = frames(&rec, &opts).unwrap();

        let mut model = vt100::Parser::new(size(4), size(20), 0);
        for (index, event) in rec.events.iter().enumerate() {
            if let CastEvent::Output { data, .. } = event {
                model.process(data.as_bytes());
            }
            let want: Vec<String> = model.screen().rows(0, 8).take(3).collect();
            let shown = viewer_rows(&frames[..=index], 8, 3);
            assert_eq!(shown, want, "after frame {index}");
        }
    }

    #[test]
    fn a_viewer_the_size_of_the_recording_sees_the_whole_screen() {
        let rec = recording(vec![
            out(0.0, "first line\r\nsecond\r\nthird\r\nfourth"),
            out(1.0, "\x1b[2;1H\x1b[2Kreplaced"),
        ]);
        let mut opts = options(ReplayStart::Beginning);
        opts.viewport = Some((20, 4));
        let frames = frames(&rec, &opts).unwrap();
        assert_eq!(
            viewer_rows(&frames, 20, 4),
            vec!["first line", "replaced", "third", "fourth"]
        );
    }

    #[test]
    fn parses_start_points() {
        assert_eq!(ReplayStart::parse("90").unwrap(), ReplayStart::Time(90.0));
        assert_eq!(ReplayStart::parse("1:30").unwrap(), ReplayStart::Time(90.0));
        assert_eq!(
            ReplayStart::parse("1:00:00").unwrap(),
            ReplayStart::Time(3600.0)
        );
        assert_eq!(
            ReplayStart::parse("resumed").unwrap(),
            ReplayStart::Marker("resumed".to_string())
        );
        assert!(ReplayStart::parse("1::x").is_ok_and(|s| matches!(s, ReplayStart::Marker(_))));
        assert!(ReplayStart::parse("1:.:").is_err());
    }
}
