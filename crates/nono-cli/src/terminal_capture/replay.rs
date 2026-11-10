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
//! clipped to the viewer's terminal as it is when the frame is drawn, so a
//! recording wider or taller than it never wraps or scrolls the viewer's
//! screen out of step with the model; the top-left part that fits is shown.
//! Resizing the terminal during a replay redraws the screen at the new size.

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
}

/// The viewer's terminal as `(cols, rows)`; `None` when output is not a
/// terminal, in which case the whole recorded screen is drawn.
pub(crate) type Viewport = Option<(u16, u16)>;

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

/// Sleep for `seconds`, stopping early on Ctrl-C. `tick` runs every step,
/// so a resized terminal is redrawn without waiting for the next frame.
fn wait(seconds: f64, mut tick: impl FnMut() -> Result<()>) -> Result<()> {
    let mut remaining = Duration::from_secs_f64(seconds.max(0.0));
    let step = Duration::from_millis(50);
    while !remaining.is_zero() && !INTERRUPTED.load(Ordering::SeqCst) {
        let nap = remaining.min(step);
        std::thread::sleep(nap);
        remaining = remaining.saturating_sub(nap);
        tick()?;
    }
    Ok(())
}

/// Rows already on the viewer's screen, so unchanged rows are not resent.
#[derive(Default)]
struct Drawn {
    rows: Vec<String>,
    /// The viewport the rows were drawn for; `None` before the first draw.
    viewport: Option<Viewport>,
}

impl Drawn {
    /// Append to `out` the bytes that bring the viewer's screen to `screen`,
    /// clipped to `viewport`. Every changed row is cleared and rewritten
    /// from its first column at an absolute position, and no row is wider
    /// than the viewer's terminal, so the viewer never wraps or scrolls. The
    /// screen is cleared and drawn in full on the first draw, when `full` is
    /// set, and when the viewport has changed.
    fn draw(&mut self, screen: &vt100::Screen, viewport: Viewport, full: bool, out: &mut String) {
        let (rows, cols) = screen.size();
        let (mut show_cols, mut show_rows) = (cols.get(), rows.get());
        if let Some((view_cols, view_rows)) = viewport {
            show_cols = show_cols.min(view_cols.max(1));
            show_rows = show_rows.min(view_rows.max(1));
        }
        if full || self.viewport != Some(viewport) {
            out.push_str("\x1b[0m\x1b[H\x1b[2J");
            self.rows.clear();
            self.viewport = Some(viewport);
        }
        // A two-column character starting in the last visible column would
        // spill past it, wrapping and scrolling the viewer's screen. Such a
        // row is drawn one column narrower, leaving the character out.
        let edge = show_cols.saturating_sub(1);
        let spills =
            |row: u16| edge > 0 && screen.cell(row, edge).is_some_and(vt100::Cell::is_wide);
        let narrow: Option<Vec<String>> = (0..show_rows).any(spills).then(|| {
            screen
                .rows_formatted(0, edge)
                .take(usize::from(show_rows))
                .collect()
        });
        // A cleared row and a blank row format the same, so a row the
        // viewer has never been sent counts as blank.
        self.rows.resize(usize::from(show_rows), String::new());
        for (index, row) in screen
            .rows_formatted(0, show_cols)
            .take(usize::from(show_rows))
            .enumerate()
        {
            let row = match &narrow {
                Some(narrow) if u16::try_from(index).is_ok_and(spills) => {
                    narrow.get(index).cloned().unwrap_or_default()
                }
                _ => row,
            };
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

/// Steps through a recording one frame at a time. Each frame is drawn when
/// it is shown, at the viewport current then, so playback follows the
/// viewer's terminal as it is resized.
struct Replayer<'a> {
    events: &'a [CastEvent],
    /// First event shown in real time; earlier ones are applied at once.
    first: usize,
    /// The next event to consider.
    next: usize,
    speed: f64,
    idle_limit: Option<f64>,
    parser: vt100::Parser,
    drawn: Drawn,
    last_time: Option<f64>,
    /// The recorded terminal was resized since the last draw.
    resized: bool,
    shown_any: bool,
}

impl<'a> Replayer<'a> {
    fn new(recording: &'a Recording, options: &ReplayOptions) -> Result<Self> {
        Ok(Self {
            events: &recording.events,
            first: start_index(recording, &options.start)?,
            next: 0,
            speed: options.speed,
            idle_limit: options.idle_limit,
            parser: vt100::Parser::new(size(recording.rows), size(recording.cols), 0),
            drawn: Drawn::default(),
            last_time: None,
            resized: false,
            shown_any: false,
        })
    }

    fn apply(&mut self, event: &CastEvent) {
        match event {
            CastEvent::Output { data, .. } => self.parser.process(data.as_bytes()),
            CastEvent::Resize { cols, rows, .. } => {
                self.parser.set_size(size(*rows), size(*cols));
                self.resized = true;
            }
            CastEvent::Input { .. } | CastEvent::Marker { .. } => {}
        }
    }

    /// The delay before the next frame, or `None` when the replay is over.
    /// Events before the start point are applied at once, without frames.
    fn next_delay(&mut self) -> Option<f64> {
        let events = self.events;
        while let Some(event) = events.get(self.next) {
            if matches!(event, CastEvent::Input { .. } | CastEvent::Marker { .. }) {
                self.next += 1;
                continue;
            }
            if self.next < self.first {
                self.apply(event);
                self.next += 1;
                continue;
            }
            let mut delay = match self.last_time {
                Some(previous) => (event.time() - previous).max(0.0),
                None => 0.0,
            };
            if let Some(limit) = self.idle_limit {
                delay = delay.min(limit);
            }
            return Some(delay / self.speed);
        }
        // Nothing after the start point: show the screen as it stood, once.
        (!self.shown_any).then_some(0.0)
    }

    /// Apply the event `next_delay` found and draw the frame at `viewport`.
    fn frame(&mut self, viewport: Viewport) -> String {
        let events = self.events;
        if let Some(event) = events.get(self.next) {
            self.apply(event);
            self.last_time = Some(event.time());
            self.next += 1;
        }
        self.shown_any = true;
        self.redraw(viewport, false)
    }

    /// Draw the current screen at `viewport`; only what changed, unless
    /// `full` or the recorded or viewer's terminal was resized.
    fn redraw(&mut self, viewport: Viewport, full: bool) -> String {
        let full = full || std::mem::take(&mut self.resized);
        let mut out = String::new();
        self.drawn
            .draw(self.parser.screen(), viewport, full, &mut out);
        out
    }

    /// Rows of the screen currently shown, for leaving the cursor below it.
    fn shown_rows(&self, viewport: Viewport) -> u16 {
        let rows = self.parser.screen().size().0.get();
        viewport.map_or(rows, |(_, view_rows)| rows.min(view_rows))
    }
}

/// Produce the frames of a replay at a fixed viewport: the delay before
/// each frame and the bytes to write, without the clock.
#[cfg(test)]
fn frames(
    recording: &Recording,
    options: &ReplayOptions,
    viewport: Viewport,
) -> Result<Vec<(f64, String)>> {
    let mut replayer = Replayer::new(recording, options)?;
    let mut frames = Vec::new();
    while let Some(delay) = replayer.next_delay() {
        frames.push((delay, replayer.frame(viewport)));
    }
    Ok(frames)
}

/// Play a recording to stdout. `viewport` reports the viewer's terminal and
/// is asked before every frame and while waiting, so a resize is followed.
pub(crate) fn play(
    recording: &Recording,
    options: &ReplayOptions,
    mut viewport: impl FnMut() -> Viewport,
) -> Result<()> {
    let mut replayer = Replayer::new(recording, options)?;
    catch_interrupt();
    let mut stdout = std::io::stdout().lock();
    let io = |e: std::io::Error| NonoError::Snapshot(format!("replay output failed: {e}"));
    let mut current = viewport();
    let mut smallest = current;
    while let Some(delay) = replayer.next_delay() {
        if replayer.shown_any {
            wait(delay, || {
                let now = viewport();
                if now == current {
                    return Ok(());
                }
                current = now;
                smallest = narrowest(smallest, now);
                stdout
                    .write_all(replayer.redraw(now, true).as_bytes())
                    .and_then(|()| stdout.flush())
                    .map_err(io)
            })?;
        }
        if INTERRUPTED.load(Ordering::SeqCst) {
            break;
        }
        current = viewport();
        smallest = narrowest(smallest, current);
        stdout
            .write_all(replayer.frame(current).as_bytes())
            .map_err(io)?;
        stdout.flush().map_err(io)?;
    }
    // Leave the cursor below the replayed screen, visible, with default
    // attributes.
    let rows = replayer.shown_rows(current);
    write!(stdout, "\x1b[0m\x1b[?25h\x1b[{rows};1H\r\n").map_err(io)?;
    stdout.flush().map_err(io)?;
    if INTERRUPTED.load(Ordering::SeqCst) {
        eprintln!("[nono] Replay stopped.");
    }
    if let Some((view_cols, view_rows)) = smallest {
        let (cols, rows) = largest_size(recording);
        if cols > view_cols || rows > view_rows {
            eprintln!(
                "[nono] The session was recorded at {cols}x{rows} and this terminal was \
                 {view_cols}x{view_rows}; only the top-left part was shown. Enlarge the \
                 terminal, or use `nono transcript` to read the whole session."
            );
        }
    }
    Ok(())
}

/// The smaller of two viewports in each dimension, for the clipping notice.
fn narrowest(a: Viewport, b: Viewport) -> Viewport {
    match (a, b) {
        (Some((ac, ar)), Some((bc, br))) => Some((ac.min(bc), ar.min(br))),
        (Some(v), None) | (None, Some(v)) => Some(v),
        (None, None) => None,
    }
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
        }
    }

    #[test]
    fn terminal_control_sequences_are_not_replayed() {
        let rec = recording(vec![out(
            0.0,
            "\x1b]52;c;cm0gLXJmIH4=\x07\x1b]0;evil title\x07\x1b[?1000h\x1bP+q544e\x1b\\hello",
        )]);
        let all: String = frames(&rec, &options(ReplayStart::Beginning), None)
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
        };
        let delays: Vec<f64> = frames(&rec, &opts, None)
            .unwrap()
            .iter()
            .map(|f| f.0)
            .collect();
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
        let frames = frames(
            &rec,
            &options(ReplayStart::Marker("suspended".to_string())),
            None,
        )
        .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, 0.0, "first frame is shown at once");
        assert!(frames[0].1.contains("one") && frames[0].1.contains("two"));
        assert_eq!(frames[1].0, 3.0);

        let by_time =
            super::frames(&rec, &options(ReplayStart::parse("0:09").unwrap()), None).unwrap();
        assert_eq!(by_time.len(), 1);
        assert!(by_time[0].1.contains("three"));

        assert!(
            super::frames(
                &rec,
                &options(ReplayStart::Marker("nope".to_string())),
                None
            )
            .is_err()
        );
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
        let frames = frames(&rec, &options(ReplayStart::Beginning), Some((8, 3))).unwrap();

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
        let frames = frames(&rec, &options(ReplayStart::Beginning), Some((20, 4))).unwrap();
        assert_eq!(
            viewer_rows(&frames, 20, 4),
            vec!["first line", "replaced", "third", "fourth"]
        );
    }

    #[test]
    fn a_wide_character_at_the_clipped_edge_is_left_out() {
        // The bottom row's last visible column starts a two-column
        // character. Drawn, it would spill past the viewer's edge, wrap and
        // scroll the top row away.
        let rec = recording(vec![out(0.0, "top\r\nmiddle\r\n1234567界xyz")]);
        let clipped = frames(&rec, &options(ReplayStart::Beginning), Some((8, 3))).unwrap();
        assert_eq!(
            viewer_rows(&clipped, 8, 3),
            vec!["top", "middle", "1234567"]
        );

        // Inside the viewport it is drawn as usual.
        let fits = frames(&rec, &options(ReplayStart::Beginning), Some((9, 3))).unwrap();
        assert_eq!(viewer_rows(&fits, 9, 3), vec!["top", "middle", "1234567界"]);
    }

    #[test]
    fn frames_follow_the_viewport_as_it_changes() {
        let rec = recording(vec![
            out(0.0, "abcdefghijklmnop\r\nsecond line here"),
            out(1.0, "\x1b[1;1HABC"),
            out(2.0, "\x1b[2;1HSECOND"),
        ]);
        let mut model = vt100::Parser::new(size(4), size(20), 0);
        let mut replayer = Replayer::new(&rec, &options(ReplayStart::Beginning)).unwrap();
        // Shrink, then grow, between frames; the viewer's terminal is
        // recreated at each size, as resizing a real one would reflow it.
        let mut sent = String::new();
        for (index, (cols, rows)) in [(20, 4), (6, 2), (12, 3)].into_iter().enumerate() {
            assert!(replayer.next_delay().is_some());
            sent = replayer.frame(Some((cols, rows)));
            if let CastEvent::Output { data, .. } = &rec.events[index] {
                model.process(data.as_bytes());
            }
            let mut viewer = vt100::Parser::new(size(rows), size(cols), 0);
            viewer.process(sent.as_bytes());
            let shown: Vec<String> = viewer.screen().rows(0, cols).collect();
            let want: Vec<String> = model
                .screen()
                .rows(0, cols)
                .take(usize::from(rows))
                .collect();
            assert_eq!(shown, want, "frame {index} at {cols}x{rows}");
        }
        // A changed viewport redraws in full: growing reveals what was cut.
        assert!(sent.contains("\x1b[2J"));
        assert!(replayer.next_delay().is_none());

        // Resized while idle: the current screen is redrawn at the new size.
        let redrawn = replayer.redraw(Some((20, 4)), true);
        let mut viewer = vt100::Parser::new(size(4), size(20), 0);
        viewer.process(redrawn.as_bytes());
        assert_eq!(
            viewer.screen().rows(0, 20).take(2).collect::<Vec<_>>(),
            vec!["ABCdefghijklmnop", "SECOND line here"]
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
