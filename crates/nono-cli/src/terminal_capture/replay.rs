//! `nono replay`: play a recording back in the terminal (NEP-0010 §8).
//!
//! Recorded output is never written to the viewer's terminal as it was
//! captured. It runs through a vt100 screen model, and the viewer receives
//! only the model's own redraw sequences (text, colour and cursor
//! position). Sequences the agent printed that act on the terminal itself,
//! such as clipboard writes (OSC 52), titles, mode changes or device
//! queries, therefore never reach whoever watches the replay.

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

/// Produce the frames of a replay: the delay before each frame and the
/// bytes to write. Kept separate from the clock so it can be tested.
pub(crate) fn frames(recording: &Recording, options: &ReplayOptions) -> Result<Vec<(f64, String)>> {
    let first = start_index(recording, &options.start)?;
    let mut parser = vt100::Parser::new(size(recording.rows), size(recording.cols), 0);
    let mut shown = parser.screen().clone();
    let mut frames = Vec::new();
    // Clear the viewer's screen and draw from the top-left corner.
    let mut pending = String::from("\x1b[0m\x1b[H\x1b[2J");
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
        let screen = parser.screen();
        if redraw || position == first || last_time.is_none() {
            pending.push_str("\x1b[H\x1b[2J");
            pending.push_str(&screen.contents_formatted());
        } else {
            pending.push_str(&screen.contents_diff(&shown));
        }
        shown = screen.clone();
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
        pending.push_str(&parser.screen().contents_formatted());
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
    // Leave the cursor below the replayed screen with default attributes.
    let rows = recording
        .events
        .iter()
        .rev()
        .find_map(|e| match e {
            CastEvent::Resize { rows, .. } => Some(*rows),
            _ => None,
        })
        .unwrap_or(recording.rows);
    write!(stdout, "\x1b[0m\x1b[{rows};1H\r\n").map_err(io)?;
    stdout.flush().map_err(io)?;
    if INTERRUPTED.load(Ordering::SeqCst) {
        eprintln!("[nono] Replay stopped.");
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
