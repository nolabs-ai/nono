//! `nono transcript`: a recording rendered as readable text (NEP-0010 §8).
//!
//! Output runs through a vt100 screen model, so cursor movement, colour and
//! redraws are resolved the way a terminal would resolve them. Text that
//! scrolls by is emitted once, as lines. A screen that is redrawn in place
//! (a full-screen interface, or `clear`) is collapsed to its state at quiet
//! points: after a pause in output, at a resize, around lifecycle events,
//! and at the end. Control characters never reach the output.

use super::recording::{CastEvent, Recording, parse_marker};
use serde::Serialize;
use std::num::NonZeroU16;

/// Output silence, in seconds, after which the screen is sampled.
const QUIET_SECS: f64 = 1.0;
/// Scrollback kept between samples; a sample is forced before it fills.
const SCROLLBACK_LINES: usize = 10_000;

/// One piece of a transcript.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Entry {
    /// Lines that scrolled by, in order.
    Lines { time: f64, lines: Vec<String> },
    /// The whole screen after it was redrawn.
    Screen { time: f64, lines: Vec<String> },
    /// Something nono recorded about the session.
    Event { time: f64, text: String },
}

struct Renderer {
    parser: vt100::Parser,
    cols: u16,
    /// Lines of the current page already emitted.
    page: Vec<String>,
    page_alt: bool,
    /// The main screen's page while a full-screen interface is up; the
    /// main screen is unchanged underneath it.
    main_page: Vec<String>,
    entries: Vec<Entry>,
}

fn size(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap_or(NonZeroU16::MIN)
}

/// Remove control characters, which have no place in a transcript.
fn clean(line: &str) -> String {
    line.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn trim_trailing_blank(lines: &mut Vec<String>) {
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
}

impl Renderer {
    fn new(cols: u16, rows: u16) -> Self {
        Self {
            parser: vt100::Parser::new(size(rows), size(cols), SCROLLBACK_LINES),
            cols,
            page: Vec::new(),
            page_alt: false,
            main_page: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Read and clear the lines that scrolled off the screen, oldest first.
    fn take_scrollback(&mut self) -> Vec<String> {
        let screen = self.parser.screen_mut();
        let len = screen.scrollback_len();
        let rows = usize::from(screen.size().0.get());
        let mut lines = Vec::with_capacity(len);
        let mut taken = 0;
        while taken < len {
            let offset = len - taken;
            screen.set_scrollback(offset);
            let page: Vec<String> = screen
                .rows(0, self.cols)
                .take(rows.min(offset))
                .map(|row| clean(&row))
                .collect();
            if page.is_empty() {
                break;
            }
            taken += page.len();
            lines.extend(page);
        }
        screen.set_scrollback(0);
        screen.clear_scrollback();
        lines
    }

    /// Sample the screen and emit what is new since the last sample.
    /// `include_cursor_line` also emits the line the cursor is on, which is
    /// otherwise held until it is finished.
    fn sample(&mut self, time: f64, include_cursor_line: bool) {
        let alt = self.parser.screen().alternate_screen();
        let scrolled = if alt {
            Vec::new()
        } else {
            self.take_scrollback()
        };
        let screen = self.parser.screen();
        let mut visible: Vec<String> = screen.rows(0, self.cols).map(|row| clean(&row)).collect();
        if !alt && !include_cursor_line {
            // The cursor line may still be changing (a prompt being typed
            // at); emit it once it is finished.
            let (cursor_row, _) = screen.cursor_position();
            visible.truncate(usize::from(cursor_row));
        }
        trim_trailing_blank(&mut visible);

        if alt {
            if !self.page_alt {
                self.main_page = std::mem::take(&mut self.page);
            }
            if (!self.page_alt || visible != self.page) && !visible.is_empty() {
                self.entries.push(Entry::Screen {
                    time,
                    lines: visible.clone(),
                });
            }
            self.page = visible;
            self.page_alt = true;
            return;
        }

        if self.page_alt {
            // Back from a full-screen interface to the main screen as it was.
            self.page = std::mem::take(&mut self.main_page);
            self.page_alt = false;
        }
        let mut document = scrolled;
        document.extend(visible.iter().cloned());
        let common = self
            .page
            .iter()
            .zip(&document)
            .take_while(|(a, b)| a == b)
            .count();
        if common == self.page.len() {
            let new: Vec<String> = document.split_off(common);
            if !new.is_empty() {
                self.entries.push(Entry::Lines { time, lines: new });
            }
        } else {
            trim_trailing_blank(&mut document);
            if !document.is_empty() {
                self.entries.push(Entry::Screen {
                    time,
                    lines: document,
                });
            }
        }
        self.page = visible;
    }

    fn event(&mut self, time: f64, text: String) {
        // An event often belongs to the line on screen, such as a password
        // prompt, so show that line first.
        self.sample(time, true);
        self.entries.push(Entry::Event { time, text });
    }
}

/// Where the first switch between the main and alternate screens starts.
fn screen_switch(data: &str) -> Option<usize> {
    ["\x1b[?1049", "\x1b[?1047", "\x1b[?47"]
        .iter()
        .filter_map(|prefix| data.find(prefix))
        .min()
}

/// What a marker contributes to a transcript, if anything.
fn marker_text(label: &str) -> Option<String> {
    let (name, body) = parse_marker(label)?;
    match name {
        "lifecycle" => match body["event"].as_str()? {
            "started" => None,
            "suspended" => Some("session suspended".to_string()),
            "resumed" => Some("session resumed".to_string()),
            "client_attached" if body["client"] == "local" => None,
            "client_attached" => Some(format!(
                "{} attached",
                clean(body["client"].as_str().unwrap_or("client"))
            )),
            "client_detached" => Some(format!(
                "{} detached",
                clean(body["client"].as_str().unwrap_or("client"))
            )),
            "exited" => Some(format!(
                "session ended ({})",
                clean(body["status"].as_str().unwrap_or("unknown"))
            )),
            _ => None,
        },
        "input" if body["suppressed"] == true => Some(match body["reason"].as_str() {
            Some("password_mode") => "input not recorded (password prompt)".to_string(),
            _ => "input not recorded".to_string(),
        }),
        "coverage" => {
            let names: Vec<String> = body["unmatched"]
                .as_array()?
                .iter()
                .filter_map(|n| n.as_str().map(clean))
                .collect();
            Some(format!(
                "credentials too short to remove from the recording: {}",
                names.join(", ")
            ))
        }
        _ => None,
    }
}

/// Render a recording into transcript entries.
pub(crate) fn render(recording: &Recording) -> Vec<Entry> {
    let mut renderer = Renderer::new(recording.cols, recording.rows);
    let mut last_output: Option<f64> = None;
    let mut end = 0.0f64;
    for event in &recording.events {
        let time = event.time();
        end = end.max(time);
        match event {
            CastEvent::Output { data, .. } => {
                if let Some(previous) = last_output
                    && time - previous >= QUIET_SECS
                {
                    renderer.sample(previous, false);
                }
                // Sample just before each switch between the main and
                // alternate screens, which would otherwise hide the screen
                // as it stood.
                let mut rest = data.as_str();
                while let Some(at) = screen_switch(rest) {
                    let (before, after) = rest.split_at(at);
                    renderer.parser.process(before.as_bytes());
                    renderer.sample(time, false);
                    let skip = after.find(['h', 'l']).map_or(after.len(), |i| i + 1);
                    let (switch, remainder) = after.split_at(skip);
                    renderer.parser.process(switch.as_bytes());
                    rest = remainder;
                }
                renderer.parser.process(rest.as_bytes());
                last_output = Some(time);
                let screen = renderer.parser.screen();
                let rows = usize::from(screen.size().0.get());
                if screen.scrollback_len() + rows * 2 >= SCROLLBACK_LINES {
                    renderer.sample(time, false);
                }
            }
            CastEvent::Resize { cols, rows, .. } => {
                renderer.sample(time, false);
                renderer.parser.set_size(size(*rows), size(*cols));
                renderer.cols = *cols;
            }
            CastEvent::Marker { label, .. } => {
                if let Some(text) = marker_text(label) {
                    renderer.event(time, text);
                }
            }
            CastEvent::Input { .. } => {}
        }
    }
    // The exit marker already sampled mid-stream; take the final screen,
    // cursor line included.
    renderer.sample(end, true);
    renderer.entries
}

fn clock(time: f64) -> String {
    let total = time.max(0.0) as u64;
    let (hours, minutes, seconds) = (total / 3600, (total / 60) % 60, total % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

/// Plain-text form of a transcript.
pub(crate) fn to_text(entries: &[Entry]) -> String {
    let mut out = String::new();
    for entry in entries {
        match entry {
            Entry::Lines { lines, .. } => {
                for line in lines {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            Entry::Screen { time, lines } => {
                out.push_str(&format!("── screen at {} ──\n", clock(*time)));
                for line in lines {
                    out.push_str(line);
                    out.push('\n');
                }
                out.push_str("──\n");
            }
            Entry::Event { time, text } => {
                out.push_str(&format!("[nono {}] {text}\n", clock(*time)));
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn recording(events: Vec<CastEvent>) -> Recording {
        Recording {
            header: serde_json::json!({}),
            cols: 40,
            rows: 5,
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

    fn marker(time: f64, label: &str) -> CastEvent {
        CastEvent::Marker {
            time,
            label: label.to_string(),
        }
    }

    #[test]
    fn scrolling_output_appears_once_in_order() {
        let mut events = vec![out(0.0, "$ ")];
        events.push(out(0.5, "seq 1 12\r\n"));
        for i in 1..=12 {
            events.push(out(0.6, &format!("{i}\r\n")));
        }
        events.push(out(0.7, "$ "));
        events.push(out(3.0, "echo done\r\ndone\r\n$ "));
        let text = to_text(&render(&recording(events)));
        let expected: Vec<String> = std::iter::once("$ seq 1 12".to_string())
            .chain((1..=12).map(|i| i.to_string()))
            .chain(["$ echo done", "done", "$"].map(String::from))
            .collect();
        assert_eq!(text.lines().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn redraws_collapse_to_the_screen_at_quiet_points() {
        let mut events = vec![out(0.0, "\x1b[?1049h")];
        for i in 0..50 {
            events.push(out(0.01 * f64::from(i), &format!("\x1b[H\x1b[2Jframe {i}")));
        }
        events.push(out(2.0, "\x1b[H\x1b[2Jfinal frame"));
        events.push(out(2.1, "\x1b[?1049l"));
        let entries = render(&recording(events));
        let screens: Vec<&Vec<String>> = entries
            .iter()
            .filter_map(|e| match e {
                Entry::Screen { lines, .. } => Some(lines),
                _ => None,
            })
            .collect();
        assert_eq!(
            screens,
            vec![
                &vec!["frame 49".to_string()],
                &vec!["final frame".to_string()]
            ]
        );
    }

    #[test]
    fn main_screen_resumes_after_a_full_screen_interlude() {
        let events = vec![
            out(0.0, "before 1\r\nbefore 2\r\n"),
            out(0.1, "\x1b[?1049h\x1b[H\x1b[2Jdash"),
            out(0.2, "board\x1b[?1049l"),
            out(0.3, "after\r\n"),
        ];
        let text = to_text(&render(&recording(events)));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            vec![
                "before 1",
                "before 2",
                "── screen at 00:00 ──",
                "dashboard",
                "──",
                "after",
            ]
        );
    }

    #[test]
    fn control_sequences_never_reach_the_text() {
        let events = vec![
            out(0.0, "\x1b]52;c;aGVsbG8=\x07\x1b[31mred\x1b[0m \x07bell\r\n"),
            out(0.1, "tab\there\r\n"),
        ];
        let text = to_text(&render(&recording(events)));
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
        assert!(text.contains("red bell"));
    }

    #[test]
    fn lifecycle_and_protection_events_are_noted() {
        let events = vec![
            marker(0.0, r#"nono:lifecycle:{"event":"started"}"#),
            out(0.1, "Password: "),
            marker(
                0.5,
                r#"nono:input:{"client":"local","suppressed":true,"reason":"password_mode"}"#,
            ),
            out(0.6, "\r\nok\r\n"),
            marker(
                1.0,
                r#"nono:lifecycle:{"event":"exited","status":"exited:0"}"#,
            ),
        ];
        let text = to_text(&render(&recording(events)));
        assert!(text.contains("[nono 00:00] input not recorded (password prompt)"));
        assert!(text.contains("[nono 00:01] session ended (exited:0)"));
        assert!(text.contains("Password:"));
        assert!(text.contains("ok"));
    }
}
