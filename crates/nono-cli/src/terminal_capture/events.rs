//! Capture events (NEP-0010 §2.1).
//!
//! Every value here is produced by the supervisor. Agent output reaches
//! recordings only as `Output` data, never as marker labels, so escape
//! sequences printed by the agent cannot forge markers or metadata.

use serde_json::json;

/// Which stream output came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputStream {
    Pty,
    Stderr,
}

impl OutputStream {
    /// Redactor and decoder slot for this stream.
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Pty => 0,
            Self::Stderr => 1,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pty => "pty",
            Self::Stderr => "stderr",
        }
    }
}

/// Redactor slot for input.
pub(crate) const INPUT_STREAM: usize = 2;

/// Terminal notifications seen by the screen model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotificationKind {
    Bell,
    Osc9,
    Osc777,
}

impl NotificationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bell => "bell",
            Self::Osc9 => "osc9",
            Self::Osc777 => "osc777",
        }
    }
}

/// Supervisor lifecycle facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lifecycle {
    Started,
    Suspended,
    Resumed,
    ClientAttached { client: String },
    ClientDetached { client: String },
    Exited { status: String },
}

/// One captured fact, after the fixed protections ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CaptureEvent {
    Output {
        stream: OutputStream,
        bytes: Vec<u8>,
    },
    Input {
        client: String,
        bytes: Vec<u8>,
    },
    /// Input was typed but its content and length were not captured.
    InputSuppressed {
        client: String,
        reason: &'static str,
    },
    /// The client sending input changed.
    InputClient {
        client: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Mode {
        icanon: bool,
        echo: bool,
    },
    Foreground {
        pgid: i32,
        exe: Option<String>,
    },
    Notification {
        kind: NotificationKind,
    },
    Lifecycle(Lifecycle),
    /// Credential names whose values are too short to match.
    Coverage {
        unmatched: Vec<String>,
    },
}

impl CaptureEvent {
    /// asciicast `m` label: `nono:<event>:<json>`.
    pub(crate) fn marker_label(&self) -> String {
        let (name, body) = match self {
            Self::Output { stream, bytes } => (
                "output",
                json!({ "stream": stream.as_str(), "len": bytes.len() }),
            ),
            Self::Input { client, .. } => ("input", json!({ "client": client })),
            Self::InputSuppressed { client, reason } => (
                "input",
                json!({ "client": client, "suppressed": true, "reason": reason }),
            ),
            Self::InputClient { client } => ("input_client", json!({ "client": client })),
            Self::Resize { cols, rows } => ("resize", json!({ "cols": cols, "rows": rows })),
            Self::Mode { icanon, echo } => ("mode", json!({ "icanon": icanon, "echo": echo })),
            Self::Foreground { pgid, exe } => ("foreground", json!({ "pgid": pgid, "exe": exe })),
            Self::Notification { kind } => ("notification", json!({ "kind": kind.as_str() })),
            Self::Lifecycle(event) => {
                let body = match event {
                    Lifecycle::Started => json!({ "event": "started" }),
                    Lifecycle::Suspended => json!({ "event": "suspended" }),
                    Lifecycle::Resumed => json!({ "event": "resumed" }),
                    Lifecycle::ClientAttached { client } => {
                        json!({ "event": "client_attached", "client": client })
                    }
                    Lifecycle::ClientDetached { client } => {
                        json!({ "event": "client_detached", "client": client })
                    }
                    Lifecycle::Exited { status } => json!({ "event": "exited", "status": status }),
                };
                ("lifecycle", body)
            }
            Self::Coverage { unmatched } => ("coverage", json!({ "unmatched": unmatched })),
        };
        format!("nono:{name}:{body}")
    }
}

/// An event with its capture order and time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProtectedEvent {
    /// Contiguous capture sequence number.
    pub(crate) seq: u64,
    /// Monotonic offset from session start, in microseconds.
    pub(crate) offset_us: u64,
    pub(crate) event: CaptureEvent,
    /// Credential values replaced in this event.
    pub(crate) redactions: u64,
}

/// How the session ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionEnd {
    pub(crate) status: String,
}
