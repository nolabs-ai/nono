//! `nono replay` and `nono transcript` (NEP-0010 §8).

use super::recording;
use super::replay::{ReplayOptions, ReplayStart};
use super::transcript;
use crate::cli::{ReplayArgs, TranscriptArgs, TranscriptFormat};
use nono::{NonoError, Result};
use std::path::PathBuf;

/// Where a session's recording lives, and whether the session is still
/// running (so its newest chunk is not on disk yet).
struct RecordingLocation {
    dir: PathBuf,
    live: bool,
}

/// Find the audit directory holding a session's recording. Accepts a
/// runtime session ID, prefix or name, or an audit session ID.
fn resolve_recording(query: &str) -> Result<RecordingLocation> {
    if let Ok(record) = crate::session::load_session(query)
        && let Some(audit_session) = record.rollback_session.as_deref()
    {
        return Ok(RecordingLocation {
            dir: crate::audit_session::resolve_session_dir(audit_session)?,
            live: record.status != crate::session::SessionStatus::Exited
                && crate::session::is_process_alive(record.supervisor_pid, record.started_epoch),
        });
    }
    Ok(RecordingLocation {
        dir: crate::audit_session::resolve_session_dir(query)?,
        live: false,
    })
}

/// Load a recording, explaining the gap when a running session has not
/// closed its first chunk yet.
fn load(query: &str) -> Result<recording::Recording> {
    let location = resolve_recording(query)?;
    match recording::load(&location.dir) {
        Ok(loaded) => {
            if location.live {
                eprintln!(
                    "[nono] Note: the session is still running; its last few seconds are not \
                     stored yet (chunks close every {} seconds).",
                    super::DEFAULT_CHUNK_MAX_DURATION.as_secs()
                );
            }
            Ok(loaded)
        }
        Err(_) if location.live && !recording::verify(&location.dir)?.present => {
            Err(NonoError::Snapshot(format!(
                "the session is still running and nothing has been stored yet; \
                 recording chunks close every {} seconds, so try again shortly",
                super::DEFAULT_CHUNK_MAX_DURATION.as_secs()
            )))
        }
        Err(e) => Err(e),
    }
}

/// Say on stderr when the recording is known to be incomplete.
fn note_incomplete(report: &recording::RecordingReport) {
    if report.lost_events > 0 {
        eprintln!(
            "[nono] Note: {} recorded event(s) were lost and are missing from this recording.",
            report.lost_events
        );
    }
    if report.truncated {
        eprintln!("[nono] Note: the recording stopped at its size limit.");
    }
}

pub(crate) fn run_replay(args: &ReplayArgs) -> Result<()> {
    let loaded = load(&args.session)?;
    note_incomplete(&loaded.report);
    let options = ReplayOptions {
        speed: args.speed,
        idle_limit: args.idle_limit,
        start: match args.from.as_deref() {
            Some(from) => ReplayStart::parse(from)?,
            None => ReplayStart::Beginning,
        },
        viewport: crate::pty_proxy::get_terminal_winsize().map(|ws| (ws.ws_col, ws.ws_row)),
    };
    super::replay::play(&loaded, &options)
}

pub(crate) fn run_transcript(args: &TranscriptArgs) -> Result<()> {
    let loaded = load(&args.session)?;
    note_incomplete(&loaded.report);
    let entries = transcript::render(&loaded);
    match args.format {
        TranscriptFormat::Text => print!("{}", transcript::to_text(&entries)),
        TranscriptFormat::Json => {
            let json = serde_json::to_string_pretty(&serde_json::json!({
                "session_id": loaded.header["nono"]["session_id"],
                "audit_session_id": loaded.header["nono"]["audit_session_id"],
                "entries": entries,
            }))
            .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
            println!("{json}");
        }
    }
    Ok(())
}
