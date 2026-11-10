//! The `file` sink (NEP-0010 §5): a copy of the recording at an
//! operator-chosen path, for hosts that collect artifacts.
//!
//! Each closed chunk's protected asciicast lines are appended to the file,
//! so the file is a playable `.cast` as the session runs. A manifest beside
//! it, `<file>.manifest.json`, lists every chunk with the hash of its stored
//! form (as recorded in the audit log) and of the bytes it contributed here,
//! and is rewritten after each chunk so it stays current if the supervisor
//! dies.
//!
//! Both files are created when the session starts, before the agent runs.
//! They are created new (never overwritten, never through a symlink) with
//! owner-only permissions, and written through the descriptors opened then,
//! so renaming or replacing the paths later does not redirect the writes.

use super::events::{ProtectedEvent, SessionEnd};
use super::writer::{ChunkInfo, Sink, hex_digest};
use nono::{NonoError, Result};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MANIFEST_FORMAT: &str = "nono-session-recording-manifest-v1";
const MANIFEST_SUFFIX: &str = ".manifest.json";

pub(crate) struct FileSink {
    cast: File,
    cast_path: PathBuf,
    manifest: File,
    manifest_path: PathBuf,
    required: bool,
    session_id: String,
    audit_session_id: String,
    offset: u64,
    chunks: Vec<Value>,
}

/// `<file>.manifest.json` for a recording file.
pub(crate) fn manifest_path(cast_path: &Path) -> PathBuf {
    let mut name = cast_path.as_os_str().to_os_string();
    name.push(MANIFEST_SUFFIX);
    PathBuf::from(name)
}

impl FileSink {
    pub(crate) fn create(
        path: &Path,
        required: bool,
        session_id: &str,
        audit_session_id: &str,
    ) -> Result<Self> {
        let manifest_path = manifest_path(path);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| {
                NonoError::Snapshot(format!("failed to create {}: {e}", parent.display()))
            })?;
        }
        let cast = create_new(path)?;
        let manifest = match create_new(&manifest_path) {
            Ok(manifest) => manifest,
            Err(e) => {
                // Do not leave a half-made destination behind.
                drop(cast);
                let _ = fs::remove_file(path);
                return Err(e);
            }
        };
        let mut sink = Self {
            cast,
            cast_path: path.to_path_buf(),
            manifest,
            manifest_path,
            required,
            session_id: session_id.to_string(),
            audit_session_id: audit_session_id.to_string(),
            offset: 0,
            chunks: Vec::new(),
        };
        sink.write_manifest(None)?;
        Ok(sink)
    }

    fn write_manifest(&mut self, end: Option<&SessionEnd>) -> Result<()> {
        let recording = self
            .cast_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        let manifest = json!({
            "format": MANIFEST_FORMAT,
            "session_id": self.session_id,
            "audit_session_id": self.audit_session_id,
            "recording": recording,
            "complete": end.is_some(),
            "status": end.map(|end| end.status.as_str()),
            "chunks": self.chunks,
        });
        let mut body = serde_json::to_vec_pretty(&manifest).map_err(|e| {
            NonoError::Snapshot(format!("failed to encode recording manifest: {e}"))
        })?;
        body.push(b'\n');
        self.manifest
            .set_len(0)
            .and_then(|()| self.manifest.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| self.manifest.write_all(&body))
            .and_then(|()| self.manifest.sync_data())
            .map_err(|e| {
                NonoError::Snapshot(format!(
                    "failed to write {}: {e}",
                    self.manifest_path.display()
                ))
            })
    }
}

fn create_new(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    // `create_new` is O_CREAT|O_EXCL: it fails on any existing entry,
    // including a symlink, so it never follows one.
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| {
        NonoError::Snapshot(format!(
            "failed to create {} (it must not already exist): {e}",
            path.display()
        ))
    })
}

impl Sink for FileSink {
    fn name(&self) -> &str {
        "file"
    }

    fn required(&self) -> bool {
        self.required
    }

    fn write(&mut self, _event: &ProtectedEvent) -> Result<()> {
        Ok(())
    }

    fn chunk_closed(&mut self, chunk: &ChunkInfo) -> Result<()> {
        self.cast
            .write_all(&chunk.raw)
            .and_then(|()| self.cast.sync_data())
            .map_err(|e| {
                NonoError::Snapshot(format!("failed to write {}: {e}", self.cast_path.display()))
            })?;
        let event = &chunk.event;
        self.chunks.push(json!({
            "index": event.index,
            "file": super::audit_events::terminal_chunk_file_name(event.index),
            "sha256": event.sha256,
            "raw_sha256": hex_digest(&chunk.raw),
            "offset": self.offset,
            "raw_bytes": event.raw_bytes,
            "stored_bytes": event.stored_bytes,
            "seq_start": event.seq_start,
            "seq_end": event.seq_end,
            "start_offset_us": event.start_offset_us,
            "end_offset_us": event.end_offset_us,
            "audit_seq_start": event.audit_seq_start,
            "audit_seq_end": event.audit_seq_end,
        }));
        self.offset = self.offset.saturating_add(chunk.raw.len() as u64);
        self.write_manifest(None)
    }

    fn close(&mut self, end: &SessionEnd) -> Result<()> {
        self.cast.sync_all().map_err(|e| {
            NonoError::Snapshot(format!("failed to write {}: {e}", self.cast_path.display()))
        })?;
        self.write_manifest(Some(end))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::terminal_capture::audit_events::TerminalChunkEvent;

    fn chunk(index: u64, raw: &[u8]) -> ChunkInfo {
        ChunkInfo {
            event: TerminalChunkEvent {
                index,
                seq_start: index * 10,
                seq_end: index * 10 + 10,
                start_offset_us: 0,
                end_offset_us: 1,
                audit_seq_start: 0,
                audit_seq_end: 1,
                raw_bytes: raw.len() as u64,
                stored_bytes: 3,
                sha256: "ab".repeat(32),
                credential_redactions: 0,
                suppressed_inputs: 0,
            },
            raw: raw.to_vec(),
        }
    }

    fn read_manifest(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(manifest_path(path)).expect("manifest"))
            .expect("manifest json")
    }

    #[test]
    fn appends_chunks_and_keeps_manifest_current() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("artifacts").join("session.cast");
        let mut sink = FileSink::create(&path, true, "s1", "a1").expect("create");
        assert_eq!(read_manifest(&path)["complete"], false);

        sink.chunk_closed(&chunk(0, b"{\"version\":2}\n[0.1,\"o\",\"hi\"]\n"))
            .expect("chunk 0");
        sink.chunk_closed(&chunk(1, b"[0.2,\"o\",\"there\"]\n"))
            .expect("chunk 1");
        let manifest = read_manifest(&path);
        assert_eq!(manifest["chunks"].as_array().map(Vec::len), Some(2));
        assert_eq!(manifest["chunks"][1]["offset"], 29);
        assert_eq!(manifest["complete"], false);

        sink.close(&SessionEnd {
            status: "exited:0".to_string(),
        })
        .expect("close");
        let manifest = read_manifest(&path);
        assert_eq!(manifest["format"], MANIFEST_FORMAT);
        assert_eq!(manifest["complete"], true);
        assert_eq!(manifest["status"], "exited:0");
        assert_eq!(manifest["recording"], "session.cast");
        assert_eq!(
            manifest["chunks"][0]["raw_sha256"],
            hex_digest(b"{\"version\":2}\n[0.1,\"o\",\"hi\"]\n")
        );
        assert_eq!(
            fs::read(&path).expect("cast"),
            b"{\"version\":2}\n[0.1,\"o\",\"hi\"]\n[0.2,\"o\",\"there\"]\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.cast");
        fs::write(&path, b"keep").expect("plant");
        assert!(FileSink::create(&path, false, "s1", "a1").is_err());
        assert_eq!(fs::read(&path).expect("planted"), b"keep");
        assert!(!manifest_path(&path).exists());
    }

    #[test]
    fn existing_manifest_leaves_no_partial_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.cast");
        fs::write(manifest_path(&path), b"keep").expect("plant");
        assert!(FileSink::create(&path, false, "s1", "a1").is_err());
        assert!(!path.exists());
        assert_eq!(fs::read(manifest_path(&path)).expect("planted"), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn never_writes_through_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        let path = dir.path().join("session.cast");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        assert!(FileSink::create(&path, false, "s1", "a1").is_err());
        assert!(!target.exists());
    }
}
