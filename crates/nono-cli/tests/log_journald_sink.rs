//! `--log-journald` replaces the log file sink, and the file sink appears only
//! when journald cannot be reached. Which branch runs depends on the host, so
//! the expected sink is derived from a journald probe.

#![cfg(target_os = "linux")]

use std::os::unix::net::UnixDatagram;
use std::process::Command;

const JOURNALD_PATH: &str = "/run/systemd/journal/socket";

/// Same probe as `tracing_journald::Layer::new`: journald must accept a payload.
fn journald_reachable() -> bool {
    UnixDatagram::unbound()
        .and_then(|socket| socket.send_to(&[], JOURNALD_PATH))
        .is_ok()
}

#[test]
fn journald_replaces_inherited_log_file() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let log = dir.path().join("nono.log");

    let output = Command::new(env!("CARGO_BIN_EXE_nono"))
        .env("NONO_LOG_FILE", &log)
        .args([
            "--log-journald",
            "run",
            "--dry-run",
            "--allow",
            "/tmp",
            "echo",
        ])
        .output()
        .expect("run nono");

    assert!(
        output.status.success(),
        "nono failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written = log.exists();
    let reachable = journald_reachable();
    assert_eq!(
        written,
        !reachable,
        "log file written={written}, journald reachable={reachable}; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
