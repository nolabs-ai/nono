//! Integration tests for `nono credential`.
//!
//! These exercise the resolution and guidance paths only — nothing here
//! writes to the developer's real keystore.

use nono_test_support::{NonoTest, nono_test};
use std::io::Write;
use std::process::{Output, Stdio};

/// Pipe `secret` into `credential set --account <account>`.
fn set_from_stdin(t: &NonoTest, account: &str, secret: &[u8]) -> Output {
    let mut child = t
        .command()
        .args(["credential", "set", "--account", account])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cargo builds CARGO_BIN_EXE_nono before running this test binary");
    child
        .stdin
        .take()
        .expect("stdin was piped above")
        .write_all(secret)
        .expect("the child is still reading");
    child.wait_with_output().expect("the child was spawned")
}

#[test]
fn list_json_reports_each_service_source() {
    let t = nono_test!("credential-list");
    let services = t.credential().list().json();

    let row = |name: &str| {
        services
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row["service"] == serde_json::json!(name))
            })
            .unwrap_or_else(|| panic!("{name} must be listed, got:\n{services:#}"))
    };

    let openai = row("openai");
    assert_eq!(openai["origin"], serde_json::json!("built-in"));
    assert_eq!(openai["source"]["kind"], serde_json::json!("keystore"));
    assert_eq!(openai["source"]["account"], serde_json::json!("openai"));

    let anthropic = row("anthropic");
    assert_eq!(anthropic["source"]["kind"], serde_json::json!("env"));
    assert_eq!(
        anthropic["source"]["env_var"],
        serde_json::json!("ANTHROPIC_API_KEY")
    );
}

#[test]
fn set_on_env_backed_service_is_declined_with_the_variable_name() {
    let t = nono_test!("credential-set-env");
    t.credential()
        .set()
        .service("anthropic")
        .output()
        .assert_failure("an env-backed service has no keystore entry to write")
        .assert_stderr_contains("ANTHROPIC_API_KEY")
        .assert_stderr_contains("--account");
}

#[test]
fn set_on_unknown_service_lists_the_available_ones() {
    let t = nono_test!("credential-set-unknown");
    t.credential()
        .set()
        .service("definitely-not-a-service")
        .output()
        .assert_failure("the service is in neither the built-ins nor a profile")
        .assert_stderr_contains("openai");
}

#[test]
fn rm_without_a_terminal_requires_explicit_confirmation() {
    let t = nono_test!("credential-rm-no-tty");
    t.credential()
        .rm()
        .account("nono_test_never_written")
        .output()
        .assert_failure("a piped stdin cannot answer the prompt")
        .assert_stderr_contains("-y");
}

#[test]
fn account_rejects_a_credential_reference() {
    let t = nono_test!("credential-set-ref");
    t.credential()
        .set()
        .account("op://vault/item/field")
        .output()
        .assert_failure("--account takes a keystore account, not a reference")
        .assert_stderr_contains("credential reference");
}

/// A terminal that survives Ctrl-C at the secret prompt.
///
/// `Drop` cannot cover this on its own: a default-disposition SIGINT ends the
/// process without unwinding, so the guard's restore never runs and the shell
/// is handed back with echo off.
#[test]
fn interrupting_the_secret_prompt_restores_terminal_echo() {
    use nix::pty::openpty;
    use nix::sys::signal::{Signal, kill};
    use nix::sys::termios::{LocalFlags, tcgetattr};
    use nix::unistd::Pid;
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let t = nono_test!("credential-set-sigint");
    let pty = openpty(None, None).expect("the test host provides ptys");

    let before = tcgetattr(&pty.slave).expect("a fresh pty answers tcgetattr");
    assert!(
        before.local_flags.contains(LocalFlags::ECHO),
        "a fresh pty must start with echo on, or this test proves nothing"
    );

    let stdio = || {
        Stdio::from(
            pty.slave
                .try_clone()
                .expect("the slave fd is open and cloneable"),
        )
    };
    let mut child = t
        .command()
        .args(["credential", "set", "--account", "nono_test_never_written"])
        .stdin(stdio())
        .stdout(stdio())
        .stderr(stdio())
        .spawn()
        .expect("cargo builds CARGO_BIN_EXE_nono before running this test binary");

    let mut master = std::fs::File::from(pty.master);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen = String::new();
    while !seen.contains("Secret for") {
        assert!(
            Instant::now() < deadline,
            "the prompt never appeared; saw: {seen:?}"
        );
        let mut buf = [0u8; 256];
        match master.read(&mut buf) {
            Ok(0) => panic!("the child exited before prompting; saw: {seen:?}"),
            Ok(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(e) => panic!("reading the pty failed: {e}"),
        }
    }

    let pid = Pid::from_raw(i32::try_from(child.id()).expect("a pid fits in i32"));
    kill(pid, Signal::SIGINT).expect("the child is still running");
    let status = child.wait().expect("the child was spawned");

    let after = tcgetattr(&pty.slave).expect("the pty outlives the child");
    assert!(
        after.local_flags.contains(LocalFlags::ECHO),
        "Ctrl-C at the prompt left the terminal with echo off (status: {status})"
    );
    assert_eq!(
        status.signal(),
        Some(Signal::SIGINT as i32),
        "restoring echo must not swallow the signal"
    );
}

#[test]
fn an_oversized_secret_is_rejected_before_it_is_stored() {
    let t = nono_test!("credential-set-oversized");
    let secret = vec![b'k'; 4 * 1024 + 1];

    let output = set_from_stdin(&t, "nono_test_never_written", &secret);
    assert!(
        !output.status.success(),
        "an oversized secret must not store"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("nothing stored"), "{stderr}");
}

#[test]
fn a_secret_that_is_not_utf8_is_rejected() {
    let t = nono_test!("credential-set-non-utf8");

    let output = set_from_stdin(&t, "nono_test_never_written", b"\xff\xfe\n");
    assert!(
        !output.status.success(),
        "a non-UTF-8 secret must not store"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("UTF-8"), "{stderr}");
}

#[test]
fn an_empty_stdin_stores_nothing() {
    let t = nono_test!("credential-set-empty");

    let output = set_from_stdin(&t, "nono_test_never_written", b"");
    assert!(!output.status.success(), "an empty stdin must not store");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no secret on stdin"), "{stderr}");
}

/// The interactive read path, driven through a real terminal.
#[test]
fn an_empty_line_at_the_prompt_stores_nothing_and_restores_echo() {
    use nix::pty::openpty;
    use nix::sys::termios::{LocalFlags, tcgetattr};
    use std::io::Read;
    use std::time::{Duration, Instant};

    let t = nono_test!("credential-set-empty-line");
    let pty = openpty(None, None).expect("the test host provides ptys");

    let stdio = || {
        Stdio::from(
            pty.slave
                .try_clone()
                .expect("the slave fd is open and cloneable"),
        )
    };
    let mut child = t
        .command()
        .args(["credential", "set", "--account", "nono_test_never_written"])
        .stdin(stdio())
        .stdout(stdio())
        .stderr(stdio())
        .spawn()
        .expect("cargo builds CARGO_BIN_EXE_nono before running this test binary");

    let mut master = std::fs::File::from(pty.master);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen = String::new();
    while !seen.contains("Secret for") {
        assert!(
            Instant::now() < deadline,
            "the prompt never appeared; saw: {seen:?}"
        );
        let mut buf = [0u8; 256];
        match master.read(&mut buf) {
            Ok(0) => panic!("the child exited before prompting; saw: {seen:?}"),
            Ok(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(e) => panic!("reading the pty failed: {e}"),
        }
    }

    master.write_all(b"\n").expect("the child is still reading");
    let status = child.wait().expect("the child was spawned");
    assert!(!status.success(), "an empty secret must not be stored");

    let after = tcgetattr(&pty.slave).expect("the pty outlives the child");
    assert!(
        after.local_flags.contains(LocalFlags::ECHO),
        "the prompt must hand the terminal back with echo on"
    );
}
