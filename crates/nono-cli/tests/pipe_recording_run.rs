//! End-to-end integration tests for supervised non-PTY pipe session recording (NEP-0010).

use nono_test_support::nono_test;
use std::fs;
use std::io::Write;
use std::process::Stdio;

fn first_audit_session_id(audit_root: &std::path::Path) -> String {
    let mut ids: Vec<String> = fs::read_dir(audit_root)
        .expect("read audit root")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    ids.sort();
    ids.into_iter().next().expect("at least one audit session")
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn pipe_run_records_stdout_and_stderr_with_input_off_by_default() {
    let t = nono_test!("pipe-rec-default");
    let cast_path = t.root().join("pipe-default.cast");

    let mut cmd = t.command();
    cmd.args([
        "run",
        "--allow-cwd",
        "--block-net",
        "--no-rollback",
        "--record-required",
        "--record-file",
    ])
    .arg(&cast_path)
    .args(["--", "/bin/sh", "-c", "echo pipe-out; echo pipe-err >&2"])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let output = cmd.output().expect("spawn nono run");
    assert!(
        output.status.success(),
        "expected success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("pipe-out"),
        "stdout missing output: {stdout}"
    );
    assert!(
        stderr.contains("pipe-err"),
        "stderr missing output: {stderr}"
    );

    let cast = fs::read_to_string(&cast_path).expect("read cast copy");
    let mut lines = cast.lines();
    let header: serde_json::Value =
        serde_json::from_str(lines.next().expect("cast header")).expect("valid header JSON");
    assert_eq!(header["nono"]["pty"], false);
    assert_eq!(header["nono"]["capture"]["input"], "off");
    assert!(cast.contains("pipe-out"));
    assert!(cast.contains("pipe-err"));

    let session_id = first_audit_session_id(&t.audit_root());
    let verify = t.audit().verify(&session_id).json();
    assert_eq!(verify["session"]["records_verified"], true, "{verify}");
    assert_eq!(verify["recording"]["present"], true, "{verify}");
    assert_eq!(verify["recording"]["chunks"], 1, "{verify}");
    assert_eq!(verify["recording"]["missing"], serde_json::json!([]));
    assert_eq!(verify["recording"]["mismatched"], serde_json::json!([]));
    assert_eq!(verify["recording"]["index_gaps"], false, "{verify}");
    assert_eq!(
        verify["recording"]["unexplained_gaps"],
        serde_json::json!([])
    );

    let transcript = t
        .command()
        .args(["transcript", &session_id])
        .output()
        .expect("run nono transcript");
    assert!(transcript.status.success());
    let text = String::from_utf8_lossy(&transcript.stdout);
    assert!(text.contains("pipe-out\n") || text.contains("pipe-out\r\n"));
    assert!(text.contains("pipe-err"));
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn pipe_run_with_input_on_relays_and_records_stdin() {
    let t = nono_test!("pipe-rec-input");
    let cast_path = t.root().join("pipe-input.cast");
    let profile_path = t.home().join("pipe-input.json");
    fs::write(
        &profile_path,
        format!(
            r#"{{
                "meta": {{ "name": "pipe-input-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }},
                "session_recording": {{
                    "enabled": true,
                    "required": true,
                    "input": "on",
                    "file": "{cast}"
                }}
            }}"#,
            workspace = t.workspace().display(),
            cast = cast_path.display()
        ),
    )
    .expect("write profile");

    let mut cmd = t.command();
    cmd.args(["run", "--no-rollback", "--profile"])
        .arg(&profile_path)
        .args(["--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn nono run");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(b"hello-pipe-stdin\n").expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait for nono run");
    assert!(
        output.status.success(),
        "expected success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "hello-pipe-stdin\n");

    let cast = fs::read_to_string(&cast_path).expect("read cast copy");
    let mut lines = cast.lines();
    let header: serde_json::Value =
        serde_json::from_str(lines.next().expect("cast header")).expect("valid header JSON");
    assert_eq!(header["nono"]["pty"], false);
    assert_eq!(header["nono"]["capture"]["input"], "on");

    let has_input = lines.any(|line| {
        serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .is_some_and(|v| v[1] == "i" && v[2] == "hello-pipe-stdin\n")
    });
    assert!(has_input, "expected recorded stdin event in {cast}");
}
