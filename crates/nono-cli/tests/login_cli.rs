//! CLI-level coverage for `nono platform login` and `nono platform logout` (NEP-0009)
//! failure paths. Each test runs the binary with HOME and XDG
//! directories pointed at a fresh temporary directory, so nothing touches the
//! developer's real session, and checks that a failed login leaves nothing
//! behind.

use std::path::Path;
use std::process::{Command, Output};

fn nono_command(home: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nono"));
    command
        .args(args)
        .env_remove("NONO_CAP_FILE")
        .env_remove("NONO_NO_ENROLL")
        .env_remove("NONO_TENANT")
        .env_remove("NONO_PLATFORM_URL")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("NONO_NO_UPDATE_CHECK", "1");
    for (name, value) in extra_env {
        command.env(name, value);
    }
    command
}

fn nono(home: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    nono_command(home, args, extra_env)
        .output()
        .expect("run nono")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_not_enrolled(home: &Path) {
    let leftovers: Vec<_> = walk(home)
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                // The empty lock file carries no credential or session state.
                name == "platform.json"
                    || (name.starts_with("platform-login") && name != "platform-login.lock")
            })
        })
        .collect();
    assert!(leftovers.is_empty(), "unexpected state: {leftovers:?}");
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walk(&path));
            } else {
                found.push(path);
            }
        }
    }
    found
}

#[test]
fn login_inside_a_sandbox_fails_closed() {
    let home = tempfile::tempdir().expect("tempdir");
    let output = nono(
        home.path(),
        &[
            "platform",
            "login",
            "--url",
            "https://nono.example.com",
            "--device-code",
        ],
        &[("NONO_CAP_FILE", "/nonexistent/cap-file")],
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("cannot be used inside a sandbox"),
        "{}",
        stderr(&output)
    );
    assert_not_enrolled(home.path());
}

#[test]
fn logout_inside_a_sandbox_fails_closed() {
    let home = tempfile::tempdir().expect("tempdir");
    let output = nono(
        home.path(),
        &["platform", "logout"],
        &[("NONO_CAP_FILE", "/nonexistent/cap-file")],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot be used inside a sandbox"));
}

#[test]
fn login_rejects_plain_http_to_a_remote_host() {
    let home = tempfile::tempdir().expect("tempdir");
    let output = nono(
        home.path(),
        &["platform", "login", "--url", "http://nono.example.com"],
        &[],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("HTTPS"), "{}", stderr(&output));
    assert_not_enrolled(home.path());
}

#[test]
fn reenrollment_without_local_registration_directs_to_normal_login() {
    let home = tempfile::tempdir().expect("home");
    let output = nono(
        home.path(),
        &[
            "platform",
            "re-enroll",
            "--url",
            "http://127.0.0.1:9",
            "--no-open",
        ],
        &[],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = String::from_utf8(output.stdout).expect("text");
    assert!(text.contains("No enrollment to replace"), "{text}");
    assert!(
        text.contains("re-enroll is only for revoked device enrollments"),
        "{text}"
    );
    assert!(
        text.contains("Use normal login: nono platform login --url http://127.0.0.1:9"),
        "{text}"
    );
    assert_not_enrolled(home.path());
}

#[test]
fn group_selection_rejects_opt_out_and_empty_names_before_sign_in() {
    let home = tempfile::tempdir().expect("home");
    for (args, env) in [
        (
            vec!["platform", "login", "--group", "Engineering", "--no-enroll"],
            vec![],
        ),
        (
            vec!["platform", "login", "--group", "Engineering"],
            vec![("NONO_NO_ENROLL", "true")],
        ),
        (vec!["platform", "login", "--group", " "], vec![]),
        (
            vec![
                "platform",
                "tenant",
                "use",
                "work",
                "--group",
                "Engineering",
                "--no-enroll",
            ],
            vec![],
        ),
    ] {
        let output = nono(home.path(), &args, &env);
        assert!(!output.status.success());
        assert!(stderr(&output).contains("--group"), "{}", stderr(&output));
        assert_not_enrolled(home.path());
    }
}

#[test]
fn reenrollment_cannot_be_combined_with_enrollment_opt_out() {
    let home = tempfile::tempdir().expect("home");
    let output = nono(home.path(), &["platform", "re-enroll", "--no-enroll"], &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot be used"));
    assert_not_enrolled(home.path());
}

#[test]
fn failed_discovery_leaves_no_session_or_key() {
    let home = tempfile::tempdir().expect("tempdir");
    // Bind and drop a listener to get a loopback port with nothing behind it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("port")
        .port();
    let url = format!("http://127.0.0.1:{port}");
    let output = nono(
        home.path(),
        &["platform", "login", "--url", &url, "--device-code"],
        &[],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("discovery"), "{}", stderr(&output));
    // No record, refresh token or session key was written.
    assert_not_enrolled(home.path());
}

#[test]
fn workload_enrollment_without_a_token_is_rejected() {
    let home = tempfile::tempdir().expect("tempdir");
    let output = nono(
        home.path(),
        &[
            "platform",
            "enroll",
            "--url",
            "https://nono.example.com",
            "--workload",
        ],
        &[],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--token"), "{}", stderr(&output));
    assert_not_enrolled(home.path());
}

#[test]
fn tenant_overrides_require_sign_in_and_local_ps_rejects_them() {
    let home = tempfile::tempdir().expect("tempdir");
    for args in [&["org", "list"][..], &["ps", "--tenant", "acme"][..]] {
        assert!(!nono(home.path(), args, &[]).status.success());
    }
    for (args, env) in [
        (vec!["remote", "list", "--tenant", "acme"], vec![]),
        (vec!["remote", "list"], vec![("NONO_TENANT", "acme")]),
    ] {
        let output = nono(home.path(), &args, &env);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("requires a platform sign-in"),
            "{}",
            stderr(&output)
        );
    }

    // Switching organization is a sign-in operation, so it is refused inside
    // a sandbox like the rest of `nono platform login`.
    let output = nono(
        home.path(),
        &["platform", "login", "--tenant", "acme"],
        &[("NONO_CAP_FILE", "/nonexistent/cap-file")],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot be used inside a sandbox"));
    assert_not_enrolled(home.path());
}

#[test]
fn logout_without_a_session_is_a_no_op() {
    let home = tempfile::tempdir().expect("tempdir");
    let output = nono(home.path(), &["platform", "logout"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Not signed in"));
}

/// Write a sign-in record (pointing at an unreachable platform) and the given
/// secret files into the test's state directory.
fn write_session(home: &Path, secrets: &[(&str, &str, u32)]) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = home.join("state").join("nono");
    std::fs::create_dir_all(&dir).expect("state dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let record = serde_json::json!({
        "protocol_version": "1",
        "platform_url": "https://nono.invalid",
        "issuer": "https://nono.invalid",
        "key_thumbprint": "k",
        "user_subject": "u",
        "user_display": "Alice",
        "tenant_id": "t-1",
        "organizations": [],
        "console_url": null,
        "signed_in_at": "2026-11-02T00:00:00Z"
    });
    std::fs::write(dir.join("platform-login.json"), record.to_string()).expect("record");
    for (name, contents, mode) in secrets {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(*mode)).expect("chmod");
    }
    dir
}

#[test]
fn logout_reports_when_unreadable_credentials_prevent_revocation() {
    let home = tempfile::tempdir().expect("tempdir");
    // A refresh token other users can read is refused, and the key is
    // corrupt: neither can be used to revoke the sign-in.
    let dir = write_session(
        home.path(),
        &[
            ("platform-login-refresh-token", "exposed-refresh", 0o644),
            ("platform-login-key", "not-a-key", 0o600),
        ],
    );
    let output = nono(home.path(), &["platform", "logout"], &[]);
    assert!(!output.status.success(), "logout must not report success");
    let message = stderr(&output);
    assert!(message.contains("not revoked"), "{message}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Signed out of"));
    for name in [
        "platform-login.json",
        "platform-login-refresh-token",
        "platform-login-key",
    ] {
        assert!(!dir.join(name).exists(), "{name} must still be removed");
    }
}

#[test]
fn logout_reports_missing_credentials_as_not_revoked() {
    let home = tempfile::tempdir().expect("tempdir");
    let dir = write_session(home.path(), &[]);
    let output = nono(home.path(), &["platform", "logout"], &[]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not revoked"),
        "{}",
        stderr(&output)
    );
    assert!(!dir.join("platform-login.json").exists());
}

#[test]
fn logout_reports_leftover_credentials_without_a_record() {
    let home = tempfile::tempdir().expect("tempdir");
    let dir = write_session(
        home.path(),
        &[("platform-login-refresh-token", "orphan-refresh", 0o600)],
    );
    std::fs::remove_file(dir.join("platform-login.json")).expect("remove record");
    let output = nono(home.path(), &["platform", "logout"], &[]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not revoked"),
        "{}",
        stderr(&output)
    );
    assert!(!dir.join("platform-login-refresh-token").exists());
}

#[test]
fn obsolete_tenant_selectors_are_rejected_instead_of_ignored() {
    let home = tempfile::tempdir().expect("home");
    let old_flag = nono(home.path(), &["platform", "login", "--org", "acme"], &[]);
    assert!(!old_flag.status.success());
    let old_env = nono(home.path(), &["remote", "list"], &[("NONO_ORG", "acme")]);
    assert!(!old_env.status.success());
    assert!(stderr(&old_env).contains("replaced by NONO_TENANT"));
}

fn write_pending_tenants(home: &Path) -> std::path::PathBuf {
    std::fs::create_dir_all(home.join("config")).expect("config dir");
    let dir = write_session(home, &[]);
    let path = dir.join("platform-login.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("record")).expect("JSON");
    record["tenant_selection_pending"] = true.into();
    record["organizations"] = serde_json::json!([
        {"tenant_id": "t-1", "slug": "alice", "display_name": "Alice", "kind": "personal"},
        {"tenant_id": "t-2", "slug": "acme", "display_name": "Acme", "kind": "organization"}
    ]);
    std::fs::write(&path, record.to_string()).expect("pending session");
    path
}

#[test]
fn tenant_picker_requires_an_explicit_tenant_without_a_terminal() {
    let home = tempfile::tempdir().expect("home");
    let path = write_pending_tenants(home.path());
    let output = nono(home.path(), &["platform", "login", "--no-enroll"], &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--tenant"));
    assert!(!output.stdout.contains(&0x1b));
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("record")).expect("JSON");
    assert_eq!(record["tenant_selection_pending"], true);
}

#[test]
fn tenant_picker_uses_connect_controls_and_restores_the_terminal_on_cancel() {
    use nix::pty::openpty;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    struct Running(std::process::Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let home = tempfile::tempdir().expect("home");
    let path = write_pending_tenants(home.path());
    let original_record = std::fs::read(&path).expect("record");
    let pty = openpty(None, None).expect("PTY");
    let original = nix::sys::termios::tcgetattr(&pty.slave).expect("terminal mode");
    let mut command = nono_command(home.path(), &["platform", "login", "--no-enroll"], &[]);
    command
        .stdin(nix::unistd::dup(&pty.slave).expect("stdin"))
        .stdout(nix::unistd::dup(&pty.slave).expect("stdout"))
        .stderr(nix::unistd::dup(&pty.slave).expect("stderr"));
    let mut child = Running(command.spawn().expect("nono"));
    let mut master = std::fs::File::from(pty.master);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut output = Vec::new();
    let mut sent = false;
    loop {
        assert!(
            Instant::now() < deadline,
            "picker timed out: {}",
            String::from_utf8_lossy(&output)
        );
        let mut descriptor = nix::libc::pollfd {
            fd: master.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is initialized and remains alive throughout poll.
        let ready = unsafe { nix::libc::poll(&mut descriptor, 1, 100) };
        assert!(ready >= 0, "poll failed");
        if descriptor.revents & nix::libc::POLLIN != 0 {
            let mut buffer = [0; 8192];
            let read = master.read(&mut buffer).expect("terminal output");
            output.extend_from_slice(&buffer[..read]);
        } else if child.0.try_wait().expect("status").is_some() {
            break;
        }
        if !sent && output.windows(4).any(|bytes| bytes == b"Acme") {
            nix::unistd::write(&master, b"\x1b[Bq").expect("arrow and cancel");
            sent = true;
        }
    }
    assert!(sent, "picker was displayed");
    assert!(!child.0.wait().expect("exit").success());
    let restored = nix::sys::termios::tcgetattr(&pty.slave).expect("restored terminal");
    assert_eq!(restored.input_flags, original.input_flags);
    assert_eq!(restored.output_flags, original.output_flags);
    assert_eq!(restored.control_flags, original.control_flags);
    assert_eq!(restored.control_chars, original.control_chars);
    // PTY input can leave the kernel's PENDIN bookkeeping bit set.
    let modes = !nix::sys::termios::LocalFlags::PENDIN;
    assert_eq!(restored.local_flags & modes, original.local_flags & modes);
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("NONO TENANT"));
    assert!(output.contains("personal"));
    assert!(output.contains("organization"));
    assert!(output.contains("enter select"));
    assert!(
        output
            .lines()
            .any(|line| line.contains('❯') && line.contains("Acme")),
        "arrow highlights Acme: {output}"
    );
    assert!(output.contains("\x1b[?1049h\x1b[?25l"));
    assert!(output.contains("\x1b[?25h\x1b[?1049l"));
    assert!(output.contains("tenant selection cancelled"));
    assert_eq!(
        std::fs::read(path).expect("retained session"),
        original_record
    );
    assert!(!home.path().join("config/nono/platform.json").exists());
}

#[test]
fn enrollment_status_uses_labels_and_keeps_ids_in_json_only() {
    let home = tempfile::tempdir().expect("home");
    let dir = home.path().join("config/nono");
    std::fs::create_dir_all(&dir).expect("config");
    let path = dir.join("platform.json");
    let mut record = serde_json::json!({
        "protocol_version": "1", "platform_url": "https://nono.example.com",
        "tenant_id": "tenant-private-uuid", "subject_id": "device-private-uuid",
        "subject_kind": "device", "management_mode": "audit_only",
        "key_algorithm": "ecdsa_p256_sha256_fixed", "key_ref": "file:///private/key/location",
        "enrolled_at": "2026-11-11T11:28:00Z", "display_name": "Alice laptop",
        "tenant": {"tenant_id":"tenant-private-uuid", "slug":"acme", "display_name":"Acme", "kind":"organization"},
        "groups": [{"group_id":"0198f357-7c22-75e6-a64d-7dcb16ad5c95", "name":"Developers", "unit_id":"0198f357-7c22-75e6-a64d-7dcb16ad5c96", "unit_name":"Engineering", "is_default":false}]
    });
    std::fs::write(&path, record.to_string()).expect("state");
    let output = nono(home.path(), &["platform", "status"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = String::from_utf8(output.stdout).expect("text");
    for label in [
        "Acme (acme)",
        "Alice laptop",
        "Developers (Engineering)",
        "Audit tenant     Acme (acme)",
        "Registered locally",
        "Automatic when sessions finish",
        "11 Nov 2026, 11:28 UTC",
    ] {
        assert!(text.contains(label), "{text}");
    }
    for internal in [
        "tenant-private-uuid",
        "device-private-uuid",
        "private/key/location",
        "audit_only",
        "ecdsa_p256",
        "0198f357-7c22-75e6-a64d-7dcb16ad5c95",
    ] {
        assert!(!text.contains(internal), "{text}");
    }
    let output = nono(home.path(), &["platform", "status", "--json"], &[]);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(json["tenant_id"], "tenant-private-uuid");
    assert_eq!(json["subject_id"], "device-private-uuid");
    assert_eq!(json.as_object().expect("object").len(), 8);
    assert_eq!(json["groups"][0]["name"], "Developers");
    assert!(json.get("key_ref").is_none());
    assert!(json.get("key_algorithm").is_none());
    record.as_object_mut().expect("object").remove("tenant");
    record.as_object_mut().expect("object").remove("groups");
    record
        .as_object_mut()
        .expect("object")
        .remove("display_name");
    std::fs::write(path, record.to_string()).expect("legacy state");
    let output = nono(home.path(), &["platform", "status"], &[]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("legacy text");
    assert!(text.contains("Name not recorded"));
    assert!(!text.contains("device-private-uuid"));
}

#[test]
fn enrollment_environment_boolean_is_validated_and_conflicts_with_recovery() {
    let home = tempfile::tempdir().expect("home");
    for value in ["true", "1"] {
        let output = nono(
            home.path(),
            &["platform", "re-enroll"],
            &[("NONO_NO_ENROLL", value)],
        );
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("cannot be used"),
            "{}",
            stderr(&output)
        );
    }
    for value in ["false", "0"] {
        let output = nono(
            home.path(),
            &["platform", "re-enroll"],
            &[("NONO_NO_ENROLL", value)],
        );
        assert!(output.status.success(), "{}", stderr(&output));
    }
    let invalid = nono(
        home.path(),
        &["platform", "login"],
        &[("NONO_NO_ENROLL", "maybe")],
    );
    assert!(!invalid.status.success());
    assert!(stderr(&invalid).contains("invalid value"));
    assert_not_enrolled(home.path());
}

#[test]
fn remote_only_status_reports_context_without_claiming_device_enrollment() {
    let home = tempfile::tempdir().expect("home");
    let dir = write_session(home.path(), &[]);
    let path = dir.join("platform-login.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("record")).expect("JSON");
    record["organizations"] = serde_json::json!([
        {"tenant_id":"t-1", "slug":"alice", "display_name":"Alice", "kind":"personal"}
    ]);
    std::fs::write(path, record.to_string()).expect("record");
    let status = nono(home.path(), &["platform", "status"], &[]);
    assert!(status.status.success(), "{}", stderr(&status));
    let text = String::from_utf8(status.stdout).expect("text");
    for label in [
        "User             Alice",
        "Current tenant   Alice (personal)",
        "CLI sign-in      Stored locally",
        "Enrollment       Not enrolled",
        "Local only",
    ] {
        assert!(text.contains(label), "{text}");
    }
    let status = nono(home.path(), &["platform", "status", "--json"], &[]);
    let json: serde_json::Value = serde_json::from_slice(&status.stdout).expect("JSON");
    assert_eq!(json["enrolled"], false);
    assert_eq!(json["context"]["tenant_id"], "t-1");
    assert_eq!(json["context"]["user_display"], "Alice");
    assert!(json["context"].get("key_thumbprint").is_none());
    assert!(json["context"].get("console_url").is_none());
}

#[test]
fn remote_commands_share_the_noninteractive_tenant_selection_error() {
    let home = tempfile::tempdir().expect("home");
    write_pending_tenants(home.path());
    for args in [
        vec!["remote", "list", "--json"],
        vec![
            "remote",
            "run",
            "--agent",
            "claude",
            "--workspace",
            "project",
            "--detach",
        ],
    ] {
        let output = nono(home.path(), &args, &[]);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("multiple tenants are available"),
            "{}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty());
        assert!(!home.path().join("config/nono/platform.json").exists());
    }
}

#[test]
fn explicit_tokens_cannot_be_silently_rebound_to_a_tenant() {
    let home = tempfile::tempdir().expect("home");
    for (args, env) in [
        (
            vec!["remote", "list", "--tenant", "acme"],
            vec![("NONO_CONNECT_TOKEN", "explicit")],
        ),
        (
            vec![
                "remote",
                "run",
                "--agent",
                "claude",
                "--workspace",
                "project",
                "--detach",
                "--tenant",
                "acme",
            ],
            vec![("NONO_RUN_TOKEN", "explicit")],
        ),
    ] {
        let output = nono(home.path(), &args, &env);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("already have their own scope"),
            "{}",
            stderr(&output)
        );
        assert_not_enrolled(home.path());
    }
}

#[test]
fn tenant_switch_and_listing_require_an_existing_human_sign_in() {
    let home = tempfile::tempdir().expect("home");
    for args in [
        vec!["platform", "tenant", "use", "acme", "--no-enroll"],
        vec!["platform", "tenant", "list", "--json"],
    ] {
        let output = nono(home.path(), &args, &[]);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("nono platform login"),
            "{}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains("Session key fingerprint"));
        assert_not_enrolled(home.path());
    }
}

#[test]
fn group_commands_require_sign_in_and_reject_sandboxed_mutations() {
    let home = tempfile::tempdir().expect("home");
    for args in [
        vec!["platform", "group", "list", "--json"],
        vec!["platform", "group", "memberships"],
        vec!["platform", "group", "add", "Engineering"],
        vec!["platform", "group", "remove", "Engineering"],
        vec![
            "platform",
            "group",
            "move",
            "--from",
            "Engineering",
            "--to",
            "Production",
        ],
    ] {
        for sandbox in [false, true] {
            let env = if sandbox {
                vec![("NONO_CAP_FILE", "/nonexistent")]
            } else {
                vec![]
            };
            let output = nono(home.path(), &args, &env);
            assert!(!output.status.success());
            assert!(
                stderr(&output).contains(if sandbox {
                    "cannot be used inside a sandbox"
                } else {
                    "nono platform login"
                }),
                "{}",
                stderr(&output)
            );
            assert_not_enrolled(home.path());
        }
    }
}
