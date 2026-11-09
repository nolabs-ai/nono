//! Exercise real listeners with two concurrent sessions sharing runtime paths.

use nono_test_support::{Argv, nono_test};
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn strict_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        use nix::libc;
        use std::os::fd::AsRawFd;
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().expect("probe socket");
        let mut fd: i32 = -1;
        let mut size = std::mem::size_of_val(&fd) as libc::socklen_t;
        // SAFETY: fd is a correctly sized output buffer for SO_PEERPIDFD.
        let ret = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut fd as *mut i32).cast(),
                &mut size,
            )
        };
        if ret != 0 {
            assert!(
                matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ENOPROTOOPT | libc::ENOSYS | libc::EINVAL)
                ),
                "unexpected probe failure"
            );
            return false;
        }
        // SAFETY: a successful SO_PEERPIDFD returned a fresh descriptor.
        unsafe { libc::close(fd) };
    }
    true
}

struct StopSession(PathBuf);

impl Drop for StopSession {
    fn drop(&mut self) {
        let _ = fs::write(&self.0, "stop");
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "session did not create {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn fake_opener(root: &Path) -> (PathBuf, PathBuf) {
    let bin = root.join("bin");
    fs::create_dir(&bin).expect("opener directory");
    let marker = root.join("opened");
    for name in ["open", "xdg-open"] {
        let path = bin.join(name);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\n",
                marker.display()
            ),
        )
        .expect("opener");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable");
    }
    (bin, marker)
}

#[test]
fn named_listeners_reject_other_sessions_and_accept_their_own_tools() {
    if !strict_supported() {
        eprintln!("strict session socket authentication unavailable on this kernel");
        return;
    }
    exercise_named_listeners(true);
}

#[test]
fn named_listeners_preserve_existing_behavior_by_default() {
    exercise_named_listeners(false);
}

fn exercise_named_listeners(strict: bool) {
    let owner = Arc::new(nono_test!("socket-owner"));
    let foreign = nono_test!("socket-foreign");
    let shared = owner.workspace().join("shared");
    fs::create_dir(&shared).expect("shared directory");
    let _stop = StopSession(shared.join("stop"));

    // The opener is outside every sandbox's write grants. Successful browser
    // requests produce a host-side marker without launching a real browser.
    let (bin, marker) = fake_opener(owner.root());
    let tool = bin.join("tool");
    fs::write(&tool, "#!/bin/sh\nscript=$2\nshift 3\neval \"$script\"\n").expect("tool");
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).expect("executable tool");
    let profile = owner.write_profile(
        "sockets",
        &json!({
            "extends": "default",
            "meta": {"name": "sockets"},
            "security": if strict { json!({"session_socket_auth": true}) } else { json!({}) },
            "workdir": {"access": "readwrite"},
            "open_urls": {"allow_origins": ["https://google.com"]},
            "command_policies": {"commands": {
                "tool": {
                    "executable": tool,
                    "sandbox": {
                        "fs_read": [shared],
                        "fs_write": [shared],
                        "open_urls": {"allow_origins": ["https://example.com"]}
                    }
                }
            }}
        })
        .to_string(),
    );
    let owner_thread = {
        let owner = Arc::clone(&owner);
        let shared = shared.clone();
        std::thread::spawn(move || {
            owner
                .run()
                .profile(&profile)
                .allow_cwd()
                .allow("/tmp")
                .no_rollback()
                .env("TMPDIR", "/tmp")
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .exec(
                    Argv::new("/bin/sh")
                        .arg("-c")
                        .arg(
                            r#"
                    set -eu
                    shared=$1
                    printf '%s\n' "$BROWSER" > "$shared/browser"
                    command -v tool > "$shared/tool"
                    "$BROWSER" https://google.com
                    tool -c '
                        set -eu
                        printf "%s\n" "$BROWSER" > "$1/tool-browser"
                        "$BROWSER" https://example.com
                    ' sh "$shared"
                    printf ready > "$shared/ready"
                    i=0
                    while [ ! -f "$shared/stop" ] && [ "$i" -lt 600 ]; do
                        /bin/sleep 0.05
                        i=$((i + 1))
                    done
                "#,
                        )
                        .arg("owner")
                        .arg(&shared),
                )
                .assert_success("owner and its brokered tool can use their own listeners")
        })
    };
    wait_for(&shared.join("ready"));
    assert_eq!(
        fs::read_to_string(&marker).expect("host opens"),
        "https://google.com\nhttps://example.com\n"
    );

    let browser = fs::read_to_string(shared.join("browser")).expect("browser");
    let browser = Path::new(browser.trim());
    let foreign_profile = foreign.write_profile("foreign-tools", &json!({
        "extends": "default",
        "meta": {"name": "foreign-tools"},
        "workdir": {"access": "readwrite"},
            "command_policies": {"commands": {"tool": {
                "executable": tool,
            "sandbox": {
                "fs_read": [shared, "/tmp"],
                "fs_write": [shared],
                    "network": {"allow_all": true},
                    "unsafe_macos_seatbelt_rules": ["(allow process-exec*)"],
                "exec_paths": [
                    "/bin/sh", browser,
                    browser.parent().expect("shim directory").join("nono-open-url-helper"),
                    fs::read_to_string(shared.join("tool")).expect("tool").trim(),
                    fs::read_to_string(shared.join("tool-browser")).expect("tool browser").trim()
                ]
            }
        }}}
    }).to_string());
    for mediated in [false, true] {
        let run = foreign.run();
        let run = if mediated {
            run.profile(&foreign_profile)
        } else {
            run
        };
        run.allow_cwd()
            .allow("/tmp")
            .allow(&shared)
            .no_rollback()
            .env("TMPDIR", "/tmp")
            .env(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin",
                    tool.parent().expect("tool directory").display()
                ),
            )
            .exec(
                Argv::new(if mediated { "tool" } else { "/bin/sh" })
                    .arg("-c")
                    .arg(
                        r#"
            set -u
            shared=$1
            strict=$2
            IFS= read -r browser < "$shared/browser"
            IFS= read -r tool < "$shared/tool"
            IFS= read -r tool_browser < "$shared/tool-browser"
            "$browser" https://google.com > "$shared/foreign-browser" 2>&1
            rc=$?
            if [ "$strict" = 1 ]; then [ "$rc" -ne 0 ]; else [ "$rc" -eq 0 ]; fi || exit 11
            "$tool_browser" https://example.com > "$shared/foreign-tool-browser" 2>&1
            [ "$?" -ne 0 ] || exit 12
            "$tool" -c 'printf escaped > "$1/escaped"' sh "$shared" > "$shared/foreign-tool" 2>&1
            [ "$?" -ne 0 ] || exit 13
            printf 'foreign listener behavior verified\n'
        "#,
                    )
                    .arg("foreign")
                    .arg(&shared)
                    .arg(if strict { "1" } else { "0" }),
            )
            .assert_success("listener authentication matches the owning session's setting")
            .assert_stdout_contains("foreign listener behavior verified");
    }

    assert!(
        !shared.join("escaped").exists(),
        "foreign tool must not execute"
    );
    let mut expected = "https://google.com\nhttps://example.com\n".to_string();
    if !strict {
        expected.push_str(&"https://google.com\n".repeat(2));
    }
    assert_eq!(
        fs::read_to_string(&marker).expect("host opens"),
        expected,
        "browser opens must match the configured session policy"
    );

    fs::write(shared.join("stop"), "stop").expect("stop owner");
    owner_thread.join().expect("owner thread");
}

#[test]
fn capture_browser_listener_rejects_other_sessions() {
    if !strict_supported() {
        eprintln!("strict session socket authentication unavailable on this kernel");
        return;
    }
    exercise_capture_listener(true);
}

#[test]
fn capture_browser_listener_preserves_existing_behavior_by_default() {
    exercise_capture_listener(false);
}

fn exercise_capture_listener(strict: bool) {
    let owner = Arc::new(nono_test!("capture-owner"));
    let foreign = nono_test!("capture-foreign");
    let shared = owner.workspace().join("shared");
    fs::create_dir(&shared).expect("shared directory");
    let _stop = StopSession(shared.join("stop"));
    let (bin, marker) = fake_opener(owner.root());
    let helper = bin.join("capture");
    fs::write(
        &helper,
        r#"#!/bin/sh
set -eu
shared=$1
printf '%s\n' "$BROWSER" > "$shared/browser"
"$BROWSER" https://google.com
printf ready > "$shared/ready"
i=0
while [ ! -f "$shared/stop" ] && [ "$i" -lt 600 ]; do
    /bin/sleep 0.05
    i=$((i + 1))
done
printf session-test-token
"#,
    )
    .expect("capture helper");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).expect("executable helper");

    let upstream = TcpListener::bind("127.0.0.1:0").expect("upstream");
    let address = upstream.local_addr().expect("upstream address");
    upstream
        .set_nonblocking(true)
        .expect("nonblocking upstream");
    let upstream_thread = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut connection = loop {
            match upstream.accept() {
                Ok((connection, _)) => break connection,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "upstream request timed out");
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(err) => panic!("upstream accept: {err}"),
            }
        };
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let len = connection.read(&mut buffer).expect("upstream request");
            assert!(
                len != 0 && request.len() < 8192,
                "incomplete upstream request"
            );
            request.extend_from_slice(&buffer[..len]);
        }
        assert!(String::from_utf8_lossy(&request).contains("session-test-token"));
        connection
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("upstream response");
    });

    let profile = owner.write_profile(
        "capture",
        &json!({
            "extends": "default",
            "meta": {"name": "capture"},
            "security": if strict { json!({"session_socket_auth": true}) } else { json!({}) },
            "workdir": {"access": "readwrite"},
            "network": {
                "credentials": ["capture_test"],
                "custom_credentials": {"capture_test": {
                    "upstream": format!("http://{address}"),
                    "credential_key": "cmd://capture_test",
                    "env_var": "CAPTURE_TEST_TOKEN",
                    "credential_format": "Bearer {}"
                }}
            },
            "credential_capture": {"capture_test": {
                "command": [helper, shared],
                "timeout_secs": 40,
                "cache_ttl_secs": 0,
                "interaction": {"open_urls": {"allow_origins": ["https://google.com"]}}
            }}
        })
        .to_string(),
    );
    let owner_thread = {
        let owner = Arc::clone(&owner);
        std::thread::spawn(move || {
            owner
                    .run()
                    .profile(&profile)
                    .allow_cwd()
                    .no_rollback()
                    .env("TMPDIR", "/tmp")
                    .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                    .exec(Argv::new("/bin/sh").arg("-c").arg(
                        r#"exec /usr/bin/curl --max-time 40 -sSf -H "Authorization: Bearer $CAPTURE_TEST_TOKEN" "$CAPTURE_TEST_BASE_URL/probe""#,
                    ))
                    .assert_success("capture helper can use its own browser listener")
                    .assert_stdout_contains("ok")
        })
    };
    wait_for(&shared.join("ready"));
    let foreign_profile = foreign.write_profile(
        "capture-caller",
        &json!({
            "extends": "default",
            "meta": {"name": "capture-caller"},
            "filesystem": {"read_file": [env!("CARGO_BIN_EXE_nono")]}
        })
        .to_string(),
    );
    foreign
        .run()
        .profile(&foreign_profile)
        .allow_cwd()
        .allow("/tmp")
        .allow(&shared)
        .no_rollback()
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(
                    r#"
            IFS= read -r browser < "$1/browser"
            "$browser" https://google.com
            rc=$?
            if [ "$2" = 1 ]; then [ "$rc" -ne 0 ]; else [ "$rc" -eq 0 ]; fi
        "#,
                )
                .arg("foreign")
                .arg(&shared)
                .arg(if strict { "1" } else { "0" }),
        )
        .assert_success("capture listener authentication matches its configuration");
    assert_eq!(
        fs::read_to_string(marker).expect("host opens"),
        "https://google.com\n".repeat(if strict { 1 } else { 2 })
    );
    fs::write(shared.join("stop"), "stop").expect("stop capture");
    let completed = owner_thread.join().expect("owner thread");
    if strict {
        completed.assert_stderr_contains("Rejected credential capture URL connection:");
    }
    upstream_thread.join().expect("upstream thread");
}

#[test]
#[cfg(target_os = "linux")]
fn enabled_authentication_refuses_an_unsupported_kernel_at_startup() {
    if strict_supported() {
        return;
    }
    let t = nono_test!("socket-auth-unsupported");
    let profile = t.write_profile(
        "strict",
        r#"{
        "extends": "default",
        "security": {"session_socket_auth": true}
    }"#,
    );
    t.run()
        .profile(&profile)
        .allow_cwd()
        .no_rollback()
        .exec(Argv::new("/bin/sh").arg("-c").arg("printf must-not-run"))
        .assert_failure("strict authentication cannot silently downgrade")
        .assert_stderr_contains("SO_PEERPIDFD requires Linux 6.5+")
        .assert_stdout_lacks("must-not-run");
}
