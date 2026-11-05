//! Runtime tests for opt-in Linux namespace isolation (NEP-0004).
//!
//! Each test skips when the host cannot create unprivileged user namespaces
//! (for example inside a default Docker seccomp profile, or under Ubuntu's
//! AppArmor userns restriction), detected from nono's own startup refusal.

#![cfg(target_os = "linux")]

use nono_test_support::{Argv, Completed, nono_test};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::process::Command;

const BLOCKED_ISOLATED: &str = r#"{"meta":{"name":"iso-blocked"},"network":{"block":true},"linux":{"isolate":{"network":true,"ipc":true,"uts":true}}}"#;
const PROXIED_ISOLATED: &str = r#"{"meta":{"name":"iso-proxied"},"network":{"allow_domain":["example.com"]},"linux":{"isolate":{"network":true}}}"#;

/// Absolute path to a system `python3` under a default-allowed bin dir.
fn python3_bin() -> Option<String> {
    ["/usr/bin/python3", "/bin/python3", "/usr/local/bin/python3"]
        .into_iter()
        .find(|cand| {
            Command::new(cand)
                .args(["-c", "import socket"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(str::to_string)
}

/// True (and logs) when nono refused because the host lacks namespace support.
fn host_unsupported(completed: &Completed) -> bool {
    let stderr = completed.stderr();
    let unsupported =
        stderr.contains("namespace isolation (") && stderr.contains("not available on this host");
    if unsupported {
        eprintln!("skipping: host cannot create unprivileged namespaces");
    }
    unsupported
}

#[test]
fn isolated_network_namespace_has_only_loopback() {
    let t = nono_test!("iso-loopback");
    let profile = t.write_profile("iso-blocked", BLOCKED_ISOLATED);
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new("/bin/cat").arg("/proc/net/dev"));
    if host_unsupported(&completed) {
        return;
    }
    let completed = completed.assert_success("isolated run succeeds");
    let interfaces: Vec<_> = completed
        .stdout()
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next().map(str::trim).map(str::to_string))
        .collect();
    assert_eq!(interfaces, vec!["lo".to_string()], "only loopback exists");
}

#[test]
fn isolated_workload_holds_no_capabilities() {
    let t = nono_test!("iso-caps");
    let profile = t.write_profile("iso-blocked", BLOCKED_ISOLATED);
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new("/bin/cat").arg("/proc/self/status"));
    if host_unsupported(&completed) {
        return;
    }
    let completed = completed.assert_success("isolated run succeeds");
    let stdout = completed.stdout();
    let effective = stdout
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim);
    assert_eq!(
        effective,
        Some("0000000000000000"),
        "the namespace-creation capabilities must not survive exec"
    );
    // The workload keeps the invoking user's uid through the identity map.
    // SAFETY: getuid cannot fail.
    let uid = unsafe { nix::libc::getuid() };
    let mapped = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().next())
        .and_then(|id| id.parse::<u32>().ok());
    assert_eq!(mapped, Some(uid));
}

#[test]
fn isolated_network_hides_host_abstract_sockets() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let name = format!("nono-nep4-{}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
    let _listener = UnixListener::bind_addr(&address).expect("bind host abstract socket");

    let t = nono_test!("iso-abstract");
    let profile = t.write_profile("iso-blocked", BLOCKED_ISOLATED);
    let script = format!(
        "import socket\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect('\\0{name}'); print('connected')\nexcept OSError as e:\n print('refused', e.errno)"
    );
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(&script));
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("isolated run succeeds")
        .assert_stdout_lacks("connected");
}

#[test]
fn isolated_proxy_bridge_reaches_the_session_proxy() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let t = nono_test!("iso-bridge");
    let profile = t.write_profile("iso-proxied", PROXIED_ISOLATED);
    // Forward a plain-HTTP request to a denied host through the bridge:
    // without the session token (407), then with it (403 from the domain
    // filter). Both responses prove the bridge reaches the real proxy and
    // that authentication and filtering still apply. No internet is needed.
    let script = r#"
import base64, http.client, os, urllib.parse
u = urllib.parse.urlparse(os.environ["HTTP_PROXY"])
assert u.hostname == "127.0.0.1", u.hostname
auth = {"Proxy-Authorization": "Basic " + base64.b64encode(f"{u.username}:{u.password}".encode()).decode()}
for label, headers in [("anonymous", {}), ("authenticated", auth)]:
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    c.request("GET", "http://denied.invalid/", headers=headers)
    print(label, c.getresponse().status)
"#;
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(script));
    if host_unsupported(&completed) {
        return;
    }
    let completed = completed.assert_success("isolated proxied run succeeds");
    let stdout = completed.stdout();
    assert!(stdout.contains("anonymous 407"), "{stdout}");
    assert!(stdout.contains("authenticated 403"), "{stdout}");
}

/// Tries UDP egress, then a request through the process's own proxy. Prints `UDP <result>` and `PROXY <status>`.
const UDP_PROXY_PROBE: &str = r#"
import base64, errno, http.client, os, socket, urllib.parse
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("192.0.2.1", 53)); print("UDP sent")
except OSError as e:
    print("UDP", errno.errorcode.get(e.errno, str(e.errno)))
u = urllib.parse.urlparse(os.environ["HTTP_PROXY"])
auth = {"Proxy-Authorization": "Basic " + base64.b64encode(f"{u.username}:{u.password}".encode()).decode()}
c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
c.request("GET", "http://denied.invalid/", headers=auth)
print("PROXY", c.getresponse().status)
"#;

#[test]
fn proxied_session_creates_udp_sockets_only_when_isolated() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    for (profile, udp) in [
        (PROXIED_ISOLATED, "UDP EACCES"),
        (
            r#"{"meta":{"name":"iso-proxied"},"network":{"allow_domain":["example.com"]}}"#,
            "UDP EPERM",
        ),
    ] {
        let t = nono_test!("iso-session-udp");
        let profile = t.write_profile("iso-proxied", profile);
        let completed = t
            .run()
            .profile(&profile)
            .exec(Argv::new(&py).arg("-c").arg(UDP_PROXY_PROBE));
        if host_unsupported(&completed) {
            return;
        }
        let completed = completed.assert_success("proxied session runs");
        let stdout = completed.stdout();
        assert!(stdout.contains(udp), "{stdout}");
        assert!(
            stdout.contains("PROXY 403"),
            "session proxy reachable: {stdout}"
        );
    }
}

#[test]
fn isolated_command_sandbox_gets_namespace_confined_udp() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    for (isolate, udp) in [
        (
            r#""linux":{"isolate":{"network":true}},"#,
            "UDP ENETUNREACH",
        ),
        ("", "UDP EPERM"),
    ] {
        let t = nono_test!("iso-command");
        let profile = t.write_profile(
            "iso-command",
            &format!(
                r#"{{"meta":{{"name":"iso-command"}},"workdir":{{"access":"read"}},
                "network":{{"allow_domain":["example.com"]}},{isolate}
                "command_policies":{{"commands":{{"python3":{{"executable":"{py}",
                "sandbox":{{"fs_read":["/usr"],"network":{{"allow_domain":["example.org"]}}}}}}}}}}}}"#
            ),
        );
        let completed = t
            .run()
            .profile(&profile)
            .allow_cwd()
            .no_rollback()
            .exec(Argv::new("python3").arg("-c").arg(UDP_PROXY_PROBE));
        if host_unsupported(&completed) {
            return;
        }
        let completed = completed.assert_success("mediated command runs");
        let stdout = completed.stdout();
        assert!(stdout.contains(udp), "{stdout}");
        assert!(
            stdout.contains("PROXY 403"),
            "scoped proxy reachable: {stdout}"
        );
    }
}

#[test]
fn isolated_network_rejects_unrestricted_network() {
    let t = nono_test!("iso-allow-all");
    let profile = t.write_profile(
        "iso-open",
        r#"{"meta":{"name":"iso-open"},"linux":{"isolate":{"network":true}}}"#,
    );
    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/true"))
        .assert_failure("isolation with allow-all networking is a configuration error")
        .assert_stderr_contains("cannot be combined with unrestricted network access");
}

#[test]
fn isolated_network_rejects_direct_reachability_grants() {
    let t = nono_test!("iso-direct");
    let profile = t.write_profile(
        "iso-direct",
        r#"{"meta":{"name":"iso-direct"},"network":{"block":true,"open_port":[5432]},"linux":{"isolate":{"network":true}}}"#,
    );
    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/true"))
        .assert_failure("isolation with direct grants is a configuration error")
        .assert_stderr_contains("network.open_port");
}

#[test]
fn wrap_rejects_isolation() {
    let t = nono_test!("iso-wrap");
    let profile = t.write_profile("iso-blocked", BLOCKED_ISOLATED);
    t.wrap()
        .profile(&profile)
        .exec(Argv::new("/bin/true"))
        .assert_failure("nono wrap cannot provide isolation")
        .assert_stderr_contains("nono wrap does not support linux.isolate");
}

const BLOCKED_LOOPBACK: &str = r#"{"meta":{"name":"iso-loopback"},"network":{"block":true},"linux":{"isolate":{"network":true,"loopback":true}}}"#;
const PROXIED_LOOPBACK: &str = r#"{"meta":{"name":"iso-proxied-loopback"},"network":{"allow_domain":["example.com"]},"linux":{"isolate":{"network":true,"loopback":true}}}"#;

/// Serves one TCP connection on the namespace loopback, then probes every
/// path that must stay closed. Prints one `LABEL result` line per check.
const LOOPBACK_PROBE: &str = r#"
import errno, os, socket, threading, urllib.parse
def name(e): return errno.errorcode.get(e.errno, str(e.errno))
def serve(label, family, host):
    try:
        s = socket.socket(family); s.bind((host, 0)); s.listen(1)
        port = s.getsockname()[1]
        threading.Thread(target=lambda: s.accept()[0].sendall(b"pong"), daemon=True).start()
        c = socket.create_connection((host, port), timeout=5)
        print(label, c.recv(4).decode())
    except OSError as e:
        print(label, "denied", name(e))
serve("LOOP4", socket.AF_INET, "127.0.0.1")
try:
    socket.create_connection(("192.0.2.1", 443), timeout=5); print("EGRESS open")
except OSError as e:
    print("EGRESS", name(e))
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("192.0.2.1", 53)); print("UDP sent")
except OSError as e:
    print("UDP", name(e))
proxy = os.environ.get("HTTP_PROXY")
if proxy:
    port = urllib.parse.urlparse(proxy).port
    for host in ["127.0.0.1", "0.0.0.0"]:
        try:
            socket.socket().bind((host, port)); print("PROXYBIND", host, "taken")
        except OSError as e:
            print("PROXYBIND", host, name(e))
"#;

#[test]
fn isolated_loopback_allows_local_tcp_without_egress() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let t = nono_test!("iso-loopback-blocked");
    let profile = t.write_profile("iso-loopback", BLOCKED_LOOPBACK);
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(LOOPBACK_PROBE));
    if host_unsupported(&completed) {
        return;
    }
    let completed = completed.assert_success("isolated loopback run succeeds");
    let stdout = completed.stdout();
    assert!(stdout.contains("LOOP4 pong"), "{stdout}");
    assert!(
        !stdout.contains("EGRESS open"),
        "no route out of the namespace: {stdout}"
    );
    assert!(
        stdout.contains("UDP EPERM"),
        "UDP stays denied in loopback mode: {stdout}"
    );
}

#[test]
fn isolated_loopback_cannot_take_the_proxy_port() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let t = nono_test!("iso-loopback-proxied");
    let profile = t.write_profile("iso-proxied-loopback", PROXIED_LOOPBACK);
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(LOOPBACK_PROBE));
    if host_unsupported(&completed) {
        return;
    }
    let completed = completed.assert_success("isolated proxied loopback run succeeds");
    let stdout = completed.stdout();
    assert!(stdout.contains("LOOP4 pong"), "{stdout}");
    assert!(!stdout.contains("EGRESS open"), "{stdout}");
    assert!(
        stdout.contains("PROXYBIND 127.0.0.1 EADDRINUSE"),
        "the bridge holds the proxy port: {stdout}"
    );
    assert!(
        stdout.contains("PROXYBIND 0.0.0.0 EADDRINUSE"),
        "a wildcard bind cannot shadow the bridge: {stdout}"
    );
}

#[test]
fn isolated_network_without_loopback_still_denies_loopback_tcp() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let t = nono_test!("iso-no-loopback");
    let profile = t.write_profile("iso-blocked", BLOCKED_ISOLATED);
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(LOOPBACK_PROBE));
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("isolated run succeeds")
        .assert_stdout_contains("LOOP4 denied");
}

#[test]
fn loopback_without_network_isolation_is_rejected() {
    let t = nono_test!("iso-loopback-alone");
    let profile = t.write_profile(
        "iso-loopback-alone",
        r#"{"meta":{"name":"iso-loopback-alone"},"network":{"block":true},"linux":{"isolate":{"loopback":true}}}"#,
    );
    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/true"))
        .assert_failure("loopback without a network namespace is a configuration error")
        .assert_stderr_contains("requires linux.isolate.network");
}

// ---- Phase 2: mount masks (linux.isolate.mounts) ----

/// Connects to each path argument and prints `<label> CONNECTED` or
/// `<label> <errno name>`; labels are the paths' file names.
const CONNECT_PROBE: &str = r#"
import errno, os, socket, sys
for path in sys.argv[1:]:
    s = socket.socket(socket.AF_UNIX); s.settimeout(5)
    label = os.path.basename(path)
    try:
        s.connect(path); print(label, "CONNECTED")
    except OSError as e:
        print(label, errno.errorcode.get(e.errno, str(e.errno)))
"#;

fn mounts_profile(extra: &str) -> String {
    format!(r#"{{"meta":{{"name":"iso-mounts"}}{extra},"linux":{{"isolate":{{"mounts":true}}}}}}"#)
}

#[test]
fn mounts_hide_masked_sockets_and_rebind_granted_ones() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let t = nono_test!("iso-mounts-sockets");
    // Socket paths must fit sun_path, so use a short directory. Outside /tmp
    // (when /dev/shm exists) the extra mask itself is what hides it.
    let short_base = if std::path::Path::new("/dev/shm").is_dir() {
        "/dev/shm"
    } else {
        "/tmp"
    };
    let scratch = tempfile::Builder::new()
        .prefix("nono-iso-")
        .tempdir_in(short_base)
        .expect("short tempdir");
    let runtime = std::fs::canonicalize(scratch.path())
        .expect("canonical scratch")
        .join("runtime");
    std::fs::create_dir_all(runtime.join("app")).expect("mkdir runtime");
    let hidden = runtime.join("hidden.sock");
    let granted = runtime.join("app").join("granted.sock");
    let _hidden = UnixListener::bind(&hidden).expect("bind hidden");
    let _granted = UnixListener::bind(&granted).expect("bind granted");
    let json = format!(
        r#"{{"meta":{{"name":"iso-mounts"}},"filesystem":{{"unix_socket":["{}"]}},"linux":{{"isolate":{{"mounts":true,"extra_masks":["{}"]}}}}}}"#,
        granted.display(),
        runtime.display()
    );
    let profile = t.write_profile("iso-mounts", &json);
    let completed = t.run().profile(&profile).exec(
        Argv::new(&py)
            .arg("-c")
            .arg(CONNECT_PROBE)
            .arg(&hidden)
            .arg(&granted),
    );
    if host_unsupported(&completed) {
        return;
    }
    let completed = completed.assert_success("masked run succeeds");
    let stdout = completed.stdout();
    assert!(
        stdout.contains("hidden.sock ENOENT"),
        "a socket under a mask is unreachable: {stdout}"
    );
    assert!(
        stdout.contains("granted.sock CONNECTED"),
        "an explicit unix_socket grant is re-bound through the mask: {stdout}"
    );
}

#[test]
fn mounts_hide_the_users_runtime_directory() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    // SAFETY: getuid cannot fail.
    let uid = unsafe { nix::libc::getuid() };
    let runtime = std::path::PathBuf::from(format!("/run/user/{uid}"));
    let bus = runtime.join("bus");
    if !bus.exists() {
        eprintln!("skipping: no session bus at {}", bus.display());
        return;
    }
    let t = nono_test!("iso-mounts-runtime");
    let profile = t.write_profile("iso-mounts", &mounts_profile(""));
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(CONNECT_PROBE).arg(&bus));
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("masked run succeeds")
        .assert_stdout_contains("bus ENOENT");
}

#[test]
fn mounts_give_the_session_a_private_tmp() {
    let marker = format!("nono-iso-private-tmp-{}", std::process::id());
    let t = nono_test!("iso-mounts-tmp");
    let profile = t.write_profile(
        "iso-mounts",
        &mounts_profile(r#","filesystem":{"allow":["/tmp"]}"#),
    );
    let script = format!("echo inside > /tmp/{marker} && cat /tmp/{marker}");
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new("/bin/sh").arg("-c").arg(&script));
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("a /tmp grant applies to the private /tmp")
        .assert_stdout_contains("inside");
    let host = std::path::Path::new("/tmp").join(&marker);
    let leaked = host.exists();
    let _ = std::fs::remove_file(&host);
    assert!(
        !leaked,
        "writes to the private /tmp must not reach the host"
    );
}

#[test]
fn mounts_cannot_be_removed_from_inside() {
    let t = nono_test!("iso-mounts-umount");
    let profile = t.write_profile("iso-mounts", &mounts_profile(""));
    // Direct umount, and umount from a nested user+mount namespace, where the
    // workload holds capabilities but the inherited masks are locked.
    let script = "/usr/bin/umount /tmp && echo UNMOUNTED; \
                  /usr/bin/unshare -Um --propagation unchanged /usr/bin/umount /tmp \
                  && echo NESTED-UNMOUNTED; echo done";
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new("/bin/sh").arg("-c").arg(script));
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("probe script runs")
        .assert_stdout_contains("done")
        .assert_stdout_lacks("UNMOUNTED");
}

#[test]
fn mounts_keep_nested_namespaces_working() {
    let t = nono_test!("iso-mounts-nested");
    let profile = t.write_profile("iso-mounts", &mounts_profile(""));
    let completed = t.run().profile(&profile).exec(
        Argv::new("/usr/bin/unshare")
            .arg("-Um")
            .arg("--propagation")
            .arg("unchanged")
            .arg("/bin/echo")
            .arg("nested-ok"),
    );
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("nested user+mount namespaces work under the mask (#1980)")
        .assert_stdout_contains("nested-ok");
}

#[test]
fn extra_masks_without_mounts_are_rejected() {
    let t = nono_test!("iso-masks-alone");
    let profile = t.write_profile(
        "iso-masks-alone",
        r#"{"meta":{"name":"iso-masks-alone"},"linux":{"isolate":{"ipc":true,"extra_masks":["/opt/agent.sock"]}}}"#,
    );
    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/true"))
        .assert_failure("extra_masks without mounts is a configuration error")
        .assert_stderr_contains("requires linux.isolate.mounts");
}

#[test]
fn mounts_reject_capability_elevation() {
    let t = nono_test!("iso-mounts-elevation");
    let profile = t.write_profile(
        "iso-mounts",
        &mounts_profile(r#","security":{"capability_elevation":true}"#),
    );
    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/true"))
        .assert_failure("supervisor-opened paths would bypass the masks")
        .assert_stderr_contains("cannot be combined with capability elevation");
}

#[test]
fn wrap_rejects_mounts() {
    let t = nono_test!("iso-mounts-wrap");
    let profile = t.write_profile("iso-mounts", &mounts_profile(""));
    t.wrap()
        .profile(&profile)
        .exec(Argv::new("/bin/true"))
        .assert_failure("nono wrap cannot provide a mount namespace")
        .assert_stderr_contains("nono wrap does not support linux.isolate");
}

/// A short scratch directory for socket paths (they must fit `sun_path`).
/// Outside `/tmp` when `/dev/shm` exists, so an extra mask is what hides it.
fn short_scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let short_base = if std::path::Path::new("/dev/shm").is_dir() {
        "/dev/shm"
    } else {
        "/tmp"
    };
    let scratch = tempfile::Builder::new()
        .prefix("nono-iso-")
        .tempdir_in(short_base)
        .expect("short tempdir");
    let root = std::fs::canonicalize(scratch.path()).expect("canonical scratch");
    (scratch, root)
}

#[test]
fn mounts_terminate_the_sandbox_when_the_host_recreates_a_masked_path() {
    let t = nono_test!("iso-mounts-recreate");
    let (_scratch, root) = short_scratch();
    let masked = root.join("daemon.sock");
    let work = root.join("work");
    std::fs::create_dir(&work).expect("mkdir work");
    std::fs::write(&masked, b"").expect("masked file");
    let marker = work.join("started");
    let json = format!(
        r#"{{"meta":{{"name":"iso-mounts"}},"filesystem":{{"allow":["{}"]}},"linux":{{"isolate":{{"mounts":true,"extra_masks":["{}"]}}}}}}"#,
        work.display(),
        masked.display()
    );
    let profile = t.write_profile("iso-mounts", &json);
    let script = format!("touch {} && exec /bin/sleep 60", marker.display());
    let started = std::time::Instant::now();
    let completed = std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            t.run()
                .profile(&profile)
                .exec(Argv::new("/bin/sh").arg("-c").arg(&script))
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !marker.exists() && !run.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if marker.exists() {
            // What a daemon restart does: the old socket goes, a new one with
            // the same name appears. The kernel detaches the mask with it.
            std::fs::remove_file(&masked).expect("remove masked file");
            std::fs::write(&masked, b"new").expect("recreate masked file");
        }
        run.join().expect("run thread")
    });
    if host_unsupported(&completed) {
        return;
    }
    assert!(
        marker.exists(),
        "sandbox never started: {}",
        completed.stderr()
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "the sandbox must be terminated, not left to finish its sleep"
    );
    completed
        .assert_failure("a lost mask terminates the sandbox")
        .assert_stderr_contains("removed the mount mask over");
}

#[test]
fn mounts_why_agrees_with_reachability_for_directory_grants() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let t = nono_test!("iso-mounts-why");
    let (_scratch, root) = short_scratch();
    let runtime = root.join("runtime");
    let app = runtime.join("app");
    std::fs::create_dir_all(&app).expect("mkdir");
    let socket = app.join("agent.sock");
    let _listener = UnixListener::bind(&socket).expect("bind");
    // A read grant of the directory, not a unix_socket grant: it is still
    // re-bound through the mask, so the socket inside connects.
    let json = format!(
        r#"{{"meta":{{"name":"iso-mounts"}},"filesystem":{{"read":["{}"]}},"linux":{{"isolate":{{"mounts":true,"extra_masks":["{}"]}}}}}}"#,
        app.display(),
        runtime.display()
    );
    let profile = t.write_profile("iso-mounts", &json);
    let why_profile = t.root().join("iso-mounts-why.json");
    std::fs::write(&why_profile, &json).expect("write why profile");
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(CONNECT_PROBE).arg(&socket));
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("masked run succeeds")
        .assert_stdout_contains("agent.sock CONNECTED");
    let why = Command::new(env!("CARGO_BIN_EXE_nono"))
        .arg("why")
        .arg("--json")
        .arg("--profile")
        .arg(&why_profile)
        .arg("--unix-socket")
        .arg(&socket)
        .env("HOME", t.home())
        .output()
        .expect("run nono why");
    let stdout = String::from_utf8_lossy(&why.stdout);
    assert!(
        !stdout.contains("isolation_mount_masked"),
        "why must not report a re-bound socket as masked: {stdout}"
    );
    let hidden = runtime.join("hidden.sock");
    let why = Command::new(env!("CARGO_BIN_EXE_nono"))
        .arg("why")
        .arg("--json")
        .arg("--profile")
        .arg(&why_profile)
        .arg("--unix-socket")
        .arg(&hidden)
        .env("HOME", t.home())
        .output()
        .expect("run nono why");
    let stdout = String::from_utf8_lossy(&why.stdout);
    assert!(
        stdout.contains("isolation_mount_masked"),
        "why reports a socket outside the grant as masked: {stdout}"
    );
}

#[test]
fn mounts_keep_a_cwd_under_a_mask_from_reaching_the_host_directory() {
    let t = nono_test!("iso-mounts-cwd");
    let scratch = tempfile::Builder::new()
        .prefix("nono-iso-cwd-")
        .tempdir_in("/tmp")
        .expect("tempdir in /tmp");
    let root = std::fs::canonicalize(scratch.path()).expect("canonical");
    let work = root.join("work");
    std::fs::create_dir(&work).expect("mkdir work");
    std::fs::write(root.join("host-sibling"), b"secret").expect("sibling");
    let profile = t.write_profile(
        "iso-mounts",
        &mounts_profile(r#","workdir":{"access":"read"}"#),
    );
    let completed = t
        .run()
        .profile(&profile)
        .allow_cwd()
        .launch_dir(&work)
        .env("PWD", &work)
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg("ls -a .. 2>/dev/null; cat ../host-sibling 2>/dev/null || echo NO-SIBLING"),
        );
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("cwd under the private /tmp works")
        .assert_stdout_contains("NO-SIBLING")
        .assert_stdout_lacks("host-sibling")
        .assert_stdout_lacks("secret");
}

#[test]
fn mounts_reject_a_working_directory_the_masks_hide() {
    let t = nono_test!("iso-mounts-hidden-cwd");
    let scratch = tempfile::Builder::new()
        .prefix("nono-iso-cwd-")
        .tempdir_in("/tmp")
        .expect("tempdir in /tmp");
    let work = std::fs::canonicalize(scratch.path()).expect("canonical");
    let profile = t.write_profile("iso-mounts", &mounts_profile(""));
    let completed = t
        .run()
        .profile(&profile)
        .launch_dir(&work)
        .env("PWD", &work)
        .exec(Argv::new("/bin/true"));
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_failure("an ungranted cwd under a mask does not exist in the sandbox")
        .assert_stderr_contains("is hidden by the linux.isolate.mounts mask over /tmp");
}

#[test]
fn mounts_ignore_a_runtime_dir_the_user_does_not_own() {
    let t = nono_test!("iso-mounts-xdg");
    let profile = t.write_profile("iso-mounts", &mounts_profile(""));
    let completed = t
        .run()
        .profile(&profile)
        .env("XDG_RUNTIME_DIR", "/usr")
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg("test -x /usr/bin/env && echo USR-INTACT"),
        );
    if host_unsupported(&completed) {
        return;
    }
    completed
        .assert_success("an untrusted XDG_RUNTIME_DIR cannot mask /usr")
        .assert_stdout_contains("USR-INTACT");
}

#[test]
fn mounts_work_with_stdio_redirected_to_a_file() {
    // Redirected stdio is granted as /proc/<child>/fd/<n>, a procfs magic
    // link, which must still resolve when rules are opened in the child's
    // mount namespace. The harness pipes stdio, so redirect explicitly.
    let t = nono_test!("iso-mounts-stdio");
    let out_path = t.root().join("stdout.txt");
    let out = std::fs::File::create(&out_path).expect("stdout file");
    let output = Command::new(env!("CARGO_BIN_EXE_nono"))
        .args(["run", "-s", "--isolate", "mounts", "--allow-cwd", "--"])
        .args(["/bin/echo", "redirected-ok"])
        .current_dir(t.workspace())
        .env("HOME", t.home())
        .env("NONO_NO_UPDATE_CHECK", "1")
        .stdout(out)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run nono");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not available on this host") {
        eprintln!("skipping: host cannot create unprivileged namespaces");
        return;
    }
    assert!(output.status.success(), "redirected run fails: {stderr}");
    let written = std::fs::read_to_string(&out_path).expect("read stdout file");
    assert!(written.contains("redirected-ok"), "stdout: {written:?}");
}
