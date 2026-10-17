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
    let unsupported = completed.stderr().contains("namespace isolation (net");
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
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM); print("UDP open")
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
    assert!(stdout.contains("UDP EPERM"), "UDP stays denied: {stdout}");
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
