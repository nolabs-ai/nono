//! End-to-end integration tests for core sandbox execution strategies.
//!
//! Each test spawns the real `nono` binary, uses an inline hermetic profile
//! (no `extends` dependency), and asserts on exit code and stderr output.
//! Linux tests rely on Landlock/seccomp; macOS tests use Seatbelt.
//!
//! Note: `select_exec_strategy` currently always returns `Supervised`, so
//! Direct and Monitor strategies are not separately exercisable via the CLI.
//! These tests verify the denial invariant end-to-end regardless of which
//! internal strategy is active.
//!
//! AF_UNIX mediation integration tests live in `socket_access_run.rs`.

use nono_test_support::{Argv, Completed, NonoTest, Profile, Sandboxed, Sandboxing, nono_test};
use std::fs;
use std::net::TcpListener;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn python3_available() -> bool {
    Command::new("python3")
        .args(["-c", "import socket"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A profile allowing only the test's workspace, with the network blocked.
fn workspace_only_profile(t: &NonoTest, name: &str) -> Profile {
    t.write_profile(
        name,
        &format!(
            r#"{{
                "meta": {{ "name": "{name}-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = t.workspace().display()
        ),
    )
}

#[test]
#[cfg(target_os = "linux")]
fn cli_auto_block_net_uses_static_seccomp_baseline() {
    if !python3_available() {
        eprintln!("skipping: python3 unavailable");
        return;
    }

    let t = nono_test!("network-baseline");
    let script = "import ctypes, socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print('UDP_OPEN')
except OSError as e:
    print('UDP_BLOCKED', e.errno)
libc = ctypes.CDLL(None, use_errno=True)
result = libc.syscall(425, 1, None)
print('IO_URING', result, ctypes.get_errno())";

    t.run()
        .allow_cwd()
        .block_net()
        .no_rollback()
        .exec(Argv::new("python3").arg("-c").arg(script))
        .assert_success("the baseline probe itself runs")
        .assert_stdout_contains("UDP_BLOCKED 1")
        .assert_stdout_lacks("UDP_OPEN")
        .assert_stdout_contains("IO_URING -1 1");
}

#[cfg(target_os = "linux")]
fn cc_available() -> bool {
    Command::new("cc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[cfg(target_os = "linux")]
fn direct_denies_path_outside_grant() {
    let t = nono_test!("direct-deny");
    let profile = workspace_only_profile(&t, "direct-deny");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(Argv::new("/bin/cat").arg("/etc/shadow"))
        .assert_failure("/etc/shadow is outside the grant set")
        .assert_stdout_lacks("root:");
}

/// On macOS, Seatbelt is used. `/etc/passwd` is world-readable and included in
/// nono's system/group paths, so it is not a useful denial target. Instead we
/// read a sibling of the granted workspace that is entirely outside any system
/// path so Seatbelt must deny it.
#[test]
#[cfg(target_os = "macos")]
fn direct_denies_path_outside_grant_macos() {
    let t = nono_test!("direct-deny-macos");

    let secret = t.root().join("outside-secret.txt");
    fs::write(&secret, "TOPSECRET-outside-grant\n").expect("write secret");

    let profile = workspace_only_profile(&t, "direct-deny-macos");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(Argv::new("/bin/cat").arg(&secret))
        .assert_failure("a path outside the grant set is denied")
        .assert_stdout_lacks("TOPSECRET");
}

#[test]
#[cfg(target_os = "linux")]
fn deny_outside_grant_produces_diagnostic_footer() {
    let t = nono_test!("deny-diag");

    let target = t.home().join("secret.txt");
    fs::write(&target, "forbidden-content").expect("write secret");

    let profile = workspace_only_profile(&t, "deny-diag");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(Argv::new("/bin/cat").arg(&target))
        .assert_failure("a path outside the grant set is denied")
        .assert_stdout_lacks("forbidden-content");
}

#[test]
#[cfg(target_os = "linux")]
fn supervised_denies_path_outside_grant() {
    let t = nono_test!("supervised-deny");
    let profile = workspace_only_profile(&t, "supervised-deny");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(Argv::new("/bin/cat").arg("/etc/shadow"))
        .assert_failure("/etc/shadow is outside the grant set")
        .assert_stdout_lacks("root:");
}

/// Positive control: reading a file inside the granted set must succeed.
#[test]
fn granted_path_exits_zero() {
    let t = nono_test!("grant-ok");

    let sentinel = t.workspace().join("hello.txt");
    fs::write(&sentinel, "hello from nono test").expect("write sentinel");

    let profile = workspace_only_profile(&t, "grant-ok");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(Argv::new("/bin/cat").arg(&sentinel))
        .assert_success("a path inside the grant set is readable")
        .assert_stdout_contains("hello from nono test");
}

/// `network.block: true` must prevent outbound TCP connections. We bind a
/// real listener so the port is genuinely reachable without a sandbox; the
/// sandboxed child must fail to connect.
#[test]
fn network_block_denies_outbound_tcp() {
    if !python3_available() {
        eprintln!("skipping: python3 not available");
        return;
    }

    let t = nono_test!("net-block");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let profile = workspace_only_profile(&t, "net-block");

    // connect_ex() returns the errno on failure so the script exits 1 on any
    // connect error. Without a sandbox, connecting to the bound listener
    // succeeds and the script exits 0.
    let py_script = format!(
        "import socket, sys; s=socket.socket(); s.settimeout(2); \
         code=s.connect_ex(('127.0.0.1', {port})); sys.exit(0 if code == 0 else 1)"
    );

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(Argv::new("python3").arg("-c").arg(&py_script))
        .assert_failure("network block denies outbound TCP to a live listener");
}

/// A profile combining `env_credentials` (env://) and `command_policies` must
/// launch successfully when the initial command is not itself a policy shim.
/// The session process receives a broker nonce rather than the real credential
/// value (broker isolation preserved).
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn env_credentials_with_command_policies_non_shim_entry_succeeds() {
    let t = nono_test!("env-creds-cmd-policies");

    let profile = t.write_profile(
        "env-creds-cmd-policies",
        &format!(
            r#"{{
                "meta": {{ "name": "env-creds-cmd-policies-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }},
                "env_credentials": {{
                    "env://API_TOKEN": "API_TOKEN"
                }},
                "command_policies": {{
                    "commands": {{
                        "cat": {{
                            "executable": "/bin/cat"
                        }}
                    }}
                }}
            }}"#,
            workspace = t.workspace().display()
        ),
    );

    t.run()
        .profile(&profile)
        .no_rollback()
        .env("API_TOKEN", "secret-value")
        .exec(Argv::new("sh").arg("-c").arg("exit 0"))
        .assert_success("env_credentials + command_policies with a non-shim entry launches");
}

/// A script written into a writable grant-dir (cwd) must still execute under
/// an active `command_policies` outer exec gate.
#[test]
#[cfg(target_os = "linux")]
fn command_policies_allows_script_exec_in_writable_grant_dir() {
    let t = nono_test!("cmd-policies-script-exec");

    let script_path = t.workspace().join("s.sh");
    fs::write(&script_path, "#!/usr/bin/env bash\necho ok\n").expect("write script");
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))
        .expect("chmod script executable");

    let profile = command_policies_profile(&t, "cmd-policies-script-exec");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(Argv::new("bash").arg("-c").arg("./s.sh"))
        .assert_success("a script in a writable grant-dir executes under command_policies")
        .assert_stdout_contains("ok");
}

/// Same as above but for a binary compiled at runtime, so it wasn't on disk
/// when the outer exec gate was set up.
#[test]
#[cfg(target_os = "linux")]
fn command_policies_allows_compiled_binary_exec_in_writable_grant_dir() {
    if !cc_available() {
        eprintln!("skipping: cc not available");
        return;
    }

    let t = nono_test!("cmd-policies-bin-exec");

    let source_path = t.workspace().join("b.c");
    fs::write(
        &source_path,
        "#include <stdio.h>\nint main(void) { printf(\"ok\\n\"); return 0; }\n",
    )
    .expect("write source");
    let binary_path = t.workspace().join("b");
    let compile_status = Command::new("cc")
        .arg("-o")
        .arg(&binary_path)
        .arg(&source_path)
        .status()
        .expect("run cc");
    assert!(compile_status.success(), "cc must compile the test binary");

    let profile = command_policies_profile(&t, "cmd-policies-bin-exec");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(Argv::new("bash").arg("-c").arg("./b"))
        .assert_success(
            "a freshly compiled binary in a writable grant-dir executes under command_policies",
        )
        .assert_stdout_contains("ok");
}

/// Workspace-only profile with an active `command_policies` outer exec gate.
#[cfg(target_os = "linux")]
fn command_policies_profile(t: &NonoTest, name: &str) -> Profile {
    t.write_profile(
        name,
        &format!(
            r#"{{
                "meta": {{ "name": "{name}-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }},
                "command_policies": {{
                    "commands": {{
                        "cat": {{
                            "executable": "/bin/cat"
                        }}
                    }}
                }}
            }}"#,
            workspace = t.workspace().display()
        ),
    )
}

/// A granted project directory to hand the child via `--workdir`, plus a launch
/// directory that is deliberately outside the capability set.
struct WorkdirCase {
    t: NonoTest,
    profile: Profile,
    launch: PathBuf,
    project: PathBuf,
}

fn setup_workdir_case(prefix: &str) -> WorkdirCase {
    let t = nono_test!(prefix);
    let launch = t.root().join("launch");
    fs::create_dir_all(&launch).expect("root is a fresh dir this test owns");

    let project = t.workspace().to_path_buf();
    let profile = workspace_only_profile(&t, prefix);

    WorkdirCase {
        t,
        profile,
        launch,
        project,
    }
}

/// Asserts the child's own `$PWD` is the workdir.
///
/// Takes the first `PWD=` line rather than looking for a matching one anywhere:
/// a corrected entry appended after a stale one would not undo it, since
/// `getenv` resolves to the first match.
fn assert_child_pwd(completed: &Completed, case: &WorkdirCase) {
    let stdout = completed.stdout();
    assert_eq!(
        stdout.lines().find_map(|line| line.strip_prefix("PWD=")),
        case.project.to_str(),
        "--workdir must set the child's $PWD\nstdout: {stdout}\nstderr: {}",
        completed.stderr(),
    );
}

/// Runs `nono <subcommand> --workdir <project> -- /usr/bin/env` from the
/// uncovered launch directory, exporting `host_pwd` as the inherited `$PWD`.
///
/// Generic over the subcommand: `run` and `wrap` differ in which rollback flags
/// they accept, so each caller supplies an already-configured builder.
fn run_workdir_case<M: Sandboxing>(
    case: &WorkdirCase,
    cmd: Sandboxed<'_, M>,
    host_pwd: &Path,
) -> Completed {
    cmd.profile(&case.profile)
        .workdir(&case.project)
        .launch_dir(&case.launch)
        .env("PWD", host_pwd)
        .exec("/usr/bin/env")
}

/// `--workdir` must reach the child's `$PWD` even though nono was launched from a
/// directory outside the capability set.
#[test]
fn direct_workdir_sets_child_pwd_from_uncovered_launch_dir() {
    let case = setup_workdir_case("workdir-pwd-direct");

    let completed = run_workdir_case(&case, case.t.wrap(), &case.launch);
    assert_child_pwd(&completed, &case);
}

#[test]
fn supervised_workdir_sets_child_pwd_from_uncovered_launch_dir() {
    let case = setup_workdir_case("workdir-pwd-supervised");

    let completed = run_workdir_case(&case, case.t.run().no_rollback(), &case.launch);
    assert_child_pwd(&completed, &case);
}

/// A stale inherited `$PWD` — here a directory nono was not launched from —
/// must not suppress the correction.
#[test]
fn direct_workdir_overrides_untrusted_host_pwd() {
    let case = setup_workdir_case("workdir-pwd-stale-direct");

    let completed = run_workdir_case(&case, case.t.wrap(), case.t.home());
    assert_child_pwd(&completed, &case);
}

#[test]
fn supervised_workdir_overrides_untrusted_host_pwd() {
    let case = setup_workdir_case("workdir-pwd-stale-supervised");

    let completed = run_workdir_case(&case, case.t.run().no_rollback(), case.t.home());
    assert_child_pwd(&completed, &case);
}
