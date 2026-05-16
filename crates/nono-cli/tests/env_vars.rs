//! Integration tests for environment variables and Windows smoke execution.
//!
//! These run as separate processes, so env vars are isolated and cannot race
//! with parallel unit tests.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Resolve `%SystemRoot%\System32\<name>.exe`. Avoids the path-hijack hazard
/// of `Command::new("<tool>")` picking up a malicious binary from the cwd.
#[cfg(target_os = "windows")]
fn system32_exe(name: &str) -> std::path::PathBuf {
    let system_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    system_root.join("System32").join(format!("{name}.exe"))
}

/// Combine stdout + stderr for assertion checking (nono writes UX to stderr).
fn combined_output(output: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
}

#[cfg(target_os = "windows")]
fn output_has_windows_access_denied(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    normalized.contains("access is denied")
        || normalized.contains("is denied.")
        || normalized.contains("unauthorizedaccessexception")
        || normalized.contains("permissiondenied:")
        || normalized.contains("unauthorized")
}

#[cfg(target_os = "windows")]
fn windows_net_probe_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_windows-net-probe"))
}

#[cfg(target_os = "windows")]
fn try_set_low_integrity_label(path: &std::path::Path) -> bool {
    let Ok(output) = Command::new(system32_exe("icacls"))
        .arg(path)
        .args(["/setintegritylevel", "(OI)(CI)L"])
        .output()
    else {
        eprintln!("skipping low-integrity label integration test because icacls is unavailable");
        return false;
    };

    if output.status.success() {
        true
    } else {
        eprintln!(
            "skipping low-integrity label integration test because icacls failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }
}

#[cfg(target_os = "windows")]
fn try_add_and_remove_windows_firewall_rule(program: &std::path::Path) -> bool {
    let suffix = format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_nanos()
    );
    let name = format!("nono-test-fw-{suffix}");
    let program_arg = format!("program={}", program.display());

    let add = Command::new(system32_exe("netsh"))
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={name}"),
            "dir=out",
            "action=block",
            &program_arg,
            "enable=yes",
            "profile=any",
        ])
        .output();
    let Ok(add) = add else {
        eprintln!("skipping firewall integration test because netsh is unavailable");
        return false;
    };
    let _ = Command::new(system32_exe("netsh"))
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={name}"),
        ])
        .output();
    if add.status.success() {
        true
    } else {
        eprintln!(
            "skipping firewall integration test because rule creation failed: {}{}",
            String::from_utf8_lossy(&add.stdout),
            String::from_utf8_lossy(&add.stderr)
        );
        false
    }
}

#[cfg(target_os = "windows")]
fn host_can_prepare_managed_windows_runtime_root(seed_dir: &std::path::Path) -> bool {
    let probe = seed_dir.join("label-probe");
    if let Err(err) = std::fs::create_dir_all(&probe) {
        eprintln!(
            "skipping managed runtime-root test because {} could not be created: {err}",
            probe.display()
        );
        return false;
    }

    if try_set_low_integrity_label(&probe) {
        true
    } else {
        eprintln!(
            "skipping managed runtime-root test because the host could not prepare a low-integrity directory inside {}",
            seed_dir.display()
        );
        false
    }
}

#[cfg(target_os = "windows")]
fn expected_windows_runtime_root(seed_dir: &std::path::Path) -> std::path::PathBuf {
    let low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .map(|local| local.join("Temp").join("Low"));
    let local_low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .and_then(|local| local.parent().map(|root| root.join("LocalLow")));
    let managed_root = seed_dir.join(".nono-runtime-low");
    let managed_root_ready =
        managed_root.exists() && nono::Sandbox::windows_supports_direct_writable_dir(&managed_root);
    if low_root
        .as_ref()
        .is_some_and(|prefix| seed_dir.starts_with(prefix))
        || local_low_root
            .as_ref()
            .is_some_and(|prefix| seed_dir.starts_with(prefix))
    {
        seed_dir.join(".nono-runtime")
    } else if managed_root_ready {
        managed_root
    } else {
        low_root
            .unwrap_or_else(|| seed_dir.join(".nono-runtime-low"))
            .join("nono")
            .join(seed_dir.to_string_lossy().replace(['\\', '/', ':'], "_"))
    }
}

#[cfg(target_os = "windows")]
fn host_can_write_expected_windows_runtime_root(seed_dir: &std::path::Path) -> bool {
    let runtime_root = expected_windows_runtime_root(seed_dir);
    let probe_dir = runtime_root.join("tmp");
    if let Err(err) = std::fs::create_dir_all(&probe_dir) {
        eprintln!(
            "skipping redirected tmp runtime-root test because {} could not be created: {err}",
            probe_dir.display()
        );
        return false;
    }

    let probe = probe_dir.join("host-write-probe.txt");
    match std::fs::write(&probe, "probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(err) => {
            eprintln!(
                "skipping redirected tmp runtime-root test because {} is not host-writable: {err}",
                probe.display()
            );
            false
        }
    }
}

#[test]
fn env_nono_allow_comma_separated() {
    // Create real temporary directories so the paths exist and appear in
    // the dry-run capability banner.  Non-existent paths are silently
    // skipped (with a WARN log), which is not visible in all environments
    // (e.g. NixOS builds with RUST_LOG unset).  See #563.
    let dir = tempfile::tempdir().expect("tmpdir");
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    std::fs::create_dir(&path_a).expect("create dir a");
    std::fs::create_dir(&path_b).expect("create dir b");

    let allow_val = format!("{},{}", path_a.display(), path_b.display());

    let output = nono_bin()
        .env("NONO_ALLOW", &allow_val)
        .args(["run", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    let a_str = path_a.display().to_string();
    let b_str = path_b.display().to_string();
    assert!(
        text.contains(a_str.as_str()) && text.contains(b_str.as_str()),
        "expected both paths in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_nono_block_net() {
    let output = nono_bin()
        .env("NONO_BLOCK_NET", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        text.contains("blocked"),
        "expected network blocked in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_nono_block_net_accepts_true() {
    let output = nono_bin()
        .env("NONO_BLOCK_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_BLOCK_NET=true should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn legacy_env_nono_net_block_still_works() {
    let output = nono_bin()
        .env("NONO_NET_BLOCK", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        text.contains("blocked"),
        "expected legacy NONO_NET_BLOCK to still block network, got:\n{text}"
    );
}

#[test]
fn env_nono_profile() {
    let output = nono_bin()
        .env("NONO_PROFILE", "claude-code")
        .args(["run", "--dry-run", "--allow-cwd", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_PROFILE=claude-code should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_network_profile() {
    let output = nono_bin()
        .env("NONO_NETWORK_PROFILE", "claude-code")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_NETWORK_PROFILE should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_flag_overrides_env_var() {
    // CLI --profile should override NONO_PROFILE env var.
    // "nonexistent-profile-from-env" would fail if used, but CLI wins.
    let output = nono_bin()
        .env("NONO_PROFILE", "nonexistent-profile-from-env")
        .args([
            "run",
            "--profile",
            "claude-code",
            "--dry-run",
            "--allow-cwd",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "CLI --profile should override env var, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_upstream_proxy() {
    let output = nono_bin()
        .env("NONO_UPSTREAM_PROXY", "squid.corp:3128")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_UPSTREAM_PROXY should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_upstream_bypass_comma_separated() {
    let output = nono_bin()
        .env("NONO_UPSTREAM_PROXY", "squid.corp:3128")
        .env("NONO_UPSTREAM_BYPASS", "internal.corp,*.private.net")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_UPSTREAM_BYPASS should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_upstream_bypass_requires_upstream_proxy() {
    // NONO_UPSTREAM_BYPASS without NONO_UPSTREAM_PROXY should fail
    let output = nono_bin()
        .env("NONO_UPSTREAM_BYPASS", "internal.corp")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_UPSTREAM_BYPASS without NONO_UPSTREAM_PROXY should fail"
    );
}

#[test]
fn env_allow_net_conflicts_with_upstream_proxy() {
    // NONO_ALLOW_NET + NONO_UPSTREAM_PROXY should conflict at the clap level.
    let output = nono_bin()
        .env("NONO_UPSTREAM_PROXY", "squid.corp:3128")
        .env("NONO_ALLOW_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_ALLOW_NET + NONO_UPSTREAM_PROXY should conflict"
    );
}

#[test]
fn allow_net_overrides_profile_external_proxy() {
    // A profile with external_proxy should be overridden by --allow-net,
    // resulting in unrestricted network (no proxy mode activation).
    let dir = tempfile::tempdir().expect("tmpdir");
    let profile_path = dir.path().join("ext-proxy-profile.json");
    std::fs::write(
        &profile_path,
        r#"{
            "meta": { "name": "ext-proxy-test" },
            "network": { "external_proxy": "squid.corp:3128" }
        }"#,
    )
    .expect("write profile");

    let output = nono_bin()
        .args([
            "run",
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--allow-net",
            "--allow",
            "/tmp",
            "--dry-run",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "--allow-net should override profile external_proxy, stderr: {text}"
    );
    // Should show "allowed" network, not proxy mode
    assert!(
        text.contains("allowed"),
        "expected unrestricted network in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_conflict_allow_net_and_block_net() {
    let output = nono_bin()
        .env("NONO_ALLOW_NET", "true")
        .env("NONO_BLOCK_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_ALLOW_NET + NONO_BLOCK_NET should conflict"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_dry_run_reports_sandbox_validation() {
    let output = nono_bin()
        .args([
            "run",
            "--dry-run",
            "--profile",
            "codex",
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows dry-run should succeed, output:\n{text}"
    );
    assert!(
        text.contains("Capabilities:"),
        "expected capability summary in dry-run output, got:\n{text}"
    );
    assert!(
        text.contains("$ cmd /c echo test"),
        "expected command preview in dry-run output, got:\n{text}"
    );
    assert!(
        text.contains("sandbox would be applied with above capabilities"),
        "expected cross-platform dry-run wording, got:\n{text}"
    );
    assert!(
        !text.contains("without claiming full parity"),
        "dry-run must not use old preview wording, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_executes_basic_command() {
    let output = nono_bin()
        .args(["run", "--", "cmd", "/c", "echo", "hello"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows direct execution should succeed, output:\n{text}"
    );
    assert!(
        text.contains("hello"),
        "expected child stdout from cmd /c echo hello, got:\n{text}"
    );
    assert!(
        text.contains("active"),
        "expected sandbox-active indicator in output, got:\n{text}"
    );
    assert!(
        !text.contains("Windows restricted execution"),
        "Windows run must not use old preview wording, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_allows_file_grants_in_preview_live_run() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let allowed_file = dir.path().join("allowed.txt");
    std::fs::write(&allowed_file, "hello from file grant").expect("write allowed file");
    let allowed_file = allowed_file.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--read-file",
            &allowed_file,
            "--",
            "cmd",
            "/c",
            "type",
            &allowed_file,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows single-file grants should fail closed under the current filesystem subset, output:\n{text}"
    );
    assert!(
        text.contains("Platform not supported: Windows filesystem enforcement does not support this capability set yet"),
        "expected explicit unsupported-subset failure for Windows single-file grants, got:\n{text}"
    );
    assert!(
        text.contains(
            "single-file grants are not in the current Windows filesystem enforcement subset"
        ),
        "expected single-file grant limitation detail, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_supported_directory_allowlist_in_live_run() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--read",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "cd",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "supported Windows directory allowlist should succeed, output:\n{text}"
    );
    assert!(
        text.to_ascii_lowercase()
            .contains(&workdir.to_ascii_lowercase()),
        "expected child cwd in output, got:\n{text}"
    );
    assert!(
        text.contains("Applying sandbox..."),
        "expected sandbox application progress in output, got:\n{text}"
    );
    assert!(
        !text.contains("Windows restricted execution"),
        "Windows directory allowlist run must not use old preview wording, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_read_only_allowlist_still_reads_inside_policy() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let file = workspace.join("inside.txt");
    std::fs::write(&file, "hello from read-only run").expect("write file");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--read",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "type",
            "inside.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "read-only Windows preview should allow reads, output:\n{text}"
    );
    assert!(
        text.contains("hello from read-only run"),
        "expected child read output, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_read_only_allowlist_blocks_runtime_write_attempt() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let userprofile = std::env::var("USERPROFILE").expect("USERPROFILE");
    let probe_path = std::path::Path::new(&userprofile).join(format!(
        "nono-low-integrity-write-probe-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&probe_path);
    let command = format!("echo denied> \"{}\"", probe_path.display());

    let output = nono_bin()
        .args([
            "run",
            "--read",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            &command,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "read-only Windows preview should block runtime writes, output:\n{text}"
    );
    assert!(
        !probe_path.exists(),
        "probe file should not be created under read-only low-integrity launch"
    );
    let _ = std::fs::remove_file(&probe_path);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_redirects_temp_vars_into_writable_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo TMP=%TMP% TEMP=%TEMP% TMPDIR=%TMPDIR%",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview temp redirection should succeed, output:\n{text}"
    );
    let normalized = text.to_ascii_lowercase();
    let runtime_root = expected_windows_runtime_root(&workspace);
    let tmp_root_lower = runtime_root
        .join("tmp")
        .to_string_lossy()
        .to_ascii_lowercase();
    assert!(
        normalized.contains(&format!("tmp={}\\", tmp_root_lower))
            || normalized.contains(&format!("tmp={}/", tmp_root_lower))
            || normalized.contains(&format!("tmp={}", tmp_root_lower)),
        "expected TMP inside writable allowlist, got:\n{text}"
    );
    assert!(
        normalized.contains(&format!("temp={}\\", tmp_root_lower))
            || normalized.contains(&format!("temp={}/", tmp_root_lower))
            || normalized.contains(&format!("temp={}", tmp_root_lower)),
        "expected TEMP inside writable allowlist, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allow_all_network_probe_connects() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
    let port = listener.local_addr().expect("listener addr").port();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let accepted = listener.accept().is_ok();
        let _ = tx.send(accepted);
    });

    let probe = windows_net_probe_bin();
    let probe_dir = probe.parent().expect("probe parent");
    let allowed = probe_dir.to_string_lossy().into_owned();
    let workdir = probe_dir.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            &probe.to_string_lossy(),
            "--connect-port",
            &port.to_string(),
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows allow-all network probe should connect successfully, output:\n{text}"
    );
    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("listener result"),
        "expected localhost listener to accept the allow-all probe"
    );
    handle.join().expect("listener thread");
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_block_net_blocks_probe_connection() {
    let probe = windows_net_probe_bin();
    if !try_add_and_remove_windows_firewall_rule(&probe) {
        return;
    }

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
    let port = listener.local_addr().expect("listener addr").port();
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");

    let probe_dir = probe.parent().expect("probe parent");
    let allowed = probe_dir.to_string_lossy().into_owned();
    let workdir = probe_dir.to_string_lossy().into_owned();

    let output = nono_bin()
        // NONO_TEST_HARNESS: required by set_windows_wfp_test_force_ready runtime
        // guard (Phase 41 REQ-CI-02) — enables --dangerous-force-wfp-ready to set
        // the WFP test-force-ready atomic from integration tests.
        .env("NONO_TEST_HARNESS", "1")
        .args([
            "run",
            "--allow",
            &allowed,
            "--dangerous-force-wfp-ready",
            "--block-net",
            "--workdir",
            &workdir,
            "--",
            &probe.to_string_lossy(),
            "--connect-port",
            &port.to_string(),
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows blocked-network probe should fail to connect, output:\n{text}"
    );
    assert!(
        text.contains("connect failed") || text.contains("exit code 42"),
        "expected blocked-network probe failure details, got:\n{text}"
    );
    assert!(
        !text.contains("install-wfp-service"),
        "expected the promoted WFP backend path rather than a readiness/setup failure, got:\n{text}"
    );

    let accept_result = listener.accept();
    assert!(
        accept_result.is_err(),
        "listener should not have accepted a blocked-network connection"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_block_net_cleans_up_promoted_wfp_filters_after_exit() {
    let probe = windows_net_probe_bin();
    if !try_add_and_remove_windows_firewall_rule(&probe) {
        return;
    }

    let blocked_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
    let blocked_port = blocked_listener.local_addr().expect("listener addr").port();
    blocked_listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");

    let probe_dir = probe.parent().expect("probe parent");
    let allowed = probe_dir.to_string_lossy().into_owned();
    let workdir = probe_dir.to_string_lossy().into_owned();

    let blocked_output = nono_bin()
        // NONO_TEST_HARNESS: required by set_windows_wfp_test_force_ready runtime
        // guard (Phase 41 REQ-CI-02).
        .env("NONO_TEST_HARNESS", "1")
        .args([
            "run",
            "--allow",
            &allowed,
            "--dangerous-force-wfp-ready",
            "--block-net",
            "--workdir",
            &workdir,
            "--",
            &probe.to_string_lossy(),
            "--connect-port",
            &blocked_port.to_string(),
        ])
        .output()
        .expect("failed to run blocked nono");

    let blocked_text = combined_output(&blocked_output);
    assert!(
        !blocked_output.status.success(),
        "blocked Windows run should fail the connection attempt, output:\n{blocked_text}"
    );
    assert!(
        blocked_text.contains("connect failed") || blocked_text.contains("exit code 42"),
        "expected blocked-network probe failure details, got:\n{blocked_text}"
    );

    let blocked_accept = blocked_listener.accept();
    assert!(
        blocked_accept.is_err(),
        "blocked listener should not have accepted a blocked-network connection"
    );

    let cleanup_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
    let cleanup_port = cleanup_listener.local_addr().expect("listener addr").port();
    let (tx, rx) = std::sync::mpsc::channel();
    let cleanup_handle = std::thread::spawn(move || {
        let accepted = cleanup_listener.accept().is_ok();
        tx.send(accepted).expect("send listener result");
    });

    let allow_output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            &probe.to_string_lossy(),
            "--connect-port",
            &cleanup_port.to_string(),
        ])
        .output()
        .expect("failed to run allow-all nono");

    let allow_text = combined_output(&allow_output);
    assert!(
        allow_output.status.success(),
        "allow-all run after blocked cleanup should succeed, output:\n{allow_text}"
    );
    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("cleanup listener result"),
        "expected allow-all listener to accept after blocked-run cleanup"
    );
    cleanup_handle.join().expect("cleanup listener thread");
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_block_net_blocks_probe_connection_through_cmd_host() {
    let probe = windows_net_probe_bin();
    if !try_add_and_remove_windows_firewall_rule(&probe) {
        return;
    }

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
    let port = listener.local_addr().expect("listener addr").port();
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");

    let probe_dir = probe.parent().expect("probe parent");
    let allowed = probe_dir.to_string_lossy().into_owned();
    let workdir = probe_dir.to_string_lossy().into_owned();
    let probe_text = probe.to_string_lossy().into_owned();

    let output = nono_bin()
        // NONO_TEST_HARNESS: required by set_windows_wfp_test_force_ready runtime
        // guard (Phase 41 REQ-CI-02).
        .env("NONO_TEST_HARNESS", "1")
        .args([
            "run",
            "--allow",
            &allowed,
            "--allow",
            r"C:\Windows",
            "--dangerous-force-wfp-ready",
            "--block-net",
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            &probe_text,
            "--connect-port",
            &port.to_string(),
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows blocked-network execution through cmd host should fail the probe connection, output:\n{text}"
    );
    assert!(
        text.contains("connect failed") || text.contains("exit code 42"),
        "expected blocked-network probe failure details from cmd-host launch, got:\n{text}"
    );
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(
        listener.accept().is_err(),
        "listener should not have accepted a connection from cmd-host blocked run"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_prefers_managed_low_integrity_runtime_root_inside_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    if !host_can_prepare_managed_windows_runtime_root(dir.path()) {
        return;
    }

    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo redirected>%TMP%\\managed-root.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow writes into a managed low-integrity runtime root inside the allowlist, output:\n{text}"
    );

    let runtime_root = workspace.join(".nono-runtime-low");
    assert!(
        nono::Sandbox::windows_supports_direct_writable_dir(&runtime_root),
        "expected managed runtime root {} to be low-integrity-compatible",
        runtime_root.display()
    );

    let probe_file = runtime_root.join("tmp").join("managed-root.txt");
    assert!(
        probe_file.exists(),
        "expected runtime-owned write at {}",
        probe_file.display()
    );
    assert_eq!(
        std::fs::read_to_string(&probe_file)
            .expect("read managed runtime root probe")
            .trim(),
        "redirected"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_redirects_profile_state_vars_into_writable_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "set",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview profile-state redirection should succeed, output:\n{text}"
    );
    let normalized = text.to_ascii_lowercase();
    let runtime_root = expected_windows_runtime_root(&workspace);
    let runtime_root_lower = runtime_root.to_string_lossy().to_ascii_lowercase();
    assert!(
        normalized.contains("path=c:\\windows\\system32;")
            || normalized.contains("path=c:\\windows\\system32\\"),
        "expected PATH to start from the Windows runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("pathext=.com;.exe;.bat;.cmd"),
        "expected PATHEXT runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("comspec=c:\\windows\\system32\\cmd.exe"),
        "expected COMSPEC runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("systemroot=c:\\windows"),
        "expected SystemRoot runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("windir=c:\\windows"),
        "expected windir runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("systemdrive=c:"),
        "expected SystemDrive runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("nodefaultcurrentdirectoryinexepath=1"),
        "expected NoDefaultCurrentDirectoryInExePath runtime baseline, got:\n{text}"
    );
    for key in [
        "appdata=",
        "localappdata=",
        "home=",
        "userprofile=",
        "xdg_config_home=",
        "xdg_cache_home=",
        "xdg_data_home=",
        "xdg_state_home=",
        "programdata=",
        "allusersprofile=",
        "public=",
        "programfiles=",
        "programfiles(x86)=",
        "programw6432=",
        "commonprogramfiles=",
        "commonprogramfiles(x86)=",
        "commonprogramw6432=",
        "onedrive=",
        "inetcache=",
        "inetcookies=",
        "inethistory=",
        "psmodulepath=",
        "psmoduleanalysiscachepath=",
        "cargo_home=",
        "rustup_home=",
        "dotnet_cli_home=",
        "nuget_packages=",
        "nuget_http_cache_path=",
        "nuget_plugins_cache_path=",
        "chocolateyinstall=",
        "chocolateytoolslocation=",
        "vcpkg_root=",
        "npm_config_cache=",
        "npm_config_userconfig=",
        "yarn_cache_folder=",
        "pip_cache_dir=",
        "pip_config_file=",
        "pip_build_tracker=",
        "pythonpycacheprefix=",
        "pythonuserbase=",
        "gocache=",
        "gomodcache=",
        "gopath=",
        "histfile=",
        "lesshistfile=",
        "node_repl_history=",
        "pythonhistfile=",
        "sqlite_history=",
        "ipythondir=",
        "gem_home=",
        "gem_path=",
        "bundle_user_home=",
        "bundle_user_cache=",
        "bundle_user_config=",
        "bundle_app_config=",
        "composer_home=",
        "composer_cache_dir=",
        "gradle_user_home=",
        "maven_user_home=",
        "ripgrep_config_path=",
        "aws_shared_credentials_file=",
        "aws_config_file=",
        "azure_config_dir=",
        "kubeconfig=",
        "docker_config=",
        "cloudsdk_config=",
        "git_config_global=",
        "gnupghome=",
        "tf_cli_config_file=",
        "tf_data_dir=",
    ] {
        assert!(
            normalized.contains(&format!("{key}{runtime_root_lower}\\"))
                || normalized.contains(&format!("{key}{runtime_root_lower}/"))
                || normalized.contains(&format!("{key}{runtime_root_lower}")),
            "expected {key} inside writable allowlist, got:\n{text}"
        );
    }
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_filters_host_toolchain_home_vars_without_runtime_dir() {
    let output = nono_bin()
        .env("CARGO_HOME", r"C:\host-cargo")
        .env("RUSTUP_HOME", r"C:\host-rustup")
        .env("NUGET_PACKAGES", r"C:\host-nuget")
        .env("DOTNET_CLI_HOME", r"C:\host-dotnet")
        .env(
            "PSModuleAnalysisCachePath",
            r"C:\host-psmodule-analysis\cache",
        )
        .env("XDG_CACHE_HOME", r"C:\host-xdg\cache")
        .env("XDG_STATE_HOME", r"C:\host-xdg\state")
        .env("ChocolateyInstall", r"C:\ProgramData\chocolatey")
        .env("VCPKG_ROOT", r"C:\vcpkg")
        .env("NUGET_HTTP_CACHE_PATH", r"C:\host-nuget-http")
        .env("NUGET_PLUGINS_CACHE_PATH", r"C:\host-nuget-plugins")
        .env("NPM_CONFIG_CACHE", r"C:\host-npm")
        .env("NPM_CONFIG_USERCONFIG", r"C:\host-npm\npmrc")
        .env("YARN_CACHE_FOLDER", r"C:\host-yarn")
        .env("PIP_CACHE_DIR", r"C:\host-pip")
        .env("PIP_CONFIG_FILE", r"C:\host-pip\pip.ini")
        .env("PIP_BUILD_TRACKER", r"C:\host-pip-build-tracker")
        .env("PYTHONPYCACHEPREFIX", r"C:\host-python-pycache")
        .env("PYTHONUSERBASE", r"C:\host-python-userbase")
        .env("GOCACHE", r"C:\host-go-cache")
        .env("GOMODCACHE", r"C:\host-go-mod-cache")
        .env("GOPATH", r"C:\host-go-path")
        .env("HISTFILE", r"C:\host-history\shell")
        .env("LESSHISTFILE", r"C:\host-history\less")
        .env("NODE_REPL_HISTORY", r"C:\host-history\node")
        .env("PYTHONHISTFILE", r"C:\host-history\python")
        .env("SQLITE_HISTORY", r"C:\host-history\sqlite")
        .env("IPYTHONDIR", r"C:\host-history\ipython")
        .env("GEM_HOME", r"C:\host-ruby\gem-home")
        .env("GEM_PATH", r"C:\host-ruby\gem-path")
        .env("BUNDLE_USER_HOME", r"C:\host-bundler\home")
        .env("BUNDLE_USER_CACHE", r"C:\host-bundler\cache")
        .env("BUNDLE_USER_CONFIG", r"C:\host-bundler\config")
        .env("BUNDLE_APP_CONFIG", r"C:\host-bundler\app-config")
        .env("COMPOSER_HOME", r"C:\host-composer\home")
        .env("COMPOSER_CACHE_DIR", r"C:\host-composer\cache")
        .env("GRADLE_USER_HOME", r"C:\host-gradle")
        .env("MAVEN_USER_HOME", r"C:\host-maven")
        .env("RIPGREP_CONFIG_PATH", r"C:\host-ripgrep\ripgreprc")
        .env("AWS_SHARED_CREDENTIALS_FILE", r"C:\host-aws\credentials")
        .env("AWS_CONFIG_FILE", r"C:\host-aws\config")
        .env("AZURE_CONFIG_DIR", r"C:\host-azure")
        .env("KUBECONFIG", r"C:\host-kube\config")
        .env("DOCKER_CONFIG", r"C:\host-docker")
        .env("CLOUDSDK_CONFIG", r"C:\host-gcloud")
        .env("GIT_CONFIG_GLOBAL", r"C:\host-git\config")
        .env("GNUPGHOME", r"C:\host-gnupg")
        .env("TF_CLI_CONFIG_FILE", r"C:\host-terraform\terraform.rc")
        .env("TF_DATA_DIR", r"C:\host-terraform\data")
        .args([
            "run",
            "--",
            "cmd",
            "/v:on",
            "/c",
            "for %v in (CARGO_HOME RUSTUP_HOME NUGET_PACKAGES DOTNET_CLI_HOME PSModuleAnalysisCachePath XDG_CACHE_HOME XDG_STATE_HOME NUGET_HTTP_CACHE_PATH NUGET_PLUGINS_CACHE_PATH ChocolateyInstall VCPKG_ROOT NPM_CONFIG_CACHE NPM_CONFIG_USERCONFIG YARN_CACHE_FOLDER PIP_CACHE_DIR PIP_CONFIG_FILE PIP_BUILD_TRACKER PYTHONPYCACHEPREFIX PYTHONUSERBASE GOCACHE GOMODCACHE GOPATH HISTFILE LESSHISTFILE NODE_REPL_HISTORY PYTHONHISTFILE SQLITE_HISTORY IPYTHONDIR GEM_HOME GEM_PATH BUNDLE_USER_HOME BUNDLE_USER_CACHE BUNDLE_USER_CONFIG BUNDLE_APP_CONFIG COMPOSER_HOME COMPOSER_CACHE_DIR GRADLE_USER_HOME MAVEN_USER_HOME RIPGREP_CONFIG_PATH AWS_SHARED_CREDENTIALS_FILE AWS_CONFIG_FILE AZURE_CONFIG_DIR KUBECONFIG DOCKER_CONFIG CLOUDSDK_CONFIG GIT_CONFIG_GLOBAL GNUPGHOME TF_CLI_CONFIG_FILE TF_DATA_DIR) do @echo %v=!%v!",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should filter host toolchain-home vars, output:\n{text}"
    );
    let normalized = text.to_ascii_lowercase();
    for key in [
        "cargo_home=",
        "rustup_home=",
        "nuget_packages=",
        "dotnet_cli_home=",
        "psmoduleanalysiscachepath=",
        "xdg_cache_home=",
        "xdg_state_home=",
        "nuget_http_cache_path=",
        "nuget_plugins_cache_path=",
        "chocolateyinstall=",
        "vcpkg_root=",
        "npm_config_cache=",
        "npm_config_userconfig=",
        "yarn_cache_folder=",
        "pip_cache_dir=",
        "pip_config_file=",
        "pip_build_tracker=",
        "pythonpycacheprefix=",
        "pythonuserbase=",
        "gocache=",
        "gomodcache=",
        "gopath=",
        "histfile=",
        "lesshistfile=",
        "node_repl_history=",
        "pythonhistfile=",
        "sqlite_history=",
        "ipythondir=",
        "gem_home=",
        "gem_path=",
        "bundle_user_home=",
        "bundle_user_cache=",
        "bundle_user_config=",
        "bundle_app_config=",
        "composer_home=",
        "composer_cache_dir=",
        "gradle_user_home=",
        "maven_user_home=",
        "ripgrep_config_path=",
        "aws_shared_credentials_file=",
        "aws_config_file=",
        "azure_config_dir=",
        "kubeconfig=",
        "docker_config=",
        "cloudsdk_config=",
        "git_config_global=",
        "gnupghome=",
        "tf_cli_config_file=",
        "tf_data_dir=",
    ] {
        assert!(
            normalized.contains(key),
            "expected {key} marker in child output, got:\n{text}"
        );
    }
    for leaked in [
        r"c:\host-cargo",
        r"c:\host-rustup",
        r"c:\host-nuget",
        r"c:\host-dotnet",
        r"c:\host-psmodule-analysis\cache",
        r"c:\host-nuget-http",
        r"c:\host-nuget-plugins",
        r"c:\programdata\chocolatey",
        r"c:\vcpkg",
        r"c:\host-npm",
        r"c:\host-yarn",
        r"c:\host-pip",
        r"c:\host-pip-build-tracker",
        r"c:\host-python-pycache",
        r"c:\host-python-userbase",
        r"c:\host-go-cache",
        r"c:\host-go-mod-cache",
        r"c:\host-go-path",
        r"c:\host-history\shell",
        r"c:\host-history\less",
        r"c:\host-history\node",
        r"c:\host-history\python",
        r"c:\host-history\sqlite",
        r"c:\host-history\ipython",
        r"c:\host-ruby\gem-home",
        r"c:\host-ruby\gem-path",
        r"c:\host-bundler\home",
        r"c:\host-bundler\cache",
        r"c:\host-bundler\config",
        r"c:\host-composer\home",
        r"c:\host-composer\cache",
        r"c:\host-gradle",
        r"c:\host-maven",
    ] {
        assert!(
            !normalized.contains(leaked),
            "host toolchain path leaked into child env: {leaked}\n{text}"
        );
    }
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_cmd_write_into_redirected_tmp_runtime_dir() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    if !host_can_write_expected_windows_runtime_root(&workspace) {
        return;
    }

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo redirected>%TMP%\\probe.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    if text.contains("not low-integrity-compatible") {
        eprintln!(
            "skipping redirected tmp write test because the host could not prepare a low-integrity runtime root:\n{text}"
        );
        return;
    }
    if output_has_windows_access_denied(&text) {
        eprintln!(
            "skipping redirected tmp write test because the restricted Windows child could not write to the runtime root on this host:\n{text}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "Windows preview should allow runtime-owned tmp writes inside allowlist, output:\n{text}"
    );
    let dest = expected_windows_runtime_root(&workspace)
        .join("tmp")
        .join("probe.txt");
    assert!(dest.exists(), "expected copied file at {}", dest.display());
    assert_eq!(
        std::fs::read_to_string(&dest).expect("read dest").trim(),
        "redirected"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_ignores_unverified_localappdata_override_when_runtime_root_is_verified() {
    let dir = tempfile::tempdir().expect("tmpdir");
    if !host_can_prepare_managed_windows_runtime_root(dir.path()) {
        return;
    }

    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let fake_localappdata = dir.path().join("fake-localappdata");
    std::fs::create_dir_all(&fake_localappdata).expect("mkdir fake localappdata");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .env("LOCALAPPDATA", &fake_localappdata)
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo redirected>%TMP%\\probe.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    if output_has_windows_access_denied(&text) {
        eprintln!(
            "skipping LOCALAPPDATA override runtime-root test because the restricted Windows child could not write to the managed runtime root on this host:\n{text}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "Windows preview should keep using the verified runtime root inside the writable allowlist, output:\n{text}"
    );
    assert!(
        !text.contains("LOCALAPPDATA override"),
        "expected verified runtime root selection to ignore the unrelated LOCALAPPDATA override, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_workspace_write_even_with_writable_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo denied> workspace-write.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block direct workspace writes under low-integrity enforcement, output:\n{text}"
    );
    assert!(
        !workspace.join("workspace-write.txt").exists(),
        "workspace write probe should not be created under low-integrity writable allowlist"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_allows_direct_write_inside_low_integrity_allowlisted_dir() {
    let low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .map(|local| local.join("Temp").join("Low"))
        .expect("LOCALAPPDATA should be set on Windows");
    std::fs::create_dir_all(&low_root).expect("ensure low root");

    let unique = format!(
        "nono-low-write-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_nanos()
    );
    let workspace = low_root.join(unique);
    std::fs::create_dir_all(&workspace).expect("mkdir low-integrity workspace");
    if !try_set_low_integrity_label(&workspace) {
        let _ = std::fs::remove_dir_all(&workspace);
        return;
    }

    let allowed = workspace.to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo direct> direct-write.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow direct writes inside low-integrity allowlisted dirs, output:\n{text}"
    );
    let probe = workspace.join("direct-write.txt");
    assert!(
        probe.exists(),
        "expected direct write at {}",
        probe.display()
    );
    assert_eq!(
        std::fs::read_to_string(&probe)
            .expect("read direct write")
            .trim(),
        "direct"
    );

    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_allows_direct_write_inside_locallow_allowlisted_dir() {
    let local_low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .and_then(|local| local.parent().map(|root| root.join("LocalLow")))
        .expect("LOCALAPPDATA should resolve LocalLow on Windows");
    if let Err(err) = std::fs::create_dir_all(&local_low_root) {
        eprintln!(
            "skipping LocalLow direct-write test because the LocalLow root is unavailable: {err}"
        );
        return;
    }

    let unique = format!(
        "nono-locallow-write-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_nanos()
    );
    let workspace = local_low_root.join(unique);
    if let Err(err) = std::fs::create_dir_all(&workspace) {
        eprintln!(
            "skipping LocalLow direct-write test because the LocalLow workspace could not be created: {err}"
        );
        return;
    }
    if !try_set_low_integrity_label(&workspace) {
        let _ = std::fs::remove_dir_all(&workspace);
        return;
    }

    let allowed = workspace.to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo direct> direct-write.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow direct writes inside LocalLow allowlisted dirs, output:\n{text}"
    );
    let probe = workspace.join("direct-write.txt");
    assert!(
        probe.exists(),
        "expected direct write at {}",
        probe.display()
    );
    assert_eq!(
        std::fs::read_to_string(&probe)
            .expect("read direct write")
            .trim(),
        "direct"
    );

    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_allows_direct_write_inside_dynamically_labeled_low_integrity_dir() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("dynamically-labeled-low");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    if !try_set_low_integrity_label(&workspace) {
        return;
    }

    let allowed = workspace.to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo dynamic> dynamic-write.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow direct writes inside dynamically low-integrity-labeled dirs, output:\n{text}"
    );
    let probe = workspace.join("dynamic-write.txt");
    assert!(
        probe.exists(),
        "expected direct write at {}",
        probe.display()
    );
    assert_eq!(
        std::fs::read_to_string(&probe)
            .expect("read direct write")
            .trim(),
        "dynamic"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_allows_cmd_type_for_relative_file_inside_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let file = workspace.join("inside.txt");
    std::fs::write(&file, "hello from type").expect("write file");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "type",
            "inside.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow cmd /c type inside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("hello from type"),
        "expected file contents from cmd /c type, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_cmd_copy_to_absolute_destination_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied").expect("write source");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_dest = outside_dir.path().join("dest.txt");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_dest = outside_dest.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "copy",
            "source.txt",
            &outside_dest,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block cmd /c copy outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("destination path argument"),
        "expected destination path rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_allows_powershell_get_content_inside_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let file = workspace.join("inside.txt");
    std::fs::write(&file, "hello from powershell").expect("write file");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "powershell.exe",
            "-Command",
            "Get-Content inside.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow PowerShell Get-Content inside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("hello from powershell"),
        "expected file contents from PowerShell Get-Content, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_allows_powershell_copy_into_redirected_tmp_runtime_dir() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    if !host_can_write_expected_windows_runtime_root(&workspace) {
        return;
    }
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied by powershell").expect("write source");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "powershell.exe",
            "-Command",
            "$dest = Join-Path $env:TEMP 'dest.txt'; Copy-Item source.txt -Destination $dest; Get-Content $dest",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    if text.contains("not low-integrity-compatible") {
        eprintln!(
            "skipping PowerShell redirected tmp copy test because the host could not prepare a low-integrity runtime root:\n{text}"
        );
        return;
    }
    if output_has_windows_access_denied(&text) {
        eprintln!(
            "skipping PowerShell redirected tmp copy test because the restricted Windows child could not write to the runtime root on this host:\n{text}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "Windows preview should allow PowerShell Copy-Item into redirected tmp runtime dir, output:\n{text}"
    );
    let dest = expected_windows_runtime_root(&workspace)
        .join("tmp")
        .join("dest.txt");
    assert!(dest.exists(), "expected copied file at {}", dest.display());
    assert_eq!(
        std::fs::read_to_string(&dest).expect("read dest"),
        "copied by powershell"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_findstr_inside_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let file = workspace.join("inside.txt");
    std::fs::write(&file, "needle in a haystack").expect("write file");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "findstr.exe",
            "/c:needle",
            "needle",
            "inside.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow findstr inside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("needle in a haystack"),
        "expected file contents from findstr, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_xcopy_destination_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied").expect("write source");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_dest = outside_dir.path().join("dest.txt");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_dest = outside_dest.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "xcopy.exe",
            "source.txt",
            &outside_dest,
            "/Y",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block xcopy outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("xcopy destination path"),
        "expected xcopy destination rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_comp_file_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let inside = workspace.join("inside.txt");
    std::fs::write(&inside, "same").expect("write inside");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside = outside_dir.path().join("outside.txt");
    std::fs::write(&outside, "same").expect("write outside");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside = outside.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "comp.exe",
            "inside.txt",
            &outside,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block comp outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("comp file argument"),
        "expected comp path rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_fc_file_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let inside = workspace.join("inside.txt");
    std::fs::write(&inside, "same").expect("write inside");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside = outside_dir.path().join("outside.txt");
    std::fs::write(&outside, "same").expect("write outside");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside = outside.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "fc.exe",
            "inside.txt",
            &outside,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block fc outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("fc file argument"),
        "expected fc path rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_cscript_destination_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let script = workspace.join("copy.vbs");
    std::fs::write(
        &script,
        r#"Set fso = CreateObject("Scripting.FileSystemObject")
Set source = fso.OpenTextFile(WScript.Arguments(0), 1)
contents = source.ReadAll
source.Close
Set dest = fso.CreateTextFile(WScript.Arguments(1), True)
dest.Write contents
dest.Close
"#,
    )
    .expect("write script");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied").expect("write source");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_dest = outside_dir.path().join("dest.txt");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_dest = outside_dest.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cscript.exe",
            "copy.vbs",
            "source.txt",
            &outside_dest,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block cscript outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument")
            || text.contains("Windows Script Host path argument"),
        "expected cscript destination rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_powershell_copy_to_absolute_destination_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied").expect("write source");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_dest = outside_dir.path().join("dest.txt");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let command = format!(
        "Copy-Item source.txt -Destination '{}'",
        outside_dest.to_string_lossy()
    );

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "powershell.exe",
            "-Command",
            &command,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block PowerShell copy outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("PowerShell destination path"),
        "expected PowerShell destination rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_directory_allowlist_when_workdir_is_outside_supported_subset() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workdir_dir = tempfile::tempdir().expect("workdir tmpdir");
    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workdir_dir.path().to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--read",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should fail closed when workdir is outside supported subset, output:\n{text}"
    );
    assert!(
        text.contains("execution directory outside supported allowlist"),
        "expected explicit Windows execution-dir rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_absolute_path_argument_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_file = outside_dir.path().join("outside.txt");
    std::fs::write(&outside_file, "hello").expect("write file");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_file = outside_file.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "more.com",
            &outside_file,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block absolute path args outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument"),
        "expected absolute path argument rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_cmd_type_for_absolute_file_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_file = outside_dir.path().join("outside.txt");
    std::fs::write(&outside_file, "outside").expect("write file");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_file = outside_file.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "type",
            &outside_file,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block cmd /c type outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("file argument"),
        "expected path-argument rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_propagates_child_exit_code() {
    let output = nono_bin()
        .args(["run", "--", "cmd", "/c", "exit", "7"])
        .output()
        .expect("failed to run nono");

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected child exit code 7, output:\n{}",
        combined_output(&output)
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_honors_workdir() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workdir = dir.path().to_string_lossy().into_owned();

    let output = nono_bin()
        .args(["run", "--workdir", &workdir, "--", "cmd", "/c", "cd"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows direct execution with workdir should succeed, output:\n{text}"
    );
    assert!(
        text.to_ascii_lowercase()
            .contains(&workdir.to_ascii_lowercase()),
        "expected child cwd in output, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_filters_dangerous_env_vars_and_keeps_safe_ones() {
    let output = nono_bin()
        .env("NODE_OPTIONS", "--require injected.js")
        .env("DOTNET_STARTUP_HOOKS", r"C:\malicious.dll")
        .env("NONO_TEST_SAFE_ENV", "kept")
        .args([
            "run",
            "--",
            "cmd",
            "/c",
            "echo SAFE=%NONO_TEST_SAFE_ENV% NODE=%NODE_OPTIONS% DOTNET=%DOTNET_STARTUP_HOOKS%",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows env sanitization check should succeed, output:\n{text}"
    );
    assert!(
        text.contains("SAFE=kept"),
        "expected safe env var to survive, got:\n{text}"
    );
    assert!(
        text.contains("NODE=") && !text.contains("NODE=--require injected.js"),
        "expected NODE_OPTIONS to be filtered, got:\n{text}"
    );
    assert!(
        text.contains("DOTNET=") && !text.contains(r"DOTNET=C:\malicious.dll"),
        "expected DOTNET_STARTUP_HOOKS to be filtered, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_smoke_validates_stdout_stderr_and_exit_code() {
    let output = nono_bin()
        .args([
            "run",
            "--",
            "cmd",
            "/c",
            "echo stdout-line & echo stderr-line 1>&2 & exit 5",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(5),
        "expected child exit code 5, output:\n{text}"
    );
    assert!(
        text.contains("stdout-line"),
        "expected child stdout in output, got:\n{text}"
    );
    assert!(
        text.contains("stderr-line"),
        "expected child stderr in output, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_root_help_reports_supported_command_surface_without_full_parity_claim() {
    let output = nono_bin()
        .args(["--help"])
        .output()
        .expect("failed to run nono --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows root help should succeed, output:\n{text}"
    );
    assert!(
        text.contains(
            "A capability-based shell for running untrusted AI agents and processes with OS-enforced isolation."
        ),
        "expected root help to describe the current Windows command surface, got:\n{text}"
    );
    assert!(
        text.contains("Unsupported flows fail closed instead of implying full sandbox parity."),
        "expected root help to avoid implying full Windows parity, got:\n{text}"
    );
    assert!(
        !text.contains("first-class supported"),
        "root help must not claim first-class Windows support yet, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_help_reports_supported_command_surface_and_backend_readiness() {
    let output = nono_bin()
        .args(["run", "--help"])
        .output()
        .expect("failed to run nono run --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows run help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("current supported command surface with backend-owned"),
        "expected run help to describe the current supported Windows surface, got:\n{text}"
    );
    assert!(
        text.contains("enforcement-dependent flows require current Windows"),
        "expected run help to mention backend readiness for enforcement-dependent flows, got:\n{text}"
    );
    assert!(
        !text.contains("first-class supported"),
        "run help must not imply first-class Windows support yet, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_shell_help_reports_documented_limitation() {
    let output = nono_bin()
        .args(["shell", "--help"])
        .output()
        .expect("failed to run nono shell --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows shell help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("ConPTY"),
        "expected Windows shell help to describe ConPTY-based launch behavior, got:\n{text}"
    );
    assert!(
        text.contains("Job Object"),
        "expected Windows shell help to describe Job Object enforcement, got:\n{text}"
    );
    assert!(
        !text.contains("preview path"),
        "shell help should not regress to preview-path wording, got:\n{text}"
    );
    assert!(
        !text.contains("first-class supported"),
        "shell help must not imply first-class Windows support yet, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "interactive shell test; requires terminal; run manually"]
fn windows_shell_live_reports_documented_limitation() {
    let output = nono_bin()
        .args(["shell"])
        .output()
        .expect("failed to run nono shell");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows shell live execution should fail closed, output:\n{text}"
    );
    assert!(
        text.contains("Live `nono shell` is intentionally unavailable on Windows."),
        "expected explicit Windows shell limitation message, got:\n{text}"
    );
    assert!(
        text.contains("Use `nono run -- <command>`"),
        "expected actionable alternative in shell limitation message, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "interactive shell test; requires terminal; run manually"]
fn windows_shell_live_reports_supported_alternative_without_preview_claim() {
    let output = nono_bin()
        .args(["shell"])
        .output()
        .expect("failed to run nono shell");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows shell live execution should fail closed, output:\n{text}"
    );
    assert!(
        text.contains("Use `nono run -- <command>`"),
        "expected shell failure to point at the supported Windows execution path, got:\n{text}"
    );
    assert!(
        !text.contains("preview"),
        "shell failure should not regress to preview-era messaging, got:\n{text}"
    );
    assert!(
        !text.contains("first-class supported"),
        "shell failure must not imply first-class Windows support yet, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_live_default_profile_executes_command() {
    let output = nono_bin()
        .args([
            "run",
            "--profile",
            "default",
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows live default profile run should succeed, output:\n{text}"
    );
    assert!(
        text.contains("test"),
        "expected child command output from live default profile run, got:\n{text}"
    );
    assert!(
        !text.contains("cannot enforce the requested sandbox controls"),
        "supported live profile run should not report unsupported sandbox controls, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires live Windows AppContainer/low-integrity enforcement; run with --include-ignored on a configured Windows host"]
fn windows_run_live_codex_profile_fails_intentionally_with_backend_reason() {
    let output = nono_bin()
        .args([
            "run",
            "--profile",
            "codex",
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "unsupported Windows codex profile run should fail closed, output:\n{text}"
    );
    assert!(
        text.contains(
            "Platform not supported: Windows filesystem enforcement does not support this capability set yet"
        ),
        "expected explicit backend enforcement failure, got:\n{text}"
    );
    assert!(
        text.contains(
            "single-file grants are not in the current Windows filesystem enforcement subset"
        ),
        "expected backend-owned unsupported reason details, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_setup_check_only_reports_live_profile_subset() {
    let output = nono_bin()
        .args(["setup", "--check-only"])
        .output()
        .expect("failed to run nono setup --check-only");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows setup --check-only should succeed, output:\n{text}"
    );
    assert!(
        text.contains("Support status: supported"),
        "expected unified setup summary support status, got:\n{text}"
    );
    assert!(
        !text.contains("Library support status:"),
        "setup output must not have separate library support line, got:\n{text}"
    );
    assert!(
        text.contains("Use 'nono run --dry-run ...' to validate profiles and policy."),
        "expected setup summary dry-run guidance, got:\n{text}"
    );
    assert!(
        text.contains(
            "Plain 'nono run -- <command>' uses the current supported Windows command surface"
        ),
        "expected setup summary direct-run support wording, got:\n{text}"
    );
    assert!(
        text.contains(
            "Blocked-network and other enforcement-dependent Windows flows require current backend readiness"
        ),
        "expected setup summary backend-readiness note, got:\n{text}"
    );
    assert!(
        text.contains("'nono wrap' is available on Windows"),
        "expected setup summary to reflect wrap availability on Windows, got:\n{text}"
    );
    assert!(
        text.contains("User state root:"),
        "expected Windows storage layout in setup summary, got:\n{text}"
    );
    assert!(
        !text.contains("Live profile enforcement is still preview-only on Windows."),
        "setup output should not regress to preview-only profile wording, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_setup_check_only_reports_unified_support_status() {
    let output = nono_bin()
        .args(["setup", "--check-only"])
        .output()
        .expect("failed to run nono setup --check-only");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows setup --check-only should succeed, output:\n{text}"
    );
    assert!(
        text.contains("Support status: supported"),
        "expected unified support status in setup output, got:\n{text}"
    );
    assert!(
        !text.contains("CLI support status:"),
        "setup output must not have separate CLI support line, got:\n{text}"
    );
    assert!(
        !text.contains("Library support status:"),
        "setup output must not have separate library support line, got:\n{text}"
    );
    assert!(
        !text.contains("restricted command surface"),
        "setup output must not use old CLI support label, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_root_help_reports_session_management_as_unsupported_surface() {
    let output = nono_bin()
        .args(["--help"])
        .output()
        .expect("failed to run nono --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows root help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("ps         Inspect the unsupported Windows session-management surface"),
        "expected root help to mark ps as unsupported on Windows, got:\n{text}"
    );
    assert!(
        text.contains("attach     Inspect the unsupported Windows session-management surface"),
        "expected root help to mark attach as unsupported on Windows, got:\n{text}"
    );
    assert!(
        text.contains("detach     Inspect the unsupported Windows session-management surface"),
        "expected root help to mark detach as unsupported on Windows, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_attach_help_reports_documented_limitation() {
    let output = nono_bin()
        .args(["attach", "--help"])
        .output()
        .expect("failed to run nono attach --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows attach help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("`nono attach` is intentionally unavailable on Windows."),
        "expected documented Windows attach limitation in help output, got:\n{text}"
    );
    assert!(
        text.contains("PTY/socket session transport"),
        "expected explicit detached-session transport limitation in attach help, got:\n{text}"
    );
    assert!(
        !text.contains("Attach by session ID"),
        "Windows attach help should not show Unix attach examples, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_detach_help_reports_documented_limitation() {
    let output = nono_bin()
        .args(["detach", "--help"])
        .output()
        .expect("failed to run nono detach --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows detach help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("`nono detach` is intentionally unavailable on Windows."),
        "expected documented Windows detach limitation in help output, got:\n{text}"
    );
    assert!(
        text.contains("PTY-backed detachable runtime sessions are not available on Windows"),
        "expected explicit PTY limitation in detach help, got:\n{text}"
    );
    assert!(
        !text.contains("Ctrl-] then d"),
        "Windows detach help should not show in-band detach examples, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_logs_help_reports_documented_limitation() {
    let output = nono_bin()
        .args(["logs", "--help"])
        .output()
        .expect("failed to run nono logs --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows logs help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("`nono logs` is intentionally unavailable on Windows."),
        "expected documented Windows logs limitation in help output, got:\n{text}"
    );
    assert!(
        text.contains("event-log inspection"),
        "expected explicit session event-log limitation in logs help, got:\n{text}"
    );
    assert!(
        !text.contains("# View recent events"),
        "Windows logs help should not show Unix logs example blocks, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_inspect_help_reports_documented_limitation() {
    let output = nono_bin()
        .args(["inspect", "--help"])
        .output()
        .expect("failed to run nono inspect --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows inspect help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("`nono inspect` is intentionally unavailable on Windows."),
        "expected documented Windows inspect limitation in help output, got:\n{text}"
    );
    assert!(
        text.contains("Detailed runtime session inspection"),
        "expected explicit session inspection limitation in help output, got:\n{text}"
    );
    assert!(
        !text.contains("# Inspect a session"),
        "Windows inspect help should not show Unix inspect example blocks, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_prune_help_reports_documented_limitation() {
    let output = nono_bin()
        .args(["prune", "--help"])
        .output()
        .expect("failed to run nono prune --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows prune help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("`nono prune` is intentionally unavailable on Windows."),
        "expected documented Windows prune limitation in help output, got:\n{text}"
    );
    assert!(
        text.contains("Runtime session file cleanup"),
        "expected explicit session cleanup limitation in help output, got:\n{text}"
    );
    assert!(
        !text.contains("Remove sessions older than 7 days"),
        "Windows prune help should not show Unix prune examples, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_open_url_helper_reports_documented_limitation() {
    let output = nono_bin()
        .args(["open-url-helper", "https://example.com"])
        .output()
        .expect("failed to run nono open-url-helper");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows open-url-helper should fail closed, output:\n{text}"
    );
    assert!(
        text.contains("Windows delegated browser-open flows are not available yet."),
        "expected documented delegated-open limitation, got:\n{text}"
    );
    assert!(
        text.contains("attached supervisor control channel"),
        "expected explicit child-transport limitation, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_allow_launch_services_reports_macos_only_limitation() {
    let output = nono_bin()
        .args([
            "run",
            "--profile",
            "default",
            "--allow-launch-services",
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono with --allow-launch-services");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows --allow-launch-services should fail closed, output:\n{text}"
    );
    assert!(
        text.contains("--allow-launch-services is only supported on macOS"),
        "expected explicit macOS-only limitation, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_live_block_net_without_enforcement() {
    let output = nono_bin()
        .args(["run", "--block-net", "--", "cmd", "/c", "echo", "test"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block live network restriction requests, output:\n{text}"
    );
    assert!(
        text.contains("network"),
        "expected network restriction reason in error, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_supervised_blocks_runtime_capability_elevation_with_actionable_diagnostic() {
    let output = nono_bin()
        .args([
            "run",
            "--capability-elevation",
            "--no-audit",
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should fail clearly for unsupported supervised features, output:\n{text}"
    );
    assert!(
        text.contains("initialized the control channel"),
        "expected supervisor control-channel startup message, got:\n{text}"
    );
    assert!(
        text.contains("runtime capability elevation"),
        "expected requested supervised feature in message, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_supervised_rollback_executes_command() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let rollback_dest = dir.path().join("rollbacks");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    std::fs::create_dir_all(&rollback_dest).expect("mkdir rollback dest");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let rollback_dest = rollback_dest.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--rollback",
            "--no-rollback-prompt",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--rollback-dest",
            &rollback_dest,
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows supervised rollback run should succeed, output:\n{text}"
    );
    assert!(
        text.contains("test"),
        "expected child command output from supervised rollback run, got:\n{text}"
    );
    assert!(
        !text.contains("scaffold only"),
        "supported supervised rollback should not claim scaffold-only behavior, got:\n{text}"
    );
    assert!(
        !text.contains("preview limitation"),
        "supported supervised rollback should not claim preview-only behavior, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_supervised_rollback_block_net_uses_promoted_wfp_backend() {
    let probe = windows_net_probe_bin();
    if !try_add_and_remove_windows_firewall_rule(&probe) {
        return;
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let port = listener
        .local_addr()
        .expect("listener addr")
        .port()
        .to_string();

    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let rollback_dest = dir.path().join("rollbacks");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    std::fs::create_dir_all(&rollback_dest).expect("mkdir rollback dest");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let rollback_dest = rollback_dest.to_string_lossy().into_owned();
    let probe = probe.to_string_lossy().into_owned();

    let output = nono_bin()
        // NONO_TEST_HARNESS: required by set_windows_wfp_test_force_ready runtime
        // guard (Phase 41 REQ-CI-02).
        .env("NONO_TEST_HARNESS", "1")
        .args([
            "run",
            "--rollback",
            "--no-rollback-prompt",
            "--dangerous-force-wfp-ready",
            "--block-net",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--rollback-dest",
            &rollback_dest,
            "--",
            &probe,
            "127.0.0.1",
            &port,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows supervised rollback blocked-network run should fail the probe connection, output:\n{text}"
    );
    assert!(
        !text.contains("install-wfp-service"),
        "expected promoted WFP backend path rather than readiness/setup failure, got:\n{text}"
    );
    assert!(
        !text.contains("not implemented yet"),
        "expected live supervised blocked-network path rather than placeholder activation, got:\n{text}"
    );
    assert!(
        !text.contains("preview limitation"),
        "supported supervised blocked-network path should not report preview-only behavior, got:\n{text}"
    );
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(
        listener.accept().is_err(),
        "listener unexpectedly accepted a connection during supervised blocked run, output:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_wrap_help_reports_documented_limitation() {
    let output = nono_bin()
        .args(["wrap", "--help"])
        .output()
        .expect("failed to run nono wrap --help");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows wrap help should succeed, output:\n{text}"
    );
    assert!(
        text.contains("Job Object"),
        "expected Windows wrap help to describe Job Object enforcement, got:\n{text}"
    );
    assert!(
        !text.contains("preview path"),
        "wrap help should not regress to preview-path wording, got:\n{text}"
    );
    assert!(
        !text.contains("first-class supported"),
        "wrap help must not imply first-class Windows support yet, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "wrap behavior semantics changed; see Phase 32 wrap availability update"]
fn windows_wrap_reports_documented_limitation() {
    let output = nono_bin()
        .args(["wrap", "--", "cmd", "/c", "echo", "test"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows wrap should fail closed, output:\n{text}"
    );
    assert!(
        text.contains("Live `nono wrap` is intentionally unavailable on Windows."),
        "expected explicit wrap limitation, got:\n{text}"
    );
    assert!(
        text.contains("Use `nono run -- <command>`"),
        "expected actionable alternative in wrap limitation message, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "wrap behavior semantics changed; see Phase 32 wrap availability update"]
fn windows_wrap_live_reports_supported_alternative_without_preview_claim() {
    let output = nono_bin()
        .args(["wrap", "--", "cmd", "/c", "echo", "test"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows wrap should fail closed, output:\n{text}"
    );
    assert!(
        text.contains("Use `nono run -- <command>`"),
        "expected wrap failure to point at the supported Windows execution path, got:\n{text}"
    );
    assert!(
        !text.contains("preview"),
        "wrap failure should not regress to preview-era messaging, got:\n{text}"
    );
    assert!(
        !text.contains("first-class supported"),
        "wrap failure must not imply first-class Windows support yet, got:\n{text}"
    );
}
