//! Integration tests for environment variable CLI flag equivalents.
//!
//! These run as separate processes via `--dry-run`, so env vars are isolated
//! and cannot race with parallel unit tests.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Combine stdout + stderr for assertion checking (nono writes UX to stderr).
fn combined_output(output: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
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
fn env_nono_capability_elevation_accepts_truthy() {
    let output = nono_bin()
        .env("NONO_CAPABILITY_ELEVATION", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_CAPABILITY_ELEVATION=1 should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_trust_override_accepts_truthy() {
    let output = nono_bin()
        .env("NONO_TRUST_OVERRIDE", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_TRUST_OVERRIDE=1 should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn env_nono_trust_proxy_ca_accepts_truthy() {
    let output = nono_bin()
        .env("NONO_TRUST_PROXY_CA", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_TRUST_PROXY_CA=1 should be accepted, stderr: {}",
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
        .env("NONO_PROFILE", "node-dev")
        .args(["run", "--dry-run", "--allow-cwd", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_PROFILE=node-dev should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_network_profile() {
    let output = nono_bin()
        .env("NONO_NETWORK_PROFILE", "node-dev")
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
            "node-dev",
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

#[test]
fn environment_allow_vars_with_profile() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let profile_path = dir.path().join("env-filter-profile.json");
    std::fs::write(
        &profile_path,
        r#"{
            "meta": { "name": "env-filter-test" },
            "filesystem": { "allow": ["/usr", "/bin", "/lib", "/tmp"] },
            "environment": {
                "allow_vars": ["PATH"]
            }
        }"#,
    )
    .expect("write profile");

    let output = nono_bin()
        .env("MY_SECRET", "should_not_see")
        .args([
            "run",
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--dry-run",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "profile with environment.allow_vars should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn environment_allow_vars_default_allows_all() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let profile_path = dir.path().join("no-env-filter-profile.json");
    std::fs::write(
        &profile_path,
        r#"{
            "meta": { "name": "no-env-filter-test" },
            "filesystem": { "allow": ["/usr", "/bin", "/lib", "/tmp"] }
        }"#,
    )
    .expect("write profile");

    let output = nono_bin()
        .args([
            "run",
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--dry-run",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "profile without environment section should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn environment_allow_vars_prefix_patterns() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let profile_path = dir.path().join("env-prefix-profile.json");
    std::fs::write(
        &profile_path,
        r#"{
            "meta": { "name": "env-prefix-test" },
            "filesystem": { "allow": ["/usr", "/bin", "/lib", "/tmp"] },
            "environment": {
                "allow_vars": ["PATH", "HOME", "AWS_*", "MYAPP_*"]
            }
        }"#,
    )
    .expect("write profile");

    let output = nono_bin()
        .args([
            "run",
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--dry-run",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "profile with prefix patterns should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn environment_allow_vars_bare_star() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let profile_path = dir.path().join("env-bare-star-profile.json");
    std::fs::write(
        &profile_path,
        r#"{
            "meta": { "name": "env-bare-star-test" },
            "filesystem": { "allow": ["/usr", "/bin", "/lib", "/tmp"] },
            "environment": {
                "allow_vars": ["*"]
            }
        }"#,
    )
    .expect("write profile");

    let output = nono_bin()
        .args([
            "run",
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--dry-run",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "profile with bare * should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
