//! Sideload feature tests.
//!
//! Two cfg sections with different run instructions:
//!
//! **Production build** (`#[cfg(not(feature = "sideload"))]`):
//!   Verifies the lockfile guard hard-errors on sideloaded entries.
//!   Run with: `cargo test -p nono-cli`
//!
//! **Sideload build** (`#[cfg(feature = "sideload")]`):
//!   Functional tests for `nono sideload` and related commands.
//!   Run with: `cargo test -p nono-cli --features sideload`

// ---------------------------------------------------------------------------
// Production build: lockfile defense-in-depth
// ---------------------------------------------------------------------------

/// On a production binary (compiled without --features sideload), a lockfile
/// containing `sideload: true` must cause hard failure with a clear message.
#[cfg(not(feature = "sideload"))]
mod production {
    fn nono_bin() -> std::process::Command {
        std::process::Command::new(env!("CARGO_BIN_EXE_nono"))
    }

    #[test]
    fn lockfile_with_sideload_entry_hard_errors() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let packages_dir = cfg.path().join("nono").join("packages");
        std::fs::create_dir_all(&packages_dir).expect("create packages dir");

        std::fs::write(
            packages_dir.join("lockfile.json"),
            r#"{
  "lockfile_version": 4,
  "registry": "",
  "packages": {
    "acme/evil-pack": {
      "version": "1.0.0",
      "installed_at": "2026-01-01T00:00:00Z",
      "sideload": true
    }
  }
}"#,
        )
        .expect("write lockfile");

        let output = nono_bin()
            .args(["list", "--installed"])
            .env("XDG_CONFIG_HOME", cfg.path())
            .output()
            .expect("spawn nono");

        assert!(
            !output.status.success(),
            "expected hard error on production binary for sideload entry"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("sideload"),
            "error must mention sideload, got:\n{stderr}"
        );
        assert!(
            stderr.contains("acme/evil-pack"),
            "error must name the offending pack, got:\n{stderr}"
        );
    }

    #[test]
    fn lockfile_without_sideload_entries_loads_cleanly() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let packages_dir = cfg.path().join("nono").join("packages");
        std::fs::create_dir_all(&packages_dir).expect("create packages dir");

        std::fs::write(
            packages_dir.join("lockfile.json"),
            r#"{
  "lockfile_version": 4,
  "registry": "https://registry.nono.sh",
  "packages": {}
}"#,
        )
        .expect("write lockfile");

        let output = nono_bin()
            .args(["list", "--installed"])
            .env("XDG_CONFIG_HOME", cfg.path())
            .output()
            .expect("spawn nono");

        assert!(
            output.status.success(),
            "expected clean load for lockfile without sideload entries, stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn sideload_subcommand_absent_on_production_binary() {
        let output = nono_bin()
            .args(["sideload", "/tmp"])
            .output()
            .expect("spawn nono");

        assert!(
            !output.status.success(),
            "expected clap to reject unknown subcommand on production binary"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unrecognized") || stderr.contains("error"),
            "expected clap error for unknown subcommand, got:\n{stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// Sideload build: functional tests
// ---------------------------------------------------------------------------

#[cfg(feature = "sideload")]
mod sideload_enabled {
    use std::path::Path;

    fn nono_bin() -> std::process::Command {
        std::process::Command::new(env!("CARGO_BIN_EXE_nono"))
    }

    /// Write a minimal valid pack fixture to `dir`.
    /// The manifest `name` field must be `namespace/name` for `nono sideload`.
    fn write_fixture_pack(dir: &Path, namespace: &str, name: &str, version: &str) {
        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": format!("{namespace}/{name}"),
            "version": version,
            "description": "test fixture pack",
            "artifacts": [
                {
                    "type": "profile",
                    "path": "profile.json",
                    "install_as": format!("{namespace}-{name}")
                }
            ],
            "wiring": []
        });
        std::fs::write(
            dir.join("package.json"),
            serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write package.json");

        std::fs::write(
            dir.join("profile.json"),
            r#"{"meta":{"name":"test","description":"test"}}"#,
        )
        .expect("write profile.json");
    }

    /// Run `nono <args>` with an isolated XDG config root.
    fn run_nono(args: &[&str], config_home: &Path) -> (String, String, bool) {
        let output = nono_bin()
            .args(args)
            .env("XDG_CONFIG_HOME", config_home)
            .output()
            .expect("spawn nono");
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status.success(),
        )
    }

    fn read_lockfile(config_home: &Path) -> serde_json::Value {
        let path = config_home
            .join("nono")
            .join("packages")
            .join("lockfile.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("read lockfile"))
            .expect("parse lockfile")
    }

    // ── startup banner ───────────────────────────────────────────────────────

    #[test]
    fn startup_banner_warns_about_sideload_feature() {
        let output = nono_bin()
            .args(["list", "--installed"])
            .output()
            .expect("spawn nono");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("integrity") && stderr.contains("DISABLED"),
            "expected sideload warning banner, got:\n{stderr}"
        );
    }

    // ── install ──────────────────────────────────────────────────────────────

    #[test]
    fn sideload_installs_pack_from_local_directory() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");
        write_fixture_pack(src.path(), "acme", "my-pack", "0.1.0");

        let (_, stderr, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path to str")],
            cfg.path(),
        );
        assert!(ok, "sideload failed:\n{stderr}");
        assert!(
            stderr.contains("acme/my-pack"),
            "pack name missing:\n{stderr}"
        );
        assert!(stderr.contains("0.1.0"), "version missing:\n{stderr}");

        // Install directory must exist.
        let install_dir = cfg
            .path()
            .join("nono")
            .join("packages")
            .join("acme")
            .join("my-pack");
        assert!(install_dir.exists(), "install dir not created");

        // Lockfile: sideload: true, pinned: true, no provenance, no bundle.
        let lf = read_lockfile(cfg.path());
        let entry = &lf["packages"]["acme/my-pack"];
        assert_eq!(entry["sideload"], true);
        assert_eq!(entry["pinned"], true);
        assert_eq!(entry["version"], "0.1.0");
        assert!(
            entry.get("provenance").is_none() || entry["provenance"].is_null(),
            "no provenance expected for sideloaded pack"
        );
        assert!(
            !install_dir.join(".nono-trust.bundle").exists(),
            "sideloaded pack must not have a .nono-trust.bundle"
        );
    }

    #[test]
    fn sideload_over_existing_install_auto_removes_then_reinstalls() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");
        write_fixture_pack(src.path(), "acme", "replaceable", "0.1.0");

        let (_, _, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path to str")],
            cfg.path(),
        );
        assert!(ok);

        // Bump version, sideload again.
        write_fixture_pack(src.path(), "acme", "replaceable", "0.2.0");
        let (_, stderr, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path to str")],
            cfg.path(),
        );
        assert!(ok, "re-sideload failed:\n{stderr}");
        assert!(
            stderr.contains("already installed") || stderr.contains("removing"),
            "expected removal notice:\n{stderr}"
        );

        let lf = read_lockfile(cfg.path());
        assert_eq!(
            lf["packages"]["acme/replaceable"]["version"], "0.2.0",
            "lockfile must reflect updated version"
        );
    }

    // ── list ─────────────────────────────────────────────────────────────────

    #[test]
    fn nono_list_annotates_sideloaded_entries() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");
        write_fixture_pack(src.path(), "acme", "listed", "1.0.0");

        let (_, _, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path to str")],
            cfg.path(),
        );
        assert!(ok);

        let (stdout, stderr, ok) = run_nono(&["list", "--installed"], cfg.path());
        assert!(ok, "list failed:\n{stderr}");
        assert!(
            stdout.contains("[sideload]"),
            "expected [sideload] annotation:\n{stdout}"
        );
        assert!(
            stdout.contains("acme/listed"),
            "pack name missing:\n{stdout}"
        );
    }

    // ── update ───────────────────────────────────────────────────────────────

    #[test]
    fn nono_update_silently_skips_sideloaded_entries() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");
        write_fixture_pack(src.path(), "acme", "skipped", "1.0.0");

        let (_, _, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path to str")],
            cfg.path(),
        );
        assert!(ok);

        // update with only sideloaded (pinned) packs must exit 0 and not hit the registry.
        let (_, stderr, ok) = run_nono(&["update"], cfg.path());
        assert!(
            ok,
            "update must succeed with only sideloaded packs:\n{stderr}"
        );
        assert!(
            !stderr.contains("registry") && !stderr.contains("http"),
            "update must not query registry for sideloaded packs:\n{stderr}"
        );
    }

    // ── outdated ─────────────────────────────────────────────────────────────

    #[test]
    fn nono_outdated_skips_sideloaded_entries() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");
        write_fixture_pack(src.path(), "acme", "outdated-test", "1.0.0");

        let (_, _, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path to str")],
            cfg.path(),
        );
        assert!(ok);

        let (stdout, stderr, ok) = run_nono(&["outdated"], cfg.path());
        assert!(ok, "outdated must succeed:\n{stderr}");
        assert!(
            !stdout.contains("acme/outdated-test"),
            "sideloaded pack must not appear in outdated output:\n{stdout}"
        );
    }

    // ── path traversal / arbitrary file read ─────────────────────────────────

    /// A manifest whose artifact.path is an absolute path (e.g. /etc/passwd)
    /// must be rejected before any filesystem access.
    #[test]
    fn sideload_rejects_absolute_artifact_path() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");

        // Write a manifest with an absolute path in the artifact list.
        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": "acme/evil-abs",
            "version": "1.0.0",
            "description": "adversarial fixture",
            "artifacts": [
                {
                    "type": "trust_policy",
                    "path": "/etc/passwd"
                }
            ],
            "wiring": []
        });
        std::fs::write(
            src.path().join("package.json"),
            serde_json::to_string_pretty(&manifest).expect("serialize"),
        )
        .expect("write package.json");

        let (_, stderr, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path")],
            cfg.path(),
        );
        assert!(!ok, "sideload must fail for absolute artifact path");
        assert!(
            stderr.contains("relative") || stderr.contains("absolute") || stderr.contains("path"),
            "error must mention path validation, got:\n{stderr}"
        );
    }

    /// A manifest whose artifact.path contains '..' must be rejected before
    /// any filesystem access to prevent directory traversal.
    #[test]
    fn sideload_rejects_dotdot_artifact_path() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");

        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": "acme/evil-dotdot",
            "version": "1.0.0",
            "description": "adversarial fixture",
            "artifacts": [
                {
                    "type": "groups",
                    "path": "../../sensitive-file"
                }
            ],
            "wiring": []
        });
        std::fs::write(
            src.path().join("package.json"),
            serde_json::to_string_pretty(&manifest).expect("serialize"),
        )
        .expect("write package.json");

        let (_, stderr, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path")],
            cfg.path(),
        );
        assert!(!ok, "sideload must fail for '..'-containing artifact path");
        assert!(
            stderr.contains("..") || stderr.contains("relative") || stderr.contains("path"),
            "error must mention path validation, got:\n{stderr}"
        );
    }

    /// A profile artifact whose path contains '..' must also be rejected.
    /// This covers a type that previously went through validate_safe_name on
    /// install_as but not validate_relative_path on the source path.
    #[test]
    fn sideload_rejects_dotdot_profile_artifact_path() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");

        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": "acme/evil-profile",
            "version": "1.0.0",
            "description": "adversarial fixture",
            "artifacts": [
                {
                    "type": "profile",
                    "path": "../outside.json",
                    "install_as": "safe-name"
                }
            ],
            "wiring": []
        });
        std::fs::write(
            src.path().join("package.json"),
            serde_json::to_string_pretty(&manifest).expect("serialize"),
        )
        .expect("write package.json");

        let (_, stderr, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path")],
            cfg.path(),
        );
        assert!(!ok, "sideload must fail for '..'-profile artifact path");
        assert!(
            stderr.contains("..") || stderr.contains("relative") || stderr.contains("path"),
            "error must mention path validation, got:\n{stderr}"
        );
    }

    // ── remove ───────────────────────────────────────────────────────────────

    #[test]
    fn nono_remove_reverses_sideloaded_pack() {
        let cfg = tempfile::tempdir().expect("cfg dir");
        let src = tempfile::tempdir().expect("pack src");
        write_fixture_pack(src.path(), "acme", "removable", "1.0.0");

        let (_, _, ok) = run_nono(
            &["sideload", src.path().to_str().expect("path to str")],
            cfg.path(),
        );
        assert!(ok);

        let install_dir = cfg
            .path()
            .join("nono")
            .join("packages")
            .join("acme")
            .join("removable");
        assert!(install_dir.exists(), "pack not installed before remove");

        let (_, stderr, ok) = run_nono(&["remove", "acme/removable"], cfg.path());
        assert!(ok, "remove failed:\n{stderr}");
        assert!(!install_dir.exists(), "install dir must be cleaned up");

        let lf = read_lockfile(cfg.path());
        assert!(
            lf["packages"].get("acme/removable").is_none(),
            "lockfile must not contain removed pack"
        );
    }
}
