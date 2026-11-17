//! Launch-time analytics attribution survives independently of current configuration.

use nono_test_support::{NonoTest, nono_test};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn captured_profile(t: &NonoTest) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let directories: Vec<_> = fs::read_dir(t.audit_root())
            .expect("audit root")
            .map(|entry| entry.expect("audit entry").path())
            .filter(|path| path.is_dir())
            .collect();
        assert_eq!(directories.len(), 1, "one session per fixture");
        let dir = &directories[0];
        if dir.join("session.json").is_file() {
            assert!(
                nono::audit::verify_audit_log(dir, None)
                    .expect("audit integrity")
                    .records_verified
            );
            return serde_json::from_slice(
                &fs::read(dir.join("platform-audit-profile.json")).expect("captured profile"),
            )
            .expect("profile reference");
        }
        assert!(Instant::now() < deadline, "session did not finalize");
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn launches_capture_explicit_profiles_recommendations_and_unknown_executables() {
    for case in [
        "explicit",
        "environment",
        "file",
        "recommended",
        "unknown",
        "shell",
        "detached",
    ] {
        let t = nono_test!("audit-profile");
        let executable = t.workspace().join("claude");
        fs::write(&executable, "#!/bin/sh\n/bin/sleep \"${1:-0}\"\n")
            .expect("harmless executable with a recognised name");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("executable fixture");
        let local_profile = t.workspace().join("customer-profile.json");
        fs::write(
            &local_profile,
            r#"{"meta":{"name":"customer-project"},"extends":"default"}"#,
        )
        .expect("local profile");
        let mut command = t.command();
        command
            .arg(if case == "shell" { "shell" } else { "run" })
            .args(["--allow-cwd", "--block-net", "--allow"])
            .arg(t.workspace());
        let expected = match case {
            "explicit" | "shell" => {
                command.args(["--profile", "default"]);
                Some("default".to_string())
            }
            "environment" => {
                command.env("NONO_PROFILE", "default");
                Some("default".to_string())
            }
            "file" => {
                command.arg("--profile").arg(&local_profile);
                Some(local_profile.to_string_lossy().into_owned())
            }
            "recommended" | "detached" => Some("nolabs-ai/claude".to_string()),
            "unknown" => None,
            _ => unreachable!(),
        };
        if case == "shell" {
            command.args(["--shell", "/bin/sh"]);
        } else {
            command.args(["--no-rollback", "--no-diagnostics"]);
            if case == "detached" {
                command.args(["--detached", "--name", "profile-ref-test"]);
            }
            command.arg("--").arg(if case == "unknown" {
                std::path::Path::new("/bin/echo")
            } else {
                &executable
            });
            if case == "detached" {
                command.arg("1");
            }
        }
        let output = command.output().expect("launch");
        assert!(
            output.status.success(),
            "{case}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(captured_profile(&t), expected, "{case}");
    }
}
