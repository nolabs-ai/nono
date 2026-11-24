use nono_test_support::{Argv, nono_test};
use serde_json::json;

#[test]
fn profile_queries_do_not_auto_approve_hosts_that_need_network_review() {
    let t = nono_test!("why-network-approval");
    for (allow, deny, host, expected) in [
        (vec![], vec![], "example.com", "approval_required"),
        (vec!["docs.rs"], vec![], "example.com", "approval_required"),
        (vec!["docs.rs"], vec![], "docs.rs", "allowed"),
        (vec!["*"], vec!["example.com"], "example.com", "denied"),
        (vec![], vec![], "169.254.169.254", "denied"),
    ] {
        let source = json!({"network": {"allow_domain":allow, "deny_domain":deny,
            "approval_backends":{"review":{"type":"webhook","auth":"platform"}},
            "approval_defaults":{"backend":"review"}}});
        t.write_profile("network-review", &source.to_string());
        let output = t
            .command()
            .args(["why", "--profile"])
            .arg(t.home().join("network-review.json"))
            .args(["--host", host, "--json"])
            .output()
            .expect("query");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON verdict");
        assert_eq!(result["status"], expected, "{host}: {result}");
    }
}

#[test]
fn self_queries_preserve_the_active_network_approval_requirement() {
    let t = nono_test!("why-self-network-approval");
    let binary = env!("CARGO_BIN_EXE_nono");
    let profile = t.write_profile(
        "network-review",
        &json!({
            "filesystem":{"read_file":[binary]},
            "network":{"approval_backends":{"review":{"type":"terminal"}},
                "approval_defaults":{"backend":"review"}}
        })
        .to_string(),
    );
    t.run()
        .profile(&profile)
        .allow_cwd()
        .no_rollback()
        .exec(
            Argv::new(binary)
                .arg("why")
                .arg("--self")
                .arg("--host")
                .arg("example.com")
                .arg("--json"),
        )
        .assert_success("active sandbox state retains approval-only networking")
        .assert_stdout_contains("\"status\": \"approval_required\"");
}
