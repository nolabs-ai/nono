//! Signed startup policy through the real CLI, without a platform checkout.
#[path = "../src/platform_policy/protocol.rs"]
mod protocol;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nono_test_support::{Argv, NonoTest, nono_test};
use protocol::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

struct Platform {
    stopped: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    thread: Option<JoinHandle<()>>,
}

impl Platform {
    fn stop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !thread::panicking() {
                result.expect("mock platform");
            }
        }
    }
}

impl Drop for Platform {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Client {
    test: NonoTest,
    platform: Platform,
    cache: PathBuf,
    allowed: PathBuf,
    denied: PathBuf,
}

impl Client {
    fn new(profile: Option<serde_json::Value>) -> Self {
        let test = nono_test!("managed-policy");
        let allowed = test.root().join("allowed.txt");
        let denied = test.root().join("denied.txt");
        fs::write(&allowed, "ASSIGNED_ACCESS").expect("allowed file");
        fs::write(&denied, "UNGRANTED_ACCESS").expect("denied file");
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("platform key");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("platform key");
        let trust = PolicyTrustRoot {
            algorithm: "ecdsa_p256_sha256_fixed".into(),
            key_id: digest(key.public_key().as_ref()),
            public_key: URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
        };
        let key_file = test.root().join("device-key");
        nono::store_secret_file(&key_file, &STANDARD.encode(pkcs8.as_ref())).expect("device key");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let mode = if profile.is_some() {
            "advisory"
        } else {
            "audit_only"
        };
        let profile = profile.map(|mut profile| {
            profile["groups"] = json!({"include":["assigned-files"]});
            let text = json!({
                "root":profile, "profiles":{},
                "groups":{"assigned-files":{"description":"delivered grant", "allow":{"read":[allowed]}}}
            }).to_string();
            DeliveredPolicy { profile_id:"assigned".into(), revision:1, delta_version:0, content_digest:digest(text.as_bytes()), profile_json:text }
        });
        let config = test.home().join(".config/nono");
        fs::create_dir_all(&config).expect("config");
        fs::write(config.join("platform.json"), json!({
            "protocol_version":PROTOCOL, "platform_url":origin, "tenant_id":"tenant", "subject_id":"device",
            "subject_kind":"device", "management_mode":"audit_only", "last_policy_mode":mode,
            "key_algorithm":trust.algorithm, "key_ref":format!("file://{}",key_file.display()), "enrolled_at":"2026-01-01T00:00:00Z"
        }).to_string()).expect("enrollment");
        let scope = serde_json::to_vec(&(&origin, "tenant", "device")).expect("scope");
        let cache = test.state().join("nono/platform-policy").join(format!(
            "{}.json",
            digest(&scope).trim_start_matches("sha256:")
        ));
        fs::create_dir_all(cache.parent().expect("cache parent")).expect("cache directory");
        fs::write(
            &cache,
            json!({"trust_root":trust, "response":null}).to_string(),
        )
        .expect("pin");
        let stopped = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = stopped.clone();
        let count = requests.clone();
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let (path, request_id) = read_request(&mut stream);
                        if path != TRUST_PATH && path != REFRESH_PATH {
                            stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").expect("audit unavailable");
                            continue;
                        }
                        let response = if path == TRUST_PATH {
                            serde_json::to_vec(&trust).expect("trust response")
                        } else {
                            assert_eq!(path, REFRESH_PATH);
                            count.fetch_add(1, Ordering::SeqCst);
                            let claims = PolicyClaims {
                                protocol_version: PROTOCOL.into(),
                                tenant_id: "tenant".into(),
                                subject_id: "device".into(),
                                request_id,
                                issued_at: chrono::Utc::now(),
                                management_mode: mode.into(),
                                assignment_version: "assignment-1".into(),
                                resolved_via: json!({"layer":"subject"}),
                                policy: profile.clone(),
                            };
                            let payload = serde_json::to_vec(&claims).expect("claims");
                            serde_json::to_vec(&SignedPolicyResponse {
                                algorithm: trust.algorithm.clone(),
                                key_id: trust.key_id.clone(),
                                payload: URL_SAFE_NO_PAD.encode(&payload),
                                signature: URL_SAFE_NO_PAD
                                    .encode(key.sign(&rng, &payload).expect("signature").as_ref()),
                            })
                            .expect("response")
                        };
                        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()).expect("headers");
                        stream.write_all(&response).expect("response body");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            }
        });
        Self {
            test,
            platform: Platform {
                stopped,
                requests,
                thread: Some(thread),
            },
            cache,
            allowed,
            denied,
        }
    }
}

fn read_request(stream: &mut TcpStream) -> (String, String) {
    stream.set_nonblocking(false).expect("blocking stream");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("request line");
    let path = line
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string();
    let mut request_id = String::new();
    let mut length = 0;
    loop {
        line.clear();
        assert_ne!(
            reader.read_line(&mut line).expect("header"),
            0,
            "incomplete request"
        );
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.trim_end().split_once(':').expect("header value");
        match name.to_ascii_lowercase().as_str() {
            "x-nono-request-id" => request_id = value.trim().into(),
            "content-length" => length = value.trim().parse().expect("body length"),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).expect("request body");
    if path == REFRESH_PATH {
        let _: PolicyRefreshRequest = serde_json::from_slice(&body).expect("refresh context");
    }
    (path, request_id)
}

fn static_profile() -> serde_json::Value {
    json!({"meta":{"name":"managed-wrap"}, "network":{"block":true}})
}

fn sessions(client: &Client) -> Vec<serde_json::Value> {
    fs::read_dir(client.test.state().join("nono/sessions"))
        .expect("sessions")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| {
            serde_json::from_slice(&fs::read(path).expect("session")).expect("session JSON")
        })
        .collect()
}

fn policy_event(client: &Client, session: &serde_json::Value) -> serde_json::Value {
    let dir = client
        .test
        .audit_root()
        .join(session["session_id"].as_str().expect("session ID"));
    let events = fs::read_to_string(dir.join(nono::audit::AUDIT_EVENTS_FILENAME)).expect("audit");
    assert!(
        nono::audit::verify_audit_log(&dir, None)
            .expect("audit integrity")
            .records_verified
    );
    events
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("event"))
        .find(|record| record["event"]["type"] == "platform_policy")
        .expect("policy event")["event"]
        .clone()
}

#[test]
fn run_and_shell_persist_input_sources_in_session_and_audit() {
    for subcommand in ["run", "shell"] {
        let client = Client::new(Some(static_profile()));
        let mut command = client.test.command();
        command.arg(subcommand).env("NONO_BLOCK_NET", "false");
        if subcommand == "run" {
            command.args([
                "--no-rollback",
                "--skip-dir",
                "private-skip-value",
                "--no-diagnostics",
                "--",
                "/bin/echo",
            ]);
        } else {
            command.args(["--shell", "/bin/sh"]);
        }
        let output = command.output().expect("launch");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let records = sessions(&client);
        assert_eq!(records.len(), 1);
        let session = &records[0];
        assert_eq!(
            session["policy"]["override_sources"]["block-net"], "environment",
            "{subcommand}: {}",
            session["policy"]
        );
        let event = policy_event(&client, session);
        assert_eq!(
            event["override_sources"],
            session["policy"]["override_sources"]
        );
        assert!(
            event["overrides"]
                .as_array()
                .expect("names")
                .contains(&json!("block-net"))
        );
        if subcommand == "run" {
            assert_eq!(event["override_sources"]["skip-dir"], "command_line");
            assert!(event["override_sources"].get("no-rollback").is_none());
            assert!(!event.to_string().contains("private-skip-value"));
        }
    }
}

#[test]
fn no_audit_remains_available_and_records_only_local_session_attribution() {
    for advisory in [true, false] {
        let client = Client::new(advisory.then(static_profile));
        let output = client
            .test
            .command()
            .args(["run", "--no-audit", "--no-diagnostics", "--", "/bin/echo"])
            .output()
            .expect("run");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let records = sessions(&client);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0]["policy"]["override_sources"]["no-audit"],
            "command_line"
        );
        assert!(!client.test.audit_root().exists());
    }
}

#[test]
fn detached_launch_reparses_cli_and_environment_sources() {
    let client = Client::new(Some(static_profile()));
    let mut command = client.test.command();
    let mut policy = static_profile();
    policy["workdir"] = json!({"access":"readwrite"});
    let profile = client.test.workspace().join("local-profile.json");
    fs::write(&profile, policy.to_string()).expect("profile");
    let output = command
        .env("NONO_PROFILE", &profile)
        .args([
            "run",
            "--detach",
            "--name",
            "provenance",
            "--no-rollback",
            "--no-diagnostics",
            "--block-net",
            "--",
            "/bin/sleep",
            "5",
        ])
        .output()
        .expect("detached launch");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = sessions(&client);
    let id = records.first().expect("session")["session_id"]
        .as_str()
        .expect("ID")
        .to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let records = sessions(&client);
        let session = records
            .iter()
            .find(|record| record["session_id"] == id)
            .expect("session");
        if session["status"] != "running" {
            assert_eq!(
                session["policy"]["override_sources"]["profile"],
                "environment"
            );
            assert_eq!(
                session["policy"]["override_sources"]["block-net"],
                "command_line"
            );
            assert!(
                session["policy"]["override_sources"]
                    .get("detached")
                    .is_none()
            );
            assert!(session["policy"]["override_sources"].get("name").is_none());
            let event = policy_event(&client, session);
            assert_eq!(
                event["override_sources"],
                session["policy"]["override_sources"]
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "detached session did not finish"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn wrap_applies_signed_groups_and_rejects_tampering_before_execution() {
    let client = Client::new(Some(static_profile()));
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/cat").arg(&client.allowed))
        .assert_success("signed group grants the assigned file")
        .assert_stdout_contains("ASSIGNED_ACCESS")
        .assert_stderr_contains("cannot deliver session audit evidence");
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/cat").arg(&client.denied))
        .assert_failure("ungranted file stays inaccessible")
        .assert_stdout_lacks("UNGRANTED_ACCESS");
    let marker = client.test.workspace().join("must-not-run");
    client
        .test
        .wrap()
        .dry_run()
        .exec(Argv::new("/usr/bin/touch").arg(&marker))
        .assert_success("dry-run verifies policy without execution");
    assert!(!marker.exists());
    let mut cache: serde_json::Value =
        serde_json::from_slice(&fs::read(&client.cache).expect("cache")).expect("cache JSON");
    cache["response"]["signature"] = URL_SAFE_NO_PAD.encode([0u8; 64]).into();
    fs::write(&client.cache, cache.to_string()).expect("tamper");
    let requests = client.platform.requests.load(Ordering::SeqCst);
    for command in [
        client.test.wrap(),
        client.test.wrap().dry_run(),
        client.test.wrap().profile_name("default"),
    ] {
        command
            .exec(Argv::new("/usr/bin/touch").arg(&marker))
            .assert_failure("invalid signature fails before execution, including overrides")
            .assert_stderr_contains("platform policy");
        assert!(!marker.exists());
    }
    assert_eq!(client.platform.requests.load(Ordering::SeqCst), requests);
}

#[test]
fn wrap_refuses_managed_features_that_need_a_supervisor() {
    for extra in [
        json!({"network":{"allow_domain":["example.com"]}}),
        json!({"network":{"deny_domain":["example.com"]}}),
        json!({"security":{"capability_elevation":true}}),
        json!({"session_recording":{"required":true}}),
        json!({"command_policies":{"commands":{"echo":{"executable":"/bin/echo","from":{"session":{"sandbox":{"fs_read":["/usr/lib"]}}}}}}}),
    ] {
        let mut profile = static_profile();
        profile
            .as_object_mut()
            .expect("profile")
            .extend(extra.as_object().expect("settings").clone());
        let client = Client::new(Some(profile));
        for command in [client.test.wrap(), client.test.wrap().dry_run()] {
            command
                .exec(Argv::new("/bin/echo").arg("MUST_NOT_RUN"))
                .assert_failure("supervised settings cannot be dropped by direct exec")
                .assert_stdout_lacks("MUST_NOT_RUN")
                .assert_stderr_contains("nono run");
        }
    }
}

#[test]
fn wrap_keeps_advisory_offline_rules_and_audit_only_local_operation() {
    for advisory in [true, false] {
        let mut client = Client::new(advisory.then(static_profile));
        client
            .test
            .wrap()
            .exec(Argv::new("/bin/echo").arg("ONLINE"))
            .assert_success("online policy is fetched");
        client.platform.stop();
        let offline = client
            .test
            .wrap()
            .exec(Argv::new("/bin/echo").arg("OFFLINE"));
        if advisory {
            offline
                .assert_failure("advisory defaults require fresh policy")
                .assert_stdout_lacks("OFFLINE");
            client
                .test
                .wrap()
                .profile_name("default")
                .exec(Argv::new("/bin/echo").arg("EXPLICIT_LOCAL"))
                .assert_success("an explicit advisory override remains available offline");
        } else {
            offline.assert_success("audit-only local operation remains available offline");
        }
    }
}
