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
    refresh_status: Arc<AtomicUsize>,
    corrupt_response: Arc<AtomicBool>,
    mode: Arc<AtomicUsize>,
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
        Self::with_pack(profile, false)
    }

    fn with_pack(profile: Option<serde_json::Value>, include_pack: bool) -> Self {
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
            if include_pack {
                let pack = test.home().join(".config/nono/packages/acme/assets");
                fs::create_dir_all(pack.join("skills")).expect("pack");
                fs::create_dir_all(pack.join("profiles")).expect("profiles");
                fs::create_dir_all(pack.join("bin")).expect("scripts");
                fs::write(pack.join("package.json"), json!({"schema_version":1,"name":"assets","artifacts":[{"type":"profile","path":"policy.json","install_as":"assets"},{"type":"plugin","path":"skills/SKILL.md"},{"type":"plugin","path":"bin/hook.sh"}],"wiring":[{"type":"write_file","source":"skills/SKILL.md","dest":"$HOME/SHOULD_NOT_BE_INSTALLED"}]}).to_string()).expect("manifest");
                fs::write(pack.join("profiles/assets.json"), json!({
                    "hooks":{"claude":{"event":"PreToolUse","matcher":"Bash","script":"bin/hook.sh"}},
                    "session_hooks":{
                        "before":{"script":"$PACK_DIR/bin/hook.sh"},
                        "after":{"script":"$PACK_DIR/bin/hook.sh"}
                    }
                }).to_string()).expect("profile with hooks");
                let hook = pack.join("bin/hook.sh");
                fs::write(&hook, "#!/bin/sh\nprintf '%s\\n' \"$NONO_HOOK_TYPE\" >> \"$HOME/HOOK_EXECUTED\"\n").expect("hook script");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).expect("executable hook");
                }
                fs::write(pack.join("skills/SKILL.md"), "# Signed skill\n").expect("skill");
                fs::write(pack.join("bundle.sig"), "{\"upstream\":\"preserved\"}").expect("upstream signature");
                fs::create_dir_all(pack.join("assets")).expect("assets");
                fs::write(pack.join("assets/blob.bin"),vec![7u8;2*1024*1024]).expect("large asset");
                profile["packs"] = json!(["acme/assets"]);
                profile["extends"] = json!("acme/assets");
                // Resolvable local paths prove non-execution independently of
                // the inherited $PACK_DIR declarations retained in the pack.
                profile["session_hooks"] = json!({
                    "before":{"script":hook},"after":{"script":hook}
                });
            }
            profile["filesystem"]["read"] = json!([allowed]);
            let source = test.root().join("source.json");
            fs::write(&source, profile.to_string()).expect("source");
            let output = test.command()
                .args(["profile", "show"]).arg(&source).args(["--format", "bundle"])
                .output().expect("export");
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            let mut export: UnsignedBundle = serde_json::from_slice(&output.stdout).expect("exported files");
            export.statement["predicate"]["revision"] = json!(1);
            let payload = serde_json::to_vec(&export.statement).expect("manifest");
            let typ = nono::trust::IN_TOTO_PAYLOAD_TYPE;
            let key = EcdsaKeyPair::from_pkcs8(
                &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(),
            ).expect("bundle key");
            let signature = key.sign(&rng, &nono::trust::pae(typ, &payload)).expect("bundle signature");
            AssignedBundle {
                profile_id: "assigned".into(),
                revision: 1,
                delta_version: 0,
                content_digest: digest(&payload),
                bundle: Some(SignedBundle {
                    signature: json!({
                        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                        "verificationMaterial": {"publicKey": {"hint": trust.key_id}, "tlogEntries": []},
                        "dsseEnvelope": {
                            "payloadType": typ,
                            "payload": STANDARD.encode(payload),
                            "signatures": [{"sig": STANDARD.encode(signature.as_ref())}]
                        }
                    }),
                    files: export.files,
                }),
            }
        });
        let config = test.home().join(".config/nono");
        fs::create_dir_all(&config).expect("config");
        fs::write(config.join("platform.json"), json!({
            "protocol_version":"1", "platform_url":origin, "tenant_id":"tenant", "subject_id":"device",
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
        let refresh_status = Arc::new(AtomicUsize::new(200));
        let status = refresh_status.clone();
        let corrupt_response = Arc::new(AtomicBool::new(false));
        let corrupt = corrupt_response.clone();
        let mode_setting = Arc::new(AtomicUsize::new(if profile.is_some() { 1 } else { 0 }));
        let response_mode = mode_setting.clone();
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let (path, request_id) = read_request(&mut stream);
                        if path == REFRESH_PATH && status.load(Ordering::SeqCst) != 200 {
                            write!(stream,"HTTP/1.1 {} Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",status.load(Ordering::SeqCst)).expect("refresh unavailable");
                            continue;
                        }
                        if path != TRUST_PATH
                            && path != REFRESH_PATH
                            && path != "/api/v1/enrollment/exchange"
                        {
                            stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").expect("audit unavailable");
                            continue;
                        }
                        let response = if path == "/api/v1/enrollment/exchange" {
                            serde_json::to_vec(&json!({
                                "protocol_version":"1","tenant_id":"tenant","subject_id":"device",
                                "subject_kind":"device","management_mode":"audit_only",
                                "enrolled_at":"2026-01-01T00:00:00Z","policy_trust_root":trust
                            }))
                            .expect("enrollment response")
                        } else if path == TRUST_PATH {
                            serde_json::to_vec(&trust).expect("trust response")
                        } else {
                            assert_eq!(path, REFRESH_PATH);
                            count.fetch_add(1, Ordering::SeqCst);
                            let claims = AssignmentClaims {
                                protocol_version: PROTOCOL.into(),
                                tenant_id: "tenant".into(),
                                subject_id: "device".into(),
                                request_id,
                                issued_at: chrono::Utc::now(),
                                management_mode: match response_mode.load(Ordering::SeqCst) {
                                    0 => "audit_only",
                                    1 => "advisory",
                                    _ => "enforced",
                                }
                                .into(),
                                assignment_version: "assignment-1".into(),
                                resolved_via: json!({"layer":"subject"}),
                                policy: profile.clone(),
                            };
                            let payload = serde_json::to_vec(&claims).expect("claims");
                            serde_json::to_vec(&PolicyRefreshResponse {
                                algorithm: trust.algorithm.clone(),
                                key_id: trust.key_id.clone(),
                                payload: URL_SAFE_NO_PAD.encode(&payload),
                                signature: if corrupt.load(Ordering::SeqCst) {
                                    URL_SAFE_NO_PAD.encode([0u8; 64])
                                } else {
                                    URL_SAFE_NO_PAD.encode(
                                        key.sign(&rng, &payload).expect("signature").as_ref(),
                                    )
                                },
                                bundle: profile.as_ref().and_then(|policy| policy.bundle.clone()),
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
                refresh_status,
                corrupt_response,
                mode: mode_setting,
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

#[test]
fn enforced_internal_launcher_rejects_local_permissions() {
    use std::os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    };

    let client = Client::new(Some(static_profile()));
    client.platform.mode.store(2, Ordering::SeqCst);
    assert!(
        client
            .test
            .command()
            .args(["platform", "status", "--refresh"])
            .output()
            .expect("refresh")
            .status
            .success()
    );
    let requests = client.platform.requests.load(Ordering::SeqCst);
    let path = client.test.workspace().join("forged-launch.json");
    fs::write(
        &path,
        json!({"caps":{"fs":[{"path":"/","access":"read"}]}}).to_string(),
    )
    .expect("local launch specification");
    let output = client
        .test
        .command()
        .env("NONO_TOOL_SANDBOX_LAUNCH_SPEC", &path)
        .output()
        .expect("local specification");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("file-based launch specifications are not accepted")
    );
    for value in ["not-a-descriptor", "-1", "0", "1", "2", "999999"] {
        let output = client
            .test
            .command()
            .env("NONO_TOOL_SANDBOX_LAUNCH_FD", value)
            .output()
            .expect("invalid descriptor");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("command-mediation launch rejected")
        );
    }
    let (_parent, child) = UnixStream::pair().expect("forged handoff");
    let fd = child.as_raw_fd();
    let mut command = client.test.command();
    command.env("NONO_TOOL_SANDBOX_LAUNCH_FD", fd.to_string());
    // SAFETY: child remains open until spawn completes; fcntl is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().expect("forged descriptor");
    assert!(!output.status.success());
    let reason = if cfg!(target_os = "macos") {
        "parent is not the running nono executable"
    } else {
        "external launch descriptors are not accepted"
    };
    assert!(String::from_utf8_lossy(&output.stderr).contains(reason));
    assert_eq!(client.platform.requests.load(Ordering::SeqCst), requests);
}

#[test]
fn enforced_command_mediation_uses_the_delivered_policy() {
    let mut profile = static_profile();
    profile["filesystem"]["allow"] = json!(["$WORKDIR"]);
    profile["command_policies"] = json!({"commands":{"cat":{
        "executable":"/bin/cat",
        "sandbox":{"fs_read":["."]}
    }}});
    let client = Client::new(Some(profile));
    client.platform.mode.store(2, Ordering::SeqCst);
    let file = client.test.workspace().join("mediated.txt");
    fs::write(&file, "PLATFORM_MEDIATED_ACCESS").expect("workspace file");
    client
        .test
        .run()
        .no_rollback()
        .exec(Argv::new("cat").arg(&file))
        .assert_success("platform command policy can launch mediated tools")
        .assert_stdout_contains("PLATFORM_MEDIATED_ACCESS");
    client
        .test
        .run()
        .no_rollback()
        .exec(Argv::new("cat").arg(&client.denied))
        .assert_failure("mediated tools cannot read outside their signed policy")
        .assert_stdout_lacks("UNGRANTED_ACCESS");
}

#[cfg(target_os = "macos")]
#[test]
fn enforced_raw_capability_requests_cannot_fall_back_to_local_approval() {
    let mut profile = static_profile();
    profile["filesystem"]["read_file"] = json!([std::env::current_exe().expect("test executable")]);
    let client = Client::new(Some(profile));
    client.platform.mode.store(2, Ordering::SeqCst);
    let output = client
        .test
        .command()
        .env("ENFORCED_TEST_REQUEST_PATH", &client.denied)
        .args(["run", "--no-rollback", "--"])
        .arg(std::env::current_exe().expect("test executable"))
        .args(["--exact", "raw_capability_request_child", "--nocapture"])
        .output()
        .expect("raw IPC request");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("PLATFORM_APPROVAL_REQUIRED"));
}

#[cfg(target_os = "macos")]
#[test]
fn raw_capability_request_child() {
    use nono::supervisor::{
        ApprovalDecision, CapabilityRequest, SupervisorMessage, SupervisorResponse,
    };
    use std::os::{
        fd::{BorrowedFd, RawFd},
        unix::net::UnixStream,
    };

    let Some(path) = std::env::var_os("ENFORCED_TEST_REQUEST_PATH") else {
        return;
    };
    let fd = (3..256)
        .find(|fd: &RawFd| {
            let mut kind = 0i32;
            let mut size = std::mem::size_of_val(&kind) as nix::libc::socklen_t;
            // SAFETY: getsockopt validates each descriptor and receives a sized output.
            unsafe {
                nix::libc::getsockopt(
                    *fd,
                    nix::libc::SOL_SOCKET,
                    nix::libc::SO_TYPE,
                    (&mut kind as *mut i32).cast(),
                    &mut size,
                ) == 0
                    && kind == nix::libc::SOCK_STREAM
            }
        })
        .expect("inherited supervisor socket");
    // SAFETY: getsockopt identified this live descriptor; clone owns its duplicate.
    let stream = UnixStream::from(
        unsafe { BorrowedFd::borrow_raw(fd) }
            .try_clone_to_owned()
            .expect("duplicate socket"),
    );
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut socket = nono::supervisor::SupervisorSocket::from_stream(stream);
    socket
        .send_message(&SupervisorMessage::Request(CapabilityRequest {
            request_id: "enforced-raw-request".into(),
            path: path.into(),
            access: nono::AccessMode::Read,
            reason: None,
            child_pid: std::process::id(),
            session_id: "raw-request".into(),
        }))
        .expect("request");
    let response = socket.recv_response().expect("response");
    assert!(
        matches!(response, SupervisorResponse::Decision {
        decision: ApprovalDecision::Denied { ref reason }, ..
    } if reason.contains("local approvals are not permitted")),
        "{response:?}"
    );
    println!("PLATFORM_APPROVAL_REQUIRED");
}

#[test]
fn enforced_policy_runs_only_with_signed_grants_and_keeps_audit_attribution() {
    let client = Client::new(Some(static_profile()));
    client.platform.mode.store(2, Ordering::SeqCst);
    client
        .test
        .run()
        .no_rollback()
        .exec(Argv::new("/bin/cat").arg(&client.allowed))
        .assert_success("enforced policy supplies the grant")
        .assert_stdout_contains("ASSIGNED_ACCESS")
        .assert_stderr_contains("Enforced");
    client
        .test
        .run()
        .no_rollback()
        .exec(
            Argv::new("/bin/echo")
                .arg("--profile")
                .arg("child-profile")
                .arg("--allow")
                .arg("/"),
        )
        .assert_success("child arguments do not become nono overrides")
        .assert_stdout_contains("--profile child-profile --allow /");
    client
        .test
        .run()
        .no_rollback()
        .exec(Argv::new("/bin/cat").arg(&client.denied))
        .assert_failure("ungranted file stays denied")
        .assert_stdout_lacks("UNGRANTED_ACCESS");
    let cwd_file = client.test.workspace().join("unassigned-workspace.txt");
    fs::write(&cwd_file, "LOCAL_WORKSPACE_ACCESS").expect("workspace");
    client
        .test
        .run()
        .no_rollback()
        .exec(Argv::new("/bin/cat").arg(&cwd_file))
        .assert_failure("no local workspace grant or prompt")
        .assert_stderr_lacks("Share ")
        .assert_stdout_lacks("LOCAL_WORKSPACE_ACCESS");
    let records = sessions(&client);
    assert!(
        records
            .iter()
            .all(|record| record["policy"]["management_mode"] == "enforced"
                && record["policy"]["policy_source"] == "platform")
    );
}

#[test]
fn enforced_mode_rejects_grants_overrides_audit_reduction_and_environment_inputs() {
    let client = Client::new(Some(static_profile()));
    client.platform.mode.store(2, Ordering::SeqCst);
    for options in [
        vec!["--allow", "/"],
        vec!["--read", "/"],
        vec!["--allow-cwd"],
        vec!["--profile", "default"],
        vec!["--config", "/nonexistent/manifest.json"],
        vec!["--allow-net"],
        vec!["--allow-domain", "example.com"],
        vec!["--allow-endpoint", "github:*:/**"],
        vec!["--credential", "github"],
        vec!["--bypass-protection", "/"],
        vec!["--no-audit"],
        vec!["--no-audit-integrity"],
        vec!["--trust-override"],
        vec!["--skip-dir", "secret"],
        vec!["--capability-elevation"],
    ] {
        let output = client
            .test
            .command()
            .arg("run")
            .args(&options)
            .args(["--", "/bin/echo", "MUST_NOT_RUN"])
            .output()
            .expect("run");
        assert!(!output.status.success(), "{options:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(options[0])
                && stderr.contains("enforced")
                && stderr.contains("Session not started"),
            "{options:?}: {stderr}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("MUST_NOT_RUN"));
    }
    for (name, value) in [
        ("NONO_PROFILE", "default"),
        ("NONO_ALLOW", "/"),
        ("NONO_TRUST_OVERRIDE", "false"),
        ("NONO_CAPABILITY_ELEVATION", "true"),
        ("NONO_PLATFORM_URL", "http://127.0.0.1:1"),
        ("NONO_TENANT", "other"),
        ("NONO_REGISTRY", "http://127.0.0.1:1"),
    ] {
        let output = client
            .test
            .command()
            .env(name, value)
            .args(["run", "--", "/bin/echo", "MUST_NOT_RUN"])
            .output()
            .expect("run");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(name) && stderr.contains("enforced"),
            "{name}: {stderr}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("MUST_NOT_RUN"));
    }
}

#[test]
fn enforced_shell_wrap_and_management_commands_cannot_bypass_assignment() {
    let client = Client::new(Some(static_profile()));
    client.platform.mode.store(2, Ordering::SeqCst);
    for args in [
        vec!["shell", "--profile", "default"],
        vec!["wrap", "--", "/bin/echo", "MUST_NOT_RUN"],
        vec!["wrap", "--dry-run", "--", "/bin/echo", "MUST_NOT_RUN"],
        vec!["proxy", "--no-auth"],
        vec!["setup"],
        vec!["profile", "init", "bypass"],
        vec!["trust", "init"],
        vec!["platform", "unenroll"],
        vec!["platform", "logout"],
        vec!["platform", "login", "--no-enroll"],
        vec!["platform", "tenant", "use", "personal", "--no-enroll"],
    ] {
        let output = client.test.command().args(&args).output().expect("command");
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("enforced"), "{args:?}: {stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("MUST_NOT_RUN"));
        assert!(
            client
                .test
                .home()
                .join(".config/nono/platform.json")
                .exists()
        );
    }
}

#[test]
fn enforced_offline_startup_and_cache_deletion_never_allow_local_override() {
    let mut client = Client::new(Some(static_profile()));
    client.platform.mode.store(2, Ordering::SeqCst);
    let output = client
        .test
        .command()
        .args(["platform", "status", "--refresh"])
        .output()
        .expect("refresh");
    assert!(output.status.success());
    client.platform.refresh_status.store(404, Ordering::SeqCst);
    client
        .test
        .run()
        .profile_name("default")
        .exec(Argv::new("/bin/echo").arg("MUST_NOT_RUN"))
        .assert_failure("HTTP failure never allows local overrides")
        .assert_stdout_lacks("MUST_NOT_RUN");
    client.platform.stop();
    fs::remove_dir_all(client.cache.parent().expect("cache root")).expect("delete cache");
    for command in [client.test.run(), client.test.run().profile_name("default")] {
        command
            .exec(Argv::new("/bin/echo").arg("MUST_NOT_RUN"))
            .assert_failure("remembered enforced mode survives cache deletion")
            .assert_stderr_contains("Session not started")
            .assert_stdout_lacks("MUST_NOT_RUN");
    }
    let output = client
        .test
        .command()
        .args(["platform", "unenroll"])
        .output()
        .expect("unenroll");
    assert!(!output.status.success());
    assert!(
        client
            .test
            .home()
            .join(".config/nono/platform.json")
            .exists()
    );
}

#[test]
fn signed_platform_downgrade_restores_advisory_overrides() {
    let client = Client::new(Some(static_profile()));
    client.platform.mode.store(2, Ordering::SeqCst);
    client
        .test
        .run()
        .no_rollback()
        .exec(Argv::new("/bin/echo").arg("ENFORCED"))
        .assert_success("verified enforced mode");
    client.platform.mode.store(1, Ordering::SeqCst);
    client
        .test
        .run()
        .profile_name("default")
        .no_rollback()
        .exec(Argv::new("/bin/echo").arg("ADVISORY"))
        .assert_success("fresh signed advisory mode allows an override")
        .assert_stderr_contains("Advisory");
}

#[test]
fn enforced_elevation_never_uses_local_or_alternate_approval_backends() {
    for backend in [
        None,
        Some(json!({"type":"terminal"})),
        Some(json!({"type":"webhook", "url":"https://alternate.example/approvals"})),
        Some(
            json!({"type":"webhook", "auth":"platform", "url":"https://alternate.example/api/v1/approvals"}),
        ),
    ] {
        let mut profile = static_profile();
        profile["security"] = json!({"capability_elevation":true});
        if let Some(backend) = backend {
            profile["security"]["approval_backends"] = json!({"reviewer":backend});
            profile["security"]["approval_defaults"] = json!({"backend":"reviewer"});
        }
        let client = Client::new(Some(profile));
        client.platform.mode.store(2, Ordering::SeqCst);
        client
            .test
            .run()
            .exec(Argv::new("/bin/echo").arg("MUST_NOT_RUN"))
            .assert_failure("elevation must use the enrolled platform")
            .assert_stderr_contains("approval backend")
            .assert_stdout_lacks("MUST_NOT_RUN");
    }
}

#[test]
fn enforced_detached_launch_checks_policy_before_local_preflight() {
    let client = Client::new(Some(static_profile()));
    client.platform.mode.store(2, Ordering::SeqCst);
    let output = client
        .test
        .command()
        .args([
            "run",
            "--detached",
            "--profile",
            "nonexistent-profile",
            "--",
            "/bin/sleep",
            "5",
        ])
        .output()
        .expect("detached override");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("enforced") && stderr.contains("--profile"),
        "{stderr}"
    );
    let output = client
        .test
        .command()
        .args([
            "run",
            "--detached",
            "--name",
            "enforced-detached",
            "--no-rollback",
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
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Share "));
    let record = sessions(&client)
        .into_iter()
        .find(|record| record["name"] == "enforced-detached")
        .expect("enforced session");
    assert_eq!(record["policy"]["management_mode"], "enforced");
    assert_eq!(record["policy"]["policy_source"], "platform");
    client
        .test
        .command()
        .arg("stop")
        .arg(record["session_id"].as_str().expect("session id"))
        .output()
        .expect("stop");
}

fn cached_bundle_directory(client: &Client) -> PathBuf {
    walkdir::WalkDir::new(client.cache.with_extension(""))
        .min_depth(2)
        .max_depth(2)
        .into_iter()
        .filter_map(Result::ok)
        .find(|entry| entry.file_type().is_dir())
        .expect("bundle directory")
        .into_path()
}

#[test]
fn recorded_revocation_never_silently_restores_local_startup() {
    for advisory in [true, false] {
        let client = Client::new(advisory.then(static_profile));
        client
            .test
            .wrap()
            .exec(Argv::new("/bin/echo").arg("ONLINE"))
            .assert_success("verified assignment");
        let path = client.test.home().join(".config/nono/platform.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("state")).expect("JSON");
        state["revoked"] = json!(true);
        fs::write(path, state.to_string()).expect("record revocation");
        for command in ["run", "wrap"] {
            for explicit in [false, true] {
                let mut run = client.test.command();
                run.arg(command);
                if explicit {
                    run.args(["--profile", "default"]);
                }
                let output = run
                    .args(["--", "/bin/echo", "MUST_NOT_RUN"])
                    .output()
                    .expect("launch");
                assert!(!output.status.success());
                assert!(!String::from_utf8_lossy(&output.stdout).contains("MUST_NOT_RUN"));
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(
                    error.contains("revoked") && error.contains("Session not started."),
                    "{error}"
                );
            }
        }
    }
}

#[test]
fn explicit_refresh_repairs_cache_only_after_fresh_verification_and_preserves_pin() {
    let client = Client::new(Some(static_profile()));
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/cat").arg(&client.allowed))
        .assert_success("initial bundle");
    let cached: serde_json::Value =
        serde_json::from_slice(&fs::read(&client.cache).expect("cache")).expect("JSON");
    let directory = cached_bundle_directory(&client);
    fs::write(directory.join("policy.json"), "{}").expect("corrupt");
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/echo").arg("MUST_NOT_RUN"))
        .assert_failure("startup never repairs or accepts tampered content")
        .assert_stdout_lacks("MUST_NOT_RUN");
    client
        .platform
        .corrupt_response
        .store(true, Ordering::SeqCst);
    let rejected = client
        .test
        .command()
        .args(["platform", "status", "--refresh"])
        .output()
        .expect("invalid refresh");
    assert!(!rejected.status.success());
    assert_eq!(
        fs::read_to_string(directory.join("policy.json")).expect("still corrupt"),
        "{}"
    );
    client
        .platform
        .corrupt_response
        .store(false, Ordering::SeqCst);
    for damage in ["policy", "extra", "signature", "missing"] {
        match damage {
            "policy" => {}
            "extra" => fs::write(directory.join("unsigned-hook.sh"), "unapproved").expect("extra"),
            "signature" => fs::write(directory.join("bundle.sig"), "{}").expect("signature"),
            _ => fs::remove_file(directory.join("groups.json")).expect("missing"),
        }
        let refreshed = client
            .test
            .command()
            .args(["platform", "status", "--refresh", "--json"])
            .output()
            .expect("repair");
        assert!(
            refreshed.status.success(),
            "{}",
            String::from_utf8_lossy(&refreshed.stderr)
        );
        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(&client.cache).expect("cache")).expect("JSON");
        assert_eq!(repaired["trust_root"], cached["trust_root"]);
        assert!(!directory.join("unsigned-hook.sh").exists());
        client
            .test
            .wrap()
            .exec(Argv::new("/bin/cat").arg(&client.allowed))
            .assert_success("repaired bundle remains platform policy")
            .assert_stdout_contains("ASSIGNED_ACCESS");
    }
}

fn enroll(client: &Client) -> std::process::Output {
    let path = client.test.home().join(".config/nono/platform.json");
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("enrollment")).expect("JSON");
    fs::remove_file(path).expect("clear fixture enrollment");
    fs::remove_file(&client.cache).expect("clear fixture pin");
    client
        .test
        .command()
        .args([
            "platform",
            "enroll",
            "--url",
            state["platform_url"].as_str().expect("URL"),
            "--token",
            "test-token",
            "--keyref",
            state["key_ref"].as_str().expect("key"),
            "--name",
            "Test laptop",
        ])
        .output()
        .expect("enroll")
}

#[test]
fn enrollment_immediately_verifies_and_reports_the_effective_assignment() {
    for advisory in [false, true] {
        let client = Client::new(advisory.then(static_profile));
        let output = enroll(&client);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        for expected in [
            "Device enrolled",
            "Policy verified",
            "Verified and ready",
            if advisory {
                "Advisory"
            } else {
                "Local / audit only"
            },
            if advisory {
                "managed-wrap · revision 1"
            } else {
                "Local profiles"
            },
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert_eq!(client.platform.requests.load(Ordering::SeqCst), 1);
        let output = client
            .test
            .command()
            .args(["platform", "status", "--json"])
            .output()
            .expect("status");
        assert!(output.status.success());
        let status: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(
            status["management_mode"],
            if advisory { "advisory" } else { "audit_only" }
        );
        assert!(status["policy_assignment"].is_object());
        assert_eq!(client.platform.requests.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn failed_enrollment_policy_check_keeps_identity_and_can_be_retried() {
    for invalid_signature in [false, true] {
        let client = Client::new(Some(static_profile()));
        if invalid_signature {
            client
                .platform
                .corrupt_response
                .store(true, Ordering::SeqCst);
        } else {
            client.platform.refresh_status.store(503, Ordering::SeqCst);
        }
        let output = enroll(&client);
        assert!(!output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("Device enrolled") && text.contains("Policy check failed"),
            "{text}"
        );
        assert!(text.contains("Not verified") && !text.contains("Verified and ready"));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("Enrollment remains saved")
                && error.contains("nono platform status --refresh"),
            "{error}"
        );
        assert!(
            error.contains(if invalid_signature {
                "invalid platform policy signature"
            } else {
                "503"
            }),
            "{error}"
        );
        let state: serde_json::Value = serde_json::from_slice(
            &fs::read(client.test.home().join(".config/nono/platform.json"))
                .expect("saved enrollment"),
        )
        .expect("JSON");
        assert!(state.get("last_policy_mode").is_none());
        let cache: serde_json::Value =
            serde_json::from_slice(&fs::read(&client.cache).expect("pin")).expect("JSON");
        assert!(cache["trust_root"].is_object() && cache["response"].is_null());
        client
            .test
            .wrap()
            .exec(Argv::new("/bin/echo").arg("MUST_NOT_RUN"))
            .assert_failure("unverified policy cannot start a session")
            .assert_stdout_lacks("MUST_NOT_RUN");
        client
            .platform
            .corrupt_response
            .store(false, Ordering::SeqCst);
        client.platform.refresh_status.store(200, Ordering::SeqCst);
        let retry = client
            .test
            .command()
            .args(["platform", "status", "--refresh", "--json"])
            .output()
            .expect("retry");
        assert!(
            retry.status.success(),
            "{}",
            String::from_utf8_lossy(&retry.stderr)
        );
        let status: serde_json::Value = serde_json::from_slice(&retry.stdout).expect("JSON");
        assert_eq!(status["subject_id"], state["subject_id"]);
        assert_eq!(status["management_mode"], "advisory");
    }
}

#[test]
fn first_assignment_must_be_verified_before_default_startup() {
    let mut client = Client::new(Some(static_profile()));
    let enrollment = client.test.home().join(".config/nono/platform.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&enrollment).expect("enrollment")).expect("JSON");
    state
        .as_object_mut()
        .expect("object")
        .remove("last_policy_mode");
    fs::write(&enrollment, state.to_string()).expect("new enrollment");
    for status in [404, 503, 0] {
        if status == 0 {
            client.platform.stop();
        } else {
            client
                .platform
                .refresh_status
                .store(status, Ordering::SeqCst);
        }
        for command in ["run", "wrap"] {
            for explicit in [false, true] {
                let mut cmd = client.test.command();
                cmd.arg(command);
                if explicit {
                    cmd.args(["--profile", "default"]);
                }
                let output = cmd
                    .args(["--", "/bin/echo", "MUST_NOT_RUN"])
                    .output()
                    .expect("launch");
                assert!(
                    !output.status.success(),
                    "{command}: HTTP {status}, explicit: {explicit}"
                );
                assert!(!String::from_utf8_lossy(&output.stdout).contains("MUST_NOT_RUN"));
                assert!(String::from_utf8_lossy(&output.stderr).contains("platform policy"));
                assert!(String::from_utf8_lossy(&output.stderr).contains("Session not started."));
            }
        }
    }
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
fn obsolete_cache_versions_cannot_disable_managed_startup() {
    let mut client = Client::new(Some(static_profile()));
    let corrupt = |client: &Client| {
        let mut cache: serde_json::Value =
            serde_json::from_slice(&fs::read(&client.cache).expect("cache")).expect("JSON");
        cache["response"]["payload"] = URL_SAFE_NO_PAD
            .encode(br#"{"protocol_version":"obsolete"}"#)
            .into();
        fs::write(&client.cache, cache.to_string()).expect("obsolete cache");
    };
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/cat").arg(&client.allowed))
        .assert_success("initial bundle");
    corrupt(&client);
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/cat").arg(&client.allowed))
        .assert_success("fresh canonical delivery replaces obsolete cache");
    corrupt(&client);
    client.platform.stop();
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/echo").arg("must not execute"))
        .assert_failure("obsolete cache cannot erase the remembered mode");
}

#[test]
fn file_bundle_delivery_runs_from_a_verified_readable_cache() {
    let client = Client::new(Some(static_profile()));
    for _ in 0..2 {
        client
            .test
            .wrap()
            .exec(Argv::new("/bin/cat").arg(&client.allowed))
            .assert_success("v2 policy grants the assigned file")
            .assert_stdout_contains("ASSIGNED_ACCESS");
    }
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/cat").arg(&client.denied))
        .assert_failure("v2 policy denies ungranted files");
    let cache: serde_json::Value =
        serde_json::from_slice(&fs::read(&client.cache).expect("cache")).expect("JSON");
    assert_eq!(cache["response"]["bundle"]["files"], json!({}));
    let directory = cached_bundle_directory(&client);
    assert!(directory.join("policy.json").is_file());
    fs::write(directory.join("policy.json"), "{}").expect("tamper");
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/cat").arg(&client.allowed))
        .assert_failure("modified cache is rejected before launch")
        .assert_stderr_contains("policy.json")
        .assert_stderr_contains("size differs from the signed inventory")
        .assert_stderr_contains("Session not started.")
        .assert_stdout_lacks("ASSIGNED_ACCESS");
}

#[test]
fn bundle_verification_logs_context_without_policy_contents_or_signatures() {
    let mut profile = static_profile();
    profile["meta"]["description"] = json!("POLICY_CONTENT_SHOULD_NOT_BE_LOGGED");
    let client = Client::new(Some(profile));
    let log = client.test.root().join("verification.log");
    let run = || {
        client
            .test
            .command()
            .env(
                "RUST_LOG",
                "nono::platform_policy=debug,nono::profile::bundle::files=debug",
            )
            .arg("--log-file")
            .arg(&log)
            .args(["wrap", "--", "/bin/echo", "MUST_NOT_RUN_AFTER_TAMPERING"])
            .output()
            .expect("launch")
    };
    assert!(run().status.success());
    let cache: serde_json::Value =
        serde_json::from_slice(&fs::read(&client.cache).expect("cache")).expect("JSON");
    let directory = cached_bundle_directory(&client);
    fs::write(directory.join("policy.json"), "{}").expect("tamper");
    let rejected = run();
    assert!(!rejected.status.success());
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains("MUST_NOT_RUN_AFTER_TAMPERING"));
    let output = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        output.contains("policy.json") && output.contains("Session not started."),
        "{output}"
    );
    let logged = fs::read_to_string(log).expect("log");
    for expected in [
        "Requesting platform policy",
        "Received platform policy response",
        "Verified fresh platform policy assignment",
        "Reading cached platform bundle",
        "Verified platform bundle signature and complete file inventory",
        "Bundle file verification failed",
        "policy.json",
        "Platform policy startup rejected; session not started",
    ] {
        assert!(logged.contains(expected), "missing {expected}: {logged}");
    }
    for secret in [
        "POLICY_CONTENT_SHOULD_NOT_BE_LOGGED",
        cache["response"]["payload"].as_str().expect("payload"),
        cache["response"]["signature"].as_str().expect("signature"),
        cache["response"]["bundle"]["signature"]["dsseEnvelope"]["payload"]
            .as_str()
            .expect("inventory"),
    ] {
        assert!(
            !logged.contains(secret),
            "policy contents or signature leaked to logs"
        );
    }
}

#[test]
fn complete_pack_is_cached_without_wiring_and_every_asset_is_verified() {
    let client = Client::with_pack(Some(static_profile()), true);
    client
        .test
        .wrap()
        .exec(Argv::new("/bin/cat").arg(&client.allowed))
        .assert_success("complete pack delivery")
        .assert_stdout_contains("ASSIGNED_ACCESS");
    let directory = cached_bundle_directory(&client);
    let skill = directory.join("packs/acme/assets/skills/SKILL.md");
    assert_eq!(
        fs::read_to_string(&skill).expect("delivered skill"),
        "# Signed skill\n"
    );
    assert_eq!(
        fs::read_to_string(directory.join("packs/acme/assets/bundle.sig"))
            .expect("upstream signature"),
        "{\"upstream\":\"preserved\"}"
    );
    assert!(!client.test.home().join("SHOULD_NOT_BE_INSTALLED").exists());
    assert!(!client.test.home().join("HOOK_EXECUTED").exists());
    assert_eq!(
        fs::read_to_string(directory.join("packs/acme/assets/bin/hook.sh"))
            .expect("delivered hook"),
        "#!/bin/sh\nprintf '%s\\n' \"$NONO_HOOK_TYPE\" >> \"$HOME/HOOK_EXECUTED\"\n"
    );
    let original: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.join("packs/acme/assets/policy.json")).expect("original pack profile"),
    )
    .expect("pack profile JSON");
    assert_eq!(
        original["session_hooks"]["before"]["script"],
        "$PACK_DIR/bin/hook.sh"
    );
    assert_eq!(
        original["session_hooks"]["after"]["script"],
        "$PACK_DIR/bin/hook.sh"
    );
    assert_eq!(original["hooks"]["claude"]["script"], "bin/hook.sh");
    for relative in [
        "skills/SKILL.md",
        "bin/hook.sh",
        "package.json",
        "policy.json",
    ] {
        let path = directory.join("packs/acme/assets").join(relative);
        let original = fs::read(&path).expect("original asset");
        let mut changed = original.clone();
        changed[0] ^= 1; // Same size: verification must check the digest.
        fs::write(&path, changed).expect("tamper");
        for mode in ["run", "wrap"] {
            let output = client
                .test
                .command()
                .args([mode, "--", "/bin/echo", "MUST_NOT_RUN"])
                .output()
                .expect("tampered startup");
            assert!(!output.status.success(), "{mode}: {relative}");
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains(&format!("packs/acme/assets/{relative}")),
                "{error}"
            );
            assert!(error.contains("Session not started."), "{error}");
            assert!(!String::from_utf8_lossy(&output.stdout).contains("MUST_NOT_RUN"));
            assert!(!client.test.home().join("HOOK_EXECUTED").exists());
            assert!(!client.test.home().join("SHOULD_NOT_BE_INSTALLED").exists());
        }
        fs::write(path, original).expect("restore test asset");
    }
}

#[test]
fn delivered_hooks_stay_inactive_in_run_and_wrap_while_policy_is_enforced() {
    let client = Client::with_pack(Some(static_profile()), true);
    let hook = client
        .test
        .home()
        .join(".config/nono/packages/acme/assets/bin/hook.sh");
    let marker = client.test.home().join("HOOK_EXECUTED");
    let control = client.test.root().join("local-hook-control.json");
    fs::write(
        &control,
        json!({"session_hooks":{
            "before":{"script":hook},"after":{"script":hook}
        }})
        .to_string(),
    )
    .expect("local hook control");
    let output = client
        .test
        .command()
        .args(["run", "--no-diagnostics", "--profile"])
        .arg(&control)
        .args(["--", "/bin/echo", "LOCAL_CONTROL"])
        .output()
        .expect("local hook control");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&marker).expect("local hooks executed"),
        "before\nafter\n"
    );
    fs::remove_file(&marker).expect("clear control marker");

    for mode in ["run", "wrap"] {
        let allowed = client
            .test
            .command()
            .args([mode, "--", "/bin/cat"])
            .arg(&client.allowed)
            .output()
            .expect("managed allowed read");
        assert!(
            allowed.status.success(),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        assert!(String::from_utf8_lossy(&allowed.stdout).contains("ASSIGNED_ACCESS"));
        let denied = client
            .test
            .command()
            .args([mode, "--", "/bin/cat"])
            .arg(&client.denied)
            .output()
            .expect("managed denied read");
        assert!(!denied.status.success());
        assert!(!String::from_utf8_lossy(&denied.stdout).contains("UNGRANTED_ACCESS"));
        assert!(
            !marker.exists(),
            "{mode} must not execute either delivered session hook"
        );
        assert!(!client.test.home().join("SHOULD_NOT_BE_INSTALLED").exists());
        let directory = cached_bundle_directory(&client);
        let sources: serde_json::Value = serde_json::from_slice(
            &fs::read(directory.join("policy.json")).expect("delivered sources"),
        )
        .expect("source JSON");
        assert_eq!(sources["session_hooks"]["before"]["script"], json!(hook));
        assert_eq!(sources["session_hooks"]["after"]["script"], json!(hook));
        assert!(
            directory
                .join("packs/acme/assets/skills/SKILL.md")
                .is_file()
        );
    }
}

#[test]
fn wrap_applies_signed_bundle_and_rejects_tampering_before_execution() {
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
