//! Integration coverage for the CONNECT handler and the real webhook transport.
//! All sockets and signing keys are test-owned; no sandbox or enrollment needed.
#![allow(clippy::unwrap_used)]

use super::*;
use nono_proxy::connect::{ConnectAuthMode, InFlightMap, NetworkApproval, handle_connect};
use nono_proxy::filter::ProxyFilter;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const DEADLINE: Duration = Duration::from_secs(10);

struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: serde_json::Value,
    response: oneshot::Sender<(u16, String)>,
}

impl HttpRequest {
    fn respond(self, status: u16, body: &str) {
        self.response.send((status, body.to_string())).unwrap();
    }

    fn network_id(&self, session_id: &str, port: u16) -> String {
        let request = &self.body["request"];
        assert_eq!(self.method, "POST");
        assert_eq!(request["capability_type"], "network");
        assert_eq!(request["host"], "127.0.0.1");
        assert_eq!(request["port"], port);
        assert_eq!(request["session_id"], session_id);
        let id = request["request_id"].as_str().unwrap();
        let uuid = uuid::Uuid::parse_str(id).unwrap();
        assert_eq!(uuid.get_version_num(), 4);
        assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
        id.to_string()
    }
}

struct WebhookServer {
    url: String,
    requests: mpsc::UnboundedReceiver<HttpRequest>,
    task: JoinHandle<()>,
}

impl WebhookServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/approvals", listener.local_addr().unwrap());
        let (tx, requests) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let tx = tx.clone();
                        connections.spawn(async move {
                            let mut stream = BufReader::new(stream);
                            let mut line = String::new();
                            stream.read_line(&mut line).await.unwrap();
                            let mut parts = line.split_whitespace();
                            let method = parts.next().unwrap().to_string();
                            let path = parts.next().unwrap().to_string();
                            let mut headers = BTreeMap::new();
                            loop {
                                line.clear();
                                stream.read_line(&mut line).await.unwrap();
                                if line == "\r\n" { break; }
                                let (name, value) = line.split_once(':').unwrap();
                                headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                            }
                            let len = headers.get("content-length").map(|s| s.parse::<usize>().unwrap()).unwrap_or(0);
                            assert!(len < 65536);
                            let mut body = vec![0; len];
                            stream.read_exact(&mut body).await.unwrap();
                            let body = if body.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&body).unwrap() };
                            let (response, reply) = oneshot::channel();
                            if tx.send(HttpRequest { method, path, headers, body, response }).is_err() { return; }
                            if let Ok((status, body)) = reply.await {
                                let response = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                                stream.get_mut().write_all(response.as_bytes()).await.unwrap();
                            }
                        });
                    }
                    Some(result) = connections.join_next() => { result.unwrap(); }
                }
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn backend(&self) -> WebhookApproval {
        WebhookApproval {
            name: "test-webhook".to_string(),
            url: self.url.clone(),
            timeout: DEADLINE,
            http: build_agent(DEADLINE),
            platform: None,
            poll_backoff: Duration::ZERO,
        }
    }

    async fn next(&mut self) -> HttpRequest {
        tokio::time::timeout(DEADLINE, self.requests.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

impl Drop for WebhookServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Session {
    backend: Arc<dyn ApprovalBackend>,
    decisions: Mutex<HashMap<(String, u16), bool>>,
    in_flight: InFlightMap,
    id: &'static str,
}

impl Session {
    fn new(backend: Arc<dyn ApprovalBackend>, id: &'static str) -> Self {
        Self {
            backend,
            decisions: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            id,
        }
    }

    async fn connect(&self, port: u16) -> u16 {
        tokio::time::timeout(DEADLINE, async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = async {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                stream
                    .write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                let mut response = String::new();
                BufReader::new(stream)
                    .read_line(&mut response)
                    .await
                    .unwrap();
                response
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse::<u16>()
                    .unwrap()
            };
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let mut blank = String::new();
                stream.read_line(&mut blank).await.unwrap();
                assert_eq!(blank, "\r\n");
                let approval = NetworkApproval {
                    backend: &self.backend,
                    session_decisions: &self.decisions,
                    in_flight: &self.in_flight,
                    session_id: self.id,
                };
                let result = handle_connect(
                    &line,
                    &mut stream.into_inner(),
                    &ProxyFilter::new_strict(&[]),
                    &zeroize::Zeroizing::new("test-token".to_string()),
                    b"",
                    ConnectAuthMode::Disabled,
                    None,
                    Some(&approval),
                )
                .await;
                assert!(
                    matches!(
                        result,
                        Ok(()) | Err(nono_proxy::ProxyError::HostDenied { .. })
                    ),
                    "{result:?}"
                );
            };
            tokio::join!(client, server).0
        })
        .await
        .unwrap()
    }

    async fn wait_for_followers(&self, connections: usize) {
        tokio::time::timeout(DEADLINE, async {
            loop {
                // Map + leader + one Arc per follower. Do not clone in this
                // observer: the count proves every CONNECT is awaiting the
                // same pending webhook before we release its response.
                let ready = self
                    .in_flight
                    .lock()
                    .unwrap()
                    .values()
                    .any(|slot| Arc::strong_count(slot) == connections + 1);
                if ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

struct Upstream {
    port: u16,
    task: JoinHandle<()>,
}

impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream);
            }
        });
        Self { port, task }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn webhook_sequential_once_grants_reconsult_policy_and_use_distinct_ids() {
    let mut webhook = WebhookServer::start().await;
    let session = Session::new(Arc::new(webhook.backend()), "session-a");
    let upstream = Upstream::start().await;
    let mut ids = BTreeSet::new();
    // A later remote revocation must be observed, despite two earlier grants.
    for (decision, expected) in [("allow", 200), ("allow", 200), ("deny", 403)] {
        let respond = async {
            let request = webhook.next().await;
            assert!(ids.insert(request.network_id(session.id, upstream.port)));
            request.respond(200, &format!(r#"{{"decision":"{decision}"}}"#));
        };
        assert_eq!(
            tokio::join!(session.connect(upstream.port), respond).0,
            expected
        );
        assert!(session.decisions.lock().unwrap().is_empty());
        assert!(session.in_flight.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn webhook_concurrent_once_grants_require_one_call_and_id_per_connection() {
    let mut webhook = WebhookServer::start().await;
    let session = Session::new(Arc::new(webhook.backend()), "session-a");
    let upstream = Upstream::start().await;
    let respond = async {
        let mut ids = BTreeSet::new();
        for i in 0..4 {
            let request = webhook.next().await;
            if i == 0 {
                session.wait_for_followers(4).await;
            }
            assert!(ids.insert(request.network_id(session.id, upstream.port)));
            request.respond(200, r#"{"decision":"allow"}"#);
        }
    };
    let (a, b, c, d, ()) = tokio::join!(
        session.connect(upstream.port),
        session.connect(upstream.port),
        session.connect(upstream.port),
        session.connect(upstream.port),
        respond
    );
    assert_eq!([a, b, c, d], [200; 4]);
    assert!(session.decisions.lock().unwrap().is_empty());
    assert!(session.in_flight.lock().unwrap().is_empty());
}

#[tokio::test]
async fn webhook_once_grant_belongs_only_to_its_initiating_connection() {
    let mut webhook = WebhookServer::start().await;
    let session = Session::new(Arc::new(webhook.backend()), "session-a");
    let upstream = Upstream::start().await;
    let mut leader = Box::pin(session.connect(upstream.port));
    // Establish the leader's identity before any follower connects.
    let first = tokio::select! {
        request = webhook.next() => request,
        _ = &mut leader => panic!("leader completed without a webhook decision"),
    };
    let first_id = first.network_id(session.id, upstream.port);
    let respond = async {
        session.wait_for_followers(3).await;
        first.respond(200, r#"{"decision":"allow"}"#);
        let next = webhook.next().await;
        assert_ne!(next.network_id(session.id, upstream.port), first_id);
        // Both original followers must now be waiting on the fresh attempt.
        session.wait_for_followers(2).await;
        next.respond(200, r#"{"decision":"deny"}"#);
    };
    let (leader, a, b, ()) = tokio::join!(
        leader,
        session.connect(upstream.port),
        session.connect(upstream.port),
        respond
    );
    assert_eq!(leader, 200);
    assert_eq!([a, b], [403; 2]);
    assert!(session.decisions.lock().unwrap().is_empty());
    assert!(session.in_flight.lock().unwrap().is_empty());
}

#[tokio::test]
async fn webhook_session_grant_is_shared_and_cached_explicitly() {
    let mut webhook = WebhookServer::start().await;
    let session = Session::new(Arc::new(webhook.backend()), "session-a");
    let upstream = Upstream::start().await;
    let respond = async {
        let request = webhook.next().await;
        session.wait_for_followers(3).await;
        request.network_id(session.id, upstream.port);
        request.respond(200, r#"{"decision":"allow_session"}"#);
    };
    let (a, b, c, ()) = tokio::join!(
        session.connect(upstream.port),
        session.connect(upstream.port),
        session.connect(upstream.port),
        respond
    );
    assert_eq!([a, b, c], [200; 3]);
    assert_eq!(session.connect(upstream.port).await, 200);
    assert!(webhook.requests.try_recv().is_err());
    assert_eq!(
        session
            .decisions
            .lock()
            .unwrap()
            .get(&("127.0.0.1".to_string(), upstream.port)),
        Some(&true)
    );
}

#[tokio::test]
async fn webhook_separate_sessions_for_the_same_target_never_reuse_ids() {
    let mut webhook = WebhookServer::start().await;
    let backend: Arc<dyn ApprovalBackend> = Arc::new(webhook.backend());
    let first = Session::new(Arc::clone(&backend), "session-a");
    let second = Session::new(backend, "session-b");
    let upstream = Upstream::start().await;
    let mut ids = BTreeSet::new();
    for session in [&first, &second] {
        let respond = async {
            let request = webhook.next().await;
            assert!(ids.insert(request.network_id(session.id, upstream.port)));
            request.respond(200, r#"{"decision":"allow_session"}"#);
        };
        assert_eq!(tokio::join!(session.connect(upstream.port), respond).0, 200);
    }
}

struct SessionGrant;

impl ApprovalBackend for SessionGrant {
    fn request_approval(&self, _: &ApprovalRequest) -> Result<ApprovalDecision> {
        Ok(ApprovalDecision::GrantedForSession)
    }
    fn backend_name(&self) -> &str {
        "session"
    }
}

#[tokio::test]
async fn webhook_mixed_all_chain_remains_single_use_in_either_order() {
    let upstream = Upstream::start().await;
    for webhook_first in [true, false] {
        let mut webhook = WebhookServer::start().await;
        let mut children: Vec<Arc<dyn ApprovalBackend>> =
            vec![Arc::new(webhook.backend()), Arc::new(SessionGrant)];
        if !webhook_first {
            children.reverse();
        }
        let session = Session::new(
            Arc::new(ChainApproval {
                name: "all".to_string(),
                mode: ApprovalChainMode::All,
                backends: children,
            }),
            "session-a",
        );
        let mut ids = BTreeSet::new();
        for _ in 0..2 {
            let respond = async {
                let request = webhook.next().await;
                assert!(ids.insert(request.network_id(session.id, upstream.port)));
                request.respond(200, r#"{"decision":"allow"}"#);
            };
            assert_eq!(tokio::join!(session.connect(upstream.port), respond).0, 200);
            assert!(session.decisions.lock().unwrap().is_empty());
        }
    }
}

/// Test-only retrying caller: the production webhook does not automatically
/// retry HTTP errors. A retry of the same attempt must receive the same request.
struct RetryOnce(WebhookApproval);

impl ApprovalBackend for RetryOnce {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        assert!(self.0.request_approval(request)?.is_denied());
        self.0.request_approval(request)
    }
    fn backend_name(&self) -> &str {
        "retry-once"
    }
    fn approval_timeout(&self) -> Option<Duration> {
        Some(DEADLINE * 2)
    }
}

#[tokio::test]
async fn webhook_retry_and_signed_polls_retain_the_attempt_id() {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    use base64::Engine as _;
    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("test-key");
    let key = EcdsaKeyPair::generate_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &aws_lc_rs::rand::SystemRandom::new(),
    )
    .unwrap();
    std::fs::write(
        &key_path,
        base64::engine::general_purpose::STANDARD.encode(key.as_ref()),
    )
    .unwrap();
    let mut webhook = WebhookServer::start().await;
    let mut backend = webhook.backend();
    backend.platform = Some(crate::platform_client::PlatformState {
        protocol_version: "1".to_string(),
        platform_url: webhook.url.clone(),
        tenant_id: "019f0000-0000-7000-8000-000000000001".to_string(),
        subject_id: "019f0000-0000-7000-8000-000000000002".to_string(),
        subject_kind: "workload".to_string(),
        management_mode: "audit_only".to_string(),
        key_algorithm: "ecdsa_p256_sha256_fixed".to_string(),
        key_ref: format!("file://{}", key_path.display()),
        enrolled_at: "2026-09-01T00:00:00Z".to_string(),
    });
    let session = Session::new(Arc::new(RetryOnce(backend)), "session-a");
    let upstream = Upstream::start().await;
    let respond = async {
        let initial = webhook.next().await;
        let id = initial.network_id(session.id, upstream.port);
        let body = initial.body.clone();
        let mut nonces = BTreeSet::new();
        assert!(nonces.insert(initial.headers["x-nono-request-id"].clone()));
        initial.respond(503, r#"{"error":"try again"}"#);
        let retry = webhook.next().await;
        assert_eq!(retry.network_id(session.id, upstream.port), id);
        assert_eq!(retry.body, body);
        assert!(nonces.insert(retry.headers["x-nono-request-id"].clone()));
        retry.respond(202, r#"{"state":"pending"}"#);
        for state in ["pending", "granted"] {
            let poll = webhook.next().await;
            assert_eq!(poll.method, "GET");
            assert_eq!(poll.path, format!("/approvals/{id}"));
            assert!(poll.body.is_null());
            assert!(nonces.insert(poll.headers["x-nono-request-id"].clone()));
            poll.respond(200, &format!(r#"{{"state":"{state}"}}"#));
        }
    };
    assert_eq!(tokio::join!(session.connect(upstream.port), respond).0, 200);
    assert!(session.decisions.lock().unwrap().is_empty());
}
