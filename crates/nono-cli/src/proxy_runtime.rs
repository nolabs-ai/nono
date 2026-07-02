use crate::cli::SandboxArgs;
use crate::command_policy::{
    CommandCredentialGrantConfig, CommandCredentialType, CommandFromConfig, CommandPoliciesConfig,
    CommandSandboxConfig, EndpointPolicyConfig, PolicyDecision, PolicyDecisionConfig,
};
use crate::launch_runtime::{
    CredentialProxyIntent, DomainFilterIntent, EndpointFilterIntent, NetworkIntent, OpenUrlIntent,
    ProxyLaunchOptions, TlsInterceptIntent, UpstreamProxyIntent,
};
use crate::network_policy;
use crate::sandbox_prepare::{PreparedSandbox, validate_external_proxy_bypass};
#[cfg(not(target_os = "macos"))]
use nono::AccessMode;
use nono::{CapabilitySet, NonoError, Result};
use nono_proxy::config::{
    EndpointPolicyConfig as ProxyEndpointPolicyConfig,
    EndpointPolicyDecision as ProxyEndpointPolicyDecision,
    EndpointPolicyDefault as ProxyEndpointPolicyDefault,
    EndpointPolicyRule as ProxyEndpointPolicyRule, InjectMode,
};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

pub(crate) struct ActiveProxyRuntime {
    pub(crate) env_vars: Vec<(String, String)>,
    pub(crate) tool_sandbox_credential_env_vars: BTreeMap<String, Vec<(String, String)>>,
    pub(crate) tool_sandbox_trust_bundle_paths: Vec<std::path::PathBuf>,
    pub(crate) handle: Option<nono_proxy::server::ProxyHandle>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EffectiveProxySettings {
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<crate::profile::AllowDomainEntry>,
    pub(crate) credentials: Vec<String>,
}

#[derive(Debug, Clone)]
struct ResolvedCredentialCaptureEntry {
    command_path: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    ttl: Duration,
    cache_path_regex: Option<Regex>,
    stdin_mode: crate::profile::CredentialCaptureStdinMode,
    output_format: crate::profile::CredentialCaptureOutputFormat,
    allow_headers: HashSet<String>,
    interactive: bool,
    stdio: bool,
    inherit_stdin: bool,
    open_urls: Option<CaptureOpenUrlPolicy>,
    allow_launch_services: bool,
}

#[derive(Debug, Clone)]
struct CaptureOpenUrlPolicy {
    allow_origins: Vec<String>,
    allow_localhost: bool,
}

#[derive(Debug)]
struct CachedCapturedCredential {
    material: nono_proxy::capture::CredentialCaptureMaterial,
    stdout_bytes: usize,
    expires_at: Instant,
}

#[derive(Debug)]
struct CaptureErrorDetails {
    action: &'static str,
    exit_status: Option<i32>,
    duration: Duration,
    stdout_bytes: Option<usize>,
    stderr_redacted: Option<String>,
    reason: Option<String>,
}

impl CaptureErrorDetails {
    fn new(action: &'static str, duration: Duration) -> Self {
        Self {
            action,
            exit_status: None,
            duration,
            stdout_bytes: None,
            stderr_redacted: None,
            reason: None,
        }
    }

    fn exit_status(mut self, exit_status: Option<i32>) -> Self {
        self.exit_status = exit_status;
        self
    }

    fn stdout_bytes(mut self, stdout_bytes: usize) -> Self {
        self.stdout_bytes = Some(stdout_bytes);
        self
    }

    fn stderr_redacted(mut self, stderr_redacted: Option<String>) -> Self {
        self.stderr_redacted = stderr_redacted;
        self
    }

    fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[derive(Debug)]
struct ProxyCredentialCaptureBackend {
    session_id: String,
    entries: HashMap<String, ResolvedCredentialCaptureEntry>,
    cache: Mutex<HashMap<String, CachedCapturedCredential>>,
    active: Mutex<HashSet<String>>,
    active_cv: Condvar,
    redaction_policy: nono::ScrubPolicy,
}

struct ActiveCaptureGuard<'a> {
    active: &'a Mutex<HashSet<String>>,
    active_cv: &'a Condvar,
    key: String,
}

impl Drop for ActiveCaptureGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.key);
            self.active_cv.notify_all();
        }
    }
}

struct CaptureBrowserBridge {
    socket_path: PathBuf,
    shim: CaptureBrowserShim,
    _listener_dir: tempfile::TempDir,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for CaptureBrowserBridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct CaptureBrowserShim {
    dir: tempfile::TempDir,
    launcher: PathBuf,
}

impl ProxyCredentialCaptureBackend {
    fn new(
        entries: &HashMap<String, crate::profile::CredentialCaptureEntry>,
        session_id: String,
    ) -> Result<Self> {
        let mut resolved = HashMap::new();
        for (name, entry) in entries {
            let Some(command) = entry.command.first() else {
                return Err(NonoError::ConfigParse(format!(
                    "credential_capture.{name}.command must not be empty"
                )));
            };
            let command_path = resolve_capture_command(command)?;
            let interaction = entry.interaction.as_ref();
            let open_urls = interaction.and_then(|interaction| {
                interaction
                    .open_urls
                    .as_ref()
                    .map(|open_urls| CaptureOpenUrlPolicy {
                        allow_origins: open_urls.allow_origins.clone(),
                        allow_localhost: open_urls.allow_localhost,
                    })
            });
            let stdio = interaction.is_some_and(|interaction| interaction.stdio);
            let inherit_stdin = interaction.is_some_and(|interaction| interaction.stdin);
            let allow_launch_services =
                interaction.is_some_and(|interaction| interaction.allow_launch_services);
            resolved.insert(
                name.clone(),
                ResolvedCredentialCaptureEntry {
                    command_path,
                    args: entry
                        .command
                        .iter()
                        .skip(1)
                        .map(|a| crate::policy::expand_env_vars(a))
                        .collect(),
                    timeout: Duration::from_secs(entry.timeout_secs.unwrap_or(5)),
                    ttl: Duration::from_secs(
                        entry.cache_ttl_secs.or(entry.ttl_secs).unwrap_or(900),
                    ),
                    cache_path_regex: entry
                        .cache_path_regex
                        .as_deref()
                        .map(Regex::new)
                        .transpose()
                        .map_err(|err| {
                            NonoError::ConfigParse(format!(
                                "credential_capture.{name}.cache_path_regex is invalid: {err}"
                            ))
                        })?,
                    stdin_mode: entry.stdin,
                    output_format: credential_capture_output_format(&entry.output),
                    allow_headers: credential_capture_allow_headers(&entry.output),
                    interactive: stdio || open_urls.is_some() || allow_launch_services,
                    stdio,
                    inherit_stdin,
                    open_urls,
                    allow_launch_services,
                },
            );
        }
        Ok(Self {
            session_id,
            entries: resolved,
            cache: Mutex::new(HashMap::new()),
            active: Mutex::new(HashSet::new()),
            active_cv: Condvar::new(),
            redaction_policy: nono::ScrubPolicy::secure_default(),
        })
    }

    fn capture_cache_scope(
        entry: &ResolvedCredentialCaptureEntry,
        request: &nono_proxy::capture::CredentialCaptureRequest,
    ) -> String {
        if let Some(regex) = &entry.cache_path_regex
            && let Some(captures) = regex.captures(&request.request_path)
            && let Some(scope) = captures.get(1).or_else(|| captures.get(0))
        {
            return scope.as_str().to_string();
        }
        request.request_host.clone()
    }

    fn capture_cache_key(
        request: &nono_proxy::capture::CredentialCaptureRequest,
        cache_scope: &str,
    ) -> String {
        format!(
            "{}\0{}\0{}",
            request.credential_name, request.request_host, cache_scope
        )
    }

    fn try_enter_capture(
        &self,
        key: &str,
    ) -> std::result::Result<Option<ActiveCaptureGuard<'_>>, String> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "credential capture active-set lock poisoned".to_string())?;
        if !active.insert(key.to_string()) {
            return Ok(None);
        }
        Ok(Some(ActiveCaptureGuard {
            active: &self.active,
            active_cv: &self.active_cv,
            key: key.to_string(),
        }))
    }

    fn wait_for_active_capture(&self, key: &str) -> std::result::Result<(), String> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "credential capture active-set lock poisoned".to_string())?;
        while active.contains(key) {
            active = self
                .active_cv
                .wait(active)
                .map_err(|_| "credential capture active-set lock poisoned".to_string())?;
        }
        Ok(())
    }

    fn run_capture_command(
        &self,
        entry: &ResolvedCredentialCaptureEntry,
        request: &nono_proxy::capture::CredentialCaptureRequest,
    ) -> std::result::Result<
        nono_proxy::capture::CredentialCaptureResponse,
        nono_proxy::capture::CredentialCaptureError,
    > {
        let start = Instant::now();
        let mut command = Command::new(&entry.command_path);
        let stdin = match entry.stdin_mode {
            crate::profile::CredentialCaptureStdinMode::Null if entry.inherit_stdin => {
                Stdio::inherit()
            }
            crate::profile::CredentialCaptureStdinMode::Null => Stdio::null(),
            crate::profile::CredentialCaptureStdinMode::RequestJson => Stdio::piped(),
        };
        let stderr = if entry.stdio {
            Stdio::inherit()
        } else {
            Stdio::piped()
        };
        let browser_bridge = prepare_capture_browser_bridge(entry, request).map_err(|err| {
            self.capture_error(
                entry,
                CaptureErrorDetails::new("browser_setup_failed", start.elapsed()).reason(format!(
                    "failed to prepare credential capture browser support: {err}"
                )),
            )
        })?;
        command
            .args(&entry.args)
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(stderr)
            .env("NONO_SESSION_ID", &request.session_id)
            .env("NONO_REQUEST_HOST", &request.request_host)
            .env("NONO_REQUEST_PATH", &request.request_path)
            .env("NONO_REQUEST_METHOD", &request.request_method)
            .env("NONO_CACHE_SCOPE", &request.cache_scope)
            .env("NONO_CAPTURE_CREDENTIAL", &request.credential_name)
            .env("NONO_CAPTURE_ROUTE", &request.route_id);
        if entry.allow_launch_services {
            command.env("NONO_CAPTURE_ALLOW_LAUNCH_SERVICES", "1");
        }
        if let Some(bridge) = browser_bridge.as_ref() {
            command
                .env("NONO_SUPERVISOR_PATH", &bridge.socket_path)
                .env("BROWSER", &bridge.shim.launcher);
            let current_path = std::env::var_os("PATH").unwrap_or_default();
            let mut paths = vec![bridge.shim.dir.path().to_path_buf()];
            paths.extend(std::env::split_paths(&current_path));
            let joined = std::env::join_paths(paths).map_err(|err| {
                self.capture_error(
                    entry,
                    CaptureErrorDetails::new("browser_setup_failed", start.elapsed()).reason(
                        format!("failed to prepare credential capture browser PATH: {err}"),
                    ),
                )
            })?;
            command.env("PATH", joined);
        }
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "NONO_PROXY_TOKEN",
            "NODE_USE_ENV_PROXY",
        ] {
            command.env_remove(name);
        }

        let mut child = command.spawn().map_err(|err| {
            self.capture_error(
                entry,
                CaptureErrorDetails::new("spawn_failed", start.elapsed())
                    .reason(format!("failed to start credential capture command: {err}")),
            )
        })?;
        if entry.stdin_mode == crate::profile::CredentialCaptureStdinMode::RequestJson {
            let stdin_payload = serde_json::json!({
                "session_id": request.session_id,
                "credential_name": request.credential_name,
                "route_id": request.route_id,
                "request_host": request.request_host,
                "request_path": request.request_path,
                "request_method": request.request_method,
                "cache_scope": request.cache_scope,
            });
            if let Some(mut stdin) = child.stdin.take() {
                let bytes = serde_json::to_vec(&stdin_payload).map_err(|err| {
                    self.capture_error(
                        entry,
                        CaptureErrorDetails::new("stdin_failed", start.elapsed()).reason(format!(
                            "failed to serialize credential capture stdin: {err}"
                        )),
                    )
                })?;
                stdin.write_all(&bytes).map_err(|err| {
                    self.capture_error(
                        entry,
                        CaptureErrorDetails::new("stdin_failed", start.elapsed())
                            .reason(format!("failed to write credential capture stdin: {err}")),
                    )
                })?;
            }
        }

        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(err) => {
                    return Err(self.capture_error(
                        entry,
                        CaptureErrorDetails::new("wait_failed", start.elapsed()).reason(format!(
                            "failed to wait for credential capture command: {err}"
                        )),
                    ));
                }
            }
            if start.elapsed() >= entry.timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(self.capture_error(
                    entry,
                    CaptureErrorDetails::new("timeout", start.elapsed()).reason(format!(
                        "credential capture command timed out after {}s",
                        entry.timeout.as_secs()
                    )),
                ));
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        let output = child.wait_with_output().map_err(|err| {
            self.capture_error(
                entry,
                CaptureErrorDetails::new("collect_failed", start.elapsed()).reason(format!(
                    "failed to collect credential capture command output: {err}"
                )),
            )
        })?;
        let status_code = output.status.code();
        if !output.status.success() {
            let stderr_redacted = redacted_stderr(&output.stderr, &self.redaction_policy);
            return Err(self.capture_error(
                entry,
                CaptureErrorDetails::new("command_failed", start.elapsed())
                    .exit_status(status_code)
                    .stderr_redacted(stderr_redacted)
                    .reason(format!(
                        "credential capture command failed with exit code {}",
                        status_code.map_or_else(|| "unknown".to_string(), |code| code.to_string())
                    )),
            ));
        }
        let mut stdout = output.stdout;
        while matches!(stdout.last(), Some(b'\r' | b'\n')) {
            stdout.pop();
        }
        let stdout_bytes = stdout.len();
        if stdout.is_empty() {
            let stderr_redacted = redacted_stderr(&output.stderr, &self.redaction_policy);
            return Err(self.capture_error(
                entry,
                CaptureErrorDetails::new("empty_stdout", start.elapsed())
                    .exit_status(status_code)
                    .stdout_bytes(stdout_bytes)
                    .stderr_redacted(stderr_redacted)
                    .reason("credential capture command produced empty stdout"),
            ));
        }
        let value = String::from_utf8(stdout).map_err(|err| {
            let stderr_redacted = redacted_stderr(&output.stderr, &self.redaction_policy);
            self.capture_error(
                entry,
                CaptureErrorDetails::new("non_utf8_stdout", start.elapsed())
                    .exit_status(status_code)
                    .stderr_redacted(stderr_redacted)
                    .reason(format!(
                        "credential capture command produced non-UTF-8 stdout: {err}"
                    )),
            )
        })?;

        let (material, header_names) = match entry.output_format {
            crate::profile::CredentialCaptureOutputFormat::Text => (
                nono_proxy::capture::CredentialCaptureMaterial::Secret(Zeroizing::new(value)),
                Vec::new(),
            ),
            crate::profile::CredentialCaptureOutputFormat::Json => {
                let headers =
                    parse_capture_headers_json(&value, &entry.allow_headers).map_err(|reason| {
                        self.capture_error(
                            entry,
                            CaptureErrorDetails::new("invalid_json_output", start.elapsed())
                                .exit_status(status_code)
                                .stdout_bytes(stdout_bytes)
                                .reason(reason),
                        )
                    })?;
                let names = headers.iter().map(|(name, _)| name.clone()).collect();
                (
                    nono_proxy::capture::CredentialCaptureMaterial::Headers(headers),
                    names,
                )
            }
        };

        Ok(nono_proxy::capture::CredentialCaptureResponse {
            material,
            metadata: nono_proxy::capture::CredentialCaptureMetadata {
                cache_action: "captured".to_string(),
                command: Some(entry.command_path.to_string_lossy().into_owned()),
                argv: scrub_capture_argv(&entry.args, &self.redaction_policy),
                exit_status: status_code,
                duration_ms: millis_u64(start.elapsed()),
                stdout_bytes: Some(stdout_bytes),
                stderr_redacted: None,
                cache_scope: Some(request.cache_scope.clone()),
                output_format: Some(capture_output_format_name(entry.output_format).to_string()),
                header_names,
                stdin_mode: Some(capture_stdin_mode_name(entry.stdin_mode).to_string()),
                interactive: Some(entry.interactive),
            },
        })
    }

    fn capture_error(
        &self,
        entry: &ResolvedCredentialCaptureEntry,
        details: CaptureErrorDetails,
    ) -> nono_proxy::capture::CredentialCaptureError {
        nono_proxy::capture::CredentialCaptureError::new(
            details
                .reason
                .unwrap_or_else(|| "credential capture failed".to_string()),
            nono_proxy::capture::CredentialCaptureMetadata {
                cache_action: details.action.to_string(),
                command: Some(entry.command_path.to_string_lossy().into_owned()),
                argv: scrub_capture_argv(&entry.args, &self.redaction_policy),
                exit_status: details.exit_status,
                duration_ms: millis_u64(details.duration),
                stdout_bytes: details.stdout_bytes,
                stderr_redacted: details.stderr_redacted,
                cache_scope: None,
                output_format: Some(capture_output_format_name(entry.output_format).to_string()),
                header_names: Vec::new(),
                stdin_mode: Some(capture_stdin_mode_name(entry.stdin_mode).to_string()),
                interactive: Some(entry.interactive),
            },
        )
    }
}

impl nono_proxy::capture::CredentialCaptureBackend for ProxyCredentialCaptureBackend {
    fn capture(
        &self,
        mut request: nono_proxy::capture::CredentialCaptureRequest,
    ) -> std::result::Result<
        nono_proxy::capture::CredentialCaptureResponse,
        nono_proxy::capture::CredentialCaptureError,
    > {
        let Some(entry) = self.entries.get(&request.credential_name) else {
            return Err(nono_proxy::capture::CredentialCaptureError::new(
                format!(
                    "credential capture '{}' is not configured",
                    request.credential_name
                ),
                nono_proxy::capture::CredentialCaptureMetadata {
                    cache_action: "unknown_credential".to_string(),
                    ..Default::default()
                },
            ));
        };
        let cache_scope = Self::capture_cache_scope(entry, &request);
        request.session_id = self.session_id.clone();
        request.cache_scope = cache_scope.clone();
        let key = Self::capture_cache_key(&request, &cache_scope);
        let guard = loop {
            let now = Instant::now();
            {
                let mut cache = self.cache.lock().map_err(|_| {
                    nono_proxy::capture::CredentialCaptureError::new(
                        "credential capture cache lock poisoned".to_string(),
                        nono_proxy::capture::CredentialCaptureMetadata {
                            cache_action: "cache_error".to_string(),
                            ..Default::default()
                        },
                    )
                })?;
                if let Some(cached) = cache.get(&key)
                    && cached.expires_at > now
                {
                    return Ok(nono_proxy::capture::CredentialCaptureResponse {
                        material: cached.material.clone(),
                        metadata: nono_proxy::capture::CredentialCaptureMetadata {
                            cache_action: "cache_hit".to_string(),
                            command: Some(entry.command_path.to_string_lossy().into_owned()),
                            argv: scrub_capture_argv(&entry.args, &self.redaction_policy),
                            exit_status: Some(0),
                            duration_ms: 0,
                            stdout_bytes: Some(cached.stdout_bytes),
                            stderr_redacted: None,
                            cache_scope: Some(cache_scope),
                            output_format: Some(
                                capture_output_format_name(entry.output_format).to_string(),
                            ),
                            header_names: capture_material_header_names(&cached.material),
                            stdin_mode: Some(capture_stdin_mode_name(entry.stdin_mode).to_string()),
                            interactive: Some(entry.interactive),
                        },
                    });
                }
                cache.remove(&key);
            }

            if let Some(guard) = self.try_enter_capture(&key).map_err(|reason| {
                nono_proxy::capture::CredentialCaptureError::new(
                    reason,
                    nono_proxy::capture::CredentialCaptureMetadata {
                        cache_action: "active_set_error".to_string(),
                        command: Some(entry.command_path.to_string_lossy().into_owned()),
                        argv: scrub_capture_argv(&entry.args, &self.redaction_policy),
                        cache_scope: Some(cache_scope.clone()),
                        output_format: Some(
                            capture_output_format_name(entry.output_format).to_string(),
                        ),
                        stdin_mode: Some(capture_stdin_mode_name(entry.stdin_mode).to_string()),
                        interactive: Some(entry.interactive),
                        ..Default::default()
                    },
                )
            })? {
                break guard;
            }

            self.wait_for_active_capture(&key).map_err(|reason| {
                nono_proxy::capture::CredentialCaptureError::new(
                    reason,
                    nono_proxy::capture::CredentialCaptureMetadata {
                        cache_action: "wait_failed".to_string(),
                        command: Some(entry.command_path.to_string_lossy().into_owned()),
                        argv: scrub_capture_argv(&entry.args, &self.redaction_policy),
                        cache_scope: Some(cache_scope.clone()),
                        output_format: Some(
                            capture_output_format_name(entry.output_format).to_string(),
                        ),
                        stdin_mode: Some(capture_stdin_mode_name(entry.stdin_mode).to_string()),
                        interactive: Some(entry.interactive),
                        ..Default::default()
                    },
                )
            })?;
        };
        let response = self
            .run_capture_command(entry, &request)
            .map_err(|mut err| {
                if err.metadata.cache_scope.is_none() {
                    err.metadata.cache_scope = Some(cache_scope.clone());
                }
                err
            })?;
        if !entry.ttl.is_zero() {
            let mut cache = self.cache.lock().map_err(|_| {
                nono_proxy::capture::CredentialCaptureError::new(
                    "credential capture cache lock poisoned".to_string(),
                    nono_proxy::capture::CredentialCaptureMetadata {
                        cache_action: "cache_error".to_string(),
                        ..Default::default()
                    },
                )
            })?;
            cache.insert(
                key,
                CachedCapturedCredential {
                    material: response.material.clone(),
                    stdout_bytes: response.metadata.stdout_bytes.unwrap_or(0),
                    expires_at: Instant::now() + entry.ttl,
                },
            );
        }
        drop(guard);
        Ok(response)
    }
}

fn prepare_capture_browser_bridge(
    entry: &ResolvedCredentialCaptureEntry,
    request: &nono_proxy::capture::CredentialCaptureRequest,
) -> Result<Option<CaptureBrowserBridge>> {
    let Some(policy) = entry.open_urls.clone() else {
        return Ok(None);
    };
    let nono_exe = std::env::current_exe().map_err(|err| {
        NonoError::SandboxInit(format!(
            "failed to locate current executable for credential capture browser helper: {err}"
        ))
    })?;
    let listener_dir = tempfile::Builder::new()
        .prefix("nono-capture-url-sock-")
        .tempdir()
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "failed to create credential capture URL listener directory: {err}"
            ))
        })?;
    let socket_path = listener_dir.path().join("supervisor.sock");
    let listener = nono::supervisor::SupervisorListener::bind(&socket_path)?;
    let shim = create_capture_browser_shim(&nono_exe, &socket_path, entry.allow_launch_services)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let credential_name = request.credential_name.clone();
    let route_id = request.route_id.clone();
    let session_id = request.session_id.clone();
    let thread = std::thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok(Some(mut socket)) => {
                    handle_capture_url_connection(
                        &mut socket,
                        &policy,
                        &credential_name,
                        &route_id,
                        &session_id,
                    );
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                Err(err) => {
                    warn!("credential capture URL listener failed: {err}");
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    });
    Ok(Some(CaptureBrowserBridge {
        socket_path,
        shim,
        _listener_dir: listener_dir,
        stop,
        thread: Some(thread),
    }))
}

fn handle_capture_url_connection(
    socket: &mut nono::supervisor::SupervisorSocket,
    policy: &CaptureOpenUrlPolicy,
    credential_name: &str,
    route_id: &str,
    session_id: &str,
) {
    let msg = match socket.recv_message() {
        Ok(msg) => msg,
        Err(err) => {
            warn!("credential capture URL listener failed to read request: {err}");
            return;
        }
    };
    let nono::supervisor::types::SupervisorMessage::OpenUrl(mut request) = msg else {
        warn!("credential capture URL listener received non-OpenUrl request");
        return;
    };
    if request.session_id.is_empty() {
        request.session_id = session_id.to_string();
    }
    let request_id = request.request_id.clone();
    let (success, error) = match validate_capture_url(&request.url, policy)
        .and_then(|()| open_url_in_browser(&request.url))
    {
        Ok(()) => {
            info!(
                credential = credential_name,
                route = route_id,
                url = %request.url,
                "credential capture opened URL"
            );
            (true, None)
        }
        Err(reason) => {
            warn!(
                credential = credential_name,
                route = route_id,
                url = %request.url,
                reason = %reason,
                "credential capture URL open denied"
            );
            (false, Some(reason))
        }
    };
    let response = nono::supervisor::types::SupervisorResponse::UrlOpened {
        request_id,
        success,
        error,
    };
    if let Err(err) = socket.send_response(&response) {
        warn!("credential capture URL listener failed to send response: {err}");
    }
}

const MAX_CAPTURE_URL_LENGTH: usize = 8192;

fn validate_capture_url(
    url: &str,
    policy: &CaptureOpenUrlPolicy,
) -> std::result::Result<(), String> {
    if url.len() > MAX_CAPTURE_URL_LENGTH {
        return Err(format!(
            "URL exceeds maximum length ({} > {})",
            url.len(),
            MAX_CAPTURE_URL_LENGTH
        ));
    }
    let parsed = url::Url::parse(url).map_err(|err| format!("Invalid URL: {err}"))?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");
    let is_localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if is_localhost {
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "Localhost URL must use http or https scheme, got: {scheme}"
            ));
        }
        if !policy.allow_localhost {
            return Err(
                "Localhost URLs are not allowed by this credential_capture interaction.open_urls policy"
                    .to_string(),
            );
        }
        return Ok(());
    }
    if scheme != "https" {
        return Err(format!(
            "Only https:// URLs are allowed (got {scheme}://). \
             file://, javascript:, data:, and other schemes are blocked."
        ));
    }
    let origin = parsed.origin().unicode_serialization();
    if policy.allow_origins.contains(&origin) {
        Ok(())
    } else {
        Err(format!(
            "Origin {origin} is not in credential_capture interaction.open_urls.allow_origins"
        ))
    }
}

fn open_url_in_browser(url: &str) -> std::result::Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: std::result::Result<std::process::ExitStatus, std::io::Error> =
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "URL opening not supported on this platform",
        ));

    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("Browser opener exited with status: {status}")),
        Err(err) => Err(format!("Failed to launch browser: {err}")),
    }
}

fn create_capture_browser_shim(
    nono_exe: &Path,
    supervisor_socket_path: &Path,
    allow_launch_services: bool,
) -> Result<CaptureBrowserShim> {
    use std::os::unix::fs::PermissionsExt;

    let shim_dir = tempfile::Builder::new()
        .prefix("nono-capture-browser-")
        .tempdir()
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "failed to create credential capture browser shim directory: {err}"
            ))
        })?;
    let shim_dir_path = shim_dir.path();
    let launcher_name = if cfg!(target_os = "macos") {
        "open"
    } else {
        "nono-browser"
    };
    let launcher_path = shim_dir_path.join(launcher_name);
    let quoted_exe = shell_quote(&nono_exe.display().to_string());
    let quoted_socket_path = shell_quote(&supervisor_socket_path.display().to_string());
    let script = if cfg!(target_os = "macos") {
        let non_url_fallback = if allow_launch_services {
            r#"exec /usr/bin/open "$@""#
        } else {
            r#"printf '%s\n' 'nono: credential capture LaunchServices fallback is disabled for this command' >&2
exit 126"#
        };
        format!(
            r#"#!/bin/sh
url_arg=""
for arg in "$@"; do
    case "$arg" in
        http://*|https://*)
            url_arg="$arg"
            break
            ;;
    esac
done

if [ -n "$url_arg" ]; then
    NONO_SUPERVISOR_PATH={quoted_socket_path} exec {quoted_exe} open-url-helper "$url_arg"
else
    {non_url_fallback}
fi
"#
        )
    } else {
        format!(
            r#"#!/bin/sh
NONO_SUPERVISOR_PATH={quoted_socket_path} exec {quoted_exe} open-url-helper "$@"
"#
        )
    };
    std::fs::write(&launcher_path, script).map_err(|err| {
        NonoError::SandboxInit(format!(
            "failed to write credential capture browser shim: {err}"
        ))
    })?;
    std::fs::set_permissions(&launcher_path, std::fs::Permissions::from_mode(0o755)).map_err(
        |err| {
            NonoError::SandboxInit(format!(
                "failed to make credential capture browser shim executable: {err}"
            ))
        },
    )?;
    Ok(CaptureBrowserShim {
        dir: shim_dir,
        launcher: launcher_path,
    })
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn scrub_capture_argv(args: &[String], policy: &nono::ScrubPolicy) -> Vec<String> {
    if args.is_empty() {
        Vec::new()
    } else {
        nono::scrub_argv_with_policy(args, policy)
    }
}

fn credential_capture_output_format(
    output: &crate::profile::CredentialCaptureOutput,
) -> crate::profile::CredentialCaptureOutputFormat {
    match output {
        crate::profile::CredentialCaptureOutput::Format(format) => *format,
        crate::profile::CredentialCaptureOutput::Config(config) => config.format,
    }
}

fn credential_capture_allow_headers(
    output: &crate::profile::CredentialCaptureOutput,
) -> HashSet<String> {
    match output {
        crate::profile::CredentialCaptureOutput::Format(_) => HashSet::new(),
        crate::profile::CredentialCaptureOutput::Config(config) => config
            .allow_headers
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect(),
    }
}

fn capture_output_format_name(
    format: crate::profile::CredentialCaptureOutputFormat,
) -> &'static str {
    match format {
        crate::profile::CredentialCaptureOutputFormat::Text => "text",
        crate::profile::CredentialCaptureOutputFormat::Json => "json",
    }
}

fn capture_stdin_mode_name(mode: crate::profile::CredentialCaptureStdinMode) -> &'static str {
    match mode {
        crate::profile::CredentialCaptureStdinMode::Null => "null",
        crate::profile::CredentialCaptureStdinMode::RequestJson => "request_json",
    }
}

fn capture_material_header_names(
    material: &nono_proxy::capture::CredentialCaptureMaterial,
) -> Vec<String> {
    match material {
        nono_proxy::capture::CredentialCaptureMaterial::Secret(_) => Vec::new(),
        nono_proxy::capture::CredentialCaptureMaterial::Headers(headers) => {
            headers.iter().map(|(name, _)| name.clone()).collect()
        }
    }
}

fn parse_capture_headers_json(
    value: &str,
    allow_headers: &HashSet<String>,
) -> std::result::Result<Vec<(String, Zeroizing<String>)>, String> {
    let parsed: serde_json::Value = serde_json::from_str(value)
        .map_err(|err| format!("credential capture JSON output could not be parsed: {err}"))?;
    let headers = parsed
        .get("headers")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            "credential capture JSON output must include an object field 'headers'".to_string()
        })?;
    if headers.is_empty() {
        return Err("credential capture JSON output headers must not be empty".to_string());
    }

    let mut result = Vec::new();
    for (name, raw_value) in headers {
        let lower = name.to_ascii_lowercase();
        if !is_safe_capture_header_name(name) {
            return Err(format!(
                "credential capture JSON output contains invalid or forbidden header '{name}'"
            ));
        }
        if !allow_headers.contains(&lower) {
            return Err(format!(
                "credential capture JSON output header '{name}' is not in output.allow_headers"
            ));
        }
        let Some(header_value) = raw_value.as_str() else {
            return Err(format!(
                "credential capture JSON output header '{name}' must have a string value"
            ));
        };
        if header_value.is_empty() || header_value.contains('\r') || header_value.contains('\n') {
            return Err(format!(
                "credential capture JSON output header '{name}' has an invalid value"
            ));
        }
        result.push((name.clone(), Zeroizing::new(header_value.to_string())));
    }
    Ok(result)
}

fn is_http_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

fn is_safe_capture_header_name(name: &str) -> bool {
    if name.is_empty() || !name.chars().all(is_http_token_char) {
        return false;
    }
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "upgrade"
            | "te"
            | "trailer"
            | "keep-alive"
    )
}

fn millis_u64(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

fn redacted_stderr(stderr: &[u8], policy: &nono::ScrubPolicy) -> Option<String> {
    if stderr.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(stderr);
    Some(nono::scrub_value_with_policy(&text, policy).into_owned())
}

fn resolve_capture_command(command: &str) -> Result<PathBuf> {
    let expanded = crate::policy::expand_env_vars(command);
    let command = expanded.as_str();
    let path = PathBuf::from(command);
    if path.is_absolute() {
        return validate_capture_command_path(path);
    }
    if command.contains(std::path::MAIN_SEPARATOR) {
        return Err(NonoError::ConfigParse(format!(
            "credential_capture command '{command}' must be an absolute path or bare command name"
        )));
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return Err(NonoError::ConfigParse(format!(
            "credential_capture command '{command}' could not be resolved because PATH is unset"
        )));
    };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(command);
        if candidate.is_file() {
            return validate_capture_command_path(candidate);
        }
    }
    Err(NonoError::ConfigParse(format!(
        "credential_capture command '{command}' was not found in PATH"
    )))
}

fn validate_capture_command_path(path: PathBuf) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .map_err(|source| NonoError::PathCanonicalization {
            path: path.clone(),
            source,
        })?;
    if !canonical.is_file() {
        return Err(NonoError::ExpectedFile(canonical));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = canonical
            .metadata()
            .map_err(NonoError::Io)?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(NonoError::ConfigParse(format!(
                "credential_capture command '{}' is not executable",
                canonical.display()
            )));
        }
    }
    Ok(canonical)
}

pub(crate) fn prepare_proxy_launch_options(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
    silent: bool,
    session_id: String,
) -> Result<NetworkIntent> {
    validate_external_proxy_bypass(args, prepared)?;

    let effective_proxy = resolve_effective_proxy_settings(args, prepared);
    let network_profile = effective_proxy.network_profile;
    let allow_domain = effective_proxy.allow_domain;
    let mut credentials = effective_proxy.credentials;
    let mut custom_credentials = prepared.custom_credentials.clone();
    let mut proxy_source_env_vars = HashMap::new();
    let mut tool_sandbox_base_url_env_vars = HashMap::new();
    let mut tool_sandbox_proxy_credentials = HashSet::new();
    extend_proxy_settings_with_tool_sandbox_credentials(
        prepared.command_policies.as_ref(),
        &mut credentials,
        &mut custom_credentials,
        &mut proxy_source_env_vars,
        &mut tool_sandbox_base_url_env_vars,
        &mut tool_sandbox_proxy_credentials,
    )?;
    let allow_bind_ports = merge_dedup_ports(&prepared.listen_ports, &args.allow_bind);
    let tls_options = resolve_tls_intercept_options(args, prepared)?;

    let upstream_proxy_addr = if args.allow_net {
        None
    } else {
        args.external_proxy
            .clone()
            .or_else(|| prepared.upstream_proxy.clone())
    };

    let upstream_bypass = if args.allow_net {
        Vec::new()
    } else if args.external_proxy.is_some() {
        args.external_proxy_bypass.clone()
    } else {
        let mut bypass = prepared.upstream_bypass.clone();
        bypass.extend(args.external_proxy_bypass.clone());
        bypass
    };

    let has_domain_filter = network_profile.is_some() || !allow_domain.is_empty();
    let has_credentials = !credentials.is_empty();
    let would_activate = has_domain_filter || has_credentials || upstream_proxy_addr.is_some();

    // --block-net always wins; profile network.block yields to any proxy config.
    let block_wins = args.block_net || (prepared.profile_network_block && !would_activate);
    if block_wins {
        if would_activate {
            warn!(
                "--block-net is active; ignoring proxy configuration \
                 that would re-enable network access"
            );
            if !silent {
                eprintln!(
                    "  [nono] Warning: --block-net overrides proxy/credential settings. \
                     Network remains fully blocked."
                );
            }
        }
        return Ok(NetworkIntent::BlockAll);
    }

    // Profile network.block + proxy flags → strict mode: deny unlisted hosts.
    let strict_filter = prepared.profile_network_block;

    let (plain_entries, endpoint_entries): (Vec<_>, Vec<_>) = allow_domain
        .into_iter()
        .partition(|e| !matches!(e, crate::profile::AllowDomainEntry::WithEndpoints { endpoints, .. } if !endpoints.is_empty()));

    let domain_filter = if network_profile.is_some() || !plain_entries.is_empty() {
        Some(DomainFilterIntent {
            network_profile,
            allow_domain: plain_entries,
        })
    } else {
        None
    };

    let endpoint_filter = if !endpoint_entries.is_empty() {
        debug_assert!(
            endpoint_entries
                .iter()
                .all(|e| matches!(e, crate::profile::AllowDomainEntry::WithEndpoints { endpoints, .. } if !endpoints.is_empty())),
            "EndpointFilterIntent invariant violated: all entries must have non-empty endpoints"
        );
        Some(EndpointFilterIntent {
            routes: endpoint_entries,
        })
    } else {
        None
    };

    let endpoint_restrictions = args
        .allow_endpoint
        .iter()
        .map(|s| parse_allow_endpoint_arg(s))
        .collect::<nono::Result<Vec<_>>>()?;

    let credentials_intent =
        if has_credentials || !custom_credentials.is_empty() || !endpoint_restrictions.is_empty() {
            Some(CredentialProxyIntent {
                credentials,
                custom_credentials,
                endpoint_restrictions,
            })
        } else {
            None
        };

    let upstream_proxy = upstream_proxy_addr.map(|address| UpstreamProxyIntent {
        address,
        bypass: upstream_bypass,
    });

    #[cfg(target_os = "macos")]
    let tls_intercept = if tls_options.trust_proxy_ca || tls_options.ca_validity.is_some() {
        Some(TlsInterceptIntent {
            trust_proxy_ca: tls_options.trust_proxy_ca,
            ca_validity: tls_options.ca_validity,
        })
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let tls_intercept = if tls_options.ca_validity.is_some() {
        Some(TlsInterceptIntent {
            ca_validity: tls_options.ca_validity,
        })
    } else {
        None
    };

    let open_url = if !prepared.open_url_origins.is_empty()
        || prepared.open_url_allow_localhost
        || prepared.allow_launch_services_active
    {
        Some(OpenUrlIntent {
            origins: prepared.open_url_origins.clone(),
            allow_localhost: prepared.open_url_allow_localhost,
            allow_launch_services: prepared.allow_launch_services_active,
        })
    } else {
        None
    };

    let opts = ProxyLaunchOptions {
        domain_filter,
        endpoint_filter,
        credentials: credentials_intent,
        upstream_proxy,
        tls_intercept,
        open_url,
        allow_bind_ports,
        proxy_port: args.proxy_port,
        strict_filter,
        proxy_leaf_validity: tls_options.leaf_validity,
        command_policies: prepared.command_policies.clone(),
        proxy_source_env_vars,
        tool_sandbox_base_url_env_vars,
        tool_sandbox_proxy_credentials,
        session_id,
        credential_capture: prepared.credential_capture.clone(),
        enable_h2: prepared.allow_http2_requested,
    };

    // Infra-only flags make no sense without an activating proxy feature.
    if !opts.is_active() {
        if opts.tls_intercept.is_some() {
            return Err(NonoError::ConfigParse(
                "--trust-proxy-ca / --proxy-ca-validity require a proxy feature \
                 (--allow-domain, --credential, or --upstream-proxy)"
                    .to_string(),
            ));
        }
        if args.proxy_port.is_some() {
            return Err(NonoError::ConfigParse(
                "--proxy-port requires a proxy feature (--allow-domain, --credential, \
                 or --upstream-proxy)"
                    .to_string(),
            ));
        }
    }

    Ok(NetworkIntent::ProxyFiltered(Box::new(opts)))
}

struct ResolvedTlsInterceptOptions {
    #[cfg(target_os = "macos")]
    trust_proxy_ca: bool,
    ca_validity: Option<std::time::Duration>,
    leaf_validity: Option<std::time::Duration>,
}

fn resolve_tls_intercept_options(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> Result<ResolvedTlsInterceptOptions> {
    let profile_tls = prepared.tls_intercept.as_ref();
    #[cfg(target_os = "macos")]
    let profile_trusted = profile_tls
        .map(|tls| matches!(tls.ca_lifecycle, crate::profile::TlsCaLifecycle::Trusted))
        .unwrap_or(false);
    #[cfg(target_os = "macos")]
    if args.trust_proxy_ca
        && let Some(tls) = profile_tls
        && tls.ca_lifecycle == crate::profile::TlsCaLifecycle::Session
    {
        return Err(NonoError::ConfigParse(
            "profile requests network.tls_intercept.ca_lifecycle=session but \
             --trust-proxy-ca requests trusted"
                .to_string(),
        ));
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(tls) = profile_tls
        && tls.ca_lifecycle == crate::profile::TlsCaLifecycle::Trusted
    {
        return Err(NonoError::ConfigParse(
            "network.tls_intercept.ca_lifecycle=trusted is currently only supported on macOS"
                .to_string(),
        ));
    }

    let profile_ca_validity = profile_tls
        .and_then(|tls| tls.ca_validity.as_deref())
        .map(|value| crate::profile::parse_tls_duration("network.tls_intercept.ca_validity", value))
        .transpose()?;
    let ca_validity = args
        .proxy_ca_validity
        .map(|days| std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60))
        .or(profile_ca_validity);
    let leaf_validity = profile_tls
        .and_then(|tls| tls.leaf_validity.as_deref())
        .map(|value| {
            crate::profile::parse_tls_duration("network.tls_intercept.leaf_validity", value)
        })
        .transpose()?;

    Ok(ResolvedTlsInterceptOptions {
        #[cfg(target_os = "macos")]
        trust_proxy_ca: args.trust_proxy_ca || profile_trusted,
        ca_validity,
        leaf_validity,
    })
}

pub(crate) fn resolve_effective_proxy_settings(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> EffectiveProxySettings {
    if args.allow_net {
        return EffectiveProxySettings {
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
        };
    }

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| prepared.network_profile.clone());
    let mut allow_domain = prepared.allow_domain.clone();
    allow_domain.extend(args.allow_proxy.iter().map(|s| parse_allow_domain_arg(s)));
    let mut credentials = prepared.credentials.clone();
    credentials.extend(args.proxy_credential.clone());

    EffectiveProxySettings {
        network_profile,
        allow_domain,
        credentials,
    }
}

fn extend_proxy_settings_with_tool_sandbox_credentials(
    config: Option<&CommandPoliciesConfig>,
    credentials: &mut Vec<String>,
    custom_credentials: &mut HashMap<String, crate::profile::CustomCredentialDef>,
    proxy_source_env_vars: &mut HashMap<String, String>,
    base_url_env_vars: &mut HashMap<String, String>,
    tool_sandbox_proxy_credentials: &mut HashSet<String>,
) -> Result<()> {
    let Some(config) = config.filter(|config| config.is_active()) else {
        return Ok(());
    };

    for command in config.commands.values() {
        if let Some(sandbox) = &command.sandbox {
            collect_tool_sandbox_proxy_grants(
                config,
                sandbox,
                credentials,
                custom_credentials,
                proxy_source_env_vars,
                base_url_env_vars,
                tool_sandbox_proxy_credentials,
            )?;
        }
        for from in command.from.values() {
            match from {
                CommandFromConfig::Edge(edge) => collect_tool_sandbox_proxy_grants(
                    config,
                    &edge.sandbox,
                    credentials,
                    custom_credentials,
                    proxy_source_env_vars,
                    base_url_env_vars,
                    tool_sandbox_proxy_credentials,
                )?,
                CommandFromConfig::Policy(sandbox) => collect_tool_sandbox_proxy_grants(
                    config,
                    sandbox,
                    credentials,
                    custom_credentials,
                    proxy_source_env_vars,
                    base_url_env_vars,
                    tool_sandbox_proxy_credentials,
                )?,
                CommandFromConfig::Deny(_) => {}
            }
        }
    }

    Ok(())
}

fn collect_tool_sandbox_proxy_grants(
    config: &CommandPoliciesConfig,
    sandbox: &CommandSandboxConfig,
    credentials: &mut Vec<String>,
    custom_credentials: &mut HashMap<String, crate::profile::CustomCredentialDef>,
    proxy_source_env_vars: &mut HashMap<String, String>,
    base_url_env_vars: &mut HashMap<String, String>,
    tool_sandbox_proxy_credentials: &mut HashSet<String>,
) -> Result<()> {
    for name in &sandbox.use_credentials {
        if config
            .credentials
            .get(name)
            .is_some_and(|credential| credential.credential_type == CommandCredentialType::Proxy)
        {
            return Err(NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{name}' must be granted with sandbox.credentials and endpoint_policy"
            )));
        }
    }

    for grant in &sandbox.credentials {
        let CommandCredentialGrantConfig::Policy(grant) = grant else {
            let CommandCredentialGrantConfig::Name(name) = grant else {
                continue;
            };
            if config.credentials.get(name).is_some_and(|credential| {
                credential.credential_type == CommandCredentialType::Proxy
            }) {
                return Err(NonoError::ConfigParse(format!(
                    "tool-sandbox proxy credential '{name}' must include endpoint_policy"
                )));
            }
            continue;
        };
        let Some(credential) = config.credentials.get(&grant.name) else {
            continue;
        };
        if credential.credential_type != CommandCredentialType::Proxy {
            continue;
        }
        let endpoint_policy = grant.endpoint_policy.as_ref().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{}' requires endpoint_policy",
                grant.name
            ))
        })?;
        validate_endpoint_policy_approval_routes(config, &grant.name, endpoint_policy)?;
        let endpoint_policy = endpoint_policy_to_proxy_policy(config, endpoint_policy);
        let upstream = credential.upstream.clone().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{}' missing upstream",
                grant.name
            ))
        })?;
        let env_var = credential.env_var.clone().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{}' missing env_var",
                grant.name
            ))
        })?;
        nono::validate_destination_env_var(&env_var).map_err(|err| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{}' has invalid env_var: {err}",
                grant.name
            ))
        })?;
        if let Some(base_url_env_var) = &credential.base_url_env_var {
            nono::validate_destination_env_var(base_url_env_var).map_err(|err| {
                NonoError::ConfigParse(format!(
                    "tool-sandbox proxy credential '{}' has invalid base_url_env_var: {err}",
                    grant.name
                ))
            })?;
        }

        let credential_key = if let Some(source) = &credential.source {
            let env_var = proxy_source_env_var(&grant.name);
            let value = load_supervisor_credential_source(source)?;
            proxy_source_env_vars.insert(env_var.clone(), value);
            Some(format!("env://{env_var}"))
        } else {
            credential.credential_key.clone()
        };

        let route = crate::profile::CustomCredentialDef {
            upstream,
            credential_key,
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: credential
                .inject_header
                .clone()
                .unwrap_or_else(|| "Authorization".to_string()),
            credential_format: credential.credential_format.clone(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: Some(env_var),
            endpoint_rules: Vec::new(),
            endpoint_policy: Some(endpoint_policy),
            tls_ca: credential
                .tls_ca
                .as_deref()
                .map(|path| {
                    crate::policy::expand_path(path).map(|path| path.to_string_lossy().into_owned())
                })
                .transpose()?,
            tls_client_cert: credential
                .tls_client_cert
                .as_deref()
                .map(|path| {
                    crate::policy::expand_path(path).map(|path| path.to_string_lossy().into_owned())
                })
                .transpose()?,
            tls_client_key: credential
                .tls_client_key
                .as_deref()
                .map(|path| {
                    crate::policy::expand_path(path).map(|path| path.to_string_lossy().into_owned())
                })
                .transpose()?,
            aws_auth: None,
        };

        if let Some(existing) = custom_credentials.get(&grant.name) {
            if existing != &route {
                return Err(NonoError::ConfigParse(format!(
                    "tool-sandbox proxy credential '{}' has conflicting endpoint policies across command grants",
                    grant.name
                )));
            }
        } else {
            if credentials.iter().any(|name| name == &grant.name) {
                return Err(NonoError::ConfigParse(format!(
                    "tool-sandbox proxy credential '{}' collides with an existing proxy credential route",
                    grant.name
                )));
            }
            custom_credentials.insert(grant.name.clone(), route);
        }
        if !credentials.iter().any(|name| name == &grant.name) {
            credentials.push(grant.name.clone());
        }
        tool_sandbox_proxy_credentials.insert(grant.name.clone());
        if let Some(base_url_env_var) = &credential.base_url_env_var {
            base_url_env_vars.insert(grant.name.clone(), base_url_env_var.clone());
        }
    }
    Ok(())
}

fn proxy_source_env_var(name: &str) -> String {
    let mut out = String::from("NONO_TOOL_SANDBOX_PROXY_CREDENTIAL_");
    for byte in name.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

fn load_supervisor_credential_source(
    source: &crate::command_policy::AmbientCredentialSourceConfig,
) -> Result<String> {
    match source {
        crate::command_policy::AmbientCredentialSourceConfig::Keystore { key } => {
            nono::keystore::load_secret_by_ref(nono::keystore::DEFAULT_SERVICE, key)
                .map(|secret| secret.to_string())
        }
        crate::command_policy::AmbientCredentialSourceConfig::Command {
            command,
            args,
            timeout_secs,
        } => load_command_credential_source(command, args, *timeout_secs),
    }
}

fn load_command_credential_source(
    command: &str,
    args: &[String],
    timeout_secs: Option<u64>,
) -> Result<String> {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(30));
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "failed to start supervisor credential source '{command}': {err}"
            ))
        })?;

    let start = Instant::now();
    loop {
        if let Some(_status) = child.try_wait().map_err(|err| {
            NonoError::SandboxInit(format!(
                "failed to wait for supervisor credential source '{command}': {err}"
            ))
        })? {
            break;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(NonoError::SandboxInit(format!(
                "supervisor credential source '{command}' timed out after {}s",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let output = child.wait_with_output().map_err(|err| {
        NonoError::SandboxInit(format!(
            "failed to collect supervisor credential source '{command}': {err}"
        ))
    })?;
    if !output.status.success() {
        return Err(NonoError::SandboxInit(format!(
            "supervisor credential source '{command}' failed with exit code {}",
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_string(), |code| code.to_string())
        )));
    }
    let value = String::from_utf8(output.stdout).map_err(|err| {
        NonoError::SandboxInit(format!(
            "supervisor credential source '{command}' produced non-UTF-8 stdout: {err}"
        ))
    })?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

struct ScopedEnvVars {
    previous: Vec<(String, Option<std::ffi::OsString>)>,
}

impl ScopedEnvVars {
    #[allow(clippy::disallowed_methods)] // Scoped production wrapper; caller runs before command launch.
    fn set(vars: &HashMap<String, String>) -> Self {
        let mut previous = Vec::new();
        for (name, value) in vars {
            previous.push((name.clone(), std::env::var_os(name)));
            // SAFETY: proxy startup is performed before the sandboxed command is
            // launched. The values are restored immediately after the proxy has
            // loaded its credential store.
            unsafe { std::env::set_var(name, value) };
        }
        Self { previous }
    }
}

#[allow(clippy::disallowed_methods)] // Restores values captured by ScopedEnvVars::set.
impl Drop for ScopedEnvVars {
    fn drop(&mut self) {
        for (name, value) in self.previous.drain(..).rev() {
            match value {
                Some(value) => {
                    // SAFETY: see ScopedEnvVars::set.
                    unsafe { std::env::set_var(name, value) };
                }
                None => {
                    // SAFETY: see ScopedEnvVars::set.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }
    }
}

fn endpoint_policy_to_proxy_policy(
    config: &CommandPoliciesConfig,
    policy: &EndpointPolicyConfig,
) -> ProxyEndpointPolicyConfig {
    ProxyEndpointPolicyConfig {
        default: endpoint_default_to_proxy(config, &policy.default),
        deny: policy
            .deny
            .iter()
            .map(|rule| endpoint_rule_to_proxy(config, rule))
            .collect(),
        approve: policy
            .approve
            .iter()
            .map(|rule| endpoint_rule_to_proxy(config, rule))
            .collect(),
        allow: policy
            .allow
            .iter()
            .map(|rule| endpoint_rule_to_proxy(config, rule))
            .collect(),
    }
}

fn validate_endpoint_policy_approval_routes(
    config: &CommandPoliciesConfig,
    credential_name: &str,
    policy: &EndpointPolicyConfig,
) -> Result<()> {
    if endpoint_decision_is_approve(&policy.default) {
        let backend = default_backend_name(&policy.default);
        validate_endpoint_approval_backend(config, credential_name, backend)?;
    }
    for rule in &policy.approve {
        validate_endpoint_approval_backend(config, credential_name, rule.backend.as_deref())?;
    }
    Ok(())
}

fn endpoint_decision_is_approve(decision: &PolicyDecisionConfig) -> bool {
    match decision {
        PolicyDecisionConfig::Decision(decision) => *decision == PolicyDecision::Approve,
        PolicyDecisionConfig::RoutedApproval(route) => route.decision == PolicyDecision::Approve,
    }
}

fn default_backend_name(default: &PolicyDecisionConfig) -> Option<&str> {
    match default {
        PolicyDecisionConfig::Decision(_) => None,
        PolicyDecisionConfig::RoutedApproval(route) => route.backend.as_deref(),
    }
}

fn validate_endpoint_approval_backend(
    config: &CommandPoliciesConfig,
    credential_name: &str,
    backend: Option<&str>,
) -> Result<()> {
    let backend_name = backend
        .or(config.approval_defaults.backend.as_deref())
        .ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{credential_name}' endpoint_policy approve route requires an approval backend"
            ))
        })?;
    if !config.approval_backends.contains_key(backend_name) {
        return Err(NonoError::ConfigParse(format!(
            "tool-sandbox proxy credential '{credential_name}' endpoint_policy references unknown approval backend '{backend_name}'"
        )));
    };
    Ok(())
}

fn endpoint_default_to_proxy(
    config: &CommandPoliciesConfig,
    default: &PolicyDecisionConfig,
) -> ProxyEndpointPolicyDefault {
    match default {
        PolicyDecisionConfig::Decision(decision) => ProxyEndpointPolicyDefault {
            decision: policy_decision_to_proxy(decision),
            backend: None,
            timeout_secs: config.approval_defaults.timeout_secs,
        },
        PolicyDecisionConfig::RoutedApproval(route) => ProxyEndpointPolicyDefault {
            decision: policy_decision_to_proxy(&route.decision),
            backend: route.backend.clone(),
            timeout_secs: resolve_approval_timeout(
                config,
                route.backend.as_deref(),
                route.timeout_secs,
            ),
        },
    }
}

fn endpoint_rule_to_proxy(
    config: &CommandPoliciesConfig,
    rule: &crate::command_policy::EndpointRuleConfig,
) -> ProxyEndpointPolicyRule {
    ProxyEndpointPolicyRule {
        method: rule.method.clone(),
        path: rule.path.clone(),
        backend: rule.backend.clone(),
        reason: rule.reason.clone(),
        timeout_secs: resolve_approval_timeout(config, rule.backend.as_deref(), rule.timeout_secs),
    }
}

fn resolve_approval_timeout(
    config: &CommandPoliciesConfig,
    backend: Option<&str>,
    explicit_timeout: Option<u64>,
) -> Option<u64> {
    explicit_timeout
        .or_else(|| {
            backend
                .or(config.approval_defaults.backend.as_deref())
                .and_then(|name| config.approval_backends.get(name))
                .and_then(|backend| backend.timeout_secs)
        })
        .or(config.approval_defaults.timeout_secs)
}

fn policy_decision_to_proxy(decision: &PolicyDecision) -> ProxyEndpointPolicyDecision {
    match decision {
        PolicyDecision::Deny => ProxyEndpointPolicyDecision::Deny,
        PolicyDecision::Approve => ProxyEndpointPolicyDecision::Approve,
        PolicyDecision::Allow => ProxyEndpointPolicyDecision::Allow,
    }
}

/// Parse a `--allow-domain` CLI argument into an `AllowDomainEntry`.
///
/// Accepts either:
/// - A plain hostname: `github.com` → `Plain("github.com")`
/// - A URL with a path pattern: `https://github.com/atko-cic/**` →
///   `WithEndpoints { domain: "github.com", endpoints: [{method: "*", path: "/atko-cic/**"}] }`
pub(crate) fn parse_allow_domain_arg(input: &str) -> crate::profile::AllowDomainEntry {
    if let Ok(parsed) = url::Url::parse(input) {
        let domain = parsed.host_str().unwrap_or(input).to_string();
        let path = parsed.path();
        if path.is_empty() || path == "/" {
            crate::profile::AllowDomainEntry::Plain(domain)
        } else {
            crate::profile::AllowDomainEntry::WithEndpoints {
                domain,
                endpoints: vec![nono_proxy::config::EndpointRule {
                    method: "*".to_string(),
                    path: path.to_string(),
                }],
            }
        }
    } else {
        crate::profile::AllowDomainEntry::Plain(input.to_string())
    }
}

pub(crate) fn merge_dedup_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut ports = a.to_vec();
    ports.extend_from_slice(b);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Parse a `--allow-endpoint` CLI argument into a `(service, EndpointRule)` pair.
///
/// Expected format: `SERVICE:METHOD:PATH`
/// Example: `"github:GET:/repos/*/issues"` → `("github", EndpointRule { method: "GET", path: "/repos/*/issues" })`
pub(crate) fn parse_allow_endpoint_arg(
    entry: &str,
) -> nono::Result<(String, nono_proxy::config::EndpointRule)> {
    let err = || {
        nono::NonoError::ConfigParse(format!(
            "--allow-endpoint '{}': expected format SERVICE:METHOD:PATH \
             (e.g., 'github:GET:/repos/*/issues')",
            entry
        ))
    };
    let (service, rest) = entry.split_once(':').ok_or_else(err)?;
    let (method, path) = rest.split_once(':').ok_or_else(err)?;
    if service.is_empty() || method.is_empty() || path.is_empty() {
        return Err(err());
    }
    if !path.starts_with('/') {
        return Err(nono::NonoError::ConfigParse(format!(
            "--allow-endpoint '{}': path pattern must start with '/' \
             (e.g., '/repos/*/issues', not 'repos/*/issues')",
            entry
        )));
    }
    Ok((
        service.to_string(),
        nono_proxy::config::EndpointRule {
            method: method.to_string(),
            path: path.to_string(),
        },
    ))
}

pub(crate) fn build_proxy_config_from_flags(
    proxy: &ProxyLaunchOptions,
) -> Result<nono_proxy::config::ProxyConfig> {
    let net_policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(net_policy_json)?;

    let mut resolved = if let Some(profile_name) = proxy
        .domain_filter
        .as_ref()
        .and_then(|d| d.network_profile.as_ref())
    {
        network_policy::resolve_network_profile(&net_policy, profile_name)?
    } else {
        network_policy::ResolvedNetworkPolicy {
            hosts: Vec::new(),
            suffixes: Vec::new(),
            routes: Vec::new(),
            profile_credentials: Vec::new(),
        }
    };

    let mut all_credentials = resolved.profile_credentials.clone();
    if let Some(ref creds) = proxy.credentials {
        for cred in &creds.credentials {
            if !all_credentials.contains(cred) {
                all_credentials.push(cred.clone());
            }
        }
    }

    let empty_custom_credentials = std::collections::HashMap::new();
    let custom_credentials = proxy
        .credentials
        .as_ref()
        .map(|c| &c.custom_credentials)
        .unwrap_or(&empty_custom_credentials);

    let mut routes =
        network_policy::resolve_credentials(&net_policy, &all_credentials, custom_credentials)?;

    // Apply --allow-endpoint overrides to credential routes.
    // Runs before domain-endpoint routes are merged so the prefix lookup
    // only matches credential routes (never `_ep_*` entries).
    let endpoint_restrictions = proxy
        .credentials
        .as_ref()
        .map(|c| c.endpoint_restrictions.as_slice())
        .unwrap_or(&[]);
    for (service, rule) in endpoint_restrictions {
        let route = routes
            .iter_mut()
            .find(|r| r.prefix == service.as_str())
            .ok_or_else(|| {
                nono::NonoError::ConfigParse(format!(
                    "--allow-endpoint: service '{}' not found in active credentials; \
                     ensure --credential {} is also specified",
                    service, service
                ))
            })?;
        route.endpoint_rules.push(rule.clone());
    }

    let plain_allow_domain = proxy
        .domain_filter
        .as_ref()
        .map(|d| d.allow_domain.as_slice())
        .unwrap_or(&[]);
    let (mut plain_hosts, _) =
        network_policy::partition_allow_domain(&net_policy, plain_allow_domain)?;

    let endpoint_allow_domain = proxy
        .endpoint_filter
        .as_ref()
        .map(|e| e.routes.as_slice())
        .unwrap_or(&[]);
    let (_, endpoint_routes) =
        network_policy::partition_allow_domain(&net_policy, endpoint_allow_domain)?;
    // Endpoint-restricted domains need filter allowlist access so the proxy
    // can reach upstream after TLS interception (h2 checks the filter at
    // connection setup, before per-stream route matching).
    for route in &endpoint_routes {
        if let Some(hp) = route.upstream.strip_prefix("https://") {
            plain_hosts.push(hp.to_string());
        } else if let Some(hp) = route.upstream.strip_prefix("http://") {
            plain_hosts.push(hp.to_string());
        }
    }
    routes.extend(endpoint_routes);
    resolved.routes = routes;

    let mut proxy_config = network_policy::build_proxy_config(&resolved, &plain_hosts);
    proxy_config.strict_filter = proxy.strict_filter;

    if let Some(ref upstream) = proxy.upstream_proxy {
        proxy_config.external_proxy = Some(nono_proxy::config::ExternalProxyConfig {
            address: upstream.address.clone(),
            auth: None,
            bypass_hosts: upstream.bypass.clone(),
        });
    }

    if let Some(port) = proxy.proxy_port {
        proxy_config.bind_port = port;
    }

    proxy_config.ca_validity = proxy.tls_intercept.as_ref().and_then(|t| t.ca_validity);
    proxy_config.leaf_validity = proxy.proxy_leaf_validity;
    proxy_config.enable_h2 = proxy.enable_h2;

    Ok(proxy_config)
}

/// Build the credential-capture backend for a set of `credential_capture`
/// entries, or `None` when no entries are configured.
///
/// Shared by the sandboxed `run` path (`start_proxy_runtime`) and the
/// standalone `nono proxy` command so `cmd://` credential routes resolve
/// identically in both.
pub(crate) fn build_credential_capture_backend(
    credential_capture: &HashMap<String, crate::profile::CredentialCaptureEntry>,
    session_id: String,
) -> Result<Option<Arc<dyn nono_proxy::capture::CredentialCaptureBackend>>> {
    if credential_capture.is_empty() {
        return Ok(None);
    }
    Ok(Some(Arc::new(ProxyCredentialCaptureBackend::new(
        credential_capture,
        session_id,
    )?)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct TokenBrokerNonceResolver(crate::tool_sandbox::token_broker::SharedBroker);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl nono_proxy::NonceResolver for TokenBrokerNonceResolver {
    fn resolve(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.0.lock().ok()?.resolve_nonce(nonce, consumer)
    }
}

/// Wire up TLS interception on a `ProxyConfig`: pick a session-scoped
/// directory for the ephemeral CA bundle, merge any parent `SSL_CERT_FILE`
/// so corporate trust survives our env-var override, and (on macOS) load a
/// preloaded CA when `--trust-proxy-ca` is set.
///
/// Shared by the sandboxed `run` path (`start_proxy_runtime`) and the
/// standalone `nono proxy` command.
pub(crate) fn apply_tls_intercept_config(
    proxy_config: &mut nono_proxy::config::ProxyConfig,
    proxy: &ProxyLaunchOptions,
) -> Result<()> {
    if let Some(dir) = prepare_intercept_ca_dir()? {
        proxy_config.intercept_ca_dir = Some(dir);
        proxy_config.intercept_parent_ca_pems = read_parent_ssl_cert_file();
    }

    #[cfg(target_os = "macos")]
    if proxy
        .tls_intercept
        .as_ref()
        .is_some_and(|t| t.trust_proxy_ca)
    {
        if proxy_config.intercept_ca_dir.is_some() {
            let validity = proxy
                .tls_intercept
                .as_ref()
                .and_then(|t| t.ca_validity)
                .unwrap_or(nono_proxy::tls_intercept::ca::CA_VALIDITY_DEFAULT);
            proxy_config.preloaded_ca = crate::macos_trust::load_or_generate_proxy_ca(validity);
        } else {
            tracing::warn!(
                "--trust-proxy-ca has no effect without TLS-intercepting credential routes"
            );
        }
    }

    // `proxy` is only read on macOS (trust_proxy_ca); silence unused warning
    // on other platforms without dropping the shared signature.
    #[cfg(not(target_os = "macos"))]
    let _ = proxy;

    Ok(())
}

pub(crate) fn start_proxy_runtime(
    intent: &NetworkIntent,
    caps: &mut CapabilitySet,
    #[cfg(any(target_os = "linux", target_os = "macos"))] shared_broker: Option<
        crate::tool_sandbox::token_broker::SharedBroker,
    >,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))] _shared_broker: Option<()>,
) -> Result<ActiveProxyRuntime> {
    let NetworkIntent::ProxyFiltered(proxy) = intent else {
        return Ok(ActiveProxyRuntime {
            env_vars: Vec::new(),
            tool_sandbox_credential_env_vars: BTreeMap::new(),
            tool_sandbox_trust_bundle_paths: Vec::new(),
            handle: None,
        });
    };
    if !proxy.is_active() {
        return Ok(ActiveProxyRuntime {
            env_vars: Vec::new(),
            tool_sandbox_credential_env_vars: BTreeMap::new(),
            tool_sandbox_trust_bundle_paths: Vec::new(),
            handle: None,
        });
    }

    let _source_env_guard = ScopedEnvVars::set(&proxy.proxy_source_env_vars);
    let mut proxy_config = build_proxy_config_from_flags(proxy)?;
    proxy_config.direct_connect_ports = caps.tcp_connect_ports().to_vec();

    apply_tls_intercept_config(&mut proxy_config, proxy)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;
    let approval_registry =
        crate::approval_runtime::build_proxy_approval_registry(proxy.command_policies.as_ref())?;
    let credential_capture_backend =
        build_credential_capture_backend(&proxy.credential_capture, proxy.session_id.clone())?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let nonce_resolver: Option<Arc<dyn nono_proxy::NonceResolver>> = shared_broker
        .map(|b| -> Arc<dyn nono_proxy::NonceResolver> { Arc::new(TokenBrokerNonceResolver(b)) });
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let nonce_resolver: Option<Arc<dyn nono_proxy::NonceResolver>> = None;

    let handle = rt
        .block_on(async {
            nono_proxy::server::start_with_nonce_resolver(
                proxy_config.clone(),
                approval_registry,
                credential_capture_backend,
                nonce_resolver,
            )
            .await
        })
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

    let port = handle.port;
    if proxy.allow_bind_ports.is_empty() {
        info!("Network proxy started on localhost:{}", port);
    } else {
        info!(
            "Network proxy started on localhost:{}, bind ports: {:?}",
            port, proxy.allow_bind_ports
        );
    }

    // Per-route diagnostic banner. Lifts credential resolution status —
    // including misses — to the user-visible info level so the silent
    // "WARN at debug" failure mode (issue #797) becomes immediately
    // discoverable.
    let route_rows = handle.route_diagnostics(&proxy_config);
    if !route_rows.is_empty() {
        info!("Proxy routes:");
        for summary in &route_rows {
            info!("  {}", summary);
        }
        if handle.intercept_ca_path().is_some() {
            info!(
                "TLS interception trust bundle: {}",
                handle
                    .intercept_ca_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
        }
    }

    let proxy_diagnostics = handle.diagnostics();
    if !proxy_diagnostics.is_empty() {
        crate::output::print_proxy_diagnostics(proxy_diagnostics);
    }
    caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
        port,
        bind_ports: proxy.allow_bind_ports.clone(),
    });

    // Grant the sandboxed child a read capability on the ephemeral
    // trust bundle so `SSL_CERT_FILE` etc. are actually openable after
    // the sandbox is applied. Only when interception is active.
    //
    // The bundle lives under `~/.nono/sessions/...`, which the protected-root
    // deny rules (`emit_protected_root_deny_rules`) cover with
    // `(deny file-read-data (subpath "~/.nono"))`. On macOS, action specificity
    // beats path specificity in Seatbelt: a `file-read*` allow on a literal
    // path is shadowed by an action-specific `file-read-data` deny on a
    // containing subpath. To override, emit action-matching `file-read-data`
    // and `file-read-metadata` allows as platform rules, which are appended
    // after the deny and win by both action specificity and last-match.
    //
    // On Linux, Landlock cannot express deny-within-allow, so the protected-
    // root rules don't shadow the grant; a plain FS cap is sufficient.
    let tool_sandbox_trust_bundle_paths = handle
        .intercept_ca_path()
        .map(|path| vec![path.to_path_buf()])
        .unwrap_or_default();

    if let Some(ca_path) = handle.intercept_ca_path() {
        #[cfg(target_os = "macos")]
        {
            let path_str = crate::policy::path_to_utf8(ca_path)?;
            let escaped = crate::policy::escape_seatbelt_path(path_str)?;
            caps.add_platform_rule(format!("(allow file-read-data (literal \"{}\"))", escaped))?;
            caps.add_platform_rule(format!(
                "(allow file-read-metadata (literal \"{}\"))",
                escaped
            ))?;
        }
        #[cfg(not(target_os = "macos"))]
        {
            caps.allow_file_mut(ca_path, AccessMode::Read)
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "Failed to grant read capability on TLS-intercept bundle '{}': {}",
                        ca_path.display(),
                        e
                    ))
                })?;
        }
        debug!(
            "Granted sandboxed child read access to TLS-intercept trust bundle: {}",
            ca_path.display()
        );
    }

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (key, value) in handle.env_vars() {
        env_vars.push((key, value));
    }

    let credential_env_vars = handle.credential_env_vars(&proxy_config);
    let tool_sandbox_credential_env_vars = scoped_tool_sandbox_proxy_credential_env_vars(
        proxy,
        &proxy_config,
        &credential_env_vars,
        port,
    )?;
    let tool_sandbox_env_var_names = tool_sandbox_proxy_env_var_names(proxy, &proxy_config);
    for (key, value) in credential_env_vars {
        if tool_sandbox_env_var_names.contains(&key) {
            continue;
        }
        env_vars.push((key, value));
    }

    std::mem::forget(rt);

    Ok(ActiveProxyRuntime {
        env_vars,
        tool_sandbox_credential_env_vars,
        tool_sandbox_trust_bundle_paths,
        handle: Some(handle),
    })
}

fn tool_sandbox_proxy_env_var_names(
    proxy: &ProxyLaunchOptions,
    proxy_config: &nono_proxy::config::ProxyConfig,
) -> HashSet<String> {
    let mut names = HashSet::new();
    for credential_name in &proxy.tool_sandbox_proxy_credentials {
        let prefix = credential_name.trim_matches('/');
        names.insert(format!("{}_BASE_URL", prefix.to_uppercase()));
        if let Some(base_url_env_var) = proxy.tool_sandbox_base_url_env_vars.get(credential_name) {
            names.insert(base_url_env_var.clone());
        }
        for route in proxy_config
            .routes
            .iter()
            .filter(|route| route.prefix.trim_matches('/') == prefix)
        {
            if let Some(env_var) = &route.env_var {
                names.insert(env_var.clone());
            } else if let Some(credential_key) = &route.credential_key
                && !credential_key.contains("://")
            {
                names.insert(credential_key.to_uppercase());
            }
        }
    }
    names
}

fn scoped_tool_sandbox_proxy_credential_env_vars(
    proxy: &ProxyLaunchOptions,
    proxy_config: &nono_proxy::config::ProxyConfig,
    credential_env_vars: &[(String, String)],
    port: u16,
) -> Result<BTreeMap<String, Vec<(String, String)>>> {
    let mut scoped = BTreeMap::new();
    for credential_name in &proxy.tool_sandbox_proxy_credentials {
        let prefix = credential_name.trim_matches('/');
        let route = proxy_config
            .routes
            .iter()
            .find(|route| route.prefix.trim_matches('/') == prefix)
            .ok_or_else(|| {
                NonoError::SandboxInit(format!(
                    "tool-sandbox proxy credential '{credential_name}' did not produce a proxy route"
                ))
            })?;
        let env_var = route.env_var.as_ref().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{credential_name}' missing env_var"
            ))
        })?;
        let token_value = credential_env_vars
            .iter()
            .find(|(key, _)| key == env_var)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| {
                NonoError::SandboxInit(format!(
                    "tool-sandbox proxy credential '{credential_name}' is unavailable to the proxy"
                ))
            })?;

        let mut env_vars = vec![(env_var.clone(), token_value)];
        if let Some(base_url_env_var) = proxy.tool_sandbox_base_url_env_vars.get(credential_name) {
            env_vars.push((
                base_url_env_var.clone(),
                format!("http://127.0.0.1:{}/{}", port, prefix),
            ));
        }
        scoped.insert(credential_name.clone(), env_vars);
    }
    Ok(scoped)
}

/// Choose the directory the proxy will write the TLS-intercept trust bundle
/// into. Conventionally `$XDG_STATE_HOME/nono/sessions/<random>/`, kept owner-only.
///
/// Returns `Ok(None)` if no `HOME` is set (rare edge cases like CI). We log
/// a warning rather than failing because TLS interception is opt-in: a
/// missing directory just means CONNECTs to L7-bearing routes will get the
/// usual 403, which is a coherent fallback rather than a hard error.
fn prepare_intercept_ca_dir() -> Result<Option<PathBuf>> {
    let dir = match crate::session::ensure_sessions_dir() {
        Ok(base) => base,
        Err(e) => {
            warn!("cannot resolve session registry for TLS-intercept setup: {e}; skipping");
            return Ok(None);
        }
    };
    // PID + start-time-nanos disambiguates concurrent invocations without
    // pulling in a randomness dep. Cryptographic uniqueness isn't the
    // goal; we just need two `nono` processes started at the same second
    // not to share a directory.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let suffix = format!("{}-{:09}", pid, nanos);
    let dir = dir.join(format!("intercept-{suffix}"));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(
            "failed to create TLS-intercept dir '{}': {}; skipping interception",
            dir.display(),
            e
        );
        return Ok(None);
    }
    set_intercept_ca_dir_permissions(&dir)?;
    Ok(Some(dir))
}

#[cfg(unix)]
fn set_intercept_ca_dir_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to set owner-only permissions on TLS-intercept dir '{}': {e}",
            dir.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_intercept_ca_dir_permissions(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Read the parent process's `SSL_CERT_FILE`, if set, so any corporate
/// CAs configured on the host are merged into the intercept trust bundle.
///
/// On any read failure we log at warn and return `None` — the proxy will
/// continue without merging, and the agent may lose trust for corp hosts.
/// Aborting feels too aggressive: nono is opt-in, and TLS interception is
/// opt-in within nono, so a corp-trust mismatch is a recoverable misconfig
/// not a security failure.
fn read_parent_ssl_cert_file() -> Option<Vec<u8>> {
    let path = std::env::var_os("SSL_CERT_FILE")?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            debug!(
                "merging parent SSL_CERT_FILE '{}' ({} bytes) into TLS-intercept trust bundle",
                std::path::Path::new(&path).display(),
                bytes.len()
            );
            Some(bytes)
        }
        Err(e) => {
            warn!(
                "could not read parent SSL_CERT_FILE '{}': {} — corporate CAs configured on \
                 the host will not be trusted by the sandboxed child",
                std::path::Path::new(&path).display(),
                e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_policy::{
        ApprovalBackendConfig, ApprovalBackendType, CommandCredentialConfig,
        CommandCredentialGrantPolicyConfig, CommandPolicyConfig, EndpointRuleConfig,
    };

    // Shared across all tests that dup/dup2 the process's stdin fd, so two such tests
    // never race on fd 0 when cargo runs them concurrently.
    #[cfg(unix)]
    static STDIN_MANIPULATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn set_intercept_ca_dir_permissions_fails_closed() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(NonoError::Io)?;
        let missing = tmp.path().join("missing");

        let err = set_intercept_ca_dir_permissions(&missing)
            .err()
            .ok_or_else(|| {
                NonoError::SandboxInit("expected missing intercept dir to fail".to_string())
            })?;

        assert!(matches!(err, NonoError::SandboxInit(_)));
        assert!(err.to_string().contains("TLS-intercept dir"));
        Ok(())
    }

    #[test]
    fn test_parse_allow_domain_arg_plain_hostname() {
        let entry = parse_allow_domain_arg("github.com");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("github.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_url_with_path() {
        let entry = parse_allow_domain_arg("https://github.com/atko-cic/**");
        match entry {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                assert_eq!(domain, "github.com");
                assert_eq!(endpoints.len(), 1);
                assert_eq!(endpoints[0].method, "*");
                assert_eq!(endpoints[0].path, "/atko-cic/**");
            }
            _ => panic!("expected WithEndpoints, got: {:?}", entry),
        }
    }

    #[test]
    fn test_parse_allow_domain_arg_url_root_is_plain() {
        let entry = parse_allow_domain_arg("https://api.example.com/");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("api.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_url_no_path_is_plain() {
        let entry = parse_allow_domain_arg("https://api.example.com");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("api.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_deep_path() {
        let entry = parse_allow_domain_arg("https://github.com/org/repo/tree/**");
        match entry {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                assert_eq!(domain, "github.com");
                assert_eq!(endpoints[0].path, "/org/repo/tree/**");
            }
            _ => panic!("expected WithEndpoints"),
        }
    }

    /// `strict_filter: true` must propagate to `ProxyConfig.strict_filter`.
    #[test]
    fn test_build_proxy_config_propagates_strict_filter() {
        let proxy = ProxyLaunchOptions {
            strict_filter: true,
            ..ProxyLaunchOptions::default()
        };
        let config = build_proxy_config_from_flags(&proxy).expect("build_proxy_config_from_flags");
        assert!(
            config.strict_filter,
            "strict_filter: true must propagate to ProxyConfig"
        );
    }

    #[test]
    fn test_build_proxy_config_strict_filter_off_by_default() {
        let proxy = ProxyLaunchOptions::default();
        let config = build_proxy_config_from_flags(&proxy).expect("build_proxy_config_from_flags");
        assert!(
            !config.strict_filter,
            "strict_filter must default off when not set"
        );
    }

    /// `{ "domain": "cdn.example.com" }` (no `endpoints` key) deserializes via serde default
    /// to `WithEndpoints { endpoints: [] }`, which is semantically identical to `Plain`.
    /// The partition must route it to `plain_entries` — not `endpoint_entries` — or the
    /// domain silently disappears from the allowlist.
    #[test]
    fn test_object_form_domain_with_no_endpoints_key_is_treated_as_plain() {
        use crate::profile::AllowDomainEntry;

        // Mirrors exactly: { "network": { "allow_domain": [ { "domain": "cdn.example.com" } ] } }
        let entries: Vec<AllowDomainEntry> = serde_json::from_str(r#"[
            "plain.example.com",
            { "domain": "object.example.com" },
            { "domain": "filtered.example.com", "endpoints": [{ "method": "GET", "path": "/v1/**" }] }
        ]"#)
        .expect("deserialize allow_domain entries");

        let (plain, endpoint): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|e| !matches!(e, AllowDomainEntry::WithEndpoints { endpoints, .. } if !endpoints.is_empty()));

        assert_eq!(
            plain.len(),
            2,
            "both Plain and no-endpoints-key object must land in plain bucket"
        );
        assert_eq!(
            endpoint.len(),
            1,
            "only the entry with actual endpoint rules goes to endpoint bucket"
        );

        assert!(
            plain
                .iter()
                .any(|e| matches!(e, AllowDomainEntry::Plain(d) if d == "plain.example.com"))
        );
        assert!(plain.iter().any(|e| matches!(e, AllowDomainEntry::WithEndpoints { domain, .. } if domain == "object.example.com")));
        assert!(endpoint.iter().any(|e| matches!(e, AllowDomainEntry::WithEndpoints { domain, .. } if domain == "filtered.example.com")));
    }

    /// A profile with only `custom_credentials` set (no enabled `credentials`,
    /// no `network_profile`, no `allow_domain`, no upstream proxy) should not
    /// activate the proxy. Custom credential entries are route definitions, not
    /// enabled routes.
    #[test]
    fn test_proxy_is_inactive_when_only_custom_credentials_are_set() {
        use crate::profile::CustomCredentialDef;
        use crate::sandbox_prepare::PreparedSandbox;
        use nono::CapabilitySet;
        use nono_proxy::config::InjectMode;
        use std::collections::HashMap;

        let mut custom_credentials: HashMap<String, CustomCredentialDef> = HashMap::new();
        custom_credentials.insert(
            "mockhttp".to_string(),
            CustomCredentialDef {
                upstream: "https://mockhttp.org".to_string(),
                credential_key: Some("env://MOCK_API_KEY".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some("MOCK_API_KEY".to_string()),
                endpoint_rules: vec![],
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                aws_auth: None,
            },
        );

        let prepared = PreparedSandbox {
            caps: CapabilitySet::new(),
            secrets: Vec::new(),
            profile_display_name: None,
            command_policies: None,
            credential_capture: HashMap::new(),
            tls_intercept: None,
            session_hooks: crate::profile::SessionHooks::default(),
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
            custom_credentials,
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            listen_ports: Vec::new(),
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            #[cfg(target_os = "linux")]
            af_unix_mediation: crate::profile::LinuxAfUnixMediation::Off,
            #[cfg(target_os = "linux")]
            sandbox_policy: crate::profile::LinuxSandboxPolicy::Auto,
            #[cfg(target_os = "linux")]
            explicit_sandbox_policy: None,
            allow_launch_services_active: false,
            allow_gpu_active: false,
            #[cfg(target_os = "linux")]
            proc_comm_notify: false,
            open_url_origins: Vec::new(),
            open_url_allow_localhost: false,
            bypass_protection_paths: Vec::new(),
            ignored_denial_paths: Vec::new(),
            suppressed_system_service_operations: Vec::new(),
            allowed_env_vars: None,
            denied_env_vars: None,
            set_vars: None,
            profile_network_block: false,
            allow_http2_requested: false,
        };

        let args = crate::cli::SandboxArgs::default();
        let intent = prepare_proxy_launch_options(&args, &prepared, true, String::new())
            .expect("prepare_proxy_launch_options");

        assert!(
            !intent.is_proxy_active(),
            "proxy must stay inactive when only custom credential definitions are present"
        );
        let proxy_opts = intent
            .proxy_options()
            .expect("NetworkIntent should be ProxyFiltered when custom credentials are present");
        assert!(
            proxy_opts.credentials.is_some(),
            "custom credential definitions should still be carried for network profile overrides"
        );
    }

    #[test]
    fn tool_sandbox_proxy_credentials_create_endpoint_filtered_route() -> Result<()> {
        let mut policies = CommandPoliciesConfig::default();
        policies.credentials.insert(
            "github-api".to_string(),
            CommandCredentialConfig {
                credential_type: CommandCredentialType::Proxy,
                upstream: Some("https://api.github.com".to_string()),
                credential_key: Some("github-token".to_string()),
                env_var: Some("GITHUB_TOKEN".to_string()),
                base_url_env_var: Some("GITHUB_API_BASE_URL".to_string()),
                inject_header: Some("Authorization".to_string()),
                credential_format: Some("Bearer {}".to_string()),
                tls_ca: Some("/tmp/github-ca.pem".to_string()),
                ..CommandCredentialConfig::default()
            },
        );
        policies.commands.insert(
            "claude".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    credentials: vec![CommandCredentialGrantConfig::Policy(
                        CommandCredentialGrantPolicyConfig {
                            name: "github-api".to_string(),
                            endpoint_policy: Some(EndpointPolicyConfig {
                                default: PolicyDecisionConfig::Decision(PolicyDecision::Deny),
                                allow: vec![EndpointRuleConfig {
                                    method: "GET".to_string(),
                                    path: "/repos/example/**".to_string(),
                                    backend: None,
                                    reason: None,
                                    timeout_secs: None,
                                }],
                                ..EndpointPolicyConfig::default()
                            }),
                        },
                    )],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );

        let mut credentials = Vec::new();
        let mut custom_credentials = HashMap::new();
        let mut proxy_source_env_vars = HashMap::new();
        let mut base_url_env_vars = HashMap::new();
        let mut tool_sandbox_proxy_credentials = HashSet::new();
        extend_proxy_settings_with_tool_sandbox_credentials(
            Some(&policies),
            &mut credentials,
            &mut custom_credentials,
            &mut proxy_source_env_vars,
            &mut base_url_env_vars,
            &mut tool_sandbox_proxy_credentials,
        )?;

        assert_eq!(credentials, vec!["github-api".to_string()]);
        assert!(tool_sandbox_proxy_credentials.contains("github-api"));
        assert_eq!(
            base_url_env_vars.get("github-api"),
            Some(&"GITHUB_API_BASE_URL".to_string())
        );
        let route = custom_credentials
            .get("github-api")
            .ok_or_else(|| NonoError::ConfigParse("missing github-api route".to_string()))?;
        assert_eq!(route.upstream, "https://api.github.com");
        assert_eq!(route.credential_key, Some("github-token".to_string()));
        assert_eq!(route.env_var, Some("GITHUB_TOKEN".to_string()));
        assert_eq!(route.tls_ca, Some("/tmp/github-ca.pem".to_string()));
        assert!(route.endpoint_rules.is_empty());
        let endpoint_policy = route
            .endpoint_policy
            .as_ref()
            .ok_or_else(|| NonoError::ConfigParse("missing endpoint policy".to_string()))?;
        assert_eq!(endpoint_policy.allow.len(), 1);
        assert_eq!(endpoint_policy.allow[0].method, "GET");
        assert_eq!(endpoint_policy.allow[0].path, "/repos/example/**");

        Ok(())
    }

    #[test]
    fn tool_sandbox_proxy_credentials_require_policy_grants() -> Result<()> {
        let mut policies = CommandPoliciesConfig::default();
        policies.credentials.insert(
            "github-api".to_string(),
            CommandCredentialConfig {
                credential_type: CommandCredentialType::Proxy,
                upstream: Some("https://api.github.com".to_string()),
                env_var: Some("GITHUB_TOKEN".to_string()),
                ..CommandCredentialConfig::default()
            },
        );
        policies.commands.insert(
            "claude".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    credentials: vec![CommandCredentialGrantConfig::Name("github-api".to_string())],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );

        let mut credentials = Vec::new();
        let mut custom_credentials = HashMap::new();
        let mut proxy_source_env_vars = HashMap::new();
        let mut base_url_env_vars = HashMap::new();
        let mut tool_sandbox_proxy_credentials = HashSet::new();
        let err = extend_proxy_settings_with_tool_sandbox_credentials(
            Some(&policies),
            &mut credentials,
            &mut custom_credentials,
            &mut proxy_source_env_vars,
            &mut base_url_env_vars,
            &mut tool_sandbox_proxy_credentials,
        )
        .err()
        .ok_or_else(|| NonoError::ConfigParse("expected proxy grant failure".to_string()))?;

        assert!(err.to_string().contains("must include endpoint_policy"));
        Ok(())
    }

    #[test]
    fn tool_sandbox_proxy_endpoint_policy_preserves_deny_and_approve_routes() {
        let policy = EndpointPolicyConfig {
            default: PolicyDecisionConfig::Decision(PolicyDecision::Deny),
            deny: vec![EndpointRuleConfig {
                method: "DELETE".to_string(),
                path: "/repos/example/**".to_string(),
                backend: None,
                reason: Some("destructive endpoint".to_string()),
                timeout_secs: None,
            }],
            approve: vec![EndpointRuleConfig {
                method: "POST".to_string(),
                path: "/repos/example/*/issues".to_string(),
                backend: Some("terminal".to_string()),
                reason: None,
                timeout_secs: None,
            }],
            allow: vec![EndpointRuleConfig {
                method: "GET".to_string(),
                path: "/repos/example/**".to_string(),
                backend: None,
                reason: None,
                timeout_secs: None,
            }],
        };

        let proxy_policy =
            endpoint_policy_to_proxy_policy(&CommandPoliciesConfig::default(), &policy);

        assert_eq!(proxy_policy.deny.len(), 1);
        assert_eq!(proxy_policy.deny[0].method, "DELETE");
        assert_eq!(proxy_policy.approve.len(), 1);
        assert_eq!(proxy_policy.approve[0].method, "POST");
        assert_eq!(
            proxy_policy.approve[0].backend,
            Some("terminal".to_string())
        );
        assert_eq!(proxy_policy.allow.len(), 1);
    }

    #[test]
    fn tool_sandbox_proxy_approve_routes_accept_configured_backend() -> Result<()> {
        let mut policies = CommandPoliciesConfig::default();
        policies.approval_defaults.backend = Some("security-review".to_string());
        policies.approval_backends.insert(
            "security-review".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Webhook,
                url: Some("https://approvals.internal.example/tool_sandbox".to_string()),
                timeout_secs: Some(10),
                mode: None,
                backends: Vec::new(),
            },
        );
        policies.credentials.insert(
            "internal-api".to_string(),
            CommandCredentialConfig {
                credential_type: CommandCredentialType::Proxy,
                upstream: Some("https://api.internal.example".to_string()),
                credential_key: Some("internal-token".to_string()),
                env_var: Some("INTERNAL_API_TOKEN".to_string()),
                ..CommandCredentialConfig::default()
            },
        );
        policies.commands.insert(
            "claude".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    credentials: vec![CommandCredentialGrantConfig::Policy(
                        CommandCredentialGrantPolicyConfig {
                            name: "internal-api".to_string(),
                            endpoint_policy: Some(EndpointPolicyConfig {
                                approve: vec![EndpointRuleConfig {
                                    method: "POST".to_string(),
                                    path: "/v1/tasks/*/comments".to_string(),
                                    backend: None,
                                    reason: Some("comment write".to_string()),
                                    timeout_secs: Some(5),
                                }],
                                ..EndpointPolicyConfig::default()
                            }),
                        },
                    )],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );

        let mut credentials = Vec::new();
        let mut custom_credentials = HashMap::new();
        let mut proxy_source_env_vars = HashMap::new();
        let mut base_url_env_vars = HashMap::new();
        let mut tool_sandbox_proxy_credentials = HashSet::new();
        extend_proxy_settings_with_tool_sandbox_credentials(
            Some(&policies),
            &mut credentials,
            &mut custom_credentials,
            &mut proxy_source_env_vars,
            &mut base_url_env_vars,
            &mut tool_sandbox_proxy_credentials,
        )?;

        let route = custom_credentials
            .get("internal-api")
            .ok_or_else(|| NonoError::ConfigParse("missing internal-api route".to_string()))?;
        let endpoint_policy = route
            .endpoint_policy
            .as_ref()
            .ok_or_else(|| NonoError::ConfigParse("missing endpoint policy".to_string()))?;
        assert_eq!(endpoint_policy.approve.len(), 1);
        assert_eq!(endpoint_policy.approve[0].timeout_secs, Some(5));

        Ok(())
    }

    #[test]
    fn tool_sandbox_proxy_env_vars_are_scoped_out_of_global_env() -> Result<()> {
        let mut proxy = ProxyLaunchOptions::default();
        proxy
            .tool_sandbox_proxy_credentials
            .insert("github-api".to_string());
        proxy
            .tool_sandbox_base_url_env_vars
            .insert("github-api".to_string(), "GITHUB_API_BASE_URL".to_string());

        let mut proxy_config = nono_proxy::config::ProxyConfig::default();
        proxy_config.routes.push(nono_proxy::config::RouteConfig {
            prefix: "github-api".to_string(),
            upstream: "https://api.github.com".to_string(),
            credential_key: Some("github-token".to_string()),
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: Some("GITHUB_TOKEN".to_string()),
            endpoint_rules: Vec::new(),
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
        });
        let credential_env_vars = vec![
            (
                "GITHUB-API_BASE_URL".to_string(),
                "http://127.0.0.1:7777/github-api".to_string(),
            ),
            ("GITHUB_TOKEN".to_string(), "phantom-token".to_string()),
        ];

        let scoped = scoped_tool_sandbox_proxy_credential_env_vars(
            &proxy,
            &proxy_config,
            &credential_env_vars,
            7777,
        )?;
        let env_names = tool_sandbox_proxy_env_var_names(&proxy, &proxy_config);

        assert!(env_names.contains("GITHUB-API_BASE_URL"));
        assert!(env_names.contains("GITHUB_API_BASE_URL"));
        assert!(env_names.contains("GITHUB_TOKEN"));
        assert_eq!(
            scoped.get("github-api"),
            Some(&vec![
                ("GITHUB_TOKEN".to_string(), "phantom-token".to_string()),
                (
                    "GITHUB_API_BASE_URL".to_string(),
                    "http://127.0.0.1:7777/github-api".to_string()
                ),
            ])
        );
        Ok(())
    }

    #[test]
    fn proxy_credential_capture_backend_captures_and_caches() -> Result<()> {
        let mut entries = HashMap::new();
        entries.insert(
            "github".to_string(),
            test_capture_entry(vec!["/bin/echo".to_string(), "ghp_test".to_string()]),
        );
        let backend = ProxyCredentialCaptureBackend::new(&entries, "sess-test".to_string())?;
        let request = nono_proxy::capture::CredentialCaptureRequest {
            credential_name: "github".to_string(),
            route_id: "github".to_string(),
            request_host: "api.github.com".to_string(),
            request_path: "/repos/nolabs-ai/nono/issues/787".to_string(),
            request_method: "GET".to_string(),
            session_id: String::new(),
            cache_scope: String::new(),
        };

        let first =
            nono_proxy::capture::CredentialCaptureBackend::capture(&backend, request.clone())
                .map_err(|err| NonoError::SandboxInit(err.to_string()))?;
        assert_capture_secret(&first, "ghp_test");
        assert_eq!(first.metadata.cache_action, "captured");
        assert_eq!(first.metadata.stdout_bytes, Some("ghp_test".len()));
        assert_eq!(
            first.metadata.cache_scope.as_deref(),
            Some("api.github.com")
        );

        let second = nono_proxy::capture::CredentialCaptureBackend::capture(&backend, request)
            .map_err(|err| NonoError::SandboxInit(err.to_string()))?;
        assert_capture_secret(&second, "ghp_test");
        assert_eq!(second.metadata.cache_action, "cache_hit");
        Ok(())
    }

    #[test]
    fn proxy_credential_capture_backend_waits_for_inflight_capture() -> Result<()> {
        let temp = tempfile::tempdir().map_err(NonoError::Io)?;
        let counter_path = temp.path().join("capture-count");
        let mut entries = HashMap::new();
        entries.insert(
            "github".to_string(),
            test_capture_entry(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf x >> \"$1\"; sleep 0.2; printf ghp_parallel".to_string(),
                "sh".to_string(),
                counter_path.to_string_lossy().into_owned(),
            ]),
        );
        let backend = std::sync::Arc::new(ProxyCredentialCaptureBackend::new(
            &entries,
            "sess-parallel".to_string(),
        )?);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let backend = std::sync::Arc::clone(&backend);
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let request = nono_proxy::capture::CredentialCaptureRequest {
                    credential_name: "github".to_string(),
                    route_id: "github".to_string(),
                    request_host: "api.github.com".to_string(),
                    request_path: "/repos/nolabs-ai/nono/issues/787".to_string(),
                    request_method: "GET".to_string(),
                    session_id: String::new(),
                    cache_scope: String::new(),
                };
                barrier.wait();
                let response = nono_proxy::capture::CredentialCaptureBackend::capture(
                    backend.as_ref(),
                    request,
                )
                .map_err(|err| err.to_string())?;
                Ok::<_, String>((
                    capture_secret(&response).to_string(),
                    response.metadata.cache_action,
                ))
            }));
        }
        barrier.wait();

        let mut actions = Vec::new();
        for handle in handles {
            let (secret, action) = handle
                .join()
                .map_err(|_| NonoError::SandboxInit("capture thread panicked".to_string()))?
                .map_err(NonoError::SandboxInit)?;
            assert_eq!(secret, "ghp_parallel");
            actions.push(action);
        }
        actions.sort();
        assert_eq!(
            actions,
            vec!["cache_hit".to_string(), "captured".to_string()]
        );
        let counter = std::fs::read_to_string(&counter_path).map_err(NonoError::Io)?;
        assert_eq!(counter, "x");
        Ok(())
    }

    #[test]
    fn proxy_credential_capture_backend_rejects_empty_stdout() -> Result<()> {
        let mut entries = HashMap::new();
        entries.insert(
            "empty".to_string(),
            test_capture_entry_no_cache(vec!["/bin/echo".to_string()]),
        );
        let backend = ProxyCredentialCaptureBackend::new(&entries, "sess-test".to_string())?;
        let request = nono_proxy::capture::CredentialCaptureRequest {
            credential_name: "empty".to_string(),
            route_id: "empty".to_string(),
            request_host: "api.example.com".to_string(),
            request_path: "/".to_string(),
            request_method: "GET".to_string(),
            session_id: String::new(),
            cache_scope: String::new(),
        };

        let err = nono_proxy::capture::CredentialCaptureBackend::capture(&backend, request)
            .expect_err("empty stdout should not produce a credential");
        assert_eq!(err.metadata.cache_action, "empty_stdout");
        assert_eq!(err.metadata.stdout_bytes, Some(0));
        Ok(())
    }

    #[test]
    fn proxy_credential_capture_backend_audits_redacted_stderr() -> Result<()> {
        let mut entries = HashMap::new();
        entries.insert(
            "github".to_string(),
            test_capture_entry_no_cache(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf 'Authorization: Bearer ghp_secret\\n' >&2; exit 7".to_string(),
            ]),
        );
        let backend = ProxyCredentialCaptureBackend::new(&entries, "sess-test".to_string())?;
        let request = nono_proxy::capture::CredentialCaptureRequest {
            credential_name: "github".to_string(),
            route_id: "github".to_string(),
            request_host: "api.github.com".to_string(),
            request_path: "/".to_string(),
            request_method: "GET".to_string(),
            session_id: String::new(),
            cache_scope: String::new(),
        };

        let err = nono_proxy::capture::CredentialCaptureBackend::capture(&backend, request)
            .expect_err("non-zero command should fail");
        assert_eq!(err.metadata.cache_action, "command_failed");
        assert_eq!(err.metadata.exit_status, Some(7));
        let stderr = err
            .metadata
            .stderr_redacted
            .expect("stderr should be retained in redacted form");
        assert!(
            stderr.contains("[REDACTED]"),
            "stderr was not redacted: {stderr}"
        );
        assert!(
            !stderr.contains("ghp_secret"),
            "stderr leaked secret value: {stderr}"
        );
        Ok(())
    }

    #[test]
    fn proxy_credential_capture_backend_uses_path_cache_scope() -> Result<()> {
        let mut entry = test_capture_entry(vec!["/bin/echo".to_string(), "scoped".to_string()]);
        entry.cache_path_regex = Some("^/(?:repos/|orgs/)?([^/]+)".to_string());
        let mut entries = HashMap::new();
        entries.insert("github".to_string(), entry);
        let backend = ProxyCredentialCaptureBackend::new(&entries, "sess-test".to_string())?;
        let request = nono_proxy::capture::CredentialCaptureRequest {
            credential_name: "github".to_string(),
            route_id: "github".to_string(),
            request_host: "api.github.com".to_string(),
            request_path: "/repos/example/private/issues/1".to_string(),
            request_method: "GET".to_string(),
            session_id: String::new(),
            cache_scope: String::new(),
        };

        let first =
            nono_proxy::capture::CredentialCaptureBackend::capture(&backend, request.clone())
                .map_err(|err| NonoError::SandboxInit(err.to_string()))?;
        assert_eq!(first.metadata.cache_scope.as_deref(), Some("example"));

        let second = nono_proxy::capture::CredentialCaptureBackend::capture(&backend, request)
            .map_err(|err| NonoError::SandboxInit(err.to_string()))?;
        assert_eq!(second.metadata.cache_action, "cache_hit");
        assert_eq!(second.metadata.cache_scope.as_deref(), Some("example"));
        Ok(())
    }

    #[test]
    fn proxy_credential_capture_backend_parses_json_headers() -> Result<()> {
        let mut entry = test_capture_entry_no_cache(vec![
            "/bin/echo".to_string(),
            r#"{"headers":{"Authorization":"Bearer one","X-Gateway-Key":"two"}}"#.to_string(),
        ]);
        entry.output = crate::profile::CredentialCaptureOutput::Config(
            crate::profile::CredentialCaptureOutputConfig {
                format: crate::profile::CredentialCaptureOutputFormat::Json,
                allow_headers: vec!["Authorization".to_string(), "X-Gateway-Key".to_string()],
            },
        );
        let mut entries = HashMap::new();
        entries.insert("gateway".to_string(), entry);
        let backend = ProxyCredentialCaptureBackend::new(&entries, "sess-test".to_string())?;
        let response = nono_proxy::capture::CredentialCaptureBackend::capture(
            &backend,
            nono_proxy::capture::CredentialCaptureRequest {
                credential_name: "gateway".to_string(),
                route_id: "gateway".to_string(),
                request_host: "api.example.com".to_string(),
                request_path: "/".to_string(),
                request_method: "POST".to_string(),
                session_id: String::new(),
                cache_scope: String::new(),
            },
        )
        .map_err(|err| NonoError::SandboxInit(err.to_string()))?;

        assert_eq!(response.metadata.output_format.as_deref(), Some("json"));
        assert_eq!(
            response.metadata.header_names,
            vec!["Authorization".to_string(), "X-Gateway-Key".to_string()]
        );
        match response.material {
            nono_proxy::capture::CredentialCaptureMaterial::Headers(headers) => {
                assert_eq!(headers.len(), 2);
                assert_eq!(headers[0].0, "Authorization");
                assert_eq!(headers[0].1.as_str(), "Bearer one");
            }
            nono_proxy::capture::CredentialCaptureMaterial::Secret(_) => {
                panic!("expected JSON header material")
            }
        }
        Ok(())
    }

    #[test]
    fn proxy_credential_capture_backend_sends_request_json_stdin() -> Result<()> {
        let mut entry = test_capture_entry_no_cache(vec!["/bin/cat".to_string()]);
        entry.stdin = crate::profile::CredentialCaptureStdinMode::RequestJson;
        entry.cache_path_regex = Some("^/orgs/([^/]+)".to_string());
        let mut entries = HashMap::new();
        entries.insert("github".to_string(), entry);
        let backend = ProxyCredentialCaptureBackend::new(&entries, "sess-stdin".to_string())?;
        let response = nono_proxy::capture::CredentialCaptureBackend::capture(
            &backend,
            nono_proxy::capture::CredentialCaptureRequest {
                credential_name: "github".to_string(),
                route_id: "github".to_string(),
                request_host: "api.github.com".to_string(),
                request_path: "/orgs/example/repos".to_string(),
                request_method: "GET".to_string(),
                session_id: String::new(),
                cache_scope: String::new(),
            },
        )
        .map_err(|err| NonoError::SandboxInit(err.to_string()))?;

        let value = capture_secret(&response);
        let payload: serde_json::Value =
            serde_json::from_str(value).map_err(|err| NonoError::ConfigParse(err.to_string()))?;
        assert_eq!(payload["session_id"], "sess-stdin");
        assert_eq!(payload["cache_scope"], "example");
        assert_eq!(payload["request_method"], "GET");
        assert_eq!(
            response.metadata.stdin_mode.as_deref(),
            Some("request_json")
        );
        Ok(())
    }

    #[test]
    fn proxy_credential_capture_backend_exposes_browser_helper_for_open_urls() -> Result<()> {
        let mut entry = test_capture_entry_no_cache(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            r#"test -n "$BROWSER" && test -x "$BROWSER" && test -S "$NONO_SUPERVISOR_PATH" && printf browser-ok"#.to_string(),
        ]);
        entry.interaction = Some(crate::profile::CredentialCaptureInteraction {
            stdio: false,
            stdin: false,
            open_urls: Some(crate::profile::OpenUrlConfig {
                allow_origins: vec!["https://github.com".to_string()],
                allow_localhost: true,
            }),
            allow_launch_services: true,
        });
        let mut entries = HashMap::new();
        entries.insert("github".to_string(), entry);
        let backend = ProxyCredentialCaptureBackend::new(&entries, "sess-browser".to_string())?;
        let response = nono_proxy::capture::CredentialCaptureBackend::capture(
            &backend,
            nono_proxy::capture::CredentialCaptureRequest {
                credential_name: "github".to_string(),
                route_id: "github".to_string(),
                request_host: "api.github.com".to_string(),
                request_path: "/".to_string(),
                request_method: "GET".to_string(),
                session_id: String::new(),
                cache_scope: String::new(),
            },
        )
        .map_err(|err| NonoError::SandboxInit(err.to_string()))?;

        assert_capture_secret(&response, "browser-ok");
        assert_eq!(response.metadata.interactive, Some(true));
        Ok(())
    }

    fn test_capture_entry(command: Vec<String>) -> crate::profile::CredentialCaptureEntry {
        crate::profile::CredentialCaptureEntry {
            command,
            timeout_secs: Some(5),
            ttl_secs: Some(60),
            cache_ttl_secs: None,
            cache_path_regex: None,
            stdin: crate::profile::CredentialCaptureStdinMode::Null,
            output: crate::profile::CredentialCaptureOutput::default(),
            interaction: None,
        }
    }

    fn test_capture_entry_no_cache(command: Vec<String>) -> crate::profile::CredentialCaptureEntry {
        let mut entry = test_capture_entry(command);
        entry.ttl_secs = Some(0);
        entry
    }

    fn assert_capture_secret(
        response: &nono_proxy::capture::CredentialCaptureResponse,
        expected: &str,
    ) {
        assert_eq!(capture_secret(response), expected);
    }

    fn capture_secret(response: &nono_proxy::capture::CredentialCaptureResponse) -> &str {
        match &response.material {
            nono_proxy::capture::CredentialCaptureMaterial::Secret(value) => value.as_str(),
            nono_proxy::capture::CredentialCaptureMaterial::Headers(_) => {
                panic!("expected text credential material")
            }
        }
    }

    #[test]
    fn test_parse_allow_endpoint_arg_valid() {
        let (service, rule) =
            parse_allow_endpoint_arg("github:GET:/repos/*/issues").expect("should parse");
        assert_eq!(service, "github");
        assert_eq!(rule.method, "GET");
        assert_eq!(rule.path, "/repos/*/issues");
    }

    #[test]
    fn test_parse_allow_endpoint_arg_wildcard_method() {
        let (service, rule) =
            parse_allow_endpoint_arg("openai:*:/v1/chat/completions").expect("should parse");
        assert_eq!(service, "openai");
        assert_eq!(rule.method, "*");
        assert_eq!(rule.path, "/v1/chat/completions");
    }

    #[test]
    fn test_parse_allow_endpoint_arg_missing_path() {
        assert!(parse_allow_endpoint_arg("github:GET").is_err());
    }

    #[test]
    fn test_parse_allow_endpoint_arg_missing_method_and_path() {
        assert!(parse_allow_endpoint_arg("github").is_err());
    }

    #[test]
    fn test_parse_allow_endpoint_arg_empty_service() {
        assert!(parse_allow_endpoint_arg(":GET:/path").is_err());
    }

    #[test]
    fn test_parse_allow_endpoint_arg_empty_path() {
        assert!(parse_allow_endpoint_arg("github:GET:").is_err());
    }

    #[test]
    fn test_parse_allow_endpoint_arg_path_must_start_with_slash() {
        let result = parse_allow_endpoint_arg("github:GET:repos/*/issues");
        assert!(result.is_err());
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains("must start with '/'"),
            "error should explain the leading slash requirement, got: {err}"
        );
    }

    fn ep(service: &str, method: &str, path: &str) -> (String, nono_proxy::config::EndpointRule) {
        (
            service.to_string(),
            nono_proxy::config::EndpointRule {
                method: method.to_string(),
                path: path.to_string(),
            },
        )
    }

    #[test]
    fn test_allow_endpoint_applied_to_credential_route() {
        let proxy = ProxyLaunchOptions {
            credentials: Some(crate::launch_runtime::CredentialProxyIntent {
                credentials: vec!["github".to_string()],
                custom_credentials: std::collections::HashMap::new(),
                endpoint_restrictions: vec![
                    ep("github", "GET", "/repos/*/issues"),
                    ep("github", "POST", "/repos/*/issues/*/comments"),
                ],
            }),
            ..ProxyLaunchOptions::default()
        };
        let config = build_proxy_config_from_flags(&proxy).expect("build");
        let github = config
            .routes
            .iter()
            .find(|r| r.prefix == "github")
            .expect("github route must exist");
        assert_eq!(github.endpoint_rules.len(), 2);
        assert_eq!(github.endpoint_rules[0].method, "GET");
        assert_eq!(github.endpoint_rules[0].path, "/repos/*/issues");
        assert_eq!(github.endpoint_rules[1].method, "POST");
        assert_eq!(github.endpoint_rules[1].path, "/repos/*/issues/*/comments");
    }

    #[test]
    fn test_allow_endpoint_does_not_affect_other_routes() {
        let proxy = ProxyLaunchOptions {
            credentials: Some(crate::launch_runtime::CredentialProxyIntent {
                credentials: vec!["github".to_string(), "openai".to_string()],
                custom_credentials: std::collections::HashMap::new(),
                endpoint_restrictions: vec![ep("github", "GET", "/repos/*/issues")],
            }),
            ..ProxyLaunchOptions::default()
        };
        let config = build_proxy_config_from_flags(&proxy).expect("build");
        let openai = config
            .routes
            .iter()
            .find(|r| r.prefix == "openai")
            .expect("openai route must exist");
        assert!(
            openai.endpoint_rules.is_empty(),
            "openai route should not have endpoint rules when only github was restricted"
        );
    }

    #[test]
    fn test_allow_endpoint_unknown_service_errors() {
        let proxy = ProxyLaunchOptions {
            credentials: Some(crate::launch_runtime::CredentialProxyIntent {
                credentials: vec!["github".to_string()],
                custom_credentials: std::collections::HashMap::new(),
                endpoint_restrictions: vec![ep("nonexistent", "GET", "/path")],
            }),
            ..ProxyLaunchOptions::default()
        };
        let result = build_proxy_config_from_flags(&proxy);
        assert!(result.is_err());
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains("nonexistent"),
            "error should name the unknown service, got: {}",
            err
        );
    }

    #[test]
    fn test_allow_endpoint_no_credential_errors() {
        let proxy = ProxyLaunchOptions {
            credentials: Some(crate::launch_runtime::CredentialProxyIntent {
                credentials: Vec::new(),
                custom_credentials: std::collections::HashMap::new(),
                endpoint_restrictions: vec![ep("github", "GET", "/repos")],
            }),
            ..ProxyLaunchOptions::default()
        };
        let result = build_proxy_config_from_flags(&proxy);
        assert!(
            result.is_err(),
            "--allow-endpoint for a service without --credential must error"
        );
    }

    // Verify that a credential helper with `stdio: true` (interaction.stdio) does not
    // inherit the terminal's stdin. The `stdio` flag is only meant to allow the helper
    // to write prompts via stderr; stdin must always be /dev/null when stdin_mode is Null.
    //
    // The test replaces the process's stdin fd with a blocking pipe (write end kept open,
    // so it never reaches EOF). If the fix is absent, the child inherits that blocking fd
    // and `select` reports it as not ready; with the fix, the child gets /dev/null instead
    // and `select` reports it as readable (EOF is a readable condition).
    #[test]
    #[cfg(unix)]
    fn capture_helper_with_stdio_true_receives_null_not_terminal_stdin() -> Result<()> {
        use nix::libc;

        let _guard = STDIN_MANIPULATION_LOCK
            .lock()
            .map_err(|e| NonoError::SandboxInit(format!("stdin lock poisoned: {e}")))?;

        let mut pipe_fds = [-1i32; 2];
        let saved_stdin;
        unsafe {
            assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0, "pipe() failed");
            saved_stdin = libc::dup(libc::STDIN_FILENO);
            assert!(saved_stdin >= 0, "dup(stdin) failed");
            assert_eq!(
                libc::dup2(pipe_fds[0], libc::STDIN_FILENO),
                libc::STDIN_FILENO,
                "dup2 failed"
            );
            libc::close(pipe_fds[0]);
        }

        let result = (|| -> Result<()> {
            let mut entry = test_capture_entry_no_cache(vec![
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                // select() with timeout=0: /dev/null stdin is immediately readable (EOF);
                // a blocking pipe (write end open, no data) is not ready.
                concat!(
                    "import select, sys; ",
                    "r, _, _ = select.select([sys.stdin], [], [], 0); ",
                    "sys.stdout.write('null' if r else 'blocked'); ",
                    "sys.stdout.flush()"
                )
                .to_string(),
            ]);
            entry.interaction = Some(crate::profile::CredentialCaptureInteraction {
                stdio: true,
                stdin: false,
                open_urls: None,
                allow_launch_services: false,
            });
            let mut entries = HashMap::new();
            entries.insert("test-cred".to_string(), entry);
            let backend =
                ProxyCredentialCaptureBackend::new(&entries, "sess-stdio-stdin".to_string())?;
            let response = nono_proxy::capture::CredentialCaptureBackend::capture(
                &backend,
                nono_proxy::capture::CredentialCaptureRequest {
                    credential_name: "test-cred".to_string(),
                    route_id: "test-cred".to_string(),
                    request_host: "example.com".to_string(),
                    request_path: "/".to_string(),
                    request_method: "GET".to_string(),
                    session_id: String::new(),
                    cache_scope: String::new(),
                },
            )
            .map_err(|err| NonoError::SandboxInit(err.to_string()))?;
            assert_eq!(
                capture_secret(&response),
                "null",
                "credential helper stdin must be /dev/null when stdio:true, not the inherited fd"
            );
            Ok(())
        })();

        // Restore stdin whether the test passed or failed.
        unsafe {
            libc::dup2(saved_stdin, libc::STDIN_FILENO);
            libc::close(saved_stdin);
            libc::close(pipe_fds[1]);
        }

        result
    }

    // Verify that setting interaction.stdin:true lets the credential helper inherit the
    // terminal stdin. This is the explicit opt-in for helpers that genuinely need to
    // prompt the user for input.
    #[test]
    #[cfg(unix)]
    fn capture_helper_with_interaction_stdin_true_inherits_terminal_stdin() -> Result<()> {
        use nix::libc;

        let _guard = STDIN_MANIPULATION_LOCK
            .lock()
            .map_err(|e| NonoError::SandboxInit(format!("stdin lock poisoned: {e}")))?;

        let mut pipe_fds = [-1i32; 2];
        let saved_stdin;
        unsafe {
            assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0, "pipe() failed");
            saved_stdin = libc::dup(libc::STDIN_FILENO);
            assert!(saved_stdin >= 0, "dup(stdin) failed");
            assert_eq!(
                libc::dup2(pipe_fds[0], libc::STDIN_FILENO),
                libc::STDIN_FILENO,
                "dup2 failed"
            );
            libc::close(pipe_fds[0]);
        }

        let result = (|| -> Result<()> {
            let mut entry = test_capture_entry_no_cache(vec![
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                concat!(
                    "import select, sys; ",
                    "r, _, _ = select.select([sys.stdin], [], [], 0); ",
                    "sys.stdout.write('null' if r else 'blocked'); ",
                    "sys.stdout.flush()"
                )
                .to_string(),
            ]);
            entry.interaction = Some(crate::profile::CredentialCaptureInteraction {
                stdio: true,
                stdin: true,
                open_urls: None,
                allow_launch_services: false,
            });
            let mut entries = HashMap::new();
            entries.insert("test-cred".to_string(), entry);
            let backend =
                ProxyCredentialCaptureBackend::new(&entries, "sess-inherit-stdin".to_string())?;
            let response = nono_proxy::capture::CredentialCaptureBackend::capture(
                &backend,
                nono_proxy::capture::CredentialCaptureRequest {
                    credential_name: "test-cred".to_string(),
                    route_id: "test-cred".to_string(),
                    request_host: "example.com".to_string(),
                    request_path: "/".to_string(),
                    request_method: "GET".to_string(),
                    session_id: String::new(),
                    cache_scope: String::new(),
                },
            )
            .map_err(|err| NonoError::SandboxInit(err.to_string()))?;
            assert_eq!(
                capture_secret(&response),
                "blocked",
                "credential helper stdin must be inherited when interaction.stdin:true"
            );
            Ok(())
        })();

        unsafe {
            libc::dup2(saved_stdin, libc::STDIN_FILENO);
            libc::close(saved_stdin);
            libc::close(pipe_fds[1]);
        }

        result
    }
}
