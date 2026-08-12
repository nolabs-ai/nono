//! Terminal-native remote attach client for nono-console.
//!
//! The open wire contract is documented in `docs/protocols/remote-attach-v1.md`.
//! Human authentication is deliberately separate from device enrollment. This
//! explicit protected file or `NONO_CONNECT_TOKEN`. Otherwise an enrolled
//! device runs browser-approved human authorization, caches a device-bound
//! opaque credential, and exchanges it for a short-lived console bearer token.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

use futures_util::{SinkExt, StreamExt};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{
    HeaderValue,
    header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL},
};
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;
use zeroize::Zeroizing;

use crate::cli::{ConnectArgs, PsArgs};

const RESPONSE_LIMIT_BYTES: u64 = 1024 * 1024;
const DISCOVERY_PROTOCOL_V1: &str = "1";
const DEVICE_AUTH_PROTOCOL_V1: &str = "1";
const DEVICE_AUTH_VERIFICATION_PATH: &str = "/platform/device";
const DEVICE_AUTH_CACHE_FILENAME: &str = "platform-console-auth.json";
const DEFAULT_DETACH_SEQUENCE: &[u8] = &[0x1d, b'd'];
const WEBSOCKET_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
static REMOTE_EXIT_CODE: AtomicI32 = AtomicI32::new(0);

#[derive(Debug, Deserialize)]
struct ListSessionsResponse {
    sessions: Vec<RemoteSession>,
}

#[derive(Debug, Deserialize)]
struct ConsoleDiscoveryResponse {
    protocol_version: String,
    tenant_id: String,
    console_url: String,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    protocol_version: String,
    device_code: String,
    user_code: String,
    verification_path: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Serialize)]
struct DevicePollRequest<'a> {
    protocol_version: &'static str,
    device_code: &'a str,
}

#[derive(Debug, Deserialize)]
struct DevicePollResponse {
    protocol_version: String,
    status: String,
    credential: Option<String>,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceAccessTokenResponse {
    protocol_version: String,
    access_token: String,
    token_type: String,
    expires_in: u64,
    tenant_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedDeviceAuthorization {
    protocol_version: String,
    platform_url: String,
    tenant_id: String,
    subject_id: String,
    credential: String,
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RemoteSession {
    global_session_id: String,
    backend_status: String,
    record: Option<RemoteSessionRecord>,
    agent: Option<RemoteAgent>,
    repo: Option<RemoteRepo>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RemoteSessionRecord {
    name: Option<String>,
    status: String,
    command: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RemoteAgent {
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RemoteRepo {
    full_name: String,
    base_branch: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerControl {
    Attached {
        protocol_version: String,
        cols: u16,
        rows: u16,
    },
    SessionExited {
        exit_code: Option<i32>,
    },
    Error {
        code: Option<String>,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachOutcome {
    Detached,
    SessionExited,
}

pub(crate) fn run_connect(args: ConnectArgs) -> Result<()> {
    if args.read_only {
        return Err(NonoError::ActionRequired(
            "read-only remote attach is not implemented yet; console fan-out must land first"
                .to_string(),
        ));
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(NonoError::ActionRequired(
            "nono connect requires an interactive terminal".to_string(),
        ));
    }

    let token = load_token(args.token_file.as_deref())?;
    let attach_url = resolve_attach_url(args.target.as_deref(), args.console.as_deref(), &token)?;
    validate_transport_url(&attach_url)?;
    let detach_sequence = crate::launch_runtime::load_configured_detach_sequence()?
        .unwrap_or_else(|| DEFAULT_DETACH_SEQUENCE.to_vec());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            NonoError::ConfigParse(format!("could not start connect runtime: {error}"))
        })?;
    match runtime.block_on(attach(attach_url, token, detach_sequence))? {
        AttachOutcome::Detached => eprintln!("\nDetached from remote session."),
        AttachOutcome::SessionExited => {}
    }
    Ok(())
}

/// List sessions visible through the enrolled tenant's nono-console.
pub(crate) fn run_remote_ps(args: &PsArgs) -> Result<()> {
    // Resolve the environment equivalents here rather than through clap. That
    // keeps a globally configured remote console from affecting local `nono ps`.
    let token_file_env = args
        .token_file
        .is_none()
        .then(|| std::env::var_os("NONO_CONNECT_TOKEN_FILE"))
        .flatten()
        .map(std::path::PathBuf::from);
    let token_file = args.token_file.as_deref().or(token_file_env.as_deref());
    let token = load_token(token_file)?;
    let console_env = if args.console.is_none() {
        match std::env::var("NONO_CONSOLE_URL") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => {
                return Err(NonoError::ConfigParse(format!(
                    "could not read NONO_CONSOLE_URL: {error}"
                )));
            }
        }
    } else {
        None
    };
    let console = match args.console.as_deref().or(console_env.as_deref()) {
        Some(console) => validate_console_url(console)?,
        None => discover_console()?,
    };
    let sessions = filter_remote_sessions(fetch_sessions(&console, &token)?, args.all);

    if args.json {
        let json = serde_json::to_string_pretty(&sessions).map_err(|error| {
            NonoError::ConfigParse(format!("JSON serialization failed: {error}"))
        })?;
        println!("{json}");
        return Ok(());
    }

    print_remote_sessions(&sessions, args.all)
}

/// Return the non-zero hosted process status recorded by `run_connect`.
/// The CLI executes one top-level command, so a process-local atomic keeps this
/// outcome out of the public `nono::NonoError` / FFI contract.
pub(crate) fn take_remote_exit_code() -> Option<i32> {
    match REMOTE_EXIT_CODE.swap(0, Ordering::AcqRel) {
        0 => None,
        code => Some(code),
    }
}

fn resolve_attach_url(target: Option<&str>, console: Option<&str>, token: &str) -> Result<Url> {
    if let Some(target) = target
        && let Ok(url) = Url::parse(target)
        && matches!(url.scheme(), "ws" | "wss")
    {
        validate_direct_attach_url(&url)?;
        return Ok(url);
    }

    let console_url = match console {
        Some(console) => validate_console_url(console)?,
        None => discover_console()?,
    };
    let session = match target {
        Some(value) => select_named_session(&list_live_sessions(&console_url, token)?, value)?,
        None => select_interactively(&list_live_sessions(&console_url, token)?)?,
    };
    terminal_url(&console_url, &session.global_session_id)
}

fn load_token(path: Option<&Path>) -> Result<Zeroizing<String>> {
    let value = match path {
        Some(path) => {
            let metadata = std::fs::metadata(path).map_err(|source| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source,
            })?;
            if metadata.len() > 64 * 1024 {
                return Err(NonoError::ConfigParse(
                    "connect token file exceeds 64 KiB".to_string(),
                ));
            }
            if !metadata.is_file() {
                return Err(NonoError::ConfigParse(
                    "connect token path must be a regular file".to_string(),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(NonoError::ActionRequired(
                        "connect token file must not be readable or writable by group/other (use mode 0600)"
                            .to_string(),
                    ));
                }
            }
            std::fs::read_to_string(path).map_err(|source| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source,
            })?
        }
        None => match std::env::var("NONO_CONNECT_TOKEN") {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => return acquire_console_access_token(),
            Err(error) => {
                return Err(NonoError::ConfigParse(format!(
                    "could not read NONO_CONNECT_TOKEN: {error}"
                )));
            }
        },
    };
    let token = value.trim();
    if token.is_empty() || token.contains(|character: char| character.is_ascii_whitespace()) {
        return Err(NonoError::ConfigParse(
            "connect token is empty or contains whitespace".to_string(),
        ));
    }
    Ok(Zeroizing::new(token.to_string()))
}

fn acquire_console_access_token() -> Result<Zeroizing<String>> {
    let state = crate::platform_client::load_state()?.ok_or_else(|| {
        NonoError::ActionRequired(
            "human authorization requires platform enrollment; run `nono platform enroll` or provide --token-file"
                .to_string(),
        )
    })?;
    if state.subject_kind != "device" {
        return Err(NonoError::ActionRequired(
            "human authorization requires a device enrollment; workload identities cannot authorize terminal access"
                .to_string(),
        ));
    }
    if let Some(cached) = load_cached_authorization(&state)?
        && let Some(token) = exchange_console_access_token(&state, &cached.credential)?
    {
        return Ok(token);
    }
    authorize_device(&state)
}

fn load_cached_authorization(
    state: &crate::platform_client::PlatformState,
) -> Result<Option<CachedDeviceAuthorization>> {
    let path = device_auth_cache_path()?;
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(NonoError::ConfigRead { path, source }),
    };
    let cached: CachedDeviceAuthorization = serde_json::from_str(&contents).map_err(|error| {
        NonoError::ConfigParse(format!("invalid device authorization cache: {error}"))
    })?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&cached.expires_at).map_err(|error| {
        NonoError::ConfigParse(format!("invalid device authorization expiry: {error}"))
    })?;
    if cached.protocol_version != DEVICE_AUTH_PROTOCOL_V1
        || cached.platform_url != state.platform_url
        || cached.tenant_id != state.tenant_id
        || cached.subject_id != state.subject_id
        || expires_at <= chrono::Utc::now()
    {
        return Ok(None);
    }
    Ok(Some(cached))
}

fn authorize_device(state: &crate::platform_client::PlatformState) -> Result<Zeroizing<String>> {
    let mut response = signed_post(state, "/api/v1/auth/device/code", &[], None)?;
    if matches!(response.status().as_u16(), 401 | 403) {
        return Err(NonoError::ActionRequired(
            "platform authentication failed; renew the platform enrollment and try again"
                .to_string(),
        ));
    }
    require_success(&response, "starting human authorization")?;
    let body = read_response(&mut response, "device authorization response")?;
    let code: DeviceCodeResponse = serde_json::from_str(&body).map_err(|error| {
        NonoError::ConfigParse(format!("invalid device authorization response: {error}"))
    })?;
    if code.protocol_version != DEVICE_AUTH_PROTOCOL_V1
        || code.verification_path != DEVICE_AUTH_VERIFICATION_PATH
        || code.expires_in == 0
        || code.expires_in > 15 * 60
        || code.interval == 0
        || code.interval > 30
    {
        return Err(NonoError::ConfigParse(
            "platform returned an unsupported device authorization contract".to_string(),
        ));
    }
    let verification_url =
        crate::platform_client::endpoint_url(&state.platform_url, &code.verification_path)?;
    eprintln!("Authorize this terminal in your browser:");
    eprintln!("  {verification_url}");
    eprintln!("  Code: {}", code.user_code);
    if let Err(error) = open_browser(&verification_url) {
        eprintln!("  Browser could not be opened automatically: {error}");
    }

    let started = std::time::Instant::now();
    loop {
        if started.elapsed() >= std::time::Duration::from_secs(code.expires_in) {
            return Err(NonoError::ActionRequired(
                "human authorization expired; run `nono connect` again".to_string(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_secs(code.interval));
        let request = DevicePollRequest {
            protocol_version: DEVICE_AUTH_PROTOCOL_V1,
            device_code: &code.device_code,
        };
        let body = serde_json::to_vec(&request).map_err(|error| {
            NonoError::ConfigParse(format!("could not encode device poll: {error}"))
        })?;
        let mut response = signed_post(state, "/api/v1/auth/device/poll", &body, None)?;
        require_success(&response, "polling human authorization")?;
        let response_body = read_response(&mut response, "device poll response")?;
        let poll: DevicePollResponse = serde_json::from_str(&response_body).map_err(|error| {
            NonoError::ConfigParse(format!("invalid device poll response: {error}"))
        })?;
        if poll.protocol_version != DEVICE_AUTH_PROTOCOL_V1 {
            return Err(NonoError::ConfigParse(
                "platform returned an unsupported device poll protocol".to_string(),
            ));
        }
        match poll.status.as_str() {
            "authorization_pending" => continue,
            "access_denied" => {
                return Err(NonoError::ActionRequired(
                    "human authorization was denied".to_string(),
                ));
            }
            "expired" => {
                return Err(NonoError::ActionRequired(
                    "human authorization expired; run `nono connect` again".to_string(),
                ));
            }
            "authorized" => {
                let credential = poll.credential.ok_or_else(|| {
                    NonoError::ConfigParse("authorized response omitted its credential".to_string())
                })?;
                let expires_at = poll.expires_at.ok_or_else(|| {
                    NonoError::ConfigParse("authorized response omitted its expiry".to_string())
                })?;
                chrono::DateTime::parse_from_rfc3339(&expires_at).map_err(|error| {
                    NonoError::ConfigParse(format!("invalid device authorization expiry: {error}"))
                })?;
                let cached = CachedDeviceAuthorization {
                    protocol_version: DEVICE_AUTH_PROTOCOL_V1.to_string(),
                    platform_url: state.platform_url.clone(),
                    tenant_id: state.tenant_id.clone(),
                    subject_id: state.subject_id.clone(),
                    credential,
                    expires_at,
                };
                crate::platform_client::write_json_secure(&device_auth_cache_path()?, &cached)?;
                let token = exchange_console_access_token(state, &cached.credential)?
                    .ok_or_else(|| {
                        NonoError::ActionRequired(
                            "the new human authorization could not be exchanged; run `nono connect` again"
                                .to_string(),
                        )
                    })?;
                eprintln!("Terminal authorized.");
                return Ok(token);
            }
            _ => {
                return Err(NonoError::ConfigParse(
                    "platform returned an unknown device authorization status".to_string(),
                ));
            }
        }
    }
}

fn exchange_console_access_token(
    state: &crate::platform_client::PlatformState,
    credential: &str,
) -> Result<Option<Zeroizing<String>>> {
    let mut response = signed_post(
        state,
        "/api/v1/auth/device/access-token",
        &[],
        Some(credential),
    )?;
    if matches!(response.status().as_u16(), 401 | 403) {
        return Ok(None);
    }
    require_success(&response, "exchanging human authorization")?;
    let body = read_response(&mut response, "console access response")?;
    let access: DeviceAccessTokenResponse = serde_json::from_str(&body).map_err(|error| {
        NonoError::ConfigParse(format!("invalid console access response: {error}"))
    })?;
    if access.protocol_version != DEVICE_AUTH_PROTOCOL_V1
        || access.token_type != "Bearer"
        || access.tenant_id != state.tenant_id
        || access.expires_in == 0
        || access.expires_in > 5 * 60
    {
        return Err(NonoError::ConfigParse(
            "platform returned an unsupported console access contract".to_string(),
        ));
    }
    validate_token(access.access_token).map(Some)
}

fn signed_post(
    state: &crate::platform_client::PlatformState,
    path: &str,
    body: &[u8],
    bearer: Option<&str>,
) -> Result<ureq::http::Response<ureq::Body>> {
    let endpoint = crate::platform_client::endpoint_url(&state.platform_url, path)?;
    let request_path = Url::parse(&endpoint)
        .map_err(|error| NonoError::ConfigParse(format!("invalid platform endpoint: {error}")))?
        .path()
        .to_string();
    let signed = crate::platform_client::sign_request_v1(
        state,
        "POST",
        &request_path,
        uuid::Uuid::now_v7(),
        body,
    )?;
    let mut request = crate::platform_client::http_agent(std::time::Duration::from_secs(15))
        .post(&endpoint)
        .config()
        .http_status_as_error(false)
        .build()
        .header("Content-Type", "application/json")
        .header(
            "X-Nono-Protocol-Version",
            crate::platform_client::REQUEST_PROTOCOL_V1,
        )
        .header("X-Nono-Subject-Id", &state.subject_id)
        .header("X-Nono-Timestamp", &signed.timestamp)
        .header("X-Nono-Request-Id", &signed.request_id)
        .header("X-Nono-Content-SHA256", &signed.body_digest)
        .header("X-Nono-Signature", &signed.signature);
    if let Some(credential) = bearer {
        request = request.header("Authorization", &format!("Bearer {credential}"));
    }
    request.send(body).map_err(|error| {
        NonoError::ConfigParse(format!("platform authorization request failed: {error}"))
    })
}

fn require_success(response: &ureq::http::Response<ureq::Body>, operation: &str) -> Result<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(NonoError::ConfigParse(format!(
            "platform returned HTTP {} while {operation}",
            response.status().as_u16()
        )))
    }
}

fn read_response(response: &mut ureq::http::Response<ureq::Body>, name: &str) -> Result<String> {
    response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT_BYTES)
        .read_to_string()
        .map_err(|error| NonoError::ConfigParse(format!("invalid {name}: {error}")))
}

fn validate_token(value: String) -> Result<Zeroizing<String>> {
    let token = value.trim();
    if token.is_empty() || token.contains(|character: char| character.is_ascii_whitespace()) {
        return Err(NonoError::ConfigParse(
            "connect token is empty or contains whitespace".to_string(),
        ));
    }
    Ok(Zeroizing::new(token.to_string()))
}

fn device_auth_cache_path() -> Result<std::path::PathBuf> {
    Ok(crate::state_paths::user_state_dir()?.join(DEVICE_AUTH_CACHE_FILENAME))
}

fn open_browser(url: &str) -> std::result::Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(url).status();
    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open").arg(url).status();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: std::result::Result<std::process::ExitStatus, std::io::Error> =
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "browser launch unsupported",
        ));
    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("browser opener exited with {status}")),
        Err(error) => Err(error.to_string()),
    }
}

fn validate_console_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)
        .map_err(|error| NonoError::ConfigParse(format!("invalid console URL: {error}")))?;
    if url.cannot_be_a_base() || !matches!(url.scheme(), "http" | "https") {
        return Err(NonoError::ConfigParse(
            "console URL must use http:// or https://".to_string(),
        ));
    }
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err(NonoError::ConfigParse(
            "console URL must use HTTPS; HTTP is allowed only for loopback development".to_string(),
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NonoError::ConfigParse(
            "console URL must not contain credentials, query parameters, or fragments".to_string(),
        ));
    }
    Ok(url)
}

fn discover_console() -> Result<Url> {
    let state = crate::platform_client::load_state()?.ok_or_else(|| {
        NonoError::ActionRequired(
            "console discovery requires platform enrollment; run `nono platform enroll` or pass --console"
                .to_string(),
        )
    })?;
    if state.subject_kind != "device" {
        return Err(NonoError::ActionRequired(
            "console discovery requires a device enrollment; workload identities cannot authorize human terminal access"
                .to_string(),
        ));
    }
    let endpoint = crate::platform_client::endpoint_url(&state.platform_url, "/api/v1/console")?;
    let request_path = Url::parse(&endpoint)
        .map_err(|error| NonoError::ConfigParse(format!("invalid discovery endpoint: {error}")))?
        .path()
        .to_string();
    let signed = crate::platform_client::sign_request_v1(
        &state,
        "GET",
        &request_path,
        uuid::Uuid::now_v7(),
        &[],
    )?;
    let mut response = crate::platform_client::http_agent(std::time::Duration::from_secs(15))
        .get(&endpoint)
        .config()
        .http_status_as_error(false)
        .build()
        .header(
            "X-Nono-Protocol-Version",
            crate::platform_client::REQUEST_PROTOCOL_V1,
        )
        .header("X-Nono-Subject-Id", &state.subject_id)
        .header("X-Nono-Timestamp", &signed.timestamp)
        .header("X-Nono-Request-Id", &signed.request_id)
        .header("X-Nono-Content-SHA256", &signed.body_digest)
        .header("X-Nono-Signature", &signed.signature)
        .call()
        .map_err(|error| NonoError::ConfigParse(format!("console discovery failed: {error}")))?;
    if !response.status().is_success() {
        return Err(NonoError::ConfigParse(format!(
            "platform returned HTTP {} while discovering nono-console",
            response.status().as_u16()
        )));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT_BYTES)
        .read_to_string()
        .map_err(|error| NonoError::ConfigParse(format!("invalid discovery response: {error}")))?;
    validate_discovery_response(&state, &body)
}

fn validate_discovery_response(
    state: &crate::platform_client::PlatformState,
    body: &str,
) -> Result<Url> {
    let response: ConsoleDiscoveryResponse = serde_json::from_str(body)
        .map_err(|error| NonoError::ConfigParse(format!("invalid discovery response: {error}")))?;
    if response.protocol_version != DISCOVERY_PROTOCOL_V1 {
        return Err(NonoError::ConfigParse(
            "platform returned an unsupported console discovery protocol".to_string(),
        ));
    }
    if response.tenant_id != state.tenant_id {
        return Err(NonoError::ConfigParse(
            "platform console discovery tenant does not match local enrollment".to_string(),
        ));
    }
    validate_console_url(&response.console_url)
}

fn validate_transport_url(url: &Url) -> Result<()> {
    if url.scheme() == "wss" || (url.scheme() == "ws" && is_loopback(url)) {
        Ok(())
    } else {
        Err(NonoError::ConfigParse(
            "remote attach must use WSS; WS is allowed only for loopback development".to_string(),
        ))
    }
}

fn validate_direct_attach_url(url: &Url) -> Result<()> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NonoError::ConfigParse(
            "attach URLs must not contain credentials, query parameters, or fragments".to_string(),
        ));
    }
    Ok(())
}

fn is_loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn fetch_sessions(console: &Url, token: &str) -> Result<Vec<RemoteSession>> {
    let endpoint = console_endpoint(console, "/api/v1/sessions")?;
    let agent = crate::platform_client::http_agent(std::time::Duration::from_secs(15));
    let authorization = format!("Bearer {token}");
    let mut response = agent
        .get(endpoint.as_str())
        .config()
        .http_status_as_error(false)
        .build()
        .header("Authorization", &authorization)
        .call()
        .map_err(|error| NonoError::ConfigParse(format!("console request failed: {error}")))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        return Err(NonoError::ConfigParse(format!(
            "console returned HTTP {status} while listing sessions"
        )));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT_BYTES)
        .read_to_string()
        .map_err(|error| NonoError::ConfigParse(format!("invalid session response: {error}")))?;
    let response: ListSessionsResponse = serde_json::from_str(&body)
        .map_err(|error| NonoError::ConfigParse(format!("invalid session response: {error}")))?;
    Ok(response.sessions)
}

fn list_live_sessions(console: &Url, token: &str) -> Result<Vec<RemoteSession>> {
    Ok(fetch_sessions(console, token)?
        .into_iter()
        .filter(is_live_session)
        .collect())
}

fn is_live_session(session: &RemoteSession) -> bool {
    session.backend_status == "ready"
        && session
            .record
            .as_ref()
            .is_some_and(|record| record.status == "running")
}

fn filter_remote_sessions(mut sessions: Vec<RemoteSession>, all: bool) -> Vec<RemoteSession> {
    if !all {
        sessions.retain(is_live_session);
    }
    sessions.sort_by(|left, right| {
        remote_name(left)
            .cmp(remote_name(right))
            .then_with(|| left.global_session_id.cmp(&right.global_session_id))
    });
    sessions
}

fn print_remote_sessions(sessions: &[RemoteSession], all: bool) -> Result<()> {
    if sessions.is_empty() {
        if all {
            eprintln!("No remote sessions found.");
        } else {
            eprintln!("No live remote sessions. Use --all to include inactive sessions.");
        }
        return Ok(());
    }

    struct Row {
        session: String,
        name: String,
        status: String,
        agent: String,
        repo: String,
    }

    let rows = sessions
        .iter()
        .map(|session| Row {
            session: session.global_session_id.clone(),
            name: remote_name(session).to_string(),
            status: remote_status(session).to_string(),
            agent: remote_agent(session).to_string(),
            repo: remote_repo(session),
        })
        .collect::<Vec<_>>();
    let session_width = rows
        .iter()
        .map(|row| row.session.len())
        .max()
        .unwrap_or("SESSION".len())
        .max("SESSION".len());
    let name_width = rows
        .iter()
        .map(|row| row.name.len())
        .max()
        .unwrap_or("NAME".len())
        .max("NAME".len())
        .min(28);
    let status_width = rows
        .iter()
        .map(|row| row.status.len())
        .max()
        .unwrap_or("STATUS".len())
        .max("STATUS".len())
        .min(16);
    let agent_width = rows
        .iter()
        .map(|row| row.agent.len())
        .max()
        .unwrap_or("AGENT".len())
        .max("AGENT".len())
        .min(20);

    println!(
        "{:<session_width$} {:<name_width$} {:<status_width$} {:<agent_width$} REPOSITORY",
        "SESSION", "NAME", "STATUS", "AGENT"
    );
    for row in rows {
        println!(
            "{:<session_width$} {:<name_width$} {:<status_width$} {:<agent_width$} {}",
            row.session,
            crate::command_display::truncate_chars(&row.name, name_width),
            crate::command_display::truncate_chars(&row.status, status_width),
            crate::command_display::truncate_chars(&row.agent, agent_width),
            row.repo,
        );
    }
    Ok(())
}

fn remote_name(session: &RemoteSession) -> &str {
    session
        .record
        .as_ref()
        .and_then(|record| record.name.as_deref())
        .unwrap_or("-")
}

fn remote_status(session: &RemoteSession) -> &str {
    session
        .record
        .as_ref()
        .map(|record| record.status.as_str())
        .unwrap_or(&session.backend_status)
}

fn remote_agent(session: &RemoteSession) -> &str {
    session
        .agent
        .as_ref()
        .map(|agent| agent.name.as_str())
        .or_else(|| {
            session
                .record
                .as_ref()
                .and_then(|record| record.command.first().map(String::as_str))
        })
        .unwrap_or("-")
}

fn remote_repo(session: &RemoteSession) -> String {
    session
        .repo
        .as_ref()
        .map(|repo| format!("{}#{}", repo.full_name, repo.base_branch))
        .unwrap_or_else(|| "-".to_string())
}

fn select_named_session(sessions: &[RemoteSession], target: &str) -> Result<RemoteSession> {
    let matches = sessions
        .iter()
        .filter(|session| {
            session.global_session_id == target
                || session.global_session_id.starts_with(target)
                || session
                    .record
                    .as_ref()
                    .and_then(|record| record.name.as_deref())
                    == Some(target)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [session] => Ok(clone_session(session)),
        [] => Err(NonoError::SessionNotFound(target.to_string())),
        _ => Err(NonoError::ConfigParse(format!(
            "remote session selector '{target}' is ambiguous"
        ))),
    }
}

fn select_interactively(sessions: &[RemoteSession]) -> Result<RemoteSession> {
    if sessions.is_empty() {
        return Err(NonoError::ActionRequired(
            "the console has no live sessions visible to this user".to_string(),
        ));
    }
    for (index, session) in sessions.iter().enumerate() {
        let record = session.record.as_ref();
        let name = record
            .and_then(|value| value.name.as_deref())
            .unwrap_or(&session.global_session_id);
        let agent = session
            .agent
            .as_ref()
            .map(|value| value.name.as_str())
            .or_else(|| record.and_then(|value| value.command.first().map(String::as_str)))
            .unwrap_or("unknown");
        let repo = session
            .repo
            .as_ref()
            .map(|value| format!("{}#{}", value.full_name, value.base_branch))
            .unwrap_or_else(|| "(no repo)".to_string());
        println!("  {}.  {:<28} {:<14} {repo}", index + 1, name, agent);
    }
    print!("> ");
    io::stdout().flush().map_err(NonoError::Io)?;
    let mut choice = String::new();
    io::stdin().read_line(&mut choice).map_err(NonoError::Io)?;
    let index = choice
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| NonoError::ConfigParse("invalid session selection".to_string()))?;
    sessions
        .get(index)
        .map(clone_session)
        .ok_or_else(|| NonoError::ConfigParse("session selection is out of range".to_string()))
}

fn clone_session(session: &RemoteSession) -> RemoteSession {
    RemoteSession {
        global_session_id: session.global_session_id.clone(),
        backend_status: session.backend_status.clone(),
        record: session.record.as_ref().map(|record| RemoteSessionRecord {
            name: record.name.clone(),
            status: record.status.clone(),
            command: record.command.clone(),
        }),
        agent: session.agent.as_ref().map(|agent| RemoteAgent {
            name: agent.name.clone(),
        }),
        repo: session.repo.as_ref().map(|repo| RemoteRepo {
            full_name: repo.full_name.clone(),
            base_branch: repo.base_branch.clone(),
        }),
    }
}

fn console_endpoint(console: &Url, path: &str) -> Result<Url> {
    let mut url = console.clone();
    let joined = format!(
        "{}/{}",
        url.path().trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    url.set_path(&joined);
    Ok(url)
}

fn terminal_url(console: &Url, session_id: &str) -> Result<Url> {
    let path = format!(
        "/api/v1/sessions/{}/terminal",
        urlencoding::encode(session_id)
    );
    let mut url = console_endpoint(console, &path)?;
    let websocket_scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(websocket_scheme)
        .map_err(|_| NonoError::ConfigParse("could not construct terminal URL".to_string()))?;
    Ok(url)
}

async fn attach(
    url: Url,
    token: Zeroizing<String>,
    detach_sequence: Vec<u8>,
) -> Result<AttachOutcome> {
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| NonoError::ConfigParse(format!("invalid terminal request: {error}")))?;
    let authorization = HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
        .map_err(|_| NonoError::ConfigParse("invalid connect token".to_string()))?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("nono.terminal.v1"),
    );

    let (socket, response) = tokio::time::timeout(
        WEBSOCKET_CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async(request),
    )
    .await
    .map_err(|_| {
        NonoError::ConfigParse("terminal connection timed out after 15 seconds".to_string())
    })?
    .map_err(|error| NonoError::ConfigParse(format!("terminal connection failed: {error}")))?;
    let selected_protocol = response
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok());
    if selected_protocol != Some("nono.terminal.v1") {
        return Err(NonoError::ConfigParse(
            "console did not negotiate the required nono.terminal.v1 protocol".to_string(),
        ));
    }
    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut input = vec![0_u8; 8192];
    let mut matcher = DetachMatcher::new(detach_sequence);
    let _terminal = RawTerminal::enter()?;
    let (cols, rows) = terminal_size();
    send_resize(&mut ws_tx, cols, rows).await?;
    let mut resize = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .map_err(NonoError::Io)?;

    loop {
        tokio::select! {
            read = stdin.read(&mut input) => {
                let read = read.map_err(NonoError::Io)?;
                if read == 0 {
                    send_detach(&mut ws_tx).await?;
                    return Ok(AttachOutcome::Detached);
                }
                let matched = matcher.push(&input[..read]);
                if !matched.forward.is_empty() {
                    ws_tx.send(Message::Binary(matched.forward.into()))
                        .await
                        .map_err(ws_error)?;
                }
                if matched.detach {
                    send_detach(&mut ws_tx).await?;
                    return Ok(AttachOutcome::Detached);
                }
            }
            _ = resize.recv() => {
                let (cols, rows) = terminal_size();
                send_resize(&mut ws_tx, cols, rows).await?;
            }
            message = ws_rx.next() => match message {
                Some(Ok(Message::Binary(bytes))) => {
                    stdout.write_all(&bytes).await.map_err(NonoError::Io)?;
                    stdout.flush().await.map_err(NonoError::Io)?;
                }
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<ServerControl>(text.as_str()) {
                        Ok(ServerControl::Attached { protocol_version, cols, rows }) => {
                            if protocol_version != "1" {
                                return Err(NonoError::ConfigParse(format!(
                                    "console selected unsupported terminal protocol {protocol_version}"
                                )));
                            }
                            let _ = (cols, rows);
                        }
                        Ok(ServerControl::SessionExited { exit_code: Some(0) }) => {
                            return Ok(AttachOutcome::SessionExited);
                        }
                        Ok(ServerControl::SessionExited { exit_code: Some(code) }) => {
                            if code < 0 {
                                return Err(NonoError::ConfigParse(
                                    "remote session returned an invalid negative exit status"
                                        .to_string(),
                                ));
                            }
                            REMOTE_EXIT_CODE.store(code, Ordering::Release);
                            return Ok(AttachOutcome::SessionExited);
                        }
                        Ok(ServerControl::SessionExited { exit_code: None }) => {
                            return Err(NonoError::ConfigParse(
                                "remote session ended without an exit status".to_string(),
                            ));
                        }
                        Ok(ServerControl::Error { code, message }) => {
                            let prefix = code.map(|value| format!("{value}: ")).unwrap_or_default();
                            return Err(NonoError::ConfigParse(format!("{prefix}{message}")));
                        }
                        Err(error) => {
                            return Err(NonoError::ConfigParse(format!(
                                "invalid terminal control frame: {error}"
                            )));
                        }
                    }
                }
                Some(Ok(Message::Ping(bytes))) => {
                    ws_tx.send(Message::Pong(bytes)).await.map_err(ws_error)?;
                }
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    return Err(NonoError::ConfigParse(
                        "terminal connection closed without a session-ended event".to_string(),
                    ));
                }
                Some(Err(error)) => return Err(ws_error(error)),
            }
        }
    }
}

fn ws_error(error: tokio_tungstenite::tungstenite::Error) -> NonoError {
    NonoError::ConfigParse(format!("terminal connection failed: {error}"))
}

async fn send_resize<S>(sink: &mut S, cols: u16, rows: u16) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let message = serde_json::json!({
        "type": "resize",
        "protocol_version": "1",
        "cols": cols,
        "rows": rows,
    });
    sink.send(Message::Text(message.to_string().into()))
        .await
        .map_err(ws_error)
}

async fn send_detach<S>(sink: &mut S) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let message = serde_json::json!({ "type": "detach", "protocol_version": "1" });
    sink.send(Message::Text(message.to_string().into()))
        .await
        .map_err(ws_error)
}

struct RawTerminal {
    original: nix::sys::termios::Termios,
}

impl RawTerminal {
    fn enter() -> Result<Self> {
        use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};
        let stdin = io::stdin();
        let original = tcgetattr(&stdin).map_err(|error| {
            NonoError::ConfigParse(format!("could not read terminal mode: {error}"))
        })?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&stdin, SetArg::TCSANOW, &raw).map_err(|error| {
            NonoError::ConfigParse(format!("could not enter raw terminal mode: {error}"))
        })?;
        Ok(Self { original })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        crate::pty_proxy::restore_terminal_modes_after_attach();
        let stdin = io::stdin();
        let _ = nix::sys::termios::tcsetattr(
            &stdin,
            nix::sys::termios::SetArg::TCSANOW,
            &self.original,
        );
    }
}

fn terminal_size() -> (u16, u16) {
    let mut size = nix::libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ only writes the fixed-size `winsize` structure.
    let result =
        unsafe { nix::libc::ioctl(nix::libc::STDOUT_FILENO, nix::libc::TIOCGWINSZ, &mut size) };
    if result == 0 && size.ws_col > 0 && size.ws_row > 0 {
        (size.ws_col, size.ws_row)
    } else {
        (80, 24)
    }
}

struct DetachMatch {
    forward: Vec<u8>,
    detach: bool,
}

struct DetachMatcher {
    sequence: Vec<u8>,
    pending_match_len: usize,
    pending_escape: Vec<u8>,
}

impl DetachMatcher {
    fn new(sequence: Vec<u8>) -> Self {
        Self {
            sequence,
            pending_match_len: 0,
            pending_escape: Vec::new(),
        }
    }

    fn push(&mut self, input: &[u8]) -> DetachMatch {
        let mut forward = Vec::with_capacity(input.len());
        for (index, &byte) in input.iter().enumerate() {
            if !self.pending_escape.is_empty() {
                self.pending_escape.push(byte);
                let Some(&expected) = self.sequence.get(self.pending_match_len) else {
                    self.flush_pending(&mut forward);
                    continue;
                };
                match crate::pty_proxy::match_enhanced_key_sequence(&self.pending_escape, expected)
                {
                    crate::pty_proxy::EnhancedKeyMatch::Pending => {
                        if self.pending_escape.len()
                            > crate::pty_proxy::MAX_ENHANCED_KEY_SEQUENCE_LEN
                        {
                            self.flush_pending(&mut forward);
                        }
                    }
                    crate::pty_proxy::EnhancedKeyMatch::Matched => {
                        self.pending_escape.clear();
                        self.pending_match_len += 1;
                        if self.pending_match_len == self.sequence.len() {
                            self.pending_match_len = 0;
                            return DetachMatch {
                                forward,
                                detach: true,
                            };
                        }
                    }
                    crate::pty_proxy::EnhancedKeyMatch::Invalid => {
                        self.flush_pending(&mut forward);
                    }
                }
                continue;
            }

            if self.sequence.is_empty() {
                forward.push(byte);
                continue;
            }

            if byte == self.sequence[self.pending_match_len] {
                self.pending_match_len += 1;
                if self.pending_match_len == self.sequence.len() {
                    self.pending_match_len = 0;
                    return DetachMatch {
                        forward,
                        detach: true,
                    };
                }
                continue;
            }

            if byte == b'\x1b'
                && input.get(index + 1).copied() == Some(b'[')
                && self
                    .sequence
                    .get(self.pending_match_len)
                    .copied()
                    .is_some_and(crate::pty_proxy::detach_key_supports_enhanced_match)
            {
                self.pending_escape.push(byte);
                continue;
            }

            if self.pending_match_len > 0 {
                forward.extend_from_slice(&self.sequence[..self.pending_match_len]);
                self.pending_match_len = 0;
                if byte == self.sequence[0] {
                    self.pending_match_len = 1;
                    continue;
                }
            }
            forward.push(byte);
        }
        DetachMatch {
            forward,
            detach: false,
        }
    }

    fn flush_pending(&mut self, forward: &mut Vec<u8>) {
        if self.pending_match_len > 0 {
            forward.extend_from_slice(&self.sequence[..self.pending_match_len]);
            self.pending_match_len = 0;
        }
        forward.extend_from_slice(&self.pending_escape);
        self.pending_escape.clear();
    }
}

#[cfg(test)]
impl DetachMatcher {
    fn pending_bytes(&self) -> bool {
        self.pending_match_len > 0 || !self.pending_escape.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn transport_refuses_cleartext_off_loopback() {
        assert!(
            validate_transport_url(&Url::parse("wss://console.example/terminal").unwrap()).is_ok()
        );
        assert!(
            validate_transport_url(&Url::parse("ws://127.0.0.1:8080/terminal").unwrap()).is_ok()
        );
        assert!(
            validate_transport_url(&Url::parse("ws://console.example/terminal").unwrap()).is_err()
        );
    }

    #[test]
    fn console_subpath_is_preserved() {
        let console = validate_console_url("https://example.test/nono").unwrap();
        let url = terminal_url(&console, "local:host:session").unwrap();
        assert_eq!(
            url.as_str(),
            "wss://example.test/nono/api/v1/sessions/local%3Ahost%3Asession/terminal"
        );
    }

    #[test]
    fn discovery_fixture_matches_enrollment_and_rejects_tenant_mismatch() {
        let state = crate::platform_client::PlatformState {
            protocol_version: "1".to_string(),
            platform_url: "https://platform.example.com".to_string(),
            tenant_id: "019f0000-0000-7000-8000-000000000001".to_string(),
            subject_id: "019f0000-0000-7000-8000-000000000002".to_string(),
            subject_kind: "device".to_string(),
            management_mode: "audit_only".to_string(),
            key_algorithm: "ecdsa_p256_sha256_fixed".to_string(),
            key_ref: "keystore:test".to_string(),
            enrolled_at: "2026-08-12T00:00:00Z".to_string(),
        };
        let fixture = include_str!("../../../tests/fixtures/console-discovery-v1.json");
        assert_eq!(
            validate_discovery_response(&state, fixture)
                .unwrap()
                .as_str(),
            "https://console.example.com/"
        );
        let mut wrong_tenant = state;
        wrong_tenant.tenant_id = "019f0000-0000-7000-8000-000000000099".to_string();
        assert!(validate_discovery_response(&wrong_tenant, fixture).is_err());
    }

    #[test]
    fn device_authorization_fixture_matches_client_contract() {
        let fixture = include_str!("../../../tests/fixtures/device-auth-v1.json");
        let response: DeviceCodeResponse = serde_json::from_str(fixture).unwrap();
        assert_eq!(response.protocol_version, DEVICE_AUTH_PROTOCOL_V1);
        assert_eq!(response.verification_path, DEVICE_AUTH_VERIFICATION_PATH);
        assert_eq!(response.expires_in, 600);
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn remote_ps_filters_live_sessions_and_sorts_by_name() {
        let sessions = vec![
            remote_session("session-exited", Some("zinc"), "ready", "exited"),
            remote_session("session-b", Some("birch"), "ready", "running"),
            remote_session("session-a", Some("alder"), "ready", "running"),
            remote_session("session-starting", Some("cedar"), "starting", "running"),
        ];

        let live = filter_remote_sessions(sessions, false);
        assert_eq!(live.len(), 2);
        assert_eq!(remote_name(&live[0]), "alder");
        assert_eq!(remote_name(&live[1]), "birch");

        let all = filter_remote_sessions(
            vec![
                remote_session("session-exited", Some("zinc"), "ready", "exited"),
                remote_session("session-a", Some("alder"), "ready", "running"),
            ],
            true,
        );
        assert_eq!(all.len(), 2);
        assert_eq!(remote_status(&all[1]), "exited");
    }

    fn remote_session(
        id: &str,
        name: Option<&str>,
        backend_status: &str,
        record_status: &str,
    ) -> RemoteSession {
        RemoteSession {
            global_session_id: id.to_string(),
            backend_status: backend_status.to_string(),
            record: Some(RemoteSessionRecord {
                name: name.map(str::to_string),
                status: record_status.to_string(),
                command: vec!["claude".to_string()],
            }),
            agent: Some(RemoteAgent {
                name: "Claude Code".to_string(),
            }),
            repo: None,
        }
    }

    #[test]
    fn detach_matcher_preserves_partial_and_mismatched_input() {
        let mut matcher = DetachMatcher::new(vec![0x1d, b'd']);
        let first = matcher.push(b"abc\x1d");
        assert_eq!(first.forward, b"abc");
        assert!(!first.detach);
        assert!(matcher.pending_bytes());
        let mismatch = matcher.push(b"x");
        assert_eq!(mismatch.forward, b"\x1dx");
        assert!(!mismatch.detach);
        let matched = matcher.push(b"z\x1ddtail");
        assert_eq!(matched.forward, b"z");
        assert!(matched.detach);
    }

    #[test]
    fn detach_matcher_accepts_csi_u_control_prefix() {
        let mut matcher = DetachMatcher::new(vec![0x1d, b'd']);
        let matched = matcher.push(b"\x1b[93;5ud");
        assert!(matched.forward.is_empty());
        assert!(matched.detach);
        assert!(!matcher.pending_bytes());
    }

    #[test]
    fn detach_matcher_accepts_chunked_csi_u_control_prefix() {
        let mut matcher = DetachMatcher::new(vec![0x1d, b'd']);
        let first = matcher.push(b"\x1b[93;");
        assert!(first.forward.is_empty());
        assert!(!first.detach);
        assert!(matcher.pending_bytes());
        let second = matcher.push(b"5u");
        assert!(second.forward.is_empty());
        assert!(!second.detach);
        let third = matcher.push(b"d");
        assert!(third.forward.is_empty());
        assert!(third.detach);
    }

    #[test]
    fn detach_matcher_forwards_unrelated_csi_u_input() {
        let mut matcher = DetachMatcher::new(vec![0x1d, b'd']);
        let unmatched = matcher.push(b"\x1b[99;5u");
        assert_eq!(unmatched.forward, b"\x1b[99;5u");
        assert!(!unmatched.detach);
        assert!(!matcher.pending_bytes());
    }

    #[test]
    fn direct_attach_url_rejects_url_credentials_and_queries() {
        assert!(
            validate_direct_attach_url(
                &Url::parse("wss://console.example/terminal?token=secret").unwrap()
            )
            .is_err()
        );
        assert!(
            validate_direct_attach_url(
                &Url::parse("wss://user:secret@console.example/terminal").unwrap()
            )
            .is_err()
        );
        assert!(validate_console_url("https://console.example?token=secret").is_err());
        assert!(validate_console_url("https://user@console.example").is_err());
    }
}
