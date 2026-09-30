//! Terminal-native remote attach client for nono-console.
//!
//! The open wire contract is documented in `docs/protocols/remote-attach-v1.md`.
//! Human authentication is deliberately separate from device enrollment. This
//! explicit protected file or `NONO_CONNECT_TOKEN`. Otherwise an enrolled
//! device runs browser-approved human authorization, caches a device-bound
//! opaque credential, and exchanges it for a short-lived console bearer token.

use std::io::{self, IsTerminal, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

use colored::Colorize;
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
const TERMINAL_PROTOCOL_V1: &str = "nono.terminal.v1";
const SELECTOR_HEADER_ROWS: u16 = 7;
const SELECTOR_ROWS_PER_SESSION: u16 = 3;
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
    let outcome = runtime.block_on(attach(attach_url, token, detach_sequence));
    // Tokio's stdin uses an uncancellable blocking read. The terminal guard
    // has restored terminal settings when attach returns, but dropping the
    // runtime would wait for another keystroke before letting this CLI exit.
    runtime.shutdown_background();
    match outcome? {
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

    let enrollment = crate::platform_client::load_state()?;
    print_remote_sessions(
        &sessions,
        args.all,
        &console,
        enrollment.as_ref().map(|state| state.platform_url.as_str()),
    );
    Ok(())
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
        verify_attach_origin(&url, console)?;
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
    print_connect_target(&session, &console_url);
    terminal_url(&console_url, &session.global_session_id)
}

pub(crate) fn load_token(path: Option<&Path>) -> Result<Zeroizing<String>> {
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

pub(crate) fn validate_console_url(value: &str) -> Result<Url> {
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

pub(crate) fn discover_console() -> Result<Url> {
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

/// Whether `url` names one of the origins already authorized for this device.
///
/// Host comparison is by exact ASCII-case-insensitive equality on the parsed
/// host, never a string prefix: `evil-console.example` and
/// `console.example.evil.test` must not match `console.example`. Effective
/// ports must agree. Scheme is deliberately not compared, because an
/// authorized origin is an `https://` console while the attach URL that same
/// console issues is `wss://` on that host.
fn attach_origin_is_authorized(url: &Url, authorized: &[Url]) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let port = url.port_or_known_default();
    authorized.iter().any(|origin| {
        origin
            .host_str()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(host))
            && origin.port_or_known_default() == port
    })
}

/// Refuse to hand the console bearer token to an unenrolled origin.
///
/// A direct `wss://` target is taken verbatim from the command line, so it can
/// be a link the operator was sent rather than one the console issued.
/// `validate_direct_attach_url` only checks the URL's shape; without an origin
/// check, `nono connect wss://evil.example/api/v1/sessions/...` opens a socket
/// to an attacker and puts `Authorization: Bearer <console token>` in the
/// upgrade request, handing over live console access for the tenant.
///
/// Fail secure: the destination must be the console named by `--console`, the
/// enrolled platform, or the console that platform discloses. Anything else is
/// refused rather than confirmed interactively — a prompt here is answered
/// under exactly the pretext that motivated the attack.
fn verify_attach_origin(url: &Url, console: Option<&str>) -> Result<()> {
    // Loopback remains the documented development exception, as in
    // `validate_transport_url`. Reaching it already requires local code
    // execution, which outranks the credential this check protects.
    if is_loopback(url) {
        return Ok(());
    }

    let mut authorized = Vec::new();
    match console {
        Some(value) => authorized.push(validate_console_url(value)?),
        None => {
            if let Some(state) = crate::platform_client::load_state()?
                && let Ok(platform) = validate_console_url(&state.platform_url)
            {
                authorized.push(platform);
            }
            // Only pay for console discovery when the platform itself did not
            // already account for the target.
            if attach_origin_is_authorized(url, &authorized) {
                return Ok(());
            }
            authorized.push(discover_console()?);
        }
    }

    if attach_origin_is_authorized(url, &authorized) {
        return Ok(());
    }

    Err(NonoError::ActionRequired(format!(
        "refusing to send console credentials to '{}': it is not the enrolled platform or its \
         console. Run `nono connect` with no target to choose a session from the enrolled console, \
         or pass --console to name the console that issued this session.",
        url.host_str().unwrap_or("<no host>")
    )))
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
    Ok(filter_remote_sessions(
        fetch_sessions(console, token)?,
        false,
    ))
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

struct RemoteDisplayRow {
    session: String,
    name: String,
    status: String,
    agent: String,
    repo: String,
    live: bool,
}

impl RemoteDisplayRow {
    fn from_session(session: &RemoteSession) -> Self {
        Self {
            session: terminal_text(&session.global_session_id),
            name: terminal_text(remote_name(session)),
            status: terminal_text(remote_status(session)),
            agent: terminal_text(remote_agent(session)),
            repo: terminal_text(&remote_repo(session)),
            live: is_live_session(session),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RemoteTableLayout {
    widths: [usize; 5],
    compact: bool,
}

fn print_remote_sessions(
    sessions: &[RemoteSession],
    all: bool,
    console: &Url,
    platform_url: Option<&str>,
) {
    if let Some(platform_url) = platform_url {
        println!("  Platform: {}", terminal_text(platform_url));
    }
    if sessions.is_empty() {
        if all {
            eprintln!("No remote sessions found.");
        } else {
            eprintln!("No live remote sessions. Use --all to include inactive sessions.");
        }
        return;
    }

    let rows = sessions
        .iter()
        .map(RemoteDisplayRow::from_session)
        .collect::<Vec<_>>();
    let live_count = rows.iter().filter(|row| row.live).count();
    let summary = if all {
        format!("{live_count} live · {} total", rows.len())
    } else {
        format!("{} live", rows.len())
    };
    println!();
    println!(
        "  {}  {}  {}",
        "REMOTE SESSIONS".bold(),
        summary.dimmed(),
        console_label(console).dimmed(),
    );
    println!();

    let columns = remote_terminal_columns();
    let layout = remote_table_layout(&rows, columns);
    if layout.compact {
        print_remote_session_cards(&rows, columns);
    } else {
        print_remote_session_table(&rows, &layout);
    }
}

fn remote_table_layout(rows: &[RemoteDisplayRow], columns: usize) -> RemoteTableLayout {
    const HEADERS: [&str; 5] = ["NAME", "STATUS", "AGENT", "REPOSITORY", "SESSION"];
    const CAPS: [usize; 5] = [28, 14, 20, 36, 32];
    const MINIMUMS: [usize; 5] = [8, 8, 8, 10, 10];
    const SHRINK_ORDER: [usize; 5] = [3, 4, 2, 0, 1];
    const DECORATION_WIDTH: usize = 2;
    const SEPARATOR_WIDTH: usize = 4;

    if columns < 52 {
        return RemoteTableLayout {
            widths: MINIMUMS,
            compact: true,
        };
    }

    let mut widths = std::array::from_fn(|index| {
        rows.iter()
            .map(|row| remote_row_field(row, index).chars().count())
            .max()
            .unwrap_or(0)
            .max(HEADERS[index].len())
            .min(CAPS[index])
    });
    let mut total = DECORATION_WIDTH + SEPARATOR_WIDTH + widths.iter().sum::<usize>();
    while total > columns {
        let mut shrunk = false;
        for index in SHRINK_ORDER {
            if widths[index] > MINIMUMS[index] {
                widths[index] -= 1;
                total -= 1;
                shrunk = true;
                if total <= columns {
                    break;
                }
            }
        }
        if !shrunk {
            return RemoteTableLayout {
                widths,
                compact: true,
            };
        }
    }
    RemoteTableLayout {
        widths,
        compact: false,
    }
}

fn print_remote_session_table(rows: &[RemoteDisplayRow], layout: &RemoteTableLayout) {
    let [
        name_width,
        status_width,
        agent_width,
        repo_width,
        session_width,
    ] = layout.widths;
    println!(
        "  {} {} {} {} {}",
        pad_cell("NAME", name_width).dimmed(),
        pad_cell("STATUS", status_width).dimmed(),
        pad_cell("AGENT", agent_width).dimmed(),
        pad_cell("REPOSITORY", repo_width).dimmed(),
        pad_cell("SESSION", session_width).dimmed(),
    );
    for row in rows {
        let status = pad_cell(&row.status, status_width);
        println!(
            "{} {} {} {} {} {}",
            remote_status_dot(row),
            pad_cell(&row.name, name_width).bold(),
            color_remote_status(&status, row),
            pad_cell(&row.agent, agent_width),
            pad_cell(&row.repo, repo_width),
            pad_cell(&row.session, session_width).dimmed(),
        );
    }
}

fn print_remote_session_cards(rows: &[RemoteDisplayRow], columns: usize) {
    let content_width = columns.saturating_sub(4).max(12);
    for row in rows {
        let title = format!("{}  {}", row.name, row.status);
        let metadata = format!("{} · {}", row.agent, row.repo);
        println!(
            "{} {}",
            remote_status_dot(row),
            crate::command_display::truncate_chars(&title, content_width).bold(),
        );
        println!(
            "    {}",
            crate::command_display::truncate_chars(&metadata, content_width).dimmed(),
        );
        println!(
            "    {}",
            crate::command_display::truncate_chars(&row.session, content_width).dimmed(),
        );
    }
}

fn remote_row_field(row: &RemoteDisplayRow, index: usize) -> &str {
    match index {
        0 => &row.name,
        1 => &row.status,
        2 => &row.agent,
        3 => &row.repo,
        _ => &row.session,
    }
}

fn pad_cell(value: &str, width: usize) -> String {
    let value = crate::command_display::truncate_chars(value, width);
    format!("{value:<width$}")
}

fn remote_status_dot(row: &RemoteDisplayRow) -> String {
    let theme = crate::theme::current();
    if row.live {
        crate::theme::fg("●", theme.green).to_string()
    } else if row.status == "exited" || row.status == "failed" {
        crate::theme::fg("●", theme.red).to_string()
    } else {
        crate::theme::fg("●", theme.yellow).to_string()
    }
}

fn color_remote_status(status: &str, row: &RemoteDisplayRow) -> String {
    let theme = crate::theme::current();
    if row.live {
        crate::theme::fg(status, theme.green).to_string()
    } else if row.status == "exited" || row.status == "failed" {
        crate::theme::fg(status, theme.red).to_string()
    } else {
        crate::theme::fg(status, theme.yellow).to_string()
    }
}

fn remote_terminal_columns() -> usize {
    if let Ok(columns) = std::env::var("COLUMNS")
        && let Ok(columns) = columns.parse::<usize>()
        && columns > 0
    {
        return columns;
    }
    if io::stdout().is_terminal() {
        usize::from(terminal_size().0)
    } else {
        120
    }
}

fn console_label(console: &Url) -> String {
    let host = console.host_str().unwrap_or("remote console");
    let label = match console.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    terminal_text(&label)
}

fn terminal_text(value: &str) -> String {
    crate::terminal_approval::sanitize_for_terminal(value)
}

fn remote_name(session: &RemoteSession) -> &str {
    session
        .record
        .as_ref()
        .and_then(|record| record.name.as_deref())
        .unwrap_or("-")
}

fn remote_status(session: &RemoteSession) -> &str {
    if session.backend_status == "ready" {
        session
            .record
            .as_ref()
            .map(|record| record.status.as_str())
            .unwrap_or(&session.backend_status)
    } else {
        &session.backend_status
    }
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
    let terminal = SelectionTerminal::enter()?;
    let mut selected = 0;
    loop {
        draw_session_selector(sessions, selected)?;
        match read_selector_key(&io::stdin())? {
            SelectorKey::Up => selected = selected.checked_sub(1).unwrap_or(sessions.len() - 1),
            SelectorKey::Down => selected = (selected + 1) % sessions.len(),
            SelectorKey::Home => selected = 0,
            SelectorKey::End => selected = sessions.len() - 1,
            SelectorKey::Select => {
                drop(terminal);
                return sessions.get(selected).map(clone_session).ok_or_else(|| {
                    NonoError::ConfigParse("session selection is out of range".to_string())
                });
            }
            SelectorKey::Cancel => {
                return Err(NonoError::ActionRequired(
                    "remote session selection cancelled".to_string(),
                ));
            }
            SelectorKey::Ignore => {}
        }
    }
}

struct SelectionTerminal {
    _raw_terminal: RawTerminal,
}

impl SelectionTerminal {
    fn enter() -> Result<Self> {
        let raw_terminal = RawTerminal::enter()?;
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(b"\x1b[?1049h\x1b[?25l")
            .map_err(NonoError::Io)?;
        stdout.flush().map_err(NonoError::Io)?;
        Ok(Self {
            _raw_terminal: raw_terminal,
        })
    }
}

impl Drop for SelectionTerminal {
    fn drop(&mut self) {
        let mut stdout = io::stdout().lock();
        let _ = stdout.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = stdout.flush();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectorKey {
    Up,
    Down,
    Home,
    End,
    Select,
    Cancel,
    Ignore,
}

fn draw_session_selector(sessions: &[RemoteSession], selected: usize) -> Result<()> {
    let (columns, rows) = terminal_size();
    let columns = usize::from(columns);
    let visible = usize::from(
        rows.saturating_sub(SELECTOR_HEADER_ROWS)
            .checked_div(SELECTOR_ROWS_PER_SESSION)
            .unwrap_or(1)
            .max(1),
    )
    .min(sessions.len());
    let mut first = selected.saturating_sub(visible / 2);
    first = first.min(sessions.len().saturating_sub(visible));
    let last = first + visible;
    let theme = crate::theme::current();
    let mut stdout = io::stdout().lock();
    stdout.write_all(b"\x1b[2J\x1b[H").map_err(NonoError::Io)?;
    write_terminal_line(
        &mut stdout,
        &format!(
            "  {}  {}",
            "NONO CONNECT".bold(),
            format!("{} live remote sessions", sessions.len()).dimmed(),
        ),
    )?;
    write_terminal_line(&mut stdout, "")?;
    write_terminal_line(
        &mut stdout,
        &format!("  {}", "Choose a session to connect to".bold()),
    )?;
    write_terminal_line(
        &mut stdout,
        &format!(
            "  {}",
            "↑/↓ or j/k move  ·  enter connect  ·  q cancel".dimmed()
        ),
    )?;
    write_terminal_line(&mut stdout, "")?;

    for (index, session) in sessions.iter().enumerate().take(last).skip(first) {
        let row = RemoteDisplayRow::from_session(session);
        let active = index == selected;
        let pointer = if active {
            crate::theme::fg("❯", theme.brand).bold().to_string()
        } else {
            " ".to_string()
        };
        let display_name = if row.name == "-" {
            &row.session
        } else {
            &row.name
        };
        let title_width = columns.saturating_sub(8).max(12);
        let title = crate::command_display::truncate_chars(
            &format!("{display_name}  {}", row.status),
            title_width,
        );
        let title = if active {
            title.bold().to_string()
        } else {
            title
        };
        write_terminal_line(
            &mut stdout,
            &format!("  {pointer} {} {title}", remote_status_dot(&row)),
        )?;
        let metadata = crate::command_display::truncate_chars(
            &format!("{} · {}", row.agent, row.repo),
            columns.saturating_sub(7).max(12),
        );
        write_terminal_line(&mut stdout, &format!("      {}", metadata.dimmed()))?;
        let session_id =
            crate::command_display::truncate_chars(&row.session, columns.saturating_sub(7).max(12));
        write_terminal_line(&mut stdout, &format!("      {}", session_id.dimmed()))?;
    }

    if visible < sessions.len() {
        write_terminal_line(
            &mut stdout,
            &format!(
                "  {}",
                format!("showing {}–{} of {}", first + 1, last, sessions.len()).dimmed()
            ),
        )?;
    }
    stdout.flush().map_err(NonoError::Io)
}

fn write_terminal_line(output: &mut impl Write, line: &str) -> Result<()> {
    output.write_all(line.as_bytes()).map_err(NonoError::Io)?;
    output.write_all(b"\r\n").map_err(NonoError::Io)
}

// Read directly from the descriptor that we poll. Buffered stdin can read ahead
// past Escape, making an arrow key look like a standalone Escape to poll().
fn read_selector_byte(input: &impl AsFd) -> Result<u8> {
    let mut byte = [0_u8; 1];
    loop {
        match nix::unistd::read(input, &mut byte) {
            Ok(0) => {
                return Err(NonoError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "terminal input closed",
                )));
            }
            Ok(_) => return Ok(byte[0]),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(NonoError::Io(error.into())),
        }
    }
}

fn read_selector_key(input: &impl AsFd) -> Result<SelectorKey> {
    match read_selector_byte(input)? {
        b'k' | b'K' => Ok(SelectorKey::Up),
        b'j' | b'J' => Ok(SelectorKey::Down),
        b'g' => Ok(SelectorKey::Home),
        b'G' => Ok(SelectorKey::End),
        b'\r' | b'\n' => Ok(SelectorKey::Select),
        b'q' | b'Q' | 0x03 => Ok(SelectorKey::Cancel),
        0x1b => read_escape_key(input),
        _ => Ok(SelectorKey::Ignore),
    }
}

fn read_escape_key(input: &impl AsFd) -> Result<SelectorKey> {
    if !selector_input_pending(input, 40)? {
        return Ok(SelectorKey::Cancel);
    }
    let prefix = read_selector_byte(input)?;
    if !matches!(prefix, b'[' | b'O') {
        return Ok(SelectorKey::Ignore);
    }
    match read_selector_byte(input)? {
        b'A' => Ok(SelectorKey::Up),
        b'B' => Ok(SelectorKey::Down),
        b'H' => Ok(SelectorKey::Home),
        b'F' => Ok(SelectorKey::End),
        _ => Ok(SelectorKey::Ignore),
    }
}

fn selector_input_pending(input: &impl AsFd, timeout_ms: i32) -> Result<bool> {
    let mut descriptor = nix::libc::pollfd {
        fd: input.as_fd().as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `descriptor` points to one initialized `pollfd`, the count is
    // exactly one, and `poll` only mutates its `revents` field.
    let result = unsafe { nix::libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        return Err(NonoError::Io(io::Error::last_os_error()));
    }
    Ok(result > 0 && descriptor.revents & nix::libc::POLLIN != 0)
}

fn print_connect_target(session: &RemoteSession, console: &Url) {
    let row = RemoteDisplayRow::from_session(session);
    let display_name = if row.name == "-" {
        &row.session
    } else {
        &row.name
    };
    let theme = crate::theme::current();
    eprintln!();
    eprintln!(
        "  {} {}",
        crate::theme::fg("◆", theme.brand),
        display_name.bold(),
    );
    eprintln!(
        "    {}",
        format!("{} · {} · {}", row.agent, row.repo, console_label(console)).dimmed(),
    );
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

struct ConnectionProgress {
    destination: String,
    secure: bool,
    interactive: bool,
    frame: usize,
    active: bool,
}

impl ConnectionProgress {
    fn start(url: &Url) -> Self {
        let destination = console_label(url);
        let secure = url.scheme() == "wss";
        let progress = Self {
            destination,
            secure,
            interactive: io::stderr().is_terminal(),
            frame: 0,
            active: true,
        };
        progress.draw();
        progress
    }

    fn tick(&mut self) {
        if !self.interactive {
            return;
        }
        self.frame = (self.frame + 1) % 8;
        self.draw();
    }

    fn connected(&mut self, detach_sequence: &[u8]) {
        self.active = false;
        let theme = crate::theme::current();
        let mut stderr = io::stderr().lock();
        if self.interactive {
            let _ = stderr.write_all(b"\r\x1b[2K");
        }
        let title = if self.secure {
            "Secure remote connection established"
        } else {
            "Local development connection established"
        };
        let transport = if self.secure {
            "WSS · TLS encrypted"
        } else {
            "WS · loopback only"
        };
        let _ = writeln!(
            stderr,
            "  {} {}",
            crate::theme::fg("✓", theme.green).bold(),
            title.bold(),
        );
        let _ = writeln!(
            stderr,
            "    {}",
            format!(
                "{} · {} · {TERMINAL_PROTOCOL_V1}",
                self.destination, transport
            )
            .dimmed(),
        );
        let _ = writeln!(
            stderr,
            "    {} {}\n",
            "detach".dimmed(),
            format_detach_sequence(detach_sequence).bold(),
        );
        let _ = stderr.flush();
    }

    fn draw(&self) {
        const FRAMES: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
        let theme = crate::theme::current();
        let action = if self.secure {
            "Establishing encrypted connection to"
        } else {
            "Connecting to local development console at"
        };
        let mut stderr = io::stderr().lock();
        if self.interactive {
            let _ = write!(
                stderr,
                "\r\x1b[2K  {} {} {}",
                crate::theme::fg(FRAMES[self.frame], theme.brand),
                action,
                self.destination.bold(),
            );
            let _ = stderr.flush();
        } else if self.frame == 0 {
            let _ = writeln!(stderr, "  · {action} {}", self.destination);
        }
    }
}

impl Drop for ConnectionProgress {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let theme = crate::theme::current();
        let mut stderr = io::stderr().lock();
        if self.interactive {
            let _ = stderr.write_all(b"\r\x1b[2K");
        }
        let _ = writeln!(
            stderr,
            "  {} Connection to {} failed",
            crate::theme::fg("×", theme.red).bold(),
            self.destination.bold(),
        );
        let _ = stderr.flush();
    }
}

fn format_detach_sequence(sequence: &[u8]) -> String {
    sequence
        .iter()
        .map(|byte| match byte {
            0x00 => "Ctrl-@".to_string(),
            0x01..=0x1a => format!("Ctrl-{}", char::from(byte + b'@')),
            0x1b => "Esc".to_string(),
            0x1c => "Ctrl-\\".to_string(),
            0x1d => "Ctrl-]".to_string(),
            0x1e => "Ctrl-^".to_string(),
            0x1f => "Ctrl-_".to_string(),
            b' ' => "Space".to_string(),
            0x7f => "Backspace".to_string(),
            byte if byte.is_ascii_graphic() => char::from(*byte).to_string(),
            byte => format!("0x{byte:02x}"),
        })
        .collect::<Vec<_>>()
        .join(" then ")
}

async fn attach(
    mut url: Url,
    token: Zeroizing<String>,
    detach_sequence: Vec<u8>,
) -> Result<AttachOutcome> {
    let (initial_cols, initial_rows) = terminal_size();
    set_initial_terminal_size(&mut url, initial_cols, initial_rows);
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| NonoError::ConfigParse(format!("invalid terminal request: {error}")))?;
    let authorization = HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
        .map_err(|_| NonoError::ConfigParse("invalid connect token".to_string()))?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(TERMINAL_PROTOCOL_V1),
    );

    let mut progress = ConnectionProgress::start(&url);
    let connection = tokio::time::timeout(
        WEBSOCKET_CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async(request),
    );
    tokio::pin!(connection);
    let mut animation = tokio::time::interval(std::time::Duration::from_millis(90));
    let connection_result = loop {
        tokio::select! {
            result = &mut connection => break result,
            _ = animation.tick() => progress.tick(),
        }
    };
    let (socket, response) = connection_result
        .map_err(|_| {
            NonoError::ConfigParse("terminal connection timed out after 15 seconds".to_string())
        })?
        .map_err(|error| NonoError::ConfigParse(format!("terminal connection failed: {error}")))?;
    let selected_protocol = response
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok());
    if selected_protocol != Some(TERMINAL_PROTOCOL_V1) {
        return Err(NonoError::ConfigParse(
            "console did not negotiate the required nono.terminal.v1 protocol".to_string(),
        ));
    }
    progress.connected(&detach_sequence);
    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut input = vec![0_u8; 8192];
    let mut matcher = DetachMatcher::new(detach_sequence);
    let mut terminal = RawTerminal::enter()?;
    send_resize(&mut ws_tx, initial_cols, initial_rows).await?;
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
                    terminal.screen.observe(&bytes);
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

fn set_initial_terminal_size(url: &mut Url, cols: u16, rows: u16) {
    url.query_pairs_mut()
        .append_pair("cols", &cols.to_string())
        .append_pair("rows", &rows.to_string());
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
    screen: crate::pty_proxy::AltScreenTracker,
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
        Ok(Self {
            original,
            screen: Default::default(),
        })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        crate::pty_proxy::restore_terminal_modes_after_attach(
            self.screen.in_alt_screen,
            terminal_size().1,
        );
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
    fn selector_reads_queued_arrow_sequences_without_cancelling() -> Result<()> {
        let (input, mut writer) = std::os::unix::net::UnixStream::pair().map_err(NonoError::Io)?;
        writer
            .write_all(b"\x1b[B\x1b[A\x1bOB\x1bOA\x1b[H\x1b[F\r")
            .map_err(NonoError::Io)?;
        for expected in [
            SelectorKey::Down,
            SelectorKey::Up,
            SelectorKey::Down,
            SelectorKey::Up,
            SelectorKey::Home,
            SelectorKey::End,
            SelectorKey::Select,
        ] {
            assert_eq!(read_selector_key(&input)?, expected);
        }
        Ok(())
    }

    #[test]
    fn selector_standalone_escape_still_cancels() -> Result<()> {
        let (input, mut writer) = std::os::unix::net::UnixStream::pair().map_err(NonoError::Io)?;
        writer.write_all(b"\x1b").map_err(NonoError::Io)?;
        assert_eq!(read_selector_key(&input)?, SelectorKey::Cancel);
        Ok(())
    }

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
    fn terminal_upgrade_carries_initial_dimensions() {
        let mut url = Url::parse("wss://console.example/terminal").unwrap();
        set_initial_terminal_size(&mut url, 144, 48);
        assert_eq!(url.query(), Some("cols=144&rows=48"));
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

    #[test]
    fn remote_status_surfaces_backend_transition() {
        let session = remote_session("session-starting", Some("cedar"), "starting", "running");

        assert_eq!(remote_status(&session), "starting");
        assert!(!is_live_session(&session));
    }

    #[test]
    fn remote_display_rows_sanitize_console_fields() {
        let mut session = remote_session(
            "session\x1b[2J-hostile",
            Some("cedar\r\nspoofed"),
            "ready",
            "running",
        );
        session.agent = Some(RemoteAgent {
            name: "agent\x1b]0;title\x07".to_string(),
        });
        session.repo = Some(RemoteRepo {
            full_name: "org/repo\x1b[1m".to_string(),
            base_branch: "main".to_string(),
        });

        let row = RemoteDisplayRow::from_session(&session);

        assert!(!row.session.contains('\x1b'));
        assert!(!row.name.contains('\r'));
        assert!(!row.name.contains('\n'));
        assert!(!row.agent.contains('\x1b'));
        assert!(!row.repo.contains('\x1b'));
    }

    #[test]
    fn remote_table_layout_fits_terminal_width() {
        let sessions = [
            remote_session(
                "local:very-long-host-name:019f0000-0000-7000-8000-000000000001",
                Some("a-very-long-session-name-that-needs-truncation"),
                "ready",
                "running",
            ),
            remote_session("local:host:short", Some("birch"), "ready", "running"),
        ];
        let rows = sessions
            .iter()
            .map(RemoteDisplayRow::from_session)
            .collect::<Vec<_>>();

        let layout = remote_table_layout(&rows, 80);

        assert!(!layout.compact);
        assert!(layout.widths.iter().sum::<usize>() + 6 <= 80);
        assert!(remote_table_layout(&rows, 44).compact);
    }

    #[test]
    fn detach_sequence_has_readable_key_names() {
        assert_eq!(
            format_detach_sequence(DEFAULT_DETACH_SEQUENCE),
            "Ctrl-] then d"
        );
        assert_eq!(format_detach_sequence(&[0x03, b' ']), "Ctrl-C then Space");
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

    #[test]
    fn attach_origin_accepts_the_enrolled_console_across_schemes() {
        let authorized = vec![Url::parse("https://console.example").unwrap()];
        // The console is https; the terminal URL it issues is wss on that host.
        assert!(attach_origin_is_authorized(
            &Url::parse("wss://console.example/api/v1/sessions/abc/terminal").unwrap(),
            &authorized
        ));
        // Host comparison ignores ASCII case, as DNS does.
        assert!(attach_origin_is_authorized(
            &Url::parse("wss://Console.Example/api/v1/sessions/abc/terminal").unwrap(),
            &authorized
        ));
    }

    #[test]
    fn attach_origin_rejects_unenrolled_and_lookalike_hosts() {
        let authorized = vec![Url::parse("https://console.example").unwrap()];
        for hostile in [
            // Plainly unrelated.
            "wss://evil.com/api/v1/sessions/abc/terminal",
            // Suffix that a naive `starts_with` on the authorized host admits.
            "wss://console.example.evil.test/api/v1/sessions/abc/terminal",
            // Prefix that a naive `ends_with` admits.
            "wss://evil-console.example.attacker.test/api/v1/sessions/abc/terminal",
            // Right host, wrong port: a different service on shared infra.
            "wss://console.example:8443/api/v1/sessions/abc/terminal",
        ] {
            assert!(
                !attach_origin_is_authorized(&Url::parse(hostile).unwrap(), &authorized),
                "must refuse credentials to {hostile}"
            );
        }
    }

    #[test]
    fn attach_origin_rejects_everything_when_nothing_is_authorized() {
        assert!(!attach_origin_is_authorized(
            &Url::parse("wss://console.example/api/v1/sessions/abc/terminal").unwrap(),
            &[]
        ));
    }

    #[test]
    fn attach_origin_check_allows_loopback_development_targets() {
        // Reaches the loopback exception without consulting enrollment state,
        // matching the development carve-out in `validate_transport_url`.
        assert!(
            verify_attach_origin(&Url::parse("ws://127.0.0.1:8080/terminal").unwrap(), None)
                .is_ok()
        );
        assert!(
            verify_attach_origin(&Url::parse("ws://localhost:8080/terminal").unwrap(), None)
                .is_ok()
        );
    }

    #[test]
    fn attach_origin_refuses_host_not_matching_explicit_console() {
        let error = verify_attach_origin(
            &Url::parse("wss://evil.com/api/v1/sessions/abc/terminal").unwrap(),
            Some("https://console.example"),
        )
        .expect_err("an unenrolled host must be refused");
        assert!(
            matches!(error, NonoError::ActionRequired(_)),
            "expected an actionable refusal, got {error:?}"
        );
    }

    #[test]
    fn attach_origin_accepts_host_matching_explicit_console() {
        assert!(
            verify_attach_origin(
                &Url::parse("wss://console.example/api/v1/sessions/abc/terminal").unwrap(),
                Some("https://console.example"),
            )
            .is_ok()
        );
    }
}
