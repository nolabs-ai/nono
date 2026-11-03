//! `nono login` and `nono logout` (NEP-0009,
//! `docs/protocols/cli-login-v1.md`).
//!
//! `nono login` signs a person in to a nono platform with OAuth 2.0: the
//! browser opens the platform's sign-in page (GitHub or Google, with the
//! platform's onboarding for new accounts), and the CLI keeps a session that
//! remote commands use to act as that person in their organizations. The
//! default flow is authorization code + PKCE on a loopback redirect; the device
//! authorization grant is the fallback for SSH sessions, containers and
//! machines without a display. Tokens are DPoP-bound to a key generated for
//! the session. Nothing here enrolls a device.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nono::{NonoError, Result};
use sha2::{Digest, Sha256};
use url::Url;

use crate::cli::{LoginArgs, LogoutArgs};
use crate::platform_client;
use crate::platform_oauth::client::{
    self, AuthorizationServer, CLIENT_ID, Grant, Identity, OAuthClient, TokenOutcome, TokenResponse,
};
use crate::platform_oauth::dpop::DpopKey;
use crate::platform_oauth::loopback::{
    CallbackResponder, CallbackResult, LoopbackListener, PendingCallback,
};
use crate::platform_oauth::{self, session};

/// The hosted nono platform, used when no platform is named or signed in to.
pub(crate) const DEFAULT_PLATFORM_URL: &str = "https://app.nolabs.ai";

/// How long the loopback flow waits for the person to finish in the browser.
const BROWSER_LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Fixed completion path on the platform origin (cli-login-v1).
const COMPLETE_PATH: &str = "/platform/cli/complete";
/// `error` value sent to the completion page when the CLI itself failed.
const CLIENT_ERROR_CODE: &str = "client_error";
const MAX_DEVICE_NAME_CHARS: usize = 64;
/// RFC 8628 §3.5: add 5 seconds on each `slow_down`.
const SLOW_DOWN_INCREMENT_SECS: u64 = 5;
const MAX_POLL_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Browser,
    DeviceCode,
}

/// A successful authorization: the tokens, plus the held browser request in
/// the loopback flow so the browser learns the final outcome.
struct Authorized {
    tokens: TokenResponse,
    responder: Option<CallbackResponder>,
}

pub(crate) fn run_login(args: LoginArgs) -> Result<()> {
    reject_if_sandboxed("login")?;
    let requested_url = args
        .url
        .as_deref()
        .map(platform_client::validate_platform_url)
        .transpose()?;

    // Hold the session lock while checking the existing session, but not
    // while waiting on the browser, so other nono commands are not blocked.
    let lock = session::lock()?;
    let mut previous_url = None;
    if let Some(record) = session::load_record()? {
        previous_url = Some(record.platform_url.clone());
        if let Some(url) = &requested_url
            && *url != record.platform_url
        {
            return Err(NonoError::ActionRequired(format!(
                "you are signed in to {}; run `nono logout` before signing in to another platform",
                record.platform_url
            )));
        }
        // Signed in already: confirm the session still works. An expired or
        // revoked one is cleared, and a fresh sign-in follows.
        match platform_oauth::session_access_locked(&lock, None) {
            Ok(Some(_)) => {
                if let Some(org) = &args.org {
                    switch_organization(&lock, org)?;
                }
                let record = session::load_record()?.ok_or_else(|| {
                    NonoError::ConfigParse("the local sign-in disappeared".to_string())
                })?;
                println!(
                    "Already signed in to {} as {}.",
                    record.platform_url, record.user_display
                );
                print_organizations(&record);
                return Ok(());
            }
            Ok(None) => {}
            Err(NonoError::ActionRequired(message)) => eprintln!("{message}"),
            Err(error) => return Err(error),
        }
    }

    drop(lock);

    let platform_url = choose_platform_url(requested_url, previous_url)?;
    // Discover before touching local state so a wrong URL leaves nothing behind.
    let server = client::discover(&platform_url)?;
    let new_key = session::create_key()?;
    let key = &new_key.key;
    let device_name = device_name(None);
    let mut authorized = authorize(
        &server,
        key,
        &platform_url,
        &platform_oauth::login_scope(),
        device_name.as_deref(),
        &args,
    )?;
    let outcome: Result<Identity> = (|| {
        let identity = validate_login_tokens(&authorized.tokens, &server)?;
        let refresh_token = authorized.tokens.refresh_token.take().ok_or_else(|| {
            NonoError::ConfigParse("platform did not issue a refresh token".to_string())
        })?;
        let record = session::new_record(
            &platform_url,
            &server.issuer,
            key,
            &identity,
            &authorized.tokens.session,
        );
        let lock = session::lock()?;
        session::store_session(&lock, &new_key, refresh_token.as_str(), &record)?;
        Ok(identity)
    })();
    finish_browser(authorized.responder, &platform_url, outcome.is_ok())?;
    let identity = outcome?;
    if let Some(org) = &args.org {
        switch_organization(&session::lock()?, org)?;
    }
    let record = session::load_record()?
        .ok_or_else(|| NonoError::ConfigParse("the local sign-in disappeared".to_string()))?;
    println!("Signed in to {platform_url} as {}.", identity.display);
    print_organizations(&record);
    Ok(())
}

pub(crate) fn run_logout(_args: LogoutArgs) -> Result<()> {
    reject_if_sandboxed("logout")?;
    let lock = session::lock()?;
    let record = match session::load_record() {
        Ok(Some(record)) => record,
        Ok(None) => {
            let leftover = session::secrets_present()?;
            session::clear(&lock)?;
            if leftover {
                return Err(NonoError::ActionRequired(
                    "removed leftover sign-in credentials, but without a sign-in record nono \
                     could not tell which platform to revoke them at; they were not revoked"
                        .to_string(),
                ));
            }
            println!("Not signed in.");
            return Ok(());
        }
        Err(error) => {
            session::clear(&lock)?;
            return Err(NonoError::ActionRequired(format!(
                "removed the local sign-in, but it could not be read ({error}), so it was not \
                 revoked on the platform"
            )));
        }
    };
    let revoked = match (session::load_key(), session::load_refresh_token()) {
        (Ok(Some(key)), Ok(Some(token))) => {
            client::discover(&record.platform_url).and_then(|server| {
                OAuthClient::new(&server, &key).revoke_refresh_token(token.as_str())
            })
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Err(NonoError::ActionRequired(
            "the local sign-in credentials are missing".to_string(),
        )),
    };
    // Local cleanup happens whatever the platform said.
    session::clear(&lock)?;
    match revoked {
        Ok(()) => {
            println!("Signed out of {}.", record.platform_url);
            Ok(())
        }
        Err(error) => Err(NonoError::ActionRequired(format!(
            "signed out locally, but the sign-in was not revoked on {}: {error}",
            record.platform_url
        ))),
    }
}

/// `--url` (or `NONO_PLATFORM_URL`), else the platform signed in to before,
/// else the hosted platform.
fn choose_platform_url(requested: Option<String>, previous: Option<String>) -> Result<String> {
    match requested.or(previous) {
        Some(url) => Ok(url),
        None => platform_client::validate_platform_url(DEFAULT_PLATFORM_URL),
    }
}

fn not_signed_in() -> NonoError {
    NonoError::ActionRequired("not signed in; run `nono login`".to_string())
}

/// Make `name` the active organization, after the platform confirms the
/// person is a member of it.
fn switch_organization(lock: &session::SessionLock, name: &str) -> Result<()> {
    let access =
        platform_oauth::session_access_locked(lock, Some(name))?.ok_or_else(not_signed_in)?;
    let mut record = session::load_record()?.ok_or_else(not_signed_in)?;
    record.tenant_id = access.organization.tenant_id;
    session::save_record(lock, &record)
}

/// List the person's organizations, marking the active one. This is the
/// CLI's only organization listing: `nono login` prints it on every run.
fn print_organizations(record: &session::SessionRecord) {
    print!("{}", organizations_text(record));
}

fn organizations_text(record: &session::SessionRecord) -> String {
    let mut text = String::from("Organizations (* active):\n");
    for org in &record.organizations {
        let marker = if org.tenant_id == record.tenant_id {
            '*'
        } else {
            ' '
        };
        let kind = if org.kind == "personal" {
            ", personal"
        } else {
            ""
        };
        text.push_str(&format!(
            "  {marker} {} ({}{kind})\n",
            org.display_name, org.slug
        ));
    }
    if record.organizations.len() > 1 {
        text.push_str(&format!(
            "Switch with `nono login --org <slug>`, or set {} for one command.\n",
            platform_oauth::ORG_ENV
        ));
    }
    text
}

/// Check everything a sign-in response must carry before anything is written.
fn validate_login_tokens(tokens: &TokenResponse, server: &AuthorizationServer) -> Result<Identity> {
    if tokens.refresh_token.is_none() {
        return Err(NonoError::ConfigParse(
            "platform did not issue a refresh token".to_string(),
        ));
    }
    let id_token = tokens
        .id_token
        .as_ref()
        .ok_or_else(|| NonoError::ConfigParse("platform did not issue an ID token".to_string()))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            NonoError::ConfigParse(format!("system clock is before Unix epoch: {error}"))
        })?
        .as_secs();
    client::identity_from_id_token(id_token.as_str(), &server.issuer, now)
}

fn authorize(
    server: &AuthorizationServer,
    key: &DpopKey,
    platform_url: &str,
    scope: &str,
    device_name: Option<&str>,
    args: &LoginArgs,
) -> Result<Authorized> {
    eprintln!("Session key fingerprint: {}", key.fingerprint());
    match choose_flow(args, server, is_headless())? {
        Flow::DeviceCode => device_flow(server, key, scope, device_name),
        Flow::Browser => match LoopbackListener::bind() {
            Ok(listener) => browser_flow(
                server,
                key,
                platform_url,
                scope,
                device_name,
                args.no_open,
                &listener,
            ),
            Err(error) if !args.browser && server.device_authorization_endpoint.is_some() => {
                eprintln!(
                    "Could not start the local sign-in listener ({error}); using a device code \
                     instead."
                );
                device_flow(server, key, scope, device_name)
            }
            Err(error) => Err(NonoError::ConfigParse(format!(
                "could not start the local sign-in listener: {error}"
            ))),
        },
    }
}

fn choose_flow(args: &LoginArgs, server: &AuthorizationServer, headless: bool) -> Result<Flow> {
    let has_browser_flow = server.authorization_endpoint.is_some();
    let has_device_flow = server.device_authorization_endpoint.is_some();
    let flow = if args.device_code {
        Flow::DeviceCode
    } else if args.browser {
        Flow::Browser
    } else if (headless || !has_browser_flow) && has_device_flow {
        Flow::DeviceCode
    } else {
        Flow::Browser
    };
    match flow {
        Flow::Browser if !has_browser_flow => Err(NonoError::ActionRequired(
            "the platform does not support browser sign-in; run `nono login --device-code`"
                .to_string(),
        )),
        Flow::DeviceCode if !has_device_flow => Err(NonoError::ActionRequired(
            "the platform does not support device-code sign-in; run `nono login --browser`"
                .to_string(),
        )),
        flow => Ok(flow),
    }
}

/// No local browser is likely: an SSH session, or (on Linux) no display.
fn is_headless() -> bool {
    let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    if set("SSH_CONNECTION") || set("SSH_TTY") {
        return true;
    }
    #[cfg(target_os = "linux")]
    if !set("DISPLAY") && !set("WAYLAND_DISPLAY") {
        return true;
    }
    false
}

fn browser_flow(
    server: &AuthorizationServer,
    key: &DpopKey,
    platform_url: &str,
    scope: &str,
    device_name: Option<&str>,
    no_open: bool,
    listener: &LoopbackListener,
) -> Result<Authorized> {
    let mut authorization_url = server.authorization_endpoint.clone().ok_or_else(|| {
        NonoError::ActionRequired("the platform does not support browser sign-in".to_string())
    })?;
    let state_param = platform_oauth::random_token()?;
    let code_verifier = platform_oauth::random_token()?;
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let redirect_uri = listener.redirect_uri();
    {
        let mut query = authorization_url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", CLIENT_ID)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", scope)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state_param.as_str())
            .append_pair("dpop_jkt", key.thumbprint());
        if let Some(name) = device_name {
            query.append_pair("device_name", name);
        }
    }

    eprintln!("Sign in to {platform_url} in your browser.");
    let opened = !no_open
        && match crate::connect_client::open_browser(authorization_url.as_str()) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("The browser could not be opened automatically: {error}");
                false
            }
        };
    if !opened {
        eprintln!("Open this URL to continue:");
        eprintln!("  {authorization_url}");
    }
    eprintln!("Waiting for sign-in to finish in the browser (Ctrl-C to cancel)...");

    let PendingCallback { responder, result } = listener.wait_for_callback(
        state_param.as_str(),
        &server.issuer,
        Instant::now() + BROWSER_LOGIN_TIMEOUT,
    )?;
    let code = match result {
        CallbackResult::Code(code) => code,
        CallbackResult::Error(error) => {
            responder.redirect(&completion_url(platform_url, Some(&error))?);
            return Err(NonoError::ActionRequired(format!(
                "sign-in was not completed: {error}"
            )));
        }
    };

    let exchanged = OAuthClient::new(server, key).token(&Grant::AuthorizationCode {
        code: code.as_str(),
        code_verifier: code_verifier.as_str(),
        redirect_uri: &redirect_uri,
    });
    match exchanged {
        Ok(TokenOutcome::Issued(tokens)) => Ok(Authorized {
            tokens,
            responder: Some(responder),
        }),
        Ok(TokenOutcome::Error(error)) => {
            responder.redirect(&completion_url(platform_url, Some(&error.code))?);
            Err(token_error(&error))
        }
        Err(error) => {
            responder.redirect(&completion_url(platform_url, Some(CLIENT_ERROR_CODE))?);
            Err(error)
        }
    }
}

fn device_flow(
    server: &AuthorizationServer,
    key: &DpopKey,
    scope: &str,
    device_name: Option<&str>,
) -> Result<Authorized> {
    let mut oauth = OAuthClient::new(server, key);
    let authorization = oauth.device_authorization(scope, device_name)?;
    // Only the plain verification URI is shown: the person must type the code
    // themselves (RFC 8628 §5.4 phishing mitigation).
    eprintln!("To sign in, open this URL on any device:");
    eprintln!("  {}", authorization.verification_uri);
    eprintln!("and enter the code:");
    eprintln!("  {}", authorization.user_code);
    eprintln!("Check that the page shows the session key fingerprint above.");

    let deadline = Instant::now() + Duration::from_secs(authorization.expires_in);
    let mut interval = authorization.interval;
    loop {
        let wait = Duration::from_secs(interval);
        if Instant::now() + wait >= deadline {
            return Err(NonoError::ActionRequired(
                "the sign-in code expired; run `nono login` again".to_string(),
            ));
        }
        std::thread::sleep(wait);
        match oauth.token(&Grant::DeviceCode {
            device_code: authorization.device_code.as_str(),
        })? {
            TokenOutcome::Issued(tokens) => {
                return Ok(Authorized {
                    tokens,
                    responder: None,
                });
            }
            TokenOutcome::Error(error) => match error.code.as_str() {
                "authorization_pending" => {}
                "slow_down" => {
                    interval = interval
                        .saturating_add(SLOW_DOWN_INCREMENT_SECS)
                        .min(MAX_POLL_INTERVAL_SECS);
                }
                "expired_token" => {
                    return Err(NonoError::ActionRequired(
                        "the sign-in code expired; run `nono login` again".to_string(),
                    ));
                }
                _ => return Err(token_error(&error)),
            },
        }
    }
}

fn token_error(error: &client::OAuthError) -> NonoError {
    match error.code.as_str() {
        "access_denied" => NonoError::ActionRequired("sign-in was denied".to_string()),
        _ => NonoError::ActionRequired(format!("sign-in failed: {error}")),
    }
}

/// Send the held browser request to the platform's fixed completion page.
/// The URL carries only the outcome: no codes, tokens or identifiers.
fn finish_browser(
    responder: Option<CallbackResponder>,
    platform_url: &str,
    succeeded: bool,
) -> Result<()> {
    if let Some(responder) = responder {
        let error = (!succeeded).then_some(CLIENT_ERROR_CODE);
        responder.redirect(&completion_url(platform_url, error)?);
    }
    Ok(())
}

fn completion_url(platform_url: &str, error: Option<&str>) -> Result<Url> {
    let mut url = Url::parse(&platform_client::endpoint_url(platform_url, COMPLETE_PATH)?)
        .map_err(|error| NonoError::ConfigParse(format!("invalid completion URL: {error}")))?;
    {
        let mut query = url.query_pairs_mut();
        match error {
            None => {
                query.append_pair("result", "success");
            }
            Some(code) => {
                let code = client::validate_error_code(code)
                    .unwrap_or_else(|_| CLIENT_ERROR_CODE.to_string());
                query
                    .append_pair("result", "error")
                    .append_pair("error", &code);
            }
        }
    }
    Ok(url)
}

/// The terminal label shown on the consent screen: the hostname, stripped of
/// control characters and bounded. The platform treats it as untrusted.
fn device_name(requested: Option<&str>) -> Option<String> {
    let raw = match requested {
        Some(name) => name.to_string(),
        None => default_device_name()?,
    };
    let clean: String = raw
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_DEVICE_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_string();
    (!clean.is_empty()).then_some(clean)
}

fn default_device_name() -> Option<String> {
    #[cfg(unix)]
    {
        nix::unistd::gethostname()
            .ok()
            .and_then(|name| name.into_string().ok())
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

fn reject_if_sandboxed(command: &str) -> Result<()> {
    // Defence in depth: the session lives in nono's protected state
    // directory, which no sandbox grant reaches, but refuse early and clearly.
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        return Err(NonoError::ActionRequired(format!(
            "`nono {command}` cannot be used inside a sandbox"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn server(browser: bool, device: bool) -> AuthorizationServer {
        let endpoint = |path: &str| Url::parse(&format!("https://nono.example.com{path}")).unwrap();
        AuthorizationServer {
            issuer: "https://nono.example.com".to_string(),
            authorization_endpoint: browser.then(|| endpoint("/oauth/authorize")),
            token_endpoint: endpoint("/oauth/token"),
            device_authorization_endpoint: device.then(|| endpoint("/oauth/device")),
            revocation_endpoint: Some(endpoint("/oauth/revoke")),
        }
    }

    fn args(browser: bool, device_code: bool) -> LoginArgs {
        LoginArgs {
            url: None,
            org: None,
            browser,
            device_code,
            no_open: false,
        }
    }

    #[test]
    fn flow_selection_prefers_browser_locally_and_device_code_headless() {
        let both = server(true, true);
        assert_eq!(
            choose_flow(&args(false, false), &both, false).unwrap(),
            Flow::Browser
        );
        assert_eq!(
            choose_flow(&args(false, false), &both, true).unwrap(),
            Flow::DeviceCode
        );
        assert_eq!(
            choose_flow(&args(true, false), &both, true).unwrap(),
            Flow::Browser
        );
        assert_eq!(
            choose_flow(&args(false, true), &both, false).unwrap(),
            Flow::DeviceCode
        );
    }

    #[test]
    fn flow_selection_follows_what_the_platform_supports() {
        assert_eq!(
            choose_flow(&args(false, false), &server(false, true), false).unwrap(),
            Flow::DeviceCode
        );
        assert_eq!(
            choose_flow(&args(false, false), &server(true, false), true).unwrap(),
            Flow::Browser
        );
        assert!(choose_flow(&args(true, false), &server(false, true), false).is_err());
        assert!(choose_flow(&args(false, true), &server(true, false), false).is_err());
    }

    #[test]
    fn completion_url_is_fixed_and_carries_only_the_outcome() {
        assert_eq!(
            completion_url("https://nono.example.com", None)
                .unwrap()
                .as_str(),
            "https://nono.example.com/platform/cli/complete?result=success"
        );
        assert_eq!(
            completion_url("https://example.com/sub", Some("access_denied"))
                .unwrap()
                .as_str(),
            "https://example.com/sub/platform/cli/complete?result=error&error=access_denied"
        );
        assert_eq!(
            completion_url("https://nono.example.com", Some("x&next=https://evil"))
                .unwrap()
                .as_str(),
            "https://nono.example.com/platform/cli/complete?result=error&error=client_error"
        );
    }

    #[test]
    fn the_hosted_platform_is_the_default() {
        assert_eq!(
            choose_platform_url(None, None).unwrap(),
            "https://app.nolabs.ai"
        );
        assert_eq!(
            choose_platform_url(None, Some("https://previous.example".to_string())).unwrap(),
            "https://previous.example"
        );
        assert_eq!(
            choose_platform_url(
                Some("https://self-hosted.example".to_string()),
                Some("https://previous.example".to_string())
            )
            .unwrap(),
            "https://self-hosted.example"
        );
    }

    #[test]
    fn device_names_are_cleaned_and_bounded() {
        assert_eq!(device_name(Some("  laptop  ")).as_deref(), Some("laptop"));
        assert_eq!(
            device_name(Some("evil\u{1b}[2J\nname")).as_deref(),
            Some("evil[2Jname")
        );
        assert_eq!(
            device_name(Some(&"x".repeat(500))).map(|name| name.len()),
            Some(MAX_DEVICE_NAME_CHARS)
        );
        assert_eq!(device_name(Some("\u{7}\u{7}")), None);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod fixture_tests {
    use super::*;
    use crate::platform_oauth::dpop;

    #[derive(serde::Deserialize)]
    struct Fixture {
        metadata_urls: Vec<MetadataCase>,
        dpop_htu: Vec<HtuCase>,
        completion_urls: Vec<CompletionCase>,
    }

    #[derive(serde::Deserialize)]
    struct MetadataCase {
        platform_url: String,
        metadata_url: String,
    }

    #[derive(serde::Deserialize)]
    struct HtuCase {
        request_url: String,
        htu: String,
    }

    #[derive(serde::Deserialize)]
    struct CompletionCase {
        platform_url: String,
        error: Option<String>,
        url: String,
    }

    #[test]
    fn cli_matches_the_cli_login_v1_fixture() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../../../tests/fixtures/cli-login-v1.json"))
                .unwrap();
        for case in fixture.metadata_urls {
            assert_eq!(
                client::metadata_url(&case.platform_url).unwrap().as_str(),
                case.metadata_url
            );
        }
        for case in fixture.dpop_htu {
            assert_eq!(
                dpop::proof_target_uri(&Url::parse(&case.request_url).unwrap()).unwrap(),
                case.htu
            );
        }
        for case in fixture.completion_urls {
            assert_eq!(
                completion_url(&case.platform_url, case.error.as_deref())
                    .unwrap()
                    .as_str(),
                case.url
            );
        }
    }

    #[test]
    fn login_lists_organizations_with_the_active_one_marked() {
        let mut record = session::tests::record();
        record.organizations[0].kind = "personal".to_string();
        assert_eq!(
            organizations_text(&record),
            "Organizations (* active):\n\
             \x20 * Alice (alice, personal)\n\
             \x20   Acme (acme)\n\
             \x20   ACME (acme-eu)\n\
             Switch with `nono login --org <slug>`, or set NONO_ORG for one command.\n"
        );
        // With one organization there is nothing to switch to.
        record.organizations.truncate(1);
        assert_eq!(
            organizations_text(&record),
            "Organizations (* active):\n  * Alice (alice, personal)\n"
        );
    }
}
