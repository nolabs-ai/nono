//! Persistent Runs API launch followed by the open remote-attach protocol.

use std::io::{self, IsTerminal, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nono::{NonoError, Result};
use serde::{Deserialize, de::DeserializeOwned};
use url::Url;
use zeroize::Zeroizing;

use crate::output::{SummaryKind, summary_heading, summary_row};
use crate::platform_oauth::ApiCredential;

use crate::cli::{ConnectArgs, RemoteLaunchArgs};
use crate::{connect_client, platform_client};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Deserialize)]
struct Workspace {
    id: String,
    name: String,
    observed_state: String,
    repository_full_name: Option<String>,
}

#[derive(Deserialize)]
struct WorkspaceList {
    workspaces: Vec<Workspace>,
}

#[derive(Deserialize)]
struct AcceptedRun {
    run_id: uuid::Uuid,
}

#[derive(Deserialize)]
struct Run {
    state: String,
    session: Option<Session>,
    failure: Option<Failure>,
}

#[derive(Deserialize)]
struct Session {
    session_id: String,
}

#[derive(Deserialize)]
struct Failure {
    code: String,
}

pub(crate) fn run(args: RemoteLaunchArgs) -> Result<()> {
    let options = &args;
    if options.workspace.is_none() && (!io::stdin().is_terminal() || !io::stderr().is_terminal()) {
        return Err(action(
            "--workspace is required without an interactive terminal",
        ));
    }
    if !args.detached && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        return Err(action(
            "remote attachment requires a terminal; use --detach to launch without attaching",
        ));
    }
    let prompt = match args.command.as_slice() {
        [] => "",
        [prompt] => prompt
            .to_str()
            .ok_or_else(|| action("the prompt must be UTF-8"))?,
        _ => {
            return Err(action(
                "pass the initial instruction as one quoted argument",
            ));
        }
    };
    if prompt.len() > 64 * 1024 {
        return Err(action("the initial instruction exceeds 64 KiB"));
    }
    let agent = &options.agent;
    let connect_token_file = options
        .connect_token_file
        .clone()
        .or_else(|| std::env::var_os("NONO_CONNECT_TOKEN_FILE").map(std::path::PathBuf::from));
    let explicit_run =
        options.run_token_file.is_some() || std::env::var_os("NONO_RUN_TOKEN").is_some();
    let explicit_connect =
        connect_token_file.is_some() || std::env::var_os("NONO_CONNECT_TOKEN").is_some();
    let tenant = crate::platform_oauth::tenant_override(options.tenant.as_deref())?;
    if tenant.is_some() && (explicit_run || explicit_connect) {
        return Err(action(
            "tenant selection requires `nono platform login`; explicit tokens already have their own scope",
        ));
    }
    // Pin one refreshed tenant and credential through launch, polling and attach.
    let session = if !explicit_run || !explicit_connect {
        crate::platform_oauth::session_access(tenant.as_deref())?
    } else {
        None
    };
    if tenant.is_some() && session.is_none() {
        return Err(action(
            "tenant selection requires a platform sign-in; run `nono platform login`",
        ));
    }
    let (run_token, session_platform) = match options.run_token_file.as_deref() {
        Some(path) => (Arc::new(connect_client::load_token(Some(path))?), None),
        None => match std::env::var("NONO_RUN_TOKEN") {
            Ok(value) => {
                let token = Zeroizing::new(value);
                if token.is_empty()
                    || token.chars().any(char::is_whitespace)
                    || token.len() > 64 * 1024
                {
                    return Err(action(
                        "NONO_RUN_TOKEN must be a nonempty bearer token without whitespace",
                    ));
                }
                (Arc::new(ApiCredential::Bearer(token)), None)
            }
            Err(std::env::VarError::NotPresent) => match session.as_ref() {
                Some(access) => (
                    Arc::clone(&access.credential),
                    Some(access.platform_url.clone()),
                ),
                None => {
                    return Err(action(
                        "sign in with `nono platform login`, or set NONO_RUN_TOKEN or --run-token-file to a personal access token with runs:create and runs:read",
                    ));
                }
            },
            Err(_) => return Err(action("NONO_RUN_TOKEN is not valid UTF-8")),
        },
    };
    let platform = match (options.platform_url.as_deref(), &session_platform) {
        (Some(value), Some(signed_in)) => {
            let requested = platform_client::validate_platform_url(value)?;
            // Never hand the session's credential to another platform.
            if &requested != signed_in {
                return Err(action(&format!(
                    "you are signed in to {signed_in}, not {requested}; drop --platform-url or \
                     sign in to that platform"
                )));
            }
            connect_client::validate_console_url(&requested)?
        }
        (Some(value), None) => connect_client::validate_console_url(value)?,
        (None, Some(signed_in)) => connect_client::validate_console_url(signed_in)?,
        (None, None) => {
            let state = platform_client::load_state()?.ok_or_else(|| {
                action("remote launch requires `nono platform login`, platform enrollment or --platform-url")
            })?;
            connect_client::validate_console_url(&state.platform_url)?
        }
    };
    let console_override = options
        .console
        .clone()
        .or_else(|| std::env::var("NONO_CONSOLE_URL").ok());
    let console_access = connect_client::console_access_from_session(
        connect_token_file.as_deref(),
        if explicit_connect { None } else { session },
    )?;
    let console = connect_client::resolve_console(console_override.as_deref(), &console_access)?;
    let tenant_flag = console_access
        .session_tenant
        .as_ref()
        .map(|tenant| {
            let selector = if tenant.kind == "personal" {
                "personal"
            } else {
                &tenant.slug
            };
            format!(
                " {}",
                crate::command_display::format_command_line(&["--tenant", &safe_label(selector)])
            )
        })
        .unwrap_or_default();
    let workspaces: WorkspaceList =
        get(&console, "/api/v1/workspaces", &console_access.credential)?;
    let workspace = select_workspace(&workspaces.workspaces, options.workspace.as_deref())?;
    let payload = serde_json::json!({
        "agent_id": agent,
        "instructions": prompt,
        "execution_mode": "persistent",
        "workspace_id": workspace.id,
    });
    let idempotency_key = uuid::Uuid::now_v7().to_string();
    eprint!(
        "{}{}{}",
        summary_heading("Launching remote session", SummaryKind::Info),
        summary_row("Workspace", &safe_label(&workspace.name)),
        summary_row("Submission key", &idempotency_key)
    );
    let endpoint = platform_client::endpoint_url(platform.as_str(), "/api/v1/runs")?;
    let endpoint_url =
        Url::parse(&endpoint).map_err(|_| action("could not construct the Runs endpoint"))?;
    let mut request = platform_client::http_agent(Duration::from_secs(15))
        .post(&endpoint)
        .config()
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    for (name, value) in run_token.headers("POST", &endpoint_url)? {
        request = request.header(name, value.as_str());
    }
    let mut response = request
        .header("Idempotency-Key", &idempotency_key)
        .header("Content-Type", "application/json")
        .send(payload.to_string().as_bytes())
        .map_err(|_| action("Run submission could not be confirmed; check platform Runs before submitting again"))?;
    let accepted: AcceptedRun = decode(&mut response)?;
    let mut summary = summary_heading("Remote session queued", SummaryKind::Success);
    if let Some(tenant) = &console_access.session_tenant {
        summary.push_str(&summary_row(
            "Tenant",
            &platform_client::tenant_label(tenant),
        ));
    }
    summary.push_str(&summary_row("Workspace", &safe_label(&workspace.name)));
    summary.push_str(&summary_row("Run", &accepted.run_id.to_string()));
    summary.push_str(&summary_row(
        "Attachment",
        if args.detached {
            "Detached"
        } else {
            "Waiting for session"
        },
    ));
    println!("{summary}");
    if args.detached {
        eprintln!(
            "Launch queued. Use `nono remote list{tenant_flag}` to find the session, then `nono remote connect{tenant_flag} <session-id>`."
        );
        return Ok(());
    }
    let start = Instant::now();
    let path = format!("/api/v1/runs/{}", accepted.run_id);
    while start.elapsed() < STARTUP_TIMEOUT {
        let run: Run = get(&platform, &path, &run_token)?;
        if matches!(
            run.state.as_str(),
            "succeeded" | "failed" | "cancelled" | "cancelling"
        ) {
            let failure = run
                .failure
                .map(|failure| safe_label(&failure.code))
                .unwrap_or_default();
            return Err(action(&format!(
                "Run {} is {} {failure}; no attachment was made",
                accepted.run_id, run.state
            )));
        }
        if let Some(session) = run.session {
            validate_session_id(&session.session_id)?;

            return connect_client::run_connect_with_access(
                ConnectArgs {
                    target: Some(session.session_id),
                    console: Some(console.to_string()),
                    token_file: connect_token_file,
                    read_only: false,
                    help: None,
                    tenant: options.tenant.clone(),
                },
                console_access,
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(action(&format!(
        "Run {} is still queued; it has not been cancelled. Use `nono remote list{tenant_flag}` and connect when ready",
        accepted.run_id
    )))
}

// The Runs API returns an identity, never an arbitrary terminal URL. Keep the
// console credential bound to the discovered/configured console origin.
fn validate_session_id(value: &str) -> Result<()> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 3
        || !matches!(parts[0], "local" | "firecracker")
        || parts[1..].iter().any(|part| {
            part.is_empty()
                || part.len() > 64
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(action("platform returned an invalid session identity"));
    }
    Ok(())
}

fn select_workspace<'a>(
    workspaces: &'a [Workspace],
    selector: Option<&str>,
) -> Result<&'a Workspace> {
    let selected = if let Some(selector) = selector {
        resolve_workspace(workspaces, selector)?
    } else {
        if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
            return Err(action(
                "--workspace is required without an interactive terminal",
            ));
        }
        if workspaces.is_empty() {
            return Err(action(
                "no remote workspaces; create and start one in nono-console first",
            ));
        }
        for (index, workspace) in workspaces.iter().enumerate() {
            eprintln!(
                "  {}. {} [{}] {}",
                index + 1,
                safe_label(&workspace.name),
                safe_label(&workspace.observed_state),
                safe_label(workspace.repository_full_name.as_deref().unwrap_or(""))
            );
        }
        eprint!("Workspace number: ");
        io::stderr().flush().map_err(NonoError::Io)?;
        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(NonoError::Io)?;
        let index = input
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1));
        index
            .and_then(|index| workspaces.get(index))
            .ok_or_else(|| action("invalid workspace selection"))?
    };
    uuid::Uuid::parse_str(&selected.id)
        .map_err(|_| action("console returned an invalid workspace ID"))?;
    if selected.observed_state != "ready" {
        return Err(action(
            "the selected workspace is not ready; start it in nono-console first",
        ));
    }
    Ok(selected)
}

fn resolve_workspace<'a>(workspaces: &'a [Workspace], selector: &str) -> Result<&'a Workspace> {
    let matches: Vec<_> = workspaces
        .iter()
        .filter(|workspace| workspace.id == selector || workspace.name == selector)
        .collect();
    match matches.as_slice() {
        [workspace] => Ok(workspace),
        [] => Err(action("remote workspace not found")),
        _ => Err(action("workspace name is ambiguous; use its ID")),
    }
}

fn get<T: DeserializeOwned>(origin: &Url, path: &str, token: &ApiCredential) -> Result<T> {
    let endpoint = platform_client::endpoint_url(origin.as_str(), path)?;
    let endpoint_url =
        Url::parse(&endpoint).map_err(|_| action("could not construct the remote API URL"))?;
    let mut request = platform_client::http_agent(Duration::from_secs(15))
        .get(&endpoint)
        .config()
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    for (name, value) in token.headers("GET", &endpoint_url)? {
        request = request.header(name, value.as_str());
    }
    let mut response = request.call().map_err(|error| {
        action(&format!(
            "remote API request to {} failed: {error}; any accepted Run remains active",
            origin.origin().ascii_serialization()
        ))
    })?;
    decode(&mut response)
}

fn decode<T: DeserializeOwned>(response: &mut ureq::http::Response<ureq::Body>) -> Result<T> {
    if !response.status().is_success() {
        return Err(action(&format!(
            "remote API returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_string()
        .map_err(|_| action("could not read remote API response"))?;
    serde_json::from_str(&body).map_err(|_| action("remote API returned an invalid response"))
}

fn safe_label(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn action(message: &str) -> NonoError {
    NonoError::ActionRequired(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::CommandFactory;

    #[test]
    fn platform_cannot_redirect_console_credentials() -> Result<()> {
        validate_session_id("firecracker:workspace-123:session-123")?;
        for value in [
            "wss://another-host/api/v1/sessions/x/terminal",
            "local:host:x/y",
            "local::x",
            "local:host:x\n",
        ] {
            assert!(validate_session_id(value).is_err());
        }
        Ok(())
    }

    #[test]
    fn remote_launch_rejects_local_policy_options() {
        for option in ["--allow-net", "--no-audit", "--rollback"] {
            assert!(
                Cli::command()
                    .try_get_matches_from(["nono", "remote", "run", "--agent", "claude", option])
                    .is_err()
            );
        }
        for suffix in [
            vec![],
            vec!["initial prompt"],
            vec!["--detached"],
            vec!["--tenant", "personal"],
        ] {
            let mut args = vec![
                "nono",
                "remote",
                "run",
                "--agent",
                "claude",
                "--workspace",
                "project",
            ];
            args.extend(suffix);
            assert!(Cli::command().try_get_matches_from(args).is_ok());
        }
    }

    #[test]
    fn workspace_selection_does_not_guess() -> Result<()> {
        let workspaces = vec![
            Workspace {
                id: uuid::Uuid::now_v7().to_string(),
                name: "project".into(),
                observed_state: "ready".into(),
                repository_full_name: None,
            },
            Workspace {
                id: uuid::Uuid::now_v7().to_string(),
                name: "project".into(),
                observed_state: "stopped".into(),
                repository_full_name: None,
            },
        ];
        assert!(resolve_workspace(&workspaces, "project").is_err());
        assert!(resolve_workspace(&workspaces, "missing").is_err());
        assert_eq!(
            select_workspace(&workspaces, Some(&workspaces[0].id))?.id,
            workspaces[0].id
        );
        assert!(select_workspace(&workspaces, Some(&workspaces[1].id)).is_err());
        Ok(())
    }
}
