use std::{fs, path::PathBuf, time::Duration};

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    cli::{PlatformPolicyArgs, PlatformPolicyCommands, SandboxArgs},
    output::{SummaryKind, summary_heading, summary_row},
    platform_client::{self, PlatformState},
    platform_policy_protocol::{POLICY_PATH, PolicyClaims, SignedPolicy},
};

const LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct PolicySelection {
    pub enrollment: Option<PlatformState>,
    pub provenance: Value,
    pub platform: bool,
}

impl std::fmt::Debug for PolicySelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicySelection")
            .field("provenance", &self.provenance)
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct Cache {
    platform_url: String,
    signed: SignedPolicy,
}

fn error(message: impl Into<String>) -> NonoError {
    NonoError::ConfigParse(format!("platform policy: {}", message.into()))
}

fn directory() -> Result<PathBuf> {
    Ok(crate::state_paths::user_state_dir()?.join("platform-policies"))
}

fn scope(state: &PlatformState) -> Result<String> {
    Ok(platform_client::sha256_hex(
        &serde_json::to_vec(&(&state.platform_url, &state.tenant_id, &state.subject_id))
            .map_err(|e| error(e.to_string()))?,
    ))
}

fn cache_path(state: &PlatformState) -> Result<PathBuf> {
    Ok(directory()?.join(format!("{}.json", scope(state)?)))
}

fn pin_path(state: &PlatformState) -> Result<PathBuf> {
    Ok(directory()?.join(format!(
        "key-{}.json",
        platform_client::sha256_hex(state.platform_url.as_bytes())
    )))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<Option<T>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(error(format!("cannot read cached state: {e}"))),
    };
    if file.metadata().map_err(|e| error(e.to_string()))?.len() > LIMIT {
        return Err(error("cached state exceeds size limit"));
    }
    serde_json::from_reader(file)
        .map(Some)
        .map_err(|_| error("invalid cached state"))
}

fn verify(
    state: &PlatformState,
    signed: &SignedPolicy,
    request: Option<Uuid>,
) -> Result<PolicyClaims> {
    if signed.algorithm != platform_client::KEY_ALGORITHM || signed.payload.len() as u64 > LIMIT {
        return Err(error("unsupported signed response"));
    }
    let decode = |text: &str| {
        URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| error("invalid signature encoding"))
    };
    let public = decode(&signed.public_key)?;
    if public.len() != 65
        || signed.key_id != format!("sha256:{}", platform_client::sha256_hex(&public))
    {
        return Err(error("invalid signing key identity"));
    }
    let payload = decode(&signed.payload)?;
    let signature = decode(&signed.signature)?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public)
        .verify(&payload, &signature)
        .map_err(|_| error("signature verification failed"))?;
    let claims: PolicyClaims =
        serde_json::from_slice(&payload).map_err(|_| error("invalid signed claims"))?;
    if claims.protocol_version != "1"
        || claims.tenant_id != state.tenant_id
        || claims.subject_id != state.subject_id
        || Uuid::parse_str(&claims.request_id).is_err()
        || !matches!(
            claims.source.as_str(),
            "subject" | "group" | "unit_default" | "implicit_default"
        )
    {
        return Err(error("response does not match this enrollment"));
    }
    if let Some(request) = request
        && (claims.request_id != request.to_string()
            || chrono::Utc::now()
                .signed_duration_since(claims.issued_at)
                .num_seconds()
                .unsigned_abs()
                > 300)
    {
        return Err(error("stale or replayed response"));
    }
    match &claims.policy {
        Some(policy) => {
            if policy.profile_id.trim().is_empty()
                || policy.profile_id.len() > 200
                || policy.profile_id.chars().any(char::is_control)
                || policy.display_name.as_ref().is_some_and(|name| {
                    name.trim().is_empty()
                        || name.chars().count() > 200
                        || name.chars().any(char::is_control)
                })
                || policy.revision <= 0
                || claims.source == "implicit_default"
                || !valid_digest(&policy.content_digest)
                || (!policy.profile_json.is_empty()
                    && policy.content_digest != digest(&policy.profile_json))
            {
                return Err(error("invalid policy identity or content digest"));
            }
        }
        None if claims.source != "implicit_default" => {
            return Err(error("assigned policy document is missing"));
        }
        None => {}
    }
    let pin: Option<String> = read_json(&pin_path(state)?)?;
    if pin.as_ref().is_some_and(|pin| pin != &signed.public_key) {
        return Err(error(
            "platform signing key changed; verify the instance's signing key before updating local trust",
        ));
    }
    Ok(claims)
}

fn cached(state: &PlatformState) -> Result<Option<PolicyClaims>> {
    let Some(cache): Option<Cache> = read_json(&cache_path(state)?)? else {
        return Ok(None);
    };
    if cache.platform_url != state.platform_url || read_json::<String>(&pin_path(state)?)?.is_none()
    {
        return Err(error("cached instance identity does not match"));
    }
    let mut claims = verify(state, &cache.signed, None)?;
    if let Some(policy) = &claims.policy
        && policy.profile_json.is_empty()
    {
        let document: Option<String> = read_json(&document_path(state, &policy.content_digest)?)?;
        complete_document(&mut claims, document.as_deref())?;
    }
    Ok(Some(claims))
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()))
}

fn digest(document: &str) -> String {
    format!(
        "sha256:{}",
        platform_client::sha256_hex(document.as_bytes())
    )
}

fn complete_document(claims: &mut PolicyClaims, cached: Option<&str>) -> Result<()> {
    if let Some(policy) = &mut claims.policy
        && policy.profile_json.is_empty()
    {
        let cached = cached
            .filter(|document| digest(document) == policy.content_digest)
            .ok_or_else(|| {
                error("current policy is missing from the verified local cache; retry sync")
            })?;
        policy.profile_json = cached.to_owned();
    }
    Ok(())
}

fn sync(state: &PlatformState) -> Result<PolicyClaims> {
    // An unusable cache requests full content; the fresh response still needs the pinned key.
    let previous = cached(state).ok().flatten();
    let request = Uuid::new_v4();
    let headers = platform_client::sign_request_v1(state, "GET", POLICY_PATH, request, &[])?;
    let endpoint = platform_client::endpoint_url(&state.platform_url, POLICY_PATH)?;
    let mut request_builder = platform_client::http_agent(Duration::from_secs(15))
        .get(&endpoint)
        .config()
        .http_status_as_error(false)
        .build()
        .header(
            "x-nono-protocol-version",
            platform_client::REQUEST_PROTOCOL_V1,
        )
        .header("x-nono-subject-id", &state.subject_id)
        .header("x-nono-timestamp", &headers.timestamp)
        .header("x-nono-request-id", &headers.request_id)
        .header("x-nono-content-sha256", &headers.body_digest)
        .header("x-nono-signature", &headers.signature);
    if let Some(policy) = previous.as_ref().and_then(|claims| claims.policy.as_ref()) {
        request_builder =
            request_builder.header("if-none-match", format!("\"{}\"", policy.content_digest));
    }
    let mut response = request_builder
        .call()
        .map_err(|_| error("cannot reach the platform; retry or supply an explicit --profile"))?;
    if !response.status().is_success() {
        if response.status().as_u16() == 401 {
            return Err(error(
                "enrollment authentication was refused; check its status in the platform",
            ));
        }
        return Err(error(format!(
            "sync failed (HTTP {}); retry or supply an explicit --profile",
            response.status().as_u16()
        )));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(LIMIT)
        .read_to_string()
        .map_err(|_| error("invalid or oversized response"))?;
    let signed: SignedPolicy = serde_json::from_str(&body)
        .map_err(|_| error("platform does not support signed policy delivery"))?;
    let mut claims = verify(state, &signed, Some(request))?;
    complete_document(
        &mut claims,
        previous
            .as_ref()
            .and_then(|claims| claims.policy.as_ref())
            .map(|policy| policy.profile_json.as_str()),
    )?;
    if let Some(policy) = &claims.policy {
        let path = document_path(state, &policy.content_digest)?;
        let bundle: crate::profile_bundle::Bundle = serde_json::from_str(&policy.profile_json)
            .map_err(|_| error("platform did not deliver a complete policy bundle"))?;
        let entry = bundle.materialize(&path.with_extension(""))?;
        let _scope = bundle.activate(
            entry
                .parent()
                .ok_or_else(|| error("invalid bundle directory"))?,
        )?;
        let loaded = crate::profile::load_profile_no_migrate(
            entry.to_str().ok_or_else(|| error("invalid cache path"))?,
        )?;
        validate_host_behavior(&loaded)?;
        if read_json::<String>(&path).ok().flatten().as_deref()
            != Some(policy.profile_json.as_str())
        {
            platform_client::write_json_secure(&path, &policy.profile_json)?;
        }
    }
    platform_client::write_json_secure(&pin_path(state)?, &signed.public_key)?;
    platform_client::write_json_secure(
        &cache_path(state)?,
        &Cache {
            platform_url: state.platform_url.clone(),
            signed,
        },
    )?;
    Ok(claims)
}

fn validate_host_behavior(profile: &crate::profile::Profile) -> Result<()> {
    if profile.session_hooks.before.is_some() || profile.session_hooks.after.is_some() {
        return Err(error(
            "platform profiles cannot run host session hooks; use an explicit local --profile",
        ));
    }
    Ok(())
}

fn document_path(state: &PlatformState, digest: &str) -> Result<PathBuf> {
    let hash = digest
        .strip_prefix("sha256:")
        .filter(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| error("invalid document digest"))?;
    Ok(directory()?.join(format!("{}-{hash}.json", scope(state)?)))
}

pub(crate) fn select_for_run(
    args: &mut SandboxArgs,
) -> Result<Option<crate::profile_bundle::Scope>> {
    if args.policy_selection.is_some() {
        return Ok(None);
    }
    let nested = std::env::var_os("NONO_CAP_FILE").is_some();
    let _lock = if nested {
        None
    } else {
        Some(crate::platform_oauth::session::lock()?)
    };
    let enrollment = if nested {
        None
    } else {
        platform_client::load_active_state()?
    };
    let mut provenance = serde_json::json!({"source":"local_defaults"});
    let mut platform = false;
    let mut scope = None;
    if let Some(explicit) = &args.profile {
        provenance = serde_json::json!({"source":"explicit_profile", "profile": explicit});
    } else if let Some(state) = &enrollment {
        let claims = sync(state)?;
        if let Some(policy) = &claims.policy {
            if args.config.is_some() {
                return Err(error(
                    "an assigned policy cannot be combined with --config; use --profile for an explicit override",
                ));
            }
            let bundle: crate::profile_bundle::Bundle = serde_json::from_str(&policy.profile_json)
                .map_err(|_| error("invalid policy bundle"))?;
            let entry = bundle
                .materialize(&document_path(state, &policy.content_digest)?.with_extension(""))?;
            scope = Some(
                bundle.activate(
                    entry
                        .parent()
                        .ok_or_else(|| error("invalid bundle directory"))?,
                )?,
            );
            args.profile = Some(entry.to_string_lossy().into_owned());
            provenance = serde_json::json!({"source":"platform", "tenant_id":state.tenant_id, "subject_id":state.subject_id, "profile_id":policy.profile_id,"profile_name":policy_name(policy),"revision":policy.revision,"content_digest":policy.content_digest,"assignment_source":claims.source,"assignment_name":claims.source_name});
            platform = true;
        }
    }
    args.policy_selection = Some(PolicySelection {
        enrollment,
        provenance,
        platform,
    });
    Ok(scope)
}

pub(crate) fn record_resolved(
    args: &mut SandboxArgs,
    loaded: &crate::profile::Profile,
) -> Result<()> {
    if let Some(selection) = args.policy_selection.as_mut() {
        if selection.platform {
            validate_host_behavior(loaded)?;
        }
        let mut value = serde_json::to_value(loaded).map_err(|e| error(e.to_string()))?;
        value.sort_all_objects();
        selection.provenance["resolved_profile_digest"] = format!(
            "sha256:{}",
            platform_client::sha256_hex(value.to_string().as_bytes())
        )
        .into();
    }
    Ok(())
}

pub(crate) fn display_selection(args: &SandboxArgs, silent: bool) {
    let Some(selection) = &args.policy_selection else {
        return;
    };
    if !silent {
        let label = if selection.platform {
            format!(
                "{} · revision {} (platform)",
                selection.provenance["profile_name"]
                    .as_str()
                    .unwrap_or("Assigned policy"),
                selection.provenance["revision"]
            )
        } else if args.profile.is_some() {
            if selection.enrollment.is_some() {
                "Explicit profile · platform overridden".into()
            } else {
                "Explicit profile".into()
            }
        } else {
            "Local defaults".into()
        };
        eprint!(
            "{}",
            summary_row(
                "Policy",
                &crate::terminal_approval::sanitize_for_terminal(&label)
            )
        );
    }
}

pub(crate) fn origin(args: &SandboxArgs) -> Option<&str> {
    if args
        .policy_selection
        .as_ref()
        .is_some_and(|selection| selection.platform)
    {
        Some("platform-assigned")
    } else {
        args.profile.as_deref()
    }
}

fn policy_name(policy: &crate::platform_policy_protocol::PolicyDocument) -> String {
    crate::terminal_approval::sanitize_for_terminal(
        policy.display_name.as_deref().unwrap_or("Assigned policy"),
    )
}

fn sync_heading(previous: Option<&PolicyClaims>, current: Option<&PolicyClaims>) -> &'static str {
    let Some(previous) = previous else {
        return "Policy synced";
    };
    if current.is_some_and(|current| {
        previous.policy == current.policy
            && previous.source == current.source
            && previous.source_name == current.source_name
    }) {
        "Policy up to date"
    } else {
        "Policy updated"
    }
}

pub(crate) fn run(args: PlatformPolicyArgs, silent: bool) -> Result<()> {
    crate::login_cmd::reject_if_sandboxed("platform policy")?;
    let _lock = crate::platform_oauth::session::lock()?;
    let state = platform_client::load_active_state()?;
    let (json, show, refreshing) = match args.command {
        PlatformPolicyCommands::Status(args) => (args.json, false, false),
        PlatformPolicyCommands::Show(args) => (args.json, true, false),
        PlatformPolicyCommands::Sync(args) => (args.json, false, true),
    };
    let previous = if refreshing {
        state
            .as_ref()
            .and_then(|state| cached(state).ok().flatten())
    } else {
        None
    };
    let claims = match &state {
        Some(state) if refreshing => Some(sync(state)?),
        Some(state) => cached(state)?,
        None if refreshing => {
            return Err(NonoError::ActionRequired(
                "no active enrollment; run `nono platform login`".into(),
            ));
        }
        None => None,
    };
    if show {
        let claims = claims.as_ref().ok_or_else(|| {
            NonoError::ActionRequired("no cached policy; run `nono platform policy sync`".into())
        })?;
        let document = claims
            .policy
            .as_ref()
            .map(|policy| serde_json::from_str::<Value>(&policy.profile_json))
            .transpose()
            .map_err(|_| error("invalid cached document"))?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&document).map_err(|e| error(e.to_string()))?
            );
        } else if !silent {
            match document {
                Some(document) => println!(
                    "{}",
                    serde_json::to_string_pretty(&document).map_err(|e| error(e.to_string()))?
                ),
                None => println!("No platform policy assigned. Local sessions use local defaults."),
            }
        }
    } else if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"enrolled":state.is_some(),"platform_url":state.as_ref().map(|s|&s.platform_url),"tenant_id":state.as_ref().map(|s|&s.tenant_id),"subject_id":state.as_ref().map(|s|&s.subject_id),"cached":claims.is_some(),"last_sync":claims.as_ref().map(|c|c.issued_at),"source":claims.as_ref().map(|c|&c.source),"source_name":claims.as_ref().and_then(|c|c.source_name.as_deref()),"policy":claims.as_ref().and_then(|c|c.policy.as_ref()).map(|p|serde_json::json!({"profile_id":p.profile_id,"display_name":p.display_name,"revision":p.revision,"content_digest":p.content_digest}))})).map_err(|e|error(e.to_string()))?);
    } else if !silent {
        let mut text = summary_heading(
            if refreshing {
                sync_heading(previous.as_ref(), claims.as_ref())
            } else {
                "Platform policy"
            },
            if refreshing {
                SummaryKind::Success
            } else {
                SummaryKind::Info
            },
        );
        let context = crate::platform_oauth::session::load_record()?;
        if let Some(context) = context {
            text.push_str(&summary_row(
                "Current tenant",
                &context
                    .active_organization()
                    .map(platform_client::tenant_label)
                    .unwrap_or_else(|| "Not selected".into()),
            ));
        }
        if let Some(claims) = &claims {
            if let Some(policy) = &claims.policy {
                text.push_str(&summary_row(
                    "Policy",
                    &format!("{} · revision {}", policy_name(policy), policy.revision),
                ));
                let source = claims.source_name.as_deref().unwrap_or(&claims.source);
                text.push_str(&summary_row(
                    "Assigned via",
                    &crate::terminal_approval::sanitize_for_terminal(source),
                ));
            } else {
                text.push_str(&summary_row("Policy", "None assigned · local defaults"));
            }
            if !refreshing {
                text.push_str(&summary_row(
                    "Last sync",
                    &claims.issued_at.format("%d %b %Y, %H:%M UTC").to_string(),
                ));
                text.push_str(&summary_row(
                    "Status",
                    "Verified cache · checked before each run",
                ));
            }
        } else {
            text.push_str(&summary_row(
                "Policy",
                if state.is_some() {
                    "Not synced"
                } else {
                    "Local defaults"
                },
            ));
        }
        text.push('\n');
        print!("{text}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
