//! Audit-only platform enrollment and protected local identity state.

use crate::cli::{
    PlatformArgs, PlatformCommands, PlatformEnrollArgs, PlatformStatusArgs, PlatformUnenrollArgs,
};
use crate::output::{SummaryKind, summary_heading, summary_row};
use crate::platform_oauth::{client::Organization, session::SessionRecord};
use crate::terminal_approval::sanitize_for_terminal as safe_text;
use crate::trust_keystore::{self, TrustKeyRef};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) const REQUEST_PROTOCOL_V1: &str = "1";
pub(crate) const ENROLLMENT_PROTOCOL_V1: &str = "1";
pub(crate) const KEY_ALGORITHM: &str = "ecdsa_p256_sha256_fixed";
const PLATFORM_KEY_SERVICE: &str = "nono-platform";
const PLATFORM_STATE_FILENAME: &str = "platform.json";
const RESPONSE_LIMIT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlatformState {
    pub protocol_version: String,
    pub platform_url: String,
    pub tenant_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub management_mode: String,
    pub key_algorithm: String,
    pub key_ref: String,
    pub enrolled_at: String,
}

#[derive(Debug, Serialize)]
struct EnrollmentExchangeRequest {
    protocol_version: String,
    token: String,
    subject_kind: String,
    display_name: Option<String>,
    key_algorithm: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EnrollmentExchangeResponse {
    #[serde(default)]
    pub replaces_subject_id: Option<String>,
    #[serde(default)]
    pub policy_trust_root: Option<crate::platform_policy::protocol::PolicyTrustRoot>,
    pub protocol_version: String,
    pub tenant_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub management_mode: String,
    pub enrolled_at: String,
}

pub(crate) fn run_platform(args: PlatformArgs) -> Result<()> {
    match args.command {
        PlatformCommands::Login(args) => crate::login_cmd::run_login(args),
        PlatformCommands::Logout(args) => crate::login_cmd::run_logout(args),
        PlatformCommands::Tenant(args) => crate::login_cmd::run_tenant(args),
        PlatformCommands::ReEnroll(mut args) => {
            args.re_enroll = true;
            crate::login_cmd::run_login(args)
        }
        PlatformCommands::Enroll(args) => enroll(args),
        PlatformCommands::Status(args) => status(args),
        PlatformCommands::Unenroll(args) => unenroll(args),
    }
}

fn enroll(args: PlatformEnrollArgs) -> Result<()> {
    let platform_url = validate_platform_url(&args.url)?;
    let state_path = state_path()?;
    if state_path.exists() {
        return Err(NonoError::ActionRequired(
            "a local enrollment already exists; inspect it with `nono platform status` or remove it with `nono platform unenroll` before manual enrollment".into(),
        ));
    }

    let key_ref = TrustKeyRef::parse(&args.keyref)?;
    let key_pair = load_or_create_signing_key_for_ref(&key_ref)?;

    let request = EnrollmentExchangeRequest {
        protocol_version: ENROLLMENT_PROTOCOL_V1.to_string(),
        token: args.token,
        subject_kind: if args.workload { "workload" } else { "device" }.to_string(),
        display_name: args.name,
        key_algorithm: KEY_ALGORITHM.to_string(),
        public_key: URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref()),
    };
    let response = post_enrollment(&platform_url, &request)?;
    if response.protocol_version != ENROLLMENT_PROTOCOL_V1
        || response.management_mode != "audit_only"
    {
        return Err(NonoError::ConfigParse(
            "platform returned an unsupported enrollment contract".to_string(),
        ));
    }
    validate_wire_identifier("tenant id", &response.tenant_id)?;
    validate_wire_identifier("subject id", &response.subject_id)?;

    let policy_trust_root = response.policy_trust_root;
    let state = PlatformState {
        protocol_version: response.protocol_version,
        platform_url,
        tenant_id: response.tenant_id,
        subject_id: response.subject_id,
        subject_kind: response.subject_kind,
        management_mode: response.management_mode,
        key_algorithm: KEY_ALGORITHM.to_string(),
        key_ref: args.keyref,
        enrolled_at: response.enrolled_at,
    };
    let stored = StoredEnrollment {
        state,
        login_user_id: None,
        display_name: request.display_name.clone(),
        tenant: None,
        revoked: false,
        last_policy_mode: None,
    };
    write_json_secure(&state_path, &stored)?;
    crate::platform_policy::pin_enrollment_key(&stored.state, policy_trust_root)?;
    print!(
        "{}",
        enrollment_text_with_heading(
            &stored,
            if stored.state.subject_kind == "workload" {
                "Workload enrolled"
            } else {
                "Device enrolled"
            },
            SummaryKind::Success,
            None,
        )
    );
    check_enrollment_policy(&stored.state)
}

pub(crate) fn check_enrollment_policy(state: &PlatformState) -> Result<()> {
    let checked = crate::platform_policy::refresh(state).and_then(|policy| {
        policy.ok_or_else(|| {
            NonoError::ActionRequired("platform returned no verified assignment".into())
        })
    });
    match checked {
        Ok(policy) => {
            print!(
                "{}",
                crate::platform_policy::display::enrollment_summary(&policy)
            );
            Ok(())
        }
        Err(error) => {
            tracing::warn!("Post-enrollment policy check failed; enrollment remains saved");
            let mut text = summary_heading("Policy check failed", SummaryKind::Attention);
            text.push_str(&summary_row("Enrollment", "Saved"));
            text.push_str(&summary_row("Policy", "Not verified"));
            text.push_str(&summary_row("Next step", "nono platform status --refresh"));
            println!("{text}");
            let subject = if state.subject_kind == "workload" {
                "Workload"
            } else {
                "Device"
            };
            Err(NonoError::ActionRequired(format!(
                "{subject} enrolled; policy check failed: {}\nEnrollment remains saved. Retry `nono platform status --refresh`; do not enrol again. Default startup still requires a successful policy check.",
                safe_text(&error.to_string())
            )))
        }
    }
}

fn status(args: PlatformStatusArgs) -> Result<()> {
    let context = crate::platform_oauth::session::load_record()?;
    let stored = match &context {
        Some(context) => load_for_session(context)?,
        None => read_state(&state_path()?)?,
    };
    // Old cache contents only inform the refresh message; a fresh reply can repair them.
    let previous = if args.refresh {
        stored
            .as_ref()
            .and_then(|stored| crate::platform_policy::cached(&stored.state).ok().flatten())
    } else {
        None
    };
    let policy = match &stored {
        Some(stored) if args.refresh => crate::platform_policy::refresh(&stored.state)?,
        Some(stored) => crate::platform_policy::cached(&stored.state)?,
        None if args.refresh => {
            return Err(NonoError::ActionRequired(
                "enrol this device before refreshing policy".into(),
            ));
        }
        None => None,
    };
    if args.json {
        let last_verified_mode = policy
            .as_ref()
            .filter(|_| args.refresh)
            .map(|policy| policy.management_mode.as_str())
            .or_else(|| {
                stored
                    .as_ref()
                    .and_then(|stored| stored.last_policy_mode.as_deref())
            });
        let mut output = match &stored {
            Some(stored) => serde_json::json!({
                "enrolled": !stored.revoked,
                "platform_url": stored.state.platform_url,
                "tenant_id": stored.state.tenant_id,
                "subject_id": stored.state.subject_id,
                "subject_kind": stored.state.subject_kind,
                "management_mode": policy.as_ref().map(|policy| policy.management_mode.as_str())
                    .or(last_verified_mode),
                "last_verified_management_mode": last_verified_mode,
                "enrolled_at": stored.state.enrolled_at,
            }),
            None => serde_json::json!({"enrolled": false}),
        };
        if stored.is_some() {
            output["policy_assignment"] =
                serde_json::to_value(&policy).map_err(|e| NonoError::ConfigParse(e.to_string()))?;
            output["policy_refreshed"] = serde_json::json!(args.refresh && policy.is_some());
        }
        if let Some(context) = &context {
            output["context"] = serde_json::json!({
                "platform_url": context.platform_url,
                "user_subject": context.user_subject,
                "user_display": context.user_display,
                "tenant_id": context.tenant_id,
                "tenant_selection_pending": context.tenant_selection_pending,
                "tenant": context.active_organization(),
                "sign_in": "stored_locally",
            });
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| NonoError::ConfigParse(error.to_string()))?
        );
    } else {
        print!(
            "{}",
            status_text(
                context.as_ref(),
                stored.as_ref(),
                policy.as_ref(),
                previous.as_ref(),
                args.refresh
            )
        );
    }
    Ok(())
}

fn status_text(
    context: Option<&crate::platform_oauth::session::SessionRecord>,
    stored: Option<&StoredEnrollment>,
    policy: Option<&crate::platform_policy::protocol::AssignmentClaims>,
    previous: Option<&crate::platform_policy::protocol::AssignmentClaims>,
    refreshed: bool,
) -> String {
    let t = crate::theme::current();
    let mut text = summary_heading("Platform", SummaryKind::Info);
    text.push_str(&summary_row(
        "User",
        &context
            .map(|context| safe_text(&context.user_display))
            .unwrap_or_else(|| "Not signed in".into()),
    ));
    let platform = context
        .map(|context| context.platform_url.as_str())
        .or_else(|| stored.map(|stored| stored.state.platform_url.as_str()));
    if let Some(platform) = platform {
        text.push_str(&summary_row("Server", &safe_text(platform)));
    }
    let tenant = match context {
        Some(context) if context.tenant_selection_pending => None,
        Some(context) => context.active_organization(),
        None => stored.and_then(|stored| stored.tenant.as_ref()),
    };
    let tenant = tenant
        .map(|tenant| {
            if tenant.kind == "personal" {
                "Personal".into()
            } else {
                tenant_label(tenant)
            }
        })
        .unwrap_or_else(|| "Not selected".into());
    text.push_str(&summary_row("Tenant", &tenant));
    if let Some(stored) = stored {
        let kind = if stored.state.subject_kind == "workload" {
            "Workload"
        } else {
            "Device"
        };
        let name = stored
            .display_name
            .as_deref()
            .map(safe_text)
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "Name not recorded".into());
        let device = format!(
            "{name} · {}",
            if stored.revoked {
                "revoked"
            } else {
                "enrolled"
            }
        );
        text.push_str(&summary_row(
            kind,
            &crate::theme::fg(&device, if stored.revoked { t.yellow } else { t.text }).to_string(),
        ));
        text.push_str(&crate::platform_policy::display::status_rows(
            policy,
            previous,
            refreshed,
            stored.last_policy_mode.as_deref(),
        ));
        let audit = if stored.revoked {
            Some("Unavailable · enrollment revoked".into())
        } else {
            match crate::audit_client::queued_count() {
                Ok(0) => None,
                Ok(count) => Some(format!("{count} pending uploads · all local queues")),
                Err(_) => Some("Queue status unavailable · run nono audit status".into()),
            }
        };
        if let Some(audit) = audit {
            text.push_str(&summary_row(
                "Audit",
                &crate::theme::fg(&audit, t.yellow).to_string(),
            ));
        }
    } else {
        text.push_str(&summary_row(
            "Device",
            &crate::theme::fg("Not enrolled", t.yellow).to_string(),
        ));
    }
    text.push('\n');
    text
}

pub(crate) fn tenant_label(tenant: &Organization) -> String {
    let name = safe_text(&tenant.display_name);
    if tenant.kind == "personal" {
        format!("{name} (personal)")
    } else if tenant.display_name == tenant.slug {
        format!("{name} (organization)")
    } else {
        format!("{name} ({})", safe_text(&tenant.slug))
    }
}

fn enrollment_text_with_heading(
    stored: &StoredEnrollment,
    title: &str,
    kind: SummaryKind,
    sign_in: Option<&str>,
) -> String {
    let state = &stored.state;
    let tenant = stored
        .tenant
        .as_ref()
        .filter(|tenant| tenant.tenant_id == state.tenant_id)
        .map(tenant_label)
        .unwrap_or_else(|| "Name not recorded (see --json)".into());
    let enrollment = if stored.revoked {
        "Revoked"
    } else {
        "Registered locally"
    };
    let delivery = if stored.revoked {
        "Unavailable: enrollment revoked"
    } else {
        "Automatic when sessions finish"
    };
    let mut text = summary_heading(title, kind);
    text.push_str(&summary_row("URL", &safe_text(&state.platform_url)));
    text.push_str(&summary_row("Audit tenant", &tenant));
    if let Some(sign_in) = sign_in {
        text.push_str(&summary_row("CLI sign-in", sign_in));
    }
    text.push_str(&summary_row("Enrollment", enrollment));
    text.push_str(&summary_row("Audit delivery", delivery));
    text.push_str(&enrollment_details(stored));
    text.push('\n');
    text
}

fn enrollment_details(stored: &StoredEnrollment) -> String {
    let name = stored
        .display_name
        .as_deref()
        .map(safe_text)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Name not recorded".into());
    let kind = if stored.state.subject_kind == "workload" {
        "Workload"
    } else {
        "Device"
    };
    let enrolled = chrono::DateTime::parse_from_rfc3339(&stored.state.enrolled_at)
        .map(|date| {
            date.with_timezone(&chrono::Utc)
                .format("%d %b %Y, %H:%M UTC")
                .to_string()
        })
        .unwrap_or_else(|_| "Not recorded".into());
    format!(
        "{}{}",
        summary_row(kind, &name),
        summary_row("Enrolled", &enrolled)
    )
}

/// Remove the local enrollment. Local-only by design: the platform-side
/// subject stays active until a human revokes it in the console, because the
/// device key must not be able to erase its own registration.
fn unenroll(args: PlatformUnenrollArgs) -> Result<()> {
    let state_path = state_path()?;
    let Some(state) = load_state()? else {
        println!("Not enrolled with a platform.");
        return Ok(());
    };
    let queued = crate::audit_client::queued_count()?;

    // Delete the key before the state file: the state holds the only key_ref,
    // so removing it first would orphan the key in the keystore if deletion
    // failed. Key removal is idempotent, so a failure here is retryable.
    if args.delete_key {
        let key_ref = TrustKeyRef::parse(&state.key_ref)?;
        let key_label = key_ref.key_id()?;
        trust_keystore::remove_secret_for_ref(&key_ref, PLATFORM_KEY_SERVICE, &key_label)?;
    }
    let active = read_state(&state_path)?;
    let user = crate::platform_oauth::session::load_record()?
        .map(|session| session.user_subject)
        .or_else(|| {
            active
                .as_ref()
                .and_then(|stored| stored.login_user_id.clone())
        });
    if let Some(user) = user {
        let path = scoped_state_path(&state.platform_url, &state.tenant_id, &user)?;
        if path.exists() {
            fs::remove_file(&path).map_err(|source| NonoError::ConfigWrite { path, source })?;
        }
    }
    if active
        .as_ref()
        .is_some_and(|stored| stored.state.subject_id == state.subject_id)
    {
        fs::remove_file(&state_path).map_err(|source| NonoError::ConfigWrite {
            path: state_path.clone(),
            source,
        })?;
    }
    let mut text = summary_heading("Device unenrolled locally", SummaryKind::Success);
    text.push_str(&summary_row("Platform", &safe_text(&state.platform_url)));
    text.push_str(&summary_row("Platform record", "Unchanged"));
    text.push_str(&summary_row(
        "Signing key",
        if args.delete_key {
            "Deleted locally"
        } else {
            "Retained locally"
        },
    ));
    if queued > 0 {
        text.push_str(&summary_row("Pending uploads", &queued.to_string()));
        text.push_str(&summary_row(
            "Audit history",
            "Evidence retains its original identity",
        ));
    }
    println!("{text}");
    Ok(())
}

fn post_enrollment(
    platform_url: &str,
    request: &EnrollmentExchangeRequest,
) -> Result<EnrollmentExchangeResponse> {
    let endpoint = endpoint_url(platform_url, "/api/v1/enrollment/exchange")?;
    let agent = http_agent(Duration::from_secs(15));
    let body = serde_json::to_string(request)
        .map_err(|error| NonoError::ConfigParse(format!("failed to encode enrollment: {error}")))?;
    let mut response = agent
        .post(&endpoint)
        .config()
        .http_status_as_error(false)
        .build()
        .header("Content-Type", "application/json")
        .send(&body)
        .map_err(|error| NonoError::ConfigParse(format!("enrollment request failed: {error}")))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let message = response
            .body_mut()
            .with_config()
            .limit(RESPONSE_LIMIT_BYTES)
            .read_to_string()
            .unwrap_or_default();
        return Err(NonoError::ConfigParse(format!(
            "platform enrollment returned HTTP {status}: {message}"
        )));
    }
    let response_body = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT_BYTES)
        .read_to_string()
        .map_err(|error| NonoError::ConfigParse(format!("invalid enrollment response: {error}")))?;
    serde_json::from_str(&response_body)
        .map_err(|error| NonoError::ConfigParse(format!("invalid enrollment response: {error}")))
}

#[derive(Serialize, Deserialize)]
struct StoredEnrollment {
    #[serde(flatten)]
    state: PlatformState,
    #[serde(default)]
    login_user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<Organization>,
    #[serde(default)]
    revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_policy_mode: Option<String>,
}

pub(crate) fn enrollment_scope_id(platform: &str, tenant: &str, user: &str) -> Result<String> {
    let scope = serde_json::to_vec(&(platform, tenant, user))
        .map_err(|_| NonoError::ConfigParse("invalid enrollment scope".into()))?;
    Ok(sha256_hex(&scope))
}

fn scoped_state_path(platform: &str, tenant: &str, user: &str) -> Result<PathBuf> {
    Ok(crate::state_paths::user_state_dir()?
        .join("platform-enrollments")
        .join(format!(
            "{}.json",
            enrollment_scope_id(platform, tenant, user)?
        )))
}

fn read_state(path: &Path) -> Result<Option<StoredEnrollment>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path).map_err(|source| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;
    let stored: StoredEnrollment = serde_json::from_str(&contents)
        .map_err(|_| NonoError::ConfigParse("invalid platform enrollment state".into()))?;
    let state = &stored.state;
    if state.protocol_version != ENROLLMENT_PROTOCOL_V1
        || state.key_algorithm != KEY_ALGORITHM
        || state.management_mode != "audit_only"
        || stored
            .last_policy_mode
            .as_deref()
            .is_some_and(|mode| !matches!(mode, "audit_only" | "advisory" | "enforced"))
    {
        return Err(NonoError::ConfigParse(
            "unsupported local platform enrollment state".into(),
        ));
    }
    validate_platform_url(&state.platform_url)?;
    validate_wire_identifier("tenant id", &state.tenant_id)?;
    validate_wire_identifier("subject id", &state.subject_id)?;
    Ok(Some(stored))
}

pub(crate) fn save_login_enrollment(
    state: PlatformState,
    session: &SessionRecord,
    display_name: &str,
) -> Result<()> {
    let path = scoped_state_path(&state.platform_url, &state.tenant_id, &session.user_subject)?;
    let last_policy_mode = if enforced_identity_is_active(&state)? {
        Some("enforced".into())
    } else {
        read_state(&path)?
            .filter(|stored| same_enrollment(&stored.state, &state))
            .and_then(|stored| stored.last_policy_mode)
    };
    let stored = login_enrollment(state, session, display_name, last_policy_mode);
    write_enrollment(&stored)
}

fn login_enrollment(
    state: PlatformState,
    session: &SessionRecord,
    display_name: &str,
    last_policy_mode: Option<String>,
) -> StoredEnrollment {
    StoredEnrollment {
        tenant: session
            .organizations
            .iter()
            .find(|tenant| tenant.tenant_id == state.tenant_id)
            .cloned(),
        state,
        login_user_id: Some(session.user_subject.clone()),
        display_name: Some(display_name.to_string()),
        revoked: false,
        last_policy_mode,
    }
}

pub(crate) fn save_login_replacement(
    state: PlatformState,
    session: &SessionRecord,
    display_name: &str,
    previous: &PlatformState,
    confirmed_previous: Option<&str>,
) -> Result<()> {
    if confirmed_previous != Some(previous.subject_id.as_str()) {
        return Err(NonoError::ActionRequired(
            "platform did not confirm policy-preserving replacement; upgrade the platform before recovery, or ask its administrator to review an existing replacement".into(),
        ));
    }
    if state.platform_url != previous.platform_url
        || state.tenant_id != previous.tenant_id
        || state.subject_id == previous.subject_id
        || state.key_ref == previous.key_ref
        || session.platform_url != state.platform_url
        || session.tenant_id != state.tenant_id
    {
        return Err(NonoError::ConfigParse(
            "replacement does not match the original enrollment scope".into(),
        ));
    }
    let old = current_enrollment(previous)?;
    if old
        .login_user_id
        .as_deref()
        .is_some_and(|user| user != session.user_subject)
    {
        return Err(NonoError::ActionRequired(
            "replacement must be authorized by the enrolled user".into(),
        ));
    }
    let stored = login_enrollment(state, session, display_name, old.last_policy_mode);
    // Only the authenticated recovery response may replace an enforced identity.
    write_json_secure(
        &scoped_state_path(
            &stored.state.platform_url,
            &stored.state.tenant_id,
            &session.user_subject,
        )?,
        &stored,
    )?;
    write_json_secure(&state_path()?, &stored)
}

fn same_enrollment(left: &PlatformState, right: &PlatformState) -> bool {
    left.platform_url == right.platform_url
        && left.tenant_id == right.tenant_id
        && left.subject_id == right.subject_id
        && left.key_ref == right.key_ref
}

pub(crate) fn enrollment_display_name() -> Result<Option<String>> {
    Ok(load_enrollment()?.and_then(|stored| stored.display_name))
}

fn current_enrollment(state: &PlatformState) -> Result<StoredEnrollment> {
    load_enrollment()?
        .filter(|stored| same_enrollment(&stored.state, state))
        .ok_or_else(|| {
            NonoError::ConfigParse("platform enrollment changed during policy refresh".into())
        })
}

pub(crate) fn last_policy_mode(state: &PlatformState) -> Result<Option<String>> {
    Ok(current_enrollment(state)?.last_policy_mode)
}

pub(crate) fn remember_policy_mode(state: &PlatformState, mode: &str) -> Result<()> {
    let mut stored = current_enrollment(state)?;
    if stored.last_policy_mode.as_deref() != Some(mode) {
        stored.last_policy_mode = Some(mode.into());
        write_enrollment(&stored)?;
    }
    Ok(())
}

fn write_enrollment(stored: &StoredEnrollment) -> Result<()> {
    let state = &stored.state;
    enforced_identity_is_active(state)?;
    if let Some(user) = &stored.login_user_id {
        write_json_secure(
            &scoped_state_path(&state.platform_url, &state.tenant_id, user)?,
            stored,
        )?;
    }
    write_json_secure(&state_path()?, stored)
}

fn enforced_identity_is_active(next: &PlatformState) -> Result<bool> {
    let active = read_state(&state_path()?)?;
    if let Some(active) = active
        && active.last_policy_mode.as_deref() == Some("enforced")
    {
        if !same_enrollment(&active.state, next) {
            return Err(NonoError::ActionRequired("enforced platform policy: changing the active enrollment requires a verified platform mode change first".into()));
        }
        return Ok(true);
    }
    Ok(false)
}

fn selected_enrollment(
    session: &crate::platform_oauth::session::SessionRecord,
) -> Result<Option<StoredEnrollment>> {
    let path = scoped_state_path(
        &session.platform_url,
        &session.tenant_id,
        &session.user_subject,
    )?;
    let stored = read_state(&path)?;
    if stored.as_ref().is_some_and(|stored| {
        stored.state.platform_url != session.platform_url
            || stored.state.tenant_id != session.tenant_id
            || stored.login_user_id.as_deref() != Some(session.user_subject.as_str())
    }) {
        return Err(NonoError::ConfigParse(
            "enrollment scope does not match the login".into(),
        ));
    }
    Ok(stored)
}

pub(crate) fn activate_login_enrollment(
    session: &crate::platform_oauth::session::SessionRecord,
) -> Result<()> {
    if let Some(stored) = selected_enrollment(session)?
        && !enforced_identity_is_active(&stored.state)?
    {
        write_json_secure(&state_path()?, &stored)?;
    }
    Ok(())
}

pub(crate) fn load_state() -> Result<Option<PlatformState>> {
    Ok(load_enrollment()?.map(|stored| stored.state))
}

pub(crate) fn load_active_state() -> Result<Option<PlatformState>> {
    Ok(load_enrollment()?
        .filter(|stored| !stored.revoked)
        .map(|stored| stored.state))
}

pub(crate) fn load_policy_state() -> Result<Option<PlatformState>> {
    let stored = load_enrollment()?;
    if stored.as_ref().is_some_and(|stored| stored.revoked) {
        return Err(NonoError::ActionRequired(
            "device enrollment was revoked; recover the enrollment before starting a session"
                .into(),
        ));
    }
    Ok(stored.map(|stored| stored.state))
}

pub(crate) fn enrollment_revoked() -> Result<bool> {
    Ok(load_enrollment()?.is_some_and(|stored| stored.revoked))
}

pub(crate) fn mark_revoked(state: &PlatformState) -> Result<()> {
    let Some(mut stored) = load_enrollment()? else {
        return Ok(());
    };
    if stored.state.subject_id != state.subject_id {
        return Ok(());
    }
    stored.revoked = true;
    write_enrollment(&stored)
}

fn with_tenant_label(mut stored: StoredEnrollment, session: &SessionRecord) -> StoredEnrollment {
    stored.tenant = session
        .organizations
        .iter()
        .find(|tenant| tenant.tenant_id == stored.state.tenant_id)
        .cloned()
        .or(stored.tenant);
    stored
}

fn load_enrollment() -> Result<Option<StoredEnrollment>> {
    let active = read_state(&state_path()?)?;
    if active
        .as_ref()
        .is_some_and(|stored| stored.last_policy_mode.as_deref() == Some("enforced"))
    {
        return Ok(active);
    }
    if let Some(session) = crate::platform_oauth::session::load_record()? {
        return load_for_session(&session);
    }
    Ok(active)
}

pub(crate) fn enrollment_for_login(session: &SessionRecord) -> Result<Option<PlatformState>> {
    Ok(load_for_session(session)?.map(|stored| stored.state))
}

fn load_for_session(session: &SessionRecord) -> Result<Option<StoredEnrollment>> {
    if session.tenant_selection_pending {
        return Ok(None);
    }
    if let Some(stored) = selected_enrollment(session)? {
        return Ok(Some(with_tenant_label(stored, session)));
    }
    Ok(read_state(&state_path()?)?
        .filter(|stored| {
            stored.state.platform_url == session.platform_url
                && stored.state.tenant_id == session.tenant_id
                && stored
                    .login_user_id
                    .as_deref()
                    .is_none_or(|user| user == session.user_subject)
        })
        .map(|stored| with_tenant_label(stored, session)))
}

pub(crate) fn load_signing_key(state: &PlatformState) -> Result<EcdsaKeyPair> {
    load_signing_key_for_ref(&TrustKeyRef::parse(&state.key_ref)?)
}

pub(crate) fn load_or_create_signing_key_for_ref(key_ref: &TrustKeyRef) -> Result<EcdsaKeyPair> {
    let key_label = key_ref.key_id()?;
    if trust_keystore::contains_secret_for_ref(key_ref, PLATFORM_KEY_SERVICE, &key_label)? {
        load_signing_key_for_ref(key_ref)
    } else {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).map_err(|_| {
                NonoError::KeystoreAccess("failed to generate platform key".to_string())
            })?;
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .map_err(|_| {
            NonoError::KeystoreAccess("failed to load generated platform key".to_string())
        })?;
        let private_key = Zeroizing::new(STANDARD.encode(pkcs8.as_ref()));
        trust_keystore::store_secret_for_ref(
            key_ref,
            PLATFORM_KEY_SERVICE,
            &key_label,
            private_key.as_str(),
        )?;
        Ok(key_pair)
    }
}

fn load_signing_key_for_ref(key_ref: &TrustKeyRef) -> Result<EcdsaKeyPair> {
    let key_label = key_ref.key_id()?;
    let encoded = match key_ref {
        TrustKeyRef::Keystore(_) => trust_keystore::load_secret(PLATFORM_KEY_SERVICE, &key_label)?,
        TrustKeyRef::File(path) => nono::load_secret_file(path)?,
    };
    let bytes =
        Zeroizing::new(STANDARD.decode(encoded.as_bytes()).map_err(|error| {
            NonoError::KeystoreAccess(format!("invalid platform key: {error}"))
        })?);
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes)
        .map_err(|_| NonoError::KeystoreAccess("invalid platform signing key".to_string()))
}

pub(crate) fn canonical_request_v1(
    method: &str,
    path: &str,
    subject_id: &str,
    timestamp_ms: &str,
    request_id: &str,
    body_digest: &str,
) -> String {
    format!(
        "nono-request-v1\n{method}\n{path}\n{subject_id}\n{timestamp_ms}\n{request_id}\n{body_digest}"
    )
}

#[derive(Debug)]
pub(crate) struct SignedRequestHeaders {
    pub(crate) timestamp: String,
    pub(crate) request_id: String,
    pub(crate) body_digest: String,
    pub(crate) signature: String,
}

pub(crate) fn sign_request_v1(
    state: &PlatformState,
    method: &str,
    path: &str,
    request_id: Uuid,
    body: &[u8],
) -> Result<SignedRequestHeaders> {
    let key_pair = load_signing_key(state)?;
    sign_request_v1_with_key(state, &key_pair, method, path, request_id, body)
}

/// Sign with a key already loaded, for callers that send many requests.
pub(crate) fn sign_request_v1_with_key(
    state: &PlatformState,
    key_pair: &EcdsaKeyPair,
    method: &str,
    path: &str,
    request_id: Uuid,
    body: &[u8],
) -> Result<SignedRequestHeaders> {
    let timestamp = current_timestamp_ms()?.to_string();
    let request_id = request_id.to_string();
    let body_digest = format!("sha256:{}", sha256_hex(body));
    let canonical = canonical_request_v1(
        method,
        path,
        &state.subject_id,
        &timestamp,
        &request_id,
        &body_digest,
    );
    let signature = key_pair
        .sign(&SystemRandom::new(), canonical.as_bytes())
        .map_err(|_| NonoError::KeystoreAccess("failed to sign platform request".to_string()))?;
    Ok(SignedRequestHeaders {
        timestamp,
        request_id,
        body_digest,
        signature: format!("p256-sha256={}", URL_SAFE_NO_PAD.encode(signature.as_ref())),
    })
}

fn current_timestamp_ms() -> Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| {
            NonoError::ConfigParse(format!("system clock is before Unix epoch: {error}"))
        })
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

pub(crate) fn endpoint_url(platform_url: &str, path: &str) -> Result<String> {
    let mut url = url::Url::parse(platform_url)
        .map_err(|error| NonoError::ConfigParse(format!("invalid platform URL: {error}")))?;
    if url.cannot_be_a_base() {
        return Err(NonoError::ConfigParse(format!(
            "invalid platform URL: {platform_url}"
        )));
    }
    // Url::join drops the base path when the endpoint starts with '/', which
    // would break a platform served under a subpath. Append instead.
    let joined = format!(
        "{}/{}",
        url.path().trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    url.set_path(&joined);
    Ok(url.to_string())
}

pub(crate) fn http_agent(global_timeout: Duration) -> ureq::Agent {
    let tls_config = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .timeout_global(Some(global_timeout))
        .timeout_resolve(Some(Duration::from_secs(2)))
        .timeout_connect(Some(Duration::from_secs(2)))
        .timeout_recv_response(Some(Duration::from_secs(5)))
        .tls_config(tls_config)
        .build()
        .new_agent()
}

/// Reject platform-supplied identifiers that could not be safely embedded in
/// HTTP headers or the newline-delimited canonical signing string. A malicious
/// platform must not be able to smuggle CRLF or separator bytes through
/// `subject_id`/`tenant_id` into later signed requests.
pub(crate) fn validate_wire_identifier(name: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 200
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(NonoError::ConfigParse(format!(
            "platform-supplied {name} contains unsupported characters"
        )))
    }
}

pub(crate) fn validate_platform_url(value: &str) -> Result<String> {
    let mut url = url::Url::parse(value)
        .map_err(|error| NonoError::ConfigParse(format!("invalid platform URL: {error}")))?;
    let loopback_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if url.scheme() != "https" && !loopback_http {
        return Err(NonoError::ConfigParse(
            "platform URL must use HTTPS; HTTP is allowed only for loopback dogfooding".to_string(),
        ));
    }
    url.set_query(None);
    url.set_fragment(None);
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn state_path() -> Result<PathBuf> {
    crate::config::user_config_dir()
        .map(|dir| dir.join(PLATFORM_STATE_FILENAME))
        .ok_or_else(|| {
            NonoError::ConfigParse("could not resolve nono config directory".to_string())
        })
}

pub(crate) fn write_json_secure<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| NonoError::ConfigParse(format!("path has no parent: {}", path.display())))?;
    fs::create_dir_all(parent).map_err(|source| NonoError::ConfigWrite {
        path: parent.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
        NonoError::ConfigWrite {
            path: parent.to_path_buf(),
            source,
        }
    })?;

    let encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| NonoError::ConfigParse(format!("failed to encode JSON: {error}")))?;

    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|source| NonoError::ConfigWrite {
            path: tmp.clone(),
            source,
        })?;
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|source| NonoError::ConfigWrite {
            path: tmp.clone(),
            source,
        })?;
    // Remove the temp file on any failure past this point: `create_new` means
    // a leftover would make every later write to this path fail permanently.
    let written = file.write_all(&encoded).and_then(|_| file.sync_all());
    if let Err(source) = written {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(NonoError::ConfigWrite { path: tmp, source });
    }
    drop(file);
    if let Err(source) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(NonoError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        });
    }
    if let Ok(parent_file) = File::open(parent) {
        let _ = parent_file.sync_all();
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct CanonicalFixture {
        method: String,
        path: String,
        subject_id: String,
        timestamp_ms: String,
        request_id: String,
        body_digest: String,
        canonical: String,
    }

    #[test]
    fn enrollment_scope_separates_instances_tenants_and_users() {
        let original = enrollment_scope_id("https://one.example", "acme", "alice").unwrap();
        for (issuer, tenant, user) in [
            ("https://two.example", "acme", "alice"),
            ("https://one.example", "personal", "alice"),
            ("https://one.example", "acme", "bob"),
        ] {
            assert_ne!(original, enrollment_scope_id(issuer, tenant, user).unwrap());
        }
    }

    #[test]
    fn enrollment_selection_is_scoped_and_unenrollment_preserves_other_tenants() {
        use crate::platform_oauth::session;
        use crate::test_env::{ENV_LOCK, EnvVarGuard};
        let _guard = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config");
        let state_home = home.path().join("state");
        fs::create_dir_all(&config).unwrap();
        let _env = EnvVarGuard::set_all(&[
            ("HOME", home.path().to_str().unwrap()),
            ("XDG_CONFIG_HOME", config.to_str().unwrap()),
            ("XDG_STATE_HOME", state_home.to_str().unwrap()),
        ]);
        let mut login = session::tests::record();
        let lock = session::lock().unwrap();
        session::save_record(&lock, &login).unwrap();
        let first = PlatformState {
            protocol_version: "1".into(),
            platform_url: login.platform_url.clone(),
            tenant_id: "t-1".into(),
            subject_id: "device-one".into(),
            subject_kind: "device".into(),
            management_mode: "audit_only".into(),
            key_algorithm: KEY_ALGORITHM.into(),
            key_ref: "keystore://fixture".into(),
            enrolled_at: "2026-11-10T00:00:00Z".into(),
        };
        save_login_enrollment(first.clone(), &login, "Laptop").unwrap();
        assert_eq!(last_policy_mode(&first).expect("mode"), None);
        remember_policy_mode(&first, "advisory").expect("remember advisory");
        save_login_enrollment(first.clone(), &login, "Laptop").expect("repeat login");
        assert_eq!(
            last_policy_mode(&first).expect("retained mode").as_deref(),
            Some("advisory")
        );
        mark_revoked(&first).unwrap();
        assert!(enrollment_revoked().unwrap());
        assert!(load_active_state().unwrap().is_none());
        assert_eq!(load_state().unwrap().unwrap().subject_id, "device-one");
        login.tenant_id = "t-2".into();
        session::save_record(&lock, &login).unwrap();
        assert!(load_state().unwrap().is_none());
        let second = PlatformState {
            tenant_id: "t-2".into(),
            subject_id: "device-two".into(),
            ..first.clone()
        };
        save_login_enrollment(second.clone(), &login, "Laptop").unwrap();
        assert_eq!(last_policy_mode(&second).expect("other tenant mode"), None);
        remember_policy_mode(&second, "enforced").unwrap();
        fs::remove_file(
            scoped_state_path(&second.platform_url, &second.tenant_id, &login.user_subject)
                .unwrap(),
        )
        .unwrap();
        save_login_enrollment(second.clone(), &login, "Laptop").unwrap();
        assert_eq!(
            last_policy_mode(&second).unwrap().as_deref(),
            Some("enforced"),
            "refreshing the same identity preserves enforcement even if its scoped copy was lost"
        );
        login.tenant_id = "t-1".into();
        login.tenant_selection_pending = true;
        session::save_record(&lock, &login).unwrap();
        assert_eq!(
            load_state().unwrap().unwrap().subject_id,
            "device-two",
            "enforced enrollment wins over changed or pending human context"
        );
        assert!(
            activate_login_enrollment(&login).is_err(),
            "lazy remote sign-in cannot activate another enrollment"
        );
        assert!(
            save_login_enrollment(first.clone(), &login, "Laptop").is_err(),
            "enrollment writes cannot bypass the identity guard"
        );
        assert_eq!(load_state().unwrap().unwrap().subject_id, "device-two");
        login.tenant_id = "t-2".into();
        login.tenant_selection_pending = false;
        session::save_record(&lock, &login).unwrap();
        remember_policy_mode(&second, "audit_only").expect("remember local");
        assert!(!enrollment_revoked().unwrap());
        login.tenant_id = "t-1".into();
        session::save_record(&lock, &login).unwrap();
        assert_eq!(load_state().unwrap().unwrap().subject_id, "device-one");
        assert_eq!(
            last_policy_mode(&first)
                .expect("original tenant mode")
                .as_deref(),
            Some("advisory")
        );
        assert!(enrollment_revoked().unwrap());
        login.user_subject = "another-user".into();
        session::save_record(&lock, &login).unwrap();
        assert!(load_state().unwrap().is_none());
        login.user_subject = "u".into();
        login.tenant_selection_pending = true;
        session::save_record(&lock, &login).unwrap();
        assert!(load_state().unwrap().is_none());
        login.tenant_selection_pending = false;
        session::save_record(&lock, &login).unwrap();
        unenroll(PlatformUnenrollArgs {
            delete_key: false,
            help: None,
        })
        .unwrap();
        assert!(load_state().unwrap().is_none());
        login.tenant_id = "t-2".into();
        session::save_record(&lock, &login).unwrap();
        assert_eq!(load_state().unwrap().unwrap().subject_id, "device-two");
    }

    #[test]
    fn replacement_requires_server_confirmation_and_preserves_enforcement() {
        use crate::platform_oauth::session;
        use crate::test_env::{ENV_LOCK, EnvVarGuard};
        let _guard = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config");
        fs::create_dir(&config).unwrap();
        let _env = EnvVarGuard::set_all(&[
            ("HOME", home.path().to_str().unwrap()),
            ("XDG_CONFIG_HOME", config.to_str().unwrap()),
            (
                "XDG_STATE_HOME",
                home.path().join("state").to_str().unwrap(),
            ),
        ]);
        let login = session::tests::record();
        let lock = session::lock().unwrap();
        session::save_record(&lock, &login).unwrap();
        let old = PlatformState {
            protocol_version: "1".into(),
            platform_url: login.platform_url.clone(),
            tenant_id: login.tenant_id.clone(),
            subject_id: "old-device".into(),
            subject_kind: "device".into(),
            management_mode: "audit_only".into(),
            key_algorithm: KEY_ALGORITHM.into(),
            key_ref: "keystore://old-device".into(),
            enrolled_at: "2026-11-23T00:00:00Z".into(),
        };
        save_login_enrollment(old.clone(), &login, "Laptop").unwrap();
        remember_policy_mode(&old, "enforced").unwrap();
        mark_revoked(&old).unwrap();
        let original = fs::read(state_path().unwrap()).unwrap();
        let replacement = PlatformState {
            subject_id: "new-device".into(),
            key_ref: "keystore://replacement".into(),
            ..old.clone()
        };
        for confirmation in [None, Some("wrong-device")] {
            assert!(
                save_login_replacement(replacement.clone(), &login, "Laptop", &old, confirmation)
                    .is_err()
            );
            assert_eq!(fs::read(state_path().unwrap()).unwrap(), original);
        }
        let wrong_tenant = PlatformState {
            tenant_id: "another-tenant".into(),
            ..replacement.clone()
        };
        assert!(
            save_login_replacement(wrong_tenant, &login, "Laptop", &old, Some(&old.subject_id))
                .is_err()
        );
        let wrong_origin = PlatformState {
            platform_url: "https://other.example".into(),
            ..replacement.clone()
        };
        assert!(
            save_login_replacement(wrong_origin, &login, "Laptop", &old, Some(&old.subject_id))
                .is_err()
        );
        let wrong_key = PlatformState {
            key_ref: old.key_ref.clone(),
            ..replacement.clone()
        };
        assert!(
            save_login_replacement(wrong_key, &login, "Laptop", &old, Some(&old.subject_id))
                .is_err()
        );
        let mut wrong_user = login.clone();
        wrong_user.user_subject = "another-user".into();
        assert!(
            save_login_replacement(
                replacement.clone(),
                &wrong_user,
                "Laptop",
                &old,
                Some(&old.subject_id)
            )
            .is_err()
        );
        assert_eq!(fs::read(state_path().unwrap()).unwrap(), original);
        save_login_replacement(
            replacement.clone(),
            &login,
            "Laptop",
            &old,
            Some(&old.subject_id),
        )
        .unwrap();
        assert_eq!(
            load_state().unwrap().unwrap().subject_id,
            replacement.subject_id
        );
        assert_eq!(
            last_policy_mode(&replacement).unwrap().as_deref(),
            Some("enforced")
        );
        assert!(!enrollment_revoked().unwrap());
        assert!(load_policy_state().unwrap().is_some());
    }

    #[test]
    fn canonical_request_matches_protocol_fixture() {
        let fixture: CanonicalFixture = serde_json::from_str(include_str!(
            "../../../tests/fixtures/audit-request-v1.json"
        ))
        .expect("valid canonical request fixture");
        assert_eq!(
            canonical_request_v1(
                &fixture.method,
                &fixture.path,
                &fixture.subject_id,
                &fixture.timestamp_ms,
                &fixture.request_id,
                &fixture.body_digest,
            ),
            fixture.canonical
        );
    }

    #[test]
    fn http_is_limited_to_loopback() {
        assert!(validate_platform_url("http://127.0.0.1:8090").is_ok());
        assert!(validate_platform_url("http://localhost:8090").is_ok());
        assert!(validate_platform_url("http://example.com").is_err());
        assert!(validate_platform_url("https://example.com").is_ok());
    }

    #[test]
    fn endpoint_url_preserves_a_platform_subpath() {
        assert_eq!(
            endpoint_url("https://example.com/platform", "/api/v1/audit/ingest").unwrap(),
            "https://example.com/platform/api/v1/audit/ingest"
        );
        assert_eq!(
            endpoint_url("https://example.com/platform/", "/api/v1/audit/ingest").unwrap(),
            "https://example.com/platform/api/v1/audit/ingest"
        );
        assert_eq!(
            endpoint_url("https://example.com", "/api/v1/audit/ingest").unwrap(),
            "https://example.com/api/v1/audit/ingest"
        );
        assert!(endpoint_url("data:text/plain,nope", "/api").is_err());
    }

    #[test]
    fn wire_identifiers_reject_header_and_canonical_separators() {
        assert!(validate_wire_identifier("subject id", "019fb1c9-fcae-7341").is_ok());
        assert!(validate_wire_identifier("tenant id", "testagent").is_ok());
        assert!(validate_wire_identifier("tenant id", "acme.prod_2").is_ok());
        assert!(validate_wire_identifier("subject id", "evil\r\nX-Injected: 1").is_err());
        assert!(validate_wire_identifier("subject id", "line\nbreak").is_err());
        assert!(validate_wire_identifier("tenant id", "").is_err());
        assert!(validate_wire_identifier("tenant id", &"a".repeat(201)).is_err());
        assert!(validate_wire_identifier("tenant id", "spaced value").is_err());
    }

    #[test]
    fn failed_write_json_secure_cleans_up_its_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        // A non-empty directory at the target makes the final rename fail.
        let target = dir.path().join("state.json");
        std::fs::create_dir_all(target.join("occupied")).unwrap();

        assert!(write_json_secure(&target, &serde_json::json!({"a": 1})).is_err());
        let tmp = target.with_extension(format!("tmp-{}", std::process::id()));
        assert!(!tmp.exists(), "temp file must not survive a failed write");

        // The same process can still write elsewhere — a leftover temp would
        // make create_new fail permanently.
        let ok_target = dir.path().join("ok.json");
        write_json_secure(&ok_target, &serde_json::json!({"a": 1})).unwrap();
        write_json_secure(&ok_target, &serde_json::json!({"a": 2})).unwrap();
    }
}
