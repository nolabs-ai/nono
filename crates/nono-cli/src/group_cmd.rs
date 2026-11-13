use nono::{NonoError, Result};

use crate::cli::{GroupArgs, GroupCommands};
use crate::enrollment_group::{self, EnrollmentGroup};
use crate::login_enrollment::{GroupAction, GroupRequest, GroupResponse};
use crate::output::{SummaryKind, summary_heading, summary_row};
use crate::platform_client;
use crate::platform_oauth::{
    self,
    client::{self, OAuthClient},
    session,
};

pub(crate) fn run(args: GroupArgs, silent: bool) -> Result<()> {
    crate::login_cmd::reject_if_sandboxed("platform group")?;
    platform_oauth::refresh_memberships()?;
    let lock = session::lock()?;
    let record = session::load_record()?.ok_or_else(not_signed_in)?;
    if record.tenant_selection_pending {
        return Err(NonoError::ActionRequired(
            "choose a tenant with `nono platform tenant use <tenant>`".into(),
        ));
    }
    let state = platform_client::load_active_state()?;
    let subject = state
        .as_ref()
        .filter(|state| state.subject_kind == "device")
        .map(|state| state.subject_id.clone());
    if !matches!(args.command, GroupCommands::List(_)) && subject.is_none() {
        return Err(NonoError::ActionRequired(
            "no active device enrollment in this tenant; run `nono platform login`".into(),
        ));
    }
    let (key, refresh) = platform_oauth::load_session_credentials(&lock, &record)?;
    let server = client::discover(&record.platform_url)?;
    let mut client = OAuthClient::new(&server, &key);
    let request = |action| GroupRequest {
        refresh_token: refresh.to_string(),
        tenant_id: record.tenant_id.clone(),
        user_id: record.user_subject.clone(),
        subject_id: subject.clone(),
        action,
    };
    let mut response = client.groups(&request(GroupAction::List))?;
    validate(&response, &record.tenant_id, subject.as_deref())?;
    let (action, json, title, fields) = match args.command {
        GroupCommands::List(args) => (None, args.json, "Platform groups", Vec::new()),
        GroupCommands::Memberships(args) => (None, args.json, "Group memberships", Vec::new()),
        GroupCommands::Add(args) => {
            let group = resolve(&response.groups, &args.group)?;
            (
                Some(GroupAction::Add {
                    group_id: group.group_id.clone(),
                }),
                args.json,
                "Group added",
                vec![(
                    "Added",
                    enrollment_group::labels(std::slice::from_ref(group)),
                )],
            )
        }
        GroupCommands::Remove(args) => {
            let groups = known_groups(&response);
            let group = resolve(&groups, &args.group)?;
            (
                Some(GroupAction::Remove {
                    group_id: group.group_id.clone(),
                }),
                args.json,
                "Group removed",
                vec![(
                    "Removed",
                    enrollment_group::labels(std::slice::from_ref(group)),
                )],
            )
        }
        GroupCommands::Move(args) => {
            let sources = known_groups(&response);
            let from = resolve(&sources, &args.from)?;
            let to = resolve(&response.groups, &args.to)?;
            if from.group_id == to.group_id {
                return Err(NonoError::ActionRequired(
                    "source and destination groups must differ".into(),
                ));
            }
            (
                Some(GroupAction::Move {
                    from: from.group_id.clone(),
                    to: to.group_id.clone(),
                }),
                args.json,
                "Group moved",
                vec![
                    ("From", enrollment_group::labels(std::slice::from_ref(from))),
                    ("To", enrollment_group::labels(std::slice::from_ref(to))),
                ],
            )
        }
    };
    let mutation = action.is_some();
    if let Some(action) = action {
        response = client.groups(&request(action))?;
        validate(&response, &record.tenant_id, subject.as_deref())?;
    }
    if let Some(subject) = &subject {
        platform_client::update_login_groups(&record, subject, response.memberships.clone()).map_err(|error| {
            NonoError::ActionRequired(format!("platform group request completed, but local status could not be refreshed: {error}; run `nono platform group memberships`"))
        })?;
    }
    if json {
        let data = serde_json::json!({
            "platform_url": record.platform_url, "tenant_id": record.tenant_id,
            "tenant": record.active_organization(), "subject_id": response.subject_id,
            "groups": response.groups, "memberships": response.memberships, "changed": response.changed,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&data)
                .map_err(|error| NonoError::ConfigParse(error.to_string()))?
        );
    } else if !silent {
        let changed = mutation && response.changed;
        let heading = if mutation && !changed {
            "Group memberships unchanged"
        } else {
            title
        };
        let mut text = summary_heading(
            heading,
            if changed {
                SummaryKind::Success
            } else {
                SummaryKind::Info
            },
        );
        text.push_str(&summary_row(
            "User",
            &crate::terminal_approval::sanitize_for_terminal(&record.user_display),
        ));
        text.push_str(&summary_row(
            "Current tenant",
            &record
                .active_organization()
                .map(platform_client::tenant_label)
                .unwrap_or_else(|| "Not selected".into()),
        ));
        if mutation {
            for (name, value) in fields {
                let name = match (changed, name) {
                    (false, "Added") => "Already in",
                    (false, "Removed") => "Not in",
                    _ => name,
                };
                text.push_str(&summary_row(name, &value));
            }
        }
        text.push_str(&memberships_row(&response.memberships));
        if title == "Platform groups" {
            text.push('\n');
            for group in &response.groups {
                let marker = if response
                    .memberships
                    .iter()
                    .any(|current| current.group_id == group.group_id)
                {
                    "*"
                } else {
                    " "
                };
                text.push_str(&format!(
                    "    {marker} {}\n",
                    enrollment_group::labels(std::slice::from_ref(group))
                ));
            }
            if response.groups.is_empty() {
                text.push_str("    No permitted groups.\n");
            }
        }
        text.push('\n');
        print!("{text}");
    }
    Ok(())
}

fn memberships_row(groups: &[EnrollmentGroup]) -> String {
    if groups.is_empty() {
        summary_row("Groups", "None")
    } else {
        platform_client::enrollment_group_row(groups)
    }
}

fn resolve<'a>(groups: &'a [EnrollmentGroup], selector: &str) -> Result<&'a EnrollmentGroup> {
    enrollment_group::resolve(groups, selector)?.ok_or_else(|| {
        NonoError::ActionRequired(
            "no matching group; run `nono platform group list --json` to see group IDs".into(),
        )
    })
}

fn validate(response: &GroupResponse, tenant: &str, subject: Option<&str>) -> Result<()> {
    if response.protocol_version != "1"
        || response.tenant_id != tenant
        || response.subject_id.as_deref() != subject
    {
        return Err(NonoError::ConfigParse(
            "platform returned mismatched group context".into(),
        ));
    }
    enrollment_group::validate(&response.groups)?;
    enrollment_group::validate(&response.memberships)
}

fn not_signed_in() -> NonoError {
    NonoError::ActionRequired("not signed in; run `nono platform login`".into())
}

fn known_groups(response: &GroupResponse) -> Vec<EnrollmentGroup> {
    let mut groups = response.groups.clone();
    for group in &response.memberships {
        if !groups
            .iter()
            .any(|candidate| candidate.group_id == group.group_id)
        {
            groups.push(group.clone());
        }
    }
    groups
}
