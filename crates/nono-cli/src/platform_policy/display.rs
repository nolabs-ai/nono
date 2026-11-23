use super::{PolicySession, protocol::*};
use crate::output::{SummaryKind, summary_heading, summary_row};
use crate::terminal_approval::sanitize_for_terminal as safe_text;
use crate::theme::{self, fg};
use chrono::{DateTime, Utc};

fn mode_label(mode: &str) -> &str {
    match mode {
        "audit_only" => "Local / audit only",
        "advisory" => "Advisory",
        "enforced" => "Enforced",
        other => other,
    }
}

pub(super) fn policy_name(policy: &AssignedBundle) -> String {
    if let Some(bundle) = &policy.bundle {
        let name = crate::profile::bundle::files::name(bundle);
        return safe_text(name.as_deref().unwrap_or(&policy.profile_id));
    }
    safe_text(&policy.profile_id)
}

pub(super) fn assigned_name(claims: &AssignmentClaims) -> Option<String> {
    let source = &claims.resolved_via;
    if claims
        .policy
        .as_ref()
        .is_none_or(|policy| source["profile_id"].as_str() == Some(policy.profile_id.as_str()))
        && let Some(name) = source["profile_name"]
            .as_str()
            .filter(|name| !name.trim().is_empty())
    {
        return Some(safe_text(name));
    }
    claims.policy.as_ref().map(policy_name)
}

pub(crate) fn session_summary(session: &PolicySession) -> String {
    let mut text = summary_heading("Policy", SummaryKind::Info);
    if let Some(profile) = &session.assigned_profile {
        let name = session.assigned_name.as_ref().unwrap_or(profile);
        let label = match session.assigned_revision {
            Some(revision) => format!("{} · revision {revision}", safe_text(name)),
            None => safe_text(name),
        };
        text.push_str(&summary_row("Profile", &label));
    }
    text.push_str(&summary_row(
        "Mode",
        &safe_text(mode_label(&session.management_mode)),
    ));
    let source = if session.policy_source == "platform" {
        "Platform"
    } else if session.management_mode == "advisory" {
        "Local profile override"
    } else {
        "Local profiles"
    };
    text.push_str(&summary_row("Source", source));
    if !session.overrides.is_empty() {
        let overrides = session
            .overrides
            .iter()
            .map(|name| format!("--{}", safe_text(name)))
            .collect::<Vec<_>>()
            .join(", ");
        let label = if session.management_mode == "enforced" {
            "Local options"
        } else {
            "Overrides"
        };
        text.push_str(&summary_row(label, &overrides));
    }
    text.push('\n');
    text
}

fn checked_at(issued: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let elapsed = (now - issued).num_seconds().max(0);
    let age = match elapsed {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", elapsed / 60),
        3600..86400 => format!("{} hr ago", elapsed / 3600),
        _ => format!("{} days ago", elapsed / 86400),
    };
    format!("{} · {age}", issued.format("%d %b %Y, %H:%M:%S UTC"))
}

fn refresh_message(previous: Option<&AssignmentClaims>, current: &AssignmentClaims) -> String {
    let Some(previous) = previous else {
        return match &current.policy {
            Some(policy) => format!("Fetched revision {}", policy.revision),
            None => "Checked · local policy applies".into(),
        };
    };
    if previous.assignment_version == current.assignment_version {
        return "Already current".into();
    }
    match (&previous.policy, &current.policy) {
        (Some(old), Some(new))
            if old.profile_id == new.profile_id && old.revision != new.revision =>
        {
            format!("Updated revision {} → {}", old.revision, new.revision)
        }
        (None, Some(new)) => format!("Policy applied · revision {}", new.revision),
        (Some(_), None) => "Updated · local policy now applies".into(),
        _ => "Assignment updated".into(),
    }
}

pub(crate) fn status_rows(
    policy: Option<&AssignmentClaims>,
    previous: Option<&AssignmentClaims>,
    refreshed: bool,
    remembered_mode: Option<&str>,
) -> String {
    let Some(policy) = policy else {
        let mut text = remembered_mode
            .map(|mode| summary_row("Mode", &format!("{} · last verified", mode_label(mode))))
            .unwrap_or_default();
        text.push_str(&summary_row(
            if refreshed { "Refresh" } else { "Policy" },
            if refreshed {
                "Policy delivery unsupported by platform"
            } else if remembered_mode.is_some() {
                "Cached assignment unavailable · use --refresh"
            } else {
                "Not checked · use --refresh"
            },
        ));
        return text;
    };
    let mut text = assignment_rows(policy);
    let checked = format!(
        "{} · {}",
        checked_at(policy.issued_at, Utc::now()),
        if refreshed { "refreshed" } else { "cached" }
    );
    text.push_str(&summary_row(
        "Checked",
        &fg(&checked, theme::current().subtext).to_string(),
    ));
    if refreshed {
        text.push_str(&summary_row(
            "Refresh",
            &fg(&refresh_message(previous, policy), theme::current().green).to_string(),
        ));
    }
    text
}

fn assignment_rows(policy: &AssignmentClaims) -> String {
    let mut text = summary_row("Mode", mode_label(&policy.management_mode));
    let profile = match &policy.policy {
        Some(bundle) => format!(
            "{} · revision {}",
            assigned_name(policy).unwrap_or_else(|| policy_name(bundle)),
            bundle.revision
        ),
        None => "Local profiles".into(),
    };
    text.push_str(&summary_row("Policy", &profile));
    if policy.policy.is_none()
        && let Some(name) = assigned_name(policy)
    {
        let label = match policy.resolved_via["revision"].as_i64() {
            Some(revision) => format!("{name} · revision {revision}"),
            None => name,
        };
        text.push_str(&summary_row("Assigned policy", &label));
    }
    text
}

pub(crate) fn enrollment_summary(policy: &AssignmentClaims) -> String {
    let mut text = summary_heading("Policy verified", SummaryKind::Success);
    text.push_str(&assignment_rows(policy));
    text.push_str(&summary_row("Status", "Verified and ready"));
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_distinguishes_revision_and_assignment_changes() {
        let before = super::super::tests::claims();
        let mut after = before.clone();
        after.issued_at = Utc::now();
        assert_eq!(refresh_message(Some(&before), &after), "Already current");
        after.assignment_version = "changed".into();
        assert_eq!(refresh_message(Some(&before), &after), "Assignment updated");
        after.policy.as_mut().expect("assigned policy").revision = 8;
        assert_eq!(
            refresh_message(Some(&before), &after),
            "Updated revision 7 → 8"
        );
        after.management_mode = "audit_only".into();
        after.policy = None;
        assert_eq!(
            refresh_message(Some(&before), &after),
            "Updated · local policy now applies"
        );
        assert_eq!(refresh_message(None, &before), "Fetched revision 7");
        assert_eq!(
            refresh_message(Some(&after), &before),
            "Policy applied · revision 7"
        );
    }

    #[test]
    fn status_uses_the_resolved_platform_name_for_every_assignment_layer() {
        for layer in ["subject", "group", "unit_default"] {
            let mut claims = super::super::tests::claims();
            let id = claims.policy.as_ref().expect("policy").profile_id.clone();
            claims.resolved_via = serde_json::json!({
                "layer": layer, "profile_id": id, "profile_name": "Engineering baseline", "revision": 7,
            });
            assert_eq!(
                assigned_name(&claims).as_deref(),
                Some("Engineering baseline")
            );
            assert!(status_rows(Some(&claims), None, true, None).contains("Engineering baseline"));
            claims.management_mode = "audit_only".into();
            claims.policy = None;
            let text = status_rows(Some(&claims), None, true, None);
            assert!(text.contains("Local profiles"));
            assert!(text.contains("Assigned policy"));
            assert!(text.contains("Engineering baseline"));
        }
    }

    #[test]
    fn a_name_for_another_profile_does_not_override_bundle_metadata() {
        let mut claims = super::super::tests::claims();
        claims.resolved_via =
            serde_json::json!({"profile_id":"different", "profile_name":"Wrong name"});
        assert_eq!(
            assigned_name(&claims),
            claims.policy.as_ref().map(policy_name)
        );
    }

    #[test]
    fn checked_time_omits_fractional_seconds_and_includes_cache_age() {
        let issued: DateTime<Utc> = "2026-11-16T15:47:56.660477Z".parse().expect("timestamp");
        let now = issued + chrono::Duration::seconds(181);
        assert_eq!(
            checked_at(issued, now),
            "16 Nov 2026, 15:47:56 UTC · 3 min ago"
        );
    }

    #[test]
    fn policy_names_accept_bundled_sources_and_strip_terminal_controls() {
        let mut policy = super::super::tests::claims()
            .policy
            .expect("assigned policy");
        let bundle = policy.bundle.as_mut().expect("bundle");
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(
                bundle.signature["dsseEnvelope"]["payload"]
                    .as_str()
                    .expect("payload"),
            )
            .expect("base64");
        let mut statement: serde_json::Value = serde_json::from_slice(&payload).expect("statement");
        statement["predicate"]["name"] = serde_json::json!("Engineering\u{001b}[2J");
        bundle.signature["dsseEnvelope"]["payload"] = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).expect("statement"))
            .into();
        assert_eq!(policy_name(&policy), "Engineering");
        policy.bundle = None;
        assert_eq!(policy_name(&policy), policy.profile_id);
    }

    #[test]
    fn startup_summary_distinguishes_local_overrides_from_platform_options() {
        let mut session = PolicySession {
            management_mode: "advisory".into(),
            assignment_version: "assignment".into(),
            assigned_profile: Some("internal-policy-id".into()),
            assigned_name: Some("Engineering".into()),
            assigned_revision: Some(2),
            assigned_digest: None,
            policy_source: "platform".into(),
            effective_profile_digest: None,
            overrides: vec!["block-net".into()],
            override_sources: Default::default(),
        };
        let text = session_summary(&session);
        assert!(text.contains("Engineering · revision 2"));
        assert!(text.contains("Platform"));
        assert!(text.contains("--block-net"));
        assert!(!text.contains("internal-policy-id"));
        assert!(!text.contains("Local profile override"));
        session.policy_source = "local".into();
        session.overrides = vec!["profile".into()];
        assert!(session_summary(&session).contains("Local profile override"));
        session.assigned_name = None;
        assert!(session_summary(&session).contains("internal-policy-id · revision 2"));
    }
}
