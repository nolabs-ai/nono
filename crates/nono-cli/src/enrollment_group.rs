use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};

use crate::login_enrollment::EnrollmentOptions;
use crate::terminal_selector::{self, Item, Picker};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnrollmentGroup {
    pub group_id: String,
    pub name: String,
    pub unit_id: String,
    pub unit_name: String,
    pub is_default: bool,
}

pub(crate) fn validate(groups: &[EnrollmentGroup]) -> Result<()> {
    let mut ids = std::collections::HashSet::new();
    if groups.len() > 1000 || groups.iter().filter(|group| group.is_default).count() > 1 {
        return Err(invalid());
    }
    for group in groups {
        if uuid::Uuid::parse_str(&group.group_id).is_err()
            || uuid::Uuid::parse_str(&group.unit_id).is_err()
            || !ids.insert(&group.group_id)
            || [&group.name, &group.unit_name].iter().any(|name| {
                name.trim().is_empty() || name.len() > 1024 || name.chars().any(char::is_control)
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(crate) fn labels(groups: &[EnrollmentGroup]) -> String {
    groups.iter().map(label).collect::<Vec<_>>().join(", ")
}

fn label(group: &EnrollmentGroup) -> String {
    let clean = crate::terminal_approval::sanitize_for_terminal;
    if group.is_default && group.name.eq_ignore_ascii_case("Default") {
        return clean(&group.name);
    }
    format!(
        "{} ({})",
        clean(&group.name),
        if group.is_default {
            "default".into()
        } else {
            clean(&group.unit_name)
        }
    )
}

pub(crate) fn resolve<'a>(
    groups: &'a [EnrollmentGroup],
    selector: &str,
) -> Result<Option<&'a EnrollmentGroup>> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(NonoError::ActionRequired(
            "group name or ID must not be empty".into(),
        ));
    }
    if let Ok(id) = uuid::Uuid::parse_str(selector)
        && let Some(group) = groups.iter().find(|group| group.group_id == id.to_string())
    {
        return Ok(Some(group));
    }
    let mut matches = groups.iter().filter(|group| group.name == selector);
    let group = matches.next();
    if matches.next().is_some() {
        return Err(NonoError::ActionRequired(
            "the group name is ambiguous; use its group ID".into(),
        ));
    }
    Ok(group)
}

pub(crate) fn select(
    options: &EnrollmentOptions,
    tenant: &str,
    requested: Option<&str>,
    context: &str,
) -> Result<Option<String>> {
    use std::io::{self, IsTerminal};
    if options.protocol_version != "1" || options.tenant_id != tenant {
        return Err(invalid());
    }
    validate(&options.groups)?;
    let groups = match &options.existing {
        Some(existing) => {
            if uuid::Uuid::parse_str(&existing.subject_id).is_err() {
                return Err(invalid());
            }
            validate(&existing.groups)?;
            if requested.is_none() {
                return Ok(None);
            }
            &existing.groups
        }
        None => &options.groups,
    };
    if let Some(requested) = requested {
        return match resolve(groups, requested)? {
            Some(group) => Ok(Some(group.group_id.clone())),
            None if options.existing.is_some() => Err(NonoError::ActionRequired(
                "this device is already enrolled in another group; use `nono platform group move`".into(),
            )),
            None => Err(NonoError::ActionRequired("no permitted enrollment group matches --group; choose an available group name or ID".into())),
        };
    }
    match groups.as_slice() {
        [] => {
            return Err(NonoError::ActionRequired(
                "no enrollment groups are available in this tenant; contact its administrator"
                    .into(),
            ));
        }
        [group] => return Ok(Some(group.group_id.clone())),
        _ => {}
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(NonoError::ActionRequired(
            "multiple enrollment groups are available; pass --group <name|id>".into(),
        ));
    }
    let items = groups
        .iter()
        .map(|group| Item {
            label: group.name.clone(),
            context: group.unit_name.clone(),
            status: if group.is_default {
                "default".into()
            } else {
                String::new()
            },
            metadata: String::new(),
            marker: None,
        })
        .collect::<Vec<_>>();
    let selected = terminal_selector::select(
        &Picker {
            title: "NONO ENROLLMENT GROUP",
            context,
            summary: &format!("{} groups", groups.len()),
            prompt: "Choose an enrollment group",
            confirm_label: "select",
        },
        &items,
    )?
    .ok_or_else(|| {
        NonoError::ActionRequired(
            "group selection cancelled; run `nono platform login --group <name|id>` to enroll"
                .into(),
        )
    })?;
    groups
        .get(selected)
        .map(|group| Some(group.group_id.clone()))
        .ok_or_else(invalid)
}

fn invalid() -> NonoError {
    NonoError::ConfigParse("platform returned invalid enrollment groups".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::login_enrollment::ExistingEnrollment;

    fn group(name: &str) -> EnrollmentGroup {
        EnrollmentGroup {
            group_id: uuid::Uuid::now_v7().to_string(),
            name: name.into(),
            unit_id: uuid::Uuid::now_v7().to_string(),
            unit_name: "Engineering".into(),
            is_default: false,
        }
    }

    fn options(groups: Vec<EnrollmentGroup>) -> EnrollmentOptions {
        EnrollmentOptions {
            protocol_version: "1".into(),
            tenant_id: "tenant".into(),
            groups,
            existing: None,
        }
    }

    #[test]
    fn one_group_is_automatic_and_explicit_choice_resolves_names_and_ids() {
        let first = group("Developers");
        let second = group("Production");
        let mut choices = options(vec![first.clone()]);
        assert_eq!(
            select(&choices, "tenant", None, "Acme").expect("group selection"),
            Some(first.group_id.clone())
        );
        choices.groups.push(second.clone());
        for selector in [&second.name, &second.group_id] {
            assert_eq!(
                select(&choices, "tenant", Some(selector), "Acme").expect("group selection"),
                Some(second.group_id.clone())
            );
        }
        assert!(
            select(&choices, "tenant", Some("missing"), "Acme")
                .expect_err("invalid group selection")
                .to_string()
                .contains("no permitted")
        );
    }

    #[test]
    fn ambiguous_names_require_an_id_and_existing_groups_are_never_moved() {
        let first = group("Developers");
        let second = group("Developers");
        let mut choices = options(vec![first.clone(), second.clone()]);
        assert!(
            select(&choices, "tenant", Some("Developers"), "Acme")
                .expect_err("invalid group selection")
                .to_string()
                .contains("ambiguous")
        );
        choices.existing = Some(ExistingEnrollment {
            subject_id: uuid::Uuid::now_v7().to_string(),
            groups: vec![first.clone()],
        });
        assert_eq!(
            select(&choices, "tenant", None, "Acme").expect("group selection"),
            None
        );
        assert_eq!(
            select(&choices, "tenant", Some(&first.group_id), "Acme").expect("group selection"),
            Some(first.group_id)
        );
        assert!(
            select(&choices, "tenant", Some(&second.group_id), "Acme")
                .expect_err("invalid group selection")
                .to_string()
                .contains("already enrolled")
        );
    }

    #[test]
    fn malformed_or_wrong_tenant_options_fail_closed() {
        let mut choices = options(vec![group("Developers")]);
        assert!(select(&choices, "other", None, "Acme").is_err());
        choices.protocol_version = "2".into();
        assert!(select(&choices, "tenant", None, "Acme").is_err());
        choices.protocol_version = "1".into();
        choices.groups[0].name.push('\n');
        assert!(select(&choices, "tenant", None, "Acme").is_err());
        choices.groups[0].name = "Developers".into();
        choices.groups.push(choices.groups[0].clone());
        assert!(select(&choices, "tenant", None, "Acme").is_err());
        choices.groups.clear();
        assert!(
            select(&choices, "tenant", None, "Acme")
                .expect_err("invalid group selection")
                .to_string()
                .contains("no enrollment groups")
        );
    }

    #[test]
    fn default_group_label_avoids_repeating_default() {
        let mut default = group("Default");
        default.is_default = true;
        assert_eq!(labels(&[default.clone()]), "Default");
        default.name = "Managed devices".into();
        assert_eq!(labels(&[default]), "Managed devices (default)");
    }

    #[test]
    fn group_summary_uses_labels_without_internal_ids() {
        let mut default = group("Unassigned");
        default.is_default = true;
        let team = group("Developers");
        assert_eq!(
            labels(&[default, team.clone()]),
            "Unassigned (default), Developers (Engineering)"
        );
        let row = crate::platform_client::enrollment_group_row(std::slice::from_ref(&team));
        assert!(row.contains("Group"));
        assert!(row.contains("Developers (Engineering)"));
        assert!(!row.contains(&team.group_id));
    }
}
