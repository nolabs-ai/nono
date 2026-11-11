//! Shared tenant choice for login and remote commands.

use nono::{NonoError, Result};

pub(crate) fn select(
    record: &crate::platform_oauth::session::SessionRecord,
) -> Result<Option<String>> {
    use crate::terminal_selector::{self, Item, Picker};
    use std::io::{self, IsTerminal};
    if record.organizations.is_empty() {
        return Err(NonoError::ActionRequired(
            "no tenants are available; run `nono platform login` to refresh membership".into(),
        ));
    }
    if record.organizations.len() == 1 {
        return Ok(Some(record.organizations[0].tenant_id.clone()));
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(NonoError::ActionRequired("multiple tenants are available; pass --tenant <slug|id|personal> or save a default with `nono platform tenant use <tenant>`".into()));
    }
    let items = record
        .organizations
        .iter()
        .map(|tenant| Item {
            label: tenant.display_name.clone(),
            context: if tenant.kind == "personal" {
                String::new()
            } else {
                tenant.slug.clone()
            },
            status: if tenant.kind == "personal" {
                "personal"
            } else {
                "organization"
            }
            .into(),
            metadata: String::new(),
            marker: None,
        })
        .collect::<Vec<_>>();
    let selected = terminal_selector::select(
        &Picker {
            title: "NONO TENANT",
            context: &record.platform_url,
            summary: &format!("{} tenants", items.len()),
            prompt: "Choose a tenant",
            confirm_label: "select",
        },
        &items,
    )?
    .ok_or_else(|| {
        NonoError::ActionRequired(
            "tenant selection cancelled; use `nono platform tenant use <slug>`".into(),
        )
    })?;
    record
        .organizations
        .get(selected)
        .map(|tenant| Some(tenant.tenant_id.clone()))
        .ok_or_else(|| NonoError::ConfigParse("tenant selection is out of range".into()))
}
