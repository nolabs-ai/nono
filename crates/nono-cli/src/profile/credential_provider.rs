use super::Profile;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};

/// Declarative provider used by mediated credential routes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProviderDef {
    #[serde(rename = "type")]
    pub provider_type: CredentialProviderType,
    /// OAuth token endpoints whose responses must be captured before the
    /// sandboxed agent can persist real tokens.
    #[serde(default)]
    pub token_endpoints: Vec<CredentialProviderTokenEndpoint>,
    /// API origins where phantom tokens are resolved on egress.
    #[serde(default)]
    pub api_hosts: Vec<String>,
    /// Header the resolved credential is injected into on `api_hosts` egress.
    /// Defaults to `Authorization` (OAuth Bearer APIs). Vault, for example,
    /// needs `X-Vault-Token`.
    #[serde(default)]
    pub inject_header: Option<String>,
    /// Format applied to the resolved credential before injection; `{}` is the
    /// token. Defaults to `Bearer {}`. Use `{}` for a raw token (e.g. Vault).
    #[serde(default)]
    pub credential_format: Option<String>,
    /// Optional provider-specific logout/session detection.
    #[serde(default)]
    pub credential_store: Option<CredentialProviderStore>,
    /// Optional human-invoked lifecycle commands. These are not run by capture.
    #[serde(default)]
    pub helpers: Option<CredentialProviderHelpers>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProviderType {
    OauthCapture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProviderTokenEndpoint {
    /// Origin serving the token endpoint, for example
    /// `https://platform.claude.com`.
    pub host: String,
    /// Absolute URL path of the token endpoint.
    pub path: String,
    /// JSON fields in the token response that carry real credentials.
    pub response_fields: CredentialProviderResponseFields,
    /// Request body encoding for refresh/exchange requests.
    #[serde(default)]
    pub request_body: CredentialProviderRequestBodyFormat,
    /// JSON request fields where phantom tokens must be resolved on refresh.
    #[serde(default)]
    pub request_nonce_fields: Vec<String>,
}

pub type CredentialProviderResponseFields = Vec<CredentialProviderResponseField>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProviderResponseField {
    pub path: String,
    #[serde(default)]
    pub kind: CredentialProviderResponseFieldKind,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProviderResponseFieldKind {
    #[default]
    Opaque,
    Jwt,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProviderRequestBodyFormat {
    #[default]
    Auto,
    Json,
    Form,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialProviderStore {
    KeychainJson {
        service: String,
        #[serde(default)]
        account_candidates: Vec<String>,
        #[serde(default)]
        phantom_fields: Vec<String>,
    },
    FileJson {
        path: String,
        #[serde(default)]
        phantom_fields: Vec<String>,
    },
    CommandStatus {
        command: Vec<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProviderHelpers {
    #[serde(default)]
    pub status: Vec<String>,
    #[serde(default)]
    pub login: Vec<String>,
    #[serde(default)]
    pub logout: Vec<String>,
}

/// Route binding for a declarative provider. The provider declares where
/// capture happens; the route declares how the sandbox sees the phantom.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRouteDef {
    pub name: String,
    pub provider: String,
    #[serde(default)]
    pub env_var: Option<String>,
    #[serde(default)]
    pub base_url_env_var: Option<String>,
    #[serde(default)]
    pub endpoint_policy: Option<nono_proxy::config::EndpointPolicyConfig>,
}

pub(super) fn validate_credential_provider_entries(profile: &Profile) -> Result<()> {
    for (name, provider) in &profile.credential_providers {
        validate_provider_name("credential_providers", name)?;
        match provider.provider_type {
            CredentialProviderType::OauthCapture => {}
        }
        if provider.token_endpoints.is_empty() {
            return Err(NonoError::ProfileParse(format!(
                "credential_providers.{name}.token_endpoints must not be empty"
            )));
        }
        if provider.api_hosts.is_empty() {
            return Err(NonoError::ProfileParse(format!(
                "credential_providers.{name}.api_hosts must not be empty"
            )));
        }
        for (index, endpoint) in provider.token_endpoints.iter().enumerate() {
            validate_provider_origin(
                &format!("credential_providers.{name}.token_endpoints[{index}].host"),
                &endpoint.host,
            )?;
            validate_provider_path(
                &format!("credential_providers.{name}.token_endpoints[{index}].path"),
                &endpoint.path,
            )?;
            if endpoint.response_fields.is_empty() {
                return Err(NonoError::ProfileParse(format!(
                    "credential_providers.{name}.token_endpoints[{index}].response_fields must not be empty"
                )));
            }
            for field in &endpoint.response_fields {
                validate_provider_field(
                    &format!(
                        "credential_providers.{name}.token_endpoints[{index}].response_fields.path"
                    ),
                    &field.path,
                )?;
            }
            // request_nonce_fields is only meaningful for refresh/exchange
            // flows that re-send a phantom in the request body. Capture-only
            // endpoints (e.g. Vault's OIDC callback, whose token is captured
            // from the response and later sent in a header) leave it empty.
            for field in &endpoint.request_nonce_fields {
                validate_provider_field(
                    &format!(
                        "credential_providers.{name}.token_endpoints[{index}].request_nonce_fields"
                    ),
                    field,
                )?;
            }
        }
        for (index, api_host) in provider.api_hosts.iter().enumerate() {
            validate_provider_origin(
                &format!("credential_providers.{name}.api_hosts[{index}]"),
                api_host,
            )?;
        }
        // A custom injection format must carry the `{}` token placeholder, or
        // the redemption route would inject a constant header that never
        // contains the resolved credential.
        if provider
            .credential_format
            .as_deref()
            .is_some_and(|format| !format.contains("{}"))
        {
            return Err(NonoError::ProfileParse(format!(
                "credential_providers.{name}.credential_format must contain the '{{}}' token placeholder"
            )));
        }
        // Same raw header-value path as the header name; reject control chars
        // to prevent header injection.
        if provider
            .credential_format
            .as_deref()
            .is_some_and(|format| format.bytes().any(|b| b.is_ascii_control() && b != b'\t'))
        {
            return Err(NonoError::ProfileParse(format!(
                "credential_providers.{name}.credential_format must not contain control characters"
            )));
        }
        if provider
            .inject_header
            .as_deref()
            .is_some_and(|header| !is_valid_http_header_name(header))
        {
            return Err(NonoError::ProfileParse(format!(
                "credential_providers.{name}.inject_header must be a valid HTTP header name (RFC 7230 token)"
            )));
        }
        if let Some(store) = &provider.credential_store {
            validate_credential_provider_store(name, store)?;
        }
        if let Some(helpers) = &provider.helpers {
            validate_optional_helper_command(name, "status", &helpers.status)?;
            validate_optional_helper_command(name, "login", &helpers.login)?;
            validate_optional_helper_command(name, "logout", &helpers.logout)?;
        }
    }

    let mut seen_routes = std::collections::HashSet::new();
    for route in &profile.credential_routes {
        validate_provider_name("credential_routes.name", &route.name)?;
        if !seen_routes.insert(route.name.clone()) {
            return Err(NonoError::ProfileParse(format!(
                "credential_routes contains duplicate route name '{}'",
                route.name
            )));
        }
        validate_provider_name("credential_routes.provider", &route.provider)?;
        if let Some(env_var) = &route.env_var {
            nono::validate_destination_env_var(env_var).map_err(|err| {
                NonoError::ProfileParse(format!(
                    "credential_routes.{} has invalid env_var '{}': {err}",
                    route.name, env_var
                ))
            })?;
        }
        if let Some(env_var) = &route.base_url_env_var {
            nono::validate_destination_env_var(env_var).map_err(|err| {
                NonoError::ProfileParse(format!(
                    "credential_routes.{} has invalid base_url_env_var '{}': {err}",
                    route.name, env_var
                ))
            })?;
        }
    }

    Ok(())
}

fn validate_credential_provider_references(profile: &Profile) -> Result<()> {
    for route in &profile.credential_routes {
        if !profile.credential_providers.contains_key(&route.provider) {
            return Err(NonoError::ProfileParse(format!(
                "credential_routes.{} references unknown credential provider '{}'",
                route.name, route.provider
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_credential_provider_resolved(profile: &Profile) -> Result<()> {
    validate_credential_provider_entries(profile)?;
    validate_credential_provider_references(profile)
}

fn validate_credential_provider_store(
    provider_name: &str,
    store: &CredentialProviderStore,
) -> Result<()> {
    match store {
        CredentialProviderStore::KeychainJson {
            service,
            account_candidates,
            phantom_fields,
        } => {
            validate_provider_field(
                &format!("credential_providers.{provider_name}.credential_store.service"),
                service,
            )?;
            if account_candidates.is_empty() {
                return Err(NonoError::ProfileParse(format!(
                    "credential_providers.{provider_name}.credential_store.account_candidates must not be empty"
                )));
            }
            for candidate in account_candidates {
                validate_provider_field(
                    &format!(
                        "credential_providers.{provider_name}.credential_store.account_candidates"
                    ),
                    candidate,
                )?;
            }
            validate_phantom_fields(provider_name, phantom_fields)?;
        }
        CredentialProviderStore::FileJson {
            path,
            phantom_fields,
        } => {
            validate_provider_field(
                &format!("credential_providers.{provider_name}.credential_store.path"),
                path,
            )?;
            validate_phantom_fields(provider_name, phantom_fields)?;
        }
        CredentialProviderStore::CommandStatus { command } => {
            validate_required_helper_command(provider_name, "credential_store.command", command)?;
        }
    }
    Ok(())
}

fn validate_phantom_fields(provider_name: &str, fields: &[String]) -> Result<()> {
    if fields.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "credential_providers.{provider_name}.credential_store.phantom_fields must not be empty"
        )));
    }
    for field in fields {
        validate_provider_field(
            &format!("credential_providers.{provider_name}.credential_store.phantom_fields"),
            field,
        )?;
    }
    Ok(())
}

fn validate_optional_helper_command(
    provider_name: &str,
    helper_name: &str,
    command: &[String],
) -> Result<()> {
    if command.is_empty() {
        return Ok(());
    }
    validate_required_helper_command(provider_name, helper_name, command)
}

fn validate_required_helper_command(
    provider_name: &str,
    helper_name: &str,
    command: &[String],
) -> Result<()> {
    if command.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "credential_providers.{provider_name}.helpers.{helper_name} must not be empty"
        )));
    }
    for part in command {
        if part.is_empty() || part.contains('\0') {
            return Err(NonoError::ProfileParse(format!(
                "credential_providers.{provider_name}.helpers.{helper_name} contains an empty or NUL-bearing argument"
            )));
        }
    }
    Ok(())
}

fn validate_provider_name(context: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(NonoError::ProfileParse(format!(
            "{context} entry '{name}' must contain only alphanumeric characters, underscores, and hyphens"
        )));
    }
    Ok(())
}

fn validate_provider_origin(context: &str, origin: &str) -> Result<()> {
    if origin.trim().is_empty() || origin.contains('\0') {
        return Err(NonoError::ProfileParse(format!(
            "{context} must be non-empty and must not contain NUL"
        )));
    }
    let parsed = url::Url::parse(origin).map_err(|err| {
        NonoError::ProfileParse(format!(
            "{context} '{origin}' is not a valid URL origin: {err}"
        ))
    })?;
    if parsed.scheme() != "https" {
        return Err(NonoError::ProfileParse(format!(
            "{context} '{origin}' must use https"
        )));
    }
    if parsed.host_str().is_none() {
        return Err(NonoError::ProfileParse(format!(
            "{context} '{origin}' must include a host"
        )));
    }
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(NonoError::ProfileParse(format!(
            "{context} '{origin}' must be an origin without path, query, or fragment"
        )));
    }
    Ok(())
}

fn validate_provider_path(context: &str, path: &str) -> Result<()> {
    if path.is_empty() || path.contains('\0') || !path.starts_with('/') {
        return Err(NonoError::ProfileParse(format!(
            "{context} must be a non-empty absolute path and must not contain NUL"
        )));
    }
    Ok(())
}

fn validate_provider_field(context: &str, field: &str) -> Result<()> {
    if field.trim().is_empty() || field.contains('\0') {
        return Err(NonoError::ProfileParse(format!(
            "{context} entries must be non-empty and must not contain NUL"
        )));
    }
    Ok(())
}

/// RFC 7230 `token`: the grammar for an HTTP header field name. Rejects
/// whitespace, colons, and control characters so a malformed `inject_header`
/// can't break the outbound request or smuggle extra header material.
fn is_valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_with(inject_header: Option<&str>, credential_format: Option<&str>) -> Profile {
        let mut profile = Profile::default();
        profile.credential_providers.insert(
            "vault_oidc".to_string(),
            CredentialProviderDef {
                provider_type: CredentialProviderType::OauthCapture,
                token_endpoints: vec![CredentialProviderTokenEndpoint {
                    host: "https://vault.example.com".to_string(),
                    path: "/v1/auth/oidc/oidc/callback".to_string(),
                    response_fields: vec![CredentialProviderResponseField {
                        path: "auth.client_token".to_string(),
                        kind: CredentialProviderResponseFieldKind::Opaque,
                    }],
                    request_body: CredentialProviderRequestBodyFormat::Auto,
                    // Capture-only endpoint: intentionally no request_nonce_fields.
                    request_nonce_fields: vec![],
                }],
                api_hosts: vec!["https://vault.example.com".to_string()],
                inject_header: inject_header.map(str::to_string),
                credential_format: credential_format.map(str::to_string),
                credential_store: None,
                helpers: None,
            },
        );
        profile
    }

    #[test]
    fn credential_format_without_placeholder_is_rejected() {
        let profile = provider_with(Some("X-Vault-Token"), Some("Bearer"));
        let err = validate_credential_provider_entries(&profile).expect_err("must reject");
        assert!(
            err.to_string().contains("credential_format"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn credential_format_with_control_chars_is_rejected() {
        for bad in [
            "{}\r\nEvil: 1",
            "Bearer {}\n",
            "{}\0",
            "{}\x01",
            "{}\x0b",
            "{}\x0c",
            "{}\x7f",
        ] {
            let profile = provider_with(Some("X-Vault-Token"), Some(bad));
            let err = validate_credential_provider_entries(&profile)
                .expect_err(&format!("must reject format {bad:?}"));
            assert!(
                err.to_string().contains("credential_format"),
                "unexpected error for {bad:?}: {err}"
            );
        }
        // Horizontal tab is a legal field-value character.
        let ok = provider_with(Some("X-Vault-Token"), Some("Bearer\t{}"));
        validate_credential_provider_entries(&ok).expect("tab is allowed");
    }

    #[test]
    fn invalid_inject_header_is_rejected() {
        for bad in ["", "  ", "X Vault Token", "X-Vault-Token:", "X\r\nEvil"] {
            let profile = provider_with(Some(bad), Some("{}"));
            let err = validate_credential_provider_entries(&profile)
                .expect_err(&format!("must reject header {bad:?}"));
            assert!(
                err.to_string().contains("inject_header"),
                "unexpected error for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn custom_header_and_capture_only_endpoint_ok() {
        // Raw-token header + empty request_nonce_fields (capture-only) is valid.
        let profile = provider_with(Some("X-Vault-Token"), Some("{}"));
        validate_credential_provider_entries(&profile).expect("valid provider");
    }
}
