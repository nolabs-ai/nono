use crate::cli::SandboxArgs;
use colored::Colorize;
use nono::{LoadedSecret, NonoError, Result};
use std::collections::HashMap;
use tracing::info;

fn parse_env_credential_map_args(values: &[String]) -> Result<Vec<(String, String)>> {
    if !values.len().is_multiple_of(2) {
        return Err(NonoError::ConfigParse(
            "--env-credential-map expects pairs: <CREDENTIAL_REF> <ENV_VAR>".to_string(),
        ));
    }

    let mut pairs = Vec::with_capacity(values.len() / 2);
    for chunk in values.chunks_exact(2) {
        let credential_ref = chunk[0].trim();
        let env_var = chunk[1].trim();

        if credential_ref.is_empty() {
            return Err(NonoError::ConfigParse(
                "--env-credential-map has an empty credential reference".to_string(),
            ));
        }

        if env_var.is_empty() {
            return Err(NonoError::ConfigParse(
                "--env-credential-map has an empty destination env var".to_string(),
            ));
        }

        pairs.push((credential_ref.to_string(), env_var.to_string()));
    }

    Ok(pairs)
}

pub(crate) fn load_env_credentials(
    args: &SandboxArgs,
    profile_secrets: &HashMap<String, String>,
    silent: bool,
) -> Result<Vec<LoadedSecret>> {
    let cli_secret_mappings = parse_env_credential_map_args(&args.env_credential_map)?;

    let secret_mappings = nono::keystore::build_secret_mappings(
        args.env_credential.as_deref(),
        &cli_secret_mappings,
        profile_secrets,
    )?;

    if secret_mappings.is_empty() {
        return Ok(Vec::new());
    }

    let op_count = secret_mappings
        .keys()
        .filter(|credential| nono::keystore::is_op_uri(credential))
        .count();
    let apple_password_count = secret_mappings
        .keys()
        .filter(|credential| nono::keystore::is_apple_password_uri(credential))
        .count();
    let keyring_count = secret_mappings.len() - op_count - apple_password_count;

    info!(
        "Loading {} credential(s) (keyring: {}, 1Password: {}, Apple Passwords: {})",
        secret_mappings.len(),
        keyring_count,
        op_count,
        apple_password_count
    );
    if !silent {
        let mut source_parts: Vec<String> = Vec::new();
        if keyring_count > 0 {
            source_parts.push(format!("{} from keystore", keyring_count));
        }
        if op_count > 0 {
            source_parts.push(format!("{} from 1Password", op_count));
        }
        if apple_password_count > 0 {
            source_parts.push(format!("{} from Apple Passwords", apple_password_count));
        }

        eprintln!(
            "  Loading {} credential(s) ({})...",
            secret_mappings.len(),
            source_parts.join(", ")
        );

        for account in secret_mappings.keys() {
            let display_account = if nono::keystore::is_op_uri(account) {
                nono::keystore::redact_op_uri(account)
            } else if nono::keystore::is_apple_password_uri(account) {
                nono::keystore::redact_apple_password_uri(account)
            } else {
                account.to_string()
            };
            eprintln!(
                "  {}: env credential '{}' exposes the secret directly to the sandboxed process.\n\
                 {}  For network API keys, use a profile with credentials for credential isolation.",
                "warning".yellow(),
                display_account,
                " ".repeat(11),
            );
        }
    }

    nono::keystore::load_secrets(nono::keystore::DEFAULT_SERVICE, &secret_mappings)
}
