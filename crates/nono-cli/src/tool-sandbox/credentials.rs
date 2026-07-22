use crate::command_policy::{
    AmbientCredentialSourceConfig, CommandCredentialConfig, CommandCredentialType,
};
use nono::{NonoError, Result};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) enum ResolvedCredential {
    LocalSocket {
        path: Option<PathBuf>,
        env_var: Option<String>,
        unavailable_reason: Option<String>,
    },
    RawFile {
        path: PathBuf,
    },
    Proxy {
        env_vars: Vec<(String, String)>,
    },
    Ambient {
        source: Option<AmbientCredentialSourceConfig>,
        /// Visible-phantom template applied to every nonce issued for this
        /// credential. Parsed from the credential's `format`.
        template: Option<nono_proxy::token::PhantomTemplate>,
    },
}

pub(crate) fn resolve_credentials(
    credentials: &BTreeMap<String, CommandCredentialConfig>,
    proxy_credential_env_vars: &BTreeMap<String, Vec<(String, String)>>,
) -> Result<BTreeMap<String, ResolvedCredential>> {
    let mut resolved = BTreeMap::new();
    for (name, credential) in credentials {
        match credential.credential_type {
            CommandCredentialType::LocalSocket => {
                let socket_template = credential.path.as_ref().ok_or_else(|| {
                    NonoError::ConfigParse(format!("local-socket credential '{name}' missing path"))
                })?;
                let (path, unavailable_reason) = match resolve_local_socket_path(socket_template) {
                    Ok(socket) => (Some(socket), None),
                    Err(reason) => (None, Some(reason)),
                };
                resolved.insert(
                    name.clone(),
                    ResolvedCredential::LocalSocket {
                        path,
                        env_var: credential.env_var.clone(),
                        unavailable_reason,
                    },
                );
            }
            CommandCredentialType::RawFile => {
                let path = credential
                    .path
                    .as_ref()
                    .ok_or_else(|| {
                        NonoError::ConfigParse(format!("raw-file credential '{name}' missing path"))
                    })
                    .map(PathBuf::from)?;
                let canonical =
                    path.canonicalize()
                        .map_err(|source| NonoError::PathCanonicalization {
                            path: path.clone(),
                            source,
                        })?;
                if !canonical.is_file() {
                    return Err(NonoError::ExpectedFile(path));
                }
                resolved.insert(
                    name.clone(),
                    ResolvedCredential::RawFile { path: canonical },
                );
            }
            CommandCredentialType::Proxy => {
                let env_vars = proxy_credential_env_vars.get(name).ok_or_else(|| {
                    NonoError::SandboxInit(format!(
                        "tool-sandbox proxy credential '{name}' was not prepared by the proxy runtime"
                    ))
                })?;
                resolved.insert(
                    name.clone(),
                    ResolvedCredential::Proxy {
                        env_vars: env_vars.clone(),
                    },
                );
            }
            CommandCredentialType::Ambient => {
                let template = match &credential.format {
                    Some(template) => Some(
                        nono_proxy::token::PhantomTemplate::parse(template).map_err(|err| {
                            NonoError::ConfigParse(format!("ambient credential '{name}' {err}"))
                        })?,
                    ),
                    None => None,
                };
                resolved.insert(
                    name.clone(),
                    ResolvedCredential::Ambient {
                        source: credential.source.clone(),
                        template,
                    },
                );
            }
        }
    }
    Ok(resolved)
}

fn resolve_local_socket_path(value: &str) -> std::result::Result<PathBuf, String> {
    let path = if let Some(name) = value.strip_prefix('$') {
        match std::env::var_os(name) {
            Some(value) => PathBuf::from(value),
            None => return Err(format!("{name} is unset")),
        }
    } else {
        PathBuf::from(value)
    };
    let canonical = path
        .canonicalize()
        .map_err(|source| format!("failed to resolve {}: {source}", path.display()))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|source| format!("failed to stat {}: {source}", canonical.display()))?;
    if !metadata.file_type().is_socket() {
        return Err(format!("{} is not a socket", canonical.display()));
    }
    Ok(canonical)
}
