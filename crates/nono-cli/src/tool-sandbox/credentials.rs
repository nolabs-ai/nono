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
                resolved.insert(
                    name.clone(),
                    ResolvedCredential::Ambient {
                        source: credential.source.clone(),
                    },
                );
            }
        }
    }
    Ok(resolved)
}

fn resolve_local_socket_path(value: &str) -> std::result::Result<PathBuf, String> {
    // Expand `$VAR` references anywhere in the string (e.g.
    // `$XDG_RUNTIME_DIR/ghtkn/agent.sock`), matching the policy-path expansion
    // used elsewhere. Strict expansion errors on an unset variable instead of
    // silently collapsing `$VAR/suffix` to `/suffix` — a silent path-widening bug.
    let expanded = crate::policy::expand_env_vars_strict(value).map_err(|e| match e {
        NonoError::EnvVarValidation { var, .. } => format!("{var} is unset"),
        other => other.to_string(),
    })?;
    let path = PathBuf::from(expanded);
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

#[cfg(test)]
mod tests {
    use super::resolve_local_socket_path;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    const DIR_VAR: &str = "NONO_TEST_CREDENTIAL_SOCKET_DIR";
    const UNSET_VAR: &str = "NONO_TEST_CREDENTIAL_SOCKET_UNSET";

    /// Bind a real Unix socket under `dir` and return its path, keeping the
    /// listener alive so the socket node stays valid for the duration of the test.
    fn bind_socket(dir: &std::path::Path, name: &str) -> (UnixListener, PathBuf) {
        let socket_path = dir.join(name);
        let listener = UnixListener::bind(&socket_path).expect("bind test socket");
        (listener, socket_path)
    }

    #[test]
    fn expands_var_with_path_suffix() {
        let _lock = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvVarGuard::set_all(&[(DIR_VAR, tmp.path().to_str().expect("utf8 path"))]);
        std::fs::create_dir_all(tmp.path().join("ghtkn")).expect("create socket dir");
        let (_listener, socket_path) = bind_socket(tmp.path(), "ghtkn/agent.sock");
        let resolved = resolve_local_socket_path(&format!("${DIR_VAR}/ghtkn/agent.sock"))
            .expect("suffixed env path resolves");
        assert_eq!(
            resolved,
            socket_path.canonicalize().expect("canonical socket")
        );
    }

    #[test]
    fn unset_var_errors_naming_only_the_variable() {
        let _lock = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let env = EnvVarGuard::set_all(&[(UNSET_VAR, "placeholder")]);
        env.remove(UNSET_VAR);
        let err = resolve_local_socket_path(&format!("${UNSET_VAR}/agent.sock"))
            .expect_err("unset var must fail");
        assert_eq!(err, format!("{UNSET_VAR} is unset"));
    }

    #[test]
    fn expands_variable_after_literal_prefix() {
        let _lock = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let name_var = "NONO_TEST_CREDENTIAL_SOCKET_NAME";
        let _env = EnvVarGuard::set_all(&[(name_var, "agent.sock")]);
        let (_listener, socket_path) = bind_socket(tmp.path(), "agent.sock");
        let value = format!("{}/${name_var}", tmp.path().to_str().expect("utf8 path"));
        let resolved = resolve_local_socket_path(&value).expect("mid-string var expands");
        assert_eq!(
            resolved,
            socket_path.canonicalize().expect("canonical socket")
        );
    }

    #[test]
    fn unset_mid_string_var_fails_closed() {
        let _lock = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let unset = "NONO_TEST_CREDENTIAL_SOCKET_MISSING";
        let env = EnvVarGuard::set_all(&[(unset, "placeholder")]);
        env.remove(unset);
        let err = resolve_local_socket_path(&format!("/tmp/${unset}/agent.sock"))
            .expect_err("unset mid-string var must fail");
        assert_eq!(err, format!("{unset} is unset"));
    }

    #[test]
    fn literal_path_without_variables_still_resolves() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_listener, socket_path) = bind_socket(tmp.path(), "agent.sock");
        let resolved = resolve_local_socket_path(socket_path.to_str().expect("utf8 path"))
            .expect("literal socket path resolves");
        assert_eq!(
            resolved,
            socket_path.canonicalize().expect("canonical socket")
        );
    }
}
