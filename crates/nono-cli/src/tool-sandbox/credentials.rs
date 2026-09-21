use crate::command_policy::{
    AmbientCredentialSourceConfig, CommandCredentialConfig, CommandCredentialType,
};
use nono::{NonoError, Result};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

/// Why a `local-socket` credential's socket could not be resolved at session start.
///
/// The distinction decides whether the command continues. A socket that is
/// merely absent is an ordinary runtime state. A path that resolves to
/// something other than a socket, or whose state cannot be checked safely,
/// contradicts what the profile declared and stays fatal.
#[derive(Debug, Clone)]
pub(crate) enum LocalSocketUnavailable {
    /// Nothing is listening at the configured location: the path template's
    /// variable is unset, or it expanded to a path that does not exist.
    /// Both are ordinary states for an agent socket — one that was never
    /// started, or one that exited and left a stale path behind — so the
    /// credential is omitted and commands that declare it still run.
    Absent(String),
    /// The path resolves to something that is not a socket. The profile
    /// asserted a socket lives here and that assertion is false, so this stays
    /// fatal rather than degrading into a silently omitted credential.
    NotASocket(String),
    /// The socket's state could not be determined safely. Errors other than a
    /// genuinely missing path (for example, permission denial or a symlink
    /// loop) must stay fatal rather than being mistaken for ordinary absence.
    CheckFailed(String),
}

impl LocalSocketUnavailable {
    pub(crate) fn reason(&self) -> &str {
        match self {
            Self::Absent(reason) | Self::NotASocket(reason) | Self::CheckFailed(reason) => reason,
        }
    }

    pub(crate) fn is_fatal(&self) -> bool {
        matches!(self, Self::NotASocket(_) | Self::CheckFailed(_))
    }
}

/// Whether a socket resolved at session start is still usable right now.
///
/// Credentials resolve once per session, but a socket can vanish while the
/// session runs — the agent exits, or a lock cycle tears it down. A
/// `UnixSocketCapability` naming a path that no longer holds a socket is
/// rejected when it is constructed, so without this re-check the command would
/// abort exactly as it did before this degrade existed, one race window later.
/// Checking here turns that into the same omission an absent socket gets.
///
/// This is inherently a race: the socket can disappear between the check and
/// the connect. That is fine, because losing the race costs a refused
/// connection inside the command rather than a capability the command should
/// not have had.
pub(crate) fn check_local_socket(path: &Path) -> std::result::Result<(), LocalSocketUnavailable> {
    let metadata =
        fs::metadata(path).map_err(|source| classify_path_error(path, "stat", source))?;
    if metadata.file_type().is_socket() {
        Ok(())
    } else {
        Err(LocalSocketUnavailable::NotASocket(format!(
            "{} is not a socket",
            path.display()
        )))
    }
}

fn classify_path_error(
    path: &Path,
    operation: &str,
    source: std::io::Error,
) -> LocalSocketUnavailable {
    let reason = format!("failed to {operation} {}: {source}", path.display());
    if source.kind() == std::io::ErrorKind::NotFound {
        LocalSocketUnavailable::Absent(reason)
    } else {
        LocalSocketUnavailable::CheckFailed(reason)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ResolvedCredential {
    LocalSocket {
        /// `None` when the socket could not be resolved at session start.
        path: Option<PathBuf>,
        env_var: Option<String>,
        /// Why `path` is `None`, which decides what the consumption sites do:
        /// [`LocalSocketUnavailable::Absent`] is omitted so the command still
        /// runs, while [`LocalSocketUnavailable::NotASocket`] is fatal.
        ///
        /// The fatal case is raised per command rather than at session start on
        /// purpose. Failing during [`resolve_credentials`] would abort the whole
        /// session before the agent launched, which is a wider blast radius than
        /// the behaviour it replaced — one contradicted credential would take
        /// down every command, including those that never declared it.
        unavailable: Option<LocalSocketUnavailable>,
    },
    RawFile {
        path: PathBuf,
    },
    Proxy {
        env_vars: Vec<(String, String)>,
    },
    Ambient {
        source: Option<AmbientCredentialSourceConfig>,
        /// Visible-phantom template applied to every phantom issued for this
        /// credential. Parsed from the credential's `format`.
        template: Option<nono_proxy::token::PhantomTemplate>,
    },
}

impl ResolvedCredential {
    /// The visible-phantom template configured for an ambient credential, if any.
    pub(crate) fn phantom_template(&self) -> Option<nono_proxy::token::PhantomTemplate> {
        match self {
            Self::Ambient { template, .. } => template.clone(),
            _ => None,
        }
    }
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
                let (path, unavailable) = match resolve_local_socket_path(socket_template) {
                    Ok(socket) => (Some(socket), None),
                    Err(unavailable) => {
                        // Warn once here, at session start, rather than at the
                        // per-command consumption sites: those run for every
                        // invocation of every command that declares the
                        // credential, which would repeat one host-level fact
                        // on a loop. Only the degrading case is warned about —
                        // a contradicted declaration reports itself by failing
                        // the command that asked for it. The reason
                        // interpolates a filesystem path, so it is sanitized
                        // before reaching a terminal.
                        if let LocalSocketUnavailable::Absent(reason) = &unavailable {
                            tracing::warn!(
                                credential = %name,
                                reason = %crate::terminal_approval::sanitize_for_terminal(reason),
                                "local-socket credential unavailable; commands declaring it run without it"
                            );
                        }
                        (None, Some(unavailable))
                    }
                };
                resolved.insert(
                    name.clone(),
                    ResolvedCredential::LocalSocket {
                        path,
                        env_var: credential.env_var.clone(),
                        unavailable,
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

fn resolve_local_socket_path(value: &str) -> std::result::Result<PathBuf, LocalSocketUnavailable> {
    // Expand `$VAR` references anywhere in the string (e.g.
    // `$XDG_RUNTIME_DIR/ghtkn/agent.sock`), matching the policy-path expansion
    // used elsewhere. Strict expansion errors on an unset variable instead of
    // silently collapsing `$VAR/suffix` to `/suffix` — a silent path-widening bug.
    let expanded = crate::policy::expand_env_vars_strict(value).map_err(|e| match e {
        NonoError::EnvVarValidation { var, .. } => {
            LocalSocketUnavailable::Absent(format!("{var} is unset"))
        }
        other => LocalSocketUnavailable::CheckFailed(other.to_string()),
    })?;
    let path = PathBuf::from(expanded);
    let canonical = path
        .canonicalize()
        .map_err(|source| classify_path_error(&path, "resolve", source))?;
    check_local_socket(&canonical)?;
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::{LocalSocketUnavailable, resolve_local_socket_path};
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// Assert the resolver reported the socket as merely absent — the class that
    /// degrades to an omitted credential — and return the reason text.
    fn expect_absent(err: LocalSocketUnavailable) -> String {
        match err {
            LocalSocketUnavailable::Absent(reason) => reason,
            LocalSocketUnavailable::NotASocket(reason) => {
                panic!("expected an absent socket, got not-a-socket: {reason}")
            }
            LocalSocketUnavailable::CheckFailed(reason) => {
                panic!("expected an absent socket, got check failure: {reason}")
            }
        }
    }

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
        assert_eq!(expect_absent(err), format!("{UNSET_VAR} is unset"));
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
        assert_eq!(expect_absent(err), format!("{unset} is unset"));
    }

    /// A path that no longer resolves is absence, not misconfiguration: an agent
    /// that has exited leaves its variable set and its socket gone, and the
    /// commands declaring it must still run.
    #[test]
    fn missing_socket_path_is_absent_not_fatal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("never-created.sock");
        let err = resolve_local_socket_path(missing.to_str().expect("utf8 path"))
            .expect_err("missing socket must fail");
        let reason = expect_absent(err);
        assert!(
            reason.starts_with("failed to resolve "),
            "unexpected reason: {reason}"
        );
    }

    /// A path that resolves to a non-socket contradicts the profile's
    /// declaration, so it stays fatal instead of degrading into a silently
    /// omitted credential.
    #[test]
    fn regular_file_is_not_a_socket_and_stays_fatal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let regular = tmp.path().join("agent.sock");
        std::fs::write(&regular, b"not a socket").expect("write regular file");
        let err = resolve_local_socket_path(regular.to_str().expect("utf8 path"))
            .expect_err("regular file must fail");
        match err {
            LocalSocketUnavailable::NotASocket(reason) => {
                assert!(reason.ends_with(" is not a socket"), "reason: {reason}");
            }
            LocalSocketUnavailable::Absent(reason) => {
                panic!("a regular file must not degrade to absent: {reason}")
            }
            LocalSocketUnavailable::CheckFailed(reason) => {
                panic!("a regular file must be classified directly: {reason}")
            }
        }
    }

    #[test]
    fn symlink_loop_is_a_fatal_check_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = tmp.path().join("first.sock");
        let second = tmp.path().join("second.sock");
        std::os::unix::fs::symlink(&second, &first).expect("first symlink");
        std::os::unix::fs::symlink(&first, &second).expect("second symlink");

        let err = resolve_local_socket_path(first.to_str().expect("utf8 path"))
            .expect_err("a symlink loop must fail closed");
        assert!(
            matches!(err, LocalSocketUnavailable::CheckFailed(_)),
            "unexpected classification: {err:?}"
        );
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
