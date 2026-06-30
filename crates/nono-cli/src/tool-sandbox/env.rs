use crate::command_policy::{CommandSandboxConfig, ResolvedCommandBinary};
use crate::tool_sandbox::protocol::{
    TOOL_SANDBOX_LAUNCH_SPEC_ENV, TOOL_SANDBOX_SHIM_DIR_ENV, TOOL_SANDBOX_SOCKET_ENV,
    TOOL_SANDBOX_URL_SOCKET_ENV, ToolSandboxShimRequest,
};
use nono::{NonoError, Result};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const DEFAULT_ENV_ALLOW: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_*",
    "TZ",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

pub(crate) fn default_env_allow_patterns() -> Vec<String> {
    DEFAULT_ENV_ALLOW
        .iter()
        .map(|value| value.to_string())
        .collect()
}

/// Build the child argv: argv[0] is the binary's canonical path, then
/// `extra_args` (the `exec` helper's fixed leading args, empty for normal
/// commands), then the policy's `argv_prepend`, then the forwarded user args
/// (`request.argv[1..]`). NUL bytes in `extra_args`/`argv_prepend` are rejected.
pub(crate) fn effective_argv_for_binary(
    binary: &ResolvedCommandBinary,
    request: &ToolSandboxShimRequest,
    policy: &CommandSandboxConfig,
    extra_args: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>> {
    if request.argv.is_empty() {
        return Err(NonoError::SandboxInit(
            "tool-sandbox request had empty argv".to_string(),
        ));
    }
    let mut argv =
        Vec::with_capacity(request.argv.len() + policy.argv_prepend.len() + extra_args.len());
    argv.push(binary.canonical_path.as_os_str().as_bytes().to_vec());
    for arg in extra_args {
        if arg.contains(&0) {
            return Err(NonoError::ConfigParse(
                "tool-sandbox exec helper arg contains NUL".to_string(),
            ));
        }
        argv.push(arg.clone());
    }
    for arg in &policy.argv_prepend {
        if arg.as_bytes().contains(&0) {
            return Err(NonoError::ConfigParse(
                "tool-sandbox policy argv_prepend contains NUL".to_string(),
            ));
        }
        argv.push(arg.as_bytes().to_vec());
    }
    argv.extend(request.argv.iter().skip(1).cloned());
    Ok(argv)
}

pub(crate) fn apply_environment_set_vars(
    env: &mut Vec<Vec<u8>>,
    policy: &CommandSandboxConfig,
) -> Result<()> {
    let Some(environment) = &policy.environment else {
        return Ok(());
    };
    for (name, value) in &environment.set_vars {
        if name.is_empty()
            || name == "PATH"
            || name.starts_with("NONO_")
            || name.contains('*')
            || name.contains('=')
            || name.as_bytes().contains(&0)
            || value.as_bytes().contains(&0)
        {
            return Err(NonoError::ConfigParse(format!(
                "invalid tool-sandbox environment.set_vars entry '{name}'"
            )));
        }
        if crate::exec_strategy::env_sanitization::is_dangerous_env_var(name) {
            return Err(NonoError::ConfigParse(format!(
                "tool-sandbox environment.set_vars rejects dangerous key '{name}'"
            )));
        }
        let prefix = format!("{name}=");
        env.retain(|entry| !entry.starts_with(prefix.as_bytes()));
        let mut entry = name.as_bytes().to_vec();
        entry.push(b'=');
        entry.extend(value.as_bytes());
        env.push(entry);
    }
    Ok(())
}

pub(crate) fn inject_chaining_control_env(
    env: &mut Vec<Vec<u8>>,
    socket_path: &Path,
    shim_dir: &Path,
) {
    let socket_prefix = format!("{TOOL_SANDBOX_SOCKET_ENV}=");
    let shim_dir_prefix = format!("{TOOL_SANDBOX_SHIM_DIR_ENV}=");
    let launch_spec_prefix = format!("{TOOL_SANDBOX_LAUNCH_SPEC_ENV}=");
    env.retain(|entry| {
        !entry.starts_with(socket_prefix.as_bytes())
            && !entry.starts_with(shim_dir_prefix.as_bytes())
            && !entry.starts_with(launch_spec_prefix.as_bytes())
    });
    env.push(format!("{TOOL_SANDBOX_SOCKET_ENV}={}", socket_path.display()).into_bytes());
    env.push(format!("{TOOL_SANDBOX_SHIM_DIR_ENV}={}", shim_dir.display()).into_bytes());
}

/// Inject the URL-open socket env var and `BROWSER` for a brokered child whose
/// command declares `open_urls` and did not opt into direct LaunchServices.
///
/// Both vars are stripped first (a child cannot smuggle its own) then set to
/// the runtime's URL socket and the open shim path. No-op when URL opening is
/// not enabled for this command.
pub(crate) fn inject_url_open_env(
    env: &mut Vec<Vec<u8>>,
    policy: &CommandSandboxConfig,
    url_socket_path: Option<&Path>,
    url_open_shim_path: Option<&Path>,
) {
    if policy.open_urls.is_none() || policy.allow_launch_services {
        return;
    }
    let (Some(url_socket_path), Some(shim_path)) = (url_socket_path, url_open_shim_path) else {
        return;
    };

    let socket_prefix = format!("{TOOL_SANDBOX_URL_SOCKET_ENV}=").into_bytes();
    env.retain(|entry| !entry.starts_with(&socket_prefix));
    let mut socket_entry = socket_prefix;
    socket_entry.extend_from_slice(url_socket_path.as_os_str().as_bytes());
    env.push(socket_entry);

    // Point BROWSER at the open shim so libraries that honour it route through
    // the runtime instead of attempting a (denied) direct browser launch.
    let browser_prefix = b"BROWSER=".to_vec();
    env.retain(|entry| !entry.starts_with(&browser_prefix));
    let mut browser_entry = browser_prefix;
    browser_entry.extend_from_slice(shim_path.as_os_str().as_bytes());
    env.push(browser_entry);
}

pub(crate) fn split_env_entry(entry: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = entry.iter().position(|byte| *byte == b'=')?;
    Some((&entry[..pos], &entry[pos + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_policy::{ResolvedExecutableKind, ResolvedExecutableShape};
    use crate::exec_strategy::env_sanitization::is_env_var_allowed;

    fn test_binary(path: &str) -> ResolvedCommandBinary {
        ResolvedCommandBinary {
            name: "cmd".to_string(),
            canonical_path: std::path::PathBuf::from(path),
            dev: 0,
            ino: 0,
            size: 0,
            mtime_nanos: 0,
            sha256: String::new(),
            duplicate_paths: vec![],
            shape: ResolvedExecutableShape {
                kind: ResolvedExecutableKind::Other,
                interpreter: None,
                interpreter_args: vec![],
            },
        }
    }

    fn test_request(argv: &[&str]) -> ToolSandboxShimRequest {
        ToolSandboxShimRequest {
            command: "gh".to_string(),
            argv: argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
            env: vec![],
            cwd: b"/".to_vec(),
            stdio_tty: [false; 3],
        }
    }

    #[test]
    fn effective_argv_forwards_helper_then_prepend_then_user_args() {
        // argv layout for an `exec` helper:
        // [helper, extra_args.., argv_prepend.., user_args (request.argv[1..])].
        let helper = test_binary("/opt/vendor/gh-wrapper");
        let request = test_request(&["gh", "auth", "switch", "--user", "someuser"]);
        let policy = CommandSandboxConfig {
            argv_prepend: vec!["--prepended".to_string()],
            ..Default::default()
        };
        let extra = vec![b"helperarg".to_vec()];

        let argv = effective_argv_for_binary(&helper, &request, &policy, &extra).expect("argv");
        let rendered: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        assert_eq!(
            rendered,
            vec![
                "/opt/vendor/gh-wrapper",
                "helperarg",
                "--prepended",
                "auth",
                "switch",
                "--user",
                "someuser",
            ]
        );
    }

    #[test]
    fn effective_argv_normal_command_has_no_extra_args() {
        // The non-exec path passes `&[]`, so argv is [binary, argv_prepend.., user_args].
        let binary = test_binary("/usr/bin/gh");
        let request = test_request(&["gh", "pr", "list"]);
        let policy = CommandSandboxConfig::default();
        let argv = effective_argv_for_binary(&binary, &request, &policy, &[]).expect("argv");
        let rendered: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        assert_eq!(rendered, vec!["/usr/bin/gh", "pr", "list"]);
    }

    #[test]
    fn effective_argv_rejects_nul_in_extra_args() {
        let helper = test_binary("/opt/vendor/helper");
        let request = test_request(&["gh", "auth", "switch"]);
        let policy = CommandSandboxConfig::default();
        let extra = vec![b"a\0b".to_vec()];
        assert!(effective_argv_for_binary(&helper, &request, &policy, &extra).is_err());
    }

    #[test]
    fn tls_trust_bundle_vars_are_in_default_allow() {
        let patterns = default_env_allow_patterns();
        for var in &[
            "SSL_CERT_FILE",
            "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            assert!(
                is_env_var_allowed(var, &patterns),
                "{var} must be allowed so tool-sandbox children can verify TLS through the intercept proxy"
            );
        }
    }
}
