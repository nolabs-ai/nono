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

pub(crate) fn effective_argv(
    binary: &ResolvedCommandBinary,
    request: &ToolSandboxShimRequest,
    policy: &CommandSandboxConfig,
) -> Result<Vec<Vec<u8>>> {
    if request.argv.is_empty() {
        return Err(NonoError::SandboxInit(
            "tool-sandbox request had empty argv".to_string(),
        ));
    }
    let mut argv = Vec::with_capacity(request.argv.len() + policy.argv_prepend.len());
    argv.push(binary.canonical_path.as_os_str().as_bytes().to_vec());
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
    use crate::exec_strategy::env_sanitization::is_env_var_allowed;

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
