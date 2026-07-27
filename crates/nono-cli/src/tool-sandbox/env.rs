use crate::command_policy::{CommandSandboxConfig, ResolvedCommandBinary};
use crate::tool_sandbox::protocol::{
    TOOL_SANDBOX_LAUNCH_SPEC_ENV, TOOL_SANDBOX_SHIM_DIR_ENV, TOOL_SANDBOX_SOCKET_ENV,
    TOOL_SANDBOX_URL_SOCKET_ENV, ToolSandboxShimRequest,
};
use nono::{NonoError, Result};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

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

/// `preserve_caller_argv0` keeps the caller's argv[0] so argv[0]-dispatch
/// multi-call binaries (busybox, `docker-credential-*`) work; `exec` helpers
/// pass false. argv[0] never selects the executed file (that stays `binary`).
pub(crate) fn effective_argv_for_binary(
    binary: &ResolvedCommandBinary,
    request: &ToolSandboxShimRequest,
    policy: &CommandSandboxConfig,
    extra_args: &[Vec<u8>],
    preserve_caller_argv0: bool,
) -> Result<Vec<Vec<u8>>> {
    if request.argv.is_empty() {
        return Err(NonoError::SandboxInit(
            "tool-sandbox request had empty argv".to_string(),
        ));
    }
    let mut argv =
        Vec::with_capacity(request.argv.len() + policy.argv_prepend.len() + extra_args.len());
    if preserve_caller_argv0 {
        argv.push(request.argv[0].clone());
    } else {
        argv.push(binary.canonical_path.as_os_str().as_bytes().to_vec());
    }
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
/// command declares `open_urls` or `allow_launch_services`.
///
/// Both vars are stripped first (a child cannot smuggle its own) then set to
/// the runtime's URL socket and the open shim path. Needed for
/// `allow_launch_services` too: the shim only recognizes itself as the
/// URL-open relay when this env var is present, and a bare `open` in the
/// child's $PATH always resolves to the shim, never straight to
/// `/usr/bin/open`, once any command in the profile needs the shim. No-op
/// when URL opening is not enabled for this command.
pub(crate) fn inject_url_open_env(
    env: &mut Vec<Vec<u8>>,
    policy: &CommandSandboxConfig,
    url_socket_path: Option<&Path>,
    url_open_shim_path: Option<&Path>,
) {
    if policy.open_urls.is_none() && !policy.allow_launch_services {
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

/// `env` re-exec's the `<interp>` behind a `#!/usr/bin/env <interp>` shebang, so
/// it must be granted alongside `env` or the re-exec is denied. Parses `env`'s
/// own args enough to find `<interp>` and where it would be searched. Only ever
/// widens the allowlist.
pub(crate) fn env_shebang_target_interpreter(
    interp: &Path,
    interpreter_args: &[String],
) -> Option<PathBuf> {
    if interp.file_name() != Some(OsStr::new("env")) {
        return None;
    }
    let mut args = interpreter_args.iter();
    let mut search_path: Option<&str> = None;
    let target = loop {
        let arg = args.next()?;
        if arg == "--" {
            break args.next()?;
        }
        if matches!(arg.as_str(), "-u" | "-C" | "--unset" | "--chdir") {
            args.next()?;
        } else if arg == "-P" {
            // BSD alternate search path.
            search_path = args.next().map(String::as_str);
        } else if let Some((name, value)) = arg.split_once('=') {
            if name == "PATH" {
                search_path = Some(value);
            }
        } else if !arg.starts_with('-') {
            break arg;
        }
    };
    let candidate = Path::new(target);
    if candidate.is_absolute() {
        return Some(candidate.to_path_buf());
    }
    // A pinned search path is authoritative; falling back elsewhere would grant
    // a path `env` never searches. Cwd components aren't known at build time.
    if let Some(path_list) = search_path {
        for dir in path_list.split(':').map(Path::new) {
            if !dir.is_absolute() {
                continue;
            }
            let path = dir.join(target);
            if path.exists() {
                return Some(path);
            }
        }
        return None;
    }
    if let Ok(resolved) = which::which(target) {
        return Some(resolved);
    }
    // Supervisor PATH may be minimal at build time; try standard locations.
    for dir in ["/usr/bin", "/bin", "/usr/local/bin"] {
        let path = Path::new(dir).join(target);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_policy::{ResolvedExecutableKind, ResolvedExecutableShape};
    use crate::exec_strategy::env_sanitization::is_env_var_allowed;

    #[test]
    fn env_shebang_target_resolves_relative_against_inline_path() {
        // Homebrew-style shebangs pin PATH; resolve the relative interp there.
        let dir = tempfile::tempdir().expect("tempdir");
        let interp = dir.path().join("myinterp");
        std::fs::File::create(&interp).expect("create interp");
        let dir_str = dir.path().to_string_lossy().into_owned();

        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &[
                    "-S".to_string(),
                    format!("PATH={dir_str}"),
                    "myinterp".to_string(),
                ],
            ),
            Some(interp.clone()),
        );
        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &["-P".to_string(), dir_str, "myinterp".to_string()],
            ),
            Some(interp),
        );
    }

    #[test]
    fn env_shebang_target_pinned_path_does_not_widen_to_supervisor_path() {
        // Pinned path missing the interp must grant nothing, not widen to the
        // supervisor PATH. `sh` is on the supervisor PATH but not in `dir`.
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_str = dir.path().to_string_lossy().into_owned();
        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &[format!("PATH={dir_str}"), "sh".to_string()],
            ),
            None,
        );
        // Empty component means cwd, not resolved at build time; still no widen.
        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &["PATH=".to_string(), "sh".to_string()],
            ),
            None,
        );
    }

    #[test]
    fn env_shebang_target_resolves_absolute_interpreter() {
        // `#!/usr/bin/env /bin/bash` — absolute target is used verbatim.
        assert_eq!(
            env_shebang_target_interpreter(Path::new("/usr/bin/env"), &["/bin/bash".to_string()]),
            Some(PathBuf::from("/bin/bash")),
        );
    }

    #[test]
    fn env_shebang_target_none_for_non_env_interpreter() {
        // A direct `#!/bin/bash` shebang needs no extra grant.
        assert_eq!(
            env_shebang_target_interpreter(Path::new("/bin/bash"), &["x".to_string()]),
            None,
        );
    }

    #[test]
    fn env_shebang_target_none_when_no_interpreter_follows() {
        // Only option flags / assignments and no interpreter: nothing to grant.
        assert_eq!(
            env_shebang_target_interpreter(Path::new("/usr/bin/env"), &["-S".to_string()]),
            None,
        );
        assert_eq!(
            env_shebang_target_interpreter(Path::new("/usr/bin/env"), &["FOO=bar".to_string()]),
            None,
        );
        assert_eq!(
            env_shebang_target_interpreter(Path::new("/usr/bin/env"), &[]),
            None,
        );
    }

    #[test]
    fn env_shebang_target_honors_end_of_options() {
        // After `--` the next token is the interpreter verbatim.
        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &["--".to_string(), "/bin/bash".to_string()],
            ),
            Some(PathBuf::from("/bin/bash")),
        );
        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &["--".to_string(), "/opt/x=y".to_string()],
            ),
            Some(PathBuf::from("/opt/x=y")),
        );
    }

    #[test]
    fn env_shebang_target_skips_split_string_flag() {
        // `#!/usr/bin/env -S <interp> -u` — skip `-S`, resolve the interpreter.
        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &["-S".to_string(), "/bin/bash".to_string(), "-u".to_string()],
            ),
            Some(PathBuf::from("/bin/bash")),
        );
    }

    #[test]
    fn env_shebang_target_skips_env_assignments() {
        // `#!/usr/bin/env FOO=bar <interp>` — skip the assignment, resolve interp.
        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &["FOO=bar".to_string(), "/bin/bash".to_string()],
            ),
            Some(PathBuf::from("/bin/bash")),
        );
    }

    #[test]
    fn env_shebang_target_skips_value_consuming_options() {
        // `-u NAME` (GNU), `-C DIR` (GNU), `-P DIR` (BSD/macOS) consume the next
        // token; it is not the interpreter.
        for flag in ["-u", "-C", "-P"] {
            assert_eq!(
                env_shebang_target_interpreter(
                    Path::new("/usr/bin/env"),
                    &[
                        flag.to_string(),
                        "/tmp".to_string(),
                        "/bin/bash".to_string()
                    ],
                ),
                Some(PathBuf::from("/bin/bash")),
                "flag {flag} should consume its value token",
            );
        }
    }

    #[test]
    fn env_shebang_target_skips_flag_and_assignment_together() {
        // `#!/usr/bin/env -S FOO=bar <interp> -u` — skip both, resolve interp.
        assert_eq!(
            env_shebang_target_interpreter(
                Path::new("/usr/bin/env"),
                &[
                    "-S".to_string(),
                    "FOO=bar".to_string(),
                    "/bin/bash".to_string(),
                    "-u".to_string(),
                ],
            ),
            Some(PathBuf::from("/bin/bash")),
        );
    }

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

        let argv =
            effective_argv_for_binary(&helper, &request, &policy, &extra, false).expect("argv");
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
        let binary = test_binary("/usr/bin/gh");
        let request = test_request(&["gh", "pr", "list"]);
        let policy = CommandSandboxConfig::default();
        let argv = effective_argv_for_binary(&binary, &request, &policy, &[], true).expect("argv");
        let rendered: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        assert_eq!(rendered, vec!["gh", "pr", "list"]);
    }

    #[test]
    fn effective_argv_preserves_caller_argv0_for_symlink_dispatch() {
        // Multi-call binary: the child must see the invoked name, not the path.
        let binary = test_binary("/opt/homebrew/bin/docker-credential-helper");
        let request = test_request(&["docker-credential-osxkeychain", "get"]);
        let policy = CommandSandboxConfig::default();
        let argv = effective_argv_for_binary(&binary, &request, &policy, &[], true).expect("argv");
        let rendered: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        assert_eq!(rendered, vec!["docker-credential-osxkeychain", "get"]);
        // argv[0] didn't change the executed file.
        assert_eq!(
            binary.canonical_path,
            std::path::PathBuf::from("/opt/homebrew/bin/docker-credential-helper")
        );
    }

    #[test]
    fn effective_argv_helper_ignores_caller_argv0() {
        // exec helper keeps its own argv[0], even with no extra_args.
        let helper = test_binary("/opt/vendor/helper");
        let request = test_request(&["git", "push"]);
        let policy = CommandSandboxConfig::default();
        let argv = effective_argv_for_binary(&helper, &request, &policy, &[], false).expect("argv");
        let rendered: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        assert_eq!(rendered, vec!["/opt/vendor/helper", "push"]);
    }

    #[test]
    fn effective_argv_rejects_nul_in_extra_args() {
        let helper = test_binary("/opt/vendor/helper");
        let request = test_request(&["gh", "auth", "switch"]);
        let policy = CommandSandboxConfig::default();
        let extra = vec![b"a\0b".to_vec()];
        assert!(effective_argv_for_binary(&helper, &request, &policy, &extra, false).is_err());
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

    #[test]
    fn inject_url_open_env_covers_allow_launch_services_without_open_urls() {
        let policy = CommandSandboxConfig {
            allow_launch_services: true,
            ..Default::default()
        };
        let mut env = Vec::new();
        inject_url_open_env(
            &mut env,
            &policy,
            Some(Path::new("/tmp/url.sock")),
            Some(Path::new("/tmp/shims/open")),
        );

        let socket_prefix = format!("{TOOL_SANDBOX_URL_SOCKET_ENV}=").into_bytes();
        assert!(
            env.iter().any(|e| e.starts_with(&socket_prefix)),
            "allow_launch_services must get the URL socket env var, since the shim only \
             recognizes itself as the URL-open relay when it's present"
        );
        assert!(
            env.iter().any(|e| e.starts_with(b"BROWSER=")),
            "allow_launch_services must get BROWSER pointed at the shim too"
        );
    }

    #[test]
    fn inject_url_open_env_noop_without_open_urls_or_launch_services() {
        let policy = CommandSandboxConfig::default();
        let mut env = Vec::new();
        inject_url_open_env(
            &mut env,
            &policy,
            Some(Path::new("/tmp/url.sock")),
            Some(Path::new("/tmp/shims/open")),
        );
        assert!(
            env.is_empty(),
            "a command with neither policy must get no URL-open env vars"
        );
    }
}
