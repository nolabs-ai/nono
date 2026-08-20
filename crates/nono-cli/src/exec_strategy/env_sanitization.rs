//! Environment sanitization boundary for sandboxed execution.
//!
//! Threat model:
//! - Untrusted parent/shell environments may inject execution behavior via
//!   linker, shell, or interpreter environment variables.
//! - All sandbox execution strategies must share one allow/deny implementation
//!   to avoid drift in security behavior across code paths.

use std::borrow::Cow;

/// Returns true if an environment variable is unsafe to inherit into a sandboxed child.
///
/// Covers linker injection (LD_PRELOAD, DYLD_INSERT_LIBRARIES), shell startup
/// injection (BASH_ENV, PROMPT_COMMAND, IFS), and interpreter code/module injection
/// (NODE_OPTIONS, PYTHONPATH, PERL5OPT, RUBYOPT, JAVA_TOOL_OPTIONS, etc.).
pub(crate) fn is_dangerous_env_var(key: &str) -> bool {
    is_loader_injection_env_var(key)
        // Shell injection
        || key == "BASH_ENV"
        || key == "ENV"
        || key == "CDPATH"
        || key == "GLOBIGNORE"
        || key.starts_with("BASH_FUNC_")
        || key == "PROMPT_COMMAND"
        || key == "IFS"
        // Python injection
        || key == "PYTHONSTARTUP"
        || key == "PYTHONPATH"
        // Node.js injection
        || key == "NODE_OPTIONS"
        || key == "NODE_PATH"
        // Perl injection
        || key == "PERL5OPT"
        || key == "PERL5LIB"
        // Ruby injection
        || key == "RUBYOPT"
        || key == "RUBYLIB"
        || key == "GEM_PATH"
        || key == "GEM_HOME"
        // JVM injection
        || key == "JAVA_TOOL_OPTIONS"
        || key == "_JAVA_OPTIONS"
        // .NET injection
        || key == "DOTNET_STARTUP_HOOKS"
        // Go injection
        || key == "GOFLAGS"
        || is_forbidden_secret_env_var(key)
}

/// 1Password meta-secrets — credentials, not tooling vars, so `export_env`
/// must never re-admit them even by exact name.
pub(crate) fn is_forbidden_secret_env_var(key: &str) -> bool {
    key == "OP_SERVICE_ACCOUNT_TOKEN"
        || key == "OP_CONNECT_TOKEN"
        || key == "OP_CONNECT_HOST"
        || key.starts_with("OP_SESSION_")
}

/// Loader vars hit any dynamically-linked child, not just an interpreter, so
/// `export_env` requires an exact-name pattern for these — `*`/prefix isn't enough.
pub(crate) fn is_loader_injection_env_var(key: &str) -> bool {
    key.starts_with("LD_") || key.starts_with("DYLD_")
}

/// Whether `text` matches `pattern`, where `*` in `pattern` matches any run of
/// zero or more characters (including none), anchored to the full string.
/// `*` is the only wildcard; every other character is matched literally.
fn glob_matches(pattern: &str, text: &str) -> bool {
    // An empty pattern is invalid and must never act as an implicit match-all
    // (every branch below treats "" as "no constraint").
    if pattern.is_empty() {
        return false;
    }
    // `split('*')` always yields at least one item, so an empty `parts` here
    // is impossible; a pattern with no `*` is just an exact match.
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let mut parts = parts.peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            // Last segment: must match the remaining text as a suffix.
            return rest.ends_with(part);
        }
        if part.is_empty() {
            continue;
        }
        match rest.find(part) {
            Some(idx) => rest = &rest[idx + part.len()..],
            None => return false,
        }
    }
    true
}

/// Returns true if `key` matches any pattern in `patterns`.
///
/// `*` may appear anywhere in a pattern — leading, trailing, or infix — and
/// matches any run of characters: `"AWS_*"`, `"*_TOKEN"`, `"*SECRET*"`, and
/// `"AWS_*_TOKEN"` are all valid. A bare `"*"` matches everything. Matching
/// is anchored to the full variable name.
///
/// When `case_insensitive` is true, both `key` and every pattern are
/// lowercased (ASCII-only) before comparison.
pub(crate) fn matches_env_var_patterns(
    key: &str,
    patterns: &[String],
    case_insensitive: bool,
) -> bool {
    let key = if case_insensitive {
        Cow::Owned(key.to_ascii_lowercase())
    } else {
        Cow::Borrowed(key)
    };
    patterns.iter().any(|pattern| {
        if case_insensitive {
            glob_matches(&pattern.to_ascii_lowercase(), &key)
        } else {
            glob_matches(pattern, &key)
        }
    })
}

/// Returns true if an environment variable matches the allow-list.
/// See [`matches_env_var_patterns`] for the pattern grammar.
pub(crate) fn is_env_var_allowed(key: &str, allowed_env_vars: &[String]) -> bool {
    matches_env_var_patterns(key, allowed_env_vars, false)
}

/// Validates env var patterns before they are used for matching.
/// `field_name` is used in the error message (e.g. `"allow_vars"` or `"deny_vars"`).
/// Returns an error message describing the first invalid pattern, or None if valid.
pub(crate) fn validate_env_var_patterns(patterns: &[String], field_name: &str) -> Option<String> {
    for pattern in patterns {
        if pattern.is_empty() {
            return Some(format!("Invalid {field_name} pattern: empty pattern"));
        }
        if pattern.contains('\0') {
            return Some(format!(
                "Invalid {field_name} pattern '{pattern}': contains a NUL byte"
            ));
        }
    }
    None
}

/// Returns true if `name` is a valid POSIX environment variable name:
/// a non-empty `[A-Za-z_][A-Za-z0-9_]*` with no `=` or NUL.
fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Validates `environment.set_vars` keys before they are injected into the
/// sandboxed child. Returns an error message describing the first invalid key,
/// or `None` if all keys are acceptable.
///
/// Rejected keys:
/// - `PATH` (reserved; controlled via allow/deny filtering, not injection)
/// - any `NONO_*` key (reserved for nono's own injected variables)
/// - empty or syntactically invalid names (must match `[A-Za-z_][A-Za-z0-9_]*`)
///
/// The dangerous-variable blocklist (`LD_PRELOAD`, `NODE_OPTIONS`, …) is
/// intentionally NOT applied here: that defense targets injection from an
/// untrusted parent shell, whereas `set_vars` is explicit operator intent.
pub(crate) fn validate_set_vars(
    set_vars: &std::collections::HashMap<String, String>,
) -> Option<String> {
    for key in set_vars.keys() {
        if key == "PATH" {
            return Some(
                "Invalid set_vars key 'PATH': PATH is reserved; use allow_vars/deny_vars to \
                 control it"
                    .to_string(),
            );
        }
        if key.starts_with("NONO_") {
            return Some(format!(
                "Invalid set_vars key '{}': the NONO_* prefix is reserved",
                key
            ));
        }
        if !is_valid_env_var_name(key) {
            return Some(format!(
                "Invalid set_vars key '{}': environment variable names must match \
                 [A-Za-z_][A-Za-z0-9_]*",
                key
            ));
        }
    }
    None
}

/// Replacement value for an inherited env var that names a working directory,
/// or `None` to copy the inherited value through unchanged.
///
/// `child_pwd` is `Some` only when the child starts in a directory other than the
/// one nono was launched from. `host_pwd` is `Some` only when the inherited `$PWD`
/// was vouched for by [`trusted_host_pwd`].
pub(super) fn rewrite_workdir_env_var<'a>(
    key: &str,
    host_pwd: Option<&'a std::ffi::OsStr>,
    child_pwd: Option<&'a std::path::Path>,
) -> Option<&'a std::ffi::OsStr> {
    let child_pwd = child_pwd?;
    let child_pwd = child_pwd.as_os_str();
    if host_pwd == Some(child_pwd) {
        return None;
    }
    match key {
        "PWD" => Some(child_pwd),
        "OLDPWD" => host_pwd,
        _ => None,
    }
}

/// Whether the working-directory rewrite may run at all for this session.
///
/// `set_vars` is injected after the inherited-env loop, so an operator-supplied
/// `PWD` wins over any rewrite. Standing down keeps `$OLDPWD` from describing a
/// move away from a directory that `$PWD` never names.
pub(super) fn pwd_rewrite_permitted(
    config_env_vars: &[(&str, &str)],
    set_vars: &[(String, String)],
    blocked_extra: &[&str],
    denied_env_vars: Option<&[String]>,
    allowed_env_vars: Option<&[String]>,
    case_insensitive_env_vars: bool,
) -> bool {
    if set_vars.iter().any(|(key, _)| key == "PWD") {
        return false;
    }
    env_var_survives_filters(
        "PWD",
        config_env_vars,
        blocked_extra,
        denied_env_vars,
        allowed_env_vars,
        case_insensitive_env_vars,
    )
}

/// The host `$PWD` eligible to drive `$OLDPWD` in [`rewrite_workdir_env_var`], or
/// `None` when the inherited value cannot be trusted.
pub(crate) fn host_pwd_before_sandbox(
    launch_cwd: Option<&std::path::Path>,
) -> Option<std::ffi::OsString> {
    trusted_host_pwd(std::env::var_os("PWD"), launch_cwd)
}

/// The host `$PWD`, accepted only when it is a spelling of the directory nono was
/// launched from.
///
/// Mirrors the guard in [`crate::sandbox_prepare`]'s `resolved_workdir`: a `$PWD` that
/// does not canonicalise to `getcwd()` is stale or spoofed, and copying it into the
/// child's `$OLDPWD` would tell the child it came from a directory it was never in.
/// When `getcwd()` itself is unavailable there is nothing to validate against, so the
/// value is rejected rather than trusted. Rejection only stands the `$OLDPWD` arm of
/// the rewrite down; correcting `$PWD` needs no trust in the inherited value.
fn trusted_host_pwd(
    raw_pwd: Option<std::ffi::OsString>,
    launch_cwd: Option<&std::path::Path>,
) -> Option<std::ffi::OsString> {
    let pwd = raw_pwd?;
    // A non-UTF-8 value is dropped from the child environment, so a `PWD` spelt
    // in one never reaches the child; rewriting `$OLDPWD` from it would claim a
    // move away from a directory the child is never told it started in.
    pwd.to_str()?;

    let launch_cwd = launch_cwd?;
    let path = std::path::Path::new(&pwd);
    if !path.is_absolute() || path.canonicalize().ok()? != launch_cwd {
        return None;
    }
    Some(pwd)
}

/// Decide whether an inherited env var should be dropped for sandbox execution.
fn should_skip_env_var(
    key: &str,
    config_env_vars: &[(&str, &str)],
    blocked_extra: &[&str],
) -> bool {
    config_env_vars.iter().any(|(ek, _)| *ek == key)
        || blocked_extra.contains(&key)
        || is_dangerous_env_var(key)
}

/// Whether an inherited env var survives every environment filter and reaches the
/// sandboxed child.
pub(super) fn env_var_survives_filters(
    key: &str,
    config_env_vars: &[(&str, &str)],
    blocked_extra: &[&str],
    denied_env_vars: Option<&[String]>,
    allowed_env_vars: Option<&[String]>,
    case_insensitive_env_vars: bool,
) -> bool {
    if should_skip_env_var(key, config_env_vars, blocked_extra) {
        return false;
    }
    if let Some(denied) = denied_env_vars
        && matches_env_var_patterns(key, denied, case_insensitive_env_vars)
    {
        return false;
    }
    if let Some(allowed) = allowed_env_vars
        && !matches_env_var_patterns(key, allowed, case_insensitive_env_vars)
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    // ============================================================================
    // 1Password env var blocklist — security-critical regression tests
    //
    // These vars are credential or session leaks that must NEVER reach a
    // sandboxed child process. If a future refactor accidentally removes one,
    // these tests will catch it.
    // ============================================================================

    #[test]
    fn test_blocks_op_service_account_token() {
        assert!(is_dangerous_env_var("OP_SERVICE_ACCOUNT_TOKEN"));
    }

    #[test]
    fn test_blocks_op_connect_token() {
        assert!(is_dangerous_env_var("OP_CONNECT_TOKEN"));
    }

    #[test]
    fn test_blocks_op_connect_host() {
        assert!(is_dangerous_env_var("OP_CONNECT_HOST"));
    }

    #[test]
    fn test_blocks_op_session_prefix() {
        // OP_SESSION_* vars carry per-account bearer tokens
        assert!(is_dangerous_env_var("OP_SESSION_my_team"));
        assert!(is_dangerous_env_var("OP_SESSION_personal"));
        assert!(is_dangerous_env_var("OP_SESSION_"));
    }

    #[test]
    fn test_allows_unrelated_env_vars() {
        // Env vars that happen to start with "OP" but aren't 1Password
        assert!(!is_dangerous_env_var("OPENAI_API_KEY"));
        assert!(!is_dangerous_env_var("OPERATOR_TOKEN"));
        assert!(!is_dangerous_env_var("OPTIONS"));
        assert!(!is_dangerous_env_var("HOME"));
        assert!(!is_dangerous_env_var("PATH"));
    }

    // ============================================================================
    // Existing categories — spot-check that the broader blocklist still works
    // ============================================================================

    #[test]
    fn test_blocks_linker_injection() {
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
    }

    #[test]
    fn test_blocks_interpreter_injection() {
        assert!(is_dangerous_env_var("NODE_OPTIONS"));
        assert!(is_dangerous_env_var("PYTHONPATH"));
        assert!(is_dangerous_env_var("RUBYOPT"));
    }

    // ============================================================================
    // Environment variable allow-list — is_env_var_allowed
    // ============================================================================

    #[test]
    fn test_env_var_allowed_exact_match() {
        let allowed: Vec<String> = vec!["PATH".into(), "HOME".into()];
        assert!(is_env_var_allowed("PATH", &allowed));
        assert!(is_env_var_allowed("HOME", &allowed));
    }

    #[test]
    fn test_env_var_allowed_exact_no_match() {
        let allowed: Vec<String> = vec!["PATH".into(), "HOME".into()];
        assert!(!is_env_var_allowed("SECRET", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_match() {
        let allowed: Vec<String> = vec!["AWS_*".into()];
        assert!(is_env_var_allowed("AWS_REGION", &allowed));
        assert!(is_env_var_allowed("AWS_SECRET_ACCESS_KEY", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_no_match() {
        let allowed: Vec<String> = vec!["AWS_*".into()];
        assert!(!is_env_var_allowed("GCP_REGION", &allowed));
    }

    #[test]
    fn test_env_var_allowed_empty_list() {
        let allowed: Vec<String> = vec![];
        assert!(!is_env_var_allowed("PATH", &allowed));
    }

    #[test]
    fn test_env_var_allowed_bare_star() {
        let allowed: Vec<String> = vec!["*".into()];
        assert!(is_env_var_allowed("ANYTHING", &allowed));
        assert!(is_env_var_allowed("PATH", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_does_not_match_partial() {
        let allowed: Vec<String> = vec!["AWS_*".into()];
        assert!(!is_env_var_allowed("AWS", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_matches_empty_suffix() {
        let allowed: Vec<String> = vec!["AWS_*".into()];
        assert!(is_env_var_allowed("AWS_", &allowed));
    }

    #[test]
    fn test_env_var_allowed_mixed_patterns() {
        let allowed: Vec<String> = vec!["PATH".into(), "AWS_*".into()];
        assert!(is_env_var_allowed("PATH", &allowed));
        assert!(is_env_var_allowed("AWS_REGION", &allowed));
        assert!(!is_env_var_allowed("HOME", &allowed));
    }

    #[test]
    fn test_env_var_allowed_mid_star_matches_infix_wildcard() {
        let allowed: Vec<String> = vec!["A*B".into()];
        assert!(is_env_var_allowed("AXB", &allowed));
        assert!(is_env_var_allowed("AB", &allowed));
        assert!(!is_env_var_allowed("AXBY", &allowed));
        assert!(!is_env_var_allowed("XAB", &allowed));
    }

    #[test]
    fn test_env_var_allowed_leading_star_matches_suffix() {
        let allowed: Vec<String> = vec!["*_TOKEN".into()];
        assert!(is_env_var_allowed("GH_TOKEN", &allowed));
        assert!(!is_env_var_allowed("GH_SECRET", &allowed));
    }

    #[test]
    fn test_env_var_allowed_contains_star_matches_substring() {
        let allowed: Vec<String> = vec!["*SECRET*".into()];
        assert!(is_env_var_allowed("MY_SECRET_KEY", &allowed));
        assert!(is_env_var_allowed("SECRET", &allowed));
        assert!(!is_env_var_allowed("PUBLIC_KEY", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_and_suffix_wildcard() {
        let allowed: Vec<String> = vec!["AWS_*_TOKEN".into()];
        assert!(is_env_var_allowed("AWS_SESSION_TOKEN", &allowed));
        assert!(!is_env_var_allowed("AWS_SESSION_SECRET", &allowed));
    }

    #[test]
    fn test_env_var_allowed_case_insensitive_mode() {
        let allowed: Vec<String> = vec!["*token*".into()];
        assert!(matches_env_var_patterns("JENKINS_TOKEN", &allowed, true));
        assert!(matches_env_var_patterns("jenkins_token", &allowed, true));
        assert!(matches_env_var_patterns("Jenkins_Token", &allowed, true));
        assert!(!matches_env_var_patterns("JENKINS_TOKEN", &allowed, false));
    }

    // ============================================================================
    // Pattern validation — validate_env_var_patterns
    // ============================================================================

    #[test]
    fn test_validate_valid_patterns() {
        let patterns: Vec<String> = vec![
            "PATH".into(),
            "AWS_*".into(),
            "*".into(),
            "*_TOKEN".into(),
            "*SECRET*".into(),
            "AWS_*_TOKEN".into(),
        ];
        assert!(validate_env_var_patterns(&patterns, "allow_vars").is_none());
    }

    #[test]
    fn test_validate_rejects_empty_pattern() {
        let patterns: Vec<String> = vec!["".into()];
        let err = validate_env_var_patterns(&patterns, "allow_vars");
        assert!(err.is_some());
    }

    #[test]
    fn test_empty_pattern_never_matches_anything() {
        // `prepare_profile` only warns on an invalid pattern rather than
        // dropping it, so the matcher itself must fail closed here: a stray
        // `""` in `allow_vars` must never act as an implicit "*".
        let patterns: Vec<String> = vec!["".into()];
        assert!(!matches_env_var_patterns(
            "ANTHROPIC_API_KEY",
            &patterns,
            false
        ));
        assert!(!matches_env_var_patterns("", &patterns, false));
    }

    #[test]
    fn test_validate_rejects_nul_byte() {
        let patterns: Vec<String> = vec!["AWS_\0TOKEN".into()];
        let err = validate_env_var_patterns(&patterns, "deny_vars");
        assert!(err.as_ref().is_some_and(|e| e.contains("deny_vars")));
    }

    #[test]
    fn test_validate_accepts_bare_star() {
        let patterns: Vec<String> = vec!["*".into()];
        assert!(validate_env_var_patterns(&patterns, "allow_vars").is_none());
    }

    #[test]
    fn test_validate_exact_name_no_star() {
        let patterns: Vec<String> = vec!["PATH".into()];
        assert!(validate_env_var_patterns(&patterns, "allow_vars").is_none());
    }

    // ============================================================================
    // is_env_var_denied
    // ============================================================================

    #[test]
    fn test_env_var_denied_exact_match() {
        let denied: Vec<String> = vec!["GH_TOKEN".into(), "ANTHROPIC_API_KEY".into()];
        assert!(matches_env_var_patterns("GH_TOKEN", &denied, false));
        assert!(matches_env_var_patterns(
            "ANTHROPIC_API_KEY",
            &denied,
            false
        ));
    }

    #[test]
    fn test_env_var_denied_prefix_match() {
        let denied: Vec<String> = vec!["GITHUB_*".into()];
        assert!(matches_env_var_patterns("GITHUB_TOKEN", &denied, false));
        assert!(matches_env_var_patterns("GITHUB_ACTIONS", &denied, false));
        assert!(!matches_env_var_patterns("GH_TOKEN", &denied, false));
    }

    #[test]
    fn test_env_var_denied_no_match() {
        let denied: Vec<String> = vec!["GH_TOKEN".into()];
        assert!(!matches_env_var_patterns("PATH", &denied, false));
        assert!(!matches_env_var_patterns("HOME", &denied, false));
    }

    #[test]
    fn test_env_var_denied_empty_list() {
        let denied: Vec<String> = vec![];
        assert!(!matches_env_var_patterns("GH_TOKEN", &denied, false));
    }

    #[test]
    fn test_env_var_denied_overrides_allowed() {
        // Simulates: deny_vars has GH_TOKEN, allow_vars has GH_TOKEN
        // deny wins: denied should return true regardless of allowed
        let denied: Vec<String> = vec!["GH_TOKEN".into()];
        let allowed: Vec<String> = vec!["GH_TOKEN".into()];
        assert!(matches_env_var_patterns("GH_TOKEN", &denied, false));
        assert!(is_env_var_allowed("GH_TOKEN", &allowed));
        // In exec path, deny is checked before allow, so GH_TOKEN is stripped
    }

    // ============================================================================
    // set_vars validation
    // ============================================================================

    fn set_vars_from(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn test_set_vars_accepts_normal_keys() {
        let set_vars = set_vars_from(&[("RUST_LOG", "debug"), ("MY_VAR", "value")]);
        assert_eq!(validate_set_vars(&set_vars), None);
    }

    #[test]
    fn test_set_vars_accepts_dangerous_keys() {
        // set_vars is explicit operator intent: dangerous keys are NOT blocked.
        let set_vars = set_vars_from(&[("LD_PRELOAD", "/tmp/x.so")]);
        assert_eq!(validate_set_vars(&set_vars), None);
        let set_vars = set_vars_from(&[("NODE_OPTIONS", "--max-old-space-size=4096")]);
        assert_eq!(validate_set_vars(&set_vars), None);
        let set_vars = set_vars_from(&[("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib")]);
        assert_eq!(validate_set_vars(&set_vars), None);
    }

    #[test]
    fn test_set_vars_rejects_path() {
        let set_vars = set_vars_from(&[("PATH", "/usr/bin")]);
        assert!(validate_set_vars(&set_vars).is_some());
    }

    #[test]
    fn test_set_vars_rejects_nono_prefix() {
        let set_vars = set_vars_from(&[("NONO_FOO", "bar")]);
        assert!(validate_set_vars(&set_vars).is_some());
        let set_vars = set_vars_from(&[("NONO_CAP_FILE", "/tmp/cap")]);
        assert!(validate_set_vars(&set_vars).is_some());
    }

    #[test]
    fn test_set_vars_rejects_invalid_names() {
        // empty name
        assert!(validate_set_vars(&set_vars_from(&[("", "v")])).is_some());
        // leading digit
        assert!(validate_set_vars(&set_vars_from(&[("1FOO", "v")])).is_some());
        // contains '='
        assert!(validate_set_vars(&set_vars_from(&[("A=B", "v")])).is_some());
        // contains a dash
        assert!(validate_set_vars(&set_vars_from(&[("MY-VAR", "v")])).is_some());
    }

    #[test]
    fn test_set_vars_empty_is_ok() {
        let set_vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        assert_eq!(validate_set_vars(&set_vars), None);
    }

    #[test]
    fn test_workdir_vars_rewritten_when_child_relocates() {
        let child = Some(std::path::Path::new("/tmp/foo"));
        assert_eq!(
            rewrite_workdir_env_var("PWD", Some(OsStr::new("/tmp/bar")), child),
            Some(OsStr::new("/tmp/foo"))
        );
        assert_eq!(
            rewrite_workdir_env_var("OLDPWD", Some(OsStr::new("/tmp/bar")), child),
            Some(OsStr::new("/tmp/bar"))
        );
    }

    #[test]
    fn test_workdir_vars_inherited_when_child_stays_put() {
        assert_eq!(
            rewrite_workdir_env_var("PWD", Some(OsStr::new("/tmp/bar")), None),
            None
        );
        assert_eq!(
            rewrite_workdir_env_var("OLDPWD", Some(OsStr::new("/tmp/bar")), None),
            None
        );
    }

    #[test]
    fn test_pwd_corrected_even_when_host_pwd_is_untrusted() {
        let child = Some(std::path::Path::new("/tmp/foo"));
        assert_eq!(
            rewrite_workdir_env_var("PWD", None, child),
            Some(OsStr::new("/tmp/foo"))
        );
    }

    #[test]
    fn test_rewrite_replaces_but_never_introduces() {
        let child = Some(std::path::Path::new("/tmp/foo"));
        assert_eq!(rewrite_workdir_env_var("OLDPWD", None, child), None);
    }

    #[test]
    fn test_oldpwd_unchanged_when_pwd_is_correct() {
        let child = Some(std::path::Path::new("/tmp/foo"));
        assert_eq!(
            rewrite_workdir_env_var("OLDPWD", Some(OsStr::new("/tmp/foo")), child),
            None
        );
    }

    #[test]
    fn test_unrelated_keys_never_rewritten() {
        let child = Some(std::path::Path::new("/tmp/foo"));
        for key in ["HOME", "PWDX", "MYPWD", "pwd", ""] {
            assert_eq!(
                rewrite_workdir_env_var(key, Some(OsStr::new("/tmp/bar")), child),
                None,
                "key {key} should not be rewritten"
            );
        }
    }

    #[test]
    fn test_non_utf8_workdir_round_trips() {
        use std::os::unix::ffi::OsStrExt;

        let raw = b"/tmp/\xff\xfeinvalid";
        let child = std::path::Path::new(OsStr::from_bytes(raw));
        let rewritten = rewrite_workdir_env_var("PWD", Some(OsStr::new("/tmp/bar")), Some(child));
        assert_eq!(rewritten.map(OsStr::as_bytes), Some(&raw[..]));
    }

    #[test]
    fn test_pwd_dropped_by_policy_is_ineligible_for_rewrite() {
        // A profile that strips `PWD` must not receive the same value as
        // `$OLDPWD`, so filtering decides eligibility for both.
        let denied = vec!["PWD".to_string()];
        assert!(!env_var_survives_filters(
            "PWD",
            &[],
            &[],
            Some(&denied),
            None,
            false
        ));

        let allowed_without_pwd = vec!["PATH".to_string(), "HOME".to_string()];
        assert!(!env_var_survives_filters(
            "PWD",
            &[],
            &[],
            None,
            Some(&allowed_without_pwd),
            false
        ));

        let allowed_with_pwd = vec!["PWD".to_string()];
        assert!(env_var_survives_filters(
            "PWD",
            &[],
            &[],
            None,
            Some(&allowed_with_pwd),
            false
        ));
        assert!(env_var_survives_filters("PWD", &[], &[], None, None, false));
    }

    #[test]
    fn test_pwd_rewrite_stands_down_when_pwd_is_injected_or_filtered() {
        assert!(pwd_rewrite_permitted(&[], &[], &[], None, None, false));

        // `set_vars` lands after the inherited-env loop, so its `PWD` wins; the
        // rewrite must not leave `$OLDPWD` describing a move `$PWD` denies.
        let set_pwd = vec![("PWD".to_string(), "/injected".to_string())];
        assert!(!pwd_rewrite_permitted(
            &[],
            &set_pwd,
            &[],
            None,
            None,
            false
        ));

        // An unrelated `set_vars` entry leaves the rewrite alone.
        let set_other = vec![("EDITOR".to_string(), "vi".to_string())];
        assert!(pwd_rewrite_permitted(
            &[],
            &set_other,
            &[],
            None,
            None,
            false
        ));

        // A `set_vars` `OLDPWD` overrides only that key; `PWD` still tracks the
        // directory the child starts in.
        let set_oldpwd = vec![("OLDPWD".to_string(), "/elsewhere".to_string())];
        assert!(pwd_rewrite_permitted(
            &[],
            &set_oldpwd,
            &[],
            None,
            None,
            false
        ));

        // Credentials and env filters gate the rewrite the same way.
        assert!(!pwd_rewrite_permitted(
            &[("PWD", "/injected")],
            &[],
            &[],
            None,
            None,
            false
        ));
        let denied = vec!["PWD".to_string()];
        assert!(!pwd_rewrite_permitted(
            &[],
            &[],
            &[],
            Some(&denied),
            None,
            false
        ));
    }

    #[test]
    fn test_trusted_host_pwd_accepts_a_spelling_of_the_launch_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::create_dir(&real).expect("create real dir");
        std::os::unix::fs::symlink(&real, &link).expect("create symlink");
        // `getcwd` reports the resolved path even when the shell's `$PWD` names
        // the symlink, so the guard must accept the symlink spelling.
        let launch_cwd = real.canonicalize().expect("canonicalize real dir");

        assert_eq!(
            trusted_host_pwd(Some(link.clone().into_os_string()), Some(&launch_cwd)),
            Some(link.into_os_string()),
            "a symlink spelling of the launch dir is the shell's logical `$PWD`"
        );
        assert_eq!(
            trusted_host_pwd(Some(launch_cwd.clone().into_os_string()), Some(&launch_cwd)),
            Some(launch_cwd.clone().into_os_string())
        );
    }

    #[test]
    fn test_trusted_host_pwd_rejects_untrustworthy_values() {
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let launch_cwd = dir.path().canonicalize().expect("canonicalize tempdir");
        let elsewhere = launch_cwd.join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("create sibling dir");

        // Unset: the child is never told a working directory, so there is
        // nothing to rewrite and nothing to introduce.
        assert_eq!(trusted_host_pwd(None, Some(&launch_cwd)), None);

        // Non-UTF-8: dropped from the child environment, so it must not become
        // the child's `$OLDPWD` either.
        let non_utf8 = std::ffi::OsString::from_vec(b"/tmp/\xff\xfeinvalid".to_vec());
        assert_eq!(trusted_host_pwd(Some(non_utf8), Some(&launch_cwd)), None);

        // Stale or spoofed: resolves somewhere other than `getcwd`.
        assert_eq!(
            trusted_host_pwd(Some(elsewhere.into_os_string()), Some(&launch_cwd)),
            None,
            "a `$PWD` that does not canonicalise to `getcwd` is not the launch dir"
        );

        // Nonexistent, so it cannot be shown to name the launch dir.
        let missing = launch_cwd.join("gone");
        assert_eq!(
            trusted_host_pwd(Some(missing.into_os_string()), Some(&launch_cwd)),
            None
        );

        // Relative values cannot be compared against `getcwd` verbatim.
        assert_eq!(
            trusted_host_pwd(Some(std::ffi::OsString::from(".")), Some(&launch_cwd)),
            None
        );

        // No `getcwd` means nothing to validate against, so the rewrite stands
        // down rather than trusting the inherited value.
        assert_eq!(
            trusted_host_pwd(Some(launch_cwd.clone().into_os_string()), None),
            None
        );
    }

    #[test]
    fn test_env_var_survives_filters_honors_overrides_and_blocklist() {
        assert!(!env_var_survives_filters(
            "PWD",
            &[("PWD", "/injected")],
            &[],
            None,
            None,
            false
        ));
        assert!(!env_var_survives_filters(
            "NONO_CAP_FILE",
            &[],
            &["NONO_CAP_FILE"],
            None,
            None,
            false
        ));
        assert!(!env_var_survives_filters(
            "LD_PRELOAD",
            &[],
            &[],
            None,
            None,
            false
        ));
        // Deny wins over an explicit allow entry for the same key.
        let denied = vec!["GITHUB_*".to_string()];
        let allowed = vec!["GITHUB_TOKEN".to_string()];
        assert!(!env_var_survives_filters(
            "GITHUB_TOKEN",
            &[],
            &[],
            Some(&denied),
            Some(&allowed),
            false
        ));

        // Case-insensitive mode matches regardless of casing on either side.
        let denied_ci = vec!["*secret*".to_string()];
        assert!(!env_var_survives_filters(
            "MY_SECRET",
            &[],
            &[],
            Some(&denied_ci),
            None,
            true
        ));
    }

    #[test]
    fn test_profile_authoring_guide_environment_example_matches_as_documented() {
        // The exact allow_vars/deny_vars/case_insensitive_vars example from
        // the "environment" section of profile-authoring-guide.md.
        let allowed = vec!["*".to_string()];
        let denied = vec![
            "*TOKEN*".to_string(),
            "*KEY*".to_string(),
            "*SECRET*".to_string(),
        ];
        let survives = |key: &str| {
            env_var_survives_filters(key, &[], &[], Some(&denied), Some(&allowed), true)
        };

        // Secret-shaped names are stripped, case-insensitively.
        assert!(!survives("GH_TOKEN"));
        assert!(!survives("gh_token"));
        assert!(!survives("AWS_SECRET_ACCESS_KEY"));
        // Everything else still passes through the "*" allow.
        assert!(survives("PATH"));
        assert!(survives("HOME"));
    }
}
