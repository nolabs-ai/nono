//! Environment sanitization boundary for sandboxed execution.
//!
//! Threat model:
//! - Untrusted parent/shell environments may inject execution behavior via
//!   linker, shell, or interpreter environment variables.
//! - All sandbox execution strategies must share one allow/deny implementation
//!   to avoid drift in security behavior across code paths.

/// Returns true if an environment variable is unsafe to inherit into a sandboxed child.
///
/// Covers linker injection (LD_PRELOAD, DYLD_INSERT_LIBRARIES), shell startup
/// injection (BASH_ENV, PROMPT_COMMAND, IFS), and interpreter code/module injection
/// (NODE_OPTIONS, PYTHONPATH, PERL5OPT, RUBYOPT, JAVA_TOOL_OPTIONS, etc.).
pub(crate) fn is_dangerous_env_var(key: &str) -> bool {
    // Linker injection
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
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
        // 1Password secrets and session tokens — meta-secrets used by
        // the parent to authenticate `op` CLI, must never leak to sandboxed child
        || key == "OP_SERVICE_ACCOUNT_TOKEN"
        || key == "OP_CONNECT_TOKEN"
        || key == "OP_CONNECT_HOST"
        || key.starts_with("OP_SESSION_")
}

/// Returns true if `key` matches any pattern in `patterns`.
///
/// Supports exact names (`"PATH"`) and prefix patterns ending with `*`
/// (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.).
/// A bare `"*"` matches everything. The `*` wildcard is only valid as a
/// trailing suffix — patterns like `"A*B"` or `"*X"` are skipped.
pub(crate) fn matches_env_var_patterns(key: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if let Some(prefix) = pattern.strip_suffix('*') {
            if prefix.contains('*') {
                continue;
            }
            if key.starts_with(prefix) {
                return true;
            }
        } else if !pattern.contains('*') && key == *pattern {
            return true;
        }
    }
    false
}

/// Returns true if an environment variable matches the allow-list.
///
/// Supports exact names (`"PATH"`) and prefix patterns ending with `*`
/// (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.).
/// A bare `"*"` matches everything.
pub(crate) fn is_env_var_allowed(key: &str, allowed_env_vars: &[String]) -> bool {
    matches_env_var_patterns(key, allowed_env_vars)
}

/// Returns true if an environment variable matches the deny-list.
///
/// Uses the same pattern syntax as `is_env_var_allowed`: exact names and
/// trailing-`*` prefix patterns.
pub(crate) fn is_env_var_denied(key: &str, denied_env_vars: &[String]) -> bool {
    matches_env_var_patterns(key, denied_env_vars)
}

/// Validates that all env var patterns use `*` only as a trailing suffix.
/// `field_name` is used in the error message (e.g. `"allow_vars"` or `"deny_vars"`).
/// Returns an error message describing the first invalid pattern, or None if valid.
pub(crate) fn validate_env_var_patterns(patterns: &[String], field_name: &str) -> Option<String> {
    for pattern in patterns {
        if pattern.contains('*') && !pattern.ends_with('*') {
            return Some(format!(
                "Invalid {} pattern '{}': '*' is only valid as a trailing suffix",
                field_name, pattern
            ));
        }
        if pattern.starts_with('*') && pattern.len() > 1 {
            return Some(format!(
                "Invalid {} pattern '{}': use a bare '*' to match all variables, or a specific prefix like 'AWS_*'",
                field_name, pattern
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

/// Decide whether an inherited env var should be dropped for sandbox execution.
pub(super) fn should_skip_env_var(
    key: &str,
    config_env_vars: &[(&str, &str)],
    blocked_extra: &[&str],
) -> bool {
    config_env_vars.iter().any(|(ek, _)| *ek == key)
        || blocked_extra.contains(&key)
        || is_dangerous_env_var(key)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_env_var_allowed_mid_star_ignored() {
        let allowed: Vec<String> = vec!["A*B".into()];
        assert!(!is_env_var_allowed("AXB", &allowed));
        assert!(!is_env_var_allowed("A*B", &allowed));
    }

    // ============================================================================
    // Pattern validation — validate_env_var_patterns
    // ============================================================================

    #[test]
    fn test_validate_valid_patterns() {
        let patterns: Vec<String> = vec!["PATH".into(), "AWS_*".into(), "*".into()];
        assert!(validate_env_var_patterns(&patterns, "allow_vars").is_none());
    }

    #[test]
    fn test_validate_rejects_mid_star() {
        let patterns: Vec<String> = vec!["A*B".into()];
        let err = validate_env_var_patterns(&patterns, "allow_vars");
        assert!(err.is_some());
        assert!(err.as_ref().is_some_and(|e| e.contains("A*B")));
    }

    #[test]
    fn test_validate_rejects_leading_star_with_suffix() {
        let patterns: Vec<String> = vec!["*X".into()];
        let err = validate_env_var_patterns(&patterns, "allow_vars");
        assert!(err.is_some());
        assert!(err.as_ref().is_some_and(|e| e.contains("*X")));
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

    #[test]
    fn test_validate_deny_vars_field_name_in_error() {
        let patterns: Vec<String> = vec!["A*B".into()];
        let err = validate_env_var_patterns(&patterns, "deny_vars");
        assert!(err.as_ref().is_some_and(|e| e.contains("deny_vars")));
        assert!(err.as_ref().is_some_and(|e| e.contains("A*B")));
    }

    // ============================================================================
    // is_env_var_denied
    // ============================================================================

    #[test]
    fn test_env_var_denied_exact_match() {
        let denied: Vec<String> = vec!["GH_TOKEN".into(), "ANTHROPIC_API_KEY".into()];
        assert!(is_env_var_denied("GH_TOKEN", &denied));
        assert!(is_env_var_denied("ANTHROPIC_API_KEY", &denied));
    }

    #[test]
    fn test_env_var_denied_prefix_match() {
        let denied: Vec<String> = vec!["GITHUB_*".into()];
        assert!(is_env_var_denied("GITHUB_TOKEN", &denied));
        assert!(is_env_var_denied("GITHUB_ACTIONS", &denied));
        assert!(!is_env_var_denied("GH_TOKEN", &denied));
    }

    #[test]
    fn test_env_var_denied_no_match() {
        let denied: Vec<String> = vec!["GH_TOKEN".into()];
        assert!(!is_env_var_denied("PATH", &denied));
        assert!(!is_env_var_denied("HOME", &denied));
    }

    #[test]
    fn test_env_var_denied_empty_list() {
        let denied: Vec<String> = vec![];
        assert!(!is_env_var_denied("GH_TOKEN", &denied));
    }

    #[test]
    fn test_env_var_denied_overrides_allowed() {
        // Simulates: deny_vars has GH_TOKEN, allow_vars has GH_TOKEN
        // deny wins: denied should return true regardless of allowed
        let denied: Vec<String> = vec!["GH_TOKEN".into()];
        let allowed: Vec<String> = vec!["GH_TOKEN".into()];
        assert!(is_env_var_denied("GH_TOKEN", &denied));
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
}
