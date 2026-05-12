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

fn env_key_matches(left: &str, right: &str) -> bool {
    if cfg!(target_os = "windows") {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

/// Decide whether an inherited env var should be dropped for sandbox execution.
pub(super) fn should_skip_env_var(
    key: &str,
    config_env_vars: &[(&str, &str)],
    blocked_extra: &[&str],
) -> bool {
    config_env_vars
        .iter()
        .any(|(ek, _)| env_key_matches(ek, key))
        || blocked_extra
            .iter()
            .any(|blocked| env_key_matches(blocked, key))
        || is_dangerous_env_var(key)
}

/// Returns true if an environment variable matches the allow-list.
///
/// Supports exact names (`"PATH"`) and prefix patterns ending with `*`
/// (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.).
/// A bare `"*"` matches everything. The `*` wildcard is only valid as a
/// trailing suffix — patterns like `"A*B"` or `"*X"` are rejected.
///
/// Ported from upstream v0.37.0 `1b412a7` per Plan 34-08a Task 3 (D-20
/// manual replay). Phase 20-03 commit `b4762e63` ported only the CLI
/// flag-parsing slice; this is part of the deferred surface.
#[allow(dead_code)] // Windows execution path uses exec_strategy_windows; allow-list wiring there ships separately.
pub(crate) fn is_env_var_allowed(key: &str, allowed_env_vars: &[String]) -> bool {
    for pattern in allowed_env_vars {
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

/// Validates that all env var patterns use `*` only as a trailing suffix.
/// `field_name` is used in the error message (e.g. `"allow_vars"` or `"deny_vars"`).
/// Returns an error message describing the first invalid pattern, or None if valid.
///
/// Ported from upstream v0.37.0 `1b412a7` per Plan 34-08a Task 3 (D-20
/// manual replay); renamed from `validate_allow_vars_pattern` to
/// `validate_env_var_patterns` with a `field_name` parameter per upstream
/// v0.52.0 `3657c935` (Plan 34-08a Task 4).
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

/// Returns true if an environment variable matches the deny-list.
///
/// Uses the same pattern syntax as `is_env_var_allowed`: exact names and
/// trailing-`*` prefix patterns.
///
/// Ported from upstream v0.52.0 `3657c935` per Plan 34-08a Task 4
/// (D-20 manual-replay-by-escalation).
#[allow(dead_code)] // Windows execution path uses exec_strategy_windows; deny-list wiring there ships separately.
pub(crate) fn is_env_var_denied(key: &str, denied_env_vars: &[String]) -> bool {
    is_env_var_allowed(key, denied_env_vars)
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

    #[cfg(target_os = "windows")]
    #[test]
    fn test_should_skip_env_var_matches_windows_keys_case_insensitively() {
        assert!(should_skip_env_var(
            "ProgramData",
            &[("PROGRAMDATA", r"C:\sandbox\programdata")],
            &[]
        ));
        assert!(should_skip_env_var("Path", &[], &["PATH"]));
    }

    // ============================================================================
    // Environment variable allow-list — is_env_var_allowed (ported v0.37.0 1b412a7)
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
    // Pattern validation — validate_env_var_patterns (ported v0.37.0 1b412a7,
    // renamed from validate_allow_vars_pattern in v0.52.0 3657c935)
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
        assert!(err.is_some());
        let msg = err.expect("validation error");
        assert!(msg.contains("deny_vars"));
        assert!(msg.contains("A*B"));
    }

    // ============================================================================
    // is_env_var_denied (ported v0.52.0 3657c935)
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
}
