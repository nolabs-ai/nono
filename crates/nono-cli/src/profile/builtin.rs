//! Built-in profiles compiled into the nono binary
//!
//! Profiles are defined declaratively in `policy.json` under the `profiles` key.
//! This module delegates to the policy resolver for loading and listing.

use super::Profile;

/// Get a built-in profile by name
pub fn get_builtin(name: &str) -> Option<Profile> {
    crate::policy::get_policy_profile(name).ok().flatten()
}

/// List all built-in profile names
pub fn list_builtin() -> Vec<String> {
    crate::policy::list_policy_profiles().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::WorkdirAccess;

    #[test]
    fn test_get_builtin_claude_code() {
        let profile = get_builtin("claude-code").expect("Profile not found");
        assert_eq!(profile.meta.name, "claude-code");
        assert!(!profile.network.block); // network allowed
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(!profile.security.groups.is_empty());
        assert!(profile
            .security
            .groups
            .contains(&"deny_credentials".to_string()));
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.cache/claude".to_string()));
        assert!(profile
            .filesystem
            .allow_file
            .contains(&"$HOME/.claude.lock".to_string()));
    }

    #[test]
    fn test_get_builtin_claude_no_kc() {
        let profile = get_builtin("claude-no-kc").expect("Profile not found");
        assert_eq!(profile.meta.name, "claude-no-kc");
        assert!(!profile.network.block);
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(profile
            .security
            .groups
            .contains(&"claude_code_linux".to_string()));
        assert!(!profile
            .security
            .groups
            .contains(&"claude_code_macos".to_string()));
        assert!(profile.policy.add_allow_readwrite.is_empty());
        assert!(profile.policy.override_deny.is_empty());
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.cache/claude".to_string()));
        assert!(profile
            .filesystem
            .allow_file
            .contains(&"$HOME/.claude.lock".to_string()));
    }

    #[test]
    fn test_get_builtin_default() {
        let profile = get_builtin("default").expect("Profile not found");
        assert_eq!(profile.meta.name, "default");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
        assert!(!profile.interactive);
        assert!(!profile.network.block);
    }

    #[test]
    fn test_get_builtin_claude_code_uses_platform_groups_for_os_paths() {
        let profile = get_builtin("claude-code").expect("Profile not found");
        assert!(profile
            .security
            .groups
            .contains(&"claude_code_macos".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"claude_code_linux".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"vscode_macos".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"vscode_linux".to_string()));
        assert!(!profile
            .filesystem
            .read
            .contains(&"$HOME/.local/share/claude".to_string()));
        assert!(!profile
            .filesystem
            .allow_file
            .contains(&"$HOME/Library/Keychains/login.keychain-db".to_string()));
        assert!(!profile
            .filesystem
            .allow_file
            .contains(&"$HOME/Library/Keychains/metadata.keychain-db".to_string()));
        assert_eq!(
            profile.policy.add_allow_readwrite,
            vec!["$HOME/Library/Keychains".to_string()]
        );
        assert_eq!(
            profile.policy.override_deny,
            vec!["$HOME/Library/Keychains".to_string()]
        );
        assert!(profile
            .filesystem
            .allow_file
            .contains(&"$HOME/.claude.lock".to_string()));
    }

    #[test]
    fn test_get_builtin_claude_no_kc_does_not_relax_keychain_denies() {
        let profile = get_builtin("claude-no-kc").expect("Profile not found");
        assert!(!profile
            .security
            .groups
            .contains(&"claude_code_macos".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"claude_code_linux".to_string()));
        assert!(!profile
            .filesystem
            .read
            .contains(&"$HOME/.local/share/claude".to_string()));
        assert!(!profile
            .filesystem
            .allow_file
            .contains(&"$HOME/Library/Keychains/login.keychain-db".to_string()));
        assert!(!profile
            .filesystem
            .allow_file
            .contains(&"$HOME/Library/Keychains/metadata.keychain-db".to_string()));
        assert!(profile.policy.add_allow_readwrite.is_empty());
        assert!(profile.policy.override_deny.is_empty());
    }

    #[test]
    fn test_get_builtin_openclaw() {
        let profile = get_builtin("openclaw").expect("Profile not found");
        assert_eq!(profile.meta.name, "openclaw");
        assert!(!profile.network.block); // network allowed
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.openclaw".to_string()));
    }

    #[test]
    fn test_get_builtin_codex() {
        let profile = get_builtin("codex").expect("Profile not found");
        assert_eq!(profile.meta.name, "codex");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(profile.interactive);
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.codex".to_string()));
        assert!(profile.security.groups.contains(&"codex_macos".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"node_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"rust_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"python_runtime".to_string()));
        assert!(profile.security.groups.contains(&"nix_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"unlink_protection".to_string()));
    }

    #[test]
    fn test_get_builtin_opencode() {
        let profile = get_builtin("opencode").expect("Profile not found");
        assert_eq!(profile.meta.name, "opencode");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(profile.interactive);
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.opencode".to_string()));
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.local/share/opentui".to_string()));
    }

    #[test]
    fn test_get_builtin_swival() {
        let profile = get_builtin("swival").expect("Profile not found");
        assert_eq!(profile.meta.name, "swival");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(profile.interactive);
        assert!(!profile.network.block);
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.config/swival".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"python_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"unlink_protection".to_string()));
    }

    #[test]
    fn test_get_builtin_nonexistent() {
        assert!(get_builtin("nonexistent").is_none());
    }

    /// PROF-04 (Phase 22) VALIDATION 22-01-T4: claude-no-kc builtin loads
    /// via the get_builtin path and resolves cleanly under the fork's
    /// existing POLY-01 stricter posture (CONTRADICTION-A reconciliation).
    #[test]
    fn claude_no_keychain_loads() {
        // Upstream calls the profile `claude-no-kc`; the plan calls it
        // `claude-no-keychain` conceptually. We follow upstream's naming.
        let profile =
            get_builtin("claude-no-kc").expect("claude-no-kc must be a registered builtin");
        assert_eq!(profile.meta.name, "claude-no-kc");

        // The no-keychain variant inherits the claude-code agent groups
        // EXCEPT claude_code_macos (which carries the keychain access).
        assert!(
            !profile
                .security
                .groups
                .contains(&"claude_code_macos".to_string()),
            "claude-no-kc must not include claude_code_macos (keychain group)"
        );
        // Network unblocked + readwrite workdir match claude-code semantics.
        assert!(!profile.network.block);
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);

        // No keychain override_deny (the whole point of the variant).
        assert!(profile.policy.override_deny.is_empty());
    }

    #[test]
    fn test_list_builtin() {
        let profiles = list_builtin();
        assert!(profiles.contains(&"default".to_string()));
        assert!(profiles.contains(&"linux-host-compat".to_string()));
        assert!(profiles.contains(&"claude-code".to_string()));
        assert!(profiles.contains(&"claude-no-kc".to_string()));
        assert!(profiles.contains(&"codex".to_string()));
        assert!(profiles.contains(&"openclaw".to_string()));
        assert!(profiles.contains(&"opencode".to_string()));
        assert!(profiles.contains(&"swival".to_string()));
    }

    #[test]
    fn test_profile_group_merging() {
        let profile = get_builtin("claude-code").expect("Profile not found");
        // Should have default profile groups
        assert!(profile
            .security
            .groups
            .contains(&"deny_credentials".to_string()));
        // Should have profile-specific groups
        assert!(profile
            .security
            .groups
            .contains(&"node_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"rust_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"unlink_protection".to_string()));
    }

    #[test]
    fn test_profile_exclusion_mechanism() {
        // Verify that built-in profiles resolve exclusions through the shared
        // group-exclusion path. Current embedded profiles do not exclude any.
        let profile = get_builtin("openclaw").expect("Profile not found");
        let default = get_builtin("default").expect("default profile");
        // All default groups should be present since embedded exclusions are empty.
        for group in &default.security.groups {
            assert!(
                profile.security.groups.contains(group),
                "openclaw should contain default profile group '{}'",
                group
            );
        }
    }

    #[test]
    fn test_default_profile_group_set_is_explicit() {
        let profile = get_builtin("default").expect("default profile");
        let mut expected = vec![
            "dangerous_commands".to_string(),
            "dangerous_commands_linux".to_string(),
            "dangerous_commands_macos".to_string(),
            "deny_browser_data_linux".to_string(),
            "deny_browser_data_macos".to_string(),
            "deny_credentials".to_string(),
            "deny_keychains_linux".to_string(),
            "deny_keychains_macos".to_string(),
            "deny_macos_private".to_string(),
            "deny_shell_configs".to_string(),
            "deny_shell_history".to_string(),
            "homebrew_linux".to_string(),
            "homebrew_macos".to_string(),
            "system_read_linux_core".to_string(),
            "system_read_macos".to_string(),
            "system_read_windows".to_string(),
            "system_write_linux".to_string(),
            "system_write_macos".to_string(),
            "user_tools".to_string(),
        ];
        let mut actual = profile.security.groups.clone();
        expected.sort();
        actual.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_embedded_profiles_extend_default() {
        let policy = crate::policy::load_embedded_policy().expect("load embedded policy");
        for (name, def) in &policy.profiles {
            if name == "default" {
                continue;
            }
            assert_eq!(
                def.extends.as_deref(),
                Some("default"),
                "embedded profile '{}' should extend default",
                name
            );
        }
    }

    #[test]
    fn test_linux_host_compat_profile_groups() {
        let profile = get_builtin("linux-host-compat").expect("Profile not found");
        assert!(profile
            .security
            .groups
            .contains(&"linux_runtime_state".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"linux_sysfs_read".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"linux_temp_read".to_string()));
    }

    #[test]
    fn test_linux_interactive_profiles_include_sysfs_but_not_runtime_state_or_temp() {
        for name in ["claude-code", "codex", "opencode", "swival"] {
            let profile = get_builtin(name).expect("Profile not found");
            assert!(
                !profile
                    .security
                    .groups
                    .contains(&"linux_runtime_state".to_string()),
                "{} should not include linux_runtime_state",
                name
            );
            assert!(
                profile
                    .security
                    .groups
                    .contains(&"linux_sysfs_read".to_string()),
                "{} should include linux_sysfs_read",
                name
            );
            assert!(
                !profile
                    .security
                    .groups
                    .contains(&"linux_temp_read".to_string()),
                "{} should not include linux_temp_read",
                name
            );
        }
    }

    #[test]
    fn test_opencode_profile_includes_tmpdir_and_state_dir() {
        let policy = crate::policy::load_embedded_policy().expect("load embedded policy");
        let opencode = policy.profiles.get("opencode").expect("opencode profile");
        assert!(
            opencode.filesystem.allow.contains(&"$TMPDIR".to_string()),
            "opencode profile should allow $TMPDIR for Bun TUI runtime extraction"
        );
        assert!(
            opencode
                .filesystem
                .allow
                .contains(&"$HOME/.local/state/opencode".to_string()),
            "opencode profile should allow $HOME/.local/state/opencode"
        );
    }

    // ------------------------------------------------------------------
    // Profile `extends` cycle-detection guard (upstream c1bc439 parity).
    //
    // Upstream c1bc439 (D-06, fix(profiles): prevent infinite recursion in
    // profile extends check) hardens the extends chain traversal against
    // cyclic definitions. The fork already carries the fix in
    // `resolve_extends` (visited-Vec + MAX_INHERITANCE_DEPTH bound — see
    // `profile/mod.rs`). These three tests are the plan-mandated regression
    // safety net for 20-02: they exercise the guard end-to-end through the
    // public `load_profile` API so a future refactor that accidentally
    // strips the guard would fail-closed here instead of stack-overflowing
    // at runtime.
    //
    // Pattern: each test writes user profile files to a tempdir, points
    // the user-config-dir env var at it (APPDATA on Windows, XDG_CONFIG_HOME
    // on Unix), and invokes the public loader. The env-var lock is
    // required because Rust unit tests run in parallel within one process
    // (see CLAUDE.md § Coding Standards > "Environment variables in tests").
    // ------------------------------------------------------------------

    /// Helper: seed a profile JSON file under `<config_dir>/nono/profiles/`.
    fn seed_user_profile(
        profiles_dir: &std::path::Path,
        name: &str,
        extends: Option<&[&str]>,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(profiles_dir)?;
        let extends_json = match extends {
            Some(bases) if bases.len() == 1 => {
                format!(r#""extends": "{}","#, bases[0])
            }
            Some(bases) => {
                let arr = bases
                    .iter()
                    .map(|b| format!("\"{}\"", b))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(r#""extends": [{}],"#, arr)
            }
            None => String::new(),
        };
        let body = format!(
            r#"{{ {extends} "meta": {{ "name": "{name}" }} }}"#,
            extends = extends_json,
            name = name,
        );
        std::fs::write(profiles_dir.join(format!("{}.json", name)), body)?;
        Ok(())
    }

    /// Helper: set the user-config-dir env var to `config_dir` for the
    /// duration of the guard. On Windows this is APPDATA; on Unix it is
    /// XDG_CONFIG_HOME (plus HOME for fallback paths). Returns the
    /// EnvVarGuard so the caller binds its drop scope to the test body.
    fn user_config_dir_guard(config_dir: &std::path::Path) -> crate::test_env::EnvVarGuard {
        let config_str = config_dir
            .to_str()
            .expect("tempdir path must be utf-8 for env var");
        #[cfg(target_os = "windows")]
        {
            crate::test_env::EnvVarGuard::set_all(&[
                ("APPDATA", config_str),
                ("USERPROFILE", config_str),
                ("HOME", config_str),
            ])
        }
        #[cfg(not(target_os = "windows"))]
        {
            crate::test_env::EnvVarGuard::set_all(&[
                ("XDG_CONFIG_HOME", config_str),
                ("HOME", config_str),
            ])
        }
    }

    #[test]
    fn test_profile_extends_self_reference_detected() {
        use tempfile::tempdir;

        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let config_root = tempdir().expect("config tempdir");
        let _env = user_config_dir_guard(config_root.path());

        // Canonicalize so the value matches XDG_CONFIG_HOME's canonicalized
        // resolution (symlink-stripped on macOS tempdirs).
        let canonical_root = config_root
            .path()
            .canonicalize()
            .expect("canonicalize tempdir");
        let profiles_dir = canonical_root.join("nono").join("profiles");

        // Profile "self-ref-a" extends itself → cycle must be caught.
        seed_user_profile(&profiles_dir, "self-ref-a", Some(&["self-ref-a"]))
            .expect("seed self-ref");

        let result = crate::profile::load_profile("self-ref-a");
        let err = result.expect_err("self-reference cycle must fail-closed, not stack-overflow");
        assert!(
            matches!(err, nono::NonoError::ProfileInheritance(_)),
            "self-reference must surface ProfileInheritance error; got {:?}",
            err
        );
        let msg = err.to_string();
        assert!(
            msg.contains("circular") || msg.contains("cycle"),
            "error must mention cycle/circular: {}",
            msg
        );
    }

    #[test]
    fn test_profile_extends_indirect_cycle_detected() {
        use tempfile::tempdir;

        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let config_root = tempdir().expect("config tempdir");
        let _env = user_config_dir_guard(config_root.path());

        let canonical_root = config_root
            .path()
            .canonicalize()
            .expect("canonicalize tempdir");
        let profiles_dir = canonical_root.join("nono").join("profiles");

        // A extends B; B extends A. Two-hop indirect cycle — guards against
        // any cycle-detection variant that only catches direct self-refs.
        seed_user_profile(&profiles_dir, "indirect-a", Some(&["indirect-b"]))
            .expect("seed indirect-a");
        seed_user_profile(&profiles_dir, "indirect-b", Some(&["indirect-a"]))
            .expect("seed indirect-b");

        let result = crate::profile::load_profile("indirect-a");
        let err = result.expect_err("indirect cycle must fail-closed, not stack-overflow");
        assert!(
            matches!(err, nono::NonoError::ProfileInheritance(_)),
            "indirect cycle must surface ProfileInheritance error; got {:?}",
            err
        );
        let msg = err.to_string();
        assert!(
            msg.contains("circular") || msg.contains("cycle"),
            "error must mention cycle/circular: {}",
            msg
        );
    }

    #[test]
    fn test_profile_extends_linear_chain_succeeds() {
        use tempfile::tempdir;

        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let config_root = tempdir().expect("config tempdir");
        let _env = user_config_dir_guard(config_root.path());

        let canonical_root = config_root
            .path()
            .canonicalize()
            .expect("canonicalize tempdir");
        let profiles_dir = canonical_root.join("nono").join("profiles");

        // Linear chain: chain-a extends chain-b extends chain-c (no cycle).
        // Regression guard: over-aggressive cycle detection must not reject
        // legitimate multi-hop chains.
        seed_user_profile(&profiles_dir, "chain-c", None).expect("seed chain-c");
        seed_user_profile(&profiles_dir, "chain-b", Some(&["chain-c"])).expect("seed chain-b");
        seed_user_profile(&profiles_dir, "chain-a", Some(&["chain-b"])).expect("seed chain-a");

        let profile = crate::profile::load_profile("chain-a")
            .expect("linear chain must resolve without false-positive cycle rejection");
        assert_eq!(profile.meta.name, "chain-a");
        // The `extends` field must be consumed by the merge pipeline.
        assert!(
            profile.extends.is_none(),
            "resolved profile's extends field should be consumed (None), was {:?}",
            profile.extends
        );
    }

    /// Regression test: verifies that all built-in profiles — regardless of
    /// their signal_mode setting — will produce Seatbelt rules that allow
    /// signaling child processes within the same sandbox.
    ///
    /// Background: the Seatbelt generator previously emitted only
    /// `(allow signal (target self))` for `signal_mode: isolated`, which
    /// blocked `kill(child_pid, sig)` on children that inherited the sandbox.
    /// This caused orphan process accumulation and progressive keyboard lag.
    ///
    /// The fix is in the Seatbelt generation layer (macos.rs): both `Isolated`
    /// and `AllowSameSandbox` now emit `(target same-sandbox)`, matching Linux
    /// where Landlock's `LANDLOCK_SCOPE_SIGNAL` cannot distinguish the two.
    #[test]
    fn test_all_profiles_signal_mode_resolves() {
        use crate::capability_ext::CapabilitySetExt;
        #[cfg(target_os = "windows")]
        use tempfile::tempdir;
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Env-var guards must hold paths that pass `Path::is_absolute()` on
        // the host platform. `/home/nono-test/...` is absolute on Unix but
        // NOT on Windows (no drive letter), which causes `expand_vars` to
        // reject the XDG_* paths and the whole test to fail with
        // EnvVarValidation. Use platform-absolute tempdir-backed paths on
        // Windows and keep the existing Unix-shaped guard on Unix.
        //
        // PROF-04 (Phase 22) per upstream 3c8b6756: pre-create
        // `$HOME/Library/Keychains` on Unix so the broadened claude-code
        // keychain grant resolves without being skipped (the directory must
        // exist for the capability allowlist to include it).
        #[cfg(not(target_os = "windows"))]
        let home = tempfile::Builder::new()
            .prefix("nono-builtin-profile-home-")
            .tempdir_in(std::env::current_dir().expect("cwd"))
            .expect("home tempdir");
        #[cfg(not(target_os = "windows"))]
        std::fs::create_dir_all(home.path().join("Library/Keychains")).expect("mkdir keychains");

        #[cfg(not(target_os = "windows"))]
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", home.path().to_str().expect("home utf8")),
            (
                "XDG_CONFIG_HOME",
                home.path().join(".config").to_str().expect("config utf8"),
            ),
            (
                "XDG_DATA_HOME",
                home.path()
                    .join(".local/share")
                    .to_str()
                    .expect("data utf8"),
            ),
            (
                "XDG_STATE_HOME",
                home.path()
                    .join(".local/state")
                    .to_str()
                    .expect("state utf8"),
            ),
            (
                "XDG_CACHE_HOME",
                home.path().join(".cache").to_str().expect("cache utf8"),
            ),
        ]);

        #[cfg(target_os = "windows")]
        let home_tmp = tempdir().expect("home tmpdir");
        // PROF-04 (Phase 22): pre-create the Library/Keychains subdirectory
        // on Windows too. The claude-code profile's `add_allow_readwrite`
        // entry for `$HOME/Library/Keychains` is gated on
        // `try_new_dir` (path-exists), so without this mkdir the matching
        // grant for the `override_deny` of the same path is silently
        // skipped on Windows and resolution fails with "no matching grant".
        // The path is platform-irrelevant (it's a tempdir under HOME); only
        // the existence matters.
        #[cfg(target_os = "windows")]
        std::fs::create_dir_all(home_tmp.path().join("Library/Keychains"))
            .expect("mkdir keychains on windows");
        #[cfg(target_os = "windows")]
        let home_str = home_tmp
            .path()
            .to_str()
            .expect("home tmpdir path is utf-8")
            .to_string();
        #[cfg(target_os = "windows")]
        let xdg_config = format!("{home_str}\\.config");
        #[cfg(target_os = "windows")]
        let xdg_data = format!("{home_str}\\.local\\share");
        #[cfg(target_os = "windows")]
        let xdg_state = format!("{home_str}\\.local\\state");
        #[cfg(target_os = "windows")]
        let xdg_cache = format!("{home_str}\\.cache");
        #[cfg(target_os = "windows")]
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", home_str.as_str()),
            // USERPROFILE wins over HOME in validated_home() on Windows, so
            // pin it to the same tempdir to keep the resolution consistent.
            ("USERPROFILE", home_str.as_str()),
            ("XDG_CONFIG_HOME", xdg_config.as_str()),
            ("XDG_DATA_HOME", xdg_data.as_str()),
            ("XDG_STATE_HOME", xdg_state.as_str()),
            ("XDG_CACHE_HOME", xdg_cache.as_str()),
        ]);

        let workdir = tempdir().expect("tmpdir");
        let args = crate::cli::SandboxArgs::default();

        let profiles = list_builtin();
        for name in &profiles {
            let profile = get_builtin(name)
                .unwrap_or_else(|| panic!("built-in profile '{}' should load", name));

            let prepared = nono::CapabilitySet::from_profile(&profile, workdir.path(), &args)
                .unwrap_or_else(|e| panic!("profile '{}' should build caps: {}", name, e));
            let caps = prepared.caps;

            // Whether the profile uses Isolated or AllowSameSandbox, the
            // Seatbelt generator must emit same-sandbox signal rules.
            // This is verified by the library tests in macos.rs; here we
            // just confirm the CapabilitySet builds without error and has
            // a signal mode that the generator handles correctly.
            let mode = caps.signal_mode();
            assert!(
                matches!(
                    mode,
                    nono::SignalMode::Isolated
                        | nono::SignalMode::AllowSameSandbox
                        | nono::SignalMode::AllowAll
                ),
                "profile '{}' has unexpected signal_mode {:?}",
                name,
                mode,
            );
        }
    }
}
