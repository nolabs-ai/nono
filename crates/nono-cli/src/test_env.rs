/// Process-global lock for tests that mutate environment variables.
///
/// Rust unit tests run in parallel within the same process, so concurrent
/// `env::set_var` / `env::remove_var` calls race against each other.
/// All env-mutating tests must acquire this lock before touching env vars.
///
/// See <https://github.com/nolabs-ai/nono/issues/567> for the plan to
/// eliminate env var mutation from tests entirely.
#[allow(dead_code)]
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Restores a set of environment variables when dropped.
pub struct EnvVarGuard {
    original: Vec<(&'static str, Option<String>)>,
}

#[allow(clippy::disallowed_methods)] // This IS the safe wrapper around env var mutation.
impl EnvVarGuard {
    /// Set multiple env vars, capturing originals for restore on drop.
    #[must_use]
    pub fn set_all(vars: &[(&'static str, &str)]) -> Self {
        let original = vars
            .iter()
            .map(|(key, _)| (*key, std::env::var(key).ok()))
            .collect::<Vec<_>>();

        for (key, value) in vars {
            // SAFETY: all callers hold ENV_LOCK, preventing concurrent env mutation.
            unsafe { std::env::set_var(key, value) };
        }

        Self { original }
    }

    /// Remove an env var mid-test (e.g. to test fallback behaviour).
    ///
    /// Only keys passed to [`set_all`](Self::set_all) can be removed — the
    /// guard restores their original values on drop. Panics if `key` is not
    /// managed by this guard, since the removal would not be reverted.
    pub fn remove(&self, key: &str) {
        assert!(
            self.original.iter().any(|(k, _)| *k == key),
            "EnvVarGuard::remove called with unmanaged key: '{key}'. \
             Only keys passed to set_all can be removed."
        );
        // SAFETY: callers hold ENV_LOCK.
        unsafe { std::env::remove_var(key) };
    }
}

#[allow(clippy::disallowed_methods)] // Restoring env vars is the other half of the safe wrapper.
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, value) in self.original.iter().rev() {
            // SAFETY: drop runs while ENV_LOCK is still held by the test.
            match value {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

/// Run `f` with `$XDG_CONFIG_HOME` pointed at a fresh empty directory, so the
/// user profile dir and the pack store start out empty and only contain what
/// the test writes.
pub(crate) fn with_isolated_config_home<F, R>(f: F) -> R
where
    F: FnOnce(&std::path::Path) -> R,
{
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().expect("tempdir");
    // Canonicalize: `resolve_user_config_dir` canonicalizes XDG_CONFIG_HOME,
    // so hand back the same form the code under test will compute (on macOS
    // the temp dir is under /var, a symlink to /private/var).
    let config_home = tmp.path().canonicalize().expect("canonicalize temp dir");
    let _env = EnvVarGuard::set_all(&[(
        "XDG_CONFIG_HOME",
        config_home.to_str().expect("utf-8 temp path"),
    )]);
    f(&config_home)
}

/// Install a fake pack under `config_home` providing one profile artifact
/// installed as `install_as` and also answering to `aliases`.
///
/// Creates:
///   `<config_home>/nono/packages/<ns>/<pack_name>/package.json`
///   `<config_home>/nono/packages/<ns>/<pack_name>/profiles/<install_as>.json`
///   `<config_home>/nono/packages/<ns>/<pack_name>/hooks/<hook_file>` (empty)
///
/// Returns the install directory.
pub(crate) fn write_fake_pack(
    config_home: &std::path::Path,
    namespace: &str,
    pack_name: &str,
    install_as: &str,
    profile_json: &str,
    aliases: &[&str],
    hook_file: Option<&str>,
) -> std::path::PathBuf {
    let install_dir = config_home
        .join("nono")
        .join("packages")
        .join(namespace)
        .join(pack_name);
    std::fs::create_dir_all(install_dir.join("profiles")).expect("create profiles dir");
    if let Some(hook_file) = hook_file {
        let hooks_dir = install_dir.join("hooks");
        std::fs::create_dir_all(&hooks_dir).expect("create hooks dir");
        std::fs::write(hooks_dir.join(hook_file), "#!/bin/sh\n").expect("write hook file");
    }
    let aliases = aliases
        .iter()
        .map(|alias| format!("\"{alias}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        install_dir.join("package.json"),
        format!(
            r#"{{
              "schema_version": 1,
              "name": "{pack_name}",
              "artifacts": [{{
                "type": "profile",
                "path": "profiles/{install_as}.json",
                "install_as": "{install_as}",
                "aliases": [{aliases}]
              }}]
            }}"#
        ),
    )
    .expect("write package.json");
    std::fs::write(
        install_dir
            .join("profiles")
            .join(format!("{install_as}.json")),
        profile_json,
    )
    .expect("write pack profile");
    install_dir
}

/// Write a user profile to `<config_home>/nono/profiles/<name>.json`, the
/// location that shadows both pack-store and built-in profiles of that name.
pub(crate) fn write_user_profile(config_home: &std::path::Path, name: &str, profile_json: &str) {
    let profiles = config_home.join("nono").join("profiles");
    std::fs::create_dir_all(&profiles).expect("create profiles dir");
    std::fs::write(profiles.join(format!("{name}.json")), profile_json).expect("write profile");
}
