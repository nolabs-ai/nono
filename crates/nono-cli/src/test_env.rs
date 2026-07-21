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
