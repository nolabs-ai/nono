//! Integration-test copy of the `EnvVarGuard` RAII primitive.
//!
//! `crates/nono-cli` is a binary-only crate; its `#[cfg(test)] mod test_env`
//! in `src/test_env.rs` is therefore NOT visible from the integration test
//! compilation unit in `tests/`.  This file mirrors the canonical abstraction
//! verbatim so integration tests can use the same Drop-restore pattern without
//! reaching across the crate boundary.
//!
//! The source of truth for the guard contract is `crates/nono-cli/src/test_env.rs`.
//! If that file changes, update this mirror in lockstep.
//!
//! Phase 44 WR-03/WR-04/IN-01 P37 (REQ-REVIEW-FU-01 D-44-E6): the gate
//! is widened to include Linux so tests/auto_pull_e2e_linux.rs can use
//! the canonical Drop-restore guard instead of a file-local EnvGuard.
//! macOS does not yet host an integration-test consumer of this mirror;
//! if one is added, widen the gate further.

#![cfg(any(target_os = "windows", target_os = "linux"))]

/// Restores a set of environment variables when dropped.
///
/// Identical to `crates/nono-cli/src::test_env::EnvVarGuard` — see that type
/// for design rationale.  Duplicated here because integration tests cannot
/// import from a binary-only crate's `#[cfg(test)]` modules (Phase 41-05,
/// REQ-CI-02).
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
            std::env::set_var(key, value);
        }

        Self { original }
    }
}

#[allow(clippy::disallowed_methods)] // Restoring env vars is the other half of the safe wrapper.
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, value) in self.original.iter().rev() {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

/// Process-global lock for tests that mutate environment variables.
///
/// Tests in this integration-test compilation unit MUST call
/// `let _lock = lock_env();` at the top of every test function that
/// constructs an `EnvVarGuard`. `EnvVarGuard`'s Drop-restore is necessary
/// but not sufficient: it restores state at test end, but does not
/// prevent a sibling test on a parallel thread from observing the
/// mutated state DURING this test's execution. `lock_env` serializes
/// the parallel runner across env-var-mutating tests.
///
/// Mirrors `crates/nono-cli/src/test_env.rs::lock_env` which is not
/// visible from integration tests (binary-crate `cfg(test)` modules
/// do not export across the crate boundary).
///
/// Phase 44 D-44-E5 dead-code justification: on Windows the only current
/// consumer is `tests/env_vars.rs`, which uses `EnvVarGuard::set_all`
/// but does NOT yet call `lock_env()` (Plan 44-02 wires that via
/// cargo-nextest subprocess-per-test isolation). On Linux the
/// `tests/auto_pull_e2e_linux.rs` consumers acquire `lock_env()`
/// directly per Plan 44-01 Task 2. The function therefore appears
/// dead in the Windows integration-test binary until Plan 44-02
/// lands; the `#[allow(dead_code)]` is a transitional justified
/// allowance that will be removed once Plan 44-02 wires a Windows
/// consumer.
#[allow(dead_code)]
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[allow(dead_code)]
pub fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    match ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
