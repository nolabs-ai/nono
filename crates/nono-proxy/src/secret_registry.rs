//! Live registry of credential values resolved for a session.
//!
//! The supervisor removes these values from recorded terminal output and
//! input (NEP-0010 §3.1). Values arrive at different times: environment
//! credentials before the child starts, proxy credentials when routes load,
//! and refreshed or captured tokens while the session runs. Producers call
//! [`SecretRegistry::register`]; consumers check [`SecretRegistry::version`]
//! cheaply and rebuild their matcher from [`SecretRegistry::snapshot`] only
//! when it changes.
//!
//! Values are held as `Zeroizing<String>` and are never formatted: `Debug`
//! prints names only.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

/// One registered credential value and the name it is reported under.
#[derive(Clone)]
pub struct RegisteredSecret {
    /// Credential name, safe to display (never the value).
    pub name: String,
    /// Credential value.
    pub value: Zeroizing<String>,
}

impl fmt::Debug for RegisteredSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredSecret")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Default)]
struct Inner {
    entries: Vec<RegisteredSecret>,
}

/// Shared, append-only set of credential values for one session.
///
/// Cloning shares the same registry.
#[derive(Clone, Default)]
pub struct SecretRegistry {
    inner: Arc<Mutex<Inner>>,
    version: Arc<AtomicU64>,
}

impl fmt::Debug for SecretRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self.lock().entries.iter().map(|e| e.name.clone()).collect();
        f.debug_struct("SecretRegistry")
            .field("version", &self.version())
            .field("names", &names)
            .finish()
    }
}

impl SecretRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The registry's entries are plain data that stay valid even if a
    /// holder panicked, so a poisoned lock is recovered rather than letting
    /// registration silently fail and leave a value unredacted.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a credential value under `name`.
    ///
    /// Empty values are ignored. Registering a value already present under
    /// the same name is a no-op, so periodic refreshes do not grow the set.
    pub fn register(&self, name: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        let mut inner = self.lock();
        if inner
            .entries
            .iter()
            .any(|e| e.name == name && e.value.as_str() == value)
        {
            return;
        }
        inner.entries.push(RegisteredSecret {
            name: name.to_string(),
            value: Zeroizing::new(value.to_string()),
        });
        // Bump while holding the lock so a reader that sees the new version
        // and then snapshots always sees the new entry.
        self.version.fetch_add(1, Ordering::Release);
    }

    /// Monotonic change counter; increases on every new registration.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Current version and a copy of every registered value.
    #[must_use]
    pub fn snapshot(&self) -> (u64, Vec<RegisteredSecret>) {
        let inner = self.lock();
        (self.version(), inner.entries.clone())
    }

    /// Whether nothing has been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn register_dedupes_and_bumps_version_only_on_change() {
        let registry = SecretRegistry::new();
        assert_eq!(registry.version(), 0);
        registry.register("api", "sk-live-1234567890");
        registry.register("api", "sk-live-1234567890");
        registry.register("api", "");
        assert_eq!(registry.version(), 1);
        registry.register("other", "sk-live-1234567890");
        assert_eq!(registry.version(), 2);
        let (version, entries) = registry.snapshot();
        assert_eq!(version, 2);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn clones_share_state() {
        let registry = SecretRegistry::new();
        let clone = registry.clone();
        clone.register("token", "abcdefgh12345678");
        assert_eq!(registry.version(), 1);
        assert!(!registry.is_empty());
    }

    #[test]
    fn debug_never_prints_values() {
        let registry = SecretRegistry::new();
        registry.register("token", "super-secret-value-123");
        let rendered = format!("{registry:?} {:?}", registry.snapshot().1);
        assert!(!rendered.contains("super-secret-value-123"));
        assert!(rendered.contains("token"));
    }
}
