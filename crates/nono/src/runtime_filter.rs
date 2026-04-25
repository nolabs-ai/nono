//! Runtime-mutable host filter for dynamic whitelist extension.
//!
//! [`RuntimeHostFilter`] wraps a [`HostFilter`] in a [`std::sync::RwLock`],
//! allowing the allowlist to be extended at runtime (e.g., when the user
//! approves a new host via an OS notification).
//!
//! The core `HostFilter` remains immutable-by-default; this module adds
//! the mutation layer needed for interactive approval workflows.

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::net_filter::{FilterResult, HostFilter};
use crate::Result;

/// Thread-safe, runtime-mutable host filter.
///
/// Unlike [`HostFilter`] (which is immutable after construction),
/// `RuntimeHostFilter` allows hosts to be added while the proxy
/// is serving requests. Reads and writes are protected by an
/// [`RwLock`], so concurrent checks do not block each other.
///
/// # Example
///
/// ```rust
/// use nono::{HostFilter, RuntimeHostFilter};
///
/// let filter = RuntimeHostFilter::new(HostFilter::new(&["allowed.com".to_string()]));
/// assert!(filter.check_host("allowed.com", &[]).is_allowed());
/// assert!(!filter.check_host("denied.com", &[]).is_allowed());
///
/// filter.add_host("denied.com").expect("add host");
/// assert!(filter.check_host("denied.com", &[]).is_allowed());
/// ```
#[derive(Debug, Clone)]
pub struct RuntimeHostFilter {
    inner: Arc<RwLock<HostFilter>>,
}

impl RuntimeHostFilter {
    /// Create a new runtime filter wrapping the given [`HostFilter`].
    #[must_use]
    pub fn new(filter: HostFilter) -> Self {
        Self {
            inner: Arc::new(RwLock::new(filter)),
        }
    }

    /// Check whether a host is allowed.
    ///
    /// Takes a read lock — multiple concurrent checks do not block each other.
    /// The `resolved_ips` parameter is forwarded to [`HostFilter::check_host`].
    #[must_use]
    pub fn check_host(&self, host: &str, resolved_ips: &[std::net::IpAddr]) -> FilterResult {
        let guard = self.read_lock();
        guard.check_host(host, resolved_ips)
    }

    /// Add an exact host to the allowlist at runtime.
    ///
    /// Takes a write lock — blocks concurrent reads and writes.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError`](crate::NonoError) if the host is empty
    /// or is a cloud metadata endpoint.
    pub fn add_host(&self, host: &str) -> Result<()> {
        let mut guard = self.write_lock();
        guard.add_host(host)
    }

    /// Add a wildcard subdomain suffix to the allowlist at runtime.
    ///
    /// Takes a write lock — blocks concurrent reads and writes.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError`](crate::NonoError) if the suffix is empty.
    pub fn add_suffix(&self, suffix: &str) -> Result<()> {
        let mut guard = self.write_lock();
        guard.add_suffix(suffix)
    }

    /// Add a host to the deny list at runtime.
    ///
    /// Takes a write lock — blocks concurrent reads and writes.
    /// Once denied, the host cannot pass the filter regardless of the
    /// allowlist. This is used for "always deny" decisions.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError`](crate::NonoError) if the host is empty.
    pub fn add_deny_host(&self, host: &str) -> Result<()> {
        let mut guard = self.write_lock();
        guard.add_deny_host(host)
    }

    /// Add a wildcard subdomain suffix to the deny list at runtime.
    ///
    /// Takes a write lock — blocks concurrent reads and writes.
    /// Once denied, any subdomain matching the suffix cannot pass the
    /// filter regardless of the allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError`](crate::NonoError) if the suffix is empty.
    pub fn add_deny_suffix(&self, suffix: &str) -> Result<()> {
        let mut guard = self.write_lock();
        guard.add_deny_suffix(suffix)
    }

    /// Snapshot the current [`HostFilter`] state.
    ///
    /// Useful for auditing or persisting the runtime allowlist.
    #[must_use]
    pub fn snapshot(&self) -> HostFilter {
        let guard = self.read_lock();
        guard.clone()
    }

    fn read_lock(&self) -> RwLockReadGuard<'_, HostFilter> {
        self.inner.read().expect("runtime filter lock poisoned")
    }

    fn write_lock(&self) -> RwLockWriteGuard<'_, HostFilter> {
        self.inner.write().expect("runtime filter lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_IPS: &[std::net::IpAddr] = &[];

    fn deny_default_filter() -> HostFilter {
        HostFilter::new(&["__deny_default_sentinel__.invalid".to_string()])
    }

    #[test]
    fn test_add_host_makes_host_allowed() {
        let filter = RuntimeHostFilter::new(deny_default_filter());
        assert!(!filter.check_host("example.com", NO_IPS).is_allowed());

        filter.add_host("example.com").expect("add host");
        assert!(filter.check_host("example.com", NO_IPS).is_allowed());
    }

    #[test]
    fn test_add_suffix_makes_subdomain_allowed() {
        let filter = RuntimeHostFilter::new(deny_default_filter());
        assert!(!filter.check_host("sub.example.com", NO_IPS).is_allowed());

        filter.add_suffix(".example.com").expect("add suffix");
        assert!(filter.check_host("sub.example.com", NO_IPS).is_allowed());
    }

    #[test]
    fn test_add_host_idempotent() {
        let filter = RuntimeHostFilter::new(deny_default_filter());
        filter.add_host("example.com").expect("add host 1");
        filter.add_host("example.com").expect("add host 2");
        let snap = filter.snapshot();
        assert_eq!(snap.allowed_count(), 2);
    }

    #[test]
    fn test_add_host_rejects_empty() {
        let filter = RuntimeHostFilter::new(deny_default_filter());
        let result = filter.add_host("");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_host_rejects_cloud_metadata() {
        let filter = RuntimeHostFilter::new(deny_default_filter());
        let result = filter.add_host("169.254.169.254");
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_captures_runtime_state() {
        let filter = RuntimeHostFilter::new(HostFilter::new(&["initial.com".to_string()]));
        filter.add_host("added.com").expect("add host");

        let snap = filter.snapshot();
        assert!(snap.check_host("initial.com", NO_IPS).is_allowed());
        assert!(snap.check_host("added.com", NO_IPS).is_allowed());
    }

    #[test]
    fn test_concurrent_reads() {
        let filter = RuntimeHostFilter::new(HostFilter::new(&["example.com".to_string()]));
        let f1 = filter.clone();
        let f2 = filter.clone();

        let h1 = std::thread::spawn(move || f1.check_host("example.com", NO_IPS));
        let h2 = std::thread::spawn(move || f2.check_host("example.com", NO_IPS));

        assert!(h1.join().expect("thread 1").is_allowed());
        assert!(h2.join().expect("thread 2").is_allowed());
    }

    #[test]
    fn test_concurrent_read_write() {
        let filter = RuntimeHostFilter::new(deny_default_filter());
        let f_read = filter.clone();
        let f_write = filter.clone();

        let writer = std::thread::spawn(move || {
            f_write.add_host("example.com").expect("add host");
        });

        writer.join().expect("writer thread");

        let reader = std::thread::spawn(move || f_read.check_host("example.com", NO_IPS));
        assert!(reader.join().expect("reader thread").is_allowed());
    }
}
