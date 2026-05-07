//! Query API for checking sandbox permissions
//!
//! This module provides utilities for querying what operations are permitted
//! by a given capability set, without actually applying the sandbox.

use crate::capability::{AccessMode, CapabilitySet};
use crate::path::try_canonicalize_ancestor_walk;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Result of querying whether an operation is permitted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueryResult {
    /// The operation is allowed
    Allowed(AllowReason),
    /// The operation is denied
    Denied(DenyReason),
}

/// Reason why an operation is allowed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AllowReason {
    /// Path is covered by a granted capability
    GrantedPath {
        /// The capability that grants access
        granted_path: String,
        /// The access mode granted
        access: String,
    },
    /// Network access is not blocked
    NetworkAllowed,
}

/// Reason why an operation is denied
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DenyReason {
    /// Path is not covered by any capability
    PathNotGranted,
    /// Path is covered but with insufficient access
    InsufficientAccess {
        /// The access mode that was granted
        granted: String,
        /// The access mode that was requested
        requested: String,
    },
    /// Network access is blocked
    NetworkBlocked,
}

/// Context for querying sandbox permissions
#[derive(Debug)]
pub struct QueryContext {
    caps: CapabilitySet,
}

impl QueryContext {
    /// Create a new query context for the given capabilities
    #[must_use]
    pub fn new(caps: CapabilitySet) -> Self {
        Self { caps }
    }

    /// Query whether a path operation is permitted
    ///
    /// Uses a hybrid resolution strategy:
    /// - If the path can be canonicalized, compare against `cap.resolved` (most accurate,
    ///   follows full symlink chain).
    /// - If canonicalization fails (path doesn't exist yet), fall back to comparing
    ///   against both `cap.original` and `cap.resolved` to handle symlink aliases
    ///   like `/tmp` -> `/private/tmp` on macOS.
    #[must_use]
    pub fn query_path(&self, path: &Path, requested: AccessMode) -> QueryResult {
        // Try to canonicalize for the most accurate comparison.
        // Falls back to ancestor-walk if the target doesn't exist yet so that
        // macOS symlinks (/tmp → /private/tmp) are resolved correctly.
        let full_canonical = std::fs::canonicalize(path).ok();
        let query_path_buf;
        let query_path: &Path = if let Some(ref c) = full_canonical {
            c.as_path()
        } else {
            // canonicalize already failed above; skip the redundant retry
            // and go straight to the ancestor-walk fallback.
            query_path_buf = try_canonicalize_ancestor_walk(path);
            query_path_buf.as_path()
        };

        for cap in self.caps.fs_capabilities() {
            let covers = if cap.is_file {
                // File capability: exact match against resolved, or if not
                // canonicalized, also check against original
                query_path == cap.resolved
                    || (full_canonical.is_none() && path == cap.original.as_path())
            } else {
                // Directory capability: path must be under the directory.
                // Check resolved first (canonical path), then original
                // (symlink path) for non-existent paths.
                query_path.starts_with(&cap.resolved)
                    || (full_canonical.is_none() && path.starts_with(&cap.original))
            };

            if covers {
                let sufficient = matches!(
                    (cap.access, requested),
                    (AccessMode::ReadWrite, _)
                        | (AccessMode::Read, AccessMode::Read)
                        | (AccessMode::Write, AccessMode::Write)
                );

                if sufficient {
                    return QueryResult::Allowed(AllowReason::GrantedPath {
                        granted_path: cap.resolved.display().to_string(),
                        access: cap.access.to_string(),
                    });
                } else {
                    return QueryResult::Denied(DenyReason::InsufficientAccess {
                        granted: cap.access.to_string(),
                        requested: requested.to_string(),
                    });
                }
            }
        }

        QueryResult::Denied(DenyReason::PathNotGranted)
    }

    /// Query whether network access is permitted
    #[must_use]
    pub fn query_network(&self) -> QueryResult {
        if self.caps.is_network_blocked() {
            QueryResult::Denied(DenyReason::NetworkBlocked)
        } else {
            QueryResult::Allowed(AllowReason::NetworkAllowed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySource, FsCapability};
    use std::path::PathBuf;

    #[test]
    fn test_query_path_granted() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test"),
            resolved: PathBuf::from("/test"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let ctx = QueryContext::new(caps);

        // Path under granted directory should be allowed
        let result = ctx.query_path(Path::new("/test/file.txt"), AccessMode::Read);
        assert!(matches!(result, QueryResult::Allowed(_)));

        // Path outside granted directory should be denied
        let result = ctx.query_path(Path::new("/other/file.txt"), AccessMode::Read);
        assert!(matches!(
            result,
            QueryResult::Denied(DenyReason::PathNotGranted)
        ));
    }

    #[test]
    fn test_query_path_symlink_alias() {
        // Simulates macOS /tmp -> /private/tmp: original is the symlink,
        // resolved is the canonicalized target.
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/tmp"),
            resolved: PathBuf::from("/private/tmp"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let ctx = QueryContext::new(caps);

        // Query via resolved path should match
        let result = ctx.query_path(Path::new("/private/tmp/file.txt"), AccessMode::Read);
        assert!(
            matches!(result, QueryResult::Allowed(_)),
            "resolved path should be allowed"
        );

        // Query via symlink path for a non-existent file should still match
        // (falls back to checking cap.original since canonicalize fails)
        let result = ctx.query_path(
            Path::new("/tmp/nonexistent-query-test-file.txt"),
            AccessMode::Write,
        );
        assert!(
            matches!(result, QueryResult::Allowed(_)),
            "symlink path for non-existent file should be allowed via original"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_query_path_existing_symlink_canonicalizes() {
        // Use a test-local symlink so the behavior is exercised on any Unix
        // platform instead of assuming a macOS-specific /tmp layout.
        let dir = tempfile::tempdir().expect("tempdir");
        let real_dir = dir.path().join("real");
        std::fs::create_dir_all(&real_dir).expect("create real dir");
        let link_dir = dir.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link_dir).expect("create symlink");
        let resolved = real_dir.canonicalize().expect("canonicalize real dir");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: link_dir.clone(),
            resolved,
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        let ctx = QueryContext::new(caps);

        let result = ctx.query_path(&link_dir, AccessMode::Read);
        assert!(
            matches!(result, QueryResult::Allowed(_)),
            "existing symlink path should canonicalize and match resolved"
        );
    }

    #[test]
    fn test_query_network() {
        let caps_allowed = CapabilitySet::new();
        let ctx = QueryContext::new(caps_allowed);
        assert!(matches!(ctx.query_network(), QueryResult::Allowed(_)));

        let caps_blocked = CapabilitySet::new().block_network();
        let ctx = QueryContext::new(caps_blocked);
        assert!(matches!(
            ctx.query_network(),
            QueryResult::Denied(DenyReason::NetworkBlocked)
        ));
    }
}
