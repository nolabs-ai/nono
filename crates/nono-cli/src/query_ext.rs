//! CLI-specific query extensions for the sandbox
//!
//! This module provides query functions and output formatting for the
//! `nono why` command.

use crate::config;
use colored::Colorize;
use nono::{try_canonicalize, AccessMode, CapabilitySet, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Structured description of the capability that matched or nearly matched
/// a query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityMatch {
    /// Granted path for the capability.
    pub path: String,
    /// Granted access mode.
    pub access: String,
    /// Capability source such as user, profile, group:<name>, or system.
    pub source: String,
}

/// Result of querying whether an operation is permitted
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum QueryResult {
    /// The operation is allowed
    #[serde(rename = "allowed")]
    Allowed {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        granted_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        access: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
    /// The operation is denied
    #[serde(rename = "denied")]
    Denied {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy_source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        matching_capability: Option<CapabilityMatch>,
        #[serde(skip_serializing_if = "Option::is_none")]
        suggested_flag: Option<String>,
    },
    /// Not running inside a sandbox
    #[serde(rename = "not_sandboxed")]
    NotSandboxed { message: String },
}

/// Query whether a path operation is permitted
///
/// `overridden_paths` contains canonicalized paths that have been exempted from
/// deny groups via `bypass_protection`. The sensitive-path check is skipped for any
/// query path that is equal to or a child of an overridden path.
pub fn query_path(
    path: &Path,
    requested: AccessMode,
    caps: &CapabilitySet,
    overridden_paths: &[std::path::PathBuf],
) -> Result<QueryResult> {
    // Canonicalize the path for proper comparison using ancestor-walk fallback
    // so that macOS symlinks (/tmp → /private/tmp) are resolved correctly even
    // when the leaf path doesn't exist yet.
    let canonical = try_canonicalize(path);

    // Check if this path is covered by a bypass_protection exemption
    let is_overridden = overridden_paths
        .iter()
        .any(|op| canonical == *op || canonical.starts_with(op));

    // Check if this is a sensitive path (CLI security policy), but skip
    // the check for paths that have been explicitly overridden.
    if !is_overridden {
        if let Some(matched) = config::check_sensitive_path(&canonical.to_string_lossy())? {
            return Ok(QueryResult::Denied {
                reason: "sensitive_path".to_string(),
                details: Some(format!(
                    "Blocked by policy group '{}': {} Use filesystem.bypass_protection to exempt specific paths when appropriate.",
                    matched.group_name, matched.description
                )),
                policy_source: Some(format!("group:{}", matched.group_name)),
                matching_capability: None,
                suggested_flag: None,
            });
        }
    }

    // Check capabilities. Prefer the most specific matching grant so broad system
    // reads (e.g. /private on macOS) do not shadow explicit user grants.
    let mut best_covering: Option<&nono::FsCapability> = None;
    let mut best_sufficient: Option<&nono::FsCapability> = None;
    let mut best_covering_score = 0usize;
    let mut best_sufficient_score = 0usize;

    for cap in caps.fs_capabilities() {
        let covers = if cap.is_file {
            cap.resolved == canonical
        } else {
            canonical.starts_with(&cap.resolved)
        };

        if !covers {
            continue;
        }

        let score = cap.resolved.as_os_str().len();
        if score >= best_covering_score {
            best_covering = Some(cap);
            best_covering_score = score;
        }

        let sufficient = matches!(
            (cap.access, requested),
            (AccessMode::ReadWrite, _)
                | (AccessMode::Read, AccessMode::Read)
                | (AccessMode::Write, AccessMode::Write)
        );

        if sufficient && score >= best_sufficient_score {
            best_sufficient = Some(cap);
            best_sufficient_score = score;
        }
    }

    if let Some(cap) = best_sufficient {
        return Ok(QueryResult::Allowed {
            reason: "granted_path".to_string(),
            granted_path: Some(cap.resolved.display().to_string()),
            access: Some(cap.access.to_string()),
            source: Some(cap.source.to_string()),
        });
    }

    if let Some(cap) = best_covering {
        return Ok(QueryResult::Denied {
            reason: "insufficient_access".to_string(),
            details: Some(format!(
                "Path is covered by '{}', which grants {} access from {} but {} was requested",
                cap.resolved.display(),
                cap.access,
                cap.source,
                requested
            )),
            policy_source: None,
            matching_capability: Some(CapabilityMatch {
                path: cap.resolved.display().to_string(),
                access: cap.access.to_string(),
                source: cap.source.to_string(),
            }),
            suggested_flag: Some(suggested_flag_for_path(&canonical, requested)),
        });
    }

    Ok(QueryResult::Denied {
        reason: "path_not_granted".to_string(),
        details: Some(format!(
            "Path is not covered by any capability: {}",
            canonical.display()
        )),
        policy_source: None,
        matching_capability: None,
        suggested_flag: Some(suggested_flag_for_path(&canonical, requested)),
    })
}

/// Query whether network access is permitted
pub fn query_network(host: &str, port: u16, caps: &CapabilitySet) -> QueryResult {
    if caps.is_network_blocked() {
        QueryResult::Denied {
            reason: "network_blocked".to_string(),
            details: Some(format!(
                "Network access is blocked. Connection to {}:{} would be denied.",
                host, port
            )),
            policy_source: None,
            matching_capability: None,
            suggested_flag: None,
        }
    } else {
        QueryResult::Allowed {
            reason: "network_allowed".to_string(),
            granted_path: None,
            access: Some(format!("Connection to {}:{} would be allowed", host, port)),
            source: None,
        }
    }
}

/// Print a query result in human-readable format
pub fn print_result(result: &QueryResult) {
    match result {
        QueryResult::Allowed {
            reason,
            granted_path,
            access,
            source,
        } => {
            println!("{}", "ALLOWED".green().bold());
            println!("  Reason: {}", reason);
            if let Some(path) = granted_path {
                println!("  Granted by: {}", path);
            }
            if let Some(acc) = access {
                println!("  Access: {}", acc);
            }
            if let Some(src) = source {
                println!("  Source: {}", src);
            }
        }
        QueryResult::Denied {
            reason,
            details,
            policy_source,
            matching_capability,
            suggested_flag,
        } => {
            println!("{}", "DENIED".red().bold());
            println!("  Reason: {}", reason);
            if let Some(d) = details {
                println!("  Details: {}", d);
            }
            if let Some(policy) = policy_source {
                println!("  Policy: {}", policy);
            }
            if let Some(cap) = matching_capability {
                println!(
                    "  Closest match: {} ({}, {})",
                    cap.path, cap.access, cap.source
                );
            }
            if let Some(flag) = suggested_flag {
                println!("  Suggested fix: {}", flag);
            }
        }
        QueryResult::NotSandboxed { message } => {
            println!("{}", "NOT SANDBOXED".yellow().bold());
            println!("  {}", message);
        }
    }
}

fn suggested_flag_for_path(path: &Path, requested: AccessMode) -> String {
    let (flag, target) = suggested_flag_parts(path, requested);
    format!("{flag} {}", target.display())
}

pub(crate) fn suggested_flag_parts(path: &Path, requested: AccessMode) -> (&'static str, PathBuf) {
    let flag = if path.is_file() {
        match requested {
            AccessMode::Read => "--read-file",
            AccessMode::Write => "--write-file",
            AccessMode::ReadWrite => "--allow-file",
        }
    } else {
        match requested {
            AccessMode::Read => "--read",
            AccessMode::Write => "--write",
            AccessMode::ReadWrite => "--allow",
        }
    };

    let target = if path.exists() || path.is_dir() || path.parent().is_none() {
        path.to_path_buf()
    } else if let Some(parent) = path.parent() {
        // Never suggest granting access to the root filesystem
        if parent == Path::new("/") {
            path.to_path_buf()
        } else {
            parent.to_path_buf()
        }
    } else {
        path.to_path_buf()
    };

    (flag, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::{CapabilitySource, FsCapability};
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_query_path_granted() {
        let dir = tempdir().expect("Failed to create temp dir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: dir.path().to_path_buf(),
            resolved: dir.path().canonicalize().expect("Failed to canonicalize"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let test_file = dir.path().join("test.txt");
        std::fs::write(&test_file, "test").expect("Failed to write test file");
        let expected_grant = dir
            .path()
            .canonicalize()
            .expect("Failed to canonicalize dir");

        let result = query_path(&test_file, AccessMode::Read, &caps, &[]).expect("Query failed");
        match result {
            QueryResult::Allowed {
                source,
                granted_path,
                access,
                ..
            } => {
                assert_eq!(source.as_deref(), Some("user"));
                assert_eq!(
                    granted_path.as_deref(),
                    Some(expected_grant.to_string_lossy().as_ref())
                );
                assert_eq!(access.as_deref(), Some("read+write"));
            }
            _ => panic!("expected allowed result"),
        }
    }

    #[test]
    fn test_query_path_denied() {
        let caps = CapabilitySet::new();
        let path = PathBuf::from("/some/random/path");

        let result = query_path(&path, AccessMode::Read, &caps, &[]).expect("Query failed");
        match result {
            QueryResult::Denied {
                reason,
                suggested_flag,
                matching_capability,
                ..
            } => {
                assert_eq!(reason, "path_not_granted");
                assert_eq!(suggested_flag.as_deref(), Some("--read /some/random"));
                assert!(matching_capability.is_none());
            }
            _ => panic!("expected denied result"),
        }
    }

    #[test]
    fn test_query_path_prefers_more_specific_sufficient_capability() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_canon = dir.path().canonicalize().expect("Failed to canonicalize");

        let mut caps = CapabilitySet::new();
        let parent = dir_canon
            .parent()
            .expect("tempdir has parent")
            .to_path_buf();

        // Broad read-only capability.
        caps.add_fs(FsCapability {
            original: parent.clone(),
            resolved: parent,
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });

        // More specific read-write user capability.
        caps.add_fs(FsCapability {
            original: dir_canon.clone(),
            resolved: dir_canon.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let test_file = dir_canon.join("test.txt");
        std::fs::write(&test_file, "test").expect("Failed to write test file");

        let result = query_path(&test_file, AccessMode::Write, &caps, &[]).expect("Query failed");
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_path_reports_near_miss_with_source_and_fix() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_canon = dir.path().canonicalize().expect("Failed to canonicalize");
        let test_file = dir.path().join("test.txt");
        std::fs::write(&test_file, "test").expect("Failed to write test file");
        let test_file_canon = test_file
            .canonicalize()
            .expect("Failed to canonicalize file");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: dir_canon.clone(),
            resolved: dir_canon,
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("dev".to_string()),
        });

        let result = query_path(&test_file, AccessMode::Write, &caps, &[]).expect("Query failed");
        match result {
            QueryResult::Denied {
                reason,
                matching_capability,
                suggested_flag,
                details,
                ..
            } => {
                let expected_flag = format!("--write-file {}", test_file_canon.display());
                assert_eq!(reason, "insufficient_access");
                assert_eq!(suggested_flag.as_deref(), Some(expected_flag.as_str()));
                let capability = matching_capability.expect("expected matching capability");
                assert_eq!(capability.access, "read");
                assert_eq!(capability.source, "group:dev");
                assert!(details
                    .as_deref()
                    .is_some_and(|d| d.contains("group:dev") && d.contains("write was requested")));
            }
            _ => panic!("expected denied result"),
        }
    }

    #[test]
    fn test_query_path_sensitive_policy_includes_policy_source() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };
        let ssh_path = PathBuf::from(format!(
            "{}/.ssh",
            crate::config::validated_home().expect("HOME should be valid in test")
        ));
        let caps = CapabilitySet::new();

        let result = query_path(&ssh_path, AccessMode::Read, &caps, &[]).expect("Query failed");
        match result {
            QueryResult::Denied {
                reason,
                policy_source,
                suggested_flag,
                details,
                ..
            } => {
                assert_eq!(reason, "sensitive_path");
                assert!(policy_source
                    .as_deref()
                    .is_some_and(|policy| policy.starts_with("group:")));
                assert!(details
                    .as_deref()
                    .is_some_and(|detail| detail.contains("filesystem.bypass_protection")));
                assert!(suggested_flag.is_none());
            }
            _ => panic!("expected denied result"),
        }
    }

    #[test]
    fn test_query_network_allowed() {
        let caps = CapabilitySet::new(); // Network allowed by default
        let result = query_network("example.com", 443, &caps);
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_network_blocked() {
        let caps = CapabilitySet::new().block_network();
        let result = query_network("example.com", 443, &caps);
        assert!(matches!(result, QueryResult::Denied { .. }));
    }
}
