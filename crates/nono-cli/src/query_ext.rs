//! CLI-specific query extensions for the sandbox
//!
//! This module provides query functions and output formatting for the
//! `nono why` command.

use crate::config;
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, Result, try_canonicalize};
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

/// Scope type for Landlock scope policy queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeQuery {
    /// `LANDLOCK_SCOPE_SIGNAL`.
    Signal,
    /// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`.
    AbstractUnixSocket,
}

impl ScopeQuery {
    fn as_str(self) -> &'static str {
        match self {
            ScopeQuery::Signal => "signal",
            ScopeQuery::AbstractUnixSocket => "abstract-unix-socket",
        }
    }
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
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint_rules: Option<Vec<crate::sandbox_state::EndpointRuleState>>,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint_rules: Option<Vec<crate::sandbox_state::EndpointRuleState>>,
    },
    /// The operation requires an approval decision.
    #[serde(rename = "approval_required")]
    ApprovalRequired {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy_source: Option<String>,
    },
    /// Not running inside a sandbox
    #[serde(rename = "not_sandboxed")]
    NotSandboxed { message: String },
    /// Landlock scope policy status.
    #[serde(rename = "scope")]
    Scope {
        scope: String,
        state: String,
        requested: bool,
        enforced: bool,
        supported: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        kernel_abi: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<String>,
    },
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
    if !is_overridden
        && let Some(matched) = config::check_sensitive_path(&canonical.to_string_lossy())?
    {
        return Ok(QueryResult::Denied {
            reason: "sensitive_path".to_string(),
            details: Some(format!(
                "Blocked by policy group '{}': {} Use filesystem.bypass_protection to exempt specific paths when appropriate.",
                matched.group_name, matched.description
            )),
            policy_source: Some(format!("group:{}", matched.group_name)),
            matching_capability: None,
            suggested_flag: None,
            endpoint_rules: None,
        });
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
            endpoint_rules: None,
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
            endpoint_rules: None,
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
        endpoint_rules: None,
    })
}

/// Query whether network access is permitted.
///
/// `allowed_domains` contains the resolved proxy allowlist (from profile
/// `allow_domain`, network profile hosts, and CLI `--allow-domain`).
/// When the network mode is `ProxyOnly`, delegates to `HostFilter` for
/// consistent matching with the proxy (including cloud metadata deny list).
pub fn query_network(
    host: &str,
    port: u16,
    caps: &CapabilitySet,
    allowed_domains: &[String],
    domain_endpoints: &[crate::sandbox_state::DomainEndpointState],
) -> QueryResult {
    let (domain, url_path) = parse_host_input(host);

    match caps.network_mode() {
        nono::NetworkMode::Blocked => QueryResult::Denied {
            reason: "network_blocked".to_string(),
            details: Some(format!(
                "Network access is fully blocked. Connection to {}:{} would be denied.",
                domain, port
            )),
            policy_source: None,
            matching_capability: None,
            suggested_flag: Some(format!("--allow-domain {}", domain)),
            endpoint_rules: None,
        },
        nono::NetworkMode::ProxyOnly { .. } => {
            let filter = if allowed_domains.is_empty() {
                nono::net_filter::HostFilter::allow_all()
            } else {
                nono::net_filter::HostFilter::new(allowed_domains)
            };
            // Pass empty IPs: DNS resolution happens at proxy time, not query time.
            match filter.check_host(&domain, &[]) {
                nono::net_filter::FilterResult::Allow => {
                    let matching_endpoints = domain_endpoints
                        .iter()
                        .find(|de| de.domain.eq_ignore_ascii_case(&domain));

                    match (matching_endpoints, &url_path) {
                        (Some(de), Some(path)) => {
                            if path_matches_endpoint_rules(path, &de.endpoints) {
                                QueryResult::Allowed {
                                    reason: "proxy_allowed".to_string(),
                                    granted_path: None,
                                    access: Some(format!(
                                        "Connection to {}:{} allowed via proxy \
                                         (path {} matches endpoint rules)",
                                        domain, port, path,
                                    )),
                                    source: Some("domain allowlist".to_string()),
                                    endpoint_rules: Some(de.endpoints.clone()),
                                }
                            } else {
                                QueryResult::Denied {
                                    reason: "endpoint_restricted".to_string(),
                                    details: Some(format!(
                                        "{} is allowed but {} does not match any endpoint rule",
                                        domain, path,
                                    )),
                                    policy_source: Some("endpoint rules".to_string()),
                                    matching_capability: None,
                                    suggested_flag: Some(format!(
                                        "--allow-domain https://{}{}",
                                        domain, path,
                                    )),
                                    endpoint_rules: Some(de.endpoints.clone()),
                                }
                            }
                        }
                        (Some(de), None) => QueryResult::Allowed {
                            reason: "proxy_allowed".to_string(),
                            granted_path: None,
                            access: Some(format!(
                                "Connection to {}:{} allowed via proxy \
                                 (restricted to {} endpoint rules)",
                                domain,
                                port,
                                de.endpoints.len(),
                            )),
                            source: Some("domain allowlist".to_string()),
                            endpoint_rules: Some(de.endpoints.clone()),
                        },
                        (None, _) => QueryResult::Allowed {
                            reason: "proxy_allowed".to_string(),
                            granted_path: None,
                            access: Some(format!(
                                "Connection to {}:{} would be allowed via proxy{}",
                                domain,
                                port,
                                if allowed_domains.is_empty() {
                                    " (no domain filter)"
                                } else {
                                    ""
                                }
                            )),
                            source: Some(if allowed_domains.is_empty() {
                                "proxy".to_string()
                            } else {
                                "domain allowlist".to_string()
                            }),
                            endpoint_rules: None,
                        },
                    }
                }
                deny => QueryResult::Denied {
                    reason: "proxy_filtered".to_string(),
                    details: Some(format!("Domain filtering is active. {}", deny.reason())),
                    policy_source: Some("proxy domain filter".to_string()),
                    matching_capability: None,
                    suggested_flag: Some(format!("--allow-domain {}", domain)),
                    endpoint_rules: None,
                },
            }
        }
        nono::NetworkMode::AllowAll => {
            // OS-level network is unrestricted, but a proxy domain filter may still
            // apply. When allowed_domains is non-empty the proxy is active; check it.
            if !allowed_domains.is_empty() {
                let filter = nono::net_filter::HostFilter::new(allowed_domains);
                match filter.check_host(&domain, &[]) {
                    nono::net_filter::FilterResult::Allow => QueryResult::Allowed {
                        reason: "proxy_allowed".to_string(),
                        granted_path: None,
                        access: Some(format!(
                            "Connection to {}:{} would be allowed via proxy",
                            domain, port
                        )),
                        source: Some("domain allowlist".to_string()),
                        endpoint_rules: None,
                    },
                    _ => QueryResult::Denied {
                        reason: "proxy_filtered".to_string(),
                        details: Some(format!(
                            "Domain filtering is active. host {} is not in the allowlist",
                            domain
                        )),
                        policy_source: Some("proxy domain filter".to_string()),
                        matching_capability: None,
                        suggested_flag: Some(format!("--allow-domain {}", domain)),
                        endpoint_rules: None,
                    },
                }
            } else {
                QueryResult::Allowed {
                    reason: "network_allowed".to_string(),
                    granted_path: None,
                    access: Some(format!(
                        "Connection to {}:{} would be allowed",
                        domain, port
                    )),
                    source: None,
                    endpoint_rules: None,
                }
            }
        }
    }
}

/// Parse a `--host` input that may be a bare hostname or a full URL.
/// Returns `(domain, optional_path)`.
fn parse_host_input(input: &str) -> (String, Option<String>) {
    if let Ok(parsed) = url::Url::parse(input) {
        let domain = parsed.host_str().unwrap_or(input).to_lowercase();
        let path = parsed.path();
        let url_path = if path.is_empty() || path == "/" {
            None
        } else {
            Some(path.to_string())
        };
        (domain, url_path)
    } else {
        (input.to_lowercase(), None)
    }
}

/// Normalize a URL path for endpoint rule matching (mirrors proxy behavior).
fn normalize_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let binary = urlencoding::decode_binary(path.as_bytes());
    let decoded = String::from_utf8_lossy(&binary);
    let segments: Vec<&str> = decoded.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// Check if a path matches any endpoint rule using glob matching.
fn path_matches_endpoint_rules(
    path: &str,
    rules: &[crate::sandbox_state::EndpointRuleState],
) -> bool {
    if rules.is_empty() {
        return true;
    }
    let normalized = normalize_path(path);
    rules.iter().any(|r| {
        let Ok(glob) = globset::Glob::new(&r.path) else {
            return false;
        };
        let matcher = glob.compile_matcher();
        matcher.is_match(&normalized)
    })
}

/// Query whether a Landlock scope is requested and enforced.
#[cfg(target_os = "linux")]
pub fn query_scope(scope: ScopeQuery, caps: &CapabilitySet) -> QueryResult {
    match nono::landlock_scope_policy(caps) {
        Ok(policy) => {
            let (requested, enforced) = match scope {
                ScopeQuery::Signal => (policy.signal_requested, policy.signal_enforced),
                ScopeQuery::AbstractUnixSocket => (
                    policy.abstract_unix_socket_requested,
                    policy.abstract_unix_socket_enforced,
                ),
            };
            QueryResult::Scope {
                scope: scope.as_str().to_string(),
                state: scope_state(requested, enforced, policy.scoping_supported).to_string(),
                requested,
                enforced,
                supported: policy.scoping_supported,
                kernel_abi: Some(policy.abi_version.to_string()),
                details: Some(scope_details(
                    scope,
                    requested,
                    enforced,
                    policy.scoping_supported,
                )),
            }
        }
        Err(err) => QueryResult::Scope {
            scope: scope.as_str().to_string(),
            state: "unavailable".to_string(),
            requested: false,
            enforced: false,
            supported: false,
            kernel_abi: None,
            details: Some(format!(
                "Landlock scope policy could not be resolved: {err}"
            )),
        },
    }
}

/// Query whether a Landlock scope is requested and enforced.
#[cfg(not(target_os = "linux"))]
pub fn query_scope(scope: ScopeQuery, _caps: &CapabilitySet) -> QueryResult {
    QueryResult::Scope {
        scope: scope.as_str().to_string(),
        state: "not_applicable".to_string(),
        requested: false,
        enforced: false,
        supported: false,
        kernel_abi: None,
        details: Some("Landlock scope queries are only available on Linux.".to_string()),
    }
}

#[cfg(target_os = "linux")]
fn scope_state(requested: bool, enforced: bool, supported: bool) -> &'static str {
    match (requested, enforced, supported) {
        (true, true, _) => "enforced",
        (true, false, false) => "unsupported",
        (true, false, true) => "not_enforced",
        (false, _, _) => "not_requested",
    }
}

#[cfg(target_os = "linux")]
fn scope_details(scope: ScopeQuery, requested: bool, enforced: bool, supported: bool) -> String {
    let label = scope.as_str();
    match (requested, enforced, supported) {
        (true, true, _) => {
            format!("{label} scope is requested by the capability set and enforced.")
        }
        (true, false, false) => {
            format!("{label} scope is requested, but this Landlock ABI does not support scoping.")
        }
        (true, false, true) => {
            format!("{label} scope is requested, but it is not enforced.")
        }
        (false, _, true) => format!("{label} scope is not requested by the capability set."),
        (false, _, false) => {
            format!("{label} scope is not requested; this Landlock ABI has no scope support.")
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
            endpoint_rules,
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
            if let Some(rules) = endpoint_rules {
                println!("  Endpoint rules ({} total):", rules.len());
                for rule in rules {
                    println!("    {} {}", rule.method, rule.path);
                }
            }
        }
        QueryResult::Denied {
            reason,
            details,
            policy_source,
            matching_capability,
            suggested_flag,
            endpoint_rules,
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
            if let Some(rules) = endpoint_rules {
                println!("  Permitted endpoints ({} total):", rules.len());
                for rule in rules {
                    println!("    {} {}", rule.method, rule.path);
                }
            }
        }
        QueryResult::ApprovalRequired {
            reason,
            details,
            policy_source,
        } => {
            println!("{}", "APPROVAL REQUIRED".yellow().bold());
            println!("  Reason: {}", reason);
            if let Some(d) = details {
                println!("  Details: {}", d);
            }
            if let Some(policy) = policy_source {
                println!("  Policy: {}", policy);
            }
        }
        QueryResult::NotSandboxed { message } => {
            println!("{}", "NOT SANDBOXED".yellow().bold());
            println!("  {}", message);
        }
        QueryResult::Scope {
            scope,
            state,
            requested,
            enforced,
            supported,
            kernel_abi,
            details,
        } => {
            println!("{}", "SCOPE".blue().bold());
            println!("  Scope: {}", scope);
            println!("  State: {}", state);
            println!("  Requested: {}", requested);
            println!("  Enforced: {}", enforced);
            println!("  Supported: {}", supported);
            if let Some(abi) = kernel_abi {
                println!("  Kernel ABI: {}", abi);
            }
            if let Some(detail) = details {
                println!("  Details: {}", detail);
            }
        }
    }
}

/// Format a flag for a known grant target (file vs directory).
pub(crate) fn suggested_flag_for_existing_target(
    target: &Path,
    is_file: bool,
    requested: AccessMode,
) -> String {
    let flag = if is_file {
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

    format!("{flag} {}", target.display())
}

/// Map a remediation to a CLI flag string when one applies.
pub(crate) fn suggested_flag_for_remediation(rem: &nono::NonoRemediation) -> Option<String> {
    match rem {
        nono::NonoRemediation::GrantPath {
            path,
            access,
            is_file,
        } => {
            if *is_file && !path.exists() {
                Some(suggested_flag_for_path(path, *access))
            } else {
                Some(suggested_flag_for_existing_target(path, *is_file, *access))
            }
        }
        nono::NonoRemediation::GrantUnixSocket { path, bind } => {
            let flag = if *bind {
                "--allow-unix-socket-bind"
            } else {
                "--allow-unix-socket"
            };
            Some(format!("{flag} {}", path.display()))
        }
        nono::NonoRemediation::AllowCwd => Some("--allow-cwd".to_string()),
        nono::NonoRemediation::DisableRollback => Some("--no-rollback".to_string()),
        nono::NonoRemediation::GrantNetwork => Some("--allow-net".to_string()),
        nono::NonoRemediation::RunDiscovery
        | nono::NonoRemediation::CheckPolicy
        | nono::NonoRemediation::AuthenticateCredentialProvider { .. }
        | nono::NonoRemediation::AdjustRollbackBudget { .. } => None,
    }
}

pub(crate) fn suggested_flag_for_path(path: &Path, requested: AccessMode) -> String {
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
                assert!(
                    details.as_deref().is_some_and(
                        |d| d.contains("group:dev") && d.contains("write was requested")
                    )
                );
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
                assert!(
                    policy_source
                        .as_deref()
                        .is_some_and(|policy| policy.starts_with("group:"))
                );
                assert!(
                    details
                        .as_deref()
                        .is_some_and(|detail| detail.contains("filesystem.bypass_protection"))
                );
                assert!(suggested_flag.is_none());
            }
            _ => panic!("expected denied result"),
        }
    }

    #[test]
    fn test_query_network_allowed() {
        let caps = CapabilitySet::new();
        let result = query_network("example.com", 443, &caps, &[], &[]);
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_network_blocked() {
        let caps = CapabilitySet::new().block_network();
        let result = query_network("example.com", 443, &caps, &[], &[]);
        assert!(matches!(result, QueryResult::Denied { .. }));
    }

    #[test]
    fn test_query_scope_returns_structured_result() {
        let caps = CapabilitySet::new();
        let result = query_scope(ScopeQuery::AbstractUnixSocket, &caps);
        match result {
            QueryResult::Scope {
                scope,
                state,
                requested,
                enforced,
                ..
            } => {
                assert_eq!(scope, "abstract-unix-socket");
                assert!(!state.is_empty());
                assert!(!enforced || requested);
            }
            _ => panic!("expected scope result"),
        }
    }

    #[test]
    fn test_query_network_proxy_domain_filtering() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        });
        let allowed = vec!["api.example.com".to_string()];

        let result = query_network("api.example.com", 443, &caps, &allowed, &[]);
        assert!(matches!(result, QueryResult::Allowed { .. }));

        match query_network("evil.com", 443, &caps, &allowed, &[]) {
            QueryResult::Denied {
                reason,
                suggested_flag,
                ..
            } => {
                assert_eq!(reason, "proxy_filtered");
                assert_eq!(suggested_flag.as_deref(), Some("--allow-domain evil.com"));
            }
            _ => panic!("expected denied result"),
        }
    }

    #[test]
    fn test_query_network_proxy_wildcard_and_bare_domain() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        });
        let allowed = vec!["*.example.com".to_string()];

        assert!(matches!(
            query_network("sub.example.com", 443, &caps, &allowed, &[]),
            QueryResult::Allowed { .. }
        ));
        // *.example.com must NOT match bare example.com (mirrors HostFilter)
        assert!(matches!(
            query_network("example.com", 443, &caps, &allowed, &[]),
            QueryResult::Denied { .. }
        ));
    }

    #[test]
    fn test_query_network_proxy_no_domain_filter() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        });
        assert!(matches!(
            query_network("anything.com", 443, &caps, &[], &[]),
            QueryResult::Allowed { .. }
        ));
    }

    #[test]
    fn test_query_network_proxy_denies_cloud_metadata() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        });
        // Cloud metadata endpoints are denied even with an empty allowlist
        assert!(matches!(
            query_network("169.254.169.254", 80, &caps, &[], &[]),
            QueryResult::Denied { .. }
        ));
        // Also denied even if explicitly in the allowlist
        let allowed = vec!["169.254.169.254".to_string()];
        assert!(matches!(
            query_network("169.254.169.254", 80, &caps, &allowed, &[]),
            QueryResult::Denied { .. }
        ));
    }

    #[test]
    fn test_query_network_url_extracts_domain() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        });
        let allowed = vec!["github.com".to_string()];
        // Full URL should extract domain and match
        assert!(matches!(
            query_network("https://github.com/some/repo", 443, &caps, &allowed, &[]),
            QueryResult::Allowed { .. }
        ));
    }

    #[test]
    fn test_query_network_url_with_endpoint_rules_path_matches() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        });
        let allowed = vec!["github.com".to_string()];
        let endpoints = vec![crate::sandbox_state::DomainEndpointState {
            domain: "github.com".to_string(),
            endpoints: vec![
                crate::sandbox_state::EndpointRuleState {
                    method: "*".to_string(),
                    path: "/atko-cic/**".to_string(),
                },
                crate::sandbox_state::EndpointRuleState {
                    method: "*".to_string(),
                    path: "/always-further/**".to_string(),
                },
            ],
        }];
        // Path that matches a rule
        let result = query_network(
            "https://github.com/atko-cic/repo",
            443,
            &caps,
            &allowed,
            &endpoints,
        );
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_network_url_with_endpoint_rules_path_denied() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        });
        let allowed = vec!["github.com".to_string()];
        let endpoints = vec![crate::sandbox_state::DomainEndpointState {
            domain: "github.com".to_string(),
            endpoints: vec![crate::sandbox_state::EndpointRuleState {
                method: "*".to_string(),
                path: "/atko-cic/**".to_string(),
            }],
        }];
        // Path that does NOT match any rule
        let result = query_network(
            "https://github.com/openai/codex",
            443,
            &caps,
            &allowed,
            &endpoints,
        );
        match result {
            QueryResult::Denied {
                reason,
                details,
                endpoint_rules,
                ..
            } => {
                assert_eq!(reason, "endpoint_restricted");
                assert!(
                    details
                        .as_deref()
                        .is_some_and(|d| d.contains("github.com") && d.contains("/openai/codex"))
                );
                let rules = endpoint_rules.expect("expected endpoint rules");
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].path, "/atko-cic/**");
            }
            _ => panic!("expected denied result, got: {:?}", result),
        }
    }

    #[test]
    fn test_query_network_bare_domain_with_endpoint_rules_shows_allowed() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        });
        let allowed = vec!["github.com".to_string()];
        let endpoints = vec![crate::sandbox_state::DomainEndpointState {
            domain: "github.com".to_string(),
            endpoints: vec![crate::sandbox_state::EndpointRuleState {
                method: "*".to_string(),
                path: "/atko-cic/**".to_string(),
            }],
        }];
        // Bare domain (no path) shows allowed with endpoint rules
        let result = query_network("github.com", 443, &caps, &allowed, &endpoints);
        match result {
            QueryResult::Allowed {
                endpoint_rules,
                access,
                ..
            } => {
                let rules = endpoint_rules.expect("expected endpoint rules");
                assert_eq!(rules.len(), 1);
                assert!(
                    access
                        .expect("expected access message")
                        .contains("restricted to 1 endpoint rules")
                );
            }
            _ => panic!("expected allowed result, got: {:?}", result),
        }
    }

    #[test]
    fn test_parse_host_input_url() {
        let (domain, path) = parse_host_input("https://github.com/openai/codex");
        assert_eq!(domain, "github.com");
        assert_eq!(path.as_deref(), Some("/openai/codex"));
    }

    #[test]
    fn test_parse_host_input_bare_hostname() {
        let (domain, path) = parse_host_input("github.com");
        assert_eq!(domain, "github.com");
        assert_eq!(path, None);
    }

    #[test]
    fn test_parse_host_input_url_root_path() {
        let (domain, path) = parse_host_input("https://api.example.com/");
        assert_eq!(domain, "api.example.com");
        assert_eq!(path, None);
    }

    #[test]
    fn test_path_matches_endpoint_rules_glob() {
        let rules = vec![
            crate::sandbox_state::EndpointRuleState {
                method: "*".to_string(),
                path: "/atko-cic/**".to_string(),
            },
            crate::sandbox_state::EndpointRuleState {
                method: "GET".to_string(),
                path: "/public/*".to_string(),
            },
        ];
        assert!(path_matches_endpoint_rules(
            "/atko-cic/repo/tree/main",
            &rules
        ));
        assert!(path_matches_endpoint_rules("/public/file.txt", &rules));
        assert!(!path_matches_endpoint_rules("/openai/codex", &rules));
        assert!(!path_matches_endpoint_rules("/other/path", &rules));
    }

    #[test]
    fn test_path_matches_empty_rules_allows_all() {
        assert!(path_matches_endpoint_rules("/any/path", &[]));
    }
}
