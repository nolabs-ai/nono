//! Trust policy loading, merging, and evaluation
//!
//! Provides functions for parsing trust policy JSON, merging multiple policies
//! from different levels (embedded, user, project), and evaluating files
//! against the merged policy.
//!
//! # Policy Composition
//!
//! Multiple `trust-policy.json` files are merged with additive-only semantics:
//! - Publishers: union (all publishers from all levels)
//! - Blocklist digests: union (all blocked digests from all levels)
//! - Blocked publishers: union
//! - Include patterns: union (all patterns from all levels)
//! - Enforcement: strictest wins (deny > warn > audit)
//!
//! Project-level policy cannot weaken user-level or embedded policy.

use crate::error::{NonoError, Result};

use super::types::{
    BlockedPublisher, Blocklist, BlocklistEntry, Enforcement, Publisher, SignerIdentity,
    TrustPolicy, VerificationOutcome, VerificationResult,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Parse a trust policy from a JSON string.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if the JSON is malformed or missing
/// required fields.
pub fn load_policy_from_str(json: &str) -> Result<TrustPolicy> {
    let policy: TrustPolicy = serde_json::from_str(json)
        .map_err(|e| NonoError::TrustPolicy(format!("failed to parse trust policy: {e}")))?;
    policy.validate_version()?;
    Ok(policy)
}

/// Parse a trust policy from a JSON file.
///
/// # Errors
///
/// Returns `NonoError::Io` if the file cannot be read, or
/// `NonoError::TrustPolicy` if the JSON is invalid.
pub fn load_policy_from_file<P: AsRef<Path>>(path: P) -> Result<TrustPolicy> {
    let content = std::fs::read_to_string(path.as_ref()).map_err(NonoError::Io)?;
    load_policy_from_str(&content)
}

/// Merge multiple trust policies into a single effective policy.
///
/// Policies are merged in order (first = lowest priority, last = highest).
/// All merging is additive-only:
/// - Publishers, blocklist entries, blocked publishers, and include
///   patterns are unioned (deduplicated by identity)
/// - Enforcement uses the strictest level across all policies
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if no policies are provided.
pub fn merge_policies(policies: &[TrustPolicy]) -> Result<TrustPolicy> {
    if policies.is_empty() {
        return Err(NonoError::TrustPolicy(
            "no trust policies to merge".to_string(),
        ));
    }

    for policy in policies {
        policy.validate_version()?;
    }

    let mut merged_patterns: Vec<String> = Vec::new();
    let mut seen_patterns: HashSet<String> = HashSet::new();

    let mut merged_files: Vec<String> = Vec::new();
    let mut seen_files: HashSet<String> = HashSet::new();

    let mut merged_publishers: Vec<Publisher> = Vec::new();
    let mut seen_publisher_names: HashSet<String> = HashSet::new();

    let mut merged_digest_entries: Vec<BlocklistEntry> = Vec::new();
    let mut seen_digests: HashSet<String> = HashSet::new();

    let mut merged_blocked_publishers: Vec<BlockedPublisher> = Vec::new();
    let mut seen_blocked_identities: HashSet<String> = HashSet::new();

    let mut strictest_enforcement = Enforcement::Audit;

    for policy in policies {
        // Merge include patterns (deduplicate by pattern string)
        for pattern in &policy.includes {
            if seen_patterns.insert(pattern.clone()) {
                merged_patterns.push(pattern.clone());
            }
        }

        // Merge explicit file paths (deduplicate by path string)
        for file in &policy.files {
            if seen_files.insert(file.clone()) {
                merged_files.push(file.clone());
            }
        }

        // Merge publishers (deduplicate by name, first-occurrence wins).
        // Callers pass policies in precedence order (user-level first),
        // so user publishers take priority over project publishers.
        for publisher in &policy.publishers {
            if !seen_publisher_names.insert(publisher.name.clone()) {
                tracing::debug!(
                    "trust policy merge: publisher '{}' appears in multiple policies, using the user-level definition for verification",
                    publisher.name
                );
            } else {
                merged_publishers.push(publisher.clone());
            }
        }

        // Merge blocklist digests (deduplicate by sha256)
        for entry in &policy.blocklist.digests {
            if seen_digests.insert(entry.sha256.clone()) {
                merged_digest_entries.push(entry.clone());
            }
        }

        // Merge blocked publishers (deduplicate by identity)
        for blocked in &policy.blocklist.publishers {
            if seen_blocked_identities.insert(blocked.identity.clone()) {
                merged_blocked_publishers.push(blocked.clone());
            }
        }

        // Enforcement: strictest wins
        strictest_enforcement = strictest_enforcement.strictest(policy.enforcement);
    }

    Ok(TrustPolicy {
        version: policies.iter().map(|p| p.version).max().unwrap_or(1),
        includes: merged_patterns,
        files: merged_files,
        publishers: merged_publishers,
        blocklist: Blocklist {
            digests: merged_digest_entries,
            publishers: merged_blocked_publishers,
        },
        enforcement: strictest_enforcement,
    })
}

/// Evaluate a file against a trust policy.
///
/// Runs the full verification pipeline:
/// 1. Blocklist check (fast reject by digest)
/// 2. If no signer identity provided, file is unsigned
/// 3. Publisher matching against the trust policy
///
/// Returns a [`VerificationResult`] with the outcome and file metadata.
///
/// This function does NOT perform cryptographic verification of bundles.
/// Bundle verification is handled by higher-level code that extracts the
/// [`SignerIdentity`] before calling this function.
pub fn evaluate_file(
    policy: &TrustPolicy,
    path: &Path,
    digest: &str,
    signer: Option<&SignerIdentity>,
) -> VerificationResult {
    // Step 1: Blocklist check (always runs, regardless of enforcement mode)
    if let Some(entry) = policy.check_blocklist(digest) {
        return VerificationResult {
            path: path.to_path_buf(),
            digest: digest.to_string(),
            outcome: VerificationOutcome::Blocked {
                reason: entry.description.clone(),
            },
        };
    }

    // Step 2: Check if file is signed
    let identity = match signer {
        Some(id) => id,
        None => {
            return VerificationResult {
                path: path.to_path_buf(),
                digest: digest.to_string(),
                outcome: VerificationOutcome::Unsigned,
            };
        }
    };

    // Step 3: Check blocked publishers
    if is_publisher_blocked(policy, identity) {
        return VerificationResult {
            path: path.to_path_buf(),
            digest: digest.to_string(),
            outcome: VerificationOutcome::UntrustedPublisher {
                identity: identity.clone(),
            },
        };
    }

    // Step 4: Publisher matching
    let matches = policy.matching_publishers(identity);
    if matches.is_empty() {
        return VerificationResult {
            path: path.to_path_buf(),
            digest: digest.to_string(),
            outcome: VerificationOutcome::UntrustedPublisher {
                identity: identity.clone(),
            },
        };
    }

    VerificationResult {
        path: path.to_path_buf(),
        digest: digest.to_string(),
        outcome: VerificationOutcome::Verified {
            publisher: matches[0].name.clone(),
        },
    }
}

/// Check if a signer identity is on the blocked publishers list.
fn is_publisher_blocked(policy: &TrustPolicy, identity: &SignerIdentity) -> bool {
    policy
        .blocklist
        .publishers
        .iter()
        .any(|blocked| match identity {
            SignerIdentity::Keyed { key_id } => blocked.identity == *key_id,
            SignerIdentity::Keyless {
                issuer, repository, ..
            } => {
                if blocked.identity != *issuer {
                    return false;
                }
                // If the blocklist entry specifies a repository, match it.
                // If no repository specified, the entire issuer is blocked.
                match &blocked.repository {
                    Some(blocked_repo) => blocked_repo == repository,
                    None => true,
                }
            }
        })
}

/// Well-known directory names that never contain instruction files and are
/// typically very large. Sorted for binary search.
const SKIP_DIRS: &[&str] = &[
    ".cache",
    ".git",
    ".gradle",
    ".hg",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".terraform",
    ".tox",
    ".venv",
    "__pycache__",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
];

/// Scan a directory for files matching instruction patterns.
///
/// Returns the list of paths that match any pattern in the trust policy.
/// Hidden directories are scanned unless they are explicitly listed in the
/// built-in heavy-directory skip set or provided via `extra_skip_dirs`.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if patterns cannot be compiled, or
/// `NonoError::Io` if directory traversal fails.
pub fn find_included_files<P: AsRef<Path>>(policy: &TrustPolicy, root: P) -> Result<Vec<PathBuf>> {
    find_included_files_with_skip_dirs(policy, root, &[])
}

/// Scan a directory for files matching instruction patterns, skipping extra
/// directory names in addition to the built-in heavy-directory list.
pub fn find_included_files_with_skip_dirs<P: AsRef<Path>>(
    policy: &TrustPolicy,
    root: P,
    extra_skip_dirs: &[String],
) -> Result<Vec<PathBuf>> {
    let root = root.as_ref();
    let matcher = policy.include_matcher()?;
    let extra_skip_dirs: std::collections::HashSet<&str> =
        extra_skip_dirs.iter().map(String::as_str).collect();
    let mut results = Vec::new();
    let mut visited = std::collections::HashSet::new();

    if policy.includes.is_empty() {
        return Ok(results);
    }

    find_files_recursive(
        root,
        root,
        &matcher,
        &extra_skip_dirs,
        &mut results,
        &mut visited,
        0,
    )?;

    results.sort();
    Ok(results)
}

fn should_skip_dir(name: &str, extra_skip_dirs: &std::collections::HashSet<&str>) -> bool {
    SKIP_DIRS.binary_search(&name).is_ok() || extra_skip_dirs.contains(name)
}

fn find_files_recursive(
    root: &Path,
    dir: &Path,
    matcher: &super::types::IncludePatterns,
    extra_skip_dirs: &std::collections::HashSet<&str>,
    results: &mut Vec<PathBuf>,
    visited: &mut std::collections::HashSet<(u64, u64)>,
    depth: u32,
) -> Result<()> {
    const MAX_DEPTH: u32 = 16;
    if depth > MAX_DEPTH {
        return Ok(());
    }

    let entries = std::fs::read_dir(dir).map_err(NonoError::Io)?;

    for entry in entries {
        let entry = entry.map_err(NonoError::Io)?;
        let path = entry.path();
        let meta = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if meta.is_dir() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if should_skip_dir(&name_str, extra_skip_dirs) {
                continue;
            }

            #[cfg(unix)]
            let file_id = Some({
                use std::os::unix::fs::MetadataExt;
                (meta.dev(), meta.ino())
            });
            #[cfg(not(unix))]
            let file_id: Option<(u64, u64)> = None;

            if let Some(file_id) = file_id
                && !visited.insert(file_id)
            {
                continue;
            }

            find_files_recursive(
                root,
                &path,
                matcher,
                extra_skip_dirs,
                results,
                visited,
                depth + 1,
            )?;
        } else if meta.is_file() {
            if path.to_string_lossy().ends_with(".bundle") {
                continue;
            }

            if let Ok(relative) = path.strip_prefix(root)
                && matcher.is_match(relative)
            {
                results.push(path);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_policy(
        enforcement: Enforcement,
        publishers: Vec<Publisher>,
        blocklist_digests: Vec<BlocklistEntry>,
    ) -> TrustPolicy {
        TrustPolicy {
            version: 1,
            includes: vec!["SKILLS*".to_string(), "CLAUDE*".to_string()],
            files: vec![],
            publishers,
            blocklist: Blocklist {
                digests: blocklist_digests,
                publishers: vec![],
            },
            enforcement,
        }
    }

    fn keyed_publisher(name: &str, key_id: &str) -> Publisher {
        Publisher {
            name: name.to_string(),
            issuer: None,
            repository: None,
            workflow: None,
            ref_pattern: None,
            key_id: Some(key_id.to_string()),
            public_key: None,
            build_signer_uri: None,
        }
    }

    fn keyless_publisher(name: &str, issuer: &str, repo: &str) -> Publisher {
        Publisher {
            name: name.to_string(),
            issuer: Some(issuer.to_string()),
            repository: Some(repo.to_string()),
            workflow: Some("*".to_string()),
            ref_pattern: Some("*".to_string()),
            key_id: None,
            public_key: None,
            build_signer_uri: None,
        }
    }

    // -----------------------------------------------------------------------
    // load_policy_from_str
    // -----------------------------------------------------------------------

    #[test]
    fn load_valid_policy() {
        let json = r#"{
            "version": 1,
            "includes": ["SKILLS*"],
            "publishers": [],
            "blocklist": { "digests": [] },
            "enforcement": "deny"
        }"#;
        let policy = load_policy_from_str(json).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.enforcement, Enforcement::Deny);
        assert_eq!(policy.includes.len(), 1);
    }

    #[test]
    fn load_policy_with_publishers() {
        let json = r#"{
            "version": 1,
            "includes": ["SKILLS*"],
            "publishers": [
                {
                    "name": "local",
                    "key_id": "nono-keystore:default"
                },
                {
                    "name": "ci",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "repository": "org/repo",
                    "workflow": "*",
                    "ref_pattern": "refs/tags/v*"
                }
            ],
            "blocklist": { "digests": [] },
            "enforcement": "warn"
        }"#;
        let policy = load_policy_from_str(json).unwrap();
        assert_eq!(policy.publishers.len(), 2);
        assert!(policy.publishers[0].is_keyed());
        assert!(policy.publishers[1].is_keyless());
        assert_eq!(policy.enforcement, Enforcement::Warn);
    }

    #[test]
    fn load_policy_invalid_json() {
        let result = load_policy_from_str("not json");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse trust policy"));
    }

    #[test]
    fn load_policy_missing_field() {
        let json = r#"{ "version": 1 }"#;
        let result = load_policy_from_str(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // load_policy_from_file
    // -----------------------------------------------------------------------

    #[test]
    fn load_policy_from_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-policy.json");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            write!(
                f,
                r#"{{
                    "version": 1,
                    "includes": ["AGENT.MD"],
                    "publishers": [],
                    "blocklist": {{ "digests": [] }},
                    "enforcement": "audit"
                }}"#
            )
            .unwrap();
        }
        let policy = load_policy_from_file(&path).unwrap();
        assert_eq!(policy.enforcement, Enforcement::Audit);
    }

    #[test]
    fn load_policy_from_file_not_found() {
        let result = load_policy_from_file("/nonexistent/trust-policy.json");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // merge_policies
    // -----------------------------------------------------------------------

    #[test]
    fn merge_empty_errors() {
        let result = merge_policies(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn merge_single_policy_unchanged() {
        let policy = make_policy(
            Enforcement::Warn,
            vec![keyed_publisher("dev", "key1")],
            vec![],
        );
        let merged = merge_policies(std::slice::from_ref(&policy)).unwrap();
        assert_eq!(merged.enforcement, Enforcement::Warn);
        assert_eq!(merged.publishers.len(), 1);
    }

    #[test]
    fn merge_unions_publishers() {
        let p1 = make_policy(
            Enforcement::Audit,
            vec![keyed_publisher("dev", "key1")],
            vec![],
        );
        let p2 = make_policy(
            Enforcement::Audit,
            vec![keyless_publisher("ci", "https://issuer", "org/repo")],
            vec![],
        );
        let merged = merge_policies(&[p1, p2]).unwrap();
        assert_eq!(merged.publishers.len(), 2);
    }

    #[test]
    fn merge_deduplicates_publishers_by_name() {
        let p1 = make_policy(
            Enforcement::Audit,
            vec![keyed_publisher("dev", "key1")],
            vec![],
        );
        let p2 = make_policy(
            Enforcement::Audit,
            vec![keyed_publisher("dev", "key2")], // same name, different key
            vec![],
        );
        let merged = merge_policies(&[p1, p2]).unwrap();
        assert_eq!(merged.publishers.len(), 1);
        // First occurrence wins
        assert_eq!(merged.publishers[0].key_id.as_deref(), Some("key1"));
    }

    #[test]
    fn merge_unions_blocklist_digests() {
        let entry1 = BlocklistEntry {
            sha256: "aaaa".to_string(),
            description: "bad1".to_string(),
            added: "2026-01-01".to_string(),
        };
        let entry2 = BlocklistEntry {
            sha256: "bbbb".to_string(),
            description: "bad2".to_string(),
            added: "2026-02-01".to_string(),
        };
        let p1 = make_policy(Enforcement::Audit, vec![], vec![entry1]);
        let p2 = make_policy(Enforcement::Audit, vec![], vec![entry2]);
        let merged = merge_policies(&[p1, p2]).unwrap();
        assert_eq!(merged.blocklist.digests.len(), 2);
    }

    #[test]
    fn merge_deduplicates_blocklist_by_digest() {
        let entry = BlocklistEntry {
            sha256: "aaaa".to_string(),
            description: "bad".to_string(),
            added: "2026-01-01".to_string(),
        };
        let p1 = make_policy(Enforcement::Audit, vec![], vec![entry.clone()]);
        let p2 = make_policy(Enforcement::Audit, vec![], vec![entry]);
        let merged = merge_policies(&[p1, p2]).unwrap();
        assert_eq!(merged.blocklist.digests.len(), 1);
    }

    #[test]
    fn merge_unions_includes() {
        let mut p1 = make_policy(Enforcement::Audit, vec![], vec![]);
        p1.includes = vec!["SKILLS*".to_string()];
        let mut p2 = make_policy(Enforcement::Audit, vec![], vec![]);
        p2.includes = vec!["AGENT.MD".to_string()];
        let merged = merge_policies(&[p1, p2]).unwrap();
        assert_eq!(merged.includes.len(), 2);
    }

    #[test]
    fn merge_deduplicates_patterns() {
        let p1 = make_policy(Enforcement::Audit, vec![], vec![]);
        let p2 = make_policy(Enforcement::Audit, vec![], vec![]);
        // Both have "SKILLS*" and "CLAUDE*"
        let merged = merge_policies(&[p1, p2]).unwrap();
        assert_eq!(merged.includes.len(), 2);
    }

    #[test]
    fn merge_strictest_enforcement_wins() {
        let p1 = make_policy(Enforcement::Audit, vec![], vec![]);
        let p2 = make_policy(Enforcement::Warn, vec![], vec![]);
        let p3 = make_policy(Enforcement::Deny, vec![], vec![]);
        let merged = merge_policies(&[p1, p2, p3]).unwrap();
        assert_eq!(merged.enforcement, Enforcement::Deny);
    }

    #[test]
    fn merge_project_cannot_weaken() {
        // User sets deny, project tries audit — deny wins
        let user = make_policy(Enforcement::Deny, vec![], vec![]);
        let project = make_policy(Enforcement::Audit, vec![], vec![]);
        let merged = merge_policies(&[user, project]).unwrap();
        assert_eq!(merged.enforcement, Enforcement::Deny);
    }

    #[test]
    fn merge_rejects_unsupported_version() {
        let p1 = make_policy(Enforcement::Audit, vec![], vec![]);
        let mut p2 = make_policy(Enforcement::Audit, vec![], vec![]);
        p2.version = 99;
        let result = merge_policies(&[p1, p2]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsupported trust policy version"));
    }

    // -----------------------------------------------------------------------
    // evaluate_file
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_blocked_file() {
        let entry = BlocklistEntry {
            sha256: "deadbeef".to_string(),
            description: "known malicious".to_string(),
            added: "2026-01-01".to_string(),
        };
        let policy = make_policy(Enforcement::Deny, vec![], vec![entry]);
        let result = evaluate_file(
            &policy,
            Path::new("SKILLS.md"),
            "deadbeef",
            Some(&SignerIdentity::Keyed {
                key_id: "key".to_string(),
            }),
        );
        assert!(matches!(
            result.outcome,
            VerificationOutcome::Blocked { .. }
        ));
    }

    #[test]
    fn evaluate_unsigned_file() {
        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let result = evaluate_file(&policy, Path::new("SKILLS.md"), "abcd1234", None);
        assert!(matches!(result.outcome, VerificationOutcome::Unsigned));
    }

    #[test]
    fn evaluate_trusted_keyed() {
        let policy = make_policy(
            Enforcement::Deny,
            vec![keyed_publisher("dev", "my-key")],
            vec![],
        );
        let identity = SignerIdentity::Keyed {
            key_id: "my-key".to_string(),
        };
        let result = evaluate_file(&policy, Path::new("SKILLS.md"), "abcd", Some(&identity));
        assert!(result.outcome.is_verified());
        if let VerificationOutcome::Verified { publisher } = &result.outcome {
            assert_eq!(publisher, "dev");
        }
    }

    #[test]
    fn evaluate_trusted_keyless() {
        let policy = make_policy(
            Enforcement::Deny,
            vec![keyless_publisher("ci", "https://issuer", "org/repo")],
            vec![],
        );
        let identity = SignerIdentity::Keyless {
            issuer: "https://issuer".to_string(),
            repository: "org/repo".to_string(),
            workflow: ".github/workflows/sign.yml".to_string(),
            git_ref: "refs/tags/v1.0.0".to_string(),
            build_signer_uri: "*".to_string(),
        };
        let result = evaluate_file(&policy, Path::new("CLAUDE.md"), "abcd", Some(&identity));
        assert!(result.outcome.is_verified());
    }

    #[test]
    fn evaluate_trusted_gitlab_keyless() {
        let publisher = Publisher {
            name: "gitlab-ci".to_string(),
            issuer: Some("https://gitlab.com".to_string()),
            repository: Some("my-group/my-project".to_string()),
            workflow: Some(
                "gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/*".to_string(),
            ),
            ref_pattern: Some("refs/heads/*".to_string()),
            key_id: None,
            public_key: None,
            build_signer_uri: None,
        };
        let policy = make_policy(Enforcement::Deny, vec![publisher], vec![]);
        let identity = SignerIdentity::Keyless {
            issuer: "https://gitlab.com".to_string(),
            repository: "my-group/my-project".to_string(),
            workflow: "gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main".to_string(),
            git_ref: "refs/heads/main".to_string(),
            build_signer_uri: "*".to_string(),
        };
        let result = evaluate_file(&policy, Path::new("SKILLS.md"), "abcd", Some(&identity));
        assert!(result.outcome.is_verified());
        if let VerificationOutcome::Verified { publisher } = &result.outcome {
            assert_eq!(publisher, "gitlab-ci");
        }
    }

    #[test]
    fn evaluate_trusted_gitlab_self_managed_keyless() {
        let publisher = Publisher {
            name: "gitlab-self-managed".to_string(),
            issuer: Some("https://gitlab.example.com".to_string()),
            repository: Some("internal/project".to_string()),
            workflow: Some(
                "gitlab.example.com/internal/project//.gitlab-ci.yml@refs/heads/*".to_string(),
            ),
            ref_pattern: Some("refs/heads/*".to_string()),
            key_id: None,
            public_key: None,
            build_signer_uri: None,
        };
        let policy = make_policy(Enforcement::Deny, vec![publisher], vec![]);
        let identity = SignerIdentity::Keyless {
            issuer: "https://gitlab.example.com".to_string(),
            repository: "internal/project".to_string(),
            workflow: "gitlab.example.com/internal/project//.gitlab-ci.yml@refs/heads/release"
                .to_string(),
            git_ref: "refs/heads/release".to_string(),
            build_signer_uri: "*".to_string(),
        };
        let result = evaluate_file(&policy, Path::new("CLAUDE.md"), "abcd", Some(&identity));
        assert!(result.outcome.is_verified());
        if let VerificationOutcome::Verified { publisher } = &result.outcome {
            assert_eq!(publisher, "gitlab-self-managed");
        }
    }

    #[test]
    fn evaluate_untrusted_gitlab_wrong_project() {
        let publisher = Publisher {
            name: "gitlab-ci".to_string(),
            issuer: Some("https://gitlab.example.com".to_string()),
            repository: Some("trusted/project".to_string()),
            workflow: Some(
                "gitlab.example.com/trusted/project//.gitlab-ci.yml@refs/heads/*".to_string(),
            ),
            ref_pattern: Some("refs/heads/*".to_string()),
            key_id: None,
            public_key: None,
            build_signer_uri: None,
        };
        let policy = make_policy(Enforcement::Deny, vec![publisher], vec![]);
        let identity = SignerIdentity::Keyless {
            issuer: "https://gitlab.example.com".to_string(),
            repository: "evil/project".to_string(),
            workflow: "gitlab.example.com/evil/project//.gitlab-ci.yml@refs/heads/main".to_string(),
            git_ref: "refs/heads/main".to_string(),
            build_signer_uri: "*".to_string(),
        };
        let result = evaluate_file(&policy, Path::new("SKILLS.md"), "abcd", Some(&identity));
        assert!(matches!(
            result.outcome,
            VerificationOutcome::UntrustedPublisher { .. }
        ));
    }

    #[test]
    fn evaluate_untrusted_publisher() {
        let policy = make_policy(
            Enforcement::Deny,
            vec![keyed_publisher("dev", "my-key")],
            vec![],
        );
        let identity = SignerIdentity::Keyed {
            key_id: "unknown-key".to_string(),
        };
        let result = evaluate_file(&policy, Path::new("SKILLS.md"), "abcd", Some(&identity));
        assert!(matches!(
            result.outcome,
            VerificationOutcome::UntrustedPublisher { .. }
        ));
    }

    #[test]
    fn evaluate_blocked_publisher() {
        let mut policy = make_policy(
            Enforcement::Deny,
            vec![keyless_publisher("ci", "https://evil.issuer", "evil/repo")],
            vec![],
        );
        policy.blocklist.publishers.push(BlockedPublisher {
            identity: "https://evil.issuer".to_string(),
            repository: None,
            reason: "compromised".to_string(),
            added: "2026-01-01".to_string(),
        });
        let identity = SignerIdentity::Keyless {
            issuer: "https://evil.issuer".to_string(),
            repository: "evil/repo".to_string(),
            workflow: "*".to_string(),
            git_ref: "*".to_string(),
            build_signer_uri: "*".to_string(),
        };
        let result = evaluate_file(&policy, Path::new("SKILLS.md"), "abcd", Some(&identity));
        assert!(matches!(
            result.outcome,
            VerificationOutcome::UntrustedPublisher { .. }
        ));
    }

    #[test]
    fn evaluate_blocked_publisher_by_repository() {
        let mut policy = make_policy(
            Enforcement::Deny,
            vec![
                keyless_publisher(
                    "ci",
                    "https://token.actions.githubusercontent.com",
                    "good/repo",
                ),
                keyless_publisher(
                    "ci2",
                    "https://token.actions.githubusercontent.com",
                    "evil/repo",
                ),
            ],
            vec![],
        );
        policy.blocklist.publishers.push(BlockedPublisher {
            identity: "https://token.actions.githubusercontent.com".to_string(),
            repository: Some("evil/repo".to_string()),
            reason: "compromised repo".to_string(),
            added: "2026-01-01".to_string(),
        });

        // evil/repo should be blocked
        let evil_identity = SignerIdentity::Keyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            repository: "evil/repo".to_string(),
            workflow: "*".to_string(),
            git_ref: "*".to_string(),
            build_signer_uri: "*".to_string(),
        };
        let result = evaluate_file(
            &policy,
            Path::new("SKILLS.md"),
            "abcd",
            Some(&evil_identity),
        );
        assert!(matches!(
            result.outcome,
            VerificationOutcome::UntrustedPublisher { .. }
        ));

        // good/repo should NOT be blocked
        let good_identity = SignerIdentity::Keyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            repository: "good/repo".to_string(),
            workflow: "*".to_string(),
            git_ref: "*".to_string(),
            build_signer_uri: "*".to_string(),
        };
        let result = evaluate_file(
            &policy,
            Path::new("SKILLS.md"),
            "abcd",
            Some(&good_identity),
        );
        assert!(matches!(
            result.outcome,
            VerificationOutcome::Verified { .. }
        ));
    }

    #[test]
    fn evaluate_blocklist_checked_before_signer() {
        // Even with a valid signer, blocklist entry should win
        let entry = BlocklistEntry {
            sha256: "baddigest".to_string(),
            description: "malicious".to_string(),
            added: "2026-01-01".to_string(),
        };
        let policy = make_policy(
            Enforcement::Deny,
            vec![keyed_publisher("dev", "my-key")],
            vec![entry],
        );
        let identity = SignerIdentity::Keyed {
            key_id: "my-key".to_string(),
        };
        let result = evaluate_file(
            &policy,
            Path::new("SKILLS.md"),
            "baddigest",
            Some(&identity),
        );
        assert!(matches!(
            result.outcome,
            VerificationOutcome::Blocked { .. }
        ));
    }

    #[test]
    fn evaluate_result_contains_path_and_digest() {
        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let result = evaluate_file(&policy, Path::new("AGENT.MD"), "digest123", None);
        assert_eq!(result.path, Path::new("AGENT.MD"));
        assert_eq!(result.digest, "digest123");
    }

    // -----------------------------------------------------------------------
    // find_included_files
    // -----------------------------------------------------------------------

    #[test]
    fn find_included_files_in_directory() {
        let dir = tempfile::tempdir().unwrap();
        // Create matching files
        std::fs::write(dir.path().join("SKILLS.md"), "content").unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "content").unwrap();
        // Create non-matching files
        std::fs::write(dir.path().join("README.md"), "content").unwrap();
        std::fs::write(dir.path().join("main.rs"), "content").unwrap();

        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let files = find_included_files(&policy, dir.path()).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn find_included_files_in_claude_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude").join("commands");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("deploy.md"), "content").unwrap();

        let mut policy = make_policy(Enforcement::Deny, vec![], vec![]);
        policy.includes.push(".claude/**/*.md".to_string());

        let files = find_included_files(&policy, dir.path()).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn find_included_files_skips_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        let hidden = dir.path().join(".git");
        std::fs::create_dir_all(&hidden).unwrap();
        std::fs::write(hidden.join("SKILLS.md"), "content").unwrap();

        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let files = find_included_files(&policy, dir.path()).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn find_included_files_in_non_special_hidden_dir() {
        let dir = tempfile::tempdir().unwrap();
        let hidden = dir.path().join(".hidden").join("commands");
        std::fs::create_dir_all(&hidden).unwrap();
        std::fs::write(hidden.join("deploy.md"), "content").unwrap();

        let mut policy = make_policy(Enforcement::Deny, vec![], vec![]);
        policy.includes.push(".hidden/**/*.md".to_string());

        let files = find_included_files(&policy, dir.path()).unwrap();
        assert_eq!(files, vec![hidden.join("deploy.md")]);
    }

    #[test]
    fn find_included_files_skips_well_known_heavy_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        std::fs::create_dir_all(&node_modules).unwrap();
        std::fs::write(node_modules.join("SKILLS.md"), "content").unwrap();
        std::fs::write(dir.path().join("SKILLS.md"), "content").unwrap();

        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let files = find_included_files(&policy, dir.path()).unwrap();

        assert_eq!(files, vec![dir.path().join("SKILLS.md")]);
    }

    #[test]
    fn find_included_files_respects_extra_skip_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let generated = dir.path().join("generated");
        std::fs::create_dir_all(&generated).unwrap();
        std::fs::write(generated.join("SKILLS.md"), "content").unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "content").unwrap();

        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let files =
            find_included_files_with_skip_dirs(&policy, dir.path(), &[String::from("generated")])
                .unwrap();

        assert_eq!(files, vec![dir.path().join("CLAUDE.md")]);
    }

    #[test]
    fn find_included_files_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let files = find_included_files(&policy, dir.path()).unwrap();
        assert!(files.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn find_included_files_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_skills.md");
        std::fs::write(&target, "content").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("SKILLS.md")).unwrap();

        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let files = find_included_files(&policy, dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].to_string_lossy().contains("SKILLS.md"));
    }

    #[test]
    fn find_included_files_skips_bundle_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILLS.md"), "content").unwrap();
        std::fs::write(dir.path().join("SKILLS.md.bundle"), "{}").unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "content").unwrap();
        std::fs::write(dir.path().join("CLAUDE.md.bundle"), "{}").unwrap();

        let policy = make_policy(Enforcement::Deny, vec![], vec![]);
        let files = find_included_files(&policy, dir.path()).unwrap();

        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .all(|path| !path.to_string_lossy().ends_with(".bundle"))
        );
    }
}
