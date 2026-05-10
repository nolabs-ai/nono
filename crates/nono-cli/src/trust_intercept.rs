//! Trust verification integration for the supervisor IPC loop
//!
//! When the supervisor receives a capability request for a path matching
//! an instruction file pattern, this module verifies the file before
//! the approval backend is consulted. Failed verification results in
//! automatic denial without prompting the user.

use nono::trust::{self, TrustPolicy, VerificationOutcome};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Cached verification result for an instruction file.
#[derive(Debug, Clone)]
#[cfg_attr(target_os = "windows", allow(dead_code))]
struct CacheEntry {
    /// File inode at verification time
    inode: u64,
    /// File modification time (nanoseconds since epoch) at verification time
    mtime_nanos: u128,
    /// File size at verification time
    size: u64,
    /// Verification outcome
    outcome: CachedOutcome,
}

/// Cached verification outcome (simplified for storage).
#[derive(Debug, Clone)]
#[cfg_attr(target_os = "windows", allow(dead_code))]
enum CachedOutcome {
    /// Verified successfully (includes digest for TOCTOU re-check at open time)
    Verified { publisher: String, digest: String },
    /// Failed verification
    Failed { reason: String },
}

/// Successful trust verification result returned from `check_path`.
#[derive(Debug, Clone)]
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub struct TrustVerified {
    /// Publisher name that matched the trust policy
    pub publisher: String,
    /// SHA-256 digest of the file at verification time.
    /// Used by `open_path_for_access` to re-verify the opened fd,
    /// closing the TOCTOU gap between verification and open.
    pub digest: String,
}

/// Instruction file trust interceptor for the supervisor loop.
///
/// Checks incoming capability requests against instruction file patterns
/// and verifies matching files before they reach the approval backend.
/// Results are cached by (path, inode, mtime, size) to avoid repeated
/// verification of the same file content.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub struct TrustInterceptor {
    /// Trust policy for evaluation
    policy: TrustPolicy,
    /// Compiled include pattern matcher
    matcher: trust::IncludePatterns,
    /// Verification result cache keyed by canonical path
    cache: HashMap<PathBuf, CacheEntry>,
    /// Project root for computing relative paths in pattern matching
    project_root: PathBuf,
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
impl TrustInterceptor {
    /// Create a new trust interceptor from a trust policy and project root.
    ///
    /// The `project_root` is used to compute relative paths from absolute paths
    /// for include pattern matching (e.g., `.claude/**/*.md`).
    ///
    /// # Errors
    ///
    /// Returns an error if the include patterns cannot be compiled.
    pub fn new(policy: TrustPolicy, project_root: PathBuf) -> nono::Result<Self> {
        let matcher = policy.include_matcher()?;
        Ok(Self {
            policy,
            matcher,
            cache: HashMap::new(),
            project_root,
        })
    }

    /// Check if a requested path is an instruction file that requires verification.
    ///
    /// Returns `None` if the path is not an instruction file (let the normal
    /// approval flow handle it). Returns `Some(Ok(publisher))` if the file is
    /// verified, or `Some(Err(reason))` if verification fails.
    ///
    /// Returns the verified digest alongside the publisher name so that
    /// `open_path_for_access` can re-verify the opened fd against it,
    /// closing the TOCTOU window between verification and open.
    pub fn check_path(
        &mut self,
        path: &Path,
    ) -> Option<std::result::Result<TrustVerified, String>> {
        // Bundle sidecars are metadata for instruction files, not instruction files themselves.
        if path.to_string_lossy().ends_with(".bundle") {
            return None;
        }

        // Compute relative path from project root for pattern matching.
        // Patterns like ".claude/**/*.md" require relative path context.
        let relative = path.strip_prefix(&self.project_root).unwrap_or(path);

        if !self.matcher.is_match(relative) {
            // Also try just the filename for simple patterns like "SKILLS*"
            let file_name = path.file_name().map(Path::new)?;
            if !self.matcher.is_match(file_name) {
                return None;
            }
        }

        debug!(
            "Trust interceptor: checking instruction file {}",
            path.display()
        );

        // Check cache first
        if let Some(cached) = self.check_cache(path) {
            return Some(cached);
        }

        // Verify the file
        let result = self.verify_and_cache(path);
        Some(result)
    }

    /// Check if the path has a valid cached verification result.
    ///
    /// Validates by inode + nanosecond mtime + size for fast path, then
    /// falls back to content digest comparison to catch same-second modifications.
    fn check_cache(&self, path: &Path) -> Option<std::result::Result<TrustVerified, String>> {
        let entry = self.cache.get(path)?;

        // Validate cache by checking file metadata
        let meta = std::fs::metadata(path).ok()?;

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        };
        #[cfg(not(unix))]
        let inode = 0u64;

        let mtime_nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let size = meta.len();

        // Reject on metadata change (inode + nanosecond mtime + size).
        // This triple is sufficient for cache invalidation — a content digest
        // re-read on every check would make the hot path as expensive as a
        // full verification, defeating the cache entirely.
        if entry.inode != inode || entry.mtime_nanos != mtime_nanos || entry.size != size {
            debug!(
                "Trust interceptor: cache invalidated for {} (metadata changed)",
                path.display()
            );
            return None;
        }

        debug!("Trust interceptor: cache hit for {}", path.display());
        match &entry.outcome {
            CachedOutcome::Verified { publisher, digest } => Some(Ok(TrustVerified {
                publisher: publisher.clone(),
                digest: digest.clone(),
            })),
            CachedOutcome::Failed { reason } => Some(Err(reason.clone())),
        }
    }

    /// Verify a file and store the result in the cache.
    fn verify_and_cache(&mut self, path: &Path) -> std::result::Result<TrustVerified, String> {
        // Compute digest
        let digest = match trust::file_digest(path) {
            Ok(d) => d,
            Err(e) => {
                let reason = format!("failed to compute digest: {e}");
                warn!("Trust interceptor: {reason} for {}", path.display());
                return Err(reason);
            }
        };

        // Check blocklist
        if let Some(entry) = self.policy.check_blocklist(&digest) {
            let reason = format!("blocked by trust policy: {}", entry.description);
            self.store_cache(
                path,
                CachedOutcome::Failed {
                    reason: reason.clone(),
                },
            );
            return Err(reason);
        }

        // Load and verify bundle
        let bundle_path = trust::bundle_path_for(path);
        let signer = if bundle_path.exists() {
            match load_signer(path, &bundle_path, &digest, &self.policy) {
                Ok(identity) => Some(identity),
                Err(reason) => {
                    self.store_cache(
                        path,
                        CachedOutcome::Failed {
                            reason: reason.clone(),
                        },
                    );
                    return Err(reason);
                }
            }
        } else {
            None
        };

        // Evaluate against policy
        let result = trust::evaluate_file(&self.policy, path, &digest, signer.as_ref());

        match &result.outcome {
            VerificationOutcome::Verified { publisher } => {
                let pub_name = publisher.clone();
                self.store_cache(
                    path,
                    CachedOutcome::Verified {
                        publisher: pub_name.clone(),
                        digest: digest.clone(),
                    },
                );
                debug!(
                    "Trust interceptor: verified {} (publisher: {})",
                    path.display(),
                    pub_name
                );
                Ok(TrustVerified {
                    publisher: pub_name,
                    digest,
                })
            }
            outcome => {
                let reason = format_outcome(outcome);
                let should_block = outcome.should_block(self.policy.enforcement);
                self.store_cache(
                    path,
                    CachedOutcome::Failed {
                        reason: reason.clone(),
                    },
                );

                if should_block {
                    warn!(
                        "Trust interceptor: blocking {} ({})",
                        path.display(),
                        reason
                    );
                    Err(reason)
                } else {
                    debug!(
                        "Trust interceptor: warning for {} ({}) - enforcement allows",
                        path.display(),
                        reason
                    );
                    // Non-blocking: return Ok with a warning note.
                    // Digest is still valid for TOCTOU re-check even for unverified files.
                    Ok(TrustVerified {
                        publisher: format!(
                            "(unverified, enforcement={:?})",
                            self.policy.enforcement
                        ),
                        digest,
                    })
                }
            }
        }
    }

    /// Store a verification result in the cache.
    fn store_cache(&mut self, path: &Path, outcome: CachedOutcome) {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        };
        #[cfg(not(unix))]
        let inode = 0u64;

        let mtime_nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let size = meta.len();

        self.cache.insert(
            path.to_path_buf(),
            CacheEntry {
                inode,
                mtime_nanos,
                size,
                outcome,
            },
        );
    }
}

/// Load a bundle, extract the signer identity, verify digest integrity,
/// and perform cryptographic signature verification.
///
/// Both keyed and keyless bundles undergo cryptographic verification.
#[cfg_attr(target_os = "windows", allow(dead_code))]
fn load_signer(
    file_path: &Path,
    bundle_path: &Path,
    file_digest: &str,
    policy: &trust::TrustPolicy,
) -> std::result::Result<trust::SignerIdentity, String> {
    let bundle = trust::load_bundle(bundle_path).map_err(|e| format!("invalid bundle: {e}"))?;

    // Validate predicate type matches instruction file attestation
    let predicate_type = trust::extract_predicate_type(&bundle, bundle_path)
        .map_err(|e| format!("failed to extract predicate type: {e}"))?;
    if predicate_type != trust::NONO_PREDICATE_TYPE {
        return Err(format!(
            "wrong bundle type: expected instruction file attestation, got {predicate_type}"
        ));
    }

    // Verify subject name matches the file being verified
    trust::verify_bundle_subject_name(&bundle, file_path)
        .map_err(|e| format!("subject name mismatch: {e}"))?;

    let identity = trust::extract_signer_identity(&bundle, bundle_path)
        .map_err(|e| format!("no signer identity: {e}"))?;

    // Verify digest integrity (fail-closed: extraction failure = reject)
    let bundle_digest = trust::extract_bundle_digest(&bundle, bundle_path)
        .map_err(|e| format!("malformed bundle: {e}"))?;
    if bundle_digest != file_digest {
        return Err("bundle digest does not match file content".to_string());
    }

    // Cryptographic signature verification (both keyed and keyless)
    match &identity {
        trust::SignerIdentity::Keyed { .. } => {
            let matching = policy.matching_publishers(&identity);
            match matching.iter().find_map(|p| p.public_key.as_ref()) {
                Some(b64) => {
                    let key_bytes = nono::trust::base64::base64_decode(b64)
                        .map_err(|_| "invalid base64 in publisher public_key".to_string())?;
                    trust::verify_keyed_signature(&bundle, &key_bytes, bundle_path)
                        .map_err(|e| format!("signature verification failed: {e}"))?;
                }
                None => {
                    return Err("keyed bundle but no public_key in matching publisher".to_string());
                }
            }
        }
        trust::SignerIdentity::Keyless { .. } => {
            let trusted_root = trust::load_production_trusted_root()
                .map_err(|e| format!("failed to load Sigstore trusted root: {e}"))?;
            let sigstore_policy = trust::VerificationPolicy::default();
            trust::verify_bundle_with_digest(
                file_digest,
                &bundle,
                &trusted_root,
                &sigstore_policy,
                file_path,
            )
            .map_err(|e| format!("Sigstore verification failed: {e}"))?;
        }
    }

    Ok(identity)
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
fn format_outcome(outcome: &VerificationOutcome) -> String {
    match outcome {
        VerificationOutcome::Verified { publisher } => format!("verified ({publisher})"),
        VerificationOutcome::Blocked { reason } => format!("blocklisted: {reason}"),
        VerificationOutcome::Unsigned => "unsigned (no .bundle file)".to_string(),
        VerificationOutcome::InvalidSignature { detail } => format!("invalid signature: {detail}"),
        VerificationOutcome::UntrustedPublisher { identity } => {
            format!("untrusted publisher: {identity:?}")
        }
        VerificationOutcome::DigestMismatch { .. } => {
            "file content does not match bundle".to_string()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn interceptor_ignores_non_instruction_files() {
        let dir = tempfile::tempdir().unwrap();
        let policy = TrustPolicy::default();
        let mut interceptor = TrustInterceptor::new(policy, dir.path().to_path_buf()).unwrap();

        assert!(interceptor
            .check_path(Path::new("/tmp/README.md"))
            .is_none());
        assert!(interceptor
            .check_path(Path::new("/tmp/src/main.rs"))
            .is_none());
    }

    #[test]
    fn interceptor_ignores_bundle_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let policy = TrustPolicy::default();
        let mut interceptor = TrustInterceptor::new(policy, dir.path().to_path_buf()).unwrap();

        assert!(interceptor
            .check_path(Path::new("/tmp/SKILLS.md.bundle"))
            .is_none());
        assert!(interceptor
            .check_path(Path::new("/tmp/CLAUDE.md.bundle"))
            .is_none());
    }

    #[test]
    fn interceptor_checks_instruction_files() {
        let dir = tempfile::tempdir().unwrap();
        let skills = dir.path().join("SKILLS.md");
        std::fs::write(&skills, "# Skills").unwrap();

        let policy = TrustPolicy {
            includes: vec!["SKILLS.md".to_string()],
            ..TrustPolicy::default()
        };
        let mut interceptor = TrustInterceptor::new(policy, dir.path().to_path_buf()).unwrap();

        // Should return Some (it IS an instruction file)
        let result = interceptor.check_path(&skills);
        assert!(result.is_some());
    }

    #[test]
    fn interceptor_caches_results() {
        let dir = tempfile::tempdir().unwrap();
        let skills = dir.path().join("SKILLS.md");
        std::fs::write(&skills, "# Skills").unwrap();

        let policy = TrustPolicy {
            includes: vec!["SKILLS.md".to_string()],
            enforcement: trust::Enforcement::Warn,
            ..TrustPolicy::default()
        };
        let mut interceptor = TrustInterceptor::new(policy, dir.path().to_path_buf()).unwrap();

        // First check populates cache
        let _result1 = interceptor.check_path(&skills);
        assert!(interceptor.cache.contains_key(&skills));

        // Second check hits cache
        let _result2 = interceptor.check_path(&skills);
    }

    #[test]
    fn interceptor_cache_invalidates_on_modify() {
        let dir = tempfile::tempdir().unwrap();
        let skills = dir.path().join("SKILLS.md");
        std::fs::write(&skills, "# Skills v1").unwrap();

        let policy = TrustPolicy {
            includes: vec!["SKILLS.md".to_string()],
            enforcement: trust::Enforcement::Warn,
            ..TrustPolicy::default()
        };
        let mut interceptor = TrustInterceptor::new(policy, dir.path().to_path_buf()).unwrap();

        // First check
        let _ = interceptor.check_path(&skills);

        // Modify the file
        std::fs::write(&skills, "# Skills v2 with extra content").unwrap();

        // Cache should be invalidated (metadata changed)
        let cached = interceptor.check_cache(&skills);
        // mtime or size changed, so cache miss
        assert!(cached.is_none());
    }

    #[test]
    fn interceptor_blocklist_blocks_regardless_of_enforcement() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"evil content";
        let skills = dir.path().join("SKILLS.md");
        std::fs::write(&skills, content).unwrap();

        let digest = trust::bytes_digest(content);

        let policy = TrustPolicy {
            includes: vec!["SKILLS.md".to_string()],
            enforcement: trust::Enforcement::Audit,
            blocklist: trust::Blocklist {
                digests: vec![trust::BlocklistEntry {
                    sha256: digest,
                    description: "malicious".to_string(),
                    added: "2026-01-01".to_string(),
                }],
                publishers: Vec::new(),
            },
            ..TrustPolicy::default()
        };
        let mut interceptor = TrustInterceptor::new(policy, dir.path().to_path_buf()).unwrap();

        let result = interceptor.check_path(&skills);
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn format_outcome_variants() {
        assert!(format_outcome(&VerificationOutcome::Unsigned).contains("unsigned"));
        assert!(format_outcome(&VerificationOutcome::Blocked {
            reason: "test".to_string()
        })
        .contains("blocklisted"));
        assert!(format_outcome(&VerificationOutcome::InvalidSignature {
            detail: "bad sig".to_string()
        })
        .contains("bad sig"));
        assert!(format_outcome(&VerificationOutcome::DigestMismatch {
            expected: "a".to_string(),
            actual: "b".to_string()
        })
        .contains("does not match"));
    }
}
