//! Exclusion filtering for snapshot file walking
//!
//! Provides the mechanism for excluding files from snapshots. The library
//! supplies `.gitignore` integration and pattern matching; clients supply
//! the actual exclusion patterns (what counts as "generated", "transient",
//! or "large" is a policy decision).

use crate::error::{NonoError, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;

/// Configuration for the exclusion filter.
///
/// All exclusion patterns are supplied by the client. The library provides
/// only the matching mechanism (component-level, path-contains, glob, and
/// `.gitignore` integration).
#[derive(Debug, Clone)]
pub struct ExclusionConfig {
    /// Whether to respect .gitignore files
    pub use_gitignore: bool,
    /// Patterns to exclude. Each pattern is matched against individual
    /// path components (exact match) or, if it contains `/`, against
    /// the full path (substring match).
    pub exclude_patterns: Vec<String>,
    /// Glob patterns to exclude. Each pattern is matched against the
    /// filename (last path component) using standard glob syntax
    /// (`*`, `?`, `[0-9]`, etc.).
    pub exclude_globs: Vec<String>,
    /// Glob patterns that override all exclusions (force-include)
    pub force_include: Vec<String>,
}

impl Default for ExclusionConfig {
    fn default() -> Self {
        Self {
            use_gitignore: true,
            exclude_patterns: Vec::new(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        }
    }
}

/// Filter that determines which files to exclude from snapshots.
///
/// Evaluation order:
/// 1. Force-include patterns override all other exclusions
/// 2. Client-supplied exclusion patterns (component/substring match)
/// 3. Client-supplied glob patterns (filename match)
/// 4. `.gitignore` rules (if enabled)
#[derive(Clone)]
pub struct ExclusionFilter {
    gitignore: Option<Gitignore>,
    exclude_patterns: Vec<String>,
    exclude_globs: Option<GlobSet>,
    force_include: Vec<String>,
}

impl ExclusionFilter {
    /// Create a new exclusion filter for the given root directory.
    ///
    /// If `use_gitignore` is true, looks for `.gitignore` in the root.
    /// Glob patterns in `exclude_globs` are compiled into a `GlobSet`.
    pub fn new(config: ExclusionConfig, root: &Path) -> Result<Self> {
        let gitignore = if config.use_gitignore {
            let gitignore_path = root.join(".gitignore");
            if gitignore_path.exists() {
                let mut builder = GitignoreBuilder::new(root);
                builder.add(&gitignore_path);
                match builder.build() {
                    Ok(gi) => Some(gi),
                    Err(e) => {
                        tracing::warn!("Failed to parse .gitignore: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let exclude_globs =
            if config.exclude_globs.is_empty() {
                None
            } else {
                let mut builder = GlobSetBuilder::new();
                for pattern in &config.exclude_globs {
                    let glob = Glob::new(pattern).map_err(|e| {
                        NonoError::ConfigParse(format!("Invalid glob pattern '{}': {}", pattern, e))
                    })?;
                    builder.add(glob);
                }
                Some(builder.build().map_err(|e| {
                    NonoError::ConfigParse(format!("Failed to build glob set: {}", e))
                })?)
            };

        Ok(Self {
            gitignore,
            exclude_patterns: config.exclude_patterns,
            exclude_globs,
            force_include: config.force_include,
        })
    }

    /// Check whether a path should be excluded from snapshotting.
    #[must_use]
    pub fn is_excluded(&self, path: &Path) -> bool {
        // Force-include overrides all exclusions
        if self.matches_force_include(path) {
            return false;
        }

        // Check client-supplied patterns
        if self.matches_exclude_patterns(path) {
            return true;
        }

        // Check glob patterns against the filename
        if self.matches_exclude_globs(path) {
            return true;
        }

        // Check gitignore
        if let Some(ref gi) = self.gitignore {
            let is_dir = path.is_dir();
            if gi.matched(path, is_dir).is_ignore() {
                return true;
            }
        }

        false
    }

    /// Check if any path component matches a client-supplied exclusion pattern.
    ///
    /// Patterns containing `/` are matched as substrings of the full path.
    /// All other patterns are matched as exact component names.
    fn matches_exclude_patterns(&self, path: &Path) -> bool {
        for pattern in &self.exclude_patterns {
            if pattern.contains('/') {
                // Multi-component pattern: substring match on full path
                let path_str = path.to_string_lossy();
                if path_str.contains(pattern.as_str()) {
                    return true;
                }
            } else {
                // Single component: exact match against each path component
                for component in path.components() {
                    if let std::path::Component::Normal(name) = component
                        && name.to_string_lossy() == *pattern
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if the filename matches any client-supplied glob pattern.
    fn matches_exclude_globs(&self, path: &Path) -> bool {
        if let Some(ref globs) = self.exclude_globs
            && let Some(filename) = path.file_name()
        {
            return globs.is_match(filename);
        }
        false
    }

    /// Check if path matches any force-include pattern.
    ///
    /// Uses the same matching logic as `matches_exclude_patterns`:
    /// patterns containing `/` are matched as substrings of the full path,
    /// all other patterns are matched as exact component names.
    fn matches_force_include(&self, path: &Path) -> bool {
        for pattern in &self.force_include {
            if pattern.contains('/') {
                let path_str = path.to_string_lossy();
                if path_str.contains(pattern.as_str()) {
                    return true;
                }
            } else {
                for component in path.components() {
                    if let std::path::Component::Normal(name) = component
                        && name.to_string_lossy() == *pattern
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn make_filter(patterns: Vec<&str>) -> ExclusionFilter {
        let dir = TempDir::new().expect("tempdir");
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: patterns.into_iter().map(String::from).collect(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        ExclusionFilter::new(config, dir.path()).expect("filter")
    }

    #[test]
    fn component_pattern_matches() {
        let filter = make_filter(vec!["node_modules", ".DS_Store"]);
        assert!(filter.is_excluded(&PathBuf::from("/project/node_modules/pkg/index.js")));
        assert!(filter.is_excluded(&PathBuf::from("/project/.DS_Store")));
    }

    #[test]
    fn slash_pattern_matches_as_substring() {
        let filter = make_filter(vec![".git/objects"]);
        assert!(filter.is_excluded(&PathBuf::from("/project/.git/objects/ab/cdef")));
        assert!(!filter.is_excluded(&PathBuf::from("/project/.git/config")));
    }

    #[test]
    fn normal_files_not_excluded() {
        let filter = make_filter(vec!["node_modules", "target"]);
        assert!(!filter.is_excluded(&PathBuf::from("/project/src/main.rs")));
        assert!(!filter.is_excluded(&PathBuf::from("/project/README.md")));
    }

    #[test]
    fn empty_patterns_excludes_nothing() {
        let filter = make_filter(vec![]);
        assert!(!filter.is_excluded(&PathBuf::from("/project/node_modules/pkg")));
        assert!(!filter.is_excluded(&PathBuf::from("/project/.DS_Store")));
    }

    #[test]
    fn force_include_overrides_patterns() {
        let dir = TempDir::new().expect("tempdir");
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: vec!["node_modules".to_string()],
            exclude_globs: Vec::new(),
            force_include: vec!["important_modules".to_string()],
        };
        let filter = ExclusionFilter::new(config, dir.path()).expect("filter");
        assert!(!filter.is_excluded(&PathBuf::from(
            "/project/important_modules/node_modules/pkg"
        )));
    }

    #[test]
    fn glob_pattern_matches_filename() {
        let dir = TempDir::new().expect("tempdir");
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: Vec::new(),
            exclude_globs: vec!["*.tmp.[0-9]*.[0-9]*".to_string()],
            force_include: Vec::new(),
        };
        let filter = ExclusionFilter::new(config, dir.path()).expect("filter");

        // Atomic write temp files should be excluded
        assert!(filter.is_excluded(&PathBuf::from("/project/README.md.tmp.48846.1771084621260")));
        assert!(filter.is_excluded(&PathBuf::from("/project/src/main.rs.tmp.12345.9876543210")));

        // Normal files should not be excluded
        assert!(!filter.is_excluded(&PathBuf::from("/project/README.md")));
        assert!(!filter.is_excluded(&PathBuf::from("/project/file.tmp")));
        // Non-numeric segments should not match
        assert!(!filter.is_excluded(&PathBuf::from("/project/file.tmp.backup.old")));
    }

    #[test]
    fn force_include_matches_path_component() {
        let dir = TempDir::new().expect("tempdir");
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: vec!["node_modules".to_string()],
            exclude_globs: Vec::new(),
            force_include: vec!["node_modules".to_string()],
        };
        let filter = ExclusionFilter::new(config, dir.path()).expect("filter");

        // Force-include should match the exact component
        assert!(!filter.is_excluded(&PathBuf::from("/project/node_modules/pkg/index.js")));
    }

    #[test]
    fn force_include_rejects_substring_match() {
        let dir = TempDir::new().expect("tempdir");
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: vec!["myapp".to_string()],
            exclude_globs: Vec::new(),
            // "app" should NOT match the component "myapp"
            force_include: vec!["app".to_string()],
        };
        let filter = ExclusionFilter::new(config, dir.path()).expect("filter");

        // "app" as force_include must not match "myapp" component
        assert!(filter.is_excluded(&PathBuf::from("/project/myapp/src/main.rs")));
    }

    #[test]
    fn gitignore_integration() {
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join(".gitignore"), "*.log\nbuild/\n").expect("write gitignore");
        // Create build/ so is_dir() returns true (gitignore "build/" only matches directories)
        std::fs::create_dir(dir.path().join("build")).expect("create build dir");

        let config = ExclusionConfig {
            use_gitignore: true,
            exclude_patterns: Vec::new(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        let filter = ExclusionFilter::new(config, dir.path()).expect("filter");
        assert!(filter.is_excluded(&dir.path().join("app.log")));
        assert!(filter.is_excluded(&dir.path().join("build")));
    }
}
