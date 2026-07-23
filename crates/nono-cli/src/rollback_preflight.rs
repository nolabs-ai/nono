//! Rollback preflight: detect large unexcluded directories before baseline creation.
//!
//! Detection uses two strategies:
//! 1. **Name-based** — immediate children matching known heavy names (.git, target, etc.)
//! 2. **Size-based** — any immediate-child directory exceeding 10,000 files
//!
//! After detection, a bounded walk estimates total scope for the notice message.
//!
//! The preflight is advisory. The library walk budget (Layer 2) provides the hard
//! enforcement at walk time.

use nono::undo::ExclusionFilter;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Well-known directory names that are typically very large and fully regenerable.
const KNOWN_HEAVY_DIRS: &[(&str, &str)] = &[
    (".git", "VCS internals"),
    ("target", "build artifacts"),
    ("node_modules", "dependencies"),
    ("__pycache__", "Python bytecode cache"),
    (".venv", "Python virtual environment"),
    (".tox", "tox environments"),
    ("dist", "distribution artifacts"),
    ("build", "build output"),
    (".next", "Next.js build"),
    (".nuxt", "Nuxt.js build"),
    (".gradle", "Gradle cache"),
    (".cache", "cache directory"),
];

/// File count threshold for size-based auto-exclusion of unknown directories.
const SIZE_THRESHOLD: usize = 10_000;

/// Maximum wall-clock time to spend counting files in a single directory.
const SIZE_CHECK_TIME_CAP: Duration = Duration::from_secs(1);

/// Maximum total wall-clock time for all size-based directory checks combined.
/// Prevents unbounded latency when a project has many immediate subdirectories.
const SIZE_CHECK_TOTAL_CAP: Duration = Duration::from_secs(5);

/// Maximum entries to visit during bounded walk (Phase 2).
const PROBE_ENTRY_CAP: usize = 5_000;

/// Maximum wall-clock time for bounded walk (Phase 2).
const PROBE_TIME_CAP: Duration = Duration::from_secs(2);

/// Result of the preflight scan.
pub(crate) struct PreflightResult {
    /// Heavy directories found that are NOT covered by the exclusion filter.
    pub heavy_dirs: Vec<HeavyDir>,
    /// Lower-bound file count from bounded walk (only populated if heavy dirs found).
    pub probe_file_count: usize,
    /// Whether the probe was capped before completion.
    pub probe_capped: bool,
    /// Wall-clock time of the probe.
    pub probe_duration: Duration,
}

/// A detected heavy directory.
pub(crate) struct HeavyDir {
    /// Full path to the directory.
    pub path: PathBuf,
    /// Directory name (e.g. "target").
    pub name: String,
    /// Human-readable description (e.g. "build artifacts").
    pub description: String,
}

impl PreflightResult {
    /// Whether this result warrants a warning or prompt.
    pub fn needs_warning(&self) -> bool {
        !self.heavy_dirs.is_empty()
    }
}

/// Run the preflight scan on tracked paths against the exclusion filter.
///
/// Phase 1 checks immediate children for known heavy directory names that are
/// not already excluded. If none are found, returns early with an empty result.
/// Phase 2 performs a bounded walk to estimate total file count.
///
/// `extra_skip_dirs` are user-supplied names treated like built-in heavy dirs.
pub(crate) fn run_preflight(
    tracked_paths: &[PathBuf],
    exclusion: &ExclusionFilter,
    extra_skip_dirs: &[String],
) -> PreflightResult {
    // Phase 1: sentinel check
    let heavy_dirs = detect_heavy_dirs(tracked_paths, exclusion, extra_skip_dirs);

    if heavy_dirs.is_empty() {
        return PreflightResult {
            heavy_dirs,
            probe_file_count: 0,
            probe_capped: false,
            probe_duration: Duration::ZERO,
        };
    }

    // Phase 2: bounded walk to estimate scope
    let start = Instant::now();
    let mut file_count: usize = 0;
    let mut capped = false;

    'outer: for tracked in tracked_paths {
        if !tracked.exists() || tracked.is_file() {
            continue;
        }

        for entry in WalkDir::new(tracked)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !exclusion.is_excluded(e.path()))
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_symlink() {
                continue;
            }
            if entry.path().is_file() {
                file_count = file_count.saturating_add(1);
            }

            if file_count >= PROBE_ENTRY_CAP || start.elapsed() >= PROBE_TIME_CAP {
                capped = true;
                break 'outer;
            }
        }
    }

    PreflightResult {
        heavy_dirs,
        probe_file_count: file_count,
        probe_capped: capped,
        probe_duration: start.elapsed(),
    }
}

/// Phase 1: check immediate children of tracked dirs for known heavy names
/// and size-based detection of unknown large directories.
fn detect_heavy_dirs(
    tracked_paths: &[PathBuf],
    exclusion: &ExclusionFilter,
    extra_skip_dirs: &[String],
) -> Vec<HeavyDir> {
    let mut found = Vec::new();
    let mut size_check_candidates = Vec::new();

    for tracked in tracked_paths {
        if !tracked.exists() || tracked.is_file() {
            continue;
        }

        let entries = match std::fs::read_dir(tracked) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let Some(name_str) = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
            else {
                continue;
            };

            // Skip already-excluded directories
            if exclusion.is_excluded(&path) {
                continue;
            }

            // Check if this is a known heavy directory by name
            if let Some((_, description)) = KNOWN_HEAVY_DIRS.iter().find(|(n, _)| *n == name_str) {
                found.push(HeavyDir {
                    path,
                    name: name_str,
                    description: (*description).to_string(),
                });
            } else if extra_skip_dirs.iter().any(|dir| dir == &name_str) {
                found.push(HeavyDir {
                    path,
                    name: name_str,
                    description: "user-defined skip directory".to_string(),
                });
            } else {
                // Not a known name — candidate for size-based check
                size_check_candidates.push((path, name_str));
            }
        }
    }

    // Size-based detection: bounded walk of unknown directories.
    // Global time cap prevents unbounded latency on projects with many subdirs.
    let size_check_start = Instant::now();
    for (path, name_str) in size_check_candidates {
        if size_check_start.elapsed() >= SIZE_CHECK_TOTAL_CAP {
            break;
        }
        if exceeds_file_threshold(&path, exclusion) {
            found.push(HeavyDir {
                path,
                name: name_str,
                description: format!("large directory (>{SIZE_THRESHOLD} files)"),
            });
        }
    }

    // Deduplicate by name (multiple tracked paths could contain same dir name)
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found.dedup_by(|a, b| a.name == b.name);
    found
}

/// Check if a directory exceeds the file count threshold via bounded walk.
/// Returns true if the directory contains more than `SIZE_THRESHOLD` files,
/// or if the time cap is hit before counting completes (assumes large).
///
/// Applies the exclusion filter to skip already-excluded subtrees, ensuring
/// the count reflects the effective snapshot scope.
fn exceeds_file_threshold(path: &std::path::Path, exclusion: &ExclusionFilter) -> bool {
    let start = Instant::now();
    let mut count: usize = 0;

    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !exclusion.is_excluded(e.path()))
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() {
            count = count.saturating_add(1);
        }
        if count > SIZE_THRESHOLD {
            return true;
        }
        if start.elapsed() >= SIZE_CHECK_TIME_CAP {
            // Time cap hit before we finished counting — treat as large
            return count > SIZE_THRESHOLD / 2;
        }
    }

    false
}

/// Print a one-line auto-exclude notice to stderr.
///
/// This is the default behavior: auto-exclude heavy dirs and transparently
/// tell the user what happened. No prompt, no blocking.
///
/// `excluded` contains only the dirs that were actually auto-excluded (after
/// `--rollback-include` filtering). `result` provides the probe metrics.
pub(crate) fn print_auto_exclude_notice(excluded: &[&HeavyDir], result: &PreflightResult) {
    let names: Vec<String> = excluded
        .iter()
        .map(|d| format!("{} ({})", d.path.display(), d.description))
        .collect();
    let file_info = if result.probe_capped {
        format!(">{} files", result.probe_file_count)
    } else {
        format!("~{} files", result.probe_file_count)
    };
    eprintln!(
        "  [nono] Rollback: auto-excluded {} [{}] in {:.1}s. \
         Use --rollback-include <name> or --rollback-all to include.",
        names.join(", "),
        file_info,
        result.probe_duration.as_secs_f64(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::undo::ExclusionConfig;

    fn make_filter(patterns: Vec<&str>) -> ExclusionFilter {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: patterns.into_iter().map(String::from).collect(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        ExclusionFilter::new(config, dir.path()).expect("filter")
    }

    #[test]
    fn preflight_result_fields() {
        let result = PreflightResult {
            heavy_dirs: vec![
                HeavyDir {
                    path: PathBuf::from("/a/target"),
                    name: "target".to_string(),
                    description: "build artifacts".to_string(),
                },
                HeavyDir {
                    path: PathBuf::from("/a/node_modules"),
                    name: "node_modules".to_string(),
                    description: "dependencies".to_string(),
                },
            ],
            probe_file_count: 5000,
            probe_capped: true,
            probe_duration: Duration::from_millis(800),
        };

        let names: Vec<&str> = result.heavy_dirs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["target", "node_modules"]);
        assert!(result.needs_warning());
        assert_eq!(result.probe_file_count, 5000);
        assert!(result.probe_capped);
        assert_eq!(result.probe_duration, Duration::from_millis(800));
    }

    #[test]
    fn empty_result_does_not_need_warning() {
        let result = PreflightResult {
            heavy_dirs: vec![],
            probe_file_count: 0,
            probe_capped: false,
            probe_duration: Duration::ZERO,
        };

        assert!(!result.needs_warning());
        assert_eq!(result.probe_file_count, 0);
        assert!(!result.probe_capped);
    }

    #[test]
    fn heavy_dir_fields_accessible() {
        let hd = HeavyDir {
            path: PathBuf::from("/project/target"),
            name: "target".to_string(),
            description: "build artifacts".to_string(),
        };
        assert_eq!(hd.path, PathBuf::from("/project/target"));
        assert_eq!(hd.description, "build artifacts");
    }

    #[test]
    fn detect_heavy_dirs_finds_known_names() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let tracked = dir.path().join("project");
        std::fs::create_dir_all(tracked.join("target")).expect("create target");
        std::fs::create_dir_all(tracked.join("node_modules")).expect("create node_modules");
        std::fs::create_dir_all(tracked.join("src")).expect("create src");

        let filter = make_filter(vec![]);
        let heavy = detect_heavy_dirs(&[tracked], &filter, &[]);

        let names: Vec<&str> = heavy.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"target"), "Should detect target/");
        assert!(
            names.contains(&"node_modules"),
            "Should detect node_modules/"
        );
        assert!(!names.contains(&"src"), "src/ is not a known heavy dir");
    }

    #[test]
    fn detect_heavy_dirs_skips_already_excluded() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let tracked = dir.path().join("project");
        std::fs::create_dir_all(tracked.join("target")).expect("create target");
        std::fs::create_dir_all(tracked.join("node_modules")).expect("create node_modules");

        // Pre-exclude target
        let filter = make_filter(vec!["target"]);
        let heavy = detect_heavy_dirs(&[tracked], &filter, &[]);

        let names: Vec<&str> = heavy.iter().map(|d| d.name.as_str()).collect();
        assert!(
            !names.contains(&"target"),
            "Already-excluded target should not appear"
        );
        assert!(
            names.contains(&"node_modules"),
            "node_modules should appear"
        );
    }

    #[test]
    fn preflight_empty_tracked_dir_no_warning() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let tracked = dir.path().join("empty_project");
        std::fs::create_dir_all(&tracked).expect("create empty dir");

        let filter = make_filter(vec![]);
        let result = run_preflight(&[tracked], &filter, &[]);

        assert!(!result.needs_warning());
    }

    #[test]
    fn preflight_nonexistent_path_no_warning() {
        let filter = make_filter(vec![]);
        let result = run_preflight(&[PathBuf::from("/nonexistent/path/xyz")], &filter, &[]);

        assert!(!result.needs_warning());
        assert_eq!(result.probe_file_count, 0);
    }
}
