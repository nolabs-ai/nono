//! Snapshot manager for capturing and restoring filesystem state
//!
//! Orchestrates the object store, exclusion filter, and Merkle tree to
//! create baseline snapshots, detect incremental changes, and restore
//! to a previous state.

use crate::error::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use super::exclusion::ExclusionFilter;
use super::merkle::MerkleTree;
use super::object_store::ObjectStore;
use super::types::{Change, ChangeType, ContentHash, FileState, SessionMetadata, SnapshotManifest};

/// Budget limits for directory walks during snapshot operations.
///
/// Provides a safety net against runaway walks when tracked directories contain
/// unexpectedly large subtrees (e.g. `node_modules/`, `target/`). When either
/// limit is exceeded, the walk returns an error instead of continuing indefinitely.
///
/// A limit of `0` means unlimited for that dimension.
pub struct WalkBudget {
    /// Maximum entries (files + dirs) to visit. 0 = unlimited.
    pub max_entries: usize,
    /// Maximum total bytes (sum of file sizes via metadata). 0 = unlimited.
    pub max_bytes: u64,
}

impl Default for WalkBudget {
    fn default() -> Self {
        Self {
            max_entries: 300_000,
            max_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
        }
    }
}

/// Manages snapshots for an undo session.
///
/// Coordinates the object store, exclusion filter, and Merkle tree to
/// capture filesystem state, detect changes, and restore files.
///
/// When multiple tracked paths are used, each root can have its own
/// exclusion filter (and thus its own `.gitignore` context). Use
/// [`new_per_root`](Self::new_per_root) to supply per-root filters.
pub struct SnapshotManager {
    session_dir: PathBuf,
    tracked_paths: Vec<PathBuf>,
    /// Per-root exclusion filters keyed by root path.
    /// When a file is walked under a tracked root, the filter for that
    /// root is used. This preserves `.gitignore` semantics: rules are
    /// interpreted relative to the directory they came from.
    exclusions: HashMap<PathBuf, ExclusionFilter>,
    object_store: ObjectStore,
    snapshot_count: u32,
    budget: WalkBudget,
}

impl SnapshotManager {
    /// Create a new snapshot manager with a single exclusion filter for all roots.
    ///
    /// Creates `snapshots/` and `changes/` subdirectories. The provided
    /// filter is used for all tracked paths.
    pub fn new(
        session_dir: PathBuf,
        tracked_paths: Vec<PathBuf>,
        exclusion: ExclusionFilter,
        budget: WalkBudget,
    ) -> Result<Self> {
        // Pair every tracked path with a clone of the same filter
        let exclusions: HashMap<PathBuf, ExclusionFilter> = tracked_paths
            .iter()
            .map(|p| (p.clone(), exclusion.clone()))
            .collect();
        Self::init(session_dir, tracked_paths, exclusions, budget)
    }

    /// Create a new snapshot manager with per-root exclusion filters.
    ///
    /// Each `(root, filter)` pair associates a tracked path with its own
    /// exclusion filter. This preserves `.gitignore` semantics: rules from
    /// each root's `.gitignore` are interpreted relative to that root.
    ///
    /// The `roots` parameter defines both the tracked paths and their filters.
    pub fn new_per_root(
        session_dir: PathBuf,
        roots: Vec<(PathBuf, ExclusionFilter)>,
        budget: WalkBudget,
    ) -> Result<Self> {
        let tracked_paths: Vec<PathBuf> = roots.iter().map(|(p, _)| p.clone()).collect();
        let exclusions: HashMap<PathBuf, ExclusionFilter> = roots.into_iter().collect();
        Self::init(session_dir, tracked_paths, exclusions, budget)
    }

    /// Shared initialization for both constructors.
    fn init(
        session_dir: PathBuf,
        tracked_paths: Vec<PathBuf>,
        exclusions: HashMap<PathBuf, ExclusionFilter>,
        budget: WalkBudget,
    ) -> Result<Self> {
        let snapshots_dir = session_dir.join("snapshots");
        let changes_dir = session_dir.join("changes");

        fs::create_dir_all(&snapshots_dir).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to create snapshots directory {}: {}",
                snapshots_dir.display(),
                e
            ))
        })?;
        fs::create_dir_all(&changes_dir).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to create changes directory {}: {}",
                changes_dir.display(),
                e
            ))
        })?;

        let object_store = ObjectStore::new(session_dir.clone())?;

        Ok(Self {
            session_dir,
            tracked_paths,
            exclusions,
            object_store,
            snapshot_count: 0,
            budget,
        })
    }

    /// Create a baseline snapshot (snapshot 0) of all tracked paths.
    ///
    /// Walks all tracked directories, applies exclusion filter, hashes and
    /// stores each file, builds the manifest with Merkle root, and writes
    /// it atomically to `snapshots/000.json`.
    pub fn create_baseline(&mut self) -> Result<SnapshotManifest> {
        let files = self.walk_and_store()?;
        let merkle = MerkleTree::from_manifest(&files)?;

        let manifest = SnapshotManifest {
            number: 0,
            timestamp: now_epoch_secs(),
            parent: None,
            files,
            merkle_root: *merkle.root(),
        };

        self.save_manifest(&manifest)?;
        self.snapshot_count = 1;

        Ok(manifest)
    }

    /// Create an incremental snapshot by comparing current state to previous.
    ///
    /// Uses mtime/size as a fast check to skip unchanged files, then hashes
    /// changed files. Detects created, modified, and deleted files.
    pub fn create_incremental(
        &mut self,
        previous: &SnapshotManifest,
    ) -> Result<(SnapshotManifest, Vec<Change>)> {
        let current_files = self.walk_and_store()?;
        let changes = compute_changes(&previous.files, &current_files);
        let merkle = MerkleTree::from_manifest(&current_files)?;

        let number = previous.number.saturating_add(1);
        let manifest = SnapshotManifest {
            number,
            timestamp: now_epoch_secs(),
            parent: Some(previous.number),
            files: current_files,
            merkle_root: *merkle.root(),
        };

        self.save_manifest(&manifest)?;

        // Save changes list
        if !changes.is_empty() {
            let changes_path = self
                .session_dir
                .join("changes")
                .join(format!("{number:03}.json"));
            let json = serde_json::to_string_pretty(&changes)
                .map_err(|e| NonoError::Snapshot(format!("Failed to serialize changes: {e}")))?;
            atomic_write(&changes_path, json.as_bytes())?;
        }

        self.snapshot_count = number.saturating_add(1);

        Ok((manifest, changes))
    }

    /// Compute what `restore_to` would change without actually restoring.
    ///
    /// Compares the current filesystem state against the manifest and returns
    /// the list of changes that would be applied. Useful for dry-run previews.
    pub fn compute_restore_diff(&self, manifest: &SnapshotManifest) -> Result<Vec<Change>> {
        self.validate_manifest_paths(manifest)?;
        let current_files = self.walk_current()?;
        let mut changes = Vec::new();

        for (path, state) in &manifest.files {
            let needs_restore = match current_files.get(path) {
                Some(current) => current.hash != state.hash,
                None => true,
            };

            if needs_restore {
                let change_type = if current_files.contains_key(path) {
                    ChangeType::Modified
                } else {
                    ChangeType::Created
                };

                changes.push(Change {
                    path: path.clone(),
                    change_type,
                    size_delta: None,
                    old_hash: current_files.get(path).map(|s| s.hash),
                    new_hash: Some(state.hash),
                });
            }
        }

        for (path, state) in &current_files {
            if !manifest.files.contains_key(path) {
                changes.push(Change {
                    path: path.clone(),
                    change_type: ChangeType::Deleted,
                    size_delta: None,
                    old_hash: Some(state.hash),
                    new_hash: None,
                });
            }
        }

        changes.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(changes)
    }

    /// Restore filesystem to the state captured by the given manifest.
    ///
    /// For each file in the manifest: restores content from object store
    /// via atomic temp+rename. Deletes files that exist on disk but aren't
    /// in the manifest. Returns the list of changes applied.
    ///
    /// All manifest paths are validated to be within tracked directories
    /// before any writes occur.
    pub fn restore_to(&self, manifest: &SnapshotManifest) -> Result<Vec<Change>> {
        self.validate_manifest_paths(manifest)?;
        let current_files = self.walk_current()?;
        let mut applied_changes = Vec::new();

        for (path, state) in &manifest.files {
            let needs_restore = match current_files.get(path) {
                Some(current) => current.hash != state.hash,
                None => true,
            };

            if needs_restore {
                self.validate_restore_target(path)?;
            }
        }

        // Restore files from manifest
        for (path, state) in &manifest.files {
            let needs_restore = match current_files.get(path) {
                Some(current) => current.hash != state.hash,
                None => true, // File was deleted, need to recreate
            };

            if needs_restore {
                // Ensure parent directory exists
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        NonoError::Snapshot(format!(
                            "Failed to create directory {}: {e}",
                            parent.display()
                        ))
                    })?;
                }

                self.object_store.retrieve_to(&state.hash, path)?;

                // Restore permissions (mask out setuid/setgid/sticky bits)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = fs::Permissions::from_mode(state.permissions & 0o0777);
                    if let Err(e) = fs::set_permissions(path, perms) {
                        tracing::warn!("Failed to set permissions on {}: {}", path.display(), e);
                    }
                }

                let change_type = if current_files.contains_key(path) {
                    ChangeType::Modified
                } else {
                    ChangeType::Created
                };

                applied_changes.push(Change {
                    path: path.clone(),
                    change_type,
                    size_delta: None,
                    old_hash: current_files.get(path).map(|s| s.hash),
                    new_hash: Some(state.hash),
                });
            }
        }

        // Delete files not in the manifest (created during session)
        for path in current_files.keys() {
            if !manifest.files.contains_key(path) {
                if let Err(e) = fs::remove_file(path) {
                    tracing::warn!("Failed to remove {}: {}", path.display(), e);
                } else {
                    applied_changes.push(Change {
                        path: path.clone(),
                        change_type: ChangeType::Deleted,
                        size_delta: None,
                        old_hash: current_files.get(path).map(|s| s.hash),
                        new_hash: None,
                    });
                }
            }
        }

        Ok(applied_changes)
    }

    /// Collect files that match the atomic temp-file pattern used by editors/tools.
    ///
    /// These files are typically named `<name>.tmp.<pid>.<timestamp>` and may be
    /// left behind when interrupted. The undo flow uses this baseline set so we
    /// can remove only files created during the session.
    #[must_use]
    pub fn collect_atomic_temp_files(&self) -> HashSet<PathBuf> {
        let mut files = HashSet::new();
        let mut entries_visited: usize = 0;

        for tracked in &self.tracked_paths {
            if !tracked.exists() {
                continue;
            }

            let exclusion = self.filter_for_root(tracked);

            if tracked.is_file() {
                if has_atomic_temp_suffix(tracked) {
                    files.insert(tracked.clone());
                }
                continue;
            }

            for entry in WalkDir::new(tracked)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !exclusion.is_excluded(e.path()))
                .filter_map(|e| e.ok())
            {
                entries_visited = entries_visited.saturating_add(1);
                if self.budget.max_entries > 0 && entries_visited > self.budget.max_entries {
                    tracing::warn!(
                        "Atomic temp file scan capped at {} entries (budget limit)",
                        entries_visited
                    );
                    return files;
                }

                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if has_atomic_temp_suffix(path) {
                    files.insert(path.to_path_buf());
                }
            }
        }

        files
    }

    /// Remove newly-created atomic temp files after a session completes.
    ///
    /// `existing` should come from `collect_atomic_temp_files()` before command
    /// execution. Files that existed before the session are preserved.
    pub fn cleanup_new_atomic_temp_files(&self, existing: &HashSet<PathBuf>) -> usize {
        let mut removed = 0usize;

        for path in self.collect_atomic_temp_files() {
            if existing.contains(&path) {
                continue;
            }

            match fs::remove_file(&path) {
                Ok(()) => removed = removed.saturating_add(1),
                Err(e) => tracing::warn!("Failed to remove temp file {}: {}", path.display(), e),
            }
        }

        removed
    }

    /// Load a manifest from disk by snapshot number.
    pub fn load_manifest(&self, number: u32) -> Result<SnapshotManifest> {
        let path = self
            .session_dir
            .join("snapshots")
            .join(format!("{number:03}.json"));
        let content = fs::read_to_string(&path).map_err(|e| {
            NonoError::Snapshot(format!("Failed to read manifest {}: {e}", path.display()))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            NonoError::Snapshot(format!("Failed to parse manifest {}: {e}", path.display()))
        })
    }

    /// Save session metadata to `session.json`.
    pub fn save_session_metadata(&self, meta: &SessionMetadata) -> Result<()> {
        let path = self.session_dir.join("session.json");
        let json = serde_json::to_string_pretty(meta).map_err(|e| {
            NonoError::Snapshot(format!("Failed to serialize session metadata: {e}"))
        })?;
        atomic_write(&path, json.as_bytes())
    }

    /// Compute the Merkle root of the current filesystem state without
    /// storing objects or writing manifests.
    ///
    /// Walks all tracked paths, applies the exclusion filter, hashes each
    /// file, and returns the Merkle root. This is useful for audit-only
    /// sessions that need a cryptographic commitment to filesystem state
    /// without the overhead of full snapshot storage.
    pub fn compute_merkle_root(&self) -> Result<ContentHash> {
        let files = self.walk_current()?;
        let merkle = MerkleTree::from_manifest(&files)?;
        Ok(*merkle.root())
    }

    /// Get the number of snapshots taken in this session.
    #[must_use]
    pub fn snapshot_count(&self) -> u32 {
        self.snapshot_count
    }

    /// Write session metadata to a session directory without requiring a
    /// `SnapshotManager` instance. Used for audit-only sessions where no
    /// rollback snapshots are taken.
    pub fn write_session_metadata(session_dir: &Path, meta: &SessionMetadata) -> Result<()> {
        let path = session_dir.join("session.json");
        let json = serde_json::to_string_pretty(meta).map_err(|e| {
            NonoError::Snapshot(format!("Failed to serialize session metadata: {e}"))
        })?;
        atomic_write(&path, json.as_bytes())
    }

    /// Load session metadata from a session directory.
    ///
    /// Does not require tracked paths or exclusion filter — reads `session.json`
    /// directly. Useful for session discovery and browsing.
    pub fn load_session_metadata(session_dir: &Path) -> Result<SessionMetadata> {
        let path = session_dir.join("session.json");
        let content = fs::read_to_string(&path).map_err(|e| {
            NonoError::SessionNotFound(format!(
                "Failed to read session metadata {}: {e}",
                path.display()
            ))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to parse session metadata {}: {e}",
                path.display()
            ))
        })
    }

    /// Load a snapshot manifest from a session directory by number.
    ///
    /// Does not require a full `SnapshotManager` — reads directly from disk.
    pub fn load_manifest_from(session_dir: &Path, number: u32) -> Result<SnapshotManifest> {
        let path = session_dir
            .join("snapshots")
            .join(format!("{number:03}.json"));
        let content = fs::read_to_string(&path).map_err(|e| {
            NonoError::Snapshot(format!("Failed to read manifest {}: {e}", path.display()))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            NonoError::Snapshot(format!("Failed to parse manifest {}: {e}", path.display()))
        })
    }

    /// Load a change record from a session directory by snapshot number.
    ///
    /// Returns `Ok(vec![])` if the change file doesn't exist (baseline or no changes).
    pub fn load_changes_from(session_dir: &Path, number: u32) -> Result<Vec<Change>> {
        let path = session_dir
            .join("changes")
            .join(format!("{number:03}.json"));
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&path).map_err(|e| {
            NonoError::Snapshot(format!("Failed to read changes {}: {e}", path.display()))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            NonoError::Snapshot(format!("Failed to parse changes {}: {e}", path.display()))
        })
    }

    /// Validate that all paths in a manifest are within the tracked directories.
    ///
    /// Two-step validation:
    /// 1. Reject paths containing `..` (parent directory) components. Without this,
    ///    a tampered manifest could include paths like `/tracked/dir/../../etc/passwd`
    ///    which pass `Path::starts_with("/tracked")` (component-wise prefix match)
    ///    but resolve to locations outside the tracked directory on the filesystem.
    /// 2. Verify each path is a descendant of at least one tracked directory
    ///    (checked via `Path::starts_with`, component-wise comparison).
    fn validate_manifest_paths(&self, manifest: &SnapshotManifest) -> Result<()> {
        for path in manifest.files.keys() {
            // Reject parent-directory traversal components to prevent path escape.
            if path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(NonoError::Snapshot(format!(
                    "Manifest contains path with parent directory traversal: {}",
                    path.display()
                )));
            }

            let within_tracked = self
                .tracked_paths
                .iter()
                .any(|tracked| path.starts_with(tracked));
            if !within_tracked {
                return Err(NonoError::Snapshot(format!(
                    "Manifest contains path outside tracked directories: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Validate the live filesystem path that restore will write through.
    ///
    /// Manifest validation is lexical: it proves stored paths are under tracked
    /// roots, but it cannot see symlinks created after the snapshot. Restore
    /// runs outside the sandbox, so every existing parent component at or below
    /// the tracked root must be a real directory before `create_dir_all`,
    /// temp-file creation, rename, or chmod touches the path.
    fn validate_restore_target(&self, path: &Path) -> Result<()> {
        let tracked = self
            .tracked_paths
            .iter()
            .filter(|tracked| path.starts_with(tracked))
            .max_by_key(|tracked| tracked.components().count())
            .ok_or_else(|| {
                NonoError::Snapshot(format!(
                    "Manifest contains path outside tracked directories: {}",
                    path.display()
                ))
            })?;

        let parent = path.parent().ok_or_else(|| {
            NonoError::Snapshot(format!("Restore target has no parent: {}", path.display()))
        })?;

        if tracked == path {
            return Ok(());
        }

        match fs::symlink_metadata(tracked) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(NonoError::Snapshot(format!(
                        "Refusing to restore through symlinked tracked path: {}",
                        tracked.display()
                    )));
                }
                if !meta.is_dir() {
                    return Err(NonoError::Snapshot(format!(
                        "Tracked restore root is not a directory: {}",
                        tracked.display()
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(NonoError::Snapshot(format!(
                    "Failed to inspect tracked path {} before restore: {e}",
                    tracked.display()
                )));
            }
        }

        let relative_parent = parent.strip_prefix(tracked).map_err(|_| {
            NonoError::Snapshot(format!(
                "Restore target parent {} is outside tracked root {}",
                parent.display(),
                tracked.display()
            ))
        })?;

        let mut current = tracked.clone();
        for component in relative_parent.components() {
            match component {
                std::path::Component::CurDir => continue,
                std::path::Component::Normal(name) => current.push(name),
                _ => {
                    return Err(NonoError::Snapshot(format!(
                        "Restore target contains unsupported path component: {}",
                        path.display()
                    )));
                }
            }

            match fs::symlink_metadata(&current) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(NonoError::Snapshot(format!(
                            "Refusing to restore through symlinked directory: {}",
                            current.display()
                        )));
                    }
                    if !meta.is_dir() {
                        return Err(NonoError::Snapshot(format!(
                            "Restore parent component is not a directory: {}",
                            current.display()
                        )));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => {
                    return Err(NonoError::Snapshot(format!(
                        "Failed to inspect restore parent {}: {e}",
                        current.display()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Walk tracked paths and store all non-excluded files in the object store.
    ///
    /// Permission errors on individual files are logged and skipped rather than
    /// failing the entire snapshot. This handles files with restrictive permissions
    /// (e.g., credential databases, lock files) that exist in tracked directories.
    ///
    /// Uses `filter_entry()` to prune entire excluded subtrees at directory-entry
    /// time, preventing descent into directories like `.git/` or `target/`.
    /// Enforces the walk budget to prevent runaway walks.
    /// Look up the exclusion filter for a given tracked root.
    fn filter_for_root(&self, tracked: &Path) -> &ExclusionFilter {
        self.exclusions.get(tracked).expect(
            "Internal error: no exclusion filter found for tracked root. \
             This indicates a bug where tracked_paths and exclusions are out of sync.",
        )
    }

    fn walk_and_store(&self) -> Result<HashMap<PathBuf, FileState>> {
        let mut files = HashMap::new();
        let mut entries_visited: usize = 0;
        let mut total_bytes: u64 = 0;

        for tracked in &self.tracked_paths {
            if !tracked.exists() {
                continue;
            }

            let exclusion = self.filter_for_root(tracked);

            if tracked.is_file() {
                if !exclusion.is_excluded(tracked) {
                    // Pre-check file size against budget before expensive I/O
                    if let Ok(meta) = fs::metadata(tracked) {
                        let file_size = meta.len();
                        if self.budget.max_bytes > 0
                            && total_bytes.saturating_add(file_size) > self.budget.max_bytes
                        {
                            return Err(NonoError::Snapshot(format!(
                                "Rollback budget exceeded: {} bytes tracked (limit: {} bytes). \
                                 Consider adding exclusion patterns for large directories, \
                                 or disable rollback with --no-rollback.",
                                total_bytes.saturating_add(file_size),
                                self.budget.max_bytes
                            )));
                        }
                    }
                    match self.hash_and_store_file(tracked) {
                        Ok(state) => {
                            entries_visited = entries_visited.saturating_add(1);
                            total_bytes = total_bytes.saturating_add(state.size);
                            self.check_budget(entries_visited, total_bytes)?;
                            files.insert(tracked.clone(), state);
                        }
                        Err(e) => {
                            tracing::warn!("Skipping unreadable file {}: {}", tracked.display(), e);
                        }
                    }
                }
                continue;
            }

            for entry in WalkDir::new(tracked)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !exclusion.is_excluded(e.path()))
                .filter_map(|e| e.ok())
            {
                entries_visited = entries_visited.saturating_add(1);
                self.check_budget(entries_visited, total_bytes)?;
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                // Pre-check file size against budget before expensive hash+store
                if let Ok(meta) = fs::metadata(path) {
                    let file_size = meta.len();
                    if self.budget.max_bytes > 0
                        && total_bytes.saturating_add(file_size) > self.budget.max_bytes
                    {
                        return Err(NonoError::Snapshot(format!(
                            "Rollback budget exceeded: {} bytes tracked (limit: {} bytes). \
                             Consider adding exclusion patterns for large directories, \
                             or disable rollback with --no-rollback.",
                            total_bytes.saturating_add(file_size),
                            self.budget.max_bytes
                        )));
                    }
                }

                match self.hash_and_store_file(path) {
                    Ok(state) => {
                        total_bytes = total_bytes.saturating_add(state.size);
                        self.check_budget(entries_visited, total_bytes)?;
                        files.insert(path.to_path_buf(), state);
                    }
                    Err(e) => {
                        tracing::warn!("Skipping unreadable file {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(files)
    }

    /// Walk tracked paths to get current file states without storing.
    ///
    /// Uses `filter_entry()` to prune excluded subtrees and enforces the walk budget.
    fn walk_current(&self) -> Result<HashMap<PathBuf, FileState>> {
        let mut files = HashMap::new();
        let mut entries_visited: usize = 0;
        let mut total_bytes: u64 = 0;

        for tracked in &self.tracked_paths {
            if !tracked.exists() {
                continue;
            }

            let exclusion = self.filter_for_root(tracked);

            if tracked.is_file() {
                if !exclusion.is_excluded(tracked)
                    && let Ok(state) = file_state_from_metadata(tracked)
                {
                    entries_visited = entries_visited.saturating_add(1);
                    total_bytes = total_bytes.saturating_add(state.size);
                    self.check_budget(entries_visited, total_bytes)?;
                    files.insert(tracked.clone(), state);
                }
                continue;
            }

            for entry in WalkDir::new(tracked)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !exclusion.is_excluded(e.path()))
                .filter_map(|e| e.ok())
            {
                entries_visited = entries_visited.saturating_add(1);
                self.check_budget(entries_visited, total_bytes)?;
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                if let Ok(state) = file_state_from_metadata(path) {
                    total_bytes = total_bytes.saturating_add(state.size);
                    self.check_budget(entries_visited, total_bytes)?;
                    files.insert(path.to_path_buf(), state);
                }
            }
        }

        Ok(files)
    }

    /// Hash a file, store it in the object store, and return its FileState.
    fn hash_and_store_file(&self, path: &Path) -> Result<FileState> {
        let hash = self.object_store.store_file(path)?;
        let metadata = fs::metadata(path).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read metadata for {}: {e}",
                path.display()
            ))
        })?;

        Ok(FileState {
            hash,
            size: metadata.len(),
            mtime: metadata.mtime(),
            permissions: metadata.mode(),
        })
    }

    /// Check whether walk counters exceed the configured budget.
    ///
    /// A limit of `0` means unlimited for that dimension.
    fn check_budget(&self, entries: usize, bytes: u64) -> Result<()> {
        if self.budget.max_entries > 0 && entries > self.budget.max_entries {
            return Err(NonoError::Snapshot(format!(
                "Rollback budget exceeded: visited {} entries (limit: {}). \
                 Consider adding exclusion patterns for large directories, \
                 or disable rollback with --no-rollback.",
                entries, self.budget.max_entries
            )));
        }
        if self.budget.max_bytes > 0 && bytes > self.budget.max_bytes {
            return Err(NonoError::Snapshot(format!(
                "Rollback budget exceeded: {} bytes tracked (limit: {} bytes). \
                 Consider adding exclusion patterns for large directories, \
                 or disable rollback with --no-rollback.",
                bytes, self.budget.max_bytes
            )));
        }
        Ok(())
    }

    /// Write a manifest to the snapshots directory atomically.
    fn save_manifest(&self, manifest: &SnapshotManifest) -> Result<()> {
        let path = self
            .session_dir
            .join("snapshots")
            .join(format!("{:03}.json", manifest.number));
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| NonoError::Snapshot(format!("Failed to serialize manifest: {e}")))?;
        atomic_write(&path, json.as_bytes())
    }
}

/// Compute changes between two snapshot file maps.
fn compute_changes(
    previous: &HashMap<PathBuf, FileState>,
    current: &HashMap<PathBuf, FileState>,
) -> Vec<Change> {
    let mut changes = Vec::new();

    // Check for modified and deleted files
    for (path, prev_state) in previous {
        match current.get(path) {
            Some(curr_state) => {
                if prev_state.hash != curr_state.hash {
                    let size_delta = i64::try_from(curr_state.size).ok().and_then(|curr| {
                        i64::try_from(prev_state.size)
                            .ok()
                            .map(|prev| curr.saturating_sub(prev))
                    });
                    changes.push(Change {
                        path: path.clone(),
                        change_type: ChangeType::Modified,
                        size_delta,
                        old_hash: Some(prev_state.hash),
                        new_hash: Some(curr_state.hash),
                    });
                } else if prev_state.permissions != curr_state.permissions {
                    changes.push(Change {
                        path: path.clone(),
                        change_type: ChangeType::PermissionsChanged,
                        size_delta: Some(0),
                        old_hash: Some(prev_state.hash),
                        new_hash: Some(curr_state.hash),
                    });
                }
            }
            None => {
                changes.push(Change {
                    path: path.clone(),
                    change_type: ChangeType::Deleted,
                    size_delta: i64::try_from(prev_state.size)
                        .ok()
                        .map(|s| s.saturating_neg()),
                    old_hash: Some(prev_state.hash),
                    new_hash: None,
                });
            }
        }
    }

    // Check for created files
    for (path, curr_state) in current {
        if !previous.contains_key(path) {
            changes.push(Change {
                path: path.clone(),
                change_type: ChangeType::Created,
                size_delta: i64::try_from(curr_state.size).ok(),
                old_hash: None,
                new_hash: Some(curr_state.hash),
            });
        }
    }

    // Sort for deterministic output
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    changes
}

/// Get file state from metadata (hash is zeroed - used for walk_current where
/// we only need to track which files exist for deletion during restore).
fn file_state_from_metadata(path: &Path) -> Result<FileState> {
    let hash = hash_file(path)?;

    let metadata = fs::metadata(path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to read metadata for {}: {e}",
            path.display()
        ))
    })?;

    Ok(FileState {
        hash,
        size: metadata.len(),
        mtime: metadata.mtime(),
        permissions: metadata.mode(),
    })
}

fn hash_file(path: &Path) -> Result<ContentHash> {
    let mut file = fs::File::open(path)
        .map_err(|e| NonoError::Snapshot(format!("Failed to open {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| NonoError::Snapshot(format!("Failed to read {}: {e}", path.display())))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(ContentHash::from_bytes(hasher.finalize().into()))
}

/// Write content to a file atomically via temp file + rename.
fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        NonoError::Snapshot(format!("Path has no parent directory: {}", path.display()))
    })?;

    let temp_path = parent.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        super::object_store::random_u32()
    ));

    let write_result = (|| -> Result<()> {
        let mut file = fs::File::create(&temp_path).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to create temp file {}: {e}",
                temp_path.display()
            ))
        })?;
        use std::io::Write;
        file.write_all(content).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to write temp file {}: {e}",
                temp_path.display()
            ))
        })?;
        file.sync_all().map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to sync temp file {}: {e}",
                temp_path.display()
            ))
        })?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        NonoError::Snapshot(format!(
            "Failed to rename {} to {}: {e}",
            temp_path.display(),
            path.display()
        ))
    })
}

/// Get the current time as Unix epoch seconds.
fn now_epoch_secs() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

/// Match files named like `<name>.tmp.<pid>.<timestamp>`.
fn has_atomic_temp_suffix(path: &Path) -> bool {
    let Some(filename) = path.file_name().and_then(|f| f.to_str()) else {
        return false;
    };

    let Some((base, tail)) = filename.rsplit_once(".tmp.") else {
        return false;
    };
    if base.is_empty() {
        return false;
    }

    let Some((pid, ts)) = tail.split_once('.') else {
        return false;
    };

    !pid.is_empty()
        && !ts.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && ts.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::undo::exclusion::ExclusionConfig;
    use crate::undo::types::ContentHash;
    use tempfile::TempDir;

    fn setup_test_dir() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let tracked = dir.path().join("project");
        fs::create_dir_all(&tracked).expect("create project dir");
        fs::write(tracked.join("file1.txt"), b"hello world").expect("write file1");
        fs::write(tracked.join("file2.txt"), b"goodbye world").expect("write file2");
        (dir, tracked)
    }

    fn make_manager(session_dir: &Path, tracked: &Path) -> SnapshotManager {
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: Vec::new(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        let filter = ExclusionFilter::new(config, tracked).expect("filter");
        SnapshotManager::new(
            session_dir.to_path_buf(),
            vec![tracked.to_path_buf()],
            filter,
            WalkBudget::default(),
        )
        .expect("manager")
    }

    #[test]
    fn baseline_captures_all_files() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let manifest = manager.create_baseline().expect("baseline");

        assert_eq!(manifest.number, 0);
        assert!(manifest.parent.is_none());
        assert_eq!(manifest.files.len(), 2);
        assert!(manifest.files.contains_key(&tracked.join("file1.txt")));
        assert!(manifest.files.contains_key(&tracked.join("file2.txt")));
    }

    #[test]
    fn incremental_detects_modification() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Modify a file
        fs::write(tracked.join("file1.txt"), b"modified content").expect("modify");

        let (manifest, changes) = manager.create_incremental(&baseline).expect("incremental");

        assert_eq!(manifest.number, 1);
        assert_eq!(manifest.parent, Some(0));
        assert!(!changes.is_empty());

        let modified = changes
            .iter()
            .find(|c| c.path == tracked.join("file1.txt"))
            .expect("should find modified file");
        assert_eq!(modified.change_type, ChangeType::Modified);
    }

    #[test]
    fn incremental_detects_creation() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Create a new file
        fs::write(tracked.join("new_file.txt"), b"new content").expect("create");

        let (_manifest, changes) = manager.create_incremental(&baseline).expect("incremental");

        let created = changes
            .iter()
            .find(|c| c.path == tracked.join("new_file.txt"))
            .expect("should find created file");
        assert_eq!(created.change_type, ChangeType::Created);
    }

    #[test]
    fn incremental_detects_deletion() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Delete a file
        fs::remove_file(tracked.join("file2.txt")).expect("delete");

        let (_manifest, changes) = manager.create_incremental(&baseline).expect("incremental");

        let deleted = changes
            .iter()
            .find(|c| c.path == tracked.join("file2.txt"))
            .expect("should find deleted file");
        assert_eq!(deleted.change_type, ChangeType::Deleted);
    }

    #[test]
    fn restore_reverts_to_baseline() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Make changes: modify one file, create another, delete one
        fs::write(tracked.join("file1.txt"), b"modified").expect("modify");
        fs::write(tracked.join("new.txt"), b"new file").expect("create");
        fs::remove_file(tracked.join("file2.txt")).expect("delete");

        // Restore to baseline
        let applied = manager.restore_to(&baseline).expect("restore");
        assert!(!applied.is_empty());

        // Verify: file1 should be back to original
        let content = fs::read_to_string(tracked.join("file1.txt")).expect("read file1");
        assert_eq!(content, "hello world");

        // file2 should be recreated
        let content = fs::read_to_string(tracked.join("file2.txt")).expect("read file2");
        assert_eq!(content, "goodbye world");

        // new.txt should be deleted
        assert!(!tracked.join("new.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn restore_rejects_symlinked_parent_directory() {
        let dir = TempDir::new().expect("tempdir");
        let tracked = dir.path().join("project");
        let outside = dir.path().join("outside");
        fs::create_dir_all(tracked.join("subdir")).expect("create tracked subdir");
        fs::create_dir_all(&outside).expect("create outside dir");
        fs::write(tracked.join("subdir/config.txt"), b"ORIGINAL").expect("write tracked file");
        fs::write(outside.join("config.txt"), b"SHOULD_NOT_CHANGE").expect("write outside file");

        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        fs::remove_dir_all(tracked.join("subdir")).expect("remove tracked subdir");
        std::os::unix::fs::symlink(&outside, tracked.join("subdir")).expect("create symlink");

        let result = manager.restore_to(&baseline);
        assert!(result.is_err());
        let err_msg = result
            .expect_err("restore should reject symlink")
            .to_string();
        assert!(
            err_msg.contains("symlinked directory"),
            "Expected symlink rejection, got: {err_msg}"
        );

        let outside_content =
            fs::read_to_string(outside.join("config.txt")).expect("read outside file");
        assert_eq!(outside_content, "SHOULD_NOT_CHANGE");
    }

    #[test]
    #[cfg(unix)]
    fn restore_rejects_symlink_before_create_dir_all() {
        let dir = TempDir::new().expect("tempdir");
        let tracked = dir.path().join("project");
        let outside = dir.path().join("outside");
        fs::create_dir_all(tracked.join("subdir/deep/nested")).expect("create tracked nested dir");
        fs::create_dir_all(&outside).expect("create outside dir");
        fs::write(tracked.join("subdir/deep/nested/config.txt"), b"ORIGINAL")
            .expect("write nested tracked file");

        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        fs::remove_dir_all(tracked.join("subdir")).expect("remove tracked subdir");
        std::os::unix::fs::symlink(&outside, tracked.join("subdir")).expect("create symlink");

        let result = manager.restore_to(&baseline);
        assert!(result.is_err());
        assert!(
            !outside.join("deep").exists(),
            "restore must not create directories through a symlink"
        );
    }

    #[test]
    fn merkle_root_differs_between_snapshots() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Modify a file
        fs::write(tracked.join("file1.txt"), b"changed").expect("modify");

        let (incremental, _) = manager.create_incremental(&baseline).expect("incremental");

        // Merkle roots should differ
        assert_ne!(baseline.merkle_root, incremental.merkle_root);
    }

    #[test]
    fn compute_merkle_root_matches_baseline() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        // compute_merkle_root uses walk_current (no storage), while
        // create_baseline uses walk_and_store. Both should produce the
        // same merkle root for the same filesystem state.
        let manager = make_manager(&session_dir, &tracked);
        let root_before = manager.compute_merkle_root().expect("compute root");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        assert_eq!(root_before, baseline.merkle_root);
    }

    #[test]
    fn compute_merkle_root_changes_after_modification() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let manager = make_manager(&session_dir, &tracked);
        let root_before = manager.compute_merkle_root().expect("compute root before");

        fs::write(tracked.join("file1.txt"), b"changed content").expect("modify");

        let root_after = manager.compute_merkle_root().expect("compute root after");
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn file_state_from_metadata_hashes_large_files() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("large.bin");
        let mut content = Vec::new();
        for idx in 0..20_000 {
            content.push((idx % 251) as u8);
        }
        fs::write(&path, &content).expect("write large file");

        let state = file_state_from_metadata(&path).expect("file state");
        let expected = ContentHash::from_bytes(sha2::Sha256::digest(&content).into());

        assert_eq!(state.hash, expected);
        assert_eq!(state.size, content.len() as u64);
    }

    #[test]
    fn manifest_roundtrip_via_disk() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        let loaded = manager.load_manifest(0).expect("load");
        assert_eq!(loaded.number, baseline.number);
        assert_eq!(loaded.files.len(), baseline.files.len());
        assert_eq!(loaded.merkle_root, baseline.merkle_root);
    }

    #[test]
    fn session_metadata_save() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        let meta = SessionMetadata {
            session_id: "test-session".to_string(),
            started: "2025-01-01T00:00:00Z".to_string(),
            ended: Some("2025-01-01T00:01:00Z".to_string()),
            command: vec!["bash".to_string(), "-c".to_string(), "echo hi".to_string()],
            executable_identity: None,
            tracked_paths: vec![tracked.to_path_buf()],
            snapshot_count: 2,
            exit_code: Some(0),
            merkle_roots: vec![baseline.merkle_root],
            network_events: vec![],
            audit_event_count: 0,
            audit_integrity: None,
            audit_attestation: None,
        };

        manager.save_session_metadata(&meta).expect("save metadata");

        let content =
            fs::read_to_string(session_dir.join("session.json")).expect("read session.json");
        let loaded: SessionMetadata = serde_json::from_str(&content).expect("parse session.json");
        assert_eq!(loaded.session_id, "test-session");
        assert_eq!(loaded.merkle_roots.len(), 1);
    }

    #[test]
    fn compute_restore_diff_shows_changes_without_modifying_disk() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Make changes
        fs::write(tracked.join("file1.txt"), b"modified").expect("modify");
        fs::write(tracked.join("new.txt"), b"new file").expect("create");
        fs::remove_file(tracked.join("file2.txt")).expect("delete");

        // Compute diff without restoring
        let diff = manager.compute_restore_diff(&baseline).expect("diff");
        assert!(!diff.is_empty());

        // Files should NOT be restored — disk state unchanged
        let content = fs::read_to_string(tracked.join("file1.txt")).expect("read");
        assert_eq!(content, "modified");
        assert!(tracked.join("new.txt").exists());
        assert!(!tracked.join("file2.txt").exists());
    }

    #[test]
    fn load_session_metadata_static() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        let meta = SessionMetadata {
            session_id: "static-load-test".to_string(),
            started: "2025-01-01T00:00:00Z".to_string(),
            ended: None,
            command: vec!["test".to_string()],
            executable_identity: None,
            tracked_paths: vec![tracked.to_path_buf()],
            snapshot_count: 1,
            exit_code: None,
            merkle_roots: vec![baseline.merkle_root],
            network_events: vec![],
            audit_event_count: 0,
            audit_integrity: None,
            audit_attestation: None,
        };
        manager.save_session_metadata(&meta).expect("save");

        // Load without a SnapshotManager
        let loaded = SnapshotManager::load_session_metadata(&session_dir).expect("load");
        assert_eq!(loaded.session_id, "static-load-test");
    }

    #[test]
    fn load_session_metadata_defaults_network_events_for_legacy_json() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        let legacy = serde_json::json!({
            "session_id": "legacy-session",
            "started": "2025-01-01T00:00:00Z",
            "ended": null,
            "command": ["test"],
            "tracked_paths": [tracked],
            "snapshot_count": 1,
            "exit_code": 0,
            "merkle_roots": [baseline.merkle_root.to_string()],
        });
        fs::write(
            session_dir.join("session.json"),
            serde_json::to_vec_pretty(&legacy).expect("serialize legacy metadata"),
        )
        .expect("write session metadata");

        let loaded = SnapshotManager::load_session_metadata(&session_dir).expect("load");
        assert!(loaded.network_events.is_empty());
    }

    #[test]
    fn load_manifest_and_changes_static() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Modify and create incremental
        fs::write(tracked.join("file1.txt"), b"modified").expect("modify");
        let (_incr, _changes) = manager.create_incremental(&baseline).expect("incremental");

        // Load via static methods
        let manifest = SnapshotManager::load_manifest_from(&session_dir, 0).expect("load manifest");
        assert_eq!(manifest.number, 0);

        let changes = SnapshotManager::load_changes_from(&session_dir, 1).expect("load changes");
        assert!(!changes.is_empty());

        // Baseline has no change file
        let baseline_changes =
            SnapshotManager::load_changes_from(&session_dir, 0).expect("load baseline changes");
        assert!(baseline_changes.is_empty());
    }

    #[test]
    fn validate_manifest_rejects_parent_dir_traversal() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let manager = make_manager(&session_dir, &tracked);

        // Craft a manifest with a path containing ".." that passes starts_with
        // but would resolve outside the tracked directory.
        let mut files = HashMap::new();
        let evil_path = tracked
            .join("subdir")
            .join("..")
            .join("..")
            .join("etc")
            .join("passwd");
        files.insert(
            evil_path,
            FileState {
                hash: ContentHash::from_bytes([0xde; 32]),
                size: 100,
                mtime: 0,
                permissions: 0o644,
            },
        );

        let manifest = SnapshotManifest {
            number: 0,
            parent: None,
            files,
            merkle_root: ContentHash::from_bytes([0; 32]),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };

        let result = manager.validate_manifest_paths(&manifest);
        assert!(result.is_err());
        let err_msg = result.expect_err("should reject").to_string();
        assert!(
            err_msg.contains("parent directory traversal"),
            "Expected traversal error, got: {err_msg}"
        );
    }

    #[test]
    fn validate_manifest_rejects_path_outside_tracked() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let manager = make_manager(&session_dir, &tracked);

        let mut files = HashMap::new();
        files.insert(
            PathBuf::from("/tmp/not-tracked/secret.txt"),
            FileState {
                hash: ContentHash::from_bytes([0xde; 32]),
                size: 50,
                mtime: 0,
                permissions: 0o644,
            },
        );

        let manifest = SnapshotManifest {
            number: 0,
            parent: None,
            files,
            merkle_root: ContentHash::from_bytes([0; 32]),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };

        let result = manager.validate_manifest_paths(&manifest);
        assert!(result.is_err());
        let err_msg = result.expect_err("should reject").to_string();
        assert!(
            err_msg.contains("outside tracked directories"),
            "Expected outside-tracked error, got: {err_msg}"
        );
    }

    #[test]
    fn validate_manifest_accepts_valid_paths() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // A real baseline manifest should pass validation.
        let result = manager.validate_manifest_paths(&baseline);
        assert!(result.is_ok());
    }

    #[test]
    fn cleanup_new_atomic_temp_files_removes_only_new_files() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");
        let manager = make_manager(&session_dir, &tracked);

        let preexisting = tracked.join("preexisting.txt.tmp.100.200");
        fs::write(&preexisting, b"old temp").expect("write preexisting temp");
        let before = manager.collect_atomic_temp_files();

        let new_temp = tracked.join("new.txt.tmp.300.400");
        fs::write(&new_temp, b"new temp").expect("write new temp");
        let not_atomic = tracked.join("kept.tmp");
        fs::write(&not_atomic, b"keep").expect("write non-atomic temp");

        let removed = manager.cleanup_new_atomic_temp_files(&before);
        assert_eq!(removed, 1);
        assert!(preexisting.exists());
        assert!(!new_temp.exists());
        assert!(not_atomic.exists());
    }

    fn make_manager_with_budget(
        session_dir: &Path,
        tracked: &Path,
        budget: WalkBudget,
    ) -> SnapshotManager {
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: Vec::new(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        let filter = ExclusionFilter::new(config, tracked).expect("filter");
        SnapshotManager::new(
            session_dir.to_path_buf(),
            vec![tracked.to_path_buf()],
            filter,
            budget,
        )
        .expect("manager")
    }

    #[test]
    fn walk_budget_entry_limit_exceeded() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        // Budget of 1 entry but dir has 2 files + dir itself = exceeds
        let mut manager = make_manager_with_budget(
            &session_dir,
            &tracked,
            WalkBudget {
                max_entries: 1,
                max_bytes: 0,
            },
        );

        let result = manager.create_baseline();
        let Err(err) = result else {
            panic!("expected budget error, got Ok");
        };
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("budget exceeded"),
            "Expected budget error, got: {err_msg}"
        );
    }

    #[test]
    fn walk_budget_byte_limit_exceeded() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        // Budget of 1 byte but files have content
        let mut manager = make_manager_with_budget(
            &session_dir,
            &tracked,
            WalkBudget {
                max_entries: 0,
                max_bytes: 1,
            },
        );

        let result = manager.create_baseline();
        let Err(err) = result else {
            panic!("expected budget error, got Ok");
        };
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("budget exceeded") || err_msg.contains("bytes tracked"),
            "Expected budget error, got: {err_msg}"
        );
    }

    #[test]
    fn budget_checked_for_tracked_files() {
        let dir = TempDir::new().expect("tempdir");
        let tracked_file = dir.path().join("bigfile.txt");
        fs::write(&tracked_file, b"some content here").expect("write file");

        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: Vec::new(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        let filter = ExclusionFilter::new(config, dir.path()).expect("filter");

        // Budget of 1 byte — the tracked file exceeds it
        let mut manager = SnapshotManager::new(
            session_dir,
            vec![tracked_file],
            filter,
            WalkBudget {
                max_entries: 0,
                max_bytes: 1,
            },
        )
        .expect("manager");

        let result = manager.create_baseline();
        let Err(err) = result else {
            panic!("expected budget error, got Ok");
        };
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("budget exceeded") || err_msg.contains("bytes tracked"),
            "Expected budget error for tracked file, got: {err_msg}"
        );
    }

    #[test]
    fn collect_atomic_temp_prunes_excluded_dirs() {
        let dir = TempDir::new().expect("tempdir");
        let tracked = dir.path().join("project");
        fs::create_dir_all(tracked.join("excluded_dir")).expect("create excluded dir");
        fs::write(
            tracked.join("excluded_dir/file.txt.tmp.100.200"),
            b"temp in excluded",
        )
        .expect("write excluded temp");
        fs::write(tracked.join("visible.txt.tmp.100.200"), b"temp visible")
            .expect("write visible temp");

        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: vec!["excluded_dir".to_string()],
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        let filter = ExclusionFilter::new(config, &tracked).expect("filter");
        let manager = SnapshotManager::new(
            session_dir,
            vec![tracked.clone()],
            filter,
            WalkBudget::default(),
        )
        .expect("manager");

        let temps = manager.collect_atomic_temp_files();
        // Should find the visible temp but not the one in excluded_dir
        assert!(temps.contains(&tracked.join("visible.txt.tmp.100.200")));
        assert!(!temps.contains(&tracked.join("excluded_dir/file.txt.tmp.100.200")));
    }

    #[test]
    fn collect_atomic_temp_respects_budget() {
        let dir = TempDir::new().expect("tempdir");
        let tracked = dir.path().join("project");
        fs::create_dir_all(&tracked).expect("create tracked");

        // Create many files so the budget is hit
        for i in 0..10 {
            fs::write(tracked.join(format!("file{i}.txt.tmp.100.200")), b"temp")
                .expect("write temp");
        }

        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: Vec::new(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        let filter = ExclusionFilter::new(config, &tracked).expect("filter");
        let manager = SnapshotManager::new(
            session_dir,
            vec![tracked],
            filter,
            WalkBudget {
                max_entries: 3, // Very low budget
                max_bytes: 0,
            },
        )
        .expect("manager");

        let temps = manager.collect_atomic_temp_files();
        // Should have fewer than 10 due to budget cap
        assert!(
            temps.len() < 10,
            "Expected budget cap, got {} temps",
            temps.len()
        );
    }
}
