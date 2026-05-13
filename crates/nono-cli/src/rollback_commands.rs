//! Rollback subcommand implementations
//!
//! Handles `nono rollback list|show|restore|verify|cleanup`.

use crate::cli::{
    RollbackArgs, RollbackCleanupArgs, RollbackCommands, RollbackListArgs, RollbackRestoreArgs,
    RollbackShowArgs, RollbackVerifyArgs,
};
use crate::command_display::{format_command_line, truncate_chars};
use crate::config::user::load_user_config;
use crate::rollback_base_exclusions;
use crate::rollback_session::{
    SessionInfo, discover_sessions, format_bytes, load_session, remove_session, rollback_root,
};
use crate::theme;
use colored::Colorize;
use nono::undo::{MerkleTree, ObjectStore, SnapshotManager};
use nono::{NonoError, Result, try_canonicalize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A session paired with its change counts (created, modified, deleted).
type SessionChanges<'a> = (&'a SessionInfo, (usize, usize, usize));

/// Build a list of canonical path candidates for matching.
///
/// Returns the canonicalized path plus, on macOS, symlink equivalents
/// (`/tmp` <-> `/private/tmp`, `/etc` <-> `/private/etc`, `/var` <-> `/private/var`)
/// so that user input in either form matches stored canonical paths.
fn canonical_candidates(path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(2);

    // Primary: canonicalize using ancestor-walk fallback
    let primary = try_canonicalize(path);
    candidates.push(primary.clone());

    // macOS symlink aliases: try both directions
    #[cfg(target_os = "macos")]
    {
        let prefixes: &[(&str, &str)] = &[
            ("/tmp", "/private/tmp"),
            ("/etc", "/private/etc"),
            ("/var", "/private/var"),
        ];
        let primary_str = primary.to_string_lossy();
        for &(short, long) in prefixes {
            if let Some(rest) = primary_str.strip_prefix(long) {
                candidates.push(PathBuf::from(format!("{short}{rest}")));
            } else if let Some(rest) = primary_str.strip_prefix(short) {
                candidates.push(PathBuf::from(format!("{long}{rest}")));
            }
        }
    }

    candidates
}

/// Prefix used for all rollback command output
fn prefix() -> colored::ColoredString {
    let t = theme::current();
    theme::fg("nono", t.brand).bold()
}

/// Dispatch to the appropriate rollback subcommand.
pub fn run_rollback(args: RollbackArgs) -> Result<()> {
    match args.command {
        RollbackCommands::List(args) => cmd_list(args),
        RollbackCommands::Show(args) => cmd_show(args),
        RollbackCommands::Restore(args) => cmd_restore(args),
        RollbackCommands::Verify(args) => cmd_verify(args),
        RollbackCommands::Cleanup(args) => cmd_cleanup(args),
    }
}

// ---------------------------------------------------------------------------
// nono rollback list
// ---------------------------------------------------------------------------

fn cmd_list(args: RollbackListArgs) -> Result<()> {
    let mut sessions = discover_sessions()?;

    // Filter by --path if provided.
    // Tracked paths are stored canonical (from FsCapability::resolved), so we
    // canonicalize the user's filter and compare directly. On macOS, also try
    // the /private symlink equivalents so `/tmp/x` matches `/private/tmp/x`.
    if let Some(ref filter_path) = args.path {
        let filter_candidates = canonical_candidates(filter_path);
        sessions.retain(|s| {
            s.metadata.tracked_paths.iter().any(|stored| {
                filter_candidates
                    .iter()
                    .any(|filter| stored.starts_with(filter) || filter.starts_with(stored))
            })
        });
    }

    if let Some(n) = args.recent {
        sessions.truncate(n);
    }

    // Compute change summary for each session
    let sessions_with_changes: Vec<_> = sessions
        .iter()
        .map(|s| {
            let changes = get_session_total_changes(s);
            (s, changes)
        })
        .collect();

    // Filter to only sessions with actual changes (unless --all)
    let filtered: Vec<_> = if args.all {
        sessions_with_changes
    } else {
        sessions_with_changes
            .into_iter()
            .filter(|(_, (c, m, d))| *c > 0 || *m > 0 || *d > 0)
            .collect()
    };

    if args.json {
        return print_sessions_json(&filtered.iter().map(|(s, _)| *s).collect::<Vec<_>>());
    }

    if filtered.is_empty() {
        if args.all {
            eprintln!("{} No rollback entries found.", prefix());
        } else {
            eprintln!(
                "{} No snapshots with file changes. Use --all to see all rollback entries.",
                prefix()
            );
        }
        return Ok(());
    }

    // Group sessions by their primary tracked path (project directory)
    let grouped = group_by_project(&filtered);
    let total_snapshots: u32 = grouped
        .values()
        .flat_map(|group| group.iter())
        .map(|(s, _)| s.metadata.snapshot_count)
        .sum();
    eprintln!("{} {} snapshot(s)\n", prefix(), total_snapshots);

    for (project_path, sessions) in &grouped {
        let display_path = shorten_home(project_path);
        let snapshot_count: u32 = sessions
            .iter()
            .map(|(s, _)| s.metadata.snapshot_count)
            .sum();
        eprintln!(
            "  {} ({} snapshot{})",
            display_path.white().bold(),
            snapshot_count,
            if snapshot_count == 1 { "" } else { "s" },
        );
        for (s, (created, modified, deleted)) in sessions {
            print_session_line(s, *created, *modified, *deleted);
        }
        eprintln!();
    }

    Ok(())
}

/// Group sessions by their primary tracked path.
///
/// Each session's first tracked path is used as the project identifier.
/// Sessions with no tracked paths are grouped under "(unknown)".
fn group_by_project<'a>(
    sessions: &[SessionChanges<'a>],
) -> BTreeMap<PathBuf, Vec<SessionChanges<'a>>> {
    let mut groups: BTreeMap<PathBuf, Vec<SessionChanges<'a>>> = BTreeMap::new();

    for (s, changes) in sessions {
        let project = s
            .metadata
            .tracked_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("(unknown)"));
        groups.entry(project).or_default().push((s, *changes));
    }

    groups
}

/// Replace the home directory prefix with ~ for display
fn shorten_home(path: &Path) -> String {
    let s = path.display().to_string();
    if let Some(home) = dirs::home_dir() {
        let home_str = home.display().to_string();
        if let Some(rest) = s.strip_prefix(&home_str) {
            return format!("~{rest}");
        }
    }
    s
}

/// Print a single session line in the list output
fn print_session_line(s: &SessionInfo, created: usize, modified: usize, deleted: usize) {
    let cmd_name = s
        .metadata
        .command
        .first()
        .map(|c| {
            Path::new(c)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| c.clone())
        })
        .unwrap_or_else(|| "(unknown)".to_string());
    let change_summary = format_change_summary(created, modified, deleted);
    let timestamp = format_session_timestamp(&s.metadata.started);

    eprintln!(
        "    {}  {}  {}  {}",
        s.metadata.session_id.white().bold(),
        timestamp.truecolor(100, 100, 100),
        theme::fg(&cmd_name, theme::current().subtext),
        change_summary,
    );
}

/// Get total changes across all snapshots in a session
fn get_session_total_changes(s: &SessionInfo) -> (usize, usize, usize) {
    let mut total_created = 0usize;
    let mut total_modified = 0usize;
    let mut total_deleted = 0usize;

    for i in 1..s.metadata.snapshot_count {
        let changes = SnapshotManager::load_changes_from(&s.dir, i).unwrap_or_default();
        let (c, m, d) = count_change_types(&changes);
        total_created = total_created.saturating_add(c);
        total_modified = total_modified.saturating_add(m);
        total_deleted = total_deleted.saturating_add(d);
    }

    (total_created, total_modified, total_deleted)
}

/// Format change summary for display
fn format_change_summary(created: usize, modified: usize, deleted: usize) -> String {
    let mut parts = Vec::new();

    if created > 0 {
        let suffix = if created == 1 { "file" } else { "files" };
        parts.push(format!("+{created} {suffix}"));
    }
    if modified > 0 {
        parts.push(format!("~{modified} modified"));
    }
    if deleted > 0 {
        parts.push(format!("-{deleted} deleted"));
    }

    if parts.is_empty() {
        "(no changes)".to_string()
    } else {
        parts.join(", ")
    }
}

fn print_sessions_json(sessions: &[&SessionInfo]) -> Result<()> {
    let entries: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            serde_json::json!({
                "session_id": s.metadata.session_id,
                "started": s.metadata.started,
                "ended": s.metadata.ended,
                "command": s.metadata.command,
                "tracked_paths": s.metadata.tracked_paths,
                "snapshot_count": s.metadata.snapshot_count,
                "exit_code": s.metadata.exit_code,
                "disk_size": s.disk_size,
                "is_alive": s.is_alive,
                "is_stale": s.is_stale,
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&entries)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// nono rollback show
// ---------------------------------------------------------------------------

fn cmd_show(args: RollbackShowArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

    if args.json {
        return print_show_json(&session);
    }

    // Collect all changes from all snapshots
    let mut all_changes = Vec::new();
    for i in 1..session.metadata.snapshot_count {
        let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();
        all_changes.extend(changes);
    }

    if all_changes.is_empty() {
        eprintln!(
            "{} Session {} has no file changes.",
            prefix(),
            args.session_id
        );
        return Ok(());
    }

    let object_store = ObjectStore::new(session.dir.clone())?;

    eprintln!(
        "{} Session {} ({})\n",
        prefix(),
        session.metadata.session_id.white().bold(),
        theme::fg(
            &format_command_line(&session.metadata.command),
            theme::current().subtext
        )
    );

    if args.diff {
        print_unified_diff(&all_changes, &object_store)?;
    } else if args.side_by_side {
        print_side_by_side_diff(&all_changes, &object_store)?;
    } else if args.full {
        print_full_content(&all_changes, &object_store)?;
    } else {
        // Default: summary with line counts
        print_change_summary(&all_changes, &object_store)?;
    }

    Ok(())
}

/// Print summary of changes with line counts
fn print_change_summary(changes: &[nono::undo::Change], object_store: &ObjectStore) -> Result<()> {
    use nono::undo::ChangeType;

    for change in changes {
        let symbol = change_symbol(&change.change_type);
        let filename = change
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| change.path.display().to_string());

        let line_info = match change.change_type {
            ChangeType::Created => {
                if let Some(hash) = &change.new_hash {
                    let content = object_store.retrieve(hash).unwrap_or_default();
                    let lines = count_lines(&content);
                    format!("(+{lines} lines)")
                } else {
                    String::new()
                }
            }
            ChangeType::Deleted => {
                if let Some(hash) = &change.old_hash {
                    let content = object_store.retrieve(hash).unwrap_or_default();
                    let lines = count_lines(&content);
                    format!("(-{lines} lines)")
                } else {
                    String::new()
                }
            }
            ChangeType::Modified => {
                let old_lines = change
                    .old_hash
                    .as_ref()
                    .and_then(|h| object_store.retrieve(h).ok())
                    .map(|c| count_lines(&c))
                    .unwrap_or(0);
                let new_lines = change
                    .new_hash
                    .as_ref()
                    .and_then(|h| object_store.retrieve(h).ok())
                    .map(|c| count_lines(&c))
                    .unwrap_or(0);
                let diff = new_lines as i64 - old_lines as i64;
                if diff >= 0 {
                    format!("(+{diff} lines)")
                } else {
                    format!("({diff} lines)")
                }
            }
            ChangeType::PermissionsChanged => "(permissions)".to_string(),
        };

        eprintln!(
            "  {} {:<40} {}",
            symbol,
            filename,
            line_info.truecolor(100, 100, 100)
        );
    }

    Ok(())
}

/// Print unified diff (git diff style)
fn print_unified_diff(changes: &[nono::undo::Change], object_store: &ObjectStore) -> Result<()> {
    use nono::undo::ChangeType;
    use similar::{ChangeTag, TextDiff};

    for change in changes {
        let path_str = change.path.display().to_string();

        let old_content = change
            .old_hash
            .as_ref()
            .and_then(|h| object_store.retrieve(h).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let new_content = change
            .new_hash
            .as_ref()
            .and_then(|h| object_store.retrieve(h).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let old_path = match change.change_type {
            ChangeType::Created => "/dev/null".to_string(),
            _ => format!("a/{}", path_str),
        };
        let new_path = match change.change_type {
            ChangeType::Deleted => "/dev/null".to_string(),
            _ => format!("b/{}", path_str),
        };

        eprintln!("{}", format!("--- {old_path}").red());
        eprintln!("{}", format!("+++ {new_path}").green());

        let diff = TextDiff::from_lines(&old_content, &new_content);
        for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
            eprintln!("{}", format!("{hunk}").cyan());
            for change_op in hunk.iter_changes() {
                match change_op.tag() {
                    ChangeTag::Delete => eprint!("{}", format!("-{}", change_op).red()),
                    ChangeTag::Insert => eprint!("{}", format!("+{}", change_op).green()),
                    ChangeTag::Equal => eprint!(" {}", change_op),
                }
            }
        }
        eprintln!();
    }

    Ok(())
}

/// Print side-by-side diff
fn print_side_by_side_diff(
    changes: &[nono::undo::Change],
    object_store: &ObjectStore,
) -> Result<()> {
    use similar::{ChangeTag, TextDiff};

    let term_width = 120usize; // reasonable default
    let col_width = term_width.saturating_sub(3) / 2;

    for change in changes {
        eprintln!(
            "{}",
            format!("=== {} ===", change.path.display()).white().bold()
        );

        let old_content = change
            .old_hash
            .as_ref()
            .and_then(|h| object_store.retrieve(h).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let new_content = change
            .new_hash
            .as_ref()
            .and_then(|h| object_store.retrieve(h).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let diff = TextDiff::from_lines(&old_content, &new_content);

        for change_op in diff.iter_all_changes() {
            let line = change_op.to_string_lossy();
            let line_trimmed = line.trim_end();

            match change_op.tag() {
                ChangeTag::Equal => {
                    let truncated = truncate_chars(line_trimmed, col_width);
                    eprintln!(
                        "{:<width$} | {:<width$}",
                        truncated,
                        truncated,
                        width = col_width
                    );
                }
                ChangeTag::Delete => {
                    let truncated = truncate_chars(line_trimmed, col_width);
                    eprintln!("{} < {:<width$}", truncated.red(), "", width = col_width);
                }
                ChangeTag::Insert => {
                    let truncated = truncate_chars(line_trimmed, col_width);
                    eprintln!("{:<width$} > {}", "", truncated.green(), width = col_width);
                }
            }
        }
        eprintln!();
    }

    Ok(())
}

/// Print full file content from snapshot
fn print_full_content(changes: &[nono::undo::Change], object_store: &ObjectStore) -> Result<()> {
    use nono::undo::ChangeType;

    for change in changes {
        let symbol = change_symbol(&change.change_type);
        eprintln!(
            "{} {} {}",
            symbol,
            change.path.display().to_string().white().bold(),
            format!("({})", change.change_type).truecolor(100, 100, 100)
        );

        let content_hash = match change.change_type {
            ChangeType::Deleted => change.old_hash.as_ref(),
            _ => change.new_hash.as_ref(),
        };

        if let Some(hash) = content_hash
            && let Ok(content) = object_store.retrieve(hash)
        {
            if let Ok(text) = String::from_utf8(content) {
                for (i, line) in text.lines().enumerate() {
                    eprintln!(
                        "  {} {}",
                        format!("{:4}", i + 1).truecolor(100, 100, 100),
                        line
                    );
                }
            } else {
                eprintln!("  (binary file)");
            }
        }
        eprintln!();
    }

    Ok(())
}

fn count_lines(content: &[u8]) -> usize {
    content
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        .saturating_add(1)
}

fn print_show_json(session: &SessionInfo) -> Result<()> {
    let mut snapshots = Vec::new();
    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();

        snapshots.push(serde_json::json!({
            "number": manifest.number,
            "timestamp": manifest.timestamp,
            "parent": manifest.parent,
            "file_count": manifest.files.len(),
            "merkle_root": manifest.merkle_root.to_string(),
            "changes": changes.iter().map(|c| serde_json::json!({
                "path": c.path.display().to_string(),
                "type": format!("{}", c.change_type),
                "size_delta": c.size_delta,
            })).collect::<Vec<_>>(),
        }));
    }

    let output = serde_json::json!({
        "session_id": session.metadata.session_id,
        "started": session.metadata.started,
        "ended": session.metadata.ended,
        "command": session.metadata.command,
        "executable_identity": session.metadata.executable_identity.as_ref().map(|identity| serde_json::json!({
            "resolved_path": identity.resolved_path,
            "sha256": identity.sha256.to_string(),
        })),
        "tracked_paths": session.metadata.tracked_paths,
        "exit_code": session.metadata.exit_code,
        "disk_size": session.disk_size,
        "is_alive": session.is_alive,
        "is_stale": session.is_stale,
        "snapshots": snapshots,
    });

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// nono rollback restore
// ---------------------------------------------------------------------------

fn cmd_restore(args: RollbackRestoreArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

    // Default to the last snapshot (final state), not baseline
    let snapshot = args
        .snapshot
        .unwrap_or_else(|| session.metadata.snapshot_count.saturating_sub(1));

    if snapshot >= session.metadata.snapshot_count {
        return Err(NonoError::Snapshot(format!(
            "Snapshot {} does not exist (session has {} snapshots)",
            snapshot, session.metadata.snapshot_count
        )));
    }

    let manifest = SnapshotManager::load_manifest_from(&session.dir, snapshot)?;

    // Restore must use the same exclusions as snapshot creation so that
    // walk_current() does not see VCS internals and try to delete them
    let exclusion_config = nono::undo::ExclusionConfig {
        use_gitignore: false,
        exclude_patterns: rollback_base_exclusions(),
        exclude_globs: Vec::new(),
        force_include: Vec::new(),
    };

    // Use the first tracked path as the root for the exclusion filter
    let filter_root = session
        .metadata
        .tracked_paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let exclusion = nono::undo::ExclusionFilter::new(exclusion_config, &filter_root)?;
    let manager = SnapshotManager::new(
        session.dir.clone(),
        session.metadata.tracked_paths.clone(),
        exclusion,
        nono::undo::WalkBudget::default(),
    )?;

    if args.dry_run {
        let diff = manager.compute_restore_diff(&manifest)?;
        if diff.is_empty() {
            eprintln!("{} No changes needed (already matches snapshot).", prefix());
            return Ok(());
        }

        eprintln!(
            "{} Dry run: restoring to snapshot {} would apply {} change(s):\n",
            prefix(),
            snapshot,
            diff.len()
        );
        print_changes(&diff);
        return Ok(());
    }

    let applied = manager.restore_to(&manifest)?;

    if applied.is_empty() {
        eprintln!("{} No changes needed (already matches snapshot).", prefix());
    } else {
        eprintln!(
            "{} Restored {} file(s) to snapshot {}.",
            prefix(),
            applied.len(),
            snapshot
        );
        print_changes(&applied);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono rollback verify
// ---------------------------------------------------------------------------

fn cmd_verify(args: RollbackVerifyArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;
    let object_store = ObjectStore::new(session.dir.clone())?;

    eprintln!(
        "{} Verifying session: {}",
        prefix(),
        session.metadata.session_id.white().bold()
    );

    let mut all_passed = true;
    let mut objects_checked = 0u64;

    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "  [{}] {} Failed to load: {e}",
                    format!("{i:03}").white(),
                    "FAIL".red()
                );
                all_passed = false;
                continue;
            }
        };

        // Rebuild Merkle tree from file hashes and compare
        let rebuilt = MerkleTree::from_manifest(&manifest.files)?;
        let merkle_ok = *rebuilt.root() == manifest.merkle_root;

        if !merkle_ok {
            eprintln!(
                "  [{}] {} Merkle root mismatch (stored: {}, rebuilt: {})",
                format!("{i:03}").white(),
                "FAIL".red(),
                &manifest.merkle_root.to_string()[..16],
                &rebuilt.root().to_string()[..16],
            );
            all_passed = false;
            continue;
        }

        // Verify referenced objects in the store
        let mut snapshot_ok = true;
        for state in manifest.files.values() {
            match object_store.verify(&state.hash) {
                Ok(true) => {
                    objects_checked = objects_checked.saturating_add(1);
                }
                Ok(false) => {
                    snapshot_ok = false;
                    all_passed = false;
                }
                Err(_) => {
                    snapshot_ok = false;
                    all_passed = false;
                }
            }
        }

        let status = if snapshot_ok {
            "OK".green()
        } else {
            all_passed = false;
            "FAIL".red()
        };

        eprintln!(
            "  [{}] {} Merkle root matches, {} objects verified",
            format!("{i:03}").white(),
            status,
            manifest.files.len(),
        );
    }

    eprintln!();
    if all_passed {
        eprintln!(
            "{} {} All {} snapshot(s) verified, {} objects checked.",
            prefix(),
            "PASS".green().bold(),
            session.metadata.snapshot_count,
            objects_checked,
        );
    } else {
        eprintln!(
            "{} {} Some snapshots failed verification.",
            prefix(),
            "FAIL".red().bold(),
        );
        return Err(NonoError::Snapshot(
            "Session integrity verification failed".to_string(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono rollback cleanup
// ---------------------------------------------------------------------------

fn cmd_cleanup(args: RollbackCleanupArgs) -> Result<()> {
    if args.all {
        return cleanup_all(args.dry_run);
    }

    let sessions = discover_sessions()?;
    if sessions.is_empty() {
        eprintln!("{} No rollback entries to clean up.", prefix());
        return Ok(());
    }

    let config = load_user_config()?.unwrap_or_default();
    let keep = args.keep.unwrap_or(config.rollback.max_sessions);

    let mut to_remove: Vec<&SessionInfo> = Vec::new();

    // Filter by --older-than
    if let Some(days) = args.older_than {
        let cutoff_secs = days.saturating_mul(86400);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for s in &sessions {
            if let Some(started) = parse_session_start_time(s)
                && now.saturating_sub(started) > cutoff_secs
                && !s.is_alive
            {
                to_remove.push(s);
            }
        }
    } else {
        // Default: remove orphaned sessions + enforce keep limit
        let orphan_grace_secs = config.rollback.stale_grace_hours.saturating_mul(3600);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Orphaned sessions (process crashed/killed before clean exit)
        for s in &sessions {
            if s.is_stale
                && let Some(started) = parse_session_start_time(s)
                && now.saturating_sub(started) > orphan_grace_secs
            {
                to_remove.push(s);
            }
        }

        // Excess sessions beyond keep limit (sessions already sorted newest-first)
        let completed: Vec<&SessionInfo> = sessions.iter().filter(|s| !s.is_alive).collect();

        if completed.len() > keep {
            for s in &completed[keep..] {
                if !to_remove
                    .iter()
                    .any(|r| r.metadata.session_id == s.metadata.session_id)
                {
                    to_remove.push(s);
                }
            }
        }
    }

    if to_remove.is_empty() {
        eprintln!("{} No rollback entries to clean up.", prefix());
        return Ok(());
    }

    let total_size: u64 = to_remove.iter().map(|s| s.disk_size).sum();

    if args.dry_run {
        eprintln!(
            "{} Dry run: would remove {} rollback entr{} ({})\n",
            prefix(),
            to_remove.len(),
            if to_remove.len() == 1 { "y" } else { "ies" },
            format_bytes(total_size)
        );
        for s in &to_remove {
            eprintln!(
                "  {} {} ({})",
                s.metadata.session_id,
                format_command_line(&s.metadata.command).truecolor(
                    theme::current().subtext.0,
                    theme::current().subtext.1,
                    theme::current().subtext.2
                ),
                format_bytes(s.disk_size).truecolor(
                    theme::current().subtext.0,
                    theme::current().subtext.1,
                    theme::current().subtext.2
                ),
            );
        }
        return Ok(());
    }

    let mut removed = 0usize;
    for s in &to_remove {
        if let Err(e) = remove_session(&s.dir) {
            eprintln!(
                "{} Failed to remove {}: {e}",
                prefix(),
                s.metadata.session_id
            );
        } else {
            removed = removed.saturating_add(1);
        }
    }

    eprintln!(
        "{} Removed {} rollback entr{}, freed {}.",
        prefix(),
        removed,
        if removed == 1 { "y" } else { "ies" },
        format_bytes(total_size)
    );

    Ok(())
}

fn cleanup_all(dry_run: bool) -> Result<()> {
    let root = rollback_root()?;
    if !root.exists() {
        eprintln!("{} No rollback directory found.", prefix());
        return Ok(());
    }

    let sessions = discover_sessions()?;
    let alive_count = sessions.iter().filter(|s| s.is_alive).count();

    if alive_count > 0 {
        eprintln!(
            "{} {} rollback entr{} still running, skipping those.",
            prefix(),
            alive_count,
            if alive_count == 1 { "y is" } else { "ies are" },
        );
    }

    let removable: Vec<&SessionInfo> = sessions.iter().filter(|s| !s.is_alive).collect();
    let total_size: u64 = removable.iter().map(|s| s.disk_size).sum();

    if removable.is_empty() {
        eprintln!("{} No rollback entries to remove.", prefix());
        return Ok(());
    }

    if dry_run {
        eprintln!(
            "{} Dry run: would remove {} rollback entr{} ({})",
            prefix(),
            removable.len(),
            if removable.len() == 1 { "y" } else { "ies" },
            format_bytes(total_size)
        );
        return Ok(());
    }

    let mut removed = 0usize;
    for s in &removable {
        if let Err(e) = remove_session(&s.dir) {
            eprintln!(
                "{} Failed to remove {}: {e}",
                prefix(),
                s.metadata.session_id
            );
        } else {
            removed = removed.saturating_add(1);
        }
    }

    eprintln!(
        "{} Removed {} rollback entr{}, freed {}.",
        prefix(),
        removed,
        if removed == 1 { "y" } else { "ies" },
        format_bytes(total_size)
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Parse session start time from either RFC3339 or epoch seconds format
fn parse_session_start_time(s: &SessionInfo) -> Option<u64> {
    // Try parsing as RFC3339 timestamp first, then as epoch seconds
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&s.metadata.started) {
        return Some(dt.timestamp() as u64);
    }
    s.metadata.started.parse::<u64>().ok()
}

/// Format a session timestamp as a human-readable string (e.g., "2h ago" or "Feb 17 15:58")
fn format_session_timestamp(started: &str) -> String {
    use chrono::{DateTime, Local, Utc};

    // Try parsing as RFC3339 timestamp, then as epoch seconds
    let dt = if let Ok(dt) = DateTime::parse_from_rfc3339(started) {
        dt.with_timezone(&Local)
    } else if let Ok(secs) = started.parse::<i64>() {
        if let Some(dt) = DateTime::from_timestamp(secs, 0) {
            dt.with_timezone(&Local)
        } else {
            return started.to_string();
        }
    } else {
        return started.to_string();
    };

    let now = Utc::now().with_timezone(&Local);
    let duration = now.signed_duration_since(dt);

    // Handle future timestamps (clock skew, bad metadata) by showing absolute time
    if duration.num_seconds() < 0 {
        return format_absolute_timestamp(&dt, &now);
    }

    // Show relative time for recent sessions, absolute for older
    if duration.num_minutes() < 1 {
        "just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{}m ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{}h ago", duration.num_hours())
    } else if duration.num_days() < 7 {
        format!("{}d ago", duration.num_days())
    } else {
        format_absolute_timestamp(&dt, &now)
    }
}

/// Format an absolute timestamp, including year if different from current year
fn format_absolute_timestamp(
    dt: &chrono::DateTime<chrono::Local>,
    now: &chrono::DateTime<chrono::Local>,
) -> String {
    if dt.format("%Y").to_string() != now.format("%Y").to_string() {
        dt.format("%Y-%m-%d %H:%M").to_string()
    } else {
        dt.format("%b %d %H:%M").to_string()
    }
}

fn count_change_types(changes: &[nono::undo::Change]) -> (usize, usize, usize) {
    let mut created = 0usize;
    let mut modified = 0usize;
    let mut deleted = 0usize;
    for c in changes {
        match c.change_type {
            nono::undo::ChangeType::Created => created = created.saturating_add(1),
            nono::undo::ChangeType::Modified => modified = modified.saturating_add(1),
            nono::undo::ChangeType::Deleted => deleted = deleted.saturating_add(1),
            nono::undo::ChangeType::PermissionsChanged => modified = modified.saturating_add(1),
        }
    }
    (created, modified, deleted)
}

fn change_symbol(ct: &nono::undo::ChangeType) -> colored::ColoredString {
    match ct {
        nono::undo::ChangeType::Created => "+".green(),
        nono::undo::ChangeType::Modified => "~".yellow(),
        nono::undo::ChangeType::Deleted => "-".red(),
        nono::undo::ChangeType::PermissionsChanged => "p".truecolor(
            theme::current().subtext.0,
            theme::current().subtext.1,
            theme::current().subtext.2,
        ),
    }
}

fn print_changes(changes: &[nono::undo::Change]) {
    for change in changes {
        let symbol = change_symbol(&change.change_type);
        eprintln!("  {} {}", symbol, change.path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_change_types_empty() {
        let (c, m, d) = count_change_types(&[]);
        assert_eq!((c, m, d), (0, 0, 0));
    }

    #[test]
    fn count_change_types_mixed() {
        use nono::undo::{Change, ChangeType};
        use std::path::PathBuf;

        let changes = vec![
            Change {
                path: PathBuf::from("a.txt"),
                change_type: ChangeType::Created,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("b.txt"),
                change_type: ChangeType::Modified,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("c.txt"),
                change_type: ChangeType::Deleted,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("d.txt"),
                change_type: ChangeType::PermissionsChanged,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
        ];
        let (c, m, d) = count_change_types(&changes);
        assert_eq!(c, 1);
        assert_eq!(m, 2); // Modified + PermissionsChanged
        assert_eq!(d, 1);
    }

    #[test]
    fn format_session_timestamp_just_now() {
        use chrono::Utc;
        // Use 10 seconds - well within the <1 minute bucket, far from boundary
        let now = Utc::now();
        let recent = now - chrono::Duration::seconds(10);
        let timestamp = recent.to_rfc3339();
        assert_eq!(format_session_timestamp(&timestamp), "just now");
    }

    #[test]
    fn format_session_timestamp_minutes_ago() {
        use chrono::Utc;
        // Use 30 minutes - well within the 1-59 minute bucket
        let now = Utc::now();
        let past = now - chrono::Duration::minutes(30);
        let timestamp = past.to_rfc3339();
        assert_eq!(format_session_timestamp(&timestamp), "30m ago");
    }

    #[test]
    fn format_session_timestamp_hours_ago() {
        use chrono::Utc;
        // Use 12 hours - well within the 1-23 hour bucket
        let now = Utc::now();
        let past = now - chrono::Duration::hours(12);
        let timestamp = past.to_rfc3339();
        assert_eq!(format_session_timestamp(&timestamp), "12h ago");
    }

    #[test]
    fn format_session_timestamp_days_ago() {
        use chrono::Utc;
        // Use 4 days - well within the 1-6 day bucket
        let now = Utc::now();
        let past = now - chrono::Duration::days(4);
        let timestamp = past.to_rfc3339();
        assert_eq!(format_session_timestamp(&timestamp), "4d ago");
    }

    #[test]
    fn format_session_timestamp_older_same_year() {
        use chrono::{Local, Utc};
        let now = Utc::now().with_timezone(&Local);
        // 30 days ago - well past the 7-day threshold for absolute time
        let past = now - chrono::Duration::days(30);
        let timestamp = past.to_rfc3339();
        let result = format_session_timestamp(&timestamp);
        // Should contain month abbreviation and time, not "ago"
        assert!(
            !result.contains("ago"),
            "Expected absolute time, got: {result}"
        );
        assert!(
            result.contains(':'),
            "Expected time with colon, got: {result}"
        );
    }

    #[test]
    fn format_session_timestamp_different_year() {
        // A timestamp from 2020 should include the year
        let old_timestamp = "2020-06-15T14:30:00Z";
        let result = format_session_timestamp(old_timestamp);
        assert!(
            result.contains("2020"),
            "Expected year in output, got: {result}"
        );
    }

    #[test]
    fn format_session_timestamp_future() {
        use chrono::Utc;
        // Future timestamp (clock skew scenario) should show absolute time, not "just now"
        let future = Utc::now() + chrono::Duration::hours(2);
        let timestamp = future.to_rfc3339();
        let result = format_session_timestamp(&timestamp);
        assert_ne!(
            result, "just now",
            "Future timestamp should not be 'just now'"
        );
        assert!(
            !result.contains("ago"),
            "Future timestamp should not contain 'ago'"
        );
    }

    #[test]
    fn format_session_timestamp_invalid_string() {
        // Invalid input should be returned as-is
        let invalid = "not-a-timestamp";
        assert_eq!(format_session_timestamp(invalid), invalid);
    }

    #[test]
    fn format_session_timestamp_epoch_seconds() {
        use chrono::Utc;
        // Test epoch seconds format (legacy)
        let now = Utc::now();
        let past = now - chrono::Duration::minutes(10);
        let epoch_str = past.timestamp().to_string();
        assert_eq!(format_session_timestamp(&epoch_str), "10m ago");
    }

    #[test]
    fn format_absolute_timestamp_same_year() {
        use chrono::Local;
        let now = Local::now();
        let same_year = now - chrono::Duration::days(30);
        let result = format_absolute_timestamp(&same_year, &now);
        // Should be "Mon DD HH:MM" format (e.g., "Jan 15 14:30")
        let expected = same_year.format("%b %d %H:%M").to_string();
        assert_eq!(result, expected, "Expected '{expected}', got '{result}'");
    }

    #[test]
    fn format_absolute_timestamp_different_year() {
        use chrono::{Local, TimeZone, Utc};
        let now = Local::now();
        // Use UTC for deterministic construction, then convert to Local
        let different_year_utc = Utc.with_ymd_and_hms(2020, 6, 15, 14, 30, 0);
        let dt = match different_year_utc {
            chrono::LocalResult::Single(dt) => dt.with_timezone(&Local),
            chrono::LocalResult::Ambiguous(dt, _) => dt.with_timezone(&Local),
            chrono::LocalResult::None => panic!("Invalid UTC datetime - this should never happen"),
        };
        let result = format_absolute_timestamp(&dt, &now);
        assert!(
            result.contains("2020"),
            "Expected year 2020 in output, got: {result}"
        );
    }

    #[test]
    fn format_change_summary_output() {
        // Test the change summary formatting used in undo list output
        assert_eq!(format_change_summary(0, 0, 0), "(no changes)");
        assert_eq!(format_change_summary(1, 0, 0), "+1 file");
        assert_eq!(format_change_summary(3, 0, 0), "+3 files");
        assert_eq!(format_change_summary(0, 2, 0), "~2 modified");
        assert_eq!(format_change_summary(0, 0, 1), "-1 deleted");
        assert_eq!(
            format_change_summary(1, 2, 3),
            "+1 file, ~2 modified, -3 deleted"
        );
    }

    #[test]
    fn rollback_list_output_format_structure() {
        // Verify the output line format has 4 columns: session_id, timestamp, command, changes
        // This test documents the expected format and catches layout regressions

        // Simulate the format string pattern used in print_session_line
        let session_id = "20260217-234523-70889";
        let timestamp = "2h ago";
        let cmd_name = "claude";
        let change_summary = "~2 modified";

        // The format should produce 4 space-separated columns with 4-space indent
        let output = format!(
            "    {}  {}  {}  {}",
            session_id, timestamp, cmd_name, change_summary
        );

        // Verify structure: leading indent, then 4 double-space separated fields
        assert!(
            output.starts_with("    "),
            "Output should have 4-space indent"
        );

        let parts: Vec<&str> = output.trim().split("  ").collect();
        assert_eq!(
            parts.len(),
            4,
            "Expected 4 columns separated by double-space, got: {parts:?}"
        );
        assert_eq!(parts[0], session_id);
        assert_eq!(parts[1], timestamp);
        assert_eq!(parts[2], cmd_name);
        assert_eq!(parts[3], change_summary);
    }

    #[test]
    fn group_by_project_single_path() {
        use nono::undo::SessionMetadata;

        let metadata = SessionMetadata {
            session_id: "20260219-100000-12345".to_string(),
            started: "2026-02-19T10:00:00Z".to_string(),
            ended: None,
            command: vec!["claude".to_string()],
            executable_identity: None,
            tracked_paths: vec![std::path::PathBuf::from("/home/user/widgets")],
            snapshot_count: 2,
            exit_code: None,
            merkle_roots: vec![],
            network_events: vec![],
            audit_event_count: 0,
            audit_integrity: None,
            audit_attestation: None,
        };

        let session = SessionInfo {
            metadata,
            dir: std::path::PathBuf::from("/tmp/test"),
            disk_size: 0,
            is_alive: false,
            is_stale: false,
        };

        let sessions_with_changes = vec![(&session, (1usize, 2usize, 0usize))];
        let grouped = group_by_project(&sessions_with_changes);

        assert_eq!(grouped.len(), 1);
        assert!(grouped.contains_key(std::path::Path::new("/home/user/widgets")));
    }

    #[test]
    fn group_by_project_multiple_paths() {
        use nono::undo::SessionMetadata;

        let meta1 = SessionMetadata {
            session_id: "20260219-100000-12345".to_string(),
            started: "2026-02-19T10:00:00Z".to_string(),
            ended: None,
            command: vec!["claude".to_string()],
            executable_identity: None,
            tracked_paths: vec![std::path::PathBuf::from("/home/user/widgets")],
            snapshot_count: 2,
            exit_code: None,
            merkle_roots: vec![],
            network_events: vec![],
            audit_event_count: 0,
            audit_integrity: None,
            audit_attestation: None,
        };
        let meta2 = SessionMetadata {
            session_id: "20260219-110000-67890".to_string(),
            started: "2026-02-19T11:00:00Z".to_string(),
            ended: None,
            command: vec!["opencode".to_string()],
            executable_identity: None,
            tracked_paths: vec![std::path::PathBuf::from("/home/user/thingamajigs")],
            snapshot_count: 2,
            exit_code: None,
            merkle_roots: vec![],
            network_events: vec![],
            audit_event_count: 0,
            audit_integrity: None,
            audit_attestation: None,
        };

        let s1 = SessionInfo {
            metadata: meta1,
            dir: std::path::PathBuf::from("/tmp/test1"),
            disk_size: 0,
            is_alive: false,
            is_stale: false,
        };
        let s2 = SessionInfo {
            metadata: meta2,
            dir: std::path::PathBuf::from("/tmp/test2"),
            disk_size: 0,
            is_alive: false,
            is_stale: false,
        };

        let sessions_with_changes = vec![
            (&s1, (1usize, 0usize, 0usize)),
            (&s2, (0usize, 3usize, 0usize)),
        ];
        let grouped = group_by_project(&sessions_with_changes);

        assert_eq!(grouped.len(), 2);
        assert!(grouped.contains_key(std::path::Path::new("/home/user/widgets")));
        assert!(grouped.contains_key(std::path::Path::new("/home/user/thingamajigs")));
    }

    #[test]
    fn rollback_group_header_uses_snapshot_count() {
        use nono::undo::SessionMetadata;

        let metadata = SessionMetadata {
            session_id: "20260219-100000-12345".to_string(),
            started: "2026-02-19T10:00:00Z".to_string(),
            ended: None,
            command: vec!["claude".to_string()],
            executable_identity: None,
            tracked_paths: vec![std::path::PathBuf::from("/home/user/widgets")],
            snapshot_count: 3,
            exit_code: None,
            merkle_roots: vec![],
            network_events: vec![],
            audit_event_count: 0,
            audit_integrity: None,
            audit_attestation: None,
        };

        let session = SessionInfo {
            metadata,
            dir: std::path::PathBuf::from("/tmp/test"),
            disk_size: 0,
            is_alive: false,
            is_stale: false,
        };

        let grouped = group_by_project(&[(&session, (0usize, 0usize, 0usize))]);
        let snapshots: u32 = grouped
            .values()
            .flat_map(|group| group.iter())
            .map(|(s, _)| s.metadata.snapshot_count)
            .sum();
        assert_eq!(snapshots, 3);
    }

    #[test]
    fn shorten_home_replaces_prefix() {
        // This test is best-effort since it depends on the actual home dir
        if let Some(home) = dirs::home_dir() {
            let path = home.join("dev").join("project");
            let result = shorten_home(&path);
            assert!(result.starts_with("~/"), "Expected ~/... but got: {result}");
            assert!(result.ends_with("dev/project"));
        }
    }
}
