//! Audit subcommand implementations
//!
//! Handles `nono audit list|show|verify` for viewing the audit trail of
//! sandboxed sessions and verifying the cryptographic integrity of an
//! audit-protected session.

use crate::audit_attestation::verify_audit_attestation;
use crate::audit_integrity::verify_audit_log;
use crate::audit_session::load_session;
use crate::cli::{
    AuditArgs, AuditCleanupArgs, AuditCommands, AuditListArgs, AuditShowArgs, AuditVerifyArgs,
};
use crate::rollback_session::{discover_sessions, remove_session, SessionInfo};
use crate::theme;
use colored::Colorize;
use nono::undo::SnapshotManager;
use nono::{NonoError, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Prefix used for all audit command output
fn prefix() -> colored::ColoredString {
    let t = theme::current();
    theme::fg("nono", t.brand).bold()
}

/// Dispatch to the appropriate audit subcommand.
pub fn run_audit(args: AuditArgs) -> Result<()> {
    match args.command {
        AuditCommands::List(args) => cmd_list(args),
        AuditCommands::Show(args) => cmd_show(args),
        AuditCommands::Verify(args) => cmd_verify(args),
        AuditCommands::Cleanup(args) => cmd_cleanup(args),
    }
}

// ---------------------------------------------------------------------------
// nono audit cleanup
// ---------------------------------------------------------------------------

/// Plan 22-05b Task 2 (upstream `4f9552ec`): peer to `nono session cleanup`,
/// operates on audit ledger sessions. AUD-04 acceptance #2.
///
/// Filters audit-tracked sessions by `--older-than` (in DAYS, matching
/// upstream's `Option<u64>` shape) and/or `--keep` (retain N newest), or
/// `--all` (remove every non-active audit session). Active sessions
/// (`is_alive == true`) are skipped to mirror the runtime-side
/// `auto_prune_if_needed` retention contract.
///
/// `--dry-run` previews what would be removed without deleting.
fn cmd_cleanup(args: AuditCleanupArgs) -> Result<()> {
    if args.keep.is_none() && args.older_than.is_none() && !args.all {
        return Err(NonoError::ConfigParse(
            "audit cleanup: specify one of --keep <N>, --older-than <DAYS>, or --all".to_string(),
        ));
    }

    let mut sessions = discover_sessions()?;
    // Newest first so `--keep N` is intuitive.
    sessions.sort_by(|a, b| b.metadata.started.cmp(&a.metadata.started));

    // Filter to sessions that have an audit ledger (audit_integrity recorded
    // OR audit-tracked paths present). Don't touch rollback-only sessions.
    let mut audit_sessions: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|s| s.metadata.audit_integrity.is_some() || !s.metadata.tracked_paths.is_empty())
        .collect();

    // Always skip active sessions.
    audit_sessions.retain(|s| !s.is_alive);

    let to_remove: Vec<&SessionInfo> = if args.all {
        audit_sessions.clone()
    } else {
        let mut filtered: Vec<&SessionInfo> = Vec::new();

        if let Some(days) = args.older_than {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| NonoError::Snapshot(format!("System time error: {e}")))?
                .as_secs();
            let cutoff = now.saturating_sub(days.saturating_mul(86_400));
            for s in &audit_sessions {
                if let Some(started) = parse_session_start_time(s) {
                    if started <= cutoff {
                        filtered.push(s);
                    }
                }
            }
        }

        if let Some(keep) = args.keep {
            // Newest-first list; everything past index `keep` is eligible.
            for s in audit_sessions.iter().skip(keep) {
                if !filtered.iter().any(|x| x.dir == s.dir) {
                    filtered.push(s);
                }
            }
        }

        filtered
    };

    if to_remove.is_empty() {
        eprintln!("{} No audit sessions match the cleanup filters.", prefix());
        return Ok(());
    }

    if args.dry_run {
        eprintln!(
            "{} Would remove {} audit session(s):",
            prefix(),
            to_remove.len()
        );
        for s in &to_remove {
            eprintln!("  {} ({})", s.metadata.session_id, s.metadata.started);
        }
        return Ok(());
    }

    let mut removed = 0usize;
    let mut errors: Vec<(String, String)> = Vec::new();
    for s in &to_remove {
        match remove_session(&s.dir) {
            Ok(()) => removed += 1,
            Err(e) => errors.push((s.metadata.session_id.clone(), format!("{e}"))),
        }
    }

    eprintln!(
        "{} Removed {}/{} audit session(s).",
        prefix(),
        removed,
        to_remove.len()
    );
    for (id, err) in &errors {
        eprintln!("  warning: failed to remove {id}: {err}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// nono audit list
// ---------------------------------------------------------------------------

fn cmd_list(args: AuditListArgs) -> Result<()> {
    let mut sessions = discover_sessions()?;

    // Apply filters
    sessions = filter_sessions(sessions, &args)?;

    if let Some(n) = args.recent {
        sessions.truncate(n);
    }

    if args.json {
        return print_list_json(&sessions);
    }

    if sessions.is_empty() {
        eprintln!("{} No sessions found matching filters.", prefix());
        return Ok(());
    }

    // Group sessions by their primary tracked path (project directory)
    let grouped = group_by_project(&sessions);
    eprintln!("{} {} session(s)\n", prefix(), sessions.len());

    for (project_path, group) in &grouped {
        let display_path = shorten_home(project_path);
        eprintln!(
            "  {} ({} session{})",
            display_path.white().bold(),
            group.len(),
            if group.len() == 1 { "" } else { "s" },
        );
        for s in group {
            let cmd = truncate_command(&s.metadata.command, 35);
            let status = session_status_label(s);
            eprintln!(
                "    {} {} {}",
                s.metadata.session_id,
                status,
                theme::fg(&cmd, theme::current().subtext),
            );
        }
        eprintln!();
    }

    Ok(())
}

fn filter_sessions(
    mut sessions: Vec<SessionInfo>,
    args: &AuditListArgs,
) -> Result<Vec<SessionInfo>> {
    // Filter by --today
    if args.today {
        let today_start = today_start_epoch()?;
        sessions.retain(|s| {
            parse_session_start_time(s)
                .map(|t| t >= today_start)
                .unwrap_or(false)
        });
    }

    // Filter by --since
    if let Some(ref since) = args.since {
        let since_epoch = parse_date_to_epoch(since)?;
        sessions.retain(|s| {
            parse_session_start_time(s)
                .map(|t| t >= since_epoch)
                .unwrap_or(false)
        });
    }

    // Filter by --until
    if let Some(ref until) = args.until {
        let until_epoch = parse_date_to_epoch(until)?.saturating_add(86400); // End of day
        sessions.retain(|s| {
            parse_session_start_time(s)
                .map(|t| t < until_epoch)
                .unwrap_or(false)
        });
    }

    // Filter by --command
    if let Some(ref cmd_filter) = args.command {
        let filter_lower = cmd_filter.to_lowercase();
        sessions.retain(|s| {
            s.metadata
                .command
                .first()
                .map(|c| c.to_lowercase().contains(&filter_lower))
                .unwrap_or(false)
        });
    }

    // Filter by --path
    if let Some(ref path_filter) = args.path {
        sessions.retain(|s| {
            s.metadata
                .tracked_paths
                .iter()
                .any(|p| p.starts_with(path_filter) || path_filter.starts_with(p))
        });
    }

    Ok(sessions)
}

fn parse_session_start_time(s: &SessionInfo) -> Option<u64> {
    // Try parsing as ISO timestamp first, then as epoch seconds
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&s.metadata.started) {
        return Some(dt.timestamp() as u64);
    }
    s.metadata.started.parse::<u64>().ok()
}

fn today_start_epoch() -> Result<u64> {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| NonoError::Snapshot(format!("System time error: {e}")))?
        .as_secs();
    // Round down to start of day (UTC)
    Ok(now - (now % 86400))
}

fn parse_date_to_epoch(date_str: &str) -> Result<u64> {
    // Parse YYYY-MM-DD format
    let dt = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .map_err(|e| NonoError::Snapshot(format!("Invalid date format '{}': {}", date_str, e)))?;
    Ok(dt
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| NonoError::Snapshot("Invalid time".to_string()))?
        .and_utc()
        .timestamp() as u64)
}

fn print_list_json(sessions: &[SessionInfo]) -> Result<()> {
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
                "network_event_count": s.metadata.network_events.len(),
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
// nono audit show
// ---------------------------------------------------------------------------

/// Phase 23 D-04 layer-2 surface: re-read the per-session NDJSON ledger and
/// return one `serde_json::Value` per `capability_decision` event. Mirrors
/// the BufReader+lines reader pattern from `audit_integrity::verify_audit_log`
/// to avoid a parallel NDJSON parser.
///
/// Best-effort: on file-missing or per-line parse error, returns
/// `Ok(vec![])` (empty list) rather than failing the audit-show command.
/// The integrity summary path (already-rendered by `cmd_show`) is the
/// load-bearing failure surface; this function is a UX add and must
/// degrade gracefully.
fn read_capability_decisions_from_ledger(
    session_dir: &std::path::Path,
) -> Result<Vec<serde_json::Value>> {
    let events_path = session_dir.join(crate::audit_integrity::AUDIT_EVENTS_FILENAME);
    let file = match std::fs::File::open(&events_path) {
        Ok(f) => f,
        Err(_) => return Ok(Vec::new()),
    };
    let reader = std::io::BufReader::new(file);
    let mut decisions = Vec::new();
    for line_result in std::io::BufRead::lines(reader) {
        let Ok(line) = line_result else { continue };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if record
            .get("event")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str())
            == Some("capability_decision")
        {
            decisions.push(record);
        }
    }
    Ok(decisions)
}

fn cmd_show(args: AuditShowArgs) -> Result<()> {
    // D-27.2-04 cascade: cmd_show, like cmd_verify, uses the audit-aware
    // loader so audit-only sessions written under <home>/.nono/audit/<id>/
    // are findable. The local `SessionInfo` here is the rollback_session
    // shape (used by helpers like print_show_json / session_status_label
    // that are also called from cmd_list); both structs have the identical
    // {metadata, dir, disk_size, is_alive, is_stale} field shape, so we
    // shim the audit-side hit into the rollback-side type at this single
    // boundary. Keeps the helper signatures untouched (out of Phase 27.2
    // scope) while honoring D-27.2-04 always-audit-first.
    let audit_session_info = load_session(&args.session_id)?;
    let session = SessionInfo {
        metadata: audit_session_info.metadata,
        dir: audit_session_info.dir,
        disk_size: audit_session_info.disk_size,
        is_alive: audit_session_info.is_alive,
        is_stale: audit_session_info.is_stale,
    };

    if args.json {
        return print_show_json(&session);
    }

    let status = session_status_label(&session);
    eprintln!(
        "{} Audit trail for session: {} {}",
        prefix(),
        session.metadata.session_id.white().bold(),
        status
    );
    eprintln!(
        "  Command:  {}",
        theme::fg(
            &session.metadata.command.join(" "),
            theme::current().subtext
        )
    );
    eprintln!("  Started:  {}", session.metadata.started);
    if let Some(ref ended) = session.metadata.ended {
        eprintln!("  Ended:    {ended}");
    }
    if let Some(code) = session.metadata.exit_code {
        eprintln!("  Exit:     {code}");
    }

    let paths: Vec<String> = session
        .metadata
        .tracked_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    eprintln!("  Paths:    {}", paths.join(", "));

    // AUD-03 SHA-256 portion (upstream 02ee0bd1): surface executable
    // identity (canonical path + SHA-256) when recorded.
    if let Some(identity) = session.metadata.executable_identity.as_ref() {
        eprintln!(
            "  Binary:   {} (sha256:{})",
            identity.resolved_path.display(),
            &identity.sha256.to_string()[..16],
        );
    }

    // Plan 22-05a Decision 5 minimal scope: surface the audit-integrity
    // summary (chain_head + merkle_root + event_count) when the session was
    // recorded with `--audit-integrity`. Fields are absent for sessions
    // recorded before this commit landed.
    if let Some(integrity) = session.metadata.audit_integrity.as_ref() {
        eprintln!();
        eprintln!("  Audit Integrity:");
        eprintln!("    Algorithm:     {}", integrity.hash_algorithm);
        eprintln!("    Event count:   {}", integrity.event_count);
        eprintln!("    Chain head:    {}", integrity.chain_head);
        eprintln!("    Merkle root:   {}", integrity.merkle_root);
    } else if session.metadata.audit_event_count > 0 {
        eprintln!();
        eprintln!(
            "  Audit Events:   {} (no integrity summary)",
            session.metadata.audit_event_count
        );
    }

    // Phase 23 D-04: Capability Decisions counter (Windows AIPC ledger
    // surface). Per-event browsing intentionally deferred to --json
    // (counter is enough for AUD-05 acceptance #1; future v2.3 backlog
    // item may add a `nono audit show <id> --stage before-prompt` filter
    // — see CONTEXT.md § Deferred Ideas).
    let decisions = read_capability_decisions_from_ledger(&session.dir).unwrap_or_default();
    if !decisions.is_empty() {
        let total = decisions.len();
        let before_prompt = decisions
            .iter()
            .filter(|d| {
                d.pointer("/event/reject_stage").and_then(|v| v.as_str()) == Some("before-prompt")
            })
            .count();
        let after_prompt = decisions
            .iter()
            .filter(|d| {
                d.pointer("/event/reject_stage").and_then(|v| v.as_str()) == Some("after-prompt")
            })
            .count();
        eprintln!();
        eprintln!(
            "  Capability Decisions: {total} ({before_prompt} before-prompt, {after_prompt} after-prompt rejections)"
        );
    }
    eprintln!();

    // Show snapshot details
    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if i == 0 {
            eprintln!(
                "  [{}] Baseline at {}  ({} files, root: {})",
                format!("{i:03}").white().bold(),
                manifest.timestamp,
                manifest.files.len(),
                &manifest.merkle_root.to_string()[..16],
            );
        } else {
            let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();
            eprintln!(
                "  [{}] Snapshot at {}  (root: {})",
                format!("{i:03}").white().bold(),
                manifest.timestamp,
                &manifest.merkle_root.to_string()[..16],
            );

            for change in &changes {
                let symbol = change_symbol(&change.change_type);
                eprintln!("        {} {}", symbol, change.path.display());
            }
        }
    }

    if !session.metadata.network_events.is_empty() {
        eprintln!();
        eprintln!(
            "  Network Events: {}",
            session.metadata.network_events.len()
        );
        for event in &session.metadata.network_events {
            let decision = match event.decision {
                nono::undo::NetworkAuditDecision::Allow => "allow".green(),
                nono::undo::NetworkAuditDecision::Deny => "deny".red(),
            };
            let mode = network_mode_label(&event.mode);
            let mut target = sanitize_for_terminal(&event.target);
            if let Some(port) = event.port {
                target = format!("{target}:{port}");
            }

            let mut details = Vec::new();
            if let Some(ref method) = event.method {
                details.push(format!("method={}", sanitize_for_terminal(method)));
            }
            if let Some(ref path) = event.path {
                details.push(format!("path={}", sanitize_for_terminal(path)));
            }
            if let Some(status) = event.status {
                details.push(format!("status={status}"));
            }
            if let Some(ref reason) = event.reason {
                details.push(format!("reason={}", sanitize_for_terminal(reason)));
            }

            if details.is_empty() {
                eprintln!("    {} {} {}", decision, mode, target);
            } else {
                eprintln!(
                    "    {} {} {} ({})",
                    decision,
                    mode,
                    target,
                    details.join(", ")
                );
            }
        }
    }

    Ok(())
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
            "file_count": manifest.files.len(),
            "merkle_root": manifest.merkle_root.to_string(),
            "changes": changes.iter().map(|c| serde_json::json!({
                "path": c.path.display().to_string(),
                "type": format!("{}", c.change_type),
                "size_delta": c.size_delta,
                "old_hash": c.old_hash.map(|h| h.to_string()),
                "new_hash": c.new_hash.map(|h| h.to_string()),
            })).collect::<Vec<_>>(),
        }));
    }

    // Plan 22-05a Decision 5 minimal scope: include audit-integrity summary
    // in JSON output when present. Absent for sessions recorded before this
    // commit landed; null is the canonical absence marker.
    let audit_integrity_json = session.metadata.audit_integrity.as_ref().map(|s| {
        serde_json::json!({
            "hash_algorithm": s.hash_algorithm,
            "event_count": s.event_count,
            "chain_head": s.chain_head.to_string(),
            "merkle_root": s.merkle_root.to_string(),
        })
    });

    // AUD-03 SHA-256 portion (upstream 02ee0bd1): include executable
    // identity in JSON output when present.
    let executable_identity_json = session.metadata.executable_identity.as_ref().map(|e| {
        serde_json::json!({
            "resolved_path": e.resolved_path.display().to_string(),
            "sha256": e.sha256.to_string(),
        })
    });

    // Phase 23 D-04: include the per-event `capability_decision` array
    // (re-read from `<session_dir>/audit-events.ndjson` via the same
    // helper as the human-readable counter line). `null` when the ledger
    // is missing or contains no capability_decision events — preserving
    // the established Phase 22-05a `audit_integrity` precedent for
    // optional fields.
    let capability_decisions_json = read_capability_decisions_from_ledger(&session.dir)
        .ok()
        .filter(|v| !v.is_empty());

    let output = serde_json::json!({
        "session_id": session.metadata.session_id,
        "started": session.metadata.started,
        "ended": session.metadata.ended,
        "command": session.metadata.command,
        "executable_identity": executable_identity_json,
        "tracked_paths": session.metadata.tracked_paths,
        "exit_code": session.metadata.exit_code,
        "merkle_roots": session.metadata.merkle_roots.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        "network_events": &session.metadata.network_events,
        "audit_event_count": session.metadata.audit_event_count,
        "audit_integrity": audit_integrity_json,
        "capability_decisions": capability_decisions_json,
        "snapshots": snapshots,
    });

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// nono audit verify
// ---------------------------------------------------------------------------

/// Verify the cryptographic integrity of an audit session (Plan 22-05a
/// Task 6, upstream `0b1822a9`). Returns `NonoError::Snapshot` with
/// "verification failed" message on tamper detection so the CLI exits
/// non-zero.
fn cmd_verify(args: AuditVerifyArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;
    let result = verify_audit_log(&session.dir, session.metadata.audit_integrity.as_ref())?;

    // Plan 22-05a Task 7 (upstream 6ecade2e): if the session was signed,
    // verify the attestation bundle. HG-01-H fix (Phase 22 review): the
    // verifier now cryptographically checks the DSSE signature AND that
    // the bundle's subjects match the recorded `(session_id, chain_head,
    // merkle_root)` tuple. Verification requires the integrity summary,
    // which must be present whenever an attestation is present.
    let attestation_status = match (
        session.metadata.audit_attestation.as_ref(),
        session.metadata.audit_integrity.as_ref(),
    ) {
        (Some(att), Some(integrity)) => Some(verify_audit_attestation(
            &session.dir,
            att,
            &session.metadata.session_id,
            integrity,
            args.public_key_file.as_deref(),
        )?),
        // Attestation present but no integrity summary recorded —
        // fail-closed: there is nothing to bind the signature to.
        (Some(_), None) => Some(false),
        (None, _) => None,
    };

    if args.json {
        let output = serde_json::json!({
            "integrity": &result,
            "attestation_present": session.metadata.audit_attestation.is_some(),
            "attestation_valid": attestation_status,
        });
        let json = serde_json::to_string_pretty(&output)
            .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        eprintln!(
            "{} Audit verification for session: {}",
            prefix(),
            session.metadata.session_id.white().bold(),
        );
        eprintln!("  Algorithm:           {}", result.hash_algorithm);
        eprintln!("  Merkle scheme:       {}", result.merkle_scheme);
        eprintln!("  Event count:         {}", result.event_count);
        eprintln!(
            "  Records verified:    {}",
            if result.records_verified {
                "yes".green()
            } else {
                "no".red()
            },
        );
        eprintln!(
            "  Event count match:   {}",
            yes_no_color(result.event_count_matches),
        );
        eprintln!(
            "  Chain head match:    {}",
            yes_no_color(result.chain_head_matches),
        );
        eprintln!(
            "  Merkle root match:   {}",
            yes_no_color(result.merkle_root_matches),
        );
        if let Some(att_ok) = attestation_status {
            eprintln!("  Attestation:         {}", yes_no_color(att_ok));
        }
    }

    let attestation_failed = matches!(attestation_status, Some(false));
    if !result.is_valid() || attestation_failed {
        return Err(NonoError::Snapshot(format!(
            "audit verification failed for session {}",
            session.metadata.session_id,
        )));
    }
    Ok(())
}

fn yes_no_color(value: bool) -> colored::ColoredString {
    if value {
        "yes".green()
    } else {
        "no".red()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn session_status_label(s: &SessionInfo) -> colored::ColoredString {
    if s.is_alive {
        "running".green()
    } else if s.is_stale {
        "orphaned".yellow()
    } else {
        theme::fg("completed", theme::current().subtext)
    }
}

fn group_by_project(sessions: &[SessionInfo]) -> BTreeMap<PathBuf, Vec<&SessionInfo>> {
    let mut groups: BTreeMap<PathBuf, Vec<&SessionInfo>> = BTreeMap::new();
    for s in sessions {
        let project = s
            .metadata
            .tracked_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("(unknown)"));
        groups.entry(project).or_default().push(s);
    }
    groups
}

fn shorten_home(path: &Path) -> String {
    let s = path.display().to_string();
    if let Ok(home) = crate::config::nono_home_dir() {
        let home_str = home.display().to_string();
        if let Some(rest) = s.strip_prefix(&home_str) {
            return format!("~{rest}");
        }
    }
    s
}

fn truncate_command(cmd: &[String], max_len: usize) -> String {
    let full = cmd.join(" ");
    if full.len() <= max_len {
        full
    } else {
        format!("{}...", &full[..max_len.saturating_sub(3)])
    }
}

fn change_symbol(ct: &nono::undo::ChangeType) -> colored::ColoredString {
    match ct {
        nono::undo::ChangeType::Created => "+".green(),
        nono::undo::ChangeType::Modified => "~".yellow(),
        nono::undo::ChangeType::Deleted => "-".red(),
        nono::undo::ChangeType::PermissionsChanged => theme::fg("p", theme::current().subtext),
    }
}

fn network_mode_label(mode: &nono::undo::NetworkAuditMode) -> &'static str {
    match mode {
        nono::undo::NetworkAuditMode::Connect => "connect",
        nono::undo::NetworkAuditMode::Reverse => "reverse",
        nono::undo::NetworkAuditMode::External => "external",
    }
}

/// Strip control characters and ANSI escape sequences from untrusted text
/// before printing to the terminal.
fn sanitize_for_terminal(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI sequence: consume until final byte 0x40-0x7E
                    chars.next();
                    for seq_c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&seq_c) {
                            break;
                        }
                    }
                } else if matches!(next, ']' | 'P' | '_' | '^' | 'X') {
                    // OSC/DCS/APC/PM/SOS: consume until ST (ESC \) or BEL
                    chars.next();
                    let mut prev = '\0';
                    for seq_c in chars.by_ref() {
                        if seq_c == '\x07' || (prev == '\x1b' && seq_c == '\\') {
                            break;
                        }
                        prev = seq_c;
                    }
                }
            }
            continue;
        }

        if c.is_control() {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::sanitize_for_terminal;

    #[test]
    fn sanitize_for_terminal_removes_carriage_return() {
        let input = "good\rbad";
        let sanitized = sanitize_for_terminal(input);
        assert!(!sanitized.contains('\r'));
        assert!(sanitized.contains("good"));
        assert!(sanitized.contains("bad"));
    }

    #[test]
    fn sanitize_for_terminal_removes_ansi_escape_sequences() {
        let input = "x\x1b[2K\x1b[1Apath";
        let sanitized = sanitize_for_terminal(input);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("x"));
        assert!(sanitized.contains("path"));
    }

    #[test]
    fn sanitize_for_terminal_removes_osc_sequences() {
        let input = "x\x1b]0;evil\x07path";
        let sanitized = sanitize_for_terminal(input);
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\x07'));
        assert!(sanitized.contains("x"));
        assert!(sanitized.contains("path"));
    }

    /// Phase 23 Task 3 Step 8: surface test for the
    /// `read_capability_decisions_from_ledger` helper. Constructs a
    /// hand-rolled NDJSON ledger with 3 capability_decision records (1
    /// before-prompt, 1 after-prompt, 1 no reject_stage) plus 2
    /// session-lifecycle records, then asserts the helper filters to
    /// exactly the 3 capability_decision records and the per-stage
    /// counts (1, 1, 1) match.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn read_capability_decisions_returns_filtered_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger_path = dir
            .path()
            .join(crate::audit_integrity::AUDIT_EVENTS_FILENAME);
        // Hand-roll 5 NDJSON lines: 1 session_started, 3 capability_decision
        // (1 before-prompt, 1 after-prompt, 1 no reject_stage), 1
        // session_ended. The helper only filters by `event.type ==
        // "capability_decision"`, so the per-line entry shape is irrelevant
        // to the test (we use serde_json::Value end-to-end, not typed
        // AuditEntry).
        let lines = [
            r#"{"sequence":0,"timestamp":"2026-04-28T00:00:00Z","event":{"type":"session_started","started":"2026-04-28T00:00:00Z","command":["test"]}}"#,
            r#"{"sequence":1,"timestamp":"2026-04-28T00:00:01Z","event":{"type":"capability_decision","entry":{"timestamp":"2026-04-28T00:00:01Z","request":{"request_id":"a"},"decision":{"Denied":{"reason":"x"}},"backend":"t","duration_ms":0},"reject_stage":"before-prompt"}}"#,
            r#"{"sequence":2,"timestamp":"2026-04-28T00:00:02Z","event":{"type":"capability_decision","entry":{"timestamp":"2026-04-28T00:00:02Z","request":{"request_id":"b"},"decision":{"Denied":{"reason":"y"}},"backend":"t","duration_ms":0},"reject_stage":"after-prompt"}}"#,
            r#"{"sequence":3,"timestamp":"2026-04-28T00:00:03Z","event":{"type":"capability_decision","entry":{"timestamp":"2026-04-28T00:00:03Z","request":{"request_id":"c"},"decision":{"Approved":null},"backend":"t","duration_ms":0}}}"#,
            r#"{"sequence":4,"timestamp":"2026-04-28T00:00:04Z","event":{"type":"session_ended","ended":"2026-04-28T00:00:04Z","exit_code":0}}"#,
        ];
        std::fs::write(&ledger_path, lines.join("\n") + "\n").expect("write ledger");

        let decisions =
            super::read_capability_decisions_from_ledger(dir.path()).expect("read ledger");
        assert_eq!(
            decisions.len(),
            3,
            "expected 3 capability_decision records, got: {decisions:?}",
        );
        let before = decisions
            .iter()
            .filter(|d| {
                d.pointer("/event/reject_stage").and_then(|v| v.as_str()) == Some("before-prompt")
            })
            .count();
        let after = decisions
            .iter()
            .filter(|d| {
                d.pointer("/event/reject_stage").and_then(|v| v.as_str()) == Some("after-prompt")
            })
            .count();
        let unstaged = decisions
            .iter()
            .filter(|d| d.pointer("/event/reject_stage").is_none())
            .count();
        assert_eq!(before, 1, "1 before-prompt record expected");
        assert_eq!(after, 1, "1 after-prompt record expected");
        assert_eq!(
            unstaged, 1,
            "1 record without reject_stage expected (Approved path)",
        );
    }

    /// Phase 23 Task 3 Step 8 part 2: helper degrades gracefully on missing
    /// ledger file — returns `Ok(vec![])` rather than failing the
    /// audit-show command (the integrity-summary path is the load-bearing
    /// failure surface).
    #[test]
    fn read_capability_decisions_returns_empty_on_missing_ledger() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No ledger file is written. The helper must return Ok(vec![]),
        // not Err.
        let decisions = super::read_capability_decisions_from_ledger(dir.path())
            .expect("missing ledger MUST be Ok(vec![])");
        assert!(
            decisions.is_empty(),
            "missing ledger MUST yield empty Vec, got: {decisions:?}",
        );
    }
}
