//! Audit subcommand implementations
//!
//! Handles `nono audit list|show` for viewing the audit trail of sandboxed sessions.

use crate::audit_attestation::verify_audit_attestation;
use crate::audit_event_reader::{command_policy_events_json, load_capability_decisions};
use crate::audit_integrity::verify_audit_log;
use crate::audit_ledger::verify_session_in_ledger;
use crate::audit_session::{
    SessionInfo, discover_sessions, format_bytes, is_legacy_audit_only_session,
    is_primary_audit_session, load_session, remove_session,
};
use crate::cli::{
    AuditArgs, AuditCleanupArgs, AuditCommands, AuditListArgs, AuditShowArgs, AuditVerifyArgs,
};
use crate::command_display::{format_command_line, truncate_command};
use crate::theme;
use colored::Colorize;
use nono::undo::{CommandPolicySummary, SnapshotManager};
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
        AuditCommands::Sync(args) => crate::audit_client::run_sync(args),
        AuditCommands::Status(args) => crate::audit_client::run_status(args),
    }
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
    eprintln!("{} {} command(s)\n", prefix(), sessions.len());

    for (project_path, group) in &grouped {
        let display_path = shorten_home(project_path);
        eprintln!(
            "  {} ({} command{})",
            display_path.white().bold(),
            group.len(),
            if group.len() == 1 { "" } else { "s" },
        );
        for s in group {
            let cmd = truncate_command(&s.metadata.command, 35);
            let timestamp = format_session_timestamp(&s.metadata.started);
            let status = session_status_label(s);
            eprintln!(
                "    {}  {}  {}  {}",
                s.metadata.session_id,
                timestamp.truecolor(100, 100, 100),
                status,
                theme::fg(&cmd, theme::current().subtext),
            );
            if !args.no_tools
                && let Some(line) = format_tool_summary_line(s)
            {
                eprintln!("      {line}");
            }
        }
        eprintln!();
    }

    Ok(())
}

/// Distinct mediated commands named on a session's list line before eliding.
const TOOL_SUMMARY_MAX_COMMANDS: usize = 4;

/// Render the mediated-tool rollup for one session, or `None` when the session
/// neither configured mediation nor mediated anything.
///
/// Reads the denormalized summary in session metadata, never the event log, so
/// listing stays independent of how many events a session recorded.
fn format_tool_summary_line(session: &SessionInfo) -> Option<String> {
    let summary = session.metadata.command_policy_summary.as_ref()?;
    Some(format!(
        "{} {}",
        theme::fg("tools:", theme::current().subtext),
        format_tool_summary_detail(summary)
    ))
}

/// Render a mediated-tool rollup without the `tools:` label, for callers with a
/// label of their own.
pub(crate) fn format_tool_summary_detail(summary: &CommandPolicySummary) -> String {
    let theme = theme::current();

    if summary.commands.is_empty() {
        // Mediation was configured and no command ever reached it. A session
        // that had none configured carries no summary and prints no line.
        return if summary.event_count == 0 {
            "active, no invocations".to_string()
        } else {
            // Events but no terminal decision, which is what a session killed
            // mid-invocation looks like.
            format!("{} event(s), no completed invocations", summary.event_count)
        };
    }

    let mut parts = Vec::new();
    for command in summary.commands.iter().take(TOOL_SUMMARY_MAX_COMMANDS) {
        let mut counts = Vec::new();
        if command.allowed > 0 {
            counts
                .push(theme::fg(&format!("{} allowed", command.allowed), theme.green).to_string());
        }
        if command.denied > 0 {
            counts.push(
                theme::fg(&format!("{} denied", command.denied), theme.red)
                    .bold()
                    .to_string(),
            );
        }
        if command.other > 0 {
            counts.push(
                theme::fg(&format!("{} unclassified", command.other), theme.yellow).to_string(),
            );
        }
        // Profile-supplied, so it reaches the terminal without ever having
        // passed through the event log's sanitization on the `audit show` path.
        parts.push(format!(
            "{} ({})",
            sanitize_for_terminal(&command.command),
            counts.join(", ")
        ));
    }

    let elided = summary
        .commands
        .len()
        .saturating_sub(TOOL_SUMMARY_MAX_COMMANDS);
    if elided > 0 {
        parts.push(format!("+{elided} more"));
    }
    // The rollup itself dropped commands, so not even `audit show` can recover
    // their per-command counts from metadata.
    if summary.truncated {
        parts.push(theme::fg("rollup truncated", theme.yellow).to_string());
    }

    parts.join(", ")
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

fn format_session_timestamp(started: &str) -> String {
    use chrono::{DateTime, Local, Utc};

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

    if duration.num_seconds() < 0 {
        return format_absolute_timestamp(&dt, &now);
    }

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
                // Whether the session had a Tool Sandbox at all: mediation was
                // configured, or a command reached mediation. Deliberately not
                // the summary's own `mediation_active`, which reports only the
                // first of those.
                "tool_sandbox_active": s.metadata.command_policy_summary.is_some(),
                "command_policy_summary": s.metadata.command_policy_summary,
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

fn cmd_show(args: AuditShowArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

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
            &format_command_line(&session.metadata.command),
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
    if let Some(ref integrity) = session.metadata.audit_integrity {
        eprintln!(
            "  Audit:    integrity enabled ({} events)",
            integrity.event_count
        );
        eprintln!("  Chain:    {}", &integrity.chain_head.to_string()[..16]);
        eprintln!("  Root:     {}", &integrity.merkle_root.to_string()[..16]);
        if let Some(ref attestation) = session.metadata.audit_attestation {
            eprintln!("  Signed:   {}", attestation.key_id);
        }
    } else if session.metadata.audit_event_count > 0 {
        eprintln!("  Audit:    {} events", session.metadata.audit_event_count);
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
                nono::undo::NetworkAuditDecision::ApproveRequested => "approve_requested".yellow(),
                nono::undo::NetworkAuditDecision::ApproveGranted => "approve_granted".green(),
                nono::undo::NetworkAuditDecision::ApproveDenied => "approve_denied".red(),
                nono::undo::NetworkAuditDecision::ApproveTimeout => "approve_timeout".red(),
                nono::undo::NetworkAuditDecision::ApproveError => "approve_error".red(),
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
                details.push(format!("reason={}", sanitize_reason_for_terminal(reason)));
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

    let command_policy_events = command_policy_events_json(&session.dir)?;
    if !command_policy_events.is_empty() {
        eprintln!();
        eprintln!("  Command Policy Events: {}", command_policy_events.len());
        for event in &command_policy_events {
            let decision = match event.get("decision").and_then(serde_json::Value::as_str) {
                Some("allowed") => "allowed".green(),
                Some("denied") => "denied".red(),
                Some(other) => sanitize_for_terminal(other).normal(),
                None => "-".normal(),
            };
            let command = event
                .get("command")
                .and_then(serde_json::Value::as_str)
                .map(sanitize_for_terminal)
                .unwrap_or_else(|| "-".to_string());
            let caller = event
                .get("caller")
                .and_then(serde_json::Value::as_str)
                .map(sanitize_for_terminal)
                .unwrap_or_else(|| "-".to_string());
            let reason = event
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .map(sanitize_reason_for_terminal);
            if let Some(reason) = reason {
                eprintln!(
                    "    {} {} caller={} reason={}",
                    decision, command, caller, reason
                );
            } else {
                eprintln!("    {} {} caller={}", decision, command, caller);
            }
        }
    }

    let capability_decisions = load_capability_decisions(&session.dir)?;
    if !capability_decisions.is_empty() {
        eprintln!();
        eprintln!("  Capability Decisions: {}", capability_decisions.len());
        for record in &capability_decisions {
            print_capability_decision(record);
        }
    }

    Ok(())
}

fn print_capability_decision(entry: &nono::supervisor::AuditEntry) {
    use nono::supervisor::{ApprovalDecision, ApprovalRequest};

    let ApprovalRequest::Capability { path, access, .. } = &entry.request else {
        return;
    };
    let decision = match &entry.decision {
        ApprovalDecision::Granted => "granted".green(),
        ApprovalDecision::Denied { .. } => "denied".red(),
        ApprovalDecision::Timeout => "timeout".red(),
    };
    let reason = match &entry.decision {
        ApprovalDecision::Denied { reason } => {
            format!(" reason={}", sanitize_reason_for_terminal(reason))
        }
        ApprovalDecision::Granted | ApprovalDecision::Timeout => String::new(),
    };

    eprintln!(
        "    {} {} {} backend={} duration={}ms{}",
        decision,
        access,
        sanitize_for_terminal(&path.display().to_string()),
        sanitize_for_terminal(&entry.backend),
        entry.duration_ms,
        reason,
    );
}

fn cmd_verify(args: AuditVerifyArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;
    let result = verify_audit_log(&session.dir, session.metadata.audit_integrity.as_ref())?;
    let ledger = verify_session_in_ledger(&session.metadata)?;
    let attestation = verify_audit_attestation(
        &session.dir,
        &session.metadata,
        args.public_key_file.as_deref(),
    )?;

    if args.json {
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "session": result,
            "ledger": ledger,
            "attestation": attestation,
        }))
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    let attestation_verified = (!attestation.present && attestation.verification_error.is_none())
        || (attestation.signature_verified
            && attestation.key_id_matches
            && attestation.merkle_root_matches
            && attestation.session_id_matches
            && attestation.expected_public_key_matches.unwrap_or(true));
    let verified = result.records_verified
        && result.event_count_matches
        && ledger.session_found
        && ledger.session_digest_matches
        && ledger.ledger_chain_verified
        && attestation_verified;
    let status = if verified {
        "VERIFIED".green().bold()
    } else {
        "MISMATCH".red().bold()
    };

    eprintln!(
        "{} Audit integrity for session {} {}",
        prefix(),
        session.metadata.session_id.white().bold(),
        status
    );
    eprintln!("  Events:   {}", result.event_count);
    eprintln!(
        "  Chain:    {}",
        result
            .computed_chain_head
            .map(|h| h.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    eprintln!(
        "  Root:     {}",
        result
            .computed_merkle_root
            .map(|h| h.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    eprintln!("  Scheme:   {}", result.merkle_scheme);

    if session.metadata.audit_integrity.is_some() {
        eprintln!(
            "  Stored:   events={}, chain={}, root={}",
            result
                .stored_event_count
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            result
                .stored_chain_head
                .map(|h| h.to_string())
                .unwrap_or_else(|| "-".to_string()),
            result
                .stored_merkle_root
                .map(|h| h.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
    }
    eprintln!(
        "  Ledger:   {} (entries={}, head={})",
        if ledger.session_found && ledger.session_digest_matches && ledger.ledger_chain_verified {
            "verified".green().bold().to_string()
        } else {
            "mismatch".red().bold().to_string()
        },
        ledger.entry_count,
        ledger
            .ledger_head
            .map(|h| h.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    if attestation.present {
        let signed_status = if attestation_verified {
            if attestation.expected_public_key_matches.is_some() {
                "verified".green().bold().to_string()
            } else {
                "self-attested".yellow().bold().to_string()
            }
        } else {
            "mismatch".red().bold().to_string()
        };
        eprintln!(
            "  Signed:   {} (key={})",
            signed_status,
            attestation
                .key_id
                .clone()
                .unwrap_or_else(|| "-".to_string())
        );
        if let Some(matches) = attestation.expected_public_key_matches {
            eprintln!(
                "  Pubkey:   {}",
                if matches {
                    "matched".green().bold().to_string()
                } else {
                    "mismatch".red().bold().to_string()
                }
            );
        }
        if attestation.expected_public_key_matches.is_none() && attestation_verified {
            eprintln!("  Trust:    rely on ledger chain, or pass --public-key-file to pin signer");
        }
        if let Some(ref error) = attestation.verification_error {
            eprintln!("  Attest:   {}", sanitize_for_terminal(error));
        }
    }

    if verified {
        Ok(())
    } else {
        Err(NonoError::Snapshot(
            "Audit integrity verification failed".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// nono audit cleanup
// ---------------------------------------------------------------------------

fn cmd_cleanup(args: AuditCleanupArgs) -> Result<()> {
    reject_if_sandboxed("audit cleanup")?;

    let sessions = discover_sessions()?;
    if sessions.is_empty() {
        eprintln!("{} No audit sessions to clean up.", prefix());
        return Ok(());
    }

    let removable: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|s| !s.is_alive)
        .filter(|s| is_primary_audit_session(&s.dir) || is_legacy_audit_only_session(s))
        .collect();

    if removable.is_empty() {
        eprintln!("{} No removable audit sessions found.", prefix());
        return Ok(());
    }

    let mut to_remove: Vec<&SessionInfo> = if args.all {
        removable
    } else if let Some(days) = args.older_than {
        let cutoff_secs = days.saturating_mul(86400);
        let now = now_epoch_secs();
        removable
            .into_iter()
            .filter(|s| {
                parse_session_start_time(s)
                    .map(|started| now.saturating_sub(started) > cutoff_secs)
                    .unwrap_or(false)
            })
            .collect()
    } else {
        removable
    };

    if let Some(keep) = args.keep {
        if to_remove.len() > keep {
            to_remove = to_remove.split_off(keep);
        } else {
            to_remove.clear();
        }
    }

    if to_remove.is_empty() {
        eprintln!("{} Nothing to clean up.", prefix());
        return Ok(());
    }

    let total_size: u64 = to_remove.iter().map(|s| s.disk_size).sum();

    if args.dry_run {
        eprintln!(
            "{} Dry run: would remove {} audit session(s) ({})\n",
            prefix(),
            to_remove.len(),
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
        "{} Removed {} audit session(s), freed {}.",
        prefix(),
        removed,
        format_bytes(total_size)
    );

    Ok(())
}

fn print_show_json(session: &SessionInfo) -> Result<()> {
    let command_policy_events = command_policy_events_json(&session.dir)?;
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
        "merkle_roots": session.metadata.merkle_roots.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        "network_events": &session.metadata.network_events,
        "command_policy_events": command_policy_events,
        "audit_event_count": session.metadata.audit_event_count,
        "audit_integrity": session.metadata.audit_integrity.as_ref().map(|summary| serde_json::json!({
            "hash_algorithm": summary.hash_algorithm,
            "event_count": summary.event_count,
            "chain_head": summary.chain_head.to_string(),
            "merkle_root": summary.merkle_root.to_string(),
        })),
        "snapshots": snapshots,
    });

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
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

fn reject_if_sandboxed(command: &str) -> Result<()> {
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        return Err(NonoError::ConfigParse(format!(
            "`nono {}` cannot be used inside a sandbox.",
            command
        )));
    }
    Ok(())
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    if let Some(home) = dirs::home_dir() {
        let home_str = home.display().to_string();
        if let Some(rest) = s.strip_prefix(&home_str) {
            return format!("~{rest}");
        }
    }
    s
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
        nono::undo::NetworkAuditMode::ConnectIntercept => "connect_intercept",
        nono::undo::NetworkAuditMode::Reverse => "reverse",
        nono::undo::NetworkAuditMode::External => "external",
    }
}

#[cfg(test)]
mod list_tests {
    use super::*;
    use crate::audit_integrity::{
        AuditRecorder, CommandPolicyAuditEvent, CommandPolicyEnvAuditEntry,
        CommandPolicyStdioAudit, CommandPolicyStdioStreamAudit,
    };
    use crate::tool_sandbox::command_policy_decision::CommandPolicyDecision;
    use nono::undo::SessionMetadata;

    #[test]
    fn audit_group_header_uses_command_count() {
        let metadata = SessionMetadata {
            session_id: "20260219-100000-12345".to_string(),
            started: "2026-02-19T10:00:00Z".to_string(),
            ended: None,
            command: vec!["/bin/pwd".to_string()],
            executable_identity: None,
            tracked_paths: vec![std::path::PathBuf::from("/home/user/widgets")],
            snapshot_count: 0,
            exit_code: Some(0),
            merkle_roots: vec![],
            network_events: vec![],
            audit_event_count: 4,
            audit_integrity: None,
            audit_attestation: None,
            command_policy_summary: None,
        };

        let session = SessionInfo {
            metadata,
            dir: std::path::PathBuf::from("/tmp/test"),
            disk_size: 0,
            is_alive: false,
            is_stale: false,
        };

        let sessions = [session];
        let grouped = group_by_project(&sessions);
        let commands: usize = grouped.values().map(std::vec::Vec::len).sum();
        assert_eq!(commands, 1);
    }

    #[test]
    fn audit_list_output_format_structure() {
        let session_id = "20260217-234523-70889";
        let timestamp = "2h ago";
        let status = "completed";
        let cmd = "/bin/pwd";

        let output = format!("    {}  {}  {}  {}", session_id, timestamp, status, cmd);
        let parts: Vec<&str> = output.trim().split("  ").collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], session_id);
        assert_eq!(parts[1], timestamp);
        assert_eq!(parts[2], status);
        assert_eq!(parts[3], cmd);
    }

    #[test]
    fn command_policy_events_json_includes_caller_context() -> nono::Result<()> {
        let dir = tempfile::tempdir().map_err(|e| nono::NonoError::Snapshot(e.to_string()))?;
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf())?;
        recorder.record_command_policy_event(
            CommandPolicyAuditEvent {
                timestamp: "2026-05-03T16:30:30Z".to_string(),
                session_id: Some("sess-tool_sandbox".to_string()),
                invocation_id: None,
                command: "ssh".to_string(),
                caller: "git".to_string(),
                caller_kind: Some("command".to_string()),
                caller_command: Some("git".to_string()),
                caller_pid: Some(100),
                shim_pid: Some(101),
                session_root_pid: Some(99),
                decision: CommandPolicyDecision::Denied.as_str().to_string(),
                reason: Some("missing from.git".to_string()),
                stdio_mode: "direct_fds".to_string(),
                argv_hash: "argv-hash".to_string(),
                env_name_hash: "env-hash".to_string(),
                cwd_hash: "cwd-hash".to_string(),
                argv_display: vec!["ssh".to_string(), "-V".to_string()],
                env_names_display: vec!["PATH".to_string()],
                env_display: vec![CommandPolicyEnvAuditEntry {
                    name: "PATH".to_string(),
                    value_display: "/bin".to_string(),
                }],
                cwd_display: "/work".to_string(),
                exit_code: None,
                stdio: Some(CommandPolicyStdioAudit {
                    stdout: Some(CommandPolicyStdioStreamAudit {
                        total_bytes: 1024,
                        forwarded_bytes: 512,
                        max_bytes: Some(512),
                        limit_exceeded: true,
                        on_limit: Some("truncate".to_string()),
                    }),
                    stderr: None,
                }),
            },
            CommandPolicyDecision::Denied.outcome(),
        )?;

        let events = command_policy_events_json(dir.path())?;
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["event_type"], "command_policy");
        assert_eq!(event["sequence"], 0);
        assert_eq!(event["session_id"], "sess-tool_sandbox");
        assert_eq!(event["decision"], "denied");
        assert_eq!(event["caller"], "git");
        assert_eq!(event["caller_kind"], "command");
        assert_eq!(event["caller_command"], "git");
        assert_eq!(event["caller_pid"], 100);
        assert_eq!(event["shim_pid"], 101);
        assert_eq!(event["session_root_pid"], 99);
        assert_eq!(event["stdio"]["stdout"]["total_bytes"], 1024);
        assert_eq!(event["stdio"]["stdout"]["forwarded_bytes"], 512);
        assert_eq!(event["stdio"]["stdout"]["max_bytes"], 512);
        assert_eq!(event["stdio"]["stdout"]["limit_exceeded"], true);
        assert_eq!(event["stdio"]["stdout"]["on_limit"], "truncate");
        Ok(())
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

fn sanitize_reason_for_terminal(input: &str) -> String {
    const MAX_REASON_CHARS: usize = 4096;

    let sanitized = sanitize_for_terminal(input);
    crate::command_display::truncate_chars(&sanitized, MAX_REASON_CHARS)
}

#[cfg(test)]
mod tool_summary_tests {
    use super::{TOOL_SUMMARY_MAX_COMMANDS, format_tool_summary_line};
    use crate::audit_session::SessionInfo;
    use nono::undo::{CommandPolicyCommandSummary, CommandPolicySummary, SessionMetadata};
    use std::path::PathBuf;

    fn session(summary: Option<CommandPolicySummary>) -> SessionInfo {
        SessionInfo {
            metadata: SessionMetadata {
                session_id: "20260806-120000-11111".to_string(),
                started: "2026-08-06T12:00:00Z".to_string(),
                ended: Some("2026-08-06T12:05:00Z".to_string()),
                command: vec!["claude".to_string()],
                executable_identity: None,
                tracked_paths: vec![PathBuf::from("/work")],
                snapshot_count: 0,
                exit_code: Some(0),
                merkle_roots: Vec::new(),
                network_events: Vec::new(),
                audit_event_count: 0,
                audit_integrity: None,
                audit_attestation: None,
                command_policy_summary: summary,
            },
            dir: PathBuf::from("/work"),
            disk_size: 0,
            is_alive: false,
            is_stale: false,
        }
    }

    fn command(name: &str, allowed: u64, denied: u64) -> CommandPolicyCommandSummary {
        CommandPolicyCommandSummary {
            command: name.to_string(),
            allowed,
            denied,
            other: 0,
        }
    }

    #[test]
    fn sessions_without_tool_activity_stay_concise() {
        assert!(format_tool_summary_line(&session(None)).is_none());
    }

    #[test]
    fn summary_names_the_command_and_its_decisions() {
        let line = format_tool_summary_line(&session(Some(CommandPolicySummary {
            mediation_active: true,
            event_count: 3,
            invocation_count: 2,
            commands: vec![command("gh", 1, 1)],
            truncated: false,
        })))
        .expect("a summary with commands always renders a line");

        assert!(line.contains("gh"));
        assert!(line.contains("1 allowed"));
        assert!(line.contains("1 denied"));
    }

    #[test]
    fn configured_mediation_is_reported_before_any_command_is_invoked() {
        let line = format_tool_summary_line(&session(Some(CommandPolicySummary {
            mediation_active: true,
            event_count: 0,
            invocation_count: 0,
            commands: Vec::new(),
            truncated: false,
        })))
        .expect("an active-mediation summary always renders a line");

        assert!(line.contains("active"));
        assert!(line.contains("no invocations"));
    }

    #[test]
    fn mediation_without_a_completed_invocation_is_still_reported() {
        let line = format_tool_summary_line(&session(Some(CommandPolicySummary {
            mediation_active: true,
            event_count: 1,
            invocation_count: 0,
            commands: Vec::new(),
            truncated: false,
        })))
        .expect("a summary with events always renders a line");

        assert!(line.contains("1 event(s)"));
        assert!(line.contains("no completed invocations"));
    }

    #[test]
    fn elided_and_truncated_commands_are_both_disclosed() {
        let commands: Vec<_> = (0..TOOL_SUMMARY_MAX_COMMANDS.saturating_add(3))
            .map(|index| command(&format!("cmd-{index}"), 1, 0))
            .collect();
        let line = format_tool_summary_line(&session(Some(CommandPolicySummary {
            mediation_active: true,
            event_count: commands.len() as u64,
            invocation_count: commands.len() as u64,
            commands,
            truncated: true,
        })))
        .expect("a summary with commands always renders a line");

        assert!(line.contains("+3 more"));
        assert!(line.contains("rollup truncated"));
    }

    /// Drop the theme's own color sequences, which are present or absent
    /// depending on whether the test binary's stdout is a terminal. Only
    /// `m`-terminated CSI is removed, so any other escape the summary emitted
    /// still reaches the caller's assertions.
    fn strip_theme_color(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut rest = line;

        while let Some(start) = rest.find("\x1b[") {
            let body = &rest[start.saturating_add(2)..];
            let Some(end) = body.find(|c: char| ('\x40'..='\x7e').contains(&c)) else {
                break;
            };
            if !body[end..].starts_with('m') {
                break;
            }
            out.push_str(&rest[..start]);
            rest = &body[end.saturating_add(1)..];
        }

        out.push_str(rest);
        out
    }

    /// A shared profile is the one place a hostile command name can enter the
    /// rollup, and unlike the `audit show` path it never passes through the
    /// event log's sanitization on the way to the terminal.
    #[test]
    fn a_command_name_cannot_carry_escapes_into_the_listing() {
        let line = format_tool_summary_line(&session(Some(CommandPolicySummary {
            mediation_active: true,
            event_count: 1,
            invocation_count: 1,
            commands: vec![command("gh\x1b]0;pwned\x07\r", 0, 1)],
            truncated: false,
        })))
        .expect("a summary with commands always renders a line");
        let line = strip_theme_color(&line);

        assert!(!line.contains('\x1b'), "{line:?}");
        assert!(!line.contains('\x07'), "{line:?}");
        assert!(!line.contains('\r'), "{line:?}");
        assert!(!line.contains("pwned"), "{line:?}");
        assert!(line.contains("1 denied"), "{line:?}");
    }

    #[test]
    fn stripping_theme_color_leaves_other_escapes_for_inspection() {
        assert_eq!(strip_theme_color("\x1b[1;38;2;1;2;3mgh\x1b[0m"), "gh");
        assert_eq!(
            strip_theme_color("gh\x1b[2J\x1b]0;x\x07"),
            "gh\x1b[2J\x1b]0;x\x07"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{sanitize_for_terminal, sanitize_reason_for_terminal};

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

    #[test]
    fn sanitize_reason_for_terminal_removes_control_sequences_and_bounds_length() {
        let input = format!("prefix\x1b]52;c;Y29weQ==\x07{}", "x".repeat(5000));

        let sanitized = sanitize_reason_for_terminal(&input);

        assert!(!sanitized.chars().any(char::is_control));
        assert!(sanitized.chars().count() <= 4096);
        assert!(sanitized.ends_with("..."));
    }
}
