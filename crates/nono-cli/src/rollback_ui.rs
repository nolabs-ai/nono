//! Post-exit interactive review/restore UI for the rollback system
//!
//! Presents the user with a summary of changes made during the session
//! and offers to restore to the initial state.

use crate::theme;
use colored::Colorize;
use nono::Result;
use nono::undo::{Change, ChangeType, SnapshotManager, SnapshotManifest};
use std::io::{BufRead, IsTerminal, Write};

/// Run the post-exit rollback review UI.
///
/// Shows a change summary and prompts the user to restore or exit.
/// Returns `true` if the user chose to restore.
pub fn review_and_restore(
    manager: &SnapshotManager,
    baseline: &SnapshotManifest,
    changes: &[Change],
) -> Result<bool> {
    let t = theme::current();
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Ok(false);
    }

    print_change_details(changes);

    eprint!(
        "{} {}",
        theme::fg("nono", t.brand).bold(),
        theme::fg("Restore to initial state? [y/N]: ", t.text)
    );
    std::io::stderr().flush().ok();

    let mut input = String::new();
    stdin
        .lock()
        .read_line(&mut input)
        .map_err(nono::NonoError::Io)?;

    let answer = input.trim().to_lowercase();
    if answer == "y" || answer == "yes" {
        eprintln!(
            "{} {}",
            theme::fg("nono", t.brand).bold(),
            theme::fg("Restoring...", t.text)
        );

        let applied = manager.restore_to(baseline)?;

        eprintln!(
            "{} Restored {} files.",
            theme::fg("nono", t.brand).bold(),
            applied.len()
        );
        Ok(true)
    } else {
        eprintln!(
            "{} {}",
            theme::fg("nono", t.brand).bold(),
            theme::fg("Exiting without restoring.", t.subtext)
        );
        Ok(false)
    }
}

/// Print details of each change
fn print_change_details(changes: &[Change]) {
    let t = theme::current();
    eprintln!(
        "{} {}",
        theme::fg("nono", t.brand).bold(),
        theme::fg("Changes:", t.text).bold()
    );

    for change in changes {
        let symbol = match change.change_type {
            ChangeType::Created => theme::fg("+", t.green),
            ChangeType::Modified => theme::fg("~", t.yellow),
            ChangeType::Deleted => theme::fg("-", t.red),
            ChangeType::PermissionsChanged => theme::fg("p", t.subtext),
        };

        let label = match change.change_type {
            ChangeType::Created => "created",
            ChangeType::Modified => "modified",
            ChangeType::Deleted => "deleted",
            ChangeType::PermissionsChanged => "permissions",
        };

        let size_info = change
            .size_delta
            .map(|delta| match delta.cmp(&0) {
                std::cmp::Ordering::Greater => format!(" (+{delta} bytes)"),
                std::cmp::Ordering::Less => format!(" ({delta} bytes)"),
                std::cmp::Ordering::Equal => String::new(),
            })
            .unwrap_or_default();

        eprintln!(
            "  {} {} ({}){}",
            symbol,
            change.path.display(),
            theme::fg(label, t.subtext),
            theme::fg(&size_info, t.overlay)
        );
    }
    eprintln!();
}
