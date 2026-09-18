//! Sleek TUI for `nono pull`. Streams per-file download progress as it
//! happens, then renders the install summary. Same output for the
//! explicit `nono pull <ref>` command and the auto-pull path triggered
//! by `--profile nolabs-ai/claude`.
//!
//! Design rules (do not relax without thinking):
//!   - No spinners, no in-place line rewrites — output stays readable in
//!     scrollback and under non-TTY (CI logs, redirected stderr).
//!   - Two-space indent for everything; no boxes/borders so narrow
//!     terminals don't wrap awkwardly.
//!   - Color is decoration, not information: every line still parses
//!     when ANSI is stripped (NO_COLOR, dumb terminals).

use crate::package::{PackageRef, PullResponse};
use colored::Colorize;
use std::io::{self, Write};

/// Artifact filenames come from the pull response, so they are
/// pack-controlled text on its way to a terminal. Strip escape sequences
/// before they reach the screen — a filename carrying ANSI could erase
/// lines, recolour, or forge rows for files the pack never shipped.
///
/// Column width is measured from the sanitized name for the same reason:
/// escape bytes counted as width inflate the padding calculation and
/// misalign every row in the block, not only the offending one.
fn display_name(filename: &str) -> String {
    crate::terminal_approval::sanitize_for_terminal(filename)
}

/// Per-file download progress sink. The pull pipeline calls
/// `started` before each download and `finished` once the digest is
/// verified. All methods are best-effort and never fail the pull —
/// IO errors writing to stderr are swallowed.
pub struct ProgressPrinter {
    name_width: usize,
    size_width: usize,
}

impl ProgressPrinter {
    /// Build a printer sized to the longest filename and the widest
    /// formatted size in the pull response. This lets every row align
    /// without per-line padding hacks.
    #[must_use]
    pub fn new(pull: &PullResponse) -> Self {
        let name_width = pull
            .artifacts
            .iter()
            .map(|a| display_name(&a.filename).len())
            .max()
            .unwrap_or(0);
        let size_width = pull
            .artifacts
            .iter()
            .map(|a| format_size(a.size_bytes).len())
            .max()
            .unwrap_or(0);
        Self {
            name_width,
            size_width,
        }
    }

    /// Print the pulling-… header. Emit once before any downloads.
    pub fn header(&self, package_ref: &PackageRef) {
        let mut err = io::stderr().lock();
        let _ = writeln!(err);
        let _ = writeln!(err, "  {} pulling {}", "⬇".cyan(), package_ref.key().bold());
        let _ = writeln!(err);
    }

    /// Mark a file as completed. Called after digest verification.
    /// `bytes` is the on-disk size of the verified file.
    pub fn finished(&self, filename: &str, bytes: u64) {
        let mut err = io::stderr().lock();
        let _ = writeln!(err, "{}", self.row(filename, bytes));
    }

    /// Build the completed-file row. Split out from `finished` so the
    /// sanitizing below is assertable without capturing stderr.
    fn row(&self, filename: &str, bytes: u64) -> String {
        let name = display_name(filename);
        let size = format_size(bytes as i64);
        format!(
            "     {name:<name_w$}   {size:>size_w$}   {tick}",
            name = name.dimmed(),
            name_w = self.name_width,
            size = size.dimmed(),
            size_w = self.size_width,
            tick = "✓".green(),
        )
    }
}

/// Render the install summary. Called once after the install
/// completes successfully.
///
/// `install_dir` is the absolute path of the installed pack inside the
/// package store. `installed_artifacts` is the count from the install
/// summary.
pub fn render_summary(
    package_ref: &PackageRef,
    pull: &PullResponse,
    install_dir: &std::path::Path,
    installed_artifacts: usize,
    copied_to_project: usize,
) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "  {} {} {}",
        "✓".green().bold(),
        package_ref.key().bold(),
        pull.version.dimmed(),
    );
    let _ = writeln!(err);

    let _ = writeln!(
        err,
        "     {label}  {body}",
        label = "Installed at".bold(),
        body = install_dir.display().to_string().dimmed(),
    );
    let _ = writeln!(
        err,
        "                   {}",
        format!("{installed_artifacts} artifact(s)").dimmed(),
    );

    if copied_to_project > 0 {
        let _ = writeln!(err);
        let _ = writeln!(
            err,
            "     Copied {copied_to_project} instruction file(s) into the current directory",
        );
    }
    let _ = writeln!(err);
}

/// "1.30 KB" / "412 B" / "2.10 MB" — three significant digits. Human
/// readable; precision matched across rows by `ProgressPrinter`'s
/// `size_width` calculation.
#[must_use]
pub fn format_size(bytes: i64) -> String {
    let bytes = bytes.max(0) as u64;
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kib = bytes as f64 / 1024.0;
    if kib < 1024.0 {
        return format!("{kib:.2} KB");
    }
    let mib = kib / 1024.0;
    if mib < 1024.0 {
        return format!("{mib:.2} MB");
    }
    let gib = mib / 1024.0;
    format!("{gib:.2} GB")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pack-controlled filename must not carry escapes to the screen.
    #[test]
    fn progress_row_strips_terminal_escapes() {
        let printer = ProgressPrinter {
            name_width: 20,
            size_width: 8,
        };
        let row = printer.row("eve\u{1b}[2K\u{1b}[31mil.json", 1024);
        assert!(!row.contains("\u{1b}[2K"), "erase-line survived: {row:?}");
        assert!(
            !row.contains("\u{1b}[31m"),
            "color escape survived: {row:?}"
        );
        assert!(row.contains("eveil.json"), "visible text lost: {row:?}");
    }

    /// Width is measured from what is printed. Measuring the raw string
    /// would let one hostile filename skew the padding of every row.
    #[test]
    fn display_name_length_excludes_escape_bytes() {
        let raw = "a\u{1b}[31mb.json";
        assert!(
            raw.len() > "ab.json".len(),
            "test fixture should contain escapes"
        );
        assert_eq!(display_name(raw).len(), "ab.json".len());
    }

    #[test]
    fn format_size_thresholds() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1500), "1.46 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    }
}
