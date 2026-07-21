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
            .map(|a| a.filename.len())
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
        let size = format_size(bytes as i64);
        let _ = writeln!(
            err,
            "     {name:<name_w$}   {size:>size_w$}   {tick}",
            name = filename.dimmed(),
            name_w = self.name_width,
            size = size.dimmed(),
            size_w = self.size_width,
            tick = "✓".green(),
        );
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
