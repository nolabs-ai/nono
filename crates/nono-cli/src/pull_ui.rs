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
    wiring_roots: &[std::path::PathBuf],
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

    // Where the pack was stored is not where its agent files went.
    // Report both: with `wiring_vars`, two installs of the same pack on
    // one machine can write to different places, and a summary that only
    // ever names the package store cannot tell them apart.
    render_wiring_roots(&mut err, wiring_roots);

    if copied_to_project > 0 {
        let _ = writeln!(err);
        let _ = writeln!(
            err,
            "     Copied {copied_to_project} instruction file(s) into the current directory",
        );
    }
    let _ = writeln!(err);
}

/// At most `MAX_SHOWN` roots, then a count. A pack writing into many
/// trees is unusual; truncating keeps one anomalous pack from burying
/// the rest of the summary.
const MAX_SHOWN_ROOTS: usize = 3;

/// Paths here come from the pack's own wiring directives, so they are
/// pack-controlled text heading for a terminal. Strip escape sequences
/// before display — a directory name carrying ANSI could otherwise
/// rewrite the summary around it and misreport where the install wrote.
fn display_root(root: &std::path::Path) -> String {
    crate::terminal_approval::sanitize_for_terminal(&root.display().to_string())
}

fn render_wiring_roots(err: &mut impl Write, roots: &[std::path::PathBuf]) {
    let Some((first, rest)) = roots.split_first() else {
        return;
    };
    let _ = writeln!(
        err,
        "     {label}    {body}",
        label = "Wired into".bold(),
        body = display_root(first).dimmed(),
    );
    for root in rest.iter().take(MAX_SHOWN_ROOTS - 1) {
        let _ = writeln!(err, "                   {}", display_root(root).dimmed());
    }
    if let Some(hidden) = rest.len().checked_sub(MAX_SHOWN_ROOTS - 1)
        && hidden > 0
    {
        let _ = writeln!(
            err,
            "                   {}",
            format!("+{hidden} more").dimmed()
        );
    }
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

    fn rendered(roots: &[&str]) -> String {
        let roots: Vec<std::path::PathBuf> = roots.iter().map(std::path::PathBuf::from).collect();
        let mut buf: Vec<u8> = Vec::new();
        render_wiring_roots(&mut buf, &roots);
        String::from_utf8(buf).expect("utf8")
    }

    /// A pack with no wiring must not print an empty heading.
    #[test]
    fn wiring_roots_render_nothing_when_empty() {
        assert_eq!(rendered(&[]), "");
    }

    /// The module's own rule: every line still parses with ANSI
    /// stripped, so assert on content rather than styling.
    #[test]
    fn wiring_roots_render_each_root() {
        let out = rendered(&["/home/u/.claude", "/home/u/.config/nono/profile-drafts"]);
        assert!(out.contains("Wired into"), "missing label: {out}");
        assert!(out.contains("/home/u/.claude"), "missing first root: {out}");
        assert!(
            out.contains("/home/u/.config/nono/profile-drafts"),
            "missing second root: {out}"
        );
        assert!(
            !out.contains("more"),
            "should not truncate two roots: {out}"
        );
    }

    /// Truncation must report an accurate remainder — an undercount
    /// would hide a directory the pack wrote to, which is the very
    /// thing this output exists to prevent.
    #[test]
    fn wiring_roots_truncate_with_accurate_count() {
        let out = rendered(&["/a", "/b", "/c", "/d", "/e"]);
        for shown in ["/a", "/b", "/c"] {
            assert!(out.contains(shown), "expected {shown} shown: {out}");
        }
        assert!(out.contains("+2 more"), "expected remainder of 2: {out}");
        assert!(!out.contains("/d"), "fourth root should be hidden: {out}");
    }

    /// Wiring paths are pack-controlled text on its way to a terminal.
    /// An escape sequence in a directory name must not survive to the
    /// screen, where it could rewrite the summary around it and
    /// misreport where the install actually wrote.
    #[test]
    fn wiring_roots_strip_terminal_escapes() {
        let out = rendered(&["/home/u/\u{1b}[2K\u{1b}[31mevil"]);
        // Assert on the injected sequences rather than "no ESC at all":
        // `.dimmed()` emits its own escapes whenever color is enabled,
        // so a blanket check would pass or fail based on the terminal.
        assert!(!out.contains("\u{1b}[2K"), "erase-line survived: {out:?}");
        assert!(
            !out.contains("\u{1b}[31m"),
            "color escape survived: {out:?}"
        );
        assert!(out.contains("evil"), "path text should remain: {out:?}");
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
