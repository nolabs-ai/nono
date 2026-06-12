//! Sleek TUI for `nono pull`. Streams per-file download progress as it
//! happens, then renders the Sigstore provenance and install summary as
//! a coherent trust-chain block. Same output for the explicit
//! `nono pull <ref>` command and the auto-pull path triggered by
//! `--profile always-further/claude`.
//!
//! Design rules (do not relax without thinking):
//!   - No spinners, no in-place line rewrites — output stays readable in
//!     scrollback and under non-TTY (CI logs, redirected stderr).
//!   - Two-space indent for everything; no boxes/borders so narrow
//!     terminals don't wrap awkwardly.
//!   - Color is decoration, not information: every line still parses
//!     when ANSI is stripped (NO_COLOR, dumb terminals).
//!   - The provenance block explains *what* was verified — users should
//!     leave with a clear mental model of "artifact ↔ source code".

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

/// Render the verified-and-installed summary. Called once after the
/// install completes successfully.
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

    let prov = &pull.provenance;
    let label_w = "workflow".len();

    let _ = writeln!(
        err,
        "     {label}  {body}",
        label = "Verified".bold(),
        body = "Sigstore cryptographic supply chain provenance binds all".normal(),
    );
    let _ = writeln!(
        err,
        "               release artifacts to the source of origin '{}'",
        prov.repository,
    );
    let _ = writeln!(err);

    write_field(&mut err, "repo", &prov.repository, label_w);
    write_field(
        &mut err,
        ref_label(&prov.git_ref),
        &strip_ref_prefix(&prov.git_ref),
        label_w,
    );
    write_field(&mut err, "workflow", &prov.workflow, label_w);
    if let Some(ts) = prov.signed_at {
        write_field(
            &mut err,
            "signed",
            &ts.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            label_w,
        );
    }
    if let Some(idx) = prov.rekor_log_index {
        let url = format!("https://search.sigstore.dev/?logIndex={idx}");
        write_field(&mut err, "rekor", &url, label_w);
    }

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

/// Field row in the provenance block. Two-space indent already applied
/// upstream; the inner formatting matches the "Verified  …" header.
fn write_field<W: Write>(out: &mut W, label: &str, value: &str, label_w: usize) {
    let _ = writeln!(
        out,
        "               {label:<width$}   {value}",
        label = label.dimmed(),
        value = value,
        width = label_w,
    );
}

/// `refs/tags/foo` → `tag`, `refs/heads/foo` → `branch`, anything that
/// looks like a SHA → `commit`, otherwise `ref`.
fn ref_label(git_ref: &str) -> &'static str {
    if git_ref.starts_with("refs/tags/") {
        "tag"
    } else if git_ref.starts_with("refs/heads/") {
        "branch"
    } else if is_sha_like(git_ref) {
        "commit"
    } else {
        "ref"
    }
}

fn strip_ref_prefix(git_ref: &str) -> String {
    if let Some(rest) = git_ref.strip_prefix("refs/tags/") {
        return rest.to_string();
    }
    if let Some(rest) = git_ref.strip_prefix("refs/heads/") {
        return rest.to_string();
    }
    git_ref.to_string()
}

fn is_sha_like(s: &str) -> bool {
    s.len() >= 7 && s.len() <= 40 && s.chars().all(|c| c.is_ascii_hexdigit())
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

    #[test]
    fn ref_label_classification() {
        assert_eq!(ref_label("refs/tags/v0.0.1"), "tag");
        assert_eq!(ref_label("refs/heads/main"), "branch");
        assert_eq!(ref_label("a1b2c3d4e5f6"), "commit");
        assert_eq!(
            ref_label("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
            "commit"
        );
        assert_eq!(ref_label("something-else"), "ref");
    }

    #[test]
    fn strip_ref_prefix_strips_known_prefixes() {
        assert_eq!(
            strip_ref_prefix("refs/tags/claude-v0.0.11"),
            "claude-v0.0.11"
        );
        assert_eq!(strip_ref_prefix("refs/heads/main"), "main");
        assert_eq!(strip_ref_prefix("abc1234"), "abc1234");
    }
}
