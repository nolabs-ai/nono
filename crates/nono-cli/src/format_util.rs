//! Cross-platform formatting helpers extracted from session_commands /
//! session_commands_windows.
//!
//! Phase 44 IN-03 P37 (REQ-REVIEW-FU-01 D-44-B5): the `format_bytes_short`
//! helper was duplicated verbatim across `session_commands.rs` and
//! `session_commands_windows.rs`. The Unix copy was production code; the
//! Windows copy was `#[cfg(test)]`-gated test-only support for the
//! limits-block round-trip parity tests. Extract the helper to this
//! shared module so a future Windows production caller can use it
//! without re-duplicating and so the two copies cannot drift.
//!
//! The module is gated on non-Windows hosts OR `cfg(test)` because on
//! Windows production code, the Limits-block emission uses the
//! `"100 MiB"` shape rather than the short `"100M"` form — there is no
//! non-test caller on Windows yet. CLAUDE.md § "lazy use of dead code"
//! forbids `#[allow(dead_code)]`, so the cfg gate prevents the helper
//! from compiling into the Windows non-test build where it would
//! otherwise warn. When a Windows production caller is introduced
//! (e.g., to render the short form in `nono inspect` output), drop the
//! `target_os = "windows"` exclusion below.

#![cfg(any(not(target_os = "windows"), test))]

/// Format a byte count as a short human-readable string with binary
/// (KiB / MiB / GiB / TiB) units, omitting the `iB` suffix to match
/// the `--memory` argument grammar used on the command line.
///
/// Round values are formatted with the largest applicable unit; non-round
/// values fall through to the raw byte count (no suffix). The output is
/// LOCKED for REQ-RESL-NIX-01 acceptance #2 — emits
/// `"memory: 100M (cgroup v2 memory.max)"`-style strings that the
/// integration tests assert via substring grep.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(format_bytes_short(0), "0");
/// assert_eq!(format_bytes_short(1024), "1K");
/// assert_eq!(format_bytes_short(1024 * 1024), "1M");
/// assert_eq!(format_bytes_short(1024 * 1024 * 1024), "1G");
/// assert_eq!(format_bytes_short(1500), "1500"); // non-round fall-through
/// ```
pub fn format_bytes_short(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;

    if bytes >= TIB && bytes.is_multiple_of(TIB) {
        format!("{}T", bytes / TIB)
    } else if bytes >= GIB && bytes.is_multiple_of(GIB) {
        format!("{}G", bytes / GIB)
    } else if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{}M", bytes / MIB)
    } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
        format!("{}K", bytes / KIB)
    } else {
        format!("{bytes}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Phase 44 IN-03 P37 regression: pin a few canonical values to
    /// prevent drift. The integration-test grep contract on the
    /// limits-block output depends on these exact rendered forms.
    #[test]
    fn format_bytes_short_handles_unit_boundaries() {
        assert_eq!(format_bytes_short(0), "0");
        assert_eq!(format_bytes_short(1024), "1K");
        assert_eq!(format_bytes_short(1024 * 1024), "1M");
        assert_eq!(format_bytes_short(1024 * 1024 * 1024), "1G");
        assert_eq!(format_bytes_short(1024_u64.pow(4)), "1T");
    }

    #[test]
    fn format_bytes_short_falls_back_to_raw_on_non_round_values() {
        assert_eq!(format_bytes_short(1500), "1500");
        assert_eq!(format_bytes_short(1025), "1025");
    }

    #[test]
    fn format_bytes_short_uses_largest_applicable_unit() {
        assert_eq!(format_bytes_short(100 * 1024 * 1024), "100M");
        assert_eq!(format_bytes_short(2 * 1024 * 1024 * 1024), "2G");
    }
}
