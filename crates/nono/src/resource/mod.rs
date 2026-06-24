//! Resource limits — parsed, validated ceilings for a sandboxed process tree.
//!
//! This is the internal, enforcement-facing representation, mirroring how
//! [`crate::capability::CapabilitySet`] is the internal type while the
//! schema-generated [`crate::manifest`] types are the on-disk contract.
//!
//! Scope note (issue #1102): this module defines the limits and parses them
//! from human-friendly CLI input; the configuration, serialization, and
//! `--dry-run` layers carry them end-to-end. Enforcement lives in the CLI
//! supervisor (`nono-cli`'s `resource_cgroup`), which renders these values to
//! cgroup v2 knobs on Linux — keeping the library policy-free.

use crate::error::{NonoError, Result};
use serde::{Deserialize, Serialize};

/// Parsed, validated resource ceilings. `None` means "no limit" for that
/// dimension. Values are raw bytes / counts — human-friendly sizes such as
/// `512M` are parsed at the CLI boundary via [`parse_size`], never stored as
/// strings, so the manifest stays a fully-resolved machine contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum resident memory for the process tree, in bytes
    /// (cgroup `memory.max` + `memory.swap.max=0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    /// Maximum CPU bandwidth for the process tree, as a percentage of a single
    /// CPU core: `100` is one full core, `150` is one and a half cores, `50` is
    /// half a core (cgroup `cpu.max` with a fixed 100 ms period). This is a
    /// *rate* cap (a share of CPU), not a cumulative CPU-seconds budget — a
    /// throttled process may run indefinitely but can never starve the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_max_percent: Option<u64>,
    /// Maximum number of processes/threads in the tree (cgroup `pids.max`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_procs: Option<u64>,
}

impl ResourceLimits {
    /// True when no ceiling is set at all. Used to decide whether limits are
    /// worth displaying or requiring a supervised run.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memory_bytes.is_none() && self.cpu_max_percent.is_none() && self.max_procs.is_none()
    }

    /// One-line human-readable summary for `--dry-run` / capability output.
    #[must_use]
    pub fn summary(&self) -> String {
        let mem = self
            .memory_bytes
            .map_or_else(|| "unlimited".to_string(), format_bytes);
        let cpu = self
            .cpu_max_percent
            .map_or_else(|| "unlimited".to_string(), |p| format!("{p}%"));
        let procs = self
            .max_procs
            .map_or_else(|| "unlimited".to_string(), |n| n.to_string());
        format!("memory={mem} cpu={cpu} max-procs={procs}")
    }
}

/// Parse a human-friendly size string into a byte count.
///
/// Accepts an integer followed by an optional unit suffix (case-insensitive):
/// bare / `B` = bytes; `K`/`KiB`/`Ki`, `M`/`MiB`/`Mi`, `G`/`GiB`/`Gi`,
/// `T`/`TiB`/`Ti` are binary (1024-based); `KB`/`MB`/`GB`/`TB` are decimal
/// (1000-based). Examples: `512M` → 536870912, `1Gi` → 1073741824.
///
/// Returns [`NonoError::ConfigParse`] on an empty string, missing number,
/// non-integer mantissa, unknown unit, overflow, or a zero result (a limit of
/// zero is rejected rather than silently meaning "unlimited").
pub fn parse_size(input: &str) -> Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        return Err(NonoError::ConfigParse("size cannot be empty".to_string()));
    }

    let digits_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num_str, unit) = s.split_at(digits_end);
    if num_str.is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "invalid size '{input}': missing numeric value (decimals are not supported, e.g. use 512M not 0.5G)"
        )));
    }
    let value: u64 = num_str.parse().map_err(|_| {
        NonoError::ConfigParse(format!(
            "invalid size '{input}': '{num_str}' is not a valid integer"
        ))
    })?;

    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "ki" | "kib" => 1024,
        "kb" => 1000,
        "m" | "mi" | "mib" => 1024 * 1024,
        "mb" => 1000 * 1000,
        "g" | "gi" | "gib" => 1024 * 1024 * 1024,
        "gb" => 1000 * 1000 * 1000,
        "t" | "ti" | "tib" => 1024_u64.pow(4),
        "tb" => 1000_u64.pow(4),
        other => {
            return Err(NonoError::ConfigParse(format!(
                "invalid size '{input}': unknown unit '{other}' (use B, K/KiB, M/MiB, G/GiB, T/TiB)"
            )));
        }
    };

    let bytes = value.checked_mul(multiplier).ok_or_else(|| {
        NonoError::ConfigParse(format!("size '{input}' overflows a 64-bit byte count"))
    })?;
    if bytes == 0 {
        return Err(NonoError::ConfigParse(format!(
            "size '{input}' must be greater than zero"
        )));
    }
    Ok(bytes)
}

/// Parse a CPU bandwidth limit into a percentage of a single core.
///
/// Two notations are accepted:
/// - a percentage with a trailing `%` — `50%` → `50`, `200%` → `200`;
/// - a (possibly fractional) number of cores — `1.5` → `150`, `2` → `200`,
///   `0.5` → `50`.
///
/// The result is "percent of one core", so `100` means one full core. This is
/// the value stored in [`ResourceLimits::cpu_max_percent`] and later rendered to
/// the cgroup `cpu.max` knob.
///
/// Returns [`NonoError::ConfigParse`] on an empty string, a non-numeric value, a
/// non-finite or non-positive number of cores, or a result of zero (a limit of
/// zero is rejected rather than silently meaning "unlimited").
pub fn parse_cpu_max(input: &str) -> Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        return Err(NonoError::ConfigParse(
            "cpu limit cannot be empty".to_string(),
        ));
    }

    if let Some(percent_str) = s.strip_suffix('%') {
        // Percent notation: a whole-number percentage of one core.
        let percent_str = percent_str.trim();
        let percent: u64 = percent_str.parse().map_err(|_| {
            NonoError::ConfigParse(format!(
                "invalid cpu limit '{input}': '{percent_str}' is not a whole percentage \
                 (e.g. 50% for half a core)"
            ))
        })?;
        if percent == 0 {
            return Err(NonoError::ConfigParse(format!(
                "cpu limit '{input}' must be greater than zero"
            )));
        }
        return Ok(percent);
    }

    // Cores notation: a possibly-fractional number of cores (e.g. 1.5).
    let cores: f64 = s.parse().map_err(|_| {
        NonoError::ConfigParse(format!(
            "invalid cpu limit '{input}': use a percentage like '50%' or a number of \
             cores like '1.5'"
        ))
    })?;
    if !cores.is_finite() || cores <= 0.0 {
        return Err(NonoError::ConfigParse(format!(
            "cpu limit '{input}' must be a positive number of cores"
        )));
    }
    // Cores → percent of one core. Round to the nearest whole percent; reject
    // anything that rounds down to zero (smaller than 1% of a core).
    let percent = (cores * 100.0).round();
    if percent < 1.0 {
        return Err(NonoError::ConfigParse(format!(
            "cpu limit '{input}' is too small (the minimum is 0.01 cores, i.e. 1%)"
        )));
    }
    // `percent` is finite and >= 1.0 here; the saturating f64→u64 cast cannot
    // wrap, and a value beyond u64 range is an absurd core count we clamp.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(percent as u64)
}

/// Format a byte count with binary units for display (e.g. `512.0 MiB`).
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut val = bytes as f64;
    let mut idx = 0;
    while val >= 1024.0 && idx < UNITS.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{bytes} B")
    } else {
        format!("{val:.1} {}", UNITS[idx])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_plain_bytes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1B").unwrap(), 1);
    }

    #[test]
    fn parse_size_binary_units() {
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("1Gi").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("2KiB").unwrap(), 2048);
        assert_eq!(parse_size("1t").unwrap(), 1024_u64.pow(4));
    }

    #[test]
    fn parse_size_decimal_units() {
        assert_eq!(parse_size("1KB").unwrap(), 1000);
        assert_eq!(parse_size("1MB").unwrap(), 1_000_000);
    }

    #[test]
    fn parse_size_is_case_insensitive_and_trims() {
        assert_eq!(parse_size("  512m  ").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("1GIB").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_rejects_bad_input() {
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("M").is_err());
        assert!(parse_size("12x").is_err());
        assert!(parse_size("0").is_err(), "zero must be rejected");
        assert!(parse_size("0M").is_err(), "zero must be rejected");
        assert!(parse_size("1.5G").is_err(), "decimals are not supported");
    }

    #[test]
    fn parse_size_rejects_overflow() {
        assert!(parse_size("99999999999999999999T").is_err());
    }

    #[test]
    fn parse_cpu_max_percentage_notation() {
        assert_eq!(parse_cpu_max("50%").unwrap(), 50);
        assert_eq!(parse_cpu_max("100%").unwrap(), 100);
        assert_eq!(parse_cpu_max("200%").unwrap(), 200);
        assert_eq!(parse_cpu_max("  75%  ").unwrap(), 75);
    }

    #[test]
    fn parse_cpu_max_cores_notation() {
        assert_eq!(parse_cpu_max("1").unwrap(), 100);
        assert_eq!(parse_cpu_max("2").unwrap(), 200);
        assert_eq!(parse_cpu_max("1.5").unwrap(), 150);
        assert_eq!(parse_cpu_max("0.5").unwrap(), 50);
        assert_eq!(parse_cpu_max("0.25").unwrap(), 25);
    }

    #[test]
    fn parse_cpu_max_rejects_bad_input() {
        assert!(parse_cpu_max("").is_err());
        assert!(parse_cpu_max("abc").is_err());
        assert!(parse_cpu_max("%").is_err());
        assert!(
            parse_cpu_max("0%").is_err(),
            "zero percent must be rejected"
        );
        assert!(parse_cpu_max("0").is_err(), "zero cores must be rejected");
        assert!(
            parse_cpu_max("0.001").is_err(),
            "below 1% must be rejected, not silently rounded to zero"
        );
        assert!(
            parse_cpu_max("-1").is_err(),
            "negative cores must be rejected"
        );
        assert!(
            parse_cpu_max("1.5%").is_err(),
            "fractional percent is not a whole percentage"
        );
    }

    #[test]
    fn limits_is_empty_and_summary() {
        let none = ResourceLimits::default();
        assert!(none.is_empty());

        let some = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            cpu_max_percent: Some(150),
            max_procs: Some(64),
        };
        assert!(!some.is_empty());
        let s = some.summary();
        assert!(s.contains("512.0 MiB"), "got: {s}");
        assert!(s.contains("cpu=150%"), "got: {s}");
        assert!(s.contains("max-procs=64"), "got: {s}");

        // A cpu-only limit is still non-empty (so it routes to a supervised run).
        let cpu_only = ResourceLimits {
            cpu_max_percent: Some(50),
            ..ResourceLimits::default()
        };
        assert!(!cpu_only.is_empty());
    }

    #[test]
    fn limits_serde_roundtrip() {
        let limits = ResourceLimits {
            memory_bytes: Some(1024),
            cpu_max_percent: Some(50),
            max_procs: None,
        };
        let json = serde_json::to_string(&limits).unwrap();
        let back: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(limits, back);
    }
}
