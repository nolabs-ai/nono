//! Resource limits — parsed, validated ceilings for a sandboxed process tree.
//!
//! This is the internal, enforcement-facing type; the schema-generated
//! [`crate::manifest`] types are the on-disk contract. (Same split as
//! [`crate::capability::CapabilitySet`] vs the manifest.)
//!
//! This module defines the limits and parses them from human-friendly CLI
//! input; config, serialization, and `--dry-run` carry them end-to-end.
//! Enforcement lives in the CLI supervisor (`nono-cli`'s `resource_cgroup`),
//! which renders these values to cgroup v2 knobs on Linux — keeping the
//! library policy-free.

use crate::error::{NonoError, Result};
use serde::{Deserialize, Serialize};

/// Parsed, validated resource ceilings. `None` means "no limit" for that
/// dimension. Values are raw bytes / counts — human-friendly sizes such as
/// `512M` are parsed at the CLI boundary via [`parse_size`], never stored as
/// strings, so the manifest stays a fully-resolved machine contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum resident memory for the process tree, in bytes
    /// (cgroup `memory.max` + `memory.swap.max=0` + `memory.oom.group=1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
}

impl ResourceLimits {
    /// True when no ceiling is set. Used to decide whether to display limits or
    /// require a supervised run.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memory_bytes.is_none()
    }

    /// One-line human-readable summary for `--dry-run` / capability output.
    #[must_use]
    pub fn summary(&self) -> String {
        let mem = self
            .memory_bytes
            .map_or_else(|| "unlimited".to_string(), format_bytes);
        format!("memory={mem}")
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

/// Format a byte count with binary units for display (e.g. `512.0 MiB`).
///
/// Shared by [`ResourceLimits::summary`] and the CLI's failure diagnostics so a
/// limit and the memory that breached it are rendered the same way everywhere.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut val = bytes as f64;
    let mut idx = 0;
    while val >= 1024.0 && idx < UNITS.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        // Under 1 KiB: whole bytes, no decimal.
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
    fn limits_is_empty_and_summary() {
        let none = ResourceLimits::default();
        assert!(none.is_empty());

        let some = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
        };
        assert!(!some.is_empty());
        let s = some.summary();
        assert_eq!(s, "memory=512.0 MiB");

        let unset = ResourceLimits::default();
        assert_eq!(unset.summary(), "memory=unlimited");
    }

    #[test]
    fn limits_serde_roundtrip() {
        let limits = ResourceLimits {
            memory_bytes: Some(1024),
        };
        let json = serde_json::to_string(&limits).unwrap();
        let back: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(limits, back);
    }

    // ---- Pure-function correctness & serde contract ----

    #[test]
    fn parse_size_zero_forms_and_leading_chars() {
        // Every spelling that evaluates to zero must be rejected: a zero limit is
        // refused rather than silently meaning "unlimited".
        assert!(parse_size("0").is_err());
        assert!(parse_size("00").is_err());
        assert!(parse_size("000").is_err());
        assert!(parse_size("0B").is_err());
        assert!(parse_size("0K").is_err());
        assert!(parse_size("000K").is_err());

        // A leading '+' is not an ASCII digit, so digits_end is 0 and the numeric
        // part is empty -> rejected as a missing numeric value (NOT parsed as +5).
        assert!(parse_size("+5").is_err());

        // Leading zeros on a non-zero value are accepted (u64 parse ignores them).
        assert_eq!(parse_size("007").unwrap(), 7);
        assert_eq!(parse_size("0007K").unwrap(), 7 * 1024);
    }

    #[test]
    fn parse_size_unit_overflow_boundaries_per_unit() {
        // For each multiplier, the largest value that still fits in u64 must parse,
        // and the next integer up must be rejected as overflow. This pins the
        // checked_mul boundary exactly rather than just "some huge value fails".

        // K / Ki / KiB multiplier = 1024. u64::MAX / 1024 = 18014398509481983.
        assert_eq!(
            parse_size("18014398509481983K").unwrap(),
            18_014_398_509_481_983_u64 * 1024
        );
        assert!(parse_size("18014398509481984K").is_err());

        // KB multiplier = 1000. u64::MAX / 1000 = 18446744073709551.
        assert_eq!(
            parse_size("18446744073709551KB").unwrap(),
            18_446_744_073_709_551_u64 * 1000
        );
        assert!(parse_size("18446744073709552KB").is_err());

        // T / Ti / TiB multiplier = 1024^4 = 1099511627776.
        // u64::MAX / 1099511627776 = 16777215.
        assert_eq!(
            parse_size("16777215T").unwrap(),
            16_777_215_u64 * 1024_u64.pow(4)
        );
        assert!(parse_size("16777216T").is_err());

        // Bare bytes have multiplier 1: u64::MAX itself fits, nothing overflows.
        assert_eq!(parse_size("18446744073709551615").unwrap(), u64::MAX);
    }

    #[test]
    fn parse_size_unit_distinctions_and_internal_whitespace() {
        // Decimal vs binary kilobyte must be distinct, asserted side by side.
        assert_eq!(parse_size("1KB").unwrap(), 1000);
        assert_eq!(parse_size("1KiB").unwrap(), 1024);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("1Ki").unwrap(), 1024);
        // ...and the same one-step-up distinction for M.
        assert_eq!(parse_size("1MB").unwrap(), 1_000_000);
        assert_eq!(parse_size("1MiB").unwrap(), 1024 * 1024);

        // Whitespace BETWEEN the number and the unit is tolerated, because the
        // unit is trimmed before matching: "1 K" -> unit " K" -> "k" -> 1024.
        assert_eq!(parse_size("1 K").unwrap(), 1024);
        assert_eq!(parse_size("512 MiB").unwrap(), 512 * 1024 * 1024);

        // But a SECOND run of digits after a space is part of the unit, which then
        // fails to match any known unit -> rejected (not silently truncated).
        assert!(parse_size("5 12").is_err());
        assert!(parse_size("1 2K").is_err());
    }

    #[test]
    fn format_bytes_via_summary_exact_boundaries() {
        // format_bytes is private; exercise it through ResourceLimits::summary(),
        // which prepends "memory=". Pin the exact rendering at the unit boundaries,
        // the sub-KiB whole-byte branch, a TiB value, the unit cap, and a rounding
        // case.
        let mem = |b: u64| {
            ResourceLimits {
                memory_bytes: Some(b),
            }
            .summary()
        };

        // Under 1 KiB: whole bytes, no decimal, ' B' suffix.
        assert_eq!(mem(1), "memory=1 B");
        assert_eq!(mem(1023), "memory=1023 B");
        // Exactly 1 KiB: switches to one-decimal binary unit.
        assert_eq!(mem(1024), "memory=1.0 KiB");
        // Half a KiB above 1 KiB.
        assert_eq!(mem(1536), "memory=1.5 KiB");
        // 1587 / 1024 = 1.5498 -> rounds to one decimal as 1.5.
        assert_eq!(mem(1587), "memory=1.5 KiB");
        // 1100 / 1024 = 1.0742 -> rounds to 1.1.
        assert_eq!(mem(1100), "memory=1.1 KiB");
        // Exact MiB / GiB.
        assert_eq!(mem(1024 * 1024), "memory=1.0 MiB");
        assert_eq!(mem(1024 * 1024 * 1024), "memory=1.0 GiB");
        // Exact TiB (1024^4).
        assert_eq!(mem(1024_u64.pow(4)), "memory=1.0 TiB");
        assert_eq!(mem(1024_u64.pow(4) + 1024_u64.pow(4) / 2), "memory=1.5 TiB");
        // 1 PiB has no PiB unit: the loop caps at TiB, so it reads as 1024.0 TiB.
        assert_eq!(mem(1024_u64.pow(5)), "memory=1024.0 TiB");
    }

    #[test]
    fn parse_size_format_bytes_roundtrip_on_exact_binary_values() {
        // For values that are an exact, single-unit binary multiple, summary()'s
        // rendered form re-parses (via parse_size) back to the same byte count:
        // a closed loop proving the human-facing units and the parser agree.
        for (bytes, unit) in [
            (1024_u64, "KiB"),
            (512 * 1024, "KiB"),
            (1024 * 1024, "MiB"),
            (512 * 1024 * 1024, "MiB"),
            (1024 * 1024 * 1024, "GiB"),
            (1024_u64.pow(4), "TiB"),
        ] {
            // summary renders e.g. "memory=1.0 KiB"; strip the prefix and the ".0"
            // to reconstruct the integer+unit the parser accepts.
            let summary = ResourceLimits {
                memory_bytes: Some(bytes),
            }
            .summary();
            let rendered = summary.strip_prefix("memory=").unwrap();
            let (value, suffix) = rendered.split_once(' ').unwrap();
            assert_eq!(suffix, unit, "unexpected unit for {bytes}");
            // The integer magnitude in the rendered "<n>.0" form, re-attached to
            // the unit, must parse straight back to the original byte count.
            let int_part = value.strip_suffix(".0").unwrap();
            let reparsed = parse_size(&format!("{int_part}{unit}")).unwrap();
            assert_eq!(reparsed, bytes, "round-trip failed for {bytes}");
        }
    }

    #[test]
    fn is_empty_tracks_memory_field_and_summary_unlimited() {
        // is_empty is exactly memory_bytes.is_none(); summary reflects the same.
        let empty = ResourceLimits { memory_bytes: None };
        assert!(empty.is_empty());
        assert_eq!(empty.summary(), "memory=unlimited");

        // Even a 1-byte limit makes it non-empty and is rendered, not elided.
        let set = ResourceLimits {
            memory_bytes: Some(1),
        };
        assert!(!set.is_empty());
        assert_eq!(set.summary(), "memory=1 B");

        // Default is the unlimited/empty state.
        assert!(ResourceLimits::default().is_empty());
    }

    #[test]
    fn none_memory_serializes_to_empty_object_with_no_key() {
        // skip_serializing_if = "Option::is_none": a None ceiling must produce an
        // empty JSON object, not `{"memory_bytes":null}`. This is the on-disk
        // contract that keeps legacy/None states forward-compatible.
        let none = ResourceLimits::default();
        assert_eq!(serde_json::to_string(&none).unwrap(), "{}");

        let v: serde_json::Value = serde_json::to_value(none).unwrap();
        let obj = v.as_object().expect("serializes to a JSON object");
        assert!(obj.is_empty(), "None must emit no keys, got {obj:?}");
        assert!(!obj.contains_key("memory_bytes"));
    }

    #[test]
    fn empty_and_null_object_deserialize_to_none() {
        // The inverse of the skip-serialize contract: an absent field (`{}`) and an
        // explicit `null` both deserialize back to None via #[serde(default)], so a
        // state written by an older build round-trips cleanly.
        let from_empty: ResourceLimits = serde_json::from_str("{}").unwrap();
        assert!(from_empty.memory_bytes.is_none());
        assert!(from_empty.is_empty());

        let from_null: ResourceLimits = serde_json::from_str(r#"{"memory_bytes":null}"#).unwrap();
        assert!(from_null.memory_bytes.is_none());
    }

    #[test]
    fn some_memory_serializes_with_exactly_one_key_and_roundtrips() {
        // Some(N) must serialize to exactly { "memory_bytes": N } — one key, the
        // right value — and survive a round-trip. (The existing roundtrip test
        // would still pass if a stray key leaked in, since serde ignores unknown
        // fields on the way back; this pins the exact serialized shape.)
        let some = ResourceLimits {
            memory_bytes: Some(536_870_912),
        };
        let v: serde_json::Value = serde_json::to_value(some).unwrap();
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 1, "exactly one serialized key, got {obj:?}");
        assert_eq!(
            obj.get("memory_bytes").and_then(serde_json::Value::as_u64),
            Some(536_870_912)
        );

        let back: ResourceLimits = serde_json::from_value(v).unwrap();
        assert_eq!(back, some);
    }
}
