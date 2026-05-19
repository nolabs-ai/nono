//! CLI-side diagnostic-footer rendering for profile-resolver errors.
//!
//! Phase 37 Plan 37-02 D-11 introduces a footer line emitted to the user
//! when `--no-auto-pull` (or `NONO_NO_AUTO_PULL=1`) is set AND the profile
//! resolver returns [`NonoError::ProfileNotFound`]. The error itself is
//! preserved verbatim per D-11 ("fall back to legacy 'profile not found'");
//! the footer is an additive UX hint so users can self-diagnose the cause
//! without grepping the help output.
//!
//! This module is intentionally narrow — it does NOT replace the library-
//! level `nono::DiagnosticFormatter` (which renders sandbox/denial footers
//! after a sandboxed command exits). Profile-resolver footers fire BEFORE
//! sandbox execution starts.

use crate::profile::ResolveContext;
use nono::NonoError;

/// Returns a footer line to emit to the user when the profile-resolver
/// failure is attributable to the `--no-auto-pull` suppression branch.
///
/// Returns `None` when no footer applies (either the error is not
/// `ProfileNotFound`, or `--no-auto-pull` is not set). Callers should
/// `eprintln!` the returned string when `Some`.
///
/// The returned text contains both `--no-auto-pull` and `set` so callers
/// (and tests) can grep for the suppression-cause marker independently of
/// the exact phrasing.
#[must_use]
pub fn format_error_footer(err: &NonoError, ctx: &ResolveContext) -> Option<String> {
    if !ctx.no_auto_pull {
        return None;
    }
    if !matches!(err, NonoError::ProfileNotFound(_)) {
        return None;
    }
    Some(
        "Hint: --no-auto-pull is set; auto-pull suppressed. \
         Re-run without the flag or unset NONO_NO_AUTO_PULL to fetch the profile."
            .to_string(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod diagnostic_footer_tests {
    use super::*;

    #[test]
    fn diagnostic_footer_notes_no_auto_pull_when_set() {
        let err = NonoError::ProfileNotFound("namespace/foo".to_string());
        let ctx = ResolveContext { no_auto_pull: true };
        let footer = format_error_footer(&err, &ctx)
            .expect("footer must fire on ProfileNotFound under --no-auto-pull");
        assert!(
            footer.contains("--no-auto-pull"),
            "footer must mention --no-auto-pull: got {footer:?}"
        );
        assert!(
            footer.contains("set"),
            "footer must indicate the flag is set: got {footer:?}"
        );
    }

    #[test]
    fn diagnostic_footer_silent_when_flag_unset() {
        let err = NonoError::ProfileNotFound("namespace/foo".to_string());
        let ctx = ResolveContext::default();
        assert!(
            format_error_footer(&err, &ctx).is_none(),
            "footer MUST NOT fire when --no-auto-pull is unset (otherwise the \
             default code path leaks the hint into unrelated errors)"
        );
    }

    #[test]
    fn diagnostic_footer_silent_for_unrelated_errors() {
        // Even with --no-auto-pull set, other error variants must NOT trigger
        // the suppression footer (no false positives).
        let err = NonoError::ProfileParse("malformed JSON".to_string());
        let ctx = ResolveContext { no_auto_pull: true };
        assert!(
            format_error_footer(&err, &ctx).is_none(),
            "footer MUST be specific to ProfileNotFound; ProfileParse must not fire it"
        );
    }
}
