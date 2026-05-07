//! Helpers for rendering user-supplied commands for display.
//!
//! Commands passed to `nono` (e.g. after `--`) preserve each argument as a
//! separate `String`. When we echo those commands back to the user — in the
//! `nono learn` "Run with:" hint, the dry-run banner, `nono ps` details,
//! audit/rollback listings — we want the rendered line to round-trip: a user
//! copy-pasting it into a shell must execute the exact same argv that was
//! learned or recorded.
//!
//! A naive `command.join(" ")` breaks that contract as soon as any argument
//! contains whitespace, quotes, `$`, backslashes, etc. `echo 'foo bar' baz`
//! becomes `echo foo bar baz` (three args instead of two). See issue #660.
//!
//! This module centralises shell-quoting via [`shlex::try_quote`] so all
//! display sites stay consistent.

use std::borrow::Cow;

/// Quote a single argument for POSIX shell display.
///
/// Returns the input unchanged when it is already safe to display unquoted
/// (e.g. a simple identifier like `echo`). Falls back to a single-quoted
/// form when the argument contains a NUL byte, which `shlex::try_quote`
/// rejects. NUL cannot appear in a real shell argument, so this fallback
/// is only about keeping display infallible — we still want the user to
/// see *something* if a recorded command contains corrupt data.
fn quote_arg(arg: &str) -> Cow<'_, str> {
    match shlex::try_quote(arg) {
        Ok(quoted) => quoted,
        Err(_) => Cow::Owned(format!("'{}'", arg.replace('\'', "'\\''"))),
    }
}

/// Render a command (program + args) as a single shell-quoted line suitable
/// for display or copy-paste back into a terminal.
///
/// Each element is quoted independently with [`shlex::try_quote`] and joined
/// with spaces. Empty `command` returns an empty string.
pub(crate) fn format_command_line(command: &[String]) -> String {
    command
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Truncate a string to at most `max_len` characters, appending an
/// ellipsis (`...`) when truncated.
///
/// Truncation operates on Unicode scalar values (`char`s), not bytes, so it
/// will never split a multi-byte UTF-8 sequence — byte slicing arbitrary
/// strings is a panic hazard whenever the input contains non-ASCII text.
/// Grapheme-cluster width (e.g. emoji ZWJ sequences, combining marks) is
/// out of scope; callers that render to a fixed-width terminal column
/// should size `max_len` conservatively.
///
/// Edge case: when `max_len < 3` and truncation is needed, the result is
/// just `"..."` (3 chars), which technically exceeds `max_len`. This
/// preserves the prior behaviour and matches the only sensible thing to
/// do — there is no shorter way to signal truncation. Callers should pass
/// `max_len >= 3`.
pub(crate) fn truncate_chars(s: &str, max_len: usize) -> String {
    // Fast path: byte length >= char count always, so if bytes fit, chars fit
    // too. When bytes exceed max_len we still need to check char count —
    // a short string of multi-byte chars may have fewer chars than max_len
    // and must not be truncated.
    if s.len() <= max_len || s.chars().count() <= max_len {
        return s.to_string();
    }
    let keep = max_len.saturating_sub(3);
    let mut truncated: String = s.chars().take(keep).collect();
    truncated.push_str("...");
    truncated
}

/// Render a command via [`format_command_line`] and truncate it to at most
/// `max_len` characters, appending an ellipsis (`...`) when truncated.
///
/// Thin wrapper over [`truncate_chars`]; see that function for truncation
/// semantics.
pub(crate) fn truncate_command(command: &[String], max_len: usize) -> String {
    truncate_chars(&format_command_line(command), max_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_args_unquoted() {
        assert_eq!(
            format_command_line(&["echo".to_string(), "hello".to_string()]),
            "echo hello"
        );
    }

    #[test]
    fn args_with_spaces_are_quoted() {
        let out =
            format_command_line(&["echo".to_string(), "foo bar".to_string(), "baz".to_string()]);
        // Must preserve "foo bar" as a single argument when re-parsed.
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "foo bar", "baz"]);
    }

    #[test]
    fn args_with_single_quotes_are_quoted() {
        let out = format_command_line(&["echo".to_string(), "it's".to_string()]);
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "it's"]);
    }

    #[test]
    fn args_with_double_quotes_are_quoted() {
        let out = format_command_line(&["echo".to_string(), "a\"b".to_string()]);
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "a\"b"]);
    }

    #[test]
    fn args_with_dollar_and_backslash_are_quoted() {
        let out =
            format_command_line(&["echo".to_string(), "$HOME".to_string(), "a\\b".to_string()]);
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "$HOME", "a\\b"]);
    }

    #[test]
    fn empty_arg_is_quoted() {
        let out = format_command_line(&["echo".to_string(), String::new()]);
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", ""]);
    }

    #[test]
    fn empty_command_returns_empty_string() {
        assert_eq!(format_command_line(&[]), "");
    }

    #[test]
    fn issue_660_repro() {
        // From issue #660: `nono learn -- echo 'foo bar' 'baz'` must not
        // render as `echo foo bar baz`.
        let rendered =
            format_command_line(&["echo".to_string(), "foo bar".to_string(), "baz".to_string()]);
        let naive = ["echo", "foo bar", "baz"].join(" ");
        assert_eq!(naive, "echo foo bar baz"); // what the bug produced
        assert_ne!(rendered, naive);
        let reparsed = shlex::split(&rendered).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "foo bar", "baz"]);
    }

    #[test]
    fn truncate_command_short_passes_through() {
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        assert_eq!(truncate_command(&cmd, 40), "echo hello");
    }

    #[test]
    fn truncate_command_handles_multibyte_utf8() {
        // shlex single-quotes non-ASCII args, so the rendered line is
        // `'éééééé'` — each `é` is 2 bytes in UTF-8. With `max_len = 5`,
        // byte slicing at index `max_len - 3 = 2` lands inside the first
        // `é` (between its two bytes, which is *not* a char boundary)
        // and would panic under the previous implementation.
        let cmd = vec!["éééééé".to_string()];
        let result = truncate_command(&cmd, 5);
        // Char-aware: keep `max_len - 3 = 2` chars (`'é`), append "...".
        assert_eq!(result, "'é...");
        assert!(result.chars().count() <= 5);
    }

    #[test]
    fn truncate_command_max_len_smaller_than_ellipsis() {
        // `max_len.saturating_sub(3)` underflows to 0 — we should still
        // produce a non-panicking result.
        let cmd = vec!["echo".to_string(), "hello world".to_string()];
        let result = truncate_command(&cmd, 2);
        assert_eq!(result, "...");
    }

    #[test]
    fn truncate_chars_short_passes_through() {
        assert_eq!(truncate_chars("hello", 40), "hello");
    }

    #[test]
    fn truncate_chars_handles_multibyte_utf8_at_byte_boundary() {
        // Regression: `print_side_by_side_diff` calls `truncate_chars` on
        // diff lines with `col_width = (120-3)/2 = 58`. Byte-slicing at
        // index `max_len - 3 = 54` panics when a 4-byte UTF-8 sequence
        // straddles that boundary.
        //
        // Build a 58-char / 61-byte line where byte 54 is inside an emoji:
        //   53 ASCII bytes + 😀 (bytes 53..57) + "tail" → 58 chars, 61 bytes.
        //   Byte 54 is a continuation byte (0x9F) inside the emoji.
        let prefix: String = "x".repeat(53);
        let line = format!("{prefix}\u{1F600}tail");
        assert_eq!(line.chars().count(), 58);
        assert_eq!(line.len(), 61);
        assert!(!line.is_char_boundary(54)); // byte 54 is mid-emoji

        // max_len = 57 < 58 chars → truncation must fire.
        // Old byte-slicing code slices at byte 54 (= 57-3) → panic.
        // New char-aware code takes 54 chars safely.
        let result = truncate_chars(&line, 57);
        assert!(result.ends_with("..."));
        assert!(result.chars().count() <= 57);
    }

    #[test]
    fn truncate_chars_max_len_smaller_than_ellipsis() {
        assert_eq!(truncate_chars("hello world", 2), "...");
    }

    #[test]
    fn truncate_chars_no_spurious_truncation_of_multibyte_string() {
        // Regression for the Gemini review finding: a string of 5 emojis is
        // 20 bytes but only 5 chars. With max_len = 10, the byte fast-path
        // (20 > 10) falls through — but the char check (5 <= 10) must catch
        // it and return the string unmodified. Without the `|| chars().count()
        // <= max_len` guard, this would be spuriously truncated.
        let s = "\u{1F600}".repeat(5); // 5 chars, 20 bytes
        assert_eq!(s.len(), 20);
        assert_eq!(s.chars().count(), 5);
        assert_eq!(truncate_chars(&s, 10), s); // must NOT truncate
    }
}
