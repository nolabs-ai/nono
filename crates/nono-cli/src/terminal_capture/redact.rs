//! Known-credential removal for captured terminal bytes (NEP-0010 §3.1).
//!
//! Every credential value nono resolved for the session is matched raw, in
//! base64 (standard and URL-safe, at every byte alignment) and
//! percent-encoded, with one linear-time Aho-Corasick automaton. Matches are
//! replaced with `[redacted:credential:<name>]`.
//!
//! A value split across two reads is still matched: each stream holds back a
//! tail one byte shorter than the longest pattern and releases it with the
//! next read, or when the caller flushes (chunk close, suspend, session end).
//!
//! Values shorter than [`MIN_MATCH_LEN`] bytes are not matched, because they
//! would match ordinary text. Their names (never their values) are reported
//! so the gap is visible.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use nono::{NonoError, Result};
use nono_proxy::SecretRegistry;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// Values shorter than this many bytes are not matched.
pub(crate) const MIN_MATCH_LEN: usize = 8;

/// The compiled matcher for one registry version.
struct Matcher {
    /// `None` when no value is long enough to match.
    automaton: Option<AhoCorasick>,
    /// Pattern id → replacement text.
    replacements: Vec<Vec<u8>>,
    /// Longest pattern length in bytes.
    max_len: usize,
    /// The patterns, sorted, to find tails that could start a match.
    sorted: Vec<Zeroizing<Vec<u8>>>,
    /// Names of values too short to match.
    unmatched: BTreeSet<String>,
}

impl Matcher {
    fn build(registry: &SecretRegistry) -> Result<Self> {
        let (_, entries) = registry.snapshot();
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut replacements = Vec::new();
        let mut unmatched = BTreeSet::new();
        for entry in &entries {
            let name = sanitize_name(&entry.name);
            if entry.value.len() < MIN_MATCH_LEN {
                unmatched.insert(name);
                continue;
            }
            for variant in encoded_variants(entry.value.as_bytes()) {
                if variant.len() < MIN_MATCH_LEN || patterns.iter().any(|p| **p == *variant) {
                    continue;
                }
                patterns.push(variant);
                replacements.push(format!("[redacted:credential:{name}]").into_bytes());
            }
        }
        let max_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let mut sorted: Vec<Zeroizing<Vec<u8>>> = patterns.clone();
        sorted.sort_unstable_by(|a, b| a.as_slice().cmp(b.as_slice()));
        let automaton = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(patterns.iter().map(|p| p.as_slice()))
                    .map_err(|e| {
                        // The error describes automaton limits, never pattern bytes.
                        NonoError::ConfigParse(format!(
                            "failed to build terminal credential matcher: {e}"
                        ))
                    })?,
            )
        };
        Ok(Self {
            automaton,
            replacements,
            max_len,
            sorted,
            unmatched,
        })
    }

    /// Whether `tail` is the start of some pattern that is longer than it,
    /// so more input could complete a match.
    fn could_continue(&self, tail: &[u8]) -> bool {
        let first = self.sorted.partition_point(|p| p.as_slice() < tail);
        self.sorted[first..]
            .iter()
            .take_while(|p| p.starts_with(tail))
            .any(|p| p.len() > tail.len())
    }

    /// Where the bytes that must be held back begin: the earliest position
    /// from which the rest of `buf` could still grow into a match. Any match
    /// that runs past the end of `buf` starts at such a position, and no
    /// pattern is longer than `max_len`, so only the last `max_len - 1`
    /// positions need checking.
    fn hold_from(&self, buf: &[u8]) -> usize {
        let earliest = buf.len().saturating_sub(self.max_len.saturating_sub(1));
        (earliest..buf.len())
            .find(|&start| self.could_continue(&buf[start..]))
            .unwrap_or(buf.len())
    }
}

/// Names are interpolated into recordings; keep them to a safe alphabet.
fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "unnamed".to_string()
    } else {
        cleaned
    }
}

/// The forms a value can take in terminal bytes: raw, percent-encoded, and
/// base64 (standard and URL-safe).
///
/// Base64 of a value embedded in a larger encoded string depends on the
/// value's byte offset modulo 3, so for each alignment only the characters
/// determined entirely by the value's own bits are used. Padding is never
/// part of a pattern, so padded and unpadded encodings both match.
fn encoded_variants(value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out = vec![Zeroizing::new(value.to_vec())];
    for upper in [true, false] {
        let encoded = percent_encode(value, upper);
        if *encoded != value {
            out.push(encoded);
        }
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for align in 0..3usize {
            let mut input = Zeroizing::new(vec![0u8; align]);
            input.extend_from_slice(value);
            let encoded = Zeroizing::new(engine.encode(input.as_slice()).into_bytes());
            let total_bits = input.len().saturating_mul(8);
            let prefix_bits = align.saturating_mul(8);
            let start = prefix_bits.div_ceil(6);
            let end = total_bits / 6;
            if start < end && end <= encoded.len() {
                out.push(Zeroizing::new(encoded[start..end].to_vec()));
            }
        }
    }
    out
}

/// Percent-encode every byte outside the RFC 3986 unreserved set.
fn percent_encode(value: &[u8], upper: bool) -> Zeroizing<Vec<u8>> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Zeroizing::new(Vec::with_capacity(value.len()));
    for &b in value {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(digits[usize::from(b >> 4)]);
            out.push(digits[usize::from(b & 0x0f)]);
        }
    }
    out
}

/// Result of protecting one read.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Redacted {
    /// Bytes safe to hand to sinks.
    pub(crate) bytes: Vec<u8>,
    /// Number of values replaced.
    pub(crate) redactions: u64,
}

/// One stream's held-back tail.
#[derive(Default)]
struct StreamState {
    pending: Zeroizing<Vec<u8>>,
}

/// Removes known credential values from one or more byte streams.
pub(crate) struct Redactor {
    registry: SecretRegistry,
    version: u64,
    matcher: Matcher,
    streams: Vec<StreamState>,
}

impl Redactor {
    /// Build a redactor over `registry` with `streams` independent streams.
    pub(crate) fn new(registry: SecretRegistry, streams: usize) -> Result<Self> {
        let version = registry.version();
        let matcher = Matcher::build(&registry)?;
        Ok(Self {
            registry,
            version,
            matcher,
            streams: (0..streams).map(|_| StreamState::default()).collect(),
        })
    }

    /// Rebuild the matcher if new values were registered.
    ///
    /// Returns the new set of unmatched names when it changed.
    pub(crate) fn refresh(&mut self) -> Result<Option<BTreeSet<String>>> {
        let version = self.registry.version();
        if version == self.version {
            return Ok(None);
        }
        let matcher = Matcher::build(&self.registry)?;
        let changed = matcher.unmatched != self.matcher.unmatched;
        self.matcher = matcher;
        self.version = version;
        Ok(changed.then(|| self.matcher.unmatched.clone()))
    }

    /// Names of values too short to match.
    pub(crate) fn unmatched_names(&self) -> &BTreeSet<String> {
        &self.matcher.unmatched
    }

    /// Whether any value can currently be matched.
    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        self.matcher.automaton.is_some()
    }

    /// Protect `input` on `stream`, holding back a possible partial match.
    pub(crate) fn process(&mut self, stream: usize, input: &[u8]) -> Redacted {
        self.run(stream, input, false)
    }

    /// Release everything held back on `stream`.
    pub(crate) fn flush(&mut self, stream: usize) -> Redacted {
        self.run(stream, &[], true)
    }

    /// Whether `stream` holds back any bytes.
    pub(crate) fn has_pending(&self, stream: usize) -> bool {
        self.streams
            .get(stream)
            .is_some_and(|s| !s.pending.is_empty())
    }

    fn run(&mut self, stream: usize, input: &[u8], final_flush: bool) -> Redacted {
        let Some(state) = self.streams.get_mut(stream) else {
            return Redacted::default();
        };
        let Some(automaton) = self.matcher.automaton.as_ref() else {
            // Nothing to match: pass through, releasing any earlier tail.
            let mut bytes = std::mem::take(&mut *state.pending);
            bytes.extend_from_slice(input);
            return Redacted {
                bytes,
                redactions: 0,
            };
        };
        let mut buf = Zeroizing::new(std::mem::take(&mut *state.pending));
        buf.extend_from_slice(input);

        let safe = if final_flush {
            buf.len()
        } else {
            self.matcher.hold_from(&buf)
        };

        let mut out = Vec::with_capacity(buf.len());
        let mut cursor = 0usize;
        let mut redactions = 0u64;
        for m in automaton.find_iter(buf.as_slice()) {
            if m.start() >= safe {
                break;
            }
            out.extend_from_slice(&buf[cursor..m.start()]);
            if let Some(replacement) = self.matcher.replacements.get(m.pattern().as_usize()) {
                out.extend_from_slice(replacement);
            }
            redactions = redactions.saturating_add(1);
            cursor = m.end();
        }
        // Release up to the safe point, unless a match already consumed past it.
        let release_to = safe.max(cursor);
        if release_to > cursor {
            out.extend_from_slice(&buf[cursor..release_to]);
        }
        state.pending = Zeroizing::new(buf[release_to..].to_vec());
        Redacted {
            bytes: out,
            redactions,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-live-abcdef0123456789";

    fn redactor_with(entries: &[(&str, &str)]) -> Redactor {
        let registry = SecretRegistry::new();
        for (name, value) in entries {
            registry.register(name, value);
        }
        Redactor::new(registry, 2).unwrap()
    }

    fn all(r: &mut Redactor, stream: usize, chunks: &[&[u8]]) -> (Vec<u8>, u64) {
        let mut bytes = Vec::new();
        let mut count = 0;
        for chunk in chunks {
            let out = r.process(stream, chunk);
            bytes.extend(out.bytes);
            count += out.redactions;
        }
        let out = r.flush(stream);
        bytes.extend(out.bytes);
        (bytes, count + out.redactions)
    }

    #[test]
    fn replaces_raw_value() {
        let mut r = redactor_with(&[("OPENAI_API_KEY", SECRET)]);
        let (out, n) = all(&mut r, 0, &[format!("key={SECRET}\r\n").as_bytes()]);
        assert_eq!(out, b"key=[redacted:credential:OPENAI_API_KEY]\r\n");
        assert_eq!(n, 1);
    }

    #[test]
    fn matches_value_split_across_reads() {
        let mut r = redactor_with(&[("tok", SECRET)]);
        let (a, b) = SECRET.split_at(7);
        let (out, n) = all(
            &mut r,
            0,
            &[format!("x{a}").as_bytes(), format!("{b}y").as_bytes()],
        );
        assert_eq!(out, b"x[redacted:credential:tok]y");
        assert_eq!(n, 1);
    }

    #[test]
    fn matches_one_byte_at_a_time() {
        let mut r = redactor_with(&[("tok", SECRET)]);
        let input = format!("> {SECRET} <");
        let chunks: Vec<&[u8]> = input.as_bytes().chunks(1).collect();
        let (out, n) = all(&mut r, 0, &chunks);
        assert_eq!(out, b"> [redacted:credential:tok] <");
        assert_eq!(n, 1);
    }

    #[test]
    fn streams_are_independent() {
        let mut r = redactor_with(&[("tok", SECRET)]);
        let (a, b) = SECRET.split_at(10);
        let first = r.process(0, a.as_bytes());
        let other = r.process(1, b.as_bytes());
        let rest = r.flush(0);
        let mut zero = first.bytes;
        zero.extend(rest.bytes);
        assert_eq!(zero, a.as_bytes());
        let mut one = other.bytes;
        one.extend(r.flush(1).bytes);
        assert_eq!(one, b.as_bytes());
    }

    #[test]
    fn matches_base64_at_every_alignment_and_both_alphabets() {
        let secret = "p4ss?w0rd>with/odd+bytes~~";
        let mut r = redactor_with(&[("pw", secret)]);
        for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
            for prefix in ["", "a", "ab", "user:"] {
                let encoded = engine.encode(format!("{prefix}{secret}trailer"));
                let (out, n) = all(&mut r, 0, &[encoded.as_bytes()]);
                assert_eq!(n, 1, "prefix {prefix:?}: {}", String::from_utf8_lossy(&out));
                assert!(!String::from_utf8_lossy(&out).contains(&engine.encode(secret)[2..10]));
            }
        }
    }

    #[test]
    fn matches_basic_auth_header() {
        let mut r = redactor_with(&[("pw", "hunter2-hunter2")]);
        let header = format!(
            "Authorization: Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:hunter2-hunter2")
        );
        let (_, n) = all(&mut r, 0, &[header.as_bytes()]);
        assert_eq!(n, 1);
    }

    #[test]
    fn matches_percent_encoded_in_either_case() {
        let secret = "a/b+c=d e&f";
        let mut r = redactor_with(&[("q", secret)]);
        let (out, n) = all(
            &mut r,
            0,
            &[b"?t=a%2Fb%2Bc%3Dd%20e%26f&u=a%2fb%2bc%3dd%20e%26f"],
        );
        assert_eq!(n, 2, "{}", String::from_utf8_lossy(&out));
    }

    #[test]
    fn short_values_are_reported_not_matched() {
        let mut r = redactor_with(&[("PIN", "1234"), ("tok", SECRET)]);
        let (out, n) = all(&mut r, 0, &[b"pin 1234"]);
        assert_eq!(out, b"pin 1234");
        assert_eq!(n, 0);
        assert!(r.unmatched_names().contains("PIN"));
        assert!(!r.unmatched_names().contains("tok"));
    }

    #[test]
    fn values_registered_later_are_matched_after_refresh() {
        let registry = SecretRegistry::new();
        let mut r = Redactor::new(registry.clone(), 1).unwrap();
        assert!(!r.is_active());
        registry.register("late", SECRET);
        registry.register("short", "abc");
        let unmatched = r.refresh().unwrap().unwrap();
        assert!(unmatched.contains("short"));
        assert!(r.refresh().unwrap().is_none());
        let (out, n) = all(&mut r, 0, &[SECRET.as_bytes()]);
        assert_eq!(out, b"[redacted:credential:late]");
        assert_eq!(n, 1);
    }

    #[test]
    fn inactive_redactor_passes_bytes_through_immediately() {
        let mut r = redactor_with(&[]);
        let out = r.process(0, b"hello");
        assert_eq!(out.bytes, b"hello");
        assert!(!r.has_pending(0));
    }

    #[test]
    fn holdback_never_exceeds_longest_pattern() {
        let mut r = redactor_with(&[("tok", SECRET)]);
        let max_len = r.matcher.max_len;
        let mut input = vec![b's'; 4096];
        input.extend_from_slice(&SECRET.as_bytes()[..SECRET.len() - 1]);
        let out = r.process(0, &input);
        assert!(input.len() - out.bytes.len() < max_len);
    }

    #[test]
    fn only_a_possible_credential_start_is_held_back() {
        let mut r = redactor_with(&[("tok", SECRET)]);
        let out = r.process(0, b"Password: ");
        assert_eq!(
            out.bytes, b"Password: ",
            "nothing here can start a credential"
        );
        assert!(!r.has_pending(0));

        let out = r.process(0, b"key=sk-li");
        assert_eq!(out.bytes, b"key=", "the possible start is held");
        let out = r.process(0, b"ve-abcdef0123456789 ok");
        assert_eq!(out.bytes, b"[redacted:credential:tok] ok");
        assert!(!r.has_pending(0));
    }

    #[test]
    fn names_are_sanitized() {
        let mut r = redactor_with(&[("bad]\x1b[31mname", SECRET)]);
        let (out, _) = all(&mut r, 0, &[SECRET.as_bytes()]);
        assert_eq!(out, b"[redacted:credential:bad___31mname]");
    }
}
