//! Per-thread deprecation warning machinery (counter + suppression).
//!
//! This module is NOT itself deprecated — it provides infrastructure that
//! survives any individual deprecation cycle. The actual deprecated
//! schema/flag definitions live in `deprecated_schema.rs` (single-cycle,
//! deletable when v1.0.0 lands); this module's primitives are reusable
//! whenever we want to count or suppress deprecation emissions.
//!
//! Why separate from `deprecated_schema.rs`: callers that wrap a parse in
//! a counter (e.g. `cmd_validate`) or suppression scope (e.g.
//! `load_profile_extends`) should not have to import from a module
//! marked "delete this whole file at v1.0.0". The lint enforcement in
//! `scripts/test-list-aliases.sh` keeps the deprecated module's import
//! surface tight precisely because the file is going away — pulling
//! these guards out preserves that property.

use std::cell::Cell;

thread_local! {
    /// `None` when not counting; `Some(n)` inside a counting scope. The
    /// drain sites in `deprecated_schema::emit_deprecation_warning` bump
    /// this when set.
    static WARNING_COUNTER: Cell<Option<usize>> = const { Cell::new(None) };

    /// Non-zero while inside one or more `WarningSuppressionGuard` scopes.
    /// While suppressed, `deprecated_schema::emit_deprecation_warning`
    /// neither prints to stderr nor increments the counter.
    static WARNING_SUPPRESS: Cell<u32> = const { Cell::new(0) };
}

/// RAII guard: activates deprecation-warning counting on the current thread
/// while alive, and exposes the accumulated count on `finish()`.
///
/// The guard must be consumed through `finish()` to read the count. Dropping
/// without calling `finish()` simply clears the slot — early-return paths
/// (e.g. `?` propagation) don't leak counter state into a subsequent
/// command on the same thread.
pub(crate) struct WarningCounterGuard {
    _priv: (),
}

impl WarningCounterGuard {
    /// Begin counting. Panics — in **both** debug and release — if a
    /// guard is already active on this thread.
    ///
    /// Why a hard panic instead of a `debug_assert!`: nested counter
    /// scopes silently corrupt each other's counts. The inner guard's
    /// `Drop` clears the slot, leaving the outer scope reading zero.
    /// `cmd_validate --strict` uses the count to decide exit code 2 vs
    /// 0 — a silently-zeroed counter would mean a profile with legacy
    /// keys passes `--strict` clean, defeating the whole gate. We'd
    /// rather take the loud failure now than miss a security-relevant
    /// signal in production.
    pub(crate) fn begin() -> Self {
        WARNING_COUNTER.with(|c| {
            assert!(
                c.get().is_none(),
                "WarningCounterGuard nested: already counting deprecations on this thread \
                 (nested scopes would silently miscount; see deprecation_warnings.rs)"
            );
            c.set(Some(0));
        });
        Self { _priv: () }
    }

    /// Consume the guard and return the accumulated warning count.
    pub(crate) fn finish(self) -> usize {
        let n = WARNING_COUNTER.with(|c| c.take().unwrap_or(0));
        std::mem::forget(self);
        n
    }
}

impl Drop for WarningCounterGuard {
    fn drop(&mut self) {
        WARNING_COUNTER.with(|c| c.set(None));
    }
}

/// RAII guard: while alive on the current thread, suppresses both stderr
/// emission and counter bumps in `emit_deprecation_warning`. Used for
/// metadata-only previews (e.g. `load_profile_extends`) so a profile
/// that's about to be re-parsed by the real load isn't warned about
/// twice. Suppression is stack-counted, not boolean — nested guards are
/// safe and each only un-suppresses on its own drop.
///
/// **Important: do NOT leak this guard.** A leaked
/// `WarningSuppressionGuard` (via `mem::forget`, panic-across-FFI, or a
/// mis-bound `_ = WarningSuppressionGuard::begin()` that drops it
/// immediately AND the same expression statement is later refactored to
/// hold the value) would leave `WARNING_SUPPRESS > 0` for the rest of
/// the thread's life. Every subsequent `emit_deprecation_warning` would
/// silently no-op — defeating the entire migration signal that is the
/// only feedback users get to migrate off the deprecated schema.
///
/// Bind to a named `_suppress` (or similar) variable, NOT to the
/// anonymous `_` placeholder, which drops at end of *statement*, not
/// end of *scope*. Tests in this module pin these invariants down.
pub(crate) struct WarningSuppressionGuard {
    _priv: (),
}

impl WarningSuppressionGuard {
    pub(crate) fn begin() -> Self {
        WARNING_SUPPRESS.with(|c| c.set(c.get().saturating_add(1)));
        Self { _priv: () }
    }
}

impl Drop for WarningSuppressionGuard {
    fn drop(&mut self) {
        WARNING_SUPPRESS.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

/// Increment the per-thread counter if a `WarningCounterGuard` is active.
/// No-op otherwise. Called from `deprecated_schema::emit_deprecation_warning`.
pub(crate) fn note_deprecation() {
    WARNING_COUNTER.with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n.saturating_add(1)));
        }
    });
}

/// Returns true while a `WarningSuppressionGuard` is active on this thread.
/// Called from `deprecated_schema::emit_deprecation_warning`.
pub(crate) fn is_suppressed() -> bool {
    WARNING_SUPPRESS.with(|c| c.get() > 0)
}

#[cfg(test)]
mod tests {
    //! These tests pin down the thread-local guards' invariants. They
    //! are pre-conditioned on a clean thread-local state — each test
    //! explicitly resets the cells at the top so a previous test's
    //! state can't leak (cargo test parallelism reuses worker threads).
    use super::*;

    fn reset_thread_locals() {
        WARNING_COUNTER.with(|c| c.set(None));
        WARNING_SUPPRESS.with(|c| c.set(0));
    }

    #[test]
    fn warning_counter_guard_drops_to_none_on_finish() {
        reset_thread_locals();
        let g = WarningCounterGuard::begin();
        WARNING_COUNTER.with(|c| assert_eq!(c.get(), Some(0)));
        let _ = g.finish();
        WARNING_COUNTER.with(|c| assert_eq!(c.get(), None));
    }

    #[test]
    fn warning_counter_guard_drops_to_none_on_implicit_drop() {
        reset_thread_locals();
        {
            let _g = WarningCounterGuard::begin();
            WARNING_COUNTER.with(|c| assert_eq!(c.get(), Some(0)));
        }
        WARNING_COUNTER.with(|c| assert_eq!(c.get(), None));
    }

    #[test]
    #[should_panic(expected = "WarningCounterGuard nested")]
    fn warning_counter_guard_nested_begin_panics_in_release_too() {
        reset_thread_locals();
        let _outer = WarningCounterGuard::begin();
        // Must panic in both debug and release; nested counter scopes
        // would silently miscount and miss --strict gates.
        let _inner = WarningCounterGuard::begin();
    }

    #[test]
    fn warning_suppression_guard_returns_to_zero_on_drop() {
        reset_thread_locals();
        {
            let _g = WarningSuppressionGuard::begin();
            WARNING_SUPPRESS.with(|c| assert_eq!(c.get(), 1));
            assert!(is_suppressed());
        }
        WARNING_SUPPRESS.with(|c| assert_eq!(c.get(), 0));
        assert!(!is_suppressed());
    }

    #[test]
    fn warning_suppression_guard_nests_to_correct_depth() {
        reset_thread_locals();
        let outer = WarningSuppressionGuard::begin();
        WARNING_SUPPRESS.with(|c| assert_eq!(c.get(), 1));
        {
            let inner = WarningSuppressionGuard::begin();
            WARNING_SUPPRESS.with(|c| assert_eq!(c.get(), 2));
            drop(inner);
        }
        WARNING_SUPPRESS.with(|c| assert_eq!(c.get(), 1));
        drop(outer);
        WARNING_SUPPRESS.with(|c| assert_eq!(c.get(), 0));
    }

    #[test]
    fn note_deprecation_increments_only_inside_counter_scope() {
        reset_thread_locals();
        // Outside scope: no-op.
        note_deprecation();
        WARNING_COUNTER.with(|c| assert_eq!(c.get(), None));

        // Inside scope: increments.
        let g = WarningCounterGuard::begin();
        note_deprecation();
        note_deprecation();
        let n = g.finish();
        assert_eq!(n, 2);
    }

    #[test]
    fn is_suppressed_is_false_outside_scope() {
        reset_thread_locals();
        assert!(!is_suppressed());
    }
}
