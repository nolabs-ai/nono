//! Coordinates terminal prompts raised off the supervisor thread with the PTY
//! relay.
//!
//! While the PTY relay runs, the user's terminal is in raw mode and its input
//! is forwarded to the sandboxed child. Prompts raised on the supervisor thread
//! pause the relay directly. Network and proxy endpoint approvals run on proxy
//! worker threads that cannot reach the relay, so they ask the supervisor loop
//! to pause it through this gate and only prompt once the pause is in effect.
//! Otherwise the prompt renders against a raw terminal and the relay competes
//! with the prompt for the user's answer.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;
use std::time::Instant;

static GATE: RelayPromptGate = RelayPromptGate::new();

struct GateState {
    /// Supervisor thread servicing the relay, while a relay is active.
    owner: Option<ThreadId>,
    /// Off-thread prompts waiting for, or running under, a relay pause.
    pending: usize,
    /// Whether the supervisor has paused the relay for pending prompts.
    paused: bool,
}

struct RelayPromptGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

/// Marks the PTY relay active for the lifetime of the value.
pub(crate) struct RelayRegistration<'a> {
    gate: &'a RelayPromptGate,
}

impl Drop for RelayRegistration<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.lock();
        state.owner = None;
        state.paused = false;
        self.gate.changed.notify_all();
    }
}

/// Counts one off-thread prompt as pending until dropped.
struct PendingPrompt<'a> {
    gate: &'a RelayPromptGate,
}

impl Drop for PendingPrompt<'_> {
    fn drop(&mut self) {
        // Always release the count so the supervisor never waits on a prompt
        // that no longer exists.
        let mut state = self.gate.lock();
        state.pending = state.pending.saturating_sub(1);
        self.gate.changed.notify_all();
    }
}

impl RelayPromptGate {
    const fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                owner: None,
                pending: 0,
                paused: false,
            }),
            changed: Condvar::new(),
        }
    }

    /// Lock the gate state, recovering from poisoning. Nothing that can panic
    /// runs while the lock is held (prompts run outside it), so a poisoned
    /// guard still holds consistent state. Treating poison as fatal would
    /// instead deny every later off-thread prompt for the rest of the session.
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self) -> RelayRegistration<'_> {
        let mut state = self.lock();
        state.owner = Some(std::thread::current().id());
        state.paused = false;
        RelayRegistration { gate: self }
    }

    /// Run `prompt` once the relay is paused, or directly when no relay is
    /// active or the caller is the supervisor thread. Returns `None` when the
    /// pause is not in effect by `deadline`, so the caller can fail closed.
    fn run_paused<T>(&self, deadline: Instant, prompt: impl FnOnce() -> T) -> Option<T> {
        let mut state = self.lock();
        let gated = state
            .owner
            .is_some_and(|owner| owner != std::thread::current().id());
        if !gated {
            drop(state);
            return Some(prompt());
        }
        state.pending = state.pending.saturating_add(1);
        let pending = PendingPrompt { gate: self };
        if !self.wait_until_paused(state, deadline) {
            return None;
        }
        let result = prompt();
        drop(pending);
        Some(result)
    }

    fn wait_until_paused(&self, mut state: MutexGuard<'_, GateState>, deadline: Instant) -> bool {
        loop {
            // A relay that ended while we waited no longer owns the terminal.
            if state.paused || state.owner.is_none() {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// When prompts are pending, pause the relay through `with_relay_paused`
    /// and hold the pause until they all finish. Called from the supervisor
    /// loop, which owns the relay.
    fn service(&self, with_relay_paused: impl FnOnce(&dyn Fn())) {
        let state = self.lock();
        if state.pending == 0 || state.paused {
            return;
        }
        drop(state);
        with_relay_paused(&|| self.hold_pause_until_prompts_finish());
    }

    fn hold_pause_until_prompts_finish(&self) {
        let mut state = self.lock();
        state.paused = true;
        self.changed.notify_all();
        // Each prompt is bounded by its own deadline, so this wait ends.
        while state.pending > 0 {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state.paused = false;
    }
}

/// Mark the PTY relay active on the calling (supervisor) thread.
pub(crate) fn register_relay() -> RelayRegistration<'static> {
    GATE.register()
}

/// Run a terminal prompt with the PTY relay paused. See
/// [`RelayPromptGate::run_paused`].
pub(crate) fn run_with_relay_paused<T>(deadline: Instant, prompt: impl FnOnce() -> T) -> Option<T> {
    GATE.run_paused(deadline, prompt)
}

/// Service off-thread prompt requests from the supervisor loop.
/// `with_relay_paused` must run its argument with the relay paused.
pub(crate) fn service_pending_prompts(with_relay_paused: impl FnOnce(&dyn Fn())) {
    GATE.service(with_relay_paused);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn leak_gate() -> &'static RelayPromptGate {
        Box::leak(Box::new(RelayPromptGate::new()))
    }

    #[test]
    fn prompts_run_directly_without_a_relay() {
        let gate = leak_gate();
        assert_eq!(gate.run_paused(Instant::now(), || 7), Some(7));
    }

    #[test]
    fn supervisor_thread_prompts_bypass_the_gate() {
        let gate = leak_gate();
        let _registration = gate.register();
        assert_eq!(gate.run_paused(Instant::now(), || 7), Some(7));
        assert_eq!(gate.lock().pending, 0);
    }

    #[test]
    fn off_thread_prompt_runs_only_while_relay_is_paused() {
        let gate = leak_gate();
        let _registration = gate.register();
        let relay_paused = &*Box::leak(Box::new(AtomicBool::new(false)));

        let requester = std::thread::spawn(move || {
            gate.run_paused(Instant::now() + Duration::from_secs(5), || {
                relay_paused.load(Ordering::SeqCst)
            })
        });
        while gate.lock().pending == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }

        let mut resumed = false;
        gate.service(|hold| {
            relay_paused.store(true, Ordering::SeqCst);
            hold();
            relay_paused.store(false, Ordering::SeqCst);
            resumed = true;
        });

        assert_eq!(requester.join().expect("join requester"), Some(true));
        assert!(resumed, "relay resumes after the prompt");
        let state = gate.lock();
        assert_eq!(state.pending, 0);
        assert!(!state.paused);
    }

    #[test]
    fn off_thread_prompt_fails_closed_when_pause_never_arrives() {
        let gate = leak_gate();
        let _registration = gate.register();
        let ran = &*Box::leak(Box::new(AtomicBool::new(false)));

        let result = std::thread::spawn(move || {
            gate.run_paused(Instant::now() + Duration::from_millis(20), || {
                ran.store(true, Ordering::SeqCst);
            })
        })
        .join()
        .expect("join requester");

        assert!(result.is_none());
        assert!(!ran.load(Ordering::SeqCst), "prompt must not run unpaused");
        assert_eq!(gate.lock().pending, 0);
    }

    #[test]
    fn waiting_prompt_proceeds_once_relay_ends() {
        let gate = leak_gate();
        let registration = gate.register();
        let requester = std::thread::spawn(move || {
            gate.run_paused(Instant::now() + Duration::from_secs(5), || 7)
        });
        while gate.lock().pending == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(registration);
        assert_eq!(requester.join().expect("join requester"), Some(7));
    }

    #[test]
    fn poisoned_gate_keeps_serving_prompts() {
        let gate = leak_gate();
        let poisoner = std::thread::spawn(move || {
            let _state = gate.state.lock();
            panic!("poison the gate");
        });
        assert!(poisoner.join().is_err());
        assert!(gate.state.is_poisoned());

        let _registration = gate.register();
        let requester = std::thread::spawn(move || {
            gate.run_paused(Instant::now() + Duration::from_secs(5), || 7)
        });
        while gate.lock().pending == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        gate.service(|hold| hold());
        assert_eq!(requester.join().expect("join requester"), Some(7));
    }

    #[test]
    fn service_without_pending_prompts_leaves_relay_alone() {
        let gate = leak_gate();
        let _registration = gate.register();
        let mut touched = false;
        gate.service(|_| touched = true);
        assert!(!touched);
    }
}
