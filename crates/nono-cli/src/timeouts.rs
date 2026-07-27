//! Named timeout and polling-interval constants used across the CLI.
//!
//! User-facing timeouts can be overridden via environment variables.
//! Internal poll intervals use fixed defaults.

use std::time::Duration;
use tracing::warn;

// exec_strategy

/// Quiet period to drain final PTY output after child exit before parent
/// diagnostics/prompts take over the terminal.
pub const POST_EXIT_PTY_DRAIN_TIMEOUT: Duration = Duration::from_millis(100);

// pty_proxy

/// Read timeout on the attach socket when reading the request-kind byte.
pub const ATTACH_SOCKET_READ_TIMEOUT: Duration = Duration::from_millis(500);

/// Delay before forwarding stdin in the attach warm-up loop, giving the
/// supervisor time to replay buffered screen content.
pub const ATTACH_STDIN_DELAY: Duration = Duration::from_millis(250);

/// Maximum time to wait on final teardown for a terminal's reply to a
/// cursor-position query (`ESC[6n`) the exiting child emitted, so the reply is
/// consumed instead of being pasted into the shell prompt. Bounds the
/// byte-at-a-time read that waits out the (possibly fragmented) reply; kept
/// short so it is imperceptible on exit.
pub const TERMINAL_QUERY_REPLY_TIMEOUT: Duration = Duration::from_millis(30);

/// Sleep before retrying a session connection that failed with `SessionGone`.
pub const ATTACH_RETRY_DELAY: Duration = Duration::from_millis(150);

// startup_runtime

/// Maximum time to wait for a detached session to create its session file
/// and attach socket.
pub const DETACH_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for a detached session to become attachable.
pub const SESSION_READY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Poll interval while waiting for a detached launch process to exit after
/// SIGTERM.
pub const TERMINATE_POLL_INTERVAL: Duration = Duration::from_millis(25);

// session_commands

/// Poll interval while waiting for a session to exit after SIGTERM.
pub const STOP_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Poll interval when tailing a log file and the reader reaches EOF.
pub const LOG_TAIL_POLL_INTERVAL: Duration = Duration::from_millis(250);

// learn

/// Delay after spawning `fs_usage` to let it attach the kernel trace
/// facility before the child command starts (macOS).
#[cfg(target_os = "macos")]
pub const FS_USAGE_SETTLE_TIME: Duration = Duration::from_secs(2);

/// Grace period after SIGTERM before escalating to SIGKILL (learn mode).
#[cfg(target_os = "macos")]
pub const SIGTERM_GRACE_PERIOD: Duration = Duration::from_secs(3);

// Configurable user-facing timeouts

/// Read `NONO_DETACH_STARTUP_TIMEOUT` (seconds). Returns the default when
/// the variable is absent or unparseable.
pub fn detach_startup_timeout() -> Duration {
    env_duration_secs("NONO_DETACH_STARTUP_TIMEOUT", DETACH_STARTUP_TIMEOUT)
}

/// Read `NONO_PTY_DRAIN_TIMEOUT` (milliseconds). Returns the default when
/// the variable is absent or unparseable.
pub fn pty_drain_timeout() -> Duration {
    env_duration_millis("NONO_PTY_DRAIN_TIMEOUT", POST_EXIT_PTY_DRAIN_TIMEOUT)
}

/// Read `NONO_PTY_ATTACH_TIMEOUT` (milliseconds). Returns the default when
/// the variable is absent or unparseable.
pub fn pty_attach_timeout_ms() -> i32 {
    env_duration_millis(
        "NONO_PTY_ATTACH_TIMEOUT",
        Duration::from_millis(PTY_ATTACH_TIMEOUT_MS as u64),
    )
    .as_millis()
    .min(i32::MAX as u128) as i32
}

/// Default for `wait_for_attach_ready` poll timeout.
pub const PTY_ATTACH_TIMEOUT_MS: i32 = 1000;

/// Upper bound for any user-supplied timeout. Prevents `Instant + Duration`
/// overflow from user-controlled values (u64::MAX seconds would panic).
const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

fn env_duration_secs(var: &str, default: Duration) -> Duration {
    match std::env::var(var) {
        Ok(val) => match val.parse::<u64>() {
            Ok(secs) => {
                let d = Duration::from_secs(secs);
                if d > MAX_TIMEOUT {
                    warn!(
                        "{var}={val} exceeds maximum ({} s), clamping",
                        MAX_TIMEOUT.as_secs()
                    );
                    MAX_TIMEOUT
                } else {
                    d
                }
            }
            Err(_) => {
                warn!("{var}={val:?} is not a valid number of seconds, using default");
                default
            }
        },
        Err(_) => default,
    }
}

fn env_duration_millis(var: &str, default: Duration) -> Duration {
    match std::env::var(var) {
        Ok(val) => match val.parse::<u64>() {
            Ok(ms) => {
                let d = Duration::from_millis(ms);
                if d > MAX_TIMEOUT {
                    warn!(
                        "{var}={val} exceeds maximum ({} s), clamping",
                        MAX_TIMEOUT.as_secs()
                    );
                    MAX_TIMEOUT
                } else {
                    d
                }
            }
            Err(_) => {
                warn!("{var}={val:?} is not a valid number of milliseconds, using default");
                default
            }
        },
        Err(_) => default,
    }
}
