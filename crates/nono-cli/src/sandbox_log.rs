#[cfg(target_os = "macos")]
use nono::SandboxViolation;
#[cfg(target_os = "macos")]
use serde_json::Value;
#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
#[cfg(target_os = "macos")]
use std::io::{BufRead, BufReader};
#[cfg(target_os = "macos")]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "macos")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "macos")]
use tracing::debug;

#[cfg(target_os = "macos")]
const LOG_STREAM_PREDICATE: &str = "((processID == 0) AND (senderImagePath CONTAINS \"/Sandbox\")) OR (process == \"sandboxd\") OR (subsystem == \"com.apple.sandbox.reporting\")";
#[cfg(target_os = "macos")]
const MAX_VIOLATIONS: usize = 50;

#[cfg(target_os = "macos")]
#[derive(Default)]
struct SharedViolations {
    seen: BTreeSet<(String, String)>,
    violations: Vec<SandboxViolation>,
}

#[cfg(target_os = "macos")]
pub struct SandboxLogCollector {
    child: Child,
    child_pid: i32,
    reader_thread: Option<JoinHandle<()>>,
    shared: Arc<Mutex<SharedViolations>>,
}

#[cfg(target_os = "macos")]
impl SandboxLogCollector {
    #[must_use]
    pub fn start(child_pid: i32) -> Option<Self> {
        let mut child = match Command::new("/usr/bin/log")
            .args([
                "stream",
                "--style",
                "ndjson",
                "--level",
                "debug",
                "--predicate",
                LOG_STREAM_PREDICATE,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                debug!("sandbox log stream failed to spawn: {e}");
                return None;
            }
        };

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                debug!("sandbox log stream missing stdout");
                return None;
            }
        };

        let shared = Arc::new(Mutex::new(SharedViolations::default()));
        let thread_shared = Arc::clone(&shared);
        let reader_thread = thread::Builder::new()
            .name("nono-sandbox-log".to_string())
            .spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    let Ok(line) = line else {
                        break;
                    };

                    let Some(violation) = parse_violation_line(Some(child_pid), &line) else {
                        continue;
                    };

                    let mut guard = match thread_shared.lock() {
                        Ok(guard) => guard,
                        Err(_) => break,
                    };
                    let key = (
                        violation.operation.clone(),
                        violation.target.clone().unwrap_or_default(),
                    );
                    if !guard.seen.insert(key) {
                        continue;
                    }
                    guard.violations.push(violation);
                    if guard.violations.len() >= MAX_VIOLATIONS {
                        break;
                    }
                }
            })
            .ok()?;

        Some(Self {
            child,
            child_pid,
            reader_thread: Some(reader_thread),
            shared,
        })
    }

    #[must_use]
    pub fn finish(mut self) -> Vec<SandboxViolation> {
        // Kill the real-time stream — it may or may not have captured
        // events depending on timing.
        let _ = self.child.kill();
        let _ = self.child.wait();

        if let Some(reader_thread) = self.reader_thread.take() {
            let _ = reader_thread.join();
        }

        let mut violations: Vec<SandboxViolation> = match Arc::try_unwrap(self.shared) {
            Ok(shared) => match shared.into_inner() {
                Ok(shared) => shared.violations,
                Err(poisoned) => poisoned.into_inner().violations,
            },
            Err(shared) => match shared.lock() {
                Ok(shared) => shared.violations.clone(),
                Err(poisoned) => poisoned.into_inner().violations.clone(),
            },
        };

        // The real-time stream is inherently racy for short-lived commands
        // (e.g. `cat`). The child can exit before the log system delivers
        // the denial event. Fall back to a historical log query which is
        // deterministic — events are already committed by this point.
        if violations.is_empty() {
            if let Some(historical) = collect_historical_violations(self.child_pid) {
                violations = historical;
            }
        }

        violations
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub struct SandboxLogCollector;

/// Query the unified log for sandbox violations that occurred in the recent past.
///
/// This is the fallback for short-lived commands where the real-time log stream
/// couldn't deliver events before the child exited. `log show --last 10s` queries
/// committed log entries, which is deterministic.
#[cfg(target_os = "macos")]
fn collect_historical_violations(_child_pid: i32) -> Option<Vec<SandboxViolation>> {
    // Use the same predicate as the real-time stream. We match any PID
    // because the child may have forked subprocesses (e.g. copilot forks
    // git, which hits the denial under a different PID). The predicate
    // parse_violation_line extracts via regex matching.
    let predicate = LOG_STREAM_PREDICATE;

    let output = Command::new("/usr/bin/log")
        .args([
            "show",
            "--style",
            "ndjson",
            "--last",
            "10s",
            "--predicate",
            predicate,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug!("log show exited with {:?}", output.status.code());
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut seen = BTreeSet::<(String, String)>::new();
    let mut violations = Vec::new();

    for line in text.lines() {
        // Pass None to match any PID — the child may have forked
        // subprocesses that triggered denials under a different PID.
        let Some(violation) = parse_violation_line(None, line) else {
            continue;
        };
        // Only include filesystem operations in historical results.
        // Non-filesystem violations (mach-lookup, signal, etc.) from the
        // broad query cannot be reliably attributed to our sandbox — they
        // may come from other sandboxed processes on the system.
        if !violation.operation.starts_with("file-") {
            continue;
        }
        let key = (
            violation.operation.clone(),
            violation.target.clone().unwrap_or_default(),
        );
        if !seen.insert(key) {
            continue;
        }
        violations.push(violation);
        if violations.len() >= MAX_VIOLATIONS {
            break;
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
impl SandboxLogCollector {
    #[must_use]
    pub fn start(_child_pid: i32) -> Option<Self> {
        None
    }

    #[must_use]
    pub fn finish(self) -> Vec<nono::SandboxViolation> {
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
fn parse_violation_line(child_pid: Option<i32>, line: &str) -> Option<SandboxViolation> {
    let value: Value = serde_json::from_str(line).ok()?;
    parse_violation_value(child_pid, &value)
}

#[cfg(target_os = "macos")]
fn parse_violation_value(child_pid: Option<i32>, value: &Value) -> Option<SandboxViolation> {
    if let Some(message) = value.get("eventMessage").and_then(Value::as_str) {
        if let Some(violation) = parse_event_message(child_pid, message) {
            return Some(violation);
        }
    }

    let metadata = value.get("eventMessage").and_then(|event_message| {
        event_message
            .as_str()
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
    });
    if let Some(violation) = metadata
        .as_ref()
        .and_then(|metadata| parse_metadata_violation(child_pid, metadata))
    {
        return Some(violation);
    }

    let metadata = value
        .get("metadata")
        .or_else(|| value.get("MetaData"))
        .or_else(|| value.get("composedMessage"))
        .and_then(|metadata| {
            if metadata.is_object() {
                Some(metadata.clone())
            } else {
                metadata
                    .as_str()
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
            }
        });

    metadata
        .as_ref()
        .and_then(|metadata| parse_metadata_violation(child_pid, metadata))
}

#[cfg(target_os = "macos")]
fn parse_metadata_violation(child_pid: Option<i32>, metadata: &Value) -> Option<SandboxViolation> {
    let pid = metadata
        .get("pid")
        .and_then(Value::as_i64)
        .or_else(|| metadata.get("processID").and_then(Value::as_i64))?;
    if let Some(expected) = child_pid {
        if pid != i64::from(expected) {
            return None;
        }
    }

    let operation = metadata
        .get("operation")
        .and_then(Value::as_str)
        .map(str::to_string)?;
    let target = metadata
        .get("target")
        .and_then(Value::as_str)
        .or_else(|| metadata.get("path").and_then(Value::as_str))
        .or_else(|| metadata.get("global-name").and_then(Value::as_str))
        .map(str::to_string);

    Some(SandboxViolation { operation, target })
}

#[cfg(target_os = "macos")]
fn parse_event_message(child_pid: Option<i32>, message: &str) -> Option<SandboxViolation> {
    // Format: "Sandbox: processname(PID) deny(N) operation target"
    // or:     "N duplicate reports for Sandbox: processname(PID) deny(N) operation target"
    let first_line = message.lines().next()?.trim();
    let sandbox_line = first_line
        .split_once("Sandbox: ")
        .map(|(_, suffix)| suffix)
        .or_else(|| first_line.strip_prefix("Sandbox: "))?;

    // When child_pid is Some, match only that PID.
    // When None, match any PID (for historical queries where the child
    // may have forked subprocesses with different PIDs).
    if let Some(pid) = child_pid {
        let pid_token = format!("({pid})");
        if !sandbox_line.contains(&pid_token) {
            return None;
        }
    }

    // Parse: "processname(PID) deny(N) operation [target]"
    let (_, after_deny) = sandbox_line.split_once(") deny(")?;
    let (_, detail) = after_deny.split_once(") ")?;
    let detail = detail.trim();
    let (operation, target) = match detail.split_once(' ') {
        Some((op, t)) => (op.to_string(), Some(t.trim().to_string())),
        None => (detail.to_string(), None),
    };

    Some(SandboxViolation { operation, target })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{parse_event_message, parse_violation_line};

    #[test]
    fn parses_file_violation_line() {
        let msg = "Sandbox: cat(1234) deny(1) file-read-data /Users/test/.ssh/id_rsa";
        let violation = parse_event_message(Some(1234), msg).expect("violation");
        assert_eq!(violation.operation, "file-read-data");
        assert_eq!(violation.target.as_deref(), Some("/Users/test/.ssh/id_rsa"));
    }

    #[test]
    fn parses_mach_violation_line() {
        let msg = "Sandbox: codex(14485) deny(1) mach-lookup com.apple.logd";
        let violation = parse_event_message(Some(14485), msg).expect("violation");
        assert_eq!(violation.operation, "mach-lookup");
        assert_eq!(violation.target.as_deref(), Some("com.apple.logd"));
    }

    #[test]
    fn parses_ndjson_metadata_violation() {
        let line = r#"{"eventMessage":"Sandbox: cat(1234) deny(1) file-read-data /Users/test/.ssh/id_rsa","subsystem":"com.apple.sandbox.reporting","category":"violation","MetaData":{"operation":"file-read-data","pid":1234,"target":"/Users/test/.ssh/id_rsa"}}"#;
        let violation = parse_violation_line(Some(1234), line).expect("violation");
        assert_eq!(violation.operation, "file-read-data");
        assert_eq!(violation.target.as_deref(), Some("/Users/test/.ssh/id_rsa"));
    }

    #[test]
    fn ignores_other_pids_when_filtered() {
        let msg = "Sandbox: cat(9999) deny(1) file-read-data /tmp/x";
        assert!(parse_event_message(Some(1234), msg).is_none());
    }

    #[test]
    fn matches_any_pid_when_none() {
        let msg = "Sandbox: copilot(9999) deny(1) mach-lookup com.apple.securityd";
        let violation = parse_event_message(None, msg).expect("violation");
        assert_eq!(violation.operation, "mach-lookup");
        assert_eq!(violation.target.as_deref(), Some("com.apple.securityd"));
    }

    #[test]
    fn parses_duplicate_reports() {
        let msg =
            "3 duplicate reports for Sandbox: git(5678) deny(1) file-read-data /etc/gitconfig";
        let violation = parse_event_message(None, msg).expect("violation");
        assert_eq!(violation.operation, "file-read-data");
        assert_eq!(violation.target.as_deref(), Some("/etc/gitconfig"));
    }
}
