//! Session lifecycle hook execution.
//!
//! Handles execution of before/after hooks for sandbox sessions.
//! All hooks run outside the sandbox with host privileges.
//!
//! Unix-only: relies on POSIX uid/mode metadata, `pre_exec`, and process
//! group signalling. Gated by `#[cfg(unix)]` at the module declaration in
//! `main.rs`.
//!
//! # Security
//!
//! - Script paths are validated before every execution
//!   (absolute, canonical, regular file, executable, owned by user, not world-writable)
//! - Hooks run as subprocesses
//! - Process group isolation for timeout-based killing
//! - NONO_ENV_FILE is used for env var export (not stdout parsing)
//! - Dangerous env vars are filtered before injection

use crate::{exec_strategy, profile, session};
use nono::{NonoError, Result};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tracing::{debug, warn};

/// Result of executing a session hook.
struct HookOutput {
    exit_code: i32,
    timed_out: bool,
}

/// Discriminator for the two hook variants.
///
/// `Before` carries the path to the env file the hook is expected to populate.
/// `After` carries the exit code of the sandboxed child process.
enum HookKind<'a> {
    Before { env_file: &'a Path },
    After { exit_code: i32 },
}

impl HookKind<'_> {
    fn type_env(&self) -> &'static str {
        match self {
            HookKind::Before { .. } => "before",
            HookKind::After { .. } => "after",
        }
    }
}

/// Execute a before-hook and return exported environment variables.
///
/// Steps:
/// 1. Validate script path
/// 2. Create NONO_ENV_FILE in private session directory (RAII guard)
/// 3. Spawn hook with isolated environment
/// 4. Wait for completion with optional timeout
/// 5. Read and parse NONO_ENV_FILE
/// 6. Filter dangerous env vars
pub(crate) fn execute_before_hook(
    hook: &profile::SessionHook,
    session_id: &str,
    workdir: &Path,
) -> Result<Vec<(String, String)>> {
    let script_path = validate_hook_script(&hook.script)?;
    let env_file = EnvFileGuard::create(session_id)?;

    let mut cmd = build_hook_command(
        &script_path,
        session_id,
        workdir,
        &HookKind::Before {
            env_file: env_file.path(),
        },
    );
    let output = run_hook(&mut cmd, hook.timeout_secs)?;

    if output.timed_out {
        warn!(
            "Before-hook timed out ({}s): {}",
            hook.timeout_secs.unwrap_or(0),
            script_path.display()
        );
        return Ok(Vec::new());
    }

    if output.exit_code != 0 {
        warn!(
            "Before-hook exited with code {}: {}",
            output.exit_code,
            script_path.display()
        );
    }

    let raw = read_env_file(env_file.path())?;
    let total = raw.len();
    let filtered: Vec<(String, String)> = raw
        .into_iter()
        .filter(|(k, _)| !exec_strategy::is_dangerous_env_var(k))
        .collect();

    debug!(
        "Before-hook exported {} env vars ({} filtered out)",
        filtered.len(),
        total.saturating_sub(filtered.len())
    );

    Ok(filtered)
}

/// Execute an after-hook for cleanup.
///
/// Steps:
/// 1. Validate script path
/// 2. Execute with isolated env, passing child exit code via NONO_EXIT_CODE
/// 3. Log result
pub(crate) fn execute_after_hook(
    hook: &profile::SessionHook,
    session_id: &str,
    workdir: &Path,
    child_exit_code: i32,
) -> Result<()> {
    let script_path = validate_hook_script(&hook.script)?;
    let mut cmd = build_hook_command(
        &script_path,
        session_id,
        workdir,
        &HookKind::After {
            exit_code: child_exit_code,
        },
    );
    let output = run_hook(&mut cmd, hook.timeout_secs)?;

    if output.timed_out {
        warn!(
            "After-hook timed out ({}s): {}",
            hook.timeout_secs.unwrap_or(0),
            script_path.display()
        );
        return Ok(());
    }

    if output.exit_code != 0 {
        warn!(
            "After-hook exited with code {}: {}",
            output.exit_code,
            script_path.display()
        );
    }

    Ok(())
}

// ===================== Internal Helpers =====================

/// Build a `Command` configured for a hook execution.
///
/// Sets `NONO_SESSION_ID` / `NONO_WORKDIR` / `NONO_HOOK_TYPE` plus the
/// kind-specific env vars and stdio. Installs the `setpgid` pre-exec hook so
/// the child can be killed as a process group on timeout.
fn build_hook_command(
    script: &Path,
    session_id: &str,
    workdir: &Path,
    kind: &HookKind<'_>,
) -> Command {
    let mut cmd = Command::new(script);
    cmd.env("NONO_SESSION_ID", session_id);
    cmd.env("NONO_WORKDIR", workdir);
    cmd.env("NONO_HOOK_TYPE", kind.type_env());
    cmd.stdin(Stdio::null());
    cmd.stderr(Stdio::piped());

    match kind {
        HookKind::Before { env_file } => {
            cmd.env("NONO_ENV_FILE", env_file);
            cmd.stdout(Stdio::piped());
        }
        HookKind::After { exit_code } => {
            cmd.env("NONO_EXIT_CODE", exit_code.to_string());
            cmd.stdout(Stdio::null());
        }
    }

    // SAFETY: setpgid(0,0) places the child in its own process group for
    // clean timeout killing. POSIX guarantees setpgid is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            let _ =
                nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0));
            Ok(())
        });
    }

    cmd
}

/// Validate a hook script path.
///
/// Security checks:
/// - Absolute path
/// - Path exists and is a regular file
/// - File is executable
/// - File is owned by current user or root
/// - File is not in a world-writable directory
fn validate_hook_script(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(NonoError::ConfigParse(format!(
            "Hook script path must be absolute: {}",
            path.display()
        )));
    }

    let canonical = path.canonicalize().map_err(|e| {
        NonoError::ConfigParse(format!("Hook script not found: {}: {}", path.display(), e))
    })?;

    let metadata = canonical.metadata().map_err(|e| {
        NonoError::ConfigParse(format!(
            "Cannot read hook script metadata: {}: {}",
            canonical.display(),
            e
        ))
    })?;

    if !metadata.is_file() {
        return Err(NonoError::ConfigParse(format!(
            "Hook script is not a regular file: {}",
            canonical.display()
        )));
    }

    let mode = metadata.permissions().mode();
    if (mode & 0o111) == 0 {
        return Err(NonoError::ConfigParse(format!(
            "Hook script is not executable: {}",
            canonical.display()
        )));
    }

    let uid = metadata.uid();
    let my_uid = nix::unistd::geteuid().as_raw();
    if uid != my_uid && uid != 0 {
        return Err(NonoError::ConfigParse(format!(
            "Hook script owned by uid {} (expected {} or root): {}",
            uid,
            my_uid,
            canonical.display()
        )));
    }

    if let Some(parent) = canonical.parent()
        && is_world_writable(parent)
    {
        return Err(NonoError::ConfigParse(format!(
            "Hook script must not be in a world-writable directory: {} (resolved: {})",
            path.display(),
            canonical.display()
        )));
    }

    Ok(canonical)
}

/// Check if a directory is world-writable.
/// Rejects ALL world-writable dirs including /tmp with sticky bit.
fn is_world_writable(path: &Path) -> bool {
    path.metadata()
        .map(|m| (m.permissions().mode() & 0o002) != 0)
        .unwrap_or(false)
}

/// RAII guard for the per-session env file.
///
/// `EnvFileGuard::create` builds `~/.nono/sessions/<id>/env` with `O_EXCL`
/// and 0o600 permissions. On `Drop` the file is best-effort zeroed and
/// unlinked, so it disappears even on early `?` returns from the caller.
struct EnvFileGuard {
    path: PathBuf,
}

impl EnvFileGuard {
    fn create(session_id: &str) -> Result<Self> {
        let sessions_dir = session::ensure_sessions_dir()?;
        let session_env_dir = sessions_dir.join(session_id);

        std::fs::create_dir_all(&session_env_dir).map_err(|e| {
            NonoError::ConfigParse(format!(
                "Failed to create session env directory {}: {e}",
                session_env_dir.display()
            ))
        })?;

        let _ = std::fs::set_permissions(&session_env_dir, std::fs::Permissions::from_mode(0o700));

        let path = session_env_dir.join("env");

        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to create env file: {e}")))?;

        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EnvFileGuard {
    fn drop(&mut self) {
        if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&self.path)
            && let Ok(metadata) = file.metadata()
        {
            use std::io::Write;
            let zeros = vec![0u8; metadata.len() as usize];
            let _ = file.write_all(&zeros);
            let _ = file.sync_all();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Read and parse `KEY=VALUE` pairs from the env file.
fn read_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to read env file: {e}")))?;

    let vars = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect();

    Ok(vars)
}

/// Run a command, wait for completion with optional timeout.
///
/// A worker thread owns the `Child` so the main thread can `recv_timeout`
/// without polling. On timeout the whole process group is killed.
fn run_hook(cmd: &mut Command, timeout_secs: Option<u64>) -> Result<HookOutput> {
    let child = cmd.spawn().map_err(|e| {
        NonoError::CommandExecution(std::io::Error::other(format!("Failed to spawn hook: {e}")))
    })?;
    let pid = child.id();

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });

    let received = match timeout_secs {
        Some(secs) => rx.recv_timeout(Duration::from_secs(secs)).map_err(|_| ()),
        None => rx.recv().map_err(|_| ()),
    };

    match received {
        Ok(Ok(output)) => Ok(HookOutput {
            exit_code: output.status.code().unwrap_or(-1),
            timed_out: false,
        }),
        Ok(Err(e)) => Err(NonoError::CommandExecution(e)),
        Err(()) if timeout_secs.is_some() => {
            kill_process_group(pid);
            Ok(HookOutput {
                exit_code: -1,
                timed_out: true,
            })
        }
        Err(()) => Err(NonoError::CommandExecution(std::io::Error::other(
            "Hook channel closed unexpectedly",
        ))),
    }
}

/// Kill a process group by leader PID.
fn kill_process_group(pid: u32) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let pgid = Pid::from_raw(pid as i32);
    let _ = killpg(pgid, Signal::SIGTERM);
    thread::sleep(Duration::from_millis(100));
    let _ = killpg(pgid, Signal::SIGKILL);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// Acquire an isolated HOME for tests that touch `~/.nono/sessions/`.
    /// Returns the lock guard, env-var guard, and the HOME tempdir; all three
    /// must stay in scope for the duration of the test.
    fn isolated_home() -> (
        std::sync::MutexGuard<'static, ()>,
        crate::test_env::EnvVarGuard,
        TempDir,
    ) {
        let lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let home = TempDir::new().unwrap();
        let home_str = home.path().to_str().unwrap();
        let env = crate::test_env::EnvVarGuard::set_all(&[("HOME", home_str)]);
        (lock, env, home)
    }

    // ---- Path validation ----

    #[test]
    fn test_validate_script_accepts_valid_path() {
        let dir = TempDir::new().unwrap();
        let script = dir.path().join("hook.sh");
        std::fs::write(&script, "#!/bin/sh\necho hello").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_hook_script(&script).is_ok());
    }

    #[test]
    fn test_validate_script_rejects_relative_path() {
        assert!(validate_hook_script(Path::new("relative/path.sh")).is_err());
    }

    #[test]
    fn test_validate_script_rejects_nonexistent() {
        assert!(validate_hook_script(Path::new("/nonexistent/path.sh")).is_err());
    }

    #[test]
    fn test_validate_script_rejects_non_executable() {
        let dir = TempDir::new().unwrap();
        let script = dir.path().join("hook.sh");
        std::fs::write(&script, "#!/bin/sh\necho hello").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_hook_script(&script).is_err());
    }

    #[test]
    fn test_validate_script_rejects_world_writable_directory() {
        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let script = dir.path().join("hook.sh");
        std::fs::write(&script, "#!/bin/sh\necho hello").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_hook_script(&script).is_err());
    }

    #[test]
    fn test_validate_script_rejects_directory() {
        let dir = TempDir::new().unwrap();
        assert!(validate_hook_script(dir.path()).is_err());
    }

    // ---- Env file parsing ----

    #[test]
    fn test_read_env_file_basic() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("env");
        std::fs::write(&file, "FOO=bar\nBAZ=qux\n").unwrap();
        let vars = read_env_file(&file).unwrap();
        assert_eq!(
            vars,
            vec![("FOO".into(), "bar".into()), ("BAZ".into(), "qux".into())]
        );
    }

    #[test]
    fn test_read_env_file_skips_comments_and_blanks() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("env");
        std::fs::write(&file, "# comment\n\nFOO=bar\n").unwrap();
        let vars = read_env_file(&file).unwrap();
        assert_eq!(vars, vec![("FOO".into(), "bar".into())]);
    }

    #[test]
    fn test_read_env_file_value_with_equals() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("env");
        std::fs::write(&file, "FLAG=--foo=bar\n").unwrap();
        let vars = read_env_file(&file).unwrap();
        assert_eq!(vars, vec![("FLAG".into(), "--foo=bar".into())]);
    }

    #[test]
    fn test_read_env_file_whitespace_trimming() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("env");
        std::fs::write(&file, "  KEY  =  value  \n").unwrap();
        let vars = read_env_file(&file).unwrap();
        assert_eq!(vars, vec![("KEY".into(), "value".into())]);
    }

    // ---- End-to-end before-hook ----

    #[test]
    fn test_execute_before_hook_basic() {
        let (_lock, _env, _home) = isolated_home();

        let dir = TempDir::new().unwrap();
        let script = dir.path().join("hook.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf 'TMPDIR=/tmp/nono-test\\nLD_PRELOAD=/evil.so\\nCUSTOM_VAR=hello' > \"$NONO_ENV_FILE\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let hook = profile::SessionHook {
            script: script.clone(),
            timeout_secs: Some(5),
        };

        let result = execute_before_hook(&hook, "test-basic", Path::new("/tmp")).unwrap();

        // LD_PRELOAD must be filtered out as a dangerous var.
        assert!(result.contains(&("TMPDIR".into(), "/tmp/nono-test".into())));
        assert!(result.contains(&("CUSTOM_VAR".into(), "hello".into())));
        assert!(!result.iter().any(|(k, _)| k == "LD_PRELOAD"));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_execute_before_hook_timeout() {
        let (_lock, _env, _home) = isolated_home();

        let dir = TempDir::new().unwrap();
        let script = dir.path().join("sleep.sh");
        std::fs::write(&script, "#!/bin/sh\nsleep 60\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let hook = profile::SessionHook {
            script,
            timeout_secs: Some(1),
        };

        let start = std::time::Instant::now();
        let result = execute_before_hook(&hook, "test-timeout", Path::new("/tmp"));
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(10), "timeout took too long");
        match result {
            Ok(vars) => assert!(vars.is_empty(), "timed-out hook should return no vars"),
            Err(e) => panic!("timed-out hook should not propagate error: {e}"),
        }
    }

    #[test]
    fn test_execute_before_hook_fail_open() {
        let (_lock, _env, _home) = isolated_home();

        let dir = TempDir::new().unwrap();
        let script = dir.path().join("fail.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let hook = profile::SessionHook {
            script,
            timeout_secs: Some(5),
        };

        let result = execute_before_hook(&hook, "test-fail", Path::new("/tmp"));
        match result {
            Ok(vars) => assert!(vars.is_empty(), "failed hook should return no vars"),
            Err(e) => panic!("fail-open contract broken: {e}"),
        }
    }

    /// Exercise the `Drop` impl on `EnvFileGuard` so the file disappears
    /// even when the caller bails before the happy path completes.
    #[test]
    fn test_env_file_guard_removes_file_on_drop() {
        let (_lock, _env, _home) = isolated_home();

        let path;
        {
            let guard = EnvFileGuard::create("guard-drop-test").unwrap();
            path = guard.path().to_path_buf();
            assert!(path.exists(), "env file should exist while guard is alive");
        }
        assert!(!path.exists(), "env file must be removed when guard drops");
    }
}
