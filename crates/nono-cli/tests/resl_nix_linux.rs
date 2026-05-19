//! Phase 25-01 integration tests — Linux resource-limit enforcement (REQ-RESL-NIX-01/02).
//!
//! Each test runs the `nono` binary with a specific resource-limit flag and asserts the
//! kernel-level enforcement is active. All tests are gated on cgroup v2 availability;
//! on a system without cgroup v2 delegation (e.g., CI with cgroup v1 or no systemd), each
//! test prints a skip message and returns without failing.
//!
//! Run individually:
//! ```sh
//! cargo test -p nono-cli --test resl_nix_linux
//! ```

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::Instant;

const NONO_BIN: &str = env!("CARGO_BIN_EXE_nono");

/// Returns `true` if the current process has a cgroup v2 delegation (single `0::/...` line).
/// Tests use this to skip gracefully on cgroup v1 / non-systemd CI hosts.
fn cgroup_v2_available() -> bool {
    let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    let trimmed = content.trim();
    let lines: Vec<&str> = trimmed.lines().collect();
    if lines.len() != 1 {
        return false;
    }
    if !lines[0].starts_with("0::/") {
        return false;
    }
    // Also confirm the cgroup directory is writable (delegation check).
    let cg_path_rel = lines[0].trim_start_matches("0::/");
    let cg_path = format!("/sys/fs/cgroup/{cg_path_rel}/cgroup.subtree_control");
    std::fs::metadata(&cg_path)
        .map(|m| !m.permissions().readonly())
        .unwrap_or(false)
}

/// Macro to skip test with an explanatory message if cgroup v2 is not available.
macro_rules! require_cgroup_v2 {
    () => {
        if !cgroup_v2_available() {
            eprintln!(
                "SKIP: cgroup v2 delegation not available on this host (non-systemd or cgroup v1); \
                 test is only meaningful on Linux with systemd user slice delegation."
            );
            return;
        }
    };
}

/// Phase 37 Plan 37-04: confirm the `cpu` controller is delegated to this
/// user-session. On default Ubuntu only `memory pids` are delegated; the
/// Phase 37 RESL CI workflow installs a `Delegate=cpu cpuset io memory pids`
/// drop-in (research finding #2 — without this, REQ-RESL-NIX-02 silently
/// fails because `cpu.max` cannot be written by the unprivileged user
/// session). The macro reads the user-session controller list from the
/// cgroup hierarchy and skips the test (rather than fails) if `cpu` is
/// missing — this keeps the test resilient on local dev machines that
/// haven't installed the drop-in while still hard-asserting on CI where
/// the workflow's verify step has already confirmed `cpu` is delegated.
macro_rules! require_cpu_controller {
    () => {
        let cg_line = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        let rel = cg_line
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("0::/"))
            .unwrap_or("");
        let controllers_path = format!("/sys/fs/cgroup/{rel}/cgroup.controllers");
        let controllers = std::fs::read_to_string(&controllers_path).unwrap_or_default();
        if !controllers.split_whitespace().any(|c| c == "cpu") {
            eprintln!(
                "SKIP: cpu controller not delegated (got controllers: {:?}); \
                 see Phase 37 Plan 37-04 Delegate= drop-in.",
                controllers.trim()
            );
            return;
        }
    };
}

/// REQ-RESL-NIX-01 criterion 1: `--memory 256m` OOM-kills a large allocation.
///
/// Spawns `bash -c 'tail -c 1G </dev/urandom'` which tries to read 1GiB into memory.
/// With a 256MiB memory.max limit, the cgroup OOM killer delivers SIGKILL (exit code 137)
/// before the allocation completes.
#[test]
fn linux_memory_limit_oom_kills_child() {
    require_cgroup_v2!();

    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--memory",
            "256m",
            "--allow-fs-read=/dev",
            "--allow-fs-read=/usr",
            "--allow-fs-read=/bin",
            "--allow-fs-read=/lib",
            "--allow-fs-read=/lib64",
            "--allow-fs-exec=/bin",
            "--allow-fs-exec=/usr",
            "--",
            "bash",
            "-c",
            // Allocate memory aggressively to trigger OOM kill
            "python3 -c \"import ctypes; buf = ctypes.create_string_buffer(1024*1024*1024)\" 2>&1 || \
             bash -c 'tail -c 1073741824 /dev/urandom > /dev/null' 2>&1",
        ])
        .output()
        .expect("failed to run nono binary");

    // Exit code 137 = 128 + 9 (SIGKILL) is the typical OOM kill exit code.
    // The child may also exit with 1 from bash if the subprocess was killed.
    // We accept any non-zero exit code as evidence the OOM limit triggered.
    assert!(
        !output.status.success(),
        "expected child to be killed by OOM, but it exited successfully. \
         Check that --memory 256m is actually enforced by cgroup v2 memory.max."
    );
}

/// REQ-RESL-NIX-01 criterion 3: `--max-processes 10` blocks the eleventh fork.
///
/// Spawns 20 background sleep processes; only 10 should succeed. The 11th+ fork
/// fails with an error containing "pids.max" or similar kernel diagnostic.
#[test]
fn linux_max_processes_blocks_eleventh_fork() {
    require_cgroup_v2!();

    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--max-processes",
            "10",
            "--allow-fs-read=/usr",
            "--allow-fs-read=/bin",
            "--allow-fs-read=/lib",
            "--allow-fs-read=/lib64",
            "--allow-fs-exec=/bin",
            "--allow-fs-exec=/usr",
            "--",
            "bash",
            "-c",
            // Try to spawn 20 background processes; the 11th+ should fail due to pids.max.
            "for i in $(seq 1 20); do sleep 60 & done; wait",
        ])
        .output()
        .expect("failed to run nono binary");

    // The child should exit non-zero because fork failures cause bash to exit with error.
    assert!(
        !output.status.success(),
        "expected child to fail with pids.max violation, but it exited successfully"
    );
}

/// REQ-RESL-NIX-02 criterion 1: `--timeout 5s` kills the child at deadline.
///
/// The child sleeps 60s but must be killed within ~5s by the cgroup.kill watchdog.
/// We assert the wall time is between 3s and 10s (generous bounds for CI variance).
#[test]
fn linux_timeout_kills_at_deadline() {
    require_cgroup_v2!();

    let start = Instant::now();
    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--timeout",
            "5s",
            "--allow-fs-exec=/bin",
            "--allow-fs-exec=/usr",
            "--allow-fs-read=/bin",
            "--allow-fs-read=/usr",
            "--allow-fs-read=/lib",
            "--allow-fs-read=/lib64",
            "--",
            "sleep",
            "60",
        ])
        .output()
        .expect("failed to run nono binary");
    let elapsed = start.elapsed();

    assert!(
        !output.status.success(),
        "expected child to be killed by timeout, but it exited successfully"
    );
    assert!(
        elapsed.as_secs_f64() < 10.0,
        "expected timeout to kill within 10s, but took {:.1}s",
        elapsed.as_secs_f64()
    );
    assert!(
        elapsed.as_secs_f64() >= 3.0,
        "expected timeout to take at least 3s, but took only {:.1}s (deadline not firing at right time)",
        elapsed.as_secs_f64()
    );
}

/// REQ-RESL-NIX-01 criterion 4: no "is not enforced on linux" warnings in stderr.
///
/// With all four resource-limit flags set, stderr must NOT contain the old Phase 16
/// "is not enforced on linux" warning strings. Presence would mean the old stub code
/// was not removed.
#[test]
fn linux_no_warnings_on_resource_flags() {
    // This test does NOT require cgroup v2 — it tests warning-string absence, which
    // should be true even on cgroup v1 hosts (the error is a different kind).
    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--memory",
            "4g", // generous limit to avoid accidental OOM in this test
            "--cpu-percent",
            "50",
            "--max-processes",
            "1000",
            "--timeout",
            "60s",
            "--allow-fs-exec=/bin",
            "--allow-fs-exec=/usr",
            "--allow-fs-read=/bin",
            "--allow-fs-read=/usr",
            "--allow-fs-read=/lib",
            "--allow-fs-read=/lib64",
            "--",
            "echo",
            "hi",
        ])
        .output()
        .expect("failed to run nono binary");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("is not enforced on linux"),
        "found stale 'is not enforced on linux' warning in stderr. \
         The old Phase 16 stub warnings should have been removed in Phase 25-01.\n\
         stderr:\n{stderr}"
    );

    assert!(
        !stderr.contains("is not enforced on macos"),
        "found stale 'is not enforced on macos' warning in stderr on Linux. \
         stderr:\n{stderr}"
    );
}

/// REQ-RESL-NIX-02 criterion 2: `--timeout` atomically kills grandchildren via cgroup.kill.
///
/// Spawns 10 background sleep processes. The timeout must kill ALL of them, not just
/// the direct child. Verified by confirming the parent's `nono run` exits within the
/// timeout window (if grandchildren weren't killed, `wait` would block indefinitely
/// after the parent receives SIGKILL but the grandchildren are still running).
#[test]
fn linux_timeout_atomic_kill_grandchildren() {
    require_cgroup_v2!();

    let start = Instant::now();
    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--timeout",
            "5s",
            "--allow-fs-exec=/bin",
            "--allow-fs-exec=/usr",
            "--allow-fs-read=/bin",
            "--allow-fs-read=/usr",
            "--allow-fs-read=/lib",
            "--allow-fs-read=/lib64",
            "--",
            "bash",
            "-c",
            // Spawn 10 grandchildren; `wait` would block forever if they survived the kill.
            "for i in $(seq 1 10); do sleep 60 & done; wait",
        ])
        .output()
        .expect("failed to run nono binary");
    let elapsed = start.elapsed();

    assert!(
        !output.status.success(),
        "expected child to be killed by timeout, but it exited successfully"
    );
    assert!(
        elapsed.as_secs_f64() < 12.0,
        "expected cgroup.kill to atomically kill grandchildren within 12s, took {:.1}s. \
         This may indicate grandchildren survived the kill and `wait` was not interrupted.",
        elapsed.as_secs_f64()
    );
}

/// Phase 37 Plan 37-04 / VALIDATION task 37-04-03 / REQ-RESL-NIX-02:
///
/// Verifies `--cpu-percent 25` actually throttles a CPU-bound workload to
/// approximately 25% on cgroup-v2 + cpu-controller-delegated runner. This is
/// the FIRST functional test exercising `cpu.max`; prior to Phase 37,
/// REQ-RESL-NIX-02 had no test covering the runtime throttling behavior.
///
/// The workload (`yes >/dev/null`) is a tight CPU loop that would consume
/// 100% of one core uncapped. Under `--cpu-percent 25`, the cgroup v2
/// `cpu.max` quota of `25000 100000` (25ms per 100ms period) limits the
/// average CPU% to ~25% over a multi-second window.
///
/// Sampling strategy: spawn nono, wait briefly for the cgroup to apply,
/// then use `pgrep -f 'yes'` to locate the actual workload PID (NOT the
/// supervisor's PID — nono may stay alive in Monitor exec strategy or
/// exec into the child in Direct strategy; the workload pid is what's
/// being throttled by the cgroup). Sample `top -p <pid>` for 5 iterations
/// at 1s intervals and average the `%CPU` column.
///
/// Tolerance band [15, 40] accommodates GitHub Actions runner load
/// variance. If this test flakes on a per-runner basis, widen the band
/// or raise the sampling window — but do NOT switch to a pass-without-
/// asserting shape (Phase 37 D-08 + T-37-14 mitigation: a silent no-op
/// would invalidate ALL of Phase 37's REQ-RESL-NIX-02 verification).
#[test]
fn linux_cpu_percent_throttles_yes_loop() {
    require_cgroup_v2!();
    require_cpu_controller!();

    // Run yes for ~6 seconds capped at 25% CPU.
    let mut child = Command::new(NONO_BIN)
        .args([
            "run",
            "--cpu-percent",
            "25",
            "--allow-fs-exec=/bin",
            "--allow-fs-exec=/usr",
            "--allow-fs-read=/bin",
            "--allow-fs-read=/usr",
            "--allow-fs-read=/lib",
            "--allow-fs-read=/lib64",
            "--",
            "timeout",
            "6",
            "sh",
            "-c",
            "yes >/dev/null",
        ])
        .spawn()
        .expect("spawn nono");

    // Allow nono to start the child + apply the cgroup before sampling.
    std::thread::sleep(std::time::Duration::from_millis(750));

    // Locate the actual workload PID via pgrep. We match `yes` rather than
    // using `child.id()` because the supervisor may stay alive on the
    // parent side (Monitor strategy) while the workload runs in a forked
    // descendant; the workload pid is the one in the throttled cgroup.
    let pgrep = Command::new("pgrep")
        .args(["-x", "yes"])
        .output()
        .expect("invoke pgrep");
    let pgrep_stdout = String::from_utf8_lossy(&pgrep.stdout);
    let workload_pid: Option<u32> = pgrep_stdout.lines().next().and_then(|l| l.trim().parse().ok());

    let workload_pid = match workload_pid {
        Some(p) => p,
        None => {
            // If pgrep returned nothing, fall back to the supervisor pid so
            // we still produce a deterministic diagnostic on failure rather
            // than passing vacuously.
            let _ = child.wait();
            panic!(
                "REQ-RESL-NIX-02: pgrep -x yes returned no PID; the workload \
                 either didn't start or exited before sampling. pgrep stdout: {:?}",
                pgrep_stdout
            );
        }
    };

    // Sample CPU% via top: -b batch, -n 5 iterations, -d 1 1-second delay,
    // -p <pid> filtered. The %CPU column position varies with top version;
    // accept any line that begins with the PID and parse the first column
    // that looks like a floating-point percentage in [0, 200].
    let output = Command::new("top")
        .args(["-b", "-n", "5", "-d", "1", "-p", &workload_pid.to_string()])
        .output()
        .expect("invoke top");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let samples: Vec<f32> = stdout
        .lines()
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            if cols.is_empty() || cols[0] != workload_pid.to_string() {
                return None;
            }
            // Walk columns looking for a plausible CPU% value.
            cols.iter().skip(1).find_map(|c| {
                c.parse::<f32>()
                    .ok()
                    .filter(|v| (0.0..=200.0).contains(v) && c.contains('.'))
            })
        })
        .collect();

    let _ = child.wait();

    assert!(
        !samples.is_empty(),
        "REQ-RESL-NIX-02: top produced no samples for pid {workload_pid}; stdout:\n{stdout}"
    );
    let avg = samples.iter().sum::<f32>() / samples.len() as f32;

    assert!(
        (15.0..=40.0).contains(&avg),
        "REQ-RESL-NIX-02: expected ~25% CPU (band [15,40] for runner noise); \
         got {avg:.1}% from samples {samples:?}"
    );
}

/// Phase 37 Plan 37-04 / VALIDATION task 37-04-04 / REQ-RESL-NIX-03:
///
/// Exercises the LOCKED REQ-RESL-NIX-03 N=5 case (the value the LOCKED
/// `nono inspect` string `max_processes: 5 (cgroup v2 pids.max)` reports).
///
/// This test SITS ALONGSIDE the existing `linux_max_processes_blocks_eleventh_fork`
/// (which covers the N=10 boundary case) — both coverages are preserved
/// per revision-1 checker W8 path b. The N=5 case matches the LOCKED
/// inspect string and the canonical example throughout Phase 37 docs.
///
/// Workload: a small shell loop that backgrounds 8 `sleep` processes.
/// With `--max-processes 5` the parent shell already counts toward the
/// pids.max budget, so the 5th-or-later background fork is rejected by
/// the kernel with EAGAIN (which `sh` surfaces as a non-zero rc from the
/// `(sleep 5 &)` subshell). The test asserts the overall command exits
/// non-zero — proof that at least one fork failure occurred.
#[test]
fn linux_max_processes_5_fork_bomb_contained() {
    require_cgroup_v2!();

    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--max-processes",
            "5",
            "--allow-fs-exec=/bin",
            "--allow-fs-exec=/usr",
            "--allow-fs-read=/bin",
            "--allow-fs-read=/usr",
            "--allow-fs-read=/lib",
            "--allow-fs-read=/lib64",
            "--",
            "sh",
            "-c",
            // Background 8 sleeps; with pids.max=5 the kernel must reject
            // some of them. Track the worst rc so a single fork failure
            // surfaces as a non-zero exit even if later forks succeed.
            "i=0; rc=0; while [ $i -lt 8 ]; do (sleep 5 &) || rc=1; i=$((i+1)); done; exit $rc",
        ])
        .output()
        .expect("failed to run nono binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Production code path either: (a) the inner shell fails to fork past
    // N=5 and exits non-zero, OR (b) the kernel surfaces an EAGAIN /
    // "resource temporarily unavailable" string on stderr. Either is
    // sufficient evidence the pids.max cap is enforced.
    assert!(
        !output.status.success()
            || stderr.to_lowercase().contains("resource")
            || stderr.to_lowercase().contains("again"),
        "REQ-RESL-NIX-03 N=5: expected fork rejection past 5 processes; \
         exit_success={} stdout={stdout} stderr={stderr}",
        output.status.success(),
    );
}
