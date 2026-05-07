//! Wall-clock benchmark for an ETI tool invocation.
//!
//! Run with: `cargo bench --bench eti_invoke`
//! For a quick compile-check / single-iteration smoke run: `cargo bench --bench eti_invoke -- --test`
//! For preflight diagnostics: `ETI_BENCH_VERBOSE=1 cargo bench --bench eti_invoke`
//!
//! Three measurements are reported:
//!
//! - `git_version_under_eti` — full ETI lifecycle (shim, policy resolve, Landlock, exec).
//! - `git_version_under_nono_no_eti` — nono with a non-ETI profile. Subtracting this from
//!   the ETI number isolates ETI-specific overhead, which is what the perf fixes
//!   (cached ELF closure, drop per-invocation SHA-256, fd-pinned exec) are expected to move.
//! - `git_version_baseline_direct` — direct fork+exec of git. The hardware floor.
//!
//! Skips silently on non-Linux platforms and when Landlock or `/usr/bin/git` is unavailable.

use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(not(target_os = "linux"))]
fn run(_c: &mut Criterion) {
    eprintln!("[skip] eti_invoke bench: ETI is Linux-only on this build");
}

#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
fn nono_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nono")
}

#[cfg(target_os = "linux")]
fn run(c: &mut Criterion) {
    if !preflight_ok() {
        eprintln!(
            "[skip] eti_invoke bench: preflight failed. \
             Re-run with ETI_BENCH_VERBOSE=1 for details. \
             Common causes: Landlock unavailable, /usr/bin/git missing, \
             or built-in linux-eti-git-ssh profile not loaded."
        );
        return;
    }

    let mut group = c.benchmark_group("eti_invoke");
    // Each iteration is a full process spawn (~tens to hundreds of ms),
    // so keep sample size low and total time bounded.
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(3));

    group.bench_function("git_version_under_eti", |b| {
        b.iter(run_eti_git_version);
    });

    group.bench_function("git_version_under_nono_no_eti", |b| {
        b.iter(run_nono_no_eti_git_version);
    });

    group.bench_function("git_version_baseline_direct", |b| {
        b.iter(run_direct_git_version);
    });

    group.finish();
}

#[cfg(target_os = "linux")]
fn run_eti_git_version() {
    run_and_assert(
        "ETI git --version",
        Command::new(nono_bin()).args([
            "run",
            "--profile",
            "linux-eti-git-ssh",
            "--",
            "git",
            "--version",
        ]),
    );
}

#[cfg(target_os = "linux")]
fn run_nono_no_eti_git_version() {
    run_and_assert(
        "nono no-ETI git --version",
        Command::new(nono_bin()).args(["run", "--profile", "default", "--", "git", "--version"]),
    );
}

#[cfg(target_os = "linux")]
fn run_direct_git_version() {
    run_and_assert(
        "direct git --version",
        Command::new("/usr/bin/git").arg("--version"),
    );
}

#[cfg(target_os = "linux")]
fn run_and_assert(label: &str, cmd: &mut Command) {
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|err| panic!("{label}: spawn failed: {err}"));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "{label}: exit {}\n--- captured stderr ---\n{}\n--- end stderr ---",
            output.status, stderr
        );
    }
}

#[cfg(target_os = "linux")]
fn preflight_ok() -> bool {
    let verbose = std::env::var_os("ETI_BENCH_VERBOSE").is_some();

    if !std::path::Path::new("/usr/bin/git").exists() {
        if verbose {
            eprintln!("preflight: /usr/bin/git missing");
        }
        return false;
    }

    let output = Command::new(nono_bin())
        .args([
            "run",
            "--profile",
            "linux-eti-git-ssh",
            "--",
            "git",
            "--version",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(if verbose {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .output();
    match output {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            if verbose {
                eprintln!("preflight: nono ETI exited with status {}", o.status);
            }
            false
        }
        Err(err) => {
            if verbose {
                eprintln!("preflight: spawn failed: {err}");
            }
            false
        }
    }
}

criterion_group!(benches, run);
criterion_main!(benches);
