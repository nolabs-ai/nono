---
phase: 25
slug: cross-platform-resl-aipc-unix-design
status: complete
nyquist_compliant: partial
wave_0_complete: true
created: 2026-05-09
---

# Phase 25 — Validation Strategy

> Per-phase validation contract. Reconstructed retroactively from artifacts after
> /gsd-audit-milestone v2.3 surfaced the missing VERIFICATION.md / VALIDATION.md
> pair. Phase shipped as a partial-execution split: Plan 25-02 (ADR) executed and
> closed REQ-AIPC-NIX-01; Plan 25-01 (RESL Unix backends) deferred to v2.4
> pending Linux/macOS host coverage — REQ-RESL-NIX-01..03 are tracked here as
> Manual-Only carry-forwards.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust + Cargo (built-in `#[test]` runner) |
| **Config file** | `Cargo.toml` (workspace) |
| **Quick run command** | `cargo test -p nono-cli --test adr_aipc_unix_futures` |
| **Full suite command** | `cargo test -p nono-cli` |
| **Estimated runtime** | <1s for the 6 ADR-shape tests; ~2-3 min for full nono-cli suite |
| **Test directory** | `crates/nono-cli/tests/` |

---

## Sampling Rate

- **After every task commit:** Run the 6 ADR-shape tests (`cargo test -p nono-cli --test adr_aipc_unix_futures`).
- **After every plan wave:** Run `cargo test -p nono-cli`.
- **Before `/gsd-verify-work`:** Full nono-cli suite green; ADR-shape tests report `6 passed; 0 failed; 0 ignored`.
- **Max feedback latency:** <1s for ADR shape; ~3 min for the full suite.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 25-02-01 | 02 | 1 | REQ-AIPC-NIX-01 | T-25-02-01 (Information Disclosure — accepted; ADR is roadmap statement) | ADR exists at `docs/architecture/aipc-unix-futures.md` with 6 HandleKind rows + Status=Accepted + length 250–400 + 6 H2 sections | unit (Rust integration) | `cargo test -p nono-cli --test adr_aipc_unix_futures` | green | green |
| 25-02-02 | 02 | 1 | REQ-AIPC-NIX-01 | T-25-02-02 (Tampering — single-line additive PROJECT.md edit) | PROJECT.md cross-links the ADR via `aipc-unix-futures` substring (idempotent — skip if present) | unit (Rust integration) | `cargo test -p nono-cli --test adr_aipc_unix_futures project_md_cross_links_the_adr` | green | green |
| 25-01-01 | 01 | — | REQ-RESL-NIX-01 | (Plan 25-01 deferred) | cgroup v2 enforces memory.max / cpu.max / pids.max; the four `is not enforced on linux` warnings deleted from `exec_strategy.rs::collect_unix_resource_limit_warnings` | integration (Linux host) | `cargo test -p nono-cli --test resl_nix_linux_integration -- --ignored` | ❌ W0 | manual-only (host-blocked → v2.4) |
| 25-01-02 | 01 | — | REQ-RESL-NIX-02 | (Plan 25-01 deferred) | `--timeout` enforces wall-clock kill of cgroup descendant tree atomically via `cgroup.kill` | integration (Linux host) | `cargo test -p nono-cli --test resl_nix_linux_timeout -- --ignored` | ❌ W0 | manual-only (host-blocked → v2.4) |
| 25-01-03 | 01 | — | REQ-RESL-NIX-03 | (Plan 25-01 deferred) | macOS `setrlimit(RLIMIT_AS, RLIMIT_NPROC)` via `pre_exec`; `--cpu-percent` rejected at clap parse time with `NotSupportedOnPlatform { feature: "cpu_percent_macos" }` | integration (macOS host) | `cargo test -p nono-cli --test resl_nix_macos_integration -- --ignored` | ❌ W0 | manual-only (host-blocked → v2.4) |

*Status legend: pending / green / red / flaky / manual-only*

---

## Wave 0 Requirements

- [x] `crates/nono-cli/tests/adr_aipc_unix_futures.rs` — 6 ADR-shape invariants (REQ-AIPC-NIX-01)

*Plan 25-01 Wave 0: deferred. Test files (`resl_nix_linux_integration.rs`, `resl_nix_linux_timeout.rs`, `resl_nix_macos_integration.rs`) will be authored alongside the v2.4 implementation; their must-haves require host-resident `/sys/fs/cgroup/` state and `setrlimit` syscalls that this Windows host cannot exercise.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `nono run --memory 256m -- bash -c "tail -c 1G </dev/urandom"` is OOM-killed; `nono inspect <id>` shows `memory_kill: true` | REQ-RESL-NIX-01 | Linux 5.13+ host with cgroup v2 systemd delegation required; cannot run from Windows host. Plan 25-01 must execute first. | (v2.4) Run on Linux POC box; assert child SIGKILL'd, inspect output reports `memory_kill: true`. |
| `nono run --cpu-percent 50 -- bash -c "yes >/dev/null"` pegs at ~50% of one core | REQ-RESL-NIX-01 | Same — Linux host required. | (v2.4) Run on Linux POC box; sample `/proc/<pid>/stat` user+system time over 5s. |
| `nono run --max-processes 10 -- bash -c "for i in {1..20}; do sleep 60 & done; wait"` fails after 10th fork with `pids.max` | REQ-RESL-NIX-01 | Same — Linux host required. | (v2.4) Run on Linux POC box; assert error contains `pids.max`. |
| Cgroup v1 / no-delegation system fails fast with `NonoError::UnsupportedPlatform { feature: "cgroup_v2" }` BEFORE any child spawn | REQ-RESL-NIX-01 | Requires a Linux system without systemd cgroup delegation (intentional negative-path). | (v2.4) Boot a cgroup v1 VM or unset systemd delegation; assert error path. |
| `nono run --timeout 5s -- sleep 60` exits at ~5s; `inspect` shows `timeout_kill: true`. Atomic kill of 100 grandchildren via `cgroup.kill` | REQ-RESL-NIX-02 | Linux host with cgroup v2 required. | (v2.4) Run on Linux POC box; sample wall time + descendant PID set. |
| `nono run --memory 256m -- <large alloc>` aborts via RLIMIT_AS mmap failure on macOS | REQ-RESL-NIX-03 | macOS host required (BSD `setrlimit`); cannot run from Windows. | (v2.4) Run on macOS POC box; assert mmap failure path. |
| `nono run --max-processes 10 -- ...` fails after 10th fork with EAGAIN from RLIMIT_NPROC on macOS | REQ-RESL-NIX-03 | macOS host required. | (v2.4) Run on macOS POC box. |
| `nono run --cpu-percent 50 -- ls` on macOS fails at clap parse with `NotSupportedOnPlatform { feature: "cpu_percent_macos" }` | REQ-RESL-NIX-03 | Requires macOS-target build (clap target-gating). | (v2.4) Build for `x86_64-apple-darwin` / `aarch64-apple-darwin` and execute; assert exit code non-zero with no child spawn. |
| Cgroup cleanup happens unconditionally via Drop guard on session exit (success + panic paths) | REQ-RESL-NIX-01 | Linux host required; tests both success and panic-via-fault-injection paths. | (v2.4) On Linux POC box, after `nono run` exits and after a forced panic, verify `ls /sys/fs/cgroup/<delegated>/nono-*/` is empty. |

*All Plan 25-01 carry-forwards are explicitly Manual-Only because Plan 25-01 plan + CONTEXT are committed (commit `3ed80d38`) but execution is deferred to v2.4 pending Linux/macOS host. The Manual-Only entries become automated integration tests when v2.4 picks up Plan 25-01.*

---

## Validation Sign-Off

- [x] Plan 25-02 (REQ-AIPC-NIX-01) has automated `<automated>` verify via `crates/nono-cli/tests/adr_aipc_unix_futures.rs` — 6 tests, all green.
- [x] Plan 25-01 (REQ-RESL-NIX-01..03) recorded as Manual-Only with v2.4 carry-forward note.
- [x] Sampling continuity holds for the executed half (Plan 25-02 ADR shape).
- [x] Wave 0 covers all MISSING references that this phase actually shipped (RESL-NIX-* tests are deferred with Plan 25-01).
- [x] No watch-mode flags.
- [x] Feedback latency <1s for ADR shape tests.
- [⚠] `nyquist_compliant: partial` — REQ-AIPC-NIX-01 has automated coverage; REQ-RESL-NIX-01..03 await v2.4 host-resident execution. Set to `true` when Plan 25-01 lands and its integration tests join the Per-Task Map.

**Approval:** approved 2026-05-09 (partial — ADR coverage automated; RESL-NIX carry-forward to v2.4 documented).
