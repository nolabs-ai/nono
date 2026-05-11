---
slug: label-guard-drop-on-sigint
quick_id: 260511-jxk
created: 2026-05-11
type: bug-tracker
status: tracking-only
deferred_to: v2.4
---

# Tracker: `AppliedLabelsGuard::Drop` revert doesn't fire on Ctrl+C; labels leak across runs

## Symptom

POC smoke session (this session, 2026-05-11):

1. User ran `nono run --profile claude-code -- cmd /c echo "claude-code profile spawned ok"`
   from `C:\Users\omack\nono-poc`.
2. Supervisor applied Low-IL labels to all profile-grant paths (`~/.claude`, `~/.cache/claude`,
   `~/.cargo`, `~/.config/git/ignore`, `~/.gitconfig`, `~/.local/bin`, `~/.claude/claude.json`,
   `~/nono-poc`).
3. Output stopped at `Applying sandbox...` — supervisor appeared to hang (probably the
   `cmd.exe` UNC-CWD issue from sibling task `260511-jxg-cmd-unc-cwd-supervised` — child
   silently doing nothing while supervisor waited for output).
4. User hit Ctrl+C to break out.
5. Subsequent `nono run` invocations from the same user account printed `WARN label guard:
   path has pre-existing mandatory-label ACE; skipping apply + revert` for every previously-
   labeled path. The labels were still on disk; nono refused to touch them.

This is a label leak. Phase 21 WSFG-02 design says labels are RAII-managed via
`AppliedLabelsGuard::Drop` (revert on supervisor exit). Drop didn't fire on Ctrl+C; labels
persisted.

## Why this matters

- Subsequent `nono run` invocations see pre-existing labels and skip applying their own.
  The WARN explicitly notes "grant may have no observable enforcement effect depending on
  pre-existing label."
- In the worst case, a previous run's NO_READ_UP label on a path the user expected to be
  readable in a later run silently makes that path unreadable to the child without any
  CLI-level error.
- Cumulative damage: every interrupted `nono run` adds to the leaked-label set. Over time
  the user's home directory accumulates explicit Low-IL ACEs that nobody planned for.
- The recovery path (manual `icacls` cleanup) is undocumented and fiddly (icacls
  `/setintegritylevel M` creates an explicit Medium ACE, doesn't actually remove the label
  — clean removal requires PowerShell .NET SACL manipulation).

## Hypothesis

Ctrl+C on Windows delivers `SIGINT`-equivalent (`CTRL_C_EVENT`) to the supervisor process.
The Rust runtime's default `SIGINT` handler **terminates the process without running
destructors** for stack-allocated values that own resources. The `AppliedLabelsGuard` lives
on the stack of `prepare_live_windows_launch` (or similar) and its `Drop` would run on
normal stack unwind, but `CTRL_C_EVENT` -> default handler -> ExitProcess bypasses the
unwind.

The Phase 21 design assumed graceful exit paths. The Ctrl+C path was not exercised in the
Phase 21 test suite (search needed: are there `#[test]` cases that wait on signals?
Probably not).

## Reproducer

```powershell
# Apply labels
cd $env:USERPROFILE\repro-leak
nono run --profile claude-code -- powershell -Command "Start-Sleep -Seconds 60"
# Hit Ctrl+C during the 60-second sleep.

# Verify labels leaked
icacls $env:USERPROFILE\.claude | Select-String "Mandatory Label"
# Expected (pre-fix): "Mandatory Label\Low Mandatory Level:(...)"
# Expected (post-fix): nothing — Drop ran during Ctrl+C handling, labels reverted.
```

## Likely fix locations

- **`crates/nono-cli/src/exec_strategy_windows/labels_guard.rs`** — `AppliedLabelsGuard`
  Drop impl. Where the revert logic lives.
- **`crates/nono-cli/src/exec_strategy_windows/launch.rs`** — owns the guard. Decide:
  catch `CTRL_C_EVENT` via `SetConsoleCtrlHandler` and run revert explicitly?
- **`crates/nono-cli/src/cli_bootstrap.rs`** or wherever the top-level Tokio runtime / main
  is set up — install a Ctrl-C handler that triggers controlled shutdown.

## Fix shape candidates

1. **Console control handler (Windows-specific)**: Install `SetConsoleCtrlHandler` early in
   `main`. On `CTRL_C_EVENT`, signal the supervisor to begin orderly shutdown (drop guards
   in reverse order, revert labels, then exit).
2. **Tokio cancellation token + ctrl_c() future**: If supervisor is async, race
   `tokio::signal::ctrl_c()` against the child-wait future. On Ctrl+C, cancel the wait and
   let stack unwind naturally.
3. **Persisted state file**: Write the label-state to a `~/.nono/labels-pending.json` at
   apply time. On next `nono` invocation, detect orphaned label-state file and revert before
   doing anything else. Defensive belt-and-suspenders.

(1) + (3) together is the robust answer. (3) alone handles crashes and SIGKILL too, where
no handler can run.

## Out of scope (this task)

- Actually fixing the bug. Tracking-only artifact for v2.4 backlog.
- Cleanup-tool fix. Separate concern: how operators recover from leaked labels. icacls
  `/setintegritylevel M` is the wrong knob (creates explicit Medium ACE instead of removing).
  Right approach: PowerShell .NET `[System.Security.AccessControl.FileSecurity]` SACL
  manipulation, or a `nono trust labels-cleanup` subcommand. Track separately if v2.4
  decides operator-facing cleanup tooling is in scope.

## Acceptance (when picked up for v2.4)

- [ ] Repro above shows zero leaked labels post-Ctrl+C.
- [ ] Regression test: spawn a sleeping child via `nono run`, send `CTRL_C_EVENT`, then
      assert no `Mandatory Label\Low Mandatory Level` ACE remains on any pre-Ctrl+C-labeled
      path.
- [ ] Cover the other interrupted-exit paths too: parent terminal closed (HUP-equivalent),
      task killed via Task Manager, system shutdown.
- [ ] `AppliedLabelsGuard::Drop` continues to fire on the graceful-exit path (don't break
      existing behavior).
- [ ] Consider also: persisted label-state file (defensive belt-and-suspenders for SIGKILL
      / power loss / OS crash cases where no handler can run).

## Severity assessment

**Medium.**
- Functional impact: subsequent runs silently lose grant enforcement on previously-labeled
  paths. The WARN-level diagnostic is the only signal, and only if the user reads stderr.
- Cumulative damage: every interrupted run adds to leaked set. POC users will accumulate
  state.
- Not a security boundary bypass (labels are too-restrictive, not too-permissive — Low-IL
  ACE leftover is denial-of-access, not grant-of-access).
- Workaround exists (manual cleanup) but it's undocumented and the obvious tool (icacls
  setintegritylevel) does the wrong thing.

## Cross-reference

- Surfaced during POC smoke 2026-05-11 (this session).
- Related quick task: `260511-jxg-cmd-unc-cwd-supervised` (the OTHER fork-side bug
  surfaced same session — likely the reason the supervisor "hung" prompting the Ctrl+C
  that triggered this label-leak).
- Phase 21 WSFG-02 origin: `AppliedLabelsGuard` RAII design assumed graceful exit only.
