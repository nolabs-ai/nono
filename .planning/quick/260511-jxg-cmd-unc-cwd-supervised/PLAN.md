---
slug: cmd-unc-cwd-supervised
quick_id: 260511-jxg
created: 2026-05-11
type: bug-tracker
status: tracking-only
deferred_to: v2.4
---

# Tracker: Supervised exec on Windows sets child CWD as `\\?\` UNC long-path form

## Symptom

POC smoke surfaced this when running `nono run --allow . -- cmd /c echo hello` from
`C:\Users\omack\nono-poc`. The child `cmd.exe` printed a stderr warning:

```
'\\?\C:\Users\omack\nono-poc'
CMD.EXE was started with the above path as the current directory.
UNC paths are not supported.  Defaulting to Windows directory.
hello
```

`hello` printed correctly because `echo` doesn't need CWD. But `cmd.exe` silently fell back
to `C:\Windows` as its actual working directory. Any child program that uses CWD-relative
paths (build tools running `dir`, scripts doing `type README.md`, AI agents using `os.getcwd()`)
will silently behave as if running from `C:\Windows`.

## Hypothesis

The Windows supervised-execution path is passing the **canonicalized `\\?\`-prefixed long
path** as the child's working directory in the `CreateProcessAsUserW` call. The long-path
prefix is correct for `SetNamedSecurityInfoW` (Phase 21 label apply path), but it should
NOT be used for the `lpCurrentDirectory` parameter of `CreateProcess*`.

Likely culprit: a shared canonicalization helper that returns `\\?\C:\...` is being used
for both label-apply target paths AND for the spawn-time CWD argument. The CWD argument
needs to be the bare `C:\Users\omack\nono-poc` (or whatever the user-facing path is) so
legacy Win32 programs (cmd.exe, scripts, older .NET CLI tools) accept it.

Per [Microsoft docs on CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw):
> "The directory must be a full, qualified pathname or relative pathname. **If the path
> contains the `\\?\` prefix, only the first MAX_PATH characters will be used.**" — but
> some programs (cmd.exe per the warning above) reject `\\?\` CWD outright.

## Reproducer

On Windows, in a non-Program-Files user-owned directory:

```powershell
mkdir $env:USERPROFILE\repro-cwd-unc -Force
cd $env:USERPROFILE\repro-cwd-unc
"file content" | Out-File test.txt
nono run --allow . -- cmd /c "echo CWD: %CD% && type test.txt"
```

Expected (post-fix): `CWD: C:\Users\<user>\repro-cwd-unc` and the file contents.
Pre-fix (current): `CWD: C:\Windows` + `cmd.exe` UNC warning + `type test.txt` fails because
`test.txt` doesn't exist in `C:\Windows`.

## Likely fix locations

Search candidates (planner to confirm):

- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — `CreateProcessAsUserW` call site.
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` — supervisor-driven child spawn.
- `crates/nono-cli/src/exec_strategy.rs` — cross-platform spawn helper (if it canonicalizes CWD).
- `crates/nono/src/sandbox/windows.rs` — if the sandbox apply pipeline writes back to spawn
  config (unlikely but worth checking).

The fix shape is probably one of:
1. Strip `\\?\` prefix from the CWD string before passing to `CreateProcessAsUserW`
2. Compute CWD separately from the canonicalized label-apply paths so there's no
   accidental reuse
3. Use `dunce::simplified()` or equivalent on the CWD string

## Out of scope (this task)

- Actually fixing the bug. This is a tracking-only artifact for v2.4 backlog.
- Auditing all `\\?\` usages workspace-wide. The fix is scoped to the spawn-side CWD;
  label-apply paths SHOULD use the `\\?\` form.

## Acceptance (when picked up for v2.4)

- [ ] Repro command above shows correct CWD instead of `C:\Windows`.
- [ ] No `cmd.exe` "UNC paths are not supported" warning on supervised runs from user dirs.
- [ ] Add a regression test in `crates/nono-cli/tests/` that spawns `cmd /c cd` and asserts
      output matches the user-passed CWD (not `C:\Windows`).
- [ ] Label-apply paths (Phase 21 WSFG-01) still use `\\?\` form internally (D-21
      invariance: `*_windows.rs` behavior preserved for the label-apply path).

## Severity assessment

**Medium-Low.**
- Cosmetic for `echo`/non-CWD-relative commands (the smoke step that surfaced it).
- Functional failure for any child that uses CWD-relative paths — build tools, AI agents
  doing `os.getcwd()`, scripts doing `dir`/`type`/`copy` without absolute paths. This is
  most of the practical agent workload.
- Not a security regression (the sandbox still applies; the child just runs from the wrong
  directory).
- POC users running anything beyond `echo` will hit this. POC handoff doc should at minimum
  note the limitation until fixed.

## Cross-reference

- Surfaced during POC smoke 2026-05-11 (this session).
- Related quick task: `260511-jxk-label-guard-drop-on-sigint` (the other fork-side bug
  surfaced same session).
