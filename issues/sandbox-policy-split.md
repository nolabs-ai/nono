# Sandbox Policy Selection Should Be Explicit and Client-Driven

## Summary

Currently, callers of the `nono` sandbox API have no way to declare
which enforcement mechanism they want. The single `Sandbox::apply()`
entry point silently chooses between Landlock and seccomp depending on
the detected kernel ABI, with no way to opt out of the fallback, assert
that enforcement is managed externally, or require Landlock-only
behaviour.

This creates several problems:

- Library consumers such as `nono-py` and `nono-ffi` cannot express
  that they want strict Landlock-only enforcement (and an error if the
  kernel cannot satisfy it), versus the current auto-fallback behaviour.
- Operators running nono inside infrastructure that already enforces
  network policy (iptables, cgroups, systemd units) have no way to tell
  nono to stand down — they still get seccomp and Landlock installed on
  top, which can conflict with their existing setup.
- There is no profile field or CLI flag to select the enforcement
  mechanism at invocation time. The selection is entirely implicit and
  invisible to the operator.

## Background

The sandbox layer currently exposes:

```rust
Sandbox::apply(caps: &CapabilitySet) -> Result<SeccompNetFallback>
Sandbox::apply_with_abi(caps, abi)  -> Result<SeccompNetFallback>
```

Internally `apply_with_abi_inner(allow_seccomp_fallback: bool)` handles
both paths, but the `allow_seccomp_fallback` knob is private. Callers
cannot reach the "Landlock-only, error on fallback" path at all.

On the CLI side, `SeccompPolicy` groups the three boolean flags
(`capability_elevation`, `proxy_fallback`, `af_unix_mediation`) that
control supervisor behaviour, but there is no corresponding user-facing
concept of "which sandbox policy am I running under". The booleans are
scattered across `ExecConfig` and `SupervisorConfig` with no shared
abstraction.

## Proposed Changes

### 1. Introduce a `SeccompPolicy` struct

Replace the scattered booleans in `ExecConfig` / `SupervisorConfig`
with a single `SeccompPolicy` struct that exposes named predicate
methods (`af_unix_mediation()`, `child_requires_dumpable()`, etc.).
This makes the supervisor code self-documenting and removes the risk of
boolean positional errors at call sites.

### 2. Split `apply()` into explicit policy entry points

Expose the `allow_seccomp_fallback` knob publicly by introducing
distinct functions:

| Function | Behaviour |
|---|---|
| `apply_auto` / `apply_auto_with_abi` | Landlock + automatic seccomp fallback (current default) |
| `apply_landlock` / `apply_landlock_with_abi` | Landlock only; error if kernel ABI cannot satisfy network restrictions |
| `apply_external` | No-op; caller asserts enforcement is external |

Deprecate `apply()` and `apply_with_abi()` as aliases for `apply_auto`
variants. Update all in-tree consumers (CLI, `nono-ffi`, `nono-py`,
tool-sandbox).

### 3. Add `LinuxSandboxPolicy` to the profile schema and CLI

Add a `linux.sandbox_policy` field (`auto` | `landlock` | `external`)
to `LinuxConfig` in the profile schema, and a corresponding
`--sandbox-policy` CLI flag on `SandboxArgs`. The CLI flag should
override the profile value; both default to `auto` to preserve existing
behaviour.

Thread the selected policy from `PreparedProfile` → `PreparedSandbox`
→ `ExecutionFlags` → `apply_pre_fork_sandbox()`.

### 4. Centralise `ExecutionFlags` construction

Each call site that builds `ExecutionFlags` manually lists Linux-only
fields. When a new field is added, every site must be updated or it
silently inherits the default instead of the profile value. Introduce
`ExecutionFlags::from_prepared(&PreparedSandbox, silent)` to map all
`PreparedSandbox` fields in one place; call sites then override only
what is specific to their invocation context.

## Acceptance Criteria

- `Sandbox::apply_landlock()` returns an error if the running kernel
  cannot enforce network restrictions via Landlock alone.
- `Sandbox::apply_external()` installs no sandbox rules and returns `Ok(())`.
- A profile with `linux.sandbox_policy: landlock` causes `nono run` to
  use Landlock-only enforcement.
- `--sandbox-policy external` causes `nono run` to skip sandbox
  installation entirely.
- CLI flag overrides profile value.
- Default behaviour (`auto`) is identical to the current release.
- All existing tests continue to pass.
- `nono-ffi` and `nono-py` are updated to use `apply_auto` before the
  deprecated `apply()` entry point is removed.

## Affected Crates

- `nono` — sandbox API (`sandbox/linux.rs`, `sandbox/mod.rs`)
- `nono-cli` — profile schema, CLI args, execution pipeline
- `nono-ffi` — C bindings (`bindings/c/src/sandbox.rs`)
- `nono-py` — Python bindings (coordinated release after `nono` publish)
