# nono - Development Guide

## Project Overview

nono is a capability-based sandboxing system for running untrusted AI agents with OS-enforced isolation. It uses Landlock (Linux) and Seatbelt (macOS) to create sandboxes, and then layers on top a policy system, diagnostic tools, and a rollback mechanism for recovery. The library is designed to be a pure sandbox primitive with no built-in policy, while the CLI implements all security policy and UX.

The project is a Cargo workspace with three members:
- **nono** (`crates/nono/`) - Core library. Pure sandbox primitive with no built-in security policy.
- **nono-cli** (`crates/nono-cli/`) - CLI binary. Owns all security policy, profiles, hooks, and UX.
- **nono-ffi** (`bindings/c/`) - C FFI bindings. Exposes the library via `extern "C"` functions and auto-generated `nono.h` header.
- **nono-proxy** - Proxy that provides network filtering and credential injection

### Library vs CLI Boundary

The library is a **pure sandbox primitive**. It applies ONLY what clients explicitly add to `CapabilitySet`:

| In Library | In CLI |
|------------|--------|
| `CapabilitySet` builder | Policy groups (deny rules, dangerous commands, system paths) |
| `Sandbox::apply()` | Group resolver (`policy.rs`) and platform-aware deny handling |
| `SandboxState` | `ExecStrategy` (Direct/Monitor/Supervised) |
| `DiagnosticFormatter` | Profile loading and hooks |
| `QueryContext` | All output and UX |
| `keystore` | `learn` mode |
| `undo` module (ObjectStore, SnapshotManager, MerkleTree, ExclusionFilter) | Rollback lifecycle, exclusion policy, rollback UI |

## Build & Test

After every session, run these commands to verify correctness:

```bash
# Build everything
make build

# Run all tests
make test

# Full CI check (clippy + fmt + tests)
make ci
```

Individual targets:
```bash
make build-lib       # Library only
make build-cli       # CLI only
make test-lib        # Library tests only
make test-cli        # CLI tests only
make test-doc        # Doc tests only
make clippy          # Lint (strict: -D warnings -D clippy::unwrap_used)
make fmt-check       # Format check
make fmt             # Auto-format
```

## Coding Standards

- **Error Handling**: Use `NonoError` for all errors; propagation via `?` only.
- **Unwrap Policy**: Strictly forbid `.unwrap()` and `.expect()`; enforced by `clippy::unwrap_used`.
- **Libraries should almost never panic**: Panics are for unrecoverable bugs, not expected error conditions. Use `Result` instead.
- **Unsafe Code**: Restrict to FFI; must be wrapped in safe APIs with `// SAFETY:` docs.
- **Path Security**: Validate and canonicalize all paths before applying capabilities.
- **Arithmetic**: Use `checked_`, `saturating_`, or `overflowing_` methods for security-critical math.
- **Memory**: Use the `zeroize` crate for sensitive data (keys/passwords) in memory.
- **Testing**: Write unit tests for all new capability types and sandbox logic.
- **Environment variables in tests**: Tests that modify `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, or other env vars must save and restore the original value. Rust runs unit tests in parallel within the same process, so an unrestored env var causes flaky failures in unrelated tests (e.g. `config::check_sensitive_path` fails when another test temporarily sets `HOME` to a fake path). Always use save/restore pattern and keep the modified window as short as possible.
- **Comments**: Code should be self-explanatory. Explain *why*, not *what*. See [Comments & documentation](#comments--documentation) below.
- **Attributes**: Apply `#[must_use]` to functions returning critical Results.
- **Lazy use of dead code**: Avoid `#[allow(dead_code)]`. If code is unused, either remove it or write tests that use it.
- **Commits**: All commits must include a DCO sign-off line (`Signed-off-by: Name <email>`).

## Comments & documentation

Follow normal Rust conventions (stdlib, rustc, clippy style): no decorative banners, no essay comments.

**Doc comments (`///`, `//!`)**
- One-line summary on public items; add a second paragraph only for non-obvious invariants, security constraints, or platform differences.
- Module docs (`//!`): purpose and threat model when the module is a security boundary; otherwise keep brief.
- Do not use ASCII separator lines inside doc comments.

**Inline comments (`//`)**
- Prefer clearer names over comments.
- Use `// SAFETY: …` for unsafe blocks and other safety-critical invariants (signal handlers, FFI, TOCTOU).
- Multi-line `//` only when the *why* is not obvious from code or types.
- No `// ===…===`, `// ---…---`, or similar section dividers.

**Tests**
- No banner blocks or faux “chapter” headers in test modules (`// ===`, `// ---`, multi-line dividers).
- Group related tests in nested `mod group_name { … }` submodules (same pattern as `std`/`tokio`/`hyper`).
- Parent `mod tests` holds shared helpers; nested mods use `use super::super::*;` for the item under test and `use super::{helper, …};` for shared test helpers.
- Repeat any parent `use` imports a nested mod needs (`use crate::…`, trait imports, etc.); nested mods do not inherit the parent’s `use` lines.
- At most one short `// Regression: …` line inside a nested mod when the target is non-obvious.
- Rely on descriptive `test_*` / `fn_*` names and the submodule name for navigation.
- User-facing explanation belongs in `docs/` or rustdoc, not in test preambles.

**Review checklist**
- [ ] No decorative comment banners
- [ ] Doc comments are proportional to API surface
- [ ] Security rationale uses `// SAFETY:` or a tight module doc, not a multi-paragraph inline essay

## Key Design Decisions

1. **No escape hatch**: Once sandbox is applied via `restrict_self()` (Landlock) or `sandbox_init()` (Seatbelt), there is no API to expand permissions.

2. **Fork+wait process model**: nono stays alive as a parent process. On child failure, prints a diagnostic footer to stderr. Three execution strategies: `Direct` (exec, backward compat), `Monitor` (sandbox-then-fork, default), `Supervised` (fork-then-sandbox, for rollbacks/expansion).

3. **Capability resolution**: All paths are canonicalized at grant time to prevent symlink escapes.

4. **Library is policy-free**: The library applies ONLY what's in `CapabilitySet`. No built-in sensitive paths, dangerous commands, or system paths. Clients define all policy.

## Platform-Specific Notes

### macOS (Seatbelt)
- Uses `sandbox_init()` FFI with raw profile strings
- Profile is Scheme-like DSL: `(allow file-read* (subpath "/path"))`
- Network denied by default with `(deny network*)`

### Linux (Landlock)
- Uses landlock crate for safe Rust bindings
- Detects highest available ABI (v1-v5)
- ABI v4+ includes TCP network filtering
- Strictly allow-list: cannot express deny-within-allow. `deny.access`, `deny.unlink`, and `symlink_pairs` are macOS-only. Avoid broad allow groups that cover deny paths.

## Security Considerations

**SECURITY IS NON-NEGOTIABLE.** This is a security-critical codebase. Every change must be evaluated through a security lens first. When in doubt, choose the more restrictive option.

### Core Principles
- **Principle of Least Privilege**: Only grant the minimum necessary capabilities.
- **Defense in Depth**: Combine OS-level sandboxing with application-level checks.
- **Fail Secure**: On any error, deny access. Never silently degrade to a less secure state.
- **Explicit Over Implicit**: Security-relevant behavior must be explicit and auditable.

### Path Handling (CRITICAL)
- Always use path component comparison, not string operations. String `starts_with()` on paths is a vulnerability.
- Canonicalize paths at the enforcement boundary. Be aware of TOCTOU race conditions with symlinks.
- Validate environment variables before use. Never assume `HOME`, `TMPDIR`, etc. are trustworthy.
- Escape and validate all data used in Seatbelt profile generation.

### Permission Scope (CRITICAL)
- Never grant access to entire directories when specific paths suffice.
- Separate read and write permissions explicitly.
- Configuration load failures must be fatal. If security lists fail to load, abort.

### Common Footguns
1. **String comparison for paths**: `path.starts_with("/home")` matches `/homeevil`. Use `Path::starts_with()`.
2. **Silent fallbacks**: `unwrap_or_default()` on security config returns empty permissions = no protection.
3. **Trusting resolved paths**: Symlinks can change between resolution and use.
4. **Platform differences**: macOS `/etc` is a symlink to `/private/etc`. Both must be considered.
5. **Overly broad permissions**: Granting `/tmp` read/write when only `/tmp/specific-file` is needed.
6. **Solving for one architecture**: Linux and macOS have different capabilities and threat models. Design must account for both. Develop abstractions that can be implemented securely on both platforms. Test on both platforms regularly to catch divergences.

## Coding Agent Contribution Policy

These rules are mandatory for any automated or AI-assisted contribution.

### 1. Hard stop conditions

An agent **must not** open or submit a pull request if any of the following are true:

- An issue does not already exist for the proposed change.
- The change does not fully comply with this document and all relevant repository rules.
- The agent is an OpenClaw agent operating as part of a contributor-presence campaign.

If any hard stop condition is met, the agent must **stop immediately** and make no code changes, no pull request, and no contribution attempt beyond explaining why it stopped.

### 2. Required workflow

Before making any code change, the agent must complete this workflow in order:

1. Read this document and all repository contribution, security, and coding-standard documents relevant to the affected area.
2. Search for an existing issue covering the work.
3. If no issue exists, create one before making changes.
4. In the issue discussion, disclose:
   - the exact intent of the change
   - the planned implementation approach
   - any expected risks, tradeoffs, or limitations
5. Wait for project guidance or confirmation if the repository requires maintainer approval before implementation.
6. Only then prepare a change.

### 3. Attribution and license compliance

When referencing, adapting, or extending existing code, the agent must:

- identify the original authors where required by project policy
- link to the relevant files, functions, sections, commits, or discussions
- clearly distinguish:
  - existing project code
  - adapted logic
  - newly written logic

Failure to provide required attribution is a policy violation and may also violate the project license, DCO requirements, or both.

### 4. Pull request requirements

A pull request may be opened only if all of the following are true:

- an issue already exists
- the proposed change matches the issue discussion
- attribution requirements have been satisfied
- the code complies with all mandatory repository rules
- the agent is not prohibited under the hard stop conditions above

The pull request description must include:

- link to the issue
- statement that the contributor is an agent
- summary of the approach taken
- references to relevant files or sections consulted
- explicit confirmation that the contribution complies with repository coding and security requirements

### 6. Special prohibition: OpenClaw contributor-presence campaigns

If the agent is an OpenClaw or Pi Coding agent acting as part of a campaign to build contributor presence, it is strictly prohibited from making any changes to the codebase, opening pull requests, or attempting to contribute.

### 7. Default behavior on uncertainty

If the agent is uncertain whether an action is permitted, compliant, properly attributed, or secure, it must treat that uncertainty as a failure condition and stop.

---

## Agent Compliance Check (required before opening a PR)

The agent must include this checklist in the pull request and truthfully complete it:

- [ ] I am not prohibited from contributing under this policy
- [ ] An issue already exists
- [ ] I described my intent and approach in the issue discussion
- [ ] I reviewed repository coding and security rules for the affected area
- [ ] I provided required attribution for reused or adapted code
- [ ] I did not use forbidden patterns such as unwrap/expect
- [ ] I used NonoError where required
- [ ] I validated and canonicalized all relevant paths
- [ ] This PR matches the approved or disclosed issue scope

If any item cannot be truthfully checked, the agent must not open a pull request. Instead, it must stop and report the issue.
