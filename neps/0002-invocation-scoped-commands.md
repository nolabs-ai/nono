---
nep: 0002
title: Tool Sandbox invocation-scoped filesystem approvals
authors:
  - Luke Hinds
status: draft
created: 2026-09-21
superseded-by:
---

# NEP-0002: Tool Sandbox invocation-scoped filesystem approvals

## Summary

Extend the Tool Sandbox policy model so that a sandboxed command can request a
narrowly scoped filesystem capability for one invocation without escaping the
filesystem policy selected for that invocation.

The central mechanism is an approval-bounded filesystem expansion: a command
may propose an exact path, but the supervisor canonicalizes it, checks it
against configured ceilings and deny paths, obtains approval, re-checks its
identity, and grants it only to the fresh child sandbox. Supporting Tool
Sandbox features—wildcard command mediation, caller-declared environment
forwarding, and Unix-domain socket grants—provide the controlled execution
context in which this expansion operates.

## Motivation

Tool Sandbox policies currently require every filesystem capability to be
known before a child invocation starts. That is too rigid for workflows such
as Git operations, package managers, build systems, and language tooling that
discover exact paths during an invocation. The obvious alternative—granting a
broad writable workspace—would undermine the sandbox's least-privilege model
and make path-specific deny rules difficult to enforce.

The proposal provides controlled filesystem expansion while retaining a policy
ceiling:

- a child may propose an exact filesystem grant for one invocation, but only
  within configured read/write roots and only after approval; and
- approved paths are revalidated by device and inode immediately before
  capability installation;
- the resulting grant is added only to the fresh child sandbox and is recorded
  in the command-policy audit event; and
- command mediation and environment forwarding remain bounded so they cannot
  be used to bypass the filesystem approval ceiling.

### Goals

- Keep command mediation and policy resolution in `nono-cli`.
- Preserve explicit command policies as the highest-precedence policy.
- Make filesystem approval exact, invocation-scoped, auditable, and bounded by
  profile-defined roots and deny paths.
- Preserve the selected caller policy while resolving an approval request.
- Support both Linux and macOS with the narrowest equivalent enforcement each
  platform provides.
- Fail closed on malformed requests, stale paths, missing policy, unsupported
  approval backends, or ambiguous command identity.

### Non-Goals

- Adding policy defaults to the `nono` library.
- Allowing a child process to expand its own policy ceiling.
- Turning filesystem approval into an ambient or session-wide capability.
- Using wildcard command mediation, environment forwarding, or Unix socket
  grants to widen the filesystem approval ceiling.
- Making macOS Seatbelt deny-within-allow semantics a prerequisite for Linux
  enforcement.

## Proposal

### Policy model

The command policy remains a CLI-owned model. A command may define:

- `from.<caller>` edges that select the policy based on the verified caller;
- `export_env` patterns for values copied from that caller's environment;
- `approval_fs` with `read_roots`, `write_roots`, an approval backend, and a
  timeout; and
- `unix_socket_bind` paths, including the Git filesystem-monitor dynamic token.

The top-level `session_export_env` applies only when the resolved caller is
the session itself. An unknown caller exports nothing. Environment patterns
must exclude reserved `NONO_*` variables, and the filtering step removes the
filesystem-request variable before launching a child so a child cannot
re-propose its caller's request as a chained capability.

### Supporting command mediation

The filesystem approval mechanism applies to normal explicit command policies
and to commands reached through the optional `commands."*"` policy. Wildcard
mediation is not itself the security boundary being proposed; it is a way to
ensure that otherwise-unlisted external commands still enter the same policy
and approval path.

The special `commands."*"` policy mediates otherwise-unlisted external
executables found in trusted original-`PATH` directories. Explicit command
entries take precedence.

At startup, the CLI inventories executable names and their filesystem
identities. The inventory is bounded and creates the exact shim names needed
for normal `PATH` lookup. Full path resolution, identity verification, and
hashing are deferred until the first invocation of a particular wildcard
command, then cached for that runtime. Expensive resolution happens outside
the shared cache lock, and cache persistence uses a unique temporary file and
atomic rename.

Wildcard mediation does not cover shell builtins, aliases, functions, or
commands added to `PATH` after startup. A command whose path or identity no
longer matches the startup inventory is denied. The wildcard policy also
cannot be combined with URL delegation while both features require the same
reserved shim name.

### Supporting caller environment forwarding

The normal child environment remains filtered by the command's policy.
`export_env` adds only variables matching the caller-declared patterns, with
exact names and constrained wildcards validated by the profile loader. Values
come from the calling process, not from the profile, so profiles should prefer
specific names over `*` and must never use this mechanism for implicit secret
forwarding.

Caller information is resolved from the supervised process lineage and policy
edges. The selected caller policy is passed through every child-launch path,
including direct, captured, approval, and helper launches.

### Invocation-scoped filesystem approval

When a command needs a path not already granted by its sandbox, the shim may
describe an exact file or directory request through the internal
`NONO_TOOL_SANDBOX_FS_REQUEST` channel. The supervisor:

1. parses and validates the request;
2. canonicalizes the requested paths and rejects malformed, relative, or
   out-of-ceiling paths;
3. checks read requests against `read_roots`, write requests against
   `write_roots`, and applies the resolved deny paths;
4. captures the approved path's device and inode identity;
5. sends the normalized request to the configured approval backend;
6. re-checks the path identity immediately before capability installation; and
7. installs the grant only for the fresh child invocation when approval is
   granted.

The configured roots are ceilings, not grants. Approval cannot widen them, and
an absent policy, invalid backend, timeout, denial, path replacement, or
identity mismatch fails closed. The normalized request, resulting decision,
and filesystem grants are included in the command-policy audit event.

### Supporting Unix-domain socket grants

`unix_socket_bind` grants connect and bind access to named AF_UNIX socket paths.
For an existing socket, the grant is scoped to the socket file. For a socket
that may be created, the grant is scoped to the necessary parent directory.
Dynamic tokens such as `@git:fsmonitor-socket` resolve from the current
worktree's private Git directory without spawning Git or trusting attacker-
controlled Git configuration.

The resolved socket grant is represented in the child capability set and is
not a substitute for arbitrary filesystem write access.

### Platform behavior

On Linux, Landlock receives only the explicitly resolved filesystem and Unix
socket capabilities. Landlock is allow-list based and cannot express
deny-within-allow, so approval roots and deny paths are resolved before the
capability set is built; the design does not rely on a post hoc deny rule.

On macOS, Seatbelt receives the equivalent resolved grants and the existing
policy-specific deny rules. Path canonicalization, root checks, deny-path
handling, and identity verification occur in the CLI before profile
generation, so platform differences do not turn an approval into a broader
grant.

No platform silently falls back to unrestricted access when a requested
capability cannot be represented. Unsupported or failed operations are denied.

### Library/CLI boundary

No new policy is added to the `nono` library. The CLI owns command discovery,
caller resolution, environment filtering, approval routing, path ceilings,
audit records, and platform policy construction. The library continues to
apply only the capabilities explicitly placed in a `CapabilitySet`, including
the final filesystem and Unix socket grants supplied by the CLI.

### Backward compatibility

Existing explicit command policies retain precedence and existing profiles
without these fields retain their current behavior. The new fields are
optional. Profiles that opt into wildcard mediation or filesystem approval
accept the stricter startup inventory, path identity, and fail-closed rules.

The profile schema and authoring guide must document the new fields and their
security constraints. The wildcard policy's reserved-shim conflict with URL
delegation is a deliberate validation error rather than an implicit precedence
rule.

## Security Considerations

### Least privilege

The design grants only the command, environment variables, paths, and sockets
selected by the resolved caller policy. Wildcard mediation is limited to the
startup inventory and does not grant arbitrary executables or future `PATH`
entries. Filesystem approval is exact and temporary; its roots are ceilings,
not ambient permissions.

### Fail-secure behavior

Malformed requests, missing policy, unavailable approval backends, timeouts,
inventory overflow, command identity changes, path replacement, and
canonicalization failures deny the invocation. No error path converts a
failed approval into a broad directory grant or unrestricted child launch.

The request environment variable is removed before child launch, preventing
chained children from inheriting a capability-proposal channel accidentally.

### Path handling and TOCTOU

All approval roots, requested paths, deny paths, and dynamic socket paths are
validated and canonicalized at the enforcement boundary. Comparisons use path
components rather than string prefixes. Existing approved paths are checked by
device and inode immediately before capability installation to reduce the
time-of-check-to-time-of-use window caused by replacement or symlink changes.

The remaining filesystem race between validation and kernel enforcement is
handled by the OS sandbox and by refusing stale identity matches; the design
does not treat a caller-controlled current working directory as an absolute
approval root.

### Credential and secret secrecy

Environment forwarding is opt-in and pattern-limited. Reserved `NONO_*`
variables and sensitive control channels are excluded, and audit output uses
the existing redaction policy. Profiles should not use `export_env` for secret
material; credentials continue to use the existing credential-provider and
proxy mechanisms.

### Library/CLI boundary

Policy decisions remain in `nono-cli`; `nono` receives only the final explicit
capability set. This prevents the library from acquiring hidden policy or
platform-specific assumptions and keeps the security decision auditable at the
CLI boundary.

## Alternatives Considered

### Require every child command to be listed explicitly

This is simple and maximally visible, but impractical for large toolchains and
does not handle commands selected dynamically by trusted tools. The wildcard
policy retains startup inventory and identity checks while reducing profile
maintenance.

### Grant the caller's whole environment

Rejected because it leaks unrelated variables and can pass control variables,
credentials, or loader settings into a child. `export_env` requires explicit
patterns and keeps the normal environment filter in place.

### Grant a broad writable workspace for dynamic filesystem needs

Rejected because it turns an invocation-specific need into ambient write
authority and makes deny paths difficult to enforce on Landlock. Approval roots
and exact grants preserve a bounded capability ceiling.

### Resolve and hash every wildcard executable at startup

Rejected because it increases startup cost and holds more state than needed.
Lazy resolution keeps startup bounded while retaining identity checks before
execution.

### Ask the library to resolve policy and approvals

Rejected because it would cross the library/CLI boundary and embed policy and
UX decisions in the sandbox primitive. The library should remain policy-free.

## Open Questions

- Should the wildcard policy and URL delegation eventually use distinct shim
  namespaces so both features can be enabled in one profile?
- Should approval backends support user-visible descriptions or risk labels for
  filesystem requests?
- Should the command inventory expose a diagnostic report listing commands
  excluded because of identity or inventory limits?
- Should future platforms expose a common capability for Unix socket grants, or
  should unsupported socket modes remain platform-specific validation errors?
