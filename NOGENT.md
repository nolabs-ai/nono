# nono Code Review Guide

Use this file as the baseline for reviewing changes to nono. nono is a
security-critical sandbox for running untrusted AI agents and tools. Reviews
must prioritize whether the change preserves isolation, least privilege,
credential secrecy, auditability, and fail-closed behavior.

If a change weakens a security boundary, requires a new trust assumption, or
changes a default, call that out explicitly.

## Review Stance

- Start from the assumption that the sandboxed child is malicious.
- Treat profiles, packages, registry responses, environment variables, paths,
  command arguments, URLs, headers, and agent-generated files as untrusted input.
- Prefer a clear deny over a surprising allow. Compatibility cannot silently
  downgrade enforcement.
- Findings should lead the review. Explain the exploit or failure mode, the
  affected boundary, and the concrete fix.
- For suspected vulnerabilities within the existing code, follow `SECURITY.md`:
  do not open a public issue or public disclosure until the issue is validated
  and reported through GitHub Security Advisories.

## Workspace Map

The workspace currently contains these crates:

- `crates/nono`: Core library. It is the policy-free sandbox primitive:
  capability model, path canonicalization, Landlock and Seatbelt application,
  diagnostics, keystore helpers, host filtering, trust and attestation types,
  rollback object storage, and supervisor protocol types. It should apply only
  capabilities explicitly supplied by the caller.
- `crates/nono-cli`: CLI, profile, policy, and runtime layer. It owns user
  policy, embedded profiles, policy group resolution, protected path handling,
  execution strategy selection, environment preparation, proxy runtime wiring,
  credential loading, audit, rollback, trust commands, package and registry
  workflows, and ephemeral tool isolation.
- `crates/nono-proxy`: Network proxy used by the supervisor. It runs outside
  the child sandbox and exposes controlled loopback access to the sandboxed
  child. It implements CONNECT host filtering, reverse proxy credential
  injection, external proxy chaining, TLS interception for L7 policy,
  endpoint filtering, OAuth2, optional SPIFFE support, diagnostics, and audit.
- `bindings/c`: `nono-ffi`, the C ABI wrapper around the core library. Review
  it for pointer validity, ownership, allocation and free symmetry, error
  propagation, and ABI stability.

Important boundary: the library must not grow CLI policy. If a change adds
default protected paths, profile semantics, command policy, user prompts, or
UX-driven fallbacks and error messages, it belongs in `nono-cli`, not `crates/nono`.

## Core Security Requirements

### Fail Closed

- Security configuration load failures must be fatal unless the feature is
  explicitly optional and the disabled state is safer.
- Missing credential material for a managed credential route must not allow the
  sandboxed child to provide its own real upstream credential.
- TLS interception requested for L7 enforcement must not fall back to an opaque
  CONNECT tunnel when interception fails.
- Unsupported platform features must return explicit errors or diagnostics, not
  silently degrade to a weaker mode.
- Avoid `Option` for operations that can fail. `None` is acceptable for true
  absence, but parsing, validation, I/O, policy lookup, crypto verification,
  and sandbox setup failures should return `Result` or `Result<Option<T>>`.

### Least Privilege

- Grant the smallest filesystem and network scope needed.
- Keep read, write, readwrite, connect, and bind permissions distinct.
- Do not widen system path grants to make a tool work unless the exact need is
  understood and tested.
- Do not let child-controlled config expand parent or supervisor privileges.
- Proxy mode should expose only loopback access to the sandboxed child; the
  proxy performs external network access on behalf of the child after policy
  checks.

### Explicit Policy

- Security-relevant behavior must be visible in profile, policy, CLI flag,
  manifest, or audit output.
- When adding a CLI flag, also add the matching profile-based policy surface
  when relevant. Check `crates/nono-cli/src/policy.rs`,
  `crates/nono-cli/data/profile-authoring-guide.md`, and
  `docs/cli/usage/flags.mdx` so runtime behavior, profile authoring guidance,
  and CLI documentation stay aligned.
- Consider whether security or capability changes require an update to
  `crates/nono/schema/capability-manifest.schema.json`.
- Backward-compatible aliases are allowed only when they preserve the same
  effective policy. Keep the `/// ALIAS(...)` convention for serde and clap
  aliases.
- Do not introduce "helpful" defaults that read secrets, trust files, allow
  domains, or grant parent directories.
- User prompts are policy decisions. Review timeout defaults, unattended
  behavior, and whether denial remains the default on no response.

### Auditability

- Denials, approvals, credential route failures, proxy filter decisions, trust
  verification failures, and rollback operations should be diagnosable.
- Audit and diagnostic logs must never contain real credentials, private keys,
  bearer tokens, OAuth tokens, or unredacted secret-bearing URLs.
- Redaction must happen before formatting values for logs, errors, `Debug`, and
  audit events.

## Feature Review Checklist

### OS Sandboxing

Review files under `crates/nono/src/sandbox`, `crates/nono/src/capability.rs`,
`crates/nono/src/path.rs`, `crates/nono-cli/src/sandbox_prepare.rs`, and
`crates/nono-cli/src/capability_ext.rs`.

- Linux Landlock and macOS Seatbelt have different capabilities. Do not assume
  deny-within-allow, symlink handling, networking, unlink controls, signals, or
  Unix sockets behave the same on both platforms.
- Landlock is allow-list oriented. Broad allows can make deny paths impossible
  to express safely.
- Seatbelt profiles are generated strings. Any interpolated path or rule must
  be escaped and structurally valid.
- Applying the sandbox is irreversible. Setup and support probes must happen in
  a child process or before enforcement.
- Review whether new capabilities are included in `nono why`, dry-run output,
  diagnostics, manifests, and tests.

### Path Handling

- Use `Path` and path component comparisons, not string prefix checks.
  `Path::starts_with` is different from `str::starts_with`.
- Canonicalize at the enforcement boundary. Understand the symlink and TOCTOU
  implications of any path that is resolved and later used.
- Validate `HOME`, `TMPDIR`, `XDG_*`, profile paths, package paths, and workdir
  values. Environment variables are attacker-controlled input.
- macOS path aliases and symlinks matter. For example, `/etc` and
  `/private/etc` may both need consideration.
- Missing exact file grants are security-sensitive. Review whether retaining a
  missing path is intentional and whether later file creation changes the
  grant.

### Tool Sandboxing

Review `crates/nono-cli/src/tool-sandbox`, `command_policy.rs`,
`terminal_approval.rs`, and related profile schema code.

- Command policy must prevent direct execution bypasses, PATH shadowing, and
  writable executable substitution.
- Resolved command identity should consider canonical path, device, inode,
  size, mtime, and digest where available.
- Invocation policy should validate argv and environment as untrusted bytes.
  Non-UTF-8 input must not bypass policy.
- Deny rules should be evaluated before approve and allow rules unless the
  policy explicitly documents a different precedence.
- Approval defaults and backend routing must deny on timeout, backend failure,
  malformed request, and missing backend.
- Command-scoped credentials must stay in the supervisor or proxy path. The
  child should see phantom tokens or scoped environment only when that is the
  intended contract.
- URL-open and token broker sockets are authority-bearing interfaces. Review
  socket path permissions, lifetime, caller identity, and audit records.

### L7 Filtering and Proxying

Review `crates/nono-proxy/src/filter.rs`, `connect.rs`, `reverse.rs`,
`route.rs`, `server.rs`, `external.rs`, `tls_intercept`, and
`crates/nono-cli/src/proxy_runtime.rs`.

- Cloud metadata hosts and link-local IPs are a non-overridable deny floor.
- DNS must be resolved once, checked, and then the checked socket addresses
  must be used for the connection to avoid DNS rebinding.
- Empty allowlists are dangerous. Review whether `strict_filter` should make
  empty mean deny-all for the call path being changed.
- Wildcards should match subdomains only as intended. `*.example.com` should
  not accidentally match `example.com` or `evil-example.com`.
- Endpoint rules and endpoint policies are default-deny when configured.
  Review HTTP method normalization, path normalization, percent encoding,
  query handling, and HTTP/2 stream behavior.
- TLS interception is selective. Only routes needing L7 visibility should be
  intercepted; other CONNECT traffic should remain opaque but still host
  filtered.
- If cert pinning or trust failure prevents interception for an L7 route, the
  request must fail and be audited.
- External proxy passthrough must still enforce nono's deny floor before
  chaining to the enterprise proxy.

### Credential Injection

Review `crates/nono/src/keystore.rs`, `crates/nono-cli/src/credential_runtime.rs`,
`crates/nono-cli/src/tool-sandbox/credentials.rs`, and
`crates/nono-proxy/src/credential.rs`.

- Real credentials should live in `Zeroizing` types where possible and should
  not appear in logs, errors, `Debug`, audit events, panic messages, temp
  files, or child-visible process args.
- Prefer proxy credential injection over environment variables for network API
  keys. Environment credentials are broader and should be reviewed as a larger
  exposure.
- Validate credential reference URI schemes and destination environment names.
- Header, query parameter, URL path, Basic Auth, OAuth2, and command-backed
  credential modes each need tests for redaction and fail-closed behavior.
- Phantom tokens must not be accepted as real credentials upstream. They are
  markers used to prove the child is using the managed proxy path.
- Command-backed credential capture needs timeouts, bounded output, stderr
  handling, and redaction.
- Persistent proxy CA material, especially macOS `--trust-proxy-ca`, is highly
  sensitive because compromise can mint trusted certs during the validity
  window. Review validity limits, Keychain access assumptions, and zeroization.

### Supply Chain Security

Review `crates/nono/src/trust`, `crates/nono-cli/src/trust_*`,
`package*.rs`, `registry_client.rs`, and embedded policy/profile data.

- Trust policy merges must be additive or stricter. A lower-precedence policy
  must not weaken enforcement, remove blocklist entries, or replace trusted
  publisher constraints.
- Sigstore bundle verification must check the cryptographic signature, trusted
  root, subject name, predicate type, signer identity, and file digest.
- Keyless publisher matching must require issuer, repository, workflow or build
  signer URI, and ref constraints. Empty certificate identity fields must not
  match wildcard publishers.
- Keyed bundle verification requires the configured public key material, not
  only a key ID string.
- Blocklists must win over otherwise trusted signatures.
- Resource bounds on trust policies, includes, files, publishers, and bundles
  are security controls. Do not remove them without replacement.
- Registry and package install paths must prevent traversal, overwrite of
  protected files, unsigned downgrade, and version rollback where tracked.
- Package install/update/pin behavior must preserve the user's trust decisions
  and make verification failures actionable.
- If a change adds unique OS-specific or distribution-specific paths to
  `crates/nono-cli/data/policy.json` or
  `crates/nono-cli/data/network-policy.json`, ask whether a nono package would
  be a better fit. The project is trying to reduce customized in-tree policy
  logic over time.

### Rollback and Audit

Review `crates/nono/src/undo`, `crates/nono-cli/src/rollback_*`,
`audit_*`, `session*`, and `sandbox_log.rs`.

- Rollback snapshots must not capture secrets or unbounded data by accident.
- Object store integrity checks and hash mismatches must fail loudly.
- Restore operations need dry-run accuracy, path validation, and protection
  against restoring outside the intended root.
- Exclusion filters are security policy. Review default exclusions, glob
  interpretation, symlink behavior, and whether exclusions are audited.
- Audit ledgers should be append-only in spirit. Review tampering, truncation,
  ordering, and integrity checks when changed.

### FFI

Review all files under `bindings/c`.

- Every raw pointer must be checked before dereference.
- Document each `unsafe` block with a `// SAFETY:` comment explaining the
  caller contract and why the operation is valid.
- C-callable functions must not unwind across the FFI boundary.
- Ownership must be explicit: who allocates, who frees, and which function
  frees returned buffers.
- Convert Rust errors to stable C error values or messages without leaking
  secrets or dangling pointers.
- Keep generated `include/nono.h` in sync with ABI changes.

## Rust Coding Guidelines

- Do not use `.unwrap()` or `.expect()` in production code. The workspace
  denies `clippy::unwrap_used`; tests may use explicit local allows only when
  the panic improves test clarity and cannot mask production behavior.
- Avoid `panic!`, `todo!`, and `unreachable!` in library and security paths.
  If an invariant can be violated by input, return an error.
- Do not return `None` for malformed security input, denied policy, missing
  required configuration, or failed validation. Silent failure is a security
  bug.
- Do not use `unwrap_or_default`, `.ok()`, `Option` `?`, `map_or`, or broad
  fallbacks on security configuration when the fallback hides malformed input
  or missing policy.
- Use `NonoError` for core and CLI-facing errors, and `ProxyError` in
  `nono-proxy`. Preserve the source error where it helps diagnosis.
- Prefer typed parsers and structured validation over ad hoc string splitting.
- Mark security-significant query and builder methods `#[must_use]` when
  ignoring the return value could skip enforcement.
- Use checked or saturating arithmetic for limits, budgets, lengths, counters,
  offsets, timeouts, and sizes that affect security or resource usage.
- Keep `Debug` implementations for secret-bearing types redacted.
- Avoid `#[allow(dead_code)]`. Remove unused code or add meaningful tests.
- Keep comments focused on invariants, platform differences, and non-obvious
  security reasoning.

## Testing Expectations

Run the smallest useful set locally, then broaden for risky changes.

```bash
make build
make test
make check
make audit
make lint-aliases
make lint-docs
```

For a full local CI pass:

```bash
make ci
```

Targeted commands:

```bash
make test-lib
make test-cli
make test-ffi
cargo test -p nono-proxy
cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::unwrap_used
cargo fmt --all -- --check
```

Security-sensitive changes should include regression tests for denial paths,
malformed input, platform-specific behavior where practical, and audit or
diagnostic output. Tests that mutate `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`,
`XDG_STATE_HOME`, `PATH`, proxy environment variables, or credential-related
environment variables must restore the original values. Rust unit tests run in
parallel in the same process.

## Review Questions

When reviewing a change, consider these:

- What new authority does this grant to the sandboxed child, supervisor, proxy,
  profile, package, or registry?
- What happens when parsing, profile loading, DNS, credential loading, trust
  verification, approval, proxy startup, or sandbox application fails?
- Can an attacker turn malformed input into allow-all, empty policy, skipped
  validation, or missing audit?
- Does this behave securely on both Linux and macOS? If not, is the unsupported
  path explicit and tested?
- Are secrets redacted at every formatting boundary?
- Are paths canonicalized or compared using path semantics?
- Are network decisions made before connecting, and are checked DNS results
  actually used?
- Can package, profile, trust, or rollback data escape its intended directory?
- Do diagnostics help users fix the issue without revealing sensitive data?

If any answer is unclear, request changes.
