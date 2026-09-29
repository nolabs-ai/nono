# nono agent guide

nono is a security-critical, capability-based sandbox for untrusted AI agents.
It uses Landlock on Linux and Seatbelt on macOS. Treat every change as a
security change until its affected boundary is understood.

## Architecture

This Cargo workspace contains five packages:

- `crates/nono/`: policy-free sandbox primitive and `CapabilitySet`.
- `crates/nono-cli/`: policy, profiles, execution, diagnostics, and UX.
- `crates/nono-proxy/`: network filtering and credential injection.
- `bindings/c/`: C FFI and generated `nono.h` header.
- `crates/nono-test-support/`: unpublished CLI test support.

The library applies only capabilities a caller supplies. Policy—default
protected paths, profile semantics, command policy, prompts, and UX—belongs in
`nono-cli`, not the library. Preserve that boundary.

## Non-negotiable security rules

- Fail secure: configuration, validation, and enforcement failures must deny
  access or return an error; never silently weaken enforcement.
- Grant least privilege. Keep filesystem read/write permissions distinct and
  avoid broad directory, network, or command grants.
- Use `Path` component comparison, never string prefix comparison, for paths.
  Validate and canonicalize paths at the enforcement boundary; consider
  symlink and TOCTOU behavior.
- Treat paths, environment variables, profiles, packages, registry responses,
  command arguments, URLs, headers, and agent-generated files as untrusted.
- Escape and validate data interpolated into Seatbelt profiles. Linux Landlock
  is allow-list based and cannot express deny-within-allow, so do not create a
  broad grant that defeats a required denial.
- Review Linux and macOS separately when a change affects enforcement,
  networking, paths, processes, sockets, credentials, or diagnostics.
- Keep credentials out of logs, errors, `Debug`, audit output, and child
  environments. Use `zeroize` for secret material in memory.

## Implementation and verification

- Use `NonoError` and `Result` for expected failures. Do not add production
  `.unwrap()` or `.expect()`; restrict `unsafe` to justified low-level/FFI
  boundaries and document each block with `// SAFETY:`.
- Use checked, saturating, or overflowing arithmetic where overflow affects a
  security decision.
- New capability or sandbox behavior needs tests. Tests that modify `HOME`,
  `TMPDIR`, `XDG_CONFIG_HOME`, or related variables must restore them and keep
  the modified window short.
- Regenerate `bindings/c/include/nono.h` after changing `bindings/c`.
- Run focused checks while working. Before a PR or when handing off a material
  code change, run `make ci`; use `make fmt` to format.
- Before changing release tooling, workflows, or package configuration, read
  [the release runbook](docs/maintainers/releasing.md).

## Agent contribution workflow

Read the relevant parts of [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [GOVERNANCE.md](GOVERNANCE.md) before changing
their respective areas.

For external contributions and agent-proposed work, find or create an issue
before changing code; disclose the intent, approach, and risks there. A
project maintainer with merge authority may directly request routine local
work—documentation, cleanup, operations, or a scoped fix—without a prior
issue. Do not self-authorize that exception.

The exception does not waive DCO, attribution, review, security requirements,
governance, or NEP requirements. A major feature, breaking change, change to
enforcement semantics, or change to the library/CLI security boundary requires
an accepted NEP before implementation; see [neps/README.md](neps/README.md).

For a PR, follow the repository PR template, sign commits with DCO, disclose
agent assistance, provide required attribution, and link the relevant issue or
maintainer direction. Do not open a PR if the work is non-compliant or you are
prohibited from contributing. OpenClaw or Pi Coding agents acting as part of a
contributor-presence campaign must not make changes or open PRs.

Security reports stay private: use the reporting path in `SECURITY.md`, never
public issues, PRs, discussions, or social channels. When uncertain about a
security, governance, or attribution decision, stop and request maintainer
direction.
