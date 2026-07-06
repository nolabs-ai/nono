# Contributing to nono

nono is a capability-based sandboxing system for running untrusted AI agents
with OS-enforced isolation. Contributions are welcome from anyone who
understands what they are submitting.

If anything here is unclear, ask in [Discord](https://discord.gg/3v2DduCsd)
before writing code. A five-minute conversation saves a rejected PR.

---

## Before You Write Code

For anything beyond a typo fix, open an issue first or find an existing one.
PRs without a linked issue will not be reviewed.

This is especially true for changes that touch the Landlock enforcement path,
the sandbox policy model, or the credential proxy. Those areas have security
constraints that are not obvious from reading the code.

For scoped, well-defined starting points, see the
[good-first-issue](https://github.com/nolabs-ai/nono/issues?q=is%3Aopen+label%3A%22good+first+issue%22)
label.

---

## Read CLAUDE.md First

Before touching any code, read [CLAUDE.md](./CLAUDE.md). It is the
authoritative source for this project's coding standards, security
requirements, error handling conventions, and platform-specific constraints.
The PR checklist references it directly.

A few things from CLAUDE.md that affect every contribution:

**Error handling.** Use `NonoError` for all errors. Propagate with `?`.
Never use `.unwrap()` or `.expect()`. This is enforced by Clippy and will
block merge.

**Path handling.** Validate and canonicalize all paths before applying
capabilities. Use `Path::starts_with()` for path comparisons, not string
`starts_with()`. String comparison on paths is a security vulnerability:
`"/home".starts_with("/home")` also matches `"/homeevil"`.

**Unsafe code.** Restrict to FFI. Every `unsafe` block requires a
`// SAFETY:` comment explaining why it is sound.

**Tests.** Write unit tests for all new capability types and sandbox logic.
If you modify environment variables in tests, save and restore the original
value. Rust runs unit tests in parallel; an unrestored env var causes flaky
failures in unrelated tests.

**Security posture.** On any error, deny access. Never silently degrade to
a less secure state. No escape hatch: once a sandbox is applied, there is no
API to expand permissions.

---

## Development Setup

**Requirements:**
- Rust 1.95 or later (`rustup update stable`)
- Linux for Landlock-dependent paths (WSL2 works)
- macOS for Seatbelt-dependent paths
- `make` (standard on Linux and macOS)

**Clone and build:**

```bash
git clone https://github.com/nolabs-ai/nono.git
cd nono
make build
```

`make build` builds the core library and CLI. It is the right starting point
for most contributors.

**Run tests:**

```bash
make test
```

**Run the full CI check locally:**

```bash
make ci
```

Run `make ci` before opening a PR. It runs Clippy, format check, all tests,
and a dependency audit in one command. A PR that fails `make ci` will not be
merged.

**Individual commands if you need them:**

```bash
make clippy       # Lint check (strict: -D warnings -D clippy::unwrap_used)
make fmt-check    # Format check
make fmt          # Auto-format (run this, then commit the result)
make audit        # Dependency audit
make test-lib     # Library tests only
make test-cli     # CLI tests only
```

**Workspace structure:**

```
crates/nono          Core library. Pure sandbox primitive, no built-in policy.
crates/nono-cli      CLI binary. Owns all security policy, profiles, and UX.
crates/nono-proxy    Proxy for network filtering and credential injection.
bindings/c           C FFI bindings (package name: nono-ffi).
```

The library/CLI boundary matters: the library applies only what clients
explicitly add to `CapabilitySet`. All policy lives in the CLI. Do not add
policy to the library.

**If you change `bindings/c`**, regenerate the FFI header after your changes:

```bash
cargo build -p nono-ffi
```

Commit the updated `bindings/c/include/nono.h` alongside your code change.
CI verifies the header is up to date and fails with an explicit error if it
is not.

---

## Commit Messages

This project uses [conventional commits](https://www.conventionalcommits.org/).
Commit messages must follow this format:

```
<type>(<optional scope>): <short description>
```

Valid types: `feat`, `fix`, `docs`, `perf`, `refactor`, `test`, `ci`,
`build`, `chore`.

Examples:

```
feat(proxy): add credential injection for GitHub token
fix(sandbox): canonicalize paths before applying capabilities
docs(contributing): add conventional commit format
```

The changelog is auto-generated from commit messages at release time.
Use the right type. A `fix` that is labeled `chore` will not appear in the
release notes under Bug Fixes.

---

## Contribution Process

**1. Open or find an issue.**

Every PR must reference an existing issue. Open one before writing code.
PRs without a linked issue will not be reviewed.

**2. Fork the repo and create a branch.**

```bash
git checkout -b type/short-description
```

Match the branch name to your commit type. `fix/proxy-rotation` is good.
`patch-1` is not.

**3. Write the code.**

Follow [CLAUDE.md](./CLAUDE.md) for all coding standards. Key requirements
repeated here for visibility:

- Use `NonoError` for all errors. Propagate with `?`.
- No `.unwrap()` or `.expect()`. Clippy will catch this and fail CI.
- Use `Path::starts_with()` for path comparisons, not string `starts_with()`.
- `unsafe` blocks require `// SAFETY:` comments.
- New functionality needs unit tests.
- New public API needs doc comments.
- Do not add policy to the library. Policy belongs in the CLI.

**4. Sign off your commits (DCO).**

nono uses the Developer Certificate of Origin. Every commit must include a
`Signed-off-by` line with your name and email.

The simplest way:

```bash
git commit -s -m "fix(proxy): your commit message here"
```

The `-s` flag adds the signoff automatically.

If you forgot to sign off on commits already made:

```bash
git commit --amend --signoff --no-edit
git push --force-with-lease
```

DCO signoff is verified by the PR checklist. A PR without signed commits
will be asked to amend before review begins.

**5. Open a pull request against `main`.**

The PR template will prompt you for:
- A linked issue (`Closes #NNN`)
- A summary of what the PR does and why
- A test plan describing how you verified the change
- A checklist including DCO signoff confirmation

Fill these in honestly. A PR description that says "integration tests are
missing, here is why and what the plan is" moves faster than one that
pretends coverage is complete.

If your PR was generated or assisted by an AI tool, complete the Agent
Disclosure and Agent Compliance Check sections in the PR template.
See [CLAUDE.md](./CLAUDE.md) for the full agent contribution policy,
including hard stop conditions that prohibit certain automated contributions.

**6. Review.**

The maintainer council reviews PRs. See [MAINTAINERS.md](./MAINTAINERS.md)
for the current list. First response within 5 business days. If that window
passes with no response, ping in [Discord](https://discord.gg/3v2DduCsd)
with a link to the PR.

---

## Scope: What nono Does and Does Not Do

nono applies OS-enforced capability restrictions to sandbox AI agents and
the tools they call. Once a sandbox is applied, there is no API to expand
permissions. The policy lives in the profile, not in the prompt.

nono is in alpha. Security guarantees are not yet stable. A third-party
security audit is planned prior to v1.0. Do not overstate what the current
implementation guarantees.

---

## Role Progression

Sustained contributors can move from Contributor to Reviewer to Maintainer.
The criteria, nomination process, and expectations for each role are in
[GOVERNANCE.md](./GOVERNANCE.md).

---

## Security Vulnerabilities

Do not open public issues for security vulnerabilities.

Report privately via GitHub Security Advisories:
https://github.com/nolabs-ai/nono/security/advisories/new

See [SECURITY.md](./SECURITY.md) for the full disclosure policy, including
guidance on LLM-generated findings.

---

## Maintainers

See [MAINTAINERS.md](./MAINTAINERS.md) for the current maintainer council
and contact information.

---

## License

By contributing, you agree your contributions are licensed under
[Apache-2.0](./LICENSE).
