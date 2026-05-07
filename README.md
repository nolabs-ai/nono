<div align="center">

<img src="assets/logo.gif" alt="nono logo" width="600"/>

<p>
  From the creator of
  <a href="https://sigstore.dev"><strong>Sigstore</strong></a>
  <br/>
  <sub>The standard for secure software attestation, used by PyPI, npm, brew, and Maven Central</sub>
</p>
<p>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/></a>
  <a href="https://github.com/always-further/nono/actions/workflows/ci.yml"><img src="https://github.com/always-further/nono/actions/workflows/ci.yml/badge.svg" alt="CI Status"/></a>
  <a href="https://docs.nono.sh"><img src="https://img.shields.io/badge/Docs-docs.nono.sh-green.svg" alt="Documentation"/></a>
</p>
<p>
  <a href="https://discord.gg/pPcjYzGvbS">
    <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
  </a>
   <a href="https://alwaysfurther.ai/careers">
      <img src="https://img.shields.io/badge/We're_Hiring-Join_the_team-ff4f00?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="We're hiring"/>
  </a>
  <a href="https://github.com/marketplace/actions/agent-sign">
    <img src="https://img.shields.io/badge/Secure_Action-agent--sign-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="agent-sign GitHub Action"/>
  </a>
</p>

---
</div>


<div align="center">

<img src="assets/term.gif" alt="nono terminal demo" width="800"/>

</div>

> [!WARNING]
> Early alpha -- not yet security audited for production use. Active development may cause breakage.


Most sandboxes feel like sandboxes. Rigid, sluggish, and designed for a different problem entirely. nono was built from the ground up for AI agents - and the developer workflows they need to thrive - agent multiplexing, snapshots, credential injection, supply chain security out of the box. Develop alongside nono, then deploy anywhere: CI pipelines, Kubernetes, cloud VMs, microVMs. The one stop shop for all your clankers.

---

## Latest News

- **nono registry** — The nono registry is now in alpha and available to try out. Host your skills, hooks, policies, and more in your own repository, then securely distribute them through the registry. This gives you the ability to run `nono pull org/repo` to pull agent skills and sandbox policies directly into the nono runtime. We are now in the process of migrating profiles out of tree and into their own packages. Check out the registry at: registry.nono.sh

[All updates](https://github.com/always-further/nono/discussions/categories/announcements)

---

**Platform support:** macOS, Linux, and [WSL2](https://nono.sh/docs/cli/internals/wsl2).

**Install:**
```bash
brew install nono
```

Other options in the [Installation Guide](https://docs.nono.sh/cli/getting_started/installation).

---

## Quick Start

Profiles for [Claude Code](https://docs.nono.sh/cli/clients/claude-code), [Codex](https://docs.nono.sh/cli/clients/codex), [OpenCode](https://docs.nono.sh/cli/clients/opencode), [OpenClaw](https://docs.nono.sh/cli/clients/openclaw), and Swival -- or [define your own](https://docs.nono.sh/cli/features/profiles-groups).

## Libraries and Bindings

The core is a Rust library that can be embedded into any application. Policy-free - it applies only what clients explicitly request.

```rust
use nono::{CapabilitySet, Sandbox};

let mut caps = CapabilitySet::new();
caps.allow_read("/data/models")?;
caps.allow_write("/tmp/workspace")?;

Sandbox::apply(&caps)?;  // Irreversible -- kernel-enforced from here on
```

Also available as [Python](https://github.com/always-further/nono-py) , [TypeScript](https://github.com/always-further/nono-ts), [Go](https://github.com/always-further/nono-go)  bindings.

## Key Features

| Feature | Description |
|---------|-------------|
| **Kernel sandbox** | Landlock (Linux) + Seatbelt (macOS). Irreversible, inherited by child processes. |
| **Credential injection** | Proxy mode keeps API keys outside the sandbox entirely. Supports keystore, 1Password, Apple Passwords. |
| **Attestation** | Sigstore-based signing and verification of instruction files (SKILLS.md, CLAUDE.md, etc.). |
| **Network filtering** | Allowlist-based host and endpoint filtering via local proxy. Cloud metadata endpoints hard-denied. |
| **Snapshots** | Content-addressable rollback with SHA-256 dedup and Merkle tree integrity. |
| **Policy profiles** | Pre-built profiles for popular agents and use cases. Custom profile builder for your own needs. |
| **Audit logs** | Default event audit for supervised runs, optional append-only integrity hashing, and optional rollback-backed filesystem evidence. |
| **Cross-platform** | Support for macOS, Linux, and WSL2. Native Windows support in planning. |
| **Multiplexing** | Run multiple agents in parallel with separate sandboxes. Attach/detach to long-running agents. |
| **Runs anywhere** | Local CLI, CI pipelines, Containers / Kubernetes, cloud VMs, microVMs. |

See the [full documentation](https://docs.nono.sh) for details and configuration.

## Contributing

We encourage using AI tools to contribute. However, you must understand and carefully review any AI-generated code before submitting. Security is paramount. If you don't understand how a change works, ask in [Discord](https://discord.gg/pPcjYzGvbS) first.

## Security

If you discover a security vulnerability, please **do not open a public issue**. Follow the process in our [Security Policy](https://github.com/always-further/nono/security).

## License

Apache-2.0
