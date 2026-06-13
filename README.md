<div align="center">

<img src="assets/logo.gif" alt="nono logo" width="600"/>

<p>
  Built by the team that brought you
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

> [!NOTE]
> In the lead-up to a 1.0 release, APIs are stabilizing. API changes may still occur where necessary, but will be kept to a minimum.

**Run AI agents in a zero latency sandbox in seconds and with zero setup** — *Claude Code, Codex, Pi, CoPilot, Hermes, OpenCode, OpenClaw* and more — nono gets you up and running within seconds, with no daemon, no container, no VM, and no disk space usage. Out of the box, nono enforces a least-privilege sandbox and supports macOS, Linux, and Windows (WSL2).

From here **fork the config**, tweak it, theme it, make it your own, and share it with your team or the community via the [nono registry](https://registry.nono.sh).

**Want to operationalise and run at scale or within your team?** Engineers at some of the largest tech companies in the world use nono as part of their workflows or to run AI agents in production.

**Copied by many** — nono pioneered the zero-latency, zero-setup agent sandbox, and continues to innovate and lead the way in agent sandboxing.

---

## Quickstart

#### macOS / Linux (Homebrew)
```bash
brew install nono
```

**Other platforms** — Debian/Ubuntu, Fedora, Arch, RHEL, openSUSE, WSL2, and Nix: [see install instructions](https://docs.nono.sh/docs/installation).

## Run it!

Search for an agent in the registry, then run it:

```bash
$ nono search opencode
always-further/opencode	-	Official Always Further Opencode Plugin

$ nono run --profile always-further/opencode -- opencode
```

That's it. `opencode` now runs with read/write access to the current directory and **nothing else** — your SSH keys, your cloud credentials, the rest of your disk are invisible to it.

Profiles for all the popular agents live at [registry.nono.sh](https://registry.nono.sh), secured and ready to pull. Each one bundles the right filesystem scope, network allowlist, hooks, skills and more.

## Make it your own!

Outgrow the defaults? Scaffold a profile and tweak it — same command you already know:

```bash
nono profile init opencode --extends always-further/opencode
nono run --profile opencode -- opencode
```

Are you an agent developer and want to publish your own agent package? We would love to have you and promote your work! [See the docs](https://nono.sh/docs/cli/features/package-publishing).

## Ready to go deep?

Head over to the [docs](https://nono.sh/docs) and discover nono's rich composable policy system, credentials injection, L7 filtering, supply chain security, rollback, multiplexing, audit and more.

## Library support

nono provides FFI bindings for Rust, Python, TypeScript, and Go.

Also available as [Python](https://github.com/always-further/nono-py), [TypeScript](https://github.com/always-further/nono-ts), and [Go](https://github.com/always-further/nono-go) bindings.

## Contributing

We encourage using AI tools to contribute. However, you must understand and carefully review any AI-generated code before submitting. Security is paramount. If you don't understand how a change works, ask in [Discord](https://discord.gg/pPcjYzGvbS) first.

## Security

If you discover a security vulnerability, please **do not open a public issue**. Follow the process in our [Security Policy](https://github.com/always-further/nono/security).

## License

Apache-2.0
