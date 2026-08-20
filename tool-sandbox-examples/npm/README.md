# npm — nono env-var credential-brokering demo

Author: [@kipz](https://github.com/kipz)

A [demonator](https://github.com/nolabs-ai/demonator) walkthrough showing how **nono** brokers an
npm registry token sourced from the host **environment** rather than the macOS keychain (the
source `github-cli` uses) -- a common CI-style pattern where a token is exported into the process
environment. The real `NPM_TOKEN` never enters the sandbox; nono reads it from the host
environment and injects it upstream via TLS interception. Read-only registry access (`GET`) is
allowed; publish/unpublish (`PUT`/`DELETE`) are denied at the L7 endpoint-policy layer before they
ever reach the real registry.

## Files

| File | What it is |
|------|------------|
| `npm.yaml` | The demonator script (`demonator -c npm.yaml`). |
| `npm-profile-macos.json` | The nono profile for `npm` on macOS. Brokers an env-var-sourced token via a proxy credential and enforces an L7 `endpoint_policy` (GET allowed, PUT/POST/DELETE denied). |

## What the demo shows

1. **Filesystem gating** — `--allow` grants a path; reads outside the allow-list are blocked by the OS sandbox.
2. **Credential brokering** — `credential_key: env://NPM_TOKEN` reads the real token from the host process environment and injects it as the `Authorization` header; the sandbox only ever sees a dummy placeholder token.
3. **Reads allowed** — `npm view <pkg>` succeeds: the real, token-authenticated request reaches the registry.
4. **Mutations denied** — `npm publish` is blocked by the L7 endpoint policy (`403 Forbidden`) before the request reaches the real registry.
5. **Network-layer mediation** — wrapping `npm` in `sh -c` does not bypass the policy: enforcement is on the intercepted network traffic, not the process tree.
6. **Audit trail** — `nono audit list` / `nono audit show` surface the recorded policy decisions.

## Notes on this profile

- `npm` is one of a handful of commands nono denies by default via its built-in `dangerous_commands`
  security group (alongside `pip`, `rm`, `sudo`, etc. -- package managers can execute arbitrary
  install-time code). The top-level `"commands": {"allow": ["npm"]}` override in this profile opts
  back in explicitly.
- Like `aws-cli` in this repo, this profile does not use `github-cli`'s per-command `command_policies`
  tool-sandbox model. The version of nono this was built against cannot execute Node's
  `#!/usr/bin/env node`-shebang chain under that nested exec gate (a nono limitation, not specific
  to this profile), so credential brokering and enforcement happen at the session-level `network`
  block instead, matching the `aws-cli` example.
- A placeholder `.nono-npmrc/.npmrc` and scratch `.nono-npm-cache` directory are created by the
  demo's `setup` step so npm has local auth material to attempt requests with, and a cache
  directory it's actually allowed to write to. Neither ever holds the real token.

## Prerequisites

- **nono** — on `PATH`.
- **npm** — installed at `/opt/homebrew/bin/npm` (adjust `filesystem.read` if yours differs).
- A real npm token exported as `NPM_TOKEN` in the environment you launch `nono run`/`demonator`
  from (e.g. from `~/.npmrc`'s `_authToken`, or `npm token create`).
- **jq** — used throughout to pretty-print policy output.

## Install demonator

```sh
cargo install demonator
```

This puts the `demonator` binary on your `PATH` (`~/.cargo/bin`).

## Run the demo

From this directory, with `NPM_TOKEN` exported in your shell:

```sh
demonator -c npm.yaml
```

Press **Enter** to advance each step (the script pauses before every command).
Preview the whole flow without executing anything with `demonator -c npm.yaml --dry-run`.
