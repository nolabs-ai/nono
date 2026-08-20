# git-ssh — nono SSH-agent socket brokering demo

A [demonator](https://github.com/nolabs-ai/demonator) walkthrough showing how **nono** brokers
SSH identity for `git` over SSH via a mediated connection to the real **ssh-agent socket**,
instead of a bearer token (`github-cli`, `npm`) or a signed request (`aws-cli`). The sandboxed process
never reads a private key file: it connects to the real, already-running ssh-agent (which may be
backed by a plain on-disk key, 1Password, or a hardware token like a YubiKey) and asks it to sign
the SSH handshake. Read-only git operations (`clone`/`fetch`/`pull`/`ls-remote`) are permitted;
`push` is denied at the argv layer before any network connection is even attempted.

This profile also demonstrates nono's `can_use` mechanism: `git` internally shells out to `ssh` as
its transport helper, and `can_use` + a `commands.ssh.from.git` edge give that child process its
own, differently-scoped sandbox (its own filesystem grants, its own credential access, its own
network policy) rather than inheriting `git`'s.

## Files

| File | What it is |
|------|------------|
| `git-ssh.yaml` | The demonator script (`demonator -c git-ssh.yaml`). |
| `git-ssh-profile-macos.json` | The nono profile for `git`/`ssh` on macOS. Brokers the ssh-agent socket via a `local-socket` credential and enforces an argv `invocation_policy`. |

## What the demo shows

1. **Filesystem gating** — `--allow` grants a path; reads outside the allow-list are blocked by the OS sandbox.
2. **Credential brokering** — nono mediates a `connect()` to `$SSH_AUTH_SOCK`; no private key file is ever granted to the sandbox, so `ls ~/.ssh` inside the sandbox shows nothing.
3. **Reads allowed** — `git clone`/`ls-remote` succeed: a real SSH handshake, signed by the real agent, reaches the real remote.
4. **Mutations denied** — `git push` is blocked by the argv `invocation_policy` before git even opens a connection.
5. **Command chaining** — `git`'s `can_use: ["ssh"]` plus `commands.ssh.from.git` gives the `ssh` subprocess its own scoped sandbox (agent socket access, `known_hosts`/`config` reads, its own network policy) distinct from `git`'s.
6. **Network-layer mediation** — wrapping `git` in `sh -c` does not bypass the policy.
7. **Audit trail** — `nono audit list` / `nono audit show` surface the recorded policy decisions.

## Prerequisites

- **nono** — on `PATH`.
- **git** — installed at `/opt/homebrew/bin/git` (adjust `fs_read`/`executable` if yours differs).
- A running SSH agent (`$SSH_AUTH_SOCK` set) with a key loaded that has read access to the demo
  repository (the script defaults to the public, world-readable `octocat/Hello-World` — no special
  access needed beyond a working GitHub SSH identity: `ssh -T git@github.com` should greet you by
  name).
- **jq** — used throughout to pretty-print policy output.

## Install demonator

```sh
cargo install demonator
```

This puts the `demonator` binary on your `PATH` (`~/.cargo/bin`).

## Run the demo

From this directory:

```sh
demonator -c git-ssh.yaml
```

Press **Enter** to advance each step (the script pauses before every command).
Preview the whole flow without executing anything with `demonator -c git-ssh.yaml --dry-run`.
