# aws-cli — nono AWS SigV4 credential-brokering demo

A [demonator](https://github.com/nolabs-ai/demonator) walkthrough showing how **nono** brokers
AWS credentials for the `aws` CLI without a bearer token or credential file ever touching the
sandbox: nono resolves your real AWS credentials on the host (via the standard profile/default
credential chain) and re-signs each outbound S3 request with SigV4 itself. The sandboxed process
only ever sees dummy placeholder credentials. Read-only S3 access (`GET`/`HEAD`) is allowed;
mutating operations (`PUT`/`POST`/`DELETE`) are denied at the L7 endpoint-policy layer before they
ever reach AWS.

This is a different nono mechanism from the [`github-cli`](../github-cli/) demo: `gh`'s token is proxied via
a per-command `command_policies` credential route, whereas `aws_auth` SigV4 signing is a
session-level `network.custom_credentials` route. The profile in this directory only uses the
network-level model — see [Known limitation](#known-limitation) below for why.

## Files

| File | What it is |
|------|------------|
| `aws-cli.yaml` | The demonator script (`demonator -c aws-cli.yaml`). |
| `aws-cli-profile-macos.json` | The nono profile for `aws` on macOS. Enables TLS interception, brokers AWS credentials via `aws_auth` SigV4 signing, and enforces an L7 `endpoint_policy` (GET/HEAD allowed, PUT/POST/DELETE denied). |

## What the demo shows

1. **Filesystem gating** — `--allow` grants a path; reads outside the allow-list are blocked by the OS sandbox.
2. **Credential brokering** — `aws_auth` resolves your real AWS credentials host-side (profile/default credential chain) and signs each request itself. The sandbox only ever sees `AWS_ACCESS_KEY_ID=dummy-access-key`.
3. **Reads allowed** — `aws s3 ls` / `aws s3 cp <remote> -` succeed: the real, signed request reaches S3.
4. **Mutations denied** — `aws s3 cp <local> <remote>` and `aws s3 rm` are blocked by the L7 endpoint policy (`403 Forbidden`) before the request reaches AWS.
5. **Network-layer mediation** — wrapping `aws` in `sh -c` does not bypass the policy: enforcement is on the intercepted network traffic, not the process tree.
6. **Audit trail** — `nono audit list` / `nono audit show` surface the recorded policy decisions.

## Known limitation

`aws_auth` SigV4 signing is currently only wired into nono's **TLS-interception** path (matching
the real AWS hostname), not the per-command `command_policies` tool-sandbox model that `github-cli`
uses — so this profile has no per-subcommand `invocation_policy` (argv) layer the way `github-cli` does
for `gh`. Separately, the per-command tool-sandbox exec gate on macOS does not currently grant exec
of a shebang-script interpreter chain (as used by the Python-based `aws` CLI) even when the
interpreter path is explicitly declared via `fs_read`/`fs_read_file` — only the top-level session
sandbox handles this automatically. Both are nono limitations, not profile bugs; the L7
endpoint-policy layer alone still fully enforces the read-only boundary demonstrated here.

## Prerequisites

- **nono** — on `PATH`.
- **aws** (AWS CLI v2) — installed at `/opt/homebrew/bin/aws` (the profile pins this path and
  awscli version `2.36.7`; adjust `filesystem.read`/`read_file` if yours differs).
- An AWS credential profile resolvable via the standard chain (`~/.aws/credentials` /
  `~/.aws/config`, SSO, or environment variables) — edit `aws_auth.profile` in the profile JSON, or
  omit it to use your default credentials.
- An S3 bucket you control, with at least one object in it. Edit both `upstream` hosts (`s3-regional`
  and `s3-global`) and the `AWS_DEFAULT_REGION` in the profile JSON to match your bucket/region.
- **jq** — used throughout to pretty-print policy output.

## Install demonator

```sh
cargo install demonator
```

This puts the `demonator` binary on your `PATH` (`~/.cargo/bin`).

## Run the demo

From this directory, after editing the bucket/region/profile fields in
`aws-cli-profile-macos.json`:

```sh
demonator -c aws-cli.yaml
```

Press **Enter** to advance each step (the script pauses before every command).
Preview the whole flow without executing anything with `demonator -c aws-cli.yaml --dry-run`.
