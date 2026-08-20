# GitHub CLI Tool-Sandbox Demo

This demo runs `gh` through nono command policy and a brokered GitHub API
credential. The sandboxed `gh` process receives a nono phantom `GH_TOKEN`; the
nono proxy validates that token, strips it, and injects the real GitHub
credential upstream to `https://api.github.com`.

## What This Shows

- `gh issue view` and `gh issue list` are allowed.
- `gh api` reads are allowed only when the L7 endpoint policy allows the API
  path.
- selected command and endpoint operations can require local approval.
- issue comments, issue creation, issue closure, release upload, and destructive
  API calls are denied.
- wrapped attempts such as `sh -c 'gh issue comment ...'` are denied because
  the command policy controls child tool execution, not only the top-level
  command line.
- `gh auth token` returns a nono phantom token, not the real GitHub token.

## Credential Model

GitHub CLI normally stores auth in the OS credential store and records account
metadata in `~/.config/gh/hosts.yml`. In this demo, nono should load the real
token before the sandbox is applied, while the sandboxed `gh` process only sees
a phantom token.

For a desktop Linux or macOS setup, prefer the same system keyring entry that
`gh` already uses:

```text
keyring://gh:github.com/<github-login>?decode=go-keyring
```

The `decode=go-keyring` suffix is required because `gh` is a Go tool and stores
the token using the `go-keyring-base64:` wrapper. Replace `<github-login>` with
the login shown by:

```bash
gh api user --jq .login
```

In a profile, that credential source lives here:

```text
command_policies.credentials.<route-name>.credential_key
```

### 1Password backend

[`ghcli-profile-1password.json`](./ghcli-profile-1password.json) is the macOS
variant that loads the GitHub token from 1Password instead of the OS keyring.
It uses this example reference:

```text
op://Development/GitHub CLI Token/password
```

The `op` CLI must be installed, signed in, and able to resolve that reference.
To seed the example from an existing `gh` login, this pipeline creates a
Password item in the `Development` vault without placing the token in command
arguments or a temporary file (omit `--vault` to choose interactively):

```bash
gh auth token \
  | jq -Rs '{
      title: "GitHub CLI Token",
      category: "PASSWORD",
      fields: [{
        id: "password",
        type: "CONCEALED",
        purpose: "PASSWORD",
        label: "password",
        value: sub("\\n$"; "")
      }]
    }' \
  | op item create --vault=Development -
```

If your vault, item, or field names differ, change
`command_policies.credentials.github-1password.credential_key` in the profile.
You can verify the reference without displaying the token:

```bash
op read 'op://Development/GitHub CLI Token/password' >/dev/null \
  && echo '1Password credential is available'
```

The 1Password CLI runs before the sandbox is applied. The real token is held by
the proxy; sandboxed `gh` receives a short-lived phantom `GH_TOKEN`, and the
proxy substitutes the real token only for requests allowed by the endpoint
policy. The profile does not grant the child process access to `op` or the
1Password vault.

For headless Linux environments, dev containers, or CI where no Secret Service
keyring is available, use the environment fallback:

```text
env://GH_TOKEN
```

and export the real token in the parent shell:

```bash
export GH_TOKEN="$(gh auth token)"
```

All credential-source variants preserve the same sandbox behavior: the parent
nono process loads the real token, and sandboxed `gh` receives only the phantom
`GH_TOKEN`.

## Linux Keyring Notes

Linux keyring support uses the Secret Service API, usually provided by GNOME
Keyring or KWallet. On Fedora, install the provider and tools if needed:

```bash
sudo dnf install libsecret gnome-keyring
```

Confirm `gh` is authenticated:

```bash
gh auth token >/dev/null
gh api user --jq .login
```

Then set the Linux profile credential source to:

```json
"credential_key": "keyring://gh:github.com/<github-login>?decode=go-keyring"
```

If nono reports that the keyring entry is missing, the common causes are:

- the Secret Service daemon is not running or unlocked
- `gh` authenticated with a different account than the profile login
- `gh` is using an environment token rather than storing a token in the keyring
- nono was built without the `system-keyring` feature

Use `env://GH_TOKEN` as the fallback when the host intentionally has no desktop
keyring.

## Local Approval Policy

The macOS profile uses the shared Python approval webhook:

```json
"approval_backends": {
  "local-webhook": {
    "type": "webhook",
    "url": "http://127.0.0.1:8765/approve",
    "timeout_secs": 5
  }
}
```

Start it from this directory before running macOS approval demos:

```bash
python3 ../approval-webhook-demo.py \
  --allowed-command gh \
  --allowed-caller session \
  --allowed-endpoint-route github-api \
  --allowed-args-prefix auth token \
  --default-decision grant
```

The Linux profile still uses nono's built-in terminal approval backend. Both
profiles ask for local approval in two demo cases:

- command approval for `gh auth token`
- endpoint approval for `GET /rate_limit` on the `github-api` route

Issue comments, creates, closes, release uploads, and destructive GitHub API
methods are denied by policy rather than sent to approval.

## Profiles

Use the platform profile directly from this directory:

```bash
nono profile validate ./ghcli-profile-macos.json
nono profile validate ./ghcli-profile-linux.json
nono profile validate ./ghcli-profile-1password.json
```

The macOS profile uses Homebrew paths for `gh`. The Linux profile uses
`/usr/bin/gh` and Fedora-style system library paths. If `gh` is installed
elsewhere, update:

```text
command_policies.commands.gh.executable
command_policies.commands.gh.from.session.sandbox.fs_read_file
```

## Scripted Demos

You will need demonator to run the scripted demos. Install it with:

```bash
cargo install demonator
```

Run the scripted demo for your platform:

```bash
# macOS
demonator -c ghcli-macos-demo.yml

# Linux
demonator -c ghcli-linux-demo.yml

# macOS with 1Password
demonator -c ghcli-1password-demo.yml
```

The Linux scripted demo exports `GH_TOKEN="$(gh auth token)"` for the
`env://GH_TOKEN` profile. If you switch the Linux profile to a Secret Service
keyring URI, remove that setup line from `ghcli-linux-demo.yml`.

## Run The Demo

Set the profile for your platform:

```bash
export GH_PROFILE=./ghcli-profile-macos.json
# or:
export GH_PROFILE=./ghcli-profile-linux.json
```

Run a command that requires command approval and shows that sandboxed `gh`
receives a phantom token:

```bash
nono run --no-audit --silent --allow-cwd \
  --profile "$GH_PROFILE" \
  -- gh auth token
```

Run an API read that requires endpoint approval:

```bash
nono run --no-audit --silent --allow-cwd \
  --profile "$GH_PROFILE" \
  -- gh api rate_limit
```

Read an issue through the allowed invocation and endpoint policy:

```bash
nono run --no-audit --silent --allow-cwd \
  --profile "$GH_PROFILE" \
  -- gh issue view 1052 \
    --repo always-further/nono \
    --json title,url,state
```

Read the same issue through `gh api`, constrained by L7 endpoint policy:

```bash
nono run --no-audit --silent --allow-cwd \
  --profile "$GH_PROFILE" \
  -- gh api repos/always-further/nono/issues/1052
```

Try a blocked high-level mutation:

```bash
nono run --no-audit --silent --allow-cwd \
  --profile "$GH_PROFILE" \
  -- gh issue comment 1052 \
    --repo always-further/nono \
    --body 'nono arg deny test'
```

Try the same class of mutation through the API:

```bash
nono run --no-audit --silent --allow-cwd \
  --profile "$GH_PROFILE" \
  -- gh api -X POST \
    repos/always-further/nono/issues/1052/comments \
    -f body='nono L7 deny test'
```

Expected: the high-level command is denied by invocation policy; the API call is
denied by endpoint policy.

## Troubleshooting

`tool-sandbox proxy credential 'github-api' is unavailable to the proxy`

The parent nono process could not load the real GitHub token. Check the
credential source in the profile. For Linux keyring, verify the login and that
the keyring is unlocked. For `env://GH_TOKEN`, verify:

```bash
test -n "$GH_TOKEN" && echo "GH_TOKEN set"
```

`gh` hangs or prompts

The profile sets `GH_PROMPT_DISABLED=1`. If `gh` still prompts, confirm the
profile can read `~/.config/gh/hosts.yml` and `~/.config/gh/config.yml`, and
that `gh auth token >/dev/null` succeeds outside nono.

macOS TLS certificate errors

The macOS profile enables trusted TLS interception. If Go-based `gh` reports a
certificate trust error, make sure the profile uses the trusted CA lifecycle and
rerun with a nono build that supports macOS proxy CA trust.
