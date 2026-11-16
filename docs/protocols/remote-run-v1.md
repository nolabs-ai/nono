# Remote Run launch prototype (v1)

`nono remote run --agent claude` selects a ready workspace and starts an
interactive session. An optional quoted argument supplies the initial prompt.
Both forms request persistent execution. Local sandbox flags are rejected;
the server selects the agent command, policy, credentials, and network grants.

```sh
nono platform login --url https://nono.example.com
nono remote run --agent claude --workspace my-project
nono remote run --agent claude --workspace my-project "Investigate the failing tests"
nono remote run --agent claude --workspace my-project --detached
nono remote list
nono remote connect <session-id>
```

The instance must have nono-console and a workspace runtime configured, with a
ready workspace accessible to the user. A local development console alone does
not provide a workspace runtime.

## Authentication and tenant context

Remote commands use the human session saved by `nono platform login`.
Device enrollment is optional: use `nono platform login --no-enroll` to sign in
without creating an audit enrollment. A separate Run API token is not required.
See [platform identity and tenant context](../platform-context.md) for the full
workflow and [CLI login v1](cli-login-v1.md) for the authentication protocol.

The tenant precedence is `--tenant` → `NONO_TENANT` → saved CLI context.
An override applies to this command only; it does not change the saved tenant,
enroll the device, or switch local audit delivery. To save a different tenant,
use `nono platform tenant use <tenant>`; add `--no-enroll` to skip automatic
enrollment.

```sh
nono remote run --tenant acme --agent claude --workspace my-project --detached
nono platform tenant use acme --no-enroll
```

The launch resolves its tenant and refreshes its human credential once, then
uses that same DPoP-bound credential for workspace listing, Run submission,
polling, and console attachment. Each HTTP request carries its own DPoP proof.

The platform URL defaults to the signed-in instance. With human Run
authentication, `--platform-url` must match that instance. The console URL comes
from the login or refresh response for the selected tenant; `--console` /
`NONO_CONSOLE_URL` explicitly override it. If the signed-in instance supplies no
console URL and none is specified, the CLI reports that remote sessions are not
configured, without falling back to enrollment discovery.

### Explicit credentials

A Run API personal access token with `runs:create` and `runs:read` can instead
be supplied through `NONO_RUN_TOKEN` or a protected `--run-token-file`.
Console authorization can be overridden separately with `--connect-token-file`,
`NONO_CONNECT_TOKEN_FILE`, or `NONO_CONNECT_TOKEN`, as described in
[remote attach v1](remote-attach-v1.md). Explicit credentials retain their own
scope; a Run PAT is not a console access token. Both credentials must authorize
the intended tenant. Combining explicit credentials with `--tenant` or
`NONO_TENANT` is rejected.

Without human Run authentication, supply `--platform-url` or use the locally
enrolled platform URL. Without a human console context or explicit console URL,
legacy console discovery uses enrollment; browser-approved console authorization
remains available when no human login or explicit console credential is present.
Enrollment alone does not supply a Run API credential.

URLs require HTTPS, except for explicit loopback development. The Run client
does not follow HTTP redirects.

## Workspace resolution

`GET /api/v1/workspaces` on the console uses the resolved console credential.
The response contains `workspaces`, each with `id`, `name`, `observed_state`,
and optional `repository_full_name`. Exact names and IDs are accepted;
ambiguous names fail. With no selector, a terminal displays a numbered picker.
Noninteractive invocation requires `--workspace`. The workspace must be ready;
creation and startup remain console operations for this prototype.

## Submission and attachment

`POST /api/v1/runs` on the platform uses the human credential or explicit Run PAT
and a fresh UUID `Idempotency-Key`, with this JSON:

```json
{
  "agent_id": "claude",
  "instructions": "",
  "execution_mode": "persistent",
  "workspace_id": "019f0000-0000-7000-8000-000000000001"
}
```

Persistent Runs permit missing or empty instructions. One-shot Runs continue
to require instructions. Instructions are bounded to 64 KiB. Persistent
workspace launches use existing workspace files without fetching or resetting
the repository; concurrent interactive agents share those files.

Submission returns a `run_id`. `--detached` (`--detach` is an alias) returns
after acceptance. Otherwise, the CLI polls `GET /api/v1/runs/{run_id}` for up to
120 seconds and attaches using the returned `session.session_id` and the existing
terminal protocol.
Failure/cancellation states stop attachment. The CLI prints IDs before attaching.
A startup timeout, transport failure, or terminal detach does not cancel a Run.
After an uncertain submission, check platform Runs before submitting again.
Cancellation uses platform/console controls in this prototype.

Server rollout requires the compatible persistent workspace launch path and
the database migration allowing empty instructions for persistent Runs.
