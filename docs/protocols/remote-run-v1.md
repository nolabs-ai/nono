# Remote Run launch prototype (v1)

`nono run --remote --agent claude` selects a ready workspace and starts an
interactive session. An optional quoted argument supplies the initial prompt.
Both forms request persistent execution. Local sandbox flags are rejected;
the server selects the agent command, policy, credentials, and network grants.

```sh
nono run --remote --agent claude --workspace my-project
nono run --remote --agent claude --workspace my-project "Investigate the failing tests"
nono run --remote --agent claude --workspace my-project --detach
nono ps --remote
nono connect <session-id>
```

The prototype requires a Run API personal access token with `runs:create` and
`runs:read`, supplied through `NONO_RUN_TOKEN` or a protected `--run-token-file`.
Workspace listing and attachment use the separate console human authorization
described in [remote attach v1](remote-attach-v1.md). Both authorizations must
refer to the intended tenant; a Run PAT is not a console access token.

The platform URL defaults to device enrollment; `--platform-url` overrides it.
Console discovery also uses enrollment; `--console` / `NONO_CONSOLE_URL` provide
an override. `--connect-token-file` / `NONO_CONNECT_TOKEN_FILE` override console
authorization. URLs require HTTPS, except for explicit loopback development.
The Run client does not follow HTTP redirects.

## Workspace resolution

`GET /api/v1/workspaces` on the console uses its human bearer credential.
The response contains `workspaces`, each with `id`, `name`, `observed_state`,
and optional `repository_full_name`. Exact names and IDs are accepted;
ambiguous names fail. With no selector, a terminal displays a numbered picker.
Noninteractive invocation requires `--workspace`. The workspace must be ready;
creation and startup remain console operations for this prototype.

## Submission and attachment

`POST /api/v1/runs` on the platform uses the Run PAT and a fresh UUID
`Idempotency-Key`, with this JSON:

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

Submission returns a `run_id`. `--detach` returns after acceptance. Otherwise,
the CLI polls `GET /api/v1/runs/{run_id}` for up to 120 seconds and attaches
using the returned `session.session_id` and the existing terminal protocol.
Failure/cancellation states stop attachment. The CLI prints IDs before attaching.
A startup timeout, transport failure, or terminal detach does not cancel a Run.
After an uncertain submission, check platform Runs before submitting again.
Cancellation uses platform/console controls in this prototype.

Server rollout requires the compatible persistent workspace launch path and
the database migration allowing empty instructions for persistent Runs.
