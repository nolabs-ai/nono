# Platform identity and tenant context

| Term | Meaning |
| --- | --- |
| Platform instance | The server selected with `nono platform login --url <origin>`. |
| User | The person authenticated by `nono platform login`. One user can belong to several tenants. |
| Tenant | The isolation boundary for platform resources, administered by a personal account or an organization. |
| CLI context | The saved platform, user and current tenant used by subsequent platform commands. Browser tenant selection is independent. |
| Enrollment | A tenant-scoped device or workload identity. The default `audit_only` mode signs local audit delivery; enrollment does not authenticate the human user for remote commands. |
| Workspace | A remote execution environment belonging to a tenant. |
| Session | One local or remote execution. A remote session belongs to its launching tenant and workspace. |

## Command groups

| Group | Commands |
| --- | --- |
| `nono platform` | `login`, `logout`, `status`, `tenant list`, `tenant use`, `enroll`, `unenroll`, `re-enroll` |
| `nono remote` | `run`, `list`, `connect` |
| `nono audit` | `list`, `show`, `verify`, `cleanup`, `sync`, `status` |

`nono run`, `shell`, `ps`, `attach`, `detach`, `stop`, `logs` and `inspect` operate
locally. Platform commands have no top-level aliases, and remote commands do not
use `--remote` on local commands. Human-readable actions use a themed heading
with aligned fields; status uses the same fields, lists show their current
context, and `--json` emits only structured data.

## Sign in and choose a tenant

```sh
nono platform login --url https://nono.example.com
nono platform status
nono platform tenant list
nono platform tenant use acme
```

Login saves the human session and the current tenant. A single accessible tenant
is selected automatically; several tenants get a terminal picker. The choice is
saved, so subsequent commands do not ask again. In a noninteractive terminal,
use `--tenant <slug|id|personal>` when no default has been selected.

Login also enrolls this installation for local audit delivery in the chosen
tenant by default. Returning to a tenant reuses its registration. A second
installation gets its own identity, even for the same user and tenant.

For sign-in and tenant switches without automatic enrollment:

```sh
export NONO_NO_ENROLL=true
nono platform tenant use acme
# Enrollment       Skipped (no-enroll enabled)
```

`nono platform login --no-enroll` is the equivalent for one invocation. Existing
registrations are retained; an existing registration for the chosen tenant can
still deliver audits. If no registration exists there, audits remain local.
This setting does not disable audit creation or replace `--no-audit`.
`nono platform re-enroll` is explicit recovery for a revoked registration and conflicts with
these opt-outs; unset `NONO_NO_ENROLL` or set it to `false` before recovery.

## Remote sessions

```sh
nono remote run --agent <agent-id> --workspace <workspace-id> --detach 'Task'
nono remote list
nono remote connect
nono remote connect <session-id>
```

These commands authenticate as the signed-in user in the current tenant.
Enrollment is optional. The instance must have nono-console configured and the
user must have access to the selected resources.

The tenant precedence is `--tenant` → `NONO_TENANT` → saved CLI context:

```sh
nono remote list --tenant personal
NONO_TENANT=acme nono remote connect
nono remote run --tenant acme --agent <agent-id> --workspace <workspace-id> --detach 'Task'
```

Remote overrides last for one command. They neither change the saved context nor
enroll or switch local audit delivery. A launch uses the same resolved tenant
through workspace selection, submission, polling and attachment. To change the
saved tenant, use `nono platform tenant use <tenant>`.

If a sign-in has an unfinished tenant selection, a remote command uses the same
picker and saves the choice, without creating an enrollment. Explicit API tokens
retain their existing scope; combining them with a tenant override is rejected.

## Switch to work for a remote session without enrolling

```sh
nono platform tenant use work --no-enroll
nono remote run --agent claude --workspace project
nono platform status
```

`tenant use` requires an existing human sign-in and saves the new tenant after
checking membership. It reuses the chosen tenant's enrollment or creates one
unless opted out. Listing tenants refreshes memberships without changing the
saved tenant or enrolling. Enrollment failure does not undo a successful tenant
switch; with no matching registration, new audits stay local. A revoked
registration requires explicit `nono platform re-enroll`.

## Audit attribution and status

Local sessions bind to the selected tenant's enrollment when they start. Changing
tenants does not move running sessions, queued audits, historical evidence or
remote sessions. Completed local audits upload automatically; `nono audit sync`
retries pending delivery, rather than initiating a live stream.

`nono platform status` shows the saved CLI context separately from enrollment.
`Stored locally` and `Registered locally` describe cached state, not a fresh
server check. `--json` preserves enrollment IDs and adds a `context` object when
signed in, without exposing tokens, private key locations or key fingerprints.
`nono audit status` reports pending uploads across all local queues.

`nono platform logout` revokes the human CLI session and retains device registration.
Enrollment revocation is independent of human sign-in and preserves history.
