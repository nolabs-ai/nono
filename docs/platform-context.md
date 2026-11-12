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
| `nono platform` | `login`, `logout`, `status`, `tenant list`, `tenant use`, `group list/memberships/add/move/remove`, `policy status/show/sync`, `enroll`, `unenroll`, `re-enroll` |
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

New registrations also select an enrollment group. One permitted group is
automatic; several use the same terminal picker as tenant selection. To choose
explicitly, including in scripts:

```sh
nono platform login --tenant acme --group Engineering
nono platform tenant use work --group <group-id>
```

Only authorized placements are offered. Self-enrollment alone permits the
tenant's default group; other groups require placement permissions in their
unit. Duplicate group names require an ID. Without a terminal, multiple choices
require `--group`; sign-in remains valid if enrollment cannot finish.

Repeated login reuses the registration and reports its current groups without
asking again. `--group` cannot move an existing registration; use
`nono platform group move` for that. Login and status show cached group labels;
JSON includes IDs. Login and group commands refresh that cache. `--group`
conflicts with enrollment opt-outs, which skip group selection.

For sign-in and tenant switches without automatic enrollment:

```sh
export NONO_NO_ENROLL=true
nono platform tenant use acme
# Enrollment       Skipped (no-enroll enabled)
```

`nono platform login --no-enroll` is the equivalent for one invocation. Existing
registrations are retained; an existing registration for the chosen tenant can
still deliver audits and supply assigned policy. If no registration exists there,
audits remain local.
This setting does not disable audit creation or replace `--no-audit`.
`nono platform re-enroll` is explicit recovery for a revoked registration and conflicts with
these opt-outs; unset `NONO_NO_ENROLL` or set it to `false` before recovery.

## Use platform policy for local runs

`nono run -- command` uses an assigned policy when the current tenant has an
active local enrollment. The platform resolves device overrides, group
assignments and unit defaults; the CLI does not duplicate those rules.

Administrators create groups in **Fleet → Groups**, create and review a profile
in **Policy → Profiles**, then assign a deployed revision to the group.
**Publish and deploy** makes a new revision available to assignments tracking
latest; publishing alone does not. A pinned assignment keeps its selected
revision until explicitly changed. Group membership changes need no re-enrollment.

An explicit `--profile` (or `NONO_PROFILE`) replaces platform policy for that run.
Without an enrollment or authored assignment, existing local defaults apply.
Other CLI permission flags keep their normal semantics: this is a default
profile, not mandatory organization enforcement. `--no-audit` affects audit
creation, not policy selection.

```sh
nono platform policy sync       # fetch, verify and cache the current assignment
nono platform policy status     # cached identity, source, revision and last sync
nono platform policy show       # cached self-contained policy bundle
nono run --allow-cwd -- your-command
nono run --profile my-local-profile -- your-command
```

Assigned policies arrive as self-contained signed bundles, including inherited
profiles and their policy groups. The platform resolves registry dependencies;
the local machine does not need those packs installed. OS conditions and path
variables are evaluated locally. Agents and plugins are installed separately.
Runtime pack assets and host hooks are rejected.
`nono profile show <profile> --format bundle --json` exports the same data format.

Policy commands show the policy name and revision. Sync reports whether it was
updated or is already up to date; IDs and digests remain available through
`--json`. A policy ID stays constant across revisions; its content digest changes
only when the bundle bytes change, so identical revisions can share a digest.
`--silent` suppresses human summaries. Status and show inspect the verified cache;
`sync` is optional because runs check the assignment automatically. The first
fetch builds and stores the bundle on the platform and caches it locally. Subsequent runs check the current
assignment with a small signed response and reuse unchanged local content.
Policy revisions or effective override changes produce a new bundle; group or
tenant switches select the applicable cached bundle. Registry updates do not
silently change an already compiled bundle. Runs fail on
fetch, signature, validation or resolution errors, including required-but-missing
policy; they do not silently use stale cache or local defaults. A signed
unassigned result is distinct from the resolver's locked-down implicit fallback.

Caches are scoped to the platform, tenant and enrolled subject. Later revisions,
group changes and tenant switches affect subsequent runs. Running sessions keep
their selected document. Output identifies the source, and the integrity-protected
`session_policy` audit event records it with the resolved profile digest and,
when assigned, the platform revision and document digest. `nono audit show <id>`
shows the selection; `--json` includes its `policy` details. Audit opt-outs remain.
`--config` cannot be combined with an assigned platform policy; use an explicit
`--profile` to choose a different profile. Automatic selection currently applies
to `nono run`; other local commands keep their existing profile behavior.

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

## Manage this device's groups

Groups collect enrolled devices and workloads within one tenant unit for policy
assignment.
One device enrollment can belong to several groups. Commands manage this
device's explicit memberships in the saved current tenant, preserving its key,
enrollment ID, and audit history. The platform stores memberships; successful
commands refresh locally cached labels.

```sh
nono platform group list                 # available groups; * marks membership
nono platform group memberships          # this device's explicit memberships
nono platform group add Engineering
nono platform group move --from Engineering --to Production
nono platform group remove Production
nono platform group memberships --json
```

`list` works without enrollment. Names must be unique among available groups;
otherwise use an ID from `list --json`. Changes require placement permissions
in the affected units. Move is atomic and preserves other memberships. Completed
retries report unchanged memberships, with **Already in** or **Not in** for
add/remove. `--silent` suppresses summaries; explicit JSON and errors remain.

Removing the last explicit membership does not unenroll the device. Attribute
rules and platform policy fallback still apply; CLI moves do not override rules.
New tenants start with a **Default** group, which administrators can rename.
Assigned policies are used by `nono run` as described above.
