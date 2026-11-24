# Managed policy delivery v2

Every enrolled `nono run`, `nono shell` or `nono wrap` startup discovers its
effective assignment through the enrollment-authenticated platform connection.
Assigned content is always a self-contained [nono Bundle v1](nono-bundle-v1.md).
The bundle specification defines the signature, inventory, delivery encoding,
limits and verification rules. No raw-profile delivery or alternate format is
accepted.

## Authority and modes

Enrollment returns `management_mode: audit_only` and pins the policy trust root;
it installs no profile. Only a fresh verified assignment chooses managed session
behaviour. Existing enrollments without a pinned key obtain the trust root through
an enrollment-authenticated request to the enrolled HTTPS origin. Redirects and
non-loopback HTTP are refused. Responses never choose their own verification key.
A changed key requires re-enrollment; rotation remains separate work.

* `audit_only`: local policy governs. Audit and approvals retain their existing
  behaviour. No applicable assignment means this mode.
* `advisory`: the assigned bundle is the default. An explicit local profile or
  capability manifest replaces it; permitted local policy flags can modify it.
  Overrides and their input sources are recorded.
* `enforced`: the assigned bundle is the only policy source. Every launch needs
  a fresh verified response. Local grants, profile selection and audit suppression
  are refused. `wrap` is refused because it has no supervisor.

Mode is the strictest applicable subject, group or ancestor-unit assignment,
resolved independently of profile precedence. Assignment mode and content come
from one database snapshot. Tenant and device identities come from the enrolled
request, never from a client-selected profile or tenant field.

## Refresh and failure behaviour

Token enrollment and confirmed login enrollment immediately refresh and verify
the effective assignment after saving the device identity and pinning the policy
key. Successful confirmation reports the mode, policy name and revision, and
`Verified and ready`. An audit-only assignment reports local profiles. If this
check fails, enrollment stays saved, the command exits nonzero and directs the
user to `nono platform status --refresh`. Retrying the policy check needs no new
enrollment token. No mode or readiness is inferred from the enrollment response;
default session startup still requires its normal fresh policy check.

A locally recorded revocation blocks session startup, including explicit local
profile overrides. Revoked enrollment is not treated as an unenrolled device;
the enrollment must be recovered or explicitly removed first.

`POST /api/v1/policy/refresh` accepts only body `protocol_version: "2"`, with
client `platform`, `home` and `workdir`. The enrolled request-authentication
protocol and HTTP path remain v1. The response binds tenant, subject, request ID,
issuance time, mode, resolution provenance and assignment identity to the bundle
reference. Freshness is checked within five minutes of the request.

The platform invokes `nono profile show <private-profile-file> --format bundle`
to collect and validate policy dependencies. Clients resolve only the source
files named by the signed inventory. Device-specific paths, OS overrides and
conditional rules are evaluated on the device. No client registry lookup or
local-profile fallback can satisfy a missing dependency.

Default managed startup needs a fresh valid response. A new enrollment has no
verified mode yet and cannot assume local policy: HTTP 404, a disconnect, or any
other failed first refresh prevents default startup. A network failure never
silently replaces a previously advisory policy with local defaults. An advisory
user may explicitly select a local profile or capability manifest when the
platform is unavailable; invalid signatures, unsupported formats and rejected
assignments remain errors. An enrollment with no verified mode cannot use an
explicit override to bypass its first check. Enforced devices have no offline
fallback, including explicit profiles. Previously local and unenrolled clients keep local
offline operation.

The last verified mode is stored with enrollment, separately from disposable
bundle caches. Deleting a cache cannot make an advisory or enforced device local.
Obsolete cached protocol versions are discarded, preserving the trust root and
remembered mode, and require a fresh response before managed use. Same-enrollment
login preserves that mode. A fresh signed audit-only assignment can return the
device to local policy.

`nono platform status` verifies and reports cached state; `--refresh` performs a
fresh exchange. Cached inspection does not grant offline launch authority.
Without a cached assignment, JSON status reports the last verified mode, or
`null` if no mode has been verified. `last_verified_management_mode` exposes that
remembered history separately; `policy_assignment: null` and
`policy_refreshed: false` make clear that no assignment was inspected. Human
output labels remembered mode `last verified` and directs the user to refresh.
Signed `resolved_via` metadata may include `profile_id`, `profile_name` and
`revision` for the effective assignment, including group and unit inheritance.
The CLI uses that platform label, falling back to bundle metadata for older
servers. In audit-only mode it distinguishes the assigned profile from the
local profiles that govern the session.
An explicit `--refresh` can replace damaged cached content after verifying the
fresh assignment and complete bundle against the existing pinned key. It never
accepts a replacement key from that response. Ordinary session startup continues
to reject cache tampering; it does not repair it implicitly. Invalid fresh
responses leave the old cache untouched.

Startup failures identify the failed check and, for file failures, the affected
bundle path. Missing files, unexpected files, size differences and SHA-256
differences have separate diagnostics. Rejected startup exits nonzero and says
`Session not started.` An error-level log records the rejection; `-v` logs fresh
verified assignments, and `-vv` also logs request IDs, endpoint status, cache
directories and file verification failures. Use `--log-file <path>` to retain
these logs. The added events exclude policy contents, authentication headers,
keys and encoded payloads or signatures.

## Session evidence and output

The supervisor stores assignment attribution on the session and emits a
`platform_policy` audit extension after `session_started`. It records mode,
profile ID, optional display name, revision, manifest digest, assignment version,
selected source, resolved-profile digest when available, and explicit override
option names and sources (`command_line` or `environment`). Credentials are never
included. The resolved-profile digest identifies the finalized profile, not the
complete OS sandbox or every command-line option.

Unknown assignment metadata is reported as unknown. An assignment is not proof
of device application; session reports retain the audit ingest/verification
status. Advisory and local modes still permit `--no-audit`, which retains only
local session attribution.

Startup names the signed bundle, revision, mode, selected source and overrides.
Status distinguishes a first fetch, unchanged assignment, revision change and
return to local mode. Human output sanitizes signed labels for terminal display;
timestamps include seconds and cache age. JSON retains exact metadata.

`nono wrap` applies static managed policy, including during `--dry-run`. It refuses
proxy rules and settings requiring a supervisor, including runtime elevation,
command policies and recording. Direct exec cannot deliver session audit
evidence, and advisory wrap launches explain that limitation.

## Enforced startup

Explicit `nono platform re-enroll` can start fresh human consent even when the
old device key is refused. Activation requires the server to confirm an owned,
revoked replacement with preserved policy context. The client carries its
remembered mode into the replacement and verifies the fresh assignment;
failed recovery does not release enforcement. Other enrollment changes retain
their normal fresh-assignment guard.

Mode is verified before any local policy is loaded, including detached-launch
preflight. The detached supervisor repeats verification. Only the signed bundle
configures the sandbox; locally installed profiles and pack contents are not
consulted. There is no interactive workspace-sharing grant or automatic Claude
LaunchServices exception. Administrators must put required paths in the policy,
including an explicit `$WORKDIR` grant when appropriate. Project-root constraints
on the choice of workspace are separate work.

Enforced launch options use an allow-list. Session/output options and rollback
options retain their existing behavior. Policy inputs permitted today are
`--block-net`, `--deny-domain`, `--block-command`, `--memory`, `--max-processes`,
`--isolate`, `--strict-broker-path`, `--workdir`, `--shell`, `--record`,
`--record-required`, `--deliver-to` (platform only) and `--audit-integrity`.
Resource flags cannot raise a limit from the policy. All other policy inputs
are refused, including explicit false environment settings. `--allow-endpoint`
is refused because its current append semantics can widen an existing endpoint
allow-list. `--record-file` is also refused; destinations belong in the policy.
Unknown future options are refused until reviewed. Child-program arguments are
not nono options.

Policy-changing `NONO_*` variables produce errors naming the setting, without
printing its value. `NONO_PLATFORM_URL`, `NONO_TENANT`, `NONO_ORG` and
`NONO_REGISTRY` cannot redirect an enforced launch. The enrolled origin and
tenant remain authoritative; an enforced enrollment also takes precedence over
the saved human sign-in context.

Command mediation resolves tool policy from the verified bundle and keeps launch
permissions in supervisor memory. On macOS, a private, single-use socket carries
them to the launcher. Before and after a fresh challenge, the launcher verifies
its direct parent's identity using the socket audit token and matching valid
code-signing hash. Failed authentication, changed parents and oversized messages
prevent execution; the handoff closes before the tool starts. On Linux, the
supervisor prepares restrictions before fork and the child applies them before
executing the verified binary through its open descriptor. There is no external
Linux launcher. Both paths apply in every mode, require running-process integrity
and avoid a platform request per tool.

Configured approval backends must be platform-authenticated webhooks to the
enrolled approval endpoint. Runtime elevation without a platform backend is
refused. An enforced supervisor without a configured platform backend denies
capability requests, including direct IPC requests when elevation is disabled;
it never falls back to a local terminal prompt.

Network policy queries preserve approval requirements: an empty domain allow-list
with configured approval backends requires review rather than granting every
host. Static allows still pass, and explicit domain and metadata-IP denies stay
denied. The platform uses this same query for its approval precheck.

Local setup, standalone proxy, profile creation/promotion, trust mutation,
unenrollment, login/logout and tenant selection are refused while enforced.
Read-only inspection, cache refresh, session controls and rollback restoration
remain available. To change enrollment through the CLI, an administrator first
changes every applicable enforced assignment on the platform; a fresh signed
response must confirm the less restrictive mode. Offline checks cannot authorize
the change. A dedicated management-approval lease is not implemented.

## Scope

This implements startup delivery and verification. Running sessions retain their
original policy. Enforced startup governs this enrolled client; machine owners
can still replace binaries or local enrollment state, and run agents directly.
Device management and binary attestation are separate controls. Policy polling,
offline managed launches, key rotation, skill activation and hook wiring remain
separate work. Additional signed files do not authorize their execution.
