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
* `enforced`: unsupported. The server rejects activation and the client refuses
  to interpret it as advisory.

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
assignments remain errors. Previously local and unenrolled clients keep local
offline operation.

The last verified mode is stored with enrollment, separately from disposable
bundle caches. Deleting a cache cannot make a previously advisory device local.
Obsolete cached protocol versions are discarded, preserving the trust root and
remembered mode, and require a fresh response before managed use. Same-enrollment
login preserves that mode. A fresh signed audit-only assignment can return the
device to local policy.

`nono platform status` verifies and reports cached state; `--refresh` performs a
fresh exchange. Cached inspection does not grant offline launch authority.
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

## Scope

This implements startup delivery and verification. Running sessions retain their
original policy. It does not enable enforced lockdown, policy polling, offline
managed launches, hardware attestation, key rotation, full pack import, skill
activation or hook wiring. Additional files can be authenticated without
authorizing their execution.
