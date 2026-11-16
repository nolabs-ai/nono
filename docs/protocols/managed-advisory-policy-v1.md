# Managed advisory policy protocol v1

An enrolled device discovers its effective session mode at every `nono run`,
`nono shell` or `nono wrap` startup. `nono platform status` reads the last verified result;
`nono platform status --refresh` performs the same discovery explicitly.
Enrollment continues to return `management_mode: audit_only` for compatibility.
Only the freshly verified assignment decides managed session behaviour. Status JSON
reports that effective mode in `management_mode` when a verified assignment is known;
its issuance time and `policy_refreshed` distinguish cached from refreshed information.

## Modes

- `audit_only`: local policy governs the session. Audit and platform approvals
  retain their existing behaviour. No applicable managed assignment means this mode.
- `advisory`: the delivered policy is the default. An explicit local profile or
  manifest replaces it; supported policy flags can modify it. Overrides are recorded.
- `enforced`: unsupported in this phase. Neither platform activation nor client
  interpretation as advisory is allowed.

New assignments default to advisory. Migrated assignments retain audit-only mode;
updates without a mode preserve the current choice. Profile precedence is unchanged.
Mode resolves independently: the strictest applicable subject, group or ancestor-unit
assignment wins. The implicit platform approval baseline is not a managed assignment.
Deleting an assignment causes resolution through the remaining assignments.

## Trust root

Token and login enrollment may include `policy_trust_root` with `algorithm`,
`key_id`, and `public_key`. The client pins it through that authenticated enrollment
exchange. Existing enrollments bootstrap using an enrollment-authenticated
`GET /api/v1/policy/trust-root` over the enrolled HTTPS origin. HTTP is accepted
only for explicit loopback development. Redirects are refused. Policy responses
never choose their own verification key. A changed key is refused; key rotation
and separate managed signing infrastructure remain later work.

## Refresh

`POST /api/v1/policy/refresh` uses the existing enrolled request-signature headers.
The signature binds method, actual request path, subject, timestamp, unique request
ID and exact body digest. The platform checks active enrollment and durably claims
request IDs to reject replay. The body contains:

```json
{"protocol_version":"1","platform":"macos","home":"/Users/developer","workdir":"/Users/developer/Work/project"}
```

The platform returns `SignedPolicyResponse`: algorithm, key ID, base64url payload
and base64url signature. P-256 SHA-256 signs the **decoded payload bytes**, not the
base64 text. The payload contains protocol version, tenant, subject, request ID,
issuance time, effective management mode, assignment version, resolution provenance
and optional policy. All fields affecting the decision are inside the signature.

An advisory policy carries profile ID, revision, grant-delta version, document digest
and exact profile JSON text. Audit-only carries no session-policy document. The
assignment version is a content digest over mode, provenance and delivered policy;
it is not a monotonic rollback counter.

The platform exports the assigned document using
`nono profile show <private-profile-file> --format portable`. This includes the root source document, a map of its dependency documents and
referenced package group definitions. Inheritance references are rewritten to bundle
identifiers. `$HOME`, `$WORKDIR`, conditional entries and platform overrides remain
unresolved. The device uses its existing inheritance resolver against that map only,
and installs the delivered group definitions without loading local package groups.
A launch carries its own resolved group policy alongside the profile; it never
changes the process-wide local policy cache.
A profile with no dependencies may also be delivered directly. Host/session hooks are rejected; executable package delivery
is outside this protocol. The client applies its own OS overrides and expands paths
using its existing policy machinery. Existing platform approval-evaluation limitations
are unchanged by this startup-delivery protocol.

## Verification and failures

Before launch, the client verifies the pinned key, signature, protocol, tenant,
subject, request ID, issuance time within five minutes, document digest, supported
mode and self-contained profile shape. Limits bound response size and HTTP timeouts.
Cached signatures and document digests are checked on inspection, but cached policy
is never used for an offline managed launch.

A previously advisory default launch cannot proceed without a fresh valid response.
An advisory user may intentionally select a local profile or manifest when transport
is unavailable. Invalid signatures or unsupported signed modes are errors. Local,
audit-only and legacy clients retain local offline operation and report discovery
failure honestly. A 404 from an older platform is not permission to abandon a
previously managed assignment. Unenrolled launches perform no policy request.

The last verified mode is also stored with the enrollment, separately from the
bundle cache and scoped to platform, tenant and device. Deleting the bundle cache
does not turn a previously advisory client into an unconfigured local client while
offline. Repeated login to the same enrollment preserves this mode; a fresh signed
audit-only reply can return it to local operation. Explicit local overrides remain
available in advisory mode. If the cache is missing, their audit attribution uses
an unknown assignment version rather than inventing a profile or revision.

## Session evidence

The supervisor stores policy attribution on the session and emits a `platform_policy`
audit extension after `session_started`. It records assigned mode/profile/revision/
digest, assignment version, selected source, resolved-profile digest where available,
and override option names. Credential values are never included. The resolved-profile
digest identifies the finalized profile, not the complete OS sandbox or every flag.
The existing audit hash chain covers the extension and existing ingest delivers it.
Fleet exposes the last reported session separately from the currently assigned policy
and retains the audit ingest/verification status. Older sessions remain unknown.

`nono wrap` verifies and applies static managed policy, including on `--dry-run`.
It refuses proxy rules and managed settings that require a supervisor, including
runtime elevation, command policies and recording, with instructions to use
`nono run`. Direct exec cannot deliver session audit evidence; advisory launches
through `wrap` display that limitation, including when a local override is selected.

## Terminal output

Platform status and startup policy summaries use the selected CLI theme and aligned
fields. Human output prefers the signed profile's `meta.name` to its internal ID;
session records retain that optional name so detached launches use the same summary.
Older session records fall back to the profile ID.

Plain status displays the verified cached policy and its check time. `status --refresh`
reports whether it fetched a policy, found the assignment already current, changed
revision, or returned to local policy. Human timestamps stop at seconds and include
cache age; JSON retains exact timestamps and identifiers. Audit queue details appear
in status only when uploads are pending, queue inspection fails, or enrollment is
revoked. Full audit delivery status remains available through `nono audit status`.

## Scope

This phase changes new-session defaults only. Running sessions retain their original
policy. It does not add enforced-mode lockdown, offline managed launch, policy polling,
key rotation, hardware attestation, workspace grants or runtime elevation.
