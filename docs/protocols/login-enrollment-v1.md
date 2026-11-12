# Enrollment during CLI login

This optional extension to [cli-login-v1](cli-login-v1.md) registers a device
after human sign-in. Human OAuth sessions and device signing keys remain separate.
It changes neither sandbox permissions nor audit opt-outs.

## CLI behavior

```console
nono platform login
nono platform login --url https://nono.acme.example --tenant engineering
nono platform login --tenant engineering --group Developers
nono platform tenant use personal
nono platform login --no-enroll
nono platform re-enroll --tenant engineering
```

`--tenant` replaces `--org`; there is no compatibility alias. `NONO_TENANT`
replaces `NONO_ORG` for a per-command remote tenant override. The old variable is
rejected with a migration message so it cannot silently select the wrong tenant.

After authentication, the CLI selects the only accessible tenant or shows a
terminal picker shared with `nono remote connect`: arrows or `j/k` move, Enter confirms,
and `q`, Escape or Ctrl-C cancels. An explicit `--tenant` takes precedence. In a
noninteractive terminal with several tenants, login retains the credentials but
requires an explicit selection before default remote access or enrollment.
Subsequent logins reuse a completed selection unless another tenant is requested.

For a new registration, the CLI selects the only permitted enrollment group or
uses the same picker for several groups. `--group <name|id>` selects explicitly;
duplicate names require IDs. Noninteractive enrollment with multiple choices
requires `--group`. Existing registrations retain their groups and skip the
picker. A different explicit group leaves the enrollment unchanged and directs
the user to `nono platform group move`.
Login and status show group labels; JSON status includes their IDs and units.
Opting out skips group discovery, and conflicts with `--group`.

Enrollment failure does not invalidate a successful human login. The CLI reports
the failure and how to retry. `--no-enroll` leaves existing registrations intact;
logout revokes only the human session. Unenrollment is explicit and local;
platform revocation retains historical attribution and refuses subsequent use.

`nono platform re-enroll` is explicit recovery for an owned, revoked device registration.
It conflicts with `--no-enroll` and `NONO_NO_ENROLL=true`. A missing local registration directs the user
to normal login without starting sign-in or creating a device key. An active
registration is refused by the server with guidance to use normal login.
Recovery defaults to the previously selected tenant and always starts a fresh
browser or device-code consent flow, even if the CLI is already authenticated.

`NONO_NO_ENROLL=true` applies `--no-enroll` to every login and tenant switch.
The summary reports `Skipped (no-enroll enabled)`. Unset it or set it to `false`
when enrollment or explicit recovery is wanted. It does not disable auditing.
Remote commands use the saved human CLI context, independently of enrollment;
see [platform identity and tenant context](../platform-context.md).

## Discovery and consent

Supporting authorization servers advertise `nono_enrollment_endpoint` in RFC 8414
metadata and `nono:enroll` in `scopes_supported`. The endpoint must share the
issuer's origin and must not contain credentials, query parameters or a fragment.
Its standard path is `/api/v1/auth/oauth/enroll`.
Servers supporting replacement also advertise `nono:reenroll`; recovery requests
both enrollment scopes and browser consent identifies replacement explicitly.

Unless `--no-enroll` is supplied, the CLI requests `nono:enroll` in addition to
the three base login scopes. Browser consent shows that registration is requested.
A legacy platform without the endpoint still supports login; the CLI reports that
manual enrollment is needed. A previously authorized CLI session lacking the new
scope, including a first login with `--no-enroll`, requests browser/device-code
consent again when login later requests enrollment. After storing the new session,
the CLI revokes the previous session; revocation failure is reported without
discarding the new login.

## Group discovery

Supporting servers additionally advertise `nono_enrollment_options_endpoint`,
normally `/api/v1/auth/oauth/enrollment-options`, with the same origin and URL
restrictions as the enrollment endpoint. The CLI posts `refresh_token`,
`tenant_id`, `user_id`, and the device's `public_key`, with a fresh login-key
DPoP proof and no `ath`. This does not rotate the refresh token or enroll.

The response includes `protocol_version`, `tenant_id`, permitted `groups`, and
optional `existing` registration metadata (`subject_id` and current `groups`).
Each group has `group_id`, `name`, `unit_id`, `unit_name`, and `is_default`;
`is_default` identifies the tenant root's default landing group. Existing
placement is visible only for a device owned by this user in this tenant.

Discovery and submission both validate the current CLI session, enrollment scope,
membership, and `enrollment:self`. Self-enrollment permits the root default.
Other placements require `enrollment_token:create` and `devices:assign` in the
group's unit, inherited through the existing unit hierarchy. Permission changes
or deletion after discovery fail submission without falling back to a default.
Responses must not be cached. No browser cookie or console access token is used.

An older server without group discovery keeps its default-placement behavior;
an explicit `--group` fails with an unsupported-feature message.

## Enrollment request

The client posts JSON to the advertised endpoint with a fresh DPoP proof from
the human login key. As at the token endpoint, there is no `ath` claim. The body
contains `refresh_token`, `intent`, and `signature`. Never log this body.

`intent` fields, in serialization order:

| Field | Value |
|---|---|
| `protocol_version` | `1` |
| `issuer` | Exact discovered issuer |
| `tenant_id` | Selected tenant UUID |
| `user_id` | Platform user UUID from the login ID token |
| `login_key_thumbprint` | Login DPoP key's JWK thumbprint |
| `public_key` | Uncompressed P-256 SEC1 point, base64url without padding |
| `display_name` | Untrusted label, 1–64 characters, no controls |
| `timestamp_ms` | Unix milliseconds, within five minutes |
| `request_id` | Fresh random UUID |
| `replaces_subject_id` | Optional revoked subject UUID; omitted for ordinary enrollment |
| `group_id` | Optional selected group UUID; omitted for legacy default placement or unchanged registration |

The independent device key signs the UTF-8 compact JSON serialization of:

```text
["nono-login-enrollment-v1","POST","/api/v1/auth/oauth/enroll",intent]
```

`signature` is the 64-byte P-256/SHA-256 signature (`r || s`), base64url without
padding. The intent binds every field, including issuer, tenant, user, login key
and the device public key. The shared `login-enrollment-v1.json` fixture is
normative for the encoding. TLS remains required outside loopback development.

The platform validates both key proofs, freshness, durable DPoP replay protection,
an unrotated/unexpired/unrevoked refresh token with `nono:enroll`, current user
membership, and `enrollment:self`. Registration does not rotate the refresh token.
Fresh MFA is required for a new registration when the selected tenant requires
it, using server-captured assurance from the browser approval. Device enrollment
does not raise human assurance or fleet policy assurance.

The platform derives ownership and authorizes group placement itself. It atomically
creates the subject and group membership, with the acting human recorded. The
same public key, user and tenant return the same subject, including concurrent
retries and retries after a lost response. A revoked registration is refused,
never reactivated. Distinct device keys create independently revocable subjects.

Replacement requires `nono:reenroll`, a CLI session created within five minutes,
current enrollment permission and applicable fresh MFA. The signed intent binds
the previous subject to the new device key. The old subject must be a revoked
device owned by this user in this tenant, and the key must differ. The platform
creates a new subject with `replaces_subject_id`; the old row remains revoked.
At most one replacement is accepted per old subject. Retrying with the same new
key returns that replacement; a different competing key is refused. This does
not prevent a permitted user from registering a new installation independently.

Success returns the existing enrollment-v1 response with `subject_kind=device`
and `management_mode=audit_only`. OAuth-style errors include `access_denied`,
`invalid_grant`, `invalid_target`, `invalid_dpop_proof`, `insufficient_scope`,
and `mfa_required`. Neither success nor error responses may be cached.
Recovery errors include `enrollment_revoked`, `enrollment_active`,
`enrollment_replaced`, and `reenrollment_authorization_required`.
`enrollment_group_mismatch` refuses changing an existing registration's groups
through login. Successful enrollment returns its actual `groups`, including
when reusing a registration; the client checks any explicitly selected group.
Group selection does not download a profile during login. Subsequent implicit
`nono run` sessions use [signed local policy delivery](local-policy-v1.md).

## Local identity and audit provenance

Device keys and registration records are scoped by issuer, tenant and platform
user. They live beneath nono's protected state root, in `platform-device-keys/`
and `platform-enrollments/`. `platform.json` remains the last activated enrollment
for signed-out and legacy clients. A signed-in client resolves only its selected
tenant/user registration; it never silently uses another tenant's registration.

Replacement keys have distinct paths under `platform-device-keys/`; staging is
stable for the old subject so interrupted requests can retry without replacing
the original key. The selected registration is updated only after server success.
Confirmed revocation is cached locally. Status reports `Revoked`, and new sessions
are not assigned that revoked enrollment. Existing queued evidence retains its
original subject and key reference and is never relabeled as the replacement.

The CLI generates a software P-256 key and stores its PKCS#8 material in an
owner-only file under `platform-device-keys/`. Repeated logins reuse that key.
A copied private key can impersonate the same installation; enrollment proves
possession of the key, not the identity of a physical machine.

Every newly audited session captures its enrollment at session start. Final
delivery and outbox retries retain that original platform, tenant, subject and
key reference across later login switches. Old queue records without an embedded
origin can use only a matching active subject and tenant; they are never
reassigned. Historical unbound sessions are not assigned to a new enrollment.
Deleting a key or revoking its subject may leave its queued evidence undeliverable.
`--no-audit` and `--no-audit-integrity` keep their existing behavior; enrollment
does not enable full terminal recording.

## Status presentation

Login identifies the signed-in account and current tenant after selection
succeeds. An existing login reports a tenant switch explicitly; an unchanged
selection gets a short confirmation. New enrollment is announced before the
request and confirmed only after success. Repeated login reports reuse when
its subject and key reference match the confirmed registration. First enrollment
and tenant switches name the destination for new session audits.
Results use a themed heading and aligned fields, with the current tenant
highlighted and the previous tenant muted on switches. Styling follows the
existing terminal color handling, including `NO_COLOR`. JSON status is unchanged.

Local registration records optionally cache the enrolled display name and tenant
label. Human-readable status uses these names, a UTC enrollment date and the
label `Registered locally`; it does not query revocation or verify key availability.
Legacy records remain readable without labels. Full identifiers remain in the
existing JSON status fields; neither format exposes credentials or key paths.
Audit status counts all local pending uploads in the state root, including
historical entries without an enrollment binding.
Delivery is attempted automatically when an audited session finishes. An empty
manual sync reports `No pending audit uploads.`; it is not a delivery history.
Switching tenant leaves existing sessions and queued audits bound to their
original enrollment, and does not revoke other registrations.

## Group membership management

Metadata advertises `nono_groups_endpoint` at
`POST /api/v1/auth/oauth/enrollment-groups`. Requests carry `refresh_token`,
`tenant_id`, `user_id`, optional `subject_id`, and an `action` tagged by `type`:
`list`, `memberships`, `add`/`remove` with `group_id`, or `move` with `from`/`to`.
The human session's DPoP proof targets this endpoint; device keys are not used
as human credentials. Responses are `no-store` and include `protocol_version`,
`tenant_id`, `subject_id`, permitted `groups`, current explicit `memberships`, and
`changed`. The shared fixture covers the wire format.

Listing requires an active tenant membership; it works without an enrollment
or enrollment scope. Subject reads require an owned device in that tenant.
Mutations additionally require `nono:enroll`, active device registration, and
existing unit placement permissions. Move is atomic, preserves other groups,
and retries already completed changes report `changed: false`. Mutations use
the same domain operation as platform group administration, including its
governance audit records. Successful CLI requests update cached labels without
replacing the enrollment key or ID. Revocation blocks mutations but does not
remove the person's ability to list permitted groups.
