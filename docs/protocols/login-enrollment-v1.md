# Enrollment during CLI login

This optional extension to [cli-login-v1](cli-login-v1.md) registers a device
after human sign-in. Human OAuth sessions and device signing keys remain separate.
It changes neither sandbox permissions nor audit opt-outs.

## CLI behavior

```console
nono login
nono login --url https://nono.acme.example --tenant engineering
nono login --tenant personal
nono login --no-enroll
```

`--tenant` replaces `--org`; there is no compatibility alias. `NONO_TENANT`
replaces `NONO_ORG` for a per-command remote tenant override. The old variable is
rejected with a migration message so it cannot silently select the wrong tenant.

After authentication, the CLI selects the only accessible tenant or shows a
terminal picker shared with `nono connect`: arrows or `j/k` move, Enter confirms,
and `q`, Escape or Ctrl-C cancels. An explicit `--tenant` takes precedence. In a
noninteractive terminal with several tenants, login retains the credentials but
requires an explicit selection before default remote access or enrollment.
Subsequent logins reuse a completed selection unless another tenant is requested.

Enrollment failure does not invalidate a successful human login. The CLI reports
the failure and how to retry. `--no-enroll` leaves existing registrations intact;
logout revokes only the human session. Unenrollment is explicit and local;
platform revocation retains historical attribution and refuses subsequent use.

## Discovery and consent

Supporting authorization servers advertise `nono_enrollment_endpoint` in RFC 8414
metadata and `nono:enroll` in `scopes_supported`. The endpoint must share the
issuer's origin and must not contain credentials, query parameters or a fragment.
Its standard path is `/api/v1/auth/oauth/enroll`.

Unless `--no-enroll` is supplied, the CLI requests `nono:enroll` in addition to
the three base login scopes. Browser consent shows that registration is requested.
A legacy platform without the endpoint still supports login; the CLI reports that
manual enrollment is needed. A previously authorized CLI session lacking the new
scope, including a first login with `--no-enroll`, requests browser/device-code
consent again when login later requests enrollment. After storing the new session,
the CLI revokes the previous session; revocation failure is reported without
discarding the new login.

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

The platform derives ownership and default group placement itself. It atomically
creates the subject and group membership, with the acting human recorded. The
same public key, user and tenant return the same subject, including concurrent
retries and retries after a lost response. A revoked registration is refused,
never reactivated. Distinct device keys create independently revocable subjects.

Success returns the existing enrollment-v1 response with `subject_kind=device`
and `management_mode=audit_only`. OAuth-style errors include `access_denied`,
`invalid_grant`, `invalid_target`, `invalid_dpop_proof`, `insufficient_scope`,
and `mfa_required`. Neither success nor error responses may be cached.

## Local identity and audit provenance

Device keys and registration records are scoped by issuer, tenant and platform
user. They live beneath nono's protected state root, in `platform-device-keys/`
and `platform-enrollments/`. `platform.json` remains the last activated enrollment
for signed-out and legacy clients. A signed-in client resolves only its selected
tenant/user registration; it never silently uses another tenant's registration.

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
