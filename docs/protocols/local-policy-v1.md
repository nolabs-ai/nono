# Local policy delivery v1

`GET /api/v1/policy/local` delivers the current enrollment's effective policy.
It uses the existing nono-request-v1 device signature headers over the exact
method, path and empty body. The server derives the tenant and subject from the
active enrollment, consumes the request ID once, reuses the assignment resolver,
and records the resolution. No human token, caller-selected policy or new
service is involved. Responses are `no-store`.

The response has `algorithm`, `key_id`, `public_key`, `payload` and `signature`.
The algorithm is `ecdsa_p256_sha256_fixed`; the key ID is `sha256:<hex>` of the
uncompressed P-256 public key. Payload is base64url JSON, signed as its decoded
bytes using fixed-width P-256/SHA-256. Claims, in serialization order:

| Field | Meaning |
| --- | --- |
| `protocol_version` | `1` |
| `tenant_id`, `subject_id` | Enrollment identity |
| `request_id` | The freshly signed request's UUID |
| `issued_at` | UTC RFC 3339 timestamp |
| `source` | `subject`, `group`, `unit_default` or `implicit_default` |
| `source_name` | Optional winning group label |
| `policy` | Document below, or null for no authored assignment |

A document contains `profile_id`, optional catalog `display_name`, positive
`revision`, `content_digest`
(`sha256:<hex>` of the exact `profile_json` bytes), and `profile_json` as a string.
It is a portable bundle compiled from the resolver's composed document, including
the subject's grant delta. The signature and digest cover the entire bundle.
The platform durably caches compiled bundles by tenant, profile revision,
effective source digest (including device grant deltas), and bundle format.
Concurrent first fetches share one compilation. Dependency versions in a stored
bundle stay fixed; publishing a new revision creates a new compilation identity.
A changed assignment is resolved before consulting the cache.

A client with verified content may send `If-None-Match: "sha256:<hex>"`.
A matching digest returns HTTP 200 with a fresh signed envelope, current
assignment metadata and `content_digest`, omitting `profile_json`. This header
is only a transfer hint: it grants no authority and cannot select a policy.
The client requires matching cached bytes and verifies their digest. Unmatched
or absent hints receive the complete document. The signed response always binds
the fresh request ID and enrollment; an HTTP 304 or old signature is insufficient.

A fail-closed resolution returns 409; it never becomes an unassigned result.
The implicit default is signed as `policy: null`, preserving existing local
behavior for audit-only users. Missing signing configuration returns 503.

The CLI validates the signature, key identity, protocol, source, enrollment,
request ID, freshness (five minutes) and document digest before accepting data.
The initial signing key is trusted through the configured HTTPS origin (HTTP is
permitted only on loopback), then pinned per instance. A key carried in a
response is not independently a trust anchor: later responses and cached reads
must match the pin. Key changes require operator verification and an explicit
local trust update; they are never accepted automatically. Redirects are disabled,
responses and cached records are bounded, and errors do not clear a verified cache.

Protected `platform-policies/` state contains the pin, signed enrollment-scoped
cache, content-addressed bundle blobs, and profile snapshots. A bundle contains
`format_version: "1"`,
an `entry` ID, a `profiles` map, and `policy` and `network` definitions. The
platform resolves and verifies registry dependencies using its private package
store; all `extends` references become internal IDs. Raw OS conditions and path
variables remain for the enforcing device to evaluate. Package group definitions
and built-in rules travel with the document; no client package installation or
ambient user profiles are needed. The normal nono loader validates the complete
inheritance graph before promoting a cache. Missing dependencies, cycles, runtime
packs and `$PACK_DIR` assets are rejected; bundles contain policy data only.
Host session hooks are rejected; downloaded profiles do not gain local-author privileges for
binary overrides, raw Seatbelt rules or external recording destinations.

Every implicit platform-policy run requires a fresh successful assignment check.
Unchanged bundles and intact materialized profiles are reused without rewriting.
Missing or corrupted cached content triggers a full fetch on the next sync.
There is no offline launch fallback in this version. Status/show may inspect an old cache
and clearly report its last sync. Explicit profiles bypass policy fetching;
ordinary CLI flags retain their behavior. This is default profile delivery, not
mandatory device management. Enrollment still has `management_mode: audit_only`.

The session binds its enrollment and policy before launch. `session_policy` is
an extension event in the existing integrity-protected audit log: source,
resolved profile digest, and platform identity/revision/content digest when used.
It describes the selected profile, not independent proof of compliance or the
final capability set after CLI flags. No credentials or device-key paths appear.

Cross-repository `local-policy-v1.json` fixtures cover serialization and signature
verification. Tests cover tampering, stale/replayed proofs and responses, wrong
identity, signing-key changes, unassigned/required policy, revocation, cache
isolation, explicit overrides and actual sandbox denial.
