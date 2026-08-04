# Audit delivery protocol v1

This document specifies the open client contract used by `nono` to enroll an
audit-only device or workload and deliver a completed session to a compatible
control plane. Enrollment does not imply mandatory fleet policy or session
conformance.

## Enrollment

An operator provisions a short-lived, single-use token bound server-side to a
tenant. The client generates an ECDSA P-256 keypair and sends:

```http
POST /api/v1/enrollment/exchange
Content-Type: application/json
```

```json
{
  "protocol_version": "1",
  "token": "<one-time token>",
  "subject_kind": "device",
  "display_name": "developer laptop",
  "key_algorithm": "ecdsa_p256_sha256_fixed",
  "public_key": "<base64url uncompressed P-256 point>"
}
```

The response binds a stable `subject_id` to the server-derived `tenant_id` and
returns `management_mode: "audit_only"`. The private key and enrollment state
must be stored outside project-controlled configuration.

## Signed final ingest

The final envelope is posted to `/api/v1/audit/ingest`:

```json
{
  "ingest_id": "<UUIDv7>",
  "tenant_id": "<tenant>",
  "session_id": "<session>",
  "shipper_id": "<enrolled subject>",
  "principal_id": null,
  "profile_ref": null,
  "merkle_root": "<lowercase SHA-256 hex>",
  "hash_chain_head": "<lowercase SHA-256 hex>",
  "started_at": "<RFC 3339 timestamp>",
  "ended_at": "<RFC 3339 timestamp>",
  "session_metadata_json": "<exact canonical session metadata JSON>",
  "session_digest": "<lowercase SHA-256 hex>",
  "events_ndjson": "<complete audit event log>"
}
```

The client sends these authentication headers:

```text
X-Nono-Protocol-Version: 1
X-Nono-Subject-Id: <enrolled subject>
X-Nono-Timestamp: <Unix milliseconds>
X-Nono-Request-Id: <ingest UUID>
X-Nono-Content-SHA256: sha256:<lowercase hex digest of exact body bytes>
X-Nono-Signature: p256-sha256:<base64url fixed-width ECDSA signature>
```

The bytes signed are UTF-8:

```text
nono-request-v1
POST
/api/v1/audit/ingest
<subject_id>
<timestamp_ms>
<request_id>
<body_digest>
```

The server must reject unsupported versions, stale timestamps, modified
bodies, unknown or revoked subjects, tenant mismatches, and reuse of a request
ID with different content. Repeating the same authenticated request ID and
body is idempotent and returns the original acceptance receipt.

## Canonical session digest

`session_metadata_json` contains the exact UTF-8 JSON bytes returned by
`nono::audit::canonical_session_digest_payload`. A verifier must not parse and
reserialize this value before hashing it.

The session digest is:

```text
SHA-256(
  "nono.audit.session-digest.alpha\n" ||
  UTF-8(session_metadata_json)
)
```

`session_digest` is the lowercase hexadecimal encoding of that digest. The
canonical payload commits to the session identity and timestamps, redacted
command, executable identity, tracked paths, snapshot state, exit code,
network events, audit integrity summary, and optional local attestation
summary.

Early v1 clients emitted envelopes without `session_metadata_json` and
`session_digest`. A v1 receiver must accept that legacy form for durable retry
compatibility. The two fields must otherwise be supplied together. Evidence
without them can still have its event chain and Merkle root verified, but an
independent verifier cannot validate the complete session metadata digest.

## Receipt and verification

An accepted v1 receipt identifies the ingest and session, reports the accepted
event count and object path, and has `verification_status: "pending"`.
Acceptance means that the platform authenticated and durably stored the
submission. It does not mean the evidence has been verified.

The platform independently recomputes the event chain, Merkle root, and, when
present, the canonical session digest. Final verification state and any
platform attestation are exposed through the platform's audit query APIs
rather than by changing the original acceptance receipt.

## Durable retry

The client writes the complete envelope and request ID to its local outbox
before attempting network delivery. Retries preserve both values exactly.
After enrollment, `nono audit sync` also discovers finalized local sessions
that have neither an outbox entry nor a platform receipt and reconstructs the
missing outbox item. Sessions completed before enrollment are not backfilled
automatically.
