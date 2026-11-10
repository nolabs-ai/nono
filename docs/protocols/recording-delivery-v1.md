# Recording delivery protocol v1

This document specifies how `nono` uploads a session's terminal recording
([NEP-0010](../../neps/0010-session-terminal-capture.md)) to the control plane
the host is enrolled with. It reuses the enrollment identity and request
signing of [audit delivery v1](audit-delivery-v1.md).

A recording is a sequence of zstd-compressed asciicast v2 chunks. Each closed
chunk is committed to the session's hash-chained audit log by a
`terminal_chunk` event. The client uploads each chunk as it closes, so a
receiver can show a running session about one chunk window behind.

## Upload a chunk

```http
POST /api/v1/audit/recordings/chunks
Content-Type: application/json
```

```json
{
  "tenant_id": "<tenant>",
  "session_id": "<audit session>",
  "shipper_id": "<enrolled subject>",
  "chunk": {
    "index": 0,
    "seq_start": 0,
    "seq_end": 5,
    "start_offset_us": 0,
    "end_offset_us": 213612,
    "audit_seq_start": 1,
    "audit_seq_end": 1,
    "raw_bytes": 569,
    "stored_bytes": 331,
    "sha256": "<lowercase SHA-256 hex of the stored bytes>",
    "credential_redactions": 0,
    "suppressed_inputs": 0
  },
  "data_base64": "<stored chunk bytes, standard base64>"
}
```

- `session_id` is the audit session ID, the same ID the session's audit log
  is delivered under.
- `chunk` carries exactly the fields of the chunk's `terminal_chunk` event.
- The request carries the audit delivery v1 authentication headers. The
  signature covers the body digest, so it covers the chunk bytes.

The receiver must:

- authenticate the request and require `tenant_id` and `shipper_id` to match
  the authenticated subject;
- check that the decoded bytes have the stated size and SHA-256, and that they
  decompress to exactly `raw_bytes`;
- store the bytes durably before answering;
- treat an identical repeat as success, and a different chunk at an index
  already stored as `409 Conflict`;
- refuse chunks for a session that another subject started uploading.

A successful answer is a receipt:

```json
{
  "session_id": "<audit session>",
  "index": 0,
  "received_at": "<RFC 3339 timestamp>",
  "status": "provisional"
}
```

## Verification

An uploaded chunk is a claim. The receiver marks it `verified` only after the
session's audit log has been delivered and verified, and the chunk's
`terminal_chunk` event there has the same fields and hash, from the same
subject. A chunk that differs, or that the verified log does not reference,
is `integrity_failed`. A chunk that arrives after the log was verified is
checked when it arrives.

## Client behaviour

- Chunks are uploaded in index order, off the capture path. Capture never
  waits on delivery.
- The client reads each chunk from the session's protected recording
  directory and checks it against its record before sending.
- `408`, `425`, `429` and `5xx` answers and network errors are retried with
  backoff up to 30 seconds. Other answers are final for that chunk.
- At session end the client waits up to the configured flush timeout
  (default 30 seconds). When delivery is required, chunks that were refused
  or are still undelivered make the session exit with status 74.
- Chunks that were not delivered remain in the local recording.
