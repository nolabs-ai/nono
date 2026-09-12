# Approval webhook protocol v1

This document specifies the open contract between `nono` and an HTTP approval
endpoint. When a policy decision is `approve`, `nono` pauses the sandboxed
action, asks the endpoint, and applies exactly one of three outcomes: granted,
denied, or timed out. Timeouts and every error are treated as denial.

There are two variants of the contract:

- **Unsigned.** One blocking `POST`; the response body is the decision. Any
  HTTP service can implement it. Configure with `type: "webhook"` and a `url`.
- **Signed.** For a client enrolled with a control plane (see
  [Audit delivery protocol v1](audit-delivery-v1.md) for enrollment). Requests
  are authenticated with the enrolled key, the tenant is derived server-side,
  and the exchange is submit-then-poll so the server may hold requests durably
  across replicas. Configure with `type: "webhook"` and `auth: "platform"`.

## Configuration

```json
{
  "command_policies": {
    "approval_backends": {
      "review": { "type": "webhook", "url": "https://approvals.example.com/hook", "timeout_secs": 60 },
      "platform": { "type": "webhook", "auth": "platform", "timeout_secs": 120 }
    },
    "approval_defaults": { "backend": "platform" }
  }
}
```

| Field | Meaning |
| --- | --- |
| `url` | Endpoint to call. Required for unsigned backends. With `auth: "platform"` it defaults to `<enrolled platform URL>/api/v1/approvals`, and if given must be `https://`, or `http://` to a loopback host. |
| `auth` | Omit for unsigned. `"platform"` selects the signed variant and fails closed if the client is not enrolled. |
| `timeout_secs` | Total time this backend waits for a decision (default 60). It is also sent to the server as the hold hint. |

## Request

Both variants `POST` the same JSON body:

```json
{
  "backend": "<backend name from the profile>",
  "request": { "capability_type": "endpoint", "request_id": "...", "session_id": "...", "...": "..." }
}
```

`request` is the `ApprovalRequest`, internally tagged by `capability_type`.
`request_id` is unique per request and is the identity the server keys on;
`session_id` identifies the sandboxed session. The variants are:

| `capability_type` | Fields |
| --- | --- |
| `capability` | `path`, `access` (`Read`, `Write`, `ReadWrite`) |
| `network` | `host`, `port`, `protocol`, `resolved_ips` |
| `endpoint` | `route_id`, `upstream`, `method`, `path`, `rule_label` |
| `command` | `command`, `args`, `caller`, `intercept_rule` |

Every variant also carries `request_id`, `session_id`, `reason` (nullable), and
`child_pid`.

Headers on every request, in both variants:

```text
Content-Type: application/json
User-Agent: nono-cli/<version>
X-Nono-Timeout-Secs: <seconds>
```

`X-Nono-Timeout-Secs` is the client's remaining patience. On the first request
it equals `timeout_secs`; on each signed poll it is what is left. A server
should hold a request open for no longer than this value minus a small margin,
so it answers before the client gives up.

The client never follows redirects. A `3xx` response is a denial.

## Unsigned variant

The endpoint answers the `POST` with `2xx` and a JSON body:

```json
{ "decision": "granted" }
{ "decision": "denied", "reason": "why" }
{ "decision": "timeout" }
```

Accepted spellings for `decision` are `grant`, `granted`, `approve`,
`approved`, `allow`, `allowed`; `deny`, `denied`, `reject`, `rejected`,
`block`, `blocked`; and `timeout`, `timed_out`. Any other value is an error and
therefore a denial. A non-`2xx` status is a denial whose reason names the
status and the elapsed time. The connection stays open until the endpoint
answers or `timeout_secs` elapses.

## Signed variant

### Authentication

Each request carries the `nono-request-v1` headers defined in
[Audit delivery protocol v1](audit-delivery-v1.md):

```text
X-Nono-Protocol-Version: 1
X-Nono-Subject-Id: <enrolled subject>
X-Nono-Timestamp: <Unix milliseconds>
X-Nono-Request-Id: <UUID, fresh per HTTP request>
X-Nono-Content-SHA256: sha256:<lowercase hex digest of the exact body bytes>
X-Nono-Signature: p256-sha256=<base64url fixed-width ECDSA signature>
```

The signed string is unchanged from the audit protocol:

```text
nono-request-v1
<METHOD>
<path as the server sees it>
<subject_id>
<timestamp_ms>
<request_id>
<body_digest>
```

The poll is a bodiless `GET`, so its digest is the SHA-256 of zero bytes,
`sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
`tests/fixtures/approval-poll-request-v1.json` is a worked example.

`X-Nono-Request-Id` is a transport nonce and is distinct from the approval's
`request_id` in the body. The server must consume each transport nonce once
and reject reuse; it must accept a repeated body `request_id` from the same
subject as an idempotent retry of the same approval.

### Submit

```http
POST /api/v1/approvals
```

The server verifies the signature, derives the tenant from the enrolled
subject, records the request, and holds the connection for up to
`min(X-Nono-Timeout-Secs - margin, its own cap)` waiting for a decision. It
answers:

- `200` with a final status when a decision exists, including an immediate
  decision from a standing grant;
- `202` with `state: "pending"` when the hold expires without a decision.

### Poll

```http
GET /api/v1/approvals/{request_id}
```

Same authentication and hold semantics. Only the subject that submitted the
request may poll it; the server answers `404` for any other subject or an
unknown id. The client repeats the poll until a final state or its own
deadline. The client bounds each HTTP request by its remaining budget and
re-checks the deadline after every response, so a decision that arrives after
`timeout_secs` is never applied.

### Status body

```json
{ "request_id": "<body request_id>", "state": "pending" }
{ "request_id": "<body request_id>", "state": "granted", "decision": "granted" }
{ "request_id": "<body request_id>", "state": "denied", "decision": "denied", "reason": "why" }
{ "request_id": "<body request_id>", "state": "timeout", "decision": "timeout", "reason": "..." }
```

`state` is one of `pending`, `granted`, `denied`, `timeout`. `decision`
repeats the final `state` so the body also satisfies the unsigned parser.
`tests/fixtures/approval-status-v1.json` lists the accepted shapes and the
decision each produces.

### Server requirements

- Reject unsupported protocol versions, timestamps outside a short skew
  window, modified bodies, unknown or revoked subjects, and reused transport
  nonces with `401`.
- Derive the tenant from the verified subject. Never trust tenant or subject
  identifiers from the body.
- Accept only subjects enrolled as workloads. A device enrollment identifies a
  person's machine, not a policy-enforcing run.
- Make the request durable before answering, and resolve it with exactly one
  decision. A request past the client's deadline must become `timeout` and
  refuse a later decision.
- Fail secure: when in doubt, answer `denied` or let the client time out.

A server may additionally remember a "for this session" grant keyed on the
verified subject, the body `session_id`, and the exact capability, and answer a
matching repeat with `granted` without a human. Such a grant must never widen
to a different method, path, host, or command.
