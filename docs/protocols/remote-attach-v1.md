# Remote terminal attach protocol v1

This document specifies the open WebSocket contract used by `nono connect` to
discover nono-console and attach a local terminal to a hosted session. It does
not define session launch, fleet policy, or local sandbox enforcement.

## Console discovery

When `--console` is absent, an enrolled device asks its configured platform for
the nono-console origin:

```text
GET /api/v1/console
X-Nono-Protocol-Version: 1
X-Nono-Subject-Id: <enrolled device UUID>
X-Nono-Timestamp: <Unix milliseconds>
X-Nono-Request-Id: <one-time UUID>
X-Nono-Content-SHA256: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Nono-Signature: p256-sha256=<base64url signature>
```

The content digest is SHA-256 of the empty request body. The P-256 signature
covers the existing canonical enrolled-request payload:

```text
nono-request-v1
GET
<exact request path>
<subject id>
<timestamp>
<request id>
<body digest>
```

The platform accepts active enrolled devices only, derives the tenant from the
authenticated subject, enforces bounded freshness, and durably consumes the
request ID once. Missing, modified, stale, replayed, workload-signed, or
revoked-subject requests fail closed.

A successful response is:

```json
{
  "protocol_version": "1",
  "tenant_id": "019f0000-0000-7000-8000-000000000001",
  "console_url": "https://console.example.com"
}
```

The client requires `protocol_version: "1"` and requires `tenant_id` to equal
its protected enrollment state. `console_url` must be an absolute `https://`
origin without credentials, query parameters, or fragments. Plain `http://` is
accepted only for an explicit loopback address. A URL path prefix is preserved.

Discovery authenticates a device and selects infrastructure; it does not prove
human identity and does not authorize session listing or attachment. Those
operations still require a separate human access token. `--console` remains an
explicit development and support override.

## Human device authorization

When no explicit human token is configured, an enrolled device obtains a
revocable CLI authorization without copying the browser session cookie. All
CLI requests below use the same enrolled-request signature headers as console
discovery, with the exact method, path, request body digest, and a fresh
one-time request UUID.

The device starts the flow with an empty signed request:

```text
POST /api/v1/auth/device/code
```

The platform returns protocol version `1`, a high-entropy `device_code`, a
short `user_code`, `verification_path: "/platform/device"`, `expires_in: 600`,
and a bounded polling `interval`. The CLI constructs the verification URL from
its enrolled platform origin; it never trusts the HTTP Host header as a public
origin.

After normal browser authentication, the human submits the displayed code:

```text
POST /api/v1/auth/device/authorize
{"protocol_version":"1","user_code":"ABCD-EFGH","decision":"approve"}
```

The platform resolves both user and tenant from the authenticated browser
session. Approval succeeds only when that tenant equals the enrolled device's
tenant. A denial uses `decision: "deny"` and is terminal.

The CLI polls with a signed JSON request:

```text
POST /api/v1/auth/device/poll
{"protocol_version":"1","device_code":"<secret>"}
```

Pending responses carry `status: "authorization_pending"`. The first approved
poll durably creates the authorization and returns `status: "authorized"`, a
random opaque `credential`, and its expiry. A retry during the original
ten-minute code lifetime returns that same credential so a lost HTTP response
does not strand the approval. Expired, denied, modified, replayed,
wrong-device, wrong-tenant, workload-signed, or revoked-device requests fail
closed without revealing whether another tenant's code exists.

The credential is not a console token. It is bound server-side to the human,
tenant, and enrolled device, is stored only as a digest by the platform, and
may be cached locally in a mode-0600 state file. Before each connection the CLI
uses a fresh signed request and presents the credential in the Authorization
header:

```text
POST /api/v1/auth/device/access-token
Authorization: Bearer <opaque CLI authorization>
```

The platform rechecks the active device, user, tenant, membership, and current
role, then returns a new five-minute, `nono-console`-audience access token. A
copied cache file is insufficient without the enrolled device key. Explicit
`--token-file` and `NONO_CONNECT_TOKEN` values remain operator overrides and do
not enter this flow.

After a newly approved credential has been cached and successfully exchanged,
the CLI reports `Terminal authorized.` A cached authorization is normally
silent. `nono ps --remote` performs the same authorization and discovery flow,
lists the sessions visible to that human, and exits successfully without
attaching a terminal.

## Session listing

The CLI lists the authenticated human's console sessions with:

```text
GET /api/v1/sessions
Authorization: Bearer <short-lived console access token>
```

The response is an object containing a `sessions` array. Each entry includes a
globally unique `global_session_id`, the backend status, and optional runtime,
agent, and repository metadata. The fields consumed by protocol v1 are:

```json
{
  "sessions": [
    {
      "global_session_id": "local:host:019f0000-0000-7000-8000-000000000003",
      "backend_status": "ready",
      "record": {
        "name": "tall-edge",
        "status": "running",
        "command": ["claude"]
      },
      "agent": { "name": "Claude Code" },
      "repo": null
    }
  ]
}
```

Additive fields are allowed. By default `nono ps --remote` and the interactive
`nono connect` picker show only entries whose backend is `ready` and whose
runtime record is `running`. `nono ps --remote --all` retains inactive entries;
`--json` emits the client-consumed protocol fields for automation. Listing and
attaching accept the same `--console` / `NONO_CONSOLE_URL` discovery override
and `--token-file` / `NONO_CONNECT_TOKEN_FILE` credential override.

## Authentication and transport

The client connects to:

```text
GET /api/v1/sessions/{global_session_id}/terminal
Upgrade: websocket
Sec-WebSocket-Protocol: nono.terminal.v1
Authorization: Bearer <human access token>
```

Authentication is never carried in the URL. The bearer token identifies a
human subject, tenant, scopes, expiry, and token/session ID. Device enrollment
is a distinct identity and must not be treated as proof of a human identity.
A later hardening revision may additionally bind the upgrade to the enrolled
device key without replacing human authorization.

Non-loopback connections must use `wss://` with normal certificate validation.
A client may trust a configured private CA, but must not offer an insecure TLS
mode. Plain `ws://` is permitted only for explicit loopback development.

The client offers `nono.terminal.v1` as the WebSocket subprotocol. A server that
does not support v1 rejects the upgrade rather than silently selecting another
protocol.

## Frames

Binary frames are raw PTY bytes:

- client to server: keyboard/input bytes;
- server to client: PTY output bytes.

Text frames are UTF-8 JSON control messages. Every client control message
carries `protocol_version: "1"`. Unknown message types or unsupported versions
produce an `error` control frame; malformed frames never widen access.

### Resize

Client to server, sent once after connection and whenever the local terminal
size changes:

```json
{
  "type": "resize",
  "protocol_version": "1",
  "cols": 120,
  "rows": 40
}
```

Both dimensions are unsigned 16-bit values and must be non-zero.

### Detach

Client to server:

```json
{
  "type": "detach",
  "protocol_version": "1"
}
```

Detach closes this attachment only. It must not stop the hosted session.

### Attached

Server to client after the backend attachment is ready:

```json
{
  "type": "attached",
  "protocol_version": "1",
  "cols": 120,
  "rows": 40
}
```

The client must not describe the session as attached before receiving this
message.

### Session ended

Server to client when the hosted session has ended:

```json
{
  "type": "session_exited",
  "exit_code": 2
}
```

`exit_code` is the hosted session process status, not the status of an
intermediate attach helper. It may be null only when the backend genuinely
cannot establish the outcome. A command-line client should return success for
zero, the reported non-zero status where its operating system supports it, and
failure for an unknown outcome.

### Error

Server to client before closing an established WebSocket:

```json
{
  "type": "error",
  "code": "attach_busy",
  "message": "session already has a writer"
}
```

Messages must not include credentials, authorization headers, captured input,
or other secrets.

## Session listing

The interactive picker uses the console's existing authenticated endpoint:

```text
GET /api/v1/sessions
Authorization: Bearer <human access token>
```

The client displays only live sessions returned for the token's server-derived
tenant. A browser-controlled tenant value is never accepted.

## Read-only and multiple attachments

The reserved query `?mode=read_only` requests a watcher that cannot send PTY
input. A server without fan-out support must reject this mode explicitly.
For writable attachments v1 permits exactly one writer; a second writer is
refused with `attach_busy`. Writer stealing is not implicit.

## Current implementation boundary

The implementation supports one writable attachment. Enrolled devices discover
the configured console origin and, unless an explicit token override is used,
complete browser-approved human authorization and exchange the cached,
device-bound credential for a short-lived console bearer token. Device-key
upgrade binding, private CA bundles, dedicated authorization management, and
read-only fan-out are follow-up work. These absences must be surfaced to the
caller and must not be replaced with an unenrolled shared secret or an insecure
TLS flag.
