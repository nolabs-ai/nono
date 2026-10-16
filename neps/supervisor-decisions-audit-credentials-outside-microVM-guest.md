---
nep: 0007
title: Supervisor decisions, audit and credentials outside a microVM guest
authors:
  - Luke Hinds
status: draft
created: 2026-10-16
superseded-by:
---

# NEP-0007: Supervisor decisions, audit and credentials outside a microVM guest

## Summary

Let nono split its supervisor across a virtual-machine boundary. Enforcement
(Landlock, seccomp, the seccomp user-notify handler) stays in the guest next
to the sandboxed process; approval decisions, the audit ledger and credential
injection move to a host-side nono component reached over vsock. The guest
never holds the policy authority, the audit history or the credentials, so a
full guest compromise does not yield them.

This work should position nono to run on projects such as agent-substrate/substrate
and google/ax, along with strengthening nono's security posture in other microVM-based deployments.

## Motivation

[security-model.mdx](https://nono.sh/docs/cli/internals/security-model) recommends
putting nono inside a microVM for hostile-code and multi-tenant deployments
("Composing with an outer boundary"). Today that composition is all-or-nothing:
the whole supervisor runs in the guest. If an attacker escapes Landlock and
seccomp through a guest kernel bug, they own the guest, and with it:

- the credentials the supervisor or its proxy hold (in guest memory, and in
  every memory snapshot of the guest);
- the network egress policy (the attacker controls the guest network stack);
- the audit log (it can be rewritten or suppressed before it leaves the guest);
- every approval decision (the attacker can answer its own requests).

Orchestrated agent platforms make this concrete. On Agent Substrate (Kata
microVMs on Cloud Hypervisor, driven by Kubernetes), actors are suspended,
snapshotted to object storage, restored and moved between worker pods many
times over their life, and thousands of them run per cluster. Anything kept in
guest memory is copied into snapshot storage. Firecracker-based systems have
the same shape.

The supervisor cannot simply be moved out of the guest: its enforcement half
depends on primitives that only exist in the guest kernel (the seccomp notify
fd, `/proc/PID/mem`, `SECCOMP_IOCTL_NOTIF_ADDFD`, `SCM_RIGHTS`, `SO_PEERCRED`).
But its decision half already sits behind a narrow interface: the
`ApprovalBackend` trait takes a serializable `ApprovalRequest` and returns an
`ApprovalDecision`. Decisions can cross a VM boundary; file descriptors never
need to.

### Goals

- A host-side nono component can decide a guest supervisor's approval requests
  over vsock, with all enforcement unchanged in the guest.
- The caller's identity comes from the transport (the per-VM vsock socket),
  never from anything the guest sends.
- Decisions and their delivery are recorded in a host-side, hash-chained audit
  ledger that the guest cannot reach, and that stays one chain per sandboxed
  workload across host-side restarts and workload moves on one host.
- Credentials can be held and injected on the host, with the guest given only
  a placeholder ("phantom") value and a vsock path to the host-side proxy.
- Works with VM snapshot/restore and live relocation: a decision pending at
  suspend completes after resume, on whichever host the guest lands on.
- A slow remote decision never stalls the rest of the sandbox.
- Everything is opt-in; existing users see no change.

### Non-Goals

- Moving enforcement out of the guest. Landlock and seccomp stay in the guest
  as defence in depth; this NEP does not treat the VM as a replacement.
- Dynamic host-file grants (exposing new host paths to the guest at runtime
  via virtio-fs or hotplug). Different problem, weakest payoff.
- Interactive human approval from the host. The protocol carries any
  `ApprovalRequest`, but this NEP targets automatic policy decisions.
- macOS hosts running Seatbelt workloads. The guest side is Linux-only (it
  relies on Landlock and seccomp user-notify). A macOS host running Linux
  guests under Virtualization.framework (which offers vsock) is an Open
  Question, not a goal.
- Multi-host audit ledgers (one chain across nodes). See Open Questions.
- Platform-specific integration code in nono (Kubernetes, Substrate CRDs).

## Proposal

The design has four parts: a wire protocol in the library, a guest-side
backend and concurrency change in the CLI, an audit extension in the library,
and a host-side component. A spike implementing all four ran on Agent
Substrate microVMs; results are summarised under "Evidence" below.

### 1. Wire protocol (`nono` library, mechanism)

A new module `nono::supervisor::remote` defines the messages and framing,
independent of transport:

```rust
pub const REMOTE_PROTOCOL_VERSION: u32 = 2;     // 1 = request/response, 2 = + ack
pub const REMOTE_PROTOCOL_MIN_VERSION: u32 = 1;

pub struct RemoteApprovalRequest  { pub version: u32, pub request: ApprovalRequest }
pub struct RemoteApprovalResponse { pub request_id: String, pub decision: ApprovalDecision }
pub struct RemoteApprovalAck      { pub request_id: String }   // v2+

pub fn write_message<W: Write, T: Serialize>(w: &mut W, m: &T) -> Result<()>;
pub fn read_message<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T>;
```

Framing is the existing `SupervisorSocket` encoding: a 4-byte big-endian
length and a JSON payload, capped at 64 KiB, with `deny_unknown_fields`. It
works over any `Read`/`Write` stream and never passes file descriptors.

Exchange: the requester sends a request; the decider answers with a response
carrying the same `request_id`; from v2 the requester acknowledges each
response it accepts. A decider answers v1 requesters without expecting an ack.

### 2. Guest side (`nono-cli`)

**A `vsock` approval backend type.** Configured like the existing webhook and
chain backends:

```json
"security": {
  "capability_elevation": true,
  "approval_backends": {
    "host": { "type": "vsock", "url": "vsock://2:10243", "timeout_secs": 60 }
  },
  "approval_defaults": { "backend": "host" }
}
```

Behaviour:

- Connections are opened lazily (no connection exists when a VM is
  snapshotted before first use, e.g. a template "golden" snapshot).
- Each request in flight uses its own connection from a small idle pool, so
  concurrent requests never queue behind each other.
- On any connection failure (connect error, EOF, broken pipe, timeout) the
  backend reconnects with backoff and re-sends the request with the same
  `request_id` until a per-request deadline (`timeout_secs`, default 60 s).
- Responses for other request IDs (late answers to an earlier attempt) are
  skipped, up to a bound; then the stream is treated as broken.
- After accepting a matching response it sends the v2 acknowledgement
  (best effort).
- Deadline expiry returns `ApprovalDecision::Timeout`; every non-`Granted`
  outcome is a denial, as today.

**Concurrent decisions in the Linux supervisor.** The supervisor handles
seccomp notifications on one thread and today calls the backend
synchronously, so one slow decision stalls every other trapped `openat` in
the sandbox (on Substrate this blocked the readiness probe and therefore
resume). This NEP adds a library trait method:

```rust
pub trait ApprovalBackend: Send + Sync {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision>;
    fn backend_name(&self) -> &str;
    /// Whether request_approval may run for several requests at once.
    fn supports_concurrent_requests(&self) -> bool { false }
}
```

The terminal backend keeps `false` (prompts share the TTY and pause the PTY
relay); the webhook backend keeps `false` for now; `vsock` returns `true`; a
chain is concurrent only if all its members are.

For a concurrent backend, everything up to the decision is unchanged and stays
on the supervisor thread (path read, liveness check, local policy, protected
roots, deny paths, rate limiter, trust interceptor). The backend call alone
moves to a worker thread. The result returns over a channel and wakes the
supervisor's `poll()` loop through a socket pair. The supervisor thread then
does everything that touches the notify fd itself — audit, the second
`notif_id_valid` check, `open_path_for_access`, `inject_fd`, or deny — in one
function shared with the synchronous path. Workers never touch the notify fd.
Beyond 64 decisions in flight the supervisor falls back to deciding
synchronously.

**Guest egress to the host-side proxy.** The guest needs a local endpoint
(e.g. `127.0.0.1:3128`) that forwards to vsock CID 2, a configured port, so a
sandboxed workload restricted to that endpoint can reach the host-side
credential proxy. The spike used a small bridge outside the sandbox; this NEP
proposes building it into nono (see Open Questions for the shape).

### 3. Audit (`nono` library, mechanism)

**Shared, resumable chains.** `AuditRecorder::open_shared(session_dir)`
opens an existing log and continues its chain. Before every append it takes
an exclusive `flock` on the log, then reads and verifies any records other
writers appended since its last append (sequence, previous chain hash, leaf
hash over the canonical event JSON, chain hash), folds them into its state,
and appends. A truncated or non-verifying record is an error and nothing is
appended after it. Writers on one host therefore extend a single linear chain.
`AuditRecorder::new` is unchanged.

**Acknowledgement event.** A new payload variant:

```rust
AuditEventPayload::DecisionAcknowledgement {
    request_id: String,
    acknowledged: bool,
    decider: String,
}
```

A decider audits the decision *before* sending it (if that fails, it sends a
denial instead — fail closed), then appends the acknowledgement:
`acknowledged: true` when the requester's ack arrived, `false` when the send
failed, the ack timed out or the link dropped. `false` means delivery is
unknown, not that the decision was not applied.

### 4. Host side (new nono component)

A host-side component (the spike's `vsock_decider`; final shape is an Open
Question) that, per VM:

- **Listens** on the hybrid-vsock host socket for the guest's decision port
  (Firecracker and Cloud Hypervisor map a guest connection to vsock port N
  onto `<vm socket>_N`), one thread per connection.
- **Derives identity from the socket path** (on Substrate,
  `/run/vc/vm/<actor_uid>/clh.sock_N`), and ignores identity claims in
  requests (`session_id`, `child_pid`).
- **Decides** by evaluating host-side policy for that identity.
- **Audits** decisions and acknowledgements into
  `<audit-dir>/<identity>/` via `open_shared`.
- **Optionally runs a per-VM credential proxy**: starts a dedicated
  `nono proxy` on a free loopback port and bridges the VM's proxy vsock port
  to it. Identity is the socket, so the proxy runs `--no-auth` on loopback and
  serves exactly one VM. A domain allowlist is mandatory: without one, the
  host side refuses to start the proxy (`nono proxy` without an allowlist
  tunnels CONNECT to any host).
- **Stops** serving a VM when its socket goes away.

For platforms where the host side must be a container entrypoint, it can run
as PID 1: start the platform's original entrypoint as a child, forward
SIGTERM/SIGINT, reap, exit with the child's status, and start children with a
clean signal mask (a Go entrypoint keeps an inherited mask and would never see
SIGTERM).

### Library/CLI split

| Piece | Location | Why |
|---|---|---|
| `supervisor::remote` wire types and framing | `nono` | Mechanism, used by both sides; no policy |
| `ApprovalBackend::supports_concurrent_requests` | `nono` | Trait capability flag, default preserves behaviour |
| `AuditRecorder::open_shared`, `DecisionAcknowledgement` | `nono` | Audit mechanism |
| `vsock` backend, concurrent dispatch, profile config | `nono-cli` | Runtime and policy wiring |
| Host-side decider, policy evaluation, proxy orchestration | `nono-cli` (or a new crate) | Policy and UX |

### Platforms

- **Linux guest:** as above. Landlock and seccomp semantics are unchanged; no
  deny-within-allow is introduced.
- **macOS:** not applicable to Seatbelt workloads. Nothing changes for macOS
  users; the `vsock` backend type is rejected at runtime on non-Linux.
- **Hosts:** any VMM exposing hybrid vsock (Firecracker, Cloud Hypervisor).

### Backward compatibility

All opt-in. Without a `vsock` backend in the profile nothing new runs:
existing backends report `supports_concurrent_requests() == false` and keep
the synchronous path; `AuditRecorder::new` is unchanged; the new audit event
appears only in logs written by a decider. Older nono versions reading a log
containing `DecisionAcknowledgement` will not recognise the variant; the
verifier test covering all payload variants is updated.

### Validation performed

On a local kind cluster running unmodified Agent Substrate (Kata guest kernel
6.18, Cloud Hypervisor), with the host side packaged into a worker image based
on Substrate's own:

- A trapped `openat` whose decision was pending when the actor was suspended
  completed after resume on a different worker: the guest re-sent the same
  `request_id` to the new worker's host side.
- With a decision held 25 s on the host, `/readyz` answered in 10–18 ms and
  suspend+resume took 1.3–1.4 s (previously blocked ~50 s).
- An actor moved across worker pods kept one verified, acknowledged audit
  chain in the node's shared directory.
- The guest sent a phantom token; the upstream received the real key, which
  existed only on the host; the guest learned only a fingerprint; direct
  egress from the guest failed.
- On gVisor (no Landlock), nono refused to start, so nothing ran unsandboxed.

## Security Considerations

**Least privilege.** The sandboxed process gains nothing: enforcement in the
guest is unchanged and every decision the host makes is about authority the
guest kernel enforces anyway. What changes is where authority lives. A full
guest compromise no longer yields credentials (never in the guest or its
snapshots), the audit history (written on the host) or host-enforced egress
(the host proxy and its allowlist). It still yields in-guest file access: a
compromised guest kernel can skip asking. Decisions about in-guest resources
are therefore only as strong as the guest kernel; decisions about
host-enforced resources (egress, credentials) are not.

**Fail-secure behaviour.**

- Decider unreachable, slow or gone: the request is re-sent until the
  deadline, then `Timeout`, which is a denial. With no decider listening the
  VMM resets the guest's connection.
- Host cannot audit a decision: it sends a denial instead.
- Host-side proxy cannot start, or no allowlist configured: no proxy, so the
  guest has no egress path.
- Concurrency limit reached or worker thread cannot start: synchronous
  decision, never a skipped one.
- Truncated or tampered audit log: `open_shared` and appends fail; nothing is
  written past the bad record.
- Unsupported platform: `vsock` backend errors on non-Linux.

**Transport identity and confused deputy.** Everything in a request is
attacker-controlled once the guest is compromised: paths, PIDs, session IDs,
reasons. The host side takes identity only from which per-VM socket the
connection arrived on, and must treat request fields as claims ("the guest
wants X"), never as proof. Guest-generated identifiers are also unreliable for
another reason: every clone of a VM snapshot starts with identical memory, so
userspace random state, nono session IDs and request-ID counters repeat across
clones (observed on Substrate; the guest kernel reseeds, userspace does not).
Host-side identity must not depend on them.

**Listener authentication.** The host socket path must be owned by the VMM's
jailer or the platform runtime and reachable only by the host side; any other
local process that can connect could obtain decisions. On Substrate the socket
lives in the worker container's private filesystem. Deployments must verify
this, and the host side should refuse to serve a socket it cannot attribute to
one VM.

**Concurrency.** Worker threads only call the backend; all actions on the
seccomp notify fd stay on the supervisor thread, so a worker can never act on
a closed or reused fd. The second `notif_id_valid` check still runs
immediately before acting.

**Denial of service.** A compromised guest can flood requests or hold
connections. The existing rate limiter runs before the backend; the in-flight
cap bounds worker threads; the host side needs per-VM limits on connections
and request rate (TBD).

**Audit integrity.** The host-side ledger is out of the guest's reach but is
still local host state, with the limits in "Audit Integrity Limits". Records
other writers appended are verified before a writer extends the chain. Two
honest-but-imperfect properties must be documented: completeness depends on
the guest asking (a compromised guest can stay silent), and
`acknowledged: true` means the guest supervisor received the decision, not
that the fd was injected.

**Credential & secret secrecy.** Credentials stay in the host-side proxy,
loaded through nono's existing credential sources (zeroizing types, redaction
in logs). They never enter the guest's environment, memory or snapshots. The
phantom value given to the guest is not a secret: it authenticates nothing,
since identity is the socket. Echoing a credential back to the guest (e.g. an
upstream reflecting headers) is outside nono's control and must be considered
in route design.

**Host-side privilege.** The host side runs with whatever privilege the
platform gives the VMM's environment (on Substrate, root inside the worker
container with its capabilities). Its parsers are the same memory-safe serde
framing as today's supervisor IPC. Its blast radius is the VMs on that host.

**Library/CLI boundary.** The library gains mechanism only (wire types,
framing, a trait flag, audit primitives). Policy evaluation, proxy
orchestration and configuration stay in `nono-cli` or the host component.

**Deployment conditions.** The guarantees above hold only if:

1. The host side is the guest's only egress path (no other guest network
   route, or a platform egress policy that refuses everything else). Note
   that some platforms exempt DNS.
2. In-guest Landlock and seccomp stay enabled.
3. Shares into the guest (virtio-fs) are as narrow as capabilities would be.
4. The host listener is authenticated as above.
5. Guest-reported context is treated as untrusted.

## Alternatives Considered

**Move the whole supervisor to the host.** Impossible: the seccomp notify fd,
`/proc/PID/mem`, fd injection, `SCM_RIGHTS` and `SO_PEERCRED` are guest-kernel
objects.

**Decide over the network instead of vsock** (an HTTPS approval API reached
through the platform's egress gateway, identity from the gateway's mTLS actor
certificate). Works without VMM integration, but requires guest networking,
puts decisions on the data path of an egress gateway, and does not cover
standalone VMs with no network device. vsock is the only channel that exists
in every VM deployment and gives transport identity directly.

**Credential injection in the platform's egress gateway** (e.g. Substrate's
`replace_headers` with its credential provider). Keeps secrets in the
platform, but supports header substitution only (no SigV4, OAuth2 exchange,
method/path rules) and is platform-specific. The proposed design can compose
with it; see Open Questions.

**nono-proxy inside the guest.** Fully protects against a sandboxed agent
that stays inside Landlock, but credentials sit in guest memory and snapshots
and are lost on guest kernel compromise.

**A single multiplexed connection instead of a pool.** Fewer sockets, but
head-of-line blocking and more complex failure handling on a link that is
expected to break at every suspend.

