---
nep: 0010
title: Session terminal capture
authors:
  - lukehinds
status: accepted
created: 2026-11-03
breaking: false
superseded-by:
---

# NEP-0010: Session terminal capture

## Summary

Let the nono supervisor capture what a session showed and was told: its
terminal output, the input sent to it, and the terminal facts around them.
nono keeps this as a tamper-evident recording linked into the audit log, and
can deliver it, durably and live, to an external receiver over open
protocols. nono captures, protects and delivers. It does not analyse the
content. NEP-0008 records what an agent *did*. This NEP records what the
session *showed and was told*, on the same timeline.

## Implementation status

Unimplemented as of 2026-11-03. The PTY proxy already keeps an attach
scrollback and a vt100 screen model. Neither is persisted or delivered.
`breaking` is unassessed.

## Motivation

The supervisor sits between the agent and its terminal, or its standard
streams. It sees every byte the agent prints and every byte sent back to it.
Today that stream feeds attach replay and is then discarded. That leaves
three gaps:

- **Debugging unattended sessions.** A detached session, or one on a CI
  runner or a cloud host, that fails leaves an exit code and an audit log of
  access decisions. Nothing shows what the agent printed, what it said it was
  doing, or the error it reported before it went wrong.
- **Audit of the conversation.** Operators need a record of what an agent
  displayed and what it was told, to the same integrity standard as the rest
  of the audit log, and reviewable away from the host that ran it.
- **Getting the record off the host.** Ephemeral hosts (CI runners, batch
  containers) are destroyed when the job ends. A record that exists only on
  the host is lost with it.

A recorder that runs inside the sandbox (`script`, asciinema, an agent's own
transcript) does not fill these gaps, because the agent can alter or delete
it. The supervisor runs outside the sandbox, so its record is out of the
agent's reach.

### Goals

- Capture output, input, resizes and terminal facts (terminal mode,
  foreground process, terminal notifications, lifecycle) for supervised
  sessions, with or without a PTY.
- Attribute input to the client that sent it.
- Before anything is stored or sent:
  - remove credential values nono resolved for the session;
  - never capture input typed while the terminal is in password mode.
- Keep a local recording that can be replayed, rendered as text, and
  verified through the audit hash chain.
- Deliver the recording to an external receiver durably (ordered,
  acknowledged, resumable) and live (best effort, watch-only), over open
  protocols, on connections nono opens outbound.
- Work on interactive and headless hosts alike, configured at launch.
- Let operators require recording, failing closed.
- Never let a slow destination stall the agent's terminal.

### Non-Goals

- **Analysing content.** nono does not classify, search or score recordings,
  and ships no secret or PII pattern lists. Receivers can analyse the stream
  as they see fit.
- **Input sent from receivers.** Live streams are watch-only. Remote input
  would need its own NEP.
- **Holding or rewriting the session's input.** Capture is passive, apart
  from the two fixed protections in §3.
- **Receiver storage, indexing or user interfaces.**
- **Direct mode (`nono wrap`).** No supervisor remains to capture anything,
  as with NEP-0008.

## Proposal

### 1. Overview

```text
            ┌─────────── Capture (PTY proxy, or supervised pipes) ───────────┐
 agent ───▶ │ output · input{client} · resize · mode · foreground · notify   │
            └───────────────────────────────┬────────────────────────────────┘
                                            ▼ ordered events
                              Fixed protections (§3)
                              · remove known credentials
                              · drop password-mode input
                                            ▼ protected events
                                 Sinks (§5), never block capture
           ┌──────────┬──────────┬──────────┴──┬──────────────┬───────────┐
       recording  audit link    file       delivery         live      scrollback
       (chunks)   (hash chain)  (artifact) (durable, §6.1)  (§6.2)    (attach)
```

Rules that hold across the design:

1. Only capture touches the PTY or the standard streams.
2. No sink ever receives bytes that have not passed through §3.
3. Markers and metadata come from the supervisor. Escape sequences printed by
   the agent cannot create them.
4. Capture is passive: it never changes what the agent receives.

### 2. Capture

#### 2.1 Events

| Event | Source | Fields |
|---|---|---|
| `Output` | `PtyProxy::record_output`, or the supervised stdout/stderr pipes | bytes, `stream` (`pty`, `stdout`, `stderr`) |
| `Input` | `PtyProxy::proxy_client_to_master` before the write to the master, or forwarded stdin | bytes, `client` |
| `Resize` | window-size propagation | cols, rows |
| `Mode` | slave termios, read via `tcgetattr` on the master before each input batch, emitted on change | `icanon`, `echo` |
| `Foreground` | `tcgetpgrp` on the master, sampled on input and after output pauses, emitted on change | pgid, executable path |
| `Notification` | terminal BEL, and OSC 9 / OSC 777 notifications (excluding OSC 9;4 progress), seen by the screen model | kind |
| `Lifecycle` | supervisor | started, suspended, resumed, client attached or detached, exited (with status) |

Every event has a contiguous `seq` and a monotonic offset from session start.
Order is capture order.

`client` is:
- `local` for the launching terminal;
- `attach:<id>` for `nono attach`;
- `remote:<principal>` when the attaching transport supplies an
  authenticated principal (for example remote attach v1).

Focus reports and attach control frames are not `Input`.

Sessions without a PTY produce `Output` and `Input` only. A receiver can tell
the difference from the session header, which records whether a PTY was used.

#### 2.2 Foreground executable

The foreground executable is resolved from `/proc/<pid>/exe` on Linux and
`proc_pidpath` on macOS, while the process group exists. If it cannot be
resolved, it is recorded as unknown, never guessed.

### 3. Fixed protections

These two protections apply to every sink. They have no configuration and
cannot be turned off.

#### 3.1 Known credential removal

nono replaces credential values it resolved for the session with
`[redacted:credential:<name>]` in both output and input. The values come
from:
- proxy-injected credentials;
- credentials loaded into the environment from keyring or provider
  sources;
- credential capture outputs.

Arbitrary environment variables are not included.

- Values are matched raw, in base64 (standard and URL-safe), and
  percent-encoded, using a linear-time multi-pattern matcher.
- A value split across reads is still matched, however long the pause
  between them. The stage holds back only a tail that could start a value,
  shorter than the longest value, and releases it with the next read. It is
  never released on a timer or at a suspend, since the rest of the value
  could follow. When the stream ends (session end, or input entering
  password mode), a held tail of 8 bytes or more is replaced rather than
  released.
- Values shorter than 8 bytes are not matched. Their names (never their
  values) are listed in the session's coverage record, so the gap is
  visible.
- Values are `Zeroizing`, never formatted or logged, and dropped at session
  end.

This removes only what nono knows. Secrets nono never held can still
appear in a recording, and receivers should treat recordings as sensitive.

#### 3.2 Password-mode input

While the terminal is in canonical mode with echo off (`ICANON` on, `ECHO`
off), which is how `sudo`, `su`, `ssh` and `getpass(3)` read passwords,
input bytes are not captured. An `Input { suppressed: true }` event records
that input was typed, without its content or length. The `Mode` events that
open and close the window are still recorded.

Raw-mode TUIs, which include most agent interfaces, also turn echo off, but
they turn off `ICANON` as well. Their input is therefore captured normally.

Sessions without a PTY have no terminal mode to read, so this protection
cannot apply to them. In pipe mode, forwarded stdin is captured only when
`input` is explicitly `on`, and the default for pipe sessions is `off`. The
documentation states that password-mode protection requires a PTY.

### 4. Recording

- **Format:** asciicast v2, so existing players can replay it.
  - `o` for output and `i` for input;
  - `r` for resize;
  - `m` markers for the other events, with labels of the form
    `nono:<event>:<json>`.

  The header carries:
  - the session id and audit session id;
  - whether a PTY was used;
  - the wall-clock start time;
  - the capture settings in effect.

  Metadata events go in the same file as markers, not in a separate events
  file. This means one chunk hash covers everything captured in that window,
  and standard players ignore labels they do not understand.
- **Location:** `$XDG_STATE_HOME/nono/audit/<session>/terminal/`. This is
  protected nono state, which the sandbox cannot read or write.
- **Chunks:** the recording is a sequence of zstd-compressed chunks.
  - A chunk's timer starts at its first event. It closes 10 seconds later,
    at 1 MiB of uncompressed data, on suspend, or at session end, whichever
    comes first.
  - Silence produces no chunks and no padding. A pause is a gap in event
    offsets, and the session and its streams carry on.
  - The 10-second and 1 MiB limits are defaults. Receivers take chunk
    boundaries from `terminal_chunk` events and never assume the limits, so
    the defaults can be tuned later without a protocol change.
- **Integrity:** when a chunk closes, the supervisor writes a
  `terminal_chunk` event into the hash-chained audit log, with:
  - the chunk index;
  - the `seq` and time range;
  - the range of audit record sequence numbers written during the same
    window, so tools can line up the recording with NEP-0008 records without
    scanning both;
  - raw and stored sizes;
  - the SHA-256 of the stored chunk;
  - credential and suppression counts.

  `nono audit verify` checks that every referenced chunk exists and matches,
  and that `seq` ranges are contiguous, or that each gap is explained by a
  `recording_lost` event.
- **Streaming compatibility:** the NEP-0008 §10 rules apply. Events are
  recorded when they happen, nothing depends on a later record, and an
  unsealed session proves everything up to its last `terminal_chunk`.
- **Bounds:** recording stops at `max_bytes` with a
  `terminal_recording_truncated` event, or, when recording is required, the
  session stops. Retention follows audit cleanup, with an optional shorter
  limit.

### 5. Sinks

```rust
trait Sink {
    fn name(&self) -> &str;
    fn required(&self) -> bool;
    fn write(&mut self, event: &ProtectedEvent) -> Result<()>;
    fn chunk_closed(&mut self, chunk: &ChunkInfo) -> Result<()>;
    fn close(&mut self, end: &SessionEnd) -> Result<()>;
}
```

| Sink | Purpose |
|---|---|
| `recording` | local chunks (§4) |
| `audit_link` | `terminal_chunk` events in the audit log |
| `file` | the finished recording and a chunk manifest, written to an operator-chosen path outside the sandbox, for hosts that collect artifacts |
| `delivery` | durable delivery to a receiver (§6.1) |
| `live` | live stream to a receiver (§6.2) |
| `scrollback` | the existing attach replay buffer, moved behind this interface with unchanged behaviour |

**Backpressure.** Each sink has a bounded queue and runs off the capture
path.
- When a queue is full, the sink spills to a spool file in the session's
  audit directory.
- When the spool is full, or the sink fails:
  - a non-required sink records `recording_lost` for the `seq` range and
    resumes when it can;
  - a required sink stops the session, with the reason recorded.

The §3 stage runs inline and costs linear time per read. Sessions with no
resolved credentials skip it. Capture never waits on a sink.

### 6. Delivery

nono delivers to a **receiver**: any service that implements the protocols
below, which will be specified in `docs/protocols/` once this NEP is
accepted. All connections are opened **outbound** by the supervisor. nono
never listens for viewers, so it needs no inbound port and works behind NAT
and proxies. Receivers outside loopback require TLS with normal certificate
validation.

#### 6.1 Durable delivery

- `terminal_chunk` events travel in the audit log through live audit
  delivery (audit delivery v2, proposed), which verifies the chain and
  acknowledges records.
- Chunk bodies are uploaded by reference:

  ```text
  PUT /api/v2/audit/sessions/{session_id}/terminal/chunks/{index}
  X-Nono-Content-SHA256: sha256:<stored chunk hash>
  ```

  A receiver accepts a body only when its hash matches the `terminal_chunk`
  event it has already acknowledged. A host therefore cannot swap a chunk
  after its event was accepted. Uploads are idempotent and resumable, and the
  spool is the buffer.
- **Flush on exit.** At session end, the supervisor uploads outstanding
  chunks and finalizes within `flush_timeout`, before exiting.
  - If delivery is required and the flush did not complete, nono exits
    non-zero with a distinct status, so a pipeline sees the failure.
  - If delivery is not required, the gap is reported, and nono's exit status
    is the agent's.

#### 6.2 Live stream

- The supervisor opens a WebSocket to the receiver and sends protected
  output, resizes and marker events as they happen. The frame format is
  remote attach v1's server-to-client frames, specified in a new
  `session-stream-v1` document, because the direction, authentication and
  absence of input differ from remote attach.
- **Watch-only.** nono ignores any input frames on this connection.
- **Lossy by design.** When the connection drops, the supervisor reconnects
  with backoff and sends a resync: the current screen, rendered from the
  screen model. It does not replay the gap. Heartbeats keep quiet sessions
  connected. The durable channel is the record.

#### 6.3 Identity

The supervisor authenticates as the host, not as a person:

- **Enrolled devices** sign requests with the enrollment key, as audit
  delivery does.
- **Workloads** (CI runners, cloud compute, containers) present an OIDC
  token issued by their environment, for example a CI provider's job token
  or a Kubernetes service account token. They exchange it with the receiver
  for a short-lived, session-scoped credential. The token's signed claims let
  the receiver establish where the session ran and decide whether to accept
  it.

Delivery credentials and identity tokens belong to the supervisor:
- they are never placed in the sandboxed process's environment;
- they are read only from paths the sandbox cannot read;
- they are `Zeroizing` in memory;
- they never appear in logs, errors or recordings.

A token passed in through an environment variable is removed from the
child's environment before exec.

### 7. Configuration

```json
"session_recording": {
  "enabled": true,
  "required": false,
  "input": "on",
  "max_bytes": 268435456,
  "retention_days": 30,
  "file": "./artifacts/session.cast",
  "delivery": { "receiver": "https://receiver.example", "required": true, "flush_timeout_secs": 60 },
  "live": { "receiver": "https://receiver.example" }
}
```

- `input` is `on` or `off`. `off` records `Input { suppressed: true }`
  markers only. §3 applies in both cases.
- `receiver` is either an `https://` URL or `platform`, meaning the receiver
  this host is enrolled with.
- Headless hosts usually set these at launch:

  ```text
  nono run --profile ci-agent --record --record-required \
    --record-file ./artifacts/session.cast \
    --deliver-to https://receiver.example --stream-live \
    --identity oidc -- agent ...
  ```

  Each flag has a matching `NONO_*` environment variable.
- **Can only be raised.** Child profiles, flags and variables can turn
  recording on, set `required`, or add a destination. They cannot turn off
  or lower what a parent profile or managed configuration requires. Managed
  configuration can limit receivers to an allow-list.
- **Notice.** When recording is on, the session starts with a one-line
  notice, which mentions live streaming when that is enabled. It is written
  to the terminal, or to stderr when there is no terminal, so it appears in
  job logs. Profiles cannot suppress it.
- The profile JSON schema and the authoring guide gain this block.

### 8. CLI

- `nono replay <session> [--speed N] [--idle-limit S] [--from <time|marker>]`
- `nono transcript <session> [--format text|json]` renders through the vt100
  model into readable text. Full-screen redraws are collapsed to the screen
  state at quiet points, and control characters are stripped.
- `nono audit verify` checks the recording (§4).
- `nono inspect` shows recording state, destinations and any loss.

### 9. Library and CLI split

- **Library (`nono`):** no recording types. The audit recorder gains one
  generic method that appends an event whose type the caller defines. It
  refuses the library's own event types, so an extension can never pass for
  one, and the verifier checks these records by their hash without
  interpreting them.
- **CLI (`nono-cli`):** capture, protections, recording, sinks, delivery,
  identity, configuration, replay and transcript, and the audit payload
  types (`terminal_chunk`, `recording_lost`, `terminal_recording_truncated`),
  written through that method.

### 10. Phasing

1. Capture, the §3 protections, the local recording, the `audit_link` and
   `file` sinks, required recording, `nono replay`, `nono transcript` and
   verification.
2. Durable delivery with flush on exit, and device and OIDC identity.
3. The live stream.

### Backward compatibility

Opt-in, and not breaking. Audit verifiers must accept the new payload types,
as for NEP-0008. Attach replay behaviour is unchanged.

## Security Considerations

- **Least privilege.** The sandboxed process gains nothing. Recordings,
  spools and delivery credentials live in protected nono state, out of the
  sandbox's reach.
- **A new store of sensitive data.** This is the main risk. A recording
  holds whatever was displayed and typed, apart from what §3 removes.
  Mitigations:
  - recording is off by default;
  - input capture can be turned off;
  - password-mode input is never captured;
  - known credentials are always removed before any sink;
  - the notice cannot be suppressed;
  - size and retention limits;
  - receivers can be limited to an allow-list.

  The documentation must state that recordings contain what was on screen.
- **Credential handling.** Matcher values and delivery credentials are
  `Zeroizing`, supervisor-only, and never formatted. Coverage records name
  unmatched credentials but never their values.
- **Fail-secure.**
  - Required recording or delivery that cannot start, write, spool, stay
    within bounds or flush stops the session, or fails the exit, with the
    reason recorded.
  - For optional destinations, gaps are recorded, never silent.
  - Invalid configuration fails profile loading.
- **Network exposure.** Connections are outbound only, and nono opens no
  listener. The live stream ignores input, so a receiver, or anyone who
  compromises one, cannot type into a session.
- **Receiver integrity.** A receiver accepts a chunk only against an
  acknowledged, chain-verified `terminal_chunk` event, so chunks cannot be
  replaced after acceptance. A host compromised before an event is written
  can still drop data, with the limits of audit delivery v2.
- **Untrusted content.** Recordings contain agent-produced escape sequences.
  `nono replay` writes them to the reviewer's terminal, as `nono attach`
  does. `nono transcript` strips them. Receivers must render recordings in a
  terminal emulator, never as markup.
- **Displayed text is not behaviour.** An agent can print anything. NEP-0008
  records remain the evidence of what was done.
- **Consent.** Recording a person's typing is monitoring. The notice is
  always shown, including in headless job logs. Whoever configures recording
  is responsible for their own notice obligations.
- **Library/CLI boundary.** The library gains payload types only.

## Alternatives Considered

- **Record inside the sandbox** (`script`, asciinema, agent transcripts).
  The agent can tamper with these, and they cannot be linked to the audit
  chain.
- **Content analysis in nono** (pattern lists, secret detection). Any fixed
  list collects exceptions and requests for removal, and analysis improves
  faster outside a release cycle. nono keeps to what only it can do: capture
  facts that are visible only on the host, and remove values only it knows.
- **A listening server for viewers.** It needs inbound reachability and its
  own authentication, and it adds attack surface to every host. Outbound
  connections avoid all three.
- **Recording only the rendered screen.** Smaller, but it loses timing and
  exact bytes and cannot be replayed. The transcript is derived from the
  recording instead.
- **Terminal bytes in the audit log.** This would make the chain far larger
  for every consumer. Chunks linked by hash are just as tamper-evident.
- **The live stream as the record.** It is lossy by design. Only
  hash-verified chunks are the record.

## Open Questions

None at this time.
