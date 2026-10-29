---
nep: 0008
title: Session flight recorder
authors:
  - lukehinds
status: draft
created: 2026-10-29
breaking:
superseded-by:
---

# NEP-0008: Session flight recorder

## Summary

Make the audit log a complete, self-describing record of an agent session:
every access nono denied, from every enforcement layer, with the reason and
the process responsible; every grant the agent held; every allowed access to
paths an operator marked as sensitive; and a statement of which sources were
live, so an operator can tell "nothing happened" apart from "nono could not
see it". The supervisor's seccomp notifications are the primary source and
work without privilege everywhere, including restricted containers. On hosts
that support it, Landlock's kernel audit can be added as a kernel-backed
layer that a hostile agent cannot evade.

## Motivation

An operator investigating a session needs to answer, after the fact:

- What was the agent allowed to do, and what did it actually use?
- What did it try that was refused, by which layer, which process, and why?
- Did it touch anything sensitive inside the folders it was granted?
- Can I trust that the record is complete?

Today the audit log answers parts of the first two questions for some layers
and none of the last two. Enforcement is unaffected: everything below is
denied correctly. The gap is the evidence.

### What the audit log records today

| Source | What it blocks or permits | Audit log today |
|---|---|---|
| Supervisor, approval backend | `openat` outside the grants (capability elevation on) | Yes (`capability_decision`), but with the session root's pid, not the requesting process |
| Supervisor policy | Protected nono state, `deny_paths`, insufficient access, rate limits, untrusted instruction files | Diagnostics only |
| Landlock filesystem | create, mkdir, unlink, rename, link, truncate, device ioctl, refer; every open when elevation is off | No |
| Landlock execute gate | `execve` of commands outside the allowlist | No |
| Landlock TCP and scopes | connect/bind outside port grants; signals; abstract UNIX sockets | No |
| Static seccomp filters | UDP, raw and non-IP sockets, `io_uring_setup` | No (silent `EPERM`) |
| Seccomp network and AF_UNIX notifications | proxy-fallback connect/send; pathname UNIX connect/bind | Yes, rate-limited with suppression summaries; no pid |
| Proxy | hosts, URLs, credential injection; runtime host approvals (#1781) | Yes: allows, denials and approval decisions, but written to the log only at session end |
| Command policy | mediated tool commands | Yes |
| Seatbelt (macOS) | every denial in supervised mode, via `log stream` | Diagnostics only, capped at 50 (`sandbox_log.rs`) |
| cgroup resource limits | OOM kills, process-count cap | End-of-session terminal report only |
| Mount namespace isolation (NEP-0004) | hidden paths (`ENOENT`) | Not a denial; layout not recorded |

Capability elevation is off by default (`security.capability_elevation`), so
by default no filesystem denial reaches the audit log on either platform.

Process attribution is also missing where the kernel provides it: capability
requests record `child.as_raw()`, the session's top-level process
(`crates/nono-cli/src/exec_strategy/supervisor_linux.rs:659`), not
`notif.pid`, the task that made the call.

### Goals

- Every denial from every nono enforcement layer reaches the audit log, with
  its source, reason and the process that caused it.
- The log records the effective grants at session start and every grant
  added during the session.
- Allowed accesses to operator-declared sensitive paths are recorded
  individually; all other allowed filesystem access is summarised per grant.
- The log states which sources were active and their fidelity, and accounts
  for every record it dropped, deduplicated or failed to collect.
- When an operator requires the recorder and nono cannot provide the
  required fidelity, the session does not start.
- The primary source works without privilege in restricted containers (for
  example AWS Fargate).

### Non-Goals

- Recording every allowed file access. A session performs hundreds of
  thousands to millions of opens; the volume would bury the signal.
- Recording denials that nono did not cause: ordinary Unix permission
  (DAC) failures, SELinux or AppArmor denials.
- Approvals for operations other than open. Approving `mkdir`, `unlink` or
  `rename` would need the supervisor to perform the operation itself,
  unsandboxed; that needs its own design.
- Direct mode (`nono wrap`). nono execs into the agent and no process
  remains to write the log; the recorder requires supervised execution, as
  `--audit-sign-key` already does.
- Protecting the record from a compromised kernel or guest. NEP-0007 moves
  the ledger outside a microVM guest; this NEP defines what goes into it.
- The streaming transport and the external verifier. Sending the log during
  the session and validating it elsewhere belong to the audit delivery
  protocol (`docs/protocols/audit-delivery-v1.md`). This NEP only requires
  that the record is stream-compatible (§10).

## Proposal

### 1. Record classes

The recorder writes five classes of event into the existing hash-chained
audit log (`crates/nono/src/audit.rs`):

1. **Grant ledger.** The resolved, canonicalised `CapabilitySet` at session
   start, and each grant added later, recorded when it is made: filesystem
   approvals (`capability_decision`) and session-scoped network host
   approvals (`GrantedForSession`, #1781). Session-scoped denials
   (`DeniedForSession`) are recorded the same way.
2. **Denials.** One new payload, `access_denied`, fed by every source in the
   table above. Fields:
   - `source`: `supervisor`, `approval_backend`, `landlock_kernel`,
     `seatbelt_kernel`, `seccomp`, `proxy`, `command_policy`, `cgroup`;
   - `fidelity`: `kernel` (the kernel reports what it denied) or
     `supervisor` (nono evaluated its own policy against a path it read);
   - `operation` and `access` (expressed as Landlock access rights, such as
     `fs.make_reg`, for both supervisor and kernel sources);
   - `target` (path, address or resource), redacted under the session's
     redaction policy;
   - `reason`: not granted, protected path, deny rule, insufficient access,
     user denied, rate limited, backend error, out of scope;
   - `pid`, `tgid`, `exe`, `comm` of the task that made the call, where the
     source provides them;
   - `timestamp` and, for kernel sources, the kernel's record serial.
3. **Sensitive-path access.** Every *allowed* access to a path matching the
   watch list, with the process and the grant that permitted it. The watch
   list defaults to nono's existing sensitive-path and protected-path lists
   and is extended by the profile (`audit.watch_paths`, name to be decided).
4. **Per-grant usage summary**: for each grant root, access count, read and
   write counts, first and last access time, and the top N paths. This
   identifies unused grants and is cheap to collect. Written in periodic
   checkpoints (§10); the final summary is the last checkpoint.
5. **Coverage and reconciliation.**
   - At session start, extend `SandboxRuntime` with the live sources, the
     fidelity level (§5), the Landlock ABI, and the known blind spots for
     this environment.
   - When a source fails or recovers mid-session, record a `source_lost` or
     `source_restored` event at that moment.
   - In each checkpoint and at session end, write per-source counts:
     recorded, deduplicated and suppressed by rate limit, plus (with the
     kernel layer) the kernel's `denials=N` per domain against the number of
     records ingested.

Changes (rollback snapshots, `--audit-integrity`), allowed network activity
(proxy) and command decisions are already recorded and are not changed.

**Process attribution, all supervisor sources.** Every supervisor record
names the task that made the call: `notif.pid`, its thread group id
(`read_tgid`), and `exe` and `comm` read from `/proc` while the task is held
in the syscall. This replaces `child_pid: child.as_raw()` for capability
requests and adds a pid to network and AF_UNIX denial events. It can ship
ahead of the rest of this NEP as a bug fix.

### 2. Primary source: the supervisor syscall trap (Linux)

When the recorder is on, the supervisor runs in supervised mode with a
seccomp notification filter covering every path syscall Landlock mediates,
whether or not capability elevation is enabled:

- `openat`, `openat2` (and `open`, `creat` where the architecture has them);
- `mkdirat`, `mknodat`, `unlinkat`, `renameat2`, `linkat`, `symlinkat`,
  `truncate` (and legacy forms);
- `execve`, `execveat`.

For each call the supervisor resolves the path and evaluates it against the
session's `CapabilitySet`, mapping the call to the Landlock access rights it
needs (for example, `O_CREAT` to `fs.make_reg`, `O_TRUNC` to `fs.truncate`,
cross-directory `rename` to `fs.refer`):

- **Outside the grants, `openat`/`openat2` with elevation on:** the existing
  approval path, unchanged.
- **Outside the grants, otherwise:** respond `EACCES` and record
  `access_denied` with `fidelity: supervisor`.
- **Within the grants:** continue; Landlock still enforces. Record
  watched-path accesses and update the per-grant counters.

`execve` and `execveat` interception also records the process tree: which
programs ran, from which parent.

Requirements of this mode:

- **io_uring is denied**, as AF_UNIX mediation already does (#2215),
  because io_uring operations bypass seccomp.
- **The evaluator is shared and tested against Landlock.** One module maps
  syscalls and flags to Landlock access rights. Differential tests run each
  operation under the real Landlock ruleset and the evaluator and require
  the same decision, so the two cannot drift as Landlock gains rights.
- **Performance is an acceptance criterion** (see Open Questions): every
  trapped call stops the calling task while the supervisor evaluates it.

**Known limit: a hostile agent can avoid being recorded.** The supervisor
reads the path from the agent's memory; the kernel reads it again when the
call continues. A multithreaded agent can pass an in-grant path to the
supervisor and then swap the buffer, so the kernel acts on a path outside
the grants. Landlock still blocks the access, but no record is written.
`seccomp_unotify(2)` documents this race. The supervisor source is therefore
complete for honest behaviour and evadable by deliberate behaviour; §3 closes
the gap where the host supports it.

### 3. Optional kernel-backed layer: Landlock audit (Linux hosts)

Landlock ABI V7 (Linux 6.15) emits `LANDLOCK_ACCESS` and `LANDLOCK_DOMAIN`
audit records. The library adds a `CapabilitySet` setting that restricts
every Landlock domain nono creates with
`LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON | LOG_SAME_EXEC_OFF`, so denials by the
exec'd agent are logged and nono's own pre-exec setup is not. The kernel
default (log same-exec only) would record nono's setup and none of the
agent's denials. The flags must be applied to every layer nono stacks: the
library `restrict_self` paths, the raw-clone child and the
command-mediation execute gate. They are gated on the detected ABI, not
`MAX_ENFORCED_ABI`, because they change what is reported, not what is
denied, and the setting fails closed below ABI V7. A prototype verified this
on Linux 7.1 (ABI V9): `fs.make_reg`, `fs.make_dir` and `fs.read_file`
denials were logged, and the domain's `denials=3` matched.

**What it adds on top of §2.** With the supervisor already denying
everything outside the grants, Landlock only denies what the supervisor let
through. So every Landlock record in a combined session is one of:

- a **raced path**: the agent swapped the buffer after the supervisor's read;
- an **io_uring** operation, if io_uring was not denied;
- an **evaluator mismatch**: the supervisor's evaluation disagreed with
  Landlock's.

Each is high-signal, and the recorder flags these records as anomalies. The
layer also costs nothing until something is denied, and covers new Landlock
rights automatically.

**Its limits.**

- Kernel 6.15 or newer.
- No per-process attribution by default. The kernel attaches a `SYSCALL`
  record (pid, exe, syscall, exit code) only when syscall auditing is active
  for the task. On a Fedora 44 host with default audit configuration (Linux
  7.1), `LANDLOCK_ACCESS` records arrived standalone, under their own audit
  serials, with no `SYSCALL` record; the only pid was the domain creator's.
  Records still identify the session (the domain), and the process tree from
  §2 narrows each to the processes alive at the time.
- It needs a reader, and readers need some privilege:
  1. **The systemd journal** (`_TRANSPORT=audit`), when
     `systemd-journald-audit.socket` is active. Readable by members of
     `systemd-journal`, `adm` or `wheel`; no new privileged code. journald
     stamps `_TRANSPORT` itself, so a process cannot forge these records via
     syslog.
  2. **A privileged bridge** holding `CAP_AUDIT_READ` (file capability or
     socket-activated service). It authenticates the caller with
     `SO_PEERCRED` and returns only records for Landlock domains created by
     that caller's sessions.
  3. **None**, which is the normal case in restricted containers such as
     Fargate: audit is not namespaced and the capability cannot be granted.

Correlation: the `LANDLOCK_DOMAIN status=allocated` record carries the pid of
the task that called `landlock_restrict_self`, which the supervisor knows.
The `status=deallocated` record carries the domain's total denial count and
is emitted when the last task in the domain exits. That gives both the loss
check and the signal that the reader may stop and the log may be sealed.

### 4. Who records what (Linux)

| Case | Decided by | Recorded by |
|---|---|---|
| Path within grants | Landlock (allows) | Supervisor: usage counters; watch list if matched |
| Outside grants, open, elevation on | Supervisor, approval backend | Supervisor (decision) |
| Outside grants, any other trapped call | Supervisor (`EACCES` before the syscall runs) | Supervisor |
| Within grants per the supervisor, swapped before the kernel runs it | Landlock (denies) | Kernel layer only, flagged as anomaly |
| io_uring operation | Denied at `io_uring_setup` | Static seccomp filter (see Open Questions) |
| Network, AF_UNIX, proxy, command policy, cgroup | Existing mechanisms | Existing sources, with pid added |

Each denial is recorded by exactly one source, so merging sources needs no
deduplication. Supervisor records of allowed access (watched paths, usage
counters) record attempts permitted by policy, not outcomes. A kernel-layer
denial for the same call identifies a raced path or an evaluator mismatch.

### 5. Fidelity levels

| Level | Sources | Guarantee |
|---|---|---|
| `supervisor` | §2 plus the existing supervisor, proxy and command-policy sources | Complete for honest behaviour; a deliberate race can avoid a record (never the denial) |
| `kernel` | `supervisor` plus §3 on Linux, or Seatbelt on macOS | Every denial the kernel made is recorded |

The session's level is written in the coverage event.

### 6. macOS

macOS has no equivalent of seccomp notifications, so Seatbelt reports are the
primary source there. Supervised sessions already collect every Seatbelt
denial through `log stream` (`crates/nono-cli/src/sandbox_log.rs`), enabled by
`(debug deny)` (`CapabilitySet::seatbelt_debug_deny`), and the reports carry
the process name and pid. The recorder:

- sends these to `access_denied` with `source: seatbelt_kernel`;
- replaces the 50-entry diagnostic cap with the shared rate-limit and
  suppression accounting;
- records `log stream` failures in the coverage and reconciliation events.

Recording allowed accesses to watched paths on macOS would need Seatbelt
report rules on allow; see Open Questions.

### 7. Volume control

An agent can generate denials at will. Every source shares the bounded
budget model already used for network denials (`NetworkDenialAuditLimits`):
denials within the budget are written individually; denials past it are
counted and written as one summary event. Repeats of the same
(source, operation, target, reason, process) are counted, not rewritten; the
running counts appear in each checkpoint. Enforcement is unaffected by the
budget. The same budget bounds the bandwidth of a streamed log; the transport
needs no separate one.

### 8. Operator controls

- A single switch turns on the recorder (name to be decided), with an
  option to add the kernel layer. It enables the
  supervisor source, and adds the kernel layer when available and requested.
- A profile setting lets an operator **require** the recorder and a minimum
  fidelity level. A required recorder cannot be turned off with
  `--no-audit`, and a session that cannot meet the level does not start.

### 9. Library and CLI split

- **Library (`nono`):** mechanism only. The Landlock restrict flags,
  seccomp filter builders for the trapped syscall set, and data
  types for the new audit payloads.
- **CLI (`nono-cli`):** everything else. The syscall-to-access-right
  evaluator, source selection, the journal reader and bridge client,
  watch-list policy, budgets, coverage and reconciliation, and operator
  requirements.

### 10. Stream compatibility

The recorder must work when the log is streamed during the session and the
Merkle structure is validated afterwards, outside nono. The existing log is
already shaped for this: each record carries its sequence number, the
previous chain hash, its leaf hash, the new chain hash and its canonical
event JSON, so a consumer can verify the chain as records arrive. The
recorder adds these rules:

- **Every source writes when the event occurs.** No source buffers events
  until session end. Today the proxy does: its network events are drained
  into the log only at finalize; they must be recorded as they happen.
- **No record depends on a later one.** End-of-session summaries (usage,
  reconciliation, repeat and suppression counts) are also written as
  periodic checkpoints, by time and by event count, carrying running totals.
  A session that never finishes still has its counts up to the last
  checkpoint.
- **Chain order is recording order.** Records are chained in the order the
  recorder writes them. A kernel record's own timestamp and serial are
  fields, not ordering keys.
- **The seal waits for kernel drain.** The final Merkle root and event count
  are written only after every Landlock domain's `deallocated` record has
  been ingested, or a timeout expires; an expired timeout is recorded.
- **An unsealed session is incomplete.** Without the seal, the stream proves
  everything up to the last chain hash and nothing after it. Consumers use
  the coverage event to know what was being watched.

### Backward compatibility

The recorder is opt-in. Existing audit consumers see new payload types and
new optional fields on `SandboxRuntime` and on network events (pid); the
verifier must accept them. Its handling of unknown payload types needs
confirming before this is accepted.

## Security Considerations

- **Least privilege.** The sandboxed process gains nothing. The supervisor
  source only adds denials before Landlock runs; io_uring is newly denied in
  recorder mode. The privileged bridge (§3, reader option 2) is new
  privileged code: it must stay minimal, run nothing else, and return only
  the caller's own domains, because `CAP_AUDIT_READ` exposes every user's
  audit records on the host.
- **Fail-secure.** A required recorder that cannot reach its level blocks
  the session. A source that fails mid-session is recorded in reconciliation
  and surfaced in the session result; it never silently becomes "zero
  denials". The Landlock restrict flags are hard-required: a kernel that
  rejects them stops the sandbox from starting.
- **Supervisor as decider.** In recorder mode the supervisor returns
  `EACCES` for calls outside the grants, where today Landlock alone decides.
  An evaluator bug can deny legitimate operations (fail-safe) or let through
  a call Landlock then denies (caught by the kernel layer where present).
  The differential tests in §2 are the guard.
- **Evadable records.** At `supervisor` fidelity, a hostile agent can race
  the path read and avoid a record, never the denial. Operators who need a
  record that holds against a hostile agent require `kernel` fidelity.
- **Host audit exposure.** With the kernel layer on, the untrusted agent can
  generate host audit records at will. That can fill the kernel audit
  backlog and cause loss of *other* host audit records. On hosts configured
  with `auditctl -f 2` (panic on failure) this is a denial-of-service risk.
  The kernel layer is opt-in and documented as a host decision, and the
  reader reports backlog loss.
- **Reader trust.** The agent must not be able to read or write the audit
  sources: `/var/log/journal` and `/run/log/journal` must never be granted.
  The session log already lives under protected nono state.
- **Path handling.** The supervisor resolves paths from `/proc/PID/mem` the
  same way as the existing `openat` handler, with the same TOCTOU window. The
  window affects only what is recorded, never what is allowed.
- **Nested Landlock domains.** An agent can call `landlock_restrict_self`
  with `LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF`. It must be confirmed that
  this cannot suppress logging of denials made by nono's outer domain. If it
  can, the seccomp baseline must reject that flag.
- **Credentials and privacy.** Paths and targets pass through the session's
  redaction policy. Sensitive-path access events record that access
  happened, never content.
- **Library/CLI boundary.** Kept as in §9: the library gains flags, filter
  builders and types, with no policy.

## Alternatives Considered

- **Landlock audit as the primary source.** Kernel-backed, zero cost and
  correct by construction, but needs kernel 6.15+, a privileged or
  group-gated reader, has no per-process attribution by default, and is
  unavailable in restricted containers. Kept as the optional kernel layer.
- **Close the open race without the kernel layer.** The supervisor could
  open every file itself and inject the fd, instead of continuing in-grant
  calls, so the kernel never re-reads the agent's buffer. It costs more per
  open and does not help `mkdir`, `rename` or `unlink`, where there is no fd
  to inject. Possible later hardening for opens.
- **Log every allowed access.** Rejected for volume and signal; see
  Non-Goals. The watch list plus per-grant summaries answer the same
  questions at a fraction of the cost.
- **eBPF (BPF LSM or fexit on `security_*` hooks).** Kernel-accurate, covers
  every LSM and gives pids, but requires `CAP_BPF`/`CAP_PERFMON` (root in
  practice) and is fragile across kernel versions. A possible later
  enterprise source.
- **fanotify.** Permission events see only accesses that already passed the
  LSM checks, so they never see a Landlock denial; they also need
  `CAP_SYS_ADMIN`.
- **ptrace with `SECCOMP_RET_TRACE`.** Unprivileged and reads the real
  return value, but a process can have only one tracer, so it breaks agents
  and tools that use ptrace. It also costs two stops per traced syscall.

## Open Questions

- **Performance.** Benchmark `npm install`, `rm -rf node_modules` and
  `git checkout` unsupervised, supervised with only `openat` trapped, and
  with the full trap set. The supervisor handles notifications on one `poll`
  loop, so a pending approval prompt also stalls audit-only calls;
  evaluation may need to move off that loop. Define an acceptable overhead
  before acceptance.
- **Evaluator coverage.** Confirm the trapped syscall list covers every
  Landlock filesystem right at the enforced ABI, including device `ioctl`,
  which cannot be evaluated by path alone.
- **Static seccomp denials.** `SECCOMP_FILTER_FLAG_LOG` on the static
  network filter would route its `EPERM` returns to kernel audit, but that
  needs the kernel layer's reader. Alternatively, convert those rules to
  notifications so the supervisor records them. Choose one.
- **Landlock attribution.** Whether to detect syscall auditing on the host
  and record exact pids from `SYSCALL` records when present, or always
  attribute kernel records at session level.
- **macOS allow reporting.** Confirm whether Seatbelt can report allowed
  accesses for specific paths (a report modifier on allow rules) to give
  watched-path parity.
- **Reader lifecycle.** Detached sessions, remote run and `nono attach`:
  which process owns the kernel-layer reader, and how long the log stays
  open after the agent exits, until the `deallocated` record arrives or a
  timeout.
- **Journal availability.** Survey whether journald collects audit records
  by default on Ubuntu, Debian, RHEL and Amazon Linux.
- **Clock correlation.** Chain order is recording order (§10), but kernel
  audit timestamps and supervisor timestamps come from different clocks.
  Define how consumers relate the two when reconstructing a timeline.
- **Decision provenance.** A connection allowed or denied by a cached
  session decision is recorded as `ApproveGranted` or `ApproveDenied` with
  the backend name, the same as a fresh prompt. Decide whether to add a
  field distinguishing "the operator was asked" from "answered from an
  earlier decision", for network and filesystem approvals alike.
- **Checkpoint interval.** Choose the time and event-count intervals for
  checkpoints, balancing log volume against how much a crashed session
  loses.
- **Verifier compatibility.** Confirm the alpha verifier tolerates unknown
  payload types, or version the scheme.
