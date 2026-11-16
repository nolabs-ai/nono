---
nep: 0011
title: macOS Endpoint Security layer for runtime approvals and kernel-enforced policy
authors:
  - lukehinds
status: draft
created: 2026-11-13
breaking: false
superseded-by:
---

# NEP-0011: macOS Endpoint Security layer for runtime approvals and kernel-enforced policy

## Summary

Give macOS the runtime approvals and kernel-enforced policy it lacks today.
An opt-in layer built on Apple's Endpoint Security framework (macOS 27+) lets
the nono supervisor make kernel-level decisions about the process tree it
launches, inside the Seatbelt sandbox, which stays the static, irreversible
ceiling.

That adds four capabilities to macOS:

- **Runtime approval of file access for unmodified agents**, with no restart
  and no code injected into the agent.
- **Kernel-enforced command policy and tool sandboxing**, decided on
  code-signing identity across the whole process tree.
- **Mach/XPC and Unix-socket allow-lists** decided in the kernel.
- **Exact denial capture and kernel-sourced audit**, including rollback
  inputs and persistence tripwires.

It is one `nono` codebase and one binary. Each release signs that binary
twice: a plain artifact exactly as today, and an ES artifact carrying the
restricted entitlement. Plain builds keep today's Seatbelt-only behaviour, and
the difference is always reported.

## Motivation

### What macOS cannot do today

Linux and macOS diverge most on one point: Linux can trap an access, ask, and
let it proceed. macOS cannot.

- **No runtime approval.** On Linux the supervisor traps `openat` with
  seccomp user-notify, asks the approval backend, opens the file itself and
  injects the fd. The agent never knows nono is there. On macOS the Seatbelt
  profile cannot change after `sandbox_init`. The only runtime mechanism is a
  sandbox extension token, which must be consumed by code running *inside*
  the agent. nono's token-receiver shim does that through
  `DYLD_INSERT_LIBRARIES`, and SIP and the hardened runtime strip that
  injection for exactly the binaries that matter: `/usr/bin/env`, `/bin/sh`,
  and standalone agent binaries such as the native `claude` build
  (`proj/DESIGN-runtime-grant.md`). Even where the shim loads, the first
  denied open fails. So today a missing grant means restarting with a wider
  profile, and users over-grant up front.
- **Command policy is not a kernel boundary.** `commands.{allow,deny}` was
  deprecated in v0.33.0 as "startup-only command gating, not kernel-enforced.
  Child processes can bypass it." Seatbelt can scope `process-exec*` by path
  but not by code-signing identity, and it cannot ask.
- **Tool sandboxing is enforced in userspace, with known gaps**
  (`docs/cli/features/tool-sandbox.mdx`):
  - mediated tools are protected by `(deny process-exec* (literal ...))`
    rules on canonical paths, so a copied or renamed binary is a different
    path;
  - the session exec allow-list comes from a startup PATH scan, so binaries
    outside PATH or installed later are not covered;
  - pinned executables are verified and then exec'd by path, which leaves a
    replace-before-launch window because macOS has no `fexecve`;
  - caller attribution walks process ancestry and puts every mediated command
    in its own POSIX session (`setsid`), which costs it its controlling
    terminal (`/dev/tty` fails, `ssh` passphrase prompts fail), and
    double-forking daemons need `daemon_pid_source` helpers that run
    unsandboxed;
  - NEP-0002 `approval_fs` grants are declare-then-relaunch: the child asks
    for an exact path and the grant applies only to a fresh sandbox.
- **Mach services use a deny-list.** The profile emits `(allow mach-lookup)`
  and then denies securityd and keychain names
  (`crates/nono/src/sandbox/macos.rs`). Every other launchd service is
  reachable, and the service owner's identity is never checked.
- **Process scoping is coarse.** `process-info*` and `signal` use
  `same-sandbox` because Seatbelt cannot tell an agent's own children apart.
- **Denials are seen late and incompletely.** The denial collector reads
  Seatbelt denials from the unified log after the fact. Nothing observes
  setuid execs, LaunchAgent installation or TCC changes.

### Why now

macOS 27 lets an ordinary command-line tool watch and gate just its own
process tree with Endpoint Security, without root and without a system
extension. Before this, ES was a host-wide facility for privileged daemons.
From the SDK header:

- a new kind of ES client, created with `es_new_descendants_client`, is
  scoped to the *caller's* process subtree, existing and future descendants,
  recursively, and unrelated processes are invisible. This NEP calls it a
  *scoped client*;
- it needs the restricted `com.apple.developer.endpoint-security.client`
  entitlement, but **no root and no TCC approval**, and it does not have to be
  a daemon or a system extension;
- `es_set_deadline_miss_mode` can be set to `FAIL_CLOSED`, which denies when
  a deadline is missed and also when a message is dropped because the queue
  is full. The default, `KILL`, would kill the client;
- `es_set_deadline_min_milliseconds`, available only to scoped clients, can
  raise a deadline above the system default, long enough for a person to
  answer a prompt;
- new authorization events cover XPC connections and Mach bootstrap
  check-in and look-up, alongside the existing Unix-domain socket events.

Apple's documentation adds, and testing confirmed, that a scoped client's tree
cannot run setuid or setgid binaries unless the client is root: such an exec is
killed before it runs and produces no exec event.

### Goals

- Runtime file approvals on macOS for unmodified agents, through the existing
  approval backends (terminal, webhook), inside a declared, bounded envelope.
- Kernel-enforced, tree-wide exec policy by path and code-signing identity.
- Tool-sandbox enforcement in the kernel, with shims remaining the way a
  request reaches the broker but no longer the boundary. Tools keep their
  controlling terminal.
- Allow-listed Mach bootstrap lookups and XPC connections, and pathname
  Unix-socket mediation.
- Exact, synchronous denial capture, kernel-sourced lineage in the audit
  ledger, change sets for rollback, and persistence and escalation tripwires.
- **One codebase, one binary, no helper.** ES comes from how a release
  artifact is signed. Every build channel keeps working unchanged.
- Fail secure: an unentitled build or a failed gate never widens Seatbelt, and
  the effective tier is always reported.

### Non-Goals

- Replacing Seatbelt. ES has no IP-network hook, no `sysctl`, POSIX IPC/shm or
  PTY-ioctl authorization, and cannot stop operations on already-open
  descriptors. Seatbelt and the proxy remain the boundary for those.
- Parity with Linux fd brokering. ES can only narrow access, so approval is a
  gate inside a ceiling, not a broker (see Security Considerations).
- Supporting macOS earlier than 27.
- Supporting `nono wrap`, which has no supervisor and `exec`s itself away.
- A system-wide ES client (`es_new_client`) or an ES system extension.

## Proposal

### What nono gains

| Capability | Today on macOS | With the layer | Limit |
| --- | --- | --- | --- |
| Runtime file approval | Restart with a wider profile | Prompt at the moment of access; unmodified agents; no DYLD | Gate inside a ceiling; open-time only |
| Command policy | Shim plus path literals; copies and renames escape | Every exec in the tree decided by cdhash, signing ID, team ID, location | Interpreters: inline code is not an exec |
| Tool sandboxing | Ancestry walk, `setsid`, PATH-scan allow-list | Kernel lineage; tools keep `/dev/tty`; pins verified at exec time | Shim still launches the tool; a direct exec is denied, not redirected |
| Mach/XPC | Blanket allow plus deny-list | Allow-list with owner identity | Static tables; no prompts (bootstrap events cannot take a minimum deadline) |
| Unix sockets | Seatbelt path rules | Decided on the resolved socket file | Pathname sockets only |
| Denial capture and audit | Unified-log reader, after the fact | Synchronous, exact, resolved path and lineage | Seatbelt exec and Mach denials are never seen by ES |
| Rollback and tripwires | None | Write/close/rename change sets; LaunchAgent, TCC, setuid | Notify-only events arrive after the fact |

#### 1. Runtime file approvals

This is the macOS counterpart of Linux elevation, with a weaker guarantee that
is stated plainly. The Seatbelt profile includes a declared *envelope*. The
gate default-denies inside it and approves at the moment of access: it holds
the `AUTH_OPEN`, asks the approval backend within a long deadline, and answers
allow, deny, or allow with write stripped. The agent just sees `open()`
succeed or fail with `EPERM`. Nothing runs inside the agent, so this works for
hardened and SIP-protected binaries, which the token-shim route cannot reach.

#### 2. Kernel-enforced command policy

`commands.{allow,deny}` was deprecated because it was not a boundary: it
checked only the startup command. This NEP does not bring it back. It enforces the existing
`command_policies` model in the kernel: deny-only entries, `dangerous_commands`
groups and `can_use` edges, evaluated at `AUTH_EXEC` for the domain the exec
happens in. A denied exec fails with `EPERM` wherever in the tree it happens
and whatever path or name it uses. Entries gain an optional identity match:

```jsonc
"command_policies": {
  "commands": {
    "sudo":   { "from": { "session": "deny" } },
    "docker": {
      "match": { "team_id": "<DOCKER_TEAM_ID>",
                 "signing_id": "com.docker.docker" },
      "from":  { "session": "deny" }
    },
    "unsigned-helpers": {
      "match": { "cs_validation_category": ["none", "local_signing"],
                 "under": ["$WORKDIR", "$TMPDIR"] },
      "from":  { "session": "deny" }   // no exec of agent-built binaries
    }
  }
}
```

- **Identity fields:** `cdhash`, `signing_id`, `team_id`, `is_platform_binary`
  and `cs_validation_category` from `es_process_t`; entitlements through
  `es_exec_entitlements` (for example, deny images carrying
  `com.apple.security.get-task-allow`).
- **Location:** `under`, compared by path component against the
  kernel-resolved image path.
- **Name resolution:** name-resolved entries are resolved at startup as today
  and then pinned by cdhash, so a copy or rename of `/usr/bin/sudo` still
  matches.
- **Scripts:** the decision covers both the interpreter image and
  `es_event_exec_t.script`. The kernel reports the script on the exec that
  resolves the shebang, including `#!/usr/bin/env` scripts, where it arrives
  with the `env` exec. It does not repeat it on the later exec of the
  interpreter, so the supervisor records the script per process and carries it
  forward.
- **Default for unlisted executables:** `macos.endpoint_security.exec.default`
  is `allow` (today's behaviour), `prompt` (through the approval backend), or
  `deny`.
- **Precedence:** Seatbelt exec rules are still evaluated. The gate can only
  deny what Seatbelt allows. A gate "allow" means "not denied by command
  policy", not "granted".

The deprecated `commands.{allow,deny}`, `--block-command` and
`process.blocked_commands` stay on NEP-0001's removal path. With the gate
active, migration guidance points to deny-only `command_policies` entries,
which now get the guarantee the old fields never had.

#### 3. Tool sandboxing in the kernel

Command mediation keeps its policy model (`command_policies`, `can_use`/`from`
edges, command sandbox policies, approval backends) and changes where it is
enforced.

| Concern | Today (userspace) | With the gate (kernel) |
| --- | --- | --- |
| Reaching a tool | PATH shim, control socket, fresh command sandbox | Unchanged. ES can deny an exec but cannot redirect it. |
| Stopping shim bypass | `process-exec*` literal per tool | `AUTH_EXEC` of any image whose cdhash matches a mediated tool is allowed only inside that tool's own domain. Copies and renames keep their cdhash. |
| Session exec allow-list | Literals from a PATH scan | Decided by identity. An unknown executable goes to `commands."*"` (NEP-0002) or a prompt instead of a silent deny. |
| Pinned `executable` | Verified, then exec'd by path (replaceable) | Verified at exec time: target cdhash and vnode must match the pin. |
| Caller attribution | Ancestry walk, `setsid`, unsandboxed `daemon_pid_source` | Domain lineage from kernel fork/exec events, keyed by audit token. |
| Controlling terminal | Lost to `setsid` | Kept: lineage no longer depends on `setsid`. |

Command sandboxes remain separate Seatbelt sandboxes built from their own
policy, which is the ceiling for each domain. Credentials, environment
filtering, stdio mediation and audit keep their current paths. Linux tool
sandboxing is unchanged. When the gate is unavailable, tool sandboxing runs
exactly as today, including `setsid` and the PATH-scan allow-list. Anything
that depends on the gate, such as keeping the controlling terminal, is enabled
only after the gate is armed.

#### 4. Mach/XPC and Unix-socket allow-lists

`AUTH_BOOTSTRAP_LOOK_UP`, `AUTH_BOOTSTRAP_CHECK_IN` and `AUTH_XPC_CONNECT`
(with the service owner's identity) can replace the blanket
`(allow mach-lookup)` plus deny-list. `AUTH_UIPC_CONNECT` and
`AUTH_UIPC_BIND` mediate pathname Unix sockets on the resolved socket file.
macOS has no abstract socket namespace, so the abstract-socket gap that
affects Linux does not arise here. These rule families start in `observe`:
macOS tooling uses Mach services heavily and with little documentation, so
allow-lists are tuned from audited would-be denials before enforcing.
Bootstrap events cannot take a minimum deadline, so these rules are static
tables with no prompts.

#### 5. Capture, audit and tripwires

`AUTH_*` events let the gate see every file and socket attempt, including
ones Seatbelt then denies, with the resolved path, flags and process identity. That feeds
`nono learn`, denial diagnostics and the audit ledger synchronously, in place
of an after-the-fact log reader. Notify events add:

- `NOTIFY_WRITE`, `CLOSE`, `RENAME`, `UNLINK` change sets for rollback;
- kernel-sourced lineage in the audit ledger;
- tripwires for LaunchAgent persistence (`BTM_LAUNCH_ITEM_ADD`), `SUDO` and
  `TCC_MODIFY`. These are best-effort audit signals: the layer subscribes and
  records what arrives, and no enforcement depends on their delivery.

ES messages carry per-event-type and global sequence numbers, and a gap means
events were dropped for this client. Recording them lets the audit state its
own completeness.

### Enforcement model: ceiling plus gate

Seatbelt and ES both sit on the XNU MAC framework, and an operation must pass
both. ES can deny or strip flags but cannot override a Seatbelt deny. An ES
"allow" does not grant anything Seatbelt refuses. So:

```
Seatbelt (static, applied in child before exec)   ES gate (dynamic, in the supervisor)
----------------------------------------------    -----------------------------------
hard denies: deny groups, credentials,            default-deny inside the envelope
  keychains, IP egress, proxy-only network        prompt -> allow once / session / deny
baseline grants (as today)                        strip FWRITE from read-only opens
approve mode only: + approvable envelope    --->  exec / mach / xpc / uipc / process rules
```

#### Order of evaluation

Seatbelt and ES do not see every operation in the same order. Each class was
tested with a Seatbelt deny:

| Operation | Does ES see it before Seatbelt denies it? | Consequence |
| --- | --- | --- |
| File open (read or write), file create, Unix-socket connect | Yes | The attempt is captured with its resolved path even though Seatbelt then refuses it |
| Exec, Mach bootstrap look-up, XPC connect | No | Seatbelt refuses first, so ES sees only what Seatbelt allows |

Capture and `observe` metrics therefore cover file and socket attempts fully.
For exec and Mach/XPC they cover only operations Seatbelt permits and ES would
narrow. Seatbelt denials in those two classes still reach diagnostics through
the existing unified-log reader.

### Modes

`macos.endpoint_security.mode`:

| Mode | Seatbelt profile | ES role | If the gate is lost mid-session |
| --- | --- | --- | --- |
| `off` (default) | as today | none | n/a |
| `harden` | **unchanged** from today | Narrowing only: exec policy, Mach/XPC allow-list, uipc rules, finer process rules, setuid block, audit events | The profile is still today's baseline, so nothing is wider than in `off`. The tree is stopped if `required`, otherwise nono warns loudly and records it in audit. |
| `approve` | today's profile **plus** the approvable envelope | Everything in `harden`, plus default-deny and prompts for envelope paths | **The whole tree is killed.** Without the gate the envelope would be open. |

Within `harden`, each rule family can be set to `observe`, which logs and
audits what it would deny so allow-lists can be tuned before enforcing.

### The supervisor is the client

A scoped client covers the *caller's* descendants, and the client belongs to
the process that created it, so the creating process must never `exec`. The nono supervisor already satisfies both conditions: it is the
ancestor of every sandboxed process and it never execs. **The supervisor is
the ES client.** No new process or binary is needed.

```
nono (supervisor; ES artifact = entitled)
 |   1. create the scoped client; FAIL_CLOSED; deadlines; mutes
 |   2. es_subscribe; es_sync_client  -> gate armed
 +- watchdog (fork of nono, no exec)                   (host domain, muted)
 +- proxy / credential sources / @git token lookups    (host domain, muted)
 +- nono __child-bootstrap        (session sandbox, domain 0)
 |    +- sandbox_init (Seatbelt) -> exec agent
 +- tool-sandbox launcher          (command sandbox, domain 1: git)
 |    +- sandbox_init (Seatbelt) -> exec git
 +- tool-sandbox launcher          (command sandbox, domain 2: npm)
```

- **Policy domains.** Each sandboxed launch the supervisor makes (the session
  child and each tool-sandbox launcher) is the root of a *domain*. The
  supervisor binds the domain ID to the root's audit token at fork, and every
  descendant inherits it through `NOTIFY_FORK`/`NOTIFY_EXEC` lineage. AUTH
  events are evaluated against their domain's rules, so one client enforces
  different rules for the session sandbox and each command sandbox.
- **The host domain.** The supervisor's own unsandboxed children (proxy,
  credential sources, approval helpers, the watchdog) are in the ES subtree
  too. Any process that does not descend from a domain root is *host*. Host
  processes are muted with `es_mute_process` when the fork notification
  arrives, and any AUTH before the mute is answered ALLOW from the fast path.
  A sandboxed process cannot become host: domain membership comes only from
  kernel lineage.
- **Handler threading.** ES messages are handled on a dedicated queue that
  never waits on other supervisor work. Static decisions are answered inline.
  Decisions needing a prompt use `es_retain_message` and are answered
  asynchronously, so an approval helper (itself in the host domain) can never
  deadlock the handler.
- **Watchdog.** A fork of the supervisor (no `exec`) holds a pipe to the
  supervisor and receives the live domain audit tokens. If the supervisor
  dies, the pipe closes and the watchdog kills every tracked process. This
  covers the case the ES client cannot: the client dies with the supervisor.

### Library/CLI split

- **`nono` (library), mechanism, macOS-only behind a cargo feature
  `endpoint-security`:** FFI to `libEndpointSecurity`, weak-linked or resolved
  with `dlsym` so the library loads on macOS < 27; a client wrapper that
  subscribes, sets deadlines and mutes as asked; domain tracking from
  fork/exec/exit lineage keyed by audit token; event decoding into owned,
  path-normalized structs; and an availability probe that tries to create a
  client. The library applies only the subscriptions and domain bindings it is
  given and makes no allow/deny decisions of its own.
- **`nono-cli`, policy:** the mode and profile schema, the envelope, default
  allow-lists, per-domain rule evaluation, prompts through the existing
  approval runtime and backends, the watchdog, audit, diagnostics and
  `nono why` output.

### Configuration surface

```jsonc
{
  "macos": {
    "endpoint_security": {
      "mode": "harden",            // off | harden | approve
      "required": false,           // true: startup error if the gate is unavailable
      "exec":  { "enforce": "observe",     // observe | enforce
                 "default": "allow" },     // allow | prompt | deny
      "mach":  { "enforce": "observe", "allow": ["com.apple.coreservices.launchservicesd"] },
      "uipc":  { "enforce": "enforce" },
      "approvable": ["$WORKDIR/..", "$HOME/Library/Caches"]  // approve mode only
    }
  }
}
```

Merge semantics follow the NEP-0004 precedent: layers can add protection but
not remove it.

- `mode` takes the stricter value for narrowing. Moving to `approve` also
  widens the Seatbelt ceiling, so `approve` from a pack or `extends` layer is
  treated like adding a filesystem grant and shown in startup diagnostics.
- `required` is a logical OR. `enforce` takes the stricter value.
- Allow-lists and `approvable` merge by deduplicated append. `approvable`
  entries are subject to the deny groups: a protected path is never in the
  envelope, and Seatbelt emits it as a hard deny. Seatbelt can express
  deny-within-allow and Landlock cannot, one reason this is macOS-only.

`security.capability_elevation` keeps its Linux meaning. Mapping it onto
`approve` automatically would change macOS semantics silently, so it stays
separate.

The `approvable` envelope defaults to empty: nothing is approvable unless the
profile lists it. The Mach/XPC allow-list ships as a baseline per macOS
release, seeded from `observe`-mode telemetry and reviewed before it is
enforced; profiles extend the baseline.

### Event handling

- **Subscriptions**, used only when the matching rule family is enabled:
  - Auth: `AUTH_EXEC`, `AUTH_OPEN`, `AUTH_CREATE`, `AUTH_UNLINK`,
    `AUTH_RENAME`, `AUTH_LINK`, `AUTH_TRUNCATE`, `AUTH_CLONE`,
    `AUTH_COPYFILE`, `AUTH_EXCHANGEDATA`, `AUTH_SETEXTATTR`,
    `AUTH_DELETEEXTATTR`, `AUTH_SETMODE`, `AUTH_SETACL`, `AUTH_MMAP`
    (PROT_EXEC only), `AUTH_UIPC_CONNECT`, `AUTH_UIPC_BIND`,
    `AUTH_BOOTSTRAP_LOOK_UP`, `AUTH_BOOTSTRAP_CHECK_IN`, `AUTH_XPC_CONNECT`,
    `AUTH_SIGNAL`, `AUTH_PROC_CHECK`, `AUTH_GET_TASK*`, `AUTH_IOKIT_OPEN`.
  - Notify: `FORK`, `EXEC`, `EXIT`, plus the audit families in Phase 4.
- **Responses.** `AUTH_OPEN` is answered with `es_respond_flags_result`: for a
  read-only grant, `FREAD` with `FWRITE` stripped. Every other auth event is
  answered with `es_respond_auth_result`.
- **Attribution of bootstrap and XPC events.** Bootstrap look-up events name
  launchd as the submitting process. The gate attributes them to the agent
  through the event's instigator, which identifies the process that made the
  request.
- **Load control.** Inverted target-path muting delivers file events only for
  paths in the envelope and rule tables; all other file operations get the
  Seatbelt verdict alone. Inverted muting also suppresses exec events, so exec
  events are re-enabled for every path with `es_mute_path_events`. Host-domain
  processes are muted. Hot-path verdicts
  come from in-memory identity and path tables inside a short per-event
  maximum deadline. Prompted events use `es_set_deadline_min_milliseconds` so
  a person can answer: 120 s by default, configurable, and the result is deny
  on timeout.
- **Caching.** The ES auth cache is shared by every ES client on the system,
  `es_clear_cache` is global and rate-limited, and creating a client clears
  it. The gate always responds with `cache=false`. The sharing is real: a
  cached allow from one client suppressed another client's `AUTH` event for
  the same executable and file, although the two clients' process trees were
  unrelated. Not caching keeps nono's own decisions out of the cache, but it
  cannot stop another ES client on the host from caching an allow that
  preempts the gate (see Security Considerations).
- **Cost.** On a compiler-heavy workload (40 `clang` runs and a `git status`),
  deciding every open and exec in a minimal handler added about 30% wall-clock
  time, and delivering file events only for a narrow prefix about 20%. Hot-path
  decisions therefore come from in-memory tables.
- **Approvals** reuse the existing approval runtime and backends. Scopes are
  once, session or deny, and session approvals update the in-memory tables.

### Relation to NEP-0002

NEP-0002 owns the `approval_fs` schema and decision rules. This NEP supplies a
macOS enforcement mechanism for them. The command sandbox's Seatbelt profile
includes the `read_roots` and `write_roots` (minus deny paths, which Seatbelt
hard-denies), and the gate default-denies inside them, approving when the tool
touches the path. There is no request channel and no relaunch, and
`NONO_TOOL_SANDBOX_FS_REQUEST` remains the Linux mechanism and the macOS
fallback without the gate. An approval is keyed to `(domain, path, access)`
and discarded when the domain's root exits, so a later invocation starts with
nothing approved. The `es_file_t` in the AUTH message is the object the kernel
resolved, so the decision and the object it applies to are the same (see Path
handling). The two NEPs can ship independently.

### Distribution: plain and ES artifacts

The entitlement is the only thing that differs between builds. nolabs has
applied to Apple for `com.apple.developer.endpoint-security.client`, and this
NEP assumes it is granted for the nolabs Developer ID team (see Assumptions).
The grant is tied to that team, so only binaries signed by nolabs, or by a
team with its own grant, can create an ES client.

**One build, two signings.** The release job compiles `nono` once per macOS
target and signs the same binary twice:

| Artifact | Signing | Shape | Who gets it |
| --- | --- | --- | --- |
| **Plain** (exists today) | Developer ID, hardened runtime, notarized. No entitlement. | Bare executable, unchanged | Current tarball, install scripts |
| **ES** (new), e.g. `nono-vX-aarch64-apple-darwin-es.tar.gz` | Same identity and runtime, plus the ES entitlement and provisioning profile. Notarized. | An app-like wrapper (`Nono.app/Contents/MacOS/nono` plus `Contents/embedded.provisionprofile`) with `nono` on PATH as a symlink into it | Users who want the ES layer |

**The ES artifact is an app-like wrapper.** A restricted entitlement must be
authorized by a provisioning profile, and Apple's guidance is that a
command-line tool cannot embed one. Testing confirmed the consequence: a
signed bare executable carrying the entitlement was killed at launch, with no
profile and with the profile embedded in the executable. The wrapper
(`Nono.app/Contents/MacOS/nono` plus `Contents/embedded.provisionprofile`)
launched normally, from a copied location and through a symlink, and creating
the client needed no root and no Full Disk Access. The user still types `nono`
and the code is identical to the plain artifact.

**At runtime both artifacts run the same code.** nono tries to create the
client. The ES artifact succeeds. The plain artifact gets `ERR_NOT_ENTITLED`
and runs Seatbelt-only, as today.

| Channel | Artifact | Effective tier |
| --- | --- | --- |
| GitHub release tarball (plain) | plain | Seatbelt-only, as today |
| GitHub release tarball (ES) | ES | Full (macOS 27+) |
| Signed `.pkg` (new, optional) | ES, installed root-owned | Full. A root-owned install resists replacement by the user, and so by the agent. |
| Homebrew core formula | Built from source, so effectively plain | Seatbelt-only, as today |
| Homebrew cask or nolabs tap (proposed) | ES, prebuilt from GitHub releases | Full |
| `cargo install`, source, dev builds | plain | Seatbelt-only |
| Organisations with their own ES grant | They sign nono with their team and profile | Full |

The signed `.pkg` is the recommended install path for users who want the
layer, because a root-owned install resists replacement by the user and so by
the agent. The Homebrew core formula is documented as Seatbelt-only. The ES
artifact is distributed through a nolabs tap first, with a homebrew-cask
submission considered once the layer is stable.

**Release pipeline changes** (`.github/workflows/release.yml`, following
`docs/maintainers/releasing.md`):

- After the existing plain signing and notarization, produce the ES artifact
  from the same build output: sign with the entitlements plist and
  provisioning profile (and wrapper if needed), then notarize. Both happen
  before packaging so checksums and provenance attestations cover both.
- **Never sign the plain artifact with the entitlement.** An entitled binary
  without a valid profile is killed at launch. CI asserts the plain
  artifact's signature has no entitlements.
- **Decode the profile and check it before signing.** A profile
  generated before the capability was enabled on the App ID lacks the
  entitlement, even though the portal lists the capability. CI must decode the
  profile (`security cms -D`) and require
  `com.apple.developer.endpoint-security.client` and the release device or
  certificate, and fail the release otherwise. Never ship an "ES" artifact
  that silently lacks the entitlement.
- Store the profile as a release secret next to the signing certificate and
  delete it in the existing cleanup step. The profile expires, so the runbook
  needs a renewal step and CI should warn ahead of expiry.
- The ES artifact is likely arm64-only if macOS 27 drops Intel. Confirm
  before Phase 1.

**Diagnostics.** Startup output, `nono doctor`/`nono why` and session audit
metadata record the effective tier (`off`, `harden`, `approve`, or
`unavailable: <reason>`), the binary's team ID and cdhash and whether it is
entitled, and the per-family enforce/observe state. Reasons for `unavailable`
are specific: macOS < 27, a plain build, entitlement rejected at client
creation, or a client setup failure. A plain build with
`macos.endpoint_security` configured prints a one-line hint naming the ES
artifact.

### Platform behavior and compatibility

- macOS 27+ only. On macOS < 27 the gate is `unavailable`, and `required`
  turns that into a startup error.
- Linux and Windows: the `macos.endpoint_security` block is inert. This NEP
  does not change Linux enforcement.
- `nono wrap`: no supervisor, so configuring a mode other than `off` is a
  startup error, matching how NEP-0004 handles `wrap` plus `isolate`.
- Purely additive and default-off. Profiles without the block behave exactly
  as today, and the plain artifact is unchanged. `breaking: false`.

### Phasing

1. **ES client in the supervisor, ES artifact, `harden` mode.** Library ES
   mechanism, domain tracking, host-domain muting and the watchdog. Release
   pipeline for the ES artifact, the `.pkg` and the cask or tap.
   Kernel-enforced command policy, the Mach/XPC allow-list, uipc and process
   rules, the setuid block, and the tier in diagnostics and audit. Every
   family starts in `observe`.
2. **Tool sandboxing in the kernel.** Command sandboxes as policy domains,
   shim-bypass detection by cdhash, exec-time verification of pinned
   executables, kernel lineage attribution, and dropping `setsid` when the
   gate is armed.
3. **Runtime approvals.** `approve` mode (session envelope) and NEP-0002
   `approval_fs` ceilings, both approved when the path is accessed.
   Security-model doc updates.
4. **Audit and rollback integration.** Change sets for rollback,
   kernel-sourced lineage in the ledger, and persistence and escalation
   tripwires as best-effort signals.

Each phase ships independently. `harden` mode (Phases 1 and 2) delivers
command policy, tool sandboxing, the Mach/XPC and socket allow-lists and
capture without widening Seatbelt. Phase 3 adds `approve` mode on top, and can
be left out if its weaker guarantee is not acceptable.

## Security Considerations

### Least privilege

- **`harden` never grants anything.** The Seatbelt profile is byte-identical to
  `off` and ES only adds denials. The worst failure is falling back to today's
  guarantee.
- **`approve` widens the Seatbelt ceiling to the envelope.** The honest
  guarantee is that *the envelope is the boundary, and the gate decides within
  it*. Threat models and user docs must treat the full envelope as reachable
  if the gate is bypassed or lost. This is weaker than Linux elevation, where
  the static grant is the boundary and expansion is brokered. The docs must
  say so plainly and must not describe the two as equivalent.
- The envelope is explicit, bounded and minus the deny groups, which Seatbelt
  hard-denies. There is no "approve anything" default.
- **Open-time only.** ES cannot revoke an fd after open, and `NOTIFY_WRITE`
  arrives after the write. Revoking an approval affects only future opens, so
  session approvals should be scoped narrowly.
- ES does not cover IP networking, `sysctl`, POSIX IPC, PTY ioctls or
  `stat`/access probes. None of those get weaker or stronger from this NEP.

### Fail-secure behavior

- **Arm before spawn.** The supervisor does not widen Seatbelt or fork any
  sandbox domain until the client is created, subscribed, set to `FAIL_CLOSED`
  with its deadlines, and `es_sync_client` has completed. Any failure falls
  back as follows: `approve` drops to the static profile *without* the
  envelope (or errors if `required`); `harden` drops to `off` (or errors if
  `required`). The drop is always reported.
- **`FAIL_CLOSED` is mandatory.** The default `KILL` would kill the
  supervisor, since it is the client. Queue-full drops are denied, so an agent
  that floods events to force missed deadlines gets denials, not a bypass. In
  testing, a missed deadline under `FAIL_CLOSED` denied the operation and the
  client survived; under the default `KILL` mode the client was killed and the
  operation was allowed.
- **Gate loss while the supervisor lives** (client error, handler failure): in
  `approve`, the supervisor kills every process in every domain, by audit
  token and pidversion rather than bare pid so a reused pid cannot redirect
  the kill. In `harden`, this applies if `required` is set.
- **Supervisor death.** The ES client dies with it. The watchdog sees its pipe
  close and kills every tracked domain process. If the watchdog is killed
  first, the next supervisor action notices and does the same. A `SIGKILL` of
  the supervisor leaves a window between death and the watchdog acting, in
  which `approve` has only the widened Seatbelt profile.
- **When the client exits, ES stops deciding and does not stop the tree.**
  Testing killed the client with `SIGKILL` while a child retried a denied
  open: the child kept running and its next open succeeded. The watchdog and
  the kill rules above, not ES, are what end the session.
- Unknown event types, decode failures, truncated paths (`path_truncated`) and
  response errors are all denied.
- **Another ES client can preempt the gate.** Because the result cache is
  shared, a host running another ES product that caches allows can cause some
  `AUTH` events never to reach nono, for executable and file pairs that product
  has already allowed. nono never caches, and creating its client clears the
  cache, but it cannot prevent this. In `harden` mode the result is Seatbelt's
  verdict, as without the gate. In `approve` mode an envelope path could be
  reachable without a prompt for those pairs, so the documentation states that
  `approve` assumes no other ES client caches allows over the envelope.

### Entitled binary and attack surface

- **The ES artifact makes the whole CLI entitled.** The power this adds is
  narrow: observing and denying *the caller's own descendants*. Code running
  inside an ES-artifact nono can restrict only its own children and gains no
  visibility into or control over other processes, so misuse does not
  escalate privilege. This is why a separate privilege-separated helper was
  rejected.
- The hardened runtime and library validation (`--options runtime`) block
  `DYLD_*` injection into the entitled binary.
- **Integrity of the binary on disk.** If the session capability set grants
  write to the running nono's real path (resolved through any wrapper or
  symlink), the gate refuses to arm and reports why. The root-owned `.pkg`
  install avoids this case.
- No helper also means no helper-identity verification, discovery, protocol
  or version skew to get wrong.
- Bootstrap and check-in events cannot take a minimum deadline, so Mach/XPC
  rules are static tables with no prompts.

### Command policy and tool sandboxing

- **Identity matching limits.** cdhash pins break on legitimate updates, so
  name-resolved entries are re-resolved at session start and a cdhash that
  changes mid-session is denied. `team_id` and `signing_id` trust Apple's
  code-signing chain, and ad-hoc signatures have no team ID. `CS_VALID` covers
  only pages validated so far, so matching is an identity check, not a malware
  verdict.
- **Interpreters stay hard.** `AUTH_EXEC` sees `python -c '...'` and
  `bash -c '...'` as the interpreter only. Command policy on interpreters is as
  strong as on any other binary but cannot see what the interpreter runs. This
  is the same limit as today and the docs must not claim more.
- **The shim is still the launch path.** A tool exec'd without its shim is
  denied, not re-sandboxed.
- **Domain integrity.** A domain is assigned only by the supervisor when it
  forks a domain root and inherited only through kernel lineage. Audit tokens
  include pidversion, so pid reuse cannot inherit a domain. A mute is never
  applied because a process asks for it.
- **Fewer unsandboxed helpers.** Lineage held in testing for a double-forked
  grandchild and for a `setsid` daemon, both reparented to launchd. Under the
  gate, `daemon_pid_source` helpers, which run unsandboxed in the supervisor
  today, are unnecessary, and `setsid` is not needed for attribution.
  Processes launched by launchd on the agent's behalf are not descendants and
  are not covered by lineage; Seatbelt and the Mach/XPC allow-list govern what
  the agent can ask launchd to start.
- **Expansion ceilings.** NEP-0002 roots become Seatbelt-reachable for the
  command sandbox when the gate is armed, so the ceiling, not the approved
  path, is the boundary under gate loss. The kill rules cover every domain.

### Path handling

- ES supplies kernel-resolved paths in `es_file_t`: `/tmp/x` arrives as
  `/private/tmp/x`, and a deny rule written against the unresolved path does
  not match. The CLI compares by `Path` component, never
  string prefix; normalizes firmlinks (`/System/Volumes/Data`) and the
  `/private` aliases; and handles APFS case-insensitivity. Policy entries are
  canonicalized the same way as capability paths. One implementation serves
  the fast-path tables and the policy layer.
- **Create and rename destinations** arrive as a (resolved dir, filename) pair
  for a node that does not exist yet. The directory arrives already resolved
  (a create under `/tmp/d` reported `/private/tmp/d` plus the filename).
  Filenames containing `/` or equal to `..` are denied.
- **Hard links.** `AUTH_LINK` is denied when the source lies outside what the
  destination's rules allow, to stop identity laundering into the envelope.
- **Atomicity.** The value of `AUTH_OPEN` and `AUTH_UIPC_CONNECT` depends on
  the kernel using the same object it authorized. Unlike the seccomp-notify
  `sockaddr` case, the decision is made on a resolved object inside the
  kernel. Testing swapped a symlink, and separately an intermediate directory
  symlink, between an allowed and a denied target while a process opened the
  path 300,000 times each. ES denied exactly the opens that resolved to the
  denied target, and the process never read denied content after an allow.
  The socket path for `AUTH_UIPC_CONNECT` was not raced separately.

### Library/CLI boundary

The library gains mechanism only: FFI, the client wrapper, domain lineage
tracking and event decoding. Mode semantics, the envelope, allow-lists,
identity rules, prompts, the watchdog and diagnostics stay in `nono-cli`.

### Credential and secret secrecy

`AUTH_EXEC` carries the full argv and environment, which can include phantom
tokens or real secrets. The ES handler copies only the fields a rule needs.
Environment values are never copied, only names when a rule requires them.
Argv goes into `Zeroizing` buffers and is redacted before it reaches logs,
diagnostics or audit. The same handling applies to `NOTIFY_TCC_MODIFY`
identities and to file paths under credential deny groups.

## Alternatives Considered

- **Sandbox extension tokens plus the DYLD token-receiver shim** (the
  existing `nono grant` route). Rejected as the general mechanism: tokens must be consumed
  inside the agent, and SIP and the hardened runtime strip the injection for
  `/usr/bin/env`, shells and standalone agent binaries. The first denied open
  also still fails. The shim and `nono grant` remain a useful path for
  cooperating SDK agents and interpreters where the shim loads.
- **ES as the primary gate over a broad Seatbelt grant, with no `harden`
  fallback.** Rejected as the only shape: the envelope is open if the gate is
  lost. `approve` mode is this design with the kill rules, the watchdog and
  `FAIL_CLOSED` added, and `harden` exists so the layer is still useful
  without it.
- **A separate entitled helper binary.** Rejected. The ES
  client must be an ancestor of the agent that never `exec`s, and the
  supervisor already is. Unentitled builds degrade the same way with or
  without a helper, and the entitlement's power is too narrow to need
  privilege separation. A helper would add discovery, runtime identity
  verification, a protocol to version and fuzz, version skew and a second
  failure mode.
- **One entitled artifact for everyone.** Rejected: it would change the shape
  of the existing artifact for every user and install script, and the
  Homebrew core formula builds from source and cannot carry the entitlement.
- **Replace Seatbelt with ES** (the direction explored in openai/codex#38028).
  Rejected: no IP, `sysctl`, POSIX IPC or PTY-ioctl hooks and no fd-level
  enforcement, so it would weaken the boundary.
- **System-wide ES client or an ES system extension.** Needs root or Full
  Disk Access and an approval flow, and observes the whole host. A
  scoped client needs neither.
- **Revive `commands.{allow,deny}` as a kernel-enforced field.** Rejected:
  NEP-0001 removes those fields for 1.0, and deny-only `command_policies`
  entries express the same intent with caller edges.
- **Redirect exec into the broker in the kernel.** Not possible: ES can only
  allow, deny or strip flags, so a direct exec of a mediated tool is denied.
- **Do nothing.** macOS stays static-only and over-granting continues.

## Assumptions

- **Entitlement granted.** Apple grants
  `com.apple.developer.endpoint-security.client` to the nolabs Developer ID
  team for a Developer ID-distributed command-line tool. The application is
  submitted. If it is refused, this NEP is blocked as written; the fallback is
  that only organisations with their own grant can use the gate, which is not
  a viable default product. Development builds work today with a development
  profile.
- **Grant scope.** The grant covers Developer ID distribution outside the App
  Store. A grant limited to development builds, or to the App Store, would
  block the ES tarball, `.pkg` and cask channels. Confirm the provisioning
  profile type when it is issued.
- **Notarization.** Apple notarization accepts the wrapper layout. The release
  pipeline notarizes and staples it, and a rejection fails the release.
