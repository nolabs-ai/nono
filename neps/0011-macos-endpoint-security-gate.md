---
nep: 0011
title: macOS Endpoint Security gate for runtime approvals and hardening
authors:
  - lukehinds
status: draft
created: 2026-11-13
breaking: false
superseded-by:
---

# NEP-0011: macOS Endpoint Security gate for runtime approvals and hardening

## Summary

Add an opt-in macOS enforcement layer built on Endpoint Security's
`es_new_descendants_client` (macOS 27+). A small, separately signed and
entitled helper, `nono-es-gate`, owns an ES client scoped to the sandboxed
process tree and forwards authorization events to the nono supervisor.
Seatbelt stays the static, irreversible boundary. ES adds kernel-enforced
decisions inside that boundary: tree-wide exec policy, Mach/XPC allow-lists,
Unix-socket mediation, and runtime approvals for file access.

Two further changes follow from this layer:
- **Tool sandboxing moves from userspace to the kernel.** Command mediation
  stops depending on PATH shims, the PATH-scan exec allow-list, the ancestry
  walk and `setsid` markers. The kernel sees every exec in the tree and its
  lineage.
- **Grant expansion on macOS.** NEP-0002's `approval_fs` ceilings and the
  session's approvable envelope are approved at the moment of access.
  Today a request must be declared up front and the child relaunched.

The main `nono` binary needs no entitlement. Unsigned and source builds, including the
Homebrew core formula, keep today's Seatbelt-only behaviour, and that
difference is reported, never silent.

## Motivation

The macOS model today is "Seatbelt is the single enforcement layer"
(`docs/cli/internals/security-model.mdx`, *macOS Model*). That leaves gaps
compared with Linux:

- **No runtime capability expansion on macOS.** Linux supervised mode can
  prompt and broker a file descriptor (`security.capability_elevation`). On
  macOS a missing grant means restarting the session with a wider profile,
  so users over-grant up front.
- **Command policy isn't kernel-enforced.** `commands.{allow,deny}` was
  deprecated in v0.33.0 as "startup-only command gating, not
  kernel-enforced. Child processes can bypass it." Seatbelt can scope
  `process-exec*` by path but not by code-signing identity, and it can't
  ask.
- **Mach services use a deny-list.** The profile emits `(allow mach-lookup)`
  then denies securityd/keychain names
  (`crates/nono/src/sandbox/macos.rs:558-580`). Every other launchd service
  is reachable, and the owner's identity is never checked.
- **Process scoping is coarse.** `process-info*` and `signal` use
  `same-sandbox` because Seatbelt can't tell an agent's own children apart
  (`macos.rs:535-619`).
- **Escalation and persistence classes aren't observed.** Examples are
  setuid execs, LaunchAgent installation, and TCC changes.
- **Tool sandboxing (command mediation) on macOS is enforced in userspace,
  with known gaps** (`docs/cli/features/tool-sandbox.mdx`):
  - **Reaching tools.** Agents reach mediated tools through PATH shims. Direct
    execution of a tool is blocked by `(deny process-exec* (literal …))` rules
    for canonical paths (`deny_direct_exec_bypass`). A copied or renamed
    binary is a different path.
  - **Session exec allow-list.** It is built by scanning PATH directories at
    startup. Binaries outside PATH (the `jspawnhelper` class) are denied
    unless listed by hand, and binaries that appear later aren't covered.
  - **Pinned executables.** These are verified, then exec'd by path, because
    macOS has no `fexecve`. The docs warn that a sandbox-writable executable
    "remains replaceable before launch".
  - **Caller attribution.** It walks process ancestry. To survive
    reparenting, every mediated command is put in its own POSIX session
    (`setsid`), which costs it its controlling terminal: `/dev/tty` fails
    with `ENXIO`, `ssh` passphrase prompts fail, and nono has to relay job
    control. Double-forking daemons need declared `daemon_pid_source`
    helpers that run **unsandboxed** in the supervisor.
- **Grant expansion for tool sandboxes is declare-then-relaunch.** NEP-0002
  `approval_fs` has a child propose an exact path through
  `NONO_TOOL_SANDBOX_FS_REQUEST`. The supervisor approves it and the grant
  applies only to a *fresh* child sandbox. Tools that find paths while
  running (git, package managers, build systems) must either know their
  paths in advance or be wrapped so they can make that request.

macOS 27 adds `es_new_descendants_client`. It creates an ES client scoped to
the caller's process subtree, including existing descendants, recursively.
It needs **no root and no TCC approval**, but does need the restricted
`com.apple.developer.endpoint-security.client` entitlement. It also adds
deadline controls built for this use: `FAIL_CLOSED` miss mode and a
descendants-only *minimum* deadline long enough for a person to answer a
prompt. A descendants client also blocks setuid/setgid execs across the
whole tree.

The full API audit, with confidence labels, is in
`docs/reports/endpoint-security-api-audit.md`.

### Goals

- Kernel-enforced, tree-wide exec policy on macOS, by path and code-signing
  identity.
- Allow-listed Mach bootstrap lookups and XPC connections, with
  service-owner identity checks.
- Pathname Unix-socket connect/bind mediation on macOS, decided in the
  kernel on the resolved socket file.
- Runtime file approvals on macOS through the existing approval backends
  (terminal, webhook), inside a declared, bounded envelope.
- **Move tool-sandbox enforcement to the kernel on macOS:**
  - every exec in the tree is decided by kernel-resolved identity (cdhash,
    signing ID, vnode), not by PATH position or shim reachability;
  - caller attribution comes from kernel-sourced lineage;
  - pinned executables are checked at exec time, not before it.
  - Shims remain the way a request *reaches* the broker, but stop being the
    boundary.
- **Grant expansion for tool sandboxes on macOS.** NEP-0002 `approval_fs`
  ceilings become the command sandbox's envelope, and approvals happen when
  the tool touches the path, with no request channel and no relaunch.
- Remove the `setsid` requirement for mediated commands when the gate is
  active, so tools keep their controlling terminal.
- **One `nono` binary that installs from any channel**, including the
  Homebrew core formula, cargo and source builds. ES support is an add-on
  component, not a requirement.
- Fail secure: a missing, unverified or failed gate never widens Seatbelt,
  and the effective tier is always reported.

### Non-Goals

- Replacing Seatbelt. ES has no IP-network hook, no sysctl, POSIX IPC/shm
  or PTY-ioctl authorization, and no enforcement on already-open
  descriptors. Seatbelt and the proxy stay the boundary for those.
- Parity with Linux fd brokering. ES can only narrow access, so approve mode
  is a gate inside a ceiling, not a broker (see Security Considerations).
- Supporting macOS earlier than 27.
- Supporting `nono wrap`, which has no supervisor.
- A system-wide ES client (`es_new_client`), which needs root and Full Disk
  Access.

## Proposal

### Enforcement model: ceiling plus gate

Seatbelt and ES both sit on the XNU MAC framework, and an operation must pass
both. ES can deny or strip flags but can't override a Seatbelt deny. So:

```
Seatbelt (static, applied in child before exec)   ES gate (dynamic, nono-es-gate + supervisor)
----------------------------------------------    ---------------------------------------------
hard denies: deny groups, credentials,            default-deny inside the envelope
  keychains, IP egress, proxy-only network        prompt -> allow once / allow session / deny
baseline grants (as today)                        strip FWRITE from opens granted read-only
approve mode only: + approvable envelope    --->  exec / mach / xpc / uipc / process rules
```

### Modes

`macos.endpoint_security.mode`:

| Mode | Seatbelt profile | ES role | If the gate is lost mid-session |
| --- | --- | --- | --- |
| `off` (default) | as today | none | n/a |
| `harden` | **unchanged** from today | Narrowing only: exec policy, Mach/XPC allow-list, uipc rules, finer process rules, setuid block, audit events | The profile is still today's baseline, so nothing is wider than in `off`. The supervisor stops the tree if `required`, otherwise warns loudly and records it in audit. |
| `approve` | today's profile **plus** the approvable envelope | Everything in `harden`, plus default-deny and prompts for envelope paths | **The supervisor kills the whole tree.** Without the gate the envelope would be open. |

Within `harden`, each rule family can be set to `observe`, which logs and
audits what it would deny, so allow-lists can be tuned before enforcing.
This matters most for Mach/XPC, which macOS tooling uses heavily and with
little documentation.

### Components and process tree

`es_new_descendants_client` covers the **caller's** descendants, so the ES
client process must be an ancestor of the agent. The ES client is lost if
its process `exec`s.

```
nono (supervisor, unentitled, any build)
 └─ nono-es-gate (entitled helper, Developer ID + provisioning profile)
     │   1. read GateSpec from supervisor over inherited socketpair
     │   2. es_new_descendants_client, set FAIL_CLOSED, deadlines, mutes
     │   3. es_subscribe, es_sync_client, send "armed" to supervisor
     ├─ fork + exec: nono __child-bootstrap        (session sandbox, domain 0)
     │    └─ sandbox_init (Seatbelt) -> exec agent
     ├─ fork + exec: nono tool-sandbox launcher    (command sandbox, domain 1: git)
     │    └─ sandbox_init (Seatbelt) -> exec git
     └─ fork + exec: nono tool-sandbox launcher    (command sandbox, domain 2: npm)
          └─ ...
```

**The helper is the single launcher for every sandboxed process in the
session.** Today the supervisor spawns the tool-sandbox launcher directly
(`tool-sandbox/launch.rs`), which would put command sandboxes outside the
ES subtree. Under the gate, the supervisor asks the helper to fork the same
launcher argv on its behalf. Each launch creates a **policy domain**, a
domain ID the supervisor assigns and that the helper binds to the forked
child's audit token. Every descendant inherits its root's domain through
`NOTIFY_FORK`/`NOTIFY_EXEC` lineage, which the helper tracks. Each AUTH
event carries its domain to the supervisor, so one ES client enforces
different rules for the session sandbox and for each command sandbox.

- **Supervisor (`nono`)** owns all policy:
  - builds a `GateSpec` (subscriptions, inverted target-path mutes, static
    allow/deny tables, deadline settings);
  - receives forwarded AUTH events;
  - decides, prompts and audits;
  - sends verdicts.

  It does not widen Seatbelt until it has received "armed" from a helper
  whose code identity it has verified.
- **`nono-es-gate`** is mechanism only, and small:
  - creates the client and applies the `GateSpec`;
  - answers hot-path events from the static tables within the deadline;
  - forwards everything else to the supervisor;
  - streams fork/exec/exit notifications so the supervisor has a pid set
    sourced from the kernel.

  It has no network access, no profile parsing and no prompts. It runs
  under the hardened runtime with library validation.
- **Bootstrap reuse.** The helper's child execs the existing `nono` child
  bootstrap with the prepared state on an inherited fd. Seatbelt is still
  applied in the child before exec, exactly as today. The helper never
  applies policy itself.

### Library/CLI split

- **`nono` (library), mechanism, macOS-only behind a cargo feature
  `endpoint-security`:**
  - FFI to `libEndpointSecurity`, weak-linked or resolved with `dlsym`, so
    the library still loads on macOS < 27;
  - `GateSpec` and the wire-protocol types (versioned, length-prefixed,
    fixed-size fields, no serde of untrusted shapes);
  - an availability probe that tries to create a client rather than
    reading the OS version;
  - event decoding into owned, path-normalized structs.

  The library applies only the spec it is given.
- **`crates/nono-es-gate` (new workspace package, unpublished binary):**
  the helper. It depends on the library mechanism and contains no policy.
- **`nono-cli`, policy:**
  - the mode and profile schema, the envelope, default allow-lists (for
    example a baseline Mach service list per macOS version), and rule
    evaluation;
  - prompts through the existing approval runtime
    (`approval_runtime.rs`, `terminal_approval.rs`,
    `security.approval_backend`), audit, diagnostics, `nono why` output,
    and helper discovery and verification.

### Configuration surface

Profile (everything defaults to off):

```jsonc
{
  "macos": {
    "endpoint_security": {
      "mode": "harden",            // off | harden | approve
      "required": false,           // true: startup error if the gate is unavailable
      "exec":  { "enforce": "observe",     // observe | enforce
                 "default": "allow" },     // allow | prompt | deny (unlisted executables)
      "mach":  { "enforce": "observe", "allow": ["com.apple.coreservices.launchservicesd"] },
      "uipc":  { "enforce": "enforce" },
      "approvable": ["$WORKDIR/..", "$HOME/Library/Caches"]  // approve mode only
    }
  }
}
```

Merge semantics, following the NEP-0004 precedent that layers can add
protection but not remove it:

- `mode` takes the **stricter** value across layers for narrowing.
  Moving to `approve` also widens the Seatbelt ceiling, so `approve` from a
  pack or `extends` layer is treated like adding a filesystem grant and
  shown in the startup diagnostics.
- `required` is a logical OR.
- `enforce` takes the stricter value.
- Allow-lists and `approvable` merge by deduplicated append. `approvable`
  entries are subject to the deny groups: a protected path is never in the
  envelope, and Seatbelt emits it as a hard deny. Seatbelt can express
  deny-within-allow, Landlock cannot, which is one reason this is
  macOS-only.

`security.capability_elevation` keeps its Linux meaning. Mapping it onto
`approve` automatically would change macOS semantics silently, so it stays
separate (see Open Questions).

Configuration that is **not profile-settable**, because profiles and packs
are untrusted input: the helper path override and any additional trusted
signing team. These live in user-level nono config only.

### Distribution and unsigned builds

The central constraint is the entitlement. nolabs has applied to Apple for
`com.apple.developer.endpoint-security.client`, and **this NEP assumes it is
granted** for the nolabs Developer ID team (see Assumptions). The grant is
tied to that team, so only binaries signed by nolabs, or by another team
with its own grant, can create an ES client.

A restricted entitlement must be authorized by a provisioning profile, and a
bare Mach-O can't embed one. The standard pattern is a minimal app-like
bundle (`Contents/MacOS/<exe>`, `Contents/embedded.provisionprofile`), even
for a CLI helper. Apple's own `eslogger` shows CLI ES clients are supported.
Phase 1 confirms the exact bundle layout and notarization with the granted
profile. **The main `nono` binary stays unentitled and bare**, which is what
makes every distribution channel keep working.

Release pipeline changes (`.github/workflows/release.yml`, following
`docs/maintainers/releasing.md`):
- Build `nono-es-gate` for both macOS targets and assemble
  `NonoESGate.app` with the embedded provisioning profile.
- Sign it with the existing Developer ID identity, the hardened runtime, the
  entitlements plist and identifier `ai.nolabs.nono.es-gate`, then notarize
  it in the same job as `nono`, before packaging, so checksums and
  provenance attestations cover the signed bundle.
- Store the provisioning profile as a release secret next to the signing
  certificate, and delete it in the existing cleanup step.
- Fail the release if the bundle's signature, entitlement or profile check
  fails. Never ship a tarball whose helper silently lacks the entitlement.
- The profile expires, so the runbook needs a renewal step and CI should
  warn ahead of expiry.

| Channel | `nono` | `nono-es-gate` | Effective tier |
| --- | --- | --- | --- |
| GitHub release tarball (macOS) | Developer ID signed + notarized (today) | Bundled `NonoESGate.app`, signed + notarized, with provisioning profile | Full (macOS 27+) |
| Signed `.pkg` (new, optional) | as above | Installed root-owned under `/Library/Application Support/nolabs/nono/` | Full. The root-owned helper resists tampering by the user, and so by the agent. |
| Homebrew core formula (`brew install nono`) | Built from source by Homebrew and ad-hoc signed | **Not present.** homebrew-core builds from source and can't sign with our identity. | Seatbelt-only, as today |
| Homebrew cask `nono-es-gate` (proposed) | any | Prebuilt signed bundle from GitHub releases. Casks distribute prebuilt signed artifacts. | Full, once the user runs `brew install --cask nono-es-gate` |
| `cargo install`, source, dev builds | unsigned or ad-hoc | Not present, or self-built without the entitlement (cannot create a client) | Seatbelt-only |
| Organisations with their own ES entitlement | any | Self-signed with their team ID, trusted via user-level config | Full |

**Helper discovery** checks these locations in order, and the first verified
match wins:
1. user-config override;
2. alongside the running binary
   (`<prefix>/libexec/nono/NonoESGate.app`);
3. the `.pkg` location;
4. the cask location.

Each candidate must pass code-identity verification (see Security
Considerations). A candidate that fails is skipped and reported, never run.

**Version skew.** The `GateSpec` handshake carries a protocol version. A
mismatched helper is treated as unavailable. Brew and cask can update
independently, so the handshake has to be strict.

**Diagnostics.** Startup output, `nono doctor`/`nono why` and session audit
metadata record:
- the effective tier (`off`, `harden`, `approve`, or `unavailable: <reason>`);
- the helper path, team ID and cdhash;
- the per-family enforce/observe state.

Reasons for `unavailable` are specific: macOS < 27, helper not found, helper
failed verification, entitlement rejected at client creation, or protocol
mismatch. `brew install nono` users see a one-line hint naming the cask.

### Event handling

- **Subscriptions**, used only when the matching rule family is enabled:
  - Auth: `AUTH_EXEC`, `AUTH_OPEN`, `AUTH_CREATE`, `AUTH_UNLINK`,
    `AUTH_RENAME`, `AUTH_LINK`, `AUTH_TRUNCATE`, `AUTH_CLONE`,
    `AUTH_COPYFILE`, `AUTH_EXCHANGEDATA`, `AUTH_SETEXTATTR`,
    `AUTH_DELETEEXTATTR`, `AUTH_SETMODE`, `AUTH_SETACL`, `AUTH_MMAP`
    (PROT_EXEC only), `AUTH_UIPC_CONNECT`, `AUTH_UIPC_BIND`,
    `AUTH_BOOTSTRAP_LOOK_UP`, `AUTH_BOOTSTRAP_CHECK_IN`, `AUTH_XPC_CONNECT`,
    `AUTH_SIGNAL`, `AUTH_PROC_CHECK`, `AUTH_GET_TASK*`, `AUTH_IOKIT_OPEN`.
  - Notify: `FORK`, `EXEC`, `EXIT`, plus audit families in Phase 3.
- **Load control:**
  - Use inverted **target-path** muting so the kernel delivers file events
    only for paths in the envelope and rule tables. All other file
    operations get the Seatbelt verdict alone.
  - Hot-path verdicts come from the helper's static tables, answered within
    a short per-event max deadline.
  - Prompted events use `es_set_deadline_min_milliseconds` (descendants
    clients only) so a person can answer. The default is 120 s,
    configurable, and the result is deny on timeout.
- **Caching:** the ES auth cache is shared by every ES client on the system,
  and `es_clear_cache` is global. Phase 1–2 respond with `cache=false`.
  Caching is revisited only if the spike shows decisions can't leak across
  clients.
- **Open:** respond with `es_respond_flags_result`. For a read-only grant,
  answer with `FREAD` and strip `FWRITE`.
- **Approvals** reuse the existing approval runtime and backends. Scopes are
  once, session, or deny. Session approvals live in the supervisor and are
  pushed into the helper's tables.

### Kernel-enforced command policy

Command policy was deprecated in v0.33.0 because it wasn't a boundary:
`commands.{allow,deny}` checked only the startup command, and "child
processes can bypass it". NEP-0001 retires those fields for 1.0, and
deny-only `command_policies` entries are the successor
(`docs/cli/features/dangerous-command-blocking.mdx`). Those entries are
still enforced by shims plus Seatbelt path literals, so a copied, renamed
or interpreter-launched binary gets past them.

With the gate, `AUTH_EXEC` covers **every exec in every domain of the
tree**, so command policy becomes kernel-enforced on macOS. This NEP
**doesn't bring back `commands.{allow,deny}`**. It enforces the existing
`command_policies` model in the kernel and adds identity matching:

- **What is enforced.** These are evaluated at `AUTH_EXEC` for the domain
  the exec happens in:
  - deny-only entries (`from.session: "deny"`, `from.<caller>: "deny"`);
  - inherited `dangerous_commands` groups;
  - `can_use` edges.

  A denied exec fails with `EPERM` in the kernel, wherever in the tree it
  happens and whatever path or name it uses.
- **What it matches on.** The kernel supplies the exec target's identity.
  A command entry gains an optional `match` block, in addition to today's
  name and `executable` resolution:

  ```jsonc
  "command_policies": {
    "commands": {
      "sudo":   { "from": { "session": "deny" } },          // resolved by name as today, then pinned by cdhash
      "docker": {
        "match": { "team_id": "<DOCKER_TEAM_ID>", "signing_id": "com.docker.docker" },
        "from":  { "session": "deny" }
      },
      "unsigned-helpers": {
        "match": { "cs_validation_category": ["none", "local_signing"],
                   "under": ["$WORKDIR", "$TMPDIR"] },
        "from":  { "session": "deny" }                     // no exec of agent-built, unsigned binaries
      }
    }
  }
  ```

  - **Identity fields:** `cdhash`, `signing_id`, `team_id`,
    `is_platform_binary` and `cs_validation_category` from `es_process_t`.
  - **Entitlements:** `es_exec_entitlements`, macOS 27. For example, deny
    images that carry `com.apple.security.get-task-allow` or the ES client
    entitlement.
  - **Location:** `under`, compared by path component against the
    kernel-resolved image path.
  - **Name resolution:** name-resolved entries are resolved at startup as
    today and then pinned by **cdhash**. A copy or rename of `/usr/bin/sudo`
    still matches, and on Apple Silicon every Mach-O has a cdhash.
  - **Interpreted scripts:** the decision covers both the interpreter image
    and `es_event_exec_t.script`, so `python evil.py` and `./evil.py` are
    judged on the script's identity as well as the interpreter's.
- **Default for unlisted executables.** This replaces the old
  `commands.allow` allow-list intent.
  `macos.endpoint_security.exec.default` is one of:
  - `allow`: current behaviour; Seatbelt exec rules still apply.
  - `prompt`: through the approval backend, with a long deadline.
  - `deny`: only listed or `commands."*"`-mediated executables run.
- **Modes.** Command policy enforcement is part of `harden`, so it **needs
  no Seatbelt widening** and is safe even if the gate is lost: the
  shim-and-literal enforcement still runs underneath. Each family starts in
  `observe`, which audits would-be denials with full identity, so profiles
  can be tuned before enforcing.
- **Precedence.** Seatbelt exec rules are still evaluated. The gate can
  only deny an exec that Seatbelt allows, never the other way round. A
  command-policy deny is final. An allow from the gate means "not denied
  by command policy", not "granted".

The deprecated `commands.{allow,deny}`, `--block-command` and
`process.blocked_commands` surfaces stay on NEP-0001's removal path. When
the gate is active, migration guidance points users to deny-only
`command_policies` entries, which now get the kernel guarantee the old
fields never had.

### Tool sandboxing in the kernel

When the gate is active, command mediation on macOS keeps its policy model
(`command_policies`, `can_use`/`from` edges, command sandbox policies,
approval backends) but changes where enforcement happens.

| Concern | Today (userspace) | With the gate (kernel) |
| --- | --- | --- |
| Reaching a tool | PATH shim → control socket → supervisor launches a fresh command sandbox | Unchanged. Shims stay the request path, because ES can deny an exec but can't redirect it into a fresh sandbox. |
| Stopping bypass of the shim | `(deny process-exec* (literal <canonical path>))` per mediated tool. A copy or rename escapes it. | `AUTH_EXEC` of any image whose **cdhash** (or vnode, for unsigned scripts) matches a mediated tool is allowed only when the instigator is a launcher the helper itself forked for that tool. On Apple Silicon every Mach-O carries a code signature, at least ad hoc, so a copied or renamed binary keeps its cdhash and is still caught. |
| Session exec allow-list | Seatbelt literals from a PATH scan at startup. Binaries outside PATH need `executable_dirs` or `exec_paths`. | `AUTH_EXEC` decides by identity: allow-list by path, cdhash, signing ID, team ID or `is_platform_binary`. An unknown executable goes to `commands."*"` (NEP-0002) or a prompt instead of a silent deny. The Seatbelt exec ceiling widens to the trusted-dir set, and the gate narrows it. |
| Pinned `executable` | Verified (path, inode, digest), then `execve` by path, so it is replaceable before launch | Verified **at exec time**: the `AUTH_EXEC` target's cdhash and vnode must match the pin, or the exec is denied. Closes the pre-launch replacement gap. For scripts, `es_event_exec_t.script` identifies the script file. |
| Caller attribution | Ancestry walk, `setsid` lineage marker, `daemon_pid_source` helpers run unsandboxed | Domain lineage from kernel fork/exec events, keyed by audit token (pid + pidversion). Daemons that double-fork to launchd stay in their domain *if* descendant tracking follows fork lineage rather than current ppid (Open Question 9). |
| Controlling terminal | Lost (`setsid` on every mediated launch) | Kept. No `setsid` is needed when lineage is kernel-sourced, so `/dev/tty`, `ssh` passphrase prompts and job control work normally. |
| Deny-only commands (`dangerous_commands`) | Shim plus Seatbelt literal | `AUTH_EXEC` by identity across the whole tree (see Kernel-enforced command policy). |
| `allow_direct_exec_bypass` | Compatibility escape that runs with session capabilities | Still supported. The exec is allowed by identity and stays in the caller's domain, so it keeps session rules. |

What doesn't change: command sandboxes are still separate Seatbelt
sandboxes built from their own policy, which is the static ceiling for each
domain. Credentials, environment filtering, stdio mediation and audit
records keep their current paths. Linux keeps cgroup lineage and its
existing mechanisms. This NEP doesn't change Linux tool sandboxing.

When the gate is unavailable (Seatbelt-only builds), tool sandboxing runs
exactly as today, including `setsid` and the PATH-scan allow-list. Any
behaviour that depends on the gate, such as keeping the controlling
terminal, is enabled only after the helper reports "armed". It is never
assumed.

### Grant expansion

ES can only narrow access, so every form of expansion on macOS uses the same
pattern: **the Seatbelt profile for a domain includes a declared ceiling,
and the gate default-denies inside it, approving at the moment of access.**
There are two kinds of ceiling, using the same machinery:

1. **Session envelope**, the `approvable` list (`approve` mode, described
   above).
2. **Command sandbox ceilings**, NEP-0002 `approval_fs.read_roots` and
   `write_roots`. NEP-0002 already defines these as "ceilings, not grants",
   with deny paths applied, an approval backend and a timeout. On macOS with
   the gate active:
   - The command sandbox's Seatbelt profile includes the roots (minus deny
     paths, which Seatbelt hard-denies).
   - `AUTH_OPEN`/`CREATE`/`RENAME`/`UNLINK`/`LINK`/`TRUNCATE` inside the roots,
     from that domain, are forwarded to the supervisor. The supervisor checks
     NEP-0002's rules (exact path, read vs write root, deny paths), asks the
     configured backend, and answers. A read-only approval answers `AUTH_OPEN`
     with `FREAD` and strips `FWRITE`.
   - **No request channel and no relaunch.** The tool doesn't need to know it
     must ask. `NONO_TOOL_SANDBOX_FS_REQUEST` remains the Linux mechanism and
     the macOS fallback without the gate.
   - **Identity is checked at decision time.** NEP-0002 records device and
     inode and checks them again before installing a grant. Here the
     `es_file_t` in the AUTH message is the object the kernel resolved, so
     the decision and the object it applies to are the same, subject to
     Open Question 4.
   - **Invocation scope.** An approval is keyed to `(domain, path, access)`
     and discarded when the domain's root exits. A later invocation of the
     same tool starts with nothing approved, as NEP-0002 requires.
   - Audit records each decision in the existing command-policy audit event,
     tagged with the domain.

Relation to NEP-0002: NEP-0002 owns the `approval_fs` schema and decision
rules. This NEP supplies a macOS enforcement mechanism for them. If NEP-0002
changes its rules, this mechanism follows. The two can ship independently:
without NEP-0002, only the session envelope exists, and without the gate,
NEP-0002 uses its request channel on macOS.

### Platform behavior

- macOS 27+ only. On macOS < 27 the gate is `unavailable`, and `required`
  turns that into a startup error.
- Linux and Windows: the `macos.endpoint_security` block is inert. This
  NEP doesn't change Linux enforcement.
- `nono wrap`: no supervisor, so configuring a mode other than `off` is a
  startup error, matching how NEP-0004 handles `wrap` + `isolate`.

### Backward compatibility

Purely additive and default-off. Profiles without the block behave exactly
as today. `breaking: false` is proposed.

### Phasing

0. **Spike.** Answer the blocking questions listed under Open Questions on
   real macOS 27 hardware, using the granted development provisioning
   profile.
1. **Helper, distribution, `harden` mode.**
   - Ship `nono-es-gate`, signing, notarization, the release tarball and
     the cask.
   - **Kernel-enforced command policy:** deny-only entries,
     `dangerous_commands`, `can_use` edges, `match` identity blocks and
     `exec.default`.
   - The Mach/XPC allow-list, uipc, and process rules.
   - Every family starts in `observe`. The setuid block. The tier in
     diagnostics and audit.
2. **Tool sandboxing in the kernel.**
   - The helper becomes the launcher for command sandboxes (policy
     domains).
   - Shim-bypass detection by cdhash, and exec-time verification of
     pinned executables.
   - Kernel lineage attribution, and dropping `setsid` when the gate is
     armed.
   - `daemon_pid_source` becomes unnecessary under the gate, subject to
     Open Question 9.
3. **Grant expansion.**
   - `approve` mode (session envelope) and NEP-0002 `approval_fs` ceilings
     for command sandboxes, both approved when the path is accessed.
   - The kill-on-gate-loss machinery and security-model doc updates.
4. **Audit and rollback integration.**
   - `NOTIFY_WRITE`/`CLOSE`/`RENAME`/`UNLINK` change sets for rollback.
   - Kernel-sourced lineage in the audit ledger.
   - Persistence and escalation tripwires (`BTM_LAUNCH_ITEM_ADD`, `SUDO`,
     `TCC_MODIFY`) if the spike shows a descendants client receives them.

## Security Considerations

### Least privilege

- **`harden` never grants anything.** The Seatbelt profile is
  byte-identical to `off`, and ES only adds denials. The worst failure is
  falling back to today's guarantee.
- **`approve` widens the Seatbelt ceiling to the envelope.** The honest
  guarantee is that **the envelope is the boundary, and the gate decides
  within it.** Threat models and user docs must treat the full envelope as
  reachable if the gate is bypassed or lost. This is weaker than Linux
  elevation, where the static grant is the boundary and expansion is
  brokered. The docs must say so plainly and must not describe the two as
  equivalent.
- The envelope is explicit, bounded and minus the deny groups, which
  Seatbelt hard-denies. There is no "approve anything" default.
- **Open-time only.** ES can't revoke an fd after open, and `NOTIFY_WRITE`
  arrives after the write. Revoking an approval affects only future opens.
  Session approvals should be scoped narrowly for this reason.

### Fail-secure behavior

- **Arm before spawn.** The supervisor doesn't widen Seatbelt or let the
  agent exec until the helper reports "armed" after `es_sync_client`.
  Failure to create the client, subscribe, set `FAIL_CLOSED` or set
  deadlines falls back as follows:
  - `approve` drops to the static profile **without** the envelope (or
    errors if `required`);
  - `harden` drops to `off` (or errors if `required`);
  - the drop is always reported.
- `FAIL_CLOSED` deadline-miss mode is mandatory. The default `KILL` would
  kill the helper. Queue-full drops are denied.
- **Gate loss** (helper exit, crash or channel EOF): in `approve`, the
  supervisor kills every pid in its kernel-sourced set. It identifies them
  by audit token and pidversion, not bare pid, so a reused pid can't
  redirect the kill. In `harden`, this applies if `required` is set.
- **Supervisor loss:** the helper sees channel EOF, denies everything
  pending, and kills its descendants.
- Unknown event types, decode failures, truncated paths
  (`path_truncated`), and response errors are all denied.
- What a descendants client's subtree does when the client process exits
  isn't documented. Until the spike establishes it, the design assumes the
  worst case, fail-open, and relies on the kill path above.

### Helper integrity and attack surface

- **Verify the running process, not the file.** After spawning the helper,
  the supervisor validates it with `SecCodeCreateWithAuditToken` (from the
  helper's peer token) against a pinned requirement:
  - Apple anchor, Developer ID leaf, nolabs team ID, identifier
    `ai.nolabs.nono.es-gate`;
  - plus any team trusted in user-level config.

  This avoids a check-then-exec TOCTOU on the bundle path.
- The helper bundle path is hard-denied for write in every Seatbelt profile.
  The helper is also rejected if it sits anywhere the session capability
  set grants write, the same rule command mediation applies to executables.
  The root-owned `.pkg` location is preferred.
- **The helper is entitled, so treat it as privileged code.**
  - It ships with a minimal dependency set, the hardened runtime and
    library validation (which blocks `DYLD_*` injection).
  - It runs with a sanitized environment.
  - The wire protocol is fuzzed.
  - Its only extra power is observing and denying **its own** descendants.
    Running it directly lets an attacker restrict only their own children,
    so misuse doesn't escalate privilege.
- Bootstrap and check-in events can't take a minimum deadline (Apple
  refuses this). Mach/XPC rules are therefore static tables only, with no
  prompts.

### Command policy and tool sandboxing

- **Identity matching limits.**
  - cdhash pins break on legitimate updates (a Homebrew upgrade, an Xcode
    CLT update). Name-resolved entries are re-resolved at session start, and
    a cdhash that changes mid-session is denied, which is fail-secure.
  - `team_id` and `signing_id` matching trusts Apple's code-signing chain.
    Ad-hoc signatures have no team ID, so `team_id` matches never apply to
    them.
  - Apple notes `CS_VALID` covers only pages validated so far. A tampered
    page is caught on page-in, and the process is killed only if `CS_KILL`
    is set. Matching is an identity check, not a malware verdict.
- **Interpreters stay hard.** `AUTH_EXEC` sees `python -c '…'` and
  `bash -c '…'` as the interpreter only. Inline code and `source`d files
  aren't execs. Command policy on interpreters is as strong as on any other
  binary, but it can't see what the interpreter runs. This is the same limit
  as today; the docs must not claim more.
- **The shim is still the launch path.** ES can deny an exec but can't
  redirect it into a fresh command sandbox. A tool exec'd without its shim
  is **denied**, not re-sandboxed. The shim remains needed for things to
  work; the kernel only guarantees nothing gets around it.
- **Domain integrity.**
  - A process's domain is assigned only by the helper at fork of a launcher
    it was asked to create, and is inherited only through kernel fork/exec
    lineage. A process can't move itself into another domain.
  - Audit tokens include pidversion, so pid reuse can't inherit a domain.
- **Fewer unsandboxed helpers.** Removing the need for `daemon_pid_source`
  helpers under the gate removes code that runs unsandboxed in the
  supervisor today. If Open Question 9 shows that descendant tracking does
  not survive reparenting, `daemon_pid_source` stays, and only `setsid`
  removal is reconsidered.
- **Expansion ceilings.** NEP-0002 roots become Seatbelt-reachable for the
  command sandbox when the gate is armed, so the ceiling, not the approved
  path, is the boundary under gate loss. The kill-on-gate-loss rule covers
  every domain, not only the session.

### Path handling

- ES supplies kernel-resolved paths in `es_file_t`. The CLI compares them
  by `Path` component, never string prefix. It normalizes firmlinks
  (`/System/Volumes/Data`) and the `/private` aliases (`/tmp`, `/var`),
  and handles APFS case-insensitivity. Linking `nono` also links this
  normalization, so a single implementation serves the helper tables and
  the supervisor.
- **Create and rename destinations** arrive as a (resolved dir, filename)
  pair for a node that doesn't exist yet. The spike must confirm the dir is
  a resolved vnode, so `..` and symlink swaps are closed. Filenames
  containing `/` or equal to `..` are denied.
- **Hard links:** `AUTH_LINK` is denied when the source lies outside what
  the destination's rules allow, to stop identity laundering into the
  envelope.
- **Atomicity:** the security value of `AUTH_OPEN` and `AUTH_UIPC_CONNECT`
  depends on the kernel using the same object it authorized. Unlike the
  seccomp-notify `sockaddr` case, the decision is made on a resolved object
  inside the kernel. This is still **to be verified**, and the Unix-socket
  boundary claim waits on that result.

### Library/CLI boundary

The library gains mechanism only: FFI, the spec, the wire protocol, and
event decoding. Mode semantics, the envelope, allow-lists, prompts, the
trust pinning list and diagnostics stay in `nono-cli`. The helper contains
no policy.

### Credential and secret secrecy

`AUTH_EXEC` carries the full argv and environment, which can include phantom
tokens or real secrets. The helper forwards only the fields a rule needs:
- **env** values are never forwarded, only names when a rule requires them;
- **argv** goes into `Zeroizing` buffers and is redacted before it reaches
  logs, diagnostics or audit.

The same handling applies to `NOTIFY_TCC_MODIFY` identities and to file
paths under credential deny groups.

## Alternatives Considered

- **Entitle the main `nono` binary.** Rejected: it would force the whole
  CLI into a provisioned bundle, break the homebrew-core formula and
  source builds, and widen the privileged surface to all of nono.
- **Replace Seatbelt with ES** (the direction explored in
  openai/codex#38028). Rejected: no IP, sysctl, POSIX IPC or PTY-ioctl
  hooks and no fd-level enforcement, so it would weaken the boundary.
- **Seatbelt extension tokens for expansion.** The token mechanism exists
  (`macos.rs:65-158`), but the sandboxed process must call
  `sandbox_extension_consume` itself. Getting arbitrary agent binaries to
  do that needs DYLD injection, which nono strips deliberately.
- **System-wide ES client or ES system extension.** Needs root or Full Disk
  Access and an approval flow. It is overkill and observes the whole host.
- **Gate only in `harden` mode, never `approve`.** Viable as a smaller
  first step and kept as a fallback if the spike finds that client death or
  atomicity can't be made safe. It forgoes macOS runtime approvals.
- **Revive `commands.{allow,deny}` as a kernel-enforced field.** Rejected:
  NEP-0001 removes those fields for 1.0, and deny-only `command_policies`
  entries already express the same intent with caller edges. Enforcing that
  existing model in the kernel avoids two command-policy schemas.
- **Redirect exec into the broker in the kernel**, so a direct exec of a
  mediated tool is transparently re-sandboxed. Not possible: ES can only
  allow, deny or strip flags. Shims stay the launch path, and a direct exec
  is denied.
- **Do nothing.** macOS stays static-only, and over-granting continues.

## Assumptions

- **Entitlement granted.** Apple grants
  `com.apple.developer.endpoint-security.client` to the nolabs Developer ID
  team for a Developer ID–distributed helper. The application is in
  progress. If it is refused, this NEP is blocked as written; the fallback
  is that only organisations with their own grant can use the gate, which
  isn't a viable default product.
- **Grant scope.** The grant covers Developer ID distribution outside the
  App Store. A grant limited to development builds, or to the App Store,
  would block the release-tarball, `.pkg` and cask channels. Confirm the
  provisioning profile type when it is issued.

## Open Questions

Blocking. Answer these in the Phase 0 spike. Item 1 is narrower now that the
grant is assumed.

1. **Packaging.** Exact provisioning-profile layout for the helper bundle.
   Does notarization accept it, and does the helper run correctly from each
   install location (tarball `libexec`, `.pkg`, cask)?
2. **Ordering.** Does ES receive AUTH events for operations Seatbelt has
   already denied? This decides whether `observe` metrics are complete.
3. **Client death.** When the client process exits, do subtree operations
   proceed, block or fail? Is a `FAIL_CLOSED` client different?
4. **Atomicity** of `AUTH_OPEN`, `AUTH_UIPC_CONNECT`, `AUTH_CREATE` and
   `AUTH_RENAME` under symlink and rebind races.
5. **Cache isolation:** whether `cache=true` from one client affects
   another client's tree.
6. **Delivery scope.** Which notifications emitted by system daemons
   (BTM, sudo, authorization, TCC) reach a descendants client when the
   instigator is in the subtree?
7. **Overhead** of `AUTH_OPEN` with inverted target-path muting on
   `cargo build` and `npm install` trees.
8. **Nesting.** nono inside nono, and nono supervising an agent that is
   itself an ES descendants client.

9. **Reparenting.** Does a descendants client keep covering a process that
   double-forks and is reparented to launchd? Apple's text ("forked or
   exec'd afterward, recursively") suggests lineage is fixed at fork, but
   this decides whether `setsid` and `daemon_pid_source` can go.
10. **Exec redirect cost.** Measure the latency of forwarding every
    `AUTH_EXEC` in a large build (`make -j`, `cargo build`), and how much
    the helper's static identity tables can answer without asking the
    supervisor.
11. **Script identity.** Is `es_event_exec_t.script` populated for every
    shebang path, including `env`-indirected ones (`#!/usr/bin/env
    python3`)?

Non-blocking:

12. Should `security.capability_elevation: true` imply `approve` on macOS
   once Phase 2 ships, or stay separate?
13. Default envelope for `approve`: empty (explicit only), the workdir
    parent, or a built-in group such as `approvable_macos_default`?
14. Baseline Mach/XPC allow-list: maintain one per macOS release, or build
    it from `observe`-mode telemetry per profile?
15. Should the `.pkg` become the recommended macOS install path, with the
    homebrew-core formula documented as Seatbelt-only?
16. Cask naming and whether homebrew-cask accepts a helper-only cask, or
    whether a nolabs tap is needed.
