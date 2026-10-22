---
nep: 0004
title: Opt-in Linux namespace isolation
authors:
  - lukehinds
status: proposed
created: 2026-09-29
superseded-by:
---

# NEP-0004: Opt-in Linux namespace isolation

## Summary

Add an opt-in, permanently default-off Linux isolation layer that runs the
sandboxed workload inside a set of unprivileged namespaces (user + network,
later a minimal mount-mask), layered on top of the existing Landlock and
seccomp enforcement. This structurally removes the local-IPC escape classes
(abstract AF_UNIX sockets, netlink, direct IP, and — with the mount mask —
pathname AF_UNIX endpoints such as the D-Bus session bus and the systemd
user manager) instead of mediating them syscall-by-syscall.

## Motivation

We have had a few escape classes reported against nono on Linux where 
there has been a misguided expectation that nono runs as an outer isolation primitive
equal to a VM or container. Concretely:

- **Pathname AF_UNIX `connect()`** is not governed by Landlock filesystem
  rules. From inside a sandbox, `/run/user/<uid>/bus` reaches the D-Bus
  session bus or the systemd user manager socket (`systemd-run` starts processes
  *outside* the sandbox), `docker.sock`, X11/Wayland, and `ssh-agent`.
- **Abstract AF_UNIX sockets** are scoped only on Landlock V6+ kernels via
  `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`. On older kernels the default
  `IpcMode::SharedMemoryOnly` continues *without* scoping: the class is
  fail-open below V6.
- **Non-TCP network** (UDP, ICMP, raw) is invisible to Landlock V4 network
  rules and handled only at socket-family granularity by the static seccomp
  baseline; the proxy cannot carry non-HTTP protocols at all (#756).

nono's existing countermeasure for the pathname class,
`linux.af_unix_mediation = "pathname"` (seccomp user-notify supervision),
is off by default, excluded from `nono wrap` and WSL2, and has proven
operationally fragile in the field (#1128, #1399, #1420, #1715, #1970).
More fundamentally, intercept-and-continue mediation of pointer-argument
syscalls is not a sound security boundary: the kernel documentation for
seccomp user notification is explicit that the notified memory remains
writable by the target, so the validated `sockaddr` bytes are subject to
rewrite between check and use. Mediation inspects a hostile interface
point-by-point; a namespace removes the interface wholesale.

Upstream Landlock is closing the same gaps natively — ABI 9 adds
`LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (kernel-enforced per-path pathname-socket
grants) and ABI 10 adds UDP bind/connect rules — and adopting those is the
right long-term default path. But those ABIs shipped in current-generation
kernels only; enterprise fleets nono supports today (e.g. RHEL 9 on 5.14,
see #1980) will lack them for years. Namespaces are the bridge that works
on every kernel nono already runs on. The two tracks are complementary,
not alternatives.

Follow up work should take place to bring nono's Landlock support up to
the current ABI so that capable kernels get kernel-native enforcement of
the same policy classes the namespace layer provides structurally on
older ones; see "Parallel track" in the Proposal for how the two compose,
with the enforcement-semantics-changing part (ABI 9) split into a
companion NEP.

Namespace isolation must never become the default: unprivileged user
namespaces are denied on Ubuntu 23.10+/24.04 (AppArmor
`kernel.apparmor_restrict_unprivileged_userns`), inside default
Docker/Kubernetes seccomp profiles, and on AWS Fargate and similar
locked-down runtimes. nono's core promise — fully unprivileged, runs on a
developer laptop, in GitHub Actions, in a stock container — is exactly the
set of environments where namespace availability is inconsistent. A default
that silently varied enforcement by host would violate the fail-secure
rule. Opt-in keeps nono completely userland-purposed by default.

### Goals

- Close the abstract-AF_UNIX, netlink, and direct-IP escape classes on
  **every supported kernel**, not just Landlock V6+ / V4+.
- Close the pathname AF_UNIX class (D-Bus, systemd, `docker.sock`)
  structurally, without per-syscall supervision.
- Preserve `nono-proxy` semantics (credential injection, domain filtering,
  session-token auth) inside a network namespace.
- Fail closed, loudly and diagnosably, when isolation is requested but the
  host cannot provide it.
- Keep the existing Landlock + seccomp stack unchanged underneath
  (defense in depth); keep macOS Seatbelt behavior untouched.
- Per-session `/tmp` (#258) as a natural consequence of the mount phase.

### Non-Goals

- **Any change to defaults.** Every namespace feature is opt-in via
  explicit profile/flag configuration, permanently.
- Building a container runtime: no rootfs construction, no `pivot_root`
  into a synthetic tree, no image handling. The mount phase is a *mask*
  over the real filesystem, preserving nono's "your machine, minus what is
  denied" model.
- PID namespaces in the initial phases (PID-1 init/reaping semantics,
  `/proc` remount coupling) — explicitly deferred, revisit after Phase 2.
- Inbound reverse-forwarding for `bind_ports` across the netns boundary —
  deferred. Phase 1 rejects `bind_ports` combined with `isolate.network`
  at startup (see "Interaction with `NetworkMode`").
- veth/pasta/slirp-style real IP connectivity inside the namespace: it
  would bypass proxy domain filtering. All egress remains proxy-brokered.
- Replacing the parallel work of adopting Landlock ABI 7–11 as kernel and
  crate support arrives.
- macOS parity. Namespaces are a Linux kernel facility; Seatbelt's
  deny-default profile already gives macOS independent coverage of the
  socket classes at issue.

## Proposal

### Phasing

**Phase 1 — network isolation (`user` + `net`, with `ipc` and `uts` as
free riders).**

The workload runs in a new user namespace (single-uid/gid identity
mapping; the enabler for everything else while unprivileged) and a new
network namespace containing only a loopback interface, brought up using
the CAP_NET_ADMIN the process holds *within its own user namespace*.

Effects, on every kernel version:

- Abstract AF_UNIX socket names are per-netns: the host abstract namespace
  is unreachable. This converts a fail-open class on pre-V6 kernels into a
  hard boundary everywhere.
- Netlink sockets reach only the empty namespace, not host services.
- Direct IP of any protocol (TCP, UDP, ICMP, raw) cannot leave the
  namespace: there is no route to the host network at all.

Interaction with `NetworkMode`:

| NetworkMode | Behavior under `isolate.network` |
|---|---|
| `Blocked` | Empty netns, no bridge. This is the cheapest deliverable and is strictly stronger than today's seccomp-based block. |
| `ProxyOnly` | Proxy bridge (below). |
| `AllowAll` | **Configuration error.** Allow-all cannot be satisfied inside an empty namespace; failing at startup is required rather than silently blocking everything the profile said to allow. |

The same reasoning applies to every grant of direct (non-proxied) reachability.
Combined with `isolate.network`, each of the following is a **configuration
error** at startup. The error names the offending field and the profile layer
that set it:

- `open_port` / `open_port_range` (`--open-port`): localhost IPC to host ports.
  The host loopback does not exist inside the netns.
- `connect_port` (`--allow-connect-port`): direct outbound TCP. The netns has
  no route out.
- `listen_port` / `listen_port_range` (`--listen-port`, `bind_ports`): inbound
  listeners. These cannot be reached from the host until reverse forwarding
  exists (deferred).
- `no_proxy`: hosts that bypass the proxy. A direct connection cannot leave
  the netns.

No built-in profile sets these fields today, so the rule does not make
built-in profiles unusable with isolation.

**Proxy bridge (Phase 1, ProxyOnly only).** A socket stays in the
network namespace it was created in, whichever process later holds its
file descriptor. The bridge uses that property, so nothing runs inside
the namespace except the workload and no new filesystem endpoint exists:

1. In the bootstrap child, after `unshare` and bringing up `lo`, the
   child creates a TCP socket, binds it to `127.0.0.1:<port>` inside the
   new netns (the same port number the proxy uses on the host, so the
   child environment is unchanged), and calls `listen`. These are raw,
   async-signal-safe syscalls and fit the existing no-alloc bootstrap.
2. The child sends the listening fd to the supervisor over the existing
   bootstrap socketpair (`SCM_RIGHTS`), then closes its own copy before
   Landlock is applied and before `exec`. The workload never holds the
   listener.
3. The supervisor, outside the namespace, `accept()`s on the passed fd.
   Each accepted connection belongs to the child's netns and is handed to
   `nono-proxy`'s existing connection handler in-process, exactly as a
   connection from the host TCP listener would be.
4. The child environment (`HTTP_PROXY`/`HTTPS_PROXY`, `NONO_PROXY_TOKEN`,
   reverse-proxy base URLs) is unchanged. Bridged connections get exactly
   the proxy authentication and filtering that host-listener connections
   get today. That includes the lenient `CONNECT` mode sandboxed sessions
   use, where the sandbox rather than the token is the trust boundary.

Compared with an in-namespace relay forwarding to a proxy Unix socket,
this design has no relay process, no relay sandbox, no Unix-socket
listener in `nono-proxy`, no supervisor-owned socket directory, and no
socket grant in the child's capability set. The bridge's only state is a
listening fd owned by the supervisor. If the supervisor dies, the session
ends anyway.

A SOCKS5 route is the intended follow-up that gives non-HTTP TCP (SSH
etc., #756) a policy-enforced path. It uses a second passed listener and
ships as a separate PR under this NEP, after the initial Phase 1 PR (see
Resolved Questions).

**Namespace-private loopback (opt-in, Phase 1 follow-up; accepted).**

With `isolate.network` alone, the workload cannot use its own loopback.
nono's existing network enforcement still applies inside the namespace. Under
`Blocked`, the static seccomp filter denies `socket(AF_INET*)` outright.
Under `ProxyOnly`, Landlock allows TCP connect only to the proxy port and
allows no bind. The seccomp-notify fallback likewise allows connects only
to `localhost:<proxy port>`. So an isolated agent cannot run a local dev
server, a test suite that listens on `127.0.0.1`, a language server over
TCP, or anything else that talks to itself over loopback. This is the most
likely reason a user would turn isolation off.

That restriction exists to keep the workload from reaching *host* loopback
services. Inside an isolated network namespace there are none. The
namespace's loopback is private to the sandbox. Nothing on the host can
connect to it, and it leads nowhere except back into the sandbox and to
the proxy bridge.

The proposal is an explicit opt-in:

```jsonc
{ "linux": { "isolate": { "network": true, "loopback": true } } }
```

CLI: `--isolate net,loopback`.

Semantics:

- `loopback` requires `network`. Requesting it without `network` is a
  configuration error, because it would grant host-loopback reachability.
- It permits TCP `bind`, `listen`, and `connect` on any port, IPv4 and IPv6,
  inside the namespace. It does not permit UDP, raw sockets, or netlink.
  Those stay exactly as they are today.
- Egress is unchanged. The only path out of the namespace is still the
  proxy bridge, with the same authentication and filtering.
- The existing direct-reachability fields (`open_port*`, `connect_port`,
  `listen_port*`, `no_proxy`) stay configuration errors under
  `isolate.network`, with or without `loopback`. Outside isolation they
  mean *host* loopback, and users write them to reach host services
  (`--open-port 5432` for the local Postgres). Silently reinterpreting them
  as namespace-local would turn a deliberate grant into something that
  quietly does not do what was asked. A separate field makes the change
  of scope visible.
- `loopback` merges by OR like the other `isolate` fields.

Enforcement:

- Landlock's network rules filter by port only, not by address. That is
  normally why nono cannot express "localhost only". Inside an isolated
  network namespace the restriction is moot: the only interface is `lo`,
  there are no routes, and the workload holds no capabilities to add any.
  Any TCP destination the workload can reach is therefore namespace
  loopback. For the TCP class, the namespace is the enforcement boundary.
- Concretely, the relaxation and the namespace travel as one value. The
  library's `NamespaceSpec` carries a `loopback_tcp` marker, which
  `validate()` and the raw child entry refuse without a network namespace.
  The CLI derives its TCP enforcement from the probed spec, never from the
  request alone. With the marker set, the child's sandbox is prepared with
  `SeccompOpts::external_tcp_with_baseline()`: Landlock does not handle
  `BindTcp`/`ConnectTcp`, and the static seccomp filter is the TCP-only
  baseline in every confined network mode, so under `Blocked` it switches
  from block-all to TCP-only. The supervisor's seccomp-notify connect
  check, which allows only `localhost:<proxy port>`, is not installed.
  Under `--sandbox-policy landlock` (no seccomp) only the Landlock TCP
  rules are lifted; `external` already delegates TCP. The library stays
  mechanism-only: it applies the enforcement it is given and never
  decides that isolation makes loopback safe.
- The proxy bridge listener is created and bound in the bootstrap child
  before Landlock, seccomp, and `exec`. The workload therefore can never
  bind the proxy port first (`EADDRINUSE`), and the bridge cannot be
  displaced. Startup validation and the pre-launch re-check
  (`prepare_namespaces`) both reject `loopback` unless the final network
  mode is `Blocked` or `ProxyOnly` *and* `network` isolation is in effect.
  If the namespace cannot be created, the launch fails. nono never applies
  the relaxed TCP enforcement without the namespace that justifies it.

Platform note: on macOS `linux.isolate` stays inert, so a profile that
relies on `loopback` for a local server works on Linux but still needs
`listen_port` on macOS. The docs must say so. Guaranteeing isolation
across platforms (`require_isolation`) remains out of scope (see Resolved
Questions).

`ipc` (SysV shm/sem/msg, POSIX MQs no longer shared with the host) and
`uts` (hostname immutable from the host's perspective) namespaces are
included in Phase 1 because they are one flag each at the same `unshare`
call site and break almost nothing.

**Phase 2 — minimal mount mask (`user` + `mnt`).**

A new mount namespace in which nono overlays a small, fixed set of masks
on the otherwise-untouched host tree:

- tmpfs over `$XDG_RUNTIME_DIR` (masks the D-Bus session bus, systemd
  user-manager private socket, and related runtime sockets),
- tmpfs or empty-file bind masks over `/run/dbus`,
  `/var/run/docker.sock`, and a short curated list of equivalent
  system-level IPC endpoints,
- a per-session tmpfs `/tmp` (resolving #258).

Paths the capability set explicitly grants (including `unix_socket`
grants) are re-bound into place over the mask, so an intentional grant of
e.g. a specific agent socket keeps working. The default mask list is fixed
policy shipped in `nono-cli`. Profiles may *add* masks; nothing below the
top-level trusted configuration may remove one (mirroring the existing
protected-paths precedent).

Mount propagation inside the namespace is set to private for the masked
mounts only; the namespace is created with propagation semantics that do
not prevent nested user/mount namespaces inside the sandbox (the #1980
use case) — a workload-created namespace is subject to the same Landlock
rules it already inherited, so nesting does not weaken enforcement.

**Parallel track (not namespace work): Landlock ABI currency.**

The `landlock` crate nono already ships (0.4.7) exposes ABI V7
(Linux 6.15: audit flags), V8 (Linux 7.0: `TSYNC` all-threads restrict)
and V9 (Linux 7.1: `AccessFs::ResolveUnix`); only ABI 10 (UDP) and 11
still need upstream crate work. The lag is in nono's own code
(`DetectedAbi` and the feature listing stop at V6), so adoption can start
immediately and proceeds in risk order:

1. **Detection and reporting** (routine, no NEP): extend `DetectedAbi`
   through V9, surface kernel-vs-enforced ABI per class in `nono why` and
   diagnostics (including the crate's errata signal). Also yields field
   data on how fast V9 kernels arrive — the number that decides when the
   fallbacks below can be demoted.
2. **ABI 8 `TSYNC`** (routine): apply-path hygiene; most valuable for
   `nono wrap`'s multi-threaded self-sandboxing; best-effort below V8.
3. **ABI 7 audit flags** (routine, opt-in diagnostics): kernel-logged
   Landlock denials answer "why was this denied" for cases the supervisor
   never sees; composes with this NEP's probe-and-diagnose posture.
4. **ABI 9 `ResolveUnix` wired to existing `unix_socket` grants** —
   changes enforcement semantics and therefore gets its own companion
   NEP. The known trap: handling `ResolveUnix` without granting anything
   flips profiles that never listed a unix socket into deny-all-unix-
   connects on V9 kernels (fail-closed but breaking); it needs curated
   system-default grants, the same class of problem as #1827.
5. **ABI 10 UDP / ABI 11** after upstream `landlock-rs` support (or
   prototyped on nono's raw-syscall prepared path).

**Composition principle: one policy vocabulary, resolver picks the
strongest available backend per class.** `CapabilitySet` already declares
intent (`unix_sockets`, `IpcMode`, `SignalMode`, `NetworkMode`, port
lists) and `LandlockScopePolicy` already reports requested-vs-enforced;
generalized, each class resolves at apply time to kernel-native Landlock
when the ABI allows it, namespace unreachability when the operator opted
in, seccomp as legacy fallback — reported per class. The tracks stay
orthogonal by construction: Landlock currency is an automatic
enforcement-quality upgrade on capable kernels with no new user
decisions; namespaces remain an explicit opt-in isolation decision.
Concretely, for the pathname AF_UNIX class the resolver order is
V9 `ResolveUnix` grant → Phase 2 mount mask → seccomp mediation →
warn-and-continue (today's status quo). On V9 kernels the two layers
reinforce each other. `ResolveUnix` makes the profile's explicit
`unix_socket` grants the only pathname endpoints a workload may connect
to. The mount mask then becomes mainly a way to hide host endpoints from
reconnaissance, while still being the pathname-socket defense on older
kernels. The proxy bridge is a passed TCP listener, not a pathname
socket, so it needs no `ResolveUnix` grant.

The shared infrastructure cost is CI: hosted runners will not have 7.x
kernels for some time, so V7–V9 enforcement paths need a VM-tier kernel
matrix (e.g. qemu) — the same lane the namespace phases need for
userns-restricted hosts. Build it once; both tracks consume it.

### Externally provisioned namespaces

On hosts where unprivileged user namespaces are unavailable and cannot be
enabled (hardened kernels, locked-down containers), the supported answer
is privileged provisioning *outside* nono: an operator, systemd unit, CI
harness, or container runtime creates the namespace as root — `unshare(1)`,
`ip netns exec`, `systemd-run PrivateNetwork=yes`, or the container itself
— and runs an unchanged, unprivileged nono inside it. nono needs no
privileged code for this and it composes today; it also delivers the one
technical advantage a privileged path would have had (a netns without a
user namespace avoids the userns kernel-attack-surface trade).

This follows the existing `Sandbox::apply_external()` precedent for
declaring TCP enforcement externally handled: the deployment, not nono,
owns that boundary. In scope for this NEP is documenting the pattern and,
as a diagnostics nicety, detecting a non-initial netns at startup so
`nono why` can report "network isolation: provided externally". Out of
scope is nono ever executing privileged setup itself — no root code path,
no setuid or file-caps helper binary (see Alternatives Considered).

### Configuration surface

Profile (all fields default absent/off; `linux.` scoping follows the
existing `linux.af_unix_mediation` precedent):

```jsonc
{
  "linux": {
    "isolate": {
      "network": true,        // Phase 1: user+net (+ipc+uts)
      "loopback": true,       // Phase 1 follow-up: TCP on the namespace's own lo; requires network
      "ipc": true,            // may also be set without network
      "uts": true,
      "mounts": true,         // Phase 2: user+mnt, default mask list
      "extra_masks": ["/opt/corp/agent.sock"]  // additive only
    }
  }
}
```

CLI: `--isolate net,loopback,ipc,uts,mounts` (comma list) as sugar for the same.

**Merge semantics.** The boolean `isolate` fields merge like `network.block`:
logical OR across every profile layer, packs and the CLI. Any layer can turn
a namespace on and no layer can turn it off, so `extends` can never strip
isolation that a base requested. `extra_masks` merges by deduplicated
append. There is no `--no-isolate`. An operator who does not want a pack's
isolation does not use that pack.
`nono why` and the startup diagnostics report the effective isolation set
and, when a namespace was requested but unavailable, which layer refused
it. Session/audit metadata records the effective isolation set.

`nono wrap` does not support `linux.isolate` (no supervisor exists to own
the proxy bridge or perform the synchronized bootstrap), consistent with
its existing exclusion from `af_unix_mediation`. `nono wrap` with
`isolate` configured is a startup error, not a silent skip.

### Library/CLI split

Following the policy-free-primitive boundary:

- **`nono` (library): mechanism.** A `NamespaceSpec` (which namespaces;
  mask list as caller-supplied paths; optional loopback bridge port) alongside
  `CapabilitySet`, an availability probe (`Sandbox::probe_namespaces()`)
  that attempts the real `unshare` in a scratch child rather than reading
  sysctls, and the apply path integrated into the existing prepared
  no-alloc child bootstrap. The library applies exactly what it is given.
- **`nono-cli` (policy).** The default mask list, the
  `NetworkMode`-interaction rules (including rejecting `AllowAll` and
  direct-reachability grants alongside `network`), profile schema, flag
  parsing, prompts and diagnostics, and the supervisor-side accept loop
  that feeds bridged connections to `nono-proxy`. The library's part of
  the bridge is mechanism only: on request, create a loopback listener
  inside the new netns and return its fd through the bootstrap channel.

### Execution mechanics

The existing supervised launch (fork / raw `CLONE_FILES` bootstrap in
`exec_strategy.rs`) is the insertion point. In the child, before Landlock
application and before `exec`:

1. `unshare(CLONE_NEWUSER | ...)` with the configured set; parent writes
   the single-line `uid_map`/`gid_map` (after `setgroups deny`) as part of
   the existing synchronized bootstrap.
2. Child (holding CAP_NET_ADMIN in its new userns) brings up `lo`; Phase 2
   performs the mask mounts.
3. In ProxyOnly mode, the child creates the loopback listener, passes it
   to the supervisor over the bootstrap socketpair, and closes its copy.
4. Landlock + seccomp apply exactly as today; `exec`.

Supervisor channels are unaffected by design: the anonymous socketpair and
the seccomp-notify fd are fd-based and namespace-agnostic, and the
supervisor addresses the child by host PID (it is outside the namespaces),
so `/proc/<pid>/...` access is unchanged.

### Platform behavior

Linux-only. On macOS the `linux.isolate` block is inert configuration,
identical to `linux.af_unix_mediation` today; Seatbelt's deny-default
profile independently covers the socket classes this NEP targets, and that
equivalence (and its limits) will be stated in the docs. A profile author
who needs isolation *guaranteed* cross-platform cannot express that today
and this NEP does not add it (see Open Questions).

### Backward compatibility

None affected. Every behavior in this NEP requires explicit opt-in; no
existing profile, flag, capability semantics, or library API changes
meaning. The library additions are new API only.

## Security Considerations

- **Least privilege.** Isolation only ever *removes* reachability; it
  grants the sandboxed process nothing new. The two additions of authority
  are scoped. CAP_NET_ADMIN and the other capabilities exist only within
  the child's own user namespace and confer nothing over host resources.
  The proxy bridge is a listener reachable only from inside the child's
  netns and is token-authenticated. That is narrower than the host
  localhost TCP port it replaces, which any host process could probe.
- **Fail-secure.** Requested-but-unavailable isolation is a startup
  error, never a silent downgrade — matching the
  `SignalMode::AllowSameSandbox` fail-closed precedent. The probe attempts
  the actual operation (AppArmor, seccomp, and sysctl denials all surface
  as `EPERM` from different layers; the diagnostic names the layer and the
  fix, e.g. the per-binary AppArmor profile nono will ship/document for
  Ubuntu 24.04+). `AllowAll` and every direct-reachability grant are
  rejected at configuration time when combined with `isolate.network`.
  A failure to create or pass the bridge listener is fatal to the launch.
  The workload never holds the listener, so it cannot accept or hijack
  bridged connections. Partial namespace application in the bootstrap is
  fatal to the launch, not recoverable.
- **Namespace-private loopback.** `isolate.loopback` is the one place
  where isolation *relaxes* another layer: Landlock TCP rules and the
  seccomp network filter are lifted for TCP. The relaxation is sound only
  while the workload sits in a network namespace with nothing but `lo`,
  no routes, and no capabilities. So the namespace and the relaxation must
  be applied together or not at all. The library takes them as one
  instruction from the CLI. The CLI rejects `loopback` without `network`
  at validation and again at launch, and a failure to create the
  namespace is fatal. The residual exposure is sandbox-to-sandbox only. A
  workload can reach its own loopback listeners and the proxy bridge,
  which it can already reach. File descriptors from the host network
  namespace are not inherited (the bootstrap scrubs fds), so no
  host-namespace socket can be smuggled in. Tests must cover: no
  non-loopback destination is reachable with `loopback` on, the workload
  cannot bind the proxy port, and `loopback` without `network` fails at
  startup.
- **AppArmor profile trade.** The shipped Ubuntu profile grants `userns`
  to the nono binary only. Any local user can then use nono to obtain an
  unprivileged user namespace, the same exposure Ubuntu accepts for its
  bubblewrap profile. The profile is an operator install step, never a
  default, and the docs state this trade.
- **Kernel attack surface (the honest trade).** Unprivileged user
  namespaces expose kernel interfaces behind which a long lineage of
  privilege-escalation bugs has lived — that is precisely why Ubuntu
  restricts them. Opting in trades a stronger *userspace* boundary for
  more exposed *kernel*. For nono's threat model (semi-trusted agent
  workloads, not hostile multi-tenant code) this is usually the right
  trade, but it must be documented as a stated trade-off in
  security-model.mdx, and it is a second, independent reason the feature
  can never be default-on.
- **Path handling.** The Phase 2 mask list and grant re-binding use the
  existing component-wise path comparison and canonicalization at the
  enforcement boundary. Masks are applied before any untrusted code runs,
  in a mount namespace the child cannot modify (no CAP_SYS_ADMIN over the
  parent userns that owns the mounts once the child has dropped into its
  final state) — there is no check-then-use window of the kind that
  affects syscall mediation. Symlinked `$XDG_RUNTIME_DIR` and bind-mount
  interactions with granted paths need dedicated tests on both plain and
  symlink-heavy layouts.
- **Library/CLI boundary.** Mechanism (`NamespaceSpec`, probe, apply) in
  `nono`; every policy decision (default masks, mode interactions, UX,
  bridge wiring) in `nono-cli`/`nono-proxy`. The library never hardcodes a
  mask path.
- **Credential secrecy.** Unchanged: credentials remain in the
  supervisor-side proxy as `Zeroizing<String>` and are injected upstream
  only. No relay component runs inside the namespace.
  Bridged connections terminate directly in the supervisor-side proxy
  and are authenticated exactly as host-listener connections are: forward
  and reverse requests require the session token (constant-time
  comparison), and sandboxed `CONNECT` stays lenient, as today. The bridge
  is reachable only from inside the child's netns. That is a tighter
  boundary than the host loopback listener, which any host process can
  reach.
- **Profile trust.** `extra_masks` is additive-only; no profile layer may
  remove a default mask. A pack cannot use `isolate` to widen anything:
  every field only narrows, and OR-merge semantics mean no layer can
  remove isolation a base requested.
- **What this does not fix.** Proxy-layer (L7) policy bugs become *more*
  load-bearing as the proxy becomes the sole egress chokepoint; filesystem
  capability policy, command policy, approval flows, and macOS enforcement
  are entirely unaffected by this NEP and keep their existing threat
  profiles.

## Alternatives Considered

- **Expand seccomp-notify AF_UNIX mediation to a full socket firewall.**
  Rejected. Intercept-and-continue over pointer arguments cannot be made
  TOCTOU-sound (kernel documentation is explicit that user-notify is not a
  security boundary for such syscalls), the field record of the existing
  pathname mediation shows the operational cost (#1128, #1399, #1420,
  #1715, #1970), and per-syscall supervision cannot cover abstract-socket
  or non-TCP classes at all on older kernels. Existing mediation is
  retained as a compatibility layer but is no longer the strategic answer.
- **eBPF egress filtering (#1848).** Rejected previously and reaffirmed:
  requires elevated privileges (CAP_BPF/CAP_NET_ADMIN at host scope),
  which contradicts nono's fully-unprivileged deployment promise. The
  same reasoning is why namespaces must be opt-in rather than default.
- **Wait for Landlock ABI 9/10.** Right destination, wrong bridge: those
  kernels are years from being a deployable baseline for the fleets nono
  supports, and ABI 9 still does not address non-TCP network or host
  `/proc`/recon surface. Adopted as the parallel track instead (see
  "Landlock ABI currency" in the Proposal), with the enforcement resolver
  choosing kernel-native Landlock over namespace/seccomp fallbacks per
  class as kernels catch up.
- **Full container-style sandbox (bubblewrap-equivalent: pivot_root,
  PID 1 init, synthetic rootfs).** Rejected as scope creep. nono's
  differentiator is the fine-grained capability model; namespaces here are
  a membrane around that model, not a container runtime growing inside
  it. bubblewrap/sandbox-runtime remain the reference for brokering all
  egress from an empty netns through a host-side proxy (proven in
  production by Anthropic's sandbox-runtime for Claude Code), not the
  product direction.
- **In-namespace relay process to a proxy Unix socket** (the bridge
  shape in the original draft of this NEP). Superseded by passing the
  netns loopback listener fd to the supervisor. The relay design worked,
  but it added an extra process inside the sandbox, a relay sandbox to
  maintain, a filesystem socket endpoint and its grant, a Unix listener
  in `nono-proxy`, and a relay-death failure mode. It also had to answer
  how the relay is launched (a re-exec of `nono` or a separate binary),
  which needs exec rights on that binary before Landlock applies. The
  fd-passing design needs none of this.
- **pasta/slirp4netns user-mode networking inside the netns.** Rejected:
  restores raw IP reachability and therefore bypasses proxy domain
  filtering; nono's network policy is domain/route-level, so all egress
  must remain proxy-brokered.
- **Privileged namespace setup (root-run path or setuid/file-caps
  helper).** Rejected, even though it would cover hosts where
  unprivileged userns is disabled and would avoid the userns
  kernel-attack-surface trade. First, it inverts nono's trust story: the
  security model's "what if the supervisor is compromised" analysis rests
  on nono holding no privilege the invoking user lacks, so supervisor or
  helper compromise is lateral movement, not escalation. A privileged
  setup path reclassifies every bug in it as a root LPE. Second, the
  field record of privileged sandbox helpers is the strongest available
  evidence against building one:
  - **Firejail** (setuid-root by design): CVE-2022-31214 — a crafted
    join target accepted by the setuid program yields an environment in
    the *initial* user namespace with `NO_NEW_PRIVS` unset and an
    attacker-controlled mount namespace, escalating to root via `su`;
    CVE-2017-5180 — euid-0 file handling plus a symlink under `--private`
    yields a root shell. The sandbox's own privilege was the escalation
    vector in both.
  - **Bubblewrap** was designed to minimize exactly this exposure, and
    still: CVE-2016-8659 (privilege escalation via ptrace) applied only
    to setuid installs, as does the recent CVE-2026-41163 (same class,
    again setuid-only). Distros shipped setuid bwrap only where kernels
    blocked unprivileged userns (Debian ≤ 10, RHEL ≤ 7), the maintainers
    have recommended against setuid installation for years, and upstream
    0.12.0 removes the build option and unconditionally refuses to run
    setuid. The project that pioneered the privileged-helper compromise
    is deleting it.
  Where privileged setup is genuinely needed, it stays outside nono:
  see "Externally provisioned namespaces" in the Proposal.

## Resolved Questions

Questions raised in the draft, with the resolutions this NEP proposes.

- **Pack semantics.** Any profile layer, packs included, may request
  isolation, and the request is mandatory. A host that cannot provide it
  fails at startup, and the error names the layer that set the field.
  Isolation only narrows, so letting a pack request it widens nothing.
  Silently dropping a pack's request would be a fail-open downgrade.
  Fields merge by OR, like `network.block` (see "Merge semantics"). A
  cross-platform `require_isolation` is out of scope. On macOS `isolate`
  stays inert, and `nono why` says so instead of claiming an equivalent
  boundary.
- **`bind_ports` in Phase 1.** Startup error, not a warning. A warning
  would start a session whose listeners can never be reached, which
  fails in confusing ways later. The error covers every
  direct-reachability grant (`open_port*`, `connect_port`,
  `listen_port*`, `no_proxy`), because each one fails inside the netns
  for the same reason. Revisit when reverse forwarding is designed.
  Listeners the workload only needs to reach itself are covered
  separately by the opt-in `isolate.loopback` (see "Namespace-private
  loopback"), which leaves these fields rejected.
  Reverse forwarding still needs something able to create sockets inside
  the netns after `exec`, which the fd-passing bridge does not provide.
- **Relay implementation shape.** No relay. The bootstrap child creates
  the loopback listener inside the netns and passes it to the supervisor
  (see "Proxy bridge"). SOCKS5 is a second passed listener, shipped as a
  follow-up PR under this NEP and not in the initial Phase 1 PR. It opens
  a new egress class (non-HTTP TCP) whose policy surface deserves its own
  review, and Phase 1 without it matches today's ProxyOnly semantics
  exactly.
- **Default mask list (Phase 2).** Starting list: `$XDG_RUNTIME_DIR`
  (D-Bus session bus, systemd user manager, Wayland, PipeWire, rootless
  Podman, keyring and agent sockets), `/run/dbus`, `/run/docker.sock`
  and `/var/run/docker.sock`, `/run/containerd/containerd.sock`,
  `/run/podman/podman.sock`, `/run/snapd.socket`, and `/run/systemd/private`.
  The per-session `/tmp` also hides `/tmp/.X11-unix` and `/tmp/ssh-*`
  agent sockets. GUI and `ssh-agent` access therefore breaks under
  `mounts` unless granted. That is acceptable for an opt-in mask, and
  explicit grants re-bind through the mask. The list lives in `nono-cli`
  policy. Any change to it is reviewed as a security change. The
  Phase 2 PR finalizes the list against real agent workloads, and
  later changes are reviewed per release, not on a fixed schedule.
- **WSL2.** Expected to work but unverified. The Phase 1 PR adds a WSL2
  feature-matrix row marked "Unverified" until tested on the Microsoft
  6.6 kernel. The probe decides at runtime either way, so an unsupported
  host fails closed. It is worth verifying because the netns provides
  kernel-enforced ProxyOnly without seccomp user notification, which is
  unavailable on WSL2 (EBUSY). The docs will not claim that until it is
  verified.
- **Ubuntu AppArmor profile distribution.** Both. The `.deb` (built with
  `cargo-deb`) ships an AppArmor profile that grants `userns` to the
  installed nono binary path. The docs give the manual install step for
  other install methods. When the probe fails with `EPERM` and
  `kernel.apparmor_restrict_unprivileged_userns` is `1`, the diagnostic
  names AppArmor as the refusing layer and prints the profile path or
  install command. Sysctls are read only to explain a failed probe,
  never to decide availability. See Security Considerations for the
  trade this profile makes.
- **`isolate.loopback` port scope.** All TCP ports. Dev servers and test
  runners pick ports dynamically, and an allow-list
  (`"loopback": [3000, 8080]`) would be brittle while buying little,
  because every reachable endpoint is inside the sandbox anyway. The field
  is a boolean today; a list form can be added later without a breaking
  change.

## Open Questions

- **Companion NEP scope for ABI 9 `ResolveUnix`** (deferred, not
  blocking). The migration semantics need their own decision record:
  curated system-default unix-socket grants, the `af_unix_mediation`
  demotion timeline, and how the enforcement resolver's per-class choice
  is reported and audited. This NEP fixes only the composition contract
  with it.
- **UDP on the namespace loopback** (deferred, not blocking). Whether
  `isolate.loopback` should also allow UDP (local DNS stubs, some test
  harnesses) once Landlock ABI 10 UDP support lands. It stays TCP-only
  until then.
