---
nep: 0004
title: Opt-in Linux namespace isolation
authors:
  - lukehinds
status: draft
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
  deferred (Phase 1 documents the limitation).
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

**Proxy bridge (Phase 1, ProxyOnly only).** Pathname AF_UNIX sockets are
filesystem-routed and therefore cross netns boundaries — the one property
that makes them an escape class becomes the transport:

1. `nono-proxy` (in the supervisor process, outside the sandbox) gains a
   Unix-socket listener alongside its TCP listener, in a supervisor-owned
   `0700` directory covered by the child's capability set as the sole
   socket grant.
2. A small relay process is started inside the namespace before the
   workload `exec`s. It listens on `127.0.0.1:<port>` inside the netns and
   relays byte-for-byte to the proxy's Unix socket. It is itself fully
   sandboxed (same Landlock/seccomp state as the workload), holds no
   credentials, and terminates with the session.
3. The child environment (`HTTP_PROXY`/`HTTPS_PROXY`, `NONO_PROXY_TOKEN`,
   reverse-proxy base URLs) is unchanged in shape; only the port's
   backing transport differs. Proxy session-token authentication continues
   to apply to every request arriving over the bridge.

A SOCKS5 route over the same bridge is the intended follow-up that gives
non-HTTP TCP (SSH etc., #756) a policy-enforced path; it is part of this
NEP's direction but may land after the initial Phase 1 PR.

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
reinforce each other: the proxy-bridge socket gets an explicit
`ResolveUnix` grant (the bridge becomes both the only *reachable* and the
only *granted* endpoint), and the mount mask relaxes into a recon-hiding
role while remaining the pathname-socket defense on older kernels.

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
      "ipc": true,            // may also be set without network
      "uts": true,
      "mounts": true,         // Phase 2: user+mnt, default mask list
      "extra_masks": ["/opt/corp/agent.sock"]  // additive only
    }
  }
}
```

CLI: `--isolate net,ipc,uts,mounts` (comma list) as sugar for the same.
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
  mask list as caller-supplied paths; bridge socket path) alongside
  `CapabilitySet`, an availability probe (`Sandbox::probe_namespaces()`)
  that attempts the real `unshare` in a scratch child rather than reading
  sysctls, and the apply path integrated into the existing prepared
  no-alloc child bootstrap. The library applies exactly what it is given.
- **`nono-cli` (policy).** The default mask list, the
  `NetworkMode`-interaction rules (including rejecting
  `AllowAll`+`network`), profile schema, flag parsing, prompts and
  diagnostics, the relay process, and the proxy's Unix-socket listener
  (`nono-proxy`).

### Execution mechanics

The existing supervised launch (fork / raw `CLONE_FILES` bootstrap in
`exec_strategy.rs`) is the insertion point. In the child, before Landlock
application and before `exec`:

1. `unshare(CLONE_NEWUSER | ...)` with the configured set; parent writes
   the single-line `uid_map`/`gid_map` (after `setgroups deny`) as part of
   the existing synchronized bootstrap.
2. Child (holding CAP_NET_ADMIN in its new userns) brings up `lo`; Phase 2
   performs the mask mounts.
3. In ProxyOnly mode, the relay process is forked inside the namespace.
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
  are scoped: CAP_NET_ADMIN etc. exist only within the child's own user
  namespace (they confer nothing over host resources), and the proxy's
  Unix socket is a single, supervisor-owned, token-authenticated endpoint
  in a `0700` directory — narrower than the localhost TCP port it
  replaces, which any host process could probe.
- **Fail-secure.** Requested-but-unavailable isolation is a startup
  error, never a silent downgrade — matching the
  `SignalMode::AllowSameSandbox` fail-closed precedent. The probe attempts
  the actual operation (AppArmor, seccomp, and sysctl denials all surface
  as `EPERM` from different layers; the diagnostic names the layer and the
  fix, e.g. the per-binary AppArmor profile nono will ship/document for
  Ubuntu 24.04+). `AllowAll`+`network` is rejected at configuration time.
  Relay-process death closes the bridge: the child loses proxy access and
  nothing widens. Partial namespace application in the bootstrap is fatal
  to the launch, not recoverable.
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
  only. The in-namespace relay is untrusted, sandboxed, and carries only
  ciphertext-equivalent traffic it could already see as the workload's
  peer; the session token continues to authenticate every bridged request
  with constant-time comparison. The bridge socket path appears in
  diagnostics but is not secret.
- **Profile trust.** `extra_masks` is additive-only; no profile layer may
  remove a default mask. A pack cannot use `isolate` to widen anything:
  every field only narrows.
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
  it. bubblewrap/sandbox-runtime remain the reference for the proxy-bridge
  pattern (proven in production by Anthropic's sandbox-runtime for Claude
  Code), not the product direction.
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

## Open Questions

- **Pack semantics:** may a pack/profile *require* isolation (fail on
  hosts without userns), or is isolation strictly a top-level operator
  decision that packs can request but not mandate? Related: should a
  future `require_isolation` express "fail if the platform cannot provide
  an equivalent boundary" and what, if anything, that means on macOS.
- **`bind_ports` UX in Phase 1:** inbound listeners (MCP servers) bound
  inside the netns are unreachable from the host until reverse forwarding
  exists. Startup error when `bind_ports` is combined with
  `isolate.network`, or permitted with a prominent warning?
- **Default mask list contents and review cadence** for Phase 2
  (`$XDG_RUNTIME_DIR`, `/run/dbus`, `docker.sock`, what else — Wayland
  and X11 sockets break GUI tooling if masked by default; curate the
  list against real agent workloads).
- **Relay implementation shape:** re-exec of the `nono` binary in a
  hidden subcommand vs. a dedicated minimal binary; and whether the
  SOCKS5 route ships in the Phase 1 PR or immediately after.
- **WSL2:** userns and netns are expected to work (real kernel), but the
  WSL2 feature matrix needs explicit verification and a row for
  isolation.
- **Ubuntu AppArmor profile distribution:** ship in packages, document
  as an install step, or both; and how the probe's diagnostic points at
  it.
- **Companion NEP scope for ABI 9 `ResolveUnix`:** the migration
  semantics (curated system-default unix-socket grants, the
  `af_unix_mediation` demotion timeline, and how the enforcement
  resolver's per-class choice is reported and audited) need their own
  decision record — this NEP only fixes the composition contract with
  it.
