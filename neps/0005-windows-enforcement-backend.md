---
nep: 0005
title: Windows enforcement backend
authors:
  - lukehinds
status: draft
created: 2026-09-29
superseded-by:
---

# NEP-0005: Windows enforcement backend

## Summary

Add a third OS enforcement backend to nono for Windows, alongside Linux
(Landlock) and macOS (Seatbelt). Windows has no facility equivalent to a
Landlock per-process filesystem ruleset or a Seatbelt deny-default
profile, so this NEP takes a position on the security model, not just the
code. It proposes a **network-first** backend built on the Windows
Filtering Platform (WFP) feeding the existing `nono-proxy`. It holds that a
**one-time elevated install** is an acceptable requirement on Windows —
unlike on Linux, where nono's no-admin rule is driven by locked-down
runtimes (GitHub Actions, Docker, AWS Fargate, hosts that deny
unprivileged user namespaces) that have no Windows equivalent nono
targets. Admin is a setup step only; every run stays unprivileged, and
enforcement fails secure if the install is absent.

## Motivation

nono today runs only on Linux and macOS. Its own reason for existing —
confining untrusted AI agents on the machine where they run — applies just
as much to developers and CI on Windows, who currently get nothing:
`Sandbox::is_supported()` is false and there is no enforcement at all.

I looked at `srt` version from anthropic which already ships a Windows backend
(`vendor/srt-win-src`), so there is a working, reviewed reference for 
what Windows realistically allows. But its enforcement model diverges
sharply from every assumption nono's Linux/macOS backends are built on,
and adopting it wholesale would silently change what
"nono sandboxes a process" *means* on Windows:

- **No per-path filesystem ruleset exists on Windows.** Landlock scopes a
  process to an explicit set of path rules; Seatbelt does the same via
  path literals with deny-default. Windows has no kernel facility that
  takes "allow read of these paths, write of those, deny the rest" and
  applies it to the current process and its descendants. The native
  options are coarser and structurally different (see Proposal).

- **`srt-win`'s answer is a dedicated low-privilege user + NTFS ACLs.**
  It provisions a persistent local account (`srt-sandbox`) at install time
  and launches the target *as that user* (`CreateProcessAsUserW`) under a
  restricted token, a locked-down job object, a non-interactive window
  station/desktop, a process-mitigation-policy stack, an explicit handle
  whitelist, and self-protection. Filesystem confinement is then whatever
  that account's SID is granted or denied by NTFS ACLs — not a
  per-invocation path allow-list. This is idiomatic Windows, but it is
  coarse and it is *stateful*: an account, ACLs, and a broker survive
  between runs.

- **The network fence needs admin and persistent WFP filters.** `srt-win`
  installs **one machine-wide, persistent** WFP filter set at
  `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`: permit loopback to the host proxy
  port range, and block all egress for tokens whose *user SID* is the
  sandbox account. Keying the block on the user SID is the design's best
  idea — it defeats the surrogate-spawn escape class (schtasks,
  `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` reparenting, BITS, RunAs
  "Interactive User" COM), because a process spawned under the account by
  *any* mechanism still carries the SID and still matches the BLOCK filter.
  But installing WFP filters and reading their status is admin-gated, and
  the filters are persistent machine state.

Every one of nono's current guarantees points the other way: enforcement
is applied **in-process**, **fully unprivileged**, with **no daemon and no
persistent system state**, at **per-invocation** granularity, with
**policy in `nono-cli` and mechanism in the `nono` library**. A Windows
backend that requires an elevated install, a standing user account, and
machine-wide filters is not a drop-in — it is a different operational and
trust model for one platform. 

### Goals

- Give Windows a real enforcement backend behind the existing
  `Sandbox` API and `nono-proxy`, so `nono wrap`-style confinement of an
  agent works on Windows at all.
- Make egress control the first, well-scoped increment: a WFP SID-fence
  that forces the sandboxed process through `nono-proxy`, preserving
  domain filtering and credential injection.
- Reuse `nono-proxy` unchanged (or nearly so) — the proxy is already
  cross-platform application-layer logic.
- Require elevation **only once, at install** — never per run — and fail
  secure if that install is absent, rather than degrading to an
  unconfined run.
- Keep mechanism in the `nono` library and policy/install/brokering in
  `nono-cli`, matching the split the other two backends observe.
- Fail secure: if the Windows fence cannot be established (not elevated,
  WFP filters absent, account missing), enforcement must **deny/refuse to
  run the workload unsandboxed**, never silently run it with no fence.

### Non-Goals

- **Feature parity with Landlock/Seatbelt path rulesets on day one.**
  Fine-grained per-path FS scoping may not be expressible on Windows at
  all with the same semantics; this NEP does not promise it.
- **Building a container or a VM.** No Windows Sandbox/WDAG image
  handling, no Hyper-V isolation. This is host-level confinement, matching
  nono's "your machine, minus what is denied" model.
- **A cross-platform capability translation guarantee.** A profile written
  for Linux/macOS will not necessarily map 1:1 to Windows enforcement;
  divergences must be documented and must fail secure, not fake success.
- **Vendoring `srt-win` unmodified.** It carries its own broker/installer
  semantics, an sqlite state DB, and MSVC-only build assumptions
- **WSL2 as the answer.** Running the Linux backend under WSL2 already
  works where WSL2 exists; this NEP is about native Windows processes.
- **Reverse/inbound port forwarding across the fence** in the first phase.

## Proposal

### Backend shape and the library/CLI boundary

Add `crates/nono/src/sandbox/windows.rs` behind `#[cfg(target_os =
"windows")]`, mirroring the existing `mod.rs` dispatch that already gates
`linux` and `macos` modules and their re-exports. The `nono` library owns
**mechanism only**:

- building the restricted token and (if adopted) resolving the sandbox
account SID
- spawning the target under the job object / desktop / mitigation stack,
- the WFP primitives (add/enumerate/delete filters, the loopback-permit +
  SID-block filter pair) as testable functions.

`nono-cli` owns **policy and privileged orchestration**: whether to
install WFP filters, whether to provision/repair the sandbox account, the
default protected paths and profile semantics, prompts, elevation UX, and
diagnostics. This matches how policy already lives in `nono-cli` and
mechanism in `nono`. Concretely, anything that writes persistent machine
state (a WFP filter set, a local account, ACL grants) is a `nono-cli`
install/broker action, not a library call a random embedder can trip.

From here we can delivery the NEP over several PRs / phases.

### Phase 1 — network fence

`nono-proxy` runs on the host and binds a loopback port (as it does today). 
Windows enforcement then consists of:

- a **WFP permit** filter for loopback to the proxy port(s) at
  `ALE_AUTH_CONNECT_V4/V6`, and
- a **WFP block** filter matching the sandbox account's user SID,
- so the child can reach only the proxy and nothing else on the network.

The child is launched so that it carries that user SID (the SID-keying is
what makes the fence robust against surrogate-spawn). Egress is
proxy-brokered exactly as on Linux/macOS, so `nono-proxy`'s domain
allow-list, cloud-metadata deny-list (`net_filter.rs`), and credential
injection all apply unchanged.

Building this first for the simple reason it is well-scoped, reuses the
proxy, and delivers the highest-value guarantee (no unmediated egress).

### Phase 2 — process/filesystem confinement

Two native mechanisms, neither equivalent to Landlock/Seatbelt:

1. **Restricted token + dedicated user + NTFS ACLs** (the `srt-win`
   approach): coarse FS scoping via a standing account's ACLs, plus job
   object, non-interactive winsta/desktop, process mitigation policies,
   handle whitelist, self-protection. Robust and battle-tested on Windows,
   but stateful (persistent account + ACLs) and not per-path/per-invocation.

2. **AppContainer + capability SIDs**: per-process isolation without a
   standing named account, closer to a per-invocation model and to nono's
   spirit. Notably, `srt-win` does **not** use this. FS access is governed
   by capability SIDs and object ACLs rather than an arbitrary path
   allow-list, so it is still coarser than Landlock, but it avoids
   provisioning a persistent user.

This NEP calls for **AppContainer + capability SIDs as the primary FS/
process mechanism**, because it minimizes persistent state and stays
closest to nono's per-invocation model. The dedicated-user + restricted-
token + ACL model is a **documented fallback only** — used where
AppContainer cannot express a specific confinement need (handle
isolation, job limits) with acceptable robustness, and only for that need,
not as the default posture. The residual unknown is not *which model we
prefer* but *whether AppContainer proves sufficient in practice*; see Open
Questions.

### The privilege model: elevated install

The nono security model is strict upon not allowing privilege escalation
beyond userspace, so nono runs in the locked-down runtimes it targets like
GitHub Actions, Docker, AWS Fargate, and hosts where unprivileged user
namespaces are denied outright (the driving constraint behind NEP-0004).
That is a Linux-runtime concern, and it does **not** transfer to Windows.
nono does not target a comparable class of Windows runtimes where
administrator access is categorically unavailable: GitHub-hosted Windows
CI runners already run elevated, and a Windows developer or agent host can
elevate once for setup. Requiring a one-time elevated install on Windows
is therefore a reasonable ask — provided it is admin *once, at install*,
never per run.

Three shapes were considered; this NEP adopts the first.

- **Option A — one-time elevated install, unprivileged per-run** (the
  `srt-win` model): a `nono install` admin step provisions the WFP filter
  set (and, under Phase 2's fallback, the account and ACLs). Every
  subsequent `nono` invocation is fully unprivileged. Cost: nono on
  Windows is no longer zero-persistent-state — it leaves machine-wide
  filters (and possibly an account) behind. This is a documented,
  intentional platform difference from Linux/macOS, not a regression.

- **Option B — never require admin**: refuse the elevated install and
  accept whatever AppContainer + a per-process WFP subscription can do
  without persistent filters — likely no sound egress fence at all.
  Rejected: it sacrifices the fence to honor a constraint (no admin) that
  Windows does not actually impose on us.

- **Option C — both, explicit**: an unprivileged best-effort default plus
  an opt-in elevated install. Rejected as the primary shape because it
  doubles the enforcement surface for a "default" that, on Windows, buys
  little — the install is a one-time step in every runtime we target.

**This NEP adopts Option A.** It delivers the full WFP SID-fence, keeps
per-run invocation unprivileged, and matches the environments nono runs in
on Windows. The one hard rule carried over from Linux is *no
per-invocation elevation*: admin is a setup step, not a runtime
dependency. Fail-secure is unchanged and non-negotiable — if the install
has not been performed or the fence is not present at run time, nono
refuses to run the workload rather than running it unconfined.

### Why per-run stays unprivileged

"Admin once, never per run" is not just a policy we assert — it is
achievable because nothing in the run path needs a privileged operation,
and the reference (`srt-win`) is built exactly this way:

- **WFP filters are persistent and SID-keyed.** They are installed once
  (`FWPM_FILTER_FLAG_PERSISTENT`, machine-wide) and match by the sandbox
  account's *user* SID. Any process later launched as that user is fenced
  the instant it exists — no run-time filter add/delete, and adding or
  deleting WFP filters is the only admin-gated network step.
- **The account credential is stored at install, so run-time logon needs
  no privilege.** The elevated install writes the sandbox account's
  password (encrypted, guarded by a DENY-gated DACL — see Security
  Considerations). At run time an unprivileged broker decrypts it and
  launches the child via the **Secondary Logon service**
  (`CreateProcessWithLogonW`), which does *not* require
  `SeAssignPrimaryTokenPrivilege`.
- **The proxy binds inside a pre-permitted loopback port range.** Because
  the persistent permit covers a small range, the proxy's actual port for
  a given run is already allowed — no per-run WFP edit to open it.

The one design choice that would *break* the one-time property is pinning
the exact single proxy port per run: that requires a per-run WFP filter
add/delete, which is admin-gated and would drag elevation back into every
invocation. So there is a real trade-off — a **range** keeps admin
one-time but permits ~10 loopback ports; an **exact-port** pin is tighter
but needs either per-run admin or a standing privileged helper to mediate
the edit. This NEP takes the range (one-time admin wins); narrowing it is
tracked in Open Questions.

### Backward compatibility

No change to Linux or macOS enforcement, capability semantics, profile
format, or the library public API on those platforms. On Windows,
`Sandbox::is_supported()` transitions from false to true (guarded by
whether the required fence is actually available at runtime). A profile
authored for another platform must not silently under-enforce on Windows;
capabilities that cannot be expressed must be reported and must fail
secure, per the rule below.

## Security Considerations

- **Least privilege.** The Windows FS model is inherently coarser than a
  Landlock/Seatbelt path ruleset (SID/ACL- or capability-SID-based, not
  arbitrary per-path). The design must scope as narrowly as the platform
  allows and must *document the residual breadth* rather than imply
  path-level parity. The WFP fence must grant egress only to the proxy
  loopback port(s), never a broad loopback permit that also exposes
  arbitrary local listeners; the `srt-win` port-*range* permit is a
  concession to avoid per-run admin and must be justified or narrowed for
  nono. SID-keyed blocking is required so surrogate-spawn cannot escape the
  fence.

- **Fail-secure behavior.** If the process is not elevated when a
  privileged step is required, if the WFP filter set is absent or
  unreadable, if the sandbox account/AppContainer cannot be established, or
  if any part of the token/job/desktop stack fails to apply — the workload
  must **not run unconfined**. Refuse and error. Partial application
  (e.g. FS confined but network fence missing) must be treated as failure,
  not a degraded success. WFP status is admin-gated; a non-elevated
  readiness check must be an affirmative behavioral probe (as `srt-win`'s
  connect-probe `verify` is), never an assumption that "no error means
  fenced."

- **Path handling.** Windows path semantics are a distinct TOCTOU/escape
  surface: NTFS junctions and symbolic links, 8.3 short names, alternate
  data streams, UNC and `\\?\` device paths, drive-relative and
  case-insensitive comparison, and reparse points. Any path logic must use
  Windows-aware canonicalization and component comparison (never string
  prefix), resolve reparse points at the enforcement boundary, and
  consider that ACL-based confinement inherits the filesystem's own
  link-following behavior. This is new code with no reuse from the
  Unix-path module and needs its own review and tests.

- **Library/CLI boundary.** Mechanism (token, job, WFP primitives) lives in
  the `nono` library; all persistent-state and privileged actions
  (installing filters, provisioning the account, granting ACLs, elevation
  UX, default protected paths) live in `nono-cli`. The library must not
  silently create machine-wide state as a side effect of an ordinary
  capability application.

- **Credential & secret secrecy.** The proxy's credential injection is
  unchanged, but the Windows spawn path must keep secrets out of the child
  environment and out of any diagnostics. `srt-win` uses DPAPI for stored
  material; if nono adopts any at-rest secret storage on Windows it must
  use zeroizing types in memory, redact before logging, and never place
  tokens in the child's environment block or command line. Persistent WFP
  filter tags/`providerData` and any state DB must not carry credentials.

- **New persistent attack surface.** Unlike the other backends, this
  backend leaves standing machine state (WFP filters, possibly an account
  with ACL grants). That state is itself a target: uninstall must be complete
  and idempotent, filters must be identifiable and removable, and a stale
  install must not leave a half-fence that reports as protected. This is a
  security property of the *installer*, which the NEP process treats with
  the same review weight as enforcement.

## Alternatives Considered

- **WSL2 (reuse the Linux backend).** Works today where WSL2 is present
  and is the right answer for Linux workloads on Windows, but does nothing
  for native Windows processes and requires the WSL2 dependency. Not a
  substitute for a native backend.

- **Windows Sandbox / Defender Application Guard (container isolation).**
  Heavyweight, Hyper-V-dependent, image-oriented, and not available on all
  SKUs. Contradicts the host-level, "your machine minus denials" model and
  the Non-Goal of not building a container.

- **AppContainer-only, no WFP.** Simpler and unprivileged, but
  AppContainer's network isolation is capability-based and does not by
  itself force traffic through the proxy the way the WFP SID-fence does;
  likely leaves egress gaps. Worth combining with WFP, not a replacement
  for it.

- **Vendor `srt-win` wholesale.** Fastest path to a working backend, but
  imports a large surface (~23 files), a broker/installer model, an sqlite
  state DB, MSVC-only build assumptions, and a security model that
  diverges from nono's without the boundary reshaping this NEP calls for.
  Better used as a reference and for specific primitives (the WFP SID-fence
  in particular) than adopted as a dependency.

- **No Windows support.** The status quo. Leaves a whole platform of agent
  users unprotected while the sibling `srt` project demonstrates it is
  achievable. Rejected as the long-term answer, though acceptable as the
  state until this NEP is decided.

## Open Questions

- **Does AppContainer hold up?** This NEP commits to AppContainer as the
  primary FS/process mechanism; the open part is empirical — whether it
  can express the handle isolation and job limits the confinement needs
  without falling back to the dedicated-user model for so much that the
  fallback becomes the de facto default. If it does, that fallback is
  re-scoped or dropped.
- **Proxy port exposure:** can nono avoid `srt-win`'s loopback *range*
  permit (which exposes several ports) and pin exactly the proxy port(s),
  or does that reintroduce a per-run admin cost?
- **Uninstall/repair semantics:** how are persistent WFP filters and any
  account/ACL state made fully removable and idempotent, and how does a
  stale/partial install report as *not* protected?
- **Build/CI:** the reference backend is MSVC-only and cannot be
  fully `cargo check`ed from a non-Windows host; what is the minimum
  Windows CI gate, and does the workspace need a Windows runner before this
  can be reviewed as implementable?
- **Capability mapping fidelity:** which existing profile capabilities have
  no faithful Windows expression, and exactly how does each fail secure and
  get surfaced to the user rather than silently under-enforcing?
- **`nono-proxy` deltas:** does anything in the proxy assume Unix-only
  behavior (socket paths, loopback binding, signal handling) that needs a
  Windows path?
