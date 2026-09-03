---
nep: 0001
title: Network approval backends with session-scoped decisions
authors:
  - Leonardo Zanivan
status: accepted
created: 2026-09-03
superseded-by:
---

# NEP-0001: Network approval backends with session-scoped decisions

## Summary

Bring runtime host approval for outbound network connections into the existing
**approval backend** system (`terminal`, `dialog`, `webhook`, `chain`) already
used for command and endpoint policies, and make each approval decision
**session-scoped** so repeated connections to the same host do not re-prompt.

## Motivation

`network.allow_domain` is a static allowlist baked into the proxy at startup.
Any host not on the list gets an immediate 403 — there is no way to interactively
approve or deny a connection request at runtime. This blocks production use for
agents that discover new outbound endpoints during a session: the only recourse
is to stop, edit the profile, and restart.

PR #698 attempted to solve this with a bespoke dialog/persistence mechanism
(`--network-approval ask` with `Allow once / Always allow / Deny once / Always deny`).
That introduced a second, parallel approval UX inconsistent with the rest of
nono: no backend composability (`chain`), no `webhook` support for headless
cases, a separate config surface, and duplicate dialog code. This NEP supersedes
that approach by reusing the approval-backend infrastructure and adding
session persistence as two new decision variants rather than a parallel path.

### Goals

- Hosts not in `allow_domain` trigger a configured approval backend instead of
  an immediate 403, using the same `approval_backends` / `approval_defaults`
  config shape already used elsewhere.
- Approval decisions can be **session-scoped**: an operator can approve or deny a
  host once, or for the remainder of the session; "for the session" decisions
  are cached in the proxy and skip re-prompting.
- No new backend types and no new dialog code — reuse `dialog` (NEP-adjacent
  work already merged in #1775), `terminal`, `webhook`, `chain`.

### Non-Goals

- Cross-session / on-disk persistence of decisions. The cache lives only for the
  lifetime of the proxy (i.e. the session).
- Per-host routing to different backends. One network backend (possibly a
  `chain`) serves all unapproved hosts.
- The non-CONNECT (plain HTTP forward) path — same pattern applies and is a
  follow-up.

## Proposal

Five layers, from config surface down to the CONNECT handler, plus the
session-decision cache. Detailed in `PLAN_NETWORK.md`; summarized here.

### Library API surface (`nono` crate)

Two new variants on `ApprovalDecision` in `nono::supervisor::types`:

```rust
/// User approved this host for the remainder of the session.
GrantedForSession,
/// User denied this host for the remainder of the session.
DeniedForSession,
```

This is the only public library API change. The `ApprovalRequest::Network`
variant already exists and is already rendered by the `dialog` backend. All
existing exhaustive matches on `ApprovalDecision` are updated; `GrantedForSession`
is treated as `Granted` and `DeniedForSession` as `Denied` everywhere except the
proxy's session-cache logic.

### CLI / proxy mechanism

- **Config** (`nono-cli`): add `approval_backends` and `approval_defaults` to the
  top-level `network:` profile section, validated by the existing
  `validate_approval_backend` / `validate_approval_defaults`, with a new
  `validate_network_approval_backends` entry point. Misconfiguration is a **fatal**
  config-load error (fail-secure).
- **Backend build** (`nono-cli`): reuse `build_approval_registry_from` to produce
  an `Option<Arc<dyn nono::ApprovalBackend>>`, threaded into proxy startup.
- **Proxy state** (`nono-proxy`): `network_approval_backend` field plus a
  session cache `session_decisions: Arc<DashMap<(String, u16), bool>>`
  (`true` = allow, `false` = deny).
- **CONNECT handler** (`nono-proxy`): on `FilterResult::DenyNotAllowed`, consult
  the cache first; on miss, call the backend via `spawn_blocking` (the call is
  sync and must not block a Tokio worker). `GrantedForSession` / `DeniedForSession`
  populate the cache; `Granted` / `Denied` / `Timeout` do not.
- **Dialog + terminal backends** (`nono-cli`): render four choices for the
  `Network` variant — Allow once → `Granted`, Always allow → `GrantedForSession`,
  Deny once → `Denied`, Always deny → `DeniedForSession`.

### Platform notes

This feature lives entirely in the userspace proxy (`nono-proxy`) and CLI, not in
the OS sandbox layer, so **Landlock vs Seatbelt divergence does not apply** to the
enforcement mechanism. The only platform-specific surface is the `dialog` backend's
desktop-session detection (macOS vs Linux), which already exists and already
fails secure (denies) in headless environments.

### Backward compatibility

Fully backward compatible. `approval_backends` / `approval_defaults` on `network:`
are optional and default to empty. With no backend configured, an unapproved host
gets a 403 exactly as today. The new `ApprovalDecision` variants are additive.

## Security Considerations

- **Least privilege**: A sandboxed process gains no new capability on its own —
  every new outbound host still requires an explicit operator decision (or a
  cached prior decision from the same session). `allow_all: true` bypasses
  approval, unchanged.
- **Fail-secure**: A backend `Timeout` is treated as `Denied` (no tunnel).
  Misconfigured backends are a fatal config-load error, never a silent downgrade.
  A missing/empty backend registry means unapproved hosts 403 as before. Headless
  desktop with a `dialog` backend denies.
- **SSRF guard is not bypassable**: Metadata IPs and explicit `reject_domain`
  entries produce `FilterResult::DenyHost` (not `DenyNotAllowed`) and are
  **hard-denied with no approval path** — the backend is never consulted and no
  cache entry is created for them.
- **DNS-rebinding / TOCTOU**: The tunnel must connect to the exact
  `check.resolved_addrs` returned by the filter that produced the decision —
  never re-resolve after approval. The session cache is keyed by `(host, port)`
  but this does not weaken the guard: a cached "allow" still routes through the
  filter, which re-checks against metadata/reject rules before yielding
  `resolved_addrs` for that connection, so a host that later resolves to a
  metadata IP is still `DenyHost`.
- **Library/CLI boundary**: Mechanism stays in the library (`ApprovalDecision`
  variants, `ApprovalBackend` trait) and the proxy (cache, CONNECT wiring); all
  *policy* (which backends exist, defaults, what `allow_domain` contains) stays
  in `nono-cli` config. No policy is baked into the library.
- **Credentials/secrets**: This design handles hostnames, ports, and resolved
  IPs only — no credentials. Nothing new to zeroize or redact. The
  `ApprovalRequest::Network` payload contains no secret material.

## Alternatives Considered

- **PR #698's parallel mechanism** — rejected: duplicates dialog code, adds a
  separate config surface, no `chain`/`webhook` composability.
- **A caching wrapper backend** instead of `ApprovalDecision` variants — rejected:
  the backend still needs a way to signal "once" vs "for session", which forces a
  new decision variant anyway; the wrapper adds indirection without removing the
  library change.
- **On-disk persistence across sessions** — deferred (non-goal): larger blast
  radius (stale grants, tampering) and warrants its own NEP.

## Open Questions

- Should the terminal backend's four-way prompt have a safe default on EOF/^D?
  (Proposed: deny once — consistent with fail-secure.)
- Should `DeniedForSession` entries be visible/inspectable via a diagnostic, or
  stay purely internal to the proxy for the session?
