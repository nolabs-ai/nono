---
nep: NNNN
title: Optional audit correlation fields and public Rust API evolution
authors:
  - Frankie-Xu
status: draft
created: 2026-10-07
superseded-by:
---

# NEP-NNNN: Optional audit correlation fields and public Rust API evolution

Draft proposal prepared with Codex assistance. No NEP number is reserved;
the `NNNN` placeholder is pending the repository numbering process. This is
not an accepted design. It makes the decision
needed for [issue #1693](https://github.com/nolabs-ai/nono/issues/1693) and
[PR #1704](https://github.com/nolabs-ai/nono/pull/1704) explicit.

## Summary

Propose optional UUID v7 correlation fields on command and network audit
events, with explicit approval of the resulting Rust struct-literal source
API change and the upgrade requirement for typed audit verifiers.

## Motivation

Audit consumers currently cannot reliably group admission and completion
or policy, authentication, credential-capture and response events. Grouping
by timestamps, PIDs, targets or hashes conflates repeated requests and makes
concurrent work difficult to reconstruct. Existing PR #1704 supplies the IDs,
but optional serde fields do not make a public Rust struct addition source
compatible. The design needs to resolve that API policy before publication.

### Goals

- A fresh command invocation ID shared by all events for one mediated request.
- A fresh network interaction ID shared by all events for one proxy request.
- Preserve canonical bytes and verification of historical events without IDs.
- Keep integrity algorithms, enforcement and credential handling unchanged.
- Make downstream Rust and verifier migration requirements explicit.

### Non-Goals

- Treat correlation IDs as credentials or authorization claims.
- Infer network-to-command attribution from PIDs, process trees or destinations.
- Change Landlock, Seatbelt, path grants, command policy or proxy permissions.
- Change leaf/chain/Merkle algorithms, domain separators or attestation predicates.

## Proposal

If accepted, extend `nono::audit::CommandPolicyAuditEvent` with optional
`invocation_id`, and `nono::undo::NetworkAuditEvent` with optional
`interaction_id` and `invocation_id`. Each field defaults to `None` when
absent and is omitted when serializing `None`. ID generation is opaque UUID
v7; no credential or target material is embedded.

The CLI creates a command ID after authenticating and receiving one shim
request and reuses it across admission, denial and completion. Linux and macOS
emit the same optional field; this adds no capability or platform enforcement
behavior. The proxy creates IDs at request boundaries and passes them through
endpoint policy, authentication, credential capture and response contexts.
A CONNECT tunnel and its individual intercepted HTTP requests have distinct
scopes; every HTTP/2 stream gets its own request ID.

Network `invocation_id` remains absent until a trusted command-to-request
channel exists. Session-scoped proxies have no reliable attribution channel
today. Identifiers never affect permission decisions.

### Rust API migration

Acceptance of this option would approve adding fields to five publicly
constructible Rust structs: `CommandPolicyAuditEvent`, `NetworkAuditEvent`,
`EventContext`, `CredentialCaptureAudit`, and `ReverseProxyCtx`. Downstream
struct literal constructors must add `None` for uncorrelated optional fields
or the known correlation values. In the current prototype,
`ReverseProxyCtx.interaction_id` is a required borrowed `&str`; its callers
must generate or provide a request ID whose backing string outlives the
request. Internal and `pub(crate)` helpers also propagate
these values, without changing externally public free-function signatures.
Release notes must describe the struct additions and migration. Maintainers
must decide whether that source API break is acceptable in the current alpha
release line.

### Wire data and integrity compatibility

Historical no-ID events serialize identically and continue to verify with an
updated reader. Present fields participate in the existing canonical event
bytes and thus the existing leaf/chain/Merkle commitments and applicable
session digest. No algorithm changes or weaker canonical equality checks are
proposed. Older typed verifiers discard the new fields when parsing, then
reject the canonical payload comparison; they must be upgraded before
verifying records containing IDs. Deserializing unknown fields successfully
is not sufficient to verify those records.

## Security Considerations

- Least privilege: IDs carry no authorization and permit no new operation.
- Fail secure: preserve every existing canonical equality and hash/chain/Merkle
  verification check. An unsupported schema is a verification failure; do not
  silently omit identifiers or relax checks to make older readers accept them.
- Paths: this design adds no filesystem comparison, grant or canonicalization
  path and changes no TOCTOU/symlink behavior.
- Boundary: the core library defines audit data and integrity mechanisms; the
  CLI and proxy retain all policy and request attribution decisions.
- Secrets: generate fresh opaque IDs, never derive IDs from tokens, headers,
  credentials, command arguments, environment values or request targets.
  Existing zeroizing credential storage and scrub policy remain intact.
- Attribution: keep parent command ID absent when unknown. Incorrect inferred
  linkage would misrepresent audit evidence even if the hash chain verifies.
- Verification must cover repeated/concurrent requests, denial and completion
  paths, secret redaction, disabled/bounded audit sinks, and legacy canonical
  vectors. Linux and macOS checks remain distinct.

## Alternatives Considered

**Preserve all existing public types through new correlated wrappers.** This
can avoid Rust source breakage. It needs additive recorder methods, a private
complete correlation serializer/verifier, a new opt-in correlated proxy sink
and retrieval API, and a CLI finalization path. The old `SharedAuditLog` alias
and typed event projections stay unchanged. This is a viable alternative if
maintainers reject public field evolution, but should receive its own concrete
interface review before implementation.

**Add a public AuditEventPayload variant.** Rejected as a source-compatibility
shortcut: the existing enum permits exhaustive downstream matching, so a new
variant is itself a source break.

**ID side tables keyed by PID/target/vector position.** Rejected: attribution
is unreliable and callers can mutate the publicly exposed vector-backed sink.

**Insert IDs into raw event_json only, or remove canonical equality.** Rejected:
the current verifier requires exact typed canonical equality; removing that
check would weaken validation rather than extend the supported schema.

## Open Questions

- Approve public Rust struct field evolution, or require additive wrappers?
- Which release/migration notice will communicate the typed-verifier upgrade?
- Is the proposed request-vs-CONNECT scope and deferred parent attribution
  sufficient for #1693, or should the trusted linkage channel be a later issue?

## References and validation state

Existing implementation: PR #1704, original head
`bbfb6dd40ad9b5ca17d9a3d614b412c26f67c0b5`. Local refresh is against upstream
`9edf3ea93956e3bef7b089e8b4a20a6102416eb7`. Relevant sources include
`crates/nono/src/audit.rs`, `crates/nono/src/undo/types.rs`,
`crates/nono-proxy/src/{audit,server,reverse}.rs`, TLS intercept handlers and
both CLI command-mediation platforms. Consulted AGENTS.md, CONTRIBUTING.md,
GOVERNANCE.md, SECURITY.md, neps/README.md and NEP-template.md.

The original Draft PR #1704 is already public. Its local refresh has not been
pushed and remains unpublished pending the design decision above. The existing
issue disclosure described the fields as requiring no migration; this proposal
corrects that assessment by identifying Rust struct-literal changes and typed
verifier upgrades. This proposal contains documentation only and does not
authorize or claim completion of the breaking Rust API implementation.
Implementation validation must include real socket and command lifecycle
regressions, redaction assertions, and both platform checks before a follow-up
implementation PR can be considered ready.
