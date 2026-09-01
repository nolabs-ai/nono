---
nep: 0000
title: NEP process
authors:
  - johndoe
status: accepted
created: 2026-08-28
superseded-by:
---

# NEP-0000: NEP process

## Summary

Establish `neps/` at the repo root as the place for design proposals on
changes too large or security-consequential for a plain PR description.

## Motivation

nono's core changes (capability semantics, policy resolution, sandbox
backends) need a written design and explicit security review before
implementation, not just PR-description-level discussion. There's
currently no consistent place for that record to live, or convention for
how it's decided and archived.

### Goals

- A lightweight, discoverable place for design proposals
- Force explicit security review on capability/policy/backend changes
- A durable, numbered record of what was decided and why

### Non-Goals

- Replacing GOVERNANCE.md or MAINTAINERS.md decision-making authority
- Heavyweight process tooling (owner assignment, machine-readable
  metadata files, staged promotion gates) — out of scope for a project
  this size

## Proposal

- New top-level `neps/` directory (sibling to `GOVERNANCE.md`,
  `CONTRIBUTING.md`, not under `docs/`, which is the generated docs site).
- `neps/README.md` describes the process, numbering, and status values.
- `neps/NEP-template.md` is the starting point for new proposals.
- Each proposal is `neps/NNNN-short-title.md`, frontmatter-tracked status.
- Proposals are authored and reviewed as normal PRs against `main`; the PR
  discussion is the record of deliberation.

## Security Considerations

- This NEP itself has no runtime effect on the sandbox; it's process only.
- Its main security value is procedural: any future NEP touching
  capability semantics, policy resolution, or the library/CLI boundary
  must fill in the template's mandatory "Security Considerations" section,
  addressed against `docs/cli/internals/security-model.mdx`, before it can
  move to `accepted`.

## Alternatives Considered

- Under `docs/`: rejected — `docs/` is the generated user-facing docs site
  (`docs.json`, Mintlify-style), not where governance material lives.
- ADRs (`docs/adr/`) instead of NEPs: rejected — ADRs typically record a
  single decision after the fact, whereas NEPs here also serve as the
  pre-decision proposal/discussion vehicle, not just the record of it.

## Open Questions

- Whether NEP numbers should be reserved via a tracking issue instead of
  claimed by PR order, once proposal volume grows enough to make
  collisions common.
