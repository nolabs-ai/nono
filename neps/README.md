# nono Enhancement Proposals (NEPs)

A NEP is the design record for a change to nono that's too large or too
consequential for a normal PR description to carry — new capability
types, changes to sandbox enforcement semantics, policy model changes,
new sandboxing backends, or anything that touches the security model
described in [docs/cli/internals/security-model.mdx](../docs/cli/internals/security-model.mdx).

A NEP can encapsulate a large part of the project at once: a major
feature, a breaking change, or a large fix that reshapes an existing
subsystem, not just a single new capability. This is what distinguishes
NEPs from `docs/protocols/` (specifications for existing wire/data
protocols). A NEP is where the decision to make a large or
security-consequential change gets proposed and reviewed *before* any
implementation planning or specification work begins.

## When you need a NEP

- A major new feature (e.g. a new capability type, a new sandbox
  primitive, a new subsystem like the rollback/undo model)
- A breaking change to the profile format, CLI flags, or the library's
  public API
- Removing or deprecating an existing capability, profile field, or
  public API
- Changing policy resolution or the group resolver's behavior
- Anything that changes the boundary between the `nono` library and
  `nono-cli` — see [security-model.mdx](../docs/cli/internals/security-model.mdx)
  for what belongs where

A bug fix, refactor, or small feature addition does not need a NEP — just
open a PR.

## Process

1. Copy `NEP-template.md` to `NNNN-short-title.md` (see Numbering below).
2. Fill in `Summary`, `Motivation`, and `Proposal` at minimum. Leave
   unfinished sections as `TBD` rather than deleting them.
3. Open a PR adding the file with `status: draft`. This is the proposal —
   discussion happens as PR review.
4. A maintainer sets `status: proposed` once the proposal is complete
   enough to evaluate, and `status: accepted` or `status: rejected` once a
   decision is made. Accepted NEPs merge to `main`.
5. Implementation happens in follow-up PRs that reference the NEP number.
   When implementation lands, a maintainer sets `status: implemented`.

Any change to the "Security Considerations" section of an accepted NEP
requires the same review as the original acceptance — don't quietly amend
a security-relevant decision after the fact.

## Numbering

Numbers are assigned sequentially, zero-padded to 4 digits, in the order
PRs are opened. Check open PRs and existing files under `neps/` for the
next free number before claiming one — a collision is resolved by
whoever merges second renumbering their file.

## Status values

| Status        | Meaning                                                         |
|---------------|------------------------------------------------------------------|
| `draft`       | Under active authoring, not yet ready for a decision              |
| `proposed`    | Complete, awaiting maintainer decision                             |
| `accepted`    | Approved; implementation may proceed                                |
| `rejected`    | Declined; kept for history, not implemented                         |
| `implemented` | Accepted and shipped                                                |
| `superseded`  | Replaced by a later NEP (link it in the `superseded-by` field)       |

## Index

| NEP  | Title                     | Status   |
|------|---------------------------|----------|
| 0000 | NEP process               | accepted |
