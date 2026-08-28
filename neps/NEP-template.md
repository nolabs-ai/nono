---
nep: NNNN
title: Short, descriptive title
authors:
  - your-name
status: draft
created: YYYY-MM-DD
superseded-by:
---

# NEP-NNNN: Title

## Summary

One or two sentences: what is this proposing.

## Motivation

Why is this needed. What's broken or missing today, and for whom.

### Goals

- ...

### Non-Goals

- ...

## Proposal

The actual design. For sandboxing/capability changes, be explicit about:

- What new API surface (if any) this adds to the `nono` library vs
  `nono-cli`, per the library/CLI split in
  [security-model.mdx](../docs/cli/internals/security-model.mdx)
- How it's expressed on Linux (Landlock) and macOS (Seatbelt) — call out
  any behavior that can't be made equivalent on both platforms
- Backward compatibility: does this change existing capability/policy
  semantics for anyone already using them

## Security Considerations

Required section — do not leave blank. Address explicitly, in terms of
the model in [security-model.mdx](../docs/cli/internals/security-model.mdx):

- Least privilege: does this let a sandboxed process do anything it
  couldn't before, and is that scoped as narrowly as possible
- Fail-secure behavior: what happens on error, partial application, or
  an unsupported platform — must default to deny, never degrade silently
- Path handling: any new path comparison/canonicalization logic, and its
  exposure to TOCTOU or symlink-escape issues
- Library/CLI boundary: does this keep policy decisions in `nono-cli` and
  mechanism in the `nono` library

## Alternatives Considered

Other approaches and why they were not chosen.

## Open Questions

- ...
