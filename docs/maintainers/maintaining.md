# Maintaining nono

This guide is the day-to-day runbook for nono maintainers. It complements
[GOVERNANCE.md](../../GOVERNANCE.md), which defines authority and decisions,
and [CONTRIBUTING.md](../../CONTRIBUTING.md), which defines the contributor
workflow. It does not replace either document.

The job is to keep the project welcoming, responsive, and secure. Be clear
about what is known, avoid making promises the project cannot keep, and leave
decisions where contributors can understand them.

## Daily and weekly practice

Check new issues, pull requests, discussions, and mentions regularly. The
project promises a first review response within five business days; an
acknowledgement, a focused question, or a handoff to the right reviewer counts
when a complete review is not yet possible.

When responding:

- Start with the contributor's concrete question or observation. Thank people
  for useful reports and effort, without implying that a proposal will be
  accepted.
- Be specific about the next step: a reproduction, missing version details, an
  issue, a NEP, a smaller PR, or a reviewer with relevant context.
- Keep technical decisions in the issue or PR. Summarize a decision reached in
  Discord or another private channel before acting on it, unless it concerns a
  security report or a Code of Conduct matter.
- Follow the [Code of Conduct](../../CODE_OF_CONDUCT.md). Move personal,
  sensitive, or conduct-related matters to the contact process it specifies.

Do not ask a contributor to disclose credentials, private configuration,
customer data, or an exploit publicly. Redirect suspected vulnerabilities to
the private reporting path in [SECURITY.md](../../SECURITY.md) and follow the
[security response runbook](security-response.md).

## Discussions and support

Use discussions for questions, design exploration, roadmap feedback, and help
that does not yet have a reproducible defect or a bounded implementation. Give
an answer when possible; otherwise say what information would make the question
actionable. Link to existing documentation, issues, or decisions rather than
creating competing guidance.

If a discussion identifies a bug, a defined enhancement, or follow-up work,
open or ask the participant to open an issue and link the discussion. For a
major feature, breaking change, capability change, or change to the library/CLI
security boundary, direct the proposer to the [NEP process](../../neps/README.md)
before implementation planning proceeds.

For a new contributor, offer one small, concrete next action. Point them to
the setup and contribution instructions, describe relevant code ownership or
platform constraints, and invite them to ask when blocked. Do not treat a
first-time contribution as lower quality by default; review the change against
the same standards while explaining project conventions kindly.

## Issue triage

Triage is about making an issue understandable and routable, not deciding that
it will be implemented.

1. Check for duplicates, related PRs, and existing decisions. Link them and
   close true duplicates with a short explanation; keep the clearest report as
   the canonical issue.
2. Confirm that the report has enough information to act: nono version,
   platform and architecture, command/profile with secrets removed, expected
   and actual behaviour, and a minimal reproduction when feasible.
3. Classify the work with the repository's existing labels. Use `bug`,
   `enhancement`, or `onboarding` where appropriate. Leave `triage` on work
   that still needs a decision or owner; do not invent labels merely to make an
   issue look categorized.
4. Identify the affected boundary: core library, CLI policy, proxy,
   platform-specific enforcement, documentation, or developer experience.
   Flag changes to enforcement, audit, credentials, or policy resolution for
   maintainer attention.
5. Put accepted work in the project board with an honest status. Moving an
   issue out of Backlog removes `triage` automatically; `Blocked` should state
   what is blocking it. Backlog items inactive for 90 days are marked `stale`
   and are closed after a further 14 days unless exempt or renewed.

Never handle a suspected sandbox escape, credential exposure, fail-open path,
or other security report as an ordinary public issue. Limit public discussion
to directing the reporter to private disclosure.

## Pull-request review and merge

Review the problem and security impact before line-by-line implementation.
The review should establish that the change matches its linked issue and,
where needed, its accepted NEP.

For every PR, verify the linked issue, focused scope, test evidence, DCO
sign-off, and relevant documentation. Ask for a rebase or conflict resolution
only when it is needed to review, test, or merge the current change. Keep
requested changes actionable: cite the file or behavior, explain the concern,
and state the desired outcome rather than prescribing an implementation when
several safe designs are possible.

Apply the stricter review standard from [GOVERNANCE.md](../../GOVERNANCE.md)
to enforcement paths, network filtering, credential handling, policy
resolution, audit behaviour, and the library/CLI boundary. Confirm that the
change fails secure, grants no broader capability than necessary, handles
macOS and Linux deliberately, and does not move policy into the library. A
security-critical decision requires explicit approval from every current
maintainer; lazy consensus is not enough.

For agent-assisted PRs, check the disclosure and compliance sections required
by the PR template. Do not waive the issue, attribution, or security-review
requirements because a contribution is automated.

Before merging, make sure required checks are green and unresolved review
threads are addressed. A maintainer must not merge their own PR without at
least one approval from another maintainer or reviewer, except for an urgent
security fix as defined in the security response runbook. Merge the smallest
reviewed change that solves the issue; follow up separately rather than
expanding scope during merge.

## Helping contributions reach merge

Maintainers should actively reduce avoidable friction without lowering the
bar. Triage a PR promptly, name one primary reviewer when possible, and keep
feedback consolidated. If a contributor is stuck, offer a minimal reproduction,
point to a comparable implementation, or split the work into independently
reviewable pieces.

Prioritize by user impact, security risk, release needs, and readiness—not by
who asks most often. An issue being assigned, labelled, or discussed is not a
promise of priority. When moving a ready PR ahead of other work, explain the
objective reason in the issue or PR so the queue remains fair and legible.

If a contributor becomes inactive, leave a concise summary of the remaining
work. Another contributor may take over only with clear attribution and a
separate branch or explicit handoff. Never rewrite or appropriate someone
else's work without acknowledgement.

## Escalation and records

Escalate uncertainty rather than silently making a security or governance
decision. Routine work follows the normal review process. Significant and
security-critical decisions follow the thresholds in
[GOVERNANCE.md](../../GOVERNANCE.md); document public decisions in their issue
or PR. Release work follows [the release runbook](releasing.md).

For security reports, keep the record private until coordinated disclosure.
For Code of Conduct reports, preserve reporter privacy and use the enforcement
process in [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md).
