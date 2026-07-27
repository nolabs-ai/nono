# Governance

nono is an open source capability-based sandboxing system for running
untrusted AI agents with OS-enforced isolation, maintained by a small
council of maintainers. The current maintainer council includes contributors
from Nolabs and the broader OpenSSF and Sigstore ecosystems, reflecting the
project's commitment to multi-organization stewardship. This document
describes how the project is governed, how decisions are made, and how
contributors can grow into maintainership.

The model is proportionate to the project's current stage. nono is early-stage
security infrastructure. A transparent maintainer-council model serves it better
than formal committees or elections at this point. This document will be revised
as the project and its contributor base grow.

---

## Principles

**Maintainership is individual, not corporate.** Maintainers participate as
individuals. If a maintainer changes employer, their role in the project does
not change. No company owns or controls the project.

**Decisions are made in the open.** Significant decisions are proposed and
discussed in public GitHub issues or pull requests before they are adopted.
Private decisions affecting the project are not binding.

**Security is a first-class concern.** Changes to the enforcement model, the
audit log, or the credential isolation path require explicit maintainer
agreement, not lazy consensus. The bar is higher because the stakes are higher.

**Honest about scale.** nono does not pretend to governance structures it has
not yet earned. This document describes what is real now and what the path
forward looks like.

---

## Security Posture

nono is currently in alpha. Security guarantees are not yet stable and
breaking changes may occur. Use in production environments is not
recommended at this stage.

The project's current security posture and known limitations are documented
in [SECURITY.md](./SECURITY.md). A comprehensive third-party security audit
conducted by OSTIF is scheduled for Q3 2026. Audit findings will be
published in full.

---

## Roles

### Contributor

Anyone who opens an issue, submits a pull request, improves documentation, or
participates in project discussion is a contributor. No formal process is
required.

### Reviewer

A reviewer has demonstrated sustained, high-quality contributions and is
trusted to review pull requests in their area of expertise. Reviewers are
expected to:

- Review pull requests and provide substantive feedback
- Flag security-relevant changes for maintainer attention
- Uphold the code quality standards in CONTRIBUTING.md

Reviewers do not have merge rights. They are recognized in CONTRIBUTORS.md.

**Becoming a reviewer:** a contributor with at least three merged pull requests
of meaningful scope may be nominated by any maintainer. The contribution
standards expected of reviewers are described in [CONTRIBUTING.md](./CONTRIBUTING.md).
Nominations are confirmed by lazy consensus among maintainers over 5 business
days. Silence counts as approval. A single objection from any maintainer blocks
the nomination and triggers a discussion.

### Maintainer

Maintainers have merge rights on the repository. They are collectively
responsible for the technical direction of the project, release decisions,
security posture, and the health of the contributor community.

Maintainers are expected to:

- Review and merge pull requests within the 5 business day SLA stated in
  CONTRIBUTING.md
- Participate in governance decisions
- Respond to security disclosures in accordance with SECURITY.md
- Represent the project's interests, not their employer's, when those conflict

**Becoming a maintainer:** a reviewer who has demonstrated sustained
contribution across multiple areas of the codebase may be nominated by any
existing maintainer. Maintainer nominations require explicit approval from all
current maintainers, not lazy consensus. A single objection triggers a
discussion before the decision is finalized.

**Stepping down:** a maintainer who is no longer able to fulfill the role
should notify the other maintainers and update this document. Merge rights
will be removed. The maintainer may return to contributor or reviewer status
at their discretion.

**Involuntary removal:** a maintainer who is unresponsive for 90 consecutive
days, or who acts contrary to the project's principles, may be removed by
explicit agreement of all remaining maintainers. Removal decisions are
documented in a public GitHub issue.

---

## Current Maintainers

See [MAINTAINERS.md](./MAINTAINERS.md) for the current maintainer council,
founding maintainers, and contact information.

The maintainer council currently has three founding members. Changes to
council membership follow the process in the Decision-Making section below.

---

## Decision-Making

### Routine decisions

Routine decisions include: merging pull requests, cutting releases, updating
documentation, adding dependencies, and adjusting CI configuration.

These are made by any maintainer following normal review process. A maintainer
should not merge their own pull request without at least one other maintainer
or reviewer approving it, except for urgent security fixes.

### Significant decisions

Significant decisions include: changes to the enforcement model or audit log
behavior, deprecation of public API, major new dependencies, changes to the
contribution or review process, and changes to this document.

These require a proposal posted as a GitHub issue with a minimum 5 business
day comment period. If no objection is raised by any maintainer within that
window, the decision passes by lazy consensus. If an objection is raised, the
maintainers must reach explicit agreement before proceeding.

### Security-critical decisions

Security-critical decisions include: changes to the sandbox enforcement
path, the network filtering and credential proxy model, the policy system,
and the security disclosure policy.

These require explicit approval from all current maintainers. Lazy consensus
does not apply. Decisions are documented in a pull request and linked from the
relevant issue.

### Tie-breaking

If maintainers cannot reach agreement after good-faith discussion, Luke Hinds
holds the deciding vote as lead founding maintainer. This mechanism exists to
keep the project moving. It is not intended to override sustained, substantive
objection from other founding maintainers. If it is used, the reasoning is
documented publicly.

---

## Releases

Release decisions are made by maintainer consensus. Any maintainer may propose
a release by opening a GitHub issue. If no objection is raised within 3
business days, the release proceeds.

Security-related releases may be cut immediately without the 3-day window at
the discretion of any maintainer, with notification to the others.

Release notes are the responsibility of the maintainer cutting the release.
They should accurately describe changes to the enforcement model, public API,
and any security-relevant behavior.

---

## Stewardship and Succession

**Maintainership is individual.** If a maintainer leaves their employer, their
maintainer status does not change. The project is not controlled by any single
organization.

**If the founding maintainer is unavailable.** If Luke Hinds becomes
unavailable for an extended period, the remaining maintainers hold all
governance authority. No single organization has veto power over the project's
direction.

**Long-term stewardship.** nono's long-term home is the OpenSSF and CNCF
ecosystems. The project intends to pursue CNCF sandbox status as the
contributor base and governance structure mature. This is a planned direction,
not a current requirement.

---

## Amendments

Changes to this document follow the significant decision process: a pull
request with a 5 business day comment period and lazy consensus or explicit
agreement as appropriate to the nature of the change. Changes to the
stewardship and succession section require explicit agreement from all
maintainers.

---

## Code of Conduct

nono follows the
[Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Reports should be directed to the maintainers via the security contact in
SECURITY.md.

---

## Standards Alignment

nono's governance is designed to satisfy the requirements of the
[OpenSSF Best Practices Badge](https://www.bestpractices.dev/en/projects/13332/passing)
and to meet the sustainability expectations of the
[Alpha-Omega project](https://alpha-omega.dev). The project currently holds
the passing badge. The maintainer-council model, multi-organization maintainer
table, documented succession path, and scheduled OSTIF security audit directly
address the concerns raised during Alpha-Omega engagement.

The project's OpenSSF Scorecard results are available at:
https://scorecard.dev/viewer/?uri=github.com/nolabs-ai/nono

nono's sandboxing model is cited as a reference implementation in
[SAF-M-74](https://github.com/secure-agentic-framework/saf-mcp), merged
June 17 2026, reviewed by the SAF-MCP SIG co-lead. This technical standing
informs the governance model: decisions about the enforcement path carry
weight beyond the project itself and are held to a higher bar accordingly.

---

*Adopted June 2026. Supersedes any prior informal governance arrangements.*
