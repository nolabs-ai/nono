# Responding to security vulnerabilities

This is the private-response runbook for nono maintainers. It operationalizes
the public reporting and disclosure commitments in [SECURITY.md](../../SECURITY.md).
It does not change the project's security model, severity taxonomy, or
governance requirements.

Treat a report as confidential from first contact. Do not copy exploit details,
proofs of concept, affected user information, credentials, or private advisory
links into public issues, pull requests, discussions, commits, CI logs, or
chat. Do not ask the reporter to publish more detail.

## 1. Receive and contain

Security reports belong in a private GitHub Security Advisory. If a report
arrives publicly, acknowledge only that it may be security-sensitive, remove
or minimize exposed details where the platform allows, and ask the reporter to
use the private advisory form linked from [SECURITY.md](../../SECURITY.md).
Do not confirm, deny, or debate the technical claim in public.

When a private report arrives:

1. Acknowledge it promptly and thank the reporter. State that the team will
   assess reproducibility and impact; do not promise a fix date, severity, or
   bounty.
2. Restrict access to maintainers who need it. Keep the advisory as the source
   of truth for the report, evidence, decisions, and reporter communication.
3. Check whether the report includes secrets or live credentials. Revoke or
   rotate project-controlled secrets through the appropriate private operational
   process, and do not attach those secrets to the advisory or repository.
4. Tell the maintainer council through a private channel that a report exists,
   sharing only the minimum detail needed for coordination.

If a public disclosure contains immediately exploitable information, focus
first on containment and a safe mitigation. Preserve links and timestamps in
the private record, coordinate moderation with the platform, and avoid asking
others to reproduce an exploit in public.

## 2. Validate safely

Assign a lead maintainer and, when useful, an independent second reviewer.
Reproduce only in an isolated environment with synthetic credentials and data.
Never test against a reporter's, user's, or third party's systems; never widen
a sandbox or disable protection on a machine holding sensitive data merely to
make reproduction easier.

Assess the report against nono's documented guarantees and threat model. In
particular, determine whether it permits an untrusted process to exceed granted
filesystem, network, credential, command, or approval authority; compromises a
trusted supervisor or broker; exposes protected credentials; or causes
enforcement to fail open. Distinguish this from expected access explicitly
granted by policy and from behavior outside the documented enforcement scope.

Record, privately:

- affected versions, platforms, configurations, and prerequisites;
- minimal reproduction and observed impact;
- the violated guarantee or policy boundary;
- mitigations users can safely apply before a release;
- the decision, evidence, and reviewers supporting the assessment.

An unverified or out-of-scope report still deserves a respectful explanation.
Do not close it as invalid without recording what was tested and why the claim
does not violate a documented guarantee.

## 3. Decide and remediate

Containment comes before a perfect fix. Consider a configuration workaround,
documentation warning, temporary feature restriction, or urgent release when
it reduces risk without weakening another security boundary. Do not silently
degrade enforcement or introduce a broad allow rule as a workaround.

Develop fixes in a private security advisory repository or another access-
controlled location. Keep commits, branch names, tests, CI output, and issue
references free of exploit details until disclosure is coordinated. Review the
fix for both Linux Landlock and macOS Seatbelt implications; a platform-specific
fix must state why the other platform is unaffected or what follow-up is
required.

The normal library/CLI boundary remains in force: the library is a pure
capability primitive and policy belongs in the CLI. Apply the project's
fail-secure, path-validation, least-privilege, and no-unwrap requirements to
the remediation exactly as to any other change.

Security-critical decisions require explicit approval from all current
maintainers under [GOVERNANCE.md](../../GOVERNANCE.md). An urgent security fix
may be merged by its author with the urgency recorded in the private advisory,
but notify the other maintainers immediately and obtain review as soon as it is
safe. Use the release process in [releasing.md](releasing.md) to publish the
fix; governance permits a security release without the ordinary three-business-
day release window.

## 4. Coordinate disclosure

Agree privately with the reporter on a disclosure plan after validation. The
plan should cover the fixed versions, mitigations, advisory text, credit or
anonymity preference, and publication time. Do not publish until affected
releases and user guidance are ready, unless active exploitation or an existing
public disclosure makes earlier communication necessary.

Use the GitHub Security Advisory to request a CVE when appropriate and to
publish the affected versions, impact, mitigation, acknowledgements, and links
to the fix. Write the public advisory so users can decide whether they are
affected without revealing unnecessary exploit mechanics. Release notes should
accurately describe any changed security behavior.

After publication, link the public advisory from any necessary public issue or
PR, thank the reporter according to their preference, and monitor for follow-up
reports. Do not retroactively expose private discussion or reporter identity.

## 5. Learn without leaking

Close the private record with a short retrospective: what failed, why existing
tests or review did not catch it, what guardrail will prevent recurrence, and
any follow-up owner. Make non-sensitive corrective work public and link it to
the advisory where useful. Changes that alter enforcement semantics, policy
resolution, or the library/CLI boundary may require a NEP before implementation;
follow [the NEP process](../../neps/README.md).

Do not use incident response as a reason to relax normal security standards.
If there is uncertainty about disclosure, severity, scope, or a conflict among
maintainers, preserve confidentiality and escalate to the maintainer council
before proceeding.
