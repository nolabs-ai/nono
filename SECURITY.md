# Security Policy

## Reporting a Vulnerability

**Do not report security issues publicly.**

* ❌ Do **not** open public GitHub issues for security vulnerabilities
* ❌ Do **not** disclose vulnerabilities in discussions, PRs, or social channels

Instead, report vulnerabilities **privately** via GitHub Security Advisories:

👉 https://github.com/nolabs-ai/nono/security/advisories/new

This ensures:

* Coordinated disclosure
* Time to assess and remediate
* Protection for users and contributors

---

## Understand nono’s security model

Before reporting a security vulnerability, read and understand nono’s security model.

nono is a fine-grained, kernel-enforced capability sandbox. It is not a VM, microVM, hypervisor, or separate guest/host isolation boundary, and it does not provide a separate kernel. Instead, it restricts processes and their descendants within the host’s shared kernel and user context.

A sandbox escape occurs when an untrusted process exceeds the authority granted by its effective policy—for example, by bypassing filesystem, network, credential, command, or approval controls. Access explicitly granted by policy is not an escape. Behavior outside nono’s documented enforcement scope or threat model is not, by itself, an escape unless it violates another documented security guarantee.

Other violations of documented security guarantees, such as compromising the trusted supervisor or broker, disclosing protected credentials, or causing enforcement to fail open, may constitute security vulnerabilities.

When submitting a report, identify the specific policy or documented security guarantee that is bypassed.

## LLM-Generated Findings

If a vulnerability is identified by a Large Language Model (LLM):

* ❌ Do **not** report it blindly
* ✅ Ensure you **fully understand and can explain** the issue, humans with a security background will be corresponding with you.
* ✅ Validate the impact and reproducibility

Low-quality or speculative reports slow down response time and reduce overall security effectiveness.

---

## Expectations

Given the alpha status:

* Breaking changes may occur without notice
* Security guarantees are **not yet stable**
* Some classes of vulnerabilities may not yet be fully mitigated

Use in production environments is **not recommended** at this stage.

---

## Disclosure Policy

We aim to:

* Acknowledge reports promptly
* Investigate and validate findings
* Provide fixes or mitigations where possible
* Coordinate disclosure with reporters

### Safe Harbor

When conducting security research in good faith and in accordance with this policy, we consider your research to be authorized. We will not initiate legal action against you for research that adheres to these guidelines.

---

## Thank You

Responsible disclosure helps make this project safer for everyone.
