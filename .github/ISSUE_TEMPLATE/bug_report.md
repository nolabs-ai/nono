---
name: Bug report
about: Something is broken or behaving unexpectedly
labels: bug, needs-triage
assignees: ''
---

## What happened

Describe what went wrong. What did you expect, and what did you get instead?

## Steps to reproduce

```
# Exact commands or config that triggers the issue
```

If you cannot reproduce it reliably, say so. Intermittent bugs are still
worth reporting.

## Environment

- nono version (`nono --version`):
- OS and kernel version (`uname -a`):
- Rust version if building from source (`rustc --version`):
- Deployment context (CLI, nono-proxy, Kubefence, other):

## Relevant output or logs

```
# Error messages, stack traces, or log output
# Remove credentials and sensitive paths before posting
```

## Profile or config

```toml
# The nono profile or config in use, with sensitive values redacted
```

## Additional context

Related issues, recent changes to your setup, links to relevant code.

---

**Security vulnerabilities** — do not use this template. Report privately:
https://github.com/nolabs-ai/nono/security/advisories/new
