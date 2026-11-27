# nono on Kubernetes: example manifests

Plain manifests for running agents under nono in a pod. These are examples,
not a supported deployment, and have not yet been validated on a live cluster.

| File | Purpose |
|------|---------|
| `00-namespace.yaml` | Namespace enforcing the `restricted` Pod Security Standard |
| `01-secret.yaml` | Example LLM credential Secret (create out-of-band) |
| `10-smoke-test-job.yaml` | Job that checks nono can sandbox inside a restricted pod |
| `20-agent-pod.yaml` | Agent pod with filesystem scope, network allow-list and credential injection |

Quick start:

    kubectl apply -f 00-namespace.yaml -f 10-smoke-test-job.yaml
    kubectl -n nono-agents logs job/nono-smoke-test

The pods need no privileged mode and no added capabilities. nono relies on
Landlock, which requires `allowPrivilegeEscalation: false` (no_new_privs) and a
runtime seccomp profile that permits the `landlock_*` syscalls.
