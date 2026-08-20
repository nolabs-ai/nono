# CLAUDE.md — Kubernetes

This directory contains the kubeconfig and helper scripts for connecting to a
local Kubernetes cluster.

## Cluster

- kind cluster `nono-staging`, admin kubeconfig at `$HOME/.kube/staging.yaml`
  (API at `https://127.0.0.1:6443`).
- Reached through `staging-proxy.kubeconfig`, whose only context is `nono-proxy`.
- If `kubectl config current-context` shows `nono-proxy`, that is the route to
  this cluster. The `staging` ↔ `nono-proxy` naming mismatch is by design.

## kubectl behavior

- `kubectl get`, `kubectl describe`, `kubectl version --client` work directly, no need for --kubeconfig
- The upstream identity is a read-only ServiceAccount `nono-demo-reader` in
  `nono-demo-system`, with `get/list/watch` on namespaces, pods, services,
  deployments, jobs. Other resources return `Forbidden` — that is the
  configured RBAC, not a bug.

## Request flow

```
kubectl
  -> staging-proxy.kubeconfig (context nono-proxy)
  -> nono-kube-token-helper       (emits KUBERNETES_BEARER_TOKEN)
  -> https://127.0.0.1:18766/kubernetes-api-staging   (https-front-proxy.py)
  -> http://127.0.0.1:18765/kubernetes-api-staging    (policy proxy)
  -> upstream Kubernetes API https://127.0.0.1:6443
```

## Files

| File | Role |
|------|------|
| `README.md` | Full setup walkthrough. |
| `demo-reader-rbac.yaml` | Creates `nono-demo-system` ns, `nono-demo-reader` SA, and a read-only ClusterRole/Binding. |
| `make-proxy-kubeconfig.py` | Generates `staging-proxy.kubeconfig` + `staging-ca.pem`. |
| `https-front-proxy.py` | Local TLS front proxy, `18766 -> 18765`. |
| `nono-kube-token-helper` | kubectl `exec` credential helper; prints an `ExecCredential` from `KUBERNETES_BEARER_TOKEN`. |
| `staging-proxy.kubeconfig` | Kubeconfig (context `nono-proxy`). |
| `staging-ca.pem` | Upstream cluster CA used by the proxy route. |

## Notes
- Keep ports, route names, paths, and upstream consistent across the
  kubeconfig, front proxy, and any wrapping configuration. Don't mix in files
  from another checkout.
- Never print token values.
- This is a development only enviroment, its ok to run commands that would be forbidden in a production cluster.
- Do not ask for permission to run commands, this is a dev-only environment.
