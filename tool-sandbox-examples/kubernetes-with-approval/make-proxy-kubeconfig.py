#!/usr/bin/env python3
"""Generate a kubeconfig that sends kubectl through the nono credential proxy."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(Path.home() / ".kube" / "staging.yaml"))
    parser.add_argument("--output", default="staging-proxy.kubeconfig")
    parser.add_argument("--ca-output", default="staging-ca.pem")
    parser.add_argument("--profile", default="staging-admin.json")
    parser.add_argument(
        "--server",
        default="https://127.0.0.1:18766/kubernetes-api-staging",
    )
    return parser.parse_args()


def kubectl_config_json(kubeconfig: str) -> dict:
    output = subprocess.check_output(
        [
            "kubectl",
            "--kubeconfig",
            kubeconfig,
            "config",
            "view",
            "--raw",
            "--minify",
            "--flatten",
            "-o",
            "json",
        ],
        text=True,
    )
    return json.loads(output)


def main() -> None:
    args = parse_args()
    source = kubectl_config_json(args.input)
    clusters = source.get("clusters") or []
    if not clusters:
        raise SystemExit(f"no clusters found in {args.input}")

    cluster = clusters[0].get("cluster") or {}
    upstream_server = cluster.get("server")
    if not upstream_server:
        raise SystemExit(f"no server found in {args.input}")

    ca_data = cluster.get("certificate-authority-data")
    if not ca_data:
        raise SystemExit(f"no certificate-authority-data found in {args.input}")

    ca_path = Path(args.ca_output)
    ca_path.write_bytes(base64.b64decode(ca_data))

    output_path = Path(args.output)
    helper_name = "nono-kube-token-helper"
    output_path.write_text(
        "\n".join(
            [
                "apiVersion: v1",
                "kind: Config",
                "clusters:",
                "- name: nono-proxy",
                "  cluster:",
                f"    server: {args.server}",
                *(
                    ["    insecure-skip-tls-verify: true"]
                    if args.server.startswith("https://")
                    else []
                ),
                "contexts:",
                "- name: nono-proxy",
                "  context:",
                "    cluster: nono-proxy",
                "    user: nono-proxy",
                "current-context: nono-proxy",
                "users:",
                "- name: nono-proxy",
                "  user:",
                "    exec:",
                "      apiVersion: client.authentication.k8s.io/v1",
                f"      command: {helper_name}",
                "      interactiveMode: Never",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"wrote {output_path}")
    print(f"wrote {ca_path}")

    profile_path = Path(args.profile)
    if profile_path.exists():
        demo_dir = Path.cwd().resolve()
        proxy_kubeconfig_path = output_path.resolve()
        helper_path = (demo_dir / "nono-kube-token-helper").resolve()

        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        command_policies = profile.setdefault("command_policies", {})
        credential = command_policies.setdefault("credentials", {}).setdefault(
            "kubernetes-api-staging", {}
        )
        credential["upstream"] = upstream_server
        credential["tls_ca"] = str(ca_path.resolve())

        kubectl = command_policies.setdefault("commands", {}).setdefault("kubectl", {})
        kubectl_edge = kubectl.setdefault("from", {}).setdefault("session", {})
        kubectl_sandbox = kubectl_edge.setdefault("sandbox", {})
        kubectl_sandbox["fs_read_file"] = [str(proxy_kubeconfig_path)]
        kubectl_sandbox.setdefault("environment", {}).setdefault("set_vars", {})[
            "KUBECONFIG"
        ] = str(proxy_kubeconfig_path)

        helper = command_policies.setdefault("commands", {}).setdefault(
            "nono-kube-token-helper", {}
        )
        helper["executable"] = str(helper_path)
        helper_edge = helper.setdefault("from", {}).setdefault("kubectl", {})
        helper_sandbox = helper_edge.setdefault("sandbox", {})
        helper_sandbox["fs_read"] = [str(demo_dir)]
        helper_sandbox["fs_read_file"] = [str(helper_path)]

        profile_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
        print(f"updated {profile_path}")


if __name__ == "__main__":
    main()
