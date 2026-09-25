# Docker command-policy prototype

This example puts two boundaries around a small command-line tool:

```text
Docker container (no extra capabilities)
└── nono command policy
    └── demo-tool (narrow filesystem and argv permissions)
```

The tools are deliberately constrained. `demo-tool` can read one approved
file and write under `/work/output`; `cat` and `sed` can inspect that same
fixture; and `curl` can reach only the explicitly allowed domain and endpoint.
nono denies reads of the fixture secret and rejects unsupported tool operations
before they start.

## Prerequisites

- Docker or a compatible runtime
- A Linux host, or Docker Desktop with a Linux VM whose kernel supports
  Landlock

The build context is this directory, so the image does not upload the rest of
the repository or local build artifacts to Docker.

## Build

From this directory:

```sh
docker build -t agent-tool .
```

The image downloads and verifies the Linux `v0.78.0` nono release asset for
the host architecture, then compiles the tiny demo tool. The final image
contains no source tree or Rust toolchain.

## Permissions

Every docker command uses the `--cap-drop=ALL` and `--security-opt=no-new-privileges:true` flags to minimize privileges, showing that nono requires no privileged capabilities itself to operate.

## Scripted walkthrough

If you prefer to run a single scripted walkthrough of command mediation, you can use the `demonator` tool instead.

Install `demonator` with `cargo install demonator`, then run from this
directory:

```sh
demonator -c docker-tool-sandbox.yaml
```

Use `demonator -c docker-tool-sandbox.yaml --dry-run` to preview the complete
flow without running Docker commands.

## Run the allowed operations

```sh
docker run --rm \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  agent-tool read /work/allowed.txt

docker run --rm \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  agent-tool write /work/output/result.txt 'created by the tool'
```

The first command prints the approved fixture. The second prints a success
message; the output is ephemeral because the container is removed afterwards.

## Run the denied operations

Reading the secret reaches the tool but is rejected by the nested filesystem
sandbox:

```sh
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  agent-tool read /work/secret.txt
```

`fetch` is rejected by the command's invocation policy before it can attempt a
connection:

```sh
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  agent-tool fetch example.com:80
```

Deletion is explicitly denied at the argv layer, even though the demo tool
contains a `delete` operation:

```sh
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  agent-tool delete /work/allowed.txt
```

## Real-world command examples

The same profile can mediate ordinary Linux tools. Override the image entrypoint
so nono runs the selected pinned command through the profile:

```sh
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  --entrypoint /usr/bin/nono agent-tool \
  run --no-audit --profile /opt/nono-tool/profile.json -- \
  cat /work/allowed.txt

docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  --entrypoint /usr/bin/nono agent-tool \
  run --no-audit --profile /opt/nono-tool/profile.json -- \
  sed -n '1p' /work/allowed.txt
```

`curl` demonstrates domain and L7 endpoint filtering. `example.com` is allowed,
but only `GET /` is permitted; `example.org` is denied at the domain layer:

```sh
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  --entrypoint /usr/bin/nono agent-tool \
  run --no-audit --profile /opt/nono-tool/profile.json -- \
  curl https://example.com/

docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  --entrypoint /usr/bin/nono agent-tool \
  run --no-audit --profile /opt/nono-tool/profile.json -- \
  curl -X POST https://example.com/

docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  --entrypoint /usr/bin/nono agent-tool \
  run --no-audit --profile /opt/nono-tool/profile.json -- \
  curl https://example.com/private

docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  --entrypoint /usr/bin/nono agent-tool \
  run --no-audit --profile /opt/nono-tool/profile.json -- \
  curl https://example.org/
```

The first request is allowed. The POST is denied by method policy, the
`/private` request by endpoint policy, and `example.org` by proxy domain rules. A command
such as `cat /work/secret.txt` is denied by the command sandbox's filesystem policy.

The `curl` command sandbox explicitly receives nono's local proxy environment
and generated interception CA variables (`HTTPS_PROXY`, `SSL_CERT_FILE`, and
related variables). This is what lets the allowed HTTPS request work inside the
container while keeping the domain and endpoint rules enforced by nono.

The important distinction is that the container is the coarse outer boundary,
while nono expresses the command policy: exact executable, allowed arguments,
filesystem policy, and proxy domain and endpoint rules.

## Security notes

- The demo does not use `--privileged`, host networking, host PID/IPC, or host
  filesystem mounts.
- The Docker boundary and nono boundary are complementary; neither should be
  treated as a complete VM boundary for hostile multi-tenant workloads.
- The image keeps `/opt/nono-tool`, the profile, the tool executable, and input
  fixtures owned by `root:root`; only `/work/output` is writable by `nono`.
- The profile intentionally grants only the one input file and one output
  directory. If you change the tool or image layout, update both the outer
  filesystem grants and the nested command sandbox policy.
- Inspect the profile before adapting it to real tools. Never add real
  credentials or broad host mounts to this demo.
