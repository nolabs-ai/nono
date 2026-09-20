# Docker tool-sandbox prototype

This example puts two boundaries around a small command-line tool:

```text
Docker container (no extra capabilities)
└── nono command policy
    └── demo-tool (narrow filesystem and argv permissions)
```

The tool is deliberately harmless. It can read one approved file and write
under `/work/output`. nono denies reads of the fixture secret, denies network
access, and rejects unsupported tool operations before the tool starts.

## Prerequisites

- Docker or a compatible runtime
- A Linux host, or Docker Desktop with a Linux VM whose kernel supports
  Landlock

The build context is this directory, so the image does not upload the rest of
the repository or local build artifacts to Docker.

## Build

From this directory:

```sh
docker build -t nono-tool-sandbox .
```

The image downloads and verifies the Linux `v0.78.0` nono release asset for
the host architecture, then compiles the tiny demo tool. The final image
contains no source tree or Rust toolchain.

## Run the allowed operations

```sh
docker run --rm \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  nono-tool-sandbox read /work/allowed.txt

docker run --rm \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  nono-tool-sandbox write /work/output/result.txt 'created by the tool'
```

The first command prints the approved fixture. The second prints a success
message; the output is ephemeral because the container is removed afterwards.

## Run the denied operations

Reading the secret reaches the tool but is rejected by the nested filesystem
sandbox:

```sh
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  nono-tool-sandbox read /work/secret.txt
```

`fetch` is rejected by the command's invocation policy before it can attempt a
connection:

```sh
docker run --rm --cap-drop=ALL --security-opt=no-new-privileges:true \
  nono-tool-sandbox fetch example.com:80
```

The important distinction is that the container is the coarse outer boundary,
while nono expresses the tool-specific policy: exact executable, allowed
arguments, filesystem capabilities, and blocked network.

## Security notes

- The demo does not use `--privileged`, host networking, host PID/IPC, or host
  filesystem mounts.
- The Docker boundary and nono boundary are complementary; neither should be
  treated as a complete VM boundary for hostile multi-tenant workloads.
- The profile intentionally grants only the one input file and one output
  directory. If you change the tool or image layout, update both the outer
  filesystem grants and the nested command sandbox grants.
- Inspect the profile before adapting it to real tools. Never add real
  credentials or broad host mounts to this demo.
