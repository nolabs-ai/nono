# RPM source packaging

This directory contains the RPM source package template used to build `nono-cli`
from source for Fedora COPR.

The GitHub Release RPM workflow uses `scripts/build-rpm.sh`, which packages an
already-built release binary. COPR should instead build from a source RPM, using
the helper below.

## Build an SRPM

```bash
scripts/build-srpm.sh
```

To build an SRPM for a specific version or tag value:

```bash
scripts/build-srpm.sh 0.61.1
scripts/build-srpm.sh v0.61.1
```

The generated SRPM is written under:

```text
target/rpm/copr/SRPMS/
```

The helper vendors Cargo dependencies into the source tarball and writes a local
Cargo source override, so COPR can build with `cargo --offline`.

## Submit to COPR

After creating the COPR project, submit the generated SRPM:

```bash
copr-cli build nolabs-ai/nono target/rpm/copr/SRPMS/*.src.rpm
```

Replace `nolabs-ai/nono` with the actual COPR owner/project name if the
official project uses a COPR group namespace.

## Build requirements

The spec expects chroots with Rust and Cargo 1.95 or newer, matching the
workspace `rust-version`. It also requires the native C/C++ toolchain and CMake
for vendored Rust dependencies that compile native code.
