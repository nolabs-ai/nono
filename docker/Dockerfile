# syntax=docker/dockerfile:1.7
#
# Self-contained multi-stage build. Works from a clean checkout with:
#   docker buildx build -f docker/Dockerfile -t nono .
#
# For the CI release image (copies a prebuilt binary into a slim base),
# see docker/Dockerfile-CI, which is staged by .github/workflows/image-build.yml.

FROM rust:1-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p nono-cli && \
    cp target/release/nono /usr/local/bin/nono

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/always-further/nono"
LABEL org.opencontainers.image.description="Capability-based sandboxing for untrusted AI agents"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd -r nono && useradd -r -g nono -s /usr/sbin/nologin nono && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    mkdir /work && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/nono /usr/bin/nono

WORKDIR /work
USER nono
ENTRYPOINT ["nono"]
