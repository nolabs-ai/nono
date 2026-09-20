# syntax=docker/dockerfile:1
# Build from this directory:
#   docker build -t nono-tool-sandbox .

FROM rust:1-bookworm AS builder

ARG TARGETARCH
ARG NONO_VERSION=0.78.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

COPY demo-tool.rs /tmp/demo-tool.rs

RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) nono_arch=x86_64-unknown-linux-gnu ;; \
      arm64) nono_arch=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported Docker architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    base_url="https://github.com/nolabs-ai/nono/releases/download/v${NONO_VERSION}"; \
    asset="nono-v${NONO_VERSION}-${nono_arch}.tar.gz"; \
    curl -fsSL "$base_url/$asset" -o "/tmp/$asset"; \
    curl -fsSL "$base_url/SHA256SUMS.txt" -o /tmp/SHA256SUMS.txt; \
    (cd /tmp && grep "  $asset$" SHA256SUMS.txt | sha256sum -c -); \
    tar -xzf "/tmp/$asset" -C /tmp; \
    rustc /tmp/demo-tool.rs --edition 2021 -O -o /tmp/demo-tool

FROM debian:bookworm-slim

RUN groupadd --system nono \
    && useradd --system --gid nono --create-home --home-dir /home/nono --shell /usr/sbin/nologin nono \
    && mkdir -p /opt/nono-tool /work/output \
    && chown -R nono:nono /opt/nono-tool /work

COPY --from=builder /tmp/nono /usr/bin/nono
COPY --from=builder /tmp/demo-tool /opt/nono-tool/demo-tool
COPY profile.json /opt/nono-tool/profile.json
COPY allowed.txt /work/allowed.txt
COPY secret.txt /work/secret.txt

RUN chmod 0555 /usr/bin/nono /opt/nono-tool/demo-tool \
    && chmod 0444 /opt/nono-tool/profile.json /work/allowed.txt /work/secret.txt \
    && chown -R nono:nono /opt/nono-tool /work

WORKDIR /work
USER nono
ENV PATH="/opt/nono-tool:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ENTRYPOINT ["/usr/bin/nono", "run", "--profile", "/opt/nono-tool/profile.json", "--", "demo-tool"]
