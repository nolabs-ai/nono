#!/usr/bin/env bash
# Run nono tests or ad hoc commands in a cached Linux Docker environment.

set -euo pipefail

IMAGE_NAME="${NONO_LINUX_IMAGE:-nono-linux-dev:bookworm}"
DOCKERFILE="${NONO_LINUX_DOCKERFILE:-tools/docker/linux-dev.Dockerfile}"
CACHE_PREFIX="${NONO_LINUX_CACHE_PREFIX:-nono-linux-bookworm}"
REGISTRY_VOLUME="${NONO_LINUX_REGISTRY_VOLUME:-${CACHE_PREFIX}-cargo-registry}"
GIT_VOLUME="${NONO_LINUX_GIT_VOLUME:-${CACHE_PREFIX}-cargo-git}"
TARGET_VOLUME="${NONO_LINUX_TARGET_VOLUME:-${CACHE_PREFIX}-target}"
REBUILD_IMAGE="${NONO_LINUX_REBUILD_IMAGE:-0}"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/test-linux-container.sh
  ./scripts/test-linux-container.sh cargo test -p nono-cli
  ./scripts/test-linux-container.sh bash -c 'cargo run -q -p nono-cli -- run --profile always-further/claude --dry-run -- echo ok'

Behavior:
  - Builds a reusable Linux dev image with required system packages
  - Reuses Docker volumes for Cargo registry, Cargo git cache, and Linux target artifacts
  - Defaults to `cargo test --workspace` when no command is provided

Environment:
  NONO_LINUX_REBUILD_IMAGE=1   Rebuild the Docker image before running
  NONO_LINUX_IMAGE             Override image name (default: nono-linux-dev:bookworm)
  NONO_LINUX_CACHE_PREFIX      Prefix for Docker cache volumes
EOF
}

require_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: required tool '$tool' not found" >&2
        exit 1
    fi
}

quote_args() {
    printf '%q ' "$@"
}

build_image_if_needed() {
    if [[ "$REBUILD_IMAGE" == "1" ]] || ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        docker build -t "$IMAGE_NAME" -f "$DOCKERFILE" .
    fi
}

main() {
    require_tool docker

    if [[ ! -f "$DOCKERFILE" ]]; then
        echo "error: dockerfile not found: $DOCKERFILE" >&2
        exit 1
    fi

    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        usage
        exit 0
    fi

    build_image_if_needed

    if [[ "$#" -eq 0 ]]; then
        set -- cargo test --workspace
    fi

    local command_string
    command_string="$(quote_args "$@")"

    docker run --rm \
        -v "$(pwd)":/work \
        -v "$REGISTRY_VOLUME":/usr/local/cargo/registry \
        -v "$GIT_VOLUME":/usr/local/cargo/git \
        -v "$TARGET_VOLUME":/cache/target \
        -w /work \
        -e CARGO_TARGET_DIR=/cache/target \
        "$IMAGE_NAME" \
        bash -c "set -euo pipefail; ${command_string}"
}

main "$@"
