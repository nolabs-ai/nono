#!/usr/bin/env bash
# Run SPIFFE/SPIRE integration tests locally.
#
# Usage:
#   ./scripts/spire-test.sh              # download SPIRE if needed, run tests, clean up
#   SPIRE_BIN=/usr/local/bin ./scripts/spire-test.sh  # use binaries already on PATH
#
# The script is idempotent: if SPIRE binaries are already present in
# SPIRE_BIN (default: /tmp/nono-spire-bin) they are reused without
# re-downloading. The SPIRE data dir is always recreated fresh so tests
# start from a clean state.
#
# Requirements: curl, tar, cargo

set -euo pipefail

SPIRE_VERSION="1.9.6"
SPIRE_BIN="${SPIRE_BIN:-/tmp/nono-spire-bin}"
SPIRE_DATA="/tmp/nono-test-spire"
SPIRE_SERVER_SOCK="${SPIRE_DATA}/server.sock"
SPIRE_AGENT_SOCK="${SPIRE_DATA}/agent.sock"
TRUST_DOMAIN="test.nono"
WORKLOAD_SPIFFE_ID="spiffe://${TRUST_DOMAIN}/nono-proxy"

SERVER_PID=""
AGENT_PID=""

# ─── Cleanup ──────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "==> Cleaning up"
    [ -n "$AGENT_PID" ]  && kill "$AGENT_PID"  2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$SPIRE_DATA"
    echo "    Done."
}
trap cleanup EXIT

# ─── SPIRE binaries ───────────────────────────────────────────────────────────

ensure_spire() {
    if command -v spire-server &>/dev/null && command -v spire-agent &>/dev/null; then
        echo "==> Using SPIRE from PATH ($(command -v spire-server))"
        return
    fi

    if [ -x "${SPIRE_BIN}/bin/spire-server" ] && [ -x "${SPIRE_BIN}/bin/spire-agent" ]; then
        echo "==> Using cached SPIRE in ${SPIRE_BIN}"
        export PATH="${SPIRE_BIN}/bin:${PATH}"
        return
    fi

    echo "==> Downloading SPIRE ${SPIRE_VERSION}"
    local os arch tarball
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "${arch}" in
        x86_64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) echo "Unsupported arch: ${arch}"; exit 1 ;;
    esac

    tarball="spire-${SPIRE_VERSION}-${os}-${arch}-musl.tar.gz"
    curl -fsSL \
        "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/${tarball}" \
        -o /tmp/spire.tar.gz
    mkdir -p "${SPIRE_BIN}"
    tar -xzf /tmp/spire.tar.gz -C "${SPIRE_BIN}" --strip-components=1
    rm -f /tmp/spire.tar.gz
    export PATH="${SPIRE_BIN}/bin:${PATH}"
    echo "    Installed to ${SPIRE_BIN}/bin"
}

# ─── SPIRE setup ──────────────────────────────────────────────────────────────

start_server() {
    echo "==> Starting SPIRE server"
    rm -rf "${SPIRE_DATA}"
    mkdir -p "${SPIRE_DATA}/data/server"
    spire-server run -config testdata/spire/server.conf &
    SERVER_PID=$!

    local i=0
    while [ $i -lt 30 ]; do
        [ -S "${SPIRE_SERVER_SOCK}" ] && break
        sleep 0.5
        i=$((i + 1))
    done
    [ -S "${SPIRE_SERVER_SOCK}" ] || { echo "SPIRE server did not start"; exit 1; }
    echo "    PID ${SERVER_PID}, socket ${SPIRE_SERVER_SOCK}"
}

start_agent() {
    echo "==> Starting SPIRE agent"
    mkdir -p "${SPIRE_DATA}/data/agent"

    local raw token
    raw="$(spire-server token generate \
        -socketPath "${SPIRE_SERVER_SOCK}" \
        -spiffeID "spiffe://${TRUST_DOMAIN}/agent")"
    token="$(echo "${raw}" | grep -oE '[0-9a-f-]{36}')"

    spire-agent run -config testdata/spire/agent.conf -joinToken "${token}" &
    AGENT_PID=$!

    local i=0
    while [ $i -lt 30 ]; do
        [ -S "${SPIRE_AGENT_SOCK}" ] && break
        sleep 0.5
        i=$((i + 1))
    done
    [ -S "${SPIRE_AGENT_SOCK}" ] || { echo "SPIRE agent did not start"; exit 1; }
    echo "    PID ${AGENT_PID}, socket ${SPIRE_AGENT_SOCK}"
}

register_workload() {
    echo "==> Registering workload entry (uid $(id -u))"
    spire-server entry create \
        -socketPath "${SPIRE_SERVER_SOCK}" \
        -spiffeID  "${WORKLOAD_SPIFFE_ID}" \
        -parentID  "spiffe://${TRUST_DOMAIN}/agent" \
        -selector  "unix:uid:$(id -u)"
    echo "    ${WORKLOAD_SPIFFE_ID}"

    # Wait for the agent to sync the entry from the server before running tests.
    # Without this, the first JWT fetch hits the agent before it has an identity
    # cached, producing harmless "No identity issued" log noise.
    echo "==> Waiting for agent to sync workload entry"
    local i=0
    while [ $i -lt 20 ]; do
        if spire-agent api fetch jwt \
            -socketPath "${SPIRE_AGENT_SOCK}" \
            -audience "warmup" 2>/dev/null | grep -q "spiffe://"; then
            break
        fi
        sleep 0.5
        i=$((i + 1))
    done
    echo "    Ready"
}

# ─── Tests ────────────────────────────────────────────────────────────────────

run_tests() {
    local env_args=(
        SPIRE_AGENT_SOCKET="${SPIRE_AGENT_SOCK}"
        SPIRE_TRUST_DOMAIN="${TRUST_DOMAIN}"
        SPIRE_WORKLOAD_SPIFFE_ID="${WORKLOAD_SPIFFE_ID}"
    )

    echo ""
    echo "==> cargo test: nono-proxy spiffe_integration"
    env "${env_args[@]}" \
        cargo test -p nono-proxy --test spiffe_integration -- --nocapture

    echo ""
    echo "==> cargo test: nono-proxy vault_integration"
    env "${env_args[@]}" \
        cargo test -p nono-proxy --test vault_integration -- --nocapture

    # Binary-level tests invoke the full nono sandbox. On macOS, Seatbelt
    # returns EPERM when applied from a test context; these tests only run
    # reliably on Linux (Landlock), which is what CI uses (ubuntu-latest).
    if [ "$(uname -s)" = "Linux" ]; then
        echo ""
        echo "==> cargo test: nono-cli spiffe_run"
        env "${env_args[@]}" \
            cargo test -p nono-cli --test spiffe_run -- --nocapture
    else
        echo ""
        echo "==> Skipping nono-cli spiffe_run (macOS: binary-level sandbox tests run in CI on Linux)"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────

cd "$(git rev-parse --show-toplevel)"

ensure_spire
start_server
start_agent
register_workload
run_tests

echo ""
echo "==> All SPIFFE/SPIRE tests passed"
