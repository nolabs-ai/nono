#!/bin/bash
# wsl-dev.sh — WSL2 development helper for nono
#
# Syncs changes from the Windows checkout into WSL2's Linux filesystem,
# builds, and runs tests. Designed to be called from Windows:
#
#   wsl.exe -d Ubuntu -- bash /mnt/c/path/to/nono/scripts/wsl-dev.sh [command]
#
# Commands:
#   setup       Install Rust toolchain and clone repo to ~/nono
#   sync        Pull latest changes from Windows checkout into ~/nono
#   build       Build all crates
#   test        Run all tests (unit + integration)
#   test-wsl2   Run only WSL2-specific tests
#   test-unit   Run only unit tests
#   ci          Full CI check (clippy + fmt + tests)
#   shell       Open a shell in ~/nono
#
# With no arguments, runs: sync + build + test-wsl2

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Auto-detect Windows repo from this script's location (scripts/ is one level down)
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIN_REPO="${NONO_WIN_REPO:-$(dirname "$_SCRIPT_DIR")}"
LINUX_REPO="${NONO_LINUX_REPO:-$HOME/nono}"

log() { echo -e "${BLUE}==>${NC} $*"; }
ok()  { echo -e "${GREEN}==>${NC} $*"; }
err() { echo -e "${RED}==>${NC} $*" >&2; }

ensure_rust() {
    if ! command -v cargo &>/dev/null; then
        # Try sourcing cargo env first
        # shellcheck disable=SC1091
        [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
    fi
    if ! command -v cargo &>/dev/null; then
        err "Rust not installed. Run: $0 setup"
        return 1
    fi
}

ensure_repo() {
    if [[ ! -d "$LINUX_REPO" ]]; then
        err "Repo not found at $LINUX_REPO. Run: $0 setup"
        return 1
    fi
}

cmd_setup() {
    log "Setting up WSL2 development environment"

    # Install Rust if missing
    if ! command -v cargo &>/dev/null; then
        if [[ -f "$HOME/.cargo/env" ]]; then
            # shellcheck disable=SC1091
            source "$HOME/.cargo/env"
        fi
    fi
    if ! command -v cargo &>/dev/null; then
        log "Installing Rust toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
        ok "Rust installed: $(cargo --version)"
    else
        ok "Rust already installed: $(cargo --version)"
    fi

    # Install build deps (Ubuntu/Debian)
    if command -v apt-get &>/dev/null; then
        log "Checking build dependencies..."
        for pkg in build-essential pkg-config; do
            if ! dpkg -s "$pkg" &>/dev/null; then
                log "Installing $pkg..."
                sudo apt-get install -y "$pkg"
            fi
        done

        # GCC 9 (Ubuntu 20.04 default) triggers a memcmp bug in aws-lc-sys.
        # Install GCC 10+ and set it as the default compiler.
        gcc_ver=$(gcc -dumpversion 2>/dev/null || echo "0")
        if [[ "${gcc_ver%%.*}" -lt 10 ]]; then
            log "GCC $gcc_ver is too old (aws-lc-sys needs 10+), installing gcc-10..."
            sudo apt-get install -y gcc-10 g++-10
            sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100 \
                --slave /usr/bin/g++ g++ /usr/bin/g++-10
            sudo update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-10 100
            ok "GCC 10 installed and set as default"
        fi
    fi

    # Sync repo from Windows working tree
    mkdir -p "$LINUX_REPO"
    cmd_sync

    # Initial build
    cd "$LINUX_REPO"
    log "Running initial build..."
    cargo build 2>&1
    ok "Setup complete! Run '$0' to sync+build+test"
}

cmd_sync() {
    ensure_repo

    cd "$LINUX_REPO"

    # rsync the entire Windows working tree (committed + uncommitted).
    # --delete ensures removed files are cleaned up. .git/ and target/
    # are excluded so git state and builds are preserved.
    log "Syncing from Windows working tree..."
    rsync -a --delete \
        --exclude '.git/' \
        --exclude 'target/' \
        --exclude 'node_modules/' \
        "$WIN_REPO/" "$LINUX_REPO/"

    # Fix Windows CRLF line endings on all source files
    find "$LINUX_REPO" \( -name '*.sh' -o -name '*.rs' -o -name '*.toml' -o -name '*.json' -o -name '*.md' -o -name '*.mdx' \) \
        -not -path '*/target/*' -exec sed -i 's/\r$//' {} + 2>/dev/null || true

    ok "Synced from $WIN_REPO"
}

cmd_build() {
    ensure_rust
    ensure_repo
    cd "$LINUX_REPO"
    log "Building..."
    cargo build 2>&1
    ok "Build succeeded"
}

cmd_test() {
    ensure_rust
    ensure_repo
    cd "$LINUX_REPO"

    log "Running unit tests..."
    cargo test 2>&1

    log "Running integration tests..."
    cargo build --release 2>&1
    for test_script in tests/integration/test_*.sh; do
        log "Running $(basename "$test_script")..."
        bash "$test_script" || true
    done

    ok "All tests complete"
}

cmd_test_wsl2() {
    ensure_rust
    ensure_repo
    cd "$LINUX_REPO"

    log "Running WSL2 unit tests..."
    cargo test --lib -p nono -- wsl2 2>&1

    log "Building release binary for integration tests..."
    cargo build --release 2>&1

    log "Running WSL2 integration tests..."
    bash tests/integration/test_wsl2.sh

    ok "WSL2 tests complete"
}

cmd_test_unit() {
    ensure_rust
    ensure_repo
    cd "$LINUX_REPO"
    log "Running unit tests..."
    cargo test 2>&1
    ok "Unit tests complete"
}

cmd_ci() {
    ensure_rust
    ensure_repo
    cd "$LINUX_REPO"
    log "Running full CI check..."
    make ci 2>&1
    ok "CI passed"
}

cmd_shell() {
    ensure_repo
    cd "$LINUX_REPO"
    log "Opening shell in $LINUX_REPO"
    exec bash -l
}

# Source cargo env if available
# shellcheck disable=SC1091
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

case "${1:-default}" in
    setup)      cmd_setup ;;
    sync)       cmd_sync ;;
    build)      cmd_build ;;
    test)       cmd_test ;;
    test-wsl2)  cmd_test_wsl2 ;;
    test-unit)  cmd_test_unit ;;
    ci)         cmd_ci ;;
    shell)      cmd_shell ;;
    default)    cmd_sync && cmd_build && cmd_test_wsl2 ;;
    *)
        echo "Usage: $0 [setup|sync|build|test|test-wsl2|test-unit|ci|shell]"
        echo ""
        echo "  setup       Install Rust and clone repo to ~/nono"
        echo "  sync        Pull latest changes from Windows into ~/nono"
        echo "  build       Build all crates"
        echo "  test        Run all tests"
        echo "  test-wsl2   Run WSL2-specific tests only"
        echo "  test-unit   Run unit tests only"
        echo "  ci          Full CI check (clippy + fmt + tests)"
        echo "  shell       Open a shell in ~/nono"
        echo ""
        echo "  (no args)   sync + build + test-wsl2"
        exit 1
        ;;
esac
