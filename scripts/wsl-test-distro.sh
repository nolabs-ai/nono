#!/bin/bash
# wsl-test-distro.sh — Bootstrap and test nono on a WSL2 distro
#
# Usage (from Windows terminal):
#   wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/path/to/nono/scripts/wsl-test-distro.sh
#   wsl.exe -d Debian       -- bash /mnt/c/path/to/nono/scripts/wsl-test-distro.sh
#   wsl.exe -d Arch         -- bash /mnt/c/path/to/nono/scripts/wsl-test-distro.sh
#
# Or from inside a WSL2 distro:
#   bash /mnt/c/path/to/nono/scripts/wsl-test-distro.sh
#
# What it does:
#   1. Detects the package manager and installs build dependencies
#   2. Installs Rust if missing
#   3. Clones the repo to ~/nono (or syncs if already cloned)
#   4. Builds release binary
#   5. Runs unit tests, integration tests, and clippy
#   6. Prints a summary

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Auto-detect Windows repo from this script's location
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIN_REPO="${NONO_WIN_REPO:-$(dirname "$_SCRIPT_DIR")}"
LINUX_REPO="${NONO_LINUX_REPO:-$HOME/nono}"

log() { echo -e "${BLUE}==>${NC} $*"; }
ok()  { echo -e "${GREEN}==>${NC} $*"; }
err() { echo -e "${RED}==>${NC} $*" >&2; }
warn() { echo -e "${YELLOW}==>${NC} $*"; }

DISTRO_NAME="unknown"
DISTRO_VERSION="unknown"
KERNEL_VERSION=$(uname -r)
RESULTS=()

record() {
    local name="$1" status="$2"
    RESULTS+=("$status|$name")
}

# =========================================================================
# 1. Detect distro
# =========================================================================

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        DISTRO_NAME="${ID:-unknown}"
        DISTRO_VERSION="${VERSION_ID:-unknown}"
    elif [[ -f /etc/alpine-release ]]; then
        DISTRO_NAME="alpine"
        DISTRO_VERSION=$(cat /etc/alpine-release)
    fi
    log "Distro: $DISTRO_NAME $DISTRO_VERSION (kernel: $KERNEL_VERSION)"
}

# =========================================================================
# 2. Install dependencies
# =========================================================================

install_deps() {
    log "Installing build dependencies..."

    case "$DISTRO_NAME" in
        ubuntu|debian|linuxmint|pop)
            sudo apt-get update -qq
            sudo apt-get install -y --no-install-recommends \
                build-essential pkg-config curl git ca-certificates rsync netcat-openbsd

            # Ubuntu 20.04 ships GCC 9 which triggers aws-lc-sys bug
            gcc_ver=$(gcc -dumpversion 2>/dev/null || echo "0")
            if [[ "${gcc_ver%%.*}" -lt 10 ]]; then
                warn "GCC $gcc_ver is too old, installing gcc-10..."
                sudo apt-get install -y gcc-10 g++-10
                sudo ln -sf gcc-10 /usr/bin/gcc
                sudo ln -sf g++-10 /usr/bin/g++
                sudo ln -sf gcc-10 /usr/bin/cc
            fi
            ;;
        fedora)
            sudo dnf install -y gcc gcc-c++ pkgconfig curl git rsync nmap-ncat
            ;;
        arch|archlinux|manjaro)
            sudo pacman -Sy --noconfirm base-devel pkgconf curl git rsync openbsd-netcat
            ;;
        alpine)
            sudo apk add --no-cache build-base pkgconf curl git rsync
            ;;
        opensuse*|suse*)
            sudo zypper install -y gcc gcc-c++ pkg-config curl git rsync netcat-openbsd
            ;;
        *)
            warn "Unknown distro '$DISTRO_NAME' — skipping dependency install"
            warn "Ensure build-essential, pkg-config, curl, git are installed"
            ;;
    esac

    ok "Dependencies installed"
}

# =========================================================================
# 3. Install Rust
# =========================================================================

install_rust() {
    # shellcheck disable=SC1091
    [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

    if cargo --version &>/dev/null; then
        ok "Rust already installed: $(cargo --version)"
        return
    fi

    log "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"

    if ! cargo --version &>/dev/null; then
        err "Rust installation failed — check output above"
        exit 1
    fi
    ok "Rust installed: $(cargo --version)"
}

# =========================================================================
# 4. Clone or sync repo
# =========================================================================

sync_repo() {
    mkdir -p "$LINUX_REPO"
    cd "$LINUX_REPO"

    # rsync the entire Windows working tree (committed + uncommitted).
    # No git clone — rsync is the single source of truth.
    log "Syncing from Windows working tree..."
    rsync -a --delete \
        --exclude '.git/' \
        --exclude 'target/' \
        --exclude 'node_modules/' \
        "$WIN_REPO/" "$LINUX_REPO/"

    # Fix Windows CRLF line endings on all source files
    find "$LINUX_REPO" \( -name '*.sh' -o -name '*.rs' -o -name '*.toml' -o -name '*.json' -o -name '*.md' -o -name '*.mdx' \) \
        -not -path '*/target/*' -exec sed -i 's/\r$//' {} + 2>/dev/null || true
    ok "Repo ready at $LINUX_REPO"
}

# =========================================================================
# 5. Build
# =========================================================================

build() {
    cd "$LINUX_REPO"
    log "Building (release)..."
    if cargo build --release 2>&1; then
        record "Release build" "PASS"
        ok "Build succeeded"
    else
        record "Release build" "FAIL"
        err "Build failed"
        return 1
    fi
}

# =========================================================================
# 6. Run tests
# =========================================================================

run_tests() {
    cd "$LINUX_REPO"

    # WSL2 detection
    log "Checking WSL2 detection..."
    if [[ -f /proc/sys/fs/binfmt_misc/WSLInterop ]] || grep -qi 'microsoft\|WSL' /proc/version 2>/dev/null; then
        record "WSL2 detection (shell)" "PASS"
        ok "WSL2 detected"
    else
        record "WSL2 detection (shell)" "FAIL"
        err "WSL2 not detected — tests may behave differently"
    fi

    # Unit tests
    log "Running WSL2 unit tests..."
    if cargo test --lib -p nono -- wsl2 2>&1; then
        record "Unit tests (wsl2)" "PASS"
    else
        record "Unit tests (wsl2)" "FAIL"
    fi

    # Full unit tests
    log "Running all unit tests..."
    if cargo test 2>&1; then
        record "Unit tests (all)" "PASS"
    else
        record "Unit tests (all)" "FAIL"
    fi

    # Clippy
    log "Running clippy..."
    if cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::unwrap_used 2>&1; then
        record "Clippy" "PASS"
    else
        record "Clippy" "FAIL"
    fi

    # Format check
    log "Checking formatting..."
    if cargo fmt --all -- --check 2>&1; then
        record "Rustfmt" "PASS"
    else
        record "Rustfmt" "FAIL"
    fi

    # WSL2 integration tests
    log "Running WSL2 integration tests..."
    if bash tests/integration/test_wsl2.sh 2>&1; then
        record "Integration tests (wsl2)" "PASS"
    else
        record "Integration tests (wsl2)" "FAIL"
    fi

    # Setup check
    log "Running setup --check-only..."
    local setup_output
    setup_output=$(./target/release/nono setup --check-only 2>&1)
    echo "$setup_output"
    if echo "$setup_output" | grep -q "WSL2"; then
        record "Setup reports WSL2" "PASS"
    else
        record "Setup reports WSL2" "FAIL"
    fi

    # Capability elevation guard
    log "Testing capability elevation guard..."
    local elev_output
    elev_output=$(./target/release/nono run --capability-elevation --allow /tmp -- echo "ok" </dev/null 2>&1)
    echo "$elev_output"
    if echo "$elev_output" | grep -q "WSL2"; then
        record "Capability elevation guard" "PASS"
    else
        record "Capability elevation guard" "FAIL"
    fi

    # Proxy fail-secure
    log "Testing proxy fail-secure default..."
    local proxy_output
    set +e
    proxy_output=$(./target/release/nono run --credential github --allow /tmp -- echo "should fail" </dev/null 2>&1)
    local proxy_exit=$?
    set -e
    if [[ "$proxy_exit" -ne 0 ]] && echo "$proxy_output" | grep -q "proxy-only network mode cannot be kernel-enforced"; then
        record "Proxy fail-secure default" "PASS"
    else
        record "Proxy fail-secure default" "FAIL"
        echo "$proxy_output" | head -10
    fi
}

# =========================================================================
# 7. Summary
# =========================================================================

print_summary() {
    local pass=0 fail=0

    echo ""
    echo "============================================"
    echo "  TEST RESULTS: $DISTRO_NAME $DISTRO_VERSION"
    echo "  Kernel: $KERNEL_VERSION"
    echo "  Rust: $(cargo --version 2>/dev/null || echo 'N/A')"
    echo "  GCC: $(gcc --version 2>/dev/null | head -1 || echo 'N/A')"
    echo "============================================"

    for result in "${RESULTS[@]}"; do
        local status="${result%%|*}"
        local name="${result#*|}"
        if [[ "$status" == "PASS" ]]; then
            echo -e "  ${GREEN}PASS${NC}  $name"
            pass=$((pass + 1))
        else
            echo -e "  ${RED}FAIL${NC}  $name"
            fail=$((fail + 1))
        fi
    done

    echo "============================================"
    echo -e "  Passed: ${GREEN}$pass${NC}  Failed: ${RED}$fail${NC}"
    echo "============================================"
    echo ""

    [[ "$fail" -eq 0 ]]
}

# =========================================================================
# Main
# =========================================================================

# shellcheck disable=SC1091
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

detect_distro
install_deps
install_rust
sync_repo
build
run_tests
print_summary
