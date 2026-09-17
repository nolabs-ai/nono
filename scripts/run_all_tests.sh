#!/bin/bash
# nono Integration Test Runner
# Builds nono and runs all integration test suites in parallel

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/tests"

case "${1:-}" in
    "")
        ;;
    --help|-h)
        echo "Usage: $0"
        echo "Runs every tests/integration/test_*.sh suite."
        exit 0
        ;;
    *)
        echo "Unknown option: $1" >&2
        echo "Usage: $0" >&2
        exit 2
        ;;
esac

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}nono integration tests${NC}"
echo ""

# Build

echo -e "${BLUE}Building nono with test trust overrides enabled...${NC}"
cd "$PROJECT_ROOT"

if ! cargo build --release -p nono-cli --features test-trust-overrides 2>&1; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
RELEASE_DIR="$TARGET_DIR/release"

export NONO_BIN="$RELEASE_DIR/nono"
export PATH="$RELEASE_DIR:$PATH"

# Verify binary exists
if [[ ! -x "$NONO_BIN" ]]; then
    echo -e "${RED}ERROR: nono binary not found at $NONO_BIN${NC}"
    exit 1
fi

echo ""
echo -e "Binary: ${GREEN}$NONO_BIN${NC}"
echo -e "Version: $("$NONO_BIN" --version 2>/dev/null || echo 'unknown')"
echo -e "Platform: $(uname -s) $(uname -m)"
echo ""

# Make test scripts executable
chmod +x "$TESTS_DIR"/integration/*.sh 2>/dev/null || true
chmod +x "$TESTS_DIR"/lib/*.sh 2>/dev/null || true

# Run Test Suites in Parallel (with concurrency limit)

# Temp directory for suite output files
RESULTS_DIR=$(mktemp -d)
TEST_ENV_DIR=$(mktemp -d)
# Keep XDG state outside /tmp and HOME. The Linux system_write policy grants
# /tmp, while the bypass-protection suite intentionally grants paths below
# HOME; either location would overlap nono's protected state root. /var/tmp is
# writable but is not part of either capability surface. Override when needed.
TEST_XDG_PARENT="${NONO_TEST_XDG_PARENT:-/var/tmp}"
mkdir -p "$TEST_XDG_PARENT"
TEST_XDG_DIR=$(mktemp -d "$TEST_XDG_PARENT/nono-integration.XXXXXX")

export NONO_NO_UPDATE_CHECK=1
# Suppress the migration prompt (--profile <pack-name> when the pack
# isn't installed) and the "save denied paths as user profile?"
# prompt. Both can fire mid-suite — the migration prompt for any
# `--profile` referencing a registry pack, the save prompt on any
# command that hits a denial. Neither is answerable in CI.
export NONO_NO_MIGRATE=1
export NONO_NO_SAVE_PROMPT=1

# Each suite receives an isolated XDG_STATE_HOME outside /tmp, so audit
# sessions, rollback snapshots, and ledgers never touch the caller's state.
trap 'rm -rf "$RESULTS_DIR" "$TEST_ENV_DIR" "$TEST_XDG_DIR"' EXIT

# All suites to run (script:name pairs)
# Discover every shell suite so newly added suites cannot be omitted from CI.
SUITES=()
for suite_path in "$TESTS_DIR"/integration/test_*.sh; do
    suite_script=$(basename "$suite_path")
    suite_name="${suite_script#test_}"
    suite_name="${suite_name%.sh}"
    suite_name="${suite_name//_/ }"
    SUITES+=("$suite_script:$suite_name")
done

TOTAL_SUITES=${#SUITES[@]}
SUITE_NAMES=()
SUITE_OUTPUT_FILES=()
SUITE_EXIT_FILES=()

# Per-suite timeout in seconds (catches hangs)
SUITE_TIMEOUT=120

# Max parallel suites. Override with NONO_TEST_JOBS=N.
# Default: nproc on Linux, sysctl on macOS, fallback 4.
if [[ -n "${NONO_TEST_JOBS:-}" ]]; then
    MAX_JOBS="$NONO_TEST_JOBS"
elif command -v nproc >/dev/null 2>&1; then
    MAX_JOBS=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
    MAX_JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
else
    MAX_JOBS=4
fi

echo -e "${BLUE}Running $TOTAL_SUITES test suites ($MAX_JOBS parallel)...${NC}"
echo ""

# Launch a suite in the background, writing output + exit code to files
launch_suite() {
    local script="$1"
    local output_file="$2"
    local exit_file="${output_file%.out}.exit"
    local suite_id="${script%.sh}"
    local suite_env_dir="$TEST_XDG_DIR/suites/$suite_id"

    # Suites run in parallel and must not share mutable XDG state. In
    # particular, rollback and audit suites otherwise race on the default
    # rollback root and audit ledger. Keep HOME intact: sensitive-path suites
    # intentionally exercise the caller's real protected paths.
    mkdir -p \
        "$suite_env_dir/config" \
        "$suite_env_dir/state" \
        "$suite_env_dir/cache" \
        "$suite_env_dir/data" \
        "$suite_env_dir/trust-config" \
        "$suite_env_dir/trust-keystore"

    if command -v timeout >/dev/null 2>&1; then
        env \
            XDG_CONFIG_HOME="$suite_env_dir/config" \
            XDG_STATE_HOME="$suite_env_dir/state" \
            XDG_CACHE_HOME="$suite_env_dir/cache" \
            XDG_DATA_HOME="$suite_env_dir/data" \
            NONO_TRUST_TEST_USER_POLICY_PATH="$suite_env_dir/trust-config/trust-policy.json" \
            NONO_TRUST_TEST_KEYSTORE_DIR="$suite_env_dir/trust-keystore" \
            timeout "$SUITE_TIMEOUT" bash "$TESTS_DIR/integration/$script" > "$output_file" 2>&1
        rc=$?
        if [[ "$rc" -eq 124 ]]; then
            echo "" >> "$output_file"
            echo "SUITE TIMED OUT after ${SUITE_TIMEOUT}s" >> "$output_file"
        fi
        echo "$rc" > "$exit_file"
    else
        env \
            XDG_CONFIG_HOME="$suite_env_dir/config" \
            XDG_STATE_HOME="$suite_env_dir/state" \
            XDG_CACHE_HOME="$suite_env_dir/cache" \
            XDG_DATA_HOME="$suite_env_dir/data" \
            NONO_TRUST_TEST_USER_POLICY_PATH="$suite_env_dir/trust-config/trust-policy.json" \
            NONO_TRUST_TEST_KEYSTORE_DIR="$suite_env_dir/trust-keystore" \
            bash "$TESTS_DIR/integration/$script" > "$output_file" 2>&1; rc=$?
        echo "$rc" > "$exit_file"
    fi
}

PIDS=()

for entry in "${SUITES[@]}"; do
    script="${entry%%:*}"
    name="${entry#*:}"

    output_file="$RESULTS_DIR/${script%.sh}.out"
    exit_file="$RESULTS_DIR/${script%.sh}.exit"

    SUITE_NAMES+=("$name")
    SUITE_OUTPUT_FILES+=("$output_file")
    SUITE_EXIT_FILES+=("$exit_file")

    # Wait for a slot if we're at the concurrency limit
    while [[ ${#PIDS[@]} -ge $MAX_JOBS ]]; do
        # Wait for any one PID to finish, then compact the array
        NEW_PIDS=()
        for pid in "${PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                NEW_PIDS+=("$pid")
            else
                wait "$pid" 2>/dev/null || true
            fi
        done
        if [[ ${#NEW_PIDS[@]} -gt 0 ]]; then
            PIDS=("${NEW_PIDS[@]}")
        else
            PIDS=()
        fi
        if [[ ${#PIDS[@]} -ge $MAX_JOBS ]]; then
            sleep 0.2
        fi
    done

    launch_suite "$script" "$output_file" &
    PIDS+=($!)
done

# Wait for remaining suites to finish
for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

# Print Results in Order

PASSED_SUITES=0
FAILED_SUITES=0
FAILED_NAMES=""

for i in "${!SUITE_NAMES[@]}"; do
    name="${SUITE_NAMES[$i]}"
    output_file="${SUITE_OUTPUT_FILES[$i]}"
    exit_file="${SUITE_EXIT_FILES[$i]}"

    exit_code=1
    if [[ -f "$exit_file" ]]; then
        exit_code=$(cat "$exit_file")
    fi

    echo ""
    echo -e "${BOLD}Suite: $name${NC}"
    echo "----------------------------------------"
    cat "$output_file"

    if [[ "$exit_code" -eq 0 ]]; then
        echo -e "${GREEN}Suite PASSED${NC}: $name"
        PASSED_SUITES=$((PASSED_SUITES + 1))
    else
        echo -e "${RED}Suite FAILED${NC}: $name"
        FAILED_SUITES=$((FAILED_SUITES + 1))
        FAILED_NAMES="$FAILED_NAMES  - $name\n"
    fi
done

# Final Summary

echo -e "${BOLD}Test summary${NC}"
echo ""
echo "Test suites run: $TOTAL_SUITES"
echo -e "Suites passed:   ${GREEN}$PASSED_SUITES${NC}"

if [[ "$FAILED_SUITES" -gt 0 ]]; then
    echo -e "Suites failed:   ${RED}$FAILED_SUITES${NC}"
    echo ""
    echo -e "Failed suites:"
    echo -e "$FAILED_NAMES"
else
    echo -e "Suites failed:   $FAILED_SUITES"
fi

echo ""

if [[ "$FAILED_SUITES" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}Some tests failed.${NC}"
    exit 1
fi
