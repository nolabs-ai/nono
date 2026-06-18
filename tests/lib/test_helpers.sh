#!/bin/bash
# nono Integration Test Helpers
# Common functions for all integration tests

set -euo pipefail

# Binary location (can be overridden)
NONO_BIN="${NONO_BIN:-./target/release/nono}"

# Test tracking
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
SANDBOX_PROBE_DONE=0
SANDBOX_AVAILABLE=1
SANDBOX_UNAVAILABLE_REASON=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create a temporary test directory
# Returns the path via stdout
setup_test_dir() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "$tmpdir"
}

# Clean up a test directory
cleanup_test_dir() {
    local dir="$1"
    if [[ -n "$dir" && -d "$dir" ]]; then
        rm -rf "$dir"
    fi
}

# Run a test and check exit code
# Usage: run_test "test name" <expected_exit_code> command args...
run_test() {
    local name="$1"
    local expected="$2"
    shift 2

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    actual=$?
    set -e

    if [[ "$actual" -eq "$expected" ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       Expected exit code: $expected, got: $actual"
        echo "       Command: $*"
        if [[ -n "$output" ]]; then
            local stripped
            stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
            echo "       Output: ${stripped:0:2000}"
        fi
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Run test expecting success (exit 0)
expect_success() {
    local name="$1"
    shift
    run_test "$name" 0 "$@" || true
}

# Run test expecting failure (any non-zero exit)
expect_failure() {
    local name="$1"
    shift

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    actual=$?
    set -e

    if [[ "$actual" -ne 0 ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name (exit $actual)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       Expected failure, but got success (exit 0)"
        echo "       Command: $*"
        if [[ -n "$output" ]]; then
            local stripped
            stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
            echo "       Output: ${stripped:0:2000}"
        fi
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 0
    fi
}

# Check output contains a string
# Usage: expect_output_contains "test name" "expected string" command args...
expect_output_contains() {
    local name="$1"
    local expected_str="$2"
    shift 2

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    exit_code=$?
    set -e

    if echo "$output" | grep -q "$expected_str"; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       Output missing: '$expected_str'"
        echo "       Exit code: $exit_code"
        if [[ -n "$output" ]]; then
            # Strip ANSI escape codes before truncation so they don't eat the budget
            local stripped
            stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
            echo "       Actual output: ${stripped:0:2000}"
        fi
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 0
    fi
}

# Check output does NOT contain a string
expect_output_not_contains() {
    local name="$1"
    local unexpected_str="$2"
    shift 2

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    set -e

    if echo "$output" | grep -q "$unexpected_str"; then
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       Output should NOT contain: '$unexpected_str'"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 0
    else
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

# Skip a test with a message
skip_test() {
    local name="$1"
    local reason="$2"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    echo -e "  ${YELLOW}SKIP${NC}: $name ($reason)"
}

# Check if running on macOS
is_macos() {
    [[ "$(uname)" == "Darwin" ]]
}

# Check if running on Linux
is_linux() {
    [[ "$(uname)" == "Linux" ]]
}

# Skip test unless on macOS
skip_unless_macos() {
    if ! is_macos; then
        skip_test "$1" "macOS only"
        return 1
    fi
    return 0
}

# Skip test unless on Linux
skip_unless_linux() {
    if ! is_linux; then
        skip_test "$1" "Linux only"
        return 1
    fi
    return 0
}

# Check if running inside WSL2 (kernel-controlled indicators only)
is_wsl2() {
    [[ -f /proc/sys/fs/binfmt_misc/WSLInterop ]] || \
        grep -qi 'microsoft\|WSL' /proc/version 2>/dev/null
}

# Skip test unless on WSL2
skip_unless_wsl2() {
    if ! is_wsl2; then
        skip_test "$1" "WSL2 only"
        return 1
    fi
    return 0
}

# Skip test if on WSL2 (for tests that are known-broken under WSL2)
skip_on_wsl2() {
    if is_wsl2; then
        skip_test "$1" "not supported on WSL2"
        return 1
    fi
    return 0
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Skip test if command doesn't exist
require_command() {
    local cmd="$1"
    local test_name="$2"
    if ! command_exists "$cmd"; then
        skip_test "$test_name" "$cmd not installed"
        return 1
    fi
    return 0
}

# Print test summary for a suite
print_summary() {
    echo ""
    echo "  --------------------------------"
    echo "  Tests run:     $TESTS_RUN"
    echo -e "  Passed:        ${GREEN}$TESTS_PASSED${NC}"
    if [[ "$TESTS_FAILED" -gt 0 ]]; then
        echo -e "  Failed:        ${RED}$TESTS_FAILED${NC}"
    else
        echo -e "  Failed:        $TESTS_FAILED"
    fi
    if [[ "$TESTS_SKIPPED" -gt 0 ]]; then
        echo -e "  Skipped:       ${YELLOW}$TESTS_SKIPPED${NC}"
    fi
    echo "  --------------------------------"

    # Return non-zero if any tests failed
    [[ "$TESTS_FAILED" -eq 0 ]]
}

# Reset test counters (useful if running multiple suites in one script)
reset_counters() {
    TESTS_RUN=0
    TESTS_PASSED=0
    TESTS_FAILED=0
    TESTS_SKIPPED=0
}

# Verify nono binary exists
verify_nono_binary() {
    if [[ ! -x "$NONO_BIN" ]]; then
        echo -e "${RED}ERROR${NC}: nono binary not found at $NONO_BIN"
        echo "Run 'cargo build --release' first"
        exit 1
    fi
}

# Detect whether the host can initialize nono's kernel sandbox backend.
# Some CI/hosted environments disallow Seatbelt/Landlock initialization.
probe_sandbox_availability() {
    if [[ "$SANDBOX_PROBE_DONE" -eq 1 ]]; then
        [[ "$SANDBOX_AVAILABLE" -eq 1 ]]
        return
    fi

    SANDBOX_PROBE_DONE=1

    local probe_dir
    probe_dir=$(mktemp -d)

    set +e
    local probe_output
    probe_output=$("$NONO_BIN" run --allow "$probe_dir" -- true </dev/null 2>&1)
    local probe_exit=$?
    set -e

    rm -rf "$probe_dir"

    if [[ "$probe_exit" -eq 0 ]]; then
        SANDBOX_AVAILABLE=1
        return 0
    fi

    if echo "$probe_output" | grep -Eiq "sandbox initialization failed|sandbox init|operation not permitted"; then
        SANDBOX_AVAILABLE=0
        SANDBOX_UNAVAILABLE_REASON="kernel sandbox unavailable in this environment"
        return 1
    fi

    SANDBOX_AVAILABLE=0
    SANDBOX_UNAVAILABLE_REASON="sandbox probe failed unexpectedly (exit $probe_exit)"
    return 1
}

# Skip a sandbox-dependent suite when the host cannot initialize kernel sandboxing.
require_working_sandbox() {
    local suite_name="$1"
    if probe_sandbox_availability; then
        return 0
    fi

    skip_test "$suite_name" "$SANDBOX_UNAVAILABLE_REASON"
    return 1
}

# Get the directory of the current script
get_script_dir() {
    cd "$(dirname "${BASH_SOURCE[1]}")" && pwd
}

# Get project root (two levels up from tests/lib/)
get_project_root() {
    local script_dir
    script_dir=$(get_script_dir)
    cd "$script_dir/../.." && pwd
}
