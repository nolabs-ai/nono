#!/bin/bash
# Learn Mode Tests (Linux only)
# Tests nono learn strace-based path discovery

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Learn Mode Tests ===${NC}"

verify_nono_binary

# Learn mode is Linux only (uses strace)
if ! is_linux; then
    skip_test "learn mode suite" "Linux only (requires strace)"
    print_summary
    exit 0
fi

if ! command_exists strace; then
    skip_test "learn mode suite" "strace not installed"
    print_summary
    exit 0
fi

echo ""

# =============================================================================
# Learn Mode
# =============================================================================

echo "--- Learn Mode ---"

# nono learn has an interactive confirmation prompt. Pipe "y" to accept it.
# The test helpers redirect stdin from /dev/null, so we wrap in sh -c with echo.

if [[ -f /etc/hostname ]]; then
    expect_output_contains "learn traces cat /etc/hostname" "/etc/hostname" \
        sh -c "echo y | '$NONO_BIN' learn -- cat /etc/hostname"
else
    expect_output_contains "learn traces cat /etc/os-release" "/etc/os-release" \
        sh -c "echo y | '$NONO_BIN' learn -- cat /etc/os-release"
fi

# JSON output
expect_output_contains "learn --json produces JSON output" "{" \
    sh -c "echo y | '$NONO_BIN' learn --json -- true"

# =============================================================================
# Summary
# =============================================================================

print_summary
