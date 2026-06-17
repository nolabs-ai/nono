#!/bin/bash
# Silent mode regression checks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Silent Output Tests ===${NC}"

verify_nono_binary
if ! skip_unless_linux "silent output suite"; then
    print_summary
    exit 0
fi

expect_output_empty() {
    local name="$1"
    shift

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    exit_code=$?
    set -e

    if [[ "$exit_code" -eq 0 && -z "$output" ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected empty output with exit 0, got exit $exit_code"
    if [[ -n "$output" ]]; then
        local stripped
        stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
        echo "       Actual output: ${stripped:0:2000}"
    fi
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 0
}

# node-dev is an embedded profile that lists `$HOME/Library/pnpm` —
# a macOS-only path that's reliably absent on Linux CI runners and
# gives us a stable "missing-path" warning to assert against under
# `-v`. The previous version used `claude-code` and asserted on a
# macOS Keychain path; that profile now ships as a registry pack so
# the assertion no longer applies in this suite.
# Note: --dry-run prints capability output by default; we assert the
# missing-path warning is suppressed, not that output is empty.
expect_output_not_contains \
    "node-dev dry-run hides missing profile warnings by default" \
    "does not exist, skipping" \
    "$NONO_BIN" run --profile node-dev --allow-cwd --dry-run -- echo ok

# $HOME/Library/pnpm is a macOS-only path in the node_runtime group.
# On macOS, nono warns about it with -v; on Linux it is silently dropped.
if is_macos; then
    expect_output_contains \
        "node-dev dry-run shows missing profile warnings with -v" \
        "Library/pnpm' does not exist, skipping" \
        "$NONO_BIN" run -v --profile node-dev --allow-cwd --dry-run -- echo ok
else
    skip_test "node-dev dry-run shows missing profile warnings with -v" \
        "macOS-only path warning; Linux drops missing paths silently"
fi

expect_output_empty \
    "silent dry-run suppresses tracing warnings and CLI status output" \
    "$NONO_BIN" run --profile node-dev --allow-cwd --silent --dry-run -- echo ok

print_summary
