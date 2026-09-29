#!/bin/bash
# shellcheck disable=SC2088 # User-facing test descriptions intentionally use ~ notation.
# Execution Strategy Tests
# Tests Supervised (default), Direct (nono wrap), signal forwarding, and diagnostic footer

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}Execution Strategy Tests${NC}"

verify_nono_binary
if ! require_working_sandbox "exec strategy suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo ""
echo "Test directory: $TMPDIR"
echo ""

# Supervised Mode (default)

echo "Supervised Mode (default)"

expect_success "default mode runs command successfully" \
    "$NONO_BIN" run --allow "$TMPDIR" -- echo "supervised mode works"

expect_output_contains "default mode output contains command output" "supervised mode works" \
    "$NONO_BIN" run --allow "$TMPDIR" -- echo "supervised mode works"

# Exit code preservation
run_test "default mode preserves exit code 0" 0 \
    "$NONO_BIN" run --allow "$TMPDIR" -- true

run_test "default mode preserves exit code 1" 1 \
    "$NONO_BIN" run --allow "$TMPDIR" -- false

run_test "default mode preserves exit code 42" 42 \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "exit 42"

expect_output_contains "default mode preserves ENOENT for missing absolute paths" "No such file or directory" \
    "$NONO_BIN" run --allow "$TMPDIR" -- cat /definitely-missing-nono-regression-path

expect_output_not_contains "missing absolute path is not reported as supervisor denial" "Denied paths during this session" \
    "$NONO_BIN" run --allow "$TMPDIR" -- cat /definitely-missing-nono-regression-path

# Direct Mode (nono wrap)

echo ""
echo "Direct Mode (nono wrap)"

expect_success "direct mode runs command successfully" \
    "$NONO_BIN" wrap --allow "$TMPDIR" -- echo "direct mode works"

expect_output_contains "direct mode output contains command output" "direct mode works" \
    "$NONO_BIN" wrap --allow "$TMPDIR" -- echo "direct mode works"

run_test "direct mode preserves exit code 0" 0 \
    "$NONO_BIN" wrap --allow "$TMPDIR" -- true

run_test "direct mode preserves exit code 1" 1 \
    "$NONO_BIN" wrap --allow "$TMPDIR" -- false

# Signal Forwarding

echo ""
echo "Signal Forwarding"

# Test SIGTERM forwarding: supervised mode (default) keeps an unsandboxed parent
# that can forward signals to the sandboxed child.
TESTS_RUN=$((TESTS_RUN + 1))

SIGNAL_RESULT=$(
    "$NONO_BIN" run --allow "$TMPDIR" -- sleep 60 </dev/null >/dev/null 2>&1 &
    NONO_PID=$!
    sleep 1

    if ! kill -0 "$NONO_PID" 2>/dev/null; then
        echo "SKIP"
        exit 0
    fi

    kill -TERM "$NONO_PID" 2>/dev/null

    WAIT_COUNT=0
    while kill -0 "$NONO_PID" 2>/dev/null && [[ "$WAIT_COUNT" -lt 10 ]]; do
        sleep 0.5
        WAIT_COUNT=$((WAIT_COUNT + 1))
    done

    if kill -0 "$NONO_PID" 2>/dev/null; then
        kill -9 "$NONO_PID" 2>/dev/null
        wait "$NONO_PID" 2>/dev/null || true
        echo "FAIL"
    else
        wait "$NONO_PID" 2>/dev/null || true
        echo "PASS"
    fi
) || true

case "$SIGNAL_RESULT" in
    PASS)
        echo -e "  ${GREEN}PASS${NC}: SIGTERM forwarded to child (nono exited after signal)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        ;;
    FAIL)
        echo -e "  ${RED}FAIL${NC}: SIGTERM forwarded to child (nono did not exit)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        ;;
    *)
        echo -e "  ${YELLOW}SKIP${NC}: SIGTERM forwarded to child (nono exited before signal could be sent)"
        TESTS_RUN=$((TESTS_RUN - 1))
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        ;;
esac

# Diagnostic Footer

echo ""
echo "Diagnostic Footer"

# Attempt to read a sensitive path to trigger a sandbox denial
# The diagnostic footer should mention the denied path or nono
if [[ -d ~/.ssh ]]; then
    TESTS_RUN=$((TESTS_RUN + 1))
    set +e
    diag_output=$("$NONO_BIN" run --allow "$TMPDIR" -- cat ~/.ssh/id_rsa </dev/null 2>&1)
    diag_exit=$?
    set -e

    if [[ "$diag_exit" -ne 0 ]]; then
        # Check for diagnostic output (either "Operation not permitted", "Permission denied", or "nono")
        if echo "$diag_output" | grep -qiE "denied|not permitted|nono"; then
            echo -e "  ${GREEN}PASS${NC}: sandbox denial produces diagnostic output"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "  ${RED}FAIL${NC}: sandbox denial produces diagnostic output"
            echo "       Expected diagnostic output but got: ${diag_output:0:500}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo -e "  ${RED}FAIL${NC}: sandbox denial produces diagnostic output"
        echo "       Expected non-zero exit but got 0"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    skip_test "sandbox denial produces diagnostic output" "~/.ssh not found"
fi

# --no-diagnostics flag suppresses the diagnostic footer (use --silent to also suppress banner)
if [[ -d ~/.ssh ]]; then
    expect_output_not_contains "no-diagnostics suppresses footer" "To grant additional access" \
        "$NONO_BIN" run --silent --no-diagnostics --allow "$TMPDIR" -- cat ~/.ssh/id_rsa
else
    skip_test "no-diagnostics suppresses footer" "~/.ssh not found"
fi

# Summary

print_summary
