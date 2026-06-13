#!/bin/bash
# Rollback/Undo System Tests
# Tests the rollback lifecycle: session creation, listing, showing, verifying

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Rollback Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "rollback suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/workdir"
echo "original content" > "$TMPDIR/workdir/file.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# Rollback List (baseline)
# =============================================================================

echo "--- Rollback List ---"

# rollback list should work (may have existing sessions from prior runs)
expect_success "rollback list exits 0" \
    "$NONO_BIN" rollback list

# =============================================================================
# Rollback Session Creation
# =============================================================================

echo ""
echo "--- Rollback Session Creation ---"

# Run a command with --rollback that modifies a file
expect_success "rollback session with file modification" \
    "$NONO_BIN" run --rollback --no-rollback-prompt --allow "$TMPDIR/workdir" -- \
    sh -c "echo 'modified content' > '$TMPDIR/workdir/file.txt'"

# Run a command with --rollback that creates a new file
expect_success "rollback session with file creation" \
    "$NONO_BIN" run --rollback --no-rollback-prompt --allow "$TMPDIR/workdir" -- \
    sh -c "echo 'new file' > '$TMPDIR/workdir/new.txt'"

# =============================================================================
# Rollback List (after sessions)
# =============================================================================

echo ""
echo "--- Rollback List After Sessions ---"

# List should still work and show sessions
expect_success "rollback list after sessions exits 0" \
    "$NONO_BIN" rollback list

# List output should contain our workdir path
expect_output_contains "rollback list shows workdir" "workdir" \
    "$NONO_BIN" rollback list

# =============================================================================
# Rollback Show
# =============================================================================

echo ""
echo "--- Rollback Show ---"

# Get the most recent session ID from rollback list
set +e
session_list=$("$NONO_BIN" rollback list </dev/null 2>&1)
set -e

# Extract a session ID. Current supervised runs use random 16-hex session IDs;
# older standalone rollback entries used YYYYMMDD-HHMMSS-PID.
session_id=$(echo "$session_list" | grep -oE '[0-9]{8}-[0-9]{6}-[0-9]+|[0-9a-f]{16}' | head -1)

if [[ -n "$session_id" ]]; then
    expect_success "rollback show session succeeds" \
        "$NONO_BIN" rollback show "$session_id"
else
    skip_test "rollback show session succeeds" "no session ID found in list output"
fi

# =============================================================================
# Rollback Verify
# =============================================================================

echo ""
echo "--- Rollback Verify ---"

if [[ -n "$session_id" ]]; then
    expect_success "rollback verify session succeeds" \
        "$NONO_BIN" rollback verify "$session_id"
else
    skip_test "rollback verify session succeeds" "no session ID found in list output"
fi

# =============================================================================
# Rollback Custom Destination (--rollback-dest)
# =============================================================================

echo ""
echo "--- Rollback Custom Destination ---"

CUSTOM_DEST="$TMPDIR/custom_rollbacks"
mkdir -p "$CUSTOM_DEST"

# --rollback-dest should store the session under the custom directory
expect_success "rollback-dest creates session in custom dir" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" --allow "$CUSTOM_DEST" \
    --rollback-dest "$CUSTOM_DEST" -- \
    sh -c "echo 'custom dest test' > '$TMPDIR/workdir/file.txt'"

# Verify a session directory was created under the custom destination
run_test "session directory created under --rollback-dest" 0 \
    bash -c "ls '$CUSTOM_DEST' | grep -qE '[0-9]{8}-[0-9]{6}-[0-9]+|[0-9a-f]{16}'"

# --rollback-dest without write permission should fail.
# We use a path under $HOME that is not covered by any system write group.
RESTRICTED_DEST="$HOME/nono_rollback_restricted_test_$$"
mkdir -p "$RESTRICTED_DEST"
trap 'cleanup_test_dir "$TMPDIR"; rm -rf "$RESTRICTED_DEST"' EXIT
expect_failure "rollback-dest without sandbox write permission fails" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" \
    --rollback-dest "$RESTRICTED_DEST" -- \
    sh -c "echo 'should fail' > '$TMPDIR/workdir/file.txt'"
rm -rf "$RESTRICTED_DEST"

# =============================================================================
# Summary
# =============================================================================

print_summary
