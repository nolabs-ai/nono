#!/bin/bash
# Edge-case tests for --rollback-dest flag
# Covers: flag validation, precheck logic, path handling, and session placement

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== --rollback-dest Edge Case Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "--rollback-dest edge cases"; then
    print_summary
    exit 0
fi

TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"; rm -rf "$HOME/nono_edge_restricted_$$"' EXIT

mkdir -p "$TMPDIR/workdir"
echo "original" > "$TMPDIR/workdir/file.txt"

echo ""

# =============================================================================
# 1. Flag validation: --rollback-dest requires --rollback
# =============================================================================
echo "--- Flag Validation ---"

expect_failure "--rollback-dest without --rollback is rejected by clap" \
    "$NONO_BIN" run \
    --allow "$TMPDIR/workdir" \
    --rollback-dest "$TMPDIR/custom" -- \
    echo test

# =============================================================================
# 2. Precheck: destination covered by explicit --allow passes
# =============================================================================
echo ""
echo "--- Precheck: Explicit Allow ---"

EXPLICIT_DEST="$TMPDIR/explicit_dest"
mkdir -p "$EXPLICIT_DEST"

expect_success "rollback-dest with explicit --allow passes precheck" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" --allow "$EXPLICIT_DEST" \
    --rollback-dest "$EXPLICIT_DEST" -- \
    sh -c "echo modified > '$TMPDIR/workdir/file.txt'"

run_test "session created inside explicit --allow dest" 0 \
    bash -c "ls '$EXPLICIT_DEST' | grep -qE '[0-9]{8}-[0-9]{6}-[0-9]+'"

# =============================================================================
# 3. Precheck: destination NOT covered by --allow fails
# =============================================================================
echo ""
echo "--- Precheck: No Write Permission ---"

RESTRICTED_DEST="$HOME/nono_edge_restricted_$$"
mkdir -p "$RESTRICTED_DEST"

expect_failure "rollback-dest outside sandbox write caps fails with error" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" \
    --rollback-dest "$RESTRICTED_DEST" -- \
    sh -c "echo modified > '$TMPDIR/workdir/file.txt'"

# Verify the error message is helpful
set +e
err_output=$("$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" \
    --rollback-dest "$RESTRICTED_DEST" -- \
    echo test </dev/null 2>&1)
set -e

if echo "$err_output" | grep -q "rollback-dest"; then
    echo -e "  ${GREEN}PASS${NC}: error message mentions --rollback-dest"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: error message missing --rollback-dest context"
    echo "       Output: $err_output"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$err_output" | grep -q "\-\-allow"; then
    echo -e "  ${GREEN}PASS${NC}: error message suggests --allow fix"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: error message missing --allow suggestion"
    echo "       Output: $err_output"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

rm -rf "$RESTRICTED_DEST"

# =============================================================================
# 4. Nested path: --rollback-dest covered by parent --allow
# =============================================================================
echo ""
echo "--- Nested Path Coverage ---"

PARENT_DEST="$TMPDIR/storage"
NESTED_DEST="$PARENT_DEST/rollbacks/sessions"
mkdir -p "$NESTED_DEST"

expect_success "rollback-dest nested under --allow parent passes precheck" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" --allow "$PARENT_DEST" \
    --rollback-dest "$NESTED_DEST" -- \
    sh -c "echo modified > '$TMPDIR/workdir/file.txt'"

run_test "session created inside nested dest" 0 \
    bash -c "ls '$NESTED_DEST' | grep -qE '[0-9]{8}-[0-9]{6}-[0-9]+'"

# =============================================================================
# 5. Nonexistent destination dir — nono should create it via create_dir_all
# =============================================================================
echo ""
echo "--- Nonexistent Destination ---"

# TMPDIR itself is covered by system_write_macos, so a nested nonexistent
# subdir should resolve via ancestor canonicalization in the precheck.
NONEXISTENT_DEST="$TMPDIR/does/not/exist/yet"
# No mkdir — nono must create the full path via create_dir_all

expect_success "rollback-dest nonexistent path (create_dir_all)" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" \
    --rollback-dest "$NONEXISTENT_DEST" -- \
    sh -c "echo modified > '$TMPDIR/workdir/file.txt'"

run_test "session created under nonexistent dest after creation" 0 \
    bash -c "ls '$NONEXISTENT_DEST' | grep -qE '[0-9]{8}-[0-9]{6}-[0-9]+'"

# =============================================================================
# 6. Session is isolated to custom dest (not written to default rollback root)
# =============================================================================
echo ""
echo "--- Isolation: Custom Dest Does Not Pollute Default ---"

ISOLATED_DEST="$TMPDIR/isolated_rollbacks"
mkdir -p "$ISOLATED_DEST"

# Count sessions in default rollback root before
default_root="${XDG_STATE_HOME:-$HOME/.local/state}/nono/rollbacks"
before_count=$(ls "$default_root" 2>/dev/null | grep -cE '[0-9]{8}-[0-9]{6}-[0-9]+' || true)

expect_success "rollback with --rollback-dest runs successfully" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" --allow "$ISOLATED_DEST" \
    --rollback-dest "$ISOLATED_DEST" -- \
    sh -c "echo custom_dest > '$TMPDIR/workdir/file.txt'"

after_count=$(ls "$default_root" 2>/dev/null | grep -cE '[0-9]{8}-[0-9]{6}-[0-9]+' || true)

if [ "$before_count" -eq "$after_count" ]; then
    echo -e "  ${GREEN}PASS${NC}: default rollback root not polluted"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: unexpected new session in default rollback root"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

isolated_count=$(ls "$ISOLATED_DEST" 2>/dev/null | grep -cE '[0-9]{8}-[0-9]{6}-[0-9]+' || true)
if [ "$isolated_count" -gt 0 ]; then
    echo -e "  ${GREEN}PASS${NC}: session correctly placed in --rollback-dest"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: no session in custom dest"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# =============================================================================
# 7. --rollback-dest is a file (not a dir) — should fail when creating session subdir
# =============================================================================
echo ""
echo "--- Destination Is A File (Not A Dir) ---"

FILE_AS_DEST="$TMPDIR/iam_a_file"
echo "i am not a directory" > "$FILE_AS_DEST"

DEST_PARENT="$TMPDIR"
expect_failure "rollback-dest pointing to a file fails" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" --allow "$DEST_PARENT" \
    --rollback-dest "$FILE_AS_DEST" -- \
    sh -c "echo modified > '$TMPDIR/workdir/file.txt'"

# =============================================================================
# 8. Multiple runs to same dest — sessions accumulate
# =============================================================================
echo ""
echo "--- Multiple Runs Accumulate Sessions ---"

MULTI_DEST="$TMPDIR/multi_rollbacks"
mkdir -p "$MULTI_DEST"

"$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" --allow "$MULTI_DEST" \
    --rollback-dest "$MULTI_DEST" -- \
    sh -c "echo run1 > '$TMPDIR/workdir/file.txt'" </dev/null 2>&1 >/dev/null || true

sleep 1  # ensure different session timestamp

"$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$TMPDIR/workdir" --allow "$MULTI_DEST" \
    --rollback-dest "$MULTI_DEST" -- \
    sh -c "echo run2 > '$TMPDIR/workdir/file.txt'" </dev/null 2>&1 >/dev/null || true

multi_count=$(ls "$MULTI_DEST" 2>/dev/null | grep -cE '[0-9]{8}-[0-9]{6}-[0-9]+' || true)
if [ "$multi_count" -ge 2 ]; then
    echo -e "  ${GREEN}PASS${NC}: multiple sessions accumulate in custom dest ($multi_count sessions)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: expected >=2 sessions, got $multi_count"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# =============================================================================
# 9. Destination same as workdir (edge case: dest and tracked path overlap)
# =============================================================================
echo ""
echo "--- Dest Same As Workdir ---"

OVERLAP_DIR="$TMPDIR/overlap"
mkdir -p "$OVERLAP_DIR"
echo "overlap content" > "$OVERLAP_DIR/file.txt"

# rollback-dest = workdir itself — unusual but should work
expect_success "rollback-dest same as tracked workdir" \
    "$NONO_BIN" run --rollback --no-rollback-prompt \
    --allow "$OVERLAP_DIR" \
    --rollback-dest "$OVERLAP_DIR" -- \
    sh -c "echo modified > '$OVERLAP_DIR/file.txt'"

# =============================================================================
# Summary
# =============================================================================

print_summary
