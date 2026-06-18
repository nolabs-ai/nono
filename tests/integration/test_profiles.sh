#!/bin/bash
# Profile machinery tests
#
# Verifies built-in profiles load, produce correct dry-run output, and
# enforce expected policies. These tests cover the *machinery* — profile
# loading, dry-run rendering, --workdir / --allow-cwd composition, basic
# sandbox enforcement — not the *content* of any specific pack.
#
# Specific pack behaviour (e.g. "the always-further/codex pack allows
# cargo") is intentionally NOT tested here, because pack content is
# published independently of the nono CLI release. Those tests live in
# the pack repos' own CI.
#
# For the pack-store resolver path (used by the migration / pull flow),
# see test_pack_resolution.sh.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Profile Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "profiles suite"; then
    print_summary
    exit 0
fi
NONO_BIN_ABS="$(cd "$(dirname "$NONO_BIN")" && pwd)/$(basename "$NONO_BIN")"

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/workdir"
echo "readable content" > "$TMPDIR/workdir/file.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# Profile Dry Run
# =============================================================================

echo "--- Profile Dry Run ---"

expect_success "default profile dry-run exits 0" \
    "$NONO_BIN" run --profile default --dry-run -- echo "test"

expect_success "node-dev profile dry-run exits 0" \
    "$NONO_BIN" run --profile node-dev --dry-run -- echo "test"

expect_failure "nonexistent profile exits non-zero" \
    "$NONO_BIN" run --profile nonexistent-profile --dry-run -- echo "test"

expect_output_contains "dry-run output shows Capabilities section" "Capabilities:" \
    "$NONO_BIN" run --profile default --dry-run -- echo "test"

# node-dev pulls the `node_runtime` capability group (paths like
# ~/.npm, ~/.nvm). Those live inside the collapsed system/group
# block in the default dry-run output and only show with -v.
# On Linux CI runners ~/.npm may not exist; use /usr/local/lib/node_modules
# (present when node is installed) as the assertion anchor instead.
if is_linux && [[ -d /usr/local/lib/node_modules ]]; then
    expect_output_contains "node-dev profile lists Node runtime paths in dry-run -v" "node_modules" \
        "$NONO_BIN" run -v --profile node-dev --dry-run -- echo "test"
elif is_linux; then
    skip_test "node-dev profile lists Node runtime paths in dry-run -v" "no node_runtime paths present on this runner"
else
    expect_output_contains "node-dev profile lists Node runtime paths in dry-run -v" ".npm" \
        "$NONO_BIN" run -v --profile node-dev --dry-run -- echo "test"
fi

# =============================================================================
# Profile Enforcement
# =============================================================================

echo ""
echo "--- Profile Enforcement ---"

# default profile blocks rm of files outside the granted area.
# Even with --allow on the parent dir, default doesn't grant
# unrestricted write semantics; rm should still fail because the
# profile's network/syscall policy and the absence of broader grants
# blocks destructive operations on most paths.
expect_failure "default profile blocks rm outside granted area" \
    "$NONO_BIN" run --profile default -- rm "$TMPDIR/workdir/file.txt"

# Verify file still exists
run_test "file not deleted (rm was blocked by profile)" 0 test -f "$TMPDIR/workdir/file.txt"

# default profile + --allow grants the path: cat should succeed
expect_success "default profile allows cat on granted path" \
    "$NONO_BIN" run --profile default --allow "$TMPDIR" -- cat "$TMPDIR/workdir/file.txt"

# pip / cargo specific tests intentionally removed: those used to
# verify that the codex pack's profile composition allowed common
# language tooling paths. Pack-specific allow-list assertions belong
# in the pack repo's CI now (see nono-packs/.github/workflows/).

# =============================================================================
# Profile with Workdir
# =============================================================================

echo ""
echo "--- Profile with Workdir ---"

expect_success "profile with --workdir flag accepted" \
    "$NONO_BIN" run --profile default --workdir "$TMPDIR/workdir" --dry-run -- echo "workdir test"

# With --allow-cwd and --workdir, the workdir should be accessible
expect_success "profile with --workdir and --allow-cwd accepted" \
    "$NONO_BIN" run --profile default --workdir "$TMPDIR/workdir" --allow-cwd --dry-run -- echo "workdir test"

# =============================================================================
# Summary
# =============================================================================

print_summary
