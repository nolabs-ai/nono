#!/bin/bash
# System Path Protection Tests
# Verifies system directories are readable but not writable

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== System Path Protection Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "system path suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# System Paths Should Be Readable
# =============================================================================

echo "--- System Paths Readable ---"

expect_success "can list /usr/bin (system executables)" \
    "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'ls /usr/bin/ >/dev/null'

expect_success "can execute /bin/echo" \
    "$NONO_BIN" run --allow "$TMPDIR" -- /bin/echo "test"

if [[ -d /usr/lib ]]; then
    expect_success "can list /usr/lib" \
        "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'ls /usr/lib/ >/dev/null'
fi

if [[ -d /etc ]]; then
    expect_success "can read /etc/hosts" \
        "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'cat /etc/hosts >/dev/null'
fi

# =============================================================================
# System Paths Should NOT Be Writable
# =============================================================================

echo ""
echo "--- System Paths NOT Writable ---"

expect_failure "cannot write to /usr/bin" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo hack > /usr/bin/evil-$$"

expect_failure "cannot write to /etc" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo hack > /etc/evil-$$.conf"

expect_failure "cannot write to /usr/lib" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo hack > /usr/lib/evil-$$.so"

# =============================================================================
# macOS Specific System Paths
# =============================================================================

echo ""
echo "--- macOS System Paths ---"

if is_macos; then
    expect_success "can read /System/Library" \
        "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'ls /System/Library/ >/dev/null'

    expect_failure "cannot write to /System/Library" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo x > /System/Library/evil-$$"

    expect_success "can read /Library" \
        "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'ls /Library/ >/dev/null'

    expect_failure "cannot write to /Library" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo x > /Library/evil-$$"

    if [[ -d /Applications ]]; then
        expect_success "can read /Applications" \
            "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'ls /Applications/ >/dev/null'
    fi
else
    skip_test "/System/Library readable" "not macOS"
    skip_test "/System/Library not writable" "not macOS"
    skip_test "/Library readable" "not macOS"
    skip_test "/Library not writable" "not macOS"
fi

# =============================================================================
# Linux Specific System Paths
# =============================================================================

echo ""
echo "--- Linux System Paths ---"

if is_linux; then
    if [[ -d /lib ]]; then
        expect_success "can read /lib" \
            "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'ls /lib/ >/dev/null'

        expect_failure "cannot write to /lib" \
            "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo x > /lib/evil-$$.so"
    fi

    if [[ -d /lib64 ]]; then
        expect_success "can read /lib64" \
            "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'ls /lib64/ >/dev/null'
    fi

    if [[ -d /proc ]]; then
        expect_success "can read /proc/self/status" \
            "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'cat /proc/self/status >/dev/null'

        expect_success "can read /proc/self/maps" \
            "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'cat /proc/self/maps >/dev/null'

        # /proc/1/maps is readable by root and in some privileged CI containers,
        # even inside the sandbox. Skip rather than assert a property that depends
        # on the host privilege level.
        if [[ "$(id -u)" -eq 0 ]] || cat /proc/1/maps >/dev/null 2>&1; then
            skip_test "cannot read foreign /proc/1/maps" "process has access to /proc/1/maps (privileged container or root)"
        else
            expect_failure "cannot read foreign /proc/1/maps" \
                "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'cat /proc/1/maps >/dev/null 2>&1'
        fi

        # Regression test for issue #602: grandchild proc/self access.
        # When bun (or any runtime) is launched via `sh -c`, it is a grandchild
        # (nono→sh→bun). The supervisor must resolve /proc/self using the
        # grandchild's TGID, not the direct child (sh)'s PID.
        if command -v bun >/dev/null 2>&1; then
            BUN_BIN=$(command -v bun)
            BUN_DIR=$(dirname "$BUN_BIN")
            expect_success "grandchild bun can read /proc/self via sh wrapper (issue #602)" \
                "$NONO_BIN" run --allow "$TMPDIR" --read "$BUN_DIR" -- sh -c "$BUN_BIN -e 'process.exit(0)'"
        else
            skip_test "grandchild bun /proc/self access (issue #602)" "bun not installed"
        fi
    fi

    if [[ -d /sys ]]; then
        skip_test "can read /sys" "sysfs not in nono system read grants on Linux"
    fi
else
    skip_test "/lib readable" "not Linux"
    skip_test "/lib not writable" "not Linux"
    skip_test "/proc readable" "not Linux"
fi

# =============================================================================
# Temp Directories Should Be Writable
# =============================================================================

echo ""
echo "--- Temp Directories Writable ---"

# TODO: Re-enable /tmp tests on Linux once Landlock EBADFD issue is resolved
# GitHub Actions Ubuntu 24.04 returns EBADFD (error 77) when adding
# Landlock rules for /tmp directories. This may be related to:
# - Container/namespace interactions with Landlock
# - tmpfs configuration on GitHub Actions runners
# - Kernel version differences
# Works correctly on native Linux systems; issue is specific to CI containers.
if is_linux; then
    skip_test "can write to /tmp" "Landlock EBADFD issue in CI containers"
else
    expect_success "can write to /tmp" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo test > /tmp/nono-test-$$"
    # Cleanup
    rm -f /tmp/nono-test-$$
fi

if is_macos; then
    expect_success "can write to /private/tmp (macOS)" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo test > /private/tmp/nono-test-$$"
    rm -f /private/tmp/nono-test-$$
fi

# Test TMPDIR environment variable path
if [[ -n "${TMPDIR:-}" ]]; then
    # Skip on Linux due to same Landlock EBADFD issue with tmpfs
    if is_linux; then
        skip_test "can write to \$TMPDIR" "Landlock EBADFD issue in CI containers"
    else
        expect_success "can write to \$TMPDIR" \
            "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo test > '$TMPDIR/nono-env-test-$$'"
        rm -f "$TMPDIR/nono-env-test-$$"
    fi
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
