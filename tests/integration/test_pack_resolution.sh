#!/bin/bash
# Pack-store profile resolver tests
#
# Hand-installs the synthetic test pack from tests/fixtures/synthetic-pack
# into the local pack store, then verifies:
#
#   - `--profile <namespace>/<package>` resolves through the pack-store
#     branch of load_profile (the same branch the pull/migration flow uses).
#   - A bare profile name never selects an installed package.
#   - Sandbox enforcement honours the same pack-shipped profile contents.
#   - Cleanup removes the pack-store entry without leaving lockfile state.
#
# Why hand-install rather than `nono pull`: pull goes through Sigstore
# verification against a real registry. Mocking that for integration
# tests is more machinery than the resolver test warrants. The pull /
# verification / wiring pipeline is covered by:
#   - wiring.rs unit tests (15+ cases)
#   - migration.rs unit tests
#   - end-to-end smoke tests in nono-packs CI
#
# This suite is specifically about: when a pack IS installed, does
# `--profile <namespace>/<package>` find it through the user-facing CLI. Real execution
# verifies pack lockfile and Sigstore metadata, so enforcement below uses
# the exact fixture profile file by path rather than treating the
# hand-installed fixture as a trusted registry install.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Pack Resolution Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "pack resolution suite"; then
    print_summary
    exit 0
fi
NONO_BIN_ABS="$(cd "$(dirname "$NONO_BIN")" && pwd)/$(basename "$NONO_BIN")"

FIXTURE_DIR="$(cd "$SCRIPT_DIR/../fixtures/synthetic-pack" && pwd)"
if [[ ! -f "$FIXTURE_DIR/package.json" ]]; then
    echo "FAIL: synthetic-pack fixture missing at $FIXTURE_DIR"
    exit 1
fi

# Use a per-run XDG_CONFIG_HOME so the test pack-store install never
# touches the user's real $XDG_CONFIG_HOME/nono. The pack-store resolver
# walks $XDG_CONFIG_HOME/nono/packages/, so by isolating that root
# we get clean install + cleanup for free.
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

export XDG_CONFIG_HOME="$TMPDIR/xdg-config"
PACK_STORE="$XDG_CONFIG_HOME/nono/packages/test-ns/synthetic"
mkdir -p "$PACK_STORE"
cp -R "$FIXTURE_DIR/." "$PACK_STORE/"
SYNTHETIC_PROFILE="$PACK_STORE/profiles/synthetic.json"

# Workdir for the sandboxed command — granted to `synthetic` profile
# via $WORKDIR expansion.
mkdir -p "$TMPDIR/workdir"
echo "synthetic content" > "$TMPDIR/workdir/data.txt"

echo ""
echo "Pack store:    $PACK_STORE"
echo "Workdir:       $TMPDIR/workdir"
echo ""

# =============================================================================
# Resolution
# =============================================================================

echo "--- Pack-Store Resolution ---"

# The resolver should find the synthetic pack's public profile by its fully
# qualified package identity. Dry-run is enough to exercise the resolver path.
expect_success "synthetic pack profile resolves by fully qualified name" \
    "$NONO_BIN" run --profile test-ns/synthetic --workdir "$TMPDIR/workdir" --dry-run -- echo "test"

expect_output_contains "synthetic profile dry-run lists Capabilities" "Capabilities:" \
    "$NONO_BIN" run --profile test-ns/synthetic --workdir "$TMPDIR/workdir" --dry-run -- echo "test"

expect_failure "bare profile name does not select installed package" \
    "$NONO_BIN" run --profile synthetic --dry-run -- echo "test"

# A fully qualified name not matching an installed package must fail cleanly,
# not silently fall through to default. (Migration prompt is bypassed
# because XDG_CONFIG_HOME is isolated and there's no TTY in CI.)
expect_failure "unknown fully qualified package profile fails to resolve" \
    "$NONO_BIN" run --profile test-ns/pack-that-doesnt-exist --dry-run -- echo "test"

# =============================================================================
# Enforcement
# =============================================================================

echo ""
echo "--- Pack-Profile Enforcement ---"

# The synthetic profile grants $WORKDIR. Reading a file inside should work.
# Use the profile file directly here: real pack-store execution is
# gated by lockfile + Sigstore verification, which this hand-installed
# resolver fixture intentionally does not provide.
expect_success "synthetic profile grants workdir read" \
    bash -lc "cd \"$TMPDIR/workdir\" && \"$NONO_BIN_ABS\" run --profile \"$SYNTHETIC_PROFILE\" --allow-cwd -- cat data.txt"

# Outside-workdir paths should NOT be granted by the synthetic profile.
# Picking a path that's never in any embedded baseline group (so the
# failure is unambiguous).
expect_failure "synthetic profile denies arbitrary outside-workdir path" \
    "$NONO_BIN" run --profile "$SYNTHETIC_PROFILE" --workdir "$TMPDIR/workdir" --allow-cwd -- cat /etc/shadow

# =============================================================================
# Cleanup behaviour (resolver no longer finds it after removal)
# =============================================================================

echo ""
echo "--- Post-Removal Resolution ---"

rm -rf "$PACK_STORE"

expect_failure "synthetic profile fails to resolve after pack removed" \
    "$NONO_BIN" run --profile test-ns/synthetic --dry-run -- echo "test"

# =============================================================================
# Summary
# =============================================================================

print_summary
