#!/bin/bash
# Pack-store profile resolver tests
#
# Hand-installs the synthetic test pack from tests/fixtures/synthetic-pack
# into the local pack store, then verifies:
#
#   - `--profile <install_as>` resolves through the pack-store branch of
#     load_profile (the same branch the pull/migration flow uses).
#   - A real (non-dry-run) invocation of an unverified hand-installed pack
#     is rejected by pack verification — it has no lockfile entry / signed
#     trust bundle, so it must not execute.
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
# Resolution vs. verification: `nono run --profile <name>` first *resolves*
# the profile (find_pack_store_profile) and then *verifies* every pack it
# declares (verify_profile_packs) before building the sandbox. Verification
# requires a lockfile entry and a signed `.nono-trust.bundle`, neither of
# which a hand-installed fixture has — and the trust bundle is pinned to the
# production trusted root, so it cannot be faked here. `--dry-run` exits
# after printing capabilities without ever executing, so it skips
# verification; that is the branch this suite uses to exercise the resolver
# in isolation. Enforcement of a pack-shipped profile during a *real* run is
# only meaningful for a properly pulled/signed pack and is covered by the
# nono-packs end-to-end CI, not here.
#
# This suite is specifically about: when a pack IS installed, does
# `--profile <name>` find it (resolver), and is an unverified pack correctly
# refused on a real run (verification gate)?

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Pack Resolution Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "pack resolution suite"; then
    print_summary
    exit 0
fi

FIXTURE_DIR="$(cd "$SCRIPT_DIR/../fixtures/synthetic-pack" && pwd)"
if [[ ! -f "$FIXTURE_DIR/package.json" ]]; then
    echo "FAIL: synthetic-pack fixture missing at $FIXTURE_DIR"
    exit 1
fi

# Use a per-run XDG_CONFIG_HOME so the test pack-store install never
# touches the user's real ~/.config/nono. The pack-store resolver
# walks $XDG_CONFIG_HOME/nono/packages/, so by isolating that root
# we get clean install + cleanup for free.
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

export XDG_CONFIG_HOME="$TMPDIR/xdg-config"
PACK_STORE="$XDG_CONFIG_HOME/nono/packages/test-ns/synthetic"
mkdir -p "$PACK_STORE"
cp -R "$FIXTURE_DIR/." "$PACK_STORE/"

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

# The resolver should find the synthetic pack's profile by `install_as`
# name and load it without complaint. Dry-run is enough to exercise
# the resolver path.
expect_success "synthetic pack profile resolves by install_as name" \
    "$NONO_BIN" run --profile synthetic --workdir "$TMPDIR/workdir" --dry-run -- echo "test"

expect_output_contains "synthetic profile dry-run lists Capabilities" "Capabilities:" \
    "$NONO_BIN" run --profile synthetic --workdir "$TMPDIR/workdir" --dry-run -- echo "test"

# A name not matching any pack OR embedded profile must fail cleanly,
# not silently fall through to default. (Migration prompt is bypassed
# because XDG_CONFIG_HOME is isolated and there's no TTY in CI.)
expect_failure "unknown pack-name profile fails to resolve" \
    "$NONO_BIN" run --profile pack-name-that-doesnt-exist --dry-run -- echo "test"

# =============================================================================
# Verification gate (real runs require a verified pack)
# =============================================================================

echo ""
echo "--- Pack Verification Gate ---"

# A *real* (non-dry-run) invocation must verify every pack the profile
# declares before building the sandbox. The synthetic pack is hand-installed
# with no lockfile entry and no signed .nono-trust.bundle, so verification
# must reject it — an unverified pack's profile must never reach execution.
# (Contrast with the dry-run resolution tests above, which skip verification
# because they execute nothing.)
expect_failure "real run of unverified hand-installed pack is rejected" \
    "$NONO_BIN" run --profile synthetic --workdir "$TMPDIR/workdir" --allow-cwd -- cat data.txt

# The rejection must be the verification gate, not some unrelated failure.
expect_output_contains "rejection cites missing pack verification metadata" "test-ns/synthetic" \
    "$NONO_BIN" run --profile synthetic --workdir "$TMPDIR/workdir" --allow-cwd -- cat data.txt

# =============================================================================
# Cleanup behaviour (resolver no longer finds it after removal)
# =============================================================================

echo ""
echo "--- Post-Removal Resolution ---"

rm -rf "$PACK_STORE"

expect_failure "synthetic profile fails to resolve after pack removed" \
    "$NONO_BIN" run --profile synthetic --dry-run -- echo "test"

# =============================================================================
# Summary
# =============================================================================

print_summary
