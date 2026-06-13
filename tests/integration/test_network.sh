#!/bin/bash
# Network Control Tests
# Verifies network blocking works correctly

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Network Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "network suite"; then
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
# Network Blocked (--block-net)
# =============================================================================

echo "--- Network Blocked ---"

if command_exists curl; then
    expect_failure "curl blocked with --block-net" \
        timeout 15 "$NONO_BIN" run --block-net --allow "$TMPDIR" -- curl -s --max-time 5 https://example.com
else
    skip_test "curl blocked" "curl not installed"
fi

if command_exists wget; then
    expect_failure "wget blocked with --block-net" \
        timeout 15 "$NONO_BIN" run --block-net --allow "$TMPDIR" -- wget -q --timeout=5 -O /dev/null https://example.com
else
    skip_test "wget blocked" "wget not installed"
fi

# Note: ping requires special privileges, may not work in all environments
if command_exists ping; then
    expect_failure "ping blocked with --block-net" \
        timeout 10 "$NONO_BIN" run --block-net --allow "$TMPDIR" -- ping -c 1 -W 2 8.8.8.8
else
    if is_linux; then
        skip_test "ping blocked with --block-net" "raw ICMP is host/kernel mediated on Linux"
    else
        skip_test "ping blocked" "ping not installed"
    fi
fi

if command_exists nc; then
    expect_failure "nc (netcat) blocked with --block-net" \
        timeout 10 "$NONO_BIN" run --block-net --allow "$TMPDIR" -- nc -z -w 2 example.com 80
else
    skip_test "nc blocked" "nc not installed"
fi

# Test that even local network is blocked
if command_exists nc; then
    expect_failure "localhost connection blocked with --block-net" \
        timeout 10 "$NONO_BIN" run --block-net --allow "$TMPDIR" -- nc -z -w 1 127.0.0.1 22
fi

# =============================================================================
# Network Allowed (Default)
# =============================================================================

echo ""
echo "--- Network Allowed (Default) ---"

if command_exists curl; then
    expect_success "curl works by default" \
        "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'curl -s --max-time 10 https://example.com >/dev/null'

    # Proxy-based domain filtering requires either Landlock TCP (Linux ≥ 6.7, ABI v4)
    # or Seatbelt network rules (macOS). On Linux CI runners with older kernels,
    # direct connections bypass the proxy and these tests would spuriously pass.
    if is_macos; then
        expect_failure "proxy mode blocks direct curl bypass with --noproxy" \
            "$NONO_BIN" run --allow "$TMPDIR" --allow-domain api.openai.com -- bash -c 'curl -s --noproxy "*" --max-time 10 https://example.com >/dev/null'

        # Keep this assertion on a profile that still bundles a network_profile.
        # python-dev still embeds the developer network profile, which makes it the
        # right built-in fixture for validating "profile enables proxy filtering"
        # plus the --allow-net override.
        expect_failure "python-dev profile blocks hosts outside developer allowlist" \
            "$NONO_BIN" run --profile python-dev --allow-cwd -- bash -c 'curl -s --max-time 10 https://example.com >/dev/null'

        expect_success "python-dev profile allows unrestricted network with --allow-net" \
            "$NONO_BIN" run --profile python-dev --allow-cwd --allow-net -- bash -c 'curl -s --max-time 10 https://example.com >/dev/null'
    else
        skip_test "proxy mode blocks direct curl bypass with --noproxy" "proxy TCP blocking requires Landlock v4 (Linux ≥ 6.7); not guaranteed in CI"
        skip_test "python-dev profile blocks hosts outside developer allowlist" "proxy TCP blocking requires Landlock v4 (Linux ≥ 6.7); not guaranteed in CI"
        skip_test "python-dev profile allows unrestricted network with --allow-net" "dependent on proxy filtering test above"
    fi
else
    skip_test "curl works by default" "curl not installed"
fi

if command_exists wget; then
    if ! wget -q --timeout=10 -O /dev/null http://example.com >/dev/null 2>&1; then
        skip_test "wget works by default" "host wget cannot fetch http://example.com"
    else
        expect_success "wget works by default" \
            "$NONO_BIN" run --allow "$TMPDIR" -- wget -q --timeout=10 -O "$TMPDIR/wget_output" http://example.com
    fi
else
    skip_test "wget works by default" "wget not installed"
fi

# DNS resolution
if command_exists host; then
    expect_success "DNS resolution works (host)" \
        "$NONO_BIN" run --allow "$TMPDIR" -- host example.com
elif command_exists nslookup; then
    expect_success "DNS resolution works (nslookup)" \
        "$NONO_BIN" run --allow "$TMPDIR" -- nslookup example.com
elif command_exists dig; then
    expect_success "DNS resolution works (dig)" \
        "$NONO_BIN" run --allow "$TMPDIR" -- dig +short example.com
else
    skip_test "DNS resolution" "no DNS tools installed"
fi

# =============================================================================
# Network with Language Runtimes
# =============================================================================

echo ""
echo "--- Network with Language Runtimes ---"

# Note: Language runtime network tests are skipped because they may require
# access to installation paths (e.g., Homebrew) that aren't in system allowlists.
# Network functionality is already verified by curl/wget tests above.

skip_test "python3 network tests" "covered by curl/wget tests"
skip_test "node network tests" "covered by curl/wget tests"

# =============================================================================
# Summary
# =============================================================================

print_summary
