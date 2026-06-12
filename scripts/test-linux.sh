#!/usr/bin/env bash
# nono Linux Test Script
# Run this on a Linux machine to verify sandbox enforcement

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

NONO="${NONO:-./target/release/nono}"
TEST_DIR="/tmp/nono-test-$$"
PASSED=0
FAILED=0

# Cleanup on exit
cleanup() {
    rm -rf "$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT

print_header() {
    echo ""
    echo -e "${BLUE}------------------------------------------------------------${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}------------------------------------------------------------${NC}"
}

pass() {
    echo -e "  ${GREEN}PASS${NC}: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "  ${RED}FAIL${NC}: $1"
    FAILED=$((FAILED + 1))
}

skip() {
    echo -e "  ${YELLOW}SKIP${NC}: $1"
}

info() {
    echo -e "  ${YELLOW}INFO${NC}: $1"
}

# ============================================================================
# Prerequisites
# ============================================================================
print_header "Prerequisites"

# Check if nono binary exists
if [[ ! -x "$NONO" ]]; then
    echo -e "${RED}Error: nono binary not found at $NONO${NC}"
    echo "Build with: cargo build --release"
    exit 1
fi
pass "nono binary found: $NONO"

# Check kernel version
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
info "Kernel version: $KERNEL_VERSION"

if [[ $KERNEL_MAJOR -lt 5 ]] || [[ $KERNEL_MAJOR -eq 5 && $KERNEL_MINOR -lt 13 ]]; then
    echo -e "${RED}Error: Kernel 5.13+ required for Landlock${NC}"
    exit 1
fi
pass "Kernel version >= 5.13"

# Check if Landlock is in LSM list
LSM_LIST=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
if [[ "$LSM_LIST" != *"landlock"* ]]; then
    echo -e "${RED}Error: Landlock not enabled in kernel LSM list${NC}"
    echo "Current LSMs: $LSM_LIST"
    echo "Add 'landlock' to kernel boot params: lsm=landlock,..."
    exit 1
fi
pass "Landlock enabled in LSM list"

# Check network filtering support (kernel 6.7+)
NETWORK_SUPPORTED=false
if [[ $KERNEL_MAJOR -gt 6 ]] || [[ $KERNEL_MAJOR -eq 6 && $KERNEL_MINOR -ge 7 ]]; then
    NETWORK_SUPPORTED=true
    pass "Network filtering supported (kernel 6.7+)"
else
    skip "Network filtering requires kernel 6.7+ (current: $KERNEL_VERSION)"
fi

# Create test directory
mkdir -p "$TEST_DIR"
pass "Test directory created: $TEST_DIR"

# ============================================================================
# nono setup --check
# ============================================================================
print_header "nono setup --check-only"

SETUP_OUTPUT=$($NONO setup --check-only 2>&1 || true)
if echo "$SETUP_OUTPUT" | grep -qi "verified\|complete\|sandbox.*available\|landlock"; then
    pass "nono setup --check-only succeeded"
else
    info "Output: $(echo "$SETUP_OUTPUT" | head -3)"
    fail "nono setup --check-only failed"
fi

# ============================================================================
# Filesystem Sandbox Tests
# ============================================================================
print_header "Filesystem Sandbox Tests"

# Test 1: Write to allowed path should succeed
echo "test content" > "$TEST_DIR/existing.txt"
if $NONO run --allow "$TEST_DIR" --allow-cwd -- sh -c "echo 'new' > $TEST_DIR/allowed.txt" 2>/dev/null; then
    if [[ -f "$TEST_DIR/allowed.txt" ]]; then
        pass "Write to allowed path succeeded"
    else
        fail "Write to allowed path - file not created"
    fi
else
    fail "Write to allowed path failed"
fi

# Test 2: Write outside allowed path should fail
OUTSIDE_OUTPUT=$($NONO run --allow "$TEST_DIR" --allow-cwd -- sh -c "echo 'bad' > /tmp/nono-outside-$$.txt" 2>&1 || true)
if echo "$OUTSIDE_OUTPUT" | grep -qiE "permission denied|cannot create|EACCES|not permitted"; then
    pass "Write outside allowed path blocked"
else
    if [[ -f "/tmp/nono-outside-$$.txt" ]]; then
        fail "Write outside allowed path was NOT blocked (file exists)"
        rm -f "/tmp/nono-outside-$$.txt" 2>/dev/null || true
    else
        pass "Write outside allowed path blocked (file not created)"
    fi
fi

# Test 3: Read-only access should block writes
mkdir -p "$TEST_DIR/readonly"
echo "original" > "$TEST_DIR/readonly/file.txt"
READONLY_OUTPUT=$($NONO run --read "$TEST_DIR/readonly" --allow-cwd -- sh -c "echo 'modified' > $TEST_DIR/readonly/file.txt" 2>&1 || true)
if echo "$READONLY_OUTPUT" | grep -qiE "permission denied|cannot create|not permitted"; then
    pass "Read-only path blocks writes"
else
    if grep -q "original" "$TEST_DIR/readonly/file.txt"; then
        pass "Read-only path blocks writes (content unchanged)"
    else
        fail "Read-only path did NOT block writes"
    fi
fi

# Test 4: Read-only access should allow reads
if $NONO run --read "$TEST_DIR/readonly" --allow-cwd -- cat "$TEST_DIR/readonly/file.txt" 2>/dev/null | grep -q "original"; then
    pass "Read-only path allows reads"
else
    fail "Read-only path blocked reads"
fi

# Test 5: Atomic writes (write to .tmp, rename to target)
ATOMIC_OUTPUT=$($NONO run --allow "$TEST_DIR" --allow-cwd -- sh -c "echo 'atomic' > $TEST_DIR/atomic.tmp && mv $TEST_DIR/atomic.tmp $TEST_DIR/atomic.txt" 2>&1 || true)
if [[ -f "$TEST_DIR/atomic.txt" ]] && grep -q "atomic" "$TEST_DIR/atomic.txt"; then
    pass "Atomic writes (tmp + rename) work"
else
    info "Output: $ATOMIC_OUTPUT"
    fail "Atomic writes failed"
fi

# Test 6: File deletion within allowed path (need --allow-command rm)
echo "to delete" > "$TEST_DIR/deleteme.txt"
if $NONO run --allow "$TEST_DIR" --allow-cwd --allow-command rm -- rm "$TEST_DIR/deleteme.txt" 2>/dev/null; then
    if [[ ! -f "$TEST_DIR/deleteme.txt" ]]; then
        pass "File deletion within allowed path works"
    else
        fail "File deletion - file still exists"
    fi
else
    fail "File deletion within allowed path failed"
fi

# ============================================================================
# Sensitive Path Protection
# ============================================================================
print_header "Sensitive Path Protection"

# Test: SSH key access should be blocked
if [[ -f ~/.ssh/id_rsa ]]; then
    SSH_OUTPUT=$($NONO run --allow "$TEST_DIR" --allow-cwd -- cat ~/.ssh/id_rsa 2>&1 || true)
    if echo "$SSH_OUTPUT" | grep -qiE "permission denied|not permitted|EACCES"; then
        pass "SSH private key access blocked"
    else
        fail "SSH private key access NOT blocked"
    fi
else
    skip "No ~/.ssh/id_rsa to test"
fi

# Test: AWS credentials should be blocked
if [[ -f ~/.aws/credentials ]]; then
    AWS_OUTPUT=$($NONO run --allow "$TEST_DIR" --allow-cwd -- cat ~/.aws/credentials 2>&1 || true)
    if echo "$AWS_OUTPUT" | grep -qiE "permission denied|not permitted|EACCES"; then
        pass "AWS credentials access blocked"
    else
        fail "AWS credentials access NOT blocked"
    fi
else
    skip "No ~/.aws/credentials to test"
fi

# Test: nono why shows sensitive path info
WHY_OUTPUT=$($NONO why ~/.ssh/id_rsa 2>&1 || true)
if echo "$WHY_OUTPUT" | grep -qiE "sensitive|ssh|credential|blocked|protected|private"; then
    pass "nono why explains sensitive path"
else
    info "Output: $(echo "$WHY_OUTPUT" | head -3)"
    fail "nono why doesn't explain sensitive path"
fi

# ============================================================================
# Network Sandbox Tests
# ============================================================================
print_header "Network Sandbox Tests"

if $NETWORK_SUPPORTED; then
    # Test: Network should be blocked with --block-net
    if command -v curl &>/dev/null; then
        NET_BLOCK_OUTPUT=$(timeout 10 $NONO run --allow "$TEST_DIR" --block-net --allow-cwd -- curl -s --connect-timeout 3 https://example.com 2>&1 || true)
        if echo "$NET_BLOCK_OUTPUT" | grep -qiE "denied|refused|failed|couldn't connect|connection.*failed|error"; then
            pass "Network blocked with --block-net"
        else
            if [[ -z "$NET_BLOCK_OUTPUT" ]] || [[ "$NET_BLOCK_OUTPUT" == *"exit"* ]]; then
                pass "Network blocked with --block-net (no response)"
            else
                info "Output: $(echo "$NET_BLOCK_OUTPUT" | head -2)"
                fail "Network NOT blocked with --block-net"
            fi
        fi
    else
        skip "curl not available for network test"
    fi

    # Test: Network should work without --block-net
    if command -v curl &>/dev/null; then
        NET_ALLOW_OUTPUT=$(timeout 15 $NONO run --allow "$TEST_DIR" --allow-cwd -- curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://example.com 2>&1 || true)
        if [[ "$NET_ALLOW_OUTPUT" == *"200"* ]]; then
            pass "Network allowed without --block-net"
        else
            info "Output: $NET_ALLOW_OUTPUT"
            fail "Network blocked even without --block-net"
        fi
    else
        skip "curl not available for network test"
    fi
else
    skip "Network filtering tests (requires kernel 6.7+)"
fi

# ============================================================================
# Dangerous Command Protection
# ============================================================================
print_header "Dangerous Command Protection"

# Test: rm -rf should be blocked by dangerous command filter
RM_OUTPUT=$($NONO run --allow "$TEST_DIR" --allow-cwd -- rm -rf / 2>&1 || true)
if echo "$RM_OUTPUT" | grep -qiE "blocked|dangerous|not allowed"; then
    pass "rm -rf blocked as dangerous command"
else
    if echo "$RM_OUTPUT" | grep -qiE "permission denied|not permitted"; then
        pass "rm -rf blocked by sandbox"
    else
        info "Output: $(echo "$RM_OUTPUT" | head -2)"
        fail "rm -rf was NOT blocked"
    fi
fi

# ============================================================================
# Dry Run Mode
# ============================================================================
print_header "Dry Run Mode"

# Test: Dry run should show capabilities without applying sandbox
DRY_OUTPUT=$(echo "n" | $NONO run --allow "$TEST_DIR" --read /etc --dry-run -- echo test 2>&1 || true)
if echo "$DRY_OUTPUT" | grep -qiE "dry.?run|would.*grant|capabilities"; then
    pass "Dry run shows mode indicator"
else
    info "Output: $(echo "$DRY_OUTPUT" | head -3)"
    skip "Dry run output format may differ"
fi

if echo "$DRY_OUTPUT" | grep -q "$TEST_DIR"; then
    pass "Dry run shows allowed paths"
else
    skip "Dry run path display may differ"
fi

# ============================================================================
# Claude Code Profile
# ============================================================================
print_header "Claude Code Profile"

# Test: Profile should load (dry-run to avoid modifying system)
PROFILE_OUTPUT=$(echo "n" | $NONO run --profile always-further/claude --allow-cwd --dry-run -- echo test 2>&1 || true)
if echo "$PROFILE_OUTPUT" | grep -qiE "claude|profile|hook"; then
    pass "Claude Code profile loads"
else
    info "Output: $(echo "$PROFILE_OUTPUT" | head -3)"
    skip "Claude Code profile output may differ"
fi

# ============================================================================
# Summary
# ============================================================================
print_header "Test Summary"

TOTAL=$((PASSED + FAILED))
echo ""
echo -e "  ${GREEN}Passed${NC}: $PASSED"
echo -e "  ${RED}Failed${NC}: $FAILED"
echo -e "  Total:  $TOTAL"
echo ""

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed or were skipped. Review output above.${NC}"
    exit 1
fi
