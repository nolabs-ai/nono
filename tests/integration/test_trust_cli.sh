#!/bin/bash
# Trust CLI Tests
# Tests trust policy scaffolding, signing, verification, listing, and startup checks

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Trust CLI Tests ===${NC}"

verify_nono_binary
NONO_BIN="$(cd "$(dirname "$NONO_BIN")" && pwd)/$(basename "$NONO_BIN")"

# Trust CLI is mostly CLI-only, but a small startup section below exercises
# sandboxed execution when the host supports it.

TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

# Generate a unique key ID for this test run to avoid collisions
KEY_ID="nono-inttest-$$"
TEST_XDG="$TMPDIR/xdg"
TRUST_KEYSTORE_DIR="$TMPDIR/trust-keystore"

INIT_DIR="$TMPDIR/init"
INIT_NO_KEY_DIR="$TMPDIR/init-no-key"
SINGLE_DIR="$TMPDIR/single"
MULTI_DIR="$TMPDIR/multi"
MISSING_DIR="$TMPDIR/missing"
STARTUP_DIR="$TMPDIR/startup"

mkdir -p \
    "$TEST_XDG" \
    "$TRUST_KEYSTORE_DIR" \
    "$INIT_DIR" \
    "$INIT_NO_KEY_DIR" \
    "$SINGLE_DIR" \
    "$MULTI_DIR" \
    "$MISSING_DIR" \
    "$STARTUP_DIR"

echo ""
echo "Test directory: $TMPDIR"
echo "Key ID: $KEY_ID"
echo ""

CAPTURED_OUTPUT=""
CAPTURED_EXIT=0

strip_ansi() {
    sed 's/\x1b\[[0-9;]*m//g'
}

with_test_env() {
    env \
        XDG_CONFIG_HOME="$TEST_XDG" \
        NONO_TRUST_TEST_USER_POLICY_PATH="$TEST_XDG/nono/trust-policy.json" \
        NONO_TRUST_TEST_KEYSTORE_DIR="$TRUST_KEYSTORE_DIR" \
        NONO_NO_UPDATE_CHECK=1 \
        "$@"
}

capture_in_dir() {
    local dir="$1"
    shift

    local raw_output=""

    set +e
    raw_output=$(cd "$dir" && "$@" </dev/null 2>&1)
    CAPTURED_EXIT=$?
    set -e

    CAPTURED_OUTPUT=$(printf '%s' "$raw_output" | strip_ansi)
}

expect_in_dir_success() {
    local name="$1"
    local dir="$2"
    shift 2

    TESTS_RUN=$((TESTS_RUN + 1))
    capture_in_dir "$dir" "$@"

    if [[ "$CAPTURED_EXIT" -eq 0 ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected exit code: 0, got: $CAPTURED_EXIT"
    echo "       Output: ${CAPTURED_OUTPUT:0:2000}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 1
}

expect_in_dir_failure() {
    local name="$1"
    local dir="$2"
    shift 2

    TESTS_RUN=$((TESTS_RUN + 1))
    capture_in_dir "$dir" "$@"

    if [[ "$CAPTURED_EXIT" -ne 0 ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name (exit $CAPTURED_EXIT)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected failure, but got success (exit 0)"
    echo "       Output: ${CAPTURED_OUTPUT:0:2000}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 1
}

expect_in_dir_success_contains() {
    local name="$1"
    local dir="$2"
    local expected_str="$3"
    shift 3

    TESTS_RUN=$((TESTS_RUN + 1))
    capture_in_dir "$dir" "$@"

    if [[ "$CAPTURED_EXIT" -eq 0 ]] && printf '%s' "$CAPTURED_OUTPUT" | grep -Fq "$expected_str"; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected exit code: 0 and output containing: $expected_str"
    echo "       Exit code: $CAPTURED_EXIT"
    echo "       Output: ${CAPTURED_OUTPUT:0:2000}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 1
}

expect_in_dir_failure_contains() {
    local name="$1"
    local dir="$2"
    local expected_str="$3"
    shift 3

    TESTS_RUN=$((TESTS_RUN + 1))
    capture_in_dir "$dir" "$@"

    if [[ "$CAPTURED_EXIT" -ne 0 ]] && printf '%s' "$CAPTURED_OUTPUT" | grep -Fq "$expected_str"; then
        echo -e "  ${GREEN}PASS${NC}: $name (exit $CAPTURED_EXIT)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected failure and output containing: $expected_str"
    echo "       Exit code: $CAPTURED_EXIT"
    echo "       Output: ${CAPTURED_OUTPUT:0:2000}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 1
}

expect_file_contains() {
    local name="$1"
    local file="$2"
    local expected_str="$3"
    run_test "$name" 0 grep -Fq "$expected_str" "$file" || true
}

expect_file_not_contains() {
    local name="$1"
    local file="$2"
    local unexpected_str="$3"
    run_test "$name" 1 grep -Fq "$unexpected_str" "$file" || true
}

# =============================================================================
# Key Generation
# =============================================================================

echo "--- Key Generation ---"

expect_success "trust keygen creates key" \
    with_test_env "$NONO_BIN" trust keygen --id "$KEY_ID"

expect_output_contains "trust keygen shows key ID" "$KEY_ID" \
    with_test_env "$NONO_BIN" trust keygen --id "${KEY_ID}-show"

# Duplicate key ID should fail
expect_failure "trust keygen duplicate ID fails" \
    with_test_env "$NONO_BIN" trust keygen --id "$KEY_ID"

# =============================================================================
# trust init
# =============================================================================

echo ""
echo "--- trust init ---"

mkdir -p "$INIT_DIR/nested" "$INIT_DIR/vendor"
printf '# Test SKILLS file\n' > "$INIT_DIR/SKILLS.md"
printf '# Nested AGENT file\n' > "$INIT_DIR/nested/AGENT.md"
printf '# Ignored vendor file\n' > "$INIT_DIR/vendor/CLAUDE.md"

expect_in_dir_success "trust init creates trust-policy.json" "$INIT_DIR" \
    with_test_env "$NONO_BIN" trust init --include SKILLS.md --key "$KEY_ID"

run_test "trust init writes policy file" 0 test -f "$INIT_DIR/trust-policy.json"
expect_file_contains "trust init writes includes field" "$INIT_DIR/trust-policy.json" '"includes"'
expect_file_contains "trust init includes requested project file" "$INIT_DIR/trust-policy.json" '"SKILLS.md"'
expect_file_not_contains "trust init omits files not explicitly included" "$INIT_DIR/trust-policy.json" '"nested/AGENT.md"'
expect_file_not_contains "trust init omits unrelated files" "$INIT_DIR/trust-policy.json" '"vendor/CLAUDE.md"'
expect_file_contains "trust init embeds publisher name when key exists" "$INIT_DIR/trust-policy.json" "\"name\": \"$KEY_ID\""
expect_file_contains "trust init embeds publisher public key" "$INIT_DIR/trust-policy.json" '"public_key"'

expect_in_dir_failure "trust init refuses to overwrite existing policy without --force" "$INIT_DIR" \
    with_test_env "$NONO_BIN" trust init --include SKILLS.md --key "$KEY_ID"

expect_in_dir_success "trust init --force updates explicit include patterns" "$INIT_DIR" \
    with_test_env "$NONO_BIN" trust init --force --include SKILLS.md nested/AGENT.md --key "$KEY_ID"

expect_file_contains "trust init force update includes nested paths when requested" "$INIT_DIR/trust-policy.json" '"nested/AGENT.md"'
expect_file_not_contains "trust init force update still omits unrelated files" "$INIT_DIR/trust-policy.json" '"vendor/CLAUDE.md"'

expect_in_dir_success "trust init --user creates a user policy in XDG config" "$INIT_DIR" \
    with_test_env "$NONO_BIN" trust init --user --force --key "$KEY_ID"

run_test "trust init --user writes user policy file" 0 test -f "$TEST_XDG/nono/trust-policy.json"
expect_file_contains "trust init --user creates empty includes by default" "$TEST_XDG/nono/trust-policy.json" '"includes": []'

expect_success "trust sign-policy signs user policy" \
    with_test_env "$NONO_BIN" trust sign-policy "$TEST_XDG/nono/trust-policy.json" --key "$KEY_ID"

run_test "trust init --user writes signed user policy bundle" 0 test -f "$TEST_XDG/nono/trust-policy.json.bundle"

printf '# Test AGENT file\n' > "$INIT_NO_KEY_DIR/AGENT.md"

expect_in_dir_success_contains "trust init notes missing signing key" "$INIT_NO_KEY_DIR" "skipping publisher entry" \
    with_test_env "$NONO_BIN" trust init --include AGENT.md --key "${KEY_ID}-missing"

expect_file_contains "trust init without key creates empty publisher list" "$INIT_NO_KEY_DIR/trust-policy.json" '"publishers": []'

# =============================================================================
# Single-file signing, verification, and listing
# =============================================================================

echo ""
echo "--- Single-file Signing ---"

printf '# Test SKILLS file\n' > "$SINGLE_DIR/SKILLS.md"
printf '# Test CLAUDE file\n' > "$SINGLE_DIR/CLAUDE.md"
printf '# Unsigned AGENT file\n' > "$SINGLE_DIR/AGENT.md"

expect_in_dir_success "single-file project trust init succeeds" "$SINGLE_DIR" \
    with_test_env "$NONO_BIN" trust init --include SKILLS.md CLAUDE.md AGENT.md --key "$KEY_ID"

expect_success "trust sign creates bundle" \
    with_test_env "$NONO_BIN" trust sign "$SINGLE_DIR/SKILLS.md" --key "$KEY_ID"

run_test "bundle file exists" 0 test -f "$SINGLE_DIR/SKILLS.md.bundle"

expect_success "trust sign second file" \
    with_test_env "$NONO_BIN" trust sign "$SINGLE_DIR/CLAUDE.md" --key "$KEY_ID"

run_test "second bundle file exists" 0 test -f "$SINGLE_DIR/CLAUDE.md.bundle"

expect_failure "trust sign nonexistent file fails" \
    with_test_env "$NONO_BIN" trust sign "$SINGLE_DIR/NONEXISTENT.md" --key "$KEY_ID"

expect_in_dir_success "trust sign-policy succeeds" "$SINGLE_DIR" \
    with_test_env "$NONO_BIN" trust sign-policy --key "$KEY_ID"

run_test "trust policy bundle exists" 0 test -f "$SINGLE_DIR/trust-policy.json.bundle"

expect_in_dir_success_contains "trust verify signed file succeeds with trust policy" "$SINGLE_DIR" "VERIFIED" \
    with_test_env "$NONO_BIN" trust verify SKILLS.md

expect_in_dir_failure_contains "trust verify unsigned file fails (no bundle)" "$SINGLE_DIR" "no .bundle file found" \
    with_test_env "$NONO_BIN" trust verify AGENT.md

printf '\n# TAMPERED CONTENT\n' >> "$SINGLE_DIR/CLAUDE.md"

expect_in_dir_failure_contains "trust verify tampered file fails" "$SINGLE_DIR" "bundle digest does not match file content" \
    with_test_env "$NONO_BIN" trust verify CLAUDE.md

expect_in_dir_success_contains "trust list --json reports verified files" "$SINGLE_DIR" '"status": "verified"' \
    with_test_env "$NONO_BIN" trust list --json

expect_in_dir_success_contains "trust list --json reports unsigned files" "$SINGLE_DIR" '"status": "unsigned"' \
    with_test_env "$NONO_BIN" trust list --json

expect_in_dir_success_contains "trust list --json reports failed files" "$SINGLE_DIR" '"status": "failed"' \
    with_test_env "$NONO_BIN" trust list --json

# =============================================================================
# Multi-subject signing
# =============================================================================

echo ""
echo "--- Multi-subject Signing ---"

printf '# Multi SKILLS file\n' > "$MULTI_DIR/SKILLS.md"
printf '# Multi CLAUDE file\n' > "$MULTI_DIR/CLAUDE.md"

expect_in_dir_success "multi-subject project trust init succeeds" "$MULTI_DIR" \
    with_test_env "$NONO_BIN" trust init --include SKILLS.md CLAUDE.md --key "$KEY_ID"

expect_in_dir_success "trust sign --all creates a multi-subject bundle" "$MULTI_DIR" \
    with_test_env "$NONO_BIN" trust sign --all --multi-subject --key "$KEY_ID"

run_test "multi-subject bundle exists" 0 test -f "$MULTI_DIR/.nono-trust.bundle"
run_test "sign --all does not create per-file sidecars" 1 test -f "$MULTI_DIR/SKILLS.md.bundle"

expect_in_dir_success "multi-subject trust sign-policy succeeds" "$MULTI_DIR" \
    with_test_env "$NONO_BIN" trust sign-policy --key "$KEY_ID"

expect_in_dir_success_contains "trust verify --all accepts multi-subject bundle" "$MULTI_DIR" "Verified 2 file(s) successfully." \
    with_test_env "$NONO_BIN" trust verify --all

expect_in_dir_success_contains "trust verify .nono-trust.bundle reports first subject" "$MULTI_DIR" "SKILLS.md" \
    with_test_env "$NONO_BIN" trust verify .nono-trust.bundle

expect_in_dir_success_contains "trust verify .nono-trust.bundle reports second subject" "$MULTI_DIR" "CLAUDE.md" \
    with_test_env "$NONO_BIN" trust verify .nono-trust.bundle

printf '\n# TAMPERED CONTENT\n' >> "$MULTI_DIR/CLAUDE.md"

expect_in_dir_failure_contains "trust verify --all rejects tampered multi-subject bundle" "$MULTI_DIR" "digest mismatch" \
    with_test_env "$NONO_BIN" trust verify --all

# =============================================================================
# Missing literal patterns
# =============================================================================

echo ""
echo "--- Missing Literal Patterns ---"

cat > "$MISSING_DIR/trust-policy.json" <<'EOF'
{
  "predicate": "https://nono.sh/attestation/trust-policy/v1",
  "version": 1,
  "includes": ["SKILLS.md"],
  "publishers": [],
  "blocklist": {
    "digests": [],
    "publishers": []
  },
  "enforcement": "deny"
}
EOF

if is_macos; then
    expect_in_dir_failure_contains "trust verify --all blocks missing literal patterns on macOS" "$MISSING_DIR" "no matching file" \
        with_test_env "$NONO_BIN" trust verify --all

    expect_in_dir_failure_contains "trust list blocks missing literal patterns on macOS" "$MISSING_DIR" "no matching file" \
        with_test_env "$NONO_BIN" trust list
else
    expect_in_dir_success_contains "trust verify --all allows missing literal patterns on Linux" "$MISSING_DIR" "No files or multi-subject bundles found to verify." \
        with_test_env "$NONO_BIN" trust verify --all

    expect_in_dir_success_contains "trust list allows missing literal patterns on Linux" "$MISSING_DIR" "No files found matching policy includes in current directory." \
        with_test_env "$NONO_BIN" trust list
fi

# =============================================================================
# Startup enforcement
# =============================================================================

echo ""
echo "--- Startup Enforcement ---"

cat > "$STARTUP_DIR/trust-policy.json" <<'EOF'
{
  "predicate": "https://nono.sh/attestation/trust-policy/v1",
  "version": 1,
  "includes": ["SKILLS.md"],
  "publishers": [],
  "blocklist": {
    "digests": [],
    "publishers": []
  },
  "enforcement": "deny"
}
EOF

expect_in_dir_success "trust sign-policy signs startup policy" "$STARTUP_DIR" \
    with_test_env "$NONO_BIN" trust sign-policy --key "$KEY_ID"

run_test "startup trust policy bundle exists" 0 test -f "$STARTUP_DIR/trust-policy.json.bundle"

if require_working_sandbox "trust startup enforcement"; then
    if is_macos; then
        expect_in_dir_failure_contains "nono run blocks missing literal instruction files on macOS startup" "$STARTUP_DIR" "no matching file" \
            with_test_env "$NONO_BIN" run --allow-cwd -- sh -c "printf STARTED"
    else
        expect_in_dir_success_contains "nono run allows missing literal instruction files on Linux startup" "$STARTUP_DIR" "STARTED" \
            with_test_env "$NONO_BIN" run --allow-cwd -- sh -c "printf STARTED"
    fi
fi

# =============================================================================
# Export Key
# =============================================================================

echo ""
echo "--- Export Key ---"

expect_success "trust export-key succeeds" \
    with_test_env "$NONO_BIN" trust export-key --id "$KEY_ID"

expect_output_contains "export-key shows base64 public key" "MF" \
    with_test_env "$NONO_BIN" trust export-key --id "$KEY_ID"

# =============================================================================
# file:// backend (headless key storage)
# =============================================================================

echo ""
echo "--- file:// Backend ---"

FILE_DIR="$TMPDIR/file-backend"
FILE_KEY_DIR="$TMPDIR/file-keys"
mkdir -p "$FILE_DIR" "$FILE_KEY_DIR"

FILE_KEYREF="file://$FILE_KEY_DIR/trust-key.pem"

printf '# Test file-backed signing\n' > "$FILE_DIR/SKILLS.md"

expect_success "trust keygen --keyref file:// creates key pair" \
    with_test_env "$NONO_BIN" trust keygen --keyref "$FILE_KEYREF"

run_test "file:// private key exists" 0 test -f "$FILE_KEY_DIR/trust-key.pem"
run_test "file:// public key exists" 0 test -f "$FILE_KEY_DIR/trust-key.pem.pub"

# Verify permissions are 0600
PRIV_PERMS=$(stat -c '%a' "$FILE_KEY_DIR/trust-key.pem" 2>/dev/null || stat -f '%Lp' "$FILE_KEY_DIR/trust-key.pem")
run_test "file:// private key has 0600 permissions" 0 test "$PRIV_PERMS" = "600"

expect_failure "trust keygen --keyref file:// rejects duplicate without --force" \
    with_test_env "$NONO_BIN" trust keygen --keyref "$FILE_KEYREF"

expect_success "trust keygen --keyref file:// --force overwrites" \
    with_test_env "$NONO_BIN" trust keygen --keyref "$FILE_KEYREF" --force

expect_output_contains "trust export-key --keyref file:// returns base64" "MF" \
    with_test_env "$NONO_BIN" trust export-key --keyref "$FILE_KEYREF"

expect_output_contains "trust export-key --keyref file:// --pem returns PEM" "BEGIN PUBLIC KEY" \
    with_test_env "$NONO_BIN" trust export-key --keyref "$FILE_KEYREF" --pem

expect_in_dir_success "trust init --keyref file:// creates policy" "$FILE_DIR" \
    with_test_env "$NONO_BIN" trust init --include SKILLS.md --keyref "$FILE_KEYREF"

expect_file_contains "file:// init embeds publisher public key" "$FILE_DIR/trust-policy.json" '"public_key"'
expect_file_contains "file:// init embeds file URI as key_id" "$FILE_DIR/trust-policy.json" "file://$FILE_KEY_DIR/trust-key.pem"

expect_in_dir_success "trust sign-policy --keyref file:// succeeds" "$FILE_DIR" \
    with_test_env "$NONO_BIN" trust sign-policy --keyref "$FILE_KEYREF"

run_test "file:// sign-policy creates bundle" 0 test -f "$FILE_DIR/trust-policy.json.bundle"

expect_success "trust sign --keyref file:// creates bundle" \
    with_test_env "$NONO_BIN" trust sign "$FILE_DIR/SKILLS.md" --keyref "$FILE_KEYREF"

run_test "file:// sign creates bundle" 0 test -f "$FILE_DIR/SKILLS.md.bundle"

expect_in_dir_success_contains "trust verify succeeds with file:// signed artifacts" "$FILE_DIR" "VERIFIED" \
    with_test_env "$NONO_BIN" trust verify SKILLS.md

# Tamper detection
printf '# tampered\n' >> "$FILE_DIR/SKILLS.md"
expect_in_dir_failure_contains "trust verify detects tampering on file:// signed file" "$FILE_DIR" "digest" \
    with_test_env "$NONO_BIN" trust verify SKILLS.md

# Re-sign after edit
expect_success "trust sign --keyref file:// re-signs after edit" \
    with_test_env "$NONO_BIN" trust sign "$FILE_DIR/SKILLS.md" --keyref "$FILE_KEYREF"

expect_in_dir_success_contains "trust verify succeeds after re-sign" "$FILE_DIR" "VERIFIED" \
    with_test_env "$NONO_BIN" trust verify SKILLS.md

# Key relocation: same key material at a different path is a different signer.
# The trust policy records the full file:// URI as the publisher key_id, so
# signing with a relocated copy fails publisher matching even though the
# cryptographic key is identical. This is by design — use a stable path.
RELOCATED_KEY_DIR="$TMPDIR/file-keys-relocated"
mkdir -p "$RELOCATED_KEY_DIR"
cp "$FILE_KEY_DIR/trust-key.pem" "$RELOCATED_KEY_DIR/trust-key.pem"
cp "$FILE_KEY_DIR/trust-key.pem.pub" "$RELOCATED_KEY_DIR/trust-key.pem.pub"
RELOCATED_KEYREF="file://$RELOCATED_KEY_DIR/trust-key.pem"

expect_success "trust sign with relocated key succeeds (signing is key-material only)" \
    with_test_env "$NONO_BIN" trust sign "$FILE_DIR/SKILLS.md" --keyref "$RELOCATED_KEYREF"

expect_in_dir_failure_contains "trust verify rejects relocated-key signer (path-dependent identity)" "$FILE_DIR" "not in trusted publishers" \
    with_test_env "$NONO_BIN" trust verify SKILLS.md

# =============================================================================
# Summary
# =============================================================================

print_summary
