#!/bin/bash
# Bypass Protection Tests
# Verifies that the canonical filesystem.bypass_protection field and
# --bypass-protection CLI flag correctly punch through deny groups while
# requiring explicit grants. The deprecated aliases also still work — see
# tests/integration/test_legacy_aliases.sh and the docs migration table in
# `nono profile guide`.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Bypass Protection Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "bypass protection suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

PROFILES_DIR="$TMPDIR/profiles"
mkdir -p "$PROFILES_DIR"

# Create a directory that mimics a sensitive path for testing.
# We use ~/.docker which is in deny_credentials.
DOCKER_DIR="$HOME/.docker"

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# CLI --bypass-protection
# =============================================================================

echo "--- CLI --bypass-protection ---"

if [[ -d "$DOCKER_DIR" ]]; then
    # bypass-protection with matching grant should succeed
    expect_success "CLI --bypass-protection with --allow succeeds (dry-run)" \
        "$NONO_BIN" run --allow "$DOCKER_DIR" --bypass-protection "$DOCKER_DIR" --dry-run -- echo ok

    # bypass-protection without grant should fail
    expect_failure "CLI --bypass-protection without grant fails" \
        "$NONO_BIN" run --bypass-protection "$DOCKER_DIR" --dry-run -- echo ok

    # bypass-protection with read-only grant should succeed
    expect_success "CLI --bypass-protection with --read succeeds (dry-run)" \
        "$NONO_BIN" run --read "$DOCKER_DIR" --bypass-protection "$DOCKER_DIR" --dry-run -- echo ok
else
    skip_test "CLI --bypass-protection with --allow" "~/.docker not found"
    skip_test "CLI --bypass-protection without grant" "~/.docker not found"
    skip_test "CLI --bypass-protection with --read" "~/.docker not found"
fi

# =============================================================================
# Profile filesystem.bypass_protection
# =============================================================================

echo ""
echo "--- Profile filesystem.bypass_protection ---"

if [[ -d "$DOCKER_DIR" ]]; then
    # Profile with bypass_protection and matching filesystem grant
    cat > "$PROFILES_DIR/docker-bypass.json" <<EOF
{
    "meta": { "name": "docker-bypass", "version": "1.0.0" },
    "extends": "default",
    "filesystem": {
        "allow": ["\$HOME/.docker"],
        "bypass_protection": ["\$HOME/.docker"]
    }
}
EOF

    expect_success "profile bypass_protection with filesystem grant succeeds (dry-run)" \
        "$NONO_BIN" run --profile "$PROFILES_DIR/docker-bypass.json" --dry-run -- echo ok

    expect_output_contains "profile bypass_protection shows .docker in capabilities" ".docker" \
        "$NONO_BIN" run --profile "$PROFILES_DIR/docker-bypass.json" --dry-run -- echo ok

    # Profile with bypass_protection but NO filesystem grant
    cat > "$PROFILES_DIR/docker-no-grant.json" <<EOF
{
    "meta": { "name": "docker-no-grant", "version": "1.0.0" },
    "extends": "default",
    "filesystem": {
        "bypass_protection": ["\$HOME/.docker"]
    }
}
EOF

    expect_failure "profile bypass_protection without grant fails" \
        "$NONO_BIN" run --profile "$PROFILES_DIR/docker-no-grant.json" --dry-run -- echo ok

    expect_output_contains "profile bypass_protection without grant mentions missing grant" \
        "no matching grant" \
        "$NONO_BIN" run --profile "$PROFILES_DIR/docker-no-grant.json" --dry-run -- echo ok

    # Profile with read-only grant (least privilege)
    cat > "$PROFILES_DIR/docker-readonly.json" <<EOF
{
    "meta": { "name": "docker-readonly", "version": "1.0.0" },
    "extends": "default",
    "filesystem": {
        "read": ["\$HOME/.docker"],
        "bypass_protection": ["\$HOME/.docker"]
    }
}
EOF

    expect_success "profile bypass_protection with read-only grant succeeds (dry-run)" \
        "$NONO_BIN" run --profile "$PROFILES_DIR/docker-readonly.json" --dry-run -- echo ok
else
    skip_test "profile bypass_protection with filesystem grant" "~/.docker not found"
    skip_test "profile bypass_protection shows .docker in capabilities" "~/.docker not found"
    skip_test "profile bypass_protection without grant fails" "~/.docker not found"
    skip_test "profile bypass_protection without grant mentions missing grant" "~/.docker not found"
    skip_test "profile bypass_protection with read-only grant" "~/.docker not found"
fi

# =============================================================================
# nono why with bypass_protection
# =============================================================================

echo ""
echo "--- nono why with bypass_protection ---"

if [[ -d "$DOCKER_DIR" ]]; then
    # Without bypass, ~/.docker should be denied
    expect_output_contains "nono why reports .docker denied without bypass" \
        "sensitive_path" \
        "$NONO_BIN" --silent why --json --path "$DOCKER_DIR" --op read

    # With profile bypass_protection, ~/.docker should be allowed
    expect_output_contains "nono why reports .docker allowed with profile bypass" \
        "\"status\": \"allowed\"" \
        "$NONO_BIN" --silent why --json --profile "$PROFILES_DIR/docker-bypass.json" \
            --path "$DOCKER_DIR" --op read

    # With read-only profile, write should be denied
    expect_output_contains "nono why reports .docker write denied with read-only profile" \
        "insufficient_access" \
        "$NONO_BIN" --silent why --json --profile "$PROFILES_DIR/docker-readonly.json" \
            --path "$DOCKER_DIR" --op write
else
    skip_test "nono why reports .docker denied without bypass" "~/.docker not found"
    skip_test "nono why reports .docker allowed with profile bypass" "~/.docker not found"
    skip_test "nono why reports .docker write denied with read-only profile" "~/.docker not found"
fi

# =============================================================================
# Bypass protection with profile inheritance
# =============================================================================

echo ""
echo "--- Profile Inheritance ---"

if [[ -d "$DOCKER_DIR" ]]; then
    # Child profile inherits bypass_protection from parent via user profiles directory.
    # The extends field resolves by name from ~/.config/nono/profiles/.
    USER_PROFILES_DIR="$HOME/.config/nono/profiles"
    CREATED_USER_PROFILES=0
    if [[ ! -d "$USER_PROFILES_DIR" ]]; then
        mkdir -p "$USER_PROFILES_DIR"
        CREATED_USER_PROFILES=1
    fi

    cat > "$USER_PROFILES_DIR/nono-test-docker-base.json" <<EOF
{
    "meta": { "name": "nono-test-docker-base", "version": "1.0.0" },
    "extends": "default",
    "filesystem": {
        "allow": ["\$HOME/.docker"],
        "bypass_protection": ["\$HOME/.docker"]
    }
}
EOF

    cat > "$USER_PROFILES_DIR/nono-test-docker-child.json" <<EOF
{
    "meta": { "name": "nono-test-docker-child", "version": "1.0.0" },
    "extends": "nono-test-docker-base",
    "filesystem": {
        "read": ["\$HOME/.config"]
    }
}
EOF

    expect_success "child profile inherits bypass_protection from parent (dry-run)" \
        "$NONO_BIN" run --profile nono-test-docker-child --dry-run -- echo ok

    expect_output_contains "child profile shows .docker from inherited bypass" ".docker" \
        "$NONO_BIN" run --profile nono-test-docker-child --dry-run -- echo ok

    # Cleanup
    rm -f "$USER_PROFILES_DIR/nono-test-docker-base.json" \
          "$USER_PROFILES_DIR/nono-test-docker-child.json"
    if [[ "$CREATED_USER_PROFILES" -eq 1 ]]; then
        rmdir "$USER_PROFILES_DIR" 2>/dev/null || true
    fi
else
    skip_test "child profile inherits bypass_protection from parent" "~/.docker not found"
    skip_test "child profile shows .docker from inherited bypass" "~/.docker not found"
fi

# =============================================================================
# Bypass protection does NOT bypass other deny groups
# =============================================================================

echo ""
echo "--- Bypass scope is targeted ---"

if [[ -d "$DOCKER_DIR" ]] && [[ -d "$HOME/.ssh" ]]; then
    # Bypassing .docker must NOT also unlock .ssh
    expect_output_contains "bypass_protection for .docker does not bypass .ssh deny" \
        "sensitive_path" \
        "$NONO_BIN" --silent why --json --profile "$PROFILES_DIR/docker-bypass.json" \
            --path "$HOME/.ssh" --op read
else
    skip_test "bypass_protection for .docker does not bypass .ssh deny" "~/.docker or ~/.ssh not found"
fi

# =============================================================================
# Warning output
# =============================================================================

echo ""
echo "--- Warning output ---"

if [[ -d "$DOCKER_DIR" ]]; then
    expect_output_not_contains "bypass_protection hides advisory by default" \
        "bypass_protection relaxing deny rule" \
        "$NONO_BIN" run --profile "$PROFILES_DIR/docker-bypass.json" --dry-run -- echo ok

    expect_output_contains "bypass_protection shows advisory with -v" \
        "bypass_protection relaxing deny rule" \
        "$NONO_BIN" run -v --profile "$PROFILES_DIR/docker-bypass.json" --dry-run -- echo ok
else
    skip_test "bypass_protection hides advisory by default" "~/.docker not found"
    skip_test "bypass_protection shows advisory with -v" "~/.docker not found"
fi

# =============================================================================
# Required groups cannot be excluded
# =============================================================================

echo ""
echo "--- Required group protection ---"

cat > "$PROFILES_DIR/exclude-required.json" <<EOF
{
    "meta": { "name": "exclude-required", "version": "1.0.0" },
    "extends": "default",
    "groups": {
        "exclude": ["deny_credentials"]
    }
}
EOF

expect_failure "excluding required deny_credentials group fails" \
    "$NONO_BIN" run --profile "$PROFILES_DIR/exclude-required.json" --dry-run -- echo ok

expect_output_contains "excluding required group mentions 'required'" \
    "required" \
    "$NONO_BIN" run --profile "$PROFILES_DIR/exclude-required.json" --dry-run -- echo ok

# =============================================================================
# Summary
# =============================================================================

print_summary
