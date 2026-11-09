#!/bin/bash
# Claude Code Startup Smoke Tests
# Installs the real Claude Code CLI in an isolated HOME and verifies nono can
# start it under both `run` and `wrap`.
#
# This suite exists specifically to guard against "runtime falls back to some
# lower-level launcher/runtime" regressions like the OpenCode/Bun failure fixed
# in PR #289. We use the published npm package instead of a mock binary so the
# startup path exercises real Node/CLI behavior.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Claude Code Startup Smoke Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "client startup suite"; then
    print_summary
    exit 0
fi

if ! skip_unless_linux "client startup smoke tests"; then
    print_summary
    exit 0
fi

ensure_node_toolchain() {
    if command_exists node && command_exists npm; then
        return 0
    fi

    if ! command_exists apt-get; then
        skip_test "client startup smoke tests" "node/npm not installed and apt-get unavailable"
        return 1
    fi

    local apt_cmd=(apt-get)
    if [[ "$(id -u)" -ne 0 ]]; then
        if command_exists sudo; then
            apt_cmd=(sudo apt-get)
        else
            skip_test "client startup smoke tests" "node/npm not installed and sudo unavailable"
            return 1
        fi
    fi

    echo "Installing nodejs/npm for client startup smoke tests..."
    "${apt_cmd[@]}" update >/dev/null 2>&1
    "${apt_cmd[@]}" install -y nodejs npm >/dev/null 2>&1

    if command_exists node && command_exists npm; then
        return 0
    fi

    skip_test "client startup smoke tests" "failed to install node/npm"
    return 1
}

if ! ensure_node_toolchain; then
    print_summary
    exit 0
fi

REAL_HOME="${HOME:-$(cd ~ && pwd)}"
TMPDIR=$(mktemp -d "$REAL_HOME/nono-client-startup.XXXXXX")
trap 'cleanup_test_dir "$TMPDIR"' EXIT

CLIENT_HOME="$TMPDIR/home"
CLAUDE_PREFIX="$CLIENT_HOME/.local/share/claude"
CLIENT_PATH="$CLAUDE_PREFIX/bin:$PATH"
CLAUDE_CODE_VERSION="2.1.71"

mkdir -p \
    "$CLIENT_HOME/.claude" \
    "$CLAUDE_PREFIX"
: > "$CLIENT_HOME/.claude.json"

echo ""
echo "Test home: $CLIENT_HOME"
echo ""

client_env() {
    env \
        HOME="$CLIENT_HOME" \
        XDG_CONFIG_HOME="$CLIENT_HOME/.config" \
        XDG_CACHE_HOME="$CLIENT_HOME/.cache" \
        XDG_DATA_HOME="$CLIENT_HOME/.local/share" \
        PATH="$CLIENT_PATH" \
        NONO_NO_UPDATE_CHECK=1 \
        "$@"
}

capture_last_nonempty_line() {
    local output="$1"
    printf '%s\n' "$output" | awk 'NF { line = $0 } END { print line }'
}

version_match_test() {
    local name="$1"
    local expected="$2"
    shift 2

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    actual=$?
    set -e

    if [[ "$actual" -ne 0 ]]; then
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       Expected exit code: 0, got: $actual"
        local stripped
        stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
        echo "       Output: ${stripped:0:2000}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    local last_line
    last_line=$(capture_last_nonempty_line "$output")
    if [[ "$last_line" == "$expected" ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected final line: $expected"
    echo "       Actual final line:   $last_line"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 1
}

echo "--- Install Package ---"

expect_success "install Claude Code npm package" \
    npm install -g --silent --no-audit --no-fund --prefix "$CLAUDE_PREFIX" "@anthropic-ai/claude-code@$CLAUDE_CODE_VERSION"

echo ""
echo "--- Claude Code Startup ---"

# The `claude` profile now ships as a registry pack
# (nolabs-ai/claude). The client-startup smoke test exercises
# the integration when both Claude Code AND the pack are installed.
# In CI environments without the pack pulled, skip the pack-dependent
# subtests cleanly rather than hit the migration prompt (which can't
# be answered non-interactively and would fail the suite).
PACK_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/nono/packages/nolabs-ai/claude"
if [[ ! -f "$PACK_DIR/package.json" ]]; then
    skip_test "nono run starts Claude Code successfully" \
        "nolabs-ai/claude pack not installed (run 'nono pull nolabs-ai/claude' first)"
    skip_test "nono wrap starts Claude Code successfully" \
        "nolabs-ai/claude pack not installed"
    print_summary
    exit 0
fi

CLAUDE_VERSION=$(client_env claude --version)
CLAUDE_VERSION=$(capture_last_nonempty_line "$CLAUDE_VERSION")

version_match_test "plain claude reports pinned version" "$CLAUDE_VERSION" \
    client_env claude --version

version_match_test "nono run starts Claude Code successfully" "$CLAUDE_VERSION" \
    client_env "$NONO_BIN" run --profile claude --allow-cwd --allow-net -- claude --version

version_match_test "nono wrap starts Claude Code successfully" "$CLAUDE_VERSION" \
    client_env "$NONO_BIN" wrap --profile claude --allow-cwd --allow-net -- claude --version

print_summary
