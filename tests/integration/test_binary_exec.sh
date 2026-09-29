#!/bin/bash
# Binary Execution Tests
# Verifies various binaries can execute and exit gracefully under the sandbox

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}Binary Execution Tests${NC}"

verify_nono_binary
if ! require_working_sandbox "binary execution suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo "test content" > "$TMPDIR/file.txt"
echo "line 1" >> "$TMPDIR/multiline.txt"
echo "line 2" >> "$TMPDIR/multiline.txt"
echo "line 3" >> "$TMPDIR/multiline.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

# Basic Commands

echo "Basic Commands"

expect_success "echo executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- echo "hello world"

expect_success "true exits 0" \
    "$NONO_BIN" run --allow "$TMPDIR" -- true

run_test "false exits 1" 1 \
    "$NONO_BIN" run --allow "$TMPDIR" -- false

run_test "exit code 42 preserved" 42 \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "exit 42"

run_test "exit code 127 preserved" 127 \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "exit 127"

# File Operations

echo ""
echo "File Operation Commands"

expect_success "ls executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- ls "$TMPDIR"

expect_success "cat executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- cat "$TMPDIR/file.txt"

expect_success "head executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- head -1 "$TMPDIR/multiline.txt"

expect_success "tail executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- tail -1 "$TMPDIR/multiline.txt"

expect_success "wc executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- wc -l "$TMPDIR/multiline.txt"

expect_success "grep executes (match found)" \
    "$NONO_BIN" run --allow "$TMPDIR" -- grep "test" "$TMPDIR/file.txt"

run_test "grep exits 1 (no match)" 1 \
    "$NONO_BIN" run --allow "$TMPDIR" -- grep "nonexistent" "$TMPDIR/file.txt"

expect_success "find executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- find "$TMPDIR" -name "*.txt"

expect_success "touch executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- touch "$TMPDIR/touched.txt"

expect_success "mkdir executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- mkdir "$TMPDIR/newdir"

# Shell and Subshells

echo ""
echo "Shell Commands"

expect_success "sh -c executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c 'echo "from sh"'

expect_success "bash -c executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- bash -c 'echo "from bash"'

if command_exists zsh; then
    expect_success "zsh -c executes" \
        "$NONO_BIN" run --allow "$TMPDIR" -- zsh -c 'echo "from zsh"'
else
    skip_test "zsh -c executes" "zsh not installed"
fi

expect_success "env executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- env >/dev/null

expect_success "printenv executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- printenv >/dev/null

# Text Processing

echo ""
echo "Text Processing Commands"

expect_success "sort executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sort "$TMPDIR/multiline.txt"

expect_success "uniq executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- uniq "$TMPDIR/multiline.txt"

expect_success "cut executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- cut -c1-4 "$TMPDIR/file.txt"

if command_exists sed; then
    expect_success "sed executes" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sed 's/test/TEST/' "$TMPDIR/file.txt"
fi

if command_exists awk; then
    expect_success "awk executes" \
        "$NONO_BIN" run --allow "$TMPDIR" -- awk '{print $1}' "$TMPDIR/file.txt"
fi

# Language Runtimes

echo ""
echo "Language Runtimes"

# Note: Language runtimes installed via Homebrew (at /opt/homebrew/) may not
# be accessible in the sandbox since Homebrew paths aren't in the system allowlist.
# Also, some runtimes like Node.js require cwd access which the sandbox may block.
# We check if each runtime can actually execute code (not just --version) before testing.

# Helper to check if a command can execute in the sandbox
# Redirects stdin from /dev/null to avoid blocking on the CWD prompt
can_run_in_sandbox() {
    "$NONO_BIN" run --allow "$TMPDIR" -- "$@" </dev/null >/dev/null 2>&1
}

# Python3 - may be installed via Homebrew or system
if command_exists python3; then
    if can_run_in_sandbox python3 -c "print('test')"; then
        expect_success "python3 executes" \
            "$NONO_BIN" run --allow "$TMPDIR" -- python3 -c "print('hello from python')"

        expect_success "python3 can read allowed file" \
            "$NONO_BIN" run --allow "$TMPDIR" -- python3 -c "print(open('$TMPDIR/file.txt').read())"
    else
        skip_test "python3 executes" "python3 not accessible in sandbox (Homebrew or cwd restriction)"
        skip_test "python3 can read allowed file" "python3 not accessible in sandbox"
    fi
else
    skip_test "python3 executes" "python3 not installed"
fi

# Node.js - often installed via Homebrew or nvm
# Node requires cwd access which the sandbox may restrict
if command_exists node; then
    if can_run_in_sandbox node -e "process.exit(0)"; then
        expect_success "node executes" \
            "$NONO_BIN" run --allow "$TMPDIR" -- node -e "console.log('hello from node')"

        expect_success "node can read allowed file" \
            "$NONO_BIN" run --allow "$TMPDIR" -- node -e "console.log(require('fs').readFileSync('$TMPDIR/file.txt', 'utf8'))"
    else
        skip_test "node executes" "node not accessible in sandbox (requires cwd access)"
        skip_test "node can read allowed file" "node not accessible in sandbox"
    fi
else
    skip_test "node executes" "node not installed"
fi

# Ruby - may be system or Homebrew
if command_exists ruby; then
    if can_run_in_sandbox ruby -e "exit 0"; then
        expect_success "ruby executes" \
            "$NONO_BIN" run --allow "$TMPDIR" -- ruby -e "puts 'hello from ruby'"
    else
        skip_test "ruby executes" "ruby not accessible in sandbox (Homebrew or cwd restriction)"
    fi
else
    skip_test "ruby executes" "ruby not installed"
fi

# printf - POSIX coreutil, always available
expect_success "printf executes" \
    "$NONO_BIN" run --allow "$TMPDIR" -- printf "hello from printf\n"

# Go tools
if command_exists go && command_exists gofmt; then
    if can_run_in_sandbox gofmt -h; then
        expect_success "gofmt executes" \
            "$NONO_BIN" run --allow "$TMPDIR" -- gofmt -h >/dev/null 2>&1
    else
        skip_test "go tools execute" "gofmt not accessible in sandbox"
    fi
else
    skip_test "go tools execute" "go not installed"
fi

# Output Verification

echo ""
echo "Output Verification"

expect_output_contains "echo output is correct" "hello world" \
    "$NONO_BIN" run --allow "$TMPDIR" -- echo "hello world"

expect_output_contains "cat output contains file content" "test content" \
    "$NONO_BIN" run --allow "$TMPDIR" -- cat "$TMPDIR/file.txt"

expect_output_contains "wc counts lines correctly" "3" \
    "$NONO_BIN" run --allow "$TMPDIR" -- wc -l "$TMPDIR/multiline.txt"

# Summary

print_summary
