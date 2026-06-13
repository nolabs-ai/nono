#!/bin/bash
# Child and tool sandbox boundary tests
# Covers credential injection, file/directory grants, and environment handling
# in both the primary child sandbox and ETI tool sandboxes.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Child / Tool Sandbox Boundary Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "child/tool boundary suite"; then
    print_summary
    exit 0
fi

TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

mkdir -p \
    "$TMPDIR/child-dir" \
    "$TMPDIR/tool-read-dir" \
    "$TMPDIR/tool-write-dir" \
    "$TMPDIR/tool-outer-only"

printf "child-dir-read\n" > "$TMPDIR/child-dir/read.txt"
printf "child-file-read\n" > "$TMPDIR/child-read-file.txt"
printf "initial\n" > "$TMPDIR/child-write-file.txt"
printf "child-secret\n" > "$TMPDIR/child-secret.txt"

printf "tool-dir-read\n" > "$TMPDIR/tool-read-dir/read.txt"
printf "tool-file-read\n" > "$TMPDIR/tool-read-file.txt"
printf "initial\n" > "$TMPDIR/tool-write-file.txt"
printf "tool-raw-secret\n" > "$TMPDIR/tool-raw-secret.txt"
printf "tool-env-secret\n" > "$TMPDIR/tool-env-secret.txt"
printf "outer-only\n" > "$TMPDIR/tool-outer-only/secret.txt"

CHILD_PROFILE="$TMPDIR/child-profile.json"
TOOL_PROFILE="$TMPDIR/tool-profile.json"
TOOL_NO_GRANTS_PROFILE="$TMPDIR/tool-no-grants-profile.json"
TOOL_NO_CREDENTIAL_USE_PROFILE="$TMPDIR/tool-no-credential-use-profile.json"

cat > "$CHILD_PROFILE" <<EOF
{
  "meta": {
    "name": "integration-child-boundary",
    "description": "Integration fixture for primary child sandbox boundaries"
  },
  "workdir": { "access": "none" },
  "filesystem": {
    "allow": ["$TMPDIR/child-dir"]
  },
  "environment": {
    "allow_vars": ["PATH", "HOME", "CHILD_ALLOWED", "CHILD_DENIED"],
    "deny_vars": ["CHILD_DENIED"]
  },
  "env_credentials": {
    "file://$TMPDIR/child-secret.txt": "CHILD_SECRET"
  }
}
EOF

cat > "$TOOL_PROFILE" <<EOF
{
  "meta": {
    "name": "integration-tool-boundary",
    "description": "Integration fixture for ETI tool sandbox boundaries"
  },
  "workdir": { "access": "none" },
  "command_policies": {
    "entrypoint": "sh",
    "credentials": {
      "raw_secret": {
        "type": "raw-file",
        "path": "$TMPDIR/tool-raw-secret.txt"
      }
    },
    "commands": {
      "sh": {
        "executable": "/bin/sh",
        "sandbox": {
          "fs_read": ["$TMPDIR/tool-read-dir"],
          "fs_write": ["$TMPDIR/tool-write-dir"],
          "fs_read_file": ["$TMPDIR/tool-read-file.txt"],
          "fs_write_file": ["$TMPDIR/tool-write-file.txt"],
          "use_credentials": ["raw_secret"],
          "environment": {
            "allow_vars": ["PATH", "HOME", "TOOL_ALLOWED", "TOOL_SECRET"],
            "set_vars": {
              "TOOL_SET": "tool-set"
            }
          }
        }
      }
    }
  }
}
EOF

cat > "$TOOL_NO_GRANTS_PROFILE" <<EOF
{
  "meta": {
    "name": "integration-tool-no-grants",
    "description": "Integration fixture proving ETI does not inherit outer path grants"
  },
  "workdir": { "access": "none" },
  "command_policies": {
    "entrypoint": "sh",
    "commands": {
      "sh": {
        "executable": "/bin/sh",
        "sandbox": {
          "environment": {
            "allow_vars": ["PATH", "HOME"]
          }
        }
      }
    }
  }
}
EOF

cat > "$TOOL_NO_CREDENTIAL_USE_PROFILE" <<EOF
{
  "meta": {
    "name": "integration-tool-no-credential-use",
    "description": "Integration fixture proving raw-file credentials are opt-in"
  },
  "workdir": { "access": "none" },
  "command_policies": {
    "entrypoint": "sh",
    "credentials": {
      "raw_secret": {
        "type": "raw-file",
        "path": "$TMPDIR/tool-raw-secret.txt"
      }
    },
    "commands": {
      "sh": {
        "executable": "/bin/sh",
        "sandbox": {
          "environment": {
            "allow_vars": ["PATH", "HOME"]
          }
        }
      }
    }
  }
}
EOF

echo ""
echo "Test directory: $TMPDIR"
echo ""

expect_exact_output() {
    local name="$1"
    local expected="$2"
    shift 2

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    actual=$?
    set -e

    if [[ "$actual" -eq 0 && "$output" == "$expected" ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected exit 0 with output: '$expected'"
    echo "       Got exit $actual with output: '$output'"
    echo "       Command: $*"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 0
}

expect_file_content() {
    local name="$1"
    local path="$2"
    local expected="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    local actual=""
    if [[ -f "$path" ]]; then
        actual="$(<"$path")"
    fi

    if [[ "$actual" == "$expected" ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected file '$path' to contain: '$expected'"
    echo "       Actual content: '$actual'"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 0
}

expect_output_payload() {
    local name="$1"
    local expected="$2"
    shift 2

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    actual=$?
    set -e

    if [[ "$actual" -eq 0 && "$output" == *"$expected"* ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected exit 0 with output containing: '$expected'"
    echo "       Got exit $actual with output: '$output'"
    echo "       Command: $*"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 0
}

run_in_dir() {
    local dir="$1"
    shift

    cd "$dir" && "$@"
}

# =============================================================================
# Primary Child Sandbox
# =============================================================================

echo "--- Primary Child Sandbox ---"

expect_exact_output "child sandbox reads granted directory file" "child-dir-read" \
    "$NONO_BIN" run --silent --no-audit --allow-cwd --allow "$TMPDIR/child-dir" -- \
    sh -c 'IFS= read -r value < "$1"; printf "%s" "$value"' sh "$TMPDIR/child-dir/read.txt"

expect_success "child sandbox writes granted directory file" \
    "$NONO_BIN" run --silent --no-audit --allow-cwd --allow "$TMPDIR/child-dir" -- \
    sh -c 'printf "%s" "child-dir-write" > "$1"' sh "$TMPDIR/child-dir/written.txt"
expect_file_content "child sandbox directory write reached host file" \
    "$TMPDIR/child-dir/written.txt" "child-dir-write"

expect_exact_output "child sandbox reads granted single file" "child-file-read" \
    "$NONO_BIN" run --silent --no-audit --allow-cwd --read-file "$TMPDIR/child-read-file.txt" -- \
    sh -c 'IFS= read -r value < "$1"; printf "%s" "$value"' sh "$TMPDIR/child-read-file.txt"

expect_success "child sandbox writes granted single file" \
    "$NONO_BIN" run --silent --no-audit --allow-cwd --write-file "$TMPDIR/child-write-file.txt" -- \
    sh -c 'printf "%s" "child-file-write" > "$1"' sh "$TMPDIR/child-write-file.txt"
expect_file_content "child sandbox single-file write reached host file" \
    "$TMPDIR/child-write-file.txt" "child-file-write"

expect_exact_output "child sandbox filters env and injects file credential" "child-visible|unset|child-secret" \
    env CHILD_ALLOWED=child-visible CHILD_DENIED=child-hidden \
    "$NONO_BIN" run --profile "$CHILD_PROFILE" --silent --no-audit -- \
    sh -c 'printf "%s|%s|%s" "$CHILD_ALLOWED" "${CHILD_DENIED-unset}" "$CHILD_SECRET"'

# =============================================================================
# ETI Tool Sandbox
# =============================================================================

echo ""
echo "--- Tool Sandbox ---"

expect_output_payload "tool sandbox applies scoped fs env and credentials" \
    "tool-dir-read|tool-file-read|tool-raw-secret|tool-visible|tool-set|unset|tool-env-secret" \
    run_in_dir "$TMPDIR" env TOOL_ALLOWED=tool-visible TOOL_BLOCKED=tool-hidden \
    "$NONO_BIN" run --profile "$TOOL_PROFILE" --silent --no-audit --allow-cwd \
    --env-credential-map "file://$TMPDIR/tool-env-secret.txt" TOOL_SECRET -- \
    sh -c '
        IFS= read -r dir_value < "$1"
        IFS= read -r file_value < "$2"
        IFS= read -r raw_secret < "$5"
        printf "%s" "$dir_value|$file_value|$raw_secret|$TOOL_ALLOWED|$TOOL_SET|${TOOL_BLOCKED-unset}|$TOOL_SECRET"
        printf "%s" "tool-dir-write" > "$3"
        printf "%s" "tool-file-write" > "$4"
    ' sh \
    "$TMPDIR/tool-read-dir/read.txt" \
    "$TMPDIR/tool-read-file.txt" \
    "$TMPDIR/tool-write-dir/written.txt" \
    "$TMPDIR/tool-write-file.txt" \
    "$TMPDIR/tool-raw-secret.txt"

expect_file_content "tool sandbox directory write reached host file" \
    "$TMPDIR/tool-write-dir/written.txt" "tool-dir-write"
expect_file_content "tool sandbox single-file write reached host file" \
    "$TMPDIR/tool-write-file.txt" "tool-file-write"

if is_macos; then
    skip_test "tool sandbox does not inherit outer --allow directory" "macOS temp path denial is host-dependent"
    skip_test "tool sandbox raw-file credential requires use_credentials" "macOS temp path denial is host-dependent"
else
    expect_failure "tool sandbox does not inherit outer --allow directory" \
        run_in_dir "$TMPDIR" "$NONO_BIN" run --profile "$TOOL_NO_GRANTS_PROFILE" --silent --no-audit --allow-cwd \
        --allow "$TMPDIR/tool-outer-only" -- \
        sh -c 'IFS= read -r value < "$1" || exit 77; printf "%s" "$value"' sh "$TMPDIR/tool-outer-only/secret.txt"

    expect_failure "tool sandbox raw-file credential requires use_credentials" \
        run_in_dir "$TMPDIR" "$NONO_BIN" run --profile "$TOOL_NO_CREDENTIAL_USE_PROFILE" --silent --no-audit --allow-cwd -- \
        sh -c 'IFS= read -r value < "$1" || exit 77; printf "%s" "$value"' sh "$TMPDIR/tool-raw-secret.txt"
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
