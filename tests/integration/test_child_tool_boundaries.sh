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

expect_file_contains() {
    local name="$1"
    local path="$2"
    local expected="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ -f "$path" ]] && grep -q "$expected" "$path"; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected file '$path' to contain: '$expected'"
    if [[ -f "$path" ]]; then
        echo "       Actual content: '$(<"$path")'"
    else
        echo "       File does not exist"
    fi
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 0
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

# --trust-override skips the trust scan, which is what otherwise leaves the
# aws-lc-rs pool threads behind and puts the supervised fork in
# ThreadingContext::CryptoExpected. Without it the fork runs under Strict,
# where a single stray thread started while preparing the tool-sandbox runtime
# aborts the run before the child ever execs.
expect_output_payload "tool sandbox forks under strict threading (--trust-override)" \
    "strict-threading-ok" \
    run_in_dir "$TMPDIR" "$NONO_BIN" run --profile "$TOOL_PROFILE" --silent --no-audit \
    --allow-cwd --trust-override -- \
    sh -c 'printf "%s" "strict-threading-ok"'

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
# Fire-and-forget chaining
# =============================================================================

echo ""
echo "--- Fire-and-forget Chaining ---"

FIRE_FORGET_DIR="$TMPDIR/fire-forget"
mkdir -p "$FIRE_FORGET_DIR"
FIRE_FORGET_PROFILE="$FIRE_FORGET_DIR/profile.json"

# Severed-caller attribution needs a platform lineage mechanism: session
# lineage on macOS, the cgroup marker on Linux — which requires a writable
# cgroup v2 base (mirrors lineage_cgroup::probe_writable_base). Without one,
# nono correctly fails closed and denies the orphaned child, so the scenario
# below cannot pass in e.g. a container with a read-only /sys/fs/cgroup.
fire_forget_lineage_available() {
    if [[ "$(uname)" != "Linux" ]]; then
        return 0
    fi
    local rel dir
    rel=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)
    dir="/sys/fs/cgroup${rel%/}"
    while [[ "$dir" == /sys/fs/cgroup* ]]; do
        if mkdir "$dir/nono-it-probe.$$" 2>/dev/null; then
            rmdir "$dir/nono-it-probe.$$" 2>/dev/null
            return 0
        fi
        [[ "$dir" == "/sys/fs/cgroup" ]] && return 1
        dir=$(dirname "$dir")
    done
    return 1
}

if fire_forget_lineage_available; then

# `parent` backgrounds `child` and exits immediately, so by the time `child`'s
# launch request is mediated, `parent` (its authorizing ancestor) has already
# been reaped and `child` is reparented to init. `child` must still resolve to
# `parent`'s policy edge rather than being denied as an unattributable caller.
cat > "$FIRE_FORGET_DIR/parent" <<'EOF'
#!/bin/sh
set -eu
echo "parent: launching child (fire & forget)"
child &
EOF
chmod 755 "$FIRE_FORGET_DIR/parent"

# Writes to the CWD (the workdir the shim forwards), not $(dirname "$0"):
# the Linux launcher execs the script through /dev/fd, so $0 is not a
# workdir-relative path there.
cat > "$FIRE_FORGET_DIR/child" <<'EOF'
#!/bin/sh
set -eu
echo "child: writing file"
echo "written by child at $(date)" > out.txt
EOF
chmod 755 "$FIRE_FORGET_DIR/child"

# Landlock can only grant write on an existing file, so pre-create it empty;
# the poll below waits for it to become non-empty, so this can't pass vacuously.
printf "" > "$FIRE_FORGET_DIR/out.txt"

# The system_write groups grant session write on /tmp and \$TMPDIR, where this
# suite's test dir lives; executable_dirs refuses any directory the session can
# write (the agent could swap the policied binaries). Excluding them here keeps
# the fixture under \$TMPDIR while matching the issue's real-world shape: a
# project directory the session cannot write.
cat > "$FIRE_FORGET_PROFILE" <<EOF
{
  "meta": { "name": "integration-fire-and-forget" },
  "workdir": { "access": "read" },
  "groups": { "exclude": ["system_write_linux", "system_write_macos"] },
  "command_policies": {
    "executable_dirs": ["."],
    "commands": {
      "parent": {
        "can_use": ["child"],
        "from": { "session": { "sandbox": { "fs_read": ["\$WORKDIR"] } } }
      },
      "child": {
        "can_use": ["date"],
        "from": {
          "parent": {
            "sandbox": {
              "fs_read": ["\$WORKDIR"],
              "fs_write_file": ["\$WORKDIR/out.txt"]
            }
          }
        }
      },
      "date": { "from": { "child": { "sandbox": {} } } }
    }
  }
}
EOF

# `child` itself launches further mediated subprocesses (`date`, `dirname`)
# before it writes out.txt, so poll for the file instead of guessing a fixed
# delay for the whole chain to finish; bounded to 5s total.
expect_success "outer session survives a fire-and-forget child launch (#1274)" \
    run_in_dir "$FIRE_FORGET_DIR" "$NONO_BIN" run --silent --no-audit --profile "$FIRE_FORGET_PROFILE" --allow-cwd -- \
    sh -c 'parent
i=0
while [ ! -s out.txt ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done'

expect_file_contains "fire-and-forget child was authorized under parent's policy edge (#1274)" \
    "$FIRE_FORGET_DIR/out.txt" "written by child at"

else
    skip_test "fire-and-forget chaining (#1274)" "no writable cgroup v2 base for lineage attribution"
fi

# =============================================================================
# Fire-and-forget from an unmediated launcher
# =============================================================================

echo ""
echo "--- Unmediated Fire-and-forget Launcher ---"

UNMEDIATED_DIR="$TMPDIR/unmediated-fire-forget"
mkdir -p "$UNMEDIATED_DIR"
UNMEDIATED_PROFILE="$UNMEDIATED_DIR/profile.json"

# The launcher is a plain fork of the session root, so nothing mediated it and
# no per-command lineage marker names it. Attribution then rests on the session
# nono created for its direct child, which exists only when nono allocated a pty
# (all three stdio a terminal), hence the python pty harness below. On Linux the
# cgroup marker attributes severed callers to commands only, never the session,
# so the scenario still fails closed there.
if [[ "$(uname)" == "Darwin" ]] && command_exists python3; then

cat > "$UNMEDIATED_DIR/launcher.sh" <<'EOF'
#!/bin/sh
set -eu
echo "launcher: firing child (fire & forget)"
child &
EOF
chmod 755 "$UNMEDIATED_DIR/launcher.sh"

cat > "$UNMEDIATED_DIR/child" <<'EOF'
#!/bin/sh
set -eu
echo "child: writing file"
echo "written by child at $(date)" > out.txt
EOF
chmod 755 "$UNMEDIATED_DIR/child"

# fs_write_file only grants an existing file, so pre-create it empty; the poll
# below waits for it to become non-empty, so this can't pass vacuously.
printf "" > "$UNMEDIATED_DIR/out.txt"

# pty.spawn's stdin copy loop never sees EOF under the suite's stdio, so drive
# the pty directly and drain it until the child closes the slave.
cat > "$UNMEDIATED_DIR/pty_run.py" <<'EOF'
import os
import pty
import select
import sys
import time

pid, master = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])

deadline = time.time() + 60
while time.time() < deadline:
    readable, _, _ = select.select([master], [], [], 0.2)
    if readable:
        try:
            if not os.read(master, 4096):
                break
        except OSError:
            break
    reaped, status = os.waitpid(pid, os.WNOHANG)
    if reaped:
        sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)

_, status = os.waitpid(pid, 0)
sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)
EOF

# `launcher.sh` is deliberately absent from `commands`: an unmediated launcher is
# the shape this case is about. Same group exclusions as the block above.
cat > "$UNMEDIATED_PROFILE" <<EOF
{
  "meta": { "name": "integration-unmediated-fire-and-forget" },
  "workdir": { "access": "read" },
  "groups": { "exclude": ["system_write_linux", "system_write_macos"] },
  "command_policies": {
    "executable_dirs": ["."],
    "commands": {
      "child": {
        "can_use": ["date"],
        "from": {
          "session": {
            "sandbox": {
              "fs_read": ["\$WORKDIR"],
              "fs_write_file": ["\$WORKDIR/out.txt"]
            }
          }
        }
      },
      "date": { "from": { "child": { "sandbox": {} } } },
      "sleep": { "from": { "session": { "sandbox": {} } } }
    }
  }
}
EOF

expect_success "outer session survives an unmediated fire-and-forget launcher (#1274)" \
    run_in_dir "$UNMEDIATED_DIR" python3 "$UNMEDIATED_DIR/pty_run.py" \
    "$NONO_BIN" run --silent --no-audit --profile "$UNMEDIATED_PROFILE" --allow-cwd -- \
    sh -c './launcher.sh
i=0
while [ ! -s out.txt ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done'

expect_file_contains "unmediated launcher's orphan was authorized under the session policy (#1274)" \
    "$UNMEDIATED_DIR/out.txt" "written by child at"

else
    skip_test "unmediated fire-and-forget launcher (#1274)" \
        "session-lineage attribution is macOS-only and needs python3 for a pty"
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
