#!/usr/bin/env bash
# Run Claude with a PATH-prepended `open` wrapper to determine whether the
# login flow resolves `open` via PATH or calls `/usr/bin/open` directly.
#
# Usage:
#   ./scripts/probe-claude-open-path.sh
# Then trigger login inside Claude. After exiting, inspect the printed log path.

set -euo pipefail

if [[ "${OSTYPE:-}" != darwin* ]]; then
    echo "This script is macOS-only." >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NONO_BIN="${NONO_BIN:-$ROOT_DIR/target/debug/nono}"
CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude || true)}"
TMP_BASE="${TMPDIR:-/tmp}"
PROBE_DIR="$(mktemp -d "$TMP_BASE/nono-open-probe.XXXXXX")"
WRAPPER_LOG="$PROBE_DIR/open-wrapper.log"
OPEN_WRAPPER="$PROBE_DIR/open"

cleanup() {
    echo
    echo "Probe directory: $PROBE_DIR"
    echo "Wrapper log: $WRAPPER_LOG"
}
trap cleanup EXIT

if [[ ! -x "$NONO_BIN" ]]; then
    echo "nono binary not found or not executable: $NONO_BIN" >&2
    echo "Build it first with: cargo build -p nono-cli" >&2
    exit 1
fi

if [[ -z "$CLAUDE_BIN" || ! -x "$CLAUDE_BIN" ]]; then
    echo "claude binary not found or not executable: ${CLAUDE_BIN:-<empty>}" >&2
    echo "Set CLAUDE_BIN=/absolute/path/to/claude and retry." >&2
    exit 1
fi

cat >"$OPEN_WRAPPER" <<'EOF'
#!/bin/sh
log_file="${NONO_OPEN_WRAPPER_LOG:-/tmp/nono-open-wrapper.log}"
{
    printf 'pid=%s argc=%s\n' "$$" "$#"
    i=1
    for arg in "$@"; do
        printf 'arg[%s]=%s\n' "$i" "$arg"
        i=$((i + 1))
    done
    printf '\n'
} >>"$log_file"
exec /usr/bin/open "$@"
EOF

chmod 755 "$OPEN_WRAPPER"

echo "Starting Claude with PATH wrapper."
echo "Trigger login, then exit Claude."
echo "If the wrapper log stays empty, Claude is not resolving \`open\` through PATH."
echo "Claude binary: $CLAUDE_BIN"
echo

env \
    PATH="$PROBE_DIR:$PATH" \
    NONO_OPEN_WRAPPER_LOG="$WRAPPER_LOG" \
    "$NONO_BIN" run --profile always-further/claude --allow-cwd --allow-launch-services \
    --read-file "$CLAUDE_BIN" -- \
    "$CLAUDE_BIN"
