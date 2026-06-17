#!/usr/bin/env bash
# Diagnose browser-opening behavior on macOS outside and inside nono.
#
# This runs a small matrix of increasingly sandboxed `open` invocations and
# records:
# - the exact command
# - the exit status
# - whether nono's macOS URL debug log was touched
#
# It intentionally uses `open -g` to avoid focusing the browser window.

set -euo pipefail

if [[ "${OSTYPE:-}" != darwin* ]]; then
    echo "This script is macOS-only." >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NONO_BIN="${NONO_BIN:-$ROOT_DIR/target/debug/nono}"
URL="${1:-https://claude.ai}"
TMP_BASE="${TMPDIR:-/tmp}"
LOG_FILE="$TMP_BASE/nono-macos-open-diagnose.log"
DEBUG_LOG="$TMP_BASE/nono-open-url-debug.log"

if [[ ! -x "$NONO_BIN" ]]; then
    echo "nono binary not found or not executable: $NONO_BIN" >&2
    echo "Build it first with: cargo build -p nono-cli" >&2
    exit 1
fi

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    printf '[%s] %s\n' "$(timestamp)" "$*" | tee -a "$LOG_FILE"
}

clear_logs() {
    rm -f "$DEBUG_LOG"
}

show_debug_log() {
    if [[ -f "$DEBUG_LOG" ]]; then
        log "debug-log: present at $DEBUG_LOG"
        while IFS= read -r line; do
            log "debug-log: $line"
        done <"$DEBUG_LOG"
    else
        log "debug-log: not created"
    fi
}

run_step() {
    local name="$1"
    shift

    clear_logs
    log "===== $name ====="
    log "command: $*"

    set +e
    "$@" >>"$LOG_FILE" 2>&1
    local rc=$?
    set -e

    log "exit-status: $rc"
    show_debug_log
    log ""
}

log "Starting macOS browser-open diagnostics"
log "root-dir: $ROOT_DIR"
log "nono-bin: $NONO_BIN"
log "url: $URL"
log "tmp-base: $TMP_BASE"
log ""

run_step \
    "outside-sandbox absolute-open" \
    /usr/bin/open -g "$URL"

run_step \
    "outside-sandbox path-open" \
    open -g "$URL"

run_step \
    "nono no-profile absolute-open" \
    "$NONO_BIN" run --allow-cwd --net-allow -- /usr/bin/open -g "$URL"

run_step \
    "nono claude-profile absolute-open" \
    "$NONO_BIN" run --profile always-further/claude --allow-cwd -- /usr/bin/open -g "$URL"

run_step \
    "nono claude-profile path-open" \
    "$NONO_BIN" run --profile always-further/claude --allow-cwd -- open -g "$URL"

run_step \
    "nono claude-profile absolute-open with lsopen" \
    "$NONO_BIN" run --profile always-further/claude --allow-cwd --allow-launch-services -- \
    /usr/bin/open -g "$URL"

run_step \
    "nono claude-profile path-open with lsopen" \
    "$NONO_BIN" run --profile always-further/claude --allow-cwd --allow-launch-services -- \
    open -g "$URL"

log "Completed diagnostics. Full log: $LOG_FILE"
