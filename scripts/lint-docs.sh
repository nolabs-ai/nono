#!/usr/bin/env bash
# scripts/lint-docs.sh
# Checks documentation files for unmarked legacy alias references.
# Scans docs/cli/**/*.mdx for "override_deny" and "override-deny" occurrences
# that are NOT on lines already containing a marker word.
#
# Design source (D-20 manual replay): f0abd413 (upstream v0.47.0)
# Plan 36-01d: docs alias-inventory check tooling
#
# Marker words that allow legacy references on the same line:
#   Legacy | Deprecated | D-36-B3
#
# Usage:
#   bash scripts/lint-docs.sh
#   bash scripts/lint-docs.sh --format json
#
# Exit codes:
#   0  No unmarked legacy references found (clean state).
#   1  Unmarked legacy alias drift found — file:line listed to stdout.
#   2  Bad argument.

set -euo pipefail
export LC_ALL=C.UTF-8 2>/dev/null || true

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

print_usage() {
    cat <<'USAGE'
Usage: scripts/lint-docs.sh [--format table|json]

Checks documentation files for unmarked legacy alias references.
Scans docs/cli/**/*.mdx for "override_deny" / "override-deny" occurrences.

Lines containing any of these marker words are ALLOWED:
  Legacy | Deprecated | D-36-B3

Options:
  --format table   Human-readable output (default)
  --format json    JSON output for CI consumers
  -h, --help       Show this message

Exit codes:
  0  No unmarked legacy drift (clean)
  1  Unmarked legacy drift found
  2  Bad argument
USAGE
}

FORMAT="table"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --format) FORMAT="$2"; shift 2 ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

case "$FORMAT" in
    table|json) ;;
    *) echo "Error: --format must be 'table' or 'json' (got: $FORMAT)" >&2; exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Locate repo root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Scan docs for legacy references
# ---------------------------------------------------------------------------
DOCS_DIR="${REPO_ROOT}/docs"

DRIFT_FILES=()
DRIFT_LINES=()
DRIFT_TEXT=()

if [[ -d "$DOCS_DIR" ]]; then
    # Find all .mdx files under docs/cli/
    while IFS= read -r mdx_file; do
        # Read file line-by-line, check for override_deny / override-deny
        lineno=0
        while IFS= read -r line; do
            lineno=$((lineno + 1))
            # Check if line contains legacy alias
            if echo "$line" | grep -qE 'override_deny|override-deny'; then
                # Check if line contains a marker word (allowed)
                if echo "$line" | grep -qE 'Legacy|Deprecated|D-36-B3'; then
                    # Marked reference — allowed
                    :
                else
                    # Unmarked legacy reference — drift
                    rel_file="${mdx_file#${REPO_ROOT}/}"
                    DRIFT_FILES+=("$rel_file")
                    DRIFT_LINES+=("$lineno")
                    DRIFT_TEXT+=("$line")
                fi
            fi
        done < "$mdx_file"
    done < <(find "$DOCS_DIR/cli" -name "*.mdx" 2>/dev/null | sort)
fi

# Also scan profile-authoring-guide.md for unmarked legacy refs
GUIDE="${REPO_ROOT}/crates/nono-cli/data/profile-authoring-guide.md"
if [[ -f "$GUIDE" ]]; then
    lineno=0
    while IFS= read -r line; do
        lineno=$((lineno + 1))
        if echo "$line" | grep -qE 'override_deny|override-deny'; then
            if ! echo "$line" | grep -qE 'Legacy|Deprecated|D-36-B3'; then
                rel_file="crates/nono-cli/data/profile-authoring-guide.md"
                DRIFT_FILES+=("$rel_file")
                DRIFT_LINES+=("$lineno")
                DRIFT_TEXT+=("$line")
            fi
        fi
    done < "$GUIDE"
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

DRIFT_COUNT="${#DRIFT_FILES[@]}"

emit_table() {
    if [[ "$DRIFT_COUNT" -eq 0 ]]; then
        printf 'OK: No unmarked legacy alias references found in documentation.\n'
    else
        printf 'FAIL: Found %d unmarked legacy alias reference(s):\n\n' "$DRIFT_COUNT"
        for i in "${!DRIFT_FILES[@]}"; do
            printf '  %s:%d\n' "${DRIFT_FILES[$i]}" "${DRIFT_LINES[$i]}"
            printf '    %s\n\n' "${DRIFT_TEXT[$i]}"
        done
        printf 'Action: Add a marker word (Legacy, Deprecated, or D-36-B3) to each\n'
        printf 'listed line, or replace the legacy alias with the canonical name.\n'
        printf '\nAllowed marker words: Legacy | Deprecated | D-36-B3\n'
    fi
}

emit_json() {
    # WR-04 fix (REVIEW.md): the previous hand-rolled JSON escape only
    # handled double-quote characters, producing invalid JSON for lines
    # containing backslashes, control chars, or already-escaped quotes.
    # Delegate to python3 (or jq as a fallback) so the JSON encoder
    # handles every edge case correctly.
    local status
    if [[ "$DRIFT_COUNT" -eq 0 ]]; then
        status="clean"
    else
        status="drift"
    fi

    if command -v python3 >/dev/null 2>&1; then
        # Stream files / lines / texts as three null-separated arrays via
        # stdin so we don't hit argv length limits and we keep newline-free
        # framing.  python3 does the JSON encoding.
        {
            printf '%s\n' "$status"
            printf '%s\n' "$DRIFT_COUNT"
            printf '%s\0' "${DRIFT_FILES[@]}"
            printf '\n'
            printf '%s\0' "${DRIFT_LINES[@]}"
            printf '\n'
            printf '%s\0' "${DRIFT_TEXT[@]}"
            printf '\n'
        } | python3 -c '
import json
import sys

raw = sys.stdin.buffer.read()
parts = raw.split(b"\n", 4)
# parts[0]=status, parts[1]=count, parts[2]=files-z, parts[3]=lines-z, parts[4]=texts-z
status = parts[0].decode("utf-8", errors="replace")
count = int(parts[1].decode("utf-8", errors="replace"))


def split_z(blob: bytes) -> list[str]:
    if not blob:
        return []
    # trailing NUL produces an empty tail entry that we drop.
    items = blob.split(b"\0")
    if items and items[-1] == b"":
        items = items[:-1]
    return [item.decode("utf-8", errors="replace") for item in items]


files = split_z(parts[2]) if len(parts) > 2 else []
lines = split_z(parts[3]) if len(parts) > 3 else []
texts = split_z(parts[4]) if len(parts) > 4 else []

drift = []
for i, f in enumerate(files):
    drift.append({
        "file": f,
        "line": int(lines[i]) if i < len(lines) and lines[i] else 0,
        "text": texts[i] if i < len(texts) else "",
    })

print(json.dumps({"status": status, "drift_count": count, "drift": drift}))
'
        return
    fi

    if command -v jq >/dev/null 2>&1; then
        # jq fallback path. Build the drift array via repeated --arg pairs
        # so each text field is treated as a literal string (no shell
        # escape rules applied).
        local jq_args=(-n --arg status "$status" --argjson count "$DRIFT_COUNT")
        local jq_filter='{status: $status, drift_count: $count, drift: []}'
        for i in "${!DRIFT_FILES[@]}"; do
            jq_args+=(
                --arg "file_$i"  "${DRIFT_FILES[$i]}"
                --arg "line_$i"  "${DRIFT_LINES[$i]}"
                --arg "text_$i"  "${DRIFT_TEXT[$i]}"
            )
            jq_filter+=" | .drift += [{file: \$file_$i, line: (\$line_$i|tonumber), text: \$text_$i}]"
        done
        jq "${jq_args[@]}" "$jq_filter"
        return
    fi

    # No JSON encoder available — the CI script requires set -euo pipefail
    # and refuses to emit a malformed JSON document.  Fail loudly rather
    # than silently producing invalid JSON.
    echo 'lint-docs.sh: --format json requires either python3 or jq on PATH' >&2
    exit 3
}

case "$FORMAT" in
    table) emit_table ;;
    json)  emit_json ;;
esac

if [[ "$DRIFT_COUNT" -gt 0 ]]; then
    exit 1
fi

exit 0
