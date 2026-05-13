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
    local drift_arr="["
    for i in "${!DRIFT_FILES[@]}"; do
        [[ $i -gt 0 ]] && drift_arr+=','
        # Escape quotes in text
        local escaped_text="${DRIFT_TEXT[$i]//\"/\\\"}"
        drift_arr+="{\"file\":\"${DRIFT_FILES[$i]}\",\"line\":${DRIFT_LINES[$i]},\"text\":\"${escaped_text}\"}"
    done
    drift_arr+="]"

    local status
    status=$([ "$DRIFT_COUNT" -eq 0 ] && echo "clean" || echo "drift")

    printf '{"status":"%s","drift_count":%d,"drift":%s}\n' \
        "$status" "$DRIFT_COUNT" "$drift_arr"
}

case "$FORMAT" in
    table) emit_table ;;
    json)  emit_json ;;
esac

if [[ "$DRIFT_COUNT" -gt 0 ]]; then
    exit 1
fi

exit 0
