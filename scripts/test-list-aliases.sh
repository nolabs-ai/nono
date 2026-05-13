#!/usr/bin/env bash
# scripts/test-list-aliases.sh
# Inventories legacy profile-schema alias usage vs canonical names.
# Reports any remaining "override_deny" JSON data keys in built-in profile
# data; clap visible_alias occurrences are expected per D-36-B3 and are
# reported informatively (NOT a failure).
#
# Design source (D-20 manual replay): f0abd413 (upstream v0.47.0)
# Plan 36-01d: alias inventory enforcement tooling
#
# Usage:
#   bash scripts/test-list-aliases.sh
#   bash scripts/test-list-aliases.sh --format json
#
# Exit codes:
#   0  No unmarked JSON-data drift found (clean state).
#   1  One or more "override_deny" JSON keys found in data files — lint failure.
#   2  Bad argument.

set -euo pipefail
export LC_ALL=C.UTF-8 2>/dev/null || true

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

print_usage() {
    cat <<'USAGE'
Usage: scripts/test-list-aliases.sh [--format table|json]

Inventories legacy profile-schema alias usage vs canonical names.
  - JSON data files (crates/nono-cli/data/): override_deny keys are a FAILURE.
  - Rust source (crates/nono-cli/src/): visible_alias = "override-deny" are
    EXPECTED per D-36-B3 indefinite-acceptance posture (reported, not failed).

Options:
  --format table   Human-readable output (default)
  --format json    JSON output for CI consumers
  -h, --help       Show this message

Exit codes:
  0  No JSON-data drift (clean state)
  1  Unmarked JSON data drift found
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
# Locate repo root (works from any subdirectory)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Scan JSON data files for legacy override_deny keys (FAILURE condition)
# ---------------------------------------------------------------------------
DATA_DIR="${REPO_ROOT}/crates/nono-cli/data"

JSON_DRIFT_FILES=()
JSON_DRIFT_LINES=()

if [[ -d "$DATA_DIR" ]]; then
    while IFS= read -r match; do
        # match format: file:line:content
        file="${match%%:*}"
        rest="${match#*:}"
        lineno="${rest%%:*}"
        content="${rest#*:}"

        # Skip nono-profile.schema.json: it intentionally defines "override_deny"
        # as a documented legacy property per D-36-B3. Schema property definitions
        # are not data-drift; they are schema meta-documentation. The description
        # field on the override_deny schema property explicitly cites D-36-B3.
        if [[ "$file" == *"nono-profile.schema.json"* ]]; then
            continue
        fi

        # Skip lines where the content itself already contains a D-36-B3 marker
        # (belt-and-suspenders for any future schema-adjacent data files).
        if echo "$content" | grep -qE 'Legacy|Deprecated|D-36-B3'; then
            continue
        fi

        JSON_DRIFT_FILES+=("$file")
        JSON_DRIFT_LINES+=("$lineno")
    done < <(grep -rn '"override_deny"' "$DATA_DIR" --include="*.json" 2>/dev/null || true)
fi

# ---------------------------------------------------------------------------
# Scan Rust source for clap visible_alias (INFORMATIONAL — expected per D-36-B3)
# ---------------------------------------------------------------------------
SRC_DIR="${REPO_ROOT}/crates/nono-cli/src"

RUST_ALIAS_FILES=()
RUST_ALIAS_LINES=()

if [[ -d "$SRC_DIR" ]]; then
    while IFS= read -r match; do
        file="${match%%:*}"
        rest="${match#*:}"
        lineno="${rest%%:*}"
        RUST_ALIAS_FILES+=("$file")
        RUST_ALIAS_LINES+=("$lineno")
    done < <(grep -rn 'visible_alias.*=.*"override-deny"\|alias.*=.*"override.deny"' "$SRC_DIR" --include="*.rs" 2>/dev/null || true)
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

JSON_COUNT="${#JSON_DRIFT_FILES[@]}"
RUST_COUNT="${#RUST_ALIAS_FILES[@]}"

emit_table() {
    if [[ "$JSON_COUNT" -eq 0 ]]; then
        printf 'OK: No legacy override_deny JSON data keys found in %s\n' "$DATA_DIR"
    else
        printf 'FAIL: Found %d legacy override_deny JSON data key(s):\n' "$JSON_COUNT"
        for i in "${!JSON_DRIFT_FILES[@]}"; do
            printf '  %s:%s\n' "${JSON_DRIFT_FILES[$i]}" "${JSON_DRIFT_LINES[$i]}"
        done
        printf '\nAction: rename "override_deny" to "bypass_protection" in each listed file.\n'
        printf 'Legacy key acceptance (D-36-B3) applies to runtime deserialization only;\n'
        printf 'the JSON data files themselves must use the canonical key.\n'
    fi

    if [[ "$RUST_COUNT" -gt 0 ]]; then
        printf '\nINFO: %d expected clap visible_alias for --override-deny (D-36-B3):\n' "$RUST_COUNT"
        for i in "${!RUST_ALIAS_FILES[@]}"; do
            printf '  %s:%s\n' "${RUST_ALIAS_FILES[$i]}" "${RUST_ALIAS_LINES[$i]}"
        done
        printf '(These are intentional per D-36-B3 indefinite CLI alias acceptance.)\n'
    fi
}

emit_json() {
    # Build JSON arrays for drift findings
    local json_arr="["
    for i in "${!JSON_DRIFT_FILES[@]}"; do
        [[ $i -gt 0 ]] && json_arr+=','
        json_arr+="{\"file\":\"${JSON_DRIFT_FILES[$i]}\",\"line\":${JSON_DRIFT_LINES[$i]}}"
    done
    json_arr+="]"

    local rust_arr="["
    for i in "${!RUST_ALIAS_FILES[@]}"; do
        [[ $i -gt 0 ]] && rust_arr+=','
        rust_arr+="{\"file\":\"${RUST_ALIAS_FILES[$i]}\",\"line\":${RUST_ALIAS_LINES[$i]}}"
    done
    rust_arr+="]"

    local status
    status=$([ "$JSON_COUNT" -eq 0 ] && echo "clean" || echo "drift")

    printf '{"status":"%s","json_data_drift":%s,"rust_aliases_expected":%s}\n' \
        "$status" "$json_arr" "$rust_arr"
}

case "$FORMAT" in
    table) emit_table ;;
    json)  emit_json ;;
esac

# Exit non-zero if JSON data drift found
if [[ "$JSON_COUNT" -gt 0 ]]; then
    exit 1
fi

exit 0
