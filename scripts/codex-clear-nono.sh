#!/usr/bin/env bash
# Clean up nono-managed Codex state for a fresh test of
# `nono run --profile nolabs-ai/codex -- codex`. Removes:
#   - the pulled pack at $XDG_CONFIG_HOME/nono/packages/nolabs-ai/codex
#   - the cache subtree at ~/.codex/plugins/cache/nolabs-ai
#   - the nono-managed fenced block in ~/.codex/config.toml (between
#     the `# >>> nono-managed (do not edit) >>>` markers — registers
#     the marketplace and enables the plugin)
#   - hook entries in ~/.codex/hooks.json whose command path points
#     into the nono pack store
#   - the `nolabs-ai/codex` entry from
#     $XDG_CONFIG_HOME/nono/packages/lockfile.json (so `nono pull` re-installs
#     instead of short-circuiting on "already up to date")
#
# Does NOT touch:
#   - your ~/.codex/config.toml outside the fenced block
#     (so `[features] codex_hooks = true`, your model + project trust
#     settings, etc. all stay)
#   - ~/.codex/auth.json or ~/.codex/sessions/*
#   - $XDG_CONFIG_HOME/nono/profiles/ (your own profiles)

set -euo pipefail

NONO_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/nono"

PACK_STORE="$NONO_CONFIG/packages/nolabs-ai/codex"
CONFIG_TOML="$HOME/.codex/config.toml"
HOOKS_JSON="$HOME/.codex/hooks.json"
LOCKFILE="$NONO_CONFIG/packages/lockfile.json"

rm -rf "$PACK_STORE" 2>/dev/null || true
rm -rf "$HOME/.codex/plugins/cache/nolabs-ai" 2>/dev/null || true
# Synthesised marketplace dir nono owns (contains the marketplace.json
# Codex's loader requires + the symlink to the pack store).
rm -rf "$HOME/.codex/plugins/marketplaces/nolabs-ai" 2>/dev/null || true

# Strip our fenced block from config.toml. Pure text edit — no TOML
# parser needed because we own the markers exactly.
if [ -f "$CONFIG_TOML" ]; then
    tmp="$(mktemp)"
    awk '
        BEGIN { in_block = 0 }
        /^# >>> nono-managed \(do not edit\) >>>/ { in_block = 1; next }
        /^# <<< nono-managed <<</           { if (in_block) { in_block = 0; next } }
        { if (!in_block) print }
    ' "$CONFIG_TOML" > "$tmp" && mv "$tmp" "$CONFIG_TOML"
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "warning: jq not installed; skipping JSON registry cleanup." >&2
    echo "         hand-edit if needed:" >&2
    echo "         - $HOOKS_JSON (drop entries whose command starts with $PACK_STORE)" >&2
    echo "         - $LOCKFILE (drop nolabs-ai/codex)" >&2
    exit 0
fi

# Run jq with extra args, atomic-rewrite the file. First arg is the
# target path; remaining args are passed through to jq (filter + any
# --arg / --argjson). No-op if the file is missing.
edit_with_jq() {
    local path="$1"
    shift
    [ -f "$path" ] || return 0
    local tmp
    tmp="$(mktemp)"
    if jq "$@" "$path" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$path"
    else
        rm -f "$tmp"
        echo "warning: jq filter failed on $path; left unchanged." >&2
    fi
}

# Drop our hook entries from ~/.codex/hooks.json. Match by command-path
# prefix so only entries pointing into our pack store are removed; drop
# matchers and events that become empty as a result.
edit_with_jq "$HOOKS_JSON" \
    --arg prefix "$PACK_STORE" \
    '
    .hooks |= (
        with_entries(
            .value |= (
                map(
                    .hooks |= map(select(.command | startswith($prefix) | not))
                )
                | map(select(.hooks | length > 0))
            )
        )
        | with_entries(select(.value | length > 0))
    )
    '

edit_with_jq "$LOCKFILE" \
    'del(.packages["nolabs-ai/codex"])'

echo "cleared nono-managed Codex state."
