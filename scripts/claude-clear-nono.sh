#!/usr/bin/env bash
# Clean up nono-managed Claude Code state for a fresh test of
# `nono run --profile nolabs-ai/claude -- claude`. Removes:
#   - the pulled pack at $XDG_CONFIG_HOME/nono/packages/nolabs-ai/claude
#   - any leftover legacy symlink at $XDG_CONFIG_HOME/nono/profiles/claude-code.json
#   - the bare pre-marketplace symlink at ~/.claude/plugins/nono
#   - the synthesised marketplace at ~/.claude/plugins/marketplaces/nolabs-ai
#   - the cache dir at ~/.claude/plugins/cache/nolabs-ai
#   - the `nolabs-ai/claude` entry from
#     $XDG_CONFIG_HOME/nono/packages/lockfile.json (so `nono pull` re-installs
#     instead of short-circuiting on "already up to date")
#   - the `nono@nolabs-ai` and bare `nono` entries in
#     ~/.claude/plugins/installed_plugins.json,
#     ~/.claude/plugins/known_marketplaces.json,
#     ~/.claude/settings.json (enabledPlugins keys)

set -euo pipefail

NONO_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/nono"

rm -f  "$NONO_CONFIG/profiles/claude-code.json" 2>/dev/null || true
rm -rf "$NONO_CONFIG/packages/nolabs-ai/claude" 2>/dev/null || true
rm -rf "$HOME/.claude/plugins/nono" 2>/dev/null || true
rm -rf "$HOME/.claude/plugins/marketplaces/nolabs-ai" 2>/dev/null || true
rm -rf "$HOME/.claude/plugins/cache/nolabs-ai" 2>/dev/null || true

if ! command -v jq >/dev/null 2>&1; then
    echo "warning: jq not installed; skipping JSON registry cleanup." >&2
    echo "         hand-edit if needed:" >&2
    echo "         - ~/.claude/settings.json::enabledPlugins[\"nono@nolabs-ai\"]" >&2
    echo "         - ~/.claude/plugins/installed_plugins.json::plugins[\"nono@nolabs-ai\"]" >&2
    echo "         - ~/.claude/plugins/known_marketplaces.json[\"nolabs-ai\"]" >&2
    exit 0
fi

strip_with_jq() {
    local path="$1" filter="$2"
    [ -f "$path" ] || return 0
    local tmp
    tmp="$(mktemp)"
    if jq "$filter" "$path" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$path"
    else
        rm -f "$tmp"
        echo "warning: jq filter failed on $path; left unchanged." >&2
    fi
}

strip_with_jq "$HOME/.claude/settings.json" \
    'del(.enabledPlugins["nono@nolabs-ai"]) | del(.enabledPlugins.nono)'
strip_with_jq "$HOME/.claude/plugins/installed_plugins.json" \
    'del(.plugins["nono@nolabs-ai"])'
strip_with_jq "$HOME/.claude/plugins/known_marketplaces.json" \
    'del(."nolabs-ai")'
strip_with_jq "$NONO_CONFIG/packages/lockfile.json" \
    'del(.packages["nolabs-ai/claude"])'

echo "cleared nono-managed Claude Code state."
