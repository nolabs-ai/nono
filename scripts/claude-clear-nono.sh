#!/usr/bin/env bash
# Clean up nono-managed Claude Code state for a fresh test of
# `nono run --profile always-further/claude -- claude`. Removes:
#   - the pulled pack at ~/.config/nono/packages/always-further/claude
#   - any leftover legacy symlink at ~/.config/nono/profiles/claude-code.json
#   - the bare pre-marketplace symlink at ~/.claude/plugins/nono
#   - the synthesised marketplace at ~/.claude/plugins/marketplaces/always-further
#   - the cache dir at ~/.claude/plugins/cache/always-further
#   - the `always-further/claude` entry from
#     ~/.config/nono/packages/lockfile.json (so `nono pull` re-installs
#     instead of short-circuiting on "already up to date")
#   - the `nono@always-further` and bare `nono` entries in
#     ~/.claude/plugins/installed_plugins.json,
#     ~/.claude/plugins/known_marketplaces.json,
#     ~/.claude/settings.json (enabledPlugins keys)

set -euo pipefail

rm -f  "$HOME/.config/nono/profiles/claude-code.json" 2>/dev/null || true
rm -rf "$HOME/.config/nono/packages/always-further/claude" 2>/dev/null || true
rm -rf "$HOME/.claude/plugins/nono" 2>/dev/null || true
rm -rf "$HOME/.claude/plugins/marketplaces/always-further" 2>/dev/null || true
rm -rf "$HOME/.claude/plugins/cache/always-further" 2>/dev/null || true

if ! command -v jq >/dev/null 2>&1; then
    echo "warning: jq not installed; skipping JSON registry cleanup." >&2
    echo "         hand-edit if needed:" >&2
    echo "         - ~/.claude/settings.json::enabledPlugins[\"nono@always-further\"]" >&2
    echo "         - ~/.claude/plugins/installed_plugins.json::plugins[\"nono@always-further\"]" >&2
    echo "         - ~/.claude/plugins/known_marketplaces.json[\"always-further\"]" >&2
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
    'del(.enabledPlugins["nono@always-further"]) | del(.enabledPlugins.nono)'
strip_with_jq "$HOME/.claude/plugins/installed_plugins.json" \
    'del(.plugins["nono@always-further"])'
strip_with_jq "$HOME/.claude/plugins/known_marketplaces.json" \
    'del(."always-further")'
strip_with_jq "$HOME/.config/nono/packages/lockfile.json" \
    'del(.packages["always-further/claude"])'

echo "cleared nono-managed Claude Code state."
