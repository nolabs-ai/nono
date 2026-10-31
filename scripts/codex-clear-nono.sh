#!/usr/bin/env bash
# Clean up nono-managed Codex state for a fresh test of
# `nono run --profile nolabs-ai/codex -- codex --no-daemon
# --sandbox danger-full-access --ask-for-approval on-request`. Removes:
#   - the pulled pack at $XDG_CONFIG_HOME/nono/packages/nolabs-ai/codex
#   - the pack-owned marker at
#     $XDG_CONFIG_HOME/nono/profile-drafts/.nono-codex-pack-marker
#   - the cache subtree at ~/.codex/plugins/cache/nolabs-ai
#   - the nono-managed fenced block in ~/.codex/config.toml (between
#     the current `# >>> nono:nolabs-ai-codex >>>` markers, or the
#     legacy `# >>> nono-managed (do not edit) >>>` markers)
#   - current marketplace/cache wiring and ~/.codex/bin/nono-draft-profile
#   - legacy hook entries in ~/.codex/hooks.json whose command path
#     points into the nono pack store
#   - the `nolabs-ai/codex` entry from
#     $XDG_CONFIG_HOME/nono/packages/lockfile.json (so `nono pull` re-installs
#     instead of short-circuiting on "already up to date")
#
# Does NOT touch:
#   - your ~/.codex/config.toml outside the fenced block
#     (so your model, project trust, and any legacy user-set
#     `[features] codex_hooks = true` setting all stay)
#   - ~/.codex/auth.json or ~/.codex/sessions/*
#   - $XDG_CONFIG_HOME/nono/profiles/ (your own profiles)
# Legacy `always-further` state is also removed when present.

set -euo pipefail

NONO_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/nono"

PACK_STORE="$NONO_CONFIG/packages/nolabs-ai/codex"
LEGACY_PACK_STORE="$NONO_CONFIG/packages/always-further/codex"
CONFIG_TOML="$HOME/.codex/config.toml"
HOOKS_JSON="$HOME/.codex/hooks.json"
LOCKFILE="$NONO_CONFIG/packages/lockfile.json"

rm -rf "$PACK_STORE" 2>/dev/null || true
rm -rf "$LEGACY_PACK_STORE" 2>/dev/null || true
rm -f "$NONO_CONFIG/profile-drafts/.nono-codex-pack-marker" 2>/dev/null || true
rm -rf "$HOME/.codex/plugins/cache/nolabs-ai" 2>/dev/null || true
rm -rf "$HOME/.codex/plugins/cache/always-further" 2>/dev/null || true
# Synthesised marketplace dir nono owns (contains the marketplace.json
# Codex's loader requires + the symlink to the pack store).
rm -rf "$HOME/.codex/plugins/marketplaces/nolabs-ai" 2>/dev/null || true
rm -rf "$HOME/.codex/plugins/marketplaces/always-further" 2>/dev/null || true
rm -f "$HOME/.codex/bin/nono-draft-profile" 2>/dev/null || true

# Strip our fenced block from config.toml. Pure text edit — no TOML
# parser needed because we own the markers exactly.
if [ -f "$CONFIG_TOML" ]; then
    tmp="$(mktemp)"
    awk '
        BEGIN { in_block = 0 }
        /^# >>> nono-managed \(do not edit\) >>>/ { in_block = 1; next }
        /^# >>> nono:nolabs-ai-codex >>>/          { in_block = 1; next }
        /^# <<< nono-managed <<</                  { if (in_block) { in_block = 0; next } }
        /^# <<< nono:nolabs-ai-codex <<</          { if (in_block) { in_block = 0; next } }
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
# shellcheck disable=SC2016 # $prefix variables belong to jq, not the shell.
edit_with_jq "$HOOKS_JSON" \
    --arg prefix "$PACK_STORE" \
    --arg legacy_prefix "$LEGACY_PACK_STORE" \
    '
    .hooks |= (
        with_entries(
            .value |= (
                map(
                    .hooks |= map(select(.command | (startswith($prefix) or startswith($legacy_prefix)) | not))
                )
                | map(select(.hooks | length > 0))
            )
        )
        | with_entries(select(.value | length > 0))
    )
    '

edit_with_jq "$LOCKFILE" \
    'del(.packages["nolabs-ai/codex"]) | del(.packages["always-further/codex"])'

echo "cleared nono-managed Codex state."
