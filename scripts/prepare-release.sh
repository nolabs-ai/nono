#!/usr/bin/env bash
# Prepare a nono release PR. See docs/maintainers/releasing.md.
set -euo pipefail

readonly CORE_MANIFEST="crates/nono/Cargo.toml"
readonly PROXY_MANIFEST="crates/nono-proxy/Cargo.toml"
readonly CLI_MANIFEST="crates/nono-cli/Cargo.toml"
readonly FFI_MANIFEST="bindings/c/Cargo.toml"
DRY_RUN=false
REQUESTED_VERSION=""

usage() {
    cat <<'EOF'
Usage: ./scripts/prepare-release.sh [--dry-run] [VERSION]

Prepare the version and changelog changes for a release PR.
VERSION must be SemVer without a leading "v" (for example 0.78.0 or 0.78.0-rc.1).

Options:
  --dry-run  Validate and show planned changes without modifying the worktree.
  -h, --help Show this help text.
EOF
}
die() { echo "Error: $*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
manifest_version() { awk -F'"' '/^version = "/ { print $2; exit }' "$1"; }
dependency_version() {
    sed -nE "s/^$2 = \{ version = \"([^\"]+)\".*/\1/p" "$1" | head -n 1
}

is_semver() {
    local version="$1" prerelease identifier
    [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]] || return 1
    prerelease="${version#*-}"
    [[ "$prerelease" == "$version" ]] && return 0
    prerelease="${prerelease%%+*}"
    IFS='.' read -r -a identifiers <<< "$prerelease"
    for identifier in "${identifiers[@]}"; do
        [[ "$identifier" =~ ^[0-9]+$ && "$identifier" =~ ^0[0-9]+$ ]] && return 1
    done
}
latest_tag() { git describe --tags --abbrev=0 2>/dev/null || true; }
latest_release_commit() {
    git log --first-parent --format='%H' --fixed-strings --grep="chore: release v$1" HEAD | head -n 1
}

next_version_from_commits() {
    local current_version="$1" release_base="$2" range commits major minor patch
    IFS='.' read -r major minor patch <<< "$current_version"
    [[ -n "$major" && -n "$minor" && -n "$patch" ]] || die "automatic bumps require a stable current version; supply VERSION explicitly"
    range="${release_base}..HEAD"
    commits=$(git log --format='%s' "$range")

    # Releases remain in the 0.x series until a coordinator explicitly selects
    # 1.0.0. Conventional feat commits therefore bump minor even when marked
    # breaking; fix-only releases bump patch.
    if printf '%s\n' "$commits" | grep -Eq '^feat(\([^)]*\))?!?: '; then
        printf '%s.%s.0\n' "$major" "$((minor + 1))"
    else
        printf '%s.%s.%s\n' "$major" "$minor" "$((patch + 1))"
    fi
}

show_bump_rationale() {
    local release_version="$1" release_base="$2" range conventional_commits
    if [[ -n "$release_base" ]]; then range="${release_base}..HEAD"; echo "Commits since release v${release_version}:";
    else range="HEAD"; echo "Commits considered for initial release:"; fi
    conventional_commits=$(git log --format='%s' "$range" | grep -E '^[[:alpha:]]+(\([^)]*\))?!?: ' || true)
    if [[ -z "$conventional_commits" ]]; then echo "  No conventional commits found in range; git-cliff selected the bump."; return; fi
    printf '%s\n' "$conventional_commits" | sed 's/^/  - /'
    if printf '%s\n' "$conventional_commits" | grep -Eq '^feat(\([^)]*\))?!?: '; then echo "Bump rationale: at least one feat commit detected, so bumping minor."
    elif printf '%s\n' "$conventional_commits" | grep -Eq '^fix(\([^)]*\))?: '; then echo "Bump rationale: only fix-level changes detected, so bumping patch."
    else echo "Bump rationale: no feat commits detected, so bumping patch."; fi
}

update_manifest_version() { sed -i.bak "s/^version = \"$2\"/version = \"$3\"/" "$1"; rm -f "$1.bak"; }
update_dependency_version() { sed -i.bak -E "s/^($2 = \{ version = )\"[^\"]*\"/\1\"$3\"/" "$1"; rm -f "$1.bak"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        -h|--help) usage; exit 0 ;;
        --*) die "unknown option: $1" ;;
        *) [[ -z "$REQUESTED_VERSION" ]] || die "only one VERSION may be provided"; REQUESTED_VERSION="${1#v}" ;;
    esac
    shift
done

require_command git
require_command cargo
require_command git-cliff
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || die "must run inside a Git worktree"
cd "$REPO_ROOT"
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || die "worktree is not clean; commit or stash changes before preparing a release"
for manifest in "$CORE_MANIFEST" "$PROXY_MANIFEST" "$CLI_MANIFEST" "$FFI_MANIFEST"; do [[ -f "$manifest" ]] || die "required manifest is missing: $manifest"; done
git show-ref --verify --quiet refs/remotes/origin/main || die "origin/main is required; fetch it before preparing a release"
git merge-base --is-ancestor origin/main HEAD || die "HEAD must contain origin/main; start from an up-to-date main or release branch"

CORE_VERSION=$(manifest_version "$CORE_MANIFEST")
PROXY_VERSION=$(manifest_version "$PROXY_MANIFEST")
CLI_VERSION=$(manifest_version "$CLI_MANIFEST")
PROXY_CORE_VERSION=$(dependency_version "$PROXY_MANIFEST" nono)
CLI_CORE_VERSION=$(dependency_version "$CLI_MANIFEST" nono)
CLI_PROXY_VERSION=$(dependency_version "$CLI_MANIFEST" nono-proxy)
[[ -n "$CORE_VERSION" ]] || die "could not read the nono version"
[[ "$PROXY_VERSION" == "$CORE_VERSION" ]] || die "nono-proxy version ($PROXY_VERSION) does not match nono ($CORE_VERSION)"
[[ "$CLI_VERSION" == "$CORE_VERSION" ]] || die "nono-cli version ($CLI_VERSION) does not match nono ($CORE_VERSION)"
[[ "$PROXY_CORE_VERSION" == "$CORE_VERSION" ]] || die "nono-proxy's nono dependency ($PROXY_CORE_VERSION) does not match $CORE_VERSION"
[[ "$CLI_CORE_VERSION" == "$CORE_VERSION" ]] || die "nono-cli's nono dependency ($CLI_CORE_VERSION) does not match $CORE_VERSION"
[[ "$CLI_PROXY_VERSION" == "$CORE_VERSION" ]] || die "nono-cli's nono-proxy dependency ($CLI_PROXY_VERSION) does not match $CORE_VERSION"

if [[ -z "$REQUESTED_VERSION" ]]; then
    echo "Fetching release tags from origin..."
    git fetch --tags origin || die "could not fetch release tags from origin"
fi
PREVIOUS_TAG=$(latest_tag)
[[ -n "$PREVIOUS_TAG" ]] || die "no release tag found; supply VERSION explicitly"
RELEASE_BASE=$(latest_release_commit "$CORE_VERSION")
[[ -n "$RELEASE_BASE" ]] || RELEASE_BASE="$PREVIOUS_TAG"
if [[ -n "$REQUESTED_VERSION" ]]; then NEXT_VERSION="$REQUESTED_VERSION"; else NEXT_VERSION=$(next_version_from_commits "$CORE_VERSION" "$RELEASE_BASE"); fi
is_semver "$NEXT_VERSION" || die "VERSION must be valid SemVer without a leading v: $NEXT_VERSION"
[[ "$NEXT_VERSION" != "$CORE_VERSION" ]] || die "target version must differ from the current version ($CORE_VERSION)"
NEXT_VERSION_WITH_V="v${NEXT_VERSION}"
git show-ref --verify --quiet "refs/tags/${NEXT_VERSION_WITH_V}" && die "tag ${NEXT_VERSION_WITH_V} already exists locally"
if git ls-remote --exit-code --tags origin "refs/tags/${NEXT_VERSION_WITH_V}" >/dev/null 2>&1; then die "tag ${NEXT_VERSION_WITH_V} already exists on origin"; fi

echo "Release preflight passed."
echo "  Current version: ${CORE_VERSION}"
echo "  Previous tag: ${PREVIOUS_TAG:-none}"
echo "  Target version: ${NEXT_VERSION}"
echo
[[ -z "$REQUESTED_VERSION" ]] && { show_bump_rationale "$CORE_VERSION" "$RELEASE_BASE"; echo; }
echo "Planned changes:"
echo "  ${CORE_MANIFEST}: package version ${CORE_VERSION} -> ${NEXT_VERSION}"
echo "  ${PROXY_MANIFEST}: package and nono dependency ${CORE_VERSION} -> ${NEXT_VERSION}"
echo "  ${CLI_MANIFEST}: package, nono, and nono-proxy dependencies ${CORE_VERSION} -> ${NEXT_VERSION}"
echo "  ${FFI_MANIFEST}: nono dependency -> ${NEXT_VERSION} (package version is unchanged)"
echo "  Cargo.lock: refresh workspace package versions"
echo "  CHANGELOG.md: prepend git-cliff unreleased notes for ${NEXT_VERSION_WITH_V}"
if [[ "$DRY_RUN" == true ]]; then echo; echo "Dry run complete; the worktree was not modified."; exit 0; fi
[[ -t 0 ]] || die "a terminal is required to confirm changes; use --dry-run in non-interactive environments"
read -r -p "Prepare release ${NEXT_VERSION}? (y/n) " REPLY
[[ "$REPLY" =~ ^[Yy]$ ]] || die "aborted"

update_manifest_version "$CORE_MANIFEST" "$CORE_VERSION" "$NEXT_VERSION"
update_manifest_version "$PROXY_MANIFEST" "$CORE_VERSION" "$NEXT_VERSION"
update_dependency_version "$PROXY_MANIFEST" nono "$NEXT_VERSION"
update_manifest_version "$CLI_MANIFEST" "$CORE_VERSION" "$NEXT_VERSION"
update_dependency_version "$CLI_MANIFEST" nono "$NEXT_VERSION"
update_dependency_version "$CLI_MANIFEST" nono-proxy "$NEXT_VERSION"
update_dependency_version "$FFI_MANIFEST" nono "$NEXT_VERSION"
echo "Updating Cargo.lock..."
cargo check --workspace --quiet
echo "Generating CHANGELOG.md..."
touch CHANGELOG.md
git cliff "${RELEASE_BASE}..HEAD" --tag "$NEXT_VERSION_WITH_V" --prepend CHANGELOG.md
echo
echo "Release PR prepared. Follow docs/maintainers/releasing.md for review, tagging, and verification."
