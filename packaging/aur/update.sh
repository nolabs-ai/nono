#!/usr/bin/env bash
# Update the nono-ai-bin AUR packaging files to an upstream release.
#
# Usage: ./update.sh <version>
#   The version (e.g. "v0.61.1" or "0.61.1") is required and always gets the
#   full update, even if pkgver already matches. The CI workflow
#   (.github/workflows/aur-publish.yml) relies on this to regenerate the
#   sha256sums and .SRCINFO deterministically from the release artifacts.
#
# Requires: pacman-contrib (provides updpkgsums), makepkg

set -euo pipefail

cd "$(dirname "$0")"
command -v updpkgsums >/dev/null || { echo "updpkgsums not found; install pacman-contrib" >&2; exit 1; }

[[ $# -ge 1 ]] || { echo "Usage: $0 <version>   (e.g. v0.61.1)" >&2; exit 1; }
ver="${1#v}"
# Same stable-release format the CI gate (aur-publish.yml, job "resolve") enforces.
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Unexpected version: '${ver}'" >&2; exit 1; }

cur="$(awk -F= '/^pkgver=/{print $2; exit}' PKGBUILD)"

if [[ "$cur" == "$ver" ]]; then
  # Same version: refresh checksums and .SRCINFO without touching pkgrel,
  # so packaging-only fixes (manual pkgrel bumps) are preserved.
  echo "Refreshing v${ver} (checksums and .SRCINFO)"
else
  echo "Bumping ${cur} -> ${ver}"
  sed -i -e "s/^pkgver=.*/pkgver=${ver}/" -e "s/^pkgrel=.*/pkgrel=1/" PKGBUILD
fi

updpkgsums
makepkg --printsrcinfo > .SRCINFO

echo "Updated PKGBUILD and .SRCINFO to v${ver}."
