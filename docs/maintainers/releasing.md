# Releasing nono

This is the maintainer release runbook. Release coordinators are
[@lhinds](https://github.com/lhinds) and [@SequeI](https://github.com/SequeI).

Release tags are immutable. Never force-move a tag or replace a published
artifact.

## 1. Prepare the release branch

Start with a clean, current `main`, then create a release branch:

```bash
git checkout main
git pull origin main
git checkout -b release/vX.Y.Z
```

Preview the release first. The script fetches release tags and, without a
version, derives the next version from conventional commits: features bump
minor and fix-only changes bump patch. Supply one when you need a specific
stable or prerelease version.

```bash
./scripts/prepare-release.sh --dry-run
./scripts/prepare-release.sh --dry-run 0.78.0
```

When the preview looks right, run the chosen command again without `--dry-run`.
The script validates the branch, version consistency, and tag availability
before changing files.

## 2. Open and merge the release PR

Commit the generated version, lockfile, and changelog changes:

```bash
git add .
git commit -s -m "chore: release vX.Y.Z"
git push origin release/vX.Y.Z
```

Open a PR titled `chore: release vX.Y.Z`; this starts the release PR checks.
Compare it with previous releases, review the changelog and version changes,
and merge only when the checks are green and the coordinators agree.

## 3. Tag the merged release

Tag from refreshed `main`, never from the release branch or an unmerged PR:

```bash
git checkout main
git pull origin main
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

Pushing the tag starts the Release workflow.

## 4. One-time: make the GHCR package public

The `publish-oci` job (added in v0.81+) pushes OCI artifacts to the existing
`ghcr.io/nolabs-ai/nono` package. GHCR packages are private by default, so
`oras pull` will fail for unauthenticated users until a maintainer makes the
package public. This needs to be done once, after the first release that
includes the `publish-oci` job:

1. Go to **GitHub → nolabs-ai org → Packages → `nono` → Package settings**.
2. Under **Danger Zone**, set visibility to **Public**.

This setting persists across releases; it does not need to be repeated.

## 5. Verify OCI artifacts after release

After each stable release, confirm the OCI artifacts are correctly published:

```bash
# Check the multi-platform index has 4 manifests
oras manifest fetch ghcr.io/nolabs-ai/nono:X.Y.Z-binary | jq '.manifests | length'

# Pull the binary and verify the GitHub provenance attestation
oras pull --platform linux/amd64 ghcr.io/nolabs-ai/nono:X.Y.Z-binary -o pulled/
gh attestation verify pulled/*.tar.gz -R nolabs-ai/nono

# Verify the Cosign keyless signature on the index
cosign verify \
  --certificate-identity "https://github.com/nolabs-ai/nono/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/nolabs-ai/nono@$(oras resolve ghcr.io/nolabs-ai/nono:X.Y.Z-binary)"
```

For end-user installation instructions, see [docs/cli/getting_started/installation.mdx](/cli/getting_started/installation).
