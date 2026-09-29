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
