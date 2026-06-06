# AUR packaging for nono

This directory contains the canonical source for the [`nono-ai-bin`](https://aur.archlinux.org/packages/nono-ai-bin)
Arch User Repository package, a pre-built binary package that tracks official
GitHub releases.

## Why `nono-ai-bin`?

The name `nono` is already taken in the official Arch repositories by an
unrelated emulator, and the AUR already hosts the source-based variants
`nono-ai` and `nono-ai-git`. Following AUR conventions, the `-bin` suffix marks
this as the package that installs pre-built release binaries instead of
compiling from source, which makes installs and updates fast while still
integrating with pacman and AUR helpers.

## Files

| File | Purpose |
|------|---------|
| `PKGBUILD` | Package build recipe. `pkgver` and the `sha256sums` arrays are rewritten by CI at publish time; the committed values correspond to a real release so the file stays locally buildable. |
| `update.sh` | Updates `PKGBUILD` to a given release, recomputes checksums with `updpkgsums`, and regenerates `.SRCINFO`. |

`.SRCINFO` is intentionally not tracked here: it is generated from the
`PKGBUILD` at publish time.

## How publishing works

The `.github/workflows/aur-publish.yml` workflow publishes this package to the
AUR. In short:

- It runs automatically after each successful **Release** (or manually via
  `workflow_dispatch` with a tag input); prereleases and non-tag refs are
  skipped.
- It regenerates `PKGBUILD`/`.SRCINFO` for the released version and pushes to
  the AUR **only if they differ** from the current AUR state, so re-runs are
  safe no-ops.
- It never builds nono itself: the package only references release artifacts
  that are already published.

The step-by-step mechanics are documented inline in the workflow file.

## Credentials

| What | Where |
|------|-------|
| AUR account | `lukehinds` (co-maintainer of `nono-ai-bin`, alongside `sarovin86`) |
| SSH private key | `AUR_SSH_PRIVATE_KEY` repository secret (Actions) |

The SSH key never appears in logs; it is written to a file readable only by the
build user inside the job container.

## SSH host key verification

The workflow refuses to talk to anything that does not present the official
`aur.archlinux.org` host keys. The expected key fingerprints are pinned in the
workflow and checked against the output of `ssh-keyscan` before any git
operation (`StrictHostKeyChecking yes`).

If Arch Linux rotates its SSH host keys, the workflow fails loudly instead of
trusting the new keys (fail secure). To update the pinned fingerprints:

1. Get the current fingerprints from the footer of <https://aur.archlinux.org/>
   ("The following SSH fingerprints are used for the AUR").
2. Replace the values in the `Verify AUR host keys and configure SSH` step of
   `.github/workflows/aur-publish.yml`.
3. Open a PR with the change.

## Testing locally

On an Arch Linux system or an `archlinux:latest` container with `base-devel`
and `pacman-contrib` installed:

```bash
cd packaging/aur
./update.sh v0.61.1   # or any released tag
makepkg -f            # downloads the artifacts, verifies checksums, builds the package
```

## History and attribution

The `PKGBUILD` and `update.sh` were originally written and maintained by
[sarovin86](https://aur.archlinux.org/account/sarovin86) in the
[sarovin/nono-ai-bin](https://github.com/sarovin/nono-ai-bin) repository, and
were moved here (with small adaptations for CI integration) as part of
[#917](https://github.com/always-further/nono/issues/917).
