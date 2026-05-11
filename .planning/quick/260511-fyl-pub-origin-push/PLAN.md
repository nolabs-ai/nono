---
slug: pub-origin-push
quick_id: 260511-fyl
created: 2026-05-11
type: ops-action
status: in-progress
---

# Quick task: Publish 326 local commits to origin/main (POC unblock prerequisite)

## Problem

The Sigstore TUF rotation workaround quick task (`260511-fpn-sigstore-tuf-rotation`)
shipped a PowerShell `Invoke-WebRequest` URL pinned to commit `281f71ab` of
`oscarmackjr-twg/nono`. POC user ran it and got HTTP 404.

Root cause: `origin/main` was at `33229adc` (Phase 22 mid-2026-04-28 era) — 326 commits
behind local. Every Phase 27+ artifact, Phase 32 sigstore code, and the fixture file
`crates/nono/tests/fixtures/trust-root-frozen.json` (committed in `d9969978`, Phase 32-01)
were local-only. The raw-GitHub URL for the fixture would 404 at every sha that wasn't on
origin — which was every sha in this session.

## Pre-push verification

- `git merge-base --is-ancestor origin/main HEAD` → YES (fast-forward, no force push)
- `git merge-base --is-ancestor d9969978 HEAD` → YES (fixture commit reachable from HEAD)
- `git rev-list --count origin/main..HEAD` → 326 commits
- First unpushed commit: `e60ab093 test(22): complete UAT — 10 passed, 1 skipped, 0 issues`
  (Phase 22 close-out — operator-of-record acceptance per Phase 22 D-05/D-06/D-07 push-cadence
  contract; per memory note `nono Windows Parity milestone`, regular pushes ARE the documented
  cadence, this is just lag, not policy change).
- Last unpushed commit (HEAD): `c63998ae docs(poc): document Sigstore TUF root rotation
  workaround + track upgrade as P32-DEFER-005`

## Action

Single command, user-authorized: `git push origin main`. Pushes `33229adc..c63998ae`.

## Out of scope

- Tags: not pushing tags this session (v1.0/v2.0/v2.1/v2.2 tags pushed at v2.2-start per
  Phase 22 D-08; subsequent tags TBD). Tag push is a separate decision per milestone close.
- Force push: not authorized (fast-forward confirmed).
- Branches: only `main`. No other local branches require publishing for the POC unblock.

## Acceptance

- [ ] `git push origin main` returns exit 0 with `33229adc..c63998ae` range.
- [ ] `raw.githubusercontent.com/oscarmackjr-twg/nono/c63998ae/crates/nono/tests/fixtures/trust-root-frozen.json`
      returns the JSON file (verify via WebFetch).
- [ ] POC user can re-run the existing `Invoke-WebRequest` workaround from
      `docs/cli/development/windows-poc-handoff.mdx` and the file lands at
      `%USERPROFILE%\.nono\trust-root\trusted_root.json`.
- [ ] `nono setup --check-only` then reports `Trust root cache: OK`.
