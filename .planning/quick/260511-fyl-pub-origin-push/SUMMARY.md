---
slug: pub-origin-push
quick_id: 260511-fyl
created: 2026-05-11
completed: 2026-05-11
type: ops-action
status: complete
---

# Summary: Published 326 local commits to origin/main

## What was published

`33229adc..c63998ae` — 326 commits spanning:

- Phase 22 UAT close-out (`e60ab093`)
- Phase 23 (Windows AIPC audit retrofit)
- Phase 24 (Parity-drift prevention)
- Phase 25 (Cross-platform RESL Unix design)
- Phase 26 (PKG streaming follow-up)
- Phase 27 / 27.1 / 27.2 (Audit-attestation hardening + NONO_TEST_HOME seam)
- Phase 28 (Authenticode chain-walker subject extraction)
- Phase 29 (WR-01 reject-stage unification)
- Phase 30 (Windows nono-shell architecture)
- Phase 31 (Broker-process architecture / shell-01)
- Phase 32 (Sigstore Integration — 16 D-32-XX decisions; introduced the
  `crates/nono/tests/fixtures/trust-root-frozen.json` fixture at `d9969978`)
- Phase 33 (Windows parity with upstream 0.52 / divergence-strategy ADR; introduced
  `DIVERGENCE-LEDGER.md` + `docs/architecture/upstream-parity-strategy.md`)
- Phase 34 CONTEXT.md (UPST3 sync execution discussion)
- This session's 3 quick tasks (landlock-windows-leak, poc-keyless-doc-fix,
  sigstore-tuf-rotation) and their commits

## Verification

| Check | Result |
|-------|--------|
| `git push origin main` exit code | ✅ 0 |
| Push range | ✅ `33229adc..c63998ae` (fast-forward, no `-f`) |
| `WebFetch raw.githubusercontent.com/oscarmackjr-twg/nono/c63998ae/.../trust-root-frozen.json` | ✅ returns valid Sigstore trusted_root JSON |
| `git merge-base --is-ancestor d9969978 origin/main` | ✅ fixture commit now on origin (was NOT before) |
| `git log origin/main -1` | ✅ now `c63998ae` |

## POC user re-try

The PowerShell workaround block in `docs/cli/development/windows-poc-handoff.mdx`
(pinned to `281f71ab`) now resolves correctly because `281f71ab` is an ancestor of
`c63998ae` and the entire 326-commit range is publicly fetchable.

POC user can re-run the same command they tried earlier:

```powershell
$cacheDir = "$env:USERPROFILE\.nono\trust-root"
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
Invoke-WebRequest -UseBasicParsing `
  -Uri "https://raw.githubusercontent.com/oscarmackjr-twg/nono/281f71ab/crates/nono/tests/fixtures/trust-root-frozen.json" `
  -OutFile "$cacheDir\trusted_root.json"
```

Or equivalently against the new HEAD:

```powershell
Invoke-WebRequest -UseBasicParsing `
  -Uri "https://raw.githubusercontent.com/oscarmackjr-twg/nono/c63998ae/crates/nono/tests/fixtures/trust-root-frozen.json" `
  -OutFile "$cacheDir\trusted_root.json"
```

Then confirm:

```powershell
nono setup --check-only   # should report: Trust root cache: OK
```

## What this does NOT change

- No code change.
- No doc change (the workaround URL in the POC handoff doc was already correct in shape;
  it just needed the underlying commit to be reachable, which the push fixes).
- No tags pushed (separate decision per milestone close).
- No upstream `always-further/nono` interaction. This is publishing to the user's own fork
  `oscarmackjr-twg/nono` only.

## Open follow-ups

- **Push-cadence drift:** Phase 22 D-07 said "push after each plan closes" — the cadence
  drifted from `33229adc` (Phase 22 close, 2026-04-28) to `c63998ae` (2026-05-11). 326
  commits / 13 days = 25 commits/day; not unreasonable for active development but the
  per-plan-close push cadence wasn't held. Operator-of-record's call whether to formalize
  a per-commit push automation, leave it as manual discipline, or accept the lag.
- **`docs/cli/development/` `.gitignore`-listed**: git add hints suggested the path is in
  a gitignore rule even though tracked files there work fine. Worth a future cleanup of
  `.gitignore` to remove that ignore directive since the directory is actively maintained.
- **P32-DEFER-005 (sigstore-verify 0.6.5 → 0.6.6 upgrade)** remains the long-term fix that
  removes the need for this workaround entirely. Tracked in
  `.planning/phases/32-sigstore-integration/deferred-items.md`.

## Files touched

- `.planning/quick/260511-fyl-pub-origin-push/PLAN.md` (new)
- `.planning/quick/260511-fyl-pub-origin-push/SUMMARY.md` (this file)
- `.planning/STATE.md` (Last activity update)

Plus the side effect: `origin/main` advanced `33229adc → c63998ae` (326 commits).
