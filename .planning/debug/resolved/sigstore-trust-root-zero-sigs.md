---
slug: sigstore-trust-root-zero-sigs
status: resolved
trigger: |
  `nono setup --refresh-trust-root` on Windows v0.53.0 fails in step [3/5]
  with: "Failed to fetch Sigstore trusted root from https://tuf-repo-cdn.sigstore.dev:
  TUF error: TUF repository load failed: Failed to verify trusted root metadata:
  Signature threshold of 3 not met for role root (0 valid signatures)"
created: 2026-05-21
updated: 2026-05-21
---

# Debug Session: sigstore-trust-root-zero-sigs

## Symptoms

- **Expected behavior**: `nono setup --refresh-trust-root` step [3/5] should
  successfully fetch and verify the Sigstore TUF root metadata and persist
  the refreshed trust root locally.
- **Actual behavior**: Setup aborts in step [3/5] with TUF verification error
  "Signature threshold of 3 not met for role root (0 valid signatures)".
  Steps [1/5] (installation check) and [2/5] (sandbox support) pass.
- **Error message** (verbatim from user):
  ```
  [3/5] Refreshing Sigstore trusted root...
  nono: Setup error: Failed to fetch Sigstore trusted root from https://tuf-repo-cdn.sigstore.dev:
  TUF error: TUF repository load failed: Failed to verify trusted root metadata:
  Signature threshold of 3 not met for role root (0 valid signatures)
  ```
- **Timeline / history**: First time running `--refresh-trust-root` on this
  machine (no prior success to regress from).
- **Reproduction**: Run `nono setup --refresh-trust-root` with installed
  v0.53.0 binary on Windows 11. Reproduced live in this session.
- **Environment**:
  - Binary: `C:\Users\OMack\AppData\Local\Programs\nono\nono.exe` v0.53.0
    (mtime 2026-05-17 23:33 — built BEFORE the v2.5 tag's sigstore 0.7.0 bump)
  - Platform: Windows 11 Enterprise (Standard User session)
  - User config root: `\\?\C:\Users\OMack\AppData\Roaming\nono`
  - User state root: `C:\Users\OMack\AppData\Local\nono`
  - User trust policy: `\\?\C:\Users\OMack\AppData\Roaming\nono\trust-policy.json`
  - Sandbox support: OK (Job Object + Token Integrity + BFE all OK)
  - WFP backend binary: missing (separate issue, unrelated to TUF failure)
- **Network confirmed reachable**: User confirmed `https://tuf-repo-cdn.sigstore.dev`
  is reachable. Confirmed independently: `curl` against
  `https://tuf-repo-cdn.sigstore.dev/14.root.json` and `/15.root.json` both
  return 200 OK. So this is NOT a connectivity failure.

## Project Context

- nono just shipped milestone v2.5 (Windows Parity) at tag v2.5; Cargo.lock
  at that tag pins `sigstore-verify 0.7.0` + `sigstore-trust-root 0.7.0` +
  `tough 0.22.0` (the 0.6.5 → 0.7.0 bump landed in commit `14ca0760` on
  2026-05-19 23:12, which IS an ancestor of v2.5 tagged 2026-05-20 10:03).
- The installed v0.53.0 binary, however, is dated 2026-05-17 23:33 — two
  days BEFORE the 0.7.0 bump, so it was built from an earlier v2.5 release
  branch commit and is statically linked against `sigstore-trust-root 0.6.6`
  / `sigstore-verify 0.6.6` / `tough 0.21.0`. (Verified by `grep -a` against
  the .exe.)
- Phase 49 (Sigstore POC trust-root resilience) shipped 2026-05-21 on the
  v2.6 branch and adds `--from-file` flag + release-asset bundling
  specifically to give users a fallback when the live TUF refresh fails.
  v0.53.0 predates Phase 49, so this binary has NO fallback path.

## Current Focus

- **hypothesis**: CONFIRMED. The installed v0.53.0 binary links
  `sigstore-trust-root 0.6.6`, whose embedded `tuf_root.json` is the
  Sigstore production v1 root from 2021-12-18. Its 5 signatures no longer
  self-verify under the post-0.6.4 strict-key-type check, so step 5.2 of
  TUF spec (verify trusted root against itself, at `tough-0.22.0` /
  `tough-0.21.0` `lib.rs:705-707`) fails before the CDN chain walk even
  begins. The error message "Failed to verify trusted root metadata"
  corresponds to `VerifyTrustedMetadataSnafu`, not the chain step.
- **test**: Built an isolated repro (`.bg-shell/sigprobe/`) that loads
  the embedded `tuf_root.json` from each crate version and calls
  `tough::schema::Signed<Root>::verify_role(&self)` directly. Result:
  - `sigstore-trust-root 0.7.0` PRODUCTION_TUF_ROOT (v14, expires
    2026-06-22): VERIFY OK.
  - `sigstore-trust-root 0.6.6` `tuf_root.json` (v1, expires 2021-12-18,
    keyids `2f64fb5e..`, `bdde902f..`, `eaf22372..`, `f40f3204..`,
    `f5055951..`): VERIFY FAILED: Signature threshold of 3 not met for
    role root (0 valid signatures). EXACT same message as the live
    failure.
- **next_action**: Present root cause + fix options to user.

## Evidence

- timestamp: 2026-05-21 / source: user CLI output / observation:
  Steps [1/5] and [2/5] pass; the failure occurs cleanly in step [3/5]
  only.
- timestamp: 2026-05-21 / source: live re-reproduction in session /
  observation: `nono setup --refresh-trust-root` against the installed
  v0.53.0 binary produces the verbatim error.
- timestamp: 2026-05-21 / source:
  `grep -aoE '(tough|sigstore-(trust-root|verify|crypto))-[0-9]+\.[0-9]+\.[0-9]+' nono.exe` /
  observation: installed binary embeds `sigstore-crypto-0.6.6`,
  `sigstore-trust-root-0.6.6`, `sigstore-verify-0.6.6`, `tough-0.21.0`.
  Does NOT match v2.5 tag's Cargo.lock (which has 0.7.0 / tough-0.22.0).
- timestamp: 2026-05-21 / source: `git show -s 14ca0760` + `git log v2.5` /
  observation: sigstore 0.6.5 → 0.7.0 bump committed 2026-05-19 23:12;
  binary mtime is 2026-05-17 23:33 — built two days before the bump
  landed on the release branch.
- timestamp: 2026-05-21 / source: byte-compare embedded v14 root vs live
  CDN `14.root.json` via `sha256sum` / observation: identical
  (`c8c41ec13f06ccabf5b48541ee2550098b4c7b5349e1d180390c29a7d5c2642c`).
  Confirms current v0.7.0 ships an up-to-date anchor.
- timestamp: 2026-05-21 / source:
  `sigstore-trust-root-0.6.6/repository/tuf_root.json` direct inspection /
  observation: `signed.version = 1`, `signed.expires =
  2021-12-18T13:28:12.99008-06:00`, root role threshold 3, keyids:
  `2f64fb5eac0cf94dd39bb453`, `bdde902f5ec668179ff5ca0d`,
  `eaf22372f417dd618a46f6c6`, `f40f32044071a9365505da3d`,
  `f505595165a177a41750a8e8`. (Five legacy keys, all rotated out years
  ago.)
- timestamp: 2026-05-21 / source: isolated repro `.bg-shell/sigprobe/`
  invoking `tough::schema::Signed<Root>::verify_role(&self)` /
  observation: 0.7.0 embedded root verifies OK; 0.6.6 embedded root
  produces "Signature threshold of 3 not met for role root (0 valid
  signatures)" — the exact failure message the user sees.
- timestamp: 2026-05-21 / source:
  `sigstore-verify-0.6.6/CHANGELOG.md` line 18-20 / observation: 0.6.4
  PR #70 made key verification "more strict about unknown key types and
  verification" — likely root cause of the v1 self-verification failure
  (the 2021 v1 root used PGP-style keys or a key type now rejected).
- timestamp: 2026-05-21 / source: `tough-0.22.0/src/lib.rs:699-707` /
  observation: `load_root` step 5.2 calls
  `root.signed.verify_role(&root).context(error::VerifyTrustedMetadataSnafu)?;`
  on the embedded bytes BEFORE any network fetch. This is why the error
  surfaces as "Failed to verify trusted root metadata" and not "Failed to
  fetch N+1.root.json".
- timestamp: 2026-05-21 / source: prior quick task
  `.planning/quick/260511-fpn-sigstore-tuf-rotation/SUMMARY.md` /
  observation: the same failure was diagnosed on 2026-05-11 against
  `sigstore-verify 0.6.5`; documented manual `Invoke-WebRequest`
  workaround at `windows-poc-handoff.mdx`. The diagnosis there said the
  embedded anchor was "stale", which is correct but not specific —
  evidence above narrows it to "the 0.6.6 embedded anchor is the 2021
  v1 root, which fails self-verify under 0.6.4+ strictness", NOT just
  "the chain to current is too far".
- timestamp: 2026-05-21 / source: `tuf-repo-cdn.sigstore.dev/15.root.json`
  fetch / observation: a v15 of root.json EXISTS as of today, expires
  2026-11-20; threshold and 5 keyids match v14. So 0.7.0's bootstrap path
  (embedded v14 → fetch v15 → done) would succeed if the user had that
  build.

## Eliminated

- **Network / connectivity**: `curl` returns 200 OK against both
  `/14.root.json` and `/15.root.json`. Not a network issue.
- **Stale local datastore**: `%LOCALAPPDATA%\sigstore\sigstore-rust\cache\tuf\`
  contained only `latest_known_time.json` (last-known-time defense). No
  poisoned root.json on disk. Deleting it changes nothing because the
  failure is in the embedded-anchor self-verify, before any cache lookup.
- **System clock skew**: System time is `2026-05-21T21:00:16Z`,
  `latest_known_time.json` is `2026-05-21T20:54:01Z`. Clock is fine.
- **Current source has the bug**: NO. Current HEAD and v2.5 tag both pin
  `sigstore-trust-root 0.7.0` whose embedded anchor (v14) self-verifies
  cleanly (proved in isolated repro). A binary built from current source
  would NOT exhibit this failure.

## Resolution

- root_cause: |
    The installed `nono.exe v0.53.0` (mtime 2026-05-17 23:33) was built
    from a v2.5 release-branch commit BEFORE Phase 37 plan 06
    (`14ca0760`, 2026-05-19) bumped sigstore-verify/sign/trust-root from
    0.6.x to 0.7.0. As a result the binary statically links
    `sigstore-trust-root 0.6.6`, whose embedded `tuf_root.json` is the
    Sigstore production **v1** root from 2021-12-18. That v1 root's 5
    signatures no longer self-verify under the post-0.6.4 strict-key-type
    check, so the very first step of TUF bootstrap
    (`tough::lib::load_root` 5.2: `root.signed.verify_role(&root)`) fails
    with `SignatureThreshold { role: Root, threshold: 3, valid: 0 }`.
    The CDN chain walk (v14 → v15) is never reached. The user's network
    is fine. The current source tree (and v2.5 tag) ship a fixed binary;
    this user is on a binary built two days too early.
- fix: |
    Two complementary fixes:
    (1) IMMEDIATE USER UNBLOCK — drop a known-good `trusted_root.json`
        into the cache. The repo already ships a fixture at
        `crates/nono/tests/fixtures/trust-root-frozen.json`. Per Phase 32
        D-32-01 verify-is-offline, `load_production_trusted_root()`
        reads cache bytes via plain JSON deserialize (no TUF re-verify),
        so the corrupt-embedded-anchor in 0.6.6 is bypassed entirely. The
        PowerShell `Invoke-WebRequest` block already documented at
        `docs/cli/development/windows-poc-handoff.mdx:182-220` works
        unchanged. This unblocks the user in 30 seconds with NO rebuild.
    (2) PERMANENT FIX — rebuild + redistribute the v0.53.0 (or follow-on
        v0.53.1) binary from current `main` / v2.5 tag, which pins
        sigstore-trust-root 0.7.0 (embedded v14 anchor, self-verifies
        OK). A binary built today from `main` will refresh successfully
        against tuf-repo-cdn.sigstore.dev:
          v14 (embedded) → fetch v15 from CDN → success.
        Optional v2.6 enhancement: backport Phase 49's `--from-file` flag
        into a v0.53.x patch release so future stale-anchor failures
        recover without a network fetch.
- verification: |
    For fix (1): user runs the PowerShell block at
    `docs/cli/development/windows-poc-handoff.mdx:188-218` and then
    `nono setup --check-only` should report `Trust root cache: OK`.
    `nono trust verify` invocations then succeed offline.
    For fix (2): build `make build-cli` from current HEAD, install,
    re-run `nono setup --refresh-trust-root`; expect step [3/5] to
    succeed and emit `* Sigstore trusted root cached at ...`. Confirmed
    via isolated repro that `sigstore-trust-root 0.7.0` PRODUCTION_TUF_ROOT
    self-verifies and bootstrap proceeds to chain walk.
- files_changed: |
    Diagnosis only — no source files changed. Affected components:
    - Installed binary at `C:\Users\OMack\AppData\Local\Programs\nono\nono.exe`
      (linked against sigstore-trust-root-0.6.6 / sigstore-verify-0.6.6 /
      tough-0.21.0).
    - Embedded anchor under
      `C:\Users\OMack\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\sigstore-trust-root-0.6.6\repository\tuf_root.json`
      (read-only registry cache; the canonical stale-anchor file).
    - `tough-0.22.0/src/lib.rs:699-707` (step 5.2 self-verify call) and
      `tough-0.22.0/src/schema/verify.rs:8-58` (the `verify_role` impl
      whose error is surfaced).
    - Isolated repro at `C:\Users\OMack\Nono\.bg-shell\sigprobe\` (kept
      as evidence; can be deleted after fix).

## Resolution Applied (2026-05-21)

- **Fix (2) applied**: User rebuilt nono-cli + nono-shell-broker from
  current `main` (commit `40114a6d`, sigstore-trust-root 0.7.0) and
  built a fresh user-scope MSI at
  `dist/windows/nono-v0.53.0-x86_64-pc-windows-msvc-user.msi`. Installed
  in place over the old v0.53.0. Verified by re-running
  `nono setup --refresh-trust-root`: the "Signature threshold of 3 not met"
  failure is gone (TUF self-verify of the embedded v14 anchor now succeeds).
- **Successor failure surfaced**: After the anchor self-verifies, the next
  TUF step (fetch `15.root.json` from `tuf-repo-cdn.sigstore.dev`) fails on
  this user's corporate TLS-inspecting network. Diagnosed in successor
  debug session `.planning/debug/sigstore-tuf-fetch-transport.md`.
