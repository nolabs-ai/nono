---
slug: 260507-wix-bump-to-7-0-0
date: 2026-05-07
status: complete
commit: 7f2da598
type: build-config
---

# Bump WiX 4.0.6 → 7.0.0 (OSMF EULA acceptance)

## What changed

Single atomic commit `7f2da598` covering the Windows MSI build pipeline migration to FireGiant WiX 7.0.0:

| File | Change |
|------|--------|
| `scripts/build-windows-msi.ps1` | Added `-acceptEula wix7` to `wix build`. Updated the missing-CLI error message to reference v7 + the dotnet tool install command. |
| `.github/workflows/release.yml` | `WIX_VERSION: 4.0.6` → `7.0.0`. |
| `docs/cli/development/windows-poc-handoff.mdx` (new) | Operator cookbook for the Windows POC handoff, written against WiX 7 from the start. |
| `docs/docs.json` | Nav entry for the new cookbook, between `windows-preview-pilot` and `windows-preview-validation`. |

## What did not change

- `.wxs` XML namespace — `http://wixtoolset.org/schemas/v4/wxs` is preserved across v4/v5/v6/v7 per FireGiant's "What's New" doc. No source rewrite needed.
- WiX element shapes used (`Package`, `MajorUpgrade`, `MediaTemplate`, `ServiceInstall`, `ServiceControl`, `Environment`, `RegistryValue`, `StandardDirectory`, `ComponentGroup`).
- `scripts/validate-windows-msi-contract.ps1` — already namespace-agnostic via `local-name()` XPath.
- GitHub `windows-latest` runner — already ships .NET 8 SDK, which is WiX 7's minimum.
- `dist/windows/nono-user.wxs` — generated artifact, regenerates on next build.

## OSMF context

WiX v6 introduced the [Open Source Maintenance Fee](https://docs.firegiant.com/wix/osmf/); v7 enforces it via `WIX7015` if no acceptance is provided. EULA v1.1 sets the fee threshold at **US$10,000/yr** of revenue from projects-using-WiX. nono is well below that threshold, so no fee is owed — but explicit EULA acknowledgement is still required by the build. We do this via the `-acceptEula wix7` CLI switch (the FireGiant-recommended CI/CD path) rather than the per-user persistent acceptance file.

## Surprise / follow-up

`docs/cli/development/` is gitignored at `.gitignore:13`. The 20+ existing `windows-*.mdx` files in that directory are tracked despite the rule (presumably grandfathered when the rule was added). The new cookbook follows the established pattern via `git add -f`, but the gitignore rule is now actively misleading — it implies development docs aren't tracked, when in fact every doc author has been working around it.

**Suggested follow-up:** open a quick task to remove the `docs/cli/development/` line from `.gitignore` and verify the tracked-file inventory is unchanged. Out of scope for this commit.

## Verification

- `git diff --stat` on commit 7f2da598: 4 files, +247 / -3.
- `git diff` review: each edit matches the planned change in `PLAN.md`.
- No build executed locally — this commit is build-config only and will be exercised when the next release tag triggers `release.yml`. Recommend manually running `.\scripts\build-windows-msi.ps1 -VersionTag v0.37.1-poc.1 -BinaryPath .\target\x86_64-pc-windows-msvc\release\nono.exe -Scope user` before the first POC user gets the MSI, to surface any unexpected `wix.exe` / .NET 8 / OSMF acceptance issues.

## References

- [FireGiant OSMF docs](https://docs.firegiant.com/wix/osmf/)
- [WiX 7 NuGet package](https://www.nuget.org/packages/wix/7.0.0)
- [What's new in WiX v6+](https://docs.firegiant.com/wix/whatsnew/)
