---
slug: 260507-wix-bump-to-7-0-0
date: 2026-05-07
status: in-progress
type: build-config
---

# Bump WiX from 4.0.6 to 7.0.0

## Goal

Migrate the Windows MSI build pipeline from WiX 4.0.6 to WiX 7.0.0 (FireGiant OSMF). Three production files change. The .wxs schema does not: FireGiant docs confirm `http://wixtoolset.org/schemas/v4/wxs` is preserved through v5/v6/v7.

## Tasks

1. **`scripts/build-windows-msi.ps1`**
   - Update the "Install WiX v4" error message at line 282 to reference WiX v7 with the dotnet tool install command.
   - Add `-acceptEula wix7` to the `wix build` invocation at line 289 so CI runs do not fail with `WIX7015` from the OSMF EULA enforcement introduced in v6 and enforced in v7.

2. **`.github/workflows/release.yml`**
   - Change `WIX_VERSION: 4.0.6` → `WIX_VERSION: 7.0.0` at line 20. The `dotnet tool install --global wix --version $env:WIX_VERSION` line on L85 picks up the new version automatically.

3. **`docs/cli/development/windows-poc-handoff.mdx`** (uncommitted, just authored)
   - Pin the install line to `dotnet tool install --global wix --version 7.0.0`.
   - Change "WiX 4 or later" to "WiX 7 or later" in prerequisites.
   - Add a one-line note explaining why `-acceptEula wix7` appears in the script (OSMF EULA acceptance, not interactive in CI).

## Out of scope

- `.wxs` XML namespace — unchanged (`http://wixtoolset.org/schemas/v4/wxs` is preserved through v7).
- `Package`, `MajorUpgrade`, `MediaTemplate`, `ServiceInstall`, `ServiceControl`, `Environment`, `RegistryValue`, `StandardDirectory`, `ComponentGroup` element shapes — preserved.
- `scripts/validate-windows-msi-contract.ps1` — already namespace-agnostic (`//*[local-name()='Foo']` XPath).
- `dist/windows/nono-user.wxs` — generated artifact, not source. Will regenerate on next build.
- GitHub `windows-latest` runner .NET SDK — already ships .NET 8, which is WiX 7's minimum.

## References

- [FireGiant OSMF docs](https://docs.firegiant.com/wix/osmf/) — EULA acceptance methods (`-acceptEula <id>` switch, `<AcceptEula>` MSBuild property, per-user persistent file).
- [WiX 7 NuGet package](https://www.nuget.org/packages/wix/7.0.0) — install command unchanged.
- [What's new in WiX v6+](https://docs.firegiant.com/wix/whatsnew/) — confirms v4 namespace preservation.

## Commit plan

- One atomic commit on the three production files: `build(windows): bump WiX to 7.0.0 with OSMF EULA acceptance`.
- Follow-up commit on the planning trail: `docs(state): record quick task 260507-wix complete`.
- DCO sign-off: `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>`.
