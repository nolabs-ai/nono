param(
    [Parameter(Mandatory = $true)]
    [string]$VersionTag,

    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    # Phase 31 Plan 04: nono-shell-broker.exe is required for v2.3 SHELL-01 enforcement.
    # The broker installs as a sibling of nono.exe in INSTALLFOLDER so the runtime
    # cascade arm in spawn_windows_child resolves it via current_exe().parent() (D-07).
    # Mandatory so release.yml's invocation cannot accidentally omit it (fail-closed).
    [Parameter(Mandatory = $true)]
    [string]$BrokerPath,

    [ValidateSet("machine", "user")]
    [string]$Scope = "machine",

    [string]$OutputDir = "dist/windows",

    [string]$Manufacturer = "Luke Hinds and Oscar Mack Jr",

    [string]$ServiceBinaryPath = "",

    # Quick task 260522-c9c: -DriverBinaryPath ships the pre-signed WFP kernel
    # driver (nono-wfp-driver.sys) as a flat data file in the machine-scope MSI.
    # The driver source MUST be the checked-in pre-signed copy under
    # `crates/nono-cli/data/windows/nono-wfp-driver.sys` (NOT a dev-build
    # artifact under target/) so the shipped MSI carries the WHQL-signed driver.
    # User scope MUST omit this parameter — a kernel driver cannot load from
    # per-user LocalAppData; the script throws fail-closed if user scope
    # receives this flag. Machine scope requires this flag whenever
    # -ServiceBinaryPath is supplied (and vice-versa): a half-installed WFP
    # backend is worse than none — the runtime probe already fail-closes with a
    # directive message when BOTH binaries are absent.
    [string]$DriverBinaryPath = "",

    [switch]$EmitOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-MsiVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tag
    )

    $normalized = $Tag.Trim()
    if ($normalized.StartsWith("v")) {
        $normalized = $normalized.Substring(1)
    }

    $coreVersion = ($normalized -split "-", 2)[0]
    $parts = $coreVersion -split "\."
    if ($parts.Count -lt 3) {
        throw "MSI packaging requires a semantic version with at least major.minor.patch; got '$Tag'."
    }

    $numericParts = @()
    foreach ($part in $parts[0..([Math]::Min($parts.Count, 4) - 1)]) {
        $parsed = 0
        if (-not [int]::TryParse($part, [ref]$parsed)) {
            throw "MSI version components must be numeric; got '$part' in '$Tag'."
        }
        $numericParts += [string]$parsed
    }

    while ($numericParts.Count -lt 3) {
        $numericParts += "0"
    }

    return ($numericParts -join ".")
}

function Get-ScopeMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallScope
    )

    switch ($InstallScope) {
        "machine" {
            return @{
                PackageScope = "perMachine"
                DirectoryXml = @"
    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="nono" />
    </StandardDirectory>
"@
                RegistryRoot = "HKLM"
                SystemPath = "yes"
                UpgradeCode = "D5948D55-89A4-4F09-AB43-44DBA9D25D1A"
                PackageSuffix = "machine"
                ScopeLabel = "administrative install"
            }
        }
        "user" {
            return @{
                PackageScope = "perUser"
                DirectoryXml = @"
    <StandardDirectory Id="LocalAppDataFolder">
      <Directory Id="USERPROGRAMS" Name="Programs">
        <Directory Id="INSTALLFOLDER" Name="nono" />
      </Directory>
    </StandardDirectory>
"@
                RegistryRoot = "HKCU"
                SystemPath = "no"
                UpgradeCode = "5451E72C-E0C4-4BF8-B9EA-0D6A22AA80E4"
                PackageSuffix = "user"
                ScopeLabel = "end-user install"
            }
        }
        default {
            throw "Unsupported MSI scope '$InstallScope'."
        }
    }
}

function Write-Utf8NoBomCompat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        Set-Content -LiteralPath $Path -Value $Value -Encoding utf8NoBOM
        return
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $utf8NoBom)
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$binaryFullPath = (Resolve-Path -LiteralPath $BinaryPath).Path

# Phase 31 Plan 04: validate the broker binary path before generating the WiX
# manifest. Fail-closed (throw) on missing path, mirroring the $ServiceBinaryPath
# validation pattern below. The broker is mandatory at the parameter level, so
# this guard catches "path resolves but file missing" cases (e.g. typoed path or
# missed cargo build step in the caller's workflow).
if (-not (Test-Path -LiteralPath $BrokerPath)) {
    throw "BrokerPath does not exist: '$BrokerPath'."
}
$brokerFullPath = (Resolve-Path -LiteralPath $BrokerPath).Path

$serviceBinaryFullPath = ""
if ($ServiceBinaryPath -ne "") {
    if (-not (Test-Path -LiteralPath $ServiceBinaryPath)) {
        throw "Service binary not found at '$ServiceBinaryPath'."
    }
    $serviceBinaryFullPath = (Resolve-Path -LiteralPath $ServiceBinaryPath).Path
}

# Quick task 260522-c9c: resolve the pre-signed WFP kernel driver path.
# Fail-closed if the caller passes a non-empty path that does not exist on
# disk (CLAUDE.md "Fail Secure": never silently degrade).
$driverBinaryFullPath = ""
if ($DriverBinaryPath -ne "") {
    if (-not (Test-Path -LiteralPath $DriverBinaryPath)) {
        throw "Driver binary not found at '$DriverBinaryPath'."
    }
    $driverBinaryFullPath = (Resolve-Path -LiteralPath $DriverBinaryPath).Path
}

# Quick task 260522-c9c: scope-coherence guards for the WFP backend.
#   - Service + driver are machine-scope only. The driver is a kernel-mode
#     component and the service runs under LocalSystem; neither can run from
#     per-user LocalAppData. Refuse user-scope invocations that try to ship
#     them so a misconfigured CI cannot silently produce a broken user MSI.
#   - If machine-scope and a service path is provided, the driver path MUST
#     also be provided (and vice-versa). A half-installed WFP backend is worse
#     than none — the runtime probe (exec_strategy_windows::network) already
#     emits a clear directive message when BOTH binaries are absent at
#     INSTALLFOLDER, but cannot recover from a partial install.
if ($Scope -eq "user" -and ($serviceBinaryFullPath -ne "" -or $driverBinaryFullPath -ne "")) {
    throw "WFP service/driver binaries are machine-scope only. Drop -ServiceBinaryPath/-DriverBinaryPath when -Scope user."
}
if ($Scope -eq "machine") {
    $hasService = $serviceBinaryFullPath -ne ""
    $hasDriver  = $driverBinaryFullPath -ne ""
    if ($hasService -xor $hasDriver) {
        throw "Machine-scope MSI requires both -ServiceBinaryPath and -DriverBinaryPath, or neither (got service='$serviceBinaryFullPath', driver='$driverBinaryFullPath')."
    }
}

$readmePath = Join-Path $repoRoot "README.md"
$licensePath = Join-Path $repoRoot "LICENSE"

if (-not (Test-Path -LiteralPath $readmePath)) {
    throw "Missing README.md at '$readmePath'."
}

if (-not (Test-Path -LiteralPath $licensePath)) {
    throw "Missing LICENSE at '$licensePath'."
}

$outputFullPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDir))
New-Item -ItemType Directory -Force -Path $outputFullPath | Out-Null

$msiVersion = ConvertTo-MsiVersion -Tag $VersionTag
$scopeInfo = Get-ScopeMetadata -InstallScope $Scope
$packageName = "nono-$VersionTag-x86_64-pc-windows-msvc-$($scopeInfo.PackageSuffix).msi"
$wxsName = "nono-$($scopeInfo.PackageSuffix).wxs"
$wxsPath = Join-Path $outputFullPath $wxsName
$msiPath = Join-Path $outputFullPath $packageName

# Service lifecycle for nono-wfp-service (machine MSI only):
#   Start="install"   - SCM starts the service after the MSI install sequence completes.
#   Stop="both"       - SCM stops the service during upgrade (deferred remove) and uninstall.
#                       MajorUpgrade uses a remove+install cycle; "both" ensures the old
#                       service is stopped before file replacement and before full uninstall.
#   Remove="uninstall"- SCM deletes the service registry entry on uninstall only.
#                       During upgrade, the new version's install re-creates the entry.
#   Wait="yes"        - Each SCM operation is synchronous; MSI sequence waits for completion.
$serviceComponentXml = ""
$driverComponentXml = ""
$eventLogComponentXml = ""
if ($Scope -eq "machine" -and $serviceBinaryFullPath -ne "") {
    $serviceComponentXml = @"
      <Component Id="cmpWfpServiceExe" Guid="*">
        <File Id="filWfpServiceExe" Source="$serviceBinaryFullPath" KeyPath="yes" />
        <ServiceInstall
            Id="svcWfpService"
            Name="nono-wfp-service"
            DisplayName="nono WFP Service"
            Description="nono Windows Filtering Platform backend service"
            Type="ownProcess"
            Start="demand"
            Account="LocalSystem"
            ErrorControl="normal"
            Arguments="--service-mode" />
        <ServiceControl
            Id="svcCtrlWfpService"
            Name="nono-wfp-service"
            Start="install"
            Stop="both"
            Remove="uninstall"
            Wait="yes" />
      </Component>
"@

    # Classic Windows Application Event Log source registration (machine MSI only).
    # Registers "nono-wfp-service" as an event source under the Application log.
    # The EventMessageFile value points to the service binary, which supplies
    # the message table resource used by Event Viewer to format log entries.
    # TypesSupported covers Information (4), Warning (2), and Error (1) = 7.
    $eventLogComponentXml = @"
      <Component Id="cmpEventLogSource" Guid="*">
        <RegistryKey
            Root="HKLM"
            Key="SYSTEM\CurrentControlSet\Services\EventLog\Application\nono-wfp-service">
          <RegistryValue
              Name="EventMessageFile"
              Type="string"
              Value="[INSTALLFOLDER]nono-wfp-service.exe"
              KeyPath="yes" />
          <RegistryValue
              Name="TypesSupported"
              Type="integer"
              Value="7" />
        </RegistryKey>
      </Component>
"@

    # Quick task 260522-c9c: ship the pre-signed WFP kernel driver as a flat
    # data file alongside nono-wfp-service.exe. The runtime probe
    # (exec_strategy_windows::network::probe_wfp_runtime) checks for the
    # presence of nono-wfp-driver.sys at INSTALLFOLDER\nono-wfp-driver.sys as a
    # sibling of nono.exe before attempting driver activation.
    #
    # We deliberately do NOT emit a <ServiceInstall> entry for the driver here:
    # kernel driver registration uses sc.exe / CreateService with the
    # SERVICE_KERNEL_DRIVER service type, which WiX's <ServiceInstall> cannot
    # represent (it only models user-mode services). The CLI command
    # `nono setup --install-wfp-driver` performs the kernel driver registration
    # post-install; the MSI's responsibility here is solely to land the .sys
    # file at a well-known sibling path so that command can find it.
    if ($driverBinaryFullPath -eq "") {
        throw "Internal error: machine scope reached driver-component emission with empty driver path. Scope coherence guard above is broken."
    }
    $driverComponentXml = @"
      <Component Id="cmpWfpDriverSys" Guid="*">
        <File Id="filWfpDriverSys" Source="$driverBinaryFullPath" Name="nono-wfp-driver.sys" KeyPath="yes" />
      </Component>
"@
}

$wxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package
      Name="nono"
      Manufacturer="$Manufacturer"
      Version="$msiVersion"
      UpgradeCode="$($scopeInfo.UpgradeCode)"
      Scope="$($scopeInfo.PackageScope)">
    <SummaryInformation
        Description="nono Windows native installer ($($scopeInfo.ScopeLabel))"
        Manufacturer="$Manufacturer" />
    <MajorUpgrade
        DowngradeErrorMessage="A newer version of [ProductName] is already installed." />
    <MediaTemplate EmbedCab="yes" CompressionLevel="high" />
    <Property Id="ARPCOMMENTS" Value="nono Windows native installer ($($scopeInfo.ScopeLabel))" />
    <Property Id="ARPCONTACT" Value="$Manufacturer" />
    <Property Id="ARPURLHELP" Value="https://docs.nono.sh/cli/getting_started/installation" />
    <Property Id="ARPURLINFOABOUT" Value="https://github.com/always-further/nono" />
    <Property Id="ARPURLUPDATEINFO" Value="https://github.com/always-further/nono/releases" />
    <Property Id="ARPNOMODIFY" Value="1" />
    <Property Id="ARPNOREPAIR" Value="1" />
    <Feature Id="MainFeature" Title="nono" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
  </Package>

  <Fragment>
$($scopeInfo.DirectoryXml)
  </Fragment>

  <Fragment>
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <Component Id="cmpNonoExe" Guid="*">
        <File Id="filNonoExe" Source="$binaryFullPath" KeyPath="yes" />
      </Component>
      <Component Id="cmpNonoShellBrokerExe" Guid="*">
        <!-- Phase 31 Plan 04: nono-shell-broker.exe lives under INSTALLFOLDER
             (the ComponentGroup's Directory attribute) so both binaries install
             to the same dir at runtime. Satisfies D-07 sibling resolution
             (current_exe().parent() finds the broker) for both machine scope
             (Program Files\nono\) and user scope (LocalAppData\Programs\nono\).
             No scope guard needed — broker is required for both MSIs. -->
        <File Id="filNonoShellBrokerExe" Source="$brokerFullPath" KeyPath="yes" />
      </Component>
      <Component Id="cmpReadme" Guid="*">
        <File Id="filReadme" Source="$readmePath" Name="README.md" KeyPath="yes" />
      </Component>
      <Component Id="cmpLicense" Guid="*">
        <File Id="filLicense" Source="$licensePath" Name="LICENSE" KeyPath="yes" />
      </Component>
      <Component Id="cmpPath" Guid="*">
        <RegistryValue
            Root="$($scopeInfo.RegistryRoot)"
            Key="Software\always-further\nono\$Scope"
            Name="InstallDir"
            Type="string"
            Value="[INSTALLFOLDER]"
            KeyPath="yes" />
        <Environment
            Id="EnvPath"
            Name="PATH"
            Action="set"
            Part="last"
            Permanent="no"
            System="$($scopeInfo.SystemPath)"
            Value="[INSTALLFOLDER]" />
      </Component>
$($serviceComponentXml)$($driverComponentXml)$($eventLogComponentXml)    </ComponentGroup>
  </Fragment>
</Wix>
"@

Write-Utf8NoBomCompat -Path $wxsPath -Value $wxsContent

if ($EmitOnly) {
    Write-Host "Wrote WiX source to $wxsPath"
    return
}

$wix = Get-Command wix -ErrorAction SilentlyContinue
if ($null -eq $wix) {
    throw "WiX CLI was not found on PATH. Install WiX v7 (e.g. ``dotnet tool install --global wix --version 7.0.0``) and rerun the packaging script."
}

if (Test-Path -LiteralPath $msiPath) {
    Remove-Item -LiteralPath $msiPath -Force
}

# -acceptEula wix7 acknowledges the FireGiant OSMF EULA non-interactively.
# Required by WiX v7 (enforced via WIX7015); our usage is below the OSMF $10K/yr
# revenue threshold so no fee is owed, but explicit acceptance is still required.
& $wix.Source build $wxsPath -arch x64 -out $msiPath -acceptEula wix7
if ($LASTEXITCODE -ne 0) {
    throw "WiX failed while building '$msiPath'."
}

Write-Host "Built MSI package: $msiPath"
