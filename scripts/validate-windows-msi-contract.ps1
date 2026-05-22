param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    # Phase 41 (REQ-CI-02): -BrokerPath is mandatory because scripts/build-windows-msi.ps1
    # made it mandatory in Phase 31 Plan 04 (2026-05-09). Without this, the MSI validator
    # fails with "Cannot process command because of one or more missing mandatory parameters: BrokerPath".
    [Parameter(Mandatory = $true)]
    [string]$BrokerPath,

    [string]$ServiceBinaryPath = "",

    # Quick task 260522-c9c: -DriverBinaryPath threads the pre-signed WFP
    # kernel driver path through to build-windows-msi.ps1. CI must pass this
    # whenever it also passes -ServiceBinaryPath: build-windows-msi.ps1's
    # scope-coherence guard throws if machine scope gets one without the
    # other.
    [string]$DriverBinaryPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-WixDocumentForScope {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scope,

        [Parameter(Mandatory = $true)]
        [string]$Binary,

        [Parameter(Mandatory = $true)]
        [string]$BrokerBinary,

        [string]$ServiceBinary = "",

        # Quick task 260522-c9c: pre-signed WFP driver path threaded through to
        # build-windows-msi.ps1 -DriverBinaryPath. Machine scope MUST receive
        # this whenever it also receives ServiceBinary; build-windows-msi.ps1
        # enforces this and the caller below maps the parameter accordingly.
        [string]$DriverBinary = ""
    )

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $tempDirName = "temp-msi-contract-" + $Scope
    $tempDir = Join-Path $repoRoot $tempDirName

    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -Recurse -Force -LiteralPath $tempDir
    }

    try {
        $buildArgs = @{
            VersionTag  = "v0.0.0-preview"
            BinaryPath  = $Binary
            BrokerPath  = $BrokerBinary    # unconditional; BrokerPath is mandatory in build-windows-msi.ps1
            Scope       = $Scope
            OutputDir   = $tempDirName
            EmitOnly    = $true
        }
        if ($ServiceBinary -ne "") {
            $buildArgs["ServiceBinaryPath"] = $ServiceBinary
        }
        if ($DriverBinary -ne "") {
            $buildArgs["DriverBinaryPath"] = $DriverBinary
        }
        & (Join-Path $PSScriptRoot "build-windows-msi.ps1") @buildArgs

        $wxsPath = Join-Path $tempDir ("nono-" + $Scope + ".wxs")
        if (-not (Test-Path -LiteralPath $wxsPath)) {
            throw "Expected WiX source was not generated for scope '$Scope'."
        }

        return [xml](Get-Content -LiteralPath $wxsPath -Raw)
    }
    finally {
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -Recurse -Force -LiteralPath $tempDir
        }
    }
}

function Get-FirstNodeByLocalName {
    param(
        [Parameter(Mandatory = $true)]
        [xml]$Document,

        [Parameter(Mandatory = $true)]
        [string]$LocalName
    )

    $nodes = $Document.SelectNodes(("//*[local-name()='" + $LocalName + "']"))
    if ($null -eq $nodes -or $nodes.Count -eq 0) {
        throw "Missing <$LocalName> node in generated WiX document."
    }

    return $nodes[0]
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]
        $Actual,

        [Parameter(Mandatory = $true)]
        $Expected,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message. Expected '$Expected', got '$Actual'."
    }
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

$binaryFullPath = (Resolve-Path -LiteralPath $BinaryPath).Path

if (-not (Test-Path -LiteralPath $BrokerPath)) {
    throw "BrokerPath does not exist: $BrokerPath"
}
$brokerFullPath = (Resolve-Path -LiteralPath $BrokerPath).Path

$serviceBinaryFullPath = ""
if ($ServiceBinaryPath -ne "") {
    if (-not (Test-Path -LiteralPath $ServiceBinaryPath)) {
        throw "Service binary not found at '$ServiceBinaryPath'."
    }
    $serviceBinaryFullPath = (Resolve-Path -LiteralPath $ServiceBinaryPath).Path
}

# Quick task 260522-c9c: resolve the checked-in pre-signed WFP driver path.
# Same fail-closed pattern as the service binary above.
$driverBinaryFullPath = ""
if ($DriverBinaryPath -ne "") {
    if (-not (Test-Path -LiteralPath $DriverBinaryPath)) {
        throw "Driver binary not found at '$DriverBinaryPath'."
    }
    $driverBinaryFullPath = (Resolve-Path -LiteralPath $DriverBinaryPath).Path
}

$machineDoc = Get-WixDocumentForScope -Scope "machine" -Binary $binaryFullPath -BrokerBinary $brokerFullPath -ServiceBinary $serviceBinaryFullPath -DriverBinary $driverBinaryFullPath
$userDoc = Get-WixDocumentForScope -Scope "user" -Binary $binaryFullPath -BrokerBinary $brokerFullPath

$machinePackage = Get-FirstNodeByLocalName -Document $machineDoc -LocalName "Package"
$userPackage = Get-FirstNodeByLocalName -Document $userDoc -LocalName "Package"
$machineMajorUpgrade = Get-FirstNodeByLocalName -Document $machineDoc -LocalName "MajorUpgrade"
$userMajorUpgrade = Get-FirstNodeByLocalName -Document $userDoc -LocalName "MajorUpgrade"

Assert-Equal -Actual $machinePackage.Scope -Expected "perMachine" -Message "Machine MSI scope mismatch"
Assert-Equal -Actual $userPackage.Scope -Expected "perUser" -Message "User MSI scope mismatch"
Assert-True -Condition ($machinePackage.UpgradeCode -ne $userPackage.UpgradeCode) -Message "Machine and user MSI must use different upgrade codes"
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($machinePackage.UpgradeCode)) -Message "Machine MSI upgrade code must be present"
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($userPackage.UpgradeCode)) -Message "User MSI upgrade code must be present"
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($machineMajorUpgrade.DowngradeErrorMessage)) -Message "Machine MSI must declare MajorUpgrade downgrade messaging"
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($userMajorUpgrade.DowngradeErrorMessage)) -Message "User MSI must declare MajorUpgrade downgrade messaging"

$machineDirectoryXml = $machineDoc.OuterXml
$userDirectoryXml = $userDoc.OuterXml

Assert-True -Condition $machineDirectoryXml.Contains('ProgramFiles64Folder') -Message "Machine MSI must target ProgramFiles64Folder"
Assert-True -Condition $userDirectoryXml.Contains('LocalAppDataFolder') -Message "User MSI must target LocalAppDataFolder"

$machineNoRepair = $machineDoc.SelectSingleNode("//*[local-name()='Property' and @Id='ARPNOREPAIR']")
$userNoRepair = $userDoc.SelectSingleNode("//*[local-name()='Property' and @Id='ARPNOREPAIR']")
$machineNoModify = $machineDoc.SelectSingleNode("//*[local-name()='Property' and @Id='ARPNOMODIFY']")
$userNoModify = $userDoc.SelectSingleNode("//*[local-name()='Property' and @Id='ARPNOMODIFY']")

if ($null -eq $machineNoRepair -or $null -eq $userNoRepair) {
    throw "Both MSI scopes must disable ARP repair in the current release contract."
}
if ($null -eq $machineNoModify -or $null -eq $userNoModify) {
    throw "Both MSI scopes must disable ARP modify in the current release contract."
}

Assert-Equal -Actual $machineNoRepair.Value -Expected "1" -Message "Machine MSI ARPNOREPAIR mismatch"
Assert-Equal -Actual $userNoRepair.Value -Expected "1" -Message "User MSI ARPNOREPAIR mismatch"
Assert-Equal -Actual $machineNoModify.Value -Expected "1" -Message "Machine MSI ARPNOMODIFY mismatch"
Assert-Equal -Actual $userNoModify.Value -Expected "1" -Message "User MSI ARPNOMODIFY mismatch"

# Service and Event Log element assertions (machine MSI only)
if ($serviceBinaryFullPath -ne "") {
    $machineServiceInstall = Get-FirstNodeByLocalName -Document $machineDoc -LocalName "ServiceInstall"
    Assert-Equal -Actual $machineServiceInstall.Name -Expected "nono-wfp-service" `
        -Message "Machine MSI ServiceInstall Name mismatch"
    Assert-Equal -Actual $machineServiceInstall.Start -Expected "demand" `
        -Message "Machine MSI ServiceInstall Start mismatch"
    Assert-Equal -Actual $machineServiceInstall.Type -Expected "ownProcess" `
        -Message "Machine MSI ServiceInstall Type mismatch"
    Assert-Equal -Actual $machineServiceInstall.Account -Expected "LocalSystem" `
        -Message "Machine MSI ServiceInstall Account mismatch"

    $machineServiceControl = Get-FirstNodeByLocalName -Document $machineDoc -LocalName "ServiceControl"
    Assert-Equal -Actual $machineServiceControl.Name -Expected "nono-wfp-service" `
        -Message "Machine MSI ServiceControl Name mismatch"
    Assert-Equal -Actual $machineServiceControl.Stop -Expected "both" `
        -Message "Machine MSI ServiceControl Stop mismatch"
    Assert-Equal -Actual $machineServiceControl.Remove -Expected "uninstall" `
        -Message "Machine MSI ServiceControl Remove mismatch"
    Assert-Equal -Actual $machineServiceControl.Wait -Expected "yes" `
        -Message "Machine MSI ServiceControl Wait mismatch"

    # User MSI must contain no service elements (D-02)
    $userServiceInstalls = $userDoc.SelectNodes("//*[local-name()='ServiceInstall']")
    Assert-True -Condition ($null -eq $userServiceInstalls -or $userServiceInstalls.Count -eq 0) `
        -Message "User MSI must not contain ServiceInstall elements"
    $userServiceControls = $userDoc.SelectNodes("//*[local-name()='ServiceControl']")
    Assert-True -Condition ($null -eq $userServiceControls -or $userServiceControls.Count -eq 0) `
        -Message "User MSI must not contain ServiceControl elements"

    # Event Log source registration must exist in machine MSI (D-07).
    # The source is registered under the classic Application log via registry keys.
    $eventLogKey = "SYSTEM\CurrentControlSet\Services\EventLog\Application\nono-wfp-service"
    $machineRegistryKeys = $machineDoc.SelectNodes("//*[local-name()='RegistryKey']")
    $machineEventLogKey = $null
    foreach ($node in $machineRegistryKeys) {
        if ($node.Key -eq $eventLogKey) {
            $machineEventLogKey = $node
            break
        }
    }
    Assert-True -Condition ($null -ne $machineEventLogKey) `
        -Message "Machine MSI must register the classic Application Event Log source for nono-wfp-service"

    # EventMessageFile value must be present so Event Viewer can format entries.
    $eventMessageFileNode = $machineEventLogKey.SelectSingleNode(
        "*[local-name()='RegistryValue' and @Name='EventMessageFile']"
    )
    Assert-True -Condition ($null -ne $eventMessageFileNode) `
        -Message "Machine MSI Event Log source must include EventMessageFile registry value"

    # TypesSupported value must be present.
    $typesSupportedNode = $machineEventLogKey.SelectSingleNode(
        "*[local-name()='RegistryValue' and @Name='TypesSupported']"
    )
    Assert-True -Condition ($null -ne $typesSupportedNode) `
        -Message "Machine MSI Event Log source must include TypesSupported registry value"

    # User MSI must not carry any EventLog registry keys.
    $userRegistryKeys = $userDoc.SelectNodes("//*[local-name()='RegistryKey']")
    $userEventLogKey = $null
    foreach ($node in $userRegistryKeys) {
        if ($null -ne $node.Key -and $node.Key.Contains("EventLog")) {
            $userEventLogKey = $node
            break
        }
    }
    Assert-True -Condition ($null -eq $userEventLogKey) `
        -Message "User MSI must not register any EventLog registry keys"
}

# Quick task 260522-c9c: WFP kernel driver component assertions (machine MSI only).
# The driver is a flat data file (no <ServiceInstall>) at INSTALLFOLDER\nono-wfp-driver.sys.
# Without it, the runtime probe in exec_strategy_windows::network fails with
# BackendDriverBinaryMissing before any sandbox can be applied.
if ($driverBinaryFullPath -ne "") {
    # Machine MSI must have a Component with Id=cmpWfpDriverSys whose <File>
    # child has Name="nono-wfp-driver.sys" (the sibling-of-nono.exe name the
    # runtime probe checks for).
    $machineDriverFiles = $machineDoc.SelectNodes("//*[local-name()='File' and @Name='nono-wfp-driver.sys']")
    Assert-True -Condition ($null -ne $machineDriverFiles -and $machineDriverFiles.Count -ge 1) `
        -Message "Machine MSI must contain a <File Name='nono-wfp-driver.sys' /> element"

    # The driver MUST NOT receive a <ServiceInstall> — WiX's element only models
    # user-mode services and cannot represent SERVICE_KERNEL_DRIVER. The CLI
    # command `nono setup install-wfp-driver` performs the kernel registration
    # post-install instead.
    $machineComponents = $machineDoc.SelectNodes("//*[local-name()='Component' and @Id='cmpWfpDriverSys']")
    Assert-True -Condition ($null -ne $machineComponents -and $machineComponents.Count -ge 1) `
        -Message "Machine MSI must contain a Component with Id='cmpWfpDriverSys'"
    $driverServiceInstalls = $machineComponents[0].SelectNodes("*[local-name()='ServiceInstall']")
    Assert-True -Condition ($null -eq $driverServiceInstalls -or $driverServiceInstalls.Count -eq 0) `
        -Message "cmpWfpDriverSys must not contain ServiceInstall (kernel driver registration is post-install via the CLI)"

    # User MSI must not carry the driver component.
    $userDriverFiles = $userDoc.SelectNodes("//*[local-name()='File' and @Name='nono-wfp-driver.sys']")
    Assert-True -Condition ($null -eq $userDriverFiles -or $userDriverFiles.Count -eq 0) `
        -Message "User MSI must not contain nono-wfp-driver.sys file element"
}

Write-Host "Validated Windows MSI contract for machine and user scopes."
