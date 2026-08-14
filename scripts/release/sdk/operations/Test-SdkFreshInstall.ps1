[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedManifestSha256,

    [Parameter(Mandatory = $true)]
    [string]$PythonPath,

    [Parameter(Mandatory = $true)]
    [string]$ArtifactReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedArtifactReceiptSha256,

    [Parameter(Mandatory = $true)]
    [string]$MetadataReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedMetadataReceiptSha256,

    [Parameter(Mandatory = $true)]
    [string]$ArtifactRoot,

    [Parameter(Mandatory = $true)]
    [string]$WorkRoot,

    [Parameter(Mandatory = $true)]
    [string]$ReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $Properties = @(
        $InputObject.PSObject.Properties |
            Where-Object { $_.Name -ceq $Name }
    )
    if ($Properties.Count -ne 1) {
        throw "STOP: required property is missing or duplicated: $Name"
    }
    return $Properties[0].Value
}

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [object]$DefaultValue = $null
    )

    $Properties = @(
        $InputObject.PSObject.Properties |
            Where-Object { $_.Name -ceq $Name }
    )
    if ($Properties.Count -gt 1) {
        throw "STOP: property is duplicated: $Name"
    }
    if ($Properties.Count -eq 0) {
        return $DefaultValue
    }
    return $Properties[0].Value
}

function Assert-HexDigest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [int]$Length,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ($Value -cnotmatch ('\A[0-9a-f]{' + $Length + '}\z')) {
        throw "STOP: invalid $Label"
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-BytesSha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $Sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($Sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $Sha256.Dispose()
    }
}

function Assert-BoundFile {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ((Get-Sha256Hex -LiteralPath $LiteralPath) -cne $ExpectedSha256) {
        throw "STOP: bound input changed during operation: $Label"
    }
}

function Read-BoundJsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][ref]$OpenStream
    )
    Assert-BoundFile $LiteralPath $ExpectedSha256 $Label
    $Stream = $null
    try {
        $Stream = [IO.File]::Open(
            $LiteralPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $OpenStream.Value = $Stream
        if ($Stream.Length -gt [int]::MaxValue) {
            throw "STOP: bound JSON input is too large: $Label"
        }
        $Bytes = [byte[]]::new([int]$Stream.Length)
        $Offset = 0
        while ($Offset -lt $Bytes.Length) {
            $ReadCount = $Stream.Read($Bytes, $Offset, $Bytes.Length - $Offset)
            if ($ReadCount -le 0) {
                throw "STOP: bound JSON input ended while reading: $Label"
            }
            $Offset += $ReadCount
        }
        if ((Get-BytesSha256Hex -Bytes $Bytes) -cne $ExpectedSha256) {
            throw "STOP: bound input changed while reading: $Label"
        }
        $StrictUtf8 = New-Object System.Text.UTF8Encoding -ArgumentList @($false, $true)
        $Value = $StrictUtf8.GetString($Bytes) | ConvertFrom-Json
        Assert-BoundFile $LiteralPath $ExpectedSha256 $Label
        return $Value
    }
    catch {
        if ($null -ne $Stream) {
            $Stream.Dispose()
            $OpenStream.Value = $null
        }
        throw
    }
}

function Open-HashedReadFile {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $Stream = $null
    $Sha256 = $null
    try {
        $Stream = [IO.File]::Open(
            $LiteralPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $Sha256 = [Security.Cryptography.SHA256]::Create()
        $ObservedSha256 = ([BitConverter]::ToString(
            $Sha256.ComputeHash($Stream)
        )).Replace('-', '').ToLowerInvariant()
        $Stream.Position = 0
        if ($ObservedSha256 -cne $ExpectedSha256) {
            throw "STOP: fixed artifact hash mismatch while locking: $Label"
        }
        return [pscustomobject]@{
            path = $LiteralPath
            label = $Label
            sha256 = $ObservedSha256
            size = [long]$Stream.Length
            stream = $Stream
        }
    }
    catch {
        if ($null -ne $Stream) {
            $Stream.Dispose()
        }
        throw
    }
    finally {
        if ($null -ne $Sha256) {
            $Sha256.Dispose()
        }
    }
}

function ConvertTo-JsonArray {
    param(
        [object[]]$Values
    )

    return (ConvertTo-Json -InputObject @($Values) -Compress)
}

function Invoke-ExternalChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $Output = @(& $FilePath @Arguments)
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        throw "STOP: $Label failed with exit code $ExitCode"
    }
    return $Output
}

function ConvertTo-CanonicalPipFreeze {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Lines,

        [Parameter(Mandatory = $true)]
        [string]$DistributionName,

        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $ExpectedNormalizedName = (
        $DistributionName -replace '[-_.]+', '-'
    ).ToLowerInvariant()
    $Canonical = @()
    foreach ($LineValue in $Lines) {
        $Line = ([string]$LineValue).Trim()
        if ([string]::IsNullOrWhiteSpace($Line)) {
            continue
        }
        if ($Line -match '\A(.+?)\s+@\s+(.+)\z') {
            $ObservedNormalizedName = (
                [string]$Matches[1] -replace '[-_.]+', '-'
            ).ToLowerInvariant()
            if ($ObservedNormalizedName -cne $ExpectedNormalizedName) {
                throw 'STOP: pip freeze contains an unexpected direct-reference dependency.'
            }
            $Canonical += ($DistributionName + '==' + $Version)
        }
        else {
            if ($Line -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._-]*==[^\s]+\z') {
                throw 'STOP: pip freeze contains a noncanonical or potentially sensitive entry.'
            }
            $Canonical += $Line
        }
    }
    return @($Canonical | Sort-Object -CaseSensitive)
}

function Write-JsonReceipt {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($Parent)) {
        $Parent = (Get-Location).Path
    }
    if (-not (Test-Path -LiteralPath $Parent -PathType Container)) {
        try {
            New-Item -ItemType Directory -Path $Parent -ErrorAction Stop |
                Out-Null
        }
        catch {
            if (-not (Test-Path -LiteralPath $Parent -PathType Container)) {
                throw
            }
        }
    }

    $FullPath = [IO.Path]::GetFullPath($Path)
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $Bytes = $Utf8NoBom.GetBytes(($Value | ConvertTo-Json -Depth 12))
    $Stream = $null
    try {
        try {
            $Stream = [IO.File]::Open(
                $FullPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None
            )
        }
        catch {
            if (Test-Path -LiteralPath $FullPath) {
                throw "STOP: receipt already exists: $FullPath"
            }
            throw
        }
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    }
    finally {
        if ($null -ne $Stream) {
            $Stream.Dispose()
        }
    }
}

foreach ($RequiredPath in @(
    $ManifestPath,
    $PythonPath,
    $ArtifactReceiptPath,
    $MetadataReceiptPath
)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "STOP: required file is unavailable: $RequiredPath"
    }
}
if (Test-Path -LiteralPath $WorkRoot) {
    throw "STOP: fresh-install work root already exists: $WorkRoot"
}
if (Test-Path -LiteralPath $ReceiptPath) {
    throw "STOP: receipt already exists: $ReceiptPath"
}
if (-not (Test-Path -LiteralPath $ArtifactRoot -PathType Container)) {
    throw "STOP: artifact root is unavailable: $ArtifactRoot"
}

$ManifestFullPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$PythonFullPath = (Resolve-Path -LiteralPath $PythonPath).Path
$ArtifactReceiptFullPath = (
    Resolve-Path -LiteralPath $ArtifactReceiptPath
).Path
$MetadataReceiptFullPath = (
    Resolve-Path -LiteralPath $MetadataReceiptPath
).Path
$ArtifactRootFullPath = (Resolve-Path -LiteralPath $ArtifactRoot).Path
Assert-HexDigest $ExpectedArtifactReceiptSha256 64 'expected artifact receipt SHA-256'
Assert-HexDigest $ExpectedMetadataReceiptSha256 64 'expected metadata receipt SHA-256'
$ExpectedArtifactReceiptSha256 = $ExpectedArtifactReceiptSha256.ToLowerInvariant()
$ExpectedMetadataReceiptSha256 = $ExpectedMetadataReceiptSha256.ToLowerInvariant()
$ArtifactReceiptSha256 = Get-Sha256Hex -LiteralPath $ArtifactReceiptFullPath
$MetadataReceiptSha256 = Get-Sha256Hex -LiteralPath $MetadataReceiptFullPath
if ($ArtifactReceiptSha256 -cne $ExpectedArtifactReceiptSha256) {
    throw 'STOP: artifact receipt bytes do not match the Human-supplied SHA-256.'
}
if ($MetadataReceiptSha256 -cne $ExpectedMetadataReceiptSha256) {
    throw 'STOP: metadata receipt bytes do not match the Human-supplied SHA-256.'
}
$WorkFullPath = [IO.Path]::GetFullPath($WorkRoot)
Assert-HexDigest $ExpectedManifestSha256 64 'expected manifest SHA-256'
$ExpectedManifestSha256 = $ExpectedManifestSha256.ToLowerInvariant()
$ManifestSha256 = Get-Sha256Hex -LiteralPath $ManifestFullPath
if ($ManifestSha256 -cne $ExpectedManifestSha256) {
    throw 'STOP: release manifest bytes do not match the Human-supplied SHA-256.'
}
$ScriptSha256 = Get-Sha256Hex -LiteralPath $PSCommandPath

$ManifestStream = $null
$ArtifactReceiptStream = $null
$MetadataReceiptStream = $null
$WheelFileBinding = $null
$SdistFileBinding = $null
try {
$Manifest = Read-BoundJsonFile `
    $ManifestFullPath `
    $ManifestSha256 `
    'release manifest' `
    ([ref]$ManifestStream)
$ArtifactReceipt = Read-BoundJsonFile `
    $ArtifactReceiptFullPath `
    $ExpectedArtifactReceiptSha256 `
    'artifact build receipt' `
    ([ref]$ArtifactReceiptStream)
$MetadataReceipt = Read-BoundJsonFile `
    $MetadataReceiptFullPath `
    $ExpectedMetadataReceiptSha256 `
    'artifact metadata receipt' `
    ([ref]$MetadataReceiptStream)

$SchemaVersion = [string](Get-RequiredProperty $Manifest 'schema_version')
if ($SchemaVersion -cne 'ln_church.sdk_release_manifest.v1') {
    throw "STOP: unsupported manifest schema: $SchemaVersion"
}

$Tooling = Get-RequiredProperty $Manifest 'tooling'
$OperationSha256 = Get-RequiredProperty $Tooling 'operation_sha256'
$ExpectedScriptSha256 = (
    [string](Get-RequiredProperty $OperationSha256 'Test-SdkFreshInstall')
).ToLowerInvariant()
$ExpectedBuildScriptSha256 = (
    [string](Get-RequiredProperty $OperationSha256 'Build-SdkArtifacts')
).ToLowerInvariant()
$ExpectedMetadataScriptSha256 = (
    [string](
        Get-RequiredProperty $OperationSha256 'Test-SdkArtifactMetadata'
    )
).ToLowerInvariant()
$ArtifactReceiptScriptSha256 = (
    [string](Get-RequiredProperty $ArtifactReceipt 'script_sha256')
).ToLowerInvariant()
$MetadataReceiptScriptSha256 = (
    [string](Get-RequiredProperty $MetadataReceipt 'script_sha256')
).ToLowerInvariant()
foreach ($DigestCheck in @(
    [pscustomobject]@{ value = $ExpectedScriptSha256; label = 'Test-SdkFreshInstall SHA-256' },
    [pscustomobject]@{ value = $ExpectedBuildScriptSha256; label = 'Build-SdkArtifacts SHA-256' },
    [pscustomobject]@{ value = $ExpectedMetadataScriptSha256; label = 'Test-SdkArtifactMetadata SHA-256' },
    [pscustomobject]@{ value = $ArtifactReceiptScriptSha256; label = 'artifact receipt script SHA-256' },
    [pscustomobject]@{ value = $MetadataReceiptScriptSha256; label = 'metadata receipt script SHA-256' }
)) {
    Assert-HexDigest $DigestCheck.value 64 $DigestCheck.label
}
if ($ScriptSha256 -cne $ExpectedScriptSha256) {
    throw 'STOP: Test-SdkFreshInstall script bytes do not match the manifest.'
}
if ($ArtifactReceiptScriptSha256 -cne $ExpectedBuildScriptSha256) {
    throw 'STOP: artifact receipt was produced by noncanonical script bytes.'
}
if ($MetadataReceiptScriptSha256 -cne $ExpectedMetadataScriptSha256) {
    throw 'STOP: metadata receipt was produced by noncanonical script bytes.'
}

foreach ($ReceiptCheck in @(
    [pscustomobject]@{
        receipt = $ArtifactReceipt
        operation = 'Build-SdkArtifacts'
        result = 'SDK_ARTIFACT_BUILD: PASS'
        label = 'artifact build'
    },
    [pscustomobject]@{
        receipt = $MetadataReceipt
        operation = 'Test-SdkArtifactMetadata'
        result = 'SDK_ARTIFACT_METADATA: PASS'
        label = 'artifact metadata'
    }
)) {
    $ObservedSchema = [string](
        Get-RequiredProperty $ReceiptCheck.receipt 'schema_version'
    )
    $ObservedOperation = [string](
        Get-RequiredProperty $ReceiptCheck.receipt 'operation'
    )
    $ObservedResult = [string](
        Get-RequiredProperty $ReceiptCheck.receipt 'result'
    )
    $ObservedManifestSha256 = (
        [string](
            Get-RequiredProperty $ReceiptCheck.receipt 'manifest_sha256'
        )
    ).ToLowerInvariant()
    if ($ObservedSchema -cne 'ln_church.sdk_release_receipt.v1' -or
        $ObservedOperation -cne $ReceiptCheck.operation -or
        $ObservedResult -cne $ReceiptCheck.result) {
        throw "STOP: $($ReceiptCheck.label) receipt is not an accepted PASS receipt."
    }
    if ($ObservedManifestSha256 -cne $ManifestSha256) {
        throw "STOP: $($ReceiptCheck.label) receipt used a different manifest."
    }
}

$MetadataArtifactReceiptSha256 = (
    [string](
        Get-RequiredProperty $MetadataReceipt 'artifact_receipt_sha256'
    )
).ToLowerInvariant()
if ($MetadataArtifactReceiptSha256 -cne $ExpectedArtifactReceiptSha256) {
    throw 'STOP: metadata receipt qualified different artifact-receipt bytes.'
}

$Release = Get-RequiredProperty $Manifest 'release'
$Package = Get-RequiredProperty $Manifest 'package'
$Python = Get-RequiredProperty $Manifest 'python'
$FreshInstall = Get-RequiredProperty $Manifest 'fresh_install'
$Version = [string](Get-RequiredProperty $Release 'version')
$Tag = [string](Get-RequiredProperty $Release 'tag')
$DistributionName = [string](
    Get-RequiredProperty $Package 'distribution_name'
)
$ImportName = [string](Get-RequiredProperty $Package 'import_name')
$ConsoleScripts = Get-RequiredProperty $Package 'console_scripts'
$ExpectedPythonMajor = [int](Get-RequiredProperty $Python 'major')
$ExpectedPythonMinor = [int](Get-RequiredProperty $Python 'minor')
$ExpectedPythonMicro = [int](Get-RequiredProperty $Python 'micro')
$ExpectedPipVersion = [string](Get-RequiredProperty $Tooling 'pip_version')
$OptionalExtra = [string](
    Get-OptionalProperty $FreshInstall 'optional_extra' ''
)
$CoreImports = @(Get-RequiredProperty $FreshInstall 'core_imports')
$CoreForbiddenImports = @(
    Get-RequiredProperty $FreshInstall 'core_forbidden_imports'
)
$ExtraImports = @(Get-RequiredProperty $FreshInstall 'extra_imports')
$SmokeCommands = @(Get-RequiredProperty $FreshInstall 'smoke_commands')

if ($Tag -cne ('v' + $Version)) {
    throw 'STOP: release tag must be exactly v plus the release version.'
}

foreach ($ModuleName in @($CoreImports + $CoreForbiddenImports + $ExtraImports)) {
    if ([string]$ModuleName -cnotmatch (
        '\A[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\z'
    )) {
        throw "STOP: invalid Python import name in manifest: $ModuleName"
    }
}
if ($ImportName -cnotmatch (
    '\A[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\z'
)) {
    throw "STOP: invalid package import name: $ImportName"
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
Assert-BoundFile $MetadataReceiptFullPath $ExpectedMetadataReceiptSha256 'artifact metadata receipt'
$PythonVersionRaw = Invoke-ExternalChecked `
    -FilePath $PythonFullPath `
    -Arguments @(
        '-I', '-c',
        ('import json,sys; print(json.dumps({' +
        '"major":sys.version_info.major,"minor":sys.version_info.minor,' +
        '"micro":sys.version_info.micro}))')
    ) `
    -Label 'Python version read'
$PythonVersion = ($PythonVersionRaw -join [Environment]::NewLine) |
    ConvertFrom-Json
if ([int]$PythonVersion.major -ne $ExpectedPythonMajor -or
    [int]$PythonVersion.minor -ne $ExpectedPythonMinor -or
    [int]$PythonVersion.micro -ne $ExpectedPythonMicro) {
    throw 'STOP: selected Python does not match the manifest version.'
}
$PythonVersionText = [string]::Format(
    '{0}.{1}.{2}',
    $PythonVersion.major,
    $PythonVersion.minor,
    $PythonVersion.micro
)

$ArtifactItems = @(Get-RequiredProperty $ArtifactReceipt 'artifacts')
$WheelItems = @($ArtifactItems | Where-Object { $_.kind -ceq 'wheel' })
$SdistItems = @($ArtifactItems | Where-Object { $_.kind -ceq 'sdist' })
if ($ArtifactItems.Count -ne 2 -or
    $WheelItems.Count -ne 1 -or
    $SdistItems.Count -ne 1) {
    throw 'STOP: artifact receipt must contain exactly one wheel and one sdist.'
}
$Wheel = $WheelItems[0]
$WheelFilename = [string](Get-RequiredProperty $Wheel 'filename')
$WheelSize = [long](Get-RequiredProperty $Wheel 'size')
$WheelSha256 = (
    [string](Get-RequiredProperty $Wheel 'sha256')
).ToLowerInvariant()
Assert-HexDigest $WheelSha256 64 'wheel SHA-256'
if ([IO.Path]::GetFileName($WheelFilename) -cne $WheelFilename -or
    [string]::IsNullOrWhiteSpace($WheelFilename)) {
    throw 'STOP: wheel filename in artifact receipt is invalid.'
}
$WheelPath = Join-Path $ArtifactRootFullPath $WheelFilename
if (-not (Test-Path -LiteralPath $WheelPath -PathType Leaf)) {
    throw "STOP: fixed wheel is unavailable: $WheelPath"
}
$WheelFileBinding = Open-HashedReadFile `
    -LiteralPath $WheelPath `
    -ExpectedSha256 $WheelSha256 `
    -Label $WheelFilename
$WheelItem = Get-Item -LiteralPath $WheelPath
if ($WheelItem.Name -cne $WheelFilename -or
    [long]$WheelItem.Length -ne $WheelSize -or
    [long]$WheelFileBinding.size -ne $WheelSize) {
    throw 'STOP: fixed wheel identity mismatch.'
}

$Sdist = $SdistItems[0]
$SdistFilename = [string](Get-RequiredProperty $Sdist 'filename')
$SdistSize = [long](Get-RequiredProperty $Sdist 'size')
$SdistSha256 = (
    [string](Get-RequiredProperty $Sdist 'sha256')
).ToLowerInvariant()
Assert-HexDigest $SdistSha256 64 'sdist SHA-256'
if ([IO.Path]::GetFileName($SdistFilename) -cne $SdistFilename -or
    [string]::IsNullOrWhiteSpace($SdistFilename)) {
    throw 'STOP: sdist filename in artifact receipt is invalid.'
}
$SdistPath = Join-Path $ArtifactRootFullPath $SdistFilename
if (-not (Test-Path -LiteralPath $SdistPath -PathType Leaf)) {
    throw "STOP: fixed sdist is unavailable: $SdistPath"
}
$SdistFileBinding = Open-HashedReadFile `
    -LiteralPath $SdistPath `
    -ExpectedSha256 $SdistSha256 `
    -Label $SdistFilename
$SdistItem = Get-Item -LiteralPath $SdistPath
if ($SdistItem.Name -cne $SdistFilename -or
    [long]$SdistItem.Length -ne $SdistSize -or
    [long]$SdistFileBinding.size -ne $SdistSize) {
    throw 'STOP: fixed sdist identity mismatch.'
}

$SavedEnvironment = @{}
$EnvironmentNames = @(
    'PIP_CONSTRAINT',
    'PIP_BUILD_CONSTRAINT',
    'PIP_REQUIREMENT',
    'PIP_CONFIG_FILE',
    'PIP_NO_INPUT',
    'PIP_DISABLE_PIP_VERSION_CHECK',
    'PIP_INDEX_URL',
    'PIP_EXTRA_INDEX_URL',
    'PIP_TRUSTED_HOST',
    'PIP_FIND_LINKS',
    'PIP_NO_INDEX',
    'PIP_CERT',
    'PIP_CLIENT_CERT',
    'PIP_TARGET',
    'PIP_PREFIX',
    'PIP_USER',
    'PIP_REQUIRE_VIRTUALENV',
    'PIP_BREAK_SYSTEM_PACKAGES',
    'PYTHONHOME',
    'PYTHONPATH',
    'VIRTUAL_ENV',
    'UV_CONSTRAINT',
    'UV_BUILD_CONSTRAINT'
)
foreach ($EnvironmentName in $EnvironmentNames) {
    $SavedEnvironment[$EnvironmentName] = [Environment]::GetEnvironmentVariable(
        $EnvironmentName,
        'Process'
    )
}

$CoreRoot = Join-Path $WorkFullPath 'core'
$ExtraRoot = Join-Path $WorkFullPath 'extra'
$RuntimeRoot = Join-Path $WorkFullPath 'runtime'
$EnvironmentReceipts = @()
$SmokeReceipts = @()

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
Assert-BoundFile $MetadataReceiptFullPath $ExpectedMetadataReceiptSha256 'artifact metadata receipt'
New-Item -ItemType Directory -Path $WorkFullPath | Out-Null
New-Item -ItemType Directory -Path $RuntimeRoot | Out-Null

try {
    foreach ($EnvironmentName in $EnvironmentNames) {
        [Environment]::SetEnvironmentVariable(
            $EnvironmentName,
            $null,
            'Process'
        )
    }
    [Environment]::SetEnvironmentVariable('PIP_CONFIG_FILE', 'NUL', 'Process')
    [Environment]::SetEnvironmentVariable('PIP_NO_INPUT', '1', 'Process')
    [Environment]::SetEnvironmentVariable(
        'PIP_DISABLE_PIP_VERSION_CHECK',
        '1',
        'Process'
    )

    Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
    Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
    Assert-BoundFile $MetadataReceiptFullPath $ExpectedMetadataReceiptSha256 'artifact metadata receipt'
    $null = Invoke-ExternalChecked `
        -FilePath $PythonFullPath `
        -Arguments @('-m', 'venv', $CoreRoot) `
        -Label 'core virtual environment creation'
    $CorePython = Join-Path (Join-Path $CoreRoot 'Scripts') 'python.exe'
    if (-not (Test-Path -LiteralPath $CorePython -PathType Leaf)) {
        throw 'STOP: core environment Python is unavailable.'
    }

    $CorePipVersionRaw = Invoke-ExternalChecked `
        -FilePath $CorePython `
        -Arguments @(
            '-I', '-c',
            "import importlib.metadata as m; print(m.version('pip'))"
        ) `
        -Label 'core pip version read'
    $CorePipVersion = (
        [string]($CorePipVersionRaw | Select-Object -First 1)
    ).Trim()
    if ($CorePipVersion -cne $ExpectedPipVersion) {
        throw (
            'STOP: core pip version mismatch. Expected {0}, observed {1}' -f
            $ExpectedPipVersion,
            $CorePipVersion
        )
    }

    $CoreImportsJson = ConvertTo-JsonArray $CoreImports
    $CoreForbiddenJson = ConvertTo-JsonArray $CoreForbiddenImports
    $PreinstallScript = (
        'import importlib.util,json,sys; ' +
        'names=json.loads(sys.argv[1])+json.loads(sys.argv[2]); ' +
        'missing=lambda n: importlib.util.find_spec(n.split(".")[0]) is None; ' +
        'assert all(missing(n) for n in names)'
    )
    $null = Invoke-ExternalChecked `
        -FilePath $CorePython `
        -Arguments @(
            '-I', '-c', $PreinstallScript, $CoreImportsJson, $CoreForbiddenJson
        ) `
        -Label 'core pre-install isolation check'

    Push-Location -LiteralPath $RuntimeRoot
    try {
        Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
        Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
        Assert-BoundFile $MetadataReceiptFullPath $ExpectedMetadataReceiptSha256 'artifact metadata receipt'
        Assert-BoundFile $WheelFileBinding.path $WheelFileBinding.sha256 'fixed wheel'
        Assert-BoundFile $SdistFileBinding.path $SdistFileBinding.sha256 'fixed sdist'
        $null = Invoke-ExternalChecked `
            -FilePath $CorePython `
            -Arguments @(
                '-m', 'pip', 'install', '--disable-pip-version-check',
                '--no-input', '--no-cache-dir', $WheelItem.FullName
            ) `
            -Label 'core fixed-wheel install'
        $null = Invoke-ExternalChecked `
            -FilePath $CorePython `
            -Arguments @('-m', 'pip', 'check') `
            -Label 'core pip check'
    }
    finally {
        Pop-Location
    }

    $InspectScript = @'
import importlib
import importlib.metadata
import json
import os
import sys
import sysconfig

distribution, version, import_name = sys.argv[1:4]
package = importlib.import_module(import_name)
origin = os.path.realpath(package.__file__)
sites = list({
    os.path.realpath(sysconfig.get_path("purelib")),
    os.path.realpath(sysconfig.get_path("platlib")),
})
matching_sites = [
    site for site in sites
    if os.path.commonpath([origin, site]) == site
]
installed = len(matching_sites) == 1
origin_relative = os.path.relpath(origin, matching_sites[0]) if installed else None
print(json.dumps({
    "version": importlib.metadata.version(distribution),
    "origin_is_installed": installed,
    "origin_relative": origin_relative,
}))
'@
    $CoreInspectRaw = Invoke-ExternalChecked `
        -FilePath $CorePython `
        -Arguments @(
            '-I', '-c', $InspectScript,
            $DistributionName, $Version, $ImportName
        ) `
        -Label 'core installed-package inspection'
    $CoreInspect = ($CoreInspectRaw -join [Environment]::NewLine) |
        ConvertFrom-Json
    if ([string]$CoreInspect.version -cne $Version -or
        -not [bool]$CoreInspect.origin_is_installed) {
        throw 'STOP: core installed package identity or origin mismatch.'
    }

    $CoreImportCheckScript = (
        'import importlib,json,sys; names=json.loads(sys.argv[1]); ' +
        '[importlib.import_module(n) for n in names]'
    )
    $null = Invoke-ExternalChecked `
        -FilePath $CorePython `
        -Arguments @(
            '-I', '-c', $CoreImportCheckScript, $CoreImportsJson
        ) `
        -Label 'core import check'

    if ($CoreForbiddenImports.Count -gt 0) {
        $ForbiddenCheckScript = (
            'import importlib.util,json,sys; names=json.loads(sys.argv[1]); ' +
            'assert all(importlib.util.find_spec(n.split(".")[0]) is None ' +
            'for n in names)'
        )
        $null = Invoke-ExternalChecked `
            -FilePath $CorePython `
            -Arguments @(
                '-I', '-c', $ForbiddenCheckScript, $CoreForbiddenJson
            ) `
            -Label 'core forbidden-optional-import check'
    }

    $CoreFreezeRaw = Invoke-ExternalChecked `
        -FilePath $CorePython `
        -Arguments @('-m', 'pip', 'freeze', '--all') `
        -Label 'core pip freeze'
    $CoreFreeze = @(
        ConvertTo-CanonicalPipFreeze `
            -Lines $CoreFreezeRaw `
            -DistributionName $DistributionName `
            -Version $Version
    )

    $EnvironmentReceipts += [pscustomobject]@{
        environment = 'core'
        installed_version = [string]$CoreInspect.version
        import_origin = 'fresh-environment-site-packages'
        import_origin_relative = [string]$CoreInspect.origin_relative
        pip_version = $CorePipVersion
        pip_freeze = $CoreFreeze
        pip_check = 'PASS'
    }

    $ExtraPython = $null
    if (-not [string]::IsNullOrWhiteSpace($OptionalExtra)) {
        if ($OptionalExtra -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._-]*\z') {
            throw 'STOP: optional extra name is invalid.'
        }
        Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
        Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
        Assert-BoundFile $MetadataReceiptFullPath $ExpectedMetadataReceiptSha256 'artifact metadata receipt'
        $null = Invoke-ExternalChecked `
            -FilePath $PythonFullPath `
            -Arguments @('-m', 'venv', $ExtraRoot) `
            -Label 'extra virtual environment creation'
        $ExtraPython = Join-Path (Join-Path $ExtraRoot 'Scripts') 'python.exe'
        if (-not (Test-Path -LiteralPath $ExtraPython -PathType Leaf)) {
            throw 'STOP: extra environment Python is unavailable.'
        }

        $ExtraPipVersionRaw = Invoke-ExternalChecked `
            -FilePath $ExtraPython `
            -Arguments @(
                '-I', '-c',
                "import importlib.metadata as m; print(m.version('pip'))"
            ) `
            -Label 'extra pip version read'
        $ExtraPipVersion = (
            [string]($ExtraPipVersionRaw | Select-Object -First 1)
        ).Trim()
        if ($ExtraPipVersion -cne $ExpectedPipVersion) {
            throw (
                'STOP: extra pip version mismatch. Expected {0}, observed {1}' -f
                $ExpectedPipVersion,
                $ExtraPipVersion
            )
        }

        $ExtraImportsJson = ConvertTo-JsonArray $ExtraImports
        $null = Invoke-ExternalChecked `
            -FilePath $ExtraPython `
            -Arguments @(
                '-I', '-c', $PreinstallScript, $ExtraImportsJson, '[]'
            ) `
            -Label 'extra pre-install isolation check'

        $WheelWithExtra = $WheelItem.FullName + '[' + $OptionalExtra + ']'
        Push-Location -LiteralPath $RuntimeRoot
        try {
            Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
            Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
            Assert-BoundFile $MetadataReceiptFullPath $ExpectedMetadataReceiptSha256 'artifact metadata receipt'
            Assert-BoundFile $WheelFileBinding.path $WheelFileBinding.sha256 'fixed wheel'
            Assert-BoundFile $SdistFileBinding.path $SdistFileBinding.sha256 'fixed sdist'
            $null = Invoke-ExternalChecked `
                -FilePath $ExtraPython `
                -Arguments @(
                    '-m', 'pip', 'install', '--disable-pip-version-check',
                    '--no-input', '--no-cache-dir', $WheelWithExtra
                ) `
                -Label 'extra fixed-wheel install'
            $null = Invoke-ExternalChecked `
                -FilePath $ExtraPython `
                -Arguments @('-m', 'pip', 'check') `
                -Label 'extra pip check'
        }
        finally {
            Pop-Location
        }

        $ExtraInspectRaw = Invoke-ExternalChecked `
            -FilePath $ExtraPython `
            -Arguments @(
                '-I', '-c', $InspectScript,
                $DistributionName, $Version, $ImportName
            ) `
            -Label 'extra installed-package inspection'
        $ExtraInspect = ($ExtraInspectRaw -join [Environment]::NewLine) |
            ConvertFrom-Json
        if ([string]$ExtraInspect.version -cne $Version -or
            -not [bool]$ExtraInspect.origin_is_installed) {
            throw 'STOP: extra installed package identity or origin mismatch.'
        }

        $ExtraImportCheckScript = (
            'import importlib,json,sys; names=json.loads(sys.argv[1]); ' +
            '[importlib.import_module(n) for n in names]'
        )
        $null = Invoke-ExternalChecked `
            -FilePath $ExtraPython `
            -Arguments @(
                '-I', '-c', $ExtraImportCheckScript, $ExtraImportsJson
            ) `
            -Label 'extra import check'

        $ExtraFreezeRaw = Invoke-ExternalChecked `
            -FilePath $ExtraPython `
            -Arguments @('-m', 'pip', 'freeze', '--all') `
            -Label 'extra pip freeze'
        $ExtraFreeze = @(
            ConvertTo-CanonicalPipFreeze `
                -Lines $ExtraFreezeRaw `
                -DistributionName $DistributionName `
                -Version $Version
        )

        $EnvironmentReceipts += [pscustomobject]@{
            environment = 'extra'
            optional_extra = $OptionalExtra
            installed_version = [string]$ExtraInspect.version
            import_origin = 'fresh-environment-site-packages'
            import_origin_relative = [string]$ExtraInspect.origin_relative
            pip_version = $ExtraPipVersion
            pip_freeze = $ExtraFreeze
            pip_check = 'PASS'
        }
    }

    $DeclaredConsoleScripts = @($ConsoleScripts.PSObject.Properties)
    foreach ($SmokeCommand in $SmokeCommands) {
        $EnvironmentName = [string](
            Get-RequiredProperty $SmokeCommand 'environment'
        )
        $EntryPoint = [string](
            Get-RequiredProperty $SmokeCommand 'entry_point'
        )
        $Arguments = @(
            Get-OptionalProperty $SmokeCommand 'arguments' @()
        )
        $ExpectedText = [string](
            Get-OptionalProperty $SmokeCommand 'expected_text' 'usage:'
        )

        $EntryMatches = @(
            $DeclaredConsoleScripts |
                Where-Object { $_.Name -ceq $EntryPoint }
        )
        if ($EntryMatches.Count -ne 1) {
            throw "STOP: smoke command uses undeclared entry point: $EntryPoint"
        }

        if ($EnvironmentName -ceq 'core') {
            $EnvironmentRoot = $CoreRoot
        }
        elseif ($EnvironmentName -ceq 'extra' -and
            $null -ne $ExtraPython) {
            $EnvironmentRoot = $ExtraRoot
        }
        else {
            throw "STOP: smoke command environment is unavailable: $EnvironmentName"
        }

        $EntryPath = Join-Path (
            Join-Path $EnvironmentRoot 'Scripts'
        ) ($EntryPoint + '.exe')
        if (-not (Test-Path -LiteralPath $EntryPath -PathType Leaf)) {
            throw "STOP: console entry-point executable is unavailable: $EntryPoint"
        }

        Push-Location -LiteralPath $RuntimeRoot
        try {
            $CommandOutput = @(& $EntryPath @Arguments)
            $CommandExitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
        if ($CommandExitCode -ne 0) {
            throw "STOP: smoke command failed with exit code $CommandExitCode"
        }
        $CommandText = $CommandOutput -join [Environment]::NewLine
        if (-not [string]::IsNullOrEmpty($ExpectedText) -and
            $CommandText.IndexOf(
                $ExpectedText,
                [StringComparison]::OrdinalIgnoreCase
            ) -lt 0) {
            throw "STOP: smoke command output did not contain: $ExpectedText"
        }
        $SmokeReceipts += [pscustomobject]@{
            environment = $EnvironmentName
            entry_point = $EntryPoint
            arguments = @($Arguments)
            expected_text = $ExpectedText
            result = 'PASS'
        }
    }
}
finally {
    foreach ($EnvironmentName in $EnvironmentNames) {
        [Environment]::SetEnvironmentVariable(
            $EnvironmentName,
            $SavedEnvironment[$EnvironmentName],
            'Process'
        )
    }
}

$Receipt = [pscustomobject]@{
    schema_version = 'ln_church.sdk_release_receipt.v1'
    operation = 'Test-SdkFreshInstall'
    result = 'SDK_FRESH_INSTALL: PASS'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    script_sha256 = $ScriptSha256
    manifest_sha256 = $ManifestSha256
    artifact_receipt_sha256 = $ExpectedArtifactReceiptSha256
    metadata_receipt_sha256 = $ExpectedMetadataReceiptSha256
    version = $Version
    distribution_name = $DistributionName
    wheel = [pscustomobject]@{
        filename = $WheelFilename
        size = $WheelSize
        sha256 = $WheelSha256
    }
    python_version = $PythonVersionText
    environments = $EnvironmentReceipts
    smoke_commands = $SmokeReceipts
    provider_read_count = 0
    provider_mutation_count = 0
    remote_git_mutation_count = 0
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
Assert-BoundFile $MetadataReceiptFullPath $ExpectedMetadataReceiptSha256 'artifact metadata receipt'
Assert-BoundFile $WheelFileBinding.path $WheelFileBinding.sha256 'fixed wheel'
Assert-BoundFile $SdistFileBinding.path $SdistFileBinding.sha256 'fixed sdist'
Write-JsonReceipt $Receipt $ReceiptPath
$Receipt | ConvertTo-Json -Depth 12
}
finally {
    if ($null -ne $SdistFileBinding -and
        $null -ne $SdistFileBinding.stream) {
        $SdistFileBinding.stream.Dispose()
    }
    if ($null -ne $WheelFileBinding -and
        $null -ne $WheelFileBinding.stream) {
        $WheelFileBinding.stream.Dispose()
    }
    if ($null -ne $MetadataReceiptStream) {
        $MetadataReceiptStream.Dispose()
    }
    if ($null -ne $ArtifactReceiptStream) {
        $ArtifactReceiptStream.Dispose()
    }
    if ($null -ne $ManifestStream) {
        $ManifestStream.Dispose()
    }
}
