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
    [string]$ArtifactRoot,

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

foreach ($RequiredPath in @($ManifestPath, $PythonPath, $ArtifactReceiptPath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "STOP: required file is unavailable: $RequiredPath"
    }
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
$ArtifactRootFullPath = (Resolve-Path -LiteralPath $ArtifactRoot).Path
Assert-HexDigest $ExpectedArtifactReceiptSha256 64 'expected artifact receipt SHA-256'
$ExpectedArtifactReceiptSha256 = $ExpectedArtifactReceiptSha256.ToLowerInvariant()
$ArtifactReceiptSha256 = Get-Sha256Hex -LiteralPath $ArtifactReceiptFullPath
if ($ArtifactReceiptSha256 -cne $ExpectedArtifactReceiptSha256) {
    throw 'STOP: artifact receipt bytes do not match the Human-supplied SHA-256.'
}
Assert-HexDigest $ExpectedManifestSha256 64 'expected manifest SHA-256'
$ExpectedManifestSha256 = $ExpectedManifestSha256.ToLowerInvariant()
$ManifestSha256 = Get-Sha256Hex -LiteralPath $ManifestFullPath
if ($ManifestSha256 -cne $ExpectedManifestSha256) {
    throw 'STOP: release manifest bytes do not match the Human-supplied SHA-256.'
}
$ScriptSha256 = Get-Sha256Hex -LiteralPath $PSCommandPath

$ManifestStream = $null
$ArtifactReceiptStream = $null
$ArtifactFileBindings = @()
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

$SchemaVersion = [string](Get-RequiredProperty $Manifest 'schema_version')
if ($SchemaVersion -cne 'ln_church.sdk_release_manifest.v1') {
    throw "STOP: unsupported manifest schema: $SchemaVersion"
}
$ArtifactReceiptSchema = [string](
    Get-RequiredProperty $ArtifactReceipt 'schema_version'
)
$ArtifactReceiptOperation = [string](
    Get-RequiredProperty $ArtifactReceipt 'operation'
)
$ArtifactReceiptResult = [string](
    Get-RequiredProperty $ArtifactReceipt 'result'
)
$ArtifactReceiptManifestSha256 = (
    [string](Get-RequiredProperty $ArtifactReceipt 'manifest_sha256')
).ToLowerInvariant()
$ArtifactReceiptScriptSha256 = (
    [string](Get-RequiredProperty $ArtifactReceipt 'script_sha256')
).ToLowerInvariant()
if ($ArtifactReceiptSchema -cne 'ln_church.sdk_release_receipt.v1' -or
    $ArtifactReceiptOperation -cne 'Build-SdkArtifacts' -or
    $ArtifactReceiptResult -cne 'SDK_ARTIFACT_BUILD: PASS') {
    throw 'STOP: artifact receipt is not an accepted build PASS receipt.'
}
if ($ArtifactReceiptManifestSha256 -cne $ManifestSha256) {
    throw 'STOP: artifact receipt used a different manifest.'
}

$Release = Get-RequiredProperty $Manifest 'release'
$Package = Get-RequiredProperty $Manifest 'package'
$Python = Get-RequiredProperty $Manifest 'python'
$Tooling = Get-RequiredProperty $Manifest 'tooling'
$Version = [string](Get-RequiredProperty $Release 'version')
$Tag = [string](Get-RequiredProperty $Release 'tag')
$DistributionName = [string](
    Get-RequiredProperty $Package 'distribution_name'
)
$ExpectedConsoleScripts = Get-RequiredProperty $Package 'console_scripts'
$ExpectedPythonMajor = [int](Get-RequiredProperty $Python 'major')
$ExpectedPythonMinor = [int](Get-RequiredProperty $Python 'minor')
$ExpectedPythonMicro = [int](Get-RequiredProperty $Python 'micro')
$ExpectedTwineVersion = [string](
    Get-RequiredProperty $Tooling 'twine_version'
)
$OperationSha256 = Get-RequiredProperty $Tooling 'operation_sha256'
$ExpectedScriptSha256 = (
    [string](
        Get-RequiredProperty $OperationSha256 'Test-SdkArtifactMetadata'
    )
).ToLowerInvariant()
$ExpectedBuildScriptSha256 = (
    [string](Get-RequiredProperty $OperationSha256 'Build-SdkArtifacts')
).ToLowerInvariant()
$ExpectedMetadata = Get-RequiredProperty $Package 'metadata'
$ExpectedRequiresPython = [string](
    Get-RequiredProperty $ExpectedMetadata 'requires_python'
)
$ExpectedProvidesExtras = @(
    @(Get-RequiredProperty $ExpectedMetadata 'provides_extras') |
        ForEach-Object { [string]$_ } |
        Sort-Object -CaseSensitive
)
$ExpectedRequiresDist = @(
    @(Get-RequiredProperty $ExpectedMetadata 'requires_dist') |
        ForEach-Object { [string]$_ } |
        Sort-Object -CaseSensitive
)

Assert-HexDigest $ExpectedScriptSha256 64 'Test-SdkArtifactMetadata SHA-256'
Assert-HexDigest $ExpectedBuildScriptSha256 64 'Build-SdkArtifacts SHA-256'
Assert-HexDigest $ArtifactReceiptScriptSha256 64 'artifact receipt script SHA-256'
if ($ScriptSha256 -cne $ExpectedScriptSha256) {
    throw 'STOP: Test-SdkArtifactMetadata script bytes do not match the manifest.'
}
if ($ArtifactReceiptScriptSha256 -cne $ExpectedBuildScriptSha256) {
    throw 'STOP: artifact receipt was produced by noncanonical script bytes.'
}
if ($Tag -cne ('v' + $Version)) {
    throw 'STOP: release tag must be exactly v plus the release version.'
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
$PythonVersionRaw = & $PythonFullPath -I -c (
    'import json,sys; print(json.dumps({' +
    '"major":sys.version_info.major,"minor":sys.version_info.minor,' +
    '"micro":sys.version_info.micro}))'
)
$PythonVersionExitCode = $LASTEXITCODE
if ($PythonVersionExitCode -ne 0) {
    throw "STOP: Python version read failed with exit code $PythonVersionExitCode"
}
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

$TwineVersionRaw = & $PythonFullPath -I -c (
    "import importlib.metadata as m; print(m.version('twine'))"
)
$TwineVersionExitCode = $LASTEXITCODE
if ($TwineVersionExitCode -ne 0) {
    throw "STOP: Twine version read failed with exit code $TwineVersionExitCode"
}
$ObservedTwineVersion = (
    [string]($TwineVersionRaw | Select-Object -First 1)
).Trim()
if ($ObservedTwineVersion -cne $ExpectedTwineVersion) {
    throw (
        'STOP: Twine version mismatch. Expected {0}, observed {1}' -f
        $ExpectedTwineVersion,
        $ObservedTwineVersion
    )
}

$ArtifactItems = @(Get-RequiredProperty $ArtifactReceipt 'artifacts')
if ($ArtifactItems.Count -ne 2) {
    throw 'STOP: artifact receipt must contain exactly two artifacts.'
}
$WheelItems = @($ArtifactItems | Where-Object { $_.kind -ceq 'wheel' })
$SdistItems = @($ArtifactItems | Where-Object { $_.kind -ceq 'sdist' })
if ($WheelItems.Count -ne 1 -or $SdistItems.Count -ne 1) {
    throw 'STOP: artifact receipt must contain one wheel and one sdist.'
}

$VerifiedArtifacts = @()
foreach ($Artifact in $ArtifactItems) {
    $ExpectedFilename = [string](Get-RequiredProperty $Artifact 'filename')
    $ExpectedSize = [long](Get-RequiredProperty $Artifact 'size')
    $ExpectedSha256 = (
        [string](Get-RequiredProperty $Artifact 'sha256')
    ).ToLowerInvariant()
    Assert-HexDigest $ExpectedSha256 64 ('artifact SHA-256 for ' + $ExpectedFilename)

    if ([IO.Path]::GetFileName($ExpectedFilename) -cne $ExpectedFilename -or
        [string]::IsNullOrWhiteSpace($ExpectedFilename)) {
        throw "STOP: artifact receipt filename is invalid: $ExpectedFilename"
    }
    $ArtifactPath = Join-Path $ArtifactRootFullPath $ExpectedFilename
    if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) {
        throw "STOP: fixed artifact is unavailable: $ArtifactPath"
    }
    $ArtifactFileBinding = Open-HashedReadFile `
        -LiteralPath $ArtifactPath `
        -ExpectedSha256 $ExpectedSha256 `
        -Label $ExpectedFilename
    $ArtifactFileBindings += $ArtifactFileBinding
    $ObservedItem = Get-Item -LiteralPath $ArtifactPath
    if ($ObservedItem.Name -cne $ExpectedFilename) {
        throw "STOP: fixed artifact filename mismatch: $ArtifactPath"
    }
    if ([long]$ObservedItem.Length -ne $ExpectedSize -or
        [long]$ArtifactFileBinding.size -ne $ExpectedSize) {
        throw "STOP: fixed artifact identity mismatch: $ExpectedFilename"
    }
    $VerifiedArtifacts += [pscustomobject]@{
        kind = [string]$Artifact.kind
        filename = $ExpectedFilename
        size = [long]$ObservedItem.Length
        sha256 = [string]$ArtifactFileBinding.sha256
    }
}

$WheelFilename = [string](Get-RequiredProperty $WheelItems[0] 'filename')
$SdistFilename = [string](Get-RequiredProperty $SdistItems[0] 'filename')
$WheelPath = Join-Path $ArtifactRootFullPath $WheelFilename
$SdistPath = Join-Path $ArtifactRootFullPath $SdistFilename

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
foreach ($ArtifactFileBinding in $ArtifactFileBindings) {
    Assert-BoundFile `
        $ArtifactFileBinding.path `
        $ArtifactFileBinding.sha256 `
        ('artifact ' + $ArtifactFileBinding.label)
}
& $PythonFullPath -I -m twine check $WheelPath $SdistPath
$TwineCheckExitCode = $LASTEXITCODE
if ($TwineCheckExitCode -ne 0) {
    throw "STOP: Twine check failed with exit code $TwineCheckExitCode"
}

$MetadataScript = @'
import configparser
from email.parser import BytesParser
from email.policy import compat32
import json
from pathlib import PurePosixPath
import sys
import tarfile
import zipfile

wheel_path, sdist_path = sys.argv[1:3]

def message_to_object(message):
    return {
        "name": message.get("Name"),
        "version": message.get("Version"),
        "requires_python": message.get("Requires-Python"),
        "provides_extra": sorted(message.get_all("Provides-Extra", [])),
        "requires_dist": sorted(message.get_all("Requires-Dist", [])),
    }

with zipfile.ZipFile(wheel_path) as archive:
    names = archive.namelist()
    wheel_unsafe = sorted(
        name for name in names
        if (
            not name
            or "\\" in name
            or PurePosixPath(name).is_absolute()
            or ".." in PurePosixPath(name).parts
            or ":" in PurePosixPath(name).parts[0]
        )
    )
    if len(names) != len(set(names)):
        raise SystemExit("wheel contains duplicate archive paths")
    metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
    entry_names = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
    if len(metadata_names) != 1 or len(entry_names) != 1:
        raise SystemExit("wheel metadata or entry-point file count is not one")
    wheel_message = BytesParser(policy=compat32).parsebytes(
        archive.read(metadata_names[0])
    )
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(archive.read(entry_names[0]).decode("utf-8"))
    console_scripts = dict(parser.items("console_scripts")) if parser.has_section("console_scripts") else {}
    wheel_forbidden = sorted(
        name for name in names
        if (
            "/.git/" in "/" + name
            or "__pycache__" in PurePosixPath(name).parts
            or name.endswith((".pyc", ".pyo"))
            or ".pytest_cache" in PurePosixPath(name).parts
        )
    )

with tarfile.open(sdist_path, mode="r:gz") as archive:
    members = archive.getmembers()
    sdist_unsafe = sorted(
        member.name for member in members
        if (
            not member.name
            or "\\" in member.name
            or PurePosixPath(member.name).is_absolute()
            or ".." in PurePosixPath(member.name).parts
            or ":" in PurePosixPath(member.name).parts[0]
            or not (member.isfile() or member.isdir())
        )
    )
    sdist_roots = sorted({
        PurePosixPath(member.name).parts[0]
        for member in members if PurePosixPath(member.name).parts
    })
    metadata_members = [
        member for member in members
        if member.isfile()
        and member.name.endswith("/PKG-INFO")
        and member.name.count("/") == 1
    ]
    if len(metadata_members) != 1:
        raise SystemExit("sdist top-level PKG-INFO count is not one")
    extracted = archive.extractfile(metadata_members[0])
    if extracted is None:
        raise SystemExit("sdist PKG-INFO could not be read")
    sdist_message = BytesParser(policy=compat32).parsebytes(extracted.read())
    sdist_forbidden = sorted(
        member.name for member in members
        if (
            "/.git/" in "/" + member.name
            or "__pycache__" in PurePosixPath(member.name).parts
            or member.name.endswith((".pyc", ".pyo"))
            or ".pytest_cache" in PurePosixPath(member.name).parts
        )
    )

print(json.dumps({
    "wheel": message_to_object(wheel_message),
    "sdist": message_to_object(sdist_message),
    "console_scripts": console_scripts,
    "wheel_unsafe_entries": wheel_unsafe,
    "sdist_unsafe_entries": sdist_unsafe,
    "sdist_top_level_roots": sdist_roots,
    "wheel_forbidden_entries": wheel_forbidden,
    "sdist_forbidden_entries": sdist_forbidden,
}, sort_keys=True))
'@

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
foreach ($ArtifactFileBinding in $ArtifactFileBindings) {
    Assert-BoundFile `
        $ArtifactFileBinding.path `
        $ArtifactFileBinding.sha256 `
        ('artifact ' + $ArtifactFileBinding.label)
}
$MetadataJsonRaw = & $PythonFullPath -I -c $MetadataScript $WheelPath $SdistPath
$MetadataExitCode = $LASTEXITCODE
if ($MetadataExitCode -ne 0) {
    throw "STOP: artifact metadata inspection failed with exit code $MetadataExitCode"
}
$Metadata = ($MetadataJsonRaw -join [Environment]::NewLine) |
    ConvertFrom-Json

foreach ($MetadataObject in @($Metadata.wheel, $Metadata.sdist)) {
    if ([string]$MetadataObject.name -cne $DistributionName) {
        throw 'STOP: artifact distribution name mismatch.'
    }
    if ([string]$MetadataObject.version -cne $Version) {
        throw 'STOP: artifact version mismatch.'
    }
}

foreach ($FieldName in @(
    'name',
    'version',
    'requires_python',
    'provides_extra',
    'requires_dist'
)) {
    $WheelValue = ConvertTo-Json `
        -InputObject $Metadata.wheel.PSObject.Properties[$FieldName].Value `
        -Compress
    $SdistValue = ConvertTo-Json `
        -InputObject $Metadata.sdist.PSObject.Properties[$FieldName].Value `
        -Compress
    if ($WheelValue -cne $SdistValue) {
        throw "STOP: wheel and sdist metadata differ for $FieldName"
    }
}

if ([string]$Metadata.wheel.requires_python -cne $ExpectedRequiresPython) {
    throw 'STOP: artifact Requires-Python does not match the manifest.'
}
$ObservedProvidesExtrasJson = ConvertTo-Json `
    -InputObject @($Metadata.wheel.provides_extra) `
    -Compress
$ExpectedProvidesExtrasJson = ConvertTo-Json `
    -InputObject @($ExpectedProvidesExtras) `
    -Compress
if ($ObservedProvidesExtrasJson -cne $ExpectedProvidesExtrasJson) {
    throw 'STOP: artifact Provides-Extra values do not match the manifest.'
}
$ObservedRequiresDistJson = ConvertTo-Json `
    -InputObject @($Metadata.wheel.requires_dist) `
    -Compress
$ExpectedRequiresDistJson = ConvertTo-Json `
    -InputObject @($ExpectedRequiresDist) `
    -Compress
if ($ObservedRequiresDistJson -cne $ExpectedRequiresDistJson) {
    throw 'STOP: artifact Requires-Dist values do not match the manifest.'
}

$ExpectedEntryProperties = @($ExpectedConsoleScripts.PSObject.Properties)
$ObservedEntryProperties = @($Metadata.console_scripts.PSObject.Properties)
if ($ExpectedEntryProperties.Count -ne $ObservedEntryProperties.Count) {
    throw 'STOP: console entry-point count mismatch.'
}
foreach ($ExpectedEntry in $ExpectedEntryProperties) {
    $Matches = @(
        $ObservedEntryProperties |
            Where-Object { $_.Name -ceq $ExpectedEntry.Name }
    )
    if ($Matches.Count -ne 1 -or
        [string]$Matches[0].Value -cne [string]$ExpectedEntry.Value) {
        throw "STOP: console entry-point mismatch: $($ExpectedEntry.Name)"
    }
}

if (@($Metadata.wheel_forbidden_entries).Count -ne 0 -or
    @($Metadata.sdist_forbidden_entries).Count -ne 0) {
    throw 'STOP: artifact contains a forbidden generated or VCS entry.'
}
if (@($Metadata.wheel_unsafe_entries).Count -ne 0 -or
    @($Metadata.sdist_unsafe_entries).Count -ne 0 -or
    @($Metadata.sdist_top_level_roots).Count -ne 1) {
    throw 'STOP: artifact archive path boundary is invalid.'
}

$Receipt = [pscustomobject]@{
    schema_version = 'ln_church.sdk_release_receipt.v1'
    operation = 'Test-SdkArtifactMetadata'
    result = 'SDK_ARTIFACT_METADATA: PASS'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    script_sha256 = $ScriptSha256
    manifest_sha256 = $ManifestSha256
    artifact_receipt_sha256 = $ExpectedArtifactReceiptSha256
    version = $Version
    distribution_name = $DistributionName
    python_version = $PythonVersionText
    twine_version = $ObservedTwineVersion
    twine_check = 'PASS'
    artifacts = $VerifiedArtifacts
    wheel_sdist_metadata_match = $true
    expected_metadata_match = $true
    console_scripts = $Metadata.console_scripts
    forbidden_entry_count = 0
    archive_path_boundary = 'PASS'
    provider_mutation_count = 0
    remote_git_mutation_count = 0
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
foreach ($ArtifactFileBinding in $ArtifactFileBindings) {
    Assert-BoundFile `
        $ArtifactFileBinding.path `
        $ArtifactFileBinding.sha256 `
        ('artifact ' + $ArtifactFileBinding.label)
}
Write-JsonReceipt $Receipt $ReceiptPath
$Receipt | ConvertTo-Json -Depth 12
}
finally {
    foreach ($ArtifactFileBinding in $ArtifactFileBindings) {
        if ($null -ne $ArtifactFileBinding.stream) {
            $ArtifactFileBinding.stream.Dispose()
        }
    }
    if ($null -ne $ArtifactReceiptStream) {
        $ArtifactReceiptStream.Dispose()
    }
    if ($null -ne $ManifestStream) {
        $ManifestStream.Dispose()
    }
}
