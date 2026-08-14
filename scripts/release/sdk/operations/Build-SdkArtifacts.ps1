[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedManifestSha256,

    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$PythonPath,

    [Parameter(Mandatory = $true)]
    [string]$SourceIdentityReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSourceIdentityReceiptSha256,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [Parameter(Mandatory = $true)]
    [string]$ReceiptPath,

    [string]$GitPath = 'git.exe'
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

foreach ($RequiredPath in @(
    $ManifestPath,
    $PythonPath,
    $SourceIdentityReceiptPath
)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "STOP: required file is unavailable: $RequiredPath"
    }
}
if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) {
    throw "STOP: SourceRoot is unavailable: $SourceRoot"
}
if (Test-Path -LiteralPath $OutputRoot) {
    throw "STOP: build output already exists: $OutputRoot"
}
if (Test-Path -LiteralPath $ReceiptPath) {
    throw "STOP: receipt already exists: $ReceiptPath"
}

$ManifestFullPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$SourceFullPath = (Resolve-Path -LiteralPath $SourceRoot).Path
$PythonFullPath = (Resolve-Path -LiteralPath $PythonPath).Path
$SourceReceiptFullPath = (
    Resolve-Path -LiteralPath $SourceIdentityReceiptPath
).Path
Assert-HexDigest $ExpectedSourceIdentityReceiptSha256 64 'expected source identity receipt SHA-256'
$ExpectedSourceIdentityReceiptSha256 = $ExpectedSourceIdentityReceiptSha256.ToLowerInvariant()
$SourceReceiptSha256 = Get-Sha256Hex -LiteralPath $SourceReceiptFullPath
if ($SourceReceiptSha256 -cne $ExpectedSourceIdentityReceiptSha256) {
    throw 'STOP: source identity receipt bytes do not match the Human-supplied SHA-256.'
}
$OutputFullPath = [IO.Path]::GetFullPath($OutputRoot)
Assert-HexDigest $ExpectedManifestSha256 64 'expected manifest SHA-256'
$ExpectedManifestSha256 = $ExpectedManifestSha256.ToLowerInvariant()
$ManifestSha256 = Get-Sha256Hex -LiteralPath $ManifestFullPath
if ($ManifestSha256 -cne $ExpectedManifestSha256) {
    throw 'STOP: release manifest bytes do not match the Human-supplied SHA-256.'
}
$ScriptSha256 = Get-Sha256Hex -LiteralPath $PSCommandPath

$ManifestStream = $null
$SourceReceiptStream = $null
$ArtifactBindings = @()
try {
$Manifest = Read-BoundJsonFile `
    $ManifestFullPath `
    $ManifestSha256 `
    'release manifest' `
    ([ref]$ManifestStream)
$SourceReceipt = Read-BoundJsonFile `
    $SourceReceiptFullPath `
    $ExpectedSourceIdentityReceiptSha256 `
    'source identity receipt' `
    ([ref]$SourceReceiptStream)

$SchemaVersion = [string](Get-RequiredProperty $Manifest 'schema_version')
if ($SchemaVersion -cne 'ln_church.sdk_release_manifest.v1') {
    throw "STOP: unsupported manifest schema: $SchemaVersion"
}
$ReceiptSchema = [string](
    Get-RequiredProperty $SourceReceipt 'schema_version'
)
$ReceiptOperation = [string](Get-RequiredProperty $SourceReceipt 'operation')
$ReceiptResult = [string](Get-RequiredProperty $SourceReceipt 'result')
$ReceiptManifestSha256 = (
    [string](Get-RequiredProperty $SourceReceipt 'manifest_sha256')
).ToLowerInvariant()
$ReceiptScriptSha256 = (
    [string](Get-RequiredProperty $SourceReceipt 'script_sha256')
).ToLowerInvariant()
if ($ReceiptSchema -cne 'ln_church.sdk_release_receipt.v1' -or
    $ReceiptOperation -cne 'Test-SdkSourceIdentity' -or
    $ReceiptResult -cne 'SDK_SOURCE_IDENTITY: PASS') {
    throw 'STOP: source identity receipt is not an accepted PASS receipt.'
}
if ($ReceiptManifestSha256 -cne $ManifestSha256) {
    throw 'STOP: source identity receipt used a different manifest.'
}

$Release = Get-RequiredProperty $Manifest 'release'
$Source = Get-RequiredProperty $Manifest 'source'
$Python = Get-RequiredProperty $Manifest 'python'
$Tooling = Get-RequiredProperty $Manifest 'tooling'
$Version = [string](Get-RequiredProperty $Release 'version')
$Tag = [string](Get-RequiredProperty $Release 'tag')
$ExpectedCommit = (
    [string](Get-RequiredProperty $Source 'commit')
).ToLowerInvariant()
$ExpectedTree = (
    [string](Get-RequiredProperty $Source 'tree')
).ToLowerInvariant()
$ExpectedBuildVersion = [string](
    Get-RequiredProperty $Tooling 'build_version'
)
$ExpectedSetuptoolsVersion = [string](
    Get-RequiredProperty $Tooling 'setuptools_version'
)
$ExpectedWheelVersion = [string](
    Get-RequiredProperty $Tooling 'wheel_version'
)
$ExpectedGitVersion = [string](Get-RequiredProperty $Tooling 'git_version')
$OperationSha256 = Get-RequiredProperty $Tooling 'operation_sha256'
$ExpectedScriptSha256 = (
    [string](Get-RequiredProperty $OperationSha256 'Build-SdkArtifacts')
).ToLowerInvariant()
$ExpectedSourceScriptSha256 = (
    [string](
        Get-RequiredProperty $OperationSha256 'Test-SdkSourceIdentity'
    )
).ToLowerInvariant()
$ExpectedPythonMajor = [int](Get-RequiredProperty $Python 'major')
$ExpectedPythonMinor = [int](Get-RequiredProperty $Python 'minor')
$ExpectedPythonMicro = [int](Get-RequiredProperty $Python 'micro')
$ArtifactDefinitions = @(Get-RequiredProperty $Manifest 'artifacts')

Assert-HexDigest $ExpectedCommit 40 'source commit'
Assert-HexDigest $ExpectedTree 40 'source tree'
Assert-HexDigest $ExpectedScriptSha256 64 'Build-SdkArtifacts SHA-256'
Assert-HexDigest $ExpectedSourceScriptSha256 64 'Test-SdkSourceIdentity SHA-256'
Assert-HexDigest $ReceiptScriptSha256 64 'source receipt script SHA-256'
if ($ScriptSha256 -cne $ExpectedScriptSha256) {
    throw 'STOP: Build-SdkArtifacts script bytes do not match the manifest.'
}
if ($ReceiptScriptSha256 -cne $ExpectedSourceScriptSha256) {
    throw 'STOP: source identity receipt was produced by noncanonical script bytes.'
}
if ($Tag -cne ('v' + $Version)) {
    throw 'STOP: release tag must be exactly v plus the release version.'
}
if ($ArtifactDefinitions.Count -ne 2) {
    throw 'STOP: manifest must declare exactly one wheel and one sdist.'
}

$ExpectedArtifacts = @()
$Kinds = @()
foreach ($Definition in $ArtifactDefinitions) {
    $Kind = [string](Get-RequiredProperty $Definition 'kind')
    $Filename = [string](Get-RequiredProperty $Definition 'filename')
    if ($Kind -cne 'wheel' -and $Kind -cne 'sdist') {
        throw "STOP: unsupported artifact kind: $Kind"
    }
    if ([IO.Path]::GetFileName($Filename) -cne $Filename -or
        [string]::IsNullOrWhiteSpace($Filename)) {
        throw "STOP: artifact filename must be a plain filename: $Filename"
    }
    if ($Kinds -contains $Kind) {
        throw "STOP: duplicate artifact kind: $Kind"
    }
    $Kinds += $Kind
    $ExpectedArtifacts += [pscustomobject]@{
        kind = $Kind
        filename = $Filename
    }
}
if ($Kinds -notcontains 'wheel' -or $Kinds -notcontains 'sdist') {
    throw 'STOP: manifest must declare one wheel and one sdist.'
}

$ReceiptCommit = (
    [string](Get-RequiredProperty $SourceReceipt 'source_commit')
).ToLowerInvariant()
$ReceiptTree = (
    [string](Get-RequiredProperty $SourceReceipt 'source_tree')
).ToLowerInvariant()
if ($ReceiptCommit -cne $ExpectedCommit -or $ReceiptTree -cne $ExpectedTree) {
    throw 'STOP: source identity receipt does not match the manifest identity.'
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $SourceReceiptFullPath $ExpectedSourceIdentityReceiptSha256 'source identity receipt'
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

$BuildToolVersionsRaw = & $PythonFullPath -I -c (
    'import importlib.metadata as m,json; ' +
    'print(json.dumps({n:m.version(n) for n in ' +
    '["build","setuptools","wheel"]},sort_keys=True))'
)
$BuildToolVersionsExitCode = $LASTEXITCODE
if ($BuildToolVersionsExitCode -ne 0) {
    throw "STOP: build tool version read failed with exit code $BuildToolVersionsExitCode"
}
$BuildToolVersions = ($BuildToolVersionsRaw -join [Environment]::NewLine) |
    ConvertFrom-Json
$ObservedBuildVersion = [string]$BuildToolVersions.build
$ObservedSetuptoolsVersion = [string]$BuildToolVersions.setuptools
$ObservedWheelVersion = [string]$BuildToolVersions.wheel
foreach ($ToolCheck in @(
    [pscustomobject]@{ name = 'build'; expected = $ExpectedBuildVersion; observed = $ObservedBuildVersion },
    [pscustomobject]@{ name = 'setuptools'; expected = $ExpectedSetuptoolsVersion; observed = $ObservedSetuptoolsVersion },
    [pscustomobject]@{ name = 'wheel'; expected = $ExpectedWheelVersion; observed = $ObservedWheelVersion }
)) {
    if ($ToolCheck.observed -cne $ToolCheck.expected) {
        throw (
            'STOP: {0} version mismatch. Expected {1}, observed {2}' -f
            $ToolCheck.name,
            $ToolCheck.expected,
            $ToolCheck.observed
        )
    }
}

$GitVersionRaw = & $GitPath --version
$GitVersionExitCode = $LASTEXITCODE
if ($GitVersionExitCode -ne 0) {
    throw "STOP: Git version read failed with exit code $GitVersionExitCode"
}
$ObservedGitVersion = (
    [string]($GitVersionRaw | Select-Object -First 1)
).Trim()
if ($ObservedGitVersion.StartsWith('git version ', [StringComparison]::Ordinal)) {
    $ObservedGitVersion = $ObservedGitVersion.Substring(12)
}
if ($ObservedGitVersion -cne $ExpectedGitVersion) {
    throw (
        'STOP: Git version mismatch. Expected {0}, observed {1}' -f
        $ExpectedGitVersion,
        $ObservedGitVersion
    )
}

$HeadRaw = & $GitPath -C $SourceFullPath rev-parse --verify 'HEAD^{commit}'
$HeadExitCode = $LASTEXITCODE
if ($HeadExitCode -ne 0) {
    throw "STOP: source commit read failed with exit code $HeadExitCode"
}
$ObservedCommit = ([string]($HeadRaw | Select-Object -First 1)).Trim().ToLowerInvariant()

$TreeRaw = & $GitPath -C $SourceFullPath rev-parse --verify 'HEAD^{tree}'
$TreeExitCode = $LASTEXITCODE
if ($TreeExitCode -ne 0) {
    throw "STOP: source tree read failed with exit code $TreeExitCode"
}
$ObservedTree = ([string]($TreeRaw | Select-Object -First 1)).Trim().ToLowerInvariant()

if ($ObservedCommit -cne $ExpectedCommit -or $ObservedTree -cne $ExpectedTree) {
    throw 'STOP: source identity drifted after source qualification.'
}

$StatusBefore = @(& $GitPath -C $SourceFullPath status --porcelain=v1)
$StatusBeforeExitCode = $LASTEXITCODE
if ($StatusBeforeExitCode -ne 0) {
    throw "STOP: source status read failed with exit code $StatusBeforeExitCode"
}
if ($StatusBefore.Count -ne 0) {
    throw 'STOP: source checkout is not clean.'
}

$TemporaryRoot = Join-Path (
    [IO.Path]::GetTempPath()
) ('ln-church-sdk-build-' + [Guid]::NewGuid().ToString('N'))
$ArchivePath = Join-Path $TemporaryRoot 'source.zip'
$StagingRoot = Join-Path $TemporaryRoot 'source'
$BuildAttemptCount = 0
$BuildExitCode = $null
$BuildEnvironmentNames = @(
    'PYTHONHOME',
    'PYTHONPATH',
    'PYTHONSTARTUP',
    'PYTHONINSPECT',
    'PYTHONOPTIMIZE',
    'PYTHONWARNINGS',
    'PYTHONDONTWRITEBYTECODE',
    'PYTEST_ADDOPTS',
    'PYTEST_PLUGINS',
    'PYTEST_DISABLE_PLUGIN_AUTOLOAD',
    'SOURCE_DATE_EPOCH',
    'SETUPTOOLS_SCM_PRETEND_VERSION',
    'PIP_CONSTRAINT',
    'PIP_BUILD_CONSTRAINT',
    'PIP_REQUIREMENT',
    'UV_CONSTRAINT',
    'UV_BUILD_CONSTRAINT'
)
$DynamicBuildEnvironmentNames = @(
    [Environment]::GetEnvironmentVariables('Process').Keys |
        ForEach-Object { [string]$_ } |
        Where-Object { $_ -match '\ASETUPTOOLS_SCM_PRETEND_VERSION_FOR_' }
)
$BuildEnvironmentNames = @(
    @($BuildEnvironmentNames + $DynamicBuildEnvironmentNames) |
        Select-Object -Unique
)
$SavedBuildEnvironment = @{}
foreach ($EnvironmentName in $BuildEnvironmentNames) {
    $SavedBuildEnvironment[$EnvironmentName] = (
        [Environment]::GetEnvironmentVariable($EnvironmentName, 'Process')
    )
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $SourceReceiptFullPath $ExpectedSourceIdentityReceiptSha256 'source identity receipt'
New-Item -ItemType Directory -Path $TemporaryRoot | Out-Null
New-Item -ItemType Directory -Path $StagingRoot | Out-Null
New-Item -ItemType Directory -Path $OutputFullPath | Out-Null

try {
    foreach ($EnvironmentName in $BuildEnvironmentNames) {
        [Environment]::SetEnvironmentVariable(
            $EnvironmentName,
            $null,
            'Process'
        )
    }
    [Environment]::SetEnvironmentVariable(
        'PYTHONDONTWRITEBYTECODE',
        '1',
        'Process'
    )

    $ArchiveArgument = '--output=' + $ArchivePath
    Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
    Assert-BoundFile $SourceReceiptFullPath $ExpectedSourceIdentityReceiptSha256 'source identity receipt'
    & $GitPath -C $SourceFullPath archive `
        --format=zip `
        $ArchiveArgument `
        $ExpectedCommit
    $ArchiveExitCode = $LASTEXITCODE
    if ($ArchiveExitCode -ne 0) {
        throw "STOP: git archive failed with exit code $ArchiveExitCode"
    }

    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $StagingRoot

    $PostArchiveHeadRaw = & $GitPath -C $SourceFullPath `
        rev-parse --verify 'HEAD^{commit}'
    $PostArchiveHeadExitCode = $LASTEXITCODE
    if ($PostArchiveHeadExitCode -ne 0) {
        throw "STOP: post-archive commit read failed with exit code $PostArchiveHeadExitCode"
    }
    $PostArchiveTreeRaw = & $GitPath -C $SourceFullPath `
        rev-parse --verify 'HEAD^{tree}'
    $PostArchiveTreeExitCode = $LASTEXITCODE
    if ($PostArchiveTreeExitCode -ne 0) {
        throw "STOP: post-archive tree read failed with exit code $PostArchiveTreeExitCode"
    }
    $PostArchiveCommit = (
        [string]($PostArchiveHeadRaw | Select-Object -First 1)
    ).Trim().ToLowerInvariant()
    $PostArchiveTree = (
        [string]($PostArchiveTreeRaw | Select-Object -First 1)
    ).Trim().ToLowerInvariant()
    if ($PostArchiveCommit -cne $ExpectedCommit -or
        $PostArchiveTree -cne $ExpectedTree) {
        throw 'STOP: source identity changed during git archive.'
    }

    $BuildAttemptCount = 1
    Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
    Assert-BoundFile $SourceReceiptFullPath $ExpectedSourceIdentityReceiptSha256 'source identity receipt'
    & $PythonFullPath -I -m build `
        --no-isolation `
        --wheel `
        --sdist `
        --outdir $OutputFullPath `
        $StagingRoot
    $BuildExitCode = $LASTEXITCODE
}
finally {
    foreach ($EnvironmentName in $BuildEnvironmentNames) {
        [Environment]::SetEnvironmentVariable(
            $EnvironmentName,
            $SavedBuildEnvironment[$EnvironmentName],
            'Process'
        )
    }
    $TempPrefix = [IO.Path]::GetFullPath(
        [IO.Path]::GetTempPath()
    ).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    $TempFullPath = [IO.Path]::GetFullPath($TemporaryRoot)
    if ($TempFullPath.StartsWith(
        $TempPrefix,
        [StringComparison]::OrdinalIgnoreCase
    ) -and (Test-Path -LiteralPath $TempFullPath -PathType Container)) {
        [IO.Directory]::Delete($TempFullPath, $true)
    }
}

if ($BuildAttemptCount -ne 1) {
    throw 'STOP: artifact build was not attempted exactly once.'
}
if ($BuildExitCode -ne 0) {
    throw (
        'STOP: artifact build failed with exit code {0}. Do not retry into the same output directory.' -f
        $BuildExitCode
    )
}

$BuiltFiles = @(Get-ChildItem -LiteralPath $OutputFullPath -File)
if ($BuiltFiles.Count -ne $ExpectedArtifacts.Count) {
    throw 'STOP: artifact build produced an unexpected file count.'
}

$ArtifactReceipts = @()
foreach ($ExpectedArtifact in $ExpectedArtifacts) {
    $ArtifactPath = Join-Path $OutputFullPath $ExpectedArtifact.filename
    if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) {
        throw "STOP: expected artifact is unavailable: $($ExpectedArtifact.filename)"
    }
    $ArtifactBinding = Open-HashedReadFile `
        -LiteralPath $ArtifactPath `
        -Label $ExpectedArtifact.filename
    $ArtifactBindings += $ArtifactBinding
    $ArtifactItem = Get-Item -LiteralPath $ArtifactPath
    if ([long]$ArtifactItem.Length -ne [long]$ArtifactBinding.size) {
        throw "STOP: artifact length changed while locking: $($ExpectedArtifact.filename)"
    }
    $ArtifactReceipts += [pscustomobject]@{
        kind = $ExpectedArtifact.kind
        filename = $ExpectedArtifact.filename
        size = [long]$ArtifactBinding.size
        sha256 = [string]$ArtifactBinding.sha256
    }
}

$ExpectedNames = @($ExpectedArtifacts | ForEach-Object { $_.filename })
$UnexpectedFiles = @(
    $BuiltFiles |
        Where-Object { $ExpectedNames -cnotcontains $_.Name }
)
if ($UnexpectedFiles.Count -ne 0) {
    throw 'STOP: artifact build produced unexpected filenames.'
}

$StatusAfter = @(& $GitPath -C $SourceFullPath status --porcelain=v1)
$StatusAfterExitCode = $LASTEXITCODE
if ($StatusAfterExitCode -ne 0) {
    throw "STOP: post-build source status read failed with exit code $StatusAfterExitCode"
}
if ($StatusAfter.Count -ne 0) {
    throw 'STOP: artifact build changed the source checkout.'
}

$FinalHeadRaw = & $GitPath -C $SourceFullPath rev-parse --verify 'HEAD^{commit}'
$FinalHeadExitCode = $LASTEXITCODE
if ($FinalHeadExitCode -ne 0) {
    throw "STOP: final source commit read failed with exit code $FinalHeadExitCode"
}
$FinalTreeRaw = & $GitPath -C $SourceFullPath rev-parse --verify 'HEAD^{tree}'
$FinalTreeExitCode = $LASTEXITCODE
if ($FinalTreeExitCode -ne 0) {
    throw "STOP: final source tree read failed with exit code $FinalTreeExitCode"
}
$FinalCommit = ([string]($FinalHeadRaw | Select-Object -First 1)).Trim().ToLowerInvariant()
$FinalTree = ([string]($FinalTreeRaw | Select-Object -First 1)).Trim().ToLowerInvariant()
if ($FinalCommit -cne $ExpectedCommit -or $FinalTree -cne $ExpectedTree) {
    throw 'STOP: source identity changed during artifact build.'
}

$Receipt = [pscustomobject]@{
    schema_version = 'ln_church.sdk_release_receipt.v1'
    operation = 'Build-SdkArtifacts'
    result = 'SDK_ARTIFACT_BUILD: PASS'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    script_sha256 = $ScriptSha256
    manifest_sha256 = $ManifestSha256
    source_identity_receipt_sha256 = $ExpectedSourceIdentityReceiptSha256
    version = $Version
    tag = $Tag
    source_commit = $ObservedCommit
    source_tree = $ObservedTree
    python_version = $PythonVersionText
    build_version = $ObservedBuildVersion
    setuptools_version = $ObservedSetuptoolsVersion
    wheel_version = $ObservedWheelVersion
    git_version = $ObservedGitVersion
    build_attempt_count = $BuildAttemptCount
    artifacts = $ArtifactReceipts
    provider_mutation_count = 0
    remote_git_mutation_count = 0
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $SourceReceiptFullPath $ExpectedSourceIdentityReceiptSha256 'source identity receipt'
foreach ($ArtifactBinding in $ArtifactBindings) {
    Assert-BoundFile `
        $ArtifactBinding.path `
        $ArtifactBinding.sha256 `
        ('built artifact ' + $ArtifactBinding.label)
}
Write-JsonReceipt $Receipt $ReceiptPath
$Receipt | ConvertTo-Json -Depth 12
}
finally {
    foreach ($ArtifactBinding in $ArtifactBindings) {
        if ($null -ne $ArtifactBinding.stream) {
            $ArtifactBinding.stream.Dispose()
        }
    }
    if ($null -ne $SourceReceiptStream) {
        $SourceReceiptStream.Dispose()
    }
    if ($null -ne $ManifestStream) {
        $ManifestStream.Dispose()
    }
}
