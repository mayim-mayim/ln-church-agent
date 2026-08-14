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
        throw "STOP: manifest property is missing or duplicated: $Name"
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
        throw "STOP: manifest property is duplicated: $Name"
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
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-BytesSha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

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
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $ObservedSha256 = Get-Sha256Hex -LiteralPath $LiteralPath
    if ($ObservedSha256 -cne $ExpectedSha256) {
        throw "STOP: bound input changed during operation: $Label"
    }
}

function Read-BoundJsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [ref]$OpenStream
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

function Get-ContainedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ([IO.Path]::IsPathRooted($RelativePath)) {
        throw "STOP: $Label must be relative."
    }

    $RootFull = [IO.Path]::GetFullPath($Root)
    $RootPrefix = $RootFull.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    $Candidate = [IO.Path]::GetFullPath((Join-Path $RootFull $RelativePath))

    if (-not $Candidate.StartsWith(
        $RootPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "STOP: $Label escapes SourceRoot."
    }
    return $Candidate
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

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "STOP: manifest is unavailable: $ManifestPath"
}
if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) {
    throw "STOP: SourceRoot is unavailable: $SourceRoot"
}
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "STOP: Python is unavailable: $PythonPath"
}
if (Test-Path -LiteralPath $ReceiptPath) {
    throw "STOP: receipt already exists: $ReceiptPath"
}

$ManifestFullPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$SourceFullPath = (Resolve-Path -LiteralPath $SourceRoot).Path
$PythonFullPath = (Resolve-Path -LiteralPath $PythonPath).Path
Assert-HexDigest $ExpectedManifestSha256 64 'expected manifest SHA-256'
$ExpectedManifestSha256 = $ExpectedManifestSha256.ToLowerInvariant()
$ManifestSha256 = Get-Sha256Hex -LiteralPath $ManifestFullPath
if ($ManifestSha256 -cne $ExpectedManifestSha256) {
    throw 'STOP: release manifest bytes do not match the Human-supplied SHA-256.'
}
$ScriptSha256 = Get-Sha256Hex -LiteralPath $PSCommandPath

$ManifestStream = $null
try {
$Manifest = Read-BoundJsonFile `
    -LiteralPath $ManifestFullPath `
    -ExpectedSha256 $ManifestSha256 `
    -Label 'release manifest' `
    -OpenStream ([ref]$ManifestStream)
$SchemaVersion = [string](Get-RequiredProperty $Manifest 'schema_version')
if ($SchemaVersion -cne 'ln_church.sdk_release_manifest.v1') {
    throw "STOP: unsupported manifest schema: $SchemaVersion"
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
$ExpectedPythonMajor = [int](Get-RequiredProperty $Python 'major')
$ExpectedPythonMinor = [int](Get-RequiredProperty $Python 'minor')
$ExpectedPythonMicro = [int](Get-RequiredProperty $Python 'micro')
$ExpectedPytestVersion = [string](
    Get-RequiredProperty $Tooling 'pytest_version'
)
$ExpectedGitVersion = [string](Get-RequiredProperty $Tooling 'git_version')
$OperationSha256 = Get-RequiredProperty $Tooling 'operation_sha256'
$ExpectedScriptSha256 = (
    [string](
        Get-RequiredProperty $OperationSha256 'Test-SdkSourceIdentity'
    )
).ToLowerInvariant()
$IdentityTestRelative = [string](
    Get-RequiredProperty $Source 'release_identity_test'
)
$IdentityTestName = [string](
    Get-RequiredProperty $Source 'release_identity_test_name'
)
$VerifyLocalTag = [bool](
    Get-OptionalProperty $Source 'verify_local_tag' $false
)

Assert-HexDigest $ExpectedCommit 40 'source commit'
Assert-HexDigest $ExpectedTree 40 'source tree'
Assert-HexDigest $ExpectedScriptSha256 64 'Test-SdkSourceIdentity SHA-256'
if ($ScriptSha256 -cne $ExpectedScriptSha256) {
    throw 'STOP: Test-SdkSourceIdentity script bytes do not match the manifest.'
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    throw 'STOP: release version is empty.'
}
if ($Tag -cne ('v' + $Version)) {
    throw 'STOP: release tag must be exactly v plus the release version.'
}
if ($IdentityTestName -cnotmatch '\Atest_[A-Za-z0-9_]+\z') {
    throw 'STOP: release identity test name is invalid.'
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
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
    throw (
        'STOP: Python version mismatch. Expected {0}.{1}.{2}, observed {3}.{4}.{5}' -f
        $ExpectedPythonMajor,
        $ExpectedPythonMinor,
        $ExpectedPythonMicro,
        $PythonVersion.major,
        $PythonVersion.minor,
        $PythonVersion.micro
    )
}
$PythonVersionText = [string]::Format(
    '{0}.{1}.{2}',
    $PythonVersion.major,
    $PythonVersion.minor,
    $PythonVersion.micro
)

$PytestVersionRaw = & $PythonFullPath -I -c (
    "import importlib.metadata as m; print(m.version('pytest'))"
)
$PytestVersionExitCode = $LASTEXITCODE
if ($PytestVersionExitCode -ne 0) {
    throw "STOP: pytest version read failed with exit code $PytestVersionExitCode"
}
$ObservedPytestVersion = (
    [string]($PytestVersionRaw | Select-Object -First 1)
).Trim()
if ($ObservedPytestVersion -cne $ExpectedPytestVersion) {
    throw (
        'STOP: pytest version mismatch. Expected {0}, observed {1}' -f
        $ExpectedPytestVersion,
        $ObservedPytestVersion
    )
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

if ($ObservedCommit -cne $ExpectedCommit) {
    throw "STOP: source commit mismatch: $ObservedCommit"
}
if ($ObservedTree -cne $ExpectedTree) {
    throw "STOP: source tree mismatch: $ObservedTree"
}

$StatusBefore = @(& $GitPath -C $SourceFullPath status --porcelain=v1)
$StatusBeforeExitCode = $LASTEXITCODE
if ($StatusBeforeExitCode -ne 0) {
    throw "STOP: source status read failed with exit code $StatusBeforeExitCode"
}
if ($StatusBefore.Count -ne 0) {
    throw 'STOP: source checkout is not clean.'
}

$ObservedTagCommit = $null
if ($VerifyLocalTag) {
    $TagReference = 'refs/tags/' + $Tag + '^{commit}'
    $TagRaw = & $GitPath -C $SourceFullPath rev-parse --verify $TagReference
    $TagExitCode = $LASTEXITCODE
    if ($TagExitCode -ne 0) {
        throw "STOP: local tag identity read failed with exit code $TagExitCode"
    }
    $ObservedTagCommit = (
        [string]($TagRaw | Select-Object -First 1)
    ).Trim().ToLowerInvariant()
    if ($ObservedTagCommit -cne $ExpectedCommit) {
        throw "STOP: local tag target mismatch: $ObservedTagCommit"
    }
}

$RequiredFileReceipts = @()
$RequiredFiles = @(Get-RequiredProperty $Source 'required_files')
foreach ($RequiredFile in $RequiredFiles) {
    $RelativePath = [string](Get-RequiredProperty $RequiredFile 'path')
    $ExpectedSha256 = (
        [string](Get-RequiredProperty $RequiredFile 'sha256')
    ).ToLowerInvariant()
    Assert-HexDigest $ExpectedSha256 64 ('required-file SHA-256 for ' + $RelativePath)

    $RequiredPath = Get-ContainedPath $SourceFullPath $RelativePath 'required file'
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "STOP: required source file is unavailable: $RelativePath"
    }
    $null = & $GitPath -C $SourceFullPath `
        ls-files --error-unmatch -- $RelativePath
    $TrackedFileExitCode = $LASTEXITCODE
    if ($TrackedFileExitCode -ne 0) {
        throw "STOP: required source file is not tracked: $RelativePath"
    }
    $ObservedSha256 = (
        Get-FileHash -LiteralPath $RequiredPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($ObservedSha256 -cne $ExpectedSha256) {
        throw "STOP: required source file hash mismatch: $RelativePath"
    }

    $RequiredFileReceipts += [pscustomobject]@{
        path = $RelativePath
        sha256 = $ObservedSha256
    }
}

$IdentityTestPath = Get-ContainedPath `
    -Root $SourceFullPath `
    -RelativePath $IdentityTestRelative `
    -Label 'release identity test'
if (-not (Test-Path -LiteralPath $IdentityTestPath -PathType Leaf)) {
    throw "STOP: release identity test is unavailable: $IdentityTestRelative"
}
$null = & $GitPath -C $SourceFullPath `
    ls-files --error-unmatch -- $IdentityTestRelative
$TrackedIdentityTestExitCode = $LASTEXITCODE
if ($TrackedIdentityTestExitCode -ne 0) {
    throw 'STOP: release identity test is not tracked by the source commit.'
}
$IdentityTestNode = $IdentityTestPath + '::' + $IdentityTestName

$TestEnvironmentNames = @(
    'PYTHONHOME',
    'PYTHONPATH',
    'PYTHONSTARTUP',
    'PYTHONINSPECT',
    'PYTHONOPTIMIZE',
    'PYTHONWARNINGS',
    'PYTHONDONTWRITEBYTECODE',
    'PYTEST_ADDOPTS',
    'PYTEST_PLUGINS',
    'PYTEST_DISABLE_PLUGIN_AUTOLOAD'
)
$SavedTestEnvironment = @{}
foreach ($EnvironmentName in $TestEnvironmentNames) {
    $SavedTestEnvironment[$EnvironmentName] = (
        [Environment]::GetEnvironmentVariable($EnvironmentName, 'Process')
    )
}
$JunitPath = Join-Path (
    [IO.Path]::GetTempPath()
) ('ln-church-sdk-identity-' + [Guid]::NewGuid().ToString('N') + '.xml')
$IdentityTestExitCode = $null
$IdentityTestCaseCount = 0
$IdentityTestSkippedCount = 0
$IdentityTestFailureCount = 0
$IdentityTestErrorCount = 0

try {
    try {
        foreach ($EnvironmentName in $TestEnvironmentNames) {
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
        [Environment]::SetEnvironmentVariable(
            'PYTEST_DISABLE_PLUGIN_AUTOLOAD',
            '1',
            'Process'
        )

        Push-Location -LiteralPath $SourceFullPath
        try {
            $JunitArgument = '--junitxml=' + $JunitPath
            Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
            & $PythonFullPath -I -m pytest `
                -q `
                -p no:cacheprovider `
                -o 'addopts=' `
                $JunitArgument `
                $IdentityTestNode
            $IdentityTestExitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
    }
    finally {
        foreach ($EnvironmentName in $TestEnvironmentNames) {
            [Environment]::SetEnvironmentVariable(
                $EnvironmentName,
                $SavedTestEnvironment[$EnvironmentName],
                'Process'
            )
        }
    }

    if ($IdentityTestExitCode -ne 0) {
        throw "STOP: release identity test failed with exit code $IdentityTestExitCode"
    }
    if (-not (Test-Path -LiteralPath $JunitPath -PathType Leaf)) {
        throw 'STOP: release identity test did not produce JUnit evidence.'
    }

    [xml]$Junit = Get-Content -LiteralPath $JunitPath -Raw
    $IdentityTestCaseCount = @($Junit.SelectNodes('//testcase')).Count
    $IdentityTestSkippedCount = @($Junit.SelectNodes('//testcase/skipped')).Count
    $IdentityTestFailureCount = @($Junit.SelectNodes('//testcase/failure')).Count
    $IdentityTestErrorCount = @($Junit.SelectNodes('//testcase/error')).Count
    if ($IdentityTestCaseCount -ne 1 -or
        $IdentityTestSkippedCount -ne 0 -or
        $IdentityTestFailureCount -ne 0 -or
        $IdentityTestErrorCount -ne 0) {
        throw 'STOP: release identity pytest did not produce exactly one passing test.'
    }
}
finally {
    if (Test-Path -LiteralPath $JunitPath -PathType Leaf) {
        Remove-Item -LiteralPath $JunitPath -Force
    }
}

$StatusAfter = @(& $GitPath -C $SourceFullPath status --porcelain=v1)
$StatusAfterExitCode = $LASTEXITCODE
if ($StatusAfterExitCode -ne 0) {
    throw "STOP: post-test source status read failed with exit code $StatusAfterExitCode"
}
if ($StatusAfter.Count -ne 0) {
    throw 'STOP: release identity test changed the source checkout.'
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
    throw 'STOP: source identity changed during qualification.'
}

$Receipt = [pscustomobject]@{
    schema_version = 'ln_church.sdk_release_receipt.v1'
    operation = 'Test-SdkSourceIdentity'
    result = 'SDK_SOURCE_IDENTITY: PASS'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    script_sha256 = $ScriptSha256
    manifest_sha256 = $ManifestSha256
    version = $Version
    tag = $Tag
    source_commit = $ObservedCommit
    source_tree = $ObservedTree
    local_tag_verified = $VerifyLocalTag
    local_tag_commit = $ObservedTagCommit
    required_files = $RequiredFileReceipts
    release_identity_test = $IdentityTestRelative
    release_identity_test_name = $IdentityTestName
    release_identity_test_result = 'PASS'
    release_identity_test_case_count = $IdentityTestCaseCount
    release_identity_test_skipped_count = $IdentityTestSkippedCount
    release_identity_test_failure_count = $IdentityTestFailureCount
    release_identity_test_error_count = $IdentityTestErrorCount
    python_version = $PythonVersionText
    pytest_version = $ObservedPytestVersion
    git_version = $ObservedGitVersion
    provider_mutation_count = 0
    remote_git_mutation_count = 0
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Write-JsonReceipt $Receipt $ReceiptPath
$Receipt | ConvertTo-Json -Depth 12
}
finally {
    if ($null -ne $ManifestStream) {
        $ManifestStream.Dispose()
    }
}
