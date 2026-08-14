[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedManifestSha256,

    [Parameter(Mandatory = $true)]
    [string]$ArtifactReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedArtifactReceiptSha256,

    [Parameter(Mandatory = $true)]
    [string]$FreshInstallReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedFreshInstallReceiptSha256,

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

function Get-ReleaseInventoryJson {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Release
    )

    $Assets = @(
        @($Release.assets) |
            Sort-Object -Property name |
            ForEach-Object {
                [ordered]@{
                    id = [long]$_.id
                    name = [string]$_.name
                    size = [long]$_.size
                    state = [string]$_.state
                    content_type = [string]$_.content_type
                    browser_download_url = [string]$_.browser_download_url
                }
            }
    )
    $Snapshot = [ordered]@{
        id = [long]$Release.id
        tag_name = [string]$Release.tag_name
        draft = [bool]$Release.draft
        prerelease = [bool]$Release.prerelease
        assets = $Assets
    }
    return (ConvertTo-Json -InputObject $Snapshot -Depth 8 -Compress)
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
    $ArtifactReceiptPath,
    $FreshInstallReceiptPath
)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "STOP: required file is unavailable: $RequiredPath"
    }
}
if (Test-Path -LiteralPath $ReceiptPath) {
    throw "STOP: receipt already exists: $ReceiptPath"
}

$ManifestFullPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$ArtifactReceiptFullPath = (
    Resolve-Path -LiteralPath $ArtifactReceiptPath
).Path
$FreshReceiptFullPath = (
    Resolve-Path -LiteralPath $FreshInstallReceiptPath
).Path
Assert-HexDigest $ExpectedArtifactReceiptSha256 64 'expected artifact receipt SHA-256'
Assert-HexDigest $ExpectedFreshInstallReceiptSha256 64 'expected fresh-install receipt SHA-256'
$ExpectedArtifactReceiptSha256 = $ExpectedArtifactReceiptSha256.ToLowerInvariant()
$ExpectedFreshInstallReceiptSha256 = $ExpectedFreshInstallReceiptSha256.ToLowerInvariant()
$ArtifactReceiptSha256 = Get-Sha256Hex -LiteralPath $ArtifactReceiptFullPath
$FreshReceiptSha256 = Get-Sha256Hex -LiteralPath $FreshReceiptFullPath
if ($ArtifactReceiptSha256 -cne $ExpectedArtifactReceiptSha256) {
    throw 'STOP: artifact receipt bytes do not match the Human-supplied SHA-256.'
}
if ($FreshReceiptSha256 -cne $ExpectedFreshInstallReceiptSha256) {
    throw 'STOP: fresh-install receipt bytes do not match the Human-supplied SHA-256.'
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
$FreshReceiptStream = $null
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
$FreshReceipt = Read-BoundJsonFile `
    $FreshReceiptFullPath `
    $ExpectedFreshInstallReceiptSha256 `
    'fresh-install receipt' `
    ([ref]$FreshReceiptStream)

$SchemaVersion = [string](Get-RequiredProperty $Manifest 'schema_version')
if ($SchemaVersion -cne 'ln_church.sdk_release_manifest.v1') {
    throw "STOP: unsupported manifest schema: $SchemaVersion"
}

$Tooling = Get-RequiredProperty $Manifest 'tooling'
$OperationSha256 = Get-RequiredProperty $Tooling 'operation_sha256'
$ExpectedScriptSha256 = (
    [string](Get-RequiredProperty $OperationSha256 'Test-GitHubReleaseAssets')
).ToLowerInvariant()
$ExpectedBuildScriptSha256 = (
    [string](Get-RequiredProperty $OperationSha256 'Build-SdkArtifacts')
).ToLowerInvariant()
$ExpectedFreshScriptSha256 = (
    [string](Get-RequiredProperty $OperationSha256 'Test-SdkFreshInstall')
).ToLowerInvariant()
$ArtifactReceiptScriptSha256 = (
    [string](Get-RequiredProperty $ArtifactReceipt 'script_sha256')
).ToLowerInvariant()
$FreshReceiptScriptSha256 = (
    [string](Get-RequiredProperty $FreshReceipt 'script_sha256')
).ToLowerInvariant()
foreach ($DigestCheck in @(
    [pscustomobject]@{ value = $ExpectedScriptSha256; label = 'Test-GitHubReleaseAssets SHA-256' },
    [pscustomobject]@{ value = $ExpectedBuildScriptSha256; label = 'Build-SdkArtifacts SHA-256' },
    [pscustomobject]@{ value = $ExpectedFreshScriptSha256; label = 'Test-SdkFreshInstall SHA-256' },
    [pscustomobject]@{ value = $ArtifactReceiptScriptSha256; label = 'artifact receipt script SHA-256' },
    [pscustomobject]@{ value = $FreshReceiptScriptSha256; label = 'fresh receipt script SHA-256' }
)) {
    Assert-HexDigest $DigestCheck.value 64 $DigestCheck.label
}
if ($ScriptSha256 -cne $ExpectedScriptSha256) {
    throw 'STOP: Test-GitHubReleaseAssets script bytes do not match the manifest.'
}
if ($ArtifactReceiptScriptSha256 -cne $ExpectedBuildScriptSha256) {
    throw 'STOP: artifact receipt was produced by noncanonical script bytes.'
}
if ($FreshReceiptScriptSha256 -cne $ExpectedFreshScriptSha256) {
    throw 'STOP: fresh-install receipt was produced by noncanonical script bytes.'
}

foreach ($ReceiptCheck in @(
    [pscustomobject]@{
        receipt = $ArtifactReceipt
        operation = 'Build-SdkArtifacts'
        result = 'SDK_ARTIFACT_BUILD: PASS'
        label = 'artifact build'
    },
    [pscustomobject]@{
        receipt = $FreshReceipt
        operation = 'Test-SdkFreshInstall'
        result = 'SDK_FRESH_INSTALL: PASS'
        label = 'fresh install'
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

$FreshArtifactReceiptSha256 = (
    [string](
        Get-RequiredProperty $FreshReceipt 'artifact_receipt_sha256'
    )
).ToLowerInvariant()
if ($FreshArtifactReceiptSha256 -cne $ExpectedArtifactReceiptSha256) {
    throw 'STOP: fresh-install receipt qualified different artifact-receipt bytes.'
}

$Release = Get-RequiredProperty $Manifest 'release'
$Source = Get-RequiredProperty $Manifest 'source'
$GitHub = Get-RequiredProperty $Manifest 'github'
$Version = [string](Get-RequiredProperty $Release 'version')
$ExpectedCommit = (
    [string](Get-RequiredProperty $Source 'commit')
).ToLowerInvariant()
$ExpectedTree = (
    [string](Get-RequiredProperty $Source 'tree')
).ToLowerInvariant()
$Repository = [string](Get-RequiredProperty $GitHub 'repository')
$ExpectedTag = [string](Get-RequiredProperty $Release 'tag')
Assert-HexDigest $ExpectedCommit 40 'source commit'
Assert-HexDigest $ExpectedTree 40 'source tree'
if ($ExpectedTag -cne ('v' + $Version)) {
    throw 'STOP: release tag must be exactly v plus the release version.'
}
if ($Repository -cnotmatch '\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z') {
    throw 'STOP: GitHub repository must be OWNER/REPOSITORY.'
}
$EscapedTag = [Uri]::EscapeDataString($ExpectedTag)
$GitHubApiRoot = 'https://api.github.com/repos/' + $Repository
$TagRefApiUri = $GitHubApiRoot + '/git/ref/tags/' + $EscapedTag
$ReleaseApiUri = $GitHubApiRoot + '/releases/tags/' + $EscapedTag
$ParsedTagRefUri = $null
if (-not [Uri]::TryCreate(
    $TagRefApiUri,
    [UriKind]::Absolute,
    [ref]$ParsedTagRefUri
) -or $ParsedTagRefUri.Scheme -cne 'https' -or
    $ParsedTagRefUri.Host -cne 'api.github.com') {
    throw 'STOP: GitHub tag-ref API URI is not an HTTPS api.github.com URI.'
}
$ParsedReleaseUri = $null
if (-not [Uri]::TryCreate(
    $ReleaseApiUri,
    [UriKind]::Absolute,
    [ref]$ParsedReleaseUri
) -or $ParsedReleaseUri.Scheme -cne 'https' -or
    $ParsedReleaseUri.Host -cne 'api.github.com') {
    throw 'STOP: GitHub Release API URI is not an HTTPS api.github.com URI.'
}

$ArtifactItems = @(Get-RequiredProperty $ArtifactReceipt 'artifacts')
if ($ArtifactItems.Count -ne 2) {
    throw 'STOP: artifact receipt must contain exactly two artifacts.'
}
foreach ($Artifact in $ArtifactItems) {
    $Filename = [string](Get-RequiredProperty $Artifact 'filename')
    $Sha256 = (
        [string](Get-RequiredProperty $Artifact 'sha256')
    ).ToLowerInvariant()
    Assert-HexDigest $Sha256 64 ('artifact SHA-256 for ' + $Filename)
    if ([IO.Path]::GetFileName($Filename) -cne $Filename -or
        [string]::IsNullOrWhiteSpace($Filename)) {
        throw "STOP: artifact filename is invalid: $Filename"
    }
}

$PreviousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
$TemporaryRoot = Join-Path (
    [IO.Path]::GetTempPath()
) ('ln-church-sdk-release-read-' + [Guid]::NewGuid().ToString('N'))
$ProviderReadCount = 0
$AssetReceipts = @()

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
Assert-BoundFile $FreshReceiptFullPath $ExpectedFreshInstallReceiptSha256 'fresh-install receipt'
New-Item -ItemType Directory -Path $TemporaryRoot | Out-Null

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Headers = @{
        'Accept' = 'application/vnd.github+json'
        'User-Agent' = 'ln-church-sdk-release-qualification'
        'Cache-Control' = 'no-cache'
    }

    Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
    Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
    Assert-BoundFile $FreshReceiptFullPath $ExpectedFreshInstallReceiptSha256 'fresh-install receipt'
    $TagRefResponse = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Get `
        -Uri $TagRefApiUri `
        -Headers $Headers `
        -TimeoutSec 30 `
        -ErrorAction Stop
    $ProviderReadCount += 1
    if ([int]$TagRefResponse.StatusCode -ne 200) {
        throw (
            'STOP: GitHub tag-ref read returned HTTP {0}' -f
            $TagRefResponse.StatusCode
        )
    }
    $ObservedTagRef = $TagRefResponse.Content | ConvertFrom-Json
    if ([string]$ObservedTagRef.ref -cne ('refs/tags/' + $ExpectedTag)) {
        throw 'STOP: GitHub tag ref name mismatch.'
    }

    $TagObjectType = [string]$ObservedTagRef.object.type
    $TagObjectSha = ([string]$ObservedTagRef.object.sha).ToLowerInvariant()
    $TagObjectUri = [string]$ObservedTagRef.object.url
    Assert-HexDigest $TagObjectSha 40 'GitHub tag object SHA'

    if ($TagObjectType -ceq 'commit') {
        $ObservedTagCommit = $TagObjectSha
        $CommitObjectUri = $TagObjectUri
    }
    elseif ($TagObjectType -ceq 'tag') {
        $ParsedTagObjectUri = $null
        if (-not [Uri]::TryCreate(
            $TagObjectUri,
            [UriKind]::Absolute,
            [ref]$ParsedTagObjectUri
        ) -or $ParsedTagObjectUri.Scheme -cne 'https' -or
            $ParsedTagObjectUri.Host -cne 'api.github.com') {
            throw 'STOP: annotated GitHub tag-object API URI is invalid.'
        }
        $AnnotatedTagResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Get `
            -Uri $TagObjectUri `
            -Headers $Headers `
            -TimeoutSec 30 `
            -ErrorAction Stop
        $ProviderReadCount += 1
        if ([int]$AnnotatedTagResponse.StatusCode -ne 200) {
            throw (
                'STOP: annotated GitHub tag read returned HTTP {0}' -f
                $AnnotatedTagResponse.StatusCode
            )
        }
        $AnnotatedTag = $AnnotatedTagResponse.Content | ConvertFrom-Json
        if ([string]$AnnotatedTag.object.type -cne 'commit') {
            throw 'STOP: annotated GitHub tag does not target a commit.'
        }
        $ObservedTagCommit = (
            [string]$AnnotatedTag.object.sha
        ).ToLowerInvariant()
        $CommitObjectUri = [string]$AnnotatedTag.object.url
    }
    else {
        throw "STOP: unsupported GitHub tag object type: $TagObjectType"
    }

    Assert-HexDigest $ObservedTagCommit 40 'GitHub tag target commit'
    if ($ObservedTagCommit -cne $ExpectedCommit) {
        throw 'STOP: GitHub tag target commit mismatch.'
    }

    $ParsedCommitObjectUri = $null
    if (-not [Uri]::TryCreate(
        $CommitObjectUri,
        [UriKind]::Absolute,
        [ref]$ParsedCommitObjectUri
    ) -or $ParsedCommitObjectUri.Scheme -cne 'https' -or
        $ParsedCommitObjectUri.Host -cne 'api.github.com') {
        throw 'STOP: GitHub commit-object API URI is invalid.'
    }

    $CommitObjectResponse = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Get `
        -Uri $CommitObjectUri `
        -Headers $Headers `
        -TimeoutSec 30 `
        -ErrorAction Stop
    $ProviderReadCount += 1
    if ([int]$CommitObjectResponse.StatusCode -ne 200) {
        throw (
            'STOP: GitHub tag commit read returned HTTP {0}' -f
            $CommitObjectResponse.StatusCode
        )
    }
    $ObservedCommitObject = $CommitObjectResponse.Content | ConvertFrom-Json
    $ObservedCommitObjectSha = (
        [string]$ObservedCommitObject.sha
    ).ToLowerInvariant()
    Assert-HexDigest $ObservedCommitObjectSha 40 'GitHub commit object SHA'
    if ($ObservedCommitObjectSha -cne $ExpectedCommit) {
        throw 'STOP: GitHub commit-object identity mismatch.'
    }
    $ObservedTagTree = (
        [string]$ObservedCommitObject.tree.sha
    ).ToLowerInvariant()
    Assert-HexDigest $ObservedTagTree 40 'GitHub tag target tree'
    if ($ObservedTagTree -cne $ExpectedTree) {
        throw 'STOP: GitHub tag target tree mismatch.'
    }

    $QuerySeparator = '?'
    if ($ReleaseApiUri.Contains('?')) {
        $QuerySeparator = '&'
    }
    $ReleaseUri = $ReleaseApiUri + $QuerySeparator +
        'nonce=' + [Guid]::NewGuid().ToString('N')

    $ReleaseResponse = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Get `
        -Uri $ReleaseUri `
        -Headers $Headers `
        -TimeoutSec 30 `
        -ErrorAction Stop
    $ProviderReadCount += 1
    if ([int]$ReleaseResponse.StatusCode -ne 200) {
        throw (
            'STOP: GitHub Release read returned HTTP {0}' -f
            $ReleaseResponse.StatusCode
        )
    }
    $ObservedRelease = $ReleaseResponse.Content | ConvertFrom-Json
    if ([string]$ObservedRelease.tag_name -cne $ExpectedTag) {
        throw 'STOP: GitHub Release tag mismatch.'
    }
    if ([bool]$ObservedRelease.draft -or [bool]$ObservedRelease.prerelease) {
        throw 'STOP: GitHub Release is draft or prerelease.'
    }

    $ObservedAssets = @($ObservedRelease.assets)
    if ($ObservedAssets.Count -ne $ArtifactItems.Count) {
        throw 'STOP: GitHub Release asset count mismatch.'
    }
    $InitialReleaseInventoryJson = Get-ReleaseInventoryJson $ObservedRelease

    foreach ($Artifact in $ArtifactItems) {
        $ExpectedFilename = [string]$Artifact.filename
        $ExpectedSize = [long]$Artifact.size
        $ExpectedSha256 = ([string]$Artifact.sha256).ToLowerInvariant()
        $Matches = @(
            $ObservedAssets |
                Where-Object { $_.name -ceq $ExpectedFilename }
        )
        if ($Matches.Count -ne 1) {
            throw "STOP: GitHub Release asset identity mismatch: $ExpectedFilename"
        }
        $RemoteAsset = $Matches[0]
        if ([string]$RemoteAsset.state -cne 'uploaded') {
            throw "STOP: GitHub Release asset is not uploaded: $ExpectedFilename"
        }
        if ([long]$RemoteAsset.size -ne $ExpectedSize) {
            throw "STOP: GitHub Release asset size mismatch: $ExpectedFilename"
        }

        $DownloadUriText = [string]$RemoteAsset.browser_download_url
        $ParsedDownloadUri = $null
        if (-not [Uri]::TryCreate(
            $DownloadUriText,
            [UriKind]::Absolute,
            [ref]$ParsedDownloadUri
        ) -or $ParsedDownloadUri.Scheme -cne 'https' -or
            $ParsedDownloadUri.Host -cne 'github.com') {
            throw "STOP: invalid GitHub asset download URI: $ExpectedFilename"
        }

        $DownloadPath = Join-Path $TemporaryRoot $ExpectedFilename
        Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
        Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
        Assert-BoundFile $FreshReceiptFullPath $ExpectedFreshInstallReceiptSha256 'fresh-install receipt'
        Invoke-WebRequest `
            -UseBasicParsing `
            -Method Get `
            -Uri $DownloadUriText `
            -Headers @{ 'User-Agent' = $Headers['User-Agent'] } `
            -OutFile $DownloadPath `
            -TimeoutSec 120 `
            -ErrorAction Stop
        $ProviderReadCount += 1

        $DownloadedItem = Get-Item -LiteralPath $DownloadPath
        $DownloadedSha256 = (
            Get-FileHash -LiteralPath $DownloadPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ([long]$DownloadedItem.Length -ne $ExpectedSize -or
            $DownloadedSha256 -cne $ExpectedSha256) {
            throw "STOP: downloaded GitHub Release asset mismatch: $ExpectedFilename"
        }

        $AssetReceipts += [pscustomobject]@{
            filename = $ExpectedFilename
            size = [long]$DownloadedItem.Length
            sha256 = $DownloadedSha256
            browser_download_url = $DownloadUriText
        }
    }

    $FinalTagRefResponse = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Get `
        -Uri $TagRefApiUri `
        -Headers $Headers `
        -TimeoutSec 30 `
        -ErrorAction Stop
    $ProviderReadCount += 1
    if ([int]$FinalTagRefResponse.StatusCode -ne 200) {
        throw (
            'STOP: final GitHub tag-ref read returned HTTP {0}' -f
            $FinalTagRefResponse.StatusCode
        )
    }
    $FinalTagRef = $FinalTagRefResponse.Content | ConvertFrom-Json
    if ([string]$FinalTagRef.ref -cne ('refs/tags/' + $ExpectedTag) -or
        [string]$FinalTagRef.object.type -cne $TagObjectType -or
        ([string]$FinalTagRef.object.sha).ToLowerInvariant() -cne $TagObjectSha) {
        throw 'STOP: GitHub tag ref changed during asset read-back.'
    }

    $FinalCommitObjectResponse = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Get `
        -Uri $CommitObjectUri `
        -Headers $Headers `
        -TimeoutSec 30 `
        -ErrorAction Stop
    $ProviderReadCount += 1
    if ([int]$FinalCommitObjectResponse.StatusCode -ne 200) {
        throw (
            'STOP: final GitHub commit read returned HTTP {0}' -f
            $FinalCommitObjectResponse.StatusCode
        )
    }
    $FinalCommitObject = $FinalCommitObjectResponse.Content | ConvertFrom-Json
    $FinalCommitSha = ([string]$FinalCommitObject.sha).ToLowerInvariant()
    $FinalTreeSha = ([string]$FinalCommitObject.tree.sha).ToLowerInvariant()
    if ($FinalCommitSha -cne $ExpectedCommit -or
        $FinalTreeSha -cne $ExpectedTree) {
        throw 'STOP: GitHub commit or tree changed during asset read-back.'
    }

    $FinalReleaseUri = $ReleaseApiUri + '?nonce=' +
        [Guid]::NewGuid().ToString('N')
    $FinalReleaseResponse = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Get `
        -Uri $FinalReleaseUri `
        -Headers $Headers `
        -TimeoutSec 30 `
        -ErrorAction Stop
    $ProviderReadCount += 1
    if ([int]$FinalReleaseResponse.StatusCode -ne 200) {
        throw (
            'STOP: final GitHub Release read returned HTTP {0}' -f
            $FinalReleaseResponse.StatusCode
        )
    }
    $FinalRelease = $FinalReleaseResponse.Content | ConvertFrom-Json
    $FinalReleaseInventoryJson = Get-ReleaseInventoryJson $FinalRelease
    if ($FinalReleaseInventoryJson -cne $InitialReleaseInventoryJson) {
        throw 'STOP: GitHub Release or asset inventory changed during read-back.'
    }
    $ObservedRelease = $FinalRelease
}
finally {
    [Net.ServicePointManager]::SecurityProtocol = $PreviousSecurityProtocol
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

$Receipt = [pscustomobject]@{
    schema_version = 'ln_church.sdk_release_receipt.v1'
    operation = 'Test-GitHubReleaseAssets'
    result = 'SDK_GITHUB_RELEASE_ASSETS: PASS'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    script_sha256 = $ScriptSha256
    manifest_sha256 = $ManifestSha256
    artifact_receipt_sha256 = $ExpectedArtifactReceiptSha256
    fresh_install_receipt_sha256 = $ExpectedFreshInstallReceiptSha256
    version = $Version
    repository = $Repository
    tag = $ExpectedTag
    tag_ref_api_uri = $TagRefApiUri
    tag_target_commit = $ObservedTagCommit
    tag_target_tree = $ObservedTagTree
    release_api_uri = $ReleaseApiUri
    release_id = $ObservedRelease.id
    release_url = [string]$ObservedRelease.html_url
    draft = [bool]$ObservedRelease.draft
    prerelease = [bool]$ObservedRelease.prerelease
    assets = $AssetReceipts
    provider_read_count = $ProviderReadCount
    provider_mutation_count = 0
    remote_git_mutation_count = 0
}

Assert-BoundFile $ManifestFullPath $ManifestSha256 'release manifest'
Assert-BoundFile $ArtifactReceiptFullPath $ExpectedArtifactReceiptSha256 'artifact build receipt'
Assert-BoundFile $FreshReceiptFullPath $ExpectedFreshInstallReceiptSha256 'fresh-install receipt'
Write-JsonReceipt $Receipt $ReceiptPath
$Receipt | ConvertTo-Json -Depth 12
}
finally {
    if ($null -ne $FreshReceiptStream) {
        $FreshReceiptStream.Dispose()
    }
    if ($null -ne $ArtifactReceiptStream) {
        $ArtifactReceiptStream.Dispose()
    }
    if ($null -ne $ManifestStream) {
        $ManifestStream.Dispose()
    }
}
