<#
Qualifies the exact reusable SDK release-operation bytes on Windows
PowerShell 5.1. It parses the five canonical operations plus this runner and
proves that every operation stops on a missing manifest before creating any
local output.

This is deliberately local-only. It does not call GitHub, a package registry,
or any runtime provider, and it does not execute a normal release path.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleaseRoot,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw "STOP: $Message"
    }
}

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-RelativeEntrySet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        return @()
    }

    $Root = [IO.Path]::GetFullPath($LiteralPath).TrimEnd('\', '/')
    return @(
        Get-ChildItem -LiteralPath $Root -Recurse -Force |
            ForEach-Object {
                $RelativePath = $_.FullName.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/')
                if ($_.PSIsContainer) {
                    return ($RelativePath + '/')
                }
                return $RelativePath
            } |
            Sort-Object
    )
}

function Write-NewJsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $Json = $Value | ConvertTo-Json -Depth 12
    $Stream = $null
    $Writer = $null
    try {
        $Stream = [IO.File]::Open(
            $LiteralPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $Writer = New-Object IO.StreamWriter -ArgumentList @($Stream, $Utf8NoBom)
        $Stream = $null
        $Writer.Write($Json)
        $Writer.Write("`n")
        $Writer.Flush()
    }
    finally {
        if ($null -ne $Writer) {
            $Writer.Dispose()
        }
        if ($null -ne $Stream) {
            $Stream.Dispose()
        }
    }
}

Assert-Condition `
    ($PSVersionTable.PSEdition -ceq 'Desktop' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -eq 1) `
    "Windows PowerShell 5.1 Desktop is required; observed $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)."
Assert-Condition (Test-Path -LiteralPath $ReleaseRoot -PathType Container) 'ReleaseRoot is unavailable.'
Assert-Condition (Test-Path -LiteralPath $EvidenceRoot -PathType Container) 'EvidenceRoot is unavailable.'

$ReleaseRootFull = [IO.Path]::GetFullPath($ReleaseRoot).TrimEnd('\', '/')
$ExpectedCodePaths = @(
    'operations/Build-SdkArtifacts.ps1',
    'operations/Test-GitHubReleaseAssets.ps1',
    'operations/Test-SdkArtifactMetadata.ps1',
    'operations/Test-SdkFreshInstall.ps1',
    'operations/Test-SdkSourceIdentity.ps1',
    'qualification/Test-SdkReleaseOperationsPS51.ps1'
)
$ObservedCodePaths = @(
    Get-ChildItem -LiteralPath $ReleaseRootFull -Recurse -File -Force |
        Where-Object { $_.Extension.ToLowerInvariant() -ceq '.ps1' } |
        ForEach-Object {
            $_.FullName.Substring($ReleaseRootFull.Length).TrimStart('\', '/').Replace('\', '/')
        } |
        Sort-Object
)
$CodeSetDifference = @(Compare-Object -ReferenceObject $ExpectedCodePaths -DifferenceObject $ObservedCodePaths)
Assert-Condition ($CodeSetDifference.Count -eq 0) 'Canonical SDK release-operation file set differs from the qualification inventory.'

$FileResults = @()
foreach ($RelativePath in $ExpectedCodePaths) {
    $LiteralPath = Join-Path $ReleaseRootFull ($RelativePath.Replace('/', '\'))
    Assert-Condition (Test-Path -LiteralPath $LiteralPath -PathType Leaf) "Qualified file is unavailable: $RelativePath"

    $Tokens = $null
    $ParseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $LiteralPath,
        [ref]$Tokens,
        [ref]$ParseErrors
    )
    $ParseErrorArray = @($ParseErrors)
    $Result = [ordered]@{
        path = $RelativePath
        sha256 = Get-Sha256Hex -LiteralPath $LiteralPath
        syntax_check = 'WINDOWS_POWERSHELL_5_1_PARSE'
        syntax_error_count = $ParseErrorArray.Count
    }
    if ($ParseErrorArray.Count -gt 0) {
        $Result.syntax_errors = @(
            $ParseErrorArray |
                ForEach-Object {
                    [ordered]@{
                        line = [int]$_.Extent.StartLineNumber
                        column = [int]$_.Extent.StartColumnNumber
                        message = [string]$_.Message
                    }
                }
        )
    }
    $FileResults += [pscustomobject]$Result
}

$ParseErrorCount = @(
    $FileResults |
        Where-Object { $_.syntax_error_count -ne 0 }
).Count
Assert-Condition ($ParseErrorCount -eq 0) 'One or more canonical SDK release-operation files have parser errors.'

$RunRoot = Join-Path $EvidenceRoot (
    'sdk-release-operations-ps51-' +
    [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
    [Guid]::NewGuid().ToString('N')
)
[IO.Directory]::CreateDirectory($RunRoot) | Out-Null
$CaseRoot = Join-Path $RunRoot 'safe-stop-cases'
[IO.Directory]::CreateDirectory($CaseRoot) | Out-Null
$ReceiptPath = Join-Path $RunRoot 'qualification-receipt.json'

$SafeStopCases = @(
    [pscustomobject]@{
        path = 'operations/Test-SdkSourceIdentity.ps1'
        arguments = @(
            '-SourceRoot', 'source',
            '-PythonPath', 'python.exe',
            '-ReceiptPath', 'receipt.json'
        )
    },
    [pscustomobject]@{
        path = 'operations/Build-SdkArtifacts.ps1'
        arguments = @(
            '-SourceRoot', 'source',
            '-PythonPath', 'python.exe',
            '-SourceIdentityReceiptPath', 'source-identity.json',
            '-ExpectedSourceIdentityReceiptSha256', '0000000000000000000000000000000000000000000000000000000000000000',
            '-OutputRoot', 'output',
            '-ReceiptPath', 'receipt.json'
        )
    },
    [pscustomobject]@{
        path = 'operations/Test-SdkArtifactMetadata.ps1'
        arguments = @(
            '-PythonPath', 'python.exe',
            '-ArtifactReceiptPath', 'artifact-receipt.json',
            '-ExpectedArtifactReceiptSha256', '0000000000000000000000000000000000000000000000000000000000000000',
            '-ArtifactRoot', 'artifacts',
            '-ReceiptPath', 'receipt.json'
        )
    },
    [pscustomobject]@{
        path = 'operations/Test-SdkFreshInstall.ps1'
        arguments = @(
            '-PythonPath', 'python.exe',
            '-ArtifactReceiptPath', 'artifact-receipt.json',
            '-ExpectedArtifactReceiptSha256', '0000000000000000000000000000000000000000000000000000000000000000',
            '-MetadataReceiptPath', 'metadata-receipt.json',
            '-ExpectedMetadataReceiptSha256', '0000000000000000000000000000000000000000000000000000000000000000',
            '-ArtifactRoot', 'artifacts',
            '-WorkRoot', 'work',
            '-ReceiptPath', 'receipt.json'
        )
    },
    [pscustomobject]@{
        path = 'operations/Test-GitHubReleaseAssets.ps1'
        arguments = @(
            '-ArtifactReceiptPath', 'artifact-receipt.json',
            '-ExpectedArtifactReceiptSha256', '0000000000000000000000000000000000000000000000000000000000000000',
            '-FreshInstallReceiptPath', 'fresh-install-receipt.json',
            '-ExpectedFreshInstallReceiptSha256', '0000000000000000000000000000000000000000000000000000000000000000',
            '-ReceiptPath', 'receipt.json'
        )
    }
)

$PowerShellExecutable = Join-Path $PSHOME 'powershell.exe'
Assert-Condition (Test-Path -LiteralPath $PowerShellExecutable -PathType Leaf) 'powershell.exe is unavailable below PSHOME.'
$SafeStopResults = @()
for ($Index = 0; $Index -lt $SafeStopCases.Count; $Index++) {
    $Case = $SafeStopCases[$Index]
    $OneCaseRoot = Join-Path $CaseRoot ('case-' + ($Index + 1).ToString('D2'))
    [IO.Directory]::CreateDirectory($OneCaseRoot) | Out-Null
    $MissingManifest = Join-Path $OneCaseRoot 'missing-manifest.json'
    $BeforeEntries = @(Get-RelativeEntrySet -LiteralPath $OneCaseRoot)
    $ScriptPath = Join-Path $ReleaseRootFull ($Case.path.Replace('/', '\'))
    $Arguments = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', $ScriptPath,
        '-ManifestPath', $MissingManifest,
        '-ExpectedManifestSha256', '0000000000000000000000000000000000000000000000000000000000000000'
    )
    foreach ($Argument in @($Case.arguments)) {
        if ([string]$Argument -cmatch '^-') {
            $Arguments += [string]$Argument
        }
        elseif ([string]$Argument -cmatch '\A[0-9a-f]{64}\z') {
            $Arguments += [string]$Argument
        }
        else {
            $Arguments += (Join-Path $OneCaseRoot ([string]$Argument))
        }
    }

    $PriorErrorActionPreference = $ErrorActionPreference
    try {
        # A deliberate child STOP writes to the native stderr stream. Keep the
        # parent runner alive long enough to inspect its exit code and output.
        $ErrorActionPreference = 'Continue'
        $OutputLines = @(& $PowerShellExecutable @Arguments 2>&1)
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PriorErrorActionPreference
    }
    $Output = @($OutputLines | ForEach-Object { [string]$_ }) -join "`n"
    $AfterEntries = @(Get-RelativeEntrySet -LiteralPath $OneCaseRoot)
    $LocalEntryDifference = @(Compare-Object -ReferenceObject $BeforeEntries -DifferenceObject $AfterEntries)
    $Passed = (
        $ExitCode -ne 0 -and
        $Output -cmatch '(?i)(manifest|required file).*unavailable' -and
        $Output -cmatch '(?i)missing-manifest\.json' -and
        $LocalEntryDifference.Count -eq 0
    )
    $SafeStopResults += [pscustomobject][ordered]@{
        path = [string]$Case.path
        result = if ($Passed) { 'PASS' } else { 'FAIL' }
        exit_code = $ExitCode
        expected_failure = 'MISSING_MANIFEST'
        local_entry_change_count = $LocalEntryDifference.Count
    }
}

$SafeStopFailureCount = @(
    $SafeStopResults |
        Where-Object { $_.result -cne 'PASS' }
).Count
Assert-Condition ($SafeStopFailureCount -eq 0) 'One or more pre-provider missing-manifest safe-stop checks failed.'

$Receipt = [pscustomobject][ordered]@{
    schema_version = 'ln_church.sdk_release_operations_ps51_qualification.v1'
    result = 'SDK_RELEASE_OPERATIONS_PS51_QUALIFICATION: PASS'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    powershell_edition = [string]$PSVersionTable.PSEdition
    powershell_version = [string]$PSVersionTable.PSVersion
    qualification_script_sha256 = Get-Sha256Hex -LiteralPath $PSCommandPath
    files = $FileResults
    safe_stops = $SafeStopResults
    parse_error_count = 0
    safe_stop_failure_count = 0
    child_powershell_process_count = $SafeStopCases.Count
    external_provider_call_count = 0
    github_api_call_count = 0
    package_registry_call_count = 0
    provider_mutation_count = 0
    github_mutation_count = 0
    package_registry_mutation_count = 0
    qualification_limit = 'Exact-byte PS5.1 parsing and deliberate missing-manifest safe stops only; normal-path build, qualification, GitHub read-back, and publication require separate receipts.'
}
Write-NewJsonFile -LiteralPath $ReceiptPath -Value $Receipt
$Receipt | ConvertTo-Json -Depth 12
