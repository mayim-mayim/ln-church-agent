[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PythonPath,

    [ValidateSet('Preflight', 'Publish')]
    [string]$Mode = 'Preflight'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedVersion = '1.17.0'
$ExpectedTag = 'v1.17.0'
$ExpectedCommit = 'a6d9d8ff82d1564e5d7a226efcafa65a72065e8f'
$ExpectedTree = '2206ce19df1c8001bba506e325925377db3e9f36'
$ExpectedWheelHash = '6e9457aab26c336f1e7a7b762b4665d48c5369c7d468233e594c54be34683882'
$ExpectedSdistHash = '8adb567305a052f224e95944d43e165510d333038fe8c299b977835be7687d0b'
$ProjectJsonUrl = 'https://pypi.org/pypi/ln-church-agent/json'
$UploadUrl = 'https://upload.pypi.org/legacy/'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistPath = Join-Path -Path $ScriptRoot -ChildPath 'dist'
$WheelPath = Join-Path -Path $DistPath -ChildPath 'ln_church_agent-1.17.0-py3-none-any.whl'
$SdistPath = Join-Path -Path $DistPath -ChildPath 'ln_church_agent-1.17.0.tar.gz'

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    $NativeExitCode = $LASTEXITCODE
    if ($NativeExitCode -ne 0) {
        throw "Native command failed with exit code ${NativeExitCode}: $FilePath"
    }
}

function Get-PublishedVersionProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ProjectJson
    )

    return $ProjectJson.releases.PSObject.Properties |
        Where-Object { $_.Name -eq $ExpectedVersion } |
        Select-Object -First 1
}

Write-Output 'V17_SDK_PYPI_GATE=START'
Write-Output "MODE=$Mode"
Write-Output "EXPECTED_TAG=$ExpectedTag"
Write-Output "EXPECTED_COMMIT=$ExpectedCommit"
Write-Output "EXPECTED_TREE=$ExpectedTree"

if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "Python executable not found: $PythonPath"
}
if (-not (Test-Path -LiteralPath $WheelPath -PathType Leaf)) {
    throw "Wheel not found: $WheelPath"
}
if (-not (Test-Path -LiteralPath $SdistPath -PathType Leaf)) {
    throw "Source distribution not found: $SdistPath"
}

$PythonVersionJson = & $PythonPath -c 'import json, sys; print(json.dumps({"major": sys.version_info.major, "minor": sys.version_info.minor, "micro": sys.version_info.micro}))'
$PythonVersionExitCode = $LASTEXITCODE
if ($PythonVersionExitCode -ne 0) {
    throw "Python version check failed with exit code $PythonVersionExitCode"
}
$PythonVersion = $PythonVersionJson | ConvertFrom-Json
if (($PythonVersion.major -ne 3) -or ($PythonVersion.minor -ne 11)) {
    throw "Python 3.11.x is required. Detected $($PythonVersion.major).$($PythonVersion.minor).$($PythonVersion.micro)"
}
Write-Output "PYTHON_VERSION=$($PythonVersion.major).$($PythonVersion.minor).$($PythonVersion.micro)"

$WheelHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $WheelPath).Hash.ToLowerInvariant()
$SdistHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SdistPath).Hash.ToLowerInvariant()
if ($WheelHash -ne $ExpectedWheelHash) {
    throw "Wheel SHA-256 mismatch. Expected $ExpectedWheelHash but found $WheelHash"
}
if ($SdistHash -ne $ExpectedSdistHash) {
    throw "Source distribution SHA-256 mismatch. Expected $ExpectedSdistHash but found $SdistHash"
}
Write-Output "WHEEL_SHA256=$WheelHash"
Write-Output "SDIST_SHA256=$SdistHash"

$ToolEnvironment = Join-Path -Path $env:TEMP -ChildPath ('ln-church-agent-v117-pypi-' + [Guid]::NewGuid().ToString('N'))
Invoke-NativeChecked -FilePath $PythonPath -Arguments @('-m', 'venv', $ToolEnvironment)
$ToolPython = Join-Path -Path $ToolEnvironment -ChildPath 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $ToolPython -PathType Leaf)) {
    throw "Temporary Python environment was not created: $ToolPython"
}

Invoke-NativeChecked -FilePath $ToolPython -Arguments @('-m', 'pip', 'install', '--disable-pip-version-check', 'twine==7.0.0')
Invoke-NativeChecked -FilePath $ToolPython -Arguments @('-m', 'twine', 'check', $WheelPath, $SdistPath)

$ExistingProject = Invoke-RestMethod -Method Get -Uri $ProjectJsonUrl -TimeoutSec 30
$ExistingVersion = Get-PublishedVersionProperty -ProjectJson $ExistingProject
if ($null -ne $ExistingVersion) {
    throw "PyPI already contains ln-church-agent $ExpectedVersion. Upload is prohibited."
}

Write-Output 'PYPI_VERSION_ABSENT=PASS'
Write-Output 'TWINE_CHECK=PASS'

if ($Mode -eq 'Preflight') {
    Write-Output "TOOL_ENVIRONMENT=$ToolEnvironment"
    Write-Output 'V17_SDK_PYPI_PREFLIGHT_GATE=PASS'
    return
}

$SecureToken = Read-Host -Prompt 'Enter the PyPI API token for ln-church-agent' -AsSecureString
$TokenPointer = [IntPtr]::Zero
$PlainToken = $null
try {
    $TokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
    $PlainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($TokenPointer)
    if ([string]::IsNullOrWhiteSpace($PlainToken)) {
        throw 'The PyPI API token is empty.'
    }

    $env:TWINE_USERNAME = '__token__'
    $env:TWINE_PASSWORD = $PlainToken
    Invoke-NativeChecked -FilePath $ToolPython -Arguments @(
        '-m', 'twine', 'upload',
        '--non-interactive',
        '--repository-url', $UploadUrl,
        $WheelPath,
        $SdistPath
    )
}
finally {
    if ($TokenPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($TokenPointer)
    }
    $PlainToken = $null
    Remove-Item -LiteralPath 'Env:\TWINE_USERNAME' -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'Env:\TWINE_PASSWORD' -ErrorAction SilentlyContinue
}

$PublishedVersion = $null
for ($Attempt = 1; $Attempt -le 6; $Attempt++) {
    $PublishedProject = Invoke-RestMethod -Method Get -Uri $ProjectJsonUrl -TimeoutSec 30
    $PublishedVersion = Get-PublishedVersionProperty -ProjectJson $PublishedProject
    if ($null -ne $PublishedVersion) {
        break
    }
    Start-Sleep -Seconds 5
}
if ($null -eq $PublishedVersion) {
    throw "PyPI upload returned success, but version $ExpectedVersion was not visible after bounded verification."
}

$PublishedHashes = @($PublishedVersion.Value | ForEach-Object { $_.digests.sha256.ToLowerInvariant() })
if ($PublishedHashes -notcontains $ExpectedWheelHash) {
    throw 'Published PyPI wheel hash does not match the fixed artifact.'
}
if ($PublishedHashes -notcontains $ExpectedSdistHash) {
    throw 'Published PyPI source distribution hash does not match the fixed artifact.'
}

Write-Output 'PYPI_VERSION_VISIBLE=PASS'
Write-Output 'PYPI_ARTIFACT_HASHES=PASS'
Write-Output 'V17_SDK_PYPI_PUBLISH_GATE=PASS'
