# SDK release qualification operations

This directory contains version-independent Windows PowerShell 5.1 operations
for qualifying an SDK release.  It deliberately stops before PyPI or MCP
Registry publication.  Those authenticated publication steps remain Human-run
operations.

The operations are bounded and ordered. A successful operation writes a
create-once JSON receipt; the next mutating local operation requires that
receipt.
Each downstream receipt fixes the SHA-256 of the upstream receipt bytes, so the
evidence chain is not based on a path alone.  Receipts use create-new file
semantics and never overwrite an existing path.
Canonical receipts contain logical names, hashes, sizes, and relative source
paths only.  Absolute workstation, checkout, artifact, evidence, virtual
environment, and import paths are deliberately excluded.  Local paths are
invocation inputs, not portable release evidence.
No operation creates or updates a GitHub ref, release, package-registry version,
or runtime resource.

## Operation order

1. `operations/Test-SdkSourceIdentity.ps1`
   - verifies the clean checkout commit and tree;
   - optionally verifies a local tag;
   - verifies required tracked-file SHA-256 values;
   - runs the repository-owned release-identity pytest without a pytest cache;
   - requires JUnit evidence for exactly one passed test and zero skipped,
     failed, or errored tests.
2. `operations/Build-SdkArtifacts.ps1`
   - requires the source-identity receipt;
   - exports the immutable manifest commit with `git archive`;
   - rechecks commit and tree immediately after the archive and after the build;
   - invokes `python -m build` exactly once in the exported staging tree;
   - writes the fixed artifact paths, sizes, and SHA-256 values to its receipt.
3. `operations/Test-SdkArtifactMetadata.ps1`
   - rechecks the fixed paths, sizes, and hashes from the build receipt;
   - runs `twine check`;
   - compares wheel and sdist metadata, checks it against manifest-fixed
     `Requires-Python`, `Provides-Extra`, and `Requires-Dist` values, checks
     exact console entry points, and rejects unsafe archive paths.
4. `operations/Test-SdkFreshInstall.ps1`
   - requires the metadata receipt;
   - creates new core and optional-extra virtual environments;
   - installs only the fixed wheel recorded by the build receipt;
   - checks installed version and import origin, all declared smoke commands,
     and `pip check`;
   - records the exact venv pip version and a path-free canonical `pip freeze`.
5. `operations/Test-GitHubReleaseAssets.ps1`
   - requires the fresh-install receipt;
   - verifies that the existing tag targets the manifest commit and tree;
   - reads an existing public GitHub Release;
   - downloads only its declared assets to a temporary directory;
   - checks exact asset names, sizes, and SHA-256 values against the build
     receipt;
   - rereads the tag, commit/tree, Release, and complete asset inventory after
     download and rejects any mid-operation change.

`Build-SdkArtifacts.ps1` refuses an existing output directory.  A failed or
ambiguous build is not retried by the operation.  Reconciliation and a new
explicit output path are required before another Human-authorized attempt.

## Manifest contract

All five operations accept the same JSON manifest plus a mandatory
Human-supplied `ExpectedManifestSha256`. The expected digest must come from the
change-controlled release handoff; deriving it from the manifest in the same
invocation would make the manifest self-trusting. Version-specific values
belong in the manifest, never in script bytes. The single parseable contract is
`sdk-release-manifest.example.json`; copy it outside this directory and replace
every placeholder before a release. The README intentionally does not carry a
second JSON copy that can drift from that contract.

The manifest binds all of the following:

- release version, canonical `v<version>` tag, source commit and tree;
- exact Python major, minor, and micro version;
- exact `build`, `setuptools`, `wheel`, `pytest`, `twine`, venv `pip`, and Git
  versions;
- exact SHA-256 for all five operation scripts;
- required source-file hashes, release-identity pytest node, package identity,
  expected metadata, console entry points, artifact filenames, fresh-install
  imports/smokes, and GitHub repository.

Every operation checks its own SHA-256 before its substantive work. Every
downstream operation also verifies that each supplied upstream receipt was made
by the manifest-fixed operation bytes. Recording an observed script hash without
checking it is not accepted as canonical evidence.
Every downstream receipt is also bound to a mandatory Human-supplied expected
SHA-256. That digest must be approved from the preceding operation's handoff
before the downstream operation starts; deriving and consuming it silently in
the same command chain would leave the receipt self-trusting. The source
identity operation has no upstream receipt. Build binds the source-identity
receipt, metadata binds the artifact-build receipt, fresh install binds both
artifact-build and metadata receipts, and GitHub read-back binds both
artifact-build and fresh-install receipts.
Each operation first rejects a manifest whose initial hash differs from the
Human-supplied expected digest. It then hashes its manifest and upstream receipts before reading them,
opens those inputs with read-only sharing, hashes and parses the bytes read from
the held streams, and keeps the streams open through final receipt creation.
Hash checks after parsing, immediately before substantive commands, and before
the receipt provide explicit drift evidence while the held handles prevent a
writer or delete/replace operation from entering the check/use interval.
Build output artifacts are opened with the same read-only sharing before their
digests are computed and remain locked through the build receipt. Metadata and
fresh-install operations lock both the fixed wheel and sdist before hashing;
they recheck those initial hashes immediately before artifact use and before
their final receipts. The read-sharing mode still permits Twine, Python, and
pip to open the same immutable files for reading.
The adjacent `.gitattributes` forces LF working-tree bytes for these scripts and
the manifest so Windows checkout EOL conversion cannot silently invalidate or
reinterpret the recorded operation hashes.

The manifest is a release input and therefore does not contain artifact hashes
that do not exist until after the build.  The build receipt fixes those hashes.
Metadata, fresh-install, GitHub Release, and Human publication work must consume
that same receipt and must not rebuild or substitute artifacts.

The GitHub read-back operation derives both API endpoints from
`github.repository` plus the single canonical `release.tag`.  Callers do not
duplicate or hand-edit a tag value or tag and Release URLs.

## Version archive

Reusable operation scripts remain under this directory and are not copied into
each version archive. A completed release archives only release-specific
identity and evidence under `scripts/release/archive/<version>/`:

- the filled release manifest;
- an executed-tool manifest fixing the exact operation paths and SHA-256 values;
- the create-once operation receipts produced during that release.

If canonical operations or receipts did not exist at execution time, the
archive must say so. A retrospective record uses a different schema and cannot
be renamed or shaped to satisfy an operation's upstream-receipt guard. The
v1.17.1 archive demonstrates this boundary: it fixes the real published bytes
and GitHub read-back, while recording that the later generic operation
candidates were not the tools that performed the release.

The build operation uses `--no-isolation` only with the manifest-qualified
frontend/backend environment. It clears ambient Python, pytest, setuptools-scm,
constraint, and source-date variables before invoking the backend. It never
archives mutable `HEAD`; the archive input is the fixed commit.

`release_identity_test_name` must select only the source/version identity test.
It must not select a repository test that builds another wheel or creates
another fresh environment; build and fresh-install attempts belong exclusively
to their respective operations.

## Typical invocation

Use new, absent receipt, output, and fresh-environment paths for each run.

```powershell
$sdkTools = 'C:\path\to\scripts\release\sdk\operations'
$manifest = 'C:\release\sdk-release-manifest.json'
$expectedManifestSha256 = '<Human-approved-64-hex-manifest-SHA-256>'
$source = 'C:\release\source'
$python = 'C:\release\qualified-python311\Scripts\python.exe'
$evidence = 'C:\release\evidence'
$expectedSourceIdentityReceiptSha256 = '<Human-approved-source-identity-receipt-SHA-256>'
$expectedArtifactReceiptSha256 = '<Human-approved-artifact-build-receipt-SHA-256>'
$expectedMetadataReceiptSha256 = '<Human-approved-metadata-receipt-SHA-256>'
$expectedFreshInstallReceiptSha256 = '<Human-approved-fresh-install-receipt-SHA-256>'

& (Join-Path $sdkTools 'Test-SdkSourceIdentity.ps1') `
    -ManifestPath $manifest `
    -ExpectedManifestSha256 $expectedManifestSha256 `
    -SourceRoot $source `
    -PythonPath $python `
    -ReceiptPath (Join-Path $evidence 'source-identity.json')

& (Join-Path $sdkTools 'Build-SdkArtifacts.ps1') `
    -ManifestPath $manifest `
    -ExpectedManifestSha256 $expectedManifestSha256 `
    -SourceRoot $source `
    -PythonPath $python `
    -SourceIdentityReceiptPath (Join-Path $evidence 'source-identity.json') `
    -ExpectedSourceIdentityReceiptSha256 $expectedSourceIdentityReceiptSha256 `
    -OutputRoot 'C:\release\artifacts' `
    -ReceiptPath (Join-Path $evidence 'artifact-build.json')

& (Join-Path $sdkTools 'Test-SdkArtifactMetadata.ps1') `
    -ManifestPath $manifest `
    -ExpectedManifestSha256 $expectedManifestSha256 `
    -PythonPath $python `
    -ArtifactReceiptPath (Join-Path $evidence 'artifact-build.json') `
    -ExpectedArtifactReceiptSha256 $expectedArtifactReceiptSha256 `
    -ArtifactRoot 'C:\release\artifacts' `
    -ReceiptPath (Join-Path $evidence 'artifact-metadata.json')

& (Join-Path $sdkTools 'Test-SdkFreshInstall.ps1') `
    -ManifestPath $manifest `
    -ExpectedManifestSha256 $expectedManifestSha256 `
    -PythonPath $python `
    -ArtifactReceiptPath (Join-Path $evidence 'artifact-build.json') `
    -ExpectedArtifactReceiptSha256 $expectedArtifactReceiptSha256 `
    -MetadataReceiptPath (Join-Path $evidence 'artifact-metadata.json') `
    -ExpectedMetadataReceiptSha256 $expectedMetadataReceiptSha256 `
    -ArtifactRoot 'C:\release\artifacts' `
    -WorkRoot 'C:\release\fresh-install' `
    -ReceiptPath (Join-Path $evidence 'fresh-install.json')

& (Join-Path $sdkTools 'Test-GitHubReleaseAssets.ps1') `
    -ManifestPath $manifest `
    -ExpectedManifestSha256 $expectedManifestSha256 `
    -ArtifactReceiptPath (Join-Path $evidence 'artifact-build.json') `
    -ExpectedArtifactReceiptSha256 $expectedArtifactReceiptSha256 `
    -FreshInstallReceiptPath (Join-Path $evidence 'fresh-install.json') `
    -ExpectedFreshInstallReceiptSha256 $expectedFreshInstallReceiptSha256 `
    -ReceiptPath (Join-Path $evidence 'github-release-assets.json')
```

## Fresh-install dependency boundary

The current fresh-install operation intentionally exercises public online
dependency resolution after clearing pip configuration and index override
variables. It fixes the wheel under test and the venv pip version, then records
the resolved package set, but it does **not** make third-party dependency bytes
reproducible. Until a manifest-qualified constraints file and hash-qualified
offline wheelhouse are added, this step is an observed compatibility smoke, not
an independently reproducible dependency-supply-chain qualification. A release
that requires the stronger boundary must stop rather than reinterpret this
receipt.

## Qualification boundary

These files are prepared candidates until their exact bytes parse and complete
their representative normal path under Windows PowerShell 5.1.  A parser PASS
alone is not an execution qualification.  Linux-based review can check JSON,
Python snippets, and static invariants, but cannot establish PS5.1 execution.

`qualification/Test-SdkReleaseOperationsPS51.ps1` is the local-only first gate.
It requires Windows PowerShell 5.1 Desktop, rejects any change to the exact set
of five operation scripts plus the qualification runner itself, parses all six
files, and starts each operation with a deliberately missing manifest.  Every
case must stop before creating a local file or directory.  The runner writes a
create-once receipt containing its own SHA-256 and the SHA-256 of every parsed
file.  It makes no provider, GitHub, or package-registry call or mutation.

Run it with an existing, empty evidence directory:

```powershell
$sdkRoot = 'C:\path\to\scripts\release\sdk'
$evidence = 'C:\release\sdk-operation-qualification'
New-Item -ItemType Directory -Path $evidence

& (Join-Path $sdkRoot 'qualification\Test-SdkReleaseOperationsPS51.ps1') `
    -ReleaseRoot $sdkRoot `
    -EvidenceRoot $evidence
```

This gate proves parser compatibility and the pre-provider missing-manifest
boundary only.  It does not qualify any normal-path operation, build artifacts,
fresh installation, GitHub Release state, or publication.  The runner is a
qualification tool, not a sixth release operation, so it is not added to a
version archive as though it had executed the v1.17.1 release.
