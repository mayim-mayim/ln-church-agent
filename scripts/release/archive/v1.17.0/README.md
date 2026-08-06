# v1.17.0 PyPI publication-tool archive

This directory preserves the exact Windows PowerShell 5.1 script used to publish `ln-church-agent==1.17.0`.

## Qualification record

| File | SHA-256 | Qualification | Observed terminal evidence |
|---|---|---|---|
| `Publish_v1.17.0_PyPI_PS51.ps1` | `dc47aaf6d0c1411f59134724a816835c65d36c4de647107b494bbf3be6cc3514` | `PS51_EXECUTED_PASS` | `PYPI_VERSION_VISIBLE=PASS`; `PYPI_ARTIFACT_HASHES=PASS`; `V17_SDK_PYPI_PUBLISH_GATE=PASS` |

## Use boundary

- This file is immutable historical release evidence, not a generic publisher.
- It fixes version 1.17.0, filenames, and artifact hashes. Re-running Publish is expected to stop because the version already exists.
- It prompts for a PyPI API token as a `SecureString`, sets Twine environment variables only for the upload, and removes them in `finally`. No token is stored in the repository.
- A future publication must use a newly generated candidate, fixed artifact identities, explicit Human publication authority, and a new Windows PowerShell 5.1 execution qualification.
- Failure to observe PyPI after upload is an ambiguous mutation result: reconcile read-only before any retry.

Cross-project qualification rules and the current registry are maintained in `mayim-mayim/LN_Church_Development-Charter`.
