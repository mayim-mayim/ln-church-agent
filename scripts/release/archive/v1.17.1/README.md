# SDK v1.17.1 release archive

This archive records the SDK v1.17.1 GitHub release without rewriting history.
The release completed before the reusable operations under
`scripts/release/sdk/operations/` were prepared. Consequently, this directory
contains a retrospective manifest and retrospective records, not fabricated
operation-generated receipts.

## Fixed public identity

- Public release commit: `64520b2692c25db8675bb235eb431401aa5006a4`
- Public release tree: `5772e8eb30e8ba4431cce0037303fa91ec0445ff`
- Audited Public Phase 2 candidate:
  `fda978c6d2af8833a9126dbbaa9df05db844cbd3`
- Tag: `v1.17.1`
- Release: <https://github.com/mayim-mayim/ln-church-agent/releases/tag/v1.17.1>

The tag targets the release commit. The audited candidate and merge commit have
the same tree.

## Files

- `release-manifest.json` records the release-specific source, package,
  tooling, operation-candidate, and GitHub inputs. Its `archive` block marks it
  as a post-publication reconstruction.
- `executed-tool-manifest.json` distinguishes the later generic operation bytes
  from the mechanisms actually used during v1.17.1.
- `receipts/artifact-identity.json` fixes the published wheel and sdist bytes.
- `receipts/qualification-summary.json` preserves the reported audit, Linux
  suite, and fresh-install result plus the native-Windows boundary.
- `receipts/github-release-readback.json` records a new read-only tag, Release,
  asset-inventory, and downloaded-digest verification.

All files under `receipts/` use
`ln_church.sdk_release_retrospective_receipt.v1`. They intentionally do not use
`ln_church.sdk_release_receipt.v1`, so the reusable operations cannot accept
them as if those operations had produced them.

## Why no canonical receipt chain is claimed

The exact reusable PowerShell operation bytes were not executed during the
release, and their Windows PowerShell 5.1 qualification is not established.
The original build command identity and operation-shaped receipt chain were not
retained.

A diagnostic build from the fixed public commit, using the observed Linux build
tool versions, produced valid artifact names but different bytes from the
published assets. Therefore the published bytes remain the release artifacts;
the diagnostic build must not replace them, and a canonical build receipt must
not be reconstructed by assertion.

## Publication scope

GitHub tag, GitHub Release, and two GitHub assets are complete. PyPI and MCP
Registry publication were not performed and were outside the authorized scope.

## Reusable-operation status

The five candidates are statically validated but remain candidates until their
exact bytes parse and execute under Windows PowerShell 5.1. This historical
GitHub release does not waive that qualification requirement for future use.
Future execution must also receive the retrospective manifest's SHA-256 as a
separate Human-approved input; the manifest is not permitted to approve its own
bytes. Each downstream operation must likewise receive independently approved
SHA-256 values for every upstream receipt. Those external anchors were not
retained for v1.17.1, which is an additional reason these retrospective records
cannot be promoted into a canonical receipt chain.
