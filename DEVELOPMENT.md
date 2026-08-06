# Public Repository Development Boundary

This repository is the public distribution surface for the LN Church Agent SDK.

## Normal source of changes

Feature and runtime development normally occurs in:

- `mayim-mayim/ln-church-agent-private`

Cross-project role, workflow, architecture, and release rules are maintained in:

- `mayim-mayim/LN_Church_Development-Charter`

This public repository receives frozen, independently audited content through an authorized promotion and release process.

## Normal flow

```text
private Agent SDK candidate
→ independent audit
→ Development Control freeze
→ Release AI promotion
→ public repository identity verification
→ package publication and post-release verification
```

## Allowed normal-flow updates

- Audited source and documentation promoted from the private repository.
- Public package metadata, release notes, tags, and release assets tied to the frozen candidate.
- Narrow public-only documentation corrections under explicit authority.

## Prohibited normal-flow updates

- New feature implementation directly in the public repository.
- Source repair by Release AI.
- Publication of content that cannot be traced to an audited private source or an explicitly authorized public-only correction.
- Committing secrets, credentials, private runtime evidence, or private test fixtures.

## Release identity

A release should preserve traceability among:

- private source commit, tree, and relevant blobs;
- audited candidate and evidence;
- promoted public tree or blobs;
- built package artifact and digest;
- tag and GitHub Release;
- PyPI / MCP Registry publication;
- post-release verification.

When source repair is required, the Release lane stops and the work returns to Development Control and the private implementation lane.

## Canonical governance

See:

- `LN_Church_Development-Charter/docs/Development_Workflow.md`
- `LN_Church_Development-Charter/docs/AI_Role_Definitions/README.md`
- `LN_Church_Development-Charter/docs/Repository_Responsibilities.md`
