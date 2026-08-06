# ln-church-agent Public Repository Rules

## Repository role

- Read `DEVELOPMENT.md` first.
- This repository is the public distribution surface for the Agent SDK.
- Normal feature and source development occurs in `mayim-mayim/ln-church-agent-private`.
- Cross-project workflow, roles, origin rules, audit gates, and release rules are maintained in `mayim-mayim/LN_Church_Development-Charter`.

## Allowed work

- Authorized promotion of frozen, independently audited private source.
- Package metadata, release notes, tags, and release assets tied to the frozen candidate.
- Narrow public-only documentation corrections under explicit bounded authority.
- Explicit Human-authorized emergency promotion, rollback, or publication work.

## Prohibited work

- Do not implement normal features directly in this repository.
- Release AI does not repair source.
- Do not publish content that cannot be traced to audited private source or an explicitly authorized public-only correction.
- Do not infer tag, GitHub Release, PyPI, MCP Registry, merge, or publication authority from permission to create a branch or PR.

## Promotion and release identity

Preserve traceability among:

- private source commit, tree, and relevant blobs;
- independent audit or Human-approved emergency-waiver authority;
- promoted public commit, tree, and blobs;
- built wheel and sdist plus digests;
- tag and GitHub Release;
- PyPI and MCP Registry publication;
- post-release verification.

Stop the Release lane and return to Development Control and the private implementation repository when source repair is required or private-to-public identity cannot be proven.

## Change control

- Never push directly to `main`.
- Use a dedicated branch from the exact authorized public base.
- Keep public-only changes narrowly scoped.
- Report commit, tree, parent, changed paths, provenance, checks, artifact identities, and unverified items.
- During active publication, use repository-owned qualified tooling where available and do not silently rebuild or substitute unverified artifacts.

## Protected information

Never commit or promote private fixtures, internal handoffs, private evidence, credentials, tokens, signing material, wallet material, authorization headers, or secret-bearing configuration.
