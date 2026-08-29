# ln-church-agent Public Repository Rules

## Repository role

- Read `DEVELOPMENT.md` first.
- This repository is the public distribution surface for the Agent SDK.
- Normal feature and source development occurs in `mayim-mayim/ln-church-agent-private`.
- Cross-project workflow, roles, origin rules, audit gates, and release rules are maintained in `mayim-mayim/LN_Church_Development-Charter`.

## Allowed work

- Authorized promotion of an exact frozen private candidate that Development Control read back from its dedicated GitHub candidate ref and that passed the required independent Release Readiness Gate.
- Package metadata, release notes, tags, and release assets tied to the frozen candidate.
- Narrow public-only documentation corrections under explicit bounded authority.
- Explicit Human-authorized emergency promotion, rollback, or publication work.

## Prohibited work

- Do not implement normal features directly in this repository.
- Release AI does not repair source, stage a missing private candidate, or recreate one as a new commit.
- Do not publish content that cannot be traced to audited private source or an explicitly authorized public-only correction.
- Do not infer tag, GitHub Release, PyPI, MCP Registry, merge, or publication authority from permission to create a branch or PR.

## Promotion and release identity

Preserve traceability among:

- private candidate ref, source commit, tree, parent, and relevant blobs;
- independent audit or Human-approved emergency-waiver authority;
- promoted public commit, tree, and blobs;
- built wheel and sdist plus digests;
- tag and GitHub Release;
- PyPI and MCP Registry publication;
- post-release verification.

The candidate-ref requirement applies prospectively. An unchanged pre-adoption exact ref is handled under the Development Charter transition rule and is not renamed, recreated, or source-reaudited solely because staging occurred before adoption.

When source repair is required or the private candidate ref／identity cannot be proven, hold the affected promotion and report through the Development Charter Audit release-problem assessment route. Release does not stage or recreate the private candidate and does not dispatch directly to Development Control or Implementation. A missing／mismatched Release Readiness ref is an identity／handoff `STOP_HANDOFF`／`STOP`, not a Product-source failure.

## Change control

- Never push directly to `main`.
- Use a dedicated branch from the exact authorized public base.
- Keep public-only changes narrowly scoped.
- Report commit, tree, parent, changed paths, provenance, checks, artifact identities, and unverified items.
- During active publication, use repository-owned qualified tooling where available and do not silently rebuild or substitute unverified artifacts.

## Protected information

Never commit or promote private fixtures, internal handoffs, private evidence, credentials, tokens, signing material, wallet material, authorization headers, or secret-bearing configuration.
