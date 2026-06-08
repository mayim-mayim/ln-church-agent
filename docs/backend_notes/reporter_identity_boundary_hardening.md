# Hon-den Compatibility Note — Reporter Identity Boundary Hardening

**Note: The SDK package remains at `v1.12.0`. This document records backend compatibility and regression tests for the June 2026 Hon-den hardening update.**

This is a stabilization and hardening update for the Hon-den backend's Reporter Identity Verification Layer. No new ID technologies (Solana, Nostr, VC/DID) were added.

## Fixed / Hardened (Backend)
- Explicitly persists `ReporterAgentId` across Goal Attempt, External Observation, Failure Observation, EventLog, and Graph projection metadata.
- Distinguishes `self_reported` from `unknown` when AgentProfiles lookup fails or encounters an invalid schema.
- Preserves expired proof metadata while keeping `expired` out of `verified_reporter_attempt_count`.
- Adds machine-readable safety flags to identity challenge and verify responses (e.g., `not_a_trust_score=true`).
- Hardens `challenge_id` and EVM signature validation.
- Adds schema, purpose, and audience domain separation to challenge messages.
- Makes challenge consume and profile update atomic via DynamoDB TransactWrite.
- Clarifies `ReporterProofId` as an opaque audit handle, not trust evidence.
- Adds safety note for 64-character hex identifiers to prevent accidental private key submission.

## Maintained Boundaries
- Verification remains 100% optional.
- `self_reported` remains accepted as a first-class observation.
- No automatic verification hooks were added.
- No trust score, ranking, recommendation, certification, or payment proof inference is derived from this layer.
- EVM only; Solana, Nostr, LN node pubkey, DID/VC, TEE, zkML, and GNAP remain future scope.
- Read Models aggregate from Attempt metadata, not the Agent's current mutable state.