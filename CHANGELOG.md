# Changelog

All notable changes to the `ln-church-agent` SDK will be documented in this file. Detailed release notes for specific versions can be found in the `docs/release_notes/` directory.

## [1.15.0] - Unreleased (Verified Domain Sponsor MVP v1)
* **Added**: SDK helpers for Verified Domain Sponsor (`create_domain_sponsor_challenge()`, `verify_domain_sponsor()`, `save_domain_sponsor_challenge_document()`).
* **Added**: CLI commands `ln-church-agent observe-domain sponsor challenge` and `ln-church-agent observe-domain sponsor verify`.
* **Added**: Public-safe models for sponsor verification read models (`DomainSponsorVerification`, `DomainSponsorVerificationSummary`, etc).
* **Safety**: Verified Domain Sponsor proves only domain-control challenge publication. It is not legal ownership proof, not a certification, not a recommendation, not a trust score, and not a security scan.
* **Safety**: SDK does not automatically issue challenges or verify sponsors after paid registration. CLI avoids printing proof headers and challenge tokens unless explicitly requested with `--json` or `--print-document`.

## [1.14.2] - 2026-06-27 (MCP Registry Metadata Fix)

* **Fixed**: Shortened the `server.json` description to satisfy the official MCP Registry `description.length <= 100` validation rule.
* **Changed**: Preserved the inspect-only MCP positioning in a more compact registry-safe form: keyless, no wallet, no signing, and no payment execution.
* **Safety**: No runtime behavior, payment execution logic, settlement serialization, telemetry submission, or API surface was altered.


## [1.14.1] - 2026-06-27 (Runtime Mode Boundary Clarification)
* **Documentation**: Explicitly separated the SDK's positioning into two distinct modes: **Inspect-only Mode** (keyless, safe for enterprise preflight) and **Execution Runtime Mode** (policy-aware settlement loop).
* **Added**: Expanded the Capability Matrix (`docs/07_capability_matrix.md`) and the `get_capability_matrix()` helper with new strict boundary fields (`mode`, `requires_private_key`, `can_execute_payment`, `can_submit_telemetry`, `auto_submits_telemetry`).
* **Changed**: Updated `ln-church-agent-mcp` metadata to explicitly declare its keyless, inspect-only nature.
* **Safety**: Added rigorous unit tests to ensure the MCP inspect entrypoint never calls the payment execution engine. No payment execution behavior or auto-telemetry logic was altered.

## [1.14.0] - 2026-06-23 (Paid Domain Observation Slot)
* **Added**: Introduced `register_domain_observation_slot` to purchase a 7-day public-safe observation run for a specified domain (x402 Paid Action).
* **Added**: Introduced public read models `get_domain_observation_request` and `get_domain_observation_read_model` to safely query the observation status and discovered surfaces.
* **Added**: Introduced internal observer APIs (`claim_domain_observation_targets`, `submit_domain_observation_result`) for observatory workers, strictly protected by `X-Internal-Secret`.
* **Added**: CLI commands `observe-domain` for paid registration/status, and `observatory` for internal worker operations.
* **Added**: Robust domain validation (`validate_public_domain_for_observation`) to prevent SSRF (blocking IPs, localhost, metadata endpoints).
* **Security**: Enforced strict `public-safe` constraints (GET/HEAD only, no forms, no login, no payment to target).
* **Architecture**: Clear separation between `requester_paid` and `domain_owner_verified`. The slot purchase does not imply domain ownership, endorsement, security scan, or certification (`not_a_verdict: true`).

## [1.13.0] - 2026-06-14 (Observation Provenance / Protocol Roles / Verification Cost Vector)
* Added public-safe `observation_provenance` metadata helpers.
* Added `protocol_roles` shape for role → protocol → capability observations.
* Added optional `verification_cost_vector` helper for sdk-reported, externally checkable cost counters.
* Added optional `protocol_roles` and `verification_cost_vector` fields to explicit observation submissions.
* Maintained v1.12.0 Reporter Identity Verification boundaries: no mandatory verification, no automatic hooks, no trust scoring, no recommendation/ranking.

## [Backend Compatibility Note] - 2026-06-08 (Reporter Identity Boundary Hardening)
* **Backend Update**: The SDK package remains `v1.12.0`. This update adds tests and documentation to verify compatibility with the latest Hon-den backend hardening.
* **Backend Hardening**: Explicitly persists `ReporterAgentId` across all telemetry metadata. Distinguishes `self_reported` from `unknown` when AgentProfiles lookups fail.
* **Backend Hardening**: Adds machine-readable safety boundaries (`verification_semantics="key_control_only"`, `not_a_trust_score=true`) to identity verify responses.
* **Docs/Tests**: Added regression tests ensuring `ensure_reporter_verification()` safely handles the new response flags without requiring a new SDK release.

## [1.12.0] - 2026-06-07 (Reporter Identity Verification Layer)
* **Added**: Introduced an optional, client-managed **Verifiable Reporter Identity Layer** to explicitly prove private key control behind an `agentId`.
* **Added**: Added `LnChurchClient.ensure_reporter_verification()` and `ensure_reporter_verification_async()` to automatically handle the full identity challenge-signature-verification lifecycle with in-memory caching.
* **Added**: Embedded reporter verification metadata inside all core telemetry frameworks (`GoalAttemptIngest`, `ExternalObserve`, and `FailureObserve`) to allow downstream registries to distinguish between anonymous and cryptographically verified claims.
* **Added**: Upgraded the Graph Ingestion engine (`AgentGraphSync`) to dynamically project `IdentityProof` nodes linked to the target agent via `HAS_IDENTITY_PROOF` edges.
* **Added**: Enriched S3 compact read models with `reporter_verification_mix` (inside `goal-attempt-summary.json`) and `verified_reporter_attempt_count` (inside `goal-surface-candidates.json`).
* **Safety**: Enforced strict non-mandatory boundaries; `self_reported` telemetry remains 100% functional and accepted. The layer proves key-control only, **never report truth or correctness**, and explicitly bypasses automated execution loops to prevent token drainage.

## [1.11.3] - 2026-06-03 (Experimental Intent Signature Observation Sidecar)
* **Added**: Experimental `intent_signature` and `classification_claims` sidecars for explicit Goal Attempt observations.
* **Safety**: No payment execution behavior changed. No automatic telemetry hooks added. Not a recommendation or stable taxonomy.

## [1.11.2] - 2026-06-03 (Grant-like Signal Detection Sidecar)
* **Added**: Inspect-only Grant-like signal detection appended as a sidecar to `InspectResult`.
* **Added**: Exposes `grant_signals` locally in the MCP `inspect_paid_surface` output.
* **Safety**: No payment execution behavior changed. No grant redemption, no marketplace, no auto-submission to Hon-den.

## [1.11.1] - 2026-05-31 (Auth-Capture Inspect-Only Standards Alignment)
* **Added**: Inspect-only classification for x402 `auth-capture` mapping it strictly to the x402 settlement rail.
* **Safety**: Absolute execution guard for `auth-capture` in `_process_payment()` ensuring no EIP-3009/Permit2 signatures are generated or executed.
* **Docs**: Capability matrix alignment and semantic glossary updates detailing that authorization signatures are not settlement proofs.
* **Maintained**: No payment execution behavior changed. Does not implement capture, void, refund, or reclaim lifecycles.

## [1.11.0] - 2026-05-31 (Surface Preflight Read Model Client)
* **Added**: `LnChurchClient.get_surface_preflight()` and `get_surface_preflight_async()` for safely reading historical observational memory of a surface before interacting with it.
* **Added**: Example script (`examples/surface_preflight_read_model.py`) and unit tests to ensure strict enforcement of safety boundaries.
* **Safety Boundaries**: No payment execution behavior was changed. The client explicitly uses isolated HTTP GET requests without engaging the `execute_detailed` HATEOAS or payment loop. Unknown surfaces safely return `known: false` without triggering HTTP 404s. The preflight result enforces `not_a_recommendation` and maintains the local runtime policy as the final authority.

## [1.10.2] - 2026-05-29 (Capability Matrix & Standards Watchlist Alignment)
* **Added**: Capability matrix documentation (`docs/07_capability_matrix.md`) mapping support boundaries and semantics.
* **Added**: Standards watch alignment documentation (`docs/08_standards_watch_alignment.md`) clarifying upstream drift monitoring.
* **Added**: `get_capability_matrix()` helper exposed safely in `ln_church_agent.capabilities` for tooling inspection.
* **Maintained**: No payment execution behavior changed. L402 / x402 / MPP / SVM exact behavior remains unchanged.
* **Maintained**: `batch-settlement` remains observe-only. AP2 / ACP / OKX APP remain inspect-only / guided-handoff surfaces. Goal Attempt telemetry remains explicit-only.

## [1.10.1] - 2026-05-22 (x402 Exact EVM Hotfix)
* **Fixed**: Prefer structured `PAYMENT-REQUIRED` over `WWW-Authenticate: x402` when both are present.
* **Fixed**: Resolve known token-address-only x402 exact assets (Base/Polygon USDC via case-insensitive matching, Solana USDC via strict case-sensitive Base58 matching).
* **Fixed**: Preserve raw `accepts[].amount` while exposing human-readable amount for policy checks.
* **Fixed**: Prevent raw/human amount double conversion in EIP-3009 exact payload generation.
* **Fixed**: Preserve structured challenge parameters such as `relayer_endpoint`.
* **Maintained**: L402 / MPP / Payment draft priority remains unchanged.
* **Maintained**: SVM exact raw transaction behavior remains unchanged.
* **Maintained**: `batch-settlement` remains observe-only.

## [1.10.0] - 2026-05-20 (Goal Attempt Observation & Memory)

* **Added**: Introduced `submit_goal_attempt_observation()` and `submit_goal_attempt_observation_async()` for explicitly archiving goal-conditioned agent traces.
* **Added**: Supports `goal_attempt.v1` payloads including goal declarations, attempt modes, free/paid/mixed steps, optional outcome assessments, and public-safe evidence metadata.
* **Added**: Supports unassessed attempts. If `outcome` is omitted, the trace is preserved without forcing success/failure semantics.
* **Added**: Lightweight Goal Attempt Memory read models allowing agents to query compact goal-scoped memory without downloading the full Monzen graph.
* **Added**: `get_goal_attempt_summary()` / async for free summary access.
* **Added**: `get_goal_surface_candidates()` / async for paid observed candidate surfaces.
* **Pricing**: Goal Attempt Summary is free. Goal Surface Candidates cost 1 SAT / 0.001 USDC / 1 JPYC. Premium full graph access remains completely unchanged.
* **Security**: Reuses strict local secret stripping while preserving public metadata such as `authorization_scheme`, `payment_performed`, and requirement fingerprints.
* **Behavior**: Goal Attempt submission is explicit-only and does not auto-hook into `execute_detailed()`.
* **Maintained**: Existing L402, x402, MPP, SVM, batch-settlement inspect-only, and external observation behaviors remain unchanged.

## [1.9.7] - 2026-05-19 (x402 Batch Settlement Inspect-Only Support)
* **Added**: Inspect-only awareness for x402 `batch-settlement` (a deferred settlement model separating request-time voucher authorization from batched onchain settlement).
* **Added**: Deferred settlement metadata (`settlement_model="deferred_batch"`, `authorization_artifact="voucher"`, etc.) to `SettlementOption` and propagates them into MCP observation payloads.
* **Security**: Explicitly blocks execution of `batch-settlement` in `_process_payment()`. The SDK safely stops without signing vouchers, depositing funds, or persisting channels.
* **Behavior**: Classifies batch settlement as `rail="x402"` with `execution_support="observe_only"`. Voucher artifacts are not treated as settlement proofs, maintaining `payment_performed=False` and `verification_status="unverified"` in observation payloads.
* **Maintained**: Existing L402, x402 exact, SVM exact, and MPP behaviors remain unchanged. `batch-settlement` is intentionally excluded from `SchemeType` and default `PaymentPolicy.allowed_schemes`.

## [1.9.6] - 2026-05-16 (Normalized Unmapped Observation Submission)
* **Added**: Introduced `submit_unmapped_observation()` and `submit_unmapped_observation_async()` for safely reporting unmapped or unknown payment surfaces to the observatory.
* **Added**: Automatically normalizes `payment_scheme_unmapped`, `unsupported_challenge_shape`, and `unknown_rail` into formal, public-safe External Observation payloads.
* **Security**: Enforces strict secret stripping (`_strip_secrets_from_evidence`) on any `extra_protocol` parameters passed to unmapped observations.
* **Behavior**: Unmapped observations are treated strictly as discovery signals (`payment_performed=False`, `verification_status="unverified"`), not payment proofs.
* **Behavior**: Default telemetry auto-submit remains conservative; explicit opt-in (e.g., `--include-unmapped`) is required to submit unmapped observation signals.
* **Maintained**: The `execute_request()` unsafe HATEOAS and cross-origin navigation guardrails (`NavigationGuardrailError`) remain fully intact.

## [1.9.5] - 2026-05-15 (Settlement Options Observation Layer)
* **Added**: Introduced `SettlementOption` model for granular tracking of all payment requirements presented by an endpoint.
* **Added**: `settlement_options` and `selected_settlement_option` fields to `InspectResult` for high-fidelity surface observation.
* **Added**: `ln_church_observatory` metadata to `InspectResult` and CLI output to clarify local observation boundaries and opt-in submission paths.
* **Improved**: The `inspect` tool now enumerates the full `accepts[]` array from x402 challenges without altering execution logic.
* **Improved**: MCP observation payloads now dynamically inherit network and asset details from selected options, reducing "unknown" fallbacks.
* **Improved**: Enhanced `missing_information` guidance for commerce surfaces (AP2/ACP/APP) when settlement rails are undeclared.
* **Documentation**: Clarified the role of the SDK as a non-executing paid surface observer and its relationship with the LN Church Observatory.

## [1.9.4] - 2026-05-14 (Payment Failure Observation Layer)
* **Added**: Introduced `PaymentFailureRecord` for structured local recording of 402 payment attempt failures.
* **Added**: Standardized failure taxonomy (e.g., `retry_mismatch`, `no_matching_payment_requirements`) to stabilize agent reasoning.
* **Added**: Public-safe challenge fingerprinting and changed-field detection to identify unstable server-side requirements (e.g., dynamic `feePayer`).
* **Added**: Payload builder for `payment_failure_observation_report.v1` for future knowledge base ingestion.
* **Security**: Guaranteed redaction of raw secrets (macaroons, preimages, private keys) from failure artifacts.
* **Behavior**: Non-verdict design; failures are modeled as "observed friction" rather than definitive server faults.

## [1.9.3] - 2026-05-12 (MCP Registry Namespace Fix)
* **Fixed**: Updated `mcp-name` metadata in README and `server.json` to use the `io.github.mayim-mayim` namespace, satisfying the Official MCP Registry ownership verification requirements.

## [1.9.2] - 2026-05-12 (Inspect-Only MCP Entrypoint)
* **Added**: Introduced inspect-only MCP entrypoint `ln-church-agent-mcp`.
* **Added**: Exposes safe MCP tools for paid surface inspection, action explanation, and MCP observation payload construction.
* **Security**: Does not require private keys or wallet configuration. Does not execute payments.
* **Maintained**: Existing L402/x402/MPP execution behavior and standard MCP execution server (`integrations.mcp`) remain strictly unchanged.

## [1.9.1] - 2026-05-11 (Guided Handoff for Agent Commerce Surfaces)
* **Added**: Introduced "Guided Handoff" to the `inspect` CLI command. When an Agent Commerce surface (AP2, ACP, OKX APP) is detected, the SDK now provides structured guidance (`ask_site_for`, `do_not`, `required_evidence`, `missing_information`) to help AI operators safely approve or investigate the transaction.
* **Added**: The `InspectResult` model now includes `handoff_mode`, `approval_required`, and `operator_approval_reason` to explicitly signal when human/operator intervention is necessary.
* **Security**: Implemented strict secret-stripping for `model_dump_json()`. Raw tokens (like `shared_payment_token`, `mandate_token`, or `broker` session keys) are safely redacted and never exposed in the inspection output.
* **Maintained**: Unchanged behavior for standard `L402`, `x402`, and `MPP` paths. Valid settlement rails will not trigger Guided Handoff unless they co-exist with a higher-order commerce surface.
* **Details**: [v1.9.1 Release Notes](docs/release_notes/v1.9.1.md)

## [1.9.0] - 2026-05-09 (AP2 / ACP Inspect-Only Commerce Surface Detection)
* **Added**: Expanded the Agent Commerce Surface Inspector to explicitly detect Google AP2 (Agent Payments Protocol) and ACP (Agentic Commerce Protocol) metadata.
* **Added**: Introduced `surface_type`, `surfaces_detected`, `settlement_rails_detected`, `detection_confidence`, `detection_reason`, and `unsupported_reason` to `InspectResult` for granular classification.
* **Changed**: Strictly decoupled Commerce Surfaces (AP2, ACP, OKX APP) from executable Settlement Rails (L402, x402, MPP). AP2/ACP metadata are treated strictly as authorization/commerce mandates, not settlement proofs.
* **Behavior**: Default `recommended_action` for AP2 and ACP is `observe_only`. The SDK intentionally **does not** execute these mandates.
* **Security**: Introduced a `stop_safely` guardrail if an AP2/ACP surface co-exists with a malformed or unsupported settlement hint.
* **Maintained**: 100% backward compatibility for existing L402, x402, and MPP execution behaviors.

## [1.8.5] - 2026-05-08 (Sandbox Evidence Corpus Readiness)
* **Added**: `SandboxCorpusCandidate` model to lightly transform sandbox execution evidence into a local candidate format.
* **Added**: `build_sandbox_corpus_candidate` helper to perform eligibility checks (e.g. `non_sandbox_scope`, `candidate_pending_client_confirmation`).
* **Added**: `client.get_last_sandbox_corpus_candidate()` and `client.build_sandbox_corpus_candidate_from_last_evidence()`.
* **Added**: Preserves rail metadata such as `network`, `asset`, `payment_method`, `authorization_scheme`, and `draft_shape` in corpus candidates.
* **Maintained**: Guaranteed no automatic submissions to `ExternalObserve` telemetry API to prevent Sandbox isolation leakage. Final corpus acceptance remains server-side.

## [1.8.4] - 2026-05-08 (Sponsored Access & Sandbox Evidence Alignment)
* **Added**: `SponsoredAccessEvidence` model to safely capture JWS grant consumption metadata (`grant_jti`, `issuer`, `scope`) with strict architectural constraints (`settlement_rail: "none"`).
* **Added**: `SandboxEvidence` model to capture isolated testbed telemetry from `sandbox_evidence_ref.v1` and `sandbox_evidence_report.v1`.
* **Added**: Optional fields `sponsored_access` and `sandbox` to `PaymentEvidenceRecord` for automatic EvidenceRepository exports.
* **Added**: Safe builder helpers and `sha256_redacted` to ensure raw `interop_token` and `grant_token` secrets are permanently excluded from JSON models and exports.
* **Added**: New public APIs including `get_last_sponsored_access_evidence()`, `get_last_sandbox_evidence()`, and `get_sandbox_evidence_logs()`.
* **Maintained**: Guaranteed no automatic submissions to `ExternalObserve` telemetry API to prevent Sandbox isolation leakage.

## [1.8.3] - 2026-05-08 (Sponsored Access Diagnostics)
* **Added**: Introduced `GrantDiagnostics` to locally pre-evaluate JWS grant tokens.
* **Added**: Added `diagnose_grant()` and `explain_grant()` to `LnChurchClient` for AI-friendly payload generation.
* **Added**: Added `ln-church-agent grant inspect` command to the CLI.
* **Clarified**: Formally decoupled Grants from settlement rails (`settlement_rail: "none"`).
* **Maintained**: Guaranteed graceful fallback behavior for invalid grants without interrupting the core L402/x402 loop.

## [1.8.2] - 2026-05-07 (Response Adapter Decompression Hotfix)
* **Fixed**: Resolved `httpx.DecodingError` during `inspect` by safely stripping hop-by-hop headers (`Content-Encoding`, `Transfer-Encoding`, `Content-Length`) from the response adapter.
* **Improved**: Ensures `inspect` fails gracefully with a structured `response_decoding_error` diagnostic instead of completely crashing the pipeline when upstream metadata is severely malformed.

## [1.8.1] - 2026-05-07 (Inspector Robustness & OpenClaw Stability)
* **Fixed**: Resolved execution environment dependencies for the `inspect` CLI. It now supports stable worker execution via direct Python API calls or `sys.executable`.
* **Improved**: Hardened the x402 challenge parser to capture non-standard shapes, such as Alchemy-style challenges that place `accepts` or `resource` fields directly within the JSON body.
* **Added**: Advanced classification logic for the `Payment` scheme, automatically mapping it to `MPP` or `x402` rails based on the provided `payment_method`.
* **Improved**: Enhanced `InspectResult` diagnostics by returning detailed `error_stage`, `failure_reason`, and `diagnostic_class` fields to facilitate automated system registration decisions.
* **Fixed**: Introduced `_safe_float` to prevent crashes when the `amount` field contains non-numeric strings or objects, ensuring they are safely handled as `0.0`.

## [1.8.0] - 2026-05-06 (Agent Commerce Surface Inspector & APP Detection)
* **Added**: Introduced the **Agent Commerce Surface Inspector** capability to the CLI `inspect` tool.
* **Added**: Safe detection for OKX Agent Payments Protocol (APP) metadata without payment execution.
* **Added**: Extensible commerce classification fields: `commerce_protocol`, `commerce_intent`, `commerce_transport`, `authorization_artifact`, `settlement_rail`, `settlement_method`, and `broker_required`.
* **Added**: Automated settlement rail normalization (e.g., mapping `scheme: exact` to `rail: x402`).
* **Behavior**: Challenge co-existence support. Can now detect both a Commerce layer and its underlying Settlement rail simultaneously (e.g., `rails_detected: ["APP", "x402"]`).
* **Architecture**: Aligned internal models with future Agent Commerce standards (Google AP2, ACP, UCP) as a buyer-side observation layer.
* **Maintained**: 100% backward compatibility for existing `L402`, `x402`, and `MPP` paths.
* **Details**: [v1.8.0 Release Notes](docs/release_notes/v1.8.0.md)

## [1.7.3] - 2026-05-03 (External Observation Client & x402 Exact Diagnostics)
* **Added**: `run_x402_evm_exact_sandbox_diagnostic()` and `run_x402_svm_exact_sandbox_diagnostic()` to test post-settlement validation of V2 exact envelopes.
* **Added**: `submit_external_observation()` and `get_external_observations()` for protocol-level telemetry, with strict local stripping of raw secrets.
* **Changed**: `parse_challenge_from_response` now strictly parses Hybrid V1+V2 challenge shapes, resolving `token_address`, `decimals`, and `accepts[].asset` accurately.
* **Changed**: `inspect` CLI command now recognizes `scheme: "exact"` and recommends `observe_only` to prevent unintended settlement loops.
* **Architecture**: Formalized that the current LN Church x402 exact sandbox acts as a *post-settlement validator*. Unbroadcasted payloads are intentionally rejected (Expected Rejection). True V2 exact settlement (where the facilitator broadcasts) is a future phase.
* **Details**: [v1.7.3 Release Notes](docs/release_notes/v1.7.3.md)

## [1.7.2] - 2026-04-30 (First Success UX - Inspect CLI)
* **Added**: Introduced the `inspect` CLI command to analyze HTTP 402 challenge structures (Rail, Intent, Shape) and provide recommended actions without executing payment.
* **Added**: Support for the short command alias `lnc-agent`.
* **Added**: `InspectResult` model for CLI analysis with first-class `--json` output support.
* **Added**: Stability tests for the CLI using mocked networks in `tests/test_cli_inspect.py`.
* **Details**: [v1.7.2 Release Notes](docs/release_notes/v1.7.2.md)

## [1.7.1] - 2026-04-30 (Agent-Side Synthetic Corpus Replay Runner)
* **Added**: `LnChurchClient.run_corpus_replay()` and async counterpart for dry-run validation of Server Synthetic Corpus Replays.
* **Added**: `CorpusReplayResult` model to encapsulate the comparison between `expected_action` and `observed_action`.
* **Details**: [v1.7.1 Release Notes](docs/release_notes/v1.7.1.md)

## [1.7.0] - 2026-04-29 (Official x402 v2 SVM Exact Path)
* **Added**: Native buyer-side runtime support for official x402 v2 SVM exact payments (`scheme: "exact"`, `network: "solana:<genesisHash>"`).
* **Added**: Native SVM Exact Transaction Builder to construct x402 v2 compatible VersionedTransaction payloads natively.
* **Added**: Optional `[svm]` and `[all]` extra dependency flags for `solana` and `solders` libraries.
* **Added**: `allowed_networks` constraint to `PaymentPolicy` for strict CAIP-2 gating.
* **Changed**: Legacy `lnc-solana-transfer` remains safely isolated as an LN Church compatibility path.
* **Details**: [v1.7.0 Release Notes](docs/release_notes/v1.7.0.md)

## [1.6.5] - 2026-04-29 (Challenge Parser Boundary Refactor)
* **Changed (Internal)**: Extracted HTTP 402 challenge parsing and Payment/MPP challenge shape classification into a dedicated internal module (`ln_church_agent/challenges.py`).
* **Compatibility**: Preserved `Payment402Client` compatibility wrappers. No public API changes were introduced, and all payment execution, settlement logic, and v1.6.4 telemetry behaviors remain strictly unchanged.
* **Details**: [v1.6.5 Release Notes](docs/release_notes/v1.6.5.md)

## [1.6.4] - 2026-04-29 (Payment Draft Telemetry & Interop Observation)
* **Added**: Payment HTTP Authentication draft-aware parsing. The SDK safely parses `Payment` scheme challenges and decodes Base64URL JSON requests to extract underlying invoices.
* **Added**: Advanced Interop Matrix telemetry for MPP. Challenges are now classified by `draft_shape` (e.g., `payment-auth-draft`, `legacy-mpp-flat`), `payment_method`, and `payment_intent`.
* **Changed**: MPP session intent is successfully observed and classified, but execution is safely halted (`mpp_session_not_supported_yet`) to prevent unverified runtime flows while still capturing the telemetry.

## [1.6.3] - 2026-04-27 (MPP Charge Sandbox Harness Integration)
* **Added**: Introduced `run_mpp_charge_sandbox_harness()` and `run_mpp_charge_sandbox_harness_async()` to `LnChurchClient` to seamlessly validate the IETF draft Machine Payments Protocol (MPP) flows.
* **Changed**: Upgraded Interop Report telemetry for *both* MPP and L402 harnesses to include dynamic protocol metadata (`rail`, `payment_intent`, `authorization_scheme`, `payment_receipt_present`), enhancing observability on the public Interop Matrix.
* **Fixed**: Replaced hardcoded authorization schemes in the Sandbox Harness with dynamic extraction from the `SettlementReceipt` to accurately absorb protocol fluctuations.
* **Added**: Introduced `test_v1_6_3_mpp_sandbox.py` to ensure regression protection for dynamic telemetry extraction.
* **Docs**: Updated Sandbox documentation and README to reflect the availability of the parallel MPP Charge endpoint.

## [1.6.2] - 2026-04-26 (x402 V2 Compatibility Improvements & Payload Normalization)
* **Added**: Support for transparent protocol extensions. The SDK captures server-provided extension metadata (like discovery configurations) and echoes it back in the settlement payload to facilitate upstream indexers.
* **Added**: Integrated standard `"exact"` scheme support into the core loop, formatting `PAYMENT-SIGNATURE` headers properly for gasless V2 settlements.
* **Changed**: Upgraded 402 challenge parsing to handle the x402 V2 `accepts` array structure, extracting matching network options based on the agent's expected `chainId`.
* **Fixed (Critical)**: Reconstructed the V2 `PAYMENT-SIGNATURE` envelope to match expected V2 hierarchy (`x402Version: 2`, `accepted`, `resource`, `payload`, `extensions`), resolving rejection loops.
* **Fixed (Critical)**: Resolved a fatal RPC failure in EVM transfers by replacing an invalid `eth_price` call with `eth_gasPrice` and properly padding raw transactions.
* **Fixed**: Implemented practical heuristics for unit normalization (Raw-to-Human), converting minimal-unit integers (e.g., Wei) to human-readable decimals to prevent false-positive blocks by local policies.
* **Fixed**: Enhanced treasury address (`payTo`) extraction from nested V2 structures and implemented safe fallbacks to expected logical symbols (USDC/JPYC) for raw contract addresses.
* **Details**: [v1.6.2 Release Notes](docs/release_notes/v1.6.2.md)

## [1.6.1] - 2026-04-24 (EVM Signature & CDP Compatibility Patch)
* **Added**: Enhanced `LnChurchClient` convenience methods (`draw_omikuji`, `submit_confession`, etc.) with `**kwargs` support for direct, seamless payload parameter injection (e.g., `chainId`).
* **Fixed**: Resolved `invalid_payload` failures in EVM gasless settlement (`lnc-evm-relay`) by extracting `r` and `s` signatures directly from the 65-byte hex string, guaranteeing strict 64-character zero-padding.
* **Fixed**: Added the missing `to` (treasury address) field to the relayer payload to ensure complete EIP-712 data transmission and full compatibility with strict verifiers like Coinbase CDP.
* **Fixed**: Explicitly included `chainId` in the relayer payload to enable seamless cross-chain gasless settlements (e.g., Base and Polygon) and prevent incorrect network defaulting.
* **Details**: [v1.6.1 Release Notes](docs/release_notes/v1.6.1.md)

## [1.6.0] - 2026-04-22 (Internal Access Selection & Refactoring)
* **Changed (Internal)**: Refactored the internal access selection loop for `LnChurchClient` by introducing strict Selector and Builder separation (`_ExecutionAccessPlan`, `_FundingPolicy`, etc.).
* **Compatibility**: Guaranteed 100% backward compatibility with the 1.5.x public API, concrete vocabulary (`GRANT_CREDIT`, `grant`, `faucet`), and wire-level protocol. 
* **Details**: [v1.6.0 Release Notes](docs/release_notes/v1.6.0.md)

## [1.5.12] - 2026-04-21 (Sponsored Access Override)
* **Added**: Introduced `set_grant_token()` to the `LnChurchClient` to hold a sponsor-issued JWS grant.
* **Added**: Implemented local JWT pre-evaluation (`has_valid_scoped_grant`) to verify expiration, audience, and route scopes client-side without cryptographic overhead.
* **Added**: Expanded `AssetType` with `GRANT_CREDIT` and `SchemeType` with `grant`.
* **Added**: `examples/use_grant_omikuji.py` to demonstrate the End-to-End sponsored access flow.
* **Changed**: Upgraded `draw_omikuji` and `draw_omikuji_async` to natively prioritize valid Grant tokens as a `paymentOverride`, gracefully falling back to legacy Faucet or standard 402 challenges if the token is invalid or expired.
* **docs(1.5.12)**: synchronize architecture roadmap with current STANDARDS_WATCHLIST and standards-tracking policy (no code changes)

## [1.5.11] - 2026-04-17 (Interop Matrix Separation & Live Diagnostics)
* **Added**: `comparison_class` and `test_mode` to Interop reports. Explicitly separates "Intentional Mismatches" (validation tests) from production errors in the ledger and UI.
* **Fixed**: Resolved an attribution bug where `executor_mode` (Native/Delegated) defaulted to Native during payment failures. Mode is now determined pre-execution.
* **Added**: Introduced diagnostic fields (`suspected_failure_origin`, `upstream_host_excerpt`) to `ExternalProtocolRunResult`. Enables heuristic identification of infrastructure errors like Cloudflare 520.
* **Added**: Implemented `run_external_protocol_verification` (Sync/Async) helpers for benchmarking live, unmanaged L402 endpoints.
* **Changed**: Extended LNBits settlement polling buffer from 1s to 5s to account for typical live Lightning Network routing latencies.

## [1.5.10] - 2026-04-16 (The Advisor & Final Judge Architecture)
* **Changed**: Refactored `RemoteTrustEvaluator` and `RemoteOutcomeMatcher` to act as final judges that synthesize remote advice with local agent policies, rather than blindly delegating decisions.
* **Added**: The LN Church backend now acts as an "Evidence-Rich Advisor", returning `recommendation`, `checks`, and `evidence_bundle` instead of centralized verdicts.
* **Changed**: Renamed `fallback_mode="unknown"` to `allow_on_error` in `RemoteTrustEvaluator` to accurately reflect its fail-open behavior.
* **Added**: Local policy overrides (e.g., `allowed_hosts`) and custom local fallback matchers now strictly supersede remote backend recommendations.

## [1.5.9] - 2026-04-15 (Evidence-Backed Session Budget Persistence)
* **Added**: Introduced `session_spend_delta_usd` to `PaymentEvidenceRecord` to capture immutable settlement budget events.
* **Added**: Expanded `EvidenceRepository` with `import_session_evidence` hooks to enable session budget recovery across agent crashes or restarts.
* **Added**: Built-in cryptographic deduplication using `receipt_id` to prevent double-counting of session budgets during HATEOAS recovery loops.
* **Changed**: Centralized the USD exchange rate logic into an internal `_estimate_usd_value` helper to ensure consistency across policy enforcement and evidence recording.
* **Changed**: Optimized the core execution loop (`execute_detailed` / `async`) to perform a lightweight, one-shot session budget restore prior to standard HATEOAS navigation.

## [1.5.8] - 2026-04-15 (Navigation Hint Normalization & Observability)
* **Added**: Introduced "Navigation Hint Normalization" to absorb HATEOAS vocabulary fluctuations (e.g., `next`, `action`, `retry_action`) and Header-based hints (`Location`, `Link`) into a canonical `NextAction` model.
* **Added**: Enhanced the observability layer by adding `navigation_source` to `PaymentEvidenceRecord`, allowing agents to audit the decision origin of HATEOAS recovery paths.
* **Changed**: Fortified Cross-Origin guardrails to use strict **netloc** (host:port) matching, preventing malicious redirections to unauthorized ports on trusted domains.
* **Changed**: Implemented "Header Hardening" to automatically isolate and strip sensitive credentials (e.g., `Authorization`) from server-suggested headers during autonomous navigation.
* **Fixed**: Eliminated redundant `asyncio.sleep(1)` from the asynchronous execution path to ensure wire-level performance parity between Sync and Async runtimes.
* **Fixed**: Synchronized the public API surface by exporting `ChallengeSource` and aligning `ParsedChallenge` with mandatory schema fields, resolving latent `NameError` in downstream validation tests. 

## [1.5.7] - 2026-04-14 (Documentation Alignment & Protocol Fluctuation Absorption)
* **Fixed (Docs)**: Resolved a documentation misalignment from v1.5.6 regarding the `Payment` and `MPP` header prefixes.
* **Changed**: Formally documented the SDK's dynamic protocol absorption capability. The client transparently supports both IETF Draft (`Payment`) and ecosystem (`MPP`) standards by dynamically constructing the `Authorization` header based on the server's `WWW-Authenticate` challenge, adhering perfectly to the Cold Spec governance.
* **Details**: [v1.5.7 Release Notes](docs/release_notes/v1.5.7.md)

## [1.5.6] - 2026-04-14 (Wire-Level Protocol Purity & Interface Sync)
* **Fixed**: Resolved a critical parsing paradox where `MPP` headers in `WWW-Authenticate` were ignored, ensuring proper dual-stack routing.
* **Fixed**: Restored protocol purity for Lightning payments (L402/MPP) by preventing `PAYMENT-SIGNATURE` and JSON body pollution, strictly using the `Authorization` header.
* **Fixed**: Synchronized the `EVMSigner` interface in `protocols.py` with the canonical v1.5.2 naming conventions to prevent `AttributeError` for custom wallet adapters.
* **Changed**: ~~Standardized the MPP authorization header output to use the `MPP` prefix instead of the legacy `Payment` prefix.~~ **(※RETRACTED IN v1.5.7: The SDK dynamically supports both `Payment` and `MPP` prefixes based on server requirements, rather than hardcoding. See v1.5.7 notes.)**
* **Details**: [v1.5.6 Release Notes](docs/release_notes/v1.5.6.md)

## [1.5.5] - 2026-04-13 (Dual-Stack Resilience & Initialization Fix)
* **Fixed**: Reordered 402 challenge parsing to prioritize Lightning (L402) over x402, resolving the "Dual-Stack Paradox" where L402 invoices were ignored. 
* **Fixed**: Normalized `ValueError` bubbling and corrected constructor argument propagation in `LnChurchClient`.
* **Fixed**: Improved the legacy challenge parser to fetch missing parameters (like destination) from the response body. 
* **Details**: [v1.5.5 Release Notes](docs/release_notes/v1.5.5.md)

## [1.5.4] - 2026-04-13 (Wire-Level Standard Compliance)
* **Changed**: Transitioned x402 payment headers from legacy string-concatenation to standard Base64URL-encoded JSON objects (Payment Payload / Payment Required / Settlement Response).
* **Fixed**: Improved `_parse_challenge` and `_extract_receipt` to prioritize Base64-encoded JSON parsing while maintaining backward compatibility with legacy string-based headers.
* **Added**: Native `_b64url_decode` and `_b64url_encode` helpers in the core client for robust payload handling.
* **Details**: [v1.5.4 Release Notes](docs/release_notes/v1.5.4.md)

## [1.5.3] - 2026-04-13 (x402 Standard Stabilization)
* **Fixed**: Resolved critical execution blockers (missing imports, `TypeError` in signature, `NameError` in policy enforcement) introduced during the 1.5.2 x402 Foundation alignment.
* **Fixed**: Restored legacy header parsers (`WWW-Authenticate`, `x-402-payment-required`) to ensure backward compatibility while migrating to standard x402.
* **Added**: Comprehensive strict-mode tests for the full `PAYMENT-REQUIRED` to `PAYMENT-RESPONSE` autonomous negotiation roundtrip.
* **Details**: [v1.5.3 Release Notes](docs/release_notes/v1.5.3.md)

## [1.5.2] - 2026-04-12 (x402 Foundation Alignment)
* **Changed**: Achieved full compliance with x402 Foundation (Linux Foundation) standards and CAIP-2 network identifiers.
* **Changed**: Updated `LnChurchClient` defaults to `L402` / `SATS`, prioritizing Lightning-native settlement.
* **Changed**: Normalized custom routing identifiers to the `lnc-` prefix (`lnc-evm-transfer`, `lnc-solana-transfer`, `lnc-evm-relay`).
* **Added**: Internal normalization layer (`_normalize_scheme`) for legacy scheme alias resolution to maintain backward compatibility.
* **Added**: Regression tests for standard compliance and convenience defaults.
* **Deprecated**: Legacy scheme Enum members (`x402-direct`, `x402-solana`).
* **Fixed**: Removed legacy vocabulary from specification artifacts (`openapi.yaml`, `agent-api.json`) and documentation.
* **Details**: [v1.5.2 Release Notes](docs/release_notes/v1.5.2.md)

## [1.5.1] - Experimental Evidence Export/Import Layer
* **Added**: `EvidenceRepository` base class with `export_evidence` and `import_evidence` hooks (sync/async).
* **Added**: `PaymentEvidenceRecord` to safely encapsulate the lifecycle of a 402 interaction (intentionally excluding secrets like preimages).
* **Changed**: Core execution engine automatically imports past evidence into `context.past_evidence` and exports records upon completion or failure.
* **Details**: [v1.5.1 Release Notes](docs/release_notes/v1.5.1.md)
* **Fixed**: Normalized `ValueError` bubbling during client initialization. Invalid private keys now consistently return a unified, predictable error message regardless of the underlying cryptographic adapter, squashing a latent initialization bug.

## [1.5.0] - Source-Agnostic Trust & Provider-Agnostic Outcome
* **Added**: `TrustEvidence` model to abstract trust evaluation inputs (URL, metadata, agent hints).
* **Changed**: `OutcomeMatcher` can now accept `SettlementReceipt` to perform cross-verification between the payment proof and the host's response.
* **Changed**: `ExecutionContext` now supports `hints` for passing top-down agent knowledge into hooks.
* **Compatibility**: Evaluators and Matchers written for v1.4 remain 100% backward compatible via dynamic signature inspection.
* **Details**: [v1.5.0 Release Notes](docs/release_notes/v1.5.0.md)

## [1.4.0] - Trust & Outcome Layer (Decide & Verify)
* **Added**: `TrustEvaluator` hooks to evaluate counterparty risk before payment.
* **Added**: `OutcomeMatcher` hooks to semantically verify expected outcomes after execution.
* **Added**: `ExecutionContext` for lightweight session and intent tracking.
* **Details**: [v1.4.0 Release Notes](docs/release_notes/v1.4.0.md)

## [1.3.1] - Async Performance & UX Patch
* **Fixed**: Reused `httpx.AsyncClient` to prevent socket exhaustion in high-frequency runtimes.
* **Fixed**: Replaced silent identity fallback with explicit `ValueError` on bad private keys.
* **Details**: [v1.3.1 Release Notes](docs/release_notes/v1.3.1.md)

## [1.3.0] - Safety & Stability Overhaul
* **Fixed**: `PaymentPolicy` type safety and precise session budget accounting.
* **Added**: Backward compatibility wrapper for `execute_paid_action`.
* **Details**: [v1.3.0 Release Notes](docs/release_notes/v1.3.0.md)

## [1.2.x] - Economic Guardrails & Risk Verification
* Introduced `PaymentPolicy` limits, `SettlementReceipt` generation, and Keyless Agent execution via `NWCAdapter`. Added MCP tools for Counterparty Risk Verification.
* **Details**: [v1.2.5](docs/release_notes/v1.2.5.md), [v1.2.4](docs/release_notes/v1.2.4.md), [v1.2.3](docs/release_notes/v1.2.3.md)

## [1.1.0] - Dynamic EVM Auto-Routing
* Enhanced `x402` schemes with Dynamic Multi-Chain Auto-Routing and Solana Standards alignment.

## [1.0.0] - Initial Stable Release
* Introduced the autonomous `Probe → Pay → Execute` loop across `L402`/`MPP` (Lightning), `x402` (Polygon), and `x402-solana` (Solana).