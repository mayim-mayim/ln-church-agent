# Changelog

All notable changes to the `ln-church-agent` SDK will be documented in this file. Detailed release notes for specific versions can be found in the `docs/release_notes/` directory.

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