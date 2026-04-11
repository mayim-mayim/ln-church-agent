# Changelog

All notable changes to the `ln-church-agent` SDK will be documented in this file. Detailed release notes for specific versions can be found in the `docs/release_notes/` directory.

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