# Architecture & Core Capabilities

The `ln-church-agent` SDK is designed to handle the complex "Settlement Negotiation" process triggered by HTTP 402 errors.
It abstracts machine-to-machine (M2M) payments, allowing AI agents to focus on reasoning rather than cryptographic transaction handling.

## 🧩 Technical Abstractions

This SDK natively manages the following layers to ensure seamless autonomous economic activity:

### 1. Multi-Protocol Settlement Layers

The client automatically intercepts 402 challenges, executes supported payment rails, and safely inspects or halts on non-executable shapes:

* **x402 (Standard Path)**: Natively handles the standard x402 settlement contract, including Base64URL JSON payloads and CAIP-2-aware routing in the core negotiation loop. The strongest validated standard path today is EVM-based settlement (EIP-712 / EIP-3009), while LN Church-specific `lnc-*` routes remain available for optimized relay and ecosystem-specific flows.
* **SVM exact (Solana)**: The client recognizes CAIP-2 `solana:<genesisHash>` exact challenges, but canonical high-level sync/async auto-payment is inspect-only and fail-closed. Recent-blockhash validity cannot be mechanically proven to end at or before canonical Unix `expires_at`, so the runtime halts before signer invocation, Solana RPC access, or the paid HTTP retry.
  * **Architecture Boundary:** The retained local builder and validator are low-level payload construction and interoperability tooling only. They emit and validate official-format `VersionedTransaction` payloads but do not make the canonical high-level lane executable. LN Church exact sandboxes remain *post-settlement validators*: they accept submitted transaction hash or Solana signature evidence and do not broadcast unsubmitted payloads.
* **L402 & MPP (Lightning Network)**: Fully compatible with Lightning Labs' L402 protocol and the emerging Machine Payments Protocol (MPP). It manages macaroon extraction, Bolt11 invoice parsing, and preimage submission.
* **LN Church Optimized Routings (`lnc-*`)**: For interacting specifically with the LN Church testbed, agents can opt-in to custom canonical routes:
  * `lnc-evm-relay`: Optimized gasless relayer orchestration.
  * `lnc-evm-transfer`: Direct on-chain EVM transfers.
  * `lnc-solana-transfer`: Natively constructs, signs, and broadcasts SPL Token (USDC) transfers via the Solana RPC. *(Requires the `[solana]` extra)*.

### 2. Economic Guardrails (v1.15+)
Autonomous agents can hallucinate or be subjected to malicious HATEOAS redirects. The `PaymentPolicy` engine intercepts every 402 challenge *before* payment execution.
* Evaluates requested `scheme` and `asset` against allowed lists.
* Calculates estimated USD value and blocks transactions exceeding `max_spend_per_tx_usd`.
* Tracks cumulative session spending and enforces `max_spend_per_session_usd` to prevent budget exhaustion across multiple HATEOAS navigations or loops.
* **Strict Amount & Token Validation (v1.16.2+)**: BOLT11 invoices are strictly decoded to verify exact SATS amounts before hitting the wallet. For x402 exact payloads, unknown EVM/SVM token contracts are safely rejected, and wire-level atomic amounts are enforced to prevent float-rounding manipulation.
* **Double-Payment Prevention (v1.16.2+)**: Enforces a strict one-irreversible-payment lock per execution context, halting infinite `402 -> pay -> 402` drain loops and preserving `Idempotency-Key` tracking.

**Internal Access Selection (v1.15+)**: The SDK internally isolates "Access Selection" (choosing between Grants, Faucets, or Direct Settlement) from the wire-level payload building. This ensures future pricing models like subsidies can be added without altering the public execution API.

### 3. Verifiable Settlement Receipts (v1.15+)
After a successful 402 negotiation, the SDK generates a `SettlementReceipt`. This allows the LLM agent to record its expenditures internally.
* Contains `receipt_id`, `scheme`, `settled_amount`, and `proof_reference`.
* Includes a `verification_status` to distinguish between cryptographically verified payments (e.g., L402 preimages) and self-reported blockchain hashes.
* The SDK can already extract receipt artifacts from `PAYMENT-RESPONSE` bodies and `Payment-Receipt` headers when they are present. However, upstream cache semantics and retry semantics around receipts remain an actively monitored standards-tracking area rather than a frozen 1.15.x public contract.

### 4. Zero-Balance Fallback (Faucet)
To prevent agent stalls due to lack of funds, the SDK includes automatic claim-and-bypass logic. It utilizes a strict `paymentOverride` schema to request temporary credits from a Faucet when necessary.

### 5. Safe HATEOAS Auto-Navigation
The engine autonomously follows `next_action` links or HTTP Redirects (`301`/`302`/`307`/`308`) provided in 4xx/5xx HATEOAS errors.
* **Guardrails**: It includes built-in protections such as maximum hop counts and absolute restrictions on unsafe method conversions.
* **Cross-Origin Integrity (v1.16.2+)**: Automatic HTTP redirects are handled manually. If an agent is redirected to a new domain (Cross-Origin), sensitive credentials (`Authorization`, `Cookie`, `macaroon`, `preimage`, private keys) are aggressively stripped before the transition to prevent credential leakage. HTTPS-to-HTTP downgrades are unconditionally blocked.

### 6. Decentralized Paywall DNS (Monzen)
The SDK allows agents to natively interact with a global registry of L402-protected APIs. Agents can:
* **Discover and Report**: Map the web by scouting new paywalls.
* **Consume Intelligence**: Spend SATS to unlock premium intelligence from the network.

### 7. Strongly Typed Responses
Every API interaction is modeled using Pydantic. This eliminates "cryptographic hallucinations" where an agent might misinterpret raw JSON, ensuring the agent's internal state remains grounded and accurate.

### 8. Trust & Outcome Layer (v76+)
To enable truly autonomous M2M economic loops, the SDK provides a "Decide & Verify" architecture via thin hooks. This allows agents to evaluate the counterparty *before* payment, and verify the semantic result *after* execution, without relying on heavy workflow engines.

* **Counterparty Trust Layer (`TrustEvaluator`)**: Intercepts the HTTP 402 challenge. You can inject custom logic to verify if the host, required payment, or past interactions meet your safety criteria before committing funds. If the evaluator returns a `TrustDecision` with `is_trusted=False`, the SDK aborts the transaction and raises a `CounterpartyTrustError`.
* **Outcome Verification Layer (`OutcomeMatcher`)**: Intercepts the HTTP 2xx response. Evaluates the actual business data returned to determine if the expected "Outcome" was achieved, generating an `OutcomeSummary` that is attached to the final `ExecutionResult`.

**Example Usage:**
```python
from ln_church_agent import Payment402Client
from ln_church_agent.models import TrustDecision, OutcomeSummary

# Decide: Evaluate the counterparty before paying
def strict_evaluator(url, challenge, context):
    if "unverified" in url:
        return TrustDecision(is_trusted=False, reason="Unverified Host")
    return TrustDecision(is_trusted=True)

# Verify: Check if the response contains the expected intelligence
def data_matcher(response, context):
    success = "premium_data" in response
    return OutcomeSummary(is_success=success, observed_state="Data Extracted")

client = Payment402Client(
    base_url="https://api.example.com",
    trust_evaluators=[strict_evaluator]
)

# Execute the request with an outcome matcher
result = client.execute_detailed(
    method="POST",
    endpoint_path="/data",
    outcome_matcher=data_matcher
)

print(f"Receipt Status: {result.settlement_receipt.verification_status}")
print(f"Outcome Status: {result.outcome.is_success}")
```
### 9. L402 Delegated Execution (v1.15+)

The SDK natively parses and settles L402 challenges via standard `LightningProvider` adapters.
It also exposes a delegate-compatible `L402Executor` interface, allowing the execution layer to be swapped or compared against external L402 executors.

The bundled `LightningLabsL402Executor` is an experimental compatibility simulator: it reproduces the expected behavior of external delegated L402 executors, including MAC reuse, token caching, and BOLT11 fulfillment, but it does not directly vendor or wrap Lightning Labs' official `L402sdk`.

This architecture respects separation of concerns: the **Executor (Delegate)** handles settlement mechanics and cache behavior, while `ln-church-agent` remains the **Buyer-Side Final Judge** for spend limits, trust evaluation, outcome verification, and evidence generation.

### 10. Agent Commerce Surface Inspection (v1.15+)
The SDK formally distinguishes between **Executable Settlement Rails** (e.g., L402, x402, MPP) and higher-order **Agent Commerce Surfaces** (e.g., Google AP2, ACP, OKX APP).

* **Inspect-Only Principle**: The SDK can detect authorization mandates (AP2 `payment_mandate`), delegated checkout tokens (ACP `agentic_checkout`), and broker metadata. However, it treats them strictly as observable surfaces. It defaults to `observe_only` or `stop_safely` and does **not** execute these higher-order protocols natively.
* **Rail Co-existence & Safety**: If a 402 challenge contains both an AP2 mandate and an x402 payment hint, the SDK parses both (`surfaces_detected: ["AP2"]`, `settlement_rails_detected: ["x402"]`). To prevent unauthorized mandate signing or checkout completion, the SDK prioritizes the commerce surface guardrail and suppresses automatic execution.

---

## 🔮 Future Protocol Evolution (Monitoring & Roadmap)
*(As of April 21, 2026 — synced with `STANDARDS_WATCHLIST.md`)*

The `ln-church-agent` SDK is designed to absorb standards drift behind a stable developer-facing interface.  
The following items are already treated as implemented in the current 1.15.x line:

- x402 Foundation alignment and CAIP-2-aware core negotiation
- Base64URL JSON handling for standard x402 payment headers
- Dynamic `Payment` / `MPP` parsing for evolving IETF draft semantics

The items below are **not** treated as frozen public contract yet. They remain under active monitoring because the upstream ecosystem is still moving and premature abstraction would create unnecessary public API risk.

### Watch Now

### 1. Payment-Receipt Semantics & Cache Rules
* **Observation:** The IETF payment draft is expanding beyond prefix negotiation and is clarifying `Payment-Receipt` semantics, retry expectations, and cache behavior around `402`, `401`, and `403` flows.
* **SDK Stance:** The SDK already extracts receipt artifacts when provided, but cache-control behavior and receipt-driven retry semantics are still monitored rather than hard-coded into the stable public contract.
* **Why Deferred:** The draft is still evolving, and real ecosystem implementations are not yet fully converged.

### 2. x402 Bazaar / Discovery & MCP Compatibility
* **Observation:** API discovery, MCP-native payment surfaces, and facilitator-aware runtime metadata are evolving quickly across the x402 ecosystem.
* **SDK Stance:** `ln-church-agent` currently supports its own reference discovery path (Monzen / LN Church) and ecosystem-specific relays, while treating Bazaar / MCP compatibility as a monitored interoperability surface rather than a fixed contract.
* **Why Deferred:** Discovery and MCP payment conventions are still stabilizing, and locking a public abstraction too early would create avoidable churn.

### Design Prep

### 3. Payment Identifier (Idempotency)
* **Observation:** Upstream x402 discussions are moving toward stronger duplicate-settlement protection and idempotency-friendly payment correlation.
* **SDK Stance:** The current 1.15.x line already reduces practical risk via evidence-backed receipt deduplication, but does not yet expose a dedicated standard Payment Identifier abstraction.
* **Why Deferred:** Existing receipt-based safety is sufficient for now, and the exact standard surface is not yet final.

### 4. Offer Receipt (Pre-settlement Agreement)
* **Observation:** The ecosystem may split pre-settlement agreement proofs from post-settlement receipts.
* **SDK Stance:** This would primarily affect the boundary between Trust evaluation, Outcome verification, and structured proof handling.
* **Why Deferred:** This is not yet a widely deployed gateway pattern, so introducing a stable API now would be premature.

### 5. Session Intent (MPP / x402)
* **Observation:** Stateful session-based payment flows are being explored to reduce repeated settlement overhead in continuous inference loops (e.g., `intent="session"` in Payment drafts).
* **SDK Stance:** As of v1.15.x, the SDK actively parses, detects, and reports session intents to the Interop Matrix for telemetry purposes. However, it safely halts execution (`mpp_session_not_supported_yet`) rather than attempting unverified stateful credential generation.
* **Why Deferred:** The wire-level challenge format and credential generation logic are not yet stable enough to standardize a robust buyer-side execution loop.

### 6. L402 Token Attenuation
* **Observation:** Multi-agent or delegated agent flows may eventually require caveat-based restriction and re-delegation of L402 capabilities.
* **SDK Stance:** This is recognized as a future extension area for delegated Lightning execution, but remains out of scope for the current single-agent stable line.
* **Why Deferred:** It is still over-spec for the current reference runtime and would add complexity without near-term interoperability benefit.

### Practical Guidance for 1.15.x Users
If you are building on `ln-church-agent` today, you should treat the current stable contract as:
- standard x402 / L402 / Payment / MPP negotiation
- stable developer-facing execution loop
- fallback-compatible legacy absorption where needed
- **Inspect-only observation for AP2, ACP, and OKX APP surfaces**

You should **not** assume that receipt cache semantics, Bazaar discovery metadata, full MPP Session execution channels, or AP2/ACP mandate executions are finalized public APIs in the current 1.15.x line. They are actively observed and classified, but not yet fully executed.

---
