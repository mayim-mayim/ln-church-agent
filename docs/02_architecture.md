# Architecture & Core Capabilities

The `ln-church-agent` SDK is designed to handle the complex "Settlement Negotiation" process triggered by HTTP 402 errors.
It abstracts machine-to-machine (M2M) payments, allowing AI agents to focus on reasoning rather than cryptographic transaction handling.

## 🧩 Technical Abstractions

This SDK natively manages the following layers to ensure seamless autonomous economic activity:

### 1. Multi-Protocol Settlement Layers
The client automatically intercepts 402 challenges and negotiates payment across different networks:
* **x402 (EVM Gasless & Direct)**: Handles autonomous EIP-712 and EIP-3009 signing combined with relayer orchestration, or direct on-chain transfers. Features **Dynamic Multi-Chain Auto-Routing**—the agent reads the `chain_id` and contract addresses provided in the HATEOAS challenge and dynamically adapts its signatures to the target EVM network (e.g., Polygon, Base) on the fly, with minimal client-side configuration.
* **x402-solana (Solana Mainnet)**: Natively constructs, signs, and broadcasts SPL Token (USDC) transfers via the Solana RPC. *(Requires the `[solana]` extra)*.
* **L402 & MPP (Lightning Network)**: Fully compatible with Lightning Labs' L402 protocol and the emerging Machine Payments Protocol (MPP). It manages macaroon extraction, Bolt11 invoice parsing, and preimage submission.
*Note on Solana:* The `x402-solana` settlement scheme is currently exclusive to the Resonance Graph export and strictly supports **USDC only**. Ensure you have installed the extra dependencies (`pip install ln-church-agent[solana]`).

### 2. Economic Guardrails (v1.3+)
Autonomous agents can hallucinate or be subjected to malicious HATEOAS redirects. The `PaymentPolicy` engine intercepts every 402 challenge *before* payment execution.
* Evaluates requested `scheme` and `asset` against allowed lists.
* Calculates estimated USD value and blocks transactions exceeding `max_spend_per_tx_usd`.
* Tracks cumulative session spending and enforces `max_spend_per_session_usd` to prevent budget exhaustion across multiple HATEOAS navigations or loops.


### 3. Verifiable Settlement Receipts (v1.3+)
After a successful 402 negotiation, the SDK generates a `SettlementReceipt`. This allows the LLM agent to record its expenditures internally.
* Contains `receipt_id`, `scheme`, `settled_amount`, and `proof_reference`.
* Includes a `verification_status` to distinguish between cryptographically verified payments (e.g., L402 preimages) and self-reported blockchain hashes.

### 4. Zero-Balance Fallback (Faucet)
To prevent agent stalls due to lack of funds, the SDK includes automatic claim-and-bypass logic. It utilizes a strict `paymentOverride` schema to request temporary credits from a Faucet when necessary.

### 5. Safe HATEOAS Auto-Navigation
The engine autonomously follows `next_action` links provided in 4xx/5xx HATEOAS errors.
* **Guardrails**: It includes built-in protections such as maximum hop counts and restrictions on unsafe HTTP methods to prevent infinite loops or unintended state mutations.

### 6. Decentralized Paywall DNS (Monzen)
The SDK allows agents to natively interact with a global registry of L402-protected APIs. Agents can:
* **Discover and Report**: Map the web by scouting new paywalls.
* **Consume Intelligence**: Spend SATS to unlock premium intelligence from the network.

### 7. Strongly Typed Responses
Every API interaction is modeled using Pydantic. This eliminates "cryptographic hallucinations" where an agent might misinterpret raw JSON, ensuring the agent's internal state remains grounded and accurate.

### 8. Trust & Outcome Layer (v1.4+)
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
---