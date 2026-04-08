# Architecture & Core Capabilities

The `ln-church-agent` SDK is designed to handle the complex "Settlement Negotiation" process triggered by HTTP 402 errors.
It abstracts machine-to-machine (M2M) payments, allowing AI agents to focus on reasoning rather than cryptographic transaction handling.

## 🧩 Technical Abstractions

This SDK natively manages the following layers to ensure seamless autonomous economic activity:

### 1. Multi-Protocol Settlement Layers
The client automatically intercepts 402 challenges and negotiates payment across different networks:
* **x402 (EVM Gasless)**: Handles autonomous EIP-712 and EIP-3009 signing combined with relayer orchestration. Features **Dynamic Multi-Chain Auto-Routing**—the agent reads the `chain_id` and contract addresses provided in the HATEOAS challenge and dynamically adapts its signatures to the target EVM network (e.g., Polygon, Base) on the fly, with minimal client-side configuration.
* **x402-solana (Solana Mainnet)**: Natively constructs, signs, and broadcasts SPL Token (USDC) transfers via the Solana RPC. *(Requires the `[solana]` extra)*.
* **L402 & MPP (Lightning Network)**: Fully compatible with Lightning Labs' L402 protocol and the emerging Machine Payments Protocol (MPP). It manages macaroon extraction, Bolt11 invoice parsing, and preimage submission.
*Note on Solana:* The `x402-solana` settlement scheme is currently exclusive to the Resonance Graph export and strictly supports **USDC only**. Ensure you have installed the extra dependencies (`pip install ln-church-agent[solana]`).

### 2. Zero-Balance Fallback (Faucet)
To prevent agent stalls due to lack of funds, the SDK includes automatic claim-and-bypass logic. It utilizes a strict `paymentOverride` schema to request temporary credits from a Faucet when necessary.

### 3. Safe HATEOAS Auto-Navigation
The engine autonomously follows `next_action` links provided in 4xx/5xx HATEOAS errors.
* **Guardrails**: It includes built-in protections such as maximum hop counts and restrictions on unsafe HTTP methods to prevent infinite loops or unintended state mutations.

### 4. Decentralized Paywall DNS (Monzen)
New in version 1.1.0, the SDK allows agents to interact with a global registry of L402-protected APIs. Agents can:
* **Discover and Report**: Map the web by scouting new paywalls.
* **Consume Intelligence**: Spend SATS to unlock premium intelligence from the network.

### 5. Strongly Typed Responses
Every API interaction is modeled using Pydantic. This eliminates "cryptographic hallucinations" where an agent might misinterpret raw JSON, ensuring the agent's internal state remains grounded and accurate.
---