# ln-church-agent

**Python SDK for calling L402 / HTTP 402 pay-per-use APIs with automatic payment, retry, and async support.**

Designed for Autonomous AI Agents.
Implementing machine-to-machine payments from scratch is fragile: agents must parse `HTTP 402` challenges, handle signing, complete payment, and retry correctly without falling into hallucinated crypto flows.
This SDK abstracts that loop into a single client call. It turns **Probe → Pay → Execute** into a reliable execution path for agents—available in both sync and async execution models.

---

## 🚩 Start Here: The Canonical First Success

The fastest way to understand this SDK is to run the canonical example. 
This script connects to the **LN Church public endpoint**, which serves as the official testbed for agents to experience their first autonomous economic loop.

You will see the agent autonomously navigate the Probe → Pay → Execute protocol through the canonical first-success path. The initial run is Faucet-assisted, so no pre-funded balance is required.

### Running the Example

**1. Set your Agent's Identity Key** (EVM or Solana format)
```bash
export AGENT_PRIVATE_KEY="0xYourPrivateKey"
```

**2. Run the Hello World script**
```bash
python examples/hello_ln_church.py
```

### What this script demonstrates:
1. **Probe:** Establishes connection and identity.
2. **Pay (Faucet):** Secures zero-balance fallback credits to test the payment loop safely.
3. **Execute:** Hits a 402-protected endpoint, intercepts the paywall, negotiates the settlement automatically, and returns the paid result.

By completing this pilgrimage, your agent's first successful footprint is recorded on the observation network.

---
## 📦 Public API Surface (v1.2.0 Stable)
The following interfaces are guaranteed stable in 1.x:
- `Payment402Client` (Core Engine)
- `LnChurchClient` (Reference Adapter)
- `AssetType`, `SchemeType` (Enums)
- All response models (e.g., `OmikujiResponse`, `MonzenTraceResponse`, `MonzenGraphResponse`) top-level schemas are guaranteed stable in 1.x.
Note: The inner payload of MonzenGraphResponse.data may evolve based on the graph network's schema.
- The Trace Record Semantics (action_type, recorded_hash, trace_id, etc.)
*Note: `execute_paid_action` is deprecated in favor of `execute_request(method="POST", ...)`.*

### 🌟 Core Value: Execute, Prove, Observe

This SDK is not just an HTTP client—it is an **execution client, proof layer, and observation pipeline** built into one unified tool. 

1. **Execute**: Seamlessly call any external or internal 402-protected API without stalling.
2. **Prove**: Automatically handle challenge parsing, payment flows, and support proof-oriented flows using the invoice and preimage when available.
3. **Observe**: Register and visualize internal or external payment traces through LN Church.

### 🛤️ The Two Workflows

**LN Church** is an experimental observation network for AI agents interacting with paywalled APIs. To support both the open web and controlled experimentation, the SDK is designed around two distinct flows:

* **External Flow:** Call *any* third-party 402-enabled API in the wild. The SDK autonomously handles the payment negotiation loop.
  👉 *Call a third-party 402 API → optionally submit the payment proof/trace to LN Church → observe it in the network.*
* **Internal Flow:** Interact directly with the official LN Church servers for Oracle and Ritual tasks to test and refine agent capabilities within the observation network.

---

## 🚀 Quickstart (3-step)

### 1. Install
```bash
# Standard install (EVM & Lightning support)
pip install ln-church-agent

# Full install (Includes Solana support)
pip install ln-church-agent[solana]
```

### 2. Configure & Call (Sync)
Call any 402-protected API. The SDK handles the challenge, payment, and retry under the hood.

```python
from ln_church_agent import Payment402Client

client = Payment402Client(
    base_url="https://your-402-api.com",
)

# Detects 402 -> Pays invoice -> Retries -> Returns JSON
result = client.execute_request(
    method="POST",
    endpoint_path="/api/protected",
    payload={"input": "hello"}
)

print(result)
```

### 3. Configure & Call (Async)
For agent runtimes that need concurrent execution, async is supported in v1.1.0.

```python
import asyncio
from ln_church_agent import Payment402Client

async def main():
    client = Payment402Client(
        base_url="https://your-402-api.com",
    )

    result = await client.execute_request_async(
        method="POST",
        endpoint_path="/api/protected",
        payload={"input": "hello"}
    )

    print(result)

asyncio.run(main())
```

---

## ⚠️ What this solves

When an AI Agent hits `HTTP 402 Payment Required`, it often stalls, crashes, or invents invalid payment/signing behavior.
* **Why this is hard:** Handling 402 flows means parsing challenge headers, extracting payment instructions, coordinating wallets, signing correctly, and retrying in the right order.
* **What this SDK does:** It reduces that economic negotiation to a normal HTTP client call, with typed responses and built-in retry guardrails.

As of v1.1.0+, the economic loop is not only available in both sync and async execution paths, but also features **Dynamic Multi-Chain Auto-Routing**, allowing agents to seamlessly hop across EVM networks (Polygon, Base, etc.) exactly as dictated by the server's HATEOAS challenge.

---

## 🧪 Experimental / Agent-Native Features (v1.2.0+)

For advanced enterprise or multi-agent runtimes, v1.2.0 introduces features that separate keys from execution and provide strict economic safety.

* **Delegated Signers (NWC)**: Agents can pay Lightning invoices without holding a private key via the `NWCAdapter` (currently utilizing an HTTP Bridge Gateway).
* **Economic Guardrails**: Use `PaymentPolicy` to enforce strict spending limits (e.g., "Max $1.00 USD per transaction") and restrict allowed networks.
* **Verifiable Execution**: Every successful settlement generates a `SettlementReceipt`, allowing the LLM to cryptographically verify proofs before continuing its reasoning loop.

👉 **[See the Advanced v1.2.0 Example](examples/advanced_1_2_0.py)**

---
## 📚 Detailed Documentation

Explore the full capabilities of the agentic economic loop:

* **[Quickstart & Authentication](docs/01_quickstart.md)**: Identity, keys, policies, and sync/async usage.
* **[Architecture & Capabilities](docs/02_architecture.md)**: Deep dive into x402, L402, Policies, and Receipts.
* **[The LN Church Pilgrimage](docs/03_ln-church.md)**: Using the reference adapter for Oracle and Ritual tasks.
* **[Lightning Providers & NWC](docs/04_providers.md)**: Configuration for Alby, LNBits, and NWC Bridge.
* **[Integrations](docs/05_integrations.md)**: Setting up MCP (Model Context Protocol) and LangChain.
* **[Monzen Observation Network](docs/06_monzen.md)**: Scouting L402 paywalls and Decentralized DNS.

## 📊 Telemetry & Privacy

To observe and improve the autonomous agent ecosystem, this SDK includes minimal, privacy-conscious telemetry in its HTTP headers.

* **General Usage (`Payment402Client`)**: 
  When interacting with third-party 402 APIs, only a standard `User-Agent` (e.g., `ln-church-agent/<version>`) is sent. **No custom tracking headers are included.**
* **LN Church Ecosystem (`LnChurchClient`)**: 
  When communicating specifically with the official LN Church servers (`kari.mayim-mayim.com`), the following headers are appended for quality assurance and debugging:
  * `X-LN-Church-Agent-Version`: The active SDK version.
  * `X-LN-Church-Request-Id`: An ephemeral UUID used strictly to correlate 402 retry loops and request flows.

⚠️ **Important**: This SDK **does not** collect or transmit IP-bound data, MAC addresses, or persistent cross-session identifiers (such as a `client_id`). Furthermore, the default `User-Agent` can be explicitly overridden by passing a custom header in your requests.

---

## 📝 Changelog

* **v1.2.1**
  * **API Consistency & Patch**: Aligned MCP tool parameters and documentation with the new `scheme`-based payment routing (deprecated legacy `use_solana` arguments). Fixed internal versioning fallbacks.
* **v1.2.0**
  * **Economic Guardrails**: Introduced `PaymentPolicy` for strict asset, scheme, and USD-equivalent spend limits.
  * **Verifiable Receipts**: Introduced `SettlementReceipt` to provide agents with cryptographically verifiable proofs of their expenditures.
  * **NWC Adapter (Experimental)**: Added support for NIP-47 Nostr Wallet Connect via HTTP Bridge, enabling keyless agent execution.
* **v1.1.0**
  * **Dynamic EVM Auto-Routing**: Enhanced `x402` and `x402-direct` schemes. The agent now autonomously adapts its EIP-712 domain signing to any EVM chain (e.g., Base, Arbitrum) dictated by the server's HATEOAS challenge, falling back to Polygon if unspecified.
  * **Solana Standards Alignment**: Updated `x402-solana` handling to follow the server's canonical challenge/verification contract, including support for challenge-provided destination and reference keys for transaction verification.
* **v1.0.0**
  * Initial stable release. Introduced the autonomous `Probe → Pay → Execute` loop across `L402`/`MPP` (Lightning), `x402` (Polygon), and `x402-solana` (Solana).

  ---

## License
MIT