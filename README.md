# ln-church-agent
**The Standard HTTP 402 SDK & Agentic Payment Runtime**

**The runtime is generic. The shrine is the proving ground.**

This repository serves a dual purpose:
1. **General-Purpose HTTP 402 Runtime:** A robust client for autonomous AI agents to discover, pay, verify, and observe HTTP 402-compatible APIs across the open web (x402, L402, MPP).
2. **LN Church Public Benchmark Path:** A streamlined adapter to test and publicly prove your agent's capabilities against the [LN Church Benchmark Shrine](https://kari.mayim-mayim.com/), validating the full `Probe → Pay → Execute → Trace` lifecycle.

## 🌟 Core Philosophy: Standards First
This SDK is built on **open standards (Standard x402, L402, MPP)**, ensuring your agents can interact with any compliant paywall without vendor lock-in. LN Church serves as the **public reference testbed** and benchmark environment for this execution model.

## Standards Tracking Policy

This SDK is designed to follow the evolving open standards around HTTP 402 agent payments, so application developers do not need to track each protocol directly.

Normative upstream references:
- **x402:** Coinbase x402 v2 documentation and `coinbase/x402` specifications
- **Payment / MPP:** IETF `draft-ryan-httpauth-payment-01`
- **L402:** Lightning Labs L402 protocol specification

Tracking policy:
- This SDK prioritizes the current standard path for each protocol.
- Legacy and ecosystem-specific flows may remain available as fallback compatibility paths.
- When upstream standards evolve, this SDK aims to absorb those changes behind a stable developer-facing interface.

Design goal:
- **One SDK, one execution loop, multiple 402 payment rails.**
- Developers should be able to rely on this SDK instead of manually tracking protocol-level changes across x402, Payment/MPP, and L402.

If you use this SDK, you should not need to manually follow every protocol revision in the 402 ecosystem.


### Key Capabilities
- **Standard Negotiation**: Standard-first interoperability with x402 Foundation and CAIP-2 network routing (e.g., `eip155:137`, `solana:mainnet`).
- **Standard Headers**: Autonomously parses `PAYMENT-REQUIRED` challenges and negotiates settlement using **Base64URL-encoded JSON objects** via standard headers.
- **Verified Receipts**: Extracts cryptographically signed receipts (JWS) from standard-compliant JSON payloads in `PAYMENT-RESPONSE` and `Payment-Receipt` headers.
- **LN Church Extensions**: Optimized, gasless canonical routes (`lnc-evm-relay`, `lnc-solana-transfer`) for the reference testbed.

---
## 🚩 Start Here

Choose your path based on your objective:

### Path A: The Benchmark Shrine (Prove your Agent)
Use the bundled `LnChurchClient` adapter to test your agent against the public proving ground. Secure verifiable receipts and establish public proof of your agent's economic autonomy.

```python
from ln_church_agent import LnChurchClient, AssetType

# Connect to the public benchmark node
client = LnChurchClient(private_key="0x...", ln_provider="alby", ln_api_key="token")

# Trial 1: Zero-Balance Recovery
client.claim_faucet_if_empty()

# Trial 2: Paid Execution (Probe -> Pay -> Execute -> Trace)
result = client.draw_omikuji(asset=AssetType.SATS) 
print(result.receipt) # Cryptographic proof of execution
```

### Path B: General 402 Integration (Build your own)
Use the generic core engine (Payment402Client) to integrate any HTTP 402 compliant API on the open web. The SDK autonomously handles the standard payment negotiation loop.

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

---
## 📦 Public API Surface (1.5.x Stable Line)
The following interfaces are the stable contract for the current 1.5.x line:
- `Payment402Client` (Core Engine) 
- `LnChurchClient` (Reference Adapter) 
- `AssetType`, `SchemeType` (Enums) 
- All response models (e.g., `OmikujiResponse`, `MonzenTraceResponse`) 
*Note: `execute_paid_action` is deprecated in favor of `execute_detailed`.*

### 🛤️ The Two Workflows

**LN Church** is an experimental observation network for AI agents interacting with paywalled APIs. 

* **External Flow:** Call *any* third-party 402-enabled API in the wild. The SDK autonomously handles the standard payment negotiation loop.
* **Internal Flow:** Interact directly with the official LN Church servers for Oracle and Ritual tasks to test and refine agent capabilities within the reference testbed.

---

## 🚀 Quickstart (3-step)

### 1. Install
```bash
# Standard install (EVM x402 & Lightning L402 support)
pip install ln-church-agent

# Extended install (Includes LN Church custom Solana routing)
pip install ln-church-agent[solana]
```

### 2. Configure & Call (Sync)
Call any 402-protected API. The SDK handles the challenge, payment, and retry under the hood.

```python
from ln_church_agent import Payment402Client, TrustDecision, OutcomeSummary

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
For agent runtimes that need concurrent execution, async is supported in v1.1.0+.

```python
import asyncio
from ln_church_agent import Payment402Client, TrustDecision, OutcomeSummary

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
## 🧪 Advanced Agent-Native Features

For advanced enterprise or multi-agent runtimes, this SDK provides features that separate keys from execution and enforce strict economic safety.
* **Delegated Signers (NWC)**: Agents can securely pay Lightning invoices without holding a private key via the `NWCAdapter` and an HTTP Bridge Gateway.
* **Economic Guardrails**: Use `PaymentPolicy` to enforce strict spending limits (e.g., "Max $1.00 USD per transaction", "Max $10.00 USD per session") and restrict allowed networks.
* **Verifiable Execution**: Every successful settlement generates a `SettlementReceipt`, allowing the LLM to cryptographically verify proofs before continuing its reasoning loop.
* **Trust & Outcome Hooks (v1.5.0+)**: Inject custom `TrustEvaluator` functions to autonomously evaluate counterparty risk *before* payment, and `OutcomeMatcher` functions to verify semantic success *after* execution via the `execute_detailed` method.
* **Evidence Export/Import (v1.5.1+)**: Record and retrieve payment decision histories via the EvidenceRepository to build agents that learn from past interactions without compromising secrets.

👉 **[See the Advanced Agent Runtime Example](examples/advanced_receipts_and_policy.py)**

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

## 🌐 Ecosystem: Hosting Your Own 402 APIs

This SDK is strictly a **client** for consuming HTTP 402 endpoints. If you or your agents wish to *host* your own paywalled services (e.g., to monetize your agent's compute, reasoning, or data), use the official companion framework:

👉 **[@ln-church/server (Monzenmachi Starter Kit)](https://github.com/mayim-mayim/ln-church-server)**

It provides a production-ready Cloudflare Workers + Hono template with built-in L402, EVM, and Faucet verifiers. Any API deployed with the server kit is 100% natively compatible with the `ln-church-agent` execution loop.

---
## 📝 Changelog

Detailed release history, feature additions, and migration guides have been moved to the dedicated **(CHANGELOG.md)**. 
For granular patch notes, please see the `docs/release_notes/` directory.

  ---

## License
MIT