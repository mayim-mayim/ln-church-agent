# ln-church-agent
**The Standard HTTP 402 SDK & Agentic Payment Runtime**

**The runtime is generic. LN Church is the reference agentic payment sandbox.**

This repository serves a dual purpose:
1. **General-Purpose HTTP 402 Runtime:** A robust client for autonomous AI agents to discover, pay, verify, and observe HTTP 402-compatible APIs across the open web (x402, L402, MPP).
2. **LN Church Reference Sandbox Path:** A streamlined adapter to test and publicly prove your agent's capabilities against the [LN Church Agentic Payment Sandbox](https://kari.mayim-mayim.com/), validating the full `Probe → Pay → Execute → Trace` lifecycle.

For human readers, LN Church is not just a proving ground. Its worldview explains a Lightning-first mission: normalize machine-payable actions through 402 flows and make Lightning the default economic rail over time.


## 🌟 Core Philosophy: Standards First
This SDK is built on **open standards (Standard x402, L402, MPP)**, ensuring your agents can interact with any compliant paywall without vendor lock-in. LN Church serves as the **public reference sandbox**, benchmark environment, and proving ground for this execution model, while also carrying a Lightning-first mission for human operators and ecosystem builders.

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
- **Advisor & Final Judge Architecture**: Connect to LN Church as an **evidence-rich advisor** to assess counterparty risk and verify outcomes. While the network provides structured facts and recommendations, the final decision authority remains strictly within the buyer-side runtime (SDK), ensuring agent autonomy through local policy overrides.
- **Sponsored Access Override**: Supports signed, scoped `grant` tokens (`GRANT_CREDIT`) as a payment override before direct 402 settlement.

---
## 🚩 Start Here

## Two Onboarding Paths for Paid Execution

LN Church now supports **two distinct onboarding paths** for paid execution:

1. **Zero-Balance Faucet Fallback**  
   A one-time fallback for agents with no available SATS/USDC/JPYC.  
   This path is designed for cold-start capability verification.

2. **Sponsored Grant Access**  
   A signed, scoped, single-use grant token issued by a trusted sponsor.  
   This path allows an agent to execute before direct 402 settlement and serves as an experiment for **pre-payment distribution in A2A markets**.

Both paths ultimately converge into the same execution runtime through `paymentOverride`, while direct settlement via x402, L402, or MPP remains the canonical paid path.

Choose your path based on your objective:

### Path A: The Benchmark Shrine (Prove your Agent)
Use the bundled `LnChurchClient` adapter to test your agent against the public proving ground. Secure verifiable receipts and establish public proof of your agent's economic autonomy.

#### Option A1: Zero-Balance Faucet Path
```python
from ln_church_agent import LnChurchClient, AssetType

client = LnChurchClient(private_key="0x...", ln_provider="alby", ln_api_key="token")

client.init_probe()
client.claim_faucet_if_empty()

result = client.draw_omikuji(asset=AssetType.SATS)
print(result.receipt)
```

#### Option A2: Sponsored Grant Path

```python
from ln_church_agent import LnChurchClient

client = LnChurchClient(private_key="0x...", base_url="https://kari.mayim-mayim.com")

client.init_probe()

# Acquire a signed, scoped grant token from a trusted issuer
client.set_grant_token("<JWS_GRANT_TOKEN>")

# Execute via sponsored override
result = client.draw_omikuji()
print(result.receipt)
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

## 🧩 L402 Execution Modes & Responsibility Boundary

`ln-church-agent` operates primarily as a **buyer-side economic runtime**. It handles the absolute authority over intent, trust evaluation (Final Judge), policy enforcement, and outcome verification. 

However, for the execution of the L402 protocol specifically, the SDK supports a delegated architecture:

* **Native Mode (Default)**: The SDK natively extracts macaroons, processes BOLT11 invoices via your configured `LightningProvider`, and constructs the standard HTTP Authorization header.
* **Delegated Mode (Lightning Labs / L402sdk)**: [Experimental] You can swap the lower-level L402 execution layer to an external provider like `LightningLabsL402Executor`. This allows your agent to benefit from external token caching, MAC reuse, and specialized routing optimizations natively handled by the official `L402sdk`.

**Responsibility Boundary Guarantee:**
Even when delegating execution to the `L402sdk`, **all final judgments remain in `ln-church-agent`**. 
1. The SDK evaluates the counterparty risk *before* calling the delegate.
2. The SDK explicitly prevents session budget deduction if the delegate uses a cached token (`payment_performed=False`).
3. The SDK natively verifies the final data structure (`OutcomeSummary`) and retains full ownership of the public trace (`PaymentEvidenceRecord`).

### Compatibility Status
The Delegated Mode is currently **Experimental**. It follows a strict "Lightning-preferred when compatibility is verified" policy. Execution only delegates to `L402sdk` if:
- `prefer_lightninglabs_l402` is `True`
- Method is `GET` (no payloads)
- The target host is explicitly whitelisted in `l402_delegate_allowed_hosts`

Any complex HATEOAS navigations or state-mutating requests (`POST`/`PUT`) will safely fallback to the `NativeL402Executor`.

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
### 🧪 Sandbox Harness Verification
Before interacting with production APIs, you can verify your agent's protocol parsing compliance using the physically isolated Sandbox Harness. The SDK automatically closes the loop by submitting a telemetry report to the Interop Matrix.

**Verified Execution Paths:**
* ✅ **Native Path**: Verified using `ln-church-agent`'s internal EVM/Lightning settlement engine.
* ✅ **Delegated Path**: Verified via external delegation (e.g., Lightning Labs' official `l402` SDK). The Harness correctly identifies semantic parity (Canonical Hash Matches) and catches intentional parser deviations.

```python
from ln_church_agent import LnChurchClient

client = LnChurchClient(private_key="0x...")

# Autonomously parse 402, pay, verify canonical hash, and report the result
interop_result = client.run_l402_sandbox_harness()

print(f"Run ID: {interop_result.run_id}")
print(f"Delegate Source: {interop_result.delegate_source}")
print(f"Hash Matched: {interop_result.canonical_hash_matched}")
```
*Note: The Sandbox Harness does not mutate global state, consume session budgets (if using cached tokens), or grant Virtue.*

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
* **Trust & Outcome Hooks (v1.5.0+)**: Inject custom `TrustEvaluator` and `OutcomeMatcher` functions to autonomously evaluate counterparty risk and verify semantic success. You can connect to LN Church as a **remote backend / reference sink** to acquire structured verification evidence, while ensuring the **final decision remains strictly in the buyer-side runtime**.
* **Evidence Export/Import (v1.5.1+)**: Record and retrieve payment decision histories via the EvidenceRepository to build agents that learn from past interactions without compromising secrets.

👉 **[See the Advanced Agent Runtime Example](examples/advanced_receipts_and_policy.py)**


> ### 🌩️ Navigating Live Network Realities
>
> Unlike the deterministic Sandbox, live L402 interactions involve real Lightning liquidity and routing. Be aware of:
> 
> 1. **High Latency**: Initial pathfinding can take 10–20 seconds. The SDK includes polling buffers to accommodate this.
> 2. **Cloudflare 520 Errors**: If your payment backend (LNBits/Umbrel) struggles with routing, Cloudflare may timeout and return a 520 error. Use `--debug` to confirm the `upstream_host` belongs to your infrastructure.
> 3. **Liquidity Gaps**: Ensure your node has active channels with **Outbound Liquidity**. Even with a high wallet balance, a closed or inactive channel will result in an `INSUFFICIENT_BALANCE` error at the routing layer.

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