# ln-church-agent
**A Buyer-Side HTTP 402 SDK & Agentic Payment Runtime**

`ln-church-agent` is a generic **HTTP 402 runtime** for autonomous AI agents. While it natively handles open standards (`x402`, `L402`, `MPP`) across the open web, **LN Church** serves as the reference **Agentic Payment Sandbox** for public benchmarking—validating the complete `Probe → Pay → Execute → Trace` lifecycle.

Whether you are integrating standard machine-to-machine paywalls or proving your agent's economic autonomy against a global leaderboard, this SDK provides a stable, unified execution loop.

---

## ⚡ Start in 5 Minutes

Choose your execution path based on your immediate goal:

### Route A: Generic Paid Fetch (Open Web Integration)
Integrate with any HTTP 402 compliant API on the open web. The SDK autonomously handles the standard payment negotiation loop, shielding your agent from cryptographic complexity.

```python
from ln_church_agent import Payment402Client

client = Payment402Client(base_url="https://your-402-api.com", private_key="0x...")

# Detects 402 -> Pays invoice -> Retries -> Returns JSON
result = client.execute_request(
    method="POST",
    endpoint_path="/api/protected",
    payload={"input": "data"}
)
print(result)
```

### Route B: Agent Tool Integration (MCP)
Instantly equip any Model Context Protocol (MCP) compatible agent (e.g., Claude Desktop) with cross-chain 402-payment and scouting capabilities.

```bash
export AGENT_PRIVATE_KEY="your-0x-prefixed-key"
python -m ln_church_agent.integrations.mcp
```
*Your agent can now autonomously call paid tools and benchmark flows directly from its reasoning loop.*

### Route C: Public Benchmark against LN Church Sandbox
Prove your agent's parsing and execution capabilities against the physically isolated Agentic Payment Sandbox. This verifies protocol compliance (L402 or MPP) and reports telemetry to the Interop Matrix.

```python
from ln_church_agent import LnChurchClient

client = LnChurchClient(private_key="0x...")

# Autonomously validate standard L402 compliance
l402_result = client.run_l402_sandbox_harness()

# Or, validate the new Machine Payments Protocol (MPP) charge flow
mpp_result = client.run_mpp_charge_sandbox_harness()

print(f"L402 Hash Matched: {l402_result.canonical_hash_matched}")
print(f"MPP Hash Matched: {mpp_result.canonical_hash_matched}")
```

---

## 🧠 What this runtime is

* **Generic Buyer-Side Runtime**: A pure client-side execution engine that keeps your AI agent's reasoning loop clean by abstracting away the HTTP 402 negotiation layer.
* **Open-Web 402 Interoperability**: Natively supports Base64URL JSON headers, CAIP-2 network routing, and multi-chain execution out of the box.
* **Reference Sandbox Support**: Optionally integrates with the LN Church observation network for public benchmarking, trace reporting, and discovery workflows.
* **Stable Interface**: An unchanging developer API surface that safely absorbs the constant fluctuations of upstream protocol drafts.

---

## 🛡️ Why teams adopt this runtime

* **Avoid tracking protocol churn**: Developers should not need to track every upstream revision manually. The SDK abstracts the evolving drafts of the x402 Foundation, IETF (`Payment` / `MPP`), and L402 into a single `execute_detailed` loop.
* **Keep final execution authority local**: Through the **Advisor & Final Judge Architecture**, the network can advise on counterparty risk, but the *final authority* to execute or block a payment remains strictly within your local runtime (`PaymentPolicy`, `TrustEvaluator`).
* **Obtain verifiable receipts**: Every successful settlement generates structured, verifiable evidence (`SettlementReceipt`, `PaymentEvidenceRecord`) that your LLM can use to audit its own budget.
* **Support cold-start execution**: Natively supports `faucet` and `grant` tokens purely as onboarding overrides, allowing zero-balance agents to bootstrap capabilities before engaging in direct 402 settlement.
* **Benchmark real behavior**: Test your agent's logic against a live, state-free public sandbox before committing real liquidity to unknown endpoints.

---

## 🔌 Protocol Coverage

The SDK supports multiple settlement rails through a unified interface.

**Canonical Paid Paths (Global Standards):**
* **`x402` (V2 Fully Supported & Agentic.Market Ready)**: Standard EVM-based settlement utilizing strict EIP-712/EIP-3009 gasless authorization payloads. The SDK natively parses x402 V2 Base64URL JSON headers, autonomously selecting the correct network parameters from the server's `accepts` array. It strictly constructs the official V2 settlement envelope, including transparent echo-back of protocol `extensions` to guarantee seamless integration with discovery indexers like Coinbase Bazaar (Agentic.Market).
* **`L402` / `MPP`**: Standard Lightning Network settlement (SATS) supporting Macaroon and BOLT11 invoice parsing.

**Compatibility & Sandbox Paths (LN Church Extensions):**
* **`lnc-evm-relay`**: Optimized gasless relayer orchestration.
* **`lnc-solana-transfer`**: Native SPL Token (USDC) transfers via Solana RPC.
* *Legacy aliases like `x402-direct` are transparently normalized internally.*

---

## 🎟️ Two LN Church Onboarding Paths (Cold-Start Overrides)

While direct settlement (x402/L402/MPP) remains the standard paid path, LN Church provides two onboarding paths for cold-start execution and sandbox testing. Both act as a `paymentOverride` before standard settlement.

### 1. Zero-Balance Faucet Fallback
A one-time fallback for agents with no available cryptocurrency. Designed strictly for initial capability verification.

```python
from ln_church_agent import LnChurchClient, AssetType

client = LnChurchClient(
    private_key="0x...",  # identity anchor for canonical agent binding
    ln_provider="alby",
    ln_api_key="token",
)
client.init_probe()
client.claim_faucet_if_empty()

result = client.draw_omikuji(asset=AssetType.SATS) # Uses Faucet override
```

### 2. Sponsored Grant Access
Execute using a signed, scoped, single-use grant token issued by a trusted sponsor. This serves as an experimental foundation for sponsor-funded pre-payment distribution in A2A settings.

```python
from ln_church_agent import LnChurchClient

client = LnChurchClient(
    private_key="0x...",  # identity anchor for canonical agent binding
    base_url="https://kari.mayim-mayim.com",
)
client.init_probe()

client.set_grant_token("<JWS_GRANT_TOKEN>")
result = client.draw_omikuji()  # Uses Grant override
```

---

## 📜 Standards Tracking Policy

This SDK is designed to follow the evolving open standards around HTTP 402 agent payments, ensuring application developers do not need to track each protocol directly.

* **Normative Upstream References:** Coinbase `x402`, IETF `draft-ryan-httpauth-payment-01` (`MPP`), and Lightning Labs `L402`.
* **Tracking Policy:** This SDK prioritizes the current standard path for each protocol. Legacy and ecosystem-specific flows remain available as fallback compatibility paths. 
* **Design Goal:** One SDK, one execution loop, multiple 402 payment rails.

When upstream standards evolve, this SDK aims to absorb those changes behind a stable developer-facing interface. **If you use this SDK, you should not need to manually follow every protocol revision in the 402 ecosystem.**

**Note on Evolving MPP Standards:**
`ln-church-agent` does not attempt to replace official MPP SDKs. Instead, it focuses on buyer-side runtime concerns: policy checks, challenge parsing, payment-shape telemetry, evidence capture, and interop observation across L402, x402, and emerging MPP-style `Payment` challenges. For instance, MPP session intent is currently actively observed and classified for telemetry, but not executed as a full runtime flow.

---

## ⚖️ Advisor & Final Judge Architecture

Agents can consult the Monzen network as an **evidence-rich advisor** to assess counterparty risk before paying, and to verify semantic outcomes after execution. 

Crucially, **the network can advise, but final authority remains in the local runtime**. 
The LN Church backend returns structured recommendations (e.g., Sanctification status, historical mismatches), but the SDK's local `PaymentPolicy` and `allowed_hosts` configuration will always explicitly supersede remote advice.

---

## 📚 Further Documentation

* **[Quickstart & Authentication](docs/01_quickstart.md)**
* **[Architecture & Capabilities](docs/02_architecture.md)**
* **[The LN Church Pilgrimage](docs/03_ln-church.md)**
* **[Integrations (MCP & LangChain)](docs/05_integrations.md)**
* **[Monzen Observation Network](docs/06_monzen.md)**

## License
MIT