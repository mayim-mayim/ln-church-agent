# ln-church-agent

Your agent will hit a 402 paywall in the wild.

Will it inspect, decide, pay, recover, verify, and continue — or freeze?

`ln-church-agent` is a **buyer-side HTTP 402 runtime and agent-commerce surface inspector** for autonomous agents.  
It helps agents inspect paid-action surfaces, distinguish executable payment rails from higher-order commerce protocols, and prove real paid execution across **L402, x402, and MPP** with receipts, policy checks, HATEOAS recovery, and traceable outcomes.

In v1.9.0+, the inspect layer explicitly classifies emerging agent-commerce surfaces such as **OKX Agent Payments Protocol (APP), Google AP2, and ACP** without executing payment logic. These protocols are treated as observable commerce / authorization patterns unless they expose a concrete HTTP 402-compatible settlement path.

## Core Doctrine

**Do not spend even one LLM token on what the agent should not need to reason about.**

`ln-church-agent` moves payment plumbing out of the model's reasoning loop and into a deterministic buyer-side runtime.

The SDK handles mechanical HTTP 402 concerns such as:
- payment-rail inspection,
- challenge parsing,
- policy checks,
- payment execution,
- HATEOAS recovery,
- receipt verification,
- evidence capture.

The LLM remains responsible for the higher-level economic decisions:
- whether the counterparty should be trusted,
- whether payment is justified,
- whether the expected outcome was delivered,
- and whether the endpoint should be reused.

## What it does

Most payment SDKs help agents *pay*.  
`ln-church-agent` helps agents complete the whole **paid-action loop**:

**Probe → Inspect → Decide → Pay → Execute → Verify → Trace**

It is designed for agents that must:
- **Inspect** HTTP 402 challenges before committing funds.
- **Choose** between L402, x402, MPP, or safe-stop paths based on local policy.
- **Execute** paid actions through policy-aware runtime controls (budgets, trust).
- **Recover** through HATEOAS-style next actions if a flow is interrupted.
- **Verify** receipts and semantic outcomes after payment.
- **Report** trace evidence to a public sandbox or local observer.

## 🧠 What this runtime is

* **Generic Buyer-Side Runtime**: A pure client-side execution engine that keeps your AI agent's reasoning loop clean by abstracting away the HTTP 402 negotiation layer.
* **Agent Commerce Surface Inspector**: Classifies emerging commerce and authorization layers such as OKX APP, AP2, ACP, and UCP separately from executable settlement rails.
* **Open-Web 402 Interoperability**: Natively supports Base64URL JSON headers, CAIP-2 network routing, and multi-chain execution out of the box.
* **Reference Sandbox Support**: Optionally integrates with the LN Church observation network for public benchmarking, trace reporting, and discovery workflows.
* **Stable Interface**: An unchanging developer API surface that safely absorbs the constant fluctuations of upstream protocol drafts.

## Managed Platform Boundary

`ln-church-agent` is not a managed wallet, payment processor, or cloud payment orchestration service.

Managed platforms such as AWS AgentCore Payments help agents execute payments inside a hosted wallet/session environment. `ln-church-agent` focuses on the open-web buyer side: inspecting HTTP 402 and agent-commerce surfaces, distinguishing executable settlement rails from commerce / authorization layers, enforcing local policy, verifying outcomes, and capturing evidence across protocols.

Use managed platforms when you need hosted wallet custody, cloud-side payment sessions, and provider-managed payment execution.

Use `ln-church-agent` when you need lightweight, local, cross-protocol inspection, decision support, evidence capture, sandbox validation, or non-AWS / open-web interoperability.

## Where it fits

- **ln-church-agent**: Buyer-side runtime for agents facing HTTP 402 challenges.
- **ln-church-server**: Provider-side starter for building agent-facing paid APIs.
- **LN Church Sandbox**: Public proving ground for benchmark, receipt, trace, and interop evidence.
- **Evidence Tracking (v1.8.4+)**: `ln-church-agent` can now capture sponsored-access and sandbox execution metadata as local evidence (`SponsoredAccessEvidence` / `SandboxEvidence`). Sandbox evidence is strictly scoped to LN Church's controlled sandbox environment (`evidence_scope: "sandbox_internal"`) and intentionally does not auto-submit external observations. Raw secrets are securely redacted.
- **Corpus Readiness (v1.8.5+)**: `SandboxEvidence` can be converted into a local `SandboxCorpusCandidate`. This does not submit to `ExternalObserve`. Final corpus acceptance remains server-side.

---

## 🧠 AI Decision Card

Use `ln-church-agent` when an AI agent must do more than simply pay for one API call.

Choose this SDK when the agent needs:
- **Multi-rail support**: L402, x402, and MPP-aware flows.
- **Policy enforcement**: Local spend limits, session budgets, and trust checks.
- **Verifiable evidence**: Receipts, evidence records, and traces for auditing.
- **Safe stopping**: Graceful handling of unsupported or unstable payment sessions.
- **Commerce surface inspection**: Detect OKX APP-style agent-commerce metadata while keeping execution disabled unless a supported 402 rail is present.

*Use a lightweight 402 proxy when the task is only a one-off, low-risk `pay-and-fetch`.*

---

## ⚡ First Success: Inspect Before Paying

Start with a no-payment inspection command. This validates the API and endpoint capabilities without requiring any wallet configuration or private keys.

```bash
pip install ln-church-agent
ln-church-agent inspect https://kari.mayim-mayim.com/api/agent/sandbox/mpp/charge/basic --json
```
This command does not execute payment. It detects the HTTP 402 challenge, identifies the payment rail, recommends a safe action, and prints the next command.

Canonical first loop: `inspect → decide → pay → verify → trace`

---

## 🧭 Agent Commerce Surface Inspection

`ln-church-agent` v1.8+ extends `inspect` from a payment-rail preflight tool into an **Agent Commerce Surface Inspector**, with v1.9.0 adding explicit classification for **Google AP2 and ACP**.

It can safely detect higher-order commerce metadata, starting with OKX Agent Payments Protocol (APP), AP2 mandates, and ACP checkouts, while keeping settlement execution strictly disabled during inspection.

In v1.9.1+, inspect results can also include Guided Handoff metadata for AP2 / ACP / OKX APP-like surfaces. This tells the upstream agent what to ask the site for, what not to treat as settlement proof, which evidence is required, what information is missing, and why operator approval may be required.

Example output:

```json
{
  "ok": true,
  "url": "https://api.example.com/checkout",
  "http_status": 402,
  "surfaces_detected": ["ACP"],
  "settlement_rails_detected": ["x402"],
  "surface_type": "checkout",
  "commerce_protocol": "acp",
  "commerce_intent": "agentic_checkout",
  "settlement_rail": "x402",
  "recommended_action": "observe_only",
  "will_execute_payment": false
}

```

```json
{
  "handoff_mode": "guided_handoff",
  "approval_required": true,
  "ask_site_for": ["quote_details", "settlement_rail_options", "receipt_or_proof_model"],
  "do_not": ["treat_authorization_artifact_as_settlement_proof"],
  "required_evidence": ["explicit_price", "merchant_identity", "settlement_rail", "receipt_model"]
}
```

This distinction is intentional:

* **L402 / x402 / MPP** are treated as executable payment rails.
* **Google AP2 / ACP / OKX APP / card-network agent payments** are treated as commerce, authorization, identity, or checkout surfaces. Even if they expose a concrete HTTP 402-compatible settlement path, their baseline recommendation defaults to observation.
* `inspect` never executes payment, initializes wallets, signs payloads, or calls brokers.

Use this mode when your agent needs to understand a paid-action surface before deciding whether payment execution is safe, unsupported, or observation-only.

---

## MCP: Inspect-only payment surface discovery

<!-- mcp-name: io.github.mayim-mayim/ln-church-agent-mcp -->

`ln-church-agent-mcp` is the inspect-only MCP entrypoint bundled with `ln-church-agent`.

It is intended for MCP-compatible agents that need to discover and inspect HTTP 402 / agent-commerce surfaces before deciding whether any separate payment execution engine should be used.

v1.9.2 adds `ln-church-agent-mcp`, a keyless MCP server for AI orchestration frameworks that need to inspect paid surfaces without executing payment.

It exposes inspect / explain / observation-payload tools, returns Guided Handoff metadata when available, and hard-locks `payment_performed=false`.

`ln-church-agent-mcp` is a public, inspect-only MCP server designed for safe reconnaissance.
It parses HTTP 402 paid surfaces, returning detailed structural classifications for L402, x402, MPP, OKX APP, AP2, and ACP.

* **No Payments Executed**: It strictly analyzes the response and suggests a `recommended_action`.
* **No Private Keys Required**: It operates entirely without wallet adapters or identity credentials.
* **Safe Telemetry**: The server can build and submit observations to `/api/agent/external/mcp-observe` with guaranteed secret redaction. (It does not auto-submit).

> **Remote MCP scope note:**  
> v1.9.2 provides a bundled **stdio MCP server** for inspect-only payment surface discovery.  
> Remote MCP / Claude custom connector hosting is not included in this release and is planned as future scope.

To expose these safe tools to your AI agent:

```bash
ln-church-agent-mcp
```
---

## ⚡ Start in 5 Minutes

Choose your execution path based on your immediate goal:

### Route A: Generic Paid Fetch (Open Web Integration)
Integrate with any HTTP 402 compliant API on the open web. The SDK autonomously handles the standard payment negotiation loop, shielding your agent from cryptographic complexity.

```python
from ln_church_agent import Payment402Client

client = Payment402Client(base_url="https://your-402-api.com", private_key="0x...")

# Inspects 402 -> Applies policy -> Pays if allowed -> Retries -> Verifies response
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

### Observation → Corpus → Synthetic Replay → Agent Dry-run Validation

`ln-church-agent` v1.8+ closes the agent-side of the LN Church interop loop.

It can read server-side `synthetic_from_corpus_v1` replay descriptors and validate whether the local parser and decision engine choose the expected behavior:

- `pay_and_verify`
- `observe_only`
- `stop_safely`
- `reject_invalid`

This is a dry-run validation path. It does not execute real payments and does not attempt raw wire-level replay.

```python
from ln_church_agent import LnChurchClient

client = LnChurchClient(private_key="0x...")

# Dry-run a synthetic replay descriptor from the Corpus
replay_result = client.run_corpus_replay(
    corpus_id="corp_12345",
    dry_run=True
)

print(f"Success: {replay_result.ok}")
print(f"Expected: {replay_result.expected_action}, Observed: {replay_result.observed_action}")
```
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

**Standard x402 v2 (Global Standards):**
* **EVM exact (`x402`)**: Standard EVM-based settlement utilizing strict EIP-712/EIP-3009 gasless authorization payloads.
* **SVM exact (Solana)**: Official x402 v2 SVM exact payments via CAIP-2 `solana:<genesisHash>` networks. This SDK features a built-in transaction builder for standard x402 SVM exact compatible payloads.
  * *Note: The current LN Church exact sandboxes act as **post-settlement validators**. They require submitted tx hash / signature evidence and will reject unbroadcasted payloads. True V2 exact settlement (facilitator broadcasting) is a future phase.*
* **L402 / MPP**: Standard Lightning Network settlement (SATS) supporting Macaroon and BOLT11 invoice parsing.

**Compatibility & Sandbox Paths (LN Church Extensions):**
* **`lnc-solana-transfer`**: Legacy compatibility path for direct SPL Token (USDC) transfers via Solana RPC.
* **`lnc-evm-relay`**: Optimized gasless relayer orchestration.
* **`grant` / `faucet`**: Cold-start overrides and sponsored access.
* *Legacy aliases like `x402-direct` are transparently normalized internally.*

**Observable Commerce / Authorization Surfaces (Inspect-Only):**
* **AP2 (Agent Payments Protocol)**: Detected via payment/checkout mandate metadata. Classified as an authorization surface. The SDK does not sign mandates.
* **ACP (Agentic Commerce Protocol)**: Detected via checkout, cart, or delegated payment token metadata. The SDK does not execute ACP checkouts.
* **OKX APP**: Detected when explicit APP metadata or broker objects are present.
* **Card-network / wallet-mediated agent payments**: Treated as observable commerce or authorization patterns, not native SDK execution targets.

---

## 🚀 Initializing with Dual-Stack Keys (EVM & SVM)

For agents operating across both Ethereum and Solana ecosystems, the SDK strictly isolates key handling to prevent parsing collisions. 

```python
from ln_church_agent import Payment402Client, PaymentPolicy
import os

client = Payment402Client(
    private_key=os.getenv("EVM_PRIVATE_KEY"),        # For standard x402 EVM
    svm_private_key=os.getenv("SVM_PRIVATE_KEY"),    # For standard x402 SVM Exact
    svm_rpc_url=os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com"),
    policy=PaymentPolicy(...)
)
```

> **⚠️ SVM Exact Architecture & Constraints:**
> * `svm_private_key` must be a standard 64-byte Base58 encoded Solana key.
> * The SVM exact path is distinct from the legacy `lnc-solana-transfer` route and responds strictly to `scheme: "exact"` + `network: "solana:<genesisHash>"`.
> * **Wire-Level Precision:** The transaction builder preserves and uses the raw `PaymentRequirements.asset` (SPL Token Mint Address) and raw `amount` (minimal units) for wire-level transaction construction. Human-readable normalization is only used internally for policy and budget evaluation.
> * **ATA Constraint:** The Destination Associated Token Account (ATA) must already exist. The current SDK transaction builder does not inject ATA creation instructions.
> * **Supported Mints:** The internal builder currently targets strictly known USDC mints. Unknown mints will be rejected due to unknown decimals.
> * **Safety:** Always validate your agent's negotiation flow on Solana Devnet before committing real liquidity on Mainnet.
> * **Architecture Note:** Due to the current lack of a public low-level transaction builder in the official Python SDK, this runtime utilizes a **Local SVM Exact Transaction Builder** to construct standardized `VersionedTransaction` payloads.
> * **Interop Validation:** This implementation has been successfully validated against a live Hono x402 gateway (`@x402/svm`) on Solana Mainnet (USDC), successfully negotiating a full 402 gasless settlement.
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

`ln-church-agent` v1.8.3 can locally diagnose a grant token before use (`client.explain_grant()`), explaining whether it appears usable for the target route/method/audience/agentId. This diagnostic is advisory only; the LN Church backend remains the authoritative validator and enforces single-use consumption.

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