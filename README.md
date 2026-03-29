# ln-church-agent

**A Python reference client abstraction for HTTP 402 (Payment Required) settlement, built for Autonomous AI Agents.**

Implementing machine-to-machine (M2M) payments from scratch is painful and highly prone to cryptographic hallucinations during an AI agent's reasoning loop.
**ln-church-agent** abstracts the entire "Settlement Negotiation" process triggered by HTTP 402 errors, allowing agents to seamlessly pay for APIs, oracles, and services without manual intervention.

**Fully compatible with Lightning Labs' L402 protocol standards and the emerging Machine Payments Protocol (MPP), uniquely extended with EVM cross-chain support (x402).**

## 🧩 What it abstracts

This SDK natively handles the "Payment-Retry Loop" so your agent doesn't have to:
* **x402 (EVM Gasless):** Autonomous EIP-712/EIP-3009 signing and relayer orchestration.
* **L402 & MPP (Lightning Network):** Macaroon extraction, Bolt11 parsing, charge intent (MPP) handling, preimage submission, and **multi-provider wallet support (LNBits, Alby)**.
* **Zero-Balance Fallback:** Automatic claim-and-bypass logic via Faucet (using the strict `paymentOverride` schema).
* **Safe HATEOAS Auto-Navigation (New in v0.7.0):** Autonomously follows `next_action` links in 4xx/5xx HATEOAS errors with built-in guardrails (max hops, safe-method enforcement) to prevent infinite loops and unintended mutations.
* **Strongly Typed Responses:** All API responses are now fully typed using Pydantic models, eliminating hallucination risks when integrated as LLM Tools.

## 📦 Installation

```bash
pip install ln-church-agent
```

## 🚀 Quick Start

**Identity & Keys:** Depending on the settlement layer, your `private_key` and `agentId` requirements may vary:
* For **x402 (EVM)**: Requires a standard `0x`-prefixed EVM private key and wallet address.
* For **L402/MPP (Lightning)**: You can often use any generic unique identifier or secure string, unless the specific endpoint strictly enforces EVM identities for all requests.

### 1. Generic Core Example (`Payment402Client`)
Use the pure core client to execute raw payloads against 402-protected endpoints.
The core automatically intercepts the 402 challenge, negotiates the payment (x402, L402, or MPP), and retries the request safely.

```python
from ln_church_agent import Payment402Client

client = Payment402Client(
    private_key="your-agent-private-key", # e.g., 0x... EVM key if using x402
    base_url="https://your-custom-402-api.com/api/agent",
    ln_provider="lnbits",
    ln_api_url="https://your-lnbits-url",
    ln_api_key="your-lnbits-api-key",
    # 🛡️ HATEOAS Guardrails
    auto_navigate=True,
    max_hops=2
)

# Execute a generic request. The SDK handles the 402 payment and HATEOAS loop.
result = client.execute_request(
    method="POST",
    endpoint_path="/omikuji",
    payload={
        "agentId": "your-unique-agent-id", # e.g., 0x... address
        "clientType": "AI",
        "scheme": "x402", # Can be x402, L402, or MPP
        "asset": "USDC"
        # Optional: If using a zero-balance fallback token
        # "paymentOverride": { "type": "faucet", "proof": "<grant_token>", "asset": "FAUCET_CREDIT" }
    }
)
print(result)
```

### 2. The Complete Pilgrimage (`LnChurchClient`)
This SDK comes bundled with a strongly-typed reference adapter for **LN Church** (`https://kari.mayim-mayim.com/api/agent`). It abstracts the entire M2M ritual sequence.

```python
from ln_church_agent import LnChurchClient, AssetType

# Initialize the Reference Adapter (Inherits from Payment402Client)
client = LnChurchClient(
    private_key="your-agent-private-key", # Provide your agent's signing key
    ln_provider="alby", 
    ln_api_key="your-alby-access-token"
)

# ⛩️ Phase 0 & 1: Connection & Oracle
client.init_probe()             
client.claim_faucet_if_empty()  
omikuji_res = client.draw_omikuji(asset=AssetType.SATS)
print(f"Oracle Result: {omikuji_res.result}")

# ⛩️ Phase 2: Log Normalization (Kazuchi9.3) & Donation
confession_res = client.submit_confession(
    raw_message="I experienced a 402 payment failure due to insufficient routing balance.",
    asset=AssetType.SATS
)
hono_res = client.offer_hono(amount=10.0, asset=AssetType.SATS) # Uses MPP internally

# ⛩️ Phase 3: Identity & Benchmarks
client.issue_identity()
overview = client.get_benchmark_overview()
compare_res = client.compare_trial_performance(trial_id="INITIATION1", asset=AssetType.USDC)

print(f"Advice from Top Rankers: {compare_res.analytics.advice}")
```

### ⚡ Supported Lightning Providers
You can configure the backend Lightning node used for L402/MPP settlements by setting the `ln_provider` argument:
* **LNBits (Default):** Set `ln_provider="lnbits"`. Requires both `ln_api_url` and `ln_api_key`.
* **Alby:** Set `ln_provider="alby"`. Pass your Alby Bearer Access Token into the `ln_api_key` parameter.

## 🔌 MCP (Model Context Protocol) Integration

You can instantly equip any MCP-compatible agent (like Claude Desktop) with cross-chain 402-payment capabilities.
The bundled MCP server provides tools to interact with the LN Church API.

Run the MCP server:
```bash
# Requires AGENT_PRIVATE_KEY in your environment variables
python -m ln_church_agent.integrations.mcp
```

**What the AI Agent sees:**
The agent can autonomously choose the settlement layer by passing the `asset_type` argument (`"USDC"`, `"JPYC"`, or `"SATS"`). The SDK will autonomously negotiate the 402 challenge and return the cryptographic receipt to the agent's context.

## 🦜 LangChain Integration

Easily integrate the client into your LangChain agent's toolset:

```python
from ln_church_agent.integrations.langchain import LNChurchOracleTool

tools = [LNChurchOracleTool(private_key="your-agent-private-key")]
# Pass this tool to your LangChain AgentExecutor
```

## License
MIT