# ln-church-agent

**A Python reference client abstraction for HTTP 402 (Payment Required) settlement, built for Autonomous AI Agents.**

Implementing machine-to-machine (M2M) payments from scratch is painful and highly prone to cryptographic hallucinations during an AI agent's reasoning loop. **ln-church-agent** abstracts the entire "Settlement Negotiation" process triggered by HTTP 402 errors, allowing agents to seamlessly pay for APIs, oracles, and services without manual intervention.

**Fully compatible with Lightning Labs' L402 protocol standards and the emerging Machine Payments Protocol (MPP), uniquely extended with EVM cross-chain support (x402).**

## 🧩 What it abstracts

This SDK natively handles the "Payment-Retry Loop" so your agent doesn't have to:
* **x402 (EVM Gasless):** Autonomous EIP-712/EIP-3009 signing and relayer orchestration.
* **L402 (Lightning Network):** Macaroon extraction, Bolt11 parsing, preimage submission, and **multi-provider wallet support (LNBits, Alby)**.
* **Zero-Balance Fallback:** Automatic claim-and-bypass logic via Faucet.
* **Verifiable Receipts:** Capture and pass-through of verifiable execution receipts for downstream verification.

## 📦 Installation

```bash
pip install ln-church-agent
```

## 🚀 Quick Start

**Note:** The core client currently works out-of-the-box with 402 challenge shapes compatible with the LN Church protocol. It is designed to evolve toward broader, protocol-agnostic 402 client reuse in future releases.
 
**Identity & Keys:** Depending on the settlement layer, your `private_key` and `agentId` requirements may vary:
* For **x402 (EVM)**: Requires a standard `0x`-prefixed EVM private key and wallet address.
* For **L402 (Lightning)**: You can often use any generic unique identifier or secure string, unless the specific endpoint strictly enforces EVM identities for all requests.

### 1. Generic Core Example (`Payment402Client`)
Use the pure core client to execute raw payloads against 402-protected endpoints. The core automatically intercepts the 402 challenge, negotiates the payment (x402 or L402), and retries the request.

```python
from ln_church_agent import Payment402Client

client = Payment402Client(
    private_key="your-agent-private-key", # e.g., 0x... EVM key if using x402
    base_url="https://your-custom-402-api.com/api/agent",
    ln_provider="lnbits",
    ln_api_url="https://your-lnbits-url",
    ln_api_key="your-lnbits-api-key"
)

# Execute a generic POST request. The SDK handles the 402 payment loop.
result = client.execute_paid_action(
    endpoint_path="/omikuji",
    payload={
        "agentId": "your-unique-agent-id", # e.g., 0x... address if using x402
        "clientType": "AI",
        "scheme": "x402",
        "asset": "USDC"
    }
)
print(result)
```

### 2. Reference Adapter Example (`LnChurchClient`)
This SDK comes bundled with a reference adapter for **LN Church** (`https://kari.mayim-mayim.com/api/agent`). It extends the core client with domain-specific methods (Probe, Faucet, Omikuji).

```python
from ln_church_agent import LnChurchClient, AssetType

# Initialize the Reference Adapter (Inherits from Payment402Client)
client = LnChurchClient(
    private_key="your-agent-private-key", # Provide your agent's signing key
    ln_provider="alby", 
    ln_api_key="your-alby-access-token"
)

client.init_probe()             # Verify connectivity
client.claim_faucet_if_empty()  # Get free test credits if balance is zero
result_l402 = client.draw_omikuji(asset=AssetType.SATS) # Execute autonomous L402 payment

print(f"Receipt: {result_l402.receipt.txHash}")
```

### ⚡ Supported Lightning Providers
You can configure the backend Lightning node used for L402 settlements by setting the `ln_provider` argument:
* **LNBits (Default):** Set `ln_provider="lnbits"`. Requires both `ln_api_url` and `ln_api_key`.
* **Alby:** Set `ln_provider="alby"`. Pass your Alby Bearer Access Token into the `ln_api_key` parameter.

## 🔌 MCP (Model Context Protocol) Integration

You can instantly equip any MCP-compatible agent (like Claude Desktop) with cross-chain 402-payment capabilities. The bundled MCP server provides a tool called `execute_paid_entropy_oracle`.

Run the MCP server:
```bash
# Requires AGENT_PRIVATE_KEY in your environment variables (e.g., 0x... for EVM)
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

