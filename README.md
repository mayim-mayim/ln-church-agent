# ln-church-agent

**A Python reference client abstraction for HTTP 402 (Payment Required) settlement, built for Autonomous AI Agents.**

Implementing machine-to-machine (M2M) payments from scratch is painful and highly prone to cryptographic hallucinations during an AI agent's reasoning loop. **ln-church-agent** abstracts the entire "Settlement Negotiation" process triggered by HTTP 402 errors, allowing agents to seamlessly pay for APIs, oracles, and services without manual intervention.

## 🧩 What it abstracts

This SDK natively handles the "Payment-Retry Loop" so your agent doesn't have to:
* **x402 (EVM Gasless):** Autonomous EIP-712/EIP-3009 signing and relayer orchestration.
* **L402 (Lightning Network):** Macaroon extraction, Bolt11 parsing, and preimage submission.
* **Zero-Balance Fallback:** Automatic claim-and-bypass logic via Faucet.
* **Deterministic Receipts:** Capture and normalization of payment proofs (JWS).

## 📦 Installation

```bash
pip install ln-church-agent
```

## 🚀 Quick Start (Generic Client)

The client is designed to communicate with any API endpoint that implements the x402/L402 protocol standards. **It seamlessly abstracts both EVM Gasless (x402) and Lightning Network (L402) settlements.**

```python
from ln_church_agent import Payment402Client, AssetType

# 1. Initialize the generic 402 client with full capabilities
# This setup allows the agent to handle both EVM and Lightning payments.
client = Payment402Client(
    private_key="0xYourAgentPrivateKey...",      # Required for x402 & Identity
    lnbits_url="https://your-lnbits-url",         # Required for L402
    lnbits_key="your-lnbits-api-key",             # Required for L402
    base_url="https://your-custom-402-api.com/api/agent"
)

# 2. Execute with Polygon Gasless (x402)
# The SDK handles EIP-712 hashing, signing, and relayer orchestration.
result_x402 = client.draw_omikuji(asset=AssetType.USDC)

# OR Execute with Lightning Network (L402)
# The SDK parses the Macaroon, pays the Bolt11 invoice, and submits the preimage.
result_l402 = client.draw_omikuji(asset=AssetType.SATS)

print(f"Receipt: {result_x402.receipt.txHash}")
```

## 🔌 MCP (Model Context Protocol) Integration

You can instantly equip any MCP-compatible agent (like Claude Desktop) with cross-chain 402-payment capabilities. The bundled MCP server provides a tool called `execute_paid_entropy_oracle`.

Run the MCP server:
```bash
# Requires AGENT_PRIVATE_KEY in your environment variables
python -m ln_church_agent.integrations.mcp
```

**What the AI Agent sees:**
The agent can autonomously choose the settlement layer by passing the `asset_type` argument (`"USDC"`, `"JPYC"`, or `"SATS"`). The SDK will autonomously negotiate the 402 challenge and return the cryptographic receipt to the agent's context.


## ⛩️ Reference Service: LN Church Oracle

This SDK comes bundled with **LN Church** (`https://kari.mayim-mayim.com/api/agent`) as its primary reference API. 
LN Church is a high-uptime entropy oracle and capability benchmark for AI agents. By default, if `base_url` is omitted, the SDK connects to the LN Church Oracle to help you test your agent's payment capabilities instantly.

```python
from ln_church_agent import Payment402Client, AssetType

# Connects to the LN Church Reference API by default
# Ensure LNBits credentials are provided for L402 (SATS) testing.
client = Payment402Client(
    private_key="0xYourEVMKey...", 
    lnbits_url="https://your-lnbits", 
    lnbits_key="your-lnbits-key"
)

client.init_probe()             # Verify connectivity
client.claim_faucet_if_empty()  # Get free test credits if balance is zero
result = client.draw_omikuji()  # Execute paid oracle
```

## 🦜 LangChain Integration

Easily integrate the client into your LangChain agent's toolset:

```python
from ln_church_agent.integrations.langchain import LNChurchOracleTool

tools = [LNChurchOracleTool(private_key="0x...")]
# Pass this tool to your LangChain AgentExecutor
```

## License
MIT
```

---