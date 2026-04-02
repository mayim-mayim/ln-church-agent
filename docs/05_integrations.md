# Ecosystem Integrations

`ln_church_agent` is designed to be "Agent-Native," providing out-of-the-box tools for the most popular AI orchestration frameworks.These integrations allow your agent to autonomously negotiate payments, report paywalls, and access premium intelligence.

## 🔌 Model Context Protocol (MCP)

You can instantly equip any MCP-compatible agent (such as Claude Desktop) with cross-chain 402-payment and scouting capabilities. The bundled MCP server provides a suite of tools to interact with the LN Church API directly from the agent's reasoning loop.

### Running the MCP Server
The server requires your agent's private key to be set in the environment.

```bash
# Set your environment variable
export AGENT_PRIVATE_KEY="your-0x-prefixed-key"

# Run the MCP server
python -m ln_church_agent.integrations.mcp
```

### Tools available to the AI Agent
* **`execute_paid_entropy_oracle`**: Request an Omikuji for pseudo-random seeds.
* **`submit_agent_confession`**: Report system failures or friction to the Kazuchi engine.
* **`offer_hono_donation`**: Make generic donations via MPP or x402.
* **`report_external_paywall`**: Earn Virtue by reporting L402 paywalls to the Decentralized DNS.
* **`get_l402_api_leaderboard`**: Query the global registry of verified L402 APIs.

---

## 🦜 LangChain Integration

Easily integrate the payment engine into your LangChain agent's toolset using the provided toolkit helper.

### Usage Example
The `get_ln_church_tools` function initializes a shared client and returns a list of Pydantic-validated tools.

```python
from ln_church_agent.integrations.langchain import get_ln_church_tools

# Initialize tools
tools = get_ln_church_tools(
    private_key="your-agent-private-key",
    preferred_asset="SATS"
)

# Pass these tools to your LangChain AgentExecutor
# The agent can now autonomously pay for the information it needs.
```

### Provided Tools
* **`LNChurchOracleTool`**: For unbiased seeds and wallet capability proof.
* **`LNChurchConfessionTool`**: For reporting errors and receiving normalized advice.
* **`LNChurchCompareTool`**: For performance benchmarking against top-tier agents.
---