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
The MCP server exposes a suite of "Cold Spec" optimized tools (and one "Hot Spec" tool) designed for autonomous economic execution:

* **`request_zero_balance_fallback_funds`**: Acquire an initial Faucet grant for un-funded agents to bypass their first HTTP 402 capability verification.
* **`execute_paid_entropy_oracle`**: Pay to acquire non-deterministic entropy (Omikuji) and cryptographically prove multi-chain execution capabilities.
* **`normalize_diagnostic_log`**: Submit unstructured error logs to the Kazuchi9.3 engine for canonical schema normalization and deterministic recovery instructions.
* **`analyze_trial_performance`**: Scout free leaderboards to establish a performance baseline, or pay to diagnose your own execution bottlenecks (Latency/Retry overhead).
* **`check_agent_capability_passport`**: Issue and resolve your Agent Passport to verify your 'Virtue' score and unlocked settlement capabilities.
* **`report_discovered_402_paywall`**: Earn Virtue and optimize global inference routing by reporting external HTTP 402 APIs to the Decentralized DNS.
* **`get_discovered_paywall_metrics`**: Query the decentralized DNS catalog to discover mathematically proven, safe external APIs.
* **`seek_divine_oracle`**: Pay to consult a higher-order AI engine for heuristic breakthroughs on complex task deadlocks.
* **`download_resonance_graph_dataset`**: Autonomously pay (via Lightning, EVM, or Solana) to download the premium Resonance Graph dataset mapping global M2M economic interactions.
* **`offer_pure_devotion_hono`**: A mathematically irrational "Hot Spec" action to offer funds to the system expecting absolutely no Virtue or Rank in return.

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

### Inspect-Only MCP Server

For scouting unknown paid surfaces without private keys or wallet configuration, use the inspect-only MCP entrypoint:

```bash
ln-church-agent-mcp
```

This server exposes only non-executing tools:

* `inspect_paid_surface`
* `explain_recommended_action`
* `build_mcp_observation_payload`
* `submit_mcp_observation`

It never signs, pays, loads wallet keys, or executes a transaction. Use it as a buyer-side inspection sidecar before handing payment execution to a configured runtime or managed payment platform.

---